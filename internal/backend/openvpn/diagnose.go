package openvpn

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

// Why an OpenVPN tunnel is not connected (issue #14). openvpn keeps a
// history of its states (management `state all`, the last 100 changes) and
// of its log (`log N`); both survive a daemon restart because they live in
// the openvpn process. Each connection attempt goes through
//
//	[RECONNECTING,<reason>] → [RESOLVE] → [TCP_CONNECT] → WAIT → AUTH → GET_CONFIG → … → CONNECTED
//
// WAIT means "waiting for the server's first reply"; openvpn enters AUTH
// once that reply has arrived. So an attempt that ended in tls-error
// without AUTH got no reply at all (wrong tls-auth/tls-crypt key or mode,
// or the server is unreachable), while one that reached AUTH stalled inside
// the TLS handshake. If that attempt logged no error of its own, only the
// handshake timeout (silentStall), the server sent its certificate and then
// went silent, which with TLS 1.3 is how a refused (for example revoked)
// client certificate looks.

type histEntry struct {
	t      int64
	state  string
	reason string
}

// parseHistory reads `state all` lines: "time,STATE,description,…".
func parseHistory(lines []string) []histEntry {
	var h []histEntry
	for _, l := range lines {
		f := strings.Split(l, ",")
		if len(f) < 2 {
			continue
		}
		t, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			continue
		}
		e := histEntry{t: t, state: f[1]}
		if len(f) > 2 {
			e.reason = f[2]
		}
		h = append(h, e)
	}
	return h
}

type logEntry struct {
	t   int64
	msg string
}

// parseLog reads `log N` lines: "time,flags,message".
func parseLog(lines []string) []logEntry {
	var out []logEntry
	for _, l := range lines {
		ts, rest, ok := strings.Cut(l, ",")
		if !ok {
			continue
		}
		t, err := strconv.ParseInt(ts, 10, 64)
		if err != nil {
			continue
		}
		_, msg, _ := strings.Cut(rest, ",")
		out = append(out, logEntry{t, msg})
	}
	return out
}

// history is what the state history says about the current and the last
// failed attempt.
type history struct {
	state       string
	since       int64   // time of the current state
	reconnects  []int64 // RECONNECTING times after the last CONNECTED
	lostAt      int64   // first RECONNECTING after a CONNECTED (0: never connected in the history)
	lastReason  string  // reason of the last RECONNECTING after the last CONNECTED
	lastAt      int64
	failedFrom  int64 // start of the attempt that ended with lastReason
	failedReply bool  // that attempt got a reply from the server (reached AUTH)
}

func analyze(h []histEntry) history {
	var r history
	if len(h) == 0 {
		return r
	}
	last := h[len(h)-1]
	r.state, r.since = last.state, last.t
	start := 0
	for i := len(h) - 1; i >= 0; i-- {
		if h[i].state == "CONNECTED" {
			start = i + 1
			break
		}
	}
	attemptFrom, reply := h[0].t, false
	if start > 0 {
		attemptFrom = h[start-1].t
	}
	for _, e := range h[start:] {
		switch e.state {
		case "RECONNECTING":
			r.reconnects = append(r.reconnects, e.t)
			if r.lostAt == 0 && start > 0 {
				r.lostAt = e.t
			}
			r.lastReason, r.lastAt = e.reason, e.t
			r.failedFrom, r.failedReply = attemptFrom, reply
			attemptFrom, reply = e.t, false
		case "AUTH", "GET_CONFIG", "ASSIGN_IP", "ADD_ROUTES":
			reply = true
		}
	}
	return r
}

// silentStall reports whether the attempt between from and to ended only
// because the handshake timed out: the log has openvpn's "TLS key
// negotiation failed to occur" and no error of its own (VERIFY ERROR,
// TLS_ERROR, OpenSSL errors, AUTH_FAILED). openvpn's management log
// history does not carry the handshake progress lines ("Initial packet",
// "VERIFY OK"), so together with the AUTH state (the server replied) this
// is the sign that the server sent its certificate and then went silent.
func silentStall(logs []logEntry, from, to int64) bool {
	timeout := false
	for _, l := range logs {
		if l.t < from || l.t > to {
			continue
		}
		m := l.msg
		switch {
		case strings.HasPrefix(m, "TLS Error: TLS key negotiation failed to occur"):
			timeout = true
		case strings.HasPrefix(m, "TLS Error: TLS handshake failed"), strings.HasPrefix(m, "SIGUSR1["):
		case strings.Contains(m, "VERIFY ERROR"), strings.Contains(m, "TLS_ERROR"), strings.Contains(m, "OpenSSL:"),
			strings.Contains(m, "AUTH_FAILED"), strings.HasPrefix(m, "TLS Error"), strings.Contains(m, "tls-crypt unwrap error"),
			strings.Contains(m, "HMAC authentication failed"):
			return false
		}
	}
	return timeout
}

// Reason codes vpncell reports (control.ProfileStatus.Reason).
const (
	ReasonNoReply       = "no-reply"
	ReasonCertStall     = "stalled-after-server-cert"
	ReasonTLS           = "tls-error"
	ReasonAuth          = "auth-failure"
	ReasonPing          = "ping-restart"
	ReasonRestartSignal = "restart"
)

// explain turns openvpn's reason and what the history and log show into a
// reason code, a short text and a hint. logs may be nil.
func explain(h history, logs []logEntry) (code, text, hint string) {
	switch h.lastReason {
	case "":
		return "", "", ""
	case "tls-error":
		switch {
		case !h.failedReply:
			return ReasonNoReply, "no reply from the server",
				"the server never answered the TLS handshake. Usually the config's tls-auth/tls-crypt key or mode (or key-direction) does not match the server; otherwise the server is unreachable"
		case silentStall(logs, h.failedFrom, h.lastAt):
			return ReasonCertStall, "the server stopped answering after its certificate",
				"the server answered and sent its certificate, then went silent until the handshake timed out. It most likely refused your client certificate (revoked, replaced or removed on the server)"
		}
		return ReasonTLS, "TLS handshake failed",
			"the server answered but the TLS handshake did not complete. Check that tls-auth/tls-crypt match the server and that your certificate is still accepted"
	case "auth-failure":
		return ReasonAuth, "authentication failed",
			"the server refused the login: check the username and password (--auth-file) or the certificate"
	case "ping-restart":
		return ReasonPing, "no keepalive reply from the server",
			"the server stopped answering; openvpn restarts the connection"
	case "SIGUSR1", "SIGHUP":
		return ReasonRestartSignal, "restarted (network change or reconnect request)", ""
	}
	return h.lastReason, h.lastReason, ""
}

// retryCounter counts reconnects per profile across polls, so the count
// keeps growing after openvpn's 100-entry state history has rolled over.
// It restarts when the tunnel connects or the unit is restarted (forget).
type retryCounter struct {
	mu   sync.Mutex
	seen map[string]map[int64]bool
}

var retries = retryCounter{seen: map[string]map[int64]bool{}}

func (c *retryCounter) update(p string, h history) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if h.state == "CONNECTED" {
		delete(c.seen, p)
		return 0
	}
	s := c.seen[p]
	if s == nil {
		s = map[int64]bool{}
		c.seen[p] = s
	}
	for _, t := range h.reconnects {
		s[t] = true
	}
	return len(s)
}

func (c *retryCounter) reset(p string) {
	c.mu.Lock()
	delete(c.seen, p)
	c.mu.Unlock()
}

func unixTime(t int64) time.Time {
	if t == 0 {
		return time.Time{}
	}
	return time.Unix(t, 0)
}
