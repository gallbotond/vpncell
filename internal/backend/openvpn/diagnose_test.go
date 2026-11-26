package openvpn

import (
	"strings"
	"testing"
)

func lines(s string) []string { return strings.Split(strings.TrimSpace(s), "\n") }

func TestAnalyzeNoReply(t *testing.T) {
	// Wrong tls-auth key: the server drops every packet, the client never
	// leaves WAIT.
	h := analyze(parseHistory(lines(`
100,CONNECTING,,,,,,
100,WAIT,,,,,,
160,RECONNECTING,tls-error,,,,,
165,WAIT,,,,,,
225,RECONNECTING,tls-error,,,,,
230,WAIT,,,,,,`)))
	if h.state != "WAIT" || len(h.reconnects) != 2 || h.lastReason != "tls-error" || h.lastAt != 225 || h.lostAt != 0 {
		t.Fatalf("%+v", h)
	}
	if h.failedReply || h.failedFrom != 160 {
		t.Fatalf("failed attempt: %+v", h)
	}
	code, text, hint := explain(h, nil)
	if code != ReasonNoReply || !strings.Contains(text, "no reply") || !strings.Contains(hint, "tls-crypt") {
		t.Fatalf("%s %q %q", code, text, hint)
	}
}

func TestAnalyzeStallAfterServerCert(t *testing.T) {
	h := analyze(parseHistory(lines(`
100,CONNECTING,,,,,,
100,WAIT,,,,,,
100,AUTH,,,,,,
160,RECONNECTING,tls-error,,,,,
165,WAIT,,,,,,
165,AUTH,,,,,,`)))
	// What openvpn's management log history really holds (no "VERIFY OK").
	logs := parseLog(lines(`
160,N,TLS Error: TLS key negotiation failed to occur within 60 seconds (check your network connectivity)
160,N,TLS Error: TLS handshake failed
160,I,SIGUSR1[soft,tls-error] received, process restarting
160,,Restart pause, 10 second(s)`))
	if !h.failedReply {
		t.Fatalf("%+v", h)
	}
	code, text, hint := explain(h, logs)
	if code != ReasonCertStall || !strings.Contains(text, "after its certificate") || !strings.Contains(hint, "revoked") {
		t.Fatalf("%s %q %q", code, text, hint)
	}
	// Without the log it is a generic TLS failure.
	if code, _, _ := explain(h, nil); code != ReasonTLS {
		t.Fatalf("without log: %s", code)
	}
	// An error of the client's own is not a silent stall.
	withErr := append(parseLog([]string{"120,N,VERIFY ERROR: depth=0, error=certificate has expired: CN=server"}), logs...)
	if code, _, _ := explain(h, withErr); code != ReasonTLS {
		t.Fatalf("with VERIFY ERROR: %s", code)
	}
	// A timeout from another attempt does not count.
	if code, _, _ := explain(h, parseLog([]string{"50,N,TLS Error: TLS key negotiation failed to occur within 60 seconds"})); code != ReasonTLS {
		t.Fatalf("old log line counted: %s", code)
	}
}

func TestAnalyzeLostConnection(t *testing.T) {
	h := analyze(parseHistory(lines(`
100,CONNECTING,,,,,,
100,WAIT,,,,,,
100,AUTH,,,,,,
101,CONNECTED,SUCCESS,10.0.70.4,x,1194,,,
500,RECONNECTING,ping-restart,,,,,
505,WAIT,,,,,,
565,RECONNECTING,tls-error,,,,,
570,WAIT,,,,,,`)))
	if h.lostAt != 500 || len(h.reconnects) != 2 || h.lastReason != "tls-error" || h.failedFrom != 500 || h.failedReply {
		t.Fatalf("%+v", h)
	}
	if code, _, _ := explain(h, nil); code != ReasonNoReply {
		t.Fatalf("%s", code)
	}
}

func TestAnalyzeConnectedClearsReason(t *testing.T) {
	h := analyze(parseHistory(lines(`
100,CONNECTING,,,,,,
160,RECONNECTING,auth-failure,,,,,
170,WAIT,,,,,,
170,AUTH,,,,,,
171,CONNECTED,SUCCESS,10.0.70.4,x,1194,,,`)))
	if h.state != "CONNECTED" || h.lastReason != "" || len(h.reconnects) != 0 {
		t.Fatalf("%+v", h)
	}
	if code, _, _ := explain(h, nil); code != "" {
		t.Fatalf("reason while connected: %s", code)
	}
	h = analyze(parseHistory(lines(`
100,CONNECTING,,,,,,
100,AUTH,,,,,,
160,RECONNECTING,auth-failure,,,,,`)))
	if code, text, _ := explain(h, nil); code != ReasonAuth || text != "authentication failed" {
		t.Fatalf("%s %s", code, text)
	}
}

func TestRetryCounterSurvivesHistoryRollover(t *testing.T) {
	retries.reset("p")
	n := retries.update("p", history{state: "WAIT", reconnects: []int64{10, 20, 30}})
	if n != 3 {
		t.Fatal(n)
	}
	// The history rolled over: only the newest entries are left.
	if n := retries.update("p", history{state: "WAIT", reconnects: []int64{30, 40}}); n != 4 {
		t.Fatal(n)
	}
	if n := retries.update("p", history{state: "CONNECTED"}); n != 0 {
		t.Fatal(n)
	}
	if n := retries.update("p", history{state: "WAIT", reconnects: []int64{50}}); n != 1 {
		t.Fatal(n)
	}
}
