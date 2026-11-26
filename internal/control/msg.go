package control

import (
	"encoding/json"
	"fmt"
	"unsafe"
)

func uintptrOf(b []uint32) uintptr   { return uintptr(unsafe.Pointer(&b[0])) }
func uintptrOfU32(p *uint32) uintptr { return uintptr(unsafe.Pointer(p)) }

// Version is the protocol version.
const Version = 1

// Request is the envelope of every client request. Only the fields of the
// given type are used.
type Request struct {
	Type    string `json:"type"`
	Version int    `json:"version,omitempty"`
	Profile string `json:"profile,omitempty"`
	Force   bool   `json:"force,omitempty"`
	Kill    bool   `json:"kill,omitempty"`

	Exec   *ExecRequest   `json:"exec,omitempty"`
	Import *ImportRequest `json:"import,omitempty"`
}

// ExecRequest starts a command in a profile. For non-TTY sessions the client
// attaches stdin, stdout and stderr (in that order) as descriptors.
type ExecRequest struct {
	Argv    []string `json:"argv"`
	Env     []string `json:"env"`
	Cwd     string   `json:"cwd"`
	TTY     bool     `json:"tty"`
	Term    string   `json:"term,omitempty"`
	Rows    uint16   `json:"rows,omitempty"`
	Cols    uint16   `json:"cols,omitempty"`
	Umask   int      `json:"umask"`
	IsShell bool     `json:"is_shell,omitempty"`
}

// ImportRequest carries a config and the files it references.
type ImportRequest struct {
	Name      string            `json:"name"`
	Kind      string            `json:"kind"` // "wireguard" | "openvpn"
	Config    string            `json:"config"`
	Files     map[string]string `json:"files,omitempty"`     // referenced path -> content
	AuthFile  string            `json:"auth_file,omitempty"` // content of a user/pass file
	Replace   bool              `json:"replace,omitempty"`
	Users     []string          `json:"users,omitempty"`
	Groups    []string          `json:"groups,omitempty"`
	Autostart string            `json:"autostart,omitempty"`
}

// Response is the envelope of every reply and event.
type Response struct {
	Type  string `json:"type"` // "ok", "error", "hello", "event", "started", "exit"
	Error *Error `json:"error,omitempty"`

	// hello
	ServerVersion int    `json:"server_version,omitempty"`
	UID           uint32 `json:"uid,omitempty"`
	Admin         bool   `json:"admin,omitempty"`

	Profiles []ProfileInfo     `json:"profiles,omitempty"`
	Status   []ProfileStatus   `json:"status,omitempty"`
	Socks    *SocksInfo        `json:"socks,omitempty"`
	Report   *ImportReport     `json:"report,omitempty"`
	Event    *Event            `json:"event,omitempty"`
	Message  string            `json:"message,omitempty"`
	Debug    map[string]uint64 `json:"debug,omitempty"`

	// session
	SessionID string `json:"session_id,omitempty"`
	// Chain: the new session's nesting chain, outermost first ("started").
	Chain []SessionRef `json:"chain,omitempty"`
	// Current: reply to "current".
	Current  *CurrentInfo `json:"current,omitempty"`
	ExitCode *int         `json:"exit_code,omitempty"`
	Signal   int          `json:"signal,omitempty"`
}

type Error struct {
	Code     string        `json:"code"`
	Message  string        `json:"message"`
	Sessions []SessionInfo `json:"sessions,omitempty"`
}

func (e *Error) Error() string { return e.Message }

// Error codes.
const (
	ErrBadRequest  = "bad_request"
	ErrDenied      = "permission_denied"
	ErrNotFound    = "not_found"
	ErrProfileDown = "profile_down"
	ErrBusy        = "sessions_active"
	ErrInternal    = "internal"
	ErrImport      = "import_rejected"
	ErrUnsupported = "unsupported"
)

func Errorf(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

type ProfileInfo struct {
	Name    string `json:"name"`
	Backend string `json:"backend"`
	State   string `json:"state"`
}

type ProfileStatus struct {
	Name          string `json:"name"`
	Backend       string `json:"backend"`
	State         string `json:"state"` // down, connecting, up, failed: <reason>
	Autostart     string `json:"autostart"`
	ExitIP        string `json:"exit_ip,omitempty"`
	LastHandshake int64  `json:"last_handshake,omitempty"` // unix seconds
	ConnectedAt   int64  `json:"connected_at,omitempty"`   // only in state "up"
	// TryingSince: not up, since when (unix seconds): when the connection
	// was lost, or when the profile was brought up if it never connected.
	TryingSince int64 `json:"trying_since,omitempty"`
	// Why the tunnel is not connected (OpenVPN; issue #14).
	Reason     string `json:"reason,omitempty"`      // code: no-reply, stalled-after-server-cert, tls-error, auth-failure, ping-restart, …
	ReasonText string `json:"reason_text,omitempty"` // one line for people
	Hint       string `json:"hint,omitempty"`        // what to check
	ReasonAt   int64  `json:"reason_at,omitempty"`   // unix seconds of the last failed attempt
	Retries    int    `json:"retries,omitempty"`     // failed attempts since the last connection
	Log        string `json:"log,omitempty"`         // command that shows the tunnel's log
	// What the profile reaches through its tunnel (issue #15).
	// routes_source "allowed-ips" (WireGuard): a hard limit. "pushed"
	// (OpenVPN): the routes the server pushed; advisory.
	Reaches         string   `json:"reaches,omitempty"` // e.g. "only 172.30.0.0/16; no IPv6"
	Routes          []string `json:"routes,omitempty"`
	RoutesSource    string   `json:"routes_source,omitempty"`
	RedirectGateway bool     `json:"redirect_gateway,omitempty"`
	SplitTunnel     bool     `json:"split_tunnel,omitempty"` // not every IPv4 address is reachable
	NoDNS           bool     `json:"no_dns,omitempty"`       // no DNS servers: hostnames fail
	// DNS servers outside the reachable networks (lookups to them fail).
	DNSUnreachable []string      `json:"dns_unreachable,omitempty"`
	RxBytes        uint64        `json:"rx_bytes"`
	TxBytes        uint64        `json:"tx_bytes"`
	SocksPort      int           `json:"socks_port"`
	Interface      string        `json:"interface,omitempty"`
	Addresses      []string      `json:"addresses,omitempty"`
	DNS            []string      `json:"dns,omitempty"`
	Sessions       []SessionInfo `json:"sessions"`
}

type SessionInfo struct {
	ID      string   `json:"id"`
	Profile string   `json:"profile"`
	UID     uint32   `json:"uid"`
	PID     int      `json:"pid"`
	Command []string `json:"command"`
	Started int64    `json:"started"`
	Scope   string   `json:"scope,omitempty"`
	// Parent is the session the starting command ran in (nested sessions;
	// issue #12). Empty: started from outside any session.
	Parent string `json:"parent,omitempty"`
	// Current marks the caller's own session; Outer an outer session of
	// it (status, issue #12).
	Current bool `json:"current,omitempty"`
	Outer   bool `json:"outer,omitempty"`
}

// SessionRef names one session of a nesting chain.
type SessionRef struct {
	ID      string `json:"id"`
	Profile string `json:"profile"`
}

// CurrentInfo answers "where am I?" (`vpncell current`, issue #12). The
// daemon finds the caller's session from its cgroup and its network from
// its network namespace (SO_PEERCRED pid); environment variables are not
// trusted.
type CurrentInfo struct {
	// Session is the caller's session; nil outside any session.
	Session *SessionInfo `json:"session,omitempty"`
	// Chain lists the sessions from the outermost to the caller's own.
	Chain []SessionRef `json:"chain,omitempty"`
	// Network is the profile whose namespace the caller is in, "host",
	// or "unknown" (another namespace).
	Network string `json:"network"`
	// State is the state of that profile (empty for host/unknown).
	State string `json:"state,omitempty"`
}

type SocksInfo struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type ImportReport struct {
	Profile  string   `json:"profile"`
	Kept     []string `json:"kept"`
	Stripped []string `json:"stripped"`
	Warnings []string `json:"warnings,omitempty"`
}

type Event struct {
	Kind    string `json:"kind"` // profile_changed, credentials_changed
	Profile string `json:"profile"`
	State   string `json:"state,omitempty"`
}

// Session messages exchanged between client and session helper after
// "started".
type SessionMsg struct {
	Type   string `json:"type"` // "signal", "exit", "started"
	Signal int    `json:"signal,omitempty"`
	Code   *int   `json:"code,omitempty"`
}

// Decode helper.
func Decode(raw json.RawMessage, v any) error { return json.Unmarshal(raw, v) }
