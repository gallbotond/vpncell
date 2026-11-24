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
	ExitCode  *int   `json:"exit_code,omitempty"`
	Signal    int    `json:"signal,omitempty"`
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
	Name          string        `json:"name"`
	Backend       string        `json:"backend"`
	State         string        `json:"state"` // down, connecting, up, failed: <reason>
	Autostart     string        `json:"autostart"`
	ExitIP        string        `json:"exit_ip,omitempty"`
	LastHandshake int64         `json:"last_handshake,omitempty"` // unix seconds
	ConnectedAt   int64         `json:"connected_at,omitempty"`
	RxBytes       uint64        `json:"rx_bytes"`
	TxBytes       uint64        `json:"tx_bytes"`
	SocksPort     int           `json:"socks_port"`
	Interface     string        `json:"interface,omitempty"`
	Addresses     []string      `json:"addresses,omitempty"`
	DNS           []string      `json:"dns,omitempty"`
	Sessions      []SessionInfo `json:"sessions"`
}

type SessionInfo struct {
	ID      string   `json:"id"`
	Profile string   `json:"profile"`
	UID     uint32   `json:"uid"`
	PID     int      `json:"pid"`
	Command []string `json:"command"`
	Started int64    `json:"started"`
	Scope   string   `json:"scope,omitempty"`
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
