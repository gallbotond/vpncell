// Package session implements the per-session helper process (DESIGN.md §8):
// it enters the profile namespace, builds a private mount namespace with the
// profile's resolver files, starts the user's command with all privileges
// dropped, then drops its own privileges and relays the exit status.
package session

import "github.com/gallbotond/vpncell/internal/control"

// Spec is what the daemon hands to the helper over a pipe.
type Spec struct {
	ID        string   `json:"id"`
	Profile   string   `json:"profile"`
	NetnsPath string   `json:"netns_path"`
	UID       uint32   `json:"uid"`
	GID       uint32   `json:"gid"`
	Groups    []uint32 `json:"groups"`
	Argv      []string `json:"argv"`
	Env       []string `json:"env"`
	Cwd       string   `json:"cwd"`
	TTY       bool     `json:"tty"`
	Rows      uint16   `json:"rows"`
	Cols      uint16   `json:"cols"`
	Umask     int      `json:"umask"`
	// ResolveDir holds stub-resolv.conf and resolv.conf for the profile.
	ResolveDir string `json:"resolve_dir"`
	// Nsswitch is the profile's nsswitch.conf.
	Nsswitch string `json:"nsswitch"`
	// Chain is the nesting chain ending with this session (issue #12).
	Chain []control.SessionRef `json:"chain,omitempty"`
}

// Descriptor numbers in the helper process.
const (
	FdConn   = 3 // client connection
	FdSpec   = 4 // spec pipe (JSON, then EOF = go)
	FdStdin  = 5 // non-TTY only
	FdStdout = 6
	FdStderr = 7
)
