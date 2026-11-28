package client

import "github.com/gallbotond/vpncell/internal/control"

// ExecOptions describe a session to start.
type ExecOptions struct {
	Profile string
	Argv    []string
	TTY     bool
	IsShell bool
	// OnStart, if set, is called once the session has started, with its
	// id and nesting chain (outermost first; issue #12).
	OnStart func(id string, chain []control.SessionRef)
}
