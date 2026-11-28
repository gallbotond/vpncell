package socks

import (
	"errors"

	"github.com/gallbotond/vpncell/internal/netns"
)

// The profile namespace's socket factory is the Linux Dialer.
var _ Dialer = (*netns.Factory)(nil)

// namespaceClosed reports whether the profile namespace went away under a
// dial (the profile was stopped).
func namespaceClosed(err error) bool { return errors.Is(err, netns.ErrClosed) }
