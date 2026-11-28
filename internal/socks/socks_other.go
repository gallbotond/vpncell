//go:build !linux

package socks

// namespaceClosed: there are no profile namespaces on this platform (#69).
func namespaceClosed(error) bool { return false }
