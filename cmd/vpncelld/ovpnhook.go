package main

import (
	"github.com/gallbotond/vpncell/internal/backend/openvpn"
	"github.com/gallbotond/vpncell/internal/daemon"
)

// runOVPNHook is `vpncelld ovpn-hook <profile>`, run by openvpn as its
// up/down script (DESIGN.md §4.4).
func runOVPNHook(args []string) int {
	return openvpn.RunHook(args, daemon.WriteProfileDNS)
}
