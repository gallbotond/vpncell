package importer

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/gallbotond/vpncell/internal/reach"
)

// Import-time warnings about what a profile can reach (issue #15). A
// profile sends all its traffic into the tunnel and never falls back to
// the host connection, so a split-tunnel server leaves every other
// address unreachable.

const noFallback = "vpncell never falls back to your normal connection"

// ReachWarnings: WireGuard's AllowedIPs are a hard limit.
func (c *WGConfig) ReachWarnings() []string {
	var allowed []netip.Prefix
	for _, p := range c.Peers {
		allowed = append(allowed, p.AllowedIPs...)
	}
	var w []string
	if !reach.Default4(allowed) {
		w = append(w, fmt.Sprintf("this profile reaches %s (the server's AllowedIPs); other addresses fail in it (%s)", reach.Describe(allowed), noFallback))
	}
	if len(c.DNSServers) == 0 {
		w = append(w, "no DNS servers: hostnames fail in this profile until you add [dns] servers")
	}
	for _, d := range c.DNSServers {
		if !reach.Covers(allowed, d) {
			w = append(w, fmt.Sprintf("DNS server %s is outside AllowedIPs: lookups to it fail", d))
		}
	}
	return w
}

// ReachWarnings: for OpenVPN the server decides at connect time (pushed
// routes, redirect-gateway), so only the config's own redirect-gateway is
// known here.
func (c *OVPNConfig) ReachWarnings() []string {
	for _, l := range c.Lines {
		if f := strings.Fields(l); len(f) > 0 && f[0] == "redirect-gateway" {
			return nil
		}
	}
	return []string{"the config has no redirect-gateway: unless the server pushes one, this profile probably reaches only the networks the server pushes routes for (" + noFallback + "); `vpncell status` shows them once connected"}
}
