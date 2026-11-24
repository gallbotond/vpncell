// Package backend defines the interface every VPN type implements. A backend
// only has to produce "a configured tunnel interface inside the profile
// namespace plus a status". DNS files, nftables and SOCKS are handled by the
// daemon around it.
package backend

import (
	"context"
	"net/netip"
	"time"

	"github.com/gallbotond/vpncell/internal/profile"
)

// Status is what a backend reports about a running tunnel.
type Status struct {
	State         string // "up", "connecting", "failed: <reason>"
	LastHandshake time.Time
	ConnectedAt   time.Time
	RxBytes       uint64
	TxBytes       uint64
	Addresses     []netip.Prefix
	PushedDNS     []netip.Addr
	PushedSearch  []string
	Present       bool // the tunnel interface exists in the namespace
}

const (
	StateDown       = "down"
	StateConnecting = "connecting"
	StateUp         = "up"
)

// Backend is one VPN implementation.
type Backend interface {
	// Up creates the tunnel, moves it into the profile namespace and
	// configures it there. The namespace already exists.
	Up(ctx context.Context, p *profile.Profile, ifname string) error
	// Down removes the tunnel.
	Down(ctx context.Context, p *profile.Profile, ifname string) error
	// Adopt reports whether a tunnel left by a previous daemon is present and
	// usable.
	Adopt(ctx context.Context, p *profile.Profile, ifname string) (bool, error)
	// Status reports the current state.
	Status(ctx context.Context, p *profile.Profile, ifname string) (Status, error)
	// OnHostNetworkChange is called after a host network change or resume.
	OnHostNetworkChange(ctx context.Context, p *profile.Profile, ifname string)
	// IfPrefix is the interface name prefix (followed by a small index).
	IfPrefix() string
}
