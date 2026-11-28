package daemon

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gallbotond/vpncell/internal/brand"
	"github.com/gallbotond/vpncell/internal/conflict"
	"github.com/gallbotond/vpncell/internal/profile"
	"github.com/godbus/dbus/v5"
)

// Connections outside vpncell, for identity conflicts (issue #19).
var (
	outsideMu sync.Mutex
	outsideAt time.Time
	outsideNM []conflict.NMConnection
	outsideWG []conflict.WGDevice
)

const outsideTTL = 15 * time.Second

// outsideConnections returns NetworkManager's active VPN and WireGuard
// connections and the host's WireGuard interfaces (not vpncell's own), read
// at most every 15 s unless fresh. Without NetworkManager, or when D-Bus
// fails, the NetworkManager list is empty: the check is skipped silently.
func outsideConnections(fresh bool) ([]conflict.NMConnection, []conflict.WGDevice) {
	outsideMu.Lock()
	defer outsideMu.Unlock()
	if !fresh && time.Since(outsideAt) < outsideTTL {
		return outsideNM, outsideWG
	}
	outsideNM, outsideWG = nil, nil
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx)); err == nil {
		outsideNM, _ = conflict.ActiveNM(ctx, conn)
		conn.Close()
	}
	if devs, err := conflict.HostWireGuard(); err == nil {
		for _, d := range devs {
			// vpncell creates its devices in the host namespace and then
			// moves them into the profile's.
			if !strings.HasPrefix(d.Name, brand.WGIfPrefix) {
				outsideWG = append(outsideWG, d)
			}
		}
	}
	outsideAt = time.Now()
	return outsideNM, outsideWG
}

// identityWarnings warns when a connection outside vpncell uses p's client
// identity (same OpenVPN client certificate or WireGuard key).
func identityWarnings(p *profile.Profile, fresh bool) []string {
	var id conflict.Identity
	switch p.Backend {
	case profile.BackendWireGuard:
		data, err := os.ReadFile(p.WireGuard.Config)
		if err != nil {
			return nil
		}
		id = conflict.WireGuardIdentity(data)
	case profile.BackendOpenVPN:
		data, err := os.ReadFile(p.OpenVPN.Config)
		if err != nil {
			return nil
		}
		id = conflict.OpenVPNIdentity(data, conflict.ReadRegular)
	}
	if id.Cert == nil && id.WGPub == nil {
		return nil
	}
	nm, wg := outsideConnections(fresh)
	if len(nm) == 0 && len(wg) == 0 {
		return nil
	}
	return conflict.Check(p.Name, id, nm, wg, conflict.ReadRegular)
}
