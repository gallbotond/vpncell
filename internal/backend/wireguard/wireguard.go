// Package wireguard implements the WireGuard backend (DESIGN.md §4.3): the
// interface is created and configured in the host namespace, so its
// encrypted UDP socket stays there, and is then moved into the profile
// namespace, where addresses, MTU and routes are applied.
package wireguard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/gallbotond/vpncell/internal/backend"
	"github.com/gallbotond/vpncell/internal/brand"
	"github.com/gallbotond/vpncell/internal/importer"
	"github.com/gallbotond/vpncell/internal/netns"
	"github.com/gallbotond/vpncell/internal/profile"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// DefaultKeepalive is used when a peer has none, so that the handshake age
// reflects the tunnel's health.
const DefaultKeepalive = 25

// HandshakeFresh is the age below which a tunnel counts as "up".
const HandshakeFresh = 180 * time.Second

type Backend struct {
	Log *slog.Logger
}

func New(log *slog.Logger) *Backend { return &Backend{Log: log} }

func (b *Backend) IfPrefix() string { return brand.WGIfPrefix }

func loadConfig(p *profile.Profile) (*importer.WGConfig, error) {
	data, err := os.ReadFile(p.WireGuard.Config)
	if err != nil {
		return nil, err
	}
	// The stored file was sanitized at import; parse it through the same
	// allowlist again in case it was edited by hand.
	cfg, _, err := importer.ParseWireGuard(string(data))
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func resolveEndpoint(ctx context.Context, ep string) (*net.UDPAddr, error) {
	host, port, err := importer.SplitHostPort(ep)
	if err != nil {
		return nil, err
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(a, uint16(port))), nil
	}
	// The daemon runs in the host namespace, so this uses the host resolver,
	// as the endpoint must be reached over the host network.
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(rctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve endpoint %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("resolve endpoint %s: no addresses", host)
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(addrs[0].Unmap(), uint16(port))), nil
}

func peerConfigs(ctx context.Context, cfg *importer.WGConfig, updateOnly bool) ([]wgtypes.PeerConfig, error) {
	var out []wgtypes.PeerConfig
	for _, pc := range cfg.Peers {
		pub, err := wgtypes.ParseKey(pc.PublicKey)
		if err != nil {
			return nil, err
		}
		c := wgtypes.PeerConfig{PublicKey: pub, UpdateOnly: updateOnly}
		if !updateOnly {
			c.ReplaceAllowedIPs = true
			for _, a := range pc.AllowedIPs {
				c.AllowedIPs = append(c.AllowedIPs, *prefixToIPNet(a))
			}
			if pc.PresharedKey != "" {
				psk, err := wgtypes.ParseKey(pc.PresharedKey)
				if err != nil {
					return nil, err
				}
				c.PresharedKey = &psk
			}
			ka := pc.PersistentKeepalive
			if ka == 0 {
				ka = DefaultKeepalive
			}
			d := time.Duration(ka) * time.Second
			c.PersistentKeepaliveInterval = &d
		}
		if pc.Endpoint != "" {
			ep, err := resolveEndpoint(ctx, pc.Endpoint)
			if err != nil {
				return nil, err
			}
			c.Endpoint = ep
		}
		out = append(out, c)
	}
	return out, nil
}

func prefixToIPNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

// Up implements backend.Backend.
func (b *Backend) Up(ctx context.Context, p *profile.Profile, ifname string) error {
	cfg, err := loadConfig(p)
	if err != nil {
		return err
	}
	peers, err := peerConfigs(ctx, cfg, false)
	if err != nil {
		return err
	}
	priv, err := wgtypes.ParseKey(cfg.PrivateKey)
	if err != nil {
		return err
	}
	// Clean up a leftover with the same name in either namespace.
	_ = b.Down(ctx, p, ifname)

	la := netlink.NewLinkAttrs()
	la.Name = ifname
	link := &netlink.Wireguard{LinkAttrs: la}
	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("create %s: %w", ifname, err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = b.Down(context.Background(), p, ifname)
		}
	}()
	wc, err := wgctrl.New()
	if err != nil {
		return err
	}
	err = wc.ConfigureDevice(ifname, wgtypes.Config{PrivateKey: &priv, ReplacePeers: true, Peers: peers})
	wc.Close()
	if err != nil {
		return fmt.Errorf("configure %s: %w", ifname, err)
	}
	l, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	nsfd, err := unix.Open(brand.NetnsPath(p.Name), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	err = netlink.LinkSetNsFd(l, nsfd)
	unix.Close(nsfd)
	if err != nil {
		return fmt.Errorf("move %s into namespace: %w", ifname, err)
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = 1420
	}
	if err := ConfigureInside(p, ifname, cfg.Addresses, mtu); err != nil {
		return err
	}
	ok = true
	return nil
}

// ConfigureInside applies addresses, MTU, link state and routes to an
// interface that is already in the profile namespace. It is shared with the
// OpenVPN hook.
func ConfigureInside(p *profile.Profile, ifname string, addrs []netip.Prefix, mtu int) error {
	return netns.Do(p.Name, func() error {
		return ConfigureHere(p.RoutesP, ifname, addrs, mtu)
	})
}

// ConfigureHere is ConfigureInside for a thread that is already in the
// namespace.
func ConfigureHere(routes []netip.Prefix, ifname string, addrs []netip.Prefix, mtu int) error {
	l, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	if mtu > 0 {
		if err := netlink.LinkSetMTU(l, mtu); err != nil {
			return fmt.Errorf("mtu: %w", err)
		}
	}
	// Replace the address set.
	existing, _ := netlink.AddrList(l, netlink.FAMILY_ALL)
	want := map[netip.Prefix]bool{}
	for _, a := range addrs {
		want[a] = true
	}
	for _, e := range existing {
		pf, ok := ipnetToPrefix(e.IPNet)
		if ok && !want[pf] && e.Scope == unix.RT_SCOPE_UNIVERSE {
			_ = netlink.AddrDel(l, &e)
		}
	}
	has6 := false
	for _, a := range addrs {
		if a.Addr().Is6() && !a.Addr().Is4In6() {
			has6 = true
		}
		na := &netlink.Addr{IPNet: prefixToIPNet(a)}
		if a.Addr().Is6() {
			na.Flags = unix.IFA_F_NODAD
		}
		if err := netlink.AddrReplace(l, na); err != nil {
			return fmt.Errorf("address %s: %w", a, err)
		}
	}
	if err := netlink.LinkSetUp(l); err != nil {
		return err
	}
	for _, r := range routes {
		if r.Addr().Is6() && !has6 {
			// IPv6 fails closed: no IPv6 route without an IPv6 tunnel address.
			continue
		}
		rt := &netlink.Route{LinkIndex: l.Attrs().Index, Dst: prefixToIPNet(r), Scope: netlink.SCOPE_LINK}
		if r.Addr().Is6() {
			rt.Scope = netlink.SCOPE_UNIVERSE
		}
		if err := netlink.RouteReplace(rt); err != nil {
			return fmt.Errorf("route %s: %w", r, err)
		}
	}
	return nil
}

func ipnetToPrefix(n *net.IPNet) (netip.Prefix, bool) {
	a, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, _ := n.Mask.Size()
	return netip.PrefixFrom(a.Unmap(), ones), true
}

// Down implements backend.Backend.
func (b *Backend) Down(ctx context.Context, p *profile.Profile, ifname string) error {
	var errs []error
	if l, err := netlink.LinkByName(ifname); err == nil {
		if err := netlink.LinkDel(l); err != nil {
			errs = append(errs, err)
		}
	}
	if netns.Exists(p.Name) {
		err := netns.Do(p.Name, func() error {
			if l, err := netlink.LinkByName(ifname); err == nil {
				return netlink.LinkDel(l)
			}
			return nil
		})
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Adopt implements backend.Backend.
func (b *Backend) Adopt(ctx context.Context, p *profile.Profile, ifname string) (bool, error) {
	found := false
	err := netns.Do(p.Name, func() error {
		l, err := netlink.LinkByName(ifname)
		if err != nil {
			return nil
		}
		found = l.Type() == "wireguard"
		return nil
	})
	return found, err
}

// Status implements backend.Backend.
func (b *Backend) Status(ctx context.Context, p *profile.Profile, ifname string) (backend.Status, error) {
	var st backend.Status
	err := netns.Do(p.Name, func() error {
		l, err := netlink.LinkByName(ifname)
		if err != nil {
			st.State = "failed: tunnel interface missing"
			return nil
		}
		st.Present = true
		if l.Attrs().Flags&net.FlagUp == 0 {
			st.State = "failed: tunnel interface is down"
		}
		addrs, _ := netlink.AddrList(l, netlink.FAMILY_ALL)
		for _, a := range addrs {
			if a.Scope != unix.RT_SCOPE_UNIVERSE {
				continue
			}
			if pf, ok := ipnetToPrefix(a.IPNet); ok {
				st.Addresses = append(st.Addresses, pf)
			}
		}
		wc, err := wgctrl.New()
		if err != nil {
			return err
		}
		defer wc.Close()
		dev, err := wc.Device(ifname)
		if err != nil {
			return err
		}
		for _, peer := range dev.Peers {
			if peer.LastHandshakeTime.After(st.LastHandshake) {
				st.LastHandshake = peer.LastHandshakeTime
			}
			st.RxBytes += uint64(peer.ReceiveBytes)
			st.TxBytes += uint64(peer.TransmitBytes)
		}
		return nil
	})
	if err != nil {
		return st, err
	}
	if st.State == "" {
		if !st.LastHandshake.IsZero() && time.Since(st.LastHandshake) < HandshakeFresh {
			st.State = backend.StateUp
		} else {
			st.State = backend.StateConnecting
		}
	}
	return st, nil
}

// OnHostNetworkChange re-resolves hostname endpoints and updates the peers.
// WireGuard roams on its own for IP endpoints.
func (b *Backend) OnHostNetworkChange(ctx context.Context, p *profile.Profile, ifname string) {
	cfg, err := loadConfig(p)
	if err != nil {
		return
	}
	hasName := false
	for _, pc := range cfg.Peers {
		if host, _, err := importer.SplitHostPort(pc.Endpoint); err == nil {
			if _, err := netip.ParseAddr(host); err != nil {
				hasName = true
			}
		}
	}
	if !hasName {
		return
	}
	peers, err := peerConfigs(ctx, cfg, true)
	if err != nil {
		b.Log.Warn("re-resolve endpoint failed", "profile", p.Name, "err", err)
		return
	}
	err = netns.Do(p.Name, func() error {
		wc, err := wgctrl.New()
		if err != nil {
			return err
		}
		defer wc.Close()
		return wc.ConfigureDevice(ifname, wgtypes.Config{Peers: peers})
	})
	if err != nil {
		b.Log.Warn("update endpoint failed", "profile", p.Name, "err", err)
	}
}
