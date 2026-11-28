package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gallbotond/vpncell/internal/backend"
	"github.com/gallbotond/vpncell/internal/brand"
	"github.com/gallbotond/vpncell/internal/control"
	"github.com/gallbotond/vpncell/internal/dnsfiles"
	"github.com/gallbotond/vpncell/internal/firewall"
	"github.com/gallbotond/vpncell/internal/netns"
	"github.com/gallbotond/vpncell/internal/platform"
	"github.com/gallbotond/vpncell/internal/profile"
	"github.com/gallbotond/vpncell/internal/reach"
	"github.com/vishvananda/netlink"
)

const factoryWorkers = 4

func (d *Daemon) setState(name string, rt *rtProfile, state, errMsg string) {
	rt.mu.Lock()
	changed := rt.state != state
	rt.state = state
	rt.lastErr = errMsg
	rt.mu.Unlock()
	if changed {
		d.log.Info("profile state", "profile", name, "state", state)
		d.events.publish(control.Event{Kind: "profile_changed", Profile: name, State: state})
	}
}

// up brings a profile up (idempotent).
func (d *Daemon) up(p *profile.Profile, rt *rtProfile) error {
	rt.op.Lock()
	defer rt.op.Unlock()
	return d.upLocked(p, rt)
}

func (d *Daemon) upLocked(p *profile.Profile, rt *rtProfile) error {
	if rt.removed {
		return fmt.Errorf("profile %q was removed", p.Name)
	}
	b := d.backends[p.Backend]
	if b == nil {
		return fmt.Errorf("backend %q is not available", p.Backend)
	}
	ifn, err := d.ifname(p)
	if err != nil {
		return err
	}
	rt.ifname = ifn
	setDesired(p.Name, true)
	if s := rt.getState(); s == backend.StateUp || s == backend.StateConnecting {
		if ok, _ := b.Adopt(d.ctx, p, ifn); ok {
			return nil
		}
	}
	d.setState(p.Name, rt, backend.StateConnecting, "")
	if _, err := netns.Create(p.Name); err != nil {
		d.setState(p.Name, rt, "failed: "+err.Error(), err.Error())
		return fmt.Errorf("namespace: %w", err)
	}
	// Firewall before the tunnel exists, so the tunnel is never up without it.
	if err := d.prepareNamespace(p, ifn); err != nil {
		d.setState(p.Name, rt, "failed: "+err.Error(), err.Error())
		return err
	}
	ctx, cancel := context.WithTimeout(d.ctx, 60*time.Second)
	defer cancel()
	if err := b.Up(ctx, p, ifn); err != nil {
		d.setState(p.Name, rt, "failed: "+err.Error(), err.Error())
		rt.mu.Lock()
		rt.retryAt = time.Now().Add(nextBackoff(rt))
		rt.mu.Unlock()
		return fmt.Errorf("tunnel: %w", err)
	}
	if err := d.startRuntime(p, rt); err != nil {
		d.setState(p.Name, rt, "failed: "+err.Error(), err.Error())
		return err
	}
	rt.mu.Lock()
	rt.upSince = time.Now()
	rt.backoff = 0
	rt.mu.Unlock()
	d.refreshStatus(p, rt)
	for _, e := range d.exts {
		e.profileUp(p, rt)
	}
	return nil
}

func nextBackoff(rt *rtProfile) time.Duration {
	if rt.backoff == 0 {
		rt.backoff = 2 * time.Second
	} else {
		rt.backoff *= 2
	}
	if rt.backoff > 2*time.Minute {
		rt.backoff = 2 * time.Minute
	}
	return rt.backoff
}

// prepareNamespace installs nftables and writes the resolver files.
func (d *Daemon) prepareNamespace(p *profile.Profile, ifn string) error {
	// Unprivileged ping in the profile (issue #10). Runs on every up and on
	// adoption, so namespaces made by older versions get it too.
	if err := setPingGroupRange(p.Name); err != nil {
		d.log.Warn("ping_group_range", "profile", p.Name, "err", err)
	}
	if p.NftablesEnabled() {
		if err := firewall.Install(p.Name, ifn); err != nil {
			return fmt.Errorf("nftables: %w", err)
		}
	} else {
		d.log.Warn("nftables layer disabled for profile (test setting)", "profile", p.Name)
		if err := firewall.Remove(p.Name); err != nil {
			return err
		}
	}
	return d.writeDNSFiles(p, nil, nil)
}

// writeDNSFiles writes resolv.conf and nsswitch.conf for the profile.
// pushed servers are appended when the profile uses pushed DNS.
func (d *Daemon) writeDNSFiles(p *profile.Profile, pushed []netip.Addr, pushedSearch []string) error {
	dir := filepath.Join(brand.ProfileRunDir(p.Name), "resolve")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	os.Chmod(brand.ProfileRunDir(p.Name), 0o755)
	servers, search := d.dnsFor(p, pushed, pushedSearch)
	rc := dnsfiles.ResolvConf(p.Name, servers, search)
	for _, n := range []string{"resolv.conf", "stub-resolv.conf"} {
		if err := dnsfiles.WriteAtomic(filepath.Join(dir, n), rc, 0o644); err != nil {
			return err
		}
	}
	ns, err := dnsfiles.NsswitchConf(platform.NsswitchConf)
	if err != nil {
		return err
	}
	return dnsfiles.WriteAtomic(filepath.Join(brand.ProfileRunDir(p.Name), "nsswitch.conf"), ns, 0o644)
}

// dnsFor returns the effective servers and search domains.
func (d *Daemon) dnsFor(p *profile.Profile, pushed []netip.Addr, pushedSearch []string) ([]netip.Addr, []string) {
	servers := append([]netip.Addr{}, p.DNSServers...)
	search := append([]string{}, p.DNS.Search...)
	if p.UsePushedDNS() {
		seen := map[netip.Addr]bool{}
		for _, s := range servers {
			seen[s] = true
		}
		for _, s := range pushed {
			if !seen[s] {
				servers = append(servers, s)
				seen[s] = true
			}
		}
		for _, s := range pushedSearch {
			if profile.ValidDomain(s) {
				search = append(search, s)
			}
		}
	}
	return servers, search
}

// startRuntime starts the per-profile socket factory.
func (d *Daemon) startRuntime(p *profile.Profile, rt *rtProfile) error {
	d.mu.Lock()
	f := rt.factory
	d.mu.Unlock()
	if f != nil {
		if id, err := netns.IDOfPath(brand.NetnsPath(p.Name)); err == nil && id == f.ID() {
			return nil
		}
		f.Close()
	}
	nf, err := netns.NewFactory(p.Name, factoryWorkers)
	if err != nil {
		return fmt.Errorf("socket factory: %w", err)
	}
	d.mu.Lock()
	rt.factory = nf
	d.mu.Unlock()
	return nil
}

// down takes a profile down. Without force or kill it refuses while
// sessions run.
func (d *Daemon) down(p *profile.Profile, rt *rtProfile, force, kill bool) error {
	rt.op.Lock()
	defer rt.op.Unlock()
	return d.downLocked(p, rt, force, kill)
}

func (d *Daemon) downLocked(p *profile.Profile, rt *rtProfile, force, kill bool) error {
	live := d.sessions.list(p.Name)
	if len(live) > 0 && !force && !kill {
		return &control.Error{Code: control.ErrBusy,
			Message:  fmt.Sprintf("profile %q has %d active session(s); use --force to drop their network or --kill to end them", p.Name, len(live)),
			Sessions: live}
	}
	if kill {
		d.sessions.killProfile(d, p.Name)
	}
	setDesired(p.Name, false)
	for _, e := range d.exts {
		e.profileDown(p, rt)
	}
	ifn := rt.ifname
	if ifn == "" {
		ifn, _ = d.ifname(p)
	}
	err := d.backends[p.Backend].Down(d.ctx, p, ifn)
	d.mu.Lock()
	f := rt.factory
	rt.factory = nil
	d.mu.Unlock()
	if f != nil {
		f.Close()
	}
	rt.mu.Lock()
	rt.status = backend.Status{}
	rt.exitIP = ""
	rt.upSince = time.Time{}
	rt.mu.Unlock()
	d.maybeDeleteNamespace(p.Name)
	d.setState(p.Name, rt, backend.StateDown, "")
	return err
}

// maybeDeleteNamespace removes a down profile's namespace once no session
// uses it. With sessions alive (down --force), the namespace stays with only
// lo, so a later `up` gives those sessions network again.
func (d *Daemon) maybeDeleteNamespace(name string) {
	if isDesired(name) || !netns.Exists(name) {
		return
	}
	if d.sessions.countLive(name) > 0 {
		return
	}
	if err := netns.Delete(name); err != nil {
		d.log.Warn("delete namespace", "profile", name, "err", err)
	}
	os.RemoveAll(brand.ProfileRunDir(name))
}

// refreshStatus asks the backend for the current state.
func (d *Daemon) refreshStatus(p *profile.Profile, rt *rtProfile) backend.Status {
	ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
	defer cancel()
	st, err := d.backends[p.Backend].Status(ctx, p, rt.ifname)
	if err != nil {
		st.State = "failed: " + err.Error()
	}
	rt.mu.Lock()
	rt.status = st
	key := fmt.Sprint(st.PushedDNS, st.PushedSearch)
	changed := p.UsePushedDNS() && key != rt.pushedKey
	if changed {
		rt.pushedKey = key
	}
	rkey := fmt.Sprint(st.RoutesSource, st.Routes, st.RedirectGateway)
	routesChanged := st.RoutesSource != "" && rkey != rt.routesKey
	if routesChanged {
		rt.routesKey = rkey
	}
	rt.mu.Unlock()
	if routesChanged {
		// What the tunnel carries (issue #15): OpenVPN's pushed routes and
		// redirect-gateway, WireGuard's AllowedIPs.
		var rs []string
		for _, r := range st.Routes {
			rs = append(rs, r.String())
		}
		d.log.Info("tunnel routes", "profile", p.Name, "source", st.RoutesSource, "routes", strings.Join(rs, ","),
			"redirect_gateway", st.RedirectGateway, "reaches", reach.Describe(reach.Intersect(p.RoutesP, st.Routes)))
	}
	if changed {
		// OpenVPN pushed (new) DNS settings: rewrite the resolver files.
		// The hook does this too, so it also works while the daemon is
		// restarting.
		if err := d.writeDNSFiles(p, st.PushedDNS, st.PushedSearch); err != nil {
			d.log.Warn("write DNS files", "profile", p.Name, "err", err)
		}
	}
	d.setState(p.Name, rt, st.State, "")
	return st
}

// supervise checks every profile periodically: repairs missing tunnels with
// backoff, updates states, garbage-collects namespaces and sessions.
func (d *Daemon) supervise() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-t.C:
		}
		d.sessions.gc(d)
		d.collectRemoved()
		d.mu.Lock()
		names := profile.Names(d.profiles)
		d.mu.Unlock()
		for _, n := range names {
			p, rt := d.getProfile(n)
			if p == nil {
				continue
			}
			if !isDesired(n) {
				d.maybeDeleteNamespace(n)
				continue
			}
			if !rt.op.TryLock() {
				continue
			}
			st := d.refreshStatus(p, rt)
			if !st.Present || !netns.Exists(n) {
				rt.mu.Lock()
				due := time.Now().After(rt.retryAt)
				rt.mu.Unlock()
				if due {
					d.log.Warn("tunnel missing; restarting it", "profile", n)
					if err := d.upLocked(p, rt); err != nil {
						d.log.Error("restart failed", "profile", n, "err", err)
					}
				}
			}
			rt.op.Unlock()
		}
	}
}

// watchHostNetwork reacts to host address/route changes and resume from
// suspend by re-resolving endpoints (debounced).
func (d *Daemon) watchHostNetwork() {
	kick := make(chan struct{}, 1)
	notify := func() {
		select {
		case kick <- struct{}{}:
		default:
		}
	}
	go func() {
		ch := make(chan netlink.AddrUpdate, 64)
		done := make(chan struct{})
		if err := netlink.AddrSubscribe(ch, done); err != nil {
			d.log.Warn("address watch unavailable", "err", err)
			return
		}
		// Seed after subscribing so that no change falls between the two.
		seen := addrSet{}
		if addrs, err := netlink.AddrList(nil, netlink.FAMILY_ALL); err == nil {
			for _, a := range addrs {
				seen[addrKey(a.LinkIndex, a.IPNet)] = true
			}
		}
		for u := range ch {
			if seen.changed(u) {
				notify()
			}
		}
	}()
	go func() {
		ch := make(chan netlink.RouteUpdate, 64)
		done := make(chan struct{})
		if err := netlink.RouteSubscribe(ch, done); err != nil {
			d.log.Warn("route watch unavailable", "err", err)
			return
		}
		for u := range ch {
			// Ignore our own tunnel devices' short host-side life.
			if u.Table == 254 || u.Table == 0 {
				notify()
			}
		}
	}()
	go d.watchSleep(notify)
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-kick:
		}
		// Debounce.
		timer := time.NewTimer(2 * time.Second)
	drain:
		for {
			select {
			case <-kick:
			case <-timer.C:
				break drain
			}
		}
		d.log.Info("host network changed; refreshing tunnels")
		d.mu.Lock()
		names := profile.Names(d.profiles)
		d.mu.Unlock()
		for _, n := range names {
			p, rt := d.getProfile(n)
			if p == nil || !isDesired(n) || rt.ifname == "" {
				continue
			}
			d.backends[p.Backend].OnHostNetworkChange(d.ctx, p, rt.ifname)
		}
	}
}

// addrSet tracks host addresses so that a lifetime refresh is not taken for a
// change: every IPv6 router advertisement re-announces the SLAAC addresses
// (RTM_NEWADDR), and some routers send one every few seconds.
type addrSet map[string]bool

func addrKey(link int, ipn *net.IPNet) string {
	return fmt.Sprintf("%d %s", link, ipn)
}

// changed records u and reports whether an address appeared or went away.
func (s addrSet) changed(u netlink.AddrUpdate) bool {
	k := addrKey(u.LinkIndex, &u.LinkAddress)
	if s[k] == u.NewAddr {
		return false
	}
	if u.NewAddr {
		s[k] = true
	} else {
		delete(s, k)
	}
	return true
}

// removeHostLinks deletes vpncell tunnel devices left in the host namespace.
func removeHostLinks(log *slog.Logger) {
	links, err := netlink.LinkList()
	if err != nil {
		return
	}
	for _, l := range links {
		n := l.Attrs().Name
		if strings.HasPrefix(n, brand.WGIfPrefix) || strings.HasPrefix(n, brand.TunIfPrefix) {
			log.Info("removing stale host link", "link", n)
			netlink.LinkDel(l)
		}
	}
}

// setPingGroupRange copies the host's net.ipv4.ping_group_range into the
// profile namespace (DECISIONS.md, issue #10). The setting is per network
// namespace and starts as "1 0" (nobody) in a new one; the host's value is
// the administrator's policy for who may use ICMP datagram sockets.
func setPingGroupRange(name string) error {
	host, err := os.ReadFile(platform.PingGroupRangeFile)
	if err != nil {
		return err
	}
	v := strings.Join(strings.Fields(string(host)), " ")
	return netns.Do(name, func() error {
		cur, err := os.ReadFile(platform.PingGroupRangeFile)
		if err == nil && strings.Join(strings.Fields(string(cur)), " ") == v {
			return nil
		}
		return os.WriteFile(platform.PingGroupRangeFile, []byte(v+"\n"), 0o644)
	})
}
