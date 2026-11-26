// Package daemon is vpncelld: profiles, namespaces, tunnels, supervision,
// the control socket, sessions and SOCKS servers.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/activation"
	"github.com/gallbotond/vpncell/internal/backend"
	"github.com/gallbotond/vpncell/internal/backend/wireguard"
	"github.com/gallbotond/vpncell/internal/brand"
	"github.com/gallbotond/vpncell/internal/netns"
	"github.com/gallbotond/vpncell/internal/profile"
	"golang.org/x/sys/unix"
)

// Daemon is the running vpncelld.
type Daemon struct {
	log      *slog.Logger
	ctx      context.Context
	global   *profile.Global
	state    *stateStore
	backends map[string]backend.Backend
	events   *broker
	hostNS   netns.ID

	// loadMu serializes loading profiles and removing them (reload, import,
	// remove, SIGHUP).
	loadMu   sync.Mutex
	mu       sync.Mutex
	profiles map[string]*profile.Profile
	rt       map[string]*rtProfile
	// removed: namespaces of removed profiles that sessions still use
	// (issue #17). supervise deletes each once its sessions end.
	removed map[string]bool

	// fds inherited from systemd's store, by name
	stored map[string]*os.File

	sessions *sessionTable
	exts     []extension
	socks    *socksManager
}

// extension lets later build steps hook into the daemon lifecycle without
// growing this file (SOCKS, OpenVPN).
type extension interface {
	profileUp(p *profile.Profile, rt *rtProfile)
	profileDown(p *profile.Profile, rt *rtProfile)
	reload(profiles map[string]*profile.Profile)
}

// rtProfile is the runtime state of one profile.
type rtProfile struct {
	op      sync.Mutex // serializes up/down/repair
	name    string
	ifname  string
	factory *netns.Factory
	mu      sync.Mutex // guards fields below
	state   string
	status  backend.Status
	lastErr string
	exitIP  string
	upSince time.Time
	backoff time.Duration
	retryAt time.Time
	// pushedKey remembers the last pushed DNS written to the resolver files.
	pushedKey string
	// routesKey remembers the last logged tunnel routes (issue #15).
	routesKey string
	// removed is set (under op) when the profile is removed, so a request
	// that looked it up before cannot bring it up again (issue #17).
	removed bool
}

func (r *rtProfile) getState() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state == "" {
		return backend.StateDown
	}
	return r.state
}

// Options configure the daemon.
type Options struct {
	Log *slog.Logger
	// Reload receives SIGHUP: re-read profiles.
	Reload <-chan os.Signal
}

// Run starts the daemon and blocks until ctx is done.
func Run(ctx context.Context, opt Options) error {
	if os.Geteuid() != 0 {
		return errors.New("vpncelld must run as root")
	}
	unix.Umask(0o022)
	d := &Daemon{
		log:      opt.Log,
		ctx:      ctx,
		rt:       map[string]*rtProfile{},
		removed:  map[string]bool{},
		events:   newBroker(),
		stored:   map[string]*os.File{},
		sessions: newSessionTable(),
	}
	var err error
	if d.hostNS, err = netns.HostID(); err != nil {
		return err
	}
	if d.global, err = profile.LoadGlobal(); err != nil {
		return err
	}
	if d.state, err = loadState(); err != nil {
		return err
	}
	d.backends = map[string]backend.Backend{
		profile.BackendWireGuard: wireguard.New(d.log),
	}
	d.registerExtensions()
	if v, err := os.ReadFile("/proc/sys/net/ipv4/ip_unprivileged_port_start"); err == nil {
		if n, _ := strconv.Atoi(string(trimNL(v))); n < d.global.PortHi+1 {
			d.log.Warn("net.ipv4.ip_unprivileged_port_start is low; unprivileged users could bind SOCKS ports while the daemon is stopped", "value", n)
		}
	}
	for _, f := range activation.Files(true) {
		d.stored[f.Name()] = f
	}
	for _, dir := range []string{brand.RunDir, filepath.Join(brand.RunDir, "profiles"), filepath.Join(brand.RunDir, "state"), filepath.Join(brand.RunDir, "sessions")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	os.Chmod(filepath.Join(brand.RunDir, "state"), 0o700)
	os.Chmod(filepath.Join(brand.RunDir, "sessions"), 0o700)

	d.loadProfiles()
	if _, err := os.Stat(bootedMarker()); err != nil {
		d.log.Info("first start since boot: removing leftovers")
		d.cleanupLeftovers()
		os.WriteFile(bootedMarker(), []byte(time.Now().Format(time.RFC3339)+"\n"), 0o644)
		d.adoptOrStart(true)
	} else {
		d.log.Info("daemon restart: adopting existing profiles")
		d.adoptOrStart(false)
	}

	d.socks.start()
	ln, err := d.controlListener()
	if err != nil {
		return err
	}
	go d.serveControl(ln)
	go d.supervise()
	go d.watchHostNetwork()
	if opt.Reload != nil {
		go func() {
			for range opt.Reload {
				d.log.Info("SIGHUP: reloading profiles")
				d.loadProfiles()
			}
		}()
	}
	sdNotify("READY=1\nSTATUS=running")
	d.log.Info("vpncelld ready", "socket", brand.ControlSock)
	<-ctx.Done()
	sdNotify("STOPPING=1")
	ln.Close()
	d.shutdown()
	return nil
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}

// controlListener returns the control socket, from systemd's fd store if a
// previous daemon left it there, so clients never see "connection refused"
// across restarts.
func (d *Daemon) controlListener() (*net.UnixListener, error) {
	if f, ok := d.stored["control"]; ok {
		delete(d.stored, "control")
		if st, err := os.Stat(brand.ControlSock); err != nil || st.Mode()&os.ModeSocket == 0 {
			// The path was removed (for example /run/vpncell was wiped):
			// the stored socket is unreachable, replace it.
			d.log.Warn("stored control socket has no path; creating a new one")
			f.Close()
			sdNotify("FDSTOREREMOVE=1\nFDNAME=control")
			goto fresh
		}
		l, err := net.FileListener(f)
		f.Close()
		if err == nil {
			if ul, ok := l.(*net.UnixListener); ok {
				ul.SetUnlinkOnClose(false)
				d.fixSocketPerms()
				d.log.Info("control socket taken from the fd store")
				return ul, nil
			}
			l.Close()
		}
	}
fresh:
	os.Remove(brand.ControlSock)
	old := unix.Umask(0o117)
	ul, err := net.ListenUnix("unix", &net.UnixAddr{Name: brand.ControlSock, Net: "unix"})
	unix.Umask(old)
	if err != nil {
		return nil, err
	}
	ul.SetUnlinkOnClose(false)
	d.fixSocketPerms()
	if err := storeFD("control", ul); err != nil {
		d.log.Warn("fd store", "err", err)
	}
	return ul, nil
}

func (d *Daemon) fixSocketPerms() {
	gid := 0
	if g, err := user.LookupGroup(brand.Group); err == nil {
		gid, _ = strconv.Atoi(g.Gid)
	} else {
		d.log.Warn("group missing; only root can use the control socket", "group", brand.Group)
	}
	os.Chown(brand.ControlSock, 0, gid)
	os.Chmod(brand.ControlSock, 0o660)
}

func (d *Daemon) loadProfiles() {
	d.loadMu.Lock()
	defer d.loadMu.Unlock()
	d.loadProfilesLocked()
}

// loadProfilesLocked re-reads the profile files. A profile whose file is
// gone while it is in use is taken down (its sessions keep running without
// network); one whose file is still there but no longer loads keeps its
// running version, so a typo in an edit does not cut a live tunnel
// (issue #17). Callers hold loadMu.
func (d *Daemon) loadProfilesLocked() {
	ps, errs := profile.LoadAll()
	for _, e := range errs {
		d.log.Error("profile not loaded", "err", e)
	}
	d.mu.Lock()
	old := d.profiles
	d.mu.Unlock()
	for _, name := range profile.Names(old) {
		if _, ok := ps[name]; ok {
			continue
		}
		p, rt := d.getProfile(name)
		if rt == nil || !d.inUse(name) {
			continue
		}
		if _, err := os.Stat(profilePath(name)); err == nil {
			d.log.Error("profile file no longer loads; keeping the running version until it is fixed or the profile is removed", "profile", name)
			ps[name] = p
			continue
		}
		n := d.sessions.countLive(name)
		d.log.Warn("profile file removed while the profile is in use; taking it down", "profile", name, "sessions", n)
		rt.op.Lock()
		if err := d.downLocked(p, rt, true, false); err != nil {
			d.log.Error("take down removed profile", "profile", name, "err", err)
		}
		rt.removed = true
		rt.op.Unlock()
	}
	d.mu.Lock()
	d.profiles = ps
	for name := range ps {
		if _, ok := d.rt[name]; !ok {
			d.rt[name] = &rtProfile{name: name}
		}
	}
	var gone []string
	for name := range d.rt {
		if _, ok := ps[name]; !ok {
			gone = append(gone, name)
			delete(d.rt, name)
		}
	}
	d.mu.Unlock()
	for _, name := range gone {
		d.forgetProfile(name)
	}
	d.state.prune(func(name string) bool {
		if ps[name] != nil {
			return true
		}
		// A file that does not load keeps its index and port.
		_, err := os.Lstat(profilePath(name))
		return err == nil
	})
	for _, e := range d.exts {
		e.reload(ps)
	}
}

// inUse reports whether a profile is up, has a namespace or has sessions.
func (d *Daemon) inUse(name string) bool {
	return isDesired(name) || netns.Exists(name) || d.sessions.countLive(name) > 0
}

// forgetProfile frees the runtime directory of a profile that no longer
// exists or, while its sessions still use the namespace, marks the
// namespace for supervise. (Its index and port go in state.prune.)
func (d *Daemon) forgetProfile(name string) {
	if netns.Exists(name) {
		d.mu.Lock()
		d.removed[name] = true
		d.mu.Unlock()
		return
	}
	os.RemoveAll(brand.ProfileRunDir(name))
}

// collectRemoved deletes the namespaces of removed profiles once their last
// session ended.
func (d *Daemon) collectRemoved() {
	d.mu.Lock()
	var names []string
	for n := range d.removed {
		if _, ok := d.profiles[n]; ok {
			// Imported again under the same name: the namespace is its.
			delete(d.removed, n)
			continue
		}
		names = append(names, n)
	}
	d.mu.Unlock()
	for _, n := range names {
		if netns.Exists(n) && d.sessions.countLive(n) > 0 {
			continue
		}
		d.mu.Lock()
		_, back := d.profiles[n]
		delete(d.removed, n)
		d.mu.Unlock()
		if back {
			continue
		}
		if netns.Exists(n) {
			d.log.Info("last session of a removed profile ended; deleting its namespace", "profile", n)
			if err := netns.Delete(n); err != nil {
				d.log.Warn("delete namespace", "profile", n, "err", err)
			}
		}
		os.RemoveAll(brand.ProfileRunDir(n))
	}
}

func profilePath(name string) string {
	return filepath.Join(brand.ProfilesDir(), name+".toml")
}

func (d *Daemon) getProfile(name string) (*profile.Profile, *rtProfile) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.profiles[name], d.rt[name]
}

func (d *Daemon) ifname(p *profile.Profile) (string, error) {
	n, err := d.state.index(p.Name)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%d", d.backends[p.Backend].IfPrefix(), n), nil
}

// cleanupLeftovers runs on the first start after boot (or after a crash that
// lost /run): stale namespaces, host-side tunnel links.
func (d *Daemon) cleanupLeftovers() {
	names, _ := netns.List()
	for _, n := range names {
		d.log.Info("removing stale namespace", "profile", n)
		netns.Delete(n)
	}
	removeHostLinks(d.log)
	d.cleanupOpenVPNUnits()
	ents, _ := os.ReadDir(filepath.Join(brand.RunDir, "profiles"))
	for _, e := range ents {
		os.RemoveAll(filepath.Join(brand.RunDir, "profiles", e.Name()))
	}
}

// adoptOrStart takes over profiles left by a previous daemon and starts
// autostart=boot profiles.
func (d *Daemon) adoptOrStart(boot bool) {
	d.mu.Lock()
	ps := d.profiles
	d.mu.Unlock()
	if !boot {
		// Sessions first: an unknown profile's namespace stays while its
		// sessions run.
		d.sessions.adopt(d)
		names, _ := netns.List()
		for _, n := range names {
			p, rt := d.getProfile(n)
			if p == nil {
				d.log.Warn("namespace of a profile that no longer exists; stopping its tunnel", "profile", n)
				d.stopUnknownTunnel(n)
				setDesired(n, false)
				if d.sessions.countLive(n) == 0 {
					d.log.Info("removing namespace of unknown profile", "profile", n)
					netns.Delete(n)
					os.RemoveAll(brand.ProfileRunDir(n))
				} else {
					d.mu.Lock()
					d.removed[n] = true
					d.mu.Unlock()
				}
				continue
			}
			d.adopt(p, rt)
		}
	}
	for _, name := range profile.Names(ps) {
		p, rt := d.getProfile(name)
		if p.Autostart == profile.AutostartBoot && rt.getState() == backend.StateDown {
			if err := d.up(p, rt); err != nil {
				d.log.Error("autostart failed", "profile", name, "err", err)
			}
		}
	}
}

func (d *Daemon) adopt(p *profile.Profile, rt *rtProfile) {
	rt.op.Lock()
	defer rt.op.Unlock()
	ifn, err := d.ifname(p)
	if err != nil {
		return
	}
	rt.ifname = ifn
	if !isDesired(p.Name) {
		// Namespace kept for sessions after `down --force`.
		d.setState(p.Name, rt, backend.StateDown, "")
		return
	}
	ok, err := d.backends[p.Backend].Adopt(d.ctx, p, ifn)
	if err != nil || !ok {
		d.log.Warn("tunnel not found after restart; bringing it up again", "profile", p.Name, "err", err)
		if err := d.upLocked(p, rt); err != nil {
			d.log.Error("re-up failed", "profile", p.Name, "err", err)
		}
		return
	}
	if err := d.prepareNamespace(p, ifn); err != nil {
		d.log.Error("adopt: namespace setup", "profile", p.Name, "err", err)
	}
	if err := d.startRuntime(p, rt); err != nil {
		d.log.Error("adopt: runtime", "profile", p.Name, "err", err)
	}
	rt.mu.Lock()
	rt.upSince = time.Now()
	rt.mu.Unlock()
	d.refreshStatus(p, rt)
	for _, e := range d.exts {
		e.profileUp(p, rt)
	}
	d.log.Info("adopted profile", "profile", p.Name, "interface", ifn)
}

func (d *Daemon) shutdown() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, rt := range d.rt {
		if rt.factory != nil {
			rt.factory.Close()
		}
	}
	// Namespaces, tunnels, OpenVPN units and sessions stay; the next daemon
	// adopts them.
}

// storeFD hands a listener's descriptor to systemd's fd store. It uses the
// raw descriptor: os.File.Fd() on a dup would switch the shared file
// description to blocking mode and break the listener's poller.
func storeFD(name string, l syscall.Conn) error {
	rc, err := l.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	err = rc.Control(func(fd uintptr) {
		serr = sdNotify("FDSTORE=1\nFDNAME="+name, int(fd))
	})
	if err != nil {
		return err
	}
	return serr
}
