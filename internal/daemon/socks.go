package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gallbotond/vpncell/internal/backend"
	"github.com/gallbotond/vpncell/internal/brand"
	"github.com/gallbotond/vpncell/internal/control"
	"github.com/gallbotond/vpncell/internal/dnsfiles"
	"github.com/gallbotond/vpncell/internal/netns"
	"github.com/gallbotond/vpncell/internal/profile"
	"github.com/gallbotond/vpncell/internal/socks"
)

type socksEntry struct {
	srv  *socks.Server
	ln   net.Listener
	port int
}

type socksCreds struct {
	User Secret `json:"-"`
	Pass Secret `json:"-"`
}

// socksManager owns one SOCKS listener per configured profile.
type socksManager struct {
	d       *Daemon
	started bool // serving starts after adoption, so no request sees a half-adopted profile
	mu      sync.Mutex
	m       map[string]*socksEntry
	creds   map[string]socksCreds
}

func credsPath() string { return filepath.Join(brand.RunDir, "state", "socks-credentials.json") }

func (sm *socksManager) loadCreds() {
	sm.creds = map[string]socksCreds{}
	data, err := os.ReadFile(credsPath())
	if err != nil {
		return
	}
	var raw map[string][2]string
	if json.Unmarshal(data, &raw) != nil {
		return
	}
	for k, v := range raw {
		sm.creds[k] = socksCreds{Secret(v[0]), Secret(v[1])}
	}
}

func (sm *socksManager) saveCredsLocked() {
	raw := map[string][2]string{}
	for k, v := range sm.creds {
		raw[k] = [2]string{v.User.Reveal(), v.Pass.Reveal()}
	}
	data, _ := json.Marshal(raw)
	os.MkdirAll(filepath.Dir(credsPath()), 0o700)
	if err := dnsfiles.WriteAtomic(credsPath(), string(data), 0o600); err != nil {
		sm.d.log.Error("save SOCKS credentials", "err", err)
	}
}

func (d *Daemon) registerExtensions() {
	sm := &socksManager{d: d, m: map[string]*socksEntry{}}
	sm.loadCreds()
	d.socks = sm
	d.exts = append(d.exts, sm)
	d.registerOpenVPN()
}

func (sm *socksManager) profileUp(p *profile.Profile, rt *rtProfile) {
	go sm.d.probeExitIP(p, rt)
}

func (sm *socksManager) profileDown(p *profile.Profile, rt *rtProfile) {
	sm.mu.Lock()
	e := sm.m[p.Name]
	sm.mu.Unlock()
	if e != nil {
		e.srv.CloseActive()
	}
}

// reload makes the set of listeners match the profiles.
func (sm *socksManager) reload(ps map[string]*profile.Profile) {
	d := sm.d
	sm.mu.Lock()
	defer sm.mu.Unlock()
	changed := false
	for name, e := range sm.m {
		p := ps[name]
		want := 0
		if p != nil {
			want, _ = d.state.port(name, p.Socks.Port, d.global.PortLo, d.global.PortHi)
		}
		if p == nil || want != e.port {
			e.srv.Stop()
			sdNotify("FDSTOREREMOVE=1\nFDNAME=socks-" + name)
			delete(sm.m, name)
			if p == nil {
				delete(sm.creds, name)
				changed = true
			}
		}
	}
	for name := range sm.creds {
		if ps[name] == nil {
			delete(sm.creds, name)
			changed = true
		}
	}
	for name, p := range ps {
		if _, ok := sm.m[name]; ok {
			continue
		}
		port, err := d.state.port(name, p.Socks.Port, d.global.PortLo, d.global.PortHi)
		if err != nil {
			d.log.Error("SOCKS port", "profile", name, "err", err)
			continue
		}
		ln, err := sm.listener(name, port)
		if err != nil {
			d.log.Error("SOCKS listen", "profile", name, "port", port, "err", err)
			continue
		}
		c, ok := sm.creds[name]
		if !ok {
			c = socksCreds{Secret(randomHex(16)), Secret(randomHex(16))}
			sm.creds[name] = c
			changed = true
			d.events.publish(control.Event{Kind: "credentials_changed", Profile: name})
		}
		srv := &socks.Server{Profile: name, Log: d.log, Backend: &socksBackend{d: d, name: name}}
		srv.SetCredentials(c.User.Reveal(), c.Pass.Reveal())
		sm.m[name] = &socksEntry{srv: srv, ln: ln, port: port}
		if sm.started {
			go srv.Serve(ln)
		}
		d.log.Info("SOCKS listener", "profile", name, "addr", ln.Addr().String())
	}
	if changed {
		sm.saveCredsLocked()
	}
	// Stored listeners of profiles that no longer exist.
	for name, f := range d.stored {
		if strings.HasPrefix(name, "socks-") {
			f.Close()
			delete(d.stored, name)
			sdNotify("FDSTOREREMOVE=1\nFDNAME=" + name)
		}
	}
}

// listener takes the profile's listening socket from systemd's fd store, or
// binds a new one and stores it. A stored socket keeps the port bound while
// the daemon restarts; connections wait in the backlog.
func (sm *socksManager) listener(name string, port int) (net.Listener, error) {
	d := sm.d
	key := "socks-" + name
	if f, ok := d.stored[key]; ok {
		delete(d.stored, key)
		l, err := net.FileListener(f)
		f.Close()
		if err == nil {
			if ta, ok := l.Addr().(*net.TCPAddr); ok && ta.Port == port && ta.IP.Equal(net.IPv4(127, 0, 0, 1)) {
				return l, nil
			}
			l.Close()
		}
		sdNotify("FDSTOREREMOVE=1\nFDNAME=" + key)
	}
	l, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, err
	}
	if err := storeFD(key, l.(*net.TCPListener)); err != nil {
		d.log.Warn("fd store", "err", err)
	}
	return l, nil
}

// start serves all listeners. Until then connections wait in the backlog.
func (sm *socksManager) start() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.started {
		return
	}
	sm.started = true
	for _, e := range sm.m {
		go e.srv.Serve(e.ln)
	}
}

func (d *Daemon) socksPort(p *profile.Profile) int {
	if d.socks == nil {
		return 0
	}
	d.socks.mu.Lock()
	defer d.socks.mu.Unlock()
	if e := d.socks.m[p.Name]; e != nil {
		return e.port
	}
	return 0
}

func (d *Daemon) handleSocks(c *caller, name string) (*control.Response, error) {
	p, _, err := d.allowedProfile(c, name)
	if err != nil {
		return nil, err
	}
	d.socks.mu.Lock()
	e := d.socks.m[p.Name]
	cr := d.socks.creds[p.Name]
	d.socks.mu.Unlock()
	if e == nil {
		return nil, control.Errorf(control.ErrInternal, "no SOCKS listener for %q", p.Name)
	}
	d.log.Info("SOCKS credentials handed out", "profile", p.Name, "uid", c.UID)
	return &control.Response{Type: "ok", Socks: &control.SocksInfo{
		Host: "127.0.0.1", Port: e.port, Username: cr.User.Reveal(), Password: cr.Pass.Reveal(),
	}}, nil
}

// socksBackend gives the SOCKS server the profile's factory and resolver.
// A profile that is not up makes every request fail; autostart=on-use
// profiles are brought up by the first request.
type socksBackend struct {
	d    *Daemon
	name string
}

func (b *socksBackend) Get(ctx context.Context) (*netns.Factory, *socks.Resolver, error) {
	d := b.d
	p, rt := d.getProfile(b.name)
	if p == nil {
		return nil, nil, fmt.Errorf("profile removed")
	}
	if !isDesired(p.Name) {
		if p.Autostart != profile.AutostartOnUse {
			return nil, nil, fmt.Errorf("profile is down")
		}
		if err := d.ensureUp(p, rt); err != nil {
			return nil, nil, err
		}
	}
	d.mu.Lock()
	f := rt.factory
	d.mu.Unlock()
	if f == nil {
		return nil, nil, fmt.Errorf("profile is not up")
	}
	rt.mu.Lock()
	st := rt.status
	rt.mu.Unlock()
	servers, search := d.dnsFor(p, st.PushedDNS, st.PushedSearch)
	return f, &socks.Resolver{Factory: f, Servers: servers, Search: search}, nil
}

// probeExitIP fetches the profile's exit_ip_url through the tunnel (opt-in,
// it contacts a third party).
func (d *Daemon) probeExitIP(p *profile.Profile, rt *rtProfile) {
	if p.Status.ExitIPURL == "" {
		return
	}
	b := &socksBackend{d: d, name: p.Name}
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			f, res, err := b.Get(ctx)
			if err != nil {
				return nil, err
			}
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			addrs, err := res.Lookup(ctx, host)
			if err != nil {
				return nil, err
			}
			var pn uint16
			fmt.Sscanf(port, "%d", &pn)
			var lastErr error
			for _, a := range addrs {
				c, err := f.Dial(ctx, "tcp", netip.AddrPortFrom(a, pn))
				if err == nil {
					return c, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}}
	for attempt := 0; attempt < 3; attempt++ {
		if !isDesired(p.Name) {
			return
		}
		resp, err := client.Get(p.Status.ExitIPURL)
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
			resp.Body.Close()
			ip := strings.TrimSpace(string(body))
			if a, err := netip.ParseAddr(ip); err == nil {
				rt.mu.Lock()
				rt.exitIP = a.String()
				rt.mu.Unlock()
				d.events.publish(control.Event{Kind: "profile_changed", Profile: p.Name, State: rt.getState()})
				return
			}
		}
		time.Sleep(5 * time.Second)
	}
}

var _ = backend.StateUp
