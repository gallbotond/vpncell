// Package openvpn implements the OpenVPN backend (DESIGN.md §4.4): openvpn
// runs as the systemd unit vpncell-openvpn@<profile> in the host namespace
// with ifconfig-noexec/route-noexec and vpncell's own up hook, which moves
// the tun device into the profile namespace and configures it there.
package openvpn

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	sdbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/gallbotond/vpncell/internal/backend"
	"github.com/gallbotond/vpncell/internal/brand"
	"github.com/gallbotond/vpncell/internal/netns"
	"github.com/gallbotond/vpncell/internal/profile"
	"github.com/vishvananda/netlink"
)

// Pushed is what the hook records about the server's pushed settings.
type Pushed struct {
	DNS       []string `json:"dns"`
	Search    []string `json:"search"`
	Addresses []string `json:"addresses"`
	Time      int64    `json:"time"`
	// Routes the server pushed and whether it pushed redirect-gateway.
	Routes          []string `json:"routes,omitempty"`
	RedirectGateway bool     `json:"redirect_gateway,omitempty"`
	// RoutesKnown: written by a hook that records routes (older hooks
	// did not; their tunnels show no route information until reconnect).
	RoutesKnown bool `json:"routes_known,omitempty"`
}

func runDir(p string) string     { return brand.ProfileRunDir(p) }
func ConfPath(p string) string   { return filepath.Join(runDir(p), "openvpn.conf") }
func MgmtPath(p string) string   { return mgmtPath(p) }
func PushedPath(p string) string { return filepath.Join(runDir(p), "pushed.json") }
func UnitName(p string) string   { return brand.OpenVPNUnit + p + ".service" }

// mgmtPath is a variable so that tests can point it at a fake socket.
var mgmtPath = func(p string) string { return filepath.Join(runDir(p), "mgmt.sock") }

type Backend struct {
	Log  *slog.Logger
	Hook string // absolute path of vpncelld (runs "vpncelld ovpn-hook <profile>")
}

func New(log *slog.Logger, hook string) *Backend { return &Backend{Log: log, Hook: hook} }

func (b *Backend) IfPrefix() string { return brand.TunIfPrefix }

func systemd(ctx context.Context) (*sdbus.Conn, error) {
	return sdbus.NewSystemConnectionContext(context.Background())
}

// forced options always come after the imported ones.
func (b *Backend) forced(p *profile.Profile, ifname string) string {
	hook := fmt.Sprintf("%q", b.Hook+" ovpn-hook "+p.Name)
	return strings.Join([]string{
		"# --- forced by vpncell ---",
		"dev " + ifname,
		"dev-type tun",
		"ifconfig-noexec",
		"route-noexec",
		"script-security 2",
		"up " + hook,
		"down " + hook,
		"up-restart",
		"persist-tun",
		"disable-dco",
		"dns-updown disable",
		"auth-retry nointeract",
		"resolv-retry infinite",
		"management " + MgmtPath(p.Name) + " unix",
		"",
	}, "\n")
}

func (b *Backend) writeConfig(p *profile.Profile, ifname string) error {
	src, err := os.ReadFile(p.OpenVPN.Config)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(runDir(p.Name), 0o755); err != nil {
		return err
	}
	content := string(src) + "\n" + b.forced(p, ifname)
	tmp := ConfPath(p.Name) + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, ConfPath(p.Name))
}

// Up implements backend.Backend.
func (b *Backend) Up(ctx context.Context, p *profile.Profile, ifname string) error {
	if err := b.writeConfig(p, ifname); err != nil {
		return err
	}
	os.Remove(PushedPath(p.Name))
	forget(p.Name)
	retries.reset(p.Name)
	c, err := systemd(ctx)
	if err != nil {
		return fmt.Errorf("systemd: %w", err)
	}
	defer c.Close()
	ch := make(chan string, 1)
	c.ResetFailedUnitContext(ctx, UnitName(p.Name))
	if _, err := c.RestartUnitContext(ctx, UnitName(p.Name), "replace", ch); err != nil {
		return fmt.Errorf("start %s: %w", UnitName(p.Name), err)
	}
	select {
	case r := <-ch:
		if r != "done" {
			return fmt.Errorf("start %s: %s", UnitName(p.Name), r)
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	// Wait (bounded) for the first connection, so that `vpncell up` usually
	// returns with the tunnel ready; the supervisor reports later changes.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		forget(p.Name)
		if st, _ := b.Status(ctx, p, ifname); st.State == backend.StateUp {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return nil
}

// Down implements backend.Backend.
func (b *Backend) Down(ctx context.Context, p *profile.Profile, ifname string) error {
	forget(p.Name)
	if c, err := systemd(ctx); err == nil {
		ch := make(chan string, 1)
		if _, err := c.StopUnitContext(ctx, UnitName(p.Name), "replace", ch); err == nil {
			select {
			case <-ch:
			case <-time.After(20 * time.Second):
			}
		}
		c.Close()
	}
	// The tun device goes away with openvpn; remove a leftover anyway.
	if l, err := netlink.LinkByName(ifname); err == nil {
		netlink.LinkDel(l)
	}
	if netns.Exists(p.Name) {
		netns.Do(p.Name, func() error {
			if l, err := netlink.LinkByName(ifname); err == nil {
				return netlink.LinkDel(l)
			}
			return nil
		})
	}
	os.Remove(PushedPath(p.Name))
	return nil
}

func unitActive(ctx context.Context, p string) (string, error) {
	c, err := systemd(ctx)
	if err != nil {
		return "", err
	}
	defer c.Close()
	prop, err := c.GetUnitPropertyContext(ctx, UnitName(p), "ActiveState")
	if err != nil {
		return "", err
	}
	return strings.Trim(prop.Value.String(), `"`), nil
}

// Adopt implements backend.Backend.
func (b *Backend) Adopt(ctx context.Context, p *profile.Profile, ifname string) (bool, error) {
	s, err := unitActive(ctx, p.Name)
	if err != nil || (s != "active" && s != "activating" && s != "reloading") {
		return false, err
	}
	return true, nil
}

// mgmt runs management commands on one connection and returns the
// response lines of each.
func mgmt(p string, cmds ...string) ([][]string, error) {
	c, err := net.DialTimeout("unix", mgmtPath(p), 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	r := bufio.NewReader(c)
	// Banner (">INFO:...").
	if _, err := r.ReadString('\n'); err != nil {
		return nil, err
	}
	var all [][]string
	for _, cmd := range cmds {
		fmt.Fprintf(c, "%s\n", cmd)
		var out []string
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return append(all, out), err
			}
			line = strings.TrimRight(line, "\r\n")
			if strings.HasPrefix(line, ">") {
				continue // asynchronous notification
			}
			out = append(out, line)
			if line == "END" || strings.HasPrefix(line, "SUCCESS:") || strings.HasPrefix(line, "ERROR:") {
				break
			}
		}
		all = append(all, out)
	}
	return all, nil
}

type cached struct {
	at    time.Time
	state string
	since time.Time
	rx    uint64
	tx    uint64

	hist    history
	retries int
	code    string
	text    string
	hint    string
}

var (
	cacheMu sync.Mutex
	cache   = map[string]cached{}
)

// mgmtStatus asks openvpn for its state history and byte counts, at most
// every 10 s (each management connection is logged by openvpn). While the
// tunnel is not connected after a TLS error it also reads the recent log,
// to tell the kinds of TLS failure apart (diagnose.go).
func mgmtStatus(p string) (cached, error) {
	cacheMu.Lock()
	c, ok := cache[p]
	cacheMu.Unlock()
	if ok && time.Since(c.at) < 10*time.Second {
		return c, nil
	}
	res, err := mgmt(p, "state all", "load-stats")
	if err != nil {
		return cached{}, err
	}
	c = cached{at: time.Now(), state: "CONNECTING"}
	if len(res) > 0 {
		c.hist = analyze(parseHistory(res[0]))
		if c.hist.state != "" {
			c.state, c.since = c.hist.state, time.Unix(c.hist.since, 0)
		}
	}
	if len(res) > 1 {
		for _, l := range res[1] {
			if strings.HasPrefix(l, "SUCCESS:") {
				for _, kv := range strings.Split(strings.TrimPrefix(l, "SUCCESS: "), ",") {
					k, v, _ := strings.Cut(kv, "=")
					n, _ := strconv.ParseUint(v, 10, 64)
					switch k {
					case "bytesin":
						c.rx = n
					case "bytesout":
						c.tx = n
					}
				}
			}
		}
	}
	c.retries = retries.update(p, c.hist)
	var logs []logEntry
	if c.state != "CONNECTED" && c.hist.lastReason == "tls-error" && c.hist.failedReply {
		if lr, err := mgmt(p, "log 500"); err == nil && len(lr) > 0 {
			logs = parseLog(lr[0])
		}
	}
	c.code, c.text, c.hint = explain(c.hist, logs)
	cacheMu.Lock()
	cache[p] = c
	cacheMu.Unlock()
	return c, nil
}

func forget(p string) {
	cacheMu.Lock()
	delete(cache, p)
	cacheMu.Unlock()
}

// Status implements backend.Backend.
func (b *Backend) Status(ctx context.Context, p *profile.Profile, ifname string) (backend.Status, error) {
	var st backend.Status
	st.LogHint = "journalctl -u " + UnitName(p.Name)
	active, _ := unitActive(ctx, p.Name)
	if active == "failed" {
		st.State = "failed: openvpn exited (see journalctl -u " + UnitName(p.Name) + ")"
		return st, nil
	}
	netns.Do(p.Name, func() error {
		l, err := netlink.LinkByName(ifname)
		if err != nil {
			return nil
		}
		st.Present = true
		_ = l
		addrs, _ := netlink.AddrList(l, netlink.FAMILY_ALL)
		for _, a := range addrs {
			if a.Scope != 0 {
				continue
			}
			if ap, ok := netip.AddrFromSlice(a.IP); ok {
				ones, _ := a.Mask.Size()
				st.Addresses = append(st.Addresses, netip.PrefixFrom(ap.Unmap(), ones))
			}
		}
		return nil
	})
	linkPresent := st.Present
	// openvpn creates the device when it connects, so before the first
	// connect it may be absent. Once connected, a missing device means the
	// tunnel is broken (for example deleted): report it, so the supervisor
	// restarts the unit.
	st.Present = active == "active" || active == "activating"
	ms, err := mgmtStatus(p.Name)
	if err != nil {
		st.State = backend.StateConnecting
		return st, nil
	}
	if ms.code != "" {
		st.Reason, st.ReasonText, st.Hint = ms.code, ms.text, ms.hint
		st.ReasonAt = unixTime(ms.hist.lastAt)
	}
	st.Retries = ms.retries
	st.LostAt = unixTime(ms.hist.lostAt)
	switch ms.state {
	case "CONNECTED":
		if !linkPresent {
			st.Present = false
			st.State = "failed: tunnel interface missing"
			forget(p.Name)
			return st, nil
		}
		st.State = backend.StateUp
		st.ConnectedAt = ms.since
	case "EXITING":
		st.State = "failed: openvpn is exiting"
	default:
		st.State = backend.StateConnecting
	}
	st.RxBytes, st.TxBytes = ms.rx, ms.tx
	if data, err := os.ReadFile(PushedPath(p.Name)); err == nil {
		var pu Pushed
		if json.Unmarshal(data, &pu) == nil {
			for _, d := range pu.DNS {
				if a, err := netip.ParseAddr(d); err == nil {
					st.PushedDNS = append(st.PushedDNS, a)
				}
			}
			st.PushedSearch = pu.Search
		}
		if pu.RoutesKnown {
			st.RoutesSource = "pushed"
			st.RedirectGateway = pu.RedirectGateway
			for _, r := range pu.Routes {
				if pf, err := netip.ParsePrefix(r); err == nil {
					st.Routes = append(st.Routes, pf)
				}
			}
			// The tunnel subnet is always reachable.
			for _, a := range pu.Addresses {
				if pf, err := netip.ParsePrefix(a); err == nil {
					st.Routes = append(st.Routes, pf.Masked())
				}
			}
			if pu.RedirectGateway {
				st.Routes = append(st.Routes, netip.MustParsePrefix("0.0.0.0/0"))
			}
		}
	}
	return st, nil
}

// OnHostNetworkChange asks a connected openvpn to reconnect at once (it
// resolves the remote again by itself). One that is still connecting or
// waiting to retry gets no signal (issue #31): it resolves the remote on its
// next attempt anyway, and a SIGUSR1 during its restart pause starts the
// pause again, so steady host network changes would keep it from ever
// connecting.
func (b *Backend) OnHostNetworkChange(ctx context.Context, p *profile.Profile, ifname string) {
	forget(p.Name)
	state, sent, err := reconnectIfConnected(p.Name)
	if err != nil {
		b.Log.Debug("openvpn reconnect signal", "profile", p.Name, "err", err)
		return
	}
	if !sent {
		b.Log.Debug("openvpn not connected; no reconnect signal", "profile", p.Name, "state", state)
	}
}

// reconnectIfConnected sends SIGUSR1 if openvpn's current state is
// CONNECTED and returns that state.
func reconnectIfConnected(p string) (state string, sent bool, err error) {
	res, err := mgmt(p, "state")
	if err != nil {
		return "", false, err
	}
	if len(res) > 0 {
		if h := parseHistory(res[0]); len(h) > 0 {
			state = h[len(h)-1].state
		}
	}
	if state != "CONNECTED" {
		return state, false, nil
	}
	if _, err := mgmt(p, "signal SIGUSR1"); err != nil {
		return state, false, err
	}
	return state, true, nil
}
