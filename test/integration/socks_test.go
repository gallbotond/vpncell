//go:build integration

package integration

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gallbotond/vpncell/internal/client"
	"github.com/gallbotond/vpncell/internal/control"
	"golang.org/x/net/proxy"
)

type socksInfo struct {
	host, user, pass string
	port             int
}

func (s socksInfo) addr() string { return fmt.Sprintf("%s:%d", s.host, s.port) }

// socksOf asks the daemon for a profile's SOCKS details as a user.
func socksOf(t testing.TB, user, profile string) (socksInfo, result) {
	t.Helper()
	r := vc(t, user, "socks", profile)
	if r.code != 0 {
		return socksInfo{}, r
	}
	u, err := url.Parse(strings.TrimSpace(r.stdout))
	if err != nil {
		t.Fatalf("socks url: %v", err)
	}
	pw, _ := u.User.Password()
	var port int
	fmt.Sscanf(u.Port(), "%d", &port)
	return socksInfo{u.Hostname(), u.User.Username(), pw, port}, r
}

func socksClient(s socksInfo, timeout time.Duration) *http.Client {
	d, _ := proxy.SOCKS5("tcp", s.addr(), &proxy.Auth{User: s.user, Password: s.pass}, &net.Dialer{Timeout: timeout})
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		DialContext:       d.(proxy.ContextDialer).DialContext,
		DisableKeepAlives: true,
	}}
}

func socksGet(s socksInfo, u string, timeout time.Duration) (string, error) {
	resp, err := socksClient(s, timeout).Get(u)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

// Required test "Isolation" (SOCKS part).
func TestSocksIsolation(t *testing.T) {
	forEachSet(t, func(t *testing.T, s profileSet) {
		ensureUp(t, s.a, s.b)
		pa, r := socksOf(t, userAllowed, s.a)
		if r.code != 0 {
			t.Fatal(r)
		}
		pb, _ := socksOf(t, userAllowed, s.b)
		if pa.port == pb.port || pa.port >= 1024 || pa.host != "127.0.0.1" {
			t.Fatalf("ports: %d %d", pa.port, pb.port)
		}
		for _, target := range []string{"http://10.99.0.10/", "http://web.lab.test/", "http://web/"} {
			var wg sync.WaitGroup
			for _, x := range []struct {
				p      socksInfo
				server string
			}{{pa, s.sa}, {pb, s.sb}} {
				wg.Add(1)
				go func(p socksInfo, server string) {
					defer wg.Done()
					body, err := socksGet(p, target, 10*time.Second)
					if err != nil || !strings.Contains(body, "lab-server "+server+"<") {
						t.Errorf("%s via port %d: want %s, got %q %v", target, p.port, server, body, err)
					}
				}(x.p, x.server)
			}
			wg.Wait()
		}
	})
}

// Required test "Thread safety": thousands of concurrent SOCKS connections
// across four profiles to the same overlapping address; every answer must
// come from the right server, and the SIOCGSKNS check must never trip.
// Also with GOMAXPROCS=1 and with very frequent GC.
func TestSocksStress(t *testing.T) {
	profiles := stressProfiles()
	if len(profiles) < 4 {
		t.Fatalf("need 4 profiles, have %d", len(profiles))
	}
	for _, variant := range []struct{ name, env string }{
		{"default", ""},
		{"gomaxprocs1", "GOMAXPROCS=1"},
		{"gogc1", "GOGC=1"},
	} {
		variant := variant
		t.Run(variant.name, func(t *testing.T) {
			setDaemonEnv(t, variant.env)
			defer setDaemonEnv(t, "")
			for _, p := range profiles {
				ensureUp(t, p[0])
			}
			before := debugCounters(t)
			const perProfile = 600
			const concurrency = 64
			var bad, good atomic.Int64
			var wg sync.WaitGroup
			sem := make(chan struct{}, concurrency)
			var firstErr sync.Once
			for _, p := range profiles {
				info, r := socksOf(t, userAllowed, p[0])
				if r.code != 0 {
					t.Fatal(r)
				}
				for i := 0; i < perProfile; i++ {
					wg.Add(1)
					sem <- struct{}{}
					go func(info socksInfo, server string) {
						defer wg.Done()
						defer func() { <-sem }()
						body, err := rawSocksHTTP(info, "10.99.0.10", 80, 15*time.Second)
						if err != nil || !strings.Contains(body, "lab-server "+server+"<") {
							bad.Add(1)
							firstErr.Do(func() { t.Errorf("profile %s: want %s, got %q %v", info.addr(), server, trim(body), err) })
							return
						}
						good.Add(1)
					}(info, p[1])
				}
			}
			wg.Wait()
			after := debugCounters(t)
			if bad.Load() > 0 {
				t.Errorf("%d of %d requests failed or reached the wrong server", bad.Load(), bad.Load()+good.Load())
			}
			if m := after["socket_namespace_mismatches"] - before["socket_namespace_mismatches"]; m != 0 && after["socket_namespace_mismatches"] >= before["socket_namespace_mismatches"] {
				t.Errorf("%d sockets were created in the wrong namespace", m)
			}
			if after["socket_namespace_mismatches"] != 0 {
				t.Errorf("namespace mismatch counter = %d", after["socket_namespace_mismatches"])
			}
			t.Logf("%d requests ok; sockets created by the daemon: %d", good.Load(), after["sockets_created"])
		})
	}
}

func trim(s string) string {
	if len(s) > 120 {
		return s[:120]
	}
	return s
}

// rawSocksHTTP does a SOCKS5 CONNECT (IP literal) and an HTTP/1.0 GET by
// hand, so that every request uses a new connection.
func rawSocksHTTP(s socksInfo, host string, port int, timeout time.Duration) (string, error) {
	d, _ := proxy.SOCKS5("tcp", s.addr(), &proxy.Auth{User: s.user, Password: s.pass}, &net.Dialer{Timeout: timeout})
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c, err := d.(proxy.ContextDialer).DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	fmt.Fprintf(c, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
	b, err := io.ReadAll(c)
	return string(b), err
}

func debugCounters(t testing.TB) map[string]uint64 {
	t.Helper()
	c, err := client.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r, files, err := c.Do(control.Request{Type: "debug"})
	control.CloseFiles(files)
	if err != nil {
		t.Fatal(err)
	}
	return r.Debug
}

// setDaemonEnv restarts the daemon with extra environment (a runtime
// drop-in; empty removes it). Profiles and sessions survive the restart.
func setDaemonEnv(t testing.TB, env string) {
	t.Helper()
	dir := "/run/systemd/system/vpncelld.service.d"
	path := filepath.Join(dir, "50-test-env.conf")
	if env == "" {
		if _, err := os.Stat(path); err != nil {
			return
		}
		os.Remove(path)
	} else {
		os.MkdirAll(dir, 0o755)
		os.WriteFile(path, []byte("[Service]\nEnvironment="+env+"\n"), 0o644)
	}
	if out, err := sh("systemctl daemon-reload && systemctl restart vpncelld"); err != nil {
		t.Fatalf("restart daemon: %v %s", err, out)
	}
	waitFor(t, 15*time.Second, "daemon back", func() bool { return root(t, "list").code == 0 })
}

// Required test "Access control" (SOCKS part).
func TestSocksAccessControl(t *testing.T) {
	sets := labSets()
	s := sets[0]
	ensureUp(t, s.a, s.b)
	if _, r := socksOf(t, userDenied, s.a); r.code == 0 {
		t.Fatalf("user without permission got SOCKS credentials: %v", r)
	}
	if _, r := socksOf(t, userNoGroup, s.a); r.code == 0 || !strings.Contains(r.stderr, "permission denied") {
		t.Fatalf("user outside the group reached the daemon: %v", r)
	}
	pa, _ := socksOf(t, userAllowed, s.a)
	pb, _ := socksOf(t, userAllowed, s.b)
	if pa.user == pb.user || pa.pass == pb.pass {
		t.Fatalf("profiles share credentials")
	}
	// A's credentials on B's port, wrong password, no auth method.
	cross := socksInfo{pb.host, pa.user, pa.pass, pb.port}
	if _, err := socksGet(cross, "http://10.99.0.10/", 5*time.Second); err == nil {
		t.Errorf("profile A's credentials accepted on profile B's port")
	}
	wrong := pa
	wrong.pass = strings.Repeat("0", len(pa.pass))
	if _, err := socksGet(wrong, "http://10.99.0.10/", 5*time.Second); err == nil {
		t.Errorf("wrong password accepted")
	}
	c, err := net.Dial("tcp", pa.addr())
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte{5, 1, 0}) // only "no authentication"
	b := make([]byte, 2)
	io.ReadFull(c, b)
	c.Close()
	if b[1] != 0xff {
		t.Errorf("no-auth method accepted: %v", b)
	}
	// UDP ASSOCIATE is not supported.
	if code := rawSocksCmd(t, pa, 3); code != 7 {
		t.Errorf("UDP ASSOCIATE reply %d, want 7", code)
	}
	// Listeners are on 127.0.0.1 only and privileged ports.
	out, _ := run("", "ss", "-Hltnp")
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "vpncelld") && !strings.Contains(l, "127.0.0.1:") {
			t.Errorf("listener not on 127.0.0.1: %s", l)
		}
	}
}

// rawSocksCmd authenticates and sends a request with the given command,
// returning the reply code.
func rawSocksCmd(t *testing.T, s socksInfo, cmd byte) byte {
	c, err := net.DialTimeout("tcp", s.addr(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	c.Write([]byte{5, 1, 2})
	b := make([]byte, 2)
	io.ReadFull(c, b)
	auth := []byte{1, byte(len(s.user))}
	auth = append(auth, s.user...)
	auth = append(auth, byte(len(s.pass)))
	auth = append(auth, s.pass...)
	c.Write(auth)
	io.ReadFull(c, b)
	if b[1] != 0 {
		t.Fatalf("auth failed")
	}
	req := []byte{5, cmd, 0, 1, 10, 99, 0, 10}
	req = binary.BigEndian.AppendUint16(req, 80)
	c.Write(req)
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		return 0xff
	}
	return rep[1]
}

// Required test "Fail closed" (SOCKS part): tunnel removed, profile down
// (manual autostart): requests fail; nothing leaves the physical interface.
func TestSocksFailClosed(t *testing.T) {
	forEachSet(t, func(t *testing.T, s profileSet) {
		p := s.a
		ensureUp(t, p)
		info, _ := socksOf(t, userAllowed, p)
		if _, err := socksGet(info, "http://10.99.0.10/", 5*time.Second); err != nil {
			t.Fatalf("baseline: %v", err)
		}
		mk := marker()
		cap := startCapture(t)
		netnsExec(p, "ip", "link", "del", tunnelIf(t, p))
		for _, u := range []string{"http://10.99.0.10/", "http://1.1.1.1/", "http://" + mk + ".example.com/", "http://[2606:4700:4700::1111]/"} {
			if body, err := socksGet(info, u, 4*time.Second); err == nil {
				t.Errorf("tunnel removed, but %s worked: %q", u, trim(body))
			}
		}
		waitFor(t, 60*time.Second, "tunnel restored", func() bool {
			_, err := socksGet(info, "http://10.99.0.10/", 3*time.Second)
			return err == nil
		})
		// Profile down with autostart=manual: general failure.
		setAutostart(t, p, "manual")
		defer setAutostart(t, p, "on-use")
		ensureDown(t, p)
		if code := rawSocksCmd(t, info, 1); code != 1 {
			t.Errorf("profile down: reply %d, want 1 (general failure)", code)
		}
		cap.assertNoLeaks(mk)
		// autostart=on-use: the first request brings the profile up.
		setAutostart(t, p, "on-use")
		if body, err := socksGet(info, "http://10.99.0.10/", 20*time.Second); err != nil || !strings.Contains(body, s.sa) {
			t.Errorf("on-use autostart via SOCKS: %q %v", trim(body), err)
		}
	})
}

func setAutostart(t *testing.T, p, mode string) {
	t.Helper()
	path := filepath.Join("/etc/vpncell/profiles.d", p+".toml")
	data, _ := os.ReadFile(path)
	lines := strings.Split(string(data), "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "autostart") {
			lines[i] = fmt.Sprintf("autostart = %q", mode)
		}
	}
	os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600)
	if r := root(t, "reload"); r.code != 0 {
		t.Fatal(r)
	}
}

// Required test "DNS" (SOCKS part): names in SOCKS requests are resolved in
// the namespace with the profile's DNS only.
func TestSocksDNS(t *testing.T) {
	forEachSet(t, func(t *testing.T, s profileSet) {
		ensureUp(t, s.a, s.b)
		pa, _ := socksOf(t, userAllowed, s.a)
		mk := marker()
		cap := startCapture(t)
		ba, bb := len(theLab.DNSQueries(s.sa)), len(theLab.DNSQueries(s.sb))
		socksGet(pa, "http://"+mk+".lab.test/", 5*time.Second)
		socksGet(pa, "http://"+mk+"/", 5*time.Second) // search domain
		qa := strings.Join(theLab.DNSQueries(s.sa)[ba:], " ")
		qb := strings.Join(theLab.DNSQueries(s.sb)[bb:], " ")
		if !strings.Contains(qa, mk+".lab.test.") {
			t.Errorf("query did not reach the profile's DNS: %s", qa)
		}
		if strings.Contains(qb, mk) {
			t.Errorf("query reached another profile's DNS")
		}
		// The host resolver never saw it.
		if out, _ := sh("journalctl -u systemd-resolved --since -1min --no-pager"); strings.Contains(out, mk) {
			t.Errorf("host resolver saw the marker")
		}
		cap.assertNoLeaks(mk)
	})
}

// Required test "No host or LAN access" (SOCKS part).
func TestSocksNoHostOrLAN(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "HOST-DEV-SERVER") }))
	port := ln.Addr().(*net.TCPAddr).Port
	lanIP, gw := hostLAN(t)
	for _, nft := range []bool{true, false} {
		nft := nft
		t.Run(fmt.Sprintf("nftables=%v", nft), func(t *testing.T) {
			forEachSet(t, func(t *testing.T, s profileSet) {
				setNftables(t, s.a, nft)
				defer setNftables(t, s.a, true)
				info, _ := socksOf(t, userAllowed, s.a)
				for _, u := range []string{
					fmt.Sprintf("http://127.0.0.1:%d/", port), fmt.Sprintf("http://localhost:%d/", port),
					fmt.Sprintf("http://%s:%d/", lanIP, port), "http://" + gw + "/", "http://127.0.0.53:53/",
				} {
					if body, err := socksGet(info, u, 4*time.Second); err == nil || strings.Contains(body, "HOST-") {
						t.Errorf("reachable via SOCKS: %s -> %q", u, trim(body))
					}
				}
			})
		})
	}
}

// Required test "Daemon restart" (SOCKS part): new connections made while
// the daemon restarts wait in the listen backlog and succeed.
func TestSocksDaemonRestart(t *testing.T) {
	forEachSet(t, func(t *testing.T, s profileSet) {
		ensureUp(t, s.a)
		info, _ := socksOf(t, userAllowed, s.a)
		var ok, fail atomic.Int64
		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				body, err := rawSocksHTTP(info, "10.99.0.10", 80, 15*time.Second)
				if err == nil && strings.Contains(body, s.sa) {
					ok.Add(1)
				} else {
					fail.Add(1)
					t.Logf("request failed: %v", err)
				}
				time.Sleep(100 * time.Millisecond)
			}
		}()
		cap := startCapture(t)
		time.Sleep(time.Second)
		for _, how := range []string{"systemctl restart vpncelld", "systemctl kill -s KILL vpncelld"} {
			if out, err := sh(how); err != nil {
				t.Fatalf("%s: %v %s", how, err, out)
			}
			time.Sleep(4 * time.Second)
		}
		close(stop)
		wg.Wait()
		cap.assertNoLeaks()
		if fail.Load() > 0 || ok.Load() < 10 {
			t.Fatalf("across restarts: ok=%d fail=%d", ok.Load(), fail.Load())
		}
		// Same port and credentials after the restarts.
		after, _ := socksOf(t, userAllowed, s.a)
		if after != info {
			t.Errorf("SOCKS details changed across restart: %v -> %v", info.port, after.port)
		}
	})
}

// SOCKS against the real VPN: exit IP and the VM's own DNS.
func TestVMSocks(t *testing.T) {
	for _, p := range vmProfiles() {
		p := p
		t.Run(p, func(t *testing.T) {
			ensureUp(t, p)
			info, _ := socksOf(t, userAllowed, p)
			mk := marker()
			cap := startCapture(t)
			body, err := socksGet(info, "https://ifconfig.me/ip", 20*time.Second)
			if err != nil || !isVMExit(t, body) {
				t.Errorf("exit IP via SOCKS: %q %v", body, err)
			}
			body, err = socksGet(info, "http://whoami.vpn-lab.test/", 10*time.Second)
			if err != nil || !strings.Contains(body, "Hostname:") {
				t.Errorf("VPN DNS via SOCKS: %q %v", trim(body), err)
			}
			socksGet(info, "http://"+mk+".example.com/", 5*time.Second)
			cap.stop()
			if cap.tunnelPackets() == 0 {
				t.Errorf("no tunnel packets captured")
			}
			cap.assertNoLeaks(mk)
		})
	}
}

// Secrets (private keys, SOCKS credentials) never appear in the journal.
func TestNoSecretsInJournal(t *testing.T) {
	var secrets []string
	for _, s := range labSets() {
		for _, p := range []string{s.a, s.b} {
			info, r := socksOf(t, userAllowed, p)
			if r.code == 0 {
				secrets = append(secrets, info.user, info.pass)
			}
		}
	}
	for _, f := range []string{"/etc/vpncell/secrets/t-wg1/wg.conf", "/etc/vpncell/secrets/vm-wg/wg.conf"} {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(l, "PrivateKey = ") || strings.HasPrefix(l, "PresharedKey = ") {
				secrets = append(secrets, strings.TrimSpace(strings.SplitN(l, "=", 2)[1]))
			}
		}
	}
	if len(secrets) < 4 {
		t.Fatalf("collected only %d secrets", len(secrets))
	}
	out, _ := sh("journalctl -u vpncelld -u 'vpncell-openvpn@*' --since -3h --no-pager -o cat")
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Errorf("a secret appears in the journal")
		}
	}
}
