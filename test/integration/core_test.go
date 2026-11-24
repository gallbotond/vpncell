//go:build integration

package integration

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gallbotond/vpncell/internal/control"
)

func marker() string {
	b := make([]byte, 6)
	rand.Read(b)
	return "leak" + hex.EncodeToString(b)
}

func statusOf(t testing.TB, profile string) control.ProfileStatus {
	t.Helper()
	r := root(t, "status", "--json", profile)
	if r.code != 0 {
		t.Fatalf("status: %v", r)
	}
	var st []control.ProfileStatus
	if err := json.Unmarshal([]byte(r.stdout), &st); err != nil || len(st) != 1 {
		t.Fatalf("status json: %v %q", err, r.stdout)
	}
	return st[0]
}

// Step 1: bring a profile up and down.
func TestUpDown(t *testing.T) {
	forEachSet(t, func(t *testing.T, s profileSet) {
		p := s.a
		ensureDown(t, p)
		if _, err := os.Stat("/run/netns/vpncell-" + p); err == nil {
			t.Fatalf("namespace exists while down")
		}
		ensureUp(t, p)
		if _, err := os.Stat("/run/netns/vpncell-" + p); err != nil {
			t.Fatalf("namespace missing while up: %v", err)
		}
		waitFor(t, 30*time.Second, "state up", func() bool { return statusOf(t, p).State == "up" })
		ifn := tunnelIf(t, p)
		if ifn == "" {
			t.Fatalf("no tunnel interface in namespace")
		}
		// Only lo and the tunnel inside.
		out, _ := netnsExec(p, "ip", "-o", "link", "show")
		if n := strings.Count(strings.TrimSpace(out), "\n") + 1; n != 2 {
			t.Fatalf("namespace has %d interfaces, want lo + tunnel:\n%s", n, out)
		}
		// The tunnel device is not left in the host namespace.
		if _, err := run("", "ip", "-o", "link", "show", ifn); err == nil {
			t.Fatalf("tunnel device %s visible in host namespace", ifn)
		}
		// nftables second layer present.
		if out, _ := netnsExec(p, "nft", "list", "table", "inet", "vpncell"); !strings.Contains(out, "policy drop") {
			t.Fatalf("nftables table missing:\n%s", out)
		}
		ensureDown(t, p)
		if _, err := os.Stat("/run/netns/vpncell-" + p); err == nil {
			t.Fatalf("namespace still exists after down")
		}
		if st := statusOf(t, p); st.State != "down" {
			t.Fatalf("state after down = %q", st.State)
		}
	})
}

// Required test "Isolation" (shell part): two profiles with overlapping
// 10.99.0.0/24 reach their own server at the same time.
func TestIsolationOverlap(t *testing.T) {
	forEachSet(t, func(t *testing.T, s profileSet) {
		ensureUp(t, s.a, s.b)
		var wg sync.WaitGroup
		errs := make(chan error, 40)
		for i := 0; i < 10; i++ {
			for _, pair := range [][2]string{{s.a, s.sa}, {s.b, s.sb}} {
				wg.Add(1)
				go func(prof, server string) {
					defer wg.Done()
					r := inProfile(t, userAllowed, prof, "curl", "-sS", "-m", "10", "http://10.99.0.10/")
					if r.code != 0 || !strings.Contains(r.stdout, "lab-server "+server+"<") {
						errs <- fmt.Errorf("%s: want server %s, got %v", prof, server, r)
					}
				}(pair[0], pair[1])
			}
		}
		wg.Wait()
		close(errs)
		for e := range errs {
			t.Error(e)
		}
	})
}

// Step 1 acceptance: the exit IP through the real VPN.
func TestVMExitIP(t *testing.T) {
	for _, p := range vmProfiles() {
		p := p
		t.Run(p, func(t *testing.T) {
			ensureUp(t, p)
			r := inProfile(t, userAllowed, p, "curl", "-sS", "-m", "20", "https://ifconfig.me")
			if r.code != 0 || strings.TrimSpace(r.stdout) != vmEndpoint {
				t.Fatalf("exit IP: want %s, got %v", vmEndpoint, r)
			}
			host, _ := run("", "curl", "-sS", "-m", "20", "https://ifconfig.me")
			if strings.TrimSpace(host) == vmEndpoint {
				t.Fatalf("host itself exits through the VPN endpoint; test is meaningless")
			}
			want := map[string]string{"vm-wg": "WireGuard", "vm-ovpn": "OpenVPN"}[p]
			r = inProfile(t, userAllowed, p, "curl", "-sS", "-m", "10", "http://172.30.0.80/")
			if r.code != 0 || !strings.Contains(r.stdout, want) {
				t.Fatalf("172.30.0.80 via %s: want page %q, got %v", p, want, r)
			}
		})
	}
}

// Required test "Fail closed" (shell part): with the tunnel removed or down,
// nothing gets out; with and without the nftables layer. The capture on the
// physical interface must show no leak.
func TestFailClosedShell(t *testing.T) {
	for _, nft := range []bool{true, false} {
		nft := nft
		t.Run(fmt.Sprintf("nftables=%v", nft), func(t *testing.T) {
			forEachSet(t, func(t *testing.T, s profileSet) {
				p := s.a
				setNftables(t, p, nft)
				defer setNftables(t, p, true)
				ensureUp(t, p)
				if r := inProfile(t, userAllowed, p, "curl", "-sS", "-m", "5", "http://10.99.0.10/"); r.code != 0 {
					t.Fatalf("baseline: %v", r)
				}
				ifn := tunnelIf(t, p)
				mk := marker()
				cap := startCapture(t)
				// 1. Interface down.
				if out, err := netnsExec(p, "ip", "link", "set", ifn, "down"); err != nil {
					t.Fatalf("link down: %v %s", err, out)
				}
				probeBlocked(t, p, mk)
				// 2. Interface removed.
				if out, err := netnsExec(p, "ip", "link", "del", ifn); err != nil {
					t.Fatalf("link del: %v %s", err, out)
				}
				probeBlocked(t, p, mk)
				cap.assertNoLeaks(mk)
				// The supervisor restores the tunnel.
				waitFor(t, 60*time.Second, "tunnel restored", func() bool {
					return inProfile(t, userAllowed, p, "curl", "-sS", "-m", "3", "http://10.99.0.10/").code == 0
				})
			})
		})
	}
}

// probeBlocked tries several ways out of a profile; all must fail.
func probeBlocked(t *testing.T, p, mk string) {
	t.Helper()
	probes := [][]string{
		{"curl", "-sS", "-m", "3", "http://10.99.0.10/"},
		{"curl", "-sS", "-m", "3", "http://1.1.1.1/"},
		{"curl", "-sS", "-m", "3", "-6", "http://[2606:4700:4700::1111]/"},
		{"curl", "-sS", "-m", "3", "http://" + mk + ".example.com/"},
		{"getent", "hosts", mk + ".lab.test"},
		{"ping", "-c", "1", "-W", "2", "1.1.1.1"},
	}
	for _, pr := range probes {
		if r := inProfile(t, userAllowed, p, pr...); r.code == 0 {
			t.Errorf("fail closed violated: %v succeeded: %v", pr, r)
		}
	}
}

// setNftables toggles the in-namespace nftables layer (test-only setting)
// and restarts the profile.
func setNftables(t *testing.T, p string, on bool) {
	t.Helper()
	path := filepath.Join("/etc/vpncell/profiles.d", p+".toml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if i := strings.Index(s, "\n[security]"); i >= 0 {
		s = s[:i+1]
	}
	if !on {
		s += "\n[security]\nnftables = false\n"
	}
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	ensureDown(t, p)
	if r := root(t, "reload"); r.code != 0 {
		t.Fatalf("reload: %v", r)
	}
	ensureUp(t, p)
	out, _ := netnsExec(p, "nft", "list", "table", "inet", "vpncell")
	if on != strings.Contains(out, "policy drop") {
		t.Fatalf("nftables=%v not applied:\n%s", on, out)
	}
}

// Required test "Access control" (session part; SOCKS part is in step 3).
func TestAccessControlExec(t *testing.T) {
	s := labSets()[0]
	ensureUp(t, s.a)
	if r := inProfile(t, userAllowed, s.a, "true"); r.code != 0 {
		t.Fatalf("allowed user refused: %v", r)
	}
	r := inProfile(t, userDenied, s.a, "true")
	if r.code == 0 || !strings.Contains(r.stderr, "no profile") {
		t.Fatalf("user without permission got a session: %v", r)
	}
	if r := vc(t, userDenied, "list"); strings.Contains(r.stdout, s.a) {
		t.Fatalf("profile visible to a user without permission: %v", r)
	}
	if r := vc(t, userDenied, "up", s.a); r.code == 0 {
		t.Fatalf("user without permission brought the profile up: %v", r)
	}
	r = inProfile(t, userNoGroup, s.a, "true")
	if r.code == 0 || !strings.Contains(r.stderr, "permission denied") {
		t.Fatalf("user outside the group reached the daemon: %v", r)
	}
	if r := vc(t, userAllowed, "import", "x", "/dev/null"); r.code == 0 {
		t.Fatalf("non-root import succeeded: %v", r)
	}
}

// Required test "Import safety" (WireGuard): hooks and unsafe keys are
// stripped or rejected, and nothing from the config ever runs.
func TestImportSafetyWireGuard(t *testing.T) {
	// t-evil reuses the wg1 client key, which takes over the lab server's
	// session; restart t-wg1 afterwards so later tests get a fresh handshake.
	defer func() { ensureDown(t, "t-wg1"); ensureUp(t, "t-wg1") }()
	canary := filepath.Join(os.TempDir(), "vpncell-canary-"+marker())
	defer os.Remove(canary)
	base, err := os.ReadFile(theLab.Servers["wg1"].ClientConfig)
	if err != nil {
		t.Fatal(err)
	}
	evil := strings.Replace(string(base), "[Interface]\n", fmt.Sprintf(
		"[Interface]\nPreUp = touch %[1]s\nPostUp = touch %[1]s\nPreDown = touch %[1]s\nPostDown = touch %[1]s\nSaveConfig = true\nTable = off\nFwMark = 0x80000\nListenPort = 51111\n", canary), 1)
	path := filepath.Join(t.TempDir(), "evil.conf")
	os.WriteFile(path, []byte(evil), 0o600)
	r := root(t, "import", "--replace", "--user", userAllowed, "t-evil", path)
	if r.code != 0 {
		t.Fatalf("import: %v", r)
	}
	for _, k := range []string{"PreUp", "PostUp", "PreDown", "PostDown", "SaveConfig", "Table", "FwMark", "ListenPort"} {
		if !strings.Contains(r.stdout, k+" (line") {
			t.Errorf("report does not list stripped %s:\n%s", k, r.stdout)
		}
	}
	stored, _ := os.ReadFile("/etc/vpncell/secrets/t-evil/wg.conf")
	if strings.Contains(string(stored), canary) {
		t.Fatalf("hook survived in stored config")
	}
	ensureUp(t, "t-evil")
	if r := inProfile(t, userAllowed, "t-evil", "curl", "-sS", "-m", "5", "http://10.99.0.10/"); r.code != 0 {
		t.Fatalf("sanitized profile does not work: %v", r)
	}
	ensureDown(t, "t-evil")
	if _, err := os.Stat(canary); err == nil {
		t.Fatalf("a hook from the imported config ran")
	}
	defer os.Remove("/etc/vpncell/profiles.d/t-evil.toml")
	defer os.RemoveAll("/etc/vpncell/secrets/t-evil")

	// Rejected outright.
	for name, cfg := range map[string]string{
		"amnezia": strings.Replace(string(base), "[Interface]\n", "[Interface]\nJc = 4\n", 1),
		"unknown": strings.Replace(string(base), "[Interface]\n", "[Interface]\nExecStart = /bin/sh\n", 1),
		"section": string(base) + "\n[Hooks]\nRun = x\n",
	} {
		p := filepath.Join(t.TempDir(), name+".conf")
		os.WriteFile(p, []byte(cfg), 0o600)
		r := root(t, "import", "t-rej", p)
		if r.code == 0 || !strings.Contains(r.stderr, "rejected") {
			t.Errorf("%s: import not rejected: %v", name, r)
		}
		if _, err := os.Stat("/etc/vpncell/profiles.d/t-rej.toml"); err == nil {
			t.Errorf("%s: rejected profile was stored", name)
			os.Remove("/etc/vpncell/profiles.d/t-rej.toml")
		}
	}
}
