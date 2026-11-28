//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// Issue #15: a split-tunnel profile says what it reaches, at import and in
// status; DNS outside it and missing DNS are reported. There is no
// fallback to the host connection.

func TestReachSplitWireGuard(t *testing.T) {
	srv, err := theLab.AddWireGuard("wg5", 5)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(srv.ClientConfig)
	if err != nil {
		t.Fatal(err)
	}
	split := strings.Replace(string(b), "AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = 10.99.0.0/24", 1)
	split = strings.Replace(split, "DNS = 10.99.0.53, lab.test", "DNS = 10.99.0.53, 192.0.2.53, lab.test", 1)
	f := filepath.Join(t.TempDir(), "split.conf")
	os.WriteFile(f, []byte(split), 0o600)
	const p = "t-split"
	r := root(t, "import", "--replace", "--user", userAllowed, p, f)
	if r.code != 0 {
		t.Fatalf("import: %v", r)
	}
	defer func() {
		root(t, "down", "--kill", p)
		os.Remove("/etc/vpncell/profiles.d/" + p + ".toml")
		os.RemoveAll("/etc/vpncell/secrets/" + p)
		root(t, "reload")
	}()
	out := r.stdout + r.stderr
	for _, want := range []string{"reaches only 10.99.0.0/24; no IPv6", "never falls back", "DNS server 192.0.2.53 is outside AllowedIPs"} {
		if !strings.Contains(out, want) {
			t.Fatalf("import output lacks %q:\n%s", want, out)
		}
	}
	ensureUp(t, p)
	// Inside the allowed range it works; outside it fails at once, and
	// never through the host.
	if r := inProfile(t, userAllowed, p, "curl", "-sS", "-m", "10", "http://10.99.0.10/"); r.code != 0 {
		t.Fatalf("lab web through the split tunnel: %v", r)
	}
	if r := inProfile(t, userAllowed, p, "curl", "-sS", "-m", "5", "http://10.99.1.10/"); r.code == 0 {
		t.Fatalf("address outside AllowedIPs answered: %v", r)
	}
	st := statusOf(t, p)
	if st.RoutesSource != "allowed-ips" || !st.SplitTunnel || st.Reaches != "only 10.99.0.0/24; no IPv6" ||
		!slices.Equal(st.Routes, []string{"10.99.0.0/24"}) || st.NoDNS || !slices.Equal(st.DNSUnreachable, []string{"192.0.2.53"}) {
		t.Fatalf("status: %+v", st)
	}
	r = root(t, "status", p)
	for _, want := range []string{"reaches:        only 10.99.0.0/24; no IPv6", "other addresses fail", "not reachable through the tunnel: 192.0.2.53"} {
		if !strings.Contains(r.stdout, want) {
			t.Fatalf("status lacks %q:\n%s", want, r.stdout)
		}
	}
	// A full-tunnel profile has no such notes.
	full := statusOf(t, "t-wg1")
	if full.State == "up" && (full.SplitTunnel || full.Reaches != "all IPv4; all IPv6") {
		t.Fatalf("full tunnel: %+v", full)
	}
}

// No DNS at all: import and status say that hostnames fail.
func TestReachNoDNS(t *testing.T) {
	b, err := os.ReadFile(theLab.Servers["wg4"].ClientConfig)
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "nodns.conf")
	os.WriteFile(f, []byte(strings.Replace(string(b), "DNS = 10.99.0.53, lab.test\n", "", 1)), 0o600)
	const p = "t-nodns"
	r := root(t, "import", "--replace", "--user", userAllowed, p, f)
	defer func() {
		os.Remove("/etc/vpncell/profiles.d/" + p + ".toml")
		os.RemoveAll("/etc/vpncell/secrets/" + p)
		root(t, "reload")
	}()
	if r.code != 0 || !strings.Contains(r.stdout+r.stderr, "no DNS servers: hostnames fail") {
		t.Fatalf("import: %v", r)
	}
}

// OpenVPN on the test VM: the server pushes 172.30.0.0/16 and 2000::/3,
// no redirect-gateway. Status shows them; the daemon logs them.
func TestReachVMOpenVPN(t *testing.T) {
	if !useVM {
		t.Skip("VPNCELL_TEST_VM=0")
	}
	// Up first, so that the down/up below is a reconnect with the same
	// routes: each connection logs its routes, not only a change.
	ensureUp(t, "vm-ovpn")
	waitFor(t, 30*time.Second, "vm-ovpn up", func() bool { return statusOf(t, "vm-ovpn").State == "up" })
	root(t, "down", "--kill", "vm-ovpn")
	// journalctl --since has whole seconds: start the window after
	// everything the first connection logged.
	time.Sleep(1100 * time.Millisecond)
	since := time.Now().Format("2006-01-02 15:04:05")
	ensureUp(t, "vm-ovpn")
	waitFor(t, 30*time.Second, "vm-ovpn up", func() bool { return statusOf(t, "vm-ovpn").State == "up" })
	st := statusOf(t, "vm-ovpn")
	if st.RoutesSource != "pushed" || st.RedirectGateway || !st.SplitTunnel ||
		!slices.Contains(st.Routes, "172.30.0.0/16") || !slices.Contains(st.Routes, "2000::/3") ||
		!strings.Contains(st.Reaches, "IPv6 internet (2000::/3)") {
		t.Fatalf("status: %+v", st)
	}
	if !slices.Equal(st.DNS, []string{"172.30.2.53"}) || len(st.DNSUnreachable) != 0 {
		t.Fatalf("pushed DNS inside the pushed routes: %+v", st)
	}
	r := root(t, "status", "vm-ovpn")
	if !strings.Contains(r.stdout, "server routes:") || !strings.Contains(r.stdout, "no redirect-gateway") {
		t.Fatalf("status text:\n%s", r.stdout)
	}
	waitFor(t, 20*time.Second, "routes in the daemon log", func() bool {
		out, _ := sh("journalctl -u vpncelld --since '" + since + "' --no-pager -o cat")
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, "tunnel routes") && strings.Contains(l, "profile=vm-ovpn") &&
				strings.Contains(l, "172.30.0.0/16") && strings.Contains(l, "redirect_gateway=false") {
				return true
			}
		}
		return false
	})
	// Import warns that the config has no redirect-gateway.
	r = root(t, "import", "--replace", "--user", userAllowed, "vm-reachimp", filepath.Join(vmConfigs, "vm-ovpn.ovpn"))
	defer func() {
		os.Remove("/etc/vpncell/profiles.d/vm-reachimp.toml")
		os.RemoveAll("/etc/vpncell/secrets/vm-reachimp")
		root(t, "reload")
	}()
	if r.code != 0 || !strings.Contains(r.stdout+r.stderr, "no redirect-gateway") {
		t.Fatalf("import: %v", r)
	}
}
