//go:build integration

package integration

import (
	"os"
	"strings"
	"testing"
	"time"
)

// Issue #10: ping works in a profile session, IPv4 and IPv6, without
// giving the session any capability.

func hostPingRange(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("/proc/sys/net/ipv4/ping_group_range")
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(strings.Fields(string(b)), " ")
}

func pingOK(t *testing.T, profile string, args ...string) {
	t.Helper()
	r := inProfile(t, userAllowed, profile, append([]string{"ping", "-c", "1", "-W", "5"}, args...)...)
	if r.code != 0 || !strings.Contains(r.stdout, "1 received") {
		t.Fatalf("ping %v in %s: %v", args, profile, r)
	}
}

func checkPingRange(t *testing.T, profile string) {
	t.Helper()
	r := inProfile(t, userAllowed, profile, "cat", "/proc/sys/net/ipv4/ping_group_range")
	if got := strings.Join(strings.Fields(r.stdout), " "); r.code != 0 || got != hostPingRange(t) {
		t.Fatalf("ping_group_range in %s = %q, host %q (%v)", profile, got, hostPingRange(t), r)
	}
}

func TestPingLab(t *testing.T) {
	forEachSet(t, func(t *testing.T, s profileSet) {
		ensureUp(t, s.a)
		checkPingRange(t, s.a)
		srv := theLab.Servers[s.sa]
		pingOK(t, s.a, "10.99.0.53")
		pingOK(t, s.a, "-6", srv.TunAddr6.Addr().String())
		// Still no capabilities in the session (the binary just runs
		// without its file capabilities).
		r := inProfile(t, userAllowed, s.a, "grep", "-E", "^(CapEff|CapPrm|CapBnd|NoNewPrivs)", "/proc/self/status")
		for _, want := range []string{"CapEff:\t0000000000000000", "CapPrm:\t0000000000000000", "CapBnd:\t0000000000000000", "NoNewPrivs:\t1"} {
			if !strings.Contains(r.stdout, want) {
				t.Fatalf("session privileges: %v", r)
			}
		}
	})
}

// The test VM: ping the DNS server behind the OpenVPN tunnel (IPv4 and
// IPv6) and behind the WireGuard tunnel (IPv4).
func TestPingVM(t *testing.T) {
	if !useVM {
		t.Skip("VPNCELL_TEST_VM=0")
	}
	ensureUp(t, "vm-ovpn", "vm-wg")
	waitFor(t, 30*time.Second, "vm-ovpn up", func() bool { return statusOf(t, "vm-ovpn").State == "up" })
	pingOK(t, "vm-ovpn", "172.30.2.53")
	pingOK(t, "vm-ovpn", "-6", "fd00:30:2::53")
	pingOK(t, "vm-wg", "172.30.1.53")
}

// A namespace adopted after a daemon restart gets the setting again (for
// example one made by a version without this fix).
func TestPingAdoptedNamespace(t *testing.T) {
	s := labSets()[0]
	ensureUp(t, s.a)
	if out, err := netnsExec(s.a, "sysctl", "-qw", "net.ipv4.ping_group_range=1 0"); err != nil {
		t.Fatalf("reset: %v %s", err, out)
	}
	if out, err := sh("systemctl restart vpncelld"); err != nil {
		t.Fatalf("restart: %v %s", err, out)
	}
	waitFor(t, 30*time.Second, "daemon back", func() bool { return root(t, "list").code == 0 })
	waitFor(t, 30*time.Second, "ping_group_range restored", func() bool {
		out, _ := netnsExec(s.a, "cat", "/proc/sys/net/ipv4/ping_group_range")
		return strings.Join(strings.Fields(out), " ") == hostPingRange(t)
	})
	checkPingRange(t, s.a)
	pingOK(t, s.a, "10.99.0.53")
}
