//go:build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Package lifecycle (prompt §10, DESIGN.md §13): installing a newer .deb
// does not interrupt active profiles or sessions; removing the package
// tears everything down; purging removes the configuration.
//
// Runs only from test/scripts/package-test.sh, which installs the first
// package and sets VPNCELL_TEST_PACKAGE to the second one.
func TestPackageUpgradeAndRemove(t *testing.T) {
	next := os.Getenv("VPNCELL_TEST_PACKAGE")
	if next == "" || !installed {
		t.Skip("run through test/scripts/package-test.sh")
	}
	apt := func(args ...string) {
		t.Helper()
		cmd := exec.Command("apt-get", append([]string{"-y", "-q"}, args...)...)
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("apt-get %v: %v\n%s", args, err, out)
		}
	}
	ver := func() string {
		out, _ := exec.Command("dpkg-query", "-W", "-f=${Version}", "vpncell").Output()
		return string(out)
	}
	v1 := ver()
	sets := labSets()
	var loops []*loop
	for _, s := range sets {
		ensureUp(t, s.a)
		l := startLoop(t, s.a)
		loops = append(loops, l)
		defer l.stop()
		waitFor(t, 30*time.Second, "loop ok "+s.name, func() bool { return l.okCount() > 0 })
	}
	for _, l := range loops {
		l.reset()
	}
	cap := startCapture(t)
	apt("install", next)
	if v2 := ver(); v2 == v1 {
		t.Fatalf("version did not change (%s)", v1)
	}
	time.Sleep(4 * time.Second)
	for i, l := range loops {
		if !l.alive() || l.failCount() > 0 || l.okCount() == 0 {
			t.Errorf("%s: interrupted by the upgrade: alive=%v ok=%d fail=%d", sets[i].name, l.alive(), l.okCount(), l.failCount())
		}
	}
	waitFor(t, 15*time.Second, "daemon back", func() bool { return root(t, "list").code == 0 })
	for _, s := range sets {
		if st := statusOf(t, s.a); st.State != "up" || len(st.Sessions) == 0 {
			t.Errorf("%s after upgrade: %+v", s.a, st)
		}
	}
	cap.assertNoLeaks()

	// Remove: everything torn down, profiles kept.
	vc(t, browserUser, "firefox-setup", "--user")
	apt("remove", "vpncell")
	waitFor(t, 10*time.Second, "sessions ended", func() bool {
		for _, l := range loops {
			if l.alive() {
				return false
			}
		}
		return true
	})
	if ents, _ := filepath.Glob("/run/netns/vpncell-*"); len(ents) > 0 {
		t.Errorf("namespaces left after remove: %v", ents)
	}
	if out, _ := exec.Command("ip", "-o", "link").Output(); strings.Contains(string(out), "vpnwg") || strings.Contains(string(out), "vpntun") {
		t.Errorf("tunnel links left after remove:\n%s", out)
	}
	if out, _ := exec.Command("systemctl", "list-units", "--no-legend", "--all", "vpncell*", "vpncelld*").Output(); strings.Contains(string(out), "active") && !strings.Contains(string(out), "inactive") {
		t.Errorf("units left after remove:\n%s", out)
	}
	for _, f := range []string{"/usr/lib/mozilla/native-messaging-hosts/vpncell.json", credsOf(browserUser).home + "/.mozilla/native-messaging-hosts/vpncell.json", "/run/vpncell", "/usr/sbin/vpncelld"} {
		if _, err := os.Stat(f); err == nil {
			t.Errorf("%s left after remove", f)
		}
	}
	if out, _ := exec.Command("ss", "-Hltnp").Output(); strings.Contains(string(out), "vpncelld") || strings.Contains(string(out), "127.0.0.1:70") {
		t.Errorf("SOCKS listeners left after remove:\n%s", out)
	}
	if _, err := os.Stat("/etc/vpncell/profiles.d/" + sets[0].a + ".toml"); err != nil {
		t.Errorf("profiles removed by remove (they must stay until purge)")
	}
	apt("purge", "vpncell")
	if _, err := os.Stat("/etc/vpncell"); err == nil {
		t.Errorf("/etc/vpncell left after purge")
	}
	if out, _ := exec.Command("getent", "group", "vpncell").Output(); len(out) > 0 {
		t.Errorf("group vpncell left after purge")
	}
}
