//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Issue #17: `vpncell remove` and profiles whose file disappears.

var rmServer struct {
	once sync.Once
	conf string
	err  error
}

// rmConfig returns the client config of a lab server used only by these
// tests, so they never take over another profile's WireGuard session.
func rmConfig(t *testing.T) string {
	rmServer.once.Do(func() {
		s, err := theLab.AddWireGuard("wg6", 6)
		if err != nil {
			rmServer.err = err
			return
		}
		rmServer.conf = s.ClientConfig
	})
	if rmServer.err != nil {
		t.Fatal(rmServer.err)
	}
	return rmServer.conf
}

const rmProfile = "t-rm"

func importRm(t *testing.T, name, conf string) {
	t.Helper()
	if err := importProfile(name, conf); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		root(t, "down", "--kill", name)
		root(t, "remove", "--kill", name)
		os.Remove("/etc/vpncell/profiles.d/" + name + ".toml")
		os.RemoveAll("/etc/vpncell/secrets/" + name)
		root(t, "reload")
	})
}

// bgSession runs a long command in the profile as the allowed user and
// returns a function that ends it (killing the client hangs up the session).
func bgSession(t *testing.T, profile string) func() {
	t.Helper()
	c := credsOf(userAllowed)
	cmd := exec.Command(cliPath, "run", "-T", profile, "--", "sleep", "600")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: c.uid, Gid: c.gid, Groups: c.groups}}
	cmd.Dir = "/tmp"
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "session start", func() bool { return len(statusOf(t, profile).Sessions) == 1 })
	pid := statusOf(t, profile).Sessions[0].PID
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cmd.Process.Kill()
			cmd.Wait()
		})
	}
	t.Cleanup(stop)
	t.Cleanup(func() { syscall.Kill(pid, syscall.SIGKILL) })
	return stop
}

func pidAlive(pid int) bool { return syscall.Kill(pid, 0) == nil }

func nsExists(name string) bool {
	_, err := os.Stat("/run/netns/vpncell-" + name)
	return err == nil
}

func listed(t *testing.T, name string) bool {
	for _, line := range strings.Split(root(t, "list").stdout, "\n") {
		if f := strings.Fields(line); len(f) > 0 && f[0] == name {
			return true
		}
	}
	return false
}

func stateHas(t *testing.T, name string) bool {
	data, err := os.ReadFile("/var/lib/vpncell/state.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Ports   map[string]int `json:"socks_ports"`
		Indexes map[string]int `json:"indexes"`
	}
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	_, p := s.Ports[name]
	_, i := s.Indexes[name]
	return p || i
}

// assertGone checks that nothing of the profile is left.
func assertGone(t *testing.T, name string) {
	t.Helper()
	for _, p := range []string{"/etc/vpncell/profiles.d/" + name + ".toml", "/etc/vpncell/secrets/" + name, "/run/vpncell/profiles/" + name, "/run/netns/vpncell-" + name} {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("%s still exists", p)
		}
	}
	if listed(t, name) {
		t.Errorf("vpncell list still shows %s", name)
	}
	if stateHas(t, name) {
		t.Errorf("state.json still has an index or port for %s", name)
	}
	if out, _ := sh("systemctl is-active vpncell-openvpn@" + name); strings.TrimSpace(out) == "active" {
		t.Errorf("OpenVPN unit of %s still active", name)
	}
}

func TestRemoveProfile(t *testing.T) {
	conf := rmConfig(t)
	importRm(t, rmProfile, conf)
	if !stateHas(t, rmProfile) {
		t.Fatalf("no SOCKS port allocated at import")
	}

	// Root only.
	if r := vc(t, userAllowed, "remove", rmProfile); r.code == 0 || !strings.Contains(r.stderr, "root only") {
		t.Fatalf("non-root remove: %v", r)
	}
	// Refused while up.
	ensureUp(t, rmProfile)
	r := root(t, "remove", rmProfile)
	if r.code == 0 || !strings.Contains(r.stderr, "is up") {
		t.Fatalf("remove of an up profile not refused: %v", r)
	}
	if !listed(t, rmProfile) || statusOf(t, rmProfile).State == "down" {
		t.Fatalf("refused remove changed the profile")
	}
	// --force takes it down and deletes everything.
	r = root(t, "remove", "--force", rmProfile)
	if r.code != 0 {
		t.Fatalf("remove --force: %v", r)
	}
	for _, want := range []string{"profile t-rm removed", "took the profile down", "deleted /etc/vpncell/profiles.d/t-rm.toml", "deleted /etc/vpncell/secrets/t-rm/"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("output lacks %q:\n%s", want, r.stdout)
		}
	}
	assertGone(t, rmProfile)
	if r := root(t, "remove", rmProfile); r.code == 0 || !strings.Contains(r.stderr, "no profile") {
		t.Fatalf("second remove: %v", r)
	}

	// A down profile is removed without flags.
	importRm(t, rmProfile, conf)
	if r := root(t, "remove", rmProfile); r.code != 0 {
		t.Fatalf("remove of a down profile: %v", r)
	}
	assertGone(t, rmProfile)

	// With a session: refused; --force keeps the session without network;
	// the namespace goes when the session ends.
	importRm(t, rmProfile, conf)
	ensureUp(t, rmProfile)
	stop := bgSession(t, rmProfile)
	pid := statusOf(t, rmProfile).Sessions[0].PID
	r = root(t, "remove", rmProfile)
	if r.code == 0 || !strings.Contains(r.stderr, "1 active session") || !strings.Contains(r.stderr, "sleep 600") {
		t.Fatalf("remove with a session not refused: %v", r)
	}
	r = root(t, "remove", "--force", rmProfile)
	if r.code != 0 || !strings.Contains(r.stdout, "1 session(s) keep running") || !strings.Contains(r.stdout, "namespace is deleted when the last session exits") {
		t.Fatalf("remove --force with a session: %v", r)
	}
	if !pidAlive(pid) {
		t.Fatalf("remove --force ended the session")
	}
	if !nsExists(rmProfile) || tunnelIf(t, rmProfile) != "" {
		t.Fatalf("namespace should stay without its tunnel (exists=%v, tunnel=%q)", nsExists(rmProfile), tunnelIf(t, rmProfile))
	}
	if listed(t, rmProfile) {
		t.Fatalf("removed profile still listed")
	}
	stop()
	waitFor(t, 20*time.Second, "namespace of the removed profile to go", func() bool { return !nsExists(rmProfile) })
	assertGone(t, rmProfile)

	// --kill ends the session.
	importRm(t, rmProfile, conf)
	ensureUp(t, rmProfile)
	bgSession(t, rmProfile)
	pid = statusOf(t, rmProfile).Sessions[0].PID
	r = root(t, "remove", "--kill", rmProfile)
	if r.code != 0 || !strings.Contains(r.stdout, "ended 1 session(s)") {
		t.Fatalf("remove --kill: %v", r)
	}
	waitFor(t, 10*time.Second, "session to end", func() bool { return !pidAlive(pid) })
	assertGone(t, rmProfile)

	// Importing the name again works and gets a working profile.
	importRm(t, rmProfile, conf)
	ensureUp(t, rmProfile)
	if r := inProfile(t, userAllowed, rmProfile, "curl", "-sS", "-m", "10", "http://10.99.0.10/"); r.code != 0 {
		t.Fatalf("re-imported profile does not work: %v", r)
	}
}

func TestRemoveOpenVPN(t *testing.T) {
	// A copy of t-ovpn2 (same client certificate): keep t-ovpn2 down.
	ensureDown(t, "t-ovpn2")
	const name = "t-rmo"
	importRm(t, name, theLab.Servers["ovpn2"].ClientConfig)
	ensureUp(t, name)
	if out, _ := sh("systemctl is-active vpncell-openvpn@" + name); strings.TrimSpace(out) != "active" {
		t.Fatalf("OpenVPN unit not active: %q", out)
	}
	if r := root(t, "remove", "--force", name); r.code != 0 {
		t.Fatalf("remove --force: %v", r)
	}
	assertGone(t, name)
}

// A profile file deleted by hand while the profile is up: reload takes the
// tunnel down instead of leaving it running out of reach.
func TestReloadDeletedProfile(t *testing.T) {
	conf := rmConfig(t)
	importRm(t, rmProfile, conf)
	ensureUp(t, rmProfile)
	stop := bgSession(t, rmProfile)
	pid := statusOf(t, rmProfile).Sessions[0].PID
	os.Remove("/etc/vpncell/profiles.d/" + rmProfile + ".toml")
	os.RemoveAll("/etc/vpncell/secrets/" + rmProfile)
	if r := root(t, "reload"); r.code != 0 {
		t.Fatalf("reload: %v", r)
	}
	if listed(t, rmProfile) {
		t.Fatalf("deleted profile still listed")
	}
	if tunnelIf(t, rmProfile) != "" {
		t.Fatalf("tunnel of the deleted profile still runs")
	}
	if !pidAlive(pid) {
		t.Fatalf("reload ended the session")
	}
	if r := inProfile(t, userAllowed, rmProfile, "true"); r.code == 0 {
		t.Fatalf("new session in a deleted profile: %v", r)
	}
	stop()
	waitFor(t, 20*time.Second, "namespace of the deleted profile to go", func() bool { return !nsExists(rmProfile) })
	assertGone(t, rmProfile)
}

// A profile file that no longer loads (typo while editing) keeps the
// running version; it stays controllable and removable.
func TestReloadBrokenProfile(t *testing.T) {
	conf := rmConfig(t)
	importRm(t, rmProfile, conf)
	ensureUp(t, rmProfile)
	path := "/etc/vpncell/profiles.d/" + rmProfile + ".toml"
	data, _ := os.ReadFile(path)
	if err := os.WriteFile(path, append(bytes.Clone(data), []byte("\nthis is = = not toml\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := root(t, "reload"); r.code != 0 {
		t.Fatalf("reload: %v", r)
	}
	if !listed(t, rmProfile) || statusOf(t, rmProfile).State == "down" || tunnelIf(t, rmProfile) == "" {
		t.Fatalf("profile with a broken file was taken down")
	}
	if r := inProfile(t, userAllowed, rmProfile, "curl", "-sS", "-m", "10", "http://10.99.0.10/"); r.code != 0 {
		t.Fatalf("running version stopped working: %v", r)
	}
	if out, _ := sh("journalctl -u vpncelld --since=-1min --no-pager -o cat | grep -c 'keeping the running version'"); strings.TrimSpace(out) == "0" {
		t.Errorf("no log line about the broken file")
	}
	ensureDown(t, rmProfile)
	if r := root(t, "remove", rmProfile); r.code != 0 {
		t.Fatalf("remove: %v", r)
	}
	assertGone(t, rmProfile)
}

// A profile file deleted while the daemon is stopped: the next daemon stops
// its OpenVPN unit and deletes its namespace instead of leaving them.
func TestRestartDeletedProfile(t *testing.T) {
	ensureDown(t, "t-ovpn2")
	const name = "t-rmo"
	importRm(t, name, theLab.Servers["ovpn2"].ClientConfig)
	ensureUp(t, name)
	if out, err := sh("systemctl stop vpncelld"); err != nil {
		t.Fatalf("stop daemon: %v %s", err, out)
	}
	os.Remove("/etc/vpncell/profiles.d/" + name + ".toml")
	os.RemoveAll("/etc/vpncell/secrets/" + name)
	if out, err := sh("systemctl start vpncelld"); err != nil {
		t.Fatalf("start daemon: %v %s", err, out)
	}
	waitFor(t, 30*time.Second, "daemon to answer", func() bool { return root(t, "list").code == 0 })
	assertGone(t, name)
}
