//go:build integration

// Package integration holds the root-only end-to-end tests (DESIGN.md
// §15.4). Run with `make itest` (compiles as the user, runs as root).
//
// Environment:
//
//	VPNCELL_TEST_INSTALLED=1  test the installed .deb instead of the dev build
//	VPNCELL_TEST_VM=0         skip profiles against the test VM
//	VPNCELL_TEST_VM_ENDPOINT  the VM's address (default: the Endpoint host
//	                          in vm-wg.conf); it is also the expected exit IP
package integration

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gallbotond/vpncell/test/lab"
)

var (
	repoRoot  string
	cliPath   string
	daemonBin string
	theLab    *lab.Lab
	installed = os.Getenv("VPNCELL_TEST_INSTALLED") == "1"
	useVM     = os.Getenv("VPNCELL_TEST_VM") != "0"
	// VM endpoint and expected exit address (DESIGN.md §15.1); set in
	// setup from VPNCELL_TEST_VM_ENDPOINT or vm-wg.conf.
	vmEndpoint string
	vmConfigs  = "/var/lib/vpncell-test/vm"
)

// vmEndpointAddr returns VPNCELL_TEST_VM_ENDPOINT, or the host part of the
// Endpoint line in the VM's WireGuard config. The address is not kept in
// the repository.
func vmEndpointAddr(wgConf string) (string, error) {
	if ep := os.Getenv("VPNCELL_TEST_VM_ENDPOINT"); ep != "" {
		return ep, nil
	}
	b, err := os.ReadFile(wgConf)
	if err != nil {
		return "", err
	}
	for _, l := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(l, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "Endpoint") {
			continue
		}
		host, _, err := net.SplitHostPort(strings.TrimSpace(v))
		if err != nil {
			return "", fmt.Errorf("%s: Endpoint: %w", wgConf, err)
		}
		return host, nil
	}
	return "", fmt.Errorf("%s: no Endpoint (set VPNCELL_TEST_VM_ENDPOINT)", wgConf)
}

// The VM's exit addresses are its IPv6 endpoint and, since the VM got IPv4
// egress (2026-11-28), the IPv4 address its traffic leaves from. Programs
// that resolve names themselves (Firefox, SOCKS clients) may use either;
// both prove that the traffic left through the VM.
var (
	vmExitOnce sync.Once
	vmExit4    string
)

// isVMExit reports whether ip is one of the VM's exit addresses. The IPv4
// one is learned once with curl -4 through vm-wg's tunnel, and must not be
// the host's own IPv4 exit address.
func isVMExit(t testing.TB, ip string) bool {
	t.Helper()
	ip = strings.TrimSpace(ip)
	if ip == vmEndpoint {
		return true
	}
	vmExitOnce.Do(func() {
		ensureUp(t, "vm-wg")
		r := inProfile(t, userAllowed, "vm-wg", "curl", "-4", "-sS", "-m", "20", "https://ifconfig.me")
		v4 := strings.TrimSpace(r.stdout)
		if a := net.ParseIP(v4); r.code != 0 || a == nil || a.To4() == nil {
			return // the VM has no IPv4 egress
		}
		host, _ := run("", "curl", "-4", "-sS", "-m", "20", "https://ifconfig.me")
		if strings.TrimSpace(host) == v4 {
			t.Errorf("vm-wg's IPv4 exit address is the host's own (%s)", v4)
			return
		}
		vmExit4 = v4
	})
	return vmExit4 != "" && ip == vmExit4
}

// Test users (created by test/scripts/dev-install.sh):
// vctest1: in group vpncell and allowed on every test profile
// vctest2: in group vpncell, not allowed
// vctest3: not in group vpncell
const (
	userAllowed  = "vctest1"
	userDenied   = "vctest2"
	userNoGroup  = "vctest3"
	labWGServers = 4
)

func TestMain(m *testing.M) {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "integration tests must run as root (make itest)")
		os.Exit(2)
	}
	wd, _ := os.Getwd()
	repoRoot = filepath.Clean(filepath.Join(wd, "..", ".."))
	if installed {
		cliPath, daemonBin = "/usr/bin/vpncell", "/usr/sbin/vpncelld"
	} else {
		cliPath, daemonBin = "/usr/local/libexec/vpncell-test/vpncell", "/usr/local/libexec/vpncell-test/vpncelld"
		must(run("", filepath.Join(repoRoot, "test/scripts/dev-install.sh")))
	}
	code := func() int {
		if err := setup(); err != nil {
			fmt.Fprintln(os.Stderr, "setup:", err)
			teardown()
			return 1
		}
		defer teardown()
		return m.Run()
	}()
	os.Exit(code)
}

func must(out string, err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, out)
		panic(err)
	}
}

// run executes a command as root and returns combined output.
func run(stdin string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func sh(script string) (string, error) { return run("", "bash", "-c", script) }

func setup() error {
	lab.Cleanup()
	_, err := sh("systemctl is-active --quiet vpncelld")
	daemonWasActive = err == nil
	// Take down leftovers of earlier runs. Only test profiles (t-*, vm-*)
	// are touched: the host may run the user's own profiles, their tunnels
	// and sessions (they survive the daemon restart below).
	sh("systemctl stop vpncelld")
	if !otherProfiles() {
		sh("systemctl clean --what=fdstore vpncelld 2>/dev/null")
	}
	sh("systemctl stop 'vpncell-openvpn@t-*' 'vpncell-openvpn@vm-*' 2>/dev/null")
	sh(`for n in /run/netns/vpncell-t-* /run/netns/vpncell-vm-*; do [ -e "$n" ] && umount -l "$n"; rm -f "$n"; done; rm -rf /run/vpncell/profiles/t-* /run/vpncell/profiles/vm-*`)
	sh("rm -f /etc/vpncell/profiles.d/t-*.toml /etc/vpncell/profiles.d/vm-*.toml; rm -rf /etc/vpncell/secrets/t-* /etc/vpncell/secrets/vm-*")
	if out, err := sh("systemctl start vpncelld"); err != nil {
		return fmt.Errorf("start daemon: %v: %s", err, out)
	}
	theLab = lab.New("/run/vpncell-lab")
	for i := 1; i <= labWGServers; i++ {
		s, err := theLab.AddWireGuard(fmt.Sprintf("wg%d", i), i)
		if err != nil {
			return err
		}
		if err := importProfile(fmt.Sprintf("t-wg%d", i), s.ClientConfig); err != nil {
			return err
		}
	}
	if err := setupOpenVPNLab(); err != nil {
		return err
	}
	if useVM {
		if _, err := os.Stat(filepath.Join(vmConfigs, "vm-wg.conf")); err != nil {
			return fmt.Errorf("VM configs missing (run test/scripts/vm-fetch-configs.sh or set VPNCELL_TEST_VM=0): %w", err)
		}
		ep, err := vmEndpointAddr(filepath.Join(vmConfigs, "vm-wg.conf"))
		if err != nil {
			return err
		}
		vmEndpoint = ep
		if err := importProfile("vm-wg", filepath.Join(vmConfigs, "vm-wg.conf")); err != nil {
			return err
		}
		if err := setupOpenVPNVM(); err != nil {
			return err
		}
	}
	return nil
}

func importProfile(name, path string, extra ...string) error {
	args := append([]string{"import", "--replace", "--user", userAllowed, "--user", "botond"}, extra...)
	args = append(args, name, path)
	out, err := run("", cliPath, args...)
	if err != nil {
		return fmt.Errorf("import %s: %v: %s", name, err, out)
	}
	return nil
}

func teardown() {
	out, _ := run("", cliPath, "list")
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 1 && (strings.HasPrefix(f[0], "t-") || strings.HasPrefix(f[0], "vm-")) {
			run("", cliPath, "down", "--kill", f[0])
		}
	}
	if theLab != nil {
		theLab.Close()
	}
	sh("rm -f /etc/vpncell/profiles.d/t-*.toml /etc/vpncell/profiles.d/vm-*.toml; rm -rf /etc/vpncell/secrets/t-* /etc/vpncell/secrets/vm-*")
	run("", cliPath, "reload")
	if os.Getenv("VPNCELL_TEST_KEEP_DAEMON") == "" && !daemonWasActive {
		sh("systemctl stop vpncelld")
	}
}

// daemonWasActive: the daemon ran before the tests; it keeps running after.
var daemonWasActive bool

// otherProfiles reports whether profiles other than the test ones exist.
func otherProfiles() bool {
	ms, _ := filepath.Glob("/etc/vpncell/profiles.d/*.toml")
	for _, m := range ms {
		b := filepath.Base(m)
		if !strings.HasPrefix(b, "t-") && !strings.HasPrefix(b, "vm-") {
			return true
		}
	}
	return false
}

// ---- running things as users ----

type userCreds struct {
	uid, gid uint32
	groups   []uint32
	home     string
}

var credCache sync.Map

func credsOf(name string) userCreds {
	if c, ok := credCache.Load(name); ok {
		return c.(userCreds)
	}
	u, err := user.Lookup(name)
	if err != nil {
		panic(err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	gids, _ := u.GroupIds()
	var gs []uint32
	for _, g := range gids {
		n, _ := strconv.Atoi(g)
		gs = append(gs, uint32(n))
	}
	c := userCreds{uint32(uid), uint32(gid), gs, u.HomeDir}
	credCache.Store(name, c)
	return c
}

type result struct {
	stdout, stderr string
	code           int
}

func (r result) String() string {
	return fmt.Sprintf("exit=%d stdout=%q stderr=%q", r.code, r.stdout, r.stderr)
}

// asUser runs a command as a test user with its groups, in /tmp.
func asUser(ctx context.Context, name string, stdin string, argv ...string) result {
	c := credsOf(name)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: c.uid, Gid: c.gid, Groups: c.groups}}
	cmd.Dir = "/tmp"
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + c.home, "USER=" + name, "LANG=C.UTF-8", "SHELL=/bin/bash"}
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	err := cmd.Run()
	code := 0
	if err != nil {
		code = -1
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
	}
	return result{so.String(), se.String(), code}
}

// vc runs the CLI as a user.
func vc(t testing.TB, name string, args ...string) result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	return asUser(ctx, name, "", append([]string{cliPath}, args...)...)
}

// inProfile runs a command in a profile (non-TTY) as a user.
func inProfile(t testing.TB, name, profile string, argv ...string) result {
	t.Helper()
	return vc(t, name, append([]string{"run", "-T", profile, "--"}, argv...)...)
}

// root runs the CLI as root.
func root(t testing.TB, args ...string) result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, cliPath, args...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	cmd.Dir = "/tmp"
	err := cmd.Run()
	code := 0
	if err != nil {
		code = -1
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
	}
	return result{so.String(), se.String(), code}
}

func ensureUp(t testing.TB, profiles ...string) {
	t.Helper()
	for _, p := range profiles {
		if r := root(t, "up", p); r.code != 0 {
			t.Fatalf("up %s: %v", p, r)
		}
	}
}

func ensureDown(t testing.TB, profiles ...string) {
	t.Helper()
	for _, p := range profiles {
		if r := root(t, "down", "--kill", p); r.code != 0 {
			t.Fatalf("down %s: %v", p, r)
		}
	}
}

// ---- profile sets ----

// profileSet is a pair of profiles used together. Every scenario runs with
// each set: WireGuard only, OpenVPN only and mixed.
type profileSet struct {
	name   string
	a, b   string // lab profiles with overlapping 10.99.0.0/24
	sa, sb string // lab server names behind a and b
}

func labSets() []profileSet {
	sets := []profileSet{{"wireguard", "t-wg1", "t-wg2", "wg1", "wg2"}}
	return append(sets, openVPNLabSets()...)
}

// vmProfiles are the profiles against the real test VM.
func vmProfiles() []string {
	if !useVM {
		return nil
	}
	return append([]string{"vm-wg"}, openVPNVMProfiles()...)
}

func forEachSet(t *testing.T, fn func(t *testing.T, s profileSet)) {
	for _, s := range labSets() {
		s := s
		t.Run(s.name, func(t *testing.T) { fn(t, s) })
	}
}

func netnsExec(profile string, args ...string) (string, error) {
	return run("", "ip", append([]string{"netns", "exec", "vpncell-" + profile}, args...)...)
}

func tunnelIf(t testing.TB, profile string) string {
	out, err := netnsExec(profile, "ip", "-o", "link", "show")
	if err != nil {
		t.Fatalf("list links in %s: %v %s", profile, err, out)
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) > 1 {
			n := strings.TrimSuffix(strings.Split(f[1], "@")[0], ":")
			if strings.HasPrefix(n, "vpnwg") || strings.HasPrefix(n, "vpntun") {
				return n
			}
		}
	}
	return ""
}

func waitFor(t testing.TB, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// stressProfiles are the profiles (with their lab servers) used by the
// thread-safety test: all four WireGuard lab profiles, plus OpenVPN ones.
func stressProfiles() [][2]string {
	var out [][2]string
	for i := 1; i <= labWGServers; i++ {
		out = append(out, [2]string{fmt.Sprintf("t-wg%d", i), fmt.Sprintf("wg%d", i)})
	}
	return append(out, openVPNStressProfiles()...)
}
