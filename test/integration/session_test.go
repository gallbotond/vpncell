//go:build integration

package integration

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
)

// ---- a tiny expect over a pty ----

type ptySession struct {
	t    *testing.T
	cmd  *exec.Cmd
	ptmx *os.File
	mu   sync.Mutex
	buf  bytes.Buffer
	done chan struct{}
	code int
}

// startShell runs `vpncell shell <profile>` as a user on a new pty.
func startShell(t *testing.T, name, profile string, rows, cols uint16) *ptySession {
	t.Helper()
	c := credsOf(name)
	cmd := exec.Command(cliPath, "shell", profile)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: c.uid, Gid: c.gid, Groups: c.groups}, Setsid: true, Setctty: true}
	cmd.Dir = "/tmp"
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + c.home, "USER=" + name, "TERM=xterm", "SHELL=/bin/bash", "PS1=$ ", "LANG=C.UTF-8"}
	ptmx, err := pty.StartWithAttrs(cmd, &pty.Winsize{Rows: rows, Cols: cols}, cmd.SysProcAttr)
	if err != nil {
		t.Fatalf("start shell: %v", err)
	}
	s := &ptySession{t: t, cmd: cmd, ptmx: ptmx, done: make(chan struct{})}
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := ptmx.Read(b)
			s.mu.Lock()
			s.buf.Write(b[:n])
			s.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	go func() {
		cmd.Wait()
		s.code = cmd.ProcessState.ExitCode()
		if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			s.code = 128 + int(ws.Signal())
		}
		close(s.done)
	}()
	t.Cleanup(func() {
		select {
		case <-s.done:
		default:
			cmd.Process.Kill()
		}
		ptmx.Close()
	})
	return s
}

func (s *ptySession) send(str string) { s.ptmx.Write([]byte(str)) }

// expect waits until the output (since the last match) matches re.
func (s *ptySession) expect(re string, d time.Duration) []string {
	s.t.Helper()
	rx := regexp.MustCompile(re)
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		out := s.buf.String()
		if m := rx.FindStringSubmatchIndex(out); m != nil {
			sub := rx.FindStringSubmatch(out)
			rest := out[m[1]:]
			s.buf.Reset()
			s.buf.WriteString(rest)
			s.mu.Unlock()
			return sub
		}
		s.mu.Unlock()
		time.Sleep(30 * time.Millisecond)
	}
	s.mu.Lock()
	out := s.buf.String()
	s.mu.Unlock()
	s.t.Fatalf("timed out waiting for %q; output so far:\n%s", re, out)
	return nil
}

func (s *ptySession) wait(d time.Duration) int {
	s.t.Helper()
	select {
	case <-s.done:
		return s.code
	case <-time.After(d):
		s.t.Fatalf("session did not end")
		return -1
	}
}

// Step 2: an interactive shell with a TTY, job control, Ctrl-C, window
// resizing and the exit code.
func TestShellTTY(t *testing.T) {
	forEachSet(t, func(t *testing.T, s profileSet) {
		ensureUp(t, s.a)
		sh := startShell(t, userAllowed, s.a, 30, 100)
		sh.expect(`escape the profile`, 10*time.Second)
		sh.send("echo PROF=$VPNCELL_PROFILE; tty; id -un; stty size\n")
		sh.expect(`PROF=`+s.a, 10*time.Second)
		sh.expect(`/dev/pts/\d+`, 5*time.Second)
		sh.expect(userAllowed, 5*time.Second)
		sh.expect(`30 100`, 5*time.Second)
		// The shell is interactive and not a login shell.
		sh.send("case $- in *i*) echo INTERACTIVE;; esac; shopt -q login_shell && echo LOGIN || echo NOLOGIN\n")
		sh.expect(`INTERACTIVE`, 5*time.Second)
		sh.expect(`NOLOGIN`, 5*time.Second)
		// The pty belongs to the user.
		sh.send("stat -c OWNER=%U $(tty)\n")
		sh.expect(`OWNER=`+userAllowed, 5*time.Second)
		// Window resize reaches the session.
		pty.Setsize(sh.ptmx, &pty.Winsize{Rows: 40, Cols: 132})
		sh.cmd.Process.Signal(syscall.SIGWINCH)
		time.Sleep(300 * time.Millisecond)
		sh.send("stty size\n")
		sh.expect(`40 132`, 5*time.Second)
		// Ctrl-C interrupts the foreground job, the shell survives.
		// (Interactive bash aborts the rest of a command list on Ctrl-C, so
		// the status is checked with a second command.)
		sh.send("sleep 30\n")
		time.Sleep(500 * time.Millisecond)
		sh.send("\x03")
		sh.send("echo AFTER=$?\n")
		sh.expect(`AFTER=130`, 5*time.Second)
		// Job control: Ctrl-Z, jobs, kill.
		sh.send("sleep 31\n")
		time.Sleep(500 * time.Millisecond)
		sh.send("\x1a")
		sh.expect(`Stopped`, 5*time.Second)
		sh.send("kill %1; wait; echo JOBDONE\n")
		sh.expect(`JOBDONE`, 5*time.Second)
		// Network works from the shell and reaches its own server.
		sh.send("curl -s -m 5 http://10.99.0.10/ | grep -o 'lab-server [a-z0-9]*' | head -1\n")
		sh.expect(`lab-server `+s.sa, 10*time.Second)
		sh.send("exit 42\n")
		if code := sh.wait(10 * time.Second); code != 42 {
			t.Fatalf("exit code = %d, want 42", code)
		}
	})
}

// Exit codes and signals for non-TTY runs.
func TestRunExitCodesAndSignals(t *testing.T) {
	s := labSets()[0]
	ensureUp(t, s.a)
	if r := inProfile(t, userAllowed, s.a, "sh", "-c", "exit 7"); r.code != 7 {
		t.Fatalf("exit 7: %v", r)
	}
	if r := inProfile(t, userAllowed, s.a, "sh", "-c", "kill -9 $$"); r.code != 128+9 {
		t.Fatalf("killed by signal: %v", r)
	}
	if r := inProfile(t, userAllowed, s.a, "no-such-command-xyz"); r.code != 127 {
		t.Fatalf("missing command: %v", r)
	}
	// stdin/stdout/stderr are the caller's.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r := asUser(ctx, userAllowed, "hello-stdin\n", cliPath, "run", "-T", s.a, "--", "sh", "-c", "cat; echo to-stderr >&2")
	if r.code != 0 || r.stdout != "hello-stdin\n" || r.stderr != "to-stderr\n" {
		t.Fatalf("stdio: %v", r)
	}
	// A signal sent to the client reaches the command.
	c := credsOf(userAllowed)
	cmd := exec.Command(cliPath, "run", "-T", s.a, "--", "sh", "-c", "trap 'echo GOT-TERM; exit 3' TERM; while :; do sleep 0.1; done")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: c.uid, Gid: c.gid, Groups: c.groups}}
	cmd.Dir = "/tmp"
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	cmd.Process.Signal(syscall.SIGTERM)
	cmd.Wait()
	if code := cmd.ProcessState.ExitCode(); code != 3 || !strings.Contains(out.String(), "GOT-TERM") {
		t.Fatalf("SIGTERM relay: code %d out %q", code, out.String())
	}
	// Killing the client hangs up the session (like ssh).
	marker := "/tmp/vpncell-hup-" + marker()
	defer os.Remove(marker)
	cmd = exec.Command(cliPath, "run", "-T", s.a, "--", "sh", "-c", "trap 'touch "+marker+"; exit 1' HUP; while :; do sleep 0.1; done")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: c.uid, Gid: c.gid, Groups: c.groups}}
	cmd.Dir = "/tmp"
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	cmd.Process.Kill()
	cmd.Wait()
	waitFor(t, 10*time.Second, "SIGHUP after client death", func() bool { _, err := os.Stat(marker); return err == nil })
}

// Required test "Privileges".
func TestPrivileges(t *testing.T) {
	forEachSet(t, func(t *testing.T, s profileSet) {
		ensureUp(t, s.a)
		c := credsOf(userAllowed)
		r := inProfile(t, userAllowed, s.a, "sh", "-c", "id -u; id -g; id -G; grep -E '^(Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs):' /proc/self/status")
		if r.code != 0 {
			t.Fatalf("%v", r)
		}
		lines := strings.Split(strings.TrimSpace(r.stdout), "\n")
		if lines[0] != fmt.Sprint(c.uid) || lines[1] != fmt.Sprint(c.gid) {
			t.Fatalf("uid/gid: %q", r.stdout)
		}
		want := map[string]bool{}
		for _, g := range c.groups {
			want[fmt.Sprint(g)] = true
		}
		for _, g := range strings.Fields(lines[2]) {
			if !want[g] {
				t.Errorf("unexpected group %s in session", g)
			}
			delete(want, g)
		}
		if len(want) > 0 {
			t.Errorf("groups missing in session: %v", want)
		}
		for _, l := range lines[3:] {
			f := strings.Fields(l)
			switch f[0] {
			case "NoNewPrivs:":
				if f[1] != "1" {
					t.Errorf("NoNewPrivs = %s", f[1])
				}
			default:
				if f[1] != "0000000000000000" {
					t.Errorf("%s %s, want 0", f[0], f[1])
				}
			}
		}
		// setns out of the namespace fails.
		for _, target := range []string{"/proc/1/ns/net", "/run/netns/vpncell-" + s.b} {
			r := inProfile(t, userAllowed, s.a, "nsenter", "--net="+target, "true")
			if r.code == 0 {
				t.Errorf("setns into %s succeeded from a session", target)
			}
		}
		// The session's own namespace is the profile's.
		r = inProfile(t, userAllowed, s.a, "readlink", "/proc/self/ns/net")
		want2, _ := os.Readlink("/proc/self/ns/net")
		if strings.TrimSpace(r.stdout) == want2 {
			t.Errorf("session runs in the host network namespace")
		}
		// setuid binaries do not gain privileges.
		if r := inProfile(t, userAllowed, s.a, "sudo", "-n", "true"); r.code == 0 {
			t.Errorf("sudo worked inside a profile")
		}
		// Root sessions also have no capabilities.
		rr := root(t, "run", "-T", s.a, "--", "grep", "CapEff", "/proc/self/status")
		if !strings.Contains(rr.stdout, "0000000000000000") {
			t.Errorf("root session has capabilities: %v", rr)
		}
	})
}

// Required test "DNS" (shell part): queries go only to the profile's DNS.
func TestDNSIsolationShell(t *testing.T) {
	forEachSet(t, func(t *testing.T, s profileSet) {
		ensureUp(t, s.a, s.b)
		mk := marker()
		cap := startCapture(t)
		beforeA, beforeB := len(theLab.DNSQueries(s.sa)), len(theLab.DNSQueries(s.sb))
		// Same name, different answer per profile.
		ra := inProfile(t, userAllowed, s.a, "getent", "ahostsv4", "web.lab.test")
		rb := inProfile(t, userAllowed, s.b, "getent", "ahostsv4", "web.lab.test")
		wantA := theLab.Servers[s.sa].SvcIP.String()
		wantB := theLab.Servers[s.sb].SvcIP.String()
		if !strings.Contains(ra.stdout, wantA) || !strings.Contains(rb.stdout, wantB) {
			t.Fatalf("web.lab.test: %s -> %q (want %s), %s -> %q (want %s)", s.a, ra.stdout, wantA, s.b, rb.stdout, wantB)
		}
		// Search domain from the profile.
		if r := inProfile(t, userAllowed, s.a, "getent", "ahostsv4", "web"); !strings.Contains(r.stdout, wantA) {
			t.Errorf("search domain: %v", r)
		}
		// Marker lookup from profile a reaches only server a.
		inProfile(t, userAllowed, s.a, "getent", "hosts", mk+".lab.test")
		inProfile(t, userAllowed, s.a, "curl", "-s", "-m", "3", "http://"+mk+".example.com/")
		qa := strings.Join(theLab.DNSQueries(s.sa)[beforeA:], " ")
		qb := strings.Join(theLab.DNSQueries(s.sb)[beforeB:], " ")
		if !strings.Contains(qa, mk) {
			t.Errorf("marker query did not reach the profile's DNS server: %s", qa)
		}
		if strings.Contains(qb, mk) {
			t.Errorf("marker query reached the other profile's DNS server")
		}
		// Host resolvers are unreachable.
		for _, probe := range [][]string{
			{"dig", "+time=2", "+tries=1", "@127.0.0.53", mk + ".stub.example"},
			{"dig", "+time=2", "+tries=1", "@127.0.0.1", mk + ".lo.example"},
		} {
			if r := inProfile(t, userAllowed, s.a, probe...); r.code == 0 && strings.Contains(r.stdout, "status:") {
				t.Errorf("%v answered: %v", probe, r)
			}
		}
		// resolved's varlink socket, avahi's socket are hidden; nsswitch has no mdns/resolve.
		r := inProfile(t, userAllowed, s.a, "sh", "-c", "ls -A /run/systemd/resolve; ls -A /run/avahi-daemon 2>/dev/null; grep ^hosts: /etc/nsswitch.conf; cat /etc/resolv.conf")
		if strings.Contains(r.stdout, "io.systemd.Resolve") || strings.Contains(r.stdout, "socket") {
			t.Errorf("host resolver socket visible: %s", r.stdout)
		}
		if strings.Contains(r.stdout, "mdns") || strings.Contains(r.stdout, "resolve [") || !strings.Contains(r.stdout, "nameserver 10.99.0.53") {
			t.Errorf("resolver files: %s", r.stdout)
		}
		// Nothing changed on the host: its own resolv.conf still points at the stub.
		if l, _ := os.Readlink("/etc/resolv.conf"); !strings.Contains(l, "stub-resolv.conf") {
			t.Errorf("host /etc/resolv.conf changed: %s", l)
		}
		hostRC, _ := os.ReadFile("/etc/resolv.conf")
		if !strings.Contains(string(hostRC), "127.0.0.53") {
			t.Errorf("host resolver config affected:\n%s", hostRC)
		}
		cap.assertNoLeaks(mk)
	})
}

// Required test "No host or LAN access" (shell part), nftables on and off.
func TestNoHostOrLANAccessShell(t *testing.T) {
	// A dev server on the host's loopback and on its LAN address.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "HOST-DEV-SERVER") }))
	port := ln.Addr().(*net.TCPAddr).Port
	lanIP, gw := hostLAN(t)
	ln2, err := net.Listen("tcp", lanIP+":0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()
	go http.Serve(ln2, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "HOST-LAN-SERVER") }))
	port2 := ln2.Addr().(*net.TCPAddr).Port
	for _, nft := range []bool{true, false} {
		nft := nft
		t.Run(fmt.Sprintf("nftables=%v", nft), func(t *testing.T) {
			forEachSet(t, func(t *testing.T, s profileSet) {
				setNftables(t, s.a, nft)
				defer setNftables(t, s.a, true)
				probes := [][]string{
					{"curl", "-sS", "-m", "3", fmt.Sprintf("http://127.0.0.1:%d/", port)},
					{"curl", "-sS", "-m", "3", fmt.Sprintf("http://localhost:%d/", port)},
					{"curl", "-sS", "-m", "3", fmt.Sprintf("http://%s:%d/", lanIP, port2)},
					{"curl", "-sS", "-m", "3", "http://" + gw + "/"},
					{"dig", "+time=2", "+tries=1", "@127.0.0.53", "example.com"},
					{"ping", "-c", "1", "-W", "2", gw},
				}
				for _, p := range probes {
					r := inProfile(t, userAllowed, s.a, p...)
					if r.code == 0 || strings.Contains(r.stdout, "HOST-") {
						t.Errorf("reachable from profile: %v -> %v", p, r)
					}
				}
			})
		})
	}
}

func hostLAN(t testing.TB) (ip, gw string) {
	out, _ := run("", "ip", "-o", "-4", "route", "get", "1.1.1.1")
	m := regexp.MustCompile(`via (\S+) .* src (\S+)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no LAN route: %q", out)
	}
	return m[2], m[1]
}

// Required test "down with sessions": refuse, --force, --kill.
func TestDownWithSessions(t *testing.T) {
	forEachSet(t, func(t *testing.T, s profileSet) {
		p := s.a
		ensureUp(t, p)
		loop := startLoop(t, p)
		defer loop.stop()
		waitFor(t, 15*time.Second, "loop ok", func() bool { return loop.okCount() > 0 })
		// Refused, and the sessions are listed.
		r := vc(t, userAllowed, "down", p)
		if r.code == 0 || !strings.Contains(r.stderr, "active session") || !strings.Contains(r.stderr, "sh -c") {
			t.Fatalf("down with sessions not refused: %v", r)
		}
		if st := statusOf(t, p); len(st.Sessions) == 0 || st.State == "down" {
			t.Fatalf("status after refused down: %+v", st)
		}
		// --force: tunnel gone, session alive without network.
		if r := vc(t, userAllowed, "down", "--force", p); r.code != 0 {
			t.Fatalf("down --force: %v", r)
		}
		loop.reset()
		time.Sleep(3 * time.Second)
		if loop.okCount() != 0 || loop.failCount() == 0 || !loop.alive() {
			t.Fatalf("after --force: ok=%d fail=%d alive=%v", loop.okCount(), loop.failCount(), loop.alive())
		}
		if out, _ := netnsExec(p, "ip", "-o", "link"); strings.Contains(out, "vpnwg") || strings.Contains(out, "vpntun") {
			t.Fatalf("tunnel still present after --force:\n%s", out)
		}
		// up gives the session network again.
		ensureUp(t, p)
		loop.reset()
		waitFor(t, 30*time.Second, "network back after up", func() bool { return loop.okCount() > 0 })
		// --kill ends the sessions.
		if r := vc(t, userAllowed, "down", "--kill", p); r.code != 0 {
			t.Fatalf("down --kill: %v", r)
		}
		waitFor(t, 10*time.Second, "session ended", func() bool { return !loop.alive() })
		if st := statusOf(t, p); len(st.Sessions) != 0 || st.State != "down" {
			t.Fatalf("status after --kill: %+v", st)
		}
		if _, err := os.Stat("/run/netns/vpncell-" + p); err == nil {
			t.Fatalf("namespace left after --kill")
		}
		ensureUp(t, p)
	})
}

// Users may not --force/--kill other users' sessions.
func TestDownOtherUsersSessions(t *testing.T) {
	s := labSets()[0]
	ensureUp(t, s.a)
	loop := startLoop(t, s.a) // as userAllowed
	defer loop.stop()
	waitFor(t, 15*time.Second, "loop ok", func() bool { return loop.okCount() > 0 })
	r := vc(t, "botond", "down", "--kill", s.a)
	if r.code == 0 || !loop.alive() {
		t.Fatalf("a user killed another user's session: %v", r)
	}
	if !strings.Contains(r.stderr, "session of another user") && !strings.Contains(r.stderr, "only root") {
		t.Fatalf("unexpected error: %v", r)
	}
}

// loop is a background session that fetches from the lab server every
// 200 ms and reports successes and failures.
type loop struct {
	t           *testing.T
	cmd         *exec.Cmd
	mu          sync.Mutex
	ok, fail    int
	done        chan struct{}
	lastSuccess time.Time
}

func startLoop(t *testing.T, profile string) *loop {
	c := credsOf(userAllowed)
	cmd := exec.Command(cliPath, "run", "-T", profile, "--", "sh", "-c",
		"while :; do if curl -s -m 1 -o /dev/null http://10.99.0.10/; then echo OK; else echo FAIL; fi; sleep 0.2; done")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: c.uid, Gid: c.gid, Groups: c.groups}}
	cmd.Dir = "/tmp"
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	l := &loop{t: t, cmd: cmd, done: make(chan struct{})}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			l.mu.Lock()
			if sc.Text() == "OK" {
				l.ok++
				l.lastSuccess = time.Now()
			} else {
				l.fail++
			}
			l.mu.Unlock()
		}
	}()
	go func() { cmd.Wait(); pw.Close(); close(l.done) }()
	return l
}

func (l *loop) okCount() int   { l.mu.Lock(); defer l.mu.Unlock(); return l.ok }
func (l *loop) failCount() int { l.mu.Lock(); defer l.mu.Unlock(); return l.fail }
func (l *loop) reset()         { l.mu.Lock(); l.ok, l.fail = 0, 0; l.mu.Unlock() }
func (l *loop) alive() bool {
	select {
	case <-l.done:
		return false
	default:
		return true
	}
}
func (l *loop) stop() {
	if l.alive() {
		l.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-l.done:
		case <-time.After(5 * time.Second):
			l.cmd.Process.Kill()
		}
	}
}

// Required test "Daemon restart" (shell part): running sessions keep
// working across `systemctl restart` and `kill -9` of the daemon, and no
// traffic leaks meanwhile. The exit code still reaches the client.
func TestDaemonRestartShell(t *testing.T) {
	forEachSet(t, func(t *testing.T, s profileSet) {
		ensureUp(t, s.a, s.b)
		la, lb := startLoop(t, s.a), startLoop(t, s.b)
		defer la.stop()
		defer lb.stop()
		waitFor(t, 15*time.Second, "loops ok", func() bool { return la.okCount() > 0 && lb.okCount() > 0 })
		cap := startCapture(t)
		for _, how := range []string{"systemctl restart vpncelld", "systemctl kill -s KILL vpncelld"} {
			la.reset()
			lb.reset()
			if out, err := sh(how); err != nil {
				t.Fatalf("%s: %v %s", how, err, out)
			}
			time.Sleep(3 * time.Second)
			if !la.alive() || !lb.alive() {
				t.Fatalf("%s: session died", how)
			}
			if la.failCount() > 0 || lb.failCount() > 0 || la.okCount() == 0 || lb.okCount() == 0 {
				t.Fatalf("%s: traffic interrupted: a ok=%d fail=%d, b ok=%d fail=%d", how, la.okCount(), la.failCount(), lb.okCount(), lb.failCount())
			}
			waitFor(t, 15*time.Second, "daemon back", func() bool { return root(t, "list").code == 0 })
			// The new daemon knows the sessions and the profile state.
			if st := statusOf(t, s.a); len(st.Sessions) == 0 || st.State != "up" {
				t.Fatalf("%s: status after restart: %+v", how, st)
			}
		}
		cap.assertNoLeaks()
		// Exit status still reaches the client after the restarts.
		la.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-la.done:
		case <-time.After(10 * time.Second):
			t.Fatalf("session did not end after SIGTERM")
		}
		if code := la.cmd.ProcessState.ExitCode(); code != 143 {
			t.Fatalf("exit code after restart = %d, want 143", code)
		}
	})
}

// Informational: which common desktop programs work inside a profile shell
// (abstract Unix sockets belong to the network namespace). Results go to
// the test log and the README.
func TestDesktopPrograms(t *testing.T) {
	s := labSets()[0]
	ensureUp(t, s.a)
	env := desktopEnv()
	if env == nil {
		t.Log("no desktop session found; nothing to check")
		return
	}
	checks := []struct{ name, cmd string }{
		{"X11 via DISPLAY (xdpyinfo)", "xdpyinfo -display \"$DISPLAY\" >/dev/null"},
		{"X11 abstract socket only", "xdpyinfo -display unix:abstract=/tmp/.X11-unix/X0 >/dev/null 2>&1 || python3 -c 'import socket;s=socket.socket(socket.AF_UNIX);s.connect(\"\\0/tmp/.X11-unix/X0\")'"},
		{"X11 path socket", "test -S /tmp/.X11-unix/X0 && python3 -c 'import socket;s=socket.socket(socket.AF_UNIX);s.connect(\"/tmp/.X11-unix/X0\")'"},
		{"Wayland socket", "python3 -c 'import os,socket;s=socket.socket(socket.AF_UNIX);s.connect(os.environ[\"XDG_RUNTIME_DIR\"]+\"/\"+os.environ.get(\"WAYLAND_DISPLAY\",\"wayland-0\"))'"},
		{"D-Bus session bus (gdbus)", "gdbus call --session --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus --method org.freedesktop.DBus.ListNames >/dev/null"},
		{"notify-send", "notify-send -t 1 vpncell-test"},
		{"systemd user manager (systemctl --user)", "systemctl --user is-system-running >/dev/null; test $? -le 1"},
		{"system bus (busctl)", "busctl --system list >/dev/null"},
		{"resolvectl (resolved over D-Bus)", "resolvectl query example.com >/dev/null"},
	}
	var rep strings.Builder
	rep.WriteString("| Check | outside a profile | inside a profile |\n|---|---|---|\n")
	runCheck := func(argv []string) string {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000, Groups: credsOf("botond").groups}}
		cmd.Env = env
		cmd.Dir = "/tmp"
		if err := cmd.Run(); err != nil {
			return "fails"
		}
		return "works"
	}
	for _, c := range checks {
		out := runCheck([]string{"sh", "-c", c.cmd})
		in := runCheck([]string{cliPath, "run", "-T", s.a, "--", "sh", "-c", c.cmd})
		fmt.Fprintf(&rep, "| %s | %s | %s |\n", c.name, out, in)
	}
	t.Logf("desktop programs inside a profile:\n%s", rep.String())
	os.WriteFile("/tmp/vpncell-desktop-programs.md", []byte(rep.String()), 0o644)
}

func desktopEnv() []string {
	out, err := run("", "sh", "-c", "pgrep -u botond -x gnome-shell | head -1")
	pid := strings.TrimSpace(out)
	if err != nil || pid == "" {
		return nil
	}
	data, err := os.ReadFile("/proc/" + pid + "/environ")
	if err != nil {
		return nil
	}
	var env []string
	for _, kv := range strings.Split(string(data), "\x00") {
		for _, k := range []string{"DISPLAY=", "WAYLAND_DISPLAY=", "XDG_RUNTIME_DIR=", "DBUS_SESSION_BUS_ADDRESS=", "XAUTHORITY=", "HOME=", "USER=", "PATH="} {
			if strings.HasPrefix(kv, k) {
				env = append(env, kv)
			}
		}
	}
	return env
}

// Required tests "Fail closed" and "DNS" against the real VPN: while the
// tunnel works, a marker lookup and fetch go only through it (only
// encrypted packets to the endpoint on the physical interface); with the
// tunnel removed, nothing leaves at all.
func TestVMFailClosedAndDNS(t *testing.T) {
	for _, p := range vmProfiles() {
		p := p
		t.Run(p, func(t *testing.T) {
			ensureUp(t, p)
			mk := marker()
			cap := startCapture(t)
			r := inProfile(t, userAllowed, p, "sh", "-c", "getent hosts "+mk+".vpn-lab.test; curl -s -m 10 http://whoami.vpn-lab.test/ ; curl -s -m 10 -o /dev/null http://"+mk+".example.com/")
			if !strings.Contains(r.stdout, "Hostname:") {
				t.Fatalf("whoami via the VPN DNS failed: %v", r)
			}
			tunnel := 0
			ifn := tunnelIf(t, p)
			netnsExec(p, "ip", "link", "del", ifn)
			probeBlocked(t, p, mk)
			r = inProfile(t, userAllowed, p, "curl", "-s", "-m", "5", "https://ifconfig.me")
			if r.code == 0 {
				t.Errorf("exit IP reachable with the tunnel removed: %v", r)
			}
			cap.stop()
			tunnel = cap.tunnelPackets()
			if tunnel == 0 {
				t.Errorf("no encrypted tunnel packets seen; capture is not working")
			}
			cap.assertNoLeaks(mk)
			waitFor(t, 60*time.Second, "tunnel restored", func() bool {
				return inProfile(t, userAllowed, p, "curl", "-s", "-m", "5", "http://172.30.0.80/").code == 0
			})
		})
	}
}
