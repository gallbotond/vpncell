package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/gallbotond/vpncell/internal/brand"
	"github.com/gallbotond/vpncell/internal/control"
	"github.com/gallbotond/vpncell/internal/platform"
	"golang.org/x/sys/unix"
)

// allowedSignals may be forwarded from the client to the session.
var allowedSignals = map[int]bool{
	int(unix.SIGHUP): true, int(unix.SIGINT): true, int(unix.SIGQUIT): true, int(unix.SIGTERM): true,
	int(unix.SIGKILL): true, int(unix.SIGUSR1): true, int(unix.SIGUSR2): true, int(unix.SIGCONT): true,
	int(unix.SIGTSTP): true, int(unix.SIGWINCH): true,
}

func fail(conn *control.Conn, format string, args ...any) int {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, "session-helper:", msg)
	if conn != nil {
		conn.Send(control.Response{Type: "error", Error: control.Errorf(control.ErrInternal, "%s", msg)})
	}
	return 1
}

// RunHelper is the entry point of `vpncelld session-helper`. It runs as
// root, started by the daemon, and must never return to the host namespace.
func RunHelper() int {
	connFile := os.NewFile(FdConn, "conn")
	fc, err := net.FileConn(connFile)
	connFile.Close()
	if err != nil {
		return fail(nil, "client connection: %v", err)
	}
	conn := control.NewConn(fc.(*net.UnixConn))
	defer conn.Close()

	specFile := os.NewFile(FdSpec, "spec")
	data, err := io.ReadAll(io.LimitReader(specFile, control.MaxFrame))
	specFile.Close()
	if err != nil || len(data) == 0 {
		// The daemon closes the pipe without a spec to abort.
		return fail(conn, "no session spec")
	}
	var spec Spec
	if err := json.Unmarshal(data, &spec); err != nil {
		return fail(conn, "bad spec: %v", err)
	}
	if spec.UID == 0 && os.Getenv("VPNCELL_ALLOW_ROOT_SESSION") == "" {
		// Root may use sessions too; nothing special is needed, but keep the
		// same drop path (it is a no-op for uid 0 apart from capabilities).
	}

	// Everything privileged happens on this locked thread, which never
	// returns to the host namespace. The helper process exits at the end.
	runtime.LockOSThread()

	if err := enterNamespaces(&spec); err != nil {
		return fail(conn, "%v", err)
	}

	var master *os.File
	var stdio [3]*os.File
	if spec.TTY {
		m, s, err := pty.Open()
		if err != nil {
			return fail(conn, "pty: %v", err)
		}
		master = m
		ttyGID := spec.GID
		if g, err := lookupTTYGroup(); err == nil {
			ttyGID = g
		}
		if err := unix.Fchown(int(s.Fd()), int(spec.UID), int(ttyGID)); err != nil {
			return fail(conn, "chown pty: %v", err)
		}
		unix.Fchmod(int(s.Fd()), 0o620)
		if spec.Rows > 0 && spec.Cols > 0 {
			pty.Setsize(master, &pty.Winsize{Rows: spec.Rows, Cols: spec.Cols})
		}
		stdio = [3]*os.File{s, s, s}
	} else {
		stdio = [3]*os.File{os.NewFile(FdStdin, "stdin"), os.NewFile(FdStdout, "stdout"), os.NewFile(FdStderr, "stderr")}
	}

	if err := dropBoundingAndSetNoNewPrivs(); err != nil {
		return fail(conn, "%v", err)
	}

	child, err := startChild(&spec, stdio)
	for _, f := range stdio {
		if f != nil {
			f.Close()
		}
	}
	if err != nil {
		return fail(conn, "start: %v", err)
	}

	// The command runs. Drop our own privileges for good.
	if err := dropToUser(spec.UID, spec.GID, spec.Groups); err != nil {
		child.Process.Kill()
		return fail(conn, "drop privileges: %v", err)
	}

	started := control.Response{Type: "started", SessionID: spec.ID}
	if master != nil {
		err = conn.Send(started, master)
		master.Close() // the client holds the only reference now
	} else {
		err = conn.Send(started)
	}
	if err != nil {
		unix.Kill(-child.Process.Pid, unix.SIGHUP)
	}

	pgid := child.Process.Pid
	go relayClient(conn, pgid, spec.TTY)

	st, werr := child.Process.Wait()
	resp := control.Response{Type: "exit"}
	if werr != nil {
		code := 255
		resp.ExitCode = &code
	} else if ws, ok := st.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		resp.Signal = int(ws.Signal())
	} else {
		code := st.ExitCode()
		resp.ExitCode = &code
	}
	conn.Send(resp)
	return 0
}

func relayClient(conn *control.Conn, pgid int, tty bool) {
	for {
		var m control.SessionMsg
		files, err := conn.RecvInto(&m)
		control.CloseFiles(files)
		if err != nil {
			// The client went away: hang up the session, like ssh.
			unix.Kill(-pgid, unix.SIGHUP)
			if !tty {
				unix.Kill(-pgid, unix.SIGCONT)
			}
			return
		}
		if m.Type == "signal" && allowedSignals[m.Signal] {
			unix.Kill(-pgid, unix.Signal(m.Signal))
		}
	}
}

// enterNamespaces moves the calling (locked) thread into the profile's
// network namespace and a new private mount namespace with the resolver
// files.
func enterNamespaces(spec *Spec) error {
	fd, err := unix.Open(spec.NetnsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("profile namespace: %w", err)
	}
	err = unix.Setns(fd, unix.CLONE_NEWNET)
	unix.Close(fd)
	if err != nil {
		return fmt.Errorf("setns: %w", err)
	}
	if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("unshare mount namespace: %w", err)
	}
	// Never propagate our mounts back to the host.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_SLAVE, ""); err != nil {
		return fmt.Errorf("make / slave: %w", err)
	}
	if err := platform.SetupResolver(spec.ResolveDir, spec.Nsswitch); err != nil {
		return err
	}
	return nil
}

// dropBoundingAndSetNoNewPrivs sets thread attributes that the child
// inherits: no_new_privs, an empty capability bounding set and empty ambient
// and inheritable sets.
func dropBoundingAndSetNoNewPrivs() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	for c := 0; c <= lastCap(); c++ {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil && !errors.Is(err, unix.EINVAL) {
			return fmt.Errorf("drop bounding cap %d: %w", c, err)
		}
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil && !errors.Is(err, unix.EINVAL) {
		return fmt.Errorf("clear ambient caps: %w", err)
	}
	// Clear inheritable, keep effective/permitted for now (still needed to
	// set up the child); setuid in the child clears them.
	var hdr = unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return err
	}
	data[0].Inheritable, data[1].Inheritable = 0, 0
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}
	return nil
}

func lastCap() int {
	b, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return 63
	}
	n := 0
	for _, c := range b {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	return n
}

func startChild(spec *Spec, stdio [3]*os.File) (*exec.Cmd, error) {
	self := "/proc/self/exe"
	args := append([]string{brand.Daemon, "session-exec", spec.Cwd}, spec.Argv...)
	cmd := &exec.Cmd{
		Path:   self,
		Args:   args,
		Env:    sessionEnv(spec),
		Stdin:  stdio[0],
		Stdout: stdio[1],
		Stderr: stdio[2],
		Dir:    "/",
	}
	groups := spec.Groups
	if groups == nil {
		groups = []uint32{}
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: spec.UID, Gid: spec.GID, Groups: groups},
		Setsid:     true,
	}
	if spec.TTY {
		cmd.SysProcAttr.Setctty = true
		cmd.SysProcAttr.Ctty = 0
	}
	old := unix.Umask(spec.Umask & 0o777)
	err := cmd.Start()
	unix.Umask(old)
	return cmd, err
}

func sessionEnv(spec *Spec) []string {
	out := make([]string, 0, len(spec.Env)+1)
	for _, kv := range spec.Env {
		if len(kv) > len(brand.EnvProfile) && kv[:len(brand.EnvProfile)+1] == brand.EnvProfile+"=" {
			continue
		}
		out = append(out, kv)
	}
	return append(out, brand.EnvProfile+"="+spec.Profile)
}

func dropToUser(uid, gid uint32, groups []uint32) error {
	gs := make([]int, len(groups))
	for i, g := range groups {
		gs[i] = int(g)
	}
	if err := syscall.Setgroups(gs); err != nil {
		return err
	}
	if err := syscall.Setresgid(int(gid), int(gid), int(gid)); err != nil {
		return err
	}
	if err := syscall.Setresuid(int(uid), int(uid), int(uid)); err != nil {
		return err
	}
	if uid == 0 {
		// Root sessions: still drop all capabilities of the helper.
		hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		var data [2]unix.CapUserData
		unix.Capset(&hdr, &data[0])
	}
	return nil
}

func lookupTTYGroup() (uint32, error) {
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		return 0, err
	}
	for _, line := range splitLines(string(data)) {
		var name, x, gid string
		n := 0
		start := 0
		for i := 0; i <= len(line) && n < 3; i++ {
			if i == len(line) || line[i] == ':' {
				switch n {
				case 0:
					name = line[start:i]
				case 1:
					x = line[start:i]
				case 2:
					gid = line[start:i]
				}
				n++
				start = i + 1
			}
		}
		_ = x
		if name == "tty" {
			var g uint32
			if _, err := fmt.Sscanf(gid, "%d", &g); err == nil {
				return g, nil
			}
		}
	}
	return 0, errors.New("no tty group")
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// RunExec is `vpncelld session-exec <cwd> <argv...>`: it runs as the
// session user with no privileges, changes to the working directory (so
// permissions are checked as the user), resolves the command in the user's
// PATH and execs it.
func RunExec(args []string) int {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "vpncell: no command")
		return 127
	}
	cwd, argv := args[0], args[1:]
	if cwd != "" {
		if err := os.Chdir(cwd); err != nil {
			home := os.Getenv("HOME")
			fmt.Fprintf(os.Stderr, "vpncell: cannot change to %s: %v; using %s\n", cwd, err, orRoot(home))
			if home == "" || os.Chdir(home) != nil {
				os.Chdir("/")
			}
		}
	}
	path, err := exec.LookPath(argv[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "vpncell: %s: command not found\n", argv[0])
		return 127
	}
	err = syscall.Exec(path, argv, os.Environ())
	fmt.Fprintf(os.Stderr, "vpncell: %s: %v\n", argv[0], err)
	if errors.Is(err, syscall.EACCES) {
		return 126
	}
	return 127
}

func orRoot(s string) string {
	if s == "" {
		return "/"
	}
	return s
}

var _ = time.Second
