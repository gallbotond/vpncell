package client

import (
	"errors"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/gallbotond/vpncell/internal/control"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// ExecOptions describe a session to start.
type ExecOptions struct {
	Profile string
	Argv    []string
	TTY     bool
	IsShell bool
}

// forwarded are the signals the client relays to the session (in TTY mode
// the terminal's own keys arrive as bytes instead).
var forwarded = []os.Signal{syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGINT}

// Exec runs a session and returns the exit code the CLI should use.
func Exec(opt ExecOptions) (int, error) {
	c, err := Dial()
	if err != nil {
		return 1, err
	}
	defer c.Close()
	cwd, _ := os.Getwd()
	umask := unix.Umask(0)
	unix.Umask(umask)
	x := &control.ExecRequest{
		Argv: opt.Argv, Env: os.Environ(), Cwd: cwd, TTY: opt.TTY,
		Term: os.Getenv("TERM"), Umask: umask, IsShell: opt.IsShell,
	}
	var files []*os.File
	if opt.TTY {
		if ws, err := pty.GetsizeFull(os.Stdin); err == nil {
			x.Rows, x.Cols = ws.Rows, ws.Cols
		}
	} else {
		files = []*os.File{os.Stdin, os.Stdout, os.Stderr}
	}
	// Catch signals from now on so none is lost between start and relay.
	sigs := make(chan os.Signal, 16)
	signal.Notify(sigs, forwarded...)
	defer signal.Stop(sigs)

	r, got, err := c.Do(control.Request{Type: "exec", Profile: opt.Profile, Exec: x}, files...)
	if err != nil {
		return 1, err
	}
	if r.Type != "started" {
		control.CloseFiles(got)
		return 1, errors.New("unexpected reply from daemon: " + r.Type)
	}
	var master *os.File
	if opt.TTY {
		if len(got) != 1 {
			control.CloseFiles(got)
			return 1, errors.New("daemon sent no terminal")
		}
		nfd, err := unix.Dup(int(got[0].Fd()))
		got[0].Close()
		if err != nil {
			return 1, err
		}
		unix.CloseOnExec(nfd)
		unix.SetNonblock(nfd, true)
		master = os.NewFile(uintptr(nfd), "pty-master")
	} else {
		control.CloseFiles(got)
	}

	var restore func()
	var outDone chan struct{}
	if master != nil {
		if term.IsTerminal(int(os.Stdin.Fd())) {
			if st, err := term.MakeRaw(int(os.Stdin.Fd())); err == nil {
				restore = func() { term.Restore(int(os.Stdin.Fd()), st) }
			}
		}
		outDone = make(chan struct{})
		go func() {
			io.Copy(os.Stdout, master)
			close(outDone)
		}()
		go func() {
			io.Copy(master, os.Stdin)
		}()
		winch := make(chan os.Signal, 4)
		signal.Notify(winch, syscall.SIGWINCH)
		go func() {
			for range winch {
				if ws, err := pty.GetsizeFull(os.Stdin); err == nil {
					pty.Setsize(master, ws)
				}
			}
		}()
	}
	cleanup := func() {
		if restore != nil {
			restore()
			restore = nil
		}
	}
	defer cleanup()

	// Relay signals.
	var smu sync.Mutex
	go func() {
		for s := range sigs {
			// In raw mode Ctrl-C arrives as a byte; a signal sent to the
			// client process itself is relayed to the session.
			sig := int(s.(syscall.Signal))
			smu.Lock()
			c.Send(control.SessionMsg{Type: "signal", Signal: sig})
			smu.Unlock()
		}
	}()

	for {
		var m control.Response
		fs, err := c.RecvInto(&m)
		control.CloseFiles(fs)
		if err != nil {
			cleanup()
			return 255, errors.New("lost connection to the session (daemon or helper ended)")
		}
		switch m.Type {
		case "exit":
			if master != nil {
				// Drain what the command printed last.
				select {
				case <-outDone:
				case <-time.After(500 * time.Millisecond):
				}
				master.Close()
			}
			cleanup()
			if m.Signal != 0 {
				return 128 + m.Signal, nil
			}
			if m.ExitCode != nil {
				return *m.ExitCode, nil
			}
			return 255, nil
		case "error":
			cleanup()
			if m.Error != nil {
				return 1, m.Error
			}
			return 1, errors.New("session failed")
		}
	}
}
