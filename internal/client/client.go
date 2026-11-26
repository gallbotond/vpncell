// Package client talks to vpncelld over the control socket. It is used by
// the CLI and the native messaging host; it has no privileges.
package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/gallbotond/vpncell/internal/brand"
	"github.com/gallbotond/vpncell/internal/control"
)

type Client struct {
	*control.Conn
	UID   uint32
	Admin bool
}

// ErrDaemonUnreachable wraps connection failures.
var ErrDaemonUnreachable = errors.New("vpncelld is not reachable")

// Notice, if set, receives a one-line "waiting for vpncelld…" message when
// the daemon has not answered the hello after NoticeAfter. The CLI sets it
// to stderr; the native messaging host leaves it nil.
var Notice io.Writer

// Timing of the hello exchange (issue #8). The control socket stays bound
// in systemd's fd store while the daemon is stopped, so connect() succeeds
// and only the hello reply shows whether a daemon is there.
//
//   - NoticeAfter: print the waiting line and start checking the unit state.
//   - HelloTimeout: give up. A restart or a package upgrade (postinst runs
//     `systemctl restart`) takes a few seconds; the daemon's start timeout
//     (TimeoutStartSec, default 90 s) is the outer bound, but a client that
//     waits that long looks hung. 30 s covers a slow start with many
//     profiles to adopt.
var (
	NoticeAfter  = 2 * time.Second
	HelloTimeout = 30 * time.Second
	// stateInterval is the pause between two unit-state checks; a unit
	// must look stopped twice in a row before Dial gives up early, so the
	// short "inactive" moment inside `systemctl restart` does not count.
	stateInterval = time.Second
)

// unitState returns the daemon unit's ActiveState and SubState. It is a
// variable so tests can replace it.
var unitState = func(ctx context.Context) (active, sub string, err error) {
	out, err := exec.CommandContext(ctx, "systemctl", "show", "--property=ActiveState,SubState", "--value", brand.DaemonUnit).Output()
	if err != nil {
		return "", "", err
	}
	f := strings.Fields(string(out))
	if len(f) < 2 {
		return "", "", fmt.Errorf("unexpected systemctl output %q", out)
	}
	return f[0], f[1], nil
}

// unitStopped reports whether the state means "stopped and not about to
// start". A crashed daemon waiting for Restart= is "auto-restart".
func unitStopped(active, sub string) bool {
	return (active == "inactive" || active == "failed") && sub != "auto-restart"
}

const hintStatus = "systemctl status " + brand.DaemonUnit

// unreachable is an error that explains why the daemon cannot be used. It
// matches ErrDaemonUnreachable with errors.Is, but its text stands alone.
type unreachable struct{ msg string }

func (e *unreachable) Error() string { return e.msg }
func (e *unreachable) Unwrap() error { return ErrDaemonUnreachable }

func unreachablef(format string, args ...any) error {
	return &unreachable{fmt.Sprintf(format, args...)}
}

func stoppedErr() error {
	return unreachablef("%s is stopped (start it with: sudo systemctl start %s; see: %s)",
		brand.Daemon, brand.DaemonUnit, hintStatus)
}

func notAnsweringErr(d time.Duration) error {
	return unreachablef("%s is not answering after %s (is it running? %s)",
		brand.Daemon, d.Round(time.Second), hintStatus)
}

// Dial connects and performs the hello exchange.
func Dial() (*Client, error) {
	return dial(brand.ControlSock)
}

func dial(path string) (*Client, error) {
	start := time.Now()
	d := net.Dialer{Timeout: HelloTimeout}
	nc, err := d.Dial("unix", path)
	if err != nil {
		return nil, connectErr(path, err)
	}
	c := control.NewConn(nc.(*net.UnixConn))
	if err := c.Send(control.Request{Type: "hello", Version: control.Version}); err != nil {
		c.Close()
		return nil, fmt.Errorf("%w: %v", ErrDaemonUnreachable, err)
	}

	type reply struct {
		r   control.Response
		err error
	}
	got := make(chan reply, 1)
	go func() {
		var r control.Response
		files, err := c.RecvInto(&r)
		control.CloseFiles(files)
		got <- reply{r, err}
	}()

	notice := time.NewTimer(NoticeAfter)
	defer notice.Stop()
	limit := time.NewTimer(HelloTimeout - time.Since(start))
	defer limit.Stop()
	var check <-chan time.Time // unit-state checks, after the notice
	stoppedSeen := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fail := func(err error) (*Client, error) {
		c.Close() // unblocks the reader goroutine
		<-got
		return nil, err
	}
	for {
		select {
		case rep := <-got:
			if rep.err != nil {
				c.Close()
				return nil, fmt.Errorf("%w: %v", ErrDaemonUnreachable, rep.err)
			}
			if rep.r.Type == "error" && rep.r.Error != nil {
				c.Close()
				return nil, rep.r.Error
			}
			return &Client{Conn: c, UID: rep.r.UID, Admin: rep.r.Admin}, nil
		case <-notice.C:
			if Notice != nil {
				fmt.Fprintf(Notice, "%s: waiting for %s…\n", brand.Name, brand.Daemon)
			}
			check = time.After(0)
		case <-check:
			cctx, ccancel := context.WithTimeout(ctx, 2*time.Second)
			active, sub, err := unitState(cctx)
			ccancel()
			if err == nil && unitStopped(active, sub) {
				stoppedSeen++
			} else {
				stoppedSeen = 0
			}
			if stoppedSeen >= 2 {
				return fail(stoppedErr())
			}
			check = time.After(stateInterval)
		case <-limit.C:
			return fail(notAnsweringErr(HelloTimeout))
		}
	}
}

// connectErr explains a failed connect().
func connectErr(path string, err error) error {
	switch {
	case errors.Is(err, syscall.EACCES):
		return &unreachable{groupHint(path)}
	case errors.Is(err, syscall.ENOENT), errors.Is(err, syscall.ECONNREFUSED):
		return unreachablef("%s is not running (no listener on %s; start it with: sudo systemctl start %s; see: %s)",
			brand.Daemon, path, brand.DaemonUnit, hintStatus)
	}
	return fmt.Errorf("%w: %v", ErrDaemonUnreachable, err)
}

// Do sends a request and reads one reply. Error replies become *control.Error.
func (c *Client) Do(req control.Request, files ...*os.File) (*control.Response, []*os.File, error) {
	if err := c.Send(req, files...); err != nil {
		return nil, nil, err
	}
	var r control.Response
	got, err := c.RecvInto(&r)
	if err != nil {
		return nil, nil, err
	}
	if r.Type == "error" {
		control.CloseFiles(got)
		if r.Error == nil {
			r.Error = control.Errorf(control.ErrInternal, "unknown error")
		}
		return &r, nil, r.Error
	}
	return &r, got, nil
}

// Call is a one-shot request on a new connection.
func Call(req control.Request) (*control.Response, error) {
	c, err := Dial()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	r, files, err := c.Do(req)
	control.CloseFiles(files)
	return r, err
}
