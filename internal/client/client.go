// Package client talks to vpncelld over the control socket. It is used by
// the CLI and the native messaging host; it has no privileges.
package client

import (
	"errors"
	"fmt"
	"os"
	"syscall"

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

// Dial connects and performs the hello exchange.
func Dial() (*Client, error) {
	c, err := control.Dial(brand.ControlSock)
	if err != nil {
		if errors.Is(err, syscall.EACCES) {
			return nil, fmt.Errorf("%w: permission denied on %s (are you in the %q group? log out and in after adding)", ErrDaemonUnreachable, brand.ControlSock, brand.Group)
		}
		return nil, fmt.Errorf("%w: %v", ErrDaemonUnreachable, err)
	}
	if err := c.Send(control.Request{Type: "hello", Version: control.Version}); err != nil {
		c.Close()
		return nil, fmt.Errorf("%w: %v", ErrDaemonUnreachable, err)
	}
	var r control.Response
	files, err := c.RecvInto(&r)
	control.CloseFiles(files)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("%w: %v", ErrDaemonUnreachable, err)
	}
	if r.Type == "error" && r.Error != nil {
		c.Close()
		return nil, r.Error
	}
	return &Client{Conn: c, UID: r.UID, Admin: r.Admin}, nil
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
