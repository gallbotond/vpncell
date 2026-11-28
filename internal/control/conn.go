// Package control implements the control-socket protocol: 4-byte big-endian
// length-prefixed JSON frames over a stream connection. File descriptors
// travel with the bytes of a frame (on Linux as SCM_RIGHTS on the sendmsg
// that carries the frame). Frames are read with exact-length reads, so a
// read never crosses a frame boundary and the descriptors are always
// attributed to the right frame.
//
// The protocol and the framing are portable. Descriptor passing and peer
// credentials depend on the platform and sit behind Transport and Peer;
// the Linux implementation is in transport_linux.go (DESIGN.md §11).
package control

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
)

// MaxFrame is the largest accepted frame.
const MaxFrame = 1 << 20

// MaxFDs is the largest number of descriptors accepted with one frame.
const MaxFDs = 8

// ErrPlatformUnsupported is returned where the platform has no descriptor passing
// or peer credentials.
var ErrPlatformUnsupported = errors.New("not supported on this platform")

// Transport is the byte stream under a Conn, plus descriptor passing.
// Conn serialises calls: at most one WriteMsg or Write and one ReadMsg run
// at a time.
type Transport interface {
	// WriteMsg writes a prefix of p and passes files with it. It returns
	// how many bytes of p it wrote; Conn writes the rest with Write.
	WriteMsg(p []byte, files []*os.File) (int, error)
	// Write writes all of p, without files.
	Write(p []byte) (int, error)
	// ReadMsg reads up to len(p) bytes and returns the files that came
	// with them. A FrameError means the descriptors of the frame are
	// broken (too many, or malformed); the caller owns the returned files
	// in every case.
	ReadMsg(p []byte) (int, []*os.File, error)
	Close() error
}

// FrameError is a descriptor error a Transport found while reading. It ends
// the frame before the read error, if any, is looked at.
type FrameError struct{ Err error }

func (e *FrameError) Error() string { return e.Err.Error() }
func (e *FrameError) Unwrap() error { return e.Err }

var errTooManyFDs = errors.New("too many file descriptors")

// Conn is one control connection.
type Conn struct {
	t   Transport
	uc  *net.UnixConn // nil unless the Conn wraps a Unix socket
	wmu sync.Mutex
	rmu sync.Mutex
}

// NewConn wraps a Unix stream connection in the platform's transport.
func NewConn(uc *net.UnixConn) *Conn { return &Conn{t: newUnixTransport(uc), uc: uc} }

// NewConnTransport wraps any transport (tests, other platforms).
func NewConnTransport(t Transport) *Conn { return &Conn{t: t} }

// Dial connects to the control socket.
func Dial(path string) (*Conn, error) {
	uc, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	return NewConn(uc), nil
}

// Unix returns the underlying Unix connection, or nil.
func (c *Conn) Unix() *net.UnixConn { return c.uc }
func (c *Conn) Close() error        { return c.t.Close() }

// Send writes one frame with optional descriptors.
func (c *Conn) Send(v any, files ...*os.File) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(body) > MaxFrame {
		return fmt.Errorf("frame too large")
	}
	buf := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(buf, uint32(len(body)))
	copy(buf[4:], body)
	c.wmu.Lock()
	defer c.wmu.Unlock()
	n, err := c.t.WriteMsg(buf, files)
	if err != nil {
		return err
	}
	if n < len(buf) {
		if _, err := c.t.Write(buf[n:]); err != nil {
			return err
		}
	}
	return nil
}

// Recv reads one frame and returns its raw JSON and any descriptors that came
// with it. The caller owns the returned files.
func (c *Conn) Recv() (json.RawMessage, []*os.File, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	var files []*os.File
	hdr := make([]byte, 4)
	if err := c.readFull(hdr, &files); err != nil {
		closeAll(files)
		return nil, nil, err
	}
	n := binary.BigEndian.Uint32(hdr)
	if n > MaxFrame {
		closeAll(files)
		return nil, nil, fmt.Errorf("frame too large (%d bytes)", n)
	}
	body := make([]byte, n)
	if err := c.readFull(body, &files); err != nil {
		closeAll(files)
		return nil, nil, err
	}
	return body, files, nil
}

func (c *Conn) readFull(p []byte, files *[]*os.File) error {
	off := 0
	for off < len(p) {
		n, got, err := c.t.ReadMsg(p[off:])
		*files = append(*files, got...)
		var fe *FrameError
		if errors.As(err, &fe) {
			return fe.Err
		}
		if len(*files) > MaxFDs {
			return errTooManyFDs
		}
		off += n
		if err != nil {
			if errors.Is(err, io.EOF) && off == len(p) {
				return nil
			}
			if off > 0 && errors.Is(err, io.EOF) {
				return io.ErrUnexpectedEOF
			}
			return err
		}
		if n == 0 {
			return io.EOF
		}
	}
	return nil
}

func closeAll(fs []*os.File) {
	for _, f := range fs {
		f.Close()
	}
}

// CloseFiles closes all files, ignoring errors.
func CloseFiles(fs []*os.File) { closeAll(fs) }

// RecvInto reads one frame and decodes it into v.
func (c *Conn) RecvInto(v any) ([]*os.File, error) {
	raw, files, err := c.Recv()
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, v); err != nil {
		closeAll(files)
		return nil, fmt.Errorf("bad frame: %w", err)
	}
	return files, nil
}

// PeerCred is the identity of the process on the other end.
type PeerCred struct {
	PID    int32
	UID    uint32
	GID    uint32
	Groups []uint32
}
