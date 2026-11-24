// Package control implements the control-socket protocol: 4-byte big-endian
// length-prefixed JSON frames over a Unix stream socket. File descriptors
// travel as SCM_RIGHTS on the sendmsg that carries the frame. Frames are read
// with exact-length reads, so a recvmsg never crosses a frame boundary and the
// descriptors are always attributed to the right frame.
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
	"syscall"

	"golang.org/x/sys/unix"
)

// MaxFrame is the largest accepted frame.
const MaxFrame = 1 << 20

// MaxFDs is the largest number of descriptors accepted with one frame.
const MaxFDs = 8

// Conn wraps a Unix stream connection.
type Conn struct {
	uc  *net.UnixConn
	wmu sync.Mutex
	rmu sync.Mutex
}

func NewConn(uc *net.UnixConn) *Conn { return &Conn{uc: uc} }

// Dial connects to the control socket.
func Dial(path string) (*Conn, error) {
	uc, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	return NewConn(uc), nil
}

func (c *Conn) Unix() *net.UnixConn { return c.uc }
func (c *Conn) Close() error        { return c.uc.Close() }

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
	var oob []byte
	if len(files) > 0 {
		fds := make([]int, len(files))
		for i, f := range files {
			fds[i] = int(f.Fd())
		}
		oob = unix.UnixRights(fds...)
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	n, oobn, err := c.uc.WriteMsgUnix(buf, oob, nil)
	if err != nil {
		return err
	}
	if oobn != len(oob) {
		return fmt.Errorf("short oob write")
	}
	if n < len(buf) {
		if _, err := c.uc.Write(buf[n:]); err != nil {
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
	oob := make([]byte, unix.CmsgSpace(MaxFDs*4))
	off := 0
	for off < len(p) {
		n, oobn, flags, _, err := c.uc.ReadMsgUnix(p[off:], oob)
		if oobn > 0 {
			got, perr := parseRights(oob[:oobn])
			for _, fd := range got {
				*files = append(*files, os.NewFile(uintptr(fd), "scm"))
			}
			if perr != nil {
				return perr
			}
		}
		if flags&unix.MSG_CTRUNC != 0 {
			return fmt.Errorf("too many file descriptors")
		}
		if len(*files) > MaxFDs {
			return fmt.Errorf("too many file descriptors")
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

func parseRights(oob []byte) ([]int, error) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	var out []int
	for _, m := range msgs {
		if m.Header.Level != unix.SOL_SOCKET || m.Header.Type != unix.SCM_RIGHTS {
			continue
		}
		fds, err := unix.ParseUnixRights(&m)
		if err != nil {
			return out, err
		}
		for _, fd := range fds {
			unix.CloseOnExec(fd)
		}
		out = append(out, fds...)
	}
	return out, nil
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

// Peer returns SO_PEERCRED and SO_PEERGROUPS of the connection.
func Peer(uc *net.UnixConn) (*PeerCred, error) {
	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var groups []uint32
	var serr error
	err = raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if serr != nil {
			return
		}
		groups, serr = getPeerGroups(int(fd))
	})
	if err != nil {
		return nil, err
	}
	if serr != nil {
		return nil, serr
	}
	return &PeerCred{PID: cred.Pid, UID: cred.Uid, GID: cred.Gid, Groups: groups}, nil
}

func getPeerGroups(fd int) ([]uint32, error) {
	buf := make([]uint32, 64)
	for {
		l := uint32(len(buf) * 4)
		_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_SOCKET, unix.SO_PEERGROUPS,
			uintptrOf(buf), uintptrOfU32(&l), 0)
		if e == unix.ERANGE {
			buf = make([]uint32, l/4+1)
			continue
		}
		if e != 0 {
			return nil, e
		}
		return buf[:l/4], nil
	}
}
