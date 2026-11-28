package control

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// unixTransport passes descriptors as SCM_RIGHTS.
type unixTransport struct {
	uc  *net.UnixConn
	oob []byte // read side; Conn serialises reads
}

func newUnixTransport(uc *net.UnixConn) Transport {
	return &unixTransport{uc: uc, oob: make([]byte, unix.CmsgSpace(MaxFDs*4))}
}

func (t *unixTransport) Write(p []byte) (int, error) { return t.uc.Write(p) }
func (t *unixTransport) Close() error                { return t.uc.Close() }

func (t *unixTransport) WriteMsg(p []byte, files []*os.File) (int, error) {
	var oob []byte
	if len(files) > 0 {
		fds := make([]int, len(files))
		for i, f := range files {
			fds[i] = int(f.Fd())
		}
		oob = unix.UnixRights(fds...)
	}
	n, oobn, err := t.uc.WriteMsgUnix(p, oob, nil)
	if err != nil {
		return n, err
	}
	if oobn != len(oob) {
		return n, fmt.Errorf("short oob write")
	}
	return n, nil
}

func (t *unixTransport) ReadMsg(p []byte) (int, []*os.File, error) {
	n, oobn, flags, _, err := t.uc.ReadMsgUnix(p, t.oob)
	var files []*os.File
	if oobn > 0 {
		got, perr := parseRights(t.oob[:oobn])
		for _, fd := range got {
			files = append(files, os.NewFile(uintptr(fd), "scm"))
		}
		if perr != nil {
			return n, files, &FrameError{perr}
		}
	}
	if flags&unix.MSG_CTRUNC != 0 {
		return n, files, &FrameError{errTooManyFDs}
	}
	return n, files, err
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

func uintptrOf(b []uint32) uintptr   { return uintptr(unsafe.Pointer(&b[0])) }
func uintptrOfU32(p *uint32) uintptr { return uintptr(unsafe.Pointer(p)) }
