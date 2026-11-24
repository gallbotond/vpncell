package netns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func sockaddr(ap netip.AddrPort) (unix.Sockaddr, int) {
	a := ap.Addr()
	if a.Is4() || a.Is4In6() {
		return &unix.SockaddrInet4{Port: int(ap.Port()), Addr: a.Unmap().As4()}, unix.AF_INET
	}
	sa := &unix.SockaddrInet6{Port: int(ap.Port()), Addr: a.As16()}
	return sa, unix.AF_INET6
}

// Dial connects to dst from inside the factory's namespace. network is "tcp"
// or "udp". Connecting happens on the calling goroutine with the normal
// netpoller; only socket creation runs on a namespace thread.
func (f *Factory) Dial(ctx context.Context, network string, dst netip.AddrPort) (net.Conn, error) {
	sa, family := sockaddr(dst)
	typ := unix.SOCK_STREAM
	proto := unix.IPPROTO_TCP
	if network == "udp" {
		typ, proto = unix.SOCK_DGRAM, unix.IPPROTO_UDP
	}
	fd, err := f.Socket(ctx, family, typ, proto)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "vpncell-sock")
	defer file.Close() // net.FileConn dups the fd
	err = unix.Connect(fd, sa)
	if err != nil && err != unix.EINPROGRESS {
		return nil, &net.OpError{Op: "dial", Net: network, Addr: net.UDPAddrFromAddrPort(dst), Err: os.NewSyscallError("connect", err)}
	}
	if err == unix.EINPROGRESS {
		if err := waitConnect(ctx, file); err != nil {
			return nil, &net.OpError{Op: "dial", Net: network, Addr: net.UDPAddrFromAddrPort(dst), Err: err}
		}
	}
	return net.FileConn(file)
}

func waitConnect(ctx context.Context, file *os.File) error {
	rc, err := file.SyscallConn()
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		file.SetWriteDeadline(dl)
	} else {
		file.SetWriteDeadline(time.Now().Add(30 * time.Second))
	}
	stop := context.AfterFunc(ctx, func() { file.SetWriteDeadline(time.Unix(1, 0)) })
	defer stop()
	var soErr error
	werr := rc.Write(func(fd uintptr) bool {
		v, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ERROR)
		if err != nil {
			soErr = err
			return true
		}
		if v == int(unix.EINPROGRESS) || v == int(unix.EALREADY) {
			return false
		}
		if v != 0 {
			soErr = os.NewSyscallError("connect", unix.Errno(v))
			return true
		}
		// Writable and no error: connected only if getpeername succeeds.
		if _, err := unix.Getpeername(int(fd)); err != nil {
			return false
		}
		return true
	})
	if werr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("connect: %w", werr)
	}
	file.SetWriteDeadline(time.Time{})
	return soErr
}
