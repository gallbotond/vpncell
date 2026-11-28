//go:build !linux

package control

import (
	"net"
	"os"
)

// unixTransport on other platforms carries frames but no descriptors.
// Descriptor passing and peer credentials there are part of #69.
type unixTransport struct{ uc *net.UnixConn }

func newUnixTransport(uc *net.UnixConn) Transport { return &unixTransport{uc: uc} }

func (t *unixTransport) Write(p []byte) (int, error) { return t.uc.Write(p) }
func (t *unixTransport) Close() error                { return t.uc.Close() }

func (t *unixTransport) WriteMsg(p []byte, files []*os.File) (int, error) {
	if len(files) > 0 {
		return 0, ErrPlatformUnsupported
	}
	return t.uc.Write(p)
}

func (t *unixTransport) ReadMsg(p []byte) (int, []*os.File, error) {
	n, err := t.uc.Read(p)
	return n, nil, err
}

// Peer is not implemented on this platform.
func Peer(*net.UnixConn) (*PeerCred, error) { return nil, ErrPlatformUnsupported }
