// Package socks is the per-profile SOCKS5 server (RFC 1928, CONNECT only,
// RFC 1929 username/password). It listens in the host namespace on
// 127.0.0.1; every outbound socket, including DNS, is created inside the
// profile namespace by the profile's socket factory (DESIGN.md §6, §7).
package socks

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gallbotond/vpncell/internal/netns"
)

// Reply codes.
const (
	repSuccess         = 0x00
	repGeneralFailure  = 0x01
	repNotAllowed      = 0x02
	repNetUnreachable  = 0x03
	repHostUnreachable = 0x04
	repConnRefused     = 0x05
	repTTLExpired      = 0x06
	repCmdUnsupported  = 0x07
	repAddrUnsupported = 0x08
)

// Backend gives the server what it needs per connection. Get returns an
// error when the profile is not usable (down, failed), which makes the
// request fail closed.
type Backend interface {
	Get(ctx context.Context) (*netns.Factory, *Resolver, error)
}

// Server is one profile's SOCKS5 server.
type Server struct {
	Profile  string
	Log      *slog.Logger
	Backend  Backend
	MaxConns int64

	mu     sync.Mutex
	user   []byte
	pass   []byte
	ln     net.Listener
	conns  atomic.Int64
	active map[net.Conn]struct{}
	closed bool
	// Accepted counts handled connections (for tests and status).
	Accepted atomic.Uint64
}

// SetCredentials replaces the username and password.
func (s *Server) SetCredentials(user, pass string) {
	s.mu.Lock()
	s.user, s.pass = []byte(user), []byte(pass)
	s.mu.Unlock()
}

// Serve accepts connections until the listener is closed.
func (s *Server) Serve(ln net.Listener) {
	s.mu.Lock()
	s.ln = ln
	if s.active == nil {
		s.active = map[net.Conn]struct{}{}
	}
	if s.MaxConns == 0 {
		s.MaxConns = 4096
	}
	s.mu.Unlock()
	for {
		c, err := ln.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.Log.Warn("socks accept", "profile", s.Profile, "err", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if s.conns.Add(1) > s.MaxConns {
			s.conns.Add(-1)
			c.Close()
			continue
		}
		s.track(c, true)
		go func() {
			defer s.conns.Add(-1)
			defer s.track(c, false)
			defer c.Close()
			s.Accepted.Add(1)
			s.handle(c)
		}()
	}
}

func (s *Server) track(c net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.active[c] = struct{}{}
	} else {
		delete(s.active, c)
	}
}

// Stop closes the listener's Go handle (the descriptor itself may stay in
// systemd's fd store) and all active connections.
func (s *Server) Stop() {
	s.mu.Lock()
	ln := s.ln
	conns := make([]net.Conn, 0, len(s.active))
	for c := range s.active {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
	for _, c := range conns {
		c.Close()
	}
}

// CloseActive closes the established connections (profile down).
func (s *Server) CloseActive() {
	s.mu.Lock()
	conns := make([]net.Conn, 0, len(s.active))
	for c := range s.active {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

func readN(r io.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

func (s *Server) handle(c net.Conn) {
	c.SetDeadline(time.Now().Add(15 * time.Second))
	// Greeting.
	h, err := readN(c, 2)
	if err != nil || h[0] != 5 || h[1] == 0 {
		return
	}
	methods, err := readN(c, int(h[1]))
	if err != nil {
		return
	}
	hasUP := false
	for _, m := range methods {
		if m == 2 {
			hasUP = true
		}
	}
	if !hasUP {
		c.Write([]byte{5, 0xff})
		return
	}
	if _, err := c.Write([]byte{5, 2}); err != nil {
		return
	}
	// RFC 1929.
	v, err := readN(c, 2)
	if err != nil || v[0] != 1 {
		return
	}
	u, err := readN(c, int(v[1]))
	if err != nil {
		return
	}
	pl, err := readN(c, 1)
	if err != nil {
		return
	}
	p, err := readN(c, int(pl[0]))
	if err != nil {
		return
	}
	s.mu.Lock()
	wantU, wantP := s.user, s.pass
	s.mu.Unlock()
	okU := subtle.ConstantTimeCompare(u, wantU)
	okP := subtle.ConstantTimeCompare(p, wantP)
	if len(wantU) == 0 || okU&okP != 1 {
		c.Write([]byte{1, 1})
		return
	}
	if _, err := c.Write([]byte{1, 0}); err != nil {
		return
	}
	// Request.
	req, err := readN(c, 4)
	if err != nil || req[0] != 5 {
		return
	}
	if req[1] != 1 { // CONNECT only
		reply(c, repCmdUnsupported, nil)
		return
	}
	var host string
	var ip netip.Addr
	switch req[3] {
	case 1:
		b, err := readN(c, 4)
		if err != nil {
			return
		}
		ip = netip.AddrFrom4([4]byte(b))
	case 4:
		b, err := readN(c, 16)
		if err != nil {
			return
		}
		ip = netip.AddrFrom16([16]byte(b)).Unmap()
	case 3:
		l, err := readN(c, 1)
		if err != nil || l[0] == 0 {
			return
		}
		b, err := readN(c, int(l[0]))
		if err != nil {
			return
		}
		host = string(b)
		if a, err := netip.ParseAddr(host); err == nil {
			ip, host = a.Unmap(), ""
		}
	default:
		reply(c, repAddrUnsupported, nil)
		return
	}
	pb, err := readN(c, 2)
	if err != nil {
		return
	}
	port := binary.BigEndian.Uint16(pb)
	if port == 0 {
		reply(c, repGeneralFailure, nil)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f, res, err := s.Backend.Get(ctx)
	if err != nil {
		s.Log.Debug("socks: profile not usable", "profile", s.Profile, "err", err)
		reply(c, repGeneralFailure, nil)
		return
	}
	var addrs []netip.Addr
	if host != "" {
		addrs, err = res.Lookup(ctx, host)
		if err != nil || len(addrs) == 0 {
			reply(c, repHostUnreachable, nil)
			return
		}
	} else {
		addrs = []netip.Addr{ip}
	}
	out, err := dialRace(ctx, f, addrs, port)
	if err != nil {
		reply(c, errCode(err), nil)
		return
	}
	defer out.Close()
	if err := reply(c, repSuccess, out.LocalAddr()); err != nil {
		return
	}
	c.SetDeadline(time.Time{})
	splice(c, out)
}

func errCode(err error) byte {
	switch {
	case errors.Is(err, syscall.ENETUNREACH):
		return repNetUnreachable
	case errors.Is(err, syscall.EHOSTUNREACH):
		return repHostUnreachable
	case errors.Is(err, syscall.ECONNREFUSED):
		return repConnRefused
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, syscall.ETIMEDOUT):
		return repTTLExpired
	case errors.Is(err, netns.ErrClosed):
		return repGeneralFailure
	}
	return repHostUnreachable
}

// dialRace connects to the first reachable address, starting a new attempt
// every 250 ms while earlier ones are still pending (happy eyeballs).
func dialRace(ctx context.Context, f *netns.Factory, addrs []netip.Addr, port uint16) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, len(addrs))
	pending := 0
	var firstErr error
	start := func(a netip.Addr) {
		pending++
		go func() {
			c, err := f.Dial(ctx, "tcp", netip.AddrPortFrom(a, port))
			ch <- res{c, err}
		}()
	}
	i := 0
	start(addrs[i])
	i++
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for pending > 0 || i < len(addrs) {
		if pending == 0 {
			start(addrs[i])
			i++
			continue
		}
		select {
		case r := <-ch:
			pending--
			if r.err == nil {
				// Close any late winners.
				go func(n int) {
					for ; n > 0; n-- {
						if x := <-ch; x.c != nil {
							x.c.Close()
						}
					}
				}(pending)
				return r.c, nil
			}
			if firstErr == nil || errors.Is(firstErr, syscall.ENETUNREACH) {
				firstErr = r.err
			}
			if i < len(addrs) {
				start(addrs[i])
				i++
			}
		case <-tick.C:
			if i < len(addrs) {
				start(addrs[i])
				i++
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("no address")
	}
	return nil, firstErr
}

func reply(c net.Conn, code byte, bound net.Addr) error {
	b := []byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}
	if ta, ok := bound.(*net.TCPAddr); ok {
		ap := ta.AddrPort()
		if ap.Addr().Is4() || ap.Addr().Is4In6() {
			a := ap.Addr().Unmap().As4()
			b = append([]byte{5, code, 0, 1}, a[:]...)
		} else {
			a := ap.Addr().As16()
			b = append([]byte{5, code, 0, 4}, a[:]...)
		}
		b = binary.BigEndian.AppendUint16(b, ap.Port())
	}
	_, err := c.Write(b)
	return err
}

func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if tc, ok := dst.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		} else {
			dst.Close()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	// Give the other direction a moment to finish its half-close.
	t := time.NewTimer(30 * time.Second)
	select {
	case <-done:
	case <-t.C:
	}
	t.Stop()
	a.Close()
	b.Close()
}
