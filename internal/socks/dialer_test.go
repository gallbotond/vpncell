package socks

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeDialer stands in for the profile namespace's socket factory. TCP
// dials get an in-memory connection to an echo peer, or the error set for
// the address; UDP dials (DNS) go to udpTarget on loopback.
type fakeDialer struct {
	mu        sync.Mutex
	dialed    []string // "network dst"
	errs      map[netip.Addr]error
	udpTarget string
}

func (d *fakeDialer) Dial(ctx context.Context, network string, dst netip.AddrPort) (net.Conn, error) {
	d.mu.Lock()
	d.dialed = append(d.dialed, network+" "+dst.String())
	err := d.errs[dst.Addr()]
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if network == "udp" {
		var nd net.Dialer
		return nd.DialContext(ctx, "udp", d.udpTarget)
	}
	a, b := net.Pipe()
	go func() { io.Copy(b, b); b.Close() }()
	return a, nil
}

func (d *fakeDialer) calls() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.dialed...)
}

type fakeBackend struct {
	d   *fakeDialer
	res *Resolver
}

func (b *fakeBackend) Get(context.Context) (Dialer, *Resolver, error) { return b.d, b.res, nil }

// connect runs a CONNECT request through the server and returns the reply
// code and the client end of the connection.
func connect(t *testing.T, s *Server, target []byte) (byte, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	go func() { s.handle(b); b.Close() }()
	a.SetDeadline(time.Now().Add(5 * time.Second))
	req := append(auth("user", "pass"), 5, 1, 0)
	go a.Write(append(req, target...))
	hdr := make([]byte, 2+2+10) // method choice, auth status, reply
	if _, err := io.ReadFull(a, hdr); err != nil {
		t.Fatal(err)
	}
	return hdr[5], a
}

func TestConnectUsesDialer(t *testing.T) {
	d := &fakeDialer{}
	code, c := connect(t, newServer(&fakeBackend{d: d}), []byte{1, 10, 0, 0, 1, 0, 80})
	defer c.Close()
	if code != repSuccess {
		t.Fatalf("reply %d", code)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "ping" {
		t.Fatalf("echo %q %v", got, err)
	}
	if calls := d.calls(); len(calls) != 1 || calls[0] != "tcp 10.0.0.1:80" {
		t.Fatalf("dialed %v", calls)
	}
}

func TestConnectErrorCodes(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.2")
	for _, tc := range []struct {
		err  error
		want byte
	}{
		{syscall.ECONNREFUSED, repConnRefused},
		{syscall.ENETUNREACH, repNetUnreachable},
		{syscall.EHOSTUNREACH, repHostUnreachable},
		{context.DeadlineExceeded, repTTLExpired},
		{errors.New("other"), repHostUnreachable},
	} {
		d := &fakeDialer{errs: map[netip.Addr]error{ip: tc.err}}
		code, c := connect(t, newServer(&fakeBackend{d: d}), []byte{1, 10, 0, 0, 2, 0, 80})
		c.Close()
		if code != tc.want {
			t.Errorf("%v: reply %d, want %d", tc.err, code, tc.want)
		}
	}
}

func TestDialRaceFallsBack(t *testing.T) {
	bad, good := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("10.0.0.3")
	d := &fakeDialer{errs: map[netip.Addr]error{bad: syscall.ENETUNREACH}}
	c, err := dialRace(context.Background(), d, []netip.Addr{bad, good}, 443)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if calls := d.calls(); len(calls) != 2 || calls[1] != "tcp 10.0.0.3:443" {
		t.Fatalf("dialed %v", calls)
	}
	if _, err := dialRace(context.Background(), d, []netip.Addr{bad}, 443); !errors.Is(err, syscall.ENETUNREACH) {
		t.Fatalf("all fail: %v", err)
	}
}

// TestNamedTargetResolvesThroughDialer: the name is looked up with the
// profile's DNS server through the Dialer, then the answer is dialled.
func TestNamedTargetResolvesThroughDialer(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		if q.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(10, 0, 0, 4),
			})
		}
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	defer srv.Shutdown()

	dnsServer := netip.MustParseAddr("10.53.0.1")
	d := &fakeDialer{udpTarget: pc.LocalAddr().String()}
	res := &Resolver{Dialer: d, Servers: []netip.Addr{dnsServer}, Timeout: 2 * time.Second}
	name := "intranet.example"
	code, c := connect(t, newServer(&fakeBackend{d: d, res: res}), append(append([]byte{3, byte(len(name))}, name...), 0, 80))
	c.Close()
	if code != repSuccess {
		t.Fatalf("reply %d", code)
	}
	var sawDNS, sawTarget bool
	for _, call := range d.calls() {
		sawDNS = sawDNS || call == "udp 10.53.0.1:53"
		sawTarget = sawTarget || call == "tcp 10.0.0.4:80"
	}
	if !sawDNS || !sawTarget {
		t.Fatalf("dialed %v", d.calls())
	}
}
