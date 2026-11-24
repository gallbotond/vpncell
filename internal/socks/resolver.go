package socks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/gallbotond/vpncell/internal/netns"
	"github.com/miekg/dns"
)

// Resolver looks names up with the profile's DNS servers, from sockets
// created inside the profile namespace. It never reads the host's
// /etc/hosts or resolv.conf.
type Resolver struct {
	Factory *netns.Factory
	Servers []netip.Addr
	Search  []string
	Timeout time.Duration
}

// ErrNoDNS means the profile has no DNS servers.
var ErrNoDNS = errors.New("profile has no DNS servers")

// ErrNotFound means the name does not exist.
var ErrNotFound = errors.New("name not found")

func (r *Resolver) candidates(name string) []string {
	name = strings.TrimSuffix(name, ".")
	var out []string
	if strings.Contains(name, ".") {
		out = append(out, name+".")
		for _, s := range r.Search {
			out = append(out, name+"."+strings.TrimSuffix(s, ".")+".")
		}
	} else {
		for _, s := range r.Search {
			out = append(out, name+"."+strings.TrimSuffix(s, ".")+".")
		}
		out = append(out, name+".")
	}
	return out
}

// Lookup returns the addresses of name (AAAA and A).
func (r *Resolver) Lookup(ctx context.Context, name string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(name); err == nil {
		return []netip.Addr{a}, nil
	}
	if len(r.Servers) == 0 {
		return nil, ErrNoDNS
	}
	if len(name) > 253 || name == "" {
		return nil, ErrNotFound
	}
	var lastErr error = ErrNotFound
	for _, fq := range r.candidates(name) {
		addrs, err := r.lookupFQDN(ctx, fq)
		if err == nil && len(addrs) > 0 {
			return addrs, nil
		}
		if err != nil && !errors.Is(err, ErrNotFound) {
			lastErr = err
		}
	}
	return nil, lastErr
}

func (r *Resolver) lookupFQDN(ctx context.Context, fq string) ([]netip.Addr, error) {
	type res struct {
		addrs []netip.Addr
		err   error
	}
	ch := make(chan res, 2)
	for _, qt := range []uint16{dns.TypeAAAA, dns.TypeA} {
		go func(qt uint16) {
			a, err := r.query(ctx, fq, qt)
			ch <- res{a, err}
		}(qt)
	}
	var all []netip.Addr
	var errs []error
	for i := 0; i < 2; i++ {
		x := <-ch
		all = append(all, x.addrs...)
		if x.err != nil {
			errs = append(errs, x.err)
		}
	}
	if len(all) > 0 {
		return all, nil
	}
	for _, e := range errs {
		if !errors.Is(e, ErrNotFound) {
			return nil, e
		}
	}
	return nil, ErrNotFound
}

func (r *Resolver) query(ctx context.Context, fq string, qt uint16) ([]netip.Addr, error) {
	m := new(dns.Msg)
	m.SetQuestion(fq, qt)
	m.RecursionDesired = true
	m.SetEdns0(1232, false)
	timeout := r.Timeout
	if timeout == 0 {
		timeout = 4 * time.Second
	}
	var lastErr error
	for _, srv := range r.Servers {
		resp, err := r.exchange(ctx, m, netip.AddrPortFrom(srv, 53), "udp", timeout)
		if err == nil && resp.Truncated {
			resp, err = r.exchange(ctx, m, netip.AddrPortFrom(srv, 53), "tcp", timeout)
		}
		if err != nil {
			lastErr = err
			continue
		}
		switch resp.Rcode {
		case dns.RcodeSuccess:
			return answers(resp, fq, qt), nil
		case dns.RcodeNameError:
			return nil, ErrNotFound
		default:
			lastErr = fmt.Errorf("dns: %s", dns.RcodeToString[resp.Rcode])
		}
	}
	return nil, lastErr
}

// answers follows CNAME chains inside the response.
func answers(resp *dns.Msg, fq string, qt uint16) []netip.Addr {
	names := map[string]bool{strings.ToLower(fq): true}
	for i := 0; i < 8; i++ {
		grew := false
		for _, rr := range resp.Answer {
			if c, ok := rr.(*dns.CNAME); ok && names[strings.ToLower(c.Hdr.Name)] && !names[strings.ToLower(c.Target)] {
				names[strings.ToLower(c.Target)] = true
				grew = true
			}
		}
		if !grew {
			break
		}
	}
	var out []netip.Addr
	for _, rr := range resp.Answer {
		if !names[strings.ToLower(rr.Header().Name)] {
			continue
		}
		switch v := rr.(type) {
		case *dns.A:
			if qt == dns.TypeA {
				if a, ok := netip.AddrFromSlice(v.A.To4()); ok {
					out = append(out, a)
				}
			}
		case *dns.AAAA:
			if qt == dns.TypeAAAA {
				if a, ok := netip.AddrFromSlice(v.AAAA); ok {
					out = append(out, a)
				}
			}
		}
	}
	return out
}

func (r *Resolver) exchange(ctx context.Context, m *dns.Msg, srv netip.AddrPort, network string, timeout time.Duration) (*dns.Msg, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c, err := r.Factory.Dial(cctx, network, srv)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := cctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	co := &dns.Conn{Conn: c}
	if network == "udp" {
		co.UDPSize = 1232
	}
	if err := co.WriteMsg(m); err != nil {
		return nil, err
	}
	for {
		resp, err := co.ReadMsg()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return nil, fmt.Errorf("dns %s: timeout", srv)
			}
			return nil, err
		}
		if resp.Id != m.Id {
			continue // stray or spoofed packet
		}
		return resp, nil
	}
}
