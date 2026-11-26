// Package reach describes which networks a profile can reach through its
// tunnel (issue #15). A profile sends everything into the tunnel and never
// falls back to the host connection, so a split-tunnel server (WireGuard
// AllowedIPs, OpenVPN pushed routes without redirect-gateway) leaves every
// other address unreachable. These helpers turn prefix lists into
// something people can read.
package reach

import (
	"net/netip"
	"sort"
	"strings"
)

var (
	all4 = netip.MustParsePrefix("0.0.0.0/0")
	all6 = netip.MustParsePrefix("::/0")
	// IPv6 global unicast: OpenVPN servers often push this instead of ::/0.
	global6 = netip.MustParsePrefix("2000::/3")
)

// Normalize masks, removes duplicates and prefixes contained in others,
// and sorts.
func Normalize(ps []netip.Prefix) []netip.Prefix {
	var in []netip.Prefix
	for _, p := range ps {
		if p.IsValid() {
			in = append(in, p.Masked())
		}
	}
	sort.Slice(in, func(i, j int) bool {
		if in[i].Addr().Is4() != in[j].Addr().Is4() {
			return in[i].Addr().Is4()
		}
		if in[i].Bits() != in[j].Bits() {
			return in[i].Bits() < in[j].Bits()
		}
		return in[i].Addr().Less(in[j].Addr())
	})
	var out []netip.Prefix
	for _, p := range in {
		covered := false
		for _, q := range out {
			if q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, p)
		}
	}
	// Two halves make the whole (redirect-gateway def1, wg-quick style).
	out = mergeHalves(out)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr().Is4() != out[j].Addr().Is4() {
			return out[i].Addr().Is4()
		}
		return out[i].Addr().Less(out[j].Addr()) || (out[i].Addr() == out[j].Addr() && out[i].Bits() < out[j].Bits())
	})
	return out
}

// mergeHalves joins sibling prefixes into their parent, repeatedly.
func mergeHalves(ps []netip.Prefix) []netip.Prefix {
	for changed := true; changed; {
		changed = false
		for i := 0; i < len(ps) && !changed; i++ {
			for j := i + 1; j < len(ps) && !changed; j++ {
				a, b := ps[i], ps[j]
				if a.Bits() != b.Bits() || a.Bits() == 0 || a.Addr().Is4() != b.Addr().Is4() {
					continue
				}
				pa, _ := a.Addr().Prefix(a.Bits() - 1)
				pb, _ := b.Addr().Prefix(b.Bits() - 1)
				if pa == pb {
					ps = append(append(append([]netip.Prefix{}, ps[:i]...), ps[i+1:j]...), ps[j+1:]...)
					ps = append(ps, pa)
					changed = true
				}
			}
		}
	}
	return ps
}

// Intersect returns the parts of a that b also covers.
func Intersect(a, b []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, x := range Normalize(a) {
		for _, y := range Normalize(b) {
			if x.Addr().Is4() != y.Addr().Is4() {
				continue
			}
			switch {
			case x.Bits() >= y.Bits() && y.Contains(x.Addr()):
				out = append(out, x)
			case y.Bits() > x.Bits() && x.Contains(y.Addr()):
				out = append(out, y)
			}
		}
	}
	return Normalize(out)
}

// Covers reports whether an address is inside one of the prefixes.
func Covers(ps []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Default4 reports whether the list reaches every IPv4 address; Default6
// whether it reaches the IPv6 internet (::/0 or 2000::/3).
func Default4(ps []netip.Prefix) bool {
	for _, p := range Normalize(ps) {
		if p == all4 {
			return true
		}
	}
	return false
}

func Default6(ps []netip.Prefix) bool {
	for _, p := range Normalize(ps) {
		if p == all6 || p == global6 {
			return true
		}
	}
	return false
}

// Describe is a short text, e.g. "all IPv4, IPv6 internet (2000::/3)" or
// "only 172.30.0.0/16; no IPv6".
func Describe(ps []netip.Prefix) string {
	n := Normalize(ps)
	var v4, v6 []string
	full4, full6 := Default4(n), false
	for _, p := range n {
		switch {
		case p == all4:
		case p == all6:
			full6 = true
		case p == global6:
			full6 = true
			v6 = append(v6, "IPv6 internet (2000::/3)")
		case p.Addr().Is4():
			v4 = append(v4, p.String())
		default:
			v6 = append(v6, p.String())
		}
	}
	var parts []string
	switch {
	case full4:
		parts = append(parts, "all IPv4")
	case len(v4) > 0:
		parts = append(parts, "only "+strings.Join(v4, ", "))
	default:
		parts = append(parts, "no IPv4")
	}
	switch {
	case full6 && len(v6) == 0:
		parts = append(parts, "all IPv6")
	case len(v6) > 0:
		parts = append(parts, strings.Join(v6, ", "))
	default:
		parts = append(parts, "no IPv6")
	}
	return strings.Join(parts, "; ")
}
