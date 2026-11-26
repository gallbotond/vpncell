package reach

import (
	"net/netip"
	"strings"
	"testing"
)

func pfx(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func TestNormalizeMergesDef1(t *testing.T) {
	got := Normalize(pfx("128.0.0.0/1", "0.0.0.0/1", "10.0.0.0/8", "::/1", "8000::/1"))
	if len(got) != 2 || got[0] != pfx("0.0.0.0/0")[0] || got[1] != pfx("::/0")[0] {
		t.Fatalf("%v", got)
	}
	if !Default4(got) || !Default6(got) {
		t.Fatal("defaults")
	}
}

func TestDescribe(t *testing.T) {
	for _, c := range []struct {
		in   []netip.Prefix
		want string
	}{
		{pfx("172.30.0.0/16"), "only 172.30.0.0/16; no IPv6"},
		{pfx("0.0.0.0/0", "::/0"), "all IPv4; all IPv6"},
		{pfx("172.30.0.0/16", "2000::/3"), "only 172.30.0.0/16; IPv6 internet (2000::/3)"},
		{pfx("0.0.0.0/1", "128.0.0.0/1"), "all IPv4; no IPv6"},
		{pfx("10.0.0.0/8", "10.1.0.0/16", "192.168.0.0/24"), "only 10.0.0.0/8, 192.168.0.0/24; no IPv6"},
		{nil, "no IPv4; no IPv6"},
	} {
		if got := Describe(c.in); got != c.want {
			t.Errorf("%v: %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIntersect(t *testing.T) {
	// Profile routes everything; server allows only the lab.
	got := Intersect(pfx("0.0.0.0/0", "::/0"), pfx("172.30.0.0/16"))
	if Describe(got) != "only 172.30.0.0/16; no IPv6" {
		t.Fatal(got)
	}
	// Profile limited to 10/8; server allows everything.
	got = Intersect(pfx("10.0.0.0/8"), pfx("0.0.0.0/0", "::/0"))
	if !strings.HasPrefix(Describe(got), "only 10.0.0.0/8") {
		t.Fatal(got)
	}
	if got := Intersect(pfx("10.0.0.0/8"), pfx("192.168.0.0/16")); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestCovers(t *testing.T) {
	ps := pfx("172.30.0.0/16")
	if !Covers(ps, netip.MustParseAddr("172.30.2.53")) || Covers(ps, netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("covers")
	}
}
