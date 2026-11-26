package daemon

import "testing"

func TestWithin(t *testing.T) {
	for _, c := range []struct {
		path string
		want bool
	}{
		{"/etc/vpncell/secrets/a/wg.conf", true},
		{"/etc/vpncell/secrets/a/../a/client.ovpn", true},
		{"/etc/vpncell/secrets/a", true},
		{"/etc/vpncell/secrets/ab/wg.conf", false},
		{"/etc/vpncell/secrets/a/../b/wg.conf", false},
		{"/home/u/wg.conf", false},
		{"/etc/vpncell/secrets/a/..x", true},
	} {
		if got := within("/etc/vpncell/secrets/a", c.path); got != c.want {
			t.Errorf("within(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}
