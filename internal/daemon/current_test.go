package daemon

import "testing"

func TestScopeSessionID(t *testing.T) {
	for in, want := range map[string]string{
		"0::/vpncell.slice/vpncell-sessions.slice/vpncell-s-demo-openvpn-1000-aff5cf31eeef.scope\n":  "aff5cf31eeef",
		"0::/vpncell.slice/vpncell-sessions.slice/vpncell-s-a-b-c-0-0123456789ab.scope/sub/cgroup\n": "0123456789ab",
		"0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-terminal.scope\n":      "",
		"12:pids:/\n0::/system.slice/vpncelld.service\n":                                             "",
	} {
		if got := scopeSessionID(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
