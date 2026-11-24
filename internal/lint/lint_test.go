// Package lint holds source checks for the privileged code.
package lint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setns may appear only where DESIGN.md §6 allows it: internal/netns, the
// session helper and the OpenVPN hook (both short-lived processes that never
// return to the host namespace), and the test lab.
var setnsAllowed = []string{"internal/netns/", "internal/session/", "internal/backend/openvpn/hook", "test/"}

func TestSetnsOnlyInAllowedPlaces(t *testing.T) {
	root := "../.."
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		data, _ := os.ReadFile(path)
		s := string(data)
		if !strings.Contains(s, "unix.Setns(") && !strings.Contains(s, "netns.Set(") && !strings.Contains(s, "SYS_SETNS") {
			return nil
		}
		for _, a := range setnsAllowed {
			if strings.HasPrefix(rel, a) {
				return nil
			}
		}
		t.Errorf("%s calls setns outside the allowed packages", rel)
		return nil
	})
}

// No vpncell code may set SO_MARK (the leak capture relies on it, and marks
// would interact with Tailscale's policy routing).
func TestNoSOMark(t *testing.T) {
	filepath.Walk("../..", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, _ := os.ReadFile(path)
		if strings.Contains(string(data), "SO_MARK") {
			t.Errorf("%s uses SO_MARK", path)
		}
		return nil
	})
}

// The daemon must not start shells or the ip/wg/nft tools.
func TestNoShellOutInDaemon(t *testing.T) {
	for _, dir := range []string{"../daemon", "../netns", "../backend", "../firewall", "../dnsfiles", "../socks", "../session"} {
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, _ := os.ReadFile(path)
			for _, bad := range []string{`"/bin/sh"`, `"sh"`, `"bash"`, `"ip"`, `"wg"`, `"nft"`, `"wg-quick"`, `"iptables"`} {
				if strings.Contains(string(data), "exec.Command("+bad) {
					t.Errorf("%s shells out to %s", path, bad)
				}
			}
			return nil
		})
	}
}
