//go:build integration

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// OpenVPN profiles (build step 5): two lab servers with the same overlapping
// service range as the WireGuard ones, and the VM's OpenVPN server.

const labOVPNServers = 2

func setupOpenVPNLab() error {
	for i := 1; i <= labOVPNServers; i++ {
		s, err := theLab.AddOpenVPN(fmt.Sprintf("ovpn%d", i), 10+i)
		if err != nil {
			return err
		}
		if err := importProfile(fmt.Sprintf("t-ovpn%d", i), s.ClientConfig); err != nil {
			return err
		}
	}
	return nil
}

func setupOpenVPNVM() error {
	return importProfile("vm-ovpn", filepath.Join(vmConfigs, "vm-ovpn.ovpn"))
}

func openVPNLabSets() []profileSet {
	return []profileSet{
		{"openvpn", "t-ovpn1", "t-ovpn2", "ovpn1", "ovpn2"},
		{"mixed", "t-wg1", "t-ovpn1", "wg1", "ovpn1"},
	}
}

func openVPNVMProfiles() []string { return []string{"vm-ovpn"} }

func openVPNStressProfiles() [][2]string {
	var out [][2]string
	for i := 1; i <= labOVPNServers; i++ {
		out = append(out, [2]string{fmt.Sprintf("t-ovpn%d", i), fmt.Sprintf("ovpn%d", i)})
	}
	return out
}

// Required test "Import safety" (OpenVPN): directives that run programs,
// change the host or need interaction are rejected, stripped ones are
// reported, and nothing from the config ever runs as root.
func TestImportSafetyOpenVPN(t *testing.T) {
	canary := filepath.Join(os.TempDir(), "vpncell-canary-"+marker())
	defer os.Remove(canary)
	base, err := os.ReadFile(theLab.Servers["ovpn1"].ClientConfig)
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(t.TempDir(), "canary.sh")
	os.WriteFile(script, []byte("#!/bin/sh\ntouch "+canary+"\n"), 0o755)
	// Rejected outright.
	for _, d := range []string{
		"up " + script, "down " + script, "route-up " + script, "route-pre-down " + script, "ipchange " + script,
		"learn-address " + script, "tls-verify " + script, "auth-user-pass-verify " + script + " via-env",
		"plugin /usr/lib/openvpn/openvpn-plugin-down-root.so " + script, "script-security 3", "up-delay",
		"config /etc/passwd", "dev-node /dev/net/tun", "management 127.0.0.1 7505", "daemon", "log /tmp/x",
		"auth-user-pass", "static-challenge \"OTP\" 1", "auth-retry interact", "dev tap", "dns-updown " + script,
		"http-proxy 127.0.0.1 3128", "route-noexec", "ifconfig-noexec", "writepid /tmp/x.pid", "cd /tmp", "chroot /tmp",
	} {
		p := filepath.Join(t.TempDir(), "evil.ovpn")
		os.WriteFile(p, append([]byte(d+"\n"), base...), 0o600)
		r := root(t, "import", "t-rej", p)
		if r.code == 0 || !strings.Contains(r.stderr, "rejected") {
			t.Errorf("%q: not rejected: %v", d, r)
		}
		if _, err := os.Stat("/etc/vpncell/profiles.d/t-rej.toml"); err == nil {
			t.Errorf("%q: rejected profile stored", d)
			os.Remove("/etc/vpncell/profiles.d/t-rej.toml")
		}
	}
	// Stripped and reported; the profile still works.
	p := filepath.Join(t.TempDir(), "strip.ovpn")
	os.WriteFile(p, append([]byte("user nobody\ngroup nogroup\npersist-tun\nresolv-retry 5\nsetenv FOO bar\nverb 9\n"), base...), 0o600)
	r := root(t, "import", "--replace", "--user", userAllowed, "t-ostrip", p)
	if r.code != 0 {
		t.Fatalf("import: %v", r)
	}
	defer func() {
		root(t, "down", "--kill", "t-ostrip")
		os.Remove("/etc/vpncell/profiles.d/t-ostrip.toml")
		os.RemoveAll("/etc/vpncell/secrets/t-ostrip")
		root(t, "reload")
		// t-ostrip reuses the ovpn1 client certificate; restart t-ovpn1.
		ensureDown(t, "t-ovpn1")
		ensureUp(t, "t-ovpn1")
	}()
	for _, k := range []string{"user", "group", "persist-tun", "resolv-retry", "setenv", "verb 9"} {
		if !strings.Contains(r.stdout, k) {
			t.Errorf("report does not list stripped %s:\n%s", k, r.stdout)
		}
	}
	stored, _ := os.ReadFile("/etc/vpncell/secrets/t-ostrip/client.ovpn")
	if strings.Contains(string(stored), "BEGIN") || strings.Contains(string(stored), "user nobody") {
		t.Errorf("stored config keeps inline keys or stripped directives:\n%s", stored)
	}
	ensureDown(t, "t-ovpn1")
	ensureUp(t, "t-ostrip")
	waitFor(t, 40*time.Second, "t-ostrip connected", func() bool {
		return inProfile(t, userAllowed, "t-ostrip", "curl", "-s", "-m", "3", "http://10.99.0.10/").code == 0
	})
	if _, err := os.Stat(canary); err == nil {
		t.Fatalf("a script from an imported config ran")
	}
}
