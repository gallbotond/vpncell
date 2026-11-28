package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gallbotond/vpncell/internal/control"
	"github.com/gallbotond/vpncell/internal/profile"
)

func mustParse(t *testing.T, text string) *profile.Profile {
	t.Helper()
	p, err := profile.Parse("t-x", []byte(text))
	if err != nil {
		t.Fatalf("%v\n%s", err, text)
	}
	return p
}

var wgImport = imported{
	backend: profile.BackendWireGuard,
	section: "[wireguard]\nconfig = \"/etc/vpncell/secrets/t-x/wg.conf\"\n",
	dns:     dnsSettings{Servers: []string{"10.99.0.53"}, Search: []string{"lab.test"}},
}

// issue #16: --replace keeps the old profile's settings.
func TestProfileTextKeepsSettings(t *testing.T) {
	old := mustParse(t, `autostart = "boot"
backend = "wireguard"
[wireguard]
config = "/etc/vpncell/secrets/t-x/wg.conf"
[dns]
servers = ["10.1.1.1"]
search = ["corp.example"]
[access]
users = ["alice", "bob"]
groups = ["vpn"]
[routing]
routes = ["10.0.0.0/8"]
[socks]
port = 41234
[status]
exit_ip_url = "https://ifconfig.me/ip"
[security]
nftables = false
`)
	text, users, groups, kept, warnings := profileText(&control.ImportRequest{Name: "t-x", DefaultUser: "carol"}, wgImport, old)
	p := mustParse(t, text)
	if p.Autostart != "boot" || !slices.Equal(p.Access.Users, []string{"alice", "bob"}) || !slices.Equal(p.Access.Groups, []string{"vpn"}) ||
		!slices.Equal(p.DNS.Servers, []string{"10.1.1.1"}) || !slices.Equal(p.DNS.Search, []string{"corp.example"}) ||
		!slices.Equal(p.Routing.Routes, []string{"10.0.0.0/8"}) || p.Socks.Port != 41234 ||
		p.Status.ExitIPURL != "https://ifconfig.me/ip" || p.NftablesEnabled() {
		t.Fatalf("settings not kept:\n%s", text)
	}
	if !slices.Equal(users, []string{"alice", "bob"}) || !slices.Equal(groups, []string{"vpn"}) {
		t.Errorf("reported access: %v %v", users, groups)
	}
	want := []string{`autostart = "boot"`, "[access]", "[dns]", "[routing]", "[socks]", "[status]", "[security]"}
	if !slices.Equal(kept, want) {
		t.Errorf("kept = %q, want %q", kept, want)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "kept [dns]") || !strings.Contains(warnings[0], "10.99.0.53") {
		t.Errorf("warnings = %q", warnings)
	}
}

func TestProfileTextFlagsWin(t *testing.T) {
	old := mustParse(t, "autostart = \"boot\"\nbackend = \"wireguard\"\n[wireguard]\nconfig = \"/x\"\n[dns]\nservers = [\"10.99.0.53\"]\nsearch = [\"lab.test\"]\n[access]\nusers = [\"alice\"]\n")
	req := &control.ImportRequest{Name: "t-x", Autostart: "manual", Groups: []string{"ops"}, DefaultUser: "carol"}
	text, users, groups, kept, _ := profileText(req, wgImport, old)
	p := mustParse(t, text)
	if p.Autostart != "manual" || len(p.Access.Users) != 0 || !slices.Equal(p.Access.Groups, []string{"ops"}) {
		t.Fatalf("flags ignored:\n%s", text)
	}
	if len(users) != 0 || !slices.Equal(groups, []string{"ops"}) || slices.Contains(kept, "[access]") {
		t.Errorf("users %v groups %v kept %v", users, groups, kept)
	}
	// Same DNS as the new config: nothing to say about [dns].
	if slices.Contains(kept, "[dns]") {
		t.Errorf("kept = %v", kept)
	}
}

func TestProfileTextNew(t *testing.T) {
	text, users, _, kept, warnings := profileText(&control.ImportRequest{Name: "t-x", DefaultUser: "carol"}, wgImport, nil)
	p := mustParse(t, text)
	if p.Autostart != "on-use" || !slices.Equal(p.Access.Users, []string{"carol"}) || !slices.Equal(p.DNS.Servers, []string{"10.99.0.53"}) {
		t.Fatalf("new profile:\n%s", text)
	}
	if !slices.Equal(users, []string{"carol"}) || len(kept) != 0 || len(warnings) != 0 {
		t.Errorf("users %v kept %v warnings %v", users, kept, warnings)
	}
}

// A backend change takes [dns] from the new config and says so.
func TestProfileTextBackendChange(t *testing.T) {
	old := mustParse(t, "backend = \"wireguard\"\n[wireguard]\nconfig = \"/x\"\n[dns]\nservers = [\"10.1.1.1\"]\n[access]\nusers = [\"alice\"]\n")
	pushed := true
	ovpn := imported{backend: profile.BackendOpenVPN, section: "[openvpn]\nconfig = \"/y\"\n", dns: dnsSettings{UsePushed: &pushed}}
	text, _, _, kept, warnings := profileText(&control.ImportRequest{Name: "t-x"}, ovpn, old)
	p := mustParse(t, text)
	if p.Backend != "openvpn" || len(p.DNS.Servers) != 0 || !p.UsePushedDNS() || !slices.Equal(p.Access.Users, []string{"alice"}) {
		t.Fatalf("backend change:\n%s", text)
	}
	if slices.Contains(kept, "[dns]") || len(warnings) != 1 || !strings.Contains(warnings[0], "backend changed") {
		t.Errorf("kept %v warnings %q", kept, warnings)
	}
}

func writeFiles(t *testing.T, dir string, names ...string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(dir+"/"+n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func listDir(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var n []string
	for _, e := range es {
		n = append(n, e.Name())
	}
	return n
}

// The secrets folder ends up with exactly the new files; a failed commit
// puts the old folder back untouched.
func TestSwapSecrets(t *testing.T) {
	base := t.TempDir()
	dir, stage, prev := filepath.Join(base, "p"), filepath.Join(base, ".p.new"), filepath.Join(base, ".p.old")
	writeFiles(t, dir, "client.ovpn", "ca.pem", "tls-auth.pem", "auth.txt")
	writeFiles(t, stage, "client.ovpn", "ca.pem", "tls-crypt.pem")

	removed, err := swapSecrets(dir, stage, prev, func() error { return errors.New("profile write failed") })
	if err == nil {
		t.Fatal("commit error not returned")
	}
	if got := listDir(t, dir); !slices.Equal(got, []string{"auth.txt", "ca.pem", "client.ovpn", "tls-auth.pem"}) {
		t.Fatalf("old folder after a failed commit: %v", got)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "ca.pem")); string(b) != dir+"/ca.pem" {
		t.Fatalf("old file changed: %q", b)
	}
	if _, err := os.Stat(prev); !os.IsNotExist(err) {
		t.Fatalf("backup folder left: %v", err)
	}

	writeFiles(t, stage, "client.ovpn", "ca.pem", "tls-crypt.pem")
	removed, err = swapSecrets(dir, stage, prev, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if got := listDir(t, dir); !slices.Equal(got, []string{"ca.pem", "client.ovpn", "tls-crypt.pem"}) {
		t.Fatalf("new folder: %v", got)
	}
	if !slices.Equal(removed, []string{"auth.txt", "tls-auth.pem"}) {
		t.Errorf("removed = %v", removed)
	}
	for _, d := range []string{stage, prev} {
		if _, err := os.Stat(d); !os.IsNotExist(err) {
			t.Errorf("%s left: %v", d, err)
		}
	}
	// First import: no old folder.
	dir2 := filepath.Join(base, "q")
	writeFiles(t, stage, "wg.conf")
	if removed, err := swapSecrets(dir2, stage, prev, func() error { return nil }); err != nil || len(removed) != 0 {
		t.Fatalf("first import: %v %v", removed, err)
	}
}
