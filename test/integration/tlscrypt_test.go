//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Issue #13: the test VM's server uses tls-crypt, so a client config
// downloaded from openvpn-ui works as it is.
func TestVMOpenVPNConfigAsDownloaded(t *testing.T) {
	if !useVM {
		t.Skip("VPNCELL_TEST_VM=0")
	}
	b, err := os.ReadFile(filepath.Join(vmConfigs, "vm-ovpn.ovpn"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "<tls-crypt>") || strings.Contains(string(b), "<tls-auth>") || strings.Contains(string(b), "key-direction") {
		t.Fatalf("vm-ovpn.ovpn is not the unmodified openvpn-ui download (run test/scripts/vm-fetch-configs.sh)")
	}
	ensureUp(t, "vm-ovpn")
	waitFor(t, 30*time.Second, "vm-ovpn up", func() bool { return statusOf(t, "vm-ovpn").State == "up" })
	r := inProfile(t, userAllowed, "vm-ovpn", "curl", "-sS", "-m", "15", "http://web.vpn-lab.test/")
	if r.code != 0 || !strings.Contains(r.stdout, "OpenVPN") {
		t.Fatalf("web.vpn-lab.test through vm-ovpn: %v", r)
	}
}

// `vpncell import --tls-auth` turns a <tls-crypt> key into tls-auth with
// key-direction 1 (for servers that use tls-auth), only when asked.
func TestImportTLSAuthOption(t *testing.T) {
	src := filepath.Join(vmConfigs, "vm-ovpn.ovpn")
	if !useVM {
		src = ""
	}
	if src == "" {
		t.Skip("VPNCELL_TEST_VM=0")
	}
	const p = "vm-tlsauth"
	defer func() {
		os.Remove("/etc/vpncell/profiles.d/" + p + ".toml")
		os.RemoveAll("/etc/vpncell/secrets/" + p)
		root(t, "reload")
	}()
	if r := root(t, "import", "--replace", "--tls-auth", "--user", userAllowed, p, src); r.code != 0 {
		t.Fatalf("import --tls-auth: %v", r)
	}
	b, err := os.ReadFile("/etc/vpncell/secrets/" + p + "/client.ovpn")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "\ntls-auth ") || !strings.Contains(string(b), "key-direction 1") || strings.Contains(string(b), "tls-crypt") {
		t.Fatalf("stored config:\n%s", b)
	}
	// Without the option the key stays tls-crypt.
	if r := root(t, "import", "--replace", "--user", userAllowed, p, src); r.code != 0 {
		t.Fatalf("import: %v", r)
	}
	b, _ = os.ReadFile("/etc/vpncell/secrets/" + p + "/client.ovpn")
	if !strings.Contains(string(b), "tls-crypt") || strings.Contains(string(b), "\ntls-auth ") {
		t.Fatalf("plain import changed the key mode:\n%s", b)
	}
	// A config that already uses tls-auth is refused.
	f := filepath.Join(t.TempDir(), "auth.ovpn")
	os.WriteFile(f, []byte(strings.ReplaceAll(strings.ReplaceAll(mustRead(t, src), "<tls-crypt>", "<tls-auth>"), "</tls-crypt>", "</tls-auth>")), 0o600)
	if r := root(t, "import", "--replace", "--tls-auth", "--user", userAllowed, p, f); r.code == 0 || !strings.Contains(r.stderr, "already uses tls-auth") {
		t.Fatalf("tls-auth config with --tls-auth: %v", r)
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
