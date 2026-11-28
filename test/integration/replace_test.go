//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gallbotond/vpncell/internal/profile"
)

// dirSnapshot maps file names to contents.
func dirSnapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, e := range es {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		m[e.Name()] = string(b)
	}
	return m
}

func sameSnapshot(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// Issue #16: import --replace keeps the profile's settings, leaves exactly
// the new config's files in the secrets folder, and a failed replace leaves
// the old profile working and unchanged.
func TestImportReplace(t *testing.T) {
	const p = "t-repl"
	prof := "/etc/vpncell/profiles.d/" + p + ".toml"
	secrets := "/etc/vpncell/secrets/" + p
	defer func() {
		run("", "chattr", "-i", prof)
		root(t, "down", "--kill", p)
		os.Remove(prof)
		os.RemoveAll(secrets)
		root(t, "reload")
	}()
	base := theLab.Servers["ovpn1"].ClientConfig
	// A variant with a tls-auth key (never connected; only its files matter).
	dir := t.TempDir()
	key := filepath.Join(dir, "ta.key")
	if out, err := run("", "openvpn", "--genkey", "secret", key); err != nil {
		t.Fatalf("openvpn --genkey: %v %s", err, out)
	}
	tlsAuth := filepath.Join(dir, "tlsauth.ovpn")
	os.WriteFile(tlsAuth, []byte(mustRead(t, base)+"key-direction 1\n<tls-auth>\n"+mustRead(t, key)+"</tls-auth>\n"), 0o600)

	if r := root(t, "import", "--replace", "--user", userAllowed, p, tlsAuth); r.code != 0 {
		t.Fatalf("first import: %v", r)
	}
	if _, err := os.Stat(filepath.Join(secrets, "tls-auth.pem")); err != nil {
		t.Fatalf("tls-auth.pem not stored: %v", err)
	}
	// Settings an admin would set by hand.
	text := strings.Replace(mustRead(t, prof), `autostart = "on-use"`, `autostart = "manual"`, 1)
	text = strings.Replace(text, "servers = []", `servers = ["10.99.0.53"]`, 1)
	text = strings.Replace(text, "search  = []", `search  = ["lab.test"]`, 1)
	text = strings.Replace(text, "users  = [\""+userAllowed+"\"]", "users  = [\""+userAllowed+"\", \"botond\"]", 1)
	text = strings.Replace(text, "groups = []", `groups = ["vpncell"]`, 1)
	text += "\n[status]\nexit_ip_url = \"http://10.99.0.10/\"\n"
	if err := os.WriteFile(prof, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := root(t, "reload"); r.code != 0 {
		t.Fatalf("reload: %v", r)
	}

	// Replace without flags: the settings stay, tls-auth.pem goes.
	r := root(t, "import", "--replace", p, base)
	if r.code != 0 {
		t.Fatalf("replace: %v", r)
	}
	for _, want := range []string{
		`kept from the old profile: autostart = "manual", [access], [dns], [status]`,
		"removed old files the new config does not use: tls-auth.pem",
		"allowed users: " + userAllowed + ",botond; groups: vpncell",
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("output lacks %q:\n%s", want, r.stdout)
		}
	}
	got, err := profile.Parse(p, []byte(mustRead(t, prof)))
	if err != nil {
		t.Fatal(err)
	}
	if got.Autostart != "manual" || !slices.Equal(got.Access.Users, []string{userAllowed, "botond"}) ||
		!slices.Equal(got.Access.Groups, []string{"vpncell"}) || !slices.Equal(got.DNS.Servers, []string{"10.99.0.53"}) ||
		!slices.Equal(got.DNS.Search, []string{"lab.test"}) || got.Status.ExitIPURL != "http://10.99.0.10/" {
		t.Fatalf("settings not kept:\n%s", mustRead(t, prof))
	}
	files := dirSnapshot(t, secrets)
	if _, ok := files["tls-auth.pem"]; ok {
		t.Errorf("tls-auth.pem left behind: %v", files)
	}
	for _, f := range []string{"client.ovpn", "ca.pem", "cert.pem", "key.pem"} {
		if _, ok := files[f]; !ok {
			t.Errorf("%s missing after replace", f)
		}
	}
	// A flag replaces the setting.
	if r := root(t, "import", "--replace", "--autostart", "on-use", p, base); r.code != 0 || strings.Contains(r.stdout, "autostart =") {
		t.Fatalf("replace --autostart: %v", r)
	}
	if !strings.Contains(mustRead(t, prof), `autostart = "on-use"`) {
		t.Fatalf("--autostart ignored:\n%s", mustRead(t, prof))
	}

	// The profile file cannot be written: the replace fails and nothing
	// changes.
	files = dirSnapshot(t, secrets)
	before := mustRead(t, prof)
	if out, err := run("", "chattr", "+i", prof); err != nil {
		t.Fatalf("chattr: %v %s", err, out)
	}
	if r := root(t, "import", "--replace", p, tlsAuth); r.code == 0 {
		t.Fatalf("replace onto an immutable profile file succeeded: %v", r)
	}
	run("", "chattr", "-i", prof)
	if mustRead(t, prof) != before {
		t.Errorf("profile file changed by a failed replace")
	}
	if !sameSnapshot(files, dirSnapshot(t, secrets)) {
		t.Errorf("secrets changed by a failed replace: %v", dirSnapshot(t, secrets))
	}
	for _, g := range []string{"/etc/vpncell/secrets/." + p + ".*", "/etc/vpncell/profiles.d/.tmp-*"} {
		if m, _ := filepath.Glob(g); len(m) > 0 {
			t.Errorf("left over: %v", m)
		}
	}
	// The old profile still connects.
	ensureUp(t, p)
	waitFor(t, 30*time.Second, p+" up", func() bool { return statusOf(t, p).State == "up" })
	if r := inProfile(t, userAllowed, p, "curl", "-sS", "-m", "10", "http://10.99.0.10/"); r.code != 0 || !strings.Contains(r.stdout, "lab-server ovpn1<") {
		t.Fatalf("old profile after a failed replace: %v", r)
	}
}
