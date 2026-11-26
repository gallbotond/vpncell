//go:build integration

package integration

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gallbotond/vpncell/internal/control"
)

// Issue #14: an OpenVPN profile that cannot connect says why, in
// `vpncell up`, `vpncell status` and `status --json`.

// randomStaticKey is an OpenVPN static key (tls-auth/tls-crypt) that no
// server knows.
func randomStaticKey() string {
	b := make([]byte, 256)
	rand.Read(b)
	h := hex.EncodeToString(b)
	var sb strings.Builder
	sb.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
	for i := 0; i < len(h); i += 32 {
		sb.WriteString(h[i:i+32] + "\n")
	}
	sb.WriteString("-----END OpenVPN Static key V1-----\n")
	return sb.String()
}

// waitReason polls `status --json` until the profile reports a reason.
func waitReason(t *testing.T, p string, d time.Duration) control.ProfileStatus {
	t.Helper()
	var st control.ProfileStatus
	waitFor(t, d, p+" reports a failure reason", func() bool {
		st = statusOf(t, p)
		return st.Reason != ""
	})
	return st
}

func checkNotConnected(t *testing.T, p string, st control.ProfileStatus) {
	t.Helper()
	if st.State == "up" || st.ConnectedAt != 0 || st.TryingSince == 0 {
		t.Fatalf("state/connected/trying since: %+v", st)
	}
	if st.Retries < 1 || st.ReasonAt == 0 || st.ReasonText == "" || st.Hint == "" {
		t.Fatalf("retries/time/text/hint missing: %+v", st)
	}
	if st.Log != "journalctl -u vpncell-openvpn@"+p+".service" {
		t.Fatalf("log hint: %q", st.Log)
	}
	r := root(t, "status", p)
	if r.code != 0 {
		t.Fatalf("status: %v", r)
	}
	for _, want := range []string{"trying since:", "hint:", "log:", st.ReasonText, "failed attempt"} {
		if !strings.Contains(r.stdout, want) {
			t.Fatalf("status lacks %q:\n%s", want, r.stdout)
		}
	}
	if strings.Contains(r.stdout, "connected:") {
		t.Fatalf("status says connected while %s:\n%s", st.State, r.stdout)
	}
}

func upNotConnected(t *testing.T, p string) {
	t.Helper()
	r := root(t, "up", p)
	if r.code != 3 {
		t.Fatalf("up %s: want exit 3 (not connected yet): %v", p, r)
	}
	if !strings.Contains(r.stdout, "is not connected yet") || !strings.Contains(r.stdout, "journalctl -u vpncell-openvpn@"+p) {
		t.Fatalf("up output: %v", r)
	}
}

// Wrong tls-auth/tls-crypt key against the test VM: the server drops every
// packet, so the client never gets a reply.
func TestOpenVPNReasonWrongKey(t *testing.T) {
	if !useVM {
		t.Skip("VPNCELL_TEST_VM=0")
	}
	b, err := os.ReadFile(filepath.Join(vmConfigs, "vm-ovpn.ovpn"))
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?s)(<(tls-auth|tls-crypt)>\n).*?(</(tls-auth|tls-crypt)>)`)
	if !re.Match(b) {
		t.Fatalf("vm-ovpn.ovpn has no inline tls-auth/tls-crypt block")
	}
	bad := re.ReplaceAllString(string(b), "${1}"+strings.ReplaceAll(randomStaticKey(), "$", "$$")+"${3}")
	f := filepath.Join(t.TempDir(), "vm-badkey.ovpn")
	if err := os.WriteFile(f, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	const p = "vm-badkey"
	if err := importProfile(p, f); err != nil {
		t.Fatal(err)
	}
	defer func() {
		root(t, "down", "--kill", p)
		os.Remove("/etc/vpncell/profiles.d/" + p + ".toml")
		os.RemoveAll("/etc/vpncell/secrets/" + p)
		root(t, "reload")
	}()
	start := time.Now()
	upNotConnected(t, p)
	st := waitReason(t, p, 100*time.Second)
	t.Logf("reason after %v: %s (%s); hint: %s", time.Since(start).Round(time.Second), st.Reason, st.ReasonText, st.Hint)
	if st.Reason != "no-reply" || !strings.Contains(st.Hint, "tls-crypt") {
		t.Fatalf("want reason no-reply: %+v", st)
	}
	checkNotConnected(t, p, st)
}

// A client certificate that the server refuses (revoked in the lab
// server's CRL): the server's certificate is verified, then nothing.
func TestOpenVPNReasonRevokedCert(t *testing.T) {
	srv := theLab.Servers["ovpn1"]
	b, err := os.ReadFile(srv.RevokedClientConfig)
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "revoked.ovpn")
	// A short handshake window keeps the test fast (default 60 s).
	if err := os.WriteFile(f, append(b, []byte("hand-window 15\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	const p = "t-revoked"
	if err := importProfile(p, f); err != nil {
		t.Fatal(err)
	}
	defer func() {
		root(t, "down", "--kill", p)
		os.Remove("/etc/vpncell/profiles.d/" + p + ".toml")
		os.RemoveAll("/etc/vpncell/secrets/" + p)
		root(t, "reload")
	}()
	upNotConnected(t, p)
	st := waitReason(t, p, 60*time.Second)
	t.Logf("reason: %s (%s); hint: %s", st.Reason, st.ReasonText, st.Hint)
	if st.Reason != "stalled-after-server-cert" || !strings.Contains(st.Hint, "revoked") {
		t.Fatalf("want reason stalled-after-server-cert: %+v", st)
	}
	checkNotConnected(t, p, st)
}
