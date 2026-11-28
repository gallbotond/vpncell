package nmimport

import (
	"bufio"
	"context"
	"crypto/rand"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gallbotond/vpncell/internal/importer"
	"github.com/godbus/dbus/v5"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const nmCerts = "/home/u/.local/share/networkmanagement/certificates/nm-openvpn/"

// A vpn.data as the NetworkManager OpenVPN plugin writes it (Ubuntu), with
// made-up names and paths.
var nmData = map[string]string{
	"auth":                     "SHA256",
	"ca":                       nmCerts + "work-ca.pem",
	"cert":                     nmCerts + "work-cert.pem",
	"cert-pass-flags":          "0",
	"challenge-response-flags": "2",
	"cipher":                   "AES-256-GCM",
	"connection-type":          "tls",
	"data-ciphers":             "AES-256-GCM:AES-128-GCM",
	"dev":                      "tun",
	"dev-type":                 "tun",
	"key":                      nmCerts + "work-key.pem",
	"ping":                     "10",
	"ping-restart":             "120",
	"remote":                   "vpn.example.com:1194:udp",
	"remote-cert-tls":          "server",
	"tls-crypt":                nmCerts + "work-tls-crypt.pem",
	"tls-version-min":          "1.2",
	"verify-x509-name":         "name:server_work",
}

// The same connection as a hand-written client config.
const handWritten = `client
dev tun
proto udp
remote vpn.example.com 1194
nobind
remote-cert-tls server
verify-x509-name server_work name
tls-version-min 1.2
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM
auth SHA256
ping 10
ping-restart 120
ca ca.pem
cert cert.pem
key key.pem
tls-crypt tls-crypt.pem
`

func fakeFiles(paths []string) map[string]string {
	m := map[string]string{}
	for _, p := range paths {
		m[p] = "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"
	}
	return m
}

// sanitized returns the importer's stored config lines, sorted, without
// comments; remote and proto are folded into "remote host port proto".
func sanitized(t *testing.T, text string, files map[string]string) []string {
	t.Helper()
	cfg, _, err := importer.ParseOpenVPN(text, files, "")
	if err != nil {
		t.Fatalf("import: %v\n%s", err, text)
	}
	var out []string
	proto := "udp"
	for _, l := range strings.Split(cfg.Render("/etc/vpncell/secrets/w"), "\n") {
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if f := strings.Fields(l); f[0] == "proto" {
			proto = f[1]
			continue
		}
		out = append(out, l)
	}
	for i, l := range out {
		if f := strings.Fields(l); f[0] == "remote" && len(f) == 3 {
			out[i] = l + " " + proto
		}
	}
	sort.Strings(out)
	return out
}

// Golden test (issue #18): the config generated from vpn.data imports to the
// same stored config as the hand-written .ovpn, including `auth SHA256`,
// which nmcli's export drops.
func TestOpenVPNConfigGolden(t *testing.T) {
	o, err := OpenVPNConfig(nmData)
	if err != nil {
		t.Fatal(err)
	}
	if o.NeedsPassword {
		t.Error("tls connection needs a password")
	}
	want := map[string]string{"ca.pem": nmCerts + "work-ca.pem", "cert.pem": nmCerts + "work-cert.pem",
		"key.pem": nmCerts + "work-key.pem", "tls-crypt.pem": nmCerts + "work-tls-crypt.pem"}
	if len(o.Files) != len(want) {
		t.Errorf("files = %q", o.Files)
	}
	for k, p := range want {
		if o.Files[k] != p {
			t.Errorf("files[%s] = %q, want %q", k, o.Files[k], p)
		}
	}
	files := fakeFiles([]string{"ca.pem", "cert.pem", "key.pem", "tls-crypt.pem"})
	gen, hand := sanitized(t, o.Text, files), sanitized(t, handWritten, files)
	if !slices.Equal(gen, hand) {
		t.Fatalf("generated config differs from the hand-written one:\ngenerated:\n%s\nhand-written:\n%s\nsource:\n%s",
			strings.Join(gen, "\n"), strings.Join(hand, "\n"), o.Text)
	}
	if !slices.Contains(gen, "auth SHA256") {
		t.Error("auth dropped")
	}
}

func TestOpenVPNConfigVariants(t *testing.T) {
	with := func(kv ...string) map[string]string {
		m := map[string]string{"connection-type": "tls", "remote": "vpn.example.com", "ca": "/c/ca.pem", "cert": "/c/cert.pem", "key": "/c/key.pem"}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	for _, c := range []struct {
		name string
		data map[string]string
		want []string // lines that must be present
	}{
		{"defaults", with(), []string{"remote vpn.example.com 1194 udp"}},
		{"port and tcp", with("port", "443", "proto-tcp", "yes"), []string{"remote vpn.example.com 443 tcp-client"}},
		{"several remotes", with("remote", "a.example.com:1195:tcp, [2001:db8::1]:1194, b.example.com"), []string{
			"remote a.example.com 1195 tcp-client", "remote 2001:db8::1 1194 udp", "remote b.example.com 1194 udp"}},
		{"tls-auth", with("ta", "/c/ta.key", "ta-dir", "1"), []string{"tls-auth tls-auth.pem 1"}},
		{"password-tls", with("connection-type", "password-tls", "username", "alice"), []string{"auth-user-pass"}},
		{"compression", with("comp-lzo", "adaptive", "compress", "lz4-v2"), []string{"comp-lzo adaptive", "compress lz4-v2"}},
		{"verify subject", with("verify-x509-name", "subject:C=DE, CN=vpn"), []string{`verify-x509-name "C=DE, CN=vpn" subject`}},
		{"flags", with("float", "yes", "remote-random", "no", "mssfix", "1400"), []string{"float", "mssfix 1400"}},
	} {
		o, err := OpenVPNConfig(c.data)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		lines := strings.Split(o.Text, "\n")
		for _, w := range c.want {
			if !slices.Contains(lines, w) {
				t.Errorf("%s: missing %q in\n%s", c.name, w, o.Text)
			}
		}
		if c.name == "flags" && slices.Contains(lines, "remote-random") {
			t.Errorf("remote-random = no produced the directive")
		}
		if c.name == "password-tls" && !o.NeedsPassword {
			t.Errorf("password-tls: NeedsPassword not set")
		}
	}
	// password mode: no client certificate even if NM still has one.
	o, err := OpenVPNConfig(with("connection-type", "password", "username", "alice"))
	if err != nil || o.Files["cert.pem"] != "" || o.Files["key.pem"] != "" || !o.NeedsPassword {
		t.Errorf("password mode: %v\n%s", err, o.Text)
	}
}

func TestOpenVPNConfigRefuses(t *testing.T) {
	base := func(kv ...string) map[string]string {
		m := map[string]string{"connection-type": "tls", "remote": "vpn.example.com", "ca": "/c/ca.pem"}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	for _, c := range []struct {
		data map[string]string
		want string
	}{
		{base("dev-type", "tap"), "tap"},
		{base("tap-dev", "yes"), "tap"},
		{base("proxy-type", "http", "proxy-server", "proxy.example.com"), "proxies"},
		{base("connection-type", "static-key", "static-key", "/c/static.key"), "static-key"},
		{base("connection-type", ""), "connection-type"},
		{base("remote", ""), "no remote"},
		{base("frobnicate", "yes"), "does not know how to import: frobnicate"},
		{base("crl-verify-dir", "/c/crl"), "directory"},
	} {
		if _, err := OpenVPNConfig(c.data); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: err = %v, want %q", c.data, err, c.want)
		}
	}
	// proxy-type none is the plugin's default and fine.
	if _, err := OpenVPNConfig(base("proxy-type", "none")); err != nil {
		t.Errorf("proxy-type none: %v", err)
	}
}

func TestFind(t *testing.T) {
	cs := []Connection{
		{ID: "work", UUID: "u1", Kind: "openvpn"},
		{ID: "dup", UUID: "u2", Kind: "openvpn"}, {ID: "dup", UUID: "u3", Kind: "wireguard"},
		{ID: "corp", UUID: "u4", Kind: "vpn: org.freedesktop.NetworkManager.vpnc"},
	}
	if c, err := Find(cs, "work"); err != nil || c.UUID != "u1" {
		t.Errorf("by name: %v %v", c, err)
	}
	if c, err := Find(cs, "u3"); err != nil || c.Kind != "wireguard" {
		t.Errorf("by UUID: %v %v", c, err)
	}
	for name, want := range map[string]string{"dup": "give the UUID", "corp": "OpenVPN and WireGuard only", "nope": "no NetworkManager VPN connection"} {
		if _, err := Find(cs, name); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// ---- a fake NetworkManager on a private bus ----

type fakeConn struct {
	settings Settings
	secrets  map[string]Settings
}

func (f fakeConn) GetSettings() (Settings, *dbus.Error) { return f.settings, nil }
func (f fakeConn) GetSecrets(setting string) (Settings, *dbus.Error) {
	if s, ok := f.secrets[setting]; ok {
		return s, nil
	}
	return nil, dbus.MakeFailedError(errNoSecrets)
}

var errNoSecrets = &noSecrets{}

type noSecrets struct{}

func (*noSecrets) Error() string { return "no secrets" }

type fakeSettings struct{ paths []dbus.ObjectPath }

func (f fakeSettings) ListConnections() ([]dbus.ObjectPath, *dbus.Error) { return f.paths, nil }

func privateBus(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("dbus-daemon"); err != nil {
		t.Fatalf("dbus-daemon is needed for this test (package dbus-daemon): %v", err)
	}
	cmd := exec.Command("dbus-daemon", "--session", "--nofork", "--print-address")
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	addr, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(addr)
}

func dial(t *testing.T, addr string) *dbus.Conn {
	t.Helper()
	c, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func v(x any) dbus.Variant { return dbus.MakeVariant(x) }

func TestReadFromFakeNM(t *testing.T) {
	addr := privateBus(t)
	srv := dial(t, addr)
	if r, err := srv.RequestName(nmDest, 0); err != nil || r != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("request name: %v %v", r, err)
	}
	priv, _ := wgtypes.GeneratePrivateKey()
	peer, _ := wgtypes.GeneratePrivateKey()
	psk, _ := wgtypes.GenerateKey()
	pub := peer.PublicKey().String()
	pw := rand.Text() // made up at runtime: no password-like literal in the repository
	conns := map[dbus.ObjectPath]fakeConn{
		settingsObj + "/1": {settings: Settings{
			"connection": {"id": v("work"), "uuid": v("u-work"), "type": v("vpn")},
			"vpn": {"service-type": v(openvpnSvc), "data": v(map[string]string{
				"connection-type": "password-tls", "remote": "vpn.example.com:1194:udp", "username": "alice",
				"ca": "/c/ca.pem", "cert": "/c/cert.pem", "key": "/c/key.pem", "password-flags": "0"})},
		}, secrets: map[string]Settings{"vpn": {"vpn": {"secrets": v(map[string]string{"password": pw})}}}},
		settingsObj + "/2": {settings: Settings{
			"connection": {"id": v("keyring"), "uuid": v("u-keyring"), "type": v("vpn")},
			"vpn": {"service-type": v(openvpnSvc), "data": v(map[string]string{
				"connection-type": "password", "remote": "vpn.example.com", "username": "bob", "ca": "/c/ca.pem", "password-flags": "1"})},
		}},
		settingsObj + "/3": {settings: Settings{
			"connection": {"id": v("lab-wg"), "uuid": v("u-wg"), "type": v("wireguard")},
			"wireguard": {"private-key-flags": v(uint32(0)), "mtu": v(uint32(1380)), "peers": v([]map[string]dbus.Variant{{
				"public-key": v(pub), "endpoint": v("[2001:db8::1]:51820"), "allowed-ips": v([]string{"0.0.0.0/0", "::/0"}),
				"persistent-keepalive": v(uint32(25))}})},
			"ipv4": {"method": v("manual"), "address-data": v([]map[string]dbus.Variant{{"address": v("10.8.0.2"), "prefix": v(uint32(24))}}),
				"dns": v([]uint32{0x0101a8c0}), "dns-search": v([]string{"lab.test"})},
			"ipv6": {"method": v("manual"), "address-data": v([]map[string]dbus.Variant{{"address": v("fd00::2"), "prefix": v(uint32(64))}})},
		}, secrets: map[string]Settings{"wireguard": {"wireguard": {"private-key": v(priv.String()), "peers": v([]map[string]dbus.Variant{{
			"public-key": v(pub), "preshared-key": v(psk.String())}})}}}},
		settingsObj + "/4": {settings: Settings{
			"connection": {"id": v("Wired"), "uuid": v("u-eth"), "type": v("802-3-ethernet")},
		}},
		settingsObj + "/5": {settings: Settings{
			"connection": {"id": v("corp"), "uuid": v("u-vpnc"), "type": v("vpn")},
			"vpn":        {"service-type": v("org.freedesktop.NetworkManager.vpnc")},
		}},
	}
	var paths []dbus.ObjectPath
	for p, c := range conns {
		paths = append(paths, p)
		if err := srv.Export(c, p, connIface); err != nil {
			t.Fatal(err)
		}
	}
	if err := srv.Export(fakeSettings{paths}, settingsObj, nmDest+".Settings"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cl := dial(t, addr)
	cs, err := List(ctx, cl)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range cs {
		names = append(names, c.ID+"="+c.Kind)
	}
	if want := []string{"corp=vpn: org.freedesktop.NetworkManager.vpnc", "keyring=openvpn", "lab-wg=wireguard", "work=openvpn"}; !slices.Equal(names, want) {
		t.Fatalf("List = %q, want %q", names, want)
	}

	c, _ := Find(cs, "work")
	r, err := Read(ctx, cl, c)
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != "openvpn" || r.NeedsAuth || r.Auth != "alice\n"+pw+"\n" || !strings.Contains(r.Config, "auth-user-pass") || r.Summary != "OpenVPN, password-tls, 3 files" {
		t.Errorf("work: %+v", r)
	}

	c, _ = Find(cs, "keyring")
	r, err = Read(ctx, cl, c)
	if err != nil {
		t.Fatal(err)
	}
	if !r.NeedsAuth || r.Auth != "" || !strings.Contains(r.AuthWhy, "password-flags 1") {
		t.Errorf("keyring: %+v", r)
	}

	c, _ = Find(cs, "lab-wg")
	r, err = Read(ctx, cl, c)
	if err != nil {
		t.Fatal(err)
	}
	want := "# Generated by vpncell from a NetworkManager connection.\n[Interface]\nPrivateKey = " + priv.String() +
		"\nAddress = 10.8.0.2/24, fd00::2/64\nDNS = 192.168.1.1, lab.test\nMTU = 1380\n\n[Peer]\nPublicKey = " + pub +
		"\nPresharedKey = " + psk.String() + "\nEndpoint = [2001:db8::1]:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n"
	if r.Kind != "wireguard" || r.Config != want {
		t.Errorf("WireGuard config:\n%s\nwant:\n%s", r.Config, want)
	}
	if _, _, err := importer.ParseWireGuard(r.Config); err != nil {
		t.Errorf("generated wg-quick config does not import: %v", err)
	}
}
