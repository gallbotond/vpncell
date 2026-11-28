//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// removeProfile deletes a test profile the way an admin would.
func removeProfile(t *testing.T, p string) {
	t.Helper()
	if !strings.HasPrefix(p, "t-") {
		t.Fatalf("not a test profile: %s", p)
	}
	root(t, "remove", "--kill", p)
	os.Remove("/etc/vpncell/profiles.d/" + p + ".toml")
	os.RemoveAll("/etc/vpncell/secrets/" + p)
	root(t, "reload")
}

func nmData(t *testing.T, name string) string {
	t.Helper()
	out, err := run("", "nmcli", "-g", "vpn.data,connection.autoconnect,GENERAL.STATE", "connection", "show", name)
	if err != nil {
		t.Fatalf("nmcli show %s: %v", name, err)
	}
	return out
}

// Issue #18: `import --from-nm` creates a profile from an (inactive)
// NetworkManager OpenVPN connection; the profile connects, and the
// connection is unchanged.
func TestImportFromNMOpenVPN(t *testing.T) {
	requireNM(t)
	const conn, p = "t-nmovpn", "t-fromnm"
	nmTestConnection(t, conn, theLab.Servers["ovpn1"].ClientConfig,
		"remote-cert-tls = server", "data-ciphers = AES-256-GCM:AES-128-GCM")
	defer removeProfile(t, p)
	before := nmData(t, conn)

	r := root(t, "import", "--from-nm")
	if r.code != 0 || !strings.Contains(r.stdout, conn) {
		t.Fatalf("list: %v", r)
	}
	r = root(t, "import", "--from-nm", "--user", userAllowed, conn, p)
	if r.code != 0 {
		t.Fatalf("import --from-nm: %v", r)
	}
	for _, want := range []string{
		`read NetworkManager connection "t-nmovpn" (OpenVPN, tls, 3 files)`,
		"profile t-fromnm imported to /etc/vpncell/profiles.d/t-fromnm.toml",
		"remote-cert-tls server",
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("output lacks %q:\n%s", want, r.stdout)
		}
	}
	for _, f := range []string{"ca.pem", "cert.pem", "key.pem", "client.ovpn"} {
		if _, err := os.Stat("/etc/vpncell/secrets/" + p + "/" + f); err != nil {
			t.Errorf("%s not stored: %v", f, err)
		}
	}
	if strings.Contains(mustRead(t, "/etc/vpncell/secrets/"+p+"/client.ovpn"), "/tmp/") {
		t.Errorf("stored config refers to the NetworkManager file paths")
	}
	// The lab server keeps one connection per certificate: t-ovpn1 uses
	// the same one.
	ensureDown(t, "t-ovpn1")
	ensureUp(t, p)
	waitFor(t, 30*time.Second, p+" up", func() bool { return statusOf(t, p).State == "up" })
	if r := inProfile(t, userAllowed, p, "curl", "-sS", "-m", "10", "http://10.99.0.10/"); r.code != 0 || !strings.Contains(r.stdout, "lab-server ovpn1<") {
		t.Fatalf("through %s: %v", p, r)
	}
	ensureDown(t, p)
	if after := nmData(t, conn); after != before {
		t.Errorf("NetworkManager connection changed:\nbefore %s\nafter  %s", before, after)
	}
	// Unsupported: tap.
	nmTestConnection(t, "t-nmtap", theLab.Servers["ovpn1"].ClientConfig, "dev-type = tap")
	if r := root(t, "import", "--from-nm", "t-nmtap", "t-fromnmtap"); r.code == 0 || !strings.Contains(r.stderr, "tap") {
		t.Errorf("tap connection: %v", r)
	}
	// A password that is not saved in the connection needs --auth-file.
	nmTestConnection(t, "t-nmpass", theLab.Servers["ovpn1"].ClientConfig,
		"connection-type = password-tls", "username = alice", "password-flags = 1")
	if r := root(t, "import", "--from-nm", "t-nmpass", "t-fromnmpass"); r.code == 0 || !strings.Contains(r.stderr, "--auth-file") {
		t.Errorf("password in a keyring: %v", r)
	}
	if _, err := os.Stat("/etc/vpncell/profiles.d/t-fromnmtap.toml"); err == nil {
		removeProfile(t, "t-fromnmtap")
		t.Error("failed import left a profile")
	}
}

func newUUID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// nmWireGuardConnection adds an inactive NetworkManager WireGuard connection
// (autoconnect off, never activated) from a wg-quick config over D-Bus and
// deletes it when the test ends. Its private key is never printed.
func nmWireGuardConnection(t *testing.T, name, wgConf string) {
	t.Helper()
	if !strings.HasPrefix(name, "t-") {
		t.Fatalf("NetworkManager test connections must be named t-…")
	}
	var priv, peerPub, endpoint string
	var addrs4, addrs6 []map[string]dbus.Variant
	var allowed []string
	for _, l := range strings.Split(mustRead(t, wgConf), "\n") {
		k, val, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		k, val = strings.TrimSpace(k), strings.TrimSpace(val)
		switch k {
		case "PrivateKey":
			priv = val
		case "PublicKey":
			peerPub = val
		case "Endpoint":
			endpoint = val
		case "AllowedIPs":
			for _, a := range strings.Split(val, ",") {
				allowed = append(allowed, strings.TrimSpace(a))
			}
		case "Address":
			for _, a := range strings.Split(val, ",") {
				pf := netip.MustParsePrefix(strings.TrimSpace(a))
				m := map[string]dbus.Variant{"address": dbus.MakeVariant(pf.Addr().String()), "prefix": dbus.MakeVariant(uint32(pf.Bits()))}
				if pf.Addr().Is4() {
					addrs4 = append(addrs4, m)
				} else {
					addrs6 = append(addrs6, m)
				}
			}
		}
	}
	settings := map[string]map[string]dbus.Variant{
		"connection": {
			"id": dbus.MakeVariant(name), "uuid": dbus.MakeVariant(newUUID()), "type": dbus.MakeVariant("wireguard"),
			"interface-name": dbus.MakeVariant(name), "autoconnect": dbus.MakeVariant(false),
		},
		"wireguard": {
			"private-key": dbus.MakeVariant(priv),
			"peers": dbus.MakeVariant([]map[string]dbus.Variant{{
				"public-key": dbus.MakeVariant(peerPub), "endpoint": dbus.MakeVariant(endpoint),
				"allowed-ips": dbus.MakeVariant(allowed),
			}}),
		},
		"ipv4": {"method": dbus.MakeVariant("manual"), "address-data": dbus.MakeVariant(addrs4), "dns-data": dbus.MakeVariant([]string{"10.99.0.53"}), "dns-search": dbus.MakeVariant([]string{"lab.test"})},
		"ipv6": {"method": dbus.MakeVariant("manual"), "address-data": dbus.MakeVariant(addrs6)},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	run("", "nmcli", "connection", "delete", name)
	var path dbus.ObjectPath
	if err := c.Object("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager/Settings").
		CallWithContext(ctx, "org.freedesktop.NetworkManager.Settings.AddConnection", 0, settings).Store(&path); err != nil {
		t.Fatalf("AddConnection: %v", err)
	}
	t.Cleanup(func() {
		if out, err := run("", "nmcli", "connection", "delete", name); err != nil {
			t.Errorf("nmcli connection delete %s: %v %s", name, err, out)
		}
	})
	if out, _ := run("", "nmcli", "-g", "GENERAL.STATE", "connection", "show", name); strings.TrimSpace(out) != "" {
		t.Fatalf("%s is active", name)
	}
}

// Issue #18, WireGuard: the private key comes from the connection (stored
// in it, flags 0); the profile connects.
func TestImportFromNMWireGuard(t *testing.T) {
	requireNM(t)
	const conn, p = "t-nmwg", "t-fromnmwg"
	nmWireGuardConnection(t, conn, theLab.Servers["wg1"].ClientConfig)
	defer removeProfile(t, p)
	r := root(t, "import", "--from-nm", "--user", userAllowed, conn, p)
	if r.code != 0 || !strings.Contains(r.stdout, `read NetworkManager connection "t-nmwg" (WireGuard, 1 peer(s))`) {
		t.Fatalf("import --from-nm: code %d\n%s", r.code, r.stderr)
	}
	prof := mustRead(t, "/etc/vpncell/profiles.d/"+p+".toml")
	if !strings.Contains(prof, `servers = ["10.99.0.53"]`) || !strings.Contains(prof, `search  = ["lab.test"]`) {
		t.Errorf("DNS not taken over:\n%s", prof)
	}
	// Same key as t-wg1: two peers with one key would flip.
	ensureDown(t, "t-wg1")
	ensureUp(t, p)
	if r := inProfile(t, userAllowed, p, "curl", "-sS", "-m", "10", "http://10.99.0.10/"); r.code != 0 || !strings.Contains(r.stdout, "lab-server wg1<") {
		t.Fatalf("through %s: code %d %s", p, r.code, r.stderr)
	}
	ensureDown(t, p)
}
