package conflict

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/prop"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// testCert makes a self-signed certificate (generated at runtime; no key
// material in the repository) and returns it as PEM.
func testCert(t *testing.T, cn string) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func files(m map[string][]byte) func(string) ([]byte, error) {
	return func(p string) ([]byte, error) {
		if b, ok := m[p]; ok {
			return b, nil
		}
		return nil, os.ErrNotExist
	}
}

func TestOpenVPNIdentity(t *testing.T) {
	c := testCert(t, "client1")
	read := files(map[string][]byte{"/etc/vpncell/secrets/w/cert.pem": c})
	for name, cfg := range map[string]string{
		"path":   "client\nca \"/etc/vpncell/secrets/w/ca.pem\"\ncert \"/etc/vpncell/secrets/w/cert.pem\"\n",
		"bare":   "cert /etc/vpncell/secrets/w/cert.pem\n",
		"inline": "client\n<cert>\n" + string(c) + "</cert>\n",
	} {
		id := OpenVPNIdentity([]byte(cfg), read)
		if id.Cert == nil || id.Cert.Subject.CommonName != "client1" {
			t.Errorf("%s: no certificate", name)
		}
	}
	if id := OpenVPNIdentity([]byte("pkcs12 x.p12\n"), read); id.Cert != nil {
		t.Errorf("pkcs12 read as a certificate")
	}
}

func TestWireGuardIdentity(t *testing.T) {
	k, _ := wgtypes.GeneratePrivateKey()
	cfg := "[Interface]\nPrivateKey = " + k.String() + "\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = " + k.PublicKey().String() + "\n"
	id := WireGuardIdentity([]byte(cfg))
	if id.WGPub == nil || *id.WGPub != k.PublicKey() {
		t.Fatalf("public key not derived")
	}
	if id := WireGuardIdentity([]byte("[Peer]\nPrivateKey = " + k.String() + "\n")); id.WGPub != nil {
		t.Errorf("key outside [Interface] used")
	}
}

func TestCheck(t *testing.T) {
	mine, other, sameCN := testCert(t, "client1"), testCert(t, "client2"), testCert(t, "client1")
	read := files(map[string][]byte{"/home/u/mine.pem": mine, "/home/u/other.pem": other, "/home/u/samecn.pem": sameCN})
	id := Identity{Cert: FirstCert(mine)}
	nm := []NMConnection{
		{ID: "work", Kind: "openvpn", CertPath: "/home/u/mine.pem"},
		{ID: "home", Kind: "openvpn", CertPath: "/home/u/other.pem"},
		{ID: "old work", Kind: "openvpn", CertPath: "/home/u/samecn.pem"},
		{ID: "gone", Kind: "openvpn", CertPath: "/home/u/missing.pem"},
		{ID: "vpnc", Kind: "org.freedesktop.NetworkManager.vpnc", CertPath: "/home/u/mine.pem"},
	}
	w := Check("work", id, nm, nil, read)
	if len(w) != 2 {
		t.Fatalf("warnings: %q", w)
	}
	if !strings.Contains(w[0], `NetworkManager connection "work" (active) uses the same client certificate as profile work`) ||
		!strings.HasSuffix(w[0], "nmcli connection down work") {
		t.Errorf("certificate warning: %q", w[0])
	}
	if !strings.Contains(w[1], `"old work"`) || !strings.Contains(w[1], "same name (CN)") || !strings.HasSuffix(w[1], "nmcli connection down 'old work'") {
		t.Errorf("CN warning: %q", w[1])
	}
	if w := Check("work", Identity{Cert: FirstCert(other)}, nm[:1], nil, read); len(w) != 0 {
		t.Errorf("different certificate warned: %q", w)
	}

	k1, _ := wgtypes.GeneratePrivateKey()
	k2, _ := wgtypes.GeneratePrivateKey()
	pub := k1.PublicKey()
	wg := []WGDevice{{Name: "wg0", Pub: k1.PublicKey()}, {Name: "wg1", Pub: k2.PublicKey()}}
	w = Check("lab", Identity{WGPub: &pub}, []NMConnection{{ID: "lab-wg", Kind: "wireguard", Interfaces: []string{"wg0"}}}, wg, read)
	if len(w) != 1 || !strings.Contains(w[0], `NetworkManager connection "lab-wg" (active, interface wg0) uses the same WireGuard key as profile lab`) {
		t.Errorf("WireGuard warning: %q", w)
	}
	w = Check("lab", Identity{WGPub: &pub}, nil, wg, read)
	if len(w) != 1 || !strings.Contains(w[0], "WireGuard interface wg0 on the host uses the same key as profile lab") {
		t.Errorf("WireGuard (no NM) warning: %q", w)
	}
	// A connection name with control characters is never printed raw.
	w = Check("work", id, []NMConnection{{ID: "x\x1b[2Jy", Kind: "openvpn", CertPath: "/home/u/mine.pem"}}, nil, read)
	if len(w) != 1 || strings.ContainsRune(w[0], '\x1b') {
		t.Errorf("control characters printed: %q", w)
	}
}

func TestReadRegular(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "c.pem")
	os.WriteFile(f, []byte("x"), 0o600)
	if b, err := ReadRegular(f); err != nil || string(b) != "x" {
		t.Fatalf("regular file: %q %v", b, err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := ReadRegular(fifo); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO read")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadRegular blocked on a FIFO")
	}
	if _, err := ReadRegular("/dev/zero"); err == nil {
		t.Fatal("device read")
	}
}

// fakeSettings is a NetworkManager settings connection.
type fakeSettings struct {
	s map[string]map[string]dbus.Variant
}

func (f fakeSettings) GetSettings() (map[string]map[string]dbus.Variant, *dbus.Error) {
	return f.s, nil
}

// privateBus starts a dbus-daemon for the test and returns its address.
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

func exportProps(t *testing.T, c *dbus.Conn, path dbus.ObjectPath, iface string, props map[string]any) {
	t.Helper()
	m := map[string]*prop.Prop{}
	for k, v := range props {
		m[k] = &prop.Prop{Value: v, Emit: prop.EmitFalse}
	}
	if _, err := prop.Export(c, path, prop.Map{iface: m}); err != nil {
		t.Fatal(err)
	}
}

// ActiveNM against a fake NetworkManager on a private bus: an active
// OpenVPN connection, an active WireGuard connection and an ethernet one.
func TestActiveNM(t *testing.T) {
	addr := privateBus(t)
	srv := dial(t, addr)
	if r, err := srv.RequestName(nmDest, 0); err != nil || r != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("request name: %v %v", r, err)
	}
	const ai = nmDest + ".Connection.Active"
	exportProps(t, srv, nmPath, nmDest, map[string]any{"ActiveConnections": []dbus.ObjectPath{
		nmPath + "/ActiveConnection/1", nmPath + "/ActiveConnection/2", nmPath + "/ActiveConnection/3"}})
	exportProps(t, srv, nmPath+"/ActiveConnection/1", ai, map[string]any{
		"Type": "vpn", "Id": "work", "Connection": dbus.ObjectPath(nmPath + "/Settings/1"),
		"Devices": []dbus.ObjectPath{nmPath + "/Devices/2"}})
	exportProps(t, srv, nmPath+"/ActiveConnection/2", ai, map[string]any{
		"Type": "wireguard", "Id": "lab-wg", "Connection": dbus.ObjectPath(nmPath + "/Settings/2"),
		"Devices": []dbus.ObjectPath{nmPath + "/Devices/7"}})
	exportProps(t, srv, nmPath+"/ActiveConnection/3", ai, map[string]any{
		"Type": "802-3-ethernet", "Id": "Wired", "Connection": dbus.ObjectPath(nmPath + "/Settings/3"),
		"Devices": []dbus.ObjectPath{nmPath + "/Devices/2"}})
	exportProps(t, srv, nmPath+"/Devices/2", nmDest+".Device", map[string]any{"Interface": "ens18"})
	exportProps(t, srv, nmPath+"/Devices/7", nmDest+".Device", map[string]any{"Interface": "wg0"})
	settings := fakeSettings{map[string]map[string]dbus.Variant{
		"connection": {"id": dbus.MakeVariant("work"), "type": dbus.MakeVariant("vpn")},
		"vpn": {
			"service-type": dbus.MakeVariant("org.freedesktop.NetworkManager.openvpn"),
			"data":         dbus.MakeVariant(map[string]string{"cert": "/home/u/cert.pem", "connection-type": "tls", "remote": "vpn.example.com"}),
		},
	}}
	if err := srv.Export(settings, nmPath+"/Settings/1", nmDest+".Settings.Connection"); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := ActiveNM(ctx, dial(t, addr))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("connections: %+v", got)
	}
	if c := got[0]; c.ID != "work" || c.Kind != "openvpn" || c.CertPath != "/home/u/cert.pem" {
		t.Errorf("OpenVPN connection: %+v", c)
	}
	if c := got[1]; c.ID != "lab-wg" || c.Kind != "wireguard" || len(c.Interfaces) != 1 || c.Interfaces[0] != "wg0" {
		t.Errorf("WireGuard connection: %+v", c)
	}
}

// Without NetworkManager on the bus, ActiveNM fails (the daemon then skips
// the check silently).
func TestActiveNMAbsent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := ActiveNM(ctx, dial(t, privateBus(t))); err == nil {
		t.Fatal("no error without NetworkManager")
	}
}
