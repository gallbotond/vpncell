// Package conflict finds VPN connections outside vpncell that use the same
// client identity as a profile (issue #19): an active NetworkManager OpenVPN
// connection with the same client certificate, or a WireGuard interface on
// the host with the same key. Two clients with one identity knock each other
// off the server. Everything here is read-only; private keys are only used
// to derive the public key and are never kept or logged.
package conflict

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unicode"

	"github.com/godbus/dbus/v5"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Identity is a profile's client identity.
type Identity struct {
	Cert  *x509.Certificate // OpenVPN client certificate, if known
	WGPub *wgtypes.Key      // WireGuard public key, if known
}

// maxFile limits what is read from paths that other programs name.
const maxFile = 1 << 20

// ReadRegular reads a regular file of at most 1 MiB. It never blocks on a
// FIFO or device: the paths come from NetworkManager connections, which
// users can create.
func ReadRegular(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxFile {
		return nil, fmt.Errorf("%s: not a regular file of at most 1 MiB", path)
	}
	return io.ReadAll(io.LimitReader(f, maxFile))
}

// FirstCert returns the first PEM certificate in data.
func FirstCert(data []byte) *x509.Certificate {
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return nil
		}
		if b.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil
			}
			return c
		}
	}
}

// OpenVPNIdentity reads the client certificate of an OpenVPN config: a
// `cert <path>` directive or an inline <cert> block. pkcs12 is not read.
func OpenVPNIdentity(config []byte, read func(string) ([]byte, error)) Identity {
	sc := bufio.NewScanner(bytes.NewReader(config))
	sc.Buffer(make([]byte, 64*1024), maxFile)
	var inline strings.Builder
	in := false
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		switch {
		case l == "<cert>":
			in = true
		case l == "</cert>":
			return Identity{Cert: FirstCert([]byte(inline.String()))}
		case in:
			inline.WriteString(l + "\n")
		case strings.HasPrefix(l, "cert ") || strings.HasPrefix(l, "cert\t"):
			arg := strings.TrimSpace(l[len("cert"):])
			if u, err := strconv.Unquote(arg); err == nil {
				arg = u
			}
			data, err := read(arg)
			if err != nil {
				return Identity{}
			}
			return Identity{Cert: FirstCert(data)}
		}
	}
	return Identity{}
}

// WireGuardIdentity derives the public key from a wg-quick config's
// [Interface] PrivateKey.
func WireGuardIdentity(config []byte) Identity {
	section := ""
	for _, l := range strings.Split(string(config), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "[") {
			section = strings.ToLower(l)
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok || section != "[interface]" || !strings.EqualFold(strings.TrimSpace(k), "PrivateKey") {
			continue
		}
		key, err := wgtypes.ParseKey(strings.TrimSpace(v))
		if err != nil {
			return Identity{}
		}
		pub := key.PublicKey()
		return Identity{WGPub: &pub}
	}
	return Identity{}
}

// NMConnection is an active NetworkManager VPN or WireGuard connection.
type NMConnection struct {
	ID         string
	Kind       string // "openvpn", "wireguard", or the VPN service type
	CertPath   string // OpenVPN: vpn.data cert
	Interfaces []string
}

const (
	nmDest = "org.freedesktop.NetworkManager"
	nmPath = "/org/freedesktop/NetworkManager"
)

func getProp(ctx context.Context, conn *dbus.Conn, path dbus.ObjectPath, iface, name string) (dbus.Variant, error) {
	var v dbus.Variant
	err := conn.Object(nmDest, path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, iface, name).Store(&v)
	return v, err
}

// ActiveNM lists NetworkManager's active VPN and WireGuard connections.
func ActiveNM(ctx context.Context, conn *dbus.Conn) ([]NMConnection, error) {
	v, err := getProp(ctx, conn, nmPath, nmDest, "ActiveConnections")
	if err != nil {
		return nil, err
	}
	paths, ok := v.Value().([]dbus.ObjectPath)
	if !ok {
		return nil, errors.New("ActiveConnections: unexpected type")
	}
	var out []NMConnection
	for _, ap := range paths {
		const ai = nmDest + ".Connection.Active"
		tv, err := getProp(ctx, conn, ap, ai, "Type")
		if err != nil {
			continue // went away meanwhile
		}
		typ, _ := tv.Value().(string)
		if typ != "vpn" && typ != "wireguard" {
			continue
		}
		c := NMConnection{Kind: typ}
		if iv, err := getProp(ctx, conn, ap, ai, "Id"); err == nil {
			c.ID, _ = iv.Value().(string)
		}
		if dv, err := getProp(ctx, conn, ap, ai, "Devices"); err == nil {
			devs, _ := dv.Value().([]dbus.ObjectPath)
			for _, dp := range devs {
				if nv, err := getProp(ctx, conn, dp, nmDest+".Device", "Interface"); err == nil {
					if n, _ := nv.Value().(string); n != "" {
						c.Interfaces = append(c.Interfaces, n)
					}
				}
			}
		}
		if typ == "vpn" {
			sv, err := getProp(ctx, conn, ap, ai, "Connection")
			if err != nil {
				continue
			}
			sp, _ := sv.Value().(dbus.ObjectPath)
			var settings map[string]map[string]dbus.Variant
			if err := conn.Object(nmDest, sp).CallWithContext(ctx, nmDest+".Settings.Connection.GetSettings", 0).Store(&settings); err != nil {
				continue
			}
			vpn := settings["vpn"]
			c.Kind, _ = vpn["service-type"].Value().(string)
			if strings.HasSuffix(c.Kind, ".openvpn") {
				c.Kind = "openvpn"
				data, _ := vpn["data"].Value().(map[string]string)
				c.CertPath = data["cert"]
			}
		}
		out = append(out, c)
	}
	return out, nil
}

// WGDevice is a WireGuard interface in the host namespace.
type WGDevice struct {
	Name string
	Pub  wgtypes.Key
}

// HostWireGuard lists the WireGuard interfaces of the calling process's
// network namespace (the daemon's: the host's).
func HostWireGuard() ([]WGDevice, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	devs, err := c.Devices()
	if err != nil {
		return nil, err
	}
	var out []WGDevice
	for _, d := range devs {
		out = append(out, WGDevice{Name: d.Name, Pub: d.PublicKey})
	}
	return out, nil
}

// Check returns a warning for each connection outside vpncell that uses the
// identity of profile name.
func Check(name string, id Identity, nm []NMConnection, wg []WGDevice, read func(string) ([]byte, error)) []string {
	var out []string
	if id.Cert != nil {
		sum := sha256.Sum256(id.Cert.Raw)
		for _, c := range nm {
			if c.Kind != "openvpn" || c.CertPath == "" {
				continue
			}
			data, err := read(c.CertPath)
			if err != nil {
				continue
			}
			other := FirstCert(data)
			switch {
			case other == nil:
			case sha256.Sum256(other.Raw) == sum:
				out = append(out, fmt.Sprintf("NetworkManager connection %q (active) uses the same client certificate as profile %s. The server will likely drop one of them. Disconnect it with: nmcli connection down %s",
					c.ID, name, shellQuote(c.ID)))
			case id.Cert.Subject.CommonName != "" && other.Subject.CommonName == id.Cert.Subject.CommonName:
				out = append(out, fmt.Sprintf("NetworkManager connection %q (active) uses a client certificate with the same name (CN) as profile %s. If the server tells clients apart by name, it will drop one of them. Disconnect it with: nmcli connection down %s",
					c.ID, name, shellQuote(c.ID)))
			}
		}
	}
	if id.WGPub != nil {
		for _, d := range wg {
			if d.Pub != *id.WGPub {
				continue
			}
			owner := ""
			for _, c := range nm {
				for _, i := range c.Interfaces {
					if i == d.Name {
						owner = c.ID
					}
				}
			}
			if owner != "" {
				out = append(out, fmt.Sprintf("NetworkManager connection %q (active, interface %s) uses the same WireGuard key as profile %s. The server's peer endpoint will flip between them. Disconnect it with: nmcli connection down %s",
					owner, d.Name, name, shellQuote(owner)))
			} else {
				out = append(out, fmt.Sprintf("WireGuard interface %s on the host uses the same key as profile %s. The server's peer endpoint will flip between them. Take it down to use the profile",
					d.Name, name))
			}
		}
	}
	return out
}

// shellQuote quotes s for a shell command line if it needs it. Control
// characters (a connection name is chosen by any local user) are shown
// escaped, never sent to the terminal as they are.
func shellQuote(s string) string {
	if strings.ContainsFunc(s, unicode.IsControl) {
		return strconv.Quote(s)
	}
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.:/@+", r))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
