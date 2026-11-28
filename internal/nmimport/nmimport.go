// Package nmimport turns a NetworkManager VPN connection (OpenVPN or
// WireGuard) into the config text a file import would read (issue #18), so
// that `import --from-nm` goes through the same allowlist and report as an
// equivalent .ovpn or wg-quick file. It only reads from NetworkManager.
//
// OpenVPN settings are mapped from vpn.data key by key (nmcli's export drops
// some of them, such as `auth`). Unknown keys and features vpncell does not
// support (tap, proxies, static keys) make the import fail with a reason.
package nmimport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/godbus/dbus/v5"
)

const (
	nmDest      = "org.freedesktop.NetworkManager"
	settingsObj = "/org/freedesktop/NetworkManager/Settings"
	connIface   = nmDest + ".Settings.Connection"
	openvpnSvc  = "org.freedesktop.NetworkManager.openvpn"
)

// Settings is a connection's settings as GetSettings returns them.
type Settings map[string]map[string]dbus.Variant

// Connection is a NetworkManager connection.
type Connection struct {
	ID   string
	UUID string
	Kind string // "openvpn", "wireguard", or "vpn: <service>" for other VPN types
	Path dbus.ObjectPath
}

// Importable reports whether vpncell can import the connection.
func (c Connection) Importable() bool { return c.Kind == "openvpn" || c.Kind == "wireguard" }

func str(v dbus.Variant) string { s, _ := v.Value().(string); return s }

func kindOf(s Settings) string {
	switch str(s["connection"]["type"]) {
	case "wireguard":
		return "wireguard"
	case "vpn":
		svc := str(s["vpn"]["service-type"])
		if svc == openvpnSvc {
			return "openvpn"
		}
		return "vpn: " + svc
	}
	return ""
}

// List returns NetworkManager's VPN and WireGuard connections.
func List(ctx context.Context, conn *dbus.Conn) ([]Connection, error) {
	var paths []dbus.ObjectPath
	if err := conn.Object(nmDest, settingsObj).CallWithContext(ctx, nmDest+".Settings.ListConnections", 0).Store(&paths); err != nil {
		return nil, fmt.Errorf("NetworkManager: %w", err)
	}
	var out []Connection
	for _, p := range paths {
		s, err := getSettings(ctx, conn, p)
		if err != nil {
			continue
		}
		k := kindOf(s)
		if k == "" {
			continue
		}
		out = append(out, Connection{ID: str(s["connection"]["id"]), UUID: str(s["connection"]["uuid"]), Kind: k, Path: p})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func getSettings(ctx context.Context, conn *dbus.Conn, p dbus.ObjectPath) (Settings, error) {
	var s Settings
	err := conn.Object(nmDest, p).CallWithContext(ctx, connIface+".GetSettings", 0).Store(&s)
	return s, err
}

func getSecrets(ctx context.Context, conn *dbus.Conn, p dbus.ObjectPath, setting string) (Settings, error) {
	var s Settings
	err := conn.Object(nmDest, p).CallWithContext(ctx, connIface+".GetSecrets", 0, setting).Store(&s)
	return s, err
}

// Find returns the connection with this name or UUID.
func Find(cs []Connection, name string) (Connection, error) {
	var found []Connection
	for _, c := range cs {
		if c.ID == name || c.UUID == name {
			found = append(found, c)
		}
	}
	switch {
	case len(found) == 0:
		return Connection{}, fmt.Errorf("no NetworkManager VPN connection %q (run `vpncell import --from-nm` to list them)", name)
	case len(found) > 1:
		return Connection{}, fmt.Errorf("%d NetworkManager connections are called %q; give the UUID instead", len(found), name)
	case !found[0].Importable():
		return Connection{}, fmt.Errorf("NetworkManager connection %q is %s; vpncell imports OpenVPN and WireGuard only", name, found[0].Kind)
	}
	return found[0], nil
}

// Result is what a file import would read.
type Result struct {
	Kind    string // "openvpn" or "wireguard"
	Config  string
	Files   map[string]string // OpenVPN: name in Config -> path to read
	Auth    string            // "user\npassword\n" read from NetworkManager, if any
	Summary string            // e.g. "OpenVPN, tls, 4 files"
	// NeedsAuth: the config has auth-user-pass and no password could be
	// read (the caller needs --auth-file).
	NeedsAuth bool
	AuthWhy   string
}

// Read builds the import for connection c. Secrets (an OpenVPN password,
// a WireGuard private key) are read only when NetworkManager stores them in
// the connection (flags 0); a secret kept in a user's keyring cannot be
// read by root, and the result says what to pass instead.
func Read(ctx context.Context, conn *dbus.Conn, c Connection) (*Result, error) {
	s, err := getSettings(ctx, conn, c.Path)
	if err != nil {
		return nil, fmt.Errorf("NetworkManager connection %q: %w", c.ID, err)
	}
	switch c.Kind {
	case "openvpn":
		data, _ := s["vpn"]["data"].Value().(map[string]string)
		cfg, err := OpenVPNConfig(data)
		if err != nil {
			return nil, fmt.Errorf("NetworkManager connection %q: %w", c.ID, err)
		}
		r := &Result{Kind: "openvpn", Config: cfg.Text, Files: cfg.Files,
			Summary: fmt.Sprintf("OpenVPN, %s, %d files", data["connection-type"], len(cfg.Files))}
		if cfg.NeedsPassword {
			r.NeedsAuth = true
			switch flags := data["password-flags"]; flags {
			case "", "0":
				sec, err := getSecrets(ctx, conn, c.Path, "vpn")
				if err == nil {
					m, _ := sec["vpn"]["secrets"].Value().(map[string]string)
					if pw := m["password"]; pw != "" {
						r.Auth, r.NeedsAuth = data["username"]+"\n"+pw+"\n", false
					}
				}
				if r.NeedsAuth {
					r.AuthWhy = "NetworkManager has no saved password for it"
				}
			default:
				r.AuthWhy = fmt.Sprintf("its password is not stored in the connection (password-flags %s: a keyring or asked each time), so root cannot read it", flags)
			}
		}
		return r, nil
	case "wireguard":
		wg, err := wireGuardFromSettings(s)
		if err != nil {
			return nil, fmt.Errorf("NetworkManager connection %q: %w", c.ID, err)
		}
		flags, _ := s["wireguard"]["private-key-flags"].Value().(uint32)
		if flags != 0 {
			return nil, fmt.Errorf("NetworkManager connection %q keeps its private key outside the connection (private-key-flags %d: a keyring or asked each time), so root cannot read it; import a wg-quick file instead", c.ID, flags)
		}
		sec, err := getSecrets(ctx, conn, c.Path, "wireguard")
		if err != nil {
			return nil, fmt.Errorf("NetworkManager connection %q: reading its private key: %w", c.ID, err)
		}
		wg.PrivateKey = str(sec["wireguard"]["private-key"])
		if peers, ok := sec["wireguard"]["peers"].Value().([]map[string]dbus.Variant); ok {
			for _, ps := range peers {
				for i := range wg.Peers {
					if wg.Peers[i].PublicKey == str(ps["public-key"]) {
						wg.Peers[i].PresharedKey = str(ps["preshared-key"])
					}
				}
			}
		}
		if wg.PrivateKey == "" {
			return nil, fmt.Errorf("NetworkManager connection %q has no private key", c.ID)
		}
		text, err := wg.Render()
		if err != nil {
			return nil, fmt.Errorf("NetworkManager connection %q: %w", c.ID, err)
		}
		return &Result{Kind: "wireguard", Config: text, Summary: fmt.Sprintf("WireGuard, %d peer(s)", len(wg.Peers))}, nil
	}
	return nil, fmt.Errorf("NetworkManager connection %q is %s; vpncell imports OpenVPN and WireGuard only", c.ID, c.Kind)
}

// OVPN is a generated OpenVPN config.
type OVPN struct {
	Text string
	// Files maps the names the config refers to ("ca.pem") to the paths
	// NetworkManager keeps them at. The names are fixed, so paths with
	// spaces (NetworkManager puts the connection name in them) need no
	// quoting and the user's paths do not end up in the stored config.
	Files         map[string]string
	NeedsPassword bool // it has auth-user-pass
}

// Keys of the NetworkManager OpenVPN plugin's vpn.data that map to one
// directive with the same argument.
var sameArg = map[string]string{
	"auth": "auth", "cipher": "cipher", "data-ciphers": "data-ciphers",
	"data-ciphers-fallback": "data-ciphers-fallback", "tls-cipher": "tls-cipher",
	"tls-version-min": "tls-version-min", "tls-version-max": "tls-version-max",
	"remote-cert-tls": "remote-cert-tls", "ns-cert-type": "ns-cert-type",
	"reneg-seconds": "reneg-sec", "tunnel-mtu": "tun-mtu", "fragment-size": "fragment",
	"ping": "ping", "ping-exit": "ping-exit", "ping-restart": "ping-restart",
	"connect-timeout": "connect-timeout", "mtu-disc": "mtu-disc",
	"allow-compression": "allow-compression", "comp-lzo": "comp-lzo",
	"ca": "ca", "cert": "cert", "key": "key", "tls-crypt": "tls-crypt",
	"tls-crypt-v2": "tls-crypt-v2", "extra-certs": "extra-certs",
}

// Keys that are a yes/no flag for a directive without argument.
var flagKey = map[string]string{
	"float": "float", "remote-random": "remote-random", "remote-random-hostname": "remote-random-hostname",
	"push-peer-info": "push-peer-info", "allow-pull-fqdn": "allow-pull-fqdn",
}

// Keys that are read with another key, or have no effect.
var handled = map[string]bool{
	"connection-type": true, "remote": true, "port": true, "proto-tcp": true, "dev-type": true,
	"tap-dev": true, "dev": true, "username": true, "password-flags": true, "cert-pass-flags": true,
	"ta": true, "ta-dir": true, "verify-x509-name": true, "mssfix": true, "compress": true,
	"crl-verify-file": true, "crl-verify-dir": true, "tun-ipv6": true, "challenge-response-flags": true,
}

// Keys for features vpncell does not support, with the reason.
var unsupported = map[string]string{
	"proxy-type":           "proxies are not supported (the tunnel must not depend on a host proxy)",
	"proxy-server":         "proxies are not supported (the tunnel must not depend on a host proxy)",
	"proxy-port":           "proxies are not supported",
	"proxy-retry":          "proxies are not supported",
	"http-proxy-username":  "proxies are not supported",
	"static-key":           "static-key (pre-shared key) mode is not supported",
	"static-key-direction": "static-key mode is not supported",
	"local-ip":             "static-key mode is not supported",
	"remote-ip":            "static-key mode is not supported",
	"pkcs11-provider":      "PKCS#11 tokens are not supported",
	"pkcs11-id":            "PKCS#11 tokens are not supported",
	"tls-remote":           "tls-remote was removed from OpenVPN; use verify-x509-name",
	"max-routes":           "max-routes was removed from OpenVPN",
	"keysize":              "keysize was removed from OpenVPN",
}

// quoteIfNeeded quotes an OpenVPN argument that has spaces or quotes.
func quoteIfNeeded(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"'\\") {
		return s
	}
	return strconv.Quote(s)
}

func yes(v string) bool { return v == "yes" || v == "true" || v == "1" }

// OpenVPNConfig maps a NetworkManager OpenVPN vpn.data to a client config.
func OpenVPNConfig(data map[string]string) (*OVPN, error) {
	var bad []string
	for k := range data {
		if why, ok := unsupported[k]; ok {
			if data[k] != "" && data[k] != "none" {
				return nil, fmt.Errorf("vpn.data %s: %s", k, why)
			}
			continue
		}
		if _, ok := sameArg[k]; ok {
			continue
		}
		if flagKey[k] != "" || handled[k] || strings.HasSuffix(k, "-flags") {
			continue
		}
		bad = append(bad, k)
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return nil, fmt.Errorf("vpn.data has settings vpncell does not know how to import: %s (import an .ovpn file instead)", strings.Join(bad, ", "))
	}
	if yes(data["tap-dev"]) || data["dev-type"] == "tap" {
		return nil, errors.New("tap (layer 2) connections are not supported")
	}
	ct := data["connection-type"]
	switch ct {
	case "tls", "password", "password-tls":
	case "static-key":
		return nil, errors.New("static-key (pre-shared key) mode is not supported")
	case "":
		return nil, errors.New("vpn.data has no connection-type")
	default:
		return nil, fmt.Errorf("connection-type %q is not supported", ct)
	}
	o := &OVPN{Files: map[string]string{}}
	var b strings.Builder
	line := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	line("# Generated by vpncell from a NetworkManager connection.")
	line("client")
	line("dev tun")
	proto := "udp"
	if yes(data["proto-tcp"]) {
		proto = "tcp-client"
	}
	remotes, err := parseRemotes(data["remote"], data["port"], proto)
	if err != nil {
		return nil, err
	}
	for _, r := range remotes {
		line("%s", r)
	}
	line("nobind")
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	file := func(directive, path string, extra ...string) {
		ref := directive + ".pem"
		o.Files[ref] = path
		line("%s", strings.Join(append([]string{directive, ref}, extra...), " "))
	}
	for _, k := range keys {
		v := data[k]
		if d, ok := sameArg[k]; ok && v != "" {
			switch k {
			case "ca", "cert", "key", "tls-crypt", "tls-crypt-v2", "extra-certs":
				if (k == "cert" || k == "key") && ct == "password" {
					continue // NM keeps them but does not use them in this mode
				}
				file(d, v)
			case "comp-lzo":
				if v != "no-by-default" {
					line("comp-lzo %s", v)
				}
			default:
				line("%s %s", d, v)
			}
		}
		if d := flagKey[k]; d != "" && yes(v) {
			line("%s", d)
		}
	}
	if ta := data["ta"]; ta != "" {
		if dir := data["ta-dir"]; dir != "" {
			file("tls-auth", ta, dir)
		} else {
			file("tls-auth", ta)
		}
	}
	if v := data["verify-x509-name"]; v != "" {
		typ, name, ok := strings.Cut(v, ":")
		if !ok {
			typ, name = "subject", v
		}
		line("verify-x509-name %s %s", quoteIfNeeded(name), typ)
	}
	if v := data["mssfix"]; v != "" && v != "no" {
		if yes(v) {
			line("mssfix")
		} else {
			line("mssfix %s", v)
		}
	}
	if v := data["compress"]; v != "" && v != "no" {
		if yes(v) {
			line("compress")
		} else {
			line("compress %s", v)
		}
	}
	if v := data["crl-verify-file"]; v != "" {
		file("crl-verify", v)
	} else if v := data["crl-verify-dir"]; v != "" {
		return nil, errors.New("crl-verify with a directory is not supported; use a CRL file")
	}
	if ct == "password" || ct == "password-tls" {
		line("auth-user-pass")
		o.NeedsPassword = true
	}
	o.Text = b.String()
	return o, nil
}

// parseRemotes reads vpn.data remote: "host[:port[:proto]]" entries
// separated by commas or spaces; IPv6 hosts in brackets.
func parseRemotes(v, port, proto string) ([]string, error) {
	if port == "" {
		port = "1194"
	}
	var out []string
	for _, e := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
		host, rest := e, ""
		if strings.HasPrefix(e, "[") {
			i := strings.Index(e, "]")
			if i < 0 {
				return nil, fmt.Errorf("remote %q: missing ]", e)
			}
			host, rest = e[1:i], strings.TrimPrefix(e[i+1:], ":")
		} else if strings.Count(e, ":") <= 2 {
			host, rest, _ = strings.Cut(e, ":")
		}
		p, pr, _ := strings.Cut(rest, ":")
		if p == "" {
			p = port
		}
		switch pr {
		case "":
			pr = proto
		case "tcp", "tcp4", "tcp6":
			pr = pr + "-client"
		}
		if host == "" {
			return nil, fmt.Errorf("remote %q: no host", e)
		}
		out = append(out, fmt.Sprintf("remote %s %s %s", host, p, pr))
	}
	if len(out) == 0 {
		return nil, errors.New("vpn.data has no remote")
	}
	return out, nil
}

// WG is a WireGuard connection.
type WG struct {
	PrivateKey string
	Addresses  []netip.Prefix
	DNS        []netip.Addr
	Search     []string
	MTU        uint32
	Peers      []WGPeer
}

type WGPeer struct {
	PublicKey    string
	PresharedKey string
	Endpoint     string
	AllowedIPs   []string
	Keepalive    uint32
}

func wireGuardFromSettings(s Settings) (*WG, error) {
	w := &WG{}
	w.MTU, _ = s["wireguard"]["mtu"].Value().(uint32)
	peers, _ := s["wireguard"]["peers"].Value().([]map[string]dbus.Variant)
	for _, p := range peers {
		pe := WGPeer{PublicKey: str(p["public-key"]), Endpoint: str(p["endpoint"])}
		pe.AllowedIPs, _ = p["allowed-ips"].Value().([]string)
		pe.Keepalive, _ = p["persistent-keepalive"].Value().(uint32)
		w.Peers = append(w.Peers, pe)
	}
	for _, fam := range []string{"ipv4", "ipv6"} {
		ip := s[fam]
		ads, _ := ip["address-data"].Value().([]map[string]dbus.Variant)
		for _, a := range ads {
			pfx, _ := a["prefix"].Value().(uint32)
			addr, err := netip.ParseAddr(str(a["address"]))
			if err != nil {
				return nil, fmt.Errorf("%s address %q: %w", fam, str(a["address"]), err)
			}
			w.Addresses = append(w.Addresses, netip.PrefixFrom(addr, int(pfx)))
		}
		if dd, ok := ip["dns-data"].Value().([]string); ok && len(dd) > 0 {
			for _, d := range dd {
				// "address[#server-name]"
				a, _, _ := strings.Cut(d, "#")
				if addr, err := netip.ParseAddr(a); err == nil {
					w.DNS = append(w.DNS, addr)
				}
			}
		} else if fam == "ipv4" {
			ds, _ := ip["dns"].Value().([]uint32)
			for _, d := range ds {
				var b [4]byte
				binary.LittleEndian.PutUint32(b[:], d) // network order in a native uint32
				w.DNS = append(w.DNS, netip.AddrFrom4(b))
			}
		} else {
			ds, _ := ip["dns"].Value().([][]byte)
			for _, d := range ds {
				if a, ok := netip.AddrFromSlice(d); ok {
					w.DNS = append(w.DNS, a)
				}
			}
		}
		if se, ok := ip["dns-search"].Value().([]string); ok {
			w.Search = append(w.Search, se...)
		}
	}
	if len(w.Peers) == 0 {
		return nil, errors.New("the WireGuard connection has no peers")
	}
	return w, nil
}

// Render writes a wg-quick config.
func (w *WG) Render() (string, error) {
	if len(w.Addresses) == 0 {
		return "", errors.New("the WireGuard connection has no addresses (ipv4/ipv6 method manual)")
	}
	var b strings.Builder
	b.WriteString("# Generated by vpncell from a NetworkManager connection.\n[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", w.PrivateKey)
	as := make([]string, len(w.Addresses))
	for i, a := range w.Addresses {
		as[i] = a.String()
	}
	fmt.Fprintf(&b, "Address = %s\n", strings.Join(as, ", "))
	var dns []string
	for _, d := range w.DNS {
		dns = append(dns, d.String())
	}
	dns = append(dns, w.Search...)
	if len(dns) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(dns, ", "))
	}
	if w.MTU != 0 {
		fmt.Fprintf(&b, "MTU = %d\n", w.MTU)
	}
	for _, p := range w.Peers {
		fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\n", p.PublicKey)
		if p.PresharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
		}
		if p.Endpoint != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", p.Endpoint)
		}
		if len(p.AllowedIPs) > 0 {
			fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(p.AllowedIPs, ", "))
		}
		if p.Keepalive != 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.Keepalive)
		}
	}
	return b.String(), nil
}
