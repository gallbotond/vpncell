// Package importer sanitizes imported VPN configurations. Everything here is
// a pure function over untrusted input: nothing is executed, and the output is
// built from an allowlist.
package importer

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/gallbotond/vpncell/internal/profile"
)

// WGPeer is one [Peer] section.
type WGPeer struct {
	PublicKey           string
	PresharedKey        string
	AllowedIPs          []netip.Prefix
	Endpoint            string // host:port, host may be a name or [v6]
	PersistentKeepalive int
}

// WGConfig is a parsed and sanitized wg-quick config.
type WGConfig struct {
	PrivateKey string
	Addresses  []netip.Prefix
	DNSServers []netip.Addr
	DNSSearch  []string
	MTU        int
	Peers      []WGPeer
}

// Report lists what an import kept, stripped and rejected.
type Report struct {
	Kept     []string
	Stripped []string
	Warnings []string
}

// ImportError is a rejection with a reason that is safe to show.
type ImportError struct{ Reasons []string }

func (e *ImportError) Error() string {
	return "import rejected:\n  - " + strings.Join(e.Reasons, "\n  - ")
}

var wgStripped = map[string]string{
	"preup":      "runs a command as root",
	"postup":     "runs a command as root",
	"predown":    "runs a command as root",
	"postdown":   "runs a command as root",
	"saveconfig": "would write the config back from the running interface",
	"table":      "vpncell manages routes inside the namespace",
	"listenport": "a random port is used",
	"fwmark":     "would interact with host policy routing (Tailscale)",
}

var amnezia = map[string]bool{
	"jc": true, "jmin": true, "jmax": true, "s1": true, "s2": true, "s3": true, "s4": true,
	"h1": true, "h2": true, "h3": true, "h4": true, "i1": true, "i2": true, "i3": true, "i4": true, "i5": true,
}

func validKey(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

// ParseWireGuard parses a wg-quick config. Secrets never appear in the
// report or in errors.
func ParseWireGuard(text string) (*WGConfig, *Report, error) {
	cfg := &WGConfig{}
	rep := &Report{}
	var rej []string
	section := ""
	var peer *WGPeer
	flush := func() {
		if peer != nil {
			cfg.Peers = append(cfg.Peers, *peer)
			peer = nil
		}
	}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	ln := 0
	for sc.Scan() {
		ln++
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			flush()
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch section {
			case "interface":
				rep.Kept = append(rep.Kept, "[Interface]")
			case "peer":
				peer = &WGPeer{}
				rep.Kept = append(rep.Kept, "[Peer]")
			default:
				rej = append(rej, fmt.Sprintf("line %d: unknown section [%s]", ln, section))
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			rej = append(rej, fmt.Sprintf("line %d: not a key = value line", ln))
			continue
		}
		key := strings.ToLower(strings.TrimSpace(k))
		val := strings.TrimSpace(v)
		orig := strings.TrimSpace(k)
		if why, ok := wgStripped[key]; ok {
			rep.Stripped = append(rep.Stripped, fmt.Sprintf("%s (line %d): %s", orig, ln, why))
			continue
		}
		if amnezia[key] {
			rej = append(rej, fmt.Sprintf("line %d: %s is an AmneziaWG option; plain WireGuard cannot talk to an AmneziaWG server", ln, orig))
			continue
		}
		switch section {
		case "interface":
			switch key {
			case "privatekey":
				if !validKey(val) {
					rej = append(rej, fmt.Sprintf("line %d: PrivateKey is not a valid key", ln))
					continue
				}
				cfg.PrivateKey = val
				rep.Kept = append(rep.Kept, "PrivateKey (stored root-only)")
			case "address":
				for _, a := range splitList(val) {
					pf, err := parsePrefixOrAddr(a)
					if err != nil {
						rej = append(rej, fmt.Sprintf("line %d: Address %q: %v", ln, a, err))
						continue
					}
					cfg.Addresses = append(cfg.Addresses, pf)
				}
				rep.Kept = append(rep.Kept, "Address = "+val)
			case "dns":
				for _, d := range splitList(val) {
					if a, err := netip.ParseAddr(d); err == nil {
						cfg.DNSServers = append(cfg.DNSServers, a)
					} else if profile.ValidDomain(d) {
						cfg.DNSSearch = append(cfg.DNSSearch, d)
					} else {
						rej = append(rej, fmt.Sprintf("line %d: DNS entry %q is neither an address nor a domain", ln, d))
					}
				}
				rep.Kept = append(rep.Kept, "DNS = "+val+" (becomes dns.servers / dns.search)")
			case "mtu":
				n, err := strconv.Atoi(val)
				if err != nil || n < 1280 || n > 9000 {
					rej = append(rej, fmt.Sprintf("line %d: MTU %q out of range 1280-9000", ln, val))
					continue
				}
				cfg.MTU = n
				rep.Kept = append(rep.Kept, "MTU = "+val)
			default:
				rej = append(rej, fmt.Sprintf("line %d: unknown [Interface] key %s", ln, orig))
			}
		case "peer":
			switch key {
			case "publickey":
				if !validKey(val) {
					rej = append(rej, fmt.Sprintf("line %d: PublicKey is not a valid key", ln))
					continue
				}
				peer.PublicKey = val
				rep.Kept = append(rep.Kept, "PublicKey = "+val)
			case "presharedkey":
				if !validKey(val) {
					rej = append(rej, fmt.Sprintf("line %d: PresharedKey is not a valid key", ln))
					continue
				}
				peer.PresharedKey = val
				rep.Kept = append(rep.Kept, "PresharedKey (stored root-only)")
			case "allowedips":
				for _, a := range splitList(val) {
					pf, err := netip.ParsePrefix(a)
					if err != nil {
						rej = append(rej, fmt.Sprintf("line %d: AllowedIPs %q: %v", ln, a, err))
						continue
					}
					peer.AllowedIPs = append(peer.AllowedIPs, pf.Masked())
				}
				rep.Kept = append(rep.Kept, "AllowedIPs = "+val)
			case "endpoint":
				if _, _, err := SplitHostPort(val); err != nil {
					rej = append(rej, fmt.Sprintf("line %d: Endpoint %q: %v", ln, val, err))
					continue
				}
				peer.Endpoint = val
				rep.Kept = append(rep.Kept, "Endpoint = "+val)
			case "persistentkeepalive":
				if strings.EqualFold(val, "off") {
					continue
				}
				n, err := strconv.Atoi(val)
				if err != nil || n < 0 || n > 65535 {
					rej = append(rej, fmt.Sprintf("line %d: PersistentKeepalive %q invalid", ln, val))
					continue
				}
				peer.PersistentKeepalive = n
				rep.Kept = append(rep.Kept, "PersistentKeepalive = "+val)
			default:
				rej = append(rej, fmt.Sprintf("line %d: unknown [Peer] key %s", ln, orig))
			}
		default:
			rej = append(rej, fmt.Sprintf("line %d: key %s outside a section", ln, orig))
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		rej = append(rej, err.Error())
	}
	if cfg.PrivateKey == "" {
		rej = append(rej, "[Interface] PrivateKey is missing")
	}
	if len(cfg.Addresses) == 0 {
		rej = append(rej, "[Interface] Address is missing")
	}
	if len(cfg.Peers) == 0 {
		rej = append(rej, "no [Peer] section")
	}
	for i, p := range cfg.Peers {
		if p.PublicKey == "" {
			rej = append(rej, fmt.Sprintf("peer %d: PublicKey is missing", i+1))
		}
	}
	if len(rej) > 0 {
		return nil, rep, &ImportError{Reasons: rej}
	}
	return cfg, rep, nil
}

// Render writes the sanitized config in wg-quick format (only the allowlisted
// keys). The daemon stores and later re-parses this.
func (c *WGConfig) Render() string {
	var b strings.Builder
	b.WriteString("# Sanitized by vpncell import. Only allowlisted keys are kept.\n[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", c.PrivateKey)
	if len(c.Addresses) > 0 {
		fmt.Fprintf(&b, "Address = %s\n", joinPrefixes(c.Addresses))
	}
	if c.MTU != 0 {
		fmt.Fprintf(&b, "MTU = %d\n", c.MTU)
	}
	for _, p := range c.Peers {
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		if p.PresharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
		}
		if len(p.AllowedIPs) > 0 {
			fmt.Fprintf(&b, "AllowedIPs = %s\n", joinPrefixes(p.AllowedIPs))
		}
		if p.Endpoint != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", p.Endpoint)
		}
		if p.PersistentKeepalive > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.PersistentKeepalive)
		}
	}
	return b.String()
}

func joinPrefixes(ps []netip.Prefix) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return strings.Join(s, ", ")
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// SplitHostPort splits "host:port" or "[v6]:port".
func SplitHostPort(s string) (string, int, error) {
	var host, port string
	if strings.HasPrefix(s, "[") {
		i := strings.Index(s, "]:")
		if i < 0 {
			return "", 0, fmt.Errorf("want [address]:port")
		}
		host, port = s[1:i], s[i+2:]
	} else {
		i := strings.LastIndexByte(s, ':')
		if i < 0 {
			return "", 0, fmt.Errorf("missing port")
		}
		host, port = s[:i], s[i+1:]
		if strings.Contains(host, ":") {
			return "", 0, fmt.Errorf("IPv6 address must be in brackets")
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", 0, fmt.Errorf("bad port %q", port)
	}
	if host == "" {
		return "", 0, fmt.Errorf("empty host")
	}
	if _, err := netip.ParseAddr(host); err != nil && !profile.ValidDomain(host) {
		return "", 0, fmt.Errorf("bad host %q", host)
	}
	return host, n, nil
}
