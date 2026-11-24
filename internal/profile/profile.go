// Package profile parses and validates profile files and evaluates access
// lists.
package profile

import (
	"fmt"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/gallbotond/vpncell/internal/brand"
)

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

// ValidName reports whether n is an acceptable profile name.
func ValidName(n string) bool { return nameRE.MatchString(n) }

const (
	BackendWireGuard = "wireguard"
	BackendOpenVPN   = "openvpn"

	AutostartBoot   = "boot"
	AutostartOnUse  = "on-use"
	AutostartManual = "manual"
)

type Profile struct {
	Name      string `toml:"-"`
	Backend   string `toml:"backend"`
	Autostart string `toml:"autostart"`

	WireGuard struct {
		Config string `toml:"config"`
	} `toml:"wireguard"`
	OpenVPN struct {
		Config   string `toml:"config"`
		AuthFile string `toml:"auth_file"`
	} `toml:"openvpn"`
	DNS struct {
		Servers   []string `toml:"servers"`
		Search    []string `toml:"search"`
		UsePushed *bool    `toml:"use_pushed"`
	} `toml:"dns"`
	Access struct {
		Users  []string `toml:"users"`
		Groups []string `toml:"groups"`
	} `toml:"access"`
	Routing struct {
		Routes []string `toml:"routes"`
	} `toml:"routing"`
	Socks struct {
		Port int `toml:"port"`
	} `toml:"socks"`
	Status struct {
		ExitIPURL string `toml:"exit_ip_url"`
	} `toml:"status"`
	Security struct {
		Nftables *bool `toml:"nftables"`
	} `toml:"security"`

	// Parsed values.
	DNSServers []netip.Addr   `toml:"-"`
	RoutesP    []netip.Prefix `toml:"-"`
}

// UsePushedDNS reports whether DNS servers pushed by the VPN are used.
func (p *Profile) UsePushedDNS() bool {
	if p.DNS.UsePushed != nil {
		return *p.DNS.UsePushed
	}
	return p.Backend == BackendOpenVPN
}

// NftablesEnabled reports whether the in-namespace nftables layer is on.
func (p *Profile) NftablesEnabled() bool {
	return p.Security.Nftables == nil || *p.Security.Nftables
}

// Parse parses and validates a profile file's content.
func Parse(name string, data []byte) (*Profile, error) {
	if !ValidName(name) {
		return nil, fmt.Errorf("invalid profile name %q (want %s)", name, nameRE.String())
	}
	p := &Profile{Name: name}
	md, err := toml.Decode(string(data), p)
	if err != nil {
		return nil, fmt.Errorf("profile %s: %w", name, err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("profile %s: unknown keys: %s", name, strings.Join(keys, ", "))
	}
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("profile %s: %w", name, err)
	}
	return p, nil
}

func (p *Profile) validate() error {
	switch p.Backend {
	case BackendWireGuard:
		if p.WireGuard.Config == "" {
			return fmt.Errorf("wireguard.config is required")
		}
	case BackendOpenVPN:
		if p.OpenVPN.Config == "" {
			return fmt.Errorf("openvpn.config is required")
		}
	default:
		return fmt.Errorf("backend must be %q or %q", BackendWireGuard, BackendOpenVPN)
	}
	switch p.Autostart {
	case "":
		p.Autostart = AutostartOnUse
	case AutostartBoot, AutostartOnUse, AutostartManual:
	default:
		return fmt.Errorf("autostart must be boot, on-use or manual")
	}
	for _, s := range p.DNS.Servers {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return fmt.Errorf("dns.servers: %w", err)
		}
		p.DNSServers = append(p.DNSServers, a)
	}
	for _, s := range p.DNS.Search {
		if !validDomain(s) {
			return fmt.Errorf("dns.search: invalid domain %q", s)
		}
	}
	routes := p.Routing.Routes
	if len(routes) == 0 {
		routes = []string{"0.0.0.0/0", "::/0"}
	}
	for _, r := range routes {
		pf, err := netip.ParsePrefix(r)
		if err != nil {
			return fmt.Errorf("routing.routes: %w", err)
		}
		p.RoutesP = append(p.RoutesP, pf.Masked())
	}
	if p.Socks.Port < 0 || p.Socks.Port > 65535 {
		return fmt.Errorf("socks.port out of range")
	}
	for _, u := range p.Access.Users {
		if u == "" {
			return fmt.Errorf("access.users: empty entry")
		}
	}
	if u := p.Status.ExitIPURL; u != "" && !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return fmt.Errorf("status.exit_ip_url must be http(s)")
	}
	return nil
}

var domainRE = regexp.MustCompile(`^([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)*[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.?$`)

func validDomain(s string) bool { return len(s) <= 253 && domainRE.MatchString(s) }

// ValidDomain is exported for the importers.
func ValidDomain(s string) bool { return validDomain(s) }

// LoadAll reads every profile in the profiles directory. Invalid files are
// returned in errs and skipped.
func LoadAll() (map[string]*Profile, []error) {
	out := map[string]*Profile{}
	var errs []error
	ents, err := os.ReadDir(brand.ProfilesDir())
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return out, []error{err}
	}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".toml") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".toml")
		path := filepath.Join(brand.ProfilesDir(), e.Name())
		if err := checkRootOnly(path); err != nil {
			errs = append(errs, err)
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		p, err := Parse(name, data)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out[name] = p
	}
	return out, errs
}

// checkRootOnly refuses profile files that other users could have written.
func checkRootOnly(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s: writable by group or others; refusing", path)
	}
	if uid := statUID(st); uid != 0 && os.Getuid() == 0 {
		return fmt.Errorf("%s: not owned by root; refusing", path)
	}
	return nil
}

// Names returns the sorted profile names.
func Names(m map[string]*Profile) []string {
	n := make([]string, 0, len(m))
	for k := range m {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

// Allowed reports whether a caller with uid and groups may use the profile.
// Root may always use every profile.
func (p *Profile) Allowed(uid uint32, gid uint32, groups []uint32) bool {
	if uid == 0 {
		return true
	}
	for _, u := range p.Access.Users {
		if id, err := strconv.ParseUint(u, 10, 32); err == nil {
			if uint32(id) == uid {
				return true
			}
			continue
		}
		if usr, err := user.Lookup(u); err == nil && usr.Uid == strconv.FormatUint(uint64(uid), 10) {
			return true
		}
	}
	all := append([]uint32{gid}, groups...)
	for _, g := range p.Access.Groups {
		var want uint64
		if id, err := strconv.ParseUint(g, 10, 32); err == nil {
			want = id
		} else if grp, err := user.LookupGroup(g); err == nil {
			want, _ = strconv.ParseUint(grp.Gid, 10, 32)
		} else {
			continue
		}
		for _, have := range all {
			if uint64(have) == want {
				return true
			}
		}
	}
	return false
}

// Global settings from /etc/vpncell/vpncell.toml.
type Global struct {
	SocksPortRange string `toml:"socks_port_range"`
	LogLevel       string `toml:"log_level"`
	PortLo, PortHi int    `toml:"-"`
}

func LoadGlobal() (*Global, error) {
	g := &Global{SocksPortRange: "700-799", LogLevel: "info"}
	data, err := os.ReadFile(brand.GlobalConfig())
	if err == nil {
		if _, err := toml.Decode(string(data), g); err != nil {
			return nil, fmt.Errorf("%s: %w", brand.GlobalConfig(), err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	lo, hi, ok := strings.Cut(g.SocksPortRange, "-")
	if !ok {
		return nil, fmt.Errorf("socks_port_range must be lo-hi")
	}
	var e1, e2 error
	g.PortLo, e1 = strconv.Atoi(strings.TrimSpace(lo))
	g.PortHi, e2 = strconv.Atoi(strings.TrimSpace(hi))
	if e1 != nil || e2 != nil || g.PortLo < 1 || g.PortHi > 65535 || g.PortLo > g.PortHi {
		return nil, fmt.Errorf("bad socks_port_range %q", g.SocksPortRange)
	}
	return g, nil
}
