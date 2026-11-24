package openvpn

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gallbotond/vpncell/internal/backend/wireguard"
	"github.com/gallbotond/vpncell/internal/brand"
	"github.com/gallbotond/vpncell/internal/profile"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// HookEnv is what OpenVPN passes to the up/down hook.
type HookEnv struct {
	ScriptType string
	Dev        string
	Addresses  []netip.Prefix
	MTU        int
	DNS        []string
	Search     []string
}

var safeEnvName = regexp.MustCompile(`^vpntun[0-9]{1,4}$`)

// ParseHookEnv reads the variables OpenVPN sets for scripts.
func ParseHookEnv(get func(string) string, environ []string) (*HookEnv, error) {
	e := &HookEnv{ScriptType: get("script_type"), Dev: get("dev")}
	if !safeEnvName.MatchString(e.Dev) {
		return nil, fmt.Errorf("unexpected device name %q", e.Dev)
	}
	if v := get("tun_mtu"); v != "" {
		e.MTU, _ = strconv.Atoi(v)
	}
	if l := get("ifconfig_local"); l != "" {
		a, err := netip.ParseAddr(l)
		if err != nil {
			return nil, fmt.Errorf("ifconfig_local: %w", err)
		}
		bits := 32
		if m := get("ifconfig_netmask"); m != "" {
			ip := net.ParseIP(m).To4()
			if ip == nil {
				return nil, fmt.Errorf("ifconfig_netmask %q", m)
			}
			bits, _ = net.IPMask(ip).Size()
		}
		e.Addresses = append(e.Addresses, netip.PrefixFrom(a, bits))
	}
	if l := get("ifconfig_ipv6_local"); l != "" {
		a, err := netip.ParseAddr(l)
		if err != nil {
			return nil, fmt.Errorf("ifconfig_ipv6_local: %w", err)
		}
		bits := 128
		if n := get("ifconfig_ipv6_netbits"); n != "" {
			bits, _ = strconv.Atoi(n)
		}
		e.Addresses = append(e.Addresses, netip.PrefixFrom(a, bits))
	}
	// DNS: classic "dhcp-option" pushes (foreign_option_N) and the 2.6+
	// "dns" option (dns_server_N_address_M, dns_search_domain_N).
	var keys []string
	for _, kv := range environ {
		k, _, _ := strings.Cut(kv, "=")
		keys = append(keys, k)
	}
	sort.Strings(keys)
	addDNS := func(v string) {
		if a, err := netip.ParseAddr(v); err == nil {
			s := a.String()
			for _, x := range e.DNS {
				if x == s {
					return
				}
			}
			e.DNS = append(e.DNS, s)
		}
	}
	addSearch := func(v string) {
		if profile.ValidDomain(v) {
			e.Search = append(e.Search, strings.TrimSuffix(v, "."))
		}
	}
	for _, k := range keys {
		v := get(k)
		switch {
		case strings.HasPrefix(k, "foreign_option_"):
			f := strings.Fields(v)
			if len(f) == 3 && f[0] == "dhcp-option" {
				switch strings.ToUpper(f[1]) {
				case "DNS", "DNS6":
					addDNS(f[2])
				case "DOMAIN", "DOMAIN-SEARCH":
					addSearch(f[2])
				}
			}
		case strings.HasPrefix(k, "dns_server_") && strings.Contains(k, "_address_"):
			addDNS(strings.Split(v, " ")[0])
		case strings.HasPrefix(k, "dns_search_domain_"):
			addSearch(v)
		}
	}
	return e, nil
}

// RunHook is `vpncelld ovpn-hook <profile>`, run by openvpn as root in the
// host namespace. On "up" it moves the tun device into the profile
// namespace (if it is still in the host namespace) and applies addresses,
// MTU and routes there itself, so reconnects work while the daemon is
// restarting. It records the pushed DNS for the daemon.
func RunHook(args []string, writeDNS func(p *profile.Profile, servers []netip.Addr, search []string) error) int {
	if len(args) < 1 || !profile.ValidName(args[0]) {
		fmt.Fprintln(os.Stderr, "ovpn-hook: bad profile")
		return 1
	}
	name := args[0]
	e, err := ParseHookEnv(os.Getenv, os.Environ())
	if err != nil {
		fmt.Fprintln(os.Stderr, "ovpn-hook:", err)
		return 1
	}
	if e.ScriptType == "down" {
		return 0 // persist-tun keeps the device; openvpn removes it on exit
	}
	data, err := os.ReadFile(filepath.Join(brand.ProfilesDir(), name+".toml"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "ovpn-hook:", err)
		return 1
	}
	p, err := profile.Parse(name, data)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ovpn-hook:", err)
		return 1
	}
	// Move the device if openvpn just created it in the host namespace.
	if l, err := netlink.LinkByName(e.Dev); err == nil {
		fd, err := unix.Open(brand.NetnsPath(name), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ovpn-hook: profile namespace:", err)
			netlink.LinkSetDown(l)
			return 1
		}
		err = netlink.LinkSetNsFd(l, fd)
		unix.Close(fd)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ovpn-hook: move device:", err)
			return 1
		}
	}
	mtu := e.MTU
	if err := wireguard.ConfigureInside(p, e.Dev, e.Addresses, mtu); err != nil {
		fmt.Fprintln(os.Stderr, "ovpn-hook: configure:", err)
		return 1
	}
	pu := Pushed{DNS: e.DNS, Search: e.Search, Time: time.Now().Unix()}
	for _, a := range e.Addresses {
		pu.Addresses = append(pu.Addresses, a.String())
	}
	out, _ := json.Marshal(pu)
	os.MkdirAll(brand.ProfileRunDir(name), 0o755)
	tmp := PushedPath(name) + ".tmp"
	if err := os.WriteFile(tmp, out, 0o644); err == nil {
		os.Rename(tmp, PushedPath(name))
	}
	if writeDNS != nil {
		var servers []netip.Addr
		for _, d := range e.DNS {
			if a, err := netip.ParseAddr(d); err == nil {
				servers = append(servers, a)
			}
		}
		if err := writeDNS(p, servers, e.Search); err != nil {
			fmt.Fprintln(os.Stderr, "ovpn-hook: dns files:", err)
		}
	}
	return 0
}
