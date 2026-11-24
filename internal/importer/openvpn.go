package importer

import (
	"bufio"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// OVPNConfig is a sanitized OpenVPN client config. Lines holds the kept
// directives (file references rewritten to the stored names); Files maps a
// stored file name to its content (inline blocks and referenced files).
type OVPNConfig struct {
	Lines    []string
	Files    map[string]string
	AuthUser string // from auth-user-pass file or inline block
	AuthPass string
	NeedAuth bool // auth-user-pass present
	Remotes  []string
}

// Directives kept as they are (allowlist, DESIGN.md §10.2).
var ovpnKeep = map[string]bool{
	"client": true, "proto": true, "remote": true, "remote-random": true, "nobind": true, "persist-key": true,
	"remote-cert-tls": true, "verify-x509-name": true, "cipher": true, "data-ciphers": true,
	"data-ciphers-fallback": true, "auth": true, "auth-nocache": true, "tls-client": true, "tls-version-min": true,
	"tls-version-max": true, "tls-cipher": true, "tls-ciphersuites": true, "tls-groups": true, "key-direction": true,
	"compress": true, "comp-lzo": true, "allow-compression": true, "verb": true, "mute": true,
	"mute-replay-warnings": true, "explicit-exit-notify": true, "keepalive": true, "ping": true, "ping-restart": true,
	"ping-timer-rem": true, "connect-retry": true, "connect-retry-max": true, "server-poll-timeout": true,
	"hand-window": true, "reneg-sec": true, "mssfix": true, "tun-mtu": true, "fragment": true, "sndbuf": true,
	"rcvbuf": true, "float": true, "pull": true, "pull-filter": true, "route": true, "route-ipv6": true,
	"dhcp-option": true, "dns": true, "redirect-gateway": true, "ns-cert-type": true, "dev-type": true,
	"tun-ipv6": true, "resolv-retry": false, "remote-cert-ku": true, "remote-cert-eku": true, "tls-timeout": true,
	"block-ipv6": false, "proto-force": true, "connect-timeout": true, "push-peer-info": true, "setenv-safe": false,
	"ifconfig-nowarn": true, "replay-window": true, "mtu-disc": true, "inactive": false, "single-session": true,
	"server-poll": false, "remote-cert-name": false, "x509-username-field": false,
}

// Directives with a file argument (or an inline block of the same name).
var ovpnFiles = map[string]bool{
	"ca": true, "cert": true, "key": true, "tls-auth": true, "tls-crypt": true, "tls-crypt-v2": true,
	"pkcs12": true, "crl-verify": true, "extra-certs": true,
}

// Stripped with a report (vpncell sets its own value, or no effect here).
var ovpnStrip = map[string]string{
	"user":  "vpncell keeps openvpn root-capable for its own hook (the unit restricts capabilities)",
	"group": "see user", "persist-tun": "vpncell sets it", "resolv-retry": "vpncell sets it",
	"auth-retry": "vpncell sets nointeract", "block-outside-dns": "Windows only",
	"ignore-unknown-option": "unknown options are rejected", "setenv": "not needed",
	"route-delay": "vpncell applies routes itself", "dev": "vpncell names the device",
	"setenv-safe": "not needed", "inactive": "would end the tunnel when idle",
	"block-ipv6": "IPv6 fails closed inside the namespace anyway", "route-method": "Windows only",
	"route-metric": "routes are applied inside the namespace", "win-sys": "Windows only",
	"service": "Windows only", "show-net-up": "Windows only", "register-dns": "Windows only",
	"ip-win32": "Windows only", "tap-sleep": "Windows only", "dhcp-renew": "Windows only",
	"dhcp-release": "Windows only", "remote-cert-name": "deprecated", "server-poll": "use server-poll-timeout",
	"x509-username-field": "server only",
}

// Rejected outright, with a reason.
var ovpnReject = map[string]string{
	"up": "runs a program", "down": "runs a program", "route-up": "runs a program", "route-pre-down": "runs a program",
	"ipchange": "runs a program", "client-connect": "runs a program", "client-disconnect": "runs a program",
	"learn-address": "runs a program", "tls-verify": "runs a program", "auth-user-pass-verify": "runs a program",
	"script-security": "allows running programs (vpncell sets its own value)",
	"plugin":          "loads code", "up-delay": "hook timing", "down-pre": "hook timing", "up-restart": "hook timing",
	"dns-updown": "runs a program on the host", "providers": "loads code", "engine": "loads code",
	"pkcs11-providers": "loads code", "pkcs11-id": "needs a token (interactive)", "config": "includes another file",
	"dev-node": "changes the host", "iproute": "runs a program", "ifconfig-noexec": "vpncell sets it",
	"route-noexec": "vpncell sets it", "lladdr": "changes the host", "mktun": "changes the host",
	"rmtun": "changes the host", "management": "vpncell sets it", "management-client": "management",
	"management-hold": "management", "management-query-passwords": "needs interaction",
	"management-signal": "management", "management-forget-disconnect": "management",
	"management-up-down": "management", "management-client-auth": "management",
	"management-external-key": "management", "management-external-cert": "management",
	"daemon": "vpncell runs openvpn under systemd", "log": "logs go to the journal", "log-append": "logs go to the journal",
	"writepid": "writes host files", "status": "writes host files", "cd": "changes directory", "chroot": "host change",
	"tmp-dir": "host change", "http-proxy": "would connect through a host proxy", "socks-proxy": "would connect through a host proxy",
	"static-challenge": "needs interaction", "askpass": "only with a file", "server": "server mode",
	"mode": "server mode", "tls-server": "server mode", "dev-type": "",
	"tun-mtu-extra": "", "dhcp-pre-release": "Windows only", "machine-readable-output": "",
	"ifconfig": "vpncell applies addresses from the server", "ifconfig-ipv6": "vpncell applies addresses from the server",
	"route-gateway": "routes are applied inside the namespace", "redirect-private": "",
	"secret": "static-key mode is not supported", "auth-gen-token": "server only", "tls-export-cert": "writes host files",
	"capath": "reads a host directory", "dh": "server only", "client-cert-not-required": "server only",
	"disable-dco": "vpncell sets it", "persist-remote-ip": "", "persist-local-ip": "", "local": "binds a host address",
	"bind": "binds a host port", "lport": "binds a host port", "port": "use remote host port", "rport": "use remote host port",
	"mark": "would interact with host policy routing (Tailscale)", "bind-dev": "binds a host device",
	"memstats": "writes host files", "echo": "", "parameter": "", "push": "server only",
	"auth-user-pass-optional": "server only", "nice": "", "fast-io": "", "multihome": "server only",
}

var inlineTag = regexp.MustCompile(`^<(/?)([a-z0-9-]+)>$`)

func ovpnTokens(line string) []string {
	var out []string
	var cur strings.Builder
	inQ := byte(0)
	esc := false
	has := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case esc:
			cur.WriteByte(c)
			esc = false
		case c == '\\' && inQ != '\'':
			esc = true
		case inQ != 0:
			if c == inQ {
				inQ = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '"' || c == '\'':
			inQ = c
			has = true
		case c == ' ' || c == '\t':
			if cur.Len() > 0 || has {
				out = append(out, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 || has {
		out = append(out, cur.String())
	}
	return out
}

var safeArg = regexp.MustCompile(`^[A-Za-z0-9_.:/@=+,\-\[\]]*$`)

// ParseOpenVPN sanitizes a .ovpn config. files holds the content of files
// the config references (by the path written in the config); authFile is
// an optional username/password file given at import.
func ParseOpenVPN(text string, files map[string]string, authFile string) (*OVPNConfig, *Report, error) {
	cfg := &OVPNConfig{Files: map[string]string{}}
	rep := &Report{}
	var rej []string
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	ln := 0
	var inline string
	var inlineBody strings.Builder
	keyDir := ""
	for sc.Scan() {
		ln++
		raw := strings.TrimRight(sc.Text(), "\r")
		line := strings.TrimSpace(raw)
		if inline != "" {
			if line == "</"+inline+">" {
				name := inline
				body := inlineBody.String()
				inline = ""
				inlineBody.Reset()
				switch {
				case ovpnFiles[name]:
					if name == "key" && encryptedKey(body) {
						rej = append(rej, fmt.Sprintf("line %d: <key> is encrypted; decrypt it before import (no password prompts)", ln))
						continue
					}
					cfg.Files[name] = body
					cfg.Lines = append(cfg.Lines, name+" "+name+".pem")
					rep.Kept = append(rep.Kept, fmt.Sprintf("<%s> (stored root-only)", name))
				case name == "auth-user-pass":
					u, p, err := parseAuth(body)
					if err != nil {
						rej = append(rej, fmt.Sprintf("line %d: <auth-user-pass>: %v", ln, err))
						continue
					}
					cfg.AuthUser, cfg.AuthPass = u, p
					rep.Kept = append(rep.Kept, "<auth-user-pass> (stored root-only)")
				default:
					rej = append(rej, fmt.Sprintf("line %d: inline block <%s> is not allowed", ln, name))
				}
				continue
			}
			inlineBody.WriteString(raw + "\n")
			continue
		}
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if m := inlineTag.FindStringSubmatch(line); m != nil {
			if m[1] == "/" {
				rej = append(rej, fmt.Sprintf("line %d: unexpected %s", ln, line))
				continue
			}
			inline = m[2]
			continue
		}
		toks := ovpnTokens(line)
		if len(toks) == 0 {
			continue
		}
		dir := strings.ToLower(strings.TrimPrefix(toks[0], "--"))
		args := toks[1:]
		for _, a := range args {
			if !safeArg.MatchString(a) && dir != "verify-x509-name" && dir != "pull-filter" {
				rej = append(rej, fmt.Sprintf("line %d: %s has an argument with unexpected characters", ln, dir))
			}
		}
		switch {
		case dir == "dev":
			if len(args) != 1 || !strings.HasPrefix(args[0], "tun") {
				rej = append(rej, fmt.Sprintf("line %d: only tun devices are supported (dev %s)", ln, strings.Join(args, " ")))
				continue
			}
			rep.Stripped = append(rep.Stripped, fmt.Sprintf("dev (line %d): vpncell names the device", ln))
		case dir == "dev-type":
			if len(args) != 1 || args[0] != "tun" {
				rej = append(rej, fmt.Sprintf("line %d: only dev-type tun is supported", ln))
			}
		case dir == "auth-user-pass":
			cfg.NeedAuth = true
			if len(args) == 0 {
				continue // satisfied by an inline block or --auth-file
			}
			content, ok := files[args[0]]
			if !ok {
				rej = append(rej, fmt.Sprintf("line %d: auth-user-pass file %s was not provided", ln, args[0]))
				continue
			}
			u, p, err := parseAuth(content)
			if err != nil {
				rej = append(rej, fmt.Sprintf("line %d: auth-user-pass file: %v", ln, err))
				continue
			}
			cfg.AuthUser, cfg.AuthPass = u, p
			rep.Kept = append(rep.Kept, "auth-user-pass (file stored root-only)")
		case dir == "auth-retry":
			if len(args) == 1 && args[0] == "interact" {
				rej = append(rej, fmt.Sprintf("line %d: auth-retry interact needs interaction", ln))
				continue
			}
			rep.Stripped = append(rep.Stripped, fmt.Sprintf("auth-retry (line %d): vpncell sets nointeract", ln))
		case dir == "verb":
			if len(args) == 1 && args[0] >= "7" && len(args[0]) == 1 {
				rep.Stripped = append(rep.Stripped, fmt.Sprintf("verb %s (line %d): too verbose (would log secrets)", args[0], ln))
				continue
			}
			cfg.Lines = append(cfg.Lines, line)
			rep.Kept = append(rep.Kept, line)
		case ovpnFiles[dir]:
			if len(args) < 1 {
				rej = append(rej, fmt.Sprintf("line %d: %s needs a file", ln, dir))
				continue
			}
			if args[0] == "[inline]" {
				continue
			}
			content, ok := files[args[0]]
			if !ok {
				rej = append(rej, fmt.Sprintf("line %d: %s file %s was not provided", ln, dir, args[0]))
				continue
			}
			if dir == "key" && encryptedKey(content) {
				rej = append(rej, fmt.Sprintf("line %d: key %s is encrypted; decrypt it before import (no password prompts)", ln, args[0]))
				continue
			}
			cfg.Files[dir] = content
			kept := dir + " " + dir + ".pem"
			if dir == "tls-auth" && len(args) > 1 {
				keyDir = args[1]
				kept += " " + args[1]
			}
			cfg.Lines = append(cfg.Lines, kept)
			rep.Kept = append(rep.Kept, fmt.Sprintf("%s (file stored root-only)", dir))
		case dir == "remote":
			if len(args) < 1 {
				rej = append(rej, fmt.Sprintf("line %d: remote needs a host", ln))
				continue
			}
			host := args[0]
			if _, err := netip.ParseAddr(host); err != nil && !validHost(host) {
				rej = append(rej, fmt.Sprintf("line %d: remote host %q is invalid", ln, host))
				continue
			}
			cfg.Remotes = append(cfg.Remotes, strings.Join(args, " "))
			cfg.Lines = append(cfg.Lines, line)
			rep.Kept = append(rep.Kept, line)
		case ovpnKeep[dir]:
			cfg.Lines = append(cfg.Lines, line)
			rep.Kept = append(rep.Kept, line)
		case ovpnStrip[dir] != "":
			rep.Stripped = append(rep.Stripped, fmt.Sprintf("%s (line %d): %s", dir, ln, ovpnStrip[dir]))
		case ovpnReject[dir] != "" || hasKey(ovpnReject, dir):
			why := ovpnReject[dir]
			if why == "" {
				why = "not allowed"
			}
			rej = append(rej, fmt.Sprintf("line %d: %s is not allowed (%s)", ln, dir, why))
		default:
			rej = append(rej, fmt.Sprintf("line %d: unknown or unsupported directive %q", ln, dir))
		}
	}
	if inline != "" {
		rej = append(rej, fmt.Sprintf("unterminated <%s> block", inline))
	}
	if authFile != "" {
		u, p, err := parseAuth(authFile)
		if err != nil {
			rej = append(rej, "--auth-file: "+err.Error())
		} else {
			cfg.AuthUser, cfg.AuthPass = u, p
			rep.Kept = append(rep.Kept, "--auth-file (stored root-only)")
		}
	}
	if cfg.NeedAuth && cfg.AuthUser == "" {
		rej = append(rej, "auth-user-pass needs a username and password, and vpncell never prompts: add an <auth-user-pass> block, a file next to the config, or --auth-file")
	}
	if len(cfg.Remotes) == 0 {
		rej = append(rej, "no remote")
	}
	if cfg.Files["ca"] == "" && cfg.Files["pkcs12"] == "" {
		rej = append(rej, "no ca (or pkcs12)")
	}
	_ = keyDir
	if len(rej) > 0 {
		return nil, rep, &ImportError{Reasons: rej}
	}
	return cfg, rep, nil
}

func hasKey(m map[string]string, k string) bool { _, ok := m[k]; return ok }

var hostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,252})$`)

func validHost(h string) bool { return hostRE.MatchString(h) }

func encryptedKey(pem string) bool {
	return strings.Contains(pem, "ENCRYPTED") || strings.Contains(pem, "Proc-Type: 4,ENCRYPTED")
}

func parseAuth(s string) (string, string, error) {
	lines := strings.Split(strings.ReplaceAll(s, "\r", ""), "\n")
	var nonEmpty []string
	for _, l := range lines {
		if l != "" {
			nonEmpty = append(nonEmpty, l)
		}
	}
	if len(nonEmpty) < 2 {
		return "", "", fmt.Errorf("needs a username line and a password line")
	}
	return nonEmpty[0], nonEmpty[1], nil
}

// Render writes the sanitized config, referring to stored files in dir.
// vpncell's forced options are appended by the daemon after this.
func (c *OVPNConfig) Render(dir string) string {
	var b strings.Builder
	b.WriteString("# Sanitized by vpncell import. Only allowlisted directives are kept.\n")
	for _, l := range c.Lines {
		f := strings.Fields(l)
		if len(f) >= 2 && ovpnFiles[f[0]] && f[1] == f[0]+".pem" {
			f[1] = fmt.Sprintf("%q", dir+"/"+f[0]+".pem")
			l = strings.Join(f, " ")
		}
		b.WriteString(l + "\n")
	}
	if c.AuthUser != "" {
		fmt.Fprintf(&b, "auth-user-pass %q\n", dir+"/auth.txt")
	}
	return b.String()
}

// FileNames returns the stored file names in a stable order.
func (c *OVPNConfig) FileNames() []string {
	var n []string
	for k := range c.Files {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}
