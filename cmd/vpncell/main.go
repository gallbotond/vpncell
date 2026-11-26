// vpncell is the unprivileged command-line client of vpncelld.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/gallbotond/vpncell/internal/client"
	"github.com/gallbotond/vpncell/internal/control"
	"golang.org/x/term"
)

var version = "dev"

const usage = `usage: vpncell <command> [arguments]

Sessions:
  shell <profile>                   start your shell inside the profile
  run [-t|-T] <profile> -- <cmd>... run a command inside the profile

Profiles:
  list                              profiles you may use
  status [--json] [profile]         state, exit IP, traffic, SOCKS port, sessions
  up <profile>                      bring a profile up
  down [--force|--kill] <profile>   take a profile down
  socks <profile>                   print the profile's SOCKS5 proxy URL

Administration (root):
  import [options] <name> <wg.conf|file.ovpn>
  reload                            re-read /etc/vpncell/profiles.d

Firefox:
  firefox-setup --user              install the native messaging manifest for you
  firefox-policy install [--strict] (root) Firefox policy that stops HTTPS-record
                                    lookups outside the proxy (README "Firefox")

Other:
  version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	client.Notice = os.Stderr
	var err error
	code := 0
	switch cmd {
	case "list", "ls":
		err = cmdList(args)
	case "status":
		err = cmdStatus(args)
	case "up":
		err = cmdUpDown("up", args)
	case "down":
		err = cmdUpDown("down", args)
	case "shell":
		code, err = cmdShell(args)
	case "run":
		code, err = cmdRun(args)
	case "socks":
		err = cmdSocks(args)
	case "import":
		err = cmdImport(args)
	case "reload":
		_, err = client.Call(control.Request{Type: "reload"})
	case "firefox-setup":
		err = cmdFirefoxSetup(args)
	case "firefox-policy":
		err = cmdFirefoxPolicy(args)
	case "version", "--version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "vpncell: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if errors.Is(err, errNotConnected) {
		err, code = nil, exitNotConnected
	}
	if err != nil {
		printErr(err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

func printErr(err error) {
	var ce *control.Error
	if errors.As(err, &ce) {
		fmt.Fprintf(os.Stderr, "vpncell: %s\n", ce.Message)
		if len(ce.Sessions) > 0 {
			fmt.Fprintln(os.Stderr, "active sessions:")
			printSessions(os.Stderr, ce.Sessions, "  ")
		}
		return
	}
	fmt.Fprintf(os.Stderr, "vpncell: %v\n", err)
}

func printSessions(w *os.File, ss []control.SessionInfo, indent string) {
	for _, s := range ss {
		name := strconv.FormatUint(uint64(s.UID), 10)
		if u, err := user.LookupId(name); err == nil {
			name = u.Username
		}
		fmt.Fprintf(w, "%s%s  user=%s pid=%d started=%s  %s\n", indent, s.ID, name, s.PID,
			time.Unix(s.Started, 0).Format("15:04:05"), strings.Join(s.Command, " "))
	}
}

func cmdList(args []string) error {
	r, err := client.Call(control.Request{Type: "list"})
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "PROFILE\tBACKEND\tSTATE")
	for _, p := range r.Profiles {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", p.Name, p.Backend, p.State)
	}
	return tw.Flush()
}

func ago(unix int64) string {
	if unix == 0 {
		return "-"
	}
	d := time.Since(time.Unix(unix, 0)).Round(time.Second)
	return d.String() + " ago"
}

func bytesStr(n uint64) string {
	const u = 1024
	if n < u {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(u), 0
	for m := n / u; m >= u; m /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	r, err := client.Call(control.Request{Type: "status", Profile: fs.Arg(0)})
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r.Status)
	}
	for i, s := range r.Status {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("%s (%s, autostart %s)\n", s.Name, s.Backend, s.Autostart)
		fmt.Printf("  state:          %s\n", stateLine(s))
		printReason(os.Stdout, s, "  ")
		if s.Interface != "" {
			fmt.Printf("  interface:      %s %s\n", s.Interface, strings.Join(s.Addresses, " "))
		}
		if s.ExitIP != "" {
			fmt.Printf("  exit IP:        %s\n", s.ExitIP)
		}
		if s.Backend == "wireguard" {
			fmt.Printf("  last handshake: %s\n", ago(s.LastHandshake))
		}
		switch {
		case s.State == "up":
			fmt.Printf("  connected:      %s\n", ago(s.ConnectedAt))
		case s.TryingSince != 0:
			fmt.Printf("  trying since:   %s\n", ago(s.TryingSince))
		}
		fmt.Printf("  traffic:        in %s, out %s\n", bytesStr(s.RxBytes), bytesStr(s.TxBytes))
		printReach(s)
		if s.SocksPort > 0 {
			fmt.Printf("  SOCKS port:     127.0.0.1:%d\n", s.SocksPort)
		}
		fmt.Printf("  sessions:       %d\n", len(s.Sessions))
		printSessions(os.Stdout, s.Sessions, "    ")
	}
	return nil
}

func cmdUpDown(op string, args []string) error {
	fs := flag.NewFlagSet(op, flag.ContinueOnError)
	force := fs.Bool("force", false, "take the tunnel down even with active sessions (they lose network)")
	kill := fs.Bool("kill", false, "end active sessions, then take the profile down")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: vpncell %s <profile>", op)
	}
	if op == "up" && (*force || *kill) {
		return fmt.Errorf("--force and --kill are for down")
	}
	r, err := client.Call(control.Request{Type: op, Profile: fs.Arg(0), Force: *force, Kill: *kill})
	if err != nil {
		return err
	}
	if op == "up" && len(r.Status) == 1 && r.Status[0].Backend == "openvpn" && r.Status[0].State != "up" {
		// The daemon waited 20 s for OpenVPN to connect, without success.
		// (WireGuard has no connection step: it is "connecting" until the
		// first handshake, which needs traffic.)
		s := r.Status[0]
		fmt.Printf("profile %s is not connected yet; vpncell keeps trying in the background\n", s.Name)
		fmt.Printf("  state:          %s\n", stateLine(s))
		if s.Reason == "" && strings.HasPrefix(s.State, "connecting") {
			fmt.Println("  no attempt has failed yet (OpenVPN gives up on a TLS handshake after 60 s)")
		}
		printReason(os.Stdout, s, "  ")
		if s.Log != "" && s.Reason == "" {
			fmt.Printf("  log:            %s\n", s.Log)
		}
		fmt.Printf("  check again:    vpncell status %s\n", s.Name)
		return errNotConnected
	}
	fmt.Println(r.Message)
	return nil
}

// errNotConnected makes `vpncell up` exit with exitNotConnected; the
// details are already printed.
var errNotConnected = errors.New("")

const exitNotConnected = 3

// stateLine is the state with a summary of why it is not up, e.g.
// "connecting (no reply from the server; 3 failed attempts, last 11:08:30)".
func stateLine(s control.ProfileStatus) string {
	if s.Reason == "" || s.State == "up" {
		return s.State
	}
	var parts []string
	if s.Retries > 0 {
		n := fmt.Sprintf("%d failed attempts", s.Retries)
		if s.Retries == 1 {
			n = "1 failed attempt"
		}
		parts = append(parts, n)
	}
	if s.ReasonAt != 0 {
		parts = append(parts, "last "+time.Unix(s.ReasonAt, 0).Format("15:04:05"))
	}
	extra := ""
	if len(parts) > 0 {
		extra = "; " + strings.Join(parts, ", ")
	}
	return fmt.Sprintf("%s (%s%s)", s.State, s.ReasonText, extra)
}

// printReason prints the hint and the log command for a profile that is
// not up.
func printReason(w *os.File, s control.ProfileStatus, indent string) {
	if s.State == "up" || s.Reason == "" {
		return
	}
	if s.Hint != "" {
		for i, l := range wrap(s.Hint, 60) {
			label := "hint:"
			if i > 0 {
				label = ""
			}
			fmt.Fprintf(w, "%s%-16s%s\n", indent, label, l)
		}
	}
	if s.Log != "" {
		fmt.Fprintf(w, "%s%-16s%s\n", indent, "log:", s.Log)
	}
}

func wrap(text string, width int) []string {
	var lines []string
	line := ""
	for _, w := range strings.Fields(text) {
		if line != "" && len(line)+1+len(w) > width {
			lines = append(lines, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += w
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

const escapeWarning = "vpncell: note: commands that hand work to a program already running outside this profile (firefox <url>, code, xdg-open) escape the profile."

// userShell returns $SHELL, or the shell from the passwd entry.
func userShell() string {
	if s := os.Getenv("SHELL"); s != "" {
		return s
	}
	uid := strconv.Itoa(os.Getuid())
	if f, err := os.Open("/etc/passwd"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			parts := strings.Split(sc.Text(), ":")
			if len(parts) >= 7 && parts[2] == uid && parts[6] != "" {
				return parts[6]
			}
		}
	}
	if out, err := runGetent(uid); err == nil {
		parts := strings.Split(strings.TrimSpace(out), ":")
		if len(parts) >= 7 && parts[6] != "" {
			return parts[6]
		}
	}
	return "/bin/sh"
}

func cmdShell(args []string) (int, error) {
	if len(args) != 1 {
		return 2, fmt.Errorf("usage: vpncell shell <profile>")
	}
	sh := userShell()
	tty := term.IsTerminal(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr, escapeWarning)
	return client.Exec(client.ExecOptions{Profile: args[0], Argv: []string{sh, "-i"}, TTY: tty, IsShell: true})
}

func cmdRun(args []string) (int, error) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	forceTTY := fs.Bool("t", false, "always use a terminal")
	noTTY := fs.Bool("T", false, "never use a terminal")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	rest := fs.Args()
	if len(rest) < 1 {
		return 2, fmt.Errorf("usage: vpncell run [-t|-T] <profile> -- <command> [args...]")
	}
	prof := rest[0]
	rest = rest[1:]
	if len(rest) > 0 && rest[0] == "--" {
		rest = rest[1:]
	}
	if len(rest) == 0 {
		return 2, fmt.Errorf("usage: vpncell run [-t|-T] <profile> -- <command> [args...]")
	}
	tty := term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
	if *forceTTY {
		tty = true
	}
	if *noTTY {
		tty = false
	}
	return client.Exec(client.ExecOptions{Profile: prof, Argv: rest, TTY: tty})
}

func cmdSocks(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: vpncell socks <profile>")
	}
	r, err := client.Call(control.Request{Type: "socks", Profile: args[0]})
	if err != nil {
		return err
	}
	s := r.Socks
	fmt.Printf("socks5h://%s:%s@%s:%d\n", s.Username, s.Password, s.Host, s.Port)
	return nil
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func cmdImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	var users, groups multi
	fs.Var(&users, "user", "user allowed to use the profile (repeatable; default: $SUDO_USER)")
	fs.Var(&groups, "group", "group allowed to use the profile (repeatable)")
	authFile := fs.String("auth-file", "", "OpenVPN username/password file (two lines)")
	autostart := fs.String("autostart", "", "boot, on-use (default) or manual")
	replace := fs.Bool("replace", false, "replace an existing profile (it must be down)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: sudo vpncell import [--user u] [--group g] [--auth-file f] [--autostart a] [--replace] <name> <wg.conf|file.ovpn>")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("import needs root: sudo vpncell import ...")
	}
	name, path := fs.Arg(0), fs.Arg(1)
	if len(users) == 0 && len(groups) == 0 {
		if su := os.Getenv("SUDO_USER"); su != "" && su != "root" {
			users = append(users, su)
		}
	}
	req, err := buildImport(name, path, *authFile)
	if err != nil {
		return err
	}
	req.Users, req.Groups, req.Autostart, req.Replace = users, groups, *autostart, *replace
	r, err := client.Call(control.Request{Type: "import", Import: req})
	if err != nil {
		return err
	}
	rep := r.Report
	fmt.Println(r.Message)
	fmt.Println("kept:")
	for _, k := range rep.Kept {
		fmt.Println("  " + k)
	}
	if len(rep.Stripped) > 0 {
		fmt.Println("stripped:")
		for _, k := range rep.Stripped {
			fmt.Println("  " + k)
		}
	} else {
		fmt.Println("stripped: nothing")
	}
	for _, w := range rep.Warnings {
		fmt.Println("warning: " + w)
	}
	if len(users) > 0 || len(groups) > 0 {
		fmt.Printf("allowed users: %s; groups: %s\n", strings.Join(users, ","), strings.Join(groups, ","))
	} else {
		fmt.Println("warning: no users or groups are allowed yet; edit [access] in the profile, then run: sudo vpncell reload")
	}
	return nil
}

func detectKind(path, text string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".ovpn":
		return "openvpn"
	case ".conf":
		if strings.Contains(text, "[Interface]") {
			return "wireguard"
		}
		return "openvpn"
	}
	if strings.Contains(text, "[Interface]") {
		return "wireguard"
	}
	return "openvpn"
}

// printReach prints what the profile reaches and its DNS (issue #15).
func printReach(s control.ProfileStatus) {
	switch s.RoutesSource {
	case "allowed-ips":
		fmt.Printf("  reaches:        %s\n", s.Reaches)
	case "pushed":
		rg := "no redirect-gateway"
		if s.RedirectGateway {
			rg = "redirect-gateway"
		}
		fmt.Printf("  server routes:  %s (pushed; %s)\n", s.Reaches, rg)
	}
	if s.SplitTunnel && s.State != "down" {
		fmt.Println("                  other addresses fail: vpncell never falls back to your normal connection")
	}
	switch {
	case s.State == "down":
		if len(s.DNS) > 0 {
			fmt.Printf("  DNS:            %s\n", strings.Join(s.DNS, " "))
		}
	case s.NoDNS:
		fmt.Println("  DNS:            none (hostnames fail; set [dns] servers)")
	default:
		line := strings.Join(s.DNS, " ")
		if len(s.DNSUnreachable) > 0 {
			line += " (not reachable through the tunnel: " + strings.Join(s.DNSUnreachable, " ") + ")"
		}
		fmt.Printf("  DNS:            %s\n", line)
	}
}
