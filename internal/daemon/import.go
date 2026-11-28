package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/gallbotond/vpncell/internal/brand"
	"github.com/gallbotond/vpncell/internal/control"
	"github.com/gallbotond/vpncell/internal/dnsfiles"
	"github.com/gallbotond/vpncell/internal/importer"
	"github.com/gallbotond/vpncell/internal/netns"
	"github.com/gallbotond/vpncell/internal/profile"
)

func tomlString(s string) string { return strconv.Quote(s) }

func tomlList(xs []string) string {
	q := make([]string, len(xs))
	for i, x := range xs {
		q[i] = tomlString(x)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

// importMu serializes imports: they share the staging folders.
var importMu sync.Mutex

// dnsSettings is a profile's [dns] table.
type dnsSettings struct {
	Servers   []string
	Search    []string
	UsePushed *bool
}

func (s dnsSettings) render() string {
	t := fmt.Sprintf("[dns]\nservers = %s\nsearch  = %s\n", tomlList(nonNil(s.Servers)), tomlList(nonNil(s.Search)))
	if s.UsePushed != nil {
		t += fmt.Sprintf("use_pushed = %t\n", *s.UsePushed)
	}
	return t
}

func (s dnsSettings) equal(o dnsSettings) bool {
	return slices.Equal(s.Servers, o.Servers) && slices.Equal(s.Search, o.Search) &&
		(s.UsePushed == nil) == (o.UsePushed == nil) && (s.UsePushed == nil || *s.UsePushed == *o.UsePushed)
}

func (s dnsSettings) String() string {
	t := fmt.Sprintf("servers %s, search %s", tomlList(nonNil(s.Servers)), tomlList(nonNil(s.Search)))
	if s.UsePushed != nil {
		t += fmt.Sprintf(", use_pushed %t", *s.UsePushed)
	}
	return t
}

// imported is what a backend importer produced from a config.
type imported struct {
	backend string      // profile.BackendWireGuard or profile.BackendOpenVPN
	section string      // the backend's table, e.g. "[wireguard]\nconfig = ...\n"
	dns     dnsSettings // [dns] for a new profile
}

// profileText builds the profile file for an import. old is the profile
// being replaced (nil for a new one): its settings are kept unless the
// request has a flag for them (issue #16). kept names what was kept;
// warnings are for the report.
func profileText(req *control.ImportRequest, im imported, old *profile.Profile) (text string, users, groups, kept, warnings []string) {
	autostart := req.Autostart
	switch {
	case autostart != "":
	case old != nil:
		autostart = old.Autostart
		if autostart != profile.AutostartOnUse {
			kept = append(kept, "autostart = "+tomlString(autostart))
		}
	default:
		autostart = profile.AutostartOnUse
	}
	users, groups = nonNil(req.Users), nonNil(req.Groups)
	switch {
	case len(users) > 0 || len(groups) > 0:
	case old != nil:
		users, groups = nonNil(old.Access.Users), nonNil(old.Access.Groups)
		kept = append(kept, "[access]")
	case req.DefaultUser != "":
		users = []string{req.DefaultUser}
	}
	dns := im.dns
	if old != nil {
		od := dnsSettings{Servers: old.DNS.Servers, Search: old.DNS.Search, UsePushed: old.DNS.UsePushed}
		if old.Backend == im.backend {
			if !od.equal(im.dns) {
				kept = append(kept, "[dns]")
				warnings = append(warnings, fmt.Sprintf("kept [dns] from the old profile (%s); the new config alone gives %s. Edit [dns] if the new one is right", od, im.dns))
			}
			dns = od
		} else if !od.equal(dnsSettings{}) {
			warnings = append(warnings, fmt.Sprintf("the backend changed from %s to %s: [dns] comes from the new config, the old one (%s) was not kept", old.Backend, im.backend, od))
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Created by `%s import` . Edit as root; run `%s reload` afterwards.\n", brand.Name, brand.Name)
	fmt.Fprintf(&b, "autostart = %s\nbackend   = %s\n\n%s\n%s\n", tomlString(autostart), tomlString(im.backend), im.section, dns.render())
	fmt.Fprintf(&b, "[access]\nusers  = %s\ngroups = %s\n", tomlList(users), tomlList(groups))
	if old != nil {
		if len(old.Routing.Routes) > 0 {
			fmt.Fprintf(&b, "\n[routing]\nroutes = %s\n", tomlList(old.Routing.Routes))
			kept = append(kept, "[routing]")
		}
		if old.Socks.Port != 0 {
			fmt.Fprintf(&b, "\n[socks]\nport = %d\n", old.Socks.Port)
			kept = append(kept, "[socks]")
		}
		if old.Status.ExitIPURL != "" {
			fmt.Fprintf(&b, "\n[status]\nexit_ip_url = %s\n", tomlString(old.Status.ExitIPURL))
			kept = append(kept, "[status]")
		}
		if old.Security.Nftables != nil {
			fmt.Fprintf(&b, "\n[security]\nnftables = %t\n", *old.Security.Nftables)
			kept = append(kept, "[security]")
		}
	}
	return b.String(), users, groups, kept, warnings
}

func (d *Daemon) handleImport(req *control.ImportRequest) (*control.Response, error) {
	if req == nil {
		return nil, control.Errorf(control.ErrBadRequest, "missing import data")
	}
	if !profile.ValidName(req.Name) {
		return nil, control.Errorf(control.ErrBadRequest, "invalid profile name %q: use lowercase letters, digits and '-', starting with a letter, at most 31 characters", req.Name)
	}
	switch req.Autostart {
	case "", profile.AutostartBoot, profile.AutostartOnUse, profile.AutostartManual:
	default:
		return nil, control.Errorf(control.ErrBadRequest, "bad autostart %q", req.Autostart)
	}
	for _, u := range append(append([]string{}, req.Users...), req.Groups...) {
		if u == "" || strings.ContainsAny(u, "\"\\\n\r\t ") {
			return nil, control.Errorf(control.ErrBadRequest, "bad user or group name %q", u)
		}
	}
	if strings.ContainsAny(req.DefaultUser, "\"\\\n\r\t ") {
		return nil, control.Errorf(control.ErrBadRequest, "bad user name %q", req.DefaultUser)
	}
	importMu.Lock()
	defer importMu.Unlock()
	profPath := filepath.Join(brand.ProfilesDir(), req.Name+".toml")
	var (
		old    *profile.Profile
		oldErr error
	)
	if data, err := os.ReadFile(profPath); err == nil {
		if !req.Replace {
			return nil, control.Errorf(control.ErrBadRequest, "profile %q exists; use --replace", req.Name)
		}
		if isDesired(req.Name) || netns.Exists(req.Name) {
			return nil, control.Errorf(control.ErrBusy, "profile %q is up; take it down first", req.Name)
		}
		old, oldErr = profile.Parse(req.Name, data)
	}
	// The new secrets go to a staging folder first. The profile's folder
	// is swapped in only once everything is written and the profile file
	// is valid, so a failed import leaves the old profile as it was.
	secretDir := filepath.Join(brand.SecretsDir(), req.Name)
	stage := filepath.Join(brand.SecretsDir(), "."+req.Name+".new")
	prev := filepath.Join(brand.SecretsDir(), "."+req.Name+".old")
	os.RemoveAll(stage) // left over from a crash
	defer os.RemoveAll(stage)
	var (
		im  imported
		rep *importer.Report
		err error
	)
	switch req.Kind {
	case "wireguard":
		im, rep, err = d.importWireGuard(req, stage, secretDir)
	case "openvpn":
		im, rep, err = d.importOpenVPN(req, stage, secretDir)
	default:
		return nil, control.Errorf(control.ErrBadRequest, "unknown config kind %q", req.Kind)
	}
	if err != nil {
		if ie, ok := err.(*importer.ImportError); ok {
			return nil, &control.Error{Code: control.ErrImport, Message: ie.Error()}
		}
		return nil, err
	}
	full, users, groups, kept, warnings := profileText(req, im, old)
	if oldErr != nil {
		warnings = append(warnings, fmt.Sprintf("the old profile file did not load, so none of its settings were kept: %v", oldErr))
	}
	if _, err := profile.Parse(req.Name, []byte(full)); err != nil {
		return nil, fmt.Errorf("generated profile is invalid: %w", err)
	}
	if err := os.MkdirAll(brand.ProfilesDir(), 0o755); err != nil {
		return nil, err
	}
	removed, err := swapSecrets(secretDir, stage, prev, func() error {
		return writeProfileFile(profPath, full)
	})
	if err != nil {
		return nil, err
	}
	d.loadProfiles()
	d.log.Info("profile imported", "profile", req.Name, "kind", req.Kind, "replace", old != nil || oldErr != nil)
	return &control.Response{Type: "ok", Report: &control.ImportReport{
		Profile: req.Name, Kept: rep.Kept, Stripped: rep.Stripped, Warnings: append(rep.Warnings, warnings...),
		KeptSettings: kept, RemovedFiles: removed, Users: users, Groups: groups,
	}, Message: "profile " + req.Name + " imported to " + profPath}, nil
}

// writeProfileFile writes the profile file; a variable so that tests can
// make it fail.
var writeProfileFile = func(path, content string) error {
	return dnsfiles.WriteAtomic(path, content, 0o600)
}

// swapSecrets replaces dir with stage and then runs commit (which writes the
// profile file). If commit fails, the old dir is put back. It returns the
// names of files the old dir had and the new one does not.
func swapSecrets(dir, stage, prev string, commit func() error) ([]string, error) {
	os.RemoveAll(prev)
	hadOld := false
	if _, err := os.Lstat(dir); err == nil {
		if err := os.Rename(dir, prev); err != nil {
			return nil, err
		}
		hadOld = true
	}
	restore := func() {
		os.RemoveAll(dir)
		if hadOld {
			os.Rename(prev, dir)
		}
	}
	if err := os.Rename(stage, dir); err != nil {
		restore()
		return nil, err
	}
	if err := commit(); err != nil {
		restore()
		return nil, err
	}
	var removed []string
	if hadOld {
		olds, _ := os.ReadDir(prev)
		for _, e := range olds {
			if _, err := os.Lstat(filepath.Join(dir, e.Name())); os.IsNotExist(err) {
				removed = append(removed, e.Name())
			}
		}
		os.RemoveAll(prev)
	}
	return removed, nil
}

func nonNil(x []string) []string {
	if x == nil {
		return []string{}
	}
	return x
}

func writeSecretDir(dir string) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	os.Chmod(filepath.Dir(dir), 0o700)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}

// importWireGuard writes the sanitized config into stage; the profile refers
// to it under dir, where it will be after the swap.
func (d *Daemon) importWireGuard(req *control.ImportRequest, stage, dir string) (imported, *importer.Report, error) {
	cfg, rep, err := importer.ParseWireGuard(req.Config)
	if err != nil {
		return imported{}, rep, err
	}
	if err := writeSecretDir(stage); err != nil {
		return imported{}, nil, err
	}
	if err := dnsfiles.WriteAtomic(filepath.Join(stage, "wg.conf"), cfg.Render(), 0o600); err != nil {
		return imported{}, nil, err
	}
	servers := make([]string, len(cfg.DNSServers))
	for i, s := range cfg.DNSServers {
		servers[i] = s.String()
	}
	rep.Warnings = append(rep.Warnings, cfg.ReachWarnings()...)
	return imported{
		backend: profile.BackendWireGuard,
		section: fmt.Sprintf("[wireguard]\nconfig = %s\n", tomlString(filepath.Join(dir, "wg.conf"))),
		dns:     dnsSettings{Servers: servers, Search: nonNil(cfg.DNSSearch)},
	}, rep, nil
}
