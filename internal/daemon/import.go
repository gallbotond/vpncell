package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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
	profPath := filepath.Join(brand.ProfilesDir(), req.Name+".toml")
	if _, err := os.Stat(profPath); err == nil {
		if !req.Replace {
			return nil, control.Errorf(control.ErrBadRequest, "profile %q exists; use --replace", req.Name)
		}
		if isDesired(req.Name) || netns.Exists(req.Name) {
			return nil, control.Errorf(control.ErrBusy, "profile %q is up; take it down first", req.Name)
		}
	}
	secretDir := filepath.Join(brand.SecretsDir(), req.Name)
	var (
		body string
		rep  *importer.Report
		err  error
	)
	switch req.Kind {
	case "wireguard":
		body, rep, err = d.importWireGuard(req, secretDir)
	case "openvpn":
		body, rep, err = d.importOpenVPN(req, secretDir)
	default:
		return nil, control.Errorf(control.ErrBadRequest, "unknown config kind %q", req.Kind)
	}
	if err != nil {
		if ie, ok := err.(*importer.ImportError); ok {
			return nil, &control.Error{Code: control.ErrImport, Message: ie.Error()}
		}
		return nil, err
	}
	autostart := req.Autostart
	if autostart == "" {
		autostart = profile.AutostartOnUse
	}
	full := fmt.Sprintf("# Created by `%s import` . Edit as root; run `%s reload` afterwards.\nautostart = %s\n%s\n[access]\nusers  = %s\ngroups = %s\n",
		brand.Name, brand.Name, tomlString(autostart), body, tomlList(nonNil(req.Users)), tomlList(nonNil(req.Groups)))
	if _, err := profile.Parse(req.Name, []byte(full)); err != nil {
		return nil, fmt.Errorf("generated profile is invalid: %w", err)
	}
	if err := os.MkdirAll(brand.ProfilesDir(), 0o755); err != nil {
		return nil, err
	}
	if err := dnsfiles.WriteAtomic(profPath, full, 0o600); err != nil {
		return nil, err
	}
	d.loadProfiles()
	d.log.Info("profile imported", "profile", req.Name, "kind", req.Kind)
	return &control.Response{Type: "ok", Report: &control.ImportReport{
		Profile: req.Name, Kept: rep.Kept, Stripped: rep.Stripped, Warnings: rep.Warnings,
	}, Message: "profile " + req.Name + " imported to " + profPath}, nil
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

func (d *Daemon) importWireGuard(req *control.ImportRequest, dir string) (string, *importer.Report, error) {
	cfg, rep, err := importer.ParseWireGuard(req.Config)
	if err != nil {
		return "", rep, err
	}
	if err := writeSecretDir(dir); err != nil {
		return "", nil, err
	}
	path := filepath.Join(dir, "wg.conf")
	if err := dnsfiles.WriteAtomic(path, cfg.Render(), 0o600); err != nil {
		return "", nil, err
	}
	servers := make([]string, len(cfg.DNSServers))
	for i, s := range cfg.DNSServers {
		servers[i] = s.String()
	}
	body := fmt.Sprintf("backend   = \"wireguard\"\n\n[wireguard]\nconfig = %s\n\n[dns]\nservers = %s\nsearch  = %s\n",
		tomlString(path), tomlList(servers), tomlList(nonNil(cfg.DNSSearch)))
	if len(servers) == 0 {
		rep.Warnings = append(rep.Warnings, "the config sets no DNS servers: name lookups in this profile fail until you add [dns] servers")
	}
	return body, rep, nil
}
