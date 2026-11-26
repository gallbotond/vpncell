package daemon

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	sdbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/gallbotond/vpncell/internal/backend/openvpn"
	"github.com/gallbotond/vpncell/internal/brand"
	"github.com/gallbotond/vpncell/internal/control"
	"github.com/gallbotond/vpncell/internal/dnsfiles"
	"github.com/gallbotond/vpncell/internal/importer"
	"github.com/gallbotond/vpncell/internal/profile"
)

// hookBinary is the vpncelld path openvpn runs as its hook: the packaged
// binary if present, else this executable.
func hookBinary() string {
	if exe, err := os.Readlink("/proc/self/exe"); err == nil {
		exe = strings.TrimSuffix(exe, " (deleted)")
		if _, err := os.Stat(exe); err == nil {
			return exe
		}
	}
	return brand.DaemonBinary
}

func (d *Daemon) registerOpenVPN() {
	d.backends[profile.BackendOpenVPN] = openvpn.New(d.log, hookBinary())
}

// cleanupOpenVPNUnits stops vpncell-openvpn@ units left from before a crash
// or reboot (first start since boot only).
func (d *Daemon) cleanupOpenVPNUnits() {
	c, err := sdbus.NewSystemConnectionContext(context.Background())
	if err != nil {
		return
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	units, err := c.ListUnitsByPatternsContext(ctx, nil, []string{brand.OpenVPNUnit + "*.service"})
	if err != nil {
		return
	}
	for _, u := range units {
		if u.ActiveState == "inactive" {
			continue
		}
		d.log.Info("stopping leftover OpenVPN unit", "unit", u.Name)
		ch := make(chan string, 1)
		if _, err := c.StopUnitContext(ctx, u.Name, "replace", ch); err == nil {
			select {
			case <-ch:
			case <-ctx.Done():
			}
		}
	}
}

func (d *Daemon) importOpenVPN(req *control.ImportRequest, dir string) (string, *importer.Report, error) {
	cfg, rep, err := importer.ParseOpenVPN(req.Config, req.Files, req.AuthFile)
	if err != nil {
		return "", rep, err
	}
	if err := writeSecretDir(dir); err != nil {
		return "", nil, err
	}
	for _, name := range cfg.FileNames() {
		if err := dnsfiles.WriteAtomic(filepath.Join(dir, name+".pem"), cfg.Files[name], 0o600); err != nil {
			return "", nil, err
		}
	}
	if cfg.AuthUser != "" {
		if err := dnsfiles.WriteAtomic(filepath.Join(dir, "auth.txt"), cfg.AuthUser+"\n"+cfg.AuthPass+"\n", 0o600); err != nil {
			return "", nil, err
		}
	}
	path := filepath.Join(dir, "client.ovpn")
	if err := dnsfiles.WriteAtomic(path, cfg.Render(dir), 0o600); err != nil {
		return "", nil, err
	}
	body := fmt.Sprintf("backend   = \"openvpn\"\n\n[openvpn]\nconfig = %s\n\n[dns]\nservers = []\nsearch  = []\nuse_pushed = true\n", tomlString(path))
	rep.Warnings = append(rep.Warnings, "DNS servers come from the server's pushes (dns.use_pushed = true); add [dns] servers if it pushes none")
	rep.Warnings = append(rep.Warnings, cfg.ReachWarnings()...)
	return body, rep, nil
}

// writeProfileDNS is used by the OpenVPN hook (a separate process) to
// rewrite the resolver files after a (re)connect, so they are right even
// while the daemon is restarting.
func WriteProfileDNS(p *profile.Profile, pushed []netip.Addr, search []string) error {
	d := &Daemon{}
	return d.writeDNSFiles(p, pushed, search)
}
