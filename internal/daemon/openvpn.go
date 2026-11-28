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
	"github.com/gallbotond/vpncell/internal/netns"
	"github.com/gallbotond/vpncell/internal/profile"
	"github.com/vishvananda/netlink"
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

// importOpenVPN writes the sanitized config and its files into stage; the
// config refers to them under dir, where they will be after the swap.
func (d *Daemon) importOpenVPN(req *control.ImportRequest, stage, dir string) (imported, *importer.Report, error) {
	cfg, rep, err := importer.ParseOpenVPN(req.Config, req.Files, req.AuthFile)
	if err != nil {
		return imported{}, rep, err
	}
	if err := writeSecretDir(stage); err != nil {
		return imported{}, nil, err
	}
	for _, name := range cfg.FileNames() {
		if err := dnsfiles.WriteAtomic(filepath.Join(stage, name+".pem"), cfg.Files[name], 0o600); err != nil {
			return imported{}, nil, err
		}
	}
	if cfg.AuthUser != "" {
		if err := dnsfiles.WriteAtomic(filepath.Join(stage, "auth.txt"), cfg.AuthUser+"\n"+cfg.AuthPass+"\n", 0o600); err != nil {
			return imported{}, nil, err
		}
	}
	if err := dnsfiles.WriteAtomic(filepath.Join(stage, "client.ovpn"), cfg.Render(dir), 0o600); err != nil {
		return imported{}, nil, err
	}
	usePushed := true
	rep.Warnings = append(rep.Warnings, "DNS servers come from the server's pushes (dns.use_pushed = true); add [dns] servers if it pushes none")
	rep.Warnings = append(rep.Warnings, cfg.ReachWarnings()...)
	return imported{
		backend: profile.BackendOpenVPN,
		section: fmt.Sprintf("[openvpn]\nconfig = %s\n", tomlString(filepath.Join(dir, "client.ovpn"))),
		dns:     dnsSettings{Servers: []string{}, Search: []string{}, UsePushed: &usePushed},
	}, rep, nil
}

// writeProfileDNS is used by the OpenVPN hook (a separate process) to
// rewrite the resolver files after a (re)connect, so they are right even
// while the daemon is restarting.
func WriteProfileDNS(p *profile.Profile, pushed []netip.Addr, search []string) error {
	d := &Daemon{}
	return d.writeDNSFiles(p, pushed, search)
}

// stopUnknownTunnel removes the tunnel of a namespace whose profile no
// longer exists (its file was deleted while the daemon was stopped; issue
// #17): it stops the profile's OpenVPN unit and deletes every link in the
// namespace but lo. Sessions in the namespace keep running without network.
func (d *Daemon) stopUnknownTunnel(name string) {
	if c, err := sdbus.NewSystemConnectionContext(d.ctx); err == nil {
		ctx, cancel := context.WithTimeout(d.ctx, 30*time.Second)
		ch := make(chan string, 1)
		if _, err := c.StopUnitContext(ctx, openvpn.UnitName(name), "replace", ch); err == nil {
			select {
			case <-ch:
			case <-ctx.Done():
			}
		}
		cancel()
		c.Close()
	}
	netns.Do(name, func() error {
		links, _ := netlink.LinkList()
		for _, l := range links {
			if l.Attrs().Name != "lo" {
				netlink.LinkDel(l)
			}
		}
		return nil
	})
	os.Remove(openvpn.PushedPath(name))
}
