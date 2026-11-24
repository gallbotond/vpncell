package daemon

import (
	"github.com/gallbotond/vpncell/internal/control"
	"github.com/gallbotond/vpncell/internal/importer"
	"github.com/gallbotond/vpncell/internal/profile"
)

// Parts that later build steps fill in.

func (d *Daemon) registerExtensions() {}

func (d *Daemon) socksPort(p *profile.Profile) int { return 0 }

func (d *Daemon) handleSocks(c *caller, name string) (*control.Response, error) {
	return nil, control.Errorf(control.ErrUnsupported, "SOCKS is not available yet")
}

func (d *Daemon) cleanupOpenVPNUnits() {}

func (d *Daemon) importOpenVPN(req *control.ImportRequest, dir string) (string, *importer.Report, error) {
	return "", nil, control.Errorf(control.ErrUnsupported, "OpenVPN import is not available yet")
}
