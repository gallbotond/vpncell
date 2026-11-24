package daemon

import (
	"github.com/gallbotond/vpncell/internal/control"
	"github.com/gallbotond/vpncell/internal/importer"
)

// Parts that later build steps fill in.

func (d *Daemon) registerOpenVPN() {}

func (d *Daemon) cleanupOpenVPNUnits() {}

func (d *Daemon) importOpenVPN(req *control.ImportRequest, dir string) (string, *importer.Report, error) {
	return "", nil, control.Errorf(control.ErrUnsupported, "OpenVPN import is not available yet")
}
