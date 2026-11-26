package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gallbotond/vpncell/internal/brand"
	"github.com/gallbotond/vpncell/internal/control"
	"github.com/gallbotond/vpncell/internal/netns"
	"github.com/gallbotond/vpncell/internal/profile"
)

// handleRemove deletes a profile (issue #17): it takes the profile down,
// deletes profiles.d/NAME.toml and secrets/NAME/, and frees the profile's
// interface index, SOCKS port and runtime state. Like `down`, it refuses
// while the profile is in use unless force (sessions lose network and keep
// running) or kill (sessions end) is given.
func (d *Daemon) handleRemove(c *caller, name string, force, kill bool) (*control.Response, error) {
	if !c.admin {
		return nil, control.Errorf(control.ErrDenied, "remove is for root only (use sudo)")
	}
	if !profile.ValidName(name) {
		return nil, control.Errorf(control.ErrBadRequest, "invalid profile name %q", name)
	}
	d.loadMu.Lock()
	defer d.loadMu.Unlock()

	profPath := profilePath(name)
	secretDir := filepath.Join(brand.SecretsDir(), name)
	p, rt := d.getProfile(name)
	_, ferr := os.Lstat(profPath)
	_, serr := os.Lstat(secretDir)
	if p == nil && ferr != nil && serr != nil {
		return nil, control.Errorf(control.ErrNotFound, "no profile %q", name)
	}

	var done []string
	if p != nil {
		rt.op.Lock()
		defer rt.op.Unlock()
		live := d.sessions.list(name)
		if d.inUse(name) {
			if !force && !kill {
				msg := fmt.Sprintf("profile %q is up; take it down first, or use --force", name)
				if len(live) > 0 {
					msg = fmt.Sprintf("profile %q has %d active session(s); use --force to drop their network or --kill to end them", name, len(live))
				}
				return nil, &control.Error{Code: control.ErrBusy, Message: msg, Sessions: d.redactSessions(c, live)}
			}
			if err := d.downLocked(p, rt, force, kill); err != nil {
				return nil, control.Errorf(control.ErrInternal, "take down %s: %v (nothing was deleted)", name, err)
			}
			done = append(done, "took the profile down")
			switch {
			case kill && len(live) > 0:
				done = append(done, fmt.Sprintf("ended %d session(s)", len(live)))
			case len(live) > 0:
				done = append(done, fmt.Sprintf("%d session(s) keep running without network until they exit", len(live)))
			}
		}
	}

	var kept []string
	if p != nil {
		for _, f := range []string{p.WireGuard.Config, p.OpenVPN.Config, p.OpenVPN.AuthFile} {
			if f != "" && !within(secretDir, f) {
				kept = append(kept, f)
			}
		}
	}
	if ferr == nil {
		if err := os.Remove(profPath); err != nil {
			return nil, control.Errorf(control.ErrInternal, "delete %s: %v", profPath, err)
		}
		done = append(done, "deleted "+profPath)
	}
	if serr == nil {
		if err := os.RemoveAll(secretDir); err != nil {
			return nil, control.Errorf(control.ErrInternal, "delete %s: %v", secretDir, err)
		}
		done = append(done, "deleted "+secretDir+"/")
	}
	if p != nil {
		d.mu.Lock()
		delete(d.profiles, name)
		d.mu.Unlock()
		rt.removed = true
	}
	d.loadProfilesLocked()
	d.log.Info("profile removed", "profile", name, "kept", strings.Join(kept, ","))

	msg := "profile " + name + " removed"
	for _, l := range done {
		msg += "\n  " + l
	}
	for _, f := range kept {
		msg += "\n  kept " + f + " (outside " + secretDir + "; delete it yourself if no longer needed)"
	}
	if netns.Exists(name) {
		msg += "\n  its namespace is deleted when the last session exits"
	}
	return &control.Response{Type: "ok", Message: msg}, nil
}

// within reports whether path is inside dir.
func within(dir, path string) bool {
	rel, err := filepath.Rel(dir, filepath.Clean(path))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}
