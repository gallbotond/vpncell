package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/gallbotond/vpncell/internal/backend"
	"github.com/gallbotond/vpncell/internal/brand"
	"github.com/gallbotond/vpncell/internal/control"
	"github.com/gallbotond/vpncell/internal/netns"
	"github.com/gallbotond/vpncell/internal/profile"
	"github.com/gallbotond/vpncell/internal/session"
)

// per-uid exec rate limit
type rateLimiter struct {
	mu   sync.Mutex
	hits map[uint32][]time.Time
}

var execLimiter = &rateLimiter{hits: map[uint32][]time.Time{}}

const (
	execBurst  = 200
	execWindow = 10 * time.Second
)

func (r *rateLimiter) allow(uid uint32) bool {
	if uid == 0 {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	h := r.hits[uid][:0]
	for _, t := range r.hits[uid] {
		if now.Sub(t) < execWindow {
			h = append(h, t)
		}
	}
	if len(h) >= execBurst {
		r.hits[uid] = h
		return false
	}
	r.hits[uid] = append(h, now)
	return true
}

// ensureUp brings a profile up for a session or the extension when its
// autostart allows it.
func (d *Daemon) ensureUp(p *profile.Profile, rt *rtProfile) error {
	if isDesired(p.Name) && netns.Exists(p.Name) {
		return nil
	}
	if p.Autostart == profile.AutostartManual {
		return control.Errorf(control.ErrProfileDown, "profile %q is down; run: %s up %s", p.Name, brand.Name, p.Name)
	}
	if err := d.up(p, rt); err != nil {
		return control.Errorf(control.ErrProfileDown, "profile %q could not be brought up: %v", p.Name, err)
	}
	return nil
}

func (d *Daemon) handleExec(c *caller, conn *control.Conn, req *control.Request, files []*os.File) (*control.Response, error) {
	defer control.CloseFiles(files)
	x := req.Exec
	if x == nil || len(x.Argv) == 0 || len(x.Argv) > 4096 || len(x.Env) > 4096 {
		return nil, control.Errorf(control.ErrBadRequest, "bad exec request")
	}
	if !x.TTY && len(files) != 3 {
		return nil, control.Errorf(control.ErrBadRequest, "non-TTY exec needs stdin, stdout and stderr descriptors")
	}
	p, rt, err := d.allowedProfile(c, req.Profile)
	if err != nil {
		return nil, err
	}
	if !execLimiter.allow(c.UID) {
		return nil, control.Errorf(control.ErrDenied, "too many sessions started; slow down")
	}
	if err := d.ensureUp(p, rt); err != nil {
		return nil, err
	}
	id := randomHex(6)
	spec := session.Spec{
		ID: id, Profile: p.Name, NetnsPath: brand.NetnsPath(p.Name),
		UID: c.UID, GID: c.GID, Groups: c.Groups,
		Argv: x.Argv, Env: x.Env, Cwd: x.Cwd, TTY: x.TTY, Rows: x.Rows, Cols: x.Cols, Umask: x.Umask,
		ResolveDir: filepath.Join(brand.ProfileRunDir(p.Name), "resolve"),
		Nsswitch:   filepath.Join(brand.ProfileRunDir(p.Name), "nsswitch.conf"),
	}
	specData, _ := json.Marshal(spec)

	connFile, err := conn.Unix().File()
	if err != nil {
		return nil, err
	}
	defer connFile.Close()
	specR, specW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer specR.Close()
	extra := []*os.File{connFile, specR}
	if !x.TTY {
		extra = append(extra, files...)
	}
	cmd := exec.Command("/proc/self/exe", "session-helper")
	cmd.Args[0] = brand.Daemon
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	cmd.ExtraFiles = extra
	cmd.Dir = "/"
	if err := cmd.Start(); err != nil {
		specW.Close()
		return nil, fmt.Errorf("start session helper: %w", err)
	}
	specR.Close()
	rec := &sessionRec{SessionInfo: control.SessionInfo{
		ID: id, Profile: p.Name, UID: c.UID, PID: cmd.Process.Pid, Command: x.Argv, Started: time.Now().Unix(),
	}, HelperPID: cmd.Process.Pid}
	scope := scopeName(p.Name, c.UID, id)
	ctx, cancel := context.WithTimeout(d.ctx, 15*time.Second)
	err = d.sessions.moveToScope(ctx, scope, fmt.Sprintf("%s session %s (profile %s, uid %d)", brand.Name, id, p.Name, c.UID), cmd.Process.Pid)
	cancel()
	if err != nil {
		d.log.Warn("session scope unavailable; the session will not survive a daemon restart", "err", err)
	} else {
		rec.Scope = scope
	}
	// Re-check: the profile may have been taken down meanwhile. The helper
	// then fails to open the namespace, which is fail closed.
	if _, err := specW.Write(specData); err != nil {
		specW.Close()
		cmd.Process.Kill()
		cmd.Wait()
		return nil, fmt.Errorf("session helper: %w", err)
	}
	specW.Close()
	d.sessions.add(rec)
	d.log.Info("session started", "session", id, "profile", p.Name, "uid", c.UID, "tty", x.TTY)
	go func() {
		cmd.Wait()
		d.sessions.markExited(id)
	}()
	if rt.getState() == backend.StateDown {
		d.log.Warn("session started while profile is down", "profile", p.Name)
	}
	return nil, errHandedOff
}
