package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	sdbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/gallbotond/vpncell/internal/brand"
	"github.com/gallbotond/vpncell/internal/control"
	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

type sessionRec struct {
	control.SessionInfo
	HelperPID int  `json:"helper_pid"`
	exited    bool // helper reaped by this daemon
}

type sessionTable struct {
	mu   sync.Mutex
	m    map[string]*sessionRec
	sdMu sync.Mutex
	sd   *sdbus.Conn
}

func newSessionTable() *sessionTable { return &sessionTable{m: map[string]*sessionRec{}} }

func sessionsDir() string { return filepath.Join(brand.RunDir, "sessions") }

func (t *sessionTable) systemd(ctx context.Context) *sdbus.Conn {
	t.sdMu.Lock()
	defer t.sdMu.Unlock()
	if t.sd != nil && t.sd.Connected() {
		return t.sd
	}
	// The connection must not be tied to a request context: go-systemd
	// closes it when that context ends.
	c, err := sdbus.NewSystemConnectionContext(context.Background())
	if err != nil {
		return nil
	}
	t.sd = c
	return c
}

func scopeName(profile string, uid uint32, id string) string {
	return fmt.Sprintf("%s%s-%d-%s.scope", brand.ScopePrefix, profile, uid, id)
}

// moveToScope puts the helper into a transient systemd scope, so it outlives
// daemon restarts and can be stopped as a unit.
func (t *sessionTable) moveToScope(ctx context.Context, name, desc string, pid int) error {
	c := t.systemd(ctx)
	if c == nil {
		return fmt.Errorf("systemd is not reachable over D-Bus")
	}
	props := []sdbus.Property{
		sdbus.PropDescription(desc),
		sdbus.PropPids(uint32(pid)),
		sdbus.PropSlice(brand.SessionSlice),
		{Name: "CollectMode", Value: dbus.MakeVariant("inactive-or-failed")},
	}
	ch := make(chan string, 1)
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := c.StartTransientUnitContext(cctx, name, "fail", props, ch); err != nil {
		return err
	}
	select {
	case res := <-ch:
		if res != "done" {
			return fmt.Errorf("scope job: %s", res)
		}
	case <-cctx.Done():
		return cctx.Err()
	}
	return nil
}

func (t *sessionTable) add(r *sessionRec) {
	t.mu.Lock()
	t.m[r.ID] = r
	t.mu.Unlock()
	data, _ := json.Marshal(r)
	os.WriteFile(filepath.Join(sessionsDir(), r.ID+".json"), data, 0o600)
}

func (t *sessionTable) markExited(id string) {
	t.mu.Lock()
	if r := t.m[id]; r != nil {
		r.exited = true
	}
	t.mu.Unlock()
}

func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	if err := unix.Kill(pid, 0); err != nil && err != unix.EPERM {
		return false
	}
	// Guard against pid reuse: the helper's cmdline names its mode.
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	return strings.Contains(string(b), "session-helper") || strings.Contains(string(b), "session-exec")
}

// live reports whether a session still has processes: its scope is active,
// or (without systemd) its helper runs.
func (t *sessionTable) live(r *sessionRec) bool {
	if r.Scope != "" {
		if c := t.systemd(context.Background()); c != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			p, err := c.GetUnitPropertyContext(ctx, r.Scope, "ActiveState")
			if err == nil {
				s := strings.Trim(p.Value.String(), `"`)
				return s == "active" || s == "activating" || s == "deactivating"
			}
		}
	}
	if r.exited {
		return false
	}
	return pidAlive(r.HelperPID)
}

func (t *sessionTable) snapshot() []*sessionRec {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]*sessionRec, 0, len(t.m))
	for _, r := range t.m {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started < out[j].Started })
	return out
}

// list returns live sessions of a profile ("" = all).
func (t *sessionTable) list(profile string) []control.SessionInfo {
	var out []control.SessionInfo
	for _, r := range t.snapshot() {
		if profile != "" && r.Profile != profile {
			continue
		}
		if t.live(r) {
			out = append(out, r.SessionInfo)
		}
	}
	return out
}

func (t *sessionTable) get(id string) *sessionRec {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.m[id]
}

func (t *sessionTable) countLive(profile string) int { return len(t.list(profile)) }

func (t *sessionTable) remove(id string) {
	t.mu.Lock()
	delete(t.m, id)
	t.mu.Unlock()
	os.Remove(filepath.Join(sessionsDir(), id+".json"))
}

// gc forgets sessions that ended.
func (t *sessionTable) gc(d *Daemon) {
	for _, r := range t.snapshot() {
		if !t.live(r) {
			t.remove(r.ID)
		}
	}
}

// adopt reads the session records a previous daemon left.
func (t *sessionTable) adopt(d *Daemon) {
	ents, _ := os.ReadDir(sessionsDir())
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(sessionsDir(), e.Name()))
		if err != nil {
			continue
		}
		var r sessionRec
		if json.Unmarshal(data, &r) != nil || r.ID == "" {
			os.Remove(filepath.Join(sessionsDir(), e.Name()))
			continue
		}
		t.mu.Lock()
		t.m[r.ID] = &r
		t.mu.Unlock()
		if !t.live(&r) {
			t.remove(r.ID)
		} else {
			d.log.Info("adopted session", "session", r.ID, "profile", r.Profile, "uid", r.UID)
		}
	}
}

// killProfile ends every session of a profile.
func (t *sessionTable) killProfile(d *Daemon, profile string) {
	for _, r := range t.snapshot() {
		if r.Profile != profile {
			continue
		}
		t.kill(d, r)
	}
	// Wait briefly for them to go away.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && t.countLive(profile) > 0 {
		time.Sleep(100 * time.Millisecond)
	}
}

func (t *sessionTable) kill(d *Daemon, r *sessionRec) {
	if r.Scope != "" {
		if c := t.systemd(d.ctx); c != nil {
			ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
			ch := make(chan string, 1)
			if _, err := c.StopUnitContext(ctx, r.Scope, "replace", ch); err == nil {
				select {
				case <-ch:
				case <-ctx.Done():
				}
			}
			cancel()
		}
	}
	// Fallback (and belt and braces): kill the helper's children's process
	// groups, then the helper.
	for _, child := range childrenOf(r.HelperPID) {
		unix.Kill(-child, unix.SIGKILL)
		unix.Kill(child, unix.SIGKILL)
	}
	if pidAlive(r.HelperPID) {
		unix.Kill(r.HelperPID, unix.SIGKILL)
	}
}

func childrenOf(pid int) []int {
	if pid <= 0 {
		return nil
	}
	// Children are listed per thread; the helper starts its child from a
	// locked thread that is not the main one.
	tasks, _ := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/children", pid))
	var out []int
	for _, tf := range tasks {
		b, err := os.ReadFile(tf)
		if err != nil {
			continue
		}
		for _, f := range strings.Fields(string(b)) {
			if n, err := strconv.Atoi(f); err == nil {
				out = append(out, n)
			}
		}
	}
	return out
}
