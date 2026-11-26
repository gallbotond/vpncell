package daemon

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/gallbotond/vpncell/internal/brand"
	"github.com/gallbotond/vpncell/internal/control"
	"github.com/gallbotond/vpncell/internal/netns"
	"github.com/gallbotond/vpncell/internal/profile"
	"golang.org/x/sys/unix"
)

// Which session and network a caller is in (issue #12). Both come from the
// kernel, through the caller's pid (SO_PEERCRED): the session from the
// systemd scope in /proc/<pid>/cgroup, the network from
// /proc/<pid>/ns/net. A user cannot fake either; VPNCELL_SESSION and
// VPNCELL_PROFILE are only for prompts.

// scopeSessionID extracts the session id from a cgroup file's content
// ("0::/vpncell.slice/vpncell-sessions.slice/vpncell-s-<profile>-<uid>-<id>.scope/…").
func scopeSessionID(cgroup string) string {
	for _, line := range strings.Split(cgroup, "\n") {
		for _, seg := range strings.Split(line, "/") {
			if !strings.HasPrefix(seg, brand.ScopePrefix) || !strings.HasSuffix(seg, ".scope") {
				continue
			}
			name := strings.TrimSuffix(seg, ".scope")
			if i := strings.LastIndexByte(name, '-'); i > 0 {
				return name[i+1:]
			}
		}
	}
	return ""
}

// callerSession returns the id of the live session the process is in.
func (d *Daemon) callerSession(pid int32) string {
	if pid <= 0 {
		return ""
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	id := scopeSessionID(string(b))
	if r := d.sessions.get(id); r == nil || !d.sessions.live(r) {
		return ""
	}
	return id
}

// chain returns the nesting chain ending with session id, outermost first.
func (d *Daemon) chain(id string) []control.SessionRef {
	var out []control.SessionRef
	seen := map[string]bool{}
	for id != "" && !seen[id] && len(out) < 32 {
		seen[id] = true
		r := d.sessions.get(id)
		if r == nil {
			break
		}
		out = append([]control.SessionRef{{ID: r.ID, Profile: r.Profile}}, out...)
		id = r.Parent
	}
	return out
}

// callerNetwork names the profile whose namespace the process is in,
// "host", or "unknown".
func (d *Daemon) callerNetwork(c *caller) string {
	id, err := nsOfPeer(c.PID, c.UID, c.GID)
	if err != nil {
		return "unknown"
	}
	if h, err := netns.HostID(); err == nil && h == id {
		return "host"
	}
	d.mu.Lock()
	names := profile.Names(d.profiles)
	d.mu.Unlock()
	for _, n := range names {
		if pid, err := netns.IDOfPath(brand.NetnsPath(n)); err == nil && pid == id {
			return n
		}
	}
	return "unknown"
}

// nsOfPeer reads the network namespace of the caller's process. The
// kernel lets a process read another's /proc/<pid>/ns/* only with ptrace
// read access (PTRACE_MODE_READ_FSCREDS), and the daemon has no
// CAP_SYS_PTRACE. So the stat runs on a throwaway thread whose fsuid and
// fsgid are the caller's: same user, access granted, nothing more. The
// thread is never unlocked, so the Go runtime discards it afterwards.
func nsOfPeer(pid int32, uid, gid uint32) (netns.ID, error) {
	type res struct {
		id  netns.ID
		err error
	}
	ch := make(chan res, 1)
	go func() {
		runtime.LockOSThread()
		// Never unlocked (thread credentials changed).
		if uid != 0 {
			unix.Setfsgid(int(gid))
			unix.Setfsuid(int(uid))
		}
		id, err := netns.IDOfPath(fmt.Sprintf("/proc/%d/ns/net", pid))
		ch <- res{id, err}
	}()
	r := <-ch
	return r.id, r.err
}

func (d *Daemon) handleCurrent(c *caller) *control.Response {
	info := &control.CurrentInfo{Network: d.callerNetwork(c)}
	if id := d.callerSession(c.PID); id != "" {
		if r := d.sessions.get(id); r != nil {
			s := r.SessionInfo
			s.Current = true
			info.Session = &s
			info.Chain = d.chain(id)
		}
	}
	if info.Network != "host" && info.Network != "unknown" {
		if p, rt := d.getProfile(info.Network); p != nil && c.may(p) {
			info.State = rt.getState()
		}
	}
	return &control.Response{Type: "ok", Current: info}
}
