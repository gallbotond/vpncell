//go:build integration

package integration

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gallbotond/vpncell/internal/control"
)

// Issue #12: a session knows which session and profile it is in.

func currentOf(t *testing.T, out string) control.CurrentInfo {
	t.Helper()
	i := strings.Index(out, "{")
	var cur control.CurrentInfo
	if i < 0 || json.Unmarshal([]byte(out[i:]), &cur) != nil {
		t.Fatalf("current --json: %q", out)
	}
	return cur
}

func TestSessionIdentity(t *testing.T) {
	s := labSets()[0]
	ensureUp(t, s.a, s.b)

	// Outside any session: exit 1, host network.
	r := vc(t, userAllowed, "current")
	if r.code != 1 || !strings.Contains(r.stdout, "session:  none") || !strings.Contains(r.stdout, "network:  host") {
		t.Fatalf("current outside a session: %v", r)
	}

	// Inside: VPNCELL_SESSION matches what the daemon finds from the
	// cgroup, and status marks the session.
	r = inProfile(t, userAllowed, s.a, "sh", "-c", `echo "env=$VPNCELL_SESSION"; vpncell current --json; echo; echo STATUS; vpncell status --json `+s.a)
	if r.code != 0 {
		t.Fatalf("run: %v", r)
	}
	envID := regexp.MustCompile(`env=([0-9a-f]{12})`).FindStringSubmatch(r.stdout)
	if envID == nil {
		t.Fatalf("no VPNCELL_SESSION: %v", r)
	}
	parts := strings.SplitN(r.stdout, "\nSTATUS\n", 2)
	if len(parts) != 2 {
		t.Fatalf("output: %v", r)
	}
	cur := currentOf(t, parts[0])
	if cur.Session == nil || cur.Session.ID != envID[1] || cur.Session.Profile != s.a || cur.Network != s.a || cur.State != "up" ||
		len(cur.Chain) != 1 {
		t.Fatalf("current: %+v (env %s)", cur, envID[1])
	}
	var st []control.ProfileStatus
	if err := json.Unmarshal([]byte(parts[1]), &st); err != nil || len(st) != 1 {
		t.Fatalf("status: %v %q", err, parts[1])
	}
	marked := 0
	for _, x := range st[0].Sessions {
		if x.Current {
			marked++
			if x.ID != envID[1] {
				t.Fatalf("wrong session marked: %+v", x)
			}
		}
	}
	if marked != 1 {
		t.Fatalf("status marks %d sessions: %+v", marked, st[0].Sessions)
	}
	// A faked VPNCELL_SESSION/VPNCELL_PROFILE does not fool the daemon.
	r = inProfile(t, userAllowed, s.a, "env", "VPNCELL_SESSION=000000000000", "VPNCELL_PROFILE="+s.b, "vpncell", "current")
	if !strings.Contains(r.stdout, "network:  profile "+s.a) || !strings.Contains(r.stdout, "VPNCELL_PROFILE="+s.b+" does not match") {
		t.Fatalf("faked env: %v", r)
	}

	// Nested: a session started from inside another one.
	r = inProfile(t, userAllowed, s.a, "vpncell", "run", "-T", s.b, "--", "vpncell", "current", "--json")
	cur = currentOf(t, r.stdout)
	if len(cur.Chain) != 2 || cur.Chain[0].Profile != s.a || cur.Chain[1].Profile != s.b || cur.Network != s.b ||
		cur.Session == nil || cur.Session.ID != cur.Chain[1].ID || cur.Session.Parent != cur.Chain[0].ID {
		t.Fatalf("nested current: %+v (%v)", cur, r)
	}
	r = inProfile(t, userAllowed, s.a, "vpncell", "run", "-T", s.b, "--", "vpncell", "current")
	if !strings.Contains(r.stdout, "nesting:  ") || !strings.Contains(r.stdout, "("+s.a+") → ") {
		t.Fatalf("nested current text: %v", r)
	}
}

// Banner on entering and leaving, and the terminal title (OSC 0, saved
// and restored with the xterm title stack).
func TestShellBannerAndTitle(t *testing.T) {
	s := labSets()[0]
	ensureUp(t, s.a)
	sh := startShell(t, userAllowed, s.a, 24, 80)
	m := sh.expect(`vpncell: entering profile `+regexp.QuoteMeta(s.a)+` \(session ([0-9a-f]{12}); type exit to leave\)`, 15*time.Second)
	sh.expect(`\x1b\[22;0t\x1b\]0;\[vpncell: `+regexp.QuoteMeta(s.a)+`\] `+userAllowed+`@`, 5*time.Second)
	sh.send("echo id=$VPNCELL_SESSION\n")
	sh.expect(`id=`+m[1], 10*time.Second)
	sh.send("exit 7\n")
	sh.expect(`\x1b\[23;0t`, 10*time.Second)
	sh.expect(`vpncell: left profile `+regexp.QuoteMeta(s.a)+` \(back on the host network\)`, 10*time.Second)
	if code := sh.wait(10 * time.Second); code != 7 {
		t.Fatalf("exit code %d", code)
	}
}
