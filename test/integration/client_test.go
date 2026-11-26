//go:build integration

package integration

import (
	"context"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Issue #8: with the daemon stopped, systemd keeps the control socket in
// the fd store, so connect() succeeds and nothing answers. The client must
// say so instead of hanging, and a command waiting while the daemon starts
// must still complete.
func TestClientDaemonStopped(t *testing.T) {
	t.Cleanup(func() {
		sh("systemctl start vpncelld")
		waitFor(t, 30*time.Second, "daemon back", func() bool { return root(t, "list").code == 0 })
	})
	if out, err := sh("systemctl stop vpncelld"); err != nil {
		t.Fatalf("stop: %v %s", err, out)
	}
	// The listening socket is still held by systemd (fd store).
	if out, _ := sh("ss -xlnp | grep -F /run/vpncell/control.sock"); !strings.Contains(out, "systemd") {
		t.Logf("note: control socket not held by systemd while stopped: %q", out)
	}
	start := time.Now()
	r := vc(t, userAllowed, "list")
	el := time.Since(start)
	if r.code == 0 {
		t.Fatalf("list succeeded with the daemon stopped: %v", r)
	}
	if !strings.Contains(r.stderr, "waiting for vpncelld") || !strings.Contains(r.stderr, "vpncelld is stopped") ||
		!strings.Contains(r.stderr, "systemctl start vpncelld") {
		t.Fatalf("message: %v", r)
	}
	if el > 15*time.Second {
		t.Fatalf("took %v to report a stopped daemon", el)
	}
	t.Logf("stopped daemon reported after %v", el.Round(100*time.Millisecond))

	// A command that is waiting completes once the daemon starts.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	done := make(chan result, 1)
	go func() { done <- asUser(ctx, userAllowed, "", cliPath, "list") }()
	time.Sleep(1500 * time.Millisecond)
	if out, err := sh("systemctl start vpncelld"); err != nil {
		t.Fatalf("start: %v %s", err, out)
	}
	if r := <-done; r.code != 0 {
		t.Fatalf("list waiting across the start failed: %v", r)
	}
}

// Issue #9: a member of the group whose login session predates the
// membership is told about newgrp/sg; a non-member gets the usermod hint.
func TestClientGroupMessages(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// vctest1 is in the group database; run it without the group in this
	// process, as a session that started before `usermod -aG` would be.
	c := credsOf(userAllowed)
	g, err := user.LookupGroup("vpncell")
	if err != nil {
		t.Fatal(err)
	}
	vgid, _ := strconv.Atoi(g.Gid)
	var groups []string
	for _, x := range c.groups {
		if int(x) != vgid {
			groups = append(groups, strconv.Itoa(int(x)))
		}
	}
	args := []string{"--reuid", strconv.Itoa(int(c.uid)), "--regid", strconv.Itoa(int(c.gid))}
	if len(groups) == 0 {
		args = append(args, "--clear-groups")
	} else {
		args = append(args, "--groups", strings.Join(groups, ","))
	}
	cmd := exec.CommandContext(ctx, "setpriv", append(args, "--", cliPath, "list")...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "USER=" + userAllowed, "HOME=/tmp"}
	cmd.Dir = "/tmp"
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("list without the group in the process succeeded: %s", out)
	}
	for _, want := range []string{"permission denied", "this login session started before", "newgrp vpncell", "sg vpncell"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("member without the group in this session: message lacks %q:\n%s", want, out)
		}
	}
	r := vc(t, userNoGroup, "list")
	if r.code == 0 || !strings.Contains(r.stderr, "you are not in the \"vpncell\" group") || !strings.Contains(r.stderr, "usermod -aG vpncell") {
		t.Fatalf("non-member: %v", r)
	}
	if strings.Contains(r.stderr, "newgrp") {
		t.Fatalf("non-member told to use newgrp: %v", r)
	}
}
