package client

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gallbotond/vpncell/internal/control"
)

// silentListener is what systemd's fd store looks like while the daemon is
// stopped: connect() succeeds, nobody ever accepts.
func silentListener(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "control.sock")
	l, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return p
}

func withTiming(t *testing.T, notice, limit, interval time.Duration, state func(context.Context) (string, string, error)) *strings.Builder {
	t.Helper()
	on, ol, oi, os, onot := NoticeAfter, HelloTimeout, stateInterval, unitState, Notice
	NoticeAfter, HelloTimeout, stateInterval, unitState = notice, limit, interval, state
	var b strings.Builder
	Notice = &b
	t.Cleanup(func() { NoticeAfter, HelloTimeout, stateInterval, unitState, Notice = on, ol, oi, os, onot })
	return &b
}

func TestDialNotAnswering(t *testing.T) {
	notice := withTiming(t, 50*time.Millisecond, 400*time.Millisecond, 20*time.Millisecond,
		func(context.Context) (string, string, error) { return "activating", "start", nil })
	p := silentListener(t)
	start := time.Now()
	_, err := dial(p)
	if !errors.Is(err, ErrDaemonUnreachable) {
		t.Fatalf("err = %v, want ErrDaemonUnreachable", err)
	}
	if el := time.Since(start); el < 400*time.Millisecond || el > 3*time.Second {
		t.Fatalf("gave up after %v, want about 400ms", el)
	}
	if !strings.Contains(err.Error(), "not answering") || !strings.Contains(err.Error(), "systemctl status vpncelld") {
		t.Fatalf("message: %v", err)
	}
	if !strings.Contains(notice.String(), "waiting for vpncelld") {
		t.Fatalf("no waiting notice: %q", notice.String())
	}
}

func TestDialStoppedFailsEarly(t *testing.T) {
	var calls atomic.Int32
	withTiming(t, 50*time.Millisecond, 10*time.Second, 20*time.Millisecond,
		func(context.Context) (string, string, error) { calls.Add(1); return "inactive", "dead", nil })
	start := time.Now()
	_, err := dial(silentListener(t))
	if !errors.Is(err, ErrDaemonUnreachable) || !strings.Contains(err.Error(), "is stopped") || !strings.Contains(err.Error(), "systemctl start vpncelld") {
		t.Fatalf("err = %v", err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("took %v; a stopped unit should fail early", el)
	}
	if calls.Load() < 2 {
		t.Fatalf("unit state checked %d times; it must be seen stopped twice", calls.Load())
	}
}

// A single "inactive" moment (inside `systemctl restart`) and a crashed
// daemon waiting for Restart= do not end the wait.
func TestDialRestartDoesNotFailEarly(t *testing.T) {
	states := [][2]string{{"inactive", "dead"}, {"activating", "start"}, {"failed", "auto-restart"}, {"activating", "auto-restart"}, {"inactive", "dead"}, {"activating", "start"}}
	var i atomic.Int32
	withTiming(t, 20*time.Millisecond, 600*time.Millisecond, 10*time.Millisecond,
		func(context.Context) (string, string, error) {
			n := int(i.Add(1)-1) % len(states)
			return states[n][0], states[n][1], nil
		})
	_, err := dial(silentListener(t))
	if err == nil || !strings.Contains(err.Error(), "not answering") {
		t.Fatalf("err = %v, want the full timeout", err)
	}
}

// A daemon that answers late (restart in progress) is used normally.
func TestDialLateReply(t *testing.T) {
	notice := withTiming(t, 30*time.Millisecond, 5*time.Second, 10*time.Millisecond,
		func(context.Context) (string, string, error) { return "activating", "start", nil })
	p := filepath.Join(t.TempDir(), "control.sock")
	l, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		time.Sleep(200 * time.Millisecond)
		nc, err := l.Accept()
		if err != nil {
			return
		}
		c := control.NewConn(nc.(*net.UnixConn))
		var req control.Request
		c.RecvInto(&req)
		c.Send(control.Response{Type: "hello", UID: 4242})
	}()
	cl, err := dial(p)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	if cl.UID != 4242 {
		t.Fatalf("uid = %d", cl.UID)
	}
	if !strings.Contains(notice.String(), "waiting") {
		t.Fatalf("expected a waiting notice, got %q", notice.String())
	}
}

func TestDialNoListener(t *testing.T) {
	_, err := dial(filepath.Join(t.TempDir(), "none.sock"))
	if !errors.Is(err, ErrDaemonUnreachable) || !strings.Contains(err.Error(), "not running") {
		t.Fatalf("err = %v", err)
	}
}

func TestUnitStopped(t *testing.T) {
	for _, c := range []struct {
		a, s string
		want bool
	}{
		{"inactive", "dead", true}, {"failed", "failed", true}, {"failed", "auto-restart", false},
		{"activating", "auto-restart", false}, {"active", "running", false}, {"deactivating", "stop-sigterm", false},
		{"activating", "start", false},
	} {
		if got := unitStopped(c.a, c.s); got != c.want {
			t.Errorf("%s/%s = %v", c.a, c.s, got)
		}
	}
}

func TestDiagnoseGroup(t *testing.T) {
	cases := []struct {
		name, entry, user string
		primary           int
		proc              []int
		want              membership
		msg               string
	}{
		{"session predates", "vpncell:x:990:alice,bob", "bob", 1000, []int{1000, 27}, memberInactive, "newgrp vpncell"},
		{"primary group", "vpncell:x:990:", "bob", 990, []int{1000}, memberInactive, "sg vpncell"},
		{"not a member", "vpncell:x:990:alice", "bob", 1000, []int{1000}, memberNone, "usermod -aG vpncell"},
		{"prefix is not a member", "vpncell:x:990:bobby", "bob", 1000, []int{1000}, memberNone, "not in"},
		{"active", "vpncell:x:990:bob", "bob", 1000, []int{1000, 990}, memberActive, "ls -l"},
		{"no group", "", "bob", 1000, []int{1000}, groupMissing, "does not exist"},
	}
	for _, c := range cases {
		got := diagnose(c.entry, c.user, c.primary, c.proc)
		if got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
		if m := membershipMessage(got, "/run/vpncell/control.sock"); !strings.Contains(m, c.msg) {
			t.Errorf("%s: message %q lacks %q", c.name, m, c.msg)
		}
	}
}
