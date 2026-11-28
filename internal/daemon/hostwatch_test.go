package daemon

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// syncBuf is a log sink safe for concurrent use.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Issue #30: when the netlink library closes the update channel (a failed
// receive) or subscribing fails, the address watcher logs it, subscribes
// again, seeds its address set again and reports one change.
func TestAddressWatchResubscribes(t *testing.T) {
	oldSub, oldList, oldRetry := addrSubscribe, addrList, watchRetry
	t.Cleanup(func() { addrSubscribe, addrList, watchRetry = oldSub, oldList, oldRetry })
	watchRetry = 10 * time.Millisecond

	_, known, _ := net.ParseCIDR("2a02:db8::1/64")
	known.IP = net.ParseIP("2a02:db8::1")
	addrList = func() ([]netlink.Addr, error) {
		return []netlink.Addr{{IPNet: known, LinkIndex: 3}}, nil
	}
	// Like the netlink library: the channel is closed when a receive fails
	// (after the error callback) or when done is closed.
	type subscription struct {
		ch   chan<- netlink.AddrUpdate
		done <-chan struct{}
		fail chan error
	}
	subs := make(chan subscription, 10)
	var calls atomic.Int32
	addrSubscribe = func(ch chan<- netlink.AddrUpdate, done <-chan struct{}, cb func(error)) error {
		if calls.Add(1) == 2 {
			return errors.New("netlink: socket: too many open files")
		}
		s := subscription{ch, done, make(chan error)}
		go func() {
			select {
			case err := <-s.fail:
				cb(err)
			case <-done:
			}
			close(ch)
		}()
		subs <- s
		return nil
	}
	var notified atomic.Int32
	log := &syncBuf{}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		keepSubscribed(ctx, slog.New(slog.NewTextHandler(log, nil)), "address", watchAddrs(slog.New(slog.NewTextHandler(log, nil)), func() { notified.Add(1) }))
		close(stopped)
	}()

	s := <-subs
	refresh := netlink.AddrUpdate{LinkAddress: *known, LinkIndex: 3, NewAddr: true}
	s.ch <- refresh // lifetime refresh of a known address: no change
	time.Sleep(20 * time.Millisecond)
	if n := notified.Load(); n != 0 {
		t.Fatalf("first subscription: %d notifications, want 0", n)
	}
	// The receive fails: the library reports it and closes the channel.
	s.fail <- errors.New("Receive failed: no buffer space available")
	waitUntil(t, "done of the dead subscription closed", func() bool {
		select {
		case <-s.done:
			return true
		default:
			return false
		}
	})
	// The next subscribe fails, the one after works.
	s = <-subs
	if c := calls.Load(); c != 3 {
		t.Fatalf("%d subscribe calls, want 3", c)
	}
	waitUntil(t, "one notification after resubscribing", func() bool { return notified.Load() == 1 })
	s.ch <- refresh // seeded again: still no change
	s.ch <- netlink.AddrUpdate{LinkAddress: *known, LinkIndex: 3, NewAddr: false}
	waitUntil(t, "removal noticed", func() bool { return notified.Load() == 2 })
	for _, want := range []string{
		"address watch error", "no buffer space available",
		"address watch stopped; subscribing again",
		"address watch unavailable; trying again", "too many open files",
	} {
		if !strings.Contains(log.String(), want) {
			t.Errorf("log lacks %q:\n%s", want, log.String())
		}
	}
	cancel()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("keepSubscribed did not stop")
	}
	select {
	case <-s.done:
	default:
		t.Error("done not closed when the context ended")
	}
}

func TestRouteWatchResubscribes(t *testing.T) {
	oldSub, oldRetry := routeSubscribe, watchRetry
	t.Cleanup(func() { routeSubscribe, watchRetry = oldSub, oldRetry })
	watchRetry = 10 * time.Millisecond
	type subscription struct {
		ch   chan<- netlink.RouteUpdate
		fail chan error
	}
	subs := make(chan subscription, 10)
	routeSubscribe = func(ch chan<- netlink.RouteUpdate, done <-chan struct{}, cb func(error)) error {
		s := subscription{ch, make(chan error)}
		go func() {
			select {
			case err := <-s.fail:
				cb(err)
			case <-done:
			}
			close(ch)
		}()
		subs <- s
		return nil
	}
	var notified atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := slog.New(slog.NewTextHandler(&syncBuf{}, nil))
	go keepSubscribed(ctx, log, "route", watchRoutes(log, func() { notified.Add(1) }))
	s := <-subs
	s.ch <- netlink.RouteUpdate{Route: netlink.Route{Table: 255}} // local table: ignored
	s.ch <- netlink.RouteUpdate{Route: netlink.Route{Table: 254}}
	waitUntil(t, "main-table route change", func() bool { return notified.Load() == 1 })
	s.fail <- errors.New("Receive failed: no buffer space available")
	s = <-subs
	waitUntil(t, "notification after resubscribing", func() bool { return notified.Load() == 2 })
	s.ch <- netlink.RouteUpdate{Route: netlink.Route{Table: 254}}
	waitUntil(t, "change on the new subscription", func() bool { return notified.Load() == 3 })
}

// Closing done on purpose (shutdown) makes the library's receive fail; that
// error is not logged.
func TestWatchErrorQuietAfterDone(t *testing.T) {
	log := &syncBuf{}
	done := make(chan struct{})
	cb := watchError(slog.New(slog.NewTextHandler(log, nil)), "route", done)
	cb(errors.New("Receive failed: no buffer space available"))
	close(done)
	cb(errors.New("Receive failed: resource temporarily unavailable"))
	if s := log.String(); !strings.Contains(s, "no buffer space") || strings.Contains(s, "temporarily unavailable") {
		t.Fatalf("log:\n%s", s)
	}
}
