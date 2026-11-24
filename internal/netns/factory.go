package netns

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/gallbotond/vpncell/internal/brand"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func setupLoopback() error {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(lo)
}

// MismatchCount counts sockets that were created in the wrong namespace and
// therefore refused. It must stay zero; the stress test reads it.
var MismatchCount atomic.Uint64

// SocketsCreated counts sockets handed out by all factories.
var SocketsCreated atomic.Uint64

type sockReq struct {
	domain, typ, proto int
	reply              chan sockResp
}

type sockResp struct {
	fd  int
	err error
}

// Factory creates sockets inside one profile namespace. Its workers are
// goroutines locked to OS threads that entered the namespace once and never
// leave it.
type Factory struct {
	profile string
	id      ID
	reqs    chan sockReq
	done    chan struct{}
	once    sync.Once
	wg      sync.WaitGroup
}

// ErrClosed is returned after the factory was stopped.
var ErrClosed = errors.New("profile namespace is not available")

// NewFactory starts n workers in the profile namespace.
func NewFactory(profile string, n int) (*Factory, error) {
	path := brand.NetnsPath(profile)
	id, err := IDOfPath(path)
	if err != nil {
		return nil, err
	}
	f := &Factory{profile: profile, id: id, reqs: make(chan sockReq), done: make(chan struct{})}
	ready := make(chan error, n)
	for i := 0; i < n; i++ {
		f.wg.Add(1)
		go f.worker(path, ready)
	}
	var firstErr error
	for i := 0; i < n; i++ {
		if err := <-ready; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		f.Close()
		return nil, firstErr
	}
	return f, nil
}

// ID returns the namespace identity the factory serves.
func (f *Factory) ID() ID { return f.id }

func (f *Factory) worker(path string, ready chan<- error) {
	defer f.wg.Done()
	runtime.LockOSThread()
	// Never unlocked: when this goroutine returns, the thread is destroyed.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		ready <- err
		return
	}
	err = unix.Setns(fd, unix.CLONE_NEWNET)
	unix.Close(fd)
	if err != nil {
		ready <- fmt.Errorf("setns: %w", err)
		return
	}
	cur, err := CurrentThreadID()
	if err != nil || cur != f.id {
		ready <- fmt.Errorf("worker thread is not in namespace %s", f.profile)
		return
	}
	ready <- nil
	for {
		select {
		case <-f.done:
			return
		case r := <-f.reqs:
			r.reply <- f.makeSocket(r.domain, r.typ, r.proto)
		}
	}
}

func (f *Factory) makeSocket(domain, typ, proto int) sockResp {
	fd, err := unix.Socket(domain, typ|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, proto)
	if err != nil {
		return sockResp{-1, err}
	}
	got, err := SocketNamespace(fd)
	if err != nil || got != f.id {
		unix.Close(fd)
		MismatchCount.Add(1)
		if err == nil {
			err = fmt.Errorf("socket created in namespace %v, want %v", got, f.id)
		}
		return sockResp{-1, err}
	}
	SocketsCreated.Add(1)
	return sockResp{fd, nil}
}

// Socket returns a non-blocking, close-on-exec socket created inside the
// namespace. The caller owns the descriptor.
func (f *Factory) Socket(ctx context.Context, domain, typ, proto int) (int, error) {
	reply := make(chan sockResp, 1)
	select {
	case <-f.done:
		return -1, ErrClosed
	case <-ctx.Done():
		return -1, ctx.Err()
	case f.reqs <- sockReq{domain, typ, proto, reply}:
	}
	select {
	case r := <-reply:
		return r.fd, r.err
	case <-ctx.Done():
		// The worker will still answer; close what it hands back.
		go func() {
			if r := <-reply; r.fd >= 0 {
				unix.Close(r.fd)
			}
		}()
		return -1, ctx.Err()
	}
}

// Close stops the workers; their threads are destroyed.
func (f *Factory) Close() {
	f.once.Do(func() { close(f.done) })
	f.wg.Wait()
}
