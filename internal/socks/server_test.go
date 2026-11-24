package socks

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/gallbotond/vpncell/internal/netns"
)

type downBackend struct{ called bool }

func (b *downBackend) Get(ctx context.Context) (*netns.Factory, *Resolver, error) {
	b.called = true
	return nil, nil, errors.New("down")
}

func newServer(b Backend) *Server {
	s := &Server{Profile: "t", Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Backend: b}
	s.SetCredentials("user", "pass")
	return s
}

func exchange(t *testing.T, s *Server, in []byte, want int) []byte {
	a, b := net.Pipe()
	go func() { s.handle(b); b.Close() }()
	a.SetDeadline(time.Now().Add(2 * time.Second))
	go a.Write(in)
	out, _ := io.ReadAll(io.LimitReader(a, int64(want)))
	a.Close()
	return out
}

func auth(u, p string) []byte {
	b := []byte{5, 1, 2, 1, byte(len(u))}
	b = append(b, u...)
	b = append(b, byte(len(p)))
	return append(b, p...)
}

func TestNoAuthRefused(t *testing.T) {
	out := exchange(t, newServer(&downBackend{}), []byte{5, 1, 0}, 2)
	if len(out) != 2 || out[1] != 0xff {
		t.Fatalf("got %v", out)
	}
}

func TestWrongPassword(t *testing.T) {
	b := &downBackend{}
	out := exchange(t, newServer(b), auth("user", "nope"), 4)
	if len(out) != 4 || out[3] != 1 || b.called {
		t.Fatalf("got %v called=%v", out, b.called)
	}
}

func TestUDPAssociateUnsupported(t *testing.T) {
	b := &downBackend{}
	in := append(auth("user", "pass"), 5, 3, 0, 1, 1, 2, 3, 4, 0, 80)
	out := exchange(t, newServer(b), in, 14)
	if len(out) < 6 || out[5] != repCmdUnsupported || b.called {
		t.Fatalf("got %v", out)
	}
}

func TestProfileDownFailsClosed(t *testing.T) {
	b := &downBackend{}
	in := append(auth("user", "pass"), 5, 1, 0, 1, 10, 99, 0, 10, 0, 80)
	out := exchange(t, newServer(b), in, 14)
	if len(out) < 6 || out[5] != repGeneralFailure || !b.called {
		t.Fatalf("got %v", out)
	}
}

func FuzzHandshake(f *testing.F) {
	f.Add(append(auth("user", "pass"), 5, 1, 0, 3, 3, 'a', 'b', 'c', 0, 80))
	f.Add([]byte{5, 255})
	f.Fuzz(func(t *testing.T, in []byte) {
		s := newServer(&downBackend{})
		a, b := net.Pipe()
		done := make(chan struct{})
		go func() { s.handle(b); b.Close(); close(done) }()
		a.SetDeadline(time.Now().Add(200 * time.Millisecond))
		go func() { a.Write(in) }()
		io.Copy(io.Discard, a)
		a.Close()
		<-done
	})
}

func TestCandidates(t *testing.T) {
	r := &Resolver{Search: []string{"corp.example"}}
	if c := r.candidates("web"); c[0] != "web.corp.example." || c[1] != "web." {
		t.Fatalf("%v", c)
	}
	if c := r.candidates("a.b"); c[0] != "a.b." {
		t.Fatalf("%v", c)
	}
}
