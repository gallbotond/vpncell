package control

import (
	"net"
	"os"
	"strings"
	"testing"
)

func pair(t *testing.T) (*Conn, *Conn) {
	fds, err := sockpair()
	if err != nil {
		t.Fatal(err)
	}
	a, _ := net.FileConn(os.NewFile(uintptr(fds[0]), "a"))
	b, _ := net.FileConn(os.NewFile(uintptr(fds[1]), "b"))
	return NewConn(a.(*net.UnixConn)), NewConn(b.(*net.UnixConn))
}

func TestFramingWithFDs(t *testing.T) {
	a, b := pair(t)
	defer a.Close()
	defer b.Close()
	f, _ := os.Open("/dev/null")
	defer f.Close()
	go func() {
		a.Send(Request{Type: "one"}, f, f)
		a.Send(Request{Type: "two"})
		a.Send(Request{Type: "three", Profile: strings.Repeat("x", 100000)}, f)
	}()
	for i, want := range []struct {
		typ string
		fds int
	}{{"one", 2}, {"two", 0}, {"three", 1}} {
		var r Request
		files, err := b.RecvInto(&r)
		if err != nil {
			t.Fatal(err)
		}
		if r.Type != want.typ || len(files) != want.fds {
			t.Fatalf("frame %d: got %s with %d fds", i, r.Type, len(files))
		}
		CloseFiles(files)
	}
}

func TestFrameTooLarge(t *testing.T) {
	a, b := pair(t)
	defer a.Close()
	defer b.Close()
	go a.uc.Write([]byte{0xff, 0xff, 0xff, 0xff})
	if _, _, err := b.Recv(); err == nil {
		t.Fatal("oversized frame accepted")
	}
}

func TestPeerCred(t *testing.T) {
	a, b := pair(t)
	defer a.Close()
	defer b.Close()
	c, err := Peer(b.uc)
	if err != nil {
		t.Fatal(err)
	}
	if c.UID != uint32(os.Getuid()) || c.PID != int32(os.Getpid()) {
		t.Fatalf("peer cred %+v", c)
	}
}
