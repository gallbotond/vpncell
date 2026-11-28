package control

import (
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
)

// fakeTransport is one end of an in-memory stream that carries files with
// the bytes they were written with, like SCM_RIGHTS on a stream socket.
type fakeTransport struct {
	mu       sync.Mutex
	cond     *sync.Cond
	in       []fakeChunk
	eof      bool
	peer     *fakeTransport
	maxRead  int // bytes per ReadMsg, 0 = no limit
	maxWrite int // bytes per WriteMsg, 0 = no limit
	readErr  error
}

type fakeChunk struct {
	b     []byte
	files []*os.File
}

func fakePair() (*fakeTransport, *fakeTransport) {
	a, b := &fakeTransport{}, &fakeTransport{}
	a.cond, b.cond = sync.NewCond(&a.mu), sync.NewCond(&b.mu)
	a.peer, b.peer = b, a
	return a, b
}

func (t *fakeTransport) push(b []byte, files []*os.File) {
	p := t.peer
	p.mu.Lock()
	p.in = append(p.in, fakeChunk{append([]byte(nil), b...), files})
	p.mu.Unlock()
	p.cond.Broadcast()
}

func (t *fakeTransport) WriteMsg(b []byte, files []*os.File) (int, error) {
	n := len(b)
	if t.maxWrite > 0 && n > t.maxWrite {
		n = t.maxWrite
	}
	t.push(b[:n], files)
	return n, nil
}

func (t *fakeTransport) Write(b []byte) (int, error) {
	t.push(b, nil)
	return len(b), nil
}

func (t *fakeTransport) ReadMsg(b []byte) (int, []*os.File, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.readErr != nil {
		return 0, nil, t.readErr
	}
	for len(t.in) == 0 && !t.eof {
		t.cond.Wait()
	}
	if len(t.in) == 0 {
		return 0, nil, io.EOF
	}
	c := &t.in[0]
	n := copy(b, c.b)
	if t.maxRead > 0 && n > t.maxRead {
		n = t.maxRead
	}
	files := c.files
	c.files = nil
	c.b = c.b[n:]
	if len(c.b) == 0 {
		t.in = t.in[1:]
	}
	return n, files, nil
}

func (t *fakeTransport) Close() error {
	for _, e := range []*fakeTransport{t, t.peer} {
		e.mu.Lock()
		e.eof = true
		e.mu.Unlock()
		e.cond.Broadcast()
	}
	return nil
}

func tempFiles(t *testing.T, n int) []*os.File {
	t.Helper()
	var fs []*os.File
	for i := 0; i < n; i++ {
		f, err := os.CreateTemp(t.TempDir(), "fd")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		fs = append(fs, f)
	}
	return fs
}

func TestFakeTransportFraming(t *testing.T) {
	ta, tb := fakePair()
	ta.maxWrite = 5 // Send must finish the frame with Write
	tb.maxRead = 3  // Recv must put frames together from short reads
	a, b := NewConnTransport(ta), NewConnTransport(tb)
	defer a.Close()
	go func() {
		a.Send(Request{Type: "one"}, tempFiles(t, 2)...)
		a.Send(Request{Type: "two"})
		a.Send(Request{Type: "three", Profile: strings.Repeat("x", 100000)}, tempFiles(t, 1)...)
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
	}
	if a.Unix() != nil {
		t.Fatal("Unix() of a non-socket transport")
	}
}

func TestFakeTransportTooManyFiles(t *testing.T) {
	ta, tb := fakePair()
	a, b := NewConnTransport(ta), NewConnTransport(tb)
	files := tempFiles(t, MaxFDs+1)
	go a.Send(Request{Type: "x"}, files...)
	if _, _, err := b.Recv(); err == nil || !strings.Contains(err.Error(), "too many file descriptors") {
		t.Fatalf("Recv = %v, want too many file descriptors", err)
	}
	// Recv closed the files it got.
	if _, err := files[0].Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("received file not closed: %v", err)
	}
}

func TestFakeTransportFrameError(t *testing.T) {
	_, tb := fakePair()
	want := errors.New("bad rights")
	tb.readErr = &FrameError{want}
	if _, _, err := NewConnTransport(tb).Recv(); err != want {
		t.Fatalf("Recv = %v, want %v", err, want)
	}
}

func TestFakeTransportEOF(t *testing.T) {
	ta, tb := fakePair()
	b := NewConnTransport(tb)
	ta.Write([]byte{0, 0, 0, 10, '{', '"'})
	ta.Close()
	if _, _, err := b.Recv(); err != io.ErrUnexpectedEOF {
		t.Fatalf("Recv = %v, want unexpected EOF", err)
	}
	if _, _, err := b.Recv(); err != io.EOF {
		t.Fatalf("Recv at the end = %v, want EOF", err)
	}
}

func TestFakeTransportFrameTooLarge(t *testing.T) {
	ta, tb := fakePair()
	ta.Write([]byte{0xff, 0xff, 0xff, 0xff})
	if _, _, err := NewConnTransport(tb).Recv(); err == nil || !strings.Contains(err.Error(), "frame too large") {
		t.Fatalf("Recv = %v, want frame too large", err)
	}
}
