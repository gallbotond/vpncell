//go:build unix

package conflict

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestReadRegular uses a FIFO and /dev/zero, so it runs on Unix only.
func TestReadRegular(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "c.pem")
	os.WriteFile(f, []byte("x"), 0o600)
	if b, err := ReadRegular(f); err != nil || string(b) != "x" {
		t.Fatalf("regular file: %q %v", b, err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := ReadRegular(fifo); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO read")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadRegular blocked on a FIFO")
	}
	if _, err := ReadRegular("/dev/zero"); err == nil {
		t.Fatal("device read")
	}
}
