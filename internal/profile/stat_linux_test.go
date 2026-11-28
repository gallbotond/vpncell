package profile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStatUIDLinux(t *testing.T) {
	f := filepath.Join(t.TempDir(), "p.toml")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(f)
	if err != nil {
		t.Fatal(err)
	}
	if uid, ok := statUID(st); !ok || uid != uint32(os.Getuid()) {
		t.Fatalf("statUID = %d, %v; want %d, true", uid, ok, os.Getuid())
	}
}
