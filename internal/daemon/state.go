package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gallbotond/vpncell/internal/brand"
	"github.com/gallbotond/vpncell/internal/dnsfiles"
	"golang.org/x/sys/unix"
)

// persistent is /var/lib/vpncell/state.json: values that must stay stable
// across daemon restarts and reboots.
type persistent struct {
	Ports   map[string]int `json:"socks_ports"`
	Indexes map[string]int `json:"indexes"`
}

type stateStore struct {
	mu   sync.Mutex
	path string
	s    persistent
}

func loadState() (*stateStore, error) {
	st := &stateStore{path: filepath.Join(brand.StateDir, "state.json")}
	st.s.Ports = map[string]int{}
	st.s.Indexes = map[string]int{}
	data, err := os.ReadFile(st.path)
	if err == nil {
		if err := json.Unmarshal(data, &st.s); err != nil {
			return nil, fmt.Errorf("%s: %w", st.path, err)
		}
		if st.s.Ports == nil {
			st.s.Ports = map[string]int{}
		}
		if st.s.Indexes == nil {
			st.s.Indexes = map[string]int{}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return st, nil
}

func (st *stateStore) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(st.path), 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(st.s, "", "  ")
	return dnsfiles.WriteAtomic(st.path, string(data)+"\n", 0o600)
}

// index returns the stable small index of a profile (for interface names).
func (st *stateStore) index(profile string) (int, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if n, ok := st.s.Indexes[profile]; ok {
		return n, nil
	}
	used := map[int]bool{}
	for _, n := range st.s.Indexes {
		used[n] = true
	}
	n := 0
	for used[n] {
		n++
	}
	if n > 9999 {
		return 0, fmt.Errorf("too many profiles")
	}
	st.s.Indexes[profile] = n
	return n, st.saveLocked()
}

// port returns the SOCKS port of a profile: fixed in the profile, or
// allocated once from the range and saved.
func (st *stateStore) port(profile string, fixed, lo, hi int) (int, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if fixed > 0 {
		if st.s.Ports[profile] != fixed {
			st.s.Ports[profile] = fixed
			if err := st.saveLocked(); err != nil {
				return 0, err
			}
		}
		return fixed, nil
	}
	if p, ok := st.s.Ports[profile]; ok && p >= lo && p <= hi {
		return p, nil
	}
	used := map[int]bool{}
	for _, p := range st.s.Ports {
		used[p] = true
	}
	for p := lo; p <= hi; p++ {
		if used[p] {
			continue
		}
		// Skip ports already bound by something else.
		l, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			continue
		}
		l.Close()
		st.s.Ports[profile] = p
		return p, st.saveLocked()
	}
	return 0, fmt.Errorf("no free SOCKS port in %d-%d", lo, hi)
}

// prune forgets the index and port of every profile not in keep, also
// those deleted while the daemon was stopped (issue #17).
func (st *stateStore) prune(keep func(string) bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	changed := false
	for _, m := range []map[string]int{st.s.Ports, st.s.Indexes} {
		for name := range m {
			if !keep(name) {
				delete(m, name)
				changed = true
			}
		}
	}
	if changed {
		st.saveLocked()
	}
}

// Secret is a string that never appears in logs.
type Secret string

func (Secret) String() string               { return "<redacted>" }
func (Secret) LogValue() slog.Value         { return slog.StringValue("<redacted>") }
func (Secret) GoString() string             { return "<redacted>" }
func (s Secret) Reveal() string             { return string(s) }
func (Secret) MarshalText() ([]byte, error) { return []byte("<redacted>"), nil }

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// runtime markers in /run/vpncell (tmpfs: gone at reboot).
func desiredPath(profile string) string {
	return filepath.Join(brand.ProfileRunDir(profile), "desired-up")
}

func setDesired(profile string, up bool) {
	if up {
		os.MkdirAll(brand.ProfileRunDir(profile), 0o755)
		os.WriteFile(desiredPath(profile), []byte("1\n"), 0o600)
	} else {
		os.Remove(desiredPath(profile))
	}
}

func isDesired(profile string) bool {
	_, err := os.Stat(desiredPath(profile))
	return err == nil
}

func bootedMarker() string { return filepath.Join(brand.RunDir, "booted") }

// sdNotify sends a state string, optionally with file descriptors, to
// systemd. It is a no-op when not running under systemd.
func sdNotify(state string, fds ...int) error {
	sock := os.Getenv("NOTIFY_SOCKET")
	if sock == "" {
		return nil
	}
	if strings.HasPrefix(sock, "@") {
		sock = "\x00" + sock[1:]
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var oob []byte
	if len(fds) > 0 {
		oob = unix.UnixRights(fds...)
	}
	return unix.Sendmsg(fd, []byte(state), oob, &unix.SockaddrUnix{Name: sock}, 0)
}
