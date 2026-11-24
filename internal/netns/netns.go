// Package netns creates, adopts and deletes profile network namespaces, and
// runs code inside them.
//
// Thread rule (DESIGN.md §6): a thread that enters a profile namespace never
// leaves it and is never returned to the Go scheduler. Every function here
// that calls setns does so on a goroutine that locks its OS thread and exits
// without unlocking, so the runtime destroys the thread.
package netns

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/gallbotond/vpncell/internal/brand"
	"golang.org/x/sys/unix"
)

// ID identifies a network namespace by device and inode.
type ID struct{ Dev, Ino uint64 }

// IDOfPath returns the namespace identity of a /run/netns entry or a
// /proc/<pid>/ns/net link.
func IDOfPath(path string) (ID, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return ID{}, err
	}
	return ID{Dev: st.Dev, Ino: st.Ino}, nil
}

// IDOfFd returns the identity of a namespace fd.
func IDOfFd(fd int) (ID, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return ID{}, err
	}
	return ID{Dev: st.Dev, Ino: st.Ino}, nil
}

// HostID returns the identity of the daemon's own (host) namespace.
// The daemon locks its main goroutine to the main thread (see
// cmd/vpncelld), so no namespace work ever runs there and /proc/self is the
// host namespace.
func HostID() (ID, error) { return IDOfPath("/proc/self/ns/net") }

// Exists reports whether a profile namespace is mounted.
func Exists(profile string) bool {
	_, err := IDOfPath(brand.NetnsPath(profile))
	if err != nil {
		return false
	}
	return isNsfs(brand.NetnsPath(profile))
}

func isNsfs(path string) bool {
	var sfs unix.Statfs_t
	if err := unix.Statfs(path, &sfs); err != nil {
		return false
	}
	return sfs.Type == unix.NSFS_MAGIC
}

// ensureNetnsDir prepares /run/netns like `ip netns add`: a shared mount
// point, so namespace mounts propagate into other mount namespaces.
func ensureNetnsDir() error {
	dir := brand.NetnsDir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for i := 0; i < 2; i++ {
		err := unix.Mount("", dir, "none", unix.MS_SHARED|unix.MS_REC, "")
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EINVAL) || i > 0 {
			return fmt.Errorf("make %s shared: %w", dir, err)
		}
		// Not a mount point yet: bind it to itself, then retry.
		if err := unix.Mount(dir, dir, "none", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			return fmt.Errorf("bind %s: %w", dir, err)
		}
	}
	return nil
}

// Create creates the namespace for a profile and returns its identity. If it
// already exists, its identity is returned unchanged.
func Create(profile string) (ID, error) {
	path := brand.NetnsPath(profile)
	if Exists(profile) {
		return IDOfPath(path)
	}
	if err := ensureNetnsDir(); err != nil {
		return ID{}, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil && !os.IsExist(err) {
		return ID{}, err
	}
	if f != nil {
		f.Close()
	}
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// Never unlocked: this thread ends in the new namespace and is
		// destroyed when the goroutine returns.
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			errc <- fmt.Errorf("unshare: %w", err)
			return
		}
		src := fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid())
		if err := unix.Mount(src, path, "none", unix.MS_BIND, ""); err != nil {
			errc <- fmt.Errorf("bind namespace: %w", err)
			return
		}
		errc <- nil
	}()
	if err := <-errc; err != nil {
		os.Remove(path)
		return ID{}, err
	}
	id, err := IDOfPath(path)
	if err != nil {
		return ID{}, err
	}
	// Bring up lo inside.
	if err := Do(profile, setupLoopback); err != nil {
		Delete(profile)
		return ID{}, err
	}
	return id, nil
}

// Delete unmounts and removes a profile namespace. Processes that are still
// inside keep it alive (with whatever interfaces remain in it).
func Delete(profile string) error {
	path := brand.NetnsPath(profile)
	if err := unix.Unmount(path, unix.MNT_DETACH); err != nil && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("unmount %s: %w", path, err)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// List returns the profile names of all mounted vpncell namespaces.
func List() ([]string, error) {
	ents, err := os.ReadDir(brand.NetnsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range ents {
		n := e.Name()
		if strings.HasPrefix(n, brand.NetnsPrefix) {
			out = append(out, strings.TrimPrefix(n, brand.NetnsPrefix))
		}
	}
	return out, nil
}

// Do runs fn on a fresh OS thread inside the profile's namespace. The thread
// is destroyed afterwards.
func Do(profile string, fn func() error) error {
	return DoPath(brand.NetnsPath(profile), fn)
}

// DoPath is Do for an arbitrary namespace path.
func DoPath(path string, fn func() error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// Never unlocked (see package comment).
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			errc <- fmt.Errorf("open %s: %w", filepath.Base(path), err)
			return
		}
		err = unix.Setns(fd, unix.CLONE_NEWNET)
		unix.Close(fd)
		if err != nil {
			errc <- fmt.Errorf("setns %s: %w", filepath.Base(path), err)
			return
		}
		defer func() {
			if r := recover(); r != nil {
				errc <- fmt.Errorf("panic in namespace %s: %v", filepath.Base(path), r)
			}
		}()
		errc <- fn()
	}()
	return <-errc
}

// CurrentThreadID returns the namespace of the calling thread.
func CurrentThreadID() (ID, error) {
	return IDOfPath(fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid()))
}

// SocketNamespace returns the namespace identity a socket was created in,
// using SIOCGSKNS.
func SocketNamespace(fd int) (ID, error) {
	nsfd, err := unix.IoctlRetInt(fd, unix.SIOCGSKNS)
	if err != nil {
		return ID{}, fmt.Errorf("SIOCGSKNS: %w", err)
	}
	defer unix.Close(nsfd)
	return IDOfFd(nsfd)
}
