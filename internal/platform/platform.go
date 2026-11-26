// Package platform holds everything specific to Ubuntu (26.04 LTS): where the
// host resolver lives, which sockets must be masked inside profiles, and
// NetworkManager integration. Other systemd distributions would add their
// variants here.
package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	ResolvConf     = "/etc/resolv.conf"
	NsswitchConf   = "/etc/nsswitch.conf"
	ResolvedRunDir = "/run/systemd/resolve"
	// NMConfFile keeps NetworkManager away from tunnel devices while they
	// briefly exist in the host namespace.
	NMConfFile = "/etc/NetworkManager/conf.d/vpncell.conf"
)

// MaskDirs are path-socket directories of host resolvers. A network
// namespace does not isolate path sockets, so sessions get an empty
// read-only tmpfs over each.
var MaskDirs = []string{"/run/avahi-daemon", "/run/nscd", "/var/run/nscd"}

func bindRO(src, dst string) error {
	if err := unix.Mount(src, dst, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind %s on %s: %w", src, dst, err)
	}
	if err := unix.Mount("", dst, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
		return fmt.Errorf("remount %s read-only: %w", dst, err)
	}
	return nil
}

func maskDir(dir string) error {
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return nil
	}
	if err := unix.Mount("tmpfs", dir, "tmpfs", unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "size=4k,mode=0755"); err != nil {
		return fmt.Errorf("mask %s: %w", dir, err)
	}
	return nil
}

// SetupResolver must run in a fresh, slave mount namespace. It makes the
// profile's resolver files visible at the standard paths and hides the host
// resolver's sockets. resolveDir contains stub-resolv.conf and resolv.conf;
// nsswitch is the profile's nsswitch.conf.
func SetupResolver(resolveDir, nsswitch string) error {
	target, err := filepath.EvalSymlinks(ResolvConf)
	if err != nil {
		// Dangling or missing: fall back to masking and a file bind below.
		target = ""
	}
	link, _ := os.Readlink(ResolvConf)
	switch {
	case link != "" && target != "" && strings.HasPrefix(target, ResolvedRunDir+"/"):
		// Ubuntu default: /etc/resolv.conf -> /run/systemd/resolve/stub-resolv.conf.
		// Replace the whole directory, which also hides resolved's varlink socket.
		if err := bindRO(resolveDir, ResolvedRunDir); err != nil {
			return err
		}
	default:
		if err := maskDir(ResolvedRunDir); err != nil {
			return err
		}
		dst := ResolvConf
		if target != "" {
			dst = target
		}
		if _, err := os.Stat(dst); err != nil {
			return fmt.Errorf("no resolv.conf to replace: %w", err)
		}
		if err := bindRO(filepath.Join(resolveDir, "resolv.conf"), dst); err != nil {
			return err
		}
	}
	for _, d := range MaskDirs {
		if err := maskDir(d); err != nil {
			return err
		}
	}
	if _, err := os.Stat(NsswitchConf); err == nil {
		if err := bindRO(nsswitch, NsswitchConf); err != nil {
			return err
		}
	}
	return nil
}

// NMUnmanagedConf is the NetworkManager drop-in content.
const NMUnmanagedConf = `# Installed by vpncell: never manage vpncell tunnel devices.
[keyfile]
unmanaged-devices=interface-name:vpnwg*;interface-name:vpntun*
`

// CapabilityBinaries are programs that Ubuntu ships with file capabilities
// and that are useful without them (issue #10). Sessions run with
// no_new_privs and no capabilities, so the kernel refuses to execute a
// binary whose file capabilities have the effective bit set (EPERM).
// UnprivilegeBinaries bind-mounts each one onto itself with nosuid: the
// kernel ignores file capabilities on a nosuid mount, so the program runs
// with the user's own (empty) capabilities. ping then uses an ICMP
// datagram socket, which net.ipv4.ping_group_range allows in the profile
// namespace. No capability is given to the session.
var CapabilityBinaries = []string{"/usr/bin/ping"}

// UnprivilegeBinaries must run in the session's private, slave mount
// namespace. Binaries without file capabilities are left alone.
func UnprivilegeBinaries() error {
	for _, b := range CapabilityBinaries {
		p, err := filepath.EvalSymlinks(b)
		if err != nil {
			continue
		}
		if !hasFileCaps(p) {
			continue
		}
		if err := bindRO(p, p); err != nil {
			return err
		}
	}
	return nil
}

func hasFileCaps(path string) bool {
	n, err := unix.Getxattr(path, "security.capability", nil)
	return err == nil && n > 0
}

// PingGroupRangeFile is the per-network-namespace setting that allows
// unprivileged ICMP (and ICMPv6) datagram sockets. A new namespace starts
// with "1 0" (nobody).
const PingGroupRangeFile = "/proc/sys/net/ipv4/ping_group_range"
