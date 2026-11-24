//go:build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Leak capture on the host's physical interface (DESIGN.md §15.3, with the
// change recorded in §12: no host firewall table is added). Tailscale's own
// traffic is excluded by the local UDP ports that tailscaled owns; nothing
// else is filtered at capture time. A leak is any packet that goes to a test
// destination, carries a marker string, or goes to the VPN endpoint on a
// port other than the VPN ports.

type capture struct {
	t      testing.TB
	iface  string
	file   string
	cmd    *exec.Cmd
	cancel context.CancelFunc
}

func physicalIface(t testing.TB) string {
	out, err := run("", "ip", "-o", "route", "get", "1.1.1.1")
	if err != nil {
		t.Fatalf("route get: %v %s", err, out)
	}
	m := regexp.MustCompile(` dev (\S+)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no default interface in %q", out)
	}
	return m[1]
}

// tailscalePorts returns the local UDP ports owned by tailscaled.
func tailscalePorts() []string {
	out, _ := run("", "ss", "-Hulpn")
	var ports []string
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "tailscaled") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		local := f[3]
		p := local[strings.LastIndex(local, ":")+1:]
		if p != "" && p != "*" && !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	return ports
}

func startCapture(t testing.TB) *capture {
	t.Helper()
	iface := physicalIface(t)
	dir, _ := os.MkdirTemp("", "vpncell-cap-")
	file := filepath.Join(dir, "cap.pcap")
	filter := ""
	if ps := tailscalePorts(); len(ps) > 0 {
		var parts []string
		for _, p := range ps {
			parts = append(parts, "udp port "+p)
		}
		filter = "not (" + strings.Join(parts, " or ") + ")"
	}
	ctx, cancel := context.WithCancel(context.Background())
	args := []string{"-i", iface, "-n", "-U", "-s", "0", "-Z", "root", "-w", file}
	if filter != "" {
		args = append(args, filter)
	}
	cmd := exec.CommandContext(ctx, "tcpdump", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("tcpdump: %v", err)
	}
	// Wait until tcpdump listens.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(stderr.String(), "listening on") {
		time.Sleep(50 * time.Millisecond)
	}
	return &capture{t: t, iface: iface, file: file, cmd: cmd, cancel: cancel}
}

func (c *capture) stop() {
	time.Sleep(500 * time.Millisecond)
	c.cmd.Process.Signal(os.Interrupt)
	done := make(chan struct{})
	go func() { c.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		c.cancel()
	}
}

// count returns the number of captured packets matching a pcap filter.
func (c *capture) count(filter string) (int, string) {
	out, _ := run("", "tcpdump", "-n", "-r", c.file, filter)
	lines := 0
	var sample []string
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) == "" || strings.HasPrefix(l, "reading from") {
			continue
		}
		lines++
		if len(sample) < 5 {
			sample = append(sample, l)
		}
	}
	return lines, strings.Join(sample, "\n")
}

// containsMarker reports whether any captured byte sequence contains the
// marker (DNS labels and HTTP payloads carry it in clear text).
func (c *capture) containsMarker(marker string) bool {
	data, err := os.ReadFile(c.file)
	if err != nil {
		c.t.Fatalf("read capture: %v", err)
	}
	return bytes.Contains(data, []byte(marker))
}

// assertNoLeaks checks the standard leak conditions.
func (c *capture) assertNoLeaks(markers ...string) {
	c.t.Helper()
	c.stop()
	if n, s := c.count("net 10.99.0.0/24 or net 10.200.0.0/16 or net 172.30.0.0/16 or net 10.0.70.0/24 or net 10.8.0.0/24"); n > 0 {
		c.t.Errorf("LEAK: %d packets to test destinations on %s:\n%s", n, c.iface, s)
	}
	if n, s := c.count(fmt.Sprintf("host %s and not (udp port 51820 or udp port 1194)", vmEndpoint)); n > 0 {
		c.t.Errorf("LEAK: %d non-tunnel packets to the VPN endpoint on %s:\n%s", n, c.iface, s)
	}
	for _, m := range markers {
		if c.containsMarker(m) {
			c.t.Errorf("LEAK: marker %q seen in clear text on %s", m, c.iface)
		}
	}
	os.RemoveAll(filepath.Dir(c.file))
}

// tunnelPackets counts packets to the VPN endpoint on the VPN ports.
func (c *capture) tunnelPackets() int {
	n, _ := c.count(fmt.Sprintf("host %s and (udp port 51820 or udp port 1194)", vmEndpoint))
	return n
}
