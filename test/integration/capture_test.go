//go:build integration

package integration

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Leak capture on the host's physical interface (DESIGN.md §15.3, with the
// change recorded in §12: no host firewall table is added). Tailscale's own
// traffic is excluded by the local UDP ports that tailscaled owns; nothing
// else is filtered at capture time. A leak is any packet that goes to a test
// destination, carries a marker string, or goes to the VPN endpoint on a
// port other than the VPN ports.

type capture struct {
	t       testing.TB
	iface   string
	file    string
	fd      int
	done    chan struct{}
	stopReq chan struct{}
	stopped bool
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
func tailscalePorts() map[uint16]bool {
	out, _ := run("", "ss", "-Hulpn")
	ports := map[uint16]bool{}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "tailscaled") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		local := f[3]
		var p uint16
		if _, err := fmt.Sscanf(local[strings.LastIndex(local, ":")+1:], "%d", &p); err == nil && p != 0 {
			ports[p] = true
		}
	}
	return ports
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// udpPorts returns the UDP source and destination ports of an Ethernet
// frame, if it is IPv4/IPv6 UDP without extension headers.
func udpPorts(fr []byte) (uint16, uint16, bool) {
	if len(fr) < 14 {
		return 0, 0, false
	}
	et := binary.BigEndian.Uint16(fr[12:14])
	p := fr[14:]
	switch et {
	case 0x0800:
		if len(p) < 20 || p[9] != 17 {
			return 0, 0, false
		}
		ihl := int(p[0]&0x0f) * 4
		if len(p) < ihl+4 {
			return 0, 0, false
		}
		return binary.BigEndian.Uint16(p[ihl:]), binary.BigEndian.Uint16(p[ihl+2:]), true
	case 0x86dd:
		if len(p) < 44 || p[6] != 17 {
			return 0, 0, false
		}
		return binary.BigEndian.Uint16(p[40:]), binary.BigEndian.Uint16(p[42:]), true
	}
	return 0, 0, false
}

// startCapture captures every frame on the physical interface (both
// directions) into a pcap file, from an AF_PACKET socket in this process.
// Frames to or from tailscaled's UDP ports are left out; nothing else is.
// (tcpdump is not used for capturing: its AppArmor profile refuses signals
// from the confined session that runs the tests, so it could not be stopped.)
func startCapture(t testing.TB) *capture {
	t.Helper()
	iface := physicalIface(t)
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		t.Fatalf("packet socket: %v", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifi.Index}); err != nil {
		t.Fatalf("bind packet socket: %v", err)
	}
	unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 8<<20)
	unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 100000})
	dir, _ := os.MkdirTemp("", "vpncell-cap-")
	file := filepath.Join(dir, "cap.pcap")
	f, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriter(f)
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:], 2)
	binary.LittleEndian.PutUint16(hdr[6:], 4)
	binary.LittleEndian.PutUint32(hdr[16:], 262144)
	binary.LittleEndian.PutUint32(hdr[20:], 1) // Ethernet
	w.Write(hdr)
	ts := tailscalePorts()
	c := &capture{t: t, iface: iface, file: file, fd: fd, done: make(chan struct{}), stopReq: make(chan struct{})}
	go func() {
		defer close(c.done)
		defer f.Close()
		defer w.Flush()
		buf := make([]byte, 262144)
		rec := make([]byte, 16)
		for {
			select {
			case <-c.stopReq:
				return
			default:
			}
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				continue // timeout: check for stop
			}
			if sp, dp, ok := udpPorts(buf[:n]); ok && (ts[sp] || ts[dp]) {
				continue
			}
			now := time.Now()
			binary.LittleEndian.PutUint32(rec[0:], uint32(now.Unix()))
			binary.LittleEndian.PutUint32(rec[4:], uint32(now.Nanosecond()/1000))
			binary.LittleEndian.PutUint32(rec[8:], uint32(n))
			binary.LittleEndian.PutUint32(rec[12:], uint32(n))
			w.Write(rec)
			w.Write(buf[:n])
		}
	}()
	t.Cleanup(c.stop)
	return c
}

func (c *capture) stop() {
	if c.stopped {
		return
	}
	c.stopped = true
	time.Sleep(500 * time.Millisecond)
	close(c.stopReq)
	<-c.done
	unix.Close(c.fd)
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
		if strings.HasPrefix(l, "tcpdump:") {
			c.t.Errorf("capture file problem: %s", l)
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
	if !bytes.Contains(data, []byte(marker)) {
		return false
	}
	// Show the packets that carry it.
	out, _ := run("", "tcpdump", "-n", "-r", c.file, "-A", "-s", "0")
	var pkt []string
	var hits []string
	flush := func() {
		if len(pkt) > 0 && strings.Contains(strings.Join(pkt, ""), marker) && len(hits) < 5 {
			hits = append(hits, pkt[0])
		}
	}
	for _, l := range strings.Split(out, "\n") {
		if len(l) > 15 && l[2] == ':' && l[5] == ':' {
			flush()
			pkt = []string{l}
		} else {
			pkt = append(pkt, l)
		}
	}
	flush()
	c.t.Logf("packets with marker %s:\n%s", marker, strings.Join(hits, "\n"))
	return true
}

// assertNoLeaks checks the standard leak conditions.
func (c *capture) assertNoLeaks(markers ...string) {
	c.t.Helper()
	c.stop()
	if n, s := c.count("net 10.99.0.0/24 or net 10.200.0.0/16 or net 172.30.0.0/16 or net 10.0.70.0/24 or net 10.8.0.0/24"); n > 0 {
		c.t.Errorf("LEAK: %d packets to test destinations on %s:\n%s", n, c.iface, s)
	}
	// ICMP errors that the host kernel sends back for tunnel packets from the
	// server (for example "port unreachable" when wg-easy keeps sending
	// keepalives to the closed port of an earlier client) quote a packet from
	// the VPN port; they carry no profile traffic.
	icmpErr := "(icmp6 and ip6[40] == 1 and (ip6[88:2] == 51820 or ip6[88:2] == 1194))"
	if n, s := c.count(fmt.Sprintf("host %s and not (udp port 51820 or udp port 1194) and not %s", vmEndpoint, icmpErr)); n > 0 {
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
