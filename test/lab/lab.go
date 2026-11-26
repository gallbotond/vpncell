// Package lab is a local, test-only VPN lab (DESIGN.md §15.1). Each lab
// server is a network namespace "vclab-<name>" that acts as a VPN server with
// services behind 10.99.0.0/24 (the same range in every server, on purpose):
//
//	10.99.0.10      HTTP responder that names its server
//	10.99.0.53      DNS responder (web.lab.test is the same name everywhere,
//	                answered with a server-specific address)
//	10.99.0.(100+i) server-specific address, also served by the HTTP responder
//	fd99::10        the HTTP responder over IPv6
//
// The tunnel's encrypted side uses the host loopback (127.0.0.1), so the lab
// never adds addresses or routes to the host namespace.
package lab

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const NetnsPrefix = "vclab-"

// Server is one lab VPN server.
type Server struct {
	Name     string
	Kind     string // "wireguard" | "openvpn"
	Index    int
	Port     int
	SvcIP    netip.Addr // server-specific service address 10.99.0.(100+i)
	TunAddr4 netip.Prefix
	TunAddr6 netip.Prefix
	// ClientConfig is the path of the generated client config.
	ClientConfig string
	// RevokedClientConfig (OpenVPN only) uses a client certificate that
	// the server's CRL revokes.
	RevokedClientConfig string

	lab       *Lab
	listeners []net.Listener
	udp       []net.PacketConn
	stop      []func()
	ovpn      *os.Process
}

// Lab holds all lab servers.
type Lab struct {
	Dir     string
	Servers map[string]*Server
	mu      sync.Mutex
	dnsLog  map[string][]string // server -> queried names
	httpLog map[string][]string // server -> "remote host path"
}

func New(dir string) *Lab {
	return &Lab{Dir: dir, Servers: map[string]*Server{}, dnsLog: map[string][]string{}, httpLog: map[string][]string{}}
}

func nsPath(name string) string { return "/run/netns/" + NetnsPrefix + name }

// inNS runs fn on a thread inside the lab namespace; the thread is never
// returned to the scheduler.
func inNS(name string, fn func() error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		fd, err := unix.Open(nsPath(name), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			errc <- err
			return
		}
		err = unix.Setns(fd, unix.CLONE_NEWNET)
		unix.Close(fd)
		if err != nil {
			errc <- err
			return
		}
		errc <- fn()
	}()
	return <-errc
}

func createNS(name string) error {
	os.MkdirAll("/run/netns", 0o755)
	p := nsPath(name)
	deleteNS(name)
	f, err := os.Create(p)
	if err != nil {
		return err
	}
	f.Close()
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			errc <- err
			return
		}
		errc <- unix.Mount(fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid()), p, "none", unix.MS_BIND, "")
	}()
	return <-errc
}

func deleteNS(name string) {
	unix.Unmount(nsPath(name), unix.MNT_DETACH)
	os.Remove(nsPath(name))
}

func ipnet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

// setupServices creates the dummy service interface and starts the HTTP and
// DNS responders inside the server namespace.
func (s *Server) setupServices() error {
	addrs := []netip.Prefix{
		netip.MustParsePrefix("10.99.0.10/24"),
		netip.MustParsePrefix("10.99.0.53/32"),
		netip.PrefixFrom(s.SvcIP, 32),
		netip.MustParsePrefix("fd99::10/64"),
	}
	err := inNS(s.Name, func() error {
		lo, _ := netlink.LinkByName("lo")
		netlink.LinkSetUp(lo)
		d := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "svc0"}}
		if err := netlink.LinkAdd(d); err != nil {
			return err
		}
		l, err := netlink.LinkByName("svc0")
		if err != nil {
			return err
		}
		for _, a := range addrs {
			na := &netlink.Addr{IPNet: ipnet(a)}
			if a.Addr().Is6() {
				na.Flags = unix.IFA_F_NODAD
			}
			if err := netlink.AddrAdd(l, na); err != nil {
				return err
			}
		}
		if err := netlink.LinkSetUp(l); err != nil {
			return err
		}
		// Listeners are created here, inside the namespace.
		for _, a := range []string{"10.99.0.10:80", s.SvcIP.String() + ":80", "[fd99::10]:80"} {
			ln, err := net.Listen("tcp", a)
			if err != nil {
				return err
			}
			s.listeners = append(s.listeners, ln)
		}
		dl, err := net.Listen("tcp", "10.99.0.53:53")
		if err != nil {
			return err
		}
		s.listeners = append(s.listeners, dl)
		du, err := net.ListenPacket("udp", "10.99.0.53:53")
		if err != nil {
			return err
		}
		s.udp = append(s.udp, du)
		return nil
	})
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		s.lab.mu.Lock()
		s.lab.httpLog[s.Name] = append(s.lab.httpLog[s.Name], host+" "+r.Host+" "+r.URL.Path)
		s.lab.mu.Unlock()
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path == "/webrtc" {
			// WebRTC leak probe: gathers ICE candidates with a public STUN
			// server and lists them.
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, webrtcPage)
			return
		}
		if r.URL.Path == "/ip" {
			fmt.Fprintln(w, host)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<!doctype html><title>lab-server %s</title><body>lab-server %s<br>client %s<br>host %s</body>\n", s.Name, s.Name, host, r.Host)
	})
	for _, ln := range s.listeners[:3] {
		srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go srv.Serve(ln)
		s.stop = append(s.stop, func() { srv.Close() })
	}
	h := dns.HandlerFunc(s.serveDNS)
	tcpSrv := &dns.Server{Listener: s.listeners[3], Handler: h}
	udpSrv := &dns.Server{PacketConn: s.udp[0], Handler: h}
	go tcpSrv.ActivateAndServe()
	go udpSrv.ActivateAndServe()
	s.stop = append(s.stop, func() { tcpSrv.Shutdown(); udpSrv.Shutdown() })
	return nil
}

func (s *Server) serveDNS(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	for _, q := range req.Question {
		name := strings.ToLower(q.Name)
		s.lab.mu.Lock()
		s.lab.dnsLog[s.Name] = append(s.lab.dnsLog[s.Name], name)
		s.lab.mu.Unlock()
		switch {
		case (name == "web.lab.test." || name == "web.") && q.Qtype == dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5}, A: s.SvcIP.AsSlice()})
		case strings.HasSuffix(name, ".ok.lab.test."):
			// Any name under ok.lab.test resolves (lets tests use marker
			// names that work inside the profile).
			if q.Qtype == dns.TypeA {
				m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5}, A: s.SvcIP.AsSlice()})
			}
		case name == "svc.lab.test." && q.Qtype == dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5}, A: net.ParseIP("10.99.0.10")})
		case name == "svc6.lab.test." && q.Qtype == dns.TypeAAAA:
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 5}, AAAA: net.ParseIP("fd99::10")})
		case name == "id.lab.test." && q.Qtype == dns.TypeTXT:
			m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 5}, Txt: []string{s.Name}})
		case strings.HasSuffix(name, ".lab.test.") || name == "lab.test.":
			// Known zone, no data (NODATA for other types of known names).
			if !strings.HasPrefix(name, "web.") && !strings.HasPrefix(name, "svc") && !strings.HasPrefix(name, "id.") {
				m.Rcode = dns.RcodeNameError
			}
		default:
			m.Rcode = dns.RcodeNameError
		}
	}
	w.WriteMsg(m)
}

// DNSQueries returns the names a server's DNS responder was asked.
func (l *Lab) DNSQueries(server string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string{}, l.dnsLog[server]...)
}

// HTTPRequests returns "client host path" lines a server's HTTP responder saw.
func (l *Lab) HTTPRequests(server string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string{}, l.httpLog[server]...)
}

// AddWireGuard creates a WireGuard lab server.
func (l *Lab) AddWireGuard(name string, index int) (*Server, error) {
	s := &Server{Name: name, Kind: "wireguard", Index: index, Port: 51900 + index, lab: l,
		SvcIP:    netip.AddrFrom4([4]byte{10, 99, 0, byte(100 + index)}),
		TunAddr4: netip.MustParsePrefix(fmt.Sprintf("10.200.%d.1/24", index)),
		TunAddr6: netip.MustParsePrefix(fmt.Sprintf("fd00:200:%d::1/64", index)),
	}
	if err := createNS(name); err != nil {
		return nil, err
	}
	l.Servers[name] = s
	if err := s.setupServices(); err != nil {
		return nil, err
	}
	srvKey, _ := wgtypes.GeneratePrivateKey()
	cliKey, _ := wgtypes.GeneratePrivateKey()
	ifn := fmt.Sprintf("vclabwg%d", index)
	if l, err := netlink.LinkByName(ifn); err == nil {
		netlink.LinkDel(l)
	}
	if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: ifn}}); err != nil {
		return nil, err
	}
	wc, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	port := s.Port
	cli4 := netip.MustParsePrefix(fmt.Sprintf("10.200.%d.2/32", index))
	cli6 := netip.MustParsePrefix(fmt.Sprintf("fd00:200:%d::2/128", index))
	err = wc.ConfigureDevice(ifn, wgtypes.Config{PrivateKey: &srvKey, ListenPort: &port, ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{{PublicKey: cliKey.PublicKey(), AllowedIPs: []net.IPNet{*ipnet(cli4), *ipnet(cli6)}}}})
	wc.Close()
	if err != nil {
		return nil, err
	}
	link, err := netlink.LinkByName(ifn)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open(nsPath(name), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	err = netlink.LinkSetNsFd(link, fd)
	unix.Close(fd)
	if err != nil {
		return nil, err
	}
	err = inNS(name, func() error {
		l, err := netlink.LinkByName(ifn)
		if err != nil {
			return err
		}
		netlink.AddrAdd(l, &netlink.Addr{IPNet: ipnet(s.TunAddr4)})
		netlink.AddrAdd(l, &netlink.Addr{IPNet: ipnet(s.TunAddr6), Flags: unix.IFA_F_NODAD})
		return netlink.LinkSetUp(l)
	})
	if err != nil {
		return nil, err
	}
	conf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.200.%d.2/24, fd00:200:%d::2/64
DNS = 10.99.0.53, lab.test

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 127.0.0.1:%d
`, base64.StdEncoding.EncodeToString(cliKey[:]), index, index, srvKey.PublicKey().String(), port)
	os.MkdirAll(filepath.Join(l.Dir, "clients"), 0o700)
	s.ClientConfig = filepath.Join(l.Dir, "clients", name+".conf")
	if err := os.WriteFile(s.ClientConfig, []byte(conf), 0o600); err != nil {
		return nil, err
	}
	return s, nil
}

// Close tears the lab down.
func (l *Lab) Close() {
	for name, s := range l.Servers {
		for _, f := range s.stop {
			f()
		}
		for _, ln := range s.listeners {
			ln.Close()
		}
		for _, u := range s.udp {
			u.Close()
		}
		if s.ovpn != nil {
			s.ovpn.Kill()
			s.ovpn.Wait()
		}
		deleteNS(name)
	}
	// Host-side leftovers (none expected: links move into the lab netns).
	links, _ := netlink.LinkList()
	for _, lk := range links {
		if strings.HasPrefix(lk.Attrs().Name, "vclab") {
			netlink.LinkDel(lk)
		}
	}
}

// Cleanup removes leftovers of a previous run.
func Cleanup() {
	ents, _ := os.ReadDir("/run/netns")
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), NetnsPrefix) {
			deleteNS(strings.TrimPrefix(e.Name(), NetnsPrefix))
		}
	}
	links, _ := netlink.LinkList()
	for _, lk := range links {
		if strings.HasPrefix(lk.Attrs().Name, "vclab") {
			netlink.LinkDel(lk)
		}
	}
}

var _ = context.Background

const webrtcPage = `<!doctype html><title>webrtc probe</title><body><pre id="c">pending</pre><script>
const out = [];
const pc = new RTCPeerConnection({iceServers: [{urls: "stun:stun.l.google.com:19302"}]});
pc.createDataChannel("x");
const done = () => { document.getElementById("c").textContent = "DONE\n" + (out.join("\n") || "no-candidates"); };
pc.onicecandidate = (e) => { if (e.candidate && e.candidate.candidate) out.push(e.candidate.candidate); else done(); };
pc.createOffer().then((o) => pc.setLocalDescription(o)).catch((e) => { out.push("error " + e); done(); });
setTimeout(done, 8000);
</script></body>`
