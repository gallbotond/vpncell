//go:build integration

package integration

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func forEachBrowser(t *testing.T, fn func(t *testing.T, k browserKind)) {
	kinds := browserKinds()
	if len(kinds) == 0 {
		t.Fatal("no Firefox found (test/firefox tarball or the snap)")
	}
	for _, k := range kinds {
		k := k
		t.Run(k.name, func(t *testing.T) { fn(t, k) })
	}
}

// hostServers starts a dev server on the host's loopback and one on its LAN
// address (both reachable only directly).
func hostServers(t *testing.T) (loop, lan string) {
	mk := func(addr, body string) string {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }))
		return ln.Addr().String()
	}
	ip, _ := hostLAN(t)
	return mk("127.0.0.1:0", "HOST-DEV-SERVER"), mk(ip+":0", "HOST-LAN-SERVER")
}

// Required tests "Browser", "Isolation" (container part), "No sharing
// between containers", "Default tabs and private windows", "No host or LAN
// access" (container part).
func TestBrowserContainers(t *testing.T) {
	loop, lan := hostServers(t)
	forEachBrowser(t, func(t *testing.T, k browserKind) {
		b := startBrowser(t, k, nil)
		for _, s := range labSets() {
			s := s
			t.Run(s.name, func(t *testing.T) {
				ensureUp(t, s.a, s.b)
				ca, cb := b.createContainer("vc-"+s.a), b.createContainer("vc-"+s.b)
				defer b.removeContainer(ca)
				defer b.removeContainer(cb)
				b.mapContainer(ca, s.a)
				b.mapContainer(cb, s.b)
				// Each container reaches its own server at the overlapping address.
				for _, x := range []struct {
					c      int
					server string
				}{{ca, s.sa}, {cb, s.sb}} {
					r := b.load(x.c, false, "http://10.99.0.10/", 20*time.Second)
					if !r.ok || !strings.Contains(r.text, "lab-server "+x.server) {
						t.Errorf("container %d: want %s, got %+v", x.c, x.server, r)
					}
				}
				// Same hostname, different server behind each tunnel, loaded
				// at the same time and repeatedly; no reuse of connections,
				// cache or DNS across containers.
				for i := 0; i < 3; i++ {
					res := b.loadParallel([]int{ca, cb, ca, cb}, "http://web.lab.test/", 20*time.Second)
					for j, c := range []int{ca, cb, ca, cb} {
						want := s.sa
						if c == cb {
							want = s.sb
						}
						if !strings.Contains(res[j].text, "lab-server "+want+"<") && !strings.Contains(res[j].text, "lab-server "+want+"\n") {
							t.Errorf("round %d tab %d: web.lab.test in container %d: want %s, got %q", i, j, c, want, trim(res[j].text))
						}
					}
				}
				// Default tab and private window: direct (they reach the host
				// LAN server), even though containers are mapped.
				if r := b.load(0, false, "http://"+lan+"/", 15*time.Second); !r.ok || !strings.Contains(r.text, "HOST-LAN-SERVER") {
					t.Errorf("default tab not direct: %+v", r)
				}
				if r := b.load(0, true, "http://"+lan+"/", 15*time.Second); !r.ok || !strings.Contains(r.text, "HOST-LAN-SERVER") {
					t.Errorf("private window not direct: %+v", r)
				}
				// Mapped containers reach neither the host's loopback nor its LAN.
				for _, u := range []string{"http://" + loop + "/", "http://localhost:" + strings.Split(loop, ":")[1] + "/", "http://" + lan + "/"} {
					if r := b.load(ca, false, u, 15*time.Second); r.ok || strings.Contains(r.text, "HOST-") {
						t.Errorf("mapped container reached %s: %+v", u, r)
					}
				}
				// An unmapped container is direct too.
				cu := b.createContainer("vc-unmapped")
				defer b.removeContainer(cu)
				if r := b.load(cu, false, "http://"+lan+"/", 15*time.Second); !r.ok {
					t.Errorf("unmapped container not direct: %+v", r)
				}
			})
		}
		// Exit IP per container through the real VPN.
		for _, p := range vmProfiles() {
			ensureUp(t, p)
			c := b.createContainer("vc-" + p)
			b.mapContainer(c, p)
			r := b.load(c, false, "https://ifconfig.me/ip", 30*time.Second)
			if !r.ok || strings.TrimSpace(r.text) != vmEndpoint {
				t.Errorf("%s exit IP in container: %+v", p, r)
			}
			b.removeContainer(c)
		}
	})
}

var _ = fmt.Sprint

// mappedBrowser starts a browser with containers mapped to s.a and s.b.
func mappedBrowser(t *testing.T, k browserKind, s profileSet, prefs map[string]any) (*browser, int, int) {
	b := startBrowser(t, k, prefs)
	ensureUp(t, s.a, s.b)
	ca, cb := b.createContainer("vc-"+s.a), b.createContainer("vc-"+s.b)
	b.mapContainer(ca, s.a)
	b.mapContainer(cb, s.b)
	return b, ca, cb
}

// Required tests "Browser" (fail closed with the daemon stopped) and "Fail
// closed" (container part): a mapped container never goes direct, neither
// while the daemon is down (grace period and after) nor with the tunnel
// removed; the toolbar shows the problem.
func TestBrowserFailClosed(t *testing.T) {
	_, lan := hostServers(t)
	forEachBrowser(t, func(t *testing.T, k browserKind) {
		s := labSets()[0]
		b, ca, _ := mappedBrowser(t, k, s, nil)
		if r := b.load(ca, false, "http://10.99.0.10/", 20*time.Second); !r.ok {
			t.Fatalf("baseline: %+v", r)
		}
		mk := marker()
		probes := []string{"http://" + lan + "/" + mk, "http://1.1.1.1/" + mk, "http://" + mk + ".example.com/"}
		cap := startCapture(t)
		// Tunnel removed.
		netnsExec(s.a, "ip", "link", "del", tunnelIf(t, s.a))
		for _, u := range probes {
			if r := b.load(ca, false, u, 15*time.Second); r.ok {
				t.Errorf("tunnel removed: %s loaded: %q", u, trim(r.text))
			}
		}
		waitFor(t, 60*time.Second, "tunnel restored", func() bool { return b.load(ca, false, "http://10.99.0.10/", 10*time.Second).ok })
		// Daemon stopped: first within the grace period, then after it.
		if out, err := sh("systemctl stop vpncelld"); err != nil {
			t.Fatalf("stop: %v %s", err, out)
		}
		defer sh("systemctl start vpncelld")
		for _, u := range probes {
			if r := b.load(ca, false, u, 10*time.Second); r.ok {
				t.Errorf("daemon stopped (grace): %s loaded: %q", u, trim(r.text))
			}
		}
		time.Sleep(32 * time.Second)
		for _, u := range append(probes, "http://10.99.0.10/") {
			start := time.Now()
			r := b.load(ca, false, u, 15*time.Second)
			if r.ok {
				t.Errorf("daemon stopped: %s loaded: %q", u, trim(r.text))
			}
			if !strings.HasPrefix(r.text, "about:neterror") {
				t.Errorf("daemon stopped: want a proxy error page, got %q after %v", r.text, time.Since(start))
			}
		}
		st := b.popupState()
		if prob, _ := st["problems"].(map[string]any); prob[s.a] == nil || st["daemonUp"] != false {
			t.Errorf("popup does not show the problem: %v", st)
		}
		// Default tabs keep working while the daemon is down.
		if r := b.load(0, false, "http://"+lan+"/", 15*time.Second); !r.ok {
			t.Errorf("default tab broken while daemon down: %+v", r)
		}
		cap.assertNoLeaks(mk)
		// Back up: the container works again without user action.
		sh("systemctl start vpncelld")
		waitFor(t, 60*time.Second, "container works again", func() bool { return b.load(ca, false, "http://10.99.0.10/", 10*time.Second).ok })
	})
}

// Required test "Daemon restart" (container part).
func TestBrowserDaemonRestart(t *testing.T) {
	forEachBrowser(t, func(t *testing.T, k browserKind) {
		s := labSets()[0]
		b, ca, cb := mappedBrowser(t, k, s, nil)
		cap := startCapture(t)
		for _, how := range []string{"systemctl restart vpncelld", "systemctl kill -s KILL vpncelld"} {
			// Start loads, restart while they are in flight, then keep loading.
			h := b.openTab(ca, false, "http://10.99.0.10/?during-"+strings.Fields(how)[1])
			if out, err := sh(how); err != nil {
				t.Fatalf("%s: %v %s", how, err, out)
			}
			for i := 0; i < 5; i++ {
				res := b.loadParallel([]int{ca, cb}, fmt.Sprintf("http://10.99.0.10/?n=%d", i), 30*time.Second)
				if !strings.Contains(res[0].text, "lab-server "+s.sa) || !strings.Contains(res[1].text, "lab-server "+s.sb) {
					t.Errorf("%s, load %d: %+v", how, i, res)
				}
				time.Sleep(500 * time.Millisecond)
			}
			if r := b.readTab(h, 30*time.Second); !strings.Contains(r.text, "lab-server "+s.sa) {
				t.Errorf("%s: load in flight during the restart: %+v", how, r)
			}
			b.closeTab(h, false)
		}
		cap.assertNoLeaks()
	})
}

// Traffic that could bypass the proxy (DESIGN.md §9.6): prediction and
// prefetch are off, WebRTC sends no UDP outside the proxy, HTTP/3 is not
// used through SOCKS, and names never go to DNS-over-HTTPS.
func TestBrowserLeakPaths(t *testing.T) {
	forEachBrowser(t, func(t *testing.T, k browserKind) {
		s := labSets()[0]
		b, ca, _ := mappedBrowser(t, k, s, nil)
		var prefs map[string]any
		err := b.chrome(`const P = Services.prefs;
const g = (n) => { switch (P.getPrefType(n)) { case P.PREF_BOOL: return P.getBoolPref(n); case P.PREF_INT: return P.getIntPref(n); case P.PREF_STRING: return P.getStringPref(n); } return "unset"; };
return {
predictor: g("network.predictor.enabled"),
prefetchNext: g("network.prefetch-next"),
dnsPrefetchOff: g("network.dns.disablePrefetch"),
speculative: g("network.http.speculative-parallel-limit"),
iceDefaultOnly: g("media.peerconnection.ice.default_address_only"),
iceNoHost: g("media.peerconnection.ice.no_host"),
iceProxyIfBehind: g("media.peerconnection.ice.proxy_only_if_behind_proxy"),
failoverDirect: g("network.proxy.failover_direct")};`, nil, &prefs)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("prefs: %v", prefs)
		want := map[string]any{"predictor": false, "prefetchNext": false, "dnsPrefetchOff": true, "speculative": float64(0),
			"iceDefaultOnly": true, "iceNoHost": true, "iceProxyIfBehind": true}
		for key, v := range want {
			if prefs[key] != v && !(key == "predictor" && prefs[key] == "unset") {
				// (network.predictor.enabled no longer exists in Firefox 161.)
				t.Errorf("pref %s = %v, want %v", key, prefs[key], v)
			}
		}
		// WebRTC in a mapped container: no UDP to the STUN server, no host
		// address in the candidates.
		lanIP, _ := hostLAN(t)
		cap := startCapture(t)
		h := b.openTab(ca, false, "http://10.99.0.10/webrtc")
		var text string
		waitFor(t, 30*time.Second, "webrtc probe done", func() bool {
			r := b.readTab(h, 2*time.Second)
			text = r.text
			return strings.HasPrefix(r.text, "DONE")
		})
		b.closeTab(h, false)
		cap.stop()
		t.Logf("candidates in container: %q", text)
		if strings.Contains(text, lanIP) || strings.Contains(text, "srflx") {
			t.Errorf("WebRTC candidates expose a non-proxied path: %q", text)
		}
		if n, sample := cap.count("udp port 19302"); n > 0 {
			t.Errorf("LEAK: %d STUN packets from a mapped container:\n%s", n, sample)
		}
		cap.assertNoLeaks()
		// HTTP/3: a site that offers h3 (Alt-Svc) is loaded twice in a
		// container mapped to the VM profile; no UDP/443 leaves the host.
		for _, p := range vmProfiles() {
			ensureUp(t, p)
			c := b.createContainer("vc-quic-" + p)
			b.mapContainer(c, p)
			cap := startCapture(t)
			for i := 0; i < 2; i++ {
				if r := b.load(c, false, "https://cloudflare-quic.com/", 40*time.Second); !r.ok {
					t.Logf("%s: cloudflare-quic.com load %d: %+v", p, i, r)
				}
			}
			cap.stop()
			// Only the test site's addresses count: other programs on the
			// host (the desktop's own browser) use QUIC too.
			ips := lookupRetry("cloudflare-quic.com")
			var hf []string
			for _, ip := range ips {
				hf = append(hf, "host "+ip)
			}
			if len(hf) == 0 {
				t.Fatalf("cannot resolve cloudflare-quic.com on the host")
			}
			if n, sample := cap.count("udp port 443 and (" + strings.Join(hf, " or ") + ")"); n > 0 {
				t.Errorf("LEAK: %d UDP/443 (QUIC) packets while loading through %s:\n%s", n, p, sample)
			}
			cap.assertNoLeaks()
			b.removeContainer(c)
		}
	})
}

// DNS-over-HTTPS (TRR-only mode) does not see names from mapped containers:
// lab names, which public DoH cannot resolve, load through the proxy.
func TestBrowserTRR(t *testing.T) {
	forEachBrowser(t, func(t *testing.T, k browserKind) {
		s := labSets()[0]
		b, ca, cb := mappedBrowser(t, k, s, map[string]any{
			"network.trr.mode": 3,
			"network.trr.uri":  "https://mozilla.cloudflare-dns.com/dns-query",
		})
		mk := marker()
		cap := startCapture(t)
		res := b.loadParallel([]int{ca, cb}, "http://web.lab.test/", 20*time.Second)
		if !strings.Contains(res[0].text, "lab-server "+s.sa) || !strings.Contains(res[1].text, "lab-server "+s.sb) {
			t.Errorf("TRR-only: lab names in containers: %+v", res)
		}
		b.load(ca, false, "http://"+mk+".lab.test/", 10*time.Second)
		if q := strings.Join(theLab.DNSQueries(s.sa), " "); !strings.Contains(q, mk) {
			t.Errorf("marker lookup did not reach the profile's DNS")
		}
		cap.assertNoLeaks(mk)
	})
}

// Mapping lifecycle: a deleted container loses its mapping, a renamed one
// keeps it (DESIGN.md §9.2).
func TestBrowserMappingLifecycle(t *testing.T) {
	forEachBrowser(t, func(t *testing.T, k browserKind) {
		s := labSets()[0]
		b := startBrowser(t, k, nil)
		ensureUp(t, s.a)
		c := b.createContainer("vc-life")
		b.mapContainer(c, s.a)
		b.chrome(`const ContextualIdentityService = (() => { for (const u of ["moz-src:///toolkit/components/contextualidentity/ContextualIdentityService.sys.mjs", "resource://gre/modules/ContextualIdentityService.sys.mjs"]) { try { return ChromeUtils.importESModule(u).ContextualIdentityService; } catch (e) {} } })();
ContextualIdentityService.update(arguments[0], "vc-renamed", "fingerprint", "red");`, []any{c}, nil)
		time.Sleep(time.Second)
		m, _ := b.popupState()["mapping"].(map[string]any)
		if m[cookieStore(c)] != s.a {
			t.Errorf("rename lost the mapping: %v", m)
		}
		if r := b.load(c, false, "http://10.99.0.10/", 20*time.Second); !strings.Contains(r.text, "lab-server "+s.sa) {
			t.Errorf("renamed container: %+v", r)
		}
		b.removeContainer(c)
		waitFor(t, 10*time.Second, "mapping removed", func() bool {
			m, _ := b.popupState()["mapping"].(map[string]any)
			_, ok := m[cookieStore(c)]
			return !ok
		})
	})
}

// A mapped container's hostnames must never reach the host resolver. With
// Firefox's defaults, HTTPS-First looks up the HTTPS record of every http://
// navigation itself, outside the proxy; `vpncell firefox-policy install`
// turns that off. This test uses the system's real Firefox configuration
// (no test pref), so it fails until that policy is installed.
func TestBrowserHTTPNameNoHostDNS(t *testing.T) {
	forEachBrowser(t, func(t *testing.T, k browserKind) {
		s := labSets()[0]
		b, ca, _ := mappedBrowser(t, k, s, map[string]any{"network.dns.native_https_query": nil})
		policy, _ := os.ReadFile("/etc/firefox/policies/policies.json")
		installed := strings.Contains(string(policy), "network.dns.native_https_query")
		for _, u := range []string{"http://%s.ok.lab.test/", "http://%s.example.com/", "https://%s.ok.lab.test/"} {
			mk := marker()
			cap := startCapture(t)
			b.load(ca, false, fmt.Sprintf(u, mk), 20*time.Second)
			time.Sleep(2 * time.Second)
			cap.stop()
			if cap.containsMarker(mk) {
				if !installed {
					t.Errorf("KNOWN FAILURE (needs the user's decision): %s in a mapped container sent the hostname to the host resolver "+
						"(HTTPS-record lookup by HTTPS-First). Fix: sudo vpncell firefox-policy install (README \"Firefox\").", u)
				} else {
					t.Errorf("LEAK: %s in a mapped container sent the hostname to the host resolver although the policy is installed", u)
				}
			}
		}
	})
}

// lookupRetry resolves a name on the host, retrying transient failures of
// the host resolver.
func lookupRetry(name string) []string {
	for i := 0; i < 10; i++ {
		if ips, err := net.LookupHost(name); err == nil && len(ips) > 0 {
			return ips
		}
		time.Sleep(time.Second)
	}
	return nil
}
