package importer

import (
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestWGReachWarnings(t *testing.T) {
	// Keys are generated: no key material in the repository.
	k, _ := wgtypes.GeneratePrivateKey()
	peer, _ := wgtypes.GeneratePrivateKey()
	split := "[Interface]\nPrivateKey = " + k.String() + "\nAddress = 10.8.0.3/32\n\n[Peer]\nPublicKey = " +
		peer.PublicKey().String() + "\nAllowedIPs = 172.30.0.0/16\nEndpoint = 192.0.2.1:51820\n"
	cfg, _, err := ParseWireGuard(split)
	if err != nil {
		t.Fatal(err)
	}
	w := strings.Join(cfg.ReachWarnings(), "\n")
	if !strings.Contains(w, "reaches only 172.30.0.0/16; no IPv6") || !strings.Contains(w, "no DNS servers") {
		t.Fatalf("%s", w)
	}
	full := strings.Replace(split, "AllowedIPs = 172.30.0.0/16", "AllowedIPs = 0.0.0.0/0, ::/0", 1)
	full = strings.Replace(full, "Address = 10.8.0.3/32", "Address = 10.8.0.3/32\nDNS = 1.1.1.1", 1)
	cfg, _, _ = ParseWireGuard(full)
	if w := cfg.ReachWarnings(); len(w) != 0 {
		t.Fatalf("full tunnel warned: %v", w)
	}
	dnsOut := strings.Replace(split, "Address = 10.8.0.3/32", "Address = 10.8.0.3/32\nDNS = 8.8.8.8", 1)
	cfg, _, _ = ParseWireGuard(dnsOut)
	if w := strings.Join(cfg.ReachWarnings(), "\n"); !strings.Contains(w, "DNS server 8.8.8.8 is outside AllowedIPs") {
		t.Fatalf("%s", w)
	}
}

func TestOVPNReachWarnings(t *testing.T) {
	if w := (&OVPNConfig{Lines: []string{"client", "remote x 1194"}}).ReachWarnings(); len(w) != 1 || !strings.Contains(w[0], "redirect-gateway") {
		t.Fatal(w)
	}
	if w := (&OVPNConfig{Lines: []string{"client", "redirect-gateway def1"}}).ReachWarnings(); len(w) != 0 {
		t.Fatal(w)
	}
}
