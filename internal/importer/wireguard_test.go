package importer

import (
	"strings"
	"testing"
)

const goodWG = `[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.8.0.4/32, fdcc::4/128
DNS = 10.0.0.53, corp.example
MTU = 1380
PostUp = iptables -A FORWARD -j ACCEPT # comment
Table = off

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
PresharedKey = 4AQZf2oVxmTI0nNNdGJGcl6Gz/3kTqdFJ0AQ3Snp0pE=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = [2600:1900:4021:668::]:51820
PersistentKeepalive = 25
`

func TestParseWireGuardStripsHooks(t *testing.T) {
	cfg, rep, err := ParseWireGuard(goodWG)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.DNSServers) != 1 || cfg.DNSSearch[0] != "corp.example" || cfg.MTU != 1380 {
		t.Fatalf("parsed wrong: %+v", cfg)
	}
	joined := strings.Join(rep.Stripped, "\n")
	for _, k := range []string{"PostUp", "Table"} {
		if !strings.Contains(joined, k) {
			t.Errorf("%s not reported as stripped: %s", k, joined)
		}
	}
	out := cfg.Render()
	if strings.Contains(out, "PostUp") || strings.Contains(out, "iptables") || strings.Contains(out, "Table") {
		t.Fatalf("render kept a stripped key:\n%s", out)
	}
	// Secrets never in the report.
	all := strings.Join(rep.Kept, "\n") + joined
	if strings.Contains(all, "yAnz5TF") || strings.Contains(all, "4AQZf2") {
		t.Fatalf("report contains a secret")
	}
	// Round trip.
	cfg2, _, err := ParseWireGuard(out)
	if err != nil || cfg2.Render() != out {
		t.Fatalf("round trip failed: %v", err)
	}
}

func TestParseWireGuardRejects(t *testing.T) {
	cases := map[string]string{
		"amnezia":        strings.Replace(goodWG, "MTU", "Jc = 3\nMTU", 1),
		"unknown key":    strings.Replace(goodWG, "MTU", "Foo = bar\nMTU", 1),
		"bad section":    goodWG + "[Hooks]\n",
		"bad key":        strings.Replace(goodWG, "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=", "abc", 1),
		"no peer":        strings.Split(goodWG, "[Peer]")[0],
		"v6 no brackets": strings.Replace(goodWG, "[2600:1900:4021:668::]:51820", "2600:1900:4021:668:::51820", 1),
		"bad dns":        strings.Replace(goodWG, "10.0.0.53, corp.example", "$(reboot)", 1),
	}
	for name, c := range cases {
		if _, _, err := ParseWireGuard(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func FuzzParseWireGuard(f *testing.F) {
	f.Add(goodWG)
	f.Add("[Interface]\nPrivateKey=\n")
	f.Fuzz(func(t *testing.T, s string) {
		cfg, _, err := ParseWireGuard(s)
		if err != nil {
			return
		}
		out := cfg.Render()
		for _, bad := range []string{"PostUp", "PreUp", "PostDown", "PreDown", "Table", "SaveConfig", "FwMark"} {
			if strings.Contains(out, bad) {
				t.Fatalf("render contains %s", bad)
			}
		}
		if _, _, err := ParseWireGuard(out); err != nil {
			t.Fatalf("render does not parse: %v\n%s", err, out)
		}
	})
}
