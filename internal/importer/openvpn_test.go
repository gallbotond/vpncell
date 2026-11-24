package importer

import (
	"strings"
	"testing"
)

const goodOVPN = `client
dev tun
proto udp
remote 2600:1900:4021:668:: 1194 udp
resolv-retry infinite
user nobody
group nogroup
persist-tun
persist-key
remote-cert-tls server
cipher AES-256-GCM
auth SHA512
auth-nocache
tls-client
verb 3
key-direction 1
<ca>
-----BEGIN CERTIFICATE-----
MIIBCA==
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
MIIBCB==
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
MIIBCC==
-----END PRIVATE KEY-----
</key>
<tls-auth>
-----BEGIN OpenVPN Static key V1-----
abcd
-----END OpenVPN Static key V1-----
</tls-auth>
`

func TestParseOpenVPNGood(t *testing.T) {
	cfg, rep, err := ParseOpenVPN(goodOVPN, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	out := cfg.Render("/etc/vpncell/secrets/x")
	for _, bad := range []string{"user nobody", "group", "persist-tun", "resolv-retry", "BEGIN"} {
		if strings.Contains(out, bad) {
			t.Errorf("render contains %q:\n%s", bad, out)
		}
	}
	if !strings.Contains(out, `ca "/etc/vpncell/secrets/x/ca.pem"`) || !strings.Contains(out, `tls-auth "/etc/vpncell/secrets/x/tls-auth.pem"`) {
		t.Errorf("file references not rewritten:\n%s", out)
	}
	st := strings.Join(rep.Stripped, "\n")
	for _, k := range []string{"user", "group", "persist-tun", "resolv-retry", "dev"} {
		if !strings.Contains(st, k+" (line") {
			t.Errorf("%s not reported as stripped: %s", k, st)
		}
	}
	if len(cfg.Files) != 4 {
		t.Errorf("files: %v", cfg.FileNames())
	}
}

func TestParseOpenVPNRejects(t *testing.T) {
	for name, extra := range map[string]string{
		"up":              "up /tmp/canary\n",
		"down":            "down /tmp/canary\n",
		"route-up":        "route-up /tmp/canary\n",
		"plugin":          "plugin /usr/lib/x.so\n",
		"script-security": "script-security 3\n",
		"tls-verify":      "tls-verify /bin/true\n",
		"learn-address":   "learn-address /bin/true\n",
		"ipchange":        "ipchange /bin/true\n",
		"config":          "config /etc/other.conf\n",
		"management":      "management 0.0.0.0 7505\n",
		"dev-node":        "dev-node /dev/net/tun\n",
		"auth-interact":   "auth-user-pass\n",
		"static-chal":     "static-challenge \"OTP\" 1\n",
		"auth-retry":      "auth-retry interact\n",
		"tap":             "dev tap\n",
		"http-proxy":      "http-proxy 10.0.0.1 3128\n",
		"dns-updown":      "dns-updown /bin/sh\n",
		"unknown":         "frobnicate yes\n",
		"bad inline":      "<connection>\nremote x 1\n</connection>\n",
		"route-noexec":    "route-noexec\n",
	} {
		_, _, err := ParseOpenVPN(goodOVPN+extra, nil, "")
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	enc := strings.Replace(goodOVPN, "BEGIN PRIVATE KEY", "BEGIN ENCRYPTED PRIVATE KEY", 1)
	if _, _, err := ParseOpenVPN(enc, nil, ""); err == nil {
		t.Errorf("encrypted key accepted")
	}
}

func TestParseOpenVPNAuth(t *testing.T) {
	c := goodOVPN + "auth-user-pass creds.txt\n"
	if _, _, err := ParseOpenVPN(c, nil, ""); err == nil {
		t.Fatal("missing auth file accepted")
	}
	cfg, _, err := ParseOpenVPN(c, map[string]string{"creds.txt": "alice\nsecret\n"}, "")
	if err != nil || cfg.AuthUser != "alice" || cfg.AuthPass != "secret" {
		t.Fatalf("auth file: %v %+v", err, cfg)
	}
	cfg, _, err = ParseOpenVPN(goodOVPN+"auth-user-pass\n", nil, "bob\npw\n")
	if err != nil || cfg.AuthUser != "bob" {
		t.Fatalf("--auth-file: %v", err)
	}
	if strings.Contains(cfg.Render("/s"), "pw") {
		t.Fatalf("password in rendered config")
	}
}

func FuzzParseOpenVPN(f *testing.F) {
	f.Add(goodOVPN)
	f.Add("up /x\n")
	f.Fuzz(func(t *testing.T, s string) {
		cfg, _, err := ParseOpenVPN(s, nil, "")
		if err != nil {
			return
		}
		out := cfg.Render("/s")
		for _, l := range strings.Split(out, "\n") {
			f := strings.Fields(l)
			if len(f) == 0 || strings.HasPrefix(f[0], "#") {
				continue
			}
			d := f[0]
			if _, bad := ovpnReject[d]; bad {
				t.Fatalf("rejected directive %q rendered", d)
			}
			if ovpnStrip[d] != "" {
				t.Fatalf("stripped directive %q rendered", d)
			}
		}
	})
}
