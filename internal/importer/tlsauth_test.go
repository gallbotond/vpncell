package importer

import (
	"strings"
	"testing"
)

func TestTLSCryptToTLSAuth(t *testing.T) {
	in := "client\nremote x 1194\nkey-direction 0\n<tls-crypt>\n-----BEGIN OpenVPN Static key V1-----\nabc\n-----END OpenVPN Static key V1-----\n</tls-crypt>\n"
	out, err := TLSCryptToTLSAuth(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "key-direction 1\n<tls-auth>\n-----BEGIN OpenVPN Static key V1-----\nabc\n") ||
		!strings.Contains(out, "</tls-auth>") || strings.Contains(out, "tls-crypt") || strings.Contains(out, "key-direction 0") {
		t.Fatalf("%s", out)
	}
	out, err = TLSCryptToTLSAuth("client\ntls-crypt ta.key\n")
	if err != nil || !strings.Contains(out, "tls-auth ta.key 1") {
		t.Fatalf("%v %s", err, out)
	}
	// The result is still accepted by the importer.
	if _, _, err := ParseOpenVPN(out, map[string]string{"ta.key": "-----BEGIN OpenVPN Static key V1-----\nabc\n-----END OpenVPN Static key V1-----\n"}, ""); err != nil && strings.Contains(err.Error(), "tls-auth") {
		t.Fatalf("importer rejects the rewrite: %v", err)
	}
	if _, err := TLSCryptToTLSAuth("client\n<tls-auth>\nk\n</tls-auth>\n"); err == nil {
		t.Fatal("tls-auth config converted")
	}
	if _, err := TLSCryptToTLSAuth("client\n"); err == nil {
		t.Fatal("config without a key converted")
	}
}
