package importer

import (
	"errors"
	"strings"
)

// TLSCryptToTLSAuth rewrites an OpenVPN client config that carries its
// control-channel key as tls-crypt into tls-auth with key-direction 1, the
// same key. It is only for servers that use `tls-auth ta.key 0` while their
// config generator writes <tls-crypt> (issue #13, openvpn-ui); for a
// server that really uses tls-crypt it breaks the config. vpncell does
// this only when asked (`vpncell import --tls-auth`), never on its own.
func TLSCryptToTLSAuth(cfg string) (string, error) {
	lines := strings.Split(cfg, "\n")
	out := make([]string, 0, len(lines)+1)
	found := false
	for _, l := range lines {
		t := strings.TrimSpace(l)
		f := strings.Fields(t)
		switch {
		case strings.EqualFold(t, "<tls-crypt>"):
			out = append(out, "key-direction 1", "<tls-auth>")
			found = true
		case strings.EqualFold(t, "</tls-crypt>"):
			out = append(out, "</tls-auth>")
		case len(f) >= 1 && strings.EqualFold(strings.TrimPrefix(f[0], "--"), "key-direction"):
			// Replaced by the one written with the key.
		case len(f) >= 2 && strings.EqualFold(strings.TrimPrefix(f[0], "--"), "tls-crypt"):
			out = append(out, "tls-auth "+f[1]+" 1")
			found = true
		case len(f) >= 1 && strings.EqualFold(strings.TrimPrefix(f[0], "--"), "tls-auth"),
			strings.EqualFold(t, "<tls-auth>"):
			return "", errors.New("--tls-auth: the config already uses tls-auth")
		default:
			out = append(out, l)
		}
	}
	if !found {
		return "", errors.New("--tls-auth: the config has no tls-crypt key to convert")
	}
	return strings.Join(out, "\n"), nil
}
