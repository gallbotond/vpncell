package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gallbotond/vpncell/internal/control"
)

func runGetent(uid string) (string, error) {
	out, err := exec.Command("getent", "passwd", uid).Output()
	return string(out), err
}

// ovpnFileDirectives take a file path as their first argument.
var ovpnFileDirectives = map[string]bool{
	"ca": true, "cert": true, "key": true, "tls-auth": true, "tls-crypt": true, "tls-crypt-v2": true,
	"pkcs12": true, "crl-verify": true, "auth-user-pass": true, "askpass": true, "extra-certs": true,
	"secret": true, "dh": true,
}

const maxImportFile = 1 << 20

func readLimited(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	if st.Size() > maxImportFile {
		return "", fmt.Errorf("%s is too large", path)
	}
	b, err := os.ReadFile(path)
	return string(b), err
}

// buildImport reads a config and, for OpenVPN, the files it references. The
// daemon decides what to keep; nothing here interprets the content.
func buildImport(name, path, authFile string) (*control.ImportRequest, error) {
	text, err := readLimited(path)
	if err != nil {
		return nil, err
	}
	req := &control.ImportRequest{Name: name, Kind: detectKind(path, text), Config: text, Files: map[string]string{}}
	if authFile != "" {
		a, err := readLimited(authFile)
		if err != nil {
			return nil, err
		}
		req.AuthFile = a
	}
	if req.Kind != "openvpn" {
		return req, nil
	}
	base := filepath.Dir(path)
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 2 || strings.HasPrefix(f[0], "#") || strings.HasPrefix(f[0], ";") {
			continue
		}
		dir := strings.ToLower(strings.TrimPrefix(f[0], "--"))
		if !ovpnFileDirectives[dir] {
			continue
		}
		ref := strings.Trim(f[1], `"'`)
		if ref == "[inline]" || (dir == "auth-user-pass" && ref == "") || ref == "stdin" {
			continue
		}
		p := ref
		if !filepath.IsAbs(p) {
			p = filepath.Join(base, p)
		}
		content, err := readLimited(p)
		if err != nil {
			return nil, fmt.Errorf("%s references %s: %w", dir, ref, err)
		}
		req.Files[ref] = content
	}
	return req, nil
}

func cmdFirefoxSetup(args []string) error {
	return fmt.Errorf("firefox-setup is not available yet")
}
