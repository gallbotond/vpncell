package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gallbotond/vpncell/internal/brand"
	"github.com/gallbotond/vpncell/internal/control"
	"github.com/gallbotond/vpncell/internal/importer"
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
func buildImport(name, path, authFile string, tlsAuth bool) (*control.ImportRequest, error) {
	text, err := readLimited(path)
	if err != nil {
		return nil, err
	}
	return buildImportText(name, detectKind(path, text), text, filepath.Dir(path), authFile, tlsAuth)
}

// buildImportText builds an import from config text of the given kind;
// relative file references are read from base.
func buildImportText(name, kind, text, base, authFile string, tlsAuth bool) (*control.ImportRequest, error) {
	var err error
	if tlsAuth {
		if kind != "openvpn" {
			return nil, fmt.Errorf("--tls-auth is for OpenVPN configs")
		}
		if text, err = importer.TLSCryptToTLSAuth(text); err != nil {
			return nil, err
		}
	}
	req := &control.ImportRequest{Name: name, Kind: kind, Config: text, Files: map[string]string{}}
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

// nativeManifest is the Firefox native messaging manifest for vpncell-native.
func nativeManifest(path string) string {
	return fmt.Sprintf(`{
  "name": %q,
  "description": "vpncell native messaging host",
  "path": %q,
  "type": "stdio",
  "allowed_extensions": [%q]
}
`, brand.NativeHost, path, brand.ExtensionID)
}

// nativeBinary finds vpncell-native: next to this binary, else the packaged path.
func nativeBinary() string {
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), "vpncell-native")
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return p
		}
	}
	return brand.NativeBinary
}

func cmdFirefoxSetup(args []string) error {
	if len(args) != 1 || (args[0] != "--user" && args[0] != "--remove-user") {
		return fmt.Errorf("usage: vpncell firefox-setup --user | --remove-user")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".mozilla", "native-messaging-hosts")
	path := filepath.Join(dir, brand.NativeHost+".json")
	if args[0] == "--remove-user" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		fmt.Println("removed", path)
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(nativeManifest(nativeBinary())), 0o644); err != nil {
		return err
	}
	fmt.Println("wrote", path)
	fmt.Println("note: the snap Firefox does not read ~/.mozilla; it uses the system-wide manifest in " + brand.SystemNMHDir + " through the desktop portal.")
	return nil
}
