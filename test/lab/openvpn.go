package lab

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type pki struct {
	caCert, caKey   []byte
	srvCert, srvKey []byte
	cliCert, cliKey []byte
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func newPKI(name string) (*pki, error) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now().Add(-time.Hour)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "vclab-ca-" + name},
		NotBefore: now, NotAfter: now.Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	ca, _ := x509.ParseCertificate(caDER)
	leaf := func(cn string, serial int64, eku x509.ExtKeyUsage) ([]byte, []byte, error) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		t := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			NotBefore: now, NotAfter: now.Add(10 * 365 * 24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement, ExtKeyUsage: []x509.ExtKeyUsage{eku},
		}
		der, err := x509.CreateCertificate(rand.Reader, t, ca, &k.PublicKey, caKey)
		if err != nil {
			return nil, nil, err
		}
		kd, _ := x509.MarshalECPrivateKey(k)
		return pemBlock("CERTIFICATE", der), pemBlock("EC PRIVATE KEY", kd), nil
	}
	p := &pki{caCert: pemBlock("CERTIFICATE", caDER)}
	kd, _ := x509.MarshalECPrivateKey(caKey)
	p.caKey = pemBlock("EC PRIVATE KEY", kd)
	if p.srvCert, p.srvKey, err = leaf("vclab-server-"+name, 2, x509.ExtKeyUsageServerAuth); err != nil {
		return nil, err
	}
	if p.cliCert, p.cliKey, err = leaf("vclab-client-"+name, 3, x509.ExtKeyUsageClientAuth); err != nil {
		return nil, err
	}
	return p, nil
}

// AddOpenVPN creates an OpenVPN lab server. openvpn runs in the host
// namespace on 127.0.0.1:<port>; its up script moves the server's tun device
// into the lab namespace, the same way vpncell's own hook works.
func (l *Lab) AddOpenVPN(name string, index int) (*Server, error) {
	s := &Server{Name: name, Kind: "openvpn", Index: index, Port: 51900 + index, lab: l,
		SvcIP:    netip.AddrFrom4([4]byte{10, 99, 0, byte(100 + index)}),
		TunAddr4: netip.MustParsePrefix(fmt.Sprintf("10.201.%d.1/24", index)),
		TunAddr6: netip.MustParsePrefix(fmt.Sprintf("fd00:201:%d::1/64", index)),
	}
	if err := createNS(name); err != nil {
		return nil, err
	}
	l.Servers[name] = s
	if err := s.setupServices(); err != nil {
		return nil, err
	}
	p, err := newPKI(name)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(l.Dir, "servers", name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	for f, b := range map[string][]byte{"ca.pem": p.caCert, "server.pem": p.srvCert, "server.key": p.srvKey} {
		if err := os.WriteFile(filepath.Join(dir, f), b, 0o600); err != nil {
			return nil, err
		}
	}
	dev := fmt.Sprintf("vclabtun%d", index)
	up := filepath.Join(dir, "up.sh")
	script := fmt.Sprintf(`#!/bin/sh
# Test-only lab server hook: move the tun device into the lab namespace.
set -e
ip link set "$dev" netns %[1]s 2>/dev/null || true
ip -n %[1]s addr replace %[2]s dev "$dev"
ip -n %[1]s -6 addr replace %[3]s dev "$dev" nodad
ip -n %[1]s link set "$dev" mtu "${tun_mtu:-1500}" up
`, NetnsPrefix+name, s.TunAddr4, s.TunAddr6)
	if err := os.WriteFile(up, []byte(script), 0o700); err != nil {
		return nil, err
	}
	conf := fmt.Sprintf(`# vpncell test lab server %[1]s
local 127.0.0.1
port %[2]d
proto udp4
dev %[3]s
dev-type tun
topology subnet
server 10.201.%[4]d.0 255.255.255.0
server-ipv6 fd00:201:%[4]d::/64
ca %[5]s/ca.pem
cert %[5]s/server.pem
key %[5]s/server.key
dh none
data-ciphers AES-256-GCM:AES-128-GCM
keepalive 5 30
persist-key
persist-tun
ifconfig-noexec
route-noexec
script-security 2
up %[6]s
up-restart
disable-dco
push "dhcp-option DNS 10.99.0.53"
push "dhcp-option DOMAIN lab.test"
verb 3
`, name, s.Port, dev, index, dir, up)
	confPath := filepath.Join(dir, "server.conf")
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		return nil, err
	}
	cmd := exec.Command("openvpn", "--config", confPath)
	logf, _ := os.Create(filepath.Join(dir, "server.log"))
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	s.ovpn = cmd.Process
	// Wait until the server is up (its tun is in the lab namespace).
	ok := false
	for i := 0; i < 100; i++ {
		out, _ := exec.Command("ip", "-n", NetnsPrefix+name, "-o", "addr", "show", "dev", dev).Output()
		if strings.Contains(string(out), s.TunAddr4.Addr().String()) {
			ok = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ok {
		log, _ := os.ReadFile(filepath.Join(dir, "server.log"))
		return nil, fmt.Errorf("openvpn lab server %s did not come up:\n%s", name, log)
	}
	client := fmt.Sprintf(`client
dev tun
proto udp4
remote 127.0.0.1 %d
nobind
remote-cert-tls server
data-ciphers AES-256-GCM:AES-128-GCM
verb 3
<ca>
%s</ca>
<cert>
%s</cert>
<key>
%s</key>
`, s.Port, p.caCert, p.cliCert, p.cliKey)
	os.MkdirAll(filepath.Join(l.Dir, "clients"), 0o700)
	s.ClientConfig = filepath.Join(l.Dir, "clients", name+".ovpn")
	if err := os.WriteFile(s.ClientConfig, []byte(client), 0o600); err != nil {
		return nil, err
	}
	return s, nil
}
