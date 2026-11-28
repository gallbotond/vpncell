//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gallbotond/vpncell/internal/conflict"
	"github.com/gallbotond/vpncell/internal/control"
	"github.com/godbus/dbus/v5"
)

// inlineBlock returns the content of <tag>...</tag> in an OpenVPN config.
func inlineBlock(t *testing.T, conf, tag string) string {
	t.Helper()
	_, rest, ok := strings.Cut(conf, "<"+tag+">\n")
	if !ok {
		t.Fatalf("no <%s> in config", tag)
	}
	body, _, ok := strings.Cut(rest, "</"+tag+">")
	if !ok {
		t.Fatalf("no </%s> in config", tag)
	}
	return body
}

// nmTestConnection creates an inactive NetworkManager OpenVPN connection
// named name (a t-… name) from a lab client config, with its files in a
// temporary folder, and deletes it when the test ends. It is never
// activated (AGENTS.md / issue limits).
func nmTestConnection(t *testing.T, name, clientConf string, extra ...string) {
	t.Helper()
	if !strings.HasPrefix(name, "t-") {
		t.Fatalf("NetworkManager test connections must be named t-…, not %q", name)
	}
	conf := mustRead(t, clientConf)
	dir := t.TempDir()
	var data []string
	for _, f := range []string{"ca", "cert", "key"} {
		p := filepath.Join(dir, f+".pem")
		if err := os.WriteFile(p, []byte(inlineBlock(t, conf, f)), 0o600); err != nil {
			t.Fatal(err)
		}
		data = append(data, f+" = "+p)
	}
	var remote string
	for _, l := range strings.Split(conf, "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == "remote" {
			remote = f[1]
			if len(f) >= 3 {
				data = append(data, "port = "+f[2])
			}
			break
		}
	}
	data = append(data, "remote = "+remote, "connection-type = tls")
	data = append(data, extra...)
	run("", "nmcli", "connection", "delete", name) // left over from an aborted run
	if out, err := run("", "nmcli", "connection", "add", "type", "vpn", "vpn-type", "openvpn",
		"con-name", name, "connection.autoconnect", "no", "vpn.data", strings.Join(data, ", ")); err != nil {
		t.Fatalf("nmcli connection add: %v %s", err, out)
	}
	t.Cleanup(func() {
		if out, err := run("", "nmcli", "connection", "delete", name); err != nil {
			t.Errorf("nmcli connection delete %s: %v %s", name, err, out)
		}
	})
}

func requireNM(t *testing.T) {
	t.Helper()
	if out, err := run("", "nmcli", "-t", "-f", "RUNNING", "general"); err != nil || strings.TrimSpace(out) != "running" {
		t.Fatalf("NetworkManager is not running: %v %s", err, out)
	}
}

// Issue #19: the daemon's reader works against the real NetworkManager and
// finds the same active VPN/WireGuard connections as nmcli (read-only).
func TestNMActiveConnectionsReadable(t *testing.T) {
	requireNM(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	got, err := conflict.ActiveNM(ctx, conn)
	if err != nil {
		t.Fatalf("ActiveNM: %v", err)
	}
	out, err := run("", "nmcli", "-t", "-f", "NAME,TYPE", "connection", "show", "--active")
	if err != nil {
		t.Fatal(err)
	}
	want := 0
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.HasSuffix(l, ":vpn") || strings.HasSuffix(l, ":wireguard") {
			want++
		}
	}
	if len(got) != want {
		t.Fatalf("ActiveNM found %d VPN/WireGuard connections, nmcli %d:\n%s", len(got), want, out)
	}
}

// An inactive NetworkManager connection with the same client certificate is
// no conflict: up and status show no warning.
func TestNMIdentityInactiveNoWarning(t *testing.T) {
	requireNM(t)
	const p = "t-ovpn1"
	nmTestConnection(t, "t-nmcheck", theLab.Servers["ovpn1"].ClientConfig)
	if out, _ := run("", "nmcli", "-t", "-f", "GENERAL.STATE", "connection", "show", "t-nmcheck"); strings.TrimSpace(out) != "" {
		t.Fatalf("t-nmcheck is active: %s", out)
	}
	root(t, "down", "--kill", p)
	r := root(t, "up", p)
	if r.code != 0 || strings.Contains(r.stdout+r.stderr, "warning:") {
		t.Fatalf("up: %v", r)
	}
	r = root(t, "status", "--json", p)
	var st []control.ProfileStatus
	if err := json.Unmarshal([]byte(r.stdout), &st); err != nil || len(st) != 1 {
		t.Fatalf("status: %v %v", r, err)
	}
	if len(st[0].Warnings) != 0 {
		t.Fatalf("warnings for an inactive connection: %q", st[0].Warnings)
	}
}
