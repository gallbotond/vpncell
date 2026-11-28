package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gallbotond/vpncell/internal/control"
	"github.com/gallbotond/vpncell/internal/nmimport"
	"github.com/godbus/dbus/v5"
)

// import --from-nm (issue #18): read a NetworkManager connection and import
// it like the equivalent .ovpn or wg-quick file. Nothing in NetworkManager
// is changed.

func nmConnect() (*dbus.Conn, context.Context, context.CancelFunc, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		cancel()
		return nil, nil, nil, fmt.Errorf("NetworkManager: %w", err)
	}
	return conn, ctx, cancel, nil
}

// listNM prints the VPN connections that can be imported.
func listNM() error {
	conn, ctx, cancel, err := nmConnect()
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()
	cs, err := nmimport.List(ctx, conn)
	if err != nil {
		return err
	}
	var ok, other []nmimport.Connection
	for _, c := range cs {
		if c.Importable() {
			ok = append(ok, c)
		} else {
			other = append(other, c)
		}
	}
	if len(ok) == 0 {
		fmt.Println("no NetworkManager OpenVPN or WireGuard connections")
	} else {
		fmt.Println("NetworkManager connections you can import (sudo vpncell import --from-nm <connection> <name>):")
		for _, c := range ok {
			fmt.Printf("  %-30s %-10s %s\n", safe(c.ID), c.Kind, c.UUID)
		}
	}
	for _, c := range other {
		fmt.Printf("not supported: %s (%s)\n", safe(c.ID), c.Kind)
	}
	return nil
}

// safe shows a connection name with control characters escaped.
func safe(s string) string {
	if strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Sprintf("%q", s)
	}
	return s
}

// buildImportNM builds the import request for NetworkManager connection
// conn as profile name.
func buildImportNM(name, connName, authFile string, tlsAuth bool) (*control.ImportRequest, error) {
	if tlsAuth {
		return nil, fmt.Errorf("--tls-auth is for config files; a NetworkManager connection already says whether it uses tls-auth or tls-crypt")
	}
	conn, ctx, cancel, err := nmConnect()
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer conn.Close()
	cs, err := nmimport.List(ctx, conn)
	if err != nil {
		return nil, err
	}
	c, err := nmimport.Find(cs, connName)
	if err != nil {
		return nil, err
	}
	r, err := nmimport.Read(ctx, conn, c)
	if err != nil {
		return nil, err
	}
	if r.NeedsAuth && authFile == "" {
		return nil, fmt.Errorf("NetworkManager connection %q needs a username and password, and %s; pass --auth-file FILE (two lines: username, password)", safe(c.ID), r.AuthWhy)
	}
	req := &control.ImportRequest{Name: name, Kind: r.Kind, Config: r.Config, Files: map[string]string{}}
	for ref, p := range r.Files {
		content, err := readLimited(p)
		if err != nil {
			return nil, fmt.Errorf("NetworkManager connection %q: %w", safe(c.ID), err)
		}
		req.Files[ref] = content
	}
	switch {
	case authFile != "":
		if req.AuthFile, err = readLimited(authFile); err != nil {
			return nil, err
		}
	case r.Auth != "":
		req.AuthFile = r.Auth
	}
	fmt.Fprintf(os.Stdout, "read NetworkManager connection %q (%s)\n", safe(c.ID), r.Summary)
	return req, nil
}
