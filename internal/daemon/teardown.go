package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gallbotond/vpncell/internal/brand"
	"github.com/gallbotond/vpncell/internal/netns"
	"github.com/vishvananda/netlink"
)

// Teardown removes everything vpncell created at run time: tunnels,
// namespaces, OpenVPN units, runtime files and per-user native messaging
// manifests. The package's prerm runs it on removal (`vpncelld teardown`)
// after stopping the daemon, the session slice and the OpenVPN units.
func Teardown(log *slog.Logger) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("teardown needs root")
	}
	d := &Daemon{log: log, ctx: context.Background()}
	d.cleanupOpenVPNUnits()
	names, _ := netns.List()
	for _, n := range names {
		netns.Do(n, func() error {
			links, _ := netlink.LinkList()
			for _, l := range links {
				if l.Attrs().Name != "lo" {
					netlink.LinkDel(l)
				}
			}
			return nil
		})
		if err := netns.Delete(n); err != nil {
			log.Warn("delete namespace", "profile", n, "err", err)
		}
	}
	removeHostLinks(log)
	os.RemoveAll(brand.RunDir)
	// Per-user manifests written by `vpncell firefox-setup --user`.
	homes, _ := filepath.Glob("/home/*/.mozilla/native-messaging-hosts/" + brand.NativeHost + ".json")
	if root, err := filepath.Glob("/root/.mozilla/native-messaging-hosts/" + brand.NativeHost + ".json"); err == nil {
		homes = append(homes, root...)
	}
	for _, m := range homes {
		data, err := os.ReadFile(m)
		if err == nil && strings.Contains(string(data), "vpncell-native") {
			os.Remove(m)
			log.Info("removed native messaging manifest", "path", m)
		}
	}
	time.Sleep(100 * time.Millisecond)
	return nil
}
