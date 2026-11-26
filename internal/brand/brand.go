// Package brand holds every name and path that carries the product name, so
// that a rename touches only this file (and one TypeScript constant).
package brand

import "os"

const (
	Name          = "vpncell"
	Daemon        = "vpncelld"
	Group         = "vpncell"
	NativeHost    = "vpncell"
	ExtensionID   = "vpncell@gallbotond.github.io"
	EnvProfile    = "VPNCELL_PROFILE"
	EnvSession    = "VPNCELL_SESSION"
	NetnsPrefix   = "vpncell-"
	WGIfPrefix    = "vpnwg"
	TunIfPrefix   = "vpntun"
	SessionSlice  = "vpncell-sessions.slice"
	ScopePrefix   = "vpncell-s-"
	OpenVPNUnit   = "vpncell-openvpn@"
	DaemonUnit    = "vpncelld.service"
	NftTable      = "vpncell"
	DaemonBinary  = "/usr/sbin/vpncelld"
	NativeBinary  = "/usr/lib/vpncell/vpncell-native"
	SystemNMHDir  = "/usr/lib/mozilla/native-messaging-hosts"
	ProtocolMajor = 1
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// Paths. The environment overrides exist for development and tests only; the
// packaged systemd unit does not set them.
var (
	EtcDir      = env("VPNCELL_ETC", "/etc/vpncell")
	RunDir      = env("VPNCELL_RUN", "/run/vpncell")
	StateDir    = env("VPNCELL_STATE", "/var/lib/vpncell")
	ControlSock = env("VPNCELL_SOCKET", RunDir+"/control.sock")
	NetnsDir    = "/run/netns"
)

func ProfilesDir() string           { return EtcDir + "/profiles.d" }
func SecretsDir() string            { return EtcDir + "/secrets" }
func GlobalConfig() string          { return EtcDir + "/" + Name + ".toml" }
func ProfileRunDir(p string) string { return RunDir + "/profiles/" + p }
func NetnsName(p string) string     { return NetnsPrefix + p }
func NetnsPath(p string) string     { return NetnsDir + "/" + NetnsName(p) }
