#!/bin/bash
# Build the vpncell .deb (Ubuntu 26.04, amd64) from this checkout:
#   packaging/build-deb.sh [version]
# Output: bin/vpncell_<version>_amd64.deb
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
version=${1:-$(cd "$repo" && git describe --tags --always 2>/dev/null | sed 's/^v//; s/-/+/g')}
[[ "$version" =~ ^[0-9] ]] || version="0.1.0+git${version}"
make -C "$repo" build extension VERSION="$version" >/dev/null
stage=$(mktemp -d); trap 'rm -rf "$stage"' EXIT
root=$stage/root
install -D -m 0755 "$repo/bin/vpncelld"        "$root/usr/sbin/vpncelld"
install -D -m 0755 "$repo/bin/vpncell"         "$root/usr/bin/vpncell"
install -D -m 0755 "$repo/bin/vpncell-native"  "$root/usr/lib/vpncell/vpncell-native"
install -D -m 0644 "$repo/bin/vpncell.xpi"     "$root/usr/share/vpncell/vpncell-unsigned.xpi"
sed "s|@DAEMON@|/usr/sbin/vpncelld|g" "$repo/packaging/systemd/vpncelld.service" > "$stage/vpncelld.service"
install -D -m 0644 "$stage/vpncelld.service"   "$root/usr/lib/systemd/system/vpncelld.service"
sed "s|@DAEMON@|/usr/sbin/vpncelld|g" "$repo/packaging/systemd/vpncell-openvpn@.service" > "$stage/ovpn.service"
install -D -m 0644 "$stage/ovpn.service"       "$root/usr/lib/systemd/system/vpncell-openvpn@.service"
install -D -m 0644 "$repo/packaging/native-messaging/vpncell.json" "$root/usr/lib/mozilla/native-messaging-hosts/vpncell.json"
install -D -m 0644 "$repo/packaging/networkmanager/vpncell.conf"   "$root/usr/lib/NetworkManager/conf.d/90-vpncell.conf"
install -D -m 0644 "$repo/packaging/vpncell.toml" "$root/etc/vpncell/vpncell.toml"
install -d -m 0755 "$root/etc/vpncell/profiles.d"
install -d -m 0700 "$root/etc/vpncell/secrets"
install -D -m 0644 "$repo/README.md" "$root/usr/share/doc/vpncell/README.md"
install -D -m 0644 "$repo/docs/DESIGN.md" "$root/usr/share/doc/vpncell/DESIGN.md"
install -d "$root/DEBIAN"
size=$(du -sk "$root" | cut -f1)
cat > "$root/DEBIAN/control" <<EOF
Package: vpncell
Version: $version
Architecture: amd64
Maintainer: vpncell <noreply@users.noreply.github.com>
Installed-Size: $size
Depends: systemd (>= 255), dbus, openvpn (>= 2.6)
Recommends: firefox
Section: net
Priority: optional
Homepage: https://github.com/gallbotond/vpncell
Description: per-profile VPN network namespaces for terminals and Firefox containers
 vpncell keeps several WireGuard and OpenVPN connections up at the same
 time, each in its own network namespace, and lets you choose which one a
 shell, a command or a Firefox Multi-Account Container uses. Traffic of a
 profile never leaves through another profile or the normal connection,
 DNS included; if a tunnel is down, that traffic fails.
EOF
echo /etc/vpncell/vpncell.toml > "$root/DEBIAN/conffiles"
for s in postinst prerm postrm; do
  install -m 0755 "$repo/packaging/debian/$s" "$root/DEBIAN/$s"
done
mkdir -p "$repo/bin"
out="$repo/bin/vpncell_${version}_amd64.deb"
dpkg-deb --root-owner-group --build "$root" "$out" >/dev/null
echo "$out"
