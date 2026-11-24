#!/bin/bash
# Test-only: install the freshly built binaries as a runtime systemd unit
# (under /run/systemd/system, gone at reboot), create the vpncell group and
# the test users. Run as root from the repository root after `make build`.
# Skipped when the .deb is installed (VPNCELL_TEST_INSTALLED=1).
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
dest=/usr/local/libexec/vpncell-test
if [[ "${VPNCELL_TEST_INSTALLED:-}" == 1 ]]; then
  echo "using the installed package"; exit 0
fi
if dpkg -s vpncell >/dev/null 2>&1; then
  echo "vpncell .deb is installed; remove it or set VPNCELL_TEST_INSTALLED=1" >&2; exit 1
fi
install -d -m 0755 "$dest"
for b in vpncelld vpncell vpncell-native; do
  [[ -f "$repo/bin/$b" ]] && install -m 0755 "$repo/bin/$b" "$dest/$b.new" && mv -f "$dest/$b.new" "$dest/$b"
done
getent group vpncell >/dev/null || groupadd --system vpncell
for u in vctest1 vctest2 vctest3; do
  id "$u" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash "$u"
done
usermod -aG vpncell vctest1; usermod -aG vpncell vctest2
[[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != root ]] && usermod -aG vpncell "$SUDO_USER"
sed -e "s|@DAEMON@|$dest/vpncelld|g" "$repo/packaging/systemd/vpncelld.service" > /run/systemd/system/vpncelld.service
if [[ -f "$repo/packaging/systemd/vpncell-openvpn@.service" ]]; then
  sed -e "s|@DAEMON@|$dest/vpncelld|g" "$repo/packaging/systemd/vpncell-openvpn@.service" > "/run/systemd/system/vpncell-openvpn@.service"
fi
systemctl daemon-reload
echo "installed test build to $dest"
