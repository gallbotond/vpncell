#!/bin/bash
# Test-only: package lifecycle and the full suite against the installed .deb.
#   sudo test/scripts/package-test.sh          (PKG_ONLY=1: lifecycle test only)
# 1. Builds two package versions, removes the dev build's runtime units.
# 2. Installs the first, runs TestPackageUpgradeAndRemove (upgrade to the
#    second with sessions running, then remove and purge).
# 3. Installs the second again and runs the whole integration suite
#    against it (VPNCELL_TEST_INSTALLED=1).
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
user=${SUDO_USER:-botond}
run_as_user() { runuser -u "$user" -- env HOME="$(getent passwd "$user" | cut -d: -f6)" PATH="/usr/local/bin:/usr/bin:/bin" "$@"; }
v1=$(run_as_user "$repo/packaging/build-deb.sh" 0.9.0)
v2=$(run_as_user "$repo/packaging/build-deb.sh" 0.9.1)
run_as_user make -C "$repo" build extension >/dev/null
run_as_user bash -c "cd '$repo' && go test -c -tags integration -o bin/itest ./test/integration"
# The dev build's runtime units would shadow the packaged ones.
systemctl stop vpncelld 2>/dev/null || true
systemctl clean --what=fdstore vpncelld 2>/dev/null || true
rm -rf /run/systemd/system/vpncelld.service /run/systemd/system/vpncelld.service.d /run/systemd/system/vpncell-openvpn@.service
systemctl daemon-reload
for u in vctest1 vctest2 vctest3; do id "$u" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash "$u"; done
DEBIAN_FRONTEND=noninteractive apt-get -y -q purge vpncell >/dev/null 2>&1 || true
DEBIAN_FRONTEND=noninteractive apt-get -y -q install "$v1" >/dev/null
usermod -aG vpncell vctest1; usermod -aG vpncell vctest2; usermod -aG vpncell "$user"
cd "$repo/test/integration"
VPNCELL_TEST_INSTALLED=1 VPNCELL_TEST_PACKAGE="$v2" "$repo/bin/itest" -test.v -test.timeout 30m -test.run 'TestPackageUpgradeAndRemove' "$@" || status=$?
if [[ "${PKG_ONLY:-}" == 1 ]]; then exit "${status:-0}"; fi
DEBIAN_FRONTEND=noninteractive apt-get -y -q install "$v2" >/dev/null
usermod -aG vpncell vctest1; usermod -aG vpncell vctest2; usermod -aG vpncell "$user"
VPNCELL_TEST_INSTALLED=1 "$repo/bin/itest" -test.v -test.timeout 90m "$@" || status=$?
exit "${status:-0}"
