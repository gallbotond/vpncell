#!/bin/bash
# Test-only: (re)fetch the vpncell test clients' configs from the test VM's
# admin UIs into /var/lib/vpncell-test/vm (root-only). Credentials are read
# from .env at runtime and never printed. The clients are created once (see
# README "Test VM changes"); this script only downloads them.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
source "$here/vm-env.sh"
out=/var/lib/vpncell-test/vm
sudo install -d -m 0700 "$out"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
U=${WGE_URL%/}
id=$(curl -fsS -u "$WGE_USER:$WGE_PASS" "$U/api/client" | jq '.[] | select(.name=="vpncell-test") | .id')
curl -fsS -u "$WGE_USER:$WGE_PASS" "$U/api/client/$id/configuration" > "$tmp/vm-wg.conf"
U=${OVUI_URL%/}; J=$tmp/jar
x=$(curl -fsS -c "$J" -b "$J" "$U/login" | grep -o 'name="_xsrf" value="[^"]*"' | sed 's/.*value="//;s/"//')
curl -fsS -c "$J" -b "$J" -o /dev/null --data-urlencode "login=$OVUI_USER" --data-urlencode "password=$OVUI_PASS" --data-urlencode "_xsrf=$x" "$U/login"
curl -fsS -c "$J" -b "$J" "$U/certificates/vpncell-test" > "$tmp/vm-ovpn.ovpn"
grep -q '^client' "$tmp/vm-ovpn.ovpn"
# Used exactly as downloaded: the VM's server uses tls-crypt, like the
# <tls-crypt> block openvpn-ui writes (issue #13, README "Test VM changes").
grep -q '^<tls-crypt>' "$tmp/vm-ovpn.ovpn"
sudo install -m 0600 "$tmp/vm-wg.conf" "$tmp/vm-ovpn.ovpn" "$out/"
echo "configs in $out"
