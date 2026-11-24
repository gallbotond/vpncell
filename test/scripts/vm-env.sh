# Test-only helper: source to read the admin UI credentials from .env at
# runtime (never printed). Block 1 = wg-easy, block 2 = openvpn-ui; each has
# URL, username, password lines.
_vc_env=${VPNCELL_ENV_FILE:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/.env}
mapfile -t _vc_lines < <(grep -v '^[[:space:]]*$' "$_vc_env")
WGE_URL=${_vc_lines[0]}; WGE_USER=${_vc_lines[1]}; WGE_PASS=${_vc_lines[2]}
OVUI_URL=${_vc_lines[3]}; OVUI_USER=${_vc_lines[4]}; OVUI_PASS=${_vc_lines[5]}
unset _vc_lines _vc_env
