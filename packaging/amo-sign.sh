#!/bin/bash
# Sign the vpncell extension as an *unlisted* add-on on addons.mozilla.org,
# so release Firefox can install it. Run it yourself with your own AMO API
# credentials (https://addons.mozilla.org/developers/addon/api/key/):
#
#   AMO_JWT_ISSUER=user:12345:67 AMO_JWT_SECRET=... packaging/amo-sign.sh
#
# The signed .xpi lands in bin/signed/. Nothing else is uploaded.
set -euo pipefail
: "${AMO_JWT_ISSUER:?set AMO_JWT_ISSUER (your AMO API key)}"
: "${AMO_JWT_SECRET:?set AMO_JWT_SECRET (your AMO API secret)}"
repo=$(cd "$(dirname "$0")/.." && pwd)
make -C "$repo" extension
mkdir -p "$repo/bin/signed"
npx --yes web-ext@10.8.0 sign \
  --channel unlisted \
  --source-dir "$repo/extension/dist" \
  --artifacts-dir "$repo/bin/signed" \
  --api-key "$AMO_JWT_ISSUER" \
  --api-secret "$AMO_JWT_SECRET"
ls -l "$repo/bin/signed"
