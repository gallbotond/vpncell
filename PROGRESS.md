# Build progress

Read this first after an interruption. Requirements: `vpncell-build-prompt.md`
→ `DECISIONS.md` (wins) → `DESIGN.md` (approved; §12 lists changes).

## Current step

**Build complete (as of 2026-11-25).** All six steps and the Firefox
policy follow-up are merged. Nothing is left for Claude to build. The
open items below need the user (see "What I need from you").

## Steps

| Step | Branch | PR | State |
|---|---|---|---|
| 0. Merge design, rename to vpncell, create repo | `main` | – | done |
| 1. Daemon + WireGuard + namespace | `step1-daemon-wireguard` | [#1](https://github.com/gallbotond/vpncell/pull/1) | merged |
| 2. Terminal sessions in full | `step2-terminal-sessions` | [#2](https://github.com/gallbotond/vpncell/pull/2) | merged |
| 3. SOCKS5 proxy | `step3-socks` | [#3](https://github.com/gallbotond/vpncell/pull/3) | merged |
| 4. Native host + Firefox extension (MV3 spike first) | `step4-firefox` | [#4](https://github.com/gallbotond/vpncell/pull/4) | merged |
| 5. OpenVPN backend | `step5-openvpn` | [#5](https://github.com/gallbotond/vpncell/pull/5) | merged |
| 6. Packaging, README | `step6-packaging` | [#6](https://github.com/gallbotond/vpncell/pull/6) | merged |
| Follow-up: package installs Firefox policy by default | `firefox-policy-default` | [#7](https://github.com/gallbotond/vpncell/pull/7) | merged |

## How to resume

```bash
make build && make test
make itest                       # root integration tests (asks sudo)
test/scripts/vm-fetch-configs.sh # if /var/lib/vpncell-test/vm is gone
```

The host has the installed `vpncell` 0.9.1 package, not the dev build
(`vpncelld` was stopped as of 2026-11-25). To test a dev build again, run `test/scripts/dev-install.sh` (it
installs runtime units under `/run/systemd/system/`).

## Test status (after #7)

The full suite (`make itest`) passes against the installed `.deb` with the
WireGuard, OpenVPN and mixed sets. This includes
`TestBrowserHTTPNameNoHostDNS` and `TestPackageUpgradeAndRemove`. There is
one known failure: the snap Firefox browser tests fail until the portal
permission is granted (see "What I need from you", item 2). The tarball
(deb-equivalent) Firefox passes them.

Harness notes: the session runs under the `claude-desktop` AppArmor
profile; confined `tcpdump` cannot be signalled from it, so captures use
AF_PACKET in the test binary.

## Next actions

None for Claude. The remaining items are the user's (see "What I need
from you", items 2–4).

## Final report

### Pull requests

| Step | PR | Result |
|---|---|---|
| 1. Daemon + WireGuard + namespace | [#1](https://github.com/gallbotond/vpncell/pull/1) | all step tests pass |
| 2. Terminal sessions | [#2](https://github.com/gallbotond/vpncell/pull/2) | all pass |
| 3. SOCKS5 proxy | [#3](https://github.com/gallbotond/vpncell/pull/3) | all pass (25 tests) |
| 4. Native host + Firefox extension | [#4](https://github.com/gallbotond/vpncell/pull/4) | tarball Firefox passes; 2 known failures at the time (snap portal permission; HTTPS-First DNS lookup without the policy — since fixed by the policy, [#7](https://github.com/gallbotond/vpncell/pull/7)) |
| 5. OpenVPN backend | [#5](https://github.com/gallbotond/vpncell/pull/5) | all scenarios pass with WireGuard, OpenVPN and mixed sets; same 2 known failures |
| 6. Packaging, README | [#6](https://github.com/gallbotond/vpncell/pull/6) | lifecycle test passes; full suite against the installed .deb passes except the 2 known failures |
| Follow-up: Firefox policy by default | [#7](https://github.com/gallbotond/vpncell/pull/7) | HTTPS-First DNS failure fixed; only the snap portal failure remains |

No test was skipped, weakened or deleted. No run found a leak in vpncell's
own code paths after the fixes listed in DESIGN.md §12 (items 22, 25, 26
are leaks the tests found in Firefox's behaviour; 25 is fixed in the
extension, 26 is fixed by the Firefox policy the package installs).

### Known limitations

All are in README "Known limitations". The ones that matter most:

1. Firefox: `http://` hostnames in mapped containers reach the host
   resolver (HTTPS-First's HTTPS-record lookup) if an admin opts out of
   the vpncell Firefox policy (the package installs it by default).
2. Firefox: a disabled, crashed or updating extension means mapped
   containers connect directly (no extension can prevent this).
3. AppArmor-confined programs (snap apps, `notify-send`, …) cannot reach
   host path sockets from a profile shell.
4. `resolvectl` and other D-Bus clients of systemd-resolved resolve through
   the host from a profile shell.
5. Established SOCKS connections are cut by a daemon restart (new ones
   wait and succeed); sessions and tunnels are not affected.

### What I need from you

1. ~~Decide on the Firefox policy~~ **Done (2026-11-24):** the `.deb`
   installs it by default (first install; an admin opt-out survives
   upgrades; removal takes it out). `TestBrowserHTTPNameNoHostDNS` and
   `TestPackageUpgradeAndRemove` pass against the package.
2. **Allow the snap Firefox once** to start the native host (portal
   dialog, or the `gdbus … SetPermission webextensions true vpncell
   snap.firefox "['yes']"` command in README "Snap Firefox"); then rerun
   `make itest RUN=TestBrowser` for the snap results.
3. **AMO signing:** `AMO_JWT_ISSUER=… AMO_JWT_SECRET=… packaging/amo-sign.sh`
   (unlisted) to get a signed `.xpi` for release Firefox.
4. Review the test-VM changes listed in README "Test VM changes".

### State of this host

The `vpncell` 0.9.1 package is installed (from the final test run); the
dev build's runtime units were removed by `test/scripts/package-test.sh`.
Test users `vctest1..3` exist. Lab namespaces are removed after each run.
