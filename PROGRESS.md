# Build progress

Read this first after an interruption. Requirements: `vpncell-build-prompt.md`
→ `DECISIONS.md` (wins) → `DESIGN.md` (approved; §12 lists changes).

## Current step

**Issue run (2026-11-26).** Working through the open GitHub issues in this
order, one branch and PR each: #8+#9, #14, #10, #15, #13, #12. See
"Issue run" below for what is merged and "Open items for the user".

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
packaging/build-deb.sh 0.9.N && sudo apt install ./bin/vpncell_0.9.N_amd64.deb
go test -c -tags integration -o bin/itest ./test/integration
cd test/integration && sudo VPNCELL_TEST_INSTALLED=1 ../../bin/itest -test.v -test.timeout 90m
test/scripts/vm-fetch-configs.sh # if /var/lib/vpncell-test/vm is gone
```

The host runs the installed `.deb` **and the user's own profiles**
(`sonrisa` = the real work VPN, `demo-openvpn`, `demo-wireguard`) with a
live session. Since #20 the integration harness touches only test profiles
(`t-*`, `vm-*`) and leaves the daemon running. **Do not run
`test/scripts/package-test.sh` on this host**: it purges the package,
which deletes `/etc/vpncell` (the user's profiles). `dev-install.sh`
refuses while the package is installed.

Harness notes: the session runs under the `claude-desktop` AppArmor
profile; confined `tcpdump` cannot be signalled from it, so captures use
AF_PACKET in the test binary.

## Issue run (2026-11-26)

| Issue(s) | Branch | PR | State |
|---|---|---|---|
| #8 hang on stopped daemon, #9 group message | `fix/client-dial-timeout` | [#20](https://github.com/gallbotond/vpncell/pull/20) | merged |
| #14 OpenVPN failure reason | `fix/openvpn-reconnect-reason` | [#21](https://github.com/gallbotond/vpncell/pull/21) | merged |
| #10 ping in sessions | `fix/ping` | [#22](https://github.com/gallbotond/vpncell/pull/22) | merged |

### #8 + #9 (PR #20, package 0.9.2)

- `client.Dial`: 2 s → "waiting for vpncelld…" and a unit-state check;
  stopped unit (seen twice, not `auto-restart`) fails at once with a
  `systemctl start` hint; otherwise 30 s limit. EACCES tells "in the group
  database but not in this session" (newgrp/sg) from "not a member".
- Tests: unit tests in `internal/client`; `TestClientDaemonStopped`,
  `TestClientGroupMessages`.
- Full suite against 0.9.2: all pass with the tarball Firefox. All snap
  browser subtests fail (see open item 1). `TestVMExitIP/vm-ovpn` failed
  once (curl to 172.30.0.80 timed out) and passed on rerun.

### #14 (PR #21, package 0.9.5)

- OpenVPN status reads openvpn's state history (`state all`) and, after a
  TLS error with a server reply, its log history. Reasons: `no-reply`,
  `stalled-after-server-cert`, `tls-error`, `auth-failure`,
  `ping-restart`, `restart`; retry count and time; `trying since` instead
  of `connected` when not up; `vpncell up` exits 3 (OpenVPN only) with
  the reason and journalctl command; reason + hint in the Firefox popup.
- Finding: openvpn's management log history has no `VERIFY OK` /
  `Initial packet` lines, so the certificate stall is detected as "server
  replied (AUTH) and the only error is the handshake timeout".
- Tests: `TestOpenVPNReasonWrongKey` (VM, ~60 s), `TestOpenVPNReasonRevokedCert`
  (lab CRL). Full suite against 0.9.5: 106 passes, only `/snap` browser
  subtests fail (open item 1).

### #10 (PR #22, package 0.9.6)

- `ping_group_range` copied from the host into each profile namespace (up
  and adoption); `/usr/bin/ping` bind-mounted onto itself `nosuid` in the
  session mount namespace, so it runs without its file capability.
  Decision in DECISIONS.md. Nothing left in "Known limitations" for ping.
- Tests: `TestPingLab`, `TestPingVM` (IPv4+IPv6), `TestPingAdoptedNamespace`.
  Full suite against 0.9.6: 112 passes, only `/snap` browser subtests fail.

## Open items for the user

1. **Snap Firefox still cannot start the native host** although the
   permission store has `webextensions/vpncell: {'snap.firefox': ['yes']}`.
   The user journal shows the portal asking again on every attempt:
   `AccessDialog call failed: … Only the focused app is allowed to show a
   system access dialog`. So the stored grant is not what this portal
   version checks. Please start the snap Firefox once in your desktop
   session with the extension installed and answer the dialog, then run
   `make itest RUN=TestBrowser` (or tell me which app ID the portal uses).
2. AMO signing (`packaging/amo-sign.sh` with your keys) — unchanged.
3. Review README "Test VM changes" — unchanged.

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
