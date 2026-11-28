# Build progress

Read this first after an interruption. Requirements: `vpncell-build-prompt.md`
→ `DECISIONS.md` (wins) → `DESIGN.md` (approved; §12 lists changes).

## Current step

**#17 merged (PR #27, 2026-11-26).** Earlier in the day: #8, #9, #10,
#12, #13, #14 and #15 merged and closed (PRs #20–#26). Still open: #16,
#18, #19. See "Issue
run" and "Open items for the user" below.

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
(`work` = the real work VPN, `demo-openvpn`, `demo-wireguard`) with a
live session. Since #20 the integration harness touches only test profiles
(`t-*`, `vm-*`) and leaves the daemon running. **Do not run
`test/scripts/package-test.sh` on this host**: it purges the package,
which deletes `/etc/vpncell` (the user's profiles). `dev-install.sh`
refuses while the package is installed.

Harness notes: the session runs under the `claude-desktop` AppArmor
profile; confined `tcpdump` cannot be signalled from it, so captures use
AF_PACKET in the test binary.

## Issue run (2026-11-28)

| Issue(s) / PR | Branch | PR | State |
|---|---|---|---|
| IPv6 lifetime refreshes in the host network watcher | `fix/ignore-addr-lifetime-refresh` | [#29](https://github.com/gallbotond/vpncell/pull/29) | merged |
| follow-up: `tunnel routes` logged on every connection | `fix/routes-log-per-connection` | [#42](https://github.com/gallbotond/vpncell/pull/42) | merged |
| popup compact and stable | `feat/popup-compact-ui` | [#33](https://github.com/gallbotond/vpncell/pull/33) | merged |
| follow-up: tests accept the VM's new IPv4 exit | `fix/test-vm-ipv4-egress` | [#43](https://github.com/gallbotond/vpncell/pull/43) | merged |
| #16 `import --replace` keeps settings, no stale secrets | `fix/import-replace-keeps-settings` | [#44](https://github.com/gallbotond/vpncell/pull/44) | merged |
| #31 OpenVPN reconnect signal only when connected | `fix/openvpn-signal-only-connected` | [#45](https://github.com/gallbotond/vpncell/pull/45) | merged |
| #30 host network watcher subscribes again | `fix/host-watch-resubscribe` | [#46](https://github.com/gallbotond/vpncell/pull/46) | merged |
| #19 warn on an identity used by an active NetworkManager VPN | `feat/nm-identity-warning` | [#47](https://github.com/gallbotond/vpncell/pull/47) | merged |
| #36 popup: exit IP under the state | `feat/popup-exit-ip` | [#49](https://github.com/gallbotond/vpncell/pull/49) | merged |
| #37 toolbar badge per tab | `feat/toolbar-badge` | [#50](https://github.com/gallbotond/vpncell/pull/50) | merged |
| #34 popup: Profiles and Containers sections | `feat/popup-sections` | [#51](https://github.com/gallbotond/vpncell/pull/51) | merged |
| #35 popup: current tab first | `feat/popup-current-tab` | [#52](https://github.com/gallbotond/vpncell/pull/52) | merged |
| #38 popup: dark mode | `feat/popup-dark-mode` | [#53](https://github.com/gallbotond/vpncell/pull/53) | merged |

### PR #29 (package 0.9.14)

- The address watcher keeps a set of host addresses (seeded from
  `AddrList` after subscribing) and fires only when an address appears or
  goes away; router-advertisement lifetime refreshes no longer send
  OpenVPN `SIGUSR1`. Rebased onto `main`; no code changes in review.
- Tests: unit test `TestAddrSetIgnoresLifetimeRefresh`. No integration
  test changes host addresses (hard limit). Against 0.9.14: `TestUpDown`,
  `TestIsolationOverlap`, `TestVMExitIP`, `TestFailClosedShell`,
  `TestOpenVPNReasonWrongKey`, `TestOpenVPNReasonRevokedCert`,
  `TestDaemonRestartShell`, `TestVMFailClosedAndDNS`,
  `TestNoSecretsInJournal`, `TestVMOpenVPNConfigAsDownloaded` pass.
  `TestReachVMOpenVPN` fails when `TestVMExitIP` runs before it (also on
  `main`): the daemon logs `tunnel routes` only when they change and never
  forgets them on `down`. Fixed separately (next row).

### Routes log per connection (PR #42, package 0.9.15)

- `downLocked` clears the remembered routes and pushed DNS, so each
  connection logs `tunnel routes` (and rewrites pushed DNS) even when they
  are the same as the last connection's.
- `TestReachVMOpenVPN` now brings `vm-ovpn` up first and checks the log of
  the reconnect, so it no longer depends on test order. It failed against
  0.9.14 and passes against 0.9.15 with `TestVMExitIP`,
  `TestReachSplitWireGuard`, `TestReachNoDNS`, `TestUpDown`,
  `TestVMFailClosedAndDNS`, `TestDaemonRestartShell`. Unit test
  `TestNoteRoutes`.

### PR #33 (extension only)

- Popup: state pills, long route lists collapsed into a count with an
  expandable list, DNS warning chips, mapped containers first, inline
  errors instead of `alert()`, and a redraw that no longer closes an open
  dropdown. The earlier review points were addressed on the branch;
  rebased onto `main`. `make extension` now creates `bin/` (it failed in a
  fresh worktree).
- Tests: extension unit tests (8/8), `make build && make test`, extension
  build. Checked in the tarball Firefox (headless, temporary profile, real
  daemon): mapped rows show `up` pills, `sonrisa` shows "only 44 IPv4
  networks" collapsed with a "DNS unreachable" chip, direct rows dimmed.

### VM IPv4 egress in the tests (PR #43, test only)

- The test VM now has IPv4 egress, so Firefox and SOCKS clients in
  `TestBrowserContainers` and `TestVMSocks` saw the VM's IPv4 address
  instead of its IPv6 endpoint. `isVMExit` accepts both; the IPv4 address
  is learned with `curl -4` through `vm-wg` and must differ from the host's
  own IPv4 exit. DESIGN.md §15.1 notes the change. Against 0.9.15:
  `TestBrowserContainers/tarball`, `TestVMSocks`, `TestVMExitIP` pass.

### #16 (PR #44, package 0.9.16)

- `import --replace` keeps `autostart`, `[access]`, `[dns]` (same backend
  only; a warning shows both when the new config's DNS differs),
  `[routing]`, `[socks]`, `[status]`, `[security]` unless a flag is
  given; the CLI no longer turns `$SUDO_USER` into an explicit `--user`
  (sent as `default_user`, used for new profiles). Output lists kept
  settings and removed files. Old comments are not kept (the file is
  regenerated from the parsed values; chosen over text editing).
- Secrets are staged in `secrets/.NAME.new` and swapped in after the
  profile validates; if writing the profile file fails, the old folder is
  restored. `WriteAtomic` now removes its temp file when the rename fails.
- Tests: unit tests `TestProfileText*`, `TestSwapSecrets`; integration
  `TestImportReplace` (lab OpenVPN, `t-repl`: kept settings, `tls-auth.pem`
  removed, `--autostart` wins, `chattr +i` on the profile file makes the
  replace fail and the old profile still connects). It failed against
  0.9.15. Against 0.9.16 it passes with `TestImportTLSAuthOption`,
  `TestImportSafety*`, `TestReach*`, `TestRemove*`, `TestUpDown`,
  `TestAccessControlExec`.

### #31 (PR #45, package 0.9.17)

- `OnHostNetworkChange` asks openvpn for `state` and sends `SIGUSR1` only
  when it is `CONNECTED` (the option the issue proposed). DESIGN.md §4.4
  and §12 item 37.
- Tests: unit tests against a fake management socket
  (`TestReconnectOnlyWhenConnected` for CONNECTED, WAIT, RECONNECTING,
  TCP_CONNECT, AUTH, GET_CONFIG, ASSIGN_IP and no state;
  `TestReconnectNoManagement`). A host network change cannot be caused in
  an integration test without changing the host (hard limit). Against
  0.9.17: `TestUpDown`, `TestIsolationOverlap`, `TestOpenVPNReason*`,
  `TestDaemonRestartShell`, `TestVMExitIP`, `TestReachVMOpenVPN`,
  `TestVMOpenVPNConfigAsDownloaded`, `TestFailClosedShell`, `TestPingVM`
  pass.

### #30 (PR #46, package 0.9.19)

- `keepSubscribed` runs the address and route subscriptions: library
  errors are logged through `ErrorCallback`; a closed channel or failed
  subscribe is logged and retried (2 s, doubling to 1 min); after a new
  subscription the address set is seeded again and one `notify()` is sent
  (the issue's proposal). `done` is closed after each subscription, so the
  socket is released. Errors from closing it on shutdown are not logged
  (0.9.18 logged `resource temporarily unavailable` on every stop; fixed
  in 0.9.19). Also gofmt of `openvpn.go` from PR #45. DESIGN.md §12 item 38.
- Tests: unit tests with fake subscriptions (`TestAddressWatchResubscribes`,
  `TestRouteWatchResubscribes`, `TestWatchErrorQuietAfterDone`, run with
  `-race`). Against 0.9.19: `TestUpDown`, `TestIsolationOverlap`,
  `TestDaemonRestartShell`, `TestVMExitIP`, `TestReachVMOpenVPN`,
  `TestSocksDaemonRestart`, `TestFailClosedShell`,
  `TestRestartDeletedProfile` pass, and the journal had no watch lines.

### #19 (PR #47, package 0.9.20)

- New `internal/conflict`: active NM VPN/WireGuard connections over D-Bus
  (read-only), host WireGuard devices (wgctrl). Match on the client
  certificate's SHA-256 (CN: weaker warning) and on the WireGuard public
  key (derived; private keys never kept or logged). Warnings in `up`,
  `import` and `status` (not while down); the CLI wraps them. Without
  NetworkManager the check is skipped. README "The same VPN in
  NetworkManager", DESIGN.md §12 item 39. The popup does not show them
  (not asked in the issue).
- Choice: match on the certificate, CN only as a weaker hint (as the
  issue proposed). Other `openvpn` processes on the host are not checked
  (optional in the issue).
- Tests: unit tests (`TestOpenVPNIdentity`, `TestWireGuardIdentity`,
  `TestCheck`, `TestReadRegular` incl. a FIFO, `TestActiveNM` and
  `TestActiveNMAbsent` against a fake NetworkManager on a private
  `dbus-daemon`; certificates and keys generated at runtime). Integration:
  `TestNMActiveConnectionsReadable` (real NetworkManager, compared with
  nmcli), `TestNMIdentityInactiveNoWarning` (an inactive NM connection
  `t-nmcheck` with `t-ovpn1`'s certificate gives no warning; created with
  autoconnect off, never activated, deleted afterwards). A positive test
  with the real NetworkManager would need an active connection (not
  allowed).
- Found on the way: `TestImportReplace` (PR #44) brought up `t-repl` with
  `t-ovpn1`'s certificate on the same lab server, which dropped `t-ovpn1`
  (`Inactivity timeout` 30 s later) and broke `TestDaemonRestartShell`
  after it. The test now takes `t-ovpn1` down first.
- Against 0.9.20: `TestNM*`, `TestUpDown`, `TestImportReplace`,
  `TestImportSafetyOpenVPN`, `TestImportSafetyWireGuard`, `TestVMExitIP`,
  `TestReachVMOpenVPN`, `TestNoSecretsInJournal`,
  `TestDaemonRestartShell` pass.

### #36 (PR #49, extension only)

- The exit IP column is gone; the IP shows under the state pill when the
  daemon probed one, and the pill of a connected profile without one has a
  tooltip naming `[status] exit_ip_url` (the issue's proposal plus its
  optional tooltip). New `extension/src/view.ts` for pure popup helpers.
- Tests: `exitIPView` unit test; `make test`, extension build; checked in
  the tarball Firefox (no column; no profile here sets `exit_ip_url`).

### #37 (PR #50, extension only)

- Per-tab toolbar badge from the tab's container (`badgeFor`): none for
  direct tabs, profile initial in green (up), amber (connecting), grey
  (down, comes up on use), red `!` when blocked or failed; tooltip with
  profile and state. Updated on tab activation, update (navigation resets
  it), creation and state changes. The global `!` badge is replaced by
  the per-tab one (the issue's colours; grey for down, amber for
  connecting). DESIGN.md §12 item 42, README "Firefox".
- Tests: `badgeFor` unit test (direct, private, up, down, connecting,
  unknown, failed, manual down, daemon down). Tarball Firefox: tabs on
  `about:blank` in a container mapped to `demo-wireguard` showed a green
  `D`, one mapped to an unknown profile a red `!`, direct tabs none (read
  with `browserAction.getBadgeText`).

### #34 (PR #51, extension only)

- Popup split into **Profiles** (one card per profile: state pill, exit
  IP, why, reach and DNS chips, Up/Down, "Used by" containers; profiles
  in use first) and **Containers** (name and dropdown only; a mapping to
  an unavailable profile shows "blocked" in its row). All visible
  profiles get a card, so a profile no container uses can still be
  brought up or down. Up/Down errors and expanded route lists are kept
  per profile.
- Tests: `profileUsers`/`profileOrder` unit test; `make test`, extension
  build; tarball Firefox with three containers mapped to two profiles
  ("Used by: Work, Banking").

### #35 (PR #52, extension only)

- "This tab" line at the top (container → profile with its state pill, or
  "connects directly" for default tabs and private windows, also for a
  mapped container's tab in a private window); the current container's
  row first in Containers, highlighted with a "this tab" tag.
- Tests: `orderContainers`/`thisTab` unit test; tarball Firefox with the
  popup opened in a container tab ("This tab: Work → sonrisa up") and in a
  default tab ("This tab connects directly").

### #38 (PR #53, extension only)

- Colours moved to CSS variables on `:root` with a dark palette under
  `prefers-color-scheme: dark`; `color-scheme: light dark`; `body` has an
  explicit background and colour; the footer's inline colour became a
  class.
- Tests: `popup-css.test.mjs` (both palettes define the same variables,
  no hex colours outside them, every `var()` defined); tarball Firefox
  with `ui.systemUsesDarkTheme` set: dark panel, readable pills, chips and
  buttons.

## Issue run (2026-11-26)

| Issue(s) | Branch | PR | State |
|---|---|---|---|
| #8 hang on stopped daemon, #9 group message | `fix/client-dial-timeout` | [#20](https://github.com/gallbotond/vpncell/pull/20) | merged |
| #14 OpenVPN failure reason | `fix/openvpn-reconnect-reason` | [#21](https://github.com/gallbotond/vpncell/pull/21) | merged |
| #10 ping in sessions | `fix/ping` | [#22](https://github.com/gallbotond/vpncell/pull/22) | merged |
| #15 split-tunnel information | `fix/split-tunnel-info` | [#23](https://github.com/gallbotond/vpncell/pull/23) | merged |
| follow-up: test key generated at runtime | `fix/test-key-runtime` | [#24](https://github.com/gallbotond/vpncell/pull/24) | merged |
| #13 tls-crypt on the VM, `import --tls-auth` | `feat/tls-auth-import` | [#25](https://github.com/gallbotond/vpncell/pull/25) | merged |
| #12 session identity (session 1–3, profile 1–2) | `feat/session-identity` | [#26](https://github.com/gallbotond/vpncell/pull/26) | merged |
| #17 `vpncell remove`, no orphaned profiles | `feat/remove-profile` | [#27](https://github.com/gallbotond/vpncell/pull/27) | merged |

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

### #15 (PR #23, package 0.9.8)

- Import warnings (WireGuard AllowedIPs/DNS, OpenVPN redirect-gateway),
  `reaches:` / `server routes:` / DNS notes in status, JSON and the
  Firefox popup, `tunnel routes` in the daemon log, README troubleshooting.
  No fallback to the host connection.
- OpenVPN route info needs a reconnect for tunnels connected before 0.9.8
  (older hook); until then status shows none (by design, no wrong claims).
- Tests: `TestReachSplitWireGuard`, `TestReachNoDNS`, `TestReachVMOpenVPN`
  + unit tests. Full suite against 0.9.8: 115 passes, only `/snap` fail.
- Note for the user: the `work` profile gets pushed DNS 8.8.8.8 /
  8.8.4.4 but only private routes, so name lookups in it probably fail;
  after its next reconnect `vpncell status work` will flag this. Set
  `[dns] servers` (your internal resolver) if needed.

### #13 (PR #25, package 0.9.9)

- Test VM: OpenVPN server switched to `tls-crypt pki/ta.key` (server.conf
  and openvpn-ui DB; backups `*.bak-vpncell-20261126072854`; README "Test
  VM changes" item 4). Fetch script no longer rewrites; `vm-ovpn.ovpn`
  re-fetched (old copy kept as `vm-ovpn.ovpn.bak-20261126072854`).
- Local `demo-openvpn` switched to tls-crypt (same key; backup
  `/etc/vpncell/secrets/demo-openvpn/client.ovpn.bak-vpncell-20261126072854`),
  brought up again with `down --force` + `up`; your session in it survived.
- `vpncell import --tls-auth` (explicit only).
- Tests: `TestVMOpenVPNConfigAsDownloaded`, `TestImportTLSAuthOption`.
  Full suite against 0.9.9: 117 passes, only `/snap` fail.

### #12 (PR #26, package 0.9.11)

- `VPNCELL_SESSION`, parent tracking, status marks, `vpncell current`
  (session from the scope cgroup, network from `/proc/<pid>/ns/net` read
  with the caller's fsuid; no new capability), shell banner and terminal
  title (`VPNCELL_QUIET=1` turns them off). DESIGN.md §12 items 31–34.
- Left in the issue (comment there; the PR closed it): session idea 4,
  profile ideas 4–6.
- Tests: `TestSessionIdentity`, `TestShellBannerAndTitle`. Full suite
  against 0.9.11: 119 passes, only `/snap` browser subtests fail.

### #17 (PR #27, package 0.9.13)

- `sudo vpncell remove [--force|--kill] NAME`: refuses while up or with
  sessions; deletes `profiles.d/NAME.toml` and `secrets/NAME/`; names
  config files outside `secrets/NAME/` instead of deleting them.
- `reload`: a profile whose file is gone while in use is taken down
  (`--force` semantics); a file that is there but does not load keeps the
  running version (journal error). Index and SOCKS port of vanished
  profiles are pruned on every load (also after a daemon restart).
- Daemon start: a namespace without a profile gets its OpenVPN unit
  stopped and its links deleted; sessions are adopted before that sweep
  (they were adopted after it, so their namespace was deleted).
- Namespaces of removed profiles that sessions still use are deleted by
  the supervisor after the last session ends.
- DESIGN.md §12 item 35, protocol table; README "Removing a profile".
- Tests: `TestRemoveProfile`, `TestRemoveOpenVPN`,
  `TestReloadDeletedProfile`, `TestReloadBrokenProfile`,
  `TestRestartDeletedProfile`; unit tests `TestWithin`, `TestStatePrune`.
  The first run against 0.9.12 found that a restart kept the deleted
  profile's index and port (fixed in 0.9.13). Full suite against 0.9.13:
  124 passes, only the 7 `/snap` browser subtests fail (open item 1).

### State of this host (end of the run)

`vpncell` 0.9.13 is installed (versions 0.9.2–0.9.13 were test builds of
this run; `bin/vpncell_0.9.*.deb`). Your profiles `work`,
`demo-openvpn` (now tls-crypt) and `demo-wireguard` are up; your session
in `demo-openvpn` was never stopped. Sessions opened before 0.9.6 do not
have the ping fix; new ones do.

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
4. **GitGuardian incident 40980131** (PR #23, `internal/importer/reach_test.go`):
   the example `PrivateKey` from the `wg(8)` man page in a test. Not a real
   secret; PR #24 replaced it with keys generated at runtime. Please mark
   the incident as a false positive. (I merged #23 before reading the
   failed check; later PRs wait for the check to pass.)
5. **`proxmox-test` OpenVPN client** (on your Proxmox machine) still has a
   `<tls-auth>` config and cannot connect since the VM server uses
   tls-crypt (#13). Download it again from openvpn-ui
   (`http://free-vm:18080/certificates/proxmox-test`) on that machine.
6. **`work` DNS** (found during #15): the work server pushes DNS
   `8.8.8.8`/`8.8.4.4` but only private routes and no redirect-gateway, so
   name lookups inside `work` probably fail. After its next reconnect
   `vpncell status work` shows this. If needed, set `[dns] servers` to
   your internal resolver in `/etc/vpncell/profiles.d/work.toml` and
   `sudo vpncell reload`. (I did not touch the profile.)
7. Issue #12 was closed by its PR; reopen it if you want the remaining
   ideas (session 4, profile 4–6) tracked there.

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
