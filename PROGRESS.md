# Build progress

Read this first after an interruption. Requirements: `vpncell-build-prompt.md`
→ `DECISIONS.md` (wins) → `DESIGN.md` (approved; §12 lists changes).

## Current step

**Step 5 — OpenVPN backend**: implemented on branch `step5-openvpn`
(importer allowlist, `vpncell-openvpn@` unit, up hook moving the tun into
the namespace, pushed DNS, management status). Lab OpenVPN servers and the
VM OpenVPN profile work by hand; the full suite with WireGuard, OpenVPN
and mixed sets is running.

## Steps

| Step | Branch | PR | State |
|---|---|---|---|
| 0. Merge design, rename to vpncell, create repo | `main` | – | done |
| 1. Daemon + WireGuard + namespace | `step1-daemon-wireguard` | [#1](https://github.com/gallbotond/vpncell/pull/1) | merged |
| 2. Terminal sessions in full | `step2-terminal-sessions` | [#2](https://github.com/gallbotond/vpncell/pull/2) | merged |
| 3. SOCKS5 proxy | `step3-socks` | [#3](https://github.com/gallbotond/vpncell/pull/3) | merged |
| 4. Native host + Firefox extension (MV3 spike first) | `step4-firefox` | [#4](https://github.com/gallbotond/vpncell/pull/4) | merged (2 known failures) |
| 5. OpenVPN backend | `step5-openvpn` | | in progress |
| 6. Packaging, README | | | |

## How to resume

```bash
make build && make test
make itest                       # root integration tests (asks sudo)
test/scripts/vm-fetch-configs.sh # if /var/lib/vpncell-test/vm is gone
```

The test build runs as a runtime unit (`/run/systemd/system/vpncelld.service`,
installed by `test/scripts/dev-install.sh`).

## Test status (after step 3)

`make itest`, WireGuard lab set (4 lab servers) + VM WireGuard profile: all
25 tests pass, including TestSocksIsolation, TestSocksStress (2400
connections over 4 profiles; default, GOMAXPROCS=1, GOGC=1; namespace
mismatch counter 0), TestSocksAccessControl, TestSocksFailClosed,
TestSocksDNS, TestSocksNoHostOrLAN (nft on/off), TestSocksDaemonRestart,
TestVMSocks, TestNoSecretsInJournal. OpenVPN and mixed sets: step 5.

## Open problems (need the user)

1. **Firefox HTTPS-First DNS leak → policy decision.** With Firefox's
   defaults, `http://` navigations in a mapped container make Firefox look
   up the HTTPS DNS record through the host resolver (DESIGN.md §12 item
   26). Fix: `sudo vpncell firefox-policy install` (locks
   `network.dns.native_https_query=false`; `--strict` also turns
   HTTPS-First off for DoH users). Installing a system-wide Firefox policy
   was refused by the session's safety policy, so it is the user's call
   (and whether the .deb should install it by default). Until then
   `TestBrowserHTTPNameNoHostDNS` is a KNOWN FAILURE.
2. **Snap Firefox portal permission.** Grant once (dialog, or the `gdbus`
   command in README "Snap Firefox"). Until then all snap browser tests are
   KNOWN FAILURES; the tarball (deb-equivalent) Firefox passes them.
3. AMO signing: run `packaging/amo-sign.sh` with your API keys.

Harness notes: the session runs under the `claude-desktop` AppArmor
profile; confined `tcpdump` cannot be signalled from it, so captures use
AF_PACKET in the test binary.

## Next actions

1. Step 5: OpenVPN backend (importer allowlist, systemd template unit,
   hook, management status), lab OpenVPN servers, VM OpenVPN profile; add
   OpenVPN and mixed sets to every scenario; rerun everything.
2. Step 6: .deb, units, uninstall, README completion, final report.
