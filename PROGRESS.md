# Build progress

Read this first after an interruption. Requirements: `vpncell-build-prompt.md`
→ `DECISIONS.md` (wins) → `DESIGN.md` (approved; §12 lists changes).

## Current step

**Step 3 — SOCKS5 proxy**: done, PR open (branch `step3-socks`).

## Steps

| Step | Branch | PR | State |
|---|---|---|---|
| 0. Merge design, rename to vpncell, create repo | `main` | – | done |
| 1. Daemon + WireGuard + namespace | `step1-daemon-wireguard` | [#1](https://github.com/gallbotond/vpncell/pull/1) | merged |
| 2. Terminal sessions in full | `step2-terminal-sessions` | [#2](https://github.com/gallbotond/vpncell/pull/2) | merged |
| 3. SOCKS5 proxy | `step3-socks` | [#3](https://github.com/gallbotond/vpncell/pull/3) | merged |
| 4. Native host + Firefox extension (MV3 spike first) | | | next |
| 5. OpenVPN backend | | | |
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

## Open problems

- None blocking.

## Next actions

1. Step 4: MV3 spike (DESIGN.md §9.1) first and record the result; then
   `vpncell-native`, `vpncell firefox-setup`, the extension (TypeScript),
   snap + tarball Firefox, browser tests (exit IP per container, fail
   closed with daemon stopped, same hostname in two containers, default and
   private windows direct, localhost blocking, WebRTC/QUIC/prefetch).
