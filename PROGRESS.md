# Build progress

Read this first after an interruption. Requirements: `vpncell-build-prompt.md`
→ `DECISIONS.md` (wins) → `DESIGN.md` (approved; §12 lists changes).

## Current step

**Step 2 — terminal sessions in full**: done, PR open (branch
`step2-terminal-sessions`).

## Steps

| Step | Branch | PR | State |
|---|---|---|---|
| 0. Merge design, rename to vpncell, create repo | `main` | – | done |
| 1. Daemon + WireGuard + namespace | `step1-daemon-wireguard` | [#1](https://github.com/gallbotond/vpncell/pull/1) | merged |
| 2. Terminal sessions in full | `step2-terminal-sessions` | [#2](https://github.com/gallbotond/vpncell/pull/2) | merged |
| 3. SOCKS5 proxy | | | next |
| 4. Native host + Firefox extension (MV3 spike first) | | | |
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

## Test status (after step 2)

`make itest`, WireGuard lab set + VM WireGuard profile, all pass:
TestUpDown, TestIsolationOverlap, TestVMExitIP, TestFailClosedShell
(nftables on/off), TestAccessControlExec, TestImportSafetyWireGuard,
TestShellTTY, TestRunExitCodesAndSignals, TestPrivileges,
TestDNSIsolationShell, TestNoHostOrLANAccessShell (nftables on/off),
TestDownWithSessions, TestDownOtherUsersSessions, TestDaemonRestartShell,
TestVMFailClosedAndDNS, TestDesktopPrograms (informational).
OpenVPN and mixed sets arrive with step 5.

## Open problems

- None blocking.

## Next actions

1. Step 3: SOCKS5 server (CONNECT, user/pass, remote DNS in the namespace,
   privileged ports in the fd store, credentials in /run), `vpncell socks`,
   thread-safety stress test, SOCKS access control, SOCKS during daemon
   restart.
