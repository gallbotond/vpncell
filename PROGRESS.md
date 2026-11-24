# Build progress

Read this first after an interruption. Requirements: `vpncell-build-prompt.md`
→ `DECISIONS.md` (wins) → `DESIGN.md` (approved; §12 lists changes).

## Current step

**Step 1 — daemon + WireGuard + namespace**: done, PR open (branch
`step1-daemon-wireguard`).

## Steps

| Step | Branch | PR | State |
|---|---|---|---|
| 0. Merge design, rename to vpncell, create repo | `main` | – | done |
| 1. Daemon + WireGuard + namespace | `step1-daemon-wireguard` | (see below) | done |
| 2. Terminal sessions in full | | | next |
| 3. SOCKS5 proxy | | | |
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

## Test status (step 1)

`make itest` with the WireGuard set and the VM WireGuard profile: all pass
(TestUpDown, TestIsolationOverlap, TestVMExitIP, TestFailClosedShell with
nftables on and off, TestAccessControlExec, TestImportSafetyWireGuard).
OpenVPN and mixed sets arrive with step 5.

## Open problems

- None blocking.

## Next actions

1. Step 2: TTY shell tests (pty driver), signals, window size, exit codes,
   DNS isolation tests, privileges (`setns` out fails), `down` with
   sessions (refuse / `--force` / `--kill`), daemon restart with a running
   shell.
