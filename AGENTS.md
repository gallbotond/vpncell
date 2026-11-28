# Agent instructions

vpncell: per-profile VPN isolation (network namespaces) for terminal sessions
and Firefox containers. Go daemon and CLI, TypeScript Firefox extension,
Debian package. Linux is the shipped product; Windows and macOS are planned
as separate platform tracks.

## Read first

1. [docs/PROGRESS.md](docs/PROGRESS.md): index of the progress files per
   platform and how to resume. Then your track's file under
   [docs/progress/](docs/progress/): current state, open items.
2. [docs/DECISIONS.md](docs/DECISIONS.md): decisions and limits. Wins over the two below.
3. [docs/DESIGN.md](docs/DESIGN.md): approved design. Code comments cite it as "DESIGN.md §N".
   It describes the Linux design; #69 will say which parts apply to Windows
   and macOS.
4. [docs/vpncell-build-prompt.md](docs/vpncell-build-prompt.md): original requirements.

## Order of work

1. #67: CI (unit tests, Windows/macOS cross-compile check). Done.
2. #68: make the shared Go packages portable. Refactor only; Linux
   behaviour does not change.
3. #69: design for profile isolation on Windows and macOS. Needs the
   user's approval.
4. Then the platform tracks, in parallel: Linux issues, Windows, macOS.
   Packaging for Windows and macOS is #70.

No Windows or macOS platform code before #69 is approved.

## All platforms

### Git

- One branch and one PR per issue or step, from an up-to-date `main`.
  Names: `fix/…`, `feat/…`, `chore/…`. Windows and macOS tracks use
  `feat/win-…`, `fix/win-…` and `feat/mac-…`, `fix/mac-…`.
- Merge the PR yourself once its tests and CI checks pass. Add a row for it
  in your track's progress file: `docs/progress/linux.md`,
  `docs/progress/windows.md` or `docs/progress/macos.md`. Cross-platform
  work (CI, portable packages) goes in `docs/progress/linux.md`,
  "Cross-platform groundwork". Edit only your own track's file.
- Required checks on `main` (branch protection, not enforced for admins, no
  required reviews): `linux` and `cross-compile` from
  `.github/workflows/ci.yml`, and `GitGuardian Security Checks`. Wait until
  all three pass before you merge, even though an admin merge could skip
  them.
- `cross-compile` builds and vets an explicit list of packages for Windows
  and macOS. When a package becomes portable, add it to the list in
  `ci.yml`. Never remove one to make the check pass.
- The `gh` token has no `workflow` scope, so an HTTPS push that changes
  `.github/workflows/` is refused. Push that branch over SSH:
  `git push git@github.com:gallbotond/vpncell.git <branch>`.

### Labels

`linux`, `windows`, `macos` for a track's issues and PRs; `cross-platform`
for work that affects all tracks (CI, portable packages, docs layout). An
issue may have more than one.

### Rules on every platform

- Never commit `.env` or copy its values into code, logs, commits, PRs or
  test fixtures. The repository is public.
- Never upload the extension to Mozilla.
- Never skip, weaken or delete a test to make it pass.

## Linux

Ubuntu 26.04 LTS, the shipped product. Development and tests run on this
host. Progress: [docs/progress/linux.md](docs/progress/linux.md).

### Hard limits

- Never change this host's routing tables, ip rules, firewall chains or DNS
  settings. Tailscale runs here and the session must stay reachable.
- Never commit `.env` or copy its values into code, logs, commits, PRs or
  test fixtures. Read it at runtime. The repository is public.
- Never upload the extension to Mozilla. The user signs it with
  `packaging/amo-sign.sh`.
- Never run `test/scripts/package-test.sh` on this host: it purges the
  package and deletes `/etc/vpncell`, which holds the user's real profiles
  (`work`, `demo-openvpn`, `demo-wireguard`). Integration tests may touch
  only test profiles (`t-*`, `vm-*`).
- Never skip, weaken or delete a test to make it pass.

### sudo

This host has passwordless sudo. You may use it without asking for build and
test work: install apt packages, install a newly built `.deb` over the
installed one (one agent at a time, see "Parallel work"), run `make itest`,
add AppArmor profiles (document each change), and create namespaces,
interfaces and firewall rules inside test namespaces.

This host is not disposable. Even with sudo:

- Never remove or purge the installed package (`apt remove`, `apt purge`,
  `dpkg -r`, `dpkg -P`). To change the version, install a newer `.deb`.
- Never import, remove or edit a profile that is not a test profile
  (`t-*`, `vm-*`). Never delete or change other files under `/etc/vpncell`,
  including `/etc/vpncell/secrets/`.
- Never bring down the user's profiles or stop or kill their sessions and
  tunnels. `vpncell reload` and restarting `vpncelld` are allowed: running
  profiles survive both, and the integration tests use them.
- The hard limits above still apply.

### Commands

```bash
make build && make test          # unit tests: Go + extension
make itest RUN=<regexp>          # root integration tests, uses sudo and the test VM
packaging/build-deb.sh 0.9.N     # .deb into bin/
```

### Parallel work

Several agents may work at once, each in its own git worktree. Code changes
and `make test` can run in parallel. These are shared by the whole host, so
only one agent at a time may use them:

- `make itest`, the running daemon and the test VM (`free-vm`).
- Installing a `.deb` (one `/etc/vpncell`, one installed package).
- Package version `0.9.N`: pick the next free number when you build, not
  when you start.

docs/progress/linux.md conflicts are expected; rebase after the other PR merges.

## Windows

Placeholder. No Windows platform code until the user approves the design
in #69. Until then, Windows work is limited to keeping the portable
packages building (CI `cross-compile`).

- Progress: [docs/progress/windows.md](docs/progress/windows.md).
- Test host, commands, shared resources and hard limits: to be defined with
  #69 and #70. Until they are written here, do not use a Windows host.
- Branches: `feat/win-…`, `fix/win-…`. Label: `windows`.

## macOS

Placeholder. No macOS platform code until the user approves the design
in #69. Until then, macOS work is limited to keeping the portable packages
building (CI `cross-compile`).

- Progress: [docs/progress/macos.md](docs/progress/macos.md).
- Test host, commands, shared resources and hard limits: to be defined with
  #69 and #70. Until they are written here, do not use a macOS host.
- Branches: `feat/mac-…`, `fix/mac-…`. Label: `macos`.
