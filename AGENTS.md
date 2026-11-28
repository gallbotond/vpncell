# Agent instructions

vpncell: per-profile VPN isolation (network namespaces) for terminal sessions
and Firefox containers. Go daemon and CLI, TypeScript Firefox extension,
Debian package.

## Read first

1. [docs/PROGRESS.md](docs/PROGRESS.md): current state, how to resume, open items.
2. [docs/DECISIONS.md](docs/DECISIONS.md): decisions and limits. Wins over the two below.
3. [docs/DESIGN.md](docs/DESIGN.md): approved design. Code comments cite it as "DESIGN.md §N".
4. [docs/vpncell-build-prompt.md](docs/vpncell-build-prompt.md): original requirements.

## Hard limits

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

## Commands

```bash
make build && make test          # unit tests: Go + extension
make itest RUN=<regexp>          # root integration tests, uses sudo and the test VM
packaging/build-deb.sh 0.9.N     # .deb into bin/
```

## Git

- One branch and one PR per issue or step, from an up-to-date `main`.
  Names: `fix/…`, `feat/…`, `chore/…`.
- Merge the PR yourself once its tests and CI checks pass. Add a row for it
  in docs/PROGRESS.md.

## Parallel work

Several agents may work at once, each in its own git worktree. Code changes
and `make test` can run in parallel. These are shared by the whole host, so
only one agent at a time may use them:

- `make itest`, the running daemon and the test VM (`free-vm`).
- Installing a `.deb` (one `/etc/vpncell`, one installed package).
- Package version `0.9.N`: pick the next free number when you build, not
  when you start.

docs/PROGRESS.md conflicts are expected; rebase after the other PR merges.
