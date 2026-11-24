# vpncell

vpncell keeps several VPN connections up at the same time, each in its own
Linux network namespace (a *cell*), and lets you choose which one a program
uses:

- **Terminal:** `vpncell shell <profile>` opens a shell whose traffic goes
  only through that profile's VPN. `vpncell run <profile> -- <cmd>` runs one
  command.
- **Firefox:** a WebExtension maps Multi-Account Containers to profiles
  (build step 4).

Profiles may use the same private address ranges and internal hostnames; they
never see each other, the host's `localhost` or the LAN. If a tunnel is down,
traffic fails instead of falling back to the normal connection.

Design: [DESIGN.md](DESIGN.md). Build progress: [PROGRESS.md](PROGRESS.md).

> This README grows with each build step; step 6 completes it (install,
> uninstall, Firefox setup, all known limitations).

## Quick start (from source)

```bash
make build
sudo test/scripts/dev-install.sh        # test build as a runtime systemd unit
sudo systemctl start vpncelld
sudo vpncell import work ~/Downloads/work.conf   # wg-quick file
vpncell run work -- curl https://ifconfig.me
```

You must be in the `vpncell` group to talk to the daemon (log out and in
after `usermod -aG vpncell $USER`), and listed in the profile's `[access]`
section.

## Commands

| Command | What it does |
|---|---|
| `vpncell list` | profiles you may use and their state |
| `vpncell status [--json] [profile]` | state, exit IP, last handshake, traffic, SOCKS port, sessions |
| `vpncell up <profile>` / `down [--force\|--kill] <profile>` | bring a profile up or down |
| `vpncell shell <profile>` | your shell inside the profile |
| `vpncell run [-t\|-T] <profile> -- <cmd>...` | one command inside the profile |
| `sudo vpncell import [--user u] [--group g] <name> <file>` | import a `wg-quick` or `.ovpn` config |
| `sudo vpncell reload` | re-read `/etc/vpncell/profiles.d` |

## Terminal sessions

- `vpncell shell <profile>` starts your `$SHELL` (taken from the
  environment of the `vpncell` command) as an **interactive, non-login**
  shell (`$SHELL -i`). If `$SHELL` is unset, the shell from your passwd
  entry is used. The shell gets `VPNCELL_PROFILE=<profile>`, so a prompt can
  show it, for example in `~/.bashrc`:
  `PS1='${VPNCELL_PROFILE:+[$VPNCELL_PROFILE] }'"$PS1"`.
- `vpncell run <profile> -- <cmd>` runs one command. It uses a terminal when
  stdin and stdout are terminals (`-t` / `-T` force it on or off);
  otherwise your stdin, stdout and stderr are passed to the command directly.
- Sessions get a new pseudo-terminal (like `ssh`); Ctrl-C, Ctrl-Z and job
  control work, window size changes are passed on, and the client exits with
  the command's exit code (128 + signal number if it was killed). Signals
  sent to the `vpncell` process (SIGTERM, SIGHUP, …) are passed on; if the
  client dies, the session gets SIGHUP.
- The command runs with your uid, gid and groups, no capabilities, an empty
  bounding set and `no_new_privs`, in your working directory and with your
  environment and umask. Resource limits are the daemon's.
- Sessions live in systemd scopes (`vpncell-sessions.slice`), so they keep
  running when the daemon restarts. `vpncell status` lists them.
- `vpncell down <profile>` refuses while sessions run and lists them.
  `--force` removes the tunnel; the sessions stay but have no network until
  the next `vpncell up`. `--kill` ends them. Only root may `--force` or
  `--kill` when sessions of other users are affected.
- On start, `vpncell shell` warns that commands which hand work to a program
  already running outside the profile (`firefox <url>`, `code`,
  `xdg-open`) escape the profile.

### What works inside a profile shell

A profile has its own network namespace and a private mount namespace (for
the resolver files). Measured on Ubuntu 26.04 with a GNOME session
(`TestDesktopPrograms`):

| Check | outside a profile | inside a profile |
|---|---|---|
| X11 through the abstract socket `@/tmp/.X11-unix/X0` | works | fails (abstract sockets belong to the network namespace) |
| X11 through the path socket `/tmp/.X11-unix/X0` (Xlib falls back to it) | works | works |
| Wayland socket | works | works |
| D-Bus session bus (`gdbus`) | works | works |
| `notify-send` (AppArmor-confined) | works | fails |
| `systemctl --user` | works | works |
| system D-Bus (`busctl`) | works | works |
| `resolvectl query` (resolved over D-Bus) | works | works — **resolves through the host** |

`localhost` is the profile's own loopback, not the host's. ssh-agent and
gpg-agent (path sockets) work.

## Import safety

Imported configs are untrusted. The WireGuard importer keeps only an
allowlist of keys. `PreUp`, `PostUp`, `PreDown`, `PostDown`, `SaveConfig`,
`Table`, `ListenPort` and `FwMark` are stripped and listed; unknown keys,
unknown sections and AmneziaWG keys are rejected. Nothing from a config is
ever executed.

## Tests

- `make test`: unit tests, fuzz targets (run with `go test -fuzz`), and
  source lint checks (setns only in allowed packages, no `SO_MARK`, no
  shelling out from the daemon).
- `make itest`: root integration tests (DESIGN.md §15.4). They install the
  test build (`test/scripts/dev-install.sh`), start a local lab and use the
  test VM. `RUN=<regexp>` selects tests; `VPNCELL_TEST_VM=0` skips the VM;
  `VPNCELL_TEST_INSTALLED=1` tests the installed `.deb`.

### Local lab

`test/lab` creates namespaces `vclab-<name>` that act as VPN servers. Every
server has the same service range `10.99.0.0/24` (HTTP at `10.99.0.10`, DNS
at `10.99.0.53` that answers `web.lab.test` differently per server). The
servers' encrypted sockets listen on `127.0.0.1`, so the lab adds no address
or route to the host. `bin/vpncell-lab` runs it by hand.

### Test users

`dev-install.sh` creates `vctest1` (group `vpncell`, allowed on test
profiles), `vctest2` (group `vpncell`, not allowed) and `vctest3` (not in the
group).

### Leak captures

Captures run on the physical interface with `tcpdump`. Tailscale's own
traffic is excluded with a BPF filter on the UDP ports `tailscaled` owns
(found with `ss -ulpn`); nothing else is excluded. A leak is a packet to a
test destination (`10.99.0.0/24`, `172.30.0.0/16`, tunnel ranges), a marker
string (random `leak…` hostnames) in clear text, or any packet to the VPN
endpoint that is not UDP 51820/1194. No host firewall rule is added.

### Test VM changes

The real-world tests use the test VM (`free-vm`, see DECISIONS.md). These
changes were made on it for vpncell (approved at the design review; backups
of every edited file are next to it as `*.bak-vpncell-<timestamp>`):

1. **DNS behind each VPN.** Two CoreDNS containers in
   `/opt/vpn-lab/docker-compose.yml`: `dns-wg` at `172.30.1.53` /
   `fd00:30:1::53` and `dns-ovpn` at `172.30.2.53` / `fd00:30:2::53`
   (configs in `/opt/vpn-lab/dns/{wg,ovpn}/Corefile`). Both answer the zone
   `vpn-lab.test` (`web.vpn-lab.test` → `172.30.0.80` on both;
   `whoami.vpn-lab.test` and `side.vpn-lab.test` → the side's own
   addresses), log every query, and forward other names to public IPv6
   resolvers.
2. **IPv6 in the OpenVPN tunnel.** `server-ipv6 fd00:70::/64` in
   `/opt/vpn-lab/openvpn/server.conf`; `fw-rules.sh` enables IPv6 forwarding
   in the container and NAT66 (`ip6tables -t nat -A POSTROUTING -s
   fd00:70::/64 -j MASQUERADE`).
3. **Test clients.** A wg-easy client `vpncell-test` (AllowedIPs
   `0.0.0.0/0, ::/0`, DNS `172.30.1.53`) and an OpenVPN client certificate
   `vpncell-test` created in openvpn-ui. A client-config-dir file
   `/opt/vpn-lab/openvpn/staticclients/vpncell-test` pushes
   `dhcp-option DNS 172.30.2.53`, `dhcp-option DOMAIN vpn-lab.test` and
   `route-ipv6 2000::/3` to that client only; other clients are unchanged.

`test/scripts/vm-fetch-configs.sh` downloads the two client configs to
`/var/lib/vpncell-test/vm` (root-only), reading the admin credentials from
`.env` at run time.

## Known limitations

(Collected here as the build goes on; see also DESIGN.md §12 and §16.)

- Programs that ask systemd-resolved directly over the system D-Bus (for
  example `resolvectl query`) resolve through the host. glibc, curl, Go,
  Python and Firefox do not do this.
- `sudo` and other setuid programs do not work inside a profile
  (`no_new_privs`).
- **AppArmor-confined programs cannot connect to the host's path sockets
  from a profile shell.** The session's private mount namespace makes the
  peer socket's path "disconnected" for AppArmor, so a confined program's
  connect to, for example, the session D-Bus or Wayland socket is denied
  (`apparmor="DENIED" … info="Failed name lookup - disconnected path"`).
  Unconfined programs (most of the desktop) are not affected, and confined
  network tools (`dig`, `nslookup`, `nc`) work because they use no path
  sockets. Affected on this host: `notify-send`, snap applications
  (Firefox, Thunderbird, Teams), `papers`, and other programs with an
  enforcing AppArmor profile (`sudo aa-status`).
- Abstract Unix sockets (X11's `@/tmp/.X11-unix/X0`, multipathd, iscsiadm)
  are not reachable from a profile; X11 clients fall back to the path socket.
- Sessions are not part of your logind session (no PAM session), and they
  run with the daemon's resource limits.
