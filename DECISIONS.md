# Decisions for the build session

These decisions were agreed on 2026-11-24, before the build started. They add to
[vpncell-build-prompt.md](vpncell-build-prompt.md). Where they differ from the
prompt, this file wins.

## Build and test environment

- **Run everything directly on this host.** It is a disposable Proxmox VM set up
  to look like a work laptop: Ubuntu 26.04.1 LTS, KVM, LXD, Docker, passwordless
  sudo. No extra test VM is needed.
- **Full autonomy on this host.** The VM is disposable, so any action that
  needs `sudo` is allowed without asking. Examples: install apt packages (Go,
  build tools, tcpdump, and so on), install and remove the built `.deb`, enable
  and start systemd units, create the `vpncell` group and add the user to it, add
  or change AppArmor profiles, change sysctls and kernel modules, create test
  namespaces, interfaces and firewall rules, and write native messaging
  manifests (per-user, system-wide, snap and portal entries). Document each
  AppArmor change, as the prompt requires. The only limits are the ones below:
  keep the host's network connection and Tailscale working.
- The host's own network connection must keep working throughout. This is
  already a requirement of the prompt; on this host it also keeps the session
  reachable.

## Supported platform

- **Ubuntu 26.04 LTS only.** Keep Ubuntu-specific parts in one place, as the
  prompt says. 24.04 is not supported or tested.

## Language

- **Go** for the daemon, the CLI and the native messaging host. Explain the
  choice in `DESIGN.md`.

## Name

- The placeholder was "vpnns". At the design review (2026-11-24) the user chose
  **`vpncell`**, as `DESIGN.md` §1 proposed. It is used everywhere: binaries,
  systemd units, group, paths, extension ID, Go module, docs and the GitHub
  repository name.

## Review gate

- **Stop after `DESIGN.md`**, as the prompt says. Write no code until the user
  approves the design. After approval, build all six steps without further
  stops.

## Git and GitHub

- Create a **private** GitHub repository under the **`gallbotond`** account
  (`gh` is already logged in) and push `main`.
- Work on **one branch and one pull request per build step**.
- **The session merges each PR itself** once that step's tests pass, then
  starts the next step from the updated `main`. The user reviews afterwards.

## Test VPN servers

- The user has VPN servers, and test services behind them, on a **Google Cloud
  VM** (`free-vm`), reached from this host with `gcloud compute ssh` through
  IAP. Inspect the VM before designing the tests, and decide from what is
  there: which VPN servers run, which networks and services are behind them,
  and whether the overlapping setup below already exists.
- **What runs there** (as of 2026-11-24, all in Docker): `wg-easy` (WireGuard,
  UDP 51820), `openvpn` (UDP 1194), `openvpn-ui`, and test services behind the
  VPNs (`whoami`, `nginx`, `iperf3`).
- **Admin UIs, reachable only over the tailnet.** This host is on the user's
  tailnet. `tailscale serve` on the VM publishes:
  - wg-easy: `http://free-vm:51821`
  - openvpn-ui: `http://free-vm:18080`

  Use the name `free-vm` (or its full MagicDNS name), not the tailnet IP:
  `tailscale serve` returns 404 for requests addressed to the IP. The user
  reaches the same UIs at `http://localhost:51821` and `http://localhost:18080`
  on their own computer through an SSH tunnel; those addresses do not work on
  this host.
- **Credentials for the admin UIs** are in `.env` in the repository root. It
  is ignored by git (`.gitignore`) and readable only by the user. These are
  test services only, so the build session may use the credentials freely to
  log in and to create VPN clients and profiles for the tests. The file is not
  in `KEY=VALUE` format; it has two blocks separated by a blank line, wg-easy
  first and openvpn-ui second, each with three lines: the URL, the username
  and the password. Never commit `.env`, and never copy its values into code,
  logs, commit messages, pull requests or test fixtures; read them at runtime.
- **The VPN endpoints are IPv6 only.** The VM has no public IPv4, only
  a public IPv6 address (not recorded here). wg-easy and OpenVPN clients
  must connect to that address. This host has working IPv6, so the tests can run from here.
- **Tailscale runs on this host.** The build and the tests must not disturb it:
  leave its routing table, firewall chains and DNS settings alone, so that the
  session stays reachable. Packet captures in the leak tests will also see
  Tailscale's own traffic (WireGuard on UDP 41641, DERP relays over HTTPS);
  exclude it explicitly and document how, without counting it as a leak or
  hiding real leaks. Never use the VM's tailnet address as a VPN endpoint in
  tests.
- The required tests still apply in full: overlapping `10.99.0.0/24` behind two
  profiles, WireGuard and OpenVPN, and mixed setups. If the VM does not provide
  what a test needs, say exactly what is missing and ask before changing the
  server side.

## Firefox

- **Signing:** build an unsigned `.xpi`. Automated tests install it as a
  temporary add-on through geckodriver. Ship a script for AMO *unlisted*
  signing; the user runs it with their own API keys. The session never uploads
  the extension to Mozilla.
- **Snap Firefox:** the installed snap (`firefox` 160, `latest/stable`) is the
  snap test target.
- **Non-snap Firefox:** use Mozilla's official tarball, unpacked into a test
  directory. It stands in for the deb from Mozilla's APT repository (same binary,
  same native messaging manifest paths). Do not add Mozilla's APT repository and
  do not replace the snap.

## Network behaviour

- **IPv6 fails closed.** If a tunnel carries no IPv6, the namespace has no IPv6
  route, so IPv6 connections fail at once and applications fall back to IPv4
  through the tunnel. IPv6 works in a profile only when the tunnel provides it.
  Do not disable IPv6 with a sysctl.

## Design review (2026-11-24)

The user reviewed and approved `DESIGN.md`, with these decisions:

- **Name:** `vpncell` (see "Name" above).
- **`vpncell shell <profile>`** starts the caller's `$SHELL`, taken from the
  client's environment, as an interactive shell (not a login shell). If
  `$SHELL` is unset, it uses the shell from the caller's passwd entry. The
  README documents this.
- **Test VM changes (`DESIGN.md` §15.2):**
  - Approved: item 1 (one DNS container per service network, pushed by both
    VPNs), item 2 (IPv6 in the OpenVPN tunnel with NAT66) and item 4 (new VPN
    clients through the admin UIs).
  - Not approved: item 3 (a second server of each type). The local lab covers
    WG+WG and OVPN+OVPN overlap.
  - Every change on the VM is documented in the README's test section.
- **Git:** one branch and one PR per build step; the session merges each PR
  when that step's tests pass.
- **Autonomy limits:** never change this host's routing tables, ip rules,
  firewall chains or DNS settings; never commit `.env` or copy its values;
  never upload the extension to Mozilla. A design part that does not work is
  replaced by an alternative that keeps the no-leak and fail-closed
  guarantees, recorded in `DESIGN.md` §12.

## ping in profile sessions (issue #10, 2026-11-26)

Decided by the build session (the issue left the choice open; DESIGN.md
§8.1 step 4 requires sessions without capabilities and with
`no_new_privs`).

- **`net.ipv4.ping_group_range`** is set in every profile namespace to the
  **host's value** (Ubuntu: `0 2147483647`), when the namespace is prepared
  on `up` and again when the daemon adopts it after a restart. A new
  namespace starts with `1 0` (nobody). Copying the host keeps the
  administrator's policy; limiting it to the `vpncell` group would break
  root's sessions and users whose session lacks that group. The setting
  also covers ICMPv6 datagram sockets.
- **File-capability `ping`:** in the session's private mount namespace,
  `/usr/bin/ping` is bind-mounted onto itself `nosuid` (read-only, nodev).
  The kernel ignores file capabilities on a `nosuid` mount, so `ping` runs
  with the user's own, empty capabilities and uses an ICMP datagram socket
  instead of failing `execve` with `EPERM`. The binary stays the system's
  own (updates apply at once; no copy to keep in sync).
- **Rejected:** keeping `CAP_NET_RAW` for sessions (against §8.1: raw
  sockets in the profile namespace would still let a session forge any
  packet into the tunnel); shipping a `vpncell ping` helper (another
  program to maintain, and users type `ping`); a capability-free copy of
  the binary (goes stale on iputils updates).
- The list of binaries treated this way is `platform.CapabilityBinaries`
  (only `ping` today; programs that really need raw sockets, such as
  `arping`, stay unusable in a profile).
