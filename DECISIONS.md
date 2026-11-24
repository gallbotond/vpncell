# Decisions for the build session

These decisions were agreed on 2026-11-24, before the build started. They add to
[vpnns-build-prompt.md](vpnns-build-prompt.md). Where they differ from the
prompt, this file wins.

## Build and test environment

- **Run everything directly on this host.** It is a disposable Proxmox VM set up
  to look like a work laptop: Ubuntu 26.04.1 LTS, KVM, LXD, Docker, passwordless
  sudo. No extra test VM is needed.
- **Allowed without asking:** install apt packages (Go, build tools, tcpdump,
  and so on), install and remove the built `.deb`, enable and start the systemd
  unit, create the `vpnns` group and add the user to it, add or change AppArmor
  profiles, write native messaging manifests (per-user, system-wide, snap and
  portal entries). Document each AppArmor change, as the prompt requires.
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

- "vpnns" is still a placeholder. **Propose a final name in `DESIGN.md`.** The
  user chooses at the design review. Use `vpnns` until then.

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
  VM**. Reach it from this host with:

  ```bash
  gcloud compute ssh --zone "us-east1-b" "free-vm" --tunnel-through-iap --project "free-vm-1792444052"
  ```

  (VM `free-vm`, zone `us-east1-b`, project `free-vm-1792444052`, SSH through
  IAP.) Inspect the VM before designing the tests, and decide from what is
  there: which VPN servers run, which networks and services are behind them,
  and whether the overlapping setup below already exists.
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
