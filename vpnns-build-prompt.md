# Build prompt: per-profile VPN isolation for terminal and Firefox containers

<!-- "vpnns" is a placeholder name. Rename it if you like. -->

## What we are building

Build **vpnns**, a Linux tool that keeps several VPN connections up at the same time, each fully separate from the others, and lets me choose which one a program uses:

- **Terminal:** `vpnns shell <profile>` opens a shell where all network traffic goes through that profile's VPN. Several shells on different profiles can run side by side.
- **Firefox:** a WebExtension that works with Multi-Account Containers. I map a container to a profile, and every request from tabs in that container goes through that profile's VPN.
- **Overlap is the point.** Two profiles may use the same private address ranges (for example, both route `10.0.0.0/16`) or the same internal hostnames. Both must work at the same time without conflict. My normal, non-VPN traffic must not be affected.

The most important property is **no leaks**. Traffic assigned to a profile must never leave through another profile or through the host's normal connection. This includes DNS. If a tunnel is down, that traffic must fail, not fall back.

## Decisions already made (keep these unless you find a concrete problem; if so, explain it before you change anything)

### 1. One network namespace per profile

Each active profile gets its own network namespace, named `vpnns-<profile>`. A namespace has its own interfaces, routing table and firewall, so overlapping subnets across profiles do not conflict.

Inside each namespace there is only `lo` and the tunnel interface. There is no veth, no bridge and no NAT to the host. The default route goes through the tunnel, so without the tunnel there is no route out. This makes the namespace fail closed by design, without depending on firewall rules.

### 2. Tunnel setup: create the interface on the host, then move it into the namespace

Both WireGuard and OpenVPN are required.

- **WireGuard:** create the `wg` interface in the host namespace, configure it there (keys, peer, endpoint), then move it into the profile namespace. The encrypted UDP socket stays bound to the host network, and the plaintext interface lives only inside the namespace. Then set addresses, MTU and routes inside the namespace. Use netlink and wgctrl directly, not shell calls to `ip`/`wg`.
- **OpenVPN:** run `openvpn` in the host namespace with `--ifconfig-noexec --route-noexec` and an `--up` hook. The hook moves the tun device into the profile namespace and applies the pushed addresses, routes and DNS there. Handle reconnects: when tun is recreated, move and configure it again.
- Design a backend interface so that other VPN types can be added later.

### 3. DNS per profile

The host's resolver (often the systemd-resolved stub at `127.0.0.53`) does not exist inside the namespaces. Every process started in a profile must see a `resolv.conf` that points to that profile's VPN DNS servers. Set them from the profile config, or from the servers OpenVPN pushes.

Use a private mount namespace for spawned processes and bind-mount the profile's `resolv.conf` over `/etc/resolv.conf`, the same way `ip netns exec` uses `/etc/netns/<name>/resolv.conf`. Also handle `nsswitch.conf`, so that `resolve`/`mdns` modules don't reach the host resolver over D-Bus. Profiles may also define search domains.

### 4. A privileged daemon, and unprivileged clients

`vpnnsd` runs as root as a systemd service. It is the only component with privileges. It:

- brings profiles up and down, and supervises them (restarts tunnels, reports health);
- listens on a Unix socket at `/run/vpnns/control.sock` and identifies callers with `SO_PEERCRED`;
- checks a per-profile access list (which local users may use which profile);
- runs the SOCKS5 proxies described in section 6.

The CLI `vpnns` is unprivileged and only talks to the daemon.

### 5. Terminal sessions

`vpnns shell <profile>` and `vpnns run <profile> -- <cmd> [args...]` work like this:

1. The client sends the request to the daemon over the control socket. It passes its stdin, stdout and stderr (and its controlling TTY) as file descriptors with `SCM_RIGHTS`, along with its working directory and environment.
2. The daemon forks. The child enters the profile's network namespace, creates its private mount namespace (for DNS, see section 3), and then drops completely to the caller's uid, gid and supplementary groups. It sets `PR_SET_NO_NEW_PRIVS`, clears all capabilities, and execs the command.
3. The client waits, forwards signals and window-size changes, and exits with the child's exit code.

Set an environment variable such as `VPNNS_PROFILE=<name>` so that the shell prompt can show the active profile.

If the profile is not up, either bring it up automatically or fail with a clear error, depending on a per-profile setting.

### 6. Firefox: a per-profile SOCKS5 proxy with outbound connections made inside the namespace

A WebExtension cannot put a tab into a network namespace, so the browser goes through a proxy:

- For each active profile, the daemon listens on `127.0.0.1:<port>` with SOCKS5 and username/password authentication. Credentials are random and per profile, so other local users or processes cannot use another profile's tunnel.
- The SOCKS server runs in the host namespace, but every **outbound** connection is opened from inside the profile's namespace. In Go: lock the goroutine to its OS thread, `setns` into the profile namespace, create the socket, then `setns` back. A socket keeps the namespace it was created in. Never leave a thread in the wrong namespace, and test this specifically.
- Hostname resolution for SOCKS requests (remote DNS) also runs inside the profile namespace, against the profile's DNS servers.
- Only CONNECT is needed. Leave out UDP ASSOCIATE unless it turns out to be necessary.

### 7. The Firefox extension

- It uses `browser.contextualIdentities` to list containers and stores a mapping from container (`cookieStoreId`) to profile.
- It registers `browser.proxy.onRequest` for `<all_urls>`. For a mapped container it returns `{type: "socks", host: "127.0.0.1", port, username, password, proxyDNS: true}`. Unmapped containers and the default container get `{type: "direct"}`.
- It gets proxy ports, credentials and profile status from the daemon through **native messaging**. A small host binary, `vpnns-native`, is installed in `~/.mozilla/native-messaging-hosts/` (and the system-wide location), and relays messages to the control socket.
- **Fail closed:** if a container is mapped but the daemon is unreachable, or the profile is down, the request must not go direct. Return a proxy that is guaranteed to fail, and show the problem: a badge on the toolbar icon and an error page or notification. Check how Firefox behaves when every returned proxy fails, and prove with a test that it does not fall back to direct.
- Popup UI: for each container, show the assigned profile, its status (up/down/connecting) and the exit IP if known. Allow changing the mapping, and allow bringing a profile up or down if the user has permission.
- Check for and document traffic that can bypass the proxy: WebRTC (consider `browser.privacy.network.webRTCIPHandlingPolicy`, and note that it is a global setting, not per container), HTTP/3/QUIC, DNS-over-HTTPS (TRR), speculative connections and prefetch. For each one, either prevent the leak or explain clearly in the README why it cannot leak.
- Use Manifest V3 if `proxy.onRequest` and native messaging work fully there in current Firefox; otherwise use MV2 and explain why.

### 8. Profile configuration

- Profiles are stored in `/etc/vpnns/profiles.d/<name>.toml`, readable only by root. Fields: backend (wireguard/openvpn), the backend config or a path to it, DNS servers and search domains, allowed users/groups, autostart (on boot / on first use / manual), and optional extra routes or a split-tunnel list (default: route everything through the tunnel).
- Secrets (private keys, OpenVPN credentials) stay in root-only files and are never sent to clients. The only secret a client ever receives is the SOCKS credentials, and only for profiles the caller may use.
- CLI commands for managing profiles: `vpnns list`, `vpnns status [profile]`, `vpnns up|down <profile>`, `vpnns import <name> <wg.conf|.ovpn>` (runs through the daemon, admin only).

## Technology

- **Language for the daemon, CLI and native host:** your choice. Use one language for all three, and explain the choice in `DESIGN.md`. The main factors are: good libraries for netlink, network namespaces and WireGuard (wgctrl); safe handling of per-thread `setns`; and small binaries with few dependencies, since the daemon runs as root.
- **Extension:** TypeScript, built into plain JS. No large framework is needed.
- **Target: Ubuntu, current LTS.** Keep Ubuntu-specific parts in one place, so that other systemd distributions can be supported later. Points to handle on Ubuntu:
  - The host uses systemd-resolved with the stub at `127.0.0.53`, which must not be reachable from or used by any profile (see section 3).
  - Ubuntu ships Firefox as a **snap** by default. A snap-confined Firefox reaches native messaging hosts through the xdg-desktop-portal, not by starting the binary directly. Find out how manifest locations and permissions work in that case, and make the extension work with both the snap Firefox and the deb Firefox from Mozilla's APT repository. Test both.
  - Check whether AppArmor profiles (for example, for `openvpn` or the Firefox snap) block anything the design needs, and document any change you make.
  - WireGuard is in the kernel. Use the `openvpn` package from the Ubuntu archive.
  - Ship a `.deb` that installs the daemon, a systemd unit, the CLI, the native messaging host and its manifests, and creates a `vpnns` group. Members of that group may talk to the daemon; per-profile access lists apply on top of that.

## Build order

Build in these steps. Each step should end in something that works and has tests.

1. **Daemon + WireGuard + namespace.** Bring a profile up and down; `vpnns run <profile> -- curl https://ifconfig.me` shows the VPN exit IP.
2. **Terminal sessions in full:** an interactive shell with TTY, signals, window resizing, exit codes, DNS isolation and privilege dropping.
3. **SOCKS5 proxy** with outbound connections and DNS done inside the namespace.
4. **Native messaging host + Firefox extension.**
5. **OpenVPN backend.**
6. **Packaging:** the `.deb`, the systemd unit, and the README.

## Required tests (the most important part; automate them in an Ubuntu VM or CI runner with root)

Run every test below with both a WireGuard profile and an OpenVPN profile, and with a mix of the two at the same time.

- **Isolation:** two profiles with overlapping subnets (for example, both route `10.99.0.0/24` to different test servers) are reachable at the same time, each from its own shell and its own container, and each reaches its own server.
- **Fail closed:** with the tunnel interface down or removed, a shell in that profile cannot reach anything, the container's requests fail, and nothing goes out on the host's physical interface. Check this with packet capture on the host interface: only encrypted tunnel packets to the VPN endpoint should appear.
- **DNS:** DNS queries from a profile go only to that profile's DNS servers. No queries reach the host resolver or the physical interface in plaintext.
- **Privileges:** a process started with `vpnns shell` runs as the calling user with no capabilities, and cannot `setns` out of its namespace.
- **Access control:** a user without permission for a profile cannot start a shell in it or get its SOCKS credentials.
- **Thread safety:** a stress test of the SOCKS server under concurrent load across several profiles. No connection may ever come from the wrong namespace.
- **Browser:** an automated Firefox test (Selenium/geckodriver or web-ext with a test page) that checks the exit IP for each container, and the fail-closed behaviour when the daemon is stopped.

## How to work

- Before you write code, write a short design note (`DESIGN.md`): the components, the control-socket protocol, the profile file format, and how each leak path above is handled. Then stop for my review.
- If something in this prompt is impossible or a bad idea on current Linux or Firefox, say so and propose an alternative. Don't work around it silently.
- Keep the privileged code small and easy to audit. Don't call shell commands from the daemon when a netlink or syscall API exists.
- Document every known limitation in the README.
