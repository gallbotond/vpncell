# vpncell design

Status: **approved** at the design review on 2026-11-24 (see the "Design
review" section in [DECISIONS.md](DECISIONS.md)). This note follows [vpncell-build-prompt.md](vpncell-build-prompt.md) and
[DECISIONS.md](DECISIONS.md). Section 12 lists every place where this design
changes or interprets the prompt; please check those first.

## 1. Name

**`vpncell`** (chosen at the design review; the placeholder was "vpnns").

- Each profile is an isolated network *cell*: a namespace with only `lo` and
  one tunnel. The word says "separate compartments", which is the point of the
  tool, and it does not depend on the implementation detail "namespace".
- Commands: `vpncell shell work`, `vpncell up lab`, daemon `vpncelld`, group
  `vpncell`, package `vpncell`.

The binary, unit, group, path and extension-ID strings live in one Go package
(`internal/brand`) and one TypeScript constant.

## 2. Language: Go

- **Libraries.** `vishvananda/netlink` (links, addresses, routes, netns moves),
  `golang.zx2c4.com/wireguard/wgctrl` (the reference WireGuard API, maintained
  by the WireGuard author), `google/nftables` (nftables over netlink, no `nft`
  binary), `coreos/go-systemd` + `godbus/dbus` (sd_notify, file-descriptor
  store, transient scopes, logind sleep signals), `golang.org/x/sys/unix`
  (setns, mounts, prctl, SCM_RIGHTS, SO_PEERCRED/SO_PEERGROUPS), `miekg/dns`
  (DNS for SOCKS requests). No cgo.
- **Per-thread `setns`.** Go can pin a goroutine to an OS thread
  (`runtime.LockOSThread`). If a locked goroutine exits without unlocking, the
  runtime destroys the thread instead of reusing it. Section 6 builds the
  namespace safety rule on this.
- **Small, static binaries.** One statically linked binary per component, no
  runtime, no interpreter. Memory safety matters for a root daemon that parses
  input from local users and untrusted VPN configs.
- Go cannot `fork()` without `exec()`. Every place that needs work between fork
  and exec (namespace entry, mounts, privilege drop) re-executes a small helper
  mode of the daemon binary. This is the same pattern runc uses.
- Toolchain: `golang-1.26-go` from the Ubuntu 26.04 archive.

## 3. Components

| Binary | Runs as | Purpose |
|---|---|---|
| `/usr/sbin/vpncelld` | root, `vpncelld.service` | The only privileged long-running component. Profiles, namespaces, tunnels, supervision, control socket, SOCKS5 servers. |
| `vpncelld session-helper` (same binary, internal mode) | root, then the caller's uid | One per terminal session. Enters the profile namespace, sets up the private mount namespace, starts the user command with full privilege drop, then drops its own privileges and reports the exit status. |
| `vpncelld ovpn-hook` (same binary, internal mode) | root, started by `openvpn` | OpenVPN `--up`/`--down` hook. Moves the tun device into the namespace and applies pushed addresses, routes and DNS there. |
| `/usr/bin/vpncell` | the user | CLI. Talks only to the control socket. |
| `/usr/lib/vpncell/vpncell-native` | the user, started by Firefox or the portal | Native messaging host. Relays between the extension and the control socket. |
| Firefox extension (TypeScript → JS) | Firefox | Container → profile mapping, `proxy.onRequest`, popup UI. |

Package layout (Go module `github.com/gallbotond/vpncell`):

```
cmd/vpncelld  cmd/vpncell  cmd/vpncell-native
internal/control     # protocol types, framing, SCM_RIGHTS
internal/profile     # TOML parsing, validation, access lists
internal/importer    # wg-quick and .ovpn sanitizers (pure functions, fuzzed)
internal/netns       # namespace create/adopt/delete, pinned-thread workers
internal/backend     # Backend interface; backend/wireguard, backend/openvpn
internal/dnsfiles    # resolv.conf and nsswitch.conf generation
internal/firewall    # in-namespace nftables ruleset
internal/session     # session-helper, pty handling, scopes
internal/socks       # SOCKS5 server (CONNECT only) and in-namespace dialer
internal/platform    # everything Ubuntu-specific (paths, NM, portal notes)
extension/           # Firefox WebExtension (TypeScript)
packaging/           # debian/, systemd units, manifests
test/                # integration tests, local lab, Firefox tests
```

Privileged code is `cmd/vpncelld` plus `internal/{netns,backend,session,socks,firewall,dnsfiles}`.
Nothing in the daemon calls a shell or `ip`/`wg`/`nft`. The only external
program it starts is `openvpn`, and only through systemd.

## 4. Namespaces and tunnels

### 4.1 Namespace

- Name `vpncell-<profile>`, created like `ip netns add`: a pinned thread calls
  `unshare(CLONE_NEWNET)`, and `/proc/thread-self/ns/net` is bind-mounted to
  `/run/netns/vpncell-<profile>`. `ip netns exec` keeps working for debugging.
- Contents: `lo` (up, `127.0.0.1/8`, `::1/128`) and one tunnel interface.
  No veth, no bridge, no NAT.
- Routes: by default `0.0.0.0/0` via the tunnel, and `::/0` via the tunnel
  **only if the tunnel has an IPv6 address**. Otherwise there is no IPv6 route,
  so IPv6 connects fail at once with `ENETUNREACH` and applications fall back to
  IPv4 (DECISIONS: IPv6 fails closed, no sysctl).
- Profile names: `^[a-z][a-z0-9-]{0,30}$`.

### 4.2 Backend interface

```go
type Backend interface {
    Up(ctx context.Context, p *Profile, ns *netns.Handle) error   // create tunnel, move it into ns, configure
    Down(ctx context.Context, p *Profile, ns *netns.Handle) error
    Adopt(ctx context.Context, p *Profile, ns *netns.Handle) (bool, error) // after daemon restart
    Status(ctx context.Context, p *Profile, ns *netns.Handle) (Status, error) // state, handshake/connect time, bytes, pushed DNS
    OnHostNetworkChange(ctx context.Context, p *Profile)          // re-resolve endpoint, nudge reconnect
}
```

Backends do not touch DNS files, nftables or SOCKS. The daemon does that
around them, so a new backend (openconnect later) only has to produce "a
configured interface inside the namespace plus a status".

### 4.3 WireGuard

1. Create link `vpnwg<N>` (type `wireguard`) in the host namespace via netlink.
   `N` is a small per-profile index, so host-side names stay under 15 bytes.
2. Configure it with wgctrl in the host namespace: private key, peers, preshared
   keys, `AllowedIPs`, keepalive and endpoint. The endpoint hostname is resolved
   by the daemon through the host resolver. The encrypted UDP socket is created
   now and stays in the host namespace.
3. Move the link into the namespace (`LinkSetNsFd`). Then, on a pinned thread
   inside the namespace: addresses, MTU, link up, routes.
4. `AllowedIPs` from the imported config are kept as they are (cryptokey
   routing). The namespace default route points into the tunnel anyway, so
   destinations outside `AllowedIPs` are dropped by WireGuard: fail closed.
5. Health: `up` if the last handshake is less than 180 s old, `connecting`
   before the first handshake or when it is older, `failed: <reason>` on setup
   errors.
6. Network changes: the daemon listens for host netlink route/address events
   and logind's `PrepareForSleep(false)`. On either, it resolves the endpoint
   hostname again (with backoff) and updates the peer. WireGuard roams on its
   own for IP endpoints.

### 4.4 OpenVPN

`openvpn` (2.7.0 from the archive) runs as a templated systemd unit,
`vpncell-openvpn@<profile>.service`, which the daemon starts and stops over
D-Bus. It is not a child of the daemon, so it survives a daemon restart, and
its output goes to the journal.

The daemon writes `/run/vpncell/<profile>/openvpn.conf`: the sanitized stored
config, followed by options vpncell always forces:

```
dev vpntun<N>
dev-type tun
ifconfig-noexec
route-noexec
script-security 2
up      "/usr/sbin/vpncelld ovpn-hook <profile>"
down    "/usr/sbin/vpncelld ovpn-hook <profile>"
up-restart
persist-tun
disable-dco                    # see below
dns-updown disable             # see below
auth-retry nointeract
resolv-retry infinite
management /run/vpncell/<profile>/mgmt.sock unix
```

- **`dns-updown disable` is essential.** OpenVPN 2.7 runs a default
  `dns-updown` script when a server pushes DNS settings, and that script
  changes the *host's* systemd-resolved configuration. That would both leak the
  profile's DNS into the host and disturb the host (and Tailscale's DNS).
- **`disable-dco`.** The 7.0 kernel has the in-tree `ovpn` data-channel
  offload driver, and OpenVPN 2.7 uses it by default. Whether an `ovpn` device
  works after a netns move is untested, and DCO creates the device differently
  from tun. v1 forces classic tun; DCO can be evaluated later.
- **The hook** (`vpncelld ovpn-hook`) reads OpenVPN's environment (`dev`,
  `ifconfig_local`, `ifconfig_netmask` / `ifconfig_remote`,
  `ifconfig_ipv6_*`, `route_*`, `route_ipv6_*`, `tun_mtu`,
  `foreign_option_*` for `dhcp-option DNS/DOMAIN`, and the `dns_*` variables
  of the 2.6+ `dns` option). It moves the device into the namespace if it is
  still in the host namespace, then applies addresses, MTU and routes inside
  the namespace, and writes the pushed DNS to `/run/vpncell/<profile>/pushed.json`.
  It does this itself with netlink, so a reconnect works while the daemon is
  restarting. It then notifies the daemon on a best-effort basis.
- **Reconnects:** with `persist-tun` the tun device survives soft restarts
  (ping-restart, SIGUSR1) and stays in the namespace. `up-restart` reruns the
  hook, which reapplies addresses and routes (they may change). If `openvpn`
  itself dies, systemd restarts it (`Restart=on-failure`), a new tun is created
  in the host namespace, unconfigured and down, and the hook moves it again.
  In the window between creation and the move, the device has no address and
  no route, so nothing can use it.
- `user`/`group` in imported configs are stripped. A process that dropped to
  `nobody` could not run the hook on restarts. Instead the unit limits
  `openvpn` to `CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN` (setns
  needs `CAP_SYS_ADMIN`), plus `ProtectHome=yes`, `PrivateTmp=yes` and
  `ProtectSystem=full`.
- Status and byte counts come from the management socket (`state on`,
  `bytecount 5`). After a host network change the daemon sends
  `signal SIGUSR1` so that it reconnects at once, but only while OpenVPN's
  state is `CONNECTED` (§12 item 37); OpenVPN resolves the remote again by
  itself.
- **AppArmor:** Ubuntu 26.04 ships no AppArmor profile for `openvpn` (checked:
  nothing in `/etc/apparmor.d`), so nothing blocks the hook. If a profile
  appears later, the package will add a local override, documented in the README.

## 5. DNS per profile

The resolver configuration a process in a profile sees:

- **`resolv.conf`**: generated by the daemon at
  `/run/vpncell/<profile>/resolv.conf` from the profile's `dns.servers` and
  `dns.search`, or from servers OpenVPN pushes (when `dns.use_pushed = true`,
  the default for OpenVPN). With no servers, the file has no `nameserver`
  line. glibc then uses `127.0.0.1`, which is the namespace's own loopback, so
  lookups fail at once instead of leaking.
- **`/etc/resolv.conf` on Ubuntu is a symlink** to
  `/run/systemd/resolve/stub-resolv.conf`. A bind mount over the symlink path
  would land on the target. So the session helper mounts an empty `tmpfs` over
  `/run/systemd/resolve` and writes `stub-resolv.conf` and `resolv.conf`
  there; the symlink then resolves to the profile's file. When
  `/etc/resolv.conf` is a regular file (other distributions), it is
  bind-mounted over instead.
- **`nsswitch.conf`**: the host file is copied with only the `hosts:` line
  rewritten to `files myhostname dns`. On this host the line is
  `files mdns4_minimal [NOTFOUND=return] mymachines dns`. `mdns4_minimal`
  reaches the host's avahi through the *path* socket
  `/run/avahi-daemon/socket`, so it would work from inside the namespace and
  leak names to the LAN. Other lines (`passwd`, `group`, …) stay unchanged, so
  LDAP/SSSD users keep working.
- **Masked sockets** (empty read-only `tmpfs` in the session's mount
  namespace): `/run/systemd/resolve` (resolved's varlink socket),
  `/run/avahi-daemon`, `/run/nscd`. They are path sockets, so a network
  namespace does not isolate them.
- **Remaining path (documented limitation):** the system D-Bus socket stays
  reachable, because masking it breaks too much (`systemctl`, polkit). A
  program that *explicitly* calls `org.freedesktop.resolve1` over D-Bus
  (for example `resolvectl query`) resolves through the host. glibc, Go,
  curl, Python and Firefox do not do this.
- **SOCKS remote DNS** (section 7) uses the same servers and search domains,
  queried with `miekg/dns` from sockets created in the namespace. It never
  reads the host's `/etc/hosts` or `resolv.conf`.

## 6. Namespace safety rule for threads

Every thread that enters a profile namespace is pinned there for its whole
life and is never returned to the Go scheduler:

- **Per-profile socket factory.** For each active profile the daemon starts a
  small pool of goroutines. Each one calls `LockOSThread`, `setns`es into the
  profile namespace and **never unlocks and never leaves**. Its only job is to
  call `socket(2)` on request and hand back the fd. A socket belongs to the
  namespace it was created in, so `connect`, DNS I/O and everything else then
  happen on ordinary goroutines with the normal netpoller. When the profile
  goes down, the workers return, and because they are still locked the Go
  runtime destroys their threads.
- **Verification per socket:** before handing back an fd, the worker checks the
  socket's namespace with `ioctl(SIOCGSKNS)` and compares the inode with the
  profile namespace. On a mismatch the fd is closed and the dial fails. This
  is the "no connection ever comes from the wrong namespace" guarantee, and the
  stress test reads the same check through a test-only counter.
- **Configuration work** inside a namespace (addresses, routes, nftables,
  wgctrl queries) runs on a throwaway goroutine that locks, `setns`es, works
  and exits without unlocking. Its thread is destroyed too.
- Outside `internal/netns`, only the session helper and the OpenVPN hook call
  `setns`. Both are short-lived processes that never return to the host
  namespace. A lint test greps for `unix.Setns` / `netns.Set` anywhere else.

## 7. SOCKS5 proxy

- One listener per profile on `127.0.0.1:<port>`, RFC 1928 CONNECT only, RFC
  1929 username/password. No UDP ASSOCIATE (Firefox does not need it for
  HTTP(S); WebRTC is handled in section 9.6).
- **Ports are privileged (below 1024) by default**, allocated once from
  `socks_port_range` (default `700-799`) and saved in
  `/var/lib/vpncell/state.json`, or fixed with `socks.port` in the profile.
  Reason: if a profile's port were above 1024, any local user could bind it
  while the daemon is stopped and receive a container's traffic, hostnames
  included. Only root can bind below 1024 on Ubuntu
  (`net.ipv4.ip_unprivileged_port_start = 1024`, checked at start; the daemon
  warns if it is lower).
- **The listening sockets go into systemd's file-descriptor store**
  (`FileDescriptorStoreMax=`, `FileDescriptorStorePreserve=yes`, systemd 259
  here). During a daemon restart the port stays bound, and new connections
  wait in the backlog until the new daemon accepts them; they are not refused.
  Established proxied connections are closed when the old process exits.
- Listeners exist for every configured profile while the daemon runs. When
  the profile is down, a request is answered with SOCKS reply `0x01`
  (general failure). The port stays reserved and the extension's view stays
  stable.
- **Credentials:** a random 128-bit username and password per profile, kept in
  `/run/vpncell/state/` (root-only, `tmpfs`). They survive daemon restarts and
  change at reboot. Compared in constant time.
- Outbound: hostname → profile DNS (section 5) → socket from the profile's
  factory (section 6) → non-blocking connect on the host goroutine → splice.
  IP literals skip DNS. If the profile has no DNS servers, hostname requests
  fail with reply `0x04`.
- Limits: per-profile connection cap, handshake timeout, no logging of
  destinations by default (debug logging can enable it, never credentials).

## 8. Terminal sessions

### 8.1 Flow

0. `vpncell shell <profile>` runs the caller's `$SHELL` (from the client's
   environment) as an interactive, non-login shell. If `$SHELL` is unset, the
   shell from the caller's passwd entry is used (review decision).
1. `vpncell shell work` (or `vpncell run work -- cmd …`) connects to
   `/run/vpncell/control.sock` and sends `exec` with argv, environment, cwd,
   `TERM`, the window size and whether stdin is a TTY. For non-TTY runs it
   attaches stdin, stdout and stderr with `SCM_RIGHTS`.
2. The daemon checks the caller (`SO_PEERCRED` for uid/gid/pid,
   `SO_PEERGROUPS` for supplementary groups) against the profile's access list
   and brings the profile up if `autostart = "on-use"`; otherwise it fails with
   `profile "work" is down; run: vpncell up work`.
3. The daemon starts `vpncelld session-helper` and hands it the client
   connection fd and the client's stdio fds. It moves the helper into a
   transient scope `vpncell-s-<profile>-<uid>-<id>.scope` under
   `vpncell-sessions.slice` (systemd D-Bus `StartTransientUnit`), and only then
   lets the helper continue. The scope keeps the session alive when the daemon
   restarts, and gives `down --kill` and `status` a clean handle.
4. The helper, still root, on one locked thread: `setns` into the profile
   namespace; `unshare(CLONE_NEWNS)`; makes `/` a recursive slave (host mounts
   such as USB drives still appear); sets up DNS files and masks (section 5);
   for TTY sessions opens a new pty pair; sets `PR_SET_NO_NEW_PRIVS`, drops
   the whole capability bounding set and the ambient and inheritable sets; then
   starts the command with `uid`, `gid` and supplementary groups of the
   caller, `setsid`, and the pty slave as controlling TTY. The child gets
   `VPNCELL_PROFILE=<name>`. It `chdir`s to the caller's cwd *after* dropping
   privileges, so permissions are checked as the user.
5. The helper then drops its own privileges to the caller (setresuid, empty
   capability sets, no_new_privs) and stays as the parent of the command to
   relay its exit status.

### 8.2 TTY handling (a change from the prompt; see section 12)

The prompt suggests passing the client's own controlling TTY to the child. A
TTY can be the controlling terminal of only one session, and that is the
user's outer shell, so the child could not get job control without stealing
it. Like `ssh`, `sudo` (`use_pty`) and `machinectl shell`, the helper creates
a **new pty** for the session and sends the **master fd to the client** over
`SCM_RIGHTS`. The client puts its own terminal in raw mode and copies bytes
between its terminal and the master. Data never flows through the daemon.

- Window size: the client handles `SIGWINCH` and sets `TIOCSWINSZ` on the
  master itself. The kernel then signals the session's foreground process
  group.
- Ctrl-C, Ctrl-Z and similar arrive as bytes, and the pty line discipline
  turns them into signals.
- Signals sent to the client process (`SIGTERM`, `SIGHUP`, …) are forwarded
  as messages to the helper, which signals the child's process group. When
  the client dies, the master closes and the session gets `SIGHUP`, as with
  ssh.
- Exit status: the helper sends `{exit_code}` or `{signal}`; the client exits
  with the code, or 128+signal.
- On start, `vpncell shell` prints a one-line warning that commands which hand
  work to an already-running instance (`firefox <url>`, `code`, `xdg-open`)
  escape the profile.

### 8.3 Effects users see (README)

- `sudo` and other setuid programs do not work inside a profile (no_new_privs,
  as required).
- `localhost` is the namespace's own loopback.
- Abstract Unix sockets belong to the network namespace. Listeners on this
  host: `@/tmp/.X11-unix/X0` (Xwayland), `@/tmp/.X11-unix/X1`
  (gnome-shell), multipathd, iscsiadm. X11 clients fall back to the path
  socket `/tmp/.X11-unix/X0`, so they still work. Wayland, the D-Bus session
  bus (`/run/user/<uid>/bus`), ssh-agent and gpg-agent use path sockets and
  work. Step 2 tests a list of common desktop programs and records the results
  in the README.
- Sessions are not part of the user's logind session (no PAM session).

## 9. Firefox extension

### 9.1 Manifest version: MV2 (persistent background page)

`proxy.onRequest` and native messaging exist in Firefox MV3, but there the
background is a non-persistent event page. When it is suspended, the in-memory
mapping cache is lost and the native messaging port is closed, so (a) a
request that wakes the page must wait for storage and a native round trip, and
(b) change notifications from the daemon are missed while it sleeps. That
breaks the "answer from an in-memory cache, never a round trip per request"
rule. MV2 with `"persistent": true` is fully supported in Firefox, and Mozilla
has announced no end date for MV2. If a spike at the start of step 4 shows
that MV3 keeps the page alive while a native port is open, I will switch and
say so.

**Spike result (2026-11-24, step 4; code in `test/spikes/mv3`).** A minimal
MV3 extension (event page, `proxy.onRequest` for `<all_urls>`, a native port
to a logging host, a 5 s timer that posts on the port) ran headless in the
tarball Firefox 161 with `extensions.background.idle.timeout = 30`:

- Run 1 (100 s): the page stayed alive; ticks continued without a gap and
  there was one page instance.
- Run 2 (70 s): ticks stopped about 30 s after start; the page was
  suspended although the native port was open. The next proxied navigation
  woke a **new** page instance (in-memory state gone, new native port), and
  that request had to wait for the page to start.

`proxy.onRequest` and native messaging work in MV3, but an open native port
does not reliably keep the event page alive, so the in-memory cache and the
daemon event stream can be lost at any time. **Decision: MV2 with a
persistent background page**, as designed.

### 9.2 Behaviour

- Mapping `cookieStoreId → profile` in `storage.local`. Only
  `firefox-container-*` IDs that exist in `contextualIdentities.query()` can
  be mapped. `firefox-default` and `firefox-private` are always direct, and the
  UI offers no mapping for them. `contextualIdentities.onRemoved` deletes the
  mapping; renames keep it. Containers from other extensions (Temporary
  Containers) get new IDs each time, so they are unmapped and direct
  (documented).
- `proxy.onRequest` for `<all_urls>`. The listener reads only the in-memory
  cache, never awaits I/O except once at startup, and is wrapped in
  `try/catch` whose fallback is the fail-closed proxy, because an exception in
  the listener would otherwise let the request through unproxied.
  - mapped and usable → `{type:"socks", host:"127.0.0.1", port, username,
    password, proxyDNS:true, failoverTimeout:1}`
  - mapped and not usable (profile down, daemon unreachable past the grace
    period, unknown profile) → **fail-closed proxy**
    `{type:"socks", host:"127.0.0.1", port:1, username:"-", password:"-", proxyDNS:true}`.
    Port 1 is privileged, so no local user can listen there, and connections
    are refused at once. Toolbar badge `!` and one notification per profile.
  - unmapped, default container, private window → `{type:"direct"}`
- **Daemon restart grace:** if the native host loses the daemon, the
  extension keeps using the cached SOCKS details for up to 30 s (the
  listening socket is held in systemd's fd store, so connections wait instead
  of failing), then switches to the fail-closed proxy.
- Cache refresh: on daemon events (profile up/down, credentials changed) pushed
  through the native host, and every 60 s as a fallback.
- Popup: per container its profile, state (up/connecting/down/failed), exit IP
  if known (under the state, no column of its own; §12 item 41), a profile
  selector, and up/down buttons when the user is allowed.

### 9.3 Native messaging

- Host name `vpncell`, manifest `allowed_extensions: ["<extension-id>"]` only.
  The extension ID will be `vpncell@gallbotond.github.io` (follows the final
  name).
- The `.deb` installs the manifest system-wide at
  `/usr/lib/mozilla/native-messaging-hosts/vpncell.json`. That path works for
  the tarball/deb Firefox *and* for the snap through the portal (the
  portal's search list, read from `/usr/libexec/xdg-desktop-portal`, contains
  `/usr/lib/mozilla/native-messaging-hosts`, `/usr/lib64/…`,
  `/usr/lib/x86_64-linux-gnu/mozilla/…` and `~/.mozilla/native-messaging-hosts`).
- `vpncell firefox-setup --user` writes a per-user copy to
  `~/.mozilla/native-messaging-hosts/`, as the prompt asks. Note: this host's
  user has neither `~/.mozilla` nor `~/.config/mozilla` (the snap keeps its
  profile under `~/snap/firefox/common/.mozilla`, which the portal does **not**
  read), so the system-wide manifest is the primary path.
- `vpncell-native` speaks Firefox's length-prefixed JSON on stdio and keeps one
  control-socket connection with a `subscribe` stream, so it can push changes.
  The daemon identifies the user by `SO_PEERCRED` of `vpncell-native`, which
  runs as that user.

### 9.4 Snap Firefox and the portal (main risk, see section 13)

Snap Firefox starts native hosts through `org.freedesktop.portal.WebExtensions`
(Ubuntu's xdg-desktop-portal 1.21.1 carries it; confirmed in the binary). The
portal (not the snap) starts `vpncell-native` on the host, unconfined, so the
control socket is reachable. On first use it asks the user through the GNOME
Access dialog and remembers the answer in the permission store table
`webextensions`. The automated tests pre-grant that entry over D-Bus
(`org.freedesktop.impl.portal.PermissionStore.SetPermission`) so they need no
click; the README tells users to expect the one-time dialog.

### 9.5 Non-snap Firefox for tests

Mozilla's official tarball, unpacked under `test/firefox/` (not committed),
driven by Mozilla's standalone `geckodriver` release. The snap's
`/snap/bin/geckodriver` is confined and can only drive the snap. Ubuntu
restricts unprivileged user namespaces through AppArmor
(`kernel.apparmor_restrict_unprivileged_userns = 1`), which degrades the
tarball Firefox's sandbox. The tests add a **test-only** AppArmor profile,
`vpncell-test-firefox`, that allows `userns` for that one path. It is
documented, not shipped in the `.deb`, and removed by the test teardown.

### 9.6 Traffic that can bypass the proxy

| Path | Handling |
|---|---|
| Extension not running (disabled, crashed, during an update) | Firefox has no listener and connects directly. **Cannot be prevented from an extension.** Documented as the main limitation. |
| Exception in the listener | `try/catch` → fail-closed proxy. |
| Startup race (container tabs restored before the cache is loaded) | The listener awaits the one-time load from `storage.local` (returns a Promise); requests before that are not answered direct. Covered by a test that restarts Firefox with restored container tabs. |
| `network.proxy.failover_direct` (default true) | Per Mozilla bug 1720221 it applies only (to be verified) to system-principal requests (updates and similar), which never carry a container. A test proves that a mapped container with a failing proxy shows an error page and produces no direct packets. |
| DNS for proxied requests | `proxyDNS: true` → names are resolved by the SOCKS server in the namespace. A capture test checks that no query for the test hostnames reaches the host resolver or the physical interface. |
| DNS-over-HTTPS (TRR) | Not used for proxied requests with remote DNS. Default tabs keep the user's TRR settings. Checked by the same capture test. |
| DNS prefetch, link prefetch, speculative connections, predictor | The extension sets `browser.privacy.network.networkPredictionEnabled = false`. This is **global** (it also affects default tabs); documented. |
| HTTP/3 / QUIC | Firefox does not use HTTP/3 through a SOCKS proxy. A capture test checks that no UDP/443 leaves the host for container requests. |
| WebRTC | `browser.privacy.network.webRTCIPHandlingPolicy = "disable_non_proxied_udp"` (global): WebRTC in a proxied tab uses only the proxy (TCP TURN), and default tabs keep working. A test with a STUN request in a container checks for leaks; if it leaks, fall back to `"proxy_only"`, which breaks WebRTC in default tabs, and document it. |
| Connection, cache and DNS sharing between containers | Firefox keys connections and cache by origin attributes (container) and proxy; the "same hostname, two containers" test proves no reuse. |

## 10. Profiles and import

### 10.1 Files

- `/etc/vpncell/profiles.d/<name>.toml`, mode `0600 root`.
- Secrets: `/etc/vpncell/secrets/<name>/` (`0700 root`): sanitized `wg.conf`
  or `client.ovpn`, key and certificate files, `auth.txt`.
- Daemon state: `/var/lib/vpncell/state.json` (SOCKS port allocations, profile
  indexes). Runtime: `/run/vpncell/` (control socket, per-profile generated files,
  credentials, OpenVPN management sockets), kept across daemon restarts
  (`RuntimeDirectoryPreserve=yes`).

```toml
backend   = "wireguard"        # "wireguard" | "openvpn"
autostart = "on-use"           # "boot" | "on-use" | "manual"
                               # on-use: `vpncell shell` and the extension bring it up
                               # manual: fail with "profile is down" instead

[wireguard]
config = "/etc/vpncell/secrets/work/wg.conf"     # sanitized at import

# [openvpn]
# config    = "/etc/vpncell/secrets/lab/client.ovpn"
# auth_file = "/etc/vpncell/secrets/lab/auth.txt" # optional, user/pass only

[dns]
servers    = ["10.99.0.53"]    # from wg DNS= or set by hand
search     = ["corp.example"]
use_pushed = true              # OpenVPN: also use pushed servers/domains

[access]
users  = ["alice"]             # root always allowed; caller must also be in group vpncell
groups = []

[routing]
routes = ["0.0.0.0/0", "::/0"] # default; a shorter list limits what the profile can reach
                               # ("::/0" applies only if the tunnel has IPv6)

[socks]
port = 0                       # 0 = allocate once from socks_port_range and keep

[status]
exit_ip_url = ""               # e.g. "https://ifconfig.me/ip"; empty = no exit-IP probe

[security]
nftables = true                # second layer; only for tests should this be false
```

Global settings: `/etc/vpncell/vpncell.toml` (`socks_port_range`, log level).

### 10.2 Import

`sudo vpncell import <name> <file> [--auth-file f]`. The CLI runs as root,
reads the file and any files it references, and sends everything inline to the
daemon (admin only, uid 0), which sanitizes, stores and prints a report. The
sanitizers are pure functions in `internal/importer`, unit-tested and fuzzed.

**WireGuard (`wg-quick` format)** — allowlist:

- Kept: `[Interface] PrivateKey, Address, DNS, MTU`; `[Peer] PublicKey,
  PresharedKey, AllowedIPs, Endpoint, PersistentKeepalive`.
- Stripped and reported: `PreUp, PostUp, PreDown, PostDown, SaveConfig,
  Table`, `ListenPort` (random port instead), `FwMark` (would interact with
  Tailscale's fwmark-based rules on the host).
- `DNS =` IP entries become `dns.servers`, name entries become `dns.search`.
- Rejected: unknown keys, AmneziaWG keys (`Jc, Jmin, Jmax, S1–S4, H1–H4,
  I1–I5`), since a plain WireGuard client cannot talk to an AmneziaWG server.
  (The test wg-easy has AmneziaWG settings stored but runs plain WireGuard, and
  its client configs do not contain those keys.)

**OpenVPN (`.ovpn`)** — an **allowlist**, not a denylist, so new or obscure
directives are rejected instead of slipping through:

- Kept: `client, dev tun (tap is rejected), dev-type tun, proto, remote,
  remote-random, nobind, persist-key, remote-cert-tls, verify-x509-name,
  cipher, data-ciphers, data-ciphers-fallback, auth, auth-nocache,
  tls-client, tls-version-min/max, tls-cipher, tls-ciphersuites, tls-groups,
  key-direction, ca, cert, key, tls-auth, tls-crypt, tls-crypt-v2, pkcs12,
  crl-verify, compress/comp-lzo (with a warning), allow-compression, verb,
  mute, mute-replay-warnings, explicit-exit-notify, keepalive, ping,
  ping-restart, ping-timer-rem, connect-retry, connect-retry-max,
  server-poll-timeout, hand-window, reneg-sec, mssfix, tun-mtu, fragment,
  sndbuf, rcvbuf, float, pull, pull-filter, route, route-ipv6, dhcp-option,
  dns, redirect-gateway (no effect; the namespace routes everything anyway),
  auth-user-pass (only with a file or --auth-file), ns-cert-type`.
- Stripped and reported (vpncell sets its own value or the option has no effect
  here): `user, group, persist-tun, resolv-retry, auth-retry nointeract,
  block-outside-dns, ignore-unknown-option, setenv, route-delay, verb >= 7`.
- **Rejected with a clear error:** everything that runs programs or loads code
  (`up, down, route-up, route-pre-down, ipchange, client-connect,
  client-disconnect, learn-address, tls-verify, auth-user-pass-verify, plugin,
  script-security, up-delay, down-pre, up-restart, dns-updown, providers,
  engine, pkcs11-providers, config`), everything that changes the host side
  (`dev-node, iproute, ifconfig-noexec, route-noexec, lladdr, mktun, rmtun,
  management*, daemon, log*, writepid, status, cd, chroot, tmp-dir,
  http-proxy, socks-proxy`), and everything that needs interaction
  (`auth-user-pass` without a file, `askpass` without a file,
  `static-challenge`, `auth-retry interact`, `management-query-passwords`,
  encrypted private keys).
- Inline blocks (`<ca>`, `<cert>`, `<key>`, `<tls-auth>`, `<tls-crypt>`,
  `<tls-crypt-v2>`, `<auth-user-pass>`, `<pkcs12>`) are written as root-only
  files and referenced by path.
- Nothing from an imported config is ever executed. The only commands
  `openvpn` runs are vpncell's own hook, set after the imported options.

## 11. Control socket protocol

- `/run/vpncell/control.sock`, `SOCK_STREAM`, mode `0660 root:vpncell`.
- Frames: 4-byte big-endian length + JSON (max 1 MiB). File descriptors travel
  as `SCM_RIGHTS` on the `sendmsg` that carries the frame's first byte.
- Every connection starts with `hello {version: 1}` → `{server_version, uid,
  admin}`. Unknown fields are ignored; unknown types get an error.

| Request | Who | Reply |
|---|---|---|
| `list` | any | profiles the caller may use: name, backend, state |
| `status {profile?}` | allowed users | state, exit IP, last handshake/connect, rx/tx bytes, SOCKS port, sessions (id, uid, pid, command, start time) |
| `up {profile}` / `down {profile, force, kill}` | allowed users | ok, or for `down` without flags: error listing the sessions |
| `exec {profile, argv, env, cwd, tty, term, winsize}` + fds | allowed users | the connection is handed to the session helper: `started {session_id}` (+ pty master fd), then `exit {code}` or `exit {signal}`; client → helper: `signal {sig}` |
| `socks {profile}` | allowed users | `{host:"127.0.0.1", port, username, password}` |
| `subscribe` | any | stream of `profile_changed {profile, state}` and `credentials_changed {profile}` events (only profiles the caller may use) |
| `import {name, files, options}` | root | report of kept/stripped/rejected items |
| `remove {profile, force, kill}` | root | take the profile down, delete its profile file and `secrets/<name>/`, free its index and SOCKS port (#17); without flags, error while it is up or has sessions |
| `reload` | root | re-read profile files |

`vpncell status --json` prints the `status` reply. Errors are
`{error: {code, message}}`. Limits: request size, per-uid exec rate,
idle timeouts. The SOCKS credentials are the only secret ever sent to a client.

## 12. Changes to and interpretations of the prompt

1. **Session TTY** (§8.2): new pty per session with the master sent to the
   client, instead of passing the client's controlling TTY to the child.
   Same user experience; job control works and the outer shell is untouched.
2. **Session helper process** (§8.1): the command's parent is a per-session
   helper in its own systemd scope, not the daemon. Without it a daemon restart
   would lose exit codes and systemd would kill the sessions with the service.
3. **OpenVPN as a systemd template unit** (§4.4), so it survives daemon
   restarts. The daemon still controls it; it is not "shelling out".
4. **Forced `dns-updown disable` and `disable-dco`** (§4.4): new in OpenVPN 2.7
   / kernel 7.0; not in the prompt.
5. **Split tunnel** (§10.1): there is no path to the host network from a
   namespace, so "split tunnel" can only *limit* what a profile reaches
   (`routing.routes`). Traffic outside the list is unreachable; it never
   goes direct.
6. **Privileged SOCKS ports and the fd store** (§7): not in the prompt;
   closes a port-squatting hole while the daemon is down and keeps the
   proxy reachable across restarts.
7. **SOCKS credentials stable across daemon restarts**, new at reboot (§7).
   The prompt allows them to change; keeping them avoids failed requests.
8. **Exit-IP probe is opt-in per profile** (`exit_ip_url`), because it
   contacts a third party through the tunnel.
9. **`down --force`** keeps the namespace (with only `lo`) while sessions live,
   so a later `up` gives those sessions network again. `--kill` stops their
   scopes.
10. **MV2** for the extension (§9.1).
11. **No `ProtectSystem`-style sandboxing for `vpncelld`**: a private mount
    namespace would hide `/run/netns` bind mounts from the host. The
    capability bounding set is still restricted.


### Changes made during the build

12. **Leak capture without a host firewall table** (§15.3). The build must
    not change this host's firewall chains, so no `inet vpncell_test` table
    is added. Captures run with `tcpdump` on the physical interface with the
    BPF filter `not (udp port <p> …)` for the UDP ports that `tailscaled`
    owns (read from `ss -ulpn`). Nothing else is filtered; leaks are found by
    test destinations, marker strings and non-VPN packets to the endpoint.
13. **Local lab over loopback** (§15.1). Lab servers use the same trick as
    the WireGuard backend: the server's tunnel device is created in the host
    namespace with its UDP socket on `127.0.0.1:<port>` and moved into the lab
    server namespace. No veth, address or route is added to the host.
14. **Daemon capabilities** (§13): the bounding set also needs
    `CAP_SETPCAP` (the session helper drops the bounding set),
    `CAP_CHOWN` (session pty owned by the user), `CAP_FOWNER` and
    `CAP_DAC_OVERRIDE` (root-only files under `/etc/vpncell` and `/run`).
15. **WireGuard keepalive** (§4.3): a peer without `PersistentKeepalive`
    gets 25 s, so that "time since last handshake" reflects tunnel health.
16. **`vpncell run` uses a pty** when stdin and stdout are terminals
    (`-t`/`-T` force it on or off); pipes and files are passed directly.
17. **Main thread pinned** (§6): `vpncelld` locks its main goroutine to the
    main thread, so a namespace worker can never wedge the main thread in a
    profile namespace.
18. **SIGHUP reloads profiles; no ignored signals** (§13). Ignored signal
    dispositions are inherited across `exec`, so the daemon must never
    `signal.Ignore` anything: a session would start with SIGHUP ignored and
    could not trap it. `ExecReload` sends SIGHUP.
19. **AppArmor and the session mount namespace** (§5, §8.3). Confined
    programs cannot connect to host path sockets from a session (AppArmor
    reports a "disconnected path"). The private mount namespace is required
    for per-profile DNS, so this is documented as a limitation instead.
20. **SOCKS serving starts after adoption** (§7, §13): listeners taken
    from the fd store are served only after the daemon has re-adopted the
    profiles, so a connection waiting in the backlog never sees a
    half-adopted profile (found by the restart test).
21. **SOCKS brings `on-use` profiles up** (§7): the first SOCKS request to
    a down profile with `autostart = "on-use"` brings it up, which is how
    the extension "uses" a profile. `manual` profiles fail the request.
22. **Leak rule for ICMP errors** (§15.3): ICMPv6 destination-unreachable
    errors that quote a UDP packet *from* the VPN port (the host's reply to
    server keepalives aimed at a closed client port) are not counted as
    leaks.
23. **Capture inside the test binary** (§15.3): `tcpdump`'s AppArmor
    profile on Ubuntu 26.04 refuses signals from other confined processes,
    so a capture started by the tests could not be stopped. The tests now
    capture with an `AF_PACKET` socket and write pcap themselves; the
    Tailscale exclusion (tailscaled's UDP ports) is applied in Go.
24. **Snap portal permission needs the user** (§9.4): pre-granting the
    WebExtensions portal permission over D-Bus from the build session was
    refused by the session's safety policy (it answers a consent dialog on
    the user's behalf). The user grants it once (README, "Snap Firefox");
    until then the snap browser tests fail with a clear "known failure"
    message.
25. **SOCKS answers "general failure" for every failed named request**
    (§7). With reply 0x04 (host unreachable) after a failed in-profile DNS
    lookup, Firefox treats the request as a DNS failure and then resolves
    the name itself through the host resolver (A/AAAA queries seen on the
    physical interface). With 0x01 it does not.
26. **Firefox's HTTPS-First looks names up outside the proxy** (§9.6).
    Firefox 161, default settings: every `http://` navigation in a mapped
    container makes Firefox query the host's HTTPS (type 65) record through
    the host resolver, for public and private names alike, although the tab
    uses SOCKS with `proxyDNS`. `https://` URLs do not. Turning off
    `network.dns.native_https_query` stops it (HTTPS-First stays on); with
    DNS-over-HTTPS enabled, HTTPS-First itself (`dom.security.https_first`)
    must also be off. No WebExtension API reaches these prefs, so vpncell
    provides `vpncell firefox-policy install [--strict]`, which adds locked
    prefs to `/etc/firefox/policies/policies.json` (read by the deb, tarball
    and snap Firefox). Installing it is a system-wide change to the user's
    Firefox, so the build session left it to the user, who decided
    (2026-11-24) that the package installs it by default: `postinst`
    installs it once (a marker in `/var/lib/vpncell` keeps an admin's
    later `firefox-policy remove` across upgrades), and `prerm` on removal
    takes vpncell's entries out again. `TestBrowserHTTPNameNoHostDNS`
    checks the real system configuration; the other browser tests set the
    same pref in their test profile.
27. **OpenVPN status through a cached management query** (§4.4): each
    management connection is logged by openvpn, so `state` and
    `load-stats` go over one connection and are cached for 10 s (the cache
    is bypassed while `up` waits for the first connection).
28. **OpenVPN unit capabilities** (§4.4): `CAP_NET_ADMIN CAP_SYS_ADMIN
    CAP_DAC_OVERRIDE`, `ProtectSystem=full`, `ProtectHome=yes`,
    `PrivateTmp=yes`, `Type=notify`. The hook also rewrites the profile's
    resolver files itself, so pushed DNS is right even while the daemon
    restarts.
29. **A connected OpenVPN profile without its tun device is broken** (§4.4):
    openvpn keeps running when its device is deleted, so status reports
    the tunnel missing when the management state is CONNECTED but the
    device is gone from the namespace, and the supervisor restarts the unit
    (found by the fail-closed tests; recovery takes about 5 s).
30. **Packaging with `dpkg-deb`** (§13, step 6): `packaging/build-deb.sh`
    builds the `.deb` from the Go binaries and the extension directly
    (no debhelper; Go modules are not packaged for offline builds). The
    maintainer scripts do what `dh_installsystemd --restart-after-upgrade`
    would: `prerm` does nothing on upgrade, `postinst` restarts the daemon,
    which adopts everything. On removal, `prerm` stops `vpncell.slice`
    (the implicit parent of `vpncell-sessions.slice`), the OpenVPN units
    and the daemon, then runs `vpncelld teardown` (namespaces, links,
    runtime files, per-user manifests). The NetworkManager drop-in lives
    in `/usr/lib/NetworkManager/conf.d/` (not a conffile). The package
    installs the Firefox policy of item 26.

### Changes after the build (issue run, 2026-11-26)

31. **Hello deadline in the client** (#8): systemd's fd store keeps the
    control socket listening while the daemon is stopped, so `client.Dial`
    waits for the hello reply with a deadline and checks the unit state
    (README "When the daemon is not running").
32. **OpenVPN state and log history** (#14): status reads `state all`
    (and, after a TLS error with a server reply, `log 500`) instead of
    `state`, to report why a tunnel does not connect.
33. **ping in sessions** (#10): `ping_group_range` copied from the host
    into each namespace; `/usr/bin/ping` bind-mounted `nosuid` in the
    session mount namespace (DECISIONS.md, "ping in profile sessions").
34. **Session identity** (#12): sessions get `VPNCELL_SESSION`; the daemon
    records each session's parent (the caller's session at `exec`) for
    nesting chains. It finds a caller's session from the systemd scope in
    `/proc/<pid>/cgroup` and its network from `/proc/<pid>/ns/net`. The
    latter needs ptrace read access, which the daemon lacks (no
    `CAP_SYS_PTRACE` in its bounding set, and none is added): the `stat`
    runs on a throwaway thread with fsuid/fsgid set to the caller's
    (`PTRACE_MODE_READ_FSCREDS` then sees the same user).
35. **`remove` and vanished profiles** (#17). `remove` refuses while the
    profile is up or has sessions; `--force` takes it down (sessions keep
    running without network), `--kill` ends the sessions. It deletes only
    `profiles.d/<name>.toml` and `secrets/<name>/`; config files a
    hand-written profile keeps elsewhere are named in the reply, not
    deleted. `reload` no longer orphans a profile whose file is gone while
    it is in use: it takes it down like `remove --force`. A file that is
    still there but no longer loads (a typo while editing) keeps the
    running version, with an error in the journal, so an edit cannot cut a
    live tunnel. The namespace of a removed profile stays while its
    sessions run and is deleted after the last one exits. At daemon start,
    a namespace without a profile has its OpenVPN unit stopped and its
    links deleted.
36. **`import --replace` keeps settings** (#16). The daemon parses the old
    profile and carries over `autostart`, `[access]`, `[dns]` (same
    backend only), `[routing]`, `[socks]`, `[status]` and `[security]`
    unless the request sets them; the CLI sends `$SUDO_USER` as a default
    for new profiles only. Secrets are written to
    `secrets/.<name>.new`, the profile is validated, the old folder is
    renamed to `secrets/.<name>.old`, the new one into place, and the
    profile file written; if that fails, the old folder is put back.
    Imports are serialized.
37. **Reconnect signal only when connected** (#31). After a host network
    change the OpenVPN backend asks the management socket for `state` and
    sends `SIGUSR1` only when it is `CONNECTED`. A connecting or waiting
    openvpn resolves the remote on its next attempt anyway, and a signal
    during its restart pause started the pause again, so steady host
    network churn kept it from ever connecting.
38. **Host network watcher stays subscribed** (#30). The netlink library
    closes an address or route subscription when a receive fails (for
    example `ENOBUFS` after a burst of events); the watcher then ended
    silently. Now each subscription logs the library's errors
    (`address watch error` / `route watch error`), and when it ends or
    cannot be made the daemon logs it and subscribes again after 2 s
    (doubling up to 1 min while it keeps failing). After a new
    subscription the address set is seeded again and one change is
    reported, since changes may have been missed. Errors caused by closing
    the subscription on shutdown are not logged.
39. **Identity conflicts with NetworkManager** (#19). `internal/conflict`
    reads NetworkManager's `ActiveConnections` over the system bus
    (`GetSettings` of each active VPN connection; read-only, 3 s timeout,
    cached 15 s) and the host namespace's WireGuard devices (wgctrl,
    vpncell's own `vpnwg*` excluded). It compares the SHA-256 of the
    profile's client certificate (DER) with each active NM OpenVPN
    connection's `cert` file (same subject CN: weaker warning), and the
    profile's WireGuard public key with the host devices' keys. Warnings
    are in `status` (`warnings`, not while down), in `up`'s reply and in
    the import report. Paths from NetworkManager are opened non-blocking
    and read only if they are regular files of at most 1 MiB, since any
    local user can create connections; key files are never read.
41. **Popup exit IP** (#36). The exit IP column is gone: the IP shows under
    the state pill when the daemon probed one (`[status] exit_ip_url`);
    a connected profile without it has a tooltip naming the setting.

## 13. Lifecycle

- **Unit** `vpncelld.service`: `Type=notify`, `Restart=on-failure`,
  `FileDescriptorStoreMax=256`, `FileDescriptorStorePreserve=yes`,
  `RuntimeDirectory=vpncell`, `RuntimeDirectoryPreserve=yes`,
  `CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_SETUID CAP_SETGID
  CAP_NET_BIND_SERVICE CAP_KILL`.
- **Start:** if `/run/vpncell/booted` is missing (first start since boot),
  remove leftovers: `/run/netns/vpncell-*` without a profile, host-namespace
  `vpnwg*`/`vpntun*` links, `vpncell-openvpn@*` units, then create the marker
  and start `autostart = "boot"` profiles. Otherwise **adopt**: for each
  `vpncell-*` namespace with a valid profile, find its tunnel (wgctrl inside
  the namespace, or the OpenVPN unit and management socket), take back the
  SOCKS listeners from the fd store, read the credentials, list session
  scopes. Anything that cannot be adopted is torn down. Running shells are
  never touched; they hold their own namespace references.
- **Upgrade:** `dh_installsystemd --restart-after-upgrade` restarts the
  daemon without stopping it first, so profiles and sessions stay up (adopt
  path).
- **Uninstall** (`prerm remove`): stop `vpncell-sessions.slice`, all
  `vpncell-openvpn@*` units and the daemon (with `down --kill` semantics),
  delete namespaces and links, remove the system native messaging manifest.
  `/etc/vpncell` is removed only on purge.
- **NetworkManager:** the package installs
  `/etc/NetworkManager/conf.d/vpncell.conf` with
  `unmanaged-devices=interface-name:vpnwg*;interface-name:vpntun*`, so NM never
  touches tunnel devices during the short time they exist in the host
  namespace. (Ubuntu-specific; lives in `internal/platform` and `packaging/`.)
- **Logging:** journal with sd-daemon priority prefixes. Secrets are wrapped
  in a type whose `String()`/`MarshalJSON()` return `<redacted>`; a test
  greps the journal for the test secrets.

## 14. In-namespace nftables (second layer)

```
table inet vpncell {
  chain output  { type filter hook output  priority 0; policy drop;
                  oifname "lo" accept; oifname "<tun>" accept; }
  chain input   { type filter hook input   priority 0; policy drop;
                  iifname "lo" accept; iifname "<tun>" accept; }
  chain forward { type filter hook forward priority 0; policy drop; }
}
```

Matched by interface *name*, so a recreated tun with the same name stays
covered. Installed with `google/nftables` inside the namespace before the
tunnel comes up. `security.nftables = false` exists only so the tests can show
that fail closed holds without it.

## 15. Tests

### 15.1 Test environment (from the inspection on 2026-11-24)

**Test VM `free-vm`** (Debian 12, Docker, `/opt/vpn-lab/docker-compose.yml`):

- wg-easy 15 (plain kernel WireGuard), `[<VM IPv6>]:51820`,
  clients `10.8.0.0/24` + `fdcc:ad94:bacf:61a4::cafe:0/112`, client
  `AllowedIPs = 172.30.0.0/16`, no DNS pushed. Two clients exist.
- OpenVPN 2.x server (d3vilh image), UDP6 1194, `10.0.70.0/24`, topology
  subnet, pushes `route 172.30.0.0/16`, **no DNS and no IPv6**. One client
  exists.
- Services: `whoami` at `172.30.1.10` (via WG) and `172.30.2.10` (via OVPN);
  iperf3 at `.11`; nginx at `.20`. **The overlap case already exists:**
  `172.30.0.80` is DNATed by each VPN server to its own page ("vpn-lab:
  WireGuard" vs "vpn-lab: OpenVPN"), and both VPNs route `172.30.0.0/16`.
  This is the VM's equivalent of the prompt's `10.99.0.0/24`.
- Internet egress: **IPv6 only**. The VM has no public IPv4 and no Cloud NAT;
  `curl -4 ifconfig.me` times out on the VM. Docker NAT66s the service
  networks, and wg-easy NAT66s its clients.
  **Update (2026-11-28):** the VM now has IPv4 egress too (`curl -4
  ifconfig.me` on the VM answers). Firefox and SOCKS clients may exit over
  IPv4; the tests accept the VM's IPv4 exit address, learned through
  `vm-wg`'s tunnel and checked to differ from the host's.
- Admin UIs work from this host over the tailnet (`http://free-vm:51821`,
  `http://free-vm:18080`); the wg-easy API accepts HTTP basic auth and the
  openvpn-ui login works. Tests read the credentials from `.env` at runtime.

**Local lab on this host (proposed, test-only):** a Go test harness creates
extra namespaces that act as VPN *servers*, each with its own service
behind `10.99.0.0/24` (a responder at `10.99.0.10` that reports which server
it is, and a DNS responder at `10.99.0.53` that gives different answers for
the same name). Two WireGuard servers and two OpenVPN servers, reached over a
test-only veth into the host namespace. The profile namespaces still contain
only `lo` and the tunnel. This gives exact `10.99.0.0/24` overlap for
WG+WG, OVPN+OVPN and WG+OVPN, DNS tests, and the thread-safety stress test,
fast and repeatable, without changing the VM. The VM covers the real-world
part: IPv6-only endpoints, internet exit IP, and the packet-capture leak
tests on `ens18`.

### 15.2 What the VM is missing (review decision: items 1, 2 and 4 approved, item 3 not)

1. **No DNS server behind either VPN, and neither pushes DNS.** Needed for
   the DNS tests and the "same hostname, different server" browser test
   against real tunnels. Proposal: one small DNS container per service network
   (for example `172.30.1.53` and `172.30.2.53`) that answers
   `web.vpn-lab.test → 172.30.0.80` on both and `whoami.vpn-lab.test` with
   different addresses on each side; wg-easy client DNS and OpenVPN
   `push "dhcp-option DNS …"` pointing to them.
2. **The OpenVPN tunnel has no IPv6, and the VM has no IPv4 egress**, so an
   OpenVPN profile cannot reach the internet at all; the exit-IP check
   (`curl https://ifconfig.me`) works only for WireGuard (exit
   the VM's IPv6 address). Proposal: enable `server-ipv6` plus NAT66 in the
   OpenVPN container (or add Cloud NAT for IPv4). Without it, OpenVPN exit
   checks use `whoami`'s `RemoteAddr` instead.
3. **One server per VPN type.** Two WireGuard profiles against the same
   wg-easy reach the *same* servers, so the overlap test for WG+WG and
   OVPN+OVPN cannot run against the VM. The local lab covers it; a second
   wg-easy and OpenVPN on the VM would be needed only if you want that case
   on real internet paths too.
4. New VPN clients (one more per type) will be created through the admin UIs,
   which DECISIONS allows.

### 15.3 Leak capture and Tailscale

Captures on the physical interface (`ens18`) must ignore Tailscale's own
traffic without hiding real leaks:

- tailscaled marks all its sockets with fwmark `0x80000/0xff0000` (that is
  what the host's `ip rule 5210` matches). A **test-only nftables table**
  (`inet vpncell_test`, separate from Tailscale's chains, removed afterwards)
  copies to `nflog` every outgoing packet on `ens18` whose mark is *not*
  `0x80000`, and the test captures `nflog:<group>`. Tailscale's packets
  never reach the capture; nothing else is filtered out. No vpncell code sets
  `SO_MARK` (checked by the lint test).
- Background host traffic (apt, snapd, the user's own Firefox) still
  appears. The tests therefore look for **markers**: random hostnames
  (`leak-<random>.vpn-lab.test`) and dedicated destinations used only by the
  test. A leak is any packet that carries a marker or goes to a test
  destination outside the tunnel. Additionally, every packet to the VPN
  endpoint must be UDP to 51820/1194.
- The host's routing tables, `ip rule`s and Tailscale chains are never
  modified. The VM's tailnet address is never used as an endpoint.

### 15.4 Test list (mapped to the required tests)

Every scenario runs with WG, OVPN and WG+OVPN profile sets. Root integration
tests are Go tests behind a build tag (`-tags=integration`), run with `sudo`.

| Required test | How |
|---|---|
| Isolation | Two profiles, each with its own shell and container, fetch `10.99.0.10` (local lab) and `172.30.0.80` (VM) at the same time; each sees its own server. |
| Fail closed | Delete or down the tunnel interface; shell and container requests fail; capture on `ens18` shows only encrypted packets to the endpoint. Run with nftables on and off. |
| DNS | Queries from shells and SOCKS reach only the profile's DNS (lab DNS logs + capture); nothing to `127.0.0.53`, avahi or `ens18` in plaintext. |
| Privileges | In a session: uid/gid/groups match the caller, `CapEff/CapPrm/CapBnd/CapAmb` = 0, `NoNewPrivs: 1`, `setns` into the host namespace fails with `EPERM`. |
| Access control | A second test user, in group `vpncell` but not in the profile's list: `exec` and `socks` are refused; a user outside `vpncell` cannot connect at all. |
| Thread safety | Thousands of concurrent SOCKS connections across 4 profiles to the overlapping `10.99.0.10`; every response must name the right server; the `SIOCGSKNS` mismatch counter must stay 0. Also run with `GOMAXPROCS=1` and with forced GC. |
| Browser | Go WebDriver client → geckodriver, snap and tarball Firefox, headless. Containers are created through Marionette's chrome context; the mapping is set through the real popup page. Exit/identity per container; daemon stopped → error page, no direct packets. |
| No sharing between containers | Two containers, same hostname (`web.vpn-lab.test`), different profiles, loaded at the same time and repeatedly; each sees its own page. |
| Default tabs and private windows | Direct (they see the host's normal path), regardless of mappings. |
| No host or LAN access | From a shell and a container: host `127.0.0.1` dev server, `127.0.0.53`, the host's LAN address, LAN gateway are unreachable; nftables on and off. |
| Import safety | Fixture configs with every rejected directive; a canary hook (`up /tmp/canary`) must never run; reports must list what was stripped. |
| Daemon restart | `systemctl restart vpncelld` during a running shell (with `ping`/`curl` loop) and a container page load loop; both keep working; capture shows no leak. Also `kill -9` the daemon. |
| `down` with sessions | refuse (lists sessions), `--force` (sessions alive, no network; `up` restores it), `--kill` (sessions gone). |

Plus unit tests and fuzzing for the importers, protocol framing and SOCKS
parsing, and an extension unit test for the decision function
(mapped/unmapped/default/private/daemon down/exception).

## 16. Open risks

1. **Snap Firefox native messaging.** Depends on Ubuntu's WebExtensions
   portal patch, the pref `widget.use-xdg-desktop-portal.native-messaging`
   (needs checking in the snap's defaults; Mozilla bug 1930119 shows it has
   broken before), and a one-time permission dialog. If the portal path fails
   on 26.04, the fallback is a documented manual step; there is no way around
   the portal for a confined snap.
2. **Fail-closed proxy in Firefox.** Firefox goes direct if the extension is
   not running, and historically when `proxy.onRequest` returned an invalid
   result (bug 1528873). The design avoids invalid results and exceptions,
   and step 4 must prove with captures that a mapped container never goes
   direct when the proxy fails, at startup and across daemon restarts. The
   "extension not running" case stays a documented limitation.
3. **WebRTC policy choice** (§9.6) may need `proxy_only`, which breaks WebRTC
   in default tabs.
4. **OpenVPN 2.7 specifics** (DCO default, `dns-updown`, the `dns_*`
   environment of the hook) are handled by forced options but untested so far.
5. **Session limitations:** no `sudo` inside profiles; programs that call
   resolved over the system D-Bus resolve through the host.
6. **Tailscale exit node:** if the user enables one, VPN endpoint packets
   (already encrypted) go through Tailscale. Not a leak, documented.
7. **Test VM gaps** (§15.2): DNS and IPv6-in-OpenVPN need a server-side
   change, and I will ask first.
