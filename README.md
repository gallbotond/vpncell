# vpncell

vpncell keeps several VPN connections up at the same time, each in its own
Linux network namespace (a *cell*), and lets you choose which one a program
uses:

- **Terminal:** `vpncell shell <profile>` opens a shell whose traffic goes
  only through that profile's VPN. `vpncell run <profile> -- <cmd>` runs one
  command.
- **Firefox:** a WebExtension maps Multi-Account Containers to profiles.

WireGuard and OpenVPN profiles are supported, side by side.

Profiles may use the same private address ranges and internal hostnames; they
never see each other, the host's `localhost` or the LAN. If a tunnel is down,
traffic fails instead of falling back to the normal connection.

Design: [docs/DESIGN.md](docs/DESIGN.md). Build history and open items:
[docs/PROGRESS.md](docs/PROGRESS.md).

## Install (Ubuntu 26.04 LTS)

```bash
packaging/build-deb.sh            # builds bin/vpncell_<version>_amd64.deb
sudo apt install ./bin/vpncell_*_amd64.deb
sudo usermod -aG vpncell "$USER"  # then log out and in again
```

The new group applies only to login sessions that start **after**
`usermod`: log out of the desktop and in again (opening a new terminal is
not enough). To use vpncell at once without logging out, for example for a
demo, start a shell that has the group, or run one command with it:

```bash
newgrp vpncell                    # this shell only
sg vpncell -c 'vpncell list'      # one command
```

If a command says `permission denied on /run/vpncell/control.sock`, the
message tells you which case it is: not in the group (`usermod`), or in the
group but in a login session that started before (`newgrp`/`sg`, or log in
again).

The package installs:

| Path | What |
|---|---|
| `/usr/sbin/vpncelld` | the daemon (`vpncelld.service`, enabled and started) |
| `/usr/bin/vpncell` | the command-line client |
| `/usr/lib/vpncell/vpncell-native` | Firefox native messaging host |
| `/usr/lib/mozilla/native-messaging-hosts/vpncell.json` | its manifest (deb, tarball and snap Firefox) |
| `/usr/lib/systemd/system/vpncell-openvpn@.service` | one OpenVPN tunnel per profile, started by the daemon |
| `/usr/lib/NetworkManager/conf.d/90-vpncell.conf` | keeps NetworkManager away from tunnel devices |
| `/usr/share/vpncell/vpncell-unsigned.xpi` | the Firefox extension (unsigned) |
| `/etc/vpncell/vpncell.toml` | global settings (SOCKS port range) |

and creates the group `vpncell`. Members may talk to the daemon; each
profile's `[access]` list decides who may use it.

Then import a profile and use it:

```bash
sudo vpncell import work ~/Downloads/work.conf      # wg-quick file
sudo vpncell import lab ~/Downloads/lab.ovpn        # OpenVPN; --auth-file for user/password
vpncell shell work
```

### Upgrade

Installing a newer `.deb` restarts the daemon without stopping anything:
tunnels, namespaces, SOCKS ports and sessions stay, and the new daemon
adopts them.

### Uninstall

`sudo apt remove vpncell` stops all sessions and OpenVPN tunnels, removes
every namespace, tunnel device, SOCKS listener and runtime file, and the
native messaging manifests (system-wide and the per-user copies written by
`vpncell firefox-setup --user`). Profiles stay in `/etc/vpncell`.
`sudo apt purge vpncell` also removes `/etc/vpncell`, `/var/lib/vpncell`
and the `vpncell` group. Removal also takes vpncell's entries out of the
Firefox policy file.

You must be in the `vpncell` group to talk to the daemon, and listed in the
profile's `[access]` section (`import` adds the user who ran `sudo`).

### When the daemon is not running

Commands never hang on a stopped daemon. systemd keeps the control socket
open while `vpncelld` is stopped (so restarts and upgrades never refuse a
connection), which means a command cannot see at once that nobody is
there. After 2 s without an answer it prints `waiting for vpncelld…` and
checks the unit: if `vpncelld.service` is stopped it fails with
`vpncelld is stopped (start it with: sudo systemctl start vpncelld; …)`.
While the daemon is restarting (`systemctl restart`, a package upgrade, a
crash followed by `Restart=`) the command keeps waiting and then
completes; it gives up after 30 s with `vpncelld is not answering`.
The Firefox extension's native host uses the same rules.

### Building from source

Needs `golang-go` (1.26) and Node.js/npm (for the extension).

```bash
make build extension    # bin/vpncelld, bin/vpncell, bin/vpncell-native, bin/vpncell.xpi
make test               # unit tests
```

## Profile files

`/etc/vpncell/profiles.d/<name>.toml` (root-only), written by `import`;
edit as root and run `sudo vpncell reload`:

```toml
backend   = "wireguard"        # or "openvpn"
autostart = "on-use"           # "boot" | "on-use" (shell, run, SOCKS bring it up) | "manual"

[wireguard]
config = "/etc/vpncell/secrets/work/wg.conf"
# [openvpn]
# config = "/etc/vpncell/secrets/lab/client.ovpn"

[dns]
servers    = ["10.99.0.53"]
search     = ["corp.example"]
use_pushed = true              # OpenVPN: also use pushed DNS (default for OpenVPN)

[access]
users  = ["alice"]
groups = []

[routing]
routes = ["0.0.0.0/0", "::/0"] # default; a shorter list limits what the profile reaches

[socks]
port = 0                       # 0 = allocated once from socks_port_range

[status]
exit_ip_url = ""               # e.g. "https://ifconfig.me/ip" (opt-in; contacts that site)
```

A profile reaches only what is behind its tunnel: never the host's
`localhost`, the systemd-resolved stub or the LAN. There is no setting to
allow that.

### Removing a profile

```bash
sudo vpncell remove work
```

This deletes `/etc/vpncell/profiles.d/work.toml` and
`/etc/vpncell/secrets/work/` (keys, certificates) and frees the profile's
SOCKS port. While the profile is up or has sessions, `remove` refuses, like
`down`: `--force` takes it down first (its sessions keep running without
network; the namespace goes when the last one exits), `--kill` ends the
sessions. Config files that a hand-written profile keeps outside
`secrets/<name>/` are listed, not deleted. Firefox containers mapped to the
profile show an error page (never a direct connection) until you map them
to another profile.

If you delete a profile file by hand instead, `sudo vpncell reload` takes
the profile down the same way. A profile file that no longer loads (for
example a typo while editing) does not stop a running profile: it keeps
running with the old settings, and `journalctl -u vpncelld` shows the error.

## Commands

| Command | What it does |
|---|---|
| `vpncell list` | profiles you may use and their state |
| `vpncell current [--json]` | the session, nesting chain and network this terminal is in |
| `vpncell status [--json] [profile]` | state, exit IP, last handshake, traffic, SOCKS port, sessions |
| `vpncell up <profile>` / `down [--force\|--kill] <profile>` | bring a profile up or down (for OpenVPN, `up` exits with 3 if the tunnel is not connected after its 20 s wait; see "When an OpenVPN profile does not connect") |
| `vpncell shell <profile>` | your shell inside the profile |
| `vpncell run [-t\|-T] <profile> -- <cmd>...` | one command inside the profile |
| `sudo vpncell import [--user u] [--group g] <name> <file>` | import a `wg-quick` or `.ovpn` config |
| `sudo vpncell remove [--force\|--kill] <profile>` | take a profile down and delete its profile file and `/etc/vpncell/secrets/<name>/` (see "Removing a profile") |
| `sudo vpncell reload` | re-read `/etc/vpncell/profiles.d` |

## Terminal sessions

- `vpncell shell <profile>` starts your `$SHELL` (taken from the
  environment of the `vpncell` command) as an **interactive, non-login**
  shell (`$SHELL -i`). If `$SHELL` is unset, the shell from your passwd
  entry is used. The shell gets `VPNCELL_PROFILE=<profile>` and
  `VPNCELL_SESSION=<session id>`, so a prompt can show them, for example in
  `~/.bashrc`: `PS1='${VPNCELL_PROFILE:+[$VPNCELL_PROFILE] }'"$PS1"`.
- `vpncell shell` prints `vpncell: entering profile B (session <id>; type
  exit to leave)` and, when the shell ends, `vpncell: left profile B (back
  on the host network)`; nested, the banner shows the path (`A → B`) and
  "back in profile A". On a terminal it also sets the window/tab title to
  `[vpncell: B] user@host` and restores the previous title on exit (xterm
  title stack; shells whose prompt sets the title, such as Ubuntu's default
  `~/.bashrc`, overwrite it at the first prompt). `VPNCELL_QUIET=1` turns
  the banner and the title off.
- `vpncell current` says where you are: the session, its nesting chain
  (`aff5cf31eeef (A) → 1b2c3d4e5f60 (B)`), and the network of the calling
  process (a profile and its state, or `host`). The daemon finds these from
  the caller's systemd scope and network namespace, not from the
  environment variables, which can be copied or changed; if
  `VPNCELL_PROFILE` disagrees, `current` says so. It exits with 1 outside a
  session; `--json` gives the same as JSON. `vpncell status` marks your own
  session with `<- this session` and its outer sessions.
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
- Sessions can be nested: `vpncell shell B` or `vpncell run B -- …` inside a
  session of profile A works. The daemon starts the new session itself, in
  B's namespace, so its traffic goes through B's tunnel only, never A's or the
  host's. The two sessions are connected only by the local terminal. The same
  access check applies as from the host (your user and B's `[access]` list),
  so nesting gives no extra access. `VPNCELL_PROFILE` is set to B in the inner
  session; `exit` returns to A.

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

`ping` (IPv4 and IPv6) works in a profile. Ubuntu's `/usr/bin/ping` has
the file capability `cap_net_raw`, which a session (no capabilities,
`no_new_privs`) cannot use: `execve` would fail with "Operation not
permitted". In each session `ping` is therefore bind-mounted onto itself
`nosuid`, so it runs without its file capability and uses an unprivileged
ICMP socket; the profile namespace allows those for the same groups as
the host (`net.ipv4.ping_group_range`, copied from the host). Sessions
still get no capability (DECISIONS.md, "ping in profile sessions").
Sessions started before vpncell 0.9.6 was installed keep the old
behaviour until you open a new one.

## SOCKS5 proxy (used by the Firefox extension)

For every configured profile the daemon listens on `127.0.0.1:<port>`
(SOCKS5, CONNECT only, username/password). `vpncell socks <profile>` prints
`socks5h://user:pass@127.0.0.1:<port>` for profiles you may use, for example
`curl -x "$(vpncell socks work)" https://ifconfig.me`.

- Every outbound connection and every DNS lookup for a SOCKS request is made
  from a socket created **inside** the profile's namespace, by threads that
  entered the namespace once and never leave it; each socket's namespace is
  checked with `SIOCGSKNS` before use.
- Hostnames are resolved with the profile's DNS servers and search domains
  only (never the host's `/etc/hosts` or resolver). A profile without DNS
  servers fails hostname requests.
- Ports are allocated once from `socks_port_range` (default `700-799`,
  privileged so no local user can take them over while the daemon is
  stopped) and saved in `/var/lib/vpncell/state.json`; `[socks] port` fixes
  one. Credentials are random per profile, kept in `/run/vpncell` (new after
  a reboot) and only given to users allowed on the profile.
- The listening sockets stay bound while the daemon restarts (systemd's fd
  store): new connections wait and then succeed. Connections that were
  already established are closed when the daemon process stops.
- When a profile is down, requests fail (SOCKS "general failure"); with
  `autostart = "on-use"` the first request brings the profile up.
- UDP ASSOCIATE is not supported.

## Firefox

The extension maps **Multi-Account Containers** to profiles. Every request
from a tab in a mapped container goes through that profile's SOCKS proxy;
names are resolved inside the profile (`proxyDNS`).

- Install the add-on (`bin/vpncell.xpi` from `make extension`; it is
  unsigned, see "Signing" below) and the native messaging host. The `.deb`
  installs the host manifest system-wide in
  `/usr/lib/mozilla/native-messaging-hosts/vpncell.json`; `vpncell
  firefox-setup --user` also writes a per-user copy to
  `~/.mozilla/native-messaging-hosts/`.
- Open the toolbar popup and choose a profile per container. The popup shows
  each container's profile, state (up, connecting, down, failed or
  blocked) and exit IP (if the profile sets `[status] exit_ip_url`), and
  has Up/Down buttons.
- **Only Multi-Account Containers can be mapped.** Default tabs and private
  windows always connect directly. Containers made by other extensions (for
  example Temporary Containers) get a new ID each time, so they are never
  mapped and connect directly. Deleting a container removes its mapping;
  renaming keeps it (mappings are keyed by `cookieStoreId` and stored in
  `storage.local`, never synced).
- **Fail closed:** if a mapped container's profile is unknown, down with
  `autostart = "manual"`, or the daemon has been unreachable for more than
  30 s, its requests get a proxy on `127.0.0.1:1` that always fails, the
  toolbar icon shows a red "!" and a notification names the profile. They
  never go direct. During the first 30 s of a daemon restart the cached
  proxy details stay in use (the SOCKS ports stay bound, so connections
  wait).
- Requests from mapped containers to the host's loopback (`localhost`,
  `127.0.0.0/8`, `[::1]`) are cancelled: Firefox never sends loopback
  addresses through a proxy, so they would otherwise go to the host.

### The vpncell Firefox policy (installed by the package)

With Firefox's default settings, opening an `http://` address in a mapped
container makes Firefox (its HTTPS-First mode) look up the site's HTTPS DNS
record **itself, through the host's resolver**, outside the proxy. The
hostname then leaves through your normal connection (a DNS leak). This
happens for public and private names; `https://` addresses are not
affected. An extension cannot change the prefs involved, so the package
installs a Firefox enterprise policy when it is first installed (the same
as running `sudo vpncell firefox-policy install`).

It adds `network.dns.native_https_query = false` (locked) to
`/etc/firefox/policies/policies.json`, keeping any other policies in that
file; restart Firefox afterwards. HTTPS-First stays on. If you use
DNS-over-HTTPS in Firefox, use `install --strict`, which also turns
HTTPS-First off (otherwise the lookup goes to your DoH server).
The policy applies to every Firefox profile on the machine (deb, tarball
and snap builds read this file) and to all tabs, not only containers.

To opt out, run `sudo vpncell firefox-policy remove`; upgrades keep that
choice (they do not add the policy again). Without the policy the leak
above is back. Removing the package takes vpncell's entries out of the file
and keeps any other policies in it.

### Snap Firefox

Ubuntu's snap Firefox starts native messaging hosts through the desktop
portal (`org.freedesktop.portal.WebExtensions`), which reads the
system-wide manifest (not `~/.mozilla`, which the snap does not use). The
first time, the portal asks in a dialog whether Firefox may start
"vpncell"; answer **Allow**. The answer is stored in the portal's permission
store. You can also grant it from a terminal in your desktop session:

```bash
gdbus call --session --dest org.freedesktop.impl.portal.PermissionStore --object-path /org/freedesktop/impl/portal/PermissionStore --method org.freedesktop.impl.portal.PermissionStore.SetPermission webextensions true vpncell snap.firefox "['yes']"
```

### Traffic that could bypass the proxy

| Path | How vpncell handles it |
|---|---|
| The extension is not running (disabled, being updated or reloaded) | Firefox then has no proxy listener and connects directly. **An extension cannot prevent this**; it is the main limitation of the browser part. |
| An error inside the proxy listener | Caught; mapped containers get the failing proxy. |
| Startup (tabs restored before the mapping is loaded) | The listener waits for the stored mapping and briefly for the daemon; a mapped container is never answered "direct". |
| `network.proxy.failover_direct` | Tested: with the daemon stopped and with the tunnel removed, mapped containers show an error page and the capture shows no direct packet. |
| DNS for proxied requests, DNS-over-HTTPS | `proxyDNS: true`: the SOCKS server resolves inside the profile. With TRR-only mode, lab names still load in containers. A failed lookup is reported to Firefox as a general proxy failure, because "host unreachable" makes Firefox retry the name through the host resolver. |
| HTTPS-First's HTTPS-record lookup for `http://` addresses | Prevented by the vpncell Firefox policy, which the package installs; without it the hostname **leaks to the host resolver** (see above). |
| DNS prefetch, link prefetch, speculative connections | Turned off with `privacy.network.networkPredictionEnabled = false`. This is a **global** setting: it also applies to default tabs. |
| HTTP/3 (QUIC) | Firefox does not use HTTP/3 through a SOCKS proxy; the test loads an HTTP/3 site in a container and sees no UDP/443 on the host interface. |
| WebRTC | `privacy.network.webRTCIPHandlingPolicy = "disable_non_proxied_udp"` (global): WebRTC in a proxied tab uses only the proxy; default tabs keep working. Tested with a STUN request from a mapped container: no UDP to the STUN server, no host candidates. |
| Connection, cache and DNS sharing between containers | Firefox keys them by container and proxy; the test loads the same hostname in two containers at the same time and each gets its own server. |

### Signing

`make extension` builds an unsigned `bin/vpncell.xpi`. Release Firefox only
installs signed add-ons; `packaging/amo-sign.sh` signs it as an *unlisted*
add-on with your own AMO API keys. (The build never uploads anything to
Mozilla.)

## OpenVPN profiles

`sudo vpncell import NAME file.ovpn [--auth-file creds.txt] [--tls-auth]` imports an
OpenVPN client config. Files it references (`ca`, `cert`, `key`,
`tls-auth`, `tls-crypt`, …) and inline blocks are stored root-only in
`/etc/vpncell/secrets/NAME/`. Logins use stored credentials only: a config
that needs a password prompt, a one-time code or an encrypted private key
is rejected (decrypt the key first; give username and password with
`--auth-file` or an `<auth-user-pass>` block).

`--tls-auth` is for servers that use `tls-auth` while the config carries
the key as `<tls-crypt>` (some openvpn-ui setups): it imports the same key
as `<tls-auth>` with `key-direction 1`. Use it only when you know the
server uses tls-auth; for a tls-crypt server it makes the profile fail
(`vpncell status` then says "no reply from the server"). vpncell never
does this on its own.

Each OpenVPN profile runs as the systemd unit `vpncell-openvpn@NAME`
(`journalctl -u vpncell-openvpn@NAME` for its log). vpncell adds its own
options after the imported ones: `ifconfig-noexec`, `route-noexec`, its
own up hook (which moves the tun device into the profile's namespace and
configures it there), `persist-tun`, `disable-dco` and
`dns-updown disable` (OpenVPN 2.7 would otherwise change the host's DNS).
DNS servers and search domains pushed by the server are used
(`[dns] use_pushed = true`). IPv6 works when the server pushes an IPv6
address; otherwise IPv6 fails closed.

### When an OpenVPN profile does not connect

OpenVPN keeps retrying, so the profile stays `connecting`. vpncell reads
openvpn's own state history and tells you why each attempt failed:

```
$ vpncell status work
work (openvpn, autostart on-use)
  state:          connecting (no reply from the server; 3 failed attempts, last 11:08:30)
  hint:           the server never answered the TLS handshake. Usually the
                  config's tls-auth/tls-crypt key or mode (or key-direction)
                  ...
  log:            journalctl -u vpncell-openvpn@work.service
  trying since:   3m12s ago
```

`connected:` is shown only while the profile is up; otherwise `trying
since:` says since when it has been without a connection.
`vpncell status --json` has the same as `reason`, `reason_text`, `hint`,
`retries`, `reason_at`, `trying_since` and `log`; the Firefox popup shows
the reason under the container's state.

| `reason` | Meaning | What to check |
|---|---|---|
| `no-reply` | The server never answered (openvpn stayed in `WAIT`). | `tls-auth` vs `tls-crypt`, the key and `key-direction` must match the server; is the server reachable? |
| `stalled-after-server-cert` | The server sent its certificate, then went silent. With TLS 1.3 this is how a **refused client certificate** looks (revoked, replaced or removed on the server). | Get a current client config; compare it with one that works. |
| `tls-error` | The server answered, the TLS handshake failed otherwise. | Certificates, `tls-auth`/`tls-crypt`, TLS settings. |
| `auth-failure` | The server refused the login. | Username/password (`--auth-file`), certificate. |
| `ping-restart` | A connected tunnel stopped getting keepalive replies. | Server or network. |

OpenVPN gives up on a TLS handshake after 60 s (`hand-window`), so the
first reason can take that long to appear. `vpncell up` waits up to 20 s
for the connection; if the tunnel is not connected by then, it prints the
reason known so far and the `journalctl` command, and exits with status 3.
The profile keeps trying in the background.

### I can't reach the internet (or some hosts) through a profile

A profile sends **all** its traffic into its tunnel (`[routing] routes`,
default `0.0.0.0/0` and `::/0`) and never falls back to your normal
connection. If the VPN server is a **split tunnel**, which offers only some
networks, every other address fails in the profile:

| Server | What happens to other addresses |
|---|---|
| WireGuard with `AllowedIPs = 172.30.0.0/16` | dropped locally, connections fail at once |
| OpenVPN that pushes `route 172.30.0.0 255.255.0.0` and no `redirect-gateway` | sent to the server, which does not forward them: timeouts |
| No DNS servers (none in the config, none pushed) | every hostname lookup fails |

vpncell tells you:

- `vpncell import` warns when a WireGuard config's `AllowedIPs` have no
  default route, when it has no DNS servers or a DNS server outside
  `AllowedIPs`, and when an OpenVPN config has no `redirect-gateway`.
- `vpncell status` shows `reaches:` (WireGuard `AllowedIPs`, a hard
  limit) or `server routes:` (OpenVPN pushed routes and whether
  `redirect-gateway` was pushed), `DNS: none`, and DNS servers that are
  not reachable through the tunnel; `--json` has `reaches`, `routes`,
  `routes_source`, `redirect_gateway`, `split_tunnel`, `no_dns` and
  `dns_unreachable`. The Firefox popup shows the same notes.
- The daemon logs what each tunnel carries
  (`journalctl -u vpncelld | grep "tunnel routes"`).

A profile reaches the internet only if its server routes the default route
(WireGuard `AllowedIPs = 0.0.0.0/0, ::/0`; OpenVPN `redirect-gateway def1`)
and forwards (NATs) that traffic, and DNS is set (`[dns] servers` or
pushed). This is intended: falling back to the host connection would break
the guarantee that profile traffic never goes direct.

## Import safety

Imported configs are untrusted. Nothing from a config is ever executed.

- **WireGuard:** only an allowlist of keys is kept. `PreUp`, `PostUp`,
  `PreDown`, `PostDown`, `SaveConfig`, `Table`, `ListenPort` and `FwMark`
  are stripped and listed; unknown keys, unknown sections and AmneziaWG keys
  are rejected.
- **OpenVPN:** an allowlist of directives is kept. Directives that run
  programs or load code (`up`, `down`, `route-up`, `ipchange`,
  `tls-verify`, `auth-user-pass-verify`, `learn-address`, `plugin`,
  `script-security`, `config`, `dns-updown`, …), change the host (`dev-node`,
  `route-noexec`, `management`, `daemon`, `log`, `writepid`, `chroot`,
  proxies, …) or need interaction (`auth-user-pass` without credentials,
  `static-challenge`, `auth-retry interact`, encrypted keys) are rejected
  with the reason. Directives vpncell sets itself or that have no effect
  (`user`, `group`, `persist-tun`, `resolv-retry`, `dev`, `setenv`,
  `verb` ≥ 7, Windows-only options, …) are stripped and listed. Unknown
  directives are rejected. `dev tap` is not supported.

## Tests

- `make test`: unit tests, fuzz targets (run with `go test -fuzz`), and
  source lint checks (setns only in allowed packages, no `SO_MARK`, no
  shelling out from the daemon).
- `make itest`: root integration tests (DESIGN.md §15.4). They install the
  test build (`test/scripts/dev-install.sh`), start a local lab and use the
  test VM. `RUN=<regexp>` selects tests; `VPNCELL_TEST_VM=0` skips the VM;
  `VPNCELL_TEST_INSTALLED=1` tests the installed `.deb`.
- `sudo test/scripts/package-test.sh`: builds two package versions,
  installs the first, upgrades to the second while sessions run in every
  profile set (no request may fail), removes and purges it, then installs
  the package again and runs the whole integration suite against it.

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

Captures run on the physical interface from an `AF_PACKET` socket inside
the test binary, which writes a pcap file; `tcpdump -r` only reads it
afterwards. (`tcpdump` itself is not used to capture: Ubuntu confines it with
an AppArmor profile that refuses signals from other confined processes, so
it could not be stopped.) Tailscale's own traffic is left out by the UDP
ports `tailscaled` owns (found with `ss -ulpn`); nothing else is left out. A
leak is a packet to a test destination (`10.99.0.0/24`, `172.30.0.0/16`,
tunnel ranges), a marker string (random `leak…` hostnames and paths) in
clear text, or any packet to the VPN endpoint that is not UDP 51820/1194.
One exception: ICMPv6 "destination unreachable" errors that quote a UDP
packet *from* the VPN port. The host kernel sends them when the server keeps
sending keepalives to the closed port of an earlier client; they carry no
profile traffic. No host firewall rule is added.

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

4. **tls-crypt on the OpenVPN server** (2026-11-26, issue #13). openvpn-ui
   always writes the server's `ta.key` into downloaded client configs as
   `<tls-crypt>`, but the server used `tls-auth pki/ta.key 0`, so a
   downloaded config could not connect without a manual rewrite. Changed
   `tls-auth pki/ta.key 0` to `tls-crypt pki/ta.key` in
   `/opt/vpn-lab/openvpn/server.conf` and the same value in openvpn-ui's
   database (`/opt/vpn-lab/openvpn/db/data.db`, table `o_v_config`, column
   `t_l_s_control_channel`), so a later save in the UI keeps it; then
   `docker restart openvpn`. Backups: `server.conf.bak-vpncell-20261126072854`,
   `db/data.db.bak-vpncell-20261126072854`. The key is unchanged.
   Clients that still use `<tls-auth>` must be re-downloaded from the UI
   (`proxmox-test`, on another machine). Note: saving the server settings
   in openvpn-ui regenerates `server.conf` from its database, which does
   not contain the `server-ipv6` line from item 2.

Client configs downloaded from openvpn-ui now work as they are;
`test/scripts/vm-fetch-configs.sh` no longer rewrites them.

`test/scripts/vm-fetch-configs.sh` downloads the two client configs to
`/var/lib/vpncell-test/vm` (root-only), reading the admin credentials from
`.env` at run time.

## Known limitations

See also DESIGN.md §12 (every change made during the build) and §16.

- **Firefox: `http://` hostnames leak to the host resolver without the
  vpncell Firefox policy.** The package installs it; if you remove it
  (`firefox-policy remove`), or run a Firefox that ignores
  `/etc/firefox/policies`, the leak is back. With DNS-over-HTTPS on, use
  `firefox-policy install --strict` (turns HTTPS-First off).
- **Firefox: if the extension is not running** (disabled, being updated or
  reloaded), Firefox connects mapped containers directly. An extension
  cannot prevent this.
- **Snap Firefox** needs the one-time portal permission (dialog or the
  `gdbus` command in "Snap Firefox"); until then the extension cannot
  reach the daemon and mapped containers fail closed.
- Firefox's prefetch/speculative-connection and WebRTC settings that
  vpncell sets are **global**: they also apply to default tabs.
- Containers of other extensions (Temporary Containers) are never mapped
  and connect directly.
- Release Firefox needs a signed extension (`packaging/amo-sign.sh` with
  your AMO keys).

- Programs that ask systemd-resolved directly over the system D-Bus (for
  example `resolvectl query`) resolve through the host. glibc, curl, Go,
  Python and Firefox do not do this.
- `sudo` and other setuid programs do not work inside a profile
  (`no_new_privs`). Programs that need raw sockets or other capabilities
  (`arping`, `tcpdump`, `mtr` in raw mode) do not work either; `ping` is
  handled specially and works.
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
- Established SOCKS connections (for example a long download in a mapped
  Firefox container) are cut when the daemon restarts; new connections wait
  and succeed.
- Sessions are not part of your logind session (no PAM session), and they
  run with the daemon's resource limits.
- Commands that hand work to a program already running outside the profile
  (`firefox <url>`, `code`, `xdg-open`) escape the profile.
- IPv6 works in a profile only when its tunnel has an IPv6 address;
  otherwise IPv6 connections fail at once (no fallback).
- OpenVPN: `dev tap`, static-key mode, interactive logins (OTP, password
  prompts) and encrypted private keys are not supported. DCO is turned
  off.
- When a profile's tunnel device disappears, the supervisor recreates it
  (WireGuard at once, OpenVPN within about 5 s); meanwhile the profile has
  no network (fail closed).
- A Tailscale exit node on the host carries the (encrypted) VPN tunnel
  packets; that is not a leak, but the tunnel then depends on it.
- Ubuntu 26.04 LTS only; other distributions are untested (Ubuntu-specific
  code is in `internal/platform`).
