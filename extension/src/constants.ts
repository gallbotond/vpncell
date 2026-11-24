// Product names in one place (the TypeScript side of internal/brand).
export const NATIVE_HOST = "vpncell";
export const PRODUCT = "vpncell";
// A proxy that always fails: port 1 is privileged (no local user can listen
// there) and nothing listens, so connections are refused at once.
export const FAIL_CLOSED_PORT = 1;
// How long cached SOCKS details stay in use while the daemon is unreachable
// (its listening sockets are held by systemd, so connections wait).
export const DAEMON_GRACE_MS = 30_000;
export const REFRESH_MS = 60_000;
