// The proxy decision for one request. Pure, so it can be unit-tested; the
// background page calls it from proxy.onRequest with its in-memory cache.
import { DAEMON_GRACE_MS, FAIL_CLOSED_PORT } from "./constants.js";

export interface SocksDetails {
  host: string;
  port: number;
  username: string;
  password: string;
}

export interface ProfileView {
  state: string; // down | connecting | up | failed: ...
  autostart: string; // boot | on-use | manual
  socks?: SocksDetails;
  exitIP?: string;
  problem?: TunnelProblem;
}

// Why a tunnel is not connected, from `status` (daemon fields reason,
// reason_text, hint, retries, reason_at, log; issue #14).
export interface TunnelProblem {
  reason: string;
  text: string;
  hint?: string;
  retries?: number;
  at?: number; // unix seconds
  log?: string;
}

export function problemFromStatus(s: any): TunnelProblem | undefined {
  if (!s || typeof s.reason !== "string" || s.reason === "" || s.state === "up") return undefined;
  return {
    reason: s.reason,
    text: typeof s.reason_text === "string" && s.reason_text ? s.reason_text : s.reason,
    hint: typeof s.hint === "string" && s.hint ? s.hint : undefined,
    retries: typeof s.retries === "number" ? s.retries : undefined,
    at: typeof s.reason_at === "number" ? s.reason_at : undefined,
    log: typeof s.log === "string" && s.log ? s.log : undefined,
  };
}

// One line for the popup, e.g. "no reply from the server (3 failed
// attempts)", and the longer hint with the log command.
export function describeProblem(p: TunnelProblem | undefined): { summary: string; detail: string } | null {
  if (!p) return null;
  let summary = p.text;
  if (p.retries && p.retries > 0) summary += ` (${p.retries} failed attempt${p.retries === 1 ? "" : "s"})`;
  const detail = [p.hint, p.log ? `Log: ${p.log}` : ""].filter(Boolean).join(". ");
  return { summary, detail };
}

export interface State {
  ready: boolean;
  mapping: Record<string, string>; // cookieStoreId -> profile
  profiles: Record<string, ProfileView>;
  daemonUp: boolean;
  daemonDownSince: number; // ms epoch, 0 if up
}

export type ProxyResult =
  | { type: "direct" }
  | {
      type: "socks";
      host: string;
      port: number;
      username: string;
      password: string;
      proxyDNS: true;
      failoverTimeout?: number;
    };

export const DIRECT: ProxyResult = { type: "direct" };

export const FAIL_CLOSED: ProxyResult = {
  type: "socks",
  host: "127.0.0.1",
  port: FAIL_CLOSED_PORT,
  username: "-",
  password: "-",
  proxyDNS: true,
};

export interface RequestView {
  cookieStoreId?: string;
  incognito?: boolean;
}

/** Only Multi-Account Containers can be mapped. */
export function isMappableContainer(id: string | undefined): boolean {
  return !!id && id.startsWith("firefox-container-");
}

export type Reason = "direct" | "proxied" | "not-ready" | "unknown-profile" | "daemon-down" | "no-credentials" | "profile-down";

export function decideWithReason(req: RequestView, st: State, now: number): [ProxyResult, Reason, string?] {
  // Private windows and default tabs always connect directly.
  if (req.incognito) return [DIRECT, "direct"];
  const id = req.cookieStoreId;
  if (!isMappableContainer(id)) return [DIRECT, "direct"];
  const profile = st.mapping[id!];
  if (!profile) return [DIRECT, "direct"];
  // From here on the container is mapped: never direct.
  if (!st.ready) return [FAIL_CLOSED, "not-ready", profile];
  const p = st.profiles[profile];
  if (!p) return [FAIL_CLOSED, "unknown-profile", profile];
  if (!st.daemonUp && now - st.daemonDownSince > DAEMON_GRACE_MS) return [FAIL_CLOSED, "daemon-down", profile];
  if (!p.socks) return [FAIL_CLOSED, "no-credentials", profile];
  if (p.state === "down" && p.autostart === "manual") return [FAIL_CLOSED, "profile-down", profile];
  return [
    {
      type: "socks",
      host: p.socks.host,
      port: p.socks.port,
      username: p.socks.username,
      password: p.socks.password,
      proxyDNS: true,
      failoverTimeout: 1,
    },
    "proxied",
    profile,
  ];
}

export function decide(req: RequestView, st: State, now: number): ProxyResult {
  return decideWithReason(req, st, now)[0];
}

/** Hosts that Firefox never sends through a proxy (allow_hijacking_localhost
 * is false by default). Requests to them from mapped containers are
 * cancelled, so a container never reaches the host's loopback. */
export function isLoopbackHost(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (/^127\.\d+\.\d+\.\d+$/.test(h)) return true;
  if (h === "0.0.0.0" || h === "::" || h === "::1" || h === "0:0:0:0:0:0:0:1") return true;
  if (/^::ffff:127\./.test(h)) return true;
  // Decimal/hex/octal IPv4 forms of 127.x are normalised by Firefox's URL
  // parser before the request reaches the extension.
  return false;
}
