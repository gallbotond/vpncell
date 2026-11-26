// vpncell background page (MV2, persistent; see DESIGN.md §9.1).
//
// proxy.onRequest answers only from the in-memory cache below. The cache is
// filled from vpncelld through the native messaging host and refreshed on
// daemon events and on a timer; never per request.
import { NATIVE_HOST, REFRESH_MS, DAEMON_GRACE_MS, PRODUCT } from "./constants.js";
import {
  State,
  ProfileView,
  decideWithReason,
  FAIL_CLOSED,
  DIRECT,
  isMappableContainer,
  isLoopbackHost,
  ProxyResult,
  TunnelProblem,
  problemFromStatus,
} from "./decide.js";

const st: State = { ready: false, mapping: {}, profiles: {}, daemonUp: false, daemonDownSince: Date.now() };

// ---- native messaging ----

type Pending = { resolve: (v: any) => void; reject: (e: Error) => void; timer: number };
let port: browser.runtime.Port | null = null;
let nextID = 1;
const pending = new Map<number, Pending>();
let firstContact: () => void = () => {};
const firstContactP = new Promise<void>((r) => (firstContact = r));

function connect(): void {
  try {
    port = browser.runtime.connectNative(NATIVE_HOST);
  } catch (e) {
    port = null;
    markDaemonDown();
    setTimeout(connect, 2000);
    return;
  }
  port.onMessage.addListener(onNative as any);
  port.onDisconnect.addListener(() => {
    port = null;
    for (const [, p] of pending) {
      clearTimeout(p.timer);
      p.reject(new Error("native host disconnected"));
    }
    pending.clear();
    markDaemonDown();
    firstContact();
    setTimeout(connect, 2000);
  });
}

function call(type: string, profile?: string): Promise<any> {
  return new Promise((resolve, reject) => {
    if (!port) {
      reject(new Error("native host not connected"));
      return;
    }
    const id = nextID++;
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error("timeout"));
    }, 15000) as unknown as number;
    pending.set(id, { resolve, reject, timer });
    port.postMessage({ id, type, profile });
  });
}

function onNative(msg: any): void {
  if (msg && typeof msg.id === "number" && msg.id > 0) {
    const p = pending.get(msg.id);
    if (!p) return;
    pending.delete(msg.id);
    clearTimeout(p.timer);
    if (msg.ok) p.resolve(msg.result);
    else p.reject(new Error(msg.error?.message ?? "error"));
    return;
  }
  const ev = msg?.event;
  if (!ev) return;
  switch (ev.kind) {
    case "daemon_up":
      st.daemonUp = true;
      st.daemonDownSince = 0;
      // A new daemon may have new credentials (after a reboot).
      refreshCredentials().catch(() => {});
      break;
    case "daemon_down":
      markDaemonDown();
      firstContact();
      break;
    case "profile_changed":
      if (ev.profile && st.profiles[ev.profile] && ev.state) st.profiles[ev.profile].state = ev.state;
      scheduleRefresh(200);
      break;
    case "credentials_changed":
      refreshCredentials().catch(() => {});
      break;
  }
}

function markDaemonDown(): void {
  if (st.daemonUp || st.daemonDownSince === 0) {
    st.daemonUp = false;
    st.daemonDownSince = Date.now();
  }
  updateBadge();
  setTimeout(updateBadge, DAEMON_GRACE_MS + 500);
}

// ---- cache refresh ----

let refreshTimer: number | null = null;
function scheduleRefresh(delay: number): void {
  if (refreshTimer !== null) return;
  refreshTimer = setTimeout(() => {
    refreshTimer = null;
    refresh().catch(() => {});
  }, delay) as unknown as number;
}

async function refresh(): Promise<void> {
  let status: any[];
  try {
    status = (await call("status")) ?? [];
  } catch {
    updateBadge();
    return;
  }
  const seen = new Set<string>();
  for (const s of status) {
    seen.add(s.name);
    const old = st.profiles[s.name];
    const v: ProfileView = { state: s.state, autostart: s.autostart, exitIP: s.exit_ip || undefined, socks: old?.socks, problem: problemFromStatus(s) };
    st.profiles[s.name] = v;
    // Credentials change only when the daemon restarted after a reboot or
    // the port changed; fetch them when unknown or when the port moved.
    if (!v.socks || v.socks.port !== s.socks_port) {
      try {
        const c = await call("socks", s.name);
        v.socks = { host: c.host, port: c.port, username: c.username, password: c.password };
      } catch {
        v.socks = undefined;
      }
    }
  }
  for (const name of Object.keys(st.profiles)) if (!seen.has(name)) delete st.profiles[name];
  st.daemonUp = true;
  st.daemonDownSince = 0;
  firstContact();
  updateBadge();
}

async function refreshCredentials(): Promise<void> {
  // After a daemon event saying credentials changed, drop all and refetch.
  for (const v of Object.values(st.profiles)) v.socks = undefined;
  await refresh();
}

// ---- failure reporting ----

const notified = new Set<string>();

function problems(): Map<string, string> {
  const out = new Map<string, string>();
  const now = Date.now();
  for (const [cid, profile] of Object.entries(st.mapping)) {
    const [, reason] = decideWithReason({ cookieStoreId: cid }, st, now);
    if (reason !== "proxied" && reason !== "direct") out.set(profile, reason);
  }
  return out;
}

function describe(reason: string): string {
  switch (reason) {
    case "daemon-down":
      return "vpncelld is not reachable";
    case "unknown-profile":
      return "profile unknown or not allowed";
    case "profile-down":
      return "profile is down";
    case "no-credentials":
      return "no proxy credentials";
    case "not-ready":
      return "starting";
  }
  return reason;
}

function updateBadge(): void {
  const p = problems();
  const text = p.size > 0 ? "!" : "";
  browser.browserAction.setBadgeText({ text }).catch(() => {});
  browser.browserAction.setBadgeBackgroundColor({ color: "#d70022" }).catch(() => {});
  const lines = [...p].map(([prof, why]) => `${prof}: ${describe(why)}`);
  browser.browserAction.setTitle({ title: lines.length ? `${PRODUCT}: blocked\n${lines.join("\n")}` : PRODUCT }).catch(() => {});
  for (const [prof, why] of p) {
    if (notified.has(prof)) continue;
    notified.add(prof);
    browser.notifications
      .create(`vpncell-${prof}`, {
        type: "basic",
        title: `${PRODUCT}: ${prof} blocked`,
        message: `Tabs in containers mapped to "${prof}" cannot connect: ${describe(why)}. They never fall back to a direct connection.`,
      })
      .catch(() => {});
  }
  for (const prof of [...notified]) if (!p.has(prof)) notified.delete(prof);
}

// ---- the proxy listener ----

let initDone: () => void = () => {};
const initP = new Promise<void>((r) => (initDone = r));

function answer(details: browser.proxy._OnRequestDetails): ProxyResult {
  const [r, reason] = decideWithReason(
    { cookieStoreId: details.cookieStoreId, incognito: details.incognito },
    st,
    Date.now(),
  );
  if (reason !== "proxied" && reason !== "direct") updateBadge();
  return r;
}

function safeFallback(details: { cookieStoreId?: string; incognito?: boolean }): ProxyResult {
  try {
    return !details.incognito && isMappableContainer(details.cookieStoreId) ? FAIL_CLOSED : DIRECT;
  } catch {
    return FAIL_CLOSED;
  }
}

// Registered synchronously at load time, so no request is ever handled
// before the listener exists while this extension runs.
browser.proxy.onRequest.addListener(
  (details): any => {
    try {
      if (!st.ready && isMappableContainer(details.cookieStoreId) && !details.incognito) {
        // Startup: wait for the mapping (and briefly for the daemon), then
        // decide. Never direct for a container that might be mapped.
        const timeout = new Promise<void>((r) => setTimeout(r, 10000));
        return Promise.race([initP, timeout]).then(
          () => {
            try {
              return st.ready ? answer(details) : FAIL_CLOSED;
            } catch {
              return FAIL_CLOSED;
            }
          },
          () => FAIL_CLOSED,
        );
      }
      return answer(details);
    } catch {
      return safeFallback(details);
    }
  },
  { urls: ["<all_urls>"] },
);

browser.proxy.onError.addListener((e) => {
  console.warn("vpncell proxy error", e);
});

// Firefox never proxies loopback hosts (network.proxy.allow_hijacking_localhost
// is false by default), so requests from mapped containers to them are
// cancelled here; a profile never reaches the host's loopback.
browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    try {
      if (details.incognito || !isMappableContainer(details.cookieStoreId)) return {};
      if (!st.mapping[details.cookieStoreId!] && st.ready) return {};
      const host = new URL(details.url).hostname;
      if (isLoopbackHost(host)) return { cancel: true };
    } catch {
      return { cancel: true };
    }
    return {};
  },
  { urls: ["<all_urls>"] },
  ["blocking"],
);

// ---- containers and mapping ----

async function saveMapping(): Promise<void> {
  await browser.storage.local.set({ mapping: st.mapping });
}

browser.contextualIdentities.onRemoved.addListener(async ({ contextualIdentity }) => {
  if (st.mapping[contextualIdentity.cookieStoreId]) {
    delete st.mapping[contextualIdentity.cookieStoreId];
    await saveMapping();
    updateBadge();
  }
});

async function pruneMapping(): Promise<void> {
  let ids: Set<string>;
  try {
    ids = new Set((await browser.contextualIdentities.query({})).map((c) => c.cookieStoreId));
  } catch {
    return;
  }
  let changed = false;
  for (const cid of Object.keys(st.mapping)) {
    if (!ids.has(cid) || !isMappableContainer(cid)) {
      delete st.mapping[cid];
      changed = true;
    }
  }
  if (changed) await saveMapping();
}

// ---- popup messages ----

browser.runtime.onMessage.addListener(async (msg: any, sender) => {
  if (sender.id !== browser.runtime.id) return undefined;
  switch (msg?.cmd) {
    case "getState": {
      let containers: browser.contextualIdentities.ContextualIdentity[] = [];
      try {
        containers = await browser.contextualIdentities.query({});
      } catch {}
      const profiles: Record<string, { state: string; autostart: string; exitIP?: string; problem?: TunnelProblem }> = {};
      for (const [n, p] of Object.entries(st.profiles)) profiles[n] = { state: p.state, autostart: p.autostart, exitIP: p.exitIP, problem: p.problem };
      const prob: Record<string, string> = {};
      for (const [k, v] of problems()) prob[k] = describe(v);
      return {
        containers: containers.map((c) => ({ id: c.cookieStoreId, name: c.name, color: c.colorCode, icon: c.icon })),
        mapping: st.mapping,
        profiles,
        daemonUp: st.daemonUp,
        problems: prob,
      };
    }
    case "setMapping": {
      const cid = String(msg.cookieStoreId);
      if (!isMappableContainer(cid)) throw new Error("only Multi-Account Containers can be mapped");
      if (msg.profile) st.mapping[cid] = String(msg.profile);
      else delete st.mapping[cid];
      await saveMapping();
      updateBadge();
      return { ok: true };
    }
    case "up":
    case "down": {
      await call(msg.cmd, String(msg.profile));
      await refresh();
      return { ok: true };
    }
    case "refresh":
      await refresh();
      return { ok: true };
  }
  return undefined;
});

// ---- start ----

async function start(): Promise<void> {
  // Global privacy settings (DESIGN.md §9.6): they apply to all tabs.
  browser.privacy.network.networkPredictionEnabled.set({ value: false }).catch(() => {});
  browser.privacy.network.webRTCIPHandlingPolicy.set({ value: "disable_non_proxied_udp" }).catch(() => {});
  try {
    const got = await browser.storage.local.get("mapping");
    st.mapping = (got.mapping as Record<string, string>) ?? {};
  } catch {
    st.mapping = {};
  }
  connect();
  // Give the daemon a moment so the first requests can be proxied instead
  // of failing closed; never longer than a few seconds.
  await Promise.race([firstContactP, new Promise((r) => setTimeout(r, 4000))]);
  st.ready = true;
  initDone();
  updateBadge();
  await pruneMapping();
  setInterval(() => {
    refresh().catch(() => {});
    updateBadge();
  }, REFRESH_MS);
}

start();
