// Popup: per container its profile, state and exit IP; change the mapping;
// bring profiles up or down.
import { describeProblem, describeReach, ReachView, TunnelProblem } from "./decide.js";
import { exitIPView } from "./view.js";
interface PopupState {
  containers: { id: string; name: string; color: string; icon: string }[];
  mapping: Record<string, string>;
  profiles: Record<string, { state: string; autostart: string; exitIP?: string; problem?: TunnelProblem; reach?: ReachView }>;
  daemonUp: boolean;
  problems: Record<string, string>;
}

// UI state that must survive the 5 s redraw.
const busy = new Set<string>(); // profiles with an up/down request in flight
// Last failed action: "p:<profile>" for up/down (shown on every row using the
// profile, dropped once its state changes), "c:<container id>" for mapping.
const errors = new Map<string, { msg: string; state?: string }>();
const openRoutes = new Set<string>(); // container ids whose route list is expanded
let lastSelectInput = 0; // ms; last mousedown/keydown/focus on a mapping <select>

function el<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Record<string, string> = {}, text = ""): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  if (text) e.textContent = text;
  return e;
}

// Run a background command; keep a failure under `key` to show in the rows.
async function act(key: string, msg: object, state?: string): Promise<void> {
  try {
    await browser.runtime.sendMessage(msg);
    errors.delete(key);
  } catch (e) {
    errors.set(key, { msg: String(e instanceof Error ? e.message : e), state });
  }
}

function pill(state: string, blocked: string | undefined): HTMLElement {
  if (blocked) return el("span", { class: "pill bad" }, "blocked");
  const word = state.split(":")[0];
  const cls = word === "up" ? "up" : word === "down" ? "down" : word === "connecting" ? "connecting" : "bad";
  return el("span", { class: `pill ${cls}` }, word);
}

async function render(): Promise<void> {
  const s: PopupState = await browser.runtime.sendMessage({ cmd: "getState" });
  const root = document.getElementById("root")!;
  root.replaceChildren();
  const daemon = el("p", { id: "daemon", class: s.daemonUp ? "ok" : "bad" }, s.daemonUp ? "vpncelld: connected" : "vpncelld: not reachable — mapped containers are blocked");
  root.append(daemon);
  if (s.containers.length === 0) {
    root.append(el("p", {}, "No containers. Create Multi-Account Containers first; default tabs and private windows always connect directly."));
  }
  const table = el("table");
  const names = Object.keys(s.profiles).sort();
  // Mapped containers first; Array.sort is stable, so each group keeps its order.
  const containers = [...s.containers].sort((a, b) => Number(!s.mapping[a.id]) - Number(!s.mapping[b.id]));
  for (const c of containers) {
    const mapped = s.mapping[c.id];
    const tr = el("tr", { "data-container": c.id, class: mapped ? "mapped" : "direct" });
    const name = el("td", { class: "name" }, c.name);
    name.style.borderLeft = `4px solid ${c.color}`;
    const sel = el("select", { "data-container": c.id, class: "mapping" });
    sel.append(el("option", { value: "" }, "Direct (no VPN)"));
    for (const n of names) {
      const o = el("option", { value: n }, n);
      if (n === mapped) o.selected = true;
      sel.append(o);
    }
    if (mapped && !s.profiles[mapped]) {
      const o = el("option", { value: mapped }, `${mapped} (unavailable)`);
      o.selected = true;
      sel.append(o);
    }
    for (const ev of ["mousedown", "keydown", "focus"]) sel.addEventListener(ev, () => (lastSelectInput = Date.now()));
    sel.addEventListener("change", async () => {
      await act(`c:${c.id}`, { cmd: "setMapping", cookieStoreId: c.id, profile: sel.value || null });
      render();
    });
    const p = mapped ? s.profiles[mapped] : undefined;
    const blocked = mapped ? s.problems[mapped] : undefined;
    const state = el("td", { class: "state" });
    if (!mapped) state.append(el("span", { class: "muted" }, "direct"));
    else {
      const pl = pill(p?.state ?? "unknown", blocked);
      // Exit IP under the pill, only when the daemon probed one (issue #36).
      const ip = blocked ? null : exitIPView(p);
      if (ip?.title) pl.title = ip.title;
      state.append(pl);
      if (ip?.text) state.append(el("div", { class: "exitip" }, ip.text));
    }
    if (blocked) state.append(el("div", { class: "why" }, blocked));
    // Why the tunnel is not connected (issue #14).
    const why = mapped && !blocked ? describeProblem(p?.problem) : null;
    if (why) {
      state.append(el("div", { class: "why", title: why.detail }, why.summary));
      if (why.detail) state.append(el("div", { class: "hint" }, why.detail));
    } else if (mapped && !blocked && p?.state.includes(":")) {
      // e.g. "failed: tunnel interface missing" with no daemon reason.
      state.append(el("div", { class: "why" }, p.state.slice(p.state.indexOf(":") + 1).trim()));
    }
    // What the profile reaches; no fallback to the normal connection (issue #15).
    const reach = mapped && !blocked ? describeReach(p?.reach) : null;
    if (reach?.summary) {
      if (reach.routes.length > 0) {
        const d = el("details", { class: "reach" });
        d.open = openRoutes.has(c.id);
        d.addEventListener("toggle", () => (d.open ? openRoutes.add(c.id) : openRoutes.delete(c.id)));
        d.append(el("summary", {}, reach.summary), el("div", { class: "routes" }, reach.routes.join("\n")));
        state.append(d);
      } else state.append(el("div", { class: "reach" }, reach.summary));
    }
    for (const w of reach?.warnings ?? []) state.append(el("span", { class: "chip", title: w.title }, `⚠ ${w.label}`));
    const pErr = mapped ? errors.get(`p:${mapped}`) : undefined;
    if (pErr && pErr.state !== p?.state) errors.delete(`p:${mapped}`); // state moved on, e.g. autostart
    for (const e of [errors.get(`p:${mapped}`), errors.get(`c:${c.id}`)]) if (e) state.append(el("div", { class: "why" }, e.msg));
    const actions = el("td");
    if (mapped && p) {
      const up = p.state === "down";
      const b = el("button", { class: up ? "up" : "down" }, up ? "Up" : "Down");
      b.disabled = busy.has(mapped);
      b.addEventListener("click", async () => {
        busy.add(mapped);
        b.disabled = true;
        // Record the state as of the click; the error is dropped when it changes.
        await act(`p:${mapped}`, { cmd: up ? "up" : "down", profile: mapped }, p.state);
        busy.delete(mapped);
        render();
      });
      actions.append(b);
    }
    const tdSel = el("td");
    tdSel.append(sel);
    tr.append(name, tdSel, state, actions);
    table.append(tr);
  }
  root.append(table);
}

render();
// Redrawing replaces the <select>, which would close an open dropdown. A
// select keeps focus after Escape or re-picking its value, so skip only
// shortly after input on it, not for as long as it is focused.
// ponytail: time-boxed guess, a dropdown left open >10 s idle closes; patch
// rows in place instead of rebuilding if that bites.
setInterval(() => {
  if (document.activeElement?.tagName === "SELECT" && Date.now() - lastSelectInput < 10_000) return;
  render();
}, 5000);
