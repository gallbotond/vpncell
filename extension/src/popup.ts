// Popup: the profiles (state, exit IP, Up/Down, which containers use them)
// and the containers (which profile each uses).
import { describeProblem, describeReach, ReachView, TunnelProblem } from "./decide.js";
import { CONTAINERS_NOTE, containerIcon, exitIPView, headerView, orderContainers, profileOrder, profileUsers, thisTab } from "./view.js";
interface PopupState {
  containers: { id: string; name: string; color: string; icon: string; iconUrl?: string }[];
  mapping: Record<string, string>;
  profiles: Record<string, { state: string; autostart: string; exitIP?: string; problem?: TunnelProblem; reach?: ReachView }>;
  daemonUp: boolean;
  problems: Record<string, string>;
}

// UI state that must survive the 5 s redraw.
const busy = new Set<string>(); // profiles with an up/down request in flight
// Last failed action: "p:<profile>" for up/down (shown on the profile's card,
// dropped once its state changes), "c:<container id>" for mapping.
const errors = new Map<string, { msg: string; state?: string }>();
const openRoutes = new Set<string>(); // profiles whose route list is expanded
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

// The container's icon in its colour, like Firefox's own container UI
// (issue #39); a colour dot if Firefox gave no icon.
function icon(c: { color: string; iconUrl?: string }): HTMLElement {
  const i = containerIcon(c.iconUrl, c.color);
  const span = el("span", { class: i ? "cicon" : "cicon dot" });
  span.style.backgroundColor = i ? i.color : c.color;
  if (i) span.style.maskImage = i.mask;
  return span;
}

function pill(state: string, blocked: string | undefined): HTMLElement {
  if (blocked) return el("span", { class: "pill bad" }, "blocked");
  const word = state.split(":")[0];
  const cls = word === "up" ? "up" : word === "down" ? "down" : word === "connecting" ? "connecting" : "bad";
  return el("span", { class: `pill ${cls}` }, word);
}

// One card per profile (issue #34): state, why, reach, Up/Down, and the
// containers that use it. The tunnel details show once per profile.
function profileCard(s: PopupState, n: string, users: string[]): HTMLElement {
  const p = s.profiles[n];
  const blocked = s.problems[n];
  const card = el("div", { class: "card", "data-profile": n });
  const head = el("div", { class: "head" });
  const pl = pill(p.state, blocked);
  // Exit IP under the pill, only when the daemon probed one (issue #36).
  const ip = blocked ? null : exitIPView(p);
  if (ip?.title) pl.title = ip.title;
  head.append(el("span", { class: "pname" }, n), pl);
  const up = p.state === "down";
  const b = el("button", { class: up ? "up" : "down" }, up ? "Up" : "Down");
  b.disabled = busy.has(n);
  b.addEventListener("click", async () => {
    busy.add(n);
    b.disabled = true;
    // Record the state as of the click; the error is dropped when it changes.
    await act(`p:${n}`, { cmd: up ? "up" : "down", profile: n }, p.state);
    busy.delete(n);
    render();
  });
  head.append(b);
  card.append(head);
  if (ip?.text) card.append(el("div", { class: "exitip" }, ip.text));
  if (blocked) card.append(el("div", { class: "why" }, blocked));
  // Why the tunnel is not connected (issue #14).
  const why = blocked ? null : describeProblem(p.problem);
  if (why) {
    card.append(el("div", { class: "why", title: why.detail }, why.summary));
    if (why.detail) card.append(el("div", { class: "hint" }, why.detail));
  } else if (!blocked && p.state.includes(":")) {
    // e.g. "failed: tunnel interface missing" with no daemon reason.
    card.append(el("div", { class: "why" }, p.state.slice(p.state.indexOf(":") + 1).trim()));
  }
  // What the profile reaches; no fallback to the normal connection (issue #15).
  const reach = blocked ? null : describeReach(p.reach);
  if (reach?.summary) {
    if (reach.routes.length > 0) {
      const d = el("details", { class: "reach" });
      d.open = openRoutes.has(n);
      d.addEventListener("toggle", () => (d.open ? openRoutes.add(n) : openRoutes.delete(n)));
      d.append(el("summary", {}, reach.summary), el("div", { class: "routes" }, reach.routes.join("\n")));
      card.append(d);
    } else card.append(el("div", { class: "reach" }, reach.summary));
  }
  for (const w of reach?.warnings ?? []) card.append(el("span", { class: "chip", title: w.title }, `⚠ ${w.label}`));
  const err = errors.get(`p:${n}`);
  if (err && err.state !== p.state) errors.delete(`p:${n}`); // state moved on, e.g. autostart
  else if (err) card.append(el("div", { class: "why" }, err.msg));
  card.append(el("div", { class: "uses" }, users.length ? `Used by: ${users.join(", ")}` : "No container uses it"));
  return card;
}

// A container row: its name and the profile dropdown (issue #34).
function containerRow(s: PopupState, c: PopupState["containers"][number], names: string[], current: boolean): HTMLElement {
  const mapped = s.mapping[c.id];
  const tr = el("tr", { "data-container": c.id, class: (mapped ? "mapped" : "direct") + (current ? " current" : "") });
  const name = el("td", { class: "name" });
  name.append(icon(c), el("span", {}, c.name));
  if (current) name.append(el("span", { class: "tag" }, "this tab"));
  const sel = el("select", { "data-container": c.id, class: "mapping" });
  sel.append(el("option", { value: "" }, "Direct (no VPN)"));
  for (const n of names) {
    const o = el("option", { value: n }, n);
    if (n === mapped) o.selected = true;
    sel.append(o);
  }
  const td = el("td");
  td.append(sel);
  if (mapped && !s.profiles[mapped]) {
    const o = el("option", { value: mapped }, `${mapped} (unavailable)`);
    o.selected = true;
    sel.append(o);
    // No card for it: say here that the container is blocked.
    td.append(el("div", { class: "why" }, `blocked: ${s.problems[mapped] ?? "profile unavailable"}`));
  }
  for (const ev of ["mousedown", "keydown", "focus"]) sel.addEventListener(ev, () => (lastSelectInput = Date.now()));
  sel.addEventListener("change", async () => {
    await act(`c:${c.id}`, { cmd: "setMapping", cookieStoreId: c.id, profile: sel.value || null });
    render();
  });
  const e = errors.get(`c:${c.id}`);
  if (e) td.append(el("div", { class: "why" }, e.msg));
  tr.append(name, td);
  return tr;
}

// The tab the popup was opened for (issue #35).
async function activeTab(): Promise<browser.tabs.Tab | undefined> {
  try {
    return (await browser.tabs.query({ active: true, currentWindow: true }))[0];
  } catch {
    return undefined;
  }
}

// "This tab: Work → sonrisa (up)" or "This tab connects directly".
function thisTabLine(s: PopupState, tab: browser.tabs.Tab | undefined): HTMLElement {
  const t = thisTab(tab, s.containers, s.mapping);
  const line = el("div", { id: "thistab" });
  if (t.kind === "direct") {
    line.classList.add("direct");
    line.textContent = t.text;
    return line;
  }
  const c = s.containers.find((x) => x.id === tab?.cookieStoreId);
  line.append(el("span", { class: "label" }, "This tab: "));
  if (c) line.append(icon(c));
  line.append(el("span", { class: "cname" }, t.container), document.createTextNode(" → "));
  if (!t.profile) {
    line.append(el("span", { class: "muted" }, "direct (no VPN)"));
  } else {
    line.append(el("span", { class: "pname" }, t.profile), document.createTextNode(" "));
    const p = s.profiles[t.profile];
    line.append(pill(p?.state ?? "unknown", s.problems[t.profile] ?? (p ? undefined : "unavailable")));
  }
  return line;
}

async function render(): Promise<void> {
  const [s, tab]: [PopupState, browser.tabs.Tab | undefined] = await Promise.all([browser.runtime.sendMessage({ cmd: "getState" }), activeTab()]);
  const root = document.getElementById("root")!;
  root.replaceChildren();
  // Header bar: status dot, daemon state, and the containers-only note as
  // an ⓘ tooltip (issue #40).
  const h = headerView(s.daemonUp);
  const header = el("header", { id: "daemon", class: h.cls, role: "status" });
  header.append(el("span", { class: "dot" }), el("span", { class: "text" }, h.text));
  header.append(el("span", { class: "info", title: CONTAINERS_NOTE, "aria-label": CONTAINERS_NOTE, tabindex: "0" }, "ⓘ"));
  root.append(header);
  root.append(thisTabLine(s, tab));
  const names = Object.keys(s.profiles).sort();
  const users = profileUsers(s.mapping, s.containers);
  if (names.length > 0) {
    root.append(el("h2", {}, "Profiles"));
    const cards = el("div", { class: "cards" });
    for (const n of profileOrder(names, users)) cards.append(profileCard(s, n, users[n] ?? []));
    root.append(cards);
  }
  root.append(el("h2", {}, "Containers"));
  if (s.containers.length === 0) {
    // The empty state keeps the note visible.
    root.append(el("p", { class: "note" }, `No containers. Create Multi-Account Containers first. ${CONTAINERS_NOTE}`));
  }
  const table = el("table", { class: "containers" });
  const current = tab && !tab.incognito ? tab.cookieStoreId : undefined;
  for (const c of orderContainers(s.containers, s.mapping, current)) table.append(containerRow(s, c, names, c.id === current));
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
