// Popup: per container its profile, state and exit IP; change the mapping;
// bring profiles up or down.
import { describeProblem, TunnelProblem } from "./decide.js";
interface PopupState {
  containers: { id: string; name: string; color: string; icon: string }[];
  mapping: Record<string, string>;
  profiles: Record<string, { state: string; autostart: string; exitIP?: string; problem?: TunnelProblem }>;
  daemonUp: boolean;
  problems: Record<string, string>;
}

function el<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Record<string, string> = {}, text = ""): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  if (text) e.textContent = text;
  return e;
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
  for (const c of s.containers) {
    const tr = el("tr", { "data-container": c.id });
    const name = el("td", { class: "name" }, c.name);
    name.style.borderLeft = `4px solid ${c.color}`;
    const sel = el("select", { "data-container": c.id, class: "mapping" });
    sel.append(el("option", { value: "" }, "Direct (no VPN)"));
    const mapped = s.mapping[c.id];
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
    sel.addEventListener("change", async () => {
      await browser.runtime.sendMessage({ cmd: "setMapping", cookieStoreId: c.id, profile: sel.value || null });
      render();
    });
    const p = mapped ? s.profiles[mapped] : undefined;
    const state = el("td", { class: "state" }, mapped ? (s.problems[mapped] ? `blocked: ${s.problems[mapped]}` : p?.state ?? "unknown") : "direct");
    // Why the tunnel is not connected (issue #14).
    const why = mapped && !s.problems[mapped] ? describeProblem(p?.problem) : null;
    if (why) {
      state.append(el("div", { class: "why", title: why.detail }, why.summary));
      if (why.detail) state.append(el("div", { class: "hint" }, why.detail));
    }
    const ip = el("td", { class: "exitip" }, p?.exitIP ?? "");
    const actions = el("td");
    if (mapped && p) {
      const up = p.state === "down";
      const b = el("button", { class: up ? "up" : "down" }, up ? "Up" : "Down");
      b.addEventListener("click", async () => {
        b.disabled = true;
        try {
          await browser.runtime.sendMessage({ cmd: up ? "up" : "down", profile: mapped });
        } catch (e) {
          alert(String(e));
        }
        render();
      });
      actions.append(b);
    }
    const tdSel = el("td");
    tdSel.append(sel);
    tr.append(name, tdSel, state, ip, actions);
    table.append(tr);
  }
  root.append(table);
}

render();
setInterval(render, 5000);
