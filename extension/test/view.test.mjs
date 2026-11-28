import { test } from "node:test";
import assert from "node:assert/strict";
import { exitIPView } from "../build/view.js";

test("exit IP under the pill (issue #36)", () => {
  assert.deepEqual(exitIPView({ state: "up", exitIP: "203.0.113.7" }), {
    text: "exit IP 203.0.113.7",
    title: "Exit IP, probed through the tunnel ([status] exit_ip_url)",
  });
  // Connected, no exit_ip_url: no text, a tooltip that names the setting.
  const none = exitIPView({ state: "up" });
  assert.equal(none.text, "");
  assert.match(none.title, /exit_ip_url/);
  // Not connected: nothing to say.
  assert.equal(exitIPView({ state: "down" }), null);
  assert.equal(exitIPView({ state: "connecting" }), null);
  assert.equal(exitIPView(undefined), null);
});

test("toolbar badge per tab (issue #37)", async () => {
  const { badgeFor, BADGE_UP, BADGE_WAIT, BADGE_DOWN, BADGE_BLOCKED } = await import("../build/view.js");
  const socks = { host: "127.0.0.1", port: 700, username: "u", password: "p" };
  const st = {
    ready: true,
    mapping: {
      "firefox-container-1": "work",
      "firefox-container-2": "lab",
      "firefox-container-3": "slow",
      "firefox-container-4": "gone",
      "firefox-container-5": "broken",
      "firefox-container-6": "manual",
    },
    profiles: {
      work: { state: "up", autostart: "on-use", socks },
      lab: { state: "down", autostart: "on-use", socks },
      slow: { state: "connecting", autostart: "on-use", socks },
      broken: { state: "failed: tunnel interface missing", autostart: "on-use", socks },
      manual: { state: "down", autostart: "manual", socks },
    },
    daemonUp: true,
    daemonDownSince: 0,
  };
  const now = 1_000_000;
  const b = (id, incognito = false) => badgeFor({ cookieStoreId: id, incognito }, st, now);
  // Direct: no badge.
  for (const id of ["firefox-default", "firefox-container-9", undefined]) assert.equal(b(id).text, "");
  assert.equal(b("firefox-container-1", true).text, "", "private window");
  assert.deepEqual(b("firefox-container-1"), { text: "W", color: BADGE_UP, title: "work: up" });
  assert.equal(b("firefox-container-2").color, BADGE_DOWN);
  assert.equal(b("firefox-container-2").text, "L");
  assert.equal(b("firefox-container-3").color, BADGE_WAIT);
  // Blocked: red "!".
  for (const id of ["firefox-container-4", "firefox-container-5", "firefox-container-6"]) {
    assert.equal(b(id).text, "!", id);
    assert.equal(b(id).color, BADGE_BLOCKED, id);
  }
  assert.match(b("firefox-container-4").title, /gone: blocked \(profile unknown or not allowed\)/);
  assert.match(b("firefox-container-6").title, /profile is down/);
  // Daemon unreachable past the grace period: every mapped tab is blocked.
  const down = { ...st, daemonUp: false, daemonDownSince: now - 60_000 };
  assert.deepEqual(badgeFor({ cookieStoreId: "firefox-container-1" }, down, now).text, "!");
  assert.match(badgeFor({ cookieStoreId: "firefox-container-1" }, down, now).title, /vpncelld is not reachable/);
});

test("profile cards and their containers (issue #34)", async () => {
  const { profileUsers, profileOrder } = await import("../build/view.js");
  const containers = [
    { id: "c1", name: "Work" },
    { id: "c2", name: "Mail" },
    { id: "c3", name: "Shopping" },
    { id: "c4", name: "Lab" },
  ];
  const users = profileUsers({ c1: "work", c2: "work", c4: "lab", c9: "gone" }, containers);
  assert.deepEqual(users, { work: ["Work", "Mail"], lab: ["Lab"] });
  assert.deepEqual(profileOrder(["zeta", "work", "alpha", "lab"], users), ["lab", "work", "alpha", "zeta"]);
});

test("current tab's container first (issue #35)", async () => {
  const { orderContainers, thisTab } = await import("../build/view.js");
  const cs = [
    { id: "firefox-container-1", name: "Personal" },
    { id: "firefox-container-2", name: "Work" },
    { id: "firefox-container-3", name: "Banking" },
    { id: "firefox-container-4", name: "Shopping" },
  ];
  const mapping = { "firefox-container-2": "work", "firefox-container-4": "lab" };
  const ids = (xs) => xs.map((c) => c.name);
  assert.deepEqual(ids(orderContainers(cs, mapping, "firefox-container-3")), ["Banking", "Work", "Shopping", "Personal"]);
  assert.deepEqual(ids(orderContainers(cs, mapping, "firefox-default")), ["Work", "Shopping", "Personal", "Banking"]);
  assert.deepEqual(ids(orderContainers(cs, mapping)), ["Work", "Shopping", "Personal", "Banking"]);

  assert.deepEqual(thisTab({ cookieStoreId: "firefox-container-2" }, cs, mapping), { kind: "container", container: "Work", profile: "work" });
  assert.deepEqual(thisTab({ cookieStoreId: "firefox-container-1" }, cs, mapping), { kind: "container", container: "Personal", profile: undefined });
  assert.equal(thisTab({ cookieStoreId: "firefox-default" }, cs, mapping).kind, "direct");
  assert.match(thisTab({ cookieStoreId: "firefox-private", incognito: true }, cs, mapping).text, /private window connects directly/);
  // Even a mapped container's tab in a private window connects directly.
  assert.equal(thisTab({ cookieStoreId: "firefox-container-2", incognito: true }, cs, mapping).kind, "direct");
  assert.equal(thisTab(undefined, cs, mapping).kind, "direct");
});

test("container icons (issue #39)", async () => {
  const { containerIcon } = await import("../build/view.js");
  assert.deepEqual(containerIcon("resource://usercontext-content/briefcase.svg", "#f89c24"), {
    mask: 'url("resource://usercontext-content/briefcase.svg")',
    color: "#f89c24",
  });
  assert.equal(containerIcon("resource://usercontext-content/cart.svg", "red; x: y").color, "currentColor");
  for (const bad of [undefined, "", "https://example.com/x.svg", 'resource://usercontext-content/a.svg") ; x', "moz-extension://x/icon.svg"]) {
    assert.equal(containerIcon(bad, "#000"), null, String(bad));
  }
});

test("header bar (issue #40)", async () => {
  const { headerView, CONTAINERS_NOTE } = await import("../build/view.js");
  assert.deepEqual(headerView(true), { cls: "ok", text: "vpncelld connected" });
  assert.equal(headerView(false).cls, "bad");
  assert.match(headerView(false).text, /not reachable — mapped containers are blocked/);
  assert.match(CONTAINERS_NOTE, /Only Multi-Account Containers can be mapped/);
});
