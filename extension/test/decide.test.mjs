import { test } from "node:test";
import assert from "node:assert/strict";
import { decide, decideWithReason, FAIL_CLOSED, DIRECT, isLoopbackHost } from "../build/decide.js";

const socks = { host: "127.0.0.1", port: 700, username: "u", password: "p" };
const base = () => ({
  ready: true,
  mapping: { "firefox-container-1": "work", "firefox-container-2": "lab", "firefox-container-3": "gone" },
  profiles: {
    work: { state: "up", autostart: "on-use", socks },
    lab: { state: "down", autostart: "manual", socks: { ...socks, port: 701 } },
  },
  daemonUp: true,
  daemonDownSince: 0,
});
const now = 1_000_000;

test("default tab, private window and unmapped containers go direct", () => {
  assert.deepEqual(decide({ cookieStoreId: "firefox-default" }, base(), now), DIRECT);
  assert.deepEqual(decide({ cookieStoreId: undefined }, base(), now), DIRECT);
  assert.deepEqual(decide({ cookieStoreId: "firefox-private", incognito: true }, base(), now), DIRECT);
  assert.deepEqual(decide({ cookieStoreId: "firefox-container-1", incognito: true }, base(), now), DIRECT);
  assert.deepEqual(decide({ cookieStoreId: "firefox-container-9" }, base(), now), DIRECT);
});

test("a mapping on a non-container id is ignored", () => {
  const st = base();
  st.mapping["firefox-default"] = "work";
  assert.deepEqual(decide({ cookieStoreId: "firefox-default" }, st, now), DIRECT);
});

test("mapped and usable goes through the profile's SOCKS proxy", () => {
  const r = decide({ cookieStoreId: "firefox-container-1" }, base(), now);
  assert.equal(r.type, "socks");
  assert.equal(r.port, 700);
  assert.equal(r.proxyDNS, true);
});

test("mapped but not usable fails closed, never direct", () => {
  const cases = [
    [{ ...base(), ready: false }, "firefox-container-1", "not-ready"],
    [base(), "firefox-container-3", "unknown-profile"],
    [base(), "firefox-container-2", "profile-down"],
    [{ ...base(), daemonUp: false, daemonDownSince: now - 31_000 }, "firefox-container-1", "daemon-down"],
  ];
  for (const [st, id, why] of cases) {
    const [r, reason] = decideWithReason({ cookieStoreId: id }, st, now);
    assert.deepEqual(r, FAIL_CLOSED, why);
    assert.equal(reason, why);
  }
  const st = base();
  delete st.profiles.work.socks;
  assert.deepEqual(decide({ cookieStoreId: "firefox-container-1" }, st, now), FAIL_CLOSED);
});

test("daemon restart grace keeps cached details", () => {
  const st = { ...base(), daemonUp: false, daemonDownSince: now - 5_000 };
  assert.equal(decide({ cookieStoreId: "firefox-container-1" }, st, now).port, 700);
});

test("loopback hosts", () => {
  for (const h of ["localhost", "LOCALHOST.", "a.localhost", "127.0.0.1", "127.1.2.3", "[::1]", "::1", "0.0.0.0", "[::ffff:127.0.0.1]"]) {
    assert.ok(isLoopbackHost(h), h);
  }
  for (const h of ["example.com", "10.99.0.10", "192.168.1.1", "localhost.example.com", "[2001:db8::1]"]) {
    assert.ok(!isLoopbackHost(h), h);
  }
});

test("tunnel problems from status (issue #14)", async () => {
  const { problemFromStatus, describeProblem } = await import("../build/decide.js");
  const s = {
    state: "connecting", reason: "no-reply", reason_text: "no reply from the server",
    hint: "check tls-crypt", retries: 3, reason_at: 1700000000, log: "journalctl -u vpncell-openvpn@work",
  };
  const p = problemFromStatus(s);
  assert.equal(p.reason, "no-reply");
  const d = describeProblem(p);
  assert.equal(d.summary, "no reply from the server (3 failed attempts)");
  assert.match(d.detail, /tls-crypt/);
  assert.match(d.detail, /journalctl -u vpncell-openvpn@work/);
  assert.equal(describeProblem(problemFromStatus({ ...s, retries: 1 })).summary, "no reply from the server (1 failed attempt)");
  // No reason, or the tunnel is up: nothing to show.
  assert.equal(problemFromStatus({ state: "connecting" }), undefined);
  assert.equal(problemFromStatus({ ...s, state: "up" }), undefined);
  assert.equal(describeProblem(undefined), null);
});

test("reach notes from status (issue #15)", async () => {
  const { reachFromStatus, describeReach } = await import("../build/decide.js");
  const wg = { state: "up", reaches: "only 172.30.0.0/16; no IPv6", routes_source: "allowed-ips", split_tunnel: true, no_dns: true };
  assert.deepEqual(describeReach(reachFromStatus(wg)), ["reaches only 172.30.0.0/16; no IPv6", "no DNS: hostnames fail"]);
  const ovpn = { state: "up", reaches: "only 192.168.0.0/16", routes_source: "pushed", split_tunnel: true, dns: ["8.8.8.8"], dns_unreachable: ["8.8.8.8"] };
  assert.deepEqual(describeReach(reachFromStatus(ovpn)), [
    "server routes: only 192.168.0.0/16 (no redirect-gateway)",
    "DNS 8.8.8.8 not reachable through the tunnel",
  ]);
  // A full tunnel with DNS: nothing to say.
  assert.deepEqual(describeReach(reachFromStatus({ state: "up", reaches: "all IPv4; all IPv6", routes_source: "allowed-ips" })), []);
  assert.equal(reachFromStatus({ state: "down", no_dns: true }), undefined);
});
