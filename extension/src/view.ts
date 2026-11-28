// Pure helpers for the popup's layout and the toolbar badge, so they can be
// unit-tested.
import { decideWithReason, RequestView, State } from "./decide.js";

// The exit IP shows under the state pill, not in a column of its own (issue
// #36): the daemon probes it only when the profile sets [status]
// exit_ip_url, so for most profiles there is none. `title` explains that on
// the pill of a connected profile without one.
export function exitIPView(p: { state: string; exitIP?: string } | undefined): { text: string; title: string } | null {
  if (!p) return null;
  if (p.exitIP) return { text: `exit IP ${p.exitIP}`, title: "Exit IP, probed through the tunnel ([status] exit_ip_url)" };
  if (p.state === "up") return { text: "", title: "No exit IP shown: set [status] exit_ip_url in the profile to probe it" };
  return null;
}

export interface Badge {
  text: string; // "" = no badge
  color: string;
  title: string; // "" = the default title
}

export const BADGE_UP = "#1d7d22";
export const BADGE_WAIT = "#b26a00";
export const BADGE_DOWN = "#6e6e6e";
export const BADGE_BLOCKED = "#d70022";

// Why a mapped tab cannot connect, in a few words.
export function blockedReason(reason: string): string {
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

// The toolbar badge for one tab (issue #37), from its container's mapping:
// direct tabs get none; a mapped tab gets the profile's initial, green when
// the tunnel is up, amber while connecting, grey when down (it comes up on
// use), and a red "!" when the tab is blocked (fail closed).
export function badgeFor(req: RequestView, st: State, now: number): Badge {
  const [, reason, profile] = decideWithReason(req, st, now);
  if (reason === "direct" || !profile) return { text: "", color: BADGE_DOWN, title: "" };
  if (reason !== "proxied") return { text: "!", color: BADGE_BLOCKED, title: `${profile}: blocked (${blockedReason(reason)})` };
  const state = st.profiles[profile]?.state ?? "";
  const initial = profile.charAt(0).toUpperCase();
  if (state === "up") return { text: initial, color: BADGE_UP, title: `${profile}: up` };
  if (state.startsWith("connecting")) return { text: initial, color: BADGE_WAIT, title: `${profile}: connecting` };
  if (state === "down") return { text: initial, color: BADGE_DOWN, title: `${profile}: down (comes up when this tab connects)` };
  // failed: …: the tab cannot connect, and never goes direct.
  return { text: "!", color: BADGE_BLOCKED, title: `${profile}: ${state}` };
}

// Which containers use each profile (issue #34), in container order.
export function profileUsers(mapping: Record<string, string>, containers: { id: string; name: string }[]): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const c of containers) {
    const p = mapping[c.id];
    if (p) (out[p] ??= []).push(c.name);
  }
  return out;
}

// Profile cards: the ones containers use first, then the others; each group
// sorted by name.
export function profileOrder(names: string[], users: Record<string, string[]>): string[] {
  const used = names.filter((n) => users[n]?.length).sort();
  const rest = names.filter((n) => !users[n]?.length).sort();
  return [...used, ...rest];
}
