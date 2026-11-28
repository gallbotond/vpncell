// Pure helpers for the popup's layout, so they can be unit-tested.

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
