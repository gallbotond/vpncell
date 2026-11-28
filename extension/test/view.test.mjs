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
