import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

// Issue #38: the popup's colours are CSS variables with a light and a dark
// palette, so a dark Firefox theme gets a dark popup.
test("popup colours come from the light and dark palettes", () => {
  const html = readFileSync(new URL("../static/popup.html", import.meta.url), "utf8");
  const css = html.slice(html.indexOf("<style>"), html.indexOf("</style>"));
  const light = css.match(/:root \{([^}]*)\}/)[1];
  const dark = css.match(/@media \(prefers-color-scheme: dark\) \{\s*:root \{([^}]*)\}/)[1];
  const names = (block) => new Set([...block.matchAll(/(--[a-z-]+):/g)].map((m) => m[1]));
  const lightVars = names(light);
  const darkVars = names(dark);
  assert.deepEqual([...darkVars].sort(), [...lightVars].sort(), "both palettes define the same variables");
  const rest = css.replace(light, "").replace(dark, "");
  assert.deepEqual(rest.match(/#[0-9a-fA-F]{3,8}\b/g) ?? [], [], "colours outside the palettes");
  for (const m of rest.matchAll(/var\((--[a-z-]+)\)/g)) assert.ok(lightVars.has(m[1]), `${m[1]} is not defined`);
  assert.match(css, /body \{[^}]*background: var\(--bg\);[^}]*color: var\(--fg\)/, "body sets background and text colour");
  assert.ok(!/style="[^"]*color/.test(html.slice(html.indexOf("</style>"))), "inline colours in the markup");
});
