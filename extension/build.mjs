// Assemble dist/ from compiled JS and static files.
import { cpSync, mkdirSync, rmSync, readdirSync } from "node:fs";
rmSync("dist", { recursive: true, force: true });
mkdirSync("dist");
for (const f of readdirSync("build")) if (f.endsWith(".js")) cpSync(`build/${f}`, `dist/${f}`);
for (const f of readdirSync("static")) cpSync(`static/${f}`, `dist/${f}`);
