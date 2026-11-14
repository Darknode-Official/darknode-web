#!/usr/bin/env node
// Copies the Nexus command list from darknode-cli's generated reference
// (docs/NEXUS-COMMANDS.md, built from the live command tables) into
// public/data/nexus-commands.json for the Docs page.
//
//   node scripts/sync-nexus-commands.mjs [--cli ../darknode-cli]
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const i = process.argv.indexOf("--cli");
const CLI = path.resolve(i > 0 ? process.argv[i + 1] : path.join(os.homedir(), "projects", "darknode-cli"));
const md = fs.readFileSync(path.join(CLI, "docs", "NEXUS-COMMANDS.md"), "utf8");

const section = (title) => { const s = md.indexOf("\n## " + title); if (s < 0) throw new Error("missing section: " + title); const e = md.indexOf("\n## ", s + 4); return md.slice(s, e < 0 ? undefined : e); };
const rows = (txt) => [...txt.matchAll(/^- `([^`]+)` — (.+)$/gm)].map((m) => [m[1], m[2].replace(/ \(opens in the side panel\)$/, "")]);

const all = rows(section("All commands"));
const groups = section("Command groups (/help)").split("\n### ").slice(1)
  .map((b) => [b.split("\n")[0].trim(), rows(b)]).filter(([g, r]) => r.length && g !== "Input prefixes");
if (all.length < 50) throw new Error("only " + all.length + " commands parsed; reference format changed?");

const out = { source: "darknode-cli docs/NEXUS-COMMANDS.md", count: all.length, groups, commands: all };
fs.writeFileSync("public/data/nexus-commands.json", JSON.stringify(out) + "\n");
console.log("wrote public/data/nexus-commands.json: " + all.length + " commands, " + groups.length + " groups");
