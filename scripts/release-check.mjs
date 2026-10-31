#!/usr/bin/env node
// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Release gate: run before asking to merge or deploy (docs/RELEASE.md, step 3).
//   npm run release:check            # compare against origin/main
//   npm run release:check -- --base <ref>
// Fails (exit 1) on anything that must not ship; warnings are printed but pass.

import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";

const args = process.argv.slice(2);
const base = args.includes("--base") ? args[args.indexOf("--base") + 1] : "origin/main";
const git = (...a) => execFileSync("git", a, { encoding: "utf8" }).trim();
const fails = [], warns = [];
const step = (name) => process.stdout.write(`- ${name} ... `);
const done = (ok = true) => console.log(ok ? "ok" : "FAILED");

// 1. Branch and tree
const branch = git("rev-parse", "--abbrev-ref", "HEAD");
step(`branch ${branch}`);
if (branch === "main") fails.push("on main: releases are cut from a release/* or feature branch");
done(branch !== "main");
step("working tree clean");
const dirty = git("status", "--porcelain").split("\n").filter((l) => l && !l.endsWith(".nexus/"));
if (dirty.length) fails.push(`${dirty.length} uncommitted change(s): commit or stash before a release check`);
done(!dirty.length);

// 2. What changed
const changed = git("diff", "--name-only", "--diff-filter=ACMR", `${base}...HEAD`).split("\n").filter(Boolean);
const js = changed.filter((f) => /\.(m?js)$/.test(f) && existsSync(f) && !f.startsWith("dist/"));
console.log(`- ${changed.length} file(s) changed since ${base} (${js.length} JS)`);

// 3. Syntax
step("node --check on changed JS");
const bad = js.filter((f) => spawnSync(process.execPath, ["--check", f]).status !== 0);
bad.forEach((f) => fails.push(`syntax error: ${f}`));
done(!bad.length);

// 4. House rules on added lines only (so old code doesn't block a release)
step("house rules on added lines");
const diff = git("diff", "-U0", `${base}...HEAD`, "--", "public", "worker", "scripts", "firebase");
let file = "";
const SECRET = /(sk-ant-[A-Za-z0-9_-]{20,}|sk-proj-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/;
const DIALOG = /(^|[^.\w])(alert|confirm|prompt)\s*\(|window\.(alert|confirm|prompt)\s*\(/;
const EMOJI = /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u;
for (const line of diff.split("\n")) {
  if (line.startsWith("+++ ")) { file = line.slice(6); continue; }
  if (!line.startsWith("+") || line.startsWith("+++")) continue;
  const s = line.slice(1);
  if (SECRET.test(s)) fails.push(`possible secret in ${file}`);
  if (/\.(m?js|html)$/.test(file) && !/vendor\//.test(file) && !/^\s*(\/\/|\*)/.test(s)) {
    if (DIALOG.test(s) && !/dn(Confirm|Prompt|Modal)/.test(s)) warns.push(`native dialog? ${file}: ${s.trim().slice(0, 80)}`);
    if (EMOJI.test(s)) warns.push(`emoji in UI code: ${file}`);
  }
}
done(!fails.some((f) => f.startsWith("possible secret")));

// 5. Commit hygiene
step("commit trailers");
const log = git("log", "--format=%B", `${base}..HEAD`);
if (/Co-Authored-By:/i.test(log)) fails.push("a commit carries a Co-Authored-By trailer");
done(!/Co-Authored-By:/i.test(log));

// 6. Rules changes need the admin claim set first
if (changed.some((f) => f.startsWith("firebase/"))) warns.push("Firestore/Storage rules changed: deploy them first and run the rules emulator tests (test/rules/)");
if (changed.some((f) => f.startsWith("worker/"))) warns.push("Worker changed: deploy to staging (wrangler --env staging) before production");

// 7. Build and tests
const run = (name, cmd, a) => { step(name); const r = spawnSync(cmd, a, { encoding: "utf8" }); const ok = r.status === 0; if (!ok) fails.push(`${name} failed:\n${(r.stdout + r.stderr).split("\n").slice(-15).join("\n")}`); done(ok); return r.stdout || ""; };
const build = run("release build", process.execPath, ["scripts/build.mjs"]);
const tests = run("npm test", "npm", ["test", "--silent"]);
const sum = (tests.match(/\d+ passed, \d+ failed[^\n]*/) || [""])[0];
const hash = (() => { try { return JSON.parse(readFileSync("dist/build.json", "utf8")).build || ""; } catch (_) { return (build.match(/build\s+([0-9a-f]{8,})/i) || [])[1] || ""; } })();

console.log("\n" + "=".repeat(60));
if (sum) console.log(`tests   ${sum}`);
if (hash) console.log(`build   ${hash}`);
warns.forEach((w) => console.log(`WARN    ${w}`));
fails.forEach((f) => console.log(`FAIL    ${f}`));
console.log(fails.length ? `\nNOT READY: ${fails.length} blocking issue(s).` : "\nREADY: ask the owner to merge and deploy (docs/RELEASE.md step 4).");
process.exit(fails.length ? 1 : 0);
