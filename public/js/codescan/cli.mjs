#!/usr/bin/env node
// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Darknode Code Scanner, command line. Runs the SAME engine as the browser scanner
// (rules.js + taint-js.js + baseline.js + github.js helpers) over a folder, so CI can
// check every commit without a browser.
//
//   node cli.mjs [dir] [--sarif out.sarif] [--diff-base <sha>] [--fail-on high]
//                [--deps] [--full-sarif] [--sarif-include-review] [--fail-on-review] [--all-files] [--quiet]
//
// --diff-base <sha>  scan only files changed since <sha> (needs git history) and gate
//                    on findings that are NEW versus that commit, so old findings do not
//                    block every push. Missing/unknown base: falls back to a full scan.
// --fail-on <sev>    critical | high | medium | low | none (default high). Exit 1 when a
//                    gated finding at or above it exists. Needs-review items (a risky call
//                    with no traced untrusted input) are reported but only gate with
//                    --fail-on-review.
// --sarif-include-review  also upload needs-review items (left out by default so the
//                    Security tab shows confirmed findings only).
// --full-sarif       in diff mode, still write SARIF for the whole tree (GitHub code
//                    scanning closes alerts missing from an upload, so CI wants this).
// --deps             check pinned dependencies against OSV.dev (network).
// --all-files        walk the folder instead of using `git ls-files`.
// Exit codes: 0 pass, 1 gate failed, 2 usage or runtime error.
// Writes a Markdown job summary when $GITHUB_STEP_SUMMARY is set.

import { readFileSync, writeFileSync, appendFileSync, statSync, readdirSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { scanFile, isManifest, parseManifest, dedupeDeps, depFinding, toSarif, SEV_ORDER } from "./rules.js";
import { diffFile } from "./baseline.js";
import { ignoreMatcher, IGNORE_FILE, pickFiles, SKIP_DIR, osvQuery, osvVuln, pool } from "./github.js";

const SEVS = ["critical", "high", "medium", "low"];
const FAIL_ON = ["critical", "high", "medium", "low", "none"];

export function parseArgs(argv) {
  const o = { dir: ".", sarif: "", diffBase: "", failOn: "high", deps: false, fullSarif: false, sarifIncludeReview: false, failOnReview: false, allFiles: false, quiet: false, help: false };
  const need = (i, flag) => { if (i >= argv.length || String(argv[i]).startsWith("--")) throw new Error(flag + " needs a value"); return String(argv[i]); };
  let dirSet = false;
  for (let i = 0; i < argv.length; i++) {
    const a = String(argv[i]);
    if (a === "--sarif") o.sarif = need(++i, a);
    else if (a === "--diff-base") o.diffBase = need(++i, a);
    else if (a === "--fail-on") { o.failOn = need(++i, a).toLowerCase(); if (!FAIL_ON.includes(o.failOn)) throw new Error("--fail-on must be one of " + FAIL_ON.join(", ")); }
    else if (a === "--deps") o.deps = true;
    else if (a === "--full-sarif") o.fullSarif = true;
    else if (a === "--sarif-include-review") o.sarifIncludeReview = true;
    else if (a === "--fail-on-review") o.failOnReview = true;
    else if (a === "--all-files") o.allFiles = true;
    else if (a === "--quiet") o.quiet = true;
    else if (a === "-h" || a === "--help") o.help = true;
    else if (a.startsWith("--")) throw new Error("Unknown option " + a);
    else if (!dirSet) { o.dir = a; dirSet = true; }
    else throw new Error("Unexpected argument " + a);
  }
  return o;
}

const USAGE = "Usage: darknode-scan [dir] [--sarif out.sarif] [--diff-base <sha>] [--fail-on critical|high|medium|low|none] [--deps] [--full-sarif] [--fail-on-review] [--all-files] [--quiet]\n";

function git(dir, args, opts = {}) {
  return execFileSync("git", ["-C", dir, ...args], { encoding: opts.buffer ? undefined : "utf8", stdio: ["ignore", "pipe", "ignore"], maxBuffer: 256 * 1024 * 1024 });
}
function isGitRepo(dir) { try { return git(dir, ["rev-parse", "--is-inside-work-tree"]).trim() === "true"; } catch (_) { return false; } }

// Every file in scope: tracked files in a git checkout (what is committed), else a walk.
function listAll(dir, useGit) {
  let paths;
  if (useGit) paths = git(dir, ["ls-files", "-z"]).split("\0").filter(Boolean);
  else {
    paths = [];
    const walk = (abs, rel) => {
      for (const e of readdirSync(abs, { withFileTypes: true })) {
        const r = rel ? rel + "/" + e.name : e.name;
        if (e.isDirectory()) { if (e.name !== ".git" && !SKIP_DIR.test(r + "/")) walk(join(abs, e.name), r); }
        else if (e.isFile()) paths.push(r);
      }
    };
    walk(dir, "");
  }
  const out = [];
  for (const p of paths) { try { const s = statSync(join(dir, ...p.split("/"))); if (s.isFile()) out.push({ path: p, size: s.size }); } catch (_) { /* deleted in the working tree */ } }
  return out;
}

const scanText = (path, text) => (typeof text !== "string" || text.indexOf("\u0000") >= 0) ? [] : scanFile(path, text).map((f) => ({ ...f, path }));

async function depFindingsFor(manifests /* [{path, text}] */) {
  const deps = [];
  for (const m of manifests) for (const d of parseManifest(m.path, m.text)) deps.push({ ...d, path: m.path });
  dedupeDeps(deps);
  if (!deps.length) return [];
  const hits = await osvQuery(deps);
  const ids = [...new Set(hits.map((h) => h.id))].slice(0, 300);
  const details = new Map();
  await pool(ids, 8, async (id) => { details.set(id, await osvVuln(id)); });
  const texts = new Map(manifests.map((m) => [m.path, m.text]));
  const seen = new Set(), out = [];
  for (const h of hits) {
    const k = h.dep.path + "|" + h.dep.name + "|" + h.id;
    if (seen.has(k)) continue; seen.add(k);
    out.push(depFinding(h.dep, h.id, details.get(h.id), (texts.get(h.dep.path) || "").split(/\r?\n/)[h.dep.line - 1] || ""));
  }
  return out;
}

// `git diff --name-status -z -M` → [{ status, path, oldPath }]
export function parseNameStatus(out) {
  const t = String(out || "").split("\0");
  const res = [];
  for (let i = 0; i < t.length && t[i]; ) {
    const st = t[i++];
    const c = st[0];
    if (c === "R" || c === "C") { const oldPath = t[i++], path = t[i++]; res.push({ status: c === "R" ? "renamed" : "added", path, oldPath: c === "R" ? oldPath : "" }); }
    else { const path = t[i++]; res.push({ status: c === "A" ? "added" : c === "D" ? "removed" : "modified", path, oldPath: "" }); }
  }
  return res;
}

const isReview = (f) => f.confidence === "review";
const reviewCount = (list, mode, leftOut) => {
  const n = list.filter(isReview).length;
  if (!n) return "";
  return `Needs review: ${n} ${mode === "diff" ? "new " : ""}item(s) where a risky call has no traced untrusted input. They do not gate${leftOut ? " and are left out of the SARIF (use --sarif-include-review to upload them)" : ""}.`;
};
const sortF = (a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev] || a.path.localeCompare(b.path) || a.line - b.line;
const gated = (f, o) => o.failOn !== "none" && SEV_ORDER[f.sev] <= SEV_ORDER[o.failOn] && (o.failOnReview || f.confidence !== "review");
const mdEsc = (s) => String(s ?? "").replace(/[|\\`*_<>[\]]/g, (c) => "\\" + c).replace(/\r?\n/g, " ");

/**
 * Run a scan. Returns { code, findings, added, fixed, mode, note, sarif }.
 * io: { env, log(line), cwd } (defaults to the process).
 */
export async function main(argv, io = {}) {
  const env = io.env || process.env;
  const log = io.log || ((s) => process.stdout.write(s + "\n"));
  let o;
  try { o = parseArgs(argv); } catch (e) { log("darknode-scan: " + e.message); log(USAGE.trim()); return { code: 2 }; }
  if (o.help) { log(USAGE.trim()); return { code: 0 }; }
  const dir = resolve(io.cwd || process.cwd(), o.dir);
  if (!existsSync(dir) || !statSync(dir).isDirectory()) { log("darknode-scan: not a folder: " + o.dir); return { code: 2 }; }
  const say = (s) => { if (!o.quiet) log(s); };
  const useGit = !o.allFiles && isGitRepo(dir);
  const t0 = Date.now();

  let ig = { test: () => false, size: 0 };
  try { ig = ignoreMatcher(readFileSync(join(dir, IGNORE_FILE), "utf8")); } catch (_) {}
  const inScope = (path, size) => !ig.test(path) && pickFiles([{ path, size }], isManifest, Infinity).chosen.length === 1;
  const all = listAll(dir, useGit);
  const kept = all.filter((f) => !ig.test(f.path));
  const scope = pickFiles(kept, isManifest, Infinity).chosen;
  const read = (p) => { try { return readFileSync(join(dir, ...p.split("/")), "utf8"); } catch (_) { return null; } };

  let mode = "full", note = "";
  let changes = null;
  if (o.diffBase) {
    if (!useGit) note = "Not a git checkout, so --diff-base was ignored and the whole folder was scanned.";
    else if (/^0+$/.test(o.diffBase)) note = "No previous commit (new branch), so the whole tree was scanned.";
    else {
      let ok = false;
      try { git(dir, ["cat-file", "-e", o.diffBase + "^{commit}"]); ok = true; } catch (_) {}
      if (!ok) note = "Base commit " + o.diffBase.slice(0, 12) + " is not in this checkout (force-push or shallow clone), so the whole tree was scanned.";
      else { mode = "diff"; changes = parseNameStatus(git(dir, ["diff", "--name-status", "-z", "-M", "--relative", o.diffBase])); }
    }
  }

  const result = { mode, note, findings: [], added: [], fixed: [], scanned: 0, changed: 0, depNote: "" };
  const fullScan = async () => {
    const fs = [];
    for (const f of scope) fs.push(...scanText(f.path, read(f.path)));
    if (o.deps) {
      try { fs.push(...await depFindingsFor(scope.filter((f) => isManifest(f.path)).map((f) => ({ path: f.path, text: read(f.path) || "" })))); }
      catch (e) { result.depNote = "Dependency check skipped: " + e.message; }
    }
    result.scanned = scope.length;
    return fs.sort(sortF);
  };

  if (mode === "full") {
    result.findings = await fullScan();
    result.added = result.findings.slice();
  } else {
    const sizeOf = new Map(all.map((f) => [f.path, f.size]));
    const baseText = (p) => { try { return git(dir, ["show", o.diffBase + ":./" + p]); } catch (_) { return null; } };
    const rows = [];
    for (const c of changes) {
      const headIn = c.status !== "removed" && sizeOf.has(c.path) && inScope(c.path, sizeOf.get(c.path));
      const oldPath = c.oldPath || c.path;
      const bt = c.status === "added" ? null : baseText(oldPath);
      const baseIn = bt != null && inScope(oldPath, Buffer.byteLength(bt));
      if (!headIn && !baseIn) continue;
      const ht = headIn ? read(c.path) : null;
      rows.push({ ...c, oldPath, head: headIn ? scanText(c.path, ht) : [], base: baseIn ? scanText(oldPath, bt) : [], ht, bt: baseIn ? bt : null });
    }
    if (o.deps) {
      const mf = rows.filter((r) => isManifest(r.path) || isManifest(r.oldPath));
      if (mf.length) {
        try {
          const h = await depFindingsFor(mf.filter((r) => r.ht != null).map((r) => ({ path: r.path, text: r.ht })));
          const b = await depFindingsFor(mf.filter((r) => r.bt != null).map((r) => ({ path: r.oldPath, text: r.bt })));
          for (const r of mf) { r.head.push(...h.filter((f) => f.path === r.path)); r.base.push(...b.filter((f) => f.path === r.oldPath)); }
        } catch (e) { result.depNote = "Dependency check skipped: " + e.message; }
      }
    }
    for (const r of rows) {
      const d = diffFile(r.base, r.head, { asPath: r.oldPath !== r.path ? r.oldPath : undefined });
      result.added.push(...d.added); result.fixed.push(...d.fixed);
      result.findings.push(...r.head);
    }
    result.changed = rows.length; result.scanned = rows.filter((r) => r.ht != null).length;
    result.added.sort(sortF); result.findings.sort(sortF);
  }

  const failing = result.added.filter((f) => gated(f, o));
  result.code = failing.length ? 1 : 0;
  const repo = env.GITHUB_REPOSITORY || "", sha = env.GITHUB_SHA || "";

  if (o.sarif) {
    const sf = mode === "diff" && o.fullSarif ? await fullScan() : result.findings;
    // Needs-review items stay out of code scanning unless asked for, so the Security tab
    // holds confirmed findings only. They are still counted in both summaries.
    result.sarifReviewLeftOut = o.sarifIncludeReview ? 0 : sf.filter(isReview).length;
    result.sarif = toSarif(o.sarifIncludeReview ? sf : sf.filter((f) => !isReview(f)), { repo, sha });
    writeFileSync(resolve(io.cwd || process.cwd(), o.sarif), JSON.stringify(result.sarif, null, 2));
  }

  // ── Console summary ─────────────────────────────────────────────────────────
  const count = (list) => SEVS.map((s) => s + " " + list.filter((f) => f.sev === s).length).join(", ");
  say("Darknode Code Scanner (" + (mode === "diff" ? "changes since " + o.diffBase.slice(0, 12) : "full scan") + ")");
  if (note) say("Note: " + note);
  if (result.depNote) say(result.depNote);
  if (ig.size) say(".darknodeignore: " + (all.length - kept.length) + " path(s) excluded");
  say(mode === "diff" ? `Changed files in scope: ${result.changed}` : `Files scanned: ${result.scanned}`);
  say((mode === "diff" ? "Findings in changed files: " : "Findings: ") + count(result.findings));
  if (mode === "diff") say("New: " + count(result.added) + " | Fixed: " + result.fixed.length);
  // Needs-review items are counted on one line; they are listed only when they gate.
  const pool = (mode === "diff" ? result.added : result.findings);
  const listable = o.failOnReview ? pool : pool.filter((f) => !isReview(f));
  const reviewLine = o.failOnReview ? "" : reviewCount(pool, mode, result.sarifReviewLeftOut);
  const show = listable.slice(0, 200);
  if (show.length) {
    say("");
    say((mode === "diff" ? "NEW " : "") + "SEVERITY  CONF    LOCATION  RULE  TITLE");
    for (const f of show) say(`${f.sev.toUpperCase().padEnd(9)} ${(f.confidence === "review" ? "review" : f.flow ? "flow" : "rule").padEnd(7)} ${f.path}:${f.line}  ${f.ruleId}  ${f.title}${f.secret ? " (" + f.secret + ")" : ""}`);
    if (listable.length > show.length) say(`... and ${listable.length - show.length} more (see the SARIF file)`);
  }
  if (reviewLine) { say(""); say(reviewLine); }
  say("");
  say(o.failOn === "none" ? "Gate: off (--fail-on none)" : failing.length ? `Gate FAILED: ${failing.length} ${mode === "diff" ? "new " : ""}finding(s) at ${o.failOn} or above.` : `Gate passed: no ${mode === "diff" ? "new " : ""}${o.failOn}-or-above findings${o.failOnReview ? "" : " (needs-review items do not gate)"}.`);
  say(`Done in ${((Date.now() - t0) / 1000).toFixed(1)}s.`);

  // ── GitHub job summary ──────────────────────────────────────────────────────
  if (env.GITHUB_STEP_SUMMARY) {
    const link = (f) => repo && sha ? `[${mdEsc(f.path)}:${f.line}](https://github.com/${repo}/blob/${sha}/${f.path.split("/").map(encodeURIComponent).join("/")}#L${f.line})` : `${mdEsc(f.path)}:${f.line}`;
    const lines = ["## Darknode Code Scanner", "",
      mode === "diff" ? `Changes since \`${o.diffBase.slice(0, 12)}\`: ${result.changed} file(s) in scope.` : `Full scan: ${result.scanned} file(s).`];
    if (note) lines.push("", "> " + mdEsc(note));
    if (result.depNote) lines.push("", "> " + mdEsc(result.depNote));
    lines.push("", "| | Critical | High | Medium | Low |", "|---|---|---|---|---|");
    const row = (label, list) => `| ${label} | ${SEVS.map((s) => list.filter((f) => f.sev === s).length).join(" | ")} |`;
    lines.push(row(mode === "diff" ? "New" : "Findings", result.added));
    if (mode === "diff") lines.push(`| Fixed | ${SEVS.map((s) => result.fixed.filter((f) => f.sev === s).length).join(" | ")} |`);
    lines.push("", o.failOn === "none" ? "**Gate:** off" : failing.length ? `**Gate failed:** ${failing.length} ${mode === "diff" ? "new " : ""}finding(s) at ${o.failOn} or above.` : `**Gate passed** (fail on ${o.failOn}).`);
    const addedList = o.failOnReview ? result.added : result.added.filter((f) => !isReview(f));
    const listed = addedList.slice(0, 100);
    if (reviewLine) lines.push("", mdEsc(reviewLine));
    if (listed.length) {
      lines.push("", mode === "diff" ? "### New findings" : "### Findings", "", "| Severity | Finding | Location | Rule |", "|---|---|---|---|");
      for (const f of listed) lines.push(`| ${f.sev}${f.confidence === "review" ? " (needs review)" : ""} | ${mdEsc(f.kind === "dep" ? f.pkg + " " + f.version + ": " + f.title : f.title)}${f.secret ? " `" + f.secret.replace(/`/g, "") + "`" : ""} | ${link(f)} | ${mdEsc(f.ruleId)} |`);
      if (addedList.length > listed.length) lines.push("", `${addedList.length - listed.length} more in the SARIF upload.`);
    } else lines.push("", mode === "diff" ? "No new confirmed findings in this change." : "No confirmed findings.");
    try { appendFileSync(env.GITHUB_STEP_SUMMARY, lines.join("\n") + "\n"); } catch (_) {}
  }
  return result;
}

const isMain = (() => { try { return !!process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url); } catch (_) { return false; } })();
if (isMain) {
  main(process.argv.slice(2)).then((r) => process.exit(r.code), (e) => { process.stdout.write("darknode-scan: " + ((e && e.message) || e) + "\n"); process.exit(2); });
}
