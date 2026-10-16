#!/usr/bin/env node
// Scaffold a Deck tool: registers it in auth.js (SIDE_DESC + show()), deck-ui.js
// NAV_DEF and ui/explain.js EXPLAIN, bumps the cache-buster stamps and creates the
// engine/UI/test stubs. Dry run by default; --write applies atomically. --check lints.
//
//   node scripts/new-deck-tool.mjs --id x --label "Label" --group identity --prefix xx \
//     --dir identity --fn renderX --icon shield [--blurb "..."] [--src "..."] [--write]
//   node scripts/new-deck-tool.mjs --check
//   --root <dir> targets another checkout (default: cwd).
//
// Exit codes: 0 ok, 1 validation/anchor/lint problems, 2 usage.

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import {
  parseNavDef, parseIcons, parseRoutes, parseBlurbs, parseExplainKeys, parseHelpKeys, parseConsoleNavIds,
  collectStamps, nextStamp, validateSpec, targetFiles,
  patchSideDesc, patchRoute, patchNavDef, patchExplain, bumpStamps,
  renderEngineStub, renderUiStub, renderTestStub, lint,
} from "./lib/deck-registry.mjs";

const argv = process.argv.slice(2);
const rootAt = argv.indexOf("--root");
const ROOT = rootAt >= 0 && argv[rootAt + 1] ? argv[rootAt + 1] : process.cwd();
if (rootAt >= 0) argv.splice(rootAt, 2);
const FILES = {
  auth: "public/js/auth.js", deck: "public/js/deck-ui.js", explain: "public/js/ui/explain.js",
  admin: "public/js/admin.js", index: "public/index.html", sw: "public/sw.js", consoleNav: "public/js/console-nav.js",
  helpA: "public/js/section-help-a.js", helpB: "public/js/section-help-b.js",
};
const REQUIRED = ["id", "label", "group", "prefix", "dir", "fn", "icon"];

function usage(msg) {
  if (msg) process.stderr.write(`error: ${msg}\n\n`);
  process.stderr.write(
    "usage: node scripts/new-deck-tool.mjs --id x --label \"Label\" --group identity --prefix xx --dir identity\n" +
    "         --fn renderX --icon shield [--blurb \"...\"] [--src \"...\"] [--write]\n" +
    "       node scripts/new-deck-tool.mjs --check\n" +
    "       --root <dir> targets another checkout (default: cwd)\n");
  process.exit(2);
}

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) { out._.push(a); continue; }
    const k = a.slice(2);
    if (k === "write" || k === "check" || k === "help") { out[k] = true; continue; }
    const v = argv[i + 1];
    if (v === undefined || v.startsWith("--")) usage(`--${k} needs a value`);
    out[k] = v; i++;
  }
  return out;
}

const read = (rel) => readFileSync(join(ROOT, rel), "utf8");

/** Minimal line diff: strip common prefix/suffix, LCS the middle, print unified-ish hunks. */
function diff(rel, a, b) {
  if (a === b) return "";
  const A = a.split("\n"), B = b.split("\n");
  let pre = 0;
  while (pre < A.length && pre < B.length && A[pre] === B[pre]) pre++;
  let suf = 0;
  while (suf < A.length - pre && suf < B.length - pre && A[A.length - 1 - suf] === B[B.length - 1 - suf]) suf++;
  const ma = A.slice(pre, A.length - suf), mb = B.slice(pre, B.length - suf);
  const ops = []; // [" "|"-"|"+", text, aLine]
  if (ma.length * mb.length <= 3e7 && ma.length < 65535 && mb.length < 65535) {
    const n = ma.length, m = mb.length;
    const dp = new Uint16Array((n + 1) * (m + 1));
    for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) {
      dp[i * (m + 1) + j] = ma[i] === mb[j] ? dp[(i + 1) * (m + 1) + j + 1] + 1 : Math.max(dp[(i + 1) * (m + 1) + j], dp[i * (m + 1) + j + 1]);
    }
    let i = 0, j = 0;
    while (i < n || j < m) {
      if (i < n && j < m && ma[i] === mb[j]) { ops.push([" ", ma[i], pre + i]); i++; j++; }
      else if (i < n && (j >= m || dp[(i + 1) * (m + 1) + j] >= dp[i * (m + 1) + j + 1])) { ops.push(["-", ma[i], pre + i]); i++; }
      else { ops.push(["+", mb[j], pre + i]); j++; }
    }
  } else {
    ma.forEach((l, i) => ops.push(["-", l, pre + i]));
    mb.forEach((l) => ops.push(["+", l, pre + ma.length]));
  }
  const CTX = 3;
  const keep = new Set();
  ops.forEach((o, k) => { if (o[0] !== " ") for (let d = -CTX; d <= CTX; d++) keep.add(k + d); });
  const out = [`--- a/${rel}`, `+++ b/${rel}`];
  const ctxLine = (k) => (k >= 0 && k < A.length ? `  ${A[k]}` : null);
  for (let d = CTX; d >= 1; d--) { const c = ctxLine(pre - d); if (c) out.push(c); }
  let last = -2;
  ops.forEach((o, k) => {
    if (!keep.has(k)) return;
    if (k !== last + 1 && last >= 0) out.push("  ...");
    out.push(`${o[0]} ${o[1]}`); last = k;
  });
  for (let d = 0; d < CTX; d++) { const c = ctxLine(A.length - suf + d); if (c) out.push(c); }
  return out.join("\n") + "\n";
}

function runCheck() {
  const probs = lint(ROOT);
  const errs = probs.filter((p) => p.severity === "error"), warns = probs.filter((p) => p.severity === "warn");
  const fmt = (p) => `  ${p.msg}${p.file ? `  [${p.file}${p.line ? ":" + p.line : ""}]` : ""}`;
  if (errs.length) process.stdout.write(`errors (${errs.length}):\n${errs.map(fmt).join("\n")}\n`);
  if (warns.length) process.stdout.write(`${errs.length ? "\n" : ""}warnings (${warns.length}):\n${warns.map(fmt).join("\n")}\n`);
  if (!probs.length) process.stdout.write("registry lint: no problems\n");
  else process.stdout.write(`\n${errs.length} error(s), ${warns.length} warning(s)\n`);
  process.exit(errs.length ? 1 : 0);
}

function runScaffold(args) {
  const missing = REQUIRED.filter((k) => !args[k]);
  if (missing.length) usage(`missing ${missing.map((k) => "--" + k).join(", ")}`);
  const spec = {
    id: args.id, label: args.label, group: args.group, prefix: args.prefix, dir: args.dir, fn: args.fn, icon: args.icon,
    blurb: args.blurb || `${args.label} analysis that runs entirely in your browser.`,
    src: args.src || "Deterministic rules over the data you load, in this browser. Nothing is uploaded.",
  };

  const src = {};
  for (const [k, rel] of Object.entries(FILES)) {
    if (!existsSync(join(ROOT, rel))) { if (k === "helpA" || k === "helpB") { src[k] = ""; continue; } usage(`missing ${rel}; run from the repo root`); }
    src[k] = read(rel);
  }

  let ctx;
  try {
    ctx = {
      nav: parseNavDef(src.deck), icons: parseIcons(src.deck), routes: parseRoutes(src.auth), blurbs: parseBlurbs(src.auth),
      explainKeys: parseExplainKeys(src.explain), helpKeys: new Set([...parseHelpKeys(src.helpA), ...parseHelpKeys(src.helpB)]),
      consoleIds: parseConsoleNavIds(src.consoleNav), exists: (rel) => existsSync(join(ROOT, rel)),
    };
  } catch (e) { process.stdout.write(`anchor problem: ${e.message}\n`); process.exit(1); }

  const problems = validateSpec(spec, ctx);
  if (problems.length) { process.stdout.write(`validation problems:\n${problems.map((p) => "  - " + p).join("\n")}\n`); process.exit(1); }

  const stamp = nextStamp([src.auth, src.deck, src.admin, src.index, src.sw].flatMap(collectStamps));
  let next;
  try {
    const auth = patchRoute(patchSideDesc(src.auth, spec.id, spec.blurb), spec.id, spec.dir, spec.fn, stamp);
    const deck = patchNavDef(src.deck, spec.group, spec.id, spec.label, spec.icon);
    const explain = patchExplain(src.explain, spec.id, spec.label, spec.blurb, spec.src);
    const b = bumpStamps({ adminSrc: src.admin, deckUiSrc: deck, indexSrc: src.index, swSrc: src.sw }, stamp);
    next = { [FILES.auth]: auth, [FILES.deck]: b.deckUiSrc, [FILES.explain]: explain, [FILES.admin]: b.adminSrc, [FILES.index]: b.indexSrc, [FILES.sw]: b.swSrc };
  } catch (e) { process.stdout.write(`anchor problem: ${e.message}\n`); process.exit(1); }

  const [engineRel, uiRel, testRel] = targetFiles(spec);
  const creates = { [engineRel]: renderEngineStub(spec), [uiRel]: renderUiStub(spec, stamp), [testRel]: renderTestStub(spec) };

  const orig = { [FILES.auth]: src.auth, [FILES.deck]: src.deck, [FILES.explain]: src.explain, [FILES.admin]: src.admin, [FILES.index]: src.index, [FILES.sw]: src.sw };
  if (!args.write) {
    process.stdout.write(`DRY RUN (stamp ${stamp}). Pass --write to apply.\n\n`);
    for (const rel of Object.keys(next)) process.stdout.write(diff(rel, orig[rel], next[rel]) + "\n");
    process.stdout.write("would create:\n" + Object.entries(creates).map(([r, s]) => `  ${r}  (${s.split("\n").length} lines)`).join("\n") + "\n");
    return;
  }
  for (const [rel, content] of Object.entries(creates)) { mkdirSync(dirname(join(ROOT, rel)), { recursive: true }); writeFileSync(join(ROOT, rel), content); }
  for (const [rel, content] of Object.entries(next)) writeFileSync(join(ROOT, rel), content);
  process.stdout.write(`applied (stamp ${stamp}):\n` + [...Object.keys(next).map((r) => `  M ${r}`), ...Object.keys(creates).map((r) => `  A ${r}`)].join("\n") + "\n");
  process.stdout.write("next: implement the engine checks, then `node test/run.mjs` and `node scripts/new-deck-tool.mjs --check`.\n");
}

const args = parseArgs(argv);
if (args.help) usage();
if (args.check) runCheck();
else runScaffold(args);
