// Deck tool registry: pure string-in/string-out parsers, validators and patchers
// for the four registration sites (auth.js SIDE_DESC + show(), deck-ui.js NAV_DEF,
// ui/explain.js EXPLAIN) plus the cache-buster stamps. Nothing here writes files
// except lint(), which only reads. Used by scripts/new-deck-tool.mjs and tests.

import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { scanDuplicates } from "./dup-scan.mjs";

const ID_RE = /^[a-z][a-z0-9]{2,24}$/;
const FN_RE = /^render[A-Z]\w+$/;
const PREFIX_RE = /^[a-z]{2,4}$/;
const DIR_RE = /^[a-z][a-z0-9-]*$/;
const EMOJI_RE = /\p{Extended_Pictographic}/u;
const STAMP_RE = /\?v=(\d{8}[a-z]{1,2})\b/g;

/** Dirs whose engines/tests are held to the strict (error-severity) rules. */
export const STRICT_DIRS = ["identity", "appsec", "ops", "exposure", "finsec", "risk", "compliance"];

/** Tool ids allowed in NAV_DEF without a route/blurb/explain entry. */
export const NAV_WHITELIST = new Set(["admin"]);

const lines = (s) => s.split("\n");
const lineAt = (src, idx) => src.slice(0, idx).split("\n").length;
/** Parsers return Maps/Sets; a repeated id is kept once and also listed in `.dups` ([{ id, line }]). */
const withDups = (coll, dups) => Object.assign(coll, { dups });
const esc = (s) => String(s).replace(/\\/g, "\\\\").replace(/"/g, "\\\"");
const escRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Find the single line index matching `re`; throw on 0 or >1. */
function onlyLine(ls, re, what) {
  const hits = [];
  ls.forEach((l, i) => { if (re.test(l)) hits.push(i); });
  if (hits.length !== 1) throw new Error(`anchor ${what}: expected 1 match, found ${hits.length}`);
  return hits[0];
}

/** Index of the first line at/after `from` matching `re`; throw if none. */
function nextLine(ls, from, re, what) {
  for (let i = from; i < ls.length; i++) if (re.test(ls[i])) return i;
  throw new Error(`anchor ${what}: closing line not found`);
}

/* ------------------------------------------------------------------ parsers */

/** Parse `const NAV_DEF = [ ... ];` from deck-ui.js. Line numbers are 1-based. */
export function parseNavDef(src) {
  const ls = lines(src);
  const start = onlyLine(ls, /^\s*const NAV_DEF = \[\s*$/, "NAV_DEF");
  const end = nextLine(ls, start + 1, /^\s*\];\s*$/, "NAV_DEF");
  const groups = [];
  const itemRe = /\["(scene|tool)",\s*"(\w+)",\s*"([^"]*)",\s*IC\.(\w+)\]/g;
  for (let i = start + 1; i < end; i++) {
    const l = ls[i];
    const head = /^\s*\{\s*(?:id:\s*"(\w+)",\s*)?g:\s*"([^"]*)",\s*items:\s*\[/.exec(l);
    if (!head) continue;
    const items = [];
    for (const m of l.matchAll(itemRe)) items.push({ kind: m[1], id: m[2], label: m[3], icon: m[4] });
    groups.push({ id: head[1] || null, title: head[2], line: i + 1, items });
  }
  const seen = new Set(), dups = [];
  for (const g of groups) for (const it of g.items) { if (seen.has(it.id)) dups.push({ id: it.id, line: g.line }); seen.add(it.id); }
  return { start: start + 1, end: end + 1, groups, dups };
}

/** Icon names from the `const IC = { name: SVG(...) }` block in deck-ui.js. */
export function parseIcons(src) {
  const ls = lines(src);
  const start = onlyLine(ls, /^\s*const IC = \{\s*$/, "IC");
  const end = nextLine(ls, start + 1, /^\s*\};\s*$/, "IC");
  const out = new Set(), dups = [];
  for (let i = start + 1; i < end; i++) {
    const m = /^\s*([a-z0-9]+):\s*SVG\(/.exec(ls[i]);
    if (m) { if (out.has(m[1])) dups.push({ id: m[1], line: i + 1 }); out.add(m[1]); }
  }
  return withDups(out, dups);
}

/** show() branches in auth.js: id -> { path|null, fn|null, line }. Scoped to show(). */
export function parseRoutes(src) {
  const ls = lines(src);
  const start = onlyLine(ls, /^\s*function show\(sec\b/, "show()");
  const end = nextLine(ls, start + 1, /^  \}\s*$/, "show()");
  const out = new Map(), dups = [];
  for (let i = start + 1; i < end; i++) {
    const l = ls[i];
    if (!/\bsec === "/.test(l)) continue;
    const imp = /import\("(\/js\/[^"?]+)(?:\?v=\w+)?"\)/.exec(l);
    let fn = null;
    const after = l.slice(l.lastIndexOf('sec === "'));
    const f = /\)\s*\{?\s*(?:[\w.]+\s*=\s*)?(\w+)\(/.exec(after);
    if (f && f[1] !== "import") fn = f[1];
    if (imp) { const t = /\.then\(\w+ => (?:[\w()&\s]*&&\s*)?\w+\.(\w+)\(/.exec(l); if (t) fn = t[1]; }
    if (!imp && !fn) continue;
    for (const m of l.matchAll(/\bsec === "(\w+)"/g)) {
      if (!out.has(m[1])) out.set(m[1], { path: imp ? imp[1] : null, fn, line: i + 1 });
      else dups.push({ id: m[1], line: i + 1 });
    }
  }
  return withDups(out, dups);
}

/** SIDE_DESC entries in auth.js: id -> blurb. */
export function parseBlurbs(src) {
  const ls = lines(src);
  const start = onlyLine(ls, /^\s*const SIDE_DESC = \{\s*$/, "SIDE_DESC");
  const end = nextLine(ls, start + 1, /^\s*\};\s*$/, "SIDE_DESC");
  const out = new Map(), dups = [];
  for (let i = start + 1; i < end; i++) {
    const m = /^\s*"?(\w+)"?:\s*"((?:[^"\\]|\\.)*)",?\s*$/.exec(ls[i]);
    if (m) { if (out.has(m[1])) dups.push({ id: m[1], line: i + 1 }); out.set(m[1], m[2].replace(/\\"/g, "\"")); }
  }
  return withDups(out, dups);
}

/** Keys of the EXPLAIN map in ui/explain.js (all keys, e.g. "tool.x", "scene.y"). */
export function parseExplainKeys(src) {
  const out = new Set(), dups = [];
  for (const m of src.matchAll(/^\s*"([\w.-]+)":\s*\{/gm)) { if (out.has(m[1])) dups.push({ id: m[1], line: lineAt(src, m.index) }); out.add(m[1]); }
  return withDups(out, dups);
}

/** Keys of a HELP map (section-help-a/b.js). Same shape as parseExplainKeys. */
export function parseHelpKeys(src) {
  return parseExplainKeys(src);
}

/** Ids referenced by console-nav.js NAV groups (`["id","Label"...]`). */
export function parseConsoleNavIds(src) {
  const out = new Set(), dups = [];
  const navIds = new Set(); // dups are counted among the G(...) menu rows only (RETIRED/DEFAULT_FAVS repeat ids on purpose)
  for (const m of src.matchAll(/\["([a-z0-9]+)",\s*"/g)) {
    out.add(m[1]);
    const ln = src.lastIndexOf("\n", m.index) + 1;
    if (!/^\s*G\("/.test(src.slice(ln, ln + 40))) continue;
    if (navIds.has(m[1])) dups.push({ id: m[1], line: lineAt(src, m.index) });
    navIds.add(m[1]);
  }
  return withDups(out, dups);
}

/** Cache-buster stamps at the 5 sites. */
export function parseStamps({ adminSrc, deckUiSrc, indexSrc, swSrc }) {
  const one = (src, re, what) => {
    const hits = [...src.matchAll(re)];
    if (hits.length !== 1) throw new Error(`stamp ${what}: expected 1 match, found ${hits.length}`);
    return hits[0][1];
  };
  const admin = one(adminSrc, /import\("\/js\/deck-ui\.js\?v=(\w+)"\)/g, "admin.js deck-ui import");
  const deckUi = one(deckUiSrc, /from "\/js\/ui\/explain\.js\?v=(\w+)"/g, "deck-ui.js explain import");
  const index = [...indexSrc.matchAll(/\/js\/auth\.js\?v=(\w+)/g)].map((m) => m[1]);
  if (index.length !== 2) throw new Error(`stamp index.html auth.js: expected 2 matches, found ${index.length}`);
  const sw = Number(one(swSrc, /^const CACHE = 'darknode-v(\d+)';/gm, "sw.js CACHE"));
  return { admin, deckUi, index, sw };
}

/** All `?v=YYYYMMDDx` stamps found in a source string. */
export function collectStamps(src) {
  return [...src.matchAll(STAMP_RE)].map((m) => m[1]);
}

/** Today's `YYYYMMDD` + the next free suffix after the highest one used today:
 *  a..z, then za..zz (51 stamps a day). */
export function nextStamp(existing, today = new Date()) {
  const d = today.getFullYear() * 10000 + (today.getMonth() + 1) * 100 + today.getDate();
  const day = String(d);
  const rank = (x) => (/^[a-z]$/.test(x) ? x.charCodeAt(0) - 97 : /^z[a-z]$/.test(x) ? 26 + x.charCodeAt(1) - 97 : -1);
  let max = -1;
  for (const s of existing) if (s.slice(0, 8) === day) max = Math.max(max, rank(s.slice(8)));
  if (max >= 51) throw new Error(`stamp letters exhausted for ${day}`);
  const n = max + 1;
  return day + (n < 26 ? String.fromCharCode(97 + n) : "z" + String.fromCharCode(97 + n - 26));
}

/* ---------------------------------------------------------------- validate */

/**
 * Validate a scaffold spec against the parsed registry context.
 * ctx: { nav, icons, routes, blurbs, explainKeys, helpKeys, consoleIds, exists(relPath) }.
 */
export function validateSpec(spec, ctx) {
  const p = [];
  const { id, label, group, prefix, dir, fn, icon, blurb } = spec;
  if (!ID_RE.test(id || "")) p.push(`id "${id}" must match ${ID_RE}`);
  if (!label || !label.trim()) p.push("label is required");
  if (EMOJI_RE.test(label || "")) p.push("label contains an emoji");
  if (!(blurb || "").trim()) p.push("blurb is required");
  else if (blurb.trim().length < 21) p.push(`blurb must be at least 21 characters (got ${blurb.trim().length})`);
  if (EMOJI_RE.test(blurb || "")) p.push("blurb contains an emoji");
  if (EMOJI_RE.test(spec.src || "")) p.push("src contains an emoji");
  if (!FN_RE.test(fn || "")) p.push(`fn "${fn}" must match ${FN_RE}`);
  if (!PREFIX_RE.test(prefix || "")) p.push(`prefix "${prefix}" must match ${PREFIX_RE}`);
  if (!DIR_RE.test(dir || "")) p.push(`dir "${dir}" must match ${DIR_RE}`);
  const groups = ctx.nav ? ctx.nav.groups.filter((g) => g.id) : [];
  if (!groups.some((g) => g.id === group)) p.push(`group "${group}" not in NAV_DEF (have: ${groups.map((g) => g.id).join(", ")})`);
  if (ctx.icons && !ctx.icons.has(icon)) p.push(`icon "${icon}" not in IC`);
  if (id) {
    if (ctx.routes && ctx.routes.has(id)) p.push(`id "${id}" already routed in auth.js show()`);
    if (ctx.blurbs && ctx.blurbs.has(id)) p.push(`id "${id}" already in SIDE_DESC`);
    if (ctx.nav && ctx.nav.groups.some((g) => g.items.some((it) => it.id === id))) p.push(`id "${id}" already in NAV_DEF`);
    if (ctx.explainKeys && ctx.explainKeys.has("tool." + id)) p.push(`"tool.${id}" already in EXPLAIN`);
    if (ctx.consoleIds && ctx.consoleIds.has(id)) p.push(`id "${id}" already in console-nav.js NAV`);
    if (typeof ctx.exists === "function") {
      for (const f of targetFiles(spec)) if (ctx.exists(f)) p.push(`target file exists: ${f}`);
    }
  }
  return p;
}

/** Relative paths of the 3 files the scaffold creates. */
export function targetFiles({ id, dir }) {
  return [`public/js/${dir}/${id}-engine.js`, `public/js/${dir}/${id}.js`, `test/security/${id}.test.mjs`];
}

/* ----------------------------------------------------------------- patchers */

/** Add `  id: "blurb",` before the SIDE_DESC closing `};`. */
export function patchSideDesc(src, id, blurb) {
  const ls = lines(src);
  const start = onlyLine(ls, /^\s*const SIDE_DESC = \{\s*$/, "SIDE_DESC");
  const end = nextLine(ls, start + 1, /^\s*\};\s*$/, "SIDE_DESC");
  if (parseBlurbs(src).has(id)) throw new Error(`SIDE_DESC already has "${id}"`);
  ls.splice(end, 0, `  ${id}: "${esc(blurb)}",`);
  return ls.join("\n");
}

/** Add a dynamic-import route branch before the `setup` branch in show(). */
export function patchRoute(src, id, dir, fn, stamp) {
  const ls = lines(src);
  const i = onlyLine(ls, /^\s*else if \(sec === "setup"\) renderSetup\(main, more\);\s*$/, "show() setup branch");
  if (new RegExp(`\\bsec === "${escRe(id)}"`).test(src)) throw new Error(`show() already routes "${id}"`);
  const indent = /^\s*/.exec(ls[i])[0];
  ls.splice(i, 0, `${indent}else if (sec === "${id}") { import("/js/${dir}/${id}.js?v=${stamp}").then(m => live() && m.${fn}(main)); }`);
  return ls.join("\n");
}

/** Append `["tool", id, label, IC.icon]` to the named NAV_DEF group's items. */
export function patchNavDef(src, group, id, label, icon) {
  const ls = lines(src);
  const nav = parseNavDef(src);
  if (nav.groups.some((g) => g.items.some((it) => it.id === id))) throw new Error(`NAV_DEF already has "${id}"`);
  const hits = nav.groups.filter((g) => g.id === group);
  if (hits.length !== 1) throw new Error(`anchor NAV_DEF group "${group}": expected 1 match, found ${hits.length}`);
  const li = hits[0].line - 1;
  const l = ls[li];
  const open = l.indexOf("items: [");
  if (open < 0) throw new Error("NAV_DEF group line has no items array");
  let depth = 0, close = -1;
  for (let k = open + 7; k < l.length; k++) {
    if (l[k] === "[") depth++;
    else if (l[k] === "]") { depth--; if (depth === 0) { close = k; break; } }
  }
  if (close < 0) throw new Error("NAV_DEF group items array is not closed on its line");
  const inner = l.slice(open + 8, close).trim();
  const item = `["tool", "${id}", "${esc(label)}", IC.${icon}]`;
  ls[li] = l.slice(0, close) + (inner ? ", " : "") + item + l.slice(close);
  return ls.join("\n");
}

/** Add `"tool.<id>"` after the last `"tool.*"` entry in EXPLAIN. */
export function patchExplain(src, id, label, blurb, srcNote) {
  const ls = lines(src);
  if (parseExplainKeys(src).has("tool." + id)) throw new Error(`EXPLAIN already has "tool.${id}"`);
  let last = -1;
  ls.forEach((l, i) => { if (/^  "tool\.\w+": \{/.test(l)) last = i; });
  if (last < 0) throw new Error("anchor EXPLAIN tool.* entries: expected >=1 match, found 0");
  const extra = srcNote ? `, src: "${esc(srcNote)}"` : "";
  ls.splice(last + 1, 0, `  "tool.${id}": { title: "${esc(label)}", body: "${esc(blurb)}"${extra} },`);
  return ls.join("\n");
}

/** Rewrite the 5 cache-buster sites to `stamp`; sw.js integer +1. */
export function bumpStamps({ adminSrc, deckUiSrc, indexSrc, swSrc }, stamp) {
  const cur = parseStamps({ adminSrc, deckUiSrc, indexSrc, swSrc });
  if (cur.index[0] !== cur.index[1]) throw new Error(`index.html auth.js stamps differ: ${cur.index.join(" vs ")}`);
  if (cur.admin === stamp || cur.deckUi === stamp || cur.index[0] === stamp) throw new Error(`stamp ${stamp} already applied`);
  return {
    adminSrc: adminSrc.replace(/import\("\/js\/deck-ui\.js\?v=\w+"\)/, `import("/js/deck-ui.js?v=${stamp}")`),
    deckUiSrc: deckUiSrc.replace(/from "\/js\/ui\/explain\.js\?v=\w+"/, `from "/js/ui/explain.js?v=${stamp}"`),
    indexSrc: indexSrc.replace(/\/js\/auth\.js\?v=\w+/g, `/js/auth.js?v=${stamp}`),
    swSrc: swSrc.replace(/^const CACHE = 'darknode-v\d+';/m, `const CACHE = 'darknode-v${cur.sw + 1}';`),
  };
}

/* ---------------------------------------------------------------- templates */

const fill = (tpl, vars) => tpl.replace(/\{\{(\w+)\}\}/g, (_, k) => {
  if (!(k in vars)) throw new Error(`template var ${k} missing`);
  return vars[k];
});

const ENGINE_TPL = `// {{label}} engine ({{id}}). Analyzes tabular exports (CSV/JSON) for
// {{blurbComment}}
// pure: no DOM, no network; deterministic. Safe to run inside a Worker.

import { sniff, parseCsv, iterJson, findColumn } from "../ingest/parse.js";

export const TOOL_ID = "{{id}}";
export const VERSION = "0.1.0";

/** Column aliases: key -> accepted header names (case-insensitive). */
export const COLUMNS = {
  timestamp: ["timestamp", "time", "date", "datetime", "created"],
  actor: ["actor", "user", "username", "account", "principal"],
};

/** Tunable thresholds; the UI renders these as the settings panel. */
export const DEFAULTS = {
  burstThreshold: 50, // rows by one actor before it is reported
};

const CONTROLS = [{ framework: "NIST CSF 2.0", id: "DE.CM-01" }];

/** Parse raw text into rows. Never throws on bad input; reports via skipped. */
export function parseInput(text) {
  const t = String(text || "");
  const skipped = [];
  if (!t.trim()) return { format: "empty", headers: [], rows: [], skipped };
  const format = sniff(t).format;
  if (format === "json") {
    const rows = [];
    for (const r of iterJson(t)) if (r && typeof r === "object") rows.push(r);
    const headers = rows.length ? Object.keys(rows[0]) : [];
    return { format, headers, rows, skipped };
  }
  const { headers, rows } = parseCsv(t);
  return { format: "csv", headers, rows, skipped };
}

function resolve(rows, skipped) {
  const headers = rows.length ? Object.keys(rows[0]) : [];
  const cols = {};
  for (const [key, aliases] of Object.entries(COLUMNS)) {
    const h = findColumn(headers, aliases);
    if (h) cols[key] = h;
  }
  return cols;
}

/**
 * Analyze rows. opts overrides DEFAULTS; ctx.progress(i, n) is called every 1000 rows.
 * Missing columns disable the checks that need them (listed in skipped), never guessed.
 */
export function analyze(rows, opts = {}, ctx) {
  const o = { ...DEFAULTS, ...opts };
  const skipped = [];
  const findings = [];
  const tables = {};
  const list = Array.isArray(rows) ? rows : [];
  const cols = resolve(list, skipped);
  const n = list.length;

  if (!cols.actor) {
    skipped.push({ check: "actor_burst", reason: "no actor column (" + COLUMNS.actor.join(", ") + ")" });
  } else {
    const byActor = new Map();
    for (let i = 0; i < n; i++) {
      if (i % 1000 === 0) ctx?.progress?.(i, n);
      const a = String(list[i][cols.actor] ?? "").trim();
      if (!a) continue;
      byActor.set(a, (byActor.get(a) || 0) + 1);
    }
    const bursts = [...byActor].filter(([, c]) => c >= o.burstThreshold).sort((x, y) => y[1] - x[1] || (x[0] < y[0] ? -1 : 1));
    tables.actors = bursts.map(([actor, count]) => ({ actor, count }));
    for (const [actor, count] of bursts) {
      findings.push({
        title: "High activity volume for one actor",
        severity: "low",
        confidence: "likely",
        category: "volume",
        description: actor + " appears in " + count + " rows (threshold " + o.burstThreshold + ").",
        recommendation: "Confirm the account is a service principal or review its activity window.",
        controls: CONTROLS,
        evidence: list.filter((r) => String(r[cols.actor] ?? "").trim() === actor).slice(0, 25),
        assets: [{ type: "IDENTITY", name: actor }],
      });
    }
  }
  ctx?.progress?.(n, n);
  const summary = { rows: n, findings: findings.length, bySeverity: countBy(findings, "severity") };
  return { summary, findings, tables, skipped, meta: { tool: TOOL_ID, version: VERSION, rows: n } };
}

function countBy(items, key) {
  const out = {};
  for (const it of items) out[it[key]] = (out[it[key]] || 0) + 1;
  return out;
}

const FINDING_COLS = ["severity", "confidence", "category", "title", "description", "recommendation", "controls", "evidenceCount"];

/** Findings as CSV with fixed columns. */
export function findingsToCsv(findings) {
  const q = (v) => '"' + String(v ?? "").replace(/"/g, '""') + '"';
  const head = FINDING_COLS.join(",");
  const body = (findings || []).map((f) => [
    f.severity, f.confidence, f.category, f.title, f.description, f.recommendation,
    (f.controls || []).map((c) => c.framework + " " + c.id).join("; "), (f.evidence || []).length,
  ].map(q).join(","));
  return [head, ...body].join("\\n");
}

/** Small seeded SYNTHETIC dataset for the "Load example" button and tests. */
export function exampleDataset(seed = 7) {
  let s = seed >>> 0;
  const rnd = () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 4294967296; };
  const actors = ["svc-backup", "alice", "bob", "carol", "dave"];
  const rows = [];
  for (let i = 0; i < 160; i++) {
    const actor = i < 60 ? actors[0] : actors[1 + Math.floor(rnd() * 4)];
    rows.push({ timestamp: "2026-01-01T" + String(i % 24).padStart(2, "0") + ":00:00Z", actor });
  }
  return { label: "synthetic example (not real data)", rows };
}

/** One real deterministic check of the engine. */
export function selfTest() {
  const tests = [];
  const { rows } = exampleDataset();
  const r = analyze(rows, { burstThreshold: 50 });
  tests.push({ name: "burst actor detected once", pass: r.findings.length === 1 && r.findings[0].assets[0].name === "svc-backup" });
  tests.push({ name: "missing actor column is skipped, not guessed", pass: analyze([{ x: 1 }]).skipped.length === 1 });
  tests.push({ name: "empty input yields no findings", pass: analyze([]).findings.length === 0 });
  return { pass: tests.every((t) => t.pass), tests };
}
`;

const UI_TPL = `// {{label}} ({{id}}): Deck tool UI. Runs entirely in the browser; the engine
// executes in a Worker via ../ingest/worker.js. No native dialogs; toasts only.

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { download, toJson, fileStamp } from "../core/export.js";
import { DEFAULTS, TOOL_ID, parseInput, findingsToCsv, exampleDataset } from "./{{id}}-engine.js?v={{stamp}}";

const ENGINE = engineUrl("./{{id}}-engine.js?v={{stamp}}", import.meta);
const P = "{{prefix}}";
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

const CSS = \`
  .{{prefix}}-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230)}
  .{{prefix}}-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .{{prefix}}-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .{{prefix}}-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .{{prefix}}-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:70ch}
  .{{prefix}}-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px}
  .{{prefix}}-drop{border:1.5px dashed var(--line,#d7dbe3);border-radius:10px;padding:26px;text-align:center;color:var(--mut,#667085);background:var(--bg,#fbfcfe)}
  .{{prefix}}-drop.over{border-color:#2552c6;background:var(--acc-soft,rgba(37,82,198,.06))}
  .{{prefix}}-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:12px}
  .{{prefix}}-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer}
  .{{prefix}}-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .{{prefix}}-btn:disabled{opacity:.5;cursor:default}
  .{{prefix}}-ctl{display:flex;flex-wrap:wrap;gap:14px 20px;align-items:flex-end}
  .{{prefix}}-field{display:flex;flex-direction:column;gap:4px}
  .{{prefix}}-field label{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085)}
  .{{prefix}}-field input{font:inherit;font-size:.84rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:7px 10px;width:120px;box-sizing:border-box}
  .{{prefix}}-kpis{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}
  .{{prefix}}-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 16px;min-width:120px}
  .{{prefix}}-kpi b{display:block;font-size:1.3rem}
  .{{prefix}}-kpi span{font-size:.74rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .{{prefix}}-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin-top:10px;display:none}
  .{{prefix}}-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .{{prefix}}-list{border:1px solid var(--line,#e6e8ee);border-radius:12px;overflow:auto}
  .{{prefix}}-list table{width:100%;border-collapse:collapse;font-size:.84rem}
  .{{prefix}}-list th{text-align:left;font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:9px 14px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee)}
  .{{prefix}}-list td{padding:10px 14px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:anywhere}
  .{{prefix}}-list tr[data-i]{cursor:pointer}
  .{{prefix}}-list tr[data-i]:hover{background:var(--bg,#f7f8fb)}
  .{{prefix}}-pill{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .{{prefix}}-pill.critical{background:#7a0012}.{{prefix}}-pill.high{background:#b00020}.{{prefix}}-pill.medium{background:#b58100}.{{prefix}}-pill.low{background:#2552c6}.{{prefix}}-pill.info{background:#667085}
  .{{prefix}}-chip{display:inline-block;font-size:.7rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085)}
  .{{prefix}}-empty{padding:28px;text-align:center;color:var(--mut,#667085)}
  .{{prefix}}-drawer{margin-top:14px;display:none}
  .{{prefix}}-drawer pre{margin:0;max-height:320px;overflow:auto;font-size:12px;background:var(--bg,#f7f8fb);border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:10px 12px}
  .{{prefix}}-skip{font-size:.78rem;color:var(--mut,#667085);margin-top:8px}
\`;

function kpi(v, l) { return '<div class="' + P + '-kpi"><b>' + esc(v) + "</b><span>" + esc(l) + "</span></div>"; }

/** Mount the tool into main. */
export function {{fn}}(main) {
  if (!document.getElementById(P + "-css")) {
    const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st);
  }
  const fields = Object.entries(DEFAULTS).map(([k, v]) =>
    '<div class="' + P + '-field"><label for="' + P + '-opt-' + k + '">' + esc(k) + '</label><input id="' + P + '-opt-' + k + '" data-opt="' + esc(k) + '" type="number" value="' + esc(v) + '"></div>').join("");
  main.innerHTML = [
    '<div class="', P, '-root">',
    '<div class="', P, '-hd"><h1>{{label}}</h1><span class="', P, '-tag">Deck</span></div>',
    '<p class="', P, '-sub">{{blurb}} Runs entirely in your browser. Nothing is uploaded.</p>',
    '<div class="', P, '-card"><div class="', P, '-drop" id="', P, '-drop">Drop a CSV or JSON export here, or click to choose a file.</div>',
    '<div class="', P, '-row"><button class="', P, '-btn" id="', P, '-example">Load example (synthetic)</button>',
    '<button class="', P, '-btn pri" id="', P, '-run" disabled>Analyze</button><span id="', P, '-file" class="', P, '-skip"></span></div>',
    '<div class="', P, '-prog" id="', P, '-prog"><i></i></div></div>',
    '<div class="', P, '-card"><div class="', P, '-ctl">', fields, "</div></div>",
    '<div class="', P, '-kpis" id="', P, '-kpis"></div>',
    '<div class="', P, '-row" id="', P, '-exports"></div>',
    '<div class="', P, '-list" id="', P, '-list"><div class="', P, '-empty">No analysis yet.</div></div>',
    '<div class="', P, '-skip" id="', P, '-skipped"></div>',
    '<div class="', P, '-drawer" id="', P, '-drawer"></div>',
    "</div>",
  ].join("");

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  let rows = [], result = null, fileName = "", isExample = false;

  const setRows = (r, name, example = false) => {
    rows = r; fileName = name; isExample = example;
    $("file").textContent = r.length ? name + ": " + r.length + " rows" : "";
    $("run").disabled = !r.length;
  };

  mountDropzone($("drop"), {
    maxBytes: 50 * 1024 * 1024,
    maxFiles: 1,
    onFiles: async (files) => {
      const f = files[0]; if (!f) return;
      const parsed = parseInput(await f.text());
      if (!parsed.rows.length) { toast("No rows found in " + f.name, "error"); return; }
      setRows(parsed.rows, f.name);
      toast("Loaded " + parsed.rows.length + " rows (" + parsed.format + ")");
    },
  });

  $("example").addEventListener("click", () => {
    const ex = exampleDataset();
    setRows(ex.rows, ex.label, true);
  });

  const opts = () => {
    const o = {};
    main.querySelectorAll("[data-opt]").forEach((el) => { const n = Number(el.value); if (Number.isFinite(n)) o[el.dataset.opt] = n; });
    return o;
  };

  $("run").addEventListener("click", async () => {
    const prog = $("prog"), bar = prog.firstElementChild;
    prog.style.display = "block"; bar.style.width = "0%"; $("run").disabled = true;
    try {
      result = await runInWorker(ENGINE, "analyze", [rows, opts()], {
        onProgress: (i, n) => { bar.style.width = (n ? Math.round(i / n * 100) : 0) + "%"; },
      });
      render(result);
      toast(result.findings.length + " finding(s)");
    } catch (e) {
      toast("Analysis failed: " + (e && e.message || e), "error");
    } finally {
      prog.style.display = "none"; $("run").disabled = !rows.length;
    }
  });

  function render(r) {
    const sum = summarize(r.findings);
    $("kpis").innerHTML = kpi(r.meta.rows, "rows") + kpi(r.findings.length, "findings") +
      ["critical", "high", "medium", "low"].map((s) => kpi(r.summary.bySeverity[s] || 0, s)).join("");
    $("skipped").textContent = r.skipped.length ? "Skipped checks: " + r.skipped.map((s) => s.check + " (" + s.reason + ")").join("; ") : "";
    const ex = $("exports");
    ex.innerHTML = '<button class="' + P + '-btn" data-x="csv">Export CSV</button><button class="' + P + '-btn" data-x="json">Export JSON</button><button class="' + P + '-btn" data-x="txt">Summary TXT</button>';
    ex.querySelector('[data-x="csv"]').addEventListener("click", () => download(TOOL_ID + "-" + fileStamp() + ".csv", findingsToCsv(r.findings), "text/csv"));
    ex.querySelector('[data-x="json"]').addEventListener("click", () => download(TOOL_ID + "-" + fileStamp() + ".json", toJson(r), "application/json"));
    ex.querySelector('[data-x="txt"]').addEventListener("click", () => download(TOOL_ID + "-" + fileStamp() + ".txt", summaryText(r, sum), "text/plain"));
    attachSinkButton(ex, () => ({ findings: r.findings, sample: isExample }), TOOL_ID, { dataset: fileName });
    const list = $("list");
    if (!r.findings.length) { list.innerHTML = '<div class="' + P + '-empty">No findings for the current thresholds.</div>'; return; }
    list.innerHTML = "<table><thead><tr><th>Severity</th><th>Finding</th><th>Confidence</th><th>Controls</th><th>Evidence</th></tr></thead><tbody>" +
      r.findings.map((f, i) => "<tr data-i=\\"" + i + "\\"><td><span class=\\"" + P + "-pill " + esc(f.severity) + "\\">" + esc(f.severity) + "</span></td><td><b>" + esc(f.title) + "</b><div>" + esc(f.description) + "</div></td><td>" + Math.round((f.confidence || 0) * 100) + "%</td><td>" +
        (f.controls || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + "</td><td>" + (f.evidence || []).length + "</td></tr>").join("") + "</tbody></table>";
    list.querySelectorAll("tr[data-i]").forEach((tr) => tr.addEventListener("click", () => {
      const f = r.findings[Number(tr.dataset.i)];
      const d = $("drawer"); d.style.display = "block";
      d.innerHTML = '<div class="' + P + '-card"><b>' + esc(f.title) + "</b><p>" + esc(f.recommendation) + "</p><pre>" + esc(JSON.stringify(f.evidence, null, 2)) + "</pre></div>";
    }));
  }

  function summaryText(r, sum) {
    return ["{{label}} summary", "Rows: " + r.meta.rows, "Findings: " + r.findings.length, "Severity: " + JSON.stringify(r.summary.bySeverity), "", "Summary: " + JSON.stringify(sum)]
      .concat(r.findings.map((f) => "- [" + f.severity + "] " + f.title + " - " + f.recommendation)).join("\\n");
  }
}
`;

const TEST_TPL = `// {{label}} engine tests (public/js/{{dir}}/{{id}}-engine.js): self-test,
// determinism and empty-input safety.

import { test, assert, group } from "../harness.mjs";
import { selfTest, analyze, parseInput, exampleDataset } from "../../public/js/{{dir}}/{{id}}-engine.js";

group("{{id}}: engine", () => {
  test("in-engine self-test passes", () => {
    const r = selfTest();
    assert.ok(r.pass, "failed: " + r.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });

  test("analyze is deterministic", () => {
    const { rows } = exampleDataset();
    assert.deepEqual(analyze(rows), analyze(rows));
  });

  test("empty input yields zero findings and does not throw", () => {
    const parsed = parseInput("");
    assert.equal(parsed.rows.length, 0);
    const r = analyze(parsed.rows);
    assert.equal(r.findings.length, 0);
    assert.equal(r.meta.rows, 0);
  });
});
`;

const specVars = (spec, stamp) => ({
  id: spec.id, label: esc(spec.label), blurb: esc(spec.blurb), blurbComment: spec.blurb.replace(/\n/g, " "),
  prefix: spec.prefix, dir: spec.dir, fn: spec.fn, stamp: stamp || "",
});

/** Engine module source. */
export function renderEngineStub(spec) { return fill(ENGINE_TPL, specVars(spec)); }
/** UI module source (needs the stamp for the engine import). */
export function renderUiStub(spec, stamp) { return fill(UI_TPL, specVars(spec, stamp)); }
/** Harness test source. */
export function renderTestStub(spec) { return fill(TEST_TPL, specVars(spec)); }

/* --------------------------------------------------------------------- lint */

/** Blank out string, template and regex literal contents on one line (heuristic). */
export function blankLiterals(line) {
  let out = "", i = 0, prev = "";
  const n = line.length;
  while (i < n) {
    const c = line[i];
    if (c === "/" && line[i + 1] === "/") { out += " ".repeat(n - i); break; }
    if (c === "\"" || c === "'" || c === "`" || (c === "/" && /^[\s(,=:[!&|?{};+]?$/.test(prev.trim() || ""))) {
      const q = c; let j = i + 1;
      while (j < n && line[j] !== q) { if (line[j] === "\\") j++; j++; }
      out += q + " ".repeat(Math.max(0, j - i - 1)) + (j < n ? q : "");
      i = j + 1; prev = q; continue;
    }
    out += c; if (!/\s/.test(c)) prev = c; i++;
  }
  return out;
}

function walk(dir, pred, out = []) {
  if (!existsSync(dir)) return out;
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) walk(full, pred, out);
    else if (pred(full)) out.push(full);
  }
  return out;
}

const read = (root, rel) => readFileSync(join(root, rel), "utf8");

/**
 * Lint the real tree. Returns [{ severity: "error"|"warn", msg, file?, line? }].
 * Mirrors test/ui/explain.test.mjs for the explain/HELP rule.
 */
export function lint(root) {
  const out = [];
  const err = (msg, file, line) => out.push({ severity: "error", msg, file, line });
  const warn = (msg, file, line) => out.push({ severity: "warn", msg, file, line });
  let authSrc, deckSrc, explainSrc, adminSrc, indexSrc, swSrc, helpA = "", helpB = "";
  try {
    authSrc = read(root, "public/js/auth.js"); deckSrc = read(root, "public/js/deck-ui.js");
    explainSrc = read(root, "public/js/ui/explain.js"); adminSrc = read(root, "public/js/admin.js");
    indexSrc = read(root, "public/index.html"); swSrc = read(root, "public/sw.js");
  } catch (e) { err("cannot read registry files: " + e.message); return out; }
  try { helpA = read(root, "public/js/section-help-a.js"); helpB = read(root, "public/js/section-help-b.js"); } catch (e) { warn("section-help maps unreadable: " + e.message); }

  let nav, routes, blurbs, explainKeys;
  try { nav = parseNavDef(deckSrc); } catch (e) { err(e.message, "public/js/deck-ui.js"); }
  try { routes = parseRoutes(authSrc); } catch (e) { err(e.message, "public/js/auth.js"); }
  try { blurbs = parseBlurbs(authSrc); } catch (e) { err(e.message, "public/js/auth.js"); }
  explainKeys = parseExplainKeys(explainSrc);
  const helpKeys = new Set([...parseHelpKeys(helpA), ...parseHelpKeys(helpB)]);
  let icons, consoleIds = null;
  try { icons = parseIcons(deckSrc); } catch (e) { err(e.message, "public/js/deck-ui.js"); }
  try { consoleIds = parseConsoleNavIds(read(root, "public/js/console-nav.js")); } catch (e) { warn("console-nav.js unreadable: " + e.message); }

  // Repeated ids: the parsers keep one copy, so report the extras instead of dropping them.
  const dupSites = [
    [nav, "NAV_DEF tool id", "public/js/deck-ui.js"], [icons, "IC icon", "public/js/deck-ui.js"],
    [routes, "show() route id", "public/js/auth.js"], [blurbs, "SIDE_DESC id", "public/js/auth.js"],
    [explainKeys, "EXPLAIN key", "public/js/ui/explain.js"], [consoleIds, "console-nav id", "public/js/console-nav.js"],
  ];
  for (const [coll, what, file] of dupSites) for (const d of (coll && coll.dups) || []) err(`duplicate ${what} "${d.id}"`, file, d.line);
  const helpAKeys = parseHelpKeys(helpA), helpBKeys = parseHelpKeys(helpB);
  for (const [k, file] of [[helpAKeys, "public/js/section-help-a.js"], [helpBKeys, "public/js/section-help-b.js"]]) for (const d of k.dups) err(`duplicate HELP key "${d.id}"`, file, d.line);
  for (const id of helpBKeys) if (helpAKeys.has(id)) err(`HELP key "${id}" is defined in both section-help-a.js and section-help-b.js`, "public/js/section-help-b.js");

  const testFiles = walk(join(root, "test/security"), (f) => f.endsWith(".test.mjs"));
  const testSrc = new Map(testFiles.map((f) => [f, readFileSync(f, "utf8")]));

  if (nav && routes && blurbs) {
    for (const g of nav.groups) for (const it of g.items) {
      if (it.kind !== "tool" || NAV_WHITELIST.has(it.id)) continue;
      const r = routes.get(it.id);
      if (!r) err(`NAV_DEF tool "${it.id}" has no show() route`, "public/js/auth.js");
      else if (r.path && !existsSync(join(root, "public", r.path))) err(`route "${it.id}" imports missing file ${r.path}`, "public/js/auth.js", r.line);
      if (!blurbs.has(it.id)) err(`NAV_DEF tool "${it.id}" has no SIDE_DESC blurb`, "public/js/auth.js");
      if (!explainKeys.has("tool." + it.id) && !helpKeys.has(it.id)) err(`NAV_DEF tool "${it.id}" has no EXPLAIN "tool.${it.id}" or HELP entry`, "public/js/ui/explain.js");
      const dir = r && r.path ? (/^\/js\/([^/]+)\//.exec(r.path) || [])[1] : null;
      if (dir && STRICT_DIRS.includes(dir)) {
        const direct = join(root, "test/security", it.id + ".test.mjs");
        if (!existsSync(direct)) {
          const stem = r.path.replace(/\.js$/, "").replace(/s$/, "");
          const covered = [...testSrc.values()].some((s) => s.includes(stem));
          (covered ? warn : err)(`tool "${it.id}" has no test/security/${it.id}.test.mjs` + (covered ? " (another test imports its module)" : ""), "test/security");
        }
      }
    }
  }

  try {
    const st = parseStamps({ adminSrc, deckUiSrc: deckSrc, indexSrc, swSrc });
    if (st.index[0] !== st.index[1]) err(`index.html auth.js stamps differ: ${st.index.join(" vs ")}`, "public/index.html");
  } catch (e) { err(e.message); }

  // Duplicate object keys / class methods / same-scope function declarations: the later one
  // silently wins, so the earlier copy is dead code (scripts/lib/dup-scan.mjs).
  for (const f of walk(join(root, "public/js"), (p) => /\.m?js$/.test(p))) {
    const rel = relative(root, f).split("\\").join("/");
    for (const d of scanDuplicates(readFileSync(f, "utf8"))) {
      const what = d.kind === "function" ? "function declaration" : d.kind === "method" ? "class method" : "object key";
      err(`duplicate ${what} "${d.name}" (first at line ${d.firstLine}; the later one wins)`, rel, d.line);
    }
  }

  const engines = walk(join(root, "public/js"), (f) => f.endsWith("-engine.js"));
  const domRe = /\b(window|document|localStorage)\s*[.[]/;
  for (const f of engines) {
    const rel = relative(root, f).split("\\").join("/");
    const dir = (/^public\/js\/([^/]+)\//.exec(rel) || [])[1];
    const strict = dir && STRICT_DIRS.includes(dir);
    const src = readFileSync(f, "utf8").split("\n");
    src.forEach((l, i) => {
      if (/^\s*(\/\/|\*|\/\*)/.test(l)) return;
      const clean = blankLiterals(l);
      const m = domRe.exec(clean);
      if (!m) return;
      if (new RegExp(`typeof\\s+${m[1]}\\b`).test(clean)) return;
      (strict ? err : warn)(`engine references ${m[1]} at module scope (not worker-safe)`, rel, i + 1);
    });
  }
  return out;
}
