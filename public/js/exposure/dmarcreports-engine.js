// DMARC Reports engine (dmarcreports). Analyzes tabular exports (CSV/JSON) for
// DMARC aggregate report analyzer: per-source alignment, sending-service classification, spoofing volume and a safe path to p=reject.
// pure: no DOM, no network; deterministic. Safe to run inside a Worker.

import { sniff, parseCsv, iterJson, findColumn } from "../ingest/parse.js";

export const TOOL_ID = "dmarcreports";
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
  return [head, ...body].join("\n");
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
