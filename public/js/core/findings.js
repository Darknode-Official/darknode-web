// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Pure helpers behind the Deck's Findings view, "Top actions" band and section pages.
// Everything works on real security-graph entities (simulated/sample data is dropped
// unless explicitly asked for) and on live feed data passed in by the caller, so each
// ranked item traces back to a record or a feed entry.

import { isSimulated } from "./posture.js";
import { cleanTitle } from "./queue-format.js";

export const FINDING_TYPES = ["FINDING", "VULNERABILITY"];
export const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
export const OPEN_STATUSES = ["new", "open", "investigating"];
const sevOf = (e) => String(e.severity || "").toLowerCase();
// hasOwnProperty-guarded rank: a severity literally named "constructor"/"toString"
// would otherwise resolve to an inherited member (truthy, so ?? -1 never fires) and
// poison the comparator with NaN, scrambling the sort order.
const sevRank = (s) => Object.prototype.hasOwnProperty.call(SEV_RANK, s) ? SEV_RANK[s] : -1;
const isOpen = (e) => !e.status || OPEN_STATUSES.includes(String(e.status).toLowerCase());

// Finding rows, most severe first, then most recently updated.
export function collectFindings(entities, opts = {}) {
  return (entities || [])
    .filter((e) => e && FINDING_TYPES.includes(e.type) && (opts.includeSim || !isSimulated(e)))
    .map((e) => ({
      id: e.id, name: cleanTitle(e), type: e.type, severity: sevOf(e) || null, status: e.status || "new",
      source: e.source || "manual", tags: e.tags || [], createdAt: e.createdAt || "", updatedAt: e.updatedAt || e.createdAt || "",
      sim: isSimulated(e),
    }))
    .sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || String(b.updatedAt).localeCompare(String(a.updatedAt)) || String(a.id).localeCompare(String(b.id)));
}

export function filterFindings(rows, f = {}) {
  const q = String(f.q || "").trim().toLowerCase();
  return rows.filter((r) =>
    (!f.severity || r.severity === f.severity) &&
    (!f.status || (f.status === "open" ? OPEN_STATUSES.includes(r.status) : r.status === f.status)) &&
    (!f.source || r.source === f.source) &&
    (!q || (r.name + " " + r.source + " " + r.tags.join(" ")).toLowerCase().includes(q)));
}

export function findingCounts(rows) {
  const open = rows.filter(isOpen);
  return {
    total: rows.length, open: open.length,
    critical: open.filter((r) => r.severity === "critical").length,
    high: open.filter((r) => r.severity === "high").length,
    resolved: rows.length - open.length,
  };
}

// CSV with RFC 4180 quoting. Cells that a spreadsheet would run as a formula
// (= + - @, tab, CR) are prefixed with a quote so exported data stays inert.
export function toCSV(rows, cols = ["severity", "name", "type", "status", "source", "createdAt", "updatedAt", "id"]) {
  const cell = (v) => {
    let s = Array.isArray(v) ? v.join(";") : String(v == null ? "" : v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  return [cols.join(","), ...rows.map((r) => cols.map((c) => cell(r[c])).join(","))].join("\r\n") + "\r\n";
}

// Ranked "do this next" list. Inputs are all real: graph entities, the live CVE page
// with its KEV set, and which integrations are connected. Highest score first.
//   { findings, cves:[{id,cvss,severity,title}], kev:Set, connected:Set, integrations:[{id,kind,name}] }
export function topActions(inp, limit = 6) {
  const out = [];
  const open = (inp.findings || []).filter((r) => !r.sim && isOpen(r));
  for (const r of open) {
    if (r.severity === "critical") out.push({ score: 100, kind: "finding", sev: "critical", id: r.id, title: r.name, detail: "Open critical finding from " + r.source });
    else if (r.severity === "high") out.push({ score: 80, kind: "finding", sev: "high", id: r.id, title: r.name, detail: "Open high finding from " + r.source });
  }
  const kev = inp.kev || new Set();
  for (const c of inp.cves || []) {
    if (kev.has(c.id)) out.push({ score: 90, kind: "cve", sev: "critical", id: c.id, title: c.id + " is being exploited", detail: "New this week and on the CISA KEV catalog. Check whether you run it: " + (c.title || "") });
    else if (!inp.kevOnly && c.cvss != null && c.cvss >= 9) out.push({ score: 60, kind: "cve", sev: "high", id: c.id, title: c.id + " (CVSS " + c.cvss + ")", detail: c.title || "" });
  }
  const conn = inp.connected || new Set(), ints = inp.integrations || [];
  const has = (kind) => ints.some((i) => i.kind === kind && conn.has(i.id));
  if (ints.length && !has("sec")) out.push({ score: 40, kind: "connect", sev: "medium", id: "intel", title: "Connect a threat-intelligence source", detail: "Without one, indicators cannot be enriched and your exposure score counts the gap." });
  if (ints.length && !has("ai")) out.push({ score: 30, kind: "connect", sev: "low", id: "ai", title: "Connect an AI model", detail: "Optional: the free Darknode AI works now; your own model adds capacity." });
  if (!open.length && !(inp.findings || []).some((r) => !r.sim)) out.push({ score: 50, kind: "start", sev: "medium", id: "scan", title: "Measure your exposure", detail: "No real findings yet. Scan a codebase or map your attack surface to get a baseline." });
  return out.sort((a, b) => b.score - a.score).slice(0, limit);
}

// Real entities that belong to a section: by entity type, or by a source/tag pattern.
export function sectionEntities(entities, def) {
  const types = def.types || [], re = def.match || null;
  return (entities || []).filter((e) => e && !isSimulated(e) &&
    (types.includes(e.type) || (re && re.test([e.source || "", ...(e.tags || [])].join(" ")))));
}
