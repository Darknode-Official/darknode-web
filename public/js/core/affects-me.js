// "What affects me" (Deck D9). PURE — no DOM, no network, deterministic. Given the entities
// already in the security graph and the CURRENT exploitation feeds (CISA KEV set + FIRST EPSS
// scores), it answers: which CVEs that this organisation actually has in its graph are
// known-exploited or high-probability right now. It reports what the graph and the live feeds
// say — it invents nothing, and it does not reproduce the catalogues. As the KEV feed grows,
// a CVE already sitting in the graph surfaces here the day it becomes known-exploited, with no
// re-import needed.
import { cveIds } from "./workflow.js";

const low = (v) => String(v == null ? "" : v).toLowerCase();
const SEV = ["critical", "high", "medium", "low", "info"];
const OPEN = new Set(["new", "open", "investigating"]);
const sevRank = (s) => { const i = SEV.indexOf(s); return i < 0 ? SEV.length : i; };
const isOpenFinding = (e) => low(e.type) === "finding" && OPEN.has(low(e.status) || "new");
// A subject worth naming for a CVE: anything in the graph that references it.
const subjectName = (e) => String(e.name || e.id || "").trim();

/**
 * affectsMe(entities, opts) -> prioritised CVEs from the graph that the live feeds flag.
 * opts: { kevSet (Set|array of CVE ids), epss ({cve:score 0..1}), epssFloor (default 0.5), now }.
 * -> { matches: [{ cve, kev, epss, severity, open, subjects:[{id,name,type}], subjectCount }],
 *      kevCount, epssCount, affectedSubjects, scanned, asOf }
 * A CVE is included when it is in kevSet OR its EPSS score >= epssFloor. matches are sorted
 * KEV-first, then by EPSS desc, then by severity, then by CVE id — deterministic.
 */
export function affectsMe(entities, opts = {}) {
  const now = Number.isFinite(opts.now) ? opts.now : Date.now();
  const kev = opts.kevSet ? (typeof opts.kevSet.has === "function" ? opts.kevSet : new Set(opts.kevSet)) : new Set();
  const epss = opts.epss && typeof opts.epss === "object" ? opts.epss : {};
  const floor = Number.isFinite(opts.epssFloor) ? opts.epssFloor : 0.5;
  const ents = Array.isArray(entities) ? entities : [];

  const byCve = new Map(); // cve -> { cve, kev, epss, severity, open, subjects:Map<id,{...}> }
  let scanned = 0;
  for (const e of ents) {
    const ids = cveIds(e);
    if (!ids.length) continue;
    scanned++;
    const sev = SEV.includes(low(e.severity)) ? low(e.severity) : null;
    const open = isOpenFinding(e) || low(e.type) !== "finding"; // non-findings (assets/software/vulns) count as present
    for (const cve of ids) {
      if (!byCve.has(cve)) byCve.set(cve, { cve, kev: kev.has(cve), epss: typeof epss[cve] === "number" ? epss[cve] : null, severity: null, open: false, subjects: new Map() });
      const row = byCve.get(cve);
      if (sev && (row.severity == null || sevRank(sev) < sevRank(row.severity))) row.severity = sev; // worst wins
      if (open) row.open = true;
      if (!row.subjects.has(e.id)) row.subjects.set(e.id, { id: e.id, name: subjectName(e), type: low(e.type) || "entity" });
    }
  }

  const matches = [];
  const affected = new Set();
  for (const row of byCve.values()) {
    const include = row.kev || (row.epss != null && row.epss >= floor);
    if (!include) continue;
    const subjects = [...row.subjects.values()].sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
    for (const s of subjects) affected.add(s.id);
    matches.push({ cve: row.cve, kev: row.kev, epss: row.epss, severity: row.severity || "info", open: row.open, subjects, subjectCount: subjects.length });
  }
  matches.sort((a, b) =>
    (b.kev ? 1 : 0) - (a.kev ? 1 : 0)
    || (b.epss || 0) - (a.epss || 0)
    || sevRank(a.severity) - sevRank(b.severity)
    || String(a.cve).localeCompare(String(b.cve)));

  return {
    matches,
    kevCount: matches.filter((m) => m.kev).length,
    epssCount: matches.filter((m) => !m.kev && m.epss != null && m.epss >= floor).length,
    affectedSubjects: affected.size,
    scanned,
    asOf: now,
  };
}

// The CVE ids present in the graph, de-duplicated — the input to an EPSS lookup so only CVEs
// the organisation actually has are queried. Capped so a feed call stays bounded.
export function graphCves(entities, cap = 400) {
  const set = new Set();
  for (const e of (Array.isArray(entities) ? entities : [])) { for (const c of cveIds(e)) { set.add(c); if (set.size >= cap) return [...set]; } }
  return [...set];
}
