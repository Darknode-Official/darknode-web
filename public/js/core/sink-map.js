// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved.
// Pure half of the findings sink: maps a tool's findings onto Security Graph
// entities + links. No DOM, no storage, no graph import — core/sink.js does the
// browser I/O. Any tool that emits the common Finding shape below can publish.
//
// Finding:
// { id?, title, severity: "critical"|"high"|"medium"|"low"|"info",
//   confidence?: "confirmed"|"likely"|"review"|number,
//   status?: "open"|"new"|"investigating"|"resolved"|"closed",
//   category?, description?, recommendation?,
//   controls?: [{ framework: "MITRE"|"CIS"|"ISO27001"|"NIST-CSF"|"NIST-800-53"|"SOC2"|"PCI"|"GDPR"|string, id: string }],
//   evidence?: object[],
//   assets?: [{ type: "ASSET"|"DOMAIN"|"IP"|"IDENTITY"|"VENDOR"|"VULNERABILITY", name, data? }],
//   tags?: string[] }

import { cyrb53 } from "./hash.js";

/** Entity `data` byte budget: worker/graph.js blanks data above 40000 chars. */
export const DATA_CAP = 38000;

export const SEVERITIES = ["critical", "high", "medium", "low", "info"];

const str = (v) => String(v == null ? "" : v);
const uniq = (arr) => Array.from(new Set(arr.filter((x) => x != null && x !== "")));
const sev = (s) => (SEVERITIES.includes(str(s).toLowerCase()) ? str(s).toLowerCase() : "info");
const assetKey = (a) => str(a.type).toUpperCase() + ":" + str(a.name).trim();
const byTypeName = (a, b) => (a.type === b.type ? a.name.localeCompare(b.name) : a.type.localeCompare(b.type));
const byLink = (a, b) => (a.from + a.rel + a.to).localeCompare(b.from + b.rel + b.to);

/**
 * Stable identity for a finding within a tool. Uses the tool's own id when given,
 * else title + category + the sorted set of affected assets (order-independent).
 * @param {string} toolId
 * @param {object} f finding
 * @returns {string}
 */
export function findingKey(toolId, f) {
  f = f || {};
  const seed = f.id || [str(f.title), str(f.category), ...(f.assets || []).map(assetKey).sort()].join("|");
  return cyrb53(str(toolId) + "|" + seed);
}

/**
 * Shrink `data` until its JSON fits under `cap`: drop evidence rows from the end
 * (keeping evidenceCount, setting evidenceTruncated), then cut description to
 * 2000 chars, then drop evidence entirely. Never mutates the input.
 * @param {object} data
 * @param {number} [cap=DATA_CAP]
 * @returns {object}
 */
export function fitUnder(data, cap = DATA_CAP) {
  const size = (d) => JSON.stringify(d).length;
  const d = { ...(data || {}) };
  if (size(d) <= cap) return d;
  if (Array.isArray(d.evidence)) {
    d.evidence = d.evidence.slice();
    if (d.evidenceCount == null) d.evidenceCount = d.evidence.length;
    while (d.evidence.length && size(d) > cap) { d.evidence.pop(); d.evidenceTruncated = true; }
    if (!d.evidence.length) delete d.evidence;
    if (size(d) <= cap) return d;
  }
  if (typeof d.description === "string" && d.description.length > 2000) d.description = d.description.slice(0, 2000);
  if (size(d) <= cap) return d;
  if ("evidence" in d) { delete d.evidence; d.evidenceTruncated = true; }
  return d;
}

/**
 * Collapse findings sharing a findingKey; the last occurrence wins but keeps the
 * position of the first.
 * @param {object[]} findings
 * @param {string} toolId
 * @returns {{ findings: object[], dropped: number }}
 */
export function dedupe(findings, toolId) {
  const order = [], slot = new Map();
  let dropped = 0;
  for (const f of findings || []) {
    const k = findingKey(toolId, f);
    if (slot.has(k)) dropped++; else order.push(k);
    slot.set(k, f);
  }
  return { findings: order.map((k) => slot.get(k)), dropped };
}

/**
 * Map findings to graph items + links. Link endpoints are type-qualified item
 * keys ("FINDING:name"). FINDING names carry "(tool:key)" so upsertToolResult's
 * lowercase-name dedupe merges re-runs instead of duplicating. With `sample`,
 * every item is tagged "sample" so isSimulated() keeps it apart from real data.
 * @param {string} toolId
 * @param {object[]} findings
 * @param {{ dataset?: string, sample?: boolean }} [o]
 * @returns {{ items: {type:string,name:string,data:object,opts:object}[], links: {from:string,to:string,rel:string}[] }}
 */
export function toEntities(toolId, findings, { dataset, sample = false } = {}) {
  const items = new Map(), links = new Set();
  const put = (type, name, data, opts) => {
    const k = type + ":" + name;
    const prev = items.get(k);
    if (!prev) items.set(k, { type, name, data, opts });
    else prev.data = { ...data, ...prev.data }; // union asset data; earlier (by key order) wins conflicts
    return k;
  };
  // Walk in findingKey order so first-seen merges are independent of input order.
  const ordered = (findings || []).filter((f) => f && str(f.title).trim())
    .map((f) => [findingKey(toolId, f), f]).sort((a, b) => a[0].localeCompare(b[0]));
  for (const [key, f] of ordered) {
    const assets = (f.assets || []).filter((a) => a && str(a.name).trim());
    const controls = (f.controls || []).filter((c) => c && str(c.id).trim());
    const evidence = Array.isArray(f.evidence) ? f.evidence : [];
    const data = fitUnder({
      findingKey: key, tool: toolId, dataset, confidence: f.confidence, category: f.category,
      controls: controls.map((c) => ({ framework: str(c.framework), id: str(c.id) })),
      assets: assets.map((a) => str(a.name).trim()), evidence, evidenceCount: evidence.length,
      description: f.description, recommendation: f.recommendation,
    });
    const fk = put("FINDING", `${str(f.title).trim()} (${toolId}:${key})`, data, {
      severity: sev(f.severity), status: f.status || "open",
      tags: uniq(["sink", toolId, ...(sample ? ["sample"] : []), ...(f.tags || [])]),
    });
    for (const a of assets) {
      const ak = put(str(a.type).toUpperCase() || "ASSET", str(a.name).trim(), a.data || {}, { tags: sample ? ["sample"] : [] });
      links.add(JSON.stringify({ from: fk, to: ak, rel: "affects" }));
    }
    for (const c of controls) {
      const ck = put("CONTROL", `${str(c.framework)} ${str(c.id)}`.trim(), { framework: str(c.framework), controlId: str(c.id) }, { tags: sample ? ["sample"] : [] });
      links.add(JSON.stringify({ from: ck, to: fk, rel: "mitigates" }));
    }
  }
  return {
    items: Array.from(items.values()).sort(byTypeName),
    links: Array.from(links).map((s) => JSON.parse(s)).sort(byLink),
  };
}

/**
 * Severity / confidence tallies for a results header.
 * @param {object[]} findings
 * @returns {{ total:number, bySeverity:object, byConfidence:object }}
 */
export function summarize(findings) {
  const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  const byConfidence = {};
  let total = 0;
  for (const f of findings || []) {
    if (!f) continue;
    total++;
    bySeverity[sev(f.severity)]++;
    const c = f.confidence == null ? "unknown" : str(f.confidence);
    byConfidence[c] = (byConfidence[c] || 0) + 1;
  }
  return { total, bySeverity, byConfidence };
}

// Framework prefixes seen in tool control/reference strings, most specific first.
const REF_FRAMEWORKS = [
  [/^ISO\s*(?:\/?\s*IEC\s*)?27001(?::\d{4})?\s*/i, "ISO27001"],
  [/^NIST\s*(?:SP\s*)?800-53(?:\s*r\d)?\s*/i, "NIST-800-53"],
  [/^NIST\s*(?:SP\s*)?800-41(?:\s*r\d)?\s*(?:sec\.?\s*)?/i, "NIST-800-41"],
  [/^NIST\s*CSF(?:\s*v?2\.0)?\s*/i, "NIST-CSF"],
  [/^CIS\s*(?:Controls?\s*)?v8\s*/i, "CIS"],
  [/^PCI\s*DSS(?:\s*v?\d\.\d)?\s*(?:req\.?\s*)?/i, "PCI"],
  [/^SOC\s*2\s*/i, "SOC2"],
  [/^SOX\s*/i, "SOX"],
];

/**
 * Parse free-text control references ("ISO 27001 A.5.18", "CIS Controls v8 4.4 / 4.5 (note)",
 * "PCI DSS 4.0 req. 1.2.5, 1.3.1", "ATT&CK T1078", "T1110.004 / T1078.004") into Finding
 * controls. Parenthetical notes are dropped; "a / b" and "a, b" lists split into one control
 * each. A string with no known framework is kept whole (framework "") rather than guessed.
 * @param {string|string[]} refs
 * @returns {{framework:string,id:string}[]} de-duplicated, input order
 */
export function controlsFromRefs(refs) {
  const out = [], seen = new Set();
  const add = (framework, id) => {
    id = str(id).trim().replace(/[.;:]+$/, "");
    const k = framework + "|" + id.toLowerCase();
    if (id && !seen.has(k)) { seen.add(k); out.push({ framework, id }); }
  };
  for (const raw of [].concat(refs || [])) {
    const s = str(raw).trim();
    if (!s) continue;
    if (/^(?:MITRE\s*)?(?:ATT&CK\s*)?T\d{4}/i.test(s)) { for (const t of s.match(/T\d{4}(?:\.\d{3})?/gi)) add("MITRE", t.toUpperCase()); continue; }
    const fw = REF_FRAMEWORKS.find(([re]) => re.test(s));
    if (!fw) { add("", s); continue; }
    const rest = s.replace(fw[0], "").replace(/\s+\([^)]*\)/g, "").trim();
    if (fw[1] === "SOX") { add("SOX", rest.replace(/:\s*/, " ")); continue; }
    for (const id of rest.split(/\s*[\/,;]\s*/)) add(fw[1], id);
  }
  return out;
}

/**
 * Share (0..1) of the distinct example rows (after `skip` header lines) still present in
 * `text`, weighted by row length so short boilerplate a real export also has ("COMMIT",
 * "*filter", a closing brace) counts for little. Tools keep a run sample-flagged while the
 * loaded example is substantially there (edited or appended to) and drop the flag once the
 * user has replaced it with real data.
 * @param {string} text
 * @param {string|null} sampleText
 * @param {number} [skip=1]
 * @returns {number}
 */
export function sampleShare(text, sampleText, skip = 1) {
  if (!text || !sampleText) return 0;
  const rows = new Set(str(sampleText).split(/\r?\n/).slice(skip).map((l) => l.trim()).filter(Boolean));
  if (!rows.size) return 0;
  const have = new Set(str(text).split(/\r?\n/).map((l) => l.trim()));
  let n = 0, total = 0;
  for (const r of rows) { total += r.length; if (have.has(r)) n += r.length; }
  return n / total;
}

/** sampleShare at or above which a run counts as sample data. */
export const SAMPLE_SHARE = 0.5;
