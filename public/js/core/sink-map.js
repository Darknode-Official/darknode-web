// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved.
// Pure half of the findings sink: maps a tool's findings onto Security Graph
// entities + links. No DOM, no storage, no graph import — core/sink.js does the
// browser I/O. Any tool that emits the common Finding shape below can publish.
//
// Finding:
// { id?, title, severity: "critical"|"high"|"medium"|"low"|"info",
//   confidence?: "confirmed"|"likely"|"review"|number,
//   status?: "open"|"new"|"investigating"|"resolved"|"closed",
//   resolution?: "fixed"|"accepted"|"false_positive"|"duplicate",  (why resolved/closed)
//   category?, description?, recommendation?,
//   controls?: [{ framework: "MITRE"|"CIS"|"ISO27001"|"NIST-CSF"|"NIST-800-53"|"SOC2"|"PCI"|"GDPR"|string, id: string }],
//   evidence?: object[],
//   assets?: [{ type: "ASSET"|"DOMAIN"|"IP"|"IDENTITY"|"VENDOR"|"VULNERABILITY", name, data? }],
//   tags?: string[] }

import { cyrb53 } from "./hash.js";
import { ruleAllows } from "./relationship-rules.js";

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

const ownFields = (d) => { const o = {}; for (const k in d || {}) if (k !== "bySource" && k !== "_toolSource") o[k] = d[k]; return o; };

/**
 * Merge a tool's `incoming` data into an existing entity's `prev` data (used by
 * graph-bridge upsertToolResult). Top level is a shallow merge where incoming wins
 * for the keys it sends, so one tool no longer erases another tool's facts.
 * Once a second tool touches the entity, data.bySource[tool] keeps each tool's own
 * latest payload (newest last), seeding the earlier tool's top-level facts under its
 * _toolSource name. If the result is over `cap`, the oldest sources are dropped first.
 * Never mutates its inputs.
 * @param {object} prev existing entity data
 * @param {object} incoming the tool's data
 * @param {string} toolName
 * @param {number} [cap=DATA_CAP]
 * @returns {object}
 */
export function mergeToolData(prev, incoming, toolName, cap = DATA_CAP) {
  const p = prev || {}, inc = ownFields(incoming), tool = str(toolName) || "unknown";
  const bySource = { ...(p.bySource && typeof p.bySource === "object" ? p.bySource : {}) };
  const prevTool = str(p._toolSource);
  if (prevTool && prevTool !== tool && !(prevTool in bySource)) bySource[prevTool] = ownFields(p);
  delete bySource[tool];
  bySource[tool] = inc;
  // A single-source entity's top level already is that tool's data; storing it twice
  // would double the graph's localStorage footprint for nothing.
  if (!p.bySource && Object.keys(bySource).length < 2) return { ...p, ...inc, _toolSource: tool };
  const out = { ...p, ...inc, _toolSource: tool, bySource };
  const names = Object.keys(bySource);
  while (names.length && JSON.stringify(out).length > cap) delete bySource[names.shift()];
  return out;
}

const REOPEN = ["new", "open"];
const KEEP_CLOSED = ["accepted", "false_positive", "duplicate"];

/**
 * Status a tool re-run should move an entity to, or null to leave it. A tool's
 * "new"/"open" does not pull back an entity an analyst is investigating, nor reopen
 * one resolved/closed as accepted / false_positive / duplicate; anything else applies, so a
 * re-scan can resolve a finding or reopen a fixed one that came back.
 * @param {string|null} current
 * @param {string|null|undefined} incoming
 * @param {string} [resolution] data.resolution
 * @returns {string|null}
 */
export function nextStatus(current, incoming, resolution) {
  if (!incoming || incoming === current) return null;
  if (REOPEN.includes(incoming) && (current === "investigating" || ((current === "closed" || current === "resolved") && KEEP_CLOSED.includes(resolution)))) return null;
  return incoming;
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
      description: f.description, recommendation: f.recommendation, resolution: f.resolution,
    });
    const fk = put("FINDING", `${str(f.title).trim()} (${toolId}:${key})`, data, {
      severity: sev(f.severity), status: f.status || "open",
      tags: uniq(["sink", toolId, ...(sample ? ["sample"] : []), ...(f.tags || [])]),
    });
    for (const a of assets) {
      const at = str(a.type).toUpperCase() || "ASSET";
      const ak = put(at, str(a.name).trim(), a.data || {}, { tags: sample ? ["sample"] : [] });
      // FINDING -affects-> only targets the rules allow (assets, hosts, identities...);
      // a VULNERABILITY / INCIDENT "asset" is linked related_to so the graph keeps it.
      links.add(JSON.stringify({ from: fk, to: ak, rel: ruleAllows("affects", "FINDING", at) ? "affects" : "related_to" }));
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
