// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// MonitorDO -> Security Graph bridge (Trident Phase 2). PURE: no DOM, no storage, no
// Durable Object — so it runs identically in a node test and in the worker.
//
// Continuous monitoring (worker/checks.js) produces real findings on the server with the
// page closed, but until now they only drove alerts and a history log — they never reached
// the workspace graph, so they could not be owned, SLA-tracked or correlated. This maps a
// monitor's findings onto the SAME Security Graph entities a browser tool produces (via the
// canonical core/sink-map.toEntities), so a monitor finding is indistinguishable in shape
// from a tool's and merges/dedupes by the same rules.
//
// Two things make the server write safe and idempotent, which a browser tool gets for free
// from its local name-keyed entity table but a stateless worker must engineer:
//   * Deterministic entity ids (cyrb53 of TYPE:lowercased-name), so a monitor's re-run
//     updates the same GraphDO record (LWW by updatedAt) instead of creating a duplicate.
//   * Content-stable timestamps. createdAt is the finding's first-seen time (so the
//     workflow SLA clock, which keys off createdAt, never resets on a re-run); updatedAt
//     only advances when a watched field actually changes. An unchanged finding therefore
//     carries the exact same record every run, which GraphDO's wins() treats as a tie and
//     skips — zero churn, no audit spam, while a changed one strictly wins and applies.
// The caller (MonitorDO) owns the first-seen / changed-at clock in `graphMeta`.

import { toEntities, findingKey } from "../public/js/core/sink-map.js";
import { cyrb53 } from "../public/js/core/hash.js";

const str = (v) => String(v == null ? "" : v);

// Map one monitor finding (worker/checks.js shape: { key, severity, title, ... }) onto the
// common Finding shape core/sink-map expects. `id: f.key` pins the findingKey so it stays
// stable across runs even though the human title drifts (e.g. "expires in 5 days"), and the
// graph title is a stable form so the entity name does not churn. Unknown check types fall
// back to a generic mapping with no invented assets (honest: no fake links).
export function monitorFindingToCommon(f, status, resolution) {
  f = f || {};
  const base = { id: str(f.key), severity: f.severity, status: status || f.status || "open", tags: ["monitor"] };
  if (resolution) base.resolution = resolution;

  if (str(f.key).startsWith("cert:") || f.category === "certificate") {
    const dom = str(f.domain) || str(f.key).replace(/^cert:/, "");
    const days = f.daysToExpiry;
    return {
      ...base,
      title: `Certificate expiring: ${dom}`,
      category: "certificate",
      tags: [...base.tags, "certificate"],
      assets: dom ? [{ type: "DOMAIN", name: dom }] : [],
      description: Number(days) < 0
        ? `The newest certificate for ${dom} has expired.`
        : `The newest certificate for ${dom} expires in ${days} day${days === 1 ? "" : "s"}.`,
      evidence: [{ domain: dom, daysToExpiry: days ?? null, issuer: str(f.issuer), notAfter: str(f.notAfter) }],
    };
  }

  if (str(f.key).startsWith("kev:") || str(f.key).startsWith("epss:") || f.category === "vulnerability") {
    const cve = str(f.cve) || str(f.key).replace(/^(kev|epss):/, "");
    const isKev = !!f.kev || str(f.key).startsWith("kev:");
    return {
      ...base,
      title: isKev ? `Known-exploited vulnerability in inventory: ${cve}` : `High exploit-likelihood vulnerability: ${cve}`,
      category: "vulnerability",
      tags: [...base.tags, "vulnerability", isKev ? "kev" : "epss"],
      assets: cve ? [{ type: "VULNERABILITY", name: cve }] : [],
      // CISA BOD 22-01 sets the KEV remediation deadline; a real, citable control for KEV hits only.
      controls: isKev ? [{ framework: "CISA", id: "BOD 22-01" }] : [],
      description: isKev
        ? `${cve} is on the CISA Known Exploited Vulnerabilities catalogue${f.dueDate ? ` (remediate by ${str(f.dueDate)})` : ""}.`
        : `${cve} has a high EPSS exploit-prediction score${typeof f.epss === "number" ? ` (${Math.round(f.epss * 100)}%)` : ""}.`,
      evidence: [{ cve, kev: isKev, dueDate: str(f.dueDate), epss: typeof f.epss === "number" ? f.epss : null }],
    };
  }

  if (str(f.key).startsWith("email:") || f.category === "email-dns") {
    const dom = str(f.domain);
    return {
      ...base,
      // the record (SPF, DMARC, MX, CAA) and domain are stable; the detail moves with the record
      title: `Weak ${str(f.check) || "DNS"} record: ${dom}`,
      category: "email-dns",
      tags: [...base.tags, "email-dns"],
      assets: dom ? [{ type: "DOMAIN", name: dom }] : [],
      description: str(f.detail),
      evidence: [{ domain: dom, check: str(f.check), detail: str(f.detail), advice: str(f.advice) }],
    };
  }

  // Generic: keep every field as evidence, no invented assets/links.
  const { key, severity, title, status: _s, ...rest } = f;
  return {
    ...base,
    title: str(f.title) || str(f.key) || "Monitor finding",
    category: str(f.category) || "monitor",
    description: str(f.detail) || str(f.description) || "",
    evidence: [rest],
  };
}

// Deterministic graph id for an entity, matching the browser's dedupe key (type + lowercased
// name) but made stable so a stateless worker re-run reuses it. cyrb53 is base36 and fits the
// GraphDO id charset ([A-Za-z0-9_-]).
export function entId(type, name) { return "g" + cyrb53(str(type).toUpperCase() + ":" + str(name).trim().toLowerCase()); }
const relId = (fromId, rel, toId) => "r" + cyrb53(fromId + "|" + rel + "|" + toId);

// Build a GraphDO push body ({ entities, relationships }) for a monitor's findings.
//   monitorId, monitorName : identify the source ("monitor:<id>") and the dataset label.
//   current  : findings present on this run (written status "open").
//   removed  : findings gone since last run (written status "resolved", resolution "fixed").
//   graphMeta: { [finding.key]: { firstSeen, changedAt } } owned by the MonitorDO (ms).
//   nowMs    : this run's time, the fallback clock for anything missing from graphMeta.
// Entities carry stable deterministic ids and content-stable timestamps so an unchanged
// re-run is a byte-for-byte no-op at the DO. Never throws on well-formed input.
export function buildGraphWrite(monitorId, monitorName, current, removed, graphMeta, nowMs) {
  const source = "monitor:" + str(monitorId);
  const meta = graphMeta || {};
  const iso = (ms) => new Date(ms).toISOString();
  const nowIso = iso(nowMs);

  const commons = [];
  const tsByFk = new Map();     // findingKey -> { createdAt, updatedAt } (ISO)
  const tsByEnt = new Map();    // "TYPE:name" -> { created } (ms) for assets/controls
  // Assets/controls a monitor emits carry no mutable content (empty data, fixed name/type),
  // so we track only their first-seen time; their updatedAt is pinned to it (see below), which
  // keeps the DOMAIN/VULNERABILITY/CONTROL record stable even as a linked finding's day-count
  // changes daily — otherwise every day-boundary would churn the asset (needless DO rewrite +
  // audit-count inflation) for a record whose content never changed.
  const noteEnt = (k, created) => {
    const cur = tsByEnt.get(k);
    if (!cur || created < cur.created) tsByEnt.set(k, { created });
  };
  const addCommon = (f, status, resolution) => {
    const common = monitorFindingToCommon(f, status, resolution);
    const m = meta[f.key] || { firstSeen: nowMs, changedAt: nowMs };
    const fk = findingKey(source, common);
    tsByFk.set(fk, { createdAt: iso(m.firstSeen), updatedAt: iso(m.changedAt) });
    for (const a of (common.assets || [])) noteEnt(str(a.type).toUpperCase() + ":" + str(a.name).trim(), m.firstSeen);
    for (const c of (common.controls || [])) noteEnt("CONTROL:" + (str(c.framework) + " " + str(c.id)).trim(), m.firstSeen);
    commons.push(common);
  };
  for (const f of (current || [])) addCommon(f, "open", undefined);
  for (const f of (removed || [])) addCommon(f, "resolved", "fixed");

  const { items, links } = toEntities(source, commons, { dataset: str(monitorName) });

  const entities = items.map((it) => {
    const o = it.opts || {};
    let createdAt, updatedAt;
    if (it.type === "FINDING") {
      const t = tsByFk.get(it.data && it.data.findingKey) || { createdAt: nowIso, updatedAt: nowIso };
      createdAt = t.createdAt; updatedAt = t.updatedAt;
    } else {
      // Content-stable: updatedAt = createdAt (first-seen) so a finding's day-count drift never
      // rewrites a monitor-emitted asset/control whose own content is fixed.
      const t = tsByEnt.get(str(it.type).toUpperCase() + ":" + str(it.name).trim());
      createdAt = t ? iso(t.created) : nowIso;
      updatedAt = createdAt;
    }
    const e = { id: entId(it.type, it.name), type: it.type, name: it.name, data: it.data || {}, source, createdAt, updatedAt };
    if (o.severity) e.severity = o.severity;
    if (o.status) e.status = o.status;
    if (o.tags) e.tags = o.tags;
    return e;
  });

  const byId = new Map(entities.map((e) => [e.id, e]));
  const keyToId = (k) => { const i = k.indexOf(":"); return entId(k.slice(0, i), k.slice(i + 1)); };
  const relationships = links.map((l) => {
    const fromId = keyToId(l.from), toId = keyToId(l.to);
    // Stable createdAt (relationships merge by createdAt): use the FINDING endpoint's own
    // createdAt so a re-run is a tie, not a rewrite.
    const findingEnd = byId.get(fromId) && byId.get(fromId).type === "FINDING" ? byId.get(fromId) : byId.get(toId);
    const createdAt = (findingEnd && findingEnd.createdAt) || nowIso;
    return { id: relId(fromId, l.rel, toId), fromId, toId, type: l.rel, createdAt };
  });

  return { entities, relationships };
}
