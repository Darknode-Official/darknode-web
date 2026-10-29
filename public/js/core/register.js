// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Register store: a workspace-scoped local list of records (vendors, identities,
// exceptions, ...) mirrored into the Security Graph as entities, the same way
// incident-tracker.js mirrors incidents. Team workspaces rebuild the list from
// the synced graph (data._full is lossless) so every member sees one register.
// Pure by injection: storage + graph adapter + clock are parameters, so it runs
// in node; in a browser the graph adapter is loaded lazily from security-graph.js.

import { cyrb53 } from "./hash.js";
import { fitUnder } from "./sink-map.js";
import { toCsv } from "./export.js";
import { accountScope as acct } from "./account.js";

const ACTIVE_WS = "dn_active_ws";

/** Workspace-scoped storage key: a team gets `base__ws_<id>`; the personal workspace gets
 *  `base__<account>`, since localStorage is shared by every account that signs in on the
 *  browser. Data under the old unscoped `base` key is left in place and no longer read. */
export function wsKey(base, storage = globalThis.localStorage) {
  try { const w = storage.getItem(ACTIVE_WS); return w ? base + "__ws_" + w : base + "__" + acct(); } catch (_) { return base + "__" + acct(); }
}

/** True when a team workspace is active (dn_active_ws set). */
export function isTeam(storage = globalThis.localStorage) {
  try { return !!storage.getItem(ACTIVE_WS); } catch (_) { return false; }
}

const isObj = (v) => v != null && typeof v === "object" && !Array.isArray(v);

// Wrap security-graph.js's module API in the small adapter shape used here.
function wrapSecurityGraph(sg) {
  return {
    create: (type, name, data, opts) => sg.createEntity(type, name, data, opts),
    update: (id, updates) => sg.updateEntity(id, updates),
    remove: (id) => sg.deleteEntity(id),
    list: (type) => sg.listEntities({ type }),
    get: (id) => sg.getEntity(id),
  };
}

/**
 * Open a register.
 * schema = { key = "id", name: rec => string, severity?: rec => sev|null, status?: rec => status|null,
 *            summary?: rec => flat object, columns: [{ key, label }] }
 * graph adapter = { create(type, name, data, opts) → {id}, update(id, updates), remove(id), list(type) → [], get(id) }
 * @param {string} toolId
 * @param {string} entityType graph ENTITY_TYPE each record mirrors to
 * @param {{ schema?: object, storage?: Storage, graph?: object|null, now?: () => string }} [o]
 */
export function openRegister(toolId, entityType, { schema = {}, storage = globalThis.localStorage, graph = null, now = () => new Date().toISOString() } = {}) {
  const key = schema.key || "id";
  const nameOf = schema.name || ((r) => String(r.name || r.title || r[key] || ""));
  const KEY = () => wsKey("reg_" + toolId, storage);
  let g = graph;
  const ready = g ? Promise.resolve(g)
    : typeof window === "undefined" ? Promise.resolve(null)
      : import("/js/security-graph.js").then((sg) => (g = wrapSecurityGraph(sg))).catch(() => null);

  const loadLocal = () => { try { const v = JSON.parse(storage.getItem(KEY()) || "[]"); return Array.isArray(v) ? v : []; } catch (_) { return []; } };
  const saveLocal = (list) => { try { storage.setItem(KEY(), JSON.stringify(list)); } catch (_) {} };
  const stripGraphId = (rec) => { const c = { ...rec }; delete c.graphId; return c; };

  function list() {
    const local = loadLocal();
    if (!isTeam(storage) || !g) return local;
    try {
      const fromGraph = (g.list(entityType) || [])
        .filter((e) => e && e.source === toolId && e.data && e.data.registerId === toolId && e.data._full)
        .map((e) => ({ ...e.data._full, graphId: e.id }));
      const seen = new Set(fromGraph.map((r) => r[key]));
      return fromGraph.concat(local.filter((r) => !r.graphId && !seen.has(r[key])));
    } catch (_) { return local; }
  }

  function mirror(rec) {
    if (!g) return rec;
    try {
      const data = { ...(schema.summary ? schema.summary(rec) || {} : {}), registerId: toolId, _toolSource: toolId, _full: fitUnder(stripGraphId(rec)) };
      const severity = schema.severity ? schema.severity(rec) || null : null;
      const status = schema.status ? schema.status(rec) || null : null;
      const name = nameOf(rec);
      if (rec.graphId && g.get(rec.graphId)) g.update(rec.graphId, { name, data, severity, status });
      else { const e = g.create(entityType, name, data, { source: toolId, severity, status }); if (e && e.id) rec.graphId = e.id; }
    } catch (_) {}
    return rec;
  }

  function saveRec(rec) {
    const local = loadLocal();
    const i = local.findIndex((r) => r[key] === rec[key]);
    if (i >= 0) local[i] = rec; else local.push(rec);
    saveLocal(local);
  }

  function upsert(rec) {
    rec = { ...(rec || {}) };
    const existing = list().find((r) => rec[key] != null && r[key] === rec[key]);
    if (existing && !rec.graphId && existing.graphId) rec.graphId = existing.graphId;
    if (existing && !rec.createdAt && existing.createdAt) rec.createdAt = existing.createdAt;
    if (!rec[key]) rec[key] = "r-" + cyrb53(JSON.stringify(rec) + now());
    rec.updatedAt = now();
    rec.createdAt = rec.createdAt || rec.updatedAt;
    mirror(rec);
    saveRec(rec);
    return rec;
  }

  function get(id) { return list().find((r) => r[key] === id) || null; }

  function remove(id) {
    const rec = get(id);
    saveLocal(loadLocal().filter((r) => r[key] !== id));
    if (rec && rec.graphId && g) { try { g.remove(rec.graphId); } catch (_) {} }
    return !!rec;
  }

  function count() { return list().length; }

  function subscribe(fn) {
    if (typeof window === "undefined" || typeof document === "undefined") return () => {};
    const regKey = KEY();
    const onStorage = (ev) => { if (!ev.key || ev.key === regKey || ev.key.startsWith("dn_security_graph")) fn(list()); };
    const onSync = () => fn(list());
    window.addEventListener("storage", onStorage);
    document.addEventListener("secgraph:sync", onSync);
    return () => { window.removeEventListener("storage", onStorage); document.removeEventListener("secgraph:sync", onSync); };
  }

  /** Mirror any local record that has no graphId yet. Resolves with the count mirrored. */
  async function backfill() {
    await ready;
    if (!g) return 0;
    const local = loadLocal();
    let n = 0;
    for (const rec of local) if (!rec.graphId) { mirror(rec); if (rec.graphId) n++; }
    if (n) saveLocal(local);
    return n;
  }

  function exportCsv(cols) {
    const columns = cols || schema.columns || Object.keys(list()[0] || { [key]: "" }).map((k) => ({ key: k, label: k }));
    const defs = columns.map((c) => (typeof c === "string" ? { key: c, label: c } : c));
    const rows = list().map((r) => Object.fromEntries(defs.map((c) => [c.label, r[c.key]])));
    return toCsv(rows, defs.map((c) => c.label));
  }

  function exportJson() { return JSON.stringify(list().map(stripGraphId), null, 2) + "\n"; }

  function importJson(text) {
    let arr;
    try { arr = typeof text === "string" ? JSON.parse(text) : text; } catch (_) { throw new Error("Invalid JSON"); }
    if (!Array.isArray(arr)) throw new Error("Expected a JSON array of records");
    let added = 0, updated = 0, rejected = 0;
    for (const it of arr) {
      if (!isObj(it)) { rejected++; continue; }
      const rec = stripGraphId(it);
      const exists = rec[key] != null && !!get(rec[key]);
      upsert(rec);
      exists ? updated++ : added++;
    }
    return { added, updated, rejected };
  }

  return { list, get, upsert, remove, subscribe, count, exportCsv, exportJson, importJson, backfill, ready };
}
