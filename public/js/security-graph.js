// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved.
import { wins } from './core/graph-merge.js';
import { ruleAllows } from './core/relationship-rules.js';

// The graph is scoped to the active workspace (Phase B2). A user's PERSONAL workspace
// keeps the original, unprefixed key so existing graphs are preserved with zero
// migration; a team workspace gets its own namespaced store. Which workspace is active
// is a single shared pointer in localStorage (dn_active_ws), so every tool iframe and the
// Deck agree on the same store and switching propagates through storage events.
const STORAGE_KEY = 'dn_security_graph';   // the personal / legacy store
export const ACTIVE_WS_KEY = 'dn_active_ws';
export function storeKeyFor(wid) { return wid ? STORAGE_KEY + '__ws_' + wid : STORAGE_KEY; }
function _activeWid() { try { return localStorage.getItem(ACTIVE_WS_KEY) || null; } catch (_) { return null; } }
let _key = storeKeyFor(_activeWid());
export function activeWorkspaceId() { return _activeWid(); }

export const ENTITY_TYPES = [
  'ASSET', 'ENDPOINT', 'DOMAIN', 'IP', 'PORT', 'SERVICE', 'CERTIFICATE',
  'SOFTWARE', 'VULNERABILITY', 'INDICATOR', 'ALERT', 'EVENT', 'INCIDENT',
  'CASE', 'INVESTIGATION', 'EVIDENCE', 'THREAT_ACTOR', 'MALWARE', 'CAMPAIGN',
  'TECHNIQUE', 'FINDING', 'DETECTION', 'PLAYBOOK', 'CONTROL', 'REPORT',
  'IDENTITY', 'VENDOR'
];

export const RELATIONSHIP_TYPES = [
  'related_to', 'contains', 'affects', 'observed_in', 'attributed_to',
  'mitigates', 'exploits', 'targets', 'part_of', 'detected_by', 'evidence_for'
];

export const SEVERITIES = [null, 'info', 'low', 'medium', 'high', 'critical'];
export const STATUSES = [null, 'new', 'open', 'investigating', 'resolved', 'closed'];

let _entities = {};
let _relationships = {};
let _index = null;

function _uid() {
  return 'sg-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 10);
}

function _now() {
  return new Date().toISOString();
}

function _emit(name, detail) {
  try { document.dispatchEvent(new CustomEvent(name, { detail })); } catch (_) {}
}

// ---- IndexedDB durability backstop ------------------------------------------------
// localStorage stays the synchronous source of truth: instant reads, zero change to
// startup. IndexedDB is a larger, durable MIRROR written behind every save and read
// back on load. Each snapshot carries a `savedAt` stamp; on load, if the IDB snapshot
// is newer than what localStorage held (which only happens when a localStorage write
// was dropped on a full quota, or the browser evicted localStorage but kept IDB), its
// records are merged back into memory under the same last-writer-wins rule. Everything
// here is feature-detected and best-effort — if IndexedDB is missing or throws anywhere
// (private mode, old browser, Node tests), the graph behaves exactly as a
// localStorage-only store. The singleton URL is unchanged, so no ?v= bump is involved.
const IDB_NAME = 'dn-secgraph', IDB_STORE = 'snap';
const _hasIDB = (() => { try { return typeof indexedDB !== 'undefined' && !!indexedDB; } catch (_) { return false; } })();
let _idbPromise = null, _idbWriteTimer = null, _hydratedKey = null;
let _memSavedAt = 0, _lastSavedAt = 0;

function _idb() {
  if (_idbPromise) return _idbPromise;
  _idbPromise = new Promise((resolve) => {
    let req;
    try { req = indexedDB.open(IDB_NAME, 1); } catch (_) { resolve(null); return; }
    req.onupgradeneeded = () => { try { const db = req.result; if (!db.objectStoreNames.contains(IDB_STORE)) db.createObjectStore(IDB_STORE); } catch (_) {} };
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => resolve(null);
    req.onblocked = () => resolve(null);
  }).catch(() => null);
  return _idbPromise;
}
function _idbGet(key) {
  return _idb().then((db) => db && new Promise((resolve) => {
    try {
      const r = db.transaction(IDB_STORE, 'readonly').objectStore(IDB_STORE).get(key);
      r.onsuccess = () => resolve(r.result || null);
      r.onerror = () => resolve(null);
    } catch (_) { resolve(null); }
  })).catch(() => null);
}
function _idbPut(key, value) {
  return _idb().then((db) => db && new Promise((resolve) => {
    try {
      const tx = db.transaction(IDB_STORE, 'readwrite');
      tx.objectStore(IDB_STORE).put(value, key);
      tx.oncomplete = () => resolve(true);
      tx.onerror = () => resolve(false);
      tx.onabort = () => resolve(false);
    } catch (_) { resolve(false); }
  })).catch(() => false);
}
// Write the current in-memory snapshot to IDB, coalesced on a 400ms timer. Runs on save
// success AND on a quota failure (that is the whole point — the data survives even when
// localStorage cannot take it). Bails if the active store changed before the flush.
function _idbSchedulePut() {
  if (!_hasIDB || _idbWriteTimer) return;
  const key = _key;
  _idbWriteTimer = setTimeout(() => {
    _idbWriteTimer = null;
    if (key !== _key) return;
    _idbFlushNow(key);
  }, 400);
}
// Mirror the CURRENT in-memory snapshot to IDB immediately, stamped with the LIVE savedAt
// (never a value frozen when a debounce window opened). This is the key to recovery: a
// save that overflowed localStorage leaves localStorage holding an OLDER savedAt, so the
// IDB copy is always strictly newer and gets adopted on reload. Called by the debounce
// flush and, synchronously, before a workspace switch clears the old store from memory.
function _idbFlushNow(key) {
  if (!_hasIDB) return;
  if (_idbWriteTimer) { clearTimeout(_idbWriteTimer); _idbWriteTimer = null; }
  try { _idbPut(key, { entities: _entities, relationships: _relationships, savedAt: _lastSavedAt }); } catch (_) {}
}
// Recover from IDB only when its snapshot is STRICTLY newer than what localStorage gave
// us — i.e. a localStorage write was dropped on quota, or localStorage was evicted while
// IDB survived. In that case the IDB snapshot is the complete latest truth, so adopt its
// key-set WHOLESALE: this restores lost records AND applies deletions the newer snapshot
// omits (localStorage carries no tombstones). Equal/older IDB is ignored, so a normal load
// never resurrects a deleted record and never clobbers a just-saved local edit (that edit
// advanced savedAt, so the gate fails). savedAt is strictly monotonic (see _save), so even
// two writes in the same millisecond cannot collide on the gate.
function _idbHydrate() {
  if (!_hasIDB || _hydratedKey === _key) return;
  _hydratedKey = _key;
  const key = _key;
  _idbGet(key).then((snap) => {
    if (!snap || key !== _key || _index === null) return;
    if (!(Number(snap.savedAt) > _memSavedAt)) return;
    _entities = snap.entities || {};
    _relationships = snap.relationships || {};
    _memSavedAt = Number(snap.savedAt);
    _lastSavedAt = Math.max(_lastSavedAt, _memSavedAt);
    try { localStorage.setItem(key, JSON.stringify({ entities: _entities, relationships: _relationships, savedAt: _memSavedAt })); } catch (_) {}
    _emit('secgraph:sync', { recovered: true });
  }).catch(() => {});
}

function _load() {
  if (_index !== null) return;
  _memSavedAt = 0;
  try {
    const raw = localStorage.getItem(_key);
    if (raw) {
      const parsed = JSON.parse(raw);
      _entities = parsed.entities || {};
      _relationships = parsed.relationships || {};
      _memSavedAt = Number(parsed.savedAt) || 0;
    }
  } catch (_) {
    _entities = {};
    _relationships = {};
  }
  _index = true;
  _lastSavedAt = Math.max(_lastSavedAt, _memSavedAt); // keep the save stamp strictly ahead of what is persisted
  _idbHydrate(); // async: recover anything a full-quota localStorage write dropped
}

// The active workspace changed in another document (the Deck's switcher), or another tab
// or an embedded tool iframe wrote the current store: in either case drop the in-memory
// copy so the next read reloads from the right place. Otherwise this document keeps
// serving stale counts and its next save would overwrite the other document's entities.
try {
  window.addEventListener('storage', (e) => {
    if (e.key === ACTIVE_WS_KEY) { _refreshStore(); return; }
    if (e.key !== _key && e.key !== null) return;
    if (_batchDepth) return;
    _index = null; _entities = {}; _relationships = {}; _hydratedKey = null;
    _emit('secgraph:sync', {});
  });
} catch (_) {}

// Re-point the store at whatever workspace is now active. The document that writes
// dn_active_ws must call this itself (a storage event does not fire in the same document).
// Flushes the current store first (unless nothing was loaded, to avoid clobbering it).
function _refreshStore() {
  const next = storeKeyFor(_activeWid());
  if (next === _key) return false;
  if (_index !== null && !_batchDepth) { _save(); _idbFlushNow(_key); } // persist the OLD store to localStorage AND IDB before leaving it
  _key = next;
  _index = null; _entities = {}; _relationships = {}; _hydratedKey = null;
  _emit('secgraph:store-changed', { wid: _activeWid() });
  _emit('secgraph:sync', {});
  return true;
}
export function refreshStore() { return _refreshStore(); }

let _batchDepth = 0;
let _dirty = false;

let _saveFailed = false;
function _save() {
  if (_batchDepth) { _dirty = true; return; }
  _lastSavedAt = Math.max(Date.now(), _lastSavedAt + 1); // strictly monotonic: a later save always out-stamps an earlier one
  try {
    localStorage.setItem(_key, JSON.stringify({
      entities: _entities,
      relationships: _relationships,
      savedAt: _lastSavedAt
    }));
    _memSavedAt = _lastSavedAt;
    _saveFailed = false;
  } catch (e) {
    // localStorage is full. The write is NOT lost: the durable IndexedDB mirror below
    // still captures it (with this newer savedAt), and the next load merges it back.
    // Surface the quota problem once anyway, so the Deck can warn (dn:graph:savefail).
    if (!_saveFailed) {
      _saveFailed = true;
      try { console.warn('[security-graph] localStorage full — persisting to IndexedDB instead:', (e && e.message) || e); } catch (_) {}
      try { window.dispatchEvent(new CustomEvent('dn:graph:savefail', { detail: String((e && e.message) || e) })); } catch (_) {}
    }
  }
  _idbSchedulePut(); // durable mirror — written on save success AND on quota failure
}
// True while the last persist succeeded; false after a quota/write failure.
export function saveHealthy() { return !_saveFailed; }

export function createEntity(type, name, data, opts) {
  _load();
  if (!ENTITY_TYPES.includes(type)) return null;
  const o = opts || {};
  const entity = {
    id: _uid(),
    type,
    name: String(name || ''),
    data: data || {},
    tags: Array.isArray(o.tags) ? o.tags : [],
    severity: SEVERITIES.includes(o.severity) ? o.severity : null,
    status: STATUSES.includes(o.status) ? o.status : 'new',
    source: o.source || 'manual',
    createdAt: _now(),
    updatedAt: _now()
  };
  _entities[entity.id] = entity;
  _save();
  _emit('secgraph:entity:created', { entity });
  return entity;
}

// Run many writes with a single localStorage save at the end.
export function batch(fn) {
  _load();
  _batchDepth++;
  try { return fn(); }
  finally {
    _batchDepth--;
    if (!_batchDepth && _dirty) { _dirty = false; _save(); }
  }
}

// Unsorted exact lookup by type + case-insensitive name (used for upserts).
export function findEntity(type, name) {
  _load();
  const key = String(name || '').trim().toLowerCase();
  for (const id in _entities) {
    const e = _entities[id];
    if (e.type === type && e.name.toLowerCase() === key) return e;
  }
  return null;
}

export function getEntity(id) {
  _load();
  return _entities[id] || null;
}

export function updateEntity(id, updates) {
  _load();
  const entity = _entities[id];
  if (!entity) return null;
  const changes = {};
  const allowed = ['name', 'data', 'tags', 'severity', 'status', 'source'];
  for (const key of allowed) {
    if (key in updates && updates[key] !== entity[key]) {
      changes[key] = { from: entity[key], to: updates[key] };
      if (key === 'data') {
        entity.data = { ...entity.data, ...updates.data };
      } else if (key === 'severity' && !SEVERITIES.includes(updates.severity)) {
        continue;
      } else if (key === 'status' && !STATUSES.includes(updates.status)) {
        continue;
      } else {
        entity[key] = updates[key];
      }
    }
  }
  if (Object.keys(changes).length === 0) return entity;
  entity.updatedAt = _now();
  _save();
  _emit('secgraph:entity:updated', { entity, changes });
  return entity;
}

export function deleteEntity(id) {
  _load();
  if (!_entities[id]) return false;
  delete _entities[id];
  const relIds = Object.keys(_relationships).filter(
    rid => _relationships[rid].fromId === id || _relationships[rid].toId === id
  );
  for (const rid of relIds) delete _relationships[rid];
  _save();
  _emit('secgraph:entity:deleted', { id });
  return true;
}

function _matchesSearch(entity, terms) {
  const haystack = [
    entity.name,
    entity.type,
    entity.source,
    ...(entity.tags || []),
    ...Object.values(entity.data || {}).filter(v => typeof v === 'string')
  ].join(' ').toLowerCase();

  for (const term of terms) {
    if (!haystack.includes(term)) return false;
  }
  return true;
}

function _fuzzyScore(hay, needle) {
  hay = hay.toLowerCase();
  needle = needle.toLowerCase();
  if (!needle) return 0;
  let hi = 0, score = 0, streak = 0;
  for (const ch of needle) {
    const idx = hay.indexOf(ch, hi);
    if (idx < 0) return -1;
    if (idx === 0 || /[\s._\-/]/.test(hay[idx - 1] || '')) score += 4;
    if (idx === hi) { streak++; score += streak; } else streak = 0;
    score += 1;
    hi = idx + 1;
  }
  return score + Math.max(0, 12 - hi);
}

export function listEntities(filter) {
  _load();
  let results = Object.values(_entities);
  if (typeof filter === 'string') filter = { type: filter };
  if (!filter) {
    results.sort((a, b) => (b.updatedAt || '').localeCompare(a.updatedAt || ''));
    return results;
  }

  if (filter.type) {
    const types = Array.isArray(filter.type) ? filter.type : [filter.type];
    results = results.filter(e => types.includes(e.type));
  }

  if (filter.severity) {
    results = results.filter(e => e.severity === filter.severity);
  }

  if (filter.status) {
    results = results.filter(e => e.status === filter.status);
  }

  if (filter.tags && filter.tags.length) {
    const fTags = filter.tags.map(t => t.toLowerCase());
    results = results.filter(e =>
      (e.tags || []).some(t => fTags.includes(t.toLowerCase()))
    );
  }

  if (filter.search) {
    const terms = filter.search.toLowerCase().split(/\s+/).filter(Boolean);
    if (terms.length) {
      results = results.filter(e => _matchesSearch(e, terms));
    }
  }

  const sortBy = filter.sortBy || 'updatedAt';
  const sortDir = filter.sortDir === 'asc' ? 1 : -1;
  results.sort((a, b) => {
    const va = a[sortBy] || '';
    const vb = b[sortBy] || '';
    if (va < vb) return -sortDir;
    if (va > vb) return sortDir;
    return 0;
  });

  const offset = filter.offset || 0;
  const limit = filter.limit || results.length;
  return results.slice(offset, offset + limit);
}

let _droppedLinks = 0, _droppedLogged = false;

export function createRelationship(fromId, toId, type) {
  _load();
  if (!_entities[fromId] || !_entities[toId]) return null;
  if (!RELATIONSHIP_TYPES.includes(type)) return null;
  // Typed graph: a link whose (fromType, rel, toType) breaks RELATIONSHIP_RULES is
  // dropped and counted (getStats().droppedLinks) instead of stored.
  const fromType = _entities[fromId].type, toType = _entities[toId].type;
  if (!ruleAllows(type, fromType, toType)) {
    _droppedLinks++;
    if (!_droppedLogged) { _droppedLogged = true; try { console.debug('[security-graph] dropped invalid link', fromType, type, toType); } catch (_) {} }
    return null;
  }
  const existing = Object.values(_relationships).find(
    r => r.fromId === fromId && r.toId === toId && r.type === type
  );
  if (existing) return existing;
  const rel = {
    id: _uid(),
    fromId,
    toId,
    type,
    createdAt: _now()
  };
  _relationships[rel.id] = rel;
  _save();
  _emit('secgraph:relationship:created', { relationship: rel });
  return rel;
}

export function getRelationships(entityId) {
  _load();
  return Object.values(_relationships).filter(
    r => r.fromId === entityId || r.toId === entityId
  );
}

export function deleteRelationship(id) {
  _load();
  if (!_relationships[id]) return false;
  delete _relationships[id];
  _save();
  return true;
}

export function getRelated(entityId, opts) {
  _load();
  const o = opts || {};
  const depth = Math.min(o.depth || 1, 3);
  // Mark nodes visited when they are discovered (enqueued), not when dequeued.
  // The previous version only added a node to `visited` when it was processed
  // as a frontier, so the final frontier — the nodes at the maximum requested
  // distance — was never recorded, making getRelated() return neighbors only
  // up to distance depth-1. With the default depth=1 that meant an empty result
  // even when direct relationships existed.
  const visited = new Set([entityId]);
  let frontier = [entityId];

  for (let d = 0; d < depth; d++) {
    const nextFrontier = [];
    for (const eid of frontier) {
      const rels = Object.values(_relationships).filter(r => {
        if (o.relType && r.type !== o.relType) return false;
        return r.fromId === eid || r.toId === eid;
      });
      for (const rel of rels) {
        const otherId = rel.fromId === eid ? rel.toId : rel.fromId;
        if (!visited.has(otherId)) { visited.add(otherId); nextFrontier.push(otherId); }
      }
    }
    frontier = nextFrontier;
  }

  visited.delete(entityId);
  let related = [...visited].map(id => _entities[id]).filter(Boolean);

  if (o.type) {
    const types = Array.isArray(o.type) ? o.type : [o.type];
    related = related.filter(e => types.includes(e.type));
  }

  return related;
}

export function search(query, opts) {
  _load();
  if (!query || !query.trim()) return [];
  const o = opts || {};
  const needle = query.trim().toLowerCase();
  const all = Object.values(_entities);

  const scored = [];
  for (const entity of all) {
    if (o.type) {
      const types = Array.isArray(o.type) ? o.type : [o.type];
      if (!types.includes(entity.type)) continue;
    }

    let bestScore = _fuzzyScore(entity.name, needle);

    for (const tag of (entity.tags || [])) {
      const ts = _fuzzyScore(tag, needle);
      if (ts > bestScore) bestScore = ts;
    }

    const dataVals = Object.values(entity.data || {}).filter(v => typeof v === 'string');
    for (const val of dataVals) {
      const vs = _fuzzyScore(val, needle);
      if (vs > bestScore) bestScore = vs;
    }

    if (entity.name.toLowerCase().includes(needle)) {
      bestScore = Math.max(bestScore, needle.length * 3);
    }

    if (bestScore > 0) {
      scored.push({ entity, score: bestScore });
    }
  }

  scored.sort((a, b) => b.score - a.score);
  const limit = o.limit || 50;
  return scored.slice(0, limit).map(s => s.entity);
}

export function importEntities(items) {
  _load();
  if (!Array.isArray(items)) return;
  for (const item of items) {
    if (!item.type || !ENTITY_TYPES.includes(item.type)) continue;
    const entity = {
      id: item.id || _uid(),
      type: item.type,
      name: String(item.name || ''),
      data: item.data || {},
      tags: Array.isArray(item.tags) ? item.tags : [],
      severity: SEVERITIES.includes(item.severity) ? item.severity : null,
      status: STATUSES.includes(item.status) ? item.status : 'new',
      source: item.source || 'import',
      createdAt: item.createdAt || _now(),
      updatedAt: item.updatedAt || _now()
    };
    _entities[entity.id] = entity;
  }
  _save();
}

export function exportAll() {
  _load();
  return {
    entities: Object.values(_entities),
    relationships: Object.values(_relationships),
    exportedAt: _now()
  };
}

// Apply remote records from the cloud sync (graph-sync.js) into the local graph under
// last-writer-wins, using the shared pure rule (core/graph-merge.js). A remote record
// only replaces the local one when it is strictly newer; a winning tombstone
// ({ id, deleted:true, updatedAt }) removes the local record (an entity cascades to its
// relationships, mirroring deleteEntity). This deliberately emits only 'secgraph:sync',
// never :created/:updated/:deleted, so the sync layer does not mistake an incoming change
// for a fresh local edit and push it straight back — that would be an endless loop.
export function applyRemote(remote) {
  _load();
  let changed = 0;
  for (const rec of (remote && remote.entities) || []) {
    if (!rec || typeof rec.id !== 'string' || !rec.id) continue;
    const cur = _entities[rec.id];
    if (!wins(rec, cur, 'updatedAt')) continue;
    if (rec.deleted) {
      if (!cur) continue;
      delete _entities[rec.id];
      for (const rid in _relationships) {
        if (_relationships[rid].fromId === rec.id || _relationships[rid].toId === rec.id) delete _relationships[rid];
      }
    } else {
      _entities[rec.id] = {
        id: rec.id, type: rec.type, name: String(rec.name || ''), data: rec.data || {},
        tags: Array.isArray(rec.tags) ? rec.tags : [],
        severity: SEVERITIES.includes(rec.severity) ? rec.severity : null,
        status: STATUSES.includes(rec.status) ? rec.status : 'new',
        source: rec.source || 'sync', createdAt: rec.createdAt || _now(), updatedAt: rec.updatedAt || _now()
      };
    }
    changed++;
  }
  for (const rec of (remote && remote.relationships) || []) {
    if (!rec || typeof rec.id !== 'string' || !rec.id) continue;
    const cur = _relationships[rec.id];
    if (!wins(rec, cur, 'createdAt')) continue;
    if (rec.deleted) {
      if (!cur) continue;
      delete _relationships[rec.id];
    } else if (_entities[rec.fromId] && _entities[rec.toId] && RELATIONSHIP_TYPES.includes(rec.type)) {
      _relationships[rec.id] = { id: rec.id, fromId: rec.fromId, toId: rec.toId, type: rec.type, createdAt: rec.createdAt || _now() };
    } else {
      continue;
    }
    changed++;
  }
  if (changed) { _save(); _emit('secgraph:sync', { remote: true }); }
  return changed;
}

export function clearAll() {
  _entities = {};
  _relationships = {};
  _index = true;
  _save();
}

export function getStats() {
  _load();
  const entities = Object.values(_entities);
  const byType = {};
  const byStatus = {};
  const bySeverity = {};

  for (const e of entities) {
    byType[e.type] = (byType[e.type] || 0) + 1;
    const st = e.status || 'none';
    byStatus[st] = (byStatus[st] || 0) + 1;
    const sv = e.severity || 'none';
    bySeverity[sv] = (bySeverity[sv] || 0) + 1;
  }

  return {
    totalEntities: entities.length,
    totalRelationships: Object.keys(_relationships).length,
    droppedLinks: _droppedLinks,
    byType,
    byStatus,
    bySeverity
  };
}

export function getEntityTypeLabel(type) {
  const labels = {
    ASSET: 'Asset', ENDPOINT: 'Endpoint', DOMAIN: 'Domain', IP: 'IP Address',
    PORT: 'Port', SERVICE: 'Service', CERTIFICATE: 'Certificate',
    SOFTWARE: 'Software', VULNERABILITY: 'Vulnerability', INDICATOR: 'Indicator',
    ALERT: 'Alert', EVENT: 'Event', INCIDENT: 'Incident', CASE: 'Case',
    INVESTIGATION: 'Investigation', EVIDENCE: 'Evidence',
    THREAT_ACTOR: 'Threat Actor', MALWARE: 'Malware', CAMPAIGN: 'Campaign',
    TECHNIQUE: 'Technique', FINDING: 'Finding', DETECTION: 'Detection',
    PLAYBOOK: 'Playbook', CONTROL: 'Control', REPORT: 'Report',
    IDENTITY: 'Identity', VENDOR: 'Vendor'
  };
  return labels[type] || type;
}

export function getSeverityColor(severity) {
  const colors = {
    info: '#3b82f6',
    low: '#22c55e',
    medium: '#f59e0b',
    high: '#f97316',
    critical: '#ef4444'
  };
  return colors[severity] || '#71717a';
}

export function getStatusColor(status) {
  const colors = {
    new: '#3b82f6',
    open: '#f59e0b',
    investigating: '#a855f7',
    resolved: '#22c55e',
    closed: '#71717a'
  };
  return colors[status] || '#71717a';
}
