// Copyright (c) 2026 Darknode-Official. All rights reserved.
const STORAGE_KEY = 'dn_security_graph';

export const ENTITY_TYPES = [
  'ASSET', 'ENDPOINT', 'DOMAIN', 'IP', 'PORT', 'SERVICE', 'CERTIFICATE',
  'SOFTWARE', 'VULNERABILITY', 'INDICATOR', 'ALERT', 'EVENT', 'INCIDENT',
  'CASE', 'INVESTIGATION', 'EVIDENCE', 'THREAT_ACTOR', 'MALWARE', 'CAMPAIGN',
  'TECHNIQUE', 'FINDING', 'DETECTION', 'PLAYBOOK', 'CONTROL', 'REPORT'
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

function _load() {
  if (_index !== null) return;
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      _entities = parsed.entities || {};
      _relationships = parsed.relationships || {};
    }
  } catch (_) {
    _entities = {};
    _relationships = {};
  }
  _index = true;
}

let _batchDepth = 0;
let _dirty = false;

function _save() {
  if (_batchDepth) { _dirty = true; return; }
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
      entities: _entities,
      relationships: _relationships
    }));
  } catch (_) {}
}

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

export function createRelationship(fromId, toId, type) {
  _load();
  if (!_entities[fromId] || !_entities[toId]) return null;
  if (!RELATIONSHIP_TYPES.includes(type)) return null;
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
    PLAYBOOK: 'Playbook', CONTROL: 'Control', REPORT: 'Report'
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
