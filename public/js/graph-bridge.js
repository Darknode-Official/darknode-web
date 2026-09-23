// Copyright (c) 2026 Darknode-Official. All rights reserved.
import * as SG from '/js/security-graph.js';
const { createEntity, getEntity, updateEntity, listEntities, createRelationship } = SG;
// Namespace access so a browser still holding an older cached security-graph.js
// (without batch/findEntity) degrades to slower writes instead of failing to load.
const batch = SG.batch || ((fn) => fn());
const findEntity = SG.findEntity || ((type, key) => listEntities({ type }).find(e => e.name.toLowerCase() === key) || null);
import { getActiveContext } from '/js/context-bar.js';

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const TYPE_COLORS = {
  ASSET: '#2563eb', ENDPOINT: '#0284c7', DOMAIN: '#06b6d4', IP: '#10b981',
  PORT: '#64748b', SERVICE: '#0d9488', CERTIFICATE: '#0e7490', SOFTWARE: '#7c3aed',
  VULNERABILITY: '#ef4444', INDICATOR: '#f59e0b', ALERT: '#ea580c', EVENT: '#6366f1',
  INCIDENT: '#dc2626', CASE: '#2563eb', INVESTIGATION: '#8b5cf6', EVIDENCE: '#0891b2',
  THREAT_ACTOR: '#7c3aed', MALWARE: '#e11d48', CAMPAIGN: '#d97706', TECHNIQUE: '#9333ea',
  FINDING: '#8b5cf6', DETECTION: '#059669', PLAYBOOK: '#b45309', CONTROL: '#15803d',
  REPORT: '#4f46e5',
};

export function addToGraph(type, name, data, opts) {
  const entity = createEntity(type, name, data, opts);
  _trackActivity('Created ' + type + ': ' + name);
  return entity;
}

export function addToolResult(toolName, resultType, name, data, opts) {
  return addToGraph(resultType, name, {
    ...data,
    _toolSource: toolName,
  }, { source: toolName, ...(opts || {}) });
}

// Find-or-create by type + case-insensitive name so repeat tool runs merge instead of duplicating.
export function upsertToolResult(toolName, type, name, data, opts) {
  const key = String(name || '').trim().toLowerCase();
  if (!key) return { entity: null, created: false };
  const existing = findEntity(type, key);
  if (existing) {
    const o = opts || {};
    const tags = Array.from(new Set([...(existing.tags || []), ...(o.tags || [])]));
    const updates = { data: { ...(data || {}), _toolSource: toolName }, tags };
    if (o.severity) updates.severity = o.severity;
    return { entity: updateEntity(existing.id, updates), created: false };
  }
  return { entity: addToolResult(toolName, type, String(name).trim(), data, opts), created: true };
}

// items: [{ type, name, data?, opts? }]. Returns { created, updated, entities }.
// With no linkTo, results attach to the active investigation/case/incident from the context bar.
export function sendToGraph(toolName, items, linkTo, quiet) {
  let created = 0, updated = 0;
  let ctxName = '';
  if (linkTo === undefined) {
    const ctx = getActiveContext();
    if (ctx && ['INVESTIGATION', 'CASE', 'INCIDENT'].includes(ctx.type)) { linkTo = ctx.id; ctxName = ctx.name; }
  }
  const entities = [];
  batch(() => {
    for (const it of items || []) {
      const r = upsertToolResult(toolName, it.type, it.name, it.data, it.opts);
      if (!r.entity) continue;
      r.created ? created++ : updated++;
      entities.push(r.entity);
      if (linkTo) createRelationship(linkTo, r.entity.id, 'contains');
    }
  });
  if (quiet) return { created, updated, entities };
  if (created || updated) _showToast('Security Graph: ' + created + ' added, ' + updated + ' updated' + (ctxName ? ' (linked to ' + ctxName + ')' : ''));
  else _showToast('Nothing to send to Security Graph');
  return { created, updated, entities };
}

// Group several sendToGraph/linkEntities calls into one storage write.
export function batchGraph(fn) { return batch(fn); }

export function linkEntities(fromId, toId, relType) {
  return createRelationship(fromId, toId, relType || 'related_to');
}

export function openEntityModal(entity) {
  if (!entity) return;
  const existing = document.getElementById('sg-entity-modal');
  if (existing) existing.remove();

  const color = TYPE_COLORS[entity.type] || '#64748b';
  const dataEntries = entity.data ? Object.entries(entity.data).filter(([k]) => !k.startsWith('_')) : [];

  const modal = document.createElement('div');
  modal.id = 'sg-entity-modal';
  modal.className = 'sg-modal-overlay';
  modal.innerHTML = `
    <style>
      .sg-modal-overlay{position:fixed;inset:0;z-index:10000;background:rgba(0,0,0,.5);display:flex;align-items:center;justify-content:center;padding:20px}
      .sg-modal-box{background:var(--card-bg,#fff);border-radius:12px;max-width:560px;width:100%;max-height:80vh;overflow-y:auto;box-shadow:0 20px 60px rgba(0,0,0,.3);border:1px solid var(--brd,#e2e8f0)}
      .sg-modal-head{padding:20px 24px 16px;border-bottom:1px solid var(--brd,#e2e8f0);display:flex;align-items:center;gap:10px}
      .sg-modal-type{padding:2px 10px;border-radius:4px;color:#fff;font-size:.7rem;font-weight:700;letter-spacing:.04em}
      .sg-modal-title{font-size:1.1rem;font-weight:700;color:var(--txt,#0f172a);flex:1}
      .sg-modal-close{background:none;border:none;font-size:1.2rem;cursor:pointer;color:var(--mut,#64748b);padding:4px 8px}
      .sg-modal-close:hover{color:var(--txt,#0f172a)}
      .sg-modal-body{padding:16px 24px 20px}
      .sg-modal-meta{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px}
      .sg-modal-badge{padding:2px 8px;border-radius:4px;font-size:.72rem;font-weight:600;background:var(--bg-2,#f1f5f9);color:var(--mut,#64748b)}
      .sg-modal-data{border-top:1px solid var(--brd,#e2e8f0);padding-top:12px}
      .sg-modal-row{display:flex;gap:8px;padding:4px 0;font-size:.82rem;border-bottom:1px solid var(--brd-light,#f1f5f9)}
      .sg-modal-key{font-weight:600;color:var(--mut,#64748b);min-width:120px;flex-shrink:0}
      .sg-modal-val{color:var(--txt,#0f172a);word-break:break-all}
      .sg-modal-actions{display:flex;gap:8px;margin-top:16px;padding-top:12px;border-top:1px solid var(--brd,#e2e8f0)}
      .sg-modal-btn{padding:6px 16px;border-radius:6px;font-size:.82rem;font-weight:600;cursor:pointer;border:1px solid var(--brd,#e2e8f0);background:var(--bg-2,#f1f5f9);color:var(--txt,#0f172a)}
      .sg-modal-btn:hover{background:var(--acc,#2563eb);color:#fff;border-color:var(--acc,#2563eb)}
      .sg-modal-btn.primary{background:var(--acc,#2563eb);color:#fff;border-color:var(--acc,#2563eb)}
      .sg-modal-btn.primary:hover{opacity:.9}
    </style>
    <div class="sg-modal-box">
      <div class="sg-modal-head">
        <span class="sg-modal-type" style="background:${color}">${esc(entity.type)}</span>
        <span class="sg-modal-title">${esc(entity.name)}</span>
        <button class="sg-modal-close" title="Close">&times;</button>
      </div>
      <div class="sg-modal-body">
        <div class="sg-modal-meta">
          ${entity.severity ? `<span class="sg-modal-badge">${esc(entity.severity.toUpperCase())}</span>` : ''}
          ${entity.status ? `<span class="sg-modal-badge">${esc(entity.status)}</span>` : ''}
          ${entity.source ? `<span class="sg-modal-badge">Source: ${esc(entity.source)}</span>` : ''}
          ${(entity.tags || []).map(t => `<span class="sg-modal-badge">${esc(t)}</span>`).join('')}
        </div>
        ${dataEntries.length ? `
          <div class="sg-modal-data">
            ${dataEntries.map(([k, v]) => `
              <div class="sg-modal-row">
                <span class="sg-modal-key">${esc(k)}</span>
                <span class="sg-modal-val">${esc(typeof v === 'object' ? JSON.stringify(v) : String(v))}</span>
              </div>
            `).join('')}
          </div>
        ` : ''}
        <div class="sg-modal-actions">
          <button class="sg-modal-btn primary" id="sg-add-to-inv">Add to Investigation</button>
          <button class="sg-modal-btn" id="sg-copy-entity">Copy JSON</button>
        </div>
      </div>
    </div>`;

  document.body.appendChild(modal);

  modal.querySelector('.sg-modal-close').onclick = () => modal.remove();
  modal.onclick = (e) => { if (e.target === modal) modal.remove(); };

  modal.querySelector('#sg-copy-entity').onclick = () => {
    navigator.clipboard?.writeText(JSON.stringify(entity, null, 2)).then(() => {
      const btn = modal.querySelector('#sg-copy-entity');
      btn.textContent = 'Copied';
      setTimeout(() => btn.textContent = 'Copy JSON', 1200);
    });
  };

  modal.querySelector('#sg-add-to-inv').onclick = () => {
    modal.remove();
    openAddToInvestigationModal(entity);
  };
}

export function openAddToInvestigationModal(entity) {
  const existing = document.getElementById('sg-inv-modal');
  if (existing) existing.remove();

  const investigations = listEntities({ type: 'INVESTIGATION' });

  const modal = document.createElement('div');
  modal.id = 'sg-inv-modal';
  modal.className = 'sg-modal-overlay';
  modal.innerHTML = `
    <style>
      .sg-inv-box{background:var(--card-bg,#fff);border-radius:12px;max-width:480px;width:100%;max-height:70vh;overflow-y:auto;box-shadow:0 20px 60px rgba(0,0,0,.3);border:1px solid var(--brd,#e2e8f0)}
      .sg-inv-head{padding:16px 20px;border-bottom:1px solid var(--brd,#e2e8f0);font-weight:700;font-size:.95rem;color:var(--txt,#0f172a)}
      .sg-inv-list{padding:8px 12px}
      .sg-inv-item{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:8px;cursor:pointer;transition:background .15s}
      .sg-inv-item:hover{background:var(--bg-2,#f1f5f9)}
      .sg-inv-name{flex:1;font-weight:600;font-size:.88rem;color:var(--txt,#0f172a)}
      .sg-inv-date{font-size:.72rem;color:var(--mut,#64748b)}
      .sg-inv-add{padding:4px 14px;border-radius:6px;font-size:.78rem;font-weight:600;cursor:pointer;border:1px solid var(--acc,#2563eb);background:var(--acc,#2563eb);color:#fff}
      .sg-inv-add:hover{opacity:.85}
      .sg-inv-new{margin:8px 12px 12px;padding:10px 16px;border-radius:8px;font-size:.86rem;font-weight:600;cursor:pointer;border:1px dashed var(--brd,#e2e8f0);background:none;color:var(--acc,#2563eb);width:calc(100% - 24px);text-align:center}
      .sg-inv-new:hover{background:var(--bg-2,#f1f5f9)}
      .sg-inv-empty{padding:20px;text-align:center;color:var(--mut,#64748b);font-size:.86rem}
    </style>
    <div class="sg-inv-box">
      <div class="sg-inv-head">Add "${esc(entity.name)}" to Investigation</div>
      <div class="sg-inv-list">
        ${investigations.length === 0 ? `<div class="sg-inv-empty">No investigations yet</div>` :
          investigations.map(inv => `
            <div class="sg-inv-item" data-inv-id="${esc(inv.id)}">
              <span class="sg-inv-name">${esc(inv.name)}</span>
              <span class="sg-inv-date">${new Date(inv.updatedAt).toLocaleDateString()}</span>
              <button class="sg-inv-add">Add</button>
            </div>
          `).join('')}
      </div>
      <button class="sg-inv-new" id="sg-create-inv">+ New Investigation</button>
    </div>`;

  document.body.appendChild(modal);
  modal.onclick = (e) => { if (e.target === modal) modal.remove(); };

  modal.querySelectorAll('.sg-inv-item').forEach(item => {
    item.querySelector('.sg-inv-add').onclick = (e) => {
      e.stopPropagation();
      const invId = item.dataset.invId;
      createRelationship(invId, entity.id, 'contains');
      _showToast('Added to investigation');
      modal.remove();
    };
  });

  modal.querySelector('#sg-create-inv').onclick = () => {
    const name = prompt('Investigation name:');
    if (!name) return;
    const inv = createEntity('INVESTIGATION', name.trim(), {
      description: '',
      notes: [],
    }, { status: 'new' });
    createRelationship(inv.id, entity.id, 'contains');
    _showToast('Created investigation and added entity');
    modal.remove();
  };
}

function _trackActivity(text) {
  try {
    const KEY = 'dn_recent_activity';
    let items = JSON.parse(localStorage.getItem(KEY) || '[]');
    items.unshift({ text, ts: Date.now() });
    items = items.slice(0, 20);
    localStorage.setItem(KEY, JSON.stringify(items));
  } catch (_) {}
}

export function showGraphToast(msg) { _showToast(msg); }

function _showToast(msg) {
  const t = document.createElement('div');
  t.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);padding:10px 24px;background:#1e293b;color:#f8fafc;border-radius:8px;font-size:.84rem;font-weight:500;z-index:100000;box-shadow:0 4px 12px rgba(0,0,0,.3);transition:opacity .3s';
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; setTimeout(() => t.remove(), 300); }, 2200);
}
