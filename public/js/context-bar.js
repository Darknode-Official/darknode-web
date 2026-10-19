// Copyright (c) 2026 Darknode-Official. All rights reserved.
import { listEntities, getEntity, getRelated, getStats, ENTITY_TYPES } from '/js/security-graph.js';

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const CTX_KEY = 'dn_active_context';

const TYPE_COLORS = {
  INVESTIGATION: '#8b5cf6', INCIDENT: '#dc2626', CASE: '#2563eb',
  ASSET: '#2563eb', VULNERABILITY: '#ef4444', INDICATOR: '#f59e0b',
  FINDING: '#8b5cf6', DOMAIN: '#06b6d4', IP: '#10b981',
  MALWARE: '#e11d48', THREAT_ACTOR: '#7c3aed', CAMPAIGN: '#d97706',
  EVENT: '#6366f1', EVIDENCE: '#0891b2', ALERT: '#ea580c',
  DETECTION: '#059669', REPORT: '#4f46e5', TECHNIQUE: '#9333ea',
  ENDPOINT: '#0284c7', SERVICE: '#0d9488', SOFTWARE: '#7c3aed',
  CERTIFICATE: '#0e7490', PORT: '#64748b', CONTROL: '#15803d',
  PLAYBOOK: '#b45309',
};

let _activeContextId = null;
let _barEl = null;
let _appShow = null;

function _load() {
  try { return localStorage.getItem(CTX_KEY) || null; } catch (_) { return null; }
}

function _save(id) {
  try {
    if (id) localStorage.setItem(CTX_KEY, id);
    else localStorage.removeItem(CTX_KEY);
  } catch (_) {}
}

export function setActiveContext(entityId) {
  _activeContextId = entityId;
  _save(entityId);
  _render();
  document.dispatchEvent(new CustomEvent('darknode:context', { detail: { entityId } }));
}

export function getActiveContext() {
  if (!_activeContextId) _activeContextId = _load();
  if (_activeContextId) {
    const e = getEntity(_activeContextId);
    if (!e) { _activeContextId = null; _save(null); return null; }
    return e;
  }
  return null;
}

export function clearContext() {
  _activeContextId = null;
  _save(null);
  _render();
  document.dispatchEvent(new CustomEvent('darknode:context', { detail: { entityId: null } }));
}

export function initContextBar(containerSelector, showFn) {
  _appShow = showFn;
  const container = document.querySelector(containerSelector);
  if (!container) return;

  _barEl = document.createElement('div');
  _barEl.id = 'ctx-bar';
  _barEl.className = 'ctx-bar';
  container.insertBefore(_barEl, container.firstChild);

  _activeContextId = _load();
  _render();

  document.addEventListener('secgraph:entity:updated', () => _render());
  document.addEventListener('secgraph:entity:deleted', (e) => {
    if (e.detail && e.detail.id === _activeContextId) clearContext();
  });
}

function _render() {
  if (!_barEl) return;
  const ctx = getActiveContext();
  if (!ctx) {
    _barEl.style.display = 'none';
    _barEl.innerHTML = '';
    return;
  }

  const color = TYPE_COLORS[ctx.type] || '#64748b';
  const related = getRelated(ctx.id);
  const stats = { entities: related.length };

  _barEl.style.display = '';
  _barEl.innerHTML = `
    <div class="ctx-bar-inner">
      <span class="ctx-bar-label">ACTIVE CONTEXT</span>
      <span class="ctx-bar-type" style="background:${color}">${esc(ctx.type)}</span>
      <span class="ctx-bar-name">${esc(ctx.name)}</span>
      ${ctx.severity ? `<span class="ctx-bar-sev ctx-sev-${ctx.severity}">${esc(ctx.severity.toUpperCase())}</span>` : ''}
      ${ctx.status ? `<span class="ctx-bar-status">${esc(ctx.status)}</span>` : ''}
      <span class="ctx-bar-count">${stats.entities} related</span>
      <button class="ctx-bar-open" title="Open investigation">Open</button>
      <button class="ctx-bar-clear" title="Clear context">x</button>
    </div>`;

  _barEl.querySelector('.ctx-bar-open').onclick = () => {
    if (_appShow && (ctx.type === 'INVESTIGATION' || ctx.type === 'CASE' || ctx.type === 'INCIDENT')) {
      _appShow('investigation');
    }
  };
  _barEl.querySelector('.ctx-bar-clear').onclick = clearContext;
  _barEl.querySelector('.ctx-bar-name').onclick = () => {
    if (_appShow && (ctx.type === 'INVESTIGATION' || ctx.type === 'CASE' || ctx.type === 'INCIDENT')) {
      _appShow('investigation');
    }
  };
}

export function getContextBarCSS() {
  return `
.ctx-bar{display:none;position:sticky;top:0;z-index:90;padding:0;margin:0 0 8px}
.ctx-bar-inner{display:flex;align-items:center;gap:8px;padding:6px 16px;background:var(--card-bg,#fff);border:1px solid var(--brd,#e2e8f0);border-radius:8px;font-size:.78rem;box-shadow:0 1px 3px rgba(0,0,0,.06)}
.ctx-bar-label{font-weight:600;color:var(--mut,#64748b);text-transform:uppercase;letter-spacing:.06em;font-size:.68rem}
.ctx-bar-type{display:inline-block;padding:1px 8px;border-radius:4px;color:#fff;font-weight:600;font-size:.68rem;letter-spacing:.03em}
.ctx-bar-name{font-weight:600;color:var(--txt,#0f172a);cursor:pointer}
.ctx-bar-name:hover{text-decoration:underline}
.ctx-bar-sev{padding:1px 6px;border-radius:3px;font-size:.66rem;font-weight:700;letter-spacing:.04em}
.ctx-sev-critical{background:#fef2f2;color:#dc2626}.ctx-sev-high{background:#fff7ed;color:#ea580c}
.ctx-sev-medium{background:#fffbeb;color:#d97706}.ctx-sev-low{background:#f0fdf4;color:#16a34a}
.ctx-sev-info{background:#f0f9ff;color:#0284c7}
.ctx-bar-status{color:var(--mut,#64748b);font-style:italic}
.ctx-bar-count{color:var(--mut,#64748b);margin-left:auto}
.ctx-bar-open,.ctx-bar-clear{background:none;border:1px solid var(--brd,#e2e8f0);border-radius:4px;padding:2px 10px;font-size:.72rem;cursor:pointer;color:var(--txt,#0f172a);font-weight:500}
.ctx-bar-open:hover{background:var(--acc,#2563eb);color:#fff;border-color:var(--acc,#2563eb)}
.ctx-bar-clear{border:none;font-size:.82rem;padding:2px 6px;color:var(--mut,#64748b)}
.ctx-bar-clear:hover{color:var(--bad,#ef4444)}
html[data-style="dark"] .ctx-bar-inner,html[data-style="classic"] .ctx-bar-inner{background:var(--card-bg,#1e293b);border-color:var(--brd,#334155)}
html[data-style="dark"] .ctx-sev-critical,html[data-style="classic"] .ctx-sev-critical{background:#451a1a;color:#f87171}
html[data-style="dark"] .ctx-sev-high,html[data-style="classic"] .ctx-sev-high{background:#431407;color:#fb923c}
html[data-style="dark"] .ctx-sev-medium,html[data-style="classic"] .ctx-sev-medium{background:#422006;color:#fbbf24}
html[data-style="dark"] .ctx-sev-low,html[data-style="classic"] .ctx-sev-low{background:#052e16;color:#4ade80}
html[data-style="dark"] .ctx-sev-info,html[data-style="classic"] .ctx-sev-info{background:#082f49;color:#38bdf8}
`;
}

export { TYPE_COLORS };
