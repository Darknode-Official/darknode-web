// Copyright (c) 2026 Darknode-Official. All rights reserved.
import { listEntities, getEntity, deleteEntity, getRelated, getStats, search, ENTITY_TYPES, SEVERITIES, STATUSES } from '/js/security-graph.js';
import { openEntityModal } from '/js/graph-bridge.js';

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

const SEV_COLORS = { critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#16a34a', info: '#0284c7' };

let _renderToken = 0;

export function renderSecurityGraphUI(main) {
  const _myToken = ++_renderToken;
  const stats = getStats();
  const CSS = `
<style>
.sgu-wrap{max-width:none}
.sgu-header{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin-bottom:20px}
.sgu-stats{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:12px;margin-bottom:24px}
.sgu-stat{background:var(--card-bg,#fff);border:1px solid var(--brd,#e2e8f0);border-radius:10px;padding:14px 16px;text-align:center}
.sgu-stat-n{font-size:1.4rem;font-weight:800;color:var(--txt,#0f172a)}
.sgu-stat-l{font-size:.72rem;color:var(--mut,#64748b);text-transform:uppercase;letter-spacing:.05em;margin-top:2px}
.sgu-filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;align-items:center}
.sgu-search{padding:8px 14px;border:1px solid var(--brd,#e2e8f0);border-radius:8px;font-size:.86rem;background:var(--card-bg,#fff);color:var(--txt,#0f172a);min-width:240px}
.sgu-select{padding:6px 10px;border:1px solid var(--brd,#e2e8f0);border-radius:6px;font-size:.8rem;background:var(--card-bg,#fff);color:var(--txt,#0f172a)}
.sgu-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}
.sgu-card{background:var(--card-bg,#fff);border:1px solid var(--brd,#e2e8f0);border-radius:10px;padding:14px 16px;cursor:pointer;transition:box-shadow .15s,border-color .15s}
.sgu-card:hover{box-shadow:0 2px 8px rgba(0,0,0,.08);border-color:var(--acc,#2563eb)}
.sgu-card-top{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.sgu-card-type{padding:2px 8px;border-radius:4px;color:#fff;font-size:.66rem;font-weight:700;letter-spacing:.03em}
.sgu-card-name{font-weight:700;font-size:.9rem;color:var(--txt,#0f172a);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sgu-card-sev{padding:1px 6px;border-radius:3px;font-size:.64rem;font-weight:700;color:#fff}
.sgu-card-meta{display:flex;gap:8px;font-size:.72rem;color:var(--mut,#64748b);flex-wrap:wrap}
.sgu-card-tag{background:var(--bg-2,#f1f5f9);padding:1px 6px;border-radius:3px;font-size:.68rem}
.sgu-card-actions{display:flex;gap:6px;margin-top:8px}
.sgu-card-btn{background:none;border:1px solid var(--brd,#e2e8f0);border-radius:4px;padding:3px 10px;font-size:.72rem;cursor:pointer;color:var(--mut,#64748b)}
.sgu-card-btn:hover{background:var(--acc,#2563eb);color:#fff;border-color:var(--acc,#2563eb)}
.sgu-card-btn.danger:hover{background:#ef4444;border-color:#ef4444}
.sgu-empty{text-align:center;padding:60px 20px;color:var(--mut,#64748b)}
.sgu-empty-title{font-size:1.1rem;font-weight:700;margin-bottom:8px;color:var(--txt,#0f172a)}
.sgu-pagination{display:flex;justify-content:center;gap:8px;margin-top:20px}
.sgu-page-btn{padding:6px 14px;border:1px solid var(--brd,#e2e8f0);border-radius:6px;font-size:.82rem;cursor:pointer;background:var(--card-bg,#fff);color:var(--txt,#0f172a)}
.sgu-page-btn:hover,.sgu-page-btn.active{background:var(--acc,#2563eb);color:#fff;border-color:var(--acc,#2563eb)}
.sgu-type-grid{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:16px}
.sgu-type-pill{padding:4px 12px;border-radius:4px;font-size:.74rem;font-weight:600;cursor:pointer;border:1px solid var(--brd,#e2e8f0);background:var(--card-bg,#fff);color:var(--txt,#0f172a);transition:all .15s}
.sgu-type-pill:hover,.sgu-type-pill.active{color:#fff}
html[data-style="dark"] .sgu-card,html[data-style="classic"] .sgu-card,
html[data-style="dark"] .sgu-stat,html[data-style="classic"] .sgu-stat{background:var(--card-bg,#1e293b);border-color:var(--brd,#334155)}
html[data-style="dark"] .sgu-search,html[data-style="classic"] .sgu-search,
html[data-style="dark"] .sgu-select,html[data-style="classic"] .sgu-select{background:var(--card-bg,#1e293b);border-color:var(--brd,#334155);color:var(--txt,#e2e8f0)}
</style>`;

  let _typeFilter = null;
  let _sevFilter = null;
  let _statusFilter = null;
  let _searchQ = '';
  let _page = 0;
  const PAGE_SIZE = 30;

  function render() {
    const filter = {};
    if (_typeFilter) filter.type = _typeFilter;
    if (_sevFilter) filter.severity = _sevFilter;
    if (_statusFilter) filter.status = _statusFilter;
    if (_searchQ) filter.search = _searchQ;
    filter.limit = PAGE_SIZE;
    filter.offset = _page * PAGE_SIZE;

    const entities = listEntities(filter);
    const allFiltered = listEntities({ ...filter, limit: 10000, offset: 0 });
    const totalPages = Math.ceil(allFiltered.length / PAGE_SIZE);
    const curStats = getStats();

    const typeCounts = curStats.byType || {};
    const typePills = ENTITY_TYPES.filter(t => typeCounts[t]).map(t => {
      const color = TYPE_COLORS[t] || '#64748b';
      const active = _typeFilter === t;
      return `<button class="sgu-type-pill${active ? ' active' : ''}" data-type="${t}" style="--tc:${color};${active ? 'background:' + color + ';border-color:' + color : ''}">${t} (${typeCounts[t]})</button>`;
    }).join('');

    main.innerHTML = CSS + `
      <div class="sgu-wrap">
        <div class="sgu-header">
          <h1 class="pg-h1" style="margin:0">Security Graph</h1>
          <span class="muted">${curStats.totalEntities} entities across ${Object.keys(typeCounts).length} types</span>
        </div>
        <div class="sgu-stats">
          <div class="sgu-stat"><div class="sgu-stat-n">${curStats.totalEntities}</div><div class="sgu-stat-l">Total Entities</div></div>
          <div class="sgu-stat"><div class="sgu-stat-n">${typeCounts.INVESTIGATION || 0}</div><div class="sgu-stat-l">Investigations</div></div>
          <div class="sgu-stat"><div class="sgu-stat-n">${typeCounts.INCIDENT || 0}</div><div class="sgu-stat-l">Incidents</div></div>
          <div class="sgu-stat"><div class="sgu-stat-n">${typeCounts.VULNERABILITY || 0}</div><div class="sgu-stat-l">Vulnerabilities</div></div>
          <div class="sgu-stat"><div class="sgu-stat-n">${typeCounts.INDICATOR || 0}</div><div class="sgu-stat-l">Indicators</div></div>
          <div class="sgu-stat"><div class="sgu-stat-n">${typeCounts.FINDING || 0}</div><div class="sgu-stat-l">Findings</div></div>
          <div class="sgu-stat"><div class="sgu-stat-n">${(curStats.bySeverity || {}).critical || 0}</div><div class="sgu-stat-l">Critical</div></div>
          <div class="sgu-stat"><div class="sgu-stat-n">${(curStats.bySeverity || {}).high || 0}</div><div class="sgu-stat-l">High Severity</div></div>
        </div>
        ${typePills ? `<div class="sgu-type-grid">${_typeFilter ? '<button class="sgu-type-pill" data-type="">All Types</button>' : ''}${typePills}</div>` : ''}
        <div class="sgu-filters">
          <input class="sgu-search" placeholder="Search entities..." value="${esc(_searchQ)}" id="sgu-search">
          <select class="sgu-select" id="sgu-sev">
            <option value="">All severities</option>
            ${SEVERITIES.filter(Boolean).map(s => `<option value="${s}"${_sevFilter === s ? ' selected' : ''}>${s.charAt(0).toUpperCase() + s.slice(1)}</option>`).join('')}
          </select>
          <select class="sgu-select" id="sgu-status">
            <option value="">All statuses</option>
            ${STATUSES.filter(Boolean).map(s => `<option value="${s}"${_statusFilter === s ? ' selected' : ''}>${s.charAt(0).toUpperCase() + s.slice(1)}</option>`).join('')}
          </select>
        </div>
        ${entities.length === 0 ? `
          <div class="sgu-empty">
            <div class="sgu-empty-title">No entities yet</div>
            <p>Entities are created when you use tools, run investigations, or import data. Start by creating an investigation or using any security tool.</p>
          </div>
        ` : `
          <div class="sgu-grid">
            ${entities.map(e => {
              const color = TYPE_COLORS[e.type] || '#64748b';
              const sevColor = SEV_COLORS[e.severity] || null;
              const related = getRelated(e.id);
              return `
                <div class="sgu-card" data-eid="${esc(e.id)}">
                  <div class="sgu-card-top">
                    <span class="sgu-card-type" style="--tc:${color};background:${color}">${esc(e.type)}</span>
                    <span class="sgu-card-name">${esc(e.name)}</span>
                    ${sevColor ? `<span class="sgu-card-sev" style="background:${sevColor}">${esc(e.severity.toUpperCase())}</span>` : ''}
                  </div>
                  <div class="sgu-card-meta">
                    ${e.status ? `<span>${esc(e.status)}</span>` : ''}
                    ${e.source ? `<span>via ${esc(e.source)}</span>` : ''}
                    <span>${new Date(e.updatedAt).toLocaleDateString()}</span>
                    ${related.length ? `<span>${related.length} related</span>` : ''}
                  </div>
                  ${(e.tags || []).length ? `<div class="sgu-card-meta" style="margin-top:4px">${e.tags.map(t => `<span class="sgu-card-tag">${esc(t)}</span>`).join('')}</div>` : ''}
                  <div class="sgu-card-actions">
                    <button class="sgu-card-btn" data-action="view" data-eid="${esc(e.id)}">View</button>
                    <button class="sgu-card-btn danger" data-action="delete" data-eid="${esc(e.id)}">Delete</button>
                  </div>
                </div>`;
            }).join('')}
          </div>
          ${totalPages > 1 ? `
            <div class="sgu-pagination">
              ${Array.from({ length: Math.min(totalPages, 10) }, (_, i) =>
                `<button class="sgu-page-btn${i === _page ? ' active' : ''}" data-page="${i}">${i + 1}</button>`
              ).join('')}
            </div>
          ` : ''}
        `}
      </div>`;

    main.querySelector('#sgu-search').oninput = (e) => { _searchQ = e.target.value; _page = 0; render(); };
    main.querySelector('#sgu-sev').onchange = (e) => { _sevFilter = e.target.value || null; _page = 0; render(); };
    main.querySelector('#sgu-status').onchange = (e) => { _statusFilter = e.target.value || null; _page = 0; render(); };

    main.querySelectorAll('.sgu-type-pill').forEach(btn => {
      btn.onclick = () => { _typeFilter = btn.dataset.type || null; _page = 0; render(); };
    });

    main.querySelectorAll('.sgu-page-btn').forEach(btn => {
      btn.onclick = () => { _page = parseInt(btn.dataset.page); render(); };
    });

    main.querySelectorAll('[data-action="view"]').forEach(btn => {
      btn.onclick = (e) => { e.stopPropagation(); const entity = getEntity(btn.dataset.eid); if (entity) openEntityModal(entity); };
    });

    main.querySelectorAll('[data-action="delete"]').forEach(btn => {
      btn.onclick = (e) => {
        e.stopPropagation();
        if (confirm('Delete this entity? This cannot be undone.')) {
          deleteEntity(btn.dataset.eid);
          render();
        }
      };
    });
  }

  render();

  // Re-render at most once per burst of changes, and detach once the user has
  // navigated away, otherwise tool sends would repaint this page over the tool.
  let _rerender = null;
  const _listener = () => {
    if (_myToken !== _renderToken || !main.querySelector('.sgu-wrap')) {
      document.removeEventListener('secgraph:entity:created', _listener);
      document.removeEventListener('secgraph:entity:deleted', _listener);
      document.removeEventListener('secgraph:entity:updated', _listener);
      return;
    }
    clearTimeout(_rerender);
    _rerender = setTimeout(render, 60);
  };
  document.addEventListener('secgraph:entity:created', _listener);
  document.addEventListener('secgraph:entity:deleted', _listener);
  document.addEventListener('secgraph:entity:updated', _listener);
}
