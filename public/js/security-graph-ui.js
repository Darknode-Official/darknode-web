// Copyright (c) 2026 Darknode-Official. All rights reserved.
import { listEntities, getEntity, deleteEntity, getRelated, getRelationships, getStats, search, exportAll, importEntities, ENTITY_TYPES, SEVERITIES, STATUSES } from '/js/security-graph.js';
import { openEntityModal } from '/js/graph-bridge.js';
import { layout, normalizeImport } from '/js/secgraph/graph-view.js?v=20261014a';

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const toast = (m, k) => { try { (window.showToast || (() => {}))(m, k); } catch (_) {} };

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
const SEV_RADIUS = { critical: 18, high: 16, medium: 14, low: 12, info: 11 };
const NODE_CAP = 300;

const svgEl = (tag, attrs) => {
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const k in (attrs || {})) el.setAttribute(k, attrs[k]);
  return el;
};

let _renderToken = 0;

export function renderSecurityGraphUI(main) {
  const _myToken = ++_renderToken;
  const CSS = `
<style>
.sgu-wrap{max-width:none}
.sgu-header{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin-bottom:20px}
.sgu-spacer{flex:1}
.sgu-toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.sgu-toggle{display:inline-flex;border:1px solid var(--brd,#e2e8f0);border-radius:8px;overflow:hidden}
.sgu-toggle button{background:var(--card-bg,#fff);border:none;padding:7px 16px;font-size:.82rem;font-weight:600;cursor:pointer;color:var(--mut,#64748b)}
.sgu-toggle button.active{background:var(--acc,#2563eb);color:#fff}
.sgu-tbtn{padding:7px 14px;border:1px solid var(--brd,#e2e8f0);border-radius:8px;font-size:.82rem;font-weight:600;cursor:pointer;background:var(--card-bg,#fff);color:var(--txt,#0f172a)}
.sgu-tbtn:hover{border-color:var(--acc,#2563eb);color:var(--acc,#2563eb)}
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
.sgu-page-btn:hover:not([disabled]),.sgu-page-btn.active{background:var(--acc,#2563eb);color:#fff;border-color:var(--acc,#2563eb)}
.sgu-page-btn[disabled]{opacity:.45;cursor:default}
.sgu-page-of{display:flex;align-items:center;font-size:.78rem;color:var(--mut,#64748b);margin-left:4px}
.sgu-type-grid{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:16px}
.sgu-type-pill{padding:4px 12px;border-radius:4px;font-size:.74rem;font-weight:600;cursor:pointer;border:1px solid var(--brd,#e2e8f0);background:var(--card-bg,#fff);color:var(--txt,#0f172a);transition:all .15s}
.sgu-type-pill:hover,.sgu-type-pill.active{color:#fff}
/* Graph view */
.sgg-host{position:relative;border:1px solid var(--brd,#e2e8f0);border-radius:12px;background:var(--card-bg,#fff);height:640px;overflow:hidden}
.sgg-svg{width:100%;height:100%;display:block;cursor:grab;touch-action:none}
.sgg-svg.panning{cursor:grabbing}
.sgg-edge{stroke:var(--brd,#94a3b8);stroke-width:1.4}
.sgg-edge-label{fill:var(--mut,#64748b);font-size:9px;font-weight:600;pointer-events:none;paint-order:stroke;stroke:var(--card-bg,#fff);stroke-width:3px}
.sgg-node{cursor:pointer}
.sgg-node circle{stroke:var(--card-bg,#fff);stroke-width:2}
.sgg-node-label{fill:var(--txt,#0f172a);font-size:11px;font-weight:600;pointer-events:none;paint-order:stroke;stroke:var(--card-bg,#fff);stroke-width:3px}
.sgg-dim{opacity:.1}
.sgg-node.sgg-sel circle{stroke:var(--acc,#2563eb);stroke-width:3.5}
.sgg-legend{position:absolute;top:10px;left:10px;display:flex;flex-wrap:wrap;gap:4px 10px;max-width:60%;padding:8px 10px;background:var(--card-bg,#fff);border:1px solid var(--brd,#e2e8f0);border-radius:8px;font-size:.7rem;color:var(--mut,#64748b)}
.sgg-legend span{display:inline-flex;align-items:center;gap:5px}
.sgg-dot{width:9px;height:9px;border-radius:50%;background:var(--c);flex-shrink:0}
.sgg-controls{position:absolute;top:10px;right:10px;display:flex;gap:6px}
.sgg-note{position:absolute;bottom:10px;left:10px;font-size:.72rem;color:var(--mut,#64748b);background:var(--card-bg,#fff);border:1px solid var(--brd,#e2e8f0);border-radius:6px;padding:4px 10px}
.sgg-panel{position:absolute;top:0;right:0;width:320px;max-width:85%;height:100%;background:var(--card-bg,#fff);border-left:1px solid var(--brd,#e2e8f0);box-shadow:-4px 0 16px rgba(0,0,0,.06);overflow-y:auto;transform:translateX(100%);transition:transform .18s}
.sgg-panel.open{transform:translateX(0)}
.sgg-p-head{padding:14px 16px;border-bottom:1px solid var(--brd,#e2e8f0);display:flex;align-items:flex-start;gap:8px}
.sgg-p-type{padding:2px 8px;border-radius:4px;color:#fff;font-size:.64rem;font-weight:700;background:var(--c)}
.sgg-p-title{font-weight:700;font-size:.95rem;color:var(--txt,#0f172a);flex:1;word-break:break-word}
.sgg-p-close{background:none;border:none;font-size:1.2rem;cursor:pointer;color:var(--mut,#64748b);line-height:1}
.sgg-p-body{padding:12px 16px}
.sgg-p-sec{font-size:.68rem;text-transform:uppercase;letter-spacing:.05em;color:var(--mut,#64748b);font-weight:700;margin:14px 0 6px}
.sgg-p-row{display:flex;gap:8px;padding:3px 0;font-size:.78rem;border-bottom:1px solid var(--brd-light,#f1f5f9)}
.sgg-p-key{font-weight:600;color:var(--mut,#64748b);min-width:96px;flex-shrink:0}
.sgg-p-val{color:var(--txt,#0f172a);word-break:break-all}
.sgg-rel{display:flex;align-items:center;gap:8px;padding:7px 8px;border-radius:7px;cursor:pointer;border:1px solid transparent}
.sgg-rel:hover{background:var(--bg-2,#f1f5f9);border-color:var(--brd,#e2e8f0)}
.sgg-rel-name{flex:1;font-size:.8rem;font-weight:600;color:var(--txt,#0f172a);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sgg-rel-type{font-size:.66rem;color:var(--mut,#64748b)}
.sgg-badge{padding:2px 8px;border-radius:4px;font-size:.7rem;font-weight:600;background:var(--bg-2,#f1f5f9);color:var(--mut,#64748b)}
.sgg-p-actions{display:flex;gap:8px;margin-top:14px}
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

  // Graph view state (persists across re-renders of this page instance).
  let _view = 'cards';
  const _expand = new Set();   // ids pulled in by traversing related entities
  const _pos = {};             // id -> {x,y} laid-out/dragged positions
  let _selected = null;
  let _tf = { x: 0, y: 0, s: 1 };

  function currentFilter() {
    const f = {};
    if (_typeFilter) f.type = _typeFilter;
    if (_sevFilter) f.severity = _sevFilter;
    if (_statusFilter) f.status = _statusFilter;
    if (_searchQ) f.search = _searchQ;
    return f;
  }

  function render() {
    const filter = { ...currentFilter(), limit: PAGE_SIZE, offset: _page * PAGE_SIZE };
    const entities = listEntities(filter);
    const allFiltered = listEntities({ ...currentFilter(), limit: 10000, offset: 0 });
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
          <span class="muted">${curStats.totalEntities} entities, ${curStats.totalRelationships} relationships across ${Object.keys(typeCounts).length} types</span>
          <span class="sgu-spacer"></span>
          <div class="sgu-toolbar">
            <div class="sgu-toggle" role="tablist">
              <button data-view="cards" class="${_view === 'cards' ? 'active' : ''}">Cards</button>
              <button data-view="graph" class="${_view === 'graph' ? 'active' : ''}">Graph</button>
            </div>
            <button class="sgu-tbtn" id="sgu-export" title="Download the whole graph as JSON">Export</button>
            <button class="sgu-tbtn" id="sgu-import" title="Load entities from a JSON file">Import</button>
            <input type="file" id="sgu-import-file" accept="application/json,.json" style="display:none">
          </div>
        </div>
        <div class="sgu-stats">
          <div class="sgu-stat"><div class="sgu-stat-n">${curStats.totalEntities}</div><div class="sgu-stat-l">Total Entities</div></div>
          <div class="sgu-stat"><div class="sgu-stat-n">${curStats.totalRelationships}</div><div class="sgu-stat-l">Relationships</div></div>
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
        ${_view === 'graph' ? `<div class="sgg-host" id="sgu-graph-host"></div>` : (entities.length === 0 ? `
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
          ${totalPages > 1 ? (() => {
            // Sliding window of page buttons + Prev/Next, so every page stays
            // reachable even past 10 (a fixed cap used to strand later pages).
            const WIN = 9;
            let start = Math.max(0, Math.min(_page - Math.floor(WIN / 2), totalPages - WIN));
            const end = Math.min(totalPages, start + WIN);
            const btn = (p, label, on, dis) =>
              `<button class="sgu-page-btn${on ? ' active' : ''}" data-page="${p}"${dis ? ' disabled' : ''}>${label}</button>`;
            let b = btn(_page - 1, 'Prev', false, _page === 0);
            for (let i = start; i < end; i++) b += btn(i, i + 1, i === _page, false);
            b += btn(_page + 1, 'Next', false, _page >= totalPages - 1);
            return `<div class="sgu-pagination">${b}<span class="sgu-page-of">Page ${_page + 1} of ${totalPages}</span></div>`;
          })() : ''}
        `)}
      </div>`;

    main.querySelector('#sgu-search').oninput = (e) => { _searchQ = e.target.value; _page = 0; render(); };
    main.querySelector('#sgu-sev').onchange = (e) => { _sevFilter = e.target.value || null; _page = 0; render(); };
    main.querySelector('#sgu-status').onchange = (e) => { _statusFilter = e.target.value || null; _page = 0; render(); };

    main.querySelectorAll('.sgu-toggle button').forEach(btn => {
      btn.onclick = () => { _view = btn.dataset.view; render(); };
    });
    main.querySelector('#sgu-export').onclick = doExport;
    const fileInput = main.querySelector('#sgu-import-file');
    main.querySelector('#sgu-import').onclick = () => fileInput.click();
    fileInput.onchange = (e) => doImport(e.target.files && e.target.files[0]);

    main.querySelectorAll('.sgu-type-pill').forEach(btn => {
      btn.onclick = () => { _typeFilter = btn.dataset.type || null; _page = 0; render(); };
    });

    main.querySelectorAll('.sgu-page-btn').forEach(btn => {
      btn.onclick = () => { if (btn.disabled) return; _page = Math.max(0, Math.min(totalPages - 1, parseInt(btn.dataset.page) || 0)); render(); };
    });

    main.querySelectorAll('[data-action="view"]').forEach(btn => {
      btn.onclick = (e) => { e.stopPropagation(); const entity = getEntity(btn.dataset.eid); if (entity) openEntityModal(entity); };
    });

    // The whole card is signalled clickable (cursor:pointer); open the entity on a
    // click anywhere on it that isn't one of the action buttons.
    main.querySelectorAll('.sgu-card').forEach(card => {
      card.onclick = (e) => {
        if (e.target.closest('.sgu-card-btn')) return;
        const entity = getEntity(card.dataset.eid); if (entity) openEntityModal(entity);
      };
    });

    main.querySelectorAll('[data-action="delete"]').forEach(btn => {
      btn.onclick = async (e) => {
        e.stopPropagation();
        if (await window.dnConfirm('Delete entity', 'Delete this entity? This cannot be undone.', { danger: true })) {
          deleteEntity(btn.dataset.eid);
          render();
        }
      };
    });

    if (_view === 'graph') drawGraph();
  }

  // ---- Export / Import -----------------------------------------------------

  function doExport() {
    try {
      const data = exportAll();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `security-graph-${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast(`Exported ${data.entities.length} entities and ${data.relationships.length} relationships`, 'ok');
    } catch (_) { toast('Export failed', 'error'); }
  }

  async function doImport(file) {
    if (!file) return;
    let items;
    try {
      const text = await file.text();
      items = normalizeImport(JSON.parse(text));
    } catch (_) { toast('Could not parse that JSON file', 'error'); return; }
    if (!items.length) { toast('No importable entities found in that file', 'error'); return; }
    if (items.length > 50) {
      const ok = await window.dnConfirm('Import entities', `This will add or merge ${items.length} entities into your Security Graph. Continue?`);
      if (!ok) return;
    }
    const before = getStats().totalEntities;
    importEntities(items);
    const added = getStats().totalEntities - before;
    toast(`Imported ${items.length} entities (${added} new, ${items.length - added} merged)`, 'ok');
    render();
  }

  // ---- Graph view ----------------------------------------------------------

  function buildGraphData() {
    const all = listEntities({ ...currentFilter(), limit: 10000, offset: 0 });
    let ids = all.map(e => e.id);
    for (const id of _expand) if (getEntity(id) && !ids.includes(id)) ids.push(id);
    let capped = false;
    if (ids.length > NODE_CAP) { ids = ids.slice(0, NODE_CAP); capped = true; }
    const idSet = new Set(ids);
    const nodes = ids.map(id => getEntity(id)).filter(Boolean);
    const relMap = {};
    for (const id of idSet) {
      for (const r of getRelationships(id)) {
        if (idSet.has(r.fromId) && idSet.has(r.toId)) relMap[r.id] = r;
      }
    }
    return { nodes, edges: Object.values(relMap), idSet, capped };
  }

  function drawGraph() {
    const host = main.querySelector('#sgu-graph-host');
    if (!host) return;
    const { nodes, edges, idSet, capped } = buildGraphData();

    if (nodes.length === 0) {
      host.innerHTML = `<div class="sgu-empty" style="padding:100px 20px"><div class="sgu-empty-title">No entities to graph</div><p>${(getStats().totalEntities ? 'No entities match the current filters.' : 'The graph is empty. Entities appear here when tools, investigations, or imports create them.')}</p></div>`;
      return;
    }

    // Drop positions for nodes no longer present; keep the rest stable.
    for (const id in _pos) if (!idSet.has(id)) delete _pos[id];
    if (_selected && !idSet.has(_selected)) _selected = null;

    const rect = host.getBoundingClientRect();
    const W = Math.max(480, rect.width || 1000);
    const H = Math.max(420, rect.height || 640);

    // Lay out only when some node has no position yet; pin known ones so the
    // existing picture stays put as traversal pulls in new neighbors.
    const needs = nodes.some(n => !_pos[n.id]);
    if (needs) {
      const laid = layout(nodes, edges, { width: W, height: H, margin: 40, iterations: 320, seed: 7, pinned: { ..._pos } });
      for (const n of nodes) if (laid[n.id]) _pos[n.id] = laid[n.id];
    }

    // Neighbor adjacency for highlight on select.
    const adj = {};
    for (const e of edges) {
      (adj[e.fromId] = adj[e.fromId] || new Set()).add(e.toId);
      (adj[e.toId] = adj[e.toId] || new Set()).add(e.fromId);
    }

    const typesPresent = [...new Set(nodes.map(n => n.type))];
    const legend = typesPresent.map(t => `<span><i class="sgg-dot" style="--c:${TYPE_COLORS[t] || '#64748b'}"></i>${esc(t)}</span>`).join('');

    host.innerHTML = `
      <svg class="sgg-svg" id="sgg-svg">
        <g id="sgg-view">
          <g id="sgg-edges"></g>
          <g id="sgg-edge-labels"></g>
          <g id="sgg-nodes"></g>
        </g>
      </svg>
      <div class="sgg-legend">${legend}</div>
      <div class="sgg-controls">
        <button class="sgu-tbtn" id="sgg-fit" title="Reset pan and zoom">Reset view</button>
      </div>
      ${capped ? `<div class="sgg-note">Showing the first ${NODE_CAP} entities. Narrow with filters to see the rest.</div>` : (edges.length === 0 ? `<div class="sgg-note">No relationships recorded yet, so nodes are shown without links.</div>` : '')}
      <div class="sgg-panel" id="sgg-panel"></div>`;

    const svg = host.querySelector('#sgg-svg');
    const view = host.querySelector('#sgg-view');
    const edgesG = host.querySelector('#sgg-edges');
    const labelsG = host.querySelector('#sgg-edge-labels');
    const nodesG = host.querySelector('#sgg-nodes');

    const edgeEls = [];
    for (const e of edges) {
      const line = svgEl('line', { class: 'sgg-edge', 'data-from': e.fromId, 'data-to': e.toId });
      edgesG.appendChild(line);
      const label = svgEl('text', { class: 'sgg-edge-label', 'text-anchor': 'middle' });
      label.textContent = (e.type || '').replace(/_/g, ' ');
      labelsG.appendChild(label);
      edgeEls.push({ e, line, label });
    }

    const nodeEls = {};
    for (const n of nodes) {
      const g = svgEl('g', { class: 'sgg-node', 'data-id': n.id });
      const r = SEV_RADIUS[n.severity] || 11;
      const circle = svgEl('circle', { r, fill: TYPE_COLORS[n.type] || '#64748b' });
      const label = svgEl('text', { class: 'sgg-node-label', 'text-anchor': 'middle', y: r + 12 });
      const name = n.name || n.type;
      label.textContent = name.length > 22 ? name.slice(0, 21) + '…' : name;
      g.appendChild(circle); g.appendChild(label);
      nodesG.appendChild(g);
      nodeEls[n.id] = g;
    }

    function positionAll() {
      for (const id in nodeEls) {
        const p = _pos[id]; if (!p) continue;
        nodeEls[id].setAttribute('transform', `translate(${p.x},${p.y})`);
      }
      for (const { e, line, label } of edgeEls) {
        const a = _pos[e.fromId], b = _pos[e.toId];
        if (!a || !b) continue;
        line.setAttribute('x1', a.x); line.setAttribute('y1', a.y);
        line.setAttribute('x2', b.x); line.setAttribute('y2', b.y);
        label.setAttribute('x', (a.x + b.x) / 2); label.setAttribute('y', (a.y + b.y) / 2 - 2);
      }
    }

    function applyTransform() { view.setAttribute('transform', `translate(${_tf.x},${_tf.y}) scale(${_tf.s})`); }

    function applyHighlight() {
      const near = _selected ? (adj[_selected] || new Set()) : null;
      for (const id in nodeEls) {
        const on = !_selected || id === _selected || near.has(id);
        nodeEls[id].classList.toggle('sgg-dim', !on);
        nodeEls[id].classList.toggle('sgg-sel', id === _selected);
      }
      for (const { e, line, label } of edgeEls) {
        const on = !_selected || e.fromId === _selected || e.toId === _selected;
        line.classList.toggle('sgg-dim', !on);
        label.classList.toggle('sgg-dim', !on);
      }
    }

    positionAll();
    applyTransform();
    applyHighlight();
    if (_selected) openPanel(_selected);

    // Pan / zoom / node drag --------------------------------------------------
    let mode = null;        // 'pan' | 'node'
    let dragId = null;
    let moved = false;
    let last = { x: 0, y: 0 };

    svg.addEventListener('pointerdown', (ev) => {
      const nodeG = ev.target.closest('.sgg-node');
      moved = false;
      last = { x: ev.clientX, y: ev.clientY };
      if (nodeG) { mode = 'node'; dragId = nodeG.dataset.id; }
      else { mode = 'pan'; svg.classList.add('panning'); }
      svg.setPointerCapture(ev.pointerId);
    });

    svg.addEventListener('pointermove', (ev) => {
      if (!mode) return;
      const dx = ev.clientX - last.x, dy = ev.clientY - last.y;
      if (Math.abs(dx) + Math.abs(dy) > 2) moved = true;
      last = { x: ev.clientX, y: ev.clientY };
      if (mode === 'pan') { _tf.x += dx; _tf.y += dy; applyTransform(); }
      else if (mode === 'node' && _pos[dragId]) {
        _pos[dragId].x += dx / _tf.s; _pos[dragId].y += dy / _tf.s;
        positionAll();
      }
    });

    const endDrag = (ev) => {
      if (!mode) return;
      if (mode === 'node' && !moved) selectNode(dragId);
      mode = null; dragId = null; svg.classList.remove('panning');
      try { svg.releasePointerCapture(ev.pointerId); } catch (_) {}
    };
    svg.addEventListener('pointerup', endDrag);
    svg.addEventListener('pointercancel', endDrag);

    svg.addEventListener('wheel', (ev) => {
      ev.preventDefault();
      const r = svg.getBoundingClientRect();
      const mx = ev.clientX - r.left, my = ev.clientY - r.top;
      const factor = ev.deltaY < 0 ? 1.12 : 1 / 1.12;
      const ns = Math.max(0.2, Math.min(4, _tf.s * factor));
      // keep the point under the cursor fixed while zooming
      _tf.x = mx - (mx - _tf.x) * (ns / _tf.s);
      _tf.y = my - (my - _tf.y) * (ns / _tf.s);
      _tf.s = ns;
      applyTransform();
    }, { passive: false });

    host.querySelector('#sgg-fit').onclick = () => { _tf = { x: 0, y: 0, s: 1 }; applyTransform(); };

    function selectNode(id) {
      _selected = _selected === id ? null : id;
      applyHighlight();
      if (_selected) openPanel(_selected); else closePanel();
    }

    // Detail panel ------------------------------------------------------------
    function closePanel() { const p = host.querySelector('#sgg-panel'); if (p) p.classList.remove('open'); }

    function openPanel(id) {
      const panel = host.querySelector('#sgg-panel');
      const ent = getEntity(id);
      if (!panel || !ent) return;
      const color = TYPE_COLORS[ent.type] || '#64748b';
      const dataEntries = ent.data ? Object.entries(ent.data).filter(([k]) => !k.startsWith('_')) : [];
      const rels = getRelationships(id);
      const relRows = rels.map(r => {
        const otherId = r.fromId === id ? r.toId : r.fromId;
        const other = getEntity(otherId);
        if (!other) return '';
        const dir = r.fromId === id ? '→' : '←';
        const oc = TYPE_COLORS[other.type] || '#64748b';
        return `<div class="sgg-rel" data-id="${esc(otherId)}">
          <i class="sgg-dot" style="--c:${oc}"></i>
          <span class="sgg-rel-name">${esc(other.name)}</span>
          <span class="sgg-rel-type">${dir} ${esc((r.type || '').replace(/_/g, ' '))}</span>
        </div>`;
      }).join('');

      panel.innerHTML = `
        <div class="sgg-p-head">
          <span class="sgg-p-type" style="--c:${color}">${esc(ent.type)}</span>
          <span class="sgg-p-title">${esc(ent.name)}</span>
          <button class="sgg-p-close" title="Close">&times;</button>
        </div>
        <div class="sgg-p-body">
          <div style="display:flex;flex-wrap:wrap;gap:6px">
            ${ent.severity ? `<span class="sgg-badge">${esc(ent.severity.toUpperCase())}</span>` : ''}
            ${ent.status ? `<span class="sgg-badge">${esc(ent.status)}</span>` : ''}
            ${ent.source ? `<span class="sgg-badge">via ${esc(ent.source)}</span>` : ''}
            ${(ent.tags || []).map(t => `<span class="sgg-badge">${esc(t)}</span>`).join('')}
          </div>
          ${dataEntries.length ? `<div class="sgg-p-sec">Fields</div>${dataEntries.map(([k, v]) => `
            <div class="sgg-p-row"><span class="sgg-p-key">${esc(k)}</span><span class="sgg-p-val">${esc(typeof v === 'object' ? JSON.stringify(v) : String(v))}</span></div>`).join('')}` : ''}
          <div class="sgg-p-sec">Related (${rels.length})</div>
          ${relRows || `<div class="muted" style="font-size:.78rem;color:var(--mut,#64748b)">No relationships recorded for this entity.</div>`}
          <div class="sgg-p-actions">
            <button class="sgu-tbtn" id="sgg-open-full">Open full record</button>
          </div>
        </div>`;
      panel.classList.add('open');

      panel.querySelector('.sgg-p-close').onclick = () => { _selected = null; applyHighlight(); closePanel(); };
      panel.querySelector('#sgg-open-full').onclick = () => openEntityModal(getEntity(id));
      panel.querySelectorAll('.sgg-rel').forEach(row => {
        row.onclick = () => {
          const target = row.dataset.id;
          // Expand: pull in the clicked entity and its neighbors, then re-center on it.
          _expand.add(target);
          for (const nb of getRelated(target)) _expand.add(nb.id);
          _selected = target;
          drawGraph();
        };
      });
    }
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
