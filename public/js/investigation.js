// Copyright (c) 2026 Darknode-Official. All rights reserved.
import { esc, formatDate, debounce } from '/js/shared.js';
import {
  createEntity, getEntity, updateEntity, deleteEntity, listEntities,
  createRelationship, getRelationships, getRelated,
  search, ENTITY_TYPES, SEVERITIES, STATUSES
} from '/js/security-graph.js';

const TYPE_COLORS = {
  ASSET: '#2563eb', VULNERABILITY: '#ef4444', INDICATOR: '#f59e0b',
  INCIDENT: '#dc2626', FINDING: '#8b5cf6', DOMAIN: '#06b6d4',
  IP: '#10b981', MALWARE: '#e11d48', THREAT_ACTOR: '#7c3aed',
  INVESTIGATION: '#2563eb', EVENT: '#64748b', CASE: '#0891b2',
  CERTIFICATE: '#6366f1', SERVICE: '#059669', SOFTWARE: '#d97706',
  DETECTION: '#7c3aed', CAMPAIGN: '#be123c', PLAYBOOK: '#0d9488',
  CONTROL: '#4f46e5', REPORT: '#475569', TECHNIQUE: '#9333ea',
};
const SEV_COLORS = { CRITICAL: '#dc2626', HIGH: '#ef4444', MEDIUM: '#f59e0b', LOW: '#22c55e', INFO: '#64748b' };
let _currentView = 'list';
let _currentInvId = null;
let _currentTab = 'overview';
let _cleanup = null;

const CSS = `
<style>
.inv-wrap{font-size:.88rem;line-height:1.5}
.inv-header{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:20px;flex-wrap:wrap}
.inv-header h1{margin:0;font-size:1.3rem;font-weight:700}
.inv-btn{display:inline-flex;align-items:center;gap:6px;padding:7px 16px;border:none;border-radius:4px;font-size:.82rem;font-weight:600;cursor:pointer;transition:background .15s,opacity .15s}
.inv-btn-primary{background:#2563eb;color:#fff}.inv-btn-primary:hover{background:#1d4ed8}
.inv-btn-ghost{background:transparent;color:var(--txt,#0f172a);border:1px solid var(--brd,#e2e8f0)}.inv-btn-ghost:hover{background:var(--hover,#f1f5f9)}
.inv-btn-danger{background:#fee2e2;color:#dc2626;border:1px solid #fecaca}.inv-btn-danger:hover{background:#fecaca}
.inv-btn-sm{padding:4px 10px;font-size:.75rem;border-radius:4px}
.inv-filters{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:16px}
.inv-select{padding:5px 10px;border:1px solid var(--brd,#e2e8f0);border-radius:6px;font-size:.8rem;background:var(--card-bg,#fff);color:var(--txt,#0f172a);cursor:pointer}
.inv-search{padding:6px 12px;border:1px solid var(--brd,#e2e8f0);border-radius:6px;font-size:.82rem;background:var(--card-bg,#fff);color:var(--txt,#0f172a);flex:1;min-width:180px}
.inv-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:14px}
.inv-card{background:var(--card-bg,#fff);border:1px solid var(--brd,#e2e8f0);border-radius:10px;padding:16px;cursor:pointer;transition:box-shadow .15s,border-color .15s}
.inv-card:hover{border-color:#2563eb;box-shadow:0 2px 8px rgba(37,99,235,.1)}
.inv-card-h{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.inv-card-h h3{margin:0;font-size:.95rem;font-weight:600;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.inv-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.68rem;font-weight:700;letter-spacing:.03em;text-transform:uppercase;line-height:1.4}
.inv-sev{color:#fff}
.inv-status-badge{background:var(--hover,#f1f5f9);color:var(--mut,#64748b)}
.inv-card-desc{font-size:.8rem;color:var(--mut,#64748b);margin:0 0 10px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.inv-card-meta{display:flex;gap:12px;font-size:.72rem;color:var(--mut,#64748b)}
.inv-card-meta span{display:flex;align-items:center;gap:3px}
.inv-detail-header{display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap}
.inv-back{background:none;border:none;font-size:.82rem;color:var(--acc,#2563eb);cursor:pointer;padding:4px 8px;border-radius:4px;font-weight:600}
.inv-back:hover{background:var(--hover,#f1f5f9)}
.inv-tabs{display:flex;gap:2px;border-bottom:1px solid var(--brd,#e2e8f0);margin-bottom:16px;overflow-x:auto}
.inv-tab{padding:8px 16px;border:none;background:none;font-size:.82rem;font-weight:500;color:var(--mut,#64748b);cursor:pointer;border-bottom:2px solid transparent;white-space:nowrap;transition:color .15s,border-color .15s}
.inv-tab:hover{color:var(--txt,#0f172a)}
.inv-tab.active{color:#2563eb;border-bottom-color:#2563eb;font-weight:600}
.inv-panel{padding:0}
.inv-field{margin-bottom:14px}
.inv-field label{display:block;font-size:.75rem;font-weight:600;color:var(--mut,#64748b);text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px}
.inv-input{width:100%;padding:7px 10px;border:1px solid var(--brd,#e2e8f0);border-radius:6px;font-size:.86rem;background:var(--card-bg,#fff);color:var(--txt,#0f172a);box-sizing:border-box}
.inv-textarea{width:100%;padding:8px 10px;border:1px solid var(--brd,#e2e8f0);border-radius:6px;font-size:.84rem;background:var(--card-bg,#fff);color:var(--txt,#0f172a);resize:vertical;min-height:80px;box-sizing:border-box;font-family:inherit;line-height:1.5}
.inv-stats{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:10px;margin-bottom:16px}
.inv-stat{background:var(--card-bg,#fff);border:1px solid var(--brd,#e2e8f0);border-radius:8px;padding:12px;text-align:center}
.inv-stat-n{font-size:1.4rem;font-weight:700;color:var(--txt,#0f172a)}
.inv-stat-l{font-size:.72rem;color:var(--mut,#64748b);text-transform:uppercase;letter-spacing:.04em}
.inv-entity-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px}
.inv-entity-card{background:var(--card-bg,#fff);border:1px solid var(--brd,#e2e8f0);border-radius:8px;padding:12px;display:flex;align-items:flex-start;gap:10px;position:relative}
.inv-entity-card:hover{border-color:var(--brd-hover,#cbd5e1)}
.inv-entity-info{flex:1;min-width:0}
.inv-entity-info h4{margin:0 0 4px;font-size:.84rem;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.inv-entity-info p{margin:0;font-size:.72rem;color:var(--mut,#64748b)}
.inv-entity-remove{position:absolute;top:8px;right:8px;background:none;border:none;color:var(--mut,#94a3b8);cursor:pointer;font-size:.82rem;padding:2px 4px;border-radius:4px}
.inv-entity-remove:hover{color:#dc2626;background:#fee2e2}
.inv-timeline{display:flex;flex-direction:column;gap:0}
.inv-tl-item{display:flex;gap:12px;padding:10px 0;border-bottom:1px solid var(--brd,#f1f5f9);align-items:flex-start}
.inv-tl-dot{width:8px;height:8px;border-radius:50%;margin-top:5px;flex-shrink:0}
.inv-tl-content{flex:1;min-width:0}
.inv-tl-content strong{font-size:.82rem}
.inv-tl-content p{margin:2px 0 0;font-size:.78rem;color:var(--mut,#64748b)}
.inv-tl-time{font-size:.7rem;color:var(--mut,#94a3b8);white-space:nowrap;flex-shrink:0}
.inv-tl-type{font-size:.65rem;font-weight:700;text-transform:uppercase;letter-spacing:.03em;padding:1px 6px;border-radius:3px;background:var(--hover,#f1f5f9);color:var(--mut,#64748b)}
.inv-note{background:var(--card-bg,#fff);border:1px solid var(--brd,#e2e8f0);border-radius:8px;padding:12px;margin-bottom:10px}
.inv-note-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}
.inv-note-meta{font-size:.72rem;color:var(--mut,#94a3b8)}
.inv-note-body{font-size:.84rem;white-space:pre-wrap;line-height:1.6}
.inv-finding{background:var(--card-bg,#fff);border:1px solid var(--brd,#e2e8f0);border-radius:8px;padding:14px;margin-bottom:10px;border-left:3px solid #8b5cf6}
.inv-finding h4{margin:0 0 6px;font-size:.9rem;font-weight:600;display:flex;align-items:center;gap:8px}
.inv-finding p{margin:4px 0;font-size:.82rem;color:var(--mut,#64748b)}
.inv-finding-actions{display:flex;gap:6px;margin-top:8px}
.inv-form-row{display:flex;gap:8px;align-items:flex-end;margin-bottom:12px;flex-wrap:wrap}
.inv-form-row .inv-field{margin-bottom:0;flex:1;min-width:140px}
.inv-empty{text-align:center;padding:40px 20px;color:var(--mut,#94a3b8);font-size:.88rem}
.inv-modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.4);z-index:9999;display:flex;align-items:center;justify-content:center;padding:20px}
.inv-modal{background:var(--card-bg,#fff);border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,.2);width:100%;max-width:540px;max-height:80vh;display:flex;flex-direction:column;overflow:hidden}
.inv-modal-h{padding:16px 20px;border-bottom:1px solid var(--brd,#e2e8f0);display:flex;align-items:center;justify-content:space-between}
.inv-modal-h h2{margin:0;font-size:1rem;font-weight:700}
.inv-modal-close{background:none;border:none;font-size:1.2rem;cursor:pointer;color:var(--mut,#64748b);padding:4px 8px;border-radius:4px}
.inv-modal-close:hover{background:var(--hover,#f1f5f9)}
.inv-modal-body{padding:16px 20px;overflow-y:auto;flex:1}
.inv-modal-item{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:4px;cursor:pointer;transition:background .1s}
.inv-modal-item:hover{background:var(--hover,#f1f5f9)}
.inv-modal-item-name{flex:1;font-size:.86rem;font-weight:500}
.inv-modal-item-meta{font-size:.72rem;color:var(--mut,#94a3b8)}
.inv-export-section{background:var(--card-bg,#fff);border:1px solid var(--brd,#e2e8f0);border-radius:8px;padding:16px;margin-bottom:12px}
.inv-export-section h3{margin:0 0 8px;font-size:.9rem;font-weight:600}
.inv-export-section p{margin:0 0 10px;font-size:.8rem;color:var(--mut,#64748b)}
.inv-type-dot{display:inline-block;width:8px;height:8px;border-radius:50%;flex-shrink:0}
.inv-related-list{display:flex;flex-direction:column;gap:4px;max-height:200px;overflow-y:auto}
.inv-related-row{display:flex;align-items:center;gap:8px;padding:5px 8px;font-size:.8rem;border-radius:4px}
.inv-related-row:hover{background:var(--hover,#f1f5f9)}
html[data-style="dark"] .inv-card,html[data-style="dark"] .inv-entity-card,html[data-style="dark"] .inv-stat,html[data-style="dark"] .inv-note,html[data-style="dark"] .inv-finding,html[data-style="dark"] .inv-export-section,html[data-style="dark"] .inv-modal{background:var(--card-bg,#1e293b);border-color:var(--brd,#334155)}
html[data-style="dark"] .inv-input,html[data-style="dark"] .inv-textarea,html[data-style="dark"] .inv-select,html[data-style="dark"] .inv-search{background:var(--card-bg,#1e293b);border-color:var(--brd,#334155);color:var(--txt,#e2e8f0)}
html[data-style="classic"] .inv-card,html[data-style="classic"] .inv-entity-card,html[data-style="classic"] .inv-stat,html[data-style="classic"] .inv-note,html[data-style="classic"] .inv-finding,html[data-style="classic"] .inv-export-section,html[data-style="classic"] .inv-modal{background:var(--card-bg,#0f1923);border-color:var(--brd,#1a2a3a)}
html[data-style="classic"] .inv-input,html[data-style="classic"] .inv-textarea,html[data-style="classic"] .inv-select,html[data-style="classic"] .inv-search{background:var(--card-bg,#0f1923);border-color:var(--brd,#1a2a3a);color:var(--txt,#d0d8e0)}
</style>`;

function sevBadge(sev) {
  if (!sev) return '';
  const c = SEV_COLORS[sev] || '#64748b';
  return `<span class="inv-badge inv-sev" style="background:${c}">${esc(sev)}</span>`;
}

function typeBadge(type) {
  if (!type) return '';
  const c = TYPE_COLORS[type] || '#64748b';
  return `<span class="inv-badge" style="background:${c}20;color:${c};border:1px solid ${c}40">${esc(type)}</span>`;
}

function timeAgo(ts) {
  if (!ts) return '';
  const diff = Date.now() - new Date(ts).getTime();
  if (diff < 60000) return 'just now';
  if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
  if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
  return Math.floor(diff / 86400000) + 'd ago';
}

function shortDate(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

function shortTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  return d.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function getAuthor() {
  try { return localStorage.getItem('sw_user_name') || 'Analyst'; } catch (_) { return 'Analyst'; }
}

// ---- List View ----
function renderListView(main, show) {
  const investigations = listEntities({ type: 'INVESTIGATION' });
  investigations.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));

  let filterStatus = '';
  let searchQuery = '';

  function renderList() {
    let filtered = investigations;
    if (filterStatus) filtered = filtered.filter(i => i.status === filterStatus);
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      filtered = filtered.filter(i => i.name.toLowerCase().includes(q) || (i.data.description || '').toLowerCase().includes(q));
    }

    const listEl = main.querySelector('#inv-list');
    if (!listEl) return;

    if (filtered.length === 0) {
      listEl.innerHTML = `<div class="inv-empty">${searchQuery || filterStatus ? 'No investigations match your filters.' : 'No investigations yet. Create one to start collecting evidence and findings.'}</div>`;
      return;
    }

    listEl.innerHTML = `<div class="inv-grid">${filtered.map(inv => {
      const related = getRelated(inv.id);
      const entityCount = related.filter(r => r.type !== 'EVENT' && r.type !== 'FINDING').length;
      const findingCount = related.filter(r => r.type === 'FINDING').length;
      return `<div class="inv-card" data-inv-id="${esc(inv.id)}">
        <div class="inv-card-h">
          <h3>${esc(inv.name)}</h3>
          ${sevBadge(inv.severity)}
        </div>
        <p class="inv-card-desc">${esc(inv.data.description || 'No description')}</p>
        <div class="inv-card-meta">
          <span class="inv-status-badge inv-badge">${esc(inv.status || 'OPEN')}</span>
          <span>${entityCount} entities</span>
          <span>${findingCount} findings</span>
          <span>${timeAgo(inv.updatedAt)}</span>
        </div>
      </div>`;
    }).join('')}</div>`;
  }

  main.innerHTML = CSS + `
    <div class="inv-wrap">
      <div class="inv-header">
        <h1>Investigations</h1>
        <button class="inv-btn inv-btn-primary" id="inv-new">+ New Investigation</button>
      </div>
      <div class="inv-filters">
        <input class="inv-search" id="inv-search-input" placeholder="Search investigations..." spellcheck="false">
        <select class="inv-select" id="inv-filter-status">
          <option value="">All statuses</option>
          ${STATUSES.map(s => `<option value="${esc(s)}">${esc(s)}</option>`).join('')}
        </select>
      </div>
      <div id="inv-list"></div>
    </div>`;

  renderList();

  main.querySelector('#inv-new').onclick = () => {
    const inv = createEntity({
      type: 'INVESTIGATION',
      name: 'New Investigation — ' + shortDate(Date.now()),
      data: { description: '', notes: [], owner: getAuthor() },
      severity: 'MEDIUM',
      status: 'OPEN',
      source: 'manual'
    });
    _currentInvId = inv.id;
    _currentView = 'detail';
    _currentTab = 'overview';
    renderDetailView(main, show);
  };

  main.querySelector('#inv-search-input').oninput = debounce((e) => {
    searchQuery = e.target.value.trim();
    renderList();
  }, 200);

  main.querySelector('#inv-filter-status').onchange = (e) => {
    filterStatus = e.target.value;
    renderList();
  };

  main.querySelector('#inv-list').onclick = (e) => {
    const card = e.target.closest('[data-inv-id]');
    if (!card) return;
    _currentInvId = card.dataset.invId;
    _currentView = 'detail';
    _currentTab = 'overview';
    renderDetailView(main, show);
  };
}

// ---- Detail View ----
function renderDetailView(main, show) {
  const inv = getEntity(_currentInvId);
  if (!inv) { renderListView(main, show); return; }

  const TABS = ['overview', 'entities', 'timeline', 'notes', 'findings', 'export'];

  main.innerHTML = CSS + `
    <div class="inv-wrap">
      <div class="inv-detail-header">
        <button class="inv-back" id="inv-back-btn">&larr; Investigations</button>
        <h1 style="flex:1;margin:0;font-size:1.1rem">${esc(inv.name)}</h1>
        ${sevBadge(inv.severity)}
        <span class="inv-status-badge inv-badge">${esc(inv.status || 'OPEN')}</span>
      </div>
      <div class="inv-tabs" id="inv-tabs">
        ${TABS.map(t => `<button class="inv-tab${t === _currentTab ? ' active' : ''}" data-tab="${t}">${t.charAt(0).toUpperCase() + t.slice(1)}</button>`).join('')}
      </div>
      <div class="inv-panel" id="inv-panel"></div>
    </div>`;

  main.querySelector('#inv-back-btn').onclick = () => {
    _currentView = 'list';
    renderListView(main, show);
  };

  main.querySelector('#inv-tabs').onclick = (e) => {
    const tab = e.target.closest('[data-tab]');
    if (!tab) return;
    _currentTab = tab.dataset.tab;
    main.querySelectorAll('.inv-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === _currentTab));
    renderTab(main, show);
  };

  renderTab(main, show);
}

function renderTab(main, show) {
  const panel = main.querySelector('#inv-panel');
  if (!panel) return;
  const inv = getEntity(_currentInvId);
  if (!inv) return;

  switch (_currentTab) {
    case 'overview': renderOverviewTab(panel, inv, main, show); break;
    case 'entities': renderEntitiesTab(panel, inv, main, show); break;
    case 'timeline': renderTimelineTab(panel, inv, main, show); break;
    case 'notes': renderNotesTab(panel, inv, main, show); break;
    case 'findings': renderFindingsTab(panel, inv, main, show); break;
    case 'export': renderExportTab(panel, inv); break;
  }
}

// ---- Overview Tab ----
function renderOverviewTab(panel, inv, main, show) {
  const related = getRelated(inv.id);
  const entityCount = related.filter(r => r.type !== 'EVENT' && r.type !== 'FINDING').length;
  const findingCount = related.filter(r => r.type === 'FINDING').length;
  const noteCount = (inv.data.notes || []).length;
  const eventCount = related.filter(r => r.type === 'EVENT').length;

  panel.innerHTML = `
    <div class="inv-stats">
      <div class="inv-stat"><div class="inv-stat-n">${entityCount}</div><div class="inv-stat-l">Entities</div></div>
      <div class="inv-stat"><div class="inv-stat-n">${findingCount}</div><div class="inv-stat-l">Findings</div></div>
      <div class="inv-stat"><div class="inv-stat-n">${noteCount}</div><div class="inv-stat-l">Notes</div></div>
      <div class="inv-stat"><div class="inv-stat-n">${eventCount}</div><div class="inv-stat-l">Events</div></div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
      <div>
        <div class="inv-field">
          <label>Name</label>
          <input class="inv-input" id="inv-o-name" value="${esc(inv.name)}">
        </div>
        <div class="inv-field">
          <label>Owner</label>
          <input class="inv-input" id="inv-o-owner" value="${esc(inv.data.owner || '')}">
        </div>
        <div class="inv-form-row">
          <div class="inv-field">
            <label>Status</label>
            <select class="inv-select" id="inv-o-status" style="width:100%">
              ${STATUSES.map(s => `<option value="${esc(s)}"${s === inv.status ? ' selected' : ''}>${esc(s)}</option>`).join('')}
            </select>
          </div>
          <div class="inv-field">
            <label>Severity</label>
            <select class="inv-select" id="inv-o-severity" style="width:100%">
              ${SEVERITIES.map(s => `<option value="${esc(s)}"${s === inv.severity ? ' selected' : ''}>${esc(s)}</option>`).join('')}
            </select>
          </div>
        </div>
        <div class="inv-field">
          <label>Description</label>
          <textarea class="inv-textarea" id="inv-o-desc" rows="4">${esc(inv.data.description || '')}</textarea>
        </div>
        <button class="inv-btn inv-btn-primary inv-btn-sm" id="inv-o-save">Save Changes</button>
        <button class="inv-btn inv-btn-danger inv-btn-sm" id="inv-o-delete" style="margin-left:8px">Delete Investigation</button>
      </div>
      <div>
        <div class="inv-field">
          <label>Related Entities (${entityCount})</label>
          <div class="inv-related-list" id="inv-o-related">
            ${related.filter(r => r.type !== 'EVENT' && r.type !== 'FINDING').length === 0
              ? '<div class="inv-empty" style="padding:16px">No entities yet. Go to the Entities tab to add some.</div>'
              : related.filter(r => r.type !== 'EVENT' && r.type !== 'FINDING').slice(0, 20).map(e =>
                `<div class="inv-related-row">
                  <span class="inv-type-dot" style="background:${TYPE_COLORS[e.type] || '#64748b'}"></span>
                  ${typeBadge(e.type)}
                  <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(e.name)}</span>
                </div>`).join('')}
          </div>
        </div>
        <div class="inv-field" style="margin-top:12px">
          <label>Metadata</label>
          <div style="font-size:.78rem;color:var(--mut,#64748b)">
            <div>Created: ${shortTime(inv.createdAt)}</div>
            <div>Updated: ${shortTime(inv.updatedAt)}</div>
            <div>ID: <span style="font-family:monospace;font-size:.72rem">${esc(inv.id)}</span></div>
          </div>
        </div>
      </div>
    </div>`;

  const saveOverview = () => {
    updateEntity(inv.id, {
      name: panel.querySelector('#inv-o-name').value.trim() || inv.name,
      status: panel.querySelector('#inv-o-status').value,
      severity: panel.querySelector('#inv-o-severity').value,
      data: {
        ...inv.data,
        description: panel.querySelector('#inv-o-desc').value,
        owner: panel.querySelector('#inv-o-owner').value.trim()
      }
    });
    const h1 = main.querySelector('.inv-detail-header h1');
    if (h1) h1.textContent = panel.querySelector('#inv-o-name').value.trim() || inv.name;
  };

  panel.querySelector('#inv-o-save').onclick = () => {
    saveOverview();
    renderDetailView(main, show);
  };

  panel.querySelector('#inv-o-delete').onclick = () => {
    if (!confirm('Delete this investigation and all related findings/events? This cannot be undone.')) return;
    const related = getRelated(inv.id);
    related.forEach(r => {
      if (r.type === 'EVENT' || r.type === 'FINDING') deleteEntity(r.id);
    });
    deleteEntity(inv.id);
    _currentView = 'list';
    renderListView(main, show);
  };
}

// ---- Entities Tab ----
function renderEntitiesTab(panel, inv, main, show) {
  const related = getRelated(inv.id).filter(r => r.type !== 'EVENT' && r.type !== 'FINDING');

  panel.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
      <span style="font-size:.82rem;color:var(--mut,#64748b)">${related.length} entities collected</span>
      <button class="inv-btn inv-btn-primary inv-btn-sm" id="inv-add-entity">+ Add Entity</button>
    </div>
    <div class="inv-entity-grid" id="inv-entity-list">
      ${related.length === 0
        ? '<div class="inv-empty" style="grid-column:1/-1">No entities collected yet. Click "Add Entity" to search and add security objects.</div>'
        : related.map(e => `<div class="inv-entity-card" data-entity-id="${esc(e.id)}">
            <span class="inv-type-dot" style="background:${TYPE_COLORS[e.type] || '#64748b'};margin-top:4px"></span>
            <div class="inv-entity-info">
              <h4>${esc(e.name)}</h4>
              <p>${typeBadge(e.type)} ${e.severity ? sevBadge(e.severity) : ''} ${e.source ? '<span style="font-size:.7rem;color:var(--mut,#94a3b8)">via ' + esc(e.source) + '</span>' : ''}</p>
            </div>
            <button class="inv-entity-remove" data-remove-id="${esc(e.id)}" title="Remove from investigation">x</button>
          </div>`).join('')}
    </div>`;

  panel.querySelector('#inv-add-entity').onclick = () => openEntitySearchModal(inv.id, () => renderEntitiesTab(panel, getEntity(inv.id), main, show));

  panel.querySelector('#inv-entity-list').onclick = (e) => {
    const removeBtn = e.target.closest('[data-remove-id]');
    if (removeBtn) {
      e.stopPropagation();
      const rels = getRelationships(inv.id);
      const rel = rels.find(r => r.targetId === removeBtn.dataset.removeId || r.sourceId === removeBtn.dataset.removeId);
      if (rel) {
        const allRels = getRelationships();
        const idx = allRels.findIndex(r => r.id === rel.id);
        if (idx >= 0) {
          allRels.splice(idx, 1);
          try { localStorage.setItem('dn_sg_relationships', JSON.stringify(allRels)); } catch (_) {}
        }
      }
      renderEntitiesTab(panel, getEntity(inv.id), main, show);
    }
  };
}

function openEntitySearchModal(invId, onDone) {
  const existing = document.querySelector('.inv-modal-overlay');
  if (existing) existing.remove();

  const overlay = document.createElement('div');
  overlay.className = 'inv-modal-overlay';
  const allEntities = listEntities().filter(e => e.type !== 'INVESTIGATION' && e.id !== invId);
  const related = getRelated(invId);
  const relatedIds = new Set(related.map(r => r.id));

  overlay.innerHTML = `
    <div class="inv-modal">
      <div class="inv-modal-h">
        <h2>Add Entity to Investigation</h2>
        <button class="inv-modal-close" id="inv-modal-close">x</button>
      </div>
      <div style="padding:8px 20px;border-bottom:1px solid var(--brd,#e2e8f0)">
        <input class="inv-search" id="inv-entity-search" placeholder="Search entities by name, type..." style="width:100%;box-sizing:border-box" spellcheck="false">
      </div>
      <div class="inv-modal-body" id="inv-modal-results"></div>
    </div>`;
  document.body.appendChild(overlay);

  const close = () => { overlay.remove(); if (onDone) onDone(); };
  overlay.querySelector('#inv-modal-close').onclick = close;
  overlay.onclick = (e) => { if (e.target === overlay) close(); };

  function renderResults(query) {
    const results = query ? search(query).filter(e => e.type !== 'INVESTIGATION') : allEntities.slice(0, 50);
    const container = overlay.querySelector('#inv-modal-results');
    if (results.length === 0) {
      container.innerHTML = '<div class="inv-empty">No entities found. Create entities from tools first.</div>';
      return;
    }
    container.innerHTML = results.map(e => {
      const alreadyAdded = relatedIds.has(e.id);
      return `<div class="inv-modal-item" data-add-id="${esc(e.id)}">
        <span class="inv-type-dot" style="background:${TYPE_COLORS[e.type] || '#64748b'}"></span>
        ${typeBadge(e.type)}
        <span class="inv-modal-item-name">${esc(e.name)}</span>
        ${alreadyAdded
          ? '<span style="font-size:.72rem;color:var(--ok,#22c55e);font-weight:600">ADDED</span>'
          : `<button class="inv-btn inv-btn-primary inv-btn-sm" data-add-btn="${esc(e.id)}">Add</button>`}
      </div>`;
    }).join('');
  }

  renderResults('');

  overlay.querySelector('#inv-entity-search').oninput = debounce((e) => {
    renderResults(e.target.value.trim());
  }, 200);
  overlay.querySelector('#inv-entity-search').focus();

  overlay.querySelector('#inv-modal-results').onclick = (e) => {
    const btn = e.target.closest('[data-add-btn]');
    if (!btn) return;
    createRelationship({
      sourceId: invId,
      targetId: btn.dataset.addBtn,
      type: 'CONTAINS'
    });
    relatedIds.add(btn.dataset.addBtn);
    const item = btn.closest('.inv-modal-item');
    if (item) {
      btn.replaceWith(Object.assign(document.createElement('span'), {
        style: 'font-size:.72rem;color:var(--ok,#22c55e);font-weight:600',
        textContent: 'ADDED'
      }));
    }
  };
}

// ---- Timeline Tab ----
function renderTimelineTab(panel, inv, main, show) {
  const events = getRelated(inv.id).filter(r => r.type === 'EVENT');
  events.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  const EVENT_TYPES = ['ACTION', 'OBSERVATION', 'NOTE', 'FINDING'];
  const EVENT_COLORS = { ACTION: '#2563eb', OBSERVATION: '#f59e0b', NOTE: '#64748b', FINDING: '#8b5cf6' };

  panel.innerHTML = `
    <div style="margin-bottom:16px;background:var(--card-bg,#fff);border:1px solid var(--brd,#e2e8f0);border-radius:8px;padding:12px">
      <div style="font-size:.78rem;font-weight:600;color:var(--mut,#64748b);margin-bottom:8px;text-transform:uppercase;letter-spacing:.04em">Add Timeline Entry</div>
      <div class="inv-form-row">
        <div class="inv-field" style="flex:2">
          <input class="inv-input" id="inv-tl-desc" placeholder="What happened?">
        </div>
        <div class="inv-field" style="flex:0 0 130px">
          <select class="inv-select" id="inv-tl-type" style="width:100%">
            ${EVENT_TYPES.map(t => `<option value="${esc(t)}">${esc(t)}</option>`).join('')}
          </select>
        </div>
        <button class="inv-btn inv-btn-primary inv-btn-sm" id="inv-tl-add">Add</button>
      </div>
    </div>
    <div class="inv-timeline" id="inv-tl-list">
      ${events.length === 0
        ? '<div class="inv-empty">No timeline entries yet.</div>'
        : events.map(ev => `<div class="inv-tl-item">
            <div class="inv-tl-dot" style="background:${EVENT_COLORS[ev.data.eventType] || '#64748b'}"></div>
            <div class="inv-tl-content">
              <strong>${esc(ev.name)}</strong>
              <p>${ev.data.eventType ? `<span class="inv-tl-type" style="color:${EVENT_COLORS[ev.data.eventType] || '#64748b'}">${esc(ev.data.eventType)}</span> ` : ''}${ev.source ? 'by ' + esc(ev.source) : ''}</p>
            </div>
            <span class="inv-tl-time">${shortTime(ev.createdAt)}</span>
          </div>`).join('')}
    </div>`;

  panel.querySelector('#inv-tl-add').onclick = () => {
    const desc = panel.querySelector('#inv-tl-desc').value.trim();
    if (!desc) return;
    const eventType = panel.querySelector('#inv-tl-type').value;
    const event = createEntity({
      type: 'EVENT',
      name: desc,
      data: { eventType },
      source: getAuthor(),
      status: 'OPEN'
    });
    createRelationship({ sourceId: inv.id, targetId: event.id, type: 'CONTAINS' });
    renderTimelineTab(panel, getEntity(inv.id), main, show);
  };
}

// ---- Notes Tab ----
function renderNotesTab(panel, inv, main, show) {
  const notes = inv.data.notes || [];

  panel.innerHTML = `
    <div style="margin-bottom:16px;background:var(--card-bg,#fff);border:1px solid var(--brd,#e2e8f0);border-radius:8px;padding:12px">
      <div style="font-size:.78rem;font-weight:600;color:var(--mut,#64748b);margin-bottom:8px;text-transform:uppercase;letter-spacing:.04em">Add Note</div>
      <textarea class="inv-textarea" id="inv-note-text" rows="3" placeholder="Write your analysis, observations, or findings..."></textarea>
      <div style="margin-top:8px"><button class="inv-btn inv-btn-primary inv-btn-sm" id="inv-note-add">Add Note</button></div>
    </div>
    <div id="inv-notes-list">
      ${notes.length === 0
        ? '<div class="inv-empty">No notes yet.</div>'
        : notes.slice().reverse().map((n, i) => `<div class="inv-note">
            <div class="inv-note-header">
              <span class="inv-note-meta">${esc(n.author || 'Analyst')} -- ${shortTime(n.ts)}</span>
              <button class="inv-btn inv-btn-danger inv-btn-sm" data-note-del="${notes.length - 1 - i}">Delete</button>
            </div>
            <div class="inv-note-body">${esc(n.content)}</div>
          </div>`).join('')}
    </div>`;

  panel.querySelector('#inv-note-add').onclick = () => {
    const text = panel.querySelector('#inv-note-text').value.trim();
    if (!text) return;
    const updatedNotes = [...(inv.data.notes || []), { content: text, author: getAuthor(), ts: new Date().toISOString() }];
    updateEntity(inv.id, { data: { ...inv.data, notes: updatedNotes } });
    renderNotesTab(panel, getEntity(inv.id), main, show);
  };

  panel.querySelector('#inv-notes-list').onclick = (e) => {
    const btn = e.target.closest('[data-note-del]');
    if (!btn) return;
    const idx = parseInt(btn.dataset.noteDel, 10);
    const updatedNotes = [...(inv.data.notes || [])];
    updatedNotes.splice(idx, 1);
    updateEntity(inv.id, { data: { ...inv.data, notes: updatedNotes } });
    renderNotesTab(panel, getEntity(inv.id), main, show);
  };
}

// ---- Findings Tab ----
function renderFindingsTab(panel, inv, main, show) {
  const findings = getRelated(inv.id).filter(r => r.type === 'FINDING');
  findings.sort((a, b) => {
    const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    return (sevOrder[a.severity] || 5) - (sevOrder[b.severity] || 5);
  });

  panel.innerHTML = `
    <div style="margin-bottom:16px;background:var(--card-bg,#fff);border:1px solid var(--brd,#e2e8f0);border-radius:8px;padding:14px">
      <div style="font-size:.78rem;font-weight:600;color:var(--mut,#64748b);margin-bottom:8px;text-transform:uppercase;letter-spacing:.04em">Create Finding</div>
      <div class="inv-form-row">
        <div class="inv-field" style="flex:2">
          <label>Title</label>
          <input class="inv-input" id="inv-f-title" placeholder="Finding title">
        </div>
        <div class="inv-field" style="flex:0 0 120px">
          <label>Severity</label>
          <select class="inv-select" id="inv-f-sev" style="width:100%">
            ${SEVERITIES.map(s => `<option value="${esc(s)}"${s === 'MEDIUM' ? ' selected' : ''}>${esc(s)}</option>`).join('')}
          </select>
        </div>
      </div>
      <div class="inv-field">
        <label>Description</label>
        <textarea class="inv-textarea" id="inv-f-desc" rows="2" placeholder="Describe the finding..."></textarea>
      </div>
      <div class="inv-field">
        <label>Remediation</label>
        <textarea class="inv-textarea" id="inv-f-remediation" rows="2" placeholder="Recommended remediation steps..."></textarea>
      </div>
      <button class="inv-btn inv-btn-primary inv-btn-sm" id="inv-f-create">Create Finding</button>
    </div>
    <div id="inv-findings-list">
      ${findings.length === 0
        ? '<div class="inv-empty">No findings yet.</div>'
        : findings.map(f => `<div class="inv-finding" style="border-left-color:${SEV_COLORS[f.severity] || '#8b5cf6'}">
            <h4>${sevBadge(f.severity)} ${esc(f.name)}</h4>
            <p>${esc(f.data.description || '')}</p>
            ${f.data.remediation ? `<p style="color:var(--ok,#22c55e)"><strong>Remediation:</strong> ${esc(f.data.remediation)}</p>` : ''}
            <div style="font-size:.72rem;color:var(--mut,#94a3b8);margin-top:4px">Created ${shortTime(f.createdAt)} ${f.source ? 'by ' + esc(f.source) : ''}</div>
            <div class="inv-finding-actions">
              <button class="inv-btn inv-btn-danger inv-btn-sm" data-finding-del="${esc(f.id)}">Delete</button>
            </div>
          </div>`).join('')}
    </div>`;

  panel.querySelector('#inv-f-create').onclick = () => {
    const title = panel.querySelector('#inv-f-title').value.trim();
    if (!title) return;
    const finding = createEntity({
      type: 'FINDING',
      name: title,
      severity: panel.querySelector('#inv-f-sev').value,
      data: {
        description: panel.querySelector('#inv-f-desc').value.trim(),
        remediation: panel.querySelector('#inv-f-remediation').value.trim()
      },
      source: getAuthor(),
      status: 'OPEN'
    });
    createRelationship({ sourceId: inv.id, targetId: finding.id, type: 'CONTAINS' });
    renderFindingsTab(panel, getEntity(inv.id), main, show);
  };

  panel.querySelector('#inv-findings-list').onclick = (e) => {
    const btn = e.target.closest('[data-finding-del]');
    if (!btn) return;
    deleteEntity(btn.dataset.findingDel);
    renderFindingsTab(panel, getEntity(inv.id), main, show);
  };
}

// ---- Export Tab ----
function renderExportTab(panel, inv) {
  const related = getRelated(inv.id);
  const entities = related.filter(r => r.type !== 'EVENT' && r.type !== 'FINDING');
  const findings = related.filter(r => r.type === 'FINDING');
  const events = related.filter(r => r.type === 'EVENT');
  const notes = inv.data.notes || [];

  panel.innerHTML = `
    <div class="inv-stats" style="margin-bottom:20px">
      <div class="inv-stat"><div class="inv-stat-n">${entities.length}</div><div class="inv-stat-l">Entities</div></div>
      <div class="inv-stat"><div class="inv-stat-n">${findings.length}</div><div class="inv-stat-l">Findings</div></div>
      <div class="inv-stat"><div class="inv-stat-n">${events.length}</div><div class="inv-stat-l">Events</div></div>
      <div class="inv-stat"><div class="inv-stat-n">${notes.length}</div><div class="inv-stat-l">Notes</div></div>
    </div>
    <div class="inv-export-section">
      <h3>Export as JSON</h3>
      <p>Download the full investigation including all entities, relationships, findings, events, and notes as a structured JSON file.</p>
      <button class="inv-btn inv-btn-primary" id="inv-export-json">Download JSON</button>
    </div>
    <div class="inv-export-section">
      <h3>Generate Text Report</h3>
      <p>Generate a structured text report suitable for sharing or archiving.</p>
      <button class="inv-btn inv-btn-primary" id="inv-export-report">Generate Report</button>
      <div id="inv-report-output" style="margin-top:12px"></div>
    </div>`;

  panel.querySelector('#inv-export-json').onclick = () => {
    const data = {
      investigation: inv,
      entities: entities,
      findings: findings,
      events: events.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt)),
      relationships: getRelationships(inv.id),
      exportedAt: new Date().toISOString(),
      exportedBy: getAuthor()
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `investigation-${inv.name.replace(/[^a-zA-Z0-9]/g, '-').toLowerCase()}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  panel.querySelector('#inv-export-report').onclick = () => {
    const lines = [];
    lines.push('=' .repeat(60));
    lines.push('INVESTIGATION REPORT');
    lines.push('=' .repeat(60));
    lines.push('');
    lines.push(`Name:        ${inv.name}`);
    lines.push(`Status:      ${inv.status}`);
    lines.push(`Severity:    ${inv.severity}`);
    lines.push(`Owner:       ${inv.data.owner || 'Unassigned'}`);
    lines.push(`Created:     ${shortTime(inv.createdAt)}`);
    lines.push(`Updated:     ${shortTime(inv.updatedAt)}`);
    lines.push('');
    if (inv.data.description) {
      lines.push('DESCRIPTION');
      lines.push('-'.repeat(40));
      lines.push(inv.data.description);
      lines.push('');
    }
    if (findings.length > 0) {
      lines.push('FINDINGS (' + findings.length + ')');
      lines.push('-'.repeat(40));
      findings.forEach((f, i) => {
        lines.push(`  ${i + 1}. [${f.severity}] ${f.name}`);
        if (f.data.description) lines.push(`     ${f.data.description}`);
        if (f.data.remediation) lines.push(`     Remediation: ${f.data.remediation}`);
        lines.push('');
      });
    }
    if (entities.length > 0) {
      lines.push('ENTITIES (' + entities.length + ')');
      lines.push('-'.repeat(40));
      entities.forEach(e => {
        lines.push(`  [${e.type}] ${e.name}${e.severity ? ' (' + e.severity + ')' : ''}`);
      });
      lines.push('');
    }
    if (events.length > 0) {
      const sorted = events.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
      lines.push('TIMELINE (' + sorted.length + ' events)');
      lines.push('-'.repeat(40));
      sorted.forEach(ev => {
        lines.push(`  ${shortTime(ev.createdAt)} [${ev.data.eventType || 'EVENT'}] ${ev.name}`);
      });
      lines.push('');
    }
    if (notes.length > 0) {
      lines.push('NOTES (' + notes.length + ')');
      lines.push('-'.repeat(40));
      notes.forEach(n => {
        lines.push(`  ${shortTime(n.ts)} (${n.author || 'Analyst'}):`);
        lines.push(`  ${n.content}`);
        lines.push('');
      });
    }
    lines.push('');
    lines.push('Report generated: ' + new Date().toISOString());
    lines.push('Generated by: Darknode Investigation Workspace');

    const reportText = lines.join('\n');
    const output = panel.querySelector('#inv-report-output');
    output.innerHTML = `<pre style="background:var(--card-bg,#f8fafc);border:1px solid var(--brd,#e2e8f0);border-radius:6px;padding:12px;font-size:.76rem;white-space:pre-wrap;max-height:400px;overflow-y:auto;font-family:monospace;line-height:1.6">${esc(reportText)}</pre>
      <div style="margin-top:8px;display:flex;gap:8px">
        <button class="inv-btn inv-btn-ghost inv-btn-sm" id="inv-copy-report">Copy to Clipboard</button>
        <button class="inv-btn inv-btn-ghost inv-btn-sm" id="inv-dl-report">Download .txt</button>
      </div>`;

    output.querySelector('#inv-copy-report').onclick = () => {
      navigator.clipboard.writeText(reportText).catch(() => {});
    };

    output.querySelector('#inv-dl-report').onclick = () => {
      const blob = new Blob([reportText], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `report-${inv.name.replace(/[^a-zA-Z0-9]/g, '-').toLowerCase()}.txt`;
      a.click();
      URL.revokeObjectURL(url);
    };
  };
}

// ---- Add-to-Investigation modal (callable from any tool) ----
export function openAddToInvestigation(entity) {
  const existing = document.querySelector('.inv-modal-overlay');
  if (existing) existing.remove();

  const investigations = listEntities({ type: 'INVESTIGATION' });
  investigations.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));

  const overlay = document.createElement('div');
  overlay.className = 'inv-modal-overlay';

  // Inject CSS if not present
  if (!document.querySelector('#inv-modal-css')) {
    const style = document.createElement('style');
    style.id = 'inv-modal-css';
    style.textContent = CSS.replace(/<\/?style>/g, '');
    document.head.appendChild(style);
  }

  overlay.innerHTML = `
    <div class="inv-modal">
      <div class="inv-modal-h">
        <h2>Add to Investigation</h2>
        <button class="inv-modal-close" id="inv-ati-close">x</button>
      </div>
      <div class="inv-modal-body">
        <div style="margin-bottom:12px;padding:10px;background:var(--hover,#f1f5f9);border-radius:6px;display:flex;align-items:center;gap:8px">
          <span class="inv-type-dot" style="background:${TYPE_COLORS[entity.type] || '#64748b'}"></span>
          ${typeBadge(entity.type)}
          <span style="font-weight:600;font-size:.86rem">${esc(entity.name)}</span>
        </div>
        ${investigations.length === 0
          ? '<div class="inv-empty">No investigations yet.</div>'
          : investigations.map(inv => {
            const related = getRelated(inv.id);
            const alreadyIn = related.some(r => r.id === entity.id);
            return `<div class="inv-modal-item">
              <span class="inv-type-dot" style="background:#2563eb"></span>
              <span class="inv-modal-item-name">${esc(inv.name)}</span>
              <span class="inv-modal-item-meta">${esc(inv.status || 'OPEN')}</span>
              ${alreadyIn
                ? '<span style="font-size:.72rem;color:var(--ok,#22c55e);font-weight:600">ADDED</span>'
                : `<button class="inv-btn inv-btn-primary inv-btn-sm" data-ati-inv="${esc(inv.id)}">Add</button>`}
            </div>`;
          }).join('')}
        <div style="margin-top:12px;padding-top:12px;border-top:1px solid var(--brd,#e2e8f0)">
          <button class="inv-btn inv-btn-ghost" id="inv-ati-new" style="width:100%">+ Create New Investigation</button>
        </div>
      </div>
    </div>`;
  document.body.appendChild(overlay);

  const close = () => overlay.remove();
  overlay.querySelector('#inv-ati-close').onclick = close;
  overlay.onclick = (e) => { if (e.target === overlay) close(); };

  overlay.querySelector('.inv-modal-body').onclick = (e) => {
    const btn = e.target.closest('[data-ati-inv]');
    if (btn) {
      createRelationship({ sourceId: btn.dataset.atiInv, targetId: entity.id, type: 'CONTAINS' });
      const item = btn.closest('.inv-modal-item');
      if (item) {
        btn.replaceWith(Object.assign(document.createElement('span'), {
          style: 'font-size:.72rem;color:var(--ok,#22c55e);font-weight:600',
          textContent: 'ADDED'
        }));
      }
    }
  };

  overlay.querySelector('#inv-ati-new').onclick = () => {
    const inv = createEntity({
      type: 'INVESTIGATION',
      name: 'Investigation — ' + shortDate(Date.now()),
      data: { description: '', notes: [], owner: getAuthor() },
      severity: 'MEDIUM',
      status: 'OPEN',
      source: 'manual'
    });
    createRelationship({ sourceId: inv.id, targetId: entity.id, type: 'CONTAINS' });
    close();
  };
}

// ---- Public API ----
export function renderInvestigation(main) {
  if (_currentView === 'detail' && _currentInvId) {
    renderDetailView(main, (sec) => { _currentView = 'list'; renderListView(main, () => {}); });
  } else {
    _currentView = 'list';
    renderListView(main, () => {});
  }
}

export function cleanupInvestigation() {
  _currentView = 'list';
  _currentInvId = null;
  _currentTab = 'overview';
}
