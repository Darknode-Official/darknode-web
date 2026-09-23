// Copyright (c) 2026 Darknode-Official. All rights reserved.
import { createEntity, getEntity, updateEntity, deleteEntity, listEntities, createRelationship, getRelated, ENTITY_TYPES, SEVERITIES, STATUSES } from '/js/security-graph.js';
import { esc } from '/js/shared.js';

const TYPE_COLORS = {
  CASE: '#2563eb', INCIDENT: '#dc2626', INVESTIGATION: '#8b5cf6',
  ASSET: '#2563eb', VULNERABILITY: '#ef4444', INDICATOR: '#f59e0b',
  FINDING: '#8b5cf6', EVIDENCE: '#0891b2',
};

const CASE_STATUSES = ['new', 'open', 'investigating', 'resolved', 'closed'];
const PRIORITIES = ['P1 - Critical', 'P2 - High', 'P3 - Medium', 'P4 - Low', 'P5 - Info'];

export function renderCaseManager(main) {
  const CSS = `
<style>
.cm-wrap{max-width:none}
.cm-header{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin-bottom:20px}
.cm-tabs{display:flex;gap:4px;margin-bottom:16px;border-bottom:2px solid var(--brd,#e2e8f0);padding-bottom:0}
.cm-tab{padding:8px 18px;border:none;background:none;font-size:.86rem;font-weight:600;cursor:pointer;color:var(--mut,#64748b);border-bottom:2px solid transparent;margin-bottom:-2px;transition:all .15s}
.cm-tab:hover{color:var(--txt,#0f172a)}.cm-tab.active{color:var(--acc,#2563eb);border-bottom-color:var(--acc,#2563eb)}
.cm-stats{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:10px;margin-bottom:20px}
.cm-stat{background:var(--card-bg,#fff);border:1px solid var(--brd,#e2e8f0);border-radius:8px;padding:12px 14px;text-align:center}
.cm-stat-n{font-size:1.3rem;font-weight:800;color:var(--txt,#0f172a)}.cm-stat-l{font-size:.7rem;color:var(--mut,#64748b);text-transform:uppercase;letter-spacing:.05em;margin-top:2px}
.cm-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:12px}
.cm-card{background:var(--card-bg,#fff);border:1px solid var(--brd,#e2e8f0);border-radius:10px;padding:16px;cursor:pointer;transition:box-shadow .15s}
.cm-card:hover{box-shadow:0 2px 8px rgba(0,0,0,.08)}
.cm-card-top{display:flex;align-items:center;gap:8px;margin-bottom:10px}
.cm-card-type{padding:2px 8px;border-radius:4px;color:#fff;font-size:.66rem;font-weight:700;letter-spacing:.03em}
.cm-card-name{font-weight:700;font-size:.92rem;color:var(--txt,#0f172a);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cm-card-prio{padding:2px 8px;border-radius:4px;font-size:.68rem;font-weight:700;background:var(--bg-2,#f1f5f9);color:var(--txt,#0f172a)}
.cm-card-body{font-size:.82rem;color:var(--mut,#64748b);margin-bottom:8px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.cm-card-meta{display:flex;gap:10px;font-size:.72rem;color:var(--mut,#64748b);flex-wrap:wrap}
.cm-card-status{padding:1px 8px;border-radius:10px;font-weight:600;font-size:.68rem}
.cm-status-new{background:#dbeafe;color:#1d4ed8}.cm-status-open{background:#fef3c7;color:#92400e}
.cm-status-investigating{background:#ede9fe;color:#6d28d9}.cm-status-resolved{background:#d1fae5;color:#065f46}.cm-status-closed{background:#f1f5f9;color:#475569}
.cm-detail{background:var(--card-bg,#fff);border:1px solid var(--brd,#e2e8f0);border-radius:12px;padding:24px}
.cm-detail-head{display:flex;align-items:center;gap:12px;margin-bottom:20px}
.cm-detail-back{background:none;border:1px solid var(--brd,#e2e8f0);border-radius:4px;padding:4px 12px;font-size:.82rem;cursor:pointer;color:var(--txt,#0f172a)}
.cm-detail-back:hover{background:var(--bg-2,#f1f5f9)}
.cm-field{margin-bottom:14px}.cm-label{font-size:.76rem;font-weight:600;color:var(--mut,#64748b);text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px}
.cm-input{width:100%;padding:8px 12px;border:1px solid var(--brd,#e2e8f0);border-radius:6px;font-size:.88rem;background:var(--card-bg,#fff);color:var(--txt,#0f172a)}
.cm-textarea{width:100%;padding:8px 12px;border:1px solid var(--brd,#e2e8f0);border-radius:6px;font-size:.84rem;min-height:80px;resize:vertical;background:var(--card-bg,#fff);color:var(--txt,#0f172a);font-family:inherit}
.cm-row{display:flex;gap:12px;flex-wrap:wrap}.cm-row>*{flex:1;min-width:150px}
.cm-related{margin-top:20px;border-top:1px solid var(--brd,#e2e8f0);padding-top:16px}
.cm-related-list{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.cm-related-tag{padding:4px 10px;border-radius:4px;font-size:.78rem;font-weight:600;background:var(--bg-2,#f1f5f9);color:var(--txt,#0f172a);cursor:pointer}
.cm-related-tag:hover{background:var(--acc,#2563eb);color:#fff}
.cm-actions{display:flex;gap:8px;margin-top:16px;padding-top:12px;border-top:1px solid var(--brd,#e2e8f0)}
.cm-btn{padding:6px 16px;border-radius:6px;font-size:.82rem;font-weight:600;cursor:pointer;border:1px solid var(--brd,#e2e8f0);background:var(--card-bg,#fff);color:var(--txt,#0f172a)}
.cm-btn:hover{background:var(--acc,#2563eb);color:#fff;border-color:var(--acc,#2563eb)}
.cm-btn.primary{background:var(--acc,#2563eb);color:#fff;border-color:var(--acc,#2563eb)}.cm-btn.primary:hover{opacity:.9}
.cm-btn.danger{color:#ef4444;border-color:#fecaca}.cm-btn.danger:hover{background:#ef4444;color:#fff}
.cm-new-btn{padding:8px 20px;border-radius:8px;font-size:.88rem;font-weight:600;cursor:pointer;border:none;background:var(--acc,#2563eb);color:#fff}
.cm-new-btn:hover{opacity:.9}
.cm-empty{text-align:center;padding:60px 20px;color:var(--mut,#64748b)}
.cm-empty-title{font-size:1.1rem;font-weight:700;margin-bottom:8px;color:var(--txt,#0f172a)}
html[data-style="dark"] .cm-card,html[data-style="classic"] .cm-card,
html[data-style="dark"] .cm-stat,html[data-style="classic"] .cm-stat,
html[data-style="dark"] .cm-detail,html[data-style="classic"] .cm-detail{background:var(--card-bg,#1e293b);border-color:var(--brd,#334155)}
html[data-style="dark"] .cm-input,html[data-style="classic"] .cm-input,
html[data-style="dark"] .cm-textarea,html[data-style="classic"] .cm-textarea{background:var(--card-bg,#1e293b);border-color:var(--brd,#334155);color:var(--txt,#e2e8f0)}
</style>`;

  let _tab = 'cases';
  let _detailId = null;

  function renderList() {
    const typeFilter = _tab === 'cases' ? 'CASE' : 'INCIDENT';
    const items = listEntities({ type: typeFilter });
    const cases = listEntities({ type: 'CASE' });
    const incidents = listEntities({ type: 'INCIDENT' });
    const openCases = cases.filter(c => c.status !== 'closed' && c.status !== 'resolved');
    const openIncidents = incidents.filter(c => c.status !== 'closed' && c.status !== 'resolved');
    const criticalCount = [...cases, ...incidents].filter(c => c.severity === 'critical' || c.severity === 'high').length;

    main.innerHTML = CSS + `
      <div class="cm-wrap">
        <div class="cm-header">
          <h1 class="pg-h1" style="margin:0">Case Manager</h1>
          <span style="flex:1"></span>
          <button class="cm-new-btn" id="cm-new">New ${_tab === 'cases' ? 'Case' : 'Incident'}</button>
        </div>
        <div class="cm-stats">
          <div class="cm-stat"><div class="cm-stat-n">${cases.length}</div><div class="cm-stat-l">Total Cases</div></div>
          <div class="cm-stat"><div class="cm-stat-n">${openCases.length}</div><div class="cm-stat-l">Open Cases</div></div>
          <div class="cm-stat"><div class="cm-stat-n">${incidents.length}</div><div class="cm-stat-l">Total Incidents</div></div>
          <div class="cm-stat"><div class="cm-stat-n">${openIncidents.length}</div><div class="cm-stat-l">Open Incidents</div></div>
          <div class="cm-stat"><div class="cm-stat-n">${criticalCount}</div><div class="cm-stat-l">Critical/High</div></div>
        </div>
        <div class="cm-tabs">
          <button class="cm-tab${_tab === 'cases' ? ' active' : ''}" data-tab="cases">Cases (${cases.length})</button>
          <button class="cm-tab${_tab === 'incidents' ? ' active' : ''}" data-tab="incidents">Incidents (${incidents.length})</button>
        </div>
        ${items.length === 0 ? `
          <div class="cm-empty">
            <div class="cm-empty-title">No ${_tab} yet</div>
            <p>Create a new ${_tab === 'cases' ? 'case' : 'incident'} to start tracking security events and investigations.</p>
          </div>
        ` : `
          <div class="cm-grid">
            ${items.map(item => {
              const color = TYPE_COLORS[item.type] || '#64748b';
              const related = getRelated(item.id);
              const prio = (item.data || {}).priority || '';
              const owner = (item.data || {}).owner || '';
              const statusClass = 'cm-status-' + (item.status || 'new');
              return `
                <div class="cm-card" data-cid="${esc(item.id)}">
                  <div class="cm-card-top">
                    <span class="cm-card-type" style="background:${color}">${esc(item.type)}</span>
                    <span class="cm-card-name">${esc(item.name)}</span>
                    <span class="cm-card-status ${statusClass}">${esc(item.status || 'new')}</span>
                  </div>
                  ${(item.data || {}).description ? `<div class="cm-card-body">${esc(item.data.description)}</div>` : ''}
                  <div class="cm-card-meta">
                    ${prio ? `<span class="cm-card-prio">${esc(prio)}</span>` : ''}
                    ${item.severity ? `<span>${esc(item.severity)}</span>` : ''}
                    ${owner ? `<span>Owner: ${esc(owner)}</span>` : ''}
                    <span>${related.length} related</span>
                    <span>${new Date(item.updatedAt).toLocaleDateString()}</span>
                  </div>
                </div>`;
            }).join('')}
          </div>
        `}
      </div>`;

    main.querySelectorAll('.cm-tab').forEach(t => {
      t.onclick = () => { _tab = t.dataset.tab; renderList(); };
    });

    main.querySelectorAll('.cm-card').forEach(card => {
      card.onclick = () => { _detailId = card.dataset.cid; renderDetail(); };
    });

    main.querySelector('#cm-new').onclick = () => {
      const name = prompt((_tab === 'cases' ? 'Case' : 'Incident') + ' name:');
      if (!name) return;
      const type = _tab === 'cases' ? 'CASE' : 'INCIDENT';
      const entity = createEntity(type, name.trim(), {
        description: '',
        priority: '',
        owner: '',
        team: '',
        timeline: [],
      }, { status: 'new' });
      _detailId = entity.id;
      renderDetail();
    };
  }

  function renderDetail() {
    const item = getEntity(_detailId);
    if (!item) { _detailId = null; renderList(); return; }
    const color = TYPE_COLORS[item.type] || '#64748b';
    const related = getRelated(item.id);
    const data = item.data || {};
    const timeline = data.timeline || [];

    main.innerHTML = CSS + `
      <div class="cm-wrap">
        <div class="cm-detail">
          <div class="cm-detail-head">
            <button class="cm-detail-back" id="cm-back">Back</button>
            <span class="cm-card-type" style="background:${color}">${esc(item.type)}</span>
            <h2 style="margin:0;flex:1;font-size:1.1rem">${esc(item.name)}</h2>
          </div>
          <div class="cm-row">
            <div class="cm-field">
              <div class="cm-label">Name</div>
              <input class="cm-input" id="cm-name" value="${esc(item.name)}">
            </div>
            <div class="cm-field">
              <div class="cm-label">Owner</div>
              <input class="cm-input" id="cm-owner" value="${esc(data.owner || '')}" placeholder="Analyst name">
            </div>
          </div>
          <div class="cm-row">
            <div class="cm-field">
              <div class="cm-label">Status</div>
              <select class="cm-input" id="cm-status">
                ${CASE_STATUSES.map(s => `<option value="${s}"${item.status === s ? ' selected' : ''}>${s.charAt(0).toUpperCase() + s.slice(1)}</option>`).join('')}
              </select>
            </div>
            <div class="cm-field">
              <div class="cm-label">Severity</div>
              <select class="cm-input" id="cm-severity">
                ${SEVERITIES.filter(Boolean).map(s => `<option value="${s}"${item.severity === s ? ' selected' : ''}>${s.charAt(0).toUpperCase() + s.slice(1)}</option>`).join('')}
              </select>
            </div>
            <div class="cm-field">
              <div class="cm-label">Priority</div>
              <select class="cm-input" id="cm-prio">
                <option value="">None</option>
                ${PRIORITIES.map(p => `<option value="${p}"${data.priority === p ? ' selected' : ''}>${p}</option>`).join('')}
              </select>
            </div>
          </div>
          <div class="cm-field">
            <div class="cm-label">Description</div>
            <textarea class="cm-textarea" id="cm-desc">${esc(data.description || '')}</textarea>
          </div>
          <div class="cm-field">
            <div class="cm-label">Team / Notes</div>
            <input class="cm-input" id="cm-team" value="${esc(data.team || '')}" placeholder="Team or additional notes">
          </div>
          <div class="cm-actions">
            <button class="cm-btn primary" id="cm-save">Save Changes</button>
            <button class="cm-btn danger" id="cm-delete">Delete</button>
          </div>
          <div class="cm-related">
            <div class="cm-label">Related Entities (${related.length})</div>
            ${related.length ? `
              <div class="cm-related-list">
                ${related.map(r => {
                  const rc = TYPE_COLORS[r.type] || '#64748b';
                  return `<span class="cm-related-tag" title="${esc(r.type)}: ${esc(r.name)}">${esc(r.type)} - ${esc(r.name)}</span>`;
                }).join('')}
              </div>
            ` : '<p class="muted" style="font-size:.82rem;margin-top:8px">No related entities. Link entities from the Security Graph or Investigation Workspace.</p>'}
          </div>
          ${timeline.length ? `
            <div class="cm-related" style="margin-top:16px">
              <div class="cm-label">Timeline (${timeline.length})</div>
              <div style="margin-top:8px">
                ${timeline.map(t => `
                  <div style="display:flex;gap:8px;padding:6px 0;border-bottom:1px solid var(--brd,#e2e8f0);font-size:.82rem">
                    <span style="color:var(--mut,#64748b);min-width:140px">${esc(new Date(t.ts).toLocaleString())}</span>
                    <span style="color:var(--txt,#0f172a)">${esc(t.text)}</span>
                  </div>
                `).join('')}
              </div>
            </div>
          ` : ''}
        </div>
      </div>`;

    main.querySelector('#cm-back').onclick = () => { _detailId = null; renderList(); };

    main.querySelector('#cm-save').onclick = () => {
      const newName = main.querySelector('#cm-name').value.trim();
      const updates = {
        name: newName || item.name,
        status: main.querySelector('#cm-status').value,
        severity: main.querySelector('#cm-severity').value,
        data: {
          ...data,
          description: main.querySelector('#cm-desc').value,
          owner: main.querySelector('#cm-owner').value.trim(),
          priority: main.querySelector('#cm-prio').value,
          team: main.querySelector('#cm-team').value.trim(),
        },
      };
      const newTimeline = [...(data.timeline || [])];
      newTimeline.push({ ts: Date.now(), text: 'Case updated' });
      updates.data.timeline = newTimeline;
      updateEntity(_detailId, updates);
      renderDetail();
    };

    main.querySelector('#cm-delete').onclick = () => {
      if (confirm('Delete this ' + item.type.toLowerCase() + '? This cannot be undone.')) {
        deleteEntity(_detailId);
        _detailId = null;
        renderList();
      }
    };
  }

  renderList();
}
