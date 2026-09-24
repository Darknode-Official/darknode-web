// Darknode Project - CRUCIBLE :: Cyber Defense & Wargaming Command
// Shell: tab bar, shared design system, pillar routing.
// Copyright (c) 2026 Darknode-Official. All rights reserved.
//
// Pillars are separate modules, each exporting one render function:
//   crucible-range.js       -> renderRange(container, ctx)
//   crucible-autopilot.js   -> renderAutopilot(container, ctx)
//   crucible-fusion.js      -> renderFusion(container, ctx)
//   crucible-afteraction.js -> renderAfterAction(container, ctx)
// ctx = { go(tabId), toast(msg, kind), core }  (core = crucible-core exports)
// All shared state, data and the engine live in crucible-core.js.

import * as core from '/js/crucible-core.js?v=20260924b';

const V = '?v=20260924b';
const { esc, CRU } = core;

const TABS = [
  { id: 'range', name: 'Wargame Range', sub: 'Adversary campaigns', mod: 'crucible-range.js', fn: 'renderRange' },
  { id: 'autopilot', name: 'Defense Autopilot', sub: 'Autonomous blue team', mod: 'crucible-autopilot.js', fn: 'renderAutopilot' },
  { id: 'fusion', name: 'Fusion Command', sub: 'Live threat picture', mod: 'crucible-fusion.js', fn: 'renderFusion' },
  { id: 'afteraction', name: 'After-Action', sub: 'Scoring & reporting', mod: 'crucible-afteraction.js', fn: 'renderAfterAction' },
];

let _root = null;
let _toastTimer = null;

function toast(msg, kind = 'info') {
  if (!_root) return;
  let t = _root.querySelector('#cru-toast');
  if (!t) { t = document.createElement('div'); t.id = 'cru-toast'; _root.appendChild(t); }
  t.className = 'cru-toast cru-toast-' + kind;
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => t.classList.remove('show'), 2600);
}

async function loadPillar(tab, container) {
  container.innerHTML = '<div class="cru-loading">Loading ' + esc(tab.name) + '…</div>';
  try {
    const m = await import('/js/' + tab.mod + V);
    if (CRU.tab !== tab.id) return; // navigated away while loading
    const fn = m[tab.fn];
    if (typeof fn !== 'function') { container.innerHTML = '<div class="cru-loading">Pillar ' + esc(tab.name) + ' is not available yet.</div>'; return; }
    container.innerHTML = '';
    fn(container, { go, toast, core });
  } catch (e) {
    container.innerHTML = '<div class="cru-loading">Failed to load ' + esc(tab.name) + '.<br><span style="opacity:.6;font-size:.8rem">' + esc(String(e && e.message || e)) + '</span></div>';
  }
}

function go(tabId) {
  const tab = TABS.find((t) => t.id === tabId) || TABS[0];
  CRU.tab = tab.id;
  if (!_root) return;
  _root.querySelectorAll('.cru-tab').forEach((b) => b.classList.toggle('on', b.dataset.tab === tab.id));
  const container = _root.querySelector('#cru-panel');
  if (container) loadPillar(tab, container);
}

export function renderCrucible(main) {
  main.innerHTML = shellHTML();
  _root = main.querySelector('#crucible-root');
  _root.querySelectorAll('.cru-tab').forEach((b) => { b.onclick = () => go(b.dataset.tab); });
  go(CRU.tab || 'range');
}

export function cleanupCrucible() {
  clearTimeout(_toastTimer);
  _root = null;
}

function shellHTML() {
  const tabs = TABS.map((t) => (
    '<button class="cru-tab' + (t.id === CRU.tab ? ' on' : '') + '" data-tab="' + t.id + '">' +
    '<span class="cru-tab-name">' + esc(t.name) + '</span>' +
    '<span class="cru-tab-sub">' + esc(t.sub) + '</span>' +
    '</button>'
  )).join('');
  return (
    '<style>' + CSS + '</style>' +
    '<div id="crucible-root">' +
      '<header class="cru-head">' +
        '<div class="cru-head-main">' +
          '<div class="cru-mark">CRUCIBLE</div>' +
          '<div class="cru-tagline">Cyber Defense &amp; Wargaming Command</div>' +
        '</div>' +
        '<div class="cru-head-meta">' +
          '<span class="cru-badge">SIMULATION</span>' +
          '<span class="cru-status"><span class="cru-dot"></span>Range online</span>' +
        '</div>' +
      '</header>' +
      '<nav class="cru-tabs">' + tabs + '</nav>' +
      '<section id="cru-panel" class="cru-panel"></section>' +
    '</div>'
  );
}

// Shared design system — inherits the site's theme tokens so it works in
// Professional, Dark and Classic without hard-coded colors. Full width,
// no emojis, 4px control corners (buttons.css also enforces this).
const CSS = `
#crucible-root{width:100%;color:var(--txt);font-size:.9rem}
#crucible-root *{box-sizing:border-box}
.cru-head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;flex-wrap:wrap;padding:0 0 16px;border-bottom:1px solid var(--line);margin-bottom:16px}
.cru-mark{font-size:1.7rem;font-weight:800;letter-spacing:.14em;color:var(--txt)}
.cru-tagline{font-size:.74rem;letter-spacing:.16em;text-transform:uppercase;color:var(--mut);margin-top:2px}
.cru-head-meta{display:flex;align-items:center;gap:10px}
.cru-badge{font-size:.6rem;font-weight:700;letter-spacing:.12em;padding:3px 8px;border:1px solid var(--line);border-radius:4px;color:var(--mut)}
.cru-status{display:inline-flex;align-items:center;gap:6px;font-size:.72rem;color:var(--mut)}
.cru-dot{width:7px;height:7px;border-radius:50%;background:#10b981;box-shadow:0 0 0 3px color-mix(in srgb,#10b981 22%,transparent)}
.cru-tabs{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin-bottom:18px}
.cru-tab{display:flex;flex-direction:column;gap:2px;text-align:left;padding:10px 14px;background:var(--card);border:1px solid var(--line);border-radius:4px;cursor:pointer;font-family:inherit;color:var(--txt);transition:border-color .15s,background .15s}
.cru-tab:hover{border-color:var(--acc)}
.cru-tab.on{border-color:var(--acc);background:color-mix(in srgb,var(--acc) 12%,var(--card));box-shadow:inset 0 0 0 1px var(--acc)}
.cru-tab-name{font-weight:700;font-size:.86rem}
.cru-tab-sub{font-size:.66rem;letter-spacing:.05em;text-transform:uppercase;color:var(--mut)}
.cru-panel{width:100%}
.cru-loading{padding:60px 20px;text-align:center;color:var(--mut)}
/* shared building blocks pillars can use */
.cru-grid{display:grid;gap:14px}
.cru-card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px}
.cru-card h3{margin:0 0 4px;font-size:.95rem}
.cru-sub{color:var(--mut);font-size:.78rem;margin:0 0 12px}
.cru-btn{background:var(--acc);color:#fff;border:none;border-radius:4px;padding:8px 16px;font-weight:600;font-size:.82rem;cursor:pointer;font-family:inherit;display:inline-flex;align-items:center;gap:6px}
.cru-btn:hover{filter:brightness(1.06)}
.cru-btn.ghost{background:transparent;color:var(--txt);border:1px solid var(--line)}
.cru-btn.ghost:hover{border-color:var(--acc);color:var(--acc)}
.cru-btn:disabled{opacity:.45;cursor:default}
.cru-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.cru-kpi{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 16px}
.cru-kpi-n{font-size:1.5rem;font-weight:800;line-height:1}
.cru-kpi-l{font-size:.68rem;letter-spacing:.06em;text-transform:uppercase;color:var(--mut);margin-top:6px}
.cru-sev-critical{color:#dc2626}.cru-sev-high{color:#ea580c}.cru-sev-medium{color:#d97706}.cru-sev-low{color:#16a34a}
.cru-toast{position:fixed;bottom:22px;left:50%;transform:translateX(-50%) translateY(20px);background:var(--txt);color:var(--bg);padding:10px 18px;border-radius:4px;font-size:.82rem;font-weight:600;opacity:0;pointer-events:none;transition:all .2s;z-index:9999}
.cru-toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.cru-toast-good{background:#16a34a;color:#fff}.cru-toast-bad{background:#dc2626;color:#fff}
@media (max-width:900px){.cru-tabs{grid-template-columns:repeat(2,1fr)}}
@media (max-width:560px){.cru-tabs{grid-template-columns:1fr}.cru-tab-sub{display:none}}
`;
