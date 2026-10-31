// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Darknet Radar — REAL extortion / known-exploited-vulnerability intelligence.
// There is no legitimate keyless "live dark web" feed, so this tool is driven by
// two genuine public sources, fetched live through the Darknode proxy:
//   - ransomware.live: recent victims posted on ransomware leak sites, and the
//     tracked ransomware groups with their data-leak-site (DLS) .onion mirrors.
//   - CISA Known Exploited Vulnerabilities catalog: CVEs confirmed exploited in
//     the wild (the vulnerabilities these groups weaponise).
// Nothing is simulated; every row is labelled with its real source.
import { dnFetchJSON, proxyConfigured } from "/js/net.js";

var esc = function(s) {
  return String(s != null ? s : '').replace(/[&<>"']/g, function(c) {
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
};

var RANSOM_VICTIMS_URL = 'https://api.ransomware.live/v2/recentvictims';
var RANSOM_GROUPS_URL = 'https://api.ransomware.live/v2/groups';
var KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

// Per-tab load state so each source is fetched once, on demand.
var _drState = {
  victims: { loaded: false, loading: false, data: null, error: '' },
  groups: { loaded: false, loading: false, data: null, error: '' },
  kev: { loaded: false, loading: false, data: null, error: '' }
};

function _drFmtDate(s) { return String(s || '').replace('T', ' ').substring(0, 16); }

function _drErrorBox(msg, source) {
  return '<div style="background:color-mix(in srgb,var(--bad) 10%,var(--card));border:1px solid color-mix(in srgb,var(--bad) 20%,transparent);border-radius:4px;padding:16px;text-align:center;">' +
    '<div style="color:var(--bad);font-size:12px;font-weight:bold;margin-bottom:4px;">Could not load live data</div>' +
    '<div style="color:var(--txt-2);font-size:12px;">' + esc(msg) + '</div>' +
    '<div style="color:var(--mut);font-size:12px;margin-top:6px;">Source: ' + esc(source) + '</div>' +
    '</div>';
}

function _drLoading() {
  return '<div style="color:var(--mut);font-family:monospace;font-size:12px;text-align:center;padding:30px;">Fetching live intelligence&hellip;</div>';
}

// ── Renderers for each real source ───────────────────────────────────────────

// Each list shows a page at a time; 100+ cards at once made a 12-screen page.
var DR_PAGE = 20;
var _drShown = { victims: DR_PAGE, groups: DR_PAGE, kev: DR_PAGE };
function _drMore(key, max, total) {
  if (total <= max) return '';
  return '<div style="text-align:center;padding:10px;color:var(--mut);font-size:12px;">Showing ' + max + ' of ' + total +
    ' <button type="button" class="dr-more btn ghost sm" data-dr-more="' + key + '" style="margin-left:8px;">Show ' + Math.min(DR_PAGE, total - max) + ' more</button></div>';
}

function _drRenderVictims(list) {
  if (!Array.isArray(list) || !list.length) return '<div style="color:var(--mut);font-size:12px;padding:20px;">No recent victims returned.</div>';
  var h = '<h3 style="color:var(--txt);font-size:14px;margin:0 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px;">Recent ransomware victims (' + list.length + ')</h3>';
  h += '<div style="color:var(--mut);font-size:12px;margin-bottom:10px;">Organisations recently published on ransomware leak sites. Source: ransomware.live</div>';
  var max = Math.min(list.length, _drShown.victims);
  for (var i = 0; i < max; i++) {
    var v = list[i];
    h += '<div style="background:var(--card2);padding:12px 16px;margin-bottom:8px;border-radius:4px;border-left:3px solid var(--bad);">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;flex-wrap:wrap;gap:6px;">';
    h += '<span style="color:var(--bad);font-size:14px;font-weight:bold;word-break:break-word;">' + esc(v.victim || '(unnamed)') + '</span>';
    if (v.group) h += '<span style="color:var(--warn);font-size:12px;border:1px solid var(--warn);padding:1px 6px;border-radius:2px;">' + esc(v.group) + '</span>';
    h += '</div>';
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:4px 16px;font-size:12px;color:var(--txt-2);line-height:1.6;">';
    if (v.activity) h += '<div><span style="color:var(--mut);">Sector:</span> ' + esc(v.activity) + '</div>';
    if (v.country) h += '<div><span style="color:var(--mut);">Country:</span> ' + esc(v.country) + '</div>';
    if (v.attackdate) h += '<div><span style="color:var(--mut);">Attack:</span> ' + esc(_drFmtDate(v.attackdate)) + '</div>';
    if (v.discovered) h += '<div><span style="color:var(--mut);">Discovered:</span> ' + esc(_drFmtDate(v.discovered)) + '</div>';
    if (v.domain) h += '<div><span style="color:var(--mut);">Domain:</span> ' + esc(v.domain) + '</div>';
    h += '</div>';
    if (v.description) h += '<div style="font-size:12px;color:var(--mut);margin-top:4px;">' + esc(String(v.description).substring(0, 300)) + '</div>';
    h += '</div>';
  }
  h += _drMore('victims', max, list.length);
  return h;
}

function _drRenderGroups(list) {
  if (!Array.isArray(list) || !list.length) return '<div style="color:var(--mut);font-size:12px;padding:20px;">No groups returned.</div>';
  var groups = list.slice().sort(function(a, b) { return String(a.name || '').localeCompare(String(b.name || '')); });
  var h = '<h3 style="color:var(--txt);font-size:14px;margin:0 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px;">Tracked ransomware groups (' + groups.length + ')</h3>';
  h += '<div style="color:var(--mut);font-size:12px;margin-bottom:10px;">Ransomware / extortion groups tracked by ransomware.live, with data-leak-site mirror counts.</div>';
  var max = Math.min(groups.length, _drShown.groups);
  for (var i = 0; i < max; i++) {
    var g = groups[i];
    var dls = Array.isArray(g.locations) ? g.locations.length : 0;
    var up = Array.isArray(g.locations) ? g.locations.filter(function(l) { return l.available; }).length : 0;
    h += '<div style="background:var(--card2);padding:10px 14px;margin-bottom:6px;border-radius:4px;border-left:3px solid var(--bad);">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;flex-wrap:wrap;gap:6px;">';
    h += '<span style="color:var(--bad);font-size:13px;font-weight:bold;">' + esc(g.name || '(unnamed)') + '</span>';
    h += '<span style="color:var(--mut);font-size:12px;">' + dls + ' DLS mirror' + (dls === 1 ? '' : 's') + ' (' + up + ' up)' + (g.added_date ? ' | tracked ' + esc(g.added_date) : '') + '</span>';
    h += '</div>';
    if (g.description) h += '<div style="font-size:12px;color:var(--txt-2);line-height:1.5;">' + esc(String(g.description).substring(0, 320)) + '</div>';
    h += '</div>';
  }
  h += _drMore('groups', max, groups.length);
  return h;
}

function _drRenderKev(vulns) {
  if (!Array.isArray(vulns) || !vulns.length) return '<div style="color:var(--mut);font-size:12px;padding:20px;">No KEV entries returned.</div>';
  var sorted = vulns.slice().sort(function(a, b) { return String(b.dateAdded || '').localeCompare(String(a.dateAdded || '')); });
  var max = Math.min(sorted.length, _drShown.kev);
  var h = '<h3 style="color:var(--txt);font-size:14px;margin:0 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px;">Known exploited vulnerabilities (' + vulns.length + ' total, newest ' + max + ')</h3>';
  h += '<div style="color:var(--mut);font-size:12px;margin-bottom:10px;">CVEs confirmed exploited in the wild. Source: CISA Known Exploited Vulnerabilities catalog.</div>';
  for (var i = 0; i < max; i++) {
    var k = sorted[i];
    var ransom = k.knownRansomwareCampaignUse === 'Known';
    var color = ransom ? '#ff2244' : '#ffaa22';
    h += '<div style="background:var(--card2);padding:10px 14px;margin-bottom:6px;border-radius:4px;border-left:3px solid ' + color + ';">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;flex-wrap:wrap;gap:6px;">';
    h += '<span style="color:' + color + ';font-family:monospace;font-size:12px;font-weight:bold;">' + esc(k.cveID || '') + '</span>';
    h += '<span style="color:var(--mut);font-size:12px;">' + esc([k.vendorProject, k.product].filter(Boolean).join(' / ')) + ' | added ' + esc(k.dateAdded || '') + '</span>';
    h += '</div>';
    h += '<div style="font-size:12px;color:var(--txt);margin-bottom:3px;">' + esc(k.vulnerabilityName || '') + '</div>';
    if (k.shortDescription) h += '<div style="font-size:12px;color:var(--txt-2);line-height:1.5;">' + esc(String(k.shortDescription).substring(0, 280)) + '</div>';
    if (ransom) h += '<div style="font-size:12px;color:var(--bad);margin-top:4px;">Known use in ransomware campaigns</div>';
    h += '</div>';
  }
  h += _drMore('kev', max, sorted.length);
  return h;
}

// ── Lazy loaders ─────────────────────────────────────────────────────────────

async function _drLoadTab(key) {
  var st = _drState[key];
  var panel = document.getElementById('dr-panel-' + key);
  if (!st || !panel) return;
  if (st.loaded || st.loading) { _drPaintTab(key); return; }
  if (!proxyConfigured()) {
    st.error = 'The Darknode proxy is not configured, so live sources cannot be reached.';
    st.loaded = true;
    _drPaintTab(key);
    return;
  }
  st.loading = true;
  panel.innerHTML = _drLoading();
  try {
    if (key === 'victims') st.data = await dnFetchJSON(RANSOM_VICTIMS_URL, { timeout: 25000 });
    else if (key === 'groups') st.data = await dnFetchJSON(RANSOM_GROUPS_URL, { timeout: 25000 });
    else if (key === 'kev') { var d = await dnFetchJSON(KEV_URL, { timeout: 25000, max: 4000000 }); st.data = (d && d.vulnerabilities) || []; }
    st.error = '';
  } catch (err) {
    st.error = String((err && err.message) || err);
  } finally {
    st.loading = false;
    st.loaded = true;
    _drPaintTab(key);
  }
}

function _drPaintTab(key) {
  var panel = document.getElementById('dr-panel-' + key);
  if (!panel) return;
  var st = _drState[key];
  if (st.loading) { panel.innerHTML = _drLoading(); return; }
  var srcName = key === 'kev' ? 'cisa.gov KEV catalog' : (key === 'groups' ? 'api.ransomware.live/v2/groups' : 'api.ransomware.live/v2/recentvictims');
  if (st.error) { panel.innerHTML = _drErrorBox(st.error, srcName); return; }
  if (key === 'victims') panel.innerHTML = _drRenderVictims(st.data);
  else if (key === 'groups') panel.innerHTML = _drRenderGroups(st.data);
  else if (key === 'kev') panel.innerHTML = _drRenderKev(st.data);
}

// ── Main Render ─────────────────────────────────────────────────────────────

export function renderDarknetRadar(container) {
  var el = typeof container === 'string' ? document.getElementById(container) : container;
  if (!el) return;

  var tabs = [
    { key: 'victims', label: 'Ransomware Victims' },
    { key: 'groups', label: 'Ransomware Groups' },
    { key: 'kev', label: 'Known Exploited Vulns' }
  ];

  var h = '';
  h += '<div>';

  // Header
  h += '<div class="pg-head"><div><h1 class="pg-h1">Darknet Radar</h1>';
  h += '<p class="muted pg-sub">Live extortion-leak and known-exploited-vulnerability intelligence. Source: ransomware.live, CISA KEV.</p></div></div>';

  // Tabs
  h += '<div id="dr-tabs" class="seg" style="margin-bottom:16px;flex-wrap:wrap;">';
  for (var ti = 0; ti < tabs.length; ti++) {
    var isActive = ti === 0;
    h += '<button class="dr-tab' + (isActive ? ' on' : '') + '" data-dr-tab="' + esc(tabs[ti].key) + '">' + esc(tabs[ti].label) + '</button>';
  }
  h += '</div>';

  // Panels
  for (var pi = 0; pi < tabs.length; pi++) {
    h += '<div id="dr-panel-' + esc(tabs[pi].key) + '" class="dr-panel" style="' + (pi === 0 ? '' : 'display:none;') + '">' + _drLoading() + '</div>';
  }

  h += '</div>';
  el.innerHTML = h;

  // Tab switching + lazy load
  el.addEventListener('click', function(e) {
    var more = e.target.closest('.dr-more');
    if (more) { var mk = more.getAttribute('data-dr-more'); _drShown[mk] += DR_PAGE; _drPaintTab(mk); return; }
    var tabBtn = e.target.closest('.dr-tab');
    if (!tabBtn) return;
    var key = tabBtn.getAttribute('data-dr-tab');
    var allTabs = el.querySelectorAll('.dr-tab');
    for (var a = 0; a < allTabs.length; a++) {
      allTabs[a].classList.toggle('on', allTabs[a] === tabBtn);
    }
    var allPanels = el.querySelectorAll('.dr-panel');
    for (var b = 0; b < allPanels.length; b++) allPanels[b].style.display = 'none';
    var panel = document.getElementById('dr-panel-' + key);
    if (panel) panel.style.display = 'block';
    _drLoadTab(key);
  });

  // Load the first tab immediately.
  _drLoadTab('victims');
};
