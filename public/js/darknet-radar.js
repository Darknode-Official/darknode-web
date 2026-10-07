// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved.
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
  return '<div style="background:#1a0a0a;border:1px solid #ff224433;border-radius:4px;padding:16px;text-align:center;">' +
    '<div style="color:#ff4444;font-size:12px;font-weight:bold;margin-bottom:4px;">COULD NOT LOAD LIVE DATA</div>' +
    '<div style="color:#ff8866;font-size:10px;">' + esc(msg) + '</div>' +
    '<div style="color:#4a6a8a;font-size:9px;margin-top:6px;">Source: ' + esc(source) + '. No simulated data is substituted.</div>' +
    '</div>';
}

function _drLoading() {
  return '<div style="color:#4a6a8a;font-family:monospace;font-size:11px;text-align:center;padding:30px;">Fetching live intelligence&hellip;</div>';
}

// ── Renderers for each real source ───────────────────────────────────────────

function _drRenderVictims(list) {
  if (!Array.isArray(list) || !list.length) return '<div style="color:#4a6a8a;font-size:11px;padding:20px;">No recent victims returned.</div>';
  var h = '<h3 style="color:#ff6644;font-size:13px;letter-spacing:2px;margin:0 0 10px;border-bottom:1px solid #3a1a1a;padding-bottom:6px;">RECENT RANSOMWARE VICTIMS (' + list.length + ')</h3>';
  h += '<div style="color:#4a6a8a;font-size:10px;margin-bottom:10px;">Organisations recently published on ransomware leak sites. Source: ransomware.live</div>';
  var max = Math.min(list.length, 150);
  for (var i = 0; i < max; i++) {
    var v = list[i];
    h += '<div style="background:#0f1218;padding:12px 16px;margin-bottom:8px;border-radius:4px;border-left:3px solid #ff2244;">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;flex-wrap:wrap;gap:6px;">';
    h += '<span style="color:#ff4444;font-size:14px;font-weight:bold;word-break:break-word;">' + esc(v.victim || '(unnamed)') + '</span>';
    if (v.group) h += '<span style="color:#ff6644;font-size:10px;border:1px solid #ff6644;padding:1px 6px;border-radius:2px;">' + esc(v.group) + '</span>';
    h += '</div>';
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:4px 16px;font-size:10px;color:#8ab4d4;line-height:1.6;">';
    if (v.activity) h += '<div><span style="color:#4a6a8a;">Sector:</span> ' + esc(v.activity) + '</div>';
    if (v.country) h += '<div><span style="color:#4a6a8a;">Country:</span> ' + esc(v.country) + '</div>';
    if (v.attackdate) h += '<div><span style="color:#4a6a8a;">Attack:</span> ' + esc(_drFmtDate(v.attackdate)) + '</div>';
    if (v.discovered) h += '<div><span style="color:#4a6a8a;">Discovered:</span> ' + esc(_drFmtDate(v.discovered)) + '</div>';
    if (v.domain) h += '<div><span style="color:#4a6a8a;">Domain:</span> ' + esc(v.domain) + '</div>';
    h += '</div>';
    if (v.description) h += '<div style="font-size:10px;color:#6a8aaa;margin-top:4px;">' + esc(String(v.description).substring(0, 300)) + '</div>';
    h += '</div>';
  }
  if (list.length > max) h += '<div style="text-align:center;padding:10px;color:#4a6a8a;font-size:10px;">Showing ' + max + ' of ' + list.length + '</div>';
  return h;
}

function _drRenderGroups(list) {
  if (!Array.isArray(list) || !list.length) return '<div style="color:#4a6a8a;font-size:11px;padding:20px;">No groups returned.</div>';
  var groups = list.slice().sort(function(a, b) { return String(a.name || '').localeCompare(String(b.name || '')); });
  var h = '<h3 style="color:#ff2244;font-size:13px;letter-spacing:2px;margin:0 0 10px;border-bottom:1px solid #3a1a1a;padding-bottom:6px;">TRACKED RANSOMWARE GROUPS (' + groups.length + ')</h3>';
  h += '<div style="color:#4a6a8a;font-size:10px;margin-bottom:10px;">Ransomware / extortion groups tracked by ransomware.live, with data-leak-site mirror counts.</div>';
  var max = Math.min(groups.length, 250);
  for (var i = 0; i < max; i++) {
    var g = groups[i];
    var dls = Array.isArray(g.locations) ? g.locations.length : 0;
    var up = Array.isArray(g.locations) ? g.locations.filter(function(l) { return l.available; }).length : 0;
    h += '<div style="background:#0f1218;padding:10px 14px;margin-bottom:6px;border-radius:4px;border-left:3px solid #ff2244;">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;flex-wrap:wrap;gap:6px;">';
    h += '<span style="color:#ff4444;font-size:13px;font-weight:bold;">' + esc(g.name || '(unnamed)') + '</span>';
    h += '<span style="color:#5a8aaa;font-size:9px;">' + dls + ' DLS mirror' + (dls === 1 ? '' : 's') + ' (' + up + ' up)' + (g.added_date ? ' | tracked ' + esc(g.added_date) : '') + '</span>';
    h += '</div>';
    if (g.description) h += '<div style="font-size:10px;color:#8ab4d4;line-height:1.5;">' + esc(String(g.description).substring(0, 320)) + '</div>';
    h += '</div>';
  }
  if (groups.length > max) h += '<div style="text-align:center;padding:10px;color:#4a6a8a;font-size:10px;">Showing ' + max + ' of ' + groups.length + '</div>';
  return h;
}

function _drRenderKev(vulns) {
  if (!Array.isArray(vulns) || !vulns.length) return '<div style="color:#4a6a8a;font-size:11px;padding:20px;">No KEV entries returned.</div>';
  var sorted = vulns.slice().sort(function(a, b) { return String(b.dateAdded || '').localeCompare(String(a.dateAdded || '')); });
  var max = Math.min(sorted.length, 120);
  var h = '<h3 style="color:#ffaa22;font-size:13px;letter-spacing:2px;margin:0 0 10px;border-bottom:1px solid #3a2a0a;padding-bottom:6px;">KNOWN EXPLOITED VULNERABILITIES (' + vulns.length + ' total, newest ' + max + ')</h3>';
  h += '<div style="color:#4a6a8a;font-size:10px;margin-bottom:10px;">CVEs confirmed exploited in the wild. Source: CISA Known Exploited Vulnerabilities catalog.</div>';
  for (var i = 0; i < max; i++) {
    var k = sorted[i];
    var ransom = k.knownRansomwareCampaignUse === 'Known';
    var color = ransom ? '#ff2244' : '#ffaa22';
    h += '<div style="background:#0f1218;padding:10px 14px;margin-bottom:6px;border-radius:4px;border-left:3px solid ' + color + ';">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;flex-wrap:wrap;gap:6px;">';
    h += '<span style="color:' + color + ';font-family:monospace;font-size:12px;font-weight:bold;">' + esc(k.cveID || '') + '</span>';
    h += '<span style="color:#5a8aaa;font-size:9px;">' + esc([k.vendorProject, k.product].filter(Boolean).join(' / ')) + ' | added ' + esc(k.dateAdded || '') + '</span>';
    h += '</div>';
    h += '<div style="font-size:11px;color:#c8d6e5;margin-bottom:3px;">' + esc(k.vulnerabilityName || '') + '</div>';
    if (k.shortDescription) h += '<div style="font-size:10px;color:#8ab4d4;line-height:1.5;">' + esc(String(k.shortDescription).substring(0, 280)) + '</div>';
    if (ransom) h += '<div style="font-size:9px;color:#ff2244;margin-top:4px;">Known use in ransomware campaigns</div>';
    h += '</div>';
  }
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
    else if (key === 'kev') { var d = await dnFetchJSON(KEV_URL, { timeout: 25000 }); st.data = (d && d.vulnerabilities) || []; }
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
  h += '<div style="background:#0a0e16;color:#c8d6e5;font-family:\'Courier New\',monospace;padding:24px;min-height:100%;">';

  // Header
  h += '<div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap;">';
  h += '<h2 style="margin:0;color:#ff2244;letter-spacing:2px;font-size:18px;">DARKNET RADAR</h2>';
  h += '<span style="color:#0a2a0a;background:#00cc66;padding:2px 8px;font-size:10px;font-weight:bold;border-radius:2px;letter-spacing:2px;">LIVE INTEL</span>';
  h += '</div>';
  h += '<div style="color:#4a6a8a;font-size:11px;margin-bottom:20px;line-height:1.6;">Real extortion-leak and known-exploited-vulnerability intelligence.<br>Sources: ransomware.live (recent victims and tracked groups) and the CISA Known Exploited Vulnerabilities catalog, fetched live through the Darknode proxy.</div>';

  // Tabs
  h += '<div id="dr-tabs" style="display:flex;gap:4px;margin-bottom:16px;flex-wrap:wrap;">';
  for (var ti = 0; ti < tabs.length; ti++) {
    var isActive = ti === 0;
    h += '<button class="dr-tab" data-dr-tab="' + esc(tabs[ti].key) + '" style="background:' + (isActive ? '#2a0a0a' : '#0f1218') + ';border:1px solid ' + (isActive ? '#ff2244' : '#1a2a3a') + ';color:' + (isActive ? '#ff2244' : '#5a7a9a') + ';padding:6px 14px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:3px;letter-spacing:1px;">' + esc(tabs[ti].label) + '</button>';
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
    var tabBtn = e.target.closest('.dr-tab');
    if (!tabBtn) return;
    var key = tabBtn.getAttribute('data-dr-tab');
    var allTabs = el.querySelectorAll('.dr-tab');
    for (var a = 0; a < allTabs.length; a++) {
      var on = allTabs[a] === tabBtn;
      allTabs[a].style.background = on ? '#2a0a0a' : '#0f1218';
      allTabs[a].style.borderColor = on ? '#ff2244' : '#1a2a3a';
      allTabs[a].style.color = on ? '#ff2244' : '#5a7a9a';
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
