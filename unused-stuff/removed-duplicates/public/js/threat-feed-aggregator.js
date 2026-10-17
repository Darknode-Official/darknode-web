// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved.
// Threat Feed Aggregator — a REAL, timestamped unified feed built live from three
// keyless public sources, fetched through the Darknode proxy at view time:
//   - CISA Known Exploited Vulnerabilities catalog (cisa.gov)
//   - ransomware.live recent victims (api.ransomware.live)
//   - Recently published CVEs from the NIST NVD (services.nvd.nist.gov)
// There are no frozen local JSON snapshots and no "LIVE" badge over stale data:
// the badge only reads LIVE after a successful fetch, and shows the fetch time.
import { dnFetchJSON, proxyConfigured } from "/js/net.js";

var esc = function(s) { return String(s != null ? s : '').replace(/[&<>"']/g, function(c) { return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

var KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
var RANSOM_URL = 'https://api.ransomware.live/v2/recentvictims';
var NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

var _tfSources = [
  { id: 'kev', name: 'CISA KEV', color: '#ff4444', icon: '[KEV]', src: 'cisa.gov' },
  { id: 'ransom', name: 'Ransomware', color: '#ff2222', icon: '[RW]', src: 'ransomware.live' },
  { id: 'cve', name: 'New CVEs', color: '#00aaff', icon: '[CVE]', src: 'nvd.nist.gov' }
];

var _tfData = [];
var _tfFilter = 'all';
var _tfLoading = false;
var _tfErrors = [];
var _tfFetchedAt = null;

function _tfCopyToClipboard(text) {
  try { navigator.clipboard.writeText(text); } catch (_) {
    var ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
  }
}

// NVD wants "YYYY-MM-DDTHH:MM:SS.000" (UTC, no zone suffix).
function _nvdDate(d) { return d.toISOString().slice(0, 19) + '.000'; }

function _sevFromCvss(score) {
  if (score == null) return 'medium';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

function _nvdMetric(cve) {
  var m = cve.metrics || {};
  var pick = (m.cvssMetricV40 || [])[0] || (m.cvssMetricV31 || [])[0] || (m.cvssMetricV30 || [])[0] || (m.cvssMetricV2 || [])[0];
  if (!pick || !pick.cvssData) return null;
  return { score: pick.cvssData.baseScore, version: pick.cvssData.version || '' };
}

// ── Source fetchers (each returns normalized feed items or throws) ───────────

async function _tfFetchKev() {
  var data = await dnFetchJSON(KEV_URL, { timeout: 25000 });
  var vulns = (data && data.vulnerabilities) || [];
  return vulns.map(function(d) {
    var ransom = d.knownRansomwareCampaignUse === 'Known';
    return {
      source: 'kev',
      title: d.cveID || 'N/A',
      subtitle: [d.vendorProject, d.product].filter(Boolean).join(' — '),
      desc: d.vulnerabilityName || d.shortDescription || '',
      time: d.dateAdded || '',
      severity: ransom ? 'critical' : 'high',
      tags: [d.vendorProject, ransom ? 'RANSOMWARE' : null].filter(Boolean),
      raw: d
    };
  });
}

async function _tfFetchRansom() {
  var victims = await dnFetchJSON(RANSOM_URL, { timeout: 25000 });
  if (!Array.isArray(victims)) return [];
  return victims.map(function(d) {
    return {
      source: 'ransom',
      title: d.victim || '(unnamed victim)',
      subtitle: d.group ? ('Group: ' + d.group) : '',
      desc: d.description || d.activity || '',
      time: d.discovered || d.attackdate || '',
      severity: 'high',
      tags: [d.group, d.activity, d.country].filter(Boolean),
      raw: d
    };
  });
}

async function _tfFetchCves() {
  var end = new Date();
  var start = new Date(end.getTime() - 7 * 86400000);
  var base = NVD_URL + '?pubStartDate=' + encodeURIComponent(_nvdDate(start)) +
    '&pubEndDate=' + encodeURIComponent(_nvdDate(end)) + '&noRejected';
  // Fetch a head record for the total, then the newest page.
  var head = await dnFetchJSON(base + '&resultsPerPage=1', { timeout: 25000 });
  var total = (head && head.totalResults) || 0;
  if (!total) return [];
  var perPage = 60;
  var startIndex = Math.max(0, total - perPage);
  var page = await dnFetchJSON(base + '&resultsPerPage=' + perPage + '&startIndex=' + startIndex, { timeout: 25000 });
  var vulns = (page && page.vulnerabilities) || [];
  return vulns.map(function(v) {
    var cve = v.cve || {};
    var desc = ((cve.descriptions || []).filter(function(x) { return x.lang === 'en'; })[0] || {}).value || '';
    var metric = _nvdMetric(cve);
    return {
      source: 'cve',
      title: cve.id || 'N/A',
      subtitle: metric ? ('CVSS ' + metric.score + (metric.version ? ' (v' + metric.version + ')' : '')) : 'Not yet scored',
      desc: desc,
      time: (cve.published || '').slice(0, 19),
      severity: metric ? _sevFromCvss(metric.score) : 'medium',
      tags: [cve.vulnStatus].filter(Boolean),
      raw: cve
    };
  }).filter(function(x) { return x.title && x.title !== 'N/A'; });
}

async function _tfFetchAll() {
  if (_tfLoading) return;
  _tfLoading = true;
  _tfErrors = [];
  var statusEl = document.getElementById('tf-status');
  if (statusEl) { statusEl.textContent = 'FETCHING...'; statusEl.style.background = '#ffaa0022'; statusEl.style.color = '#ffaa00'; statusEl.style.borderColor = '#ffaa0044'; }

  if (!proxyConfigured()) {
    _tfLoading = false;
    _tfErrors.push('Darknode proxy not configured — live sources cannot be reached.');
    _tfSetStatus(false);
    _tfRenderFeed();
    return;
  }

  _tfData = [];
  var fetchers = [
    { id: 'CISA KEV', fn: _tfFetchKev },
    { id: 'ransomware.live', fn: _tfFetchRansom },
    { id: 'NVD', fn: _tfFetchCves }
  ];

  var results = await Promise.all(fetchers.map(function(f) {
    return f.fn().then(function(items) { return { ok: true, items: items }; })
      .catch(function(err) { _tfErrors.push(f.id + ': ' + ((err && err.message) || err)); return { ok: false, items: [] }; });
  }));

  results.forEach(function(r) { if (r.ok) _tfData = _tfData.concat(r.items); });

  // Sort by timestamp descending (ISO / YYYY-MM-DD strings sort lexically).
  _tfData.sort(function(a, b) { return (b.time || '').localeCompare(a.time || ''); });

  _tfLoading = false;
  _tfFetchedAt = new Date();
  _tfSetStatus(_tfData.length > 0);
  _tfUpdateStats();
  _tfRenderFeed();
}

function _tfSetStatus(live) {
  var statusEl = document.getElementById('tf-status');
  if (!statusEl) return;
  if (live) {
    statusEl.textContent = 'LIVE ' + (_tfFetchedAt ? _tfFetchedAt.toLocaleTimeString() : '');
    statusEl.style.background = '#00ff8822'; statusEl.style.color = '#00ff88'; statusEl.style.borderColor = '#00ff8844';
  } else {
    statusEl.textContent = 'FETCH FAILED';
    statusEl.style.background = '#ff224422'; statusEl.style.color = '#ff4444'; statusEl.style.borderColor = '#ff224444';
  }
}

function _tfUpdateStats() {
  var stats = { total: _tfData.length, kev: 0, ransom: 0, cve: 0, critical: 0 };
  for (var i = 0; i < _tfData.length; i++) {
    stats[_tfData[i].source] = (stats[_tfData[i].source] || 0) + 1;
    if (_tfData[i].severity === 'critical') stats.critical++;
  }
  var map = { 'tf-total': stats.total, 'tf-kev': stats.kev, 'tf-ransom': stats.ransom, 'tf-cve': stats.cve, 'tf-critical': stats.critical };
  Object.keys(map).forEach(function(id) { var el = document.getElementById(id); if (el) el.textContent = map[id]; });
}

function _tfSevColor(s) {
  if (s === 'critical') return '#ff4444';
  if (s === 'high') return '#ff8800';
  if (s === 'medium') return '#ffcc00';
  return '#4a6a8a';
}

function _tfSourceInfo(id) {
  for (var i = 0; i < _tfSources.length; i++) { if (_tfSources[i].id === id) return _tfSources[i]; }
  return { name: id, color: '#4a6a8a', icon: '[?]', src: '' };
}

function _tfRenderFeed() {
  var el = document.getElementById('tf-feed');
  if (!el) return;

  if (_tfLoading && _tfData.length === 0) {
    el.innerHTML = '<div style="color:#4a6a8a;font-family:monospace;font-size:11px;text-align:center;padding:40px;">Fetching live threat intelligence&hellip;</div>';
    return;
  }

  var filtered = _tfFilter === 'all' ? _tfData : _tfData.filter(function(d) { return d.source === _tfFilter; });

  var h = '';
  if (_tfErrors.length) {
    h += '<div style="background:#1a0a0a;border-bottom:1px solid #ff224433;padding:8px 14px;color:#ff8866;font-family:monospace;font-size:10px;">';
    h += 'Some sources did not load: ' + esc(_tfErrors.join(' | ')) + '. Only successfully fetched data is shown below &mdash; nothing is substituted.';
    h += '</div>';
  }

  if (filtered.length === 0) {
    if (!_tfErrors.length) h += '<div style="color:#4a6a8a;font-family:monospace;font-size:11px;text-align:center;padding:40px;">No items. Click FETCH ALL to load live threat intelligence.</div>';
    el.innerHTML = h;
    return;
  }

  var maxItems = Math.min(filtered.length, 250);
  for (var i = 0; i < maxItems; i++) {
    var item = filtered[i];
    var src = _tfSourceInfo(item.source);
    var sevColor = _tfSevColor(item.severity);

    h += '<div style="padding:10px 14px;border-bottom:1px solid #0d1525;display:flex;gap:10px;align-items:flex-start;">';
    h += '<div style="flex-shrink:0;min-width:44px;">';
    h += '<div style="background:' + src.color + '22;color:' + src.color + ';font-size:8px;font-family:monospace;padding:2px 4px;border-radius:2px;border:1px solid ' + src.color + '33;text-align:center;font-weight:bold;letter-spacing:1px;white-space:nowrap;">' + esc(src.icon) + '</div>';
    h += '</div>';
    h += '<div style="flex:1;min-width:0;">';
    h += '<div style="display:flex;align-items:center;gap:6px;margin-bottom:2px;">';
    h += '<span style="font-family:monospace;font-size:12px;color:#c8d6e5;font-weight:bold;word-break:break-all;">' + esc(String(item.title).substring(0, 90)) + '</span>';
    h += '<span style="background:' + sevColor + '22;color:' + sevColor + ';font-size:7px;font-family:monospace;padding:1px 4px;border-radius:2px;flex-shrink:0;">' + (item.severity || '').toUpperCase() + '</span>';
    h += '</div>';
    if (item.subtitle) h += '<div style="font-family:monospace;font-size:10px;color:#8ab4d4;margin-bottom:2px;">' + esc(item.subtitle) + '</div>';
    if (item.desc) h += '<div style="font-family:monospace;font-size:9px;color:#4a6a8a;margin-bottom:3px;word-break:break-word;">' + esc(String(item.desc).substring(0, 240)) + '</div>';
    if (item.tags && item.tags.length > 0) {
      h += '<div style="display:flex;gap:3px;flex-wrap:wrap;">';
      for (var t = 0; t < item.tags.length; t++) {
        h += '<span style="background:#0a1a2a;color:#5a8aaa;font-size:7px;font-family:monospace;padding:1px 4px;border-radius:2px;border:1px solid #1a2a44;">' + esc(item.tags[t]) + '</span>';
      }
      h += '</div>';
    }
    h += '</div>';
    h += '<div style="flex-shrink:0;font-family:monospace;font-size:9px;color:#3a5a7a;white-space:nowrap;">' + esc((item.time || '').replace('T', ' ').substring(0, 16)) + '</div>';
    h += '</div>';
  }

  if (filtered.length > maxItems) {
    h += '<div style="text-align:center;padding:12px;color:#4a6a8a;font-family:monospace;font-size:10px;">Showing ' + maxItems + ' of ' + filtered.length + ' items</div>';
  }

  el.innerHTML = h;
}

export function renderThreatFeedAggregator(container) {
  var h = '';
  h += '<div style="padding:20px 24px;max-width:1100px;margin:0 auto;">';

  // Header
  h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px;">';
  h += '<div>';
  h += '<h2 style="margin:0;font-size:20px;color:#ff8800;font-family:monospace;letter-spacing:2px;text-transform:uppercase;">THREAT FEED AGGREGATOR</h2>';
  h += '<div style="color:#4a6a8a;font-size:11px;font-family:monospace;margin-top:4px;">Live feed from CISA KEV, ransomware.live and NIST NVD</div>';
  h += '</div>';
  h += '<div style="display:flex;gap:8px;align-items:center;">';
  h += '<div id="tf-status" style="background:#1a2a44;color:#8ab4d4;font-size:10px;font-family:monospace;padding:4px 10px;border-radius:4px;border:1px solid #1a2a44;font-weight:bold;">READY</div>';
  h += '<button onclick="_tfFetchAll()" style="background:#ff880022;border:1px solid #ff880066;border-radius:4px;padding:6px 14px;color:#ff8800;font-family:monospace;font-size:11px;font-weight:bold;cursor:pointer;">Fetch All</button>';
  h += '<button onclick="_tfExport()" style="background:#0a1a28;border:1px solid #1a3050;border-radius:4px;padding:6px 14px;color:#5a8aaa;font-family:monospace;font-size:11px;cursor:pointer;">Export JSON</button>';
  h += '</div></div>';

  // Stats row
  h += '<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:6px;margin-bottom:14px;">';
  var statDefs = [
    { id: 'tf-total', label: 'TOTAL', color: '#00aaff' },
    { id: 'tf-kev', label: 'CISA KEV', color: '#ff4444' },
    { id: 'tf-ransom', label: 'RANSOM VICTIMS', color: '#ff2222' },
    { id: 'tf-cve', label: 'NEW CVES', color: '#00ddff' },
    { id: 'tf-critical', label: 'CRITICAL', color: '#ff0000' }
  ];
  for (var si = 0; si < statDefs.length; si++) {
    var sd = statDefs[si];
    h += '<div style="background:#0a0e1a;border:1px solid ' + sd.color + '33;border-radius:6px;padding:8px;text-align:center;">';
    h += '<div id="' + sd.id + '" style="color:' + sd.color + ';font-size:18px;font-weight:bold;font-family:monospace;">--</div>';
    h += '<div style="color:#4a6a8a;font-size:7px;font-family:monospace;letter-spacing:1px;">' + sd.label + '</div>';
    h += '</div>';
  }
  h += '</div>';

  // Source filters
  h += '<div style="display:flex;gap:4px;margin-bottom:12px;flex-wrap:wrap;">';
  h += '<button onclick="_tfSetFilter(\'all\')" id="tf-filter-all" style="background:#00aaff22;border:1px solid #00aaff66;border-radius:4px;padding:4px 10px;color:#00ddff;font-family:monospace;font-size:10px;cursor:pointer;">ALL</button>';
  for (var fi = 0; fi < _tfSources.length; fi++) {
    var fs = _tfSources[fi];
    h += '<button onclick="_tfSetFilter(\'' + fs.id + '\')" id="tf-filter-' + fs.id + '" style="background:#0a0e1a;border:1px solid #1a2a44;border-radius:4px;padding:4px 10px;color:#4a6a8a;font-family:monospace;font-size:10px;cursor:pointer;">' + esc(fs.name) + '</button>';
  }
  h += '</div>';

  // Feed area
  h += '<div id="tf-feed" style="background:#080c14;border:1px solid #1a2a44;border-radius:8px;max-height:600px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:#1a3050 transparent;">';
  h += '<div style="color:#4a6a8a;font-family:monospace;font-size:11px;text-align:center;padding:40px;">Loading live threat intelligence&hellip;</div>';
  h += '</div>';

  h += '<div style="color:#3a5a7a;font-family:monospace;font-size:9px;margin-top:8px;line-height:1.6;">Sources: CISA Known Exploited Vulnerabilities (cisa.gov), ransomware.live recent victims, NIST NVD recently published CVEs. Fetched live through the Darknode proxy; timestamps are from the sources.</div>';

  h += '</div>';

  container.innerHTML = h;

  // Auto-load on open.
  _tfFetchAll();
};

function _tfUpdateFilterButtons() {
  var all = document.getElementById('tf-filter-all');
  var setBtn = function(el, active, color) {
    if (!el) return;
    el.style.background = active ? color + '22' : '#0a0e1a';
    el.style.borderColor = active ? color + '66' : '#1a2a44';
    el.style.color = active ? color : '#4a6a8a';
  };
  setBtn(all, _tfFilter === 'all', '#00aaff');
  _tfSources.forEach(function(s) { setBtn(document.getElementById('tf-filter-' + s.id), _tfFilter === s.id, s.color); });
}

window._tfSetFilter = function(f) {
  _tfFilter = f;
  _tfUpdateFilterButtons();
  _tfRenderFeed();
};

window._tfFetchAll = _tfFetchAll;

window._tfExport = function() {
  var exportData = {
    exported: new Date().toISOString(),
    fetchedAt: _tfFetchedAt ? _tfFetchedAt.toISOString() : null,
    sources: _tfSources.map(function(s) { return { id: s.id, name: s.name, source: s.src }; }),
    errors: _tfErrors,
    totalItems: _tfData.length,
    items: _tfData.map(function(d) { return { source: d.source, title: d.title, subtitle: d.subtitle, severity: d.severity, time: d.time, tags: d.tags }; })
  };
  _tfCopyToClipboard(JSON.stringify(exportData, null, 2));
  var statusEl = document.getElementById('tf-status');
  if (statusEl) {
    var prev = statusEl.textContent;
    statusEl.textContent = 'COPIED';
    setTimeout(function() { statusEl.textContent = prev; }, 1500);
  }
};
