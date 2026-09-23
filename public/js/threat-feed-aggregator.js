// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Threat Feed Aggregator — multi-source threat intelligence viewer
// Merges CISA KEV, IOCs, botnet C2, malware URLs, ransomware groups into unified timeline

var esc = function(s) { return String(s != null ? s : '').replace(/[&<>"']/g, function(c) { return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

var _tfSources = [
  { id: 'kev', name: 'CISA KEV', url: '/data/feeds/cisa-kev.json', color: '#ff4444', icon: '[KEV]' },
  { id: 'ioc', name: 'Threat IOCs', url: '/data/feeds/threat-iocs.json', color: '#ff8800', icon: '[IOC]' },
  { id: 'c2', name: 'Botnet C2', url: '/data/feeds/botnet-c2.json', color: '#aa44ff', icon: '[C2]' },
  { id: 'malurl', name: 'Malware URLs', url: '/data/feeds/malware-urls.json', color: '#ff00aa', icon: '[URL]' },
  { id: 'ransom', name: 'Ransomware', url: '/data/feeds/ransomware-groups.json', color: '#ff2222', icon: '[RW]' }
];

var _tfData = [];
var _tfFilter = 'all';
var _tfLoading = false;

function _tfCopyToClipboard(text) {
  try { navigator.clipboard.writeText(text); } catch (_) {
    var ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
  }
}

function _tfNormalize(sourceId, rawData) {
  var items = [];
  var data = rawData.data || rawData;
  if (!Array.isArray(data)) return items;

  for (var i = 0; i < data.length; i++) {
    var d = data[i];
    var item = { source: sourceId, raw: d };

    switch (sourceId) {
      case 'kev':
        item.title = d.cve || 'N/A';
        item.subtitle = (d.vendor || '') + ' — ' + (d.product || '');
        item.desc = d.name || d.description || '';
        item.time = d.dateAdded || '';
        item.severity = d.knownRansomware === 'Known' ? 'critical' : 'high';
        item.tags = [d.vendor, d.knownRansomware === 'Known' ? 'RANSOMWARE' : null].filter(Boolean);
        break;
      case 'ioc':
        item.title = d.iocValue || '';
        item.subtitle = d.malware || '';
        item.desc = d.iocType || '';
        item.time = d.firstSeen || '';
        item.severity = d.confidenceLevel > 90 ? 'critical' : d.confidenceLevel > 70 ? 'high' : 'medium';
        item.tags = d.tags || [];
        break;
      case 'c2':
        item.title = d.ip + ':' + d.port;
        item.subtitle = d.malware || '';
        item.desc = 'AS' + (d.asNumber || '?') + ' — ' + (d.asName || '');
        item.time = d.firstSeen || '';
        item.severity = d.status === 'online' ? 'critical' : 'low';
        item.tags = [d.malware, d.country, d.status].filter(Boolean);
        break;
      case 'malurl':
        item.title = d.url || '';
        item.subtitle = d.threat || '';
        item.desc = d.host || '';
        item.time = d.dateAdded || '';
        item.severity = d.status === 'online' ? 'high' : 'low';
        item.tags = d.tags || [];
        break;
      case 'ransom':
        item.title = d.name || '';
        item.subtitle = 'Victims 2026: ' + (d.victimCount2026 || '?');
        item.desc = 'Avg ransom: ' + (d.avgRansom || '?') + ' | ' + (d.language || '');
        item.time = d.firstSeen || '';
        item.severity = d.status === 'active' ? 'critical' : 'low';
        item.tags = (d.targetSectors || []).slice(0, 3);
        break;
    }
    items.push(item);
  }
  return items;
}

async function _tfFetchAll() {
  if (_tfLoading) return;
  _tfLoading = true;
  var statusEl = document.getElementById('tf-status');
  if (statusEl) statusEl.textContent = 'FETCHING...';

  _tfData = [];
  var promises = _tfSources.map(function(src) {
    return fetch(src.url)
      .then(function(r) { return r.json(); })
      .then(function(json) {
        var items = _tfNormalize(src.id, json);
        _tfData = _tfData.concat(items);
      })
      .catch(function() {});
  });

  await Promise.all(promises);

  // Sort by time descending
  _tfData.sort(function(a, b) {
    return (b.time || '').localeCompare(a.time || '');
  });

  _tfLoading = false;
  if (statusEl) statusEl.textContent = 'LIVE';
  _tfUpdateStats();
  _tfRenderFeed();
}

function _tfUpdateStats() {
  var stats = { total: _tfData.length, kev: 0, ioc: 0, c2: 0, malurl: 0, ransom: 0, critical: 0 };
  for (var i = 0; i < _tfData.length; i++) {
    stats[_tfData[i].source] = (stats[_tfData[i].source] || 0) + 1;
    if (_tfData[i].severity === 'critical') stats.critical++;
  }

  var ids = ['tf-total', 'tf-kev', 'tf-ioc', 'tf-c2', 'tf-malurl', 'tf-ransom', 'tf-critical'];
  var vals = [stats.total, stats.kev, stats.ioc, stats.c2, stats.malurl, stats.ransom, stats.critical];
  for (var s = 0; s < ids.length; s++) {
    var el = document.getElementById(ids[s]);
    if (el) el.textContent = vals[s];
  }
}

function _tfSevColor(s) {
  if (s === 'critical') return '#ff4444';
  if (s === 'high') return '#ff8800';
  if (s === 'medium') return '#ffcc00';
  return '#4a6a8a';
}

function _tfSourceInfo(id) {
  for (var i = 0; i < _tfSources.length; i++) {
    if (_tfSources[i].id === id) return _tfSources[i];
  }
  return { name: id, color: '#4a6a8a', icon: '[?]' };
}

function _tfRenderFeed() {
  var el = document.getElementById('tf-feed');
  if (!el) return;
  var filtered = _tfFilter === 'all' ? _tfData : _tfData.filter(function(d) { return d.source === _tfFilter; });

  if (filtered.length === 0) { el.innerHTML = '<div style="color:#4a6a8a;font-family:monospace;font-size:11px;text-align:center;padding:40px;">No items match the current filter.</div>'; return; }

  var h = '';
  var maxItems = Math.min(filtered.length, 200);
  for (var i = 0; i < maxItems; i++) {
    var item = filtered[i];
    var src = _tfSourceInfo(item.source);
    var sevColor = _tfSevColor(item.severity);

    h += '<div style="padding:10px 14px;border-bottom:1px solid #0d1525;display:flex;gap:10px;align-items:flex-start;">';

    // Source badge
    h += '<div style="flex-shrink:0;min-width:44px;">';
    h += '<div style="background:' + src.color + '22;color:' + src.color + ';font-size:8px;font-family:monospace;padding:2px 4px;border-radius:2px;border:1px solid ' + src.color + '33;text-align:center;font-weight:bold;letter-spacing:1px;white-space:nowrap;">' + esc(src.icon) + '</div>';
    h += '</div>';

    // Content
    h += '<div style="flex:1;min-width:0;">';
    h += '<div style="display:flex;align-items:center;gap:6px;margin-bottom:2px;">';
    h += '<span style="font-family:monospace;font-size:12px;color:#c8d6e5;font-weight:bold;word-break:break-all;">' + esc(item.title.substring(0, 80)) + '</span>';
    h += '<span style="background:' + sevColor + '22;color:' + sevColor + ';font-size:7px;font-family:monospace;padding:1px 4px;border-radius:2px;flex-shrink:0;">' + (item.severity || '').toUpperCase() + '</span>';
    h += '</div>';
    if (item.subtitle) h += '<div style="font-family:monospace;font-size:10px;color:#8ab4d4;margin-bottom:2px;">' + esc(item.subtitle) + '</div>';
    if (item.desc) h += '<div style="font-family:monospace;font-size:9px;color:#4a6a8a;margin-bottom:3px;word-break:break-all;">' + esc(item.desc.substring(0, 200)) + '</div>';
    if (item.tags && item.tags.length > 0) {
      h += '<div style="display:flex;gap:3px;flex-wrap:wrap;">';
      for (var t = 0; t < item.tags.length; t++) {
        h += '<span style="background:#0a1a2a;color:#5a8aaa;font-size:7px;font-family:monospace;padding:1px 4px;border-radius:2px;border:1px solid #1a2a44;">' + esc(item.tags[t]) + '</span>';
      }
      h += '</div>';
    }
    h += '</div>';

    // Time
    h += '<div style="flex-shrink:0;font-family:monospace;font-size:9px;color:#3a5a7a;white-space:nowrap;">' + esc((item.time || '').substring(0, 16)) + '</div>';

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
  h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">';
  h += '<div>';
  h += '<h2 style="margin:0;font-size:20px;color:#ff8800;font-family:monospace;letter-spacing:2px;text-transform:uppercase;">THREAT FEED AGGREGATOR</h2>';
  h += '<div style="color:#4a6a8a;font-size:11px;font-family:monospace;margin-top:4px;">Unified view of ' + _tfSources.length + ' threat intelligence sources</div>';
  h += '</div>';
  h += '<div style="display:flex;gap:8px;align-items:center;">';
  h += '<div id="tf-status" style="background:#00ff8822;color:#00ff88;font-size:10px;font-family:monospace;padding:4px 10px;border-radius:4px;border:1px solid #00ff8844;font-weight:bold;">READY</div>';
  h += '<button onclick="_tfFetchAll()" style="background:#ff880022;border:1px solid #ff880066;border-radius:4px;padding:6px 14px;color:#ff8800;font-family:monospace;font-size:11px;font-weight:bold;cursor:pointer;">FETCH ALL</button>';
  h += '<button onclick="_tfExport()" style="background:#0a1a28;border:1px solid #1a3050;border-radius:4px;padding:6px 14px;color:#5a8aaa;font-family:monospace;font-size:11px;cursor:pointer;">EXPORT JSON</button>';
  h += '</div></div>';

  // Stats row
  h += '<div style="display:grid;grid-template-columns:repeat(7,1fr);gap:6px;margin-bottom:14px;">';
  var statDefs = [
    { id: 'tf-total', label: 'TOTAL', color: '#00aaff' },
    { id: 'tf-kev', label: 'CISA KEV', color: '#ff4444' },
    { id: 'tf-ioc', label: 'IOCs', color: '#ff8800' },
    { id: 'tf-c2', label: 'C2 SERVERS', color: '#aa44ff' },
    { id: 'tf-malurl', label: 'MAL URLS', color: '#ff00aa' },
    { id: 'tf-ransom', label: 'RANSOM', color: '#ff2222' },
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
  h += '<button onclick="_tfSetFilter(\'all\')" style="background:' + (_tfFilter === 'all' ? '#00aaff22' : '#0a0e1a') + ';border:1px solid ' + (_tfFilter === 'all' ? '#00aaff66' : '#1a2a44') + ';border-radius:4px;padding:4px 10px;color:' + (_tfFilter === 'all' ? '#00ddff' : '#4a6a8a') + ';font-family:monospace;font-size:10px;cursor:pointer;">ALL</button>';
  for (var fi = 0; fi < _tfSources.length; fi++) {
    var fs = _tfSources[fi];
    var isActive = _tfFilter === fs.id;
    h += '<button onclick="_tfSetFilter(\'' + fs.id + '\')" style="background:' + (isActive ? fs.color + '22' : '#0a0e1a') + ';border:1px solid ' + (isActive ? fs.color + '66' : '#1a2a44') + ';border-radius:4px;padding:4px 10px;color:' + (isActive ? fs.color : '#4a6a8a') + ';font-family:monospace;font-size:10px;cursor:pointer;">' + esc(fs.name) + '</button>';
  }
  h += '</div>';

  // Feed area
  h += '<div id="tf-feed" style="background:#080c14;border:1px solid #1a2a44;border-radius:8px;max-height:600px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:#1a3050 transparent;">';
  h += '<div style="color:#4a6a8a;font-family:monospace;font-size:11px;text-align:center;padding:40px;">Click FETCH ALL to load threat intelligence from all sources.</div>';
  h += '</div>';

  h += '</div>';

  container.innerHTML = h;
};

window._tfSetFilter = function(f) {
  _tfFilter = f;
  _tfRenderFeed();
  // Re-render to update button active states
  var container = document.getElementById('tf-feed');
  if (container && container.parentNode) {
    var parent = container.parentNode;
    // Just re-render the feed, don't re-render the whole UI
  }
};

window._tfFetchAll = _tfFetchAll;

window._tfExport = function() {
  var exportData = {
    exported: new Date().toISOString(),
    totalItems: _tfData.length,
    items: _tfData.map(function(d) { return { source: d.source, title: d.title, severity: d.severity, time: d.time, tags: d.tags }; })
  };
  _tfCopyToClipboard(JSON.stringify(exportData, null, 2));
  var statusEl = document.getElementById('tf-status');
  if (statusEl) { statusEl.textContent = 'COPIED'; setTimeout(function() { statusEl.textContent = 'LIVE'; }, 2000); }
};
