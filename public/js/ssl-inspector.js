// Copyright (c) 2026 Darknode-Official. All rights reserved.
// SSL Inspector — Certificate Transparency search, subdomain discovery, chain analysis
// Uses crt.sh public API (no key required, CORS-friendly JSON output)

var esc = function(s) { return String(s != null ? s : '').replace(/[&<>"']/g, function(c) { return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

export function renderSSLInspector(container) {
  if (!container) return;
  var h = '';
  h += '<div style="background:#0a0e14;color:#c8d6e5;font-family:\'Courier New\',monospace;padding:24px;min-height:80vh;">';

  // Header
  h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;">';
  h += '<div>';
  h += '<h2 style="margin:0;font-size:20px;color:#00d4ff;letter-spacing:2px;">SSL INSPECTOR</h2>';
  h += '<div style="color:#4a6a8a;font-size:11px;letter-spacing:1px;margin-top:4px;">Certificate Transparency Search &bull; Subdomain Discovery &bull; Chain Analysis</div>';
  h += '</div>';
  h += '<div style="display:flex;gap:6px;">';
  h += '<div style="background:#0a1a2a;border:1px solid #00d4ff33;border-radius:6px;padding:6px 14px;text-align:center;">';
  h += '<div style="color:#556;font-size:8px;letter-spacing:1px;">SOURCE</div>';
  h += '<div style="color:#00d4ff;font-size:12px;font-weight:bold;">crt.sh</div>';
  h += '</div>';
  h += '<div style="background:#0a1a2a;border:1px solid #00ff8833;border-radius:6px;padding:6px 14px;text-align:center;">';
  h += '<div style="color:#556;font-size:8px;letter-spacing:1px;">API KEY</div>';
  h += '<div style="color:#00ff88;font-size:12px;font-weight:bold;">NONE</div>';
  h += '</div>';
  h += '</div></div>';

  // Search bar
  h += '<div style="display:flex;gap:8px;margin-bottom:20px;">';
  h += '<input id="ssl-domain" type="text" placeholder="Enter domain (e.g. example.com)" style="flex:1;background:#0c1525;border:1px solid #1a3a5c;border-radius:4px;padding:10px 14px;color:#c8d6e5;font-family:monospace;font-size:13px;outline:none;" onkeydown="if(event.key===\'Enter\')_sslSearch()">';
  h += '<button onclick="_sslSearch()" style="background:#00d4ff22;color:#00d4ff;border:1px solid #00d4ff44;border-radius:4px;padding:10px 20px;font-family:monospace;font-size:12px;cursor:pointer;letter-spacing:1px;font-weight:bold;">SEARCH</button>';
  h += '</div>';

  // Tabs
  h += '<div id="ssl-tabs" style="display:flex;gap:4px;margin-bottom:16px;">';
  var tabs = [
    { id: 'certs', label: 'Certificates' },
    { id: 'subdomains', label: 'Subdomains' },
    { id: 'timeline', label: 'Timeline' },
    { id: 'analysis', label: 'Analysis' }
  ];
  for (var t = 0; t < tabs.length; t++) {
    var active = t === 0 ? 'background:#00d4ff22;border-color:#00d4ff66;color:#00d4ff;' : 'background:#0a0e1a;border-color:#1a2a44;color:#556;';
    h += '<button class="ssl-tab" data-tab="' + tabs[t].id + '" style="' + active + 'border:1px solid;border-radius:4px;padding:6px 14px;font-family:monospace;font-size:11px;cursor:pointer;letter-spacing:1px;">' + esc(tabs[t].label) + '</button>';
  }
  h += '</div>';

  // Results
  h += '<div id="ssl-results" style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:20px;min-height:300px;">';
  h += '<div style="text-align:center;color:#4a6a8a;padding:60px 20px;">';
  h += '<div style="font-size:40px;margin-bottom:12px;opacity:0.3;">&#x1F50D;</div>';
  h += '<div style="font-size:13px;">Enter a domain to search Certificate Transparency logs</div>';
  h += '<div style="font-size:10px;color:#3a5a7a;margin-top:6px;">Discovers subdomains, certificate history, and SSL chain information</div>';
  h += '</div></div>';

  h += '</div>';
  container.innerHTML = h;

  // Tab switching
  container.addEventListener('click', function(e) {
    if (e.target.classList.contains('ssl-tab')) {
      var allTabs = container.querySelectorAll('.ssl-tab');
      for (var i = 0; i < allTabs.length; i++) {
        allTabs[i].style.background = '#0a0e1a';
        allTabs[i].style.borderColor = '#1a2a44';
        allTabs[i].style.color = '#556';
      }
      e.target.style.background = '#00d4ff22';
      e.target.style.borderColor = '#00d4ff66';
      e.target.style.color = '#00d4ff';
      _sslRenderTab(e.target.getAttribute('data-tab'));
    }
  });
};

var _sslData = { certs: [], subdomains: [], domain: '' };
var _sslActiveTab = 'certs';

function _sslSearch() {
  var input = document.getElementById('ssl-domain');
  var results = document.getElementById('ssl-results');
  if (!input || !results) return;
  var domain = input.value.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (!domain || domain.indexOf('.') < 1) {
    results.innerHTML = '<div style="color:#ff4444;padding:20px;text-align:center;">Enter a valid domain name</div>';
    return;
  }
  _sslData.domain = domain;
  results.innerHTML = '<div style="text-align:center;padding:40px;color:#00d4ff;"><div style="font-size:14px;letter-spacing:2px;animation:pulse 1.5s ease-in-out infinite;">QUERYING CT LOGS FOR ' + esc(domain.toUpperCase()) + '...</div></div>';
  _sslActiveTab = 'certs';

  fetch('https://crt.sh/?q=%25.' + encodeURIComponent(domain) + '&output=json')
    .then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
    .then(function(data) {
      _sslData.certs = data || [];
      // Extract unique subdomains from name_value fields
      var subMap = {};
      for (var i = 0; i < _sslData.certs.length; i++) {
        var names = (_sslData.certs[i].name_value || '').split('\n');
        for (var n = 0; n < names.length; n++) {
          var nm = names[n].trim().toLowerCase().replace(/^\*\./, '');
          if (nm && nm.indexOf(domain) !== -1 && nm !== domain) {
            subMap[nm] = (subMap[nm] || 0) + 1;
          }
        }
      }
      _sslData.subdomains = Object.keys(subMap).sort().map(function(s) { return { name: s, certCount: subMap[s] }; });
      _sslRenderTab(_sslActiveTab);
    })
    .catch(function(err) {
      results.innerHTML = '<div style="color:#ff4444;padding:20px;text-align:center;">' +
        '<div style="font-size:14px;font-weight:bold;margin-bottom:8px;">CT LOG QUERY FAILED</div>' +
        '<div style="font-size:11px;color:#aa6666;">' + esc(err.message) + '</div>' +
        '<div style="font-size:10px;color:#556;margin-top:8px;">crt.sh may be temporarily unavailable or rate-limited</div>' +
        '</div>';
    });
}

function _sslRenderTab(tabId) {
  _sslActiveTab = tabId;
  var results = document.getElementById('ssl-results');
  if (!results) return;
  if (_sslData.certs.length === 0) {
    results.innerHTML = '<div style="color:#556;padding:20px;text-align:center;">No data — search a domain first</div>';
    return;
  }
  switch (tabId) {
    case 'certs': _sslRenderCerts(results); break;
    case 'subdomains': _sslRenderSubdomains(results); break;
    case 'timeline': _sslRenderTimeline(results); break;
    case 'analysis': _sslRenderAnalysis(results); break;
  }
}

function _sslRenderCerts(el) {
  var certs = _sslData.certs;
  var h = '';
  h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">';
  h += '<div style="color:#00d4ff;font-size:12px;letter-spacing:1px;">' + certs.length + ' CERTIFICATES FOUND</div>';
  h += '<div style="display:flex;align-items:center;gap:10px;"><span style="color:#556;font-size:10px;">Domain: ' + esc(_sslData.domain) + '</span>' + _sslGraphBtnHTML() + '</div>';
  h += '</div>';

  h += '<div style="overflow-x:auto;">';
  h += '<table style="width:100%;border-collapse:collapse;font-size:10px;">';
  h += '<thead><tr style="border-bottom:2px solid #1a3a5c;">';
  var headers = ['ID', 'COMMON NAME', 'ISSUER', 'NOT BEFORE', 'NOT AFTER', 'STATUS'];
  for (var hi = 0; hi < headers.length; hi++) {
    h += '<th style="text-align:left;padding:6px 8px;color:#00d4ff;font-size:9px;letter-spacing:1px;white-space:nowrap;">' + headers[hi] + '</th>';
  }
  h += '</tr></thead><tbody>';

  var limit = Math.min(certs.length, 100);
  var now = new Date();
  for (var i = 0; i < limit; i++) {
    var c = certs[i];
    var notAfter = new Date(c.not_after || '');
    var expired = notAfter < now;
    var statusColor = expired ? '#ff4444' : '#00ff88';
    var statusText = expired ? 'EXPIRED' : 'VALID';
    var rowBg = i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)';

    h += '<tr style="border-bottom:1px solid #0d1525;background:' + rowBg + ';">';
    h += '<td style="padding:5px 8px;color:#556;">' + esc(String(c.id || '')) + '</td>';
    h += '<td style="padding:5px 8px;color:#c8d6e5;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + esc(c.common_name || '') + '">' + esc(c.common_name || '--') + '</td>';
    h += '<td style="padding:5px 8px;color:#8899aa;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + esc(c.issuer_name || '') + '">' + esc((c.issuer_name || '').replace(/^.*O=/, '').replace(/,.*$/, '') || '--') + '</td>';
    h += '<td style="padding:5px 8px;color:#6688aa;white-space:nowrap;">' + esc((c.not_before || '').substring(0, 10)) + '</td>';
    h += '<td style="padding:5px 8px;color:#6688aa;white-space:nowrap;">' + esc((c.not_after || '').substring(0, 10)) + '</td>';
    h += '<td style="padding:5px 8px;"><span style="color:' + statusColor + ';font-weight:bold;font-size:9px;letter-spacing:1px;">' + statusText + '</span></td>';
    h += '</tr>';
  }
  h += '</tbody></table></div>';
  if (certs.length > 100) h += '<div style="color:#556;font-size:10px;margin-top:8px;text-align:center;">Showing first 100 of ' + certs.length + ' certificates</div>';
  el.innerHTML = h;
}

function _sslRenderSubdomains(el) {
  var subs = _sslData.subdomains;
  var h = '';
  h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">';
  h += '<div style="color:#00ff88;font-size:12px;letter-spacing:1px;">' + subs.length + ' UNIQUE SUBDOMAINS DISCOVERED</div>';
  h += '<button onclick="_sslCopySubdomains()" style="background:#00ff8822;color:#00ff88;border:1px solid #00ff8844;border-radius:4px;padding:4px 12px;font-family:monospace;font-size:10px;cursor:pointer;">COPY ALL</button>';
  h += '</div>';

  if (subs.length === 0) {
    h += '<div style="color:#556;text-align:center;padding:30px;">No subdomains found in certificate SAN fields</div>';
    el.innerHTML = h;
    return;
  }

  h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:6px;">';
  for (var i = 0; i < subs.length; i++) {
    var s = subs[i];
    var wildcard = s.name.indexOf('*.') === 0;
    h += '<div style="background:#0a1018;border:1px solid #1a2a44;border-radius:3px;padding:6px 10px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="navigator.clipboard.writeText(\'' + esc(s.name) + '\');this.style.borderColor=\'#00ff88\';var el=this;setTimeout(function(){el.style.borderColor=\'#1a2a44\';},500);">';
    h += '<span style="color:' + (wildcard ? '#ffaa00' : '#c8d6e5') + ';font-size:11px;">' + (wildcard ? '<span style="color:#ffaa00;">*</span> ' : '') + esc(s.name) + '</span>';
    h += '<span style="color:#556;font-size:9px;">' + s.certCount + ' cert' + (s.certCount > 1 ? 's' : '') + '</span>';
    h += '</div>';
  }
  h += '</div>';
  el.innerHTML = h;
}

function _sslCopySubdomains() {
  var text = _sslData.subdomains.map(function(s) { return s.name; }).join('\n');
  navigator.clipboard.writeText(text).then(function() {
    var btn = document.querySelector('[onclick="_sslCopySubdomains()"]');
    if (btn) { btn.textContent = 'COPIED!'; setTimeout(function() { btn.textContent = 'COPY ALL'; }, 1500); }
  });
}

function _sslRenderTimeline(el) {
  var certs = _sslData.certs;
  // Group by year
  var byYear = {};
  for (var i = 0; i < certs.length; i++) {
    var year = (certs[i].not_before || '').substring(0, 4);
    if (!year || year.length !== 4) continue;
    byYear[year] = (byYear[year] || 0) + 1;
  }
  var years = Object.keys(byYear).sort();
  var maxCount = 0;
  for (var y = 0; y < years.length; y++) { if (byYear[years[y]] > maxCount) maxCount = byYear[years[y]]; }

  var h = '';
  h += '<div style="color:#aa66ff;font-size:12px;letter-spacing:1px;margin-bottom:14px;">CERTIFICATE ISSUANCE TIMELINE</div>';

  if (years.length === 0) {
    h += '<div style="color:#556;text-align:center;padding:30px;">No timeline data available</div>';
    el.innerHTML = h;
    return;
  }

  h += '<div style="display:flex;align-items:flex-end;gap:6px;height:150px;padding:0 10px;border-bottom:1px solid #1a3a5c;">';
  for (var yi = 0; yi < years.length; yi++) {
    var count = byYear[years[yi]];
    var pct = maxCount > 0 ? (count / maxCount * 100) : 0;
    var barH = Math.max(4, pct * 1.3);
    h += '<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:4px;">';
    h += '<div style="color:#aa66ff;font-size:9px;">' + count + '</div>';
    h += '<div style="width:100%;max-width:40px;height:' + barH + 'px;background:linear-gradient(180deg,#aa66ff,#6633cc);border-radius:2px 2px 0 0;"></div>';
    h += '</div>';
  }
  h += '</div>';
  h += '<div style="display:flex;gap:6px;padding:6px 10px;">';
  for (var yl = 0; yl < years.length; yl++) {
    h += '<div style="flex:1;text-align:center;color:#556;font-size:9px;">' + years[yl] + '</div>';
  }
  h += '</div>';

  // Issuer breakdown
  var issuers = {};
  for (var ic = 0; ic < certs.length; ic++) {
    var issuer = (certs[ic].issuer_name || '').replace(/^.*O=/, '').replace(/,.*$/, '').trim() || 'Unknown';
    issuers[issuer] = (issuers[issuer] || 0) + 1;
  }
  var issuerList = Object.keys(issuers).map(function(k) { return { name: k, count: issuers[k] }; }).sort(function(a, b) { return b.count - a.count; }).slice(0, 10);

  h += '<div style="color:#ffaa00;font-size:12px;letter-spacing:1px;margin:20px 0 10px;">TOP ISSUERS</div>';
  for (var il = 0; il < issuerList.length; il++) {
    var iss = issuerList[il];
    var issPct = certs.length > 0 ? (iss.count / certs.length * 100).toFixed(1) : '0';
    h += '<div style="display:flex;align-items:center;gap:10px;margin:4px 0;">';
    h += '<div style="width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#c8d6e5;font-size:10px;" title="' + esc(iss.name) + '">' + esc(iss.name) + '</div>';
    h += '<div style="flex:1;height:6px;background:#1a2a3a;border-radius:3px;overflow:hidden;"><div style="height:100%;width:' + issPct + '%;background:linear-gradient(90deg,#ffaa00,#ff6600);border-radius:3px;"></div></div>';
    h += '<div style="color:#ffaa00;font-size:10px;min-width:50px;text-align:right;">' + iss.count + ' (' + issPct + '%)</div>';
    h += '</div>';
  }

  el.innerHTML = h;
}

// Findings derived from CT log statistics (shared by the Analysis tab and the graph export).
function _sslFindings(st) {
  var findings = [];
  if (st.expired > st.total * 0.5) findings.push({ severity: 'HIGH', title: 'Poor certificate lifecycle management', msg: 'Over 50% of certificates are expired — poor certificate lifecycle management' });
  if (st.wildcards > 5) findings.push({ severity: 'MEDIUM', title: 'Excessive wildcard certificates', msg: st.wildcards + ' wildcard certificates found — increases attack surface if private keys are compromised' });
  if (st.issuers > 5) findings.push({ severity: 'LOW', title: 'Many certificate issuers', msg: 'Multiple certificate issuers (' + st.issuers + ') — consider consolidating for easier management' });
  if (st.recent30d > 10) findings.push({ severity: 'INFO', title: 'High certificate churn', msg: st.recent30d + ' certificates issued in last 30 days — high certificate churn may indicate automation or rapid deployment' });
  if (_sslData.subdomains.length > 50) findings.push({ severity: 'INFO', title: 'Large CT-exposed attack surface', msg: _sslData.subdomains.length + ' subdomains discovered — large attack surface exposed via CT logs' });
  return findings;
}

function _sslCertStats() {
  var certs = _sslData.certs, now = new Date();
  var st = { total: certs.length, expired: 0, wildcards: 0, issuers: 0, recent30d: 0 };
  var iss = {};
  for (var i = 0; i < certs.length; i++) {
    var c = certs[i];
    if (new Date(c.not_after || '') < now) st.expired++;
    if ((c.common_name || '').indexOf('*') !== -1 || (c.name_value || '').indexOf('*') !== -1) st.wildcards++;
    if ((now - new Date(c.not_before || '')) < 30 * 86400000) st.recent30d++;
    var org = (c.issuer_name || '').replace(/^.*O=/, '').replace(/,.*$/, '').trim();
    if (org) iss[org] = true;
  }
  st.issuers = Object.keys(iss).length;
  return st;
}

function _sslGraphBtnHTML() {
  return '<button onclick="_sslToGraph(this)" style="background:#00aaff22;color:#00aaff;border:1px solid #00aaff44;border-radius:4px;padding:4px 12px;font-family:monospace;font-size:10px;cursor:pointer;letter-spacing:1px;">SEND TO SECURITY GRAPH</button>';
}

// Live crt.sh data: root DOMAIN, currently valid certificates (newest 50) as CERTIFICATE
// linked to the domain, and CT-derived findings as FINDING --affects--> DOMAIN.
function _sslToGraph(btn) {
  var domain = _sslData.domain;
  if (!domain || !_sslData.certs.length) return;
  var now = new Date();
  var valid = _sslData.certs.filter(function(c) { return new Date(c.not_after || '') >= now; })
    .sort(function(a, b) { return String(b.not_before || '').localeCompare(String(a.not_before || '')); })
    .slice(0, 50);
  var findings = _sslFindings(_sslCertStats());
  var sevMap = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low', INFO: 'info' };
  var tags = ['ssl', 'ct-log', 'crt.sh'];
  btn.disabled = true;
  import('/js/graph-bridge.js?v=20260923c').then(function(gb) {
    var rr = gb.sendToGraph('SSL Inspector', [{ type: 'DOMAIN', name: domain, data: { ctCertificates: _sslData.certs.length, ctSubdomains: _sslData.subdomains.length }, opts: { tags: tags } }], undefined, true);
    var root = rr.entities[0];
    var cr = gb.sendToGraph('SSL Inspector', valid.map(function(c) {
      return {
        type: 'CERTIFICATE', name: (c.common_name || domain) + ' #' + (c.id || c.serial_number || ''),
        data: { commonName: c.common_name || '', sans: (c.name_value || '').split('\n').join(', '), issuer: c.issuer_name || '', notBefore: c.not_before || '', notAfter: c.not_after || '', serial: c.serial_number || '', crtShId: c.id || '' },
        opts: { tags: tags.concat(((c.common_name || '').indexOf('*') !== -1) ? ['wildcard'] : []) }
      };
    }), undefined, true);
    var fr = gb.sendToGraph('SSL Inspector', findings.map(function(f) {
      return { type: 'FINDING', name: f.title + ' (' + domain + ')', data: { description: f.msg, domain: domain, source: 'CT log analysis' }, opts: { tags: tags, severity: sevMap[f.severity] || null } };
    }), undefined, true);
    if (root) {
      cr.entities.forEach(function(e) { gb.linkEntities(e.id, root.id, 'related_to'); });
      fr.entities.forEach(function(e) { gb.linkEntities(e.id, root.id, 'affects'); });
    }
    var created = rr.created + cr.created + fr.created, updated = rr.updated + cr.updated + fr.updated;
    btn.textContent = 'SENT: ' + created + ' NEW, ' + updated + ' MERGED';
    gb.showGraphToast('Security Graph: ' + domain + ', ' + cr.entities.length + ' certificates, ' + fr.entities.length + ' findings');
  }).catch(function() { btn.textContent = 'GRAPH UNAVAILABLE'; btn.disabled = false; });
}

function _sslRenderAnalysis(el) {
  var certs = _sslData.certs;
  var now = new Date();
  var expired = 0, valid = 0, wildcards = 0, recent30d = 0;
  var uniqueIssuers = {};
  for (var i = 0; i < certs.length; i++) {
    var c = certs[i];
    var notAfter = new Date(c.not_after || '');
    var notBefore = new Date(c.not_before || '');
    if (notAfter < now) expired++;
    else valid++;
    if ((c.common_name || '').indexOf('*') !== -1 || (c.name_value || '').indexOf('*') !== -1) wildcards++;
    if ((now - notBefore) < 30 * 86400000) recent30d++;
    var issOrg = (c.issuer_name || '').replace(/^.*O=/, '').replace(/,.*$/, '').trim();
    if (issOrg) uniqueIssuers[issOrg] = true;
  }

  var h = '';
  h += '<div style="color:#00d4ff;font-size:12px;letter-spacing:1px;margin-bottom:14px;">SECURITY ANALYSIS</div>';

  // Stats grid
  h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin-bottom:20px;">';
  var stats = [
    { label: 'TOTAL CERTS', value: certs.length, color: '#00d4ff' },
    { label: 'VALID', value: valid, color: '#00ff88' },
    { label: 'EXPIRED', value: expired, color: '#ff4444' },
    { label: 'WILDCARDS', value: wildcards, color: '#ffaa00' },
    { label: 'LAST 30 DAYS', value: recent30d, color: '#aa66ff' },
    { label: 'SUBDOMAINS', value: _sslData.subdomains.length, color: '#00ff88' },
    { label: 'UNIQUE ISSUERS', value: Object.keys(uniqueIssuers).length, color: '#ffaa00' }
  ];
  for (var si = 0; si < stats.length; si++) {
    var st = stats[si];
    h += '<div style="background:#0a1018;border:1px solid ' + st.color + '33;border-radius:4px;padding:10px;text-align:center;">';
    h += '<div style="color:' + st.color + ';font-size:20px;font-weight:bold;">' + st.value + '</div>';
    h += '<div style="color:#556;font-size:8px;letter-spacing:1px;margin-top:2px;">' + st.label + '</div>';
    h += '</div>';
  }
  h += '</div>';

  // Security findings
  h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">';
  h += '<div style="color:#ff6644;font-size:12px;letter-spacing:1px;">FINDINGS</div>';
  h += _sslGraphBtnHTML();
  h += '</div>';
  var findings = _sslFindings({ total: certs.length, expired: expired, wildcards: wildcards, issuers: Object.keys(uniqueIssuers).length, recent30d: recent30d });
  if (findings.length === 0) findings.push({ severity: 'INFO', msg: 'No significant issues detected in certificate transparency data' });

  var sevColors = { HIGH: '#ff4444', MEDIUM: '#ff8800', LOW: '#ffcc00', INFO: '#00aaff' };
  for (var fi = 0; fi < findings.length; fi++) {
    var f = findings[fi];
    h += '<div style="background:#0a1018;border-left:3px solid ' + sevColors[f.severity] + ';padding:8px 12px;margin:6px 0;border-radius:0 4px 4px 0;">';
    h += '<span style="color:' + sevColors[f.severity] + ';font-size:9px;font-weight:bold;letter-spacing:1px;margin-right:8px;">[' + f.severity + ']</span>';
    h += '<span style="color:#c8d6e5;font-size:11px;">' + esc(f.msg) + '</span>';
    h += '</div>';
  }

  el.innerHTML = h;
}

window._sslSearch = _sslSearch;
window._sslCopySubdomains = _sslCopySubdomains;
window._sslToGraph = _sslToGraph;
