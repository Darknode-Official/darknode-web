// Copyright (c) 2026 Darknode-Official. All rights reserved.
// SSL Inspector — Certificate Transparency search, subdomain discovery, issuance analysis
// Uses crt.sh public API (no key required, CORS-friendly JSON output)

var esc = function(s) { return String(s != null ? s : '').replace(/[&<>"']/g, function(c) { return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

export function renderSSLInspector(container) {
  if (!container) return;
  var h = '';
  h += '<div class="ssl-wrap">';

  // Header
  h += '<div class="pg-head"><div>';
  h += '<h1 class="pg-h1">SSL Inspector</h1>';
  h += '<p class="muted pg-sub">Search Certificate Transparency logs for a domain\'s certificates, subdomains and issuance history. Source: crt.sh (no API key).</p>';
  h += '</div></div>';

  // Search bar
  h += '<div style="display:flex;gap:8px;margin-bottom:16px;">';
  h += '<input id="ssl-domain" type="text" placeholder="Domain" style="flex:1;" onkeydown="if(event.key===\'Enter\')_sslSearch()">';
  h += '<button class="btn" onclick="_sslSearch()">Search</button>';
  h += '</div>';

  // Tabs
  h += '<div id="ssl-tabs" class="seg" style="margin-bottom:16px;">';
  var tabs = [
    { id: 'certs', label: 'Certificates' },
    { id: 'subdomains', label: 'Subdomains' },
    { id: 'timeline', label: 'Timeline' },
    { id: 'analysis', label: 'Analysis' }
  ];
  for (var t = 0; t < tabs.length; t++) {
    h += '<button class="ssl-tab' + (t === 0 ? ' on' : '') + '" data-tab="' + tabs[t].id + '">' + esc(tabs[t].label) + '</button>';
  }
  h += '</div>';

  // Results
  h += '<div id="ssl-results" class="card" style="min-height:300px;">';
  h += '<div style="text-align:center;color:var(--mut);padding:60px 20px;">';
  h += '<div style="font-size:14px;">Enter a domain to search Certificate Transparency logs</div>';
  h += '<div style="font-size:12px;margin-top:6px;">Discovers subdomains, certificate history, and SSL chain information</div>';
  h += '</div></div>';

  h += '</div>';
  container.innerHTML = h;

  // Tab switching
  container.addEventListener('click', function(e) {
    if (e.target.classList.contains('ssl-tab')) {
      var allTabs = container.querySelectorAll('.ssl-tab');
      for (var i = 0; i < allTabs.length; i++) allTabs[i].classList.remove('on');
      e.target.classList.add('on');
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
  var domain = input.value.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '');
  if (!domain || domain.indexOf('.') < 1) {
    results.innerHTML = '<div style="color:var(--bad);padding:20px;text-align:center;">Enter a valid domain name</div>';
    return;
  }
  _sslData.domain = domain;
  results.innerHTML = '<div style="text-align:center;padding:40px;color:var(--acc);"><div style="font-size:14px;animation:pulse 1.5s ease-in-out infinite;">Querying CT logs for ' + esc(domain) + '...</div></div>';
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
          if (nm && nm.slice(-(domain.length + 1)) === '.' + domain) { // a SAN such as myexample.com or example.com.evil.net is not a subdomain
            subMap[nm] = (subMap[nm] || 0) + 1;
          }
        }
      }
      _sslData.subdomains = Object.keys(subMap).sort().map(function(s) { return { name: s, certCount: subMap[s] }; });
      _sslRenderTab(_sslActiveTab);
    })
    .catch(function(err) {
      results.innerHTML = '<div style="color:var(--bad);padding:20px;text-align:center;">' +
        '<div style="font-size:14px;font-weight:bold;margin-bottom:8px;">CT log query failed</div>' +
        '<div style="font-size:12px;color:var(--mut);">' + esc(err.message) + '</div>' +
        '<div style="font-size:12px;color:var(--mut);margin-top:8px;">crt.sh may be temporarily unavailable or rate-limited</div>' +
        '</div>';
    });
}

function _sslRenderTab(tabId) {
  _sslActiveTab = tabId;
  var results = document.getElementById('ssl-results');
  if (!results) return;
  if (_sslData.certs.length === 0) {
    results.innerHTML = '<div style="color:var(--mut);padding:20px;text-align:center;">No data — search a domain first</div>';
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
  h += '<div style="color:var(--txt);font-size:14px;font-weight:600;">' + certs.length + ' certificates found</div>';
  h += '<div style="display:flex;align-items:center;gap:10px;"><span style="color:var(--mut);font-size:12px;">Domain: ' + esc(_sslData.domain) + '</span>' + _sslGraphBtnHTML() + '</div>';
  h += '</div>';

  h += '<div style="overflow-x:auto;">';
  h += '<table style="width:100%;border-collapse:collapse;font-size:12px;">';
  h += '<thead><tr style="border-bottom:2px solid var(--line);">';
  var headers = ['ID', 'Common name', 'Issuer', 'Not before', 'Not after', 'Status'];
  for (var hi = 0; hi < headers.length; hi++) {
    h += '<th style="text-align:left;padding:6px 8px;color:var(--acc);font-size:12px;white-space:nowrap;">' + headers[hi] + '</th>';
  }
  h += '</tr></thead><tbody>';

  var limit = Math.min(certs.length, 100);
  var now = new Date();
  for (var i = 0; i < limit; i++) {
    var c = certs[i];
    var notAfter = new Date(c.not_after || '');
    var expired = notAfter < now;
    var statusColor = expired ? 'var(--bad)' : 'var(--ok)';
    var statusText = expired ? 'Expired' : 'Unexpired';
    var rowBg = i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)';

    h += '<tr style="border-bottom:1px solid var(--line);background:' + rowBg + ';">';
    h += '<td style="padding:5px 8px;color:var(--mut);">' + esc(String(c.id || '')) + '</td>';
    h += '<td style="padding:5px 8px;color:var(--txt);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + esc(c.common_name || '') + '">' + esc(c.common_name || '--') + '</td>';
    h += '<td style="padding:5px 8px;color:var(--txt-2);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + esc(c.issuer_name || '') + '">' + esc((c.issuer_name || '').replace(/^.*O=/, '').replace(/,.*$/, '') || '--') + '</td>';
    h += '<td style="padding:5px 8px;color:var(--mut);white-space:nowrap;">' + esc((c.not_before || '').substring(0, 10)) + '</td>';
    h += '<td style="padding:5px 8px;color:var(--mut);white-space:nowrap;">' + esc((c.not_after || '').substring(0, 10)) + '</td>';
    h += '<td style="padding:5px 8px;"><span style="color:' + statusColor + ';font-weight:bold;font-size:12px;">' + statusText + '</span></td>';
    h += '</tr>';
  }
  h += '</tbody></table></div>';
  if (certs.length > 100) h += '<div style="color:var(--mut);font-size:12px;margin-top:8px;text-align:center;">Showing first 100 of ' + certs.length + ' certificates</div>';
  el.innerHTML = h;
}

function _sslRenderSubdomains(el) {
  var subs = _sslData.subdomains;
  var h = '';
  h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">';
  h += '<div style="color:var(--txt);font-size:14px;font-weight:600;">' + subs.length + ' unique subdomains discovered</div>';
  h += '<button class="btn ghost sm" onclick="_sslCopySubdomains()">Copy all</button>';
  h += '</div>';

  if (subs.length === 0) {
    h += '<div style="color:var(--mut);text-align:center;padding:30px;">No subdomains found in certificate SAN fields</div>';
    el.innerHTML = h;
    return;
  }

  h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:6px;">';
  for (var i = 0; i < subs.length; i++) {
    var s = subs[i];
    var wildcard = s.name.indexOf('*.') === 0;
    h += '<div style="background:var(--card2);border:1px solid var(--line);border-radius:3px;padding:6px 10px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="navigator.clipboard.writeText(' + esc(JSON.stringify(s.name)) + ');this.style.borderColor=\'var(--ok)\';var el=this;setTimeout(function(){el.style.borderColor=\'var(--line)\';},500);">';
    h += '<span style="color:' + (wildcard ? 'var(--warn)' : 'var(--txt)') + ';font-size:12px;">' + (wildcard ? '<span style="color:var(--warn);">*</span> ' : '') + esc(s.name) + '</span>';
    h += '<span style="color:var(--mut);font-size:12px;">' + s.certCount + ' cert' + (s.certCount > 1 ? 's' : '') + '</span>';
    h += '</div>';
  }
  h += '</div>';
  el.innerHTML = h;
}

function _sslCopySubdomains() {
  var text = _sslData.subdomains.map(function(s) { return s.name; }).join('\n');
  navigator.clipboard.writeText(text).then(function() {
    var btn = document.querySelector('[onclick="_sslCopySubdomains()"]');
    if (btn) { btn.textContent = 'Copied'; setTimeout(function() { btn.textContent = 'Copy all'; }, 1500); }
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
  h += '<div style="color:var(--txt);font-size:14px;font-weight:600;margin-bottom:14px;">Certificate issuance timeline</div>';

  if (years.length === 0) {
    h += '<div style="color:var(--mut);text-align:center;padding:30px;">No timeline data available</div>';
    el.innerHTML = h;
    return;
  }

  h += '<div style="display:flex;align-items:flex-end;gap:6px;height:150px;padding:0 10px;border-bottom:1px solid var(--line);">';
  for (var yi = 0; yi < years.length; yi++) {
    var count = byYear[years[yi]];
    var pct = maxCount > 0 ? (count / maxCount * 100) : 0;
    var barH = Math.max(4, pct * 1.3);
    h += '<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:4px;">';
    h += '<div style="color:var(--acc-2);font-size:12px;">' + count + '</div>';
    h += '<div style="width:100%;max-width:40px;height:' + barH + 'px;background:linear-gradient(180deg,var(--acc-2),var(--acc-2));border-radius:2px 2px 0 0;"></div>';
    h += '</div>';
  }
  h += '</div>';
  h += '<div style="display:flex;gap:6px;padding:6px 10px;">';
  for (var yl = 0; yl < years.length; yl++) {
    h += '<div style="flex:1;text-align:center;color:var(--mut);font-size:12px;">' + years[yl] + '</div>';
  }
  h += '</div>';

  // Issuer breakdown
  var issuers = {};
  for (var ic = 0; ic < certs.length; ic++) {
    var issuer = (certs[ic].issuer_name || '').replace(/^.*O=/, '').replace(/,.*$/, '').trim() || 'Unknown';
    issuers[issuer] = (issuers[issuer] || 0) + 1;
  }
  var issuerList = Object.keys(issuers).map(function(k) { return { name: k, count: issuers[k] }; }).sort(function(a, b) { return b.count - a.count; }).slice(0, 10);

  h += '<div style="color:var(--txt);font-size:14px;font-weight:600;margin:20px 0 10px;">Top issuers</div>';
  for (var il = 0; il < issuerList.length; il++) {
    var iss = issuerList[il];
    var issPct = certs.length > 0 ? (iss.count / certs.length * 100).toFixed(1) : '0';
    h += '<div style="display:flex;align-items:center;gap:10px;margin:4px 0;">';
    h += '<div style="width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--txt);font-size:12px;" title="' + esc(iss.name) + '">' + esc(iss.name) + '</div>';
    h += '<div style="flex:1;height:6px;background:var(--line);border-radius:3px;overflow:hidden;"><div style="height:100%;width:' + issPct + '%;background:linear-gradient(90deg,var(--warn),var(--warn));border-radius:3px;"></div></div>';
    h += '<div style="color:var(--warn);font-size:12px;min-width:50px;text-align:right;">' + iss.count + ' (' + issPct + '%)</div>';
    h += '</div>';
  }

  el.innerHTML = h;
}

// Findings derived from CT log statistics (shared by the Analysis tab and the graph export).
function _sslFindings(st) {
  var findings = [];
  // CT logs keep every certificate ever issued, so most entries are expired by design; only flag a domain with no unexpired certificate at all.
  if (st.total > 0 && st.expired === st.total) findings.push({ severity: 'MEDIUM', title: 'No unexpired certificate in CT logs', msg: 'Every certificate logged for this domain has passed its expiry date. Check whether the site still serves TLS with a current certificate.' });
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
  return '<button class="btn ghost sm" onclick="_sslToGraph(this)">Send to Security Graph</button>';
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
  import('/js/graph-bridge.js?v=20261028c').then(function(gb) {
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
    btn.textContent = 'Sent: ' + created + ' new, ' + updated + ' merged';
    gb.showGraphToast('Security Graph: ' + domain + ', ' + cr.entities.length + ' certificates, ' + fr.entities.length + ' findings');
  }).catch(function() { btn.textContent = 'Graph unavailable'; btn.disabled = false; });
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
  h += '<div style="color:var(--txt);font-size:14px;font-weight:600;margin-bottom:14px;">Security analysis</div>';

  // Stats grid
  h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin-bottom:20px;">';
  var stats = [
    { label: 'Total certs', value: certs.length, color: '#00d4ff' },
    { label: 'Unexpired', value: valid, color: '#00ff88' },
    { label: 'Expired', value: expired, color: '#ff4444' },
    { label: 'Wildcards', value: wildcards, color: '#ffaa00' },
    { label: 'Last 30 days', value: recent30d, color: '#aa66ff' },
    { label: 'Subdomains', value: _sslData.subdomains.length, color: '#00ff88' },
    { label: 'Unique issuers', value: Object.keys(uniqueIssuers).length, color: '#ffaa00' }
  ];
  for (var si = 0; si < stats.length; si++) {
    var st = stats[si];
    h += '<div style="background:var(--card2);border:1px solid ' + st.color + '33;border-radius:4px;padding:10px;text-align:center;">';
    h += '<div style="color:' + st.color + ';font-size:20px;font-weight:bold;">' + st.value + '</div>';
    h += '<div style="color:var(--mut);font-size:12px;margin-top:2px;">' + st.label + '</div>';
    h += '</div>';
  }
  h += '</div>';

  // Security findings
  h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">';
  h += '<div style="color:var(--txt);font-size:14px;font-weight:600;">Findings</div>';
  h += _sslGraphBtnHTML();
  h += '</div>';
  var findings = _sslFindings({ total: certs.length, expired: expired, wildcards: wildcards, issuers: Object.keys(uniqueIssuers).length, recent30d: recent30d });
  if (findings.length === 0) findings.push({ severity: 'INFO', msg: 'No significant issues detected in certificate transparency data' });

  var sevColors = { HIGH: 'var(--bad)', MEDIUM: 'var(--warn)', LOW: 'var(--warn)', INFO: 'var(--acc)' };
  for (var fi = 0; fi < findings.length; fi++) {
    var f = findings[fi];
    h += '<div style="background:var(--card2);border-left:3px solid ' + sevColors[f.severity] + ';padding:8px 12px;margin:6px 0;border-radius:0 4px 4px 0;">';
    h += '<span style="color:' + sevColors[f.severity] + ';font-size:12px;font-weight:bold;margin-right:8px;">[' + f.severity + ']</span>';
    h += '<span style="color:var(--txt);font-size:12px;">' + esc(f.msg) + '</span>';
    h += '</div>';
  }

  el.innerHTML = h;
}

window._sslSearch = _sslSearch;
window._sslCopySubdomains = _sslCopySubdomains;
window._sslToGraph = _sslToGraph;
