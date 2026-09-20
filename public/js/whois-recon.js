// Copyright (c) 2026 Darknode-Official. All rights reserved.
// WHOIS Recon — Domain/IP Intelligence Tool
// DNS lookups, IP geolocation, certificate transparency, reverse DNS
// All queries run in the browser via free CORS-friendly APIs

var esc = function(s) { return String(s != null ? s : '').replace(/[&<>"']/g, function(c) { return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

var _wrHistory = [];
var _wrMaxHistory = 20;

function _wrLoadHistory() {
  try { _wrHistory = JSON.parse(localStorage.getItem('dn_whois_history') || '[]'); } catch (_) { _wrHistory = []; }
}
function _wrSaveHistory() {
  try { localStorage.setItem('dn_whois_history', JSON.stringify(_wrHistory.slice(0, _wrMaxHistory))); } catch (_) {}
}
function _wrAddHistory(query, type) {
  _wrHistory.unshift({ query: query, type: type, time: new Date().toISOString() });
  if (_wrHistory.length > _wrMaxHistory) _wrHistory.length = _wrMaxHistory;
  _wrSaveHistory();
}

function _wrCopyText(text) {
  try { navigator.clipboard.writeText(text); } catch (_) {
    var ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
  }
}

function _wrIsIP(str) { return /^(\d{1,3}\.){3}\d{1,3}$/.test(str); }

// Google DNS-over-HTTPS
function _wrDnsLookup(domain, type) {
  return fetch('https://dns.google/resolve?name=' + encodeURIComponent(domain) + '&type=' + type)
    .then(function(r) { return r.json(); })
    .then(function(data) { return data.Answer || []; });
}

// Cloudflare DNS fallback
function _wrDnsCF(domain, type) {
  return fetch('https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(domain) + '&type=' + type, {
    headers: { 'Accept': 'application/dns-json' }
  }).then(function(r) { return r.json(); })
    .then(function(data) { return data.Answer || []; });
}

// IP geolocation
function _wrGeoIP(ip) {
  return fetch('https://ipapi.co/' + encodeURIComponent(ip) + '/json/')
    .then(function(r) { return r.json(); });
}

// Certificate Transparency
function _wrCertSearch(domain) {
  return fetch('https://crt.sh/?q=%25.' + encodeURIComponent(domain) + '&output=json')
    .then(function(r) { return r.json(); })
    .catch(function() { return []; });
}

// Reverse DNS
function _wrReverseDNS(ip) {
  var arpa = ip.split('.').reverse().join('.') + '.in-addr.arpa';
  return _wrDnsLookup(arpa, 'PTR');
}

function _wrRenderTable(headers, rows) {
  var h = '<div style="overflow-x:auto;margin:8px 0;">';
  h += '<table style="width:100%;border-collapse:collapse;font-family:monospace;font-size:11px;">';
  h += '<thead><tr>';
  for (var i = 0; i < headers.length; i++) {
    h += '<th style="text-align:left;padding:6px 10px;color:#00aaff;font-size:9px;letter-spacing:1px;border-bottom:2px solid #1a2a44;white-space:nowrap;">' + esc(headers[i]) + '</th>';
  }
  h += '</tr></thead><tbody>';
  for (var r = 0; r < rows.length; r++) {
    h += '<tr style="border-bottom:1px solid #0d1525;">';
    for (var c = 0; c < rows[r].length; c++) {
      h += '<td style="padding:5px 10px;color:#c8d6e5;word-break:break-all;">' + esc(String(rows[r][c])) + '</td>';
    }
    h += '</tr>';
  }
  h += '</tbody></table></div>';
  return h;
}

function _wrRenderSection(title, contentHtml, copyData) {
  var copyBtn = copyData ? ' <span onclick="_wrCopyText(\'' + esc(copyData.replace(/'/g, "\\'")) + '\')" style="color:#4a6a8a;cursor:pointer;font-size:9px;letter-spacing:1px;margin-left:8px;">[COPY]</span>' : '';
  return '<div style="margin-bottom:16px;">' +
    '<div style="color:#00aaff;font-size:11px;font-family:monospace;letter-spacing:2px;font-weight:bold;margin-bottom:6px;border-bottom:1px solid #1a2a44;padding-bottom:4px;">' + esc(title) + copyBtn + '</div>' +
    contentHtml + '</div>';
}

async function _wrRunLookup(query) {
  var resultsEl = document.getElementById('wr-results');
  if (!resultsEl) return;
  query = query.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (!query) { resultsEl.innerHTML = '<div style="color:#ff4444;font-family:monospace;font-size:11px;padding:16px;">Enter a domain or IP address.</div>'; return; }

  resultsEl.innerHTML = '<div style="text-align:center;padding:30px;color:#00aaff;font-family:monospace;font-size:12px;">Querying intelligence sources for <b>' + esc(query) + '</b>...</div>';
  _wrAddHistory(query, _wrIsIP(query) ? 'ip' : 'domain');
  _wrRenderHistory();

  var html = '';
  var isIP = _wrIsIP(query);

  try {
    // DNS Records (for domains)
    if (!isIP) {
      var types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'];
      var dnsResults = {};
      var dnsPromises = types.map(function(t) {
        return _wrDnsLookup(query, t).then(function(answers) { dnsResults[t] = answers; }).catch(function() { dnsResults[t] = []; });
      });
      await Promise.all(dnsPromises);

      var dnsRows = [];
      var allIPs = [];
      for (var t = 0; t < types.length; t++) {
        var answers = dnsResults[types[t]] || [];
        for (var a = 0; a < answers.length; a++) {
          dnsRows.push([types[t], answers[a].name || query, answers[a].data || '--', answers[a].TTL || '--']);
          if (types[t] === 'A') allIPs.push(answers[a].data);
        }
      }
      if (dnsRows.length > 0) {
        html += _wrRenderSection('DNS RECORDS', _wrRenderTable(['TYPE', 'NAME', 'VALUE', 'TTL'], dnsRows), dnsRows.map(function(r) { return r.join('\t'); }).join('\n'));
      } else {
        html += _wrRenderSection('DNS RECORDS', '<div style="color:#ff6644;font-family:monospace;font-size:11px;">No DNS records found for ' + esc(query) + '</div>');
      }

      // GeoIP for first A record
      if (allIPs.length > 0) {
        try {
          var geo = await _wrGeoIP(allIPs[0]);
          var geoRows = [
            ['IP', allIPs[0]], ['Country', (geo.country_name || '--') + ' (' + (geo.country_code || '--') + ')'],
            ['Region', geo.region || '--'], ['City', geo.city || '--'],
            ['ISP', geo.org || '--'], ['ASN', geo.asn || '--'],
            ['Timezone', geo.timezone || '--'], ['Latitude', geo.latitude || '--'],
            ['Longitude', geo.longitude || '--']
          ];
          html += _wrRenderSection('IP GEOLOCATION — ' + allIPs[0],
            _wrRenderTable(['FIELD', 'VALUE'], geoRows),
            JSON.stringify(geo, null, 2));
        } catch (e) {
          html += _wrRenderSection('IP GEOLOCATION', '<div style="color:#ffaa00;font-family:monospace;font-size:11px;">Geolocation lookup failed: ' + esc(e.message) + '</div>');
        }
      }

      // Certificate Transparency
      try {
        var certs = await _wrCertSearch(query);
        var uniqueDomains = {};
        for (var ci = 0; ci < certs.length; ci++) {
          var cn = certs[ci].common_name || '';
          var nv = certs[ci].name_value || '';
          var names = (cn + '\n' + nv).split('\n');
          for (var ni = 0; ni < names.length; ni++) {
            var n = names[ni].trim().toLowerCase().replace(/^\*\./, '');
            if (n && n.indexOf(query) !== -1) uniqueDomains[n] = (uniqueDomains[n] || 0) + 1;
          }
        }
        var subdomains = Object.keys(uniqueDomains).sort();
        if (subdomains.length > 0) {
          var certRows = subdomains.slice(0, 100).map(function(d) { return [d, uniqueDomains[d]]; });
          html += _wrRenderSection('CERTIFICATE TRANSPARENCY — ' + subdomains.length + ' subdomains',
            _wrRenderTable(['SUBDOMAIN', 'CERT COUNT'], certRows),
            subdomains.join('\n'));
        } else {
          html += _wrRenderSection('CERTIFICATE TRANSPARENCY', '<div style="color:#4a6a8a;font-family:monospace;font-size:11px;">No certificates found.</div>');
        }
      } catch (e) {
        html += _wrRenderSection('CERTIFICATE TRANSPARENCY', '<div style="color:#ffaa00;font-family:monospace;font-size:11px;">crt.sh query failed: ' + esc(e.message) + '</div>');
      }

    } else {
      // IP address — geolocation + reverse DNS
      try {
        var geo = await _wrGeoIP(query);
        var geoRows = [
          ['IP', query], ['Country', (geo.country_name || '--') + ' (' + (geo.country_code || '--') + ')'],
          ['Region', geo.region || '--'], ['City', geo.city || '--'],
          ['ISP', geo.org || '--'], ['ASN', geo.asn || '--'],
          ['Timezone', geo.timezone || '--'], ['Latitude', geo.latitude || '--'],
          ['Longitude', geo.longitude || '--'], ['Postal', geo.postal || '--']
        ];
        html += _wrRenderSection('IP GEOLOCATION', _wrRenderTable(['FIELD', 'VALUE'], geoRows), JSON.stringify(geo, null, 2));
      } catch (e) {
        html += _wrRenderSection('IP GEOLOCATION', '<div style="color:#ff6644;font-family:monospace;font-size:11px;">Lookup failed: ' + esc(e.message) + '</div>');
      }

      // Reverse DNS
      try {
        var ptrs = await _wrReverseDNS(query);
        if (ptrs.length > 0) {
          var ptrRows = ptrs.map(function(p) { return [p.data || '--', p.TTL || '--']; });
          html += _wrRenderSection('REVERSE DNS (PTR)', _wrRenderTable(['HOSTNAME', 'TTL'], ptrRows));
        } else {
          html += _wrRenderSection('REVERSE DNS (PTR)', '<div style="color:#4a6a8a;font-family:monospace;font-size:11px;">No PTR record found.</div>');
        }
      } catch (e) {
        html += _wrRenderSection('REVERSE DNS', '<div style="color:#ffaa00;font-family:monospace;font-size:11px;">Reverse lookup failed.</div>');
      }

      // Forward DNS for any PTR results
      try {
        var ptrs2 = await _wrReverseDNS(query);
        if (ptrs2.length > 0 && ptrs2[0].data) {
          var hostname = ptrs2[0].data.replace(/\.$/, '');
          var fwdA = await _wrDnsLookup(hostname, 'A');
          if (fwdA.length > 0) {
            html += _wrRenderSection('FORWARD CONFIRMATION — ' + hostname, _wrRenderTable(['TYPE', 'VALUE', 'TTL'], fwdA.map(function(a) { return ['A', a.data, a.TTL]; })));
          }
        }
      } catch (_) {}
    }
  } catch (e) {
    html += '<div style="color:#ff4444;font-family:monospace;font-size:11px;padding:16px;">Error: ' + esc(e.message || 'Unknown error') + '</div>';
  }

  resultsEl.innerHTML = html;
}

function _wrRenderHistory() {
  var el = document.getElementById('wr-history');
  if (!el) return;
  if (_wrHistory.length === 0) { el.innerHTML = '<div style="color:#3a5a7a;font-size:10px;font-family:monospace;">No recent lookups.</div>'; return; }
  var h = '';
  for (var i = 0; i < Math.min(_wrHistory.length, 10); i++) {
    var item = _wrHistory[i];
    var typeColor = item.type === 'ip' ? '#ff6644' : '#00aaff';
    h += '<div style="display:flex;align-items:center;gap:8px;padding:3px 0;border-bottom:1px solid #0d1525;cursor:pointer;" onclick="document.getElementById(\'wr-input\').value=\'' + esc(item.query) + '\';_wrRunLookup(\'' + esc(item.query) + '\')">';
    h += '<span style="color:' + typeColor + ';font-size:9px;font-family:monospace;min-width:30px;">[' + (item.type === 'ip' ? 'IP' : 'DNS') + ']</span>';
    h += '<span style="color:#c8d6e5;font-size:11px;font-family:monospace;">' + esc(item.query) + '</span>';
    h += '<span style="color:#3a5a7a;font-size:9px;font-family:monospace;margin-left:auto;">' + esc(item.time ? item.time.substring(0, 16).replace('T', ' ') : '') + '</span>';
    h += '</div>';
  }
  el.innerHTML = h;
}

window.renderWhoisRecon = function(container) {
  _wrLoadHistory();

  container.innerHTML =
    '<div style="padding:20px 24px;max-width:1100px;margin:0 auto;">' +
    '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">' +
    '<div>' +
    '<h2 style="margin:0;font-size:20px;color:#00aaff;font-family:monospace;letter-spacing:2px;text-transform:uppercase;">WHOIS RECON</h2>' +
    '<div style="color:#4a6a8a;font-size:11px;font-family:monospace;margin-top:4px;">Domain &amp; IP Intelligence — DNS, Geolocation, Certificate Transparency</div>' +
    '</div>' +
    '<div style="display:flex;gap:8px;">' +
    '<div style="background:#0a0e1a;border:1px solid #00aaff33;border-radius:6px;padding:6px 14px;text-align:center;">' +
    '<div style="color:#556;font-size:8px;font-family:monospace;letter-spacing:1px;">SOURCES</div>' +
    '<div style="color:#00aaff;font-size:18px;font-weight:bold;font-family:monospace;">4</div>' +
    '</div>' +
    '</div>' +
    '</div>' +

    // Input
    '<div style="display:flex;gap:8px;margin-bottom:16px;">' +
    '<input id="wr-input" type="text" placeholder="Enter domain or IP (e.g. example.com or 8.8.8.8)" ' +
    'style="flex:1;background:#0a0e1a;border:1px solid #1a2a44;border-radius:6px;padding:10px 14px;color:#c8d6e5;font-family:monospace;font-size:13px;outline:none;" ' +
    'onkeydown="if(event.key===\'Enter\')_wrRunLookup(this.value)">' +
    '<button onclick="_wrRunLookup(document.getElementById(\'wr-input\').value)" ' +
    'style="background:linear-gradient(135deg,#00aaff22,#00aaff11);border:1px solid #00aaff66;border-radius:6px;padding:10px 20px;color:#00ddff;font-family:monospace;font-size:12px;font-weight:bold;cursor:pointer;letter-spacing:1px;">LOOKUP</button>' +
    '</div>' +

    // Quick links
    '<div style="display:flex;gap:6px;margin-bottom:16px;flex-wrap:wrap;">' +
    '<span style="color:#3a5a7a;font-size:10px;font-family:monospace;line-height:26px;">QUICK:</span>' +
    ['google.com', 'cloudflare.com', 'github.com', '8.8.8.8', '1.1.1.1', 'darknode.ai'].map(function(d) {
      return '<button onclick="document.getElementById(\'wr-input\').value=\'' + d + '\';_wrRunLookup(\'' + d + '\')" ' +
        'style="background:#0a1a28;border:1px solid #1a3050;color:#5a8aaa;padding:3px 10px;font-size:10px;font-family:monospace;cursor:pointer;border-radius:3px;">' + d + '</button>';
    }).join('') +
    '</div>' +

    // Results
    '<div id="wr-results" style="background:#080c14;border:1px solid #1a2a44;border-radius:8px;padding:16px;min-height:200px;">' +
    '<div style="color:#3a5a7a;font-size:11px;font-family:monospace;text-align:center;padding:40px;">Enter a domain or IP address above to begin intelligence gathering.</div>' +
    '</div>' +

    // History
    '<div style="margin-top:16px;">' +
    '<div style="color:#4a6a8a;font-size:10px;font-family:monospace;letter-spacing:2px;margin-bottom:6px;">RECENT LOOKUPS</div>' +
    '<div id="wr-history" style="background:#080c14;border:1px solid #1a2a44;border-radius:6px;padding:10px;"></div>' +
    '</div>' +

    '</div>';

  _wrRenderHistory();
};

window._wrRunLookup = _wrRunLookup;
window._wrCopyText = _wrCopyText;
