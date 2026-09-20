// Copyright (c) 2026 Darknode-Official. All rights reserved.
// IP Geolocation & Reputation — locate IPs, check ASN reputation, bulk lookup
// Uses ipapi.co (free, 1000/day, CORS OK) — no API key required

var esc = function(s) { return String(s != null ? s : '').replace(/[&<>"']/g, function(c) { return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

var BULLETPROOF_ASNS = {
  '4785': 'XTOM (known hosting abuse)', '9009': 'M247 (mixed reputation)', '16276': 'OVH (frequent abuse reports)',
  '14061': 'DigitalOcean (frequent C2 hosting)', '24940': 'Hetzner (hosting abuse)', '49505': 'Selectel (RU hosting)',
  '197540': 'Netcup (DE hosting)', '53667': 'FranTech/BuyVM', '62563': 'GTHost (bulletproof)',
  '210644': 'Aeza Group (RU bulletproof)', '210558': 'MVPS (BG bulletproof)', '44477': 'Stark Industries (RU bulletproof)',
  '57043': 'Hostkey (NL bulletproof)', '213371': 'Squitter (abuse-tolerant)', '51396': 'Pfcloud (abuse-tolerant)',
  '47583': 'Hostinger (frequent abuse)', '209588': 'PINDC (bulletproof hosting)', '203953': 'PPTechnology (abuse)',
  '59642': 'CherryServers (abuse-tolerant)', '50673': 'Serverius (NL abuse-tolerant)'
};

var HIGH_RISK_COUNTRIES = ['RU', 'CN', 'KP', 'IR', 'BY', 'SY', 'VE', 'CU'];

window.renderIPGeolocation = function(container) {
  if (!container) return;
  var h = '';
  h += '<div style="background:#0a0e14;color:#c8d6e5;font-family:\'Courier New\',monospace;padding:24px;min-height:80vh;">';

  h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;">';
  h += '<div>';
  h += '<h2 style="margin:0;font-size:20px;color:#ff6644;letter-spacing:2px;">IP GEOLOCATION</h2>';
  h += '<div style="color:#4a6a8a;font-size:11px;letter-spacing:1px;margin-top:4px;">Locate &bull; Reputation &bull; ASN Analysis &bull; Bulk Lookup</div>';
  h += '</div>';
  h += '<button onclick="_ipLookupSelf()" style="background:#ff664422;color:#ff6644;border:1px solid #ff664444;border-radius:4px;padding:8px 16px;font-family:monospace;font-size:11px;cursor:pointer;letter-spacing:1px;">MY IP</button>';
  h += '</div>';

  // Tabs
  h += '<div style="display:flex;gap:4px;margin-bottom:16px;">';
  h += '<button class="ip-tab" data-tab="single" style="background:#ff664422;border:1px solid #ff664466;color:#ff6644;border-radius:4px;padding:6px 14px;font-family:monospace;font-size:11px;cursor:pointer;">Single Lookup</button>';
  h += '<button class="ip-tab" data-tab="bulk" style="background:#0a0e1a;border:1px solid #1a2a44;color:#556;border-radius:4px;padding:6px 14px;font-family:monospace;font-size:11px;cursor:pointer;">Bulk Lookup</button>';
  h += '</div>';

  // Single lookup
  h += '<div id="ip-single-panel">';
  h += '<div style="display:flex;gap:8px;margin-bottom:16px;">';
  h += '<input id="ip-input" type="text" placeholder="Enter IP address (e.g. 8.8.8.8)" style="flex:1;background:#0c1525;border:1px solid #1a3a5c;border-radius:4px;padding:10px 14px;color:#c8d6e5;font-family:monospace;font-size:13px;outline:none;" onkeydown="if(event.key===\'Enter\')_ipLookup()">';
  h += '<button onclick="_ipLookup()" style="background:#ff664422;color:#ff6644;border:1px solid #ff664444;border-radius:4px;padding:10px 20px;font-family:monospace;font-size:12px;cursor:pointer;letter-spacing:1px;font-weight:bold;">LOCATE</button>';
  h += '</div>';
  h += '<div id="ip-result" style="min-height:300px;background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:20px;">';
  h += '<div style="text-align:center;color:#4a6a8a;padding:60px 20px;"><div style="font-size:36px;margin-bottom:10px;opacity:0.3;">&#x1F4CD;</div><div style="font-size:13px;">Enter an IP address to geolocate</div></div>';
  h += '</div></div>';

  // Bulk lookup (hidden by default)
  h += '<div id="ip-bulk-panel" style="display:none;">';
  h += '<textarea id="ip-bulk-input" placeholder="Paste IPs — one per line (max 20)" style="width:100%;height:120px;background:#0c1525;border:1px solid #1a3a5c;border-radius:4px;padding:10px 14px;color:#c8d6e5;font-family:monospace;font-size:12px;outline:none;resize:vertical;margin-bottom:8px;box-sizing:border-box;"></textarea>';
  h += '<button onclick="_ipBulkLookup()" style="background:#ff664422;color:#ff6644;border:1px solid #ff664444;border-radius:4px;padding:8px 20px;font-family:monospace;font-size:12px;cursor:pointer;letter-spacing:1px;margin-bottom:16px;">LOOKUP ALL</button>';
  h += '<div id="ip-bulk-result"></div>';
  h += '</div>';

  h += '</div>';
  container.innerHTML = h;

  // Tab switching
  container.addEventListener('click', function(e) {
    if (e.target.classList.contains('ip-tab')) {
      var tab = e.target.getAttribute('data-tab');
      var allTabs = container.querySelectorAll('.ip-tab');
      for (var t = 0; t < allTabs.length; t++) { allTabs[t].style.background = '#0a0e1a'; allTabs[t].style.borderColor = '#1a2a44'; allTabs[t].style.color = '#556'; }
      e.target.style.background = '#ff664422'; e.target.style.borderColor = '#ff664466'; e.target.style.color = '#ff6644';
      document.getElementById('ip-single-panel').style.display = tab === 'single' ? 'block' : 'none';
      document.getElementById('ip-bulk-panel').style.display = tab === 'bulk' ? 'block' : 'none';
    }
  });
};

function _ipLookup(ipOverride) {
  var ip = ipOverride || (document.getElementById('ip-input') || {}).value || '';
  ip = ip.trim();
  var result = document.getElementById('ip-result');
  if (!result) return;
  if (!ip) { result.innerHTML = '<div style="color:#ff4444;padding:20px;text-align:center;">Enter an IP address</div>'; return; }

  result.innerHTML = '<div style="text-align:center;padding:30px;color:#ff6644;font-size:13px;letter-spacing:2px;">LOCATING ' + esc(ip) + '...</div>';

  fetch('https://ipapi.co/' + encodeURIComponent(ip) + '/json/')
    .then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
    .then(function(d) {
      if (d.error) throw new Error(d.reason || 'API error');
      _ipRenderResult(result, d);
    })
    .catch(function(err) {
      result.innerHTML = '<div style="color:#ff4444;padding:20px;text-align:center;"><div style="font-size:14px;font-weight:bold;margin-bottom:6px;">LOOKUP FAILED</div><div style="font-size:11px;color:#aa6666;">' + esc(err.message) + '</div></div>';
    });
}

function _ipLookupSelf() {
  var result = document.getElementById('ip-result');
  if (result) result.innerHTML = '<div style="text-align:center;padding:30px;color:#ff6644;font-size:13px;letter-spacing:2px;">DETECTING YOUR IP...</div>';
  var input = document.getElementById('ip-input');

  fetch('https://ipapi.co/json/')
    .then(function(r) { return r.json(); })
    .then(function(d) {
      if (input) input.value = d.ip || '';
      _ipRenderResult(result || document.getElementById('ip-result'), d);
    })
    .catch(function(err) {
      if (result) result.innerHTML = '<div style="color:#ff4444;padding:20px;text-align:center;">' + esc(err.message) + '</div>';
    });
}

function _ipRenderResult(el, d) {
  var asnStr = String(d.asn || '').replace('AS', '');
  var isBulletproof = BULLETPROOF_ASNS[asnStr];
  var isHighRisk = HIGH_RISK_COUNTRIES.indexOf(d.country_code || '') !== -1;
  var riskLevel = isBulletproof ? 'HIGH' : isHighRisk ? 'MEDIUM' : 'LOW';
  var riskColor = { HIGH: '#ff4444', MEDIUM: '#ffaa00', LOW: '#00ff88' }[riskLevel];

  var h = '';

  // Map visualization — simple SVG dot on world
  var mapLon = ((d.longitude || 0) + 180) / 360 * 100;
  var mapLat = (90 - (d.latitude || 0)) / 180 * 100;
  h += '<div style="position:relative;background:#060a12;border:1px solid #1a2a44;border-radius:6px;height:160px;margin-bottom:16px;overflow:hidden;">';
  h += '<svg viewBox="0 0 100 50" style="width:100%;height:100%;opacity:0.15;"><rect x="5" y="5" width="90" height="40" fill="none" stroke="#1a3a5c" stroke-width="0.2"/>';
  // Simplified continent outlines (rough)
  h += '<path d="M15,15 L20,12 L25,13 L28,15 L30,14 L32,16 L28,20 L25,22 L22,25 L18,30 L15,28 L12,25 L14,20 Z" fill="#1a3a5c"/>';
  h += '<path d="M35,10 L55,8 L65,12 L70,15 L68,20 L60,22 L55,18 L50,20 L45,18 L40,20 L38,15 Z" fill="#1a3a5c"/>';
  h += '<path d="M55,22 L62,24 L65,30 L60,38 L55,35 L53,28 Z" fill="#1a3a5c"/>';
  h += '<path d="M70,15 L85,12 L90,18 L88,25 L82,28 L78,22 L75,20 L72,18 Z" fill="#1a3a5c"/>';
  h += '<path d="M78,30 L85,28 L88,32 L86,38 L82,40 L78,36 Z" fill="#1a3a5c"/>';
  h += '</svg>';
  h += '<div style="position:absolute;left:' + mapLon + '%;top:' + mapLat + '%;transform:translate(-50%,-50%);">';
  h += '<div style="width:8px;height:8px;background:' + riskColor + ';border-radius:50%;box-shadow:0 0 12px ' + riskColor + ';"></div>';
  h += '<div style="position:absolute;top:-18px;left:50%;transform:translateX(-50%);color:' + riskColor + ';font-size:8px;white-space:nowrap;font-family:monospace;">' + esc(d.ip || '') + '</div>';
  h += '</div>';
  h += '<div style="position:absolute;top:6px;right:8px;color:#556;font-size:8px;">LAT ' + (d.latitude || 0).toFixed(4) + ' / LON ' + (d.longitude || 0).toFixed(4) + '</div>';
  h += '</div>';

  // Info grid
  h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:10px;margin-bottom:16px;">';
  var fields = [
    { label: 'IP ADDRESS', value: d.ip, color: '#ff6644' },
    { label: 'COUNTRY', value: (d.country_name || '--') + ' (' + (d.country_code || '--') + ')', color: isHighRisk ? '#ff4444' : '#c8d6e5' },
    { label: 'CITY', value: (d.city || '--') + ', ' + (d.region || ''), color: '#c8d6e5' },
    { label: 'ISP / ORG', value: d.org || d.isp || '--', color: isBulletproof ? '#ff4444' : '#c8d6e5' },
    { label: 'ASN', value: (d.asn || '--') + ' — ' + (d.org || ''), color: isBulletproof ? '#ff4444' : '#00aaff' },
    { label: 'TIMEZONE', value: d.timezone || '--', color: '#8899aa' },
    { label: 'POSTAL', value: d.postal || '--', color: '#8899aa' },
    { label: 'CURRENCY', value: (d.currency_name || '--') + ' (' + (d.currency || '') + ')', color: '#8899aa' }
  ];
  for (var fi = 0; fi < fields.length; fi++) {
    var f = fields[fi];
    h += '<div style="background:#0a1018;border:1px solid #1a2a4422;border-radius:4px;padding:8px 10px;">';
    h += '<div style="color:#556;font-size:8px;letter-spacing:1px;margin-bottom:2px;">' + f.label + '</div>';
    h += '<div style="color:' + f.color + ';font-size:12px;word-break:break-all;">' + esc(f.value || '--') + '</div>';
    h += '</div>';
  }
  h += '</div>';

  // Reputation
  h += '<div style="background:#0a1018;border:1px solid ' + riskColor + '33;border-radius:6px;padding:12px 16px;">';
  h += '<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">';
  h += '<div style="color:' + riskColor + ';font-size:12px;font-weight:bold;letter-spacing:1px;">RISK: ' + riskLevel + '</div>';
  h += '<div style="flex:1;height:4px;background:#1a2a3a;border-radius:2px;overflow:hidden;"><div style="height:100%;width:' + (riskLevel === 'HIGH' ? '90' : riskLevel === 'MEDIUM' ? '50' : '15') + '%;background:' + riskColor + ';border-radius:2px;"></div></div>';
  h += '</div>';
  var reasons = [];
  if (isBulletproof) reasons.push('ASN ' + asnStr + ' — ' + isBulletproof);
  if (isHighRisk) reasons.push('Located in high-risk country: ' + (d.country_name || d.country_code));
  if (reasons.length === 0) reasons.push('No known negative reputation indicators for this ASN or country');
  for (var ri = 0; ri < reasons.length; ri++) {
    h += '<div style="color:#8899aa;font-size:10px;margin:2px 0;">&bull; ' + esc(reasons[ri]) + '</div>';
  }
  h += '</div>';

  el.innerHTML = h;
}

function _ipBulkLookup() {
  var textarea = document.getElementById('ip-bulk-input');
  var result = document.getElementById('ip-bulk-result');
  if (!textarea || !result) return;

  var ips = textarea.value.split('\n').map(function(l) { return l.trim(); }).filter(function(l) { return l && /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(l); });
  if (ips.length === 0) { result.innerHTML = '<div style="color:#ff4444;padding:12px;text-align:center;">No valid IPs found — enter one IP per line</div>'; return; }
  if (ips.length > 20) { ips = ips.slice(0, 20); }

  result.innerHTML = '<div style="color:#ff6644;padding:12px;text-align:center;">Looking up ' + ips.length + ' IPs...</div>';

  var promises = ips.map(function(ip) {
    return fetch('https://ipapi.co/' + encodeURIComponent(ip) + '/json/')
      .then(function(r) { return r.json(); })
      .then(function(d) { return d; })
      .catch(function() { return { ip: ip, error: true }; });
  });

  Promise.all(promises).then(function(results) {
    var h = '';
    h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:16px;">';
    h += '<div style="color:#ff6644;font-size:12px;letter-spacing:1px;margin-bottom:10px;">' + results.length + ' IPs GEOLOCATED</div>';
    h += '<div style="overflow-x:auto;"><table style="width:100%;border-collapse:collapse;font-size:10px;">';
    h += '<thead><tr style="border-bottom:2px solid #1a3a5c;">';
    var headers = ['IP', 'COUNTRY', 'CITY', 'ISP/ORG', 'ASN', 'RISK'];
    for (var hi = 0; hi < headers.length; hi++) h += '<th style="text-align:left;padding:6px;color:#ff6644;font-size:9px;white-space:nowrap;">' + headers[hi] + '</th>';
    h += '</tr></thead><tbody>';

    for (var i = 0; i < results.length; i++) {
      var d = results[i];
      if (d.error) {
        h += '<tr style="border-bottom:1px solid #0d1525;"><td colspan="6" style="padding:5px 6px;color:#ff4444;">' + esc(d.ip) + ' — lookup failed</td></tr>';
        continue;
      }
      var asnStr = String(d.asn || '').replace('AS', '');
      var isBP = BULLETPROOF_ASNS[asnStr];
      var isHR = HIGH_RISK_COUNTRIES.indexOf(d.country_code || '') !== -1;
      var risk = isBP ? 'HIGH' : isHR ? 'MEDIUM' : 'LOW';
      var rColor = { HIGH: '#ff4444', MEDIUM: '#ffaa00', LOW: '#00ff88' }[risk];
      var rowBg = i % 2 ? 'rgba(255,255,255,0.02)' : 'transparent';

      h += '<tr style="border-bottom:1px solid #0d1525;background:' + rowBg + ';">';
      h += '<td style="padding:5px 6px;color:#c8d6e5;cursor:pointer;" onclick="navigator.clipboard.writeText(this.textContent)">' + esc(d.ip || '') + '</td>';
      h += '<td style="padding:5px 6px;color:' + (isHR ? '#ff4444' : '#8899aa') + ';">' + esc(d.country_code || '--') + '</td>';
      h += '<td style="padding:5px 6px;color:#8899aa;">' + esc(d.city || '--') + '</td>';
      h += '<td style="padding:5px 6px;color:' + (isBP ? '#ff4444' : '#8899aa') + ';max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + esc(d.org || '--') + '</td>';
      h += '<td style="padding:5px 6px;color:#556;">' + esc(d.asn || '--') + '</td>';
      h += '<td style="padding:5px 6px;"><span style="color:' + rColor + ';font-weight:bold;font-size:9px;">' + risk + '</span></td>';
      h += '</tr>';
    }
    h += '</tbody></table></div></div>';
    result.innerHTML = h;
  });
}

window._ipLookup = _ipLookup;
window._ipLookupSelf = _ipLookupSelf;
window._ipBulkLookup = _ipBulkLookup;
