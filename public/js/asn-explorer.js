// Copyright (c) 2026 Darknode-Official. All rights reserved.
// ASN Explorer — Autonomous System Number intelligence via BGPView API

var esc = function(s) { return String(s != null ? s : '').replace(/[&<>"']/g, function(c) {
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

var _asnBulletproof = {
  48693: 'MAROSNET — bulletproof hosting (RU)',
  200019: 'ALEXHOST — bulletproof hosting (MD)',
  49349: 'DOTSI — bulletproof hosting (PT/NL)',
  57043: 'HOSTWINDS — abuse-tolerant (US)',
  51159: 'MVPS LTD — bulletproof (BG)',
  210558: 'MVPS-NEW — bulletproof (BG)',
  204957: 'GREENFLOID — bulletproof (NL)',
  44477: 'STARK INDUSTRIES — bulletproof (MD)',
  9009: 'M247 LTD — abuse-tolerant (RO/SG)',
  16276: 'OVH — frequently abused (FR)',
  14061: 'DIGITALOCEAN — frequently abused (US)',
  53667: 'FRANTECH/BUYVM — abuse-tolerant (US/LU)',
  62904: 'EONIX — bulletproof (US)',
  394711: 'LIMENET — bulletproof (US)',
  210644: 'AEZA GROUP — bulletproof (RU)',
  47583: 'AS-HOSTINGER — abuse-tolerant (LT)',
  398101: 'GCORE — abuse-tolerant (LU)',
  202422: 'GHOSTNET — bulletproof (DE)',
  42624: 'SIMPLECARRIER — bulletproof (RU)',
  201011: 'NETZBETRIEB — bulletproof (DE)'
};

window.renderAsnExplorer = function(container) {
  var h = '';
  h += '<div style="background:#0a0e14;color:#c8d6e5;font-family:\'Courier New\',monospace;padding:20px;min-height:600px;">';
  h += '<h2 style="color:#00ddff;font-size:18px;letter-spacing:2px;margin:0 0 4px;">ASN EXPLORER</h2>';
  h += '<div style="color:#4a6a8a;font-size:11px;margin-bottom:20px;">Autonomous System Number intelligence — BGP prefixes, peers, reputation</div>';

  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:16px;margin-bottom:16px;">';
  h += '<div style="display:flex;gap:8px;">';
  h += '<input id="asn-input" style="flex:1;background:#080c14;border:1px solid #1a2a44;border-radius:4px;color:#c8d6e5;font-family:monospace;font-size:12px;padding:8px 12px;" placeholder="AS number (e.g. 13335) or org name (e.g. Cloudflare)">';
  h += '<button onclick="_asnLookup()" style="background:#00aaff22;color:#00aaff;border:1px solid #00aaff44;padding:8px 16px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px;">LOOKUP</button>';
  h += '<button onclick="_asnSearch()" style="background:#ffaa0022;color:#ffaa00;border:1px solid #ffaa0044;padding:8px 16px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px;">SEARCH</button>';
  h += '</div>';
  h += '<div style="color:#3a5a7a;font-size:9px;margin-top:6px;">Data from BGPView API (api.bgpview.io) — free, no API key required</div>';
  h += '</div>';

  h += '<div id="asn-results"></div>';

  // Bulletproof ASN reference
  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:14px;margin-top:16px;">';
  h += '<div style="color:#ff4444;font-size:12px;font-weight:bold;margin-bottom:10px;letter-spacing:1px;">KNOWN BULLETPROOF / ABUSE-TOLERANT ASNs</div>';
  h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:6px;">';
  var bpKeys = Object.keys(_asnBulletproof);
  for (var b = 0; b < bpKeys.length; b++) {
    var asn = bpKeys[b];
    h += '<div style="background:#1a0a0a;border:1px solid #ff222233;border-radius:3px;padding:5px 8px;font-size:10px;display:flex;justify-content:space-between;cursor:pointer;" onclick="_asnLookupDirect(' + esc(asn) + ')">';
    h += '<span style="color:#ff4444;font-weight:bold;">AS' + esc(asn) + '</span>';
    h += '<span style="color:#ff8866;">' + esc(_asnBulletproof[asn]) + '</span>';
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';

  h += '</div>';
  container.innerHTML = h;

  document.getElementById('asn-input').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') { var v = this.value.trim(); if (/^\d+$/.test(v) || /^AS\d+$/i.test(v)) _asnLookup(); else _asnSearch(); }
  });
};

window._asnLookupDirect = function(asn) {
  var inp = document.getElementById('asn-input');
  if (inp) inp.value = String(asn);
  _asnLookup();
};

window._asnLookup = function() {
  var input = (document.getElementById('asn-input') || {}).value;
  var results = document.getElementById('asn-results');
  if (!input || !results) return;
  input = input.trim().replace(/^AS/i, '');
  if (!/^\d+$/.test(input)) { _asnSearch(); return; }

  results.innerHTML = '<div style="color:#ffaa00;font-size:11px;padding:16px;text-align:center;">Looking up AS' + esc(input) + '...</div>';

  var asnData = null, prefixData = null, peerData = null;
  var done = 0;

  function render() {
    if (done < 3) return;
    _asnRenderResults(results, input, asnData, prefixData, peerData);
  }

  fetch('https://api.bgpview.io/asn/' + encodeURIComponent(input))
    .then(function(r) { return r.json(); }).then(function(d) { asnData = d; }).catch(function() { asnData = null; }).finally(function() { done++; render(); });
  fetch('https://api.bgpview.io/asn/' + encodeURIComponent(input) + '/prefixes')
    .then(function(r) { return r.json(); }).then(function(d) { prefixData = d; }).catch(function() { prefixData = null; }).finally(function() { done++; render(); });
  fetch('https://api.bgpview.io/asn/' + encodeURIComponent(input) + '/peers')
    .then(function(r) { return r.json(); }).then(function(d) { peerData = d; }).catch(function() { peerData = null; }).finally(function() { done++; render(); });
};

window._asnSearch = function() {
  var input = (document.getElementById('asn-input') || {}).value;
  var results = document.getElementById('asn-results');
  if (!input || !results) return;

  results.innerHTML = '<div style="color:#ffaa00;font-size:11px;padding:16px;text-align:center;">Searching for "' + esc(input) + '"...</div>';

  fetch('https://api.bgpview.io/search?query_term=' + encodeURIComponent(input.trim()))
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (!data || !data.data) { results.innerHTML = '<div style="color:#ff4444;font-size:11px;">Search failed.</div>'; return; }
      var asns = (data.data.asns || []).slice(0, 20);
      if (asns.length === 0) { results.innerHTML = '<div style="color:#4a6a8a;font-size:11px;">No results found.</div>'; return; }

      var h = '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:14px;">';
      h += '<div style="color:#00ddff;font-size:12px;font-weight:bold;margin-bottom:10px;">SEARCH RESULTS (' + asns.length + ')</div>';
      h += '<table style="width:100%;border-collapse:collapse;font-size:10px;">';
      h += '<thead><tr style="border-bottom:2px solid #1a2a44;">';
      h += '<th style="text-align:left;padding:6px;color:#00aaff;">ASN</th>';
      h += '<th style="text-align:left;padding:6px;color:#00aaff;">NAME</th>';
      h += '<th style="text-align:left;padding:6px;color:#00aaff;">COUNTRY</th>';
      h += '<th style="text-align:left;padding:6px;color:#00aaff;">REPUTATION</th>';
      h += '</tr></thead><tbody>';
      for (var i = 0; i < asns.length; i++) {
        var a = asns[i];
        var isBP = _asnBulletproof[a.asn];
        var repColor = isBP ? '#ff4444' : '#00ff88';
        var repText = isBP ? 'SUSPICIOUS' : 'NORMAL';
        h += '<tr style="border-bottom:1px solid #0d1525;cursor:pointer;" onclick="_asnLookupDirect(' + a.asn + ')">';
        h += '<td style="padding:6px;color:#00ddff;font-weight:bold;">AS' + a.asn + '</td>';
        h += '<td style="padding:6px;color:#c8d6e5;">' + esc(a.name || a.description || '') + '</td>';
        h += '<td style="padding:6px;color:#6a8aaa;">' + esc(a.country_code || '??') + '</td>';
        h += '<td style="padding:6px;"><span style="color:' + repColor + ';font-size:9px;padding:1px 6px;background:' + repColor + '15;border:1px solid ' + repColor + '33;border-radius:2px;">' + repText + '</span></td>';
        h += '</tr>';
        if (isBP) {
          h += '<tr><td colspan="4" style="padding:2px 6px 6px;color:#ff8866;font-size:9px;">&#9888; ' + esc(isBP) + '</td></tr>';
        }
      }
      h += '</tbody></table></div>';
      results.innerHTML = h;
    })
    .catch(function(err) {
      results.innerHTML = '<div style="color:#ff4444;font-size:11px;">Search error: ' + esc(String(err.message || err)) + '</div>';
    });
};

function _asnRenderResults(el, asn, asnData, prefixData, peerData) {
  var h = '';
  var info = asnData && asnData.data ? asnData.data : null;
  var isBP = _asnBulletproof[asn];

  if (!info) {
    el.innerHTML = '<div style="color:#ff4444;font-size:11px;">ASN data unavailable. BGPView API may be rate-limited.</div>';
    return;
  }

  // Header card
  var repColor = isBP ? '#ff4444' : '#00ff88';
  h += '<div style="background:#0c1020;border:2px solid ' + repColor + ';border-radius:8px;padding:16px;margin-bottom:12px;">';
  h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">';
  h += '<div>';
  h += '<div style="font-size:20px;font-weight:bold;color:#00ddff;">AS' + esc(String(asn)) + '</div>';
  h += '<div style="color:#c8d6e5;font-size:13px;margin-top:2px;">' + esc(info.name || '') + '</div>';
  h += '<div style="color:#6a8aaa;font-size:11px;">' + esc(info.description_full || info.description_short || '') + '</div>';
  h += '</div>';
  h += '<div style="text-align:right;">';
  h += '<div style="color:' + repColor + ';font-size:14px;font-weight:bold;">' + (isBP ? 'SUSPICIOUS' : 'CLEAN') + '</div>';
  if (isBP) h += '<div style="color:#ff8866;font-size:9px;max-width:200px;">' + esc(isBP) + '</div>';
  h += '</div>';
  h += '</div>';

  // Details grid
  h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:8px;">';
  var details = [
    { label: 'COUNTRY', value: (info.rir_allocation || {}).country_code || info.country_code || '??' },
    { label: 'RIR', value: (info.rir_allocation || {}).rir_name || '??' },
    { label: 'ALLOCATED', value: (info.rir_allocation || {}).date_allocated || '??' },
    { label: 'WEBSITE', value: info.website || 'N/A' },
    { label: 'EMAIL', value: (info.email_contacts || [])[0] || 'N/A' },
    { label: 'ABUSE', value: (info.abuse_contacts || [])[0] || 'N/A' }
  ];
  for (var d = 0; d < details.length; d++) {
    h += '<div style="background:#080c14;border:1px solid #1a2a44;border-radius:3px;padding:6px 8px;">';
    h += '<div style="color:#3a5a7a;font-size:8px;letter-spacing:1px;">' + details[d].label + '</div>';
    h += '<div style="color:#c8d6e5;font-size:11px;word-break:break-all;">' + esc(details[d].value) + '</div>';
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';

  // Prefixes
  if (prefixData && prefixData.data) {
    var v4 = prefixData.data.ipv4_prefixes || [];
    var v6 = prefixData.data.ipv6_prefixes || [];

    h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:14px;margin-bottom:12px;">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">';
    h += '<div style="color:#00ff88;font-size:12px;font-weight:bold;">ANNOUNCED PREFIXES</div>';
    h += '<div style="display:flex;gap:12px;">';
    h += '<span style="color:#00aaff;font-size:11px;">IPv4: <strong>' + v4.length + '</strong></span>';
    h += '<span style="color:#aa66ff;font-size:11px;">IPv6: <strong>' + v6.length + '</strong></span>';
    h += '</div>';
    h += '</div>';

    // Visual bar
    var maxPrefixes = Math.max(v4.length, v6.length, 1);
    h += '<div style="display:flex;gap:8px;margin-bottom:10px;">';
    h += '<div style="flex:1;"><div style="color:#3a5a7a;font-size:9px;margin-bottom:2px;">IPv4</div><div style="background:#1a2a44;border-radius:2px;height:8px;overflow:hidden;"><div style="background:#00aaff;height:100%;width:' + Math.round((v4.length / maxPrefixes) * 100) + '%;border-radius:2px;"></div></div></div>';
    h += '<div style="flex:1;"><div style="color:#3a5a7a;font-size:9px;margin-bottom:2px;">IPv6</div><div style="background:#1a2a44;border-radius:2px;height:8px;overflow:hidden;"><div style="background:#aa66ff;height:100%;width:' + Math.round((v6.length / maxPrefixes) * 100) + '%;border-radius:2px;"></div></div></div>';
    h += '</div>';

    if (v4.length > 0) {
      h += '<div style="max-height:200px;overflow-y:auto;">';
      h += '<table style="width:100%;border-collapse:collapse;font-size:10px;">';
      h += '<thead><tr style="border-bottom:1px solid #1a2a44;"><th style="text-align:left;padding:4px;color:#00aaff;">PREFIX</th><th style="text-align:left;padding:4px;color:#00aaff;">NAME</th><th style="text-align:left;padding:4px;color:#00aaff;">DESCRIPTION</th></tr></thead><tbody>';
      for (var p = 0; p < Math.min(v4.length, 50); p++) {
        h += '<tr style="border-bottom:1px solid #0d1525;">';
        h += '<td style="padding:4px;color:#00ff88;font-weight:bold;">' + esc(v4[p].prefix) + '</td>';
        h += '<td style="padding:4px;color:#c8d6e5;">' + esc(v4[p].name || '') + '</td>';
        h += '<td style="padding:4px;color:#6a8aaa;">' + esc(v4[p].description || '') + '</td>';
        h += '</tr>';
      }
      if (v4.length > 50) h += '<tr><td colspan="3" style="padding:4px;color:#4a6a8a;">...and ' + (v4.length - 50) + ' more</td></tr>';
      h += '</tbody></table></div>';
    }
    h += '</div>';
  }

  // Peers
  if (peerData && peerData.data) {
    var upstream = peerData.data.ipv4_peers || [];
    h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:14px;">';
    h += '<div style="color:#ffaa00;font-size:12px;font-weight:bold;margin-bottom:10px;">BGP PEERS (' + upstream.length + ')</div>';
    if (upstream.length > 0) {
      h += '<div style="display:flex;flex-wrap:wrap;gap:4px;max-height:150px;overflow-y:auto;">';
      for (var u = 0; u < Math.min(upstream.length, 40); u++) {
        var peer = upstream[u];
        var peerBP = _asnBulletproof[peer.asn];
        var peerColor = peerBP ? '#ff4444' : '#00aaff';
        h += '<span style="background:' + peerColor + '10;border:1px solid ' + peerColor + '33;border-radius:3px;padding:2px 6px;font-size:9px;color:' + peerColor + ';cursor:pointer;" onclick="_asnLookupDirect(' + peer.asn + ')" title="' + esc(peer.name || '') + '">AS' + peer.asn + '</span>';
      }
      if (upstream.length > 40) h += '<span style="color:#4a6a8a;font-size:9px;padding:2px 6px;">+' + (upstream.length - 40) + ' more</span>';
      h += '</div>';
    } else {
      h += '<div style="color:#4a6a8a;font-size:10px;">No peer data available.</div>';
    }
    h += '</div>';
  }

  el.innerHTML = h;
}
