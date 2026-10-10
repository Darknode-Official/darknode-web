// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved.
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

var _ASN_CSS = '<style>' +
  '.asn-wrap{color:var(--txt,#e7eefc);background:var(--card,#0b1120);padding:20px;min-height:600px;border-radius:8px}' +
  '.asn-h2{color:var(--acc,#2563eb);font-size:18px;letter-spacing:2px;margin:0 0 4px;font-weight:700}' +
  '.asn-sub{color:var(--mut,#7a93b8);font-size:11px;margin-bottom:20px}' +
  '.asn-bar{background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);border-radius:6px;padding:16px;margin-bottom:16px}' +
  '.asn-input{flex:1;background:var(--card,#0b1120);border:1px solid var(--line,#283a5a);border-radius:4px;color:var(--txt,#e7eefc);font-family:var(--font-mono);font-size:12px;padding:8px 12px}' +
  '.asn-btn{background:color-mix(in srgb,var(--acc,#2563eb) 14%,transparent);color:var(--acc,#2563eb);border:1px solid color-mix(in srgb,var(--acc,#2563eb) 40%,transparent);padding:8px 16px;font-size:11px;cursor:pointer;border-radius:4px;font-family:inherit}' +
  '.asn-btn.warn{background:rgba(217,119,6,.14);color:#d97706;border-color:rgba(217,119,6,.4)}' +
  '.asn-note{color:var(--mut,#7a93b8);font-size:9px;margin-top:6px}' +
  '.asn-card{background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);border-radius:6px;padding:14px;margin-top:16px}' +
  '.asn-bp-title{color:#dc2626;font-size:12px;font-weight:bold;margin-bottom:10px;letter-spacing:1px}' +
  '.asn-bp-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:6px}' +
  '.asn-bp-item{background:rgba(220,38,38,.07);border:1px solid rgba(220,38,38,.25);border-radius:4px;padding:5px 8px;font-size:10px;display:flex;justify-content:space-between;cursor:pointer}' +
  '.asn-bp-asn{color:#dc2626;font-weight:bold;font-family:var(--font-mono)}' +
  '.asn-bp-desc{color:#e08a76}' +
  '.asn-busy{color:#d97706;font-size:11px;padding:16px;text-align:center}' +
  '.asn-err{color:#dc2626;font-size:11px}' +
  '.asn-empty{color:var(--mut,#7a93b8);font-size:11px}' +
  '.asn-panel{background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);border-radius:6px;padding:14px}' +
  '.asn-res-title{color:var(--acc,#2563eb);font-size:12px;font-weight:bold;margin-bottom:10px}' +
  '.asn-th{text-align:left;padding:6px;color:var(--acc,#2563eb)}' +
  '.asn-td-asn{padding:6px;color:var(--acc,#2563eb);font-weight:bold;font-family:var(--font-mono)}' +
  '.asn-td{padding:6px;color:var(--txt,#e7eefc)}' +
  '.asn-td-mut{padding:6px;color:var(--txt-2,#9fb0cc)}' +
  '.asn-detail-cell{background:var(--card,#0b1120);border:1px solid var(--line,#283a5a);border-radius:3px;padding:6px 8px}' +
  '.asn-detail-label{color:var(--mut,#7a93b8);font-size:8px;letter-spacing:1px}' +
  '.asn-detail-val{color:var(--txt,#e7eefc);font-size:11px;word-break:break-all}' +
  '.asn-as-num{font-size:20px;font-weight:bold;color:var(--acc,#2563eb);font-family:var(--font-mono)}' +
  '.asn-as-name{color:var(--txt,#e7eefc);font-size:13px;margin-top:2px}' +
  '.asn-as-desc{color:var(--txt-2,#9fb0cc);font-size:11px}' +
  '.asn-prefix-title{color:#16a34a;font-size:12px;font-weight:bold}' +
  '.asn-peer-title{color:#d97706;font-size:12px;font-weight:bold;margin-bottom:10px}' +
  '.asn-mono{font-family:var(--font-mono)}' +
  '</style>';

export function renderAsnExplorer(container) {
  var h = _ASN_CSS;
  h += '<div class="asn-wrap">';
  h += '<h2 class="asn-h2">ASN EXPLORER</h2>';
  h += '<div class="asn-sub">Autonomous System Number intelligence — BGP prefixes, peers, reputation</div>';

  h += '<div class="asn-bar">';
  h += '<div style="display:flex;gap:8px;">';
  h += '<input id="asn-input" class="asn-input" placeholder="AS number (e.g. 13335) or org name (e.g. Cloudflare)">';
  h += '<button onclick="_asnLookup()" class="asn-btn">Lookup</button>';
  h += '<button onclick="_asnSearch()" class="asn-btn warn">Search</button>';
  h += '</div>';
  h += '<div class="asn-note">Data from BGPView API (api.bgpview.io) — free, no API key required</div>';
  h += '</div>';

  h += '<div id="asn-results"></div>';

  // Bulletproof ASN reference
  h += '<div class="asn-card">';
  h += '<div class="asn-bp-title">KNOWN BULLETPROOF / ABUSE-TOLERANT ASNs</div>';
  h += '<div class="asn-bp-grid">';
  var bpKeys = Object.keys(_asnBulletproof);
  for (var b = 0; b < bpKeys.length; b++) {
    var asn = bpKeys[b];
    h += '<div class="asn-bp-item" onclick="_asnLookupDirect(' + esc(asn) + ')">';
    h += '<span class="asn-bp-asn">AS' + esc(asn) + '</span>';
    h += '<span class="asn-bp-desc">' + esc(_asnBulletproof[asn]) + '</span>';
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

  results.innerHTML = '<div class="asn-busy">Looking up AS' + esc(input) + '...</div>';

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

  results.innerHTML = '<div class="asn-busy">Searching for "' + esc(input) + '"...</div>';

  fetch('https://api.bgpview.io/search?query_term=' + encodeURIComponent(input.trim()))
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (!data || !data.data) { results.innerHTML = '<div class="asn-err">Search failed.</div>'; return; }
      var asns = (data.data.asns || []).slice(0, 20);
      if (asns.length === 0) { results.innerHTML = '<div class="asn-empty">No results found.</div>'; return; }

      var h = '<div class="asn-panel">';
      h += '<div class="asn-res-title">SEARCH RESULTS (' + asns.length + ')</div>';
      h += '<table style="width:100%;border-collapse:collapse;font-size:10px;">';
      h += '<thead><tr style="border-bottom:2px solid var(--line,#283a5a);">';
      h += '<th class="asn-th">ASN</th>';
      h += '<th class="asn-th">NAME</th>';
      h += '<th class="asn-th">COUNTRY</th>';
      h += '<th class="asn-th">REPUTATION</th>';
      h += '</tr></thead><tbody>';
      for (var i = 0; i < asns.length; i++) {
        var a = asns[i];
        var isBP = _asnBulletproof[a.asn];
        var repColor = isBP ? '#dc2626' : '#16a34a';
        var repText = isBP ? 'SUSPICIOUS' : 'NORMAL';
        h += '<tr style="border-bottom:1px solid var(--line,#283a5a);cursor:pointer;" onclick="_asnLookupDirect(' + a.asn + ')">';
        h += '<td class="asn-td-asn">AS' + a.asn + '</td>';
        h += '<td class="asn-td">' + esc(a.name || a.description || '') + '</td>';
        h += '<td class="asn-td-mut">' + esc(a.country_code || '??') + '</td>';
        h += '<td style="padding:6px;"><span style="color:' + repColor + ';font-size:9px;padding:1px 6px;background:' + repColor + '15;border:1px solid ' + repColor + '33;border-radius:2px;">' + repText + '</span></td>';
        h += '</tr>';
        if (isBP) {
          h += '<tr><td colspan="4" style="padding:2px 6px 6px;color:#e08a76;font-size:9px;">&#9888; ' + esc(isBP) + '</td></tr>';
        }
      }
      h += '</tbody></table></div>';
      results.innerHTML = h;
    })
    .catch(function(err) {
      results.innerHTML = '<div class="asn-err">Search error: ' + esc(String(err.message || err)) + '</div>';
    });
};

function _asnRenderResults(el, asn, asnData, prefixData, peerData) {
  var h = '';
  var info = asnData && asnData.data ? asnData.data : null;
  var isBP = _asnBulletproof[asn];

  if (!info) {
    el.innerHTML = '<div class="asn-err">ASN data unavailable. BGPView API may be rate-limited.</div>';
    return;
  }

  // Header card
  var repColor = isBP ? '#dc2626' : '#16a34a';
  h += '<div style="background:var(--card2,#0f1726);border:2px solid ' + repColor + ';border-radius:8px;padding:16px;margin-bottom:12px;">';
  h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">';
  h += '<div>';
  h += '<div class="asn-as-num">AS' + esc(String(asn)) + '</div>';
  h += '<div class="asn-as-name">' + esc(info.name || '') + '</div>';
  h += '<div class="asn-as-desc">' + esc(info.description_full || info.description_short || '') + '</div>';
  h += '</div>';
  h += '<div style="text-align:right;">';
  h += '<div style="color:' + repColor + ';font-size:14px;font-weight:bold;">' + (isBP ? 'SUSPICIOUS' : 'CLEAN') + '</div>';
  if (isBP) h += '<div style="color:#e08a76;font-size:9px;max-width:200px;">' + esc(isBP) + '</div>';
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
    h += '<div class="asn-detail-cell">';
    h += '<div class="asn-detail-label">' + details[d].label + '</div>';
    h += '<div class="asn-detail-val">' + esc(details[d].value) + '</div>';
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';

  // Prefixes
  if (prefixData && prefixData.data) {
    var v4 = prefixData.data.ipv4_prefixes || [];
    var v6 = prefixData.data.ipv6_prefixes || [];

    h += '<div class="asn-panel" style="margin-bottom:12px;">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">';
    h += '<div class="asn-prefix-title">ANNOUNCED PREFIXES</div>';
    h += '<div style="display:flex;gap:12px;">';
    h += '<span style="color:var(--acc,#2563eb);font-size:11px;">IPv4: <strong>' + v4.length + '</strong></span>';
    h += '<span style="color:#7c3aed;font-size:11px;">IPv6: <strong>' + v6.length + '</strong></span>';
    h += '</div>';
    h += '</div>';

    // Visual bar
    var maxPrefixes = Math.max(v4.length, v6.length, 1);
    h += '<div style="display:flex;gap:8px;margin-bottom:10px;">';
    h += '<div style="flex:1;"><div style="color:var(--mut,#7a93b8);font-size:9px;margin-bottom:2px;">IPv4</div><div style="background:var(--line,#283a5a);border-radius:2px;height:8px;overflow:hidden;"><div style="background:var(--acc,#2563eb);height:100%;width:' + Math.round((v4.length / maxPrefixes) * 100) + '%;border-radius:2px;"></div></div></div>';
    h += '<div style="flex:1;"><div style="color:var(--mut,#7a93b8);font-size:9px;margin-bottom:2px;">IPv6</div><div style="background:var(--line,#283a5a);border-radius:2px;height:8px;overflow:hidden;"><div style="background:#7c3aed;height:100%;width:' + Math.round((v6.length / maxPrefixes) * 100) + '%;border-radius:2px;"></div></div></div>';
    h += '</div>';

    if (v4.length > 0) {
      h += '<div style="max-height:200px;overflow-y:auto;">';
      h += '<table style="width:100%;border-collapse:collapse;font-size:10px;">';
      h += '<thead><tr style="border-bottom:1px solid var(--line,#283a5a);"><th class="asn-th" style="padding:4px;">PREFIX</th><th class="asn-th" style="padding:4px;">NAME</th><th class="asn-th" style="padding:4px;">DESCRIPTION</th></tr></thead><tbody>';
      for (var p = 0; p < Math.min(v4.length, 50); p++) {
        h += '<tr style="border-bottom:1px solid var(--line,#283a5a);">';
        h += '<td style="padding:4px;color:#16a34a;font-weight:bold;font-family:var(--font-mono);">' + esc(v4[p].prefix) + '</td>';
        h += '<td style="padding:4px;color:var(--txt,#e7eefc);">' + esc(v4[p].name || '') + '</td>';
        h += '<td style="padding:4px;color:var(--txt-2,#9fb0cc);">' + esc(v4[p].description || '') + '</td>';
        h += '</tr>';
      }
      if (v4.length > 50) h += '<tr><td colspan="3" style="padding:4px;color:var(--mut,#7a93b8);">...and ' + (v4.length - 50) + ' more</td></tr>';
      h += '</tbody></table></div>';
    }
    h += '</div>';
  }

  // Peers
  if (peerData && peerData.data) {
    var upstream = peerData.data.ipv4_peers || [];
    h += '<div class="asn-panel">';
    h += '<div class="asn-peer-title">BGP PEERS (' + upstream.length + ')</div>';
    if (upstream.length > 0) {
      h += '<div style="display:flex;flex-wrap:wrap;gap:4px;max-height:150px;overflow-y:auto;">';
      for (var u = 0; u < Math.min(upstream.length, 40); u++) {
        var peer = upstream[u];
        var peerBP = _asnBulletproof[peer.asn];
        var peerColor = peerBP ? '#dc2626' : '#2563eb';
        h += '<span style="background:' + peerColor + '10;border:1px solid ' + peerColor + '33;border-radius:4px;padding:2px 6px;font-size:9px;color:' + peerColor + ';cursor:pointer;font-family:var(--font-mono);" onclick="_asnLookupDirect(' + peer.asn + ')" title="' + esc(peer.name || '') + '">AS' + peer.asn + '</span>';
      }
      if (upstream.length > 40) h += '<span style="color:var(--mut,#7a93b8);font-size:9px;padding:2px 6px;">+' + (upstream.length - 40) + ' more</span>';
      h += '</div>';
    } else {
      h += '<div class="asn-empty" style="font-size:10px;">No peer data available.</div>';
    }
    h += '</div>';
  }

  el.innerHTML = h;
}
