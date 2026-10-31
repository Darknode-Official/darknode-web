// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Network Scanner: resolves a host over DNS-over-HTTPS, then reports the open ports
// Shodan's internet-wide scans last observed for each address (InternetDB, keyless),
// plus a real HTTP/HTTPS request made through the Darknode edge proxy.
// A browser cannot open raw TCP connections, so this page does not probe ports itself.

import { dnFetch, dnFetchJSON, proxyConfigured } from '/js/net.js';

var esc = function(s) { return String(s != null ? s : '').replace(/[&<>"']/g, function(c) {
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

var _nsCommonPorts = [
  { port: 21, service: 'FTP', category: 'file' },
  { port: 22, service: 'SSH', category: 'remote' },
  { port: 23, service: 'Telnet', category: 'remote' },
  { port: 25, service: 'SMTP', category: 'mail' },
  { port: 53, service: 'DNS', category: 'infra' },
  { port: 80, service: 'HTTP', category: 'web' },
  { port: 110, service: 'POP3', category: 'mail' },
  { port: 143, service: 'IMAP', category: 'mail' },
  { port: 443, service: 'HTTPS', category: 'web' },
  { port: 445, service: 'SMB', category: 'file' },
  { port: 993, service: 'IMAPS', category: 'mail' },
  { port: 995, service: 'POP3S', category: 'mail' },
  { port: 1433, service: 'MSSQL', category: 'db' },
  { port: 1521, service: 'Oracle', category: 'db' },
  { port: 3306, service: 'MySQL', category: 'db' },
  { port: 3389, service: 'RDP', category: 'remote' },
  { port: 5432, service: 'PostgreSQL', category: 'db' },
  { port: 5900, service: 'VNC', category: 'remote' },
  { port: 6379, service: 'Redis', category: 'db' },
  { port: 8080, service: 'HTTP-Alt', category: 'web' },
  { port: 8443, service: 'HTTPS-Alt', category: 'web' },
  { port: 9200, service: 'Elasticsearch', category: 'db' },
  { port: 27017, service: 'MongoDB', category: 'db' }
];

export function renderNetworkScanner(container) {
  var h = '';
  h += '<div>';
  h += '<div class="pg-head"><div><h1 class="pg-h1">Network Scanner</h1>';
  h += '<p class="muted pg-sub">Resolves a host, lists the open ports and possible CVEs that Shodan\'s internet-wide scans last recorded for it, and checks HTTP and HTTPS through the edge proxy.</p></div></div>';

  // Input
  h += '<div class="card">';
  h += '<div style="display:flex;gap:8px;margin-bottom:10px;">';
  h += '<input id="ns-target" style="flex:1;" placeholder="Domain or IPv4 address" data-on-keydown="if(event.key===\'Enter\')_nsLookup()">';
  h += '<button class="btn" data-on-click="_nsLookup()">Look up</button>';
  h += '</div>';
  h += '<div style="color:var(--mut);font-size:12px;">Port data comes from Shodan InternetDB and reflects its most recent public scan, not a scan run now. Browsers cannot open raw TCP connections, so no ports are probed from this page.</div>';
  h += '</div>';

  // Results
  h += '<div id="ns-results"></div>';

  // Port reference
  h += '<div class="card" style="margin-top:16px;">';
  h += '<div style="color:var(--txt);font-size:14px;font-weight:600;margin-bottom:10px;">Common ports (reference)</div>';
  h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:6px;">';
  for (var p = 0; p < _nsCommonPorts.length; p++) {
    var port = _nsCommonPorts[p];
    h += '<div style="background:var(--card2);border:1px solid var(--line);border-radius:3px;padding:4px 8px;font-size:12px;display:flex;justify-content:space-between;">';
    h += '<span style="color:var(--txt);font-weight:600;">' + port.port + '</span>';
    h += '<span style="color:var(--mut);">' + esc(port.service) + '</span>';
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';

  h += '</div>';
  container.innerHTML = h;
};

var _nsSeq = 0;
var _IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

function _nsService(port) {
  for (var i = 0; i < _nsCommonPorts.length; i++) if (_nsCommonPorts[i].port === port) return _nsCommonPorts[i].service;
  return '';
}

function _nsLine(color, text) {
  return '<div style="color:' + color + ';font-size:12px;margin:4px 0;">' + text + '</div>';
}

async function _nsResolve(host) {
  if (_IPV4.test(host)) return [host];
  var data = await dnFetchJSON('https://dns.google/resolve?name=' + encodeURIComponent(host) + '&type=A');
  return (data.Answer || []).filter(function(a) { return a.type === 1; }).map(function(a) { return a.data; });
}

async function _nsHttp(host, scheme) {
  try {
    var r = await dnFetch(scheme + '://' + host + '/', { redirect: 'manual', timeout: 12000 });
    var loc = r.headers && (r.headers.location || r.headers.Location);
    return 'HTTP ' + r.status + (r.statusText ? ' ' + esc(r.statusText) : '') + (loc ? ' &#8594; ' + esc(loc) : '');
  } catch (e) {
    return '<span style="color:var(--bad);">' + esc((e && e.message) || 'No response') + '</span>';
  }
}

function _nsIpCard(ip, d) {
  var h = '<div style="border-top:1px solid var(--line);padding-top:10px;margin-top:10px;">';
  h += '<div style="color:var(--txt);font-weight:600;font-size:13px;margin-bottom:6px;">' + esc(ip) + (d && d.hostnames && d.hostnames.length ? ' <span style="color:var(--mut);font-weight:400;">' + d.hostnames.slice(0, 4).map(esc).join(', ') + '</span>' : '') + '</div>';
  if (!d || !Array.isArray(d.ports)) {
    h += _nsLine('var(--mut)', d ? 'Shodan has no record for this address.' : 'Shodan InternetDB could not be reached.');
    return h + '</div>';
  }
  if (!d.ports.length) h += _nsLine('var(--mut)', 'No open ports recorded.');
  else {
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:6px;">';
    d.ports.forEach(function(port) {
      h += '<div style="background:var(--card2);border:1px solid var(--line);border-radius:4px;padding:6px 10px;font-size:12px;display:flex;justify-content:space-between;">';
      h += '<span style="color:var(--txt);font-weight:600;">' + esc(port) + '</span><span style="color:var(--mut);">' + esc(_nsService(port) || 'Open') + '</span></div>';
    });
    h += '</div>';
  }
  if (d.vulns && d.vulns.length) h += _nsLine('var(--warn)', 'Possible CVEs from version matching (' + d.vulns.length + '): ' + d.vulns.slice(0, 20).map(esc).join(', ') + (d.vulns.length > 20 ? ', ...' : ''));
  if (d.tags && d.tags.length) h += _nsLine('var(--mut)', 'Tags: ' + d.tags.map(esc).join(', '));
  if (d.cpes && d.cpes.length) h += _nsLine('var(--mut)', 'Software: ' + d.cpes.slice(0, 8).map(esc).join(', '));
  return h + '</div>';
}

window._nsLookup = async function() {
  var target = ((document.getElementById('ns-target') || {}).value || '').trim();
  if (!target) {
    try { (window.dnToast || window.showToast || function() {})('Enter a domain or IP address first.', 'warning'); } catch (_) {}
    return;
  }
  var host = target.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').replace(/:\d+$/, '').toLowerCase();
  var results = document.getElementById('ns-results');
  if (!results) return;
  var seq = ++_nsSeq;
  if (!proxyConfigured()) {
    results.innerHTML = '<div class="card" style="margin-top:16px;">' + _nsLine('var(--bad)', 'Lookups need the Darknode proxy, which is not configured here.') + '</div>';
    return;
  }
  results.innerHTML = '<div class="card" style="margin-top:16px;">' + _nsLine('var(--mut)', 'Looking up ' + esc(host) + '...') + '</div>';

  var h = '<div class="card" style="margin-top:16px;">';
  h += '<div style="color:var(--txt);font-size:14px;font-weight:600;margin-bottom:8px;">Results for ' + esc(host) + '</div>';
  var ips;
  try { ips = await _nsResolve(host); }
  catch (e) { ips = null; h += _nsLine('var(--bad)', 'DNS lookup failed: ' + esc((e && e.message) || e)); }
  if (seq !== _nsSeq) return;
  if (ips && !ips.length) h += _nsLine('var(--bad)', 'No IPv4 address found for this name.');
  if (ips && ips.length) h += _nsLine('var(--mut)', 'Resolves to ' + ips.map(esc).join(', '));

  var shown = (ips || []).slice(0, 4);
  var all = await Promise.all([
    _nsHttp(host, 'https'),
    _nsHttp(host, 'http'),
    Promise.all(shown.map(function(ip) { return dnFetchJSON('https://internetdb.shodan.io/' + ip).catch(function() { return null; }); }))
  ]);
  if (seq !== _nsSeq) return;
  h += _nsLine('var(--txt)', 'HTTPS (443): ' + all[0]);
  h += _nsLine('var(--txt)', 'HTTP (80): ' + all[1]);
  shown.forEach(function(ip, i) { h += _nsIpCard(ip, all[2][i]); });
  if (ips && ips.length > 4) h += _nsLine('var(--mut)', (ips.length - 4) + ' more addresses not shown.');
  h += '<div style="color:var(--mut);font-size:12px;margin-top:10px;">Source: Shodan InternetDB (last observed scan data). CVEs are inferred from software versions and may not apply.</div>';
  h += '</div>';
  results.innerHTML = h;
};
