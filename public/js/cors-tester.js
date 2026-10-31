// Copyright (c) 2026 Darknode-Official. All rights reserved.
// CORS Tester — test Cross-Origin Resource Sharing policies on any URL

import { dnFetch } from '/js/net.js';
import { registrableDomain } from '/js/dataprotect/phish-engine.js?v=20261029e';

var esc = function(s) { return String(s != null ? s : '').replace(/[&<>"']/g, function(c) {
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

export function renderCorsTester(container) {
  var h = '';
  h += '<div>';
  h += '<div class="pg-head"><div><h1 class="pg-h1">CORS Tester</h1>';
  h += '<p class="muted pg-sub">Test the Cross-Origin Resource Sharing policy of any URL.</p></div></div>';

  h += '<div class="card">';
  h += '<div style="display:flex;gap:8px;margin-bottom:10px;">';
  h += '<input id="cors-url" style="flex:1;" placeholder="https://api.example.com/endpoint" onkeydown="if(event.key===\'Enter\')_corsTest()">';
  h += '<button class="btn" onclick="_corsTest()">Test</button>';
  h += '</div>';

  h += '<div style="display:flex;gap:8px;margin-bottom:8px;">';
  h += '<input id="cors-origin" style="flex:1;" placeholder="Extra Origin to try (optional)">';
  h += '</div>';
  h += '<div style="color:var(--mut);font-size:12px;">Sends the request from the Darknode edge with several Origin headers (an unrelated site, null, look-alike names, plain http, the site itself) and checks which ones the server lets read its responses, and whether cookies are allowed.</div>';
  h += '</div>';

  h += '<div id="cors-results"></div>';

  // Quick test buttons
  h += '<div class="card" style="margin-top:16px;">';
  h += '<div style="color:var(--txt);font-size:14px;font-weight:600;margin-bottom:10px;">Quick test: known APIs</div>';
  h += '<div style="display:flex;flex-wrap:wrap;gap:6px;">';
  var quickTests = [
    { url: 'https://api.github.com', label: 'GitHub API' },
    { url: 'https://dns.google/resolve?name=google.com&type=A', label: 'Google DoH' },
    { url: 'https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/significant_hour.geojson', label: 'USGS' },
    { url: 'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1', label: 'NVD API' },
    { url: 'https://ipapi.co/json/', label: 'ipapi.co' },
    { url: 'https://crt.sh/?q=google.com&output=json', label: 'crt.sh' },
    { url: 'https://stat.ripe.net/data/as-overview/data.json?resource=AS13335', label: 'RIPEstat' },
    { url: 'https://opensky-network.org/api/states/all?lamin=45&lomin=-1&lamax=46&lomax=0', label: 'OpenSky' }
  ];
  for (var i = 0; i < quickTests.length; i++) {
    var qt = quickTests[i];
    h += '<button onclick="document.getElementById(\'cors-url\').value=\'' + esc(qt.url) + '\';_corsTest()" class="btn ghost sm">' + esc(qt.label) + '</button>';
  }
  h += '</div></div>';

  // CORS reference
  h += '<div class="card" style="margin-top:12px;">';
  h += '<div style="color:var(--txt);font-size:14px;font-weight:600;margin-bottom:10px;">CORS headers reference</div>';
  var corsHeaders = [
    { header: 'Access-Control-Allow-Origin', desc: 'Which origins can access (e.g. *, https://example.com)', importance: 'REQUIRED' },
    { header: 'Access-Control-Allow-Methods', desc: 'Which HTTP methods are allowed (GET, POST, etc.)', importance: 'PREFLIGHT' },
    { header: 'Access-Control-Allow-Headers', desc: 'Which request headers are allowed', importance: 'PREFLIGHT' },
    { header: 'Access-Control-Allow-Credentials', desc: 'Whether cookies/auth can be sent cross-origin', importance: 'OPTIONAL' },
    { header: 'Access-Control-Max-Age', desc: 'How long to cache preflight response (seconds)', importance: 'OPTIONAL' },
    { header: 'Access-Control-Expose-Headers', desc: 'Which response headers JS can read', importance: 'OPTIONAL' }
  ];
  for (var ch = 0; ch < corsHeaders.length; ch++) {
    var hdr = corsHeaders[ch];
    var impColor = hdr.importance === 'REQUIRED' ? '#ff4444' : hdr.importance === 'PREFLIGHT' ? '#ffaa00' : '#00cc88';
    h += '<div style="margin:4px 0;font-size:12px;display:flex;flex-wrap:wrap;gap:4px 8px;align-items:flex-start;">';
    h += '<span style="color:' + impColor + ';font-size:12px;padding:1px 4px;background:' + impColor + '15;border:1px solid ' + impColor + '33;border-radius:2px;flex-shrink:0;">' + hdr.importance + '</span>';
    h += '<span style="color:var(--acc);min-width:min(240px,100%);flex-shrink:0;">' + esc(hdr.header) + '</span>';
    h += '<span style="color:var(--mut);flex:1 1 180px;min-width:0;">' + esc(hdr.desc) + '</span>';
    h += '</div>';
  }
  h += '</div>';

  h += '</div>';
  container.innerHTML = h;
};

// One probe per Origin a misconfigured server tends to trust. sev is the severity when the
// server echoes that origin back [with Access-Control-Allow-Credentials: true, without it].
function corsProbes(u, extra) {
  var host = u.hostname, org = registrableDomain(host) || host, port = u.port ? ':' + u.port : '';
  var list = [
    { kind: 'foreign', origin: 'https://darknode-cors-check.example', what: 'an unrelated website', sev: ['critical', 'medium'] },
    { kind: 'null', origin: 'null', what: 'the null origin (sandboxed iframes, local files)', sev: ['high', 'low'] },
    { kind: 'suffix', origin: 'https://' + host + '.darknode-cors-check.example', what: 'a look-alike that starts with your host name', sev: ['critical', 'medium'] },
    { kind: 'prefix', origin: 'https://dncheck' + org, what: 'a look-alike that ends with your domain name', sev: ['critical', 'medium'] }
  ];
  if (u.protocol === 'https:') list.push({ kind: 'http', origin: 'http://' + host + port, what: 'your own site over plain http', sev: ['medium', 'low'] });
  list.push({ kind: 'self', origin: u.protocol + '//' + host + port, what: 'the site itself', sev: ['info', 'info'] });
  if (extra) list.push({ kind: 'custom', origin: extra, what: 'the origin you entered', sev: ['high', 'low'] });
  return list;
}

window._corsTest = function() {
  var url = ((document.getElementById('cors-url') || {}).value || '').trim();
  var extra = ((document.getElementById('cors-origin') || {}).value || '').trim().replace(/\/+$/, '');
  var results = document.getElementById('cors-results');
  if (!url || !results) return;
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
  var u;
  try { u = new URL(url); } catch (_) { results.innerHTML = '<div style="color:var(--warn);font-size:12px;padding:12px;">That is not a valid URL.</div>'; return; }
  if (extra && !/^(null|https?:\/\/[a-z0-9.-]+(:\d{1,5})?)$/i.test(extra)) { results.innerHTML = '<div style="color:var(--warn);font-size:12px;padding:12px;">The extra Origin must be null or scheme://host[:port], with no path.</div>'; return; }

  results.innerHTML = '<div style="color:var(--warn);font-size:12px;padding:16px;text-align:center;">Testing CORS for ' + esc(u.href) + '...</div>';
  var probes = corsProbes(u, extra);
  Promise.all(probes.map(function(p) {
    return dnFetch(u.href, { raw: true, origin: p.origin, timeout: 15000 })
      .then(function(r) { p.res = r; }, function(e) { p.err = String((e && e.message) || e); });
  })).then(function() {
    if (probes.every(function(p) { return p.err; })) {
      results.innerHTML = '<div style="background:color-mix(in srgb,var(--bad) 10%,var(--card));border:2px solid var(--bad);border-radius:8px;padding:16px;color:var(--warn);font-size:12px;">Could not reach the URL: ' + esc(probes[0].err) + '</div>';
      return;
    }
    var rank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    var colors = { critical: '#ff4444', high: '#ff8844', medium: '#ffaa00', low: '#00aaff', info: '#00cc88' };
    var findings = [], worst = 'info', reflectedAny = false, vary = '';
    probes.forEach(function(p) {
      if (p.err) { p.verdict = 'no answer'; return; }
      var hd = p.res.headers || {};
      var acao = (hd['access-control-allow-origin'] || '').trim();
      var creds = /^true$/i.test((hd['access-control-allow-credentials'] || '').trim());
      vary = vary || hd['vary'] || '';
      p.acao = acao; p.creds = creds;
      if (acao && acao !== '*' && acao.toLowerCase() === p.origin.toLowerCase()) {
        p.verdict = p.kind === 'self' ? 'allowed' : 'TRUSTED';
        if (p.kind !== 'self') {
          reflectedAny = true;
          var sev = p.sev[creds ? 0 : 1];
          findings.push({ sev: sev, text: 'Trusts ' + p.what + ' (' + p.origin + ')' + (creds ? ' with credentials: that site can read responses sent with your users’ cookies.' : ', without credentials: it can read responses that need no login.') });
          if (rank[sev] > rank[worst]) worst = sev;
        }
      } else if (acao === '*') {
        p.verdict = 'public (*)';
      } else {
        p.verdict = acao ? 'not trusted' : 'no CORS header';
      }
    });
    if (probes.some(function(p) { return p.acao === '*'; })) {
      findings.push({ sev: 'info', text: 'Answers Access-Control-Allow-Origin: * — any site can read responses, but browsers never send cookies with a wildcard' + (probes.some(function(p) { return p.acao === '*' && p.creds; }) ? ' (the Allow-Credentials: true it also sends is ignored).' : '.') + ' Fine for public data.' });
    }
    if (reflectedAny && !/(^|,)\s*(origin|\*)\s*(,|$)/i.test(vary)) {
      findings.push({ sev: 'low', text: 'The allowed origin changes per request but the response has no Vary: Origin, so a shared cache can serve one origin’s CORS answer to another.' });
      if (rank.low > rank[worst]) worst = 'low';
    }
    if (!findings.length) findings.push({ sev: 'info', text: 'Only the site itself (or nobody) may read responses cross-origin. No CORS misconfiguration found for this URL.' });
    findings.sort(function(a, b) { return rank[b.sev] - rank[a.sev]; });

    var verdictText = { critical: 'CRITICAL MISCONFIGURATION', high: 'HIGH-RISK MISCONFIGURATION', medium: 'WEAK ORIGIN CHECK', low: 'MINOR ISSUE', info: 'NO MISCONFIGURATION FOUND' }[worst];
    var c = colors[worst];
    var first = probes.find(function(p) { return p.res; });
    var h = '<div style="background:var(--card2);border:2px solid ' + c + ';border-radius:8px;padding:16px;margin-bottom:12px;text-align:center;">';
    h += '<div style="color:' + c + ';font-size:16px;font-weight:bold;">' + verdictText + '</div>';
    h += '<div style="color:var(--mut);font-size:12px;margin-top:4px;word-break:break-all;">' + esc(u.href) + ' — HTTP ' + esc(String(first.res.status)) + '</div></div>';

    h += '<div style="background:var(--card2);border:1px solid var(--line);border-radius:6px;padding:14px;margin-bottom:12px;">';
    h += '<div style="color:var(--txt);font-size:14px;font-weight:600;margin-bottom:10px;">Findings</div>';
    findings.forEach(function(f) {
      h += '<div style="margin:6px 0;font-size:12px;display:flex;gap:8px;align-items:flex-start;"><span style="color:' + colors[f.sev] + ';font-size:12px;padding:1px 4px;border:1px solid ' + colors[f.sev] + '55;border-radius:2px;flex-shrink:0;">' + f.sev + '</span><span>' + esc(f.text) + '</span></div>';
    });
    h += '</div>';

    h += '<div style="background:var(--card2);border:1px solid var(--line);border-radius:6px;padding:14px;overflow-x:auto;">';
    h += '<div style="color:var(--txt);font-size:14px;font-weight:600;margin-bottom:10px;">Origins tried</div>';
    h += '<table style="width:100%;border-collapse:collapse;font-size:12px;"><tr style="color:var(--mut);text-align:left;"><th style="padding:4px;">Origin sent</th><th style="padding:4px;">Allow-Origin</th><th style="padding:4px;">Credentials</th><th style="padding:4px;">Result</th></tr>';
    probes.forEach(function(p) {
      var vc = p.verdict === 'TRUSTED' ? '#ff6644' : p.verdict === 'allowed' || p.verdict === 'public (*)' ? '#00cc88' : '#6a8aaa';
      h += '<tr style="border-top:1px solid var(--line);"><td style="padding:4px;word-break:break-all;">' + esc(p.origin) + '</td><td style="padding:4px;word-break:break-all;">' + esc(p.err ? '' : (p.acao || '(none)')) + '</td><td style="padding:4px;">' + (p.err ? '' : p.creds ? 'true' : 'no') + '</td><td style="padding:4px;color:' + vc + ';">' + esc(p.err ? 'error: ' + p.err : p.verdict) + '</td></tr>';
    });
    h += '</table></div>';
    results.innerHTML = h;
  });
};
