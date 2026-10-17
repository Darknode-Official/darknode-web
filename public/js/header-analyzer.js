// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved.
// HTTP Security Header Analyzer — checks the REAL security headers of any URL.
// Requests are made through the Darknode Worker's SSRF-guarded /api/fetch proxy,
// so we read the genuine upstream response headers (browser CORS cannot).
// Grades headers A-F and provides recommendations.

import { dnFetch, proxyConfigured } from '/js/net.js';

var esc = function(s) { return String(s != null ? s : '').replace(/[&<>"']/g, function(c) { return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

var _haSecurityHeaders = [
  { name: 'Content-Security-Policy', weight: 20, critical: true, desc: 'Controls which resources the browser can load. Prevents XSS, data injection, clickjacking.', rec: 'Add a strict CSP: default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:; object-src \'none\'; base-uri \'self\'; form-action \'self\'' },
  { name: 'Strict-Transport-Security', weight: 15, critical: true, desc: 'Forces HTTPS connections. Prevents SSL stripping attacks.', rec: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload', weak: function(v) { if (!v) return false; /* RFC 6797 §6.1: directive names are case-insensitive and the value may be a quoted-string, so a valid "Max-Age=..." or max-age="..." must not be mis-graded weak. */ var m = /max-age\s*=\s*"?(\d+)"?/i.exec(v); return !m || parseInt(m[1], 10) < 31536000; } },
  { name: 'X-Content-Type-Options', weight: 10, critical: false, desc: 'Prevents MIME-type sniffing. Stops browsers from guessing content types.', rec: 'Add: X-Content-Type-Options: nosniff', weak: function(v) { return v && v.toLowerCase() !== 'nosniff'; } },
  { name: 'X-Frame-Options', weight: 10, critical: false, desc: 'Prevents clickjacking by controlling iframe embedding.', rec: 'Add: X-Frame-Options: DENY (or SAMEORIGIN)', weak: function(v) { return v && v.toLowerCase() === 'allowall'; } },
  { name: 'Referrer-Policy', weight: 8, critical: false, desc: 'Controls what referrer information is sent with requests.', rec: 'Add: Referrer-Policy: strict-origin-when-cross-origin', weak: function(v) { return v && (v.toLowerCase() === 'unsafe-url' || v.toLowerCase() === 'no-referrer-when-downgrade'); } },
  { name: 'Permissions-Policy', weight: 8, critical: false, desc: 'Controls which browser features the site can use (camera, microphone, geolocation).', rec: 'Add: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()' },
  { name: 'X-XSS-Protection', weight: 5, critical: false, desc: 'Legacy XSS filter. Modern browsers use CSP instead, but still good to have.', rec: 'Add: X-XSS-Protection: 0 (or rely on CSP instead). Note: deprecated in modern browsers.' },
  { name: 'Cross-Origin-Opener-Policy', weight: 7, critical: false, desc: 'Isolates browsing context to prevent Spectre-style attacks.', rec: 'Add: Cross-Origin-Opener-Policy: same-origin' },
  { name: 'Cross-Origin-Resource-Policy', weight: 7, critical: false, desc: 'Controls which origins can load this resource.', rec: 'Add: Cross-Origin-Resource-Policy: same-origin (or same-site)' },
  { name: 'Cross-Origin-Embedder-Policy', weight: 5, critical: false, desc: 'Ensures all sub-resources are loaded with CORS or CORP headers.', rec: 'Add: Cross-Origin-Embedder-Policy: require-corp' },
  { name: 'X-DNS-Prefetch-Control', weight: 3, critical: false, desc: 'Controls DNS prefetching which can leak browsing information.', rec: 'Add: X-DNS-Prefetch-Control: off' },
  { name: 'X-Permitted-Cross-Domain-Policies', weight: 2, critical: false, desc: 'Controls Adobe Flash/PDF cross-domain policy loading.', rec: 'Add: X-Permitted-Cross-Domain-Policies: none' }
];

function _haGradeFromScore(score) {
  if (score >= 90) return { grade: 'A', color: '#00ff88', label: 'EXCELLENT' };
  if (score >= 80) return { grade: 'B', color: '#00cc66', label: 'GOOD' };
  if (score >= 65) return { grade: 'C', color: '#ffcc00', label: 'AVERAGE' };
  if (score >= 50) return { grade: 'D', color: '#ff8800', label: 'BELOW AVERAGE' };
  if (score >= 30) return { grade: 'E', color: '#ff4444', label: 'POOR' };
  return { grade: 'F', color: '#ff0000', label: 'CRITICAL' };
}

// Disclosure headers: the secure state is absence.
var _haDisclosure = [
  { name: 'Server', note: 'consider hiding this' },
  { name: 'X-Powered-By', note: 'REMOVE THIS — reveals technology stack' },
  { name: 'X-AspNet-Version', note: 'remove — reveals the exact framework version' },
  { name: 'X-AspNetMvc-Version', note: 'remove — reveals the exact framework version' }
];

var _haLast = null; // last graded result, for the Security Graph send

// Raw "Name: Value" lines (pasted, or `curl -sI` output) -> { status, statusText, headers }.
// With several responses (redirects), the last block wins, as curl prints them in order.
function _haParseRaw(raw) {
  var out = { status: '', statusText: '', headers: {} };
  String(raw || '').split(/\r?\n/).forEach(function(line) {
    var sl = /^HTTP\/[\d.]+\s+(\d{3})\s*(.*)$/i.exec(line.trim());
    if (sl) { out = { status: sl[1], statusText: sl[2] || '', headers: {} }; return; }
    var c = line.indexOf(':');
    if (c <= 0) return;
    var k = line.slice(0, c).trim().toLowerCase(), v = line.slice(c + 1).trim();
    if (!/^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(k)) return;
    out.headers[k] = out.headers[k] ? out.headers[k] + ', ' + v : v;
  });
  return out;
}

function _haBox(title, msg, sub) {
  return '<div style="background:#1a0a0a;border:1px solid #ff444444;border-radius:8px;padding:20px;text-align:center;">' +
    '<div style="color:#ff4444;font-size:14px;font-family:monospace;font-weight:bold;margin-bottom:8px;">' + esc(title) + '</div>' +
    '<div style="color:#8ab4d4;font-size:11px;font-family:monospace;' + (sub ? 'margin-bottom:8px;' : '') + '">' + esc(msg) + '</div>' +
    (sub ? '<div style="color:#4a6a8a;font-size:10px;font-family:monospace;">' + esc(sub) + '</div>' : '') + '</div>';
}

function _haNormUrl(url) {
  url = String(url || '').trim();
  if (!url) return '';
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
  return url;
}

async function _haAnalyze(url) {
  var resultsEl = document.getElementById('ha-results');
  if (!resultsEl) return;
  url = _haNormUrl(url);
  if (!url) { resultsEl.innerHTML = '<div style="color:#ff4444;font-family:monospace;font-size:11px;padding:16px;">Enter a URL to analyze.</div>'; return; }

  if (!proxyConfigured()) {
    resultsEl.innerHTML = _haBox('LIVE LOOKUP UNAVAILABLE', 'The Darknode fetch proxy is not configured, so real headers cannot be retrieved. Use the local agent or paste headers instead.');
    return;
  }

  resultsEl.innerHTML = '<div style="text-align:center;padding:30px;color:#00aaff;font-family:monospace;font-size:12px;">Analyzing headers for <b>' + esc(url) + '</b>...</div>';

  try {
    var start = performance.now();
    var resp = await dnFetch(url, { redirect: 'manual' });
    var headers = {};
    var rawHeaders = resp.headers || {};
    Object.keys(rawHeaders).forEach(function(key) { headers[key.toLowerCase()] = rawHeaders[key]; });
    _haRender(resultsEl, { url: url, headers: headers, status: resp.status, statusText: resp.statusText || '', finalUrl: resp.finalUrl || url, timing: Math.round(performance.now() - start), redirects: resp.redirectChain || [], source: 'proxy' });
  } catch (e) {
    resultsEl.innerHTML = _haBox('ANALYSIS FAILED', e.message || 'Request failed', 'The target could not be reached through the Darknode proxy (the host may be down, private, or blocking automated requests). No results are shown — nothing is guessed.');
  }
}

// Local agent mode: the Darknode CLI bridge runs a real `curl -sI` on this machine
// (reaches internal hosts the proxy cannot).
async function _haAgent(url) {
  var resultsEl = document.getElementById('ha-results');
  if (!resultsEl) return;
  url = _haNormUrl(url);
  var b = window._bridge;
  if (!b || !b.connected || !b.hasTool('curl')) { resultsEl.innerHTML = _haBox('LOCAL AGENT NOT CONNECTED', 'Start the Darknode local agent (with curl installed) to fetch headers from this machine.'); return; }
  var href = '';
  try { href = new URL(url).href; } catch (_) {}
  if (!href || /['"\\\s`$;|&<>(){}]/.test(href)) { resultsEl.innerHTML = _haBox('INVALID URL', 'Enter a plain http(s) URL.'); return; }
  resultsEl.innerHTML = '<div style="text-align:center;padding:30px;color:#00aaff;font-family:monospace;font-size:12px;">Fetching headers with the local agent for <b>' + esc(href) + '</b>...</div>';
  try {
    var start = performance.now();
    var r = await b.exec("curl -sI --max-time 15 '" + href + "' 2>/dev/null | head -60");
    var p = _haParseRaw(r.stdout || '');
    if (!p.status && !Object.keys(p.headers).length) { resultsEl.innerHTML = _haBox('NO RESPONSE', 'curl returned no headers for this URL.', 'The host may be unreachable from this machine.'); return; }
    _haRender(resultsEl, { url: href, headers: p.headers, status: p.status, statusText: p.statusText, finalUrl: href, timing: Math.round(performance.now() - start), redirects: [], source: 'agent' });
  } catch (e) {
    resultsEl.innerHTML = _haBox('LOCAL AGENT ERROR', e.message || 'curl failed');
  }
}

function _haPasted() {
  var resultsEl = document.getElementById('ha-results');
  var raw = (document.getElementById('ha-paste') || {}).value || '';
  if (!resultsEl) return;
  var p = _haParseRaw(raw);
  if (!Object.keys(p.headers).length) { resultsEl.innerHTML = '<div style="color:#ff4444;font-family:monospace;font-size:11px;padding:16px;">Paste response headers, one per line (Name: Value).</div>'; return; }
  var u = _haNormUrl((document.getElementById('ha-input') || {}).value);
  _haRender(resultsEl, { url: u, headers: p.headers, status: p.status, statusText: p.statusText, finalUrl: u, timing: null, redirects: [], source: 'pasted' });
}

function _haSeverity(r) {
  var w = r.header.weight, missing = r.status === 'missing';
  if (w >= 15) return missing ? 'high' : 'medium';
  if (w >= 7) return missing ? 'medium' : 'low';
  if (w >= 5) return 'low';
  return 'info';
}

function _haHostOf(u) { try { return new URL(u).hostname.toLowerCase(); } catch (_) { return ''; } }

function _haToGraph(btn) {
  var g = _haLast;
  if (!g) return;
  var hostIn = document.getElementById('ha-graph-host');
  var host = (hostIn ? hostIn.value : '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/[\/:].*$/, '') || _haHostOf(g.url);
  var tags = ['http-headers', g.source === 'pasted' ? 'pasted' : 'live'];
  var label = host || 'pasted headers';
  var items = g.results.filter(function(r) { return r.status !== 'present'; }).map(function(r) {
    return { type: 'FINDING', name: r.header.name + ' header ' + (r.status === 'missing' ? 'missing' : 'weak') + ' (' + label + ')',
      data: { header: r.header.name, value: r.value || '', check: r.status, domain: host, grade: g.grade, score: g.score, recommendation: r.header.rec },
      opts: { tags: tags.concat('security-header'), severity: _haSeverity(r) } };
  }).concat(g.disclosed.map(function(d) {
    return { type: 'FINDING', name: d.name + ' header discloses software (' + label + ')', data: { header: d.name, value: d.value, domain: host }, opts: { tags: tags.concat('info-disclosure'), severity: 'low' } };
  }));
  btn.disabled = true;
  import('/js/graph-bridge.js?v=20261017d').then(function(gb) {
    var root = host ? gb.sendToGraph('Header Analyzer', [{ type: 'DOMAIN', name: host, data: { headerGrade: g.grade, headerScore: g.score }, opts: { tags: tags } }], undefined, true).entities[0] : null;
    var r = gb.sendToGraph('Header Analyzer', items, undefined, true);
    if (root) r.entities.forEach(function(e) { gb.linkEntities(e.id, root.id, 'affects'); });
    btn.textContent = 'Sent: ' + r.created + ' new, ' + r.updated + ' merged';
    gb.showGraphToast('Security Graph: ' + r.entities.length + ' header findings for ' + label + (root ? '' : ' (not linked: no domain given)'));
  }).catch(function() { btn.textContent = 'Security Graph unavailable'; btn.disabled = false; });
}

function _haRender(resultsEl, info) {
    var headers = info.headers, url = info.url || '';
    var totalWeight = 0;
    var earnedWeight = 0;
    var results = [];

    for (var i = 0; i < _haSecurityHeaders.length; i++) {
      var hdr = _haSecurityHeaders[i];
      var key = hdr.name.toLowerCase();
      var value = headers[key] || null;
      totalWeight += hdr.weight;

      var status, statusColor, statusLabel;
      if (value) {
        if (hdr.weak && hdr.weak(value)) {
          status = 'weak'; statusColor = '#ffcc00'; statusLabel = 'WEAK';
          earnedWeight += hdr.weight * 0.5;
        } else {
          status = 'present'; statusColor = '#00ff88'; statusLabel = 'PRESENT';
          earnedWeight += hdr.weight;
        }
      } else {
        status = 'missing'; statusColor = hdr.critical ? '#ff4444' : '#ff8844'; statusLabel = 'MISSING';
      }

      results.push({ header: hdr, value: value, status: status, color: statusColor, label: statusLabel });
    }

    // Software-disclosing headers (absent = good)
    var disclosed = _haDisclosure.filter(function(d) { return headers[d.name.toLowerCase()]; }).map(function(d) { return { name: d.name, note: d.note, value: headers[d.name.toLowerCase()] }; });
    var acao = headers['access-control-allow-origin'] || '';
    var acac = /^\s*true\s*$/i.test(headers['access-control-allow-credentials'] || '');

    var score = Math.round((earnedWeight / totalWeight) * 100);
    var grade = _haGradeFromScore(score);

    // HTTPS check (pasted headers without a URL are graded on headers alone)
    var isHTTPS = !url || url.toLowerCase().indexOf('https://') === 0;
    if (!isHTTPS) { score = Math.max(0, score - 20); grade = _haGradeFromScore(score); }

    var srcLabel = info.source === 'agent' ? 'LOCAL AGENT (curl -sI)' : info.source === 'pasted' ? 'PASTED HEADERS' : 'DARKNODE PROXY';
    var h = '';

    // Grade card
    h += '<div style="display:flex;gap:16px;margin-bottom:20px;align-items:center;flex-wrap:wrap;">';
    h += '<div style="width:100px;height:100px;border-radius:12px;border:3px solid ' + grade.color + ';display:flex;flex-direction:column;align-items:center;justify-content:center;background:rgba(0,0,0,0.3);">';
    h += '<div style="font-size:42px;font-weight:bold;color:' + grade.color + ';font-family:monospace;line-height:1;">' + grade.grade + '</div>';
    h += '<div style="font-size:9px;color:' + grade.color + ';font-family:monospace;letter-spacing:1px;">' + grade.label + '</div>';
    h += '</div>';
    h += '<div style="flex:1;min-width:0;">';
    h += '<div style="font-size:14px;color:#c8d6e5;font-family:monospace;font-weight:bold;margin-bottom:4px;word-break:break-all;">' + esc(info.finalUrl || url || 'Pasted response headers') + '</div>';
    h += '<div style="font-size:11px;color:#4a6a8a;font-family:monospace;">' + (info.status ? 'HTTP ' + esc(String(info.status)) + ' ' + esc(info.statusText || '') + ' | ' : '') + 'Score: ' + score + '/100 | Headers checked: ' + _haSecurityHeaders.length + (info.timing != null ? ' | ' + info.timing + 'ms' : '') + ' | Source: ' + srcLabel + '</div>';
    if (!isHTTPS) h += '<div style="color:#ff4444;font-size:11px;font-family:monospace;margin-top:4px;">WARNING: Not using HTTPS (-20 points)</div>';
    for (var di = 0; di < disclosed.length; di++) h += '<div style="color:#ffaa00;font-size:10px;font-family:monospace;margin-top:2px;word-break:break-all;">' + esc(disclosed[di].name) + ': ' + esc(disclosed[di].value) + ' (' + esc(disclosed[di].note) + ')</div>';
    if (/^3\d\d$/.test(String(info.status)) && headers['location']) h += '<div style="color:#8ab4d4;font-size:10px;font-family:monospace;margin-top:2px;word-break:break-all;">Redirects to: ' + esc(headers['location']) + ' (headers graded on this redirect response)</div>';
    if (info.redirects && info.redirects.length) h += '<div style="color:#8ab4d4;font-size:10px;font-family:monospace;margin-top:2px;word-break:break-all;">Redirect chain: ' + info.redirects.map(function(hop) { return esc(typeof hop === 'string' ? hop : ((hop.status != null ? hop.status + ' ' : '') + (hop.url || hop.from || '') + (hop.location || hop.to ? ' -> ' + (hop.location || hop.to) : ''))); }).join(' | ') + '</div>';
    if (headers['allow']) h += '<div style="color:#8ab4d4;font-size:10px;font-family:monospace;margin-top:2px;">Advertised methods (Allow): ' + esc(headers['allow']) + '</div>';
    if (acao === '*' && acac) h += '<div style="color:#ff4444;font-size:10px;font-family:monospace;margin-top:2px;">CORS: Access-Control-Allow-Origin * together with Allow-Credentials true (browsers reject it, but it signals a misconfigured policy)</div>';
    else if (acao) h += '<div style="color:#8ab4d4;font-size:10px;font-family:monospace;margin-top:2px;word-break:break-all;">CORS: Access-Control-Allow-Origin ' + esc(acao) + (acac ? ' with credentials' : '') + '</div>';
    h += '</div>';
    h += '</div>';

    // Progress bar
    h += '<div style="background:#1a2a3a;height:6px;border-radius:3px;margin-bottom:20px;overflow:hidden;">';
    h += '<div style="background:' + grade.color + ';height:100%;width:' + score + '%;border-radius:3px;transition:width 0.5s;"></div>';
    h += '</div>';

    // Header results
    h += '<div style="color:#00aaff;font-size:11px;font-family:monospace;letter-spacing:2px;font-weight:bold;margin-bottom:8px;border-bottom:1px solid #1a2a44;padding-bottom:4px;">SECURITY HEADERS</div>';

    for (var r = 0; r < results.length; r++) {
      var res = results[r];
      h += '<div style="padding:10px 0;border-bottom:1px solid #0d1525;">';
      h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">';
      h += '<div style="font-family:monospace;font-size:12px;color:#c8d6e5;font-weight:bold;">' + esc(res.header.name) + (res.header.critical ? ' <span style="color:#ff4444;font-size:8px;">CRITICAL</span>' : '') + '</div>';
      h += '<span style="background:' + res.color + '22;color:' + res.color + ';font-size:9px;font-family:monospace;padding:2px 8px;border-radius:3px;border:1px solid ' + res.color + '44;font-weight:bold;letter-spacing:1px;">' + res.label + '</span>';
      h += '</div>';
      if (res.value) {
        h += '<div style="font-family:monospace;font-size:10px;color:#8ab4d4;word-break:break-all;margin:4px 0;padding:4px 8px;background:#0a1018;border-radius:3px;">' + esc(res.value.substring(0, 300)) + (res.value.length > 300 ? '...' : '') + '</div>';
      }
      h += '<div style="font-family:monospace;font-size:10px;color:#4a6a8a;margin-top:2px;">' + esc(res.header.desc) + '</div>';
      if (res.status !== 'present') {
        h += '<div style="font-family:monospace;font-size:10px;color:#ffaa00;margin-top:4px;">Recommendation: ' + esc(res.header.rec) + '</div>';
      }
      h += '</div>';
    }

    // Send issues to the Security Graph
    var issueCount = results.filter(function(x) { return x.status !== 'present'; }).length + disclosed.length;
    if (issueCount) {
      h += '<div style="display:flex;gap:8px;align-items:center;margin-top:14px;flex-wrap:wrap;">';
      if (info.source === 'pasted' && !_haHostOf(url)) h += '<input id="ha-graph-host" type="text" placeholder="Domain (optional, links findings)" style="flex:1;min-width:180px;background:#0a0e1a;border:1px solid #1a2a44;border-radius:4px;padding:6px 10px;color:#c8d6e5;font-family:monospace;font-size:11px;outline:none;">';
      h += '<button id="ha-graph" style="background:#00aaff22;border:1px solid #00aaff66;border-radius:4px;padding:6px 14px;color:#00ddff;font-family:monospace;font-size:11px;font-weight:bold;cursor:pointer;">Send ' + issueCount + ' header issue' + (issueCount === 1 ? '' : 's') + ' to Security Graph</button>';
      h += '</div>';
    }

    // Raw headers dump
    h += '<div style="margin-top:16px;">';
    h += '<div style="color:#4a6a8a;font-size:10px;font-family:monospace;letter-spacing:2px;margin-bottom:6px;cursor:pointer;" onclick="var el=document.getElementById(\'ha-raw\');el.hidden=!el.hidden;">ALL RESPONSE HEADERS [TOGGLE]</div>';
    h += '<div id="ha-raw" hidden style="background:#0a0e1a;border:1px solid #1a2a44;border-radius:6px;padding:10px;max-height:300px;overflow-y:auto;">';
    var hdrKeys = Object.keys(headers).sort();
    for (var hi = 0; hi < hdrKeys.length; hi++) {
      h += '<div style="font-family:monospace;font-size:10px;padding:2px 0;border-bottom:1px solid #0d1525;">';
      h += '<span style="color:#00aaff;">' + esc(hdrKeys[hi]) + ':</span> <span style="color:#c8d6e5;">' + esc(headers[hdrKeys[hi]]) + '</span>';
      h += '</div>';
    }
    h += '</div></div>';

    resultsEl.innerHTML = h;
    _haLast = { url: url, source: info.source, grade: grade.grade, score: score, results: results, disclosed: disclosed };
    var gbtn = resultsEl.querySelector('#ha-graph');
    if (gbtn) gbtn.addEventListener('click', function() { _haToGraph(gbtn); });
}

export function renderHeaderAnalyzer(container) {
  var agentReady = !!(window._bridge && window._bridge.connected && window._bridge.hasTool && window._bridge.hasTool('curl'));
  var btnCss = 'border-radius:4px;padding:10px 16px;font-family:monospace;font-size:12px;font-weight:bold;cursor:pointer;letter-spacing:1px;';
  container.innerHTML =
    '<div style="padding:20px 24px;max-width:1000px;margin:0 auto;">' +
    '<h2 style="margin:0 0 4px;font-size:20px;color:#00aaff;font-family:monospace;letter-spacing:2px;text-transform:uppercase;">HTTP SECURITY HEADERS</h2>' +
    '<div style="color:#4a6a8a;font-size:11px;font-family:monospace;margin-bottom:16px;">Grade any URL\'s security headers A through F: live through the Darknode proxy, from this machine with the local agent, or from pasted headers</div>' +

    '<div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;">' +
    '<input id="ha-input" type="text" placeholder="https://example.com" ' +
    'style="flex:1;min-width:200px;background:#0a0e1a;border:1px solid #1a2a44;border-radius:6px;padding:10px 14px;color:#c8d6e5;font-family:monospace;font-size:13px;outline:none;" ' +
    'onkeydown="if(event.key===\'Enter\')_haAnalyze(this.value)">' +
    '<button onclick="_haAnalyze(document.getElementById(\'ha-input\').value)" ' +
    'style="background:linear-gradient(135deg,#00aaff22,#00aaff11);border:1px solid #00aaff66;color:#00ddff;' + btnCss + '">Analyze</button>' +
    (agentReady ? '<button id="ha-agent" title="Run curl -sI on this machine through the Darknode local agent" style="background:#22c55e18;border:1px solid #22c55e66;color:#22c55e;' + btnCss + '">Fetch via local agent</button>' : '') +
    '</div>' +

    '<details style="margin-bottom:12px;"><summary style="color:#5a8aaa;font-size:11px;font-family:monospace;cursor:pointer;">Or paste response headers (e.g. from curl -sI or browser dev tools)</summary>' +
    '<textarea id="ha-paste" rows="6" placeholder="Name: Value, one per line" style="width:100%;box-sizing:border-box;margin-top:8px;background:#0a0e1a;border:1px solid #1a2a44;border-radius:6px;padding:10px 14px;color:#c8d6e5;font-family:monospace;font-size:12px;outline:none;resize:vertical;"></textarea>' +
    '<button id="ha-paste-go" style="margin-top:6px;background:#0a1a28;border:1px solid #1a3050;color:#5a8aaa;' + btnCss + '">Grade pasted headers</button>' +
    '</details>' +

    '<div style="color:#4a6a8a;font-size:9px;font-family:monospace;margin-bottom:12px;padding:6px 10px;background:#0a0e1a;border-radius:4px;border:1px solid #1a2a44;">' +
    'Note: Analyze retrieves the real upstream response headers server-side through the Darknode SSRF-guarded proxy (public hosts only). The local agent fetches from your own machine, so it also reaches internal hosts.</div>' +

    '<div id="ha-results" style="background:#080c14;border:1px solid #1a2a44;border-radius:8px;padding:16px;min-height:200px;">' +
    '<div style="color:#3a5a7a;font-size:11px;font-family:monospace;text-align:center;padding:40px;">Enter a URL above to analyze its security headers.</div>' +
    '</div>' +
    '</div>';
  var ag = container.querySelector('#ha-agent');
  if (ag) ag.addEventListener('click', function() { _haAgent(container.querySelector('#ha-input').value); });
  container.querySelector('#ha-paste-go').addEventListener('click', _haPasted);
};

window._haAnalyze = _haAnalyze;
