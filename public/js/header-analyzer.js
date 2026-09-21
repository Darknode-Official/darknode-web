// Copyright (c) 2026 Darknode-Official. All rights reserved.
// HTTP Security Header Analyzer — checks security headers of any CORS-enabled URL
// Grades headers A-F and provides recommendations

var esc = function(s) { return String(s != null ? s : '').replace(/[&<>"']/g, function(c) { return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

var _haSecurityHeaders = [
  { name: 'Content-Security-Policy', weight: 20, critical: true, desc: 'Controls which resources the browser can load. Prevents XSS, data injection, clickjacking.', rec: 'Add a strict CSP: default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:; object-src \'none\'; base-uri \'self\'; form-action \'self\'' },
  { name: 'Strict-Transport-Security', weight: 15, critical: true, desc: 'Forces HTTPS connections. Prevents SSL stripping attacks.', rec: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload', weak: function(v) { return v && parseInt(v.replace(/.*max-age=(\d+).*/, '$1'), 10) < 31536000; } },
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

async function _haAnalyze(url) {
  var resultsEl = document.getElementById('ha-results');
  if (!resultsEl) return;
  url = url.trim();
  if (!url) { resultsEl.innerHTML = '<div style="color:#ff4444;font-family:monospace;font-size:11px;padding:16px;">Enter a URL to analyze.</div>'; return; }
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;

  resultsEl.innerHTML = '<div style="text-align:center;padding:30px;color:#00aaff;font-family:monospace;font-size:12px;">Analyzing headers for <b>' + esc(url) + '</b>...</div>';

  try {
    var resp = await fetch(url, { method: 'HEAD', mode: 'cors' }).catch(function() {
      return fetch(url, { method: 'GET', mode: 'cors' });
    });

    var headers = {};
    resp.headers.forEach(function(value, key) { headers[key.toLowerCase()] = value; });

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

    // Check for dangerous headers
    var serverHeader = headers['server'] || null;
    var poweredBy = headers['x-powered-by'] || null;

    var score = Math.round((earnedWeight / totalWeight) * 100);
    var grade = _haGradeFromScore(score);

    // HTTPS check
    var isHTTPS = url.toLowerCase().indexOf('https://') === 0;
    if (!isHTTPS) { score = Math.max(0, score - 20); grade = _haGradeFromScore(score); }

    var h = '';

    // Grade card
    h += '<div style="display:flex;gap:16px;margin-bottom:20px;align-items:center;">';
    h += '<div style="width:100px;height:100px;border-radius:12px;border:3px solid ' + grade.color + ';display:flex;flex-direction:column;align-items:center;justify-content:center;background:rgba(0,0,0,0.3);">';
    h += '<div style="font-size:42px;font-weight:bold;color:' + grade.color + ';font-family:monospace;line-height:1;">' + grade.grade + '</div>';
    h += '<div style="font-size:9px;color:' + grade.color + ';font-family:monospace;letter-spacing:1px;">' + grade.label + '</div>';
    h += '</div>';
    h += '<div style="flex:1;">';
    h += '<div style="font-size:14px;color:#c8d6e5;font-family:monospace;font-weight:bold;margin-bottom:4px;">' + esc(url) + '</div>';
    h += '<div style="font-size:11px;color:#4a6a8a;font-family:monospace;">Score: ' + score + '/100 | Headers checked: ' + _haSecurityHeaders.length + '</div>';
    if (!isHTTPS) h += '<div style="color:#ff4444;font-size:11px;font-family:monospace;margin-top:4px;">WARNING: Not using HTTPS (-20 points)</div>';
    if (serverHeader) h += '<div style="color:#ffaa00;font-size:10px;font-family:monospace;margin-top:2px;">Server: ' + esc(serverHeader) + ' (consider hiding this)</div>';
    if (poweredBy) h += '<div style="color:#ffaa00;font-size:10px;font-family:monospace;">X-Powered-By: ' + esc(poweredBy) + ' (REMOVE THIS — reveals technology stack)</div>';
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

    // Raw headers dump
    h += '<div style="margin-top:16px;">';
    h += '<div style="color:#4a6a8a;font-size:10px;font-family:monospace;letter-spacing:2px;margin-bottom:6px;cursor:pointer;" onclick="var el=document.getElementById(\'ha-raw\');el.hidden=!el.hidden;">ALL RESPONSE HEADERS [TOGGLE]</div>';
    h += '<div id="ha-raw" hidden style="background:#0a0e1a;border:1px solid #1a2a44;border-radius:6px;padding:10px;max-height:300px;overflow-y:auto;">';
    var hdrKeys = [];
    resp.headers.forEach(function(v, k) { hdrKeys.push(k); });
    hdrKeys.sort();
    for (var hi = 0; hi < hdrKeys.length; hi++) {
      h += '<div style="font-family:monospace;font-size:10px;padding:2px 0;border-bottom:1px solid #0d1525;">';
      h += '<span style="color:#00aaff;">' + esc(hdrKeys[hi]) + ':</span> <span style="color:#c8d6e5;">' + esc(headers[hdrKeys[hi].toLowerCase()]) + '</span>';
      h += '</div>';
    }
    h += '</div></div>';

    resultsEl.innerHTML = h;

  } catch (e) {
    resultsEl.innerHTML =
      '<div style="background:#1a0a0a;border:1px solid #ff444444;border-radius:8px;padding:20px;text-align:center;">' +
      '<div style="color:#ff4444;font-size:14px;font-family:monospace;font-weight:bold;margin-bottom:8px;">ANALYSIS FAILED</div>' +
      '<div style="color:#8ab4d4;font-size:11px;font-family:monospace;margin-bottom:8px;">' + esc(e.message || 'Request blocked') + '</div>' +
      '<div style="color:#4a6a8a;font-size:10px;font-family:monospace;">This usually means the target blocks cross-origin requests (CORS). ' +
      'The analysis only works for sites that allow CORS. Try sites like github.com, google.com, or your own.</div>' +
      '</div>';
  }
}

export function renderHeaderAnalyzer(container) {
  container.innerHTML =
    '<div style="padding:20px 24px;max-width:1000px;margin:0 auto;">' +
    '<h2 style="margin:0 0 4px;font-size:20px;color:#00aaff;font-family:monospace;letter-spacing:2px;text-transform:uppercase;">HTTP SECURITY HEADERS</h2>' +
    '<div style="color:#4a6a8a;font-size:11px;font-family:monospace;margin-bottom:16px;">Analyze any URL for security header compliance — grades A through F</div>' +

    '<div style="display:flex;gap:8px;margin-bottom:12px;">' +
    '<input id="ha-input" type="text" placeholder="Enter URL (e.g. https://github.com)" ' +
    'style="flex:1;background:#0a0e1a;border:1px solid #1a2a44;border-radius:6px;padding:10px 14px;color:#c8d6e5;font-family:monospace;font-size:13px;outline:none;" ' +
    'onkeydown="if(event.key===\'Enter\')_haAnalyze(this.value)">' +
    '<button onclick="_haAnalyze(document.getElementById(\'ha-input\').value)" ' +
    'style="background:linear-gradient(135deg,#00aaff22,#00aaff11);border:1px solid #00aaff66;border-radius:6px;padding:10px 20px;color:#00ddff;font-family:monospace;font-size:12px;font-weight:bold;cursor:pointer;letter-spacing:1px;">ANALYZE</button>' +
    '</div>' +

    '<div style="display:flex;gap:6px;margin-bottom:16px;flex-wrap:wrap;">' +
    '<span style="color:#3a5a7a;font-size:10px;font-family:monospace;line-height:26px;">TEST:</span>' +
    ['https://github.com', 'https://google.com', 'https://cloudflare.com', 'https://darknode.ai'].map(function(u) {
      return '<button onclick="document.getElementById(\'ha-input\').value=\'' + u + '\';_haAnalyze(\'' + u + '\')" ' +
        'style="background:#0a1a28;border:1px solid #1a3050;color:#5a8aaa;padding:3px 10px;font-size:10px;font-family:monospace;cursor:pointer;border-radius:3px;">' + esc(u.replace('https://', '')) + '</button>';
    }).join('') +
    '</div>' +

    '<div style="color:#4a6a8a;font-size:9px;font-family:monospace;margin-bottom:12px;padding:6px 10px;background:#0a0e1a;border-radius:4px;border:1px solid #1a2a44;">' +
    'Note: Analysis works for CORS-enabled sites only. Sites that block cross-origin requests will show an error. ' +
    'All checks run entirely in your browser — no data is sent to any server.</div>' +

    '<div id="ha-results" style="background:#080c14;border:1px solid #1a2a44;border-radius:8px;padding:16px;min-height:200px;">' +
    '<div style="color:#3a5a7a;font-size:11px;font-family:monospace;text-align:center;padding:40px;">Enter a URL above to analyze its security headers.</div>' +
    '</div>' +
    '</div>';
};

window._haAnalyze = _haAnalyze;
