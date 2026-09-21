// Copyright (c) 2026 Darknode-Official. All rights reserved.
// HTTP Probe — endpoint probing, method testing, header fingerprinting

var esc = function(s) { return String(s != null ? s : '').replace(/[&<>"']/g, function(c) {
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

var _hpSecurityHeaders = [
  { name: 'content-security-policy', label: 'CSP', weight: 3 },
  { name: 'strict-transport-security', label: 'HSTS', weight: 3 },
  { name: 'x-frame-options', label: 'X-Frame-Options', weight: 2 },
  { name: 'x-content-type-options', label: 'X-Content-Type-Options', weight: 2 },
  { name: 'referrer-policy', label: 'Referrer-Policy', weight: 1 },
  { name: 'permissions-policy', label: 'Permissions-Policy', weight: 1 },
  { name: 'x-xss-protection', label: 'X-XSS-Protection', weight: 1 },
  { name: 'cross-origin-opener-policy', label: 'COOP', weight: 1 },
  { name: 'cross-origin-resource-policy', label: 'CORP', weight: 1 },
  { name: 'cross-origin-embedder-policy', label: 'COEP', weight: 1 }
];

var _hpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'];

export function renderHttpProbe(container) {
  var h = '';
  h += '<div style="background:#0a0e14;color:#c8d6e5;font-family:\'Courier New\',monospace;padding:20px;min-height:600px;">';
  h += '<h2 style="color:#00ddff;font-size:18px;letter-spacing:2px;margin:0 0 4px;">HTTP PROBE</h2>';
  h += '<div style="color:#4a6a8a;font-size:11px;margin-bottom:20px;">Endpoint probing, method testing, security header analysis, server fingerprinting</div>';

  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:16px;margin-bottom:16px;">';
  h += '<div style="display:flex;gap:8px;margin-bottom:8px;">';
  h += '<input id="hp-url" style="flex:1;background:#080c14;border:1px solid #1a2a44;border-radius:4px;color:#c8d6e5;font-family:monospace;font-size:12px;padding:8px 12px;" placeholder="https://example.com">';
  h += '<button onclick="_hpProbe()" style="background:#00aaff22;color:#00aaff;border:1px solid #00aaff44;padding:8px 16px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px;">PROBE</button>';
  h += '</div>';
  h += '<div style="color:#ff664480;font-size:9px;">Note: Some sites block cross-origin requests (CORS). Results may be incomplete for those targets.</div>';
  h += '</div>';

  h += '<div id="hp-results"></div>';
  h += '</div>';
  container.innerHTML = h;

  document.getElementById('hp-url').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') _hpProbe();
  });
};

window._hpProbe = function() {
  var url = (document.getElementById('hp-url') || {}).value;
  var results = document.getElementById('hp-results');
  if (!url || !results) return;
  url = url.trim();
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;

  results.innerHTML = '<div style="color:#ffaa00;font-size:11px;padding:16px;text-align:center;">Probing ' + esc(url) + '...</div>';

  var probeResults = { url: url, methods: {}, headers: {}, timing: 0, status: 0, redirects: [], server: null, tech: [] };

  // Main GET request
  var start = performance.now();
  fetch(url, { method: 'GET', mode: 'cors', redirect: 'follow' })
    .then(function(resp) {
      probeResults.timing = Math.round(performance.now() - start);
      probeResults.status = resp.status;
      probeResults.finalUrl = resp.url;
      if (resp.url !== url) probeResults.redirects.push({ from: url, to: resp.url });

      // Extract headers
      resp.headers.forEach(function(value, key) {
        probeResults.headers[key.toLowerCase()] = value;
      });

      // Server fingerprint
      probeResults.server = probeResults.headers['server'] || null;
      var xPowered = probeResults.headers['x-powered-by'];
      if (xPowered) probeResults.tech.push(xPowered);
      var via = probeResults.headers['via'];
      if (via) probeResults.tech.push('Via: ' + via);

      // Test methods
      return _hpTestMethods(url);
    })
    .then(function(methodResults) {
      probeResults.methods = methodResults;
      _hpRenderResults(results, probeResults);
    })
    .catch(function(err) {
      // Try no-cors mode
      var start2 = performance.now();
      fetch(url, { method: 'GET', mode: 'no-cors' })
        .then(function() {
          probeResults.timing = Math.round(performance.now() - start2);
          probeResults.status = 0;
          probeResults.corsBlocked = true;
          _hpTestMethods(url).then(function(mr) { probeResults.methods = mr; _hpRenderResults(results, probeResults); });
        })
        .catch(function(err2) {
          results.innerHTML = '<div style="background:#1a0a0a;border:1px solid #ff224433;border-radius:6px;padding:16px;text-align:center;">' +
            '<div style="color:#ff4444;font-size:12px;font-weight:bold;">PROBE FAILED</div>' +
            '<div style="color:#ff8866;font-size:10px;margin-top:4px;">' + esc(String(err2.message || err)) + '</div></div>';
        });
    });
};

function _hpTestMethods(url) {
  var results = {};
  var promises = [];

  for (var i = 0; i < _hpMethods.length; i++) {
    (function(method) {
      promises.push(
        fetch(url, { method: method, mode: 'cors' })
          .then(function(resp) { results[method] = { status: resp.status, allowed: resp.status < 500 }; })
          .catch(function() { results[method] = { status: 0, allowed: false }; })
      );
    })(_hpMethods[i]);
  }

  return Promise.all(promises).then(function() { return results; });
}

function _hpRenderResults(el, data) {
  var h = '';

  // Overview card
  var statusColor = data.status >= 200 && data.status < 300 ? '#00ff88' : data.status >= 300 && data.status < 400 ? '#ffaa00' : data.status >= 400 ? '#ff4444' : '#4a6a8a';
  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:14px;margin-bottom:12px;">';
  h += '<div style="color:#00ddff;font-size:12px;font-weight:bold;margin-bottom:10px;">PROBE RESULTS</div>';
  h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:8px;">';
  h += '<div style="background:#080c14;border:1px solid #1a2a44;border-radius:3px;padding:6px 8px;text-align:center;">';
  h += '<div style="color:#3a5a7a;font-size:8px;letter-spacing:1px;">STATUS</div>';
  h += '<div style="color:' + statusColor + ';font-size:18px;font-weight:bold;">' + (data.corsBlocked ? 'CORS' : data.status) + '</div></div>';
  h += '<div style="background:#080c14;border:1px solid #1a2a44;border-radius:3px;padding:6px 8px;text-align:center;">';
  h += '<div style="color:#3a5a7a;font-size:8px;letter-spacing:1px;">RESPONSE</div>';
  h += '<div style="color:#00aaff;font-size:18px;font-weight:bold;">' + data.timing + 'ms</div></div>';
  h += '<div style="background:#080c14;border:1px solid #1a2a44;border-radius:3px;padding:6px 8px;text-align:center;">';
  h += '<div style="color:#3a5a7a;font-size:8px;letter-spacing:1px;">SERVER</div>';
  h += '<div style="color:#ffaa00;font-size:11px;font-weight:bold;word-break:break-all;">' + esc(data.server || 'Hidden') + '</div></div>';
  h += '<div style="background:#080c14;border:1px solid #1a2a44;border-radius:3px;padding:6px 8px;text-align:center;">';
  h += '<div style="color:#3a5a7a;font-size:8px;letter-spacing:1px;">TECH</div>';
  h += '<div style="color:#aa66ff;font-size:10px;">' + (data.tech.length > 0 ? esc(data.tech.join(', ')) : 'Unknown') + '</div></div>';
  h += '</div>';
  if (data.corsBlocked) {
    h += '<div style="color:#ff8844;font-size:10px;margin-top:8px;padding:6px;background:#1a120a;border:1px solid #ff884433;border-radius:3px;">&#9888; CORS blocked — headers not accessible. Method testing uses no-cors mode.</div>';
  }
  if (data.redirects.length > 0) {
    h += '<div style="margin-top:8px;font-size:10px;"><span style="color:#4a7a9a;">REDIRECT:</span> <span style="color:#ffaa00;">' + esc(data.redirects[0].from) + '</span> &#8594; <span style="color:#00ff88;">' + esc(data.redirects[0].to) + '</span></div>';
  }
  h += '</div>';

  // HTTP Methods
  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:14px;margin-bottom:12px;">';
  h += '<div style="color:#ffaa00;font-size:12px;font-weight:bold;margin-bottom:10px;">HTTP METHODS</div>';
  h += '<div style="display:flex;flex-wrap:wrap;gap:6px;">';
  for (var m = 0; m < _hpMethods.length; m++) {
    var method = _hpMethods[m];
    var mr = data.methods[method];
    var mColor = mr && mr.allowed ? '#00ff88' : '#ff4444';
    var mStatus = mr ? mr.status : '?';
    h += '<div style="background:' + mColor + '10;border:1px solid ' + mColor + '33;border-radius:4px;padding:6px 12px;text-align:center;min-width:70px;">';
    h += '<div style="color:' + mColor + ';font-weight:bold;font-size:12px;">' + method + '</div>';
    h += '<div style="color:#4a6a8a;font-size:9px;">' + (mr && mr.allowed ? mStatus : 'BLOCKED') + '</div>';
    h += '</div>';
  }
  h += '</div></div>';

  // Security Headers
  if (!data.corsBlocked) {
    var maxScore = 0, score = 0;
    h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:14px;margin-bottom:12px;">';
    h += '<div style="color:#00ff88;font-size:12px;font-weight:bold;margin-bottom:10px;">SECURITY HEADERS</div>';

    for (var s = 0; s < _hpSecurityHeaders.length; s++) {
      var sh = _hpSecurityHeaders[s];
      maxScore += sh.weight;
      var present = !!data.headers[sh.name];
      if (present) score += sh.weight;
      var shColor = present ? '#00ff88' : '#ff4444';
      var shStatus = present ? 'PRESENT' : 'MISSING';
      h += '<div style="display:flex;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid #0d1525;">';
      h += '<span style="color:' + shColor + ';font-size:9px;width:60px;font-weight:bold;padding:1px 6px;background:' + shColor + '15;border:1px solid ' + shColor + '33;border-radius:2px;text-align:center;">' + shStatus + '</span>';
      h += '<span style="color:#c8d6e5;font-size:11px;flex:1;">' + esc(sh.label) + '</span>';
      if (present) h += '<span style="color:#4a6a8a;font-size:9px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + esc(data.headers[sh.name].substring(0, 60)) + '</span>';
      h += '</div>';
    }

    // Grade
    var pct = maxScore > 0 ? Math.round((score / maxScore) * 100) : 0;
    var grade = pct >= 90 ? 'A' : pct >= 75 ? 'B' : pct >= 50 ? 'C' : pct >= 25 ? 'D' : 'F';
    var gradeColor = pct >= 75 ? '#00ff88' : pct >= 50 ? '#ffaa00' : '#ff4444';
    h += '<div style="margin-top:10px;text-align:center;padding:8px;border-top:1px solid #1a2a44;">';
    h += '<span style="font-size:28px;font-weight:bold;color:' + gradeColor + ';text-shadow:0 0 12px ' + gradeColor + '40;">' + grade + '</span>';
    h += '<div style="color:#4a6a8a;font-size:9px;">SECURITY GRADE (' + score + '/' + maxScore + ')</div>';
    h += '</div>';
    h += '</div>';

    // All response headers
    h += '<details style="margin-bottom:12px;">';
    h += '<summary style="color:#4a6a8a;font-size:11px;cursor:pointer;background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:8px 14px;">All Response Headers (' + Object.keys(data.headers).length + ')</summary>';
    h += '<div style="background:#080c14;border:1px solid #1a2a44;border-radius:0 0 6px 6px;padding:10px;max-height:250px;overflow-y:auto;">';
    var hKeys = Object.keys(data.headers).sort();
    for (var hk = 0; hk < hKeys.length; hk++) {
      h += '<div style="margin:2px 0;font-size:10px;word-break:break-all;"><span style="color:#00aaff;">' + esc(hKeys[hk]) + ':</span> <span style="color:#8ab4d4;">' + esc(data.headers[hKeys[hk]]) + '</span></div>';
    }
    h += '</div></details>';
  }

  el.innerHTML = h;
}
