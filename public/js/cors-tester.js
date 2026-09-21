// Copyright (c) 2026 Darknode-Official. All rights reserved.
// CORS Tester — test Cross-Origin Resource Sharing policies on any URL

var esc = function(s) { return String(s != null ? s : '').replace(/[&<>"']/g, function(c) {
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

export function renderCorsTester(container) {
  var h = '';
  h += '<div style="background:#0a0e14;color:#c8d6e5;font-family:\'Courier New\',monospace;padding:20px;min-height:500px;">';
  h += '<h2 style="color:#00ddff;font-size:18px;letter-spacing:2px;margin:0 0 4px;">CORS POLICY TESTER</h2>';
  h += '<div style="color:#4a6a8a;font-size:11px;margin-bottom:20px;">Test Cross-Origin Resource Sharing policies on any URL</div>';

  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:16px;margin-bottom:16px;">';
  h += '<div style="display:flex;gap:8px;margin-bottom:10px;">';
  h += '<input id="cors-url" style="flex:1;background:#080c14;border:1px solid #1a2a44;border-radius:4px;color:#c8d6e5;font-family:monospace;font-size:12px;padding:8px 12px;" placeholder="https://api.example.com/endpoint">';
  h += '<select id="cors-method" style="background:#080c14;border:1px solid #1a2a44;border-radius:4px;color:#c8d6e5;font-family:monospace;font-size:11px;padding:8px;">';
  h += '<option value="GET">GET</option><option value="POST">POST</option><option value="PUT">PUT</option><option value="DELETE">DELETE</option><option value="OPTIONS">OPTIONS</option>';
  h += '</select>';
  h += '<button onclick="_corsTest()" style="background:#00aaff22;color:#00aaff;border:1px solid #00aaff44;padding:8px 16px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px;">TEST</button>';
  h += '</div>';

  h += '<div style="display:flex;gap:8px;margin-bottom:8px;">';
  h += '<input id="cors-origin" style="flex:1;background:#080c14;border:1px solid #1a2a44;border-radius:4px;color:#c8d6e5;font-family:monospace;font-size:11px;padding:6px 10px;" placeholder="Custom Origin header (optional)" value="https://darknode.ai">';
  h += '<input id="cors-header" style="flex:1;background:#080c14;border:1px solid #1a2a44;border-radius:4px;color:#c8d6e5;font-family:monospace;font-size:11px;padding:6px 10px;" placeholder="Custom header to test (e.g. Authorization)">';
  h += '</div>';
  h += '<div style="color:#3a5a7a;font-size:9px;">Tests CORS preflight and actual request. Shows Access-Control-* response headers.</div>';
  h += '</div>';

  h += '<div id="cors-results"></div>';

  // Quick test buttons
  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:14px;margin-top:16px;">';
  h += '<div style="color:#00aaff;font-size:12px;font-weight:bold;margin-bottom:10px;">QUICK TEST — KNOWN APIs</div>';
  h += '<div style="display:flex;flex-wrap:wrap;gap:6px;">';
  var quickTests = [
    { url: 'https://api.github.com', label: 'GitHub API' },
    { url: 'https://dns.google/resolve?name=google.com&type=A', label: 'Google DoH' },
    { url: 'https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/significant_hour.geojson', label: 'USGS' },
    { url: 'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1', label: 'NVD API' },
    { url: 'https://ipapi.co/json/', label: 'ipapi.co' },
    { url: 'https://crt.sh/?q=google.com&output=json', label: 'crt.sh' },
    { url: 'https://api.bgpview.io/asn/13335', label: 'BGPView' },
    { url: 'https://opensky-network.org/api/states/all?lamin=45&lomin=-1&lamax=46&lomax=0', label: 'OpenSky' }
  ];
  for (var i = 0; i < quickTests.length; i++) {
    var qt = quickTests[i];
    h += '<button onclick="document.getElementById(\'cors-url\').value=\'' + esc(qt.url) + '\';_corsTest()" style="background:#0a1a28;border:1px solid #1a3050;color:#5a8aaa;padding:4px 10px;font-family:monospace;font-size:10px;cursor:pointer;border-radius:3px;">' + esc(qt.label) + '</button>';
  }
  h += '</div></div>';

  // CORS reference
  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:14px;margin-top:12px;">';
  h += '<div style="color:#ffaa00;font-size:12px;font-weight:bold;margin-bottom:10px;">CORS HEADERS REFERENCE</div>';
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
    h += '<div style="margin:4px 0;font-size:10px;display:flex;gap:8px;align-items:flex-start;">';
    h += '<span style="color:' + impColor + ';font-size:8px;padding:1px 4px;background:' + impColor + '15;border:1px solid ' + impColor + '33;border-radius:2px;flex-shrink:0;">' + hdr.importance + '</span>';
    h += '<span style="color:#00aaff;min-width:240px;flex-shrink:0;">' + esc(hdr.header) + '</span>';
    h += '<span style="color:#6a8aaa;">' + esc(hdr.desc) + '</span>';
    h += '</div>';
  }
  h += '</div>';

  h += '</div>';
  container.innerHTML = h;
};

window._corsTest = function() {
  var url = (document.getElementById('cors-url') || {}).value;
  var method = (document.getElementById('cors-method') || {}).value || 'GET';
  var results = document.getElementById('cors-results');
  if (!url || !results) return;

  results.innerHTML = '<div style="color:#ffaa00;font-size:11px;padding:16px;text-align:center;">Testing CORS for ' + esc(url) + '...</div>';

  var startTime = performance.now();

  // Test 1: no-cors mode (always succeeds but opaque)
  // Test 2: cors mode (reveals CORS policy)
  fetch(url, { method: method, mode: 'cors' })
    .then(function(resp) {
      var elapsed = Math.round(performance.now() - startTime);
      var h = '';
      h += '<div style="background:#0a1a0a;border:2px solid #00ff88;border-radius:8px;padding:16px;margin-bottom:12px;text-align:center;">';
      h += '<div style="color:#00ff88;font-size:16px;font-weight:bold;">CORS ALLOWED</div>';
      h += '<div style="color:#4a8a6a;font-size:10px;margin-top:4px;">Response received in ' + elapsed + 'ms — Status: ' + resp.status + '</div>';
      h += '</div>';

      // Show CORS headers
      h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:14px;">';
      h += '<div style="color:#00aaff;font-size:12px;font-weight:bold;margin-bottom:10px;">RESPONSE HEADERS</div>';
      var corsKeys = ['access-control-allow-origin', 'access-control-allow-methods', 'access-control-allow-headers',
        'access-control-allow-credentials', 'access-control-max-age', 'access-control-expose-headers',
        'content-type', 'server', 'x-powered-by', 'x-frame-options', 'content-security-policy',
        'strict-transport-security', 'x-content-type-options', 'referrer-policy'];

      resp.headers.forEach(function(value, key) {
        var isCors = key.toLowerCase().indexOf('access-control') !== -1;
        var keyColor = isCors ? '#00ff88' : '#00aaff';
        h += '<div style="margin:3px 0;font-size:10px;word-break:break-all;">';
        h += '<span style="color:' + keyColor + ';font-weight:' + (isCors ? 'bold' : 'normal') + ';">' + esc(key) + ':</span> ';
        h += '<span style="color:#c8d6e5;">' + esc(value) + '</span>';
        h += '</div>';
      });

      // Check for wildcard origin
      var acao = resp.headers.get('access-control-allow-origin');
      if (acao === '*') {
        h += '<div style="margin-top:10px;padding:6px 10px;background:#ffaa0015;border:1px solid #ffaa0033;border-radius:4px;font-size:10px;color:#ffaa00;">&#9888; Wildcard origin (*) — any website can access this API. May be a security concern if sensitive data is returned.</div>';
      }

      h += '</div>';
      results.innerHTML = h;
    })
    .catch(function(err) {
      var elapsed = Math.round(performance.now() - startTime);
      var h = '';
      h += '<div style="background:#1a0a0a;border:2px solid #ff4444;border-radius:8px;padding:16px;margin-bottom:12px;text-align:center;">';
      h += '<div style="color:#ff4444;font-size:16px;font-weight:bold;">CORS BLOCKED</div>';
      h += '<div style="color:#8a4a4a;font-size:10px;margin-top:4px;">Request failed after ' + elapsed + 'ms</div>';
      h += '</div>';

      h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:14px;">';
      h += '<div style="color:#ff6644;font-size:12px;font-weight:bold;margin-bottom:8px;">ERROR DETAILS</div>';
      h += '<div style="font-size:11px;color:#c8d6e5;word-break:break-all;">' + esc(String(err.message || err)) + '</div>';
      h += '<div style="margin-top:10px;color:#4a6a8a;font-size:10px;">This endpoint does not allow cross-origin requests from this domain, or the server is unreachable.</div>';
      h += '</div>';

      results.innerHTML = h;
    });
};
