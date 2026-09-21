// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Technology Fingerprinter — identify web technologies from response headers and content

var esc = function(s) { return String(s != null ? s : '').replace(/[&<>"']/g, function(c) {
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

var _tfSignatures = [
  { name: 'Nginx', category: 'Web Server', detect: function(h) { return (h.get('server') || '').toLowerCase().indexOf('nginx') !== -1; }, color: '#00aa44' },
  { name: 'Apache', category: 'Web Server', detect: function(h) { return (h.get('server') || '').toLowerCase().indexOf('apache') !== -1; }, color: '#cc2222' },
  { name: 'IIS', category: 'Web Server', detect: function(h) { return (h.get('server') || '').toLowerCase().indexOf('microsoft-iis') !== -1; }, color: '#0078d4' },
  { name: 'Cloudflare', category: 'CDN/WAF', detect: function(h) { return h.has('cf-ray') || (h.get('server') || '').toLowerCase().indexOf('cloudflare') !== -1; }, color: '#f48120' },
  { name: 'AWS CloudFront', category: 'CDN', detect: function(h) { return h.has('x-amz-cf-id') || h.has('x-amz-cf-pop'); }, color: '#ff9900' },
  { name: 'Akamai', category: 'CDN', detect: function(h) { return h.has('x-akamai-transformed') || (h.get('server') || '').indexOf('AkamaiGHost') !== -1; }, color: '#009bdb' },
  { name: 'Fastly', category: 'CDN', detect: function(h) { return h.has('x-served-by') && h.has('x-cache') && h.has('x-timer'); }, color: '#ff282d' },
  { name: 'Varnish', category: 'Cache', detect: function(h) { return h.has('x-varnish') || (h.get('via') || '').indexOf('varnish') !== -1; }, color: '#00bcd4' },
  { name: 'PHP', category: 'Language', detect: function(h) { return (h.get('x-powered-by') || '').toLowerCase().indexOf('php') !== -1; }, color: '#777bb3' },
  { name: 'ASP.NET', category: 'Framework', detect: function(h) { return (h.get('x-powered-by') || '').toLowerCase().indexOf('asp.net') !== -1 || h.has('x-aspnet-version'); }, color: '#512bd4' },
  { name: 'Express', category: 'Framework', detect: function(h) { return (h.get('x-powered-by') || '').toLowerCase().indexOf('express') !== -1; }, color: '#333333' },
  { name: 'Django', category: 'Framework', detect: function(h) { return h.has('x-frame-options') && (h.get('content-type') || '').indexOf('csrfmiddlewaretoken') !== -1; }, color: '#092e20' },
  { name: 'Firebase', category: 'Platform', detect: function(h) { return (h.get('server') || '').indexOf('Google Frontend') !== -1 || h.has('x-cloud-trace-context'); }, color: '#ffca28' },
  { name: 'Vercel', category: 'Platform', detect: function(h) { return h.has('x-vercel-id') || (h.get('server') || '').indexOf('Vercel') !== -1; }, color: '#000000' },
  { name: 'Netlify', category: 'Platform', detect: function(h) { return h.has('x-nf-request-id') || (h.get('server') || '').indexOf('Netlify') !== -1; }, color: '#00c7b7' },
  { name: 'WordPress', category: 'CMS', detect: function(h) { return (h.get('link') || '').indexOf('wp-json') !== -1 || (h.get('x-powered-by') || '').indexOf('WordPress') !== -1; }, color: '#21759b' },
  { name: 'Shopify', category: 'CMS', detect: function(h) { return h.has('x-shopid') || (h.get('x-powered-by') || '').indexOf('Shopify') !== -1; }, color: '#96bf48' },
  { name: 'Next.js', category: 'Framework', detect: function(h) { return h.has('x-nextjs-cache') || h.has('x-nextjs-matched-path'); }, color: '#000000' },
  { name: 'HSTS Enabled', category: 'Security', detect: function(h) { return h.has('strict-transport-security'); }, color: '#00ff88' },
  { name: 'CSP Enabled', category: 'Security', detect: function(h) { return h.has('content-security-policy'); }, color: '#00cc66' }
];

export function renderTechFingerprint(container) {
  var h = '';
  h += '<div style="background:#0a0e14;color:#c8d6e5;font-family:\'Courier New\',monospace;padding:20px;min-height:500px;">';
  h += '<h2 style="color:#00ddff;font-size:18px;letter-spacing:2px;margin:0 0 4px;">TECHNOLOGY FINGERPRINTER</h2>';
  h += '<div style="color:#4a6a8a;font-size:11px;margin-bottom:20px;">Identify web technologies, servers, CDNs, frameworks, and security configurations</div>';

  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:16px;margin-bottom:16px;">';
  h += '<div style="display:flex;gap:8px;">';
  h += '<input id="tf-url" style="flex:1;background:#080c14;border:1px solid #1a2a44;border-radius:4px;color:#c8d6e5;font-family:monospace;font-size:12px;padding:8px 12px;" placeholder="https://example.com">';
  h += '<button onclick="_tfScan()" style="background:#00aaff22;color:#00aaff;border:1px solid #00aaff44;padding:8px 20px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px;">FINGERPRINT</button>';
  h += '</div>';
  h += '<div style="color:#3a5a7a;font-size:9px;margin-top:6px;">Analyzes HTTP response headers to detect technologies. Limited by CORS — works best with sites that allow cross-origin requests.</div>';
  h += '</div>';

  h += '<div id="tf-results"></div>';

  // Signature database reference
  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:14px;margin-top:16px;">';
  h += '<div style="color:#00aaff;font-size:12px;font-weight:bold;margin-bottom:10px;">DETECTION SIGNATURES (' + _tfSignatures.length + ')</div>';
  h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:4px;">';
  for (var s = 0; s < _tfSignatures.length; s++) {
    var sig = _tfSignatures[s];
    h += '<div style="background:#080c14;border:1px solid #1a2a44;border-radius:3px;padding:4px 8px;font-size:9px;display:flex;align-items:center;gap:6px;">';
    h += '<span style="width:6px;height:6px;border-radius:50%;background:' + sig.color + ';flex-shrink:0;"></span>';
    h += '<span style="color:#c8d6e5;">' + esc(sig.name) + '</span>';
    h += '<span style="color:#3a5a7a;margin-left:auto;">' + esc(sig.category) + '</span>';
    h += '</div>';
  }
  h += '</div></div>';

  h += '</div>';
  container.innerHTML = h;
};

window._tfScan = function() {
  var url = (document.getElementById('tf-url') || {}).value;
  var results = document.getElementById('tf-results');
  if (!url || !results) return;
  if (!/^https?:\/\//.test(url)) url = 'https://' + url;

  results.innerHTML = '<div style="color:#ffaa00;font-size:11px;padding:16px;text-align:center;">Fingerprinting ' + esc(url) + '...</div>';

  var start = performance.now();

  fetch(url, { mode: 'cors', redirect: 'follow' })
    .then(function(resp) {
      var elapsed = Math.round(performance.now() - start);
      var detected = [];
      var headerDump = [];

      resp.headers.forEach(function(value, key) {
        headerDump.push({ key: key, value: value });
      });

      for (var i = 0; i < _tfSignatures.length; i++) {
        try {
          if (_tfSignatures[i].detect(resp.headers)) {
            detected.push(_tfSignatures[i]);
          }
        } catch (e) {}
      }

      var h = '';

      // Summary
      h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:16px;margin-bottom:12px;">';
      h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">';
      h += '<div>';
      h += '<div style="color:#00ddff;font-size:14px;font-weight:bold;">' + esc(url) + '</div>';
      h += '<div style="color:#4a6a8a;font-size:10px;margin-top:2px;">Status: ' + resp.status + ' | Time: ' + elapsed + 'ms | Technologies: ' + detected.length + '</div>';
      h += '</div>';
      h += '</div>';

      if (detected.length > 0) {
        h += '<div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px;">';
        for (var d = 0; d < detected.length; d++) {
          var tech = detected[d];
          h += '<div style="background:' + tech.color + '18;border:1px solid ' + tech.color + '44;border-radius:4px;padding:6px 12px;display:flex;align-items:center;gap:6px;">';
          h += '<span style="width:8px;height:8px;border-radius:50%;background:' + tech.color + ';"></span>';
          h += '<span style="color:#c8d6e5;font-size:12px;font-weight:bold;">' + esc(tech.name) + '</span>';
          h += '<span style="color:#6a8aaa;font-size:9px;">' + esc(tech.category) + '</span>';
          h += '</div>';
        }
        h += '</div>';
      } else {
        h += '<div style="color:#ffaa00;font-size:11px;margin-bottom:10px;">No technologies detected from headers. The site may block cross-origin requests or not expose identifying headers.</div>';
      }

      // Server info
      var server = resp.headers.get('server');
      var poweredBy = resp.headers.get('x-powered-by');
      if (server || poweredBy) {
        h += '<div style="padding:8px;background:#080c14;border-radius:4px;margin-bottom:10px;font-size:11px;">';
        if (server) h += '<div><span style="color:#4a7a9a;">Server:</span> <span style="color:#00ff88;">' + esc(server) + '</span></div>';
        if (poweredBy) h += '<div><span style="color:#4a7a9a;">X-Powered-By:</span> <span style="color:#ffaa00;">' + esc(poweredBy) + '</span></div>';
        h += '</div>';
      }

      // All headers
      h += '<details>';
      h += '<summary style="color:#4a6a8a;font-size:10px;cursor:pointer;margin-top:8px;">All response headers (' + headerDump.length + ')</summary>';
      h += '<div style="background:#060a10;border:1px solid #0d1525;border-radius:4px;padding:8px;margin-top:4px;max-height:250px;overflow-y:auto;">';
      for (var hi = 0; hi < headerDump.length; hi++) {
        h += '<div style="font-size:10px;margin:2px 0;word-break:break-all;"><span style="color:#00aaff;">' + esc(headerDump[hi].key) + ':</span> <span style="color:#8ab4d4;">' + esc(headerDump[hi].value) + '</span></div>';
      }
      h += '</div></details>';

      h += '</div>';
      results.innerHTML = h;
    })
    .catch(function(err) {
      var elapsed = Math.round(performance.now() - start);
      results.innerHTML =
        '<div style="background:#1a0a0a;border:1px solid #ff444433;border-radius:6px;padding:16px;text-align:center;">' +
        '<div style="color:#ff4444;font-size:14px;font-weight:bold;">CORS BLOCKED</div>' +
        '<div style="color:#6a4a4a;font-size:10px;margin-top:4px;">' + esc(String(err.message || err)) + '</div>' +
        '<div style="color:#4a6a8a;font-size:10px;margin-top:8px;">This site blocks cross-origin requests. Try sites with open CORS policies (APIs, public services).</div>' +
        '</div>';
    });
};
