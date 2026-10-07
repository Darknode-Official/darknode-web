// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved.
// Technology Fingerprinter — identify web technologies from the REAL response
// headers and body. Requests go through the Darknode SSRF-guarded /api/fetch
// proxy so the genuine upstream headers and HTML can be inspected (browser CORS
// cannot read them). No fabricated detections — only what the response proves.

import { dnFetch, proxyConfigured } from '/js/net.js';

var esc = function(s) { return String(s != null ? s : '').replace(/[&<>"']/g, function(c) {
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

// Wrap the proxy's plain header object in a Headers-like accessor so the header
// signatures below can use .get()/.has() exactly as with a real Headers object.
function _tfHeaders(obj) {
  var low = {};
  Object.keys(obj || {}).forEach(function(k) { low[k.toLowerCase()] = obj[k]; });
  return {
    get: function(k) { var v = low[String(k).toLowerCase()]; return v == null ? '' : v; },
    has: function(k) { return low[String(k).toLowerCase()] != null; },
    entries: low
  };
}

// Body-marker signatures — matched against the real returned HTML/JS.
var _tfBodySignatures = [
  { name: 'WordPress', category: 'CMS', color: '#21759b', test: function(b) { return /\/wp-content\/|\/wp-includes\/|\/wp-json\//.test(b); } },
  { name: 'Drupal', category: 'CMS', color: '#0678be', test: function(b) { return /Drupal\.settings|\/sites\/(all|default)\/|drupal\.js/.test(b); } },
  { name: 'Joomla', category: 'CMS', color: '#5091cd', test: function(b) { return /\/media\/jui\/|Joomla!|option=com_/.test(b); } },
  { name: 'Shopify', category: 'CMS', color: '#96bf48', test: function(b) { return /cdn\.shopify\.com|Shopify\.theme|myshopify\.com/.test(b); } },
  { name: 'Next.js', category: 'Framework', color: '#111111', test: function(b) { return /__NEXT_DATA__|\/_next\/static\//.test(b); } },
  { name: 'Nuxt.js', category: 'Framework', color: '#00c58e', test: function(b) { return /__NUXT__|\/_nuxt\//.test(b); } },
  { name: 'React', category: 'JS Library', color: '#61dafb', test: function(b) { return /data-reactroot|react-dom(\.production)?(\.min)?\.js/.test(b); } },
  { name: 'Vue.js', category: 'JS Library', color: '#42b883', test: function(b) { return /data-v-[0-9a-f]{8}|vue(\.runtime)?(\.min)?\.js|__vue__/.test(b); } },
  { name: 'Angular', category: 'Framework', color: '#dd0031', test: function(b) { return /ng-version=|ng-app=|angular(\.min)?\.js/.test(b); } },
  { name: 'Svelte', category: 'Framework', color: '#ff3e00', test: function(b) { return /svelte-[0-9a-z]{6}/.test(b); } },
  { name: 'jQuery', category: 'JS Library', color: '#0769ad', test: function(b) { return /jquery(-\d[\d.]*)?(\.slim)?(\.min)?\.js/i.test(b); } },
  { name: 'Bootstrap', category: 'UI Framework', color: '#7952b3', test: function(b) { return /bootstrap(\.bundle)?(\.min)?\.(css|js)/i.test(b); } },
  { name: 'Tailwind CSS', category: 'UI Framework', color: '#38bdf8', test: function(b) { return /tailwind(css)?(\.min)?\.css|(?:^|["\s])(?:tw-)?(?:flex|grid)\s/.test(b) && /--tw-/.test(b); } },
  { name: 'Google Analytics', category: 'Analytics', color: '#e37400', test: function(b) { return /google-analytics\.com\/(ga|analytics)\.js|gtag\(|www\.googletagmanager\.com\/gtag/.test(b); } },
  { name: 'Google Tag Manager', category: 'Analytics', color: '#246fdb', test: function(b) { return /googletagmanager\.com\/gtm\.js|GTM-[A-Z0-9]+/.test(b); } },
  { name: 'Cloudflare Turnstile', category: 'Security', color: '#f48120', test: function(b) { return /challenges\.cloudflare\.com\/turnstile/.test(b); } }
];

function _tfExtractGenerator(body) {
  var m = /<meta[^>]+name=["']generator["'][^>]*content=["']([^"']+)["']/i.exec(body) ||
          /<meta[^>]+content=["']([^"']+)["'][^>]*name=["']generator["']/i.exec(body);
  return m ? m[1] : '';
}

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
  // "csrfmiddlewaretoken" is a Django HTML form field, never a Content-Type
  // value (RFC 9110 §8.3), so the old test could never fire. Key off Django's
  // distinctive csrftoken cookie instead (readable when Set-Cookie is exposed).
  { name: 'Django', category: 'Framework', detect: function(h) { return (h.get('set-cookie') || '').toLowerCase().indexOf('csrftoken') !== -1; }, color: '#092e20' },
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
  h += '<button onclick="_tfScan()" style="background:#00aaff22;color:#00aaff;border:1px solid #00aaff44;padding:8px 20px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px;">Fingerprint</button>';
  h += '</div>';
  h += '<div style="color:#3a5a7a;font-size:9px;margin-top:6px;">Fetches the target server-side through the Darknode SSRF-guarded proxy and fingerprints technologies from the real response headers and HTML body. Public hosts only.</div>';
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

window._tfScan = async function() {
  var url = (document.getElementById('tf-url') || {}).value;
  var results = document.getElementById('tf-results');
  if (!url || !results) return;
  url = url.trim();
  if (!/^https?:\/\//.test(url)) url = 'https://' + url;

  if (!proxyConfigured()) {
    results.innerHTML =
      '<div style="background:#1a0a0a;border:1px solid #ff444433;border-radius:6px;padding:16px;text-align:center;">' +
      '<div style="color:#ff4444;font-size:14px;font-weight:bold;">LIVE FINGERPRINT UNAVAILABLE</div>' +
      '<div style="color:#4a6a8a;font-size:10px;margin-top:8px;">The Darknode fetch proxy is not configured, so real headers and content cannot be retrieved. No detections are fabricated.</div>' +
      '</div>';
    return;
  }

  results.innerHTML = '<div style="color:#ffaa00;font-size:11px;padding:16px;text-align:center;">Fingerprinting ' + esc(url) + '...</div>';

  var start = performance.now();

  try {
    var resp = await dnFetch(url, { redirect: 'manual' });
    var elapsed = Math.round(performance.now() - start);
    var hdr = _tfHeaders(resp.headers);
    var body = resp.body || '';
    var detected = [];
    var seen = {};
    function add(sig) { if (!seen[sig.name]) { seen[sig.name] = 1; detected.push(sig); } }

    for (var i = 0; i < _tfSignatures.length; i++) {
      try { if (_tfSignatures[i].detect(hdr)) add(_tfSignatures[i]); } catch (e) {}
    }
    for (var j = 0; j < _tfBodySignatures.length; j++) {
      try { if (_tfBodySignatures[j].test(body)) add(_tfBodySignatures[j]); } catch (e) {}
    }

    var generator = _tfExtractGenerator(body);
    var headerKeys = Object.keys(resp.headers || {}).sort();

    var h = '';

    // Summary
    h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:16px;margin-bottom:12px;">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">';
    h += '<div>';
    h += '<div style="color:#00ddff;font-size:14px;font-weight:bold;">' + esc(resp.finalUrl || url) + '</div>';
    h += '<div style="color:#4a6a8a;font-size:10px;margin-top:2px;">Status: ' + esc(String(resp.status)) + ' | Time: ' + elapsed + 'ms | Technologies: ' + detected.length + (resp.truncated ? ' | body truncated' : '') + '</div>';
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
      h += '<div style="color:#ffaa00;font-size:11px;margin-bottom:10px;">No known technologies matched the real response headers or body. The site may not expose identifying markers.</div>';
    }

    // Server info
    var server = hdr.get('server');
    var poweredBy = hdr.get('x-powered-by');
    if (server || poweredBy || generator) {
      h += '<div style="padding:8px;background:#080c14;border-radius:4px;margin-bottom:10px;font-size:11px;">';
      if (server) h += '<div><span style="color:#4a7a9a;">Server:</span> <span style="color:#00ff88;">' + esc(server) + '</span></div>';
      if (poweredBy) h += '<div><span style="color:#4a7a9a;">X-Powered-By:</span> <span style="color:#ffaa00;">' + esc(poweredBy) + '</span></div>';
      if (generator) h += '<div><span style="color:#4a7a9a;">Meta generator:</span> <span style="color:#aa66ff;">' + esc(generator) + '</span></div>';
      h += '</div>';
    }

    // All headers
    h += '<details>';
    h += '<summary style="color:#4a6a8a;font-size:10px;cursor:pointer;margin-top:8px;">All response headers (' + headerKeys.length + ')</summary>';
    h += '<div style="background:#060a10;border:1px solid #0d1525;border-radius:4px;padding:8px;margin-top:4px;max-height:250px;overflow-y:auto;">';
    for (var hi = 0; hi < headerKeys.length; hi++) {
      h += '<div style="font-size:10px;margin:2px 0;word-break:break-all;"><span style="color:#00aaff;">' + esc(headerKeys[hi]) + ':</span> <span style="color:#8ab4d4;">' + esc(resp.headers[headerKeys[hi]]) + '</span></div>';
    }
    h += '</div></details>';

    h += '</div>';
    results.innerHTML = h;
  } catch (err) {
    results.innerHTML =
      '<div style="background:#1a0a0a;border:1px solid #ff444433;border-radius:6px;padding:16px;text-align:center;">' +
      '<div style="color:#ff4444;font-size:14px;font-weight:bold;">FINGERPRINT FAILED</div>' +
      '<div style="color:#6a4a4a;font-size:10px;margin-top:4px;">' + esc(String((err && err.message) || err)) + '</div>' +
      '<div style="color:#4a6a8a;font-size:10px;margin-top:8px;">The target could not be reached through the Darknode proxy. No technologies are guessed.</div>' +
      '</div>';
  }
};
