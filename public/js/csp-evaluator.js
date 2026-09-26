/**
 * DARKNODE — CSP Evaluator & Generator
 * Content Security Policy parser, grader, bypass detector, and builder
 * Copyright 2024-2026 Darknode Project. All rights reserved.
 */

export function renderCspEvaluator(container) {
  var esc = function(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; };

  var DIRECTIVES_INFO = {
    'default-src':     { desc: 'Fallback for all fetch directives', importance: 'critical' },
    'script-src':      { desc: 'Sources for JavaScript execution', importance: 'critical' },
    'style-src':       { desc: 'Sources for CSS stylesheets', importance: 'high' },
    'img-src':         { desc: 'Sources for images', importance: 'medium' },
    'connect-src':     { desc: 'Sources for fetch, XHR, WebSocket', importance: 'high' },
    'font-src':        { desc: 'Sources for web fonts', importance: 'low' },
    'frame-src':       { desc: 'Sources for iframes', importance: 'high' },
    'frame-ancestors': { desc: 'Who can embed this page (clickjacking)', importance: 'critical' },
    'object-src':      { desc: 'Sources for plugins (Flash, Java)', importance: 'critical' },
    'base-uri':        { desc: 'Restricts <base> tag URLs', importance: 'high' },
    'form-action':     { desc: 'Restricts form submission targets', importance: 'high' },
    'worker-src':      { desc: 'Sources for Worker/SharedWorker/ServiceWorker', importance: 'medium' },
    'child-src':       { desc: 'Sources for workers and frames', importance: 'medium' },
    'media-src':       { desc: 'Sources for audio/video', importance: 'low' },
    'manifest-src':    { desc: 'Sources for web manifests', importance: 'low' },
    'prefetch-src':    { desc: 'Sources for prefetching', importance: 'low' },
    'navigate-to':     { desc: 'Restricts navigation targets', importance: 'medium' },
    'report-uri':      { desc: 'Endpoint for CSP violation reports (deprecated)', importance: 'low' },
    'report-to':       { desc: 'Reporting API group for violations', importance: 'low' },
    'sandbox':         { desc: 'Applies sandbox restrictions', importance: 'medium' },
    'upgrade-insecure-requests': { desc: 'Upgrade HTTP to HTTPS', importance: 'medium' },
    'block-all-mixed-content':   { desc: 'Block mixed HTTP/HTTPS content', importance: 'medium' },
    'require-trusted-types-for': { desc: 'Enforce Trusted Types for DOM XSS', importance: 'high' },
    'trusted-types':   { desc: 'Define Trusted Types policies', importance: 'high' }
  };

  var DANGEROUS_SOURCES = {
    "'unsafe-inline'": { level: 'critical', msg: 'Allows inline scripts/styles — defeats CSP XSS protection' },
    "'unsafe-eval'":   { level: 'critical', msg: 'Allows eval(), Function(), setTimeout(string) — code injection risk' },
    "'unsafe-hashes'": { level: 'high', msg: 'Allows specific inline event handlers by hash' },
    '*':               { level: 'critical', msg: 'Wildcard — allows loading from ANY source' },
    'data:':           { level: 'high', msg: 'Allows data: URIs — can be used for XSS in script-src' },
    'blob:':           { level: 'medium', msg: 'Allows blob: URIs — can execute code from Blob objects' },
    'http:':           { level: 'high', msg: 'Allows any HTTP source — no TLS, MitM risk' },
    'https:':          { level: 'medium', msg: 'Allows any HTTPS source — very broad' }
  };

  var JSONP_BYPASS_DOMAINS = [
    'accounts.google.com', 'ajax.googleapis.com', 'cdn.jsdelivr.net',
    'cdnjs.cloudflare.com', 'raw.githubusercontent.com', 'unpkg.com',
    'www.google.com', 'www.googleapis.com', 'maps.googleapis.com',
    'translate.googleapis.com', 'www.gstatic.com', 'api.twitter.com',
    'platform.twitter.com', 'connect.facebook.net', 'graph.facebook.com'
  ];

  var PRESETS = {
    strict: "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests",
    moderate: "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https:; connect-src 'self' https://api.example.com; font-src 'self' https://fonts.gstatic.com; frame-src 'none'; object-src 'none'; base-uri 'self'",
    permissive: "default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:; img-src * data: blob:; connect-src *; font-src *; frame-src https:; object-src 'self'",
    broken: "default-src *; script-src * 'unsafe-inline' 'unsafe-eval' data: blob:; style-src * 'unsafe-inline'; img-src * data: blob:; connect-src *; font-src *; frame-src *; object-src *"
  };

  var state = { parsed: null, grade: null, bypasses: [], generatorDirs: {} };

  function parseCSP(raw) {
    var directives = {};
    raw.split(';').forEach(function(part) {
      var trimmed = part.trim();
      if (!trimmed) return;
      var tokens = trimmed.split(/\s+/);
      var name = tokens[0].toLowerCase();
      // CSP Level 3: on a duplicate directive the FIRST occurrence is enforced
      // and later ones are ignored (browsers only log a warning).
      if (!Object.prototype.hasOwnProperty.call(directives, name)) directives[name] = tokens.slice(1);
    });
    return directives;
  }

  function assessSource(src, directive) {
    var s = src.toLowerCase();
    if (DANGEROUS_SOURCES[s]) {
      var info = DANGEROUS_SOURCES[s];
      if (s === 'data:' && directive !== 'script-src' && directive !== 'object-src') return { level: 'low', msg: 'data: URI — acceptable in ' + directive };
      if (s === 'blob:' && directive !== 'script-src') return { level: 'low', msg: 'blob: URI — acceptable in ' + directive };
      if (s === "'unsafe-inline'" && directive === 'style-src') return { level: 'medium', msg: 'unsafe-inline in style-src — less risky than script-src but still not ideal' };
      return info;
    }
    if (s.indexOf('*') === 0 && s.length > 1) return { level: 'high', msg: 'Wildcard subdomain — broad scope' };
    return null;
  }

  function gradeCSP(dirs) {
    var score = 100;
    var issues = [];
    var scriptSrc = dirs['script-src'] || dirs['default-src'] || [];
    var ss = scriptSrc.map(function(s) { return s.toLowerCase(); });

    if (!dirs['default-src']) { score -= 15; issues.push({ sev: 'high', msg: 'Missing default-src — no fallback policy' }); }
    if (ss.indexOf("'unsafe-inline'") >= 0) { score -= 25; issues.push({ sev: 'critical', msg: "script-src allows 'unsafe-inline' — XSS protection nullified" }); }
    if (ss.indexOf("'unsafe-eval'") >= 0) { score -= 20; issues.push({ sev: 'critical', msg: "script-src allows 'unsafe-eval' — code injection possible" }); }
    if (ss.indexOf('*') >= 0) { score -= 20; issues.push({ sev: 'critical', msg: 'script-src allows * wildcard — any source can execute scripts' }); }
    if (ss.indexOf('data:') >= 0) { score -= 15; issues.push({ sev: 'high', msg: 'script-src allows data: — XSS via data: URIs' }); }
    if (ss.indexOf('https:') >= 0) { score -= 10; issues.push({ sev: 'high', msg: 'script-src allows any HTTPS source — too broad' }); }

    if (!dirs['frame-ancestors']) { score -= 10; issues.push({ sev: 'high', msg: 'Missing frame-ancestors — no clickjacking protection' }); }
    var objSrc = dirs['object-src'] || dirs['default-src'] || [];
    if (objSrc.length === 0 || (objSrc.length > 0 && objSrc[0] !== "'none'")) { score -= 10; issues.push({ sev: 'high', msg: "Missing or permissive object-src — plugin-based XSS possible" }); }
    if (!dirs['base-uri']) { score -= 8; issues.push({ sev: 'medium', msg: 'Missing base-uri — base tag injection possible' }); }
    if (!dirs['form-action']) { score -= 5; issues.push({ sev: 'medium', msg: 'Missing form-action — forms can submit anywhere' }); }

    var styleSrc = dirs['style-src'] || dirs['default-src'] || [];
    if (styleSrc.map(function(s) { return s.toLowerCase(); }).indexOf("'unsafe-inline'") >= 0) { score -= 5; issues.push({ sev: 'medium', msg: "style-src allows 'unsafe-inline'" }); }

    if (dirs['upgrade-insecure-requests']) { score += 3; }
    if (dirs['require-trusted-types-for']) { score += 5; }

    score = Math.max(0, Math.min(100, score));
    var grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
    return { score: score, grade: grade, issues: issues };
  }

  function detectBypasses(dirs) {
    var bypasses = [];
    var scriptSrc = dirs['script-src'] || dirs['default-src'] || [];
    var ss = scriptSrc.map(function(s) { return s.toLowerCase(); });

    scriptSrc.forEach(function(src) {
      JSONP_BYPASS_DOMAINS.forEach(function(domain) {
        if (src.toLowerCase().indexOf(domain) >= 0) {
          bypasses.push({ sev: 'high', title: 'JSONP Bypass via ' + domain, desc: 'This CDN/API domain hosts JSONP endpoints that can be abused to execute arbitrary JS. An attacker can load a JSONP callback to run code within the CSP.' });
        }
      });
    });

    var hasNonce = scriptSrc.some(function(s) { return s.indexOf("'nonce-") === 0; });
    var hasHash = scriptSrc.some(function(s) { return s.indexOf("'sha256-") === 0 || s.indexOf("'sha384-") === 0 || s.indexOf("'sha512-") === 0; });
    if ((hasNonce || hasHash) && ss.indexOf("'unsafe-inline'") >= 0) {
      bypasses.push({ sev: 'info', title: "Nonce/Hash overrides 'unsafe-inline'", desc: "When a nonce or hash is present, 'unsafe-inline' is ignored by modern browsers. The unsafe-inline is likely left for legacy browser fallback." });
    }

    if (!dirs['base-uri']) {
      bypasses.push({ sev: 'medium', title: 'Base Tag Injection', desc: 'Without base-uri restriction, an attacker who can inject HTML can add a <base> tag to redirect relative URLs to a malicious server.' });
    }
    if (!dirs['object-src'] && (!dirs['default-src'] || dirs['default-src'][0] !== "'none'")) {
      bypasses.push({ sev: 'high', title: 'Plugin-Based XSS', desc: 'Without object-src none, an attacker can embed Flash/Java applets to execute scripts in the page context.' });
    }

    var connectSrc = dirs['connect-src'] || dirs['default-src'] || [];
    if (connectSrc.some(function(s) { return s === '*' || s === 'https:'; })) {
      bypasses.push({ sev: 'medium', title: 'Overly Broad connect-src', desc: 'Wildcard or https: in connect-src allows data exfiltration to any endpoint via fetch/XHR.' });
    }

    if (ss.indexOf("'strict-dynamic'") >= 0 && !hasNonce && !hasHash) {
      bypasses.push({ sev: 'high', title: "strict-dynamic without nonce/hash", desc: "strict-dynamic is meaningless without a nonce or hash — it only trusts scripts loaded by already-trusted scripts." });
    }

    if (!dirs['frame-ancestors'] && !dirs['x-frame-options']) {
      bypasses.push({ sev: 'medium', title: 'Clickjacking Possible', desc: 'Without frame-ancestors, the page can be embedded in an iframe for clickjacking attacks.' });
    }

    return bypasses;
  }

  function analyze(raw) {
    if (!raw || !raw.trim()) return;
    var dirs = parseCSP(raw);
    state.parsed = dirs;
    state.grade = gradeCSP(dirs);
    state.bypasses = detectBypasses(dirs);
    renderResults();
  }

  function renderResults() {
    var out = document.getElementById('csp-results');
    if (!out || !state.parsed) return;
    var dirs = state.parsed;
    var g = state.grade;
    var h = '';

    var gc = { A: '#00ff88', B: '#44dd66', C: '#ffaa00', D: '#ff6600', F: '#ff2222' }[g.grade] || '#ccc';
    h += '<div style="display:flex;gap:20px;align-items:center;margin-bottom:16px;padding:16px;background:#0c1020;border:1px solid #1a2a44;border-radius:8px;">';
    h += '<div style="width:80px;height:80px;border:3px solid ' + gc + ';border-radius:50%;display:flex;flex-direction:column;align-items:center;justify-content:center;flex-shrink:0;">';
    h += '<div style="font-size:32px;font-weight:800;color:' + gc + ';text-shadow:0 0 15px ' + gc + '60;">' + g.grade + '</div>';
    h += '<div style="font-size:9px;color:#4a6a8a;letter-spacing:1px;">' + g.score + '/100</div></div>';
    h += '<div style="flex:1;">';
    g.issues.forEach(function(issue) {
      var ic = issue.sev === 'critical' ? '#ff2222' : issue.sev === 'high' ? '#ff6600' : issue.sev === 'medium' ? '#ffaa00' : '#00aaff';
      h += '<div style="display:flex;gap:8px;align-items:flex-start;margin:3px 0;font-size:10px;">';
      h += '<span style="color:' + ic + ';font-weight:bold;min-width:60px;font-size:8px;letter-spacing:0.5px;padding:1px 4px;background:' + ic + '15;border:1px solid ' + ic + '33;border-radius:2px;">' + issue.sev.toUpperCase() + '</span>';
      h += '<span style="color:#8ab4d4;">' + esc(issue.msg) + '</span></div>';
    });
    if (g.issues.length === 0) h += '<div style="color:#00ff88;font-size:11px;">No major issues detected</div>';
    h += '</div></div>';

    h += '<div style="margin-bottom:16px;">';
    h += '<div style="color:#00aaff;font-size:12px;font-weight:bold;letter-spacing:2px;margin-bottom:8px;">DIRECTIVE ANALYSIS</div>';
    var allDirs = Object.keys(dirs);
    allDirs.forEach(function(dir) {
      var vals = dirs[dir];
      var info = DIRECTIVES_INFO[dir] || { desc: 'Custom directive', importance: 'low' };
      var impC = info.importance === 'critical' ? '#ff2222' : info.importance === 'high' ? '#ff6600' : info.importance === 'medium' ? '#ffaa00' : '#4a6a8a';
      h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:10px 12px;margin-bottom:6px;">';
      h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">';
      h += '<span style="color:#00ddff;font-weight:bold;font-size:11px;">' + esc(dir) + '</span>';
      h += '<span style="color:' + impC + ';font-size:8px;letter-spacing:0.5px;">' + info.importance.toUpperCase() + '</span></div>';
      h += '<div style="color:#3a5a7a;font-size:9px;margin-bottom:6px;">' + esc(info.desc) + '</div>';
      h += '<div style="display:flex;flex-wrap:wrap;gap:4px;">';
      vals.forEach(function(v) {
        var assessment = assessSource(v, dir);
        var vc = '#00ff88';
        if (assessment) {
          vc = assessment.level === 'critical' ? '#ff2222' : assessment.level === 'high' ? '#ff6600' : assessment.level === 'medium' ? '#ffaa00' : '#88cc88';
        }
        h += '<span style="background:' + vc + '12;color:' + vc + ';border:1px solid ' + vc + '33;padding:2px 8px;border-radius:3px;font-size:10px;cursor:default;" title="' + (assessment ? esc(assessment.msg) : 'OK') + '">' + esc(v) + '</span>';
      });
      if (vals.length === 0) h += '<span style="color:#3a5a7a;font-size:9px;font-style:italic;">no values (boolean directive)</span>';
      h += '</div></div>';
    });

    var missing = ['default-src', 'script-src', 'object-src', 'base-uri', 'frame-ancestors', 'form-action'].filter(function(d) { return !dirs[d]; });
    if (missing.length > 0) {
      h += '<div style="background:#ff220008;border:1px solid #ff222233;border-radius:6px;padding:10px 12px;margin-top:8px;">';
      h += '<div style="color:#ff6644;font-size:10px;font-weight:bold;margin-bottom:4px;">MISSING DIRECTIVES</div>';
      missing.forEach(function(m) {
        var info = DIRECTIVES_INFO[m] || {};
        h += '<div style="color:#ff8866;font-size:10px;margin:2px 0;">' + esc(m) + ' <span style="color:#4a6a8a;">— ' + esc(info.desc || '') + '</span></div>';
      });
      h += '</div>';
    }
    h += '</div>';

    if (state.bypasses.length > 0) {
      h += '<div style="margin-bottom:16px;">';
      h += '<div style="color:#ff6644;font-size:12px;font-weight:bold;letter-spacing:2px;margin-bottom:8px;">BYPASS DETECTION (' + state.bypasses.length + ')</div>';
      state.bypasses.forEach(function(b) {
        var bc = b.sev === 'high' ? '#ff6600' : b.sev === 'medium' ? '#ffaa00' : '#00aaff';
        h += '<div style="background:#0c1020;border-left:3px solid ' + bc + ';padding:8px 12px;margin-bottom:6px;border-radius:0 6px 6px 0;">';
        h += '<div style="color:' + bc + ';font-weight:bold;font-size:11px;">' + esc(b.title) + '</div>';
        h += '<div style="color:#6a8aaa;font-size:10px;margin-top:2px;">' + esc(b.desc) + '</div>';
        h += '</div>';
      });
      h += '</div>';
    }

    out.innerHTML = h;
  }

  function buildGenerator() {
    var GEN_DIRS = [
      { key: 'default-src', rec: "'none'", label: 'default-src' },
      { key: 'script-src', rec: "'self'", label: 'script-src' },
      { key: 'style-src', rec: "'self' 'unsafe-inline'", label: 'style-src' },
      { key: 'img-src', rec: "'self' data:", label: 'img-src' },
      { key: 'connect-src', rec: "'self'", label: 'connect-src' },
      { key: 'font-src', rec: "'self'", label: 'font-src' },
      { key: 'frame-src', rec: "'none'", label: 'frame-src' },
      { key: 'frame-ancestors', rec: "'none'", label: 'frame-ancestors' },
      { key: 'object-src', rec: "'none'", label: 'object-src' },
      { key: 'base-uri', rec: "'self'", label: 'base-uri' },
      { key: 'form-action', rec: "'self'", label: 'form-action' },
      { key: 'worker-src', rec: "'self'", label: 'worker-src' }
    ];

    var h = '<div style="margin-top:16px;background:#0c1020;border:1px solid #1a2a44;border-radius:8px;padding:16px;">';
    h += '<div style="color:#aa66ff;font-size:12px;font-weight:bold;letter-spacing:2px;margin-bottom:12px;">CSP GENERATOR</div>';
    GEN_DIRS.forEach(function(d) {
      h += '<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px;">';
      h += '<label style="color:#00ddff;font-size:10px;min-width:110px;font-weight:bold;">' + esc(d.label) + '</label>';
      h += '<input id="csp-gen-' + d.key + '" type="text" value="' + esc(d.rec) + '" placeholder="' + esc(d.rec) + '" style="flex:1;background:#060a14;border:1px solid #1a3050;border-radius:4px;color:#c8d6e5;font-family:monospace;font-size:10px;padding:5px 8px;">';
      h += '</div>';
    });
    h += '<div style="display:flex;gap:8px;margin-top:6px;align-items:center;">';
    h += '<label style="color:#00ddff;font-size:10px;min-width:110px;">Options</label>';
    h += '<label style="color:#6a8aaa;font-size:10px;cursor:pointer;"><input type="checkbox" id="csp-gen-upgrade" checked style="margin-right:4px;">upgrade-insecure-requests</label>';
    h += '</div>';
    h += '<div style="display:flex;gap:8px;margin-top:12px;">';
    h += '<button id="csp-gen-build" style="background:#aa66ff15;color:#aa66ff;border:1px solid #aa66ff44;padding:6px 16px;font-family:monospace;font-size:10px;cursor:pointer;border-radius:4px;">BUILD CSP</button>';
    h += '<button id="csp-gen-copy" style="background:#00ff8815;color:#00ff88;border:1px solid #00ff8844;padding:6px 16px;font-family:monospace;font-size:10px;cursor:pointer;border-radius:4px;">COPY</button>';
    h += '</div>';
    h += '<pre id="csp-gen-output" style="background:#040810;border:1px solid #1a2a44;border-radius:4px;padding:10px;margin-top:10px;font-size:10px;color:#00ddff;white-space:pre-wrap;word-break:break-all;display:none;"></pre>';
    h += '</div>';
    return h;
  }

  function wireGenerator() {
    var GEN_KEYS = ['default-src','script-src','style-src','img-src','connect-src','font-src','frame-src','frame-ancestors','object-src','base-uri','form-action','worker-src'];
    var buildBtn = document.getElementById('csp-gen-build');
    var copyBtn = document.getElementById('csp-gen-copy');
    var output = document.getElementById('csp-gen-output');
    if (!buildBtn) return;

    function buildCSP() {
      var parts = [];
      GEN_KEYS.forEach(function(key) {
        var el = document.getElementById('csp-gen-' + key);
        if (el && el.value.trim()) parts.push(key + ' ' + el.value.trim());
      });
      var upgradeEl = document.getElementById('csp-gen-upgrade');
      if (upgradeEl && upgradeEl.checked) parts.push('upgrade-insecure-requests');
      var csp = parts.join('; ');
      output.textContent = csp;
      output.style.display = 'block';
      return csp;
    }

    buildBtn.addEventListener('click', function() { buildCSP(); });
    copyBtn.addEventListener('click', function() {
      var csp = buildCSP();
      try {
        navigator.clipboard.writeText(csp);
        copyBtn.textContent = 'COPIED';
        setTimeout(function() { copyBtn.textContent = 'COPY'; }, 1500);
      } catch (e) { /* ignore */ }
    });
  }

  var html = '<div style="background:#0a0e14;color:#c8d6e5;font-family:\'Courier New\',monospace;padding:20px;min-height:100vh;">';
  html += '<div style="text-align:center;margin-bottom:20px;padding-bottom:12px;border-bottom:1px solid #1a2a44;">';
  html += '<div style="font-size:22px;font-weight:800;letter-spacing:4px;color:#00ddff;text-shadow:0 0 20px rgba(0,212,255,0.3);">CSP EVALUATOR</div>';
  html += '<div style="font-size:10px;color:#4a6a8a;letter-spacing:2px;">CONTENT SECURITY POLICY ANALYZER &amp; GENERATOR</div></div>';

  html += '<div style="display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap;">';
  html += '<button class="csp-preset-btn" data-preset="strict" style="background:#00ff8815;color:#00ff88;border:1px solid #00ff8833;padding:5px 12px;font-family:monospace;font-size:9px;cursor:pointer;border-radius:4px;letter-spacing:1px;">STRICT</button>';
  html += '<button class="csp-preset-btn" data-preset="moderate" style="background:#ffaa0015;color:#ffaa00;border:1px solid #ffaa0033;padding:5px 12px;font-family:monospace;font-size:9px;cursor:pointer;border-radius:4px;letter-spacing:1px;">MODERATE</button>';
  html += '<button class="csp-preset-btn" data-preset="permissive" style="background:#ff660015;color:#ff6600;border:1px solid #ff660033;padding:5px 12px;font-family:monospace;font-size:9px;cursor:pointer;border-radius:4px;letter-spacing:1px;">PERMISSIVE</button>';
  html += '<button class="csp-preset-btn" data-preset="broken" style="background:#ff222215;color:#ff2222;border:1px solid #ff222233;padding:5px 12px;font-family:monospace;font-size:9px;cursor:pointer;border-radius:4px;letter-spacing:1px;">BROKEN</button>';
  html += '</div>';

  html += '<div style="margin-bottom:16px;">';
  html += '<textarea id="csp-input" rows="4" placeholder="Paste a CSP header here, e.g.:\ndefault-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:; object-src \'none\'" style="width:100%;box-sizing:border-box;background:#060a14;border:2px solid #1a3050;border-radius:6px;color:#00ddff;font-family:monospace;font-size:11px;padding:10px;resize:vertical;"></textarea>';
  html += '</div>';

  html += '<div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;">';
  html += '<button id="csp-analyze-btn" style="background:#00aaff15;color:#00aaff;border:1px solid #00aaff44;padding:8px 20px;font-family:monospace;font-size:11px;font-weight:bold;cursor:pointer;border-radius:4px;letter-spacing:1px;">ANALYZE</button>';
  html += '<div style="display:flex;gap:4px;flex:1;min-width:200px;">';
  html += '<input id="csp-url-input" type="text" placeholder="Or enter a URL to fetch CSP from..." style="flex:1;background:#060a14;border:1px solid #1a3050;border-radius:4px;color:#c8d6e5;font-family:monospace;font-size:10px;padding:8px;">';
  html += '<button id="csp-fetch-btn" style="background:#aa66ff15;color:#aa66ff;border:1px solid #aa66ff44;padding:8px 14px;font-family:monospace;font-size:10px;cursor:pointer;border-radius:4px;">FETCH</button>';
  html += '</div></div>';

  html += '<div id="csp-status" style="display:none;padding:8px 12px;margin-bottom:12px;border-radius:4px;font-size:10px;"></div>';
  html += '<div id="csp-results"></div>';

  html += buildGenerator();
  html += '</div>';

  container.innerHTML = html;

  var inputEl = document.getElementById('csp-input');
  var analyzeBtn = document.getElementById('csp-analyze-btn');
  var fetchBtn = document.getElementById('csp-fetch-btn');
  var urlInput = document.getElementById('csp-url-input');
  var statusEl = document.getElementById('csp-status');

  function showStatus(msg, type) {
    statusEl.textContent = msg;
    statusEl.style.display = 'block';
    statusEl.style.background = type === 'error' ? '#ff222215' : type === 'success' ? '#00ff8815' : '#00aaff15';
    statusEl.style.color = type === 'error' ? '#ff4444' : type === 'success' ? '#00ff88' : '#00aaff';
    statusEl.style.border = '1px solid ' + (type === 'error' ? '#ff222233' : type === 'success' ? '#00ff8833' : '#00aaff33');
  }

  analyzeBtn.addEventListener('click', function() {
    var raw = inputEl.value.trim();
    if (!raw) { showStatus('Enter a CSP header to analyze', 'error'); return; }
    statusEl.style.display = 'none';
    analyze(raw);
  });

  fetchBtn.addEventListener('click', function() {
    var url = urlInput.value.trim();
    if (!url) { showStatus('Enter a URL', 'error'); return; }
    if (url.indexOf('http') !== 0) url = 'https://' + url;
    showStatus('Fetching headers from ' + url + '...', 'info');
    fetch(url, { method: 'HEAD', mode: 'cors' }).then(function(resp) {
      var csp = resp.headers.get('content-security-policy') || resp.headers.get('content-security-policy-report-only');
      if (csp) {
        inputEl.value = csp;
        showStatus('CSP header retrieved — ' + csp.length + ' chars', 'success');
        analyze(csp);
      } else {
        showStatus('No CSP header found in the response (CORS may hide it — try pasting the header manually)', 'error');
      }
    }).catch(function(err) {
      showStatus('Fetch failed: ' + err.message + ' — CORS likely blocked the request. Copy the CSP header manually from browser DevTools → Network → Response Headers.', 'error');
    });
  });

  var presetBtns = container.querySelectorAll('.csp-preset-btn');
  presetBtns.forEach(function(btn) {
    btn.addEventListener('click', function() {
      var key = btn.getAttribute('data-preset');
      if (PRESETS[key]) {
        inputEl.value = PRESETS[key];
        analyze(PRESETS[key]);
      }
    });
  });

  inputEl.addEventListener('keydown', function(e) {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); analyzeBtn.click(); }
  });

  wireGenerator();
};
