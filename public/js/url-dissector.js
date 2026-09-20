/**
 * DARKNODE — URL Dissector
 * Deep URL analysis, encoding detection, suspicious pattern scanning
 * Copyright 2024-2026 Darknode Project. All rights reserved.
 */
export function renderUrlDissector(container) {
  var esc = function(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; };

  var S = {
    bg: '#0a0e14', card: '#0c1220', border: '#1a2a44', accent: '#00ddff',
    green: '#00ff88', red: '#ff4444', orange: '#ff8800', yellow: '#ffaa00',
    dim: '#4a6a8a', text: '#c8d6e5', mono: "'Courier New','JetBrains Mono',monospace"
  };

  var tabs = ['ANALYZE', 'BATCH', 'COMPARE', 'BUILD', 'DEFANG'];
  var activeTab = 'ANALYZE';

  function render() {
    var h = '<div style="background:' + S.bg + ';color:' + S.text + ';font-family:' + S.mono + ';padding:20px;min-height:100vh;">';
    h += '<div style="text-align:center;margin-bottom:20px;border-bottom:1px solid ' + S.border + ';padding-bottom:12px;">';
    h += '<div style="font-size:24px;font-weight:800;letter-spacing:4px;color:' + S.accent + ';text-shadow:0 0 20px rgba(0,212,255,0.3);">URL DISSECTOR</div>';
    h += '<div style="font-size:10px;color:' + S.dim + ';letter-spacing:2px;">DEEP URL ANALYSIS &amp; SECURITY ASSESSMENT</div></div>';

    h += '<div style="display:flex;gap:4px;margin-bottom:16px;">';
    tabs.forEach(function(t) {
      var act = t === activeTab;
      h += '<button onclick="window._udTab(\'' + t + '\')" style="flex:1;padding:8px;font-family:' + S.mono + ';font-size:10px;letter-spacing:1px;border:1px solid ' + (act ? S.accent : S.border) + ';background:' + (act ? S.accent + '15' : S.card) + ';color:' + (act ? S.accent : S.dim) + ';cursor:pointer;border-radius:4px;">' + t + '</button>';
    });
    h += '</div>';

    if (activeTab === 'ANALYZE') h += renderAnalyze();
    else if (activeTab === 'BATCH') h += renderBatch();
    else if (activeTab === 'COMPARE') h += renderCompare();
    else if (activeTab === 'BUILD') h += renderBuild();
    else if (activeTab === 'DEFANG') h += renderDefang();

    h += '</div>';
    container.innerHTML = h;
  }

  function inp(id, ph, val) {
    return '<input id="' + id + '" value="' + esc(val || '') + '" placeholder="' + esc(ph) + '" style="width:100%;box-sizing:border-box;background:#060a14;border:1px solid ' + S.border + ';color:' + S.accent + ';font-family:' + S.mono + ';font-size:13px;padding:10px 12px;border-radius:4px;" spellcheck="false">';
  }

  function ta(id, ph, rows) {
    return '<textarea id="' + id + '" placeholder="' + esc(ph) + '" rows="' + (rows || 5) + '" style="width:100%;box-sizing:border-box;background:#060a14;border:1px solid ' + S.border + ';color:' + S.accent + ';font-family:' + S.mono + ';font-size:11px;padding:10px;border-radius:4px;resize:vertical;" spellcheck="false"></textarea>';
  }

  function btn(label, onclick, color) {
    color = color || S.accent;
    return '<button onclick="' + onclick + '" style="background:' + color + '15;border:1px solid ' + color + '44;color:' + color + ';font-family:' + S.mono + ';font-size:11px;padding:8px 16px;cursor:pointer;border-radius:4px;letter-spacing:1px;">' + label + '</button>';
  }

  function badge(text, color) {
    return '<span style="display:inline-block;font-size:8px;font-weight:bold;letter-spacing:1px;padding:2px 6px;border-radius:2px;background:' + color + '18;color:' + color + ';border:1px solid ' + color + '33;margin:1px 2px;">' + esc(text) + '</span>';
  }

  // ── ANALYZE ──
  function renderAnalyze() {
    var h = '<div style="margin-bottom:12px;">' + inp('ud-url', 'https://example.com/path?key=value#frag') + '</div>';
    h += '<div style="margin-bottom:16px;">' + btn('DISSECT', 'window._udAnalyze()') + '</div>';
    h += '<div id="ud-result"></div>';
    return h;
  }

  function parseURL(raw) {
    var r = { raw: raw, parts: {}, params: [], encodings: [], suspicions: [] };
    try {
      var u = new URL(raw);
      r.parts.protocol = u.protocol;
      r.parts.hostname = u.hostname;
      r.parts.port = u.port || (u.protocol === 'https:' ? '443' : u.protocol === 'http:' ? '80' : '');
      r.parts.pathname = u.pathname;
      r.parts.search = u.search;
      r.parts.hash = u.hash;
      r.parts.origin = u.origin;
      r.parts.username = u.username;
      r.parts.password = u.password;
      r.parts.pathSegments = u.pathname.split('/').filter(Boolean);
      u.searchParams.forEach(function(v, k) { r.params.push({ key: k, value: v }); });
    } catch (e) {
      r.parseError = e.message;
    }
    detectEncodings(raw, r);
    detectSuspicious(raw, r);
    return r;
  }

  function detectEncodings(raw, r) {
    if (/%25[0-9A-Fa-f]{2}/.test(raw)) r.encodings.push({ type: 'Double URL Encoding', detail: 'Contains %25XX sequences (double-encoded)', severity: 'high' });
    if (/%[0-9A-Fa-f]{2}/.test(raw)) {
      var decoded;
      try { decoded = decodeURIComponent(raw); } catch (e) { decoded = ''; }
      if (decoded !== raw) r.encodings.push({ type: 'URL Encoding', detail: 'Decoded: ' + decoded.substring(0, 200), severity: 'info' });
    }
    if (/%u[0-9A-Fa-f]{4}/.test(raw)) r.encodings.push({ type: 'Unicode Encoding', detail: 'Contains %uXXXX sequences (non-standard)', severity: 'medium' });
    if (/&(?:#\d+|#x[0-9a-f]+|[a-z]+);/i.test(raw)) r.encodings.push({ type: 'HTML Entities', detail: 'URL contains HTML entity references', severity: 'medium' });
    if (/xn--/.test(raw)) r.encodings.push({ type: 'Punycode / IDN', detail: 'Internationalized domain name detected (xn-- prefix)', severity: 'high' });
    r.params.forEach(function(p) {
      if (/^[A-Za-z0-9+/]{20,}={0,2}$/.test(p.value)) {
        var decoded64 = '';
        try { decoded64 = atob(p.value); } catch (e) { return; }
        if (/^[\x20-\x7E]+$/.test(decoded64)) r.encodings.push({ type: 'Base64 in Param', detail: 'Param "' + p.key + '" decodes to: ' + decoded64.substring(0, 120), severity: 'medium' });
      }
    });
  }

  function detectSuspicious(raw, r) {
    var s = r.suspicions;
    if (/^javascript:/i.test(raw)) s.push({ flag: 'JavaScript URI', detail: 'javascript: protocol can execute arbitrary code', severity: 'critical' });
    if (/^data:/i.test(raw)) s.push({ flag: 'Data URI', detail: 'data: protocol can embed executable content', severity: 'high' });
    if (r.parts.username) s.push({ flag: 'Credentials in URL', detail: 'Username: ' + r.parts.username + (r.parts.password ? ', Password present' : ''), severity: 'high' });
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(r.parts.hostname || '')) s.push({ flag: 'IP Address Host', detail: 'Using IP instead of domain — may indicate phishing or C2', severity: 'medium' });
    var port = parseInt(r.parts.port || '0', 10);
    if (port && port !== 80 && port !== 443 && port !== 8080 && port !== 8443) s.push({ flag: 'Unusual Port', detail: 'Port ' + port + ' is non-standard', severity: 'low' });
    if (raw.length > 2048) s.push({ flag: 'Excessive Length', detail: raw.length + ' characters (>2048 limit for many browsers/servers)', severity: 'medium' });
    if (/%00/.test(raw)) s.push({ flag: 'Null Byte', detail: 'Contains %00 — may truncate URL processing', severity: 'critical' });
    if (/\.\.\/|\.\.\\/.test(raw)) s.push({ flag: 'Path Traversal', detail: 'Contains ../ or ..\\ sequences', severity: 'high' });
    if (/^\/\/[^/]/.test(raw) || /\/\\[^\\]/.test(raw)) s.push({ flag: 'Open Redirect Pattern', detail: 'Protocol-relative or backslash-based redirect', severity: 'high' });
    if (/@/.test((r.parts.pathname || '') + (r.parts.search || ''))) s.push({ flag: '@ Sign in Path/Query', detail: 'May cause authority confusion in some parsers', severity: 'medium' });

    var host = r.parts.hostname || '';
    var cyrillic = /[Ѐ-ӿ]/;
    if (cyrillic.test(raw)) s.push({ flag: 'Homograph Characters', detail: 'Cyrillic or similar lookalike characters detected', severity: 'critical' });
    if (host && /[^\x00-\x7F]/.test(host) && !/xn--/.test(host)) s.push({ flag: 'Non-ASCII Domain', detail: 'Domain contains non-ASCII characters (possible IDN homograph)', severity: 'high' });

    var redirectParams = ['url', 'redirect', 'redirect_uri', 'return', 'returnTo', 'return_url', 'next', 'dest', 'destination', 'redir', 'target', 'continue', 'goto'];
    r.params.forEach(function(p) {
      if (redirectParams.indexOf(p.key.toLowerCase()) !== -1) s.push({ flag: 'Redirect Parameter', detail: 'Param "' + p.key + '" commonly used for open redirects → ' + p.value.substring(0, 80), severity: 'high' });
    });
  }

  function renderResult(r) {
    if (r.parseError) return '<div style="color:' + S.red + ';padding:12px;background:' + S.red + '10;border:1px solid ' + S.red + '33;border-radius:4px;">Parse error: ' + esc(r.parseError) + '</div>';

    var h = '';
    var colors = { protocol: '#ff66aa', hostname: '#00ddff', port: '#ffaa00', pathname: '#00ff88', search: '#aa88ff', hash: '#ff8844' };

    // Colorized URL
    h += '<div style="background:#060a14;border:1px solid ' + S.border + ';border-radius:4px;padding:10px;margin-bottom:12px;font-size:12px;word-break:break-all;">';
    h += '<span style="color:' + colors.protocol + ';">' + esc(r.parts.protocol) + '</span>';
    h += '<span style="color:' + S.dim + ';">//</span>';
    if (r.parts.username) h += '<span style="color:' + S.red + ';">' + esc(r.parts.username) + (r.parts.password ? ':' + esc(r.parts.password) : '') + '@</span>';
    h += '<span style="color:' + colors.hostname + ';font-weight:bold;">' + esc(r.parts.hostname) + '</span>';
    if (r.parts.port && r.parts.port !== '80' && r.parts.port !== '443') h += '<span style="color:' + colors.port + ';">:' + esc(r.parts.port) + '</span>';
    h += '<span style="color:' + colors.pathname + ';">' + esc(r.parts.pathname) + '</span>';
    h += '<span style="color:' + colors.search + ';">' + esc(r.parts.search) + '</span>';
    h += '<span style="color:' + colors.hash + ';">' + esc(r.parts.hash) + '</span>';
    h += '</div>';

    // Components table
    h += '<details open style="margin-bottom:10px;"><summary style="color:' + S.accent + ';font-size:11px;cursor:pointer;padding:6px 0;font-weight:bold;">COMPONENTS</summary>';
    h += '<div style="background:' + S.card + ';border:1px solid ' + S.border + ';border-radius:4px;padding:8px;">';
    var fields = [
      ['Protocol', r.parts.protocol, colors.protocol],
      ['Hostname', r.parts.hostname, colors.hostname],
      ['Port', r.parts.port, colors.port],
      ['Origin', r.parts.origin, S.dim]
    ];
    if (r.parts.username) fields.push(['Username', r.parts.username, S.red]);
    if (r.parts.password) fields.push(['Password', r.parts.password, S.red]);
    fields.push(['Path', r.parts.pathname, colors.pathname]);
    if (r.parts.pathSegments.length > 0) fields.push(['Segments', r.parts.pathSegments.join(' → '), colors.pathname]);
    fields.push(['Query', r.parts.search || '(none)', colors.search]);
    fields.push(['Fragment', r.parts.hash || '(none)', colors.hash]);

    fields.forEach(function(f) {
      h += '<div style="display:flex;gap:8px;padding:3px 0;font-size:10px;border-bottom:1px solid ' + S.border + ';">';
      h += '<span style="color:' + S.dim + ';min-width:90px;">' + f[0] + '</span>';
      h += '<span style="color:' + f[2] + ';word-break:break-all;">' + esc(f[1]) + '</span></div>';
    });
    h += '</div></details>';

    // Query parameters
    if (r.params.length > 0) {
      h += '<details open style="margin-bottom:10px;"><summary style="color:' + S.accent + ';font-size:11px;cursor:pointer;padding:6px 0;font-weight:bold;">QUERY PARAMETERS (' + r.params.length + ')</summary>';
      h += '<div style="background:' + S.card + ';border:1px solid ' + S.border + ';border-radius:4px;padding:8px;">';
      r.params.forEach(function(p) {
        h += '<div style="display:flex;gap:8px;padding:3px 0;font-size:10px;border-bottom:1px solid ' + S.border + ';">';
        h += '<span style="color:' + S.yellow + ';min-width:120px;font-weight:bold;">' + esc(p.key) + '</span>';
        h += '<span style="color:' + S.text + ';word-break:break-all;">' + esc(p.value) + '</span></div>';
      });
      h += '</div></details>';
    }

    // Encodings
    if (r.encodings.length > 0) {
      h += '<details open style="margin-bottom:10px;"><summary style="color:' + S.orange + ';font-size:11px;cursor:pointer;padding:6px 0;font-weight:bold;">ENCODINGS DETECTED (' + r.encodings.length + ')</summary>';
      h += '<div style="background:' + S.card + ';border:1px solid ' + S.border + ';border-radius:4px;padding:8px;">';
      r.encodings.forEach(function(e) {
        var ec = e.severity === 'high' ? S.red : e.severity === 'medium' ? S.orange : S.accent;
        h += '<div style="padding:4px 0;font-size:10px;border-bottom:1px solid ' + S.border + ';">';
        h += badge(e.type, ec) + ' <span style="color:' + S.text + ';">' + esc(e.detail) + '</span></div>';
      });
      h += '</div></details>';
    }

    // Suspicions
    if (r.suspicions.length > 0) {
      h += '<details open style="margin-bottom:10px;"><summary style="color:' + S.red + ';font-size:11px;cursor:pointer;padding:6px 0;font-weight:bold;">SECURITY FLAGS (' + r.suspicions.length + ')</summary>';
      h += '<div style="background:' + S.card + ';border:1px solid ' + S.border + ';border-radius:4px;padding:8px;">';
      r.suspicions.forEach(function(s) {
        var sc = s.severity === 'critical' ? S.red : s.severity === 'high' ? S.orange : s.severity === 'medium' ? S.yellow : S.green;
        h += '<div style="padding:6px 8px;margin:3px 0;border-left:3px solid ' + sc + ';background:' + sc + '08;border-radius:0 4px 4px 0;font-size:10px;">';
        h += badge(s.severity.toUpperCase(), sc) + ' <span style="color:' + S.text + ';font-weight:bold;">' + esc(s.flag) + '</span>';
        h += '<div style="color:' + S.dim + ';margin-top:2px;">' + esc(s.detail) + '</div></div>';
      });
      h += '</div></details>';
    }

    if (r.suspicions.length === 0 && r.encodings.length === 0) {
      h += '<div style="padding:10px;text-align:center;color:' + S.green + ';font-size:11px;background:' + S.green + '08;border:1px solid ' + S.green + '33;border-radius:4px;">NO SUSPICIOUS PATTERNS DETECTED</div>';
    }

    return h;
  }

  window._udAnalyze = function() {
    var url = (document.getElementById('ud-url') || {}).value || '';
    if (!url.trim()) return;
    var r = parseURL(url.trim());
    var el = document.getElementById('ud-result');
    if (el) el.innerHTML = renderResult(r);
  };

  // ── BATCH ──
  function renderBatch() {
    var h = '<div style="margin-bottom:12px;">' + ta('ud-batch', 'Paste URLs, one per line...', 8) + '</div>';
    h += '<div style="margin-bottom:16px;">' + btn('SCAN ALL', 'window._udBatch()') + '</div>';
    h += '<div id="ud-batch-result"></div>';
    return h;
  }

  window._udBatch = function() {
    var raw = (document.getElementById('ud-batch') || {}).value || '';
    var urls = raw.split('\n').map(function(l) { return l.trim(); }).filter(Boolean);
    if (urls.length === 0) return;
    var results = urls.map(function(u) { return parseURL(u); });

    var h = '<div style="font-size:11px;color:' + S.accent + ';margin-bottom:8px;font-weight:bold;">' + results.length + ' URLs ANALYZED</div>';
    h += '<div style="overflow-x:auto;">';
    h += '<table style="width:100%;border-collapse:collapse;font-size:10px;">';
    h += '<tr style="border-bottom:2px solid ' + S.border + ';">';
    ['#', 'HOST', 'PATH', 'PARAMS', 'ENCODINGS', 'FLAGS', 'RISK'].forEach(function(th) {
      h += '<th style="text-align:left;padding:6px;color:' + S.dim + ';font-size:9px;letter-spacing:1px;">' + th + '</th>';
    });
    h += '</tr>';

    results.forEach(function(r, i) {
      var flags = r.suspicions.length;
      var risk = flags === 0 ? 'CLEAN' : flags <= 2 ? 'LOW' : flags <= 4 ? 'MEDIUM' : 'HIGH';
      var rc = risk === 'CLEAN' ? S.green : risk === 'LOW' ? S.yellow : risk === 'MEDIUM' ? S.orange : S.red;
      h += '<tr style="border-bottom:1px solid ' + S.border + ';cursor:pointer;" onclick="window._udBatchDetail(' + i + ')">';
      h += '<td style="padding:5px;color:' + S.dim + ';">' + (i + 1) + '</td>';
      h += '<td style="padding:5px;color:' + S.accent + ';max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + esc(r.parts.hostname || r.raw.substring(0, 30)) + '</td>';
      h += '<td style="padding:5px;color:' + S.text + ';max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + esc(r.parts.pathname || '/') + '</td>';
      h += '<td style="padding:5px;color:' + S.yellow + ';">' + r.params.length + '</td>';
      h += '<td style="padding:5px;color:' + S.orange + ';">' + r.encodings.length + '</td>';
      h += '<td style="padding:5px;color:' + S.red + ';">' + flags + '</td>';
      h += '<td style="padding:5px;">' + badge(risk, rc) + '</td>';
      h += '</tr>';
    });
    h += '</table></div>';
    h += '<div id="ud-batch-detail" style="margin-top:12px;"></div>';

    var el = document.getElementById('ud-batch-result');
    if (el) el.innerHTML = h;
    window._udBatchResults = results;
  };

  window._udBatchDetail = function(i) {
    var r = (window._udBatchResults || [])[i];
    if (!r) return;
    var el = document.getElementById('ud-batch-detail');
    if (el) el.innerHTML = '<div style="border-top:1px solid ' + S.border + ';padding-top:12px;">' + renderResult(r) + '</div>';
  };

  // ── COMPARE ──
  function renderCompare() {
    var h = '<div style="display:flex;gap:8px;margin-bottom:12px;">';
    h += '<div style="flex:1;">' + inp('ud-cmp1', 'URL #1') + '</div>';
    h += '<div style="flex:1;">' + inp('ud-cmp2', 'URL #2') + '</div>';
    h += '</div>';
    h += '<div style="margin-bottom:16px;">' + btn('COMPARE', 'window._udCompare()') + '</div>';
    h += '<div id="ud-cmp-result"></div>';
    return h;
  }

  window._udCompare = function() {
    var u1 = (document.getElementById('ud-cmp1') || {}).value || '';
    var u2 = (document.getElementById('ud-cmp2') || {}).value || '';
    if (!u1.trim() || !u2.trim()) return;
    var r1 = parseURL(u1.trim()), r2 = parseURL(u2.trim());
    if (r1.parseError || r2.parseError) {
      var el = document.getElementById('ud-cmp-result');
      if (el) el.innerHTML = '<div style="color:' + S.red + ';">Parse error in one or both URLs</div>';
      return;
    }

    var h = '<div style="font-size:11px;color:' + S.accent + ';margin-bottom:8px;font-weight:bold;">STRUCTURAL COMPARISON</div>';
    h += '<div style="background:' + S.card + ';border:1px solid ' + S.border + ';border-radius:4px;padding:8px;">';

    var fields = ['protocol', 'hostname', 'port', 'pathname', 'search', 'hash', 'username', 'password'];
    fields.forEach(function(f) {
      var v1 = r1.parts[f] || '', v2 = r2.parts[f] || '';
      var same = v1 === v2;
      var ic = same ? S.green : S.red;
      h += '<div style="display:flex;gap:8px;padding:4px 0;font-size:10px;border-bottom:1px solid ' + S.border + ';align-items:center;">';
      h += '<span style="color:' + S.dim + ';min-width:80px;">' + f + '</span>';
      h += '<span style="color:' + ic + ';min-width:12px;">' + (same ? '=' : '≠') + '</span>';
      h += '<span style="flex:1;color:' + (same ? S.text : S.orange) + ';word-break:break-all;">' + esc(v1 || '(empty)') + '</span>';
      h += '<span style="flex:1;color:' + (same ? S.text : S.yellow) + ';word-break:break-all;">' + esc(v2 || '(empty)') + '</span>';
      h += '</div>';
    });
    h += '</div>';

    // Param diff
    var allKeys = {};
    r1.params.forEach(function(p) { allKeys[p.key] = [p.value, null]; });
    r2.params.forEach(function(p) { if (allKeys[p.key]) allKeys[p.key][1] = p.value; else allKeys[p.key] = [null, p.value]; });
    var paramKeys = Object.keys(allKeys);
    if (paramKeys.length > 0) {
      h += '<div style="margin-top:8px;font-size:11px;color:' + S.accent + ';font-weight:bold;margin-bottom:4px;">PARAMETER DIFF</div>';
      h += '<div style="background:' + S.card + ';border:1px solid ' + S.border + ';border-radius:4px;padding:8px;">';
      paramKeys.forEach(function(k) {
        var v = allKeys[k];
        var status = v[0] === null ? 'ADDED' : v[1] === null ? 'REMOVED' : v[0] === v[1] ? 'SAME' : 'CHANGED';
        var sc = status === 'SAME' ? S.green : status === 'ADDED' ? S.accent : status === 'REMOVED' ? S.red : S.orange;
        h += '<div style="display:flex;gap:8px;padding:3px 0;font-size:10px;border-bottom:1px solid ' + S.border + ';">';
        h += badge(status, sc);
        h += '<span style="color:' + S.yellow + ';min-width:100px;">' + esc(k) + '</span>';
        h += '<span style="flex:1;color:' + S.text + ';word-break:break-all;">' + esc(v[0] || '-') + '</span>';
        h += '<span style="flex:1;color:' + S.text + ';word-break:break-all;">' + esc(v[1] || '-') + '</span>';
        h += '</div>';
      });
      h += '</div>';
    }

    // Flag comparison
    h += '<div style="display:flex;gap:12px;margin-top:10px;">';
    h += '<div style="flex:1;padding:8px;background:' + S.card + ';border:1px solid ' + S.border + ';border-radius:4px;text-align:center;">';
    h += '<div style="font-size:9px;color:' + S.dim + ';letter-spacing:1px;">URL #1 FLAGS</div>';
    h += '<div style="font-size:20px;font-weight:bold;color:' + (r1.suspicions.length > 0 ? S.red : S.green) + ';">' + r1.suspicions.length + '</div></div>';
    h += '<div style="flex:1;padding:8px;background:' + S.card + ';border:1px solid ' + S.border + ';border-radius:4px;text-align:center;">';
    h += '<div style="font-size:9px;color:' + S.dim + ';letter-spacing:1px;">URL #2 FLAGS</div>';
    h += '<div style="font-size:20px;font-weight:bold;color:' + (r2.suspicions.length > 0 ? S.red : S.green) + ';">' + r2.suspicions.length + '</div></div>';
    h += '</div>';

    var el = document.getElementById('ud-cmp-result');
    if (el) el.innerHTML = h;
  };

  // ── BUILD ──
  function renderBuild() {
    var fields = [
      ['ud-b-proto', 'Protocol', 'https:'],
      ['ud-b-host', 'Hostname', 'example.com'],
      ['ud-b-port', 'Port', ''],
      ['ud-b-path', 'Path', '/api/v1/users'],
      ['ud-b-query', 'Query (key=val&key=val)', 'page=1&limit=10'],
      ['ud-b-frag', 'Fragment', '']
    ];
    var h = '<div style="background:' + S.card + ';border:1px solid ' + S.border + ';border-radius:4px;padding:12px;margin-bottom:12px;">';
    fields.forEach(function(f) {
      h += '<div style="margin-bottom:8px;">';
      h += '<label style="font-size:9px;color:' + S.dim + ';letter-spacing:1px;display:block;margin-bottom:2px;">' + f[1].toUpperCase() + '</label>';
      h += inp(f[0], f[2]);
      h += '</div>';
    });
    h += '</div>';
    h += btn('BUILD URL', 'window._udBuild()');
    h += '<div id="ud-build-result" style="margin-top:12px;"></div>';
    return h;
  }

  window._udBuild = function() {
    var g = function(id) { return (document.getElementById(id) || {}).value || ''; };
    var proto = g('ud-b-proto') || 'https:';
    if (!proto.endsWith(':')) proto += ':';
    var host = g('ud-b-host') || 'example.com';
    var port = g('ud-b-port');
    var path = g('ud-b-path');
    if (path && !path.startsWith('/')) path = '/' + path;
    var query = g('ud-b-query');
    if (query && !query.startsWith('?')) query = '?' + query;
    var frag = g('ud-b-frag');
    if (frag && !frag.startsWith('#')) frag = '#' + frag;

    var url = proto + '//' + host + (port ? ':' + port : '') + (path || '/') + (query || '') + (frag || '');

    var h = '<div style="background:#060a14;border:1px solid ' + S.accent + '44;border-radius:4px;padding:10px;font-size:12px;word-break:break-all;color:' + S.accent + ';cursor:pointer;" onclick="navigator.clipboard.writeText(this.textContent)">' + esc(url) + '</div>';
    h += '<div style="font-size:9px;color:' + S.dim + ';margin-top:4px;">Click to copy</div>';
    var el = document.getElementById('ud-build-result');
    if (el) el.innerHTML = h;
  };

  // ── DEFANG / REFANG ──
  function renderDefang() {
    var h = '<div style="margin-bottom:12px;">' + ta('ud-defang', 'Paste URL(s) to defang or refang...', 5) + '</div>';
    h += '<div style="display:flex;gap:8px;margin-bottom:16px;">';
    h += btn('DEFANG →', 'window._udDefang()');
    h += btn('← REFANG', 'window._udRefang()', S.orange);
    h += '</div>';
    h += '<div id="ud-defang-result"></div>';
    return h;
  }

  function defangUrl(url) {
    return url
      .replace(/https?:\/\//gi, function(m) { return m.replace('http', 'hxxp'); })
      .replace(/ftp:\/\//gi, 'fxp://')
      .replace(/\./g, '[.]')
      .replace(/:\/\//g, '[://]');
  }

  function refangUrl(url) {
    return url
      .replace(/hxxps?/gi, function(m) { return m.replace('hxxp', 'http'); })
      .replace(/fxp/gi, 'ftp')
      .replace(/\[\.\]/g, '.')
      .replace(/\[:\/\/\]/g, '://');
  }

  window._udDefang = function() {
    var raw = (document.getElementById('ud-defang') || {}).value || '';
    var lines = raw.split('\n').filter(function(l) { return l.trim(); });
    var result = lines.map(function(l) { return defangUrl(l.trim()); }).join('\n');
    var el = document.getElementById('ud-defang-result');
    if (el) el.innerHTML = '<div style="background:#060a14;border:1px solid ' + S.green + '44;border-radius:4px;padding:10px;font-size:11px;color:' + S.green + ';white-space:pre-wrap;word-break:break-all;cursor:pointer;" onclick="navigator.clipboard.writeText(this.textContent)">' + esc(result) + '</div><div style="font-size:9px;color:' + S.dim + ';margin-top:4px;">Click to copy</div>';
  };

  window._udRefang = function() {
    var raw = (document.getElementById('ud-defang') || {}).value || '';
    var lines = raw.split('\n').filter(function(l) { return l.trim(); });
    var result = lines.map(function(l) { return refangUrl(l.trim()); }).join('\n');
    var el = document.getElementById('ud-defang-result');
    if (el) el.innerHTML = '<div style="background:#060a14;border:1px solid ' + S.orange + '44;border-radius:4px;padding:10px;font-size:11px;color:' + S.orange + ';white-space:pre-wrap;word-break:break-all;cursor:pointer;" onclick="navigator.clipboard.writeText(this.textContent)">' + esc(result) + '</div><div style="font-size:9px;color:' + S.dim + ';margin-top:4px;">Click to copy — CAUTION: these are live URLs</div>';
  };

  window._udTab = function(t) { activeTab = t; render(); };

  render();
};
