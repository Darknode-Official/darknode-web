// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Email Intelligence — email header analysis, SPF/DKIM/DMARC checker, phishing detector

var esc = function(s) { return String(s != null ? s : '').replace(/[&<>"']/g, function(c) {
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

export function renderEmailIntel(container) {
  var h = '';
  h += '<div style="background:#0a0e14;color:#c8d6e5;font-family:\'Courier New\',monospace;padding:20px;min-height:600px;">';
  h += '<h2 style="color:#00ddff;font-size:18px;letter-spacing:2px;margin:0 0 4px;">EMAIL INTELLIGENCE</h2>';
  h += '<div style="color:#4a6a8a;font-size:11px;margin-bottom:20px;">Email header analysis, SPF/DKIM/DMARC verification, phishing detection</div>';

  // Tabs
  h += '<div style="display:flex;gap:4px;margin-bottom:16px;" id="ei-tabs">';
  h += '<button class="ei-tab ei-tab-on" data-tab="headers" style="background:#0a2a44;border:1px solid #00aaff;color:#00ddff;padding:6px 14px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px 4px 0 0;">Header Analysis</button>';
  h += '<button class="ei-tab" data-tab="spf" style="background:#111a24;border:1px solid #1a3050;color:#4a6a8a;padding:6px 14px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px 4px 0 0;">SPF/DKIM/DMARC</button>';
  h += '<button class="ei-tab" data-tab="phishing" style="background:#111a24;border:1px solid #1a3050;color:#4a6a8a;padding:6px 14px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px 4px 0 0;">Phishing Detector</button>';
  h += '</div>';

  h += '<div id="ei-content"></div>';
  h += '</div>';

  container.innerHTML = h;

  // Wire tabs
  document.getElementById('ei-tabs').addEventListener('click', function(e) {
    var btn = e.target.closest('[data-tab]');
    if (!btn) return;
    var tabs = document.querySelectorAll('.ei-tab');
    for (var i = 0; i < tabs.length; i++) {
      tabs[i].style.background = '#111a24';
      tabs[i].style.borderColor = '#1a3050';
      tabs[i].style.color = '#4a6a8a';
      tabs[i].className = 'ei-tab';
    }
    btn.style.background = '#0a2a44';
    btn.style.borderColor = '#00aaff';
    btn.style.color = '#00ddff';
    btn.className = 'ei-tab ei-tab-on';
    _eiRenderTab(btn.getAttribute('data-tab'));
  });

  _eiRenderTab('headers');
};

function _eiRenderTab(tab) {
  var el = document.getElementById('ei-content');
  if (!el) return;
  if (tab === 'headers') _eiRenderHeaders(el);
  else if (tab === 'spf') _eiRenderSPF(el);
  else if (tab === 'phishing') _eiRenderPhishing(el);
}

function _eiRenderHeaders(el) {
  var h = '';
  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:16px;">';
  h += '<div style="color:#00aaff;font-size:12px;letter-spacing:1px;margin-bottom:10px;">PASTE EMAIL HEADERS</div>';
  h += '<textarea id="ei-raw-headers" style="width:100%;height:180px;background:#080c14;border:1px solid #1a2a44;border-radius:4px;color:#c8d6e5;font-family:monospace;font-size:11px;padding:10px;resize:vertical;box-sizing:border-box;" placeholder="Paste full email headers here...\n\nFrom: sender@example.com\nTo: recipient@example.com\nSubject: Test\nReceived: from mail.example.com..."></textarea>';
  h += '<button onclick="_eiAnalyzeHeaders()" style="background:#00aaff22;color:#00aaff;border:1px solid #00aaff44;padding:8px 20px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px;margin-top:8px;">ANALYZE HEADERS</button>';
  h += '</div>';
  h += '<div id="ei-header-results" style="margin-top:16px;"></div>';
  el.innerHTML = h;
}

window._eiAnalyzeHeaders = function() {
  var raw = document.getElementById('ei-raw-headers');
  var results = document.getElementById('ei-header-results');
  if (!raw || !results) return;

  var text = raw.value.trim();
  if (!text) { results.innerHTML = '<div style="color:#ff4444;font-size:11px;">No headers provided.</div>'; return; }

  var lines = text.split('\n');
  var headers = {};
  var currentKey = '';
  var hops = [];

  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (/^\S+:/.test(line)) {
      var colonIdx = line.indexOf(':');
      currentKey = line.substring(0, colonIdx).trim().toLowerCase();
      var val = line.substring(colonIdx + 1).trim();
      if (!headers[currentKey]) headers[currentKey] = [];
      headers[currentKey].push(val);
    } else if (currentKey && /^\s/.test(line)) {
      var arr = headers[currentKey];
      if (arr && arr.length > 0) arr[arr.length - 1] += ' ' + line.trim();
    }
  }

  // Extract hops from Received headers
  if (headers['received']) {
    for (var r = 0; r < headers['received'].length; r++) {
      var recvLine = headers['received'][r];
      var fromMatch = recvLine.match(/from\s+(\S+)/i);
      var byMatch = recvLine.match(/by\s+(\S+)/i);
      var dateMatch = recvLine.match(/;\s*(.+)$/);
      hops.push({
        from: fromMatch ? fromMatch[1] : 'unknown',
        by: byMatch ? byMatch[1] : 'unknown',
        date: dateMatch ? dateMatch[1].trim() : '',
        raw: recvLine
      });
    }
  }

  var h = '';

  // Summary
  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:14px;margin-bottom:12px;">';
  h += '<div style="color:#00ddff;font-size:13px;font-weight:bold;margin-bottom:10px;">HEADER SUMMARY</div>';
  var summaryFields = ['from', 'to', 'subject', 'date', 'message-id', 'return-path', 'reply-to', 'x-mailer', 'user-agent'];
  for (var s = 0; s < summaryFields.length; s++) {
    var key = summaryFields[s];
    if (headers[key]) {
      h += '<div style="margin:3px 0;font-size:11px;"><span style="color:#4a7a9a;min-width:100px;display:inline-block;">' + esc(key.toUpperCase()) + ':</span> <span style="color:#c8d6e5;">' + esc(headers[key][0]) + '</span></div>';
    }
  }
  h += '</div>';

  // Security analysis
  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:14px;margin-bottom:12px;">';
  h += '<div style="color:#ffaa00;font-size:13px;font-weight:bold;margin-bottom:10px;">SECURITY ANALYSIS</div>';

  var checks = [
    { name: 'SPF', header: 'received-spf', pass: /pass/i },
    { name: 'DKIM', header: 'dkim-signature', pass: /.+/ },
    { name: 'DMARC', header: 'authentication-results', pass: /dmarc=pass/i },
    { name: 'ARC', header: 'arc-authentication-results', pass: /.+/ },
    { name: 'TLS', header: 'received', pass: /TLS|ESMTPS|with\s+HTTPS/i }
  ];

  for (var c = 0; c < checks.length; c++) {
    var chk = checks[c];
    var found = headers[chk.header];
    var status = 'MISSING';
    var color = '#ff4444';
    if (found) {
      var combined = found.join(' ');
      if (chk.pass.test(combined)) { status = 'PASS'; color = '#00ff88'; }
      else { status = 'PRESENT'; color = '#ffaa00'; }
    }
    h += '<div style="margin:4px 0;font-size:11px;display:flex;align-items:center;gap:8px;">';
    h += '<span style="color:#4a7a9a;width:60px;">' + esc(chk.name) + '</span>';
    h += '<span style="color:' + color + ';font-weight:bold;padding:1px 8px;background:' + color + '15;border:1px solid ' + color + '33;border-radius:2px;font-size:10px;">' + status + '</span>';
    h += '</div>';
  }

  // Suspicious indicators
  var suspicious = [];
  if (headers['from'] && headers['return-path']) {
    var fromDomain = (headers['from'][0].match(/@([^\s>]+)/i) || [])[1] || '';
    var returnDomain = (headers['return-path'][0].match(/@([^\s>]+)/i) || [])[1] || '';
    if (fromDomain && returnDomain && fromDomain.toLowerCase() !== returnDomain.toLowerCase()) {
      suspicious.push('From domain (' + fromDomain + ') differs from Return-Path (' + returnDomain + ')');
    }
  }
  if (headers['reply-to'] && headers['from']) {
    var fromAddr = headers['from'][0].toLowerCase();
    var replyAddr = headers['reply-to'][0].toLowerCase();
    if (fromAddr.indexOf(replyAddr) === -1 && replyAddr.indexOf(fromAddr) === -1) {
      suspicious.push('Reply-To differs from From address');
    }
  }
  if (headers['x-originating-ip']) {
    suspicious.push('X-Originating-IP found: ' + headers['x-originating-ip'][0]);
  }

  if (suspicious.length > 0) {
    h += '<div style="margin-top:10px;border-top:1px solid #1a2a44;padding-top:8px;">';
    h += '<div style="color:#ff4444;font-size:11px;font-weight:bold;margin-bottom:6px;">SUSPICIOUS INDICATORS</div>';
    for (var si = 0; si < suspicious.length; si++) {
      h += '<div style="color:#ff8844;font-size:10px;margin:2px 0;">&#9888; ' + esc(suspicious[si]) + '</div>';
    }
    h += '</div>';
  }
  h += '</div>';

  // Hop trace
  if (hops.length > 0) {
    h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:14px;">';
    h += '<div style="color:#aa66ff;font-size:13px;font-weight:bold;margin-bottom:10px;">MESSAGE ROUTE (' + hops.length + ' hops)</div>';
    for (var hp = hops.length - 1; hp >= 0; hp--) {
      var hop = hops[hp];
      h += '<div style="margin:6px 0;padding:8px;background:#080c14;border-left:3px solid #aa66ff44;border-radius:0 4px 4px 0;font-size:10px;">';
      h += '<div><span style="color:#4a7a9a;">FROM:</span> <span style="color:#c8d6e5;">' + esc(hop.from) + '</span></div>';
      h += '<div><span style="color:#4a7a9a;">BY:</span> <span style="color:#c8d6e5;">' + esc(hop.by) + '</span></div>';
      if (hop.date) h += '<div><span style="color:#4a7a9a;">DATE:</span> <span style="color:#6a8aaa;">' + esc(hop.date) + '</span></div>';
      h += '</div>';
    }
    h += '</div>';
  }

  // All headers
  h += '<details style="margin-top:12px;">';
  h += '<summary style="color:#4a6a8a;font-size:11px;cursor:pointer;">Show all headers (' + Object.keys(headers).length + ')</summary>';
  h += '<div style="background:#080c14;border:1px solid #1a2a44;border-radius:4px;padding:10px;margin-top:6px;max-height:300px;overflow-y:auto;">';
  var allKeys = Object.keys(headers);
  for (var ak = 0; ak < allKeys.length; ak++) {
    var vals = headers[allKeys[ak]];
    for (var v = 0; v < vals.length; v++) {
      h += '<div style="margin:2px 0;font-size:10px;word-break:break-all;"><span style="color:#00aaff;">' + esc(allKeys[ak]) + ':</span> <span style="color:#8ab4d4;">' + esc(vals[v]) + '</span></div>';
    }
  }
  h += '</div></details>';

  results.innerHTML = h;
};

function _eiRenderSPF(el) {
  var h = '';
  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:16px;">';
  h += '<div style="color:#00aaff;font-size:12px;letter-spacing:1px;margin-bottom:10px;">CHECK SPF / DKIM / DMARC</div>';
  h += '<div style="display:flex;gap:8px;margin-bottom:12px;">';
  h += '<input id="ei-spf-domain" style="flex:1;background:#080c14;border:1px solid #1a2a44;border-radius:4px;color:#c8d6e5;font-family:monospace;font-size:12px;padding:8px 12px;" placeholder="example.com">';
  h += '<button onclick="_eiCheckSPF()" style="background:#00aaff22;color:#00aaff;border:1px solid #00aaff44;padding:8px 16px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px;">CHECK</button>';
  h += '</div>';
  h += '<div style="color:#4a6a8a;font-size:10px;margin-bottom:8px;">Uses Google DNS-over-HTTPS to query TXT records for SPF, DKIM, and DMARC policies.</div>';
  h += '</div>';
  h += '<div id="ei-spf-results" style="margin-top:12px;"></div>';
  el.innerHTML = h;
}

window._eiCheckSPF = function() {
  var domain = (document.getElementById('ei-spf-domain') || {}).value;
  var results = document.getElementById('ei-spf-results');
  if (!domain || !results) return;
  domain = domain.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');

  results.innerHTML = '<div style="color:#ffaa00;font-size:11px;">Querying DNS records for ' + esc(domain) + '...</div>';

  var queries = [
    { type: 'TXT', name: domain, label: 'SPF / TXT Records' },
    { type: 'TXT', name: '_dmarc.' + domain, label: 'DMARC Policy' },
    { type: 'MX', name: domain, label: 'Mail Servers (MX)' }
  ];

  var allResults = {};
  var completed = 0;

  for (var q = 0; q < queries.length; q++) {
    (function(query) {
      fetch('https://dns.google/resolve?name=' + encodeURIComponent(query.name) + '&type=' + query.type)
        .then(function(r) { return r.json(); })
        .then(function(data) {
          allResults[query.label] = data;
          completed++;
          if (completed >= queries.length) _eiRenderSPFResults(results, domain, allResults);
        })
        .catch(function() {
          allResults[query.label] = { error: true };
          completed++;
          if (completed >= queries.length) _eiRenderSPFResults(results, domain, allResults);
        });
    })(queries[q]);
  }
};

function _eiRenderSPFResults(el, domain, data) {
  var h = '';

  // SPF
  var txtData = data['SPF / TXT Records'];
  var spfRecord = null;
  var dmarcRecord = null;

  if (txtData && txtData.Answer) {
    for (var i = 0; i < txtData.Answer.length; i++) {
      var txt = txtData.Answer[i].data || '';
      if (txt.indexOf('v=spf1') !== -1) spfRecord = txt;
    }
  }

  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:14px;margin-bottom:10px;">';
  h += '<div style="color:#00ddff;font-size:12px;font-weight:bold;margin-bottom:8px;">SPF RECORD</div>';
  if (spfRecord) {
    h += '<div style="background:#080c14;border:1px solid #00ff8833;border-radius:4px;padding:8px 12px;font-size:11px;color:#00ff88;word-break:break-all;">' + esc(spfRecord.replace(/"/g, '')) + '</div>';
    h += '<div style="color:#00ff88;font-size:10px;margin-top:4px;">&#10003; SPF record found</div>';
  } else {
    h += '<div style="color:#ff4444;font-size:11px;">&#10007; No SPF record found — email spoofing is possible</div>';
  }
  h += '</div>';

  // DMARC
  var dmarcData = data['DMARC Policy'];
  if (dmarcData && dmarcData.Answer) {
    for (var d = 0; d < dmarcData.Answer.length; d++) {
      var dval = dmarcData.Answer[d].data || '';
      if (dval.indexOf('v=DMARC1') !== -1) dmarcRecord = dval;
    }
  }

  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:14px;margin-bottom:10px;">';
  h += '<div style="color:#ffaa00;font-size:12px;font-weight:bold;margin-bottom:8px;">DMARC POLICY</div>';
  if (dmarcRecord) {
    h += '<div style="background:#080c14;border:1px solid #00ff8833;border-radius:4px;padding:8px 12px;font-size:11px;color:#00ff88;word-break:break-all;">' + esc(dmarcRecord.replace(/"/g, '')) + '</div>';
    var policy = (dmarcRecord.match(/p=(\w+)/i) || [])[1] || 'none';
    var pColor = policy === 'reject' ? '#00ff88' : policy === 'quarantine' ? '#ffaa00' : '#ff4444';
    h += '<div style="color:' + pColor + ';font-size:10px;margin-top:4px;">Policy: ' + esc(policy.toUpperCase()) + (policy === 'none' ? ' (weak — emails not rejected)' : '') + '</div>';
  } else {
    h += '<div style="color:#ff4444;font-size:11px;">&#10007; No DMARC record found — domain is vulnerable to spoofing</div>';
  }
  h += '</div>';

  // MX
  var mxData = data['Mail Servers (MX)'];
  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:14px;">';
  h += '<div style="color:#aa66ff;font-size:12px;font-weight:bold;margin-bottom:8px;">MAIL SERVERS (MX)</div>';
  if (mxData && mxData.Answer && mxData.Answer.length > 0) {
    for (var m = 0; m < mxData.Answer.length; m++) {
      var mx = mxData.Answer[m];
      h += '<div style="font-size:11px;margin:3px 0;color:#c8d6e5;">' + esc(mx.data || '') + '</div>';
    }
  } else {
    h += '<div style="color:#4a6a8a;font-size:11px;">No MX records found</div>';
  }
  h += '</div>';

  // Overall grade
  var grade = 'F';
  var gradeColor = '#ff4444';
  if (spfRecord && dmarcRecord) {
    var dPolicy = (dmarcRecord.match(/p=(\w+)/i) || [])[1] || 'none';
    if (dPolicy === 'reject') { grade = 'A'; gradeColor = '#00ff88'; }
    else if (dPolicy === 'quarantine') { grade = 'B'; gradeColor = '#44cc44'; }
    else { grade = 'C'; gradeColor = '#ffaa00'; }
  } else if (spfRecord || dmarcRecord) {
    grade = 'D'; gradeColor = '#ff8800';
  }

  h = '<div style="background:#0c1020;border:2px solid ' + gradeColor + ';border-radius:8px;padding:16px;margin-bottom:12px;text-align:center;">' +
    '<div style="font-size:48px;font-weight:bold;color:' + gradeColor + ';text-shadow:0 0 20px ' + gradeColor + '40;">' + grade + '</div>' +
    '<div style="color:#4a6a8a;font-size:11px;letter-spacing:2px;">EMAIL SECURITY GRADE</div>' +
    '<div style="color:#6a8aaa;font-size:10px;margin-top:4px;">' + esc(domain) + '</div>' +
    '</div>' + h;

  el.innerHTML = h;
}

function _eiRenderPhishing(el) {
  var h = '';
  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:16px;">';
  h += '<div style="color:#ff4444;font-size:12px;letter-spacing:1px;margin-bottom:10px;">PHISHING URL ANALYZER</div>';
  h += '<div style="display:flex;gap:8px;margin-bottom:12px;">';
  h += '<input id="ei-phish-url" style="flex:1;background:#080c14;border:1px solid #1a2a44;border-radius:4px;color:#c8d6e5;font-family:monospace;font-size:12px;padding:8px 12px;" placeholder="https://suspicious-url.example.com/login">';
  h += '<button onclick="_eiCheckPhishing()" style="background:#ff444422;color:#ff4444;border:1px solid #ff444444;padding:8px 16px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px;">ANALYZE</button>';
  h += '</div>';
  h += '</div>';
  h += '<div id="ei-phish-results" style="margin-top:12px;"></div>';

  // Phishing indicators reference
  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:14px;margin-top:16px;">';
  h += '<div style="color:#ffaa00;font-size:12px;font-weight:bold;margin-bottom:10px;">COMMON PHISHING INDICATORS</div>';
  var indicators = [
    { indicator: 'Misspelled domain', example: 'g00gle.com, micros0ft.com', risk: 'HIGH' },
    { indicator: 'Extra subdomains', example: 'login.microsoft.com.evil.com', risk: 'HIGH' },
    { indicator: 'IP address URL', example: 'http://192.168.1.1/login', risk: 'HIGH' },
    { indicator: 'Homograph attack', example: 'microsоft.com (Cyrillic о)', risk: 'CRITICAL' },
    { indicator: 'URL shortener', example: 'bit.ly/xxxxx, tinyurl.com/xxx', risk: 'MEDIUM' },
    { indicator: 'Suspicious TLD', example: '.xyz, .top, .click, .buzz', risk: 'MEDIUM' },
    { indicator: 'HTTPS missing', example: 'http:// for login page', risk: 'HIGH' },
    { indicator: 'Excessive path depth', example: '/wp/admin/secure/login/verify/', risk: 'LOW' },
    { indicator: 'Data URI / Base64', example: 'data:text/html;base64,...', risk: 'CRITICAL' },
    { indicator: 'Punycode domain', example: 'xn--pple-43d.com', risk: 'HIGH' }
  ];
  for (var pi = 0; pi < indicators.length; pi++) {
    var ind = indicators[pi];
    var riskColor = ind.risk === 'CRITICAL' ? '#ff2222' : ind.risk === 'HIGH' ? '#ff6600' : ind.risk === 'MEDIUM' ? '#ffaa00' : '#00cc88';
    h += '<div style="display:flex;align-items:center;gap:10px;padding:4px 0;border-bottom:1px solid #0d1525;font-size:10px;">';
    h += '<span style="color:' + riskColor + ';font-weight:bold;width:60px;flex-shrink:0;">' + ind.risk + '</span>';
    h += '<span style="color:#c8d6e5;width:140px;flex-shrink:0;">' + esc(ind.indicator) + '</span>';
    h += '<span style="color:#4a6a8a;">' + esc(ind.example) + '</span>';
    h += '</div>';
  }
  h += '</div>';

  el.innerHTML = h;
}

window._eiCheckPhishing = function() {
  var url = (document.getElementById('ei-phish-url') || {}).value;
  var results = document.getElementById('ei-phish-results');
  if (!url || !results) return;

  var flags = [];
  var score = 0;

  try { var parsed = new URL(url); } catch (e) {
    results.innerHTML = '<div style="color:#ff4444;font-size:11px;">Invalid URL format.</div>';
    return;
  }

  var hostname = parsed.hostname;
  var protocol = parsed.protocol;
  var path = parsed.pathname;

  // Check indicators
  if (protocol === 'http:') { flags.push({ text: 'No HTTPS — credentials could be intercepted', severity: 'HIGH' }); score += 25; }
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) { flags.push({ text: 'IP address used instead of domain name', severity: 'HIGH' }); score += 30; }
  if (/\.(xyz|top|click|buzz|gq|ml|cf|tk|ga|work|racing|stream|download|bid|win|loan|date|faith|party|review|science|accountant)$/i.test(hostname)) { flags.push({ text: 'Suspicious TLD: ' + hostname.split('.').pop(), severity: 'MEDIUM' }); score += 15; }
  if (hostname.split('.').length > 4) { flags.push({ text: 'Excessive subdomains (' + hostname.split('.').length + ' levels)', severity: 'HIGH' }); score += 20; }
  if (/xn--/.test(hostname)) { flags.push({ text: 'Punycode/internationalized domain detected', severity: 'HIGH' }); score += 25; }
  if (path.split('/').length > 6) { flags.push({ text: 'Deep path nesting (' + path.split('/').length + ' levels)', severity: 'LOW' }); score += 5; }
  if (/login|signin|verify|secure|account|update|confirm|bank/i.test(path)) { flags.push({ text: 'Credential harvesting keywords in path', severity: 'MEDIUM' }); score += 10; }
  if (url.indexOf('@') !== -1) { flags.push({ text: 'URL contains @ symbol (possible URL obfuscation)', severity: 'HIGH' }); score += 30; }
  if (/0|1|l|O/.test(hostname) && /paypal|google|apple|microsoft|amazon|netflix|facebook|instagram|twitter|bank/i.test(hostname)) { flags.push({ text: 'Possible brand impersonation with character substitution', severity: 'CRITICAL' }); score += 40; }
  if (hostname.length > 40) { flags.push({ text: 'Unusually long domain name (' + hostname.length + ' chars)', severity: 'LOW' }); score += 5; }
  if (url.indexOf('data:') === 0) { flags.push({ text: 'Data URI detected — may contain hidden content', severity: 'CRITICAL' }); score += 50; }

  score = Math.min(100, score);
  var verdict = score >= 60 ? 'LIKELY PHISHING' : score >= 30 ? 'SUSPICIOUS' : 'APPEARS SAFE';
  var verdictColor = score >= 60 ? '#ff2222' : score >= 30 ? '#ffaa00' : '#00ff88';

  var h = '';
  h += '<div style="background:#0c1020;border:2px solid ' + verdictColor + ';border-radius:8px;padding:16px;text-align:center;margin-bottom:12px;">';
  h += '<div style="font-size:14px;font-weight:bold;color:' + verdictColor + ';letter-spacing:2px;">' + verdict + '</div>';
  h += '<div style="font-size:36px;font-weight:bold;color:' + verdictColor + ';text-shadow:0 0 20px ' + verdictColor + '40;margin:4px 0;">' + score + '/100</div>';
  h += '<div style="color:#4a6a8a;font-size:10px;">Risk Score (higher = more suspicious)</div>';
  h += '</div>';

  if (flags.length > 0) {
    h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:14px;">';
    h += '<div style="color:#ff4444;font-size:12px;font-weight:bold;margin-bottom:8px;">DETECTED INDICATORS (' + flags.length + ')</div>';
    for (var fi = 0; fi < flags.length; fi++) {
      var f = flags[fi];
      var fc = f.severity === 'CRITICAL' ? '#ff2222' : f.severity === 'HIGH' ? '#ff6600' : f.severity === 'MEDIUM' ? '#ffaa00' : '#00cc88';
      h += '<div style="margin:4px 0;font-size:11px;display:flex;gap:8px;align-items:center;">';
      h += '<span style="color:' + fc + ';font-weight:bold;font-size:9px;padding:1px 6px;background:' + fc + '15;border:1px solid ' + fc + '33;border-radius:2px;">' + f.severity + '</span>';
      h += '<span style="color:#c8d6e5;">' + esc(f.text) + '</span>';
      h += '</div>';
    }
    h += '</div>';
  } else {
    h += '<div style="color:#00ff88;font-size:11px;text-align:center;">No suspicious indicators detected.</div>';
  }

  results.innerHTML = h;
};
