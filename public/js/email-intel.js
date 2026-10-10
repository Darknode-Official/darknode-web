// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved.
// Email Intelligence — email header analysis, SPF/DKIM/DMARC checker, phishing detector

var esc = function(s) { return String(s != null ? s : '').replace(/[&<>"']/g, function(c) {
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

export function renderEmailIntel(container) {
  var h = '';
  h += '<div style="color:var(--txt,#e7eefc);padding:4px 2px;min-height:600px;">';
  h += '<h2 style="color:var(--txt,#e7eefc);font-size:20px;font-weight:700;letter-spacing:-.01em;margin:0 0 4px;">Email Intelligence</h2>';
  h += '<div style="color:var(--txt-2,#9fb0cc);font-size:13px;margin-bottom:20px;">Email header analysis, SPF/DKIM/DMARC verification, phishing detection</div>';

  // Tabs
  h += '<div style="display:flex;gap:6px;margin-bottom:16px;border-bottom:1px solid var(--line,#283a5a);" id="ei-tabs">';
  h += '<button class="ei-tab ei-tab-on" data-tab="headers" style="background:var(--card2,#0f1726);border:1px solid var(--acc,#2563eb);border-bottom:none;color:var(--txt,#e7eefc);padding:8px 16px;font-size:12px;font-weight:600;cursor:pointer;border-radius:8px 8px 0 0;">Header Analysis</button>';
  h += '<button class="ei-tab" data-tab="spf" style="background:transparent;border:1px solid var(--line,#283a5a);border-bottom:none;color:var(--txt-2,#9fb0cc);padding:8px 16px;font-size:12px;font-weight:600;cursor:pointer;border-radius:8px 8px 0 0;">SPF/DKIM/DMARC</button>';
  h += '<button class="ei-tab" data-tab="phishing" style="background:transparent;border:1px solid var(--line,#283a5a);border-bottom:none;color:var(--txt-2,#9fb0cc);padding:8px 16px;font-size:12px;font-weight:600;cursor:pointer;border-radius:8px 8px 0 0;">Phishing Detector</button>';
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
      tabs[i].style.background = 'transparent';
      tabs[i].style.borderColor = 'var(--line,#283a5a)';
      tabs[i].style.color = 'var(--txt-2,#9fb0cc)';
      tabs[i].className = 'ei-tab';
    }
    btn.style.background = 'var(--card2,#0f1726)';
    btn.style.borderColor = 'var(--acc,#2563eb)';
    btn.style.color = 'var(--txt,#e7eefc)';
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
  h += '<div style="background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);border-radius:10px;padding:16px;">';
  h += '<div style="color:var(--txt-2,#9fb0cc);font-size:12px;font-weight:600;letter-spacing:.02em;margin-bottom:10px;">PASTE EMAIL HEADERS</div>';
  h += '<textarea id="ei-raw-headers" style="width:100%;height:180px;background:var(--card,#0b1120);border:1px solid var(--line,#283a5a);border-radius:8px;color:var(--txt,#e7eefc);font-family:var(--font-mono,ui-monospace,monospace);font-size:12px;padding:10px;resize:vertical;box-sizing:border-box;" placeholder="Paste full email headers here...\n\nFrom: sender@example.com\nTo: recipient@example.com\nSubject: Test\nReceived: from mail.example.com..."></textarea>';
  h += '<button onclick="_eiAnalyzeHeaders()" style="background:var(--acc,#2563eb);color:#fff;border:none;padding:9px 20px;font-size:12px;font-weight:600;cursor:pointer;border-radius:8px;margin-top:10px;">Analyze Headers</button>';
  h += '</div>';
  h += '<div id="ei-header-results" style="margin-top:16px;"></div>';
  el.innerHTML = h;
}

window._eiAnalyzeHeaders = function() {
  var raw = document.getElementById('ei-raw-headers');
  var results = document.getElementById('ei-header-results');
  if (!raw || !results) return;

  var text = raw.value.trim();
  if (!text) { results.innerHTML = '<div style="color:#dc2626;font-size:12px;">No headers provided.</div>'; return; }

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
  h += '<div style="background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);border-radius:10px;padding:14px;margin-bottom:12px;">';
  h += '<div style="color:var(--txt,#e7eefc);font-size:13px;font-weight:700;margin-bottom:10px;">Header Summary</div>';
  var summaryFields = ['from', 'to', 'subject', 'date', 'message-id', 'return-path', 'reply-to', 'x-mailer', 'user-agent'];
  for (var s = 0; s < summaryFields.length; s++) {
    var key = summaryFields[s];
    if (headers[key]) {
      h += '<div style="margin:3px 0;font-size:12px;"><span style="color:var(--mut,#7a93b8);min-width:110px;display:inline-block;">' + esc(key.toUpperCase()) + ':</span> <span style="color:var(--txt,#e7eefc);font-family:var(--font-mono,ui-monospace,monospace);">' + esc(headers[key][0]) + '</span></div>';
    }
  }
  h += '</div>';

  // Security analysis
  h += '<div style="background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);border-radius:10px;padding:14px;margin-bottom:12px;">';
  h += '<div style="color:var(--txt,#e7eefc);font-size:13px;font-weight:700;margin-bottom:10px;">Security Analysis</div>';

  var checks = [
    { name: 'SPF', header: 'received-spf', pass: /pass/i },
    { name: 'DKIM', header: 'authentication-results', pass: /dkim=pass/i },
    { name: 'DMARC', header: 'authentication-results', pass: /dmarc=pass/i },
    { name: 'ARC', header: 'arc-authentication-results', pass: /arc=pass/i },
    { name: 'TLS', header: 'received', pass: /TLS|ESMTPS|with\s+HTTPS/i }
  ];

  for (var c = 0; c < checks.length; c++) {
    var chk = checks[c];
    var found = headers[chk.header];
    var status = 'MISSING';
    var color = '#dc2626';
    if (found) {
      var combined = found.join(' ');
      if (chk.pass.test(combined)) { status = 'PASS'; color = '#16a34a'; }
      else { status = 'PRESENT'; color = '#d97706'; }
    }
    h += '<div style="margin:4px 0;font-size:12px;display:flex;align-items:center;gap:8px;">';
    h += '<span style="color:var(--mut,#7a93b8);width:60px;">' + esc(chk.name) + '</span>';
    h += '<span style="color:' + color + ';font-weight:700;padding:2px 8px;background:' + color + '1a;border:1px solid ' + color + '40;border-radius:4px;font-size:10px;">' + status + '</span>';
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
    h += '<div style="margin-top:10px;border-top:1px solid var(--line,#283a5a);padding-top:10px;">';
    h += '<div style="color:#dc2626;font-size:12px;font-weight:700;margin-bottom:6px;">Suspicious Indicators</div>';
    for (var si = 0; si < suspicious.length; si++) {
      h += '<div style="color:#ea580c;font-size:11px;margin:3px 0;">Warning: ' + esc(suspicious[si]) + '</div>';
    }
    h += '</div>';
  }
  h += '</div>';

  // Hop trace
  if (hops.length > 0) {
    h += '<div style="background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);border-radius:10px;padding:14px;">';
    h += '<div style="color:var(--txt,#e7eefc);font-size:13px;font-weight:700;margin-bottom:10px;">Message Route (' + hops.length + ' hops)</div>';
    for (var hp = hops.length - 1; hp >= 0; hp--) {
      var hop = hops[hp];
      h += '<div style="margin:6px 0;padding:8px 10px;background:var(--card,#0b1120);border-left:3px solid var(--acc,#2563eb);border-radius:0 6px 6px 0;font-size:11px;">';
      h += '<div><span style="color:var(--mut,#7a93b8);">FROM:</span> <span style="color:var(--txt,#e7eefc);font-family:var(--font-mono,ui-monospace,monospace);">' + esc(hop.from) + '</span></div>';
      h += '<div><span style="color:var(--mut,#7a93b8);">BY:</span> <span style="color:var(--txt,#e7eefc);font-family:var(--font-mono,ui-monospace,monospace);">' + esc(hop.by) + '</span></div>';
      if (hop.date) h += '<div><span style="color:var(--mut,#7a93b8);">DATE:</span> <span style="color:var(--txt-2,#9fb0cc);">' + esc(hop.date) + '</span></div>';
      h += '</div>';
    }
    h += '</div>';
  }

  // All headers
  h += '<details style="margin-top:12px;">';
  h += '<summary style="color:var(--txt-2,#9fb0cc);font-size:12px;cursor:pointer;">Show all headers (' + Object.keys(headers).length + ')</summary>';
  h += '<div style="background:var(--card,#0b1120);border:1px solid var(--line,#283a5a);border-radius:8px;padding:10px;margin-top:6px;max-height:300px;overflow-y:auto;">';
  var allKeys = Object.keys(headers);
  for (var ak = 0; ak < allKeys.length; ak++) {
    var vals = headers[allKeys[ak]];
    for (var v = 0; v < vals.length; v++) {
      h += '<div style="margin:2px 0;font-size:11px;word-break:break-all;font-family:var(--font-mono,ui-monospace,monospace);"><span style="color:var(--acc,#2563eb);">' + esc(allKeys[ak]) + ':</span> <span style="color:var(--txt-2,#9fb0cc);">' + esc(vals[v]) + '</span></div>';
    }
  }
  h += '</div></details>';

  results.innerHTML = h;
};

function _eiRenderSPF(el) {
  var h = '';
  h += '<div style="background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);border-radius:10px;padding:16px;">';
  h += '<div style="color:var(--txt-2,#9fb0cc);font-size:12px;font-weight:600;letter-spacing:.02em;margin-bottom:10px;">CHECK SPF / DKIM / DMARC</div>';
  h += '<div style="display:flex;gap:8px;margin-bottom:12px;">';
  h += '<input id="ei-spf-domain" style="flex:1;background:var(--card,#0b1120);border:1px solid var(--line,#283a5a);border-radius:8px;color:var(--txt,#e7eefc);font-family:var(--font-mono,ui-monospace,monospace);font-size:13px;padding:9px 12px;" placeholder="example.com">';
  h += '<button onclick="_eiCheckSPF()" style="background:var(--acc,#2563eb);color:#fff;border:none;padding:9px 18px;font-size:12px;font-weight:600;cursor:pointer;border-radius:8px;">Check</button>';
  h += '</div>';
  h += '<div style="color:var(--mut,#7a93b8);font-size:11px;margin-bottom:8px;">Uses Google DNS-over-HTTPS to query TXT records for SPF, DKIM, and DMARC policies.</div>';
  h += '</div>';
  h += '<div id="ei-spf-results" style="margin-top:12px;"></div>';
  el.innerHTML = h;
}

window._eiCheckSPF = function() {
  var domain = (document.getElementById('ei-spf-domain') || {}).value;
  var results = document.getElementById('ei-spf-results');
  if (!domain || !results) return;
  domain = domain.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');

  results.innerHTML = '<div style="color:var(--warn,#d97706);font-size:12px;">Querying DNS records for ' + esc(domain) + '...</div>';

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

  h += '<div style="background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);border-radius:10px;padding:14px;margin-bottom:10px;">';
  h += '<div style="color:var(--txt,#e7eefc);font-size:13px;font-weight:700;margin-bottom:8px;">SPF Record</div>';
  if (spfRecord) {
    h += '<div style="background:var(--card,#0b1120);border:1px solid #16a34a40;border-radius:8px;padding:8px 12px;font-size:12px;font-family:var(--font-mono,ui-monospace,monospace);color:#16a34a;word-break:break-all;">' + esc(spfRecord.replace(/"/g, '')) + '</div>';
    h += '<div style="color:#16a34a;font-size:11px;margin-top:6px;">SPF record found</div>';
  } else {
    h += '<div style="color:#dc2626;font-size:12px;">No SPF record found — email spoofing is possible</div>';
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

  h += '<div style="background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);border-radius:10px;padding:14px;margin-bottom:10px;">';
  h += '<div style="color:var(--txt,#e7eefc);font-size:13px;font-weight:700;margin-bottom:8px;">DMARC Policy</div>';
  if (dmarcRecord) {
    h += '<div style="background:var(--card,#0b1120);border:1px solid #16a34a40;border-radius:8px;padding:8px 12px;font-size:12px;font-family:var(--font-mono,ui-monospace,monospace);color:#16a34a;word-break:break-all;">' + esc(dmarcRecord.replace(/"/g, '')) + '</div>';
    var policy = (dmarcRecord.match(/(?:^|[;\s])p=(\w+)/i) || [])[1] || 'none';
    var pColor = policy === 'reject' ? '#16a34a' : policy === 'quarantine' ? '#d97706' : '#dc2626';
    h += '<div style="color:' + pColor + ';font-size:11px;margin-top:6px;">Policy: ' + esc(policy.toUpperCase()) + (policy === 'none' ? ' (weak — emails not rejected)' : '') + '</div>';
  } else {
    h += '<div style="color:#dc2626;font-size:12px;">No DMARC record found — domain is vulnerable to spoofing</div>';
  }
  h += '</div>';

  // MX
  var mxData = data['Mail Servers (MX)'];
  h += '<div style="background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);border-radius:10px;padding:14px;">';
  h += '<div style="color:var(--txt,#e7eefc);font-size:13px;font-weight:700;margin-bottom:8px;">Mail Servers (MX)</div>';
  if (mxData && mxData.Answer && mxData.Answer.length > 0) {
    for (var m = 0; m < mxData.Answer.length; m++) {
      var mx = mxData.Answer[m];
      h += '<div style="font-size:12px;margin:3px 0;color:var(--txt,#e7eefc);font-family:var(--font-mono,ui-monospace,monospace);">' + esc(mx.data || '') + '</div>';
    }
  } else {
    h += '<div style="color:var(--mut,#7a93b8);font-size:12px;">No MX records found</div>';
  }
  h += '</div>';

  // Overall grade
  var grade = 'F';
  var gradeColor = '#dc2626';
  if (spfRecord && dmarcRecord) {
    var dPolicy = (dmarcRecord.match(/(?:^|[;\s])p=(\w+)/i) || [])[1] || 'none';
    if (dPolicy === 'reject') { grade = 'A'; gradeColor = '#16a34a'; }
    else if (dPolicy === 'quarantine') { grade = 'B'; gradeColor = '#22c55e'; }
    else { grade = 'C'; gradeColor = '#d97706'; }
  } else if (spfRecord || dmarcRecord) {
    grade = 'D'; gradeColor = '#ea580c';
  }

  h = '<div style="background:var(--card2,#0f1726);border:1px solid ' + gradeColor + ';border-radius:12px;padding:16px;margin-bottom:12px;text-align:center;">' +
    '<div style="font-size:48px;font-weight:800;color:' + gradeColor + ';">' + grade + '</div>' +
    '<div style="color:var(--txt-2,#9fb0cc);font-size:11px;letter-spacing:.08em;">EMAIL SECURITY GRADE</div>' +
    '<div style="color:var(--mut,#7a93b8);font-size:11px;margin-top:4px;font-family:var(--font-mono,ui-monospace,monospace);">' + esc(domain) + '</div>' +
    '</div>' + h;

  el.innerHTML = h;
}

function _eiRenderPhishing(el) {
  var h = '';
  h += '<div style="background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);border-radius:10px;padding:16px;">';
  h += '<div style="color:var(--txt-2,#9fb0cc);font-size:12px;font-weight:600;letter-spacing:.02em;margin-bottom:10px;">PHISHING URL ANALYZER</div>';
  h += '<div style="display:flex;gap:8px;margin-bottom:12px;">';
  h += '<input id="ei-phish-url" style="flex:1;background:var(--card,#0b1120);border:1px solid var(--line,#283a5a);border-radius:8px;color:var(--txt,#e7eefc);font-family:var(--font-mono,ui-monospace,monospace);font-size:13px;padding:9px 12px;" placeholder="https://suspicious-url.example.com/login">';
  h += '<button onclick="_eiCheckPhishing()" style="background:var(--acc,#2563eb);color:#fff;border:none;padding:9px 18px;font-size:12px;font-weight:600;cursor:pointer;border-radius:8px;">Analyze</button>';
  h += '</div>';
  h += '</div>';
  h += '<div id="ei-phish-results" style="margin-top:12px;"></div>';

  // Phishing indicators reference
  h += '<div style="background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);border-radius:10px;padding:14px;margin-top:16px;">';
  h += '<div style="color:var(--txt,#e7eefc);font-size:13px;font-weight:700;margin-bottom:10px;">Common Phishing Indicators</div>';
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
    var riskColor = ind.risk === 'CRITICAL' ? '#b91c1c' : ind.risk === 'HIGH' ? '#ea580c' : ind.risk === 'MEDIUM' ? '#d97706' : '#16a34a';
    h += '<div style="display:flex;align-items:center;gap:10px;padding:5px 0;border-bottom:1px solid var(--line,#283a5a);font-size:11px;">';
    h += '<span style="color:' + riskColor + ';font-weight:700;width:60px;flex-shrink:0;">' + ind.risk + '</span>';
    h += '<span style="color:var(--txt,#e7eefc);width:140px;flex-shrink:0;">' + esc(ind.indicator) + '</span>';
    h += '<span style="color:var(--mut,#7a93b8);font-family:var(--font-mono,ui-monospace,monospace);">' + esc(ind.example) + '</span>';
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
    results.innerHTML = '<div style="color:#dc2626;font-size:12px;">Invalid URL format.</div>';
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
  // Leetspeak brand impersonation (g00gle, micros0ft): normalize 0→o and 1→l
  // and check the RESULT against the brand list. The old test required both a
  // digit AND the intact brand string, which are mutually exclusive for a
  // substituted brand — so it never fired for g00gle/micros0ft (its documented
  // targets) and only matched intact-brand+digit hosts.
  var brandNorm = hostname.replace(/0/g, 'o').replace(/1/g, 'l');
  if (brandNorm !== hostname && /paypal|google|apple|microsoft|amazon|netflix|facebook|instagram|twitter|bank/i.test(brandNorm)) { flags.push({ text: 'Possible brand impersonation with character substitution', severity: 'CRITICAL' }); score += 40; }
  if (hostname.length > 40) { flags.push({ text: 'Unusually long domain name (' + hostname.length + ' chars)', severity: 'LOW' }); score += 5; }
  if (url.indexOf('data:') === 0) { flags.push({ text: 'Data URI detected — may contain hidden content', severity: 'CRITICAL' }); score += 50; }

  score = Math.min(100, score);
  var verdict = score >= 60 ? 'LIKELY PHISHING' : score >= 30 ? 'SUSPICIOUS' : 'APPEARS SAFE';
  var verdictColor = score >= 60 ? '#dc2626' : score >= 30 ? '#d97706' : '#16a34a';

  var h = '';
  h += '<div style="background:var(--card2,#0f1726);border:1px solid ' + verdictColor + ';border-radius:12px;padding:16px;text-align:center;margin-bottom:12px;">';
  h += '<div style="font-size:14px;font-weight:700;color:' + verdictColor + ';letter-spacing:.06em;">' + verdict + '</div>';
  h += '<div style="font-size:36px;font-weight:800;color:' + verdictColor + ';margin:4px 0;">' + score + '/100</div>';
  h += '<div style="color:var(--mut,#7a93b8);font-size:11px;">Risk Score (higher = more suspicious)</div>';
  h += '</div>';

  if (flags.length > 0) {
    h += '<div style="background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);border-radius:10px;padding:14px;">';
    h += '<div style="color:var(--txt,#e7eefc);font-size:13px;font-weight:700;margin-bottom:8px;">Detected Indicators (' + flags.length + ')</div>';
    for (var fi = 0; fi < flags.length; fi++) {
      var f = flags[fi];
      var fc = f.severity === 'CRITICAL' ? '#b91c1c' : f.severity === 'HIGH' ? '#ea580c' : f.severity === 'MEDIUM' ? '#d97706' : '#16a34a';
      h += '<div style="margin:5px 0;font-size:12px;display:flex;gap:8px;align-items:center;">';
      h += '<span style="color:' + fc + ';font-weight:700;font-size:10px;padding:2px 6px;background:' + fc + '1a;border:1px solid ' + fc + '40;border-radius:4px;">' + f.severity + '</span>';
      h += '<span style="color:var(--txt,#e7eefc);">' + esc(f.text) + '</span>';
      h += '</div>';
    }
    h += '</div>';
  } else {
    h += '<div style="color:#16a34a;font-size:12px;text-align:center;">No suspicious indicators detected.</div>';
  }

  results.innerHTML = h;
};
