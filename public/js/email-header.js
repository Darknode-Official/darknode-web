import { esc } from '/js/shared.js';

const SAMPLE_HEADERS = `Delivered-To: analyst@darknode.ai
Received: by 2002:a05:6902:1024:b0:e0a:1234:5678 with SMTP id x4csp4012345qkl;
        Mon, 16 Sep 2026 08:15:32 -0700 (PDT)
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=1e100.net; s=20230601
Received: from mail-wm1-f54.google.com (mail-wm1-f54.google.com [209.85.128.54])
        by mx.google.com with ESMTPS id a1-2345.6789
        for <analyst@darknode.ai>; Mon, 16 Sep 2026 08:15:31 -0700 (PDT)
Received: from suspicious-relay.example.ru (unknown [185.220.101.34])
        by mail-wm1-f54.google.com with ESMTP id z9-2345.6789
        for <analyst@darknode.ai>; Mon, 16 Sep 2026 08:15:29 -0700 (PDT)
Received: from internal-mail.corp.example.com (10.0.1.50)
        by suspicious-relay.example.ru with SMTP;
        Mon, 16 Sep 2026 18:15:27 +0300
Authentication-Results: mx.google.com;
       dkim=pass header.i=@example.com header.s=selector1;
       spf=fail (google.com: domain of ceo@example.com does not designate 185.220.101.34 as permitted sender) smtp.mailfrom=ceo@example.com;
       dmarc=fail (p=REJECT sp=REJECT dis=QUARANTINE) header.from=example.com
From: "John Smith - CEO" <ceo@example.com>
To: analyst@darknode.ai
Subject: URGENT: Wire Transfer Required - Confidential
Date: Mon, 16 Sep 2026 18:15:25 +0300
Message-ID: <abc123def456@suspicious-relay.example.ru>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
X-Mailer: Microsoft Outlook 16.0
Reply-To: ceo-personal@gmail.com
X-Originating-IP: 185.220.101.34
Return-Path: <bounce@suspicious-relay.example.ru>`;

const HEADER_REF = [
  { field: 'From', desc: 'The sender address displayed to the recipient. Can be easily spoofed.', risk: 'high' },
  { field: 'Return-Path', desc: 'Where bounce messages are sent. Mismatch with From may indicate spoofing.', risk: 'high' },
  { field: 'Reply-To', desc: 'Address used when recipient clicks Reply. Different from From is suspicious.', risk: 'medium' },
  { field: 'Received', desc: 'Added by each mail server in the delivery chain. Read bottom-to-top for routing.', risk: 'info' },
  { field: 'Authentication-Results', desc: 'SPF, DKIM, and DMARC verification results from the receiving server.', risk: 'high' },
  { field: 'X-Originating-IP', desc: 'IP address of the original sender. May reveal true origin.', risk: 'high' },
  { field: 'Message-ID', desc: 'Unique identifier for the message. Domain should match sender domain.', risk: 'medium' },
  { field: 'DKIM-Signature', desc: 'Cryptographic signature proving the email was not altered in transit.', risk: 'medium' },
  { field: 'X-Mailer', desc: 'Email client used to send the message. Can indicate automated tools.', risk: 'low' },
  { field: 'Content-Type', desc: 'MIME type of the message body. HTML emails can contain phishing content.', risk: 'low' },
  { field: 'Date', desc: 'When the email was composed. Timezone can reveal sender location.', risk: 'info' },
  { field: 'Subject', desc: 'Message subject line. Urgency language is a common phishing indicator.', risk: 'info' },
  { field: 'MIME-Version', desc: 'Version of MIME standard used. Always 1.0 in modern email.', risk: 'info' },
  { field: 'To', desc: 'Intended recipient(s). BCC recipients are hidden from this field.', risk: 'info' },
];

function parseHeaders(raw) {
  var lines = raw.replace(/\r\n/g, '\n').split('\n');
  var headers = [];
  var current = null;
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (/^\s/.test(line) && current) {
      current.value += ' ' + line.trim();
    } else {
      var m = line.match(/^([A-Za-z0-9_-]+):\s*(.*)/);
      if (m) {
        current = { name: m[1], value: m[2] };
        headers.push(current);
      }
    }
  }
  return headers;
}

function extractField(headers, name) {
  var h = headers.find(function(x) { return x.name.toLowerCase() === name.toLowerCase(); });
  return h ? h.value : '';
}

function extractAllFields(headers, name) {
  return headers.filter(function(x) { return x.name.toLowerCase() === name.toLowerCase(); }).map(function(x) { return x.value; });
}

function parseReceived(val) {
  var from = '', by = '', ip = '', date = '', proto = '';
  var fm = val.match(/from\s+([^\s(]+)(?:\s*\(([^)]*)\))?/i);
  if (fm) { from = fm[1]; if (fm[2]) { var ipm = fm[2].match(/\[?([\d.]+)\]?/); if (ipm) ip = ipm[1]; } }
  var bm = val.match(/by\s+([^\s]+)/i);
  if (bm) by = bm[1];
  var pm = val.match(/with\s+(ESMTPS?A?|SMTP|LMTP|HTTP)/i);
  if (pm) proto = pm[1];
  var dm = val.match(/;\s*(.+)$/);
  if (dm) date = dm[1].trim();
  if (!ip) { var ip2 = val.match(/\[(\d+\.\d+\.\d+\.\d+)\]/); if (ip2) ip = ip2[1]; }
  if (!ip) { var ip3 = val.match(/\((\d+\.\d+\.\d+\.\d+)\)/); if (ip3) ip = ip3[1]; }
  return { from: from, by: by, ip: ip, date: date, proto: proto };
}

function parseAuth(val) {
  var results = { spf: 'none', dkim: 'none', dmarc: 'none', spfDetail: '', dkimDetail: '', dmarcDetail: '' };
  var spf = val.match(/spf=(\w+)(?:\s*\(([^)]*)\))?/i);
  if (spf) { results.spf = spf[1].toLowerCase(); results.spfDetail = spf[2] || ''; }
  var dkim = val.match(/dkim=(\w+)/i);
  if (dkim) { results.dkim = dkim[1].toLowerCase(); }
  var dmarc = val.match(/dmarc=(\w+)(?:\s*\(([^)]*)\))?/i);
  if (dmarc) { results.dmarc = dmarc[1].toLowerCase(); results.dmarcDetail = dmarc[2] || ''; }
  return results;
}

function detectSuspicious(headers, hops, auth) {
  var flags = [];
  var from = extractField(headers, 'From');
  var replyTo = extractField(headers, 'Reply-To');
  var returnPath = extractField(headers, 'Return-Path');
  var subject = extractField(headers, 'Subject');
  var msgId = extractField(headers, 'Message-ID');
  var origIP = extractField(headers, 'X-Originating-IP');

  if (replyTo && from) {
    var fromDomain = (from.match(/@([^>]+)>?/) || [])[1] || '';
    var replyDomain = (replyTo.match(/@([^>]+)>?/) || [])[1] || '';
    if (fromDomain && replyDomain && fromDomain.toLowerCase() !== replyDomain.toLowerCase()) {
      flags.push({ severity: 'high', text: 'Reply-To domain (' + esc(replyDomain) + ') does not match From domain (' + esc(fromDomain) + '). Possible phishing.' });
    }
  }
  if (returnPath && from) {
    var fromD = (from.match(/@([^>]+)>?/) || [])[1] || '';
    var rpD = (returnPath.match(/@([^>]+)>?/) || [])[1] || '';
    if (fromD && rpD && fromD.toLowerCase() !== rpD.toLowerCase()) {
      flags.push({ severity: 'high', text: 'Return-Path domain (' + esc(rpD) + ') differs from From domain (' + esc(fromD) + '). Likely spoofed.' });
    }
  }
  if (auth.spf === 'fail') flags.push({ severity: 'critical', text: 'SPF check FAILED. Sending server is not authorized for this domain.' });
  if (auth.dmarc === 'fail') flags.push({ severity: 'critical', text: 'DMARC check FAILED. Domain policy indicates this email should be rejected.' });
  if (auth.dkim === 'fail') flags.push({ severity: 'high', text: 'DKIM signature FAILED. Email may have been altered in transit.' });
  if (/urgent|immediate|wire transfer|confidential|act now|verify your account|suspended/i.test(subject)) {
    flags.push({ severity: 'medium', text: 'Subject line contains urgency/social engineering language: "' + esc(subject.substring(0, 60)) + '"' });
  }
  if (msgId) {
    var msgDomain = (msgId.match(/@([^>]+)/) || [])[1] || '';
    var senderDomain = (from.match(/@([^>]+)>?/) || [])[1] || '';
    if (msgDomain && senderDomain && msgDomain.toLowerCase() !== senderDomain.toLowerCase()) {
      flags.push({ severity: 'medium', text: 'Message-ID domain (' + esc(msgDomain) + ') does not match sender domain (' + esc(senderDomain) + ').' });
    }
  }
  if (hops.length > 5) flags.push({ severity: 'medium', text: 'Unusual number of mail relays (' + hops.length + '). Normal is 2-4.' });
  for (var i = 0; i < hops.length; i++) {
    if (hops[i].from && /\.ru$|\.cn$|\.ir$|\.kp$/i.test(hops[i].from)) {
      flags.push({ severity: 'high', text: 'Mail routed through high-risk TLD server: ' + esc(hops[i].from) });
    }
    if (hops[i].ip && /^(185\.220\.|91\.219\.|77\.247\.|45\.154\.)/.test(hops[i].ip)) {
      flags.push({ severity: 'high', text: 'Known Tor exit node or suspicious IP in routing: ' + esc(hops[i].ip) });
    }
  }
  if (origIP) flags.push({ severity: 'info', text: 'X-Originating-IP exposed: ' + esc(origIP) + '. This reveals the sender true IP.' });
  if (flags.length === 0) flags.push({ severity: 'info', text: 'No obvious suspicious indicators detected. Exercise standard caution.' });
  return flags;
}

export function renderEmailHeader(container) {
  var activeTab = 'analysis';
  var parsedHeaders = [];
  var rawInput = '';

  var EH_CSS = '<style>' +
    '.eh-wrap{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#c8d6e5;max-width:1100px}' +
    '.eh-title{font-size:1.6rem;font-weight:700;margin:0 0 6px;color:var(--txt)}' +
    '.eh-sub{color:var(--mut);font-size:.85rem;margin-bottom:20px;line-height:1.5}' +
    '.eh-tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:24px}' +
    '.eh-tab{background:var(--card);border:1px solid var(--line);color:var(--mut);padding:8px 16px;font-size:.75rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase;cursor:pointer;border-radius:var(--btn-radius,4px);transition:all .15s;font-family:inherit}' +
    '.eh-tab:hover{background:color-mix(in srgb,var(--acc) 8%,var(--card));color:var(--txt)}' +
    '.eh-tab.active{background:var(--acc);color:var(--on-acc,#fff);border-color:var(--acc)}' +
    '.eh-panel{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:20px;margin-bottom:16px}' +
    '.eh-panel-title{font-size:.8rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--acc);margin-bottom:12px}' +
    '.eh-textarea{width:100%;min-height:200px;background:var(--card2,#0a0e14);border:1px solid var(--line);color:var(--txt);font-family:ui-monospace,monospace;font-size:.75rem;padding:12px;border-radius:6px;resize:vertical}' +
    '.eh-textarea:focus{border-color:var(--acc);outline:none}' +
    '.eh-btn{background:var(--acc);color:var(--on-acc,#fff);border:1px solid var(--acc);padding:8px 16px;border-radius:6px;font-size:.78rem;font-weight:600;cursor:pointer;font-family:inherit;transition:all .15s}' +
    '.eh-btn:hover{opacity:.9}' +
    '.eh-btn.ghost{background:transparent;color:var(--acc);border-color:var(--line)}' +
    '.eh-btn.ghost:hover{border-color:var(--acc);background:color-mix(in srgb,var(--acc) 8%,transparent)}' +
    '.eh-row{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;align-items:flex-start}' +
    '.eh-field{display:flex;gap:8px;padding:8px 0;border-bottom:1px solid var(--line);font-size:.8rem}' +
    '.eh-field-name{font-weight:700;color:var(--acc);min-width:140px;flex-shrink:0;font-family:ui-monospace,monospace;font-size:.75rem}' +
    '.eh-field-val{color:var(--txt);word-break:break-all;line-height:1.5}' +
    '.eh-badge{display:inline-block;padding:3px 8px;border-radius:4px;font-size:.65rem;font-weight:700;letter-spacing:.04em;text-transform:uppercase}' +
    '.eh-badge.pass{background:rgba(22,163,74,.15);color:#16a34a}' +
    '.eh-badge.fail{background:rgba(220,38,38,.15);color:#dc2626}' +
    '.eh-badge.none{background:rgba(100,116,139,.15);color:#64748b}' +
    '.eh-badge.warn{background:rgba(217,119,6,.15);color:#d97706}' +
    '.eh-hop{display:flex;align-items:flex-start;gap:16px;padding:14px 0;border-bottom:1px solid var(--line)}' +
    '.eh-hop-num{width:28px;height:28px;border-radius:50%;background:var(--acc);color:#fff;display:flex;align-items:center;justify-content:center;font-size:.7rem;font-weight:700;flex-shrink:0}' +
    '.eh-hop-info{flex:1;font-size:.78rem}' +
    '.eh-hop-server{font-weight:600;color:var(--txt);margin-bottom:2px}' +
    '.eh-hop-detail{color:var(--mut);font-size:.72rem}' +
    '.eh-hop-arrow{color:var(--acc);text-align:center;padding:4px 0;font-size:.7rem}' +
    '.eh-alert{padding:10px 14px;border-radius:6px;margin-bottom:8px;font-size:.78rem;display:flex;align-items:flex-start;gap:8px;line-height:1.5}' +
    '.eh-alert.critical{background:rgba(220,38,38,.1);border-left:3px solid #dc2626;color:#fca5a5}' +
    '.eh-alert.high{background:rgba(249,115,22,.1);border-left:3px solid #f97316;color:#fdba74}' +
    '.eh-alert.medium{background:rgba(217,119,6,.1);border-left:3px solid #d97706;color:#fcd34d}' +
    '.eh-alert.info{background:rgba(37,99,235,.08);border-left:3px solid #2563eb;color:#93c5fd}' +
    '.eh-alert-icon{flex-shrink:0;font-size:1rem}' +
    '.eh-table{width:100%;border-collapse:collapse;font-size:.78rem}' +
    '.eh-table th{text-align:left;padding:10px 12px;background:rgba(0,0,0,.2);color:var(--mut);font-weight:600;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;border-bottom:2px solid var(--line)}' +
    '.eh-table td{padding:10px 12px;border-bottom:1px solid var(--line);color:var(--txt);vertical-align:top}' +
    '.eh-table tr:hover td{background:rgba(0,0,0,.05)}' +
    '.eh-risk{display:inline-block;padding:2px 6px;border-radius:3px;font-size:.6rem;font-weight:700;text-transform:uppercase}' +
    '.eh-risk.high{background:rgba(220,38,38,.15);color:#dc2626}' +
    '.eh-risk.medium{background:rgba(217,119,6,.15);color:#d97706}' +
    '.eh-risk.low{background:rgba(22,163,74,.15);color:#16a34a}' +
    '.eh-risk.info{background:rgba(100,116,139,.15);color:#64748b}' +
    '.eh-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}' +
    '@media(max-width:768px){.eh-grid{grid-template-columns:1fr}}' +
    '[data-style=pro] .eh-wrap{color:#0f172a}' +
    '[data-style=pro] .eh-panel{background:#fff;border-color:#e2e8f0}' +
    '[data-style=pro] .eh-textarea{background:#f8fafc;border-color:#e2e8f0;color:#0f172a}' +
    '[data-style=pro] .eh-field-val{color:#334155}' +
    '[data-style=pro] .eh-hop-server{color:#0f172a}' +
    '[data-style=pro] .eh-hop-detail{color:#64748b}' +
    '[data-style=pro] .eh-table td{color:#334155}' +
    '[data-style=pro] .eh-table th{background:#f1f5f9;color:#475569}' +
    '[data-style=pro] .eh-table tr:hover td{background:#f8fafc}' +
    '[data-style=pro] .eh-alert.critical{background:rgba(220,38,38,.06);color:#991b1b}' +
    '[data-style=pro] .eh-alert.high{background:rgba(249,115,22,.06);color:#9a3412}' +
    '[data-style=pro] .eh-alert.medium{background:rgba(217,119,6,.06);color:#92400e}' +
    '[data-style=pro] .eh-alert.info{background:rgba(37,99,235,.06);color:#1e40af}' +
    '</style>';

  function render() {
    var headers = parsedHeaders;
    var from = extractField(headers, 'From');
    var to = extractField(headers, 'To');
    var subject = extractField(headers, 'Subject');
    var date = extractField(headers, 'Date');
    var msgId = extractField(headers, 'Message-ID');
    var receivedAll = extractAllFields(headers, 'Received');
    var hops = receivedAll.map(parseReceived).reverse();
    var authResults = extractField(headers, 'Authentication-Results');
    var auth = authResults ? parseAuth(authResults) : { spf: 'none', dkim: 'none', dmarc: 'none', spfDetail: '', dkimDetail: '', dmarcDetail: '' };
    var suspicious = headers.length > 0 ? detectSuspicious(headers, hops, auth) : [];

    var tabsHtml = ['analysis', 'route', 'auth', 'reference'].map(function(t) {
      var labels = { analysis: 'Analysis', route: 'Route Trace', auth: 'Authentication', reference: 'Reference' };
      return '<button class="eh-tab' + (activeTab === t ? ' active' : '') + '" data-tab="' + t + '">' + labels[t] + '</button>';
    }).join('');

    var contentHtml = '';

    if (activeTab === 'analysis') {
      contentHtml = '<div class="eh-panel">' +
        '<div class="eh-panel-title">Paste Email Headers</div>' +
        '<textarea class="eh-textarea" id="eh-input" placeholder="Paste raw email headers here...">' + esc(rawInput) + '</textarea>' +
        '<div class="eh-row" style="margin-top:12px">' +
          '<button class="eh-btn" id="eh-analyze">Analyze Headers</button>' +
          '<button class="eh-btn ghost" id="eh-sample">Load Sample</button>' +
          '<button class="eh-btn ghost" id="eh-clear">Clear</button>' +
        '</div>' +
      '</div>';
      if (headers.length > 0) {
        contentHtml += '<div class="eh-panel"><div class="eh-panel-title">Key Fields</div>';
        var fields = [['From', from], ['To', to], ['Subject', subject], ['Date', date], ['Message-ID', msgId], ['Return-Path', extractField(headers, 'Return-Path')], ['Reply-To', extractField(headers, 'Reply-To')], ['X-Mailer', extractField(headers, 'X-Mailer')]];
        fields.forEach(function(f) {
          if (f[1]) contentHtml += '<div class="eh-field"><span class="eh-field-name">' + esc(f[0]) + '</span><span class="eh-field-val">' + esc(f[1]) + '</span></div>';
        });
        contentHtml += '</div>';
        if (suspicious.length > 0) {
          contentHtml += '<div class="eh-panel"><div class="eh-panel-title">Suspicious Indicators (' + suspicious.length + ')</div>';
          var icons = { critical: '[!!]', high: '[!]', medium: '[!]', info: 'ℹ' };
          suspicious.forEach(function(f) {
            contentHtml += '<div class="eh-alert ' + f.severity + '"><span class="eh-alert-icon">' + (icons[f.severity] || '') + '</span><span>' + f.text + '</span></div>';
          });
          contentHtml += '</div>';
        }
      }
    } else if (activeTab === 'route') {
      if (hops.length === 0) {
        contentHtml = '<div class="eh-panel"><div class="eh-panel-title">Route Trace</div><p style="color:var(--mut);font-size:.82rem">Analyze email headers first to see the routing path.</p></div>';
      } else {
        contentHtml = '<div class="eh-panel"><div class="eh-panel-title">Mail Routing Path (' + hops.length + ' hops)</div>';
        hops.forEach(function(h, i) {
          if (i > 0) contentHtml += '<div class="eh-hop-arrow">↓</div>';
          contentHtml += '<div class="eh-hop">' +
            '<div class="eh-hop-num">' + (i + 1) + '</div>' +
            '<div class="eh-hop-info">' +
              '<div class="eh-hop-server">' + esc(h.from || 'Origin') + ' → ' + esc(h.by || '?') + '</div>' +
              '<div class="eh-hop-detail">' +
                (h.ip ? 'IP: <strong>' + esc(h.ip) + '</strong> · ' : '') +
                (h.proto ? 'Protocol: ' + esc(h.proto) + ' · ' : '') +
                (h.date ? esc(h.date) : '') +
              '</div>' +
            '</div>' +
          '</div>';
        });
        contentHtml += '</div>';
      }
    } else if (activeTab === 'auth') {
      var badgeClass = function(status) { return status === 'pass' ? 'pass' : status === 'fail' ? 'fail' : status === 'none' ? 'none' : 'warn'; };
      contentHtml = '<div class="eh-panel"><div class="eh-panel-title">Email Authentication Results</div>';
      if (!authResults) {
        contentHtml += '<p style="color:var(--mut);font-size:.82rem">No Authentication-Results header found. Analyze headers first.</p>';
      } else {
        contentHtml += '<div class="eh-grid">';
        [['SPF', auth.spf, auth.spfDetail, 'Sender Policy Framework verifies that the sending server is authorized to send email for the domain.'],
         ['DKIM', auth.dkim, auth.dkimDetail, 'DomainKeys Identified Mail uses cryptographic signatures to verify the email was not altered.'],
         ['DMARC', auth.dmarc, auth.dmarcDetail, 'Domain-based Message Authentication builds on SPF and DKIM to set policies for failed checks.']
        ].forEach(function(a) {
          contentHtml += '<div class="eh-panel" style="margin-bottom:0">' +
            '<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">' +
              '<strong style="font-size:.9rem">' + a[0] + '</strong>' +
              '<span class="eh-badge ' + badgeClass(a[1]) + '">' + a[1].toUpperCase() + '</span>' +
            '</div>' +
            '<p style="font-size:.78rem;color:var(--mut);margin:0 0 6px;line-height:1.5">' + a[3] + '</p>' +
            (a[2] ? '<p style="font-size:.72rem;color:var(--txt);margin:0;font-family:ui-monospace,monospace;word-break:break-all">' + esc(a[2]) + '</p>' : '') +
          '</div>';
        });
        contentHtml += '</div>';
      }
      contentHtml += '</div>';
    } else if (activeTab === 'reference') {
      contentHtml = '<div class="eh-panel"><div class="eh-panel-title">Email Header Field Reference</div>' +
        '<table class="eh-table"><thead><tr><th>Field</th><th>Description</th><th>Risk</th></tr></thead><tbody>';
      HEADER_REF.forEach(function(r) {
        contentHtml += '<tr><td><strong style="font-family:ui-monospace,monospace;font-size:.75rem">' + esc(r.field) + '</strong></td><td>' + esc(r.desc) + '</td><td><span class="eh-risk ' + r.risk + '">' + r.risk + '</span></td></tr>';
      });
      contentHtml += '</tbody></table></div>';
    }

    container.innerHTML = EH_CSS +
      '<div class="eh-wrap">' +
        '<h1 class="eh-title">Email Header Analyzer</h1>' +
        '<p class="eh-sub">Parse and analyze raw email headers to detect spoofing, trace mail routing, and verify authentication.</p>' +
        '<div class="eh-tabs">' + tabsHtml + '</div>' +
        contentHtml +
      '</div>';

    container.querySelectorAll('.eh-tab').forEach(function(btn) {
      btn.onclick = function() { activeTab = btn.dataset.tab; render(); };
    });
    var analyzeBtn = container.querySelector('#eh-analyze');
    if (analyzeBtn) analyzeBtn.onclick = function() {
      rawInput = container.querySelector('#eh-input').value;
      parsedHeaders = parseHeaders(rawInput);
      render();
    };
    var sampleBtn = container.querySelector('#eh-sample');
    if (sampleBtn) sampleBtn.onclick = function() {
      rawInput = SAMPLE_HEADERS;
      parsedHeaders = parseHeaders(rawInput);
      render();
    };
    var clearBtn = container.querySelector('#eh-clear');
    if (clearBtn) clearBtn.onclick = function() {
      rawInput = '';
      parsedHeaders = [];
      render();
    };
  }

  render();
}
