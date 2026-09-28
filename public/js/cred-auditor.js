import { esc } from '/js/shared.js';

const CA_COMMON = new Set(['password','123456','12345678','qwerty','abc123','monkey','master','dragon','111111',
  'baseball','iloveyou','trustno1','sunshine','princess','football','shadow','superman','michael','admin',
  'letmein','welcome','login','starwars','passw0rd','hello','charlie','donald','password1','qwerty123',
  '1234567890','password123','000000','1q2w3e4r','aa12345678','root','toor','changeme','test','guest']);

const CA_HASH_PATTERNS = [
  { name: 'MD5', re: /^[a-f0-9]{32}$/i, len: 32 },
  { name: 'SHA-1', re: /^[a-f0-9]{40}$/i, len: 40 },
  { name: 'SHA-256', re: /^[a-f0-9]{64}$/i, len: 64 },
  { name: 'SHA-512', re: /^[a-f0-9]{128}$/i, len: 128 },
  { name: 'NTLM', re: /^[a-f0-9]{32}$/i, len: 32 },
  { name: 'bcrypt', re: /^\$2[aby]?\$\d{2}\$.{53}$/, len: null },
  { name: 'SHA-512 Crypt', re: /^\$6\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]{86}$/, len: null },
  { name: 'SHA-256 Crypt', re: /^\$5\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]{43}$/, len: null },
  { name: 'MD5 Crypt', re: /^\$1\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]{22}$/, len: null },
  { name: 'MySQL 4.1+', re: /^\*[A-F0-9]{40}$/i, len: 41 },
  { name: 'LM Hash', re: /^[a-f0-9]{32}$/i, len: 32 },
  { name: 'CRC32', re: /^[a-f0-9]{8}$/i, len: 8 }
];

function scorePassword(pw) {
  if (!pw) return { score: 0, label: 'Empty', color: '#64748b', breakdown: [] };
  var score = 0, bd = [];
  if (pw.length >= 8) { score += 10; bd.push({ rule: 'Length ≥ 8', pass: true }); }
  else { bd.push({ rule: 'Length ≥ 8', pass: false }); }
  if (pw.length >= 12) { score += 10; bd.push({ rule: 'Length ≥ 12', pass: true }); }
  else { bd.push({ rule: 'Length ≥ 12', pass: false }); }
  if (pw.length >= 16) { score += 10; bd.push({ rule: 'Length ≥ 16', pass: true }); }
  else { bd.push({ rule: 'Length ≥ 16', pass: false }); }
  if (/[a-z]/.test(pw)) { score += 10; bd.push({ rule: 'Lowercase letters', pass: true }); }
  else { bd.push({ rule: 'Lowercase letters', pass: false }); }
  if (/[A-Z]/.test(pw)) { score += 10; bd.push({ rule: 'Uppercase letters', pass: true }); }
  else { bd.push({ rule: 'Uppercase letters', pass: false }); }
  if (/\d/.test(pw)) { score += 10; bd.push({ rule: 'Numbers', pass: true }); }
  else { bd.push({ rule: 'Numbers', pass: false }); }
  if (/[^a-zA-Z0-9]/.test(pw)) { score += 15; bd.push({ rule: 'Special characters', pass: true }); }
  else { bd.push({ rule: 'Special characters', pass: false }); }
  if (CA_COMMON.has(pw.toLowerCase())) { score = Math.max(0, score - 40); bd.push({ rule: 'Not in common list', pass: false }); }
  else { bd.push({ rule: 'Not in common list', pass: true }); }
  if (/(.)\1{2,}/.test(pw)) { score = Math.max(0, score - 10); bd.push({ rule: 'No repeated chars (3+)', pass: false }); }
  else { bd.push({ rule: 'No repeated chars (3+)', pass: true }); }
  if (/^(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(pw)) {
    score = Math.max(0, score - 10); bd.push({ rule: 'No sequential patterns', pass: false });
  } else { bd.push({ rule: 'No sequential patterns', pass: true }); }
  var charSet = 0;
  if (/[a-z]/.test(pw)) charSet += 26;
  if (/[A-Z]/.test(pw)) charSet += 26;
  if (/\d/.test(pw)) charSet += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) charSet += 33;
  var entropy = Math.floor(pw.length * Math.log2(Math.max(charSet, 1)));
  score = Math.min(100, score);
  var label, color;
  if (score >= 80) { label = 'Strong'; color = '#16a34a'; }
  else if (score >= 60) { label = 'Good'; color = '#22c55e'; }
  else if (score >= 40) { label = 'Fair'; color = '#eab308'; }
  else if (score >= 20) { label = 'Weak'; color = '#f97316'; }
  else { label = 'Very Weak'; color = '#dc2626'; }
  return { score: score, label: label, color: color, breakdown: bd, entropy: entropy, charSet: charSet, length: pw.length };
}

function identifyHash(h) {
  h = h.trim();
  var matches = [];
  if (h.startsWith('$2')) {
    matches.push({ name: 'bcrypt', confidence: 95 });
    return matches;
  }
  if (h.startsWith('$6$')) { matches.push({ name: 'SHA-512 Crypt', confidence: 95 }); return matches; }
  if (h.startsWith('$5$')) { matches.push({ name: 'SHA-256 Crypt', confidence: 95 }); return matches; }
  if (h.startsWith('$1$')) { matches.push({ name: 'MD5 Crypt', confidence: 95 }); return matches; }
  if (h.startsWith('*') && /^[A-F0-9]{40}$/i.test(h.slice(1))) { matches.push({ name: 'MySQL 4.1+', confidence: 90 }); return matches; }
  CA_HASH_PATTERNS.forEach(function(p) {
    if (p.re.test(h)) {
      var conf = 70;
      if (p.len && h.length === p.len) conf = 80;
      if (p.name === 'MD5' && h.length === 32) matches.push({ name: 'MD5', confidence: 75 });
      else if (p.name === 'NTLM' && h.length === 32) matches.push({ name: 'NTLM', confidence: 60 });
      else if (p.name === 'LM Hash' && h.length === 32) matches.push({ name: 'LM Hash', confidence: 50 });
      else if (p.name !== 'MD5' && p.name !== 'NTLM' && p.name !== 'LM Hash') matches.push({ name: p.name, confidence: conf });
    }
  });
  matches.sort(function(a, b) { return b.confidence - a.confidence; });
  var seen = new Set();
  return matches.filter(function(m) { if (seen.has(m.name)) return false; seen.add(m.name); return true; });
}

function checkPolicy(passwords, policy) {
  var results = [];
  passwords.forEach(function(pw) {
    var issues = [];
    if (pw.length < policy.minLen) issues.push('Too short (min ' + policy.minLen + ')');
    if (policy.reqUpper && !/[A-Z]/.test(pw)) issues.push('Needs uppercase');
    if (policy.reqLower && !/[a-z]/.test(pw)) issues.push('Needs lowercase');
    if (policy.reqDigit && !/\d/.test(pw)) issues.push('Needs digit');
    if (policy.reqSpecial && !/[^a-zA-Z0-9]/.test(pw)) issues.push('Needs special char');
    if (policy.noCommon && CA_COMMON.has(pw.toLowerCase())) issues.push('Common password');
    if (policy.maxLen && pw.length > policy.maxLen) issues.push('Too long (max ' + policy.maxLen + ')');
    results.push({ password: pw, pass: issues.length === 0, issues: issues, score: scorePassword(pw) });
  });
  return results;
}

export function renderCredAuditor(container) {
  var state = {
    tab: 'strength',
    password: '',
    hashInput: '',
    policyPasswords: '',
    policy: { minLen: 8, maxLen: 128, reqUpper: true, reqLower: true, reqDigit: true, reqSpecial: true, noCommon: true },
    genLen: 16, genIncUpper: true, genIncLower: true, genIncDigit: true, genIncSpecial: true, generated: []
  };

  var CSS = '<style>' +
    '.ca-wrap{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:var(--txt,#c8d6e5)}' +
    '.ca-header{margin-bottom:24px}' +
    '.ca-title{font-size:1.5rem;font-weight:700;margin:0 0 6px}' +
    '.ca-sub{color:var(--mut,#64748b);font-size:.85rem}' +
    '.ca-tabs{display:flex;gap:4px;margin-bottom:20px;flex-wrap:wrap}' +
    '.ca-tab{padding:8px 16px;border:1px solid var(--line,#1e293b);border-radius:4px;background:transparent;color:var(--mut,#8899aa);cursor:pointer;font-size:.78rem;font-weight:600;text-transform:uppercase;letter-spacing:.04em;transition:all .15s;font-family:inherit}' +
    '.ca-tab:hover{background:rgba(255,255,255,.05);color:var(--txt)}' +
    '.ca-tab.active{background:var(--acc,#2563eb);color:#fff;border-color:var(--acc,#2563eb)}' +
    '.ca-panel{background:var(--card,#0d1117);border:1px solid var(--line,#1e293b);border-radius:8px;padding:20px;margin-bottom:16px}' +
    '.ca-input{width:100%;background:var(--card2,#080c14);border:1px solid var(--line,#1e293b);border-radius:6px;color:var(--txt,#e2e8f0);font-family:ui-monospace,monospace;font-size:.85rem;padding:10px 14px}' +
    '.ca-input:focus{border-color:var(--acc);outline:none}' +
    '.ca-textarea{width:100%;min-height:140px;background:var(--card2,#080c14);border:1px solid var(--line,#1e293b);border-radius:6px;color:var(--txt);font-family:ui-monospace,monospace;font-size:.78rem;padding:12px;resize:vertical;line-height:1.5}' +
    '.ca-textarea:focus{border-color:var(--acc);outline:none}' +
    '.ca-btn{padding:7px 16px;border:none;border-radius:6px;background:var(--acc,#2563eb);color:#fff;cursor:pointer;font-size:.78rem;font-weight:600;font-family:inherit;transition:all .15s}' +
    '.ca-btn:hover{opacity:.9}' +
    '.ca-btn-ghost{background:transparent;border:1px solid var(--line);color:var(--mut)}' +
    '.ca-btn-ghost:hover{border-color:var(--acc);color:var(--acc)}' +
    '.ca-meter{height:8px;border-radius:4px;background:var(--line,#1e293b);margin:12px 0;overflow:hidden}' +
    '.ca-meter-fill{height:100%;border-radius:4px;transition:width .4s,background .4s}' +
    '.ca-score-label{font-size:1.1rem;font-weight:800;letter-spacing:.02em}' +
    '.ca-breakdown{list-style:none;padding:0;margin:14px 0 0}' +
    '.ca-breakdown li{display:flex;align-items:center;gap:8px;padding:5px 0;font-size:.78rem;border-bottom:1px solid var(--line,#1e293b)}' +
    '.ca-breakdown li:last-child{border-bottom:none}' +
    '.ca-check-icon{width:16px;height:16px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:.6rem;font-weight:700;flex-shrink:0}' +
    '.ca-stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin:14px 0}' +
    '.ca-stat{background:var(--card2,#080c14);border:1px solid var(--line);border-radius:8px;padding:14px;text-align:center}' +
    '.ca-stat-val{font-size:1.2rem;font-weight:800;color:var(--acc);font-variant-numeric:tabular-nums}' +
    '.ca-stat-lbl{font-size:.65rem;color:var(--mut);text-transform:uppercase;letter-spacing:.04em;margin-top:2px}' +
    '.ca-hash-match{padding:10px 14px;border-left:3px solid var(--acc);background:rgba(37,99,235,.06);border-radius:0 6px 6px 0;margin-bottom:8px}' +
    '.ca-hash-name{font-weight:700;font-size:.85rem}' +
    '.ca-hash-conf{font-size:.72rem;color:var(--mut)}' +
    '.ca-policy-row{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--line);font-size:.78rem}' +
    '.ca-policy-row:last-child{border-bottom:none}' +
    '.ca-policy-row label{flex:1}' +
    '.ca-toggle{position:relative;width:36px;height:20px;border-radius:10px;background:var(--line);cursor:pointer;transition:background .2s;flex-shrink:0}' +
    '.ca-toggle.on{background:var(--acc,#2563eb)}' +
    '.ca-toggle::after{content:"";position:absolute;width:16px;height:16px;border-radius:50%;background:#fff;top:2px;left:2px;transition:left .2s}' +
    '.ca-toggle.on::after{left:18px}' +
    '.ca-num-input{width:60px;background:var(--card2);border:1px solid var(--line);border-radius:4px;color:var(--txt);padding:4px 6px;font-size:.78rem;text-align:center;font-family:inherit}' +
    '.ca-num-input:focus{outline:none;border-color:var(--acc)}' +
    '.ca-result-row{display:flex;align-items:center;gap:10px;padding:8px 10px;border-bottom:1px solid var(--line);font-size:.78rem}' +
    '.ca-result-row:last-child{border-bottom:none}' +
    '.ca-result-pw{flex:1;font-family:ui-monospace,monospace;word-break:break-all}' +
    '.ca-result-badge{padding:2px 8px;border-radius:3px;font-size:.65rem;font-weight:700;text-transform:uppercase;letter-spacing:.03em}' +
    '.ca-gen-row{display:flex;align-items:center;gap:6px;padding:6px 10px;background:var(--card2);border:1px solid var(--line);border-radius:6px;margin-bottom:6px;font-family:ui-monospace,monospace;font-size:.8rem}' +
    '.ca-gen-score{width:50px;text-align:right;font-weight:700;font-size:.72rem}' +
    '.ca-gen-copy{padding:3px 8px;border:1px solid var(--line);border-radius:4px;background:transparent;color:var(--mut);cursor:pointer;font-size:.65rem;font-family:inherit}' +
    '.ca-gen-copy:hover{border-color:var(--acc);color:var(--acc)}' +
    '.ca-empty{text-align:center;padding:40px;color:var(--mut);font-size:.85rem}' +
    '[data-style=pro] .ca-wrap{color:#0f172a}' +
    '[data-style=pro] .ca-panel{background:#fff;border-color:#e2e8f0}' +
    '[data-style=pro] .ca-input,[data-style=pro] .ca-textarea{background:#f8fafc;border-color:#e2e8f0;color:#0f172a}' +
    '[data-style=pro] .ca-stat{background:#f8fafc;border-color:#e2e8f0}' +
    '[data-style=pro] .ca-tab{border-color:#e2e8f0;color:#64748b}' +
    '[data-style=pro] .ca-tab:hover{background:#f1f5f9;color:#0f172a}' +
    '[data-style=pro] .ca-tab.active{background:#2563eb;color:#fff;border-color:#2563eb}' +
    '[data-style=pro] .ca-breakdown li{border-bottom-color:#f1f5f9}' +
    '[data-style=pro] .ca-meter{background:#e2e8f0}' +
    '[data-style=pro] .ca-policy-row{border-bottom-color:#f1f5f9}' +
    '[data-style=pro] .ca-toggle{background:#cbd5e1}' +
    '[data-style=pro] .ca-result-row{border-bottom-color:#f1f5f9}' +
    '[data-style=pro] .ca-gen-row{background:#f8fafc;border-color:#e2e8f0}' +
    '[data-style=pro] .ca-gen-copy{border-color:#e2e8f0;color:#64748b}' +
    '[data-style=pro] .ca-gen-copy:hover{border-color:#2563eb;color:#2563eb}' +
    '[data-style=pro] .ca-hash-match{background:rgba(37,99,235,.04)}' +
    '[data-style=pro] .ca-num-input{background:#f8fafc;border-color:#e2e8f0;color:#0f172a}' +
    '</style>';

  function render() {
    var tabs = [
      { id: 'strength', label: 'Strength' },
      { id: 'hashid', label: 'Hash ID' },
      { id: 'policy', label: 'Policy Check' },
      { id: 'generator', label: 'Generator' }
    ];
    var html = CSS + '<div class="ca-wrap">' +
      '<div class="ca-header"><h1 class="ca-title">Credential Auditor</h1><p class="ca-sub">Test password strength, identify hash types, check policies, and generate secure passwords</p></div>' +
      '<div class="ca-tabs">' + tabs.map(function(t) { return '<button class="ca-tab' + (state.tab === t.id ? ' active' : '') + '" data-tab="' + t.id + '">' + t.label + '</button>'; }).join('') + '</div>';

    if (state.tab === 'strength') html += renderStrength();
    else if (state.tab === 'hashid') html += renderHashId();
    else if (state.tab === 'policy') html += renderPolicy();
    else if (state.tab === 'generator') html += renderGenerator();

    html += '</div>';
    container.innerHTML = html;
    wireEvents();
  }

  function renderStrength() {
    var h = '<div class="ca-panel">' +
      '<input class="ca-input" id="ca-pw" type="text" placeholder="Enter a password to test..." value="' + esc(state.password) + '" autocomplete="off">' +
      '</div>';
    if (state.password) {
      var res = scorePassword(state.password);
      h += '<div class="ca-panel">' +
        '<div style="display:flex;align-items:center;justify-content:space-between">' +
        '<div class="ca-score-label" style="color:' + res.color + '">' + res.label + '</div>' +
        '<div style="font-size:.85rem;font-weight:700;color:' + res.color + '">' + res.score + '/100</div></div>' +
        '<div class="ca-meter"><div class="ca-meter-fill" style="width:' + res.score + '%;background:' + res.color + '"></div></div>' +
        '<div class="ca-stat-grid">' +
        '<div class="ca-stat"><div class="ca-stat-val">' + res.length + '</div><div class="ca-stat-lbl">Length</div></div>' +
        '<div class="ca-stat"><div class="ca-stat-val">' + res.entropy + '</div><div class="ca-stat-lbl">Entropy (bits)</div></div>' +
        '<div class="ca-stat"><div class="ca-stat-val">' + res.charSet + '</div><div class="ca-stat-lbl">Charset Size</div></div>' +
        '</div>' +
        '<ul class="ca-breakdown">';
      res.breakdown.forEach(function(b) {
        var col = b.pass ? '#16a34a' : '#dc2626';
        h += '<li><div class="ca-check-icon" style="background:' + col + '22;color:' + col + '">' + (b.pass ? '&#10003;' : '&#10007;') + '</div><span>' + b.rule + '</span></li>';
      });
      h += '</ul></div>';
    }
    return h;
  }

  function renderHashId() {
    var h = '<div class="ca-panel">' +
      '<textarea class="ca-textarea" id="ca-hash" placeholder="Paste hash(es) to identify — one per line...\n\nExamples:\n5d41402abc4b2a76b9719d911017c592\n$2b$12$LJ3m4ys3Gk9PJv7k/kR7iOTpiYwQFCep7PJvLjKB.fOe/kNCT84u.">' + esc(state.hashInput) + '</textarea>' +
      '<div style="margin-top:10px"><button class="ca-btn" id="ca-id-hash">Identify Hashes</button></div>' +
      '</div>';
    if (state.hashInput) {
      var lines = state.hashInput.trim().split('\n').filter(Boolean);
      var anyResult = false;
      lines.forEach(function(line) {
        var matches = identifyHash(line.trim());
        if (matches.length) {
          anyResult = true;
          h += '<div class="ca-panel">' +
            '<div style="font-family:ui-monospace,monospace;font-size:.75rem;color:var(--mut);margin-bottom:10px;word-break:break-all">' + esc(line.trim()) + '</div>';
          matches.forEach(function(m) {
            var confCol = m.confidence >= 80 ? '#16a34a' : m.confidence >= 60 ? '#eab308' : '#f97316';
            h += '<div class="ca-hash-match">' +
              '<div class="ca-hash-name">' + esc(m.name) + '</div>' +
              '<div class="ca-hash-conf">Confidence: <span style="color:' + confCol + ';font-weight:700">' + m.confidence + '%</span></div></div>';
          });
          h += '</div>';
        }
      });
      if (!anyResult) h += '<div class="ca-empty">No known hash formats detected.</div>';
    }
    return h;
  }

  function renderPolicy() {
    var p = state.policy;
    var h = '<div class="ca-panel"><h3 style="margin:0 0 14px;font-size:.85rem">Password Policy</h3>';
    var rules = [
      { key: 'minLen', label: 'Minimum length', type: 'num', val: p.minLen },
      { key: 'maxLen', label: 'Maximum length', type: 'num', val: p.maxLen },
      { key: 'reqUpper', label: 'Require uppercase', type: 'toggle', val: p.reqUpper },
      { key: 'reqLower', label: 'Require lowercase', type: 'toggle', val: p.reqLower },
      { key: 'reqDigit', label: 'Require digit', type: 'toggle', val: p.reqDigit },
      { key: 'reqSpecial', label: 'Require special character', type: 'toggle', val: p.reqSpecial },
      { key: 'noCommon', label: 'Block common passwords', type: 'toggle', val: p.noCommon }
    ];
    rules.forEach(function(r) {
      h += '<div class="ca-policy-row"><label>' + r.label + '</label>';
      if (r.type === 'toggle') {
        h += '<div class="dn-round ca-toggle' + (r.val ? ' on' : '') + '" data-policy="' + r.key + '"></div>';
      } else {
        h += '<input class="ca-num-input" type="number" data-policy-num="' + r.key + '" value="' + r.val + '" min="1" max="256">';
      }
      h += '</div>';
    });
    h += '</div>';

    h += '<div class="ca-panel"><h3 style="margin:0 0 10px;font-size:.85rem">Test Passwords Against Policy</h3>' +
      '<textarea class="ca-textarea" id="ca-policy-pw" placeholder="Enter passwords to check — one per line...">' + esc(state.policyPasswords) + '</textarea>' +
      '<div style="margin-top:10px"><button class="ca-btn" id="ca-check-policy">Check Policy</button></div></div>';

    if (state.policyPasswords) {
      var pws = state.policyPasswords.trim().split('\n').filter(Boolean);
      var results = checkPolicy(pws, state.policy);
      var passCount = results.filter(function(r) { return r.pass; }).length;
      h += '<div class="ca-panel"><div style="display:flex;justify-content:space-between;margin-bottom:10px;font-size:.78rem"><span>' + results.length + ' passwords tested</span><span style="color:' + (passCount === results.length ? '#16a34a' : '#dc2626') + ';font-weight:700">' + passCount + ' pass / ' + (results.length - passCount) + ' fail</span></div>';
      results.forEach(function(r) {
        var col = r.pass ? '#16a34a' : '#dc2626';
        h += '<div class="ca-result-row"><div class="ca-result-badge" style="background:' + col + '22;color:' + col + '">' + (r.pass ? 'PASS' : 'FAIL') + '</div>' +
          '<span class="ca-result-pw">' + esc(r.password) + '</span>';
        if (!r.pass) h += '<span style="font-size:.68rem;color:var(--mut)">' + r.issues.join(', ') + '</span>';
        h += '</div>';
      });
      h += '</div>';
    }
    return h;
  }

  function generatePassword(len, upper, lower, digit, special) {
    var chars = '';
    if (lower) chars += 'abcdefghijklmnopqrstuvwxyz';
    if (upper) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (digit) chars += '0123456789';
    if (special) chars += '!@#$%^&*()-_=+[]{}|;:,.<>?';
    if (!chars) chars = 'abcdefghijklmnopqrstuvwxyz';
    var arr = new Uint32Array(len);
    crypto.getRandomValues(arr);
    var pw = '';
    for (var i = 0; i < len; i++) pw += chars[arr[i] % chars.length];
    return pw;
  }

  function renderGenerator() {
    var h = '<div class="ca-panel"><h3 style="margin:0 0 14px;font-size:.85rem">Password Generator</h3>' +
      '<div class="ca-policy-row"><label>Length</label><input class="ca-num-input" type="number" id="ca-gen-len" value="' + state.genLen + '" min="4" max="128"></div>' +
      '<div class="ca-policy-row"><label>Uppercase (A-Z)</label><div class="dn-round ca-toggle' + (state.genIncUpper ? ' on' : '') + '" data-gen="upper"></div></div>' +
      '<div class="ca-policy-row"><label>Lowercase (a-z)</label><div class="dn-round ca-toggle' + (state.genIncLower ? ' on' : '') + '" data-gen="lower"></div></div>' +
      '<div class="ca-policy-row"><label>Digits (0-9)</label><div class="dn-round ca-toggle' + (state.genIncDigit ? ' on' : '') + '" data-gen="digit"></div></div>' +
      '<div class="ca-policy-row"><label>Special (!@#$...)</label><div class="dn-round ca-toggle' + (state.genIncSpecial ? ' on' : '') + '" data-gen="special"></div></div>' +
      '<div style="display:flex;gap:8px;margin-top:14px">' +
      '<button class="ca-btn" id="ca-gen-one">Generate 1</button>' +
      '<button class="ca-btn ca-btn-ghost" id="ca-gen-five">Generate 5</button>' +
      '<button class="ca-btn ca-btn-ghost" id="ca-gen-clear">Clear</button></div></div>';

    if (state.generated.length) {
      h += '<div class="ca-panel">';
      state.generated.forEach(function(pw) {
        var s = scorePassword(pw);
        h += '<div class="ca-gen-row"><span style="flex:1;word-break:break-all">' + esc(pw) + '</span><span class="ca-gen-score" style="color:' + s.color + '">' + s.score + '</span><button class="ca-gen-copy" data-pw="' + esc(pw) + '">Copy</button></div>';
      });
      h += '</div>';
    }
    return h;
  }

  function wireEvents() {
    container.querySelectorAll('.ca-tab').forEach(function(btn) {
      btn.onclick = function() { state.tab = btn.dataset.tab; render(); };
    });

    var pwInput = container.querySelector('#ca-pw');
    if (pwInput) {
      pwInput.oninput = function() { state.password = pwInput.value; render(); var el = container.querySelector('#ca-pw'); if (el) { el.focus(); el.selectionStart = el.selectionEnd = el.value.length; } };
    }

    var hashBtn = container.querySelector('#ca-id-hash');
    if (hashBtn) hashBtn.onclick = function() {
      var el = container.querySelector('#ca-hash');
      if (el) state.hashInput = el.value;
      render();
    };

    container.querySelectorAll('.ca-toggle[data-policy]').forEach(function(t) {
      t.onclick = function() { state.policy[t.dataset.policy] = !state.policy[t.dataset.policy]; render(); };
    });
    container.querySelectorAll('input[data-policy-num]').forEach(function(inp) {
      inp.onchange = function() { state.policy[inp.dataset.policyNum] = parseInt(inp.value) || 1; };
    });

    var checkBtn = container.querySelector('#ca-check-policy');
    if (checkBtn) checkBtn.onclick = function() {
      var el = container.querySelector('#ca-policy-pw');
      if (el) state.policyPasswords = el.value;
      render();
    };

    container.querySelectorAll('.ca-toggle[data-gen]').forEach(function(t) {
      t.onclick = function() {
        var k = t.dataset.gen;
        if (k === 'upper') state.genIncUpper = !state.genIncUpper;
        else if (k === 'lower') state.genIncLower = !state.genIncLower;
        else if (k === 'digit') state.genIncDigit = !state.genIncDigit;
        else if (k === 'special') state.genIncSpecial = !state.genIncSpecial;
        render();
      };
    });

    var genOne = container.querySelector('#ca-gen-one');
    if (genOne) genOne.onclick = function() {
      var lenEl = container.querySelector('#ca-gen-len');
      if (lenEl) state.genLen = parseInt(lenEl.value) || 16;
      state.generated.unshift(generatePassword(state.genLen, state.genIncUpper, state.genIncLower, state.genIncDigit, state.genIncSpecial));
      render();
    };
    var genFive = container.querySelector('#ca-gen-five');
    if (genFive) genFive.onclick = function() {
      var lenEl = container.querySelector('#ca-gen-len');
      if (lenEl) state.genLen = parseInt(lenEl.value) || 16;
      for (var i = 0; i < 5; i++) state.generated.unshift(generatePassword(state.genLen, state.genIncUpper, state.genIncLower, state.genIncDigit, state.genIncSpecial));
      render();
    };
    var genClear = container.querySelector('#ca-gen-clear');
    if (genClear) genClear.onclick = function() { state.generated = []; render(); };

    container.querySelectorAll('.ca-gen-copy').forEach(function(btn) {
      btn.onclick = function() {
        if (navigator.clipboard) navigator.clipboard.writeText(btn.dataset.pw);
        btn.textContent = 'Copied!';
        setTimeout(function() { btn.textContent = 'Copy'; }, 1500);
      };
    });
  }

  render();
}
