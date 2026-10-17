import { esc } from '/js/shared.js';

var KEYBOARD_WALKS = [
  'qwerty', 'qwertyuiop', 'asdf', 'asdfgh', 'asdfghjkl', 'zxcvbn', 'zxcvbnm',
  'qazwsx', 'wsxedc', 'edcrfv', 'rfvtgb', 'tgbyhn', 'yhnujm',
  '1qaz2wsx', '2wsx3edc', '!@#$%', '12345', '123456', '1234567890',
  'abcdef', 'abcdefgh', 'abc123', 'password', 'letmein', 'welcome',
  'qweasd', 'zaqwsx', 'poiuyt', 'lkjhgf', 'mnbvcx'
];

var LEET_MAP = {
  'a': ['4', '@'], 'b': ['8'], 'c': ['('], 'e': ['3'],
  'g': ['6', '9'], 'h': ['#'], 'i': ['1', '!', '|'], 'l': ['1', '|'],
  'o': ['0'], 's': ['5', '$'], 't': ['7', '+'], 'z': ['2']
};

var COMMON_PATTERNS = [
  { name: 'Dictionary word', regex: /^[a-zA-Z]{4,}$/, desc: 'Single dictionary word with no complexity' },
  { name: 'Word + digits', regex: /^[a-zA-Z]+\d{1,4}$/, desc: 'Common word followed by a few numbers' },
  { name: 'Digits + word', regex: /^\d{1,4}[a-zA-Z]+$/, desc: 'Numbers followed by a word' },
  { name: 'Date pattern (MMDDYYYY)', regex: /^(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(19|20)\d{2}$/, desc: 'Date in MMDDYYYY format' },
  { name: 'Date pattern (YYYYMMDD)', regex: /^(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])$/, desc: 'Date in YYYYMMDD format' },
  { name: 'Date pattern (DDMMYYYY)', regex: /^(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])(19|20)\d{2}$/, desc: 'Date in DDMMYYYY format' },
  { name: 'Phone number', regex: /^\d{3}[-.]?\d{3}[-.]?\d{4}$/, desc: 'US phone number format' },
  { name: 'All same character', regex: /^(.)\1+$/, desc: 'Single character repeated' },
  { name: 'Capitalized word + symbol + digits', regex: /^[A-Z][a-z]+[!@#$%^&*]\d+$/, desc: 'Very common pattern: Word!123' },
  { name: 'Season + year', regex: /^(spring|summer|fall|autumn|winter)(20\d{2}|19\d{2})[!@#$%^&*]?$/i, desc: 'Seasonal password pattern' }
];

var POLICIES = [
  {
    name: 'NIST 800-63B',
    desc: 'National Institute of Standards and Technology Digital Identity Guidelines (2024)',
    rules: [
      { id: 'nist-len', label: 'Minimum 8 characters', check: function(p) { return p.length >= 8; } },
      { id: 'nist-max', label: 'Support up to 64 characters', check: function(p) { return p.length <= 64; } },
      { id: 'nist-no-trunc', label: 'Not truncated by system', check: function() { return true; } },
      { id: 'nist-no-compose', label: 'No composition rules required', check: function() { return true; }, info: true },
      { id: 'nist-no-hints', label: 'No password hints', check: function() { return true; }, info: true },
      { id: 'nist-breach', label: 'Not in breached password list', check: function(p) { return p.length >= 8 && !/^(password|12345678|qwerty123|letmein|welcome1|admin123|monkey|dragon|master|trustno1)$/i.test(p); } }
    ]
  },
  {
    name: 'PCI DSS v4.0',
    desc: 'Payment Card Industry Data Security Standard for cardholder data environments',
    rules: [
      { id: 'pci-len', label: 'Minimum 12 characters (or 8 if MFA)', check: function(p) { return p.length >= 12; } },
      { id: 'pci-alpha', label: 'Contains alphabetic characters', check: function(p) { return /[a-zA-Z]/.test(p); } },
      { id: 'pci-num', label: 'Contains numeric characters', check: function(p) { return /\d/.test(p); } },
      { id: 'pci-change', label: 'Changed every 90 days', check: function() { return true; }, info: true },
      { id: 'pci-history', label: 'Different from last 4 passwords', check: function() { return true; }, info: true },
      { id: 'pci-lockout', label: 'Account lockout after 10 attempts', check: function() { return true; }, info: true }
    ]
  },
  {
    name: 'HIPAA',
    desc: 'Health Insurance Portability and Accountability Act technical safeguards',
    rules: [
      { id: 'hipaa-len', label: 'Minimum 8 characters', check: function(p) { return p.length >= 8; } },
      { id: 'hipaa-upper', label: 'Contains uppercase letter', check: function(p) { return /[A-Z]/.test(p); } },
      { id: 'hipaa-lower', label: 'Contains lowercase letter', check: function(p) { return /[a-z]/.test(p); } },
      { id: 'hipaa-digit', label: 'Contains digit', check: function(p) { return /\d/.test(p); } },
      { id: 'hipaa-special', label: 'Contains special character', check: function(p) { return /[^a-zA-Z0-9]/.test(p); } },
      { id: 'hipaa-expire', label: 'Changed every 60-90 days', check: function() { return true; }, info: true },
      { id: 'hipaa-unique', label: 'Unique (not reused across systems)', check: function() { return true; }, info: true }
    ]
  }
];

function calcEntropy(pw) {
  if (!pw || pw.length === 0) return 0;
  var charset = 0;
  if (/[a-z]/.test(pw)) charset += 26;
  if (/[A-Z]/.test(pw)) charset += 26;
  if (/\d/.test(pw)) charset += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) charset += 33;
  if (charset === 0) charset = 1;
  // length * log2(charset) is algebraically identical to log2(charset^length)
  // but avoids Math.pow overflowing to Infinity for long passwords (e.g.
  // charset^length exceeds Number.MAX_VALUE past ~150 chars), which used to
  // report "Infinity bits".
  return Math.round(pw.length * Math.log2(charset) * 10) / 10;
}

function crackTime(entropy) {
  var combos = Math.pow(2, entropy);
  var speeds = [
    { name: 'Online attack', rate: 1e3, desc: '1K guesses/sec (throttled)' },
    { name: 'Offline (slow hash)', rate: 1e6, desc: '1M guesses/sec (bcrypt)' },
    { name: 'Offline (fast hash)', rate: 1e9, desc: '1B guesses/sec (MD5/SHA1)' },
    { name: 'GPU cluster', rate: 1e11, desc: '100B guesses/sec (hashcat)' }
  ];
  return speeds.map(function(s) {
    var secs = combos / s.rate / 2;
    return { name: s.name, desc: s.desc, time: formatTime(secs) };
  });
}

function formatTime(secs) {
  if (!isFinite(secs) || secs > 1e18) return 'centuries+';
  if (secs < 0.001) return 'instant';
  if (secs < 1) return 'less than a second';
  if (secs < 60) return Math.round(secs) + ' seconds';
  if (secs < 3600) return Math.round(secs / 60) + ' minutes';
  if (secs < 86400) return Math.round(secs / 3600) + ' hours';
  if (secs < 2592000) return Math.round(secs / 86400) + ' days';
  if (secs < 31536000) return Math.round(secs / 2592000) + ' months';
  var years = secs / 31536000;
  if (years < 1000) return Math.round(years) + ' years';
  if (years < 1e6) return Math.round(years / 1000) + 'K years';
  if (years < 1e9) return Math.round(years / 1e6) + 'M years';
  if (years < 1e12) return Math.round(years / 1e9) + 'B years';
  return 'centuries+';
}

function charBreakdown(pw) {
  var upper = 0, lower = 0, digits = 0, symbols = 0, spaces = 0;
  for (var i = 0; i < pw.length; i++) {
    var ch = pw[i];
    if (/[A-Z]/.test(ch)) upper++;
    else if (/[a-z]/.test(ch)) lower++;
    else if (/\d/.test(ch)) digits++;
    else if (ch === ' ') spaces++;
    else symbols++;
  }
  return { upper: upper, lower: lower, digits: digits, symbols: symbols, spaces: spaces, total: pw.length };
}

function strengthLabel(entropy) {
  if (entropy === 0) return { label: 'None', color: '#64748b', pct: 0 };
  if (entropy < 28) return { label: 'Very Weak', color: '#dc2626', pct: 10 };
  if (entropy < 36) return { label: 'Weak', color: '#f97316', pct: 25 };
  if (entropy < 60) return { label: 'Fair', color: '#d97706', pct: 45 };
  if (entropy < 80) return { label: 'Strong', color: '#16a34a', pct: 70 };
  if (entropy < 120) return { label: 'Very Strong', color: '#059669', pct: 90 };
  return { label: 'Excellent', color: '#0891b2', pct: 100 };
}

function detectPatterns(pw) {
  var found = [];
  if (!pw) return found;
  var lower = pw.toLowerCase();

  for (var i = 0; i < KEYBOARD_WALKS.length; i++) {
    if (lower.indexOf(KEYBOARD_WALKS[i]) !== -1) {
      found.push({ severity: 'high', text: 'Contains keyboard walk pattern: "' + KEYBOARD_WALKS[i] + '"' });
      break;
    }
  }

  for (var i = 0; i < COMMON_PATTERNS.length; i++) {
    if (COMMON_PATTERNS[i].regex.test(pw)) {
      found.push({ severity: 'medium', text: COMMON_PATTERNS[i].name + ': ' + COMMON_PATTERNS[i].desc });
    }
  }

  if (/(.)\1{2,}/.test(pw)) {
    var rep = pw.match(/(.)\1{2,}/);
    found.push({ severity: 'medium', text: 'Repeated characters detected: "' + rep[0].substring(0, 8) + '"' });
  }

  var seqCount = 0;
  for (var i = 0; i < pw.length - 2; i++) {
    if (pw.charCodeAt(i) + 1 === pw.charCodeAt(i + 1) && pw.charCodeAt(i + 1) + 1 === pw.charCodeAt(i + 2)) {
      seqCount++;
    }
  }
  if (seqCount > 0) {
    found.push({ severity: 'medium', text: 'Sequential characters detected (' + seqCount + ' sequence' + (seqCount > 1 ? 's' : '') + ')' });
  }

  var hasLeet = false;
  var leetKeys = Object.keys(LEET_MAP);
  for (var i = 0; i < leetKeys.length; i++) {
    var subs = LEET_MAP[leetKeys[i]];
    for (var j = 0; j < subs.length; j++) {
      if (pw.indexOf(subs[j]) !== -1) { hasLeet = true; break; }
    }
    if (hasLeet) break;
  }
  var deleet = pw.toLowerCase().replace(/4/g, 'a').replace(/@/g, 'a').replace(/8/g, 'b').replace(/\(/g, 'c')
    .replace(/3/g, 'e').replace(/6/g, 'g').replace(/#/g, 'h').replace(/1/g, 'i').replace(/\|/g, 'i')
    .replace(/0/g, 'o').replace(/5/g, 's').replace(/\$/g, 's').replace(/7/g, 't').replace(/\+/g, 't').replace(/2/g, 'z');
  if (hasLeet && /^[a-z]+$/.test(deleet) && deleet.length >= 4) {
    found.push({ severity: 'medium', text: 'Possible l33t speak substitution detected (decoded: "' + deleet.substring(0, 20) + '")' });
  }

  if (/^[a-zA-Z]+$/.test(pw) && pw.length < 10) {
    found.push({ severity: 'high', text: 'Letters only with no digits or symbols. Highly vulnerable to dictionary attacks.' });
  }
  if (/^\d+$/.test(pw)) {
    found.push({ severity: 'high', text: 'Digits only. Extremely small keyspace.' });
  }

  if (found.length === 0) {
    found.push({ severity: 'info', text: 'No common weak patterns detected. Password appears to use a good structure.' });
  }
  return found;
}

function generatePassword(len, useUpper, useLower, useDigits, useSymbols, customChars) {
  var chars = '';
  if (useLower) chars += 'abcdefghijklmnopqrstuvwxyz';
  if (useUpper) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (useDigits) chars += '0123456789';
  if (useSymbols) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';
  if (customChars) chars += customChars;
  if (!chars) chars = 'abcdefghijklmnopqrstuvwxyz';
  var result = '';
  var arr = new Uint32Array(len);
  crypto.getRandomValues(arr);
  for (var i = 0; i < len; i++) {
    result += chars[arr[i] % chars.length];
  }
  return result;
}

export function renderPasswordAnalyzer(container) {
  var activeTab = 'analyze';
  var password = '';
  var showPw = false;
  var genLength = 16;
  var genUpper = true;
  var genLower = true;
  var genDigits = true;
  var genSymbols = true;
  var genCustom = '';
  var generatedPws = [];
  var policyPassword = '';

  var PA_CSS = '<style>' +
    '.pa-wrap{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#c8d6e5;max-width:1100px}' +
    '.pa-title{font-size:1.6rem;font-weight:700;margin:0 0 6px;color:var(--txt)}' +
    '.pa-sub{color:var(--mut);font-size:.85rem;margin-bottom:20px;line-height:1.5}' +
    '.pa-tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:24px}' +
    '.pa-tab{background:var(--card);border:1px solid var(--line);color:var(--mut);padding:8px 16px;font-size:.75rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase;cursor:pointer;border-radius:4px;transition:all .15s;font-family:inherit}' +
    '.pa-tab:hover{background:color-mix(in srgb,var(--acc) 8%,var(--card));color:var(--txt)}' +
    '.pa-tab.active{background:var(--acc);color:var(--on-acc,#fff);border-color:var(--acc)}' +
    '.pa-panel{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:20px;margin-bottom:16px}' +
    '.pa-panel-title{font-size:.8rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--acc);margin-bottom:12px}' +
    '.pa-input-wrap{display:flex;gap:8px;margin-bottom:16px}' +
    '.pa-input{flex:1;background:var(--card2,#0a0e14);border:1px solid var(--line);color:var(--txt);font-family:ui-monospace,monospace;font-size:.85rem;padding:12px;border-radius:6px}' +
    '.pa-input:focus{border-color:var(--acc);outline:none}' +
    '.pa-btn{background:var(--acc);color:var(--on-acc,#fff);border:1px solid var(--acc);padding:8px 16px;border-radius:4px;font-size:.78rem;font-weight:600;cursor:pointer;font-family:inherit;transition:all .15s}' +
    '.pa-btn:hover{opacity:.9}' +
    '.pa-btn.ghost{background:transparent;color:var(--acc);border-color:var(--line)}' +
    '.pa-btn.ghost:hover{border-color:var(--acc);background:color-mix(in srgb,var(--acc) 8%,transparent)}' +
    '.pa-btn.sm{padding:6px 12px;font-size:.72rem}' +
    '.pa-meter-track{width:100%;height:8px;background:var(--card2,#0a0e14);border-radius:4px;overflow:hidden;margin:8px 0}' +
    '.pa-meter-fill{height:100%;border-radius:4px;transition:width .3s,background .3s}' +
    '.pa-strength-row{display:flex;align-items:center;justify-content:space-between;margin-bottom:4px}' +
    '.pa-strength-label{font-size:.85rem;font-weight:700}' +
    '.pa-entropy{font-size:.75rem;color:var(--mut);font-family:ui-monospace,monospace}' +
    '.pa-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}' +
    '@media(max-width:768px){.pa-grid{grid-template-columns:1fr}}' +
    '.pa-stat{display:flex;align-items:center;gap:10px;padding:10px;background:var(--card2,#0a0e14);border-radius:6px;margin-bottom:8px}' +
    '.pa-stat-icon{width:36px;height:36px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:1rem;font-weight:700;flex-shrink:0}' +
    '.pa-stat-val{font-size:1.1rem;font-weight:700;color:var(--txt)}' +
    '.pa-stat-lbl{font-size:.7rem;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}' +
    '.pa-crack{display:flex;align-items:center;gap:12px;padding:10px 14px;border-bottom:1px solid var(--line);font-size:.8rem}' +
    '.pa-crack:last-child{border-bottom:none}' +
    '.pa-crack-name{font-weight:600;color:var(--txt);min-width:140px;flex-shrink:0}' +
    '.pa-crack-desc{color:var(--mut);font-size:.7rem;flex:1}' +
    '.pa-crack-time{font-weight:700;font-family:ui-monospace,monospace;font-size:.78rem;white-space:nowrap}' +
    '.pa-alert{padding:10px 14px;border-radius:6px;margin-bottom:8px;font-size:.78rem;display:flex;align-items:flex-start;gap:8px;line-height:1.5}' +
    '.pa-alert.high{background:rgba(249,115,22,.1);border-left:3px solid #f97316;color:#fdba74}' +
    '.pa-alert.medium{background:rgba(217,119,6,.1);border-left:3px solid #d97706;color:#fcd34d}' +
    '.pa-alert.info{background:rgba(37,99,235,.08);border-left:3px solid #2563eb;color:#93c5fd}' +
    '.pa-alert-icon{flex-shrink:0;font-size:1rem}' +
    '.pa-table{width:100%;border-collapse:collapse;font-size:.78rem}' +
    '.pa-table th{text-align:left;padding:10px 12px;background:rgba(0,0,0,.2);color:var(--mut);font-weight:600;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;border-bottom:2px solid var(--line)}' +
    '.pa-table td{padding:10px 12px;border-bottom:1px solid var(--line);color:var(--txt);vertical-align:top}' +
    '.pa-table tr:hover td{background:rgba(0,0,0,.05)}' +
    '.pa-badge{display:inline-block;padding:3px 8px;border-radius:4px;font-size:.65rem;font-weight:700;letter-spacing:.04em;text-transform:uppercase}' +
    '.pa-badge.pass{background:rgba(22,163,74,.15);color:#16a34a}' +
    '.pa-badge.fail{background:rgba(220,38,38,.15);color:#dc2626}' +
    '.pa-badge.info{background:rgba(100,116,139,.15);color:#64748b}' +
    '.pa-gen-output{background:var(--card2,#0a0e14);border:1px solid var(--line);border-radius:6px;padding:14px;font-family:ui-monospace,monospace;font-size:.85rem;color:var(--txt);word-break:break-all;margin:12px 0;min-height:42px;line-height:1.6}' +
    '.pa-slider-wrap{display:flex;align-items:center;gap:12px;margin-bottom:14px}' +
    '.pa-slider{flex:1;accent-color:var(--acc)}' +
    '.pa-slider-val{font-family:ui-monospace,monospace;font-size:.85rem;color:var(--txt);min-width:36px;text-align:center}' +
    '.pa-toggle-row{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px}' +
    '.pa-toggle{display:flex;align-items:center;gap:6px;padding:6px 14px;background:var(--card2,#0a0e14);border:1px solid var(--line);border-radius:4px;cursor:pointer;font-size:.78rem;color:var(--mut);transition:all .15s;user-select:none}' +
    '.pa-toggle.on{border-color:var(--acc);color:var(--acc);background:color-mix(in srgb,var(--acc) 10%,var(--card2,#0a0e14))}' +
    '.pa-toggle-dot{width:10px;height:10px;border-radius:50%;background:var(--line);transition:background .15s}' +
    '.pa-toggle.on .pa-toggle-dot{background:var(--acc)}' +
    '.pa-row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}' +
    '.pa-pct-bar{display:flex;height:6px;border-radius:3px;overflow:hidden;margin-top:6px}' +
    '.pa-policy-card{border:1px solid var(--line);border-radius:8px;padding:16px;margin-bottom:12px;background:var(--card)}' +
    '.pa-policy-name{font-size:.9rem;font-weight:700;color:var(--txt);margin-bottom:2px}' +
    '.pa-policy-desc{font-size:.72rem;color:var(--mut);margin-bottom:12px;line-height:1.4}' +
    '.pa-rule{display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid color-mix(in srgb,var(--line) 50%,transparent);font-size:.78rem}' +
    '.pa-rule:last-child{border-bottom:none}' +
    '.pa-rule-icon{font-size:.9rem;flex-shrink:0}' +
    '.pa-rule-text{flex:1;color:var(--txt)}' +
    '.pa-leet-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(100px,1fr));gap:8px}' +
    '.pa-leet-item{background:var(--card2,#0a0e14);border:1px solid var(--line);border-radius:6px;padding:8px 12px;text-align:center}' +
    '.pa-leet-char{font-size:1.1rem;font-weight:700;color:var(--acc);font-family:ui-monospace,monospace}' +
    '.pa-leet-sub{font-size:.72rem;color:var(--mut);margin-top:2px;font-family:ui-monospace,monospace}' +
    '[data-style=pro] .pa-wrap{color:#0f172a}' +
    '[data-style=pro] .pa-panel{background:#fff;border-color:#e2e8f0}' +
    '[data-style=pro] .pa-input{background:#f8fafc;border-color:#e2e8f0;color:#0f172a}' +
    '[data-style=pro] .pa-stat{background:#f8fafc}' +
    '[data-style=pro] .pa-gen-output{background:#f8fafc;border-color:#e2e8f0;color:#0f172a}' +
    '[data-style=pro] .pa-toggle{background:#f8fafc;border-color:#e2e8f0;color:#475569}' +
    '[data-style=pro] .pa-toggle.on{background:rgba(59,130,246,.06);color:#2563eb}' +
    '[data-style=pro] .pa-crack-name{color:#0f172a}' +
    '[data-style=pro] .pa-crack-desc{color:#64748b}' +
    '[data-style=pro] .pa-table td{color:#334155}' +
    '[data-style=pro] .pa-table th{background:#f1f5f9;color:#475569}' +
    '[data-style=pro] .pa-table tr:hover td{background:#f8fafc}' +
    '[data-style=pro] .pa-alert.high{background:rgba(249,115,22,.06);color:#9a3412}' +
    '[data-style=pro] .pa-alert.medium{background:rgba(217,119,6,.06);color:#92400e}' +
    '[data-style=pro] .pa-alert.info{background:rgba(37,99,235,.06);color:#1e40af}' +
    '[data-style=pro] .pa-leet-item{background:#f8fafc;border-color:#e2e8f0}' +
    '[data-style=pro] .pa-policy-card{background:#fff;border-color:#e2e8f0}' +
    '[data-style=pro] .pa-rule-text{color:#334155}' +
    '[data-style=pro] .pa-meter-track{background:#e2e8f0}' +
    '</style>';

  function render() {
    var tabsHtml = ['analyze', 'generator', 'policy', 'patterns'].map(function(t) {
      var labels = { analyze: 'Analyze', generator: 'Generator', policy: 'Policy', patterns: 'Patterns' };
      return '<button class="pa-tab' + (activeTab === t ? ' active' : '') + '" data-tab="' + t + '">' + labels[t] + '</button>';
    }).join('');

    var contentHtml = '';

    if (activeTab === 'analyze') {
      var entropy = calcEntropy(password);
      var strength = strengthLabel(entropy);
      var bd = charBreakdown(password);
      var cracks = crackTime(entropy);
      var patterns = detectPatterns(password);

      contentHtml = '<div class="pa-panel">' +
        '<div class="pa-panel-title">Password Input</div>' +
        '<div class="pa-input-wrap">' +
          '<input class="pa-input" id="pa-pw" type="' + (showPw ? 'text' : 'password') + '" placeholder="Enter a password to analyze..." value="' + esc(password) + '">' +
          '<button class="pa-btn ghost sm" id="pa-toggle-show">' + (showPw ? 'Hide' : 'Show') + '</button>' +
          '<button class="pa-btn ghost sm" id="pa-clear">Clear</button>' +
        '</div>' +
        '<div class="pa-strength-row">' +
          '<span class="pa-strength-label" style="color:' + strength.color + '">' + strength.label + '</span>' +
          '<span class="pa-entropy">' + entropy + ' bits of entropy</span>' +
        '</div>' +
        '<div class="pa-meter-track">' +
          '<div class="pa-meter-fill" style="width:' + strength.pct + '%;background:' + strength.color + '"></div>' +
        '</div>' +
      '</div>';

      if (password) {
        contentHtml += '<div class="pa-grid">' +
          '<div class="pa-panel">' +
            '<div class="pa-panel-title">Character Breakdown</div>' +
            '<div class="pa-stat"><div class="pa-stat-icon" style="background:rgba(37,99,235,.15);color:#3b82f6">Aa</div><div><div class="pa-stat-val">' + bd.upper + '</div><div class="pa-stat-lbl">Uppercase (' + (bd.total ? Math.round(bd.upper / bd.total * 100) : 0) + '%)</div></div></div>' +
            '<div class="pa-stat"><div class="pa-stat-icon" style="background:rgba(16,185,129,.15);color:#10b981">ab</div><div><div class="pa-stat-val">' + bd.lower + '</div><div class="pa-stat-lbl">Lowercase (' + (bd.total ? Math.round(bd.lower / bd.total * 100) : 0) + '%)</div></div></div>' +
            '<div class="pa-stat"><div class="pa-stat-icon" style="background:rgba(245,158,11,.15);color:#f59e0b">09</div><div><div class="pa-stat-val">' + bd.digits + '</div><div class="pa-stat-lbl">Digits (' + (bd.total ? Math.round(bd.digits / bd.total * 100) : 0) + '%)</div></div></div>' +
            '<div class="pa-stat"><div class="pa-stat-icon" style="background:rgba(168,85,247,.15);color:#a855f7">!@</div><div><div class="pa-stat-val">' + bd.symbols + '</div><div class="pa-stat-lbl">Symbols (' + (bd.total ? Math.round(bd.symbols / bd.total * 100) : 0) + '%)</div></div></div>' +
            (bd.spaces > 0 ? '<div class="pa-stat"><div class="pa-stat-icon" style="background:rgba(100,116,139,.15);color:#64748b">_</div><div><div class="pa-stat-val">' + bd.spaces + '</div><div class="pa-stat-lbl">Spaces (' + Math.round(bd.spaces / bd.total * 100) + '%)</div></div></div>' : '') +
            '<div style="margin-top:6px">' +
              '<div style="font-size:.7rem;color:var(--mut);margin-bottom:4px">Composition</div>' +
              '<div class="pa-pct-bar">' +
                (bd.upper ? '<div style="width:' + (bd.upper / bd.total * 100) + '%;background:#3b82f6" title="Uppercase"></div>' : '') +
                (bd.lower ? '<div style="width:' + (bd.lower / bd.total * 100) + '%;background:#10b981" title="Lowercase"></div>' : '') +
                (bd.digits ? '<div style="width:' + (bd.digits / bd.total * 100) + '%;background:#f59e0b" title="Digits"></div>' : '') +
                (bd.symbols ? '<div style="width:' + (bd.symbols / bd.total * 100) + '%;background:#a855f7" title="Symbols"></div>' : '') +
                (bd.spaces ? '<div style="width:' + (bd.spaces / bd.total * 100) + '%;background:#64748b" title="Spaces"></div>' : '') +
              '</div>' +
            '</div>' +
          '</div>' +
          '<div class="pa-panel">' +
            '<div class="pa-panel-title">Crack Time Estimates</div>';
        cracks.forEach(function(c) {
          var timeColor = '#16a34a';
          if (c.time === 'instant' || c.time === 'less than a second') timeColor = '#dc2626';
          else if (/seconds|minutes/.test(c.time)) timeColor = '#f97316';
          else if (/hours|days/.test(c.time)) timeColor = '#d97706';
          contentHtml += '<div class="pa-crack">' +
            '<div class="pa-crack-name">' + c.name + '</div>' +
            '<div class="pa-crack-desc">' + c.desc + '</div>' +
            '<div class="pa-crack-time" style="color:' + timeColor + '">' + c.time + '</div>' +
          '</div>';
        });
        contentHtml += '</div></div>';

        contentHtml += '<div class="pa-panel"><div class="pa-panel-title">Pattern Analysis</div>';
        patterns.forEach(function(p) {
          var icon = p.severity === 'high' ? '[!]' : p.severity === 'medium' ? '[~]' : 'ℹ';
          contentHtml += '<div class="pa-alert ' + p.severity + '">' +
            '<span class="pa-alert-icon">' + icon + '</span>' +
            '<span>' + esc(p.text) + '</span>' +
          '</div>';
        });
        contentHtml += '</div>';
      }

    } else if (activeTab === 'generator') {
      contentHtml = '<div class="pa-panel">' +
        '<div class="pa-panel-title">Password Generator</div>' +
        '<div class="pa-slider-wrap">' +
          '<span style="font-size:.78rem;color:var(--mut);min-width:50px">Length:</span>' +
          '<input type="range" class="pa-slider" id="pa-gen-len" min="8" max="128" value="' + genLength + '">' +
          '<span class="pa-slider-val" id="pa-gen-len-val">' + genLength + '</span>' +
        '</div>' +
        '<div class="pa-toggle-row">' +
          '<div class="pa-toggle' + (genUpper ? ' on' : '') + '" data-opt="upper"><span class="pa-toggle-dot"></span> Uppercase (A-Z)</div>' +
          '<div class="pa-toggle' + (genLower ? ' on' : '') + '" data-opt="lower"><span class="pa-toggle-dot"></span> Lowercase (a-z)</div>' +
          '<div class="pa-toggle' + (genDigits ? ' on' : '') + '" data-opt="digits"><span class="pa-toggle-dot"></span> Digits (0-9)</div>' +
          '<div class="pa-toggle' + (genSymbols ? ' on' : '') + '" data-opt="symbols"><span class="pa-toggle-dot"></span> Symbols (!@#$)</div>' +
        '</div>' +
        '<div style="margin-bottom:14px">' +
          '<label style="font-size:.72rem;color:var(--mut);display:block;margin-bottom:4px">Custom characters (optional):</label>' +
          '<input class="pa-input" id="pa-gen-custom" type="text" placeholder="Add custom characters..." value="' + esc(genCustom) + '" style="font-size:.78rem;padding:8px 12px">' +
        '</div>' +
        '<div class="pa-row" style="margin-bottom:4px">' +
          '<button class="pa-btn" id="pa-gen-one">Generate</button>' +
          '<button class="pa-btn ghost" id="pa-gen-batch">Generate 10</button>' +
          '<button class="pa-btn ghost" id="pa-gen-copy">Copy</button>' +
        '</div>' +
      '</div>';

      if (generatedPws.length > 0) {
        contentHtml += '<div class="pa-panel"><div class="pa-panel-title">Generated Passwords</div>';
        if (generatedPws.length === 1) {
          contentHtml += '<div class="pa-gen-output" id="pa-gen-out">' + esc(generatedPws[0]) + '</div>';
          var ge = calcEntropy(generatedPws[0]);
          var gs = strengthLabel(ge);
          contentHtml += '<div style="font-size:.75rem;color:var(--mut)">Entropy: <strong style="color:var(--txt)">' + ge + ' bits</strong> · Strength: <strong style="color:' + gs.color + '">' + gs.label + '</strong></div>';
        } else {
          contentHtml += '<table class="pa-table"><thead><tr><th>#</th><th>Password</th><th>Entropy</th><th>Strength</th><th></th></tr></thead><tbody>';
          generatedPws.forEach(function(pw, idx) {
            var ge = calcEntropy(pw);
            var gs = strengthLabel(ge);
            contentHtml += '<tr>' +
              '<td>' + (idx + 1) + '</td>' +
              '<td style="font-family:ui-monospace,monospace;font-size:.75rem;word-break:break-all">' + esc(pw) + '</td>' +
              '<td>' + ge + ' bits</td>' +
              '<td><span class="pa-badge ' + (gs.pct >= 70 ? 'pass' : 'fail') + '">' + gs.label + '</span></td>' +
              '<td><button class="pa-btn ghost sm pa-copy-single" data-idx="' + idx + '">Copy</button></td>' +
            '</tr>';
          });
          contentHtml += '</tbody></table>';
        }
        contentHtml += '</div>';
      }

    } else if (activeTab === 'policy') {
      contentHtml = '<div class="pa-panel">' +
        '<div class="pa-panel-title">Check Password Against Policies</div>' +
        '<div class="pa-input-wrap">' +
          '<input class="pa-input" id="pa-policy-pw" type="text" placeholder="Enter a password to check compliance..." value="' + esc(policyPassword) + '">' +
          '<button class="pa-btn" id="pa-policy-check">Check</button>' +
        '</div>' +
      '</div>';

      if (policyPassword) {
        POLICIES.forEach(function(pol) {
          var passed = 0;
          var total = 0;
          pol.rules.forEach(function(r) {
            if (!r.info) { total++; if (r.check(policyPassword)) passed++; }
          });
          var allPass = passed === total;
          contentHtml += '<div class="pa-policy-card">' +
            '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px">' +
              '<div class="pa-policy-name">' + esc(pol.name) + '</div>' +
              '<span class="pa-badge ' + (allPass ? 'pass' : 'fail') + '">' + (allPass ? 'COMPLIANT' : passed + '/' + total + ' PASS') + '</span>' +
            '</div>' +
            '<div class="pa-policy-desc">' + esc(pol.desc) + '</div>';
          pol.rules.forEach(function(r) {
            var ok = r.check(policyPassword);
            var icon = r.info ? '[i]' : (ok ? '[OK]' : '[X]');
            contentHtml += '<div class="pa-rule">' +
              '<span class="pa-rule-icon">' + icon + '</span>' +
              '<span class="pa-rule-text">' + esc(r.label) + '</span>' +
              (r.info ? '<span class="pa-badge info">INFO</span>' : '<span class="pa-badge ' + (ok ? 'pass' : 'fail') + '">' + (ok ? 'PASS' : 'FAIL') + '</span>') +
            '</div>';
          });
          contentHtml += '</div>';
        });

        contentHtml += '<div class="pa-panel"><div class="pa-panel-title">Compliance Summary</div>' +
          '<table class="pa-table"><thead><tr><th>Standard</th><th>Status</th><th>Pass</th><th>Fail</th></tr></thead><tbody>';
        POLICIES.forEach(function(pol) {
          var passed = 0, failed = 0;
          pol.rules.forEach(function(r) { if (!r.info) { if (r.check(policyPassword)) passed++; else failed++; } });
          contentHtml += '<tr><td><strong>' + esc(pol.name) + '</strong></td>' +
            '<td><span class="pa-badge ' + (failed === 0 ? 'pass' : 'fail') + '">' + (failed === 0 ? 'COMPLIANT' : 'NON-COMPLIANT') + '</span></td>' +
            '<td style="color:#16a34a;font-weight:600">' + passed + '</td>' +
            '<td style="color:' + (failed > 0 ? '#dc2626' : '#64748b') + ';font-weight:600">' + failed + '</td></tr>';
        });
        contentHtml += '</tbody></table></div>';
      } else {
        contentHtml += '<div class="pa-panel" style="text-align:center;padding:40px">' +
          '<p style="color:var(--mut);font-size:.85rem;margin:0">Enter a password above and click <strong>Check</strong> to evaluate compliance against NIST, PCI DSS, and HIPAA policies.</p>' +
        '</div>';
      }

    } else if (activeTab === 'patterns') {
      contentHtml = '<div class="pa-panel">' +
        '<div class="pa-panel-title">Keyboard Walk Patterns</div>' +
        '<p style="font-size:.78rem;color:var(--mut);margin-bottom:12px;line-height:1.5">Keyboard walks are passwords formed by pressing adjacent keys in sequence. Attackers test these early because they are extremely common.</p>' +
        '<table class="pa-table"><thead><tr><th>Pattern</th><th>Type</th><th>Risk</th></tr></thead><tbody>';
      var walks = [
        ['qwerty / qwertyuiop', 'Horizontal row', 'Critical'],
        ['asdf / asdfghjkl', 'Home row walk', 'Critical'],
        ['zxcvbn / zxcvbnm', 'Bottom row walk', 'Critical'],
        ['qazwsx / wsxedc', 'Vertical column walk', 'High'],
        ['1qaz2wsx', 'Mixed row diagonal', 'High'],
        ['!@#$%^&*', 'Shifted number row', 'High'],
        ['poiuyt / lkjhgf / mnbvcx', 'Reverse walks', 'High']
      ];
      walks.forEach(function(w) {
        var riskColor = w[2] === 'Critical' ? '#dc2626' : '#f97316';
        contentHtml += '<tr><td style="font-family:ui-monospace,monospace;font-size:.75rem">' + esc(w[0]) + '</td><td>' + esc(w[1]) + '</td><td><span class="pa-badge" style="background:' + (w[2] === 'Critical' ? 'rgba(220,38,38,.15)' : 'rgba(249,115,22,.15)') + ';color:' + riskColor + '">' + w[2] + '</span></td></tr>';
      });
      contentHtml += '</tbody></table></div>';

      contentHtml += '<div class="pa-panel">' +
        '<div class="pa-panel-title">L33t Speak Substitutions</div>' +
        '<p style="font-size:.78rem;color:var(--mut);margin-bottom:12px;line-height:1.5">L33t speak replaces letters with numbers or symbols. Attackers apply these substitutions automatically, providing minimal security benefit.</p>' +
        '<div class="pa-leet-grid">';
      var leetKeys = Object.keys(LEET_MAP);
      leetKeys.forEach(function(k) {
        contentHtml += '<div class="pa-leet-item">' +
          '<div class="pa-leet-char">' + k.toUpperCase() + '</div>' +
          '<div class="pa-leet-sub">→ ' + LEET_MAP[k].join(' , ') + '</div>' +
        '</div>';
      });
      contentHtml += '</div></div>';

      contentHtml += '<div class="pa-panel">' +
        '<div class="pa-panel-title">Common Password Structures</div>' +
        '<table class="pa-table"><thead><tr><th>Pattern</th><th>Example</th><th>Risk</th></tr></thead><tbody>';
      var structures = [
        ['Word + numbers', 'monkey123', 'Critical'],
        ['Capitalized word + symbol + numbers', 'Summer2024!', 'High'],
        ['Season + year', 'Winter2025', 'Critical'],
        ['Name + birth year', 'Jessica1990', 'Critical'],
        ['Dictionary word (l33t)', 'p@$$w0rd', 'High'],
        ['Date formats', '01152024 / 20240115', 'High'],
        ['Phone number', '5551234567', 'High'],
        ['Repeated characters', 'aaaaaa / 111111', 'Critical'],
        ['Sequential characters', 'abcdef / 123456', 'Critical'],
        ['Company + year + symbol', 'Acme2024!', 'High']
      ];
      structures.forEach(function(s) {
        var riskColor = s[2] === 'Critical' ? '#dc2626' : '#f97316';
        contentHtml += '<tr><td>' + esc(s[0]) + '</td><td style="font-family:ui-monospace,monospace;font-size:.75rem">' + esc(s[1]) + '</td><td><span class="pa-badge" style="background:' + (s[2] === 'Critical' ? 'rgba(220,38,38,.15)' : 'rgba(249,115,22,.15)') + ';color:' + riskColor + '">' + s[2] + '</span></td></tr>';
      });
      contentHtml += '</tbody></table></div>';

      contentHtml += '<div class="pa-panel">' +
        '<div class="pa-panel-title">Tips for Strong Passwords</div>';
      var tips = [
        ['Use passphrases', 'Combine 4-6 random words: "correct horse battery staple" has more entropy than "P@ssw0rd!"'],
        ['Avoid personal info', 'Never use names, birthdays, pet names, or addresses. These are easily found via OSINT.'],
        ['Unique per service', 'Never reuse passwords. A breach on one site compromises all accounts with the same password.'],
        ['Use a password manager', 'Generate and store unique 20+ character passwords for every account.'],
        ['Enable MFA', 'Multi-factor authentication adds a second layer even if the password is compromised.'],
        ['Length over complexity', 'A 20-character lowercase passphrase is stronger than an 8-character complex password.'],
        ['Avoid dictionary words', 'Single words, even with substitutions, are quickly cracked by modern tools.'],
        ['Check breach databases', 'Use services like HaveIBeenPwned to verify passwords have not been exposed.']
      ];
      tips.forEach(function(t) {
        contentHtml += '<div style="padding:10px 0;border-bottom:1px solid var(--line)">' +
          '<div style="font-weight:600;font-size:.82rem;color:var(--txt);margin-bottom:3px">' + esc(t[0]) + '</div>' +
          '<div style="font-size:.75rem;color:var(--mut);line-height:1.5">' + esc(t[1]) + '</div>' +
        '</div>';
      });
      contentHtml += '</div>';
    }

    container.innerHTML = PA_CSS +
      '<div class="pa-wrap">' +
        '<h1 class="pa-title">Password Analyzer</h1>' +
        '<p class="pa-sub">Analyze password strength, estimate crack times, check policy compliance, and generate secure passwords.</p>' +
        '<div class="pa-tabs">' + tabsHtml + '</div>' +
        contentHtml +
      '</div>';

    container.querySelectorAll('.pa-tab').forEach(function(btn) {
      btn.onclick = function() { activeTab = btn.dataset.tab; render(); };
    });

    var pwInput = container.querySelector('#pa-pw');
    if (pwInput) {
      pwInput.oninput = function() { password = pwInput.value; render(); };
      pwInput.focus();
      if (password) pwInput.setSelectionRange(password.length, password.length);
    }

    var toggleBtn = container.querySelector('#pa-toggle-show');
    if (toggleBtn) toggleBtn.onclick = function() { showPw = !showPw; render(); };

    var clearBtn = container.querySelector('#pa-clear');
    if (clearBtn) clearBtn.onclick = function() { password = ''; render(); };

    var lenSlider = container.querySelector('#pa-gen-len');
    if (lenSlider) {
      lenSlider.oninput = function() {
        genLength = parseInt(lenSlider.value, 10);
        var valEl = container.querySelector('#pa-gen-len-val');
        if (valEl) valEl.textContent = genLength;
      };
    }

    container.querySelectorAll('.pa-toggle').forEach(function(tog) {
      tog.onclick = function() {
        var opt = tog.dataset.opt;
        if (opt === 'upper') genUpper = !genUpper;
        else if (opt === 'lower') genLower = !genLower;
        else if (opt === 'digits') genDigits = !genDigits;
        else if (opt === 'symbols') genSymbols = !genSymbols;
        render();
      };
    });

    var customInput = container.querySelector('#pa-gen-custom');
    if (customInput) customInput.onchange = function() { genCustom = customInput.value; };

    var genOneBtn = container.querySelector('#pa-gen-one');
    if (genOneBtn) genOneBtn.onclick = function() {
      genCustom = (container.querySelector('#pa-gen-custom') || {}).value || '';
      generatedPws = [generatePassword(genLength, genUpper, genLower, genDigits, genSymbols, genCustom)];
      render();
    };

    var genBatchBtn = container.querySelector('#pa-gen-batch');
    if (genBatchBtn) genBatchBtn.onclick = function() {
      genCustom = (container.querySelector('#pa-gen-custom') || {}).value || '';
      generatedPws = [];
      for (var i = 0; i < 10; i++) {
        generatedPws.push(generatePassword(genLength, genUpper, genLower, genDigits, genSymbols, genCustom));
      }
      render();
    };

    var copyBtn = container.querySelector('#pa-gen-copy');
    if (copyBtn) copyBtn.onclick = function() {
      if (generatedPws.length > 0) {
        navigator.clipboard.writeText(generatedPws[0]).then(function() {
          copyBtn.textContent = 'Copied!';
          setTimeout(function() { copyBtn.textContent = 'Copy'; }, 1500);
        });
      }
    };

    container.querySelectorAll('.pa-copy-single').forEach(function(btn) {
      btn.onclick = function() {
        var idx = parseInt(btn.dataset.idx, 10);
        if (generatedPws[idx]) {
          navigator.clipboard.writeText(generatedPws[idx]).then(function() {
            btn.textContent = 'Copied!';
            setTimeout(function() { btn.textContent = 'Copy'; }, 1500);
          });
        }
      };
    });

    var policyPwInput = container.querySelector('#pa-policy-pw');
    if (policyPwInput) {
      policyPwInput.onkeydown = function(e) {
        if (e.key === 'Enter') { policyPassword = policyPwInput.value; render(); }
      };
    }
    var policyCheckBtn = container.querySelector('#pa-policy-check');
    if (policyCheckBtn) policyCheckBtn.onclick = function() {
      var inp = container.querySelector('#pa-policy-pw');
      if (inp) { policyPassword = inp.value; render(); }
    };
  }

  render();
}
