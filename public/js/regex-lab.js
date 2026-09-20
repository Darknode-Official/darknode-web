// Regex Lab — Interactive regex builder and tester for security.
// Copyright (c) 2026 Darknode-Official. All rights reserved.

const esc = (s) => String(s != null ? s : "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// ── Security regex library ──
var REGEX_LIBRARY = [
  { cat: "Network", name: "IPv4 Address", pattern: "\\b(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\b", desc: "Matches valid IPv4 addresses (0.0.0.0 – 255.255.255.255)" },
  { cat: "Network", name: "IPv4 with CIDR", pattern: "\\b(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\/(?:3[0-2]|[12]?\\d)\\b", desc: "IPv4 with subnet mask in CIDR notation" },
  { cat: "Network", name: "IPv6 Address", pattern: "(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}", desc: "Matches common IPv6 address formats" },
  { cat: "Network", name: "MAC Address", pattern: "(?:[0-9a-fA-F]{2}[:\\-]){5}[0-9a-fA-F]{2}", desc: "MAC address in colon or hyphen separated format" },
  { cat: "Network", name: "Port Number", pattern: "\\b(?:[1-9]\\d{0,3}|[1-5]\\d{4}|6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])\\b", desc: "Valid port numbers 1-65535" },
  { cat: "Network", name: "URL", pattern: "https?:\\/\\/[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=%]+", desc: "HTTP/HTTPS URLs" },
  { cat: "Network", name: "Domain Name", pattern: "\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}\\b", desc: "Valid domain names" },

  { cat: "Identity", name: "Email Address", pattern: "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}", desc: "Standard email address format" },
  { cat: "Identity", name: "SSN (US)", pattern: "\\b\\d{3}[\\-\\s]?\\d{2}[\\-\\s]?\\d{4}\\b", desc: "US Social Security Number" },
  { cat: "Identity", name: "Phone (US)", pattern: "\\b(?:\\+?1[\\-\\s]?)?\\(?\\d{3}\\)?[\\-\\s]?\\d{3}[\\-\\s]?\\d{4}\\b", desc: "US phone number in various formats" },
  { cat: "Identity", name: "Phone (International)", pattern: "\\+?\\d{1,4}[\\-\\s]?\\(?\\d{1,4}\\)?[\\-\\s]?\\d{2,4}[\\-\\s]?\\d{2,4}(?:[\\-\\s]?\\d{2,4})?", desc: "International phone numbers" },
  { cat: "Identity", name: "Date (ISO 8601)", pattern: "\\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\\d|3[01])", desc: "Date in YYYY-MM-DD format" },

  { cat: "Financial", name: "Credit Card (Visa)", pattern: "\\b4\\d{3}[\\-\\s]?\\d{4}[\\-\\s]?\\d{4}[\\-\\s]?\\d{4}\\b", desc: "Visa card numbers (starts with 4)" },
  { cat: "Financial", name: "Credit Card (Mastercard)", pattern: "\\b5[1-5]\\d{2}[\\-\\s]?\\d{4}[\\-\\s]?\\d{4}[\\-\\s]?\\d{4}\\b", desc: "Mastercard (starts with 51-55)" },
  { cat: "Financial", name: "Credit Card (Amex)", pattern: "\\b3[47]\\d{2}[\\-\\s]?\\d{6}[\\-\\s]?\\d{5}\\b", desc: "American Express (starts with 34/37)" },
  { cat: "Financial", name: "Bitcoin Address", pattern: "\\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\\b", desc: "Bitcoin P2PKH or P2SH address" },

  { cat: "Credentials", name: "AWS Access Key", pattern: "(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}", desc: "AWS access key ID" },
  { cat: "Credentials", name: "GitHub Token (classic)", pattern: "ghp_[0-9a-zA-Z]{36}", desc: "GitHub personal access token" },
  { cat: "Credentials", name: "GitHub Token (fine-grained)", pattern: "github_pat_[0-9a-zA-Z_]{82}", desc: "GitHub fine-grained PAT" },
  { cat: "Credentials", name: "Slack Token", pattern: "xox[bpsorta]-[0-9a-zA-Z\\-]{10,250}", desc: "Slack bot/user/app token" },
  { cat: "Credentials", name: "Stripe Secret Key", pattern: "<STRIPE_SECRET_KEY>", desc: "Stripe live secret key" },
  { cat: "Credentials", name: "Google API Key", pattern: "AIza[0-9A-Za-z\\-_]{35}", desc: "Google API key" },
  { cat: "Credentials", name: "Generic API Key", pattern: "(?:api[_\\-]?key|apikey|api_secret)\\s*[:=]\\s*['\"]?([0-9a-zA-Z\\-_]{16,64})['\"]?", desc: "Generic API key in config files" },
  { cat: "Credentials", name: "Generic Password", pattern: "(?:password|passwd|pwd|secret)\\s*[:=]\\s*['\"]?([^\\s'\"]{4,64})['\"]?", desc: "Password assignments in config" },
  { cat: "Credentials", name: "Private Key Header", pattern: "-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", desc: "PEM private key header" },
  { cat: "Credentials", name: "JWT Token", pattern: "eyJ[A-Za-z0-9\\-_]+\\.eyJ[A-Za-z0-9\\-_]+\\.[A-Za-z0-9\\-_.+/=]*", desc: "JSON Web Token" },
  { cat: "Credentials", name: "Bearer Token", pattern: "Bearer\\s+[A-Za-z0-9\\-._~+/]+=*", desc: "Bearer authentication token" },

  { cat: "Hashes", name: "MD5 Hash", pattern: "\\b[a-fA-F0-9]{32}\\b", desc: "32-char hex (MD5)" },
  { cat: "Hashes", name: "SHA-1 Hash", pattern: "\\b[a-fA-F0-9]{40}\\b", desc: "40-char hex (SHA-1)" },
  { cat: "Hashes", name: "SHA-256 Hash", pattern: "\\b[a-fA-F0-9]{64}\\b", desc: "64-char hex (SHA-256)" },
  { cat: "Hashes", name: "bcrypt Hash", pattern: "\\$2[aby]?\\$\\d{2}\\$[./A-Za-z0-9]{53}", desc: "bcrypt password hash" },
  { cat: "Hashes", name: "Base64 String", pattern: "(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", desc: "Base64 encoded string" },

  { cat: "Attacks", name: "SQL Injection (UNION)", pattern: "(?:UNION\\s+(?:ALL\\s+)?SELECT|SELECT\\s+.*\\s+FROM|OR\\s+1\\s*=\\s*1|'\\s*OR\\s*'|--\\s*$)", desc: "SQL injection patterns" },
  { cat: "Attacks", name: "XSS Payload", pattern: "<script[^>]*>|javascript\\s*:|on(?:load|error|click|mouseover|focus|blur)\\s*=", desc: "Common XSS vectors" },
  { cat: "Attacks", name: "Command Injection", pattern: "[;&|`$]\\s*(?:cat|ls|id|whoami|wget|curl|nc|bash|sh|python|perl)\\b", desc: "OS command injection" },
  { cat: "Attacks", name: "Path Traversal", pattern: "(?:\\.\\.[\\/\\\\]){2,}|%2e%2e[%2f%5c]", desc: "Directory traversal" },
  { cat: "Attacks", name: "SSRF (metadata)", pattern: "169\\.254\\.169\\.254|metadata\\.google|100\\.100\\.100\\.200", desc: "Cloud metadata endpoints" },
  { cat: "Attacks", name: "Log4Shell", pattern: "\\$\\{jndi:(?:ldap|rmi|dns|iiop)://", desc: "Log4j JNDI injection (CVE-2021-44228)" },

  { cat: "Logs", name: "Apache Access Log", pattern: "^(\\S+) \\S+ \\S+ \\[([^\\]]+)\\] \"(\\S+) (\\S+) \\S+\" (\\d{3}) (\\d+|-)", desc: "Apache combined log format" },
  { cat: "Logs", name: "Syslog", pattern: "^<(\\d+)>\\s*(\\w{3}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2})\\s+(\\S+)\\s+(\\S+?)(?:\\[(\\d+)\\])?:", desc: "BSD syslog format" },
  { cat: "Logs", name: "Timestamp (ISO)", pattern: "\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:Z|[+-]\\d{2}:?\\d{2})?", desc: "ISO 8601 timestamp" },
  { cat: "Logs", name: "Timestamp (Unix)", pattern: "\\b1[0-9]{9}\\b", desc: "Unix epoch timestamp (10 digits)" },

  { cat: "Files", name: "Windows File Path", pattern: "[A-Za-z]:\\\\(?:[^\\\\/:*?\"<>|\\r\\n]+\\\\)*[^\\\\/:*?\"<>|\\r\\n]*", desc: "Windows file path" },
  { cat: "Files", name: "Linux File Path", pattern: "(?:/[\\w.\\-]+)+/?", desc: "Unix/Linux absolute file path" },
  { cat: "Files", name: "Registry Key", pattern: "HK(?:LM|CU|CR|U|CC)\\\\(?:[^\\\\]+\\\\)*[^\\\\]*", desc: "Windows registry key path" },
  { cat: "Files", name: "UUID", pattern: "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", desc: "UUID / GUID" },

  { cat: "Security IDs", name: "CVE ID", pattern: "CVE-\\d{4}-\\d{4,}", desc: "CVE identifier" },
  { cat: "Security IDs", name: "MITRE ATT&CK ID", pattern: "T\\d{4}(?:\\.\\d{3})?", desc: "MITRE ATT&CK technique ID" },
  { cat: "Security IDs", name: "CWE ID", pattern: "CWE-\\d{1,4}", desc: "Common Weakness Enumeration" },
];

// ── Regex explainer ──
function explainRegex(pattern) {
  var tokens = [];
  var pos = 0;
  var TOKENS = [
    [/^\^/, "Start of string"],
    [/^\$/, "End of string"],
    [/^\\b/, "Word boundary"],
    [/^\\d/, "Digit [0-9]"],
    [/^\\D/, "Non-digit"],
    [/^\\w/, "Word char [a-zA-Z0-9_]"],
    [/^\\W/, "Non-word char"],
    [/^\\s/, "Whitespace"],
    [/^\\S/, "Non-whitespace"],
    [/^\./, "Any character"],
    [/^\*\?/, "Zero or more (lazy)"],
    [/^\+\?/, "One or more (lazy)"],
    [/^\*/, "Zero or more (greedy)"],
    [/^\+/, "One or more (greedy)"],
    [/^\?/, "Optional"],
    [/^\{(\d+),(\d+)\}/, "Between $1 and $2 times"],
    [/^\{(\d+),\}/, "$1 or more times"],
    [/^\{(\d+)\}/, "Exactly $1 times"],
    [/^\(\?:/, "Non-capturing group"],
    [/^\(\?=/, "Positive lookahead"],
    [/^\(\?!/, "Negative lookahead"],
    [/^\(\?<=/, "Positive lookbehind"],
    [/^\(\?<!/, "Negative lookbehind"],
    [/^\(/, "Capturing group"],
    [/^\)/, "Group end"],
    [/^\|/, "OR (alternation)"],
    [/^\[\^/, "Negated char class"],
    [/^\[/, "Character class"],
    [/^\]/, "End char class"],
  ];

  while (pos < pattern.length) {
    var remaining = pattern.substring(pos);
    var matched = false;
    for (var i = 0; i < TOKENS.length; i++) {
      var m = remaining.match(TOKENS[i][0]);
      if (m) {
        var label = TOKENS[i][1];
        if (m[1]) label = label.replace("$1", m[1]);
        if (m[2]) label = label.replace("$2", m[2]);
        tokens.push({ text: m[0], label: label });
        pos += m[0].length;
        matched = true;
        break;
      }
    }
    if (!matched) {
      if (remaining[0] === "\\") {
        tokens.push({ text: remaining.substring(0, 2), label: "Literal '" + remaining[1] + "'" });
        pos += 2;
      } else {
        tokens.push({ text: remaining[0], label: "Literal '" + remaining[0] + "'" });
        pos += 1;
      }
    }
  }
  return tokens;
}

// ── Backtracking detector ──
function detectBacktracking(pattern) {
  var warnings = [];
  if (/\([^)]*[+*]\)[+*]/.test(pattern))
    warnings.push("Nested quantifiers detected — can cause catastrophic backtracking with O(2^n) time.");
  if (/\.\*.*\.\*/.test(pattern))
    warnings.push("Multiple .* patterns — may cause excessive backtracking.");
  return warnings;
}

// ── Quick reference ──
var QUICK_REF = {
  "Character Classes": [
    [".","Any character except newline"],
    ["\\d","Digit [0-9]"], ["\\D","Non-digit"],
    ["\\w","Word character [a-zA-Z0-9_]"], ["\\W","Non-word"],
    ["\\s","Whitespace"], ["\\S","Non-whitespace"],
    ["[abc]","Any of a, b, or c"], ["[^abc]","Not a, b, or c"],
    ["[a-z]","Range a-z"],
  ],
  "Quantifiers": [
    ["*","0 or more"], ["+","1 or more"], ["?","0 or 1"],
    ["{n}","Exactly n"], ["{n,}","n or more"], ["{n,m}","Between n and m"],
    ["*?","0+ (lazy)"], ["+?","1+ (lazy)"],
  ],
  "Anchors": [
    ["^","Start of string/line"], ["$","End of string/line"],
    ["\\b","Word boundary"], ["\\B","Non-word boundary"],
  ],
  "Groups": [
    ["(...)","Capturing group"], ["(?:...)","Non-capturing"],
    ["(?=...)","Positive lookahead"], ["(?!...)","Negative lookahead"],
    ["(?<=...)","Positive lookbehind"], ["(?<!...)","Negative lookbehind"],
    ["|","Alternation (OR)"], ["\\1","Back-reference"],
  ],
  "Flags": [
    ["g","Global (all matches)"], ["i","Case-insensitive"],
    ["m","Multiline"], ["s","Dotall (. matches \\n)"],
    ["u","Unicode"], ["y","Sticky"],
  ],
};

// ── CSS ──
var RX_CSS =
  '<style>' +
  '.rx-wrap{font-family:var(--font-body,system-ui);color:var(--txt,#ccc)}' +
  '.rx-input{width:100%;padding:10px 12px;background:var(--card,#161b22);border:1px solid var(--line,#333);color:var(--txt,#ccc);border-radius:4px;font-family:monospace;font-size:.9rem;box-sizing:border-box}' +
  '.rx-input:focus{outline:none;border-color:var(--acc,#00d4ff)}' +
  'textarea.rx-input{min-height:120px;resize:vertical;line-height:1.6}' +
  '.rx-flags{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0}' +
  '.rx-flag{padding:4px 10px;border:1px solid var(--line,#333);background:var(--card,#161b22);color:var(--mut,#888);border-radius:4px;cursor:pointer;font-family:monospace;font-size:.85rem}' +
  '.rx-flag.on{border-color:var(--acc,#00d4ff);color:var(--acc,#00d4ff);background:rgba(0,212,255,.08)}' +
  '.rx-match{background:rgba(0,212,255,.2);border-radius:2px;padding:0 1px}' +
  '.rx-table{width:100%;border-collapse:collapse;font-size:.82rem}' +
  '.rx-table th{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line,#333);color:var(--mut,#888);font-weight:500}' +
  '.rx-table td{padding:5px 10px;border-bottom:1px solid var(--line,#222);font-family:monospace}' +
  '.rx-lib-cats{display:flex;gap:0;border-bottom:1px solid var(--line,#333);margin-bottom:10px;flex-wrap:wrap}' +
  '.rx-lib-cat{padding:6px 12px;cursor:pointer;border:none;background:none;color:var(--mut,#888);font-size:.8rem;border-bottom:2px solid transparent}' +
  '.rx-lib-cat.on{color:var(--acc,#00d4ff);border-bottom-color:var(--acc,#00d4ff)}' +
  '.rx-lib-item{padding:8px 10px;border:1px solid var(--line,#333);border-radius:4px;margin:4px 0;cursor:pointer;transition:border-color .15s}' +
  '.rx-lib-item:hover{border-color:var(--acc,#00d4ff)}' +
  '.rx-lib-name{font-weight:500;font-size:.85rem}' +
  '.rx-lib-pat{font-family:monospace;font-size:.75rem;color:var(--acc,#00d4ff);margin-top:2px;word-break:break-all}' +
  '.rx-lib-desc{font-size:.75rem;color:var(--mut,#888);margin-top:2px}' +
  '.rx-explain{margin:10px 0;padding:10px;background:var(--card,#161b22);border:1px solid var(--line,#333);border-radius:4px}' +
  '.rx-explain-token{display:inline-block;margin:2px 4px 2px 0;padding:2px 6px;background:rgba(0,212,255,.1);border-radius:3px;font-family:monospace;font-size:.82rem;cursor:help}' +
  '.rx-warn{padding:8px 12px;background:rgba(255,180,0,.1);border:1px solid rgba(255,180,0,.3);border-radius:4px;font-size:.82rem;margin:8px 0}' +
  '.rx-ops{display:flex;gap:8px;margin:10px 0;flex-wrap:wrap}' +
  '.rx-op-btn{padding:5px 12px;background:var(--card,#161b22);border:1px solid var(--line,#333);color:var(--txt,#ccc);border-radius:4px;cursor:pointer;font-size:.8rem}' +
  '.rx-op-btn:hover{border-color:var(--acc,#00d4ff)}' +
  '.rx-ref-title{font-size:.85rem;font-weight:600;margin:10px 0 4px}' +
  '.rx-ref-row{display:flex;gap:8px;font-size:.78rem;padding:2px 0}' +
  '.rx-ref-pat{font-family:monospace;color:var(--acc,#00d4ff);min-width:80px}' +
  '.rx-ref-desc{color:var(--mut,#888)}' +
  '.rx-tabs{display:flex;gap:0;border-bottom:1px solid var(--line,#333);margin-bottom:12px;flex-wrap:wrap}' +
  '.rx-tab{padding:7px 14px;cursor:pointer;border:none;background:none;color:var(--mut,#888);font-size:.83rem;border-bottom:2px solid transparent}' +
  '.rx-tab.on{color:var(--acc,#00d4ff);border-bottom-color:var(--acc,#00d4ff)}' +
  '.rx-panel{display:none}.rx-panel.on{display:block}' +
  '.rx-result-box{padding:10px;background:var(--card,#161b22);border:1px solid var(--line,#333);border-radius:4px;font-family:monospace;font-size:.82rem;max-height:200px;overflow-y:auto;white-space:pre-wrap;word-break:break-all}' +
  '</style>';

// ── Main render ──
export function renderRegexLab(main) {
  var TABS = [
    { id: "tester", label: "Tester" },
    { id: "library", label: "Pattern Library" },
    { id: "explain", label: "Explainer" },
    { id: "operations", label: "Operations" },
    { id: "reference", label: "Quick Reference" }
  ];

  var tabsHtml = TABS.map(function(t) {
    return '<button class="rx-tab' + (t.id === "tester" ? " on" : "") + '" data-tab="' + t.id + '">' + esc(t.label) + '</button>';
  }).join("");

  var panelsHtml = TABS.map(function(t) {
    return '<div class="rx-panel' + (t.id === "tester" ? " on" : "") + '" data-panel="' + t.id + '" id="rx-' + t.id + '"></div>';
  }).join("");

  main.innerHTML = RX_CSS +
    '<div class="rx-wrap">' +
    '<h1 class="pg-h1">Regex Lab</h1>' +
    '<p class="muted pg-sub">' + REGEX_LIBRARY.length + ' security patterns. Interactive builder, explainer, and tester — everything in your browser.</p>' +
    '<div class="rx-tabs">' + tabsHtml + '</div>' +
    panelsHtml +
    '</div>';

  main.querySelector(".rx-tabs").onclick = function(e) {
    var btn = e.target.closest(".rx-tab");
    if (!btn) return;
    main.querySelectorAll(".rx-tab").forEach(function(t) { t.classList.toggle("on", t === btn); });
    main.querySelectorAll(".rx-panel").forEach(function(p) { p.classList.toggle("on", p.dataset.panel === btn.dataset.tab); });
  };

  var curPattern = "";
  var curFlags = "gi";

  function setPattern(pat) {
    curPattern = pat;
    var inp = main.querySelector("#rx-pattern");
    if (inp) inp.value = pat;
    updateMatches();
  }

  // ── Tester ──
  var testerPanel = main.querySelector("#rx-tester");
  testerPanel.innerHTML =
    '<label style="font-size:.82rem;color:var(--mut)">Regular Expression</label>' +
    '<input class="rx-input" id="rx-pattern" placeholder="Enter regex pattern...">' +
    '<div class="rx-flags" id="rx-flags">' +
      '<button class="rx-flag on" data-flag="g">g</button>' +
      '<button class="rx-flag on" data-flag="i">i</button>' +
      '<button class="rx-flag" data-flag="m">m</button>' +
      '<button class="rx-flag" data-flag="s">s</button>' +
      '<button class="rx-flag" data-flag="u">u</button>' +
    '</div>' +
    '<div id="rx-warn-area"></div>' +
    '<label style="font-size:.82rem;color:var(--mut)">Test String</label>' +
    '<textarea class="rx-input" id="rx-test" placeholder="Enter test string..."></textarea>' +
    '<div style="font-size:.82rem;color:var(--mut);margin:6px 0" id="rx-match-info"></div>' +
    '<div id="rx-highlighted" style="margin:8px 0;padding:10px;background:var(--card);border:1px solid var(--line);border-radius:4px;font-family:monospace;font-size:.85rem;white-space:pre-wrap;word-break:break-all;min-height:40px"></div>' +
    '<h4 style="margin:12px 0 6px;font-size:.85rem">Match Table</h4>' +
    '<div style="overflow-x:auto"><table class="rx-table" id="rx-match-table"><tr><td class="muted">No matches yet</td></tr></table></div>';

  var patInput = testerPanel.querySelector("#rx-pattern");
  var testArea = testerPanel.querySelector("#rx-test");

  patInput.oninput = function() { curPattern = patInput.value; updateMatches(); };
  testArea.oninput = updateMatches;

  testerPanel.querySelector("#rx-flags").onclick = function(e) {
    var btn = e.target.closest(".rx-flag");
    if (!btn) return;
    btn.classList.toggle("on");
    curFlags = "";
    testerPanel.querySelectorAll(".rx-flag.on").forEach(function(f) { curFlags += f.dataset.flag; });
    updateMatches();
  };

  function updateMatches() {
    var pattern = curPattern;
    var testStr = testArea ? testArea.value : "";
    var info = testerPanel.querySelector("#rx-match-info");
    var highlighted = testerPanel.querySelector("#rx-highlighted");
    var table = testerPanel.querySelector("#rx-match-table");
    var warnArea = testerPanel.querySelector("#rx-warn-area");

    if (!pattern) {
      info.textContent = "";
      highlighted.innerHTML = esc(testStr);
      table.innerHTML = '<tr><td class="muted">Enter a pattern</td></tr>';
      warnArea.innerHTML = "";
      return;
    }

    var warns = detectBacktracking(pattern);
    warnArea.innerHTML = warns.map(function(w) { return '<div class="rx-warn">' + esc(w) + '</div>'; }).join("");

    var re;
    try { re = new RegExp(pattern, curFlags); }
    catch (err) {
      info.innerHTML = '<span style="color:#f44">Invalid: ' + esc(err.message) + '</span>';
      highlighted.innerHTML = esc(testStr);
      table.innerHTML = '<tr><td style="color:#f44">' + esc(err.message) + '</td></tr>';
      return;
    }

    if (!testStr) {
      info.textContent = "Enter test string.";
      highlighted.innerHTML = "";
      table.innerHTML = '<tr><td class="muted">No test string</td></tr>';
      return;
    }

    var matches = [];
    if (curFlags.indexOf("g") >= 0) {
      re.lastIndex = 0;
      var m;
      while ((m = re.exec(testStr)) !== null && matches.length < 500) {
        matches.push({ index: m.index, text: m[0], groups: Array.from(m).slice(1) });
        if (m[0].length === 0) re.lastIndex++;
      }
    } else {
      var m2 = re.exec(testStr);
      if (m2) matches.push({ index: m2.index, text: m2[0], groups: Array.from(m2).slice(1) });
    }

    info.textContent = matches.length + " match" + (matches.length !== 1 ? "es" : "");

    var html = "";
    var lastIdx = 0;
    for (var i = 0; i < matches.length; i++) {
      if (matches[i].index > lastIdx) html += esc(testStr.substring(lastIdx, matches[i].index));
      html += '<span class="rx-match">' + esc(matches[i].text) + '</span>';
      lastIdx = matches[i].index + matches[i].text.length;
    }
    if (lastIdx < testStr.length) html += esc(testStr.substring(lastIdx));
    highlighted.innerHTML = html;

    if (matches.length === 0) {
      table.innerHTML = '<tr><td class="muted">No matches</td></tr>';
    } else {
      var hasGroups = matches.some(function(m3) { return m3.groups.length > 0; });
      var maxG = hasGroups ? Math.max.apply(null, matches.map(function(m4) { return m4.groups.length; })) : 0;
      var hdr = '<tr><th>#</th><th>Match</th><th>Index</th><th>Len</th>';
      for (var g = 0; g < maxG; g++) hdr += '<th>G' + (g + 1) + '</th>';
      hdr += '</tr>';

      var rows = matches.slice(0, 100).map(function(m5, idx) {
        var r = '<tr><td>' + (idx + 1) + '</td><td>' + esc(m5.text) + '</td><td>' + m5.index + '</td><td>' + m5.text.length + '</td>';
        for (var g2 = 0; g2 < maxG; g2++) r += '<td>' + (m5.groups[g2] !== undefined ? esc(m5.groups[g2]) : '-') + '</td>';
        return r + '</tr>';
      }).join("");

      table.innerHTML = hdr + rows;
    }
  }

  // ── Library ──
  var libPanel = main.querySelector("#rx-library");
  var cats = [];
  REGEX_LIBRARY.forEach(function(r) { if (cats.indexOf(r.cat) < 0) cats.push(r.cat); });

  libPanel.innerHTML =
    '<h3 style="margin:0 0 10px">Security Regex Library</h3>' +
    '<p class="muted" style="font-size:.82rem;margin-bottom:10px">' + REGEX_LIBRARY.length + ' patterns — click to load into tester.</p>' +
    '<div class="rx-lib-cats"><button class="rx-lib-cat on" data-cat="all">All</button>' +
    cats.map(function(c) { return '<button class="rx-lib-cat" data-cat="' + esc(c) + '">' + esc(c) + '</button>'; }).join("") + '</div>' +
    '<div id="rx-lib-items">' + REGEX_LIBRARY.map(function(r) {
      return '<div class="rx-lib-item" data-cat="' + esc(r.cat) + '" data-pat="' + esc(r.pattern) + '">' +
        '<div class="rx-lib-name">' + esc(r.name) + ' <span style="font-size:.7rem;color:var(--mut)">' + esc(r.cat) + '</span></div>' +
        '<div class="rx-lib-pat">' + esc(r.pattern) + '</div>' +
        '<div class="rx-lib-desc">' + esc(r.desc) + '</div></div>';
    }).join("") + '</div>';

  libPanel.querySelector(".rx-lib-cats").onclick = function(e) {
    var btn = e.target.closest(".rx-lib-cat");
    if (!btn) return;
    libPanel.querySelectorAll(".rx-lib-cat").forEach(function(b) { b.classList.toggle("on", b === btn); });
    var cat = btn.dataset.cat;
    libPanel.querySelectorAll(".rx-lib-item").forEach(function(item) {
      item.style.display = (cat === "all" || item.dataset.cat === cat) ? "" : "none";
    });
  };

  libPanel.querySelector("#rx-lib-items").onclick = function(e) {
    var item = e.target.closest(".rx-lib-item");
    if (!item) return;
    setPattern(item.dataset.pat);
    main.querySelectorAll(".rx-tab").forEach(function(t) { t.classList.toggle("on", t.dataset.tab === "tester"); });
    main.querySelectorAll(".rx-panel").forEach(function(p) { p.classList.toggle("on", p.dataset.panel === "tester"); });
  };

  // ── Explainer ──
  var explPanel = main.querySelector("#rx-explain");
  explPanel.innerHTML =
    '<h3 style="margin:0 0 10px">Regex Explainer</h3>' +
    '<p class="muted" style="font-size:.82rem;margin-bottom:10px">Paste a regex to see it broken down token by token.</p>' +
    '<input class="rx-input" id="rx-explain-input" placeholder="Paste a regex pattern...">' +
    '<div class="rx-explain" id="rx-explain-out"><span class="muted">Enter a pattern above</span></div>';

  explPanel.querySelector("#rx-explain-input").oninput = function() {
    var pat = explPanel.querySelector("#rx-explain-input").value;
    var out = explPanel.querySelector("#rx-explain-out");
    if (!pat) { out.innerHTML = '<span class="muted">Enter a pattern above</span>'; return; }
    var tokens = explainRegex(pat);
    out.innerHTML = tokens.map(function(t) {
      return '<span class="rx-explain-token" title="' + esc(t.label) + '"><span style="color:var(--acc)">' + esc(t.text) + '</span> <span style="color:var(--mut);font-size:.75rem">' + esc(t.label) + '</span></span>';
    }).join("");
  };

  // ── Operations ──
  var opsPanel = main.querySelector("#rx-operations");
  opsPanel.innerHTML =
    '<h3 style="margin:0 0 10px">Regex Operations</h3>' +
    '<label style="font-size:.82rem;color:var(--mut)">Pattern</label>' +
    '<input class="rx-input" id="rx-ops-pat" placeholder="Regex pattern...">' +
    '<label style="font-size:.82rem;color:var(--mut);margin-top:8px">Input Text</label>' +
    '<textarea class="rx-input" id="rx-ops-text" placeholder="Input text..."></textarea>' +
    '<label style="font-size:.82rem;color:var(--mut);margin-top:8px">Replacement (for Replace)</label>' +
    '<input class="rx-input" id="rx-ops-repl" placeholder="Replacement ($1, $2 for groups)">' +
    '<div class="rx-ops">' +
      '<button class="rx-op-btn" data-op="extract">Extract All</button>' +
      '<button class="rx-op-btn" data-op="replace">Replace</button>' +
      '<button class="rx-op-btn" data-op="split">Split</button>' +
      '<button class="rx-op-btn" data-op="test">Test (bool)</button>' +
    '</div>' +
    '<label style="font-size:.82rem;color:var(--mut)">Result</label>' +
    '<div class="rx-result-box" id="rx-ops-result">Run an operation</div>';

  opsPanel.querySelector(".rx-ops").onclick = function(e) {
    var btn = e.target.closest(".rx-op-btn");
    if (!btn) return;
    var pat = opsPanel.querySelector("#rx-ops-pat").value;
    var text = opsPanel.querySelector("#rx-ops-text").value;
    var repl = opsPanel.querySelector("#rx-ops-repl").value;
    var result = opsPanel.querySelector("#rx-ops-result");
    if (!pat) { result.textContent = "Enter a pattern."; return; }
    var re2;
    try { re2 = new RegExp(pat, "g"); }
    catch (err) { result.textContent = "Invalid regex: " + err.message; return; }
    var op = btn.dataset.op;
    if (op === "extract") { var ms = text.match(re2); result.textContent = ms ? ms.join("\n") : "(no matches)"; }
    else if (op === "replace") { result.textContent = text.replace(re2, repl); }
    else if (op === "split") { result.textContent = text.split(re2).join("\n"); }
    else if (op === "test") { result.textContent = re2.test(text) ? "TRUE" : "FALSE"; }
  };

  // ── Reference ──
  var refPanel = main.querySelector("#rx-reference");
  var refHtml = '<h3 style="margin:0 0 10px">Quick Reference</h3>';
  Object.keys(QUICK_REF).forEach(function(section) {
    refHtml += '<div class="rx-ref-title">' + esc(section) + '</div>';
    QUICK_REF[section].forEach(function(entry) {
      refHtml += '<div class="rx-ref-row"><span class="rx-ref-pat">' + esc(entry[0]) + '</span><span class="rx-ref-desc">' + esc(entry[1]) + '</span></div>';
    });
  });
  refPanel.innerHTML = refHtml;
}
