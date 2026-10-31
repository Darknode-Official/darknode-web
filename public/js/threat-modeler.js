// Threat Modeler — interactive threat modeling, STRIDE/DREAD, PASTA, LINDDUN, CVSS calculators, attack trees, DFDs
import { THREAT_LIBRARY, STRIDE_KEY, PASTA_STAGES, LINDDUN_CATEGORIES, DFD_TRUST_BOUNDARY_PATTERNS, STRIDE_COMPLIANCE_MAP, SECURITY_REQUIREMENTS_TEMPLATES } from "/js/threat-library-data.js";
import { acctKey } from "/js/core/account.js"; // per-account storage key
const esc = (s) => String(s != null ? s : "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

// ── STRIDE Definitions ──
const STRIDE = [
  { id: "S", name: "Spoofing", desc: "Pretending to be something or someone other than yourself", examples: ["Forged authentication tokens", "IP spoofing", "ARP spoofing", "Email spoofing", "DNS spoofing", "Credential theft", "Session hijacking", "Certificate forgery"], mitigations: ["Strong authentication (MFA)", "Digital signatures", "Certificate pinning", "Mutual TLS", "Anti-spoofing filters", "DMARC/DKIM/SPF"] },
  { id: "T", name: "Tampering", desc: "Modifying data or code without authorization", examples: ["SQL injection", "Man-in-the-middle attacks", "Binary patching", "Configuration file modification", "Log tampering", "Memory corruption", "Parameter tampering", "Cookie manipulation"], mitigations: ["Input validation", "Integrity checks (HMAC)", "Code signing", "Tamper-evident logging", "Write-once storage", "File integrity monitoring"] },
  { id: "R", name: "Repudiation", desc: "Claiming to have not performed an action", examples: ["Deleting audit logs", "Using shared accounts", "Denying transactions", "Timestamp manipulation", "Log injection", "Unsigned transactions"], mitigations: ["Audit logging", "Digital signatures", "Timestamps from trusted source", "Non-repudiation tokens", "Immutable audit trails", "WORM storage"] },
  { id: "I", name: "Information Disclosure", desc: "Exposing information to unauthorized individuals", examples: ["Eavesdropping", "Directory traversal", "Error message leakage", "Metadata exposure", "Side-channel attacks", "Memory dumps", "Backup exposure", "API over-exposure"], mitigations: ["Encryption at rest and in transit", "Access control lists", "Data classification", "Minimal error messages", "Data masking", "DLP tools"] },
  { id: "D", name: "Denial of Service", desc: "Denying or degrading service to users", examples: ["SYN flood", "Application-layer DoS", "Resource exhaustion", "Algorithmic complexity attacks", "Zip bombs", "XML bombs", "ReDoS", "Account lockout abuse"], mitigations: ["Rate limiting", "Load balancing", "CDN/WAF", "Input size limits", "Graceful degradation", "Auto-scaling", "Circuit breakers"] },
  { id: "E", name: "Elevation of Privilege", desc: "Gaining capabilities without proper authorization", examples: ["Buffer overflow exploitation", "SQL injection to admin", "Privilege escalation exploits", "Insecure deserialization", "IDOR", "JWT algorithm confusion", "Kernel exploits", "Container escape"], mitigations: ["Least privilege principle", "Input validation", "Sandboxing", "RBAC/ABAC", "Mandatory access controls", "Regular patching", "Security boundaries"] }
];

// ── CVSS v3.1 calculator Data ──
const CVSS31_METRICS = {
  AV: { name: "Attack Vector", options: [{ val: "N", label: "Network", score: 0.85 }, { val: "A", label: "Adjacent", score: 0.62 }, { val: "L", label: "Local", score: 0.55 }, { val: "P", label: "Physical", score: 0.20 }] },
  AC: { name: "Attack Complexity", options: [{ val: "L", label: "Low", score: 0.77 }, { val: "H", label: "High", score: 0.44 }] },
  PR: { name: "Privileges Required", options: [{ val: "N", label: "None", score: [0.85, 0.85] }, { val: "L", label: "Low", score: [0.62, 0.68] }, { val: "H", label: "High", score: [0.27, 0.50] }] },
  UI: { name: "User Interaction", options: [{ val: "N", label: "None", score: 0.85 }, { val: "R", label: "Required", score: 0.62 }] },
  S: { name: "Scope", options: [{ val: "U", label: "Unchanged", score: 0 }, { val: "C", label: "Changed", score: 1 }] },
  C: { name: "Confidentiality", options: [{ val: "N", label: "None", score: 0 }, { val: "L", label: "Low", score: 0.22 }, { val: "H", label: "High", score: 0.56 }] },
  I: { name: "Integrity", options: [{ val: "N", label: "None", score: 0 }, { val: "L", label: "Low", score: 0.22 }, { val: "H", label: "High", score: 0.56 }] },
  A: { name: "Availability", options: [{ val: "N", label: "None", score: 0 }, { val: "L", label: "Low", score: 0.22 }, { val: "H", label: "High", score: 0.56 }] }
};

function calcCVSS31(vals) {
  var av = CVSS31_METRICS.AV.options.find(function(o) { return o.val === vals.AV; });
  var ac = CVSS31_METRICS.AC.options.find(function(o) { return o.val === vals.AC; });
  var pr = CVSS31_METRICS.PR.options.find(function(o) { return o.val === vals.PR; });
  var ui = CVSS31_METRICS.UI.options.find(function(o) { return o.val === vals.UI; });
  var s = vals.S;
  var cVal = CVSS31_METRICS.C.options.find(function(o) { return o.val === vals.C; });
  var iVal = CVSS31_METRICS.I.options.find(function(o) { return o.val === vals.I; });
  var aVal = CVSS31_METRICS.A.options.find(function(o) { return o.val === vals.A; });
  if (!av || !ac || !pr || !ui || !cVal || !iVal || !aVal) return { score: 0, severity: "None", vector: "" };
  var scopeChanged = s === "C";
  var prScore = Array.isArray(pr.score) ? pr.score[scopeChanged ? 1 : 0] : pr.score;
  var iss = 1 - ((1 - cVal.score) * (1 - iVal.score) * (1 - aVal.score));
  var impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss; // base (3.1 spec 7.1); 0.9731/^13 is the environmental form
  if (impact <= 0) return { score: 0, severity: "None", vector: "CVSS:3.1/AV:" + vals.AV + "/AC:" + vals.AC + "/PR:" + vals.PR + "/UI:" + vals.UI + "/S:" + vals.S + "/C:" + vals.C + "/I:" + vals.I + "/A:" + vals.A };
  var exploitability = 8.22 * av.score * ac.score * prScore * ui.score;
  var score;
  if (scopeChanged) {
    score = Math.min(1.08 * (impact + exploitability), 10);
  } else {
    score = Math.min(impact + exploitability, 10);
  }
  score = Math.ceil(score * 10) / 10;
  var severity = score === 0 ? "None" : score < 4 ? "Low" : score < 7 ? "Medium" : score < 9 ? "High" : "Critical";
  var vector = "CVSS:3.1/AV:" + vals.AV + "/AC:" + vals.AC + "/PR:" + vals.PR + "/UI:" + vals.UI + "/S:" + vals.S + "/C:" + vals.C + "/I:" + vals.I + "/A:" + vals.A;
  return { score: score, severity: severity, vector: vector };
}

// ── DREAD Calculator ──
const DREAD_FACTORS = [
  { id: "damage", name: "Damage Potential", desc: "How great is the damage if the vulnerability is exploited?" },
  { id: "reproducibility", name: "Reproducibility", desc: "How easy is it to reproduce the attack?" },
  { id: "exploitability", name: "Exploitability", desc: "How easy is it to launch an attack?" },
  { id: "affected", name: "Affected Users", desc: "As a rough percentage, how many users are affected?" },
  { id: "discoverability", name: "Discoverability", desc: "How easy is it to find the vulnerability?" }
];

// ── Kill Chain / ATT&CK Mapping ──
const KILL_CHAIN = [
  { phase: "Reconnaissance", desc: "Researching, identifying, and selecting targets", mitre: ["TA0043"], examples: ["OSINT gathering", "Port scanning", "Social media profiling"] },
  { phase: "Weaponization", desc: "Creating attack payload paired with exploit", mitre: ["TA0042"], examples: ["Malware creation", "Exploit development", "Phishing kit building"] },
  { phase: "Delivery", desc: "Transmitting the weapon to the target", mitre: ["TA0001"], examples: ["Phishing email", "Watering hole", "USB drop", "Supply chain"] },
  { phase: "Exploitation", desc: "Exploiting vulnerability to execute code", mitre: ["TA0002"], examples: ["Buffer overflow", "SQL injection", "Zero-day exploit"] },
  { phase: "Installation", desc: "Installing malware or backdoor on target", mitre: ["TA0003"], examples: ["Dropper execution", "Registry persistence", "Scheduled task"] },
  { phase: "Command & Control", desc: "Establishing communication channel", mitre: ["TA0011"], examples: ["HTTP beaconing", "DNS tunneling", "Domain fronting"] },
  { phase: "Actions on Objectives", desc: "Achieving the attacker's goal", mitre: ["TA0009", "TA0010", "TA0040"], examples: ["Data exfiltration", "Ransomware encryption", "Lateral movement"] }
];

// ── Compliance Frameworks ──
const COMPLIANCE_CONTROLS = {
  "NIST CSF": ["ID.AM", "ID.BE", "ID.GV", "ID.RA", "ID.RM", "ID.SC", "PR.AC", "PR.AT", "PR.DS", "PR.IP", "PR.MA", "PR.PT", "DE.AE", "DE.CM", "DE.DP", "RS.RP", "RS.CO", "RS.AN", "RS.MI", "RS.IM", "RC.RP", "RC.IM", "RC.CO"],
  "ISO 27001": ["A.5", "A.6", "A.7", "A.8", "A.9", "A.10", "A.11", "A.12", "A.13", "A.14", "A.15", "A.16", "A.17", "A.18"],
  "OWASP Top 10": ["A01:2021 Broken Access Control", "A02:2021 Cryptographic Failures", "A03:2021 Injection", "A04:2021 Insecure Design", "A05:2021 Security Misconfiguration", "A06:2021 Vulnerable Components", "A07:2021 Auth Failures", "A08:2021 Software/Data Integrity", "A09:2021 Logging Failures", "A10:2021 SSRF"],
  "CIS Controls v8": ["CIS 1: Inventory of Enterprise Assets", "CIS 2: Inventory of Software", "CIS 3: Data Protection", "CIS 4: Secure Configuration", "CIS 5: Account Management", "CIS 6: Access Control Management", "CIS 7: Continuous Vulnerability Management", "CIS 8: Audit Log Management", "CIS 9: Email & Browser Protections", "CIS 10: Malware Defenses", "CIS 11: Data Recovery", "CIS 12: Network Infrastructure Management", "CIS 13: Network Monitoring & Defense", "CIS 14: Security Awareness Training", "CIS 15: Service Provider Management", "CIS 16: Application Software Security", "CIS 17: Incident Response Management", "CIS 18: Penetration Testing"],
  "PCI DSS v4.0": ["Req 1: Network Security Controls", "Req 2: Secure Configurations", "Req 3: Protect Stored Account Data", "Req 4: Protect with Strong Cryptography", "Req 5: Protect from Malicious Software", "Req 6: Develop Secure Systems", "Req 7: Restrict Access by Business Need", "Req 8: Identify Users and Auth", "Req 9: Restrict Physical Access", "Req 10: Log and Monitor Access", "Req 11: Test Security Regularly", "Req 12: Support with Policies"]
};

// ── Risk Matrix ──
const RISK_LEVELS = ["Very Low", "Low", "Medium", "High", "Very High"];
const RISK_COLORS = ["#2d7d46", "var(--ok)", "var(--warn)", "var(--bad)", "var(--bad)"];

// ── Main Render ──
export function renderThreatModeler(main) {
  var tabs = [
    { id: "stride", label: "STRIDE Analysis" },
    { id: "dread", label: "DREAD Scoring" },
    { id: "pasta", label: "PASTA" },
    { id: "linddun", label: "LINDDUN Privacy" },
    { id: "cvss", label: "CVSS Calculator" },
    { id: "threats", label: "Threat Library" },
    { id: "requirements", label: "Security Requirements" },
    { id: "assets", label: "Asset Inventory" },
    { id: "risk", label: "Risk Matrix" },
    { id: "attacktree", label: "Attack Trees" },
    { id: "dfd", label: "Data Flow Diagram" },
    { id: "killchain", label: "Kill Chain" },
    { id: "compliance", label: "Compliance" },
    { id: "report", label: "Report" }
  ];

  var tabBtns = tabs.map(function(t) {
    return '<button class="chip' + (t.id === "stride" ? " on" : "") + '" data-tab="' + t.id + '">' + esc(t.label) + '</button>';
  }).join("");

  main.innerHTML =
    '<div class="pg-head"><div><h1 class="pg-h1">Threat Modeler</h1>' +
    '<p class="muted pg-sub">Interactive threat modeling — STRIDE, DREAD, PASTA, LINDDUN privacy, CVSS, a CWE-tagged threat library, security requirements, attack trees, data flow diagrams, and compliance mapping.</p></div></div>' +
    '<div class="seg" id="tm-tabs" style="flex-wrap:wrap">' + tabBtns + '</div>' +
    '<div id="tm-content" style="margin-top:16px"></div>';

  var content = main.querySelector("#tm-content");

  function showTab(id) {
    main.querySelectorAll("#tm-tabs .chip").forEach(function(b) { b.classList.toggle("on", b.dataset.tab === id); });
    content.onchange = content.oninput = null; // PASTA/LINDDUN delegate on the container; don't leak into other tabs
    if (id === "stride") renderSTRIDE(content);
    else if (id === "dread") renderDREAD(content);
    else if (id === "pasta") renderPASTA(content);
    else if (id === "linddun") renderLINDDUN(content);
    else if (id === "cvss") renderCVSS(content);
    else if (id === "threats") renderThreats(content);
    else if (id === "requirements") renderRequirements(content, showTab);
    else if (id === "assets") renderAssets(content);
    else if (id === "risk") renderRisk(content);
    else if (id === "attacktree") renderAttackTree(content);
    else if (id === "dfd") renderDFD(content);
    else if (id === "killchain") renderKillChain(content);
    else if (id === "compliance") renderCompliance(content);
    else if (id === "report") renderReportTab(content);
  }

  main.querySelector("#tm-tabs").onclick = function(e) {
    var b = e.target.closest(".chip");
    if (b) showTab(b.dataset.tab);
  };

  showTab("stride");
}

// ── STRIDE Tab ──
function renderSTRIDE(el) {
  var cards = STRIDE.map(function(s) {
    var examples = s.examples.map(function(ex) { return '<li>' + esc(ex) + '</li>'; }).join("");
    var mits = s.mitigations.map(function(m) { return '<li>' + esc(m) + '</li>'; }).join("");
    return '<div class="arse-card" style="cursor:default;margin-bottom:12px">' +
      '<div class="an"><span style="background:var(--acc);color:var(--on-acc,#fff);padding:2px 8px;border-radius:2px;font-weight:700;margin-right:8px">' + s.id + '</span>' + esc(s.name) + '</div>' +
      '<div class="ad" style="margin:8px 0">' + esc(s.desc) + '</div>' +
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;font-size:.82rem">' +
        '<div><strong style="color:var(--acc)">Examples</strong><ul style="margin:4px 0;padding-left:18px;color:var(--mut)">' + examples + '</ul></div>' +
        '<div><strong style="color:var(--ok)">Mitigations</strong><ul style="margin:4px 0;padding-left:18px;color:var(--mut)">' + mits + '</ul></div>' +
      '</div>' +
    '</div>';
  }).join("");

  el.innerHTML =
    '<h2 class="pg-h2">STRIDE threat classification</h2>' +
    '<p class="muted" style="margin-bottom:16px">Systematically identify threats by classifying them into six categories. For each component in your system, ask: can an attacker do this?</p>' +
    cards +
    '<div class="arse-card" style="cursor:default;margin-top:16px;padding:16px">' +
      '<h3 style="margin:0 0 8px">STRIDE Per-Element Analysis</h3>' +
      '<p class="muted" style="font-size:.82rem;margin-bottom:12px">Add a system element and check which STRIDE categories apply:</p>' +
      '<div style="display:flex;gap:8px;margin-bottom:12px">' +
        '<input id="stride-elem" placeholder="Element name (e.g., Login API)" style="flex:1;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
        '<select id="stride-type" style="padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
          '<option value="Process">Process</option><option value="Data Store">Data Store</option><option value="Data Flow">Data Flow</option><option value="External Entity">External Entity</option><option value="Trust Boundary">Trust Boundary</option>' +
        '</select>' +
        '<button class="btn" id="stride-add" style="padding:6px 16px">Add</button>' +
      '</div>' +
      '<div id="stride-table"></div>' +
    '</div>';

  var items = [];
  try { items = JSON.parse(localStorage.getItem(acctKey("tm_stride_items")) || "[]"); } catch (_) {}

  function renderTable() {
    if (!items.length) {
      el.querySelector("#stride-table").innerHTML = '<p class="muted" style="font-size:.82rem">No elements added yet.</p>';
      return;
    }
    var header = '<tr><th style="text-align:left;padding:6px;border-bottom:1px solid var(--line)">Element</th><th style="padding:6px;border-bottom:1px solid var(--line)">Type</th>';
    STRIDE.forEach(function(s) { header += '<th style="padding:6px;border-bottom:1px solid var(--line);width:40px;text-align:center" title="' + esc(s.name) + '">' + s.id + '</th>'; });
    header += '<th style="padding:6px;border-bottom:1px solid var(--line);width:40px"></th></tr>';
    var rows = items.map(function(item, idx) {
      var checks = STRIDE.map(function(s) {
        var checked = item.threats && item.threats.indexOf(s.id) >= 0;
        return '<td style="text-align:center;padding:4px"><input type="checkbox" data-idx="' + idx + '" data-sid="' + s.id + '"' + (checked ? " checked" : "") + ' style="width:16px;height:16px"></td>';
      }).join("");
      return '<tr><td style="padding:6px;border-bottom:1px solid var(--line)">' + esc(item.name) + '</td>' +
        '<td style="padding:6px;border-bottom:1px solid var(--line);color:var(--mut);font-size:.8rem">' + esc(item.type) + '</td>' +
        checks +
        '<td style="padding:4px;border-bottom:1px solid var(--line)"><button class="btn" data-del="' + idx + '" style="padding:2px 8px;font-size:.75rem;background:var(--bad)">x</button></td></tr>';
    }).join("");
    el.querySelector("#stride-table").innerHTML = '<table style="width:100%;border-collapse:collapse;font-size:.82rem">' + header + rows + '</table>';
  }
  renderTable();

  el.querySelector("#stride-add").onclick = function() {
    var name = el.querySelector("#stride-elem").value.trim();
    var type = el.querySelector("#stride-type").value;
    if (!name) return;
    items.push({ name: name, type: type, threats: [] });
    try { localStorage.setItem(acctKey("tm_stride_items"), JSON.stringify(items)); } catch (_) {}
    el.querySelector("#stride-elem").value = "";
    renderTable();
  };
  el.querySelector("#stride-table").onclick = function(e) {
    if (e.target.dataset.del !== undefined) {
      items.splice(parseInt(e.target.dataset.del), 1);
      try { localStorage.setItem(acctKey("tm_stride_items"), JSON.stringify(items)); } catch (_) {}
      renderTable();
    }
  };
  el.querySelector("#stride-table").onchange = function(e) {
    if (e.target.type === "checkbox" && e.target.dataset.idx !== undefined) {
      var idx = parseInt(e.target.dataset.idx);
      var sid = e.target.dataset.sid;
      if (!items[idx].threats) items[idx].threats = [];
      if (e.target.checked) { if (items[idx].threats.indexOf(sid) < 0) items[idx].threats.push(sid); }
      else { items[idx].threats = items[idx].threats.filter(function(t) { return t !== sid; }); }
      try { localStorage.setItem(acctKey("tm_stride_items"), JSON.stringify(items)); } catch (_) {}
    }
  };
}

// ── DREAD Tab ──
function renderDREAD(el) {
  var sliders = DREAD_FACTORS.map(function(f) {
    return '<div style="margin-bottom:14px">' +
      '<div style="display:flex;justify-content:space-between;align-items:center">' +
        '<label style="font-weight:600;font-size:.85rem">' + esc(f.name) + '</label>' +
        '<span class="dread-val" id="dv-' + f.id + '" style="font-weight:700;color:var(--acc)">5</span>' +
      '</div>' +
      '<p class="muted" style="font-size:.75rem;margin:2px 0 6px">' + esc(f.desc) + '</p>' +
      '<input type="range" id="dr-' + f.id + '" min="1" max="10" value="5" style="width:100%;accent-color:var(--acc)">' +
    '</div>';
  }).join("");

  el.innerHTML =
    '<h2 class="pg-h2">DREAD risk scoring</h2>' +
    '<p class="muted" style="margin-bottom:16px">Rate each factor from 1 (low) to 10 (high). The overall DREAD score is the average.</p>' +
    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:24px">' +
      '<div>' + sliders + '</div>' +
      '<div>' +
        '<div class="arse-card" style="cursor:default;text-align:center;padding:24px">' +
          '<div style="font-size:.8rem;color:var(--mut);margin-bottom:8px">DREAD Score</div>' +
          '<div id="dread-score" style="font-size:3rem;font-weight:800;color:var(--acc)">5.0</div>' +
          '<div id="dread-level" style="font-size:1rem;font-weight:600;margin-top:4px">Medium</div>' +
          '<div id="dread-vector" style="font-size:.75rem;color:var(--mut);margin-top:12px;font-family:var(--mono,monospace)"></div>' +
        '</div>' +
        '<div class="arse-card" style="cursor:default;margin-top:12px;padding:16px">' +
          '<h3 style="margin:0 0 8px;font-size:.9rem">DREAD Scale Reference</h3>' +
          '<table style="width:100%;font-size:.78rem;border-collapse:collapse">' +
            '<tr><td style="padding:4px;border-bottom:1px solid var(--line)"><strong>1-3</strong></td><td style="padding:4px;border-bottom:1px solid var(--line);color:var(--ok)">Low Risk</td></tr>' +
            '<tr><td style="padding:4px;border-bottom:1px solid var(--line)"><strong>4-6</strong></td><td style="padding:4px;border-bottom:1px solid var(--line);color:var(--warn)">Medium Risk</td></tr>' +
            '<tr><td style="padding:4px;border-bottom:1px solid var(--line)"><strong>7-8</strong></td><td style="padding:4px;border-bottom:1px solid var(--line);color:var(--bad)">High Risk</td></tr>' +
            '<tr><td style="padding:4px"><strong>9-10</strong></td><td style="padding:4px;color:var(--bad)">Critical Risk</td></tr>' +
          '</table>' +
        '</div>' +
      '</div>' +
    '</div>';

  function updateDread() {
    var total = 0;
    var parts = [];
    DREAD_FACTORS.forEach(function(f) {
      var v = parseInt(el.querySelector("#dr-" + f.id).value);
      el.querySelector("#dv-" + f.id).textContent = v;
      total += v;
      parts.push(f.id.charAt(0).toUpperCase() + ":" + v);
    });
    var avg = (total / 5).toFixed(1);
    el.querySelector("#dread-score").textContent = avg;
    var level = avg < 4 ? "Low" : avg < 7 ? "Medium" : avg < 9 ? "High" : "Critical";
    var color = avg < 4 ? "var(--ok)" : avg < 7 ? "var(--warn)" : avg < 9 ? "var(--bad)" : "var(--bad)";
    el.querySelector("#dread-score").style.color = color;
    el.querySelector("#dread-level").textContent = level;
    el.querySelector("#dread-level").style.color = color;
    el.querySelector("#dread-vector").textContent = "DREAD/" + parts.join("/");
  }
  DREAD_FACTORS.forEach(function(f) {
    el.querySelector("#dr-" + f.id).oninput = updateDread;
  });
  updateDread();
}

// ── CVSS Tab ──
function renderCVSS(el) {
  var metricsHTML = Object.keys(CVSS31_METRICS).map(function(key) {
    var m = CVSS31_METRICS[key];
    var opts = m.options.map(function(o) {
      return '<option value="' + o.val + '">' + esc(o.label) + ' (' + o.val + ')</option>';
    }).join("");
    return '<div style="margin-bottom:10px">' +
      '<label style="font-size:.82rem;font-weight:600;display:block;margin-bottom:4px">' + esc(m.name) + '</label>' +
      '<select class="cvss-sel" data-key="' + key + '" style="width:100%;padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' + opts + '</select>' +
    '</div>';
  }).join("");

  el.innerHTML =
    '<h2 class="pg-h2">CVSS v3.1 calculator</h2>' +
    '<p class="muted" style="margin-bottom:16px">Select base metric values to calculate the CVSS v3.1 score.</p>' +
    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:24px">' +
      '<div>' + metricsHTML + '</div>' +
      '<div>' +
        '<div class="arse-card" style="cursor:default;text-align:center;padding:24px">' +
          '<div style="font-size:.8rem;color:var(--mut);margin-bottom:8px">CVSS v3.1 Base Score</div>' +
          '<div id="cvss-score" style="font-size:3rem;font-weight:800;color:var(--acc)">0.0</div>' +
          '<div id="cvss-sev" style="font-size:1rem;font-weight:600;margin-top:4px">None</div>' +
          '<div id="cvss-vector" style="font-size:.75rem;color:var(--mut);margin-top:12px;font-family:var(--mono,monospace);word-break:break-all"></div>' +
        '</div>' +
        '<div class="arse-card" style="cursor:default;margin-top:12px;padding:16px">' +
          '<h3 style="margin:0 0 8px;font-size:.9rem">Severity Scale</h3>' +
          '<div style="display:flex;gap:4px;margin-bottom:8px">' +
            '<span style="flex:1;text-align:center;padding:6px;background:#2d7d46;color:#fff;font-size:.75rem;border-radius:2px">None<br>0.0</span>' +
            '<span style="flex:1;text-align:center;padding:6px;background:var(--ok);color:#fff;font-size:.75rem;border-radius:2px">Low<br>0.1-3.9</span>' +
            '<span style="flex:1;text-align:center;padding:6px;background:var(--warn);color:#fff;font-size:.75rem;border-radius:2px">Med<br>4.0-6.9</span>' +
            '<span style="flex:1;text-align:center;padding:6px;background:var(--bad);color:#fff;font-size:.75rem;border-radius:2px">High<br>7.0-8.9</span>' +
            '<span style="flex:1;text-align:center;padding:6px;background:var(--bad);color:#fff;font-size:.75rem;border-radius:2px">Crit<br>9.0-10</span>' +
          '</div>' +
        '</div>' +
      '</div>' +
    '</div>';

  function update() {
    var vals = {};
    el.querySelectorAll(".cvss-sel").forEach(function(sel) { vals[sel.dataset.key] = sel.value; });
    var result = calcCVSS31(vals);
    el.querySelector("#cvss-score").textContent = result.score.toFixed(1);
    el.querySelector("#cvss-sev").textContent = result.severity;
    var color = result.score === 0 ? "#2d7d46" : result.score < 4 ? "var(--ok)" : result.score < 7 ? "var(--warn)" : result.score < 9 ? "var(--bad)" : "var(--bad)";
    el.querySelector("#cvss-score").style.color = color;
    el.querySelector("#cvss-sev").style.color = color;
    el.querySelector("#cvss-vector").textContent = result.vector;
  }
  el.querySelectorAll(".cvss-sel").forEach(function(sel) { sel.onchange = update; });
  update();
}

// ── Threat Library Tab ──
function renderThreats(el) {
  var categories = ["All"].concat(STRIDE.map(function(s) { return s.id + " - " + s.name; }));
  var sevs = ["All", "Critical", "High", "Medium", "Low"];
  var filterHTML =
    '<div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap">' +
      '<select id="tl-cat" style="padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
        categories.map(function(c) { return '<option value="' + esc(c.split(" - ")[0]) + '">' + esc(c) + '</option>'; }).join("") +
      '</select>' +
      '<select id="tl-sev" style="padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
        sevs.map(function(s) { return '<option>' + esc(s) + '</option>'; }).join("") +
      '</select>' +
      '<input id="tl-search" placeholder="Search threats..." style="flex:1;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
    '</div>';

  el.innerHTML =
    '<h2 class="pg-h2">Threat library</h2>' +
    '<p class="muted" style="margin-bottom:16px">' + THREAT_LIBRARY.length + ' threats mapped to STRIDE categories, ' + THREAT_LIBRARY.filter(function(t) { return t.cwe; }).length + ' of them tagged with a CWE weakness, with mitigations and MITRE ATT&CK references. Tick threats that apply to your system to generate Security Requirements.</p>' +
    filterHTML +
    '<div id="tl-count" class="muted" style="font-size:.78rem;margin-bottom:8px"></div>' +
    '<div id="tl-list"></div>';

  var selected = loadReqSelection();
  function renderList() {
    var cat = el.querySelector("#tl-cat").value;
    var sev = el.querySelector("#tl-sev").value;
    var search = el.querySelector("#tl-search").value.toLowerCase();
    var filtered = THREAT_LIBRARY.filter(function(t) {
      if (cat !== "All" && t.stride !== cat) return false;
      if (sev !== "All" && t.severity !== sev) return false;
      if (search && (t.id + " " + t.name + " " + t.desc + " " + t.cwe + " " + t.mitre).toLowerCase().indexOf(search) < 0) return false;
      return true;
    });
    el.querySelector("#tl-count").textContent = filtered.length + " shown, " + Object.keys(selected).length + " selected for requirements";
    var sevColor = { Critical: "var(--bad)", High: "var(--bad)", Medium: "var(--warn)", Low: "var(--ok)" };
    var cards = filtered.map(function(t) {
      var mits = t.mitigations.map(function(m) { return '<span style="display:inline-block;padding:2px 8px;background:var(--bg);border:1px solid var(--line);border-radius:2px;font-size:.75rem;margin:2px;max-width:100%;white-space:normal">' + esc(m) + '</span>'; }).join("");
      var refs = [t.id, t.cwe, t.mitre ? "MITRE " + t.mitre : ""].filter(Boolean).join(" · ");
      return '<div class="arse-card" style="cursor:default;margin-bottom:8px">' +
        '<div class="an" style="display:flex;align-items:center;gap:8px">' +
          '<span style="background:var(--acc);color:var(--on-acc,#fff);padding:1px 6px;border-radius:2px;font-size:.75rem;font-weight:700">' + t.stride + '</span>' +
          esc(t.name) +
          '<span style="margin-left:auto;color:' + (sevColor[t.severity] || "var(--mut)") + ';font-size:.75rem;font-weight:600">' + esc(t.severity) + '</span>' +
        '</div>' +
        '<div class="ad" style="margin:6px 0">' + esc(t.desc) + '</div>' +
        (t.example ? '<div class="muted" style="font-size:.75rem;margin:0 0 6px">Example: ' + esc(t.example) + '</div>' : '') +
        '<div style="margin-bottom:4px">' + mits + '</div>' +
        '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
          '<span style="font-size:.75rem;color:var(--mut);font-family:var(--mono,monospace)">' + esc(refs) + '</span>' +
          '<label style="margin-left:auto;display:flex;align-items:center;gap:6px;font-size:.75rem;cursor:pointer"><input type="checkbox" data-req="' + esc(t.id) + '"' + (selected[t.id] ? " checked" : "") + '> Applies to my system</label>' +
        '</div>' +
      '</div>';
    }).join("");
    el.querySelector("#tl-list").innerHTML = filtered.length ? cards : '<p class="muted">No threats match the current filters.</p>';
  }
  el.querySelector("#tl-list").onchange = function(e) {
    var cb = e.target.closest("[data-req]"); if (!cb) return;
    if (cb.checked) selected[cb.dataset.req] = true; else delete selected[cb.dataset.req];
    saveReqSelection(selected);
    el.querySelector("#tl-count").textContent = el.querySelector("#tl-count").textContent.replace(/\d+ selected/, Object.keys(selected).length + " selected");
  };
  el.querySelector("#tl-cat").onchange = renderList;
  el.querySelector("#tl-sev").onchange = renderList;
  el.querySelector("#tl-search").oninput = renderList;
  renderList();
}

// ── Asset Inventory Tab ──
function renderAssets(el) {
  var classifications = ["Public", "Internal", "Confidential", "Restricted"];
  var types = ["Application", "Server", "Database", "Network Device", "API", "Cloud Service", "Workstation", "Mobile Device", "IoT Device", "Data Store"];

  el.innerHTML =
    '<h2 class="pg-h2">Asset inventory</h2>' +
    '<p class="muted" style="margin-bottom:16px">Catalog your assets with classification levels to prioritize threat modeling efforts.</p>' +
    '<div class="arse-card" style="cursor:default;padding:16px;margin-bottom:16px">' +
      '<div style="display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:8px">' +
        '<input id="asset-name" placeholder="Asset name" style="padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
        '<select id="asset-type" style="padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' + types.map(function(t) { return '<option>' + esc(t) + '</option>'; }).join("") + '</select>' +
        '<select id="asset-class" style="padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' + classifications.map(function(c) { return '<option>' + esc(c) + '</option>'; }).join("") + '</select>' +
        '<button class="btn" id="asset-add" style="padding:6px 16px">Add</button>' +
      '</div>' +
      '<input id="asset-desc" placeholder="Description (optional)" style="width:100%;margin-top:8px;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
    '</div>' +
    '<div id="asset-list"></div>';

  var assets = [];
  try { assets = JSON.parse(localStorage.getItem(acctKey("tm_assets")) || "[]"); } catch (_) {}
  var classColors = { Public: "var(--ok)", Internal: "var(--acc)", Confidential: "var(--warn)", Restricted: "var(--bad)" };

  function renderAssetList() {
    if (!assets.length) { el.querySelector("#asset-list").innerHTML = '<p class="muted">No assets added yet.</p>'; return; }
    var cards = assets.map(function(a, i) {
      return '<div class="arse-card" style="cursor:default;margin-bottom:6px;display:flex;align-items:center;gap:12px">' +
        '<span style="width:6px;height:6px;border-radius:50%;background:' + (classColors[a.classification] || "var(--mut)") + ';flex-shrink:0"></span>' +
        '<div style="flex:1">' +
          '<div style="font-weight:600;font-size:.85rem">' + esc(a.name) + ' <span style="color:var(--mut);font-weight:400;font-size:.75rem">(' + esc(a.type) + ')</span></div>' +
          (a.desc ? '<div class="muted" style="font-size:.75rem">' + esc(a.desc) + '</div>' : '') +
        '</div>' +
        '<span style="padding:2px 8px;border-radius:2px;font-size:.75rem;font-weight:600;color:' + (classColors[a.classification] || "var(--mut)") + ';border:1px solid ' + (classColors[a.classification] || "var(--line)") + '">' + esc(a.classification) + '</span>' +
        '<button class="btn" data-del="' + i + '" style="padding:2px 8px;font-size:.75rem;background:var(--bad)">x</button>' +
      '</div>';
    }).join("");
    el.querySelector("#asset-list").innerHTML = cards;
  }
  renderAssetList();

  el.querySelector("#asset-add").onclick = function() {
    var name = el.querySelector("#asset-name").value.trim();
    if (!name) return;
    assets.push({ name: name, type: el.querySelector("#asset-type").value, classification: el.querySelector("#asset-class").value, desc: el.querySelector("#asset-desc").value.trim() });
    try { localStorage.setItem(acctKey("tm_assets"), JSON.stringify(assets)); } catch (_) {}
    el.querySelector("#asset-name").value = "";
    el.querySelector("#asset-desc").value = "";
    renderAssetList();
  };
  el.querySelector("#asset-list").onclick = function(e) {
    if (e.target.dataset.del !== undefined) {
      assets.splice(parseInt(e.target.dataset.del), 1);
      try { localStorage.setItem(acctKey("tm_assets"), JSON.stringify(assets)); } catch (_) {}
      renderAssetList();
    }
  };
}

// ── Risk Matrix Tab ──
function renderRisk(el) {
  var cells = [];
  for (var li = 4; li >= 0; li--) {
    for (var ii = 0; ii < 5; ii++) {
      var riskLevel = Math.round((li + ii) / 2);
      cells.push({ li: li, ii: ii, risk: riskLevel });
    }
  }
  var matrixHTML = '<table style="border-collapse:collapse;width:100%;table-layout:fixed">';
  matrixHTML += '<tr><th style="width:80px"></th>';
  for (var i = 0; i < 5; i++) {
    matrixHTML += '<th style="padding:8px;text-align:center;font-size:.75rem;border:1px solid var(--line)">' + RISK_LEVELS[i] + '<br>Impact</th>';
  }
  matrixHTML += '</tr>';
  for (var l = 4; l >= 0; l--) {
    matrixHTML += '<tr><th style="padding:8px;text-align:right;font-size:.75rem;border:1px solid var(--line)">' + RISK_LEVELS[l] + '<br>Likelihood</th>';
    for (var im = 0; im < 5; im++) {
      var risk = Math.round((l + im) / 2);
      matrixHTML += '<td style="padding:12px;text-align:center;border:1px solid var(--line);background:' + RISK_COLORS[risk] + '20;cursor:pointer;font-size:.75rem;color:' + RISK_COLORS[risk] + ';font-weight:600" data-l="' + l + '" data-i="' + im + '">' + RISK_LEVELS[risk] + '</td>';
    }
    matrixHTML += '</tr>';
  }
  matrixHTML += '</table>';

  el.innerHTML =
    '<h2 class="pg-h2">Risk assessment matrix</h2>' +
    '<p class="muted" style="margin-bottom:16px">5x5 likelihood vs. impact matrix. Click a cell to place a risk item.</p>' +
    matrixHTML +
    '<div style="margin-top:16px">' +
      '<div style="display:flex;gap:8px;margin-bottom:12px">' +
        '<input id="risk-name" placeholder="Risk / Threat name" style="flex:1;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
      '</div>' +
      '<div id="risk-items"></div>' +
    '</div>';

  var riskItems = [];
  try { riskItems = JSON.parse(localStorage.getItem(acctKey("tm_risk_items")) || "[]"); } catch (_) {}

  function renderRiskItems() {
    if (!riskItems.length) { el.querySelector("#risk-items").innerHTML = '<p class="muted" style="font-size:.82rem">Click a matrix cell to place a risk. Enter a name first.</p>'; return; }
    var html = riskItems.map(function(r, i) {
      var risk = Math.round((r.likelihood + r.impact) / 2);
      return '<div class="arse-card" style="cursor:default;margin-bottom:4px;display:flex;align-items:center;gap:8px;padding:8px 12px">' +
        '<span style="width:8px;height:8px;border-radius:50%;background:' + RISK_COLORS[risk] + '"></span>' +
        '<span style="font-size:.82rem;font-weight:600">' + esc(r.name) + '</span>' +
        '<span class="muted" style="font-size:.75rem;margin-left:auto">L:' + RISK_LEVELS[r.likelihood] + ' / I:' + RISK_LEVELS[r.impact] + '</span>' +
        '<span style="color:' + RISK_COLORS[risk] + ';font-size:.75rem;font-weight:600">' + RISK_LEVELS[risk] + '</span>' +
        '<button class="btn" data-rdel="' + i + '" style="padding:1px 6px;font-size:.75rem;background:var(--bad)">x</button>' +
      '</div>';
    }).join("");
    el.querySelector("#risk-items").innerHTML = html;
  }
  renderRiskItems();

  el.querySelector("table").onclick = function(e) {
    var td = e.target.closest("td[data-l]");
    if (!td) return;
    var name = el.querySelector("#risk-name").value.trim();
    if (!name) { el.querySelector("#risk-name").focus(); return; }
    riskItems.push({ name: name, likelihood: parseInt(td.dataset.l), impact: parseInt(td.dataset.i) });
    try { localStorage.setItem(acctKey("tm_risk_items"), JSON.stringify(riskItems)); } catch (_) {}
    el.querySelector("#risk-name").value = "";
    renderRiskItems();
  };
  el.querySelector("#risk-items").onclick = function(e) {
    if (e.target.dataset.rdel !== undefined) {
      riskItems.splice(parseInt(e.target.dataset.rdel), 1);
      try { localStorage.setItem(acctKey("tm_risk_items"), JSON.stringify(riskItems)); } catch (_) {}
      renderRiskItems();
    }
  };
}

// ── Attack Tree Tab ──
function renderAttackTree(el) {
  el.innerHTML =
    '<h2 class="pg-h2">Attack trees</h2>' +
    '<p class="muted" style="margin-bottom:16px">Model attack scenarios as trees. The root is the attacker\'s goal; branches are sub-goals connected by AND/OR gates.</p>' +
    '<div style="display:flex;gap:8px;margin-bottom:12px">' +
      '<input id="at-root" placeholder="Root goal (e.g., Steal customer data)" value="" style="flex:1;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
      '<button class="btn" id="at-reset" style="padding:6px 12px;background:var(--bad)">Reset</button>' +
    '</div>' +
    '<div id="at-tree" style="padding:16px;background:var(--card);border:1px solid var(--line);border-radius:2px;overflow-x:auto"></div>' +
    '<div style="display:flex;gap:8px;margin-top:12px">' +
      '<input id="at-child" placeholder="Add sub-goal..." style="flex:1;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
      '<select id="at-gate" style="padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px"><option>OR</option><option>AND</option></select>' +
      '<button class="btn" id="at-addchild" style="padding:6px 12px">Add to Selected</button>' +
    '</div>' +
    '<p class="muted" style="font-size:.75rem;margin-top:8px">Click a node to select it, then add children. OR = any child suffices. AND = all children required.</p>';

  var tree = { id: "root", name: "Attacker Goal", gate: "OR", children: [], expanded: true };
  try { var saved = JSON.parse(localStorage.getItem(acctKey("tm_attack_tree"))); if (saved) tree = saved; } catch (_) {}
  var selectedId = "root";

  function renderNode(node, depth) {
    var indent = depth * 24;
    var isSel = node.id === selectedId;
    var gateColor = node.gate === "AND" ? "var(--bad)" : "var(--ok)";
    var childrenHTML = "";
    if (node.children && node.children.length) {
      childrenHTML = node.children.map(function(c) { return renderNode(c, depth + 1); }).join("");
    }
    return '<div style="margin-left:' + indent + 'px;margin-bottom:4px">' +
      '<div data-nid="' + esc(node.id) + '" style="display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border:2px solid ' + (isSel ? "var(--acc)" : "var(--line)") + ';border-radius:4px;cursor:pointer;background:' + (isSel ? "var(--acc)10" : "var(--card)") + '">' +
        (node.children && node.children.length ? '<span style="font-size:.75rem;padding:1px 4px;border-radius:2px;background:' + gateColor + ';color:#fff;font-weight:700">' + node.gate + '</span>' : '') +
        '<span style="font-size:.82rem">' + esc(node.name) + '</span>' +
        (node.id !== "root" ? '<span class="at-del" data-did="' + esc(node.id) + '" style="font-size:.75rem;color:var(--bad);cursor:pointer;margin-left:4px">[x]</span>' : '') +
      '</div>' +
      childrenHTML +
    '</div>';
  }

  function paint() {
    el.querySelector("#at-tree").innerHTML = renderNode(tree, 0);
  }
  paint();

  var idCounter = Date.now();
  function findNode(node, id) {
    if (node.id === id) return node;
    if (node.children) { for (var i = 0; i < node.children.length; i++) { var f = findNode(node.children[i], id); if (f) return f; } }
    return null;
  }
  function removeNode(parent, id) {
    if (parent.children) {
      parent.children = parent.children.filter(function(c) { return c.id !== id; });
      parent.children.forEach(function(c) { removeNode(c, id); });
    }
  }

  el.querySelector("#at-tree").onclick = function(e) {
    var del = e.target.closest("[data-did]");
    if (del) { removeNode(tree, del.dataset.did); if (selectedId === del.dataset.did) selectedId = "root"; try { localStorage.setItem(acctKey("tm_attack_tree"), JSON.stringify(tree)); } catch (_) {} paint(); return; }
    var nd = e.target.closest("[data-nid]");
    if (nd) { selectedId = nd.dataset.nid; paint(); }
  };
  el.querySelector("#at-addchild").onclick = function() {
    var name = el.querySelector("#at-child").value.trim();
    if (!name) return;
    var parent = findNode(tree, selectedId);
    if (!parent) return;
    if (!parent.children) parent.children = [];
    parent.gate = el.querySelector("#at-gate").value;
    parent.children.push({ id: "n" + (++idCounter), name: name, gate: "OR", children: [] });
    try { localStorage.setItem(acctKey("tm_attack_tree"), JSON.stringify(tree)); } catch (_) {}
    el.querySelector("#at-child").value = "";
    paint();
  };
  el.querySelector("#at-root").onchange = function() {
    tree.name = el.querySelector("#at-root").value.trim() || "Attacker Goal";
    try { localStorage.setItem(acctKey("tm_attack_tree"), JSON.stringify(tree)); } catch (_) {}
    paint();
  };
  el.querySelector("#at-root").value = tree.name;
  el.querySelector("#at-reset").onclick = function() {
    tree = { id: "root", name: "Attacker Goal", gate: "OR", children: [], expanded: true };
    selectedId = "root";
    try { localStorage.setItem(acctKey("tm_attack_tree"), JSON.stringify(tree)); } catch (_) {}
    el.querySelector("#at-root").value = tree.name;
    paint();
  };
}

// ── Data Flow Diagram Tab ──
function renderDFD(el) {
  el.innerHTML =
    '<h2 class="pg-h2">Data flow diagram</h2>' +
    '<p class="muted" style="margin-bottom:16px">Model your system\'s data flows to identify trust boundaries and potential threats.</p>' +
    '<div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap">' +
      '<select id="dfd-type" style="padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
        '<option value="external">External Entity</option><option value="process">Process</option><option value="datastore">Data Store</option><option value="boundary">Trust Boundary</option>' +
      '</select>' +
      '<input id="dfd-name" placeholder="Name" style="flex:1;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
      '<button class="btn" id="dfd-add" style="padding:6px 12px">Add Element</button>' +
    '</div>' +
    '<div style="display:flex;gap:8px;margin-bottom:12px">' +
      '<select id="dfd-from" style="flex:1;padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px"><option value="">From...</option></select>' +
      '<select id="dfd-to" style="flex:1;padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px"><option value="">To...</option></select>' +
      '<input id="dfd-flowname" placeholder="Data label" style="flex:1;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
      '<button class="btn" id="dfd-addflow" style="padding:6px 12px">Add Flow</button>' +
    '</div>' +
    '<div id="dfd-canvas" style="background:var(--card);border:1px solid var(--line);border-radius:2px;padding:20px;min-height:300px;overflow:auto"></div>' +
    '<div style="margin-top:8px;display:flex;gap:12px;font-size:.75rem;color:var(--mut)">' +
      '<span style="display:flex;align-items:center;gap:4px"><span style="display:inline-block;width:16px;height:16px;border:2px solid var(--acc);border-radius:50%"></span> External Entity</span>' +
      '<span style="display:flex;align-items:center;gap:4px"><span style="display:inline-block;width:16px;height:16px;border:2px solid var(--acc);border-radius:2px"></span> Process</span>' +
      '<span style="display:flex;align-items:center;gap:4px"><span style="display:inline-block;width:16px;height:6px;border-top:2px solid var(--ok);border-bottom:2px solid var(--ok)"></span> Data Store</span>' +
      '<span style="display:flex;align-items:center;gap:4px"><span style="display:inline-block;width:16px;height:16px;border:2px dashed var(--bad);border-radius:2px"></span> Trust Boundary</span>' +
    '</div>' +
    '<details style="margin-top:16px"><summary style="cursor:pointer;font-weight:600;font-size:.85rem">Common trust boundaries (' + DFD_TRUST_BOUNDARY_PATTERNS.length + ')</summary>' +
      DFD_TRUST_BOUNDARY_PATTERNS.map(function(p) { return '<div class="arse-card" style="cursor:default;margin-top:8px"><div class="an">' + esc(p.name) + '</div><div class="ad" style="margin-top:4px">' + esc(p.description) + '</div></div>'; }).join("") +
    '</details>';

  var elements = [];
  var flows = [];
  try { elements = JSON.parse(localStorage.getItem(acctKey("tm_dfd_elements")) || "[]"); } catch (_) {}
  try { flows = JSON.parse(localStorage.getItem(acctKey("tm_dfd_flows")) || "[]"); } catch (_) {}

  function typeStyle(type) {
    if (type === "external") return "border:2px solid var(--acc);border-radius:50%;padding:8px 16px;background:#2196f310";
    if (type === "process") return "border:2px solid var(--acc);border-radius:2px;padding:8px 16px;background:var(--acc)10";
    if (type === "datastore") return "border-top:2px solid var(--ok);border-bottom:2px solid var(--ok);padding:8px 16px;background:#4caf5010";
    if (type === "boundary") return "border:2px dashed var(--bad);border-radius:2px;padding:8px 16px;background:#f4433608";
    return "";
  }

  function paintDFD() {
    var elems = elements.map(function(e, i) {
      return '<div style="display:inline-block;margin:8px;' + typeStyle(e.type) + ';font-size:.82rem;position:relative">' +
        esc(e.name) +
        '<span class="dfd-del dn-round" data-eidx="' + i + '" style="position:absolute;top:-6px;right:-6px;width:16px;height:16px;border-radius:50%;background:var(--bad);color:#fff;font-size:.75rem;display:flex;align-items:center;justify-content:center;cursor:pointer">x</span>' +
      '</div>';
    }).join("");
    var flowsList = flows.map(function(f, i) {
      return '<div style="font-size:.78rem;padding:4px 0;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:6px">' +
        '<span style="font-weight:600">' + esc(f.from) + '</span>' +
        ' <span style="color:var(--acc)">→</span> ' +
        '<span style="font-weight:600">' + esc(f.to) + '</span>' +
        '<span class="muted">(' + esc(f.label) + ')</span>' +
        '<span class="dfd-fdel" data-fidx="' + i + '" style="margin-left:auto;color:var(--bad);cursor:pointer;font-size:.75rem">[x]</span>' +
      '</div>';
    }).join("");
    el.querySelector("#dfd-canvas").innerHTML =
      '<div style="margin-bottom:16px">' + (elems || '<span class="muted">No elements yet. Add external entities, processes, and data stores above.</span>') + '</div>' +
      (flowsList ? '<h4 style="font-size:.85rem;margin:12px 0 4px">Data Flows</h4>' + flowsList : '');
    updateDropdowns();
  }

  function updateDropdowns() {
    var opts = '<option value="">Select...</option>' + elements.filter(function(e) { return e.type !== "boundary"; }).map(function(e) { return '<option>' + esc(e.name) + '</option>'; }).join("");
    el.querySelector("#dfd-from").innerHTML = opts;
    el.querySelector("#dfd-to").innerHTML = opts;
  }
  paintDFD();

  el.querySelector("#dfd-add").onclick = function() {
    var name = el.querySelector("#dfd-name").value.trim();
    if (!name) return;
    elements.push({ name: name, type: el.querySelector("#dfd-type").value });
    try { localStorage.setItem(acctKey("tm_dfd_elements"), JSON.stringify(elements)); } catch (_) {}
    el.querySelector("#dfd-name").value = "";
    paintDFD();
  };
  el.querySelector("#dfd-addflow").onclick = function() {
    var from = el.querySelector("#dfd-from").value;
    var to = el.querySelector("#dfd-to").value;
    var label = el.querySelector("#dfd-flowname").value.trim() || "data";
    if (!from || !to) return;
    flows.push({ from: from, to: to, label: label });
    try { localStorage.setItem(acctKey("tm_dfd_flows"), JSON.stringify(flows)); } catch (_) {}
    el.querySelector("#dfd-flowname").value = "";
    paintDFD();
  };
  el.querySelector("#dfd-canvas").onclick = function(e) {
    var eidx = e.target.closest("[data-eidx]");
    if (eidx) { elements.splice(parseInt(eidx.dataset.eidx), 1); try { localStorage.setItem(acctKey("tm_dfd_elements"), JSON.stringify(elements)); } catch (_) {} paintDFD(); return; }
    var fidx = e.target.closest("[data-fidx]");
    if (fidx) { flows.splice(parseInt(fidx.dataset.fidx), 1); try { localStorage.setItem(acctKey("tm_dfd_flows"), JSON.stringify(flows)); } catch (_) {} paintDFD(); }
  };
}

// ── Kill Chain Tab ──
function renderKillChain(el) {
  var phases = KILL_CHAIN.map(function(kc, i) {
    var examples = kc.examples.map(function(ex) { return '<span style="display:inline-block;padding:1px 6px;background:var(--bg);border:1px solid var(--line);border-radius:2px;font-size:.75rem;margin:2px">' + esc(ex) + '</span>'; }).join("");
    var mitreLinks = kc.mitre.map(function(t) { return '<span style="font-family:var(--mono,monospace);font-size:.75rem;color:var(--acc)">' + esc(t) + '</span>'; }).join(", ");
    return '<div class="arse-card" style="cursor:default;margin-bottom:8px;display:flex;gap:12px;align-items:flex-start">' +
      '<div style="min-width:32px;height:32px;display:flex;align-items:center;justify-content:center;background:var(--acc);color:var(--on-acc,#fff);font-weight:800;border-radius:2px;font-size:.85rem">' + (i + 1) + '</div>' +
      '<div style="flex:1">' +
        '<div style="font-weight:700;font-size:.9rem;margin-bottom:4px">' + esc(kc.phase) + '</div>' +
        '<div class="muted" style="font-size:.8rem;margin-bottom:6px">' + esc(kc.desc) + '</div>' +
        '<div style="margin-bottom:4px">' + examples + '</div>' +
        '<div>MITRE: ' + mitreLinks + '</div>' +
      '</div>' +
    '</div>';
  }).join("");

  el.innerHTML =
    '<h2 class="pg-h2">Cyber Kill Chain and ATT&CK mapping</h2>' +
    '<p class="muted" style="margin-bottom:16px">Map threats to Lockheed Martin\'s Cyber Kill Chain phases and corresponding MITRE ATT&CK tactics.</p>' +
    phases +
    '<div class="arse-card" style="cursor:default;margin-top:16px;padding:16px">' +
      '<h3 style="margin:0 0 8px;font-size:.9rem">MITRE ATT&CK Tactics Overview</h3>' +
      '<div style="display:flex;flex-wrap:wrap;gap:6px">' +
        ["TA0043 Recon", "TA0042 Resource Dev", "TA0001 Initial Access", "TA0002 Execution", "TA0003 Persistence", "TA0004 Priv Esc", "TA0005 Defense Evasion", "TA0006 Credential Access", "TA0007 Discovery", "TA0008 Lateral Movement", "TA0009 Collection", "TA0010 Exfiltration", "TA0011 C2", "TA0040 Impact"].map(function(t) {
          return '<span style="padding:4px 8px;background:var(--bg);border:1px solid var(--line);border-radius:2px;font-size:.75rem;font-family:var(--mono,monospace)">' + esc(t) + '</span>';
        }).join("") +
      '</div>' +
    '</div>';
}

// ── Compliance Tab ──
function renderCompliance(el) {
  var frameworks = Object.keys(COMPLIANCE_CONTROLS);
  var frameworkCards = frameworks.map(function(fw) {
    var controls = COMPLIANCE_CONTROLS[fw].map(function(c) {
      return '<div style="padding:4px 8px;background:var(--bg);border:1px solid var(--line);border-radius:2px;font-size:.75rem">' + esc(c) + '</div>';
    }).join("");
    return '<div class="arse-card" style="cursor:default;margin-bottom:12px">' +
      '<div class="an">' + esc(fw) + ' <span style="color:var(--mut);font-size:.75rem">(' + COMPLIANCE_CONTROLS[fw].length + ' controls)</span></div>' +
      '<div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:8px">' + controls + '</div>' +
    '</div>';
  }).join("");

  el.innerHTML =
    '<h2 class="pg-h2">Compliance framework mapping</h2>' +
    '<p class="muted" style="margin-bottom:16px">Map identified threats to compliance framework controls. Reference for NIST CSF, ISO 27001, OWASP, CIS, and PCI DSS.</p>' +
    '<h3 style="font-size:.95rem;margin:0 0 8px">STRIDE to control mapping</h3>' +
    '<p class="muted" style="font-size:.8rem;margin-bottom:10px">The NIST SP 800-53, ISO/IEC 27001:2022 Annex A and CIS Controls v8 controls that most directly mitigate each STRIDE category.</p>' +
    STRIDE.map(function(s) {
      var m = STRIDE_COMPLIANCE_MAP[STRIDE_KEY[s.id]]; if (!m) return "";
      var row = function(label, ids) { return '<div style="font-size:.75rem;margin-top:4px"><strong>' + label + ':</strong> <span style="font-family:var(--mono,monospace)">' + esc(ids.join(", ")) + '</span></div>'; };
      return '<div class="arse-card" style="cursor:default;margin-bottom:8px"><div class="an">' + s.id + ' - ' + esc(s.name) + '</div><div class="ad" style="margin:4px 0">' + esc(m.rationale) + '</div>' +
        row("NIST 800-53", m.nist) + row("ISO 27001", m.iso) + row("CIS v8", m.cis) + '</div>';
    }).join("") +
    '<h3 style="font-size:.95rem;margin:16px 0 8px">Framework control families</h3>' +
    frameworkCards;
}

// ── Shared state for the ported tabs (persisted like the rest of the modeler) ──
function loadJSON(key, dflt) { try { var v = JSON.parse(localStorage.getItem(key)); return v && typeof v === "object" ? v : dflt; } catch (_) { return dflt; } }
function saveJSON(key, v) { try { localStorage.setItem(key, JSON.stringify(v)); } catch (_) {} }
function loadReqSelection() { var a = loadJSON("tm_req_selected", []); var o = {}; (Array.isArray(a) ? a : []).forEach(function(id) { o[id] = true; }); return o; }
function saveReqSelection(o) { saveJSON("tm_req_selected", Object.keys(o)); }
var CAT_NAME = { spoofing: "Spoofing", tampering: "Tampering", repudiation: "Repudiation", information_disclosure: "Information Disclosure", denial_of_service: "Denial of Service", elevation_of_privilege: "Elevation of Privilege" };
var tmInput = "width:100%;box-sizing:border-box;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px;font:inherit;font-size:.8rem";

// Selected threats -> the requirement templates for every STRIDE category they touch.
function generateRequirements() {
  var sel = loadReqSelection();
  var threats = THREAT_LIBRARY.filter(function(t) { return sel[t.id]; });
  var cats = []; threats.forEach(function(t) { var k = STRIDE_KEY[t.stride]; if (cats.indexOf(k) < 0) cats.push(k); });
  var reqs = [];
  cats.forEach(function(k) { (SECURITY_REQUIREMENTS_TEMPLATES[k] || []).forEach(function(r) { reqs.push({ id: r.id, requirement: r.requirement, priority: r.priority, verification: r.verification, category: k }); }); });
  return { threats: threats, reqs: reqs };
}

// ── PASTA Tab ──
function renderPASTA(el) {
  var st = loadJSON("tm_pasta", {});
  var done = PASTA_STAGES.filter(function(s) { return st[s.stage] && st[s.stage].done; }).length;
  el.innerHTML =
    '<h2 class="pg-h2">PASTA: Process for Attack Simulation and Threat Analysis</h2>' +
    '<p class="muted" style="margin-bottom:8px">A seven-stage, risk-centric methodology that starts and ends with business objectives, so every technical finding is translated into business risk. Work through the stages, record your findings per stage, and they are included in the Report.</p>' +
    '<p id="pasta-progress" style="font-size:.8rem;margin-bottom:12px"><strong>' + done + '/' + PASTA_STAGES.length + '</strong> stages complete</p>' +
    PASTA_STAGES.map(function(s) {
      var v = st[s.stage] || {};
      return '<div class="arse-card" style="cursor:default;margin-bottom:12px">' +
        '<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">' +
          '<span style="min-width:28px;height:28px;display:inline-flex;align-items:center;justify-content:center;background:var(--acc);color:var(--on-acc,#fff);font-weight:800;border-radius:2px">' + s.stage + '</span>' +
          '<span style="font-weight:700">' + esc(s.name) + '</span><span class="muted" style="font-size:.75rem">(' + esc(s.abbr) + ')</span>' +
          '<label style="margin-left:auto;display:flex;align-items:center;gap:6px;font-size:.75rem;cursor:pointer"><input type="checkbox" data-pdone="' + s.stage + '"' + (v.done ? " checked" : "") + '> Complete</label>' +
        '</div>' +
        '<div style="font-size:.82rem;font-weight:600;margin:8px 0">' + esc(s.objective) + '</div>' +
        '<details><summary style="cursor:pointer;font-size:.78rem;color:var(--acc)">Guidance, activities and deliverables</summary>' +
          s.narrative.split("\n\n").map(function(p) { return '<p style="font-size:.8rem;line-height:1.6;margin:8px 0">' + esc(p) + '</p>'; }).join("") +
          '<div style="font-weight:600;font-size:.8rem;margin-top:8px">Key activities</div><ul style="margin:4px 0 0 18px;font-size:.78rem;line-height:1.6">' + s.activities.map(function(a) { return '<li>' + esc(a) + '</li>'; }).join("") + '</ul>' +
          '<div style="font-weight:600;font-size:.8rem;margin-top:8px">Deliverables</div><ul style="margin:4px 0 0 18px;font-size:.78rem;line-height:1.6">' + s.deliverables.map(function(d) { return '<li>' + esc(d) + '</li>'; }).join("") + '</ul>' +
        '</details>' +
        '<textarea data-pnote="' + s.stage + '" rows="3" placeholder="Findings for this stage" style="' + tmInput + ';margin-top:8px;resize:vertical">' + esc(v.notes || "") + '</textarea>' +
      '</div>';
    }).join("");
  function save() {
    el.querySelectorAll("[data-pdone]").forEach(function(cb) { var k = cb.dataset.pdone; st[k] = st[k] || {}; st[k].done = cb.checked; });
    el.querySelectorAll("[data-pnote]").forEach(function(ta) { var k = ta.dataset.pnote; st[k] = st[k] || {}; st[k].notes = ta.value; });
    saveJSON("tm_pasta", st);
    var n = PASTA_STAGES.filter(function(s) { return st[s.stage] && st[s.stage].done; }).length;
    el.querySelector("#pasta-progress").innerHTML = '<strong>' + n + '/' + PASTA_STAGES.length + '</strong> stages complete';
  }
  el.onchange = save; el.oninput = function(e) { if (e.target.matches("[data-pnote]")) save(); };
}

// ── LINDDUN Tab ──
function renderLINDDUN(el) {
  var st = loadJSON("tm_linddun", {});
  function paint() {
    var done = LINDDUN_CATEGORIES.filter(function(c) { return st[c.key] && st[c.key].assessed; }).length;
    el.innerHTML =
      '<h2 class="pg-h2">LINDDUN privacy threat modeling</h2>' +
      '<p class="muted" style="margin-bottom:8px">LINDDUN covers privacy threats that STRIDE does not: linking, identifying, non-repudiation, detecting, data disclosure, unawareness and non-compliance. Use it whenever the system collects, processes or stores personal data. Mark each category assessed and note where it applies.</p>' +
      '<p style="font-size:.8rem;margin-bottom:12px"><strong>' + done + '/' + LINDDUN_CATEGORIES.length + '</strong> categories assessed</p>' +
      LINDDUN_CATEGORIES.map(function(c) {
        var v = st[c.key] || {};
        return '<div class="arse-card" style="cursor:default;margin-bottom:12px">' +
          '<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">' +
            '<span style="min-width:28px;height:28px;display:inline-flex;align-items:center;justify-content:center;background:var(--acc);color:var(--on-acc,#fff);font-weight:800;border-radius:2px">' + esc(c.letter) + '</span>' +
            '<span style="font-weight:700">' + esc(c.name) + '</span>' +
            '<label style="margin-left:auto;display:flex;align-items:center;gap:6px;font-size:.75rem;cursor:pointer"><input type="checkbox" data-lassess="' + esc(c.key) + '"' + (v.assessed ? " checked" : "") + '> Assessed</label>' +
          '</div>' +
          '<div class="muted" style="font-size:.8rem;font-style:italic;margin:6px 0">' + esc(c.tagline) + '</div>' +
          '<details><summary style="cursor:pointer;font-size:.78rem;color:var(--acc)">Description, examples and mitigations</summary>' +
            '<p style="font-size:.8rem;line-height:1.6;margin:8px 0">' + esc(c.description) + '</p>' +
            '<div style="font-weight:600;font-size:.8rem">Examples</div><ul style="margin:4px 0 0 18px;font-size:.78rem;line-height:1.6">' + c.examples.map(function(x) { return '<li>' + esc(x) + '</li>'; }).join("") + '</ul>' +
            '<div style="font-weight:600;font-size:.8rem;margin-top:8px">Mitigations</div><ul style="margin:4px 0 0 18px;font-size:.78rem;line-height:1.6">' + c.mitigations.map(function(x) { return '<li>' + esc(x) + '</li>'; }).join("") + '</ul>' +
          '</details>' +
          '<textarea data-lnote="' + esc(c.key) + '" rows="2" placeholder="Where this applies, and how it is handled" style="' + tmInput + ';margin-top:8px;resize:vertical">' + esc(v.notes || "") + '</textarea>' +
        '</div>';
      }).join("");
  }
  paint();
  el.onchange = function(e) {
    var cb = e.target.closest("[data-lassess]"); if (!cb) return;
    var k = cb.dataset.lassess; st[k] = st[k] || {}; st[k].assessed = cb.checked; saveJSON("tm_linddun", st); paint();
  };
  el.oninput = function(e) {
    var ta = e.target.closest("[data-lnote]"); if (!ta) return;
    var k = ta.dataset.lnote; st[k] = st[k] || {}; st[k].notes = ta.value; saveJSON("tm_linddun", st);
  };
}

// ── Security Requirements Tab ──
function renderRequirements(el, showTab) {
  var g = generateRequirements();
  var csv = function() {
    var q = function(v) { return '"' + String(v).replace(/^(?=[=+@\t\r]|-(?!\d+(?:\.\d+)?$))/, "'").replace(/"/g, '""') + '"'; };
    return ["ID,Category,Requirement,Priority,Verification"].concat(g.reqs.map(function(r) { return [r.id, CAT_NAME[r.category], r.requirement, r.priority, r.verification].map(q).join(","); })).join("\n");
  };
  var th = 'style="text-align:left;padding:6px;border-bottom:1px solid var(--line)"', td = 'style="padding:6px;border-bottom:1px solid var(--line);vertical-align:top"';
  el.innerHTML =
    '<h2 class="pg-h2">Security requirements</h2>' +
    '<p class="muted" style="margin-bottom:16px">Concrete, testable requirements generated from the threats you ticked in the Threat Library, grouped by STRIDE category, each with a suggested verification method so it can be tracked through to acceptance testing.</p>' +
    (!g.threats.length ?
      '<div class="arse-card" style="cursor:default">No threats selected yet. Open the Threat Library, tick "Applies to my system" on the threats that are relevant, then come back here.<div style="margin-top:10px"><button class="btn" id="rq-goto">Open Threat Library</button></div></div>' :
      '<div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:12px;font-size:.82rem">' +
        '<span><strong>' + g.threats.length + '</strong> threats selected</span><span><strong>' + g.reqs.length + '</strong> requirements</span>' +
        '<span><strong>' + g.reqs.filter(function(r) { return r.priority === "Critical"; }).length + '</strong> critical</span><span><strong>' + g.reqs.filter(function(r) { return r.priority === "High"; }).length + '</strong> high</span>' +
      '</div>' +
      '<div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap"><button class="btn" id="rq-csv">Export CSV</button><button class="btn" id="rq-copy">Copy as Markdown</button><button class="btn" id="rq-clear">Clear selection</button></div>' +
      '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.78rem"><thead><tr><th ' + th + '>ID</th><th ' + th + '>Category</th><th ' + th + '>Requirement</th><th ' + th + '>Priority</th><th ' + th + '>Verification</th></tr></thead><tbody>' +
        g.reqs.map(function(r) { return '<tr><td ' + td + '><span style="font-family:var(--mono,monospace)">' + esc(r.id) + '</span></td><td ' + td + '>' + esc(CAT_NAME[r.category]) + '</td><td ' + td + '>' + esc(r.requirement) + '</td><td ' + td + '>' + esc(r.priority) + '</td><td ' + td + '>' + esc(r.verification) + '</td></tr>'; }).join("") +
      '</tbody></table></div>' +
      '<h3 style="font-size:.9rem;margin:16px 0 6px">Selected threats</h3>' +
      '<ul style="margin:0 0 0 18px;font-size:.78rem;line-height:1.6">' + g.threats.map(function(t) { return '<li><span style="font-family:var(--mono,monospace)">' + esc(t.id) + '</span> [' + t.stride + '] ' + esc(t.name) + (t.cwe ? ' (' + esc(t.cwe) + ')' : '') + '</li>'; }).join("") + '</ul>');
  var go = el.querySelector("#rq-goto"); if (go) go.onclick = function() { showTab("threats"); };
  var b = el.querySelector("#rq-csv");
  if (b) b.onclick = function() {
    var url = URL.createObjectURL(new Blob([csv()], { type: "text/csv" }));
    var a = document.createElement("a"); a.href = url; a.download = "security-requirements.csv"; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function() { URL.revokeObjectURL(url); }, 1000);
  };
  b = el.querySelector("#rq-copy");
  if (b) b.onclick = function() {
    var md = "| ID | Category | Requirement | Priority | Verification |\n|---|---|---|---|---|\n" + g.reqs.map(function(r) { return "| " + [r.id, CAT_NAME[r.category], r.requirement, r.priority, r.verification].join(" | ") + " |"; }).join("\n");
    navigator.clipboard.writeText(md).then(function() { el.querySelector("#rq-copy").textContent = "Copied"; setTimeout(function() { var x = el.querySelector("#rq-copy"); if (x) x.textContent = "Copy as Markdown"; }, 2000); }).catch(function() {});
  };
  b = el.querySelector("#rq-clear");
  if (b) b.onclick = function() { saveReqSelection({}); renderRequirements(el, showTab); };
}

// ── Report Tab ──
function renderReportTab(el) {
  var items = []; try { items = JSON.parse(localStorage.getItem(acctKey("tm_stride_items")) || "[]"); } catch (_) {}
  var assets = []; try { assets = JSON.parse(localStorage.getItem(acctKey("tm_assets")) || "[]"); } catch (_) {}
  var risks = []; try { risks = JSON.parse(localStorage.getItem(acctKey("tm_risk_items")) || "[]"); } catch (_) {}
  var tree = null; try { tree = JSON.parse(localStorage.getItem(acctKey("tm_attack_tree"))); } catch (_) {}

  var now = new Date().toISOString().split("T")[0];
  var report = "# Threat model report\n";
  report += "Generated: " + now + "\n\n";
  report += "## Assets (" + assets.length + ")\n";
  assets.forEach(function(a) { report += "- " + a.name + " [" + a.type + "] — " + a.classification + (a.desc ? ": " + a.desc : "") + "\n"; });
  report += "\n## STRIDE Analysis (" + items.length + " elements)\n";
  items.forEach(function(item) {
    report += "- " + item.name + " (" + item.type + "): " + (item.threats && item.threats.length ? item.threats.join(", ") : "No threats identified") + "\n";
  });
  report += "\n## Risk Items (" + risks.length + ")\n";
  risks.forEach(function(r) {
    var risk = Math.round((r.likelihood + r.impact) / 2);
    report += "- " + r.name + " — Likelihood: " + RISK_LEVELS[r.likelihood] + ", Impact: " + RISK_LEVELS[r.impact] + " → " + RISK_LEVELS[risk] + " risk\n";
  });
  var pasta = loadJSON("tm_pasta", {});
  var pastaRows = PASTA_STAGES.filter(function(s) { var v = pasta[s.stage]; return v && (v.done || (v.notes || "").trim()); });
  if (pastaRows.length) {
    report += "\n## PASTA (" + PASTA_STAGES.filter(function(s) { return pasta[s.stage] && pasta[s.stage].done; }).length + "/" + PASTA_STAGES.length + " stages complete)\n";
    pastaRows.forEach(function(s) { var v = pasta[s.stage]; report += "- Stage " + s.stage + " " + s.name + (v.done ? " [complete]" : "") + ((v.notes || "").trim() ? ": " + v.notes.trim() : "") + "\n"; });
  }
  var lind = loadJSON("tm_linddun", {});
  var lindRows = LINDDUN_CATEGORIES.filter(function(c) { var v = lind[c.key]; return v && (v.assessed || (v.notes || "").trim()); });
  if (lindRows.length) {
    report += "\n## LINDDUN Privacy (" + LINDDUN_CATEGORIES.filter(function(c) { return lind[c.key] && lind[c.key].assessed; }).length + "/" + LINDDUN_CATEGORIES.length + " assessed)\n";
    lindRows.forEach(function(c) { var v = lind[c.key]; report += "- " + c.name + (v.assessed ? " [assessed]" : "") + ((v.notes || "").trim() ? ": " + v.notes.trim() : "") + "\n"; });
  }
  var gen = generateRequirements();
  if (gen.threats.length) {
    report += "\n## Selected Threats (" + gen.threats.length + ")\n";
    gen.threats.forEach(function(t) { report += "- " + t.id + " [" + t.stride + "] " + t.name + " (" + t.severity + (t.cwe ? ", " + t.cwe : "") + ")\n"; });
    report += "\n## Security Requirements (" + gen.reqs.length + ")\n";
    gen.reqs.forEach(function(r) { report += "- " + r.id + " [" + r.priority + "] " + r.requirement + " Verify: " + r.verification + "\n"; });
  }
  if (tree && tree.children && tree.children.length) {
    report += "\n## Attack Tree: " + tree.name + "\n";
    function printTree(node, indent) {
      report += indent + (node.children && node.children.length ? "[" + node.gate + "] " : "- ") + node.name + "\n";
      if (node.children) node.children.forEach(function(c) { printTree(c, indent + "  "); });
    }
    printTree(tree, "");
  }

  el.innerHTML =
    '<h2 class="pg-h2">Threat model report</h2>' +
    '<p class="muted" style="margin-bottom:16px">Auto-generated report from your threat modeling data. Copy and save as needed.</p>' +
    '<div style="display:flex;gap:8px;margin-bottom:12px">' +
      '<button class="btn" id="tm-copy">Copy to Clipboard</button>' +
    '</div>' +
    '<pre style="background:var(--card);border:1px solid var(--line);padding:16px;font-size:.78rem;white-space:pre-wrap;overflow-x:auto;max-height:500px;overflow-y:auto;border-radius:2px;color:var(--txt)">' + esc(report) + '</pre>';

  el.querySelector("#tm-copy").onclick = function() {
    navigator.clipboard.writeText(report).then(function() {
      el.querySelector("#tm-copy").textContent = "Copied!";
      setTimeout(function() { el.querySelector("#tm-copy").textContent = "Copy to Clipboard"; }, 2000);
    });
  };
}
