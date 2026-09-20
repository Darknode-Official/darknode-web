// Incident Tracker — security incident management dashboard with localStorage persistence
const esc = (s) => String(s != null ? s : "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

// ── Constants ──
const SEVERITIES = ["P1 — Critical", "P2 — High", "P3 — Medium", "P4 — Low"];
const SEV_COLORS = { "P1 — Critical": "#b71c1c", "P2 — High": "#f44336", "P3 — Medium": "#ff9800", "P4 — Low": "#4caf50" };
const STATUSES = ["New", "Triage", "Investigating", "Contained", "Eradicated", "Recovered", "Closed"];
const STATUS_COLORS = { New: "#2196f3", Triage: "#9c27b0", Investigating: "#ff9800", Contained: "#f44336", Eradicated: "#e91e63", Recovered: "#4caf50", Closed: "#607d8b" };
const TYPES = ["Malware", "Phishing", "Data Breach", "DDoS", "Insider Threat", "Unauthorized Access", "Ransomware", "Web Defacement", "Credential Theft", "Supply Chain", "Cryptomining", "APT Intrusion", "BEC", "DNS Hijacking", "Zero-Day", "Lateral Movement", "Other"];

const MITRE_TACTICS = [
  "TA0001 Initial Access", "TA0002 Execution", "TA0003 Persistence", "TA0004 Privilege Escalation",
  "TA0005 Defense Evasion", "TA0006 Credential Access", "TA0007 Discovery", "TA0008 Lateral Movement",
  "TA0009 Collection", "TA0010 Exfiltration", "TA0011 Command and Control", "TA0040 Impact",
  "TA0042 Resource Development", "TA0043 Reconnaissance"
];

const PLAYBOOK_MAP = {
  "Malware": { name: "Malware Incident Response", steps: ["Isolate affected systems from network", "Identify malware family and behavior (static + dynamic analysis)", "Determine infection vector (email, web, USB, lateral movement)", "Scan all systems for IOCs (hashes, C2 domains, registry keys)", "Remove malware and persistence mechanisms", "Patch vulnerability used for initial access", "Monitor for re-infection", "Update detection rules (YARA, Sigma, EDR)"] },
  "Phishing": { name: "Phishing Response", steps: ["Identify all recipients of the phishing email", "Block sender domain/IP at email gateway", "Remove phishing emails from all mailboxes", "Identify who clicked links or opened attachments", "Reset credentials for compromised accounts", "Scan endpoints of affected users for malware", "Report phishing domain for takedown", "Update email filtering rules", "Send awareness notification to organization"] },
  "Data Breach": { name: "Data Breach Response", steps: ["Identify scope: what data, how much, how many affected", "Stop the breach — patch vulnerability, revoke access", "Preserve evidence (forensic images, logs)", "Assess regulatory obligations (GDPR 72hr, HIPAA, PCI)", "Notify legal and compliance teams", "Prepare customer notification", "Engage PR/communications team", "Offer credit monitoring if PII exposed", "Conduct root cause analysis"] },
  "DDoS": { name: "DDoS Response", steps: ["Activate DDoS mitigation service (CDN/scrubbing)", "Identify attack type (volumetric, application-layer, protocol)", "Implement rate limiting and geo-blocking", "Scale infrastructure if possible", "Enable WAF rules for application-layer attacks", "Monitor for secondary attacks (DDoS as distraction)", "Document attack patterns for future defense", "Update incident communication to stakeholders"] },
  "Ransomware": { name: "Ransomware Response", steps: ["Immediately isolate infected systems (disconnect network)", "DO NOT pay ransom (in most cases)", "Identify ransomware variant (ID Ransomware)", "Check for available decryptors (No More Ransom project)", "Determine encryption scope (local, network shares, backups)", "Preserve encrypted files and ransom notes as evidence", "Restore from clean, verified backups", "Patch vulnerability used for initial access", "Reset all credentials in affected domain", "Report to law enforcement (FBI IC3, local CERT)"] },
  "Insider Threat": { name: "Insider Threat Response", steps: ["Coordinate with HR and Legal before technical actions", "Preserve evidence without alerting the subject", "Review access logs and data movement patterns", "Analyze DLP alerts and file access history", "Document chain of custody for all evidence", "Revoke access when authorized by HR/Legal", "Forensic analysis of endpoint", "Assess data exposure and regulatory impact", "Update access controls and monitoring"] },
  "Unauthorized Access": { name: "Unauthorized Access Response", steps: ["Identify compromised accounts and access scope", "Reset credentials immediately", "Review authentication logs for persistence", "Check for backdoors, new accounts, SSH keys", "Revoke active sessions and tokens", "Audit privilege escalation paths used", "Update firewall rules and access controls", "Enable MFA on all affected accounts", "Monitor for continued unauthorized access"] },
  "Credential Theft": { name: "Credential Theft Response", steps: ["Identify stolen credentials and affected accounts", "Force password reset for all compromised accounts", "Revoke all active sessions and OAuth tokens", "Check for credential reuse across systems", "Investigate method of theft (keylogger, phishing, breach, Mimikatz)", "Scan for credential dumping tools on endpoints", "Enable MFA on affected accounts", "Review authentication logs for unauthorized use", "Rotate service account credentials and API keys"] },
  "APT Intrusion": { name: "APT Response", steps: ["Do NOT tip off the adversary — coordinate response carefully", "Engage specialized IR team or external IR firm", "Identify all compromised systems (assume widespread)", "Map adversary TTPs to MITRE ATT&CK framework", "Collect forensic evidence (memory, disk, network)", "Identify persistence mechanisms (scheduled tasks, services, registry)", "Develop and execute remediation plan (simultaneous eviction)", "Reset ALL credentials in the environment", "Rebuild compromised systems from clean images", "Implement enhanced monitoring for adversary return", "Report to government CERT and sector ISAC"] },
};

// ── Storage helpers ──
function loadIncidents() { try { return JSON.parse(localStorage.getItem("ir_incidents") || "[]"); } catch (_) { return []; } }
function saveIncidents(list) { try { localStorage.setItem("ir_incidents", JSON.stringify(list)); } catch (_) {} }
function loadIOCs() { try { return JSON.parse(localStorage.getItem("ir_iocs") || "[]"); } catch (_) { return []; } }
function saveIOCs(list) { try { localStorage.setItem("ir_iocs", JSON.stringify(list)); } catch (_) {} }

// ── Main Render ──
export function renderIncidentTracker(main) {
  var tabs = [
    { id: "list", label: "Incidents" },
    { id: "create", label: "New Incident" },
    { id: "iocs", label: "IOC Tracker" },
    { id: "mitre", label: "ATT&CK Map" },
    { id: "playbooks", label: "Playbooks" },
    { id: "metrics", label: "Metrics" },
    { id: "lessons", label: "Lessons Learned" },
  ];

  var tabBtns = tabs.map(function(t) {
    return '<button class="chip' + (t.id === "list" ? " on" : "") + '" data-tab="' + t.id + '">' + esc(t.label) + '</button>';
  }).join("");

  main.innerHTML =
    '<h1 class="pg-h1">Incident Tracker</h1>' +
    '<p class="muted pg-sub">Security incident management — track incidents, IOCs, map to MITRE ATT&CK, and run playbooks. All data stays in your browser.</p>' +
    '<div class="cs-filter" id="ir-tabs">' + tabBtns + '</div>' +
    '<div id="ir-content" style="margin-top:16px"></div>';

  var content = main.querySelector("#ir-content");
  var curTab = "list";

  function showTab(id) {
    curTab = id;
    main.querySelectorAll("#ir-tabs .chip").forEach(function(b) { b.classList.toggle("on", b.dataset.tab === id); });
    if (id === "list") renderList(content);
    else if (id === "create") renderCreate(content);
    else if (id === "iocs") renderIOCs(content);
    else if (id === "mitre") renderMitre(content);
    else if (id === "playbooks") renderPlaybooks(content);
    else if (id === "metrics") renderMetrics(content);
    else if (id === "lessons") renderLessons(content);
  }

  main.querySelector("#ir-tabs").onclick = function(e) {
    var b = e.target.closest(".chip");
    if (b) showTab(b.dataset.tab);
  };

  showTab("list");
}

// ── Incident List Tab ──
function renderList(el) {
  var incidents = loadIncidents();

  var filterHTML =
    '<div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap">' +
      '<select id="il-sev" style="padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px"><option value="">All Severities</option>' + SEVERITIES.map(function(s) { return '<option>' + esc(s) + '</option>'; }).join("") + '</select>' +
      '<select id="il-status" style="padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px"><option value="">All Statuses</option>' + STATUSES.map(function(s) { return '<option>' + esc(s) + '</option>'; }).join("") + '</select>' +
      '<select id="il-type" style="padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px"><option value="">All Types</option>' + TYPES.map(function(t) { return '<option>' + esc(t) + '</option>'; }).join("") + '</select>' +
      '<input id="il-search" placeholder="Search..." style="flex:1;min-width:150px;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
    '</div>';

  el.innerHTML =
    '<h2 class="pg-h2">Incidents <span style="color:var(--mut);font-weight:400">(' + incidents.length + ')</span></h2>' +
    filterHTML +
    '<div id="il-list"></div>';

  function renderFiltered() {
    var sev = el.querySelector("#il-sev").value;
    var status = el.querySelector("#il-status").value;
    var type = el.querySelector("#il-type").value;
    var search = (el.querySelector("#il-search").value || "").toLowerCase();
    var filtered = incidents.filter(function(inc) {
      if (sev && inc.severity !== sev) return false;
      if (status && inc.status !== status) return false;
      if (type && inc.type !== type) return false;
      if (search && inc.title.toLowerCase().indexOf(search) < 0 && (inc.description || "").toLowerCase().indexOf(search) < 0) return false;
      return true;
    });
    if (!filtered.length) { el.querySelector("#il-list").innerHTML = '<p class="muted">No incidents match the current filters.</p>'; return; }
    var cards = filtered.map(function(inc, idx) {
      var realIdx = incidents.indexOf(inc);
      return '<div class="arse-card" style="cursor:default;margin-bottom:8px">' +
        '<div style="display:flex;align-items:center;gap:8px">' +
          '<span style="color:' + (SEV_COLORS[inc.severity] || "var(--mut)") + ';font-weight:700;font-size:.8rem;min-width:28px">' + esc(inc.severity.split(" ")[0]) + '</span>' +
          '<span style="font-weight:600;font-size:.9rem;flex:1">' + esc(inc.title) + '</span>' +
          '<span style="padding:2px 8px;border-radius:2px;font-size:.7rem;font-weight:600;color:#fff;background:' + (STATUS_COLORS[inc.status] || "var(--mut)") + '">' + esc(inc.status) + '</span>' +
          '<span style="font-size:.72rem;color:var(--mut)">' + esc(inc.type) + '</span>' +
        '</div>' +
        (inc.description ? '<div class="muted" style="font-size:.78rem;margin-top:4px;padding-left:36px">' + esc(inc.description.substring(0, 150)) + (inc.description.length > 150 ? "..." : "") + '</div>' : '') +
        '<div style="display:flex;gap:8px;margin-top:6px;padding-left:36px">' +
          '<span class="muted" style="font-size:.7rem">Created: ' + esc(new Date(inc.created).toLocaleDateString()) + '</span>' +
          (inc.affected ? '<span class="muted" style="font-size:.7rem">Affected: ' + esc(inc.affected) + '</span>' : '') +
          '<span style="margin-left:auto;display:flex;gap:4px">' +
            '<select data-sidx="' + realIdx + '" class="il-status-sel" style="padding:2px 4px;font-size:.7rem;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
              STATUSES.map(function(s) { return '<option' + (s === inc.status ? ' selected' : '') + '>' + esc(s) + '</option>'; }).join("") +
            '</select>' +
            '<button class="btn" data-idel="' + realIdx + '" style="padding:1px 6px;font-size:.68rem;background:#f44336">Delete</button>' +
          '</span>' +
        '</div>' +
        (inc.evidence && inc.evidence.length ? '<div style="padding-left:36px;margin-top:6px"><span style="font-size:.72rem;font-weight:600;color:var(--acc)">Evidence (' + inc.evidence.length + '):</span>' + inc.evidence.map(function(e) { return '<div style="font-size:.72rem;color:var(--mut);padding:1px 0">• ' + esc(e) + '</div>'; }).join("") + '</div>' : '') +
        (inc.mitre && inc.mitre.length ? '<div style="padding-left:36px;margin-top:4px;display:flex;gap:4px;flex-wrap:wrap">' + inc.mitre.map(function(t) { return '<span style="padding:1px 6px;background:var(--bg);border:1px solid var(--line);border-radius:2px;font-size:.68rem;font-family:var(--mono,monospace)">' + esc(t) + '</span>'; }).join("") + '</div>' : '') +
        '<div style="padding-left:36px;margin-top:6px;display:flex;gap:4px">' +
          '<input class="ev-input" data-evidx="' + realIdx + '" placeholder="Add evidence note..." style="flex:1;padding:3px 8px;font-size:.72rem;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
          '<button class="btn ev-add" data-evidx="' + realIdx + '" style="padding:2px 8px;font-size:.68rem">Add</button>' +
        '</div>' +
      '</div>';
    }).join("");
    el.querySelector("#il-list").innerHTML = cards;
  }
  renderFiltered();

  el.querySelector("#il-sev").onchange = renderFiltered;
  el.querySelector("#il-status").onchange = renderFiltered;
  el.querySelector("#il-type").onchange = renderFiltered;
  el.querySelector("#il-search").oninput = renderFiltered;

  el.querySelector("#il-list").onclick = function(e) {
    if (e.target.dataset.idel !== undefined) {
      incidents.splice(parseInt(e.target.dataset.idel), 1);
      saveIncidents(incidents);
      renderFiltered();
    }
    if (e.target.classList.contains("ev-add")) {
      var idx = parseInt(e.target.dataset.evidx);
      var input = el.querySelector('input.ev-input[data-evidx="' + idx + '"]');
      var val = input.value.trim();
      if (!val) return;
      if (!incidents[idx].evidence) incidents[idx].evidence = [];
      incidents[idx].evidence.push(val);
      saveIncidents(incidents);
      input.value = "";
      renderFiltered();
    }
  };
  el.querySelector("#il-list").onchange = function(e) {
    if (e.target.classList.contains("il-status-sel")) {
      var idx = parseInt(e.target.dataset.sidx);
      incidents[idx].status = e.target.value;
      if (e.target.value === "Closed" && !incidents[idx].closedAt) incidents[idx].closedAt = new Date().toISOString();
      saveIncidents(incidents);
      renderFiltered();
    }
  };
}

// ── Create Incident Tab ──
function renderCreate(el) {
  el.innerHTML =
    '<h2 class="pg-h2">Create New Incident</h2>' +
    '<div class="arse-card" style="cursor:default;padding:16px">' +
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">' +
        '<div><label style="font-size:.78rem;font-weight:600;display:block;margin-bottom:4px">Title *</label>' +
          '<input id="ic-title" style="width:100%;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px" placeholder="Incident title"></div>' +
        '<div><label style="font-size:.78rem;font-weight:600;display:block;margin-bottom:4px">Severity *</label>' +
          '<select id="ic-sev" style="width:100%;padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' + SEVERITIES.map(function(s) { return '<option>' + esc(s) + '</option>'; }).join("") + '</select></div>' +
        '<div><label style="font-size:.78rem;font-weight:600;display:block;margin-bottom:4px">Type *</label>' +
          '<select id="ic-type" style="width:100%;padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' + TYPES.map(function(t) { return '<option>' + esc(t) + '</option>'; }).join("") + '</select></div>' +
        '<div><label style="font-size:.78rem;font-weight:600;display:block;margin-bottom:4px">Affected Systems</label>' +
          '<input id="ic-affected" style="width:100%;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px" placeholder="e.g., web-prod-01, db-cluster"></div>' +
      '</div>' +
      '<label style="font-size:.78rem;font-weight:600;display:block;margin:12px 0 4px">Description</label>' +
      '<textarea id="ic-desc" rows="4" style="width:100%;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px;resize:vertical" placeholder="Describe the incident..."></textarea>' +
      '<label style="font-size:.78rem;font-weight:600;display:block;margin:12px 0 4px">MITRE ATT&CK Techniques</label>' +
      '<div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:12px">' +
        MITRE_TACTICS.map(function(t) {
          return '<label style="display:inline-flex;align-items:center;gap:3px;padding:2px 6px;background:var(--bg);border:1px solid var(--line);border-radius:2px;font-size:.7rem;cursor:pointer"><input type="checkbox" value="' + esc(t) + '" class="ic-mitre" style="width:12px;height:12px">' + esc(t) + '</label>';
        }).join("") +
      '</div>' +
      '<button class="btn" id="ic-submit" style="padding:8px 24px">Create Incident</button>' +
      '<span id="ic-msg" style="margin-left:12px;font-size:.82rem;color:#4caf50"></span>' +
    '</div>';

  el.querySelector("#ic-submit").onclick = function() {
    var title = el.querySelector("#ic-title").value.trim();
    if (!title) { el.querySelector("#ic-msg").textContent = "Title is required."; el.querySelector("#ic-msg").style.color = "#f44336"; return; }
    var mitre = [];
    el.querySelectorAll(".ic-mitre:checked").forEach(function(cb) { mitre.push(cb.value); });
    var incident = {
      id: "INC-" + Date.now().toString(36).toUpperCase(),
      title: title,
      severity: el.querySelector("#ic-sev").value,
      type: el.querySelector("#ic-type").value,
      affected: el.querySelector("#ic-affected").value.trim(),
      description: el.querySelector("#ic-desc").value.trim(),
      status: "New",
      mitre: mitre,
      evidence: [],
      comms: [],
      created: new Date().toISOString(),
      closedAt: null
    };
    var incidents = loadIncidents();
    incidents.unshift(incident);
    saveIncidents(incidents);
    el.querySelector("#ic-msg").textContent = "Incident " + incident.id + " created.";
    el.querySelector("#ic-msg").style.color = "#4caf50";
    el.querySelector("#ic-title").value = "";
    el.querySelector("#ic-desc").value = "";
    el.querySelector("#ic-affected").value = "";
    el.querySelectorAll(".ic-mitre:checked").forEach(function(cb) { cb.checked = false; });
  };
}

// ── IOC Tracker Tab ──
function renderIOCs(el) {
  var iocs = loadIOCs();
  var iocTypes = ["IP Address", "Domain", "URL", "File Hash (MD5)", "File Hash (SHA-1)", "File Hash (SHA-256)", "Email Address", "Registry Key", "Mutex", "User Agent", "File Path", "Certificate Hash"];
  var verdicts = ["Malicious", "Suspicious", "Benign", "Unknown"];
  var verdictColors = { Malicious: "#f44336", Suspicious: "#ff9800", Benign: "#4caf50", Unknown: "var(--mut)" };

  el.innerHTML =
    '<h2 class="pg-h2">IOC Tracker</h2>' +
    '<p class="muted" style="margin-bottom:16px">Track Indicators of Compromise. ' + iocs.length + ' IOCs tracked.</p>' +
    '<div class="arse-card" style="cursor:default;padding:16px;margin-bottom:16px">' +
      '<div style="display:flex;gap:8px;flex-wrap:wrap">' +
        '<select id="ioc-type" style="padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' + iocTypes.map(function(t) { return '<option>' + esc(t) + '</option>'; }).join("") + '</select>' +
        '<input id="ioc-val" placeholder="IOC value" style="flex:1;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px;font-family:var(--mono,monospace)">' +
        '<select id="ioc-verdict" style="padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' + verdicts.map(function(v) { return '<option>' + esc(v) + '</option>'; }).join("") + '</select>' +
        '<input id="ioc-note" placeholder="Note (optional)" style="width:200px;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
        '<button class="btn" id="ioc-add" style="padding:6px 16px">Add IOC</button>' +
      '</div>' +
    '</div>' +
    '<div style="display:flex;gap:8px;margin-bottom:12px">' +
      '<select id="ioc-ftype" style="padding:4px;font-size:.8rem;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px"><option value="">All Types</option>' + iocTypes.map(function(t) { return '<option>' + esc(t) + '</option>'; }).join("") + '</select>' +
      '<select id="ioc-fverdict" style="padding:4px;font-size:.8rem;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px"><option value="">All Verdicts</option>' + verdicts.map(function(v) { return '<option>' + esc(v) + '</option>'; }).join("") + '</select>' +
      '<input id="ioc-search" placeholder="Search IOCs..." style="flex:1;padding:4px 8px;font-size:.8rem;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
      '<button class="btn" id="ioc-export" style="padding:4px 12px;font-size:.8rem">Copy CSV</button>' +
    '</div>' +
    '<div id="ioc-list"></div>';

  function renderIOCList() {
    var ft = el.querySelector("#ioc-ftype").value;
    var fv = el.querySelector("#ioc-fverdict").value;
    var fs = (el.querySelector("#ioc-search").value || "").toLowerCase();
    var filtered = iocs.filter(function(i) {
      if (ft && i.type !== ft) return false;
      if (fv && i.verdict !== fv) return false;
      if (fs && i.value.toLowerCase().indexOf(fs) < 0 && (i.note || "").toLowerCase().indexOf(fs) < 0) return false;
      return true;
    });
    if (!filtered.length) { el.querySelector("#ioc-list").innerHTML = '<p class="muted">No IOCs match.</p>'; return; }
    var rows = filtered.map(function(i, idx) {
      var realIdx = iocs.indexOf(i);
      return '<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--line);font-size:.8rem">' +
        '<span style="width:6px;height:6px;border-radius:50%;background:' + (verdictColors[i.verdict] || "var(--mut)") + ';flex-shrink:0"></span>' +
        '<span style="min-width:100px;color:var(--mut);font-size:.72rem">' + esc(i.type) + '</span>' +
        '<code style="flex:1;font-family:var(--mono,monospace);word-break:break-all">' + esc(i.value) + '</code>' +
        '<span style="color:' + (verdictColors[i.verdict] || "var(--mut)") + ';font-size:.72rem;font-weight:600;min-width:70px">' + esc(i.verdict) + '</span>' +
        (i.note ? '<span class="muted" style="font-size:.7rem;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(i.note) + '</span>' : '') +
        '<button class="btn" data-iocdel="' + realIdx + '" style="padding:1px 6px;font-size:.68rem;background:#f44336">x</button>' +
      '</div>';
    }).join("");
    el.querySelector("#ioc-list").innerHTML = rows;
  }
  renderIOCList();

  el.querySelector("#ioc-add").onclick = function() {
    var val = el.querySelector("#ioc-val").value.trim();
    if (!val) return;
    iocs.push({ type: el.querySelector("#ioc-type").value, value: val, verdict: el.querySelector("#ioc-verdict").value, note: el.querySelector("#ioc-note").value.trim(), added: new Date().toISOString() });
    saveIOCs(iocs);
    el.querySelector("#ioc-val").value = "";
    el.querySelector("#ioc-note").value = "";
    renderIOCList();
  };
  el.querySelector("#ioc-ftype").onchange = renderIOCList;
  el.querySelector("#ioc-fverdict").onchange = renderIOCList;
  el.querySelector("#ioc-search").oninput = renderIOCList;
  el.querySelector("#ioc-list").onclick = function(e) {
    if (e.target.dataset.iocdel !== undefined) {
      iocs.splice(parseInt(e.target.dataset.iocdel), 1);
      saveIOCs(iocs);
      renderIOCList();
    }
  };
  el.querySelector("#ioc-export").onclick = function() {
    var csv = "Type,Value,Verdict,Note,Added\n" + iocs.map(function(i) {
      return [i.type, i.value, i.verdict, i.note || "", i.added].map(function(f) { return '"' + String(f).replace(/"/g, '""') + '"'; }).join(",");
    }).join("\n");
    navigator.clipboard.writeText(csv).then(function() {
      el.querySelector("#ioc-export").textContent = "Copied!";
      setTimeout(function() { el.querySelector("#ioc-export").textContent = "Copy CSV"; }, 2000);
    });
  };
}

// ── MITRE ATT&CK Map Tab ──
function renderMitre(el) {
  var incidents = loadIncidents();
  var coverage = {};
  incidents.forEach(function(inc) {
    if (inc.mitre) inc.mitre.forEach(function(t) {
      if (!coverage[t]) coverage[t] = [];
      coverage[t].push(inc.title);
    });
  });

  var cards = MITRE_TACTICS.map(function(tactic) {
    var count = coverage[tactic] ? coverage[tactic].length : 0;
    var incidents_list = coverage[tactic] ? coverage[tactic].map(function(t) { return '<div style="font-size:.72rem;color:var(--mut);padding:1px 0">• ' + esc(t) + '</div>'; }).join("") : '<div style="font-size:.72rem;color:var(--mut)">No incidents mapped</div>';
    var bgIntensity = count === 0 ? "00" : count < 3 ? "20" : count < 5 ? "40" : "60";
    return '<div class="arse-card" style="cursor:default;margin-bottom:6px;border-left:4px solid ' + (count > 0 ? "var(--acc)" : "var(--line)") + '">' +
      '<div style="display:flex;justify-content:space-between;align-items:center">' +
        '<span style="font-weight:600;font-size:.82rem">' + esc(tactic) + '</span>' +
        '<span style="padding:2px 8px;border-radius:2px;font-size:.72rem;font-weight:700;background:var(--acc)' + bgIntensity + ';color:' + (count > 0 ? "var(--acc)" : "var(--mut)") + '">' + count + '</span>' +
      '</div>' +
      (count > 0 ? '<div style="margin-top:6px">' + incidents_list + '</div>' : '') +
    '</div>';
  }).join("");

  el.innerHTML =
    '<h2 class="pg-h2">MITRE ATT&CK Coverage Map</h2>' +
    '<p class="muted" style="margin-bottom:16px">Shows which ATT&CK tactics have been observed across your tracked incidents.</p>' +
    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">' + cards + '</div>';
}

// ── Playbooks Tab ──
function renderPlaybooks(el) {
  var types = Object.keys(PLAYBOOK_MAP);
  var cards = types.map(function(type) {
    var pb = PLAYBOOK_MAP[type];
    var steps = pb.steps.map(function(s, i) {
      return '<div style="display:flex;gap:8px;padding:4px 0;border-bottom:1px solid var(--line)">' +
        '<span style="min-width:20px;font-weight:700;color:var(--acc);font-size:.82rem">' + (i + 1) + '</span>' +
        '<span style="font-size:.82rem">' + esc(s) + '</span>' +
      '</div>';
    }).join("");
    return '<div class="arse-card" style="cursor:default;margin-bottom:12px">' +
      '<div class="an">' + esc(pb.name) + ' <span style="color:var(--mut);font-size:.75rem">(' + pb.steps.length + ' steps)</span></div>' +
      '<div style="margin-top:8px">' + steps + '</div>' +
    '</div>';
  }).join("");

  el.innerHTML =
    '<h2 class="pg-h2">Incident Response Playbooks</h2>' +
    '<p class="muted" style="margin-bottom:16px">' + types.length + ' playbooks for common incident types. Each provides step-by-step response guidance.</p>' + cards;
}

// ── Metrics Tab ──
function renderMetrics(el) {
  var incidents = loadIncidents();
  var total = incidents.length;
  var open = incidents.filter(function(i) { return i.status !== "Closed"; }).length;
  var closed = total - open;

  var bySev = {};
  SEVERITIES.forEach(function(s) { bySev[s] = 0; });
  incidents.forEach(function(i) { if (bySev[i.severity] !== undefined) bySev[i.severity]++; });

  var byType = {};
  incidents.forEach(function(i) { byType[i.type] = (byType[i.type] || 0) + 1; });

  var byStatus = {};
  STATUSES.forEach(function(s) { byStatus[s] = 0; });
  incidents.forEach(function(i) { if (byStatus[i.status] !== undefined) byStatus[i.status]++; });

  // MTTD/MTTR (simulated — based on created to closed)
  var closedIncs = incidents.filter(function(i) { return i.closedAt; });
  var avgResolveHrs = 0;
  if (closedIncs.length) {
    var totalHrs = closedIncs.reduce(function(a, i) {
      return a + (new Date(i.closedAt) - new Date(i.created)) / (1000 * 60 * 60);
    }, 0);
    avgResolveHrs = (totalHrs / closedIncs.length).toFixed(1);
  }

  var statsHTML =
    '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px">' +
      '<div class="arse-card" style="cursor:default;text-align:center;padding:16px">' +
        '<div style="font-size:2rem;font-weight:800;color:var(--acc)">' + total + '</div><div class="muted" style="font-size:.78rem">Total Incidents</div>' +
      '</div>' +
      '<div class="arse-card" style="cursor:default;text-align:center;padding:16px">' +
        '<div style="font-size:2rem;font-weight:800;color:#f44336">' + open + '</div><div class="muted" style="font-size:.78rem">Open</div>' +
      '</div>' +
      '<div class="arse-card" style="cursor:default;text-align:center;padding:16px">' +
        '<div style="font-size:2rem;font-weight:800;color:#4caf50">' + closed + '</div><div class="muted" style="font-size:.78rem">Closed</div>' +
      '</div>' +
      '<div class="arse-card" style="cursor:default;text-align:center;padding:16px">' +
        '<div style="font-size:2rem;font-weight:800;color:var(--txt)">' + avgResolveHrs + 'h</div><div class="muted" style="font-size:.78rem">Avg MTTR</div>' +
      '</div>' +
    '</div>';

  var sevBars = SEVERITIES.map(function(s) {
    var count = bySev[s] || 0;
    var pct = total ? Math.round(count / total * 100) : 0;
    return '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">' +
      '<span style="min-width:100px;font-size:.78rem;color:' + (SEV_COLORS[s] || "var(--mut)") + '">' + esc(s.split(" — ")[1]) + '</span>' +
      '<div style="flex:1;background:var(--bg);border-radius:2px;height:18px;overflow:hidden"><div style="height:100%;width:' + pct + '%;background:' + (SEV_COLORS[s] || "var(--line)") + '30;min-width:' + (count > 0 ? "2px" : "0") + '"></div></div>' +
      '<span style="min-width:30px;text-align:right;font-size:.78rem;font-weight:600">' + count + '</span>' +
    '</div>';
  }).join("");

  var typeBars = Object.keys(byType).sort(function(a, b) { return byType[b] - byType[a]; }).map(function(t) {
    var count = byType[t];
    var pct = total ? Math.round(count / total * 100) : 0;
    return '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">' +
      '<span style="min-width:140px;font-size:.78rem;color:var(--mut)">' + esc(t) + '</span>' +
      '<div style="flex:1;background:var(--bg);border-radius:2px;height:18px;overflow:hidden"><div style="height:100%;width:' + pct + '%;background:var(--acc)30"></div></div>' +
      '<span style="min-width:30px;text-align:right;font-size:.78rem;font-weight:600">' + count + '</span>' +
    '</div>';
  }).join("");

  var statusBars = STATUSES.map(function(s) {
    var count = byStatus[s] || 0;
    return '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">' +
      '<span style="min-width:100px;font-size:.78rem;color:' + (STATUS_COLORS[s] || "var(--mut)") + '">' + esc(s) + '</span>' +
      '<span style="font-size:.78rem;font-weight:600">' + count + '</span>' +
    '</div>';
  }).join("");

  el.innerHTML =
    '<h2 class="pg-h2">Incident Metrics</h2>' +
    statsHTML +
    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">' +
      '<div class="arse-card" style="cursor:default;padding:16px"><h3 style="margin:0 0 12px;font-size:.9rem">By Severity</h3>' + (sevBars || '<p class="muted">No data</p>') + '</div>' +
      '<div class="arse-card" style="cursor:default;padding:16px"><h3 style="margin:0 0 12px;font-size:.9rem">By Status</h3>' + (statusBars || '<p class="muted">No data</p>') + '</div>' +
    '</div>' +
    '<div class="arse-card" style="cursor:default;padding:16px;margin-top:12px"><h3 style="margin:0 0 12px;font-size:.9rem">By Type</h3>' + (typeBars || '<p class="muted">No data</p>') + '</div>';
}

// ── Lessons Learned Tab ──
function renderLessons(el) {
  var lessons = [];
  try { lessons = JSON.parse(localStorage.getItem("ir_lessons") || "[]"); } catch (_) {}

  el.innerHTML =
    '<h2 class="pg-h2">Lessons Learned</h2>' +
    '<p class="muted" style="margin-bottom:16px">Document post-incident findings to improve future response.</p>' +
    '<div class="arse-card" style="cursor:default;padding:16px;margin-bottom:16px">' +
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px">' +
        '<input id="ll-incident" placeholder="Incident title / ID" style="padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
        '<input id="ll-date" type="date" style="padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
      '</div>' +
      '<textarea id="ll-what" rows="2" placeholder="What happened?" style="width:100%;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px;resize:vertical;margin-bottom:6px"></textarea>' +
      '<textarea id="ll-root" rows="2" placeholder="Root cause?" style="width:100%;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px;resize:vertical;margin-bottom:6px"></textarea>' +
      '<textarea id="ll-worked" rows="2" placeholder="What worked well?" style="width:100%;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px;resize:vertical;margin-bottom:6px"></textarea>' +
      '<textarea id="ll-improve" rows="2" placeholder="What to improve?" style="width:100%;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px;resize:vertical;margin-bottom:6px"></textarea>' +
      '<textarea id="ll-actions" rows="2" placeholder="Action items" style="width:100%;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px;resize:vertical;margin-bottom:8px"></textarea>' +
      '<button class="btn" id="ll-save" style="padding:6px 16px">Save Lesson</button>' +
    '</div>' +
    '<div id="ll-list"></div>';

  function renderLessonList() {
    if (!lessons.length) { el.querySelector("#ll-list").innerHTML = '<p class="muted">No lessons documented yet.</p>'; return; }
    var cards = lessons.map(function(l, i) {
      return '<div class="arse-card" style="cursor:default;margin-bottom:8px">' +
        '<div style="display:flex;justify-content:space-between;align-items:center">' +
          '<span style="font-weight:600">' + esc(l.incident) + '</span>' +
          '<span style="display:flex;gap:8px;align-items:center"><span class="muted" style="font-size:.72rem">' + esc(l.date) + '</span>' +
          '<button class="btn" data-lldel="' + i + '" style="padding:1px 6px;font-size:.68rem;background:#f44336">x</button></span>' +
        '</div>' +
        (l.what ? '<div style="margin-top:6px;font-size:.82rem"><strong>What happened:</strong> ' + esc(l.what) + '</div>' : '') +
        (l.root ? '<div style="margin-top:4px;font-size:.82rem"><strong>Root cause:</strong> ' + esc(l.root) + '</div>' : '') +
        (l.worked ? '<div style="margin-top:4px;font-size:.82rem;color:#4caf50"><strong>Worked well:</strong> ' + esc(l.worked) + '</div>' : '') +
        (l.improve ? '<div style="margin-top:4px;font-size:.82rem;color:#ff9800"><strong>To improve:</strong> ' + esc(l.improve) + '</div>' : '') +
        (l.actions ? '<div style="margin-top:4px;font-size:.82rem;color:var(--acc)"><strong>Action items:</strong> ' + esc(l.actions) + '</div>' : '') +
      '</div>';
    }).join("");
    el.querySelector("#ll-list").innerHTML = cards;
  }
  renderLessonList();

  el.querySelector("#ll-save").onclick = function() {
    var incident = el.querySelector("#ll-incident").value.trim();
    if (!incident) return;
    lessons.push({
      incident: incident,
      date: el.querySelector("#ll-date").value || new Date().toISOString().split("T")[0],
      what: el.querySelector("#ll-what").value.trim(),
      root: el.querySelector("#ll-root").value.trim(),
      worked: el.querySelector("#ll-worked").value.trim(),
      improve: el.querySelector("#ll-improve").value.trim(),
      actions: el.querySelector("#ll-actions").value.trim()
    });
    try { localStorage.setItem("ir_lessons", JSON.stringify(lessons)); } catch (_) {}
    ["#ll-incident", "#ll-what", "#ll-root", "#ll-worked", "#ll-improve", "#ll-actions"].forEach(function(s) { el.querySelector(s).value = ""; });
    renderLessonList();
  };
  el.querySelector("#ll-list").onclick = function(e) {
    if (e.target.dataset.lldel !== undefined) {
      lessons.splice(parseInt(e.target.dataset.lldel), 1);
      try { localStorage.setItem("ir_lessons", JSON.stringify(lessons)); } catch (_) {}
      renderLessonList();
    }
  };
}
