// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.

const FRAMEWORKS = [
  { id: "owasp", name: "OWASP Top 10", ver: "2021", items: [
    { title: "A01: Broken Access Control", desc: "Ensure users cannot act outside their intended permissions. Verify role-based access controls, deny by default, enforce record ownership, disable directory listing, and invalidate JWT tokens on logout." },
    { title: "A02: Cryptographic Failures", desc: "Protect data in transit and at rest. Use TLS 1.2+ for all connections, AES-256 or ChaCha20 for encryption at rest, bcrypt/scrypt/Argon2 for passwords, and never store secrets in source code." },
    { title: "A03: Injection", desc: "Prevent untrusted data from being sent to an interpreter. Use parameterized queries for SQL, contextual output encoding for XSS, and allowlist server-side input validation." },
    { title: "A04: Insecure Design", desc: "Integrate security from the design phase. Perform threat modeling, define security user stories, apply secure design patterns, and conduct design reviews before implementation." },
    { title: "A05: Security Misconfiguration", desc: "Harden all environments consistently. Remove default credentials, disable unnecessary features, review cloud storage permissions, send security headers (CSP, HSTS, X-Frame-Options), and automate configuration verification." },
    { title: "A06: Vulnerable Components", desc: "Track and update all dependencies. Maintain a software bill of materials (SBOM), subscribe to CVE alerts for your stack, remove unused dependencies, and only source components from official channels." },
    { title: "A07: Auth & ID Failures", desc: "Implement robust authentication. Enforce MFA, prevent credential stuffing with rate limiting, use secure session management, never ship default credentials, and check passwords against breach databases." },
    { title: "A08: Software & Data Integrity", desc: "Verify integrity of software updates and CI/CD pipelines. Use signed artifacts, verify checksums, review code changes, protect CI/CD credentials, and ensure deserialization uses allowlists." },
    { title: "A09: Logging & Monitoring Failures", desc: "Detect breaches quickly with comprehensive logging. Log authentication events, access control failures, and input validation errors. Use tamper-evident logs, set up alerting, and establish an incident response plan." },
    { title: "A10: Server-Side Request Forgery", desc: "Prevent SSRF by sanitizing user-supplied URLs, enforcing allowlists for outbound requests, disabling HTTP redirects, and blocking access to metadata endpoints (169.254.169.254)." },
  ]},
  { id: "cis", name: "CIS Controls", ver: "v8 Top 18", items: [
    { title: "CIS 1: Enterprise Asset Inventory", desc: "Maintain an accurate, up-to-date inventory of all technology assets (hardware, virtual, cloud, IoT) that connect to the network. Use active and passive discovery tools and track ownership." },
    { title: "CIS 2: Software Asset Inventory", desc: "Catalog all installed and authorized software. Track versions, use application allowlisting, and remove unauthorized software. Automate discovery on a weekly basis." },
    { title: "CIS 3: Data Protection", desc: "Classify data by sensitivity, encrypt sensitive data at rest and in transit, enforce DLP policies, control access to data stores, and securely dispose of data when no longer needed." },
    { title: "CIS 4: Secure Configuration", desc: "Establish and enforce hardened configurations using CIS Benchmarks or DISA STIGs. Disable unnecessary services, change defaults, remove sample applications, and automate compliance checks." },
    { title: "CIS 5: Account Management", desc: "Manage the lifecycle of user and admin accounts. Enforce unique credentials, disable dormant accounts, require MFA for privileged access, and centralize account management through a directory service." },
    { title: "CIS 6: Access Control Management", desc: "Implement least-privilege access. Define role-based access, require MFA for remote and administrative access, review permissions quarterly, and log all privilege escalations." },
    { title: "CIS 7: Continuous Vulnerability Management", desc: "Run authenticated vulnerability scans at least monthly, remediate critical/high within 14 days, track remediation SLAs, and integrate scanning into CI/CD pipelines." },
    { title: "CIS 8: Audit Log Management", desc: "Collect, retain, and review audit logs from all enterprise assets. Centralize in a SIEM, retain for at least 90 days (1 year recommended), and alert on anomalous patterns." },
    { title: "CIS 9: Email & Browser Protections", desc: "Deploy email filtering (SPF, DKIM, DMARC), block known malicious URLs, restrict browser extensions, and enable DNS-based filtering for all endpoints." },
    { title: "CIS 10: Malware Defenses", desc: "Deploy endpoint detection and response (EDR) on all assets. Enable automatic updates, centralize management, block execution from removable media, and scan downloads in real time." },
  ]},
  { id: "soc2", name: "SOC2 Trust Services", ver: "2024", items: [
    { title: "CC1: Control Environment", desc: "Management demonstrates commitment to integrity and ethics. Define organizational structure, assign security responsibilities, and establish a code of conduct reviewed annually." },
    { title: "CC2: Communication & Information", desc: "Generate and use relevant, quality information. Document security policies, communicate expectations to all personnel, and provide channels for reporting security concerns." },
    { title: "CC3: Risk Assessment", desc: "Identify and analyze risks to objectives. Maintain a risk register, assess likelihood and impact, consider fraud scenarios, and evaluate changes that could significantly affect internal controls." },
    { title: "CC5: Control Activities", desc: "Select and develop control activities that mitigate risks. Implement segregation of duties, change management procedures, logical access controls, and technology general controls." },
    { title: "CC6: Logical & Physical Access", desc: "Restrict logical and physical access. Use identity management, MFA, encryption, physical security controls (badges, cameras), and restrict data center access to authorized personnel." },
    { title: "CC7: System Operations", desc: "Detect and respond to anomalies. Monitor infrastructure, implement IDS/IPS, define incident response procedures, conduct tabletop exercises, and maintain business continuity plans." },
    { title: "CC8: Change Management", desc: "Control changes to infrastructure and software. Use a formal change process with testing, approval, and rollback procedures. Separate development from production environments." },
    { title: "CC9: Risk Mitigation", desc: "Identify and mitigate vendor and business risks. Assess third-party providers, maintain vendor agreements with security requirements, and obtain SOC reports from critical vendors." },
    { title: "Availability: System Uptime", desc: "Maintain system availability per SLAs. Implement redundancy, capacity planning, disaster recovery, backup testing, and document recovery time objectives (RTO) and recovery point objectives (RPO)." },
    { title: "Confidentiality: Data Handling", desc: "Protect confidential information throughout its lifecycle. Classify data, restrict access, encrypt in transit and at rest, enforce retention policies, and securely destroy data no longer needed." },
  ]},
  { id: "nist", name: "NIST CSF", ver: "2.0", items: [
    { title: "ID.AM: Asset Management", desc: "Inventory all physical devices, software platforms, data flows, and external information systems. Map communication paths and prioritize assets by business value." },
    { title: "ID.RA: Risk Assessment", desc: "Identify threats and vulnerabilities, assess likelihood and impact, determine risk, and document risk responses. Use frameworks like FAIR or OCTAVE for quantitative analysis." },
    { title: "PR.AC: Identity & Access Management", desc: "Manage identities, credentials, and access. Enforce least privilege, implement MFA, protect remote access, and manage permissions throughout the identity lifecycle." },
    { title: "PR.DS: Data Security", desc: "Protect data at rest (encryption, access controls), in transit (TLS), and during processing. Implement DLP, manage data through its lifecycle, and ensure adequate capacity." },
    { title: "PR.IP: Protective Processes", desc: "Maintain and manage security baselines, implement change control, conduct backups, enforce policy on removable media, and achieve secure disposal of data and hardware." },
    { title: "PR.AT: Awareness & Training", desc: "Ensure personnel and partners are trained. Privileged users understand their roles, stakeholders understand physical security, and training is updated for evolving threats." },
    { title: "DE.CM: Continuous Monitoring", desc: "Monitor networks, physical environment, personnel activity, malicious code, mobile code, and unauthorized connections. Use SIEM for correlation and alerting." },
    { title: "DE.AE: Anomaly & Event Detection", desc: "Establish baselines for network operations and expected data flows. Detect anomalous events, correlate from multiple sources, and determine incident impact thresholds." },
    { title: "RS.RP: Response Planning", desc: "Execute incident response plan during or after an event. Define roles, communication channels, coordination with external parties, and lessons-learned processes." },
    { title: "RC.RP: Recovery Planning", desc: "Execute recovery plans during or after a cybersecurity event. Incorporate lessons learned, update recovery strategy, and manage public relations and reputation repair." },
  ]},
  { id: "pci", name: "PCI DSS", ver: "v4.0 Quick Check", items: [
    { title: "Req 1: Network Security Controls", desc: "Install and maintain firewalls/NSCs between trusted and untrusted networks. Restrict inbound and outbound traffic to that which is necessary, and document all allowed connections." },
    { title: "Req 2: Secure Configurations", desc: "Change vendor defaults before installing on the network. Remove unnecessary services, protocols, and accounts. Encrypt all non-console administrative access." },
    { title: "Req 3: Protect Stored Account Data", desc: "Keep cardholder data storage to a minimum. Render PAN unreadable (truncation, hashing, tokenization, or strong encryption). Never store SAD after authorization." },
    { title: "Req 4: Encrypt Transmission", desc: "Encrypt cardholder data with strong cryptography during transmission over open, public networks. Use TLS 1.2+ and verify certificates. Never send PAN via unencrypted messaging." },
    { title: "Req 5: Anti-Malware", desc: "Deploy anti-malware on all systems commonly affected by malware. Keep definitions current, perform periodic scans, and ensure anti-malware cannot be disabled by users." },
    { title: "Req 6: Secure Development", desc: "Develop and maintain secure systems. Address vulnerabilities via patching (critical within 30 days), follow secure coding guidelines, and review custom code before release." },
    { title: "Req 7: Restrict Access", desc: "Limit access to cardholder data to business need-to-know. Implement role-based access control, default deny-all, and review access rights at least semi-annually." },
    { title: "Req 8: Identify & Authenticate", desc: "Assign unique IDs to all users. Enforce MFA for all access into the cardholder data environment. Use complex passwords (12+ chars) and lock accounts after 10 failed attempts." },
    { title: "Req 10: Log & Monitor Access", desc: "Log all access to network resources and cardholder data. Synchronize clocks, review logs daily, retain audit trails for at least one year with 3 months immediately available." },
    { title: "Req 11: Test Security Regularly", desc: "Run quarterly internal and external vulnerability scans (ASV). Perform annual penetration testing, deploy intrusion detection, and implement file integrity monitoring." },
    { title: "Req 12: Security Policy", desc: "Maintain an information security policy reviewed annually. Conduct risk assessments, implement a security awareness program, screen personnel, and manage service providers." },
  ]},
];

const LS_PREFIX = "dn_checklist_";

function loadState(fwId) {
  try { return JSON.parse(localStorage.getItem(LS_PREFIX + fwId)) || {}; } catch { return {}; }
}
function saveState(fwId, state) {
  try { localStorage.setItem(LS_PREFIX + fwId, JSON.stringify(state)); } catch {}
}

function injectStyles() {
  if (document.getElementById("sc-css")) return;
  const s = document.createElement("style"); s.id = "sc-css";
  s.textContent = `
.sc-wrap{max-width:none;padding:0}
.sc-header{margin-bottom:24px}
.sc-header h1{font-size:1.5rem;font-weight:700;margin:0 0 4px;color:var(--txt)}
.sc-header p{color:var(--txt-2);font-size:.85rem;margin:0}
.sc-tabs{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:24px}
.sc-tab{padding:8px 16px;border-radius:4px;border:1px solid var(--line);background:var(--card);color:var(--txt-2);font-size:.78rem;font-weight:600;cursor:pointer;transition:all .15s ease;white-space:nowrap}
.sc-tab:hover{border-color:var(--acc);color:var(--acc)}
.sc-tab.active{background:var(--acc);color:#fff;border-color:var(--acc)}
.sc-tab-ver{font-weight:400;opacity:.7;margin-left:4px}
.sc-toolbar{display:flex;flex-wrap:wrap;align-items:center;gap:10px;margin-bottom:20px}
.sc-toolbar .sc-btn{padding:6px 14px;border-radius:4px;border:1px solid var(--line);background:var(--card);color:var(--txt-2);font-size:.75rem;font-weight:600;cursor:pointer;transition:all .15s ease}
.sc-toolbar .sc-btn:hover{border-color:var(--acc);color:var(--acc)}
.sc-toolbar .sc-btn.danger:hover{border-color:#dc2626;color:#dc2626}
.sc-progress-wrap{flex:1;min-width:200px;display:flex;align-items:center;gap:10px}
.sc-progress-bar{flex:1;height:6px;background:var(--line);border-radius:3px;overflow:hidden}
.sc-progress-fill{height:100%;background:var(--acc);border-radius:3px;transition:width .3s ease}
.sc-progress-text{font-size:.75rem;font-weight:600;color:var(--txt-2);min-width:42px;text-align:right}
.sc-summary{display:flex;flex-wrap:wrap;gap:16px;margin-bottom:24px}
.sc-stat{background:var(--card);border:1px solid var(--line);border-radius:var(--r,8px);padding:14px 20px;min-width:100px;text-align:center}
.sc-stat-val{font-size:1.3rem;font-weight:700;color:var(--txt)}
.sc-stat-label{font-size:.7rem;color:var(--txt-2);text-transform:uppercase;letter-spacing:.04em;margin-top:2px}
.sc-list{display:flex;flex-direction:column;gap:8px}
.sc-item{background:var(--card);border:1px solid var(--line);border-radius:var(--r,8px);overflow:hidden;transition:border-color .15s ease}
.sc-item:hover{border-color:color-mix(in srgb,var(--acc) 40%,var(--line))}
.sc-item-head{display:flex;align-items:center;gap:10px;padding:12px 16px;cursor:pointer;user-select:none}
.sc-item-check{width:18px;height:18px;accent-color:var(--acc);cursor:pointer;flex-shrink:0}
.sc-item-title{flex:1;font-size:.85rem;font-weight:600;color:var(--txt)}
.sc-item-status{padding:3px 10px;border-radius:4px;font-size:.68rem;font-weight:600;text-transform:uppercase;letter-spacing:.03em;border:none;background:var(--line);color:var(--txt-2);cursor:pointer}
.sc-item-status option{background:var(--card);color:var(--txt)}
.sc-item-toggle{background:none;border:none;color:var(--txt-2);cursor:pointer;font-size:.75rem;padding:4px 8px;border-radius:4px;transition:background .15s ease}
.sc-item-toggle:hover{background:var(--line)}
.sc-item-body{padding:0 16px 14px;display:none}
.sc-item.open .sc-item-body{display:block}
.sc-item-desc{font-size:.8rem;color:var(--txt-2);line-height:1.6;margin-bottom:10px}
.sc-item-evidence{width:100%;padding:8px 10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--txt);font-size:.78rem;resize:vertical;min-height:48px;font-family:inherit}
.sc-item-evidence::placeholder{color:var(--mut,#666)}
.sc-item-evidence:focus{outline:none;border-color:var(--acc)}
.sc-status-pass{background:#16a34a22;color:#16a34a}
.sc-status-fail{background:#dc262622;color:#dc2626}
.sc-status-na{background:var(--line);color:var(--txt-2)}
@media(max-width:600px){.sc-tabs{gap:6px}.sc-tab{padding:6px 10px;font-size:.72rem}.sc-toolbar{flex-direction:column;align-items:stretch}.sc-summary{gap:8px}.sc-stat{flex:1;min-width:70px;padding:10px}}`;
  document.head.appendChild(s);
}

function getStatusClass(status) {
  if (status === "pass") return "sc-status-pass";
  if (status === "fail") return "sc-status-fail";
  if (status === "na") return "sc-status-na";
  return "";
}

function computeStats(fw, state) {
  const total = fw.items.length;
  let pass = 0, fail = 0, na = 0, pending = 0;
  fw.items.forEach((_, i) => {
    const s = state[i]?.status || "pending";
    if (s === "pass") pass++;
    else if (s === "fail") fail++;
    else if (s === "na") na++;
    else pending++;
  });
  const assessed = pass + fail + na;
  const pct = total > 0 ? Math.round((assessed / total) * 100) : 0;
  const score = (pass + na) > 0 ? Math.round((pass / (pass + fail || 1)) * 100) : 0;
  return { total, pass, fail, na, pending, assessed, pct, score };
}

function exportJSON(fw, state) {
  const data = { framework: fw.name, version: fw.ver, exportedAt: new Date().toISOString(), items: fw.items.map((item, i) => ({
    title: item.title, status: state[i]?.status || "pending", checked: !!state[i]?.checked, evidence: state[i]?.evidence || ""
  }))};
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `darknode-${fw.id}-checklist.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

function exportHTML(fw, state) {
  const stats = computeStats(fw, state);
  const rows = fw.items.map((item, i) => {
    const s = state[i]?.status || "pending";
    const ev = state[i]?.evidence || "—";
    const color = s === "pass" ? "#16a34a" : s === "fail" ? "#dc2626" : "#666";
    return `<tr><td>${item.title}</td><td style="color:${color};font-weight:600;text-transform:uppercase">${s}</td><td style="font-size:.85em;color:#555">${item.desc}</td><td style="font-size:.85em">${ev}</td></tr>`;
  }).join("");
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${fw.name} Checklist - Darknode</title>
<style>body{font-family:system-ui,sans-serif;margin:40px;color:#1e293b}h1{font-size:1.4rem}
table{width:100%;border-collapse:collapse;margin-top:20px}th,td{border:1px solid #e2e8f0;padding:10px;text-align:left;font-size:.85rem}
th{background:#f1f5f9;font-weight:600}.meta{color:#64748b;font-size:.85rem;margin-bottom:8px}</style></head>
<body><h1>${fw.name} (${fw.ver}) - Security Checklist</h1>
<p class="meta">Generated by Darknode on ${new Date().toLocaleDateString()} | Score: ${stats.score}% | Completion: ${stats.pct}%</p>
<table><thead><tr><th>Control</th><th>Status</th><th>Description</th><th>Evidence</th></tr></thead><tbody>${rows}</tbody></table></body></html>`;
  const blob = new Blob([html], { type: "text/html" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `darknode-${fw.id}-checklist.html`;
  a.click();
  URL.revokeObjectURL(a.href);
}

export function renderSecChecklist(main) {
  injectStyles();
  let activeId = FRAMEWORKS[0].id;
  const states = {};
  FRAMEWORKS.forEach(fw => { states[fw.id] = loadState(fw.id); });

  function render() {
    const fw = FRAMEWORKS.find(f => f.id === activeId);
    const state = states[activeId];
    const stats = computeStats(fw, state);

    main.innerHTML = `<div class="sc-wrap">
      <div class="sc-header"><h1>Security Checklist Generator</h1><p>Interactive compliance checklists for security assessments. Select a framework, evaluate each control, and export your results.</p></div>
      <div class="sc-tabs">${FRAMEWORKS.map(f => `<button class="sc-tab${f.id === activeId ? " active" : ""}" data-fw="${f.id}">${f.name}<span class="sc-tab-ver">${f.ver}</span></button>`).join("")}</div>
      <div class="sc-summary">
        <div class="sc-stat"><div class="sc-stat-val">${stats.score}%</div><div class="sc-stat-label">Pass Rate</div></div>
        <div class="sc-stat"><div class="sc-stat-val">${stats.pass}</div><div class="sc-stat-label">Pass</div></div>
        <div class="sc-stat"><div class="sc-stat-val">${stats.fail}</div><div class="sc-stat-label">Fail</div></div>
        <div class="sc-stat"><div class="sc-stat-val">${stats.na}</div><div class="sc-stat-label">N/A</div></div>
        <div class="sc-stat"><div class="sc-stat-val">${stats.pending}</div><div class="sc-stat-label">Pending</div></div>
      </div>
      <div class="sc-toolbar">
        <div class="sc-progress-wrap"><div class="sc-progress-bar"><div class="sc-progress-fill" style="width:${stats.pct}%"></div></div><span class="sc-progress-text">${stats.pct}%</span></div>
        <button class="sc-btn" data-action="export-json">Export JSON</button>
        <button class="sc-btn" data-action="export-html">Export Report</button>
        <button class="sc-btn danger" data-action="reset">Reset</button>
      </div>
      <div class="sc-list">${fw.items.map((item, i) => {
        const s = state[i] || {};
        const status = s.status || "pending";
        return `<div class="sc-item${s.open ? " open" : ""}" data-idx="${i}">
          <div class="sc-item-head">
            <input type="checkbox" class="sc-item-check" ${s.checked ? "checked" : ""} data-idx="${i}">
            <span class="sc-item-title">${item.title}</span>
            <select class="sc-item-status ${getStatusClass(status)}" data-idx="${i}"><option value="pending"${status==="pending"?" selected":""}>Pending</option><option value="pass"${status==="pass"?" selected":""}>Pass</option><option value="fail"${status==="fail"?" selected":""}>Fail</option><option value="na"${status==="na"?" selected":""}>N/A</option></select>
            <button class="sc-item-toggle" data-idx="${i}">${s.open ? "Collapse" : "Expand"}</button>
          </div>
          <div class="sc-item-body">
            <div class="sc-item-desc">${item.desc}</div>
            <textarea class="sc-item-evidence" placeholder="Evidence / notes..." data-idx="${i}">${s.evidence || ""}</textarea>
          </div>
        </div>`;
      }).join("")}</div>
    </div>`;

    main.querySelector(".sc-tabs").onclick = (e) => {
      const btn = e.target.closest(".sc-tab");
      if (btn && btn.dataset.fw) { activeId = btn.dataset.fw; render(); }
    };
    main.querySelector(".sc-toolbar").onclick = (e) => {
      const btn = e.target.closest(".sc-btn");
      if (!btn) return;
      const action = btn.dataset.action;
      if (action === "export-json") exportJSON(fw, state);
      else if (action === "export-html") exportHTML(fw, state);
      else if (action === "reset") {
        if (confirm("Reset all checklist progress for " + fw.name + "?")) {
          states[activeId] = {};
          saveState(activeId, {});
          render();
        }
      }
    };
    main.querySelector(".sc-list").addEventListener("click", (e) => {
      const toggle = e.target.closest(".sc-item-toggle");
      if (toggle) {
        const idx = parseInt(toggle.dataset.idx);
        if (!state[idx]) state[idx] = {};
        state[idx].open = !state[idx].open;
        saveState(activeId, state);
        const item = toggle.closest(".sc-item");
        item.classList.toggle("open");
        toggle.textContent = item.classList.contains("open") ? "Collapse" : "Expand";
        return;
      }
    });
    main.querySelector(".sc-list").addEventListener("change", (e) => {
      const check = e.target.closest(".sc-item-check");
      if (check) {
        const idx = parseInt(check.dataset.idx);
        if (!state[idx]) state[idx] = {};
        state[idx].checked = check.checked;
        if (check.checked && (!state[idx].status || state[idx].status === "pending")) {
          state[idx].status = "pass";
        }
        saveState(activeId, state);
        render();
        return;
      }
      const sel = e.target.closest(".sc-item-status");
      if (sel) {
        const idx = parseInt(sel.dataset.idx);
        if (!state[idx]) state[idx] = {};
        state[idx].status = sel.value;
        if (sel.value === "pass") state[idx].checked = true;
        else if (sel.value === "fail" || sel.value === "na") state[idx].checked = false;
        saveState(activeId, state);
        render();
        return;
      }
    });
    main.querySelector(".sc-list").addEventListener("input", (e) => {
      const ta = e.target.closest(".sc-item-evidence");
      if (ta) {
        const idx = parseInt(ta.dataset.idx);
        if (!state[idx]) state[idx] = {};
        state[idx].evidence = ta.value;
        saveState(activeId, state);
      }
    });
  }

  render();
}
