// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Threat Intel Feed — CVE/advisory aggregator with severity filtering, search, and export

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const SEV = {
  CRITICAL: { label: "Critical", color: "#dc2626", floor: 9.0 },
  HIGH:     { label: "High",     color: "#ea580c", floor: 7.0 },
  MEDIUM:   { label: "Medium",   color: "#d97706", floor: 4.0 },
  LOW:      { label: "Low",      color: "#16a34a", floor: 0.0 },
};

function sevOf(cvss) {
  if (cvss >= 9) return "CRITICAL";
  if (cvss >= 7) return "HIGH";
  if (cvss >= 4) return "MEDIUM";
  return "LOW";
}

function randomDate(daysBack) {
  const d = new Date();
  d.setDate(d.getDate() - Math.floor(Math.random() * daysBack));
  return d.toISOString().slice(0, 10);
}

function buildCVEs() {
  const vendors = ["Microsoft", "Linux Kernel", "Apache", "Cisco", "Google Chrome", "Mozilla Firefox",
    "OpenSSL", "VMware", "Oracle", "Adobe", "Fortinet", "Palo Alto Networks", "SolarWinds",
    "Ivanti", "Juniper", "Red Hat", "Nginx", "WordPress", "Drupal", "GitLab"];
  const titles = [
    ["Remote Code Execution in {v} HTTP Handler", "A crafted HTTP request triggers a buffer overflow in the request parser, allowing unauthenticated remote code execution.", "HTTP daemon, Web server module"],
    ["Privilege Escalation via {v} Kernel Driver", "A local attacker can exploit a race condition in the kernel driver to escalate from user to root privileges.", "Kernel driver, OS core"],
    ["SQL Injection in {v} Admin Panel", "Improper input sanitization in the administrative interface allows authenticated attackers to execute arbitrary SQL queries.", "Admin panel, Database layer"],
    ["Cross-Site Scripting in {v} Dashboard", "Reflected XSS in the search parameter of the dashboard allows attackers to steal session tokens.", "Web dashboard, Search module"],
    ["Authentication Bypass in {v} SSO Module", "A flaw in the SAML assertion parser allows attackers to forge authentication tokens and bypass login.", "SSO module, SAML handler"],
    ["Denial of Service via {v} TLS Handshake", "A malformed TLS ClientHello message causes an infinite loop, consuming all available CPU resources.", "TLS/SSL library, Network stack"],
    ["Information Disclosure in {v} API", "The REST API returns internal stack traces and database connection strings in error responses.", "REST API, Error handler"],
    ["Path Traversal in {v} File Upload", "Insufficient path validation allows attackers to write files outside the intended upload directory.", "File upload handler, Storage module"],
    ["Deserialization Vulnerability in {v} RPC", "Untrusted data passed to the deserialization function allows remote code execution via crafted payloads.", "RPC handler, Serialization library"],
    ["Memory Corruption in {v} Image Parser", "A heap-based buffer overflow in the image parsing library allows code execution when processing crafted PNG files.", "Image parser, Media handler"],
    ["Command Injection in {v} Diagnostic Tool", "User-supplied input is passed unsanitized to a shell command in the diagnostic utility.", "Diagnostic module, CLI tool"],
    ["Insecure Default Configuration in {v}", "The default installation ships with debug mode enabled and a hardcoded API key, exposing internal endpoints.", "Configuration module, Setup wizard"],
    ["Certificate Validation Bypass in {v}", "The TLS client does not verify the server certificate chain, enabling man-in-the-middle attacks.", "TLS client, Certificate handler"],
    ["Use-After-Free in {v} Session Manager", "A use-after-free condition in session cleanup allows an attacker to execute arbitrary code in the context of the service.", "Session manager, Memory allocator"],
    ["Integer Overflow in {v} Protocol Parser", "An integer overflow in packet length validation leads to a heap buffer overflow during protocol parsing.", "Protocol parser, Network stack"],
  ];
  const mitigations = [
    "Apply the vendor patch immediately. If patching is not possible, restrict network access to the affected service.",
    "Update to the latest version. Implement network segmentation to limit lateral movement.",
    "Apply the security update. Enable WAF rules to block known exploit patterns.",
    "Upgrade to the patched release. Disable the affected feature if not required.",
    "Install the vendor fix. Monitor logs for indicators of exploitation.",
  ];
  const refs = [
    "https://nvd.nist.gov/vuln/detail/", "https://cve.mitre.org/cgi-bin/cvename.cgi?name=",
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
  ];

  const cves = [];
  for (let i = 0; i < 50; i++) {
    const t = titles[i % titles.length];
    const v = vendors[i % vendors.length];
    const cvss = +(Math.random() * 9.2 + 0.8).toFixed(1);
    const id = `CVE-2026-${String(40000 + i).padStart(5, "0")}`;
    cves.push({
      id, vendor: v, cvss, severity: sevOf(cvss),
      title: t[0].replace("{v}", v),
      description: t[1],
      affected: t[2],
      date: randomDate(90),
      mitigation: mitigations[i % mitigations.length],
      references: [refs[0] + id, refs[1] + id],
    });
  }
  cves.sort((a, b) => b.date.localeCompare(a.date));
  return cves;
}

function injectStyles() {
  if (document.getElementById("tf-css")) return;
  const s = document.createElement("style");
  s.id = "tf-css";
  s.textContent = `
.tf-wrap{max-width:none;padding:0 0 40px}
.tf-header{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:20px}
.tf-header h1{font-size:1.4rem;font-weight:700;margin:0;color:var(--txt)}
.tf-actions{display:flex;gap:8px;flex-wrap:wrap}
.tf-btn{padding:6px 14px;border-radius:6px;border:1px solid var(--line);background:var(--card);color:var(--txt-2);
  font-size:.78rem;cursor:pointer;transition:all .15s ease;font-weight:500}
.tf-btn:hover{border-color:var(--acc);color:var(--acc)}
.tf-btn.active{background:var(--acc);color:#fff;border-color:var(--acc)}
.tf-filters{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px;align-items:center}
.tf-search{flex:1;min-width:200px;padding:8px 12px;border-radius:6px;border:1px solid var(--line);
  background:var(--card);color:var(--txt);font-size:.82rem;outline:none;transition:border-color .15s}
.tf-search:focus{border-color:var(--acc)}
.tf-select{padding:8px 12px;border-radius:6px;border:1px solid var(--line);background:var(--card);
  color:var(--txt);font-size:.82rem;cursor:pointer;outline:none}
.tf-stats{display:flex;gap:16px;margin-bottom:16px;flex-wrap:wrap}
.tf-stat{padding:10px 16px;border-radius:8px;background:var(--card);border:1px solid var(--line);
  display:flex;flex-direction:column;align-items:center;min-width:80px}
.tf-stat-num{font-size:1.3rem;font-weight:700}
.tf-stat-label{font-size:.68rem;color:var(--txt-2);text-transform:uppercase;letter-spacing:.04em;margin-top:2px}
.tf-list{display:flex;flex-direction:column;gap:8px}
.tf-card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 18px;
  cursor:pointer;transition:border-color .15s,box-shadow .15s}
.tf-card:hover{border-color:var(--acc);box-shadow:0 2px 8px rgba(0,0,0,.06)}
.tf-card-top{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.tf-cve-id{font-family:ui-monospace,monospace;font-size:.78rem;font-weight:600;color:var(--acc)}
.tf-sev{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.68rem;font-weight:600;
  color:#fff;text-transform:uppercase;letter-spacing:.03em}
.tf-cvss{font-size:.78rem;font-weight:600;color:var(--txt-2)}
.tf-vendor{font-size:.75rem;color:var(--txt-2);margin-left:auto}
.tf-date{font-size:.72rem;color:var(--mut,var(--txt-2))}
.tf-title{font-size:.88rem;font-weight:600;color:var(--txt);margin-top:6px;line-height:1.4}
.tf-detail{display:none;margin-top:12px;padding-top:12px;border-top:1px solid var(--line);font-size:.82rem;
  color:var(--txt-2);line-height:1.6}
.tf-card.open .tf-detail{display:block}
.tf-detail-section{margin-bottom:10px}
.tf-detail-label{font-weight:600;color:var(--txt);font-size:.76rem;text-transform:uppercase;
  letter-spacing:.04em;margin-bottom:4px}
.tf-detail a{color:var(--acc);text-decoration:none;word-break:break-all}
.tf-detail a:hover{text-decoration:underline}
.tf-empty{text-align:center;padding:40px;color:var(--txt-2);font-size:.88rem}
.tf-count{font-size:.78rem;color:var(--txt-2);margin-bottom:8px}
@media(max-width:600px){
  .tf-header{flex-direction:column;align-items:stretch}
  .tf-filters{flex-direction:column}
  .tf-search{min-width:0}
  .tf-stats{gap:8px}
  .tf-stat{flex:1;min-width:60px;padding:8px 10px}
  .tf-card-top{gap:6px}
  .tf-vendor{margin-left:0}
}`;
  document.head.appendChild(s);
}

export function renderThreatFeed(main) {
  injectStyles();
  const cves = buildCVEs();
  let expanded = new Set();
  let autoRefresh = false;
  let autoTimer = null;

  function getFiltered(query, severity, range) {
    const now = Date.now();
    const ranges = { "7d": 7, "30d": 30, "90d": 90, all: Infinity };
    const days = ranges[range] || Infinity;
    const q = (query || "").toLowerCase().trim();
    return cves.filter(c => {
      if (severity !== "all" && c.severity !== severity) return false;
      if (days !== Infinity) {
        const age = (now - new Date(c.date).getTime()) / 86400000;
        if (age > days) return false;
      }
      if (q && !c.id.toLowerCase().includes(q) && !c.title.toLowerCase().includes(q)
          && !c.vendor.toLowerCase().includes(q) && !c.description.toLowerCase().includes(q)) return false;
      return true;
    });
  }

  function render() {
    const query = main.querySelector(".tf-search")?.value || "";
    const severity = main.querySelector("#tf-sev-filter")?.value || "all";
    const range = main.querySelector("#tf-range-filter")?.value || "all";
    const filtered = getFiltered(query, severity, range);

    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    filtered.forEach(c => counts[c.severity]++);

    const statsEl = main.querySelector(".tf-stats");
    if (statsEl) {
      statsEl.innerHTML = Object.entries(SEV).map(([k, v]) =>
        `<div class="tf-stat"><span class="tf-stat-num" style="color:${v.color}">${counts[k]}</span><span class="tf-stat-label">${v.label}</span></div>`
      ).join("") + `<div class="tf-stat"><span class="tf-stat-num">${filtered.length}</span><span class="tf-stat-label">Total</span></div>`;
    }

    const listEl = main.querySelector(".tf-list");
    if (!listEl) return;

    if (filtered.length === 0) {
      listEl.innerHTML = `<div class="tf-empty">No CVEs match the current filters.</div>`;
      return;
    }

    const countEl = main.querySelector(".tf-count");
    if (countEl) countEl.textContent = `Showing ${filtered.length} of ${cves.length} advisories`;

    listEl.innerHTML = filtered.map(c => {
      const sev = SEV[c.severity];
      const isOpen = expanded.has(c.id);
      return `<div class="tf-card${isOpen ? " open" : ""}" data-id="${esc(c.id)}">
        <div class="tf-card-top">
          <span class="tf-cve-id">${esc(c.id)}</span>
          <span class="tf-sev" style="background:${sev.color}">${sev.label}</span>
          <span class="tf-cvss">CVSS ${c.cvss}</span>
          <span class="tf-date">${esc(c.date)}</span>
          <span class="tf-vendor">${esc(c.vendor)}</span>
        </div>
        <div class="tf-title">${esc(c.title)}</div>
        <div class="tf-detail">
          <div class="tf-detail-section">
            <div class="tf-detail-label">Description</div>
            <div>${esc(c.description)}</div>
          </div>
          <div class="tf-detail-section">
            <div class="tf-detail-label">Affected Products</div>
            <div>${esc(c.affected)}</div>
          </div>
          <div class="tf-detail-section">
            <div class="tf-detail-label">Mitigation</div>
            <div>${esc(c.mitigation)}</div>
          </div>
          <div class="tf-detail-section">
            <div class="tf-detail-label">References</div>
            ${c.references.map(r => `<div><a href="${esc(r)}" target="_blank" rel="noopener">${esc(r)}</a></div>`).join("")}
          </div>
        </div>
      </div>`;
    }).join("");
  }

  function exportJSON() {
    const query = main.querySelector(".tf-search")?.value || "";
    const severity = main.querySelector("#tf-sev-filter")?.value || "all";
    const range = main.querySelector("#tf-range-filter")?.value || "all";
    const data = getFiltered(query, severity, range);
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "threat-feed-export.json";
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function exportCSV() {
    const query = main.querySelector(".tf-search")?.value || "";
    const severity = main.querySelector("#tf-sev-filter")?.value || "all";
    const range = main.querySelector("#tf-range-filter")?.value || "all";
    const data = getFiltered(query, severity, range);
    const header = "CVE ID,Title,Severity,CVSS,Vendor,Date,Description\n";
    const rows = data.map(c =>
      `"${c.id}","${c.title.replace(/"/g, '""')}","${c.severity}",${c.cvss},"${c.vendor}","${c.date}","${c.description.replace(/"/g, '""')}"`
    ).join("\n");
    const blob = new Blob([header + rows], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "threat-feed-export.csv";
    a.click();
    URL.revokeObjectURL(a.href);
  }

  main.innerHTML = `<div class="tf-wrap">
    <div class="tf-header">
      <h1>Threat Intel Feed</h1>
      <div class="tf-actions">
        <button class="tf-btn" id="tf-auto">Auto-Refresh: Off</button>
        <button class="tf-btn" id="tf-export-json">Export JSON</button>
        <button class="tf-btn" id="tf-export-csv">Export CSV</button>
      </div>
    </div>
    <div class="tf-filters">
      <input class="tf-search" placeholder="Search by CVE ID, keyword, or vendor..." spellcheck="false" autocomplete="off">
      <select class="tf-select" id="tf-sev-filter">
        <option value="all">All Severities</option>
        <option value="CRITICAL">Critical</option>
        <option value="HIGH">High</option>
        <option value="MEDIUM">Medium</option>
        <option value="LOW">Low</option>
      </select>
      <select class="tf-select" id="tf-range-filter">
        <option value="all">All Time</option>
        <option value="7d">Last 7 Days</option>
        <option value="30d">Last 30 Days</option>
        <option value="90d">Last 90 Days</option>
      </select>
    </div>
    <div class="tf-stats"></div>
    <div class="tf-count"></div>
    <div class="tf-list"></div>
  </div>`;

  render();

  const searchEl = main.querySelector(".tf-search");
  const sevEl = main.querySelector("#tf-sev-filter");
  const rangeEl = main.querySelector("#tf-range-filter");
  searchEl.addEventListener("input", render);
  sevEl.addEventListener("change", render);
  rangeEl.addEventListener("change", render);

  main.querySelector(".tf-list").addEventListener("click", (e) => {
    const card = e.target.closest(".tf-card");
    if (!card) return;
    const id = card.dataset.id;
    if (expanded.has(id)) expanded.delete(id); else expanded.add(id);
    card.classList.toggle("open");
  });

  main.querySelector("#tf-export-json").addEventListener("click", exportJSON);
  main.querySelector("#tf-export-csv").addEventListener("click", exportCSV);

  const autoBtn = main.querySelector("#tf-auto");
  autoBtn.addEventListener("click", () => {
    autoRefresh = !autoRefresh;
    autoBtn.textContent = `Auto-Refresh: ${autoRefresh ? "On" : "Off"}`;
    autoBtn.classList.toggle("active", autoRefresh);
    if (autoRefresh) {
      autoTimer = setInterval(render, 30000);
    } else {
      clearInterval(autoTimer);
      autoTimer = null;
    }
  });
}
