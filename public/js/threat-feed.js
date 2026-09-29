// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Threat Intel Feed — recently published CVEs from the NIST NVD API, with severity filtering, search, and export

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const SEV = {
  CRITICAL: { label: "Critical", color: "#dc2626", floor: 9.0 },
  HIGH:     { label: "High",     color: "#ea580c", floor: 7.0 },
  MEDIUM:   { label: "Medium",   color: "#d97706", floor: 4.0 },
  LOW:      { label: "Low",      color: "#16a34a", floor: 0.0 },
  NONE:     { label: "Unscored", color: "#64748b", floor: -1 },
};

function sevOf(cvss) {
  if (cvss >= 9) return "CRITICAL";
  if (cvss >= 7) return "HIGH";
  if (cvss >= 4) return "MEDIUM";
  return "LOW";
}

// ---------------------------------------------------------------------------
// Live data: NIST NVD CVE API 2.0 (same public source as the CVE Search page;
// allowed by the site CSP connect-src). No API key, so NVD rate-limits to about
// 5 requests / 30 s. We ask for CVEs published in the selected window and keep
// the newest PAGE_SIZE of them.
// ---------------------------------------------------------------------------
const NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const PAGE_SIZE = 200;

// NVD wants "YYYY-MM-DDTHH:MM:SS.000" (UTC, no zone suffix).
function nvdDate(d) { return d.toISOString().slice(0, 19) + ".000"; }

function nvdUrl(days, startIndex, perPage) {
  const end = new Date();
  const start = new Date(end.getTime() - days * 86400000);
  return NVD_API + "?pubStartDate=" + encodeURIComponent(nvdDate(start)) +
    "&pubEndDate=" + encodeURIComponent(nvdDate(end)) +
    "&noRejected&resultsPerPage=" + perPage + "&startIndex=" + startIndex;
}

async function nvdJSON(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error("NVD returned HTTP " + r.status + (r.status === 403 || r.status === 429 ? " (rate limited, try again in 30 seconds)" : ""));
  return r.json();
}

function metricOf(cve) {
  const m = cve.metrics || {};
  const pick = (m.cvssMetricV40 || [])[0] || (m.cvssMetricV31 || [])[0] || (m.cvssMetricV30 || [])[0] || (m.cvssMetricV2 || [])[0];
  if (!pick || !pick.cvssData) return null;
  return { score: pick.cvssData.baseScore, version: pick.cvssData.version || "" };
}

// First vendor/product pairs from CPE match strings (cpe:2.3:a:vendor:product:...).
function productsOf(cve) {
  const out = [];
  (cve.configurations || []).forEach(cfg => (cfg.nodes || []).forEach(n => (n.cpeMatch || []).forEach(cm => {
    const p = String(cm.criteria || "").split(":");
    if (p.length > 4) {
      const name = (p[3] + " " + p[4]).replace(/_/g, " ");
      if (!out.includes(name)) out.push(name);
    }
  })));
  return out;
}

function mapNvd(v) {
  const cve = v.cve || {};
  const desc = ((cve.descriptions || []).find(d => d.lang === "en") || (cve.descriptions || [])[0] || {}).value || "";
  const metric = metricOf(cve);
  const products = productsOf(cve);
  const cwes = [];
  (cve.weaknesses || []).forEach(w => (w.description || []).forEach(d => { if (d.value && !cwes.includes(d.value)) cwes.push(d.value); }));
  const refs = (cve.references || []).map(r => r.url).filter(u => /^https?:\/\//i.test(u || ""));
  const firstSentence = desc.split(/(?<=\.)\s/)[0] || desc;
  return {
    id: cve.id,
    vendor: products.length ? products[0].split(" ")[0] : "",
    cvss: metric ? metric.score : null,
    cvssVersion: metric ? metric.version : "",
    severity: metric ? sevOf(metric.score) : "NONE",
    title: firstSentence.length > 160 ? firstSentence.slice(0, 157) + "..." : firstSentence,
    description: desc,
    affected: products.slice(0, 8).join(", ") || "Not yet listed by NVD",
    weaknesses: cwes.join(", "),
    status: cve.vulnStatus || "",
    date: String(cve.published || "").slice(0, 10),
    references: ["https://nvd.nist.gov/vuln/detail/" + encodeURIComponent(cve.id)].concat(refs.slice(0, 6)),
  };
}

// Newest PAGE_SIZE CVEs published in the last `days` days.
async function fetchRecentCVEs(days) {
  const head = await nvdJSON(nvdUrl(days, 0, 1));
  const total = head.totalResults || 0;
  if (!total) return { cves: [], total: 0 };
  const startIndex = Math.max(0, total - PAGE_SIZE);
  const page = await nvdJSON(nvdUrl(days, startIndex, PAGE_SIZE));
  const cves = (page.vulnerabilities || []).map(mapNvd).filter(c => c.id);
  cves.sort((a, b) => b.date.localeCompare(a.date) || b.id.localeCompare(a.id));
  return { cves, total };
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
.tf-btn{padding:6px 14px;border-radius:4px;border:1px solid var(--line);background:var(--card);color:var(--txt-2);
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
.tf-source{font-size:.76rem;color:var(--txt-2);margin:-8px 0 16px;line-height:1.5}
.tf-err{padding:14px 16px;border-radius:8px;border:1px solid #dc262655;background:rgba(220,38,38,.06);color:var(--txt);font-size:.82rem;margin-bottom:12px}
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
  let cves = [];
  let totalInWindow = 0;
  let loading = false;
  let loadError = "";
  let loadedAt = null;
  let expanded = new Set();
  let autoRefresh = false;
  let autoTimer = null;

  const RANGE_DAYS = { "7d": 7, "30d": 30, "90d": 90 };

  function getFiltered(query, severity) {
    const q = (query || "").toLowerCase().trim();
    return cves.filter(c => {
      if (severity !== "all" && c.severity !== severity) return false;
      if (q && !c.id.toLowerCase().includes(q) && !c.title.toLowerCase().includes(q)
          && !c.vendor.toLowerCase().includes(q) && !c.description.toLowerCase().includes(q)) return false;
      return true;
    });
  }

  function render() {
    const query = main.querySelector(".tf-search")?.value || "";
    const severity = main.querySelector("#tf-sev-filter")?.value || "all";
    const filtered = getFiltered(query, severity);

    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0 };
    filtered.forEach(c => counts[c.severity]++);

    const statsEl = main.querySelector(".tf-stats");
    if (statsEl) {
      statsEl.innerHTML = Object.entries(SEV).map(([k, v]) =>
        `<div class="tf-stat"><span class="tf-stat-num" style="color:${v.color}">${counts[k]}</span><span class="tf-stat-label">${v.label}</span></div>`
      ).join("") + `<div class="tf-stat"><span class="tf-stat-num">${filtered.length}</span><span class="tf-stat-label">Total</span></div>`;
    }

    const listEl = main.querySelector(".tf-list");
    if (!listEl) return;
    const countEl = main.querySelector(".tf-count");
    const srcEl = main.querySelector(".tf-source");
    const days = RANGE_DAYS[main.querySelector("#tf-range-filter")?.value] || 7;
    if (srcEl) {
      srcEl.textContent = "Source: NIST National Vulnerability Database (services.nvd.nist.gov), CVEs published in the last " + days + " days" +
        (loadedAt ? ". Fetched " + loadedAt.toLocaleTimeString() + (totalInWindow > cves.length ? "; showing " + cves.length + " of " + totalInWindow + " (the last page of NVD results)." : ".") : ".");
    }

    if (loading && !cves.length) {
      if (countEl) countEl.textContent = "";
      listEl.innerHTML = `<div class="tf-empty">Loading recent CVEs from NVD...</div>`;
      return;
    }
    if (loadError && !cves.length) {
      if (countEl) countEl.textContent = "";
      listEl.innerHTML = `<div class="tf-err"><strong>Could not load CVEs from NVD.</strong> ${esc(loadError)}<br>Use Refresh to try again. The CVE Search page also queries NVD directly.</div>`;
      return;
    }

    if (filtered.length === 0) {
      if (countEl) countEl.textContent = "";
      listEl.innerHTML = `<div class="tf-empty">No CVEs match the current filters.</div>`;
      return;
    }

    if (countEl) countEl.textContent = `Showing ${filtered.length} of ${cves.length} CVEs` + (loadError ? ` (last refresh failed: ${loadError})` : "");

    listEl.innerHTML = filtered.map(c => {
      const sev = SEV[c.severity];
      const isOpen = expanded.has(c.id);
      return `<div class="tf-card${isOpen ? " open" : ""}" data-id="${esc(c.id)}">
        <div class="tf-card-top">
          <span class="tf-cve-id">${esc(c.id)}</span>
          <span class="tf-sev" style="background:${sev.color}">${sev.label}</span>
          <span class="tf-cvss">${c.cvss != null ? "CVSS " + c.cvss + (c.cvssVersion ? " (v" + esc(c.cvssVersion) + ")" : "") : "Not yet scored"}</span>
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
          ${c.weaknesses ? `<div class="tf-detail-section">
            <div class="tf-detail-label">Weakness</div>
            <div>${esc(c.weaknesses)}</div>
          </div>` : ""}
          ${c.status ? `<div class="tf-detail-section">
            <div class="tf-detail-label">NVD Status</div>
            <div>${esc(c.status)}</div>
          </div>` : ""}
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
    const data = getFiltered(query, severity);
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
    const data = getFiltered(query, severity);
    const header = "CVE ID,Title,Severity,CVSS,Vendor,Date,Description\n";
    const rows = data.map(c =>
      `"${c.id}","${c.title.replace(/"/g, '""')}","${c.severity}",${c.cvss != null ? c.cvss : ""},"${c.vendor.replace(/"/g, '""')}","${c.date}","${c.description.replace(/"/g, '""')}"`
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
        <button class="tf-btn" id="tf-refresh">Refresh</button>
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
        <option value="NONE">Unscored</option>
      </select>
      <select class="tf-select" id="tf-range-filter">
        <option value="7d" selected>Published: Last 7 Days</option>
        <option value="30d">Published: Last 30 Days</option>
        <option value="90d">Published: Last 90 Days</option>
      </select>
    </div>
    <div class="tf-source"></div>
    <div class="tf-stats"></div>
    <div class="tf-count"></div>
    <div class="tf-list"></div>
  </div>`;

  async function load() {
    if (loading) return;
    loading = true;
    const days = RANGE_DAYS[main.querySelector("#tf-range-filter")?.value] || 7;
    const btn = main.querySelector("#tf-refresh");
    if (btn) { btn.disabled = true; btn.textContent = "Loading..."; }
    render();
    try {
      const res = await fetchRecentCVEs(days);
      cves = res.cves;
      totalInWindow = res.total;
      loadError = "";
      loadedAt = new Date();
    } catch (err) {
      loadError = String((err && err.message) || err || "Network error");
    } finally {
      loading = false;
      if (btn) { btn.disabled = false; btn.textContent = "Refresh"; }
    }
    if (main.querySelector(".tf-wrap")) render();
  }

  render();
  load();

  const searchEl = main.querySelector(".tf-search");
  const sevEl = main.querySelector("#tf-sev-filter");
  const rangeEl = main.querySelector("#tf-range-filter");
  searchEl.addEventListener("input", render);
  sevEl.addEventListener("change", render);
  rangeEl.addEventListener("change", () => { cves = []; expanded = new Set(); load(); });
  main.querySelector("#tf-refresh").addEventListener("click", load);

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
    autoBtn.textContent = `Auto-Refresh: ${autoRefresh ? "On (10 min)" : "Off"}`;
    autoBtn.classList.toggle("active", autoRefresh);
    if (autoRefresh) {
      // NVD asks unauthenticated clients to stay well under 5 requests / 30 s.
      autoTimer = setInterval(() => {
        if (!main.querySelector(".tf-wrap")) { clearInterval(autoTimer); autoTimer = null; return; }
        load();
      }, 10 * 60 * 1000);
    } else {
      clearInterval(autoTimer);
      autoTimer = null;
    }
  });
}
