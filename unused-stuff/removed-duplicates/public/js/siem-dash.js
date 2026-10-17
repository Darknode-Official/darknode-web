/* ================================================================
   SIEM Dashboard  —  Security Information & Event Management
   Darknode  |  prefix: sd-

   Operates on REAL logs the user pastes or uploads. Supported formats:
   syslog / auth.log, Apache/Nginx access logs (common & combined),
   and JSON lines. Every metric on this page — event counts, top source
   IPs, status-code distribution, failed-auth spikes, time series — is
   derived from the ACTUAL parsed input. There is no sample/random data.
   ================================================================ */
import { esc } from "/js/shared.js";

function sdToast(msg, type) { try { (window.showToast || function () {})(msg, type || "info"); } catch (_) {} }

/* ---------- colour constants ---------- */
const SEV_COLORS = {
  critical: "#dc2626",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#22c55e",
  info:     "#64748b",
};
const SEV_ICONS = {
  critical: "[!!]",
  high:     "[!]",
  medium:   "[i]",
  low:      "[ok]",
  info:     "--",
};
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

const SAMPLE_LOGS = `Jan 15 09:21:44 web-prod-01 sshd[20481]: Failed password for invalid user admin from 203.0.113.42 port 55122 ssh2
Jan 15 09:21:46 web-prod-01 sshd[20483]: Failed password for root from 203.0.113.42 port 55124 ssh2
192.0.2.15 - - [15/Jan/2026:09:22:01 +0000] "GET /login HTTP/1.1" 200 1534 "-" "Mozilla/5.0"
192.0.2.15 - - [15/Jan/2026:09:22:05 +0000] "POST /admin HTTP/1.1" 403 221 "-" "curl/8.0"
198.51.100.7 - - [15/Jan/2026:09:22:09 +0000] "GET /../../etc/passwd HTTP/1.1" 404 0 "-" "nikto"
{"time":"2026-01-15T09:22:12Z","src_ip":"198.51.100.7","status":500,"msg":"unhandled exception in /api/users","level":"error"}`;

/* ================================================================
   LOG PARSERS  — turn raw text into structured events
   ================================================================ */
const IPV4_RE = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/;
const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
const ACCESS_RE = /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)[^"]*"\s+(\d{3})\s+(\d+|-)/;
const SYSLOG_RE = /^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\[]+?)(?:\[(\d+)\])?:\s+(.*)$/;

function parseAccessDate(s) {
  // 15/Jan/2026:09:22:01 +0000
  const m = /^(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})/.exec(s);
  if (!m) return null;
  const d = new Date(Date.UTC(+m[3], MONTHS[m[2]] != null ? MONTHS[m[2]] : 0, +m[1], +m[4], +m[5], +m[6]));
  return isNaN(d.getTime()) ? null : d;
}
function parseSyslogDate(s) {
  // "Jan 15 09:21:44" — syslog omits the year; assume current year.
  const m = /^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/.exec(s);
  if (!m) return null;
  const d = new Date(new Date().getFullYear(), MONTHS[m[1]] != null ? MONTHS[m[1]] : 0, +m[2], +m[3], +m[4], +m[5]);
  return isNaN(d.getTime()) ? null : d;
}
function coerceTime(v) {
  if (v == null) return null;
  if (typeof v === "number") { const d = new Date(v > 1e12 ? v : v * 1000); return isNaN(d.getTime()) ? null : d; }
  const d = new Date(v);
  return isNaN(d.getTime()) ? null : d;
}

function sevFromStatus(status) {
  if (status >= 500) return "high";
  if (status === 401 || status === 403) return "medium";
  if (status >= 400) return "medium";
  if (status >= 300) return "low";
  return "info";
}

function parseLine(line) {
  const raw = line;
  line = line.trim();
  if (!line) return null;

  /* ---- JSON lines ---- */
  if (line.charAt(0) === "{") {
    try {
      const o = JSON.parse(line);
      const ip = o.src_ip || o.ip || o.clientip || o.client_ip || o.remote_addr || o.source || "";
      const status = parseInt(o.status || o.status_code || o.response || o.statusCode, 10);
      const level = String(o.level || o.severity || "").toLowerCase();
      let sev = "info";
      if (!isNaN(status)) sev = sevFromStatus(status);
      if (level === "error" || level === "err" || level === "critical" || level === "crit") sev = "high";
      else if (level === "warn" || level === "warning") sev = "medium";
      const msg = String(o.msg || o.message || o.event || line);
      const user = o.user || o.username || o.account || "";
      const failedAuth = /fail|invalid|denied|unauthor/i.test(msg) && /login|auth|password|credential/i.test(msg);
      if (failedAuth) sev = "high";
      return {
        time: coerceTime(o.time || o.timestamp || o["@timestamp"] || o.date || o.ts),
        srcIp: ip ? String(ip).match(IPV4_RE) ? String(ip).match(IPV4_RE)[1] : String(ip) : "",
        dstHost: o.host || o.hostname || o.server || "",
        user: user ? String(user) : "",
        method: o.method || "", path: o.path || o.url || o.uri || "",
        status: isNaN(status) ? null : status,
        process: "", sev: sev,
        type: !isNaN(status) ? ("HTTP " + status) : (failedAuth ? "Auth Failure" : "JSON Event"),
        msg: msg, failedAuth: failedAuth, format: "json", raw: raw,
      };
    } catch (_) { /* fall through to other parsers */ }
  }

  /* ---- Apache / Nginx access log ---- */
  const am = ACCESS_RE.exec(line);
  if (am) {
    const status = parseInt(am[5], 10);
    const sev = sevFromStatus(status);
    return {
      time: parseAccessDate(am[2]),
      srcIp: am[1].match(IPV4_RE) ? am[1].match(IPV4_RE)[1] : am[1],
      dstHost: "", user: "", method: am[3], path: am[4],
      status: isNaN(status) ? null : status, bytes: am[6] === "-" ? 0 : +am[6],
      process: "", sev: sev,
      type: "HTTP " + status,
      msg: am[3] + " " + am[4] + " -> " + status,
      failedAuth: status === 401 || status === 403, format: "access", raw: raw,
    };
  }

  /* ---- syslog / auth.log ---- */
  const sm = SYSLOG_RE.exec(line);
  if (sm) {
    const msg = sm[5];
    const proc = sm[3].trim();
    const ipm = msg.match(/from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/) || msg.match(IPV4_RE);
    const userm = msg.match(/(?:invalid user|user|for)\s+([A-Za-z0-9_.\-]+)\s+from/) || msg.match(/for\s+([A-Za-z0-9_.\-]+)/);
    const failedAuth = /failed password|authentication failure|invalid user|failed publickey|failed login|auth(entication)? fail/i.test(msg);
    let sev = "info";
    if (failedAuth) sev = "high";
    else if (/error|fatal|segfault|panic|denied|refused/i.test(msg)) sev = "medium";
    else if (/accepted password|session opened|started|success/i.test(msg)) sev = "low";
    return {
      time: parseSyslogDate(sm[1]),
      srcIp: ipm ? ipm[1] : "",
      dstHost: sm[2], user: userm ? userm[1] : "",
      method: "", path: "", status: null, process: proc, sev: sev,
      type: failedAuth ? "Auth Failure" : (proc ? proc : "System"),
      msg: msg, failedAuth: failedAuth, format: "syslog", raw: raw,
    };
  }

  /* ---- generic fallback: keep the line, pull any IP ---- */
  const gip = line.match(IPV4_RE);
  const failedAuth = /failed password|authentication failure|invalid user|login failed/i.test(line);
  return {
    time: null, srcIp: gip ? gip[1] : "", dstHost: "", user: "",
    method: "", path: "", status: null, process: "",
    sev: failedAuth ? "high" : (/error|fatal|denied/i.test(line) ? "medium" : "info"),
    type: failedAuth ? "Auth Failure" : "Log Line",
    msg: line, failedAuth: failedAuth, format: "raw", raw: raw,
  };
}

function parseLogs(text) {
  const out = [];
  String(text || "").split(/\r?\n/).forEach(function (ln) {
    const e = parseLine(ln);
    if (e) out.push(e);
  });
  return out;
}

/* ---------- CSS ---------- */
const STYLE = `
/* ===== SIEM DASHBOARD — sd- prefix ===== */
.sd-wrap{font-family:system-ui,-apple-system,sans-serif;color:var(--txt,#c8d6e5);max-width:1100px;margin:0 auto;padding:20px 0}
.sd-hdr{display:flex;align-items:center;gap:14px;margin-bottom:18px;flex-wrap:wrap}
.sd-hdr h2{margin:0;font-size:1.45rem;font-weight:700;letter-spacing:-.02em}
.sd-hdr .sd-sim-note{font-size:.75rem;color:var(--mut,#94a3b8)}
.sd-hdr .sd-badge{background:var(--acc,#2563eb);color:#fff;font-size:.65rem;padding:2px 8px;border-radius:9999px;font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.sd-tabs{display:flex;gap:4px;margin-bottom:18px;border-bottom:1px solid var(--line,#1e293b);padding-bottom:0;flex-wrap:wrap}
.sd-tab{background:none;border:none;color:var(--mut,#64748b);font-size:.82rem;padding:8px 16px;cursor:pointer;border-bottom:2px solid transparent;transition:color .15s,border-color .15s;font-weight:500}
.sd-tab:hover{color:var(--txt,#c8d6e5)}
.sd-tab.active{color:var(--acc,#2563eb);border-bottom-color:var(--acc,#2563eb)}
.sd-panel{display:none}
.sd-panel.active{display:block}

/* cards */
.sd-card{background:var(--card,#0d1117);border:1px solid var(--line,#1e293b);border-radius:10px;padding:16px 18px;margin-bottom:14px}
.sd-card h3{margin:0 0 10px;font-size:.95rem;font-weight:600}
.sd-row{display:flex;gap:12px;flex-wrap:wrap}
.sd-row>.sd-card{flex:1;min-width:220px}

/* ingest */
.sd-ingest-area{width:100%;min-height:200px;background:var(--card2,#080c14);color:var(--txt,#c8d6e5);border:1px solid var(--line,#1e293b);border-radius:6px;padding:12px;font-family:monospace;font-size:.76rem;line-height:1.5;resize:vertical}
.sd-ingest-controls{display:flex;gap:10px;align-items:center;margin-top:12px;flex-wrap:wrap}
.sd-ingest-controls button,.sd-ingest-controls label.sd-file{background:var(--card2,#080c14);color:var(--txt,#c8d6e5);border:1px solid var(--line,#1e293b);border-radius:4px;padding:7px 14px;font-size:.78rem;cursor:pointer}
.sd-ingest-controls button:hover,.sd-ingest-controls label.sd-file:hover{border-color:var(--acc,#2563eb)}
.sd-ingest-controls .sd-primary{background:var(--acc,#2563eb);color:#fff;border-color:var(--acc,#2563eb)}
.sd-ingest-controls .sd-parsed{margin-left:auto;font-size:.75rem;color:var(--mut,#64748b)}
.sd-hint{font-size:.74rem;color:var(--mut,#64748b);margin:8px 0 0;line-height:1.6}

/* live feed */
.sd-feed-controls{display:flex;gap:10px;align-items:center;margin-bottom:12px;flex-wrap:wrap}
.sd-feed-controls select,.sd-feed-controls button{background:var(--card2,#080c14);color:var(--txt,#c8d6e5);border:1px solid var(--line,#1e293b);border-radius:4px;padding:6px 12px;font-size:.78rem;cursor:pointer}
.sd-feed-controls button:hover{border-color:var(--acc,#2563eb)}
.sd-feed-controls .sd-count{margin-left:auto;font-size:.75rem;color:var(--mut,#64748b)}
.sd-feed-log{max-height:480px;overflow-y:auto;display:flex;flex-direction:column;gap:2px}
.sd-evt{display:grid;grid-template-columns:28px 150px 120px 140px 1fr;gap:8px;align-items:center;padding:7px 10px;border-radius:6px;font-size:.78rem;background:var(--card2,#080c14);border-left:3px solid transparent;transition:background .15s}
.sd-evt:hover{background:var(--card,#0d1117)}
.sd-evt .sd-sev-icon{font-size:.95rem;text-align:center}
.sd-evt .sd-ts{color:var(--mut,#64748b);font-family:monospace;font-size:.72rem}
.sd-evt .sd-ip{font-family:monospace;font-size:.74rem}
.sd-evt .sd-etype{font-weight:600;font-size:.73rem}
.sd-evt .sd-msg{color:var(--txt,#c8d6e5);font-size:.76rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sd-sev-critical{border-left-color:#dc2626}
.sd-sev-high{border-left-color:#f97316}
.sd-sev-medium{border-left-color:#eab308}
.sd-sev-low{border-left-color:#22c55e}
.sd-sev-info{border-left-color:#64748b}
.sd-sev-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}

/* alerts table */
.sd-alert-tbl{width:100%;border-collapse:collapse;font-size:.8rem}
.sd-alert-tbl th{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line,#1e293b);color:var(--mut,#64748b);font-weight:600;font-size:.72rem;text-transform:uppercase;letter-spacing:.04em}
.sd-alert-tbl td{padding:8px 10px;border-bottom:1px solid var(--line,#1e293b)}
.sd-alert-tbl tr:hover{background:var(--card2,#080c14)}
.sd-sev-pill{display:inline-block;padding:2px 10px;border-radius:9999px;font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.03em;color:#fff}

/* correlation */
.sd-rule{display:grid;grid-template-columns:1fr auto;gap:12px;align-items:start;padding:14px 16px;background:var(--card2,#080c14);border-radius:8px;margin-bottom:8px;border:1px solid var(--line,#1e293b)}
.sd-rule-hdr{display:flex;align-items:center;gap:10px}
.sd-rule-name{font-weight:600;font-size:.88rem}
.sd-rule-id{color:var(--mut,#64748b);font-size:.72rem;font-family:monospace}
.sd-rule-cond{color:var(--mut,#64748b);font-size:.78rem;margin-top:4px}
.sd-rule-action{color:var(--acc,#2563eb);font-size:.76rem;margin-top:2px}
.sd-rule-stats{display:flex;gap:16px;font-size:.74rem;color:var(--mut,#64748b);margin-top:6px;flex-wrap:wrap}
.sd-rule-stats span{display:flex;align-items:center;gap:4px}
.sd-rule-match{font-size:1.25rem;font-weight:700;text-align:right;font-variant-numeric:tabular-nums}

/* sources */
.sd-src{display:grid;grid-template-columns:1fr 110px 90px 120px;gap:10px;align-items:center;padding:12px 16px;background:var(--card2,#080c14);border-radius:8px;margin-bottom:6px;font-size:.8rem;border:1px solid var(--line,#1e293b)}
.sd-src-name{font-weight:600}
.sd-src-status{display:flex;align-items:center;gap:6px;font-size:.76rem;font-weight:500}
.sd-src-eps{font-family:monospace;text-align:right;font-size:.78rem}
.sd-src-last{color:var(--mut,#64748b);font-size:.74rem;text-align:right}
.sd-src-bar{height:4px;background:var(--line,#1e293b);border-radius:2px;margin-top:6px;overflow:hidden}
.sd-src-bar-fill{height:100%;border-radius:2px;transition:width .5s}

/* analytics */
.sd-analytics-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:700px){.sd-analytics-grid{grid-template-columns:1fr} .sd-evt{grid-template-columns:28px 1fr;} .sd-evt .sd-ts,.sd-evt .sd-ip,.sd-evt .sd-etype{display:none}}
.sd-bar-chart{display:flex;align-items:flex-end;gap:4px;height:120px;padding-top:8px}
.sd-bar{flex:1;background:var(--acc,#2563eb);border-radius:4px 4px 0 0;min-width:0;position:relative;transition:height .3s;opacity:.75}
.sd-bar:hover{opacity:1}
.sd-bar-label{position:absolute;bottom:-20px;left:50%;transform:translateX(-50%);font-size:.56rem;color:var(--mut,#64748b);white-space:nowrap}
.sd-bar-val{position:absolute;top:-18px;left:50%;transform:translateX(-50%);font-size:.62rem;color:var(--txt,#c8d6e5);white-space:nowrap}
.sd-stat-row{display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid var(--line,#1e293b);font-size:.78rem}
.sd-stat-row:last-child{border-bottom:none}
.sd-stat-bar-bg{flex:1;background:var(--line,#1e293b);border-radius:4px;height:8px;margin:0 10px;overflow:hidden;align-self:center}
.sd-stat-bar-fill{height:100%;border-radius:4px;transition:width .3s}

/* summary strip */
.sd-summary{display:flex;gap:12px;margin-bottom:14px;flex-wrap:wrap}
.sd-summary-card{flex:1;min-width:130px;background:var(--card,#0d1117);border:1px solid var(--line,#1e293b);border-radius:8px;padding:12px 14px;text-align:center}
.sd-summary-card .sd-sum-val{font-size:1.5rem;font-weight:700;line-height:1}
.sd-summary-card .sd-sum-lbl{font-size:.7rem;color:var(--mut,#64748b);margin-top:4px;text-transform:uppercase;letter-spacing:.04em}

/* alert detail row */
.sd-alert-count{display:flex;gap:12px;margin-bottom:14px;flex-wrap:wrap}
.sd-alert-count-item{display:flex;align-items:center;gap:6px;font-size:.78rem}
.sd-alert-count-item .sd-count-num{font-weight:700;font-size:1.1rem}

/* empty state */
.sd-empty{text-align:center;padding:40px 20px;color:var(--mut,#64748b);font-size:.85rem;line-height:1.7}

/* scrollbar styling */
.sd-feed-log::-webkit-scrollbar{width:6px}
.sd-feed-log::-webkit-scrollbar-track{background:transparent}
.sd-feed-log::-webkit-scrollbar-thumb{background:var(--line,#1e293b);border-radius:3px}
.sd-feed-log::-webkit-scrollbar-thumb:hover{background:var(--mut,#64748b)}

/* ---------- pro-theme overrides ---------- */
[data-style="pro"] .sd-wrap{color:#1e293b}
[data-style="pro"] .sd-card{background:#fff;border-color:#e2e8f0}
[data-style="pro"] .sd-evt{background:#f8fafc}
[data-style="pro"] .sd-evt:hover{background:#f1f5f9}
[data-style="pro"] .sd-evt .sd-msg{color:#1e293b}
[data-style="pro"] .sd-tab{color:#64748b}
[data-style="pro"] .sd-tab.active{color:#2563eb;border-bottom-color:#2563eb}
[data-style="pro"] .sd-feed-controls select,[data-style="pro"] .sd-feed-controls button,[data-style="pro"] .sd-ingest-area,[data-style="pro"] .sd-ingest-controls button,[data-style="pro"] .sd-ingest-controls label.sd-file{background:#fff;color:#1e293b;border-color:#e2e8f0}
[data-style="pro"] .sd-ingest-controls .sd-primary{background:#2563eb;color:#fff}
[data-style="pro"] .sd-alert-tbl tr:hover{background:#f1f5f9}
[data-style="pro"] .sd-rule{background:#f8fafc;border-color:#e2e8f0}
[data-style="pro"] .sd-src{background:#f8fafc;border-color:#e2e8f0}
[data-style="pro"] .sd-bar{background:#2563eb}
[data-style="pro"] .sd-stat-bar-bg{background:#e2e8f0}
[data-style="pro"] .sd-tabs{border-bottom-color:#e2e8f0}
[data-style="pro"] .sd-alert-tbl th{border-bottom-color:#e2e8f0;color:#64748b}
[data-style="pro"] .sd-alert-tbl td{border-bottom-color:#e2e8f0}
[data-style="pro"] .sd-stat-row{border-bottom-color:#e2e8f0}
[data-style="pro"] .sd-summary-card{background:#fff;border-color:#e2e8f0}
[data-style="pro"] .sd-src-bar{background:#e2e8f0}
[data-style="pro"] .sd-feed-log::-webkit-scrollbar-thumb{background:#cbd5e1}
[data-style="pro"] .sd-alert-count-item{color:#334155}
`;

function fmtTs(d) {
  if (!d) return "—";
  const p = (v) => String(v).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/* ================================================================
   RENDER
   ================================================================ */
export function renderSiemDash(container) {
  /* cleanup any legacy intervals from a previous build */
  if (container._sdCleanup) { try { container._sdCleanup(); } catch (_) {} container._sdCleanup = null; }

  const TABS = [
    { id: "ingest",      label: "Log Ingest" },
    { id: "feed",        label: "Event Feed" },
    { id: "alerts",      label: "Alerts" },
    { id: "correlation", label: "Correlation" },
    { id: "sources",     label: "Sources" },
    { id: "analytics",   label: "Analytics" },
  ];

  /* ---- state (all derived from real input) ---- */
  let activeTab = "ingest";
  let rawText = "";
  let events = [];
  let filterSev = "all";

  container.innerHTML = `<style>${STYLE}</style>
  <div class="sd-wrap">
    <div class="sd-hdr">
      <h2>SIEM Dashboard</h2>
      <span class="sd-sim-note">All metrics are derived from the logs you paste or upload — no sample or generated data.</span>
    </div>
    <div class="sd-tabs">${TABS.map(t => `<button class="sd-tab${t.id === activeTab ? " active" : ""}" data-tab="${t.id}">${esc(t.label)}</button>`).join("")}</div>
    <div id="sd-content"></div>
  </div>`;

  const wrap = container.querySelector(".sd-wrap");
  const content = container.querySelector("#sd-content");

  wrap.querySelector(".sd-tabs").addEventListener("click", (e) => {
    const btn = e.target.closest(".sd-tab");
    if (!btn) return;
    activeTab = btn.dataset.tab;
    wrap.querySelectorAll(".sd-tab").forEach(b => b.classList.toggle("active", b.dataset.tab === activeTab));
    renderTab();
  });

  function renderTab() {
    if (activeTab === "ingest") renderIngest();
    else if (activeTab === "feed") renderFeed();
    else if (activeTab === "alerts") renderAlerts();
    else if (activeTab === "correlation") renderCorrelation();
    else if (activeTab === "sources") renderSources();
    else if (activeTab === "analytics") renderAnalytics();
  }

  function emptyState(msg) {
    return `<div class="sd-card"><div class="sd-empty">${msg}</div></div>`;
  }
  const NO_DATA = 'No logs parsed yet. Open the <strong>Log Ingest</strong> tab and paste or upload logs to begin.';

  /* ================ INGEST ================ */
  function renderIngest() {
    content.innerHTML = `
      <div class="sd-card">
        <h3>Ingest Logs</h3>
        <p class="sd-hint" style="margin-top:0">Paste raw log text or upload a file. Supported: syslog / auth.log, Apache &amp; Nginx access logs (common/combined), and JSON lines. Everything stays in your browser.</p>
        <textarea class="sd-ingest-area" id="sd-log-input" placeholder="Paste log lines here...">${esc(rawText)}</textarea>
        <div class="sd-ingest-controls">
          <button class="sd-primary" id="sd-parse">Parse Logs</button>
          <label class="sd-file">Upload file<input type="file" id="sd-file" accept=".log,.txt,.json,.out,text/*" style="display:none"></label>
          <button id="sd-sample">Load example</button>
          <button id="sd-clear">Clear</button>
          <span class="sd-parsed">${events.length ? events.length.toLocaleString() + " events parsed" : "no events yet"}</span>
        </div>
        <p class="sd-hint">Derived views: event feed, derived alerts (brute-force, HTTP error surges, path scanning), correlation matches, per-source breakdown, and analytics (time series, severity, top IPs, status codes).</p>
      </div>`;

    const ta = content.querySelector("#sd-log-input");
    content.querySelector("#sd-parse").addEventListener("click", () => {
      rawText = ta.value;
      events = parseLogs(rawText);
      if (!events.length) { sdToast("No log lines found to parse.", "error"); }
      else { sdToast(events.length + " events parsed.", "success"); activeTab = "feed"; wrap.querySelectorAll(".sd-tab").forEach(b => b.classList.toggle("active", b.dataset.tab === activeTab)); }
      renderTab();
    });
    content.querySelector("#sd-sample").addEventListener("click", () => { ta.value = SAMPLE_LOGS; });
    content.querySelector("#sd-clear").addEventListener("click", () => { ta.value = ""; rawText = ""; events = []; renderIngest(); });
    content.querySelector("#sd-file").addEventListener("change", (e) => {
      const f = e.target.files && e.target.files[0];
      if (!f) return;
      const reader = new FileReader();
      reader.onload = () => { ta.value = String(reader.result || ""); sdToast("File loaded — click Parse Logs.", "info"); };
      reader.onerror = () => sdToast("Could not read that file.", "error");
      reader.readAsText(f);
    });
  }

  function sevCounts() {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    events.forEach(e => { c[e.sev] = (c[e.sev] || 0) + 1; });
    return c;
  }
  function uniqueIps() {
    const s = {};
    events.forEach(e => { if (e.srcIp) s[e.srcIp] = 1; });
    return Object.keys(s);
  }

  /* ================ EVENT FEED ================ */
  function renderFeed() {
    if (!events.length) { content.innerHTML = emptyState(NO_DATA); return; }
    const counts = sevCounts();
    const failed = events.filter(e => e.failedAuth).length;
    const filtered = filterSev === "all" ? events : events.filter(e => e.sev === filterSev);
    content.innerHTML = `
      <div class="sd-summary">
        <div class="sd-summary-card"><div class="sd-sum-val">${events.length.toLocaleString()}</div><div class="sd-sum-lbl">Total Events</div></div>
        <div class="sd-summary-card"><div class="sd-sum-val" style="color:${SEV_COLORS.high}">${counts.high}</div><div class="sd-sum-lbl">High</div></div>
        <div class="sd-summary-card"><div class="sd-sum-val" style="color:${SEV_COLORS.medium}">${counts.medium}</div><div class="sd-sum-lbl">Medium</div></div>
        <div class="sd-summary-card"><div class="sd-sum-val" style="color:${SEV_COLORS.high}">${failed}</div><div class="sd-sum-lbl">Failed Auth</div></div>
        <div class="sd-summary-card"><div class="sd-sum-val">${uniqueIps().length}</div><div class="sd-sum-lbl">Unique IPs</div></div>
      </div>
      <div class="sd-card">
        <div class="sd-feed-controls">
          <select id="sd-sev-filter">
            <option value="all"${filterSev === "all" ? " selected" : ""}>All Severities</option>
            ${SEV_ORDER.map(s => `<option value="${s}"${filterSev === s ? " selected" : ""}>${s.charAt(0).toUpperCase() + s.slice(1)} (${counts[s]})</option>`).join("")}
          </select>
          <span class="sd-count">${filtered.length} of ${events.length} events</span>
        </div>
        <div class="sd-feed-log" id="sd-feed-log">
          ${filtered.length === 0 ? '<div class="sd-empty">No events match the current filter.</div>' : filtered.slice(0, 500).map(evtRow).join("")}
        </div>
      </div>`;
    content.querySelector("#sd-sev-filter").addEventListener("change", (e) => { filterSev = e.target.value; renderFeed(); });
  }

  function evtRow(e) {
    return `<div class="sd-evt sd-sev-${e.sev}">
      <span class="sd-sev-icon">${SEV_ICONS[e.sev]}</span>
      <span class="sd-ts">${esc(fmtTs(e.time))}</span>
      <span class="sd-ip">${esc(e.srcIp || "—")}</span>
      <span class="sd-etype" style="color:${SEV_COLORS[e.sev]}">${esc(e.type)}</span>
      <span class="sd-msg">${esc(e.msg)}</span>
    </div>`;
  }

  /* ================ DERIVED ALERTS ================ */
  function deriveAlerts() {
    const alerts = [];
    // group helpers
    const failedByIp = {}, status5xxByIp = {}, pathsByIp = {};
    events.forEach(e => {
      if (e.failedAuth && e.srcIp) (failedByIp[e.srcIp] = failedByIp[e.srcIp] || []).push(e);
      if (e.status >= 500 && e.srcIp) (status5xxByIp[e.srcIp] = status5xxByIp[e.srcIp] || []).push(e);
      if (e.status === 404 && e.srcIp) { (pathsByIp[e.srcIp] = pathsByIp[e.srcIp] || {}); if (e.path) pathsByIp[e.srcIp][e.path] = 1; }
    });
    function span(list) {
      const ts = list.map(x => x.time).filter(Boolean).sort((a, b) => a - b);
      return ts.length ? fmtTs(ts[0]) + " → " + fmtTs(ts[ts.length - 1]) : "no timestamps";
    }
    Object.keys(failedByIp).forEach(ip => { if (failedByIp[ip].length >= 5) alerts.push({ sev: "high", host: ip, rule: "Failed-auth burst (" + failedByIp[ip].length + " failures)", mitre: "T1110", detail: span(failedByIp[ip]) }); });
    Object.keys(status5xxByIp).forEach(ip => { if (status5xxByIp[ip].length >= 10) alerts.push({ sev: "medium", host: ip, rule: "HTTP 5xx surge (" + status5xxByIp[ip].length + " errors)", mitre: "T1499", detail: span(status5xxByIp[ip]) }); });
    Object.keys(pathsByIp).forEach(ip => { const n = Object.keys(pathsByIp[ip]).length; if (n >= 15) alerts.push({ sev: "medium", host: ip, rule: "Path scanning (" + n + " distinct 404 paths)", mitre: "T1595", detail: "" }); });
    alerts.sort((a, b) => SEV_ORDER.indexOf(a.sev) - SEV_ORDER.indexOf(b.sev));
    return alerts;
  }

  function renderAlerts() {
    if (!events.length) { content.innerHTML = emptyState(NO_DATA); return; }
    const alerts = deriveAlerts();
    const bySev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    alerts.forEach(a => bySev[a.sev]++);
    if (!alerts.length) {
      content.innerHTML = emptyState('No correlation thresholds were crossed in this input.<br>Alerts are raised for failed-auth bursts (5+/IP), HTTP 5xx surges (10+/IP) and path scanning (15+ distinct 404s/IP).');
      return;
    }
    content.innerHTML = `
      <div class="sd-alert-count">
        <div class="sd-alert-count-item"><span class="sd-count-num" style="color:#f97316">${bySev.high}</span><span>High</span></div>
        <div class="sd-alert-count-item"><span class="sd-count-num" style="color:#eab308">${bySev.medium}</span><span>Medium</span></div>
        <div class="sd-alert-count-item" style="margin-left:auto"><span class="sd-count-num">${alerts.length}</span><span>Total Derived Alerts</span></div>
      </div>
      <div class="sd-card">
        <h3>Derived Alerts</h3>
        <table class="sd-alert-tbl">
          <thead><tr><th>Severity</th><th>Source</th><th>Correlation</th><th>MITRE</th><th>Window</th></tr></thead>
          <tbody>
            ${alerts.map(a => `<tr>
              <td><span class="sd-sev-pill" style="background:${SEV_COLORS[a.sev]}">${esc(a.sev)}</span></td>
              <td style="font-family:monospace;font-size:.76rem">${esc(a.host)}</td>
              <td>${esc(a.rule)}</td>
              <td style="color:var(--acc,#2563eb);font-size:.76rem">${esc(a.mitre)}</td>
              <td style="color:var(--mut,#64748b);font-size:.74rem">${esc(a.detail)}</td>
            </tr>`).join("")}
          </tbody>
        </table>
      </div>`;
  }

  /* ================ CORRELATION ================ */
  function renderCorrelation() {
    if (!events.length) { content.innerHTML = emptyState(NO_DATA); return; }
    const failedByIp = {}, s5xxByIp = {}, p404ByIp = {};
    let authFailTotal = 0;
    events.forEach(e => {
      if (e.failedAuth) { authFailTotal++; if (e.srcIp) failedByIp[e.srcIp] = (failedByIp[e.srcIp] || 0) + 1; }
      if (e.status >= 500 && e.srcIp) s5xxByIp[e.srcIp] = (s5xxByIp[e.srcIp] || 0) + 1;
      if (e.status === 404 && e.srcIp && e.path) { (p404ByIp[e.srcIp] = p404ByIp[e.srcIp] || {})[e.path] = 1; }
    });
    const bruteIps = Object.keys(failedByIp).filter(ip => failedByIp[ip] >= 5);
    const surgeIps = Object.keys(s5xxByIp).filter(ip => s5xxByIp[ip] >= 10);
    const scanIps = Object.keys(p404ByIp).filter(ip => Object.keys(p404ByIp[ip]).length >= 15);

    const rules = [
      { id: "CR-01", name: "Brute Force Detection", cond: "5+ failed authentications from the same source IP", mitre: "T1110", matches: bruteIps.length, hits: bruteIps },
      { id: "CR-02", name: "Authentication Failure Volume", cond: "Total failed-auth events across all sources", mitre: "T1110.001", matches: authFailTotal, hits: [] },
      { id: "CR-03", name: "HTTP Error Surge", cond: "10+ HTTP 5xx responses to the same source IP", mitre: "T1499", matches: surgeIps.length, hits: surgeIps },
      { id: "CR-04", name: "Path Scanning / Enumeration", cond: "15+ distinct 404 paths from the same source IP", mitre: "T1595", matches: scanIps.length, hits: scanIps },
    ];

    content.innerHTML = `
      <div class="sd-card">
        <h3>Correlation Engine — run against your parsed events</h3>
        <p class="sd-hint" style="margin-top:0">Each rule is evaluated against the ${events.length.toLocaleString()} parsed events. Match counts are real.</p>
        <div id="sd-rules-list">
          ${rules.map(r => `
            <div class="sd-rule">
              <div>
                <div class="sd-rule-hdr"><span class="sd-rule-id">${esc(r.id)}</span><span class="sd-rule-name">${esc(r.name)}</span></div>
                <div class="sd-rule-cond">IF ${esc(r.cond)}</div>
                <div class="sd-rule-stats">
                  <span style="color:var(--acc,#2563eb)">MITRE: ${esc(r.mitre)}</span>
                  ${r.hits && r.hits.length ? `<span>Matched: ${esc(r.hits.slice(0, 6).join(", "))}${r.hits.length > 6 ? " +" + (r.hits.length - 6) + " more" : ""}</span>` : ""}
                </div>
              </div>
              <div class="sd-rule-match" style="color:${r.matches > 0 ? SEV_COLORS.high : "var(--mut,#64748b)"}">${r.matches}</div>
            </div>`).join("")}
        </div>
      </div>`;
  }

  /* ================ SOURCES ================ */
  function renderSources() {
    if (!events.length) { content.innerHTML = emptyState(NO_DATA); return; }
    const FORMAT_LABELS = { access: "Web Access Log (Apache/Nginx)", syslog: "Syslog / auth.log", json: "JSON Lines", raw: "Unstructured / Other" };
    const groups = {};
    events.forEach(e => {
      const key = e.format || "raw";
      const g = groups[key] || (groups[key] = { count: 0, last: null, sev: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } });
      g.count++; g.sev[e.sev]++;
      if (e.time && (!g.last || e.time > g.last)) g.last = e.time;
    });
    const keys = Object.keys(groups).sort((a, b) => groups[b].count - groups[a].count);
    const maxCount = Math.max(...keys.map(k => groups[k].count), 1);
    content.innerHTML = `
      <div class="sd-summary">
        <div class="sd-summary-card"><div class="sd-sum-val">${keys.length}</div><div class="sd-sum-lbl">Log Formats</div></div>
        <div class="sd-summary-card"><div class="sd-sum-val">${events.length.toLocaleString()}</div><div class="sd-sum-lbl">Total Events</div></div>
        <div class="sd-summary-card"><div class="sd-sum-val">${uniqueIps().length}</div><div class="sd-sum-lbl">Unique IPs</div></div>
      </div>
      <div class="sd-card">
        <h3>Detected Log Sources</h3>
        <div class="sd-src" style="font-weight:600;background:transparent;border:none;color:var(--mut,#64748b);font-size:.72rem;text-transform:uppercase;letter-spacing:.04em">
          <span>Source Format</span><span>High/Med</span><span style="text-align:right">Events</span><span style="text-align:right">Last Event</span>
        </div>
        ${keys.map(k => {
          const g = groups[k];
          const pct = ((g.count / maxCount) * 100).toFixed(0);
          return `<div class="sd-src">
            <div><span class="sd-src-name">${esc(FORMAT_LABELS[k] || k)}</span>
              <div class="sd-src-bar"><div class="sd-src-bar-fill" style="width:${pct}%;background:${SEV_COLORS.info}"></div></div></div>
            <span class="sd-src-status"><span style="color:${SEV_COLORS.high}">${g.sev.high}</span> / <span style="color:${SEV_COLORS.medium}">${g.sev.medium}</span></span>
            <span class="sd-src-eps">${g.count.toLocaleString()}</span>
            <span class="sd-src-last">${esc(fmtTs(g.last))}</span>
          </div>`;
        }).join("")}
      </div>`;
  }

  /* ================ ANALYTICS ================ */
  function renderAnalytics() {
    if (!events.length) { content.innerHTML = emptyState(NO_DATA); return; }
    const sev = sevCounts();
    const total = events.length;

    // time series — bucket across the observed span (up to 24 buckets)
    const times = events.map(e => e.time).filter(Boolean).sort((a, b) => a - b);
    let seriesHtml;
    if (times.length < 2) {
      seriesHtml = '<div class="sd-empty" style="padding:20px">Not enough timestamps parsed to build a time series.</div>';
    } else {
      const t0 = times[0].getTime(), t1 = times[times.length - 1].getTime();
      const N = 24, span = Math.max(1, t1 - t0), bw = span / N;
      const buckets = new Array(N).fill(0);
      events.forEach(e => { if (e.time) { let i = Math.floor((e.time.getTime() - t0) / bw); if (i >= N) i = N - 1; if (i < 0) i = 0; buckets[i]++; } });
      const maxB = Math.max(...buckets, 1);
      const p = (v) => String(v).padStart(2, "0");
      seriesHtml = `<div class="sd-bar-chart">${buckets.map((v, i) => {
        const h = Math.max(3, (v / maxB) * 100);
        const bt = new Date(t0 + i * bw);
        return `<div class="sd-bar" style="height:${h}%" title="${esc(fmtTs(bt))}: ${v} events"><span class="sd-bar-val">${v || ""}</span><span class="sd-bar-label">${p(bt.getHours())}:${p(bt.getMinutes())}</span></div>`;
      }).join("")}</div>`;
    }

    // top IPs
    const ipHits = {};
    events.forEach(e => { if (e.srcIp) ipHits[e.srcIp] = (ipHits[e.srcIp] || 0) + 1; });
    const topIps = Object.entries(ipHits).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const maxIp = topIps.length ? topIps[0][1] : 1;

    // status codes
    const statusHits = {};
    events.forEach(e => { if (e.status != null) { const k = String(e.status); statusHits[k] = (statusHits[k] || 0) + 1; } });
    const topStatus = Object.entries(statusHits).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const maxStatus = topStatus.length ? topStatus[0][1] : 1;
    function statusColor(code) { const c = parseInt(code, 10); return c >= 500 ? SEV_COLORS.high : c >= 400 ? SEV_COLORS.medium : c >= 300 ? SEV_COLORS.low : SEV_COLORS.info; }

    content.innerHTML = `
      <div class="sd-card">
        <h3>Events over time (${times.length} timestamped events)</h3>
        ${seriesHtml}
      </div>
      <div class="sd-analytics-grid">
        <div class="sd-card">
          <h3>Severity Distribution</h3>
          ${SEV_ORDER.map(s => {
            const pct = ((sev[s] / total) * 100).toFixed(1);
            return `<div class="sd-stat-row">
              <span><span class="sd-sev-dot" style="background:${SEV_COLORS[s]}"></span>${s.charAt(0).toUpperCase() + s.slice(1)}</span>
              <div class="sd-stat-bar-bg"><div class="sd-stat-bar-fill" style="width:${pct}%;background:${SEV_COLORS[s]}"></div></div>
              <span>${sev[s]} (${pct}%)</span>
            </div>`;
          }).join("")}
        </div>
        <div class="sd-card">
          <h3>Status-Code Distribution</h3>
          ${topStatus.length === 0 ? '<div class="sd-empty" style="padding:16px">No HTTP status codes in this input.</div>' : topStatus.map(([code, cnt]) => {
            const pct = ((cnt / maxStatus) * 100).toFixed(0);
            return `<div class="sd-stat-row">
              <span style="font-family:monospace">${esc(code)}</span>
              <div class="sd-stat-bar-bg"><div class="sd-stat-bar-fill" style="width:${pct}%;background:${statusColor(code)}"></div></div>
              <span>${cnt}</span>
            </div>`;
          }).join("")}
        </div>
        <div class="sd-card">
          <h3>Top Source IPs</h3>
          ${topIps.length === 0 ? '<div class="sd-empty" style="padding:16px">No source IPs found in this input.</div>' : topIps.map(([ip, cnt]) => {
            const pct = ((cnt / maxIp) * 100).toFixed(0);
            return `<div class="sd-stat-row">
              <span style="font-family:monospace;font-size:.76rem">${esc(ip)}</span>
              <div class="sd-stat-bar-bg"><div class="sd-stat-bar-fill" style="width:${pct}%;background:var(--acc,#2563eb)"></div></div>
              <span>${cnt}</span>
            </div>`;
          }).join("")}
        </div>
        <div class="sd-card">
          <h3>Failed Authentications</h3>
          ${(function () {
            const fByIp = {};
            events.forEach(e => { if (e.failedAuth && e.srcIp) fByIp[e.srcIp] = (fByIp[e.srcIp] || 0) + 1; });
            const rows = Object.entries(fByIp).sort((a, b) => b[1] - a[1]).slice(0, 10);
            if (!rows.length) return '<div class="sd-empty" style="padding:16px">No failed-auth events detected.</div>';
            const mx = rows[0][1];
            return rows.map(([ip, cnt]) => {
              const pct = ((cnt / mx) * 100).toFixed(0);
              return `<div class="sd-stat-row">
                <span style="font-family:monospace;font-size:.76rem">${esc(ip)}</span>
                <div class="sd-stat-bar-bg"><div class="sd-stat-bar-fill" style="width:${pct}%;background:${SEV_COLORS.high}"></div></div>
                <span>${cnt}</span>
              </div>`;
            }).join("");
          })()}
        </div>
      </div>`;
  }

  /* ---- initial render ---- */
  renderTab();
}
