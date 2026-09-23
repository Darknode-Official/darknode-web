/* ================================================================
   SIEM Dashboard  —  Security Information & Event Management
   Darknode  |  prefix: sd-
   ================================================================ */
import { esc } from "/js/shared.js";

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

/* ---------- sample data generators ---------- */
const IPS = [
  "10.0.1.34","192.168.4.17","172.16.0.99","10.10.5.201","203.0.113.42",
  "198.51.100.7","192.168.1.105","10.0.8.55","172.20.3.14","192.168.0.88",
  "45.33.32.156","185.220.101.34","91.219.236.222","104.248.50.87","23.129.64.100",
];
const HOSTS = [
  "dc01.corp.local","web-prod-01","db-master","fw-edge-01","vpn-gw-02",
  "mail-relay","k8s-node-03","soc-analyst-ws","dev-ci-runner","file-srv-02",
];
const USERS = [
  "admin","jdoe","svc_backup","root","analyst01",
  "deploy-bot","k.chen","m.rodriguez","t.nakamura","ops-svc",
];
const PORTS = [22, 80, 443, 3389, 8080, 445, 3306, 5432, 8443, 1433, 53, 161, 25, 587, 636];
const EVENT_TEMPLATES = [
  { sev: "critical", type: "Malware Detection",    msgs: ["Trojan.GenericKD detected in memory on {host}","Ransomware payload intercepted — encrypted staging observed on {host}","Rootkit signature match (CVE-2025-31337) on {host}","Cobalt Strike beacon identified on {host} — PID {n}","Fileless malware via PowerShell on {host}"] },
  { sev: "critical", type: "Privilege Escalation",  msgs: ["Unexpected SYSTEM token duplication by PID {n} on {host}","Local admin created via net.exe on {host}","Kernel exploit (CVE-2025-21310) privilege escalation on {host}","sudo to root by non-sudoer {user} on {host}"] },
  { sev: "critical", type: "Data Breach Indicator", msgs: ["Large data export ({n} MB) to external IP {ip} from {host}","Credentials database accessed by {user} on {host}","PII exfiltration pattern detected — {n} records queried on {host}"] },
  { sev: "high",     type: "Auth Failure Burst",    msgs: ["{n} failed SSH logins from {ip} in 30 s","Kerberos pre-auth failures spike — {n} attempts against {host}","RDP brute-force from {ip} — {n} failures","LDAP bind failures from {ip} — {n} attempts in 60 s"] },
  { sev: "high",     type: "IDS Alert",             msgs: ["Snort SID:2024891 — ET EXPLOIT attempt from {ip}","Suricata alert: lateral movement indicator from {ip}","WAF blocked SQL injection from {ip} targeting {host}","XSS payload detected in POST from {ip}"] },
  { sev: "high",     type: "Suspicious Process",    msgs: ["Mimikatz-like behavior detected on {host} by {user}","Reverse shell spawned on {host} — outbound to {ip}:443","Process hollowing detected on {host} — PID {n}"] },
  { sev: "medium",   type: "Port Scan",             msgs: ["SYN scan detected from {ip} — {n} ports in 10 s","Stealth FIN scan from {ip} targeting {host}","UDP sweep from {ip} on ports 53,161,500","XMAS scan from {ip} — {n} hosts probed"] },
  { sev: "medium",   type: "Policy Violation",      msgs: ["USB mass-storage mounted on {host} — policy block","Outbound DNS over HTTPS detected from {host}","Unauthorized VPN client on {host}","TOR exit node connection from {host}"] },
  { sev: "medium",   type: "Anomalous Traffic",     msgs: ["Unusual outbound volume from {host} — {n} MB in 5 min","DNS tunneling pattern from {host} to {ip}","ICMP tunnel suspected from {host}","Encrypted traffic to known C2 IP {ip}"] },
  { sev: "low",      type: "Config Change",         msgs: ["Firewall rule modified by admin@{host}","SNMP community string changed on {host}","SSH config modified on {host}","Audit policy changed by {user} on {host}"] },
  { sev: "low",      type: "Account Activity",      msgs: ["Service account svc_backup logged in interactively on {host}","User password reset for {user} on {host}","New user {user} added to Domain Admins on {host}","Account lockout for {user} on {host}"] },
  { sev: "info",     type: "System Event",          msgs: ["Agent heartbeat resumed on {host}","Log rotation completed on {host}","Certificate renewal succeeded for {host}","Patch scan completed on {host} — {n} updates available"] },
  { sev: "info",     type: "Network Event",         msgs: ["VPN tunnel established from {ip}","DHCP lease renewed for {host}","NTP sync completed on {host}","BGP peer {ip} state change to Established"] },
];

function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function randInt(a, b) { return a + Math.floor(Math.random() * (b - a + 1)); }
function ts(d) {
  const p = (v) => String(v).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function genEvent() {
  const tpl = pick(EVENT_TEMPLATES);
  const ip = pick(IPS);
  const host = pick(HOSTS);
  const user = pick(USERS);
  let msg = pick(tpl.msgs)
    .replace("{ip}", ip)
    .replace("{host}", host)
    .replace("{user}", user)
    .replace("{n}", String(randInt(5, 120)));
  return {
    id: crypto.randomUUID(),
    time: new Date(),
    sev: tpl.sev,
    type: tpl.type,
    srcIp: ip,
    dstHost: host,
    user,
    msg,
  };
}

/* ---------- sample alerts ---------- */
function sampleAlerts() {
  const now = Date.now();
  return [
    { id: "A001", sev: "critical", host: "dc01.corp.local",   rule: "Ransomware Behavior",          created: new Date(now - 3600e3*2),  status: "new" },
    { id: "A002", sev: "critical", host: "web-prod-01",       rule: "Web Shell Upload",              created: new Date(now - 3600e3*5),  status: "investigating" },
    { id: "A003", sev: "high",     host: "vpn-gw-02",         rule: "Brute Force — SSH",             created: new Date(now - 3600e3*1),  status: "new" },
    { id: "A004", sev: "high",     host: "k8s-node-03",       rule: "Container Escape Attempt",      created: new Date(now - 3600e3*8),  status: "investigating" },
    { id: "A005", sev: "medium",   host: "mail-relay",        rule: "Outbound C2 Beacon",            created: new Date(now - 3600e3*12), status: "new" },
    { id: "A006", sev: "medium",   host: "dev-ci-runner",     rule: "Secrets in Build Logs",         created: new Date(now - 3600e3*3),  status: "resolved" },
    { id: "A007", sev: "low",      host: "file-srv-02",       rule: "Excessive File Access",         created: new Date(now - 3600e3*24), status: "resolved" },
    { id: "A008", sev: "high",     host: "soc-analyst-ws",    rule: "Credential Dump — lsass",       created: new Date(now - 3600e3*0.5),status: "new" },
  ];
}

/* ---------- correlation rules ---------- */
const CORR_RULES = [
  { id: "CR-01", name: "Brute Force Detection",         cond: "3+ failed logins from same IP in 60 s",          action: "Raise Brute Force Alert",   mitre: "T1110",  matches: 47,  last: "2 min ago",  enabled: true },
  { id: "CR-02", name: "Port Scan Correlation",          cond: "Port scan from IP + auth failure within 5 min",  action: "Raise Recon Alert",         mitre: "T1046",  matches: 23,  last: "8 min ago",  enabled: true },
  { id: "CR-03", name: "Privilege Escalation Chain",     cond: "Failed auth then privilege escalation in 10 min",action: "Raise Compromise Alert",    mitre: "T1068",  matches: 5,   last: "1 hr ago",   enabled: true },
  { id: "CR-04", name: "Lateral Movement",               cond: "Login from internal IP to 3+ hosts in 5 min",   action: "Raise Lateral Mvmt Alert",  mitre: "T1021",  matches: 12,  last: "22 min ago", enabled: true },
  { id: "CR-05", name: "Data Exfiltration",              cond: "Outbound > 500 MB to single IP in 15 min",      action: "Raise Exfil Alert",         mitre: "T1041",  matches: 3,   last: "3 hr ago",   enabled: false },
  { id: "CR-06", name: "C2 Beacon Pattern",              cond: "Periodic outbound HTTP at fixed interval",       action: "Raise C2 Alert",            mitre: "T1071",  matches: 8,   last: "45 min ago", enabled: true },
  { id: "CR-07", name: "Credential Stuffing",            cond: "50+ unique usernames from same IP in 2 min",     action: "Raise Credential Alert",    mitre: "T1110.004", matches: 2, last: "6 hr ago",  enabled: false },
  { id: "CR-08", name: "DNS Tunneling Detection",        cond: "High-entropy DNS queries > 100/min from host",   action: "Raise Exfil Alert",         mitre: "T1048.003", matches: 6, last: "18 min ago", enabled: true },
];

/* ---------- log sources ---------- */
const LOG_SOURCES = [
  { name: "Firewall (pfSense)",    status: "connected", eps: 342,  lastEvt: "just now" },
  { name: "IDS / IPS (Suricata)",  status: "connected", eps: 128,  lastEvt: "2 s ago" },
  { name: "Active Directory",      status: "connected", eps: 56,   lastEvt: "5 s ago" },
  { name: "Web Server (nginx)",    status: "degraded",  eps: 18,   lastEvt: "34 s ago" },
  { name: "Endpoint Agent (EDR)",  status: "connected", eps: 210,  lastEvt: "1 s ago" },
  { name: "Cloud Trail (AWS)",     status: "offline",   eps: 0,    lastEvt: "12 min ago" },
];

/* ---------- CSS ---------- */
const STYLE = `
/* ===== SIEM DASHBOARD — sd- prefix ===== */
.sd-wrap{font-family:system-ui,-apple-system,sans-serif;color:var(--txt,#c8d6e5);max-width:1100px;margin:0 auto;padding:20px 0}
.sd-hdr{display:flex;align-items:center;gap:14px;margin-bottom:18px;flex-wrap:wrap}
.sd-hdr h2{margin:0;font-size:1.45rem;font-weight:700;letter-spacing:-.02em}
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
.sd-status-sel{background:var(--card2,#080c14);color:var(--txt,#c8d6e5);border:1px solid var(--line,#1e293b);border-radius:4px;padding:3px 6px;font-size:.74rem;cursor:pointer}
.sd-sev-pill{display:inline-block;padding:2px 10px;border-radius:9999px;font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.03em;color:#fff}

/* correlation */
.sd-rule{display:grid;grid-template-columns:1fr auto;gap:12px;align-items:start;padding:14px 16px;background:var(--card2,#080c14);border-radius:8px;margin-bottom:8px;border:1px solid var(--line,#1e293b)}
.sd-rule-hdr{display:flex;align-items:center;gap:10px}
.sd-rule-name{font-weight:600;font-size:.88rem}
.sd-rule-id{color:var(--mut,#64748b);font-size:.72rem;font-family:monospace}
.sd-rule-cond{color:var(--mut,#64748b);font-size:.78rem;margin-top:4px}
.sd-rule-action{color:var(--acc,#2563eb);font-size:.76rem;margin-top:2px}
.sd-rule-stats{display:flex;gap:16px;font-size:.74rem;color:var(--mut,#64748b);margin-top:6px}
.sd-rule-stats span{display:flex;align-items:center;gap:4px}
.sd-toggle{position:relative;width:38px;height:20px;cursor:pointer}
.sd-toggle input{opacity:0;width:0;height:0}
.sd-toggle-track{position:absolute;inset:0;background:var(--line,#1e293b);border-radius:10px;transition:background .2s}
.sd-toggle input:checked+.sd-toggle-track{background:var(--acc,#2563eb)}
.sd-toggle-thumb{position:absolute;top:2px;left:2px;width:16px;height:16px;background:#fff;border-radius:50%;transition:transform .2s}
.sd-toggle input:checked~.sd-toggle-thumb{transform:translateX(18px)}

/* sources */
.sd-src{display:grid;grid-template-columns:1fr 110px 90px 120px;gap:10px;align-items:center;padding:12px 16px;background:var(--card2,#080c14);border-radius:8px;margin-bottom:6px;font-size:.8rem;border:1px solid var(--line,#1e293b)}
.sd-src-name{font-weight:600}
.sd-src-status{display:flex;align-items:center;gap:6px;font-size:.76rem;font-weight:500}
.sd-src-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.sd-src-dot.connected{background:#22c55e}
.sd-src-dot.degraded{background:#eab308}
.sd-src-dot.offline{background:#dc2626}
.sd-src-eps{font-family:monospace;text-align:right;font-size:.78rem}
.sd-src-last{color:var(--mut,#64748b);font-size:.74rem;text-align:right}

/* analytics */
.sd-analytics-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:700px){.sd-analytics-grid{grid-template-columns:1fr} .sd-evt{grid-template-columns:28px 1fr;} .sd-evt .sd-ts,.sd-evt .sd-ip,.sd-evt .sd-etype{display:none}}
.sd-bar-chart{display:flex;align-items:flex-end;gap:6px;height:120px;padding-top:8px}
.sd-bar{flex:1;background:var(--acc,#2563eb);border-radius:4px 4px 0 0;min-width:0;position:relative;transition:height .3s;opacity:.75}
.sd-bar:hover{opacity:1}
.sd-bar-label{position:absolute;bottom:-20px;left:50%;transform:translateX(-50%);font-size:.6rem;color:var(--mut,#64748b);white-space:nowrap}
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
.sd-live-dot{display:inline-block;width:8px;height:8px;background:#22c55e;border-radius:50%;margin-right:6px;animation:sd-pulse 1.5s infinite}
@keyframes sd-pulse{0%,100%{opacity:1}50%{opacity:.3}}

/* alert detail row */
.sd-alert-notes{font-size:.72rem;color:var(--mut,#64748b);font-style:italic;margin-top:2px}
.sd-alert-count{display:flex;gap:12px;margin-bottom:14px;flex-wrap:wrap}
.sd-alert-count-item{display:flex;align-items:center;gap:6px;font-size:.78rem}
.sd-alert-count-item .sd-count-num{font-weight:700;font-size:1.1rem}

/* source detail */
.sd-src-bar{height:4px;background:var(--line,#1e293b);border-radius:2px;margin-top:6px;overflow:hidden}
.sd-src-bar-fill{height:100%;border-radius:2px;transition:width .5s}

/* empty state */
.sd-empty{text-align:center;padding:40px 20px;color:var(--mut,#64748b);font-size:.85rem}

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
[data-style="pro"] .sd-feed-controls select,[data-style="pro"] .sd-feed-controls button{background:#fff;color:#1e293b;border-color:#e2e8f0}
[data-style="pro"] .sd-alert-tbl tr:hover{background:#f1f5f9}
[data-style="pro"] .sd-status-sel{background:#fff;color:#1e293b;border-color:#e2e8f0}
[data-style="pro"] .sd-rule{background:#f8fafc;border-color:#e2e8f0}
[data-style="pro"] .sd-src{background:#f8fafc;border-color:#e2e8f0}
[data-style="pro"] .sd-toggle-track{background:#cbd5e1}
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

/* ================================================================
   RENDER
   ================================================================ */
export function renderSiemDash(container) {
  /* cleanup previous intervals */
  if (container._sdCleanup) { container._sdCleanup(); container._sdCleanup = null; }
  else if (container._sdInterval) { clearInterval(container._sdInterval); clearInterval(container._sdEpmInterval); }

  const TABS = [
    { id: "feed",        label: "Live Feed" },
    { id: "alerts",      label: "Alerts" },
    { id: "correlation", label: "Correlation" },
    { id: "sources",     label: "Sources" },
    { id: "analytics",   label: "Analytics" },
  ];

  /* ---- state ---- */
  let activeTab = "feed";
  let feedEvents = [];
  let paused = false;
  let filterSev = "all";
  const alerts = sampleAlerts();
  const corrRules = CORR_RULES.map(r => ({ ...r }));
  const epmHistory = Array.from({ length: 10 }, () => randInt(12, 60));
  const ipHits = {};
  const ruleHits = {};
  IPS.forEach(ip => { ipHits[ip] = randInt(2, 80); });
  corrRules.forEach(r => { ruleHits[r.name] = r.matches; });

  /* seed initial events */
  for (let i = 0; i < 25; i++) {
    const e = genEvent();
    e.time = new Date(Date.now() - (25 - i) * 2500);
    feedEvents.push(e);
  }

  /* ---- shell ---- */
  container.innerHTML = `<style>${STYLE}</style>
  <div class="sd-wrap">
    <div class="sd-hdr">
      <h2>SIEM Dashboard</h2>
      <span class="sd-badge">Real-Time</span>
    </div>
    <div class="sd-tabs">${TABS.map(t => `<button class="sd-tab${t.id === activeTab ? " active" : ""}" data-tab="${t.id}">${esc(t.label)}</button>`).join("")}</div>
    <div id="sd-content"></div>
  </div>`;

  const wrap = container.querySelector(".sd-wrap");
  const content = container.querySelector("#sd-content");

  /* ---- tab switching ---- */
  wrap.querySelector(".sd-tabs").addEventListener("click", (e) => {
    const btn = e.target.closest(".sd-tab");
    if (!btn) return;
    activeTab = btn.dataset.tab;
    wrap.querySelectorAll(".sd-tab").forEach(b => b.classList.toggle("active", b.dataset.tab === activeTab));
    renderTab();
  });

  /* ---- render current tab ---- */
  function renderTab() {
    if (activeTab === "feed") renderFeed();
    else if (activeTab === "alerts") renderAlerts();
    else if (activeTab === "correlation") renderCorrelation();
    else if (activeTab === "sources") renderSources();
    else if (activeTab === "analytics") renderAnalytics();
  }

  /* ================ LIVE FEED ================ */
  function feedSeverityCounts() {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    feedEvents.forEach(e => { counts[e.sev]++; });
    return counts;
  }

  function renderFeed() {
    const filtered = filterSev === "all" ? feedEvents : feedEvents.filter(e => e.sev === filterSev);
    const counts = feedSeverityCounts();
    const totalEps = LOG_SOURCES.reduce((s, src) => s + src.eps, 0);
    content.innerHTML = `
      <div class="sd-summary">
        <div class="sd-summary-card">
          <div class="sd-sum-val">${feedEvents.length}</div>
          <div class="sd-sum-lbl"><span class="sd-live-dot"></span>Total Events</div>
        </div>
        <div class="sd-summary-card">
          <div class="sd-sum-val" style="color:${SEV_COLORS.critical}">${counts.critical}</div>
          <div class="sd-sum-lbl">Critical</div>
        </div>
        <div class="sd-summary-card">
          <div class="sd-sum-val" style="color:${SEV_COLORS.high}">${counts.high}</div>
          <div class="sd-sum-lbl">High</div>
        </div>
        <div class="sd-summary-card">
          <div class="sd-sum-val" style="color:${SEV_COLORS.medium}">${counts.medium}</div>
          <div class="sd-sum-lbl">Medium</div>
        </div>
        <div class="sd-summary-card">
          <div class="sd-sum-val">${totalEps.toLocaleString()}</div>
          <div class="sd-sum-lbl">Events/sec</div>
        </div>
      </div>
      <div class="sd-card">
        <div class="sd-feed-controls">
          <select id="sd-sev-filter">
            <option value="all"${filterSev === "all" ? " selected" : ""}>All Severities</option>
            ${SEV_ORDER.map(s => `<option value="${s}"${filterSev === s ? " selected" : ""}>${s.charAt(0).toUpperCase() + s.slice(1)} (${counts[s]})</option>`).join("")}
          </select>
          <button id="sd-pause">${paused ? "Resume" : "Pause"}</button>
          <span class="sd-count">${filtered.length} events displayed</span>
        </div>
        <div class="sd-feed-log" id="sd-feed-log">
          ${filtered.length === 0 ? '<div class="sd-empty">No events match the current filter.</div>' : filtered.slice().reverse().map(evtRow).join("")}
        </div>
      </div>`;

    content.querySelector("#sd-sev-filter").addEventListener("change", (e) => { filterSev = e.target.value; renderFeed(); });
    content.querySelector("#sd-pause").addEventListener("click", () => { paused = !paused; renderFeed(); });
  }

  function evtRow(e) {
    return `<div class="sd-evt sd-sev-${e.sev}">
      <span class="sd-sev-icon">${SEV_ICONS[e.sev]}</span>
      <span class="sd-ts">${esc(ts(e.time))}</span>
      <span class="sd-ip">${esc(e.srcIp)}</span>
      <span class="sd-etype" style="color:${SEV_COLORS[e.sev]}">${esc(e.type)}</span>
      <span class="sd-msg">${esc(e.msg)}</span>
    </div>`;
  }

  function appendEvent(e) {
    feedEvents.push(e);
    if (feedEvents.length > 200) feedEvents = feedEvents.slice(-200);
    /* update ip counter */
    ipHits[e.srcIp] = (ipHits[e.srcIp] || 0) + 1;
    /* update epm */
    epmHistory[epmHistory.length - 1]++;

    if (activeTab !== "feed") return;
    if (filterSev !== "all" && e.sev !== filterSev) return;

    const log = container.querySelector("#sd-feed-log");
    if (!log) return;
    const div = document.createElement("div");
    div.innerHTML = evtRow(e);
    const row = div.firstElementChild;
    log.prepend(row);

    /* trim DOM */
    while (log.children.length > 150) log.removeChild(log.lastChild);

    /* update count */
    const cnt = container.querySelector(".sd-count");
    if (cnt) {
      const visCount = filterSev === "all" ? feedEvents.length : feedEvents.filter(ev => ev.sev === filterSev).length;
      cnt.textContent = visCount + " events";
    }
  }

  /* ================ ALERTS ================ */
  function renderAlerts() {
    const statusColors = { new: "#dc2626", investigating: "#f97316", resolved: "#22c55e" };
    const statusCounts = { new: 0, investigating: 0, resolved: 0 };
    alerts.forEach(a => { statusCounts[a.status]++; });
    content.innerHTML = `
      <div class="sd-alert-count">
        <div class="sd-alert-count-item">
          <span class="sd-count-num" style="color:#dc2626">${statusCounts.new}</span>
          <span>New</span>
        </div>
        <div class="sd-alert-count-item">
          <span class="sd-count-num" style="color:#f97316">${statusCounts.investigating}</span>
          <span>Investigating</span>
        </div>
        <div class="sd-alert-count-item">
          <span class="sd-count-num" style="color:#22c55e">${statusCounts.resolved}</span>
          <span>Resolved</span>
        </div>
        <div class="sd-alert-count-item" style="margin-left:auto">
          <span class="sd-count-num">${alerts.length}</span>
          <span>Total Alerts</span>
        </div>
      </div>
      <div class="sd-card">
        <h3>Active Alerts</h3>
        <table class="sd-alert-tbl">
          <thead><tr><th>ID</th><th>Severity</th><th>Host</th><th>Rule</th><th>Created</th><th>Status</th></tr></thead>
          <tbody>
            ${alerts.map((a, i) => `<tr>
              <td style="font-family:monospace;font-size:.74rem">${esc(a.id)}</td>
              <td><span class="sd-sev-pill" style="background:${SEV_COLORS[a.sev]}">${esc(a.sev)}</span></td>
              <td style="font-family:monospace;font-size:.76rem">${esc(a.host)}</td>
              <td>${esc(a.rule)}</td>
              <td style="color:var(--mut,#64748b);font-size:.76rem">${esc(ts(a.created))}</td>
              <td>
                <select class="sd-status-sel" data-aidx="${i}" style="color:${statusColors[a.status] || "#64748b"}">
                  <option value="new"${a.status === "new" ? " selected" : ""}>New</option>
                  <option value="investigating"${a.status === "investigating" ? " selected" : ""}>Investigating</option>
                  <option value="resolved"${a.status === "resolved" ? " selected" : ""}>Resolved</option>
                </select>
              </td>
            </tr>`).join("")}
          </tbody>
        </table>
      </div>`;

    content.querySelectorAll(".sd-status-sel").forEach(sel => {
      sel.addEventListener("change", (e) => {
        const idx = parseInt(e.target.dataset.aidx, 10);
        alerts[idx].status = e.target.value;
        const colors = { new: "#dc2626", investigating: "#f97316", resolved: "#22c55e" };
        e.target.style.color = colors[e.target.value] || "#64748b";
      });
    });
  }

  /* ================ CORRELATION ================ */
  function renderCorrelation() {
    content.innerHTML = `
      <div class="sd-card">
        <h3>Correlation Rules Engine</h3>
        <div id="sd-rules-list">
          ${corrRules.map((r, i) => `
            <div class="sd-rule">
              <div>
                <div class="sd-rule-hdr">
                  <span class="sd-rule-id">${esc(r.id)}</span>
                  <span class="sd-rule-name">${esc(r.name)}</span>
                </div>
                <div class="sd-rule-cond">IF ${esc(r.cond)}</div>
                <div class="sd-rule-action">THEN ${esc(r.action)}</div>
                <div class="sd-rule-stats">
                  <span>Matches: <strong>${r.matches}</strong></span>
                  <span>Last: ${esc(r.last)}</span>
                  <span style="color:var(--acc,#2563eb)">MITRE: ${esc(r.mitre)}</span>
                </div>
              </div>
              <label class="sd-toggle" title="${r.enabled ? "Enabled" : "Disabled"}">
                <input type="checkbox" data-ridx="${i}" ${r.enabled ? "checked" : ""}>
                <span class="sd-toggle-track"></span>
                <span class="sd-toggle-thumb"></span>
              </label>
            </div>`).join("")}
        </div>
      </div>`;

    content.querySelectorAll(".sd-toggle input").forEach(cb => {
      cb.addEventListener("change", (e) => {
        const idx = parseInt(e.target.dataset.ridx, 10);
        corrRules[idx].enabled = e.target.checked;
        e.target.closest(".sd-toggle").title = e.target.checked ? "Enabled" : "Disabled";
      });
    });
  }

  /* ================ SOURCES ================ */
  function renderSources() {
    const maxEps = Math.max(...LOG_SOURCES.map(s => s.eps), 1);
    const totalEps = LOG_SOURCES.reduce((s, src) => s + src.eps, 0);
    const connectedCount = LOG_SOURCES.filter(s => s.status === "connected").length;
    const degradedCount = LOG_SOURCES.filter(s => s.status === "degraded").length;
    const offlineCount = LOG_SOURCES.filter(s => s.status === "offline").length;
    content.innerHTML = `
      <div class="sd-summary">
        <div class="sd-summary-card">
          <div class="sd-sum-val">${LOG_SOURCES.length}</div>
          <div class="sd-sum-lbl">Total Sources</div>
        </div>
        <div class="sd-summary-card">
          <div class="sd-sum-val" style="color:#22c55e">${connectedCount}</div>
          <div class="sd-sum-lbl">Connected</div>
        </div>
        <div class="sd-summary-card">
          <div class="sd-sum-val" style="color:#eab308">${degradedCount}</div>
          <div class="sd-sum-lbl">Degraded</div>
        </div>
        <div class="sd-summary-card">
          <div class="sd-sum-val" style="color:#dc2626">${offlineCount}</div>
          <div class="sd-sum-lbl">Offline</div>
        </div>
        <div class="sd-summary-card">
          <div class="sd-sum-val">${totalEps.toLocaleString()}</div>
          <div class="sd-sum-lbl">Total EPS</div>
        </div>
      </div>
      <div class="sd-card">
        <h3>Connected Log Sources</h3>
        <div class="sd-src" style="font-weight:600;background:transparent;border:none;color:var(--mut,#64748b);font-size:.72rem;text-transform:uppercase;letter-spacing:.04em">
          <span>Source</span><span>Status</span><span style="text-align:right">Events/sec</span><span style="text-align:right">Last Event</span>
        </div>
        ${LOG_SOURCES.map(s => {
          const barColor = s.status === "connected" ? "#22c55e" : s.status === "degraded" ? "#eab308" : "#dc2626";
          const barPct = ((s.eps / maxEps) * 100).toFixed(0);
          return `
          <div class="sd-src">
            <div>
              <span class="sd-src-name">${esc(s.name)}</span>
              <div class="sd-src-bar"><div class="sd-src-bar-fill" style="width:${barPct}%;background:${barColor}"></div></div>
            </div>
            <span class="sd-src-status"><span class="sd-src-dot ${s.status}"></span>${esc(s.status.charAt(0).toUpperCase() + s.status.slice(1))}</span>
            <span class="sd-src-eps">${s.eps.toLocaleString()} eps</span>
            <span class="sd-src-last">${esc(s.lastEvt)}</span>
          </div>`;
        }).join("")}
      </div>`;
  }

  /* ================ ANALYTICS ================ */
  function renderAnalytics() {
    const maxEpm = Math.max(...epmHistory, 1);
    const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    feedEvents.forEach(e => { sevCounts[e.sev]++; });
    const totalEvt = feedEvents.length || 1;
    const topIps = Object.entries(ipHits).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const maxIp = topIps.length ? topIps[0][1] : 1;
    const topRules = Object.entries(ruleHits).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const maxRule = topRules.length ? topRules[0][1] : 1;

    content.innerHTML = `
      <div class="sd-analytics-grid">
        <div class="sd-card">
          <h3>Events per Minute (last 10 min)</h3>
          <div class="sd-bar-chart">
            ${epmHistory.map((v, i) => {
              const h = Math.max(4, (v / maxEpm) * 100);
              const lbl = (i - 9) === 0 ? "now" : `${i - 9}m`;
              return `<div class="sd-bar" style="height:${h}%"><span class="sd-bar-val">${v}</span><span class="sd-bar-label">${lbl}</span></div>`;
            }).join("")}
          </div>
        </div>
        <div class="sd-card">
          <h3>Severity Distribution</h3>
          ${SEV_ORDER.map(s => {
            const pct = ((sevCounts[s] / totalEvt) * 100).toFixed(1);
            return `<div class="sd-stat-row">
              <span><span class="sd-sev-dot" style="background:${SEV_COLORS[s]}"></span>${s.charAt(0).toUpperCase() + s.slice(1)}</span>
              <div class="sd-stat-bar-bg"><div class="sd-stat-bar-fill" style="width:${pct}%;background:${SEV_COLORS[s]}"></div></div>
              <span>${sevCounts[s]} (${pct}%)</span>
            </div>`;
          }).join("")}
        </div>
        <div class="sd-card">
          <h3>Top 10 Source IPs</h3>
          ${topIps.map(([ip, cnt]) => {
            const pct = ((cnt / maxIp) * 100).toFixed(0);
            return `<div class="sd-stat-row">
              <span style="font-family:monospace;font-size:.76rem">${esc(ip)}</span>
              <div class="sd-stat-bar-bg"><div class="sd-stat-bar-fill" style="width:${pct}%;background:var(--acc,#2563eb)"></div></div>
              <span>${cnt}</span>
            </div>`;
          }).join("")}
        </div>
        <div class="sd-card">
          <h3>Most Triggered Rules</h3>
          ${topRules.map(([name, cnt]) => {
            const pct = ((cnt / maxRule) * 100).toFixed(0);
            return `<div class="sd-stat-row">
              <span style="font-size:.76rem">${esc(name)}</span>
              <div class="sd-stat-bar-bg"><div class="sd-stat-bar-fill" style="width:${pct}%;background:var(--acc,#2563eb)"></div></div>
              <span>${cnt}</span>
            </div>`;
          }).join("")}
        </div>
      </div>`;
  }

  /* ---- initial render ---- */
  renderTab();

  /* ---- live event generator ---- */
  const feedIntervalId = setInterval(() => {
    if (paused) return;
    appendEvent(genEvent());
  }, randInt(2000, 3000));

  /* rotate epm bucket every 60 s */
  const epmIntervalId = setInterval(() => {
    epmHistory.shift();
    epmHistory.push(0);
    if (activeTab === "analytics") renderAnalytics();
  }, 60000);

  /* store interval IDs for cleanup on re-render */
  container._sdInterval = feedIntervalId;
  container._sdEpmInterval = epmIntervalId;
  container._sdCleanup = () => {
    clearInterval(feedIntervalId);
    clearInterval(epmIntervalId);
  };
}
