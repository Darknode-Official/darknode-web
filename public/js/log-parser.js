// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.

const LOG_FORMATS = {
  apache: { name: "Apache/Nginx Access Log", regex: /^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (.+?) \S+" (\d+) (\d+|-)(?: "([^"]*)" "([^"]*)")?/, fields: ["ip","timestamp","method","path","status","size","referer","user_agent"] },
  auth: { name: "auth.log / syslog", regex: /^(\S+ +\d+ \d+:\d+:\d+) (\S+) (\S+?)(?:\[\d+\])?: (.+)/, fields: ["timestamp","host","service","message"] },
  json: { name: "JSON Log", regex: /^\{/, fields: [] },
  syslog: { name: "Syslog (RFC 3164)", regex: /^<(\d+)>(\S+ +\d+ \d+:\d+:\d+) (\S+) (\S+?)(?:\[\d+\])?: (.+)/, fields: ["priority","timestamp","host","service","message"] },
  csv: { name: "CSV", regex: /^[^,]+,[^,]+,[^,]+/, fields: [] },
  windows: { name: "Windows Event Log", regex: /EventID|<Event |<EventData/, fields: [] },
  firewall: { name: "Firewall Log", regex: /(?:SRC|src)=\S+ (?:DST|dst)=\S+/, fields: [] },
  fail2ban: { name: "fail2ban", regex: /fail2ban\.\w+\s+\[\d+\]/, fields: ["timestamp","service","level","message"] },
};

// Sample logs for each format
const SAMPLE_LOGS = {
  "Apache - SQLi Attempts": `192.168.1.105 - - [09/Sep/2026:14:23:01 +0000] "GET /products?id=1' OR '1'='1 HTTP/1.1" 200 4523 "-" "sqlmap/1.7"
192.168.1.105 - - [09/Sep/2026:14:23:02 +0000] "GET /products?id=1 UNION SELECT null,username,password FROM users-- HTTP/1.1" 200 6891 "-" "sqlmap/1.7"
192.168.1.105 - - [09/Sep/2026:14:23:03 +0000] "GET /products?id=1; DROP TABLE users-- HTTP/1.1" 500 234 "-" "sqlmap/1.7"
10.0.0.50 - admin [09/Sep/2026:14:24:00 +0000] "GET /admin/dashboard HTTP/1.1" 200 8921 "https://example.com/login" "Mozilla/5.0"
192.168.1.105 - - [09/Sep/2026:14:24:05 +0000] "POST /login HTTP/1.1" 200 1234 "-" "sqlmap/1.7"
192.168.1.105 - - [09/Sep/2026:14:24:06 +0000] "GET /products?id=1 AND 1=1 HTTP/1.1" 200 4523 "-" "sqlmap/1.7"
192.168.1.105 - - [09/Sep/2026:14:24:07 +0000] "GET /products?id=1 AND 1=2 HTTP/1.1" 200 4400 "-" "sqlmap/1.7"
10.0.0.22 - - [09/Sep/2026:14:25:00 +0000] "GET /index.html HTTP/1.1" 200 12500 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
10.0.0.23 - - [09/Sep/2026:14:25:30 +0000] "GET /api/users HTTP/1.1" 200 890 "-" "curl/7.88.1"
192.168.1.105 - - [09/Sep/2026:14:26:00 +0000] "GET /products?id=EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()))) HTTP/1.1" 500 234 "-" "sqlmap/1.7"`,

  "auth.log - Brute Force": `Sep  9 03:14:01 webserver sshd[12345]: Failed password for root from 45.33.32.156 port 52413 ssh2
Sep  9 03:14:02 webserver sshd[12346]: Failed password for root from 45.33.32.156 port 52414 ssh2
Sep  9 03:14:03 webserver sshd[12347]: Failed password for root from 45.33.32.156 port 52415 ssh2
Sep  9 03:14:04 webserver sshd[12348]: Failed password for root from 45.33.32.156 port 52416 ssh2
Sep  9 03:14:05 webserver sshd[12349]: Failed password for root from 45.33.32.156 port 52417 ssh2
Sep  9 03:14:06 webserver sshd[12350]: Failed password for admin from 45.33.32.156 port 52418 ssh2
Sep  9 03:14:07 webserver sshd[12351]: Failed password for admin from 45.33.32.156 port 52419 ssh2
Sep  9 03:14:10 webserver sshd[12352]: Failed password for invalid user test from 45.33.32.156 port 52420 ssh2
Sep  9 03:14:11 webserver sshd[12353]: Failed password for invalid user guest from 45.33.32.156 port 52421 ssh2
Sep  9 03:14:12 webserver sshd[12354]: Failed password for invalid user ubuntu from 45.33.32.156 port 52422 ssh2
Sep  9 03:15:00 webserver sshd[12400]: Accepted publickey for deploy from 10.0.0.5 port 43210 ssh2
Sep  9 03:15:01 webserver sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/systemctl restart nginx`,

  "Syslog - Privilege Escalation": `Sep  9 02:30:00 db-server kernel: [42.123456] audit: type=1400 msg=audit(1725849000.123:42): avc:  denied  { write } for  pid=1234 comm="exploit" name="shadow" dev="sda1"
Sep  9 02:30:01 db-server sudo: www-data : TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash
Sep  9 02:30:02 db-server su[5678]: Successful su for root by www-data
Sep  9 02:30:03 db-server kernel: [43.234567] process 'bash' (pid 5679) spawned by www-data with uid 0
Sep  9 02:30:04 db-server sshd[6000]: Accepted password for root from 192.168.1.100 port 44444 ssh2
Sep  9 02:30:05 db-server bash: HISTORY: PID=5679 UID=0 cat /etc/shadow
Sep  9 02:30:06 db-server bash: HISTORY: PID=5679 UID=0 useradd -o -u 0 -g 0 backdoor
Sep  9 02:30:07 db-server bash: HISTORY: PID=5679 UID=0 echo 'backdoor:password123' | chpasswd
Sep  9 02:30:08 db-server cron[100]: (root) CMD (/tmp/.hidden/reverse_shell.sh)
Sep  9 02:30:10 db-server kernel: [45.345678] TCP: connection from 192.168.1.100:44444 to 10.10.14.5:4444 established`,

  "Firewall - Port Scan": `Sep 09 01:00:01 fw kernel: [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc SRC=203.0.113.50 DST=10.0.0.1 LEN=44 TOS=0x00 PROTO=TCP SPT=12345 DPT=21 SEQ=0 SYN
Sep 09 01:00:01 fw kernel: [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc SRC=203.0.113.50 DST=10.0.0.1 LEN=44 TOS=0x00 PROTO=TCP SPT=12346 DPT=22 SEQ=0 SYN
Sep 09 01:00:01 fw kernel: [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc SRC=203.0.113.50 DST=10.0.0.1 LEN=44 TOS=0x00 PROTO=TCP SPT=12347 DPT=23 SEQ=0 SYN
Sep 09 01:00:01 fw kernel: [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc SRC=203.0.113.50 DST=10.0.0.1 LEN=44 TOS=0x00 PROTO=TCP SPT=12348 DPT=25 SEQ=0 SYN
Sep 09 01:00:02 fw kernel: [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc SRC=203.0.113.50 DST=10.0.0.1 LEN=44 TOS=0x00 PROTO=TCP SPT=12349 DPT=80 SEQ=0 SYN
Sep 09 01:00:02 fw kernel: [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc SRC=203.0.113.50 DST=10.0.0.1 LEN=44 TOS=0x00 PROTO=TCP SPT=12350 DPT=443 SEQ=0 SYN
Sep 09 01:00:02 fw kernel: [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc SRC=203.0.113.50 DST=10.0.0.1 LEN=44 TOS=0x00 PROTO=TCP SPT=12351 DPT=445 SEQ=0 SYN
Sep 09 01:00:02 fw kernel: [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc SRC=203.0.113.50 DST=10.0.0.1 LEN=44 TOS=0x00 PROTO=TCP SPT=12352 DPT=3306 SEQ=0 SYN
Sep 09 01:00:03 fw kernel: [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc SRC=203.0.113.50 DST=10.0.0.1 LEN=44 TOS=0x00 PROTO=TCP SPT=12353 DPT=3389 SEQ=0 SYN
Sep 09 01:00:03 fw kernel: [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc SRC=203.0.113.50 DST=10.0.0.1 LEN=44 TOS=0x00 PROTO=TCP SPT=12354 DPT=8080 SEQ=0 SYN`,
};

// Anomaly detection patterns
const ANOMALIES = [
  { name: "Brute Force", check: (entries) => { const ipFails = {}; for (const e of entries) { if (/[Ff]ail|[Dd]enied|[Uu]nauthorized|401/.test(e.raw)) { ipFails[e.ip] = (ipFails[e.ip] || 0) + 1; } } return Object.entries(ipFails).filter(([,c]) => c >= 5).map(([ip, count]) => ({ ip, count, desc: `${count} failed attempts from ${ip}` })); } },
  { name: "Port Scan", check: (entries) => { const ipPorts = {}; for (const e of entries) { if (e.port) { if (!ipPorts[e.ip]) ipPorts[e.ip] = new Set(); ipPorts[e.ip].add(e.port); } } return Object.entries(ipPorts).filter(([,ports]) => ports.size >= 5).map(([ip, ports]) => ({ ip, count: ports.size, desc: `${ports.size} different ports probed from ${ip}` })); } },
  { name: "SQL Injection", check: (entries) => { const sqli = /('|--|UNION|SELECT|DROP|INSERT|UPDATE|DELETE|OR\s+\d+=\d+|AND\s+\d+=\d+|EXTRACTVALUE|CONCAT|0x[0-9a-f]+)/i; return entries.filter(e => sqli.test(e.raw)).map(e => ({ ip: e.ip, desc: `SQLi pattern in: ${(e.path || e.raw).slice(0, 80)}` })); } },
  { name: "XSS Attempt", check: (entries) => { const xss = /(<script|javascript:|onerror|onload|alert\(|document\.cookie|eval\()/i; return entries.filter(e => xss.test(e.raw)).map(e => ({ ip: e.ip, desc: `XSS pattern in: ${(e.path || e.raw).slice(0, 80)}` })); } },
  { name: "Privilege Escalation", check: (entries) => { return entries.filter(e => /su for root by|USER=root|uid.?=.?0|useradd.*-u\s*0|passwd|shadow/.test(e.raw)).map(e => ({ ip: e.ip || "local", desc: e.raw.slice(0, 100) })); } },
  { name: "Suspicious Tool", check: (entries) => { const tools = /sqlmap|nikto|nmap|masscan|hydra|gobuster|dirbuster|wfuzz|nuclei|metasploit/i; return entries.filter(e => tools.test(e.raw)).map(e => ({ ip: e.ip, desc: `Security tool detected: ${(e.user_agent || e.raw).slice(0, 80)}` })); } },
];

function detectFormat(text) {
  const line = text.trim().split("\n")[0] || "";
  for (const [key, fmt] of Object.entries(LOG_FORMATS)) {
    if (fmt.regex.test(line)) return key;
  }
  return "apache";
}

function parseLogLine(line, format) {
  const entry = { raw: line, ip: "", timestamp: "", method: "", path: "", status: "", user_agent: "", service: "", message: "", port: "" };
  const fmt = LOG_FORMATS[format];
  if (!fmt) return entry;

  if (format === "json") {
    try { const j = JSON.parse(line); Object.assign(entry, j); entry.ip = j.ip || j.remote_addr || j.source || j.src || ""; entry.timestamp = j.timestamp || j.time || j["@timestamp"] || ""; } catch (_) {}
    return entry;
  }

  const m = line.match(fmt.regex);
  if (m) {
    for (let i = 0; i < fmt.fields.length; i++) {
      entry[fmt.fields[i]] = m[i + 1] || "";
    }
  }

  // Extract port from firewall logs
  const dptMatch = line.match(/DPT=(\d+)/);
  if (dptMatch) entry.port = dptMatch[1];

  // Extract IP from auth logs
  if (!entry.ip && entry.message) {
    const ipMatch = entry.message.match(/from (\d+\.\d+\.\d+\.\d+)/);
    if (ipMatch) entry.ip = ipMatch[1];
  }
  // Extract IP from firewall logs
  if (!entry.ip) {
    const srcMatch = line.match(/SRC=(\d+\.\d+\.\d+\.\d+)/);
    if (srcMatch) entry.ip = srcMatch[1];
  }

  return entry;
}

export function renderLogParser(container) {
  let rawInput = "";
  let entries = [];
  let detectedFormat = "";
  let searchQuery = "";
  let sevFilter = "";
  let activeTab = "logs"; // logs | analysis | anomalies

  function parse() {
    if (!rawInput.trim()) { entries = []; return; }
    detectedFormat = detectFormat(rawInput);
    entries = rawInput.trim().split("\n").filter(l => l.trim()).map(l => parseLogLine(l, detectedFormat));
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      entries = entries.filter(e => e.raw.toLowerCase().includes(q));
    }
  }

  function getAnalysis() {
    const ips = {}, statuses = {}, methods = {}, paths = {}, agents = {};
    for (const e of entries) {
      if (e.ip) ips[e.ip] = (ips[e.ip] || 0) + 1;
      if (e.status) statuses[e.status] = (statuses[e.status] || 0) + 1;
      if (e.method) methods[e.method] = (methods[e.method] || 0) + 1;
      if (e.path) { const p = e.path.split("?")[0]; paths[p] = (paths[p] || 0) + 1; }
      if (e.user_agent && e.user_agent !== "-") agents[e.user_agent] = (agents[e.user_agent] || 0) + 1;
    }
    return {
      topIPs: Object.entries(ips).sort((a,b) => b[1]-a[1]).slice(0, 15),
      statusDist: Object.entries(statuses).sort((a,b) => b[1]-a[1]),
      methodDist: Object.entries(methods).sort((a,b) => b[1]-a[1]),
      topPaths: Object.entries(paths).sort((a,b) => b[1]-a[1]).slice(0, 15),
      topAgents: Object.entries(agents).sort((a,b) => b[1]-a[1]).slice(0, 10),
    };
  }

  function getAnomalies() {
    const results = [];
    for (const anomaly of ANOMALIES) {
      const found = anomaly.check(entries);
      if (found.length) results.push({ name: anomaly.name, findings: found });
    }
    return results;
  }

  function statusColor(s) { if(s>=500) return "#ef4444"; if(s>=400) return "#f59e0b"; if(s>=300) return "#60a5fa"; if(s>=200) return "#22c55e"; return "#94a3b8"; }

  function render() {
    parse();
    const analysis = entries.length ? getAnalysis() : null;
    const anomalies = entries.length ? getAnomalies() : [];
    const totalAnomalies = anomalies.reduce((s,a) => s + a.findings.length, 0);

    container.innerHTML = `
      <div style="font-family:system-ui;color:#e2e8f0;display:flex;flex-direction:column;height:100vh">
        <div style="padding:12px 20px;background:#0f172a;border-bottom:1px solid #1e293b;display:flex;align-items:center;gap:16px">
          <h3 style="margin:0;font-size:16px;font-weight:700">Security Log Analyzer</h3>
          <select id="lp-sample" style="padding:4px 8px;border:1px solid #334155;border-radius:4px;background:#1e293b;color:#e2e8f0;font-size:12px">
            <option value="">Load sample...</option>
            ${Object.keys(SAMPLE_LOGS).map(k => `<option value="${k}">${k}</option>`).join("")}
          </select>
          ${detectedFormat ? `<span style="padding:2px 8px;border-radius:4px;background:#1e293b;font-size:11px;color:#60a5fa">Format: ${LOG_FORMATS[detectedFormat]?.name || detectedFormat}</span>` : ""}
          <div style="flex:1"></div>
          <span style="font-size:12px;color:#64748b">${entries.length} entries</span>
          ${totalAnomalies ? `<span style="padding:2px 8px;border-radius:4px;background:#7f1d1d;font-size:11px;color:#fca5a5;font-weight:600">${totalAnomalies} anomalies</span>` : ""}
        </div>
        <div style="display:flex;flex:1;min-height:0">
          <!-- Input panel -->
          <div style="width:50%;display:flex;flex-direction:column;border-right:1px solid #1e293b">
            <div style="padding:8px 16px;background:#0f172a;border-bottom:1px solid #1e293b;font-size:12px;color:#64748b">Paste logs below</div>
            <textarea id="lp-input" style="flex:1;background:#0a0f1a;color:#e2e8f0;border:none;padding:12px;font-family:monospace;font-size:12px;resize:none;outline:none">${rawInput}</textarea>
          </div>
          <!-- Output panel -->
          <div style="width:50%;display:flex;flex-direction:column">
            <div style="display:flex;border-bottom:1px solid #1e293b;background:#0f172a">
              ${["logs","analysis","anomalies"].map(t => `
                <button class="lp-tab" data-tab="${t}" style="padding:8px 16px;border:none;background:${t===activeTab?'#1e293b':'transparent'};color:${t===activeTab?'#f8fafc':'#64748b'};cursor:pointer;font-size:13px;border-bottom:2px solid ${t===activeTab?'#60a5fa':'transparent'}">
                  ${t.charAt(0).toUpperCase()+t.slice(1)}${t==="anomalies"&&totalAnomalies?` (${totalAnomalies})`:""}
                </button>
              `).join("")}
              <div style="flex:1"></div>
              <input type="text" id="lp-search" placeholder="Search..." value="${searchQuery}" style="margin:4px 8px;padding:4px 8px;border:1px solid #334155;border-radius:4px;background:#1e293b;color:#e2e8f0;font-size:12px;width:150px">
            </div>
            <div style="flex:1;overflow-y:auto;padding:12px;font-size:12px">
              ${activeTab === "logs" ? renderLogsTab() : activeTab === "analysis" ? renderAnalysisTab(analysis) : renderAnomaliesTab(anomalies)}
            </div>
          </div>
        </div>
      </div>`;
    bindEvents();
  }

  function renderLogsTab() {
    if (!entries.length) return `<div style="color:#64748b;text-align:center;padding:40px">Paste log data in the left panel to begin analysis</div>`;
    return entries.slice(0, 200).map((e, i) => {
      const isSuspicious = /[Ff]ail|[Dd]enied|[Bb]lock|500|sqlmap|UNION|SELECT.*FROM|<script/i.test(e.raw);
      return `<div style="padding:6px 8px;margin-bottom:2px;border-radius:4px;font-family:monospace;background:${isSuspicious?'#7f1d1d20':'transparent'};border-left:3px solid ${isSuspicious?'#ef4444':e.status>=400?'#f59e0b':e.status>=200?'#22c55e':'#334155'}">
        <span style="color:#64748b;margin-right:8px">${i+1}</span>
        ${e.ip?`<span style="color:#60a5fa">${e.ip}</span> `:""}
        ${e.method?`<span style="color:#a78bfa;font-weight:600">${e.method}</span> `:""}
        ${e.path?`<span style="color:#e2e8f0">${e.path.slice(0,60)}</span> `:""}
        ${e.status?`<span style="color:${statusColor(+e.status)};font-weight:600">${e.status}</span> `:""}
        ${!e.method&&!e.path?`<span style="color:#94a3b8">${e.raw.slice(0,120)}</span>`:""}
      </div>`;
    }).join("") + (entries.length > 200 ? `<div style="padding:12px;text-align:center;color:#64748b">Showing 200 of ${entries.length}</div>` : "");
  }

  function renderAnalysisTab(analysis) {
    if (!analysis) return `<div style="color:#64748b;text-align:center;padding:40px">No data to analyze</div>`;
    const maxIP = analysis.topIPs[0]?.[1] || 1;
    return `
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
        <div style="padding:16px;background:#1e293b;border-radius:8px">
          <h4 style="margin:0 0 12px;color:#94a3b8;font-size:12px">Top Source IPs</h4>
          ${analysis.topIPs.map(([ip,c]) => `
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
              <span style="width:120px;font-family:monospace;font-size:11px;color:#60a5fa">${ip}</span>
              <div style="flex:1;height:12px;background:#0f172a;border-radius:3px;overflow:hidden">
                <div style="height:100%;width:${(c/maxIP)*100}%;background:#3b82f6;border-radius:3px"></div>
              </div>
              <span style="font-size:11px;font-weight:600;width:30px;text-align:right">${c}</span>
            </div>
          `).join("")}
        </div>
        <div style="padding:16px;background:#1e293b;border-radius:8px">
          <h4 style="margin:0 0 12px;color:#94a3b8;font-size:12px">Status Code Distribution</h4>
          ${analysis.statusDist.map(([s,c]) => `
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
              <span style="width:40px;font-family:monospace;font-weight:600;color:${statusColor(+s)}">${s}</span>
              <div style="flex:1;height:12px;background:#0f172a;border-radius:3px;overflow:hidden">
                <div style="height:100%;width:${(c/entries.length)*100}%;background:${statusColor(+s)};border-radius:3px"></div>
              </div>
              <span style="font-size:11px;width:30px;text-align:right">${c}</span>
            </div>
          `).join("")}
        </div>
        ${analysis.topPaths.length ? `
        <div style="padding:16px;background:#1e293b;border-radius:8px;grid-column:1/3">
          <h4 style="margin:0 0 12px;color:#94a3b8;font-size:12px">Top Requested Paths</h4>
          ${analysis.topPaths.slice(0,10).map(([p,c]) => `
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;font-size:11px">
              <span style="flex:1;font-family:monospace;color:#e2e8f0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${p}</span>
              <span style="font-weight:600;color:#94a3b8">${c}</span>
            </div>
          `).join("")}
        </div>` : ""}
        ${analysis.topAgents.length ? `
        <div style="padding:16px;background:#1e293b;border-radius:8px;grid-column:1/3">
          <h4 style="margin:0 0 12px;color:#94a3b8;font-size:12px">User Agents</h4>
          ${analysis.topAgents.map(([ua,c]) => {
            const isTool = /sqlmap|nikto|nmap|hydra|gobuster|dirbuster|wfuzz|nuclei|curl/i.test(ua);
            return `<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;font-size:11px;${isTool?'background:#7f1d1d20;padding:4px 8px;border-radius:4px':''}">
              <span style="flex:1;color:${isTool?'#fca5a5':'#94a3b8'};overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${ua}${isTool?' ':''}</span>
              <span style="font-weight:600">${c}</span>
            </div>`;
          }).join("")}
        </div>` : ""}
      </div>`;
  }

  function renderAnomaliesTab(anomalies) {
    if (!anomalies.length) return `<div style="color:#64748b;text-align:center;padding:40px">${entries.length ? "No anomalies detected" : "Paste log data to scan for anomalies"}</div>`;
    return anomalies.map(a => `
      <div style="margin-bottom:16px;padding:16px;background:#1e293b;border-radius:8px;border-left:4px solid #ef4444">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
          <span style="font-weight:700;color:#fca5a5">${a.name}</span>
          <span style="padding:2px 6px;border-radius:4px;background:#7f1d1d;color:#fca5a5;font-size:10px;font-weight:600">${a.findings.length} finding${a.findings.length>1?'s':''}</span>
        </div>
        ${a.findings.slice(0,10).map(f => `
          <div style="padding:6px 8px;margin-bottom:4px;background:#0f172a;border-radius:4px;font-size:11px;font-family:monospace;color:#e2e8f0">
            ${f.ip?`<span style="color:#60a5fa">${f.ip}</span> — `:""}${f.desc}
          </div>
        `).join("")}
        ${a.findings.length > 10 ? `<div style="font-size:11px;color:#64748b;padding:4px">...and ${a.findings.length-10} more</div>` : ""}
      </div>
    `).join("");
  }

  function bindEvents() {
    const input = container.querySelector("#lp-input");
    if (input) input.addEventListener("input", e => { rawInput = e.target.value; render(); });

    const sampleSelect = container.querySelector("#lp-sample");
    if (sampleSelect) sampleSelect.addEventListener("change", e => {
      if (e.target.value && SAMPLE_LOGS[e.target.value]) { rawInput = SAMPLE_LOGS[e.target.value]; render(); }
    });

    container.querySelectorAll(".lp-tab").forEach(btn => {
      btn.addEventListener("click", () => { activeTab = btn.dataset.tab; render(); });
    });

    const searchInput = container.querySelector("#lp-search");
    if (searchInput) searchInput.addEventListener("input", e => { searchQuery = e.target.value; render(); });
  }

  render();
}
