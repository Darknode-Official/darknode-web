// Log Threat Hunter — pure engine. Parses web access logs (nginx/Apache CLF,
// IIS W3C, Cloudflare/ALB JSON lines), Linux auth logs (sshd, sudo, pam,
// useradd, journald short-iso) and Windows Security event exports (Event Viewer
// CSV, EVTX JSON, EVTX XML) into one event shape, then runs deterministic
// threat-hunting rules mapped to MITRE ATT&CK. No DOM, no network: the UI
// (log-hunter.js) feeds records in chunks so 200k lines never block the page.
// Copyright (c) 2026 Darknode-Official. All rights reserved.

import { controlsFromRefs } from "../core/sink-map.js";

export const VERSION = "1.0.0";
export const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const EVIDENCE_CAP = 30;

export const DEFAULT_SETTINGS = {
  // Web
  notFoundBurstN: 30, notFoundWindowMin: 10,
  loginAttemptsN: 20, loginWindowMin: 30,
  uaBurstN: 50,
  // Linux
  bruteN: 10, bruteWindowMin: 10,
  distIpsN: 5,
  successAfterFailN: 3, successAfterFailWindowMin: 60,
  invalidUserN: 5,
  // Windows
  winFailN: 10, winFailWindowMin: 10,
  sprayUsersN: 5,
  lockoutN: 3, lockoutWindowMin: 60,
  fanoutHostsN: 5,
  newUserAdminWindowMin: 60,
  kerberoastN: 5,
  ntlmBurstN: 20, ntlmWindowMin: 10,
  explicitCredTargetsN: 5,
  // Business hours (local = UTC + utcOffset hours)
  businessStart: 8, businessEnd: 18, utcOffset: 0, weekendOffHours: true,
  // Classification
  internalCidrs: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"],
  loginPaths: ["/login", "/signin", "/sign-in", "/wp-login.php", "/xmlrpc.php", "/api/auth", "/api/login", "/oauth/token", "/session", "/user/login", "/account/login", "/auth", "/j_security_check"],
  adminNamePattern: "admin|administrator|^root$|adm$|^svc|^sa$|da$|domain admin|enterprise admin",
  // Year assumed for syslog lines that carry no year
  assumeYear: new Date().getUTCFullYear(),
};

export function mergeSettings(s) {
  const out = Object.assign({}, DEFAULT_SETTINGS, s || {});
  if (typeof out.internalCidrs === "string") out.internalCidrs = out.internalCidrs.split(/[\s,]+/).filter(Boolean);
  if (typeof out.loginPaths === "string") out.loginPaths = out.loginPaths.split(/[\s,]+/).filter(Boolean);
  for (const k of Object.keys(DEFAULT_SETTINGS)) {
    if (typeof DEFAULT_SETTINGS[k] === "number") { const n = Number(out[k]); out[k] = Number.isFinite(n) ? n : DEFAULT_SETTINGS[k]; }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Detection catalogue (MITRE ATT&CK technique ids). Each rule is deterministic;
// severity defaults here can be raised or lowered by the context at finish().
// ---------------------------------------------------------------------------
const D = (name, technique, techniqueName, tactic, severity, confidence, source, explain, action) => ({ name, technique, techniqueName, tactic, severity, confidence, source, explain, action });
export const DETECTIONS = {
  "web.sqli": D("SQL injection probes", "T1190", "Exploit Public-Facing Application", "Initial Access", "high", "high", "web",
    "Requests carried SQL syntax in the URL (UNION SELECT, OR 1=1, sleep(), information_schema and similar). Scanners send these to find parameters that reach a database query.",
    "Check whether the targeted endpoints build SQL from request input and confirm parameterised queries. Block the source at the edge if it keeps probing and review database logs for the same window."),
  "web.xss": D("Cross-site scripting probes", "T1190", "Exploit Public-Facing Application", "Initial Access", "medium", "high", "web",
    "Requests carried script tags or event handlers (<script, onerror=, javascript:) in the URL. This is a probe for pages that echo input without encoding.",
    "Verify output encoding on the targeted pages and set a Content-Security-Policy. Treat 200 responses to these URLs as the ones to test first."),
  "web.traversal": D("Path traversal probes", "T1083", "File and Directory Discovery", "Discovery", "high", "high", "web",
    "URLs contained ../ sequences (plain or percent-encoded) or named system files such as /etc/passwd or win.ini. The sender is trying to read files outside the web root.",
    "Confirm the application never builds file paths from user input. A 200 response to one of these URLs means a file was likely served; check the response size and rotate anything exposed."),
  "web.cmdi": D("Command injection probes", "T1059", "Command and Scripting Interpreter", "Execution", "high", "medium", "web",
    "URL parameters contained shell metacharacters followed by commands (;id, |cat, $(...), /bin/sh, cmd.exe, powershell). The sender is testing whether input reaches a system shell.",
    "Look for any code path that passes request input to a shell or process spawn. Check the server for new processes or outbound connections in the same minute."),
  "web.webshell": D("Web shell indicators", "T1505.003", "Server Software Component: Web Shell", "Persistence", "critical", "medium", "web",
    "Requests hit script files with names used by known web shells, passed cmd=/exec= style parameters to a script, or POSTed to scripts inside upload or media directories.",
    "List the files at these paths on the server now. A script in an upload directory that you did not deploy is a compromise; preserve it for analysis, remove it, and find how it was written."),
  "web.sensitive": D("Sensitive path probing", "T1595.003", "Active Scanning: Wordlist Scanning", "Reconnaissance", "low", "high", "web",
    "Requests for files that should never be public: .env, .git/, wp-login.php, xmlrpc.php, phpmyadmin, actuator, .aws/credentials, server-status and similar. Background noise unless the server answered 200.",
    "Any 200 is the real finding: fetch the same path yourself and remove or deny it. Add deny rules for dotfiles and admin consoles at the web server or CDN."),
  "web.sensitive.served": D("Sensitive path served (HTTP 200)", "T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access", "high", "high", "web",
    "A probe for a sensitive file or console got a 200 response, which means the server returned content for it.",
    "Open the path yourself to confirm what is exposed. If it is .env, .git or a credentials file, assume every secret in it is compromised and rotate."),
  "web.scanner": D("Scanner user-agents", "T1595", "Active Scanning", "Reconnaissance", "low", "high", "web",
    "The User-Agent names a vulnerability scanner or brute-force tool (sqlmap, nikto, nuclei, gobuster, ffuf, wpscan and others).",
    "Block the source if it is not your own authorised test. The other findings for the same IP tell you what the scan found."),
  "web.toolburst": D("Scripted client burst", "T1595", "Active Scanning", "Reconnaissance", "low", "medium", "web",
    "A generic HTTP library user-agent (python-requests, Go-http-client, curl) sent a large number of requests from one IP.",
    "Decide whether this is a known integration. If not, rate-limit the source and check its paths for probing."),
  "web.404burst": D("404 burst / forced browsing", "T1595.003", "Active Scanning: Wordlist Scanning", "Reconnaissance", "medium", "high", "web",
    "One IP produced many 404 responses in a short window, the signature of a wordlist scan for hidden files and directories.",
    "Rate-limit or block the source. Compare its 200 responses against the 404s to see what it found."),
  "web.credstuff": D("Credential stuffing on login endpoint", "T1110.004", "Brute Force: Credential Stuffing", "Credential Access", "medium", "medium", "web",
    "One IP sent many POST requests to a login endpoint in a short window, mostly rejected (401/403/400). This is automated password testing.",
    "Add rate limits and a challenge on the login route. If a later POST from the same IP returned 200, treat that account as compromised and force a reset."),
  "web.credstuff.success": D("Login success after repeated failures", "T1078", "Valid Accounts", "Defense Evasion", "high", "medium", "web",
    "After many rejected login POSTs, the same IP got a 200 from the login endpoint. One of the guessed credentials probably worked.",
    "Find the session created at that time, terminate it, and reset the account. Review what that session did afterwards."),
  "web.log4shell": D("Log4Shell JNDI payload", "T1190", "Exploit Public-Facing Application", "Initial Access", "critical", "high", "web",
    "A request contained a ${jndi:...} lookup string (CVE-2021-44228). Any Java service that logs the field with a vulnerable Log4j will fetch and run attacker code.",
    "Confirm every Java component is on Log4j 2.17.1 or later. Check outbound connections from the server to the host named in the payload."),
  "web.ssrf": D("SSRF-style internal URL in parameter", "T1190", "Exploit Public-Facing Application", "Initial Access", "medium", "medium", "web",
    "A URL parameter pointed at an internal address (localhost, 169.254.169.254 metadata, private ranges, file://). The sender wants the server to fetch it on their behalf.",
    "Check whether the endpoint fetches URLs from input. Block link-local and private destinations in that code and review cloud metadata access logs."),

  "linux.brute": D("SSH brute force from one IP", "T1110.001", "Brute Force: Password Guessing", "Credential Access", "high", "high", "linux",
    "One IP produced many failed SSH authentications in a short window.",
    "Block the source (fail2ban or firewall), disable password authentication for SSH where possible, and check the same IP for any Accepted line."),
  "linux.spray": D("Distributed brute force on one account", "T1110.003", "Brute Force: Password Spraying", "Credential Access", "medium", "medium", "linux",
    "Failed SSH logins for a single account arrived from many different IPs, which per-IP blocking does not stop.",
    "Confirm the account is key-only or has a strong password. Consider restricting SSH to a VPN or allow-list."),
  "linux.success_after_fail": D("SSH success after failures (same IP)", "T1078", "Valid Accounts", "Defense Evasion", "high", "high", "linux",
    "An IP that had several failed SSH authentications was then accepted. This is the strongest sign in an auth log that a guess succeeded.",
    "Treat the account as compromised: terminate the session, rotate its credentials and keys, and inspect commands run after the Accepted line."),
  "linux.invalid_user": D("Invalid-user enumeration", "T1087", "Account Discovery", "Discovery", "medium", "high", "linux",
    "One IP tried many usernames that do not exist on the host, working through a wordlist.",
    "Block the source. Confirm the real account names on the host were not among those tried."),
  "linux.root_login": D("Root login accepted over SSH", "T1078.003", "Valid Accounts: Local Accounts", "Persistence", "high", "high", "linux",
    "sshd accepted a login directly as root. Direct root logins hide who did what and are the usual target of brute force.",
    "Set PermitRootLogin to no (or prohibit-password) and verify the source IP is one you expect."),
  "linux.new_user": D("New user or group created", "T1136.001", "Create Account: Local Account", "Persistence", "medium", "high", "linux",
    "useradd or groupadd created an account on the host.",
    "Confirm a change ticket exists for this account. Attackers create accounts to keep access after the original hole is fixed."),
  "linux.priv_group": D("User added to privileged group", "T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "Privilege Escalation", "high", "high", "linux",
    "A user was added to sudo, wheel, admin or root, which grants administrator rights on the host.",
    "Verify the change was approved. Remove the membership if not and review that user's sudo history."),
  "linux.sudoers": D("sudoers modified", "T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "Privilege Escalation", "high", "high", "linux",
    "A command touched /etc/sudoers or /etc/sudoers.d (visudo or a direct edit).",
    "Diff the sudoers file against your baseline. Look for NOPASSWD entries or new users."),
  "linux.sudo_shell": D("Suspicious sudo command", "T1059.004", "Command and Scripting Interpreter: Unix Shell", "Execution", "high", "medium", "linux",
    "sudo ran a shell, piped a download into a shell, made a file in /tmp executable, used nc -e or decoded base64. These are the common steps of a hands-on intrusion.",
    "Ask the named user whether they ran this. If not, treat the account as compromised and inspect the files or hosts named in the command."),
  "linux.sudo_fail": D("sudo refused or wrong password", "T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "Privilege Escalation", "medium", "medium", "linux",
    "A user attempted sudo without being in sudoers, or entered a wrong password repeatedly.",
    "Check whether the account is expected to need root. Repeated attempts from a service account are a sign of a compromised process."),
  "linux.breakin": D("sshd reverse-DNS mismatch (POSSIBLE BREAK-IN ATTEMPT)", "T1110", "Brute Force", "Credential Access", "low", "low", "linux",
    "sshd logged POSSIBLE BREAK-IN ATTEMPT because the client's reverse DNS did not match. Often misconfigured DNS, but it accompanies scanning.",
    "Low priority on its own. Check the same IP for failures or an Accepted line."),
  "linux.persist": D("Cron or systemd persistence write", "T1053.003", "Scheduled Task/Job: Cron", "Persistence", "medium", "medium", "linux",
    "A crontab was replaced or a systemd unit was enabled. Both are standard ways to survive a reboot.",
    "Read the new crontab or unit file and confirm who made the change."),

  "win.fail_burst": D("Failed logon burst (4625) from one source", "T1110", "Brute Force", "Credential Access", "high", "high", "windows",
    "Many 4625 failed logons came from one source address or workstation in a short window.",
    "Block or isolate the source. Check for a 4624 from the same source after the burst."),
  "win.spray": D("Password spraying (one source, many accounts)", "T1110.003", "Brute Force: Password Spraying", "Credential Access", "high", "medium", "windows",
    "One source produced failures against many different accounts, which is how attackers avoid lockout thresholds.",
    "Block the source and reset any account that later shows a 4624 from it. Review the lockout policy."),
  "win.enum": D("Account enumeration (unknown usernames)", "T1087.002", "Account Discovery: Domain Account", "Discovery", "medium", "medium", "windows",
    "4625 events with sub-status 0xC0000064 (user does not exist) for many distinct names from one source. The sender is guessing usernames.",
    "Block the source. Confirm which guessed names are real accounts and watch those."),
  "win.lockout": D("Account lockout spike (4740)", "T1110", "Brute Force", "Credential Access", "medium", "medium", "windows",
    "Several accounts were locked out within a short window, consistent with automated guessing.",
    "Find the Caller Computer Name in the 4740 events; that is the host sending the bad credentials."),
  "win.rdp_external": D("RDP logon (type 10) from an external address", "T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement", "high", "high", "windows",
    "A 4624 with LogonType 10 (RemoteInteractive) came from an address outside your internal ranges.",
    "Confirm RDP is meant to be reachable from the internet. If not, the host is exposed; close the port and reset the account."),
  "win.fanout": D("Network logon fan-out from one source", "T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement", "high", "medium", "windows",
    "One source address logged on (type 3) to many different computers. Admin tools do this, and so does lateral movement.",
    "Identify the source host and the account used. If it is not a management server or scanner, isolate it."),
  "win.explicit_creds": D("Explicit credential use (4648)", "T1550", "Use Alternate Authentication Material", "Lateral Movement", "medium", "medium", "windows",
    "A process logged on using credentials different from the signed-in user (RunAs, PsExec, scheduled tasks and lateral movement all do this).",
    "Review the subject account and target server pairs. Many distinct targets from one account is the lateral-movement pattern."),
  "win.new_user": D("User account created (4720)", "T1136.001", "Create Account: Local Account", "Persistence", "medium", "high", "windows",
    "A new account was created.",
    "Confirm a change ticket exists. Check whether the account was then added to a privileged group."),
  "win.new_admin": D("New account added to privileged group", "T1098", "Account Manipulation", "Persistence", "critical", "high", "windows",
    "An account was created (4720) and then added to Administrators, Domain Admins or Enterprise Admins within a short window. This is the textbook persistence step after a compromise.",
    "Disable the account now, then find who created it (Subject account in the 4720) and treat that account as compromised."),
  "win.priv_group": D("Member added to privileged group", "T1098", "Account Manipulation", "Persistence", "high", "high", "windows",
    "4728/4732/4756: a member was added to Administrators, Domain Admins, Enterprise Admins or another high-privilege group.",
    "Verify the change was approved. Remove the membership if not."),
  "win.account_change": D("Account enabled, password reset or changed", "T1098", "Account Manipulation", "Persistence", "low", "medium", "windows",
    "4722/4724/4738: an account was enabled, had its password reset by another user, or had attributes changed.",
    "Routine for help desks. Review resets of privileged accounts and changes made outside business hours."),
  "win.log_cleared": D("Audit log cleared (1102)", "T1070.001", "Indicator Removal: Clear Windows Event Logs", "Defense Evasion", "critical", "high", "windows",
    "The Security log was cleared. Legitimate admins almost never do this; attackers do it to hide their tracks.",
    "Treat the host as compromised from before the clear. Pull logs from your collector or other hosts for the preceding period."),
  "win.sched_task": D("Scheduled task created (4698)", "T1053.005", "Scheduled Task/Job: Scheduled Task", "Persistence", "medium", "medium", "windows",
    "A scheduled task was registered. Common for software updates; also the most common Windows persistence method.",
    "Read the task's action. Anything running from a user profile, Temp, or with an encoded PowerShell command is suspicious."),
  "win.new_service": D("New service installed (7045)", "T1543.003", "Create or Modify System Process: Windows Service", "Persistence", "medium", "medium", "windows",
    "A service was installed. PsExec, remote-admin tools and malware all install services.",
    "Check the Service File Name path. Binaries in Temp, user profiles or with random names should be removed."),
  "win.special_priv": D("Special privileges for non-admin-named account (4672)", "T1078", "Valid Accounts", "Privilege Escalation", "low", "low", "windows",
    "An account whose name does not look like an administrator account received administrator privileges at logon.",
    "Confirm the account is meant to be an administrator. Edit the admin name pattern in settings to match your naming scheme."),
  "win.kerberoast": D("Kerberoasting hint (4769 with RC4)", "T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting", "Credential Access", "medium", "medium", "windows",
    "Service tickets were requested with RC4 encryption (0x17) for user-run service accounts. Kerberoasting tools request RC4 tickets because they crack faster.",
    "Give service accounts long random passwords or use gMSA and enable AES for them. Investigate the requesting account."),
  "win.pth": D("Pass-the-hash hint (LogonType 9 / NTLM burst)", "T1550.002", "Use Alternate Authentication Material: Pass the Hash", "Lateral Movement", "medium", "medium", "windows",
    "4624 with LogonType 9 (NewCredentials) or a burst of NTLM authentications (4776) from one workstation. Both appear when stolen hashes are used; both also appear with some legitimate tools.",
    "Correlate with 4648 and type-3 fan-out from the same source. If the account is privileged, reset it and check the source host for credential dumping."),
  "win.proc_suspicious": D("Suspicious process creation (4688)", "T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution", "high", "medium", "windows",
    "A process command line matched attacker tooling patterns: encoded or hidden PowerShell, certutil downloads, mshta, rundll32 with script, whoami, net user /add, shadow copy deletion.",
    "Pull the full command line and parent process. Shadow copy deletion means ransomware is minutes away."),
  "offhours.admin": D("Administrator logon outside business hours", "T1078", "Valid Accounts", "Defense Evasion", "medium", "low", "mixed",
    "An administrator-named account (or root) logged on outside the configured business hours.",
    "Confirm with the account owner. Adjust the business hours and UTC offset in settings to match your team."),
};

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------
const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export function isIp(s) {
  if (!s) return false;
  if (IPV4.test(s)) return s.split(".").every((o) => Number(o) <= 255);
  return /^[0-9a-f:.]+$/i.test(s) && s.includes(":") && s.length <= 45;
}

// Repeated percent-decoding (double encoding is a common filter bypass), '+' as
// space, and inline SQL comments collapsed so "UN/**/ION" reads as "UN ION".
export function urlDecode(s) {
  let out = String(s == null ? "" : s);
  for (let i = 0; i < 3; i++) {
    const plus = out.replace(/\+/g, " ");
    let next;
    try { next = decodeURIComponent(plus); }
    catch (_) { next = plus.replace(/%([0-9a-f]{2})/gi, (m, h) => String.fromCharCode(parseInt(h, 16))); }
    if (next === out) break;
    out = next;
  }
  return out.replace(/\/\*.*?\*\//g, " ");
}

// Parse an IP into { v: 4|6, n: BigInt } or null.
export function ipToInt(ip) {
  if (!ip) return null;
  let s = String(ip).trim();
  if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
  const mapped = s.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (mapped) s = mapped[1];
  const m4 = s.match(IPV4);
  if (m4) {
    const o = m4.slice(1).map(Number);
    if (o.some((x) => x > 255)) return null;
    return { v: 4, n: BigInt(o[0]) * 16777216n + BigInt(o[1]) * 65536n + BigInt(o[2]) * 256n + BigInt(o[3]) };
  }
  if (!s.includes(":")) return null;
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const fill = 8 - head.length - tail.length;
  if (fill < 0 || (halves.length === 1 && fill !== 0)) return null;
  const groups = [...head, ...Array(fill).fill("0"), ...tail];
  let n = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
    n = (n << 16n) + BigInt(parseInt(g, 16));
  }
  return { v: 6, n };
}

export function parseCidr(c) {
  const [ip, bitsStr] = String(c).trim().split("/");
  const p = ipToInt(ip);
  if (!p) return null;
  const max = p.v === 4 ? 32 : 128;
  const bits = bitsStr == null ? max : Number(bitsStr);
  if (!Number.isFinite(bits) || bits < 0 || bits > max) return null;
  const full = (1n << BigInt(max)) - 1n;
  const mask = bits === 0 ? 0n : full ^ ((1n << BigInt(max - bits)) - 1n);
  return { v: p.v, net: p.n & mask, mask };
}

export function compileCidrs(list) { return (list || []).map(parseCidr).filter(Boolean); }

export function isInternalIp(ip, cidrs) {
  const p = ipToInt(ip);
  if (!p) return false;
  const compiled = Array.isArray(cidrs) && cidrs.length && cidrs[0] && cidrs[0].mask !== undefined;
  const list = compiled ? cidrs : compileCidrs(cidrs || DEFAULT_SETTINGS.internalCidrs);
  return list.some((c) => c.v === p.v && (p.n & c.mask) === c.net);
}

function tzOffsetMs(z) {
  if (!z || z === "Z") return 0;
  const m = z.match(/^([+-])(\d{2}):?(\d{2})$/);
  if (!m) return 0;
  return (m[1] === "-" ? -1 : 1) * (Number(m[2]) * 60 + Number(m[3])) * 60000;
}

// Returns epoch ms or null. Handles CLF, syslog (no year), ISO, IIS, Windows
// Event Viewer (m/d/yyyy h:mm:ss AM), PowerShell /Date(ms)/, and epoch numbers.
export function parseTs(s, assumeYear) {
  if (s == null || s === "") return null;
  if (typeof s === "number") return epochNorm(s);
  const str = String(s).trim();
  let m;
  if ((m = str.match(/^(\d{1,2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s*([+-]\d{4}|Z))?$/))) {
    const mon = MONTHS[m[2].toLowerCase()]; if (mon == null) return null;
    return Date.UTC(+m[3], mon, +m[1], +m[4], +m[5], +m[6]) - tzOffsetMs(m[7]);
  }
  if ((m = str.match(/^(\w{3})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2})$/))) {
    const mon = MONTHS[m[1].toLowerCase()]; if (mon == null) return null;
    const y = assumeYear || new Date().getUTCFullYear();
    let t = Date.UTC(y, mon, +m[2], +m[3], +m[4], +m[5]);
    if (t > Date.now() + 86400000) t = Date.UTC(y - 1, mon, +m[2], +m[3], +m[4], +m[5]);
    return t;
  }
  if ((m = str.match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d+))?\s*(Z|[+-]\d{2}:?\d{2})?$/))) {
    const ms = m[7] ? Math.round(Number("0." + m[7]) * 1000) : 0;
    return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6], ms) - tzOffsetMs(m[8]);
  }
  if ((m = str.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})(?:\s*([AP])M)?$/i))) {
    let h = +m[4];
    if (m[7]) { const pm = m[7].toUpperCase() === "P"; if (pm && h < 12) h += 12; if (!pm && h === 12) h = 0; }
    return Date.UTC(+m[3], +m[1] - 1, +m[2], h, +m[5], +m[6]);
  }
  if ((m = str.match(/^\/Date\((\d+)\)\/$/))) return Number(m[1]);
  if (/^\d{9,19}$/.test(str)) return epochNorm(Number(str));
  const d = Date.parse(str);
  return Number.isFinite(d) ? d : null;
}
function epochNorm(n) {
  if (!Number.isFinite(n)) return null;
  if (n > 1e17) return Math.floor(n / 1e6);
  if (n > 1e14) return Math.floor(n / 1e3);
  if (n > 1e11) return Math.floor(n);
  return Math.floor(n * 1000);
}

// Densest window: does any run of n events fit in windowMs? Null timestamps
// count as "in window" because we cannot place them outside it.
export function burstWindow(tss, n, windowMs) {
  const nulls = tss.filter((t) => t == null).length;
  const ts = tss.filter((t) => t != null).sort((a, b) => a - b);
  if (nulls + ts.length < n) return { hit: false, best: nulls + ts.length, start: null, end: null };
  if (!ts.length) return { hit: true, best: nulls, start: null, end: null };
  let best = 0, bi = 0, j = 0;
  for (let i = 0; i < ts.length; i++) {
    while (ts[i] - ts[j] > windowMs) j++;
    if (i - j + 1 > best) { best = i - j + 1; bi = j; }
  }
  const total = best + nulls;
  return { hit: total >= n, best: total, start: ts[bi], end: ts[bi + best - 1] };
}

export function isOffHours(ts, s) {
  if (ts == null) return false;
  const d = new Date(ts + (s.utcOffset || 0) * 3600000);
  const h = d.getUTCHours(), dow = d.getUTCDay();
  if (s.weekendOffHours && (dow === 0 || dow === 6)) return true;
  return h < s.businessStart || h >= s.businessEnd;
}

function mkEvent(o) {
  return Object.assign({ ts: null, ip: null, user: null, action: null, status: null, path: null, method: null, ua: null, host: null, eventId: null, raw: "", lineNo: 0, file: "", source: "unknown", format: null, extra: null }, o);
}

// ---------------------------------------------------------------------------
// Record splitting: CSV (quoted newlines), XML <Event> blocks, or plain lines.
// ---------------------------------------------------------------------------
const WIN_CSV_HEAD = /^"?(level|date and time|timecreated|time created|id|event ?id|keywords|source|providername|message)"?\s*,/i;

export function splitRecords(text, file) {
  const t = String(text || "");
  const firstLine = (t.match(/^[^\n]*/) || [""])[0].trim();
  if (WIN_CSV_HEAD.test(firstLine) && /event ?id|^"?id"?,|,"?id"?(,|$)/i.test(firstLine)) {
    const rows = parseCsv(t);
    return { mode: "csv", records: rows.map((r) => ({ cols: r.cols, lineNo: r.lineNo, text: r.cols.join(","), file })) };
  }
  if (/<Event[\s>]/.test(t) && /<\/Event>/.test(t)) {
    const records = []; let pos = 0, scanned = 0, lineNo = 1;
    for (;;) {
      const a = t.indexOf("<Event", pos); if (a < 0) break;
      const b = t.indexOf("</Event>", a); if (b < 0) break;
      lineNo += countNl(t, scanned, a); scanned = a;
      records.push({ text: t.slice(a, b + 8), lineNo, file });
      pos = b + 8;
    }
    return { mode: "xml", records };
  }
  const lines = t.split(/\r?\n/);
  const records = [];
  for (let i = 0; i < lines.length; i++) if (lines[i].trim()) records.push({ text: lines[i], lineNo: i + 1, file });
  return { mode: "lines", records };
}
function countNl(s, a, b) { let n = 0; for (let i = a; i < b; i++) if (s.charCodeAt(i) === 10) n++; return n; }

export function parseCsv(text) {
  const rows = []; let cols = [], cur = "", q = false, lineNo = 1, rowLine = 1;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"') { if (text[i + 1] === '"') { cur += '"'; i++; } else q = false; }
      else { cur += c; if (c === "\n") lineNo++; }
    } else if (c === '"') q = true;
    else if (c === ",") { cols.push(cur); cur = ""; }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      cols.push(cur); if (cols.some((x) => x.trim())) rows.push({ cols, lineNo: rowLine });
      cols = []; cur = ""; lineNo++; rowLine = lineNo;
    } else cur += c;
  }
  cols.push(cur); if (cols.some((x) => x.trim())) rows.push({ cols, lineNo: rowLine });
  return rows;
}

// ---------------------------------------------------------------------------
// Web access logs
// ---------------------------------------------------------------------------
const CLF = /^([^\s,]+(?:,\s*[^\s,]+)*) (\S+) (\S+) \[([^\]]+)\] "(?:([A-Z]+) ([^"]*?)(?: (HTTP\/[\d.]+))?|-|([^"]*))" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?(.*)$/;
const IIS_DEFAULT = "date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken".split(" ");

function parseClf(line, rec, st) {
  let s = line, vhost = null;
  // vhost-prefixed combined: "example.com 1.2.3.4 - - [...]"
  const sp = s.indexOf(" ");
  if (sp > 0) {
    const t0 = s.slice(0, sp), rest = s.slice(sp + 1);
    const sp2 = rest.indexOf(" ");
    const t1 = sp2 > 0 ? rest.slice(0, sp2) : rest;
    if (!isIp(t0.replace(/,$/, "")) && /[a-z]/i.test(t0) && isIp(t1.replace(/,$/, ""))) { s = rest; vhost = t0; }
  }
  const m = s.match(CLF);
  if (!m) return null;
  let ip = m[1].split(/,\s*/)[0];
  let proxyIp = null;
  const trailing = m[13] || "";
  const xff = trailing.match(/"((?:\d{1,3}\.){3}\d{1,3}|[0-9a-f:]{3,45})(?:,[^"]*)?"/i);
  if (xff && isIp(xff[1]) && xff[1] !== ip) { proxyIp = ip; ip = xff[1]; }
  const status = Number(m[9]);
  return mkEvent({
    ts: parseTs(m[4], st.assumeYear), ip, user: m[3] && m[3] !== "-" ? m[3] : null, action: "request",
    status: Number.isFinite(status) ? status : null, path: m[6] != null ? m[6] : (m[8] || null), method: m[5] || null,
    ua: m[12] && m[12] !== "-" ? m[12] : null, host: vhost, raw: line, lineNo: rec.lineNo, file: rec.file,
    source: "web", format: "clf", extra: { referer: m[11] && m[11] !== "-" ? m[11] : null, bytes: m[10] === "-" ? null : Number(m[10]), proxyIp },
  });
}

function parseIis(line, rec, st) {
  if (line.startsWith("#")) {
    const f = line.match(/^#Fields:\s*(.*)$/i);
    if (f) st.iisFields = f[1].trim().split(/\s+/);
    return "skip";
  }
  const fields = st.iisFields || IIS_DEFAULT;
  const parts = line.split(/\s+/);
  if (parts.length < 4) return null;
  const g = (name) => { const i = fields.indexOf(name); return i >= 0 && parts[i] !== undefined && parts[i] !== "-" ? parts[i] : null; };
  const date = g("date"), time = g("time");
  const ip = g("c-ip");
  const xff = g("cs(X-Forwarded-For)") || g("cs(X-FORWARDED-FOR)") || g("X-Forwarded-For");
  const stem = g("cs-uri-stem"), query = g("cs-uri-query");
  const ua = g("cs(User-Agent)");
  const status = Number(g("sc-status"));
  const xffIp = xff ? xff.split(",")[0] : null;
  const clientIp = xffIp && isIp(xffIp) ? xffIp : ip;
  return mkEvent({
    ts: date && time ? parseTs(date + " " + time) : null, ip: clientIp, user: g("cs-username"), action: "request",
    status: Number.isFinite(status) ? status : null, path: stem ? stem + (query ? "?" + query : "") : null, method: g("cs-method"),
    ua: ua ? ua.replace(/\+/g, " ") : null, host: g("cs-host") || g("s-computername") || null, raw: line, lineNo: rec.lineNo, file: rec.file,
    source: "web", format: "iis", extra: { proxyIp: clientIp !== ip ? ip : null, referer: g("cs(Referer)") },
  });
}

function getPath(o, p) { return p.split(".").reduce((a, k) => (a != null && typeof a === "object" ? a[k] : undefined), o); }
function firstOf(o, keys) { for (const k of keys) { const v = k.includes(".") ? getPath(o, k) : o[k]; if (v != null && v !== "" && v !== "-") return v; } return null; }

function parseWebJson(o, rec, line) {
  let ip = firstOf(o, ["ClientIP", "client_ip", "clientIp", "clientIP", "remote_addr", "remoteAddr", "remote_ip", "src_ip", "srcip", "source_ip", "source.ip", "client.ip", "ip", "httpRequest.remoteIp", "client"]);
  if (ip != null) { ip = String(ip).split(",")[0].trim(); const pm = ip.match(/^(\d+\.\d+\.\d+\.\d+):\d+$/); if (pm) ip = pm[1]; }
  const xff = firstOf(o, ["x_forwarded_for", "http_x_forwarded_for", "xff", "X-Forwarded-For"]);
  let proxyIp = null;
  if (xff) { const x0 = String(xff).split(",")[0].trim(); if (isIp(x0) && x0 !== ip) { proxyIp = ip; ip = x0; } }
  let method = firstOf(o, ["ClientRequestMethod", "method", "request_method", "http.request.method", "httpRequest.requestMethod", "cs-method"]);
  let path = firstOf(o, ["ClientRequestURI", "uri", "request_uri", "path", "url.original", "url.path", "url", "httpRequest.requestUrl", "cs-uri-stem"]);
  const req = o.request;
  if (typeof req === "string" && /^[A-Z]+ \S+/.test(req)) { const rp = req.split(" "); method = method || rp[0]; path = path || rp[1]; }
  if (typeof path === "string" && /^https?:\/\//i.test(path)) { try { const u = new URL(path); path = u.pathname + u.search; } catch (_) { /* keep as-is */ } }
  if (typeof o.query === "string" && o.query && path && !path.includes("?")) path += "?" + o.query;
  if (o.ClientRequestQuery && path && !path.includes("?")) path += String(o.ClientRequestQuery).startsWith("?") ? o.ClientRequestQuery : "?" + o.ClientRequestQuery;
  const statusRaw = firstOf(o, ["EdgeResponseStatus", "status", "status_code", "response_code", "elb_status_code", "http.response.status_code", "httpRequest.status", "sc-status", "responseStatus"]);
  const status = statusRaw != null ? Number(statusRaw) : null;
  const ua = firstOf(o, ["ClientRequestUserAgent", "user_agent", "userAgent", "http_user_agent", "user_agent.original", "httpRequest.userAgent", "ua"]);
  const tsRaw = firstOf(o, ["EdgeStartTimestamp", "timestamp", "@timestamp", "time", "ts", "time_local", "datetime", "date", "time_iso8601", "msec"]);
  const user = firstOf(o, ["remote_user", "user", "username", "user.name"]);
  const host = firstOf(o, ["ClientRequestHost", "host", "http_host", "server_name", "url.domain", "vhost", "domain"]);
  return mkEvent({
    ts: parseTs(tsRaw), ip: ip ? String(ip) : null, user: user ? String(user) : null, action: "request",
    status: Number.isFinite(status) ? status : null, path: path ? String(path) : null, method: method ? String(method).toUpperCase() : null,
    ua: ua ? String(ua) : null, host: host ? String(host) : null, raw: line, lineNo: rec.lineNo, file: rec.file, source: "web", format: "json", extra: { proxyIp },
  });
}

// ---------------------------------------------------------------------------
// Linux auth / syslog / journald
// ---------------------------------------------------------------------------
const SYSLOG = /^(?:<\d+>\d?\s*)?(?:(\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2})|(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?))\s+(\S+)\s+([\w.\-/()]+?)(?:\[(\d+)\])?:\s+(.*)$/;
const LINUX_HINT = /Failed password|Accepted (publickey|password|keyboard-interactive)|Invalid user|Connection closed by|Disconnected from|sudo:|pam_unix|useradd|usermod|groupadd|BREAK-IN|authentication failure|maximum authentication attempts|crontab|CRON|systemd|session opened|sshd/;
const PRIV_GROUPS = /^(sudo|wheel|admin|root|adm|docker|lxd|shadow)$/i;
const SUDO_SUSP = [
  /(?:^|[\s;|&])(?:\/bin\/|\/usr\/bin\/)?(?:bash|sh|zsh|dash|ksh)(?:\s+-i)?\s*$/i,
  /(?:^|\s)su(?:\s+-|\s+root)?\s*$/i,
  /(curl|wget)[^|;]*\|\s*(?:sudo\s+)?(?:\/bin\/)?(?:ba)?sh\b/i,
  /chmod\s+(?:\+x|[0-7]*7[0-7]*|u\+x|a\+x)\s+\/(?:tmp|dev\/shm|var\/tmp)\//i,
  /\bnc(?:at)?\b.*\s-e\s/i,
  /base64\s+(?:-d|--decode)/i,
  /python[23]?\s+-c\s/i,
  /\/dev\/tcp\//i,
  /\bchattr\b/i,
  /\b(?:useradd|adduser)\b/i,
  /\bcrontab\s+-/i,
  /\/etc\/(?:passwd|shadow)\b/i,
  /\bsetcap\b|\bsetuid\b/i,
];

function parseLinuxMsg(prog, msg) {
  let m;
  const p = (prog || "").toLowerCase();
  if ((m = msg.match(/^Failed (?:password|publickey|keyboard-interactive\/pam|none) for (invalid user )?(\S+) from (\S+)(?: port (\d+))?/)))
    return { action: "auth_fail", user: m[2], ip: m[3], extra: { invalid: !!m[1] } };
  if ((m = msg.match(/^Accepted (publickey|password|keyboard-interactive\/pam|none|hostbased|gssapi-with-mic) for (\S+) from (\S+)(?: port (\d+))?/)))
    return { action: "auth_ok", user: m[2], ip: m[3], extra: { method: m[1] } };
  if ((m = msg.match(/^Invalid user (\S*) from (\S+)/)))
    return { action: "invalid_user", user: m[1] || "(empty)", ip: m[2], extra: {} };
  if ((m = msg.match(/^(?:Connection closed|Disconnected from|Received disconnect from)(?: by)? (invalid|authenticating) user (\S+) (\S+)(?: port (\d+))?/)))
    return { action: "auth_fail", user: m[2], ip: m[3], extra: { invalid: m[1] === "invalid", preauth: true } };
  if ((m = msg.match(/^error: maximum authentication attempts exceeded for (?:invalid user )?(\S+) from (\S+)/)))
    return { action: "auth_fail", user: m[1], ip: m[2], extra: { maxAttempts: true } };
  if (/POSSIBLE BREAK-IN ATTEMPT/.test(msg)) {
    m = msg.match(/\[(\d+\.\d+\.\d+\.\d+|[0-9a-f:]+)\]/i);
    return { action: "breakin", user: null, ip: m ? m[1] : null, extra: {} };
  }
  if (/^pam_unix\(sshd:auth\): authentication failure/.test(msg)) {
    const u = msg.match(/\b(?:user|ruser)=(\S+)/), r = msg.match(/rhost=(\S+)/);
    return { action: "auth_fail", user: u ? u[1] : null, ip: r ? r[1] : null, extra: { pam: true } };
  }
  if (p === "sudo" || /^\s*\S+ : (?:TTY=|.*COMMAND=|.*incorrect password|.*NOT in sudoers|command not allowed)/.test(msg)) {
    if ((m = msg.match(/^\s*(\S+) : (\d+ incorrect password attempts?|user NOT in sudoers|command not allowed|.*not allowed to execute)/)))
      return { action: "sudo_fail", user: m[1], ip: null, extra: { reason: m[2], command: (msg.match(/COMMAND=(.*)$/) || [])[1] || null } };
    if ((m = msg.match(/^\s*(\S+) : .*COMMAND=(.*)$/)))
      return { action: "sudo", user: m[1], ip: null, extra: { command: m[2].trim(), pwd: (msg.match(/PWD=(\S+)/) || [])[1] || null, runas: (msg.match(/USER=(\S+)/) || [])[1] || null } };
    if ((m = msg.match(/^pam_unix\(sudo:auth\): authentication failure.*\buser=(\S+)/)))
      return { action: "sudo_fail", user: m[1], ip: null, extra: { reason: "authentication failure" } };
  }
  if ((m = msg.match(/^pam_unix\(([\w-]+):session\): session opened for user (\S+?)(?:\(uid=\d+\))? by (\S*?)(?:\(uid=\d+\))?$/)))
    return { action: "session_open", user: m[2], ip: null, extra: { service: m[1], by: m[3] || null } };
  if ((m = msg.match(/^new user: name=([^,]+)/)))
    return { action: "user_add", user: m[1], ip: null, extra: { home: (msg.match(/home=([^,]+)/) || [])[1] || null, shell: (msg.match(/shell=([^,]+)/) || [])[1] || null } };
  if ((m = msg.match(/^new group: name=([^,]+)/)))
    return { action: "group_add", user: null, ip: null, extra: { group: m[1] } };
  if ((m = msg.match(/^add '([^']+)' to (?:shadow )?group '([^']+)'/)))
    return { action: "group_member_add", user: m[1], ip: null, extra: { group: m[2] } };
  if ((m = msg.match(/^(?:change user '([^']+)' password|password for '([^']+)' changed|changed password expiry for (\S+))/)))
    return { action: "password_change", user: m[1] || m[2] || m[3], ip: null, extra: {} };
  if (/\/etc\/sudoers/.test(msg) || /\bvisudo\b/.test(msg))
    return { action: "sudoers", user: (msg.match(/^\s*(\S+) :/) || [])[1] || null, ip: null, extra: { command: (msg.match(/COMMAND=(.*)$/) || [])[1] || msg } };
  if (p === "crontab" && (m = msg.match(/^\((\S+)\) (REPLACE|DELETE) \((\S+)\)/)))
    return { action: "cron_write", user: m[1], ip: null, extra: { op: m[2], target: m[3] } };
  if ((p === "cron" || p === "crond") && (m = msg.match(/^\((\S+)\) CMD \((.*)\)$/)))
    return { action: "cron_run", user: m[1], ip: null, extra: { command: m[2] } };
  if ((m = msg.match(/Created symlink .*\/etc\/systemd\/system\/[^\s]*?([^\s/]+\.(?:service|timer))/)))
    return { action: "systemd_unit", user: null, ip: null, extra: { unit: m[1] } };
  if (p === "systemd" && (m = msg.match(/^Started ([^\s]+\.(?:service|timer))/)))
    return { action: "systemd_start", user: null, ip: null, extra: { unit: m[1] } };
  if ((m = msg.match(/^(?:Session \d+ logged out|Removed session|session closed for user (\S+))/)))
    return { action: "session_close", user: m[1] || null, ip: null, extra: {} };
  if (p.startsWith("sshd") || /sshd/.test(msg)) return { action: "ssh_other", user: null, ip: (msg.match(/from (\d+\.\d+\.\d+\.\d+|[0-9a-f:]+)/) || [])[1] || null, extra: {} };
  return null;
}

function parseLinux(line, rec, st) {
  const m = line.match(SYSLOG);
  let ts = null, host = null, prog = null, msg = line;
  if (m) { ts = parseTs(m[1] || m[2], st.assumeYear); host = m[3]; prog = m[4]; msg = m[6]; }
  else if (!LINUX_HINT.test(line)) return null;
  else {
    // fragments without a syslog prefix, e.g. "sshd[123]: Failed password ..."
    const f = line.match(/^(?:\S+\s+)?([\w.\-/]+)(?:\[\d+\])?:\s+(.*)$/);
    if (f && LINUX_HINT.test(f[2])) { prog = f[1]; msg = f[2]; }
  }
  const r = parseLinuxMsg(prog, msg);
  if (!r) return m ? mkEvent({ ts, host, action: "other", raw: line, lineNo: rec.lineNo, file: rec.file, source: "linux", format: "syslog", extra: { program: prog } }) : null;
  return mkEvent({ ts, ip: r.ip || null, user: r.user, action: r.action, host, raw: line, lineNo: rec.lineNo, file: rec.file, source: "linux", format: "syslog", extra: Object.assign({ program: prog }, r.extra) });
}

// ---------------------------------------------------------------------------
// Windows Security events
// ---------------------------------------------------------------------------
export const WIN_STATUS = {
  "0xc000006d": "bad username or password", "0xc000006a": "wrong password", "0xc0000064": "user does not exist",
  "0xc0000234": "account locked out", "0xc0000072": "account disabled", "0xc000006f": "outside allowed hours",
  "0xc0000070": "workstation restriction", "0xc0000193": "account expired", "0xc0000071": "password expired",
  "0xc0000224": "must change password", "0xc000015b": "logon type not granted", "0xc000005e": "no logon servers",
  "0xc0000133": "clock skew", "0xc000018c": "trust relationship failed", "0xc0000413": "authentication firewall",
  "0x6": "client principal unknown", "0x12": "client revoked, disabled or locked", "0x17": "password expired", "0x18": "pre-authentication failed",
};
const PRIV_WIN_GROUPS = /^(?:(?:BUILTIN\\)?Administrators|Domain Admins|Enterprise Admins|Schema Admins|Account Operators|Backup Operators|Server Operators|Print Operators|DnsAdmins|Group Policy Creator Owners|Remote Desktop Users|Hyper-V Administrators)$/i;
const WIN_PROC_SUSP = [
  /powershell[^\n]*\s-(?:e|en|enc|encodedcommand)\s/i, /powershell[^\n]*-(?:nop|noprofile)\b[^\n]*-(?:w|windowstyle)\s+hidden/i, /powershell[^\n]*\b(?:iex|invoke-expression|downloadstring|frombase64string|bypass)\b/i,
  /certutil[^\n]*-urlcache/i, /\bmshta\b[^\n]*(?:http|javascript|vbscript)/i, /rundll32[^\n]*(?:javascript|\.txt|\\temp\\)/i,
  /\bbitsadmin\b[^\n]*\/transfer/i, /\bwscript\b|\bcscript\b/i, /\bwhoami\b/i, /\bnet1?\s+(?:user|localgroup)\b[^\n]*\/add/i,
  /reg\s+add[^\n]*\\currentversion\\run/i, /vssadmin[^\n]*delete\s+shadows/i, /wmic[^\n]*shadowcopy\s+delete/i, /bcdedit[^\n]*recoveryenabled\s+no/i,
  /wmic[^\n]*process\s+call\s+create/i, /\bnltest\b|\bdsquery\b|\badfind\b/i, /\bmimikatz\b|\bsekurlsa\b|\blsass\b/i, /\bschtasks\b[^\n]*\/create/i,
  /\bprocdump\b|\bcomsvcs\.dll\b[^\n]*minidump/i,
];

export const WIN_EVENT_IDS = { 4624: "Logon", 4625: "Failed logon", 4634: "Logoff", 4647: "User-initiated logoff", 4648: "Logon with explicit credentials", 4672: "Special privileges assigned", 4688: "Process created", 4698: "Scheduled task created", 4720: "User account created", 4722: "User account enabled", 4724: "Password reset attempt", 4728: "Member added to global group", 4732: "Member added to local group", 4738: "User account changed", 4740: "Account locked out", 4756: "Member added to universal group", 4768: "Kerberos TGT requested", 4769: "Kerberos service ticket requested", 4771: "Kerberos pre-auth failed", 4776: "NTLM credential validation", 1102: "Audit log cleared", 104: "Event log cleared", 7045: "Service installed" };

// Pull fields out of an Event Viewer message body (section-aware: "Subject:",
// "New Logon:", "Member:", "Group:" blocks each repeat "Account Name").
export function winFieldsFromMessage(msg) {
  const out = {};
  let section = "";
  for (const rawLine of String(msg || "").split(/\r?\n/)) {
    const line = rawLine.replace(/\t/g, " ").trim();
    if (!line) continue;
    const m = line.match(/^([A-Za-z][A-Za-z0-9 \/()'-]*?):\s*(.*)$/);
    if (!m) continue;
    const key = m[1].trim().toLowerCase(), val = m[2].trim();
    if (!val) { section = key; continue; }
    const sect = section;
    switch (key) {
      case "account name":
        if (sect === "subject") out.subjectUser = out.subjectUser || val;
        else if (sect === "member") out.member = val;
        else if (/^(new logon|account for which logon failed|account whose credentials were used|target account|new account|account that was locked out|target server|logon account)$/.test(sect)) out.targetUser = val;
        else if (!out.targetUser) out.targetUser = val;
        break;
      case "account domain": if (sect === "subject") out.subjectDomain = out.subjectDomain || val; else out.targetDomain = val; break;
      case "security id": if (sect === "member" && !out.member) out.memberSid = val; break;
      case "group name": out.group = val; break;
      case "source network address": case "client address": case "source address": case "ip address": if (val !== "-") out.ip = val.replace(/^::ffff:/, ""); break;
      case "source port": out.port = val; break;
      case "logon type": out.logonType = Number(val); break;
      case "status": if (sect !== "additional information" || !out.status) out.status = val; break;
      case "sub status": out.subStatus = val; break;
      case "failure code": case "result code": out.status = out.status || val; break;
      case "ticket encryption type": out.encType = val; break;
      case "service name": out.service = val; break;
      case "service file name": out.imagePath = val; break;
      case "task name": out.task = val; break;
      case "task content": out.taskContent = val; break;
      case "new process name": case "process name": out.process = out.process || val; break;
      case "process command line": out.cmdline = val; break;
      case "caller computer name": case "workstation name": case "source workstation": out.workstation = val; break;
      case "target server name": out.targetServer = val; break;
      case "privileges": out.privileges = val; break;
      case "logon process": out.logonProcess = val; break;
      case "authentication package": out.authPackage = val; break;
      default: break;
    }
  }
  return out;
}

function cnOf(dn) {
  if (!dn) return null;
  const m = String(dn).match(/^CN=([^,]+)/i);
  return m ? m[1] : String(dn);
}

// Flatten EVTX EventData of any common JSON shape into a plain object.
function flattenEventData(ed) {
  if (!ed || typeof ed !== "object") return {};
  if (Array.isArray(ed.Data)) {
    const out = {};
    for (const d of ed.Data) {
      if (d && typeof d === "object") {
        const n = d["@Name"] || (d["#attributes"] && d["#attributes"].Name) || d.Name;
        const v = d["#text"] != null ? d["#text"] : (d.text != null ? d.text : (d.value != null ? d.value : ""));
        if (n) out[n] = v;
      }
    }
    return out;
  }
  if (Array.isArray(ed)) { const out = {}; for (const d of ed) if (d && d.Name) out[d.Name] = d["#text"] != null ? d["#text"] : (d.Value != null ? d.Value : ""); return out; }
  return ed;
}

function normalizeWinFields(d) {
  const g = (k) => { const v = d[k]; return v == null || v === "" || v === "-" ? null : String(v); };
  return {
    subjectUser: g("SubjectUserName"), subjectDomain: g("SubjectDomainName"),
    targetUser: g("TargetUserName") || g("TargetAccountName") || g("AccountName"), targetDomain: g("TargetDomainName"),
    ip: (g("IpAddress") || g("ClientAddress") || g("SourceAddress") || g("Address") || "").replace(/^::ffff:/, "") || null,
    logonType: g("LogonType") != null ? Number(g("LogonType")) : null,
    status: g("Status") || g("FailureCode") || g("ResultCode") || null, subStatus: g("SubStatus"),
    member: cnOf(g("MemberName")), memberSid: g("MemberSid"), group: null,
    encType: g("TicketEncryptionType"), service: g("ServiceName"), imagePath: g("ImagePath") || g("ServiceFileName"),
    task: g("TaskName"), taskContent: g("TaskContent"), process: g("NewProcessName") || g("ProcessName"), cmdline: g("CommandLine"),
    workstation: g("WorkstationName") || g("Workstation") || g("TargetServerName"), targetServer: g("TargetServerName") || g("TargetInfo"),
    privileges: g("PrivilegeList"), authPackage: g("AuthenticationPackageName"), logonProcess: g("LogonProcessName"),
  };
}

function finishWinEvent(eventId, ts, computer, f, rec, line, format) {
  const id = Number(eventId);
  if ([4728, 4732, 4756, 4729, 4733, 4757].includes(id)) {
    // In EventData the group is TargetUserName; in message text it is "Group Name".
    if (!f.group) f.group = f.targetUser;
    if (f.group === f.targetUser) f.targetUser = f.member || f.targetUser;
  }
  if (f.ip === "-") f.ip = null;
  const user = f.targetUser || f.subjectUser || null;
  return mkEvent({
    ts, ip: f.ip && isIp(f.ip) ? f.ip : null, user, action: "win_event", status: f.status || null, host: computer || null, eventId: id,
    raw: line, lineNo: rec.lineNo, file: rec.file, source: "windows", format, extra: f,
  });
}

function parseWinCsv(rec, st) {
  const cols = rec.cols;
  if (!st.csvCols) {
    const idx = (re) => cols.findIndex((c) => re.test(c.trim()));
    st.csvCols = { id: idx(/^"?(event ?id|id)"?$/i), time: idx(/^"?(date and time|timecreated|time created|time)"?$/i), msg: idx(/^"?(message|description)"?$/i), comp: idx(/^"?(computer|machinename|computername)"?$/i), n: cols.length };
    return "skip";
  }
  const c = st.csvCols;
  if (c.id < 0) return null;
  const eventId = Number((cols[c.id] || "").trim());
  if (!Number.isFinite(eventId) || !eventId) return null;
  const tsRaw = c.time >= 0 ? cols[c.time] : null;
  let msg = "";
  if (c.msg >= 0) msg = cols[c.msg] || "";
  else if (cols.length > c.n) msg = cols.slice(c.n).join(",");
  else if (c.id !== cols.length - 1 && c.time !== cols.length - 1) msg = cols[cols.length - 1] || "";
  const f = winFieldsFromMessage(msg);
  const comp = c.comp >= 0 ? cols[c.comp] : (String(msg).match(/Computer:\s*(\S+)/) || [])[1] || null;
  return finishWinEvent(eventId, parseTs(tsRaw, st.assumeYear), comp, f, rec, rec.text.slice(0, 600), "wincsv");
}

function parseWinJson(o, rec, line) {
  const sys = (o.Event && o.Event.System) || o.System || o.winlog || o;
  let eventId = firstOf(sys, ["EventID", "event_id", "EventId", "Id", "id", "event.code"]);
  if (eventId && typeof eventId === "object") eventId = eventId["#text"] != null ? eventId["#text"] : (eventId.text != null ? eventId.text : eventId.Value);
  if (eventId == null) eventId = firstOf(o, ["EventID", "event_id", "EventId", "Id", "event.code", "winlog.event_id"]);
  eventId = Number(eventId);
  if (!Number.isFinite(eventId)) return null;
  let ts = firstOf(sys, ["TimeCreated.#attributes.SystemTime", "TimeCreated.SystemTime", "TimeCreated.@SystemTime", "TimeCreated", "time_created", "@timestamp"]);
  if (ts && typeof ts === "object") ts = ts.SystemTime || (ts["#attributes"] && ts["#attributes"].SystemTime) || ts["@SystemTime"] || null;
  if (ts == null) ts = firstOf(o, ["@timestamp", "TimeCreated", "timestamp", "time", "UtcTime"]);
  const computer = firstOf(sys, ["Computer", "computer_name", "MachineName"]) || firstOf(o, ["Computer", "MachineName", "host.name", "computer_name"]);
  const ed = (o.Event && (o.Event.EventData || o.Event.UserData)) || o.EventData || (o.winlog && o.winlog.event_data) || o.event_data || null;
  const message = o.Message || o.message || null;
  let f;
  if (ed) f = normalizeWinFields(flattenEventData(ed));
  else if (message) f = winFieldsFromMessage(message);
  else f = normalizeWinFields(o);
  if (message && ed) { const mf = winFieldsFromMessage(message); for (const k of Object.keys(mf)) if (f[k] == null) f[k] = mf[k]; }
  return finishWinEvent(eventId, parseTs(ts), computer, f, rec, line, "winjson");
}

function parseWinXml(rec) {
  const x = rec.text;
  const id = x.match(/<EventID(?:\s[^>]*)?>(\d+)<\/EventID>/);
  if (!id) return null;
  const ts = (x.match(/SystemTime=['"]([^'"]+)['"]/) || [])[1] || null;
  const comp = (x.match(/<Computer>([^<]*)<\/Computer>/) || [])[1] || null;
  const d = {};
  const re = /<Data Name=['"]([^'"]+)['"]\s*(?:\/>|>([^<]*)<\/Data>)/g;
  let m; while ((m = re.exec(x))) d[m[1]] = m[2] == null ? "" : m[2].trim();
  return finishWinEvent(id[1], parseTs(ts), comp, normalizeWinFields(d), rec, x.replace(/\s+/g, " ").slice(0, 600), "winxml");
}

// ---------------------------------------------------------------------------
// Parser (stateful per file for IIS #Fields and CSV header)
// ---------------------------------------------------------------------------
export function createParser(settings) {
  const s = mergeSettings(settings);
  const st = { iisFields: null, csvCols: null, assumeYear: s.assumeYear, lastFile: null };
  const stats = { records: 0, parsed: 0, unknown: 0, sources: { web: 0, linux: 0, windows: 0 }, formats: {}, files: {} };
  const unknownSamples = [];

  function feed(rec) {
    if (rec.file !== st.lastFile) { st.iisFields = null; st.csvCols = null; st.lastFile = rec.file; }
    stats.records++;
    const ev = parseRecord(rec, st);
    if (ev === "skip") return null;
    if (!ev) { stats.unknown++; if (unknownSamples.length < 20) unknownSamples.push({ lineNo: rec.lineNo, file: rec.file, text: (rec.text || "").slice(0, 200) }); return null; }
    stats.parsed++;
    stats.sources[ev.source] = (stats.sources[ev.source] || 0) + 1;
    stats.formats[ev.format] = (stats.formats[ev.format] || 0) + 1;
    const fk = rec.file || "(paste)";
    const f = stats.files[fk] || (stats.files[fk] = { lines: 0, sources: {} });
    f.lines++; f.sources[ev.source] = (f.sources[ev.source] || 0) + 1;
    return ev;
  }
  return { feed, stats, unknownSamples, settings: s };
}

function parseRecord(rec, st) {
  if (rec.cols) return parseWinCsv(rec, st);
  const line = rec.text;
  const t = line.trim();
  if (!t) return "skip";
  if (t.startsWith("<Event")) return parseWinXml(rec);
  if (t.startsWith("{") && t.endsWith("}")) {
    let o; try { o = JSON.parse(t); } catch (_) { o = null; }
    if (o && typeof o === "object") {
      const isWin = (o.Event && o.Event.System) || o.EventData || o.winlog || o.EventID != null || o.event_id != null || (o.Id != null && (o.Message || o.ProviderName || o.LogName)) || (o.System && o.System.EventID != null);
      if (isWin) return parseWinJson(o, rec, line);
      return parseWebJson(o, rec, line);
    }
  }
  if (t.startsWith("#")) { if (/^#(Fields|Software|Version|Date|Start-Date|End-Date|Remark):/i.test(t)) return parseIis(t, rec, st); return "skip"; }
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \S+ (?:[A-Z]+|-) /.test(t) || (st.iisFields && /^\d{4}-\d{2}-\d{2} /.test(t))) { const e = parseIis(t, rec, st); if (e) return e; }
  if (/\[\d{1,2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2}/.test(t)) { const e = parseClf(t, rec, st); if (e) return e; }
  const lx = parseLinux(t, rec, st);
  if (lx) return lx;
  return parseClf(t, rec, st);
}

// Convenience: parse a whole text synchronously.
export function parseText(text, file, settings) {
  const p = createParser(settings);
  const { records } = splitRecords(text, file || "");
  const events = [];
  for (const r of records) { const ev = p.feed(r); if (ev) events.push(ev); }
  return { events, stats: p.stats, unknownSamples: p.unknownSamples };
}

// ---------------------------------------------------------------------------
// Web request classifiers (matched on the decoded and the raw path)
// ---------------------------------------------------------------------------
const RX = {
  sqli: [/union[\s(]+(?:all[\s(]+)?(?:distinct[\s(]+)?select\b/i, /'\s*(?:or|and)\s+'?\d+'?\s*=\s*'?\d+/i, /\b(?:or|and)\s+1\s*=\s*1\b/i, /'\s*or\s*'[^']*'\s*=\s*'/i, /\bsleep\s*\(\s*\d/i, /\bbenchmark\s*\(/i, /information_schema/i, /\bwaitfor\s+delay\b/i, /;\s*(?:drop|truncate|alter)\s+table\b/i, /\bxp_cmdshell\b/i, /\bload_file\s*\(/i, /\bextractvalue\s*\(/i, /\bupdatexml\s*\(/i, /\bpg_sleep\s*\(/i, /\bconcat\s*\(\s*0x/i, /'\s*;\s*--/, /\border\s+by\s+\d+\s*--/i, /\bselect\b.{0,40}\bfrom\b.{0,40}\bwhere\b/i, /\/\*!\d*\s*select/i],
  xss: [/<script\b/i, /<\/script/i, /\bon(?:error|load|mouseover|focus|click|animationstart)\s*=/i, /javascript\s*:/i, /<img\b[^>]*\bsrc\b/i, /<svg\b[^>]*\bon/i, /<iframe\b/i, /\balert\s*\(/i, /document\.cookie/i, /<body\b[^>]*\bonload/i, /String\.fromCharCode\(/i],
  traversal: [/\.\.[\/\\]/, /\.\.;\//, /\/etc\/(?:passwd|shadow|hosts|group|issue)\b/i, /\bwin\.ini\b/i, /\bboot\.ini\b/i, /\/proc\/self\//i, /c:\\windows\\/i, /\/windows\/system32\//i, /\.\.%c0%af/i, /%c0%ae/i],
  cmdi: [/[;|&`]\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|ping|nslookup|dig|echo|rm|chmod|python|perl|php)\b/i, /\$\([^)]{1,80}\)/, /`[^`]{1,80}`/, /\/bin\/(?:ba|z|da)?sh\b/i, /\bcmd(?:\.exe)?\s*\/c\b/i, /\bcmd\.exe\b/i, /\bpowershell(?:\.exe)?\b/i, /\n\s*(?:cat|ls|id|whoami|wget|curl|nc|bash|sh)\b/i, /\|\|\s*(?:cat|id|whoami|curl|wget)\b/i, /&&\s*(?:cat|id|whoami|curl|wget|dir|type)\b/i, /\bexec\s*\(\s*['"]/i, /\bsystem\s*\(\s*['"]/i],
  webshellName: /\/(?:c99|c100|r57|wso|b374k|alfa|indoxploit|mini|shell|webshell|cmd|cmdasp|cmdjsp|up|upload|uploader|backdoor|bypass|priv8|filesman|adminer)\.(?:php\d?|phtml|aspx?|jspx?|asp|cfm)(?:$|\?)/i,
  webshellParam: /[?&](?:cmd|exec|command|execute|pass|passwd|shell|run|c|x|ps)=/i,
  scriptExt: /\.(?:php\d?|phtml|phar|aspx?|ashx|asmx|jspx?|jsw|cfm|cgi|pl)(?:$|\?|\/)/i,
  uploadDir: /\/(?:uploads?|upload_files|files|images?|img|media|attachments?|tmp|temp|cache|assets|static|public|wp-content\/uploads|storage|data|backup)\//i,
  sensitive: [/\/\.env(?:\.|$|\?)/i, /\/\.git(?:\/|$|\?)/i, /\/\.svn\//i, /\/\.hg\//i, /\/wp-login\.php/i, /\/xmlrpc\.php/i, /\/phpmyadmin/i, /\/pma\//i, /\/actuator(?:\/|$|\?)/i, /\/\.aws\/credentials/i, /\/server-status/i, /\/\.DS_Store/i, /\/\.htpasswd/i, /\/\.htaccess/i, /\/\.ssh\//i, /\/id_rsa/i, /\/config\.php(?:\.bak|~|\.old|\.save)/i, /\/wp-config\.php/i, /\/backup\.(?:sql|zip|tar|gz|tgz)/i, /\/\w*dump\.sql/i, /\/\.bash_history/i, /\/manager\/html/i, /\/console(?:\/|$)/i, /\/solr\//i, /\/jmx-console/i, /\/_?debug(?:\/|$)/i, /\/swagger(?:-ui|\.json)/i, /\/graphql\?.*__schema/i, /\/\.vscode\//i, /\/\.idea\//i, /\/composer\.(?:json|lock)/i, /\/web\.config$/i, /\/elmah\.axd/i, /\/trace\.axd/i, /\/cgi-bin\/(?:test-cgi|php|printenv)/i, /\/owa\/auth/i, /\/ecp\//i, /\/boaform\//i, /\/HNAP1/i, /\/cgi-bin\/luci/i, /\/telescope\//i, /\/_profiler\//i, /\/\.docker/i, /\/docker-compose\.ya?ml/i, /\/\.npmrc/i, /\/\.pypirc/i, /\/credentials\.json/i, /\/secrets?\.(?:json|ya?ml|env)/i, /\/\.travis\.yml/i, /\/\.github\//i, /\/sftp-config\.json/i, /\/wp-admin\/install\.php/i, /\/admin\/config\.php/i],
  scannerUa: /\b(?:sqlmap|nikto|nuclei|masscan|zgrab|dirbuster|gobuster|ffuf|wpscan|nmap|acunetix|netsparker|burp(?:suite|collaborator)?|arachni|w3af|whatweb|wfuzz|feroxbuster|dirb|hydra|medusa|openvas|nessus|qualys|zap|owasp|havij|jorgee|morfeus|muieblackcat|xspider|webshag|skipfish|paros|projectdiscovery|nmap scripting engine|libwww-perl|zmap|censysinspect|internetmeasurement|expanse|l9explore|l9tcpid|leakix)\b/i,
  toolUa: /^(?:python-requests|python-urllib|go-http-client|curl|wget|java|okhttp|axios|node-fetch|undici|libcurl|httpx|aiohttp|scrapy|ruby|php|perl|httpclient|apache-httpclient)\b/i,
  log4shell: [/\$\{\s*jndi\s*:/i, /\$\{[^}]{0,80}jndi/i, /\$\{\s*\$\{/, /jndi:(?:ldaps?|rmi|dns|iiop|corba|nds|http)/i],
  ssrf: /[?&][\w\[\].-]*=(?:(?:https?|ftp|gopher|dict|file|ldap|tftp|jar|netdoc):\/\/|\/\/)?(?:localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|0x7f000001|2130706433|017700000001|169\.254\.169\.254|169\.254\.170\.2|fd00:ec2::254|metadata\.google\.internal|metadata\.azure\.com|100\.100\.100\.200|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|\[::1\]|\[::ffff:)/i,
  ssrfScheme: /[?&][\w\[\].-]*=(?:file|gopher|dict|tftp|ldap|jar|netdoc):\/\//i,
};

export function classifyRequest(ev) {
  const out = [];
  const rawPath = ev.path || "";
  const dec = urlDecode(rawPath);
  const test = (list) => list.some((r) => r.test(dec) || r.test(rawPath));
  const uaDec = ev.ua ? urlDecode(ev.ua) : "";
  const refDec = ev.extra && ev.extra.referer ? urlDecode(ev.extra.referer) : "";
  if (test(RX.log4shell) || (uaDec && RX.log4shell.some((r) => r.test(uaDec))) || (refDec && RX.log4shell.some((r) => r.test(refDec)))) out.push("web.log4shell");
  if (test(RX.sqli)) out.push("web.sqli");
  if (test(RX.xss)) out.push("web.xss");
  if (test(RX.traversal)) out.push("web.traversal");
  if (RX.cmdi.some((r) => r.test(dec))) out.push("web.cmdi");
  const isScript = RX.scriptExt.test(dec);
  if (RX.webshellName.test(dec) || (isScript && RX.webshellParam.test(dec)) || (isScript && ev.method === "POST" && RX.uploadDir.test(dec))) out.push("web.webshell");
  if (RX.sensitive.some((r) => r.test(dec))) out.push(ev.status === 200 ? "web.sensitive.served" : "web.sensitive");
  if (ev.ua && RX.scannerUa.test(ev.ua)) out.push("web.scanner");
  if (RX.ssrf.test(dec) || RX.ssrfScheme.test(dec)) out.push("web.ssrf");
  return out;
}

export function compileLoginRe(paths) {
  const list = (paths || []).map((p) => String(p).trim()).filter(Boolean);
  if (!list.length) return null;
  const esc = (x) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp("^(?:" + list.map(esc).join("|") + ")(?:$|[/?])", "i");
}
export function isLoginPath(path, loginRe) {
  if (!path || !loginRe) return false;
  return loginRe.test(urlDecode(path.split("?")[0]));
}

// ---------------------------------------------------------------------------
// The hunt: feed events, then finish() to compute findings and summaries.
// ---------------------------------------------------------------------------
export function createHunt(settings) {
  const s = mergeSettings(settings);
  const cidrs = compileCidrs(s.internalCidrs);
  const loginRe = compileLoginRe(s.loginPaths);
  let adminRe; try { adminRe = new RegExp(s.adminNamePattern || DEFAULT_SETTINGS.adminNamePattern, "i"); } catch (_) { adminRe = new RegExp(DEFAULT_SETTINGS.adminNamePattern, "i"); }
  const isAdminName = (u) => !!u && adminRe.test(String(u).replace(/^.*\\/, ""));
  const internal = (ip) => isInternalIp(ip, cidrs);

  const S = {
    n: 0, firstTs: null, lastTs: null, noTs: 0, sources: { web: 0, linux: 0, windows: 0 },
    ips: new Map(), hours: new Map(),
    agg: new Map(),
    web: new Map(),
    lx: { failsByIp: new Map(), failsByUser: new Map(), invalidByIp: new Map(), okByIp: new Map() },
    win: { failBySrc: new Map(), lockouts: [], type3: new Map(), explicit: new Map(), newUsers: new Map(), groupAdds: [], kerb: new Map(), ntlm: new Map(), enumBySrc: new Map() },
    adminLogons: [],
  };

  function dossier(ip) {
    let d = S.ips.get(ip);
    if (!d) { d = { ip, internal: internal(ip), count: 0, first: null, last: null, uas: new Map(), paths: new Map(), users: new Set(), fails: 0, ok: 0, statuses: new Map(), sources: new Set(), hosts: new Set(), findings: new Set() }; S.ips.set(ip, d); }
    return d;
  }
  function agg(det, key, ev, meta) {
    const k = det + "|" + key;
    let a = S.agg.get(k);
    if (!a) { a = { det, key, count: 0, evidence: [], first: null, last: null, meta: {}, users: new Set(), ips: new Set(), hosts: new Set() }; S.agg.set(k, a); }
    a.count++;
    if (a.evidence.length < EVIDENCE_CAP) a.evidence.push(ev);
    if (ev.ts != null) { if (a.first == null || ev.ts < a.first) a.first = ev.ts; if (a.last == null || ev.ts > a.last) a.last = ev.ts; }
    if (ev.user) a.users.add(ev.user);
    if (ev.ip) a.ips.add(ev.ip);
    if (ev.host) a.hosts.add(ev.host);
    if (meta) Object.assign(a.meta, meta);
    return a;
  }
  function hour(ev, flag) {
    const k = ev.ts == null ? "none" : Math.floor(ev.ts / 3600000);
    let h = S.hours.get(k);
    if (!h) { h = { key: k, ts: k === "none" ? null : k * 3600000, total: 0, web: 0, linux: 0, windows: 0, flagged: 0 }; S.hours.set(k, h); }
    h.total++; h[ev.source] = (h[ev.source] || 0) + 1; if (flag) h.flagged++;
  }
  const push = (m, k, v) => { let a = m.get(k); if (!a) { a = []; m.set(k, a); } a.push(v); return a; };

  function feed(ev) {
    if (!ev) return;
    S.n++;
    S.sources[ev.source] = (S.sources[ev.source] || 0) + 1;
    if (ev.ts == null) S.noTs++;
    else { if (S.firstTs == null || ev.ts < S.firstTs) S.firstTs = ev.ts; if (S.lastTs == null || ev.ts > S.lastTs) S.lastTs = ev.ts; }
    let d = null;
    if (ev.ip) {
      d = dossier(ev.ip); d.count++; d.sources.add(ev.source);
      if (ev.ts != null) { if (d.first == null || ev.ts < d.first) d.first = ev.ts; if (d.last == null || ev.ts > d.last) d.last = ev.ts; }
      if (ev.ua) d.uas.set(ev.ua, (d.uas.get(ev.ua) || 0) + 1);
      if (ev.path) { const p = ev.path.split("?")[0]; d.paths.set(p, (d.paths.get(p) || 0) + 1); }
      if (ev.user) d.users.add(ev.user);
      if (ev.host) d.hosts.add(ev.host);
      if (ev.status != null) d.statuses.set(ev.status, (d.statuses.get(ev.status) || 0) + 1);
    }
    let flag = false;
    if (ev.source === "web") flag = feedWeb(ev, d);
    else if (ev.source === "linux") flag = feedLinux(ev, d);
    else if (ev.source === "windows") flag = feedWin(ev, d);
    hour(ev, flag);
  }

  function feedWeb(ev, d) {
    const ip = ev.ip || "(no ip)";
    let w = S.web.get(ip);
    if (!w) { w = { nf: [], login: [], tool: [], total: 0 }; S.web.set(ip, w); }
    w.total++;
    const dets = classifyRequest(ev);
    for (const det of dets) agg(det, ip, ev);
    if (ev.status === 404) w.nf.push(ev);
    if (ev.method === "POST" && isLoginPath(ev.path, loginRe)) w.login.push(ev);
    if (ev.ua && RX.toolUa.test(ev.ua) && !RX.scannerUa.test(ev.ua)) w.tool.push(ev);
    if (d) { if (ev.status != null && ev.status >= 400) d.fails++; else d.ok++; }
    return dets.length > 0;
  }

  function feedLinux(ev, d) {
    const L = S.lx;
    let flag = false;
    switch (ev.action) {
      case "auth_fail":
        flag = true;
        if (ev.ip) push(L.failsByIp, ev.ip, ev);
        if (ev.user) push(L.failsByUser, ev.user, ev);
        if (ev.extra && ev.extra.invalid && ev.ip) push(L.invalidByIp, ev.ip, ev);
        if (d) d.fails++;
        break;
      case "invalid_user":
        flag = true;
        if (ev.ip) push(L.invalidByIp, ev.ip, ev);
        break;
      case "auth_ok":
        if (ev.ip) push(L.okByIp, ev.ip, ev);
        if (d) d.ok++;
        if (ev.user === "root") { agg("linux.root_login", ev.ip || "-", ev, { external: ev.ip ? !internal(ev.ip) : false }); flag = true; }
        if (ev.user === "root" || isAdminName(ev.user)) S.adminLogons.push(ev);
        break;
      case "user_add": agg("linux.new_user", "user:" + ev.user, ev); flag = true; break;
      case "group_add": agg("linux.new_user", "group:" + (ev.extra && ev.extra.group), ev); flag = true; break;
      case "group_member_add":
        if (ev.extra && PRIV_GROUPS.test(ev.extra.group)) { agg("linux.priv_group", ev.user + ">" + ev.extra.group, ev); flag = true; }
        else agg("linux.new_user", "member:" + ev.user, ev);
        break;
      case "sudoers": agg("linux.sudoers", ev.user || "-", ev); flag = true; break;
      case "sudo": {
        const c = (ev.extra && ev.extra.command) || "";
        if (/\/etc\/sudoers/.test(c) || /\bvisudo\b/.test(c)) { agg("linux.sudoers", ev.user || "-", ev); flag = true; }
        else if (SUDO_SUSP.some((r) => r.test(c))) { agg("linux.sudo_shell", ev.user || "-", ev); flag = true; }
        if (/\/etc\/cron/.test(c) || /\bcrontab\s+-[er]\b/.test(c)) { agg("linux.persist", "sudo:" + (ev.user || "-"), ev); flag = true; }
        break;
      }
      case "sudo_fail": agg("linux.sudo_fail", ev.user || "-", ev); flag = true; break;
      case "breakin": agg("linux.breakin", ev.ip || "-", ev); break;
      case "cron_write": agg("linux.persist", "cron:" + (ev.user || "-"), ev); flag = true; break;
      case "systemd_unit": agg("linux.persist", "unit:" + (ev.extra && ev.extra.unit), ev); flag = true; break;
      case "session_open":
        if (ev.user === "root" && ev.extra && ev.extra.service === "sshd") S.adminLogons.push(ev);
        break;
      default: break;
    }
    return flag;
  }

  function feedWin(ev, d) {
    const W = S.win, x = ev.extra || {}, id = ev.eventId;
    const src = ev.ip || (x.workstation ? "ws:" + x.workstation : null);
    let flag = false;
    switch (id) {
      case 4625: case 4771:
        flag = true;
        if (src) push(W.failBySrc, src, ev);
        if (d) d.fails++;
        if (id === 4625 && /0xc0000064$/i.test(x.subStatus || x.status || "") && src) push(W.enumBySrc, src, ev);
        break;
      case 4768:
        if (/^0x(?:18|12)$/i.test(x.status || "")) { flag = true; if (src) push(W.failBySrc, src, ev); }
        else if (/^0x6$/i.test(x.status || "") && src) { flag = true; push(W.enumBySrc, src, ev); }
        break;
      case 4740: W.lockouts.push(ev); flag = true; break;
      case 4624: {
        if (d) d.ok++;
        const lt = x.logonType;
        if (lt === 10 && ev.ip && !internal(ev.ip)) { agg("win.rdp_external", ev.ip, ev); flag = true; }
        if (lt === 3 && src) { let m = W.type3.get(src); if (!m) { m = { hosts: new Set(), evs: [] }; W.type3.set(src, m); } if (ev.host) m.hosts.add(ev.host); if (m.evs.length < EVIDENCE_CAP) m.evs.push(ev); m.n = (m.n || 0) + 1; }
        if (lt === 9) { agg("win.pth", "type9:" + (x.subjectUser || ev.user || "-"), ev, { kind: "type9" }); flag = true; }
        if (isAdminName(ev.user) && lt !== 3 && lt !== 5 && lt !== 0) S.adminLogons.push(ev);
        break;
      }
      case 4648: {
        const subj = x.subjectUser || "-";
        let m = W.explicit.get(subj); if (!m) { m = { targets: new Set(), evs: [] }; W.explicit.set(subj, m); }
        m.targets.add((x.targetServer || "-") + "|" + (x.targetUser || "-")); m.evs.push(ev);
        break;
      }
      case 4672:
        if (ev.user && !isAdminName(ev.user) && !/\$$/.test(ev.user) && !/^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-\d+|UMFD-\d+|ANONYMOUS LOGON|IUSR)$/i.test(ev.user)) agg("win.special_priv", ev.user, ev);
        break;
      case 4720: W.newUsers.set((ev.user || "").toLowerCase(), ev); agg("win.new_user", ev.user || "-", ev, { by: x.subjectUser }); flag = true; break;
      case 4728: case 4732: case 4756: {
        const grp = x.group || "";
        const member = x.member || ev.user || "-";
        if (PRIV_WIN_GROUPS.test(grp)) { W.groupAdds.push(ev); agg("win.priv_group", member + ">" + grp, ev, { group: grp, by: x.subjectUser }); flag = true; }
        break;
      }
      case 4722: case 4724: case 4738: {
        const self = x.subjectUser && ev.user && x.subjectUser.toLowerCase() === ev.user.toLowerCase();
        if (!(id === 4738 && self)) agg("win.account_change", id + ":" + (ev.user || "-"), ev, { admin: isAdminName(ev.user) });
        break;
      }
      case 1102: case 104: agg("win.log_cleared", ev.host || "-", ev, { by: x.subjectUser }); flag = true; break;
      case 4698: agg("win.sched_task", (ev.host || "-") + ":" + (x.task || "-"), ev, { susp: !!(x.taskContent && WIN_PROC_SUSP.some((r) => r.test(x.taskContent))) }); flag = true; break;
      case 7045: agg("win.new_service", (ev.host || "-") + ":" + (x.service || "-"), ev, { susp: !!(x.imagePath && (/\\(?:temp|tmp|users|appdata|programdata|public|downloads)\\/i.test(x.imagePath) || WIN_PROC_SUSP.some((r) => r.test(x.imagePath)) || /^%(?:temp|appdata)%/i.test(x.imagePath))) }); flag = true; break;
      case 4688: {
        const cl = (x.cmdline || "") + " " + (x.process || "");
        if (WIN_PROC_SUSP.some((r) => r.test(cl))) { agg("win.proc_suspicious", (ev.host || "-") + ":" + (x.subjectUser || ev.user || "-"), ev); flag = true; }
        break;
      }
      case 4769: {
        const svc = x.service || "";
        if (/^0x17$/i.test(x.encType || "") && svc && !/^krbtgt/i.test(svc) && !/\$$/.test(svc) && (!x.status || /^0x0$/i.test(x.status))) {
          const u = ev.user || "-"; let m = W.kerb.get(u); if (!m) { m = { services: new Set(), evs: [] }; W.kerb.set(u, m); } m.services.add(svc); m.evs.push(ev); flag = true;
        }
        break;
      }
      case 4776: {
        const ws = x.workstation || ev.ip || "-";
        push(W.ntlm, ws, ev);
        if (/^0xc/i.test(x.status || "")) { flag = true; push(W.failBySrc, src || "ws:" + ws, ev); }
        break;
      }
      default: break;
    }
    return flag;
  }

  function finish() {
    const findings = [];
    const min = (m) => m * 60000;
    const fmtWin = (n, m) => `${n} within ${m} min`;
    const plural = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;

    // ---- aggregated per-event findings
    for (const a of S.agg.values()) {
      const det = DETECTIONS[a.det];
      let severity = det.severity, confidence = det.confidence, detail = "";
      switch (a.det) {
        case "web.sensitive": if (a.count >= 20) severity = "medium"; detail = `${plural(a.count, "probe")} for sensitive paths; none returned 200.`; break;
        case "web.sensitive.served": detail = `${plural(a.count, "request")} for sensitive paths returned HTTP 200.`; break;
        case "web.webshell": {
          const named = a.evidence.some((e) => RX.webshellName.test(urlDecode(e.path || "")));
          const param = a.evidence.some((e) => RX.webshellParam.test(urlDecode(e.path || "")));
          if (!named && !param) { severity = "medium"; confidence = "low"; detail = "POST to script files inside upload or media directories; no known shell name or command parameter seen."; }
          else { confidence = named ? "high" : "medium"; detail = named ? "Known web shell file names requested." : "Command-style parameters sent to script files."; }
          const ok = a.evidence.filter((e) => e.status === 200).length;
          if (ok) detail += ` ${ok} of the sampled requests got HTTP 200.`;
          break;
        }
        case "web.sqli": case "web.xss": case "web.traversal": case "web.cmdi": {
          const ok = a.evidence.filter((e) => e.status === 200).length;
          detail = `${plural(a.count, "matching request")}`;
          const err = a.evidence.filter((e) => e.status != null && e.status >= 500).length;
          if (ok) detail += `; ${ok} of the sampled ones returned HTTP 200 (check those first)`;
          else if (err && (a.det === "web.sqli" || a.det === "web.cmdi")) detail += `; ${err} returned a 5xx server error, which means the input reached the backend`;
          else if (a.evidence.every((e) => e.status != null && e.status >= 400)) { detail += "; all sampled requests were rejected (4xx/5xx)"; if (severity === "high") severity = "medium"; }
          detail += ".";
          break;
        }
        case "web.scanner": detail = `User-Agent: ${[...new Set(a.evidence.map((e) => e.ua))].slice(0, 3).join(" | ")}`; break;
        case "web.ssrf": detail = `${plural(a.count, "request")} with internal or non-HTTP URLs in parameters.`; break;
        case "web.log4shell": detail = `${plural(a.count, "request")} carrying a JNDI lookup.`; break;
        case "linux.root_login": severity = a.meta.external ? "high" : "medium"; detail = a.meta.external ? "Source is outside the configured internal ranges." : "Source is inside the internal ranges."; break;
        case "linux.new_user":
          if (a.key.startsWith("group:")) detail = `Group ${a.key.slice(6)} created.`;
          else if (a.key.startsWith("member:")) { detail = `${a.key.slice(7)} added to a non-privileged group.`; severity = "low"; }
          else detail = `User ${a.key.slice(5)} created.`;
          break;
        case "linux.priv_group": detail = `${a.key.replace(">", " added to group ")}.`; break;
        case "linux.sudo_shell": detail = [...new Set(a.evidence.map((e) => (e.extra && e.extra.command) || ""))].slice(0, 3).join(" | "); break;
        case "linux.sudoers": detail = "sudoers file referenced in a command."; break;
        case "linux.sudo_fail": detail = `${plural(a.count, "refused sudo attempt")} by ${a.key}.`; if (a.count >= 5) severity = "high"; break;
        case "linux.breakin": detail = `${plural(a.count, "reverse-DNS mismatch warning")}.`; break;
        case "linux.persist": detail = a.key.startsWith("unit:") ? `systemd unit ${a.key.slice(5)} enabled.` : `crontab written (${a.key.replace(/^\w+:/, "")}).`; break;
        case "win.rdp_external": detail = `${plural(a.count, "RDP logon")} for ${[...a.users].slice(0, 3).join(", ")} from ${a.key}.`; break;
        case "win.pth": detail = `${plural(a.count, "NewCredentials (type 9) logon")}; often RunAs /netonly, also pass-the-hash.`; break;
        case "win.special_priv": detail = `${plural(a.count, "privileged logon")} for ${a.key}.`; break;
        case "win.new_user": detail = `${a.key} created${a.meta.by ? " by " + a.meta.by : ""}.`; break;
        case "win.priv_group": detail = `${a.key.replace(">", " added to ")}${a.meta.by ? " by " + a.meta.by : ""}.`; break;
        case "win.account_change": { const [eid, u] = a.key.split(":"); detail = `${WIN_EVENT_IDS[eid] || eid} for ${u} (${a.count}).`; if (a.meta.admin && eid === "4724") severity = "high"; else if (a.meta.admin) severity = "medium"; break; }
        case "win.log_cleared": detail = `Log cleared on ${a.key}${a.meta.by ? " by " + a.meta.by : ""}.`; break;
        case "win.sched_task": detail = `Task ${a.key.split(":").slice(1).join(":")} on ${a.key.split(":")[0]}.`; if (a.meta.susp) { severity = "high"; detail += " Task action matches attacker tooling."; } break;
        case "win.new_service": detail = `Service ${a.key.split(":").slice(1).join(":")} on ${a.key.split(":")[0]}.`; if (a.meta.susp) { severity = "high"; detail += " Binary path is in a temp or user directory, or matches attacker tooling."; } break;
        case "win.proc_suspicious": detail = [...new Set(a.evidence.map((e) => (e.extra && (e.extra.cmdline || e.extra.process)) || ""))].slice(0, 2).join(" | "); break;
        default: detail = `${plural(a.count, "matching event")}.`;
      }
      findings.push(mkFinding(a.det, { key: a.key, severity, confidence, detail, count: a.count, evidence: a.evidence, first: a.first, last: a.last,
        ip: a.ips.size === 1 ? [...a.ips][0] : (isIp(a.key) ? a.key : null), user: a.users.size === 1 ? [...a.users][0] : null, host: a.hosts.size === 1 ? [...a.hosts][0] : null, ips: [...a.ips] }));
    }

    // ---- web windows
    for (const [ip, w] of S.web) {
      if (w.nf.length >= s.notFoundBurstN) {
        const b = burstWindow(w.nf.map((e) => e.ts), s.notFoundBurstN, min(s.notFoundWindowMin));
        if (b.hit) {
          const top = topN(w.nf.map((e) => (e.path || "").split("?")[0]), 5);
          findings.push(mkFinding("web.404burst", { ip, count: w.nf.length, evidence: w.nf, first: b.start, last: b.end, threshold: fmtWin(s.notFoundBurstN, s.notFoundWindowMin), detail: `${w.nf.length} 404s in total, ${b.best} in the densest ${s.notFoundWindowMin} min window. Top paths: ${top.join(", ")}.` }));
        }
      }
      if (w.login.length >= s.loginAttemptsN) {
        const b = burstWindow(w.login.map((e) => e.ts), s.loginAttemptsN, min(s.loginWindowMin));
        if (b.hit) {
          const fails = w.login.filter((e) => isLoginFail(e.status)).length;
          const okAfter = findOkAfterFails(w.login, s.loginAttemptsN);
          findings.push(mkFinding("web.credstuff", { ip, count: w.login.length, evidence: w.login, first: b.start, last: b.end, threshold: fmtWin(s.loginAttemptsN, s.loginWindowMin), detail: `${w.login.length} login POSTs, ${fails} rejected (4xx), ${b.best} in the densest ${s.loginWindowMin} min window.`, severity: fails >= s.loginAttemptsN ? "high" : "medium" }));
          if (okAfter) findings.push(mkFinding("web.credstuff.success", { ip, count: 1, evidence: [okAfter], first: okAfter.ts, last: okAfter.ts, detail: `HTTP 200 from ${(okAfter.path || "").split("?")[0]} after ${w.login.indexOf(okAfter)} earlier login POSTs from this IP.` }));
        }
      }
      if (w.tool.length >= s.uaBurstN) {
        findings.push(mkFinding("web.toolburst", { ip, count: w.tool.length, evidence: w.tool, first: minTs(w.tool), last: maxTs(w.tool), threshold: `${s.uaBurstN} requests`, detail: `${w.tool.length} requests with User-Agent ${topN(w.tool.map((e) => e.ua), 1)[0]}.` }));
      }
    }

    // ---- linux windows
    const L = S.lx;
    for (const [ip, evs] of L.failsByIp) {
      const b = burstWindow(evs.map((e) => e.ts), s.bruteN, min(s.bruteWindowMin));
      if (b.hit) {
        const users = topN(evs.map((e) => e.user), 5);
        findings.push(mkFinding("linux.brute", { ip, count: evs.length, evidence: evs, first: b.start, last: b.end, threshold: fmtWin(s.bruteN, s.bruteWindowMin), detail: `${evs.length} failures in total, ${b.best} in the densest ${s.bruteWindowMin} min window. Accounts tried: ${users.join(", ")}.`, severity: internal(ip) ? "medium" : "high" }));
      }
    }
    for (const [user, evs] of L.failsByUser) {
      const ips = new Set(evs.map((e) => e.ip).filter(Boolean));
      if (ips.size >= s.distIpsN) {
        findings.push(mkFinding("linux.spray", { user, count: evs.length, evidence: evs, first: minTs(evs), last: maxTs(evs), threshold: `${s.distIpsN} distinct IPs`, detail: `${evs.length} failures for ${user} from ${ips.size} distinct IPs.`, ips: [...ips], severity: ips.size >= s.distIpsN * 4 ? "high" : "medium" }));
      }
    }
    for (const [ip, oks] of L.okByIp) {
      const fails = L.failsByIp.get(ip);
      if (!fails || fails.length < s.successAfterFailN) continue;
      for (const ok of oks) {
        const before = fails.filter((f) => f.ts == null || ok.ts == null || (f.ts <= ok.ts && ok.ts - f.ts <= min(s.successAfterFailWindowMin)));
        if (before.length >= s.successAfterFailN) {
          findings.push(mkFinding("linux.success_after_fail", { ip, user: ok.user, count: before.length + 1, evidence: [...before.slice(-(EVIDENCE_CAP - 1)), ok], first: minTs(before), last: ok.ts, threshold: `${s.successAfterFailN} failures within ${s.successAfterFailWindowMin} min before success`, detail: `${before.length} failed attempts, then Accepted ${(ok.extra && ok.extra.method) || ""} for ${ok.user}.`, severity: ok.user === "root" || isAdminName(ok.user) ? "critical" : "high" }));
          break;
        }
      }
    }
    for (const [ip, evs] of L.invalidByIp) {
      const users = new Set(evs.map((e) => e.user).filter(Boolean));
      if (users.size >= s.invalidUserN) findings.push(mkFinding("linux.invalid_user", { ip, count: evs.length, evidence: evs, first: minTs(evs), last: maxTs(evs), threshold: `${s.invalidUserN} distinct invalid usernames`, detail: `${users.size} distinct non-existent usernames tried: ${[...users].slice(0, 8).join(", ")}${users.size > 8 ? ", ..." : ""}.` }));
    }

    // ---- windows windows
    const W = S.win;
    const srcParts = (src) => { const label = src.startsWith("ws:") ? src.slice(3) : src; return { label, ip: isIp(label) ? label : null, host: isIp(label) ? null : label }; };
    for (const [src, evs] of W.failBySrc) {
      const b = burstWindow(evs.map((e) => e.ts), s.winFailN, min(s.winFailWindowMin));
      const users = new Set(evs.map((e) => e.user).filter(Boolean));
      const sp = srcParts(src);
      if (b.hit) {
        const codes = topN(evs.map((e) => decodeStatus((e.extra && (e.extra.subStatus || e.extra.status)) || "")), 3);
        findings.push(mkFinding("win.fail_burst", { ip: sp.ip, host: sp.host, count: evs.length, evidence: evs, first: b.start, last: b.end, threshold: fmtWin(s.winFailN, s.winFailWindowMin), detail: `${evs.length} failures from ${sp.label}, ${b.best} in the densest ${s.winFailWindowMin} min window, ${plural(users.size, "account")}. Reasons: ${codes.join("; ")}.`, severity: sp.ip && internal(sp.ip) ? "medium" : "high" }));
      }
      if (users.size >= s.sprayUsersN) {
        findings.push(mkFinding("win.spray", { ip: sp.ip, host: sp.host, count: evs.length, evidence: evs, first: minTs(evs), last: maxTs(evs), threshold: `${s.sprayUsersN} distinct accounts from one source`, detail: `${users.size} distinct accounts failed from ${sp.label}: ${[...users].slice(0, 8).join(", ")}${users.size > 8 ? ", ..." : ""}.`, severity: users.size >= s.sprayUsersN * 4 ? "critical" : "high" }));
      }
    }
    for (const [src, evs] of W.enumBySrc) {
      const users = new Set(evs.map((e) => e.user).filter(Boolean));
      const sp = srcParts(src);
      if (users.size >= s.sprayUsersN) findings.push(mkFinding("win.enum", { ip: sp.ip, host: sp.host, count: evs.length, evidence: evs, first: minTs(evs), last: maxTs(evs), threshold: `${s.sprayUsersN} distinct unknown usernames`, detail: `${users.size} non-existent usernames tried from ${sp.label}.` }));
    }
    if (W.lockouts.length >= s.lockoutN) {
      const b = burstWindow(W.lockouts.map((e) => e.ts), s.lockoutN, min(s.lockoutWindowMin));
      if (b.hit) {
        const callers = topN(W.lockouts.map((e) => (e.extra && e.extra.workstation) || "-"), 3);
        findings.push(mkFinding("win.lockout", { count: W.lockouts.length, evidence: W.lockouts, first: b.start, last: b.end, threshold: fmtWin(s.lockoutN, s.lockoutWindowMin), detail: `${W.lockouts.length} lockouts, ${b.best} in the densest ${s.lockoutWindowMin} min window. Caller computers: ${callers.join(", ")}.`, severity: W.lockouts.length >= s.lockoutN * 3 ? "high" : "medium" }));
      }
    }
    for (const [src, m] of W.type3) {
      if (m.hosts.size >= s.fanoutHostsN) {
        const sp = srcParts(src);
        findings.push(mkFinding("win.fanout", { ip: sp.ip, count: m.n || m.evs.length, evidence: m.evs, first: minTs(m.evs), last: maxTs(m.evs), threshold: `${s.fanoutHostsN} distinct computers`, detail: `${sp.label} logged on (type 3) to ${m.hosts.size} computers: ${[...m.hosts].slice(0, 6).join(", ")}${m.hosts.size > 6 ? ", ..." : ""}. Accounts: ${topN(m.evs.map((e) => e.user), 3).join(", ")}.` }));
      }
    }
    for (const [subj, m] of W.explicit) {
      const many = m.targets.size >= s.explicitCredTargetsN;
      findings.push(mkFinding("win.explicit_creds", { user: subj, count: m.evs.length, evidence: m.evs, first: minTs(m.evs), last: maxTs(m.evs), threshold: `${s.explicitCredTargetsN} distinct targets raises severity`, detail: `${subj} used explicit credentials ${plural(m.evs.length, "time")} against ${plural(m.targets.size, "target")}.`, severity: many ? "high" : "medium", confidence: many ? "medium" : "low" }));
    }
    for (const ga of W.groupAdds) {
      const member = ((ga.extra && ga.extra.member) || ga.user || "").toLowerCase();
      const nu = W.newUsers.get(member) || W.newUsers.get(member.replace(/^.*\\/, ""));
      if (nu && (nu.ts == null || ga.ts == null || (ga.ts >= nu.ts && ga.ts - nu.ts <= min(s.newUserAdminWindowMin)))) {
        const later = ga.ts != null && nu.ts != null ? ` ${Math.round((ga.ts - nu.ts) / 60000)} min later` : "";
        findings.push(mkFinding("win.new_admin", { user: nu.user, host: ga.host, count: 2, evidence: [nu, ga], first: nu.ts, last: ga.ts, threshold: `group add within ${s.newUserAdminWindowMin} min of creation`, detail: `${nu.user} created${nu.extra && nu.extra.subjectUser ? " by " + nu.extra.subjectUser : ""}, then added to ${ga.extra && ga.extra.group}${later}.` }));
      }
    }
    for (const [u, m] of W.kerb) {
      const many = m.services.size >= s.kerberoastN;
      findings.push(mkFinding("win.kerberoast", { user: u, count: m.evs.length, evidence: m.evs, first: minTs(m.evs), last: maxTs(m.evs), threshold: `${s.kerberoastN} distinct services raises severity`, detail: `${u} requested RC4 service tickets for ${plural(m.services.size, "service account")}: ${[...m.services].slice(0, 6).join(", ")}.`, severity: many ? "high" : "medium", confidence: many ? "high" : "medium" }));
    }
    for (const [ws, evs] of W.ntlm) {
      const b = burstWindow(evs.map((e) => e.ts), s.ntlmBurstN, min(s.ntlmWindowMin));
      if (b.hit) findings.push(mkFinding("win.pth", { host: ws, count: evs.length, evidence: evs, first: b.start, last: b.end, threshold: fmtWin(s.ntlmBurstN, s.ntlmWindowMin), detail: `${evs.length} NTLM validations (4776) from ${ws}, ${b.best} in the densest ${s.ntlmWindowMin} min window. Accounts: ${topN(evs.map((e) => e.user), 4).join(", ")}.`, confidence: "medium" }));
    }

    // ---- off-hours admin logons (windows + linux)
    const off = S.adminLogons.filter((e) => isOffHours(e.ts, s));
    if (off.length) {
      const byUser = new Map();
      for (const e of off) push(byUser, e.user || "-", e);
      const thr = `outside ${pad(s.businessStart)}:00-${pad(s.businessEnd)}:00 (UTC${s.utcOffset >= 0 ? "+" : ""}${s.utcOffset})${s.weekendOffHours ? ", weekends" : ""}`;
      for (const [u, evs] of byUser) findings.push(mkFinding("offhours.admin", { user: u, ip: new Set(evs.map((e) => e.ip)).size === 1 ? evs[0].ip : null, count: evs.length, evidence: evs, first: minTs(evs), last: maxTs(evs), threshold: thr, detail: `${plural(evs.length, "logon")} for ${u} outside business hours.` }));
    }

    // ---- order, ids, dossier linkage
    findings.sort((a, b) => (SEV_RANK[b.severity] - SEV_RANK[a.severity]) || (b.count - a.count) || a.name.localeCompare(b.name));
    findings.forEach((f, i) => { f.id = "F-" + String(i + 1).padStart(3, "0"); for (const ip of f.ips) { const d = S.ips.get(ip); if (d) d.findings.add(f.id); } });

    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;

    const ips = [...S.ips.values()].map((d) => ({
      ip: d.ip, internal: d.internal, count: d.count, first: d.first, last: d.last, fails: d.fails, ok: d.ok,
      users: [...d.users].slice(0, 10), hosts: [...d.hosts].slice(0, 10), sources: [...d.sources],
      topUa: topEntries(d.uas, 3), topPaths: topEntries(d.paths, 5), topStatuses: topEntries(d.statuses, 5),
      findings: [...d.findings], maxSeverity: maxSev(findings, d.findings),
    })).sort((a, b) => (SEV_RANK[b.maxSeverity || "info"] - SEV_RANK[a.maxSeverity || "info"]) || (b.count - a.count));

    const timeline = [...S.hours.values()].filter((h) => h.ts != null).sort((a, b) => a.ts - b.ts);
    const noTime = S.hours.get("none");

    const iocIps = [...new Set(findings.filter((f) => SEV_RANK[f.severity] >= 2).flatMap((f) => f.ips))];
    const iocs = { external: iocIps.filter((ip) => !internal(ip)).sort(), internal: iocIps.filter((ip) => internal(ip)).sort() };

    const stats = {
      events: S.n, noTs: S.noTs, sources: S.sources, firstTs: S.firstTs, lastTs: S.lastTs,
      uniqueIps: S.ips.size, externalIps: ips.filter((d) => !d.internal).length, internalIps: ips.filter((d) => d.internal).length,
      noTimeEvents: noTime ? noTime.total : 0,
    };
    const report = { version: VERSION, generatedAt: Date.now(), settings: s, stats, findings, bySeverity, timeline, ips, iocs, summary: "" };
    report.summary = summarize(report);
    return report;
  }

  return { feed, finish, settings: s };
}

function isLoginFail(status) { return status != null && [400, 401, 403, 422, 429].includes(status); }
function decodeStatus(code) {
  const k = String(code || "").toLowerCase();
  return WIN_STATUS[k] ? `${code} ${WIN_STATUS[k]}` : (code || "unknown");
}
function pad(n) { return String(n).padStart(2, "0"); }
function minTs(evs) { let m = null; for (const e of evs) if (e.ts != null && (m == null || e.ts < m)) m = e.ts; return m; }
function maxTs(evs) { let m = null; for (const e of evs) if (e.ts != null && (m == null || e.ts > m)) m = e.ts; return m; }
function topN(arr, n) { const m = new Map(); for (const x of arr) if (x != null) m.set(x, (m.get(x) || 0) + 1); return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map((e) => e[0]); }
function topEntries(map, n) { return [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map(([k, v]) => ({ value: k, count: v })); }
function maxSev(findings, ids) { let best = null; for (const f of findings) if (ids.has(f.id) && (best == null || SEV_RANK[f.severity] > SEV_RANK[best])) best = f.severity; return best; }
function findOkAfterFails(login, n) {
  let fails = 0;
  for (const e of login) {
    if (isLoginFail(e.status)) fails++;
    else if (e.status === 200 && fails >= n) return e;
  }
  return null;
}

function mkFinding(det, o) {
  const d = DETECTIONS[det];
  const evidence = (o.evidence || []).slice(0, EVIDENCE_CAP).map((e) => ({ lineNo: e.lineNo, file: e.file || "", ts: e.ts, text: String(e.raw || "").slice(0, 400) }));
  const ips = o.ips || (o.ip ? [o.ip] : [...new Set((o.evidence || []).map((e) => e.ip).filter(Boolean))]);
  return {
    // key: stable subject of the finding (the aggregation key, else ip / user / host),
    // unlike id, which is the position in the sorted list.
    id: "", key: det + ":" + String(o.key || o.ip || o.user || o.host || ""), det, name: d.name, technique: d.technique, techniqueName: d.techniqueName, tactic: d.tactic, source: d.source,
    severity: o.severity || d.severity, confidence: o.confidence || d.confidence,
    ip: o.ip || null, user: o.user || null, host: o.host || null, ips,
    count: o.count || evidence.length, firstTs: o.first == null ? null : o.first, lastTs: o.last == null ? null : o.last,
    threshold: o.threshold || null, detail: o.detail || "", explanation: d.explain, action: d.action, evidence,
  };
}

// Template summary built from counts (no AI involved).
export function summarize(r) {
  const st = r.stats, bs = r.bySeverity;
  const parts = [];
  const srcs = Object.entries(st.sources).filter(([, n]) => n > 0).map(([k, n]) => `${n.toLocaleString()} ${k === "web" ? "web request" : k === "linux" ? "Linux auth event" : "Windows event"}${n === 1 ? "" : "s"}`);
  const iso = (t) => new Date(t).toISOString().slice(0, 16).replace("T", " ");
  const span = st.firstTs != null && st.lastTs != null ? ` spanning ${fmtSpan(st.lastTs - st.firstTs)} (${iso(st.firstTs)} to ${iso(st.lastTs)} UTC)` : "";
  parts.push(`Parsed ${st.events.toLocaleString()} event${st.events === 1 ? "" : "s"}${srcs.length ? " (" + srcs.join(", ") + ")" : ""}${span} from ${st.uniqueIps.toLocaleString()} distinct IP${st.uniqueIps === 1 ? "" : "s"}, ${st.externalIps.toLocaleString()} external.`);
  const total = r.findings.length;
  if (!total) parts.push("No detection fired. That means none of the rules matched, not that the logs are clean; widen the time range or lower thresholds if you expected hits.");
  else {
    parts.push(`${total} finding${total === 1 ? "" : "s"}: ${bs.critical} critical, ${bs.high} high, ${bs.medium} medium, ${bs.low} low.`);
    const top = r.findings.slice(0, 3).map((f) => `${f.name}${f.ip ? " from " + f.ip : f.user ? " for " + f.user : f.host ? " on " + f.host : ""} (${f.technique})`);
    parts.push(`Highest priority: ${top.join("; ")}.`);
    parts.push(`ATT&CK tactics seen: ${[...new Set(r.findings.map((f) => f.tactic))].join(", ")}.`);
    if (r.iocs.external.length) parts.push(`${r.iocs.external.length} external IP${r.iocs.external.length === 1 ? "" : "s"} tied to medium-or-higher findings are listed as indicators.`);
  }
  if (st.noTs) parts.push(`${st.noTs.toLocaleString()} event${st.noTs === 1 ? "" : "s"} had no parseable timestamp and were counted without time-window checks.`);
  return parts.join(" ");
}
function fmtSpan(ms) {
  if (ms < 60000) return `${Math.round(ms / 1000)} s`;
  if (ms < 3600000) return `${Math.round(ms / 60000)} min`;
  if (ms < 86400000 * 2) return `${(ms / 3600000).toFixed(1)} h`;
  return `${(ms / 86400000).toFixed(1)} days`;
}

// Convenience for tests and small inputs: parse + hunt in one call.
export function analyzeText(text, settings, file) {
  const { events, stats } = parseText(text, file || "", settings);
  const h = createHunt(settings);
  for (const e of events) h.feed(e);
  const report = h.finish();
  report.parse = stats;
  return report;
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
const csvq = (v) => `"${String(v == null ? "" : v).replace(/"/g, '""')}"`;
export function findingsToCsv(findings) {
  const head = "id,severity,confidence,finding,technique,technique_name,tactic,source,ip,user,host,count,first_seen,last_seen,threshold,detail,action,evidence_lines";
  const rows = findings.map((f) => [f.id, f.severity, f.confidence, f.name, f.technique, f.techniqueName, f.tactic, f.source, f.ip || "", f.user || "", f.host || "", f.count,
    f.firstTs != null ? new Date(f.firstTs).toISOString() : "", f.lastTs != null ? new Date(f.lastTs).toISOString() : "", f.threshold || "", f.detail, f.action,
    f.evidence.map((e) => (e.file ? e.file + ":" : "") + e.lineNo).join(" ")].map(csvq).join(","));
  return [head, ...rows].join("\n") + "\n";
}
export function reportToJson(report) {
  return JSON.stringify({ version: report.version, generatedAt: new Date(report.generatedAt).toISOString(), stats: report.stats, bySeverity: report.bySeverity, summary: report.summary, settings: report.settings, findings: report.findings, iocs: report.iocs, ips: report.ips.slice(0, 1000) }, null, 2);
}
export function iocText(report) {
  const lines = [`# Log Threat Hunter indicators ${new Date(report.generatedAt).toISOString()}`, `# External IPs tied to findings of medium severity or higher (${report.iocs.external.length}). Internal IPs omitted: ${report.iocs.internal.length}.`];
  return lines.concat(report.iocs.external).join("\n") + "\n";
}

// Security Graph sink: report findings -> common Finding shape (core/sink-map.js).
// id and title come from the detection + its stable subject (never F-nnn or counts),
// so a re-hunt over the same logs merges into the same graph findings.
export function toSinkFindings(report) {
  return ((report && report.findings) || []).map((f) => {
    const subject = f.key.slice(f.det.length + 1);
    const ips = (f.ips || []).slice(0, 25);
    return {
      id: f.key, title: subject && subject !== "-" ? `${f.name}: ${subject}` : f.name,
      severity: f.severity, confidence: f.confidence, category: f.tactic,
      description: [f.detail, f.explanation].filter(Boolean).join(" "), recommendation: f.action,
      controls: controlsFromRefs([f.technique]),
      evidence: f.evidence.map((e) => ({ file: e.file, line: e.lineNo, ts: e.ts != null ? new Date(e.ts).toISOString() : null, text: e.text })),
      evidenceCount: f.count,
      assets: [...ips.map((ip) => ({ type: "IP", name: ip })), ...(f.user ? [{ type: "IDENTITY", name: f.user }] : []), ...(f.host ? [{ type: "ASSET", name: f.host, data: { kind: "host" } }] : [])],
      tags: ["loghunt", f.source],
    };
  });
}
