// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Blue Team Detection & Response Playbooks — comprehensive defense procedures

export const BLUE_TEAM_PLAYBOOKS = [
  {
    id: "bt-001", name: "Ransomware Detection & Response", threat_type: "Ransomware",
    data_sources: ["EDR telemetry", "File integrity monitoring", "Volume Shadow Copy events", "Process creation logs (Sysmon EID 1)", "Network connections (Sysmon EID 3)", "SMB traffic logs"],
    detection_rules: [
      { name: "Mass file encryption", query: "process where event.action == 'file_rename' | stats count by process.name, user.name | where count > 100 AND timespan < 60s" },
      { name: "Shadow copy deletion", query: "process where process.name in ('vssadmin.exe','wmic.exe','bcdedit.exe') AND process.command_line matches ('*delete*shadows*','*shadowcopy*delete*','*recoveryenabled*no*')" },
      { name: "Suspicious encryption tool", query: "process where process.name in ('cipher.exe') AND process.command_line matches '*encrypt*' OR file.extension in ('.encrypted','.locked','.crypt','.ransom')" },
      { name: "Known ransomware note creation", query: "file where file.name in ('README.txt','DECRYPT.txt','HOW_TO_RECOVER.txt','RESTORE_FILES.txt','ransom_note.html') AND event.action == 'creation'" },
      { name: "Abnormal SMB lateral spread", query: "network where destination.port == 445 | stats dc(destination.ip) by source.ip | where dc_destination_ip > 20 AND timespan < 300s" }
    ],
    triage: [
      { step: 1, action: "Identify patient zero", tool: "EDR", what_to_look_for: "First host with file encryption activity — check process tree for initial dropper" },
      { step: 2, action: "Determine ransomware family", tool: "ID Ransomware / VirusTotal", what_to_look_for: "Upload ransom note and encrypted file sample to identify variant and check for decryptors" },
      { step: 3, action: "Map blast radius", tool: "EDR + AD logs", what_to_look_for: "All hosts with C2 beacon activity, lateral movement evidence, encrypted files" },
      { step: 4, action: "Check for data exfiltration", tool: "Network logs / CASB", what_to_look_for: "Large outbound transfers before encryption — cloud storage uploads, FTP, HTTP POST" }
    ],
    containment: [
      "Isolate infected hosts from network immediately (EDR network containment)",
      "Block C2 domains/IPs at firewall and DNS sinkhole",
      "Disable compromised accounts and force password reset for all admin accounts",
      "Segment unaffected network portions",
      "Preserve infected system memory dumps before shutdown"
    ],
    eradication: [
      "Image infected systems for forensic analysis",
      "Wipe and rebuild from known-good images",
      "Remove all persistence mechanisms (scheduled tasks, services, registry keys)",
      "Scan all systems with updated signatures",
      "Verify no dormant C2 beacons remain"
    ],
    recovery: [
      "Restore from offline/immutable backups (verify backup integrity first)",
      "Prioritize critical business systems for restoration",
      "Monitor restored systems closely for re-infection (24-48 hours)",
      "Gradually reconnect network segments",
      "Validate data integrity post-restoration"
    ],
    metrics: { mttd: "< 15 minutes", mttr: "< 4 hours for containment, 24-72 hours full recovery", priority: "P1 Critical" }
  },
  {
    id: "bt-002", name: "Business Email Compromise Response", threat_type: "BEC / Email Account Takeover",
    data_sources: ["Email gateway logs", "Azure AD / Entra ID sign-in logs", "Mailbox audit logs", "Conditional Access logs", "MFA challenge logs"],
    detection_rules: [
      { name: "Impossible travel", query: "SigninLogs | where ResultType == 0 | summarize locations=make_set(Location) by UserPrincipalName, bin(TimeGenerated, 1h) | where array_length(locations) > 1" },
      { name: "Inbox rule creation (forwarding)", query: "OfficeActivity | where Operation in ('New-InboxRule','Set-InboxRule') AND (Parameters contains 'ForwardTo' OR Parameters contains 'RedirectTo')" },
      { name: "Suspicious OAuth app consent", query: "AuditLogs | where OperationName == 'Consent to application' AND TargetResources[0].modifiedProperties contains 'Mail.Read'" },
      { name: "MFA fatigue / push bombing", query: "SigninLogs | where ResultType == 50074 | summarize attempts=count() by UserPrincipalName, bin(TimeGenerated, 5m) | where attempts > 5" }
    ],
    triage: [
      { step: 1, action: "Confirm compromise", tool: "Azure AD logs", what_to_look_for: "Sign-ins from unusual locations, devices, or IP addresses" },
      { step: 2, action: "Check for mail forwarding rules", tool: "Exchange admin / PowerShell", what_to_look_for: "Inbox rules forwarding to external addresses" },
      { step: 3, action: "Review sent items", tool: "Mailbox audit", what_to_look_for: "Phishing emails sent from compromised account, financial fraud emails" },
      { step: 4, action: "Check OAuth apps", tool: "Azure AD Enterprise Apps", what_to_look_for: "Unauthorized third-party apps with mail/calendar permissions" }
    ],
    containment: [
      "Force sign-out of all sessions and revoke refresh tokens",
      "Reset password and require MFA re-enrollment",
      "Remove malicious inbox rules and forwarding",
      "Revoke unauthorized OAuth app consents",
      "Block source IPs at conditional access level"
    ],
    eradication: [
      "Remove any persistence (OAuth apps, forwarding rules, delegates)",
      "Recall phishing emails sent from compromised account",
      "Notify recipients of fraudulent emails",
      "Review and remediate any financial transactions initiated"
    ],
    recovery: [
      "Re-enable account with new credentials and phishing-resistant MFA (FIDO2)",
      "Monitor account closely for 30 days",
      "Review and harden conditional access policies",
      "Conduct awareness training for affected user"
    ],
    metrics: { mttd: "< 1 hour", mttr: "< 2 hours for containment", priority: "P1 Critical" }
  },
  {
    id: "bt-003", name: "Credential Stuffing Attack Response", threat_type: "Credential Stuffing",
    data_sources: ["WAF logs", "Application auth logs", "CDN/load balancer logs", "Bot detection signals"],
    detection_rules: [
      { name: "High volume failed logins from single IP", query: "auth_logs | where status == 'failed' | stats count by src_ip, bin(timestamp, 5m) | where count > 50" },
      { name: "Distributed credential stuffing", query: "auth_logs | where status == 'failed' | stats dc(src_ip) by bin(timestamp, 10m) | where dc_src_ip > 100 AND total_failures > 1000" },
      { name: "Successful login after many failures (different users)", query: "auth_logs | stats count_fail=countif(status=='failed'), count_success=countif(status=='success') by src_ip | where count_fail > 20 AND count_success > 0" },
      { name: "Known leaked credential usage", query: "auth_logs | where password_hash IN (SELECT hash FROM breach_database) — conceptual, requires credential screening service" }
    ],
    triage: [
      { step: 1, action: "Confirm attack vs legitimate traffic", tool: "WAF / CDN logs", what_to_look_for: "Automated patterns: consistent timing, no JS execution, missing cookies, known bot user agents" },
      { step: 2, action: "Identify successfully compromised accounts", tool: "Auth logs", what_to_look_for: "Successful logins from attack IPs — these are confirmed compromised credentials" },
      { step: 3, action: "Assess impact", tool: "Application logs", what_to_look_for: "Actions taken by attacker post-login: data access, purchases, account changes" }
    ],
    containment: [
      "Rate limit login endpoints (progressive delays after failures)",
      "Block attacking IP ranges at WAF/CDN level",
      "Enable CAPTCHA on login after 3 failures",
      "Force password reset for all confirmed compromised accounts",
      "Temporarily disable login from untrusted geolocations"
    ],
    eradication: [
      "Implement credential screening against breach databases (Have I Been Pwned API)",
      "Require password change for users with breached credentials",
      "Review and revoke unauthorized sessions"
    ],
    recovery: [
      "Notify affected users with forced password reset",
      "Implement MFA for all user accounts",
      "Deploy bot detection / CAPTCHA permanently",
      "Review and enhance rate limiting rules"
    ],
    metrics: { mttd: "< 5 minutes (automated)", mttr: "< 30 minutes for blocking", priority: "P2 High" }
  },
  {
    id: "bt-004", name: "Lateral Movement Detection", threat_type: "Lateral Movement / Pass-the-Hash",
    data_sources: ["Windows Event Logs (4624, 4625, 4648, 4672)", "Sysmon (EID 1, 3, 10, 17, 18)", "Network flow data", "EDR telemetry", "Kerberos logs (4768, 4769, 4771)"],
    detection_rules: [
      { name: "PsExec usage", query: "process where process.name == 'PSEXESVC.exe' OR (process.name == 'services.exe' AND process.child.name matches 'PSEXE*')" },
      { name: "Pass-the-Hash detection", query: "EventID == 4624 AND LogonType == 3 AND AuthenticationPackage == 'NTLM' AND TargetUserName != 'ANONYMOUS LOGON' | stats dc(TargetComputer) by TargetUserName | where dc > 5" },
      { name: "Remote service creation", query: "EventID == 7045 AND ServiceFileName matches ('*cmd*','*powershell*','*\\\\*')" },
      { name: "WMI remote execution", query: "process where process.parent.name == 'WmiPrvSE.exe' AND process.name in ('cmd.exe','powershell.exe','mshta.exe')" },
      { name: "Abnormal RDP connections", query: "EventID == 4624 AND LogonType == 10 | stats dc(TargetComputer) by SourceIP | where dc > 3 AND SourceIP IN internal_ranges" }
    ],
    triage: [
      { step: 1, action: "Identify compromised account", tool: "AD logs + EDR", what_to_look_for: "Account used for lateral movement — check if it's a service account, admin, or regular user" },
      { step: 2, action: "Map movement path", tool: "BloodHound + logs", what_to_look_for: "Sequence of hosts accessed, tools used, timestamps — build the attack chain" },
      { step: 3, action: "Determine initial compromise vector", tool: "EDR / email logs", what_to_look_for: "How did the attacker get the initial credentials? Phishing, exploitation, insider?" },
      { step: 4, action: "Check for privilege escalation", tool: "AD audit logs", what_to_look_for: "Group membership changes, new service accounts, Kerberoasting evidence (4769 with RC4)" }
    ],
    containment: [
      "Disable compromised accounts immediately",
      "Isolate affected hosts via EDR network containment",
      "Block lateral movement tools at endpoint (PsExec, WMI remote, PowerShell remoting)",
      "Reset Kerberos TGT (krbtgt) twice with 12-hour interval if Golden Ticket suspected",
      "Enable enhanced Kerberos logging"
    ],
    eradication: [
      "Reset credentials for all compromised accounts",
      "Remove any persistence on affected hosts",
      "Audit all service accounts for unauthorized changes",
      "Scan for credential dumping artifacts (lsass dumps, SAM copies)"
    ],
    recovery: [
      "Rebuild compromised hosts from clean images",
      "Implement LAPS (Local Administrator Password Solution)",
      "Deploy Credential Guard on endpoints",
      "Restrict lateral movement with Windows Firewall rules",
      "Implement tiered administration model"
    ],
    metrics: { mttd: "< 30 minutes", mttr: "< 2 hours containment", priority: "P1 Critical" }
  },
  {
    id: "bt-005", name: "Data Exfiltration Detection", threat_type: "Data Exfiltration",
    data_sources: ["DLP alerts", "Proxy/firewall logs", "DNS logs", "CASB alerts", "Endpoint file access logs", "Cloud storage audit logs"],
    detection_rules: [
      { name: "Large outbound transfer", query: "network_logs | where direction == 'outbound' AND bytes_sent > 100000000 | stats sum(bytes_sent) by src_ip, dst_ip, dst_port" },
      { name: "DNS tunneling", query: "dns_logs | where query_length > 50 OR subdomain_count > 4 | stats count by src_ip, query_domain | where count > 100" },
      { name: "Cloud storage upload spike", query: "cloud_audit | where action in ('upload','put_object','insert') | stats sum(file_size) by user, bin(timestamp, 1h) | where total > 500MB" },
      { name: "Encrypted archive creation", query: "process where process.name in ('7z.exe','rar.exe','zip.exe') AND process.command_line matches ('*-p*','*-hp*','*password*')" },
      { name: "USB mass storage", query: "sysmon_eid_6 | where DeviceType == 'USB Mass Storage' OR (EventID == 6416 AND ClassName == 'DiskDrive')" }
    ],
    triage: [
      { step: 1, action: "Validate alert — is this normal business activity?", tool: "DLP / CASB", what_to_look_for: "Compare against user's baseline transfer patterns, check if known backup or sync job" },
      { step: 2, action: "Identify what data was accessed/transferred", tool: "File access logs + DLP", what_to_look_for: "File names, classifications, sensitivity labels, volume" },
      { step: 3, action: "Determine destination", tool: "Proxy / DNS / network logs", what_to_look_for: "Where did the data go? Personal cloud, competitor, nation-state infrastructure?" },
      { step: 4, action: "Identify the actor", tool: "EDR + identity logs", what_to_look_for: "Is this a compromised account, insider threat, or automated malware exfil?" }
    ],
    containment: [
      "Block destination IPs/domains at firewall",
      "Revoke user access to sensitive data stores",
      "Enable enhanced DLP monitoring on affected user",
      "Disable USB ports on affected endpoints via GPO",
      "Block cloud storage upload for user/group"
    ],
    eradication: [
      "Remove any exfiltration tools or malware",
      "Revoke and rotate API keys/tokens used for data access",
      "Audit all data access for the past 30-90 days"
    ],
    recovery: [
      "Assess regulatory notification requirements (GDPR 72h, state breach laws)",
      "Engage legal counsel for breach assessment",
      "Notify affected data subjects if required",
      "Implement data classification and enhanced DLP rules",
      "Review and restrict data access permissions (least privilege)"
    ],
    metrics: { mttd: "< 1 hour", mttr: "< 4 hours containment", priority: "P1 Critical" }
  },
  {
    id: "bt-006", name: "C2 Beacon Detection", threat_type: "Command & Control Communication",
    data_sources: ["Network flow data", "DNS logs", "Proxy logs", "TLS certificate logs", "EDR process/network telemetry", "JA3/JA3S fingerprints"],
    detection_rules: [
      { name: "Periodic beaconing", query: "network_flows | where dst_port in (80,443) | stats count, stdev(interval) by src_ip, dst_ip | where count > 50 AND stdev < 5 (low jitter = beacon)" },
      { name: "DGA domain detection", query: "dns_logs | where shannon_entropy(query_name) > 3.5 AND query_name not in whitelist AND length(query_name) > 15" },
      { name: "Suspicious JA3 fingerprint", query: "tls_logs | where ja3_hash IN (known_c2_ja3_list) AND dst_ip NOT IN cdn_whitelist" },
      { name: "Long DNS TXT responses", query: "dns_logs | where query_type == 'TXT' AND response_length > 200 | stats count by src_ip, query_domain | where count > 10" },
      { name: "Cobalt Strike malleable C2", query: "http_logs | where uri matches '/api/v[0-9]+/.*' AND user_agent matches 'Mozilla/5.0 *' AND response_size < 1000 AND method == 'GET' | stats interval_stdev by src_ip" }
    ],
    triage: [
      { step: 1, action: "Confirm C2 vs legitimate traffic", tool: "Network analysis + threat intel", what_to_look_for: "Check domain reputation, WHOIS, certificate details, JA3 against known C2 frameworks" },
      { step: 2, action: "Identify infected endpoints", tool: "EDR", what_to_look_for: "All hosts communicating with the C2 infrastructure" },
      { step: 3, action: "Determine C2 framework", tool: "Network forensics", what_to_look_for: "Cobalt Strike (named pipes, default certs), Sliver (mTLS), Metasploit (staged payloads), custom" },
      { step: 4, action: "Assess attacker activity", tool: "EDR + endpoint logs", what_to_look_for: "Commands executed, data accessed, tools deployed, lateral movement" }
    ],
    containment: [
      "Sinkhole C2 domains at DNS level",
      "Block C2 IPs at network firewall",
      "Isolate infected endpoints via EDR",
      "Block associated JA3 fingerprints at proxy",
      "Disable outbound DNS over HTTPS (DoH) to prevent DNS tunneling bypass"
    ],
    eradication: [
      "Remove implants from all infected endpoints",
      "Kill persistence mechanisms (services, scheduled tasks, registry, WMI subscriptions)",
      "Scan entire network for indicators of compromise from the same campaign",
      "Check for secondary C2 channels (DNS, ICMP, steganography)"
    ],
    recovery: [
      "Rebuild compromised endpoints",
      "Implement DNS filtering and monitoring",
      "Deploy network traffic analysis (NTA/NDR)",
      "Add JA3/JA3S monitoring to detection pipeline",
      "Block uncategorized/newly registered domains at proxy"
    ],
    metrics: { mttd: "< 15 minutes (with NTA)", mttr: "< 2 hours containment", priority: "P1 Critical" }
  },
  {
    id: "bt-007", name: "Web Shell Detection & Response", threat_type: "Web Shell / Backdoor",
    data_sources: ["Web server access logs", "File integrity monitoring", "WAF logs", "EDR", "Web server process monitoring"],
    detection_rules: [
      { name: "Suspicious web process spawning shell", query: "process where process.parent.name in ('w3wp.exe','httpd','nginx','apache2','php-fpm','java') AND process.name in ('cmd.exe','powershell.exe','bash','sh','python','perl')" },
      { name: "New file in web root", query: "file where file.path matches ('*/wwwroot/*','*/htdocs/*','*/public_html/*','*/var/www/*') AND file.extension in ('.php','.aspx','.asp','.jsp','.jspx') AND event.action == 'creation'" },
      { name: "Encoded/obfuscated web requests", query: "http_logs | where uri contains 'base64' OR uri contains 'eval' OR request_body matches '.*(?:base64_decode|eval|exec|system|passthru).*'" },
      { name: "POST to static resource", query: "http_logs | where method == 'POST' AND uri matches '.*\\.(jpg|gif|png|css|ico|txt)$'" }
    ],
    triage: [
      { step: 1, action: "Identify the web shell file", tool: "FIM + web logs", what_to_look_for: "Recently created/modified files in web root, check file contents for eval/exec/system calls" },
      { step: 2, action: "Determine how it was uploaded", tool: "Web access logs", what_to_look_for: "File upload requests, PUT/POST to the webshell path, vulnerability exploitation (RCE, file upload bypass)" },
      { step: 3, action: "Assess attacker activity", tool: "Web logs + EDR", what_to_look_for: "Commands executed through webshell, files accessed, network connections made" }
    ],
    containment: [
      "Delete or quarantine the web shell file immediately",
      "Block the attacker's IP at WAF/firewall",
      "Restrict web server process permissions",
      "Take web application offline if actively exploited"
    ],
    eradication: [
      "Scan entire web root for additional shells (YARA rules, hashing)",
      "Patch the vulnerability that allowed the upload",
      "Review and harden file upload functionality",
      "Check for persistence (cron, scheduled tasks, additional backdoors)"
    ],
    recovery: [
      "Redeploy web application from source control",
      "Enable file integrity monitoring on web root",
      "Implement WAF rules blocking web shell indicators",
      "Regular web root integrity scans"
    ],
    metrics: { mttd: "< 10 minutes", mttr: "< 1 hour", priority: "P1 Critical" }
  },
  {
    id: "bt-008", name: "Cryptomining Detection", threat_type: "Cryptojacking / Cryptomining",
    data_sources: ["EDR CPU monitoring", "Network flow (Stratum protocol)", "DNS logs", "Cloud billing alerts", "Container runtime monitoring"],
    detection_rules: [
      { name: "Stratum protocol detection", query: "network_logs | where payload contains 'mining.subscribe' OR payload contains 'mining.authorize' OR dst_port in (3333,4444,5555,7777,8888,9999,14444)" },
      { name: "Sustained high CPU", query: "endpoint_metrics | where cpu_percent > 80 AND duration > 600s AND process.name NOT IN known_heavy_processes" },
      { name: "Known mining pool DNS", query: "dns_logs | where query matches '*.pool.*' OR query matches '*mining*' OR query IN mining_pool_domains" },
      { name: "XMRig / mining binary", query: "process where process.hash IN known_miner_hashes OR process.name in ('xmrig','minerd','cgminer','bfgminer','cpuminer')" }
    ],
    triage: [
      { step: 1, action: "Confirm mining activity", tool: "EDR + network", what_to_look_for: "Process with sustained CPU, network connections to mining pools" },
      { step: 2, action: "Determine infection vector", tool: "EDR process tree", what_to_look_for: "How was the miner deployed? Container escape, vulnerable web app, stolen credentials, supply chain?" },
      { step: 3, action: "Assess scope", tool: "Network logs", what_to_look_for: "All hosts connecting to mining pool domains/IPs" }
    ],
    containment: [
      "Kill mining processes on affected hosts",
      "Block mining pool domains and IPs at firewall",
      "Isolate compromised hosts if lateral movement detected"
    ],
    eradication: [
      "Remove mining binaries and scripts",
      "Remove persistence mechanisms (cron jobs, systemd services, container restarts)",
      "Patch exploited vulnerability",
      "Rotate credentials if password-based access was used"
    ],
    recovery: [
      "Restore affected systems to known-good state",
      "Implement CPU usage alerts",
      "Block Stratum protocol at network level",
      "Deploy container security scanning"
    ],
    metrics: { mttd: "< 30 minutes", mttr: "< 1 hour", priority: "P2 High" }
  },
  {
    id: "bt-009", name: "Insider Threat Response", threat_type: "Insider Threat / Data Theft",
    data_sources: ["DLP alerts", "UEBA anomalies", "Badge access logs", "Printing logs", "USB device logs", "Email/cloud storage audit", "HR termination notifications"],
    detection_rules: [
      { name: "After-hours data access", query: "file_access | where hour NOT BETWEEN 7 AND 19 AND user.department IN sensitive_departments | stats count by user, bin(timestamp, 1d) | where count > baseline * 3" },
      { name: "Bulk download before resignation", query: "file_access | where action == 'download' AND user IN (SELECT user FROM hr_terminations WHERE notice_date > now() - 30d) | stats sum(file_size), count by user" },
      { name: "USB data copy by departing employee", query: "usb_events | where action == 'file_copy_to_usb' AND user IN departing_employees_list" },
      { name: "Email to personal account", query: "email_logs | where sender_domain == 'company.com' AND recipient_domain IN ('gmail.com','yahoo.com','hotmail.com','protonmail.com') AND attachment_count > 0 AND attachment_size > 1MB" }
    ],
    triage: [
      { step: 1, action: "Correlate with HR data", tool: "HR system", what_to_look_for: "Is the user on a PIP, recently passed over for promotion, submitted resignation, or facing termination?" },
      { step: 2, action: "Review data access patterns", tool: "UEBA / DLP", what_to_look_for: "Deviation from normal behavior — accessing files outside their scope, bulk downloads, unusual hours" },
      { step: 3, action: "Check for data staging", tool: "Endpoint logs", what_to_look_for: "Archive creation (zip/rar), files copied to USB/cloud, large email attachments" },
      { step: 4, action: "Involve legal and HR", tool: "Process", what_to_look_for: "Do NOT alert the employee — coordinate with legal, HR, and management before any action" }
    ],
    containment: [
      "Reduce access permissions to minimum required for current role (do NOT remove entirely — may alert subject)",
      "Enable enhanced DLP monitoring and logging",
      "Disable USB ports on subject's devices",
      "Monitor email and cloud storage in real-time",
      "Coordinate with legal on evidence preservation requirements"
    ],
    eradication: [
      "Upon authorized termination: immediately revoke all access",
      "Collect company devices and badge",
      "Disable email forwarding rules",
      "Revoke OAuth app consents and API tokens",
      "Archive mailbox and cloud storage for legal hold"
    ],
    recovery: [
      "Forensic analysis of devices for evidence of data theft",
      "Determine what data was exfiltrated and assess regulatory impact",
      "Implement data classification and enhanced access controls",
      "Review and update offboarding procedures",
      "Consider legal action if IP theft confirmed"
    ],
    metrics: { mttd: "< 24 hours (UEBA)", mttr: "Varies — legal process", priority: "P2 High" }
  },
  {
    id: "bt-010", name: "DNS Tunneling Detection", threat_type: "DNS Tunneling / DNS Exfiltration",
    data_sources: ["DNS query logs (full packet capture preferred)", "Passive DNS", "Network flow", "Endpoint DNS cache"],
    detection_rules: [
      { name: "High entropy DNS queries", query: "dns_logs | where shannon_entropy(subdomain) > 3.8 AND query_type IN ('A','AAAA','TXT','MX','CNAME')" },
      { name: "Excessive queries to single domain", query: "dns_logs | where query_domain NOT IN top_1000_domains | stats count by src_ip, query_domain | where count > 500 AND timespan < 3600" },
      { name: "Long subdomain labels", query: "dns_logs | where length(subdomain) > 40 OR label_count > 5" },
      { name: "TXT record abuse", query: "dns_logs | where query_type == 'TXT' AND response_size > 200 | stats count, sum(response_size) by src_ip, query_domain" },
      { name: "Known DNS tunneling tools", query: "process where process.name in ('iodine','dnscat2','dns2tcp','godoh') OR process.command_line matches '*dns*tunnel*'" }
    ],
    triage: [
      { step: 1, action: "Analyze the domain", tool: "Threat intel + WHOIS", what_to_look_for: "Recently registered domain, privacy-protected WHOIS, hosted on suspicious infrastructure" },
      { step: 2, action: "Decode the queries", tool: "CyberChef / custom script", what_to_look_for: "Base32/Base64 encoded data in subdomain labels — decode to see what's being exfiltrated" },
      { step: 3, action: "Identify the tool", tool: "EDR + network", what_to_look_for: "iodine (Base128), dnscat2 (custom encoding), dns2tcp, cobalt strike DNS beacon" }
    ],
    containment: [
      "Sinkhole the tunneling domain at DNS resolver",
      "Block the domain's authoritative nameservers",
      "Isolate the source endpoint",
      "Force all DNS through monitored resolvers (block direct DNS to external servers)"
    ],
    eradication: [
      "Remove tunneling tool from endpoint",
      "Kill associated processes and persistence",
      "Identify and patch initial compromise vector"
    ],
    recovery: [
      "Implement DNS monitoring and analytics",
      "Deploy DNS firewall (RPZ/Response Policy Zones)",
      "Restrict DNS to approved resolvers only",
      "Block DNS over HTTPS (DoH) and DNS over TLS (DoT) to unauthorized resolvers",
      "Monitor for new tunneling domains"
    ],
    metrics: { mttd: "< 15 minutes (with DNS analytics)", mttr: "< 1 hour", priority: "P1 Critical" }
  },
  {
    id: "bt-011", name: "Phishing Response", threat_type: "Phishing Campaign",
    data_sources: ["Email gateway logs", "User reports (phish button)", "URL reputation", "Sandbox detonation", "EDR"],
    detection_rules: [
      { name: "Suspicious sender domain", query: "email_logs | where sender_domain similarity_score(company_domain) > 0.8 AND sender_domain != company_domain" },
      { name: "URL with credential harvesting indicators", query: "email_logs | where url_in_body matches '*login*' AND url_domain NOT IN trusted_domains AND url_has_https == true" },
      { name: "Attachment with macro", query: "email_logs | where attachment_extension IN ('.docm','.xlsm','.pptm','.doc','.xls') AND attachment_has_macro == true" },
      { name: "User-reported phishing", query: "phish_reports | where source == 'user_report' AND verdict == 'malicious'" }
    ],
    triage: [
      { step: 1, action: "Analyze the email", tool: "Email gateway / sandbox", what_to_look_for: "Sender authentication (SPF/DKIM/DMARC), URL destinations, attachment behavior in sandbox" },
      { step: 2, action: "Identify all recipients", tool: "Email logs", what_to_look_for: "How many users received the same email? Use message ID, subject, sender to find all instances" },
      { step: 3, action: "Check for clicks/interactions", tool: "Proxy logs / URL protection", what_to_look_for: "Which users clicked the link or opened the attachment? These are potentially compromised" }
    ],
    containment: [
      "Purge the phishing email from all mailboxes",
      "Block sender domain and URL at email gateway",
      "Block phishing URL at web proxy",
      "Force password reset for users who entered credentials",
      "Revoke sessions for potentially compromised users"
    ],
    eradication: [
      "Scan endpoints of users who clicked for malware",
      "Remove any downloaded payloads",
      "Check for persistence if malware was executed"
    ],
    recovery: [
      "Notify users who received the email with guidance",
      "Update email filtering rules with new indicators",
      "Conduct targeted awareness training for users who clicked",
      "Submit phishing indicators to threat intel sharing platforms"
    ],
    metrics: { mttd: "< 5 minutes (automated) / < 15 minutes (user-reported)", mttr: "< 30 minutes for purge", priority: "P2 High" }
  },
  {
    id: "bt-012", name: "Privilege Escalation Detection", threat_type: "Privilege Escalation",
    data_sources: ["Windows Event Logs (4672, 4728, 4732, 4756)", "Sysmon (EID 1, 13)", "Linux auditd", "EDR", "AD audit logs"],
    detection_rules: [
      { name: "Sensitive group modification", query: "EventID IN (4728,4732,4756) AND TargetGroupName IN ('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators')" },
      { name: "Suspicious SUID binary", query: "auditd | where syscall == 'chmod' AND mode matches '*4???*' AND exe NOT IN known_suid_binaries" },
      { name: "Token manipulation", query: "process where api_call IN ('AdjustTokenPrivileges','ImpersonateLoggedOnUser','SetThreadToken') AND process.name NOT IN system_processes" },
      { name: "UAC bypass attempt", query: "process where process.integrity_level == 'high' AND process.parent.integrity_level == 'medium' AND process.parent.name NOT IN ('consent.exe','svchost.exe')" },
      { name: "Kernel exploit indicators", query: "process where process.name matches '*exploit*' OR (process.parent.name == 'cmd.exe' AND process.integrity_level == 'system' AND process.parent.integrity_level == 'medium')" }
    ],
    triage: [
      { step: 1, action: "Verify if change was authorized", tool: "Change management / ticketing", what_to_look_for: "Was there an approved change request for this privilege modification?" },
      { step: 2, action: "Identify escalation method", tool: "EDR process tree", what_to_look_for: "Exploit? Misconfiguration? Credential theft? Trace the full chain from initial access to escalation" },
      { step: 3, action: "Assess current privilege level", tool: "AD / IAM", what_to_look_for: "What access does the attacker now have? Domain Admin? Root? Cloud admin?" }
    ],
    containment: [
      "Revert unauthorized group membership changes",
      "Disable compromised accounts",
      "Isolate affected hosts",
      "Patch exploited vulnerability immediately"
    ],
    eradication: [
      "Remove all persistence mechanisms created with elevated privileges",
      "Audit all accounts for unauthorized privilege changes (30-day lookback)",
      "Reset credentials for all potentially compromised privileged accounts"
    ],
    recovery: [
      "Implement just-in-time (JIT) privileged access",
      "Deploy PAM (Privileged Access Management) solution",
      "Enable Protected Users security group",
      "Regular privileged access reviews",
      "Implement Credential Guard"
    ],
    metrics: { mttd: "< 10 minutes (real-time alerting)", mttr: "< 1 hour", priority: "P1 Critical" }
  },
  {
    id: "bt-013", name: "Brute Force Attack Response", threat_type: "Brute Force / Password Spraying",
    data_sources: ["Authentication logs", "AD event logs (4625, 4771)", "VPN logs", "Web application auth logs", "Firewall logs"],
    detection_rules: [
      { name: "Traditional brute force (single target)", query: "auth_logs | where status == 'failure' AND reason == 'bad_password' | stats count by target_user, src_ip, bin(timestamp, 5m) | where count > 10" },
      { name: "Password spray (many users, few attempts each)", query: "auth_logs | where status == 'failure' | stats dc(target_user) by src_ip, bin(timestamp, 30m) | where dc_target_user > 20" },
      { name: "Slow brute force evasion", query: "auth_logs | where status == 'failure' | stats count by src_ip, target_user, bin(timestamp, 24h) | where count > 50" },
      { name: "Account lockout spike", query: "EventID == 4740 | stats count by bin(TimeGenerated, 15m) | where count > 10" }
    ],
    triage: [
      { step: 1, action: "Identify attack type", tool: "Auth logs analysis", what_to_look_for: "Single user targeted (brute force) or many users (spray)? Internal or external source?" },
      { step: 2, action: "Check for successful auth", tool: "Auth logs", what_to_look_for: "Did any login succeed from the attacking IP? Those accounts are now compromised" },
      { step: 3, action: "Determine target service", tool: "Network logs", what_to_look_for: "RDP, SSH, VPN, OWA, web app, API — which service is being attacked?" }
    ],
    containment: [
      "Block attacking IPs at firewall",
      "Force password reset for any successfully compromised accounts",
      "Implement progressive account lockout (not permanent — DoS risk)",
      "Enable CAPTCHA on targeted login endpoints",
      "Geo-block if attack originates from unexpected regions"
    ],
    eradication: [
      "Verify no persistence was established on compromised accounts",
      "Check for mail forwarding rules, OAuth apps on compromised accounts",
      "Audit recent activity on compromised accounts"
    ],
    recovery: [
      "Implement MFA on all externally accessible services",
      "Deploy password complexity requirements and breached password screening",
      "Rate limit authentication endpoints",
      "Consider passwordless authentication (FIDO2/WebAuthn)",
      "Add brute force detection to automated response playbook"
    ],
    metrics: { mttd: "< 5 minutes (automated)", mttr: "< 15 minutes for blocking", priority: "P2 High" }
  },
  {
    id: "bt-014", name: "Supply Chain Compromise Response", threat_type: "Supply Chain Attack",
    data_sources: ["Software inventory / SBOM", "Package manager logs", "CI/CD pipeline logs", "Vendor security advisories", "Threat intelligence feeds"],
    detection_rules: [
      { name: "Compromised dependency alert", query: "sbom_scan | where package_name IN threat_intel_compromised_packages OR package_hash IN known_malicious_hashes" },
      { name: "Unexpected network from build process", query: "ci_cd_logs | where stage == 'build' AND network_connection.dst NOT IN approved_registries" },
      { name: "Post-install script execution", query: "package_manager_logs | where event == 'postinstall' AND process.child.name IN ('curl','wget','powershell','bash') AND network_connection == true" },
      { name: "Dependency confusion", query: "package_manager_logs | where package_source == 'public_registry' AND package_name IN internal_package_names" }
    ],
    triage: [
      { step: 1, action: "Identify affected software/version", tool: "SBOM / dependency tree", what_to_look_for: "Exact package, version, and all applications that include it" },
      { step: 2, action: "Determine if malicious version was installed", tool: "Package lock files / build logs", what_to_look_for: "Check lock files, build artifacts, deployed containers for the compromised version" },
      { step: 3, action: "Assess execution", tool: "EDR / build logs", what_to_look_for: "Did the malicious code execute? Check for install scripts, imported modules, runtime behavior" }
    ],
    containment: [
      "Pin all dependencies to known-good versions immediately",
      "Block compromised package versions in internal registry/proxy",
      "Halt deployments using affected pipeline",
      "Isolate systems running compromised software"
    ],
    eradication: [
      "Update to patched version or remove compromised dependency",
      "Rebuild all affected applications from source with clean dependencies",
      "Regenerate all secrets/credentials that were accessible during build",
      "Scan build infrastructure for persistence"
    ],
    recovery: [
      "Implement SBOM generation and monitoring",
      "Use private package registry with allow-listing",
      "Pin all dependency versions and verify checksums",
      "Implement Sigstore/cosign for artifact signing",
      "Regular dependency audits (npm audit, pip-audit, safety)"
    ],
    metrics: { mttd: "< 1 hour (with SBOM monitoring)", mttr: "< 4 hours", priority: "P1 Critical" }
  },
  {
    id: "bt-015", name: "Persistence Mechanism Detection", threat_type: "Attacker Persistence",
    data_sources: ["Sysmon (EID 1, 11, 12, 13)", "Scheduled task logs", "Service installation logs (7045)", "Registry monitoring", "Startup folder monitoring", "crontab monitoring"],
    detection_rules: [
      { name: "New scheduled task", query: "EventID == 4698 AND TaskContent matches ('*powershell*','*cmd*','*http*','*base64*','*encoded*')" },
      { name: "New service installed", query: "EventID == 7045 AND ServiceFileName matches ('*temp*','*appdata*','*public*','*programdata*') OR ServiceFileName contains '\\\\'" },
      { name: "Registry Run key modification", query: "registry where key matches '*\\Run\\*' OR key matches '*\\RunOnce\\*' AND event.action IN ('modification','creation')" },
      { name: "WMI event subscription", query: "EventID IN (19,20,21) (Sysmon WMI events) — new permanent event consumer" },
      { name: "Crontab modification", query: "auditd | where syscall == 'rename' AND name matches '*crontab*' OR file.path matches '*/cron.d/*' AND event.action == 'creation'" },
      { name: "Startup folder addition", query: "file where file.path matches '*Startup*' AND file.extension IN ('.exe','.bat','.vbs','.ps1','.lnk','.cmd') AND event.action == 'creation'" }
    ],
    triage: [
      { step: 1, action: "Identify the persistence type", tool: "EDR / Autoruns", what_to_look_for: "Registry, scheduled task, service, WMI, startup folder, cron, systemd, profile scripts?" },
      { step: 2, action: "Trace to initial compromise", tool: "EDR process tree", what_to_look_for: "What process created the persistence? Follow the chain back to the initial access vector" },
      { step: 3, action: "Check all common persistence locations", tool: "Autoruns / LinPEAS", what_to_look_for: "Attacker may have multiple persistence mechanisms — check all of them" }
    ],
    containment: [
      "Remove identified persistence mechanisms",
      "Kill associated running processes",
      "Block execution of persistence payloads (AppLocker/WDAC)",
      "Isolate host if active C2 detected"
    ],
    eradication: [
      "Comprehensive persistence sweep using Autoruns (Windows) or linux-persistence-check",
      "Verify removal by rebooting and checking for re-establishment",
      "Scan for additional hosts with similar persistence indicators"
    ],
    recovery: [
      "If extensive persistence found, consider full rebuild",
      "Implement application whitelisting",
      "Enable Sysmon with comprehensive config",
      "Monitor persistence locations continuously",
      "Regular Autoruns baseline comparisons"
    ],
    metrics: { mttd: "< 10 minutes (real-time monitoring)", mttr: "< 2 hours", priority: "P1 Critical" }
  }
];

export const DETECTION_ENGINEERING = {
  data_source_priorities: [
    { source: "EDR/XDR telemetry", coverage: "Endpoint visibility — process, file, registry, network", priority: 1 },
    { source: "Windows Event Logs", coverage: "Authentication, process creation, service installation", priority: 1 },
    { source: "Network flow / PCAP", coverage: "Lateral movement, C2, exfiltration", priority: 1 },
    { source: "DNS logs", coverage: "C2 beaconing, tunneling, DGA", priority: 2 },
    { source: "Email gateway logs", coverage: "Phishing, BEC, malware delivery", priority: 2 },
    { source: "Cloud audit logs (CloudTrail, Azure Activity)", coverage: "Cloud API abuse, privilege escalation", priority: 2 },
    { source: "Web proxy / WAF logs", coverage: "Web attacks, data exfiltration via HTTP", priority: 2 },
    { source: "Identity provider logs (Azure AD, Okta)", coverage: "Credential abuse, MFA bypass, consent phishing", priority: 1 },
    { source: "DLP alerts", coverage: "Data exfiltration, policy violations", priority: 3 },
    { source: "Vulnerability scanner output", coverage: "Attack surface, exploitable weaknesses", priority: 3 }
  ],
  siem_query_languages: [
    { platform: "Splunk", language: "SPL", example: "index=windows EventCode=4624 LogonType=10 | stats count by src_ip, dest" },
    { platform: "Microsoft Sentinel", language: "KQL", example: "SecurityEvent | where EventID == 4624 and LogonType == 10 | summarize count() by SourceIP, Computer" },
    { platform: "Elastic", language: "EQL/KQL", example: "event.code: 4624 AND winlog.event_data.LogonType: 10" },
    { platform: "Chronicle", language: "YARA-L", example: "rule lateral_rdp { meta: events: $e.metadata.event_type = 'USER_LOGIN' $e.metadata.product_event_type = '4624' condition: $e }" },
    { platform: "Sigma", language: "Sigma YAML", example: "detection: selection: EventID: 4624 LogonType: 10 condition: selection" }
  ]
};
