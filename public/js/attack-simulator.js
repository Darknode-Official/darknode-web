// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Attack Simulator -- interactive cyber attack kill chain walkthrough and tabletop exercises.
// 12 scenarios, interactive phase execution, defense reports, MITRE ATT&CK coverage

var esc = function(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, function(c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
};

var SCENARIOS = [
  {
    name: "Spear Phishing Campaign",
    type: "Social Engineering",
    difficulty: "Intermediate",
    impact: "Critical",
    realWorld: "SolarWinds (2020), RSA SecurID (2011)",
    phases: [
      { name: "Reconnaissance", time: "Days-Weeks", severity: "low", attacker: "Attacker researches target organization via LinkedIn, company website, SEC filings. Identifies key employees in finance/IT with elevated access. Harvests email addresses using theHarvester, hunter.io.", defender: "Monitor for excessive LinkedIn profile views. Track domain mentions in paste sites. Implement email address obfuscation on public-facing pages.", mitre: "T1589 - Gather Victim Identity Information", iocs: ["Increased social media reconnaissance", "Suspicious email address harvesting attempts"], prevention: ["Employee social media awareness training", "Limit publicly available org information", "Use email aliases for public contacts"], tools: ["theHarvester", "SpiderFoot", "Maltego", "hunter.io", "Recon-ng"], execSteps: ["Scanning LinkedIn for target employees...", "Harvesting email addresses from company domain...", "Cross-referencing org chart with public records...", "Building target profile with role and access level...", "Identifying 5 high-value targets in Finance/IT"] },
      { name: "Weaponization", time: "Hours-Days", severity: "medium", attacker: "Creates convincing phishing email impersonating a trusted vendor or executive. Crafts malicious Office document with VBA macro that downloads second-stage payload. Registers typosquatted domain for C2.", defender: "Domain monitoring for typosquats using dnstwist. Monitor certificate transparency logs for suspicious domain registrations.", mitre: "T1566.001 - Phishing: Spearphishing Attachment", iocs: ["Newly registered lookalike domains", "Suspicious SSL certificates", "Macro-enabled document artifacts"], prevention: ["Email gateway with attachment sandboxing", "Disable Office macros via GPO for non-power users", "DMARC/DKIM/SPF enforcement"], tools: ["GoPhish", "SET", "msfvenom", "dnstwist", "Evilginx2"], execSteps: ["Registering typosquatted domain...", "Generating SSL certificate for phishing domain...", "Crafting macro-enabled Excel document...", "Embedding PowerShell download cradle in VBA...", "Testing payload against sandbox detection..."] },
      { name: "Delivery", time: "Minutes", severity: "medium", attacker: "Sends spear phishing email to 3-5 targeted employees during business hours. Email references a legitimate ongoing project to increase credibility. Attachment is a macro-enabled Excel file with invoice data.", defender: "Email gateway should flag macro-enabled attachments. Monitor for emails from newly registered domains. Check DMARC alignment on inbound mail.", mitre: "T1566.001 - Phishing: Spearphishing Attachment", iocs: ["Email from external domain impersonating internal", "Macro-enabled Office attachment", "URL pointing to recently registered domain"], prevention: ["Advanced email filtering (Proofpoint, Mimecast)", "User phishing awareness training", "Banner warnings on external emails"], tools: ["Exchange Online Protection", "Proofpoint", "Mimecast"], execSteps: ["Sending phishing email to target #1 (Finance Director)...", "Sending phishing email to target #2 (IT Manager)...", "Email delivered successfully to 4 of 5 targets...", "1 email quarantined by gateway (macro detection)...", "Waiting for user interaction..."] },
      { name: "Exploitation", time: "Minutes", severity: "high", attacker: "Victim opens attachment and enables macros. VBA code executes PowerShell command that downloads and runs Cobalt Strike beacon. Initial beacon establishes HTTPS C2 channel via domain fronting.", defender: "AMSI should detect PowerShell download cradle. EDR should alert on Office spawning PowerShell. Application whitelisting should block unsigned executables.", mitre: "T1059.001 - PowerShell, T1204.002 - User Execution: Malicious File", iocs: ["Office application spawning cmd.exe or PowerShell", "PowerShell with encoded commands", "Outbound HTTPS to newly registered domain", "Process injection into legitimate processes"], prevention: ["AMSI enabled", "Constrained Language Mode for PowerShell", "AppLocker/WDAC policies", "EDR with behavioral detection"], tools: ["Cobalt Strike", "Metasploit", "PowerShell Empire"], execSteps: ["Target #2 opened attachment and enabled macros...", "VBA macro executing PowerShell download cradle...", "Cobalt Strike beacon downloaded and executed...", "HTTPS C2 channel established via domain fronting...", "Initial foothold achieved on workstation WKSTN-IT-042"] },
      { name: "Credential Theft", time: "Minutes-Hours", severity: "critical", attacker: "Beacon runs Mimikatz to dump credentials from LSASS memory. Obtains NTLM hashes and Kerberos tickets for the compromised user and cached domain admin credentials.", defender: "Credential Guard should protect LSASS. Monitor for LSASS access by non-system processes (Sysmon Event ID 10). Alert on Mimikatz signatures.", mitre: "T1003.001 - OS Credential Dumping: LSASS Memory", iocs: ["LSASS memory access by unusual processes", "Mimikatz string patterns in memory", "Suspicious DLL loaded into LSASS", "Event ID 4624 type 9 logon"], prevention: ["Windows Credential Guard", "RunAsPPL for LSASS", "Disable WDigest authentication", "Restrict debug privileges"], tools: ["Mimikatz", "ProcDump", "comsvcs.dll MiniDump"], execSteps: ["Elevating privileges on compromised workstation...", "Dumping LSASS process memory...", "Extracting NTLM hashes from memory dump...", "Found cached domain admin credentials...", "Obtained 12 credential sets including 2 admin accounts"] },
      { name: "Lateral Movement", time: "Hours-Days", severity: "critical", attacker: "Uses stolen credentials with PsExec to move to file server. Deploys additional beacons on critical servers. Uses RDP to access domain controller via compromised admin account.", defender: "Monitor for PsExec service installation (Event ID 7045). Track lateral movement via network flow analysis. Alert on unusual RDP connections.", mitre: "T1021.002 - SMB/Windows Admin Shares, T1021.001 - RDP", iocs: ["PsExec service installation on remote hosts", "SMB connections from workstation to server", "RDP from unexpected source IPs", "Pass-the-hash authentication patterns"], prevention: ["Network segmentation", "Privileged Access Workstations", "LAPS for local admin passwords", "Restrict RDP to jump hosts"], tools: ["PsExec", "CrackMapExec", "Impacket", "Evil-WinRM"], execSteps: ["Using Pass-the-Hash to authenticate to file server...", "PsExec service installed on FILESRV-01...", "Deploying Cobalt Strike beacon on FILESRV-01...", "RDP session to DC-01 via compromised admin account...", "Lateral movement to 4 additional servers complete"] },
      { name: "Data Exfiltration", time: "Hours-Days", severity: "critical", attacker: "Identifies sensitive data on file shares (financial records, customer PII, trade secrets). Stages data in a compressed, encrypted archive. Exfiltrates via HTTPS to cloud storage (OneDrive, Google Drive) to blend with normal traffic.", defender: "DLP should detect large file transfers to cloud storage. Monitor for unusual data access patterns. Track archive creation on file servers.", mitre: "T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage", iocs: ["Large archive file creation on file servers", "Unusual volume of file access", "Data upload to personal cloud storage", "DNS queries to cloud storage providers at unusual hours"], prevention: ["Data Loss Prevention (DLP) policies", "Cloud Access Security Broker (CASB)", "Network traffic analysis", "Data classification and access monitoring"], tools: ["Rclone", "MEGAcmd", "CloudBrute"], execSteps: ["Enumerating accessible file shares...", "Identified 2.3GB of sensitive financial data...", "Compressing and encrypting data archive...", "Uploading to cloud storage via HTTPS...", "Exfiltration complete: 2.3GB transferred in 4 hours"] },
    ]
  },
  {
    name: "SQL Injection to Database Breach",
    type: "Web Application Attack",
    difficulty: "Intermediate",
    impact: "High",
    realWorld: "Heartland Payment Systems (2008), TalkTalk (2015)",
    phases: [
      { name: "Reconnaissance", time: "Hours", severity: "low", attacker: "Scans target web application for input fields and URL parameters. Tests for error-based SQL injection by injecting single quotes. Identifies the database type from error messages (MySQL, MSSQL, PostgreSQL).", defender: "WAF should detect SQL injection probes. Monitor for scanning patterns in web logs. Implement custom error pages that hide DB information.", mitre: "T1190 - Exploit Public-Facing Application", iocs: ["Repeated requests with SQL special characters", "HTTP 500 errors with database error messages", "Requests to common SQL injection test paths"], prevention: ["WAF deployment", "Custom error pages", "Input validation", "Parameterized queries"], tools: ["SQLMap", "Burp Suite", "OWASP ZAP"], execSteps: ["Scanning web application for input parameters...", "Testing search field with single quote injection...", "MySQL error message detected in response...", "Identified 3 injectable parameters...", "Database type confirmed: MySQL 8.0"] },
      { name: "Exploitation", time: "Hours", severity: "high", attacker: "Uses UNION-based injection to enumerate database schema. Extracts table names, column names. Identifies tables containing user credentials and payment data. Uses sqlmap with --dump flag to extract all data.", defender: "Database activity monitoring should alert on UNION queries. IDS signatures for SQL injection patterns. Application should use parameterized queries.", mitre: "T1190 - Exploit Public-Facing Application", iocs: ["UNION SELECT in HTTP parameters", "Information schema queries in logs", "Unusual database query patterns", "Slow query log entries with injection syntax"], prevention: ["Parameterized queries / prepared statements", "ORM with query builder", "Least privilege database accounts", "Database activity monitoring"], tools: ["SQLMap", "jSQL Injection", "NoSQLMap"], execSteps: ["Running UNION-based column enumeration...", "Found 8 columns in target query...", "Extracting table names from information_schema...", "Located users table with 45K records...", "Dumping payment_cards table (12K records)..."] },
      { name: "Privilege Escalation", time: "Hours", severity: "critical", attacker: "Uses database-specific escalation techniques. On MySQL: reads /etc/passwd via LOAD_FILE(). On MSSQL: enables xp_cmdshell for OS command execution. Obtains database admin credentials from configuration tables.", defender: "Database should run with least privilege. xp_cmdshell should be disabled. FILE privilege should not be granted to web application accounts.", mitre: "T1068 - Exploitation for Privilege Escalation", iocs: ["xp_cmdshell execution attempts", "LOAD_FILE() or INTO OUTFILE queries", "Privilege escalation stored procedures", "New admin accounts created in database"], prevention: ["Least privilege database accounts", "Disable dangerous stored procedures", "Remove FILE privilege", "Regular database security audits"], tools: ["SQLMap --os-shell", "PowerUpSQL", "ODAT"], execSteps: ["Attempting LOAD_FILE() to read /etc/passwd...", "FILE privilege confirmed on db user...", "Reading database configuration file...", "Found database admin credentials in config...", "Escalated to DBA role with full privileges"] },
      { name: "Data Exfiltration", time: "Hours-Days", severity: "critical", attacker: "Dumps all user credentials, payment card data, PII. Uses DNS exfiltration to bypass DLP if direct download is blocked. Exfiltrates data in small chunks to avoid triggering volume-based alerts.", defender: "Database DLP should detect mass data extraction. DNS monitoring should flag unusually long DNS queries (tunneling). Track database query result sizes.", mitre: "T1048.003 - Exfiltration Over Alternative Protocol: DNS", iocs: ["Large result sets from database queries", "Long DNS queries with encoded data", "Unusual outbound DNS volume", "Database queries accessing all rows of sensitive tables"], prevention: ["Database Activity Monitoring", "DNS filtering and monitoring", "Query result size limits", "Tokenization of sensitive data"], tools: ["SQLMap", "dnscat2", "iodine"], execSteps: ["Dumping users table (45K records)...", "Dumping payment_cards table (12K records)...", "DLP blocking direct download, switching to DNS exfil...", "Encoding data chunks in DNS queries...", "Exfiltration complete: 230MB extracted over 6 hours"] },
      { name: "Persistence", time: "Minutes-Hours", severity: "high", attacker: "Creates backdoor database user. Installs web shell in web root via INTO OUTFILE. Modifies stored procedures to include backdoor functionality. Sets up scheduled database job for persistence.", defender: "File integrity monitoring should detect new files in web root. Database user auditing should flag new privileged accounts. Monitor for modified stored procedures.", mitre: "T1505.003 - Server Software Component: Web Shell", iocs: ["New files in web application directories", "New database user accounts", "Modified stored procedures", "Scheduled database jobs created"], prevention: ["File integrity monitoring on web root", "Database user account auditing", "Regular stored procedure review", "Web application file permissions"], tools: ["China Chopper", "WSO", "b374k"], execSteps: ["Creating backdoor database user 'svc_backup'...", "Writing web shell to /var/www/html/.cache.php...", "Modifying login stored procedure with backdoor...", "Creating scheduled job for daily credential dump...", "Persistence mechanisms installed successfully"] },
    ]
  },
  {
    name: "Ransomware Attack",
    type: "Extortion",
    difficulty: "Advanced",
    impact: "Critical",
    realWorld: "Colonial Pipeline (2021), Kaseya (2021), WannaCry (2017)",
    phases: [
      { name: "Initial Access", time: "Minutes-Hours", severity: "medium", attacker: "Gains initial foothold via phishing email, exploiting VPN vulnerability (e.g., CVE-2021-20016 SonicWall), or purchasing RDP credentials from initial access broker on dark web.", defender: "Patch VPN appliances immediately. Enforce MFA on all remote access. Monitor dark web for compromised credentials.", mitre: "T1133 - External Remote Services, T1078 - Valid Accounts", iocs: ["RDP brute force attempts", "VPN login from unusual geolocation", "Credential purchases on dark web forums", "Exploitation attempts against VPN CVEs"], prevention: ["MFA on all remote access", "Patch management for edge devices", "Dark web monitoring", "RDP behind VPN only"], tools: ["Metasploit", "RDP brute force tools", "Initial access broker markets"], execSteps: ["Purchasing RDP credentials from access broker...", "Testing credentials against target VPN...", "VPN login successful from proxy in Eastern Europe...", "Initial shell obtained on terminal server...", "Foothold established on TERMSRV-01"] },
      { name: "Internal Reconnaissance", time: "Hours-Days", severity: "medium", attacker: "Maps the network using tools like Advanced IP Scanner, BloodHound. Identifies domain controllers, backup servers, file shares. Enumerates Group Policy to understand security posture.", defender: "Monitor for port scanning activity. Alert on BloodHound/SharpHound data collection. Detect LDAP enumeration queries.", mitre: "T1018 - Remote System Discovery, T1087 - Account Discovery", iocs: ["Port scanning from internal workstation", "SharpHound LDAP queries", "SAMR/LSARPC enumeration", "Large volume of DNS lookups from single host"], prevention: ["Network segmentation", "Honeypots/honeytokens", "Endpoint detection for recon tools", "Restrict LDAP access"], tools: ["BloodHound", "ADRecon", "Advanced IP Scanner", "Nmap"], execSteps: ["Running Advanced IP Scanner on local subnet...", "Discovered 342 live hosts across 5 VLANs...", "Running SharpHound to map AD environment...", "Identified 3 domain controllers and 2 backup servers...", "Group Policy analysis reveals weak security posture"] },
      { name: "Privilege Escalation and Credential Theft", time: "Hours", severity: "critical", attacker: "Exploits misconfigured services, unpatched local vulnerabilities (PrintNightmare, ZeroLogon). Dumps credentials with Mimikatz. Obtains domain admin access.", defender: "Patch critical vulnerabilities immediately. Enable Credential Guard. Monitor for credential dumping indicators.", mitre: "T1003 - OS Credential Dumping, T1068 - Exploitation for Privilege Escalation", iocs: ["ZeroLogon exploitation attempts (Event ID 4742)", "PrintNightmare exploitation", "LSASS memory access", "New service principal names"], prevention: ["Timely patching of critical CVEs", "Credential Guard", "Tiered admin model", "LAPS deployment"], tools: ["Mimikatz", "Rubeus", "PrintNightmare exploits", "ZeroLogon scripts"], execSteps: ["Testing for PrintNightmare vulnerability...", "CVE-2021-34527 exploitation successful...", "Dumping LSASS memory with Mimikatz...", "Domain admin hash recovered...", "Full domain admin access achieved"] },
      { name: "Lateral Movement and Staging", time: "Hours-Days", severity: "critical", attacker: "Uses stolen domain admin credentials to access all systems. Deploys Cobalt Strike beacons across the network. Identifies and disables backup systems, shadow copies, and EDR solutions.", defender: "Monitor for mass SMB file copies. Alert on backup service disruption. Detect EDR tampering or service stops.", mitre: "T1490 - Inhibit System Recovery, T1562.001 - Disable or Modify Tools", iocs: ["vssadmin delete shadows commands", "Backup agent service stopped", "EDR/AV services disabled", "Mass lateral movement via SMB"], prevention: ["Immutable/air-gapped backups", "EDR tamper protection", "Backup monitoring and alerting", "Privileged access management"], tools: ["Cobalt Strike", "PsExec", "WMIC", "PowerShell"], execSteps: ["Deploying beacons to 50 critical servers...", "Disabling Veeam backup agent on BACKUP-01...", "Deleting volume shadow copies on all servers...", "Disabling Windows Defender via GPO...", "All backup and recovery mechanisms neutralized"] },
      { name: "Encryption and Extortion", time: "Minutes-Hours", severity: "critical", attacker: "Deploys ransomware payload to all accessible systems simultaneously via Group Policy or PsExec. Files encrypted with AES-256, key encrypted with RSA-2048. Ransom note demands cryptocurrency payment. Threatens to publish stolen data on leak site.", defender: "EDR should detect mass file encryption. Network monitoring should flag sudden spike in file modifications. Incident response plan should include ransomware playbook.", mitre: "T1486 - Data Encrypted for Impact, T1657 - Financial Theft", iocs: ["Mass file extension changes", "Ransom note files dropped in directories", "CPU spike from encryption processes", "Outbound connections to Tor hidden services"], prevention: ["Tested offline backups", "Network segmentation", "Application whitelisting", "Ransomware-specific EDR rules"], tools: ["LockBit", "BlackCat/ALPHV", "Cl0p", "REvil"], execSteps: ["Deploying ransomware payload via Group Policy...", "Encryption process initiated on 342 endpoints...", "File encryption rate: 1.2GB per minute per host...", "Ransom notes deployed to all desktops...", "Leak site updated with victim countdown timer"] },
    ]
  },
  {
    name: "Supply Chain Compromise",
    type: "Advanced Persistent Threat",
    difficulty: "Expert",
    impact: "Critical",
    realWorld: "SolarWinds Orion (2020), Codecov (2021), 3CX (2023)",
    phases: [
      { name: "Vendor Compromise", time: "Weeks-Months", severity: "high", attacker: "Targets a software vendor's build/CI pipeline. Compromises developer credentials via phishing or repo access tokens. Inserts malicious code into the software update mechanism that will be distributed to all customers.", defender: "Vendor should implement code signing, build pipeline integrity checks (SLSA framework). Customers should verify software integrity via checksums and signatures.", mitre: "T1195.002 - Supply Chain Compromise: Compromise Software Supply Chain", iocs: ["Unauthorized commits to build pipeline", "Modified build scripts", "New dependencies added without review", "CI/CD configuration changes"], prevention: ["SLSA framework compliance", "Code signing with hardware security modules", "Build reproducibility", "Dependency review and pinning"], tools: ["Sigstore", "in-toto", "SLSA verifier"], execSteps: ["Phishing vendor developer for repo access...", "Compromised developer access token obtained...", "Injecting malicious code into build pipeline...", "Code passes automated tests (designed to evade)...", "Malicious update queued for next release cycle"] },
      { name: "Distribution", time: "Days-Weeks", severity: "critical", attacker: "Malicious update is signed with the vendor's legitimate code signing certificate and distributed through normal update channels. All customers who auto-update receive the trojanized version.", defender: "Software composition analysis should track all dependencies. Binary analysis of updates before deployment. Network monitoring for unusual post-update behavior.", mitre: "T1195.002 - Supply Chain Compromise", iocs: ["Unexpected network connections after software update", "New processes spawned by trusted software", "Unusual DNS queries from updated software", "Binary hash mismatch from vendor's published hash"], prevention: ["Staged rollout of updates", "Binary verification", "Network behavior baseline for software", "Air-gapped environments for critical systems"], tools: ["VirusTotal", "YARA", "Software Composition Analysis tools"], execSteps: ["Trojanized update signed with vendor certificate...", "Update pushed to vendor's CDN...", "18,000 organizations downloading update...", "Auto-update installing on customer systems...", "Backdoor deployed to all updated instances"] },
      { name: "Activation", time: "Weeks", severity: "high", attacker: "Backdoor activates after a dormancy period (2-4 weeks) to avoid association with the update. Performs initial system fingerprinting and environment checks (anti-sandbox). Establishes C2 channel disguised as legitimate vendor telemetry traffic.", defender: "Network monitoring should baseline vendor telemetry and detect deviations. EDR should monitor process behavior changes after updates.", mitre: "T1497 - Virtualization/Sandbox Evasion, T1071 - Application Layer Protocol", iocs: ["Software connecting to non-vendor domains", "DNS requests to DGA domains", "Steganographic data in HTTP responses", "Process behavior change weeks after update"], prevention: ["Network segmentation for vendor software", "Behavioral monitoring", "DNS monitoring and sinkholing", "Zero-trust architecture"], tools: ["Zeek", "Suricata", "Carbon Black", "CrowdStrike"], execSteps: ["Dormancy period elapsed (14 days)...", "Backdoor performing environment fingerprinting...", "Anti-sandbox checks passed (not a VM)...", "C2 channel established via vendor telemetry mimicry...", "Beacon active, awaiting operator commands"] },
      { name: "Targeted Exploitation", time: "Weeks-Months", severity: "critical", attacker: "From thousands of compromised organizations, attacker selects high-value targets (government, defense, critical infrastructure). Deploys custom second-stage implants only to selected targets. Begins data collection and exfiltration.", defender: "Threat hunting should look for anomalous outbound connections from vendor software. Implement micro-segmentation around vendor products. Monitor for second-stage payload delivery.", mitre: "T1587.001 - Develop Capabilities: Malware", iocs: ["Targeted second-stage payloads", "Custom implant communication patterns", "Selective targeting based on organization", "Encrypted C2 traffic to cloud infrastructure"], prevention: ["Micro-segmentation", "Threat hunting program", "Network traffic analysis", "EDR with behavioral detection"], tools: ["CrowdStrike", "SentinelOne", "Palo Alto Cortex XDR"], execSteps: ["Filtering compromised orgs for high-value targets...", "Selected 40 government and defense targets...", "Deploying custom second-stage implant to targets...", "Data collection initiated on classified networks...", "Long-term persistent access established"] },
    ]
  },
  {
    name: "Insider Threat",
    type: "Data Theft",
    difficulty: "Beginner",
    impact: "High",
    realWorld: "Edward Snowden (2013), Anthony Levandowski/Waymo (2017)",
    phases: [
      { name: "Motivation", time: "Weeks-Months", severity: "low", attacker: "Disgruntled employee or one recruited by competitor/nation-state. Has legitimate access to sensitive systems and data. Begins planning data theft, often triggered by perceived slight, financial pressure, or job change.", defender: "HR and management should monitor for behavioral indicators: sudden policy violations, after-hours access, expressions of dissatisfaction. Implement insider threat program.", mitre: "N/A - Pre-attack phase", iocs: ["Increased policy violations", "After-hours badge access", "Browsing job sites", "Accessing data outside normal job function"], prevention: ["Insider threat awareness program", "Regular access reviews", "Exit interview process", "Employee assistance programs"], tools: ["UEBA platforms", "HR analytics"], execSteps: ["Employee passed over for promotion (trigger event)...", "Behavioral indicators increasing over 3 weeks...", "After-hours access patterns detected...", "Job site browsing from corporate device...", "Employee begins planning data collection"] },
      { name: "Data Staging", time: "Days-Weeks", severity: "medium", attacker: "Begins accessing and downloading files beyond normal job requirements. Copies sensitive documents to personal devices, email, or cloud storage. May use encryption or steganography to hide the data.", defender: "DLP should flag unusual download volumes. UEBA should detect deviation from normal data access patterns. Monitor for USB device connections and cloud upload activity.", mitre: "T1074 - Data Staged, T1052 - Exfiltration Over Physical Medium", iocs: ["Downloading large volumes of files", "Accessing databases not related to job role", "USB device connections", "Emailing files to personal accounts", "Cloud storage uploads"], prevention: ["DLP policies", "USB device restrictions", "Cloud access controls", "Data access monitoring", "Principle of least privilege"], tools: ["Microsoft Purview DLP", "Forcepoint", "Digital Guardian", "Teramind"], execSteps: ["Employee accessing engineering file shares...", "Downloading product roadmap documents...", "Copying source code to personal USB drive...", "Accessing customer database (outside normal role)...", "842 files staged on personal device over 5 days"] },
      { name: "Exfiltration", time: "Days", severity: "critical", attacker: "Transfers data out of the organization via personal email, USB drives, cloud storage, or printed documents. May use personal devices or home network to avoid corporate monitoring. Timing often coincides with resignation or termination notice.", defender: "Increase monitoring during notice period. Disable access to sensitive systems upon resignation notification. Forensic preservation of employee devices.", mitre: "T1567 - Exfiltration Over Web Service, T1052 - Exfiltration Over Physical Medium", iocs: ["Email forwarding rules to external addresses", "Large print jobs of sensitive documents", "File transfers during off-hours", "Data access spike before resignation"], prevention: ["Enhanced monitoring during notice period", "Immediate access revocation for terminated employees", "Print and copy monitoring", "Exit interviews with NDA reminder"], tools: ["Email DLP", "Print monitoring", "CASB", "Endpoint forensics"], execSteps: ["Employee submits resignation notice...", "Spike in file access detected in final week...", "Large email attachment sent to personal Gmail...", "USB device connected and 4.2GB transferred...", "Employee departs with proprietary data"] },
    ]
  },
  {
    name: "DDoS Attack",
    type: "Availability Attack",
    difficulty: "Beginner",
    impact: "High",
    realWorld: "Dyn DNS Attack (2016), GitHub DDoS (2018), AWS (2020)",
    phases: [
      { name: "Botnet Assembly", time: "Weeks-Months", severity: "medium", attacker: "Compromises IoT devices (cameras, routers, DVRs) using default credentials or known vulnerabilities. Builds botnet of thousands to millions of compromised devices. Tests botnet capability with small probe attacks.", defender: "ISPs should detect and notify compromised IoT devices. Organizations should change default credentials on all IoT devices. Network monitoring for C2 traffic from IoT devices.", mitre: "T1583.005 - Acquire Infrastructure: Botnet", iocs: ["IoT devices connecting to known C2 servers", "Scanning for Telnet/SSH on IoT ports", "Default credential brute force attempts", "Mirai-like traffic patterns"], prevention: ["Change default IoT credentials", "Network segmentation for IoT", "Firmware updates", "IoT device inventory"], tools: ["Mirai", "Mozi", "Hajime"], execSteps: ["Scanning for IoT devices with default credentials...", "Found 45,000 vulnerable cameras and routers...", "Deploying botnet agent to compromised devices...", "Botnet C2 infrastructure established...", "Test attack: 50Gbps capacity confirmed"] },
      { name: "Attack Launch", time: "Minutes", severity: "critical", attacker: "Launches volumetric attack (DNS amplification, NTP reflection, memcached amplification) reaching hundreds of Gbps. Simultaneously launches application-layer attacks (HTTP floods, slowloris). Uses multiple vectors to overwhelm different defense layers.", defender: "CDN and DDoS mitigation service should absorb volumetric attacks. Rate limiting and challenge pages for application-layer attacks. Anycast routing to distribute traffic.", mitre: "T1498 - Network Denial of Service, T1499 - Endpoint Denial of Service", iocs: ["Sudden traffic spike from many source IPs", "DNS amplification responses", "NTP monlist responses", "HTTP flood from distributed sources"], prevention: ["DDoS mitigation service (Cloudflare, Akamai, AWS Shield)", "Rate limiting", "Anycast DNS", "Traffic scrubbing"], tools: ["LOIC (educational)", "HOIC (educational)", "Amplification tools"], execSteps: ["Initiating DNS amplification from 45K bots...", "Traffic volume: 180Gbps and rising...", "Launching HTTP flood on application layer...", "Target website unreachable (HTTP 503)...", "Attack sustained at 320Gbps peak volume"] },
      { name: "Sustained Attack and Extortion", time: "Hours-Days", severity: "critical", attacker: "Maintains attack for hours or days, adjusting vectors as defenses adapt. Sends ransom demand threatening continued or escalated attack. May launch secondary attack against different infrastructure components.", defender: "Incident response team coordinates with ISP and DDoS mitigation provider. Implement backup communication channels. Document attack for law enforcement.", mitre: "T1498 - Network Denial of Service, T1657 - Financial Theft", iocs: ["Sustained high traffic volume", "Attack vector changes", "Ransom demand via email", "Secondary attacks on other services"], prevention: ["DDoS response playbook", "Multiple ISP connections", "Cloud-based failover", "Law enforcement coordination"], tools: ["Cloudflare", "Akamai Prolexic", "AWS Shield Advanced"], execSteps: ["Attack sustained for 4 hours, vectors rotating...", "Ransom demand email sent: 10 BTC to stop...", "Secondary attack launched against DNS servers...", "Mitigation service engaging, traffic scrubbing...", "Attack duration: 18 hours total downtime"] },
    ]
  },
  {
    name: "Cloud Account Takeover",
    type: "Cloud Attack",
    difficulty: "Intermediate",
    impact: "Critical",
    realWorld: "Capital One (2019), Twitch (2021)",
    phases: [
      { name: "Credential Discovery", time: "Minutes-Hours", severity: "medium", attacker: "Finds exposed AWS access keys in public GitHub repository, S3 bucket, or Docker image. Alternatively, exploits SSRF vulnerability to reach cloud metadata service (IMDSv1) and steal IAM role credentials.", defender: "Scan repositories for secrets using tools like truffleHog, git-secrets. Enforce IMDSv2. Monitor for unusual API calls from unexpected sources.", mitre: "T1552.005 - Unsecured Credentials: Cloud Instance Metadata API", iocs: ["GitHub commits containing access keys", "SSRF attempts targeting 169.254.169.254", "API calls from unusual IP ranges", "Credential usage outside normal patterns"], prevention: ["Secret scanning in CI/CD pipeline", "IMDSv2 enforcement", "Rotate credentials regularly", "Limit IAM role permissions"], tools: ["truffleHog", "git-secrets", "Gitleaks", "Pacu"], execSteps: ["Scanning GitHub for exposed AWS credentials...", "Found AKIA*** access key in public repository...", "Key committed 3 hours ago, not yet rotated...", "Testing key permissions with sts:GetCallerIdentity...", "Key has AdministratorAccess policy attached"] },
      { name: "Enumeration", time: "Hours", severity: "medium", attacker: "Uses stolen credentials to enumerate cloud resources: S3 buckets, EC2 instances, Lambda functions, RDS databases. Maps IAM policies to find privilege escalation paths. Identifies high-value data stores.", defender: "CloudTrail monitoring should detect enumeration API calls. Alert on IAM policy enumeration. SCPs should limit what can be discovered.", mitre: "T1580 - Cloud Infrastructure Discovery, T1087.004 - Cloud Account Discovery", iocs: ["Rapid API enumeration calls (ListBuckets, DescribeInstances)", "IAM policy listing from unusual principal", "Cross-region API activity", "API calls during off-hours"], prevention: ["CloudTrail monitoring with alerts", "Service Control Policies", "Least privilege IAM roles", "AWS Access Analyzer"], tools: ["Pacu", "ScoutSuite", "Prowler", "CloudMapper"], execSteps: ["Listing S3 buckets (found 47)...", "Enumerating EC2 instances across all regions...", "Mapping IAM roles and policies...", "Identified privilege escalation via Lambda...", "Located RDS instances with customer data"] },
      { name: "Privilege Escalation", time: "Hours", severity: "high", attacker: "Exploits IAM misconfigurations: iam:PassRole to escalate via Lambda, iam:CreatePolicyVersion to grant admin, iam:AttachUserPolicy to self-grant. Creates new access key for persistence.", defender: "Monitor for IAM policy changes, new access key creation, role assumption from unexpected principals. Use AWS Access Analyzer to find overly permissive policies.", mitre: "T1078.004 - Valid Accounts: Cloud Accounts", iocs: ["CreateAccessKey for existing user", "AttachUserPolicy or PutUserPolicy calls", "AssumeRole to admin role from unexpected principal", "CreatePolicyVersion with admin permissions"], prevention: ["Least privilege IAM policies", "SCP guardrails", "MFA for IAM operations", "Regular IAM access reviews"], tools: ["Pacu", "PMapper", "Cloudsplaining", "Parliament"], execSteps: ["Exploiting iam:PassRole with Lambda function...", "Lambda executed with elevated service role...", "Creating new IAM policy version with admin access...", "Attaching admin policy to compromised user...", "Full cloud account admin access achieved"] },
      { name: "Data Access and Exfiltration", time: "Hours-Days", severity: "critical", attacker: "Accesses S3 buckets containing sensitive data (PII, financial records, backups). Copies RDS database snapshots to attacker-controlled account. Downloads Lambda function code containing hardcoded secrets.", defender: "S3 access logging should detect unusual access patterns. Macie should classify and alert on sensitive data access. VPC flow logs should track data transfer volumes.", mitre: "T1530 - Data from Cloud Storage Object", iocs: ["S3 GetObject for sensitive buckets from new principal", "RDS snapshot shared with external account", "Large data transfer out of VPC", "Lambda GetFunction calls"], prevention: ["S3 bucket policies restricting access", "Amazon Macie for data classification", "VPC endpoints for S3", "GuardDuty enabled"], tools: ["AWS CLI", "s3-inspector", "Pacu"], execSteps: ["Downloading S3 bucket 'prod-customer-data'...", "Sharing RDS snapshot with external AWS account...", "Extracting Lambda function source code...", "Found 12 hardcoded API keys in Lambda functions...", "Total exfiltration: 890GB across 3 data stores"] },
    ]
  },
  {
    name: "Watering Hole Attack",
    type: "Strategic Web Compromise",
    difficulty: "Advanced",
    impact: "High",
    realWorld: "NotPetya via MeDoc (2017), CCleaner (2017)",
    phases: [
      { name: "Target Profiling", time: "Weeks", severity: "low", attacker: "Identifies websites frequently visited by target organization employees (industry forums, news sites, vendor portals). Compromises a less-secure website in the target's browsing habits.", defender: "Maintain inventory of commonly accessed third-party websites. Web proxy logging and analysis. DNS monitoring for compromised domains.", mitre: "T1594 - Search Victim-Owned Websites", iocs: ["Reconnaissance of organization browsing patterns", "Probing of industry-specific websites", "Vulnerability scanning of third-party sites"], prevention: ["Web filtering and categorization", "Browser isolation for untrusted sites", "Network segmentation"], tools: ["Proxy logs analysis", "DNS monitoring"], execSteps: ["Analyzing target organization web traffic patterns...", "Identified top 10 frequently visited industry sites...", "Vulnerability scanning industry news portal...", "Found XSS vulnerability in industry forum...", "Selected target: industry trade association website"] },
      { name: "Website Compromise", time: "Hours-Days", severity: "high", attacker: "Exploits vulnerability in the target website (CMS exploit, compromised credentials). Injects malicious JavaScript or iframe that serves a browser exploit kit. Only triggers for visitors from the target organization's IP range.", defender: "Web proxies should inspect downloaded content. Browser should be updated and sandboxed. Content Security Policy should prevent unauthorized script injection.", mitre: "T1189 - Drive-by Compromise", iocs: ["JavaScript injection on trusted website", "New iframe pointing to exploit kit", "Website serving different content based on visitor IP", "Obfuscated JavaScript on legitimate page"], prevention: ["Browser patching", "Browser isolation", "Web proxy with content inspection", "CSP enforcement"], tools: ["BeEF", "Browser Exploitation Framework"], execSteps: ["Exploiting CMS vulnerability on trade association site...", "Injecting obfuscated JavaScript payload...", "Configuring IP-based targeting filter...", "Payload only triggers for target org IP range...", "Watering hole active, awaiting victim visits"] },
      { name: "Exploitation and Implant", time: "Days-Weeks", severity: "critical", attacker: "Browser exploit drops implant on victim workstation. Implant establishes C2 channel. Begins internal reconnaissance and credential theft.", defender: "EDR should detect exploit shellcode execution. Browser sandbox should contain exploitation. Network monitoring should flag new C2 channels.", mitre: "T1189 - Drive-by Compromise, T1059 - Command and Scripting Interpreter", iocs: ["Browser process spawning unexpected child processes", "Shellcode execution in browser context", "New scheduled tasks or services", "C2 beacon traffic"], prevention: ["Browser sandboxing", "Exploit mitigation (EMET/Windows Exploit Guard)", "Network monitoring", "Endpoint detection"], tools: ["CrowdStrike", "Carbon Black", "SentinelOne"], execSteps: ["Target employee visits compromised website...", "Browser exploit triggered (Chrome V8 vulnerability)...", "Implant dropped and executed on workstation...", "C2 channel established over HTTPS...", "Internal reconnaissance and credential theft initiated"] },
    ]
  },
  {
    name: "Zero-Day Exploitation",
    type: "Advanced Attack",
    difficulty: "Expert",
    impact: "Critical",
    realWorld: "Log4Shell (2021), ProxyLogon/ProxyShell (2021), MOVEit (2023)",
    phases: [
      { name: "Vulnerability Discovery", time: "Weeks-Months", severity: "medium", attacker: "Discovers zero-day vulnerability through fuzzing, reverse engineering, or purchasing from exploit broker. Develops reliable exploit with high success rate. Tests against target environment.", defender: "Deploy defense-in-depth so single vulnerability compromise is not catastrophic. Implement application whitelisting and behavioral detection that does not rely on signatures.", mitre: "T1587.004 - Develop Capabilities: Exploits", iocs: ["Cannot be detected via signatures before disclosure", "Unusual application behavior may be only indicator"], prevention: ["Defense in depth", "Application whitelisting", "Behavioral EDR", "Network segmentation", "Micro-segmentation"], tools: ["AFL", "libFuzzer", "WinAFL", "Zerodium (broker)"], execSteps: ["Fuzzing target application for crashes...", "Heap overflow discovered in parser module...", "Developing reliable exploitation primitive...", "Exploit achieves code execution in 95% of tests...", "Zero-day weaponized and ready for deployment"] },
      { name: "Mass Exploitation", time: "Hours-Days", severity: "critical", attacker: "Scans internet for vulnerable instances of the target software. Exploits all discovered instances within hours of beginning the campaign. Deploys web shells or backdoors for persistent access.", defender: "Rapid patching once vendor releases fix. WAF virtual patching as temporary mitigation. Monitor for exploitation indicators shared by threat intel community.", mitre: "T1190 - Exploit Public-Facing Application", iocs: ["Exploitation attempts in web/application logs", "New files in web application directories", "Unexpected outbound connections from servers", "IOCs shared by CISA/vendor advisories"], prevention: ["Rapid patch deployment process", "WAF with virtual patching", "Threat intelligence integration", "Vulnerability scanning"], tools: ["Nuclei", "Shodan", "Censys"], execSteps: ["Scanning Shodan for vulnerable instances...", "Found 24,000 exposed targets worldwide...", "Mass exploitation campaign initiated...", "Web shells deployed on 8,400 systems...", "Backdoor access established across multiple sectors"] },
      { name: "Post-Exploitation", time: "Days-Weeks", severity: "critical", attacker: "Establishes persistence via web shells, scheduled tasks, or modified system configurations. Begins data theft or ransomware deployment depending on attacker motivation. May sell access to other threat actors.", defender: "Assume compromise and hunt for indicators. Deploy IOCs from vendor and community. Conduct forensic analysis of all exposed systems.", mitre: "T1505.003 - Web Shell, T1053 - Scheduled Task/Job", iocs: ["Web shells in application directories", "Unauthorized scheduled tasks", "New user accounts", "Modified system configurations", "Cryptominer deployment"], prevention: ["File integrity monitoring", "Assume-breach mentality", "Forensic readiness", "Incident response plan"], tools: ["YARA", "Thor", "Loki (scanner)", "Velociraptor"], execSteps: ["Installing persistent web shell on target...", "Creating scheduled task for daily callback...", "Deploying cryptominer on low-priority targets...", "Selling access to ransomware affiliate for high-value targets...", "Post-exploitation activities ongoing across 8,400 hosts"] },
    ]
  },
  {
    name: "Active Directory Takeover",
    type: "Enterprise Compromise",
    difficulty: "Advanced",
    impact: "Critical",
    realWorld: "NotPetya (2017), SolarWinds lateral movement (2020)",
    phases: [
      { name: "Initial Foothold", time: "Minutes-Hours", severity: "medium", attacker: "Compromises a single domain-joined workstation via phishing, drive-by, or exploiting a vulnerability. Obtains local admin access on the workstation.", defender: "EDR should detect initial compromise. Network segmentation should limit lateral movement options. LAPS should prevent password reuse.", mitre: "T1078.002 - Valid Accounts: Domain Accounts", iocs: ["Malicious document execution", "Suspicious PowerShell commands", "New local admin account", "Unusual process execution"], prevention: ["EDR deployment", "Email filtering", "Application whitelisting", "LAPS"], tools: ["Cobalt Strike", "Metasploit"], execSteps: ["Phishing email delivered to target employee...", "Malicious document opened, macro executed...", "Cobalt Strike beacon deployed on WKSTN-HR-017...", "Local admin access obtained via UAC bypass...", "Initial foothold established on domain-joined workstation"] },
      { name: "AD Enumeration", time: "Hours", severity: "medium", attacker: "Runs BloodHound/SharpHound to map entire AD environment. Identifies shortest path to Domain Admin. Finds Kerberoastable accounts, AS-REP roastable accounts, and delegation misconfigurations.", defender: "Monitor for LDAP enumeration queries characteristic of BloodHound. Alert on mass SAMR queries. Detect SPN enumeration (Kerberoasting recon).", mitre: "T1087.002 - Account Discovery: Domain Account", iocs: ["BloodHound/SharpHound LDAP queries", "Mass SPN enumeration", "SAMR enumeration from workstation", "Unusual LDAP query volume"], prevention: ["Honeypot accounts and SPNs", "LDAP query monitoring", "Tiered admin model", "Remove unnecessary SPNs"], tools: ["BloodHound", "SharpHound", "ADRecon", "PowerView"], execSteps: ["Running SharpHound data collection...", "Mapping all users, groups, and computers...", "Identified shortest path to Domain Admin (3 hops)...", "Found 14 Kerberoastable service accounts...", "Discovered unconstrained delegation on WEBSRV-02"] },
      { name: "Privilege Escalation", time: "Hours-Days", severity: "critical", attacker: "Kerberoasts service accounts with weak passwords. AS-REP roasts accounts without pre-authentication. Exploits unconstrained delegation to capture TGTs. Abuses ADCS misconfiguration (ESC1) to obtain domain admin certificate.", defender: "Monitor for TGS requests for service accounts (Event ID 4769). Enforce pre-authentication on all accounts. Audit ADCS templates for dangerous configurations.", mitre: "T1558.003 - Kerberoasting, T1649 - Steal or Forge Authentication Certificates", iocs: ["TGS requests with RC4 encryption for SPNs", "AS-REP responses for accounts without pre-auth", "Certificate enrollment from unexpected principals", "TGT delegation to unexpected services"], prevention: ["Strong passwords on service accounts (25+ chars)", "Enforce pre-authentication", "Audit ADCS with Certify/Certipy", "Remove unconstrained delegation"], tools: ["Rubeus", "Certipy", "Impacket GetUserSPNs", "ADCSPwn"], execSteps: ["Kerberoasting 14 service accounts...", "Cracking TGS tickets offline (hashcat)...", "svc_sql password cracked: 'Summer2024!'...", "Exploiting ADCS ESC1 template misconfiguration...", "Domain admin certificate obtained via Certipy"] },
      { name: "Domain Dominance", time: "Hours", severity: "critical", attacker: "With domain admin: performs DCSync to extract all password hashes from NTDS.dit. Creates golden ticket for persistent domain admin access. Modifies AdminSDHolder for long-term persistence. Creates shadow credentials on domain controller.", defender: "Monitor for DCSync (replication) from non-DC sources. Alert on golden ticket usage (TGT with unusual lifetime). Track AdminSDHolder modifications. Audit msDS-KeyCredentialLink changes.", mitre: "T1003.006 - DCSync, T1558.001 - Golden Ticket", iocs: ["Directory replication from non-DC (Event 4662)", "TGT with 10-year lifetime", "AdminSDHolder ACL changes", "Unexpected msDS-KeyCredentialLink values"], prevention: ["Limit replication permissions", "Monitor Event ID 4662", "Regular AdminSDHolder audits", "PAM/tiered admin model", "Credential Guard on DCs"], tools: ["Mimikatz (DCSync)", "ticketer", "Rubeus", "SharpLAPS"], execSteps: ["Performing DCSync attack from compromised workstation...", "Extracting all domain password hashes (NTDS.dit)...", "Creating golden ticket (krbtgt hash obtained)...", "Modifying AdminSDHolder ACL for persistence...", "Full domain dominance achieved with persistent access"] },
    ]
  },
  {
    name: "Cryptojacking Campaign",
    type: "Resource Abuse",
    difficulty: "Beginner",
    impact: "Medium",
    realWorld: "Coinhive (2018), Tesla AWS (2018), Docker Hub Images (2020)",
    phases: [
      { name: "Initial Compromise", time: "Minutes-Hours", severity: "medium", attacker: "Gains access to target infrastructure through exposed Docker API, misconfigured Kubernetes dashboard, stolen cloud credentials, or vulnerable web application. Targets cloud and container environments for high compute resources.", defender: "Secure Docker API endpoints. Require authentication on Kubernetes dashboards. Monitor for unauthorized access to container orchestration. Scan for exposed management interfaces.", mitre: "T1190 - Exploit Public-Facing Application, T1133 - External Remote Services", iocs: ["Unauthenticated access to Docker API (port 2375/2376)", "Kubernetes dashboard accessed from external IP", "Login to cloud console from unusual location", "New container images pulled from unknown registries"], prevention: ["Authenticate all management interfaces", "Network segmentation for container infrastructure", "Cloud security posture management", "Restrict egress traffic from containers"], tools: ["Shodan", "Masscan", "Peirates", "kubeletctl"], execSteps: ["Scanning for exposed Docker API endpoints...", "Found unauthenticated Docker API on target host...", "Testing API access with container listing...", "Full Docker API access confirmed (no auth)...", "Target host has 64 CPU cores available for mining"] },
      { name: "Payload Deployment", time: "Minutes", severity: "medium", attacker: "Deploys cryptocurrency mining software (XMRig for Monero) within containers or directly on hosts. Configures mining pool connection with attacker's wallet. Sets CPU/GPU usage limits to avoid obvious detection (typically 60-80% utilization).", defender: "Container image scanning should detect known miners. Runtime monitoring should flag unexpected processes. Track CPU utilization baselines per workload.", mitre: "T1496 - Resource Hijacking", iocs: ["Known mining binary hashes (XMRig, ccminer)", "Connections to mining pool domains/IPs", "Stratum protocol traffic on port 3333/45700", "Sudden CPU utilization increase across hosts"], prevention: ["Container image scanning and admission control", "Runtime process monitoring (Falco, Sysdig)", "Egress filtering to block mining pools", "CPU usage alerting"], tools: ["XMRig", "ccminer", "Docker containers", "Mining pool proxies"], execSteps: ["Pulling custom Docker image with embedded XMRig...", "Deploying mining container with resource limits...", "Configuring Monero mining pool connection...", "Setting CPU throttle to 70% to reduce detection...", "Mining operation initiated on 64 cores"] },
      { name: "Resource Hijacking", time: "Days-Weeks", severity: "medium", attacker: "Mining software consumes CPU/GPU resources generating cryptocurrency. Attacker monitors hashrate and earnings through mining pool dashboard. May scale horizontally by compromising additional hosts or spinning up new cloud instances.", defender: "Cost monitoring should flag unexpected compute bills. Cloud billing alerts at usage thresholds. Monitor for new instance launches in unusual regions.", mitre: "T1496 - Resource Hijacking", iocs: ["Elevated CPU usage on servers/containers", "Increased cloud compute billing (300-500% spike)", "New instances launched in all available regions", "Constant high network throughput to mining pools"], prevention: ["Cloud billing alerts and budgets", "Resource quotas per project/namespace", "Regular cost audits", "Instance launch monitoring"], tools: ["Cloud billing dashboards", "Prometheus/Grafana", "Cost management tools"], execSteps: ["Mining hashrate: 45 KH/s across target infrastructure...", "Earnings: approximately $180/day in Monero...", "Launching additional instances in eu-west-1...", "Total compute hijacked: 256 vCPUs across 8 instances...", "Monthly cloud bill increased by $12,000 (victim pays)"] },
      { name: "Persistence", time: "Hours", severity: "high", attacker: "Installs multiple persistence mechanisms: cron jobs, systemd services, modified Docker images, Kubernetes DaemonSets. Deploys rootkit to hide mining processes from standard monitoring tools. Creates backup access credentials.", defender: "File integrity monitoring should detect new services. Kubernetes audit logs should flag DaemonSet creation. Rootkit detection tools should scan for hidden processes.", mitre: "T1053.003 - Cron, T1543.002 - Systemd Service, T1014 - Rootkit", iocs: ["New cron jobs running mining binaries", "Unknown systemd services with mining process", "DaemonSets deployed across all nodes", "Process hiding via LD_PRELOAD rootkit"], prevention: ["Immutable container infrastructure", "Kubernetes RBAC and admission policies", "File integrity monitoring", "Host-based intrusion detection"], tools: ["Cron", "systemd", "Kubernetes DaemonSets", "LD_PRELOAD rootkits"], execSteps: ["Installing cron job for miner restart on reboot...", "Creating systemd service 'kube-proxy-helper'...", "Deploying Kubernetes DaemonSet for cluster-wide mining...", "Installing LD_PRELOAD rootkit to hide processes...", "Persistence mechanisms operational on all nodes"] },
      { name: "Detection Evasion", time: "Ongoing", severity: "medium", attacker: "Renames mining binary to mimic legitimate processes (kworker, kube-proxy). Limits CPU usage during business hours and increases at night. Uses mining proxy to disguise pool traffic as HTTPS. Modifies log files to remove evidence.", defender: "Behavioral analytics should detect unusual process patterns. Network traffic analysis should identify mining protocol signatures. Compare process lists with known-good baselines.", mitre: "T1036 - Masquerading, T1070 - Indicator Removal", iocs: ["Processes named to mimic system services", "CPU usage patterns correlating with off-hours", "Encrypted traffic to unusual destinations on port 443", "Modified or truncated log files"], prevention: ["Process allow-listing", "Network traffic deep packet inspection", "Log forwarding to immutable storage", "24/7 SOC monitoring"], tools: ["Process monitors", "Network DPI", "Log analysis (Splunk, ELK)", "eBPF-based monitoring"], execSteps: ["Renaming XMRig binary to 'kube-proxy-cache'...", "Configuring CPU schedule: 40% daytime, 90% nighttime...", "Routing mining traffic through HTTPS proxy...", "Truncating /var/log entries related to mining activity...", "Evasion measures active, mining undetected for 3 weeks"] },
    ]
  },
  {
    name: "IoT Botnet Attack",
    type: "IoT Compromise",
    difficulty: "Intermediate",
    impact: "High",
    realWorld: "Mirai (2016), Mozi (2019), BotenaGo (2021)",
    phases: [
      { name: "Scanning", time: "Hours-Days", severity: "low", attacker: "Performs internet-wide scanning on common IoT ports: Telnet (23), SSH (22), HTTP (80/8080), UPnP (5000), MQTT (1883). Uses tools like Masscan and ZMap for high-speed scanning. Identifies device types from banners and HTTP responses.", defender: "ISPs should detect and rate-limit scanning traffic. Firewalls should block inbound connections to IoT management ports. Monitor for scanning activity targeting your network.", mitre: "T1595 - Active Scanning, T1046 - Network Service Discovery", iocs: ["Mass port scanning from single or distributed sources", "Telnet and SSH connection attempts on non-standard ports", "UPnP discovery packets from external sources", "MQTT connection attempts without authentication"], prevention: ["Block IoT management ports at network perimeter", "IoT device inventory and asset management", "Network monitoring for scan activity", "ISP-level scanning detection"], tools: ["Masscan", "ZMap", "Nmap", "Shodan"], execSteps: ["Initiating Masscan sweep on Telnet port 23...", "Scanning rate: 10 million packets per second...", "Found 3.2 million devices with open Telnet...", "Banner grabbing to identify device types...", "Catalogued 890K cameras, 1.4M routers, 920K DVRs"] },
      { name: "Default Credential Exploitation", time: "Hours", severity: "high", attacker: "Attempts login with known default credentials for each device type (admin/admin, root/root, admin/password). Many IoT devices ship with hardcoded credentials that cannot be changed. Success rate typically 5-15% of scanned devices.", defender: "Change default credentials on all IoT devices before deployment. Disable Telnet and use SSH with key-based auth. Implement network access control for IoT devices.", mitre: "T1078.001 - Valid Accounts: Default Accounts, T1110 - Brute Force", iocs: ["Multiple failed login attempts on IoT devices", "Successful logins with known default credentials", "Rapid authentication attempts from single source", "Telnet sessions from external IP addresses"], prevention: ["Change all default credentials", "Disable Telnet, enforce SSH with key auth", "Network access control for IoT VLANs", "Vendor security assessment before purchase"], tools: ["Hydra", "Medusa", "Custom credential spraying scripts", "Default credential databases"], execSteps: ["Loading default credential database (127 vendor defaults)...", "Testing credentials on 3.2 million Telnet endpoints...", "Success rate: 8.4% (268,800 devices compromised)...", "Device breakdown: 112K cameras, 89K routers, 67K DVRs...", "Credential exploitation complete, preparing enrollment"] },
      { name: "Botnet Enrollment", time: "Minutes-Hours", severity: "high", attacker: "Deploys lightweight botnet agent to compromised devices. Agent is compiled for multiple architectures (ARM, MIPS, x86). Disables competing malware and closes management ports to prevent re-compromise by other botnets.", defender: "Monitor for unusual outbound connections from IoT devices. Detect firmware modifications and unauthorized binary execution. Network segmentation to isolate IoT devices.", mitre: "T1583.005 - Acquire Infrastructure: Botnet, T1059 - Command and Scripting Interpreter", iocs: ["Download of unknown binaries to IoT devices", "Outbound connections to known botnet C2 addresses", "Telnet/SSH ports closed after initial compromise", "Competing malware processes killed on device"], prevention: ["Firmware integrity verification", "Network segmentation for IoT", "Outbound traffic monitoring for IoT VLANs", "Regular firmware updates"], tools: ["Custom botnet agents", "Cross-compilers (ARM, MIPS)", "Dropper scripts"], execSteps: ["Deploying botnet agent (ARM variant) to cameras...", "Deploying botnet agent (MIPS variant) to routers...", "Killing competing malware processes on devices...", "Closing Telnet port to prevent re-compromise...", "Botnet enrollment complete: 268,800 active bots"] },
      { name: "Command and Control", time: "Ongoing", severity: "medium", attacker: "Establishes distributed C2 infrastructure using multiple servers across jurisdictions. Uses domain generation algorithms (DGA) for resilient C2 resolution. Implements peer-to-peer fallback if centralized C2 is taken down.", defender: "DNS monitoring should detect DGA domains. Network monitoring for known botnet C2 patterns. Coordinate with ISPs and CERTs for botnet disruption.", mitre: "T1568.002 - Dynamic Resolution: Domain Generation Algorithms, T1573 - Encrypted Channel", iocs: ["DNS queries to algorithmically generated domains", "Periodic beaconing to C2 servers", "P2P communication between IoT devices", "Encrypted C2 traffic on non-standard ports"], prevention: ["DNS filtering and sinkholing", "Botnet C2 blocklists", "ISP cooperation for takedown", "IoT traffic baseline monitoring"], tools: ["DGA generators", "P2P protocols", "Bulletproof hosting", "Fast-flux DNS"], execSteps: ["C2 infrastructure deployed across 5 countries...", "DGA generating 1,000 domains per day for resilience...", "P2P fallback mesh network configured...", "268,800 bots checking in every 60 seconds...", "Botnet fully operational and awaiting attack commands"] },
      { name: "Attack Deployment", time: "Minutes-Hours", severity: "critical", attacker: "Launches coordinated DDoS attack using full botnet capacity. Attack types include TCP SYN floods, UDP amplification, HTTP floods, and DNS water torture. Can generate 1-3 Tbps of attack traffic. Targets selected based on highest-bidding customer (DDoS-for-hire) or operator motivation.", defender: "Targets should activate DDoS mitigation services. Upstream ISPs should implement BCP38 (anti-spoofing). Law enforcement coordination for botnet takedown. CERT notifications to affected networks.", mitre: "T1498 - Network Denial of Service, T1499 - Endpoint Denial of Service", iocs: ["Massive traffic spike from distributed IoT sources", "SYN flood with spoofed source addresses", "DNS amplification responses overwhelming target", "Multiple attack vectors simultaneously"], prevention: ["DDoS mitigation services", "BCP38 anti-spoofing at ISP level", "Anycast infrastructure", "Rate limiting and traffic scrubbing"], tools: ["Botnet C2 interface", "Attack modules (SYN, UDP, HTTP, DNS)", "DDoS-for-hire platforms"], execSteps: ["Attack command issued to 268,800 bots...", "Launching SYN flood: 800 Gbps...", "Adding UDP amplification: total 1.6 Tbps...", "HTTP flood layer: 15 million requests per second...", "Target infrastructure completely overwhelmed"] },
    ]
  },
  {
    name: "Business Email Compromise",
    type: "Financial Fraud",
    difficulty: "Intermediate",
    impact: "Critical",
    realWorld: "Ubiquiti ($46.7M, 2015), Toyota ($37M, 2019), Nikkei ($29M, 2019)",
    phases: [
      { name: "Reconnaissance", time: "Days-Weeks", severity: "low", attacker: "Researches target organization structure, financial processes, and key personnel. Identifies CEO, CFO, finance team, and regular vendors/suppliers. Studies communication patterns, invoice formats, and payment schedules through publicly available information and social engineering.", defender: "Limit public exposure of organizational hierarchy. Train finance team to recognize BEC indicators. Establish out-of-band verification for financial requests.", mitre: "T1589 - Gather Victim Identity Information, T1591 - Gather Victim Org Information", iocs: ["LinkedIn research on finance team members", "Probing of company email conventions", "Vendor relationship research via public filings", "Test emails to verify email address formats"], prevention: ["Minimize public org chart information", "BEC-specific awareness training for finance", "Establish verification procedures for payments", "Monitor for organizational reconnaissance"], tools: ["LinkedIn", "Hunter.io", "SEC EDGAR filings", "Google dorking"], execSteps: ["Mapping organizational hierarchy via LinkedIn...", "Identified CFO, Controller, and 3 AP staff...", "Studying vendor relationships from press releases...", "Email format confirmed: first.last@company.com...", "Payment schedule identified: NET-30, wire transfers"] },
      { name: "Account Compromise", time: "Hours-Days", severity: "high", attacker: "Compromises the email account of a senior executive or trusted vendor through credential phishing, password spraying, or purchasing credentials from access brokers. Alternatively, registers a lookalike domain for email spoofing if direct compromise fails.", defender: "Enforce MFA on all email accounts (FIDO2 preferred). Monitor for impossible travel alerts. Implement conditional access policies. Check for email forwarding rules.", mitre: "T1078 - Valid Accounts, T1114.002 - Remote Email Collection", iocs: ["Login from unusual location or device", "Impossible travel alerts", "New inbox forwarding rules created", "Mail access from non-corporate IP", "OAuth application grants"], prevention: ["MFA on all email accounts (phishing-resistant preferred)", "Conditional access policies", "Monitor for inbox rule changes", "Email access logging and alerting"], tools: ["Evilginx2", "Modlishka", "Password spraying tools", "OAuth phishing"], execSteps: ["Launching AiTM phishing targeting CFO email...", "Phishing page proxying Microsoft 365 login...", "CFO credentials and session token captured...", "Logging into CFO mailbox from attacker infrastructure...", "Setting hidden forwarding rule to monitor all emails"] },
      { name: "Monitoring and Planning", time: "Days-Weeks", severity: "medium", attacker: "Silently monitors email communications for weeks. Studies invoice formats, payment processes, approval chains, and communication styles. Identifies a pending large transaction or vendor payment that can be intercepted. Creates convincing email templates matching the writing style of the compromised executive.", defender: "Monitor for email forwarding rules and delegate access. Track mailbox access from unusual locations. Implement alerts for suspicious email patterns.", mitre: "T1114 - Email Collection, T1589.003 - Gather Victim Identity Information: Employee Names", iocs: ["Email forwarding rules to external addresses", "Mailbox accessed from multiple geolocations simultaneously", "Unusual email search queries (invoice, payment, wire)", "Extended session durations from external IPs"], prevention: ["Regular audit of email forwarding rules", "Impossible travel detection", "Mailbox access monitoring", "DLP for sensitive financial terms"], tools: ["Microsoft 365 Admin Center", "Email forwarding monitoring", "CASB solutions"], execSteps: ["Monitoring CFO email for 12 days...", "Identified pending $4.2M vendor payment...", "Studying invoice format and approval workflow...", "Copying writing style of CFO communications...", "Creating fraudulent invoice with modified bank details"] },
      { name: "Fraudulent Transaction", time: "Hours", severity: "critical", attacker: "Sends fraudulent email from compromised account (or spoofed domain) to accounts payable instructing a wire transfer to attacker-controlled bank account. Email references real invoice and ongoing project. Emphasizes urgency and confidentiality to prevent verification.", defender: "Require multi-person approval for large wire transfers. Implement callback verification to known phone numbers for payment changes. Train AP staff to verify all bank detail changes.", mitre: "T1657 - Financial Theft, T1534 - Internal Spearphishing", iocs: ["Wire transfer request with new bank details", "Urgency language in financial requests", "Bank account in different country than usual vendor", "Request to bypass normal approval process"], prevention: ["Dual authorization for wire transfers over threshold", "Callback verification for bank detail changes", "Separation of duties in payment process", "Wire transfer confirmation delays"], tools: ["Compromised email account", "Lookalike domain", "Forged invoices"], execSteps: ["Sending fraudulent payment instruction from CFO account...", "Email references real project and invoice number...", "Modified bank details point to shell company account...", "AP staff processes wire transfer for $4.2M...", "Funds transferred to attacker-controlled account"] },
      { name: "Cover-up", time: "Hours-Days", severity: "high", attacker: "Deletes sent emails and relevant correspondence to hide the fraud. Removes email forwarding rules. Moves stolen funds through multiple accounts across jurisdictions within hours. Converts to cryptocurrency or withdraws before banks can freeze accounts.", defender: "Bank fraud alerts should flag unusual transactions. Finance team should verify all completed payments. Implement payment reconciliation processes. Coordinate with law enforcement immediately.", mitre: "T1070.008 - Clear Mailbox Data, T1036 - Masquerading", iocs: ["Deleted email items in compromised mailbox", "Forwarding rules removed after fraud", "Rapid movement of funds through multiple banks", "Cryptocurrency purchases from shell accounts"], prevention: ["Payment reconciliation within 24 hours", "Bank relationship with fraud alert capabilities", "Law enforcement coordination plan", "Cyber insurance for financial losses"], tools: ["Email deletion tools", "Money mule networks", "Cryptocurrency exchanges", "Shell company bank accounts"], execSteps: ["Deleting sent email and forwarding rules...", "Funds arriving at shell company account...", "Splitting $4.2M across 6 intermediary accounts...", "Converting $2.8M to cryptocurrency within 4 hours...", "Remaining funds withdrawn via ATM network globally"] },
    ]
  },
];

var KILL_CHAIN = [
  { id: "recon", name: "Reconnaissance", desc: "Gathering information about the target" },
  { id: "weapon", name: "Weaponization", desc: "Creating the attack payload" },
  { id: "delivery", name: "Delivery", desc: "Transmitting the payload to the target" },
  { id: "exploit", name: "Exploitation", desc: "Triggering the vulnerability" },
  { id: "install", name: "Installation", desc: "Installing malware or backdoor" },
  { id: "c2", name: "Command & Control", desc: "Establishing remote control channel" },
  { id: "action", name: "Actions on Objectives", desc: "Achieving the attacker's goal" },
];

var DEFENSE_CATEGORIES = {
  "Network": ["Network segmentation", "DDoS mitigation", "Rate limiting", "DNS filtering", "Firewall rules", "VPN", "Anycast", "Traffic scrubbing", "Web proxy", "Egress filtering", "Network monitoring", "IDS/IPS"],
  "Endpoint": ["EDR", "Application whitelisting", "AMSI", "Credential Guard", "LAPS", "Antivirus", "File integrity monitoring", "Host-based IDS", "Patch management", "Container scanning"],
  "Identity": ["MFA", "Least privilege", "PAM", "Conditional access", "FIDO2", "SSO", "Access reviews", "Tiered admin model", "RBAC", "Service account management"],
  "Data": ["DLP", "Encryption", "CASB", "Data classification", "Backup", "Tokenization", "Database activity monitoring", "Log management"]
};

var SEVERITY_COLORS = {
  "low": "#22c55e",
  "medium": "#f59e0b",
  "high": "#f97316",
  "critical": "#ef4444"
};

var DIFFICULTY_COLORS = {
  "Beginner": "#22c55e",
  "Intermediate": "#f59e0b",
  "Advanced": "#f97316",
  "Expert": "#ef4444"
};

function renderScenarioList(main) {
  var html = '<h1 class="pg-h1">Attack Simulator</h1>' +
    '<p class="muted pg-sub">Interactive cyber attack simulations with ' + SCENARIOS.length + ' scenarios. Step through real-world attack chains from both attacker and defender perspectives.</p>';

  var stats = { total: SCENARIOS.length, phases: 0, techniques: 0 };
  for (var s = 0; s < SCENARIOS.length; s++) {
    stats.phases += SCENARIOS[s].phases.length;
    for (var p = 0; p < SCENARIOS[s].phases.length; p++) {
      if (SCENARIOS[s].phases[p].mitre && SCENARIOS[s].phases[p].mitre !== "N/A - Pre-attack phase") stats.techniques++;
    }
  }

  html += '<div class="as-stats-row">' +
    '<div class="as-stat-box"><div class="as-stat-val">' + stats.total + '</div><div class="as-stat-lbl">Scenarios</div></div>' +
    '<div class="as-stat-box"><div class="as-stat-val">' + stats.phases + '</div><div class="as-stat-lbl">Attack Phases</div></div>' +
    '<div class="as-stat-box"><div class="as-stat-val">' + stats.techniques + '</div><div class="as-stat-lbl">MITRE Techniques</div></div>' +
  '</div>';

  html += '<div class="as-grid">';
  for (var i = 0; i < SCENARIOS.length; i++) {
    var sc = SCENARIOS[i];
    var diffColor = DIFFICULTY_COLORS[sc.difficulty] || "#94a3b8";
    html += '<div class="as-card" data-idx="' + i + '">' +
      '<div class="as-card-type">' + esc(sc.type) + '</div>' +
      '<div class="as-card-name">' + esc(sc.name) + '</div>' +
      '<div class="as-card-meta-row">' +
        '<span class="as-card-phases">' + sc.phases.length + ' phases</span>' +
        '<span class="as-difficulty-badge" style="color:' + diffColor + ';border-color:' + diffColor + '44">' + esc(sc.difficulty) + '</span>' +
        '<span class="as-impact-badge">' + esc(sc.impact) + ' Impact</span>' +
      '</div>' +
      '<div class="as-card-rw">Real-world: ' + esc(sc.realWorld) + '</div>' +
    '</div>';
  }
  html += '</div>';
  main.innerHTML = html;

  main.querySelectorAll('.as-card').forEach(function(card) {
    card.onclick = function() { renderScenarioDetail(main, parseInt(card.dataset.idx)); };
  });
}

function renderScenarioDetail(main, idx) {
  var s = SCENARIOS[idx];
  if (!s) return;
  var viewMode = "attacker";
  var currentPhase = 0;
  var executedPhases = {};
  var executingPhase = -1;
  var showDefenseReport = false;

  function render() {
    if (showDefenseReport) { renderDefenseReport(); return; }
    var phase = s.phases[currentPhase];
    var sevColor = SEVERITY_COLORS[phase.severity] || "#94a3b8";
    var html = '<div style="margin-bottom:12px;display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
      '<button class="btn sm" id="as-back">Back to Scenarios</button>' +
      '<span style="font-size:1rem;font-weight:600">' + esc(s.name) + '</span>' +
      '<span style="font-size:.75rem;color:var(--mut)">' + esc(s.type) + '</span>' +
      '<span class="as-difficulty-badge" style="font-size:.65rem;color:' + (DIFFICULTY_COLORS[s.difficulty] || '#94a3b8') + ';border-color:' + (DIFFICULTY_COLORS[s.difficulty] || '#94a3b8') + '44">' + esc(s.difficulty) + '</span>' +
    '</div>';

    html += '<div class="as-timeline">';
    for (var i = 0; i < s.phases.length; i++) {
      var active = i === currentPhase ? ' as-phase-active' : '';
      var done = i < currentPhase ? ' as-phase-done' : '';
      var executed = executedPhases[i] ? ' as-phase-executed' : '';
      var phaseSevColor = SEVERITY_COLORS[s.phases[i].severity] || "#94a3b8";
      html += '<div class="as-phase-dot' + active + done + executed + '" data-phase="' + i + '">' +
        '<div class="as-phase-num" style="' + (i === currentPhase ? 'border-color:' + phaseSevColor + ';background:' + phaseSevColor : '') + '">' + (executedPhases[i] ? 'OK' : (i + 1)) + '</div>' +
        '<div class="as-phase-label">' + esc(s.phases[i].name) + '</div>' +
        '<div class="as-phase-time">' + esc(s.phases[i].time || '') + '</div>' +
      '</div>';
      if (i < s.phases.length - 1) html += '<div class="as-phase-line' + done + '"></div>';
    }
    html += '</div>';

    html += '<div class="as-view-toggle">' +
      '<button class="btn sm' + (viewMode === "attacker" ? "" : " ghost") + '" id="as-atk-view">Attacker View</button>' +
      '<button class="btn sm' + (viewMode === "defender" ? "" : " ghost") + '" id="as-def-view">Defender View</button>' +
      '<span style="flex:1"></span>' +
      '<button class="btn sm ghost" id="as-defense-report">Defense Report</button>' +
    '</div>';

    html += '<div class="as-detail">' +
      '<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;flex-wrap:wrap">' +
        '<h2 style="margin:0">Phase ' + (currentPhase + 1) + ': ' + esc(phase.name) + '</h2>' +
        '<span class="as-severity-badge" style="background:' + sevColor + '22;color:' + sevColor + ';border:1px solid ' + sevColor + '44">' + esc(phase.severity) + '</span>' +
        (phase.time ? '<span class="muted" style="font-size:.75rem">Est. time: ' + esc(phase.time) + '</span>' : '') +
      '</div>';

    if (viewMode === "attacker") {
      html += '<div class="as-section"><div class="as-section-title">Attacker Actions</div>' +
        '<div class="as-section-body">' + esc(phase.attacker) + '</div></div>';
      html += '<div class="as-section"><div class="as-section-title">Tools Used</div>' +
        '<div class="as-tags">';
      for (var t = 0; t < phase.tools.length; t++) {
        html += '<span class="as-tag">' + esc(phase.tools[t]) + '</span>';
      }
      html += '</div></div>';
      html += '<div class="as-section"><div class="as-section-title">MITRE ATT&CK</div>' +
        '<div class="as-mitre">' + esc(phase.mitre) + '</div></div>';
      html += '<div class="as-section"><div class="as-section-title">Indicators of Compromise</div><ul class="as-ioc-list">';
      for (var io = 0; io < phase.iocs.length; io++) {
        html += '<li>' + esc(phase.iocs[io]) + '</li>';
      }
      html += '</ul></div>';
    } else {
      html += '<div class="as-section as-def"><div class="as-section-title">Defender Response</div>' +
        '<div class="as-section-body">' + esc(phase.defender) + '</div></div>';
      html += '<div class="as-section as-def"><div class="as-section-title">Detection Opportunities</div><ul class="as-ioc-list">';
      for (var d = 0; d < phase.iocs.length; d++) {
        html += '<li>' + esc(phase.iocs[d]) + '</li>';
      }
      html += '</ul></div>';
      html += '<div class="as-section as-def"><div class="as-section-title">Prevention Measures</div><ul class="as-ioc-list">';
      for (var p = 0; p < phase.prevention.length; p++) {
        html += '<li>' + esc(phase.prevention[p]) + '</li>';
      }
      html += '</ul></div>';
    }

    if (!executedPhases[currentPhase] && executingPhase !== currentPhase) {
      html += '<div style="margin-top:12px"><button class="btn sm" id="as-execute">Execute Phase</button></div>';
    }
    html += '<div id="as-exec-log"></div>';
    html += '</div>';

    if (executedPhases[currentPhase]) {
      html += '<div class="as-exec-summary">' +
        '<div class="as-exec-summary-title">Phase Execution Summary</div>' +
        '<div class="as-exec-kv"><span>Technique:</span><span>' + esc(phase.mitre) + '</span></div>' +
        '<div class="as-exec-kv"><span>Tools:</span><span>' + phase.tools.map(function(tool) { return esc(tool); }).join(', ') + '</span></div>' +
        '<div class="as-exec-kv"><span>Detection Methods:</span><span>' + phase.iocs.slice(0, 2).map(function(ioc) { return esc(ioc); }).join('; ') + '</span></div>' +
        '<div class="as-exec-kv"><span>Mitigations:</span><span>' + phase.prevention.slice(0, 2).map(function(prev) { return esc(prev); }).join('; ') + '</span></div>' +
        '<div class="as-exec-kv"><span>Status:</span><span style="color:#22c55e;font-weight:600">Executed</span></div>' +
      '</div>';
    }

    html += '<div class="as-nav">';
    if (currentPhase > 0) html += '<button class="btn sm ghost" id="as-prev">Previous Phase</button>';
    html += '<span style="flex:1"></span>';
    if (currentPhase < s.phases.length - 1) html += '<button class="btn sm" id="as-next">Next Phase</button>';
    html += '</div>';

    html += '<div class="as-exercise">' +
      '<h3>Tabletop Exercise Questions</h3>' +
      '<ol class="as-exercise-list">' +
        '<li>What detection capabilities does your organization have for this phase?</li>' +
        '<li>How quickly could your SOC identify the indicators listed above?</li>' +
        '<li>What is your response procedure if this activity is detected?</li>' +
        '<li>Who needs to be notified, and what is the escalation path?</li>' +
        '<li>Are the prevention measures listed above implemented in your environment?</li>' +
      '</ol>' +
    '</div>';

    main.innerHTML = STYLE + html;

    main.querySelector('#as-back').onclick = function() { renderScenarioList(main); };
    var atkBtn = main.querySelector('#as-atk-view');
    var defBtn = main.querySelector('#as-def-view');
    if (atkBtn) atkBtn.onclick = function() { viewMode = "attacker"; render(); };
    if (defBtn) defBtn.onclick = function() { viewMode = "defender"; render(); };
    var prevBtn = main.querySelector('#as-prev');
    var nextBtn = main.querySelector('#as-next');
    if (prevBtn) prevBtn.onclick = function() { currentPhase--; render(); };
    if (nextBtn) nextBtn.onclick = function() { currentPhase++; render(); };
    var defReportBtn = main.querySelector('#as-defense-report');
    if (defReportBtn) defReportBtn.onclick = function() { showDefenseReport = true; render(); };
    main.querySelectorAll('.as-phase-dot').forEach(function(dot) {
      dot.onclick = function() { currentPhase = parseInt(dot.dataset.phase); render(); };
    });

    var execBtn = main.querySelector('#as-execute');
    if (execBtn) {
      execBtn.onclick = function() {
        executePhase(currentPhase);
      };
    }
  }

  function executePhase(phaseIdx) {
    executingPhase = phaseIdx;
    var phase = s.phases[phaseIdx];
    var steps = phase.execSteps || [];
    if (steps.length === 0) {
      executedPhases[phaseIdx] = true;
      executingPhase = -1;
      render();
      return;
    }
    var execBtn = main.querySelector('#as-execute');
    if (execBtn) execBtn.style.display = 'none';
    var logDiv = main.querySelector('#as-exec-log');
    if (!logDiv) return;
    logDiv.innerHTML = '<div class="as-exec-log-box"><div class="as-exec-log-header">Executing: ' + esc(phase.name) + '</div><div id="as-exec-lines"></div></div>';
    var linesDiv = main.querySelector('#as-exec-lines');
    var stepIdx = 0;
    function showStep() {
      if (stepIdx >= steps.length) {
        var doneDiv = document.createElement('div');
        doneDiv.className = 'as-exec-line as-exec-done';
        doneDiv.textContent = '[COMPLETE] Phase ' + (phaseIdx + 1) + ' execution finished.';
        linesDiv.appendChild(doneDiv);
        executedPhases[phaseIdx] = true;
        executingPhase = -1;
        setTimeout(function() { render(); }, 800);
        return;
      }
      var lineDiv = document.createElement('div');
      lineDiv.className = 'as-exec-line';
      lineDiv.textContent = '[' + (stepIdx + 1) + '/' + steps.length + '] ' + steps[stepIdx];
      linesDiv.appendChild(lineDiv);
      linesDiv.scrollTop = linesDiv.scrollHeight;
      stepIdx++;
      setTimeout(showStep, 600);
    }
    showStep();
  }

  function renderDefenseReport() {
    var allPrevention = {};
    var allMitre = [];
    for (var i = 0; i < s.phases.length; i++) {
      var ph = s.phases[i];
      if (ph.mitre && ph.mitre !== "N/A - Pre-attack phase") {
        var techniques = ph.mitre.split(', ');
        for (var mt = 0; mt < techniques.length; mt++) {
          var found = false;
          for (var ex = 0; ex < allMitre.length; ex++) {
            if (allMitre[ex] === techniques[mt]) { found = true; break; }
          }
          if (!found) allMitre.push(techniques[mt]);
        }
      }
      for (var pp = 0; pp < ph.prevention.length; pp++) {
        var prev = ph.prevention[pp];
        var categorized = false;
        for (var cat in DEFENSE_CATEGORIES) {
          if (!DEFENSE_CATEGORIES.hasOwnProperty(cat)) continue;
          var keywords = DEFENSE_CATEGORIES[cat];
          for (var kw = 0; kw < keywords.length; kw++) {
            if (prev.toLowerCase().indexOf(keywords[kw].toLowerCase()) !== -1) {
              if (!allPrevention[cat]) allPrevention[cat] = [];
              var dupFound = false;
              for (var dp = 0; dp < allPrevention[cat].length; dp++) {
                if (allPrevention[cat][dp] === prev) { dupFound = true; break; }
              }
              if (!dupFound) allPrevention[cat].push(prev);
              categorized = true;
              break;
            }
          }
          if (categorized) break;
        }
        if (!categorized) {
          if (!allPrevention["General"]) allPrevention["General"] = [];
          var gDup = false;
          for (var gd = 0; gd < allPrevention["General"].length; gd++) {
            if (allPrevention["General"][gd] === prev) { gDup = true; break; }
          }
          if (!gDup) allPrevention["General"].push(prev);
        }
      }
    }

    var html = '<div style="margin-bottom:12px;display:flex;align-items:center;gap:8px">' +
      '<button class="btn sm" id="as-report-back">Back to Simulation</button>' +
      '<span style="font-size:1rem;font-weight:600">Defense Report: ' + esc(s.name) + '</span>' +
    '</div>';

    html += '<div class="as-report-section">' +
      '<h3 class="as-report-title">MITRE ATT&CK Coverage (' + allMitre.length + ' techniques)</h3>' +
      '<div class="as-mitre-grid">';
    for (var m = 0; m < allMitre.length; m++) {
      html += '<div class="as-mitre-item">' + esc(allMitre[m]) + '</div>';
    }
    html += '</div></div>';

    html += '<div class="as-report-section"><h3 class="as-report-title">Defense Recommendations by Category</h3>';
    for (var category in allPrevention) {
      if (!allPrevention.hasOwnProperty(category)) continue;
      var items = allPrevention[category];
      html += '<div class="as-defense-cat">' +
        '<div class="as-defense-cat-name">' + esc(category) + ' (' + items.length + ')</div>' +
        '<ul class="as-defense-list">';
      for (var di = 0; di < items.length; di++) {
        html += '<li>' + esc(items[di]) + '</li>';
      }
      html += '</ul></div>';
    }
    html += '</div>';

    html += '<div class="as-report-section">' +
      '<h3 class="as-report-title">Execution Status</h3>' +
      '<div class="as-exec-status-grid">';
    for (var ei = 0; ei < s.phases.length; ei++) {
      var eSevColor = SEVERITY_COLORS[s.phases[ei].severity] || "#94a3b8";
      html += '<div class="as-exec-status-item">' +
        '<span class="as-exec-status-dot" style="background:' + (executedPhases[ei] ? '#22c55e' : 'var(--line)') + '"></span>' +
        '<span>' + esc(s.phases[ei].name) + '</span>' +
        '<span class="as-severity-badge" style="background:' + eSevColor + '22;color:' + eSevColor + ';border:1px solid ' + eSevColor + '44;font-size:.6rem">' + esc(s.phases[ei].severity) + '</span>' +
        '<span class="muted" style="font-size:.72rem">' + (executedPhases[ei] ? 'Executed' : 'Pending') + '</span>' +
      '</div>';
    }
    html += '</div></div>';

    main.innerHTML = STYLE + html;
    main.querySelector('#as-report-back').onclick = function() { showDefenseReport = false; render(); };
  }

  render();
}

var STYLE = '<style>' +
  '.as-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px;margin-top:16px}' +
  '.as-card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px;cursor:pointer;transition:border-color .15s}' +
  '.as-card:hover{border-color:var(--acc)}' +
  '.as-card-type{font-size:.68rem;text-transform:uppercase;letter-spacing:.05em;color:var(--acc);font-weight:600;margin-bottom:4px}' +
  '.as-card-name{font-size:1rem;font-weight:600;margin-bottom:6px}' +
  '.as-card-phases{font-size:.78rem;color:var(--mut);margin-bottom:4px}' +
  '.as-card-rw{font-size:.72rem;color:var(--mut);font-style:italic;margin-top:6px}' +
  '.as-card-meta-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:2px}' +
  '.as-difficulty-badge{font-size:.68rem;font-weight:600;padding:1px 8px;border:1px solid;border-radius:4px}' +
  '.as-impact-badge{font-size:.68rem;font-weight:600;padding:1px 8px;border-radius:4px;background:#ef444422;color:#ef4444;border:1px solid #ef444444}' +
  '.as-stats-row{display:flex;gap:10px;margin:16px 0;flex-wrap:wrap}' +
  '.as-stat-box{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 20px;min-width:120px;flex:1;text-align:center}' +
  '.as-stat-val{font-size:1.6rem;font-weight:800;color:var(--acc)}' +
  '.as-stat-lbl{font-size:.72rem;color:var(--mut)}' +
  '.as-timeline{display:flex;align-items:flex-start;gap:0;margin:16px 0;overflow-x:auto;padding-bottom:8px}' +
  '.as-phase-dot{text-align:center;cursor:pointer;min-width:80px;position:relative}' +
  '.as-phase-num{width:28px;height:28px;border-radius:50%;background:var(--card);border:2px solid var(--line);display:flex;align-items:center;justify-content:center;margin:0 auto 4px;font-size:.75rem;font-weight:600;transition:all .15s}' +
  '.as-phase-active .as-phase-num{border-color:var(--acc);background:var(--acc);color:var(--bg)}' +
  '.as-phase-done .as-phase-num{border-color:#22c55e;background:#22c55e;color:#fff}' +
  '.as-phase-executed .as-phase-num{border-color:#22c55e;background:#22c55e;color:#fff}' +
  '.as-phase-label{font-size:.68rem;color:var(--mut)}' +
  '.as-phase-active .as-phase-label{color:var(--acc);font-weight:600}' +
  '.as-phase-time{font-size:.6rem;color:var(--mut);opacity:.7}' +
  '.as-phase-line{flex:1;height:2px;background:var(--line);margin-top:14px;min-width:20px}' +
  '.as-phase-done+.as-phase-line,.as-phase-line.as-phase-done{background:#22c55e}' +
  '.as-view-toggle{display:flex;gap:6px;margin-bottom:12px;align-items:center}' +
  '.as-detail{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px;margin-bottom:12px}' +
  '.as-section{margin-bottom:12px}' +
  '.as-section-title{font-size:.75rem;text-transform:uppercase;letter-spacing:.04em;color:var(--acc);font-weight:600;margin-bottom:4px}' +
  '.as-section-body{font-size:.85rem;line-height:1.5;color:var(--txt)}' +
  '.as-def .as-section-title{color:#22c55e}' +
  '.as-tags{display:flex;flex-wrap:wrap;gap:4px}' +
  '.as-tag{font-size:.7rem;padding:3px 8px;background:var(--acc-soft,rgba(0,212,255,.1));color:var(--acc);border-radius:4px;border:1px solid var(--acc-line,rgba(0,212,255,.2))}' +
  '.as-mitre{font-family:var(--mono);font-size:.78rem;color:var(--acc)}' +
  '.as-ioc-list{margin:4px 0 0 16px;font-size:.82rem;line-height:1.6;color:var(--txt)}' +
  '.as-nav{display:flex;gap:8px;margin-bottom:16px}' +
  '.as-exercise{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px}' +
  '.as-exercise h3{margin:0 0 8px;font-size:.9rem}' +
  '.as-exercise-list{margin:0 0 0 16px;font-size:.82rem;line-height:1.8;color:var(--txt)}' +
  '.as-severity-badge{display:inline-block;padding:1px 8px;border-radius:4px;font-size:.68rem;font-weight:600;text-transform:uppercase}' +
  '.as-exec-log-box{background:#020617;border:1px solid var(--line);border-radius:6px;overflow:hidden;margin-top:12px}' +
  '.as-exec-log-header{padding:8px 12px;font-size:.75rem;font-weight:600;color:var(--acc);border-bottom:1px solid var(--line);background:var(--card)}' +
  '#as-exec-lines{padding:10px 12px;max-height:200px;overflow-y:auto;font-family:var(--mono);font-size:.75rem}' +
  '.as-exec-line{color:#22c55e;margin-bottom:4px;opacity:0;animation:as-fade-in .3s forwards}' +
  '.as-exec-done{color:var(--acc);font-weight:600}' +
  '@keyframes as-fade-in{from{opacity:0;transform:translateX(-8px)}to{opacity:1;transform:translateX(0)}}' +
  '.as-exec-summary{background:var(--card);border:1px solid #22c55e44;border-radius:8px;padding:14px;margin-bottom:12px}' +
  '.as-exec-summary-title{font-size:.8rem;font-weight:600;color:#22c55e;margin-bottom:8px}' +
  '.as-exec-kv{display:flex;justify-content:space-between;gap:12px;font-size:.78rem;padding:3px 0;border-bottom:1px solid rgba(255,255,255,.04)}' +
  '.as-exec-kv span:first-child{color:var(--mut);white-space:nowrap;min-width:120px}' +
  '.as-exec-kv span:last-child{text-align:right}' +
  '.as-report-section{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px;margin-bottom:12px}' +
  '.as-report-title{margin:0 0 12px;font-size:.95rem;color:var(--acc)}' +
  '.as-mitre-grid{display:flex;flex-wrap:wrap;gap:6px}' +
  '.as-mitre-item{font-size:.72rem;padding:4px 10px;background:var(--acc-soft,rgba(0,212,255,.1));color:var(--acc);border:1px solid var(--acc-line,rgba(0,212,255,.2));border-radius:4px;font-family:var(--mono)}' +
  '.as-defense-cat{margin-bottom:12px}' +
  '.as-defense-cat-name{font-size:.82rem;font-weight:600;color:var(--txt);margin-bottom:4px}' +
  '.as-defense-list{margin:0 0 0 16px;font-size:.78rem;line-height:1.6;color:var(--mut)}' +
  '.as-exec-status-grid{display:flex;flex-direction:column;gap:6px}' +
  '.as-exec-status-item{display:flex;align-items:center;gap:8px;font-size:.82rem}' +
  '.as-exec-status-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}' +
'</style>';

export function renderAttackSimulator(main) {
  main.innerHTML = STYLE;
  var content = document.createElement('div');
  main.appendChild(content);
  renderScenarioList(content);
}
