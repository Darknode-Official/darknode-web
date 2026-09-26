const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[c]);

// ═══════════════════════════════════════════════════════════════════════════════
// MITRE ATT&CK DATA
// ═══════════════════════════════════════════════════════════════════════════════

const TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance', short: 'Recon' },
  { id: 'TA0042', name: 'Resource Development', short: 'ResDev' },
  { id: 'TA0001', name: 'Initial Access', short: 'InitAccess' },
  { id: 'TA0002', name: 'Execution', short: 'Execution' },
  { id: 'TA0003', name: 'Persistence', short: 'Persist' },
  { id: 'TA0004', name: 'Privilege Escalation', short: 'PrivEsc' },
  { id: 'TA0005', name: 'Defense Evasion', short: 'DefEvas' },
  { id: 'TA0006', name: 'Credential Access', short: 'CredAccess' },
  { id: 'TA0007', name: 'Discovery', short: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement', short: 'LatMov' },
  { id: 'TA0009', name: 'Collection', short: 'Collection' },
  { id: 'TA0011', name: 'Command and Control', short: 'C2' },
  { id: 'TA0010', name: 'Exfiltration', short: 'Exfil' },
  { id: 'TA0040', name: 'Impact', short: 'Impact' }
];

const TECHNIQUES = [
  // Reconnaissance
  { id: 'T1595', name: 'Active Scanning', tactic: 'TA0043', desc: 'Adversaries scan victim IP blocks to gather information for targeting.', datasources: ['Network Traffic'], mitigations: ['Pre-compromise monitoring'], atomicTests: ['T1595-1'] },
  { id: 'T1592', name: 'Gather Victim Host Info', tactic: 'TA0043', desc: 'Gather information about victim hosts including hardware, software, and configurations.', datasources: ['Internet Scan'], mitigations: ['Pre-compromise OPSEC'], atomicTests: [] },
  { id: 'T1589', name: 'Gather Victim Identity Info', tactic: 'TA0043', desc: 'Gather victim identity information such as credentials, email addresses, employee names.', datasources: ['OSINT'], mitigations: ['Limit public exposure'], atomicTests: [] },
  { id: 'T1591', name: 'Gather Victim Org Info', tactic: 'TA0043', desc: 'Gather information about victim organization structure, business relationships, and key personnel.', datasources: ['OSINT'], mitigations: ['Limit public information'], atomicTests: [] },
  { id: 'T1598', name: 'Phishing for Information', tactic: 'TA0043', desc: 'Send phishing messages to elicit sensitive information before the actual compromise.', datasources: ['Email Gateway', 'Web Proxy'], mitigations: ['User training', 'Email filtering'], atomicTests: ['T1598-1', 'T1598-2'] },

  // Resource Development
  { id: 'T1583', name: 'Acquire Infrastructure', tactic: 'TA0042', desc: 'Buy, lease, or rent infrastructure for use during targeting (servers, domains, VPS).', datasources: ['Domain Registration', 'WHOIS'], mitigations: ['Pre-compromise monitoring'], atomicTests: [] },
  { id: 'T1586', name: 'Compromise Accounts', tactic: 'TA0042', desc: 'Compromise existing accounts for use during targeting rather than creating new ones.', datasources: ['Social Media Monitoring'], mitigations: ['MFA', 'Account monitoring'], atomicTests: [] },
  { id: 'T1584', name: 'Compromise Infrastructure', tactic: 'TA0042', desc: 'Compromise third-party infrastructure to use during targeting (web servers, DNS).', datasources: ['Threat Intel Feeds'], mitigations: ['Infrastructure monitoring'], atomicTests: [] },
  { id: 'T1587', name: 'Develop Capabilities', tactic: 'TA0042', desc: 'Build capabilities (malware, exploits, tools) for use in operations.', datasources: ['Malware Repositories'], mitigations: ['Threat intelligence'], atomicTests: [] },
  { id: 'T1588', name: 'Obtain Capabilities', tactic: 'TA0042', desc: 'Buy or download tools, malware, exploits, and certificates for use in operations.', datasources: ['Malware Analysis'], mitigations: ['Vulnerability management'], atomicTests: [] },

  // Initial Access
  { id: 'T1566', name: 'Phishing', tactic: 'TA0001', desc: 'Send phishing messages with malicious attachments or links to gain initial access.', datasources: ['Email Gateway', 'File Monitoring'], mitigations: ['Email filtering', 'User training', 'Sandboxing'], atomicTests: ['T1566.001-1', 'T1566.002-1'] },
  { id: 'T1190', name: 'Exploit Public-Facing App', tactic: 'TA0001', desc: 'Exploit vulnerabilities in internet-facing applications (web servers, VPN, email gateways).', datasources: ['Application Log', 'Network IDS'], mitigations: ['Patch management', 'WAF', 'Network segmentation'], atomicTests: ['T1190-1'] },
  { id: 'T1133', name: 'External Remote Services', tactic: 'TA0001', desc: 'Leverage external remote services (VPN, RDP, Citrix) for initial access using valid credentials.', datasources: ['Authentication Logs', 'VPN Logs'], mitigations: ['MFA', 'Network segmentation'], atomicTests: ['T1133-1'] },
  { id: 'T1078', name: 'Valid Accounts', tactic: 'TA0001', desc: 'Use stolen or compromised credentials to gain initial access and bypass access controls.', datasources: ['Authentication Logs', 'AD Logs'], mitigations: ['MFA', 'Password policy', 'Account monitoring'], atomicTests: ['T1078-1', 'T1078.003-1'] },
  { id: 'T1195', name: 'Supply Chain Compromise', tactic: 'TA0001', desc: 'Manipulate products or delivery mechanisms prior to receipt by the end consumer.', datasources: ['File Integrity', 'Software Inventory'], mitigations: ['Supply chain risk management', 'Code signing'], atomicTests: [] },
  { id: 'T1199', name: 'Trusted Relationship', tactic: 'TA0001', desc: 'Breach organizations through trusted third-party relationships (MSPs, contractors).', datasources: ['Authentication Logs', 'Network Traffic'], mitigations: ['Vendor management', 'Least privilege'], atomicTests: [] },

  // Execution
  { id: 'T1059', name: 'Command & Scripting Interpreter', tactic: 'TA0002', desc: 'Use command-line interfaces and scripting languages (PowerShell, cmd, bash, Python) to execute commands.', datasources: ['Process Creation', 'Script Execution'], mitigations: ['Script blocking', 'AppLocker', 'AMSI'], atomicTests: ['T1059.001-1', 'T1059.003-1'] },
  { id: 'T1203', name: 'Exploitation for Client Execution', tactic: 'TA0002', desc: 'Exploit software vulnerabilities in client applications to execute code (browser, Office, PDF).', datasources: ['Process Creation', 'Application Log'], mitigations: ['Patching', 'Exploit protection'], atomicTests: ['T1203-1'] },
  { id: 'T1047', name: 'WMI', tactic: 'TA0002', desc: 'Use Windows Management Instrumentation for execution on local and remote systems.', datasources: ['WMI Logs', 'Process Creation'], mitigations: ['WMI restrictions', 'User account management'], atomicTests: ['T1047-1'] },
  { id: 'T1053', name: 'Scheduled Task/Job', tactic: 'TA0002', desc: 'Abuse task scheduling to execute malicious code at defined times or intervals.', datasources: ['Scheduled Task Logs', 'Process Creation'], mitigations: ['Privileged account management', 'Audit scheduled tasks'], atomicTests: ['T1053.005-1', 'T1053.003-1'] },
  { id: 'T1204', name: 'User Execution', tactic: 'TA0002', desc: 'Rely on user interaction to execute malicious content (clicking links, opening files).', datasources: ['Process Creation', 'File Creation'], mitigations: ['User training', 'Execution prevention'], atomicTests: ['T1204.001-1', 'T1204.002-1'] },
  { id: 'T1569', name: 'System Services', tactic: 'TA0002', desc: 'Abuse system services (Windows Service Control Manager) to execute commands or programs.', datasources: ['Service Creation', 'Process Creation'], mitigations: ['Privileged account management'], atomicTests: ['T1569.002-1'] },

  // Persistence
  { id: 'T1547', name: 'Boot or Logon Autostart', tactic: 'TA0003', desc: 'Configure system settings to automatically execute programs during boot or logon (Registry Run keys, Startup folder).', datasources: ['Registry', 'File Monitoring'], mitigations: ['Restrict registry permissions'], atomicTests: ['T1547.001-1', 'T1547.001-2'] },
  { id: 'T1136', name: 'Create Account', tactic: 'TA0003', desc: 'Create new accounts (local, domain, cloud) to maintain access.', datasources: ['Authentication Logs', 'AD Logs'], mitigations: ['Privileged account management', 'MFA'], atomicTests: ['T1136.001-1', 'T1136.002-1'] },
  { id: 'T1543', name: 'Create or Modify System Process', tactic: 'TA0003', desc: 'Create or modify system processes (Windows services, systemd) for persistence.', datasources: ['Service Creation', 'Process Creation'], mitigations: ['Audit service changes'], atomicTests: ['T1543.003-1'] },
  { id: 'T1546', name: 'Event Triggered Execution', tactic: 'TA0003', desc: 'Establish persistence using system mechanisms triggered by specific events (WMI subscriptions, AppInit DLLs).', datasources: ['WMI Logs', 'Registry'], mitigations: ['Disable unnecessary triggers'], atomicTests: ['T1546.003-1'] },
  { id: 'T1505', name: 'Server Software Component', tactic: 'TA0003', desc: 'Abuse server software components (web shells, SQL stored procedures, IIS modules) for persistence.', datasources: ['File Monitoring', 'Application Log'], mitigations: ['File integrity monitoring', 'Audit web servers'], atomicTests: ['T1505.003-1'] },
  { id: 'T1098', name: 'Account Manipulation', tactic: 'TA0003', desc: 'Manipulate accounts to maintain access (add credentials, modify permissions, add to groups).', datasources: ['AD Logs', 'Authentication Logs'], mitigations: ['MFA', 'Privileged account management'], atomicTests: ['T1098-1'] },

  // Privilege Escalation
  { id: 'T1068', name: 'Exploitation for Privilege Escalation', tactic: 'TA0004', desc: 'Exploit software vulnerabilities to gain elevated privileges on a system.', datasources: ['Process Creation', 'Application Log'], mitigations: ['Patching', 'Exploit protection'], atomicTests: ['T1068-1'] },
  { id: 'T1055', name: 'Process Injection', tactic: 'TA0004', desc: 'Inject code into running processes to escalate privileges and evade detection.', datasources: ['Process Access', 'API Monitoring'], mitigations: ['Endpoint protection', 'Code integrity'], atomicTests: ['T1055.001-1', 'T1055.012-1'] },
  { id: 'T1548', name: 'Abuse Elevation Control', tactic: 'TA0004', desc: 'Bypass UAC or sudo mechanisms to gain elevated privileges.', datasources: ['Process Creation', 'Windows Event Log'], mitigations: ['UAC enforcement', 'Sudo configuration'], atomicTests: ['T1548.002-1'] },
  { id: 'T1134', name: 'Access Token Manipulation', tactic: 'TA0004', desc: 'Manipulate access tokens to impersonate other users or escalate privileges.', datasources: ['Process Metadata', 'API Monitoring'], mitigations: ['Privileged account management'], atomicTests: ['T1134.001-1'] },

  // Defense Evasion
  { id: 'T1027', name: 'Obfuscated Files or Info', tactic: 'TA0005', desc: 'Obfuscate or encrypt payloads, scripts, and data to evade detection.', datasources: ['File Content', 'Script Execution'], mitigations: ['Antivirus', 'Behavior-based detection'], atomicTests: ['T1027-1', 'T1027.001-1'] },
  { id: 'T1070', name: 'Indicator Removal', tactic: 'TA0005', desc: 'Delete or modify artifacts (logs, files, timestamps) to remove evidence of compromise.', datasources: ['File Deletion', 'Event Log'], mitigations: ['Remote logging', 'Log integrity'], atomicTests: ['T1070.001-1', 'T1070.004-1'] },
  { id: 'T1036', name: 'Masquerading', tactic: 'TA0005', desc: 'Manipulate names or locations of executables to evade defenses and observation.', datasources: ['File Metadata', 'Process Creation'], mitigations: ['Code signing enforcement'], atomicTests: ['T1036.003-1', 'T1036.005-1'] },
  { id: 'T1562', name: 'Impair Defenses', tactic: 'TA0005', desc: 'Disable or modify security tools (AV, EDR, firewall) to avoid detection.', datasources: ['Process Termination', 'Service Changes'], mitigations: ['Tamper protection', 'Least privilege'], atomicTests: ['T1562.001-1'] },
  { id: 'T1112', name: 'Modify Registry', tactic: 'TA0005', desc: 'Modify the Windows registry to hide configuration, evade detection, or maintain persistence.', datasources: ['Registry'], mitigations: ['Registry auditing'], atomicTests: ['T1112-1'] },
  { id: 'T1218', name: 'System Binary Proxy Execution', tactic: 'TA0005', desc: 'Use signed system binaries (rundll32, mshta, certutil) to proxy execution of malicious code.', datasources: ['Process Creation', 'Command Line'], mitigations: ['Execution prevention policies'], atomicTests: ['T1218.005-1', 'T1218.011-1'] },
  { id: 'T1497', name: 'Virtualization/Sandbox Evasion', tactic: 'TA0005', desc: 'Detect and avoid virtualization and sandbox environments used for analysis.', datasources: ['Process Creation', 'API Monitoring'], mitigations: ['Hardened analysis environments'], atomicTests: ['T1497.001-1'] },

  // Credential Access
  { id: 'T1003', name: 'OS Credential Dumping', tactic: 'TA0006', desc: 'Dump credentials from the OS (LSASS, SAM, NTDS.dit, /etc/shadow) to obtain account login info.', datasources: ['Process Access', 'LSASS Access'], mitigations: ['Credential Guard', 'LSA protection'], atomicTests: ['T1003.001-1', 'T1003.002-1', 'T1003.003-1'] },
  { id: 'T1110', name: 'Brute Force', tactic: 'TA0006', desc: 'Use brute force techniques to attempt access when passwords are unknown or hashes obtained.', datasources: ['Authentication Logs', 'Account Lockout'], mitigations: ['Account lockout', 'MFA', 'Password policy'], atomicTests: ['T1110.001-1', 'T1110.003-1'] },
  { id: 'T1555', name: 'Credentials from Password Stores', tactic: 'TA0006', desc: 'Search for credentials in password stores (browsers, keychains, credential managers).', datasources: ['File Access', 'Process Access'], mitigations: ['Password manager enforcement'], atomicTests: ['T1555.003-1'] },
  { id: 'T1558', name: 'Steal or Forge Kerberos Tickets', tactic: 'TA0006', desc: 'Steal or forge Kerberos tickets (Kerberoasting, Golden Ticket, Silver Ticket) for lateral movement.', datasources: ['AD Logs', 'Authentication Logs'], mitigations: ['Strong service account passwords', 'AES encryption'], atomicTests: ['T1558.003-1'] },
  { id: 'T1552', name: 'Unsecured Credentials', tactic: 'TA0006', desc: 'Search for credentials stored insecurely in files, registries, or source code.', datasources: ['File Access', 'Registry'], mitigations: ['Credential management', 'Audit sensitive files'], atomicTests: ['T1552.001-1'] },

  // Discovery
  { id: 'T1087', name: 'Account Discovery', tactic: 'TA0007', desc: 'Attempt to discover accounts (local, domain, cloud, email) for use in subsequent operations.', datasources: ['Process Creation', 'AD Logs'], mitigations: ['Limit information exposure'], atomicTests: ['T1087.001-1', 'T1087.002-1'] },
  { id: 'T1082', name: 'System Information Discovery', tactic: 'TA0007', desc: 'Gather detailed system information (OS, architecture, patches, hostname) from compromised hosts.', datasources: ['Process Creation', 'Command Line'], mitigations: ['None — detection only'], atomicTests: ['T1082-1'] },
  { id: 'T1083', name: 'File and Directory Discovery', tactic: 'TA0007', desc: 'Enumerate files and directories to find interesting data and inform further actions.', datasources: ['Process Creation', 'Command Line'], mitigations: ['None — detection only'], atomicTests: ['T1083-1'] },
  { id: 'T1018', name: 'Remote System Discovery', tactic: 'TA0007', desc: 'Discover remote systems on the network (ping sweep, net view, AD queries) for lateral movement targets.', datasources: ['Network Traffic', 'Process Creation'], mitigations: ['Network segmentation'], atomicTests: ['T1018-1'] },
  { id: 'T1069', name: 'Permission Groups Discovery', tactic: 'TA0007', desc: 'Discover local and domain permission groups and group memberships.', datasources: ['Process Creation', 'AD Logs'], mitigations: ['Limit information exposure'], atomicTests: ['T1069.001-1', 'T1069.002-1'] },
  { id: 'T1057', name: 'Process Discovery', tactic: 'TA0007', desc: 'Enumerate running processes to gather information about software and security tools.', datasources: ['Process Creation'], mitigations: ['None — detection only'], atomicTests: ['T1057-1'] },

  // Lateral Movement
  { id: 'T1021', name: 'Remote Services', tactic: 'TA0008', desc: 'Use remote services (RDP, SSH, SMB, WinRM) to move laterally within the network.', datasources: ['Authentication Logs', 'Network Traffic'], mitigations: ['MFA', 'Network segmentation', 'Least privilege'], atomicTests: ['T1021.001-1', 'T1021.002-1', 'T1021.006-1'] },
  { id: 'T1570', name: 'Lateral Tool Transfer', tactic: 'TA0008', desc: 'Transfer tools and files between systems in the compromised environment.', datasources: ['File Creation', 'Network Traffic'], mitigations: ['Network segmentation'], atomicTests: ['T1570-1'] },
  { id: 'T1550', name: 'Use Alternate Authentication', tactic: 'TA0008', desc: 'Use alternate authentication material (pass the hash, pass the ticket, web session cookies) for lateral movement.', datasources: ['Authentication Logs'], mitigations: ['Credential Guard', 'MFA'], atomicTests: ['T1550.002-1', 'T1550.003-1'] },
  { id: 'T1080', name: 'Taint Shared Content', tactic: 'TA0008', desc: 'Deliver payloads via shared network drives, repositories, or content delivery systems.', datasources: ['File Modification', 'Network Share'], mitigations: ['Restrict write permissions on shares'], atomicTests: [] },

  // Collection
  { id: 'T1560', name: 'Archive Collected Data', tactic: 'TA0009', desc: 'Compress and/or encrypt collected data prior to exfiltration.', datasources: ['File Creation', 'Process Creation'], mitigations: ['Audit archiving tools'], atomicTests: ['T1560.001-1'] },
  { id: 'T1005', name: 'Data from Local System', tactic: 'TA0009', desc: 'Search local system sources (file systems, databases, browser data) for data of interest.', datasources: ['File Access', 'Command Line'], mitigations: ['Data loss prevention'], atomicTests: ['T1005-1'] },
  { id: 'T1114', name: 'Email Collection', tactic: 'TA0009', desc: 'Collect emails from local mailboxes, mail servers, or cloud mail services.', datasources: ['Mail Server Logs', 'Process Access'], mitigations: ['MFA', 'Encrypt sensitive emails'], atomicTests: ['T1114.001-1'] },
  { id: 'T1056', name: 'Input Capture', tactic: 'TA0009', desc: 'Capture user input through keylogging, credential interception, or GUI input capture.', datasources: ['API Monitoring', 'Process Creation'], mitigations: ['Endpoint protection'], atomicTests: ['T1056.001-1'] },
  { id: 'T1113', name: 'Screen Capture', tactic: 'TA0009', desc: 'Take screenshots of the victim\'s desktop to gather information.', datasources: ['API Monitoring', 'Process Creation'], mitigations: ['None — detection only'], atomicTests: ['T1113-1'] },

  // Command and Control
  { id: 'T1071', name: 'Application Layer Protocol', tactic: 'TA0011', desc: 'Communicate over application layer protocols (HTTP/S, DNS, SMTP) to blend with normal traffic.', datasources: ['Network Traffic', 'DNS Logs'], mitigations: ['Network intrusion detection', 'SSL inspection'], atomicTests: ['T1071.001-1'] },
  { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'TA0011', desc: 'Transfer tools or files from an external system into the compromised environment.', datasources: ['Network Traffic', 'File Creation'], mitigations: ['Network intrusion prevention'], atomicTests: ['T1105-1'] },
  { id: 'T1572', name: 'Protocol Tunneling', tactic: 'TA0011', desc: 'Tunnel network communications through another protocol (DNS tunneling, SSH tunneling) to avoid detection.', datasources: ['Network Traffic', 'DNS Logs'], mitigations: ['DNS monitoring', 'Network segmentation'], atomicTests: ['T1572-1'] },
  { id: 'T1090', name: 'Proxy', tactic: 'TA0011', desc: 'Use proxies (SOCKS, multi-hop) to direct C2 traffic through intermediary systems.', datasources: ['Network Traffic'], mitigations: ['SSL inspection', 'Network monitoring'], atomicTests: ['T1090-1'] },
  { id: 'T1573', name: 'Encrypted Channel', tactic: 'TA0011', desc: 'Use encrypted channels for C2 communication to prevent content inspection.', datasources: ['Network Traffic'], mitigations: ['SSL inspection'], atomicTests: ['T1573.001-1'] },
  { id: 'T1219', name: 'Remote Access Software', tactic: 'TA0011', desc: 'Use legitimate remote access tools (TeamViewer, AnyDesk, RMM) for C2.', datasources: ['Process Creation', 'Network Traffic'], mitigations: ['Application whitelisting', 'Execution prevention'], atomicTests: ['T1219-1'] },

  // Exfiltration
  { id: 'T1048', name: 'Exfiltration Over Alternative Protocol', tactic: 'TA0010', desc: 'Steal data over a different protocol than the C2 channel (DNS, ICMP, FTP).', datasources: ['Network Traffic', 'DNS Logs'], mitigations: ['DLP', 'Network segmentation'], atomicTests: ['T1048.003-1'] },
  { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'TA0010', desc: 'Steal data by sending it over the existing C2 communication channel.', datasources: ['Network Traffic'], mitigations: ['DLP', 'Network monitoring'], atomicTests: ['T1041-1'] },
  { id: 'T1567', name: 'Exfiltration Over Web Service', tactic: 'TA0010', desc: 'Steal data by uploading to cloud storage or web services (Google Drive, Dropbox, Mega).', datasources: ['Network Traffic', 'Cloud Logs'], mitigations: ['DLP', 'CASB'], atomicTests: ['T1567.002-1'] },
  { id: 'T1029', name: 'Scheduled Transfer', tactic: 'TA0010', desc: 'Schedule data exfiltration at specific intervals to avoid detection spikes.', datasources: ['Network Traffic'], mitigations: ['DLP', 'Network monitoring'], atomicTests: [] },

  // Impact
  { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'TA0040', desc: 'Encrypt victim data to disrupt operations and demand ransom.', datasources: ['File Modification', 'Process Creation'], mitigations: ['Backup strategy', 'Endpoint protection'], atomicTests: ['T1486-1'] },
  { id: 'T1485', name: 'Data Destruction', tactic: 'TA0040', desc: 'Destroy data and files on systems to disrupt operations and cause damage.', datasources: ['File Deletion', 'Process Creation'], mitigations: ['Backup strategy', 'Access control'], atomicTests: ['T1485-1'] },
  { id: 'T1489', name: 'Service Stop', tactic: 'TA0040', desc: 'Stop or disable system services to cause disruption or inhibit response.', datasources: ['Service Changes', 'Process Creation'], mitigations: ['Service recovery settings', 'Least privilege'], atomicTests: ['T1489-1'] },
  { id: 'T1490', name: 'Inhibit System Recovery', tactic: 'TA0040', desc: 'Delete or disable recovery mechanisms (shadow copies, backups, boot config) to maximize impact.', datasources: ['Process Creation', 'File Deletion'], mitigations: ['Offsite backups', 'Access control'], atomicTests: ['T1490-1'] },
  { id: 'T1498', name: 'Network Denial of Service', tactic: 'TA0040', desc: 'Perform denial of service attacks against network resources to disrupt availability.', datasources: ['Network Traffic', 'Sensor Health'], mitigations: ['DDoS mitigation', 'CDN'], atomicTests: [] },
  { id: 'T1491', name: 'Defacement', tactic: 'TA0040', desc: 'Modify visual content (websites, desktops) to convey a message or intimidate.', datasources: ['File Modification', 'Application Log'], mitigations: ['File integrity monitoring', 'Backup'], atomicTests: ['T1491.002-1'] }
];

const DETECTION_SOURCES = [
  'Process Creation', 'Network Traffic', 'File Monitoring', 'Registry', 'Authentication Logs',
  'DNS Logs', 'Email Gateway', 'Application Log', 'API Monitoring', 'AD Logs',
  'Endpoint Detection', 'Script Execution', 'WMI Logs', 'Cloud Logs', 'Service Changes'
];

// ═══════════════════════════════════════════════════════════════════════════════
// THREAT ACTOR PROFILES
// ═══════════════════════════════════════════════════════════════════════════════

const THREAT_ACTORS = [
  { id: 'apt28', name: 'APT28', alias: 'Fancy Bear', nation: 'Russia', attribution: 'GRU Unit 26165', targets: ['Government', 'Military', 'Media', 'Defense'], campaigns: ['DNC Hack 2016', 'Bundestag 2015', 'WADA 2016'], techniques: ['T1566','T1059','T1078','T1003','T1071','T1027','T1070','T1547','T1082','T1021','T1005','T1041','T1190','T1053','T1087','T1036','T1105','T1573'] },
  { id: 'apt29', name: 'APT29', alias: 'Cozy Bear', nation: 'Russia', attribution: 'SVR', targets: ['Government', 'Think Tanks', 'Healthcare', 'Technology'], campaigns: ['SolarWinds 2020', 'COVID Vaccine Research', 'DNC 2016'], techniques: ['T1195','T1078','T1059','T1053','T1547','T1027','T1070','T1003','T1087','T1082','T1021','T1071','T1105','T1573','T1134','T1055','T1505','T1562'] },
  { id: 'apt33', name: 'APT33', alias: 'Elfin', nation: 'Iran', attribution: 'IRGC', targets: ['Energy', 'Aerospace', 'Defense', 'Petrochemical'], campaigns: ['Shamoon 2012', 'Shamoon 2 2016', 'Aerospace targeting 2017'], techniques: ['T1566','T1204','T1059','T1053','T1547','T1027','T1003','T1082','T1071','T1105','T1486','T1485','T1190','T1110','T1083'] },
  { id: 'apt41', name: 'APT41', alias: 'Winnti', nation: 'China', attribution: 'MSS Contractors', targets: ['Technology', 'Healthcare', 'Manufacturing', 'Telecom'], campaigns: ['Supply chain attacks 2017-2019', 'COVID research 2020'], techniques: ['T1195','T1190','T1059','T1053','T1547','T1543','T1027','T1036','T1003','T1082','T1083','T1021','T1570','T1071','T1105','T1005','T1560','T1041','T1055'] },
  { id: 'volt_typhoon', name: 'Volt Typhoon', alias: 'BRONZE SILHOUETTE', nation: 'China', attribution: 'PLA', targets: ['Critical Infrastructure', 'Telecom', 'Energy', 'Transportation'], campaigns: ['US critical infrastructure pre-positioning 2023-2024'], techniques: ['T1190','T1078','T1059','T1053','T1547','T1218','T1562','T1003','T1082','T1087','T1018','T1021','T1005','T1071','T1090','T1105'] },
  { id: 'lazarus', name: 'Lazarus Group', alias: 'HIDDEN COBRA', nation: 'North Korea', attribution: 'RGB', targets: ['Finance', 'Cryptocurrency', 'Defense', 'Media'], campaigns: ['Sony 2014', 'WannaCry 2017', 'Bangladesh Bank 2016', 'Crypto heists 2022-2024'], techniques: ['T1566','T1204','T1059','T1203','T1547','T1543','T1027','T1036','T1497','T1003','T1082','T1083','T1021','T1071','T1105','T1573','T1486','T1485','T1560','T1041'] },
  { id: 'kimsuky', name: 'Kimsuky', alias: 'Velvet Chollima', nation: 'North Korea', attribution: 'RGB', targets: ['Government', 'Think Tanks', 'Academia', 'Media'], campaigns: ['KHNP 2014', 'Think tank targeting 2018-2024'], techniques: ['T1598','T1566','T1204','T1059','T1547','T1027','T1003','T1555','T1082','T1083','T1071','T1105','T1114','T1005','T1041'] },
  { id: 'sandworm', name: 'Sandworm', alias: 'Voodoo Bear', nation: 'Russia', attribution: 'GRU Unit 74455', targets: ['Energy', 'Government', 'Telecom', 'Media'], campaigns: ['BlackEnergy 2015', 'Industroyer 2016', 'NotPetya 2017', 'Industroyer2 2022'], techniques: ['T1190','T1566','T1059','T1053','T1547','T1543','T1027','T1070','T1562','T1003','T1082','T1018','T1021','T1570','T1071','T1105','T1486','T1485','T1489','T1490'] },
  { id: 'turla', name: 'Turla', alias: 'Venomous Bear', nation: 'Russia', attribution: 'FSB Center 16', targets: ['Government', 'Diplomatic', 'Military', 'Research'], campaigns: ['Snake malware', 'Uroburos', 'Carbon backdoor'], techniques: ['T1583','T1584','T1566','T1190','T1059','T1053','T1547','T1546','T1027','T1036','T1070','T1003','T1082','T1087','T1069','T1021','T1071','T1572','T1090','T1005','T1560','T1048'] },
  { id: 'fin7', name: 'FIN7', alias: 'Carbanak', nation: 'Russia', attribution: 'Cybercriminal', targets: ['Retail', 'Hospitality', 'Finance', 'Food & Beverage'], campaigns: ['Carbanak banking attacks', 'POS malware campaigns'], techniques: ['T1566','T1204','T1059','T1053','T1547','T1027','T1036','T1003','T1555','T1082','T1083','T1057','T1021','T1071','T1105','T1005','T1056','T1041'] },
  { id: 'fin11', name: 'FIN11', alias: 'TA505', nation: 'Russia', attribution: 'Cybercriminal', targets: ['Finance', 'Retail', 'Healthcare', 'Technology'], campaigns: ['Clop ransomware', 'MOVEit exploitation 2023'], techniques: ['T1190','T1566','T1059','T1204','T1053','T1547','T1027','T1003','T1082','T1083','T1021','T1071','T1105','T1486','T1489','T1560','T1567'] },
  { id: 'hafnium', name: 'Hafnium', alias: 'SILK TYPHOON', nation: 'China', attribution: 'MSS', targets: ['Government', 'Defense', 'Healthcare', 'Education', 'NGO'], campaigns: ['Exchange ProxyLogon 2021'], techniques: ['T1190','T1505','T1059','T1136','T1078','T1003','T1082','T1087','T1083','T1021','T1570','T1071','T1105','T1560','T1567'] },
  { id: 'darkside', name: 'DarkSide', alias: 'BlackMatter', nation: 'Russia', attribution: 'Cybercriminal (RaaS)', targets: ['Energy', 'Finance', 'Manufacturing', 'Technology'], campaigns: ['Colonial Pipeline 2021'], techniques: ['T1078','T1133','T1059','T1053','T1547','T1027','T1562','T1003','T1082','T1083','T1021','T1071','T1105','T1486','T1489','T1490','T1560','T1041'] },
  { id: 'lockbit', name: 'LockBit', alias: 'LockBit 3.0', nation: 'Russia', attribution: 'Cybercriminal (RaaS)', targets: ['All Sectors'], campaigns: ['LockBit RaaS 2019-2024', 'Royal Mail 2023', 'Boeing 2023'], techniques: ['T1190','T1078','T1133','T1059','T1053','T1547','T1027','T1562','T1003','T1082','T1083','T1057','T1021','T1570','T1071','T1486','T1489','T1490','T1005','T1041'] },
  { id: 'blackcat', name: 'BlackCat', alias: 'ALPHV', nation: 'Russia', attribution: 'Cybercriminal (RaaS)', targets: ['Healthcare', 'Finance', 'Government', 'Technology'], campaigns: ['Change Healthcare 2024', 'MGM Resorts 2023'], techniques: ['T1190','T1078','T1566','T1059','T1053','T1547','T1027','T1562','T1112','T1003','T1082','T1083','T1021','T1071','T1573','T1486','T1489','T1490','T1560','T1567'] }
];

// ═══════════════════════════════════════════════════════════════════════════════
// STYLES
// ═══════════════════════════════════════════════════════════════════════════════

const STYLE = `
.ap-wrap { font-family: ui-sans-serif, system-ui, sans-serif; color: #c8d6e5; }
.ap-header { margin-bottom: 20px; }
.ap-title { font-size: 24px; font-weight: 800; color: #fff; margin: 0 0 6px; }
.ap-subtitle { font-size: 13px; color: #667788; margin: 0; }
.ap-tabs { display: flex; gap: 2px; margin-bottom: 20px; flex-wrap: wrap; }
.ap-tab { background: #0d1117; border: 1px solid #1a2332; color: #8899aa; padding: 8px 16px; font-size: 12px; font-family: monospace; cursor: pointer; border-radius: 4px 4px 0 0; text-transform: uppercase; letter-spacing: 1px; transition: all .2s; }
.ap-tab:hover { color: #c8d6e5; border-color: #2a3a4a; }
.ap-tab.active { background: #1a2332; color: #00e5ff; border-color: #00e5ff; border-bottom-color: #1a2332; }
.ap-panel { background: #0d1117; border: 1px solid #1a2332; border-radius: 0 8px 8px 8px; padding: 20px; min-height: 500px; }
.ap-section-title { font-size: 13px; font-family: monospace; color: #00e5ff; text-transform: uppercase; letter-spacing: 2px; margin: 0 0 14px; padding-bottom: 8px; border-bottom: 1px solid #1a2332; }
.ap-actor-select { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }
.ap-actor-select label { font-size: 12px; color: #8899aa; font-family: monospace; text-transform: uppercase; letter-spacing: 1px; }
.ap-select { background: #111820; border: 1px solid #1a2332; color: #c8d6e5; padding: 8px 12px; border-radius: 4px; font-size: 13px; font-family: monospace; min-width: 250px; cursor: pointer; }
.ap-select:focus { outline: none; border-color: #00e5ff; }
.ap-actor-info { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 10px; margin-bottom: 20px; }
.ap-info-card { background: #111820; border: 1px solid #1a2332; border-radius: 6px; padding: 12px; }
.ap-info-label { font-size: 9px; color: #667788; font-family: monospace; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 4px; }
.ap-info-value { font-size: 14px; color: #c8d6e5; font-weight: bold; }

/* Matrix view */
.ap-matrix-scroll { overflow-x: auto; margin-bottom: 16px; }
.ap-matrix { display: grid; grid-template-columns: repeat(14, minmax(90px, 1fr)); gap: 2px; min-width: 1260px; }
.ap-matrix-header { background: #111820; border: 1px solid #1a2332; padding: 8px 4px; font-size: 9px; color: #00e5ff; font-family: monospace; text-transform: uppercase; letter-spacing: 0.5px; text-align: center; font-weight: bold; border-radius: 4px 4px 0 0; }
.ap-matrix-col { display: flex; flex-direction: column; gap: 2px; }
.ap-tech-cell { background: #0a0e14; border: 1px solid #1a2332; padding: 6px 4px; font-size: 9px; color: #8899aa; font-family: monospace; cursor: pointer; border-radius: 3px; text-align: center; transition: all .15s; line-height: 1.3; min-height: 36px; display: flex; align-items: center; justify-content: center; }
.ap-tech-cell:hover { border-color: #2a3a4a; color: #c8d6e5; background: #111820; }
.ap-tech-cell.actor-uses { background: #1a0a0a; border-color: #ff224444; color: #ff6666; }
.ap-tech-cell.detected { background: #0a1a0a; border-color: #00ff8844; color: #00ff88; }
.ap-tech-cell.gap { background: #1a1a0a; border-color: #eab30844; color: #eab308; }
.ap-tech-cell.selected { background: #0a1a2a; border-color: #00e5ff; color: #00e5ff; box-shadow: 0 0 8px #00e5ff22; }

.ap-legend { display: flex; gap: 16px; margin-bottom: 16px; flex-wrap: wrap; }
.ap-legend-item { display: flex; align-items: center; gap: 6px; font-size: 11px; color: #8899aa; font-family: monospace; }
.ap-legend-dot { width: 12px; height: 12px; border-radius: 3px; }

/* Playbook builder */
.ap-playbook { margin-top: 16px; }
.ap-chain { display: flex; align-items: center; gap: 4px; flex-wrap: wrap; padding: 16px; background: #111820; border: 1px solid #1a2332; border-radius: 6px; min-height: 80px; }
.ap-chain-step { background: #0d1117; border: 1px solid #00e5ff44; border-radius: 6px; padding: 10px 12px; font-family: monospace; position: relative; min-width: 120px; }
.ap-chain-step .ap-cs-id { font-size: 10px; color: #00e5ff; font-weight: bold; }
.ap-chain-step .ap-cs-name { font-size: 11px; color: #c8d6e5; margin-top: 2px; }
.ap-chain-step .ap-cs-tactic { font-size: 9px; color: #667788; margin-top: 2px; }
.ap-chain-step .ap-cs-remove { position: absolute; top: 2px; right: 4px; background: none; border: none; color: #ff6666; cursor: pointer; font-size: 14px; padding: 0 4px; line-height: 1; }
.ap-chain-arrow { color: #334; font-size: 18px; flex-shrink: 0; }
.ap-chain-empty { color: #445566; font-size: 12px; font-family: monospace; margin: auto; text-align: center; }
.ap-chain-actions { display: flex; gap: 8px; margin-top: 12px; }

/* Heatmap */
.ap-heatmap-wrap { overflow-x: auto; }
.ap-heatmap { border-collapse: collapse; font-family: monospace; font-size: 10px; min-width: 600px; }
.ap-heatmap th { background: #111820; color: #8899aa; padding: 6px 8px; border: 1px solid #1a2332; text-align: center; font-weight: normal; white-space: nowrap; }
.ap-heatmap th:first-child { text-align: left; min-width: 160px; }
.ap-heatmap td { padding: 4px; border: 1px solid #1a2332; text-align: center; width: 30px; height: 30px; }
.ap-heatmap th.ap-hm-toggle { cursor: pointer; }
.ap-heatmap th.ap-hm-toggle:hover { color: #c8d6e5; border-color: #2a3a4a; }
.ap-heatmap th.ap-hm-toggle.on { background: #0a2a0a; color: #00ff88; }
.ap-cov-help { font-size: 12px; color: #8899aa; margin: 0 0 12px; line-height: 1.5; }
.ap-cov-help .ap-btn { margin-left: 8px; }
.ap-hm-covered { background: #0a2a0a; color: #00ff88; }
.ap-hm-partial { background: #2a2a0a; color: #eab308; }
.ap-hm-none { background: #2a0a0a; color: #ff4444; }
.ap-coverage-bar { margin-top: 12px; display: flex; align-items: center; gap: 12px; }
.ap-coverage-fill { height: 8px; border-radius: 4px; transition: width .3s; }

/* Detail panel */
.ap-detail { background: #111820; border: 1px solid #1a2332; border-radius: 6px; padding: 16px; margin-top: 16px; }
.ap-detail-title { font-size: 16px; color: #fff; font-weight: bold; margin: 0 0 4px; }
.ap-detail-id { font-size: 12px; color: #00e5ff; font-family: monospace; margin-bottom: 8px; }
.ap-detail-desc { font-size: 13px; color: #aabbcc; line-height: 1.6; margin-bottom: 12px; }
.ap-detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.ap-detail-section { background: #0d1117; border: 1px solid #1a2332; border-radius: 4px; padding: 10px; }
.ap-detail-section-title { font-size: 10px; color: #00e5ff; font-family: monospace; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px; }
.ap-detail-list { list-style: none; padding: 0; margin: 0; }
.ap-detail-list li { font-size: 11px; color: #8899aa; padding: 2px 0; }
.ap-detail-list li::before { content: '\\25B8 '; color: #00e5ff; }

/* Exercise generator */
.ap-exercise { background: #111820; border: 1px solid #1a2332; border-radius: 6px; padding: 16px; margin-bottom: 12px; }
.ap-exercise-title { font-size: 14px; color: #fff; font-weight: bold; margin-bottom: 8px; }
.ap-exercise-field { margin-bottom: 10px; }
.ap-exercise-label { font-size: 10px; color: #667788; font-family: monospace; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 3px; }
.ap-exercise-value { font-size: 12px; color: #c8d6e5; line-height: 1.5; }

/* Campaign timeline */
.ap-timeline { position: relative; padding: 20px 0 20px 30px; }
.ap-tl-line { position: absolute; left: 14px; top: 0; bottom: 0; width: 2px; background: #1a2332; }
.ap-tl-node { position: relative; margin-bottom: 16px; padding-left: 24px; }
.ap-tl-dot { position: absolute; left: -24px; top: 6px; width: 12px; height: 12px; border-radius: 50%; border: 2px solid; }
.ap-tl-time { font-size: 10px; color: #667788; font-family: monospace; margin-bottom: 2px; }
.ap-tl-action { font-size: 12px; color: #c8d6e5; }
.ap-tl-tech { font-size: 10px; color: #00e5ff; font-family: monospace; }

/* Buttons */
.ap-btn { background: #00e5ff; color: #000; border: none; padding: 8px 16px; border-radius: 4px; font-size: 12px; font-family: monospace; font-weight: bold; cursor: pointer; text-transform: uppercase; letter-spacing: 1px; transition: all .2s; }
.ap-btn:hover { background: #33eeff; }
.ap-btn-ghost { background: transparent; color: #00e5ff; border: 1px solid #00e5ff44; }
.ap-btn-ghost:hover { background: #00e5ff11; border-color: #00e5ff; }
.ap-btn-sm { padding: 5px 10px; font-size: 10px; }

/* STIX output */
.ap-stix-output { background: #0a0e14; border: 1px solid #1a2332; border-radius: 4px; padding: 12px; font-family: monospace; font-size: 11px; color: #c8d6e5; max-height: 400px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; }

/* Pro theme overrides */
[data-style=pro] .ap-wrap { color: #3f3f46; }
[data-style=pro] .ap-title { color: #18181b; }
[data-style=pro] .ap-subtitle { color: #71717a; }
[data-style=pro] .ap-tab { background: #fff; border-color: #e5e5e5; color: #71717a; }
[data-style=pro] .ap-tab:hover { color: #3f3f46; border-color: #d4d4d8; }
[data-style=pro] .ap-tab.active { background: #f9fafb; color: #2563eb; border-color: #2563eb; }
[data-style=pro] .ap-panel { background: #fff; border-color: #e5e5e5; }
[data-style=pro] .ap-section-title { color: #2563eb; border-color: #e5e5e5; }
[data-style=pro] .ap-select { background: #f9fafb; border-color: #e5e5e5; color: #18181b; }
[data-style=pro] .ap-info-card { background: #f9fafb; border-color: #e5e5e5; }
[data-style=pro] .ap-info-label { color: #71717a; }
[data-style=pro] .ap-info-value { color: #18181b; }
[data-style=pro] .ap-matrix-header { background: #f9fafb; border-color: #e5e5e5; color: #2563eb; }
[data-style=pro] .ap-tech-cell { background: #fff; border-color: #e5e5e5; color: #71717a; }
[data-style=pro] .ap-tech-cell:hover { background: #f9fafb; color: #18181b; }
[data-style=pro] .ap-tech-cell.actor-uses { background: #fef2f2; border-color: #fca5a5; color: #dc2626; }
[data-style=pro] .ap-tech-cell.detected { background: #f0fdf4; border-color: #86efac; color: #16a34a; }
[data-style=pro] .ap-tech-cell.gap { background: #fefce8; border-color: #fde047; color: #ca8a04; }
[data-style=pro] .ap-tech-cell.selected { background: #eff6ff; border-color: #2563eb; color: #2563eb; }
[data-style=pro] .ap-chain { background: #f9fafb; border-color: #e5e5e5; }
[data-style=pro] .ap-chain-step { background: #fff; border-color: #bfdbfe; }
[data-style=pro] .ap-chain-step .ap-cs-id { color: #2563eb; }
[data-style=pro] .ap-chain-step .ap-cs-name { color: #18181b; }
[data-style=pro] .ap-chain-step .ap-cs-tactic { color: #71717a; }
[data-style=pro] .ap-chain-arrow { color: #d4d4d8; }
[data-style=pro] .ap-detail { background: #f9fafb; border-color: #e5e5e5; }
[data-style=pro] .ap-detail-title { color: #18181b; }
[data-style=pro] .ap-detail-id { color: #2563eb; }
[data-style=pro] .ap-detail-desc { color: #3f3f46; }
[data-style=pro] .ap-detail-section { background: #fff; border-color: #e5e5e5; }
[data-style=pro] .ap-detail-section-title { color: #2563eb; }
[data-style=pro] .ap-detail-list li { color: #52525b; }
[data-style=pro] .ap-heatmap th { background: #f9fafb; color: #52525b; border-color: #e5e5e5; }
[data-style=pro] .ap-heatmap td { border-color: #e5e5e5; }
[data-style=pro] .ap-hm-covered { background: #dcfce7; color: #166534; }
[data-style=pro] .ap-hm-partial { background: #fef9c3; color: #854d0e; }
[data-style=pro] .ap-hm-none { background: #fee2e2; color: #991b1b; }
[data-style=pro] .ap-exercise { background: #f9fafb; border-color: #e5e5e5; }
[data-style=pro] .ap-exercise-title { color: #18181b; }
[data-style=pro] .ap-exercise-label { color: #71717a; }
[data-style=pro] .ap-exercise-value { color: #3f3f46; }
[data-style=pro] .ap-tl-line { background: #e5e5e5; }
[data-style=pro] .ap-tl-time { color: #71717a; }
[data-style=pro] .ap-tl-action { color: #18181b; }
[data-style=pro] .ap-tl-tech { color: #2563eb; }
[data-style=pro] .ap-btn { background: #18181b; color: #fff; }
[data-style=pro] .ap-btn:hover { background: #3f3f46; }
[data-style=pro] .ap-btn-ghost { background: transparent; color: #18181b; border-color: #d4d4d8; }
[data-style=pro] .ap-btn-ghost:hover { background: #f4f4f5; }
[data-style=pro] .ap-stix-output { background: #f9fafb; border-color: #e5e5e5; color: #18181b; }
[data-style=pro] .ap-legend-item { color: #52525b; }
[data-style=pro] .ap-chain-empty { color: #a1a1aa; }

@media (max-width: 768px) {
  .ap-matrix { grid-template-columns: repeat(14, 80px); }
  .ap-detail-grid { grid-template-columns: 1fr; }
  .ap-actor-info { grid-template-columns: 1fr 1fr; }
}
`;

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN RENDER
// ═══════════════════════════════════════════════════════════════════════════════

export function renderAdversaryPlaybook(container) {
  if (!document.getElementById('ap-styles')) {
    const s = document.createElement('style');
    s.id = 'ap-styles';
    s.textContent = STYLE;
    document.head.appendChild(s);
  }

  let selectedActor = THREAT_ACTORS[0];
  let selectedTechniques = new Set();
  let killChain = [];
  let currentTab = 'matrix';
  let detailTech = null;

  // Detection coverage is YOUR input: which techniques your SOC can detect.
  // It starts empty and is saved in this browser (localStorage) as you toggle it.
  const COVERAGE_KEY = 'dn_ap_detected_v1';
  function loadCoverage() {
    try {
      const raw = localStorage.getItem(COVERAGE_KEY);
      const arr = raw ? JSON.parse(raw) : [];
      const valid = new Set(TECHNIQUES.map(t => t.id));
      return new Set(Array.isArray(arr) ? arr.filter(id => valid.has(id)) : []);
    } catch (e) { return new Set(); }
  }
  function saveCoverage() {
    try { localStorage.setItem(COVERAGE_KEY, JSON.stringify(Array.from(detectedTechniques))); } catch (e) { /* storage unavailable: keep in memory only */ }
  }
  function toggleDetected(tid) {
    if (detectedTechniques.has(tid)) detectedTechniques.delete(tid); else detectedTechniques.add(tid);
    saveCoverage();
  }
  let detectedTechniques = loadCoverage();

  function getTechById(id) { return TECHNIQUES.find(t => t.id === id); }
  function getTechsForTactic(tacticId) { return TECHNIQUES.filter(t => t.tactic === tacticId); }

  function render() {
    let h = '<div class="ap-wrap">';
    h += '<div class="ap-header">';
    h += '<h1 class="ap-title">ADVERSARY PLAYBOOK BUILDER</h1>';
    h += '<p class="ap-subtitle">MITRE ATT&CK-based adversary emulation planning, detection coverage analysis, and purple team exercise generation</p>';
    h += '</div>';

    // Actor selector
    h += '<div class="ap-actor-select">';
    h += '<label>Threat Actor:</label>';
    h += '<select class="ap-select" id="ap-actor-sel">';
    THREAT_ACTORS.forEach(a => {
      h += '<option value="' + esc(a.id) + '"' + (a.id === selectedActor.id ? ' selected' : '') + '>' + esc(a.name) + ' (' + esc(a.alias) + ') — ' + esc(a.nation) + '</option>';
    });
    h += '</select>';
    h += '</div>';

    // Actor info cards
    h += '<div class="ap-actor-info">';
    h += '<div class="ap-info-card"><div class="ap-info-label">Attribution</div><div class="ap-info-value">' + esc(selectedActor.attribution) + '</div></div>';
    h += '<div class="ap-info-card"><div class="ap-info-label">Nation</div><div class="ap-info-value">' + esc(selectedActor.nation) + '</div></div>';
    h += '<div class="ap-info-card"><div class="ap-info-label">Known Techniques</div><div class="ap-info-value">' + selectedActor.techniques.length + '</div></div>';
    h += '<div class="ap-info-card"><div class="ap-info-label">Target Sectors</div><div class="ap-info-value">' + selectedActor.targets.length + '</div></div>';
    h += '<div class="ap-info-card"><div class="ap-info-label">Detection Coverage</div><div class="ap-info-value">' + calcCoverage() + '%</div></div>';
    h += '</div>';

    // Tabs
    const tabs = [
      { id: 'matrix', label: 'ATT&CK Matrix' },
      { id: 'playbook', label: 'Playbook Builder' },
      { id: 'heatmap', label: 'Detection Heatmap' },
      { id: 'exercise', label: 'Purple Team Exercises' },
      { id: 'timeline', label: 'Campaign Timeline' },
      { id: 'stix', label: 'STIX Export' }
    ];
    h += '<div class="ap-tabs">';
    tabs.forEach(t => {
      h += '<div class="ap-tab' + (t.id === currentTab ? ' active' : '') + '" data-tab="' + t.id + '">' + esc(t.label) + '</div>';
    });
    h += '</div>';

    h += '<div class="ap-panel">';
    if (currentTab === 'matrix') h += renderMatrix();
    else if (currentTab === 'playbook') h += renderPlaybook();
    else if (currentTab === 'heatmap') h += renderHeatmap();
    else if (currentTab === 'exercise') h += renderExercises();
    else if (currentTab === 'timeline') h += renderTimeline();
    else if (currentTab === 'stix') h += renderStix();
    h += '</div>';

    // Detail panel
    if (detailTech) {
      h += renderDetailPanel(detailTech);
    }

    h += '</div>';
    container.innerHTML = h;
    wireEvents();
  }

  function calcCoverage() {
    const actorTechs = selectedActor.techniques;
    if (!actorTechs.length) return 0;
    let covered = 0;
    actorTechs.forEach(tid => {
      if (detectedTechniques.has(tid)) covered++;
    });
    return Math.round((covered / actorTechs.length) * 100);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // ATT&CK Matrix
  // ─────────────────────────────────────────────────────────────────────────────
  function renderMatrix() {
    let h = '';
    h += '<div class="ap-section-title">MITRE ATT&CK TECHNIQUE MATRIX</div>';

    h += '<div class="ap-legend">';
    h += '<div class="ap-legend-item"><div class="ap-legend-dot" style="background:#ff224444;border:1px solid #ff6666"></div> Actor uses</div>';
    h += '<div class="ap-legend-item"><div class="ap-legend-dot" style="background:#00ff8844;border:1px solid #00ff88"></div> You detect</div>';
    h += '<div class="ap-legend-item"><div class="ap-legend-dot" style="background:#eab30844;border:1px solid #eab308"></div> Gap (actor uses, you don\'t detect)</div>';
    h += '<div class="ap-legend-item"><div class="ap-legend-dot" style="background:#00e5ff44;border:1px solid #00e5ff"></div> Selected for playbook</div>';
    h += '</div>';

    h += '<div class="ap-matrix-scroll">';
    h += '<div class="ap-matrix">';

    TACTICS.forEach(tactic => {
      h += '<div class="ap-matrix-col">';
      h += '<div class="ap-matrix-header">' + esc(tactic.short) + '</div>';
      const techs = getTechsForTactic(tactic.id);
      techs.forEach(tech => {
        let cls = 'ap-tech-cell';
        const actorUses = selectedActor.techniques.includes(tech.id);
        const youDetect = detectedTechniques.has(tech.id);
        const inChain = selectedTechniques.has(tech.id);
        if (inChain) cls += ' selected';
        else if (actorUses && youDetect) cls += ' detected';
        else if (actorUses && !youDetect) cls += ' gap';
        else if (actorUses) cls += ' actor-uses';
        h += '<div class="' + cls + '" data-tech="' + esc(tech.id) + '" title="' + esc(tech.id + ': ' + tech.name) + '">';
        h += esc(tech.id.replace('T', ''));
        h += '<br>' + esc(tech.name.length > 18 ? tech.name.substring(0, 16) + '…' : tech.name);
        h += '</div>';
      });
      h += '</div>';
    });

    h += '</div>';
    h += '</div>';
    return h;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Playbook Builder
  // ─────────────────────────────────────────────────────────────────────────────
  function renderPlaybook() {
    let h = '';
    h += '<div class="ap-section-title">KILL CHAIN PLAYBOOK BUILDER</div>';
    h += '<p style="font-size:12px;color:#667788;margin-bottom:12px">Click techniques in the matrix tab to add them to the kill chain, or select from the actor\'s known techniques below.</p>';

    h += '<div class="ap-chain">';
    if (killChain.length === 0) {
      h += '<div class="ap-chain-empty">No techniques added yet. Select techniques from the matrix or use the quick-add below.</div>';
    } else {
      killChain.forEach((tid, idx) => {
        const tech = getTechById(tid);
        if (!tech) return;
        const tactic = TACTICS.find(t => t.id === tech.tactic);
        h += '<div class="ap-chain-step">';
        h += '<button class="ap-cs-remove" data-remove="' + idx + '">&times;</button>';
        h += '<div class="ap-cs-id">' + esc(tech.id) + '</div>';
        h += '<div class="ap-cs-name">' + esc(tech.name) + '</div>';
        h += '<div class="ap-cs-tactic">' + esc(tactic ? tactic.name : '') + '</div>';
        h += '</div>';
        if (idx < killChain.length - 1) h += '<span class="ap-chain-arrow">→</span>';
      });
    }
    h += '</div>';

    h += '<div class="ap-chain-actions">';
    h += '<button class="ap-btn ap-btn-sm" id="ap-auto-chain">Auto-Generate Kill Chain</button>';
    h += '<button class="ap-btn ap-btn-sm ap-btn-ghost" id="ap-clear-chain">Clear</button>';
    h += '</div>';

    // Quick-add from actor's techniques
    h += '<div style="margin-top:16px">';
    h += '<div class="ap-section-title" style="font-size:11px;margin-bottom:8px">' + esc(selectedActor.name) + ' — KNOWN TECHNIQUES (click to add)</div>';
    h += '<div style="display:flex;flex-wrap:wrap;gap:4px">';
    selectedActor.techniques.forEach(tid => {
      const tech = getTechById(tid);
      if (!tech) return;
      const inChain = killChain.includes(tid);
      h += '<div class="ap-tech-cell' + (inChain ? ' selected' : ' actor-uses') + '" data-add-tech="' + esc(tid) + '" style="min-height:auto;padding:4px 8px;cursor:pointer;font-size:10px">';
      h += esc(tech.id) + ' ' + esc(tech.name);
      h += '</div>';
    });
    h += '</div>';
    h += '</div>';

    return h;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Detection Heatmap
  // ─────────────────────────────────────────────────────────────────────────────
  function renderHeatmap() {
    let h = '';
    h += '<div class="ap-section-title">DETECTION COVERAGE HEATMAP — ' + esc(selectedActor.name) + '</div>';
    h += '<div class="ap-cov-help">Coverage is your own assessment: click a technique column header to mark it as detected (or not) by your SOC. ' +
      'It starts with nothing detected and is saved in this browser only. ' + detectedTechniques.size + ' technique' + (detectedTechniques.size === 1 ? '' : 's') + ' marked detected.' +
      (detectedTechniques.size ? ' <button class="ap-btn ap-btn-ghost ap-btn-sm" id="ap-clear-detect">Clear coverage</button>' : '') + '</div>';

    const actorTechs = selectedActor.techniques.map(tid => getTechById(tid)).filter(Boolean);
    if (actorTechs.length === 0) {
      h += '<p style="color:#667788">No techniques data for selected actor.</p>';
      return h;
    }

    h += '<div class="ap-heatmap-wrap">';
    h += '<table class="ap-heatmap">';
    h += '<thead><tr><th>DATA SOURCE</th>';
    actorTechs.forEach(tech => {
      const on = detectedTechniques.has(tech.id);
      h += '<th class="ap-hm-toggle' + (on ? ' on' : '') + '" data-detect-toggle="' + esc(tech.id) + '" role="button" tabindex="0" aria-pressed="' + on + '" title="' + esc(tech.id + ': ' + tech.name + (on ? ' (detected, click to unmark)' : ' (not detected, click to mark detected)')) + '">' + esc(tech.id.replace('T', '')) + '</th>';
    });
    h += '</tr></thead><tbody>';

    let totalCells = 0, coveredCells = 0;
    DETECTION_SOURCES.forEach(src => {
      h += '<tr><th>' + esc(src) + '</th>';
      actorTechs.forEach(tech => {
        totalCells++;
        const hasSrc = tech.datasources.includes(src);
        const isDetected = detectedTechniques.has(tech.id);
        let cls, sym;
        if (hasSrc && isDetected) { cls = 'ap-hm-covered'; sym = '●'; coveredCells++; }
        else if (hasSrc) { cls = 'ap-hm-partial'; sym = '◐'; coveredCells += 0.5; }
        else { cls = 'ap-hm-none'; sym = '○'; }
        h += '<td class="' + cls + '">' + sym + '</td>';
      });
      h += '</tr>';
    });
    h += '</tbody></table>';
    h += '</div>';

    const pct = Math.round((coveredCells / totalCells) * 100);
    const barColor = pct > 70 ? '#00ff88' : pct > 40 ? '#eab308' : '#ff4444';
    h += '<div class="ap-coverage-bar">';
    h += '<span style="font-size:12px;color:#8899aa;font-family:monospace;min-width:140px">OVERALL COVERAGE:</span>';
    h += '<div style="flex:1;background:#111820;border-radius:4px;height:8px;overflow:hidden">';
    h += '<div class="ap-coverage-fill" style="width:' + pct + '%;background:' + barColor + '"></div>';
    h += '</div>';
    h += '<span style="font-size:14px;color:' + barColor + ';font-family:monospace;font-weight:bold">' + pct + '%</span>';
    h += '</div>';

    return h;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Purple Team Exercise Generator
  // ─────────────────────────────────────────────────────────────────────────────
  function renderExercises() {
    let h = '';
    h += '<div class="ap-section-title">PURPLE TEAM EXERCISE GENERATOR</div>';

    const techsToTest = killChain.length > 0 ? killChain : selectedActor.techniques.slice(0, 5);

    techsToTest.forEach((tid, idx) => {
      const tech = getTechById(tid);
      if (!tech) return;
      const tactic = TACTICS.find(t => t.id === tech.tactic);

      h += '<div class="ap-exercise">';
      h += '<div class="ap-exercise-title">Exercise ' + (idx + 1) + ': ' + esc(tech.name) + ' (' + esc(tech.id) + ')</div>';

      h += '<div class="ap-exercise-field"><div class="ap-exercise-label">Objective</div>';
      h += '<div class="ap-exercise-value">Test organizational detection and response capability against ' + esc(tech.name) + ' (' + esc(tactic ? tactic.name : '') + ' tactic) as employed by ' + esc(selectedActor.name) + '.</div></div>';

      h += '<div class="ap-exercise-field"><div class="ap-exercise-label">Red Team Actions</div>';
      h += '<div class="ap-exercise-value">' + getRedTeamActions(tech) + '</div></div>';

      h += '<div class="ap-exercise-field"><div class="ap-exercise-label">Blue Team Expected Response</div>';
      h += '<div class="ap-exercise-value">' + getBlueTeamResponse(tech) + '</div></div>';

      h += '<div class="ap-exercise-field"><div class="ap-exercise-label">Success Criteria</div>';
      h += '<div class="ap-exercise-value">Detection alert fires within 15 minutes. SOC analyst triages within 30 minutes. Containment action taken within 1 hour.</div></div>';

      h += '<div class="ap-exercise-field"><div class="ap-exercise-label">Tools Required</div>';
      h += '<div class="ap-exercise-value">' + getToolsForTech(tech) + '</div></div>';

      h += '<div class="ap-exercise-field"><div class="ap-exercise-label">Atomic Red Team Tests</div>';
      h += '<div class="ap-exercise-value">' + (tech.atomicTests.length > 0 ? tech.atomicTests.join(', ') : 'No mapped tests — custom procedure required') + '</div></div>';

      h += '</div>';
    });

    h += '<div style="margin-top:12px">';
    h += '<button class="ap-btn" id="ap-export-exercises">Export Exercise Plan</button>';
    h += '</div>';

    return h;
  }

  function getRedTeamActions(tech) {
    const actions = {
      'T1566': 'Craft spearphishing email with malicious attachment. Target 3 employees in HR/Finance. Use current pretext relevant to organization.',
      'T1190': 'Scan for known vulnerabilities in public-facing applications. Attempt exploitation of identified CVEs.',
      'T1059': 'Execute encoded PowerShell commands. Use living-off-the-land binaries for subsequent actions.',
      'T1003': 'Attempt credential dumping using Mimikatz or comsvcs.dll MiniDump. Target LSASS process memory.',
      'T1021': 'Use obtained credentials to RDP/SSH/SMB to lateral systems. Access at least 2 additional hosts.',
      'T1071': 'Establish HTTPS C2 channel to team infrastructure. Beacon every 60 seconds with jitter.',
      'T1486': 'Simulate ransomware encryption on pre-designated test files in isolated share.',
      'T1078': 'Use compromised valid credentials to access systems. Test with both local and domain accounts.',
      'T1053': 'Create scheduled tasks on target systems for persistence. Use both schtasks and AT commands.',
      'T1027': 'Deploy obfuscated payloads using encoding, encryption, and packing techniques.',
    };
    return actions[tech.id] || 'Execute ' + esc(tech.name) + ' technique following documented procedures. Document all actions and timing.';
  }

  function getBlueTeamResponse(tech) {
    const responses = {
      'T1566': 'Email gateway should flag suspicious attachment. SOC alert on Office macro execution. EDR should detect child process spawning.',
      'T1190': 'WAF/IDS should detect exploitation attempt. Application logs should show anomalous requests. Alert on new process from web server.',
      'T1059': 'AMSI should log script content. PowerShell logging (4104) should capture command. EDR alerts on suspicious interpreter usage.',
      'T1003': 'Protected process violations should trigger. LSASS access events (4663) should fire. EDR should alert on credential dumping tools.',
      'T1021': 'Anomalous lateral movement detected. RDP/SMB authentication from unusual source. Time-based anomaly on service access.',
      'T1071': 'Proxy/SSL inspection should flag unknown HTTPS destinations. DNS monitoring for C2 indicators. JA3/JA3S fingerprint analysis.',
      'T1486': 'File integrity monitoring alerts on mass file changes. Ransomware canary files trigger alert. Volume shadow copy deletion detected.',
      'T1078': 'Impossible travel detection. Unusual logon patterns. Off-hours access alerts.',
      'T1053': 'Scheduled task creation event (4698) logged. EDR alerts on new persistence. Task content inspected.',
      'T1027': 'Static analysis flags obfuscated content. Dynamic analysis in sandbox. Behavioral detection triggers.',
    };
    return responses[tech.id] || 'Monitor relevant data sources (' + tech.datasources.join(', ') + '). Alert on anomalous activity. Triage and escalate per IR procedures.';
  }

  function getToolsForTech(tech) {
    const tools = {
      'T1566': 'GoPhish, King Phisher, custom email templates, O365/Gmail test accounts',
      'T1190': 'Burp Suite, SQLMap, Metasploit, Nuclei, custom exploits',
      'T1059': 'PowerShell Empire, Cobalt Strike, custom scripts, LOLBins',
      'T1003': 'Mimikatz, Rubeus, comsvcs.dll, ProcDump, SharpDump',
      'T1021': 'RDP client, SSH, PsExec, WinRM, Impacket',
      'T1071': 'Cobalt Strike, Covenant, Sliver, custom C2',
      'T1486': 'Test ransomware simulator (non-destructive), custom encryption script',
      'T1078': 'Credential database, Impacket, Evil-WinRM, Rubeus',
      'T1053': 'schtasks.exe, at.exe, PowerShell, crontab',
      'T1027': 'Veil-Evasion, custom packers, PowerShell encoding',
    };
    return tools[tech.id] || 'Atomic Red Team, Caldera, MITRE ATT&CK tools, custom procedures';
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Campaign Timeline
  // ─────────────────────────────────────────────────────────────────────────────
  function renderTimeline() {
    let h = '';
    h += '<div class="ap-section-title">CAMPAIGN TIMELINE — ' + esc(selectedActor.name) + ' EMULATION</div>';

    const phases = buildCampaignPhases();

    h += '<div class="ap-timeline">';
    h += '<div class="ap-tl-line"></div>';
    phases.forEach((phase, idx) => {
      const colors = ['#3b82f6', '#00e5ff', '#eab308', '#ff6644', '#00ff88', '#e879a8', '#a855f7', '#ef4444'];
      const color = colors[idx % colors.length];
      h += '<div class="ap-tl-node">';
      h += '<div class="ap-tl-dot" style="border-color:' + color + ';background:' + color + '33"></div>';
      h += '<div class="ap-tl-time">' + esc(phase.time) + '</div>';
      h += '<div class="ap-tl-action">' + esc(phase.action) + '</div>';
      h += '<div class="ap-tl-tech">' + esc(phase.techniques.join(' → ')) + '</div>';
      h += '</div>';
    });
    h += '</div>';

    return h;
  }

  function buildCampaignPhases() {
    const techs = selectedActor.techniques;
    const phases = [];
    const tacticOrder = TACTICS.map(t => t.id);

    const byTactic = {};
    techs.forEach(tid => {
      const tech = getTechById(tid);
      if (tech) {
        if (!byTactic[tech.tactic]) byTactic[tech.tactic] = [];
        byTactic[tech.tactic].push(tech);
      }
    });

    const timeLabels = ['T+0h', 'T+2h', 'T+6h', 'T+12h', 'T+24h', 'T+36h', 'T+48h', 'T+72h', 'T+96h', 'T+120h', 'T+168h', 'T+240h', 'T+336h', 'T+504h'];
    let timeIdx = 0;

    tacticOrder.forEach(tacticId => {
      const tactic = TACTICS.find(t => t.id === tacticId);
      const techsInTactic = byTactic[tacticId];
      if (!techsInTactic || techsInTactic.length === 0) return;
      if (timeIdx >= timeLabels.length) return;

      phases.push({
        time: timeLabels[timeIdx],
        action: tactic.name + ': ' + techsInTactic.map(t => t.name).join(', '),
        techniques: techsInTactic.map(t => t.id)
      });
      timeIdx++;
    });

    return phases;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // STIX 2.1 Export
  // ─────────────────────────────────────────────────────────────────────────────
  function renderStix() {
    let h = '';
    h += '<div class="ap-section-title">STIX 2.1 BUNDLE EXPORT</div>';
    h += '<p style="font-size:12px;color:#667788;margin-bottom:12px">Structured Threat Information Expression (STIX) bundle for ' + esc(selectedActor.name) + ' including threat actor, campaign, and attack pattern objects.</p>';

    const bundle = generateStixBundle();
    h += '<div class="ap-stix-output" id="ap-stix-json">' + esc(JSON.stringify(bundle, null, 2)) + '</div>';

    h += '<div style="margin-top:12px;display:flex;gap:8px">';
    h += '<button class="ap-btn" id="ap-copy-stix">Copy to Clipboard</button>';
    h += '<button class="ap-btn ap-btn-ghost" id="ap-download-stix">Download .json</button>';
    h += '</div>';

    return h;
  }

  function generateStixBundle() {
    const actor = selectedActor;
    const now = new Date().toISOString();
    const actorId = 'threat-actor--' + crypto.randomUUID();
    const campaignId = 'campaign--' + crypto.randomUUID();

    const objects = [
      {
        type: 'threat-actor',
        spec_version: '2.1',
        id: actorId,
        created: now,
        modified: now,
        name: actor.name,
        description: actor.alias + ' — attributed to ' + actor.attribution + ' (' + actor.nation + ')',
        threat_actor_types: ['nation-state'],
        aliases: [actor.alias],
        roles: ['agent'],
        goals: ['espionage', 'disruption'],
        sophistication: 'expert',
        resource_level: 'government',
        primary_motivation: actor.nation === 'North Korea' ? 'financial-gain' : 'political',
      },
      {
        type: 'campaign',
        spec_version: '2.1',
        id: campaignId,
        created: now,
        modified: now,
        name: actor.name + ' Emulation Campaign',
        description: 'Purple team exercise emulating ' + actor.name + ' TTPs',
        first_seen: now,
      }
    ];

    const techsToExport = killChain.length > 0 ? killChain : actor.techniques;
    techsToExport.forEach(tid => {
      const tech = getTechById(tid);
      if (!tech) return;
      const apId = 'attack-pattern--' + crypto.randomUUID();
      objects.push({
        type: 'attack-pattern',
        spec_version: '2.1',
        id: apId,
        created: now,
        modified: now,
        name: tech.name,
        description: tech.desc,
        external_references: [{ source_name: 'mitre-attack', external_id: tech.id, url: 'https://attack.mitre.org/techniques/' + tech.id + '/' }],
        kill_chain_phases: [{ kill_chain_name: 'mitre-attack', phase_name: (TACTICS.find(t => t.id === tech.tactic) || {}).name || '' }]
      });
      objects.push({
        type: 'relationship',
        spec_version: '2.1',
        id: 'relationship--' + crypto.randomUUID(),
        created: now,
        modified: now,
        relationship_type: 'uses',
        source_ref: actorId,
        target_ref: apId,
      });
    });

    return {
      type: 'bundle',
      id: 'bundle--' + crypto.randomUUID(),
      objects
    };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Detail Panel
  // ─────────────────────────────────────────────────────────────────────────────
  function renderDetailPanel(tech) {
    const tactic = TACTICS.find(t => t.id === tech.tactic);
    let h = '<div class="ap-detail">';
    h += '<div style="display:flex;justify-content:space-between;align-items:flex-start">';
    h += '<div>';
    h += '<div class="ap-detail-title">' + esc(tech.name) + '</div>';
    h += '<div class="ap-detail-id">' + esc(tech.id) + ' — ' + esc(tactic ? tactic.name : '') + '</div>';
    h += '</div>';
    h += '<button class="ap-btn ap-btn-sm' + (killChain.includes(tech.id) ? '' : ' ap-btn-ghost') + '" id="ap-toggle-chain">' + (killChain.includes(tech.id) ? 'Remove from Chain' : 'Add to Kill Chain') + '</button>';
    h += '</div>';
    h += '<div class="ap-detail-desc">' + esc(tech.desc) + '</div>';

    h += '<div class="ap-detail-grid">';
    h += '<div class="ap-detail-section"><div class="ap-detail-section-title">Data Sources</div><ul class="ap-detail-list">';
    tech.datasources.forEach(ds => { h += '<li>' + esc(ds) + '</li>'; });
    h += '</ul></div>';
    h += '<div class="ap-detail-section"><div class="ap-detail-section-title">Mitigations</div><ul class="ap-detail-list">';
    tech.mitigations.forEach(m => { h += '<li>' + esc(m) + '</li>'; });
    h += '</ul></div>';
    h += '<div class="ap-detail-section"><div class="ap-detail-section-title">Atomic Red Team Tests</div><ul class="ap-detail-list">';
    if (tech.atomicTests.length > 0) {
      tech.atomicTests.forEach(t => { h += '<li>' + esc(t) + '</li>'; });
    } else {
      h += '<li style="color:#667788">No mapped Atomic tests</li>';
    }
    h += '</ul></div>';
    h += '<div class="ap-detail-section"><div class="ap-detail-section-title">Detection Status</div>';
    h += '<button class="ap-btn ap-btn-ghost ap-btn-sm" id="ap-toggle-detect" style="margin-bottom:8px">' + (detectedTechniques.has(tech.id) ? 'Mark as not detected' : 'Mark as detected') + '</button>';
    if (detectedTechniques.has(tech.id)) {
      h += '<div style="color:#00ff88;font-size:13px;font-weight:bold">● COVERED</div>';
    } else if (selectedActor.techniques.includes(tech.id)) {
      h += '<div style="color:#ff4444;font-size:13px;font-weight:bold">● GAP — ' + esc(selectedActor.name) + ' uses this technique</div>';
    } else {
      h += '<div style="color:#667788;font-size:13px">○ Not in actor profile</div>';
    }
    h += '</div>';
    h += '</div>';

    h += '</div>';
    return h;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Event wiring
  // ─────────────────────────────────────────────────────────────────────────────
  function wireEvents() {
    // Actor select
    const actorSel = container.querySelector('#ap-actor-sel');
    if (actorSel) actorSel.onchange = () => {
      selectedActor = THREAT_ACTORS.find(a => a.id === actorSel.value) || THREAT_ACTORS[0];
      detailTech = null;
      render();
    };

    // Tab switching
    container.querySelectorAll('.ap-tab').forEach(tab => {
      tab.onclick = () => { currentTab = tab.dataset.tab; render(); };
    });

    // Detection coverage toggles (heatmap headers + detail panel)
    container.querySelectorAll('[data-detect-toggle]').forEach(th => {
      const act = () => { toggleDetected(th.dataset.detectToggle); render(); };
      th.onclick = act;
      th.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); act(); } };
    });
    const detBtn = container.querySelector('#ap-toggle-detect');
    if (detBtn && detailTech) detBtn.onclick = () => { toggleDetected(detailTech.id); render(); };
    const clrDet = container.querySelector('#ap-clear-detect');
    if (clrDet) clrDet.onclick = () => { detectedTechniques = new Set(); saveCoverage(); render(); };

    // Tech cell clicks
    container.querySelectorAll('[data-tech]').forEach(cell => {
      cell.onclick = () => {
        const tech = getTechById(cell.dataset.tech);
        if (tech) { detailTech = tech; render(); }
      };
    });

    // Add tech to chain from quick-add
    container.querySelectorAll('[data-add-tech]').forEach(el => {
      el.onclick = () => {
        const tid = el.dataset.addTech;
        if (!killChain.includes(tid)) {
          killChain.push(tid);
          selectedTechniques.add(tid);
        }
        render();
      };
    });

    // Remove from chain
    container.querySelectorAll('[data-remove]').forEach(btn => {
      btn.onclick = (e) => {
        e.stopPropagation();
        const idx = parseInt(btn.dataset.remove);
        const removed = killChain.splice(idx, 1);
        if (removed[0]) selectedTechniques.delete(removed[0]);
        render();
      };
    });

    // Auto-generate kill chain
    const autoBtn = container.querySelector('#ap-auto-chain');
    if (autoBtn) autoBtn.onclick = () => {
      killChain = [];
      selectedTechniques.clear();
      const tacticOrder = TACTICS.map(t => t.id);
      tacticOrder.forEach(tacticId => {
        const techsForTactic = selectedActor.techniques.filter(tid => {
          const t = getTechById(tid);
          return t && t.tactic === tacticId;
        });
        if (techsForTactic.length > 0) {
          const pick = techsForTactic[0];
          killChain.push(pick);
          selectedTechniques.add(pick);
        }
      });
      render();
    };

    // Clear chain
    const clearBtn = container.querySelector('#ap-clear-chain');
    if (clearBtn) clearBtn.onclick = () => {
      killChain = [];
      selectedTechniques.clear();
      render();
    };

    // Toggle chain from detail
    const toggleBtn = container.querySelector('#ap-toggle-chain');
    if (toggleBtn && detailTech) toggleBtn.onclick = () => {
      const tid = detailTech.id;
      if (killChain.includes(tid)) {
        killChain = killChain.filter(t => t !== tid);
        selectedTechniques.delete(tid);
      } else {
        killChain.push(tid);
        selectedTechniques.add(tid);
      }
      render();
    };

    // Copy STIX
    const copyStix = container.querySelector('#ap-copy-stix');
    if (copyStix) copyStix.onclick = () => {
      const json = container.querySelector('#ap-stix-json');
      if (json) {
        navigator.clipboard.writeText(json.textContent).then(() => {
          copyStix.textContent = 'COPIED!';
          setTimeout(() => { copyStix.textContent = 'Copy to Clipboard'; }, 1500);
        });
      }
    };

    // Download STIX
    const dlStix = container.querySelector('#ap-download-stix');
    if (dlStix) dlStix.onclick = () => {
      const bundle = generateStixBundle();
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = selectedActor.id + '-stix-bundle.json';
      a.click();
      URL.revokeObjectURL(url);
    };

    // Export exercises
    const exportEx = container.querySelector('#ap-export-exercises');
    if (exportEx) exportEx.onclick = () => {
      let text = 'PURPLE TEAM EXERCISE PLAN\n';
      text += 'Adversary: ' + selectedActor.name + ' (' + selectedActor.alias + ')\n';
      text += 'Generated: ' + new Date().toISOString() + '\n';
      text += '='.repeat(60) + '\n\n';

      const techsToTest = killChain.length > 0 ? killChain : selectedActor.techniques.slice(0, 5);
      techsToTest.forEach((tid, idx) => {
        const tech = getTechById(tid);
        if (!tech) return;
        const tactic = TACTICS.find(t => t.id === tech.tactic);
        text += 'EXERCISE ' + (idx + 1) + ': ' + tech.name + ' (' + tech.id + ')\n';
        text += 'Tactic: ' + (tactic ? tactic.name : '') + '\n';
        text += 'Red Team: ' + getRedTeamActions(tech) + '\n';
        text += 'Blue Team: ' + getBlueTeamResponse(tech) + '\n';
        text += 'Tools: ' + getToolsForTech(tech) + '\n';
        text += 'Atomic Tests: ' + (tech.atomicTests.length ? tech.atomicTests.join(', ') : 'N/A') + '\n';
        text += '-'.repeat(40) + '\n\n';
      });

      navigator.clipboard.writeText(text).then(() => {
        exportEx.textContent = 'COPIED!';
        setTimeout(() => { exportEx.textContent = 'Export Exercise Plan'; }, 1500);
      });
    };
  }

  render();
}
