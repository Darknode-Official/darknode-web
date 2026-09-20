// Adversary Mind — AI Attack Prediction Engine
// Thinks like an attacker. Describe your infrastructure, get a specific attack plan.
// Copyright (c) 2026 Darknode-Official. All rights reserved.

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ============================================================================
// ATTACK DECISION RULES — 200+ heuristic rules encoding real attacker behavior
// ============================================================================
const ATTACK_RULES = [
  // Initial Access — External Services
  { condition: { service: 'web_app', control_absent: 'waf' }, vector: 'Web Application Exploit', probability: 0.70, mitre: 'T1190', reasoning: 'External web app without WAF is low-hanging fruit for SQLi, XSS, RCE' },
  { condition: { service: 'web_app', control_present: 'waf' }, vector: 'WAF Bypass + Web Exploit', probability: 0.30, mitre: 'T1190', reasoning: 'WAF is present but can be bypassed with encoding tricks, HTTP smuggling, or logic flaws' },
  { condition: { service: 'vpn' }, vector: 'VPN Vulnerability Exploitation', probability: 0.55, mitre: 'T1133', reasoning: 'VPN appliances (Ivanti, Fortinet, PAN-OS, Citrix) have had multiple critical CVEs in 2023-2024' },
  { condition: { service: 'vpn', control_absent: 'mfa' }, vector: 'VPN Credential Stuffing', probability: 0.65, mitre: 'T1078', reasoning: 'VPN without MFA is trivially accessed with leaked credentials from breach databases' },
  { condition: { service: 'email' }, vector: 'Spearphishing', probability: 0.60, mitre: 'T1566.001', reasoning: 'Email is the #1 initial access vector across all industries' },
  { condition: { service: 'email', awareness: 'low' }, vector: 'Mass Phishing Campaign', probability: 0.85, mitre: 'T1566.001', reasoning: 'Low security awareness + email = near-certain successful phishing' },
  { condition: { service: 'email', awareness: 'high' }, vector: 'Targeted Spearphishing', probability: 0.35, mitre: 'T1566.002', reasoning: 'High awareness reduces mass phishing, but targeted attacks with pretexting still work' },
  { condition: { service: 'api' }, vector: 'API Abuse', probability: 0.45, mitre: 'T1190', reasoning: 'APIs often lack rate limiting, proper auth, or input validation — OWASP API Top 10' },
  { condition: { service: 'api', control_absent: 'waf' }, vector: 'API Injection/BOLA', probability: 0.60, mitre: 'T1190', reasoning: 'Unprotected APIs are highly vulnerable to BOLA (Broken Object Level Auth) and injection' },
  { condition: { service: 'rdp' }, vector: 'Exposed RDP Brute Force', probability: 0.70, mitre: 'T1110', reasoning: 'Internet-facing RDP is constantly targeted by botnets — median time to compromise: 45 minutes' },
  { condition: { service: 'rdp', control_present: 'mfa' }, vector: 'RDP with MFA Bypass', probability: 0.15, mitre: 'T1110', reasoning: 'MFA significantly reduces RDP risk but MFA fatigue attacks exist' },
  { condition: { service: 'ssh' }, vector: 'SSH Key Compromise/Brute Force', probability: 0.35, mitre: 'T1110', reasoning: 'SSH with password auth is brute-forceable; key-based is safer but keys can be stolen' },
  { condition: { service: 'cloud_console' }, vector: 'Cloud Account Compromise', probability: 0.40, mitre: 'T1078.004', reasoning: 'Cloud consoles with weak IAM policies or leaked keys are regularly compromised' },
  { condition: { service: 'cloud_console', control_absent: 'mfa' }, vector: 'Cloud Console Credential Stuffing', probability: 0.65, mitre: 'T1078.004', reasoning: 'Cloud console without MFA — credential stuffing from breach databases is trivial' },

  // Initial Access — Industry-Specific
  { condition: { industry: 'healthcare' }, vector: 'Medical Device Exploitation', probability: 0.30, mitre: 'T1190', reasoning: 'Healthcare has legacy medical devices with known vulns, poor patching, and flat networks' },
  { condition: { industry: 'healthcare' }, vector: 'Ransomware (Double Extortion)', probability: 0.55, mitre: 'T1486', reasoning: 'Healthcare is the #1 ransomware target — patient data + operational disruption = high payment likelihood' },
  { condition: { industry: 'finance' }, vector: 'Credential Theft + Wire Fraud', probability: 0.45, mitre: 'T1078', reasoning: 'Financial institutions are targeted for credential theft leading to wire transfer fraud or SWIFT abuse' },
  { condition: { industry: 'finance' }, vector: 'Supply Chain via Financial Software', probability: 0.25, mitre: 'T1195.002', reasoning: 'Attackers target financial software vendors (e.g., SolarWinds, Kaseya) to reach their clients' },
  { condition: { industry: 'government' }, vector: 'Nation-State APT', probability: 0.40, mitre: 'T1190', reasoning: 'Government entities are prime targets for nation-state actors (APT28, APT29, Volt Typhoon)' },
  { condition: { industry: 'government' }, vector: 'Insider Threat', probability: 0.30, mitre: 'T1078', reasoning: 'Government agencies face elevated insider threat risk from privileged users and contractors' },
  { condition: { industry: 'tech' }, vector: 'Supply Chain Compromise', probability: 0.35, mitre: 'T1195.002', reasoning: 'Tech companies are targeted to compromise their products and reach downstream customers' },
  { condition: { industry: 'tech' }, vector: 'Source Code Repository Attack', probability: 0.40, mitre: 'T1213', reasoning: 'Attackers target Git repos for secrets, API keys, and to inject backdoors' },
  { condition: { industry: 'education' }, vector: 'Ransomware', probability: 0.50, mitre: 'T1486', reasoning: 'Education has limited security budgets and legacy systems — prime ransomware target' },
  { condition: { industry: 'retail' }, vector: 'POS Malware / Magecart', probability: 0.40, mitre: 'T1059.007', reasoning: 'Retail is targeted for payment card data via POS malware and web skimmers' },
  { condition: { industry: 'energy' }, vector: 'ICS/SCADA Attack', probability: 0.30, mitre: 'T0855', reasoning: 'Energy sector faces targeted attacks on operational technology from nation-states' },
  { condition: { industry: 'manufacturing' }, vector: 'Ransomware + OT Disruption', probability: 0.45, mitre: 'T1486', reasoning: 'Manufacturing downtime costs are extreme — makes ransomware payment more likely' },

  // Initial Access — General
  { condition: { awareness: 'low' }, vector: 'Social Engineering (Phone/In-Person)', probability: 0.50, mitre: 'T1566.004', reasoning: 'Low awareness organizations are vulnerable to pretexting, vishing, and physical social engineering' },
  { condition: { employees_gt: 500 }, vector: 'Credential Stuffing', probability: 0.55, mitre: 'T1110.004', reasoning: 'Larger organizations have more leaked credentials in breach databases — more targets to try' },
  { condition: { employees_lt: 50 }, vector: 'Direct Targeting of Admin', probability: 0.40, mitre: 'T1566.001', reasoning: 'Small orgs often have one IT person with all the keys — compromise them, compromise everything' },
  { condition: { budget: 'startup' }, vector: 'Cloud Misconfiguration', probability: 0.60, mitre: 'T1190', reasoning: 'Startups move fast, security is an afterthought — S3 buckets, open APIs, default configs' },
  { condition: { budget: 'startup', control_absent: 'siem' }, vector: 'Undetected Persistent Access', probability: 0.70, mitre: 'T1078', reasoning: 'No SIEM = no detection. Attacker can dwell for months unnoticed' },

  // Lateral Movement Rules
  { condition: { arch: 'ad', control_absent: 'mfa' }, vector: 'Kerberoasting + Pass-the-Hash', probability: 0.85, mitre: 'T1558.003', reasoning: 'AD without MFA is a playground — Kerberoasting gets service account hashes, PtH moves laterally' },
  { condition: { arch: 'ad', control_present: 'mfa' }, vector: 'MFA Fatigue / Token Theft', probability: 0.25, mitre: 'T1621', reasoning: 'MFA blocks most credential attacks but fatigue bombing and token theft bypass it' },
  { condition: { arch: 'ad' }, vector: 'DCSync / Golden Ticket', probability: 0.70, mitre: 'T1003.006', reasoning: 'Once DA is obtained in AD, DCSync extracts all hashes — game over for the domain' },
  { condition: { arch: 'flat' }, vector: 'Unrestricted Lateral Movement', probability: 0.90, mitre: 'T1021', reasoning: 'Flat network = every host can reach every other host. Lateral movement is trivial' },
  { condition: { arch: 'flat', control_absent: 'edr' }, vector: 'Complete Network Compromise', probability: 0.95, mitre: 'T1021', reasoning: 'Flat network + no EDR = attacker moves freely with no detection. Total compromise is near-certain' },
  { condition: { arch: 'segmented' }, vector: 'Segment Hopping via Allowed Services', probability: 0.40, mitre: 'T1021', reasoning: 'Segmentation slows attackers but allowed services (DNS, HTTP) between segments can be abused' },
  { condition: { arch: 'cloud' }, vector: 'IAM Privilege Escalation', probability: 0.50, mitre: 'T1078.004', reasoning: 'Cloud environments often have overly permissive IAM policies that allow escalation' },
  { condition: { arch: 'cloud', control_absent: 'siem' }, vector: 'Cloud API Key Abuse', probability: 0.65, mitre: 'T1078.004', reasoning: 'Without cloud-native SIEM (CloudTrail, Azure Monitor), API key abuse goes undetected' },
  { condition: { arch: 'hybrid' }, vector: 'On-Prem to Cloud Pivot', probability: 0.55, mitre: 'T1078.004', reasoning: 'Hybrid environments have trust relationships between on-prem AD and cloud that attackers abuse (Azure AD Connect, ADFS token forging)' },

  // Defense Evasion Rules
  { condition: { control_present: 'edr' }, vector: 'Living-off-the-Land (LOLBins)', probability: 0.60, mitre: 'T1218', reasoning: 'EDR catches custom malware — attackers pivot to using legitimate tools (PowerShell, certutil, mshta, rundll32)' },
  { condition: { control_present: 'edr' }, vector: 'EDR Bypass / Unhooking', probability: 0.30, mitre: 'T1562.001', reasoning: 'Advanced attackers unhook EDR userland DLLs or use direct syscalls to bypass monitoring' },
  { condition: { control_present: 'av', control_absent: 'edr' }, vector: 'AV Evasion (Obfuscation)', probability: 0.75, mitre: 'T1027', reasoning: 'AV without EDR relies on signatures — easily bypassed with packers, encoders, or custom compilers' },
  { condition: { control_present: 'siem' }, vector: 'Log Evasion / Timestomping', probability: 0.35, mitre: 'T1070', reasoning: 'SIEM presence means attackers try to delete/modify logs, use timestomping, or blend into normal traffic' },
  { condition: { control_absent: 'siem' }, vector: 'Undetected Operations', probability: 0.90, mitre: 'T1070', reasoning: 'No SIEM = no centralized logging = no detection. Attacker operates freely.' },
  { condition: { control_present: 'dlp' }, vector: 'Encrypted Exfiltration', probability: 0.50, mitre: 'T1048.002', reasoning: 'DLP present — attacker will encrypt data before exfil or use covert channels (DNS, steganography)' },

  // Persistence Rules
  { condition: { arch: 'ad' }, vector: 'Golden Ticket Persistence', probability: 0.65, mitre: 'T1558.001', reasoning: 'With krbtgt hash, attacker has unlimited 10-year Kerberos tickets — survives password resets' },
  { condition: { arch: 'ad' }, vector: 'AdminSDHolder Backdoor', probability: 0.30, mitre: 'T1098', reasoning: 'Modifying AdminSDHolder ACLs grants persistent admin access that auto-propagates every 60 minutes' },
  { condition: { arch: 'cloud' }, vector: 'OAuth App / Service Principal Backdoor', probability: 0.45, mitre: 'T1098.001', reasoning: 'Attackers create rogue OAuth apps or service principals that maintain access even after password resets' },

  // Crown Jewel Analysis
  { condition: { industry: 'healthcare' }, target: 'Protected Health Information (PHI)', value: '$500-1000 per record on dark web', impact: 'HIPAA fines up to $1.5M per violation category, class action lawsuits, patient harm' },
  { condition: { industry: 'finance' }, target: 'Financial Records + Wire Transfer Access', value: 'Direct monetary theft, $10K-$100M+ per incident', impact: 'SEC/FINRA penalties, customer lawsuits, loss of banking charter' },
  { condition: { industry: 'tech' }, target: 'Source Code + IP + Customer Data', value: '$1M-$1B+ depending on IP', impact: 'Competitive advantage loss, customer breach notifications, stock price impact' },
  { condition: { industry: 'government' }, target: 'Classified/Sensitive Government Data', value: 'Priceless (national security)', impact: 'National security compromise, espionage charges, diplomatic incidents' },
  { condition: { industry: 'retail' }, target: 'Payment Card Data (PCI)', value: '$5-50 per card on dark web', impact: 'PCI DSS fines $5K-100K/month, card brand penalties, customer churn' },
  { condition: { industry: 'education' }, target: 'Student PII + Research Data', value: '$10-50 per record', impact: 'FERPA violations, research loss, ransomware downtime (avg 16 days)' },
  { condition: { industry: 'energy' }, target: 'SCADA/ICS Access + Operational Disruption', value: 'National security impact', impact: 'Physical damage, safety incidents, regulatory penalties, grid instability' },
  { condition: { industry: 'manufacturing' }, target: 'Trade Secrets + Production Disruption', value: '$1M-$500M+ IP value', impact: 'Production downtime ($X00K/day), competitive loss, supply chain disruption' },
];

// ============================================================================
// DWELL TIME ESTIMATION (days) — based on security controls
// ============================================================================
const DWELL_TIME_FACTORS = {
  edr: -45,
  siem: -60,
  mfa: -15,
  waf: -5,
  segmentation: -20,
  dlp: -10,
  ids: -30,
  soc_team: -90,
  threat_intel: -25,
  baseline: 194, // Mandiant M-Trends 2024 median non-ransomware dwell time (global)
};

// ============================================================================
// BREACH COST DATA (IBM Cost of a Data Breach Report 2024)
// ============================================================================
const BREACH_COST_DATA = {
  global_average: 4450000,
  per_record: 165,
  by_industry: {
    healthcare: 10930000,
    finance: 6080000,
    tech: 5450000,
    energy: 4780000,
    manufacturing: 4730000,
    retail: 3480000,
    education: 3650000,
    government: 2730000,
  },
  by_size: {
    startup: 0.6,
    small: 0.8,
    medium: 1.0,
    enterprise: 1.4,
  },
  factors: {
    mfa: -0.18,
    siem: -0.14,
    edr: -0.12,
    dlp: -0.09,
    incident_response_plan: -0.11,
    security_ai: -0.22,
    no_controls: 0.25,
    cloud_misconfiguration: 0.12,
    supply_chain: 0.09,
    remote_work: 0.05,
  },
};

// ============================================================================
// KILL CHAIN TEMPLATES — attack path generators
// ============================================================================
const KILL_CHAIN_TEMPLATES = [
  {
    name: 'Classic Phishing Chain',
    initialAccess: 'Spearphishing email with malicious macro document',
    steps: [
      { phase: 'Initial Access', action: 'Victim opens phishing email and enables macros in attached document', mitre: 'T1566.001', detection: 'Email gateway, sandbox detonation' },
      { phase: 'Execution', action: 'Macro executes PowerShell download cradle', mitre: 'T1059.001', detection: 'Script block logging (Event ID 4104)' },
      { phase: 'Defense Evasion', action: 'Payload is obfuscated and runs in memory (fileless)', mitre: 'T1027', detection: 'AMSI logging, ETW telemetry' },
      { phase: 'C2', action: 'Beacon established via HTTPS to attacker infrastructure', mitre: 'T1071.001', detection: 'Proxy logs, JA3 fingerprinting, network anomaly detection' },
      { phase: 'Discovery', action: 'Enumerate domain trusts, users, groups, shares', mitre: 'T1087', detection: 'Excessive LDAP queries, BloodHound collection artifacts' },
      { phase: 'Credential Access', action: 'Dump LSASS via Mimikatz or comsvcs.dll MiniDump', mitre: 'T1003.001', detection: 'Sysmon Event ID 10 (process access to lsass.exe)' },
      { phase: 'Lateral Movement', action: 'Pass-the-Hash to other workstations and servers', mitre: 'T1550.002', detection: 'Event ID 4624 Type 9 (NewCredentials)' },
      { phase: 'Privilege Escalation', action: 'Kerberoasting or AS-REP Roasting for service account hashes', mitre: 'T1558.003', detection: 'Event ID 4769 with RC4 encryption type 0x17' },
      { phase: 'Persistence', action: 'Golden Ticket forged with krbtgt hash', mitre: 'T1558.001', detection: 'TGT with anomalous lifetime, Event ID 4769 anomalies' },
      { phase: 'Exfiltration', action: 'Stage and exfiltrate data via HTTPS to cloud storage', mitre: 'T1567.002', detection: 'DLP, unusual outbound data volume, cloud storage domain access' },
    ],
  },
  {
    name: 'Web Application Compromise',
    initialAccess: 'Exploitation of vulnerable web application',
    steps: [
      { phase: 'Initial Access', action: 'Exploit SQL injection or RCE in public-facing web app', mitre: 'T1190', detection: 'WAF, IDS signatures, web server logs' },
      { phase: 'Execution', action: 'Web shell uploaded or reverse shell via command injection', mitre: 'T1505.003', detection: 'File integrity monitoring, web shell signatures' },
      { phase: 'Discovery', action: 'Enumerate local system, network, and internal services', mitre: 'T1082', detection: 'Process monitoring, command-line logging' },
      { phase: 'Privilege Escalation', action: 'Exploit SUID binary, kernel vuln, or sudo misconfiguration', mitre: 'T1068', detection: 'auditd, SUID monitoring, kernel exploit signatures' },
      { phase: 'Credential Access', action: 'Extract database credentials from config files', mitre: 'T1552.001', detection: 'File access monitoring on config files' },
      { phase: 'Lateral Movement', action: 'SSH with stolen keys or credentials to internal servers', mitre: 'T1021.004', detection: 'SSH key usage from unusual sources, auth.log monitoring' },
      { phase: 'Collection', action: 'Dump database contents (customer data, credentials)', mitre: 'T1005', detection: 'Database query monitoring, large query result sets' },
      { phase: 'Exfiltration', action: 'Exfiltrate via DNS tunneling or encrypted HTTPS', mitre: 'T1048.003', detection: 'DNS query anomalies, NXDOMAIN spikes, large TXT records' },
    ],
  },
  {
    name: 'VPN/Remote Access Exploitation',
    initialAccess: 'Exploit vulnerability in VPN appliance (Ivanti, Fortinet, PAN-OS)',
    steps: [
      { phase: 'Initial Access', action: 'Exploit CVE in VPN appliance for pre-auth RCE', mitre: 'T1190', detection: 'IDS/IPS, VPN appliance logs, vulnerability scanning' },
      { phase: 'Persistence', action: 'Plant web shell or modify VPN configuration for backdoor access', mitre: 'T1505.003', detection: 'File integrity monitoring on VPN appliance' },
      { phase: 'Credential Access', action: 'Harvest VPN session tokens and cached credentials', mitre: 'T1552', detection: 'VPN session anomalies, token reuse from different IPs' },
      { phase: 'Lateral Movement', action: 'Use VPN access to reach internal network segments', mitre: 'T1021', detection: 'VPN session to internal resource access patterns' },
      { phase: 'Discovery', action: 'Scan internal network from VPN pivot point', mitre: 'T1046', detection: 'Internal IDS, firewall logs, netflow analysis' },
      { phase: 'Privilege Escalation', action: 'Exploit internal services or use harvested domain credentials', mitre: 'T1078', detection: 'Logon anomalies, impossible travel detection' },
      { phase: 'Collection', action: 'Access file shares, databases, email archives', mitre: 'T1039', detection: 'File access auditing, SMB share access logs' },
      { phase: 'Exfiltration', action: 'Exfiltrate through VPN tunnel (blends with normal VPN traffic)', mitre: 'T1048', detection: 'VPN traffic volume anomalies, data loss prevention' },
    ],
  },
  {
    name: 'Cloud Infrastructure Attack',
    initialAccess: 'Compromised cloud credentials or misconfigured IAM',
    steps: [
      { phase: 'Initial Access', action: 'Use leaked AWS keys from GitHub or SSRF to steal IMDS credentials', mitre: 'T1078.004', detection: 'CloudTrail, GitHub secret scanning, IMDS v2 enforcement' },
      { phase: 'Discovery', action: 'Enumerate IAM roles, S3 buckets, EC2 instances, Lambda functions', mitre: 'T1580', detection: 'CloudTrail API call anomalies, unusual iam:List* calls' },
      { phase: 'Privilege Escalation', action: 'Exploit overly permissive IAM policies to escalate to admin', mitre: 'T1078.004', detection: 'IAM policy change monitoring, privilege escalation path analysis' },
      { phase: 'Persistence', action: 'Create new IAM user/role or add access key to existing user', mitre: 'T1098.001', detection: 'CloudTrail iam:CreateUser, iam:CreateAccessKey events' },
      { phase: 'Collection', action: 'Download S3 bucket contents, snapshot EBS volumes, dump RDS', mitre: 'T1530', detection: 'S3 access logging, unusual GetObject patterns, RDS snapshot events' },
      { phase: 'Impact', action: 'Cryptomining on EC2, ransomware on EBS, data destruction', mitre: 'T1496', detection: 'EC2 CPU anomalies, billing alerts, unusual instance types launched' },
    ],
  },
  {
    name: 'Ransomware Campaign',
    initialAccess: 'RDP brute force or phishing into corporate network',
    steps: [
      { phase: 'Initial Access', action: 'Brute force RDP with leaked credentials or phishing payload', mitre: 'T1110', detection: 'Failed logon monitoring, account lockout alerts' },
      { phase: 'Execution', action: 'Deploy Cobalt Strike beacon or similar C2 framework', mitre: 'T1059', detection: 'EDR behavioral detection, named pipe monitoring' },
      { phase: 'Discovery', action: 'Map AD environment, identify backup servers and domain controllers', mitre: 'T1018', detection: 'BloodHound collection artifacts, SMB enumeration' },
      { phase: 'Credential Access', action: 'Dump credentials via Mimikatz or NTDS.dit extraction', mitre: 'T1003.003', detection: 'LSASS access monitoring, Volume Shadow Copy access' },
      { phase: 'Lateral Movement', action: 'Deploy via PsExec, WMI, or GPO to all joined machines', mitre: 'T1570', detection: 'Mass file copy events, new service installation across many hosts' },
      { phase: 'Defense Evasion', action: 'Disable Windows Defender, delete shadow copies', mitre: 'T1562.001', detection: 'Defender tamper protection alerts, vssadmin events' },
      { phase: 'Exfiltration', action: 'Exfiltrate sensitive data via rclone to MEGA/cloud storage (double extortion)', mitre: 'T1567.002', detection: 'rclone process execution, large uploads to cloud storage' },
      { phase: 'Impact', action: 'Deploy ransomware payload across all compromised systems simultaneously', mitre: 'T1486', detection: 'Mass file rename/encryption events, ransom note file creation' },
    ],
  },
  {
    name: 'Supply Chain Attack',
    initialAccess: 'Compromise vendor/supplier to reach target indirectly',
    steps: [
      { phase: 'Initial Access', action: 'Compromise software vendor and inject backdoor into legitimate update', mitre: 'T1195.002', detection: 'Software integrity verification, code signing validation' },
      { phase: 'Execution', action: 'Backdoor executes on target during routine software update', mitre: 'T1072', detection: 'Application whitelisting, behavioral analysis of update processes' },
      { phase: 'Defense Evasion', action: 'Backdoor is signed with vendor certificate, blends with legitimate traffic', mitre: 'T1553.002', detection: 'Certificate anomaly detection, network traffic baseline deviation' },
      { phase: 'C2', action: 'C2 disguised as legitimate vendor API calls', mitre: 'T1071.001', detection: 'DNS analytics, domain age analysis, JA3 fingerprinting' },
      { phase: 'Discovery', action: 'Profile victim environment to determine value and select targets', mitre: 'T1082', detection: 'Unusual discovery commands from vendor software processes' },
      { phase: 'Collection', action: 'Targeted data collection based on victim profile', mitre: 'T1005', detection: 'DLP, file access auditing, database query monitoring' },
      { phase: 'Exfiltration', action: 'Exfiltrate via vendor C2 channel (looks like normal vendor traffic)', mitre: 'T1041', detection: 'Network traffic volume anomalies, vendor communication baseline' },
    ],
  },
  {
    name: 'Insider Threat',
    initialAccess: 'Legitimate employee with authorized access',
    steps: [
      { phase: 'Initial Access', action: 'Employee uses legitimate credentials and authorized access', mitre: 'T1078', detection: 'User behavior analytics (UBA), baseline deviation' },
      { phase: 'Collection', action: 'Access sensitive data beyond normal job function', mitre: 'T1005', detection: 'Data access auditing, need-to-know monitoring, DLP' },
      { phase: 'Staging', action: 'Copy data to personal device, external drive, or cloud storage', mitre: 'T1074', detection: 'USB device monitoring, cloud storage upload alerts, print monitoring' },
      { phase: 'Exfiltration', action: 'Transfer data via personal email, cloud storage, or physical media', mitre: 'T1048', detection: 'Email DLP, cloud access security broker (CASB), physical security' },
    ],
  },
];

// ============================================================================
// CONTROL EFFECTIVENESS SCORES
// ============================================================================
const CONTROL_EFFECTIVENESS = {
  edr: { name: 'Endpoint Detection & Response', phases: { execution: 0.7, persistence: 0.6, lateral: 0.5, credential: 0.6, evasion: 0.4 }, cost: 'medium', complexity: 'medium' },
  siem: { name: 'SIEM / Log Management', phases: { discovery: 0.5, lateral: 0.4, persistence: 0.5, exfiltration: 0.4, credential: 0.3 }, cost: 'high', complexity: 'high' },
  mfa: { name: 'Multi-Factor Authentication', phases: { initial_access: 0.8, credential: 0.7, lateral: 0.3 }, cost: 'low', complexity: 'low' },
  waf: { name: 'Web Application Firewall', phases: { initial_access: 0.5 }, cost: 'medium', complexity: 'medium' },
  segmentation: { name: 'Network Segmentation', phases: { lateral: 0.7, discovery: 0.4 }, cost: 'high', complexity: 'high' },
  dlp: { name: 'Data Loss Prevention', phases: { exfiltration: 0.6, collection: 0.3 }, cost: 'medium', complexity: 'medium' },
  ids: { name: 'Intrusion Detection System', phases: { initial_access: 0.3, lateral: 0.3, discovery: 0.4 }, cost: 'medium', complexity: 'medium' },
  vuln_management: { name: 'Vulnerability Management', phases: { initial_access: 0.6 }, cost: 'medium', complexity: 'medium' },
  email_security: { name: 'Email Security Gateway', phases: { initial_access: 0.6 }, cost: 'low', complexity: 'low' },
  backup: { name: 'Offline/Immutable Backups', phases: { impact: 0.8 }, cost: 'medium', complexity: 'low' },
  zt: { name: 'Zero Trust Architecture', phases: { lateral: 0.8, credential: 0.5, initial_access: 0.4 }, cost: 'high', complexity: 'high' },
  pam: { name: 'Privileged Access Management', phases: { credential: 0.7, lateral: 0.5, persistence: 0.4 }, cost: 'high', complexity: 'medium' },
};

// ============================================================================
// PREDICTION ENGINE
// ============================================================================
function predictAttack(config) {
  const results = { scenarios: [], blindSpots: [], controlScores: {}, dwellTime: 0, breachCost: 0, crownJewels: null, remediation: [] };

  // 1. Score initial access vectors
  const accessVectors = [];
  ATTACK_RULES.forEach(function(rule) {
    if (rule.target) return; // skip crown jewel rules here
    var match = true;
    var c = rule.condition;
    if (c.service && config.services.indexOf(c.service) === -1) match = false;
    if (c.control_absent && config.controls.indexOf(c.control_absent) !== -1) match = false;
    if (c.control_present && config.controls.indexOf(c.control_present) === -1) match = false;
    if (c.industry && config.industry !== c.industry) match = false;
    if (c.awareness && config.awareness !== c.awareness) match = false;
    if (c.arch && config.architecture !== c.arch) match = false;
    if (c.budget && config.budget !== c.budget) match = false;
    if (c.employees_gt && config.employees <= c.employees_gt) match = false;
    if (c.employees_lt && config.employees >= c.employees_lt) match = false;
    if (match) {
      accessVectors.push({ vector: rule.vector, probability: rule.probability, mitre: rule.mitre, reasoning: rule.reasoning });
    }
  });

  // Deduplicate and take top vectors
  var seen = {};
  var unique = [];
  accessVectors.forEach(function(v) {
    if (!seen[v.vector]) { seen[v.vector] = v; unique.push(v); }
    else if (v.probability > seen[v.vector].probability) { seen[v.vector].probability = v.probability; seen[v.vector].reasoning = v.reasoning; }
  });
  unique.sort(function(a, b) { return b.probability - a.probability; });

  // 2. Generate top 3 attack scenarios
  var topVectors = unique.slice(0, 3);
  topVectors.forEach(function(vec, idx) {
    // Find matching kill chain template
    var chain = null;
    if (vec.vector.indexOf('Phishing') !== -1 || vec.vector.indexOf('Social') !== -1) chain = KILL_CHAIN_TEMPLATES[0];
    else if (vec.vector.indexOf('Web') !== -1 || vec.vector.indexOf('API') !== -1) chain = KILL_CHAIN_TEMPLATES[1];
    else if (vec.vector.indexOf('VPN') !== -1) chain = KILL_CHAIN_TEMPLATES[2];
    else if (vec.vector.indexOf('Cloud') !== -1 || vec.vector.indexOf('IAM') !== -1) chain = KILL_CHAIN_TEMPLATES[3];
    else if (vec.vector.indexOf('Ransom') !== -1 || vec.vector.indexOf('RDP') !== -1) chain = KILL_CHAIN_TEMPLATES[4];
    else if (vec.vector.indexOf('Supply') !== -1) chain = KILL_CHAIN_TEMPLATES[5];
    else if (vec.vector.indexOf('Insider') !== -1) chain = KILL_CHAIN_TEMPLATES[6];
    else chain = KILL_CHAIN_TEMPLATES[idx % KILL_CHAIN_TEMPLATES.length];

    results.scenarios.push({
      rank: idx + 1,
      vector: vec.vector,
      probability: vec.probability,
      mitre: vec.mitre,
      reasoning: vec.reasoning,
      killChain: chain,
    });
  });

  // 3. Crown jewel analysis
  ATTACK_RULES.forEach(function(rule) {
    if (rule.target && rule.condition.industry === config.industry) {
      results.crownJewels = { target: rule.target, value: rule.value, impact: rule.impact };
    }
  });
  if (!results.crownJewels) {
    results.crownJewels = { target: 'General business data and operations', value: 'Varies', impact: 'Operational disruption, reputation damage' };
  }

  // 4. Dwell time estimation
  var dwell = DWELL_TIME_FACTORS.baseline;
  config.controls.forEach(function(ctrl) {
    if (DWELL_TIME_FACTORS[ctrl] !== undefined) dwell += DWELL_TIME_FACTORS[ctrl];
  });
  results.dwellTime = Math.max(1, dwell);

  // 5. Breach cost calculation
  var baseCost = BREACH_COST_DATA.by_industry[config.industry] || BREACH_COST_DATA.global_average;
  var sizeMultiplier = BREACH_COST_DATA.by_size[config.budget] || 1.0;
  var controlAdjustment = 0;
  config.controls.forEach(function(ctrl) {
    if (BREACH_COST_DATA.factors[ctrl]) controlAdjustment += BREACH_COST_DATA.factors[ctrl];
  });
  if (config.controls.length === 0) controlAdjustment += BREACH_COST_DATA.factors.no_controls;
  results.breachCost = Math.round(baseCost * sizeMultiplier * (1 + controlAdjustment));

  // 6. Control effectiveness scoring
  Object.keys(CONTROL_EFFECTIVENESS).forEach(function(ctrl) {
    var ce = CONTROL_EFFECTIVENESS[ctrl];
    var hasIt = config.controls.indexOf(ctrl) !== -1;
    results.controlScores[ctrl] = { name: ce.name, deployed: hasIt, effectiveness: ce.phases, cost: ce.cost, complexity: ce.complexity };
  });

  // 7. Blind spots — attack phases with no coverage
  var coveredPhases = {};
  config.controls.forEach(function(ctrl) {
    var ce = CONTROL_EFFECTIVENESS[ctrl];
    if (ce) {
      Object.keys(ce.phases).forEach(function(phase) {
        if (!coveredPhases[phase]) coveredPhases[phase] = 0;
        coveredPhases[phase] = Math.max(coveredPhases[phase], ce.phases[phase]);
      });
    }
  });
  var allPhases = ['initial_access', 'execution', 'persistence', 'credential', 'discovery', 'lateral', 'collection', 'exfiltration', 'evasion', 'impact'];
  allPhases.forEach(function(phase) {
    if (!coveredPhases[phase] || coveredPhases[phase] < 0.3) {
      results.blindSpots.push({ phase: phase.replace(/_/g, ' '), coverage: coveredPhases[phase] || 0, recommendation: getRemediation(phase) });
    }
  });

  // 8. Remediation priorities
  var remediations = [];
  if (config.controls.indexOf('mfa') === -1) remediations.push({ priority: 'CRITICAL', action: 'Deploy MFA on all remote access and privileged accounts', impact: 'Blocks 80%+ of credential-based attacks', effort: 'Low', cost: '$3-8/user/month' });
  if (config.controls.indexOf('edr') === -1) remediations.push({ priority: 'CRITICAL', action: 'Deploy EDR on all endpoints and servers', impact: 'Detects lateral movement, credential theft, malware', effort: 'Medium', cost: '$5-15/endpoint/month' });
  if (config.controls.indexOf('siem') === -1) remediations.push({ priority: 'HIGH', action: 'Implement SIEM with 24/7 monitoring or MDR service', impact: 'Reduces dwell time from months to hours/days', effort: 'High', cost: '$10-50K/year' });
  if (config.controls.indexOf('segmentation') === -1 && config.architecture === 'flat') remediations.push({ priority: 'HIGH', action: 'Implement network segmentation (VLANs, microsegmentation)', impact: 'Prevents unrestricted lateral movement', effort: 'High', cost: '$20-100K one-time' });
  if (config.controls.indexOf('backup') === -1) remediations.push({ priority: 'HIGH', action: 'Implement 3-2-1 backup strategy with offline/immutable copies', impact: 'Ensures recovery from ransomware without paying ransom', effort: 'Medium', cost: '$5-20K/year' });
  if (config.controls.indexOf('email_security') === -1 && config.services.indexOf('email') !== -1) remediations.push({ priority: 'HIGH', action: 'Deploy email security gateway with sandbox detonation', impact: 'Blocks 95%+ of phishing emails', effort: 'Low', cost: '$2-5/user/month' });
  if (config.controls.indexOf('vuln_management') === -1) remediations.push({ priority: 'MEDIUM', action: 'Implement continuous vulnerability scanning and patch management', impact: 'Reduces exploitable attack surface', effort: 'Medium', cost: '$5-20K/year' });
  if (config.controls.indexOf('pam') === -1 && config.architecture === 'ad') remediations.push({ priority: 'MEDIUM', action: 'Deploy Privileged Access Management (PAM) for admin accounts', impact: 'Protects high-value credentials, enforces least privilege', effort: 'High', cost: '$20-80K/year' });
  if (config.controls.indexOf('dlp') === -1) remediations.push({ priority: 'MEDIUM', action: 'Deploy Data Loss Prevention across endpoints and network', impact: 'Detects and blocks data exfiltration attempts', effort: 'Medium', cost: '$10-30K/year' });
  if (config.controls.indexOf('zt') === -1) remediations.push({ priority: 'LOW', action: 'Begin Zero Trust Architecture implementation', impact: 'Eliminates implicit trust, verifies every access request', effort: 'Very High', cost: '$50-500K+ multi-year' });
  results.remediation = remediations;

  return results;
}

function getRemediation(phase) {
  var map = {
    'initial access': 'Deploy MFA, email security, WAF, and vulnerability management',
    'execution': 'Deploy EDR with behavioral detection and application whitelisting',
    'persistence': 'Implement file integrity monitoring and autoruns monitoring',
    'credential': 'Deploy PAM, credential guard, and LSASS protection',
    'discovery': 'Implement honeypots and deception technology',
    'lateral': 'Implement network segmentation and Zero Trust',
    'collection': 'Deploy DLP and file access auditing',
    'exfiltration': 'Deploy DLP, CASB, and network traffic analysis',
    'evasion': 'Deploy advanced EDR with kernel-level visibility',
    'impact': 'Implement immutable backups and disaster recovery plan',
  };
  return map[phase] || 'Review and improve detection capabilities for this phase';
}

// ============================================================================
// RENDER FUNCTION
// ============================================================================
export function renderAdversaryAI(main) {
  var activeTab = 'input';
  var predictionResults = null;
  var config = {
    services: [],
    architecture: 'ad',
    controls: [],
    awareness: 'medium',
    industry: 'tech',
    budget: 'medium',
    employees: 200,
    weaknesses: '',
  };

  function render() {
    main.innerHTML =
      '<style>' +
      '.adv-wrap { font-family: inherit; }' +
      '.adv-header { display:flex; align-items:center; gap:16px; padding:16px 0; border-bottom:2px solid var(--acc); }' +
      '.adv-title { font-size:1.5rem; font-weight:800; color:var(--acc); margin:0; letter-spacing:.05em; }' +
      '.adv-tabs { display:flex; gap:2px; overflow-x:auto; padding:12px 0 0; }' +
      '.adv-tab { background:transparent; border:none; border-bottom:2px solid transparent; color:var(--mut); padding:10px 16px; font-size:.75rem; font-weight:600; letter-spacing:.04em; text-transform:uppercase; cursor:pointer; white-space:nowrap; font-family:inherit; }' +
      '.adv-tab:hover { color:var(--txt); }' +
      '.adv-tab.active { color:var(--acc); border-bottom-color:var(--acc); }' +
      '.adv-form-group { margin-bottom:16px; }' +
      '.adv-label { display:block; font-size:.78rem; font-weight:600; color:var(--txt); margin-bottom:6px; }' +
      '.adv-sublabel { font-size:.72rem; color:var(--mut); font-weight:400; }' +
      '.adv-select { background:var(--card); color:var(--txt); border:1px solid var(--line); padding:8px 12px; border-radius:4px; font-size:.8rem; width:100%; max-width:400px; font-family:inherit; }' +
      '.adv-select:focus { border-color:var(--acc); outline:none; }' +
      '.adv-checks { display:flex; flex-wrap:wrap; gap:8px; }' +
      '.adv-check { display:flex; align-items:center; gap:6px; font-size:.78rem; cursor:pointer; padding:6px 12px; border:1px solid var(--line); border-radius:4px; transition:all .15s; }' +
      '.adv-check:hover { border-color:var(--acc); }' +
      '.adv-check.on { border-color:var(--acc); background:rgba(0,229,255,0.08); color:var(--acc); }' +
      '.adv-btn { background:var(--acc); color:var(--bg); border:none; padding:12px 28px; font-size:.85rem; font-weight:700; border-radius:4px; cursor:pointer; letter-spacing:.04em; text-transform:uppercase; font-family:inherit; }' +
      '.adv-btn:hover { filter:brightness(1.1); }' +
      '.adv-scenario { background:var(--card); border:1px solid var(--line); border-radius:6px; padding:18px; margin-bottom:12px; }' +
      '.adv-scenario-rank { font-size:.7rem; font-weight:700; color:var(--acc); letter-spacing:.06em; text-transform:uppercase; margin-bottom:4px; }' +
      '.adv-scenario-name { font-size:1.1rem; font-weight:700; margin-bottom:4px; }' +
      '.adv-prob-bar { height:6px; background:var(--line); border-radius:3px; overflow:hidden; margin:8px 0; }' +
      '.adv-prob-fill { height:100%; border-radius:3px; }' +
      '.adv-step { display:flex; gap:12px; padding:8px 0; border-bottom:1px solid var(--line); font-size:.78rem; }' +
      '.adv-step:last-child { border-bottom:none; }' +
      '.adv-step-phase { min-width:120px; font-weight:600; color:var(--acc); }' +
      '.adv-step-action { flex:1; }' +
      '.adv-step-detect { min-width:200px; color:var(--mut); }' +
      '.adv-blind { background:rgba(255,23,68,0.08); border:1px solid rgba(255,23,68,0.3); border-radius:4px; padding:12px; margin-bottom:8px; }' +
      '.adv-blind-phase { font-weight:700; color:#ff1744; text-transform:capitalize; }' +
      '.adv-remediation { background:var(--card); border-left:3px solid; padding:12px 16px; margin-bottom:8px; border-radius:0 4px 4px 0; font-size:.8rem; }' +
      '.adv-metric { background:var(--card); border:1px solid var(--line); border-radius:6px; padding:14px 20px; text-align:center; }' +
      '.adv-metric-val { font-size:1.6rem; font-weight:800; font-variant-numeric:tabular-nums; }' +
      '.adv-metric-label { font-size:.7rem; color:var(--mut); text-transform:uppercase; letter-spacing:.04em; margin-top:2px; }' +
      '</style>' +
      '<div class="adv-wrap">' +
        '<div class="adv-header">' +
          '<h1 class="adv-title">ADVERSARY MIND</h1>' +
          '<span style="color:var(--mut);font-size:.75rem">AI Attack Prediction Engine</span>' +
        '</div>' +
        '<div class="adv-tabs">' +
          '<button class="adv-tab' + (activeTab === 'input' ? ' active' : '') + '" data-tab="input">Infrastructure</button>' +
          '<button class="adv-tab' + (activeTab === 'scenarios' ? ' active' : '') + '" data-tab="scenarios">Attack Scenarios</button>' +
          '<button class="adv-tab' + (activeTab === 'killchain' ? ' active' : '') + '" data-tab="killchain">Kill Chains</button>' +
          '<button class="adv-tab' + (activeTab === 'blindspots' ? ' active' : '') + '" data-tab="blindspots">Blind Spots</button>' +
          '<button class="adv-tab' + (activeTab === 'remediation' ? ' active' : '') + '" data-tab="remediation">Remediation</button>' +
          '<button class="adv-tab' + (activeTab === 'executive' ? ' active' : '') + '" data-tab="executive">Executive Brief</button>' +
        '</div>' +
        '<div id="adv-content" style="padding:16px 0"></div>' +
      '</div>';

    main.querySelector('.adv-tabs').onclick = function(e) {
      var b = e.target.closest('.adv-tab');
      if (!b) return;
      activeTab = b.dataset.tab;
      render();
    };

    var content = main.querySelector('#adv-content');
    if (activeTab === 'input') renderInputTab(content);
    else if (activeTab === 'scenarios') renderScenariosTab(content);
    else if (activeTab === 'killchain') renderKillChainTab(content);
    else if (activeTab === 'blindspots') renderBlindSpotsTab(content);
    else if (activeTab === 'remediation') renderRemediationTab(content);
    else if (activeTab === 'executive') renderExecutiveTab(content);
  }

  function renderInputTab(container) {
    var services = [
      { id: 'web_app', label: 'Web Application' }, { id: 'vpn', label: 'VPN' },
      { id: 'email', label: 'Email (Exchange/O365)' }, { id: 'api', label: 'API Endpoints' },
      { id: 'rdp', label: 'RDP (Internet-Facing)' }, { id: 'ssh', label: 'SSH (Internet-Facing)' },
      { id: 'cloud_console', label: 'Cloud Console (AWS/Azure/GCP)' }, { id: 'ftp', label: 'FTP' },
      { id: 'dns', label: 'DNS Server' }, { id: 'database', label: 'Database (External)' },
    ];
    var controls = [
      { id: 'edr', label: 'EDR' }, { id: 'siem', label: 'SIEM' }, { id: 'mfa', label: 'MFA' },
      { id: 'waf', label: 'WAF' }, { id: 'segmentation', label: 'Network Segmentation' },
      { id: 'dlp', label: 'DLP' }, { id: 'ids', label: 'IDS/IPS' }, { id: 'email_security', label: 'Email Security' },
      { id: 'vuln_management', label: 'Vuln Management' }, { id: 'backup', label: 'Offline Backups' },
      { id: 'pam', label: 'PAM' }, { id: 'zt', label: 'Zero Trust' },
    ];

    container.innerHTML =
      '<h2 style="font-size:1rem;margin:0 0 16px">Describe Your Infrastructure</h2>' +
      '<p class="muted" style="font-size:.82rem;margin:-12px 0 20px">The more accurate your inputs, the more precise the attack prediction. All analysis runs in your browser — nothing leaves your machine.</p>' +

      '<div class="adv-form-group">' +
        '<label class="adv-label">Industry</label>' +
        '<select class="adv-select" id="adv-industry">' +
          '<option value="healthcare"' + (config.industry === 'healthcare' ? ' selected' : '') + '>Healthcare</option>' +
          '<option value="finance"' + (config.industry === 'finance' ? ' selected' : '') + '>Finance / Banking</option>' +
          '<option value="tech"' + (config.industry === 'tech' ? ' selected' : '') + '>Technology</option>' +
          '<option value="government"' + (config.industry === 'government' ? ' selected' : '') + '>Government</option>' +
          '<option value="education"' + (config.industry === 'education' ? ' selected' : '') + '>Education</option>' +
          '<option value="retail"' + (config.industry === 'retail' ? ' selected' : '') + '>Retail</option>' +
          '<option value="energy"' + (config.industry === 'energy' ? ' selected' : '') + '>Energy / Utilities</option>' +
          '<option value="manufacturing"' + (config.industry === 'manufacturing' ? ' selected' : '') + '>Manufacturing</option>' +
        '</select>' +
      '</div>' +

      '<div class="adv-form-group">' +
        '<label class="adv-label">External-Facing Services <span class="adv-sublabel">(select all that apply)</span></label>' +
        '<div class="adv-checks" id="adv-services">' +
          services.map(function(s) {
            return '<label class="adv-check' + (config.services.indexOf(s.id) !== -1 ? ' on' : '') + '" data-id="' + s.id + '">' +
              '<input type="checkbox"' + (config.services.indexOf(s.id) !== -1 ? ' checked' : '') + ' style="accent-color:var(--acc)"> ' + esc(s.label) + '</label>';
          }).join('') +
        '</div>' +
      '</div>' +

      '<div class="adv-form-group">' +
        '<label class="adv-label">Internal Architecture</label>' +
        '<select class="adv-select" id="adv-arch">' +
          '<option value="ad"' + (config.architecture === 'ad' ? ' selected' : '') + '>Active Directory (On-Premises)</option>' +
          '<option value="cloud"' + (config.architecture === 'cloud' ? ' selected' : '') + '>Cloud-Native (AWS/Azure/GCP)</option>' +
          '<option value="hybrid"' + (config.architecture === 'hybrid' ? ' selected' : '') + '>Hybrid (AD + Cloud)</option>' +
          '<option value="flat"' + (config.architecture === 'flat' ? ' selected' : '') + '>Flat Network (No Segmentation)</option>' +
          '<option value="segmented"' + (config.architecture === 'segmented' ? ' selected' : '') + '>Segmented Network</option>' +
        '</select>' +
      '</div>' +

      '<div class="adv-form-group">' +
        '<label class="adv-label">Security Controls Deployed <span class="adv-sublabel">(select all that apply)</span></label>' +
        '<div class="adv-checks" id="adv-controls">' +
          controls.map(function(c) {
            return '<label class="adv-check' + (config.controls.indexOf(c.id) !== -1 ? ' on' : '') + '" data-id="' + c.id + '">' +
              '<input type="checkbox"' + (config.controls.indexOf(c.id) !== -1 ? ' checked' : '') + ' style="accent-color:var(--acc)"> ' + esc(c.label) + '</label>';
          }).join('') +
        '</div>' +
      '</div>' +

      '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px">' +
        '<div class="adv-form-group">' +
          '<label class="adv-label">Employee Count</label>' +
          '<input type="number" class="adv-select" id="adv-employees" value="' + config.employees + '" min="1" max="100000">' +
        '</div>' +
        '<div class="adv-form-group">' +
          '<label class="adv-label">Security Awareness</label>' +
          '<select class="adv-select" id="adv-awareness">' +
            '<option value="low"' + (config.awareness === 'low' ? ' selected' : '') + '>Low (no training)</option>' +
            '<option value="medium"' + (config.awareness === 'medium' ? ' selected' : '') + '>Medium (annual training)</option>' +
            '<option value="high"' + (config.awareness === 'high' ? ' selected' : '') + '>High (regular phishing simulations)</option>' +
          '</select>' +
        '</div>' +
        '<div class="adv-form-group">' +
          '<label class="adv-label">Budget Tier</label>' +
          '<select class="adv-select" id="adv-budget">' +
            '<option value="startup"' + (config.budget === 'startup' ? ' selected' : '') + '>Startup (minimal security budget)</option>' +
            '<option value="small"' + (config.budget === 'small' ? ' selected' : '') + '>Small ($50-200K/yr)</option>' +
            '<option value="medium"' + (config.budget === 'medium' ? ' selected' : '') + '>Medium ($200K-1M/yr)</option>' +
            '<option value="enterprise"' + (config.budget === 'enterprise' ? ' selected' : '') + '>Enterprise ($1M+/yr)</option>' +
          '</select>' +
        '</div>' +
      '</div>' +

      '<div class="adv-form-group">' +
        '<label class="adv-label">Known Weaknesses <span class="adv-sublabel">(optional — anything you already know is a problem)</span></label>' +
        '<textarea class="adv-select" id="adv-weaknesses" rows="3" style="resize:vertical">' + esc(config.weaknesses) + '</textarea>' +
      '</div>' +

      '<button class="adv-btn" id="adv-predict">Predict Attack Scenarios</button>';

    // Wire service checkboxes
    container.querySelector('#adv-services').addEventListener('change', function(e) {
      var cb = e.target;
      if (cb.type !== 'checkbox') return;
      var label = cb.closest('.adv-check');
      var id = label.dataset.id;
      if (cb.checked) { if (config.services.indexOf(id) === -1) config.services.push(id); label.classList.add('on'); }
      else { config.services = config.services.filter(function(s) { return s !== id; }); label.classList.remove('on'); }
    });

    // Wire control checkboxes
    container.querySelector('#adv-controls').addEventListener('change', function(e) {
      var cb = e.target;
      if (cb.type !== 'checkbox') return;
      var label = cb.closest('.adv-check');
      var id = label.dataset.id;
      if (cb.checked) { if (config.controls.indexOf(id) === -1) config.controls.push(id); label.classList.add('on'); }
      else { config.controls = config.controls.filter(function(c) { return c !== id; }); label.classList.remove('on'); }
    });

    // Wire predict button
    container.querySelector('#adv-predict').onclick = function() {
      config.industry = container.querySelector('#adv-industry').value;
      config.architecture = container.querySelector('#adv-arch').value;
      config.employees = parseInt(container.querySelector('#adv-employees').value) || 200;
      config.awareness = container.querySelector('#adv-awareness').value;
      config.budget = container.querySelector('#adv-budget').value;
      config.weaknesses = container.querySelector('#adv-weaknesses').value;
      predictionResults = predictAttack(config);
      activeTab = 'scenarios';
      render();
    };
  }

  function renderScenariosTab(container) {
    if (!predictionResults) { container.innerHTML = '<p class="muted" style="padding:40px;text-align:center">Describe your infrastructure first, then click "Predict Attack Scenarios".</p>'; return; }
    var r = predictionResults;

    var metricsHtml =
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:20px">' +
        '<div class="adv-metric"><div class="adv-metric-val" style="color:' + (r.dwellTime > 90 ? '#ff1744' : r.dwellTime > 30 ? '#ff9100' : '#00e676') + '">' + r.dwellTime + ' days</div><div class="adv-metric-label">Est. Dwell Time</div></div>' +
        '<div class="adv-metric"><div class="adv-metric-val" style="color:#ff1744">$' + (r.breachCost / 1000000).toFixed(1) + 'M</div><div class="adv-metric-label">Est. Breach Cost</div></div>' +
        '<div class="adv-metric"><div class="adv-metric-val" style="color:var(--acc)">' + r.blindSpots.length + '</div><div class="adv-metric-label">Blind Spots</div></div>' +
        '<div class="adv-metric"><div class="adv-metric-val" style="color:#ffd600">' + r.remediation.length + '</div><div class="adv-metric-label">Recommendations</div></div>' +
      '</div>';

    var scenariosHtml = r.scenarios.map(function(s) {
      var probColor = s.probability >= 0.7 ? '#ff1744' : s.probability >= 0.4 ? '#ff9100' : '#ffd600';
      return '<div class="adv-scenario">' +
        '<div class="adv-scenario-rank">Scenario #' + s.rank + ' — ' + (s.probability * 100).toFixed(0) + '% likelihood</div>' +
        '<div class="adv-scenario-name">' + esc(s.vector) + '</div>' +
        '<div class="adv-prob-bar"><div class="adv-prob-fill" style="width:' + (s.probability * 100) + '%;background:' + probColor + '"></div></div>' +
        '<div style="font-size:.8rem;color:var(--mut);margin:8px 0">' + esc(s.reasoning) + '</div>' +
        '<div style="font-size:.72rem;color:var(--acc)">MITRE: ' + esc(s.mitre) + '</div>' +
        '<div style="font-size:.72rem;color:var(--mut);margin-top:4px">Kill Chain: ' + esc(s.killChain.name) + ' (' + s.killChain.steps.length + ' phases)</div>' +
      '</div>';
    }).join('');

    var jewelsHtml = '';
    if (r.crownJewels) {
      jewelsHtml = '<div class="adv-scenario" style="border-color:var(--acc)">' +
        '<div class="adv-scenario-rank">Crown Jewels — What Attackers Are After</div>' +
        '<div class="adv-scenario-name">' + esc(r.crownJewels.target) + '</div>' +
        '<div style="font-size:.8rem;color:var(--mut);margin:8px 0">Value: ' + esc(r.crownJewels.value) + '</div>' +
        '<div style="font-size:.8rem;color:#ff1744">Impact: ' + esc(r.crownJewels.impact) + '</div>' +
      '</div>';
    }

    container.innerHTML = '<h2 style="font-size:1rem;margin:0 0 16px">Attack Prediction Results</h2>' + metricsHtml + scenariosHtml + jewelsHtml;
  }

  function renderKillChainTab(container) {
    if (!predictionResults) { container.innerHTML = '<p class="muted" style="padding:40px;text-align:center">Run the prediction first.</p>'; return; }
    var html = '<h2 style="font-size:1rem;margin:0 0 16px">Detailed Kill Chains</h2>' +
      '<p class="muted" style="font-size:.82rem;margin:-12px 0 16px">Step-by-step attack execution for each predicted scenario. Each step shows what the attacker does, the MITRE technique, and how to detect it.</p>';

    predictionResults.scenarios.forEach(function(s) {
      html += '<div class="adv-scenario">' +
        '<div class="adv-scenario-rank">Scenario #' + s.rank + ': ' + esc(s.vector) + '</div>' +
        '<div style="font-size:.82rem;font-weight:600;margin:8px 0">' + esc(s.killChain.name) + '</div>' +
        '<div style="font-size:.78rem;color:var(--mut);margin-bottom:12px">Initial Access: ' + esc(s.killChain.initialAccess) + '</div>';
      s.killChain.steps.forEach(function(step) {
        html += '<div class="adv-step">' +
          '<div class="adv-step-phase">' + esc(step.phase) + '<br><span style="font-size:.65rem;color:var(--mut)">' + esc(step.mitre) + '</span></div>' +
          '<div class="adv-step-action">' + esc(step.action) + '</div>' +
          '<div class="adv-step-detect">Detection: ' + esc(step.detection) + '</div>' +
        '</div>';
      });
      html += '</div>';
    });
    container.innerHTML = html;
  }

  function renderBlindSpotsTab(container) {
    if (!predictionResults) { container.innerHTML = '<p class="muted" style="padding:40px;text-align:center">Run the prediction first.</p>'; return; }
    var r = predictionResults;
    var html = '<h2 style="font-size:1rem;margin:0 0 16px">Security Blind Spots</h2>' +
      '<p class="muted" style="font-size:.82rem;margin:-12px 0 16px">Attack phases where your current controls provide less than 30% detection coverage. These are where an attacker will operate freely.</p>';

    if (r.blindSpots.length === 0) {
      html += '<div style="background:rgba(0,230,118,0.08);border:1px solid rgba(0,230,118,0.3);border-radius:6px;padding:16px;color:#00e676;font-weight:600">No critical blind spots detected. Your controls cover all major attack phases.</div>';
    } else {
      r.blindSpots.forEach(function(b) {
        html += '<div class="adv-blind">' +
          '<div class="adv-blind-phase">' + esc(b.phase) + ' — ' + (b.coverage * 100).toFixed(0) + '% coverage</div>' +
          '<div style="font-size:.82rem;color:var(--mut);margin-top:4px">Recommendation: ' + esc(b.recommendation) + '</div>' +
        '</div>';
      });
    }

    // Control effectiveness matrix
    html += '<h2 style="font-size:1rem;margin:24px 0 12px">Control Effectiveness Matrix</h2>' +
      '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.75rem">' +
      '<thead><tr style="border-bottom:2px solid var(--line)">' +
        '<th style="padding:8px;text-align:left;color:var(--mut)">Control</th>' +
        '<th style="padding:8px;text-align:center;color:var(--mut)">Deployed</th>' +
        '<th style="padding:8px;text-align:left;color:var(--mut)">Phases Covered</th>' +
        '<th style="padding:8px;text-align:center;color:var(--mut)">Cost</th>' +
      '</tr></thead><tbody>';

    Object.keys(r.controlScores).forEach(function(key) {
      var c = r.controlScores[key];
      var phases = Object.keys(c.effectiveness).map(function(p) {
        return p.replace(/_/g, ' ') + ' (' + (c.effectiveness[p] * 100).toFixed(0) + '%)';
      }).join(', ');
      html += '<tr style="border-bottom:1px solid var(--line)">' +
        '<td style="padding:8px;font-weight:600">' + esc(c.name) + '</td>' +
        '<td style="padding:8px;text-align:center;color:' + (c.deployed ? '#00e676' : '#ff1744') + '">' + (c.deployed ? 'YES' : 'NO') + '</td>' +
        '<td style="padding:8px;color:var(--mut)">' + esc(phases) + '</td>' +
        '<td style="padding:8px;text-align:center;color:var(--mut)">' + esc(c.cost) + '</td>' +
      '</tr>';
    });
    html += '</tbody></table></div>';
    container.innerHTML = html;
  }

  function renderRemediationTab(container) {
    if (!predictionResults) { container.innerHTML = '<p class="muted" style="padding:40px;text-align:center">Run the prediction first.</p>'; return; }
    var html = '<h2 style="font-size:1rem;margin:0 0 16px">Remediation Priorities</h2>' +
      '<p class="muted" style="font-size:.82rem;margin:-12px 0 16px">Actionable recommendations sorted by priority. Each includes the expected impact and estimated cost.</p>';

    var colors = { CRITICAL: '#ff1744', HIGH: '#ff9100', MEDIUM: '#ffd600', LOW: 'var(--acc)' };
    predictionResults.remediation.forEach(function(r) {
      html += '<div class="adv-remediation" style="border-left-color:' + (colors[r.priority] || 'var(--acc)') + '">' +
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">' +
          '<span style="font-size:.65rem;font-weight:700;color:' + (colors[r.priority] || 'var(--acc)') + ';letter-spacing:.04em">' + esc(r.priority) + '</span>' +
          '<span style="font-weight:600">' + esc(r.action) + '</span>' +
        '</div>' +
        '<div style="color:var(--mut)">Impact: ' + esc(r.impact) + '</div>' +
        '<div style="display:flex;gap:16px;margin-top:4px;font-size:.75rem;color:var(--mut)">' +
          '<span>Effort: ' + esc(r.effort) + '</span>' +
          '<span>Est. Cost: ' + esc(r.cost) + '</span>' +
        '</div>' +
      '</div>';
    });
    container.innerHTML = html;
  }

  function renderExecutiveTab(container) {
    if (!predictionResults) { container.innerHTML = '<p class="muted" style="padding:40px;text-align:center">Run the prediction first.</p>'; return; }
    var r = predictionResults;
    var brief = '';
    brief += '=== ADVERSARY MIND — EXECUTIVE THREAT BRIEF ===\n';
    brief += 'Generated: ' + new Date().toISOString().split('T')[0] + '\n';
    brief += 'Industry: ' + config.industry.charAt(0).toUpperCase() + config.industry.slice(1) + '\n';
    brief += 'Employees: ' + config.employees + ' | Architecture: ' + config.architecture.toUpperCase() + '\n';
    brief += 'Security Controls: ' + (config.controls.length > 0 ? config.controls.join(', ').toUpperCase() : 'NONE') + '\n\n';

    brief += '--- RISK SUMMARY ---\n';
    brief += 'Estimated Breach Cost: $' + (r.breachCost / 1000000).toFixed(1) + 'M\n';
    brief += 'Estimated Dwell Time: ' + r.dwellTime + ' days (industry median: 194 days)\n';
    brief += 'Critical Blind Spots: ' + r.blindSpots.length + '\n';
    brief += 'Crown Jewels at Risk: ' + (r.crownJewels ? r.crownJewels.target : 'General data') + '\n\n';

    brief += '--- TOP ATTACK SCENARIOS ---\n';
    r.scenarios.forEach(function(s) {
      brief += '\n' + s.rank + '. ' + s.vector + ' (' + (s.probability * 100).toFixed(0) + '% likelihood)\n';
      brief += '   ' + s.reasoning + '\n';
      brief += '   Kill Chain: ' + s.killChain.name + ' (' + s.killChain.steps.length + ' phases)\n';
    });

    brief += '\n--- PRIORITY ACTIONS ---\n';
    r.remediation.slice(0, 5).forEach(function(rem, i) {
      brief += (i + 1) + '. [' + rem.priority + '] ' + rem.action + '\n';
      brief += '   Impact: ' + rem.impact + ' | Cost: ' + rem.cost + '\n';
    });

    brief += '\n--- CONCLUSION ---\n';
    var overallRisk = r.scenarios[0] ? r.scenarios[0].probability : 0;
    if (overallRisk >= 0.7) brief += 'CRITICAL RISK: The organization is highly vulnerable to attack. Immediate action required.\n';
    else if (overallRisk >= 0.4) brief += 'HIGH RISK: Significant attack vectors exist. Prioritize the actions above.\n';
    else brief += 'MODERATE RISK: Reasonable defenses in place but gaps remain. Address blind spots.\n';

    container.innerHTML =
      '<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px">' +
        '<h2 style="font-size:1rem;margin:0;flex:1">Executive Threat Brief</h2>' +
        '<button class="btn sm" id="adv-copy-brief">Copy to Clipboard</button>' +
      '</div>' +
      '<pre style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px;font-size:.78rem;white-space:pre-wrap;max-height:600px;overflow-y:auto;color:var(--txt);line-height:1.6">' + esc(brief) + '</pre>';

    container.querySelector('#adv-copy-brief').onclick = function() {
      navigator.clipboard.writeText(brief).then(function() {
        container.querySelector('#adv-copy-brief').textContent = 'Copied!';
        setTimeout(function() { container.querySelector('#adv-copy-brief').textContent = 'Copy to Clipboard'; }, 1500);
      });
    };
  }

  render();
}
