// Deception Architect — Build Honeypots, Honeytokens, and Tripwires
// Design and deploy deception technology to detect attackers early.
// Copyright (c) 2026 Darknode-Official. All rights reserved.

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// =============================================================================
// HONEYPOT TEMPLATES
// =============================================================================
const HONEYPOT_TEMPLATES = [
  {
    name: 'SSH Honeypot',
    type: 'network',
    desc: 'Emulates an SSH server that logs all connection attempts, credentials, and commands. Attracts brute-force attacks and reveals attacker TTPs.',
    tools: ['Cowrie', 'Kippo', 'ssh-honeypot'],
    ports: [22, 2222],
    attackerBehavior: ['Brute force credentials (root:root, admin:admin)', 'Download malware via wget/curl', 'Enumerate system info (uname, id, ifconfig)', 'Install cryptocurrency miners', 'Attempt lateral movement', 'Plant SSH keys for persistence'],
    dockerCompose: 'version: "3"\nservices:\n  cowrie:\n    image: cowrie/cowrie:latest\n    ports:\n      - "2222:2222"\n    volumes:\n      - ./cowrie-logs:/cowrie/cowrie-git/var/log/cowrie\n    environment:\n      - COWRIE_TELNET_ENABLED=no\n    restart: unless-stopped',
    siemRule: 'index=honeypot sourcetype=cowrie | stats count by src_ip session commands | where count > 0 | table _time src_ip session commands',
    detectionValue: 'Any connection to this host is suspicious by definition — zero false positives',
    mitre: ['T1110', 'T1021.004', 'T1059'],
  },
  {
    name: 'Web Application Honeypot',
    type: 'network',
    desc: 'Fake web application with login forms, admin panels, and intentional vulnerabilities. Captures SQLi, XSS, and credential stuffing attempts.',
    tools: ['SNARE/TANNER', 'Glastopf', 'HoneyPress (WordPress)'],
    ports: [80, 443, 8080],
    attackerBehavior: ['Directory brute force (/admin, /wp-admin, /phpmyadmin)', 'SQL injection attempts in forms and parameters', 'XSS payload injection', 'Credential stuffing with leaked databases', 'Web shell upload attempts', 'API abuse and scraping'],
    dockerCompose: 'version: "3"\nservices:\n  snare:\n    image: mushorg/snare:latest\n    ports:\n      - "8080:8080"\n    command: snare --port 8080 --page-dir pages\n    restart: unless-stopped\n  tanner:\n    image: mushorg/tanner:latest\n    ports:\n      - "8090:8090"\n    restart: unless-stopped',
    siemRule: 'index=honeypot sourcetype=snare | stats count values(path) values(method) by src_ip | sort -count',
    detectionValue: 'Reveals attacker tools, techniques, and payloads before they hit real applications',
    mitre: ['T1190', 'T1110.001', 'T1059.007'],
  },
  {
    name: 'Database Honeypot',
    type: 'network',
    desc: 'Fake database server (MySQL/MSSQL/PostgreSQL) with seeded fake data. Detects unauthorized database access and data exfiltration attempts.',
    tools: ['HoneyDB', 'mysql-honeypotd', 'Elastichoney'],
    ports: [3306, 1433, 5432],
    attackerBehavior: ['Credential brute force', 'Query system tables (information_schema)', 'Attempt to enable xp_cmdshell (MSSQL)', 'Data dumping (SELECT * FROM users)', 'Privilege escalation attempts', 'Ransomware encryption of databases'],
    dockerCompose: 'version: "3"\nservices:\n  mysql-honeypot:\n    image: mysql:5.7\n    ports:\n      - "3306:3306"\n    environment:\n      - MYSQL_ROOT_PASSWORD=weakpassword\n      - MYSQL_DATABASE=customers\n    volumes:\n      - ./seed-data.sql:/docker-entrypoint-initdb.d/seed.sql\n      - ./mysql-logs:/var/log/mysql\n    command: --general-log=1 --general-log-file=/var/log/mysql/general.log\n    restart: unless-stopped',
    siemRule: 'index=honeypot sourcetype=mysql_general | search NOT user="honeypot_monitor" | stats count values(query) by src_ip user',
    detectionValue: 'Any query to this database indicates an attacker has penetrated the network and is accessing data stores',
    mitre: ['T1110', 'T1005', 'T1213'],
  },
  {
    name: 'File Share Honeypot',
    type: 'network',
    desc: 'Fake SMB/NFS share with seeded documents (fake credentials, network diagrams, sensitive data). Detects lateral movement and data discovery.',
    tools: ['OpenCanary', 'Honeyd', 'Samba with audit logging'],
    ports: [445, 139, 2049],
    attackerBehavior: ['SMB share enumeration', 'Access to "IT_Backup" or "HR_Confidential" shares', 'Download bait documents', 'Attempt to plant ransomware or web shells', 'Credential harvesting from .env files'],
    dockerCompose: 'version: "3"\nservices:\n  samba-honeypot:\n    image: dperson/samba\n    ports:\n      - "445:445"\n    volumes:\n      - ./bait-files:/shares/IT_Backup\n    command: -s "IT_Backup;/shares/IT_Backup;yes;no;no;guest"\n    restart: unless-stopped',
    siemRule: 'index=honeypot sourcetype=samba_audit | stats count values(file) by src_ip user action | sort -count',
    detectionValue: 'Detects lateral movement — any access means attacker is inside the network and browsing file shares',
    mitre: ['T1021.002', 'T1039', 'T1083'],
  },
  {
    name: 'RDP Honeypot',
    type: 'network',
    desc: 'Fake Windows RDP server. Captures brute force attempts, records sessions, and detects BlueKeep/other RDP exploits.',
    tools: ['RDPY', 'PyRDP', 'HoneyPy'],
    ports: [3389],
    attackerBehavior: ['RDP brute force', 'BlueKeep exploitation attempts', 'NLA bypass attempts', 'Session recording reveals attacker actions', 'Credential harvesting'],
    dockerCompose: 'version: "3"\nservices:\n  rdp-honeypot:\n    image: gosecure/pyrdp:latest\n    ports:\n      - "3389:3389"\n    volumes:\n      - ./rdp-logs:/home/pyrdp/log\n      - ./rdp-replays:/home/pyrdp/replays\n    restart: unless-stopped',
    siemRule: 'index=honeypot sourcetype=rdp_honeypot | stats count by src_ip credentials success | sort -count',
    detectionValue: 'Records full RDP sessions — see exactly what the attacker does on a Windows desktop',
    mitre: ['T1110', 'T1021.001', 'T1210'],
  },
  {
    name: 'IoT Device Honeypot',
    type: 'network',
    desc: 'Emulates vulnerable IoT devices (cameras, routers, printers). Attracts Mirai-variant botnets and IoT-specific exploits.',
    tools: ['IoTPOT', 'HoneyThing', 'Dionaea'],
    ports: [23, 80, 8443, 554],
    attackerBehavior: ['Telnet brute force with default IoT credentials', 'Mirai-style infection attempts', 'UPnP exploitation', 'Firmware download/upload attempts', 'Botnet recruitment commands'],
    dockerCompose: 'version: "3"\nservices:\n  dionaea:\n    image: dinotools/dionaea:latest\n    ports:\n      - "23:23"\n      - "80:80"\n      - "8443:8443"\n    volumes:\n      - ./dionaea-logs:/opt/dionaea/var/log\n    restart: unless-stopped',
    siemRule: 'index=honeypot sourcetype=dionaea | stats count values(protocol) values(payload_md5) by src_ip | sort -count',
    detectionValue: 'Catches automated botnet scanning and IoT-targeted malware in your network',
    mitre: ['T1110', 'T1059', 'T1583.005'],
  },
  {
    name: 'Email/SMTP Honeypot',
    type: 'network',
    desc: 'Fake mail server that accepts all email. Catches spam, phishing probes, and open relay scanning.',
    tools: ['mailoney', 'shiva', 'smtp-honeypot'],
    ports: [25, 587],
    attackerBehavior: ['Open relay testing', 'SMTP VRFY/EXPN user enumeration', 'Spam relay attempts', 'Phishing email delivery testing', 'SMTP authentication brute force'],
    dockerCompose: 'version: "3"\nservices:\n  mailhoney:\n    image: phin3has/mailoney:latest\n    ports:\n      - "25:25"\n    volumes:\n      - ./mail-logs:/logs\n    restart: unless-stopped',
    siemRule: 'index=honeypot sourcetype=smtp_honeypot | stats count values(mail_from) values(rcpt_to) by src_ip | sort -count',
    detectionValue: 'Detects email infrastructure reconnaissance and open relay abuse',
    mitre: ['T1589.002', 'T1566'],
  },
  {
    name: 'DNS Honeypot',
    type: 'network',
    desc: 'Fake DNS server that logs all queries. Detects DNS tunneling, C2 beaconing, and reconnaissance.',
    tools: ['dns-honeypot', 'Heralding'],
    ports: [53],
    attackerBehavior: ['DNS enumeration (zone transfer attempts)', 'DNS tunneling for C2/exfiltration', 'Cache poisoning attempts', 'Subdomain brute force', 'DGA domain resolution'],
    dockerCompose: 'version: "3"\nservices:\n  dns-honeypot:\n    image: heralding/heralding:latest\n    ports:\n      - "53:53/udp"\n      - "53:53/tcp"\n    volumes:\n      - ./dns-logs:/var/log/heralding\n    restart: unless-stopped',
    siemRule: 'index=honeypot sourcetype=dns_honeypot | stats count dc(query) by src_ip | where dc_query > 50 | sort -count',
    detectionValue: 'DNS tunneling detection — high query volume to unusual domains indicates C2 or exfiltration',
    mitre: ['T1071.004', 'T1048.003', 'T1568'],
  },
];

// =============================================================================
// HONEYTOKEN TEMPLATES
// =============================================================================
const HONEYTOKEN_TEMPLATES = [
  {
    name: 'Fake AWS Credentials',
    type: 'credential',
    desc: 'AWS access keys in AKIA format that trigger an alert when used. Place in code repos, .env files, or config files.',
    format: 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    placement: ['Source code repositories (.env, config.py, settings.js)', 'Developer workstations (~/.aws/credentials)', 'CI/CD pipeline environment variables', 'S3 bucket backup files', 'Shared network drives'],
    trigger: 'Any AWS API call using these keys triggers CloudTrail alert. Use AWS canary tokens (canarytokens.org) for automatic alerting.',
    falsePositives: 'Developers accidentally using the wrong credentials — label clearly as "HONEYPOT DO NOT USE" in a comment above',
    siemRule: 'index=cloudtrail userIdentity.accessKeyId="AKIA*EXAMPLE" | table _time sourceIPAddress eventName userAgent',
  },
  {
    name: 'Fake Database Connection String',
    type: 'credential',
    desc: 'Database connection strings pointing to a monitored honeypot database. Any connection attempt is an intrusion indicator.',
    format: 'DB_HOST=db-backup-02.internal.corp.local\nDB_USER=svc_reporting\nDB_PASS=R3p0rt1ng#2024!\nDB_NAME=customer_data',
    placement: ['Web application config files (web.config, .env)', 'Shared drives (IT_Documentation/db_access.txt)', 'Confluence/Wiki pages titled "Database Access"', 'Developer home directories'],
    trigger: 'TCP connection to the honeypot DB server on port 3306/1433/5432',
    falsePositives: 'Minimal — the honeypot hostname should not match any real infrastructure',
    siemRule: 'index=network dest="db-backup-02.internal.corp.local" dest_port IN (3306,1433,5432) | table _time src_ip dest_port',
  },
  {
    name: 'Canary Document',
    type: 'document',
    desc: 'Word/PDF document with an embedded image URL that triggers a callback when opened. Detects unauthorized access to sensitive files.',
    format: 'Create a document titled "Employee_Salary_Data_2024.xlsx" or "VPN_Credentials_ALL.docx" with an embedded image tag pointing to a canary URL: <img src="https://canarytokens.com/your-token/image.gif">',
    placement: ['HR shared drives', 'Finance department shares', 'IT admin folders', 'Backup directories', 'Desktops of high-value targets'],
    trigger: 'HTTP request to the canary URL when the document is opened — reveals IP, user agent, and time',
    falsePositives: 'Legitimate employees opening the file — use convincing but clearly "too good to be true" filenames that real documents wouldn\'t have',
    siemRule: 'Search web proxy logs for canary domain access or monitor the canarytokens dashboard',
  },
  {
    name: 'Fake API Keys',
    type: 'credential',
    desc: 'API keys in provider-specific format that trigger alerts when used. Each provider format is different.',
    format: 'GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\nSTRIPE_SK=<STRIPE_KEY>\nSLACK_TOKEN=<SLACK_TOKEN>\nSENDGRID_KEY=SG.xxxxxxxxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\nTWILIO_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    placement: ['Public or private code repositories', '.env files on development servers', 'CI/CD pipeline configurations', 'Documentation wikis'],
    trigger: 'API call using the token — GitHub shows usage in security logs, Stripe shows in dashboard events',
    falsePositives: 'Almost none — these tokens are unique and should never be used legitimately',
    siemRule: 'Monitor provider dashboards for usage of canary tokens, or use webhook-enabled canary services',
  },
  {
    name: 'Breadcrumb Files',
    type: 'file',
    desc: 'Fake sensitive files placed where attackers look first. The content leads them to honeypots or triggers alerts.',
    format: '# passwords.txt\nadmin:SuperSecretP@ss123!\nbackup_admin:Backup#2024\ndb_root:MySQL_R00t!\n\n# Note: connect to db-backup-02.internal:3306',
    placement: ['User desktops and Documents folders', 'C:\\Users\\Public\\', '/tmp/ on Linux servers', 'Web server document roots', 'Backup directories'],
    trigger: 'File access audit (Windows: Event ID 4663, Linux: auditd) or connection to the referenced honeypot services',
    falsePositives: 'Low — file names like "passwords.txt" should not exist in legitimate operations',
    siemRule: 'index=wineventlog EventCode=4663 ObjectName="*passwords.txt" OR ObjectName="*credentials*" | table _time SubjectUserName ObjectName AccessMask',
  },
  {
    name: 'Active Directory Honeytoken',
    type: 'credential',
    desc: 'Fake AD accounts with enticing names and descriptions. Any authentication attempt triggers an alert.',
    format: 'User: svc_backup_admin\nDescription: "Service account for backup system - DO NOT DISABLE"\nPassword: Never logged in, has complex password\nMember of: Domain Admins (makes it a Kerberoasting target)',
    placement: ['Active Directory as a normal-looking service account', 'Set SPN to attract Kerberoasting', 'Set "Do not require Kerberos preauthentication" to attract AS-REP roasting'],
    trigger: 'Any authentication attempt (Event ID 4625/4624), Kerberos TGS request (Event ID 4769), or AS-REP request (Event ID 4768)',
    falsePositives: 'None if the account is never used for legitimate purposes — any auth attempt is suspicious',
    siemRule: 'index=wineventlog (EventCode=4624 OR EventCode=4625 OR EventCode=4769 OR EventCode=4768) Account_Name="svc_backup_admin" | table _time EventCode src_ip Account_Name',
  },
  {
    name: 'DNS Canary',
    type: 'network',
    desc: 'A unique subdomain that triggers an alert when resolved. Place the hostname in files or configurations that only an attacker would find and use.',
    format: 'internal-vpn-gateway.yourdomain.canarytokens.com\nbackup-server-mgmt.yourdomain.canarytokens.com',
    placement: ['Internal documentation (wiki pages about VPN access)', 'Configuration files with server references', 'Internal DNS records for non-existent servers', 'Breadcrumb files referencing "other servers"'],
    trigger: 'DNS resolution of the canary domain — reveals the resolver IP (and thus the attacker\'s location/network)',
    falsePositives: 'Minimal — the canary domain should only exist in placed bait',
    siemRule: 'index=dns query="*canarytokens*" OR query="*internal-vpn-gateway*" | table _time src_ip query answer',
  },
];

// =============================================================================
// TRIPWIRE TEMPLATES
// =============================================================================
const TRIPWIRE_TEMPLATES = [
  { category: 'File System', name: 'Sensitive file access', desc: 'Monitor access to bait files in common attacker search paths', monitor: 'C:\\Users\\Public\\passwords.txt, /tmp/.credentials, ~/Desktop/VPN_Access.txt', detection: 'Windows: Audit object access (Event ID 4663), Linux: auditd with watches', mitre: 'T1083' },
  { category: 'File System', name: 'Web shell detection', desc: 'Monitor web roots for new executable files', monitor: '/var/www/html/*.php, C:\\inetpub\\wwwroot\\*.aspx, */uploads/*.jsp', detection: 'File integrity monitoring (OSSEC, Wazuh, Tripwire) on web directories', mitre: 'T1505.003' },
  { category: 'Registry', name: 'Persistence keys', desc: 'Monitor Windows persistence registry locations for changes', monitor: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run, HKCU\\...\\Run, HKLM\\SYSTEM\\CurrentControlSet\\Services', detection: 'Sysmon Event ID 12/13/14 (registry create/set/delete)', mitre: 'T1547.001' },
  { category: 'Registry', name: 'Security policy changes', desc: 'Monitor for security policy modifications', monitor: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa, HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender', detection: 'Windows Event ID 4719 (audit policy change), Sysmon registry events', mitre: 'T1562' },
  { category: 'Network', name: 'Darknet monitoring', desc: 'Unused IP addresses that should never receive traffic — any packet is anomalous', monitor: 'Dedicate unused IPs in each subnet (e.g., .250-.254 if not in use)', detection: 'IDS/IPS alert on any traffic to/from monitored IPs, firewall deny logs', mitre: 'T1046' },
  { category: 'Network', name: 'Port tripwire', desc: 'Services running on honeypot ports that alert on any connection', monitor: 'Common target ports: 22, 23, 3389, 445, 1433, 3306, 8080 on non-production IPs', detection: 'TCP SYN to monitored port triggers SIEM alert', mitre: 'T1046' },
  { category: 'Network', name: 'ARP monitoring', desc: 'Detect ARP spoofing and new devices on the network', monitor: 'Static ARP table for critical servers, DHCP snooping, Dynamic ARP Inspection', detection: 'Gratuitous ARP from unexpected MAC addresses', mitre: 'T1557.002' },
  { category: 'Active Directory', name: 'Privileged group changes', desc: 'Alert on any modification to high-privilege AD groups', monitor: 'Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators', detection: 'Windows Event ID 4728/4732/4756 (member added to security group)', mitre: 'T1098' },
  { category: 'Active Directory', name: 'GPO modifications', desc: 'Alert on Group Policy Object changes outside change windows', monitor: 'All GPOs, especially those linked to Domain Controllers OU', detection: 'Windows Event ID 5136 (directory service object modified) for GPO objects', mitre: 'T1484.001' },
  { category: 'Active Directory', name: 'Kerberos anomalies', desc: 'Detect golden ticket and Kerberoasting attacks', monitor: 'TGT with anomalous lifetime, RC4 encryption in Kerberos (should be AES)', detection: 'Event ID 4769 with encryption type 0x17 (RC4), Event ID 4768 with unusual ticket options', mitre: 'T1558' },
  { category: 'Cloud', name: 'IAM policy changes', desc: 'Alert on IAM policy modifications, new admin users, role changes', monitor: 'AWS: CloudTrail events for CreateUser, AttachUserPolicy, PutRolePolicy', detection: 'CloudTrail with EventName filter for IAM write events', mitre: 'T1098' },
  { category: 'Cloud', name: 'Unused region activity', desc: 'Alert on any resource creation in AWS regions you don\'t use', monitor: 'All AWS regions except your primary (e.g., alert on any activity in ap-southeast-1 if you only use us-east-1)', detection: 'CloudTrail with awsRegion filter for non-primary regions', mitre: 'T1578' },
  { category: 'Cloud', name: 'S3 policy changes', desc: 'Alert when bucket policies are modified to allow public access', monitor: 'S3 BucketPolicy and ACL changes, especially AllUsers or AuthenticatedUsers grants', detection: 'CloudTrail PutBucketPolicy, PutBucketAcl events', mitre: 'T1530' },
  { category: 'Endpoint', name: 'LSASS access', desc: 'Alert on processes accessing LSASS memory — credential dumping indicator', monitor: 'lsass.exe process memory reads from non-system processes', detection: 'Sysmon Event ID 10 with TargetImage=lsass.exe, exclude known legitimate callers', mitre: 'T1003.001' },
  { category: 'Endpoint', name: 'Command-line logging', desc: 'Monitor for reconnaissance and attack commands', monitor: 'whoami, net user, net group, nltest, dsquery, cmdkey, mimikatz, rubeus, SharpHound', detection: 'Sysmon Event ID 1 with CommandLine matching suspicious patterns', mitre: 'T1059' },
];

// =============================================================================
// MITRE DECEPTION COVERAGE
// =============================================================================
const DECEPTION_MITRE_COVERAGE = {
  'T1110': { tactic: 'Credential Access', technique: 'Brute Force', deception: 'SSH/RDP/DB honeypots capture all brute force attempts' },
  'T1021': { tactic: 'Lateral Movement', technique: 'Remote Services', deception: 'Honeypots on SMB/RDP/SSH detect lateral movement' },
  'T1046': { tactic: 'Discovery', technique: 'Network Service Scanning', deception: 'Port tripwires and darknet IPs detect scanning' },
  'T1083': { tactic: 'Discovery', technique: 'File and Directory Discovery', deception: 'Breadcrumb files detect filesystem browsing' },
  'T1003': { tactic: 'Credential Access', technique: 'OS Credential Dumping', deception: 'AD honeytokens detect credential harvesting (Kerberoasting, DCSync)' },
  'T1005': { tactic: 'Collection', technique: 'Data from Local System', deception: 'Canary documents detect data access' },
  'T1039': { tactic: 'Collection', technique: 'Data from Network Shared Drive', deception: 'File share honeypots detect data collection' },
  'T1190': { tactic: 'Initial Access', technique: 'Exploit Public-Facing App', deception: 'Web honeypots capture exploit attempts' },
  'T1071': { tactic: 'Command and Control', technique: 'Application Layer Protocol', deception: 'DNS honeypots detect C2 tunneling' },
  'T1048': { tactic: 'Exfiltration', technique: 'Exfiltration Over Alternative Protocol', deception: 'DNS canaries and network tripwires detect exfiltration' },
  'T1505': { tactic: 'Persistence', technique: 'Server Software Component', deception: 'Web directory monitoring detects web shell deployment' },
  'T1547': { tactic: 'Persistence', technique: 'Boot or Logon Autostart', deception: 'Registry tripwires detect persistence installation' },
  'T1558': { tactic: 'Credential Access', technique: 'Steal or Forge Kerberos Tickets', deception: 'AD honeytokens with SPNs detect Kerberoasting' },
  'T1098': { tactic: 'Persistence', technique: 'Account Manipulation', deception: 'AD group change tripwires detect privilege escalation' },
};

// =============================================================================
// MAIN RENDER
// =============================================================================
export function renderDeceptionArchitect(main) {
  var activeTab = 'honeypots';

  function render() {
    var tabs = [
      { id: 'honeypots', label: 'Honeypots' },
      { id: 'honeytokens', label: 'Honeytokens' },
      { id: 'tripwires', label: 'Tripwires' },
      { id: 'planner', label: 'Network Planner' },
      { id: 'coverage', label: 'MITRE Coverage' },
      { id: 'roi', label: 'ROI Calculator' },
    ];

    main.innerHTML =
      '<h1 class="pg-h1">Deception Architect</h1>' +
      '<p class="muted pg-sub">Design honeypots, honeytokens, and tripwires to detect attackers early. Zero false positives — any interaction with deception is a confirmed intrusion.</p>' +
      '<div class="tab-bar" style="overflow-x:auto;flex-wrap:nowrap">' +
        tabs.map(function(t) { return '<button class="tab' + (activeTab === t.id ? ' active' : '') + '" data-tab="' + t.id + '">' + esc(t.label) + '</button>'; }).join('') +
      '</div>' +
      '<div id="da-content" style="margin-top:12px"></div>';

    main.querySelector('.tab-bar').onclick = function(e) {
      var b = e.target.closest('.tab');
      if (!b) return;
      activeTab = b.dataset.tab;
      render();
    };

    var content = main.querySelector('#da-content');
    if (activeTab === 'honeypots') renderHoneypots(content);
    else if (activeTab === 'honeytokens') renderHoneytokens(content);
    else if (activeTab === 'tripwires') renderTripwires(content);
    else if (activeTab === 'planner') renderPlanner(content);
    else if (activeTab === 'coverage') renderCoverage(content);
    else if (activeTab === 'roi') renderROI(content);
  }

  function renderHoneypots(container) {
    container.innerHTML = '<h2 class="pg-h2">Honeypot Templates</h2>' +
      '<p class="muted" style="margin-bottom:16px">Pre-configured honeypot deployments with Docker Compose, SIEM integration, and detection rules. Click any template to see the full configuration.</p>' +
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:12px">' +
      HONEYPOT_TEMPLATES.map(function(hp, i) {
        return '<div class="arse-card" style="cursor:pointer" id="hp-card-' + i + '">' +
          '<div class="an">' + esc(hp.name) + ' <span style="font-size:.7rem;color:var(--acc);font-weight:400">Ports: ' + hp.ports.join(', ') + '</span></div>' +
          '<div class="ad">' + esc(hp.desc) + '</div>' +
          '<div style="margin-top:6px;font-size:.72rem;color:var(--mut)">Tools: ' + esc(hp.tools.join(', ')) + '</div>' +
          '<div style="margin-top:4px;font-size:.68rem;color:var(--acc)">MITRE: ' + hp.mitre.join(', ') + '</div>' +
          '<div id="hp-detail-' + i + '" style="display:none;margin-top:10px;border-top:1px solid var(--line);padding-top:10px">' +
            '<h4 style="margin:0 0 6px;font-size:.8rem">Expected Attacker Behavior</h4>' +
            '<ul style="margin:0 0 10px;padding-left:16px;font-size:.75rem;color:var(--mut)">' + hp.attackerBehavior.map(function(b) { return '<li>' + esc(b) + '</li>'; }).join('') + '</ul>' +
            '<h4 style="margin:0 0 6px;font-size:.8rem">Docker Compose</h4>' +
            '<pre style="background:rgba(0,0,0,.3);padding:8px;border-radius:4px;font-size:.7rem;overflow-x:auto;margin:0 0 10px">' + esc(hp.dockerCompose) + '</pre>' +
            '<h4 style="margin:0 0 6px;font-size:.8rem">SIEM Detection Rule</h4>' +
            '<pre style="background:rgba(0,0,0,.3);padding:8px;border-radius:4px;font-size:.7rem;overflow-x:auto;margin:0 0 10px;color:var(--acc)">' + esc(hp.siemRule) + '</pre>' +
            '<div style="font-size:.75rem;color:#00e676"><strong>Detection Value:</strong> ' + esc(hp.detectionValue) + '</div>' +
          '</div>' +
        '</div>';
      }).join('') + '</div>';

    HONEYPOT_TEMPLATES.forEach(function(_, i) {
      var card = container.querySelector('#hp-card-' + i);
      if (card) card.onclick = function() {
        var detail = container.querySelector('#hp-detail-' + i);
        if (detail) detail.style.display = detail.style.display === 'none' ? 'block' : 'none';
      };
    });
  }

  function renderHoneytokens(container) {
    container.innerHTML = '<h2 class="pg-h2">Honeytoken Generator</h2>' +
      '<p class="muted" style="margin-bottom:16px">Generate realistic-looking fake credentials and files to plant across your infrastructure. Any use of these tokens confirms an intrusion.</p>' +
      HONEYTOKEN_TEMPLATES.map(function(ht, i) {
        return '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:14px;margin-bottom:10px">' +
          '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">' +
            '<span style="font-weight:600;font-size:.9rem">' + esc(ht.name) + '</span>' +
            '<span style="font-size:.65rem;color:var(--acc);border:1px solid var(--acc);padding:1px 6px;border-radius:3px">' + esc(ht.type) + '</span>' +
          '</div>' +
          '<div style="font-size:.8rem;color:var(--mut);margin-bottom:8px">' + esc(ht.desc) + '</div>' +
          '<h4 style="margin:0 0 4px;font-size:.75rem;color:var(--txt)">Token Format</h4>' +
          '<pre style="background:rgba(0,0,0,.3);padding:8px;border-radius:4px;font-size:.72rem;overflow-x:auto;margin:0 0 10px;color:#ff9100">' + esc(ht.format) + '</pre>' +
          '<h4 style="margin:0 0 4px;font-size:.75rem;color:var(--txt)">Where to Place</h4>' +
          '<ul style="margin:0 0 8px;padding-left:16px;font-size:.75rem;color:var(--mut)">' + ht.placement.map(function(p) { return '<li>' + esc(p) + '</li>'; }).join('') + '</ul>' +
          '<div style="font-size:.75rem;margin-bottom:4px"><strong style="color:#00e676">Trigger:</strong> <span style="color:var(--mut)">' + esc(ht.trigger) + '</span></div>' +
          '<div style="font-size:.75rem;margin-bottom:4px"><strong style="color:#ffd600">False Positives:</strong> <span style="color:var(--mut)">' + esc(ht.falsePositives) + '</span></div>' +
          '<div style="font-size:.75rem"><strong style="color:var(--acc)">SIEM Query:</strong> <code style="font-size:.68rem;color:var(--acc)">' + esc(ht.siemRule) + '</code></div>' +
        '</div>';
      }).join('');
  }

  function renderTripwires(container) {
    var categories = [];
    TRIPWIRE_TEMPLATES.forEach(function(t) { if (categories.indexOf(t.category) === -1) categories.push(t.category); });

    container.innerHTML = '<h2 class="pg-h2">Tripwire Designer</h2>' +
      '<p class="muted" style="margin-bottom:16px">Configure monitoring points that alert on attacker activity. Each tripwire has near-zero false positive rate.</p>' +
      categories.map(function(cat) {
        var items = TRIPWIRE_TEMPLATES.filter(function(t) { return t.category === cat; });
        return '<h3 style="margin:16px 0 8px;color:var(--acc)">' + esc(cat) + '</h3>' +
          items.map(function(t) {
            return '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:12px;margin-bottom:6px;font-size:.82rem">' +
              '<div style="font-weight:600;margin-bottom:4px">' + esc(t.name) + ' <span style="font-size:.65rem;color:var(--acc)">' + esc(t.mitre) + '</span></div>' +
              '<div style="color:var(--mut);margin-bottom:6px">' + esc(t.desc) + '</div>' +
              '<div style="font-size:.75rem;margin-bottom:3px"><strong>Monitor:</strong> <code style="font-size:.7rem">' + esc(t.monitor) + '</code></div>' +
              '<div style="font-size:.75rem"><strong>Detection:</strong> <span style="color:var(--mut)">' + esc(t.detection) + '</span></div>' +
            '</div>';
          }).join('');
      }).join('');
  }

  function renderPlanner(container) {
    container.innerHTML = '<h2 class="pg-h2">Deception Network Planner</h2>' +
      '<p class="muted" style="margin-bottom:16px">Strategic placement recommendations for maximum deception coverage.</p>' +

      '<h3 style="margin:0 0 8px">Placement Strategy by Network Zone</h3>' +
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:10px;margin-bottom:20px">' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:12px">' +
          '<div style="font-weight:600;color:var(--acc);margin-bottom:6px">DMZ / Perimeter</div>' +
          '<ul style="margin:0;padding-left:16px;font-size:.78rem;color:var(--mut)">' +
            '<li>Web application honeypot (port 80/443)</li>' +
            '<li>SMTP honeypot (port 25)</li>' +
            '<li>DNS canary tokens in public-facing configs</li>' +
            '<li>Fake API endpoints returning seeded data</li>' +
          '</ul>' +
        '</div>' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:12px">' +
          '<div style="font-weight:600;color:var(--acc);margin-bottom:6px">Server Segment</div>' +
          '<ul style="margin:0;padding-left:16px;font-size:.78rem;color:var(--mut)">' +
            '<li>Database honeypot (same subnet as real DB)</li>' +
            '<li>SSH honeypot on an unused IP</li>' +
            '<li>File share with breadcrumb documents</li>' +
            '<li>Fake Jenkins/GitLab instance</li>' +
          '</ul>' +
        '</div>' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:12px">' +
          '<div style="font-weight:600;color:var(--acc);margin-bottom:6px">Workstation Segment</div>' +
          '<ul style="margin:0;padding-left:16px;font-size:.78rem;color:var(--mut)">' +
            '<li>RDP honeypot (attracts lateral movement)</li>' +
            '<li>Canary documents on shared drives</li>' +
            '<li>AD honeytoken accounts</li>' +
            '<li>Fake credentials in browser password stores</li>' +
          '</ul>' +
        '</div>' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:12px">' +
          '<div style="font-weight:600;color:var(--acc);margin-bottom:6px">Active Directory</div>' +
          '<ul style="margin:0;padding-left:16px;font-size:.78rem;color:var(--mut)">' +
            '<li>Honeytoken service accounts with SPNs</li>' +
            '<li>AS-REP roastable accounts (tripwire)</li>' +
            '<li>Fake Domain Admin for golden ticket detection</li>' +
            '<li>GPO modification alerts</li>' +
          '</ul>' +
        '</div>' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:12px">' +
          '<div style="font-weight:600;color:var(--acc);margin-bottom:6px">Cloud Environment</div>' +
          '<ul style="margin:0;padding-left:16px;font-size:.78rem;color:var(--mut)">' +
            '<li>Fake AWS keys in code repos (canary tokens)</li>' +
            '<li>S3 bucket with honeypot data</li>' +
            '<li>Unused region activity alerts</li>' +
            '<li>IAM role change monitoring</li>' +
          '</ul>' +
        '</div>' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:12px">' +
          '<div style="font-weight:600;color:var(--acc);margin-bottom:6px">OT/ICS Network</div>' +
          '<ul style="margin:0;padding-left:16px;font-size:.78rem;color:var(--mut)">' +
            '<li>Fake Modbus/DNP3 devices (Conpot)</li>' +
            '<li>HMI honeypot with fake process data</li>' +
            '<li>Network darknet monitoring on unused IPs</li>' +
            '<li>Port tripwires on ICS protocols (502, 20000)</li>' +
          '</ul>' +
        '</div>' +
      '</div>' +

      '<h3 style="margin:0 0 8px">Deployment Checklist</h3>' +
      '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:14px;font-size:.8rem">' +
        '<ol style="margin:0;padding-left:20px;line-height:2">' +
          '<li>Map your network — identify subnets, critical assets, and likely attack paths</li>' +
          '<li>Identify unused IPs in each subnet for honeypot placement</li>' +
          '<li>Deploy at least one honeypot per network segment</li>' +
          '<li>Plant honeytokens on high-value targets (DCs, file shares, dev workstations)</li>' +
          '<li>Configure tripwires on AD privileged groups and critical registry keys</li>' +
          '<li>Set up SIEM alerts for ALL deception elements — these are zero-false-positive detections</li>' +
          '<li>Create an incident response playbook specifically for deception alerts</li>' +
          '<li>Document all deception elements to prevent friendly-fire (SOC must know they exist)</li>' +
          '<li>Test monthly — attempt to trigger each deception element to verify alerting</li>' +
          '<li>Rotate honeytokens quarterly — stale tokens may be discovered and avoided</li>' +
        '</ol>' +
      '</div>';
  }

  function renderCoverage(container) {
    var tactics = ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impact'];

    container.innerHTML = '<h2 class="pg-h2">MITRE ATT&CK Deception Coverage</h2>' +
      '<p class="muted" style="margin-bottom:16px">Which attack techniques your deception infrastructure can detect.</p>' +
      '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.78rem">' +
      '<thead><tr style="border-bottom:2px solid var(--line)">' +
      '<th style="padding:8px;text-align:left;color:var(--mut)">MITRE ID</th>' +
      '<th style="padding:8px;text-align:left;color:var(--mut)">Tactic</th>' +
      '<th style="padding:8px;text-align:left;color:var(--mut)">Technique</th>' +
      '<th style="padding:8px;text-align:left;color:var(--mut)">Deception Detection</th>' +
      '</tr></thead><tbody>' +
      Object.keys(DECEPTION_MITRE_COVERAGE).map(function(id) {
        var m = DECEPTION_MITRE_COVERAGE[id];
        return '<tr style="border-bottom:1px solid var(--line)">' +
          '<td style="padding:8px;color:var(--acc);font-weight:600">' + esc(id) + '</td>' +
          '<td style="padding:8px;color:var(--mut)">' + esc(m.tactic) + '</td>' +
          '<td style="padding:8px">' + esc(m.technique) + '</td>' +
          '<td style="padding:8px;color:#00e676">' + esc(m.deception) + '</td>' +
          '</tr>';
      }).join('') +
      '</tbody></table></div>' +

      '<div style="margin-top:16px;display:flex;gap:12px;flex-wrap:wrap">' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:12px 20px">' +
          '<div style="font-size:1.4rem;font-weight:700;color:#00e676">' + Object.keys(DECEPTION_MITRE_COVERAGE).length + '</div>' +
          '<div style="font-size:.75rem;color:var(--mut)">Techniques covered</div>' +
        '</div>' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:12px 20px">' +
          '<div style="font-size:1.4rem;font-weight:700;color:var(--acc)">' + (new Set(Object.values(DECEPTION_MITRE_COVERAGE).map(function(m) { return m.tactic; }))).size + '</div>' +
          '<div style="font-size:.75rem;color:var(--mut)">Tactics covered</div>' +
        '</div>' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:12px 20px">' +
          '<div style="font-size:1.4rem;font-weight:700;color:#ffd600">~0%</div>' +
          '<div style="font-size:.75rem;color:var(--mut)">Expected false positive rate</div>' +
        '</div>' +
      '</div>';
  }

  function renderROI(container) {
    container.innerHTML = '<h2 class="pg-h2">Deception Technology ROI Calculator</h2>' +
      '<p class="muted" style="margin-bottom:16px">Calculate the return on investment for deploying deception technology based on industry data.</p>' +
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;max-width:700px">' +
        '<div>' +
          '<label style="font-size:.8rem;color:var(--mut);display:block;margin-bottom:4px">Industry</label>' +
          '<select id="roi-industry" style="width:100%;background:var(--card);color:var(--txt);border:1px solid var(--line);padding:8px;border-radius:4px;font-family:inherit">' +
            '<option value="4.45">Average (All Industries) — $4.45M</option>' +
            '<option value="10.93">Healthcare — $10.93M</option>' +
            '<option value="5.90">Financial — $5.90M</option>' +
            '<option value="5.13">Technology — $5.13M</option>' +
            '<option value="4.66">Industrial — $4.66M</option>' +
            '<option value="3.86">Education — $3.86M</option>' +
            '<option value="3.65">Retail — $3.65M</option>' +
          '</select>' +
        '</div>' +
        '<div>' +
          '<label style="font-size:.8rem;color:var(--mut);display:block;margin-bottom:4px">Annual deception budget ($)</label>' +
          '<input type="number" id="roi-budget" value="50000" style="width:100%;background:var(--card);color:var(--txt);border:1px solid var(--line);padding:8px;border-radius:4px;font-family:inherit">' +
        '</div>' +
        '<div>' +
          '<label style="font-size:.8rem;color:var(--mut);display:block;margin-bottom:4px">Estimated annual breach probability (%)</label>' +
          '<input type="number" id="roi-prob" value="25" min="1" max="100" style="width:100%;background:var(--card);color:var(--txt);border:1px solid var(--line);padding:8px;border-radius:4px;font-family:inherit">' +
        '</div>' +
        '<div>' +
          '<label style="font-size:.8rem;color:var(--mut);display:block;margin-bottom:4px">Deception detection rate improvement (%)</label>' +
          '<input type="number" id="roi-detect" value="35" min="1" max="100" style="width:100%;background:var(--card);color:var(--txt);border:1px solid var(--line);padding:8px;border-radius:4px;font-family:inherit">' +
        '</div>' +
      '</div>' +
      '<button class="btn sm" id="roi-calc" style="margin-top:12px">Calculate ROI</button>' +
      '<div id="roi-result" style="margin-top:16px"></div>';

    container.querySelector('#roi-calc').onclick = function() {
      var cost = parseFloat(container.querySelector('#roi-industry').value) * 1000000;
      var budget = parseFloat(container.querySelector('#roi-budget').value) || 50000;
      var prob = (parseFloat(container.querySelector('#roi-prob').value) || 25) / 100;
      var detect = (parseFloat(container.querySelector('#roi-detect').value) || 35) / 100;

      var expectedLoss = cost * prob;
      var reducedLoss = cost * prob * (1 - detect);
      var savings = expectedLoss - reducedLoss;
      var roi = ((savings - budget) / budget * 100).toFixed(0);
      var mttdReduction = Math.round(197 * detect);

      container.querySelector('#roi-result').innerHTML =
        '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px">' +
          '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:12px">' +
            '<div style="font-size:1.2rem;font-weight:700;color:#ff1744">$' + (expectedLoss / 1000000).toFixed(2) + 'M</div>' +
            '<div style="font-size:.72rem;color:var(--mut)">Expected annual loss (without deception)</div>' +
          '</div>' +
          '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:12px">' +
            '<div style="font-size:1.2rem;font-weight:700;color:#00e676">$' + (savings / 1000000).toFixed(2) + 'M</div>' +
            '<div style="font-size:.72rem;color:var(--mut)">Estimated annual savings</div>' +
          '</div>' +
          '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:12px">' +
            '<div style="font-size:1.2rem;font-weight:700;color:var(--acc)">' + roi + '%</div>' +
            '<div style="font-size:.72rem;color:var(--mut)">Return on investment</div>' +
          '</div>' +
          '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:12px">' +
            '<div style="font-size:1.2rem;font-weight:700;color:#ffd600">-' + mttdReduction + ' days</div>' +
            '<div style="font-size:.72rem;color:var(--mut)">MTTD reduction (from 197 day avg)</div>' +
          '</div>' +
        '</div>' +
        '<p style="font-size:.75rem;color:var(--mut);margin-top:10px">Based on IBM Cost of a Data Breach Report 2023 averages. Actual results vary by organization size, industry, and implementation quality. The 197-day MTTD is the IBM-reported average; deception typically reduces this to hours or days.</p>';
    };
  }

  render();
}
