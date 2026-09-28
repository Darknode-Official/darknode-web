// Curated directories of external tools, references, and platforms — opens in a new tab.
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// [name, url, description]
const ARSENAL = {
  "Web & crypto": [
    ["CyberChef", "https://gchq.github.io/CyberChef/", "The cyber swiss-army knife — encode, decode, crypto, data ops"],
    ["regex101", "https://regex101.com/", "Build and debug regular expressions with live explanation"],
    ["JWT.io", "https://jwt.io/", "Decode, verify, and craft JSON Web Tokens"],
    ["CrackStation", "https://crackstation.net/", "Free lookup of unsalted hash → plaintext"],
    ["hashes.com", "https://hashes.com/en/decrypt/hash", "Hash identifier and cracking service"],
    ["dcode.fr", "https://www.dcode.fr/en", "Huge collection of cipher and encoding tools"],
    ["URL Encoder", "https://www.urlencoder.org/", "Quick URL encode / decode"],
    ["explainshell", "https://explainshell.com/", "Break down any shell command flag by flag"],
  ],
  "Recon & OSINT": [
    ["Shodan", "https://www.shodan.io/", "Search engine for internet-connected devices and services"],
    ["Censys", "https://search.censys.io/", "Internet-wide scan data for hosts and certs"],
    ["crt.sh", "https://crt.sh/", "Certificate Transparency logs — find subdomains"],
    ["DNSDumpster", "https://dnsdumpster.com/", "DNS recon and mapping"],
    ["ViewDNS.info", "https://viewdns.info/", "Reverse IP, WHOIS, DNS, and more"],
    ["SecurityTrails", "https://securitytrails.com/", "DNS and domain history"],
    ["urlscan.io", "https://urlscan.io/", "Scan and analyse websites safely"],
    ["GreyNoise", "https://viz.greynoise.io/", "See who's scanning the internet"],
    ["Wayback Machine", "https://web.archive.org/", "Historical snapshots of any site"],
    ["OSINT Framework", "https://osintframework.com/", "Directory of OSINT tools by category"],
  ],
  "Cheatsheets & payloads": [
    ["HackTricks", "https://book.hacktricks.xyz/", "The pentester's bible — techniques for every service"],
    ["PayloadsAllTheThings", "https://github.com/swisskyrepo/PayloadsAllTheThings", "Payloads and bypasses for every web bug class"],
    ["GTFOBins", "https://gtfobins.github.io/", "Unix binaries to bypass local security restrictions"],
    ["LOLBAS", "https://lolbas-project.github.io/", "Living-off-the-land binaries for Windows"],
    ["OWASP Cheat Sheets", "https://cheatsheetseries.owasp.org/", "Concise defensive guidance per topic"],
    ["revshells.com", "https://www.revshells.com/", "Reverse shell generator for every language"],
    ["SecLists", "https://github.com/danielmiessler/SecLists", "The security tester's companion wordlists"],
    ["PentestMonkey", "https://pentestmonkey.net/cheat-sheet", "Classic reverse-shell and SQLi cheat sheets"],
  ],
  "Coding & dev": [
    ["DevDocs", "https://devdocs.io/", "Fast, unified API documentation for everything"],
    ["MDN Web Docs", "https://developer.mozilla.org/", "The reference for web platform APIs"],
    ["Compiler Explorer", "https://godbolt.org/", "See the assembly your code compiles to"],
    ["Stack Overflow", "https://stackoverflow.com/", "Q&A for every programming problem"],
    ["crontab.guru", "https://crontab.guru/", "Decode and build cron schedules"],
    ["Can I use", "https://caniuse.com/", "Browser support tables for web features"],
    ["JSON Formatter", "https://jsonformatter.org/", "Format, validate, and diff JSON"],
    ["ray.so", "https://ray.so/", "Turn code into shareable images"],
  ],
};

const TRAINING = {
  "Learning & practice": [
    ["Hack The Box", "https://www.hackthebox.com/", "Hands-on machines and labs, beginner to elite"],
    ["TryHackMe", "https://tryhackme.com/", "Guided rooms and learning paths for all levels"],
    ["PortSwigger Web Security Academy", "https://portswigger.net/web-security", "Free, world-class web-hacking labs"],
    ["PentesterLab", "https://pentesterlab.com/", "Focused exercises on real vulnerabilities"],
    ["VulnHub", "https://www.vulnhub.com/", "Downloadable vulnerable VMs to practice on"],
    ["OverTheWire", "https://overthewire.org/wargames/", "Classic wargames — start with Bandit"],
    ["picoCTF", "https://picoctf.org/", "Beginner-friendly CTF from CMU"],
    ["Root-Me", "https://www.root-me.org/", "Hundreds of challenges across all domains"],
    ["pwn.college", "https://pwn.college/", "Deep-dive into binary exploitation"],
    ["Exploit Education", "https://exploit.education/", "Phoenix / Nebula exploitation VMs"],
  ],
  "Bug bounty": [
    ["HackerOne", "https://www.hackerone.com/", "The largest bug bounty and disclosure platform"],
    ["Bugcrowd", "https://www.bugcrowd.com/", "Crowdsourced security programs"],
    ["Intigriti", "https://www.intigriti.com/", "European bug bounty platform"],
    ["YesWeHack", "https://www.yeswehack.com/", "Global bug bounty and VDP platform"],
    ["disclose.io", "https://disclose.io/", "Safe-harbor and VDP standards"],
    ["HackerOne Hacktivity", "https://hackerone.com/hacktivity", "Public disclosed reports to learn from"],
    ["Google VRP", "https://bughunters.google.com/", "Google's vulnerability reward program"],
    ["Bug Bounty Hunter", "https://www.bugbountyhunter.com/", "Methodology and guided bug-bounty training"],
  ],
};

function renderDir(main, title, sub, data) {
  const cats = Object.keys(data);
  main.innerHTML = `
    <h1 class="pg-h1">${esc(title)}</h1>
    <p class="muted pg-sub">${esc(sub)}</p>
    <div class="cs-filter" id="arseFilter"><button class="chip on" data-c="all">All</button>${cats.map((c) => `<button class="chip" data-c="${esc(c)}">${esc(c)}</button>`).join("")}</div>
    <div id="arseWrap">
      ${cats.map((c) => `<div class="arse-cat" data-cat="${esc(c)}"><h2 class="pg-h2" style="margin:18px 0 10px">${esc(c)}</h2><div class="arse-grid">${data[c].map(([n, u, d]) => `<a class="arse-card" href="${esc(u)}" target="_blank" rel="noopener"><div class="an">${esc(n)} <span class="ax">&#8599;</span></div><div class="ad">${esc(d)}</div><div class="au">${esc(u.replace(/^https?:\/\//, "").replace(/\/$/, ""))}</div></a>`).join("")}</div></div>`).join("")}
    </div>`;
  main.querySelector("#arseFilter").onclick = (e) => {
    const b = e.target.closest(".chip"); if (!b) return;
    main.querySelectorAll("#arseFilter .chip").forEach((x) => x.classList.toggle("on", x === b));
    main.querySelectorAll(".arse-cat").forEach((cat) => { cat.style.display = (b.dataset.c === "all" || cat.dataset.cat === b.dataset.c) ? "" : "none"; });
  };
}

export function renderArsenal(main) {
  const n = Object.values(ARSENAL).reduce((a, b) => a + b.length, 0);
  renderDir(main, "External Resources", `${n} external references and community tools — for when you need something outside the Darknode platform. Opens in a new tab.`, ARSENAL);
}

export function renderEngines(main) {
  const engines = [
    { name: "Threat Detection Engine", file: "threat-engine.js", desc: "IOC extraction, DGA domain detection, YARA rule matching, MITRE ATT&CK mapping, beaconing detection, malware classification", lines: 633, category: "Detection" },
    { name: "Cryptographic Engine", file: "crypto-engine.js", desc: "MD5, SHA-1/256/512, AES-128/256, RSA math, HMAC, XOR/Caesar/Vigenere analysis, JWT decoder, X.509 parser", lines: 833, category: "Crypto" },
    { name: "Forensic Analysis Engine", file: "forensic-engine.js", desc: "PE/ELF binary parser, hex viewer, file signature database, entropy calculator, string extractor, registry hive parser, timestamp converter", lines: 570, category: "Forensics" },
    { name: "Network Analysis Engine", file: "network-engine.js", desc: "PCAP reader, TCP stream reassembly, TLS/DNS parsers, HTTP inspector, subnet calculator, ARP spoof detection, MAC vendor lookup", lines: 566, category: "Network" },
    { name: "Exploit Framework", file: "exploit-framework.js", desc: "45+ reverse shells, shellcode encoder, buffer overflow tools, SQLi/XSS/SSRF/SSTI/XXE payload libraries, JWT attacks, deserialization", lines: 1567, category: "Offensive" },
    { name: "Vulnerability Scanner Engine", file: "vuln-scanner-engine.js", desc: "CMS/tech stack detection, security header grading, CVSS v3.1 calculator, OWASP Top 10 checker, SSL/TLS analyzer, API security tester", lines: 1374, category: "Assessment" },
    { name: "SIEM Engine", file: "siem-engine.js", desc: "6 log format parsers, 200+ detection rules, Sigma rule converter (Splunk/ELK/Sentinel), correlation engine, anomaly detection, user behavior analytics", lines: 1283, category: "Detection" },
    { name: "IDS Rule Engine", file: "ids-engine.js", desc: "Snort/Suricata rule parser and matcher, 100+ built-in Snort rules, YARA parser, 50+ YARA rules, network flow analyzer, threat intel feed parser", lines: 668, category: "Detection" },
    { name: "Red Team Engine", file: "redteam-engine.js", desc: "Full MITRE ATT&CK matrix (200+ techniques), kill chain mapper, AD attack paths, cloud attack patterns, social engineering playbooks, engagement scoping", lines: 1789, category: "Offensive" },
    { name: "Blue Team Engine", file: "blueteam-engine.js", desc: "20 IR playbooks, Windows/Linux forensic artifacts, 75+ Splunk hunting queries, compliance mapper (NIST/ISO/SOC2/PCI/HIPAA/GDPR), tabletop exercises", lines: 1094, category: "Defensive" },
    { name: "Malware Analysis Engine", file: "malware-engine.js", desc: "PE/ELF/Mach-O analyzers, API behavior classifier, 70+ packer signatures, 52 anti-analysis techniques, 80+ malware families, YARA rule generator", lines: 1346, category: "Forensics" },
    { name: "OSINT Engine", file: "osint-engine.js", desc: "Email/domain/IP OSINT, 500+ subdomain wordlist, 200+ Google dorks, 35 social media platforms, metadata extractors, dark web patterns", lines: 969, category: "Recon" },
    { name: "APT Defense Engine", file: "apt-defense.js", desc: "80+ real APT groups database, Diamond Model, kill chain coverage, STRIDE threat modeling, DREAD calculator, zero-day detection heuristics", lines: 1299, category: "Defense" },
    { name: "Threat Hunting Engine", file: "threat-hunt.js", desc: "30+ hunting hypotheses with Splunk/KQL queries, Windows Event ID reference, Sysmon events, Linux audit logs, cloud log reference", lines: 724, category: "Detection" },
    { name: "Cloud Security Engine", file: "cloud-security.js", desc: "AWS/Azure/GCP attack techniques, IAM policy analyzer, S3/security group checker, Kubernetes pod security, Terraform scanner, compliance mapper", lines: 707, category: "Cloud" },
    { name: "IoT Security Engine", file: "iot-security.js", desc: "MQTT/CoAP/Modbus/DNP3 parsers, ICS/SCADA vulnerabilities, firmware analysis, 100+ default credentials, CAN bus parser, RF band reference", lines: 656, category: "IoT" },
    { name: "Cyber Warfare Defense", file: "cyber-warfare.js", desc: "Nation-state threat actors, 16 critical infrastructure sectors, NIST CSF, election security, power grid/water/telecom protection, STIX/TAXII", lines: 1538, category: "Defense" },
    { name: "Defense Operations", file: "defense-ops.js", desc: "SOC maturity model, alert triage, incident classification, STIX 2.1, vulnerability management, patch prioritization, security metrics/KPIs", lines: 897, category: "Operations" },
  ];
  const cats = [...new Set(engines.map(e => e.category))];
  const totalLines = engines.reduce((a, e) => a + e.lines, 0);
  const filterHtml = cats.map(c => '<button class="chip" data-c="' + esc(c) + '">' + esc(c) + '</button>').join("");
  const cardsHtml = engines.map(e =>
    '<div class="arse-card eng-card" data-cat="' + esc(e.category) + '" style="cursor:default">' +
      '<div class="an">' + esc(e.name) + ' <span style="font-size:.7rem;color:var(--acc);font-weight:400">' + e.lines.toLocaleString() + ' lines</span></div>' +
      '<div class="ad">' + esc(e.desc) + '</div>' +
      '<div class="au" style="display:flex;gap:8px;align-items:center;margin-top:4px">' +
        '<span class="chip" style="font-size:.65rem">' + esc(e.category) + '</span>' +
        '<span style="color:var(--mut);font-size:.72rem">' + esc(e.file) + '</span>' +
      '</div>' +
    '</div>'
  ).join("");
  main.innerHTML =
    '<h1 class="pg-h1">Security Engines</h1>' +
    '<style>.eng-card.arse-card,.eng-card.arse-card:hover{cursor:default;transform:none!important;box-shadow:none!important;border-color:var(--line)!important;background:color-mix(in srgb,var(--acc) 3%,transparent)}[data-style=pro] .eng-card.arse-card,[data-style=pro] .eng-card.arse-card:hover{border-color:#e5e5e5!important;background:#fff!important}[data-style=dark] .eng-card.arse-card,[data-style=dark] .eng-card.arse-card:hover{border-color:#334155!important;background:#1e293b!important}</style>' +
    '<p class="muted pg-sub">Reference list of the ' + engines.length + ' JavaScript engine modules bundled with Darknode (' + totalLines.toLocaleString() + ' lines in total). These are libraries, listed for information only; the cards are not clickable and do not open a tool.</p>' +
    '<div class="cs-filter" id="engFilter"><button class="chip on" data-c="all">All</button>' + filterHtml + '</div>' +
    '<div class="arse-grid" id="engGrid">' + cardsHtml + '</div>';
  main.querySelector("#engFilter").onclick = (e) => {
    const b = e.target.closest(".chip"); if (!b) return;
    main.querySelectorAll("#engFilter .chip").forEach(x => x.classList.toggle("on", x === b));
    main.querySelectorAll(".eng-card").forEach(c => { c.style.display = (b.dataset.c === "all" || c.dataset.cat === b.dataset.c) ? "" : "none"; });
  };
}
export function renderTraining(main) {
  const n = Object.values(TRAINING).reduce((a, b) => a + b.length, 0);
  renderDir(main, "Training", `${n} places to sharpen your skills — hands-on labs, wargames, CTFs, and bug-bounty platforms. Opens in a new tab.`, TRAINING);
}
