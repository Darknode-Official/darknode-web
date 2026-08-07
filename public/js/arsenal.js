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
  renderDir(main, "Arsenal", `${n} hand-picked web tools and references from across the security and dev community — encoders, OSINT, cheat sheets, and coding utilities. Opens in a new tab.`, ARSENAL);
}
export function renderTraining(main) {
  const n = Object.values(TRAINING).reduce((a, b) => a + b.length, 0);
  renderDir(main, "Training", `${n} places to sharpen your skills — hands-on labs, wargames, CTFs, and bug-bounty platforms. Opens in a new tab.`, TRAINING);
}
