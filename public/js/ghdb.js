// Google Hacking Database — curated dorks for OSINT/recon. Runs the query on
// Google (optionally scoped to a target domain). For authorized testing only.
import { getTarget, setTarget } from "/js/target.js";
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const DORKS = {
  "Passwords & secrets": [
    ["Exposed .env files", 'intitle:"index of" ".env"'],
    ["Passwords in log files", 'filetype:log intext:password'],
    ["Exposed wp-config.php", 'intitle:"index of" "wp-config.php"'],
    ["SQL dumps with passwords", 'filetype:sql "INSERT INTO" password'],
    ["Exposed SSH private keys", 'intitle:"index of" "id_rsa"'],
    ["AWS keys in logs", 'filetype:log intext:"AKIA"'],
    ["htpasswd files", 'intitle:"index of" ".htpasswd"'],
  ],
  "Sensitive files & dirs": [
    ["Open directory listing", 'intitle:"index of" "parent directory"'],
    ["Exposed .git repo", 'intitle:"index of" ".git"'],
    ["Backup files in listings", 'intitle:"index of" "backup"'],
    ["Exposed config.php", 'intitle:"index of" "config.php"'],
    ["Exposed .DS_Store", 'intitle:"index of" ".DS_Store"'],
    ["phpinfo() pages", 'intitle:"phpinfo()" "PHP Version"'],
  ],
  "Login & admin panels": [
    ["Admin login pages", "inurl:admin/login"],
    ["phpMyAdmin", '"Welcome to phpMyAdmin" intitle:phpMyAdmin'],
    ["WordPress admin", "inurl:/wp-admin/"],
    ["Web dashboards on 8080", "intitle:dashboard inurl:8080"],
    ["Jenkins", 'intitle:"Dashboard [Jenkins]"'],
  ],
  "Exposed documents": [
    ["Confidential PDFs", 'filetype:pdf "confidential"'],
    ["Spreadsheets with emails", "filetype:xls inurl:email"],
    ["Exposed databases", "ext:sql OR ext:mdb OR ext:dbf"],
    ["Config / ini files", "ext:ini OR ext:conf"],
  ],
  "Errors & info leak": [
    ["SQL errors", '"sql syntax near" OR "syntax error has occurred"'],
    ["PHP errors", '"PHP Parse error" OR "PHP Warning"'],
    ["Laravel debug traces", '"Whoops, looks like something went wrong"'],
    ["Exposed .env via error", 'intext:"APP_KEY" ext:env'],
  ],
  "Cameras & devices": [
    ["Network cameras", "inurl:/view.shtml OR inurl:ViewerFrame?Mode="],
    ["webcamXP", 'intitle:"webcamXP 5"'],
    ["HP printers", "inurl:hp/device/this.LCDispatcher"],
    ["Router login panels", 'intitle:"router" intext:"login" inurl:8080'],
  ],
  "Cloud storage": [
    ["Public S3 buckets", "site:s3.amazonaws.com"],
    ["Azure blobs", "site:blob.core.windows.net"],
    ["GCS buckets", "site:storage.googleapis.com"],
    ["DigitalOcean Spaces", "site:digitaloceanspaces.com"],
    ["Open Firebase", 'site:firebaseio.com'],
  ],
};

export function renderGHDB(main) {
  const cats = Object.keys(DORKS);
  const total = Object.values(DORKS).reduce((a, b) => a + b.length, 0);
  main.innerHTML = `
    <h1 class="pg-h1">Google Hacking DB</h1>
    <p class="muted pg-sub">${total} curated Google dorks for recon and exposure discovery. Set a target to scope every search to one domain. For authorized testing and research only.</p>
    <div class="ghdb-bar">
      <input class="tk-f" id="ghDomain" placeholder="scope to domain (optional) — e.g. example.com" spellcheck="false" autocomplete="off">
      <span class="muted" id="ghScope">searching all of Google</span>
    </div>
    <div class="cs-filter" id="ghFilter"><button class="chip on" data-c="all">All</button>${cats.map((c) => `<button class="chip" data-c="${esc(c)}">${esc(c)}</button>`).join("")}</div>
    <div id="ghWrap">
      ${cats.map((c) => `<div class="gh-cat" data-cat="${esc(c)}"><h2 class="pg-h2">${esc(c)}</h2>${DORKS[c].map(([d, q]) => `<div class="gh-row"><div class="gh-desc">${esc(d)}</div><code class="gh-q">${esc(q)}</code><div class="gh-actions"><button class="btn sm gh-search" data-q="${esc(q)}">Search &#8599;</button><button class="cs-copy gh-copy" data-q="${esc(q)}">copy</button></div></div>`).join("")}</div>`).join("")}
    </div>`;
  const $ = (s) => main.querySelector(s);
  const dom = $("#ghDomain"), scope = $("#ghScope");
  dom.value = getTarget();
  const build = (q) => { const d = dom.value.trim(); return d ? `site:${d} ${q}` : q; };
  const syncScope = () => { const d = dom.value.trim(); scope.textContent = d ? `scoped to ${d}` : "searching all of Google"; };
  dom.oninput = () => { syncScope(); setTarget(dom.value); };
  syncScope();
  $("#ghFilter").onclick = (e) => {
    const b = e.target.closest(".chip"); if (!b) return;
    main.querySelectorAll("#ghFilter .chip").forEach((x) => x.classList.toggle("on", x === b));
    main.querySelectorAll(".gh-cat").forEach((cat) => { cat.style.display = (b.dataset.c === "all" || cat.dataset.cat === b.dataset.c) ? "" : "none"; });
  };
  $("#ghWrap").onclick = (e) => {
    const s = e.target.closest(".gh-search"), cp = e.target.closest(".gh-copy");
    if (s) window.open("https://www.google.com/search?q=" + encodeURIComponent(build(s.dataset.q)), "_blank", "noopener");
    else if (cp) { navigator.clipboard?.writeText(build(cp.dataset.q)); cp.textContent = "copied"; setTimeout(() => (cp.textContent = "copy"), 1000); }
  };
}
