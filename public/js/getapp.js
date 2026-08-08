// Downloads section — desktop app + CLI, hosted on GitHub Releases.
// Fetches the live release assets so file sizes and versions are always current.
const REPO = "Darknode-Official/sentinel-web";
const TAG = "sentinel";
const RELEASES = "https://github.com/" + REPO + "/releases";
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// Map an asset filename to a friendly label + install/run command.
const META = [
  { re: /_amd64\.deb$/, group: "Desktop app", os: "Linux", fmt: ".deb installer", cmd: (f) => `sudo apt install ./${f}` },
  { re: /\.AppImage$/, group: "Desktop app", os: "Linux", fmt: "AppImage", cmd: (f) => `chmod +x ${f} && ./${f}` },
  { re: /Setup.*\.exe$/i, group: "Desktop app", os: "Windows", fmt: ".exe installer", cmd: (f) => `double-click ${f}` },
  { re: /cli-linux$/, group: "Terminal edition (CLI)", os: "Linux", fmt: "CLI binary", cmd: (f, u) => `curl -L ${u} -o sentinel && chmod +x sentinel && ./sentinel` },
  { re: /cli-windows\.exe$/i, group: "Terminal edition (CLI)", os: "Windows", fmt: "CLI .exe", cmd: (f, u) => `curl.exe -L ${u} -o sentinel.exe; .\\sentinel.exe` },
];
const fmtSize = (n) => n > 1e9 ? (n / 1e9).toFixed(2) + " GB" : n > 1e6 ? (n / 1e6).toFixed(1) + " MB" : (n / 1e3).toFixed(0) + " KB";
const verOf = (name) => (name.match(/(\d+\.\d+\.\d+)/) || [])[1] || "";

const SITE = "https://sentinel-web-2hq9.onrender.com";
const APP_EDITIONS = [
  { name: "Netinstall", tag: "lightest · ~95 MB", desc: "Just the app. Every tool auto-configures itself the first time you launch it — nothing pre-downloaded.", steps: ["Install the .deb / AppImage / .exe from the Builds tab.", "Open any tool — Sentinel sets it up on first use."] },
  { name: "Slim", tag: "recommended", desc: "The app plus the essential toolset: recon, web, and password tools.", steps: ["Install the app from the Builds tab.", `curl -sL ${SITE}/arsenal.sh | bash -s -- recon web passwords`] },
  { name: "Full", tag: "everything + AI", desc: "The app, the complete arsenal (all 10 categories), and local AI models.", steps: ["Install the app from the Builds tab.", `curl -sL ${SITE}/arsenal.sh | bash`, "ollama pull llama3.1 && ollama pull minicpm-v"] },
];
const CLI_EDITIONS = [
  { name: "git clone", tag: "tiny · ~300 KB", desc: "Clone the source and run with Node — no 52 MB binary on disk, and git pull keeps it current. Needs Node 18+.", steps: ["git clone https://github.com/Darknode-Official/sentinel-cli && cd sentinel-cli && node sentinel.js"] },
  { name: "Compact", tag: "standalone · ~52 MB", desc: "The self-contained binary — Node bundled in, no dependencies, runs on its own. Grab it from the Builds tab.", steps: ["Download the CLI binary from the Builds tab — it just runs."] },
  { name: "Pro", tag: "full toolset", desc: "The CLI (either way above) plus the complete external toolset it can drive (nmap, sqlmap, nuclei…).", steps: [`curl -sL ${SITE}/arsenal.sh | bash`] },
];

const edCard = (e) => `
  <div class="ed-card">
    <div class="ed-head"><h3>${esc(e.name)}</h3><span class="chip">${esc(e.tag)}</span></div>
    <p class="muted" style="font-size:.83rem;margin:6px 0 10px">${esc(e.desc)}</p>
    <ol class="ed-steps">${e.steps.map((s) => /^[a-z]+ |curl|ollama|sudo/.test(s) && !/ from the /.test(s) ? `<li><code data-cmd>${esc(s)}</code></li>` : `<li>${esc(s)}</li>`).join("")}</ol>
  </div>`;

export function renderDownloads(main) {
  main.innerHTML = `
    <h1 class="pg-h1">Downloads</h1>
    <p class="muted pg-sub">The desktop app and terminal edition go far beyond the web console &mdash; a QEMU/KVM VM runner, a native port scanner, DNS/WHOIS/TLS recon, subdomain enumeration, a code workbench, live terminals, an autonomous AI agent, and auto-configuring tools.</p>
    <h2 class="pg-h2">1 · Choose a build</h2>
    <div class="card" style="max-width:640px">
      <div class="dl-pick">
        <label class="pc-f" style="flex:1"><span>Platform &amp; format</span><select class="tk-f" id="dlSelect"><option>loading releases…</option></select></label>
      </div>
      <div id="dlDetail" class="dl-detail"></div>
    </div>
    <h2 class="pg-h2" style="margin-top:24px">2 · Choose a setup edition</h2>
    <p class="muted" style="font-size:.85rem;margin:-6px 0 12px">Same installer, different amount of tooling. Pick how much you want set up, then run the command after installing.</p>
    <h3 class="pg-h3" style="margin:0 0 8px">Desktop app</h3>
    <div class="ed-grid">${APP_EDITIONS.map(edCard).join("")}</div>
    <h3 class="pg-h3" style="margin:22px 0 8px">Terminal edition (CLI)</h3>
    <div class="ed-grid">${CLI_EDITIONS.map(edCard).join("")}</div>
    <p class="muted" style="font-size:.78rem;margin-top:14px">Provisioning uses systems you own or are authorized to test. Review the script anytime at <a href="${SITE}/arsenal.sh" target="_blank" rel="noopener">/arsenal.sh</a>.</p>
    <p class="muted" style="font-size:.8rem;margin-top:16px">All builds are MIT-licensed. &middot; <a href="${RELEASES}" target="_blank" rel="noopener">All releases →</a></p>`;
  const sel = main.querySelector("#dlSelect"), detail = main.querySelector("#dlDetail");

  const fallback = () => {
    sel.innerHTML = `<option>unavailable</option>`;
    detail.innerHTML = `<p class="muted">Couldn't load release info. Browse all downloads on <a href="${RELEASES}/tag/${TAG}" target="_blank" rel="noopener">GitHub Releases</a>.</p>`;
  };

  const showDetail = (a) => {
    const m = META.find((x) => x.re.test(a.name)); if (!m) return;
    const ver = verOf(a.name);
    detail.innerHTML = `
      <div class="dl-meta">
        <div><span class="dl-k">Platform</span><span>${esc(m.os)} · ${esc(m.fmt)}</span></div>
        <div><span class="dl-k">Version</span><span>${ver ? "v" + esc(ver) : "latest"}</span></div>
        <div><span class="dl-k">Size</span><span>${esc(fmtSize(a.size))}</span></div>
        <div><span class="dl-k">Downloads</span><span>${a.download_count.toLocaleString()}</span></div>
      </div>
      <a class="btn" href="${esc(a.browser_download_url)}" download style="margin:12px 0 4px;display:inline-block">Download ${esc(a.name)}</a>
      <div class="dlapp-cmd"><span class="dlapp-cmd-l">After download</span><code data-cmd>${esc(m.cmd(a.name, a.browser_download_url))}</code></div>`;
  };

  const ctrl = new AbortController(); setTimeout(() => ctrl.abort(), 8000);
  fetch("https://api.github.com/repos/" + REPO + "/releases/tags/" + TAG, { signal: ctrl.signal })
    .then((r) => r.ok ? r.json() : Promise.reject())
    .then((rel) => {
      const assets = (rel.assets || []).filter((a) => META.some((m) => m.re.test(a.name)));
      if (!assets.length) return fallback();
      assets.sort((a, b) => META.findIndex((m) => m.re.test(a.name)) - META.findIndex((m) => m.re.test(b.name)));
      const groups = [...new Set(assets.map((a) => META.find((m) => m.re.test(a.name)).group))];
      sel.innerHTML = groups.map((g) => `<optgroup label="${esc(g)}">` + assets.filter((a) => META.find((m) => m.re.test(a.name)).group === g).map((a) => {
        const m = META.find((x) => x.re.test(a.name));
        return `<option value="${esc(a.name)}">${esc(m.os)} — ${esc(m.fmt)} (${esc(fmtSize(a.size))})</option>`;
      }).join("") + `</optgroup>`).join("");
      const byName = (n) => assets.find((a) => a.name === n);
      sel.onchange = () => showDetail(byName(sel.value));
      showDetail(assets[0]);
    })
    .catch(fallback);

  main.addEventListener("click", (e) => {
    const c = e.target.closest("code[data-cmd]"); if (!c) return;
    navigator.clipboard?.writeText(c.textContent).then(() => { c.style.outline = "1px solid var(--acc)"; setTimeout(() => (c.style.outline = ""), 500); });
  });
}
