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

export function renderDownloads(main) {
  main.innerHTML = `
    <h1 class="pg-h1">Downloads</h1>
    <p class="muted pg-sub">The desktop app and terminal edition go far beyond the web console &mdash; a QEMU/KVM VM runner, a native port scanner, DNS/WHOIS/TLS recon, subdomain enumeration, a code workbench, live terminals, an autonomous AI agent, and auto-configuring tools.</p>
    <div class="card" style="max-width:640px">
      <div class="dl-pick">
        <label class="pc-f" style="flex:1"><span>Choose a build</span><select class="tk-f" id="dlSelect"><option>loading releases…</option></select></label>
      </div>
      <div id="dlDetail" class="dl-detail"></div>
    </div>
    <p class="muted" style="font-size:.8rem;margin-top:16px">All builds are MIT-licensed and run only tools you invoke on systems you're authorized to test. &middot; <a href="${RELEASES}" target="_blank" rel="noopener">All releases →</a></p>`;
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
