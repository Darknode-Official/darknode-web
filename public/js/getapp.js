// Downloads section — desktop app + CLI, hosted on GitHub Releases.
// Fetches the live release assets so file sizes and versions are always current.
const REPO = "SpartanKing18/darknode-web";
const TAG = "darknode";
const RELEASES = "https://github.com/" + REPO + "/releases";
const REL_DL = RELEASES + "/download/" + TAG;
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// Map an asset filename to a friendly label + install/run command.
const META = [
  { re: /_amd64\.deb$/, group: "Desktop app", os: "Linux", fmt: ".deb installer", cmd: (f) => `sudo apt install ./${f}` },
  { re: /\.AppImage$/, group: "Desktop app", os: "Linux", fmt: "AppImage", cmd: (f) => `chmod +x ${f} && ./${f}` },
  { re: /Setup.*\.exe$/i, group: "Desktop app", os: "Windows", fmt: ".exe installer", cmd: (f) => `double-click ${f}` },
  { re: /cli-linux$/, group: "Terminal edition (CLI)", os: "Linux", fmt: "CLI binary", cmd: (f, u) => `curl -L ${u} -o darknode && chmod +x darknode && ./darknode` },
  { re: /cli-windows\.exe$/i, group: "Terminal edition (CLI)", os: "Windows", fmt: "CLI .exe", cmd: (f, u) => `curl.exe -L ${u} -o darknode.exe; .\\darknode.exe` },
  { re: /\.dmg$/, group: "Desktop app", os: "macOS", fmt: ".dmg (Apple Silicon + Intel)", cmd: (f) => `open ${f}   # then drag Darknode to Applications` },
  { re: /-macos-arm64$/, group: "Terminal edition (CLI)", os: "macOS · Apple Silicon", fmt: "CLI binary", cmd: (f, u) => `curl -L ${u} -o darknode && chmod +x darknode && codesign --sign - darknode && ./darknode` },
  { re: /-macos-x64$/, group: "Terminal edition (CLI)", os: "macOS · Intel", fmt: "CLI binary", cmd: (f, u) => `curl -L ${u} -o darknode && chmod +x darknode && codesign --sign - darknode && ./darknode` },
];
const fmtSize = (n) => n > 1e9 ? (n / 1e9).toFixed(2) + " GB" : n > 1e6 ? (n / 1e6).toFixed(1) + " MB" : (n / 1e3).toFixed(0) + " KB";
const verOf = (name) => (name.match(/(\d+\.\d+\.\d+)/) || [])[1] || "";

const SITE = "https://darknode.ai";
const OS_REPO = "https://github.com/SpartanKing18/darknode-os";
const NEXUS_REPO = "https://github.com/SpartanKing18/nexus";
const APP_EDITIONS = [
  { name: "Netinstall", tag: "lightest · ~95 MB", desc: "Just the app. Every tool auto-configures itself the first time you launch it — nothing pre-downloaded.", steps: ["Install the .deb / AppImage / .exe from the Builds tab.", "Open any tool — Darknode sets it up on first use."] },
  { name: "Slim", tag: "recommended", desc: "The app plus the essential toolset: recon, web, and password tools.", steps: ["Install the app from the Builds tab.", `curl -sL ${SITE}/arsenal.sh | bash -s -- recon web passwords`] },
  { name: "Full", tag: "everything + AI", desc: "The app, the complete arsenal (all 10 categories), and local AI models.", steps: ["Install the app from the Builds tab.", `curl -sL ${SITE}/arsenal.sh | bash`, "Local AI (Ollama + models) is set up automatically on first launch."] },
];
const CLI_EDITIONS = [
  { name: "git clone", tag: "tiny · ~300 KB", desc: "Clone the source and run with Node — no 52 MB binary on disk, and git pull keeps it current. Needs Node 18+.", steps: ["git clone https://github.com/SpartanKing18/darknode-cli && cd darknode-cli && node darknode.js"] },
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
    <p class="muted pg-sub">The desktop app, terminal edition, and the full Darknode OS VM go far beyond the web console &mdash; a native port scanner, DNS/WHOIS/TLS recon, subdomain enumeration, a code workbench, live terminals, an autonomous AI agent, and auto-configuring tools.</p>
    <p style="margin:-6px 0 14px"><button class="btn ghost" data-sec="dlguide">Not sure which to download? Read the full guide &rarr;</button></p>
    <div class="card" style="max-width:640px;border-color:color-mix(in srgb,var(--acc) 45%,transparent);margin-bottom:14px">
      <h2 class="pg-h2" style="margin:0 0 6px">Nexus &mdash; AI coding agent</h2>
      <p class="muted" style="font-size:.85rem;margin:0 0 10px">A terminal AI coder (like Claude Code) built into the CLI: it edits files and runs commands using your own local models &mdash; private, no cloud. Download the CLI, then run <code data-cmd>darknode nexus</code>.</p>
      <div class="btns" style="flex-wrap:wrap;gap:8px">
        <a class="btn" href="${REL_DL}/Darknode-cli-linux" download>Nexus (CLI) &middot; Linux</a>
        <a class="btn" href="${REL_DL}/Darknode-cli-windows.exe" download>Nexus (CLI) &middot; Windows</a>
        <button class="btn ghost" data-sec="coder">About Nexus</button>
        <a class="btn ghost" href="${NEXUS_REPO}" target="_blank" rel="noopener">Nexus source &middot; GitHub</a>
      </div>
    </div>
    <div class="card" style="max-width:640px;border-color:color-mix(in srgb,var(--acc) 45%,transparent);margin-bottom:14px">
      <h2 class="pg-h2" style="margin:0 0 6px">Darknode OS &mdash; the security VM</h2>
      <p class="muted" style="font-size:.85rem;margin:0 0 10px">A self-provisioning Linux workstation &mdash; a Kali / BlackArch alternative. Pick the edition that fits: a bare terminal, a lean desktop, or the everything build. Each boots in VirtualBox or QEMU/KVM and self-configures on first launch.</p>
      <div class="btns" style="flex-wrap:wrap;gap:8px;margin-bottom:12px">
        <a class="btn" href="${OS_REPO}" target="_blank" rel="noopener">Get Darknode OS &middot; GitHub</a>
        <a class="btn ghost" href="${OS_REPO}#readme" target="_blank" rel="noopener">Build &amp; boot guide</a>
      </div>
      <div class="os-editions">
        <div class="os-ed">
          <div class="os-ed-h"><b>netinstall</b><span class="os-ed-sz">~12&nbsp;GB</span></div>
          <p class="muted os-ed-d">Just a terminal &mdash; no desktop, no UI. Core CLI security stack + Nexus AI agent + local models. Boots straight to a console. Smallest &amp; fastest.</p>
          <div class="dlapp-cmd"><code data-cmd>./build.sh debian netinstall &amp;&amp; ./launch.sh netinstall</code></div>
        </div>
        <div class="os-ed">
          <div class="os-ed-h"><b>slim</b><span class="os-ed-sz">~20&nbsp;GB</span></div>
          <p class="muted os-ed-d">Full branded XFCE desktop + Nexus + the CLI toolset &mdash; minus Metasploit, SecLists, Docker and the cockpit app. A lean graphical workstation.</p>
          <div class="dlapp-cmd"><code data-cmd>./build.sh debian slim &amp;&amp; ./export-vbox.sh slim</code></div>
        </div>
        <div class="os-ed os-ed-full">
          <div class="os-ed-h"><b>full</b><span class="os-ed-sz">~30&nbsp;GB</span><span class="os-ed-tag">everything</span></div>
          <p class="muted os-ed-d">The complete workstation: desktop, cockpit app, Metasploit, SecLists, Exploit-DB, Docker, autonomous AI recon, honeypot &mdash; 80+ tools, all pre-installed.</p>
          <div class="dlapp-cmd"><code data-cmd>./build.sh debian full &amp;&amp; ./export-vbox.sh full</code></div>
        </div>
      </div>
      <p class="muted" style="font-size:.78rem;margin:10px 0 0">First <code>git clone ${OS_REPO} &amp;&amp; cd darknode-os</code>. The image builds from Debian + a cloud-init recipe on your own machine (nothing to host); first boot sets everything up. On macOS: <code>brew install qemu</code>, then <code>./launch.sh &lt;edition&gt;</code> or import the built <code>darknode-os-&lt;edition&gt;.qcow2</code> into UTM / VirtualBox.</p>
    </div>
    <h2 class="pg-h2">1 · Choose a build</h2>
    <p class="muted" style="font-size:.85rem;margin:-6px 0 12px">Prefer just the app or the terminal edition? Grab the latest build for your platform — Linux, Windows or macOS.</p>
    <div class="card" style="max-width:760px">
      <div id="dlBuilds" class="dl-builds"><p class="muted" style="margin:0">Loading the latest builds…</p></div>
    </div>
    <h2 class="pg-h2" style="margin-top:24px">2 · Choose a setup edition</h2>
    <p class="muted" style="font-size:.85rem;margin:-6px 0 12px">Same installer, different amount of tooling. Pick how much you want set up, then run the command after installing.</p>
    <h3 class="pg-h3" style="margin:0 0 8px">Desktop app</h3>
    <div class="ed-grid">${APP_EDITIONS.map(edCard).join("")}</div>
    <h3 class="pg-h3" style="margin:22px 0 8px">Terminal edition (CLI)</h3>
    <div class="ed-grid">${CLI_EDITIONS.map(edCard).join("")}</div>
    <p class="muted" style="font-size:.78rem;margin-top:14px">Provisioning uses systems you own or are authorized to test. <a href="${SITE}/arsenal.sh" download>Download the script</a> to review it first.</p>
    <p class="muted" style="font-size:.8rem;margin-top:16px">All rights reserved.</p>`;
  const builds = main.querySelector("#dlBuilds");
  const cmpVer = (a, b) => { const pa = (a || "0").split(".").map(Number), pb = (b || "0").split(".").map(Number); for (let i = 0; i < 3; i++) { if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0); } return 0; };
  const osBtn = (m, a) => { const ver = verOf(a.name); return `<a class="dl-osbtn" href="${esc(a.browser_download_url)}" download>
      <span class="dl-os">${esc(m.os)}</span>
      <span class="dl-fmt">${esc(m.fmt)}${ver ? " · v" + esc(ver) : ""} · ${esc(fmtSize(a.size))}</span></a>`; };
  const fallback = () => {
    builds.innerHTML = `<p class="muted" style="margin:0 0 10px">Live release info unavailable &mdash; download directly:</p>
      <div class="dl-btnrow">
        <a class="dl-osbtn" href="${REL_DL}/Darknode-cli-linux" download><span class="dl-os">Linux</span><span class="dl-fmt">Nexus CLI</span></a>
        <a class="dl-osbtn" href="${REL_DL}/Darknode-cli-windows.exe" download><span class="dl-os">Windows</span><span class="dl-fmt">Nexus CLI</span></a>
        <a class="dl-osbtn" href="${REL_DL}/Darknode-cli-macos-arm64" download><span class="dl-os">macOS · Apple Silicon</span><span class="dl-fmt">Nexus CLI</span></a>
        <a class="dl-osbtn" href="${REL_DL}/Darknode-cli-macos-x64" download><span class="dl-os">macOS · Intel</span><span class="dl-fmt">Nexus CLI</span></a>
      </div>`;
  };
  const ctrl = new AbortController(); setTimeout(() => ctrl.abort(), 8000);
  fetch("https://api.github.com/repos/" + REPO + "/releases/tags/" + TAG, { signal: ctrl.signal })
    .then((r) => r.ok ? r.json() : Promise.reject())
    .then((rel) => {
      const all = rel.assets || [];
      // one button per platform/format — the LATEST version only (by semver, then upload time)
      const latest = META.map((m) => {
        const ms = all.filter((a) => m.re.test(a.name));
        if (!ms.length) return null;
        ms.sort((a, b) => cmpVer(verOf(b.name), verOf(a.name)) || (new Date(b.created_at) - new Date(a.created_at)));
        return { m, a: ms[0] };
      }).filter(Boolean);
      if (!latest.length) return fallback();
      const groups = [...new Set(META.map((m) => m.group))];
      builds.innerHTML = groups.map((g) => {
        const items = latest.filter((x) => x.m.group === g);
        if (!items.length) return "";
        return `<div class="dl-bgroup"><h4 class="dl-bh">${esc(g)}</h4><div class="dl-btnrow">` + items.map(({ m, a }) => osBtn(m, a)).join("") + `</div></div>`;
      }).join("");
    })
    .catch(fallback);

  main.addEventListener("click", (e) => {
    const c = e.target.closest("code[data-cmd]"); if (!c) return;
    navigator.clipboard?.writeText(c.textContent).then(() => { c.style.outline = "1px solid var(--acc)"; setTimeout(() => (c.style.outline = ""), 500); });
  });
  main.querySelectorAll("[data-sec]").forEach((b) => b.addEventListener("click", () => { const it = document.querySelector('.side-item[data-sec="' + b.dataset.sec + '"]'); if (it) it.click(); }));
}

// ---------------------------------------------------------------------------
// Download guide — a full, plain-English explanation of every download option:
// what it is, who it's for, requirements, exact install/run steps, and gotchas.
// ---------------------------------------------------------------------------
const dlDoc = (d) => `
  <div class="card dl-doc" style="max-width:760px;margin:0 0 14px">
    <div class="ed-head" style="align-items:baseline">
      <h3 style="margin:0">${esc(d.title)}</h3>
      <span class="chip">${esc(d.os)} · ${esc(d.fmt)}</span>
    </div>
    <p class="muted" style="font-size:.86rem;margin:8px 0 4px"><b>What it is.</b> ${d.what}</p>
    <p class="muted" style="font-size:.86rem;margin:4px 0"><b>Best if.</b> ${d.best}</p>
    <p class="muted" style="font-size:.86rem;margin:4px 0"><b>Requirements.</b> ${d.req}</p>
    <div style="margin:10px 0 2px;font-size:.8rem;color:var(--mut);text-transform:uppercase;letter-spacing:.05em">Install &amp; run</div>
    <ol class="ed-steps">${d.steps.map((s) => s.cmd ? `<li>${s.t ? esc(s.t) + "<br>" : ""}<code data-cmd>${esc(s.cmd)}</code></li>` : `<li>${s.t}</li>`).join("")}</ol>
    ${d.note ? `<p class="muted" style="font-size:.8rem;margin:8px 0 0"><b>Note.</b> ${d.note}</p>` : ""}
    ${d.trouble ? `<details style="margin-top:8px"><summary class="muted" style="cursor:pointer;font-size:.82rem">Troubleshooting</summary><p class="muted" style="font-size:.82rem;margin:6px 0 0">${d.trouble}</p></details>` : ""}
  </div>`;

const DL_LINUX_DEB = `${REL_DL}/darknode-app_2.45.0_amd64.deb`;
const DL_APPIMG = `${REL_DL}/Darknode-2.45.0.AppImage`;
const DL_WIN = `${REL_DL}/Darknode.Setup.2.45.0.exe`;

const APP_DOCS = [
  { title: "Desktop app — Debian / Ubuntu installer", os: "Linux", fmt: ".deb",
    what: "The full Darknode desktop application packaged as a native <code>.deb</code>. Installs into <code>/opt/Darknode</code>, adds a menu entry, and wires up the AI Assistant, VM runner, recon tools and live terminals.",
    best: "you run Debian, Ubuntu, Kali, Pop!_OS or any apt-based distro and want a normal installed app with a launcher icon.",
    req: "64-bit Linux (x86-64), apt, ~250&nbsp;MB free. Local AI features use Ollama, which the Darknode CLI installs for you.",
    steps: [ { t: "Download the .deb from the Builds tab, then install it (pulls in any missing system libraries):", cmd: `sudo apt install ./darknode-app_2.45.0_amd64.deb` }, { t: "Launch it from your app menu, or from a terminal:", cmd: `darknode-app` } ],
    note: "Updating later? Just <code>sudo apt install ./&lt;newer&gt;.deb</code> over the top — settings are preserved.",
    trouble: "If it won't open, run <code>darknode-app</code> in a terminal to see the error. A sandbox error on some kernels is fixed by launching with <code>darknode-app --no-sandbox</code>. Missing-AI replies mean Ollama isn't running: <code>ollama serve</code>." },
  { title: "Desktop app — AppImage (portable)", os: "Linux", fmt: "AppImage",
    what: "A single self-contained file that runs the desktop app without installing anything. Nothing is written to system directories — delete the file and it's gone.",
    best: "you can't or don't want to use apt (non-Debian distro, no root, a USB stick, or just trying it out).",
    req: "64-bit Linux with FUSE (present on most desktops), ~250&nbsp;MB free.",
    steps: [ { t: "Download the AppImage, make it executable, then run it:", cmd: `chmod +x Darknode-2.45.0.AppImage && ./Darknode-2.45.0.AppImage` } ],
    note: "It does not auto-update — grab a newer AppImage when you want the latest.",
    trouble: "\"FUSE\" error? Install it (<code>sudo apt install libfuse2</code>) or extract-and-run with <code>./Darknode-2.45.0.AppImage --appimage-extract-and-run</code>." },
  { title: "Desktop app — Windows installer", os: "Windows", fmt: ".exe",
    what: "The standard Windows installer (NSIS). Sets up the app, a Start-menu shortcut and an uninstaller.",
    best: "you're on Windows 10 or 11 and want the graphical app.",
    req: "Windows 10/11 64-bit. Local AI features use Ollama, which the Darknode CLI installs for you.",
    steps: [ { t: "Download and double-click the installer, then follow the prompts:", cmd: `Darknode.Setup.2.45.0.exe` }, { t: "Launch “Darknode” from the Start menu." } ],
    trouble: "SmartScreen may warn on a new unsigned build — choose “More info → Run anyway”. It's the same binary published on GitHub Releases." },
  { title: "Desktop app — macOS (.dmg)", os: "macOS", fmt: ".dmg · Apple Silicon + Intel",
    what: "The Darknode desktop app as a native macOS <code>.dmg</code> (universal — Apple Silicon and Intel). Same AI Assistant, VM runner, recon tools and live terminals as every other platform.",
    best: "you're on macOS 12+ and want the graphical app.",
    req: "macOS 12 (Monterey) or newer, ~300&nbsp;MB free. Local AI uses Ollama (<code>brew install ollama</code>).",
    steps: [ { t: "Download the .dmg from the Builds tab, open it, and drag Darknode to Applications:", cmd: `open Darknode-*.dmg` }, { t: "First launch: right-click the app → Open (unsigned build) to clear Gatekeeper once." } ],
    note: "Built with <code>npm run dist:mac</code> from source on a Mac if a signed release isn't posted yet.",
    trouble: "\"App is damaged / can't be opened\" (Gatekeeper on an unsigned build): <code>xattr -dr com.apple.quarantine /Applications/Darknode.app</code>, then open it." },
];

const CLI_DOCS = [
  { title: "Nexus / CLI — Linux binary", os: "Linux", fmt: "standalone binary",
    what: "The terminal edition as one self-contained executable (Node is bundled in). Gives you the whole toolkit plus <b>Nexus</b>, the AI coding agent, with no runtime to install.",
    best: "you live in the terminal, are on a server/headless box, or want the AI coder without installing Node.",
    req: "64-bit Linux. Nothing else for the tools. Nexus's <code>claude</code> engine needs the Claude Code CLI; the free <code>ollama</code> engine needs Ollama.",
    steps: [ { t: "Download, mark executable, and (optionally) put it on your PATH:", cmd: `curl -L ${REL_DL}/Darknode-cli-linux -o darknode && chmod +x darknode && sudo mv darknode /usr/local/bin/` }, { t: "Run the AI coder:", cmd: `darknode nexus --tui` } ],
    note: "No PATH access? Just run <code>./darknode</code> from wherever you saved it.",
    trouble: "“Permission denied” means it isn't executable yet: <code>chmod +x darknode</code>." },
  { title: "Nexus / CLI — Windows executable", os: "Windows", fmt: "CLI .exe",
    what: "The same terminal edition and Nexus agent, compiled for Windows as a standalone <code>.exe</code>.",
    best: "you want the CLI and Nexus on Windows without installing Node.",
    req: "Windows 10/11 64-bit. Use Windows Terminal / PowerShell for the best rendering.",
    steps: [ { t: "Download it, then run from PowerShell:", cmd: `curl.exe -L ${REL_DL}/Darknode-cli-windows.exe -o darknode.exe; .\\darknode.exe nexus --tui` } ],
    trouble: "If box-drawing looks off, use Windows Terminal (not the legacy console)." },
  { title: "Nexus / CLI — macOS binary", os: "macOS", fmt: "Apple Silicon + Intel",
    what: "The terminal edition + Nexus AI agent as a standalone macOS binary. Pick <code>Darknode-cli-macos-arm64</code> (Apple Silicon) or <code>-x64</code> (Intel).",
    best: "you want the CLI on a Mac without installing Node.",
    req: "macOS 12+. The free <code>ollama</code> engine (default) needs Ollama (<code>brew install ollama</code>) — no API key, no cost.",
    steps: [ { t: "Download, make executable, ad-hoc sign (Apple Silicon requires it), then run:", cmd: `curl -L ${REL_DL}/Darknode-cli-macos-arm64 -o darknode && chmod +x darknode && codesign --sign - darknode && ./darknode nexus --tui` } ],
    note: "Prefer no binary? <code>git clone</code> below runs on macOS with Node — nothing to sign.",
    trouble: "\"killed\" / \"cannot be opened\": it needs the ad-hoc signature above (<code>codesign --sign - darknode</code>), then <code>xattr -d com.apple.quarantine darknode</code> if downloaded via a browser." },
  { title: "Nexus / CLI — from source (git clone)", os: "Any", fmt: "~300 KB + Node",
    what: "Run the CLI straight from source with Node. Tiny footprint, and <code>git pull</code> keeps it current.",
    best: "you already have Node 18+ and want the smallest download or plan to tweak the code.",
    req: "Node.js 18 or newer, git.",
    steps: [ { t: "Clone and run:", cmd: `git clone https://github.com/SpartanKing18/darknode-cli && cd darknode-cli && node darknode.js nexus --tui` } ],
    note: "Update anytime with <code>git pull</code> — no re-download." },
];

export function renderDownloadDocs(main) {
  main.innerHTML = `
    <h1 class="pg-h1">Download guide</h1>
    <p class="muted pg-sub">Every download in plain English &mdash; what it is, who it's for, and exactly how to install and run it. Not sure? Start with the picker below.</p>

    <div class="card" style="max-width:760px;margin-bottom:16px">
      <h2 class="pg-h2" style="margin:0 0 8px">Which one should I get?</h2>
      <div style="overflow-x:auto"><table class="cmp-table"><tbody>
        <tr><td>I want a normal app with a window &amp; icon</td><td class="yes">Desktop app</td><td>.deb (Ubuntu/Kali) · AppImage (any Linux) · .exe (Windows)</td></tr>
        <tr><td>I want the AI coding agent (Nexus) in my terminal</td><td class="yes">Terminal edition (CLI)</td><td>Linux binary · Windows .exe · or git clone</td></tr>
        <tr><td>I'm on a server / headless box</td><td class="yes">CLI Linux binary</td><td>no GUI, no Node needed</td></tr>
        <tr><td>I can't use apt / want zero install</td><td class="yes">AppImage</td><td>one file, just run it</td></tr>
        <tr><td>I already have Node and want the smallest download</td><td class="yes">git clone</td><td>~300&nbsp;KB, <code>git pull</code> to update</td></tr>
      </tbody></table></div>
      <p class="muted" style="font-size:.82rem;margin:10px 0 0">The desktop app and the CLI share the same toolkit. The difference is the interface: a window vs. your terminal. You can run both.</p>
    </div>

    <h2 class="pg-h2">Desktop app</h2>
    <p class="muted" style="font-size:.85rem;margin:-4px 0 12px">A graphical app: AI Assistant, VM lab runner, recon &amp; exploitation tools, live terminals.</p>
    ${APP_DOCS.map(dlDoc).join("")}

    <h2 class="pg-h2" style="margin-top:22px">Terminal edition &amp; Nexus</h2>
    <p class="muted" style="font-size:.85rem;margin:-4px 0 12px">The full toolkit plus <b>Nexus</b> &mdash; the AI coding agent with a live token/cost meter, <code>/undo</code> checkpoints, and a hybrid local+cloud engine. Run <code data-cmd>darknode nexus --tui</code> after installing.</p>
    ${CLI_DOCS.map(dlDoc).join("")}

    <h2 class="pg-h2" style="margin-top:22px">Setup editions (how much tooling)</h2>
    <p class="muted" style="font-size:.85rem;margin:-4px 0 12px">After you install either the app or the CLI, pick how much of the external toolset to provision. Same program &mdash; just more tools set up.</p>
    <h3 class="pg-h3" style="margin:0 0 8px">Desktop app</h3>
    <div class="ed-grid">${APP_EDITIONS.map(edCard).join("")}</div>
    <h3 class="pg-h3" style="margin:22px 0 8px">Terminal edition (CLI)</h3>
    <div class="ed-grid">${CLI_EDITIONS.map(edCard).join("")}</div>

    <h2 class="pg-h2" style="margin-top:22px">After you install</h2>
    <div class="card" style="max-width:760px">
      <ol class="ed-steps">
        <li><b>Desktop app:</b> open it and pick a tool &mdash; anything not present auto-configures on first use.</li>
        <li><b>CLI:</b> scaffold a project with <code data-cmd>darknode init</code>, then start the agent with <code data-cmd>darknode nexus --tui</code>.</li>
        <li><b>For free/local AI:</b> the Darknode CLI installs Ollama + local models for you on setup &mdash; then just <code data-cmd>darknode nexus --engine ollama</code>.</li>
        <li><b>For the strongest AI:</b> install the Claude Code CLI and log in; Nexus's default <code>claude</code> engine drives it and shows your real token cost per turn.</li>
      </ol>
    </div>

    <h2 class="pg-h2" style="margin-top:22px">Updating &amp; removing</h2>
    <div class="card" style="max-width:760px">
      <p class="muted" style="font-size:.85rem;margin:0 0 6px"><b>Update:</b> .deb &mdash; install the newer file over the top. AppImage / CLI binary &mdash; download the new one. git clone &mdash; <code data-cmd>git pull</code>.</p>
      <p class="muted" style="font-size:.85rem;margin:0"><b>Remove:</b> .deb &mdash; <code data-cmd>sudo apt remove darknode-app</code>. AppImage / CLI binary &mdash; delete the file. Windows &mdash; use “Add or remove programs”.</p>
    </div>

    <p class="muted" style="font-size:.8rem;margin-top:16px">All rights reserved. &middot; <button class="linklike" data-sec="downloads">Back to downloads</button> &middot; <button class="linklike" data-sec="coder">About Nexus</button></p>`;

  main.addEventListener("click", (e) => {
    const c = e.target.closest("code[data-cmd]"); if (c) { navigator.clipboard?.writeText(c.textContent).then(() => { c.style.outline = "1px solid var(--acc)"; setTimeout(() => (c.style.outline = ""), 500); }); return; }
  });
  main.querySelectorAll("[data-sec]").forEach((b) => b.addEventListener("click", () => { const it = document.querySelector('.side-item[data-sec="' + b.dataset.sec + '"]'); if (it) it.click(); }));
}
