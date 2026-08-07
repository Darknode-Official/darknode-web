// Downloads section for the signed-in console — links the desktop app and CLI
// (hosted on GitHub Releases). Kept in one place so URLs are easy to update.
const REL = "https://github.com/Darknode-Official/sentinel-web/releases/download/sentinel";
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

export function renderDownloads(main) {
  const item = (name, fmt, file, cmd) => `
    <div class="dlapp-item">
      <a class="dlapp-card" href="${REL}/${file}" download><div class="dlapp-os">${esc(name)}</div><div class="dlapp-fmt">${esc(fmt)}</div></a>
      <div class="dlapp-cmd"><span class="dlapp-cmd-l">Command</span><code data-cmd>${esc(cmd)}</code></div>
    </div>`;
  main.innerHTML = `
    <h1 class="pg-h1">Downloads</h1>
    <p class="muted pg-sub">The desktop app and terminal edition go far beyond the web console &mdash; a native port scanner, DNS/WHOIS/TLS recon, subdomain enumeration, a code workbench, live terminals, and local AI.</p>

    <h2 class="pg-h2">Desktop app</h2>
    <div class="dlapp-grid">
      ${item("Linux", ".deb installer", "sentinel-app_2.4.0_amd64.deb", "sudo apt install ./sentinel-app_2.4.0_amd64.deb")}
      ${item("Linux", "AppImage", "Sentinel-2.4.0.AppImage", "chmod +x Sentinel-2.4.0.AppImage && ./Sentinel-2.4.0.AppImage")}
      ${item("Windows", ".exe installer", "Sentinel.Setup.2.4.0.exe", "double-click Sentinel.Setup.2.4.0.exe")}
    </div>

    <h2 class="pg-h2">Terminal edition (CLI)</h2>
    <div class="dlapp-grid">
      ${item("Linux", "CLI binary", "Sentinel-cli-linux", "curl -L " + REL + "/Sentinel-cli-linux -o sentinel && chmod +x sentinel && ./sentinel")}
      ${item("Windows", "CLI .exe", "Sentinel-cli-windows.exe", "curl.exe -L " + REL + "/Sentinel-cli-windows.exe -o sentinel.exe; .\\sentinel.exe")}
    </div>

    <p class="muted" style="font-size:.8rem;margin-top:18px">All builds are MIT-licensed and run only tools you invoke on systems you're authorized to test.</p>`;

  main.addEventListener("click", (e) => {
    const c = e.target.closest("code[data-cmd]"); if (!c) return;
    navigator.clipboard?.writeText(c.textContent).then(() => { const o = c.style.outline; c.style.outline = "1px solid var(--acc)"; setTimeout(() => (c.style.outline = o), 500); });
  });
}
