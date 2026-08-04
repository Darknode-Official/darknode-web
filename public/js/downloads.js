// Install commands with per-OS variants + local "installed" tracking.
// Netlify can't host the tools/models, so the "download" is the command you run.
// Installed state is per-browser (localStorage) since a website can't see your machine.

const OS_LABELS = { linux: "Linux", mac: "macOS", windows: "Windows" };
export function detectOS() {
  const s = (navigator.userAgent + " " + (navigator.platform || "")).toLowerCase();
  if (s.includes("win")) return "windows";
  if (s.includes("mac")) return "mac";
  return "linux";
}

const INST_KEY = "sentinel_installed";
export function getInstalled() {
  try { return new Set(JSON.parse(localStorage.getItem(INST_KEY) || "[]")); } catch { return new Set(); }
}
function saveInstalled(set) { try { localStorage.setItem(INST_KEY, JSON.stringify([...set])); } catch {} }
export function isInstalled(id) { return getInstalled().has(id); }

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

export const DOWNLOADS = [
  { group: "Editors & runtimes", items: [
    { id: "vscode", name: "Visual Studio Code", desc: "Code editor", cmds: {
      linux: "sudo snap install code --classic", mac: "brew install --cask visual-studio-code", windows: "winget install Microsoft.VisualStudioCode" } },
    { id: "git", name: "Git", desc: "Version control", cmds: {
      linux: "sudo apt install -y git", mac: "brew install git", windows: "winget install Git.Git" } },
    { id: "python", name: "Python", desc: "Language + pip", cmds: {
      linux: "sudo apt install -y python3 python3-pip", mac: "brew install python", windows: "winget install Python.Python.3.12" } },
    { id: "node", name: "Node.js", desc: "JS runtime + npm", cmds: {
      linux: "sudo apt install -y nodejs npm", mac: "brew install node", windows: "winget install OpenJS.NodeJS" } },
  ]},
  { group: "Ollama + models", items: [
    { id: "ollama", name: "Ollama", desc: "Local LLM runner - install first", cmds: {
      linux: "curl -fsSL https://ollama.com/install.sh | sh", mac: "brew install ollama", windows: "winget install Ollama.Ollama" } },
    { id: "m-llama", name: "llama3.1", desc: "General model", cmds: { linux: "ollama pull llama3.1", mac: "ollama pull llama3.1", windows: "ollama pull llama3.1" } },
    { id: "m-coder", name: "qwen2.5-coder", desc: "Coding model", cmds: { linux: "ollama pull qwen2.5-coder", mac: "ollama pull qwen2.5-coder", windows: "ollama pull qwen2.5-coder" } },
    { id: "m-embed", name: "nomic-embed-text", desc: "Embeddings", cmds: { linux: "ollama pull nomic-embed-text", mac: "ollama pull nomic-embed-text", windows: "ollama pull nomic-embed-text" } },
  ]},
  { group: "Security tools", items: [
    { id: "nmap", name: "Nmap", desc: "Network scanner", cmds: {
      linux: "sudo apt install -y nmap", mac: "brew install nmap", windows: "winget install Insecure.Nmap" } },
    { id: "theharvester", name: "theHarvester", desc: "OSINT recon", cmds: {
      linux: "sudo apt install -y theharvester", mac: "brew install theharvester", windows: "pipx install theHarvester" } },
    { id: "sqlmap", name: "sqlmap", desc: "SQLi automation", cmds: {
      linux: "sudo apt install -y sqlmap", mac: "brew install sqlmap", windows: "pip install sqlmap" } },
    { id: "openssh", name: "OpenSSH", desc: "SSH client + server", cmds: {
      linux: "sudo apt install -y openssh-client openssh-server", mac: "brew install openssh",
      windows: "Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0" } },
  ]},
];

// Tools shown in the interactive "Tools" checklist (the ones you actually run).
export const TOOLS = DOWNLOADS.find((g) => g.group === "Security tools").items;

let curOS = detectOS();
let _el = null;

export function renderDownloads(el) {
  _el = el;
  const inst = getInstalled();
  el.innerHTML = `
    <div class="os-tabs">${Object.keys(OS_LABELS).map((o) =>
      `<button class="os-tab${o === curOS ? " active" : ""}" data-os="${o}">${OS_LABELS[o]}</button>`).join("")}</div>
    ${DOWNLOADS.map((g) => `
      <div class="dl-group"><div class="dl-group-title">${g.group}</div>
        <div class="dl-grid">${g.items.map((it) => card(it, inst.has(it.id))).join("")}</div>
      </div>`).join("")}`;
  el.onclick = onClick;
}

function card(it, installed) {
  const cmd = it.cmds[curOS] || it.cmds.linux;
  return `<div class="dl-card${installed ? " installed" : ""}" id="dl-${it.id}" data-id="${it.id}">
    <div class="dl-name">${esc(it.name)}${installed ? ' <span class="dl-check">installed</span>' : ""}</div>
    <div class="dl-desc">${esc(it.desc)}</div>
    ${installed
      ? `<button class="dl-mark" data-act="uninstall" data-id="${it.id}">mark not installed</button>`
      : `<div class="dl-cmd-row"><code class="dl-cmd">${esc(cmd)}</code>
           <button class="dl-copy" data-act="copy" data-cmd="${esc(cmd)}">copy</button></div>
         <button class="dl-mark" data-act="install" data-id="${it.id}">mark installed</button>`}
  </div>`;
}

function onClick(ev) {
  const tab = ev.target.closest(".os-tab");
  if (tab) { curOS = tab.dataset.os; renderDownloads(_el); return; }
  const b = ev.target.closest("[data-act]");
  if (!b) return;
  const act = b.dataset.act;
  if (act === "copy") {
    navigator.clipboard?.writeText(b.dataset.cmd).then(() => {
      const t = b.textContent; b.textContent = "copied"; setTimeout(() => (b.textContent = t), 1200);
    });
  } else if (act === "install" || act === "uninstall") {
    const s = getInstalled();
    if (act === "install") s.add(b.dataset.id); else s.delete(b.dataset.id);
    saveInstalled(s);
    renderDownloads(_el);
    document.dispatchEvent(new CustomEvent("sentinel:installed-changed"));
  }
}

// Scroll to a tool's command card and flash it (used by the Tools checklist).
export function highlightTool(id) {
  const c = document.getElementById("dl-" + id);
  if (!c) return;
  c.scrollIntoView({ behavior: "smooth", block: "center" });
  c.classList.remove("flash"); void c.offsetWidth; c.classList.add("flash");
}
