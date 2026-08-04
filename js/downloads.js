// Download/install commands for tools + models (Debian/Kali-oriented). Each card
// shows the command to run; click "copy" to grab it. Netlify can't host the tools
// or multi-GB models, so the "download" is the command you run locally.
export const DOWNLOADS = [
  {
    group: "Editors & runtimes",
    items: [
      { name: "Visual Studio Code", desc: "Code editor", cmd: "sudo snap install code --classic" },
      { name: "Git", desc: "Version control", cmd: "sudo apt install -y git" },
      { name: "Python", desc: "Language + pip", cmd: "sudo apt install -y python3 python3-pip" },
      { name: "Node.js", desc: "JS runtime + npm", cmd: "sudo apt install -y nodejs npm" },
    ],
  },
  {
    group: "Ollama + models",
    items: [
      { name: "Ollama", desc: "Local LLM runner - install first", cmd: "curl -fsSL https://ollama.com/install.sh | sh" },
      { name: "llama3.1", desc: "General model", cmd: "ollama pull llama3.1" },
      { name: "qwen2.5-coder", desc: "Coding model", cmd: "ollama pull qwen2.5-coder" },
      { name: "nomic-embed-text", desc: "Embeddings", cmd: "ollama pull nomic-embed-text" },
    ],
  },
  {
    group: "Security tools",
    items: [
      { name: "Nmap", desc: "Network scanner", cmd: "sudo apt install -y nmap" },
      { name: "theHarvester", desc: "OSINT recon", cmd: "sudo apt install -y theharvester" },
      { name: "sqlmap", desc: "SQLi automation", cmd: "sudo apt install -y sqlmap" },
      { name: "OpenSSH", desc: "SSH client + server", cmd: "sudo apt install -y openssh-client openssh-server" },
    ],
  },
];

export function renderDownloads(el) {
  if (!el) return;
  const escAttr = (s) => String(s).replace(/"/g, "&quot;");
  el.innerHTML = DOWNLOADS.map((g) => `
    <div class="dl-group">
      <div class="dl-group-title">${g.group}</div>
      <div class="dl-grid">
        ${g.items.map((it) => `
          <div class="dl-card">
            <div class="dl-name">${it.name}</div>
            <div class="dl-desc">${it.desc}</div>
            <div class="dl-cmd-row">
              <code class="dl-cmd">${it.cmd}</code>
              <button class="dl-copy" data-cmd="${escAttr(it.cmd)}" title="Copy">copy</button>
            </div>
          </div>`).join("")}
      </div>
    </div>`).join("");

  el.onclick = (ev) => {
    const b = ev.target.closest(".dl-copy");
    if (!b) return;
    navigator.clipboard?.writeText(b.dataset.cmd).then(() => {
      const t = b.textContent; b.textContent = "copied"; setTimeout(() => (b.textContent = t), 1200);
    });
  };
}
