// Download cards. Netlify can't host multi-GB tools/models, so these link to the
// official sources (and show the install command where that's the real "download").
export const DOWNLOADS = [
  {
    group: "Editors & runtimes",
    items: [
      { name: "Visual Studio Code", desc: "Code editor", url: "https://code.visualstudio.com/download" },
      { name: "Git", desc: "Version control", url: "https://git-scm.com/downloads" },
      { name: "Python", desc: "Language runtime", url: "https://www.python.org/downloads/" },
      { name: "Node.js", desc: "JS runtime", url: "https://nodejs.org/en/download" },
    ],
  },
  {
    group: "Ollama + models",
    items: [
      { name: "Ollama", desc: "Local LLM runner - install first", url: "https://ollama.com/download" },
      { name: "Model library", desc: "Browse pullable models", url: "https://ollama.com/library" },
      { name: "llama3.1", desc: "run: ollama pull llama3.1", cmd: "ollama pull llama3.1" },
      { name: "qwen2.5-coder", desc: "run: ollama pull qwen2.5-coder", cmd: "ollama pull qwen2.5-coder" },
      { name: "nomic-embed-text", desc: "embeddings - ollama pull nomic-embed-text", cmd: "ollama pull nomic-embed-text" },
    ],
  },
  {
    group: "Security tools",
    items: [
      { name: "Nmap", desc: "Network scanner", url: "https://nmap.org/download" },
      { name: "theHarvester", desc: "OSINT recon", url: "https://github.com/laramies/theHarvester/releases" },
      { name: "sqlmap", desc: "SQLi automation", url: "https://github.com/sqlmapproject/sqlmap/releases" },
      { name: "OpenSSH", desc: "SSH client/server", url: "https://www.openssh.com/portable.html" },
    ],
  },
];

export function renderDownloads(el) {
  if (!el) return;
  el.innerHTML = DOWNLOADS.map((g) => `
    <div class="dl-group">
      <div class="dl-group-title">${g.group}</div>
      <div class="dl-grid">
        ${g.items.map((it) => it.cmd
          ? `<div class="dl-card"><div class="dl-name">${it.name}</div><div class="dl-desc">${it.desc}</div><code class="dl-cmd">${it.cmd}</code></div>`
          : `<a class="dl-card" href="${it.url}" target="_blank" rel="noopener noreferrer"><div class="dl-name">${it.name} &#8599;</div><div class="dl-desc">${it.desc}</div></a>`
        ).join("")}
      </div>
    </div>`).join("");
}
