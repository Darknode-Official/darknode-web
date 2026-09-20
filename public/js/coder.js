// Nexus — showcase page for `darknode nexus`, the terminal AI coding agent built
// into the Darknode CLI: multi-engine (Claude / local Ollama / OpenCode), private,
// git-native, security-aware, single dependency-free binary.
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const REL = "https://github.com/Darknode-Official/darknode-web/releases/download/darknode";

// features shown in the grid: [command/label, title, description, tag?]
const FEATURES = [
  ["/race", "Race cloud vs local", "Run the same prompt on Claude <b>and</b> your local model at once, see every answer, keep the best. No other agent does this.", "unique"],
  ["/review", "Cross-engine second opinion", "Have a <b>different</b> model critique the last answer for bugs and security holes before you ship it.", "unique"],
  ["hybrid", "Hybrid cost-saver", "Local model does the routine work, Claude only the hard parts — often cutting your Claude bill by well over half.", ""],
  ["/watch", "Auto-fix loop", "Give it a test or build command; it runs, reads the failure, fixes the code, and re-runs until green.", "unique"],
  ["/redact", "Cloud privacy layer", "Masks API keys, tokens and private keys <b>before</b> anything is sent to a cloud engine. Your local runs never leave the box.", "unique"],
  ["/undo", "Git checkpoints", "A safe checkpoint before every turn — <b>/undo</b>, <b>/redo</b> and <b>/rewind N</b> restore your files instantly.", ""],
  ["meter", "Live cost & context meter", "Real token usage, dollar cost and context % in the status bar, plus <b>/budget</b> to hard-cap spend.", ""],
  ["/agents", "Parallel sub-agents", "Fan independent tasks out across the engine at once — <code>/agents a ;; b ;; c</code>.", ""],
  ["MCP", "MCP + hooks", "Connect MCP servers from <code>.nexus/mcp.json</code>; run shell hooks on prompt/tool/stop events.", ""],
  ["tools", "Full device access", "Local agent can read/write/edit files, run any shell command, search &amp; find, fetch URLs, inspect the system and manage the filesystem.", ""],
  ["/secrets", "Security toolkit", "Built-in secret scanner, <b>/scan</b> port scanner, plus recon &amp; exploitation in the desktop app.", ""],
  ["overnight", "Overnight autonomy", "Plans a big goal into tasks, executes, verifies and checkpoints so it can run for hours and resume.", ""],
];

// slash-command palette
const CMDS = [
  "/cowork", "/cheap", "/lean", "/effort", "/estimate", "/models", "/recent", "/docs", "/race", "/ensemble", "/bench", "/review", "/watch", "/commit", "/diff", "/explain", "/test", "/index", "/snippet",
  "/plan", "/guard", "/impact", "/gaps", "/dream", "/git", "/blame", "/pin", "/redact", "/offline", "/secrets", "/scan", "/agents", "/mcp", "/hooks", "/undo", "/redo", "/rewind",
  "/budget", "/cost", "/tree", "/theme", "/resume", "/export", "/copy", "/status", "/doctor", "/engine", "@file", "!cmd", "#note",
];

function terminalMock() {
  const line = (cls, html) => `<div class="l ${cls}">${html}</div>`;
  return `
  <div class="nx-term">
    <div class="nx-term-bar"><span class="nx-dot r"></span><span class="nx-dot y"></span><span class="nx-dot g"></span><span class="nx-term-t">darknode nexus --tui</span></div>
    <div class="nx-term-body">
      ${line("", `<span class="nx-logo">███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗</span>`)}
      ${line("", `<span class="nx-logo">██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗</span>`)}
      ${line("", `<span class="nx-logo">╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝</span>`)}
      ${line("nx-g", `AI coding agent · claude · ~/app`)}
      ${line("", `<span class="nx-m">› you</span> add rate limiting to the API and run the tests`)}
      ${line("", `<span class="nx-c">● nexus</span>  <span class="nx-g">claude</span>`)}
      ${line("nx-g", `  ● thinking (ctrl+o to show)`)}
      ${line("", `  <span class="nx-ok">●</span> <b>Read(server.js)</b> <span class="nx-g">0.2s</span>`)}
      ${line("", `  <span class="nx-ok">●</span> <b>Update(server.js)</b> <span class="nx-g">0.4s</span>`)}
      ${line("", `  <span class="nx-ok">●</span> <b>Bash(npm test)</b> <span class="nx-g">3.1s</span>`)}
      ${line("nx-w", `  Added a token-bucket limiter and 3 tests — all green.`)}
      ${line("nx-g", `  1 file · 1 cmd · ↑12.4k ↓380 tok · $0.03 · 6.2s · undo #1`)}
      ${line("nx-rule", `────────────────────────────────────────────────────────`)}
      ${line("", `<span class="nx-c">opus-4-8</span> <span class="nx-g">· ctx</span> <span class="nx-c">6%</span> <span class="nx-g">▓░░░░░░░ · ↑12.4k ↓380 tok ·</span> <span class="nx-ok">$0.03</span> <span class="nx-g">·</span> <span class="nx-ok">auto-accept</span>`)}
      ${line("nx-rule", `────────────────────────────────────────────────────────`)}
      ${line("", `<span class="nx-prompt">></span> <span class="nx-g">/race how should I shard this table?</span>`)}
    </div>
  </div>`;
}

export function renderCliCoder(main) {
  main.innerHTML = `
    <section class="nx-hero">
      <span class="nx-badge">darknode nexus · terminal AI agent</span>
      <h1 class="nx-title">Code with cloud and local AI —<br>on your terms.</h1>
      <p class="nx-sub">Nexus is a single dependency-free binary that drives <b>Claude</b>, your <b>local</b> models, or <b>OpenCode</b> from one terminal UI. It reads &amp; writes files, runs commands, checkpoints every change, shows your real cost live, and keeps your secrets off the cloud.</p>
      <div class="nx-cta">
        <a class="btn lg" href="${REL}/Darknode-cli-linux" download>Download · Linux</a>
        <a class="btn lg ghost" href="${REL}/Darknode-cli-windows.exe" download>Download · Windows</a>
        <button class="btn lg ghost" data-sec="downloads">All builds</button>
      </div>
      ${terminalMock()}
    </section>

    <h2 class="nx-h2">Why Nexus</h2>
    <p class="nx-lead">Everything Claude Code does — plus the things only a multi-engine, local-first, security-native agent can.</p>
    <div class="nx-grid">
      ${FEATURES.map((f) => `
        <div class="nx-feat">
          ${f[3] ? `<span class="nx-tag">${esc(f[3])}</span>` : ""}
          <h4>${/^\/|^@|^!|^#/.test(f[0]) ? `<code>${esc(f[0])}</code>` : ""}${esc(f[1])}</h4>
          <p>${f[2]}</p>
        </div>`).join("")}
    </div>

    <h2 class="nx-h2">One command bar, everything at hand</h2>
    <p class="nx-lead">Type <code>/</code> for the full menu. A few of the built-ins:</p>
    <div class="nx-chips">
      ${CMDS.map((c) => `<span class="nx-chip"><b>${esc(c)}</b></span>`).join("")}
    </div>

    <h2 class="nx-h2">Nexus vs Claude Code</h2>
    <div style="overflow-x:auto">
    <table class="cmp-table">
      <thead><tr><th></th><th>Nexus</th><th>Claude Code</th></tr></thead>
      <tbody>
        <tr><td>Engines</td><td class="yes">Claude, local Ollama, or OpenCode</td><td>Claude only</td></tr>
        <tr><td>Works offline / free option</td><td class="yes">Yes (local models)</td><td>No</td></tr>
        <tr><td>Race cloud vs local in one keystroke</td><td class="yes">Yes (/race)</td><td>No</td></tr>
        <tr><td>Cross-engine second opinion</td><td class="yes">Yes (/review)</td><td>No</td></tr>
        <tr><td>Hybrid cost-saver</td><td class="yes">Yes</td><td>No</td></tr>
        <tr><td>Live token, context &amp; real cost meter</td><td class="yes">Always on</td><td>Partial</td></tr>
        <tr><td>Spend cap that halts runaway cost</td><td class="yes">Yes (/budget)</td><td>No</td></tr>
        <tr><td>Secrets masked before cloud sends</td><td class="yes">Yes (/redact)</td><td>No</td></tr>
        <tr><td>Git checkpoints · undo · redo · rewind</td><td class="yes">Yes</td><td>Interactive only</td></tr>
        <tr><td>Auto test-fix loop</td><td class="yes">Yes (/watch)</td><td>Manual</td></tr>
        <tr><td>MCP servers &amp; project hooks</td><td class="yes">Yes</td><td>Yes</td></tr>
        <tr><td>Nexus-driven parallel sub-agents</td><td class="yes">Yes (/agents)</td><td>Its own</td></tr>
        <tr><td>Security toolkit (scan, recon, VM labs)</td><td class="yes">Yes</td><td>No</td></tr>
        <tr><td>Single self-contained binary</td><td class="yes">Yes</td><td>Needs Node + npm</td></tr>
        <tr><td>Price</td><td class="yes">Free</td><td>Subscription</td></tr>
      </tbody>
    </table>
    </div>

    <h2 class="nx-h2">Get started</h2>
    <pre class="code-block"><button class="cb-copy">copy</button><code># download the Darknode CLI — it installs Ollama + local models for you:
darknode init                    # scaffold .nexus/ (project context Nexus reads each session)
darknode nexus --tui             # full-screen UI (Claude if installed, else local)
darknode nexus --tui -e ollama   # drive a 100% local, private agent</code></pre>
    <div class="btns" style="margin:12px 0;flex-wrap:wrap;gap:8px">
      <a class="btn" href="${REL}/Darknode-cli-linux" download>CLI · Linux</a>
      <a class="btn" href="${REL}/Darknode-cli-windows.exe" download>CLI · Windows</a>
      <button class="btn ghost" data-sec="dlguide">Download guide</button>
    </div>

    <h2 class="nx-h2">Autonomous runs</h2>
    <p class="nx-lead">Give Nexus a big goal; it plans, executes, verifies and checkpoints so it can run for hours and resume.</p>
    <pre class="code-block"><button class="cb-copy">copy</button><code>darknode nexus run "build a REST API with tests" --engine hybrid
darknode nexus overnight "refactor and fix all failing tests" --until 07:00
darknode nexus agents "add tests" "write docs" "fix lint"   # parallel
darknode nexus run --resume                                  # continue where it left off</code></pre>
    <p class="muted" style="margin-top:16px">Prefer a GUI? The same agent — plus recon, exploitation and VM-lab tools — lives in the <button class="linklike" data-sec="downloads">desktop app</button>'s Assistant.</p>`;

  main.querySelectorAll(".cb-copy").forEach((b) => b.addEventListener("click", () => {
    const code = b.parentElement.querySelector("code");
    navigator.clipboard?.writeText(code.textContent).then(() => { b.textContent = "copied"; setTimeout(() => (b.textContent = "copy"), 1000); });
  }));
  main.querySelectorAll("[data-sec]").forEach((b) => b.addEventListener("click", () => {
    const it = document.querySelector('.side-item[data-sec="' + b.dataset.sec + '"]'); if (it) it.click();
  }));
}
