// Nexus — showcase page for `nexus`, the terminal AI coding agent built
// into the Darknode CLI: multi-engine (Claude Code, Gemini, Codex, OpenCode, Aider, local Ollama), private,
// git-native, security-aware, single dependency-free binary.
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// features shown in the grid: [command/label, title, description, tag?]
const FEATURES = [
  ["/race", "Race every engine", "Run the same prompt on every engine at once, cloud and local, see every answer and keep the best.", ""],
  ["/review", "Cross-engine second opinion", "Have a <b>different</b> model critique the last answer for bugs and security holes before you ship it.", ""],
  ["/cheap", "Lossless cost saver", "Keeps the prompt cache warm through breaks and stops sending unused skill descriptions: the same answers for fewer billed tokens. <a href=\"/docs#doc-cost\">Measured savings by model</a>.", ""],
  ["/cowork", "Split the work", "A strong model writes the code while a cheaper or free local model handles tests, builds and commit messages.", ""],
  ["/watch", "Auto-fix loop", "Give it a test or build command; it runs, reads the failure, fixes the code, and re-runs until green.", ""],
  ["/redact", "Cloud privacy layer", "Masks API keys, tokens and private keys <b>before</b> anything is sent to a cloud engine. Your local runs never leave the box.", ""],
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
      <span class="nx-badge">nexus · terminal AI agent</span>
      <h1 class="nx-title">Code with cloud and local AI —<br>on your terms.</h1>
      <p class="nx-sub">Nexus is a single dependency-free binary that drives six engines (<b>Claude Code</b>, <b>Gemini</b>, <b>Codex</b>, <b>OpenCode</b>, <b>Aider</b> and your <b>local</b> Ollama models) from one terminal UI. It reads &amp; writes files, runs commands, checkpoints every change, shows your real cost live, and keeps your secrets off the cloud.</p>
      <div class="nx-cta">
        <!-- NPM_SUSPENDED: restore <code>npm i -g darknode-cli</code> here when the npm account is back -->
        <pre class="code-block cta-cmd"><button class="cb-copy">copy</button><code>git clone https://github.com/Darknode-Official/darknode-cli &amp;&amp; cd darknode-cli &amp;&amp; node darknode.js nexus</code></pre>
        <button class="btn lg ghost" data-sec="downloads">All builds</button>
      </div>
      <p class="nx-sub" style="margin-top:8px;opacity:.75">Works everywhere Node 18+ runs — Linux, macOS, Windows. Needs git.</p>
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

    <h2 class="nx-h2">What Nexus adds on top of the engines it drives</h2>
    <p class="nx-sub">Nexus runs the agent CLIs you already use (it drives Claude Code for the Claude engine) and adds these to every one of them:</p>
    <div style="overflow-x:auto">
    <table class="cmp-table">
      <thead><tr><th>Adds</th><th>Command</th></tr></thead>
      <tbody>
        <tr><td>Six engines behind one set of commands</td><td class="yes">/engine</td></tr>
        <tr><td>Same prompt on every engine, keep the best</td><td class="yes">/race</td></tr>
        <tr><td>A different engine reviews the last answer</td><td class="yes">/review</td></tr>
        <tr><td>Savers that cannot lower answer quality</td><td class="yes">/cheap</td></tr>
        <tr><td>Prompt-cache countdown, warm vs cold cost</td><td class="yes">/warm</td></tr>
        <tr><td>Per-turn cost at exact list prices</td><td class="yes">/turns</td></tr>
        <tr><td>Spend cap checked within turns</td><td class="yes">/budget</td></tr>
        <tr><td>Secrets masked before cloud sends</td><td class="yes">/redact</td></tr>
        <tr><td>Destructive commands checked first</td><td class="yes">/guard</td></tr>
        <tr><td>Git checkpoints on every engine</td><td class="yes">/undo /redo /rewind</td></tr>
        <tr><td>Find the turn that broke your tests</td><td class="yes">/bisect</td></tr>
        <tr><td>Run until the tests pass</td><td class="yes">/watch</td></tr>
        <tr><td>Background sessions you can attach to</td><td class="yes">nexus bg</td></tr>
      </tbody>
    </table>
    </div>

    <h2 class="nx-h2">Get started</h2>
    <!-- NPM_SUSPENDED: restore the npm install block (npm i -g darknode-cli / nexus / nexus init / nexus --tui -e ollama) when the npm account is back -->
    <pre class="code-block"><button class="cb-copy">copy</button><code>git clone https://github.com/Darknode-Official/darknode-cli
cd darknode-cli
node darknode.js nexus              # start the agent (Claude if installed, else local)
node darknode.js nexus init        # optional: scaffold .nexus/ project context
node darknode.js nexus --tui -e ollama   # drive a 100% local, private agent</code></pre>
    <div class="btns" style="margin:12px 0;flex-wrap:wrap;gap:8px">
      <!-- NPM_SUSPENDED: restore the "View on npm" link (https://www.npmjs.com/package/darknode-cli) when the npm account is back -->
      <a class="btn" href="https://github.com/Darknode-Official/darknode-cli" target="_blank" rel="noopener">Source on GitHub</a>
      <button class="btn ghost" data-sec="dlguide">Download guide</button>
    </div>

    <h2 class="nx-h2">Autonomous runs</h2>
    <p class="nx-lead">Give Nexus a big goal; it plans, executes, verifies and checkpoints so it can run for hours and resume.</p>
    <pre class="code-block"><button class="cb-copy">copy</button><code>nexus run "build a REST API with tests" --engine hybrid
nexus overnight "refactor and fix all failing tests" --until 07:00
nexus agents "add tests" "write docs" "fix lint"   # parallel
nexus run --resume                                 # continue where it left off</code></pre>
    <p class="muted" style="margin-top:16px">Prefer a GUI? The same agent — plus recon, exploitation and VM-lab tools — lives in the <button class="linklike" data-sec="downloads">desktop app</button>'s Assistant.</p>`;

  main.querySelectorAll(".cb-copy").forEach((b) => b.addEventListener("click", () => {
    const code = b.parentElement.querySelector("code");
    navigator.clipboard?.writeText(code.textContent).then(() => { b.textContent = "copied"; setTimeout(() => (b.textContent = "copy"), 1000); });
  }));
  main.querySelectorAll("[data-sec]").forEach((b) => b.addEventListener("click", () => {
    const it = document.querySelector('.side-item[data-sec="' + b.dataset.sec + '"]'); if (it) it.click();
  }));
}
