// CLI AI coder — showcase/docs page for `sentinel nexus`, the terminal AI coding agent
// built into the Sentinel CLI. Private & local (talks to the user's own Ollama).
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

export function renderCliCoder(main) {
  main.innerHTML = `
    <h1 class="pg-h1">Nexus <span class="pill">sentinel nexus</span></h1>
    <p class="muted pg-sub">A terminal AI coding agent built into the Sentinel CLI — like Glitch/Claude&nbsp;Code, but a single dependency-free binary that runs on <b>your</b> machine against <b>your</b> local models. It reads &amp; writes files and runs commands to finish a task, then verifies its own work.</p>

    <div class="card-grid">
      <div class="card"><div class="card-h">Private &amp; local</div><p class="muted">Talks only to your local Ollama (<code>127.0.0.1:11434</code>). No cloud, no API keys — your code never leaves the box.</p></div>
      <div class="card"><div class="card-h">Agentic</div><p class="muted">Plans, then <code>read_file</code> / <code>write_file</code> / <code>edit_file</code> / <code>list_dir</code> / <code>run_command</code> in a loop until the task is done.</p></div>
      <div class="card"><div class="card-h">Zero dependencies</div><p class="muted">One self-contained binary (Node builtins only). Works on Linux &amp; Windows — no npm install, no runtime.</p></div>
    </div>

    <h2 class="pg-h2">Why Nexus over Claude Code or Glitch</h2>
    <p class="muted pg-sub">Nexus can drive Claude Code under the hood &mdash; so it&rsquo;s at least as capable &mdash; but it adds what the others don&rsquo;t: a free local fallback, a hybrid mode that slashes your Claude bill, offline use, and it ships as one dependency-free binary.</p>
    <div style="overflow-x:auto">
    <table class="cmp-table">
      <thead><tr><th></th><th>Nexus</th><th>Claude Code</th><th>Glitch</th></tr></thead>
      <tbody>
        <tr><td>Engines</td><td class="yes">Claude, local Ollama, or OpenCode</td><td>Claude only</td><td>Delegates to Claude/OpenCode</td></tr>
        <tr><td>Works offline / free option</td><td class="yes">Yes (local models)</td><td>No</td><td>No</td></tr>
        <tr><td>Hybrid cost-saver (local does the easy work, Claude the hard)</td><td class="yes">Yes</td><td>No</td><td>No</td></tr>
        <tr><td>Overnight autonomous runs (plan &middot; verify &middot; resume)</td><td class="yes">Yes</td><td>Limited</td><td>Yes (paid tiers)</td></tr>
        <tr><td>Full-screen TUI chat</td><td class="yes">Yes</td><td>Yes</td><td>Via Claude Code</td></tr>
        <tr><td>Security toolkit (recon, exploit, VM labs)</td><td class="yes">Yes (part of Sentinel)</td><td>No</td><td>No</td></tr>
        <tr><td>Single self-contained binary</td><td class="yes">Yes</td><td>Needs Node + npm</td><td>Needs Node + npm</td></tr>
        <tr><td>Price</td><td class="yes">Free &amp; open (MIT)</td><td>Subscription</td><td>Free + paid tiers</td></tr>
      </tbody>
    </table>
    </div>
    <p class="muted" style="font-size:.82rem">The killer feature: <code>sentinel nexus run "&hellip;" --engine hybrid</code> plans with Claude, does the routine work on your free local model, and only escalates the hard parts to Claude &mdash; often cutting Claude usage by well over half while keeping the quality where it matters.</p>

    <h2 class="pg-h2">Get it</h2>
    <p class="muted">Grab the Sentinel CLI (Terminal edition) and pull a model:</p>
    <pre class="code-block"><button class="cb-copy">copy</button><code># 1. install a local model (once)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5-coder     # or: hermes3

# 2. download the Sentinel CLI, then run the coder
sentinel nexus "add input validation to server.js and run the tests"</code></pre>
    <div class="btns" style="margin:12px 0;flex-wrap:wrap;gap:8px">
      <a class="btn" href="https://github.com/Darknode-Official/sentinel-web/releases/download/sentinel/Sentinel-cli-linux" download>CLI &middot; Linux</a>
      <a class="btn" href="https://github.com/Darknode-Official/sentinel-web/releases/download/sentinel/Sentinel-cli-windows.exe" download>CLI &middot; Windows</a>
      <button class="btn ghost" data-sec="downloads">All builds &amp; editions</button>
    </div>

    <h2 class="pg-h2">Use it</h2>
    <pre class="code-block"><button class="cb-copy">copy</button><code>sentinel init                                              # set up Nexus in this project (.nexus/)
sentinel nexus                                             # chat session with a boxed UI
sentinel nexus --tui                                       # full-screen UI (scrolling chat + fixed input box)
sentinel nexus "refactor utils.py into smaller functions"  # one-shot task
sentinel nexus --engine ollama                             # chat with a local model instead</code></pre>
    <p class="muted"><code>sentinel init</code> scaffolds <code>.nexus/NEXUS.md</code> (project instructions Nexus reads every session) and a config. The chat picks its engine automatically: Claude Code if installed, else local Ollama.</p>
    <p class="muted">Override the model per run with <code>SENTINEL_MODEL=hermes3 sentinel nexus "…"</code>, or point at a remote Ollama with <code>OLLAMA_HOST</code> / <code>OLLAMA_PORT</code>.</p>

    <h2 class="pg-h2">Autonomous runs (overnight)</h2>
    <p class="muted pg-sub">Give Nexus a big goal and it plans it into tasks, executes each one, verifies, and keeps going &mdash; checkpointing so it can run for hours and resume. Pick the engine: local <b>Ollama</b> (private, free), or delegate to <b>Claude Code</b> / <b>OpenCode</b> if you have them installed (far stronger, runs in the cloud).</p>
    <pre class="code-block"><button class="cb-copy">copy</button><code>sentinel nexus run "build a REST API with tests" --engine claude
sentinel nexus overnight "refactor the codebase and fix all failing tests" --until 07:00
sentinel nexus run --resume        # continue where it left off</code></pre>
    <p class="muted">Plan, progress and a final report live in <code>./.nexus/</code> (run.json, report.md, memory.md). Engines: <code>--engine claude</code> (default when installed) / <code>ollama</code> / <code>opencode</code>. Note: Claude/OpenCode run with full autonomy &mdash; use in a repo you trust.</p>

    <h2 class="pg-h2">Example session</h2>
    <pre class="code-block"><code>${esc(`▌ Nexus
  model hermes3   workdir ~/app

task> Create hello.py that prints "Hello from Nexus", then run it.
  • I'll write the file with write_file.
  write hello.py (1 lines)
  • Now run it to verify.
  $ python3 hello.py
    Hello from Nexus
  Done: created and verified hello.py prints the expected message.`)}</code></pre>

    <p class="muted" style="margin-top:18px">Prefer a GUI? The same agent — plus recon, exploitation, and VM-lab tools — lives in the <button class="linklike" data-sec="downloads">desktop app</button>'s Assistant.</p>`;

  main.querySelectorAll(".cb-copy").forEach((b) => b.addEventListener("click", () => {
    const code = b.parentElement.querySelector("code");
    navigator.clipboard?.writeText(code.textContent).then(() => { b.textContent = "copied"; setTimeout(() => (b.textContent = "copy"), 1000); });
  }));
  main.querySelectorAll("[data-sec]").forEach((b) => b.addEventListener("click", () => {
    const it = document.querySelector('.side-item[data-sec="' + b.dataset.sec + '"]'); if (it) it.click();
  }));
}
