// CLI AI coder — showcase/docs page for `sentinel code`, the terminal AI coding agent
// built into the Sentinel CLI. Private & local (talks to the user's own Ollama).
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

export function renderCliCoder(main) {
  main.innerHTML = `
    <h1 class="pg-h1">CLI AI coder <span class="pill">sentinel code</span></h1>
    <p class="muted pg-sub">A terminal AI coding agent built into the Sentinel CLI — like Glitch/Claude&nbsp;Code, but a single dependency-free binary that runs on <b>your</b> machine against <b>your</b> local models. It reads &amp; writes files and runs commands to finish a task, then verifies its own work.</p>

    <div class="card-grid">
      <div class="card"><div class="card-h">🔒 Private &amp; local</div><p class="muted">Talks only to your local Ollama (<code>127.0.0.1:11434</code>). No cloud, no API keys — your code never leaves the box.</p></div>
      <div class="card"><div class="card-h">🛠️ Agentic</div><p class="muted">Plans, then <code>read_file</code> / <code>write_file</code> / <code>edit_file</code> / <code>list_dir</code> / <code>run_command</code> in a loop until the task is done.</p></div>
      <div class="card"><div class="card-h">📦 Zero deps</div><p class="muted">One self-contained binary (Node builtins only). Works on Linux &amp; Windows — no npm install, no runtime.</p></div>
    </div>

    <h2 class="pg-h2">Get it</h2>
    <p class="muted">Grab the Sentinel CLI (Terminal edition) and pull a model:</p>
    <pre class="code-block"><button class="cb-copy">copy</button><code># 1. install a local model (once)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5-coder     # or: hermes3

# 2. download the Sentinel CLI, then run the coder
sentinel code "add input validation to server.js and run the tests"</code></pre>
    <div class="btns" style="margin:12px 0"><button class="btn" data-sec="downloads">Download the CLI</button></div>

    <h2 class="pg-h2">Use it</h2>
    <pre class="code-block"><button class="cb-copy">copy</button><code>sentinel code "refactor utils.py into smaller functions"   # one-shot task
sentinel code                                             # interactive REPL
sentinel                                                  # menu → [a] AI coder</code></pre>
    <p class="muted">Override the model per run with <code>SENTINEL_MODEL=hermes3 sentinel code "…"</code>, or point at a remote Ollama with <code>OLLAMA_HOST</code> / <code>OLLAMA_PORT</code>.</p>

    <h2 class="pg-h2">Example session</h2>
    <pre class="code-block"><code>${esc(`▌ AI coder
  model hermes3   workdir ~/app

task> Create hello.py that prints "Hello from Sentinel Coder", then run it.
  • I'll write the file with write_file.
  write hello.py (1 lines)
  • Now run it to verify.
  $ python3 hello.py
    Hello from Sentinel Coder
  ✓ Created and verified hello.py prints the expected message.`)}</code></pre>

    <p class="muted" style="margin-top:18px">Prefer a GUI? The same agent — plus recon, exploitation, and VM-lab tools — lives in the <button class="linklike" data-sec="downloads">desktop app</button>'s Assistant.</p>`;

  main.querySelectorAll(".cb-copy").forEach((b) => b.addEventListener("click", () => {
    const code = b.parentElement.querySelector("code");
    navigator.clipboard?.writeText(code.textContent).then(() => { b.textContent = "copied"; setTimeout(() => (b.textContent = "copy"), 1000); });
  }));
}
