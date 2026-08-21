// Documentation hub — product docs + the legal/policy pages "no one reads".
// Sticky table of contents on the left, anchored sections on the right.
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const UPDATED = "August 2026";

// Nexus command reference, grouped.
const CMD_GROUPS = [
  ["Engines & models", [
    ["/engine claude|ollama|opencode", "switch the AI engine (cloud Claude, free local Ollama, or OpenCode)"],
    ["/model [name]", "show or set the model"],
    ["/models", "list cloud tiers and installed local models"],
    ["/fallback <model>", "auto-retry on a cheaper model when the main one is rate-limited"],
    ["/cowork <strong> <weak>", "strong model codes; a cheaper/free local model does mechanical work"],
  ]],
  ["Save cost", [
    ["/cheap", "one-tap preset: lean output + low effort"],
    ["/lean", "ask the model for minimal output (cuts the expensive output tokens)"],
    ["/effort low|medium|high", "Claude thinking budget — lower is cheaper"],
    ["/estimate <prompt>", "rough token/cost estimate before you send"],
    ["/budget <usd>", "hard spend cap (also enforced mid-turn)"],
    ["/index", "index the repo so the local model auto-pulls only relevant files"],
    ["/impact", "session receipt: tokens & cost saved"],
  ]],
  ["Multi-engine", [
    ["/race <prompt>", "run the same prompt on every engine at once, keep the best"],
    ["/ensemble <prompt>", "every engine answers, then one synthesizes the best answer"],
    ["/review [engine]", "a different engine critiques the last answer"],
    ["/bench <prompt>", "speed / tokens / cost table per engine"],
  ]],
  ["Build & verify", [
    ["/plan <goal>", "generate an editable, runnable task checklist (/plan run)"],
    ["/watch <cmd>", "run a command; auto-fix the code and re-run until it passes"],
    ["/test <file>", "generate and run unit tests for a file"],
    ["/agents a ;; b ;; c", "run independent tasks in parallel (isolated git worktrees)"],
  ]],
  ["Git & safety", [
    ["/undo /redo /rewind N", "restore files from checkpoints taken before every turn"],
    ["/diff /git /blame /recent", "session diff, status, line authorship, recent files"],
    ["/commit", "AI commit message + commit"],
    ["/guard enforce|warn|off", "preflight destructive shell commands"],
    ["/secrets /scan <host>", "scan the repo for leaked credentials · quick port scan"],
    ["/redact /offline", "mask secrets before cloud sends · force local-only"],
  ]],
  ["Context & session", [
    ["@file · !cmd · #note", "inline a file · run a shell command · save a memory"],
    ["/pin <file> /tree", "keep a file in context · project file tree"],
    ["/compact /context", "shrink & inspect the context window"],
    ["/resume /export /copy", "reload a session · export to markdown · copy last reply"],
    ["/dream /gaps", "consolidate the session into memory · list TODO/FIXME"],
    ["/theme /keys /status /doctor", "color theme · shortcuts · session status · health check"],
  ]],
];

const TOC = [
  ["getting-started", "Getting started"],
  ["nexus", "Nexus command reference"],
  ["cost", "Cost-saving guide"],
  ["security", "Security & privacy"],
  ["faq", "FAQ"],
  ["terms", "Terms of Service"],
  ["privacy", "Privacy Policy"],
  ["aup", "Acceptable Use Policy"],
  ["license", "License"],
  ["changelog", "Changelog"],
];

const CHANGELOG = [
  ["2.29.x", "Nexus multi-engine agent: /cowork model tiering, /lean /effort /cheap /estimate, local RAG (/index), /race /ensemble /bench, /plan /watch /agents (worktree-isolated), /guard /secrets /scan /redact /offline, git checkpoints (/undo /redo /rewind), MCP + hooks, ~56 commands. NEXUS.md now reaches the Claude engine; plan mode is truly read-only."],
  ["2.28.x", "Desktop Assistant: structured-output autonomous loop, permissions toggle, attack playbooks, MCP client, vision input. CLI recon/exploit toolkit."],
  ["2.2x", "Web console, downloads, practice targets, vulnerable-VM runner, threat intel, private-cloud generator."],
];

const sec = (id, title, body) => `<section id="doc-${id}" class="doc-sec"><h2 class="pg-h2">${esc(title)}</h2>${body}</section>`;

export function renderDocs(main) {
  const cmdRef = CMD_GROUPS.map(([g, rows]) => `
    <h3 class="pg-h3">${esc(g)}</h3>
    <table class="doc-table"><tbody>${rows.map(([c, d]) => `<tr><td><code>${esc(c)}</code></td><td>${esc(d)}</td></tr>`).join("")}</tbody></table>`).join("");

  main.innerHTML = `
    <div class="doc-wrap">
      <aside class="doc-toc">
        <div class="doc-toc-h">Documentation</div>
        ${TOC.map(([id, t]) => `<a href="#doc-${id}" class="doc-toc-l" data-doc="${id}">${esc(t)}</a>`).join("")}
      </aside>
      <div class="doc-body">
        <h1 class="pg-h1">Sentinel documentation</h1>
        <p class="muted pg-sub">Everything for the Sentinel suite — the web console, the desktop app, the terminal edition (CLI), and <b>Nexus</b>, its AI coding agent. Last updated ${UPDATED}.</p>

        ${sec("getting-started", "Getting started", `
          <p class="muted">Sentinel ships in three editions that share one toolkit:</p>
          <div class="card-grid">
            <div class="card"><div class="card-h">Web console</div><p class="muted">Recon, payloads, threat intel and the AI assistant in your browser. Nothing to install.</p></div>
            <div class="card"><div class="card-h">Desktop app</div><p class="muted">The console plus a VM lab runner, native scanners, live terminals and the autonomous Assistant.</p></div>
            <div class="card"><div class="card-h">Terminal (CLI + Nexus)</div><p class="muted">A single dependency-free binary: the toolkit plus the Nexus coding agent. Runs anywhere.</p></div>
          </div>
          <pre class="code-block"><button class="cb-copy">copy</button><code># terminal edition
curl -L .../Sentinel-cli-linux -o sentinel &amp;&amp; chmod +x sentinel
./sentinel init          # scaffold .nexus/ project context
./sentinel nexus --tui   # launch the AI coding agent</code></pre>
          <p class="muted">The desktop app and CLI use only systems you own or are authorized to test. See the <button class="linklike" data-sec="dlguide">Download guide</button> for every install option.</p>`)}

        ${sec("nexus", "Nexus command reference", `
          <p class="muted">In the Nexus TUI, type <code>/</code> to open the command menu. The full set:</p>
          ${cmdRef}
          <p class="muted" style="font-size:.82rem">Prefixes: <code>@file</code> inlines a file, <code>!cmd</code> runs a shell command, <code>#note</code> saves a project memory. Keys: <code>Shift+Tab</code> cycles mode, <code>Ctrl+O</code> expands tool detail, <code>Ctrl+C</code> stops a turn.</p>`)}

        ${sec("cost", "Cost-saving guide", `
          <p class="muted">Nexus is built to cut token spend without hurting quality. In rough order of impact:</p>
          <ol class="doc-ol">
            <li><b>Use a free local worker.</b> <code>/cowork opus ollama:qwen2.5-coder</code> — the strong model codes; a free local model runs tests, builds and commit messages when the CLI estimates it saves more than the delegation overhead.</li>
            <li><b>Trim output.</b> <code>/lean</code> — output tokens cost several times more than input, so minimizing them is the biggest per-turn win.</li>
            <li><b>Lower thinking.</b> <code>/effort low</code> for mechanical work.</li>
            <li><b>Feed less context.</b> <code>/index</code> lets the local model auto-pull only the relevant files instead of you dumping whole directories.</li>
            <li><b>Cap spend.</b> <code>/budget 5</code> stops before a runaway bill — enforced both between and within turns.</li>
            <li><b>Preview.</b> <code>/estimate &lt;prompt&gt;</code> shows the rough cost first; <code>/impact</code> shows what you saved.</li>
          </ol>
          <p class="muted"><code>/cheap</code> turns on lean + low effort in one command.</p>`)}

        ${sec("security", "Security &amp; privacy", `
          <p class="muted">Sentinel is a security tool, so it defaults to safe:</p>
          <ul class="doc-ul">
            <li><b>Destructive-command preflight.</b> The local agent's shell commands are screened (<code>rm</code> on system paths, <code>git reset --hard</code>, <code>dd</code>, pipe-to-shell, fork bombs…) and blocked by default (<code>/guard</code>).</li>
            <li><b>Secret redaction.</b> <code>/redact</code> masks API keys, tokens and private keys <em>before</em> anything is sent to a cloud engine. <code>/offline</code> forces a local-only, nothing-leaves-the-box mode.</li>
            <li><b>Secret scanning.</b> Files the agent writes are scanned; <code>/secrets</code> audits the whole repo.</li>
            <li><b>Local first.</b> With the Ollama engine, your code and prompts never leave your machine.</li>
            <li><b>Reversible.</b> A git checkpoint is taken before every file-changing turn; <code>/undo</code> restores only what Nexus changed.</li>
          </ul>
          <p class="muted">Authorized use only: use the recon, exploitation and lab tools solely on systems you own or have explicit written permission to test.</p>`)}

        ${sec("faq", "FAQ", `
          <div class="doc-faq">
            <details><summary>Do I need an API key?</summary><p class="muted">No. The Claude engine drives your logged-in Claude Code CLI; the local engine talks to your own Ollama. Nexus stores no keys.</p></details>
            <details><summary>Does my code leave my machine?</summary><p class="muted">Only if you use a cloud engine (Claude/OpenCode). The Ollama engine is fully local. <code>/redact</code> masks secrets before any cloud send; <code>/offline</code> blocks cloud entirely.</p></details>
            <details><summary>How is Nexus different from Claude Code?</summary><p class="muted">Multiple engines (cloud + free local), a real cost-saving toolkit, git-native checkpoints, a built-in security preflight, and ~56 commands — see the <button class="linklike" data-sec="coder">Nexus page</button>.</p></details>
            <details><summary>Is it free?</summary><p class="muted">The software is free to use. Cloud model usage is billed by your provider; the local engine is free.</p></details>
            <details><summary>Where is my project data stored?</summary><p class="muted">In <code>.nexus/</code> in your project (session, plan, index, memory) — gitignored automatically. Web-console account data is described in the Privacy Policy below.</p></details>
          </div>`)}

        ${sec("terms", "Terms of Service", `
          <p class="muted doc-legal">These terms govern your use of the Sentinel suite (the "Software" and "Services"). By using them you agree to them.</p>
          <ol class="doc-ol doc-legal">
            <li><b>License to use.</b> The Software is provided as-is; all rights are reserved by the author.</li>
            <li><b>Authorized use only.</b> You will use the security tooling exclusively against systems you own or are explicitly authorized in writing to test. You are solely responsible for compliance with all applicable laws.</li>
            <li><b>No warranty.</b> The Software and Services are provided "as is", without warranty of any kind. Automated agents can make mistakes; review their changes.</li>
            <li><b>Limitation of liability.</b> To the maximum extent permitted by law, the authors are not liable for any damages arising from use of the Software or Services, including data loss, downtime or misuse.</li>
            <li><b>Third-party services.</b> Cloud AI providers, model usage and billing are governed by those providers' own terms.</li>
            <li><b>Changes.</b> These terms may be updated; continued use constitutes acceptance.</li>
          </ol>`)}

        ${sec("privacy", "Privacy Policy", `
          <p class="muted doc-legal">We collect the minimum needed to run the Services.</p>
          <ul class="doc-ul doc-legal">
            <li><b>Local edition.</b> The CLI and desktop app run on your machine. Project state lives in <code>.nexus/</code>. We do not collect your code or prompts. Cloud engines send your prompt to the provider you chose (masked when <code>/redact</code> is on).</li>
            <li><b>Web console.</b> If you sign in, we store your account identifier and preferences to provide the service. We do not sell personal data.</li>
            <li><b>Feedback.</b> Feedback you submit is stored to improve the product and is readable only by you and the maintainers.</li>
            <li><b>Retention & deletion.</b> You may request deletion of your account data at any time via Settings or by contacting the maintainers.</li>
            <li><b>Cookies.</b> Only functional cookies/localStorage for auth and preferences.</li>
          </ul>`)}

        ${sec("aup", "Acceptable Use Policy", `
          <p class="muted doc-legal">You agree <b>not</b> to use Sentinel to:</p>
          <ul class="doc-ul doc-legal">
            <li>Access, scan, exploit or disrupt systems you do not own or lack written authorization to test.</li>
            <li>Develop or distribute malware for malicious use, conduct denial-of-service attacks, or target individuals.</li>
            <li>Exfiltrate data, evade detection for unlawful purposes, or violate any law or third-party rights.</li>
          </ul>
          <p class="muted doc-legal">Sentinel is intended for authorized penetration testing, CTFs, security research and defense. Misuse is your responsibility.</p>`)}

        ${sec("license", "License", `
          <p class="muted doc-legal">The Sentinel suite is proprietary &mdash; all rights reserved by the author. No license to use, copy, modify, or distribute is granted. The software is provided "as is", without warranty of any kind.</p>`)}

        ${sec("changelog", "Changelog", `
          <div class="doc-changelog">${CHANGELOG.map(([v, d]) => `<div class="doc-cl"><span class="doc-cl-v">${esc(v)}</span><p class="muted">${esc(d)}</p></div>`).join("")}</div>
          <p class="muted" style="font-size:.8rem">Use only on systems you are authorized to test.</p>`)}
      </div>
    </div>`;

  // copy buttons + in-app navigation + smooth scroll
  main.querySelectorAll(".cb-copy").forEach((b) => b.addEventListener("click", () => {
    const code = b.parentElement.querySelector("code");
    navigator.clipboard?.writeText(code.textContent).then(() => { b.textContent = "copied"; setTimeout(() => (b.textContent = "copy"), 1000); });
  }));
  main.querySelectorAll("[data-sec]").forEach((b) => b.addEventListener("click", () => { const it = document.querySelector('.side-item[data-sec="' + b.dataset.sec + '"]'); if (it) it.click(); }));
  main.querySelectorAll("[data-doc]").forEach((a) => a.addEventListener("click", (e) => { e.preventDefault(); const t = document.getElementById("doc-" + a.dataset.doc); if (t) t.scrollIntoView({ behavior: "smooth", block: "start" }); }));
}
