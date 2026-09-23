import { esc } from '/js/shared.js';

const UPDATED = "September 2026";

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

const CHANGELOG = [
  ["2.29.x", "Nexus multi-engine agent: /cowork model tiering, /lean /effort /cheap /estimate, local RAG (/index), /race /ensemble /bench, /plan /watch /agents (worktree-isolated), /guard /secrets /scan /redact /offline, git checkpoints (/undo /redo /rewind), MCP + hooks, ~56 commands. NEXUS.md now reaches the Claude engine; plan mode is truly read-only."],
  ["2.28.x", "Desktop Assistant: structured-output autonomous loop, permissions toggle, attack playbooks, MCP client, vision input. CLI recon/exploit toolkit."],
  ["2.2x", "Web console, downloads, practice targets, vulnerable-VM runner, threat intel, private-cloud generator."],
];

const TABS = [
  { id: "getting-started", label: "Getting Started" },
  { id: "nexus", label: "Nexus Commands" },
  { id: "cost", label: "Cost Saving" },
  { id: "security", label: "Security" },
  { id: "faq", label: "FAQ" },
  { id: "terms", label: "Terms" },
  { id: "privacy", label: "Privacy" },
  { id: "aup", label: "Acceptable Use" },
  { id: "license", label: "License" },
  { id: "changelog", label: "Changelog" },
];

function renderSection(id) {
  const cmdRef = CMD_GROUPS.map(([g, rows]) =>
    '<h3 style="font-size:1rem;font-weight:700;margin:24px 0 10px;color:var(--txt,#e2e8f0)">' + esc(g) + '</h3>' +
    '<table class="dc-table"><tbody>' + rows.map(([c, d]) =>
      '<tr><td><code class="dc-code">' + esc(c) + '</code></td><td style="color:var(--mut,#94a3b8)">' + esc(d) + '</td></tr>'
    ).join("") + '</tbody></table>'
  ).join("");

  switch (id) {
    case 'getting-started': return `
      <p style="color:var(--mut,#94a3b8);margin-bottom:20px">Darknode ships in three editions that share one toolkit:</p>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px;margin-bottom:24px">
        <div class="dc-card"><div style="font-weight:700;margin-bottom:6px;color:var(--txt,#e2e8f0)">Web console</div><p style="color:var(--mut,#94a3b8);font-size:.9rem;margin:0">Recon, payloads, threat intel and the AI assistant in your browser. Nothing to install.</p></div>
        <div class="dc-card"><div style="font-weight:700;margin-bottom:6px;color:var(--txt,#e2e8f0)">Desktop app</div><p style="color:var(--mut,#94a3b8);font-size:.9rem;margin:0">The console plus a VM lab runner, native scanners, live terminals and the autonomous Assistant.</p></div>
        <div class="dc-card"><div style="font-weight:700;margin-bottom:6px;color:var(--txt,#e2e8f0)">Terminal (CLI + Nexus)</div><p style="color:var(--mut,#94a3b8);font-size:.9rem;margin:0">A single dependency-free binary: the toolkit plus the Nexus coding agent. Runs anywhere.</p></div>
      </div>
      <pre class="dc-pre"><code># terminal edition
curl -L .../Darknode-cli-linux -o darknode &amp;&amp; chmod +x darknode
./darknode init          # scaffold .nexus/ project context
./darknode nexus --tui   # launch the AI coding agent</code></pre>
      <p style="color:var(--mut,#94a3b8);margin-top:16px">The desktop app and CLI use only systems you own or are authorized to test.</p>`;

    case 'nexus': return `
      <p style="color:var(--mut,#94a3b8);margin-bottom:16px">In the Nexus TUI, type <code class="dc-code">/</code> to open the command menu. The full set:</p>
      ${cmdRef}
      <p style="color:var(--mut,#94a3b8);font-size:.85rem;margin-top:20px">Prefixes: <code class="dc-code">@file</code> inlines a file, <code class="dc-code">!cmd</code> runs a shell command, <code class="dc-code">#note</code> saves a project memory. Keys: <code class="dc-code">Shift+Tab</code> cycles mode, <code class="dc-code">Ctrl+O</code> expands tool detail, <code class="dc-code">Ctrl+C</code> stops a turn.</p>`;

    case 'cost': return `
      <p style="color:var(--mut,#94a3b8);margin-bottom:16px">Nexus is built to cut token spend without hurting quality. In rough order of impact:</p>
      <ol class="dc-ol">
        <li><strong>Use a free local worker.</strong> <code class="dc-code">/cowork opus ollama:qwen2.5-coder</code> — the strong model codes; a free local model runs tests, builds and commit messages.</li>
        <li><strong>Trim output.</strong> <code class="dc-code">/lean</code> — output tokens cost several times more than input, so minimizing them is the biggest per-turn win.</li>
        <li><strong>Lower thinking.</strong> <code class="dc-code">/effort low</code> for mechanical work.</li>
        <li><strong>Feed less context.</strong> <code class="dc-code">/index</code> lets the local model auto-pull only the relevant files.</li>
        <li><strong>Cap spend.</strong> <code class="dc-code">/budget 5</code> stops before a runaway bill — enforced both between and within turns.</li>
        <li><strong>Preview.</strong> <code class="dc-code">/estimate &lt;prompt&gt;</code> shows the rough cost first; <code class="dc-code">/impact</code> shows what you saved.</li>
      </ol>
      <p style="color:var(--mut,#94a3b8);margin-top:16px"><code class="dc-code">/cheap</code> turns on lean + low effort in one command.</p>`;

    case 'security': return `
      <p style="color:var(--mut,#94a3b8);margin-bottom:16px">Darknode is a security tool, so it defaults to safe:</p>
      <ul class="dc-ul">
        <li><strong>Destructive-command preflight.</strong> Shell commands are screened and blocked by default (<code class="dc-code">/guard</code>).</li>
        <li><strong>Secret redaction.</strong> <code class="dc-code">/redact</code> masks API keys and tokens <em>before</em> anything is sent to a cloud engine. <code class="dc-code">/offline</code> forces local-only mode.</li>
        <li><strong>Secret scanning.</strong> Files the agent writes are scanned; <code class="dc-code">/secrets</code> audits the whole repo.</li>
        <li><strong>Local first.</strong> With the Ollama engine, your code and prompts never leave your machine.</li>
        <li><strong>Reversible.</strong> A git checkpoint is taken before every file-changing turn; <code class="dc-code">/undo</code> restores only what Nexus changed.</li>
      </ul>
      <p style="color:var(--mut,#94a3b8);margin-top:16px">Authorized use only: use the recon, exploitation and lab tools solely on systems you own or have explicit written permission to test.</p>`;

    case 'faq': return `
      <div style="display:flex;flex-direction:column;gap:12px">
        <details class="dc-details"><summary>Do I need an API key?</summary><p style="color:var(--mut,#94a3b8);padding:12px 16px 0;margin:0">No. The Claude engine drives your logged-in Claude Code CLI; the local engine talks to your own Ollama. Nexus stores no keys.</p></details>
        <details class="dc-details"><summary>Does my code leave my machine?</summary><p style="color:var(--mut,#94a3b8);padding:12px 16px 0;margin:0">Only if you use a cloud engine (Claude/OpenCode). The Ollama engine is fully local. <code class="dc-code">/redact</code> masks secrets before any cloud send; <code class="dc-code">/offline</code> blocks cloud entirely.</p></details>
        <details class="dc-details"><summary>How is Nexus different from Claude Code?</summary><p style="color:var(--mut,#94a3b8);padding:12px 16px 0;margin:0">Multiple engines (cloud + free local), a real cost-saving toolkit, git-native checkpoints, a built-in security preflight, and ~56 commands.</p></details>
        <details class="dc-details"><summary>Is it free?</summary><p style="color:var(--mut,#94a3b8);padding:12px 16px 0;margin:0">The software is free to use. Cloud model usage is billed by your provider; the local engine is free.</p></details>
        <details class="dc-details"><summary>Where is my project data stored?</summary><p style="color:var(--mut,#94a3b8);padding:12px 16px 0;margin:0">In <code class="dc-code">.nexus/</code> in your project (session, plan, index, memory) — gitignored automatically. Web-console account data is described in the Privacy Policy.</p></details>
      </div>`;

    case 'terms': return `
      <p style="color:var(--mut,#94a3b8);margin-bottom:16px;font-size:.9rem">These terms govern your use of the Darknode suite (the "Software" and "Services"). By using them you agree to them.</p>
      <ol class="dc-ol" style="font-size:.9rem">
        <li><strong>License to use.</strong> The Software is provided as-is; all rights are reserved by the author.</li>
        <li><strong>Authorized use only.</strong> You will use the security tooling exclusively against systems you own or are explicitly authorized in writing to test. You are solely responsible for compliance with all applicable laws.</li>
        <li><strong>No warranty.</strong> The Software and Services are provided "as is", without warranty of any kind. Automated agents can make mistakes; review their changes.</li>
        <li><strong>Limitation of liability.</strong> To the maximum extent permitted by law, the authors are not liable for any damages arising from use of the Software or Services.</li>
        <li><strong>Third-party services.</strong> Cloud AI providers, model usage and billing are governed by those providers' own terms.</li>
        <li><strong>Changes.</strong> These terms may be updated; continued use constitutes acceptance.</li>
      </ol>`;

    case 'privacy': return `
      <p style="color:var(--mut,#94a3b8);margin-bottom:16px;font-size:.9rem">We collect the minimum needed to run the Services.</p>
      <ul class="dc-ul" style="font-size:.9rem">
        <li><strong>Local edition.</strong> The CLI and desktop app run on your machine. Project state lives in <code class="dc-code">.nexus/</code>. We do not collect your code or prompts.</li>
        <li><strong>Web console.</strong> If you sign in, we store your account identifier and preferences to provide the service. We do not sell personal data.</li>
        <li><strong>Feedback.</strong> Feedback you submit is stored to improve the product and is readable only by you and the maintainers.</li>
        <li><strong>Retention &amp; deletion.</strong> You may request deletion of your account data at any time via Settings or by contacting the maintainers.</li>
        <li><strong>Cookies.</strong> Only functional cookies/localStorage for auth and preferences.</li>
      </ul>`;

    case 'aup': return `
      <p style="color:var(--mut,#94a3b8);margin-bottom:16px;font-size:.9rem">You agree <strong>not</strong> to use Darknode to:</p>
      <ul class="dc-ul" style="font-size:.9rem">
        <li>Access, scan, exploit or disrupt systems you do not own or lack written authorization to test.</li>
        <li>Develop or distribute malware for malicious use, conduct denial-of-service attacks, or target individuals.</li>
        <li>Exfiltrate data, evade detection for unlawful purposes, or violate any law or third-party rights.</li>
      </ul>
      <p style="color:var(--mut,#94a3b8);margin-top:16px;font-size:.9rem">Darknode is intended for authorized penetration testing, CTFs, security research and defense. Misuse is your responsibility.</p>`;

    case 'license': return `
      <p style="color:var(--mut,#94a3b8);font-size:.9rem">The Darknode suite is proprietary — all rights reserved by the author. No license to use, copy, modify, or distribute is granted. The software is provided "as is", without warranty of any kind.</p>`;

    case 'changelog': return `
      <div style="display:flex;flex-direction:column;gap:14px">
        ${CHANGELOG.map(([v, d]) => '<div class="dc-card" style="padding:16px"><span style="display:inline-block;background:var(--acc,#00aaff);color:#fff;padding:2px 10px;border-radius:4px;font-size:.8rem;font-weight:700;margin-bottom:8px">' + esc(v) + '</span><p style="color:var(--mut,#94a3b8);margin:0;font-size:.9rem;line-height:1.6">' + esc(d) + '</p></div>').join("")}
      </div>
      <p style="color:var(--mut,#64748b);font-size:.8rem;margin-top:16px">Use only on systems you are authorized to test.</p>`;

    default: return '<p style="color:var(--mut,#94a3b8)">Section not found.</p>';
  }
}

var _dcCurrentTab = 'getting-started';

function _dcSwitchTab(id, container) {
  _dcCurrentTab = id;
  container.querySelectorAll('.dc-tab').forEach(function(t) {
    t.classList.toggle('active', t.dataset.tab === id);
  });
  var breadcrumb = container.querySelector('.dc-breadcrumb-current');
  if (breadcrumb) {
    var tab = TABS.find(function(t) { return t.id === id; });
    breadcrumb.textContent = tab ? tab.label : id;
  }
  var body = container.querySelector('.dc-body');
  if (body) {
    body.innerHTML = renderSection(id);
    body.querySelectorAll('.dc-details').forEach(function(d) {
      d.querySelector('summary').addEventListener('click', function(e) {
        e.preventDefault();
        d.toggleAttribute('open');
      });
    });
  }
}

export function renderDocs(main) {
  _dcCurrentTab = 'getting-started';

  var style = document.createElement('style');
  style.textContent =
    '.dc-wrap{max-width:960px;margin:0 auto;padding:40px 32px 60px}' +
    '.dc-header{display:flex;align-items:center;gap:16px;margin-bottom:8px}' +
    '.dc-back{display:inline-flex;align-items:center;gap:6px;background:var(--card,#141c28);color:var(--acc,#00aaff);border:1px solid var(--line,#1a2a44);border-radius:4px;padding:8px 16px;cursor:pointer;font-size:.85rem;font-weight:600;font-family:inherit;transition:all .15s}' +
    '.dc-back:hover{background:var(--acc,#00aaff);color:#fff;border-color:var(--acc,#00aaff)}' +
    '.dc-breadcrumb{display:flex;align-items:center;gap:6px;color:var(--mut,#64748b);font-size:.82rem;margin-bottom:24px}' +
    '.dc-breadcrumb a{color:var(--acc,#00aaff);text-decoration:none;cursor:pointer}' +
    '.dc-breadcrumb a:hover{text-decoration:underline}' +
    '.dc-breadcrumb span{color:var(--mut,#64748b)}' +
    '.dc-title{font-size:1.8rem;font-weight:800;color:var(--txt,#e2e8f0);margin:0;letter-spacing:-.02em}' +
    '.dc-sub{color:var(--mut,#94a3b8);font-size:.9rem;margin:4px 0 0}' +
    '.dc-tabs{display:flex;flex-wrap:wrap;gap:4px;margin-bottom:28px;border-bottom:1px solid var(--line,#1a2a44);padding-bottom:0}' +
    '.dc-tab{padding:10px 16px;background:transparent;border:none;border-bottom:2px solid transparent;color:var(--mut,#64748b);cursor:pointer;font-size:.82rem;font-weight:600;font-family:inherit;white-space:nowrap;transition:all .15s}' +
    '.dc-tab:hover{color:var(--txt,#e2e8f0);background:var(--card,#141c2808)}' +
    '.dc-tab.active{color:var(--acc,#00aaff);border-bottom-color:var(--acc,#00aaff)}' +
    '.dc-body{animation:dcFadeIn .2s ease}' +
    '@keyframes dcFadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}' +
    '.dc-card{background:var(--card,#141c28);border:1px solid var(--line,#1a2a44);border-radius:8px;padding:20px}' +
    '.dc-table{width:100%;border-collapse:collapse;margin-bottom:12px}' +
    '.dc-table td{padding:8px 12px;border-bottom:1px solid var(--line,#1a2a4433);font-size:.88rem;vertical-align:top}' +
    '.dc-table td:first-child{white-space:nowrap;width:1%}' +
    '.dc-code{background:var(--card,#141c28);padding:2px 6px;border-radius:3px;font-family:monospace;font-size:.82rem;color:var(--acc,#00aaff)}' +
    '.dc-pre{background:var(--card,#0d1117);border:1px solid var(--line,#1a2a44);border-radius:8px;padding:16px 20px;overflow-x:auto;font-size:.82rem;line-height:1.6;color:var(--txt,#e2e8f0);margin:0 0 16px}' +
    '.dc-ol,.dc-ul{color:var(--mut,#94a3b8);line-height:1.7;padding-left:24px}' +
    '.dc-ol li,.dc-ul li{margin-bottom:10px}' +
    '.dc-ol li strong,.dc-ul li strong{color:var(--txt,#e2e8f0)}' +
    '.dc-details{background:var(--card,#141c28);border:1px solid var(--line,#1a2a44);border-radius:8px;overflow:hidden}' +
    '.dc-details summary{padding:12px 16px;cursor:pointer;font-weight:600;color:var(--txt,#e2e8f0);font-size:.92rem;list-style:none}' +
    '.dc-details summary::-webkit-details-marker{display:none}' +
    '.dc-details summary::before{content:"\\25B6";display:inline-block;margin-right:10px;font-size:.7em;transition:transform .15s;color:var(--acc,#00aaff)}' +
    '.dc-details[open] summary::before{transform:rotate(90deg)}' +
    '.dc-details[open]{border-color:var(--acc,#00aaff33)}' +
    '@media(max-width:768px){.dc-wrap{padding:20px 16px 40px}.dc-title{font-size:1.3rem}.dc-tabs{gap:2px}.dc-tab{padding:8px 10px;font-size:.75rem}}';
  main.innerHTML = '';
  main.appendChild(style);

  var wrap = document.createElement('div');
  wrap.className = 'dc-wrap';
  wrap.innerHTML =
    '<div class="dc-header">' +
      '<button class="dc-back" id="dc-back-btn">&#8592; Dashboard</button>' +
    '</div>' +
    '<div class="dc-breadcrumb">' +
      '<a data-sec="home">Dashboard</a>' +
      '<span>/</span>' +
      '<span style="color:var(--txt,#e2e8f0)">Docs</span>' +
      '<span>/</span>' +
      '<span class="dc-breadcrumb-current" style="color:var(--txt,#e2e8f0)">Getting Started</span>' +
    '</div>' +
    '<h1 class="dc-title">Darknode Documentation</h1>' +
    '<p class="dc-sub">Everything for the Darknode suite — the web console, the desktop app, the terminal edition (CLI), and <strong>Nexus</strong>, its AI coding agent. Last updated ' + UPDATED + '.</p>' +
    '<div style="height:24px"></div>' +
    '<nav class="dc-tabs">' +
      TABS.map(function(t) {
        return '<button class="dc-tab' + (t.id === _dcCurrentTab ? ' active' : '') + '" data-tab="' + t.id + '">' + esc(t.label) + '</button>';
      }).join('') +
    '</nav>' +
    '<div class="dc-body"></div>';
  main.appendChild(wrap);

  var body = wrap.querySelector('.dc-body');
  body.innerHTML = renderSection(_dcCurrentTab);

  wrap.querySelector('.dc-tabs').addEventListener('click', function(e) {
    var tab = e.target.closest('.dc-tab');
    if (!tab) return;
    _dcSwitchTab(tab.dataset.tab, wrap);
  });

  wrap.querySelector('#dc-back-btn').addEventListener('click', function() {
    var homeBtn = document.querySelector('.side-item[data-sec="home"]');
    if (homeBtn) homeBtn.click();
  });

  wrap.querySelectorAll('[data-sec]').forEach(function(a) {
    a.addEventListener('click', function() {
      var btn = document.querySelector('.side-item[data-sec="' + a.dataset.sec + '"]');
      if (btn) btn.click();
    });
  });
}
