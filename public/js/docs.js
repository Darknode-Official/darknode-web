import { esc } from '/js/shared.js';

const UPDATED = "November 2026";

// Highlights only; the full list comes from /data/nexus-commands.json
// (scripts/sync-nexus-commands.mjs, generated from darknode-cli's command tables).
const STANDOUT = [
  ["See and cut cost", [
    ["/cheap", "turns on every saver that cannot lower answer quality, then shows what each one did (/cheap status)"],
    ["/warm", "prompt-cache countdown and what your next message costs warm vs cold"],
    ["/turns", "per-turn cost ledger at exact list prices"],
    ["/savings", "what you saved across sessions, with a 30-day projection"],
  ]],
  ["Use several engines together", [
    ["/race", "the same prompt on every engine at once"],
    ["/ensemble", "every engine answers, then one combines the best answer"],
    ["/review", "a different engine gives a second opinion on the last answer"],
    ["/cowork", "a strong model writes the code, a cheaper or local one does the routine work"],
  ]],
  ["Stay safe and reversible", [
    ["/guard", "checks destructive shell commands before they run"],
    ["/redact · /offline", "mask secrets before a cloud send, or lock to local engines only"],
    ["/undo · /rewind", "git checkpoints before every turn that changes files"],
    ["/bisect", "finds the turn that broke your tests"],
  ]],
  ["Work faster", [
    ["/codereview", "parallel reviewers, each finding checked by a verifier, ranked by severity"],
    ["/btw", "a side question answered from context, never added to the chat"],
    ["/find", "search the whole conversation, tool output included"],
    ["nexus bg · nexus attach", "run sessions in the background and take one over later"],
  ]],
];

const CHANGELOG = [
  ["3.3.x", "Live integrations: Deck security integrations are connected only after a live key test, through a relay to fixed provider endpoints (VirusTotal, Shodan, AbuseIPDB, GreyNoise, OTX, urlscan, SecurityTrails, ipinfo, Have I Been Pwned, Hunter, Pulsedive, Hybrid Analysis, plus keyless NVD and CIRCL CVE). The Deck Assistant can run lookups on connected integrations, asking first each time unless you choose Always allow. Text boxes no longer refill from saved lists on reload; a Load saved list button brings them back on request. A full bug sweep fixed about 90 issues across the Deck, the business tools, the flagship tools and all 780 quick utilities, among them wrong file hashes for binary files, a strict CSP graded as broken, missed SQL injection and display-name spoofing, the ASN Explorer (moved from the retired BGPView to RIPEstat), and spreadsheet formula injection in CSV exports. Nexus background sessions (nexus bg / attach / sessions); signed-in Nexus and desktop app report version, OS and VM counts every 6 hours (/shareusage off, or Settings > Share app usage). Docs: the Nexus Commands tab lists every Nexus command, and Cost Saving shows /cheap before-and-after costs on each Claude model, measured on real sessions."],
  ["3.2.x", "Business security platform: the Darknode Deck with native Personal and Organization spaces (domain posture grading, certificate watch, link and email phishing checks, code-secret scanning, sensitive-data checks with redaction, domain portfolios and fleet views), a Web toolkit tab linking the hands-on web-security tools, plan-based tool availability, team workspaces, and removal of the off-topic financial tools."],
  ["3.1.x", "Web console line: flagship platforms (PHANTOM packet/network ops, CITADEL SOC console, ORACLE threat-intel engine, SPECTRE cloud posture, CRUCIBLE defensive wargaming, NAVARCH maritime defense), a platform-wide Security Graph that cross-links findings, the Sentinel Eye 3D threat globe, 125 security tools plus 780 quick utilities, the Professional theme, the Darknode assistant (Help button in the top bar), and Nexus AI integration."],
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
  const H3 = '<h3 style="font-size:1rem;font-weight:700;margin:24px 0 10px;color:var(--txt,#e2e8f0)">';
  const cmdRows = (rows) => '<table class="dc-table"><tbody>' + rows.map(([c, d]) =>
    '<tr><td><code class="dc-code">' + esc(c) + '</code></td><td style="color:var(--mut,#94a3b8)">' + esc(d) + '</td></tr>').join("") + '</tbody></table>';
  const standout = '<div class="dc-grid2">' + STANDOUT.map(([g, rows]) =>
    '<div class="dc-card"><div style="font-weight:700;margin-bottom:8px;color:var(--txt,#e2e8f0)">' + esc(g) + '</div>' + cmdRows(rows) + '</div>').join("") + '</div>';

  switch (id) {
    case 'getting-started': return `
      <p style="color:var(--mut,#94a3b8);margin-bottom:20px">Darknode ships in three editions that share one toolkit:</p>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px;margin-bottom:24px">
        <div class="dc-card"><div style="font-weight:700;margin-bottom:6px;color:var(--txt,#e2e8f0)">Web platform</div><p style="color:var(--mut,#94a3b8);font-size:.9rem;margin:0">Scan code, cloud, dependencies and web exposure, triage findings and build reports in your browser. Nothing to install.</p></div>
        <div class="dc-card"><div style="font-weight:700;margin-bottom:6px;color:var(--txt,#e2e8f0)">Desktop app</div><p style="color:var(--mut,#94a3b8);font-size:.9rem;margin:0">The Deck plus a VM lab runner, native scanners, live terminals and the autonomous Assistant.</p></div>
        <div class="dc-card"><div style="font-weight:700;margin-bottom:6px;color:var(--txt,#e2e8f0)">Terminal (CLI + Nexus)</div><p style="color:var(--mut,#94a3b8);font-size:.9rem;margin:0">A single dependency-free binary: the toolkit plus the Nexus coding agent. Runs anywhere.</p></div>
      </div>
      <!-- NPM_SUSPENDED: revert this block to "npm i -g darknode-cli / nexus / nexus init" when the npm account is restored -->
      <pre class="dc-pre"><code># terminal edition — runs anywhere Node 18+ is installed
git clone https://github.com/Darknode-Official/darknode-cli
cd darknode-cli &amp;&amp; node darknode.js nexus   # launch the AI coding agent
node darknode.js nexus init                 # optional: scaffold .nexus/ project context</code></pre>
      <p style="color:var(--mut,#94a3b8);margin-top:16px">The desktop app and CLI use only systems you own or are authorized to test.</p>`;

    case 'nexus': return `
      <p style="color:var(--mut,#94a3b8);margin-bottom:16px">Nexus is a terminal coding agent that drives six engines (Claude Code, Gemini, Codex, OpenCode, Aider and local Ollama) behind one set of commands, with the same cost tracking, checkpoints and safety checks on each. These are the commands most worth knowing:</p>
      ${standout}
      ${H3}Every command</h3>
      <div data-nx="cmds"><p style="color:var(--mut,#94a3b8)">Loading the command list...</p></div>
      <p style="color:var(--mut,#94a3b8);font-size:.85rem;margin-top:20px">Prefixes: <code class="dc-code">@file</code> attaches a file, <code class="dc-code">!cmd</code> runs a shell command, <code class="dc-code">#note</code> saves a project memory. Keys: <code class="dc-code">Shift+Tab</code> cycles mode, <code class="dc-code">Ctrl+O</code> expands tool detail, <code class="dc-code">Esc</code> stops a turn. Inside Nexus, <code class="dc-code">/docs</code> searches all of this.</p>`;

    case 'cost': return `
      <p style="color:var(--mut,#94a3b8);margin-bottom:16px"><code class="dc-code">/cheap</code> turns on only the savers that cannot lower answer quality. You get the same model, the same effort and the same answers, for fewer billed tokens. Turn it off with <code class="dc-code">/cheap off</code> and your earlier settings come back.</p>
      <ul class="dc-ul">
        <li><strong>Keeps the prompt cache warm through breaks.</strong> On a one-hour cache, coming back after an hour normally rewrites your whole context at the cache-write price. Nexus sends a one-line ping shortly before expiry (contexts of 20k+ tokens, up to 6 hours after your last message), so the next message reads the cache instead.</li>
        <li><strong>Lists unused skills by name only.</strong> Skill descriptions you have not used in this project stop riding along in every request.</li>
        <li><strong>Shares the cached prefix across folders.</strong> Per-machine details move out of the system prompt, so sessions in different folders can reuse the same cache.</li>
        <li><strong>Surgical edits.</strong> Edits change only what differs instead of rewriting whole blocks (<code class="dc-code">/tight</code>).</li>
      </ul>
      ${H3}Before and after /cheap, by model</h3>
      <div data-nx="cheap"><p style="color:var(--mut,#94a3b8)">Loading the measurement...</p></div>
      ${H3}Other ways to spend less</h3>
      <p style="color:var(--mut,#94a3b8);margin-bottom:8px">These trade something for the saving, so <code class="dc-code">/cheap</code> leaves them to you:</p>
      <ol class="dc-ol">
        <li><strong>Split the work.</strong> <code class="dc-code">/cowork &lt;strong&gt; &lt;weak&gt;</code>: the strong model writes the code; a cheaper or free local model runs tests, builds and commit messages.</li>
        <li><strong>Shorter answers.</strong> <code class="dc-code">/lean</code> asks for minimal output. Output tokens cost several times more than input.</li>
        <li><strong>Less thinking.</strong> <code class="dc-code">/effort low</code> for routine work.</li>
        <li><strong>Cap spend.</strong> <code class="dc-code">/budget 5</code> stops before a runaway bill, checked between and within turns.</li>
        <li><strong>Check first.</strong> <code class="dc-code">/estimate &lt;prompt&gt;</code> shows the rough cost before you send; <code class="dc-code">/warm</code> shows whether the next message hits the cache.</li>
      </ol>`;

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
        <details class="dc-details"><summary>What is Darknode?</summary><p style="color:var(--mut,#94a3b8);padding:12px 16px 0;margin:0">A cybersecurity platform for businesses and individuals: scan your code, cloud, dependencies and web exposure, triage the findings, and fix what matters. It runs on the web, as a desktop app, in the terminal (CLI + Nexus), and as Darknode OS.</p></details>
        <details class="dc-details"><summary>What are the Personal and Organization spaces?</summary><p style="color:var(--mut,#94a3b8);padding:12px 16px 0;margin:0">Two spaces in the Darknode Deck. Personal is for one person: check your domain, watch your certificates, check a suspicious link or email, scan a project for leaked keys, check text before you share it, and open the Web toolkit. Organization runs the same checks at company scale: a domain portfolio, a certificate fleet, a phishing triage queue, repository secret scans and data-loss review.</p></details>
        <details class="dc-details"><summary>Where did the console go?</summary><p style="color:var(--mut,#94a3b8);padding:12px 16px 0;margin:0">The Darknode Deck is the workspace after you sign in, and every tool opens inside it: use the sidebar or Ctrl K search. The older console view has been retired for users; a link to a tool (darknode.ai/&lt;tool&gt;) opens that tool in the Deck.</p></details>
        <details class="dc-details"><summary>Which tools do I get on my plan?</summary><p style="color:var(--mut,#94a3b8);padding:12px 16px 0;margin:0">Tools are shown according to your plan; anything outside your plan is simply not listed. Free covers the Personal space and platform basics; Pro adds exposure, application-security and reporting tools; Team adds the Organization space, identity and security-operations tools and team workspaces; Enterprise adds risk and compliance tooling.</p></details>
        <details class="dc-details"><summary>Do the checks touch my systems?</summary><p style="color:var(--mut,#94a3b8);padding:12px 16px 0;margin:0">The domain and certificate checks read only public signals (HTTP headers, DNS, certificate transparency, security.txt). Secret and sensitive-data checks run entirely in your browser. The Web toolkit's API, WebSocket and fuzzing tools do send requests to the target you name, so use them only on systems you own or are authorized to test.</p></details>
        <details class="dc-details"><summary>Do I need an API key for Nexus?</summary><p style="color:var(--mut,#94a3b8);padding:12px 16px 0;margin:0">No. The Claude engine drives your logged-in Claude Code CLI; the local engine talks to your own Ollama. Nexus stores no keys.</p></details>
        <details class="dc-details"><summary>Does my code leave my machine?</summary><p style="color:var(--mut,#94a3b8);padding:12px 16px 0;margin:0">Only if you use a cloud engine (every engine except Ollama). The Ollama engine is fully local. <code class="dc-code">/redact</code> masks secrets before any cloud send; <code class="dc-code">/offline</code> blocks cloud entirely.</p></details>
        <details class="dc-details"><summary>How is Nexus different from Claude Code?</summary><p style="color:var(--mut,#94a3b8);padding:12px 16px 0;margin:0">Nexus is not a replacement: its Claude engine drives your Claude Code. It puts Claude Code and five other engines (Gemini, Codex, OpenCode, Aider, local Ollama) behind one set of over 140 commands, and adds lossless cost savers, exact per-turn cost, git checkpoints and a destructive-command check to each of them.</p></details>
        <details class="dc-details"><summary>Is it free?</summary><p style="color:var(--mut,#94a3b8);padding:12px 16px 0;margin:0">The core platform, the CLI and Nexus are free. Paid Pro, Team and Enterprise plans (coming soon) add more tools. Cloud model usage in Nexus is billed by your provider; the local engine is free.</p></details>
        <details class="dc-details"><summary>Where is my project data stored?</summary><p style="color:var(--mut,#94a3b8);padding:12px 16px 0;margin:0">In <code class="dc-code">.nexus/</code> in your project (session, plan, index, memory) — gitignored automatically. Web-console account data is described in the Privacy Policy.</p></details>
      </div>`;

    case 'terms': return `
      <p style="color:var(--mut,#94a3b8);margin-bottom:16px;font-size:.9rem">These terms govern your use of the Darknode suite (the "Software" and "Services"). By using them you agree to them.</p>
      <ol class="dc-ol" style="font-size:.9rem">
        <li><strong>License to use.</strong> The Software is provided as-is; all rights are reserved by the author.</li>
        <li><strong>Authorized use only.</strong> You will use the security tooling exclusively against systems you own or are explicitly authorized in writing to test. You are solely responsible for compliance with all applicable laws.</li>
        <li><strong>No guarantee of detection or compliance.</strong> The analysis tools identify some potential issues; they do not and cannot find every vulnerability, misconfiguration, or error, and may produce false positives and false negatives. A clean or passing result is not a certification, warranty, or representation that your code, systems, or data are secure, correct, or compliant. The tools aid — they never replace — qualified human review, professional penetration testing, and independent audit.</li>
        <li><strong>No professional advice.</strong> Nothing we provide — findings, scores, mappings, analyses, or recommendations — is legal, accounting, tax, financial, audit, or other professional advice, or a certification of compliance. Obtain independent professional advice before relying on any output. You are solely responsible for the security and correctness of your own systems and data and for any decision made in reliance on a result.</li>
        <li><strong>No warranty.</strong> The Software and Services are provided "as is" and "as available", without warranty of any kind, express or implied, including merchantability, fitness for a particular purpose, accuracy, completeness, and non-infringement. Automated agents can make mistakes; review their output.</li>
        <li><strong>Limitation of liability.</strong> To the maximum extent permitted by law, the authors are not liable for any indirect, incidental, special, consequential, or punitive damages, or for lost profits, data, or business, arising from use of the Software or Services — even if advised of the possibility — and total aggregate liability will not exceed the greater of fees you paid in the prior 12 months or US$100.</li>
        <li><strong>Self-hosted use.</strong> Where you run Darknode in your own environment, you alone control and are responsible for that deployment and all data processed within it; we have no access to it. We do not receive the source code, systems, or data you analyze client-side or on-premises.</li>
        <li><strong>AI features.</strong> The built-in web assistant sends messages through Darknode's edge proxy to a third-party model provider (Google Gemini by default, or Anthropic when a signed-in user picks a Claude model); Darknode does not log or store them. Cloud AI providers, model usage and billing are governed by those providers' own terms.</li>
        <li><strong>Assistant lookups.</strong> With a security integration connected in the Deck, the assistant can run lookups on it; it shows each call and asks first unless you choose Always allow.</li>
        <li><strong>Plans.</strong> Which tools and spaces you can use depends on your plan; features outside your plan are not shown.</li>
        <li><strong>Changes.</strong> These terms may be updated; continued use constitutes acceptance.</li>
      </ol>
      <!-- The pointing-up emoji below is the one emoji the owner explicitly asked to keep here (points up at the terms); no other emojis in the UI. -->
      <p style="color:var(--mut,#94a3b8);margin-top:16px;font-size:.9rem;font-style:italic">Our lawyers made us say all of that. <span aria-hidden="true">&#9757;&#65039;</span> They were, regrettably, correct. The short version, which changes none of the binding version above: the tools help, they are not magic, nothing here is a guarantee, and you are responsible for your own systems, data, and decisions.</p>`;

    case 'privacy': return `
      <p style="color:var(--mut,#94a3b8);margin-bottom:16px;font-size:.9rem">We collect the minimum needed to run the Services.</p>
      <ul class="dc-ul" style="font-size:.9rem">
        <li><strong>Local edition.</strong> The CLI and desktop app run on your machine. Project state lives in <code class="dc-code">.nexus/</code>. We do not collect your code or prompts.</li>
        <li><strong>Web Deck.</strong> If you sign in, we store your account identifier and preferences to provide the service. We do not sell personal data.</li>
        <li><strong>Feedback.</strong> Feedback you submit is stored to improve the product and is readable only by you and the maintainers.</li>
        <li><strong>Retention &amp; deletion.</strong> You may request deletion of your account data at any time via Settings or by contacting the maintainers.</li>
        <li><strong>In-browser tools.</strong> Most analysis runs in your browser. Check history and saved domain lists in the Deck spaces are kept in your browser's local storage, unless you turn on the weekly email digest. Live checks against a domain you enter are fetched through our edge proxy and are not stored.</li>
        <li><strong>Weekly email digest.</strong> Off unless you turn it on in Settings. While it is on we store your watched domains and your latest certificate-check results (domain, expiry date, issuer) on our servers to build the email, and send it to your account email through our email provider, Resend. Turn it off in Settings or with the unsubscribe link in any digest.</li>
        <li><strong>AI assistant.</strong> Questions to the built-in assistant pass through our edge proxy to the model provider and are not logged or stored by us. To apply the daily message limits we keep a count of messages for the current UTC day, per account (or per IP address when you are not signed in); the count holds no message content and is cleared the next day.</li>
        <li><strong>Integrations.</strong> A Deck integration is connected only after a live test of your key, which stays in your browser. Lookups to providers that block browser calls (such as VirusTotal or Shodan) pass your key and the looked-up value through our edge relay to that provider only; we do not log or store the key, the value or the result. The assistant asks before each lookup unless you choose Always allow.</li>
        <li><strong>Product usage.</strong> Signed in to Nexus or the desktop app, it tells us about every 6 hours that your account uses it, with the app version and operating system; the desktop app also sends how many virtual machines it holds and when one last started, never their names, disks or contents. Turn it off with <code class="dc-code">/shareusage off</code> in Nexus or Settings &gt; Share app usage in the app. Signed out, nothing is sent.</li>
        <li><strong>Cookies.</strong> Only functional cookies/localStorage for auth and preferences.</li>
      </ul>`;

    case 'aup': return `
      <p style="color:var(--mut,#94a3b8);margin-bottom:16px;font-size:.9rem">You agree <strong>not</strong> to use Darknode to:</p>
      <ul class="dc-ul" style="font-size:.9rem">
        <li>Access, scan, exploit or disrupt systems you do not own or lack written authorization to test. This includes the web-security toolkit (API and WebSocket testers, fuzzers, header and CORS checks).</li>
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

// Data-backed blocks in the Nexus and Cost tabs, filled after the tab renders.
const _dcData = {};
function _dcJSON(name) {
  return _dcData[name] || (_dcData[name] = fetch('/data/' + name + '.json').then(function(r) {
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  }).catch(function(e) { delete _dcData[name]; throw e; }));
}
function _dcMoney(n) { return '$' + n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 }); }
const _dcMut = 'color:var(--mut,#94a3b8)';

function _dcFillCmds(el) {
  _dcJSON('nexus-commands').then(function(d) {
    var rowHTML = function(r) { return '<tr data-q="' + esc((r[0] + ' ' + r[1]).toLowerCase()) + '"><td><code class="dc-code">' + esc(r[0]) + '</code></td><td style="' + _dcMut + '">' + esc(r[1]) + '</td></tr>'; };
    el.innerHTML =
      '<p style="' + _dcMut + ';margin-bottom:10px">All ' + d.count + ' commands, generated from the commands built into Nexus.</p>' +
      '<input class="dc-filter" type="search" placeholder="Filter commands" aria-label="Filter commands">' +
      '<p class="dc-filter-none" style="' + _dcMut + ';display:none">No command matches.</p>' +
      '<table class="dc-table"><tbody>' + d.commands.map(rowHTML).join('') + '</tbody></table>';
    var rows = el.querySelectorAll('tr'), none = el.querySelector('.dc-filter-none');
    el.querySelector('.dc-filter').addEventListener('input', function(e) {
      var q = e.target.value.trim().toLowerCase(), shown = 0;
      rows.forEach(function(tr) { var hit = !q || tr.dataset.q.indexOf(q) >= 0; tr.style.display = hit ? '' : 'none'; if (hit) shown++; });
      none.style.display = shown ? 'none' : '';
    });
  }).catch(function() { el.innerHTML = '<p style="' + _dcMut + '">The command list could not load. Run <code class="dc-code">/help</code> in Nexus to see every command.</p>'; });
}

function _dcFillCheap(el) {
  _dcJSON('nexus-cheap-replay').then(function(d) {
    var s = d.sample, num = function(n) { return n.toLocaleString('en-US'); };
    el.innerHTML =
      '<p style="' + _dcMut + ';margin-bottom:12px">Measured, not estimated: ' + num(s.calls) + ' real requests from ' + num(s.sessions) + ' sessions over ' + d.period.days + ' days (' + esc(d.period.from) + ' to ' + esc(d.period.to) + '), replayed with and without /cheap. The same tokens are priced at each model’s list rates, so the rows compare models fairly.</p>' +
      '<div class="dc-scroll"><table class="dc-table dc-num"><thead><tr><th>Model</th><th>Without /cheap</th><th>With /cheap</th><th>Saved</th><th>Keep-warm saved</th><th>Ping cost</th><th>Skill trim saved</th></tr></thead><tbody>' +
      d.models.map(function(m) {
        return '<tr><td>' + esc(m.label) + '</td><td>' + _dcMoney(m.before) + '</td><td>' + _dcMoney(m.after) + '</td><td><strong>' + _dcMoney(m.saved) + ' (' + m.pct + '%)</strong></td><td>' + _dcMoney(m.keepWarmSaved) + '</td><td>&minus;' + _dcMoney(m.pingCost) + '</td><td>' + _dcMoney(m.skillSaved) + '</td></tr>';
      }).join('') + '</tbody></table></div>' +
      '<ul class="dc-ul" style="font-size:.86rem">' +
        '<li><strong>Why the percentage differs by model.</strong> Keep-warm turns a cache write into a cache read, and the gap between those two prices is wider on some models than others. Models with a wider gap save a larger share.</li>' +
        '<li><strong>What drove it.</strong> ' + num(s.rebuildsAfterBreaks) + ' times the cache had expired after a break of over an hour; keep-warm would have prevented ' + num(s.rebuildsAvoided) + ' of them, for ' + num(s.keepWarmPings) + ' pings. Every ping is charged in the With column, including pings in breaks too long to save.</li>' +
        '<li><strong>Limits.</strong> One developer’s Claude Code sessions with a one-hour cache. It assumes Nexus stays open during breaks, since keep-warm only runs while it is. The model-switch hold and cross-folder cache sharing are left out because their effect cannot be measured from past usage, and other engines were not measured. Your share depends on how often you take breaks and how large your context is.</li>' +
      '</ul>' +
      '<p style="' + _dcMut + ';font-size:.82rem">Inside Nexus, <code class="dc-code">/cheap status</code> shows what each saver did in your own session, and <code class="dc-code">/savings</code> totals it across sessions.</p>';
  }).catch(function() { el.innerHTML = '<p style="' + _dcMut + '">The measurement could not load. Run <code class="dc-code">/cheap status</code> in Nexus to see your own numbers.</p>'; });
}

function _dcHydrate(body) {
  var c = body.querySelector('[data-nx="cmds"]'); if (c) _dcFillCmds(c);
  var h = body.querySelector('[data-nx="cheap"]'); if (h) _dcFillCheap(h);
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
    _dcHydrate(body);
    if (history.replaceState) history.replaceState(history.state, '', location.pathname + location.search + '#doc-' + id);
    body.querySelectorAll('.dc-details').forEach(function(d) {
      d.querySelector('summary').addEventListener('click', function(e) {
        e.preventDefault();
        d.toggleAttribute('open');
      });
    });
  }
}

// The privacy and acceptable-use text, for the public legal pages (legal.js).
export function docSectionHTML(id) { return renderSection(id); }

export function renderDocs(main) {
  var fromHash = /^#doc-(.+)$/.exec(location.hash);
  _dcCurrentTab = fromHash && TABS.some(function(t) { return t.id === fromHash[1]; }) ? fromHash[1] : 'getting-started';

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
    '.dc-grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:14px;margin-bottom:8px}' +
    '.dc-grid2 .dc-card{padding:16px 16px 6px}' +
    '.dc-scroll{overflow-x:auto;margin-bottom:12px}' +
    '.dc-table th{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line,#1a2a44);font-size:.78rem;font-weight:700;color:var(--mut,#94a3b8);white-space:nowrap}' +
    '.dc-num td,.dc-num th{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}' +
    '.dc-num td:first-child,.dc-num th:first-child{text-align:left}' +
    '.dc-filter{width:100%;max-width:360px;box-sizing:border-box;padding:8px 12px;margin-bottom:10px;background:var(--card,#141c28);border:1px solid var(--line,#1a2a44);border-radius:6px;color:var(--txt,#e2e8f0);font:inherit;font-size:.88rem}' +
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
    '@media(max-width:768px){.dc-wrap{padding:20px 16px 40px}.dc-title{font-size:1.3rem}.dc-tabs{gap:2px}.dc-tab{padding:8px 10px;font-size:.75rem}.dc-grid2{grid-template-columns:1fr}}';
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
    '<p class="dc-sub">Everything for the Darknode suite — the web Deck, the desktop app, the terminal edition (CLI), and <strong>Nexus</strong>, its AI coding agent. Last updated ' + UPDATED + '.</p>' +
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
  _dcHydrate(body);
  var cur = TABS.find(function(t) { return t.id === _dcCurrentTab; });
  if (cur) wrap.querySelector('.dc-breadcrumb-current').textContent = cur.label;

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
