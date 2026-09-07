// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
(function(){var _h=location.hostname,_a=["darknode.ai","www.darknode.ai","localhost","127.0.0.1"];if(!_a.some(function(d){return _h===d}))throw document.body.innerHTML="",new Error("unlicensed")}());

const GITHUB = "https://github.com/SpartanKing18";

export function renderLanding(view, actions) {
  view.innerHTML = `

    <!-- ====== HERO ====== -->
    <section class="hero" aria-label="Hero">
      <div class="hero-mesh"></div>
      <div class="hero-grain"></div>
      <div class="wrap hero-inner">
        <div class="hero-badge"><span class="badge-dot"></span> Open source &middot; Free forever</div>
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
          <div class="trust-item"><span class="trust-n" data-count="80">0</span><span class="trust-l">Security tools</span></div>
          <div class="trust-sep"></div>
          <div class="trust-item"><span class="trust-n" data-count="59">0</span><span class="trust-l">AI modules</span></div>
          <div class="trust-sep"></div>
          <div class="trust-item"><span class="trust-n" data-count="8">0</span><span class="trust-l">AI engines</span></div>
          <div class="trust-sep"></div>
          <div class="trust-item"><span class="trust-n">100%</span><span class="trust-l">Local &amp; private</span></div>
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
            <p>One command: <code>npm i -g darknode-cli</code>. 80+ tools, AI agent, and the Nexus engine in your terminal.</p>
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
              <h3>80+ security tools, one command away</h3>
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

    <!-- ====== NEXUS ENGINE ====== -->
    <section class="section" id="nexus" aria-labelledby="nexus-title">
      <div class="wrap">
        <div class="sec-label">AI Engine</div>
        <h2 class="sec-title" id="nexus-title">Nexus — 9,600 lines of AI infrastructure</h2>
        <p class="sec-sub">Not a wrapper around ChatGPT. A full agentic platform with planning, multi-agent orchestration, self-evaluation, and 8 AI backends.</p>
        <div class="nexus-grid">
          <div class="nx-card"><div class="nx-n">59</div><div class="nx-l">modules</div></div>
          <div class="nx-card"><div class="nx-n">10,586</div><div class="nx-l">lines of code</div></div>
          <div class="nx-card"><div class="nx-n">93</div><div class="nx-l">tests passing</div></div>
          <div class="nx-card"><div class="nx-n">8</div><div class="nx-l">AI engines</div></div>
          <div class="nx-card"><div class="nx-n">0</div><div class="nx-l">dependencies</div></div>
          <div class="nx-card"><div class="nx-n">30+</div><div class="nx-l">research papers</div></div>
        </div>
        <details class="nx-details">
          <summary>See all 52 modules &darr;</summary>
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

    <!-- ====== HOW IT WORKS ====== -->
    <section class="section alt" id="how">
      <div class="wrap">
        <div class="sec-label">Get started</div>
        <h2 class="sec-title">Up and running in 60 seconds</h2>
        <div class="timeline">
          <div class="tl-step">
            <div class="tl-dot">1</div>
            <div class="tl-content">
              <h3>Create a free account</h3>
              <p>Sign in with Google or GitHub. No credit card.</p>
            </div>
          </div>
          <div class="tl-step">
            <div class="tl-dot">2</div>
            <div class="tl-content">
              <h3>Choose your setup</h3>
              <p>Web app (instant), CLI (<code>npm i -g darknode-cli</code>), or the full Linux VM.</p>
            </div>
          </div>
          <div class="tl-step">
            <div class="tl-dot">3</div>
            <div class="tl-content">
              <h3>Learn by doing</h3>
              <p>Launch a lab, scan it, find vulnerabilities, and let Nexus AI guide you.</p>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- ====== OPEN SOURCE ====== -->
    <section class="section" id="open-source">
      <div class="wrap" style="text-align:center">
        <div class="sec-label">Open source</div>
        <h2 class="sec-title">Built in the open</h2>
        <p class="sec-sub">Every line of code is on GitHub. Audit it, fork it, contribute to it.</p>
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
              <li>80+ security tools</li>
              <li>Practice labs (DVWA, Juice Shop)</li>
              <li>Learning hub &amp; cheat sheets</li>
              <li>Nexus AI &mdash; core agent</li>
              <li>Security RAG &mdash; AI with built-in OWASP, CVEs, attack patterns</li>
              <li>5 MCP server integrations</li>
            </ul>
            <button class="btn lg" id="price-free">Get started free</button>
          </div>
          <div class="price-card featured">
            <div class="price-badge">Recommended</div>
            <div class="price-tier">Pro</div>
            <div class="price-amount">$12<span class="price-period">/month</span></div>
            <p class="price-desc">Advanced AI features for serious learners.</p>
            <ul class="price-features">
              <li>Everything in Free, plus:</li>
              <li>Multi-agent pipelines (8 roles)</li>
              <li>Ghost Agents &mdash; background monitoring</li>
              <li>Thought Stream &mdash; visible reasoning</li>
              <li>Smart Test Generator</li>
              <li>Attack Planner — AI pentest methodology</li>
              <li>CTF Assistant — guided challenge solving</li>
              <li>Threat Modeler — STRIDE analysis</li>
              <li>Vulnerability Scanner — security headers</li>
              <li>Code Radar &mdash; codebase analysis</li>
              <li>25 MCP server integrations</li>
              <li>Priority support</li>
            </ul>
            <button class="btn lg glow" id="price-pro" disabled>Coming soon</button>
          </div>
          <div class="price-card">
            <div class="price-tier">Team</div>
            <div class="price-amount">$25<span class="price-period">/month</span></div>
            <p class="price-desc">Collaborate, compete, and train together.</p>
            <ul class="price-features">
              <li>Everything in Pro, plus:</li>
              <li>Skill Forge &mdash; AI creates its own tools</li>
              <li>World Model &mdash; simulate before acting</li>
              <li>Deep Memory (3-tier cognitive)</li>
              <li>Time Travel &mdash; undo any action</li>
              <li>Team workspace &amp; shared labs</li>
              <li>Custom training scenarios</li>
              <li>Report Generator — professional pentest reports</li>
              <li>OWASP Top 10 compliance checker</li>
              <li>Full STRIDE threat modeling</li>
              <li>White-label report branding</li>
              <li>Plugin system &amp; extensions</li>
            </ul>
            <button class="btn lg" id="price-team" disabled>Coming soon</button>
          </div>
          <div class="price-card">
            <div class="price-tier">Enterprise</div>
            <div class="price-amount">Custom</div>
            <p class="price-desc">Tailored security training for your organization.</p>
            <ul class="price-features">
              <li>Everything in Team, plus:</li>
              <li>SSO &amp; SAML authentication</li>
              <li>Dedicated instance &amp; data isolation</li>
              <li>Custom compliance frameworks</li>
              <li>Admin dashboard &amp; usage analytics</li>
              <li>Role-based access control</li>
              <li>SLA &amp; dedicated support</li>
              <li>Custom AI model deployment</li>
              <li>Unlimited MCP integrations</li>
              <li>On-prem or private cloud hosting</li>
              <li>Audit logging &amp; SOC 2 reporting</li>
            </ul>
            <button class="btn lg" id="price-enterprise" disabled>Coming soon</button>
          </div>
        </div>
        <p class="pricing-note">All plans include BYOK &mdash; bring your own Claude, GPT, or Gemini key. Paid plans unlock <strong>platform features</strong>, not AI access. You never pay us for AI tokens.</p>
      </div>
    </section>

    <!-- ====== CTA ====== -->
    <section class="cta-final">
      <div class="cta-mesh"></div>
      <div class="wrap" style="position:relative;text-align:center">
        <h2>Start learning security today.</h2>
        <p class="cta-sub">Free. Open source. Private. No catch.</p>
        <button class="btn lg glow" id="cta-signup">Get started &rarr;</button>
      </div>
    </section>

    <!-- ====== FOOTER ====== -->
    <footer class="foot" role="contentinfo">
      <div class="wrap foot-grid">
        <div class="foot-brand">
          <img class="brand-wordmark" src="/wordmark.svg" alt="Darknode" height="14" style="opacity:.85">
          <span class="foot-tagline">Learn cybersecurity by doing it.</span>
        </div>
        <div class="foot-col">
          <h4>Product</h4>
          <a href="#products">Web App</a>
          <a href="${GITHUB}/darknode-cli">CLI</a>
          <a href="${GITHUB}/darknode-os">Linux VM</a>
          <a href="#nexus">Nexus AI</a>
        </div>
        <div class="foot-col">
          <h4>Resources</h4>
          <a href="#features">Features</a>
          <a href="#pricing">Pricing</a>
          <a href="#how">Get started</a>
          <a href="${GITHUB}">GitHub</a>
        </div>
        <div class="foot-col">
          <h4>Legal</h4>
          <a href="#">Terms</a>
          <a href="#">Privacy</a>
          <a href="#">Acceptable Use</a>
        </div>
      </div>
      <div class="wrap foot-bottom">
        <span class="foot-copy">&copy; 2026 Darknode. All rights reserved.</span>
        <span class="foot-note">All tools run locally. We never collect your data.</span>
      </div>
    </footer>`;

  const $ = (id) => view.querySelector("#" + id);
  $("cta-start").onclick = actions.onGetStarted;
  $("cta-signup").onclick = actions.onGetStarted;
  if ($("price-free")) $("price-free").onclick = actions.onGetStarted;
  if ($("price-pro")) $("price-pro").onclick = actions.onGetStarted;
  if ($("price-team")) $("price-team").onclick = actions.onGetStarted;

  // Animated counter for hero stats
  view.querySelectorAll("[data-count]").forEach(el => {
    const target = parseInt(el.dataset.count);
    let current = 0;
    const step = Math.max(1, Math.floor(target / 30));
    const timer = setInterval(() => {
      current += step;
      if (current >= target) { current = target; clearInterval(timer); }
      el.textContent = current;
    }, 40);
  });

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

  // Scroll reveal
  if ("IntersectionObserver" in window) {
    let reduce = false; try { reduce = matchMedia("(prefers-reduced-motion:reduce)").matches; } catch (_) {}
    if (!reduce) {
      const io = new IntersectionObserver((entries) => {
        entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add("revealed"); io.unobserve(e.target); } });
      }, { threshold: 0.08, rootMargin: "0px 0px -40px 0px" });
      view.querySelectorAll(".sec-title, .bento-card, .price-card, .feature-row, .tl-step, .nx-card, .gh-card, .cta-final, .sec-label, .sec-sub, .pricing-note, .nx-details, .hero-trust").forEach(el => io.observe(el));
    } else {
      // If reduced motion preferred, make everything visible immediately
      view.querySelectorAll(".sec-title, .bento-card, .price-card, .feature-row, .tl-step, .nx-card, .gh-card, .cta-final, .sec-label, .sec-sub").forEach(el => el.classList.add("revealed"));
    }
  }

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
}
