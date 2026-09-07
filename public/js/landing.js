// Marketing landing page — clean, focused, one clear product offering.
// actions: { onGetStarted, onSignIn }

const SITE = "https://darknode.ai";
const GITHUB = "https://github.com/SpartanKing18";

const ICON = {
  terminal: '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>',
  shield:   '<path d="M12 2l8 4v6c0 5-3.5 8-8 10-4.5-2-8-5-8-10V6z"/>',
  ai:       '<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/>',
  book:     '<path d="M4 5a2 2 0 0 1 2-2h13v16H6a2 2 0 0 0-2 2z"/><path d="M19 3v18"/>',
  download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>',
  code:     '<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>',
};
const svg = (k) => `<svg class="ico" viewBox="0 0 24 24">${ICON[k]}</svg>`;

export function renderLanding(view, actions) {
  const feature = (icon, t, d) => `<div class="feat-card"><div class="feat-ico">${svg(icon)}</div><h3>${t}</h3><p>${d}</p></div>`;
  const product = (icon, name, desc, link, linkText) => `<div class="product-card"><div class="product-ico">${svg(icon)}</div><h3>${name}</h3><p>${desc}</p><a class="product-link" href="${link}">${linkText} &rarr;</a></div>`;

  view.innerHTML = `
    <section class="hero">
      <div class="hero-grid-bg"></div>
      <div class="wrap hero-inner">
        <div class="hero-copy">
          <h1 class="hero-h1">Learn cybersecurity by <span class="grad-text">doing it.</span></h1>
          <p class="hero-sub">Darknode gives you the tools, labs, and AI to practice ethical hacking — all running on your own machine. Nothing to configure. Nothing leaves your computer.</p>
          <div class="hero-cta">
            <button class="btn lg glow" id="cta-start">Get started free &rarr;</button>
          </div>
          <div class="hero-trust">
            <span><span class="tk">&#10003;</span> 100% free</span>
            <span><span class="tk">&#10003;</span> Runs locally</span>
            <span><span class="tk">&#10003;</span> No data collection</span>
          </div>
        </div>
        <div class="hero-visual">
          <div class="term-window">
            <div class="tw-bar"><span class="tw-dot r"></span><span class="tw-dot y"></span><span class="tw-dot g"></span><span class="tw-title">darknode</span></div>
            <pre class="tw-body"><span class="tw-line" style="animation-delay:.15s"><span class="c-pl">darknode@ai</span>:<span class="c-path">~</span>$ darknode scan 10.10.14.7</span><span class="tw-line" style="animation-delay:.6s"><span class="c-mut">Scanning...</span></span><span class="tw-line" style="animation-delay:1s">PORT     STATE SERVICE</span><span class="tw-line" style="animation-delay:1.2s">22/tcp   <span class="c-ok">open</span>  ssh</span><span class="tw-line" style="animation-delay:1.45s">80/tcp   <span class="c-ok">open</span>  http</span><span class="tw-line" style="animation-delay:1.7s">443/tcp  <span class="c-ok">open</span>  https</span><span class="tw-line" style="animation-delay:2s"><span class="c-acc">[+]</span> 3 open ports found</span><span class="tw-line" style="animation-delay:2.3s"><span class="c-pl">darknode@ai</span>:<span class="c-path">~</span>$ <span class="tw-cursor">&#9619;</span></span></pre>
          </div>
        </div>
      </div>
    </section>

    <section class="section" id="what">
      <div class="wrap">
        <h2 class="sec-title">What is Darknode?</h2>
        <p class="sec-sub muted" style="max-width:640px;margin:0 auto 32px;text-align:center">Darknode is a cybersecurity learning platform &mdash; like TryHackMe or HackTheBox, but everything runs on your own computer. No subscriptions. No cloud dependency. You own your environment.</p>
        <div class="feat-grid">
          ${feature("terminal", "Security tools", "80+ pre-configured tools for scanning, recon, and testing &mdash; with one-command install.")}
          ${feature("ai", "Built-in AI", "An AI coding agent that helps you learn, explains vulnerabilities, and writes scripts. Bring your own API key or use free local models.")}
          ${feature("shield", "Practice labs", "Launch vulnerable apps (DVWA, Juice Shop) locally with one click. Safe, legal, on your machine.")}
          ${feature("book", "Learning hub", "Cheat sheets, study paths, quizzes, and walkthroughs organized by topic.")}
        </div>
      </div>
    </section>

    <section class="section alt" id="products">
      <div class="wrap">
        <h2 class="sec-title">Pick how you want to use it</h2>
        <p class="sec-sub muted" style="max-width:580px;margin:0 auto 32px;text-align:center">Three ways to use Darknode. All free. All run on your machine.</p>
        <div class="product-grid">
          ${product("code", "Web App", "Use Darknode right in your browser. Tools, cheat sheets, CVE lookup, and the learning hub &mdash; no install needed.", "#", "Open web app")}
          ${product("terminal", "CLI", "A terminal command with 80+ security tools built in. Install with npm and you're ready.", GITHUB + "/darknode-cli", "View on GitHub")}
          ${product("download", "Linux VM", "A full security workstation &mdash; like Kali Linux but with Darknode and AI built in. Runs in VirtualBox.", GITHUB + "/darknode-os", "View on GitHub")}
        </div>
      </div>
    </section>

    <section class="section" id="ai">
      <div class="wrap">
        <h2 class="sec-title">AI that runs on your machine</h2>
        <p class="sec-sub muted" style="max-width:620px;margin:0 auto 32px;text-align:center">Darknode includes Nexus &mdash; an AI agent engine. It reads your code, runs commands, and explains security concepts. Use free local models (Ollama) or bring your own API key for Claude, GPT, or Gemini.</p>
        <div class="feat-grid">
          ${feature("ai", "Your key, your models", "Bring your own API key for Claude, GPT, or Gemini. Or use 100% free local models via Ollama. We never see your key or your data.")}
          ${feature("terminal", "Runs locally", "The AI runs on YOUR computer. Your prompts, your code, your data &mdash; nothing is sent to our servers. Ever.")}
          ${feature("shield", "No restrictions", "No token limits. No tier gates. No credits to manage. Use whatever model you want, as much as you want.")}
          ${feature("code", "Built for security", "Nexus understands security tools, CVEs, and pentesting workflows. It's not a generic chatbot &mdash; it's built for this.")}
        </div>
      </div>
    </section>

    <section class="section alt" id="how">
      <div class="wrap">
        <h2 class="sec-title">Get started in 60 seconds</h2>
        <div class="steps">
          <div class="step"><div class="step-n">1</div><div><h3>Create an account</h3><p>Sign in with Google or GitHub. Takes 5 seconds.</p></div></div>
          <div class="step"><div class="step-n">2</div><div><h3>Choose your setup</h3><p>Web app (no install), CLI (<code>npm i -g darknode-cli</code>), or the full Linux VM.</p></div></div>
          <div class="step"><div class="step-n">3</div><div><h3>Start learning</h3><p>Launch a practice lab, scan it with Darknode, and learn by doing.</p></div></div>
        </div>
      </div>
    </section>

    <section class="cta-band">
      <div class="cta-glow"></div>
      <div class="wrap cta-band-inner">
        <div>
          <h2>Ready to start?</h2>
          <p class="muted">Free forever. No credit card. No catch.</p>
        </div>
        <button class="btn lg glow" id="cta-signup">Get started free &rarr;</button>
      </div>
    </section>

    <footer class="site-foot">
      <div class="wrap foot-inner">
        <span class="brand">Darknode</span>
        <span class="muted">Learn cybersecurity by doing it.</span>
        <nav class="foot-links">
          <a href="#what">What is it</a>
          <a href="#products">Products</a>
          <a href="#ai">AI</a>
          <a href="${GITHUB}">GitHub</a>
          <a id="foot-signin">Sign in</a>
        </nav>
      </div>
    </footer>`;

  const $ = (id) => view.querySelector("#" + id);
  $("cta-start").onclick = actions.onGetStarted;
  $("cta-signup").onclick = actions.onGetStarted;
  $("foot-signin").onclick = actions.onSignIn;

  // Scroll-reveal
  if ("IntersectionObserver" in window) {
    let reduceMotion = false; try { reduceMotion = matchMedia("(prefers-reduced-motion:reduce)").matches; } catch (_) {}
    if (!reduceMotion) {
      const targets = view.querySelectorAll(
        ".sec-title, .feat-card, .product-card, .step, .cta-band-inner"
      );
      const io = new IntersectionObserver((entries) => {
        entries.forEach((e) => { if (e.isIntersecting) { e.target.classList.add("revealed"); io.unobserve(e.target); } });
      }, { threshold: 0.12 });
      targets.forEach((el) => io.observe(el));
    }
  }
}
