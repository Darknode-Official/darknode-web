// Marketing landing page shown to signed-out visitors.
// actions: { onGetStarted, onSignIn }

// Installers are hosted on the site itself, under public/downloads/. Build each one
// (see sentinel-app/README.md), drop it into public/downloads/ with these exact
// names, and the buttons below download it straight from the website.
const APP_FILES = {
  linux: "/downloads/Sentinel-linux.AppImage",
  windows: "/downloads/Sentinel-windows.exe",
  mac: "/downloads/Sentinel-mac.dmg",
};

export function renderLanding(view, actions) {
  const feature = (t, d) => `<div class="feat-card"><h3>${t}</h3><p>${d}</p></div>`;
  const step = (n, t, d) => `<div class="step"><div class="step-n">${n}</div><div><h3>${t}</h3><p>${d}</p></div></div>`;
  const osCard = (name, fmt, os) => `<a class="dlapp-card" href="${APP_FILES[os]}" download><div class="dlapp-os">${name}</div><div class="dlapp-fmt">${fmt}</div></a>`;

  view.innerHTML = `
    <section class="hero">
      <div class="wrap hero-inner">
        <div class="eyebrow">SECURITY CONSOLE</div>
        <h1 class="hero-h1">Every tool you need, in one console.</h1>
        <p class="hero-sub">Sentinel brings your security tools, local AI models, and setup guides into one place. Sign in and get your environment running in minutes.</p>
        <div class="hero-cta">
          <button class="btn lg" id="cta-start">Get Started</button>
          <button class="btn ghost lg" id="cta-learn">Learn more</button>
        </div>
        <div class="hero-note">Free to use &middot; sign in with Google, GitHub, or email.</div>
      </div>
    </section>

    <section class="section" id="features">
      <div class="wrap">
        <h2 class="sec-title">Built for getting things done</h2>
        <div class="feat-grid">
          ${feature("Curated tooling", "Install nmap, sqlmap, theHarvester and more with copy-paste commands tailored to your OS.")}
          ${feature("Local AI models", "Run Ollama models like llama3.1 and qwen2.5-coder on your own machine &mdash; nothing leaves your box.")}
          ${feature("One sign-in", "Google, GitHub, or email with verification. Your setup follows your account.")}
          ${feature("Guided onboarding", "A step-by-step walkthrough gets newcomers productive fast &mdash; skippable anytime.")}
        </div>
      </div>
    </section>

    <section class="section alt" id="how">
      <div class="wrap">
        <h2 class="sec-title">Up and running in three steps</h2>
        <div class="steps">
          ${step(1, "Create an account", "Sign in with Google, GitHub, or email in seconds.")}
          ${step(2, "Grab your tools", "Pick your OS and copy the exact install commands.")}
          ${step(3, "Track &amp; return", "Mark what's installed and jump back to any tool anytime.")}
        </div>
      </div>
    </section>

    <section class="section" id="get-app">
      <div class="wrap">
        <h2 class="sec-title">Get the desktop app</h2>
        <p class="muted dlapp-sub">Far more powerful than the web version &mdash; the native app runs tools with a live terminal and talks to your local AI, right on your machine.</p>
        <div class="dlapp-grid">
          ${osCard("Linux", "AppImage", "linux")}
          ${osCard("Windows", ".exe installer", "windows")}
          ${osCard("macOS", ".dmg", "mac")}
        </div>
      </div>
    </section>

    <section class="cta-band">
      <div class="wrap cta-band-inner">
        <div>
          <h2>Ready to set up your console?</h2>
          <p class="muted">Create your account &mdash; it takes under a minute.</p>
        </div>
        <button class="btn lg" id="cta-signup">Sign up</button>
      </div>
    </section>

    <footer class="site-foot">
      <div class="wrap foot-inner">
        <span class="brand">Sentinel</span>
        <span class="muted">Your security workspace.</span>
        <nav class="foot-links">
          <a href="#features">Features</a>
          <a href="#how">How it works</a>
          <a id="foot-signin">Sign in</a>
        </nav>
      </div>
    </footer>`;

  const $ = (id) => view.querySelector("#" + id);
  $("cta-start").onclick = actions.onGetStarted;
  $("cta-signup").onclick = actions.onGetStarted;
  $("cta-learn").onclick = () => document.getElementById("features")?.scrollIntoView({ behavior: "smooth" });
  $("foot-signin").onclick = actions.onSignIn;
}
