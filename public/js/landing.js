// Marketing landing page shown to signed-out visitors.
// actions: { onGetStarted, onSignIn }

// Installers are hosted on GitHub Releases (too large to commit to the repo).
const REL = "https://github.com/RonaldPulisic/sentinel-web/releases/download/sentinel";
const APP_FILES = {
  linux: REL + "/sentinel-app_1.0.0_amd64.deb",
  appimage: REL + "/Sentinel-1.0.0.AppImage",
  windows: REL + "/Sentinel.Setup.1.0.0.exe",
};

const ICON = {
  tools: '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>',
  ai: '<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/>',
  shield: '<path d="M12 2l8 4v6c0 5-3.5 8-8 10-4.5-2-8-5-8-10V6z"/>',
  book: '<path d="M4 5a2 2 0 0 1 2-2h13v16H6a2 2 0 0 0-2 2z"/><path d="M19 3v18"/>',
  terminal: '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>',
  bolt: '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
  code: '<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>',
  globe: '<circle cx="12" cy="12" r="9"/><line x1="3" y1="12" x2="21" y2="12"/><path d="M12 3a15 15 0 0 1 0 18 15 15 0 0 1 0-18z"/>',
};
const svg = (k) => `<svg class="ico" viewBox="0 0 24 24">${ICON[k]}</svg>`;
const TOOLS_MARQUEE = ["nmap", "sqlmap", "ffuf", "nuclei", "metasploit", "hydra", "gobuster", "wireshark", "john", "hashcat", "burp", "theHarvester", "subfinder", "wpscan"];

export function renderLanding(view, actions) {
  const feature = (icon, t, d) => `<div class="feat-card"><div class="feat-ico">${svg(icon)}</div><h3>${t}</h3><p>${d}</p></div>`;
  const step = (n, t, d) => `<div class="step"><div class="step-n">${n}</div><div><h3>${t}</h3><p>${d}</p></div></div>`;
  const mod = (icon, t, d) => `<div class="mod-card"><div class="mod-ico">${svg(icon)}</div><div><div class="mod-t">${t}</div><div class="mod-d">${d}</div></div></div>`;
  const osCard = (name, fmt, os, cmd, note) => `
    <div class="dlapp-item">
      <a class="dlapp-card" href="${APP_FILES[os]}" download><div class="dlapp-os">${name}</div><div class="dlapp-fmt">${fmt}</div></a>
      <div class="dlapp-cmd"><span class="dlapp-cmd-l">After download</span><code>${cmd}</code></div>
      ${note ? `<p class="dlapp-note">${note}</p>` : ""}
    </div>`;

  view.innerHTML = `
    <section class="hero">
      <div class="hero-grid-bg"></div>
      <div class="wrap hero-inner">
        <div class="hero-copy">
          <div class="eyebrow"><span class="dot-live"></span> SECURITY CONSOLE</div>
          <h1 class="hero-h1">Your entire <span class="grad-text">security toolkit</span>, in one console.</h1>
          <p class="hero-sub">Tools, threat intel, cheat sheets, and local AI &mdash; on the web and in a powerful desktop app. Recon, exploit, and report without leaving Sentinel.</p>
          <div class="hero-cta">
            <button class="btn lg glow" id="cta-start">Get Started &rarr;</button>
            <button class="btn ghost lg" id="cta-learn">See what's inside</button>
          </div>
          <div class="hero-metrics">
            <div class="hm"><div class="hm-n">80+</div><div class="hm-l">tools</div></div>
            <div class="hm"><div class="hm-n">10</div><div class="hm-l">tracked CVEs</div></div>
            <div class="hm"><div class="hm-n">9</div><div class="hm-l">cheat sheets</div></div>
            <div class="hm"><div class="hm-n">3</div><div class="hm-l">platforms</div></div>
          </div>
        </div>
        <div class="hero-visual">
          <div class="term-window">
            <div class="tw-bar"><span class="tw-dot r"></span><span class="tw-dot y"></span><span class="tw-dot g"></span><span class="tw-title">sentinel — recon</span></div>
            <pre class="tw-body"><span class="c-pl">sentinel@kali</span>:<span class="c-path">~</span>$ nmap -sV 10.10.14.7
<span class="c-mut">Starting Nmap 7.94 · scanning…</span>
PORT     STATE SERVICE   VERSION
22/tcp   <span class="c-ok">open</span>  ssh       OpenSSH 8.2p1
80/tcp   <span class="c-ok">open</span>  http      nginx 1.18.0
443/tcp  <span class="c-ok">open</span>  ssl/http  nginx 1.18.0
<span class="c-acc">[+]</span> 3 open ports · 2 services fingerprinted
<span class="c-pl">sentinel@kali</span>:<span class="c-path">~</span>$ <span class="tw-cursor">▋</span></pre>
          </div>
        </div>
      </div>
      <div class="marquee-wrap"><span class="marquee-label">Ships with</span>
        <div class="marquee">${TOOLS_MARQUEE.map((t) => `<span class="mchip">${t}</span>`).join("")}</div>
      </div>
    </section>

    <section class="section" id="features">
      <div class="wrap">
        <div class="eyebrow center">CAPABILITIES</div>
        <h2 class="sec-title">Built to get real work done</h2>
        <div class="feat-grid">
          ${feature("tools", "Curated tooling", "80+ security tools with copy-paste install commands and in-browser utilities &mdash; encoders, hashes, payloads.")}
          ${feature("ai", "Local AI models", "Run Ollama models like llama3.1 and qwen2.5-coder on your own machine &mdash; nothing leaves your box.")}
          ${feature("shield", "Threat intel", "Notable CVEs, a common-ports attack-surface map, and a security-posture checklist.")}
          ${feature("book", "Cheat sheets", "Battle-tested one-liners for recon, shells, privesc, and cracking &mdash; one click to copy.")}
          ${feature("code", "Code workbench", "The desktop app ships a real editor, file tree, run-code, and an integrated terminal.")}
          ${feature("bolt", "Payloads & handlers", "Generate reverse shells, listeners, and msfvenom payloads with live builders.")}
        </div>
      </div>
    </section>

    <section class="section alt" id="inside">
      <div class="wrap">
        <div class="eyebrow center">WHAT'S INSIDE</div>
        <h2 class="sec-title">One console, every stage of the kill chain</h2>
        <div class="mod-grid">
          ${mod("globe", "Recon & HTTP", "Scanners, subdomain discovery, and a request repeater.")}
          ${mod("terminal", "Live terminal", "Real PTY terminals with tabs in the desktop app.")}
          ${mod("bolt", "Exploitation", "Payload builders, listeners, and exploit references.")}
          ${mod("shield", "Threat intel", "CVE feed, ports reference, and posture tracking.")}
          ${mod("book", "Cheat sheets", "Copy-paste playbooks for every engagement phase.")}
          ${mod("ai", "Local AI", "Chat and code with private, on-device models.")}
        </div>
      </div>
    </section>

    <section class="section" id="how">
      <div class="wrap">
        <div class="eyebrow center">GET STARTED</div>
        <h2 class="sec-title">Up and running in three steps</h2>
        <div class="steps">
          ${step(1, "Create an account", "Sign in with Google, GitHub, or email in seconds.")}
          ${step(2, "Grab your tools", "Pick your OS and copy the exact install commands.")}
          ${step(3, "Work the console", "Recon, exploit, take notes, and jump back anytime.")}
        </div>
      </div>
    </section>

    <section class="section alt" id="get-app">
      <div class="wrap">
        <div class="eyebrow center">DESKTOP APP</div>
        <h2 class="sec-title">Serious power for experienced operators</h2>
        <p class="muted dlapp-sub">Far more capable than the web &mdash; the native app runs tools with a live terminal, a full code workbench, and your local AI, right on your machine.</p>
        <div class="dlapp-grid">
          ${osCard("Linux", ".deb installer", "linux", "sudo apt install ./Sentinel-linux.deb", "Debian / Ubuntu / Kali &mdash; recommended. Adds Sentinel to your app menu; launch it there or run <code>sentinel</code>.")}
          ${osCard("Linux", "AppImage (portable)", "appimage", "chmod +x Sentinel-linux.AppImage &amp;&amp; ./Sentinel-linux.AppImage", "Any distro (Fedora / Arch / &hellip;). Needs FUSE: <code>sudo apt install libfuse2</code>, or run it with <code>--appimage-extract-and-run</code>.")}
          ${osCard("Windows", ".exe installer", "windows", "Double-click Sentinel-windows.exe", "If SmartScreen warns, choose More info &rarr; Run anyway (the installer is unsigned).")}
        </div>

        <div class="dlcli">
          <h3 class="dlcli-h"><span class="mono grad-text">&gt;_</span> Prefer the terminal? Get the CLI edition</h3>
          <p class="muted dlapp-sub">A single, dependency-free command-line console &mdash; native port scanner, reverse-shell generator, encoders, and cheat sheets. Runs anywhere, even over SSH on a headless box.</p>
          <div class="dlapp-grid">
            <div class="dlapp-item">
              <a class="dlapp-card" href="${REL}/Sentinel-cli-linux" download><div class="dlapp-os">Linux</div><div class="dlapp-fmt">CLI binary</div></a>
              <div class="dlapp-cmd"><span class="dlapp-cmd-l">After download</span><code>chmod +x Sentinel-cli-linux &amp;&amp; ./Sentinel-cli-linux</code></div>
            </div>
            <div class="dlapp-item">
              <a class="dlapp-card" href="${REL}/Sentinel-cli-windows.exe" download><div class="dlapp-os">Windows</div><div class="dlapp-fmt">CLI .exe</div></a>
              <div class="dlapp-cmd"><span class="dlapp-cmd-l">After download</span><code>.\\Sentinel-cli-windows.exe</code></div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <section class="cta-band">
      <div class="cta-glow"></div>
      <div class="wrap cta-band-inner">
        <div>
          <h2>Ready to set up your console?</h2>
          <p class="muted">Create your account &mdash; it takes under a minute.</p>
        </div>
        <button class="btn lg glow" id="cta-signup">Sign up free &rarr;</button>
      </div>
    </section>

    <footer class="site-foot">
      <div class="wrap foot-inner">
        <span class="brand">Sentinel</span>
        <span class="muted">Your security workspace.</span>
        <nav class="foot-links">
          <a href="#features">Features</a>
          <a href="#inside">Inside</a>
          <a href="#get-app">Download</a>
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
