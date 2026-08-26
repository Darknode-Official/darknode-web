const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const EDITIONS = [
  { id: "full", name: "Full", size: "~30 GB", desc: "XFCE desktop, Sentinel app, Nexus CLI, all tools", icon: "⭐" },
  { id: "slim", name: "Slim", size: "~20 GB", desc: "XFCE desktop, core tools, no heavy packages", icon: "⚡" },
  { id: "netinstall", name: "Netinstall", size: "~12 GB", desc: "Terminal only, minimal footprint", icon: "⌘" },
];

const FEATURES = [
  ["Pre-installed tools", "nmap, Hydra, Metasploit, Burp, SQLmap, and 40+ more"],
  ["XFCE desktop", "Lightweight themed desktop (Slim & Full editions)"],
  ["Nexus CLI", "AI-powered coding agent built in"],
  ["Sentinel app", "Full GUI toolkit launcher (Full edition)"],
  ["Cloud-init ready", "Customize on first boot via user-data"],
  ["VNC support", "Access the desktop from your browser"],
];

export function renderVMLab(main) {
  let connected = false;

  main.innerHTML = `
    <style>
      .vl-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin:18px 0}
      @media(max-width:800px){.vl-grid{grid-template-columns:1fr}}
      .vl-card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);padding:18px;transition:border-color .2s}
      .vl-card:hover{border-color:var(--acc)}
      .vl-card h3{margin:0 0 6px;font-size:.95rem;color:var(--txt)}
      .vl-card p{margin:0;font-size:.78rem;color:var(--mut);line-height:1.5}
      .vl-card .vl-size{font-size:.7rem;color:var(--acc);font-weight:600;margin-top:6px}
      .vl-viewer{background:#0a0c10;border:1px solid var(--line);border-radius:var(--radius);min-height:420px;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:14px;position:relative;overflow:hidden;margin:18px 0}
      .vl-logo{font-size:3rem;opacity:.3;user-select:none}
      .vl-placeholder{color:var(--mut);font-size:.85rem;text-align:center;max-width:400px;line-height:1.6}
      .vl-conn{display:flex;gap:8px;align-items:center;padding:10px 14px;background:var(--card);border:1px solid var(--line);border-radius:var(--radius);margin:14px 0;flex-wrap:wrap}
      .vl-conn label{font-size:.75rem;color:var(--mut);white-space:nowrap}
      .vl-conn input{background:var(--bg);border:1px solid var(--line);color:var(--txt);padding:6px 10px;border-radius:4px;font-family:var(--font-mono);font-size:.8rem;width:140px}
      .vl-conn button{background:var(--acc);color:#000;border:none;padding:6px 16px;border-radius:4px;font-weight:600;cursor:pointer;font-size:.78rem}
      .vl-conn button.sec{background:var(--card2);color:var(--txt);border:1px solid var(--line)}
      .vl-badge{font-size:.7rem;font-weight:600;padding:2px 8px;border-radius:10px}
      .vl-badge.off{background:rgba(255,92,108,.12);color:var(--bad)}
      .vl-badge.on{background:rgba(46,230,166,.15);color:var(--ok)}
      .vl-steps{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);padding:18px;margin:14px 0}
      .vl-steps h3{margin:0 0 10px;font-size:.9rem;color:var(--txt)}
      .vl-steps pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:14px;font-family:var(--font-mono);font-size:.78rem;color:var(--txt-2);overflow-x:auto;line-height:1.6;white-space:pre;margin:8px 0}
      .vl-steps .vl-comment{color:var(--mut)}
      .vl-feat{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px;margin:14px 0}
      .vl-feat-item{display:flex;gap:10px;padding:10px 14px;background:var(--card);border:1px solid var(--line);border-radius:var(--radius)}
      .vl-feat-icon{color:var(--acc);font-size:1.1rem;flex:none;width:24px;text-align:center}
      .vl-feat-text h4{margin:0;font-size:.82rem;color:var(--txt)}
      .vl-feat-text p{margin:2px 0 0;font-size:.72rem;color:var(--mut)}
      .vl-creds{display:inline-block;background:var(--bg);border:1px solid var(--line);border-radius:4px;padding:3px 10px;font-family:var(--font-mono);font-size:.78rem;color:var(--ok);margin:4px 0}
    </style>
    <h1 class="pg-h1">VM Lab</h1>
    <p class="muted pg-sub">Launch and access your Sentinel OS virtual machine from the browser.</p>

    <div class="vl-conn">
      <span id="vl-status" class="vl-badge off">disconnected</span>
      <label>Host</label>
      <input id="vl-host" value="localhost" spellcheck="false">
      <label>Port</label>
      <input id="vl-port" value="6080" spellcheck="false" style="width:70px">
      <button id="vl-open">Launch VM Viewer</button>
      <button id="vl-vnc" class="sec">Open noVNC</button>
    </div>

    <div class="vl-viewer" id="vl-viewer">
      <div class="vl-logo">██ SENTINEL OS</div>
      <div class="vl-placeholder">
        Start your VM with VNC enabled, then connect.<br>
        The viewer opens in a new tab via noVNC / websockify.
      </div>
      <div class="vl-placeholder" style="font-size:.75rem">
        Default credentials: <span class="vl-creds">sentinel / sentinel</span>
      </div>
    </div>

    <div class="vl-steps">
      <h3>Quick start</h3>
      <pre><span class="vl-comment"># 1. Start the VM with VNC enabled</span>
./launch.sh --vnc

<span class="vl-comment"># Or with QEMU directly</span>
qemu-system-x86_64 \\
  -m 4096 -smp 2 \\
  -drive file=sentinel-os.qcow2,format=qcow2 \\
  -vnc :0 -display none \\
  -net nic -net user,hostfwd=tcp::2222-:22

<span class="vl-comment"># 2. Install and start websockify (bridges VNC to WebSocket)</span>
pip install websockify
websockify 6080 localhost:5900

<span class="vl-comment"># 3. Click "Launch VM Viewer" above</span></pre>
    </div>

    <h2 class="pg-h2" style="margin:24px 0 12px">Editions</h2>
    <div class="vl-grid">
      ${EDITIONS.map((e) => `
        <div class="vl-card">
          <h3>${e.icon} ${esc(e.name)}</h3>
          <p>${esc(e.desc)}</p>
          <div class="vl-size">${esc(e.size)}</div>
        </div>
      `).join("")}
    </div>

    <h2 class="pg-h2" style="margin:24px 0 12px">Features</h2>
    <div class="vl-feat">
      ${FEATURES.map(([title, desc]) => `
        <div class="vl-feat-item">
          <div class="vl-feat-icon">◆</div>
          <div class="vl-feat-text"><h4>${esc(title)}</h4><p>${esc(desc)}</p></div>
        </div>
      `).join("")}
    </div>`;

  const hostInput = main.querySelector("#vl-host");
  const portInput = main.querySelector("#vl-port");

  main.querySelector("#vl-open").onclick = () => {
    const h = hostInput.value.trim() || "localhost";
    const p = portInput.value.trim() || "6080";
    window.open(`http://${esc(h)}:${esc(p)}/vnc.html?autoconnect=true`, "_blank");
  };

  main.querySelector("#vl-vnc").onclick = () => {
    const h = hostInput.value.trim() || "localhost";
    const p = portInput.value.trim() || "6080";
    window.open(`http://${esc(h)}:${esc(p)}`, "_blank");
  };

  // Probe the websockify endpoint to show connection status
  function probe() {
    const h = hostInput.value.trim() || "localhost";
    const p = portInput.value.trim() || "6080";
    const badge = main.querySelector("#vl-status");
    try {
      const ws = new WebSocket(`ws://${h}:${p}`);
      ws.onopen = () => { badge.textContent = "VM reachable"; badge.className = "vl-badge on"; ws.close(); };
      ws.onerror = () => { badge.textContent = "disconnected"; badge.className = "vl-badge off"; };
      setTimeout(() => { try { ws.close(); } catch (_) {} }, 3000);
    } catch (_) { badge.textContent = "disconnected"; badge.className = "vl-badge off"; }
  }
  probe();
  hostInput.onchange = probe;
  portInput.onchange = probe;
}
