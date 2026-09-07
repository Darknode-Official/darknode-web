const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const DEMO_FS = {
  "/home/darknode": ["Desktop", "Documents", "Downloads", "tools", ".bashrc", ".ssh"],
  "/home/darknode/tools": ["nmap-scan.sh", "recon.py", "wordlists"],
  "/home/darknode/Documents": ["notes.txt", "targets.csv"],
  "/": ["bin", "etc", "home", "root", "tmp", "usr", "var"],
};

const DEMO_CMDS = {
  help: `Available commands:
  help                      Show this message
  ollama list               List installed models
  ollama pull <model>       Download a model (e.g. gpt-oss:120b)
  ollama run <model> <msg>  Chat with a model
  whoami / id / pwd         Identity & location
  ls [dir] / cd <dir>       Navigate (demo filesystem)
  cat <file>                Read a file
  uname -a / hostname       System info
  ifconfig / ps aux         Network & processes
  uptime / date             Timing
  clear / echo <msg>        Utilities

Recommended: ollama pull gpt-oss:120b
Requires Ollama running locally: OLLAMA_ORIGINS=* ollama serve`,
  whoami: "darknode",
  hostname: "darknode-os",
  id: "uid=1000(darknode) gid=1000(darknode) groups=1000(darknode),27(sudo),100(users)",
  "uname -a": "Linux darknode-os 6.1.0-darknode #1 SMP x86_64 GNU/Linux",
  "uname -r": "6.1.0-darknode",
  uptime: () => ` ${new Date().toLocaleTimeString()} up 4:32, 1 user, load average: 0.12, 0.08, 0.05`,
  date: () => new Date().toString(),
  ifconfig: `eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255
        ether 08:00:27:a1:b2:c3  txqueuelen 1000
        RX packets 14832  bytes 18294021 (17.4 MiB)
        TX packets 8421  bytes 942103 (920.0 KiB)`,
  "ps aux": `USER       PID %CPU %MEM    VSZ   RSS TTY   STAT START   TIME COMMAND
root         1  0.0  0.1  16984  4420 ?     Ss   08:00   0:01 /sbin/init
root        42  0.0  0.1  24684  5120 ?     Ss   08:00   0:00 /usr/sbin/sshd
darknode   301  0.0  0.0   8212  3984 pts/0 Ss   08:15   0:00 -bash
darknode   412  0.0  0.0   9440  3124 pts/0 R+   12:47   0:00 ps aux`,
};

export function renderWebshell(main) {
  let ws = null;
  let cwd = "/home/darknode";
  let lines = [];
  let histBuf = [];
  let histIdx = -1;

  const MAX_LINES = 500;

  function addLine(text, cls = "") {
    lines.push({ text, cls });
    if (lines.length > MAX_LINES) lines = lines.slice(-MAX_LINES);
  }

  const OLLAMA = "http://127.0.0.1:11434";

  async function ollamaList() {
    try { const r = await fetch(OLLAMA + "/api/tags"); const d = await r.json(); return (d.models || []).map((m) => m.name); }
    catch (_) { return null; }
  }

  async function ollamaPull(model) {
    addLine(`pulling ${model}...`, "sys"); paint();
    try {
      const r = await fetch(OLLAMA + "/api/pull", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: model, stream: true }) });
      if (!r.ok || !r.body) throw new Error("status " + r.status);
      const reader = r.body.getReader(), dec = new TextDecoder(); let buf = "", lastPct = "";
      for (;;) {
        const { done, value } = await reader.read(); if (done) break;
        buf += dec.decode(value, { stream: true });
        let nl; while ((nl = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1);
          if (!line) continue;
          try { const j = JSON.parse(line); const pct = j.completed && j.total ? Math.round(j.completed / j.total * 100) + "%" : ""; if (pct && pct !== lastPct) { lastPct = pct; addLine(`  ${j.status || "downloading"} ${pct}`, "sys"); paint(); } else if (j.status && !j.completed) { addLine(`  ${j.status}`, "sys"); paint(); } } catch (_) {}
        }
      }
      addLine(`${model} pulled successfully`, "sys");
    } catch (e) { addLine(`pull failed: ${e.message}. Is Ollama running? (OLLAMA_ORIGINS=* ollama serve)`, "err"); }
  }

  async function ollamaRun(model, prompt) {
    if (!prompt) { addLine("usage: ollama run <model> <prompt>", "err"); return; }
    addLine(`[${model}] thinking...`, "sys"); paint();
    try {
      const r = await fetch(OLLAMA + "/api/chat", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ model, messages: [{ role: "user", content: prompt }], stream: true }) });
      if (!r.ok || !r.body) throw new Error("status " + r.status);
      const reader = r.body.getReader(), dec = new TextDecoder(); let buf = "", out = "";
      for (;;) {
        const { done, value } = await reader.read(); if (done) break;
        buf += dec.decode(value, { stream: true });
        let nl; while ((nl = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1);
          if (!line) continue;
          try { const j = JSON.parse(line); if (j.message && j.message.content) out += j.message.content; } catch (_) {}
        }
      }
      addLine(out || "(empty response)");
    } catch (e) { addLine(`error: ${e.message}. Is Ollama running? (OLLAMA_ORIGINS=* ollama serve)`, "err"); }
  }

  async function demoExec(cmd) {
    const parts = cmd.trim().split(/\s+/);
    const base = parts[0];
    if (!base) return;
    if (base === "clear") { lines = []; return; }
    if (base === "echo") { addLine(parts.slice(1).join(" ")); return; }
    if (base === "cd") {
      const target = parts[1] || "/home/darknode";
      if (target === "~") { cwd = "/home/darknode"; }
      else if (target === "..") { cwd = cwd.split("/").slice(0, -1).join("/") || "/"; }
      else if (target.startsWith("/")) { cwd = target; }
      else { cwd = cwd === "/" ? "/" + target : cwd + "/" + target; }
      return;
    }
    if (base === "pwd") { addLine(cwd); return; }
    if (base === "ls") {
      const dir = parts[1] ? (parts[1].startsWith("/") ? parts[1] : cwd + "/" + parts[1]) : cwd;
      const entries = DEMO_FS[dir];
      if (entries) addLine(entries.join("  "));
      else addLine(`ls: cannot access '${esc(parts[1] || dir)}': No such file or directory`, "err");
      return;
    }
    if (base === "cat") {
      if (!parts[1]) { addLine("cat: missing operand", "err"); return; }
      if (parts[1] === ".bashrc" || parts[1] === "/home/darknode/.bashrc") {
        addLine("# ~/.bashrc\nexport PS1='\\[\\e[32m\\]darknode@darknode-os\\[\\e[0m\\]:\\[\\e[34m\\]\\w\\[\\e[0m\\]\\$ '\nalias ll='ls -la'\nalias tools='cd ~/tools'");
      } else if (parts[1] === "notes.txt" || parts[1].endsWith("/notes.txt")) {
        addLine("# Engagement notes\n- Target: 10.10.10.x\n- Scope: full pentest\n- Status: recon phase");
      } else {
        addLine(`cat: ${esc(parts[1])}: No such file or directory`, "err");
      }
      return;
    }
    if (base === "ollama") {
      const sub = parts[1] || "";
      if (sub === "list" || sub === "ls") {
        const ms = await ollamaList();
        if (ms === null) addLine("Ollama not reachable. Start it: OLLAMA_ORIGINS=* ollama serve", "err");
        else if (!ms.length) addLine("No models installed. Try: ollama pull gpt-oss:120b");
        else addLine("NAME\n" + ms.join("\n"));
      } else if (sub === "pull" && parts[2]) {
        await ollamaPull(parts[2]);
      } else if (sub === "run" && parts[2]) {
        await ollamaRun(parts[2], parts.slice(3).join(" "));
      } else {
        addLine("usage:\n  ollama list              list installed models\n  ollama pull <model>      download a model (e.g. gpt-oss:120b)\n  ollama run <model> <msg> chat with a model\n\nRecommended: ollama pull gpt-oss:120b");
      }
      return;
    }
    const full = cmd.trim();
    const entry = DEMO_CMDS[full] || DEMO_CMDS[base];
    if (entry !== undefined) {
      addLine(typeof entry === "function" ? entry() : entry);
    } else {
      addLine(`${esc(base)}: command not found (demo mode)`, "err");
    }
  }

  function paint() {
    const out = main.querySelector("#ws-output");
    const inp = main.querySelector("#ws-input");
    const badge = main.querySelector("#ws-status");
    if (!out) return;
    out.innerHTML = lines.map((l) =>
      `<div class="ws-line${l.cls ? " " + l.cls : ""}">${esc(l.text)}</div>`
    ).join("");
    out.scrollTop = out.scrollHeight;
    if (badge) {
      if (ws && ws.readyState === 1) { badge.textContent = "connected"; badge.className = "ws-badge ok"; }
      else if (ws) { badge.textContent = "connecting..."; badge.className = "ws-badge warn"; }
      else { badge.textContent = "demo mode"; badge.className = "ws-badge demo"; }
    }
  }

  async function send(cmd) {
    if (ws && ws.readyState === 1) {
      addLine(`darknode@darknode-os:${cwd}$ ${cmd}`, "prompt");
      ws.send(cmd);
      histBuf.unshift(cmd);
      histIdx = -1;
    } else {
      addLine(`darknode@darknode-os:${cwd}$ ${cmd}`, "prompt");
      await demoExec(cmd);
      histBuf.unshift(cmd);
      histIdx = -1;
    }
    paint();
  }

  function connect(url) {
    try {
      if (ws) { ws.close(); ws = null; }
      ws = new WebSocket(url);
      ws.onopen = () => { addLine("Connected to " + url, "sys"); paint(); };
      ws.onmessage = (e) => { addLine(String(e.data)); paint(); };
      ws.onerror = () => { addLine("WebSocket error", "err"); paint(); };
      ws.onclose = () => { addLine("Disconnected", "sys"); ws = null; paint(); };
      paint();
    } catch (e) { addLine("Connection failed: " + e.message, "err"); paint(); }
  }

  function disconnect() {
    if (ws) { ws.close(); ws = null; }
    addLine("Disconnected", "sys");
    paint();
  }

  main.innerHTML = `
    <style>
      .ws-wrap{display:flex;flex-direction:column;height:calc(100vh - var(--topbar-h) - 40px);min-height:400px}
      .ws-bar{display:flex;gap:8px;align-items:center;padding:10px 14px;background:var(--card);border:1px solid var(--line);border-radius:var(--radius) var(--radius) 0 0;flex:none}
      .ws-bar input{flex:1;background:var(--bg);border:1px solid var(--line);color:var(--txt);padding:6px 10px;border-radius:4px;font-family:var(--font-mono);font-size:.8rem}
      .ws-bar button{background:var(--acc);color:#000;border:none;padding:6px 14px;border-radius:4px;font-weight:600;cursor:pointer;font-size:.78rem;white-space:nowrap}
      .ws-bar button.dc{background:var(--bad)}
      .ws-badge{font-size:.7rem;font-weight:600;padding:2px 8px;border-radius:10px;white-space:nowrap}
      .ws-badge.ok{background:rgba(46,230,166,.15);color:var(--ok)}
      .ws-badge.warn{background:rgba(245,176,65,.15);color:var(--warn)}
      .ws-badge.demo{background:rgba(124,92,255,.15);color:var(--acc-2)}
      .ws-badge.off{background:rgba(255,92,108,.12);color:var(--bad)}
      .ws-term{flex:1;background:#0a0c10;border-left:1px solid var(--line);border-right:1px solid var(--line);overflow:hidden;display:flex;flex-direction:column;position:relative}
      #ws-output{flex:1;overflow-y:auto;padding:12px 14px;font-family:var(--font-mono);font-size:.82rem;line-height:1.55;color:#c8d6e5;white-space:pre-wrap;word-break:break-all}
      #ws-output::-webkit-scrollbar{width:6px}#ws-output::-webkit-scrollbar-thumb{background:#2a3a55;border-radius:3px}
      .ws-line{min-height:1.2em}
      .ws-line.prompt{color:#2ee6a6}
      .ws-line.err{color:#ff5c6c}
      .ws-line.sys{color:#6f88ab;font-style:italic}
      .ws-input-row{display:flex;gap:0;border-top:1px solid #1e2a44;background:#080a0f;flex:none}
      .ws-prompt-label{padding:8px 0 8px 14px;color:#2ee6a6;font-family:var(--font-mono);font-size:.82rem;white-space:nowrap;flex:none}
      #ws-input{flex:1;background:transparent;border:none;color:#e6eefc;font-family:var(--font-mono);font-size:.82rem;padding:8px 14px 8px 6px;outline:none;caret-color:var(--acc)}
      .ws-foot{padding:8px 14px;background:var(--card);border:1px solid var(--line);border-radius:0 0 var(--radius) var(--radius);border-top:none;font-size:.72rem;color:var(--mut);flex:none}
      .ws-glow{text-shadow:0 0 6px rgba(46,230,166,.25)}
    </style>
    <h1 class="pg-h1">Web Shell</h1>
    <p class="muted pg-sub">Connect to your Darknode OS instance or use demo mode to explore.</p>
    <div class="ws-wrap">
      <div class="ws-bar">
        <span id="ws-status" class="ws-badge demo">demo mode</span>
        <input id="ws-url" value="ws://localhost:8765" placeholder="ws://host:port" spellcheck="false">
        <button id="ws-conn">Connect</button>
        <button id="ws-disc" class="dc" style="display:none">Disconnect</button>
      </div>
      <div class="ws-term">
        <div id="ws-output" class="ws-glow"></div>
        <div class="ws-input-row">
          <span class="ws-prompt-label ws-glow">darknode@darknode-os:~$&nbsp;</span>
          <input id="ws-input" spellcheck="false" autocomplete="off" autofocus placeholder="type a command...">
        </div>
      </div>
      <div class="ws-foot">Tab for history &middot; Enter to send &middot; Connect to a live instance for full access &middot; Demo mode supports basic commands</div>
    </div>`;

  addLine("DARKNODE OS Web Shell v1.0", "sys");
  addLine('Type "help" for available commands. Connect to a live instance for full shell access.', "sys");
  addLine("", "");
  paint();

  const inp = main.querySelector("#ws-input");
  const connBtn = main.querySelector("#ws-conn");
  const discBtn = main.querySelector("#ws-disc");
  const urlInput = main.querySelector("#ws-url");

  inp.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      const v = inp.value; inp.value = ""; send(v);
      main.querySelector(".ws-prompt-label").innerHTML = `<span class="ws-glow">darknode@darknode-os:${esc(cwd)}$&nbsp;</span>`;
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (histBuf.length) { histIdx = Math.min(histIdx + 1, histBuf.length - 1); inp.value = histBuf[histIdx] || ""; }
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (histIdx > 0) { histIdx--; inp.value = histBuf[histIdx] || ""; }
      else { histIdx = -1; inp.value = ""; }
    }
  });

  connBtn.onclick = () => { connect(urlInput.value.trim()); connBtn.style.display = "none"; discBtn.style.display = ""; };
  discBtn.onclick = () => { disconnect(); discBtn.style.display = "none"; connBtn.style.display = ""; };
}
