var esc = function(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function(c) {
  return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];
}); };

var DEMO_FS = {
  "/home/darknode": ["Desktop", "Documents", "Downloads", "tools", ".bashrc", ".ssh"],
  "/home/darknode/tools": ["nmap-scan.sh", "recon.py", "wordlists"],
  "/home/darknode/Documents": ["notes.txt", "targets.csv"],
  "/": ["bin", "etc", "home", "root", "tmp", "usr", "var"],
};

var DEMO_CMDS = {
  help: "Available commands:\n" +
    "  help                      Show this message\n" +
    "  ollama list               List installed models\n" +
    "  ollama pull <model>       Download a model (e.g. gpt-oss:120b)\n" +
    "  ollama run <model> <msg>  Chat with a model\n" +
    "  whoami / id / pwd         Identity & location\n" +
    "  ls [dir] / cd <dir>       Navigate (demo filesystem)\n" +
    "  cat <file>                Read a file\n" +
    "  uname -a / hostname       System info\n" +
    "  ifconfig / ps aux         Network & processes\n" +
    "  uptime / date             Timing\n" +
    "  clear / echo <msg>        Utilities\n" +
    "\nRecommended: ollama pull gpt-oss:120b\n" +
    "Requires Ollama running locally: OLLAMA_ORIGINS=* ollama serve",
  whoami: "darknode",
  hostname: "darknode-os",
  id: "uid=1000(darknode) gid=1000(darknode) groups=1000(darknode),27(sudo),100(users)",
  "uname -a": "Linux darknode-os 6.1.0-darknode #1 SMP x86_64 GNU/Linux",
  "uname -r": "6.1.0-darknode",
  uptime: function() { return " " + new Date().toLocaleTimeString() + " up 4:32, 1 user, load average: 0.12, 0.08, 0.05"; },
  date: function() { return new Date().toString(); },
  ifconfig: "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n" +
    "        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\n" +
    "        ether 08:00:27:a1:b2:c3  txqueuelen 1000\n" +
    "        RX packets 14832  bytes 18294021 (17.4 MiB)\n" +
    "        TX packets 8421  bytes 942103 (920.0 KiB)",
  "ps aux": "USER       PID %CPU %MEM    VSZ   RSS TTY   STAT START   TIME COMMAND\n" +
    "root         1  0.0  0.1  16984  4420 ?     Ss   08:00   0:01 /sbin/init\n" +
    "root        42  0.0  0.1  24684  5120 ?     Ss   08:00   0:00 /usr/sbin/sshd\n" +
    "darknode   301  0.0  0.0   8212  3984 pts/0 Ss   08:15   0:00 -bash\n" +
    "darknode   412  0.0  0.0   9440  3124 pts/0 R+   12:47   0:00 ps aux",
};

/* ------------------------------------------------------------------
   ANSI color code parser — converts basic SGR codes to HTML spans
   Supports: 30-37 (fg), 1 (bold), 0 (reset), 90-97 (bright)
   ------------------------------------------------------------------ */
var ANSI_COLORS = {
  "30": "#1a1a2e", "31": "#ff5c6c", "32": "#2ee6a6", "33": "#f5b041",
  "34": "#5dade2", "35": "#bb86fc", "36": "#56d7e5", "37": "#c8d6e5",
  "90": "#6f88ab", "91": "#ff7b8a", "92": "#5effc4", "93": "#ffd76e",
  "94": "#82c8ff", "95": "#d4a5ff", "96": "#7ef0f7", "97": "#f2f5f9"
};

function parseAnsi(raw) {
  var result = "";
  var openSpans = 0;
  var i = 0;
  var text = String(raw);
  while (i < text.length) {
    if (text.charCodeAt(i) === 27 && text.charAt(i + 1) === "[") {
      var end = text.indexOf("m", i + 2);
      if (end === -1) { result += esc(text.charAt(i)); i++; continue; }
      var codes = text.substring(i + 2, end).split(";");
      i = end + 1;
      var style = "";
      for (var ci = 0; ci < codes.length; ci++) {
        var code = codes[ci];
        if (code === "0" || code === "") {
          while (openSpans > 0) { result += "</span>"; openSpans--; }
        } else if (code === "1") {
          style += "font-weight:bold;";
        } else if (ANSI_COLORS[code]) {
          style += "color:" + ANSI_COLORS[code] + ";";
        }
      }
      if (style) { result += '<span style="' + style + '">'; openSpans++; }
    } else {
      result += esc(text.charAt(i));
      i++;
    }
  }
  while (openSpans > 0) { result += "</span>"; openSpans--; }
  return result;
}

/* ------------------------------------------------------------------
   Main shell renderer
   ------------------------------------------------------------------ */
export function renderWebshell(main) {
  var ws = null;
  var cwd = "/home/darknode";
  var lines = [];
  var histBuf = [];
  var histIdx = -1;
  var MAX_LINES = 500;
  var reconnectTimer = null;
  var reconnectAttempts = 0;
  var MAX_RECONNECT = 5;
  var RECONNECT_DELAY = 3000;
  var connHost = "localhost";
  var connPort = "8765";

  /* Determine saved shell mode */
  var shellMode = "education";
  try { shellMode = localStorage.getItem("dn_shell_mode") || "education"; } catch (_) {}
  if (shellMode !== "real") shellMode = "education";

  function addLine(text, cls) {
    lines.push({ text: text, cls: cls || "" });
    if (lines.length > MAX_LINES) lines = lines.slice(-MAX_LINES);
  }

  function addAnsiLine(text) {
    lines.push({ html: parseAnsi(text), cls: "ansi" });
    if (lines.length > MAX_LINES) lines = lines.slice(-MAX_LINES);
  }

  /* ---- Ollama integration (education mode) ---- */
  var OLLAMA = "http://127.0.0.1:11434";

  function ollamaList() {
    return fetch(OLLAMA + "/api/tags").then(function(r) { return r.json(); }).then(function(d) {
      return (d.models || []).map(function(m) { return m.name; });
    }).catch(function() { return null; });
  }

  function ollamaPull(model) {
    addLine("pulling " + model + "...", "sys"); paint();
    return fetch(OLLAMA + "/api/pull", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: model, stream: true })
    }).then(function(r) {
      if (!r.ok || !r.body) throw new Error("status " + r.status);
      var reader = r.body.getReader();
      var dec = new TextDecoder();
      var buf = "";
      var lastPct = "";
      function readChunk() {
        return reader.read().then(function(chunk) {
          if (chunk.done) { addLine(model + " pulled successfully", "sys"); return; }
          buf += dec.decode(chunk.value, { stream: true });
          var nl;
          while ((nl = buf.indexOf("\n")) >= 0) {
            var line = buf.slice(0, nl).trim();
            buf = buf.slice(nl + 1);
            if (!line) continue;
            try {
              var j = JSON.parse(line);
              var pct = j.completed && j.total ? Math.round(j.completed / j.total * 100) + "%" : "";
              if (pct && pct !== lastPct) { lastPct = pct; addLine("  " + (j.status || "downloading") + " " + pct, "sys"); paint(); }
              else if (j.status && !j.completed) { addLine("  " + j.status, "sys"); paint(); }
            } catch (_) {}
          }
          return readChunk();
        });
      }
      return readChunk();
    }).catch(function(e) {
      addLine("pull failed: " + e.message + ". Is Ollama running? (OLLAMA_ORIGINS=* ollama serve)", "err");
    });
  }

  function ollamaRun(model, prompt) {
    if (!prompt) { addLine("usage: ollama run <model> <prompt>", "err"); return Promise.resolve(); }
    addLine("[" + model + "] thinking...", "sys"); paint();
    return fetch(OLLAMA + "/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model: model, messages: [{ role: "user", content: prompt }], stream: true })
    }).then(function(r) {
      if (!r.ok || !r.body) throw new Error("status " + r.status);
      var reader = r.body.getReader();
      var dec = new TextDecoder();
      var buf = "";
      var out = "";
      function readChunk() {
        return reader.read().then(function(chunk) {
          if (chunk.done) { addLine(out || "(empty response)"); return; }
          buf += dec.decode(chunk.value, { stream: true });
          var nl;
          while ((nl = buf.indexOf("\n")) >= 0) {
            var line = buf.slice(0, nl).trim();
            buf = buf.slice(nl + 1);
            if (!line) continue;
            try { var j = JSON.parse(line); if (j.message && j.message.content) out += j.message.content; } catch (_) {}
          }
          return readChunk();
        });
      }
      return readChunk();
    }).catch(function(e) {
      addLine("error: " + e.message + ". Is Ollama running? (OLLAMA_ORIGINS=* ollama serve)", "err");
    });
  }

  /* ---- Demo exec for education mode ---- */
  function demoExec(cmd) {
    var parts = cmd.trim().split(/\s+/);
    var base = parts[0];
    if (!base) return Promise.resolve();
    if (base === "clear") { lines = []; return Promise.resolve(); }
    if (base === "echo") { addLine(parts.slice(1).join(" ")); return Promise.resolve(); }
    if (base === "cd") {
      var target = parts[1] || "/home/darknode";
      if (target === "~") { cwd = "/home/darknode"; }
      else if (target === "..") { cwd = cwd.split("/").slice(0, -1).join("/") || "/"; }
      else if (target.startsWith("/")) { cwd = target; }
      else { cwd = cwd === "/" ? "/" + target : cwd + "/" + target; }
      return Promise.resolve();
    }
    if (base === "pwd") { addLine(cwd); return Promise.resolve(); }
    if (base === "ls") {
      var dir = parts[1] ? (parts[1].startsWith("/") ? parts[1] : cwd + "/" + parts[1]) : cwd;
      var entries = DEMO_FS[dir];
      if (entries) addLine(entries.join("  "));
      else addLine("ls: cannot access '" + esc(parts[1] || dir) + "': No such file or directory", "err");
      return Promise.resolve();
    }
    if (base === "cat") {
      if (!parts[1]) { addLine("cat: missing operand", "err"); return Promise.resolve(); }
      if (parts[1] === ".bashrc" || parts[1] === "/home/darknode/.bashrc") {
        addLine("# ~/.bashrc\nexport PS1='\\[\\e[32m\\]darknode@darknode-os\\[\\e[0m\\]:\\[\\e[34m\\]\\w\\[\\e[0m\\]\\$ '\nalias ll='ls -la'\nalias tools='cd ~/tools'");
      } else if (parts[1] === "notes.txt" || parts[1].endsWith("/notes.txt")) {
        addLine("# Engagement notes\n- Target: 10.10.10.x\n- Scope: full pentest\n- Status: recon phase");
      } else {
        addLine("cat: " + esc(parts[1]) + ": No such file or directory", "err");
      }
      return Promise.resolve();
    }
    if (base === "ollama") {
      var sub = parts[1] || "";
      if (sub === "list" || sub === "ls") {
        return ollamaList().then(function(ms) {
          if (ms === null) addLine("Ollama not reachable. Start it: OLLAMA_ORIGINS=* ollama serve", "err");
          else if (!ms.length) addLine("No models installed. Try: ollama pull gpt-oss:120b");
          else addLine("NAME\n" + ms.join("\n"));
        });
      } else if (sub === "pull" && parts[2]) {
        return ollamaPull(parts[2]);
      } else if (sub === "run" && parts[2]) {
        return ollamaRun(parts[2], parts.slice(3).join(" "));
      } else {
        addLine("usage:\n  ollama list              list installed models\n  ollama pull <model>      download a model (e.g. gpt-oss:120b)\n  ollama run <model> <msg> chat with a model\n\nRecommended: ollama pull gpt-oss:120b");
        return Promise.resolve();
      }
    }
    var full = cmd.trim();
    var entry = DEMO_CMDS[full] || DEMO_CMDS[base];
    if (entry !== undefined) {
      addLine(typeof entry === "function" ? entry() : entry);
    } else {
      addLine(esc(base) + ": command not found (education mode)", "err");
    }
    return Promise.resolve();
  }

  /* ---- Connection status helpers ---- */
  function getConnState() {
    if (ws && ws.readyState === WebSocket.OPEN) return "connected";
    if (ws && ws.readyState === WebSocket.CONNECTING) return "connecting";
    return "disconnected";
  }

  function promptStr() {
    if (shellMode === "real" && getConnState() === "connected") {
      return "darknode@live:" + esc(cwd) + "$";
    }
    return "darknode@darknode-os:" + esc(cwd) + "$";
  }

  /* ---- Render ---- */
  function paint() {
    var out = main.querySelector("#ws-output");
    var inp = main.querySelector("#ws-input");
    if (!out) return;
    out.innerHTML = lines.map(function(l) {
      if (l.html) return '<div class="ws-line ' + l.cls + '">' + l.html + '</div>';
      return '<div class="ws-line' + (l.cls ? " " + l.cls : "") + '">' + esc(l.text) + '</div>';
    }).join("");
    out.scrollTop = out.scrollHeight;

    /* Update status badge */
    var badge = main.querySelector("#ws-status");
    if (badge) {
      if (shellMode === "education") {
        badge.textContent = "Education Mode";
        badge.className = "ws-badge demo";
      } else if (getConnState() === "connected") {
        badge.textContent = "Connected";
        badge.className = "ws-badge ok";
      } else if (getConnState() === "connecting") {
        badge.textContent = "Connecting...";
        badge.className = "ws-badge warn";
      } else {
        badge.textContent = "Disconnected";
        badge.className = "ws-badge off";
      }
    }

    /* Update prompt label */
    var label = main.querySelector(".ws-prompt-label");
    if (label) label.innerHTML = '<span class="ws-glow">' + promptStr() + '&nbsp;</span>';

    /* Update mode toggle highlights */
    var edBtn = main.querySelector("#ws-mode-edu");
    var realBtn = main.querySelector("#ws-mode-real");
    if (edBtn) edBtn.classList.toggle("active", shellMode === "education");
    if (realBtn) realBtn.classList.toggle("active", shellMode === "real");

    /* Show/hide connection panel */
    var cp = main.querySelector("#ws-conn-panel");
    if (cp) cp.style.display = shellMode === "real" ? "" : "none";

    /* Update connection panel state */
    if (shellMode === "real") {
      var connBtn = main.querySelector("#ws-conn");
      var discBtn = main.querySelector("#ws-disc");
      var hostIn = main.querySelector("#ws-host");
      var portIn = main.querySelector("#ws-port");
      if (getConnState() === "connected") {
        if (connBtn) connBtn.style.display = "none";
        if (discBtn) discBtn.style.display = "";
        if (hostIn) hostIn.disabled = true;
        if (portIn) portIn.disabled = true;
      } else {
        if (connBtn) { connBtn.style.display = ""; connBtn.disabled = getConnState() === "connecting"; }
        if (discBtn) discBtn.style.display = "none";
        if (hostIn) hostIn.disabled = false;
        if (portIn) portIn.disabled = false;
      }
    }
  }

  /* ---- WebSocket connection ---- */
  function clearReconnect() {
    if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
    reconnectAttempts = 0;
  }

  function scheduleReconnect() {
    if (reconnectAttempts >= MAX_RECONNECT) {
      addLine("Max reconnect attempts reached. Click Connect to retry.", "err");
      paint();
      return;
    }
    var delay = RECONNECT_DELAY * Math.pow(1.5, reconnectAttempts);
    reconnectAttempts++;
    addLine("Reconnecting in " + Math.round(delay / 1000) + "s (attempt " + reconnectAttempts + "/" + MAX_RECONNECT + ")...", "sys");
    paint();
    reconnectTimer = setTimeout(function() {
      reconnectTimer = null;
      connectWs();
    }, delay);
  }

  function connectWs() {
    var hostIn = main.querySelector("#ws-host");
    var portIn = main.querySelector("#ws-port");
    if (hostIn) connHost = hostIn.value.trim() || "localhost";
    if (portIn) connPort = portIn.value.trim() || "8765";
    var url = "ws://" + connHost + ":" + connPort;

    if (ws) { try { ws.close(); } catch (_) {} ws = null; }

    addLine("Connecting to " + url + "...", "sys");
    paint();

    try {
      ws = new WebSocket(url);
    } catch (e) {
      addLine("Connection failed: " + e.message, "err");
      paint();
      return;
    }

    ws.onopen = function() {
      clearReconnect();
      addLine("Connected to Darknode Shell Server at " + url, "sys");
      addLine("You are now executing real commands on your machine.", "sys");
      addLine("Type commands as you would in a normal terminal.", "sys");
      addLine("", "");
      paint();
    };

    ws.onmessage = function(e) {
      try {
        var msg = JSON.parse(e.data);
        if (msg.type === "output" && msg.data !== undefined) {
          var outputLines = String(msg.data).split("\n");
          for (var oi = 0; oi < outputLines.length; oi++) {
            addAnsiLine(outputLines[oi]);
          }
        } else if (msg.type === "error" && msg.data !== undefined) {
          var errLines = String(msg.data).split("\n");
          for (var ei = 0; ei < errLines.length; ei++) {
            addLine(errLines[ei], "err");
          }
        } else if (msg.type === "cwd" && msg.data) {
          cwd = msg.data;
        } else if (msg.type === "exit_code" && msg.data !== undefined) {
          if (parseInt(msg.data, 10) !== 0) {
            addLine("(exit code: " + msg.data + ")", "sys");
          }
        } else if (msg.type === "info" && msg.data) {
          addLine(msg.data, "sys");
        } else {
          /* Raw text fallback */
          addAnsiLine(String(e.data));
        }
      } catch (_) {
        /* Not JSON — treat as raw text */
        addAnsiLine(String(e.data));
      }
      paint();
    };

    ws.onerror = function() {
      addLine("WebSocket error", "err");
      paint();
    };

    ws.onclose = function(ev) {
      ws = null;
      var reason = ev.reason ? " (" + ev.reason + ")" : "";
      addLine("Disconnected from server" + reason, "sys");
      paint();
      if (shellMode === "real") {
        scheduleReconnect();
      }
    };

    paint();
  }

  function disconnectWs() {
    clearReconnect();
    if (ws) { try { ws.close(); } catch (_) {} ws = null; }
    addLine("Disconnected", "sys");
    paint();
  }

  /* ---- Command dispatch ---- */
  function send(cmd) {
    if (!cmd.trim()) return Promise.resolve();

    histBuf.unshift(cmd);
    if (histBuf.length > 200) histBuf = histBuf.slice(0, 200);
    histIdx = -1;

    /* Real mode + connected: send via WebSocket */
    if (shellMode === "real" && ws && ws.readyState === WebSocket.OPEN) {
      addLine(promptStr() + " " + cmd, "prompt");

      /* Handle local shell builtins */
      if (cmd.trim() === "clear") {
        lines = [];
        paint();
        return Promise.resolve();
      }

      ws.send(JSON.stringify({ type: "exec", cmd: cmd }));
      paint();
      return Promise.resolve();
    }

    /* Education mode or disconnected */
    addLine(promptStr() + " " + cmd, "prompt");
    return demoExec(cmd).then(function() { paint(); });
  }

  /* ---- Set mode ---- */
  function setMode(mode) {
    shellMode = mode;
    try { localStorage.setItem("dn_shell_mode", mode); } catch (_) {}

    if (mode === "education") {
      disconnectWs();
      addLine("", "");
      addLine("Switched to Education Mode", "sys");
      addLine("Using simulated filesystem. Type 'help' for available commands.", "sys");
    } else {
      addLine("", "");
      addLine("Switched to Real Terminal Mode", "sys");
      addLine("Configure host and port, then click Connect.", "sys");
      addLine("Run 'darknode-agent serve' on your machine to start the shell server.", "sys");
    }
    paint();
  }

  /* ================================================================
     BUILD UI
     ================================================================ */
  main.innerHTML =
    '<style>' +
    '.ws-wrap{display:flex;flex-direction:column;height:calc(100vh - var(--topbar-h) - 40px);min-height:460px}' +
    '.ws-mode-bar{display:flex;gap:0;align-items:center;padding:8px 14px;background:var(--card);border:1px solid var(--line);border-radius:var(--radius) var(--radius) 0 0;flex:none}' +
    '.ws-mode-btn{background:transparent;border:1px solid var(--line);color:var(--mut);padding:6px 16px;font-family:var(--font-mono);font-size:.78rem;cursor:pointer;font-weight:600;transition:all .2s}' +
    '.ws-mode-btn:first-child{border-radius:4px 0 0 4px}' +
    '.ws-mode-btn:last-child{border-radius:0 4px 4px 0;border-left:none}' +
    '.ws-mode-btn.active{background:var(--acc);color:#000;border-color:var(--acc)}' +
    '.ws-mode-btn:hover:not(.active){background:rgba(124,92,255,.08);color:var(--txt)}' +
    '.ws-status-area{margin-left:auto;display:flex;align-items:center;gap:10px}' +
    '.ws-conn-panel{display:flex;gap:8px;align-items:center;padding:8px 14px;background:var(--card);border-left:1px solid var(--line);border-right:1px solid var(--line);flex:none;flex-wrap:wrap}' +
    '.ws-conn-panel label{font-size:.72rem;color:var(--mut);font-weight:600;text-transform:uppercase;letter-spacing:.04em}' +
    '.ws-conn-panel input{background:var(--bg);border:1px solid var(--line);color:var(--txt);padding:5px 8px;border-radius:4px;font-family:var(--font-mono);font-size:.78rem;width:120px}' +
    '.ws-conn-panel input.port-in{width:60px}' +
    '.ws-conn-panel button{padding:5px 14px;border-radius:4px;font-weight:600;cursor:pointer;font-size:.76rem;border:none;white-space:nowrap}' +
    '.ws-conn-btn{background:var(--acc);color:#000}' +
    '.ws-conn-btn:hover{opacity:.85}' +
    '.ws-conn-btn:disabled{opacity:.5;cursor:not-allowed}' +
    '.ws-disc-btn{background:var(--bad);color:#fff}' +
    '.ws-disc-btn:hover{opacity:.85}' +
    '.ws-conn-hint{font-size:.7rem;color:var(--mut);font-style:italic;flex-basis:100%;margin-top:2px}' +
    '.ws-badge{font-size:.7rem;font-weight:600;padding:2px 8px;border-radius:10px;white-space:nowrap}' +
    '.ws-badge.ok{background:rgba(46,230,166,.15);color:var(--ok)}' +
    '.ws-badge.warn{background:rgba(245,176,65,.15);color:var(--warn)}' +
    '.ws-badge.demo{background:rgba(124,92,255,.15);color:var(--acc-2)}' +
    '.ws-badge.off{background:rgba(255,92,108,.12);color:var(--bad)}' +
    '.ws-term{flex:1;background:#0a0e14;border-left:1px solid var(--line);border-right:1px solid var(--line);overflow:hidden;display:flex;flex-direction:column;position:relative}' +
    '#ws-output{flex:1;overflow-y:auto;padding:12px 14px;font-family:var(--font-mono);font-size:.82rem;line-height:1.55;color:#c8d6e5;white-space:pre-wrap;word-break:break-all}' +
    '#ws-output::-webkit-scrollbar{width:6px}' +
    '#ws-output::-webkit-scrollbar-thumb{background:#2a3a55;border-radius:3px}' +
    '#ws-output::-webkit-scrollbar-track{background:transparent}' +
    '.ws-line{min-height:1.2em}' +
    '.ws-line.prompt{color:#2ee6a6}' +
    '.ws-line.err{color:#ff5c6c}' +
    '.ws-line.sys{color:#6f88ab;font-style:italic}' +
    '.ws-line.ansi{}' +
    '.ws-input-row{display:flex;gap:0;border-top:1px solid #1e2a44;background:#080a0f;flex:none}' +
    '.ws-prompt-label{padding:8px 0 8px 14px;color:#2ee6a6;font-family:var(--font-mono);font-size:.82rem;white-space:nowrap;flex:none}' +
    '#ws-input{flex:1;background:transparent;border:none;color:#e6eefc;font-family:var(--font-mono);font-size:.82rem;padding:8px 14px 8px 6px;outline:none;caret-color:var(--acc)}' +
    '.ws-foot{padding:8px 14px;background:var(--card);border:1px solid var(--line);border-radius:0 0 var(--radius) var(--radius);border-top:none;font-size:.72rem;color:var(--mut);flex:none;display:flex;gap:16px;flex-wrap:wrap}' +
    '.ws-foot kbd{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);padding:1px 5px;border-radius:3px;font-family:var(--font-mono);font-size:.7rem}' +
    '.ws-glow{text-shadow:0 0 6px rgba(46,230,166,.25)}' +
    '</style>' +
    '<h1 class="pg-h1">Web Shell</h1>' +
    '<p class="muted pg-sub">Execute commands in a sandboxed demo or connect to your own machine via the Darknode Shell Server.</p>' +
    '<div class="ws-wrap">' +

    /* Mode toggle bar */
    '<div class="ws-mode-bar">' +
      '<button class="ws-mode-btn' + (shellMode === "education" ? " active" : "") + '" id="ws-mode-edu">Education</button>' +
      '<button class="ws-mode-btn' + (shellMode === "real" ? " active" : "") + '" id="ws-mode-real">Real Terminal</button>' +
      '<div class="ws-status-area">' +
        '<span id="ws-status" class="ws-badge demo">Education Mode</span>' +
      '</div>' +
    '</div>' +

    /* Connection panel (real mode only) */
    '<div class="ws-conn-panel" id="ws-conn-panel" style="' + (shellMode === "real" ? "" : "display:none") + '">' +
      '<label>Host</label>' +
      '<input id="ws-host" value="localhost" placeholder="localhost" spellcheck="false">' +
      '<label>Port</label>' +
      '<input id="ws-port" class="port-in" value="8765" placeholder="8765" spellcheck="false">' +
      '<button class="ws-conn-btn" id="ws-conn">Connect</button>' +
      '<button class="ws-disc-btn" id="ws-disc" style="display:none">Disconnect</button>' +
      '<div class="ws-conn-hint">Run <span style="color:var(--acc);font-family:var(--font-mono)">darknode-agent serve</span> on your machine, or start the Python server: <span style="color:var(--acc);font-family:var(--font-mono)">darknode-serve</span></div>' +
    '</div>' +

    /* Terminal area */
    '<div class="ws-term">' +
      '<div id="ws-output" class="ws-glow"></div>' +
      '<div class="ws-input-row">' +
        '<span class="ws-prompt-label ws-glow">' + promptStr() + '&nbsp;</span>' +
        '<input id="ws-input" spellcheck="false" autocomplete="off" placeholder="type a command...">' +
      '</div>' +
    '</div>' +

    /* Footer */
    '<div class="ws-foot">' +
      '<span><kbd>Enter</kbd> Execute</span>' +
      '<span><kbd>&uarr;</kbd><kbd>&darr;</kbd> History</span>' +
      '<span><kbd>Tab</kbd> Hint</span>' +
      '<span><kbd>Ctrl+C</kbd> Interrupt</span>' +
      '<span><kbd>Ctrl+L</kbd> Clear</span>' +
    '</div>' +
    '</div>';

  /* ---- Welcome messages ---- */
  addLine("", "");
  addLine("  ____             _                      _       ", "sys");
  addLine(" |  _ \\  __ _ _ __| | ___ __   ___   __| | ___  ", "sys");
  addLine(" | | | |/ _` | '__| |/ / '_ \\ / _ \\ / _` |/ _ \\ ", "sys");
  addLine(" | |_| | (_| | |  |   <| | | | (_) | (_| |  __/ ", "sys");
  addLine(" |____/ \\__,_|_|  |_|\\_\\_| |_|\\___/ \\__,_|\\___| ", "sys");
  addLine("", "");
  addLine("DARKNODE Web Shell v2.0", "sys");
  if (shellMode === "education") {
    addLine('Education Mode -- simulated filesystem. Type "help" for commands.', "sys");
    addLine('Switch to Real Terminal mode to run commands on your own machine.', "sys");
  } else {
    addLine('Real Terminal Mode -- configure connection above and click Connect.', "sys");
    addLine('Run "darknode-agent serve" on your machine to start the shell server.', "sys");
  }
  addLine("", "");
  paint();

  /* ---- Wire up events ---- */
  var inp = main.querySelector("#ws-input");
  setTimeout(function() { if (inp) inp.focus(); }, 0);

  /* Mode toggle */
  var eduBtn = main.querySelector("#ws-mode-edu");
  var realBtn = main.querySelector("#ws-mode-real");
  if (eduBtn) eduBtn.onclick = function() { if (shellMode !== "education") setMode("education"); };
  if (realBtn) realBtn.onclick = function() { if (shellMode !== "real") setMode("real"); };

  /* Connect / Disconnect */
  var connBtn = main.querySelector("#ws-conn");
  var discBtn = main.querySelector("#ws-disc");
  if (connBtn) connBtn.onclick = function() { connectWs(); };
  if (discBtn) discBtn.onclick = function() { disconnectWs(); };

  /* Tab hint — list available commands */
  var TAB_HINTS = ["help", "ls", "cd", "cat", "pwd", "whoami", "hostname", "uname -a", "ifconfig",
    "ps aux", "uptime", "date", "echo", "clear", "ollama list", "ollama pull", "ollama run"];

  /* Input handling */
  if (inp) {
    inp.addEventListener("keydown", function(e) {
      /* Enter — execute */
      if (e.key === "Enter") {
        e.preventDefault();
        var v = inp.value;
        inp.value = "";
        send(v);
        return;
      }

      /* Arrow Up — history back */
      if (e.key === "ArrowUp") {
        e.preventDefault();
        if (histBuf.length) {
          histIdx = Math.min(histIdx + 1, histBuf.length - 1);
          inp.value = histBuf[histIdx] || "";
        }
        return;
      }

      /* Arrow Down — history forward */
      if (e.key === "ArrowDown") {
        e.preventDefault();
        if (histIdx > 0) { histIdx--; inp.value = histBuf[histIdx] || ""; }
        else { histIdx = -1; inp.value = ""; }
        return;
      }

      /* Tab — show hint / autocomplete */
      if (e.key === "Tab") {
        e.preventDefault();
        var partial = inp.value.trim().toLowerCase();
        if (!partial) {
          addLine("Available: " + TAB_HINTS.join(", "), "sys");
          paint();
          return;
        }
        var matches = [];
        for (var ti = 0; ti < TAB_HINTS.length; ti++) {
          if (TAB_HINTS[ti].indexOf(partial) === 0) matches.push(TAB_HINTS[ti]);
        }
        if (matches.length === 1) {
          inp.value = matches[0] + " ";
        } else if (matches.length > 1) {
          addLine(promptStr() + " " + partial, "prompt");
          addLine(matches.join("  "), "sys");
          paint();
        }
        return;
      }

      /* Ctrl+C — interrupt / send signal */
      if (e.ctrlKey && (e.key === "c" || e.key === "C")) {
        e.preventDefault();
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: "signal", signal: "SIGINT" }));
        }
        addLine(promptStr() + " " + inp.value + "^C", "prompt");
        inp.value = "";
        paint();
        return;
      }

      /* Ctrl+L — clear */
      if (e.ctrlKey && (e.key === "l" || e.key === "L")) {
        e.preventDefault();
        lines = [];
        paint();
        return;
      }
    });

    /* Keep focus on click anywhere in terminal */
    var term = main.querySelector(".ws-term");
    if (term) {
      term.addEventListener("click", function(e) {
        if (e.target.tagName !== "INPUT" && e.target.tagName !== "BUTTON") {
          inp.focus();
        }
      });
    }
  }
}
