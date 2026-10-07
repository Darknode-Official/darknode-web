/*
 * Darknode Assistant — the in-house support chat.
 *
 * Replaces the former third-party Botpress webchat: nothing leaves darknode.ai.
 * The chat UI is rendered here (no external iframe/CDN), general Q&A streams from
 * the Darknode AI proxy (/api/chat, the same free service the AI tools use), and
 * natural-language "open / go to / show X" requests are resolved locally and
 * routed through window.dnNavigate — the agentic layer the platform is known for.
 *
 * SAFETY: navigation can only invoke a fixed ALLOWLIST of verbs (ACTIONS below) and
 * always goes through window.dnNavigate (defined in auth.js), which only routes.
 * There is no eval / arbitrary-code path; an unknown action is ignored.
 *
 * Public API (unchanged from the previous bridge, so callers keep working):
 *   window.darknode.control({action,target})  window.darknode.openHelp()
 *   window.darknode.closeHelp()  window.darknode.open()  window.darknode.close()
 *   window.__openHelp()
 */
(function () {
  "use strict";

  if (window.__darknodeChat) return; // idempotent
  window.__darknodeChat = true;

  var log = function (m, x) { try { console.info("[darknode-agent] " + m, x === undefined ? "" : x); } catch (_) {} };

  // ── Allowlisted navigation verbs ───────────────────────────────────────────
  var ACTIONS = {
    navigate: function (c) { return nav(c.target, c); },
    show: function (c) { return nav(c.target, c); },
    goto: function (c) { return nav(c.target, c); },
    open: function (c) { return nav(c.target, c); },
    scroll: function (c) { return nav(c.target, c); },
    section: function (c) { return nav(c.target, c); },
    openTool: function (c) { return nav(c.target ? "tool-" + String(c.target).replace(/^tool-/, "") : "toolbox", c); },
    tool: function (c) { return nav(c.target ? "tool-" + String(c.target).replace(/^tool-/, "") : "toolbox", c); },
    toolbox: function () { return nav("toolbox"); },
    settings: function (c) { return nav("settings", { more: c.target || c.tab || c.more || "" }); },
    ai: function () { return nav("ai"); },
    signup: function () { return nav("signup"); },
    getStarted: function () { return nav("signup"); },
    login: function () { return nav("signin"); },
    signin: function () { return nav("signin"); },
    openChat: function () { return openPanel(); },
    closeChat: function () { return closePanel(); },
  };

  function nav(target, opts) {
    if (typeof window.dnNavigate === "function") return window.dnNavigate(target, opts || {});
    try {
      var t = String(target || "").replace(/^[#/]+/, "");
      var el = document.getElementById(t);
      if (el) { el.scrollIntoView({ behavior: "smooth", block: "start" }); return true; }
      if (t) { window.location.href = "/" + t; return true; }
    } catch (_) {}
    return false;
  }

  window.darknode = window.darknode || {};
  window.darknode.control = function (cmd) {
    try {
      var c = typeof cmd === "string" ? JSON.parse(cmd) : (cmd || {});
      var fn = ACTIONS[c.action];
      if (!fn) { log("ignored action", c.action); return false; }
      return fn(c);
    } catch (e) { log("control error", e && e.message); return false; }
  };

  // ── Local intent: resolve "open / go to / show X" to a real section/tool ────
  var norm = function (s) { return String(s || "").toLowerCase().replace(/[^a-z0-9]/g, ""); };
  var INTENT = /^(?:hey\s+|hi\s+|ok(?:ay)?\s+)?(?:please\s+)?(?:(?:can|could|would|will)\s+you\s+(?:please\s+)?|i\s+(?:want|need|would like)\s+to\s+|let\s+me\s+|help\s+me\s+)?(?:open(?:\s+up)?|go\s+to|goto|navigate\s+to|take\s+me\s+to|bring\s+(?:me\s+to|up)|show(?:\s+me)?|launch|start|run|use|pull\s+up|jump\s+to|switch\s+to|visit)\s+(?:the\s+|my\s+|a\s+)?(.+?)$/i;
  var TRAIL = /\s+(?:for\s+me|please|pls|now|page|tab|tool|section|dashboard|panel|app|screen|menu|on\s+the\s+(?:website|site)|thanks?|thank\s+you)$/i;
  function intentTarget(text) {
    var m = String(text || "").trim().replace(/[.!?\s]+$/, "").match(INTENT);
    if (!m) return null;
    var t = m[1];
    for (var i = 0; i < 4; i++) t = t.replace(TRAIL, "");
    return t.trim();
  }
  function resolveSection(q) {
    var list = Array.isArray(window.dnSections) ? window.dnSections : [];
    var n = norm(q);
    if (!n) return null;
    var tiers = [[], [], [], []];
    list.forEach(function (s) {
      var l = norm(s.label), k = norm(s.sec.replace(/^tool-/, ""));
      if (l === n || k === n) tiers[0].push(s);
      else if (l.indexOf(n) === 0 || k.indexOf(n) === 0) tiers[1].push(s);
      else if (n.length >= 4 && l.indexOf(n) >= 0) tiers[2].push(s);
      else if (l.length >= 4 && n.indexOf(l) >= 0) tiers[3].push(s);
    });
    for (var j = 0; j < tiers.length; j++) {
      if (!tiers[j].length) continue;
      tiers[j].sort(function (a, b) { return (/^tool-/.test(a.sec) - /^tool-/.test(b.sec)) || a.label.length - b.label.length; });
      return tiers[j][0];
    }
    return null;
  }
  function executeHit(hit) {
    if (!document.body.classList.contains("app")) { nav("signin"); return "Sign in first — then I'll open " + hit.label + " for you."; }
    var ok = nav(hit.sec);
    log("chat intent -> " + hit.sec, ok);
    return ok ? "Opened " + hit.label + "." : null;
  }

  // ── Agentic router: a free Gemini call classifies fuzzy action requests ─────
  function proxyUrl() { try { if (window.DARKNODE_PROXY_URL) return window.DARKNODE_PROXY_URL; } catch (_) {} return "/api/chat"; }
  var ACTION_VERB = /\b(open|launch|start|run|go\s*to|goto|navigate|take\s+me|bring\s+(?:me|up)|show|pull\s+up|jump|switch|visit|find|search|scan|check|use|get\s+me|where\s+is|i\s+(?:want|need|wanna|would\s+like))\b/i;
  var PURE_Q = /^\s*(?:who|what|why|when|how|which|is|are|does|do|can\s+you\s+(?:explain|tell)|explain|tell\s+me\s+about)\b/i;
  function mightBeAction(text) {
    var t = String(text || "").trim();
    if (!t || t.length > 240) return false;
    if (PURE_Q.test(t) && !ACTION_VERB.test(t)) return false;
    return ACTION_VERB.test(t);
  }
  function mainSectionLabels() {
    var list = Array.isArray(window.dnSections) ? window.dnSections : [];
    return list.filter(function (s) { return !/^tool-/.test(s.sec); }).map(function (s) { return s.label; }).slice(0, 70);
  }
  function extractJson(s) {
    if (!s) return null;
    var m = s.replace(/```json|```/gi, "").match(/\{[\s\S]*\}/);
    if (!m) return null;
    try { return JSON.parse(m[0]); } catch (_) { return null; }
  }
  function geminiRoute(text) {
    var sys = "You are the navigation router for the Darknode security & coding platform's help assistant. " +
      "Decide what the user wants and reply with ONLY one compact JSON object, no prose and no code fence:\n" +
      '{"action":"open"|"search"|"none","target":"<short name or topic>","say":"<=6 word confirmation>"}\n' +
      "- open: they want to go to / launch / use a specific page or tool.\n" +
      "- search: they want to find or list tools about a topic -> target is the topic.\n" +
      "- none: a general question, greeting, or anything that is not a request to open/run/find something.\n" +
      "target is the THING to open (never the verb), kept short. " +
      "Main sections include: " + mainSectionLabels().join(", ") + ". " +
      "Hundreds of security and coding tools also exist; give a short target and the app resolves it.";
    var body = { provider: "gemini", model: "gemini-flash-lite-latest", messages: [{ role: "system", content: sys }, { role: "user", content: String(text || "").slice(0, 240) }] };
    var ctl = null; try { ctl = new AbortController(); } catch (_) {}
    var timer = ctl ? setTimeout(function () { try { ctl.abort(); } catch (_) {} }, 6000) : null;
    return fetch(proxyUrl(), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), signal: ctl ? ctl.signal : undefined })
      .then(function (r) { if (!r.ok || !r.body) throw new Error("router " + r.status); return r.body.getReader(); })
      .then(function (reader) {
        var dec = new TextDecoder(), buf = "", out = "";
        return (function pump() {
          return reader.read().then(function (res) {
            if (res.done) return out;
            buf += dec.decode(res.value, { stream: true });
            var nl; while ((nl = buf.indexOf("\n")) >= 0) {
              var line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1);
              if (!line.indexOf("data: ")) { var p = line.slice(6); if (p === "[DONE]") return out; try { var j = JSON.parse(p); var d = j.choices && j.choices[0] && j.choices[0].delta; if (d && d.content) out += d.content; } catch (_) {} }
            }
            return pump();
          });
        })();
      })
      .then(function (txt) { if (timer) clearTimeout(timer); return extractJson(txt); })
      .catch(function () { if (timer) clearTimeout(timer); return null; });
  }

  // Try to resolve a message as a navigation request. Returns a Promise<string|null>
  // where the string is a short confirmation to show; null = not an action, answer it.
  function tryNavigate(text) {
    var fast = intentTarget(text);
    if (fast) { var hit = resolveSection(fast); if (hit) return Promise.resolve(executeHit(hit)); }
    if (!mightBeAction(text)) return Promise.resolve(null);
    return geminiRoute(text).then(function (route) {
      if (!route || route.action === "none" || !route.target) return null;
      var hit2 = resolveSection(route.target);
      if (hit2) return executeHit(hit2);
      if (route.action === "search") { nav("toolbox"); return "Showing tools for “" + route.target + "”."; }
      return null;
    });
  }

  // ── Chat Q&A: stream from the Darknode AI proxy ────────────────────────────
  var SYS = "You are the Darknode Assistant, the built-in help agent for darknode.ai — a professional " +
    "cybersecurity and AI-coding platform with 190+ security tools (recon, OSINT, threat intel, vulnerability " +
    "research, forensics, malware analysis, defensive labs) and the Nexus AI coding agent. Answer concisely and " +
    "practically. When a user wants to reach a tool or page, tell them you can open it and that they can just say " +
    "“open <name>”. Keep answers grounded in what Darknode provides; do not invent features. No emojis.";

  function streamAnswer(history, onToken) {
    var messages = [{ role: "system", content: SYS }].concat(history.slice(-10));
    var body = { provider: "gemini", model: "gemini-flash-lite-latest", messages: messages };
    var ctl = null; try { ctl = new AbortController(); } catch (_) {}
    return fetch(proxyUrl(), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), signal: ctl ? ctl.signal : undefined })
      .then(function (r) { if (!r.ok || !r.body) throw new Error("chat " + r.status); return r.body.getReader(); })
      .then(function (reader) {
        var dec = new TextDecoder(), buf = "";
        return (function pump() {
          return reader.read().then(function (res) {
            if (res.done) return;
            buf += dec.decode(res.value, { stream: true });
            var nl; while ((nl = buf.indexOf("\n")) >= 0) {
              var line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1);
              if (!line.indexOf("data: ")) { var p = line.slice(6); if (p === "[DONE]") return; try { var j = JSON.parse(p); var d = j.choices && j.choices[0] && j.choices[0].delta; if (d && d.content) onToken(d.content); } catch (_) {} }
            }
            return pump();
          });
        })();
      });
  }

  // ── UI ─────────────────────────────────────────────────────────────────────
  var CSS =
    "#dnchat-launch{position:fixed;right:20px;bottom:20px;z-index:2147483640;display:inline-flex;align-items:center;gap:8px;" +
      "background:#0f172a;color:#fff;border:1px solid #2563eb;border-radius:999px;padding:11px 18px;font:600 13px/1 system-ui,-apple-system,sans-serif;" +
      "cursor:pointer;box-shadow:0 10px 30px rgba(2,6,23,.28);transition:transform .12s ease,box-shadow .12s ease}" +
    "#dnchat-launch:hover{transform:translateY(-1px);box-shadow:0 14px 38px rgba(2,6,23,.34)}" +
    "#dnchat-launch .dnchat-dot{width:8px;height:8px;border-radius:50%;background:#22c55e;box-shadow:0 0 0 3px rgba(34,197,94,.22)}" +
    "#dnchat-panel{position:fixed;right:20px;bottom:20px;z-index:2147483641;width:380px;max-width:calc(100vw - 32px);height:560px;max-height:calc(100vh - 40px);" +
      "display:none;flex-direction:column;background:#fff;border:1px solid rgba(2,6,23,.12);border-radius:16px;overflow:hidden;" +
      "box-shadow:0 20px 56px rgba(2,6,23,.30),0 3px 12px rgba(2,6,23,.14);font:400 14px/1.5 system-ui,-apple-system,sans-serif}" +
    "#dnchat-panel.open{display:flex}" +
    "#dnchat-head{display:flex;align-items:center;gap:10px;background:#0f172a;color:#fff;padding:13px 14px;border-bottom:1px solid #2563eb}" +
    "#dnchat-head .dnchat-t{font-weight:700;font-size:14px;letter-spacing:.2px}" +
    "#dnchat-head .dnchat-s{font-size:11px;color:#94a3b8;margin-top:1px}" +
    "#dnchat-head .dnchat-x{margin-left:auto;background:transparent;border:0;color:#cbd5e1;font-size:20px;line-height:1;cursor:pointer;padding:2px 6px;border-radius:6px}" +
    "#dnchat-head .dnchat-x:hover{background:rgba(255,255,255,.12);color:#fff}" +
    "#dnchat-log{flex:1;overflow-y:auto;padding:14px;background:#f8fafc;display:flex;flex-direction:column;gap:10px}" +
    ".dnchat-msg{max-width:84%;padding:9px 12px;border-radius:12px;white-space:pre-wrap;word-wrap:break-word;overflow-wrap:anywhere}" +
    ".dnchat-msg.u{align-self:flex-end;background:#2563eb;color:#fff;border-bottom-right-radius:4px}" +
    ".dnchat-msg.a{align-self:flex-start;background:#fff;color:#0f172a;border:1px solid #e2e8f0;border-bottom-left-radius:4px}" +
    ".dnchat-msg.a.sys{background:#eef2ff;border-color:#c7d2fe;color:#1e293b}" +
    ".dnchat-typing{display:inline-block;color:#64748b;font-style:italic}" +
    "#dnchat-foot{border-top:1px solid #e2e8f0;background:#fff;padding:10px;display:flex;gap:8px;align-items:flex-end}" +
    "#dnchat-in{flex:1;resize:none;max-height:120px;min-height:38px;border:1px solid #cbd5e1;border-radius:10px;padding:9px 11px;font:400 14px/1.4 inherit;color:#0f172a;outline:none}" +
    "#dnchat-in:focus{border-color:#2563eb;box-shadow:0 0 0 3px rgba(37,99,235,.15)}" +
    "#dnchat-send{background:#0f172a;color:#fff;border:0;border-radius:10px;padding:0 15px;height:38px;font:600 13px/1 inherit;cursor:pointer}" +
    "#dnchat-send:disabled{opacity:.5;cursor:default}" +
    "#dnchat-send:not(:disabled):hover{background:#1e293b}" +
    /* dark / pro skin: follow the console surface tokens when present */
    "html[data-style=pro] #dnchat-panel,html[data-skin=command] #dnchat-panel{background:var(--card,#0b0f17);border-color:var(--line,#1e293b)}" +
    "html[data-style=pro] #dnchat-log,html[data-skin=command] #dnchat-log{background:var(--bg,#070b12)}" +
    "html[data-style=pro] .dnchat-msg.a,html[data-skin=command] .dnchat-msg.a{background:var(--card2,#0f1623);border-color:var(--line,#1e293b);color:var(--txt,#e2e8f0)}" +
    "html[data-style=pro] #dnchat-foot,html[data-skin=command] #dnchat-foot{background:var(--card,#0b0f17);border-color:var(--line,#1e293b)}" +
    "html[data-style=pro] #dnchat-in,html[data-skin=command] #dnchat-in{background:var(--card2,#0f1623);border-color:var(--line,#1e293b);color:var(--txt,#e2e8f0)}" +
    "@media (max-width:480px){#dnchat-panel{right:8px;bottom:8px;width:calc(100vw - 16px);height:calc(100vh - 16px);max-height:none}}";

  var panel, logEl, inputEl, sendBtn, launchBtn, built = false, busy = false;
  var history = []; // {role:'user'|'assistant', content}

  function addMsg(role, text, cls) {
    var el = document.createElement("div");
    el.className = "dnchat-msg " + (role === "user" ? "u" : "a") + (cls ? " " + cls : "");
    el.textContent = text;
    logEl.appendChild(el);
    logEl.scrollTop = logEl.scrollHeight;
    return el;
  }

  function build() {
    if (built) return;
    built = true;
    var style = document.createElement("style");
    style.id = "dnchat-style"; style.textContent = CSS;
    document.head.appendChild(style);

    launchBtn = document.createElement("button");
    launchBtn.id = "dnchat-launch"; launchBtn.type = "button";
    launchBtn.setAttribute("aria-label", "Open the Darknode Assistant");
    launchBtn.innerHTML = '<span class="dnchat-dot"></span>Ask Darknode';
    launchBtn.addEventListener("click", function () { openPanel(); });
    document.body.appendChild(launchBtn);

    panel = document.createElement("div");
    panel.id = "dnchat-panel";
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-label", "Darknode Assistant");
    panel.innerHTML =
      '<div id="dnchat-head"><div><div class="dnchat-t">Darknode Assistant</div>' +
        '<div class="dnchat-s">On-platform help &amp; navigation</div></div>' +
        '<button class="dnchat-x" type="button" aria-label="Close">×</button></div>' +
      '<div id="dnchat-log"></div>' +
      '<div id="dnchat-foot">' +
        '<textarea id="dnchat-in" rows="1" placeholder="Ask anything, or say “open port scanner”…" aria-label="Message"></textarea>' +
        '<button id="dnchat-send" type="button">Send</button>' +
      '</div>';
    document.body.appendChild(panel);

    logEl = panel.querySelector("#dnchat-log");
    inputEl = panel.querySelector("#dnchat-in");
    sendBtn = panel.querySelector("#dnchat-send");
    panel.querySelector(".dnchat-x").addEventListener("click", closePanel);
    sendBtn.addEventListener("click", submit);
    inputEl.addEventListener("keydown", function (e) {
      if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); submit(); }
    });
    inputEl.addEventListener("input", function () {
      inputEl.style.height = "auto"; inputEl.style.height = Math.min(inputEl.scrollHeight, 120) + "px";
    });

    addMsg("assistant",
      "Hi — I'm the Darknode Assistant. Ask me about any of the platform's security or AI-coding tools, " +
      "or tell me where to go (try “open subdomain finder” or “take me to threat intel”).", "sys");
  }

  function openPanel() {
    build();
    panel.classList.add("open");
    launchBtn.style.display = "none";
    setTimeout(function () { try { inputEl.focus(); } catch (_) {} }, 40);
    return true;
  }
  function closePanel() {
    if (!panel) return false;
    panel.classList.remove("open");
    launchBtn.style.display = "";
    return true;
  }

  function submit() {
    if (busy) return;
    var text = (inputEl.value || "").trim();
    if (!text) return;
    inputEl.value = ""; inputEl.style.height = "auto";
    addMsg("user", text);
    history.push({ role: "user", content: text });
    busy = true; sendBtn.disabled = true;

    var typing = addMsg("assistant", "Thinking…", "typing");

    tryNavigate(text).then(function (confirm) {
      if (confirm) {
        typing.classList.remove("typing");
        typing.textContent = confirm;
        history.push({ role: "assistant", content: confirm });
        busy = false; sendBtn.disabled = false;
        return;
      }
      // Not a navigation action → stream a real answer.
      typing.classList.remove("typing");
      typing.textContent = "";
      var acc = "";
      return streamAnswer(history, function (tok) {
        acc += tok; typing.textContent = acc; logEl.scrollTop = logEl.scrollHeight;
      }).then(function () {
        if (!acc) typing.textContent = "I didn't get a response just then — please try again.";
        history.push({ role: "assistant", content: acc || "" });
        busy = false; sendBtn.disabled = false;
      });
    }).catch(function () {
      typing.classList.remove("typing");
      typing.textContent = "Something went wrong reaching the assistant. Please try again in a moment.";
      busy = false; sendBtn.disabled = false;
    });
  }

  // ── Public API (compat with the old bridge) ────────────────────────────────
  window.darknode.openHelp = function () { return openPanel(); };
  window.darknode.closeHelp = function () { return closePanel(); };
  window.darknode.open = function () { return openPanel(); };
  window.darknode.close = function () { return closePanel(); };
  window.__openHelp = function () { return openPanel(); };

  // Build the launcher on idle so it never blocks boot.
  function boot() { try { build(); } catch (e) { log("chat build error", e && e.message); } }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();

  log("darknode assistant ready (in-house, no external chat)");
})();
