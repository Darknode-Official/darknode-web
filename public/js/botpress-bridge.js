/*
 * Botpress -> Darknode website control bridge.
 *
 * Lets the Botpress support agent drive the site (navigate to a section, open a
 * tool, jump to a settings panel, open the sign-up flow, open/close the chat).
 *
 * SAFETY: the bot can only invoke a fixed ALLOWLIST of verbs below. There is no
 * eval / arbitrary code path — an unknown action is ignored. All navigation goes
 * through window.dnNavigate (defined in auth.js), which itself only routes.
 *
 * ── How to trigger from the bot ───────────────────────────────────────────────
 * In Botpress Studio, send a Custom Event to the webchat with a payload like:
 *     { "action": "navigate", "target": "pricing" }
 *     { "action": "openTool",  "target": "jwt-decode" }
 *     { "action": "settings",  "target": "mcp" }
 *     { "action": "signup" }
 *     { "action": "openChat" } | { "action": "closeChat" }
 * The page receives it via window.botpress.on('customEvent', …).
 * You can also test from the console: window.darknode.control({action:'navigate',target:'pricing'})
 */
(function () {
  "use strict";

  var log = function (m, x) { try { console.info("[darknode-agent] " + m, x === undefined ? "" : x); } catch (_) {} };

  // ── Allowlisted verbs ──────────────────────────────────────────────────────
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
    openChat: function () { return chat("open"); },
    closeChat: function () { return chat("close"); },
  };

  function nav(target, opts) {
    if (typeof window.dnNavigate === "function") return window.dnNavigate(target, opts || {});
    // Fallback before auth.js is ready: best-effort scroll / route.
    try {
      var t = String(target || "").replace(/^[#/]+/, "");
      var el = document.getElementById(t);
      if (el) { el.scrollIntoView({ behavior: "smooth", block: "start" }); return true; }
      if (t) { window.location.href = "/" + t; return true; }
    } catch (_) {}
    return false;
  }

  function chat(which) {
    try {
      if (window.botpress && typeof window.botpress[which] === "function") { window.botpress[which](); return true; }
    } catch (_) {}
    return false;
  }

  // ── Style the webchat + hide the default floating bubble ───────────────────
  // The entire webchat (FAB + chat window) is rendered inside #fab-root's shadow
  // DOM, so page-level CSS cannot reach it (a `#fab-root{display:none}` would hide
  // the chat window too). Instead we inject a <style> INTO the shadow root that:
  //   • hides only .bpFabWrapper (the floating button) — access is via the Help tab;
  //   • removes the "⚡ by Botpress" composer footer;
  //   • aligns the popup to the Darknode brand (accent header, softer radius/shadow).
  var SHADOW_CSS =
    /* hide the floating bubble; the chat opens from the Help tab */
    ".bpFabWrapper{display:none !important}" +
    /* drop the Botpress footer branding */
    ".bpComposerFooter{display:none !important}" +
    /* popup shell: refined corners, depth and hairline border */
    ".bpWebchat{border-radius:18px !important;overflow:hidden !important;" +
      "box-shadow:0 16px 48px rgba(2,6,23,.24),0 2px 10px rgba(2,6,23,.12) !important;" +
      "border:1px solid rgba(2,6,23,.10) !important}" +
    /* header on the site accent, white foreground for contrast */
    ".bpHeaderContainer{background:#2563eb !important;border-bottom:none !important}" +
    ".bpHeaderContainer,.bpHeaderContainer *{color:#fff !important}";

  var styled = false;
  function styleWidget() {
    try {
      var host = document.getElementById("fab-root");
      if (!host || !host.shadowRoot) return false;
      var sr = host.shadowRoot;
      var st = sr.getElementById("dn-webchat-style");
      if (!st) {
        st = document.createElement("style");
        st.id = "dn-webchat-style";
        sr.appendChild(st);
      }
      if (st.textContent !== SHADOW_CSS) st.textContent = SHADOW_CSS;
      styled = true;
      log("webchat styled (bubble hidden, footer removed, brand skin)");
      return true;
    } catch (_) { return false; }
  }
  // The shadow root appears asynchronously after the widget mounts; poll for it.
  // Keep a light re-apply loop briefly in case Botpress re-renders the subtree.
  var styleTries = 0;
  var styleIv = setInterval(function () {
    styleTries++;
    var ok = styleWidget();
    if (styleTries > 200) clearInterval(styleIv);
  }, 150);

  // ── Normalise many possible command shapes into { action, target, … } ──────
  function parseCmd(raw) {
    if (raw == null) return null;
    if (typeof raw === "string") {
      var s = raw.trim();
      // "dn:navigate:pricing" | "navigate:pricing" | "navigate pricing"
      var m = s.match(/^(?:dn[:\s])?\s*([a-zA-Z]+)[:\s]+(.+)$/);
      if (m) return { action: m[1], target: m[2].trim() };
      try { var j = JSON.parse(s); return parseCmd(j); } catch (_) {}
      return { action: s };
    }
    if (typeof raw === "object") {
      // Unwrap common envelopes.
      if (raw.payload && (raw.payload.action || raw.payload.type)) raw = raw.payload;
      else if (raw.data && (raw.data.action || raw.data.type)) raw = raw.data;
      var action = raw.action || raw.type || raw.command || raw.verb;
      var target = raw.target != null ? raw.target : (raw.value != null ? raw.value : (raw.payload != null && typeof raw.payload !== "object" ? raw.payload : raw.section || raw.tool || raw.to));
      if (!action) return null;
      return { action: String(action), target: target, more: raw.more || raw.tab, raw: raw };
    }
    return null;
  }

  function dispatch(raw) {
    var cmd = parseCmd(raw);
    if (!cmd || !cmd.action) return false;
    // Tolerate a "darknode" namespace prefix / envelope type.
    if (/^darknode$/i.test(cmd.action) && cmd.raw) cmd = parseCmd({ action: cmd.raw.do || cmd.raw.verb, target: cmd.raw.target });
    if (!cmd || !cmd.action) return false;
    var key = Object.keys(ACTIONS).find(function (k) { return k.toLowerCase() === String(cmd.action).toLowerCase(); });
    if (!key) { log("ignored unknown action", cmd.action); return false; }
    var ok = false;
    try { ok = ACTIONS[key](cmd); } catch (e) { log("action error", e && e.message); }
    log("dispatch " + key + (cmd.target ? " -> " + cmd.target : ""), ok);
    return ok;
  }

  // Public handle for testing / manual control.
  window.darknode = window.darknode || {};
  window.darknode.control = dispatch;
  window.darknode.navigate = function (t, o) { return nav(t, o); };
  // Open/close the support chat — called by the "Help" tab in the topbar. If the
  // widget has not finished loading yet, retry briefly.
  window.darknode.openHelp = function () {
    var n = 0;
    (function tryOpen() {
      if (window.botpress && typeof window.botpress.open === "function") { try { window.botpress.open(); } catch (_) {} return; }
      if (n++ < 25) setTimeout(tryOpen, 200);
    })();
  };
  window.darknode.closeHelp = function () { try { window.botpress && window.botpress.close && window.botpress.close(); } catch (_) {} };

  // ── Wire Botpress events once the widget is ready ──────────────────────────
  var wired = false;
  function wire() {
    if (wired || !window.botpress || typeof window.botpress.on !== "function") return;
    wired = true;
    var on = window.botpress.on.bind(window.botpress);
    // Primary channel: bot-emitted custom events.
    ["customEvent", "custom", "event", "webchatEvent", "trigger"].forEach(function (ev) {
      try { on(ev, function (e) { dispatch(e); }); } catch (_) {}
    });
    // Secondary: inspect messages for an embedded { action } payload.
    try {
      on("message", function (m) {
        try {
          var p = m && (m.payload || m.message || m);
          if (p && (p.action || p.type === "custom")) dispatch(p);
          else if (p && typeof p.text === "string") {
            var mm = p.text.match(/%%\s*(\{[\s\S]*?\}|dn[:\s][\s\S]*?)\s*%%/i);
            if (mm) dispatch(mm[1]);
          }
        } catch (_) {}
      });
    } catch (_) {}
    log("bridge wired to botpress");
  }

  // postMessage fallback (only from botpress origins).
  window.addEventListener("message", function (ev) {
    try {
      if (!/\.botpress\.cloud$|\.bpcontent\.cloud$/.test(new URL(ev.origin).hostname)) return;
      var d = ev.data;
      if (d && (d.darknodeAction || (d.action && d.source === "darknode"))) dispatch(d.darknodeAction || d);
    } catch (_) {}
  });

  // Poll for the widget for up to ~30s, then also hook the ready event.
  var tries = 0;
  var iv = setInterval(function () {
    tries++;
    if (window.botpress && typeof window.botpress.on === "function") {
      wire();
      try { window.botpress.on("webchat:ready", wire); } catch (_) {}
      clearInterval(iv);
    } else if (tries > 150) { clearInterval(iv); }
  }, 200);
})();
