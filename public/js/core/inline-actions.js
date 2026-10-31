// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Runs declarative handlers written as data-on-<event>="fn('arg', this.value)" so the
// site can ship a Content-Security-Policy without 'unsafe-inline'. This is NOT eval:
// a small parser accepts only
//   stmt  := call | if (cond) stmt | if (cond) { stmt; ... }
//   cond  := operand [(===|!==|==|!=) operand] [&& cond]
//   call  := [window.]NAME(args) where NAME is in ALLOW, or event.preventDefault() /
//            event.stopPropagation()
//   arg   := 'string' | "string" | number | true | false | null | this[.prop...] |
//            event[.prop...] | call
// Anything else is ignored and reported once to the console. Injected markup can at
// most call one of the allow-listed app functions with literal arguments.
(function () {
  "use strict";
  if (window.__dnInlineActions) return;
  window.__dnInlineActions = true;

  // App functions reachable from markup. test/security/inline-actions.test.mjs fails
  // if a data-on-* handler in public/ calls a name that is not listed here.
  var ALLOW = new Set([
    "__openHelp", "_asnLookup", "_asnLookupDirect", "_asnSearch", "_blDoFilter", "_corsTest",
    "_cveBackToList", "_cveCopyId", "_cveDoSearch", "_cveExport", "_cveLatest", "_cveMore",
    "_cveShowDetail", "_cveToGraph", "_haAnalyze", "_nsLookup", "_sslCopySubdomains", "_sslSearch",
    "_sslToGraph", "_tfScan", "_udAnalyze", "_udBatch", "_udBatchDetail", "_udBuild", "_udCompare",
    "_udDefang", "_udRefang", "_udTab", "_vgAbort", "_vgCopyReport", "_vgExportJSON",
    "_vgExportLog", "_vgIntelTab", "_vgLaunchRecon", "_vgSendRiskToGraph", "_wsClear", "_wsConnect",
    "_wsDisconnect", "_wsSend", "_wsSendJSON", "dnCopy", "dnCopyPre", "dnCopyText", "dnHide",
    "dnHideId", "dnLogoFallback", "dnSetValue", "dnToggleHidden", "dnToggleNext", "dnVal"
  ]);

  // ---- helpers callable from markup -------------------------------------------------
  function flash(el) {
    if (!el || !el.style) return;
    var prev = el.style.color;
    el.style.color = "var(--ok)";
    setTimeout(function () { el.style.color = prev; }, 900);
  }
  window.dnCopy = function (text, el) {
    try { navigator.clipboard.writeText(String(text == null ? "" : text)).then(function () { flash(el); }); } catch (_) {}
  };
  window.dnCopyText = function (el) { if (el) window.dnCopy(el.textContent, el); };
  window.dnHide = function (el) { if (el && el.style) el.style.display = "none"; };
  window.dnHideId = function (id) { window.dnHide(document.getElementById(id)); };
  window.dnToggleHidden = function (id) { var el = document.getElementById(id); if (el) el.hidden = !el.hidden; };
  window.dnSetValue = function (id, v) { var el = document.getElementById(id); if (el) el.value = v; };
  window.dnVal = function (id) { var el = document.getElementById(id); return el ? el.value : ""; };
  // Favicon chip that failed to load -> monogram span (deck-ui logoHTML).
  window.dnLogoFallback = function (img) {
    if (!img || !img.parentNode) return;
    var d = img.dataset || {}, sp = document.createElement("span");
    sp.className = (d.fbCls || "") + " mono";
    if (d.fbA) sp.style.setProperty("--a", d.fbA);
    sp.textContent = d.fbT || "";
    img.parentNode.replaceChild(sp, img);
  };
  // Copy the <pre> in the button's card (button sits two levels below the card).
  window.dnCopyPre = function (el) {
    var card = el && el.parentElement && el.parentElement.parentElement;
    var pre = card && card.querySelector("pre"); if (!pre) return;
    try {
      navigator.clipboard.writeText(pre.textContent).then(function () {
        var t = el.textContent; el.textContent = "Copied";
        setTimeout(function () { el.textContent = t; }, 1000);
      });
    } catch (_) {}
  };
  // Disclosure rows: toggles the next sibling; if sel is given, flips .open on that
  // child of the row (e.g. a tree arrow).
  window.dnToggleNext = function (el, sel) {
    var n = el && el.nextElementSibling; if (!n) return;
    n.hidden = !n.hidden;
    var a = sel ? el.querySelector(sel) : null;
    if (a) a.classList.toggle("open");
  };

  // ---- tokenizer -------------------------------------------------------------------
  function lex(src) {
    var t = [], i = 0, n = src.length, m;
    var re = /\s+|(===|!==|==|!=|&&)|([A-Za-z_$][\w$]*)|(-?\d+(?:\.\d+)?)|'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)"|([().,;{}])/y;
    while (i < n) {
      re.lastIndex = i;
      if (!(m = re.exec(src))) throw new Error("bad token at " + i);
      i = re.lastIndex;
      if (m[1]) t.push({ k: "op", v: m[1] });
      else if (m[2]) t.push({ k: "id", v: m[2] });
      else if (m[3]) t.push({ k: "num", v: Number(m[3]) });
      else if (m[4] != null) t.push({ k: "str", v: unesc(m[4]) });
      else if (m[5] != null) t.push({ k: "str", v: unesc(m[5]) });
      else if (m[6]) t.push({ k: "p", v: m[6] });
    }
    return t;
  }
  function unesc(s) {
    return s.replace(/\\(u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)/g, function (_, c) {
      if (c[0] === "u" && c.length === 5) return String.fromCharCode(parseInt(c.slice(1), 16));
      if (c[0] === "x" && c.length === 3) return String.fromCharCode(parseInt(c.slice(1), 16));
      return { n: "\n", t: "\t", r: "\r" }[c] || c;
    });
  }

  // ---- parser -> closures ----------------------------------------------------------
  function compile(src) {
    var t = lex(src), p = 0;
    function peek(v) { return t[p] && t[p].v === v; }
    function eat(v) { if (!peek(v)) throw new Error("expected " + v); p++; }
    function stmts(stop) {
      var out = [];
      while (p < t.length && !(stop && peek(stop))) {
        if (peek(";")) { p++; continue; }
        out.push(stmt());
      }
      return function (ctx) { for (var i = 0; i < out.length; i++) out[i](ctx); };
    }
    function stmt() {
      if (peek("if")) {
        p++; eat("(");
        var c = cond(); eat(")");
        var body;
        if (peek("{")) { p++; body = stmts("}"); eat("}"); } else body = stmt();
        return function (ctx) { if (c(ctx)) body(ctx); };
      }
      var e = operand();
      if (!e.isCall) throw new Error("statement must be a call");
      return e;
    }
    function cond() {
      var a = operand(), f = a;
      if (t[p] && t[p].k === "op" && t[p].v !== "&&") {
        var op = t[p++].v, b = operand();
        f = function (ctx) {
          var x = a(ctx), y = b(ctx);
          return op === "===" ? x === y : op === "!==" ? x !== y : op === "==" ? x == y : x != y; // eslint-disable-line eqeqeq
        };
      }
      if (peek("&&")) { p++; var rest = cond(), left = f; return function (ctx) { return left(ctx) && rest(ctx); }; }
      return f;
    }
    function operand() {
      var tk = t[p++];
      if (!tk) throw new Error("unexpected end");
      if (tk.k === "str" || tk.k === "num") { var v = tk.v; return function () { return v; }; }
      if (tk.k !== "id") throw new Error("unexpected " + tk.v);
      if (tk.v === "true" || tk.v === "false" || tk.v === "null") {
        var lit = tk.v === "true" ? true : tk.v === "false" ? false : null;
        return function () { return lit; };
      }
      if (tk.v === "this" || tk.v === "event") {
        var root = tk.v, path = [];
        while (peek(".")) { p++; var nm = t[p++]; if (!nm || nm.k !== "id") throw new Error("bad member"); path.push(nm.v); }
        if (peek("(")) {
          if (root !== "event" || path.length !== 1 || (path[0] !== "preventDefault" && path[0] !== "stopPropagation")) throw new Error("call not allowed");
          eat("("); eat(")");
          var meth = path[0];
          var ev = function (ctx) { if (ctx.event) ctx.event[meth](); };
          ev.isCall = true; return ev;
        }
        return function (ctx) {
          var o = root === "this" ? ctx.el : ctx.event;
          for (var i = 0; i < path.length && o != null; i++) o = o[path[i]];
          return o;
        };
      }
      var name = tk.v;
      if (name === "window") { eat("."); var nt = t[p++]; if (!nt || nt.k !== "id") throw new Error("bad member"); name = nt.v; }
      if (!ALLOW.has(name)) throw new Error("not allowed: " + name);
      eat("(");
      var args = [];
      while (!peek(")")) { args.push(operand()); if (peek(",")) p++; else break; }
      eat(")");
      var call = function (ctx) {
        var fn = window[name];
        if (typeof fn !== "function") return undefined;
        var vals = [];
        for (var i = 0; i < args.length; i++) vals.push(args[i](ctx));
        return fn.apply(window, vals);
      };
      call.isCall = true;
      return call;
    }
    var prog = stmts(null);
    if (p !== t.length) throw new Error("trailing input");
    return prog;
  }

  // Exposed for test/security/inline-actions.test.mjs.
  window.__dnInlineCompile = compile;
  window.__dnInlineAllow = ALLOW;

  var cache = new Map(), warned = new Set();
  function run(el, type, event) {
    var src = el.getAttribute("data-on-" + type);
    if (!src) return;
    var fn = cache.get(src);
    if (fn === undefined) {
      try { fn = compile(src); } catch (e) {
        fn = null;
        if (!warned.has(src)) { warned.add(src); try { console.warn("[inline-actions] ignored handler:", src, "-", e.message); } catch (_) {} }
      }
      cache.set(src, fn);
    }
    if (fn) {
      try { fn({ el: el, event: event }); } catch (e) { try { console.error(e); } catch (_) {} }
    }
  }

  // Bubbling events: walk from the target up, like inline handlers would fire.
  var BUBBLE = ["click", "dblclick", "change", "input", "submit", "keydown", "keyup", "keypress", "contextmenu", "dragstart", "drop", "paste"];
  // Non-bubbling events: only the target itself, caught in the capture phase.
  var DIRECT = ["error", "load", "focus", "blur", "toggle", "mouseenter", "mouseleave"];
  BUBBLE.forEach(function (type) {
    document.addEventListener(type, function (event) {
      var el = event.target;
      while (el && el.nodeType === 1) {
        if (el.hasAttribute("data-on-" + type)) {
          run(el, type, event);
          if (event.cancelBubble) break;
        }
        el = el.parentElement;
      }
    }, false);
  });
  DIRECT.forEach(function (type) {
    document.addEventListener(type, function (event) {
      var el = event.target;
      if (el && el.nodeType === 1 && el.hasAttribute("data-on-" + type)) run(el, type, event);
    }, true);
  });
})();
