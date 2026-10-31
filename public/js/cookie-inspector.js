// Cookie Security Analyzer — parse and grade Set-Cookie headers for the Darknode web app.
// Paste one or more Set-Cookie lines (or a raw HTTP response header block) and get a
// per-cookie attribute breakdown, security findings and a letter grade.
// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Fully client-side. No network, no external libraries. Offline parsing done by hand.

const esc = (s) => String(s != null ? s : "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// ── constants ──
var ONE_YEAR = 60 * 60 * 24 * 365; // seconds
var VALUE_DISPLAY_MAX = 80;

// ── severity ranking (worst-first) ──
var SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
var SEV_COLOR = {
  critical: "var(--bad)",
  high: "var(--bad)",
  medium: "var(--warn)",
  low: "var(--warn)",
  info: "var(--mut)"
};

// ── split a pasted blob into individual Set-Cookie header values ──
// Robust: never naively split on comma (Expires dates contain commas). Split on
// newlines; if the text looks like a raw HTTP header block, keep only Set-Cookie lines.
function extractCookieLines(raw) {
  var text = String(raw || "").replace(/\r\n/g, "\n").replace(/\r/g, "\n");

  // Unfold obsolete HTTP header line folding (RFC 7230 §3.2.4): a line that begins
  // with a space or tab is a continuation of the previous header line. Join it back
  // before any per-cookie processing so a wrapped Set-Cookie stays a single value.
  var rawLines = text.split("\n");
  var lines = [];
  rawLines.forEach(function (ln) {
    if (/^[ \t]/.test(ln) && lines.length) {
      lines[lines.length - 1] += " " + ln.trim();
    } else {
      lines.push(ln);
    }
  });

  // Does this look like a raw header block (has at least one "Header: value" that
  // is not a Set-Cookie)? If so, only pull Set-Cookie lines out of it.
  var hasSetCookie = lines.some(function (l) { return /^\s*set-cookie\s*:/i.test(l); });

  var out = [];
  lines.forEach(function (ln) {
    var t = ln.trim();
    if (!t) return;
    var m = t.match(/^set-cookie\s*:\s*(.*)$/i);
    if (m) {
      out.push(m[1].trim());
    } else if (!hasSetCookie) {
      // No Set-Cookie prefixes anywhere — treat every non-empty line as a bare
      // cookie string (user pasted values without the header name).
      // Skip lines that are obviously other HTTP headers (word chars + colon early).
      if (/^[A-Za-z][A-Za-z0-9-]*\s*:\s*\S/.test(t) && !/=/.test(t.split(":")[1] || "=")) return;
      out.push(t);
    }
  });
  return out.filter(Boolean);
}

// ── parse one Set-Cookie header value ──
function parseCookie(rawLine) {
  var line = String(rawLine || "").trim();
  // The cookie-pair is everything up to the first ';'. Attributes follow.
  var firstSemi = line.indexOf(";");
  var pairStr = firstSemi >= 0 ? line.slice(0, firstSemi) : line;
  var rest = firstSemi >= 0 ? line.slice(firstSemi + 1) : "";

  var eq = pairStr.indexOf("=");
  var name, value;
  if (eq >= 0) {
    name = pairStr.slice(0, eq).trim();
    value = pairStr.slice(eq + 1).trim();
  } else {
    name = pairStr.trim();
    value = "";
  }
  // Strip surrounding double quotes from a quoted value.
  if (value.length >= 2 && value.charAt(0) === '"' && value.charAt(value.length - 1) === '"') {
    value = value.slice(1, -1);
  }

  var attrs = {
    domain: null,
    path: null,
    expires: null,
    maxAge: null,       // raw string
    maxAgeNum: null,    // parsed number or null
    secure: false,
    httpOnly: false,
    sameSite: null,     // "Strict" | "Lax" | "None" | raw
    partitioned: false,
    priority: null,
    unknown: []
  };

  // Split attributes on ';'. Expires value can contain a comma but NOT a semicolon,
  // so splitting on ';' is safe.
  rest.split(";").forEach(function (seg) {
    var s = seg.trim();
    if (!s) return;
    var aEq = s.indexOf("=");
    var key = (aEq >= 0 ? s.slice(0, aEq) : s).trim().toLowerCase();
    var av = aEq >= 0 ? s.slice(aEq + 1).trim() : "";
    switch (key) {
      case "domain": attrs.domain = av; break;
      case "path": attrs.path = av; break;
      case "expires": attrs.expires = av; break;
      case "max-age":
        attrs.maxAge = av;
        // RFC 6265 5.2.2: a Max-Age that is not an optional '-' plus digits is ignored
        attrs.maxAgeNum = /^-?\d+$/.test(av) ? parseInt(av, 10) : null;
        break;
      case "secure": attrs.secure = true; break;
      case "httponly": attrs.httpOnly = true; break;
      case "samesite":
        var sv = av.toLowerCase();
        if (sv === "strict") attrs.sameSite = "Strict";
        else if (sv === "lax") attrs.sameSite = "Lax";
        else if (sv === "none") attrs.sameSite = "None";
        else attrs.sameSite = av || "(empty)";
        break;
      case "partitioned": attrs.partitioned = true; break;
      case "priority": attrs.priority = av; break;
      default: if (key) attrs.unknown.push(s); break;
    }
  });

  var prefixHost = /^__Host-/.test(name);
  var prefixSecure = /^__Secure-/.test(name);

  // Session vs persistent + deletion detection.
  var expiresDate = attrs.expires ? new Date(attrs.expires) : null;
  var expiresValid = expiresDate && !isNaN(expiresDate.getTime());
  var isSession = !expiresValid && attrs.maxAgeNum == null; // browsers ignore an unparseable Expires or Max-Age
  var isDeletion = (attrs.maxAgeNum != null && attrs.maxAgeNum <= 0) ||
    (expiresValid && expiresDate.getTime() < Date.now());

  // Effective lifetime in seconds for a live persistent cookie (Max-Age wins over
  // Expires, per RFC 6265). null for session/deletion cookies or an unparseable date.
  var lifetimeSec = null;
  if (!isDeletion && !isSession) {
    if (attrs.maxAgeNum != null) lifetimeSec = attrs.maxAgeNum;
    else if (expiresValid) lifetimeSec = Math.round((expiresDate.getTime() - Date.now()) / 1000);
  }

  return {
    raw: line,
    name: name,
    value: value,
    attrs: attrs,
    prefixHost: prefixHost,
    prefixSecure: prefixSecure,
    expiresValid: expiresValid,
    expiresDate: expiresValid ? expiresDate : null,
    isSession: isSession,
    isDeletion: isDeletion,
    lifetimeSec: lifetimeSec
  };
}

// ── grading rules (declarative, data-driven table) ──
// Each rule is { id, test(parsed) -> bool, severity, message, fix }. message/fix may be
// a plain string or a function(parsed) -> string. The grader (gradeCookie) evaluates
// every rule in order and emits a finding for each test that passes. Rules whose tests
// cover the same attribute are written to be mutually exclusive, so exactly one fires
// per attribute, and the overall grade is derived deterministically from the worst
// severity emitted. Adding or auditing a rule means editing one entry here — no control
// flow to untangle. ALL rules below preserve the severities of the original grader.
var COOKIE_RULES = [
  // ── Secure (one of these fires) ──
  {
    id: "secure-missing-samesite-none",
    test: function (c) { return !c.attrs.secure && c.attrs.sameSite === "None"; },
    severity: "critical",
    message: "SameSite=None set without the Secure attribute.",
    fix: "Browsers reject a SameSite=None cookie that is not Secure. Add Secure."
  },
  {
    id: "secure-missing-prefix",
    test: function (c) { return !c.attrs.secure && c.attrs.sameSite !== "None" && (c.prefixHost || c.prefixSecure); },
    severity: "critical",
    message: function (c) { return "A " + (c.prefixHost ? "__Host-" : "__Secure-") + " prefixed cookie lacks the Secure attribute."; },
    fix: "Browsers reject prefixed cookies without Secure. Add Secure or drop the prefix."
  },
  {
    id: "secure-missing",
    test: function (c) { return !c.attrs.secure && c.attrs.sameSite !== "None" && !c.prefixHost && !c.prefixSecure && !c.isDeletion; }, // a deletion carries no value worth protecting
    severity: "high",
    message: "Secure attribute missing — the cookie can be sent over plaintext HTTP.",
    fix: "Add Secure so the cookie is only transmitted over HTTPS."
  },
  {
    id: "secure-ok",
    test: function (c) { return !!c.attrs.secure; },
    severity: "info",
    message: "Secure is set — cookie is only sent over HTTPS."
  },

  // ── HttpOnly (one of these fires) ──
  {
    id: "httponly-missing",
    test: function (c) { return !c.attrs.httpOnly && !c.isDeletion; },
    severity: "medium",
    message: "HttpOnly missing — the cookie is readable by JavaScript (document.cookie).",
    fix: "Add HttpOnly unless this cookie is intentionally read by client-side scripts (e.g. a CSRF token mirror)."
  },
  {
    id: "httponly-ok",
    test: function (c) { return !!c.attrs.httpOnly; },
    severity: "info",
    message: "HttpOnly is set — not exposed to document.cookie."
  },

  // ── SameSite (one of these fires) ──
  {
    id: "samesite-absent",
    test: function (c) { return c.attrs.sameSite == null && !c.isDeletion; },
    severity: "medium",
    message: "SameSite not set — modern browsers default to Lax, but being explicit is safer and portable.",
    fix: "Set SameSite=Strict or Lax (or None for cross-site contexts, with Secure)."
  },
  {
    id: "samesite-none-needs-secure",
    test: function (c) { return c.attrs.sameSite === "None" && !c.attrs.secure; },
    severity: "info",
    message: "SameSite=None requires Secure (see critical finding above)."
  },
  {
    id: "samesite-none-ok",
    test: function (c) { return c.attrs.sameSite === "None" && c.attrs.secure; },
    severity: "low",
    message: "SameSite=None — the cookie is sent on cross-site requests (needed for some third-party flows).",
    fix: "Confirm cross-site delivery is actually required; otherwise prefer Lax or Strict."
  },
  {
    id: "samesite-strict",
    test: function (c) { return c.attrs.sameSite === "Strict"; },
    severity: "info",
    message: "SameSite=Strict — strongest CSRF protection; cookie is withheld on cross-site navigation."
  },
  {
    id: "samesite-lax",
    test: function (c) { return c.attrs.sameSite === "Lax"; },
    severity: "info",
    message: "SameSite=Lax — reasonable default CSRF protection."
  },
  {
    id: "samesite-unknown",
    test: function (c) { var s = c.attrs.sameSite; return s != null && s !== "None" && s !== "Strict" && s !== "Lax"; },
    severity: "medium",
    message: function (c) { return "SameSite has an unrecognized value: " + c.attrs.sameSite + "."; },
    fix: "Use one of Strict, Lax or None."
  },

  // ── __Host- prefix contract: Secure + Path=/ + NO Domain (path/domain can both fire) ──
  {
    id: "host-prefix-path",
    test: function (c) { return c.prefixHost && c.attrs.path !== "/"; },
    severity: "high",
    message: function (c) { return "__Host- prefix requires Path=/ but Path is " + (c.attrs.path == null ? "absent" : c.attrs.path) + "."; },
    fix: "Set Path=/ or the browser will reject the cookie."
  },
  {
    id: "host-prefix-domain",
    test: function (c) { return c.prefixHost && c.attrs.domain != null; },
    severity: "high",
    message: function (c) { return "__Host- prefix forbids a Domain attribute, but Domain=" + c.attrs.domain + " is present."; },
    fix: "Remove the Domain attribute to satisfy the __Host- prefix contract."
  },
  {
    id: "host-prefix-ok",
    test: function (c) { return c.prefixHost && c.attrs.path === "/" && c.attrs.domain == null && c.attrs.secure; },
    severity: "info",
    message: "__Host- prefix contract satisfied (Secure, Path=/, no Domain)."
  },

  // ── __Secure- prefix contract: must be Secure (missing-Secure handled above) ──
  {
    id: "secure-prefix-ok",
    test: function (c) { return c.prefixSecure && c.attrs.secure; },
    severity: "info",
    message: "__Secure- prefix contract satisfied (Secure present)."
  },

  // ── Session vs persistent / long-lived (one of these fires) ──
  {
    id: "deletion",
    test: function (c) { return c.isDeletion; },
    severity: "info",
    message: "This is a deletion cookie (Max-Age<=0 or an Expires in the past) — it clears the cookie."
  },
  {
    id: "session",
    test: function (c) { return !c.isDeletion && c.isSession; },
    severity: "info",
    message: "Session cookie (no Expires or Max-Age) — cleared when the browser session ends."
  },
  {
    id: "long-lived",
    test: function (c) { return !c.isDeletion && !c.isSession && c.lifetimeSec != null && c.lifetimeSec > ONE_YEAR; },
    severity: "low",
    message: function (c) { return "Long-lived persistent cookie (~" + (c.lifetimeSec / ONE_YEAR).toFixed(1) + " year(s)) — a long window for tracking or token reuse."; },
    fix: "Shorten the lifetime; prefer short-lived cookies with silent refresh for sessions."
  },
  {
    id: "bounded-lifetime",
    test: function (c) { return !c.isDeletion && !c.isSession && !(c.lifetimeSec != null && c.lifetimeSec > ONE_YEAR); },
    severity: "info",
    message: "Persistent cookie with a bounded lifetime."
  },

  // ── Overly broad Domain (one of these may fire) ──
  {
    id: "domain-leading-dot",
    test: function (c) { return c.attrs.domain != null && c.attrs.domain.charAt(0) === "."; },
    severity: "low",
    message: function (c) { return "Domain begins with a leading dot (" + c.attrs.domain + ") — the cookie is shared across all subdomains."; },
    fix: "Scope the cookie to the exact host where possible; avoid leading-dot domains."
  },
  {
    id: "domain-apex",
    test: function (c) { var d = c.attrs.domain; return d != null && d.charAt(0) !== "." && d.split(".").length <= 2 && d.indexOf(".") > 0; },
    severity: "info",
    message: function (c) { return "Domain=" + c.attrs.domain + " covers the apex and its subdomains — confirm that breadth is intended."; }
  }
];

// worst severity -> letter grade + numeric score (deterministic).
var GRADE_FOR = {
  critical: { grade: "F", score: 25 },
  high: { grade: "D", score: 50 },
  medium: { grade: "C", score: 72 },
  low: { grade: "B", score: 86 },
  info: { grade: "A", score: 98 }
};

function resolve(v, c) { return typeof v === "function" ? v(c) : v; }

// Evaluate the declarative rule table against one parsed cookie.
function gradeCookie(c) {
  var findings = [];
  COOKIE_RULES.forEach(function (rule) {
    if (!rule.test(c)) return;
    findings.push({
      id: rule.id,
      sev: resolve(rule.severity, c),
      msg: resolve(rule.message, c),
      rec: rule.fix == null ? "" : resolve(rule.fix, c)
    });
  });

  // grade derived from the worst finding
  var worst = "info";
  findings.forEach(function (f) { if (SEV_RANK[f.sev] > SEV_RANK[worst]) worst = f.sev; });
  var g = GRADE_FOR[worst] || GRADE_FOR.info;

  // sort findings worst-first for display (stable: keeps rule-table order within a tier)
  findings.sort(function (x, y) { return SEV_RANK[y.sev] - SEV_RANK[x.sev]; });

  return { findings: findings, worst: worst, grade: g.grade, score: g.score };
}

// ── self-check: runnable assertions over the pure logic (parse + grade) ──
// Exported so it can be driven from a console or a test runner; returns a structured
// result and also fires console.assert so failures surface where logs are watched.
export function __selftest() {
  var results = [];
  function check(name, cond) {
    results.push({ name: name, pass: !!cond });
    if (typeof console !== "undefined" && typeof console.assert === "function") {
      console.assert(!!cond, "[cookie-inspector] " + name);
    }
  }

  // 1. The good __Host- example grades A.
  var good = parseCookie("__Host-session=9f8b3a1c2d; Secure; Path=/; HttpOnly; SameSite=Strict");
  check("good __Host- example grades A", gradeCookie(good).grade === "A");

  // 2. The flagless Domain cookie flags missing Secure / HttpOnly / SameSite.
  var bad = gradeCookie(parseCookie("sid=abc123; Domain=.example.com"));
  var badIds = bad.findings.map(function (f) { return f.id; });
  check("flagless cookie flags missing Secure", badIds.indexOf("secure-missing") >= 0);
  check("flagless cookie flags missing HttpOnly", badIds.indexOf("httponly-missing") >= 0);
  check("flagless cookie flags missing SameSite", badIds.indexOf("samesite-absent") >= 0);

  // 3. An Expires date containing a comma is parsed as ONE cookie, not split on it.
  var lines = extractCookieLines("Set-Cookie: a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT");
  check("Expires comma is not split into two lines", lines.length === 1);
  var pc = parseCookie(lines[0]);
  check("Expires comma cookie keeps its name", pc.name === "a");
  check("Expires value retains the comma", /Wed, 21 Oct 2026/.test(pc.attrs.expires || ""));

  // 4. Value containing '=' is preserved whole (split on the first '=' only).
  var eqc = parseCookie("token=a=b=c; Secure");
  check("value with '=' is preserved", eqc.name === "token" && eqc.value === "a=b=c");

  var passed = results.every(function (r) { return r.pass; });
  return { passed: passed, results: results };
}

function gradeColor(grade) {
  if (grade === "A" || grade === "B") return "var(--ok)";
  if (grade === "C") return "var(--warn)";
  return "var(--bad)"; // D / F
}

// Overall worst grade across all cookies (lowest letter wins).
var GRADE_RANK = { A: 4, B: 3, C: 2, D: 1, F: 0 };
function worstGrade(grades) {
  if (!grades.length) return "A";
  return grades.reduce(function (acc, g) { return GRADE_RANK[g] < GRADE_RANK[acc] ? g : acc; }, "A");
}

function truncVal(v) {
  if (v.length <= VALUE_DISPLAY_MAX) return { text: v, truncated: false };
  return { text: v.slice(0, VALUE_DISPLAY_MAX), truncated: true };
}

// ── CSS ──
var CK_CSS =
  '<style>' +
  '.ck-wrap{color:var(--txt)}' +
  '.ck-grid{display:grid;grid-template-columns:minmax(0,420px) minmax(0,1fr);gap:16px;align-items:start}' +
  '@media(max-width:860px){.ck-grid{grid-template-columns:minmax(0,1fr)}}' +
  '.ck-col{display:flex;flex-direction:column;gap:14px;min-width:0}' +
  '.ck-lbl{display:block;font-size:.8rem;color:var(--mut);margin-bottom:4px}' +
  '.ck-ta{width:100%;box-sizing:border-box;background:var(--card2);border:1px solid var(--line);color:var(--txt);border-radius:4px;padding:10px 12px;font-size:.82rem;font-family:var(--font-mono);line-height:1.55;resize:vertical;min-height:150px}' +
  '.ck-ta:focus{outline:none;border-color:var(--acc);box-shadow:0 0 0 3px color-mix(in srgb,var(--acc) 15%,transparent)}' +
  '.ck-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}' +
  '.ck-mini{font-size:.76rem;padding:5px 11px}' +
  '.ck-hint{font-size:.8rem;color:var(--mut);margin-top:6px;line-height:1.5}' +
  '.ck-summary{display:flex;align-items:center;gap:12px;flex-wrap:wrap;font-size:.86rem;color:var(--txt-2);margin-bottom:4px}' +
  '.ck-summary strong{color:var(--txt)}' +
  '.ck-empty{color:var(--mut);font-size:.86rem;padding:18px;text-align:center;border:1px dashed var(--line);border-radius:6px}' +
  '.ck-card{border:1px solid var(--line);border-radius:8px;padding:14px;margin-bottom:12px;background:color-mix(in srgb,var(--card2) 50%,var(--card))}' +
  '.ck-card-head{display:flex;align-items:center;gap:12px;margin-bottom:12px}' +
  '.ck-name{font-family:var(--font-mono);font-size:.92rem;color:var(--txt);word-break:break-all;flex:1;min-width:0}' +
  '.ck-prefix{display:inline-block;font-size:.75rem;font-family:var(--font-mono);color:var(--acc);border:1px solid color-mix(in srgb,var(--acc) 45%,var(--line));border-radius:3px;padding:1px 5px;margin-left:6px;vertical-align:middle}' +
  '.ck-badge{flex-shrink:0;width:38px;height:38px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:1.25rem;color:var(--bg)}' +
  '.ck-valrow{font-size:.76rem;color:var(--mut);margin-bottom:10px;font-family:var(--font-mono);word-break:break-all}' +
  '.ck-valrow .ck-v{color:var(--txt-2)}' +
  '.ck-tbl{width:100%;border-collapse:collapse;font-size:.8rem;margin-bottom:12px}' +
  '.ck-tbl td{padding:5px 8px;border-bottom:1px solid var(--line);vertical-align:top}' +
  '.ck-tbl td:first-child{color:var(--mut);width:118px;font-size:.8rem;white-space:nowrap}' +
  '.ck-tbl td:last-child{color:var(--txt);font-family:var(--font-mono);word-break:break-all}' +
  '.ck-present{color:var(--ok)}' +
  '.ck-absent{color:var(--mut);font-style:italic}' +
  '.ck-find{display:flex;align-items:flex-start;gap:9px;padding:8px 0;border-top:1px solid var(--line)}' +
  '.ck-find:first-child{border-top:none}' +
  '.ck-dot{flex-shrink:0;width:9px;height:9px;border-radius:50%;margin-top:5px}' +
  '.ck-find-body{min-width:0}' +
  '.ck-find-msg{font-size:.82rem;color:var(--txt);line-height:1.45}' +
  '.ck-find-sev{font-size:.75rem;font-weight:700;margin-right:6px}' +
  '.ck-find-rec{font-size:.76rem;color:var(--txt-2);margin-top:3px;line-height:1.45}' +
  '.ck-find-rec::before{content:"Fix: ";color:var(--mut)}' +
  '.ck-findings-h{font-size:.875rem;font-weight:600;color:var(--txt);margin:0 0 2px}' +
  '</style>';

// ── examples ──
function exampleText() {
  var past = new Date(Date.now() - 86400000).toUTCString();
  return [
    "Set-Cookie: __Host-session=9f8b3a1c2d; Secure; Path=/; HttpOnly; SameSite=Strict",
    "Set-Cookie: sid=abc123; Domain=.example.com",
    "Set-Cookie: tracker=u8812; Domain=.ads.example.com; Max-Age=63072000; Secure; SameSite=None",
    "Set-Cookie: old_pref=; Path=/; Expires=" + past
  ].join("\n");
}

// ── render ──
export function renderCookieInspector(main) {
  function toast(msg) {
    if (typeof window.showToast === "function") window.showToast(msg);
  }

  main.innerHTML = CK_CSS +
    '<div class="ck-wrap">' +
    '<div class="pg-head"><div>' +
    '<h1 class="pg-h1">Cookie Security Analyzer</h1>' +
    '<p class="muted pg-sub">Paste one or more Set-Cookie headers (or a full response header block) to grade them for Secure, HttpOnly, SameSite, cookie prefixes and lifetime. Everything runs in your browser.</p>' +
    '</div></div>' +
    '<div class="ck-grid">' +

    // left: input
    '<div class="ck-col">' +
    '<div class="panel">' +
    '<div class="panel-h"><h2 class="pg-h2">Input</h2></div>' +
    '<label class="ck-lbl" for="ck-input">Set-Cookie headers</label>' +
    '<textarea class="ck-ta" id="ck-input" placeholder="Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Strict&#10;Set-Cookie: sid=xyz; Domain=.example.com&#10;&#10;One per line. The leading &quot;Set-Cookie:&quot; is optional; a full raw header block is accepted too."></textarea>' +
    '<div class="ck-actions">' +
    '<button class="btn primary ck-mini" id="ck-analyze" type="button">Analyze</button>' +
    '<button class="btn ghost ck-mini" id="ck-example" type="button">Load example</button>' +
    '<button class="btn ghost ck-mini" id="ck-clear" type="button">Clear</button>' +
    '<button class="btn ghost ck-mini" id="ck-copy" type="button">Copy report</button>' +
    '</div>' +
    '<p class="ck-hint">Parsing is offline and comma-safe: lines are split on newlines, so commas inside an Expires date never break a cookie. Values are never sent anywhere.</p>' +
    '</div>' +
    '</div>' +

    // right: results
    '<div class="ck-col">' +
    '<div class="panel">' +
    '<div class="panel-h"><h2 class="pg-h2">Results</h2></div>' +
    '<div id="ck-results"><div class="ck-empty">No cookies analyzed yet. Paste headers and press Analyze, or load the example.</div></div>' +
    '</div>' +
    '</div>' +

    '</div></div>';

  var $ = function (id) { return main.querySelector("#" + id); };
  var input = $("ck-input");
  var results = $("ck-results");
  var lastReport = "";

  function attrCell(present, value) {
    if (!present) return '<span class="ck-absent">absent</span>';
    return '<span class="ck-present">' + esc(value) + '</span>';
  }

  function renderResults(cookies) {
    if (!cookies.length) {
      results.innerHTML = '<div class="ck-empty">No Set-Cookie headers found in the input. Check the format and try again.</div>';
      lastReport = "";
      return;
    }

    var graded = cookies.map(function (c) { return { cookie: c, g: gradeCookie(c) }; });
    var grades = graded.map(function (x) { return x.g.grade; });
    var overall = worstGrade(grades);

    var summary = '<div class="ck-summary">' +
      '<span><strong>' + cookies.length + '</strong> cookie' + (cookies.length > 1 ? "s" : "") + ' analyzed</span>' +
      '<span>Worst grade: <strong style="color:' + gradeColor(overall) + '">' + overall + '</strong></span>' +
      '</div>';

    var cards = graded.map(function (x) {
      var c = x.cookie, g = x.g, a = c.attrs;
      var vt = truncVal(c.value);
      var prefixTag = "";
      if (c.prefixHost) prefixTag = '<span class="ck-prefix">__Host-</span>';
      else if (c.prefixSecure) prefixTag = '<span class="ck-prefix">__Secure-</span>';

      var valDisplay = c.value === ""
        ? '<span class="ck-absent">(empty)</span>'
        : '<span class="ck-v">' + esc(vt.text) + (vt.truncated ? '<span class="ck-absent"> … (' + c.value.length + ' chars, truncated)</span>' : '') + '</span>';

      var sameSiteDisplay = a.sameSite == null
        ? '<span class="ck-absent">absent (browser default: Lax)</span>'
        : '<span class="ck-present">' + esc(a.sameSite) + '</span>';

      var expiresDisplay;
      if (a.expires) {
        expiresDisplay = '<span class="' + (c.expiresValid ? 'ck-present' : 'ck-absent') + '">' + esc(a.expires) + (c.expiresValid ? '' : ' (unparseable)') + '</span>';
      } else {
        expiresDisplay = '<span class="ck-absent">absent</span>';
      }

      var tbl = '<table class="ck-tbl"><tbody>' +
        '<tr><td>Domain</td><td>' + attrCell(a.domain != null, a.domain) + '</td></tr>' +
        '<tr><td>Path</td><td>' + attrCell(a.path != null, a.path) + '</td></tr>' +
        '<tr><td>Expires</td><td>' + expiresDisplay + '</td></tr>' +
        '<tr><td>Max-Age</td><td>' + (a.maxAge != null && c.attrs.maxAgeNum == null ? '<span class="ck-absent">' + esc(a.maxAge) + ' (not a number, ignored)</span>' : attrCell(a.maxAge != null, a.maxAge)) + '</td></tr>' +
        '<tr><td>Secure</td><td>' + (a.secure ? '<span class="ck-present">yes</span>' : '<span class="ck-absent">no</span>') + '</td></tr>' +
        '<tr><td>HttpOnly</td><td>' + (a.httpOnly ? '<span class="ck-present">yes</span>' : '<span class="ck-absent">no</span>') + '</td></tr>' +
        '<tr><td>SameSite</td><td>' + sameSiteDisplay + '</td></tr>' +
        '<tr><td>Partitioned</td><td>' + (a.partitioned ? '<span class="ck-present">yes (CHIPS)</span>' : '<span class="ck-absent">no</span>') + '</td></tr>' +
        (a.priority ? '<tr><td>Priority</td><td><span class="ck-present">' + esc(a.priority) + '</span></td></tr>' : '') +
        '<tr><td>Lifetime</td><td>' + (c.isDeletion ? '<span class="ck-absent">deletion</span>' : (c.isSession ? '<span class="ck-present">session</span>' : '<span class="ck-present">persistent</span>')) + '</td></tr>' +
        '</tbody></table>';

      var findings = g.findings.map(function (f) {
        return '<div class="ck-find">' +
          '<span class="ck-dot" style="background:' + SEV_COLOR[f.sev] + '"></span>' +
          '<div class="ck-find-body">' +
          '<div class="ck-find-msg"><span class="ck-find-sev" style="color:' + SEV_COLOR[f.sev] + '">' + f.sev + '</span>' + esc(f.msg) + '</div>' +
          (f.rec ? '<div class="ck-find-rec">' + esc(f.rec) + '</div>' : '') +
          '</div></div>';
      }).join("");

      return '<div class="ck-card">' +
        '<div class="ck-card-head">' +
        '<div class="ck-name">' + esc(c.name || "(unnamed)") + prefixTag + '</div>' +
        '<div class="ck-badge" style="background:' + gradeColor(g.grade) + '" title="score ' + g.score + '/100">' + g.grade + '</div>' +
        '</div>' +
        '<div class="ck-valrow">value: ' + valDisplay + '</div>' +
        tbl +
        '<p class="ck-findings-h">Findings (' + g.findings.length + ')</p>' +
        findings +
        '</div>';
    }).join("");

    results.innerHTML = summary + cards;
    lastReport = buildReport(graded, overall);
  }

  function buildReport(graded, overall) {
    var L = [];
    L.push("Cookie Security Analyzer report");
    L.push("Cookies: " + graded.length + "   Worst grade: " + overall);
    L.push("");
    graded.forEach(function (x, i) {
      var c = x.cookie, g = x.g, a = c.attrs;
      L.push((i + 1) + ". " + (c.name || "(unnamed)") + "  [grade " + g.grade + ", score " + g.score + "/100]");
      L.push("   Secure=" + a.secure + "  HttpOnly=" + a.httpOnly + "  SameSite=" + (a.sameSite || "absent") +
        "  Partitioned=" + a.partitioned);
      L.push("   Domain=" + (a.domain != null ? a.domain : "absent") + "  Path=" + (a.path != null ? a.path : "absent") +
        "  Lifetime=" + (c.isDeletion ? "deletion" : (c.isSession ? "session" : "persistent")));
      g.findings.forEach(function (f) {
        L.push("   [" + f.sev.toUpperCase() + "] " + f.msg + (f.rec ? "  -> " + f.rec : ""));
      });
      L.push("");
    });
    return L.join("\n");
  }

  function analyze() {
    var lines = extractCookieLines(input.value);
    var cookies = lines.map(parseCookie).filter(function (c) { return c.name; });
    renderResults(cookies);
  }

  $("ck-analyze").onclick = analyze;
  $("ck-example").onclick = function () { input.value = exampleText(); analyze(); toast("Loaded example Set-Cookie headers"); };
  $("ck-clear").onclick = function () {
    input.value = "";
    results.innerHTML = '<div class="ck-empty">No cookies analyzed yet. Paste headers and press Analyze, or load the example.</div>';
    lastReport = "";
    input.focus();
  };
  $("ck-copy").onclick = function () {
    if (!lastReport) { toast("Nothing to copy — analyze some cookies first"); return; }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(lastReport).then(
        function () { toast("Report copied to clipboard"); },
        function () { toast("Copy failed — select the text manually"); });
    } else {
      toast("Clipboard unavailable — select the text manually");
    }
  };
}
