// CVSS 3.1 Base Score Calculator — vulnerability-scoring tool for the Darknode web app.
// Computes the exact FIRST.org CVSS v3.1 base score, severity rating and vector string.
// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved.
// Fully client-side. No network, no external libraries. Pure CVSS math.
//
// Architecture: a pure, side-effect-free scoring core (computeCvss / parseVector /
// buildVector) is kept entirely separate from the DOM. renderCvssCalculator() builds
// the UI once and then performs targeted in-place updates — it never re-renders the
// whole tool on a metric change. The core is self-checked against known vectors
// (see __selftest) so correctness is auditable independent of the UI.

const esc = (s) => String(s != null ? s : "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// ── metric definitions ──
// Each metric: abbreviation, label, and ordered options [code, label, weight].
// Privileges Required weight is scope-dependent, handled specially in scoring.
var METRICS = [
  {
    key: "AV", label: "Attack Vector", help: "How the vulnerability is reached.",
    options: [
      ["N", "Network", 0.85],
      ["A", "Adjacent", 0.62],
      ["L", "Local", 0.55],
      ["P", "Physical", 0.2]
    ]
  },
  {
    key: "AC", label: "Attack Complexity", help: "Conditions beyond the attacker's control.",
    options: [
      ["L", "Low", 0.77],
      ["H", "High", 0.44]
    ]
  },
  {
    key: "PR", label: "Privileges Required", help: "Privilege level needed before exploiting.",
    options: [
      // weight is resolved at score time (scope-dependent)
      ["N", "None", 0.85],
      ["L", "Low", 0.62],
      ["H", "High", 0.27]
    ]
  },
  {
    key: "UI", label: "User Interaction", help: "Whether a separate user must act.",
    options: [
      ["N", "None", 0.85],
      ["R", "Required", 0.62]
    ]
  },
  {
    key: "S", label: "Scope", help: "Can the vulnerability affect resources beyond its security scope?",
    options: [
      ["U", "Unchanged", 0],
      ["C", "Changed", 0]
    ]
  },
  {
    key: "C", label: "Confidentiality", help: "Impact to confidentiality of information.",
    options: [
      ["H", "High", 0.56],
      ["L", "Low", 0.22],
      ["N", "None", 0]
    ]
  },
  {
    key: "I", label: "Integrity", help: "Impact to integrity (trustworthiness of information).",
    options: [
      ["H", "High", 0.56],
      ["L", "Low", 0.22],
      ["N", "None", 0]
    ]
  },
  {
    key: "A", label: "Availability", help: "Impact to availability of the affected component.",
    options: [
      ["H", "High", 0.56],
      ["L", "Low", 0.22],
      ["N", "None", 0]
    ]
  }
];

var METRIC_ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];

// Default selections → the canonical AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 Critical).
var DEFAULT_METRICS = { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" };

// Valid codes per metric, derived once from the definitions (used by parseVector).
var VALID_CODES = (function () {
  var map = {};
  METRICS.forEach(function (m) { map[m.key] = m.options.map(function (o) { return o[0]; }); });
  return map;
})();

// ══════════════════════════════════════════════════════════════════════════
//  PURE SCORING CORE  (no DOM, no globals, no side effects — safe to unit test)
// ══════════════════════════════════════════════════════════════════════════

// quick lookup of weight for a non-PR metric
function weightOf(key, code) {
  var m = METRICS.find(function (x) { return x.key === key; });
  if (!m) return 0;
  var o = m.options.find(function (x) { return x[0] === code; });
  return o ? o[2] : 0;
}

// Privileges Required weight depends on Scope (Changed raises Low/High).
function prWeight(code, scopeChanged) {
  if (code === "N") return 0.85;
  if (code === "L") return scopeChanged ? 0.68 : 0.62;
  if (code === "H") return scopeChanged ? 0.5 : 0.27;
  return 0.85;
}

// ── CVSS v3.1 roundup (per specification Appendix A) — NOT a naive Math.ceil ──
function roundup(input) {
  var int = Math.round(input * 100000);
  if (int % 10000 === 0) return int / 100000;
  return (Math.floor(int / 10000) + 1) / 10;
}

// ── severity rating (CVSS v3.1 qualitative scale) ──
function severityOf(s) {
  if (s <= 0) return "None";
  if (s < 4.0) return "Low";
  if (s < 7.0) return "Medium";
  if (s < 9.0) return "High";
  return "Critical";
}

// ── vector string ──
function buildVector(metrics) {
  var m = metrics || {};
  return "CVSS:3.1/" + METRIC_ORDER.map(function (k) { return k + ":" + m[k]; }).join("/");
}

// ── parse a vector string into a metrics object ──
// Tolerates a missing / CVSS:3.0 / CVSS:3.1 prefix and ignores unknown metrics
// without throwing. Unrecognised metrics fall back to DEFAULT_METRICS.
// Returns the full metrics object plus how many of the 8 base metrics matched.
function parseVectorInfo(str) {
  var metrics = Object.assign({}, DEFAULT_METRICS);
  var matched = 0;
  var s = String(str == null ? "" : str).trim();
  // tolerate a leading CVSS:3.1/ or CVSS:3.0/ prefix, or none at all
  s = s.replace(/^\s*cvss:3\.[01]\s*\//i, "");
  s.split("/").forEach(function (part) {
    var kv = part.split(":");
    if (kv.length !== 2) return;
    var k = kv[0].trim().toUpperCase();
    var v = kv[1].trim().toUpperCase();
    if (VALID_CODES[k] && VALID_CODES[k].indexOf(v) >= 0) { metrics[k] = v; matched++; }
  });
  return { metrics: metrics, matched: matched, total: METRIC_ORDER.length };
}

// Public pure parser: vector string → full metrics object.
function parseVector(str) {
  return parseVectorInfo(str).metrics;
}

// ── core scoring: metrics → { baseScore, severity, impact, exploitability, vector } ──
function computeCvss(metrics) {
  // merge over defaults so a partial/garbage input can never throw or read undefined
  var m = Object.assign({}, DEFAULT_METRICS, metrics || {});
  var scopeChanged = m.S === "C";

  var av = weightOf("AV", m.AV);
  var ac = weightOf("AC", m.AC);
  var pr = prWeight(m.PR, scopeChanged);
  var ui = weightOf("UI", m.UI);
  var c = weightOf("C", m.C);
  var i = weightOf("I", m.I);
  var a = weightOf("A", m.A);

  var iss = 1 - ((1 - c) * (1 - i) * (1 - a));
  var impact;
  if (scopeChanged) {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  } else {
    impact = 6.42 * iss;
  }
  var exploitability = 8.22 * av * ac * pr * ui;

  var baseScore;
  if (impact <= 0) {
    baseScore = 0;
  } else if (scopeChanged) {
    baseScore = roundup(Math.min(1.08 * (impact + exploitability), 10));
  } else {
    baseScore = roundup(Math.min(impact + exploitability, 10));
  }

  return {
    baseScore: baseScore,
    severity: severityOf(baseScore),
    impact: Math.max(0, roundup(impact)),
    exploitability: roundup(exploitability),
    vector: buildVector(m)
  };
}

// ── self-check: a tiny set of known vectors, verifiable without the DOM ──
// Exported so the module (or a test) can run it once. Uses console.assert, which is
// a no-op-ish/strippable in production yet surfaces regressions in dev.
export function __selftest() {
  var cases = [
    // [vector, expected baseScore, expected severity]
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"], // canonical default
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "None"],     // no impact → 0.0
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "Medium"],   // classic reflected XSS
    ["CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9, "Critical"]  // scope-changed PR weight 0.68
  ];
  var ok = true;
  cases.forEach(function (t) {
    var r = computeCvss(parseVector(t[0]));
    var pass = Math.abs(r.baseScore - t[1]) < 1e-9 && r.severity === t[2];
    if (!pass) ok = false;
    if (typeof console !== "undefined" && console.assert) {
      console.assert(pass, "CVSS selftest FAILED: " + t[0] +
        " expected " + t[1] + " " + t[2] + " got " + r.baseScore + " " + r.severity);
    }
  });
  return ok;
}

// Run the self-check once at module load (guarded; never throws into the app).
try { __selftest(); } catch (_) {}

// ── preset examples ──
function presets() {
  return [
    {
      name: "Remote RCE (Critical)",
      note: "Unauthenticated network RCE, full impact",
      sel: { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" }
    },
    {
      name: "Stored XSS (Medium)",
      note: "Network, scope change, low C/I impact, user interaction",
      sel: { AV: "N", AC: "L", PR: "L", UI: "R", S: "C", C: "L", I: "L", A: "N" }
    },
    {
      name: "Local Info Leak (Low)",
      note: "Local access, high complexity, low confidentiality only",
      sel: { AV: "L", AC: "H", PR: "L", UI: "N", S: "U", C: "L", I: "N", A: "N" }
    }
  ];
}

var SEV_COLOR = {
  Critical: "#f0484a",
  High: "#f5920b",
  Medium: "#f5b544",
  Low: "#38d99a",
  None: "var(--acc)"
};

// ── CSS ──
var CV_CSS =
  '<style>' +
  '.cv-wrap{color:var(--txt)}' +
  '.cv-grid{display:grid;grid-template-columns:minmax(0,1.3fr) minmax(0,1fr);gap:16px;align-items:start}' +
  '@media(max-width:900px){.cv-grid{grid-template-columns:minmax(0,1fr)}}' +
  '.cv-col{display:flex;flex-direction:column;gap:14px;min-width:0}' +
  '.cv-metric{margin-bottom:14px}' +
  '.cv-metric:last-child{margin-bottom:0}' +
  '.cv-mhead{display:flex;align-items:baseline;gap:8px;margin-bottom:6px;flex-wrap:wrap}' +
  '.cv-mlabel{font-size:.82rem;font-weight:600;color:var(--txt)}' +
  '.cv-mabbr{font-family:var(--font-mono);font-size:.72rem;color:var(--acc)}' +
  '.cv-mhelp{font-size:.72rem;color:var(--mut);flex:1 1 100%;margin-top:2px}' +
  '.cv-seg{display:flex;flex-wrap:wrap;gap:6px}' +
  '.cv-opt{flex:1 1 auto;min-width:68px;background:var(--card2);border:1px solid var(--line);color:var(--txt-2);border-radius:5px;padding:8px 10px;font-size:.82rem;font-family:inherit;cursor:pointer;text-align:center;transition:border-color .12s,background .12s,color .12s}' +
  '.cv-opt:hover{border-color:var(--acc);color:var(--txt)}' +
  '.cv-opt:focus-visible{outline:2px solid var(--acc);outline-offset:2px}' +
  '.cv-opt.sel{background:color-mix(in srgb,var(--acc) 18%,transparent);border-color:var(--acc);color:var(--txt);font-weight:600}' +
  '.cv-opt .cv-w{display:block;font-size:.66rem;color:var(--mut);font-family:var(--font-mono);margin-top:2px}' +
  '.cv-opt.sel .cv-w{color:var(--acc)}' +
  '.cv-score-card{text-align:center;padding:18px 14px}' +
  '.cv-score-num{font-size:3.4rem;line-height:1;font-weight:700;font-family:var(--font-mono);letter-spacing:-.02em}' +
  '.cv-badge{display:inline-block;margin-top:10px;padding:5px 16px;border-radius:999px;font-size:.84rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#0a0d12}' +
  '.cv-subs{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:16px}' +
  '.cv-sub{background:var(--card2);border:1px solid var(--line);border-radius:6px;padding:10px 12px;text-align:center}' +
  '.cv-sub-lbl{font-size:.7rem;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}' +
  '.cv-sub-val{font-size:1.3rem;font-weight:600;font-family:var(--font-mono);margin-top:3px;color:var(--txt)}' +
  '.cv-vecbox{font-family:var(--font-mono);font-size:.82rem;line-height:1.5;word-break:break-all;background:var(--card2);border:1px solid var(--line);border-radius:6px;padding:12px;color:var(--txt);margin-bottom:10px}' +
  '.cv-actions{display:flex;flex-wrap:wrap;gap:8px}' +
  '.cv-mini{font-size:.76rem;padding:6px 12px}' +
  '.cv-field{margin-bottom:0}' +
  '.cv-lbl{display:block;font-size:.74rem;color:var(--mut);margin-bottom:4px;text-transform:uppercase;letter-spacing:.04em}' +
  '.cv-row{display:grid;grid-template-columns:1fr auto;gap:8px}' +
  '.cv-in{width:100%;box-sizing:border-box;background:var(--card2);border:1px solid var(--line);color:var(--txt);border-radius:4px;padding:8px 10px;font-size:.82rem;font-family:var(--font-mono)}' +
  '.cv-in:focus{outline:none;border-color:var(--acc);box-shadow:0 0 0 3px color-mix(in srgb,var(--acc) 15%,transparent)}' +
  '.cv-in.err{border-color:#f0484a}' +
  '.cv-err{font-size:.72rem;color:#f0484a;margin-top:6px;display:none}' +
  '.cv-err.show{display:block}' +
  '.cv-presets{display:flex;flex-direction:column;gap:8px}' +
  '.cv-preset{text-align:left;background:var(--card2);border:1px solid var(--line);color:var(--txt);border-radius:6px;padding:10px 12px;cursor:pointer;font-family:inherit}' +
  '.cv-preset:hover{border-color:var(--acc)}' +
  '.cv-preset-name{font-size:.84rem;font-weight:600;display:block}' +
  '.cv-preset-note{font-size:.72rem;color:var(--mut);display:block;margin-top:2px}' +
  '.cv-hint{font-size:.72rem;color:var(--mut);margin-top:6px}' +
  '.cv-sticky{position:sticky;top:12px}' +
  '</style>';

// ══════════════════════════════════════════════════════════════════════════
//  RENDER  (DOM layer — reads the pure core, never duplicates the math)
// ══════════════════════════════════════════════════════════════════════════
export function renderCvssCalculator(main) {
  // Selection model. Hydrated from the URL hash if a valid vector is present,
  // otherwise the canonical 9.8 default.
  var sel = Object.assign({}, DEFAULT_METRICS);

  // Reading the hash is always safe; writing it is suppressed when embedded so
  // we never fight a host page's navigation.
  var embedded = (function () { try { return window.self !== window.top; } catch (_) { return true; } })();

  (function hydrateFromHash() {
    try {
      var h = (location.hash || "").replace(/^#/, "");
      if (!h) return;
      var info = parseVectorInfo(decodeURIComponent(h));
      if (info.matched >= METRIC_ORDER.length) sel = info.metrics;
    } catch (_) {}
  })();

  function updateHash() {
    if (embedded) return;
    try {
      history.replaceState(history.state, "", location.pathname + location.search + "#" + buildVector(sel));
    } catch (_) {}
  }

  function toast(msg) {
    if (typeof window.showToast === "function") window.showToast(msg);
  }

  // render a metric group with weight hints (PR weights shown scope-aware)
  function metricHtml(m) {
    var scopeChanged = sel.S === "C";
    var opts = m.options.map(function (o) {
      var isSel = sel[m.key] === o[0];
      var w;
      if (m.key === "PR") w = prWeight(o[0], scopeChanged);
      else if (m.key === "S") w = null;
      else w = o[2];
      var wHtml = (w == null) ? "" : '<span class="cv-w">' + w.toFixed(2) + '</span>';
      return '<button type="button" role="radio" aria-checked="' + (isSel ? "true" : "false") +
        '" tabindex="' + (isSel ? "0" : "-1") + '" class="cv-opt' + (isSel ? " sel" : "") +
        '" data-metric="' + m.key + '" data-code="' + o[0] + '"' +
        ' aria-label="' + esc(m.label + ": " + o[1]) + '">' +
        esc(o[1]) + wHtml + '</button>';
    }).join("");
    return '<div class="cv-metric" data-metric-group="' + m.key + '">' +
      '<div class="cv-mhead"><span class="cv-mlabel" id="cv-lbl-' + m.key + '">' + esc(m.label) + '</span>' +
      '<span class="cv-mabbr">' + m.key + '</span>' +
      '<span class="cv-mhelp">' + esc(m.help) + '</span></div>' +
      '<div class="cv-seg" role="radiogroup" aria-labelledby="cv-lbl-' + m.key + '">' + opts + '</div></div>';
  }

  main.innerHTML = CV_CSS +
    '<div class="cv-wrap">' +
    '<div class="pg-head"><div>' +
    '<h1 class="pg-h1">CVSS 3.1 Base Score Calculator</h1>' +
    '<p class="muted pg-sub">Compute the exact FIRST.org CVSS v3.1 base score, severity and vector string. Everything runs in your browser.</p>' +
    '</div></div>' +
    '<div class="cv-grid">' +

    // ── left column (metrics) ──
    '<div class="cv-col">' +
    '<div class="panel">' +
    '<div class="panel-h"><h2 class="pg-h2">Base Metrics</h2></div>' +
    '<div id="cv-metrics">' + METRICS.map(metricHtml).join("") + '</div>' +
    '</div>' +
    '</div>' +

    // ── right column (readout) ──
    '<div class="cv-col cv-sticky">' +
    '<div class="panel">' +
    '<div class="panel-h"><h2 class="pg-h2">Base Score</h2></div>' +
    '<div class="cv-score-card">' +
    '<div class="cv-score-num" id="cv-score">0.0</div>' +
    '<div class="cv-badge" id="cv-badge">None</div>' +
    '<div class="cv-subs">' +
    '<div class="cv-sub"><div class="cv-sub-lbl">Impact</div><div class="cv-sub-val" id="cv-impact">0.0</div></div>' +
    '<div class="cv-sub"><div class="cv-sub-lbl">Exploitability</div><div class="cv-sub-val" id="cv-exploit">0.0</div></div>' +
    '</div></div>' +
    '</div>' +

    '<div class="panel">' +
    '<div class="panel-h"><h2 class="pg-h2">Vector</h2>' +
    '<div class="cv-actions">' +
    '<button class="btn ghost cv-mini" id="cv-copy-vec" type="button">Copy vector</button>' +
    '<button class="btn ghost cv-mini" id="cv-copy-score" type="button">Copy score</button>' +
    '</div></div>' +
    '<div class="cv-vecbox" id="cv-vector"></div>' +
    '<div class="cv-field"><label class="cv-lbl" for="cv-load">Load a vector string</label>' +
    '<div class="cv-row"><input class="cv-in" id="cv-load" aria-describedby="cv-load-err" placeholder="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">' +
    '<button class="btn ghost cv-mini" id="cv-load-btn" type="button">Load</button></div>' +
    '<p class="cv-err" id="cv-load-err" role="alert"></p>' +
    '<p class="cv-hint">Paste a CVSS:3.1 vector to set all metrics at once.</p></div>' +
    '</div>' +

    '<div class="panel">' +
    '<div class="panel-h"><h2 class="pg-h2">Examples</h2></div>' +
    '<div class="cv-presets" id="cv-presets"></div>' +
    '</div>' +

    '</div>' +
    '</div></div>';

  var $ = function (id) { return main.querySelector("#" + id); };
  var metricsWrap = $("cv-metrics");
  var scoreEl = $("cv-score");
  var badgeEl = $("cv-badge");
  var impactEl = $("cv-impact");
  var exploitEl = $("cv-exploit");
  var vectorEl = $("cv-vector");
  var loadInput = $("cv-load");
  var loadErr = $("cv-load-err");

  // ── targeted readout update (no innerHTML churn) ──
  function refresh() {
    var r = computeCvss(sel);
    scoreEl.textContent = r.baseScore.toFixed(1);
    scoreEl.style.color = SEV_COLOR[r.severity];
    badgeEl.textContent = r.severity;
    badgeEl.style.background = SEV_COLOR[r.severity];
    impactEl.textContent = r.impact.toFixed(1);
    exploitEl.textContent = r.exploitability.toFixed(1);
    vectorEl.textContent = r.vector;
  }

  // Update one metric group's selected state / aria / roving tabindex in place.
  function paintGroup(key) {
    var group = metricsWrap.querySelector('[data-metric-group="' + key + '"]');
    if (!group) return;
    group.querySelectorAll(".cv-opt").forEach(function (b) {
      var on = b.dataset.code === sel[key];
      b.classList.toggle("sel", on);
      b.setAttribute("aria-checked", on ? "true" : "false");
      b.tabIndex = on ? 0 : -1;
    });
  }

  // Scope changes the displayed PR weights — update just those labels in place.
  function paintPrWeights() {
    var group = metricsWrap.querySelector('[data-metric-group="PR"]');
    if (!group) return;
    var scopeChanged = sel.S === "C";
    group.querySelectorAll(".cv-opt").forEach(function (b) {
      var span = b.querySelector(".cv-w");
      if (span) span.textContent = prWeight(b.dataset.code, scopeChanged).toFixed(2);
    });
  }

  // Re-sync every group (used when all metrics change at once: load / preset / hash).
  function syncAll() {
    METRIC_ORDER.forEach(paintGroup);
    paintPrWeights();
  }

  // Single entry point for a metric change: model + DOM + score + hash.
  function selectMetric(key, code) {
    if (!VALID_CODES[key] || VALID_CODES[key].indexOf(code) < 0) return;
    if (sel[key] === code) return;
    sel[key] = code;
    paintGroup(key);
    if (key === "S") paintPrWeights(); // PR weight labels are scope-dependent
    refresh();
    updateHash();
  }

  // ── interaction: click selects an option ──
  metricsWrap.addEventListener("click", function (e) {
    var btn = e.target.closest(".cv-opt");
    if (!btn) return;
    selectMetric(btn.dataset.metric, btn.dataset.code);
    btn.focus();
  });

  // ── interaction: full keyboard radio-group semantics ──
  metricsWrap.addEventListener("keydown", function (e) {
    var btn = e.target.closest && e.target.closest(".cv-opt");
    if (!btn) return;
    var key = btn.dataset.metric;
    var group = metricsWrap.querySelector('[data-metric-group="' + key + '"]');
    var opts = Array.prototype.slice.call(group.querySelectorAll(".cv-opt"));
    var idx = opts.indexOf(btn);
    var next = -1;
    switch (e.key) {
      case "ArrowRight": case "ArrowDown": next = (idx + 1) % opts.length; break;
      case "ArrowLeft": case "ArrowUp": next = (idx - 1 + opts.length) % opts.length; break;
      case "Home": next = 0; break;
      case "End": next = opts.length - 1; break;
      case " ": case "Enter": e.preventDefault(); selectMetric(key, btn.dataset.code); return;
      default: return;
    }
    if (next < 0) return;
    e.preventDefault();
    var target = opts[next];
    selectMetric(key, target.dataset.code); // radio semantics: moving selects
    target.focus();
  });

  // ── copy actions ──
  function copy(text, okMsg) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { toast(okMsg); },
        function () { toast("Copy failed — select the text manually"); });
    } else {
      toast("Clipboard unavailable — select the text manually");
    }
  }
  $("cv-copy-vec").onclick = function () { copy(buildVector(sel), "Vector copied"); };
  $("cv-copy-score").onclick = function () {
    var r = computeCvss(sel);
    copy(r.baseScore.toFixed(1) + " (" + r.severity + ")", "Score copied");
  };

  // ── load vector (inline error on garbage, in-place update on success) ──
  function showLoadErr(msg) {
    if (msg) { loadErr.textContent = msg; loadErr.classList.add("show"); loadInput.classList.add("err"); }
    else { loadErr.textContent = ""; loadErr.classList.remove("show"); loadInput.classList.remove("err"); }
  }
  function applyVector(str) {
    if (!String(str == null ? "" : str).trim()) {
      showLoadErr("Enter a CVSS:3.1 vector string.");
      return;
    }
    var info = parseVectorInfo(str);
    if (info.matched < info.total) {
      showLoadErr("Not a complete CVSS:3.1 vector — recognised " +
        info.matched + " of " + info.total + " base metrics.");
      return;
    }
    showLoadErr("");
    sel = info.metrics;
    syncAll();
    refresh();
    updateHash();
    toast("Vector loaded");
  }
  $("cv-load-btn").onclick = function () { applyVector(loadInput.value); };
  loadInput.onkeydown = function (e) { if (e.key === "Enter") { e.preventDefault(); applyVector(loadInput.value); } };
  loadInput.oninput = function () { if (loadErr.classList.contains("show")) showLoadErr(""); };

  // ── presets ──
  var presetWrap = $("cv-presets");
  var presetList = presets();
  presetWrap.innerHTML = presetList.map(function (p, i) {
    return '<button type="button" class="cv-preset" data-ex="' + i + '">' +
      '<span class="cv-preset-name">' + esc(p.name) + '</span>' +
      '<span class="cv-preset-note">' + esc(p.note) + '</span></button>';
  }).join("");
  presetWrap.onclick = function (e) {
    var b = e.target.closest(".cv-preset");
    if (!b) return;
    var p = presetList[+b.dataset.ex];
    sel = Object.assign({}, p.sel);
    showLoadErr("");
    syncAll();
    refresh();
    updateHash();
    toast("Loaded example: " + p.name);
  };

  // initial paint + reflect current selection in the hash
  refresh();
  updateHash();
}
