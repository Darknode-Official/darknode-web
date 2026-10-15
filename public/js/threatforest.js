// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
// ThreatForest — automated attack trees from source code (UI layer).
//
// Inspired by the research project of the same name (AWS / Black Hat USA 2026,
// "ThreatForest: Automated Attack Trees from Source Code"), rebuilt from scratch
// to be faster and more capable:
//   - FAST: a deterministic client-side static-analysis engine runs instantly in
//     the browser. Weaknesses carry their own CWE/CAPEC/MITRE ATT&CK/STRIDE labels,
//     so mapping is a lookup, not a slow embedding search. No server round-trip is
//     needed to get a full result.
//   - POWERFUL: every finding is cross-walked to CWE + CAPEC + ATT&CK + STRIDE, woven
//     into a goal-oriented attack tree, scored for risk, and can be pushed into the
//     Security Graph or exported. An optional one-pass AI deep-dive (Darknode AI) adds
//     prioritised remediation and extra attack paths on top of the deterministic core.
//
// Pure analysis logic lives in threatforest-engine.js (unit-tested under Node); this
// file is the UI. Analysis is heuristic and advisory: it flags patterns that are
// commonly dangerous. Confidence is shown per finding; treat high-confidence findings
// first. For JavaScript/TypeScript, a reused inter-procedural data-flow (taint) engine
// CONFIRMS which source->sink paths are actually reachable and cites the traced path;
// those nodes are marked "confirmed reachable". For every other language, and for
// categories the taint engine does not model, source->sink labels report LEXICAL
// co-location only, NOT call-graph reachability.

import { GOALS, RULES, SEV_LABEL, analyze, buildTree, riskScore } from "./threatforest-engine.js";

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// Severity palette as TEXT colour only (restrained, theme-safe on the light
// Professional default). Dots use these via a `--c` custom property + a class rule,
// never an inline `background:#0…/#1…` — the pro-theme catch-all would wash those
// to white. See STANDING RULES.
const SEV_COLOR = { 5: "#b00020", 4: "#c0501b", 3: "#8a6d00", 2: "var(--mut)", 1: "var(--mut)" };
const sevClass = (s) => "tf-s" + s;

// ---- Example inputs ---------------------------------------------------------
// Deliberately-vulnerable snippets the user can load to see the engine work. These
// are analysis INPUTS, not results: ThreatForest genuinely analyses them with the
// same engine it runs on your code. The field stays empty until you load one.
const SAMPLES = {
  "Node / Express API": `const express = require('express');\nconst { exec } = require('child_process');\nconst db = require('./db');\nconst app = express();\nconst API_KEY = "sk_live_9f8a7b6c5d4e3f2a1b0c";\n\napp.get('/ping', (req, res) => {\n  // pings a host the user supplies\n  exec('ping -c 1 ' + req.query.host, (e, out) => res.send(out));\n});\n\napp.get('/user', (req, res) => {\n  const q = "SELECT * FROM users WHERE id = " + req.query.id;\n  db.query(q, (e, rows) => res.send('<b>' + rows[0].name + '</b>'));\n});\n\napp.post('/avatar', (req, res) => {\n  res.sendFile(req.body.path);\n});\n\napp.listen(3000);`, // darknode-ignore: deliberately vulnerable sample for ThreatForest to analyze
  "Python / Flask": `import os, pickle, hashlib, yaml\nfrom flask import Flask, request\napp = Flask(__name__)\n\n@app.route('/run')\ndef run():\n    cmd = request.args.get('cmd')\n    return os.system(cmd)\n\n@app.route('/load', methods=['POST'])\ndef load():\n    data = pickle.loads(request.data)   # untrusted\n    return str(data)\n\n@app.route('/hash')\ndef h():\n    return hashlib.md5(request.args['p'].encode()).hexdigest()\n\nif __name__ == '__main__':\n    app.run(debug=True)`,
  "PHP / legacy": `<?php\n$pass = "P@ssw0rd_admin_2024";\n$id = $_GET['id'];\n$res = mysqli_query($conn, "SELECT * FROM accounts WHERE id = $id");\necho "Welcome " . $_GET['name'];\ninclude($_GET['page'] . ".php");\n$data = unserialize($_POST['blob']);\n?>`,
};

// ---- State + rendering ------------------------------------------------------
let _root = null;
let S = null;

function freshState() {
  return { code: "", result: null, tree: null, risk: null, tab: "analyze", ai: "", aiBusy: false, sentGraph: false };
}

const CSS = `
#tf-root{--tf-acc:var(--acc,#2563eb);width:100%;color:var(--txt);font-size:.9rem;line-height:1.5}
#tf-root *{box-sizing:border-box}
.tf-head{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:14px}
.tf-mark{font-weight:800;letter-spacing:.14em;font-size:1.05rem;color:var(--txt)}
.tf-mark b{color:var(--tf-acc)}
.tf-badge{font-size:.6rem;font-weight:700;letter-spacing:.08em;padding:3px 7px;border-radius:4px;background:color-mix(in srgb,var(--tf-acc) 18%,transparent);color:var(--tf-acc);border:1px solid color-mix(in srgb,var(--tf-acc) 40%,transparent)}
.tf-tag{font-size:.72rem;color:var(--mut)}
.tf-tabs{display:flex;gap:6px;flex-wrap:wrap;border-bottom:1px solid var(--line);margin-bottom:16px;padding-bottom:8px}
.tf-tab{background:transparent;border:1px solid var(--line);color:var(--mut);padding:7px 14px;border-radius:4px;font:inherit;font-size:.78rem;cursor:pointer;white-space:nowrap;transition:all .15s}
.tf-tab:hover{color:var(--txt);border-color:color-mix(in srgb,var(--tf-acc) 45%,var(--line))}
.tf-tab.on{color:var(--tf-acc);border-color:var(--tf-acc);background:color-mix(in srgb,var(--tf-acc) 10%,transparent);font-weight:600}
.tf-tab:disabled{opacity:.4;cursor:not-allowed}
.tf-panel{min-height:200px}
.tf-ta{width:100%;min-height:260px;background:var(--card,#fff);color:var(--txt);border:1px solid var(--line);border-radius:6px;padding:12px;font-family:ui-monospace,"JetBrains Mono",monospace;font-size:.82rem;resize:vertical}
.tf-row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:12px 0}
.tf-btn{background:var(--tf-acc);color:#fff;border:none;padding:9px 16px;border-radius:4px;font:inherit;font-weight:600;font-size:.82rem;cursor:pointer;transition:filter .15s}
.tf-btn:hover{filter:brightness(1.08)}
.tf-btn:disabled{opacity:.5;cursor:not-allowed}
.tf-btn.ghost{background:transparent;color:var(--txt);border:1px solid var(--line)}
.tf-btn.ghost:hover{border-color:var(--tf-acc);color:var(--tf-acc)}
.tf-samples{display:flex;gap:6px;flex-wrap:wrap}
.tf-chip{background:transparent;border:1px solid var(--line);color:var(--mut);padding:5px 11px;border-radius:999px;font:inherit;font-size:.74rem;cursor:pointer}
.tf-chip:hover{border-color:var(--tf-acc);color:var(--tf-acc)}
.tf-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin:14px 0}
.tf-kpi{background:var(--card,#fff);border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.tf-kpi-v{font-size:1.5rem;font-weight:800;line-height:1}
.tf-kpi-l{font-size:.68rem;color:var(--mut);text-transform:uppercase;letter-spacing:.06em;margin-top:5px}
.tf-grade{display:inline-flex;align-items:center;justify-content:center;width:44px;height:44px;border-radius:10px;font-weight:800;font-size:1.3rem;border:1px solid var(--line);background:var(--card,#fff)}
.tf-note{font-size:.74rem;color:var(--mut);background:color-mix(in srgb,var(--tf-acc) 7%,transparent);border:1px solid var(--line);border-left:3px solid var(--tf-acc);border-radius:4px;padding:9px 12px;margin:10px 0}
.tf-empty{color:var(--mut);text-align:center;padding:40px 0}
.tf-tbl{width:100%;border-collapse:collapse;font-size:.8rem}
.tf-tbl th{text-align:left;color:var(--mut);font-weight:600;font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;padding:8px 10px;border-bottom:1px solid var(--line)}
.tf-tbl td{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
.tf-tbl tr:hover td{background:color-mix(in srgb,var(--tf-acc) 5%,transparent)}
.tf-pill{display:inline-block;font-size:.66rem;font-weight:700;padding:2px 7px;border-radius:4px;white-space:nowrap;border:1px solid var(--line);background:var(--card,#fff)}
.tf-s5{color:#b00020;border-color:color-mix(in srgb,#b00020 45%,var(--line))}
.tf-s4{color:#c0501b;border-color:color-mix(in srgb,#c0501b 45%,var(--line))}
.tf-s3{color:#8a6d00;border-color:color-mix(in srgb,#8a6d00 45%,var(--line))}
.tf-s2{color:var(--mut);border-color:var(--line)}
.tf-s1{color:var(--mut);border-color:var(--line)}
.tf-conf{font-size:.66rem;color:var(--mut)}
.tf-confirmed{display:inline-block;font-size:.6rem;font-weight:800;letter-spacing:.06em;padding:2px 7px;border-radius:4px;color:#b00020;border:1px solid color-mix(in srgb,#b00020 55%,var(--line));background:color-mix(in srgb,#b00020 7%,transparent);white-space:nowrap}
.tf-flow{font-family:ui-monospace,"JetBrains Mono",monospace;font-size:.68rem;color:var(--mut);margin-top:3px;line-height:1.5;word-break:break-word}
.tf-flow b{color:var(--txt)}
.tf-weight{font-size:.64rem;color:var(--mut);white-space:nowrap}
.tf-code{font-family:ui-monospace,"JetBrains Mono",monospace;font-size:.74rem;color:var(--mut);background:var(--card,#fff);padding:2px 5px;border-radius:3px;display:inline-block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tf-ref{font-size:.68rem;color:var(--mut)}
.tf-ref a,.tf-ref span{color:var(--tf-acc)}
.tf-tree{list-style:none;margin:0;padding:0}
.tf-tree ul{list-style:none;margin:0 0 0 20px;padding:6px 0 0;border-left:1px dashed var(--line)}
.tf-tnode{padding:4px 0}
.tf-tgoal{display:flex;align-items:center;gap:8px;cursor:pointer;padding:8px 10px;border:1px solid var(--line);border-radius:6px;background:var(--card,#fff);margin-bottom:4px}
.tf-tgoal:hover{border-color:var(--tf-acc)}
.tf-tgoal .tf-caret{transition:transform .15s;color:var(--mut)}
.tf-tgoal.col .tf-caret{transform:rotate(-90deg)}
.tf-tleaf{display:flex;align-items:flex-start;gap:8px;padding:6px 10px;margin-left:8px}
.tf-dot{width:8px;height:8px;border-radius:50%;flex:none;margin-top:5px;background:var(--c,var(--mut))}
.tf-matrix{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px}
.tf-mcard{background:var(--card,#fff);border:1px solid var(--line);border-radius:8px;padding:12px}
.tf-mcard h4{margin:0 0 6px;font-size:.82rem;color:var(--tf-acc)}
.tf-mcard .tf-ref{display:block;margin:3px 0}
.tf-aiout{background:var(--card,#fff);border:1px solid var(--line);border-radius:8px;padding:14px;white-space:pre-wrap;font-size:.82rem;min-height:60px}
.tf-sec-h{font-size:.8rem;font-weight:700;color:var(--txt);margin:18px 0 8px;text-transform:uppercase;letter-spacing:.05em}
`;

function shellHTML() {
  return "<style>" + CSS + "</style>" +
    '<div id="tf-root">' +
    '<div class="tf-head"><span class="tf-mark">THREAT<b>FOREST</b></span>' +
    '<span class="tf-badge">CODE &rarr; ATTACK TREES</span>' +
    '<span class="tf-tag">Static analysis &middot; MITRE ATT&amp;CK &middot; CWE &middot; CAPEC &middot; STRIDE</span></div>' +
    '<nav class="tf-tabs" id="tf-tabs"></nav>' +
    '<section class="tf-panel" id="tf-panel"></section>' +
    "</div>";
}

const TABS = [
  { id: "analyze", name: "Analyze" },
  { id: "tree", name: "Attack Tree" },
  { id: "findings", name: "Findings" },
  { id: "attack", name: "ATT&CK / CAPEC" },
  { id: "mitigations", name: "Mitigations" },
  { id: "report", name: "Report" },
];

function renderTabs() {
  const nav = _root && _root.querySelector("#tf-tabs");
  if (!nav) return;
  nav.innerHTML = TABS.map((t) => {
    const needsResult = t.id !== "analyze";
    const dis = needsResult && !S.result ? " disabled" : "";
    return '<button class="tf-tab' + (t.id === S.tab ? " on" : "") + '" data-tab="' + t.id + '"' + dis + ">" + esc(t.name) + "</button>";
  }).join("");
  nav.querySelectorAll(".tf-tab").forEach((b) => { b.onclick = () => { if (b.disabled) return; S.tab = b.dataset.tab; renderTabs(); renderPanel(); }; });
}

function renderPanel() {
  const p = _root && _root.querySelector("#tf-panel");
  if (!p) return;
  if (S.tab === "analyze") return paintAnalyze(p);
  if (!S.result) { p.innerHTML = '<p class="tf-empty">Run an analysis first.</p>'; return; }
  if (S.tab === "tree") return paintTree(p);
  if (S.tab === "findings") return paintFindings(p);
  if (S.tab === "attack") return paintAttack(p);
  if (S.tab === "mitigations") return paintMitigations(p);
  if (S.tab === "report") return paintReport(p);
}

// ---- Analyze tab ----
function paintAnalyze(p) {
  p.innerHTML =
    '<p class="tf-tag" style="margin:0 0 4px">Paste source code to build its attack tree.</p>' +
    '<p class="tf-tag" style="margin:0 0 10px">Any language, one or many files. Everything is analysed locally in your browser &mdash; nothing is uploaded unless you run the optional AI deep-dive.</p>' +
    '<div class="tf-samples">Load an example: ' + Object.keys(SAMPLES).map((k) => '<button class="tf-chip" data-sample="' + esc(k) + '">' + esc(k) + "</button>").join("") + "</div>" +
    '<textarea class="tf-ta" id="tf-code" spellcheck="false" placeholder="Paste source code here">' + esc(S.code) + "</textarea>" +
    '<div class="tf-row">' +
    '<button class="tf-btn" id="tf-run">Build attack tree</button>' +
    '<button class="tf-btn ghost" id="tf-clear">Clear</button>' +
    '<span class="tf-tag" id="tf-stat"></span></div>' +
    (S.result ? summaryHTML() : "");
  p.querySelectorAll("[data-sample]").forEach((b) => b.onclick = () => {
    S.code = SAMPLES[b.dataset.sample] || "";
    const ta = p.querySelector("#tf-code"); if (ta) ta.value = S.code;
  });
  p.querySelector("#tf-clear").onclick = () => { S.code = ""; S.result = null; renderTabs(); paintAnalyze(p); };
  p.querySelector("#tf-run").onclick = () => {
    const ta = p.querySelector("#tf-code"); S.code = ta ? ta.value : "";
    if (!S.code.trim()) { const st = p.querySelector("#tf-stat"); if (st) st.textContent = "Paste some code first."; return; }
    const t0 = performance.now();
    S.result = analyze(S.code);
    S.tree = buildTree(S.result.findings);
    S.risk = riskScore(S.result.findings);
    S.sentGraph = false; S.ai = "";
    const ms = Math.max(1, Math.round(performance.now() - t0));
    S._ms = ms;
    S.tab = "tree"; renderTabs(); renderPanel();
  };
}

function summaryHTML() {
  const r = S.risk, res = S.result;
  const chColor = (r.by[5] + r.by[4]) ? "#b00020" : "#1b7f4d";
  return "" +
    '<div class="tf-kpis">' +
    '<div class="tf-kpi"><div class="tf-kpi-v"><span class="tf-grade ' + sevClass(r.score >= 55 ? 5 : r.score >= 35 ? 4 : r.score >= 15 ? 3 : 2) + '">' + r.grade + "</span></div><div class=\"tf-kpi-l\">Risk grade</div></div>" +
    '<div class="tf-kpi"><div class="tf-kpi-v">' + r.score + '</div><div class="tf-kpi-l">Risk score / 100</div></div>' +
    '<div class="tf-kpi"><div class="tf-kpi-v">' + res.findings.length + '</div><div class="tf-kpi-l">Weaknesses</div></div>' +
    '<div class="tf-kpi"><div class="tf-kpi-v" style="color:' + chColor + '">' + (r.by[5] + r.by[4]) + '</div><div class="tf-kpi-l">Critical + High</div></div>' +
    '<div class="tf-kpi"><div class="tf-kpi-v">' + (S.tree ? S.tree.branches.length : 0) + '</div><div class="tf-kpi-l">Attack paths</div></div>' +
    '<div class="tf-kpi"><div class="tf-kpi-v" style="color:' + (res.confirmed ? "#b00020" : "var(--mut)") + '">' + (res.confirmed || 0) + '</div><div class="tf-kpi-l">Confirmed flows</div></div>' +
    "</div>" +
    '<p class="tf-note">Analyzed ' + res.loc + " lines" + (res.langs.length ? " (" + esc(res.langs.join(", ")) + ")" : "") +
    (S._ms ? " in " + S._ms + " ms" : "") + ". " +
    (res.confirmed ? res.confirmed + " path(s) were <b>confirmed reachable</b> by the JS/TS data-flow engine (traced source&rarr;sink); " : "") +
    "other findings are heuristic and advisory &mdash; verify high-confidence findings first.</p>";
}

// ---- Attack tree tab ----
function paintTree(p) {
  if (!S.tree.branches.length) { p.innerHTML = '<p class="tf-empty">No attack paths found. Either the code is clean of the patterns ThreatForest checks, or paste more of it.</p>'; return; }
  const branches = S.tree.branches.map((b) => {
    const leaves = b.leaves.map((l) => {
      const label = l.reach
        ? '<span class="tf-confirmed">CONFIRMED REACHABLE</span>'
        : (l.coloc ? '<span class="tf-conf">&middot; ' + esc(l.coloc.text) + "</span>" : "");
      const path = l.reach && l.reach.flow && l.reach.flow.length
        ? '<div class="tf-flow">Traced path: ' + l.reach.flow.map((s, i, a) =>
            (i === 0 || i === a.length - 1 ? "<b>" + esc(s.label) + "</b>" : esc(s.label)) + " (line " + s.line + ")"
          ).join(" &rarr; ") + "</div>"
        : "";
      return '<li class="tf-tleaf"><span class="tf-dot" style="--c:' + SEV_COLOR[l.sev] + '"></span>' +
        "<div><div><b>" + esc(l.title) + '</b> <span class="tf-pill ' + sevClass(l.sev) + '">' + SEV_LABEL[l.sev] + "</span> " + label + "</div>" +
        '<div class="tf-ref">line ' + l.line + " &middot; " + esc(l.cwe) + " &middot; " + esc((l.att[0] || "")) +
        ' &middot; <span class="tf-weight">likelihood ~' + Math.round((l.weight ? l.weight.p : 0) * 100) + "% (heuristic)</span></div>" + path + "</div></li>";
    }).join("");
    const bw = b.weight ? ' <span class="tf-weight">&middot; path likelihood ~' + Math.round(b.weight.p * 100) + "% (heuristic)</span>" : "";
    return '<li class="tf-tnode"><div class="tf-tgoal" data-g="' + esc(b.goal) + '">' +
      '<span class="tf-caret">&#9660;</span><span class="tf-dot" style="--c:' + SEV_COLOR[b.sev] + '"></span>' +
      "<b>" + esc(b.name) + '</b> <span class="tf-tag">(' + b.leaves.length + ")</span>" +
      (b.confirmed ? ' <span class="tf-confirmed">HAS CONFIRMED PATH</span>' : "") + bw + "</div><ul>" + leaves + "</ul></li>";
  }).join("");
  p.innerHTML = '<p class="tf-tag" style="margin:0 0 6px"><b>Goal:</b> ' + esc(S.tree.root) + " &mdash; click a path to collapse. Each leaf is a concrete weakness that advances that goal.</p>" +
    '<p class="tf-tag" style="margin:0 0 6px"><span class="tf-confirmed">CONFIRMED REACHABLE</span> nodes (JavaScript/TypeScript) were traced end-to-end by the data-flow engine &mdash; the exact path is shown. Act on these first.</p>' +
    '<p class="tf-tag" style="margin:0 0 6px">Co-location labels (&ldquo;untrusted input used on this line&rdquo; / &ldquo;near untrusted input&rdquo;) are lexical heuristics for the regex-derived nodes, NOT proven call-graph reachability &mdash; confirm the data flow before acting.</p>' +
    '<p class="tf-tag" style="margin:0 0 12px">Likelihood percentages are a transparent ranking heuristic (from severity + evidence strength), not measured exploit probabilities.</p>' +
    '<ul class="tf-tree">' + branches + "</ul>" +
    '<div class="tf-row" style="margin-top:16px"><button class="tf-btn ghost" id="tf-graph"' + (S.sentGraph ? " disabled" : "") + ">" + (S.sentGraph ? "Sent to Security Graph" : "Send to Security Graph") + "</button></div>";
  p.querySelectorAll(".tf-tgoal").forEach((el) => el.onclick = () => {
    el.classList.toggle("col");
    const ul = el.nextElementSibling; if (ul) ul.style.display = el.classList.contains("col") ? "none" : "";
  });
  const gb = p.querySelector("#tf-graph"); if (gb) gb.onclick = () => sendGraph(gb);
}

// ---- Findings tab ----
function paintFindings(p) {
  if (!S.result.findings.length) { p.innerHTML = '<p class="tf-empty">No weaknesses detected.</p>'; return; }
  const rows = S.result.findings.map((f) => {
    const sub = f.reach
      ? '<span class="tf-confirmed">CONFIRMED REACHABLE</span> <span class="tf-conf">&middot; ' + esc(f.reach.text) + "</span>" +
        (f.reach.flow && f.reach.flow.length ? '<div class="tf-flow">' + f.reach.flow.map((s) => esc(s.label) + " (L" + s.line + ")").join(" &rarr; ") + "</div>" : "")
      : '<span class="tf-conf">confidence: ' + esc(f.confidence) + (f.coloc ? " &middot; " + esc(f.coloc.text) : "") + "</span>";
    return "<tr><td><span class=\"tf-pill " + sevClass(f.sev) + '">' + SEV_LABEL[f.sev] + "</span></td>" +
      "<td><b>" + esc(f.title) + "</b><br>" + sub + "</td>" +
      "<td>" + f.line + "</td>" +
      '<td><span class="tf-code">' + esc(f.excerpt) + "</span></td>" +
      '<td class="tf-ref">' + esc(f.cwe) + "<br>" + esc(f.capec) + "</td></tr>";
  }).join("");
  p.innerHTML = '<table class="tf-tbl"><thead><tr><th>Severity</th><th>Weakness</th><th>Line</th><th>Evidence</th><th>Refs</th></tr></thead><tbody>' + rows + "</tbody></table>";
}

// ---- ATT&CK / CAPEC tab ----
function paintAttack(p) {
  const tech = {};
  for (const f of S.result.findings) for (const a of f.att) {
    const id = a.split(" ")[0];
    tech[a] = tech[a] || { name: a, id, count: 0, cwes: new Set(), capecs: new Set() };
    tech[a].count++; tech[a].cwes.add(f.cwe); tech[a].capecs.add(f.capec);
  }
  const list = Object.values(tech).sort((a, b) => b.count - a.count);
  if (!list.length) { p.innerHTML = '<p class="tf-empty">No techniques mapped.</p>'; return; }
  const cards = list.map((t) => {
    const tid = t.id.split(".")[0];
    return '<div class="tf-mcard"><h4>' + esc(t.name) + "</h4>" +
      '<div class="tf-ref">Hits: <b>' + t.count + "</b></div>" +
      '<div class="tf-ref">CWE: ' + esc(Array.from(t.cwes).join(", ")) + "</div>" +
      '<div class="tf-ref">CAPEC: ' + esc(Array.from(t.capecs).join(", ")) + "</div>" +
      '<div class="tf-ref"><a href="https://attack.mitre.org/techniques/' + esc(tid.replace(".", "/")) + '/" target="_blank" rel="noopener">MITRE ' + esc(t.id) + " &nearr;</a></div></div>";
  }).join("");
  p.innerHTML = '<p class="tf-tag" style="margin:0 0 12px">' + list.length + " ATT&amp;CK technique(s) mapped deterministically from the detected weaknesses &mdash; no embedding guesswork.</p>" +
    '<div class="tf-matrix">' + cards + "</div>";
}

// ---- Mitigations tab ----
function paintMitigations(p) {
  const seen = {}, groups = [];
  for (const f of S.result.findings) {
    if (seen[f.rid]) continue; seen[f.rid] = 1;
    groups.push(f);
  }
  groups.sort((a, b) => b.sev - a.sev);
  const rows = groups.map((f) =>
    '<div class="tf-mcard" style="margin-bottom:10px"><h4>' + esc(f.title) + ' <span class="tf-pill ' + sevClass(f.sev) + '">' + SEV_LABEL[f.sev] + "</span></h4>" +
    "<div style=\"margin:6px 0\">" + esc(f.fix) + "</div>" +
    '<div class="tf-ref">' + esc(f.cwe) + " &middot; " + esc(f.capec) + " &middot; STRIDE: " + esc(f.stride) + "</div></div>"
  ).join("");
  p.innerHTML = '<p class="tf-sec-h">Prioritised remediation (' + groups.length + " weakness classes)</p>" + rows +
    '<div class="tf-row" style="margin-top:14px">' +
    '<button class="tf-btn" id="tf-ai"' + (S.aiBusy ? " disabled" : "") + ">" + (S.aiBusy ? "Thinking…" : "AI deep-dive & extra attack paths") + "</button>" +
    '<span class="tf-tag">Optional: sends the findings (not your full code) to Darknode AI for a prioritised, context-aware remediation plan.</span></div>' +
    (S.ai ? '<div class="tf-aiout" id="tf-aiout" style="margin-top:12px">' + esc(S.ai) + "</div>" : '<div class="tf-aiout" id="tf-aiout" style="margin-top:12px;display:none"></div>');
  const ab = p.querySelector("#tf-ai"); if (ab) ab.onclick = () => runAI(p);
}

// ---- Report tab ----
function toMarkdown() {
  const r = S.risk, res = S.result;
  let md = "# ThreatForest report\n\n";
  md += "- **Risk grade:** " + r.grade + " (" + r.score + "/100)\n";
  md += "- **Lines analyzed:** " + res.loc + (res.langs.length ? " (" + res.langs.join(", ") + ")" : "") + "\n";
  md += "- **Weaknesses:** " + res.findings.length + " (critical " + r.by[5] + ", high " + r.by[4] + ", medium " + r.by[3] + ", low " + r.by[2] + ")\n\n";
  md += "## Attack tree\n\nGoal: " + S.tree.root + "\n\n";
  for (const b of S.tree.branches) {
    md += "- **" + b.name + "**" + (b.weight ? " _(path likelihood ~" + Math.round(b.weight.p * 100) + "%, heuristic)_" : "") + "\n";
    for (const l of b.leaves) {
      md += "  - " + l.title + " (" + SEV_LABEL[l.sev] + ", line " + l.line + ", " + l.cwe + ", " + (l.att[0] || "") + ")";
      md += l.reach ? " — CONFIRMED REACHABLE: " + l.reach.flow.map((s) => s.label + " (L" + s.line + ")").join(" -> ") + "\n"
                    : (l.coloc ? " — " + l.coloc.text + "\n" : "\n");
    }
  }
  md += "\n## Findings\n\n| Sev | Weakness | Line | CWE | CAPEC |\n|---|---|---|---|---|\n";
  for (const f of res.findings) md += "| " + SEV_LABEL[f.sev] + " | " + f.title + " | " + f.line + " | " + f.cwe + " | " + f.capec + " |\n";
  md += "\n## Remediation\n\n";
  const seen = {};
  for (const f of res.findings) { if (seen[f.rid]) continue; seen[f.rid] = 1; md += "- **" + f.title + ":** " + f.fix + "\n"; }
  if (S.ai) md += "\n## AI deep-dive\n\n" + S.ai + "\n";
  md += "\n---\n_ThreatForest (Darknode). For JavaScript/TypeScript, nodes marked CONFIRMED REACHABLE were traced end-to-end by the data-flow engine; all other source->sink labels are lexical co-location, not call-graph reachability. Likelihood percentages are a ranking heuristic, not measured probabilities. Verify before acting._\n";
  return md;
}
function paintReport(p) {
  const md = toMarkdown();
  p.innerHTML =
    '<div class="tf-row"><button class="tf-btn" id="tf-copy">Copy Markdown</button>' +
    '<button class="tf-btn ghost" id="tf-json">Download JSON</button>' +
    '<button class="tf-btn ghost" id="tf-md">Download .md</button></div>' +
    '<textarea class="tf-ta" readonly style="min-height:340px">' + esc(md) + "</textarea>";
  p.querySelector("#tf-copy").onclick = () => {
    navigator.clipboard && navigator.clipboard.writeText(md);
    const b = p.querySelector("#tf-copy"); b.textContent = "Copied"; setTimeout(() => (b.textContent = "Copy Markdown"), 1200);
  };
  p.querySelector("#tf-json").onclick = () => download("threatforest-report.json", JSON.stringify({ risk: S.risk, result: S.result, tree: S.tree, ai: S.ai }, null, 2), "application/json");
  p.querySelector("#tf-md").onclick = () => download("threatforest-report.md", md, "text/markdown");
}
function download(name, data, type) {
  try {
    const blob = new Blob([data], { type: type });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = name;
    document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 100);
  } catch (_) {}
}

// ---- AI deep-dive (optional, one streaming pass via the Darknode proxy) ----
function proxyUrl() { try { if (window.DARKNODE_PROXY_URL) return window.DARKNODE_PROXY_URL; } catch (_) {} return "/api/chat"; }
async function runAI(p) {
  if (S.aiBusy) return;
  S.aiBusy = true; S.ai = ""; paintMitigations(p);
  const out = p.querySelector("#tf-aiout");
  if (out) { out.style.display = ""; out.textContent = ""; }
  const brief = S.result.findings.slice(0, 40).map((f) => "- " + f.title + " (" + SEV_LABEL[f.sev] + ", " + f.cwe + ", line " + f.line + ")").join("\n");
  const sys = "You are a senior application-security engineer. You are given a list of statically-detected weaknesses from a codebase. Produce: (1) the single most urgent fix and why, (2) any additional attack paths that chain these weaknesses together, (3) a short prioritised remediation checklist. Be concrete and terse. Do not repeat the raw list.";
  const user = "Weaknesses found (" + S.result.findings.length + " total, top shown):\n" + brief + "\n\nLanguages: " + (S.result.langs.join(", ") || "unknown") + ".";
  try {
    const r = await fetch(proxyUrl(), {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ provider: "gemini", model: "gemini-flash-latest", messages: [{ role: "system", content: sys }, { role: "user", content: user }] }),
    });
    if (!r.ok || !r.body) throw new Error("AI service " + r.status);
    const reader = r.body.getReader(), dec = new TextDecoder(); let buf = "";
    for (;;) {
      const { done, value } = await reader.read(); if (done) break;
      buf += dec.decode(value, { stream: true });
      let nl; while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1);
        if (!line.startsWith("data: ")) continue;
        const pl = line.slice(6); if (pl === "[DONE]") break;
        try { const j = JSON.parse(pl); const d = j.choices && j.choices[0] && j.choices[0].delta; if (d && d.content) { S.ai += d.content; if (out) out.textContent = S.ai; } } catch (_) {}
      }
    }
    if (!S.ai) S.ai = "The AI service returned no content. The deterministic findings above are complete on their own.";
  } catch (e) {
    S.ai = "AI deep-dive unavailable (" + (e && e.message ? e.message : "offline") + "). The deterministic analysis above is complete without it.";
    if (out) { out.style.display = ""; out.textContent = S.ai; }
  }
  S.aiBusy = false;
  const ab = p.querySelector("#tf-ai"); if (ab) { ab.disabled = false; ab.textContent = "AI deep-dive & extra attack paths"; }
}

// ---- Security Graph feed ----
function sendGraph(btn) {
  if (S.sentGraph || !S.result) return;
  btn.disabled = true; btn.textContent = "Sending…";
  import("/js/graph-bridge.js?v=20261012a").then((gb) => {
    try {
      const sevMap = { 5: "critical", 4: "high", 3: "medium", 2: "low", 1: "info" };
      const asset = gb.sendToGraph("ThreatForest", [{
        type: "ASSET", name: "ThreatForest scan (" + (S.result.langs.join("/") || "code") + ")",
        data: { lines: S.result.loc, weaknesses: S.result.findings.length, riskScore: S.risk.score, grade: S.risk.grade, _tool: "threatforest" },
        opts: { tags: ["threatforest", "sast"] },
      }], undefined, true).entities[0];
      gb.batchGraph(() => {
        const findItems = S.result.findings.slice(0, 60).map((f) => ({
          type: "VULNERABILITY", name: f.title + " @ line " + f.line,
          data: { cwe: f.cwe, capec: f.capec, attack: (f.att[0] || ""), stride: f.stride, confidence: f.confidence, reachable: !!f.reach, evidence: f.excerpt, _goal: f.goal },
          opts: { tags: ["threatforest", f.goal], severity: sevMap[f.sev] },
        }));
        const out = gb.sendToGraph("ThreatForest", findItems, undefined, true);
        if (asset) out.entities.forEach((e) => { if (e) try { gb.linkEntities(asset.id, e.id, "contains"); } catch (_) {} });
        // techniques
        const techNames = {};
        S.result.findings.forEach((f) => f.att.forEach((a) => (techNames[a] = 1)));
        const techItems = Object.keys(techNames).map((a) => ({ type: "TECHNIQUE", name: a, data: { _tool: "threatforest" }, opts: { tags: ["threatforest", "mitre"] } }));
        if (techItems.length) {
          const tout = gb.sendToGraph("ThreatForest", techItems, undefined, true);
          if (asset) tout.entities.forEach((e) => { if (e) try { gb.linkEntities(asset.id, e.id, "related_to"); } catch (_) {} });
        }
      });
      S.sentGraph = true;
      btn.textContent = "Sent to Security Graph";
      if (gb.showGraphToast) gb.showGraphToast("ThreatForest: " + S.result.findings.length + " weaknesses sent to the Security Graph.");
    } catch (e) {
      btn.disabled = false; btn.textContent = "Send to Security Graph";
    }
  }).catch(() => { btn.disabled = false; btn.textContent = "Send to Security Graph"; });
}

// ---- Entry points -----------------------------------------------------------
export function renderThreatforest(main) {
  S = freshState();
  main.innerHTML = shellHTML();
  _root = main.querySelector("#tf-root");
  // retint to the user's accent
  try { const acc = getComputedStyle(document.body).getPropertyValue("--acc"); if (acc && _root) _root.style.setProperty("--tf-acc", acc.trim()); } catch (_) {}
  renderTabs();
  renderPanel();
}
export function cleanupThreatforest() { _root = null; S = null; }
