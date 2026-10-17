// Endpoint Fleet Compliance (fleetcomply): Deck tool UI. Runs entirely in the browser; the engine
// executes in a Worker via ../ingest/worker.js. No native dialogs; toasts only.

import { mountDropzone } from "../ingest/dropzone.js";
import { runInWorker, engineUrl } from "../ingest/worker.js";
import { summarize } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";
import { download, toJson, fileStamp } from "../core/export.js";
import { DEFAULTS, TOOL_ID, parseInput, findingsToCsv, exampleDataset } from "./fleetcomply-engine.js?v=20261016j";

const ENGINE = engineUrl("./fleetcomply-engine.js?v=20261016j", import.meta);
const P = "flt";
const toast = (m, t) => { try { (window.showToast || (() => {}))(m, t); } catch (_) {} };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

const CSS = `
  .flt-root{width:100%;font-size:14px;line-height:1.5;color:var(--tx,#1a2230)}
  .flt-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .flt-hd h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .flt-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .flt-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:70ch}
  .flt-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:14px}
  .flt-drop{border:1.5px dashed var(--line,#d7dbe3);border-radius:10px;padding:26px;text-align:center;color:var(--mut,#667085);background:var(--bg,#fbfcfe)}
  .flt-drop.over{border-color:#2552c6;background:var(--acc-soft,rgba(37,82,198,.06))}
  .flt-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:12px}
  .flt-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer}
  .flt-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .flt-btn:disabled{opacity:.5;cursor:default}
  .flt-ctl{display:flex;flex-wrap:wrap;gap:14px 20px;align-items:flex-end}
  .flt-field{display:flex;flex-direction:column;gap:4px}
  .flt-field label{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085)}
  .flt-field input{font:inherit;font-size:.84rem;color:var(--tx,#1a2230);background:var(--card,#fff);border:1px solid var(--line,#d7dbe3);border-radius:8px;padding:7px 10px;width:120px;box-sizing:border-box}
  .flt-kpis{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}
  .flt-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 16px;min-width:120px}
  .flt-kpi b{display:block;font-size:1.3rem}
  .flt-kpi span{font-size:.74rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .flt-prog{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin-top:10px;display:none}
  .flt-prog i{display:block;height:100%;width:0;background:#2552c6;transition:width .15s}
  .flt-list{border:1px solid var(--line,#e6e8ee);border-radius:12px;overflow:auto}
  .flt-list table{width:100%;border-collapse:collapse;font-size:.84rem}
  .flt-list th{text-align:left;font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:9px 14px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee)}
  .flt-list td{padding:10px 14px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:anywhere}
  .flt-list tr[data-i]{cursor:pointer}
  .flt-list tr[data-i]:hover{background:var(--bg,#f7f8fb)}
  .flt-pill{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff;background:#667085;white-space:nowrap}
  .flt-pill.critical{background:#7a0012}.flt-pill.high{background:#b00020}.flt-pill.medium{background:#b58100}.flt-pill.low{background:#2552c6}.flt-pill.info{background:#667085}
  .flt-chip{display:inline-block;font-size:.7rem;border:1px solid var(--line,#d7dbe3);border-radius:6px;padding:1px 6px;margin:1px 4px 1px 0;color:var(--mut,#667085)}
  .flt-empty{padding:28px;text-align:center;color:var(--mut,#667085)}
  .flt-drawer{margin-top:14px;display:none}
  .flt-drawer pre{margin:0;max-height:320px;overflow:auto;font-size:12px;background:var(--bg,#f7f8fb);border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:10px 12px}
  .flt-skip{font-size:.78rem;color:var(--mut,#667085);margin-top:8px}
`;

function kpi(v, l) { return '<div class="' + P + '-kpi"><b>' + esc(v) + "</b><span>" + esc(l) + "</span></div>"; }

/** Mount the tool into main. */
export function renderFleetComply(main) {
  if (!document.getElementById(P + "-css")) {
    const st = document.createElement("style"); st.id = P + "-css"; st.textContent = CSS; document.head.appendChild(st);
  }
  const fields = Object.entries(DEFAULTS).map(([k, v]) =>
    '<div class="' + P + '-field"><label for="' + P + '-opt-' + k + '">' + esc(k) + '</label><input id="' + P + '-opt-' + k + '" data-opt="' + esc(k) + '" type="number" value="' + esc(v) + '"></div>').join("");
  main.innerHTML = [
    '<div class="', P, '-root">',
    '<div class="', P, '-hd"><h1>Endpoint Fleet Compliance</h1><span class="', P, '-tag">Deck</span></div>',
    '<p class="', P, '-sub">Check Intune, Jamf, CrowdStrike, Defender and workstation audit exports for missing encryption, stale EDR, end-of-life operating systems, patch age and local admins. Runs entirely in your browser. Nothing is uploaded.</p>',
    '<div class="', P, '-card"><div class="', P, '-drop" id="', P, '-drop">Drop a CSV or JSON export here, or click to choose a file.</div>',
    '<div class="', P, '-row"><button class="', P, '-btn" id="', P, '-example">Load example (synthetic)</button>',
    '<button class="', P, '-btn pri" id="', P, '-run" disabled>Analyze</button><span id="', P, '-file" class="', P, '-skip"></span></div>',
    '<div class="', P, '-prog" id="', P, '-prog"><i></i></div></div>',
    '<div class="', P, '-card"><div class="', P, '-ctl">', fields, "</div></div>",
    '<div class="', P, '-kpis" id="', P, '-kpis"></div>',
    '<div class="', P, '-row" id="', P, '-exports"></div>',
    '<div class="', P, '-list" id="', P, '-list"><div class="', P, '-empty">No analysis yet.</div></div>',
    '<div class="', P, '-skip" id="', P, '-skipped"></div>',
    '<div class="', P, '-drawer" id="', P, '-drawer"></div>',
    "</div>",
  ].join("");

  const $ = (id) => main.querySelector("#" + P + "-" + id);
  let rows = [], result = null, fileName = "", isExample = false;

  const setRows = (r, name, example = false) => {
    rows = r; fileName = name; isExample = example;
    $("file").textContent = r.length ? name + ": " + r.length + " rows" : "";
    $("run").disabled = !r.length;
  };

  mountDropzone($("drop"), {
    maxBytes: 50 * 1024 * 1024,
    maxFiles: 1,
    onFiles: async (files) => {
      const f = files[0]; if (!f) return;
      const parsed = parseInput(await f.text());
      if (!parsed.rows.length) { toast("No rows found in " + f.name, "error"); return; }
      setRows(parsed.rows, f.name);
      toast("Loaded " + parsed.rows.length + " rows (" + parsed.format + ")");
    },
  });

  $("example").addEventListener("click", () => {
    const ex = exampleDataset();
    setRows(ex.rows, ex.label, true);
  });

  const opts = () => {
    const o = {};
    main.querySelectorAll("[data-opt]").forEach((el) => { const n = Number(el.value); if (Number.isFinite(n)) o[el.dataset.opt] = n; });
    return o;
  };

  $("run").addEventListener("click", async () => {
    const prog = $("prog"), bar = prog.firstElementChild;
    prog.style.display = "block"; bar.style.width = "0%"; $("run").disabled = true;
    try {
      result = await runInWorker(ENGINE, "analyze", [rows, opts()], {
        onProgress: (i, n) => { bar.style.width = (n ? Math.round(i / n * 100) : 0) + "%"; },
      });
      render(result);
      toast(result.findings.length + " finding(s)");
    } catch (e) {
      toast("Analysis failed: " + (e && e.message || e), "error");
    } finally {
      prog.style.display = "none"; $("run").disabled = !rows.length;
    }
  });

  function render(r) {
    const sum = summarize(r.findings);
    $("kpis").innerHTML = kpi(r.meta.rows, "rows") + kpi(r.findings.length, "findings") +
      ["critical", "high", "medium", "low"].map((s) => kpi(r.summary.bySeverity[s] || 0, s)).join("");
    $("skipped").textContent = r.skipped.length ? "Skipped checks: " + r.skipped.map((s) => s.check + " (" + s.reason + ")").join("; ") : "";
    const ex = $("exports");
    ex.innerHTML = '<button class="' + P + '-btn" data-x="csv">Export CSV</button><button class="' + P + '-btn" data-x="json">Export JSON</button><button class="' + P + '-btn" data-x="txt">Summary TXT</button>';
    ex.querySelector('[data-x="csv"]').addEventListener("click", () => download(TOOL_ID + "-" + fileStamp() + ".csv", findingsToCsv(r.findings), "text/csv"));
    ex.querySelector('[data-x="json"]').addEventListener("click", () => download(TOOL_ID + "-" + fileStamp() + ".json", toJson(r), "application/json"));
    ex.querySelector('[data-x="txt"]').addEventListener("click", () => download(TOOL_ID + "-" + fileStamp() + ".txt", summaryText(r, sum), "text/plain"));
    attachSinkButton(ex, () => ({ findings: r.findings, sample: isExample }), TOOL_ID, { dataset: fileName });
    const list = $("list");
    if (!r.findings.length) { list.innerHTML = '<div class="' + P + '-empty">No findings for the current thresholds.</div>'; return; }
    list.innerHTML = "<table><thead><tr><th>Severity</th><th>Finding</th><th>Confidence</th><th>Controls</th><th>Evidence</th></tr></thead><tbody>" +
      r.findings.map((f, i) => "<tr data-i=\"" + i + "\"><td><span class=\"" + P + "-pill " + esc(f.severity) + "\">" + esc(f.severity) + "</span></td><td><b>" + esc(f.title) + "</b><div>" + esc(f.description) + "</div></td><td>" + Math.round((f.confidence || 0) * 100) + "%</td><td>" +
        (f.controls || []).map((c) => '<span class="' + P + '-chip">' + esc(c.framework + " " + c.id) + "</span>").join("") + "</td><td>" + (f.evidence || []).length + "</td></tr>").join("") + "</tbody></table>";
    list.querySelectorAll("tr[data-i]").forEach((tr) => tr.addEventListener("click", () => {
      const f = r.findings[Number(tr.dataset.i)];
      const d = $("drawer"); d.style.display = "block";
      d.innerHTML = '<div class="' + P + '-card"><b>' + esc(f.title) + "</b><p>" + esc(f.recommendation) + "</p><pre>" + esc(JSON.stringify(f.evidence, null, 2)) + "</pre></div>";
    }));
  }

  function summaryText(r, sum) {
    return ["Endpoint Fleet Compliance summary", "Rows: " + r.meta.rows, "Findings: " + r.findings.length, "Severity: " + JSON.stringify(r.summary.bySeverity), "", "Summary: " + JSON.stringify(sum)]
      .concat(r.findings.map((f) => "- [" + f.severity + "] " + f.title + " - " + f.recommendation)).join("\n");
  }
}
