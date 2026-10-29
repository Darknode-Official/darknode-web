// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Data Protection (DLP) scanner — finds secrets and PII in pasted text or dropped
// files and produces an exposure report plus a redacted copy. Everything runs in the
// browser: nothing is uploaded, nothing leaves the page. See dlp-engine.js for the
// pure, tested detectors.
//
//   renderDlp(main) -> void

import { scan, redact, DETECTORS } from "/js/dataprotect/dlp-engine.js?v=20261028c";
import { attachSinkButton } from "../core/sink.js";
import { dlpFindings } from "/js/dataprotect/dp-sink.js";

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const toast = (m) => { try { (window.showToast || (() => {}))(m); } catch (_) {} };

const SEV = {
  critical: { label: "Critical", c: "#b00020" },
  high:     { label: "High",     c: "#d9480f" },
  medium:   { label: "Medium",   c: "#b58100" },
  low:      { label: "Low",      c: "#2f7d9e" },
};
const GRADE = {
  clean:    { label: "No sensitive data found", c: "#2f9e56" },
  low:      { label: "Low exposure",            c: "#2f7d9e" },
  elevated: { label: "Elevated exposure",       c: "#b58100" },
  high:     { label: "High exposure",           c: "#d9480f" },
  critical: { label: "Critical exposure",       c: "#b00020" },
};

let injected = false;
function injectStyle() {
  if (injected) return; injected = true;
  const st = document.createElement("style"); st.id = "dlp-css";
  st.textContent = `
  .dlp{width:100%;font-size:14px;line-height:1.5}
  .dlp .dlp-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .dlp h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .dlp .dlp-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .dlp .dlp-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:74ch}
  .dlp .dlp-warn{background:var(--acc-soft,rgba(47,158,86,.08));border:1px solid var(--line,#e6e8ee);border-left:3px solid #2f9e56;border-radius:8px;padding:11px 14px;color:var(--tx,#1a2230);font-size:.84rem;margin-bottom:16px}
  .dlp .dlp-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:16px}
  .dlp h3{font-size:.95rem;margin:0 0 10px}
  .dlp .dlp-drop{border:1.5px dashed var(--line,#cdd3de);border-radius:10px;transition:border-color .12s,background .12s}
  .dlp .dlp-drop.over{border-color:#2552c6;background:var(--acc-soft,rgba(37,82,198,.05))}
  .dlp textarea{width:100%;font:inherit;font-size:.82rem;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;padding:12px 14px;border:0;border-radius:10px;background:transparent;color:var(--tx,#1a2230);box-sizing:border-box;min-height:200px;resize:vertical}
  .dlp textarea:focus{outline:none}
  .dlp .dlp-row{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-top:12px}
  .dlp .dlp-hint{color:var(--mut,#667085);font-size:.78rem;margin:6px 2px 0}
  .dlp .dlp-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer}
  .dlp .dlp-btn:hover{border-color:#9aa6bd}
  .dlp .dlp-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .dlp .dlp-btn.pri:hover{background:#1c42a6}
  .dlp .dlp-btn.sm{padding:5px 10px;font-size:.78rem}
  .dlp .dlp-btn:disabled{opacity:.5;cursor:default}
  .dlp .dlp-score{display:flex;align-items:center;gap:18px;flex-wrap:wrap}
  .dlp .dlp-grade{font-size:1.15rem;font-weight:700}
  .dlp .dlp-sevs{display:flex;gap:8px;flex-wrap:wrap}
  .dlp .dlp-sev{display:flex;align-items:center;gap:6px;font-size:.82rem;font-weight:600;padding:4px 10px;border:1px solid var(--line,#e6e8ee);border-radius:999px}
  .dlp .dlp-dot{width:9px;height:9px;border-radius:50%;background:var(--c,#999)}
  .dlp table{width:100%;border-collapse:collapse;font-size:.84rem}
  .dlp th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:8px 12px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee)}
  .dlp td{padding:9px 12px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:anywhere}
  .dlp tr:last-child td{border-bottom:0}
  .dlp .dlp-list{border:1px solid var(--line,#e6e8ee);border-radius:12px;overflow:hidden}
  .dlp .dlp-pill{display:inline-block;font-size:.68rem;font-weight:700;color:#fff;padding:2px 8px;border-radius:999px;white-space:nowrap}
  .dlp code.dlp-val{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem;background:var(--bg,#f2f4f8);padding:1px 5px;border-radius:5px}
  .dlp .dlp-loc{color:var(--mut,#667085);font-size:.78rem;white-space:nowrap}
  .dlp .dlp-advice{color:var(--mut,#667085);font-size:.78rem;margin-top:3px}
  .dlp .dlp-red{width:100%;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem;white-space:pre-wrap;word-break:break-word;background:var(--bg,#f7f8fb);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:12px 14px;max-height:340px;overflow:auto;box-sizing:border-box}
  .dlp .dlp-types{display:flex;flex-wrap:wrap;gap:8px}
  .dlp .dlp-type{display:flex;align-items:center;gap:7px;font-size:.8rem;border:1px solid var(--line,#e6e8ee);border-radius:8px;padding:6px 10px}
  .dlp .dlp-type b{font-weight:700}
  .dlp .dlp-clean{text-align:center;padding:26px 12px;color:#2f9e56;font-weight:600}
  .dlp select{font:inherit;font-size:.82rem;padding:6px 9px;border:1px solid var(--line,#d7dbe3);border-radius:8px;background:var(--card,#fff);color:var(--tx,#1a2230)}
  .dlp .dlp-opts{padding:0}
  .dlp .dlp-opts summary{cursor:pointer;font-weight:700;font-size:.9rem;padding:14px 18px;list-style:none}
  .dlp .dlp-opts summary::-webkit-details-marker{display:none}
  .dlp .dlp-opts summary::before{content:"\\25B6";font-size:.68rem;margin-right:8px;color:var(--mut,#667085)}
  .dlp .dlp-opts[open] summary::before{content:"\\25BC"}
  .dlp .dlp-optbar{display:flex;gap:8px;padding:0 18px 10px;flex-wrap:wrap}
  .dlp .dlp-optgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:16px;padding:0 18px 16px}
  .dlp .dlp-optgroup h4{margin:0 0 8px;font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;color:var(--mut,#667085);font-weight:700}
  .dlp .dlp-checks{display:flex;flex-direction:column;gap:6px}
  .dlp .dlp-check{display:flex;align-items:flex-start;gap:7px;font-size:.82rem;cursor:pointer;line-height:1.35}
  .dlp .dlp-check input[type=checkbox]{margin:2px 0 0}
  .dlp .dlp-check.dlp-num{flex-wrap:wrap;gap:7px;align-items:center}
  .dlp .dlp-check.dlp-num input[type=number]{width:72px;font:inherit;font-size:.82rem;padding:4px 7px;border:1px solid var(--line,#d7dbe3);border-radius:6px;background:var(--card,#fff);color:var(--tx,#1a2230)}
  .dlp .dlp-opthint{color:var(--mut,#667085);font-size:.74rem;margin:2px 2px 0}
  `;
  document.head.appendChild(st);
}

const SAMPLE = [
  "# dropped config — example with planted secrets",
  "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
  'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
  "DATABASE_URL=postgres://admin:Sup3rS3cret@db.internal:5432/payments", // darknode-ignore: planted fake credential in the DLP demo input
  "github_token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
  "",
  "Customer record:",
  "  name: Test User   email: test@darknode.ai",
  "  card: 4111 1111 1111 1111   ssn: 123-45-6789",
  "  iban: DE89 3704 0044 0532 0130 00",
].join("\n");

function optionsHtml() {
  const groups = {};
  for (const d of DETECTORS) (groups[d.kind] || (groups[d.kind] = [])).push(d);
  const box = (id, label) => `<label class="dlp-check"><input type="checkbox" class="dlp-det" value="${esc(id)}" checked> <span>${esc(label)}</span></label>`;
  const secretBoxes = (groups.secret || []).map((d) => box(d.id, d.label)).join("");
  const piiBoxes = (groups.pii || []).map((d) => box(d.id, d.label)).join("");
  return `
  <details class="dlp-card dlp-opts">
    <summary>Detectors &amp; options</summary>
    <div class="dlp-optbar">
      <button type="button" class="dlp-btn sm" id="dlpSelAll">Enable all</button>
      <button type="button" class="dlp-btn sm" id="dlpSelNone">Disable all</button>
    </div>
    <div class="dlp-optgrid">
      <div class="dlp-optgroup"><h4>Secrets</h4><div class="dlp-checks">${secretBoxes}</div></div>
      <div class="dlp-optgroup"><h4>Personal data (PII)</h4><div class="dlp-checks">${piiBoxes}</div></div>
      <div class="dlp-optgroup"><h4>Heuristics</h4><div class="dlp-checks">
        ${box("high-entropy", "High-entropy token sweep")}
        <label class="dlp-check"><input type="checkbox" id="dlpExclPriv"> <span>Skip private, loopback, link-local IPs and version strings</span></label>
        <label class="dlp-check dlp-num"><span>Entropy threshold</span><input type="number" id="dlpEntropy" min="2.5" max="6" step="0.1" value="4.2"></label>
        <p class="dlp-opthint">Higher = fewer high-entropy guesses. Default 4.2 bits/char.</p>
      </div></div>
    </div>
  </details>`;
}

export function renderDlp(main) {
  injectStyle();
  main.innerHTML = `
  <div class="dlp">
    <div class="dlp-hd"><h1>Data Protection Scanner</h1><span class="dlp-tag">DLP</span></div>
    <p class="dlp-sub">Find exposed secrets and personal data in documents, logs, config and exports before they leak. Paste text or drop files below.</p>
    <div class="dlp-warn"><b>Private by design.</b> Scanning runs entirely in your browser. Nothing you paste or drop is uploaded, logged or sent anywhere.</div>

    <div class="dlp-card" style="padding:0;overflow:hidden">
      <div class="dlp-drop" id="dlpDrop">
        <textarea id="dlpIn" placeholder="Paste text, a log, a .env, source, or an export here — or drop files onto this box." spellcheck="false"></textarea>
      </div>
    </div>
    <p class="dlp-hint">Files are read locally as text (no upload). Large inputs scan in one pass; binary files may show noise.</p>
    ${optionsHtml()}
    <div class="dlp-row">
      <button class="dlp-btn pri" id="dlpRun">Scan</button>
      <button class="dlp-btn" id="dlpSample">Load example</button>
      <button class="dlp-btn" id="dlpClear">Clear</button>
      <input type="file" id="dlpFile" multiple style="display:none" />
      <button class="dlp-btn" id="dlpPick">Add files…</button>
      <span class="dlp-hint" id="dlpMeta" style="margin:0"></span>
    </div>

    <div id="dlpOut" style="margin-top:18px"></div>
  </div>`;

  const $ = (id) => main.querySelector(id);
  const ta = $("#dlpIn"), out = $("#dlpOut"), meta = $("#dlpMeta");
  let last = null, sampleLoaded = false;

  const setMeta = () => {
    const n = ta.value.length;
    meta.textContent = n ? `${n.toLocaleString()} characters` : "";
  };
  ta.addEventListener("input", () => { if (!ta.value.trim()) sampleLoaded = false; setMeta(); });

  const collectOpts = () => {
    const ids = Array.from(main.querySelectorAll(".dlp-det:checked")).map((c) => c.value);
    const opts = { detectors: ids };
    const th = parseFloat($("#dlpEntropy").value);
    if (Number.isFinite(th)) opts.entropyThreshold = th;
    if ($("#dlpExclPriv").checked) opts.excludePrivateIp = true;
    return opts;
  };

  const run = () => {
    const text = ta.value;
    if (!text.trim()) { out.innerHTML = ""; toast("Paste or drop something to scan first."); return; }
    last = scan(text, collectOpts());
    renderReport(out, text, last, run, sampleLoaded);
  };

  $("#dlpRun").addEventListener("click", run);
  $("#dlpSample").addEventListener("click", () => { ta.value = SAMPLE; sampleLoaded = true; setMeta(); run(); });
  $("#dlpClear").addEventListener("click", () => { ta.value = ""; sampleLoaded = false; out.innerHTML = ""; setMeta(); ta.focus(); });

  const rescanIfReady = () => { if (last && ta.value.trim()) run(); };
  $("#dlpSelAll").addEventListener("click", () => { main.querySelectorAll(".dlp-det").forEach((c) => (c.checked = true)); rescanIfReady(); });
  $("#dlpSelNone").addEventListener("click", () => { main.querySelectorAll(".dlp-det").forEach((c) => (c.checked = false)); rescanIfReady(); });
  main.querySelector(".dlp-opts").addEventListener("change", rescanIfReady);

  const file = $("#dlpFile");
  $("#dlpPick").addEventListener("click", () => file.click());
  file.addEventListener("change", () => readFiles(file.files, ta, setMeta, run));

  const drop = $("#dlpDrop");
  ["dragenter", "dragover"].forEach((e) => drop.addEventListener(e, (ev) => { ev.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach((e) => drop.addEventListener(e, (ev) => { ev.preventDefault(); if (e === "dragleave" && drop.contains(ev.relatedTarget)) return; drop.classList.remove("over"); }));
  drop.addEventListener("drop", (ev) => { const f = ev.dataTransfer && ev.dataTransfer.files; if (f && f.length) readFiles(f, ta, setMeta, run); });

  ta.focus();
}

function readFiles(files, ta, setMeta, run) {
  const list = Array.from(files).slice(0, 25);
  let pending = list.length;
  const chunks = [];
  if (!pending) return;
  list.forEach((f, i) => {
    if (f.size > 8 * 1024 * 1024) { chunks[i] = `\n/* ${f.name}: skipped (over 8 MB) */\n`; if (--pending === 0) done(); return; }
    const r = new FileReader();
    r.onload = () => { chunks[i] = `\n/* ===== ${f.name} ===== */\n` + String(r.result || ""); if (--pending === 0) done(); };
    r.onerror = () => { chunks[i] = `\n/* ${f.name}: could not read */\n`; if (--pending === 0) done(); };
    r.readAsText(f);
  });
  function done() {
    ta.value = (ta.value ? ta.value + "\n" : "") + chunks.join("");
    setMeta();
    toast(`Loaded ${list.length} file${list.length > 1 ? "s" : ""}`);
    run();
  }
}

function renderReport(out, text, res, rerun, sample) {
  const g = GRADE[res.grade] || GRADE.clean;
  if (res.counts.total === 0) {
    out.innerHTML = `<div class="dlp-card"><div class="dlp-clean">No secrets or personal data detected across ${res.bytes.toLocaleString()} characters.</div>
      <p class="dlp-hint" style="text-align:center">A clean result is not a guarantee — detectors cover common patterns, not every possible format.</p></div>`;
    return;
  }

  const sevChips = Object.keys(SEV).filter((k) => res.bySeverity[k]).map((k) =>
    `<span class="dlp-sev"><span class="dlp-dot" style="--c:${SEV[k].c}"></span>${res.bySeverity[k]} ${SEV[k].label}</span>`).join("");

  const typeChips = res.byType.map((t) =>
    `<span class="dlp-type"><span class="dlp-dot" style="--c:${SEV[t.severity].c}"></span><b>${t.count}</b> ${esc(t.label)}</span>`).join("");

  const rows = res.findings.map((f) => `
    <tr class="dlp-sev-${f.severity}">
      <td><span class="dlp-pill" style="background:${SEV[f.severity].c}">${SEV[f.severity].label}</span></td>
      <td>${esc(f.label)}${f.detail ? ` <span class="dlp-loc">(${esc(f.detail)})</span>` : ""}
        <div class="dlp-advice">${esc(f.advice || "")}</div></td>
      <td><code class="dlp-val">${esc(f.masked)}</code></td>
      <td class="dlp-loc">line ${f.line}, col ${f.col}</td>
    </tr>`).join("");

  out.innerHTML = `
  <div class="dlp-card">
    <div class="dlp-score">
      <span class="dlp-grade" style="color:${g.c}">${g.label}</span>
      <div class="dlp-sevs">${sevChips}</div>
      <span class="dlp-hint" style="margin-left:auto">${res.counts.secrets} secret${res.counts.secrets === 1 ? "" : "s"} · ${res.counts.pii} PII · ${res.bytes.toLocaleString()} chars</span>
    </div>
    <div class="dlp-types" style="margin-top:14px">${typeChips}</div>
  </div>

  <div class="dlp-card" style="padding:0;overflow:hidden">
    <div class="dlp-list dn-scrollbox"><table>
      <thead><tr><th>Severity</th><th>Type</th><th>Value (masked)</th><th>Location</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>
  </div>

  <div class="dlp-card">
    <h3>Redacted copy</h3>
    <div class="dlp-row" style="margin-top:0;margin-bottom:10px">
      <label class="dlp-hint" style="margin:0">Style</label>
      <select id="dlpStyle">
        <option value="label">Labelled [REDACTED:type]</option>
        <option value="mask">Masked (keep last 4)</option>
        <option value="block">Solid block</option>
      </select>
      <button class="dlp-btn sm" id="dlpCopy">Copy</button>
      <button class="dlp-btn sm" id="dlpDl">Download .txt</button>
      <button class="dlp-btn sm" id="dlpJson">Export report (JSON)</button>
      <button class="dlp-btn sm" id="dlpCsv">Export findings (CSV)</button>
    </div>
    <div class="dlp-red" id="dlpRedOut"></div>
  </div>`;

  const sel = out.querySelector("#dlpStyle");
  const redOut = out.querySelector("#dlpRedOut");
  const paint = () => { redOut.textContent = redact(text, res.findings, sel.value); };
  sel.addEventListener("change", paint);
  paint();

  out.querySelector("#dlpCopy").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(redOut.textContent); toast("Redacted text copied"); }
    catch (_) { toast("Copy blocked by the browser"); }
  });
  out.querySelector("#dlpDl").addEventListener("click", () => download("redacted.txt", redOut.textContent, "text/plain"));
  out.querySelector("#dlpJson").addEventListener("click", () => {
    const report = {
      generated: new Date().toISOString(), tool: "Darknode DLP Scanner",
      bytes: res.bytes, grade: res.grade, score: res.score,
      counts: res.counts, bySeverity: res.bySeverity,
      findings: res.findings.map((f) => ({ type: f.id, label: f.label, kind: f.kind, severity: f.severity, line: f.line, col: f.col, detail: f.detail || undefined, masked: f.masked })),
      note: "Values are masked. Scan ran client-side; no data was uploaded.",
    };
    download("dlp-report.json", JSON.stringify(report, null, 2), "application/json");
  });
  attachSinkButton(out.querySelector("#dlpCsv").parentElement, () => ({ findings: dlpFindings(res, text), sample: !!sample }), "dlp"); // no dataset: each scan is different text, so findings missing from it are not "fixed"
  out.querySelector("#dlpCsv").addEventListener("click", () => {
    const head = ["severity", "type", "label", "kind", "line", "col", "detail", "masked"];
    const cell = (v) => { const s = String(v == null ? "" : v).replace(/^(?=[=+@\t\r]|-(?!\d+(?:\.\d+)?$))/, "'"); return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
    const lines = [head.join(",")];
    for (const f of res.findings) {
      lines.push([f.severity, f.id, f.label, f.kind, f.line, f.col, f.detail || "", f.masked].map(cell).join(","));
    }
    download("dlp-findings.csv", lines.join("\r\n"), "text/csv");
  });
}

function download(name, content, type) {
  try {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = name; document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);
  } catch (_) { toast("Download blocked by the browser"); }
}

export default renderDlp;
