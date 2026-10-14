// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Data Protection (DLP) scanner — finds secrets and PII in pasted text or dropped
// files and produces an exposure report plus a redacted copy. Everything runs in the
// browser: nothing is uploaded, nothing leaves the page. See dlp-engine.js for the
// pure, tested detectors.
//
//   renderDlp(main) -> void

import { scan, redact } from "/js/dataprotect/dlp-engine.js?v=20261013i";

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
  .dlp{max-width:1180px;margin:0 auto;font-size:14px;line-height:1.5}
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
  `;
  document.head.appendChild(st);
}

const SAMPLE = [
  "# dropped config — example with planted secrets",
  "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
  'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
  "DATABASE_URL=postgres://admin:Sup3rS3cret@db.internal:5432/payments",
  "github_token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
  "",
  "Customer record:",
  "  name: Jane Roe   email: jane.roe@acme.com",
  "  card: 4111 1111 1111 1111   ssn: 123-45-6789",
  "  iban: DE89 3704 0044 0532 0130 00",
].join("\n");

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
  let last = null;

  const setMeta = () => {
    const n = ta.value.length;
    meta.textContent = n ? `${n.toLocaleString()} characters` : "";
  };
  ta.addEventListener("input", setMeta);

  const run = () => {
    const text = ta.value;
    if (!text.trim()) { out.innerHTML = ""; toast("Paste or drop something to scan first."); return; }
    last = scan(text);
    renderReport(out, text, last, run);
  };

  $("#dlpRun").addEventListener("click", run);
  $("#dlpSample").addEventListener("click", () => { ta.value = SAMPLE; setMeta(); run(); });
  $("#dlpClear").addEventListener("click", () => { ta.value = ""; out.innerHTML = ""; setMeta(); ta.focus(); });

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

function renderReport(out, text, res, rerun) {
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
    <tr>
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
    <div class="dlp-list"><table>
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
