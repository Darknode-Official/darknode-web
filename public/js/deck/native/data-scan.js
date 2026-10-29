// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Native Sensitive Data Check: dlp-engine over pasted text or files, with one-click
// redaction. Personal = "is it safe to share?"; Enterprise = data-loss review.

import { scan, redact } from "/js/dataprotect/dlp-engine.js?v=20261028c";
import { dlpFindings } from "/js/dataprotect/dp-sink.js";
import { attachSinkButton } from "/js/core/sink.js";
import { esc, toast, sevPill, recordRun, readFiles, download } from "./ui.js";

const GRADE = { critical: ["Do not share", "#b00020", "bad"], high: ["Contains sensitive data", "#d9480f", "bad"], elevated: ["Review before sharing", "#b58100", "warn"], low: ["Minor personal data", "#2f7d9e", "good"], clean: ["Nothing sensitive found", "#2f9e56", "good"] };

export function mount(el, { space, mode }) {
  const ent = mode === "dlp";
  el.innerHTML = `
    <div class="ns-card"><h2>${ent ? "Data-loss review" : "Safe to share?"}</h2>
      <p class="ns-sub">${ent
        ? "Check documents, exports and logs for payment cards, bank numbers, national IDs, contact data and credentials before they leave the organization. Produce a redacted copy that is safe to send."
        : "Before you paste something into a chat, ticket or AI tool, check it for passwords, keys, card numbers and personal details, and get a cleaned-up copy."}</p>
      <textarea class="ns-ta" id="nsDsIn" aria-label="Text to check" placeholder="Paste the text you want to check" spellcheck="false"></textarea>
      <div class="ns-row"><button class="ns-btn" id="nsDsGo">Check text</button><button class="ns-btn ghost" id="nsDsF">Check files</button><input type="file" id="nsDsFiles" multiple hidden></div>
      <p class="ns-help">Runs entirely in your browser. Card numbers are Luhn-checked and bank numbers checksum-validated, so random digits do not trigger.</p></div>
    <div id="nsDsOut"></div>`;
  const ta = el.querySelector("#nsDsIn"), out = el.querySelector("#nsDsOut"), fi = el.querySelector("#nsDsFiles");

  const show = (text, label, files) => {
    const res = scan(text);
    // several files: which one holds what is the first thing a reviewer needs
    const RANK = { critical: 4, high: 3, elevated: 2, low: 1, clean: 0 };
    const per = files && files.length > 1 ? files.map((f) => ({ path: f.path, r: scan(f.text) })).sort((a, b) => RANK[b.r.grade] - RANK[a.r.grade] || b.r.counts.total - a.r.counts.total) : null;
    const [vlabel, vc, lvl] = GRADE[res.grade] || GRADE.clean;
    out.innerHTML = `
      <div class="ns-card" style="border-left:6px solid ${vc}">
        <div style="font-size:12px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;color:${vc}">Result</div>
        <div style="font-size:24px;font-weight:800;color:${vc};margin:2px 0 4px">${esc(vlabel)}</div>
        <div style="color:var(--ns-mut);font-size:13px">${res.counts.secrets} credential${res.counts.secrets === 1 ? "" : "s"} &middot; ${res.counts.pii} personal-data item${res.counts.pii === 1 ? "" : "s"} &middot; ${res.bytes.toLocaleString()} characters checked</div>
        ${res.byType.length ? `<div class="ns-scroll" style="margin-top:12px"><table class="ns-tbl"><thead><tr><th>Severity</th><th>Type</th><th>Count</th><th>Example (masked)</th></tr></thead><tbody>
          ${res.byType.map((t) => { const ex = res.findings.find((f) => f.id === t.id); return `<tr><td>${sevPill(t.severity)}</td><td><b>${esc(t.label)}</b></td><td>${t.count}</td><td class="mono">${esc(ex ? ex.masked : "")}</td></tr>`; }).join("")}
        </tbody></table></div>` : ""}
        <div class="ns-row" data-act></div></div>
      ${per ? `<div class="ns-card"><h2>By file<span class="r">${per.filter((x) => x.r.counts.total).length} of ${per.length} with findings</span></h2><div class="ns-scroll"><table class="ns-tbl"><thead><tr><th>Result</th><th>File</th><th>Credentials</th><th>Personal data</th><th>Found</th></tr></thead><tbody>
        ${per.map(({ path, r }) => { const [gl, gc] = GRADE[r.grade] || GRADE.clean; return `<tr><td><span class="ns-pill" style="background:${gc}">${esc(gl)}</span></td><td class="mono">${esc(path)}</td><td>${r.counts.secrets}</td><td>${r.counts.pii}</td><td>${esc(r.byType.map((t) => t.label + (t.count > 1 ? " x" + t.count : "")).join(", ") || "-")}</td></tr>`; }).join("")}
      </tbody></table></div></div>` : ""}
      ${res.findings.length ? `<div class="ns-card"><h2>Redacted copy<span class="r"><select class="ns-in" id="nsDsSty" style="min-width:0;padding:5px 8px;font-size:12.5px"><option value="label">Labels</option><option value="mask">Partial mask</option><option value="block">Blocks</option></select></span></h2>
        <textarea class="ns-ta" id="nsDsRed" readonly style="min-height:160px"></textarea>
        <div class="ns-row"><button class="ns-btn" id="nsDsCopy">Copy redacted text</button></div></div>` : ""}`;
    const act = out.querySelector("[data-act]");
    if (ent) attachSinkButton(act, () => ({ findings: dlpFindings(res, text) }), "dlp", { dataset: files && files.length === 1 ? "dlp " + label : undefined }); // only one named file is a re-runnable subject; "pasted text" / "N files" are different inputs each time
    const red = out.querySelector("#nsDsRed");
    if (red) {
      const sty = out.querySelector("#nsDsSty");
      // one file: the file marker (kept for dp-sink attribution) is not part of the copy the user takes away
      const paint = () => { const r = redact(text, res.findings, sty.value); red.value = files && files.length === 1 ? r.replace(/^\n\/\* ===== .+? ===== \*\/\n/, "") : r; };
      sty.onchange = paint; paint();
      out.querySelector("#nsDsCopy").onclick = async () => { try { await navigator.clipboard.writeText(red.value); toast("Redacted text copied"); } catch (_) { red.select(); toast("Select and copy the text"); } };
      if (ent) { const d = document.createElement("button"); d.className = "ns-btn ghost"; d.textContent = "Download redacted"; d.onclick = () => download("redacted.txt", red.value, "text/plain"); out.querySelector("#nsDsCopy").after(d); }
    }
    recordRun(space, { tool: "data", target: label, summary: vlabel + " (" + res.counts.total + " item" + (res.counts.total === 1 ? "" : "s") + ")", level: lvl, counts: res.counts });
  };
  el.querySelector("#nsDsGo").onclick = () => { const t = ta.value; if (!t.trim()) { toast("Paste some text first"); return; } show(t, "pasted text"); };
  el.querySelector("#nsDsF").onclick = () => fi.click();
  fi.onchange = async () => {
    const { files, skipped } = await readFiles(fi.files, { maxFiles: 200 });
    fi.value = ""; // choosing the same files again re-runs the check
    if (!files.length) { toast("No readable text files"); return; }
    if (skipped.length) toast("Skipped " + skipped.length + " file" + (skipped.length === 1 ? "" : "s") + " (binary, too large, or dependency folders)");
    // File markers let dp-sink attribute each hit back to its file.
    const text = files.map((f) => "\n/* ===== " + f.path + " ===== */\n" + f.text).join("");
    show(text, files.length === 1 ? files[0].path : files.length + " files", files);
  };
}
