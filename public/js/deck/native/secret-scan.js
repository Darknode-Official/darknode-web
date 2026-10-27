// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Native Secret & Code Scan: codescan/rules.js over pasted code or a dropped project
// folder, entirely in the browser. Secrets are shown masked; nothing is uploaded.

import { scanFile, SEV_ORDER } from "/js/codescan/rules.js?v=20261025g";
import { esc, toast, sevPill, recordRun, readFiles, download } from "./ui.js";

const rank = (s) => (s in SEV_ORDER ? SEV_ORDER[s] : 99);

export function mount(el, { space, mode }) {
  const repo = mode === "repo";
  el.innerHTML = `
    <div class="ns-card"><h2>${repo ? "Repository sweep" : "Scan your code for leaked secrets"}</h2>
      <p class="ns-sub">${repo
        ? "Drop a checked-out repository (or any folder) to find hard-coded credentials, private keys and risky code patterns across every file. Runs locally in this browser: no file leaves the machine."
        : "Find API keys, passwords, tokens and private keys before you push them. Drop your project folder or paste a file. Everything is scanned in your browser; nothing is uploaded."}</p>
      <div class="ns-drop" id="nsScDrop">Drop a folder or files here, or <button class="ns-btn ghost sm" id="nsScPick">Choose folder</button> <button class="ns-btn ghost sm" id="nsScPickF">Choose files</button>
        <input type="file" id="nsScDir" webkitdirectory multiple hidden><input type="file" id="nsScFiles" multiple hidden></div>
      <details style="margin-top:12px"><summary style="cursor:pointer;font-weight:600;font-size:13px">Or paste code</summary>
        <div class="ns-form" style="margin-top:8px"><input class="ns-in" id="nsScName" aria-label="File name" style="max-width:240px;flex:none" placeholder="File name, e.g. config.py" spellcheck="false"></div>
        <textarea class="ns-ta" id="nsScIn" aria-label="Source code or config to scan" style="margin-top:8px" placeholder="Paste source code or a config file" spellcheck="false"></textarea>
        <div class="ns-row"><button class="ns-btn" id="nsScGo">Scan pasted code</button></div>
        <p class="ns-help">The file name sets the language for code checks. Secrets are detected in any file type.</p></details></div>
    <div id="nsScOut"></div>`;
  const out = el.querySelector("#nsScOut"), drop = el.querySelector("#nsScDrop");
  const dir = el.querySelector("#nsScDir"), files = el.querySelector("#nsScFiles");
  el.querySelector("#nsScPick").onclick = () => dir.click();
  el.querySelector("#nsScPickF").onclick = () => files.click();

  const run = (list, skipped, label) => {
    const hits = [];
    let placeholders = 0;
    for (const f of list) { const r = scanFile(f.path, f.text); placeholders += r.placeholders || 0; for (const h of r) hits.push({ ...h, path: f.path }); }
    hits.sort((a, b) => rank(a.sev) - rank(b.sev) || (a.kind === "secret" ? -1 : 1));
    const secrets = hits.filter((h) => h.kind === "secret"), code = hits.filter((h) => h.kind !== "secret");
    const crit = hits.filter((h) => h.sev === "critical" || h.sev === "high").length;
    let filter = secrets.length || !code.length ? "secret" : "code";
    const paint = () => {
      const rows = filter === "secret" ? secrets : code;
      out.innerHTML = `
        <div class="ns-kpis">
          <div class="ns-kpi" style="--c:${secrets.length ? "#b00020" : "#2f9e56"}"><div class="v">${secrets.length}</div><div class="l">Exposed secrets</div></div>
          <div class="ns-kpi" style="--c:${code.length ? "#b58100" : "#2f9e56"}"><div class="v">${code.length}</div><div class="l">Risky code patterns</div></div>
          <div class="ns-kpi" style="--c:${crit ? "#d9480f" : "#2f9e56"}"><div class="v">${crit}</div><div class="l">Critical or high</div></div>
          <div class="ns-kpi"><div class="v">${list.length}</div><div class="l">Files scanned${skipped ? " (" + skipped + " skipped)" : ""}</div></div></div>
        <div class="ns-card"><h2><span class="ns-seg"><button data-f="secret" class="${filter === "secret" ? "on" : ""}">Secrets (${secrets.length})</button><button data-f="code" class="${filter === "code" ? "on" : ""}">Code (${code.length})</button></span>
          <span class="r"><button class="ns-btn ghost sm" id="nsScJson">Export JSON</button></span></h2>
          ${rows.length ? `<div class="ns-scroll" style="margin-top:10px"><table class="ns-tbl"><thead><tr><th>Severity</th><th>Finding</th><th>Where</th><th>What to do</th></tr></thead><tbody>
            ${rows.slice(0, 500).map((h) => `<tr><td>${sevPill(h.sev)}</td><td><b>${esc(h.title)}</b><div class="mono" style="color:var(--ns-mut);margin-top:3px">${esc(h.snippet)}</div></td><td class="mono">${esc(h.path)}:${h.line}</td><td style="font-size:12.5px">${esc(h.fix || h.why || "")}</td></tr>`).join("")}
          </tbody></table></div>` : `<div class="ns-empty">${filter === "secret" ? (placeholders ? `No real secrets found. ${placeholders} example or placeholder value${placeholders === 1 ? " was" : "s were"} skipped (like AWS's AKIA…EXAMPLE or 1234567890abcdef); real keys are reported.` : "No secrets found. Nice.") : "No risky code patterns found."}</div>`}
          ${secrets.length ? `<div class="ns-note">A secret that was ever committed or shared should be treated as leaked: revoke or rotate it at the provider first, then remove it from the code and its history.</div>` : ""}</div>`;
      out.querySelectorAll("[data-f]").forEach((b) => b.onclick = () => { filter = b.dataset.f; paint(); });
      out.querySelector("#nsScJson").onclick = () => download("secret-scan.json", JSON.stringify({ scanned: list.length, findings: hits.map(({ path, line, ruleId, title, sev, kind, snippet }) => ({ path, line, ruleId, title, sev, kind, snippet })) }, null, 2));
    };
    paint();
    recordRun(space, { tool: "secrets", target: label, summary: secrets.length + " secret" + (secrets.length === 1 ? "" : "s") + ", " + code.length + " code issue" + (code.length === 1 ? "" : "s"), level: secrets.length || crit ? "bad" : code.length ? "warn" : "good", counts: { secrets: secrets.length, code: code.length } });
  };

  const fromFiles = async (fl) => {
    if (!fl || !fl.length) return;
    out.innerHTML = `<div class="ns-card"><span class="ns-spin"></span>Reading ${fl.length} file${fl.length === 1 ? "" : "s"}...</div>`;
    const { files: list, skipped } = await readFiles(fl, { maxFiles: repo ? 5000 : 2000 });
    if (!list.length) { out.innerHTML = `<div class="ns-card ns-empty">No readable text files (dependencies, build output and binaries are skipped).</div>`; return; }
    const root = (list[0].path.split("/")[0]) || "files";
    setTimeout(() => run(list, skipped.length, list.length > 1 ? root : list[0].path), 0);
  };
  // copy then clear, so choosing the same folder again (after fixing a finding) re-runs the scan
  dir.onchange = () => { const l = Array.from(dir.files || []); dir.value = ""; fromFiles(l); };
  files.onchange = () => { const l = Array.from(files.files || []); files.value = ""; fromFiles(l); };
  drop.ondragover = (e) => { e.preventDefault(); drop.classList.add("over"); };
  drop.ondragleave = () => drop.classList.remove("over");
  drop.ondrop = async (e) => {
    e.preventDefault(); drop.classList.remove("over");
    const items = Array.from(e.dataTransfer.items || []).map((i) => i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean);
    if (!items.some((x) => x.isDirectory)) { fromFiles(e.dataTransfer.files); return; }
    const collected = [];
    const walk = (entry, prefix) => new Promise((res) => {
      if (entry.isFile) { entry.file((f) => { try { Object.defineProperty(f, "webkitRelativePath", { value: prefix + f.name }); } catch (_) {} collected.push(f); res(); }, () => res()); return; }
      if (/^(node_modules|\.git|dist|build|vendor)$/.test(entry.name)) { res(); return; }
      const rd = entry.createReader(), all = [];
      const more = () => rd.readEntries(async (ents) => { if (!ents.length) { for (const c of all) await walk(c, prefix + entry.name + "/"); res(); } else { all.push(...ents); more(); } }, () => res());
      more();
    });
    for (const it of items) await walk(it, "");
    fromFiles(collected);
  };
  el.querySelector("#nsScGo").onclick = () => {
    const text = el.querySelector("#nsScIn").value; if (!text.trim()) { toast("Paste some code first"); return; }
    const name = (el.querySelector("#nsScName").value || "").trim() || "pasted code";
    run([{ path: name, text }], 0, name);
  };
}
