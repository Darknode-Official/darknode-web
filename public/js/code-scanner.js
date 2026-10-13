// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Code Scanner — scan a GitHub repository (or a local folder) for leaked secrets,
// risky code patterns and known-vulnerable dependencies, then review every finding
// in a three-pane workspace that opens the file at the exact line, with the issue,
// why it matters and how to fix it pinned under that line.
//
// Detection is deterministic (public/js/codescan/rules.js) and dependency advisories
// come from OSV.dev. Code is fetched straight from GitHub into this tab and scanned
// here: nothing is uploaded to Darknode, and no AI is involved.

import { scanFile, parseManifest, isManifest, osvSeverity, osvFixed, repoScore, toSarif, SEV_ORDER, langOf } from "/js/codescan/rules.js?v=20261013a";
import * as gh from "/js/codescan/github.js?v=20261013a";

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmt = (n) => Number(n || 0).toLocaleString();
const SEVS = ["critical", "high", "medium", "low", "info"];
const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Review" };
const KIND_LABEL = { secret: "Secrets", code: "Code", dep: "Dependencies" };
const HIST_KEY = "dn_codescan_recent";
const toast = (m, t) => { try { (window.dnToast || window.showToast || (() => {}))(m, t); } catch (_) {} };

const CSS = `<style id="cs-css">
.cs{--cs-line:var(--line,#e4e7ec);--cs-card:var(--card,#fff);--cs-txt:var(--txt,#101828);--cs-mut:var(--mut,#5f6b7a);--cs-acc:var(--acc,#0972d3);
  --sev-critical:#b42318;--sev-high:#d92d20;--sev-medium:#b54708;--sev-low:#475467;--sev-info:#98a2b3;color:var(--cs-txt);--cs-font:inherit}
.cs *{box-sizing:border-box}
.cs-note,.cs-note *{font-family:var(--cs-font)}
.cs .pg-sub{max-width:760px}
.cs-card{background:var(--cs-card);border:1px solid var(--cs-line);border-radius:10px;padding:20px}
.cs-start{display:grid;grid-template-columns:minmax(0,1.3fr) minmax(0,1fr);gap:16px;margin-top:16px}
@media (max-width:900px){.cs-start{grid-template-columns:1fr}}
.cs-h2{font-size:15px;font-weight:650;margin:0 0 4px}
.cs-p{font-size:13px;color:var(--cs-mut);margin:0 0 14px;line-height:1.5}
.cs-help{font-size:12px;color:var(--cs-mut);margin:6px 0 0;line-height:1.45}
.cs-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.cs-in{height:32px;padding:0 10px;border:1px solid var(--cs-line);border-radius:6px;background:var(--cs-card);color:var(--cs-txt);font:inherit;font-size:13px;min-width:0;flex:1}
.cs-in:focus{outline:none;border-color:var(--cs-acc);box-shadow:0 0 0 3px color-mix(in srgb,var(--cs-acc) 18%,transparent)}
.cs .cs-btn{height:32px;padding:0 14px;border-radius:6px;border:1px solid var(--cs-line);background:var(--cs-card);color:var(--cs-txt);font:inherit;font-size:13px;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
.cs .cs-btn:hover{border-color:color-mix(in srgb,var(--cs-txt) 30%,transparent)}
.cs .cs-btn.pri{background:var(--cs-acc);border-color:var(--cs-acc);color:#fff}
.cs .cs-btn.pri:hover{filter:brightness(.95)}
.cs .cs-btn.sm{height:28px;padding:0 10px;font-size:12px}
.cs .cs-btn[disabled]{opacity:.55;cursor:default}
.cs-link{background:none;border:0;padding:0;color:var(--cs-acc);font:inherit;font-size:12.5px;cursor:pointer}
.cs-seg{display:inline-flex;border:1px solid var(--cs-line);border-radius:6px;overflow:hidden;margin-bottom:14px}
.cs-seg button{height:30px;padding:0 14px;border:0;background:transparent;font:inherit;font-size:13px;color:var(--cs-mut);cursor:pointer}
.cs-seg button.on{background:color-mix(in srgb,var(--cs-acc) 10%,transparent);color:var(--cs-acc);font-weight:600}
.cs-repos{margin-top:12px;border:1px solid var(--cs-line);border-radius:8px;max-height:360px;overflow:auto}
.cs-repo{display:flex;align-items:center;gap:10px;padding:0 12px;min-height:44px;border-top:1px solid var(--cs-line);font-size:13px}
.cs-repo:first-child{border-top:0}
.cs-repo .nm{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:600}
.cs-repo .meta{color:var(--cs-mut);font-size:12px;white-space:nowrap}
.cs-pill{display:inline-flex;align-items:center;height:20px;padding:0 7px;border-radius:999px;font-size:11px;font-weight:600;border:1px solid var(--cs-line);color:var(--cs-mut)}
.cs-list{margin:0;padding:0;list-style:none;font-size:13px}
.cs-list li{display:flex;gap:10px;padding:8px 0;border-top:1px solid var(--cs-line);line-height:1.45}
.cs-list li:first-child{border-top:0}
.cs-list b{min-width:110px;font-weight:600}
.cs-empty{padding:28px 12px;text-align:center;color:var(--cs-mut);font-size:13px}
.cs-prog{margin-top:16px}
.cs-bar{height:6px;border-radius:999px;background:color-mix(in srgb,var(--cs-txt) 8%,transparent);overflow:hidden;margin:10px 0 8px}
.cs-bar i{display:block;height:100%;width:0;background:var(--cs-acc);transition:width .2s}
.cs-err{border:1px solid color-mix(in srgb,var(--sev-high) 35%,transparent);background:color-mix(in srgb,var(--sev-high) 6%,transparent);color:var(--sev-critical);border-radius:8px;padding:10px 12px;font-size:13px;margin-top:12px}
/* Workspace */
.cs-sum{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin:14px 0 12px}
.cs-sum .repo{font-weight:650;font-size:15px}
.cs-sum .sha{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--cs-mut)}
.cs-sum .sp{flex:1}
.cs-score{display:inline-flex;align-items:baseline;gap:4px;font-weight:700;font-size:20px}
.cs-score small{font-size:12px;color:var(--cs-mut);font-weight:500}
.cs-chips{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px}
.cs-chip{height:28px;padding:0 10px;border-radius:999px;border:1px solid var(--cs-line);background:var(--cs-card);font:inherit;font-size:12.5px;color:var(--cs-txt);cursor:pointer;display:inline-flex;align-items:center;gap:6px}
.cs-chip.on{border-color:var(--cs-acc);background:color-mix(in srgb,var(--cs-acc) 8%,transparent)}
.cs-chip .d{width:8px;height:8px;border-radius:50%}
.cs-ws{display:grid;grid-template-columns:260px minmax(0,1fr) 340px;border:1px solid var(--cs-line);border-radius:10px;background:var(--cs-card);height:calc(100vh - 250px);min-height:480px;overflow:hidden}
@media (max-width:1200px){.cs-ws{grid-template-columns:220px minmax(0,1fr);}.cs-ws .cs-side.r{display:none}}
@media (max-width:760px){.cs-ws{grid-template-columns:1fr;height:auto}.cs-ws .cs-side.l{max-height:220px}.cs-code{height:60vh}}
.cs-side{display:flex;flex-direction:column;min-height:0;min-width:0}
.cs-side.l{border-right:1px solid var(--cs-line)}
.cs-side.r{border-left:1px solid var(--cs-line)}
.cs-side .hd{display:flex;align-items:center;gap:8px;height:44px;padding:0 12px;border-bottom:1px solid var(--cs-line);font-size:12px;font-weight:650;color:var(--cs-mut);text-transform:uppercase;letter-spacing:.04em;flex:none}
.cs-side .hd .cs-in{height:28px;text-transform:none;letter-spacing:0;font-weight:400}
.cs-scroll{overflow:auto;min-height:0;flex:1}
.cs-file{display:flex;align-items:center;gap:8px;width:100%;min-height:34px;padding:4px 12px;border:0;background:none;font:inherit;font-size:12.5px;color:var(--cs-txt);cursor:pointer;text-align:left}
.cs-file:hover{background:color-mix(in srgb,var(--cs-txt) 4%,transparent)}
.cs-file.on{background:color-mix(in srgb,var(--cs-acc) 9%,transparent)}
.cs-file .p{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;direction:rtl;text-align:left}
.cs-n{min-width:20px;height:18px;padding:0 5px;border-radius:999px;font-size:11px;font-weight:700;color:#fff;display:inline-flex;align-items:center;justify-content:center}
.cs-codehd{display:flex;align-items:center;gap:10px;height:44px;padding:0 14px;border-bottom:1px solid var(--cs-line);font-size:13px;min-width:0}
.cs-codehd .p{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font:12.5px ui-monospace,SFMono-Regular,Menlo,monospace}
.cs-mid{display:flex;flex-direction:column;min-width:0;min-height:0}
.cs-code{position:relative;overflow:auto;flex:1;min-height:0;font:12.5px/20px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:color-mix(in srgb,var(--cs-txt) 2%,var(--cs-card))}
.cs-ln{display:grid;grid-template-columns:56px 1fr;min-width:max-content}
.cs-ln .g{color:var(--cs-mut);text-align:right;padding:0 12px 0 0;user-select:none;opacity:.75;border-left:3px solid transparent}
.cs-ln .t{white-space:pre;padding-right:24px}
.cs-ln.hit .g{opacity:1;font-weight:700}
.cs-ln.hit{background:color-mix(in srgb,var(--sev,#d92d20) 9%,transparent)}
.cs-ln.hit .g{border-left-color:var(--sev,#d92d20);color:var(--sev,#d92d20)}
.cs-ln.cur{background:color-mix(in srgb,var(--sev,#d92d20) 16%,transparent)}
.cs-note{margin:4px 16px 10px 56px;max-width:720px;border:1px solid var(--cs-line);border-left:3px solid var(--sev,#d92d20);border-radius:8px;background:var(--cs-card);padding:10px 12px;font-size:13px;line-height:1.5;white-space:normal;box-shadow:0 1px 2px rgba(16,24,40,.06)}
.cs-note:not(.open){cursor:pointer;padding-block:6px}
.cs-note:not(.open) .tt{margin:0}
.cs-note:not(.open) p{display:none}
.cs-note .tt{display:flex;align-items:center;gap:8px;font-weight:650;margin-bottom:4px;flex-wrap:wrap}
.cs-note p{margin:4px 0 0;color:var(--cs-mut);font-size:12.5px}
.cs-note p b{color:var(--cs-txt);font-weight:600}
.cs-note:not(.open) .cs-flow{display:none}
.cs-flow{list-style:none;margin:8px 0 2px;padding:0;counter-reset:fl}
.cs-flow li{position:relative;padding:0 0 8px 26px;font-size:12.5px;color:var(--cs-txt);counter-increment:fl}
.cs-flow li::before{content:counter(fl);position:absolute;left:0;top:1px;width:18px;height:18px;border-radius:50%;background:color-mix(in srgb,var(--sev,#d92d20) 14%,var(--cs-card));color:var(--sev,#d92d20);font-size:10.5px;font-weight:700;display:grid;place-items:center}
.cs-flow li:not(:last-child)::after{content:"";position:absolute;left:8.5px;top:21px;bottom:1px;border-left:1px dashed color-mix(in srgb,var(--sev,#d92d20) 45%,transparent)}
.cs-flow li:last-child{padding-bottom:0}
.cs-flow button{border:0;background:none;padding:0 4px 0 0;font:600 12px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:var(--cs-acc);cursor:pointer}
.cs-flow button:hover{text-decoration:underline}
.cs-df{font-family:var(--aws-font,system-ui,sans-serif);display:inline-flex;align-items:center;height:18px;padding:0 6px;border-radius:4px;border:1px solid var(--cs-line);font-size:10.5px;font-weight:650;color:var(--cs-mut);margin-right:6px}
.cs-ln.flash{animation:csflash 1.2s ease-out}
@keyframes csflash{from{background:color-mix(in srgb,var(--cs-acc) 22%,transparent)}to{background:transparent}}
.cs-sev{display:inline-flex;align-items:center;height:20px;padding:0 7px;border-radius:4px;font-size:11px;font-weight:700;color:#fff;background:var(--sev,#d92d20)}
.cs-fd{display:block;width:100%;text-align:left;border:0;border-bottom:1px solid var(--cs-line);background:none;padding:10px 12px;font:inherit;cursor:pointer;color:var(--cs-txt)}
.cs-fd:hover{background:color-mix(in srgb,var(--cs-txt) 4%,transparent)}
.cs-fd.on{background:color-mix(in srgb,var(--cs-acc) 9%,transparent)}
.cs-fd .t1{display:flex;align-items:center;gap:8px;font-size:13px;font-weight:600}
.cs-fd .t1 span:last-child{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cs-fd .t2{font:11.5px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--cs-mut);margin-top:3px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cs-kbd{font:11px ui-monospace,monospace;border:1px solid var(--cs-line);border-radius:4px;padding:0 4px;color:var(--cs-mut)}
</style>`;

const sevVar = (s) => `--sev:var(--sev-${s in SEV_LABEL ? s : "low"})`;

function loadRecent() { try { return JSON.parse(localStorage.getItem(HIST_KEY) || "[]"); } catch (_) { return []; } }
function saveRecent(entry) {
  try { const list = loadRecent().filter((x) => x.full !== entry.full); list.unshift(entry); localStorage.setItem(HIST_KEY, JSON.stringify(list.slice(0, 8))); } catch (_) {}
}

export function renderCodeScanner(main) {
  const st = { mode: "github", repos: null, filter: "", scan: null, sevOn: new Set(SEVS), kindOn: new Set(["secret", "code", "dep"]), file: "", idx: -1, fileFilter: "", busy: false };
  let token = 0; // render token: stale async work checks this before touching the DOM

  const pageFont = (() => { try { return getComputedStyle(main).fontFamily; } catch (_) { return ""; } })();
  main.innerHTML = CSS + `<div class="cs" style="--cs-font:${esc(pageFont || "system-ui, sans-serif")}">
    <div class="pg-head"><div>
      <h1 class="pg-h1">Code Scanner</h1>
      <p class="muted pg-sub">Find leaked secrets, risky code and vulnerable dependencies in a repository, then go straight to the line that needs fixing. Rules run in your browser and your code is never uploaded to Darknode.</p>
    </div></div>
    <div id="csBody"></div></div>`;
  const body = main.querySelector("#csBody");

  // ── Start screen ────────────────────────────────────────────────────────────
  function renderStart(err) {
    const my = ++token;
    const recent = loadRecent();
    body.innerHTML = `<div class="cs-start">
      <div class="cs-card">
        <div class="cs-seg" role="tablist">
          <button data-mode="github" class="${st.mode === "github" ? "on" : ""}" type="button">GitHub</button>
          <button data-mode="local" class="${st.mode === "local" ? "on" : ""}" type="button">Local folder</button>
        </div>
        <div id="csSrc"></div>
        ${err ? `<div class="cs-err">${esc(err)}</div>` : ""}
      </div>
      <div class="cs-card">
        <h2 class="cs-h2">What gets checked</h2>
        <ul class="cs-list">
          <li><b>Secrets</b><span>Cloud keys, tokens, private keys and passwords committed to the code. Values are masked on screen.</span></li>
          <li><b>Risky code</b><span>Injection, unsafe deserialisation, disabled TLS checks, weak crypto and more across JavaScript, TypeScript, Python, Go, PHP, Java, Dockerfiles and GitHub Actions.</span></li>
          <li><b>Dependencies</b><span>Pinned packages from lockfiles (npm, PyPI, Go, crates.io, RubyGems, Packagist, Maven) checked against OSV.dev advisories.</span></li>
        </ul>
        ${recent.length ? `<h2 class="cs-h2" style="margin-top:18px">Recent scans</h2><ul class="cs-list">${recent.map((r) => `<li><b style="min-width:0;flex:1;overflow:hidden;text-overflow:ellipsis">${esc(r.full)}</b><span class="cs-pill">${r.total} findings</span><span class="cs-pill">Score ${r.score}</span></li>`).join("")}</ul>` : ""}
      </div></div>`;
    body.querySelectorAll(".cs-seg button").forEach((b) => b.onclick = () => { st.mode = b.dataset.mode; renderStart(); });
    const src = body.querySelector("#csSrc");
    if (st.mode === "local") {
      src.innerHTML = `<h2 class="cs-h2">Scan a folder on this computer</h2>
        <p class="cs-p">Pick a project folder. Files are read locally and never leave your browser.</p>
        <label class="cs-btn pri" style="width:max-content">Choose folder<input id="csDir" type="file" webkitdirectory multiple hidden></label>`;
      src.querySelector("#csDir").onchange = (e) => { const files = [...(e.target.files || [])]; if (files.length) runLocal(files); };
      return;
    }
    if (!gh.connected()) {
      src.innerHTML = `<h2 class="cs-h2">Connect GitHub</h2>
        <p class="cs-p">See your repositories, including private ones, and pick one to scan.</p>
        <button class="cs-btn pri" id="csConnect" type="button">Connect GitHub</button>
        <p class="cs-help">Darknode asks GitHub for read access to your repositories. The access token stays in this tab only and is cleared when you close it.</p>
        <h2 class="cs-h2" style="margin-top:22px">Or scan a public repository</h2>
        <div class="cs-row"><input class="cs-in" id="csRepo" placeholder="owner/repo" autocomplete="off" spellcheck="false"><button class="cs-btn" id="csGo" type="button">Scan</button></div>
        <p class="cs-help">Paste owner/repo or a github.com link. Add /tree/branch to scan a branch other than the default.</p>
        <p class="cs-help"><button class="cs-link" id="csPatBtn" type="button">Use a personal access token instead</button></p>
        <div id="csPat" hidden style="margin-top:8px"><div class="cs-row"><input class="cs-in" id="csPatIn" type="password" placeholder="github_pat_…" autocomplete="off"><button class="cs-btn" id="csPatGo" type="button">Use token</button></div>
        <p class="cs-help">A fine-grained token with read-only Contents access is enough. It is kept in memory for this tab only.</p></div>`;
      src.querySelector("#csConnect").onclick = async (e) => {
        e.target.disabled = true;
        try { await gh.connectGitHub(); st.repos = null; renderStart(); }
        catch (x) { if (my === token) renderStart(x.message); }
      };
      const go = () => { const p = gh.parseRepo(src.querySelector("#csRepo").value); if (!p) return renderStart("Enter a repository as owner/repo or a github.com link."); runGitHub(p); };
      src.querySelector("#csGo").onclick = go;
      src.querySelector("#csRepo").onkeydown = (e) => { if (e.key === "Enter") go(); };
      src.querySelector("#csPatBtn").onclick = () => { src.querySelector("#csPat").hidden = false; src.querySelector("#csPatIn").focus(); };
      src.querySelector("#csPatGo").onclick = async () => {
        try { await gh.useToken(src.querySelector("#csPatIn").value); st.repos = null; renderStart(); }
        catch (x) { renderStart(x.message); }
      };
      return;
    }
    src.innerHTML = `<div class="cs-row" style="margin-bottom:4px"><h2 class="cs-h2" style="flex:1;margin:0">Your repositories</h2>
        <span class="cs-help" style="margin:0">Signed in as <b>${esc(gh.ghUser())}</b></span><button class="cs-link" id="csOut" type="button">Disconnect</button></div>
      <div class="cs-row" style="margin-top:10px"><input class="cs-in" id="csFilter" placeholder="Filter repositories" value="${esc(st.filter)}" autocomplete="off"></div>
      <div class="cs-repos" id="csRepos"><div class="cs-empty">Loading repositories…</div></div>
      <p class="cs-help">Repository missing? An organization may need to approve the Darknode app in its GitHub settings first.</p>`;
    src.querySelector("#csOut").onclick = () => { gh.disconnect(); st.repos = null; renderStart(); };
    const list = src.querySelector("#csRepos");
    const draw = () => {
      const q = st.filter.toLowerCase();
      const rows = (st.repos || []).filter((r) => !q || r.full.toLowerCase().includes(q));
      list.innerHTML = rows.length ? rows.slice(0, 200).map((r) => `<div class="cs-repo"><span class="nm" title="${esc(r.full)}">${esc(r.full)}</span>${r.private ? '<span class="cs-pill">Private</span>' : ""}<span class="meta">${esc(r.lang)}</span><button class="cs-btn sm" data-full="${esc(r.full)}" type="button">Scan</button></div>`).join("") : `<div class="cs-empty">No repositories match.</div>`;
      list.querySelectorAll("button[data-full]").forEach((b) => b.onclick = () => runGitHub(gh.parseRepo(b.dataset.full)));
    };
    src.querySelector("#csFilter").oninput = (e) => { st.filter = e.target.value; draw(); };
    if (st.repos) draw();
    else gh.listRepos().then((r) => { st.repos = r; if (my === token) draw(); }).catch((x) => { if (my === token) list.innerHTML = `<div class="cs-empty">${esc(x.message)}</div>`; });
  }

  // ── Progress ────────────────────────────────────────────────────────────────
  function progress(title) {
    const my = ++token;
    body.innerHTML = `<div class="cs-card cs-prog"><div class="cs-row"><h2 class="cs-h2" style="flex:1;margin:0">${esc(title)}</h2><button class="cs-btn sm" id="csCancel" type="button">Cancel</button></div>
      <div class="cs-bar"><i id="csBar"></i></div><div class="cs-help" id="csStat">Preparing…</div></div>`;
    body.querySelector("#csCancel").onclick = () => { token++; renderStart(); };
    return {
      alive: () => my === token,
      set: (done, total, note) => {
        if (my !== token) return;
        body.querySelector("#csBar").style.width = (total ? Math.round(100 * done / total) : 0) + "%";
        body.querySelector("#csStat").textContent = note;
      }
    };
  }

  // ── Scan pipeline (shared by GitHub + local) ────────────────────────────────
  async function scanAll(files, read, ui, meta) {
    const findings = [];
    const texts = new Map(); // only files with findings keep their text
    const deps = [];
    let done = 0, failed = 0;
    await gh.pool(files, 8, async (f) => {
      if (!ui.alive()) return;
      let text;
      try { text = await read(f); } catch (e) { failed++; if (/rate limit/i.test(e.message)) throw e; return; }
      if (typeof text !== "string" || text.indexOf("\u0000") >= 0) { done++; return; }
      const fs = scanFile(f.path, text).map((x) => ({ ...x, path: f.path }));
      if (isManifest(f.path)) for (const d of parseManifest(f.path, text)) deps.push({ ...d, path: f.path });
      if (fs.length || isManifest(f.path)) texts.set(f.path, text);
      findings.push(...fs);
      done++;
      if (done % 10 === 0 || done === files.length) ui.set(done, files.length + 1, `Scanned ${fmt(done)} of ${fmt(files.length)} files${gh.rate.remaining != null && meta.github ? " · GitHub API requests left: " + fmt(gh.rate.remaining) : ""}`);
    });
    if (!ui.alive()) return null;
    // A lockfile has the exact resolved versions, so it wins over package.json in the same folder.
    const dir = (p) => p.replace(/[^/]*$/, "");
    const locked = new Set(deps.filter((d) => !/(^|\/)package\.json$/.test(d.path)).map((d) => dir(d.path)));
    for (let k = deps.length - 1; k >= 0; k--) if (/(^|\/)package\.json$/.test(deps[k].path) && locked.has(dir(deps[k].path))) deps.splice(k, 1);
    let depNote = "";
    if (deps.length) {
      ui.set(files.length, files.length + 1, `Checking ${fmt(deps.length)} dependencies against OSV.dev…`);
      try {
        const hits = await gh.osvQuery(deps);
        const ids = [...new Set(hits.map((h) => h.id))].slice(0, 300);
        const details = new Map();
        await gh.pool(ids, 8, async (id) => { details.set(id, await gh.osvVuln(id)); });
        const seen = new Set();
        for (const h of hits) {
          const v = details.get(h.id);
          const k = h.dep.path + "|" + h.dep.name + "|" + h.id;
          if (seen.has(k)) continue; seen.add(k);
          const alias = v && (v.aliases || []).find((a) => /^CVE-/.test(a));
          const fixed = v ? osvFixed(v, h.dep.name) : "";
          findings.push({ kind: "dep", ruleId: "dep." + h.id, title: (v && v.summary) || "Known vulnerability in " + h.dep.name, sev: v ? osvSeverity(v) : "medium",
            path: h.dep.path, line: h.dep.line, col: 1, snippet: (texts.get(h.dep.path) || "").split(/\r?\n/)[h.dep.line - 1] || "",
            pkg: h.dep.name, version: h.dep.version, ecosystem: h.dep.ecosystem, advisory: h.id, cve: alias || "", fixed,
            why: `${h.dep.name} ${h.dep.version} (${h.dep.ecosystem}) is affected by ${h.id}${alias ? " / " + alias : ""}.`,
            fix: fixed ? `Upgrade ${h.dep.name} to ${fixed} or later and regenerate the lockfile.` : "No fixed release is listed yet. Check the advisory for mitigations or replace the package." });
        }
      } catch (e) { depNote = "Dependency check skipped: " + e.message; }
    }
    findings.sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev] || a.path.localeCompare(b.path) || a.line - b.line);
    return { ...meta, findings, texts, scanned: done, failed, deps: deps.length, depNote, at: Date.now() };
  }

  // Drop the paths the repository's own .darknodeignore lists; the count is shown with the results.
  async function applyIgnore(all, read) {
    const f = all.find((x) => x.path === gh.IGNORE_FILE);
    if (!f) return { kept: all, ignored: 0 };
    let m;
    try { m = gh.ignoreMatcher(await read(f)); } catch (_) { return { kept: all, ignored: 0 }; }
    const kept = all.filter((x) => !m.test(x.path));
    return { kept, ignored: all.length - kept.length };
  }

  async function runGitHub(p) {
    const ui = progress("Scanning " + p.owner + "/" + p.repo);
    try {
      ui.set(0, 1, "Reading repository…");
      const r = await gh.resolveRepo(p);
      const { kept, ignored } = await applyIgnore(await gh.listFiles(r), (f) => gh.fileText(r, f.path));
      const { chosen, skipped } = gh.pickFiles(kept, isManifest);
      if (!ui.alive()) return;
      if (!chosen.length) throw new Error("No scannable source files were found in this repository.");
      const res = await scanAll(chosen, (f) => gh.fileText(r, f.path), ui, { github: true, full: r.full, sha: r.sha, branch: r.branch, skipped, ignored, url: r.htmlUrl });
      if (res) finish(res);
    } catch (e) { if (ui.alive()) renderStart(e.message); }
  }

  async function runLocal(fileList) {
    const root = (fileList[0].webkitRelativePath || "").split("/")[0] || "folder";
    const { kept, ignored } = await applyIgnore(fileList.map((f) => ({ path: (f.webkitRelativePath || f.name).split("/").slice(1).join("/") || f.name, size: f.size, file: f })), (f) => f.file.text());
    const { chosen, skipped } = gh.pickFiles(kept, isManifest);
    const ui = progress("Scanning " + root);
    if (!chosen.length) return renderStart("No scannable source files were found in that folder.");
    const res = await scanAll(chosen, (f) => f.file.text(), ui, { github: false, full: root, sha: "", skipped, ignored });
    if (res) finish(res);
  }

  function finish(res) {
    st.scan = res; st.file = ""; st.idx = -1; st.sevOn = new Set(res.findings.some((f) => f.sev !== "info") ? SEVS.filter((v) => v !== "info") : SEVS); st.kindOn = new Set(["secret", "code", "dep"]);
    const counts = Object.fromEntries(SEVS.map((s) => [s, res.findings.filter((f) => f.sev === s).length]));
    saveRecent({ full: res.full, sha: res.sha.slice(0, 7), at: res.at, total: res.findings.length, score: repoScore(res.findings), counts });
    if (res.findings.length) st.idx = 0;
    renderWorkspace();
  }

  // ── Workspace ───────────────────────────────────────────────────────────────
  const visible = () => st.scan.findings.filter((f) => st.sevOn.has(f.sev) && st.kindOn.has(f.kind));

  function renderWorkspace() {
    ++token;
    const s = st.scan;
    const counts = Object.fromEntries(SEVS.map((v) => [v, s.findings.filter((f) => f.sev === v).length]));
    const kinds = Object.fromEntries(Object.keys(KIND_LABEL).map((k) => [k, s.findings.filter((f) => f.kind === k).length]));
    const score = repoScore(s.findings);
    const toGraph = s.findings.filter((f) => f.sev !== "info");
    body.innerHTML = `<div class="cs-sum">
        <span class="repo">${esc(s.full)}</span>${s.sha ? `<span class="sha">${esc(s.branch || "")} @ ${esc(s.sha.slice(0, 7))}</span>` : ""}
        <span class="cs-pill">${fmt(s.scanned)} files scanned</span>${s.skipped ? `<span class="cs-pill" title="Binary, vendored, generated or oversized files are skipped">${fmt(s.skipped)} skipped</span>` : ""}${s.ignored ? `<span class="cs-pill" title="The repository's .darknodeignore file lists these paths as not production code, so they were not scanned">${fmt(s.ignored)} excluded by .darknodeignore</span>` : ""}
        <span class="sp"></span>
        <span class="cs-score" title="100 means no findings. Each finding lowers the score by its severity; review items do not count.">${score}<small>/ 100</small></span>
        <button class="cs-btn sm" id="csSarif" type="button">Export SARIF</button>
        <button class="cs-btn sm" id="csCsv" type="button">Export CSV</button>
        ${toGraph.length ? `<button class="cs-btn sm" id="csGraph" type="button" title="Record these findings in the Security Graph so they appear in Findings and your exposure score. Review items are left out.">Add ${fmt(toGraph.length)} to graph</button>` : ""}
        <button class="cs-btn sm pri" id="csNew" type="button">New scan</button>
      </div>
      ${!s.deps && !s.depNote ? `<p class="cs-help" style="margin:-4px 0 12px">No lockfile or pinned dependency versions were found, so dependencies were not checked against advisories.</p>` : ""}
      ${s.depNote ? `<div class="cs-err" style="margin:0 0 12px">${esc(s.depNote)}</div>` : ""}
      <div class="cs-chips">
        ${SEVS.map((v) => `<button class="cs-chip ${st.sevOn.has(v) ? "on" : ""}" data-sev="${v}" type="button"><span class="d" style="background:var(--sev-${v})"></span>${SEV_LABEL[v]} ${fmt(counts[v])}</button>`).join("")}
        <span style="width:8px"></span>
        ${Object.keys(KIND_LABEL).map((k) => `<button class="cs-chip ${st.kindOn.has(k) ? "on" : ""}" data-kind="${k}" type="button">${KIND_LABEL[k]} ${fmt(kinds[k])}</button>`).join("")}
      </div>
      ${s.findings.length ? `<div class="cs-ws">
        <div class="cs-side l"><div class="hd"><input class="cs-in" id="csFF" placeholder="Filter files" value="${esc(st.fileFilter)}"></div><div class="cs-scroll" id="csFiles"></div></div>
        <div class="cs-mid"><div class="cs-codehd" id="csCodeHd"></div><div class="cs-code" id="csCode"></div></div>
        <div class="cs-side r"><div class="hd"><span style="flex:1">Findings</span><span class="cs-kbd" title="Next / previous finding">J</span><span class="cs-kbd">K</span></div><div class="cs-scroll" id="csFind"></div></div>
      </div>` : `<div class="cs-card cs-empty" style="padding:48px 12px"><h2 class="cs-h2">No findings</h2><p class="cs-p" style="margin:0">None of the rules matched in the ${fmt(s.scanned)} files scanned${s.deps ? `, and none of the ${fmt(s.deps)} pinned dependencies has a known advisory` : ""}.</p></div>`}`;
    body.querySelector("#csNew").onclick = () => renderStart();
    body.querySelector("#csSarif").onclick = () => download(s.full.replace(/\W+/g, "-") + ".sarif", JSON.stringify(toSarif(s.findings, { repo: s.github ? s.full : "", sha: s.sha }), null, 2), "application/json");
    body.querySelector("#csCsv").onclick = () => download(s.full.replace(/\W+/g, "-") + "-findings.csv", toCsv(s.findings), "text/csv");
    const gb = body.querySelector("#csGraph");
    if (gb) gb.onclick = () => {
      // One entity per finding (repo + file + line + rule), so a re-scan updates rather
      // than duplicates. Secret values are never written, only where they are.
      const items = toGraph.slice(0, 2000).map((f) => ({
        type: f.kind === "dep" ? "VULNERABILITY" : "FINDING",
        name: (f.kind === "dep" ? f.pkg + " " + f.version + ": " + (f.advisory || f.title) : f.title) + " (" + s.full + ":" + f.path + ":" + f.line + ")",
        data: { repo: s.full, sha: s.sha || "", path: f.path, line: f.line, rule: f.ruleId || "", cwe: f.cwe || "", advisory: f.advisory || "", cve: f.cve || "", fixedIn: f.fixed || "", kind: f.kind },
        opts: { severity: f.sev, status: "open", tags: ["code", f.kind] },
      }));
      import("/js/graph-bridge.js?v=20261012a").then((m) => {
        const r = m.sendToGraph("Code Scanner", items);
        gb.textContent = "Added to graph"; gb.disabled = true;
        try { window.showToast && window.showToast("Security Graph: " + (r.created || 0) + " added, " + (r.updated || 0) + " updated"); } catch (_) {}
      }).catch(() => { try { window.showToast && window.showToast("Couldn't reach the Security Graph", "err"); } catch (_) {} });
    };
    body.querySelectorAll("[data-sev]").forEach((b) => b.onclick = () => { toggle(st.sevOn, b.dataset.sev); st.idx = 0; renderWorkspace(); });
    body.querySelectorAll("[data-kind]").forEach((b) => b.onclick = () => { toggle(st.kindOn, b.dataset.kind); st.idx = 0; renderWorkspace(); });
    if (!s.findings.length) return;
    const ff = body.querySelector("#csFF");
    ff.oninput = () => { st.fileFilter = ff.value; drawFiles(); };
    drawFiles(); drawFindings();
    const v = visible();
    if (v.length) select(Math.min(Math.max(st.idx, 0), v.length - 1));
    else { body.querySelector("#csCode").innerHTML = `<div class="cs-empty">No findings match the selected filters.</div>`; body.querySelector("#csCodeHd").innerHTML = ""; }
  }

  function drawFiles() {
    const by = new Map();
    for (const f of visible()) { const e = by.get(f.path) || { n: 0, top: "low" }; e.n++; if (SEV_ORDER[f.sev] < SEV_ORDER[e.top]) e.top = f.sev; by.set(f.path, e); }
    const q = st.fileFilter.toLowerCase();
    const rows = [...by.entries()].filter(([p]) => !q || p.toLowerCase().includes(q)).sort((a, b) => SEV_ORDER[a[1].top] - SEV_ORDER[b[1].top] || b[1].n - a[1].n);
    const el = body.querySelector("#csFiles");
    el.innerHTML = rows.length ? rows.map(([p, e]) => `<button class="cs-file ${p === st.file ? "on" : ""}" data-path="${esc(p)}" title="${esc(p)}" type="button"><span class="p">‎${esc(p)}</span><span class="cs-n" style="background:var(--sev-${e.top})">${e.n}</span></button>`).join("") : `<div class="cs-empty">No files match.</div>`;
    el.querySelectorAll(".cs-file").forEach((b) => b.onclick = () => { const i = visible().findIndex((f) => f.path === b.dataset.path); if (i >= 0) select(i); });
  }

  function drawFindings() {
    const el = body.querySelector("#csFind");
    const v = visible();
    el.innerHTML = v.length ? v.slice(0, 1500).map((f, i) => `<button class="cs-fd ${i === st.idx ? "on" : ""}" data-i="${i}" style="${sevVar(f.sev)}" type="button"><div class="t1"><span class="cs-sev">${SEV_LABEL[f.sev]}</span><span>${esc(f.kind === "dep" ? f.pkg + " " + f.version : f.title)}</span></div><div class="t2">${f.flow ? `<span class="cs-df" title="Traced from where the input enters to where it is used">Data flow</span>` : ""}${f.advisory ? esc(f.advisory) + " · " : ""}${esc(f.path)}:${f.line}</div></button>`).join("") : `<div class="cs-empty">No findings match the selected filters.</div>`;
    el.querySelectorAll(".cs-fd").forEach((b) => b.onclick = () => select(+b.dataset.i));
  }

  async function select(i) {
    const v = visible();
    if (!v[i]) return;
    st.idx = i;
    const f = v[i];
    const s = st.scan;
    body.querySelectorAll(".cs-fd").forEach((b) => b.classList.toggle("on", +b.dataset.i === i));
    const on = body.querySelector(`.cs-fd[data-i="${i}"]`); if (on) on.scrollIntoView({ block: "nearest" });
    const ghLink = s.github ? `https://github.com/${s.full}/blob/${s.sha}/${f.path.split("/").map(encodeURIComponent).join("/")}#L${f.line}` : "";
    body.querySelector("#csCodeHd").innerHTML = `<span class="p" title="${esc(f.path)}">${esc(f.path)}</span><span class="cs-help" style="margin:0">${esc(langOf(f.path) || "text")}</span>${ghLink ? `<a class="cs-btn sm" href="${esc(ghLink)}" target="_blank" rel="noopener">Open on GitHub</a>` : ""}`;
    const code = body.querySelector("#csCode");
    if (st.file !== f.path) {
      st.file = f.path;
      drawFiles();
      const text = s.texts.get(f.path);
      if (text == null) { code.innerHTML = `<div class="cs-empty">This file's contents are not available.</div>`; return; }
      const lines = text.split(/\r?\n/);
      const marks = new Map();
      for (const x of visible().filter((x) => x.path === f.path)) { const a = marks.get(x.line) || []; a.push(x); marks.set(x.line, a); }
      const LIMIT = 20000;
      // A private key's body sits on the lines after the BEGIN marker: hide them all.
      const hidden = new Set();
      for (const [n, m] of marks) if (m.some((x) => x.ruleId === "secret.private-key") && !/-----END /.test(lines[n - 1])) for (let k = n + 1; k <= lines.length && !/-----END /.test(lines[k - 1]); k++) hidden.add(k);
      let html = "";
      for (let n = 1; n <= Math.min(lines.length, LIMIT); n++) {
        const m = marks.get(n);
        const top = m ? m.reduce((a, b) => (SEV_ORDER[b.sev] < SEV_ORDER[a.sev] ? b : a)).sev : "";
        html += `<div class="cs-ln${m ? " hit" : ""}" id="csL${n}"${m ? ` style="${sevVar(top)}"` : ""}><span class="g">${n}</span><span class="t">${hidden.has(n) ? "[key material hidden]" : esc(maskLine(lines[n - 1], m))}</span></div>`;
        if (m) html += m.map((x) => noteHtml(x, s)).join("");
      }
      if (lines.length > LIMIT) html += `<div class="cs-empty">File truncated at ${fmt(LIMIT)} lines.</div>`;
      code.innerHTML = html;
    }
    code.querySelectorAll(".cs-ln.cur").forEach((e) => e.classList.remove("cur"));
    code.querySelectorAll(".cs-note").forEach((e) => e.classList.toggle("open", e.dataset.k === f.ruleId + "|" + f.line));
    code.onclick = (e) => {
      const g = e.target.closest("[data-goto]");
      if (g) { const t = code.querySelector("#csL" + g.dataset.goto); if (t) { code.scrollTop = Math.max(0, t.offsetTop - code.clientHeight / 3); t.classList.remove("flash"); void t.offsetWidth; t.classList.add("flash"); } return; }
      const n = e.target.closest(".cs-note:not(.open)"); if (!n) return; const j = visible().findIndex((x) => x.path === st.file && x.ruleId + "|" + x.line === n.dataset.k); if (j >= 0) select(j); };
    const ln = code.querySelector("#csL" + f.line);
    if (ln) { ln.classList.add("cur"); code.scrollTop = Math.max(0, ln.offsetTop - code.clientHeight / 3); }
  }

  function noteHtml(x, s) {
    const cwe = x.cwe ? `<a href="https://cwe.mitre.org/data/definitions/${x.cwe}.html" target="_blank" rel="noopener">CWE-${x.cwe}</a>` : "";
    const adv = x.advisory ? `<a href="https://osv.dev/vulnerability/${encodeURIComponent(x.advisory)}" target="_blank" rel="noopener">${esc(x.advisory)}</a>${x.cve ? " · " + esc(x.cve) : ""}` : "";
    return `<div class="cs-note" data-k="${esc(x.ruleId + "|" + x.line)}" style="${sevVar(x.sev)}"><div class="tt"><span class="cs-sev">${SEV_LABEL[x.sev]}</span><span>${esc(x.kind === "dep" ? x.pkg + " " + x.version + ": " + x.title : x.title)}</span></div>
      <p><b>Why it matters.</b> ${esc(x.why)}</p>${x.flow ? `<p><b>Data flow.</b> How the input reaches this line:</p><ol class="cs-flow">${x.flow.map((t) => `<li><button type="button" data-goto="${t.line}" title="Show line ${t.line}">L${t.line}</button>${esc(t.label)}</li>`).join("")}</ol>` : ""}<p><b>How to fix.</b> ${esc(x.fix)}</p>
      <p>${[cwe, adv, x.secret && x.ruleId !== "secret.private-key" ? "Value: " + esc(x.secret) : "", x.kind !== "dep" ? `Rule ${esc(x.ruleId)}` : ""].filter(Boolean).join(" · ")}</p>${x.kind !== "dep" ? `<p>Not a real problem here? Put a <b>darknode-ignore</b> comment on the line (or <b>darknode-ignore-next-line</b> above it) with the reason, or list the path in a <b>.darknodeignore</b> file at the repository root.</p>` : ""}</div>`;
  }

  // Never render a detected secret in full, even in the code view.
  function maskLine(line, marks) {
    let out = String(line || "");
    for (const m of marks || []) if (m.kind === "secret") out = out.replace(/[A-Za-z0-9_\-+/=.]{16,}/g, (t) => t.slice(0, 4) + "…" + t.slice(-4));
    return out;
  }

  const onKey = (e) => {
    if (!document.body.contains(body)) { document.removeEventListener("keydown", onKey); return; }
    if (!st.scan || /^(INPUT|TEXTAREA|SELECT)$/.test((e.target && e.target.tagName) || "")) return;
    if (e.key === "j" || e.key === "k") { const n = visible().length; if (!n) return; select((st.idx + (e.key === "j" ? 1 : n - 1)) % n); e.preventDefault(); }
  };
  document.addEventListener("keydown", onKey);

  renderStart();
}

function toggle(set, v) { if (set.has(v) && set.size > 1) set.delete(v); else set.add(v); }

function toCsv(findings) {
  const q = (v) => '"' + String(v ?? "").replace(/"/g, '""') + '"';
  const rows = [["severity", "type", "title", "file", "line", "rule", "cwe", "package", "version", "advisory", "fixed_in", "data_flow"]];
  for (const f of findings) rows.push([f.sev, f.kind, f.title, f.path, f.line, f.ruleId, f.cwe || "", f.pkg || "", f.version || "", f.advisory || "", f.fixed || "", f.flow ? f.flow.map((t) => "L" + t.line + " " + t.label).join(" > ") : ""]);
  return rows.map((r) => r.map(q).join(",")).join("\n");
}

function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
