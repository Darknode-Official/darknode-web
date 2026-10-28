// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Ticket handoff dialog for the Deck Findings scene. Jira, ServiceNow and Azure
// Boards get an import-ready CSV (built by core/tickets.js, downloaded locally);
// GitHub gets real issues through the REST API with the user's own token. The token
// is sent only to api.github.com, kept in sessionStorage unless the user opts in to
// "Remember on this device" (the per-account key store), and never written anywhere else.
//
//   openTicketExport(entities, { onLinked }) -> Promise<void> (resolves when closed)
//   onLinked(entityId, { url, label }) is awaited after each issue GitHub creates.

import {
  toJiraCsv, toServiceNowCsv, toAzureDevOpsCsv, githubIssuePayload, exportable, parseRepo, hasGithubTicket, TICKET_LIMITS,
} from "../core/tickets.js";
import { download, fileStamp } from "../core/export.js";

const TOKEN_KEY = "dn_gh_issue_token";
const REPO_KEY = "dn_gh_issue_repo";
// GitHub asks for serial content creation (80/min, 500/h); one per ~1.1 s stays clear.
// https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api
const GH_DELAY_MS = 1100;

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const toast = (m, kind) => { try { (window.showToast || (() => {}))(m, kind); } catch (_) {} };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const store = (kind) => { try { return kind === "local" ? window.localStorage : window.sessionStorage; } catch (_) { return null; } };
const sget = (kind, k) => { try { return store(kind)?.getItem(k) || ""; } catch (_) { return ""; } };
const sset = (kind, k, v) => { try { v ? store(kind)?.setItem(k, v) : store(kind)?.removeItem(k); } catch (_) {} };
// The token belongs to the signed-in account, not the browser: the session copy is keyed by uid
// (a tab can sign out and in as someone else) and a remembered one lives in the per-account key
// store (user-keys.js). A token remembered under the old browser-wide key is dropped, not migrated.
const uid = () => { try { return window.__dnUid || ""; } catch (_) { return ""; } };
const sessKey = () => TOKEN_KEY + "_u_" + (uid() || "none");
const keyGet = () => { try { return (window.dnKeys && window.dnKeys.get(TOKEN_KEY)) || ""; } catch (_) { return ""; } };
const keySet = (v) => { try { if (window.dnKeys) v ? window.dnKeys.set(TOKEN_KEY, v) : window.dnKeys.del(TOKEN_KEY); } catch (_) {} };
sset("local", TOKEN_KEY, ""); sset("session", TOKEN_KEY, "");

const TARGETS = [
  { id: "jira", label: "Jira", file: "jira", make: (l, o) => toJiraCsv(l, { issueType: o.type }),
    note: "In Jira open System > External System Import > CSV. Map Summary, Issue Type, Priority, Description, Due Date and every Labels column, and set the date format to yyyy-MM-dd.",
    typeLabel: "Issue type" },
  { id: "servicenow", label: "ServiceNow", file: "servicenow", make: (l, o) => toServiceNowCsv(l, { category: o.category }),
    note: "In ServiceNow open System Import Sets > Load Data, choose File, then create a transform map to Incident (or the table you choose). Columns use incident field names; set correlation_id as coalesce so re-imports update instead of duplicating." },
  { id: "azure_devops", label: "Azure Boards", file: "azure-boards", make: (l, o) => toAzureDevOpsCsv(l, { workItemType: o.type }),
    note: "In Azure DevOps open Boards > Queries > Import work items, choose the file, review the rows, then Save items. Up to 1,000 items per file; the type must exist in your process.",
    typeLabel: "Work item type" },
  { id: "github", label: "GitHub issues" },
];

let injected = false;
function injectStyle() {
  if (injected || document.getElementById("tkx-css")) { injected = true; return; }
  injected = true;
  const st = document.createElement("style"); st.id = "tkx-css";
  st.textContent = `
  .tkx .tkx-tabs{display:flex;flex-wrap:wrap;gap:6px;margin:4px 0 14px}
  .tkx .tkx-tab{appearance:none;font:inherit;font-size:.82rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--txt,#0f172a);padding:7px 12px;border-radius:8px;cursor:pointer}
  .tkx .tkx-tab[aria-selected=true]{border-color:var(--acc,#2563eb);color:var(--acc,#2563eb);box-shadow:inset 0 0 0 1px var(--acc,#2563eb)}
  .tkx .tkx-note{font-size:.82rem;color:var(--mut,#64748b);line-height:1.5;margin:0 0 12px;overflow-wrap:anywhere}
  .tkx .tkx-fld{display:flex;flex-direction:column;gap:5px;margin-bottom:10px}
  .tkx .tkx-lbl{font-size:.78rem;font-weight:600;color:var(--txt,#0f172a)}
  .tkx .tkx-help{font-size:.74rem;color:var(--mut,#64748b);line-height:1.45;overflow-wrap:anywhere}
  .tkx .tkx-chk{display:flex;align-items:center;gap:8px;font-size:.82rem;color:var(--txt,#0f172a);margin:2px 0 10px}
  .tkx .tkx-row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:6px}
  .tkx .tkx-err{color:#b00020;font-size:.8rem;min-height:1em}
  .tkx .tkx-prog{font-size:.82rem;color:var(--txt,#0f172a);margin-top:10px}
  .tkx .tkx-bar{height:6px;border-radius:3px;background:var(--line,#e6e8ee);overflow:hidden;margin:6px 0}
  .tkx .tkx-bar>i{display:block;height:100%;width:0;background:var(--acc,#2563eb);transition:width .2s}
  .tkx .tkx-res{list-style:none;margin:8px 0 0;padding:0;max-height:180px;overflow:auto;font-size:.8rem;border-top:1px solid var(--line,#e6e8ee)}
  .tkx .tkx-res li{padding:5px 0;border-bottom:1px solid var(--line,#e6e8ee);display:flex;gap:8px;overflow-wrap:anywhere}
  .tkx .tkx-res b{flex:none;min-width:58px;font-weight:600}
  .tkx .tkx-res a{color:var(--acc,#2563eb)}
  .tkx .tkx-ok{color:#1b7f4d}.tkx .tkx-skip{color:var(--mut,#64748b)}.tkx .tkx-bad{color:#b00020}
  `;
  document.head.appendChild(st);
}

/**
 * Open the ticket export dialog for the given FINDING entities.
 * @param {object[]} entities
 * @param {{ onLinked?: (id:string, ticket:{url:string,label:string}) => any }} [o]
 * @returns {Promise<void>}
 */
export function openTicketExport(entities, { onLinked } = {}) {
  injectStyle();
  const all = Array.isArray(entities) ? entities.filter(Boolean) : [];
  const list = exportable(all);
  const sampleCount = all.length - list.length;
  let target = "jira", running = false, abort = false;
  const made = new Set(); // "owner/repo#id" issued in this dialog, so a re-run never duplicates one whose link-back failed

  return new Promise((resolve) => {
    const prevFocus = document.activeElement;
    const ov = document.createElement("div");
    ov.className = "dn-modal-ov";
    ov.innerHTML = `<div class="dn-modal tkx" role="dialog" aria-modal="true" aria-label="Create tickets">
      <div class="dn-modal-h">Create tickets</div>
      <p class="dn-modal-d">${list.length} finding${list.length === 1 ? "" : "s"} ready${sampleCount ? `; ${sampleCount} sample item${sampleCount === 1 ? "" : "s"} left out` : ""}.</p>
      <div class="tkx-tabs" role="tablist">${TARGETS.map((t) => `<button type="button" class="tkx-tab" role="tab" data-t="${t.id}">${esc(t.label)}</button>`).join("")}</div>
      <div class="tkx-body"></div>
      <div class="dn-modal-actions"><div class="dn-modal-extra"></div><div class="dn-modal-main"><button type="button" class="btn ghost sm" data-close>Close</button></div></div>
    </div>`;
    document.body.appendChild(ov);
    requestAnimationFrame(() => ov.classList.add("open"));
    const body = ov.querySelector(".tkx-body");

    const close = () => {
      if (running) { abort = true; return; }
      ov.classList.remove("open"); document.removeEventListener("keydown", onKey);
      setTimeout(() => ov.remove(), 150);
      if (prevFocus && typeof prevFocus.focus === "function" && document.contains(prevFocus)) { try { prevFocus.focus(); } catch (_) {} }
      resolve();
    };
    const onKey = (e) => {
      const tops = document.querySelectorAll(".dn-modal-ov");
      if (tops.length && tops[tops.length - 1] !== ov) return;
      if (e.key === "Escape") { e.preventDefault(); close(); }
    };
    document.addEventListener("keydown", onKey);
    ov.addEventListener("mousedown", (e) => { if (e.target === ov && !running) close(); });
    ov.querySelector("[data-close]").onclick = close;
    ov.querySelectorAll(".tkx-tab").forEach((b) => { b.onclick = () => { if (!running) { target = b.dataset.t; paint(); } }; });

    function paint() {
      ov.querySelectorAll(".tkx-tab").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.t === target)));
      if (target === "github") return paintGithub();
      const t = TARGETS.find((x) => x.id === target);
      body.innerHTML = `<p class="tkx-note">${esc(t.note)}</p>
        ${t.typeLabel ? `<label class="tkx-fld"><span class="tkx-lbl">${esc(t.typeLabel)}</span><input class="dn-modal-in" data-k="type" value="Task" placeholder="Task"><span class="tkx-help">Must match a type in the target project.</span></label>` : ""}
        ${t.id === "servicenow" ? `<label class="tkx-fld"><span class="tkx-lbl">Category (optional)</span><input class="dn-modal-in" data-k="category" placeholder="Category value"><span class="tkx-help">Use a choice value that exists on your table, or leave empty.</span></label>` : ""}
        ${t.id === "azure_devops" && list.length > TICKET_LIMITS.adoMaxRows ? `<p class="tkx-err">Azure Boards imports at most ${TICKET_LIMITS.adoMaxRows} items per file; select fewer findings.</p>` : ""}
        <div class="tkx-row"><button type="button" class="btn sm" data-dl ${list.length ? "" : "disabled"}>Download CSV</button></div>`;
      const btn = body.querySelector("[data-dl]");
      btn.onclick = () => {
        const v = (k) => (body.querySelector(`[data-k="${k}"]`) || {}).value || "";
        try {
          download(`darknode-findings-${t.file}-${fileStamp()}.csv`, t.make(list, { type: v("type"), category: v("category") }), "text/csv;charset=utf-8");
          toast(`${t.label} CSV downloaded (${list.length} row${list.length === 1 ? "" : "s"})`, "success");
        } catch (err) { toast("Could not build the CSV: " + (err && err.message || err), "error"); }
      };
    }

    function paintGithub() {
      const remembered = !!keyGet();
      const tok = sget("session", sessKey()) || keyGet();
      body.innerHTML = `<p class="tkx-note">Creates one issue per finding in your repository using your own token. Findings already linked to an issue in the same repository are skipped. Labels are applied only if the token's owner has push access.</p>
        <label class="tkx-fld"><span class="tkx-lbl">Repository</span><input class="dn-modal-in" data-k="repo" placeholder="owner/repo" autocomplete="off" spellcheck="false" value="${esc(sget("local", REPO_KEY))}"></label>
        <label class="tkx-fld"><span class="tkx-lbl">Fine-grained token</span><input class="dn-modal-in" data-k="token" type="password" placeholder="Token" autocomplete="off" spellcheck="false" value="${esc(tok)}"><span class="tkx-help">Needs repository access to this repo with Issues: Read and write. Sent only to api.github.com.</span></label>
        <label class="tkx-chk"><input type="checkbox" data-k="remember" ${remembered ? "checked" : ""}> Remember on this device</label>
        <div class="tkx-err" data-err></div>
        <div class="tkx-row"><button type="button" class="btn sm" data-go ${list.length ? "" : "disabled"}>Create issues</button>${tok ? `<button type="button" class="btn ghost sm" data-forget>Forget token</button>` : ""}</div>
        <div class="tkx-prog" data-prog hidden><div data-ptxt></div><div class="tkx-bar"><i></i></div><ul class="tkx-res"></ul></div>`;
      const $ = (s) => body.querySelector(s);
      const forget = $("[data-forget]");
      if (forget) forget.onclick = () => { sset("session", sessKey(), ""); keySet(""); toast("GitHub token removed from this browser", "info"); paintGithub(); };
      $("[data-go]").onclick = () => runGithub($);
    }

    async function runGithub($) {
      const err = $("[data-err]");
      const rp = parseRepo($('[data-k="repo"]').value);
      const token = $('[data-k="token"]').value.trim();
      err.textContent = "";
      if (!rp) { err.textContent = "Enter the repository as owner/repo."; return; }
      if (!token || /\s/.test(token)) { err.textContent = "Enter a GitHub token."; return; }
      const remember = $('[data-k="remember"]').checked;
      sset("session", sessKey(), token);
      keySet(remember ? token : "");
      sset("local", REPO_KEY, rp.owner + "/" + rp.repo);

      const rk = (rp.owner + "/" + rp.repo).toLowerCase() + "#";
      const todo = list.filter((e) => !hasGithubTicket(e, rp.owner, rp.repo) && !made.has(rk + e.id));
      const skipped = list.length - todo.length;
      if (!todo.length) { err.textContent = "Every selected finding already has an issue in " + rp.owner + "/" + rp.repo + "."; return; }
      const ok = typeof window.dnConfirm === "function"
        ? await window.dnConfirm("Create " + todo.length + " GitHub issue" + (todo.length === 1 ? "" : "s") + "?", "Issues are created in " + rp.owner + "/" + rp.repo + " one at a time and notify the repository's watchers." + (skipped ? " " + skipped + " already linked will be skipped." : ""), { submitText: "Create" })
        : false;
      if (!ok) return;

      running = true; abort = false;
      const go = $("[data-go]"), prog = $("[data-prog]"), ptxt = $("[data-ptxt]"), bar = prog.querySelector(".tkx-bar>i"), res = prog.querySelector(".tkx-res");
      go.disabled = true; prog.hidden = false; res.innerHTML = "";
      const closeBtn = ov.querySelector("[data-close]"); closeBtn.textContent = "Stop";
      const line = (cls, tag, html) => { const li = document.createElement("li"); li.innerHTML = `<b class="${cls}">${esc(tag)}</b><span>${html}</span>`; res.appendChild(li); li.scrollIntoView({ block: "nearest" }); };
      if (skipped) line("tkx-skip", "Skipped", esc(skipped + " already linked to an issue in this repository"));

      let created = 0, failed = 0, stopped = "";
      const url = `https://api.github.com/repos/${encodeURIComponent(rp.owner)}/${encodeURIComponent(rp.repo)}/issues`;
      for (let i = 0; i < todo.length; i++) {
        if (abort) { stopped = "Stopped by you."; break; }
        const e = todo[i], payload = githubIssuePayload(e);
        ptxt.textContent = `Creating ${i + 1} of ${todo.length}...`;
        let r, j = null;
        try {
          r = await fetch(url, {
            method: "POST", credentials: "omit", referrerPolicy: "no-referrer",
            headers: { "Accept": "application/vnd.github+json", "Authorization": "Bearer " + token, "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json" },
            body: JSON.stringify(payload),
          });
          try { j = await r.json(); } catch (_) {}
        } catch (x) { stopped = "Network error reaching api.github.com: " + (x && x.message || x); break; }
        const msg = (j && j.message) || "";
        if (r.status === 201 && j && j.html_url) {
          created++; made.add(rk + e.id);
          line("tkx-ok", "#" + j.number, `<a href="${esc(j.html_url)}" target="_blank" rel="noopener noreferrer">${esc(payload.title)}</a>`);
          try { if (typeof onLinked === "function") await onLinked(e.id, { url: j.html_url, label: "GitHub #" + j.number }); }
          catch (x) { line("tkx-bad", "Link", esc("Issue created but the finding could not be updated: " + (x && x.message || x))); }
        } else if (r.status === 401) { sset("session", sessKey(), ""); keySet(""); stopped = "GitHub rejected the token (401). Check that it is valid and not expired."; break; }
        else if (r.status === 403 || r.status === 429) {
          const ra = Number(r.headers.get("retry-after")), rem = r.headers.get("x-ratelimit-remaining"), reset = Number(r.headers.get("x-ratelimit-reset"));
          const wait = ra ? `Retry in ${ra} s.` : rem === "0" && reset ? `Retry after ${new Date(reset * 1000).toLocaleTimeString()}.` : "Wait at least a minute before retrying.";
          stopped = /rate limit/i.test(msg) || r.status === 429 || rem === "0"
            ? "GitHub rate limit reached. " + wait
            : "Forbidden (403): the token needs Issues: Read and write on this repository." + (msg ? " GitHub said: " + msg : "");
          break;
        }
        else if (r.status === 404) { stopped = "Repository not found, or the token cannot see it (404)."; break; }
        else if (r.status === 410) { stopped = "Issues are disabled for this repository (410)."; break; }
        else { failed++; line("tkx-bad", String(r.status), esc(payload.title + (msg ? ": " + msg : ""))); }
        bar.style.width = Math.round(((i + 1) / todo.length) * 100) + "%";
        if (i < todo.length - 1) await sleep(GH_DELAY_MS);
      }
      running = false; closeBtn.textContent = "Close"; go.disabled = false;
      const sum = `Created ${created} of ${todo.length}` + (skipped ? `, skipped ${skipped}` : "") + (failed ? `, ${failed} failed` : "") + ".";
      ptxt.textContent = sum + (stopped ? " " + stopped : "");
      if (stopped) line("tkx-bad", "Stopped", esc(stopped));
      toast(sum + (stopped ? " " + stopped : ""), created && !stopped && !failed ? "success" : created ? "warning" : "error");
    }

    paint();
    const first = ov.querySelector(".tkx-tab"); if (first) first.focus();
  });
}
