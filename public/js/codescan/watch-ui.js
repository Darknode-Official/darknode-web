// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Code Scanner: commit watch + GitHub Actions setup (browser layer).
//
// Watching a repository branch stores { repo, branch, last scanned commit, running
// baseline } in this browser (localStorage, per Darknode user). No token is stored
// unless the user opts in on the token form. Each check lists the commits added since
// the last scanned one, then for every commit, oldest first: the compare API gives the
// changed files, only those are fetched and scanned (secrets, code rules, data flow,
// and OSV.dev when a manifest changed), and the per-file diff against the running
// baseline gives that commit's new and fixed findings. Pure logic: watch.js, ci.js.

import { newWatch, watchKey, listNewCommits, commitMeta, planCommit, applyCommit, chip, graphItem, COMMIT_CAP } from "./watch.js?v=20261017d";
import { workflowYaml, toBase64, resolvePin, sha256Hex, WORKFLOW_PATH, FAIL_LEVELS, SCANNER_REPO } from "./ci.js?v=20261017d";

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmt = (n) => Number(n || 0).toLocaleString();
const short = (sha) => String(sha || "").slice(0, 7);
const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
const INTERVALS = [[0, "Off"], [5, "Every 5 min"], [15, "Every 15 min"], [30, "Every 30 min"], [60, "Every hour"]];
const LOCKS = /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml)$/;
const blobUrl = (full, sha, path, line) => `https://github.com/${full}/blob/${sha}/${String(path).split("/").map(encodeURIComponent).join("/")}${line ? "#L" + line : ""}`;
const ago = (ms) => {
  if (!ms) return "";
  const s = Math.max(0, (Date.now() - ms) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return Math.floor(s / 60) + " min ago";
  if (s < 86400) return Math.floor(s / 3600) + " h ago";
  if (s < 86400 * 30) return Math.floor(s / 86400) + " d ago";
  try { return new Date(ms).toLocaleDateString(); } catch (_) { return ""; }
};

const CSS = `<style id="cs-watch-css">
.csw-card{background:var(--cs-card);border:1px solid var(--cs-line);border-radius:10px;padding:16px 18px;margin-top:14px;min-width:0}
.csw-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:14px 0 4px}
.csw-head .repo{font-weight:650;font-size:15px;min-width:0;overflow-wrap:anywhere}
.csw-head .sp{flex:1}
.csw-meta{display:flex;gap:6px 14px;flex-wrap:wrap;font-size:12.5px;color:var(--cs-mut);margin:4px 0 0}
.csw-meta b{color:var(--cs-txt);font-weight:600}
.csw-mono{font:12px ui-monospace,SFMono-Regular,Menlo,monospace}
.csw-bar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:12px}
.csw-bar .cs-in{flex:0 1 220px;min-width:120px}
.csw-sel{height:28px;border:1px solid var(--cs-line);border-radius:6px;background:var(--cs-card);color:var(--cs-txt);font:inherit;font-size:12.5px;padding:0 6px;max-width:100%}
.csw-note{border:1px solid var(--cs-line);border-left:3px solid var(--sev-medium);border-radius:8px;padding:10px 12px;font-size:13px;margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;line-height:1.45}
.csw-note.err{border-left-color:var(--sev-critical)}
.csw-note span{flex:1;min-width:200px}
.csw-tl{margin-top:12px;border:1px solid var(--cs-line);border-radius:10px;background:var(--cs-card);overflow:hidden}
.csw-row{display:flex;align-items:center;gap:6px 12px;flex-wrap:wrap;padding:10px 14px;border-top:1px solid var(--cs-line);cursor:pointer;font-size:13px}
.csw-row:first-child{border-top:0}
.csw-row:hover{background:color-mix(in srgb,var(--cs-txt) 3%,transparent)}
.csw-row.on{background:color-mix(in srgb,var(--cs-acc) 7%,transparent)}
.csw-row .msg{flex:1 1 260px;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.csw-row .who{color:var(--cs-mut);font-size:12px;white-space:nowrap;max-width:min(280px,100%);overflow:hidden;text-overflow:ellipsis}
.csw-row a.csw-mono{color:var(--cs-acc);text-decoration:none}
.csw-chip{display:inline-flex;align-items:center;height:22px;padding:0 8px;border-radius:999px;font-size:11.5px;font-weight:650;white-space:nowrap;border:1px solid var(--cs-line);color:var(--cs-mut);background:var(--cs-card)}
.csw-chip.ok{color:#067647;border-color:color-mix(in srgb,#067647 35%,transparent);background:color-mix(in srgb,#067647 7%,transparent)}
.csw-chip.crit{color:#fff;background:var(--sev-critical);border-color:var(--sev-critical)}
.csw-chip.high{color:#fff;background:var(--sev-high);border-color:var(--sev-high)}
.csw-chip.med{color:var(--sev-medium);border-color:color-mix(in srgb,var(--sev-medium) 40%,transparent)}
.csw-chip.warn,.csw-chip.err{color:var(--sev-critical);border-color:color-mix(in srgb,var(--sev-critical) 40%,transparent)}
.csw-chip.run{color:var(--cs-acc);border-color:color-mix(in srgb,var(--cs-acc) 40%,transparent)}
.csw-tag{font-size:10.5px;font-weight:650;border:1px dashed var(--cs-line);border-radius:4px;padding:0 5px;color:var(--cs-mut)}
.csw-det{padding:4px 14px 14px;border-top:1px dashed var(--cs-line);background:color-mix(in srgb,var(--cs-txt) 2%,var(--cs-card));font-size:13px;cursor:default}
.csw-det h3{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--cs-mut);margin:12px 0 6px;font-weight:650}
.csw-it{display:flex;align-items:center;gap:8px;padding:5px 0;min-width:0;flex-wrap:wrap}
.csw-it .lb{flex:1 1 200px;min-width:0;overflow-wrap:anywhere}
.csw-it a{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--cs-acc);min-width:0;overflow-wrap:anywhere}
.csw-empty{padding:22px 12px;text-align:center;color:var(--cs-mut);font-size:13px}
.csw-list .row{display:flex;align-items:center;gap:8px 10px;flex-wrap:wrap;padding:9px 0;border-top:1px solid var(--cs-line);font-size:13px}
.csw-list .row:first-child{border-top:0}
.csw-list .nm{flex:1 1 160px;min-width:0;font-weight:600;overflow-wrap:anywhere}
.csw-yaml{margin:10px 0 0;max-height:300px;overflow:auto;border:1px solid var(--cs-line);border-radius:8px;padding:10px 12px;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;background:color-mix(in srgb,var(--cs-txt) 2%,var(--cs-card));white-space:pre}
.csw-perm{margin:8px 0 0;padding-left:18px;font-size:12.5px;color:var(--cs-mut);line-height:1.6}
.csw-perm b{color:var(--cs-txt)}
.csw-runs .row{display:flex;align-items:center;gap:6px 10px;flex-wrap:wrap;padding:8px 0;border-top:1px solid var(--cs-line);font-size:13px}
.csw-runs .row:first-child{border-top:0}
.csw-runs .t{flex:1 1 200px;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.csw-chk{display:inline-flex;align-items:center;gap:6px;font-size:12.5px;color:var(--cs-txt)}
</style>`;

/**
 * ctx: { body, gh, engine: { scanFile, isManifest, parseManifest, depFinding }, toast(msg, kind),
 *        claim() → render token, current(t) → bool, back(), fullRescan(parsedRepo), showScan() }
 */
export function createWatch(ctx) {
  const { body, gh, engine } = ctx;
  const toast = ctx.toast || (() => {});
  const running = new Map();   // key → { queue: [meta], current: sha }
  const view = { key: "", open: "", tok: 0, runs: null, runsErr: "", ci: { failOn: "high", deps: false }, pin: null, pinBusy: false, pinErr: "" };
  const lsKey = () => { let uid = "anon"; try { uid = window.__dnUid || "anon"; } catch (_) {} return "dn_codescan_watch_" + uid; };
  const loadAll = () => { try { const j = JSON.parse(localStorage.getItem(lsKey()) || "{}"); return j && typeof j === "object" && !Array.isArray(j) ? j : {}; } catch (_) { return {}; } };
  const load = (key) => loadAll()[key] || null;
  const save = (state) => saveState(state);
  function saveState(state) {
    const all = loadAll();
    all[watchKey(state.full, state.branch)] = state;
    try { localStorage.setItem(lsKey(), JSON.stringify(all)); return true; }
    catch (_) { toast("Couldn't save the watch in this browser: storage is full", "error"); return false; }
  }
  function remove(key) { const all = loadAll(); delete all[key]; try { localStorage.setItem(lsKey(), JSON.stringify(all)); } catch (_) {} }
  const css = () => { if (!document.getElementById("cs-watch-css")) document.head.insertAdjacentHTML("beforeend", CSS); };

  // ── Engine glue ─────────────────────────────────────────────────────────────
  const inScopeFor = (ig) => (path) => !ig.test(path) && gh.pickFiles([{ path, size: 0 }], engine.isManifest, Infinity).chosen.length === 1;
  const scanText = (path, text) => (typeof text !== "string" || text.indexOf("\u0000") >= 0) ? [] : engine.scanFile(path, text).map((f) => ({ ...f, path }));
  const repoRef = (state, sha) => ({ full: state.full, private: !!state.private, sha });
  const isRate = (e) => !!(e && (e.rateLimited || /rate limit/i.test(e.message || "")));

  // OSV for the manifests a commit touched. A package.json beside a lockfile is skipped
  // (the lockfile has the exact versions), matching the full scan.
  async function depsFor(list, knownPaths) {
    const dir = (p) => p.replace(/[^/]*$/, "");
    const lockDirs = new Set([...knownPaths, ...list.map((m) => m.path)].filter((p) => LOCKS.test(p)).map(dir));
    const deps = [];
    for (const m of list) {
      if (/(^|\/)package\.json$/.test(m.path) && lockDirs.has(dir(m.path))) continue;
      for (const d of engine.parseManifest(m.path, m.text)) deps.push({ ...d, path: m.path });
    }
    if (!deps.length) return [];
    const hits = await gh.osvQuery(deps);
    const ids = [...new Set(hits.map((h) => h.id))].slice(0, 300);
    const details = new Map();
    await gh.pool(ids, 8, async (id) => { details.set(id, await gh.osvVuln(id)); });
    const texts = new Map(list.map((m) => [m.path, m.text]));
    const seen = new Set(), out = [];
    for (const h of hits) {
      const k = h.dep.path + "|" + h.dep.name + "|" + h.id;
      if (seen.has(k)) continue; seen.add(k);
      out.push(engine.depFinding(h.dep, h.id, details.get(h.id), (texts.get(h.dep.path) || "").split(/\r?\n/)[h.dep.line - 1] || ""));
    }
    return out;
  }

  // Fetch + scan one commit's changed files. `known` decides which previous versions
  // must be scanned too (files the baseline has never seen). files: optional compare list.
  async function collect(state, c, known, files) {
    let truncated = false;
    if (!files) {
      const res = c.parent ? await gh.api(`/repos/${state.full}/compare/${c.parent}...${c.sha}`) : await gh.api(`/repos/${state.full}/commits/${c.sha}`);
      files = res.files || [];
    }
    truncated = files.length >= 300; // the API lists at most 300 files per comparison
    let ignoreText = state.ignoreText || "";
    const igf = files.find((f) => f.filename === gh.IGNORE_FILE);
    if (igf) ignoreText = igf.status === "removed" ? "" : await gh.fileText(repoRef(state, c.sha), gh.IGNORE_FILE).catch((e) => { if (isRate(e)) throw e; return ignoreText; });
    const plan = planCommit(files, inScopeFor(gh.ignoreMatcher(ignoreText)), known);
    const results = [];
    await gh.pool(plan, 6, async (p) => {
      const r = { path: p.path, oldPath: p.oldPath, status: p.status, findings: p.status === "removed" || p.status === "excluded" ? [] : null };
      results.push(r);
      try {
        if (p.head) {
          const t = await gh.fileText(repoRef(state, c.sha), p.path);
          if (typeof t === "string" && t.length > gh.MAX_FILE) { r.status = "excluded"; return; }
          r.text = t; r.findings = scanText(p.path, t);
        }
        if (p.base && c.parent) {
          let bt = null;
          try { bt = await gh.fileText(repoRef(state, c.parent), p.oldPath); } catch (e) { if (isRate(e)) throw e; }
          r.oldText = typeof bt === "string" && bt.length <= gh.MAX_FILE ? bt : null;
          r.oldFindings = r.oldText == null ? [] : scanText(p.oldPath, r.oldText);
        } else if (p.base) r.oldFindings = [];
      } catch (e) { if (isRate(e)) throw e; r.findings = null; r.error = e.message; }
    });
    let depNote = "";
    const mf = results.filter((r) => engine.isManifest(r.path) && (r.text != null || r.oldText != null));
    if (mf.length) {
      try {
        const kp = Object.keys(state.known || {});
        const head = await depsFor(mf.filter((r) => r.text != null).map((r) => ({ path: r.path, text: r.text })), kp);
        const base = await depsFor(mf.filter((r) => r.oldText != null).map((r) => ({ path: r.oldPath, text: r.oldText })), kp);
        for (const r of mf) {
          if (r.findings) r.findings.push(...head.filter((f) => f.path === r.path));
          if (r.oldFindings) r.oldFindings.push(...base.filter((f) => f.path === r.oldPath));
        }
      } catch (e) {
        depNote = "Dependency check skipped: " + e.message;
        // Keep the previous advisories so a failed lookup never reads as "fixed".
        for (const r of mf) if (r.findings) r.findings.push(...((state.files || {})[r.oldPath] || []).filter((i) => i.kind === "dep"));
      }
    }
    for (const r of results) { delete r.text; delete r.oldText; }
    return { results, ignoreText, truncated, depNote, nFiles: files.length };
  }

  // ── Checking for new commits ────────────────────────────────────────────────
  async function check(key, { quiet = false } = {}) {
    if (running.has(key)) return;
    let state = load(key);
    if (!state) return;
    const run = { queue: [], current: "" };
    running.set(key, run);
    // Settings and manual scans may change while a check runs: keep the stored ones.
    // Returns false once the user has stopped watching, which ends the run.
    const save = (st) => { const cur = load(key); if (!cur) { running.delete(key); return false; } st.interval = cur.interval; st.manual = cur.manual; return saveState(st); };
    state.lastCheck = Date.now(); state.notice = null;
    save(state); redraw(key);
    try {
      const fetchPage = (page, per) => gh.api(`/repos/${state.full}/commits?sha=${encodeURIComponent(state.branch)}&per_page=${per}&page=${page}`);
      const res = await listNewCommits(fetchPage, state.lastSha, COMMIT_CAP);
      let queue = res.commits.map((c) => commitMeta(c, state.full));
      const forced = () => ({ kind: "force", text: `Commit ${short(state.lastSha)} is no longer on ${state.branch} (the branch was force-pushed or rewritten), so commit-by-commit diffs can't continue from it. Run a full rescan at HEAD to start a new baseline.` });
      if (res.exhausted) { state.notice = forced(); queue = []; }
      else if (res.capped && queue.length) {
        // More than COMMIT_CAP new commits, or history rewritten: the compare status decides.
        let cmp = null;
        try { cmp = await gh.api(`/repos/${state.full}/compare/${state.lastSha}...${queue[0].sha}`); } catch (e) { if (e.status !== 404) throw e; }
        if (!cmp || (cmp.status !== "ahead" && cmp.status !== "identical")) { state.notice = forced(); queue = []; }
        else if (queue[0].parent && queue[0].parent !== state.lastSha) {
          const earlier = Math.max(1, (cmp.ahead_by || 0) - 1);
          queue.unshift({ sha: queue[0].parent, parent: state.lastSha, parents: 1, author: "", combined: true, at: queue[0].at,
            msg: `${fmt(earlier)} earlier commit${earlier === 1 ? "" : "s"} (more than ${COMMIT_CAP} new), scanned together`,
            url: `https://github.com/${state.full}/compare/${state.lastSha}...${queue[0].parent}` });
          state.notice = { kind: "info", text: `More than ${COMMIT_CAP} new commits: the latest ${COMMIT_CAP} are scanned one by one and the older ones as a single combined change.` };
        }
      }
      save(state);
      run.queue = queue.slice();
      redraw(key);
      let newHigh = 0;
      for (const c of queue) {
        if (!running.has(key)) break;
        run.current = c.sha; redraw(key);
        try {
          const col = await collect(state, c, state.known || {});
          const out = applyCommit(state, col.results, { sha: c.sha, parent: c.parent, parents: c.parents, author: c.author, msg: c.msg, at: c.at, url: c.url, combined: !!c.combined, truncated: col.truncated, depNote: col.depNote, scannedAt: Date.now() });
          state = { ...out.state, ignoreText: col.ignoreText };
          save(state);
          newHigh += publish(state, c, out.added);
        } catch (e) {
          if (isRate(e)) {
            const at = gh.rate.reset ? new Date(gh.rate.reset).toLocaleTimeString() : "later";
            state.notice = { kind: "rate", text: `GitHub API limit reached after commit ${short(state.lastSha)}. The remaining ${fmt(run.queue.length)} commit(s) wait until the limit resets at ${at}; use Resume then.${gh.connected() ? "" : " A token raises the limit from 60 to 5,000 requests an hour."}` };
          } else {
            state.commits = [{ ...c, status: "error", error: e.message }, ...(state.commits || []).filter((x) => x.sha !== c.sha)].slice(0, 100);
            state.notice = { kind: "err", text: `Stopped at commit ${short(c.sha)}: ${e.message} Later commits were not scanned yet; Resume retries from there.` };
          }
          save(state);
          break;
        } finally {
          run.queue = run.queue.filter((x) => x.sha !== c.sha);
        }
      }
      if (!quiet) {
        if (state.notice && state.notice.kind !== "info") toast(state.notice.text, "error");
        else if (!newHigh) toast(queue.length ? `${state.full}: ${queue.length} new commit${queue.length === 1 ? "" : "s"} scanned` : `${state.full}: no new commits`, "ok");
      }
    } catch (e) {
      state.notice = isRate(e)
        ? { kind: "rate", text: `GitHub API limit reached. It resets at ${gh.rate.reset ? new Date(gh.rate.reset).toLocaleTimeString() : "the top of the hour"}; use Resume then.${gh.connected() ? "" : " A token raises the limit from 60 to 5,000 requests an hour."}` }
        : { kind: "err", text: e.status === 404 && !gh.connected() ? `${state.full} was not found. If it is private, add a token with Contents: Read access to it.` : e.message };
      save(state);
      if (!quiet) toast(state.notice.text, "error");
    } finally {
      running.delete(key);
      redraw(key);
    }
  }

  // New critical/high (data-flow confirmed or plain rule) findings → Security Graph + toast.
  function publish(state, c, added) {
    const hot = (added || []).filter((f) => (f.sev === "critical" || f.sev === "high") && f.confidence !== "review" && f.ruleId);
    if (!hot.length) return 0;
    const crit = hot.filter((f) => f.sev === "critical").length;
    toast(`${state.full} @ ${short(c.sha)}: ${hot.length} new ${crit ? crit + " critical, " + (hot.length - crit) + " high" : "high"} finding${hot.length === 1 ? "" : "s"}`, "error");
    import("/js/graph-bridge.js?v=20261017d").then((m) => m.sendToGraph("Code Scanner", hot.slice(0, 500).map((f) => graphItem(f, { full: state.full, sha: c.sha })))).catch(() => {});
    return hot.length;
  }

  async function manualScan(key, sha) {
    const state = load(key);
    if (!state) return;
    sha = String(sha || "").trim();
    if (!/^[0-9a-f]{7,40}$/i.test(sha)) { toast("Enter a commit SHA (7 to 40 hexadecimal characters)", "error"); return; }
    if (running.has(key)) { toast("A check is already running for this repository", "error"); return; }
    running.set(key, { queue: [], current: sha, manual: true });
    redraw(key);
    try {
      const one = await gh.api(`/repos/${state.full}/commits/${sha}`);
      const c = commitMeta(one, state.full);
      // Independent of the running baseline: every changed file's previous version is scanned.
      const col = await collect({ ...state, known: {} }, c, {}, one.files || []);
      const out = applyCommit({ files: {}, known: {}, commits: [] }, col.results, { ...c, manual: true, truncated: col.truncated, depNote: col.depNote, scannedAt: Date.now() });
      const s2 = load(key) || state;
      s2.manual = [out.record, ...(s2.manual || []).filter((x) => x.sha !== c.sha)].slice(0, 10);
      save(s2);
      view.open = "m:" + c.sha;
      toast(`Commit ${short(c.sha)}: ${chip(out.record).text}`, "ok");
    } catch (e) {
      toast(isRate(e) ? "GitHub API limit reached. Try again after it resets." : e.status === 404 ? "That commit was not found in " + state.full + "." : e.message, "error");
    } finally { running.delete(key); redraw(key); }
  }

  // ── Starting a watch ────────────────────────────────────────────────────────
  // From a finished full GitHub scan: that scan IS the baseline.
  function fromScan(s) {
    const st = newWatch({ full: s.full, branch: s.branch, isPrivate: !!s.private, sha: s.sha, findings: s.findings, paths: s.paths || [], ignoreText: s.ignoreText || "", mode: "full" });
    const prev = load(watchKey(s.full, s.branch));
    if (prev) { st.interval = prev.interval || 0; st.commits = prev.commits || []; st.manual = prev.manual || []; }
    save(st);
    return watchKey(s.full, s.branch);
  }
  const resetFromScan = (s) => { const k = watchKey(s.full, s.branch); if (load(k)) fromScan(s); return k; };

  // From a chosen commit without a full scan: only later changes are scanned, and each
  // changed file's previous version is scanned on demand so old findings are not "new".
  async function startAt(p, sha) {
    const r = await gh.resolveRepo(p);
    let at = r.sha;
    if (sha) { const c = await gh.api(`/repos/${r.full}/commits/${encodeURIComponent(sha)}`); at = c.sha; }
    let ignoreText = "";
    try { ignoreText = await gh.fileText({ full: r.full, private: r.private, sha: at }, gh.IGNORE_FILE); } catch (e) { if (isRate(e)) throw e; }
    const st = newWatch({ full: r.full, branch: r.branch, isPrivate: r.private, sha: at, ignoreText, mode: "lazy" });
    save(st);
    return watchKey(r.full, r.branch);
  }

  // ── Watched list (start screen) ─────────────────────────────────────────────
  function mountList(el) {
    css();
    const all = loadAll();
    const keys = Object.keys(all);
    el.innerHTML = `<h2 class="cs-h2">Watch commits</h2>
      <p class="cs-p">Scan each new commit on a branch as it lands and see what it added or fixed. Repositories you watch are saved in this browser only.</p>
      ${keys.length ? `<div class="csw-list">${keys.map((k) => { const s = all[k]; const last = (s.commits || [])[0]; const c = running.has(k) ? { cls: "run", text: "Checking" } : s.notice && s.notice.kind !== "info" ? { cls: "err", text: s.notice.kind === "force" ? "Needs full rescan" : s.notice.kind === "rate" ? "Paused: rate limit" : "Error" } : last ? chip(last) : { cls: "", text: "No new commits" };
        return `<div class="row"><span class="nm">${esc(s.full)} <span class="csw-mono" style="font-weight:400;color:var(--cs-mut)">${esc(s.branch)}</span></span><span class="csw-chip ${c.cls}">${esc(c.text)}</span><button class="cs-btn sm" data-wopen="${esc(k)}" type="button">Commits</button></div>`; }).join("")}</div>` : ""}
      <div class="cs-row" style="margin-top:12px"><input class="cs-in" id="cswRepo" placeholder="owner/repo" autocomplete="off" spellcheck="false" aria-label="Repository to watch"></div>
      <div class="cs-row" style="margin-top:8px"><select class="csw-sel" id="cswFrom" aria-label="Start watching from"><option value="full">Full scan of the latest commit first</option><option value="sha">From a commit I choose</option></select>
        <input class="cs-in" id="cswSha" placeholder="Commit SHA" autocomplete="off" spellcheck="false" hidden style="flex:0 1 160px" aria-label="Commit to start from"><button class="cs-btn" id="cswGo" type="button">Watch</button></div>
      <p class="cs-help">A full scan sets the baseline. Starting from a commit scans only the files later commits change. Add /tree/branch to watch a branch other than the default.</p>
      <div class="cs-err" id="cswErr" hidden></div>`;
    el.querySelectorAll("[data-wopen]").forEach((b) => b.onclick = () => open(b.dataset.wopen));
    const from = el.querySelector("#cswFrom"), shaIn = el.querySelector("#cswSha"), err = el.querySelector("#cswErr");
    from.onchange = () => { shaIn.hidden = from.value !== "sha"; };
    el.querySelector("#cswGo").onclick = async (e) => {
      const p = gh.parseRepo(el.querySelector("#cswRepo").value);
      err.hidden = true;
      if (!p) { err.textContent = "Enter a repository as owner/repo or a github.com link."; err.hidden = false; return; }
      if (from.value === "full") { ctx.fullRescan(p, true); return; }
      e.target.disabled = true;
      try { const k = await startAt(p, shaIn.value.trim()); open(k); }
      catch (x) { err.textContent = x.message; err.hidden = false; e.target.disabled = false; }
    };
  }

  // ── Commits view ────────────────────────────────────────────────────────────
  function open(key) {
    css();
    view.key = key; view.tok = ctx.claim(); view.runs = null; view.runsErr = "";
    const state = load(key);
    if (!state) { ctx.back(); return; }
    body.innerHTML = `<div class="csw" id="cswRoot"></div>`;
    draw();
  }

  function redraw(key) {
    if (view.key !== key || !ctx.current(view.tok) || !body.querySelector("#cswRoot")) return;
    draw();
  }

  function authLine() {
    const r = gh.rate;
    const who = gh.connected() ? `${gh.tokenKind() === "pat" ? "Token" : "GitHub"}: <b>${esc(gh.ghUser())}</b>` : "No token: 60 GitHub API requests an hour";
    return `<span>${who}</span>${r.remaining != null ? `<span>API requests left: <b>${fmt(r.remaining)}</b> of ${fmt(r.limit)}${r.reset ? ", resets " + esc(new Date(r.reset).toLocaleTimeString()) : ""}</span>` : ""}`;
  }

  function draw() {
    const root = body.querySelector("#cswRoot");
    if (!root) return;
    const key = view.key, s = load(key);
    if (!s) { ctx.back(); return; }
    const run = running.get(key);
    const pending = run ? run.queue.slice().reverse().map((c) => ({ ...c, status: c.sha === run.current ? "scanning" : "queued" })) : [];
    const rows = [...pending, ...(s.commits || []).filter((c) => !pending.some((p) => p.sha === c.sha))];
    const n = s.notice;
    root.innerHTML = `<div class="csw-head"><button class="cs-btn sm" id="cswBack" type="button">Back</button>
        <span class="repo">${esc(s.full)}</span><span class="cs-pill">${esc(s.branch)}</span>${s.private ? '<span class="cs-pill">Private</span>' : ""}
        <span class="sp"></span>
        <button class="cs-btn sm pri" id="cswCheck" type="button" ${run ? "disabled" : ""}>${run && !run.manual ? "Checking…" : n && (n.kind === "rate" || n.kind === "err") ? "Resume" : "Check for new commits"}</button>
        <button class="cs-btn sm" id="cswFull" type="button" ${run ? "disabled" : ""}>Full rescan at HEAD</button></div>
      <div class="csw-meta"><span>Last scanned commit <a class="csw-mono" href="https://github.com/${esc(s.full)}/commit/${esc(s.lastSha)}" target="_blank" rel="noopener">${esc(short(s.lastSha))}</a></span>
        <span>${s.mode === "full" ? "Baseline: full scan" : "Baseline: changed files only, from " + esc(short(s.startSha))}</span>
        <span>Last check: ${s.lastCheck ? esc(ago(s.lastCheck)) : "never"}</span>${authLine()}</div>
      ${n ? `<div class="csw-note ${n.kind === "info" ? "" : "err"}"><span>${esc(n.text)}</span>${n.kind === "force" ? `<button class="cs-btn sm pri" data-act="full" type="button">Full rescan</button>` : ""}</div>` : ""}
      <div class="csw-bar">
        <label class="csw-chk" for="cswInt">Check automatically</label>
        <select class="csw-sel" id="cswInt">${INTERVALS.map(([v, l]) => `<option value="${v}" ${(+s.interval || 0) === v ? "selected" : ""}>${l}</option>`).join("")}</select>
        <span style="flex:1"></span>
        <input class="cs-in" id="cswMan" placeholder="Commit SHA" autocomplete="off" spellcheck="false" aria-label="Commit SHA to scan">
        <button class="cs-btn sm" id="cswManGo" type="button" ${run ? "disabled" : ""}>Scan a specific commit</button>
        <button class="cs-link" id="cswStop" type="button">Stop watching</button>
      </div>
      <p class="cs-help">Automatic checks run only while this page is open. Each check costs one GitHub API request when nothing changed, plus about one per new commit.</p>
      <div class="csw-tl" id="cswTl">${rows.length ? rows.map((c) => rowHtml(s, c, "c:")).join("") : `<div class="csw-empty">${run ? "Looking for new commits…" : "No commits scanned yet. New commits on " + esc(s.branch) + " after " + esc(short(s.lastSha)) + " appear here."}</div>`}</div>
      ${(s.manual || []).length ? `<h2 class="cs-h2" style="margin-top:18px">Scanned on request</h2><p class="cs-p" style="margin:0">Each changed file compared with its previous version; the watch baseline is not changed.</p><div class="csw-tl">${s.manual.map((c) => rowHtml(s, c, "m:")).join("")}</div>` : ""}
      <div class="csw-card" id="cswCi"></div>`;
    root.querySelector("#cswBack").onclick = () => ctx.back();
    root.querySelector("#cswCheck").onclick = () => check(key);
    const full = () => ctx.fullRescan({ owner: s.full.split("/")[0], repo: s.full.split("/")[1], branch: s.branch }, true);
    root.querySelector("#cswFull").onclick = full;
    root.querySelectorAll('[data-act="full"]').forEach((b) => b.onclick = full);
    root.querySelector("#cswInt").onchange = (e) => { const x = load(key); if (x) { x.interval = +e.target.value || 0; save(x); } };
    const man = root.querySelector("#cswMan");
    root.querySelector("#cswManGo").onclick = () => manualScan(key, man.value);
    man.onkeydown = (e) => { if (e.key === "Enter") manualScan(key, man.value); };
    root.querySelector("#cswStop").onclick = async () => {
      const ok = typeof window.dnConfirm === "function" ? await window.dnConfirm("Stop watching " + s.full + "?", "Removes the saved baseline and commit history for " + s.full + " (" + s.branch + ") from this browser.", { danger: true, submitText: "Stop watching" }) : false;
      if (!ok) return;
      running.delete(key); remove(key); ctx.back();
    };
    root.querySelectorAll(".csw-row").forEach((r) => r.onclick = (e) => {
      if (e.target.closest("a,button")) return;
      view.open = view.open === r.dataset.id ? "" : r.dataset.id; draw();
    });
    root.querySelectorAll("[data-rescan]").forEach((b) => b.onclick = () => manualScan(key, b.dataset.rescan));
    drawCi(s);
  }

  function rowHtml(s, c, prefix) {
    const id = prefix + c.sha;
    const ch = chip(c);
    const on = view.open === id;
    return `<div class="csw-row ${on ? "on" : ""}" data-id="${esc(id)}">
        <span class="csw-chip ${ch.cls}">${esc(ch.text)}</span>
        <a class="csw-mono" href="${esc(c.url || "https://github.com/" + s.full + "/commit/" + c.sha)}" target="_blank" rel="noopener">${esc(c.combined ? short(c.parent) + "…" + short(c.sha) : short(c.sha))}</a>
        <span class="msg" title="${esc(c.msg)}">${esc(c.msg || "(no message)")}</span>
        ${c.combined ? '<span class="csw-tag">Combined</span>' : ""}${(c.parents || 0) > 1 ? '<span class="csw-tag">Merge</span>' : ""}
        <span class="who">${esc(c.author)}${c.at ? " · " + esc(ago(c.at)) : ""}</span></div>${on ? detailHtml(s, c) : ""}`;
  }

  function itemHtml(s, it, sha) {
    return `<div class="csw-it" style="--sev:var(--sev-${SEV_LABEL[it.sev] ? it.sev : "low"})"><span class="cs-sev">${SEV_LABEL[it.sev] || "Low"}</span>${it.conf === "review" ? '<span class="cs-rev">Needs review</span>' : ""}<span class="lb">${esc(it.label)}</span>
      <a href="${esc(blobUrl(s.full, sha, it.path, it.line))}" target="_blank" rel="noopener">${esc(it.path)}:${it.line}</a></div>`;
  }

  function detailHtml(s, c) {
    if (c.status === "scanning" || c.status === "queued") return `<div class="csw-det"><p class="cs-help">${c.status === "scanning" ? "Scanning the files this commit changed…" : "Waiting for the commits before it."}</p></div>`;
    if (c.status === "error") return `<div class="csw-det"><p class="cs-help">${esc(c.error || "This commit could not be scanned.")}</p></div>`;
    const notes = [];
    if (c.truncated) notes.push("GitHub lists at most 300 changed files per comparison, so files beyond that were not scanned.");
    if (c.failed) notes.push(`${fmt(c.failed)} changed file(s) could not be read and keep their previous findings.`);
    if (c.depNote) notes.push(c.depNote);
    const newer = c.newItems || [], fixed = c.fixedItems || [];
    return `<div class="csw-det">
      <p class="cs-help">${fmt(c.files || 0)} changed file(s) scanned${c.scannedAt ? " · " + esc(ago(c.scannedAt)) : ""}${c.manual ? " · compared with the previous version of each file" : ""}.</p>
      ${notes.map((t) => `<p class="cs-help">${esc(t)}</p>`).join("")}
      <h3>New in this commit (${fmt(Object.values(c.counts || {}).reduce((a, b) => a + b, 0))})</h3>
      ${newer.length ? newer.map((it) => itemHtml(s, it, c.sha)).join("") : '<p class="cs-help" style="margin:0">Nothing new.</p>'}
      <h3>Fixed by this commit (${fmt(c.fixedCount || 0)})</h3>
      ${fixed.length ? fixed.map((it) => itemHtml(s, it, c.parent || c.sha)).join("") : '<p class="cs-help" style="margin:0">Nothing fixed.</p>'}
      ${!c.combined && !c.manual ? `<div class="cs-row" style="margin-top:10px"><button class="cs-btn sm" data-rescan="${esc(c.sha)}" type="button">Rescan this commit on its own</button></div>` : ""}
    </div>`;
  }

  // ── GitHub Actions: generate, install, follow runs ──────────────────────────
  function drawCi(s) {
    const el = body.querySelector("#cswCi");
    if (!el) return;
    const pin = view.pin;
    const yaml = pin ? workflowYaml({ pin, failOn: view.ci.failOn, deps: view.ci.deps }) : "";
    const pat = gh.connected() && gh.tokenKind() === "pat";
    const pinHtml = pin
      ? `<p class="cs-help">Scanner pinned to <a class="csw-mono" href="https://github.com/${SCANNER_REPO}/tree/${esc(pin.sha)}/public/js/codescan" target="_blank" rel="noopener">${esc(SCANNER_REPO)}@${esc(pin.sha.slice(0, 7))}</a>${pin.date ? " (" + esc(new Date(pin.date).toLocaleDateString()) + ")" : ""}. The workflow downloads those exact files and checks each SHA-256 before running, so it fails rather than run anything else. Regenerate and update the file to upgrade the scanner. <button class="cs-link" id="cswPin" type="button" ${view.pinBusy ? "disabled" : ""}>${view.pinBusy ? "Checking…" : "Check for a newer scanner"}</button></p>`
      : `<p class="cs-help">The workflow pins the scanner to the latest commit of ${esc(SCANNER_REPO)} and the SHA-256 of each file, so a run can only use the exact code you generated it with.</p>
        <div class="cs-row"><button class="cs-btn sm pri" id="cswPin" type="button" ${view.pinBusy ? "disabled" : ""}>${view.pinBusy ? "Pinning the scanner…" : "Generate workflow"}</button></div>${view.pinErr ? `<div class="cs-err">${esc(view.pinErr)}</div>` : ""}`;
    el.innerHTML = `<h2 class="cs-h2">Scan every commit with GitHub Actions</h2>
      <p class="cs-p">Runs the same scanner on every push and pull request inside your repository's own GitHub Actions, with no browser open. Only findings that are new versus the previous commit fail the run, and results go to the repository's Security tab (code scanning). Your code is not sent to Darknode.</p>
      <div class="cs-row"><label class="csw-chk" for="cswFail">Fail on</label><select class="csw-sel" id="cswFail">${FAIL_LEVELS.map((v) => `<option value="${v}" ${view.ci.failOn === v ? "selected" : ""}>${v === "none" ? "Never (report only)" : v[0].toUpperCase() + v.slice(1) + (v === "low" ? "" : " and above")}</option>`).join("")}</select>
        <label class="csw-chk"><input type="checkbox" id="cswDeps" ${view.ci.deps ? "checked" : ""}> Check dependencies (OSV.dev)</label></div>
      ${pinHtml}
      ${pin ? `<pre class="csw-yaml" id="cswYaml">${esc(yaml)}</pre>
      <div class="cs-row" style="margin-top:10px"><button class="cs-btn sm" id="cswCopy" type="button">Copy YAML</button><button class="cs-btn sm" id="cswDl" type="button">Download</button>
        <button class="cs-btn sm pri" id="cswPut" type="button">Add to ${esc(s.full)}</button></div>` : ""}
      <p class="cs-help">Save it as <span class="csw-mono">${esc(WORKFLOW_PATH)}</span>, or add it here with a fine-grained personal access token${pat ? "" : " (use one from the GitHub tab on the start screen)"} that has:</p>
      <ul class="csw-perm"><li>Repository access: <b>only ${esc(s.full)}</b></li><li><b>Contents: Read and write</b> to commit the file</li><li><b>Workflows: Read and write</b>, which GitHub requires for any file under .github/workflows</li><li><b>Actions: Read-only</b> to list the runs below (Metadata: Read-only is added automatically)</li></ul>
      <p class="cs-help">GitHub sign-in from Darknode can't add workflow files: it doesn't ask for the workflow scope.</p>
      <div class="cs-row" style="margin-top:14px"><h2 class="cs-h2" style="flex:1;margin:0">Recent runs</h2><button class="cs-btn sm" id="cswRuns" type="button">${view.runs ? "Refresh" : "Load runs"}</button></div>
      <div class="csw-runs" id="cswRunList">${runsHtml()}</div>`;
    el.querySelector("#cswFail").onchange = (e) => { view.ci.failOn = e.target.value; drawCi(s); };
    el.querySelector("#cswDeps").onchange = (e) => { view.ci.deps = e.target.checked; drawCi(s); };
    el.querySelector("#cswPin").onclick = async () => {
      view.pinBusy = true; view.pinErr = ""; drawCi(s);
      try {
        const next = await resolvePin({ fetch: (u, o) => fetch(u, o), sha256: sha256Hex });
        if (view.pin && view.pin.sha === next.sha) toast("The workflow already uses the newest scanner", "ok");
        view.pin = next;
      } catch (e) { view.pinErr = e.message; if (view.pin) toast(e.message, "error"); }
      view.pinBusy = false;
      if (body.querySelector("#cswCi")) drawCi(s);
    };
    el.querySelector("#cswRuns").onclick = () => loadRuns(s);
    if (!pin) return;
    el.querySelector("#cswCopy").onclick = async () => { try { await navigator.clipboard.writeText(yaml); toast("Workflow copied", "ok"); } catch (_) { toast("Couldn't copy. Select the text and copy it instead.", "error"); } };
    el.querySelector("#cswDl").onclick = () => {
      const url = URL.createObjectURL(new Blob([yaml], { type: "text/yaml" }));
      const a = Object.assign(document.createElement("a"), { href: url, download: "darknode-scan.yml" });
      document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    };
    el.querySelector("#cswPut").onclick = () => installWorkflow(s, yaml);
  }

  function runsHtml() {
    if (view.runsErr) return `<p class="cs-help">${esc(view.runsErr)}</p>`;
    if (!view.runs) return `<p class="cs-help">Load the workflow's runs to see every commit's result here.</p>`;
    if (!view.runs.length) return `<p class="cs-help">No runs yet. The first one starts with the next push.</p>`;
    return view.runs.map((r) => {
      const res = r.status !== "completed" ? { cls: "run", text: r.status === "queued" ? "Queued" : "Running" } : r.conclusion === "success" ? { cls: "ok", text: "Passed" } : r.conclusion === "failure" ? { cls: "crit", text: "New findings" } : { cls: "", text: String(r.conclusion || "Done").replace(/_/g, " ") };
      return `<div class="row"><span class="csw-chip ${res.cls}">${esc(res.text)}</span><a class="csw-mono" href="${esc(r.html_url)}" target="_blank" rel="noopener">${esc(short(r.head_sha))}</a>
        <span class="t" title="${esc(r.display_title || "")}">${esc(r.display_title || "")}</span><span class="cs-help" style="margin:0">${esc(r.head_branch || "")} · ${esc(r.event || "")} · ${esc(ago(Date.parse(r.created_at)))}</span></div>`;
    }).join("");
  }

  async function loadRuns(s) {
    if (view.runsBusy) return;
    view.runsBusy = true; view.runsErr = "";
    const btn0 = body.querySelector("#cswRuns");
    if (btn0) { btn0.disabled = true; btn0.textContent = "Loading…"; }
    try {
      const j = await gh.api(`/repos/${s.full}/actions/workflows/darknode-scan.yml/runs?per_page=15`);
      view.runs = j.workflow_runs || [];
    } catch (e) {
      view.runs = null;
      view.runsErr = isRate(e) ? e.message : e.status === 404 ? `No ${WORKFLOW_PATH} workflow was found in ${s.full}${gh.connected() ? ", or the token can't read its Actions" : " (a private repository needs a token with Actions: Read-only)"}.` : e.message;
    } finally { view.runsBusy = false; }
    const el = body.querySelector("#cswRunList");
    if (el && view.key === watchKey(s.full, s.branch)) el.innerHTML = runsHtml();
    const b = body.querySelector("#cswRuns"); if (b) { b.disabled = false; b.textContent = "Refresh"; }
  }

  async function installWorkflow(s, yaml) {
    if (!gh.connected() || gh.tokenKind() !== "pat") { toast("Add a fine-grained personal access token first (start screen, GitHub tab), or copy the YAML into the repository yourself.", "error"); return; }
    const ok = typeof window.dnConfirm === "function" ? await window.dnConfirm("Add the workflow to " + s.full + "?",
      "Commits " + WORKFLOW_PATH + " to the " + s.branch + " branch of " + s.full + " as " + gh.ghUser() + ". If the file already exists it is replaced. The commit itself starts the first scan.", { submitText: "Add workflow" }) : false;
    if (!ok) return;
    const path = WORKFLOW_PATH.split("/").map(encodeURIComponent).join("/");
    try {
      let existing = null;
      try { existing = await gh.api(`/repos/${s.full}/contents/${path}?ref=${encodeURIComponent(s.branch)}`); } catch (e) { if (e.status !== 404) throw e; }
      await gh.api(`/repos/${s.full}/contents/${path}`, { method: "PUT", body: { message: existing ? "Update Darknode code scan workflow" : "Add Darknode code scan workflow", content: toBase64(yaml), branch: s.branch, ...(existing && existing.sha ? { sha: existing.sha } : {}) } });
      toast("Workflow added to " + s.full + " (" + s.branch + ")", "ok");
      setTimeout(() => loadRuns(s), 4000);
    } catch (e) {
      const msg = isRate(e) ? e.message
        : e.status === 404 ? `GitHub answered 404: this token can't see ${s.full}, or can't write workflow files there. Check the token's repository access and that it has Contents and Workflows set to Read and write.`
        : e.status === 403 ? `GitHub refused the write (403). The token needs Contents: Read and write and Workflows: Read and write on ${s.full}, and an organization may have to approve fine-grained tokens first.`
        : e.status === 409 || e.status === 422 ? `GitHub rejected the commit (${e.status}): the ${s.branch} branch may be protected, or the file changed meanwhile. Try again, or open a pull request with the YAML instead.`
        : e.message;
      toast(msg, "error");
    }
  }

  // ── Opening the scanner + automatic checks ──────────────────────────────────
  function autoStart() {
    const all = loadAll();
    for (const k of Object.keys(all).slice(0, 5)) if (!all[k].private || gh.connected()) check(k, { quiet: true });
    const timer = setInterval(() => {
      if (!document.body.contains(body)) { clearInterval(timer); return; }
      const now = Date.now(), a = loadAll();
      for (const k of Object.keys(a)) { const s = a[k]; if (s.interval > 0 && now - (s.lastCheck || 0) >= s.interval * 60000 && (!s.private || gh.connected())) check(k, { quiet: true }); }
    }, 60000);
  }

  return { mountList, open, fromScan, resetFromScan, autoStart, isWatched: (full, branch) => !!load(watchKey(full, branch)), keyOf: watchKey };
}
