// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Code Scanner commit watch: pure state + diff logic (no DOM, no network, no storage).
//
// A watch keeps, per repository branch, the last scanned commit and a running
// baseline: the findings of every scanned file, stored as compact items (stable key,
// severity, kind, label, path, line; never a secret value). Each new commit changes a
// set of files; those files are rescanned at that commit and diffed per file against
// the running baseline, giving that commit's NEW and FIXED findings. A removed file
// fixes all of its findings. The browser layer (watch-ui.js) does the fetching and
// persistence; tests drive these functions with fixture data.

import { findingKey, diffFile } from "./baseline.js?v=20261017d";

export const COMMIT_CAP = 100;   // most commits listed per check
export const HISTORY_CAP = 100;  // commit records kept per watch
export const ITEMS_PER_COMMIT = 200;

// Compact, storable form of a finding. `k` is the line-independent baseline key.
export function toItem(f) {
  if (f && f.k && !f.ruleId) return f;
  const label = f.kind === "dep" ? (f.pkg || "") + " " + (f.version || "") + ": " + (f.title || f.advisory || "") : (f.title || f.ruleId || "");
  const it = { k: f.k || findingKey(f), sev: f.sev || "low", kind: f.kind || "code", label: String(label).slice(0, 180), path: String(f.path || ""), line: f.line || 1, rule: f.ruleId || f.rule || "" };
  if (f.cwe) it.cwe = f.cwe;
  if (f.advisory) it.adv = f.advisory;
  if (f.confidence === "review" || f.conf === "review") it.conf = "review";
  return it;
}

const byPath = (items) => {
  const files = {};
  for (const it of items) (files[it.path] = files[it.path] || []).push(it);
  return files;
};

/**
 * A new watch. `findings` + `paths` come from a full scan at `sha` (paths = every file
 * that scan covered, so a later change to a clean file is known to start clean). With
 * no findings/paths the watch starts empty and each changed file's previous version
 * is scanned on demand instead.
 */
export function newWatch({ full, branch, isPrivate = false, sha, findings = [], paths = [], ignoreText = "", at = Date.now(), mode = "full" }) {
  const known = {};
  for (const p of paths) known[p] = 1;
  return { v: 1, full, branch, private: !!isPrivate, lastSha: sha, startSha: sha, mode, at, lastCheck: 0, interval: 0,
    files: byPath(findings.map(toItem)), known, ignoreText: String(ignoreText || ""), commits: [], manual: [] };
}

export const watchKey = (full, branch) => String(full).toLowerCase() + "@" + String(branch || "");

/**
 * Walk the branch history newest-first until `knownSha`, at most `cap` commits.
 * fetchPage(page, perPage) resolves to the GitHub /commits array for that page.
 * → { commits: oldest-first, found, capped, exhausted }
 *   found     — knownSha was reached; `commits` is exactly the new range
 *   capped    — stopped at `cap` without reaching knownSha (long gap OR rewritten history)
 *   exhausted — history ended without knownSha: the branch no longer contains it (force-push)
 */
export async function listNewCommits(fetchPage, knownSha, cap = COMMIT_CAP) {
  const per = Math.min(100, cap);
  const out = [];
  let found = false, exhausted = false;
  for (let page = 1; out.length < cap; page++) {
    const list = await fetchPage(page, per);
    if (!Array.isArray(list)) break;
    for (const c of list) {
      if (c.sha === knownSha) { found = true; break; }
      out.push(c);
      if (out.length >= cap) break;
    }
    if (found) break;
    if (list.length < per) { exhausted = true; break; }
  }
  return { commits: out.reverse(), found, capped: !found && !exhausted && out.length >= cap, exhausted: !found && exhausted };
}

// The few fields the timeline shows, from a GitHub commit object (list or compare).
export function commitMeta(c, full) {
  const msg = String((c.commit && c.commit.message) || "").split(/\r?\n/)[0].slice(0, 200);
  const au = (c.author && c.author.login) || (c.commit && c.commit.author && c.commit.author.name) || "";
  return { sha: c.sha, parent: (c.parents && c.parents[0] && c.parents[0].sha) || "", parents: (c.parents || []).length,
    author: String(au).slice(0, 80), msg, at: Date.parse((c.commit && (c.commit.committer || c.commit.author) || {}).date || "") || 0,
    url: c.html_url || ("https://github.com/" + full + "/commit/" + c.sha) };
}

/**
 * Which files a commit touched, and what to fetch for each.
 * files: GitHub compare `files` ({ filename, status, previous_filename }).
 * inScope(path) → whether the scanner covers this path (skip rules + .darknodeignore).
 * known: the watch's known-path map; a changed file the baseline has never seen needs
 * its previous version scanned so its old findings are not reported as new.
 * → [{ path, oldPath, status, head, base }]   status: added | modified | renamed | removed | excluded
 */
export function planCommit(files, inScope, known = {}) {
  const plan = [];
  for (const f of files || []) {
    let status = f.status;
    if (status === "unchanged") continue;
    if (status === "copied") status = "added";
    if (status === "changed") status = "modified";
    const path = f.filename, oldPath = status === "renamed" ? (f.previous_filename || path) : path;
    if (status === "removed") { plan.push({ path, oldPath, status, head: false, base: !known[oldPath] && inScope(oldPath) }); continue; }
    const headIn = inScope(path);
    if (!headIn) { plan.push({ path, oldPath, status: "excluded", head: false, base: false }); continue; }
    const base = status !== "added" && !known[oldPath] && inScope(oldPath);
    plan.push({ path, oldPath, status, head: true, base });
  }
  return plan;
}

/**
 * Apply one commit to a watch. results: [{ path, oldPath, status, findings, oldFindings? }]
 *   findings     the file's findings at the commit (null when the fetch failed: the file
 *                keeps its baseline and the commit is marked partial)
 *   oldFindings  the previous version's findings, when the baseline did not know the file
 * Returns { state, record }; never mutates the input state.
 */
export function applyCommit(state, results, meta = {}) {
  const files = { ...state.files };
  const known = { ...state.known };
  const added = [], fixed = [];
  let failed = 0, scanned = 0;
  for (const r of results || []) {
    const oldPath = r.oldPath || r.path;
    const old = r.oldFindings ? r.oldFindings.map(toItem) : (files[oldPath] || []);
    if (r.status === "excluded") { delete files[oldPath]; delete known[oldPath]; delete files[r.path]; delete known[r.path]; continue; }
    if (r.status === "removed") { fixed.push(...old); delete files[oldPath]; delete known[oldPath]; continue; }
    if (r.findings == null) { failed++; continue; }
    scanned++;
    const d = diffFile(old, r.findings, { asPath: oldPath !== r.path ? oldPath : undefined });
    added.push(...d.added);
    fixed.push(...d.fixed.map(toItem));
    if (oldPath !== r.path) { delete files[oldPath]; delete known[oldPath]; }
    const items = r.findings.map(toItem);
    if (items.length) files[r.path] = items; else delete files[r.path];
    known[r.path] = 1;
  }
  const newItems = added.map(toItem);
  const record = { ...meta, status: failed ? "partial" : "done", files: scanned, failed,
    counts: sevCounts(newItems), fixedCount: fixed.length,
    newItems: newItems.slice(0, ITEMS_PER_COMMIT), fixedItems: fixed.slice(0, ITEMS_PER_COMMIT) };
  const next = { ...state, files, known, lastSha: meta.sha || state.lastSha, commits: [record, ...(state.commits || []).filter((c) => c.sha !== meta.sha)].slice(0, HISTORY_CAP) };
  return { state: next, record, added };
}

export function sevCounts(items) {
  const c = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const it of items || []) if (it.sev in c) c[it.sev]++;
  return c;
}

// Status chip text for a commit record.
export function chip(rec) {
  if (!rec) return { cls: "", text: "" };
  if (rec.status === "scanning") return { cls: "run", text: "Scanning" };
  if (rec.status === "queued") return { cls: "run", text: "Queued" };
  if (rec.status === "error") return { cls: "err", text: "Error" };
  const c = rec.counts || {};
  const n = (c.critical || 0) + (c.high || 0) + (c.medium || 0) + (c.low || 0);
  const parts = [];
  if (n) {
    const top = ["critical", "high"].filter((s) => c[s]).map((s) => c[s] + " " + s);
    parts.push(n + " new" + (top.length ? ": " + top.join(", ") : ""));
  }
  if (rec.fixedCount) parts.push("fixed " + rec.fixedCount);
  if (!parts.length) return { cls: rec.status === "partial" ? "warn" : "ok", text: rec.status === "partial" ? "Clean (partial)" : "Clean" };
  return { cls: c.critical ? "crit" : c.high ? "high" : n ? "med" : "ok", text: parts.join(" · ") + (rec.status === "partial" ? " (partial)" : "") };
}

// Security Graph entity for a finding, named exactly like the Code Scanner's
// "Add to graph" entities so a commit finding and a full-scan finding merge.
export function graphItem(f, { full, sha }) {
  return {
    type: f.kind === "dep" ? "VULNERABILITY" : "FINDING",
    name: (f.kind === "dep" ? f.pkg + " " + f.version + ": " + (f.advisory || f.title) : f.title) + " (" + full + ":" + f.path + ":" + f.line + ")",
    data: { repo: full, sha: sha || "", commit: sha || "", path: f.path, line: f.line, rule: f.ruleId || "", cwe: f.cwe || "", advisory: f.advisory || "", cve: f.cve || "", fixedIn: f.fixed || "", kind: f.kind,
      evidence: [{ type: "commit", commit: sha || "", url: sha ? "https://github.com/" + full + "/commit/" + sha : "", location: f.path + ":" + f.line }] },
    opts: { severity: f.sev, status: "open", tags: ["code", f.kind, "commit-watch"] },
  };
}
