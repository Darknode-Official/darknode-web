// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved.
// Ticket handoff, pure half: turns Security Graph FINDING entities into the import
// formats of the ticketing systems teams already run. No DOM, no network, no clock:
// the same entities always give the same bytes. deck/ticket-export.js does the I/O.
//
// Formats, checked against the vendors' documentation (2026-10):
//  Jira Cloud CSV import (External System Import > CSV):
//    https://support.atlassian.com/jira-cloud-administration/docs/import-data-from-a-csv-file/
//    Header row must contain Summary (the only required column) and should carry no
//    punctuation. Multiple labels = one label per column, the "Labels" column repeated.
//    Dates are parsed with the Java SimpleDateFormat chosen in the wizard (we emit
//    yyyy-MM-dd). Jira labels cannot contain spaces. Summary is capped at 255 chars.
//  ServiceNow Import Sets (System Import Sets > Load Data, then a transform map):
//    https://www.servicenow.com/docs/r/integrate-applications/system-import-sets/c_ImportSetsKeyConcepts.html
//    RFC 4180 CSV, the first row becomes the import set columns, and "double quotes
//    may not appear inside fields" (so we swap " for ' in this format only).
//    Incident impact/urgency are 1 - High, 2 - Medium, 3 - Low and priority is looked
//    up from the pair:
//    https://www.servicenow.com/docs/r/zurich/it-service-management/incident-management/def-prio-lookup-rules.html
//    Columns use the incident/task field names (short_description is 160 chars on
//    incident; correlation_id lets a transform map coalesce re-imports).
//  Azure Boards "Import work items" from CSV (Boards > Queries > Import work items):
//    https://learn.microsoft.com/en-us/azure/devops/boards/queries/import-work-items-from-csv
//    New items need Work Item Type + Title and no ID column; at most 1,000 rows per
//    file; Description is an HTML field (line breaks become <p>); multiple tags are
//    separated by semicolons; Priority is 1-4. Fields must exist on the type, so we
//    keep to Title/Description/Priority/Tags (Due Date is not on every process).
//  GitHub REST "Create an issue" (POST /repos/{owner}/{repo}/issues):
//    https://docs.github.com/en/rest/issues/issues#create-an-issue
//    Body { title (required), body, labels }; labels need push access and are
//    silently dropped otherwise. Title max 256 chars, body max 65536 code points
//    (https://github.com/dead-claudia/github-limits). Label names are kept to 50
//    chars, the length GitHub's label form accepts (not stated in the REST reference).

import { isSimulated } from "./posture.js";

export const TICKET_TARGETS = ["jira", "servicenow", "azure_devops", "github"];

/** Field limits applied before export (see the doc links above). */
export const TICKET_LIMITS = {
  jiraSummary: 255, jiraLabel: 255,
  snowShortDescription: 160,
  adoTitle: 255, adoTag: 100, adoMaxRows: 1000,
  ghTitle: 256, ghBody: 65536, ghLabel: 50, ghLabels: 10,
  evidenceLines: 10, evidenceLine: 300,
};

const SEVS = ["critical", "high", "medium", "low", "info"];
const PRIORITY = { critical: "Highest", high: "High", medium: "Medium", low: "Low", info: "Lowest" }; // Jira default scheme
const ADO_PRIORITY = { critical: 1, high: 2, medium: 3, low: 4, info: 4 };
// [impact, urgency] -> ServiceNow sample lookup priority 1..5 (Critical..Planning).
const SNOW_IU = { critical: [1, 1], high: [2, 1], medium: [2, 2], low: [2, 3], info: [3, 3] };

const str = (v) => String(v == null ? "" : v);
const sevOf = (e) => (SEVS.includes(str(e && e.severity).toLowerCase()) ? str(e.severity).toLowerCase() : "info");
const cut = (s, n) => { const a = Array.from(str(s)); return a.length <= n ? str(s) : a.slice(0, Math.max(0, n - 3)).join("") + "..."; };
const uniqCI = (arr) => { const seen = new Set(), out = []; for (const x of arr) { const k = x.toLowerCase(); if (x && !seen.has(k)) { seen.add(k); out.push(x); } } return out; };

/** Accepts ms, ISO/date strings, Firestore-style {seconds} or {toMillis()}; returns YYYY-MM-DD (UTC) or null. */
export function isoDate(v) {
  if (v == null || v === "") return null;
  let ms;
  if (typeof v === "number") ms = v;
  else if (typeof v === "string") { if (/^\d{4}-\d{2}-\d{2}$/.test(v)) return v; ms = Date.parse(v); }
  else if (typeof v.toMillis === "function") ms = v.toMillis();
  else if (typeof v.seconds === "number") ms = v.seconds * 1000;
  else if (v instanceof Date) ms = v.getTime();
  if (!Number.isFinite(ms)) return null;
  return new Date(ms).toISOString().slice(0, 10);
}

/** Entities that may leave the platform: present and not sample/simulated data. */
export function exportable(entities) {
  return (entities || []).filter((e) => e && typeof e === "object" && !isSimulated(e));
}

/** Title without the "(tool:key)" suffix the sink adds for dedupe. */
function titleOf(e) {
  const d = e.data || {};
  let t = str(e.name).trim();
  if (d.tool && d.findingKey) {
    const suf = ` (${d.tool}:${d.findingKey})`;
    if (t.endsWith(suf)) t = t.slice(0, -suf.length).trim();
  } else t = t.replace(/\s*\([a-z0-9_-]+:[a-z0-9]+\)$/i, "").trim();
  return t || "Untitled finding";
}

function evidenceLine(ev) {
  if (ev == null) return "";
  if (typeof ev !== "object") return cut(str(ev).replace(/\s+/g, " ").trim(), TICKET_LIMITS.evidenceLine);
  const parts = Object.keys(ev).sort().map((k) => {
    const v = ev[k];
    return k + ": " + (v != null && typeof v === "object" ? JSON.stringify(v) : str(v));
  });
  return cut(parts.join("; ").replace(/\s+/g, " ").trim(), TICKET_LIMITS.evidenceLine);
}

// Structured content shared by every renderer.
function parts(e) {
  const d = (e && e.data) || {};
  const tool = str(d.tool) || "darknode";
  const key = str(d.findingKey) || str(e.id);
  const evidence = (Array.isArray(d.evidence) ? d.evidence : []).map(evidenceLine).filter(Boolean);
  const evTotal = Math.max(evidence.length, Number(d.evidenceCount) || 0);
  return {
    title: titleOf(e), severity: sevOf(e), status: str(e.status) || "open", tool, key,
    description: str(d.description).trim(), recommendation: str(d.recommendation).trim(),
    assets: (Array.isArray(d.assets) ? d.assets : []).map((a) => str(a && typeof a === "object" ? a.name : a).trim()).filter(Boolean),
    controls: (Array.isArray(d.controls) ? d.controls : []).filter((c) => c && str(c.id).trim()).map((c) => `${str(c.framework)} ${str(c.id)}`.trim()),
    evidence: evidence.slice(0, TICKET_LIMITS.evidenceLines), evMore: Math.max(0, evTotal - Math.min(evidence.length, TICKET_LIMITS.evidenceLines)),
    firstSeen: isoDate(e.createdAt), dueDate: isoDate(d.dueAt), owner: str(d.owner).trim(),
    sourceRef: `Darknode finding: ${key} (${tool})`,
  };
}

function renderMarkdown(p) {
  const L = [];
  if (p.description) L.push(p.description, "");
  if (p.recommendation) L.push("### Recommendation", "", p.recommendation, "");
  if (p.assets.length) L.push("### Affected assets", "", ...p.assets.map((a) => "- `" + a.replace(/`/g, "'") + "`"), "");
  if (p.controls.length) L.push("### Control references", "", ...p.controls.map((c) => "- " + c), "");
  if (p.evidence.length) {
    L.push("### Evidence", "", "```", ...p.evidence.map((x) => x.replace(/```/g, "'''")), "```");
    if (p.evMore) L.push(`_${p.evMore} more evidence item(s) in Darknode._`);
    L.push("");
  }
  L.push("### Details", "", `- Severity: ${p.severity}`, `- Status: ${p.status}`);
  if (p.firstSeen) L.push(`- First seen: ${p.firstSeen}`);
  if (p.dueDate) L.push(`- Due: ${p.dueDate}`);
  if (p.owner) L.push(`- Owner: ${p.owner}`);
  L.push("", "---", p.sourceRef);
  return L.join("\n");
}

function renderText(p) {
  const L = [];
  if (p.description) L.push(p.description, "");
  if (p.recommendation) L.push("Recommendation:", p.recommendation, "");
  if (p.assets.length) L.push("Affected assets:", ...p.assets.map((a) => "- " + a), "");
  if (p.controls.length) L.push("Control references:", ...p.controls.map((c) => "- " + c), "");
  if (p.evidence.length) {
    L.push("Evidence:", ...p.evidence.map((x) => "- " + x));
    if (p.evMore) L.push(`(${p.evMore} more evidence item(s) in Darknode)`);
    L.push("");
  }
  L.push(`Severity: ${p.severity}`, `Status: ${p.status}`);
  if (p.firstSeen) L.push(`First seen: ${p.firstSeen}`);
  if (p.dueDate) L.push(`Due: ${p.dueDate}`);
  if (p.owner) L.push(`Owner: ${p.owner}`);
  L.push("", p.sourceRef);
  return L.join("\n");
}

const h = (s) => str(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
function renderHtml(p) {
  const para = (s) => str(s).split(/\r?\n/).filter((l) => l.trim()).map((l) => `<p>${h(l)}</p>`).join("");
  const list = (a) => "<ul>" + a.map((x) => `<li>${h(x)}</li>`).join("") + "</ul>";
  let o = "";
  if (p.description) o += para(p.description);
  if (p.recommendation) o += "<p><strong>Recommendation</strong></p>" + para(p.recommendation);
  if (p.assets.length) o += "<p><strong>Affected assets</strong></p>" + list(p.assets);
  if (p.controls.length) o += "<p><strong>Control references</strong></p>" + list(p.controls);
  if (p.evidence.length) o += "<p><strong>Evidence</strong></p>" + list(p.evidence) + (p.evMore ? `<p>${p.evMore} more evidence item(s) in Darknode</p>` : "");
  const det = [`Severity: ${p.severity}`, `Status: ${p.status}`];
  if (p.firstSeen) det.push(`First seen: ${p.firstSeen}`);
  if (p.dueDate) det.push(`Due: ${p.dueDate}`);
  if (p.owner) det.push(`Owner: ${p.owner}`);
  return o + list(det) + `<p>${h(p.sourceRef)}</p>`;
}

/**
 * System-neutral ticket content for one finding.
 * @param {object} entity FINDING entity
 * @returns {{ title:string, body:string, severity:string, priority:string, labels:string[], assets:string[], dueDate:string|null, sourceRef:string }}
 */
export function ticketFields(entity) {
  const p = parts(entity || {});
  return {
    title: p.title, body: renderMarkdown(p), severity: p.severity, priority: PRIORITY[p.severity],
    labels: uniqCI(["darknode", p.severity, p.tool]), assets: p.assets, dueDate: p.dueDate, sourceRef: p.sourceRef,
  };
}

// ---------------------------------------------------------------------------
// CSV (RFC 4180): fields holding a comma, quote, CR or LF are quoted and inner
// quotes doubled; rows end in CRLF. Formula-injection guard: spreadsheet apps (and
// some importers' preview grids) evaluate a cell starting with = + - @ TAB or CR as a
// formula, which can run commands or exfiltrate data when an analyst opens the file.
// Finding text comes from scanned, attacker-influenced input, so such cells get a
// leading apostrophe, which every spreadsheet shows as literal text.
// ---------------------------------------------------------------------------

export function csvCell(v) {
  let s = str(v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}
const csv = (rows) => rows.map((r) => r.map(csvCell).join(",")).join("\r\n") + "\r\n";

/** Jira labels: no whitespace (it would split the label), no empty values, 255 max. */
export function jiraLabel(s) { return cut(str(s).trim().replace(/\s+/g, "-"), TICKET_LIMITS.jiraLabel); }
/** Azure Boards tags: ';' is the separator, so it cannot appear inside a tag. */
export function adoTag(s) { return cut(str(s).replace(/;/g, " ").replace(/\s+/g, " ").trim(), TICKET_LIMITS.adoTag); }
/** GitHub labels: single-spaced, comma-free (commas break label filters), 50 chars max. */
export function ghLabel(s) { return cut(str(s).replace(/,/g, " ").replace(/\s+/g, " ").trim(), TICKET_LIMITS.ghLabel); }

const extra = (o) => (Array.isArray(o && o.labels) ? o.labels : []);

/**
 * Jira Cloud CSV. One row per finding; Labels repeats once per label.
 * @param {object[]} entities
 * @param {{ issueType?: string, labels?: string[] }} [opts]
 */
export function toJiraCsv(entities, opts = {}) {
  const issueType = str(opts.issueType).trim() || "Task";
  const rows = exportable(entities).map((e) => {
    const p = parts(e);
    return {
      summary: cut(p.title, TICKET_LIMITS.jiraSummary), priority: PRIORITY[p.severity], due: p.dueDate || "",
      description: renderText(p), labels: uniqCI(["darknode", p.severity, p.tool, ...extra(opts)].map(jiraLabel).filter(Boolean)),
    };
  });
  const nLabels = Math.max(1, ...rows.map((r) => r.labels.length));
  const head = ["Summary", "Issue Type", "Priority", "Due Date", "Description", ...Array(nLabels).fill("Labels")];
  return csv([head, ...rows.map((r) => [r.summary, issueType, r.priority, r.due, r.description, ...Array.from({ length: nLabels }, (_, i) => r.labels[i] || "")])]);
}

/**
 * ServiceNow import set CSV, incident field names. Load it with System Import Sets >
 * Load Data and transform it into the table you choose.
 * @param {object[]} entities
 * @param {{ category?: string }} [opts]
 */
export function toServiceNowCsv(entities, opts = {}) {
  const nq = (s) => str(s).replace(/"/g, "'"); // ServiceNow: no double quotes inside fields
  const head = ["short_description", "description", "impact", "urgency", "category", "due_date", "correlation_id", "correlation_display"];
  const rows = exportable(entities).map((e) => {
    const p = parts(e);
    const [impact, urgency] = SNOW_IU[p.severity];
    return [cut(p.title, TICKET_LIMITS.snowShortDescription), renderText(p), impact, urgency, str(opts.category).trim(), p.dueDate || "", p.key, "Darknode"].map(nq);
  });
  return csv([head, ...rows]);
}

/**
 * Azure Boards CSV for new work items (no ID column).
 * @param {object[]} entities
 * @param {{ workItemType?: string, labels?: string[] }} [opts]
 */
export function toAzureDevOpsCsv(entities, opts = {}) {
  const type = str(opts.workItemType).trim() || "Task";
  const head = ["Work Item Type", "Title", "Description", "Priority", "Tags"];
  const rows = exportable(entities).map((e) => {
    const p = parts(e);
    const tags = uniqCI(["darknode", p.severity, p.tool, ...extra(opts)].map(adoTag).filter(Boolean));
    return [type, cut(p.title, TICKET_LIMITS.adoTitle), renderHtml(p), ADO_PRIORITY[p.severity], tags.join("; ")];
  });
  return csv([head, ...rows]);
}

/**
 * Request body for GitHub POST /repos/{owner}/{repo}/issues. Null for sample data.
 * @param {object} entity
 * @param {{ labels?: string[] }} [opts]
 * @returns {{ title:string, body:string, labels:string[] }|null}
 */
export function githubIssuePayload(entity, opts = {}) {
  if (!exportable([entity]).length) return null;
  const p = parts(entity);
  const labels = uniqCI(["darknode", p.severity, p.tool, ...extra(opts)].map(ghLabel).filter(Boolean)).slice(0, TICKET_LIMITS.ghLabels);
  let body = renderMarkdown(p);
  if (Array.from(body).length > TICKET_LIMITS.ghBody) {
    // Keep the reference line so a truncated issue can still be matched to its finding.
    const tail = "\n\n_Truncated._\n\n---\n" + p.sourceRef;
    body = Array.from(body).slice(0, TICKET_LIMITS.ghBody - Array.from(tail).length).join("") + tail;
  }
  return { title: cut(p.title, TICKET_LIMITS.ghTitle), body, labels };
}

/** "owner/repo" -> { owner, repo } or null. Owner: GitHub login rules; repo: [A-Za-z0-9._-], no .git. */
export function parseRepo(s) {
  const m = /^\s*([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))\/([A-Za-z0-9._-]{1,100})\s*$/.exec(str(s));
  if (!m || /\.git$/i.test(m[2]) || m[2] === "." || m[2] === "..") return null;
  return { owner: m[1], repo: m[2] };
}

/** True when data.tickets already links an issue in owner/repo (case-insensitive). */
export function hasGithubTicket(entity, owner, repo) {
  const pre = `https://github.com/${str(owner)}/${str(repo)}/issues/`.toLowerCase();
  const t = entity && entity.data && Array.isArray(entity.data.tickets) ? entity.data.tickets : [];
  return t.some((x) => x && str(x.url).toLowerCase().startsWith(pre));
}
