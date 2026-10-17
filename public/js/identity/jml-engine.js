// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Lifecycle & Offboarding Verifier engine (jml). Pure: no DOM, no network, no
// clock (opts.now or the latest timestamp in the data). Safe inside a Worker.
//
// Extends Access Review (one HR-vs-directory reconciliation) to joiner / mover /
// leaver verification across the IdP AND every SaaS user list: leavers who are
// still enabled or still signed in, time-to-disable against an SLA, movers who
// kept their old department's groups, joiners provisioned too early or not at
// all, orphan SaaS accounts, licence waste and terminated managers of record.
//
// Inputs are several exports dropped together. Each file is classified by its
// headers (and, for SaaS lists, the app is inferred from headers or file name):
//   hr          Workday / BambooHR / Gusto / Rippling / generic roster
//   hr-changes  movers file (Employee ID, Effective Date, Change Type, From/To Department ...)
//   idp         Entra Get-MgUser CSV/JSON, Okta users JSON, Google Workspace users CSV
//   saas        Slack, GitHub, Microsoft 365 licences, Zoom, Salesforce, Atlassian, Zendesk, generic
//   devices     Intune or Jamf inventory
//
// Control references: ISO 27001:2022 A.5.18 / A.6.5, SOC 2 CC6.2 / CC6.3,
// NIST SP 800-53 AC-2(3) / PS-4 / PS-5, CIS Controls v8 5.3 / 6.2, MITRE ATT&CK T1078.

import { sniff, parseCsv, iterJson, flatten } from "../ingest/parse.js";
import {
  parseHR, parseDirectory, findColumn, normalizeEmail, normalizeName, levenshtein, parseDate, looksLikeServiceAccount,
} from "./access-review-engine.js";

export const TOOL_ID = "jml";
export const VERSION = "1.0.0";

const HOUR = 3600000, DAY = 86400000;
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** Logical columns per file kind -> accepted header names (normalised, case-insensitive). */
export const COLUMNS = {
  hr: {
    // "Employee #" (BambooHR id) and "Employee" (Gusto name) both normalise to "employee"; loadRoster tells them apart by the raw header.
    employeeId: ["employee id", "employee number", "employee no", "worker id", "emp id", "staff id", "personnel number"],
    name: ["worker", "full name", "employee name", "worker name", "display name", "name", "legal name", "preferred name"],
    firstName: ["first name", "given name", "legal first name"],
    lastName: ["last name", "surname", "family name", "legal last name"],
    email: ["email - primary work", "work email", "business email", "company email", "email", "email address", "primary email"],
    hireDate: ["hire date", "start date", "date of hire", "original hire date", "join date", "employment start date"],
    termDate: ["termination date", "term date", "end date", "separation date", "last day", "last day of work", "exit date", "employment end date"],
    status: ["active status", "employment status", "employee status", "worker status", "status", "active"],
    dept: ["department", "cost center", "department name", "division", "business unit", "team"],
    title: ["job title", "business title", "title", "position"],
    manager: ["manager", "reports to", "manager name", "supervisor", "manager email", "manager id"],
    type: ["worker type", "employee type", "employment type"],
  },
  changes: {
    employeeId: ["employee id", "employee #", "employee number", "worker id", "emp id"],
    email: ["email", "work email", "email - primary work"],
    name: ["worker", "employee", "full name", "name"],
    effectiveDate: ["effective date", "change date", "date"],
    changeType: ["change type", "event", "action", "business process", "reason"],
    fromDept: ["from department", "previous department", "old department", "from cost center"],
    toDept: ["to department", "new department", "department", "to cost center"],
    fromManager: ["from manager", "previous manager", "old manager"],
    toManager: ["to manager", "new manager", "manager"],
  },
  idp: {
    // Resolved by access-review-engine parseDirectory; these are the extras this engine reads from raw rows.
    statusChanged: ["statuschanged", "deleteddatetime", "disableddate", "deactivatedat", "disabledat", "deprovisioneddate", "status changed"],
    groups: ["memberof", "groups", "group memberships", "group membership"],
    licenses: ["assignedlicenses", "licenses", "assigned licenses", "licenseassignmentstates"],
    deleted: ["deleteddatetime"],
  },
  saas: {
    email: ["email", "email address", "user email", "work email", "mail", "saml identity", "user principal name", "username", "login", "user name"],
    login: ["login", "username", "user name", "userid", "user id"],
    name: ["fullname", "full name", "name", "display name", "displayname", "real name"],
    firstName: ["first name"],
    lastName: ["last name"],
    status: ["status", "active", "enabled", "suspended", "block credential", "deactivated", "state", "account status"],
    role: ["role", "profile", "type", "user type"],
    lastLogin: ["last login", "last sign-in", "last sign in", "last seen in jira software", "last seen in confluence", "last seen", "last active", "last activity", "lastlogin", "last signin"],
    licensed: ["billing-active", "licenses", "user license", "license", "licensed", "seat", "plan"],
    twoFactor: ["has-2fa", "two-factor", "2fa", "mfa"],
  },
  devices: {
    user: ["primary user upn", "username", "user", "primary user", "user principal name", "owner", "assigned user", "last logged on user"],
    device: ["device name", "computer name", "name", "device", "hostname", "serial number"],
    lastCheckin: ["last check-in", "last checkin", "last contact", "last sync", "last sync date time", "last seen", "last report time"],
    compliance: ["compliance state", "compliance", "compliant"],
    os: ["os", "operating system", "platform"],
  },
};

/** Tunable thresholds; the UI renders these as the settings panel. */
export const DEFAULTS = {
  disableSlaHours: 24,       // hours allowed between termination and IdP disable
  moverGraceDays: 14,        // days a mover may keep old-department access
  joinerLeadDays: 7,         // days before the hire date an IdP account may exist
  licenseCostMonthly: {},    // { appName: number } entered by the user; never invented
  allowDomains: [],          // external domains that are expected in SaaS lists
  now: null,                 // ISO timestamp; default = latest timestamp in the data
};

const C = {
  iso518: { framework: "ISO27001", id: "A.5.18" },
  iso65: { framework: "ISO27001", id: "A.6.5" },
  soc62: { framework: "SOC2", id: "CC6.2" },
  soc63: { framework: "SOC2", id: "CC6.3" },
  ac23: { framework: "NIST-800-53", id: "AC-2(3)" },
  ps4: { framework: "NIST-800-53", id: "PS-4" },
  ps5: { framework: "NIST-800-53", id: "PS-5" },
  cis53: { framework: "CIS", id: "5.3" },
  cis62: { framework: "CIS", id: "6.2" },
  t1078: { framework: "MITRE", id: "T1078" },
};

export const KINDS = ["hr", "hr-changes", "idp", "saas", "devices", "ignore"];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const str = (v) => String(v == null ? "" : v).trim();
const low = (v) => str(v).toLowerCase();
const norm = (h) => low(h).replace(/\[[^\]]*\]/g, "").replace(/\([^)]*\)/g, "").replace(/[^a-z0-9]/g, "");
const iso = (t) => (t == null ? null : new Date(t).toISOString());
const day = (t) => (t == null ? null : new Date(t).toISOString().slice(0, 10));
const hours = (a, b) => Math.round(((b - a) / HOUR) * 10) / 10;
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const uniq = (arr) => Array.from(new Set(arr.filter((x) => x != null && x !== "")));
const median = (nums) => {
  const a = nums.filter((n) => Number.isFinite(n)).sort((x, y) => x - y);
  if (!a.length) return null;
  const m = a.length >> 1;
  return a.length % 2 ? a[m] : Math.round(((a[m - 1] + a[m]) / 2) * 10) / 10;
};
const emailDomain = (e) => { const s = low(e); const i = s.lastIndexOf("@"); return i > 0 ? s.slice(i + 1) : ""; };
const localPart = (e) => { const s = low(e); const i = s.indexOf("@"); return i > 0 ? s.slice(0, i) : s; };
const truthy = (v) => /^(true|yes|y|1|active|enabled|licensed|on|t)$/i.test(str(v));
const falsy = (v) => /^(false|no|n|0|inactive|disabled|deactivated|suspended|off|f|blocked)$/i.test(str(v));

function col(headers, aliases) { return findColumn(headers, aliases.map(norm)); }

function csvQuote(v) { const s = String(v == null ? "" : v); return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; }

/** Re-serialise rows as CSV with headers renamed through `map` (original header -> canonical name). */
function toCsvRenamed(headers, rows, map) {
  const hs = headers.map((h) => (map[h] || h));
  const out = [hs.map(csvQuote).join(",")];
  for (const r of rows) out.push(headers.map((h) => csvQuote(r[h])).join(","));
  return out.join("\n");
}

// ---------------------------------------------------------------------------
// File classification
// ---------------------------------------------------------------------------
const APP_NAME_RE = [
  [/slack/i, "Slack"], [/github/i, "GitHub"], [/gitlab/i, "GitLab"], [/m365|o365|office ?365|microsoft ?365|licen[cs]es?/i, "Microsoft 365"],
  [/zoom/i, "Zoom"], [/salesforce|sfdc/i, "Salesforce"], [/atlassian|jira|confluence/i, "Atlassian"], [/zendesk/i, "Zendesk"],
  [/notion/i, "Notion"], [/dropbox/i, "Dropbox"], [/box\b/i, "Box"], [/hubspot/i, "HubSpot"], [/figma/i, "Figma"], [/asana/i, "Asana"],
  [/workday/i, "Workday"], [/bamboo/i, "BambooHR"], [/gusto/i, "Gusto"], [/rippling/i, "Rippling"],
  [/okta/i, "Okta"], [/entra|azure|aad|mguser/i, "Entra ID"], [/google|gws|workspace/i, "Google Workspace"],
  [/intune/i, "Intune"], [/jamf/i, "Jamf"],
];

export function appFromName(name) {
  const base = str(name).replace(/\.[a-z0-9]+$/i, "");
  for (const [re, app] of APP_NAME_RE) if (re.test(base)) return app;
  return base.replace(/[-_]+/g, " ").replace(/\b(users?|members?|export|people|list|report|licen[cs]es?)\b/gi, "").replace(/\s+/g, " ").trim() || "SaaS app";
}

/**
 * Classify one parsed file by its headers. Returns { kind, app, vendor, confidence }.
 * kind: hr | hr-changes | idp | saas | devices | unknown. confidence: high | medium | low.
 */
export function classifyFile(headers, { name = "", isJson = false, rows = [] } = {}) {
  const n = new Set((headers || []).map(norm));
  const has = (...ks) => ks.every((k) => n.has(norm(k)));
  const any = (...ks) => ks.some((k) => n.has(norm(k)));
  const fname = low(name);
  const r = (kind, vendor, app, confidence) => ({ kind, vendor, app: app || null, confidence });

  // HR changes / movers
  if (any("change type", "changetype") && any("effective date", "effectivedate")) return r("hr-changes", "generic", null, "high");
  if (any("from department", "to department") && any("effective date", "change date")) return r("hr-changes", "generic", null, "medium");

  // Device inventories
  if (has("device name", "primary user upn")) return r("devices", "intune", "Intune", "high");
  if (has("computer name", "username") && any("last check-in", "last checkin", "last contact")) return r("devices", "jamf", "Jamf", "high");
  if (any("device name", "computer name", "hostname") && any("last check-in", "last checkin", "last sync", "last contact") && any("primary user", "username", "user", "owner", "primary user upn")) return r("devices", "generic", "Devices", "medium");

  // Identity providers
  if (has("userprincipalname") && any("accountenabled", "accountEnabled")) return r("idp", "entra", "Entra ID", "high");
  if (isJson && any("login", "profile.login") && any("status") && any("statuschanged", "created", "activated")) return r("idp", "okta", "Okta", "high");
  if (!isJson && has("login", "status") && any("statuschanged", "lastlogin")) return r("idp", "okta", "Okta", "medium");
  if (any("email address") && any("org unit path", "orgunitpath")) return r("idp", "google", "Google Workspace", "high");
  if (has("userprincipalname") && !any("licenses", "block credential")) return r("idp", "entra", "Entra ID", "medium");

  // SaaS lists (vendor headers)
  if (any("billing-active", "billingactive") || (has("username", "email", "status") && any("has-2fa", "has2fa", "fullname"))) return r("saas", "slack", "Slack", "high");
  if (has("login") && any("two-factor", "twofactor", "saml identity", "samlidentity")) return r("saas", "github", "GitHub", "high");
  if (isJson && has("login") && any("node_id", "nodeid", "site_admin", "siteadmin", "html_url", "htmlurl", "avatar_url")) return r("saas", "github", "GitHub", "high");
  if (has("user principal name", "licenses") || (has("userprincipalname") && any("block credential", "blockcredential"))) return r("saas", "m365", "Microsoft 365", "high");
  if (has("email", "type") && any("last login") && any("dept", "department") && /licensed|basic/i.test(JSON.stringify(rows.slice(0, 50)))) return r("saas", "zoom", "Zoom", "high");
  if (has("email", "type", "status") && any("dept", "department") && any("last login")) return r("saas", "zoom", "Zoom", "medium");
  if (any("user license", "userlicense") || (has("username", "email", "active") && any("profile"))) return r("saas", "salesforce", "Salesforce", "high");
  if (any("last seen in jira software", "last seen in confluence", "last seen in jira") || (has("user name", "email", "active") && [...n].some((k) => k.startsWith("lastseenin")))) return r("saas", "atlassian", "Atlassian", "high");
  if (has("email", "role") && any("suspended") && any("organization", "last login", "time zone", "external id")) return r("saas", "zendesk", "Zendesk", "medium");

  // HR rosters
  const hrDate = any("hire date", "start date", "termination date", "term date", "end date", "date of hire", "separation date");
  const hrId = any("employee id", "employee #", "employee number", "worker", "worker id", "employee", "first name", "full name", "employee name");
  if (hrDate && hrId) {
    const raw = new Set((headers || []).map((h) => low(h).replace(/\s+/g, " ")));
    if (has("worker") && any("email - primary work", "active status", "cost center", "business title")) return r("hr", "workday", "Workday", "high");
    if (raw.has("employee #") || (has("work email", "first name") && any("reports to"))) return r("hr", "bamboohr", "BambooHR", "high");
    if (raw.has("employee") && has("email") && any("start date") && any("termination date")) return r("hr", "gusto", "Gusto", "high");
    if (/rippling/.test(fname) || (any("work email") && any("employment status") && any("end date"))) return r("hr", "rippling", "Rippling", "high");
    return r("hr", "generic", null, any("termination date", "term date", "end date", "separation date") ? "high" : "medium");
  }
  if (hrDate && any("email", "work email", "name")) return r("hr", "generic", null, "medium");

  // Generic SaaS list: an email/login plus a status-like column
  const hasIdent = any("email", "email address", "user email", "login", "username", "user name", "user principal name", "mail");
  const hasStatus = any("status", "active", "enabled", "suspended", "deactivated", "state", "account status", "role", "last login", "last sign-in", "last seen", "last active");
  if (hasIdent && hasStatus) return r("saas", "generic", appFromName(name), hasStatus && any("status", "active", "enabled", "suspended") ? "medium" : "low");
  if (hasIdent) return r("saas", "generic", appFromName(name), "low");
  return r("unknown", "generic", null, "low");
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------
// Flatten one JSON user: Okta profile.* and Entra signInActivity.* are promoted to
// top-level names, arrays of objects (groups, assignedLicenses, roles) become ";"-joined labels.
function promoteOkta(o) {
  const out = {};
  const label = (x) => (x && typeof x === "object" ? (x.profile && x.profile.name) || x.displayName || x.name || x.label || x.skuId || x.id || JSON.stringify(x) : String(x == null ? "" : x));
  for (const [k, v] of Object.entries(o || {})) {
    if (Array.isArray(v)) out[k] = v.map(label).join(";");
    else if (v && typeof v === "object") {
      const flat = flatten(v, k);
      for (const [fk, fv] of Object.entries(flat)) out[fk.replace(/^(profile|signInActivity)\./, "")] = fv == null ? "" : fv;
    } else out[k] = v == null ? "" : v;
  }
  return out;
}

function parseOne(name, text) {
  const t = String(text || "");
  const trimmed = t.replace(/^﻿/, "").trim();
  if (!trimmed) return { name, format: "empty", headers: [], rows: [], text: t, isJson: false };
  const format = sniff(trimmed).format;
  if (format === "json" || format === "ndjson") {
    let rows = [];
    try { rows = iterJson(trimmed).filter((r) => r && typeof r === "object").map(promoteOkta); } catch (_) { rows = []; }
    const hs = new Set();
    for (const r of rows) for (const k of Object.keys(r)) hs.add(k);
    return { name, format, headers: [...hs], rows, text: t, isJson: true };
  }
  const { headers, rows } = parseCsv(trimmed);
  return { name, format: format === "tsv" ? "tsv" : "csv", headers, rows, text: t, isJson: false };
}

/**
 * Parse raw text or several files. Accepts a string, {name,text}, or an array of
 * either. Returns { format, headers, rows, files, skipped } where `files` carries
 * one classified entry per input: { name, kind, vendor, app, confidence, format,
 * headers, rows, rowCount, text }. Never throws on bad input.
 */
export function parseInput(input) {
  const list = Array.isArray(input) ? input : [input];
  const skipped = [];
  const files = [];
  list.forEach((it, i) => {
    const name = it && typeof it === "object" ? str(it.name) || "file-" + (i + 1) : "file-" + (i + 1);
    const text = it && typeof it === "object" ? (it.text != null ? it.text : "") : it;
    const p = parseOne(name, text);
    if (!p.rows.length) { skipped.push({ check: "parse", reason: name + ": no rows (" + p.format + ")" }); }
    const cls = classifyFile(p.headers, { name, isJson: p.isJson, rows: p.rows });
    if (cls.kind === "saas" && !cls.app) cls.app = appFromName(name);
    if (cls.kind === "unknown") skipped.push({ check: "classify", reason: name + ": headers not recognised; set the kind manually" });
    files.push({ name, format: p.format, headers: p.headers, rows: p.rows, rowCount: p.rows.length, text: p.text, isJson: p.isJson, ...cls });
  });
  const first = files[0] || { format: "empty", headers: [], rows: [] };
  return {
    format: files.length > 1 ? "multi" : first.format,
    headers: first.headers, rows: first.rows, kind: first.kind, files, skipped,
  };
}

// --- HR roster via access-review parseHR (headers mapped to names it knows) --
const HR_CANON = {
  employeeId: "Employee ID", name: "Full Name", firstName: "First Name", lastName: "Last Name", email: "Work Email",
  hireDate: "Start Date", termDate: "Termination Date", status: "Employment Status", dept: "Department", title: "Job Title", manager: "Manager", type: "Worker Type",
};

function renameMap(headers, spec, overrides = {}, canon) {
  const map = {};
  const used = new Set();
  for (const key of Object.keys(spec)) {
    const h = overrides[key] && headers.includes(overrides[key]) ? overrides[key] : col(headers.filter((x) => !used.has(x)), spec[key]);
    if (h) { map[h] = canon[key]; used.add(h); }
  }
  // Any unmapped header that would collide with a canonical name is prefixed so it cannot shadow a mapped one.
  const canonSet = new Set(Object.values(canon).map(norm));
  for (const h of headers) if (!map[h] && canonSet.has(norm(h))) map[h] = "x_" + h;
  return map;
}

function loadRoster(file, now, opts) {
  const ov = { ...(file.columns || {}) };
  for (const h of file.headers) {
    const l = low(h).replace(/\s+/g, " ");
    if (l === "employee #" && !ov.employeeId) ov.employeeId = h;
    else if (l === "employee" && !ov.name) ov.name = h;
  }
  const map = renameMap(file.headers, COLUMNS.hr, ov, HR_CANON);
  const hr = parseHR(toCsvRenamed(file.headers, file.rows, map), { now, aliasDomains: opts.aliasDomains });
  const mapped = {};
  for (const [h, c] of Object.entries(map)) if (!c.startsWith("x_")) mapped[c] = h;
  return { hr, mapped, file: file.name, vendor: file.vendor };
}

function loadChanges(file) {
  const h = file.headers, ov = file.columns || {};
  const pick = (k) => (ov[k] && h.includes(ov[k]) ? ov[k] : col(h, COLUMNS.changes[k]));
  const c = {}; for (const k of Object.keys(COLUMNS.changes)) c[k] = pick(k);
  const rows = file.rows.map((r) => ({
    employeeId: str(c.employeeId && r[c.employeeId]), email: low(c.email && r[c.email]), name: str(c.name && r[c.name]),
    effectiveDate: parseDate(c.effectiveDate && r[c.effectiveDate]), changeType: str(c.changeType && r[c.changeType]),
    fromDept: str(c.fromDept && r[c.fromDept]), toDept: str(c.toDept && r[c.toDept]),
    fromManager: str(c.fromManager && r[c.fromManager]), toManager: str(c.toManager && r[c.toManager]), raw: r,
  }));
  return { rows, columns: c, file: file.name };
}

function loadIdp(file, now, opts) {
  let text = file.isJson ? JSON.stringify(file.rows) : file.text;
  if (file.columns && Object.keys(file.columns).length) {
    // Honour UI column overrides by renaming to names parseDirectory knows.
    const canon = { email: "mail", upn: "userPrincipalName", name: "displayName", enabled: "accountEnabled", lastSignIn: "lastSignInDateTime", created: "createdDateTime", dept: "department", statusChanged: "statusChanged", groups: "memberOf" };
    const map = {};
    for (const [k, h] of Object.entries(file.columns)) if (canon[k] && file.headers.includes(h)) map[h] = canon[k];
    text = toCsvRenamed(file.headers, file.rows, map);
  }
  const dir = parseDirectory(text, { now, aliasDomains: opts.aliasDomains });
  const h = text === file.text ? file.headers : Object.keys(dir.users[0] && dir.users[0].raw || {});
  const extra = {
    statusChanged: col(h, COLUMNS.idp.statusChanged), groups: col(h, COLUMNS.idp.groups), licenses: col(h, COLUMNS.idp.licenses), deleted: col(h, COLUMNS.idp.deleted),
  };
  const users = dir.users.map((u) => {
    const raw = u.raw || {};
    const statusChanged = extra.statusChanged ? parseDate(raw[extra.statusChanged]) : null;
    const deleted = extra.deleted ? parseDate(raw[extra.deleted]) : null;
    const groups = extra.groups ? String(raw[extra.groups] || "").split(/[;|,\n]+/).map((g) => g.trim()).filter(Boolean) : [];
    const licRaw = extra.licenses ? str(raw[extra.licenses]) : "";
    const licensed = extra.licenses ? !!licRaw && !/^(\[\]|none|null|0|-|false)$/i.test(licRaw) : null;
    return { ...u, statusChanged, deleted, groups, licensed, upn: low(u.id), source: dir.source };
  });
  return { dir, users, extra, file: file.name, vendor: dir.source };
}

const VENDOR_STATUS = {
  slack: (v) => (/^(member|admin|owner|primary owner|restricted|ultra restricted|single-channel guest|multi-channel guest)$/i.test(v) ? "active" : /deactivated|deleted/i.test(v) ? "inactive" : /invited/i.test(v) ? "invited" : null),
  zoom: (v) => (/^(active|pending)$/i.test(v) ? (/pending/i.test(v) ? "invited" : "active") : /inactive|deactivated/i.test(v) ? "inactive" : null),
  m365: (v) => (truthy(v) ? "inactive" : falsy(v) ? "active" : null), // Block credential: True = sign-in blocked
  zendesk: (v) => (truthy(v) ? "inactive" : falsy(v) ? "active" : null), // Suspended
  generic: (v) => (truthy(v) ? "active" : falsy(v) ? "inactive" : /^(member|admin|owner|user|active|licensed)$/i.test(v) ? "active" : /deactivated|deprovisioned|suspended|disabled|blocked|inactive|removed|archived/i.test(v) ? "inactive" : /invited|pending/i.test(v) ? "invited" : null),
};

function licenseFlag(vendor, licRaw, roleRaw, statusHeader) {
  const l = str(licRaw), role = str(roleRaw);
  if (vendor === "slack") return l === "" ? null : truthy(l) || l === "1";
  if (vendor === "m365") return l === "" ? false : !/^(none|unlicensed|-)$/i.test(l);
  if (vendor === "zoom") return /licensed|pro|business|enterprise/i.test(role) ? true : /basic/i.test(role) ? false : null;
  if (vendor === "salesforce") return l === "" ? null : !/chatter free|chatter external|guest|identity/i.test(l);
  if (l === "") return null;
  if (truthy(l)) return true;
  if (falsy(l) || /^(none|unlicensed|free|-)$/i.test(l)) return false;
  return true; // a named plan or SKU
}

function loadSaas(file) {
  const h = file.headers, ov = file.columns || {}, vendor = file.vendor || "generic";
  const pick = (k) => (ov[k] && h.includes(ov[k]) ? ov[k] : col(h, COLUMNS.saas[k]));
  const c = {};
  for (const k of Object.keys(COLUMNS.saas)) c[k] = pick(k);
  if (vendor === "slack") { c.status = col(h, ["status"]); c.licensed = col(h, ["billing-active"]); }
  if (vendor === "m365") { c.status = col(h, ["block credential"]); c.licensed = col(h, ["licenses"]); c.email = col(h, ["user principal name"]); c.lastLogin = col(h, ["last sign-in", "last sign in", "last signin"]); }
  if (vendor === "zoom") { c.role = col(h, ["type"]); c.status = col(h, ["status"]); }
  if (vendor === "salesforce") { c.status = col(h, ["active"]); c.licensed = col(h, ["user license"]); c.email = col(h, ["email"]); c.login = col(h, ["username"]); }
  if (vendor === "atlassian") { c.status = col(h, ["active"]); c.email = col(h, ["email"]); c.login = col(h, ["user name"]); }
  if (vendor === "zendesk") { c.status = col(h, ["suspended"]); }
  if (vendor === "github") { c.email = col(h, ["saml identity", "email"]); c.login = col(h, ["login"]); c.status = null; c.role = col(h, ["role"]); }
  const statusFn = VENDOR_STATUS[vendor] || VENDOR_STATUS.generic;
  const accounts = file.rows.map((r, i) => {
    let email = low(c.email && r[c.email]);
    const login = str(c.login && r[c.login]);
    if (!email.includes("@") && login.includes("@")) email = low(login);
    if (!email.includes("@")) email = "";
    let name = str(c.name && r[c.name]);
    if (!name && (c.firstName || c.lastName)) name = (str(c.firstName && r[c.firstName]) + " " + str(c.lastName && r[c.lastName])).trim();
    let status = null;
    if (c.status) status = statusFn(str(r[c.status])) || VENDOR_STATUS.generic(str(r[c.status]));
    if (!c.status) status = "active"; // membership lists (GitHub people) contain only current members
    const lastLogin = c.lastLogin ? parseDate(r[c.lastLogin]) : null;
    return {
      key: email || low(login) || low(name) || "row-" + (i + 1), email, emailKey: normalizeEmail(email), login, name, nameKey: normalizeName(name),
      status, role: str(c.role && r[c.role]), lastLogin, hasLastLogin: !!c.lastLogin,
      licensed: licenseFlag(vendor, c.licensed ? r[c.licensed] : "", c.role ? r[c.role] : "", c.status), raw: r,
    };
  }).filter((a) => a.email || a.login || a.name);
  return { app: file.app || appFromName(file.name), vendor, accounts, columns: c, file: file.name };
}

function loadDevices(file) {
  const h = file.headers, ov = file.columns || {};
  const pick = (k) => (ov[k] && h.includes(ov[k]) ? ov[k] : col(h, COLUMNS.devices[k]));
  const c = {}; for (const k of Object.keys(COLUMNS.devices)) c[k] = pick(k);
  const devices = file.rows.map((r) => ({
    user: low(c.user && r[c.user]), device: str(c.device && r[c.device]), lastCheckin: c.lastCheckin ? parseDate(r[c.lastCheckin]) : null,
    compliance: str(c.compliance && r[c.compliance]), os: str(c.os && r[c.os]), raw: r,
  })).filter((d) => d.user || d.device);
  return { devices, columns: c, file: file.name, vendor: file.vendor };
}

// ---------------------------------------------------------------------------
// People index and matching: exact email > UPN local-part > normalised name (lev <= 1, "review")
// ---------------------------------------------------------------------------
function buildIndex(people) {
  const byEmail = new Map(), byLocal = new Map(), byName = new Map(), byId = new Map();
  const add = (m, k, p) => { if (!k) return; if (!m.has(k)) m.set(k, []); if (!m.get(k).includes(p)) m.get(k).push(p); };
  for (const p of people) {
    for (const e of p.emails) { add(byEmail, e, p); add(byLocal, localPart(e), p); }
    if (p.employeeId) add(byId, low(p.employeeId), p);
    if (p.nameKey) add(byName, p.nameKey, p);
  }
  return { byEmail, byLocal, byName, byId, people };
}

function matchPerson(idx, { email, login, name, employeeId }) {
  const one = (m, k) => { const l = k && m.get(k); return l && l.length === 1 ? l[0] : null; };
  if (employeeId) { const p = one(idx.byId, low(employeeId)); if (p) return { person: p, method: "employeeId", confidence: "confirmed" }; }
  const ek = normalizeEmail(email);
  if (ek && ek.includes("@")) { const p = one(idx.byEmail, ek); if (p) return { person: p, method: "email", confidence: "confirmed" }; }
  const lp = localPart(ek || login);
  if (lp && lp.length >= 3) { const p = one(idx.byLocal, lp); if (p) return { person: p, method: "local-part", confidence: "likely" }; }
  const nk = normalizeName(name);
  if (nk && nk.includes(" ")) {
    const p = one(idx.byName, nk); if (p) return { person: p, method: "name", confidence: "likely" };
    let best = null, n = 0;
    for (const [k, list] of idx.byName) if (list.length === 1 && levenshtein(k, nk, 1) <= 1) { best = list[0]; n++; }
    if (n === 1) return { person: best, method: "name~1", confidence: "review" };
  }
  // A login like "jdoe" against a name key "jane doe" (first initial + surname) is too loose; left unmatched.
  return null;
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------
function resolveNow(opts, loaded) {
  if (opts.now) { const t = parseDate(opts.now); if (t != null) return t; }
  let max = null;
  const bump = (t) => { if (t != null && Number.isFinite(t) && (max == null || t > max)) max = t; };
  // Hire dates are excluded: pre-boarded joiners legitimately have a start date in the future.
  for (const r of loaded.rosters) for (const e of r.hr.employees) bump(e.endDate);
  for (const i of loaded.idps) for (const u of i.users) { bump(u.lastSignIn); bump(u.created); bump(u.statusChanged); bump(u.deleted); }
  for (const s of loaded.saas) for (const a of s.accounts) bump(a.lastLogin);
  for (const d of loaded.devices) for (const x of d.devices) bump(x.lastCheckin);
  for (const c of loaded.changes) for (const x of c.rows) bump(x.effectiveDate);
  return max == null ? 0 : max;
}

function normalizeFiles(dataset) {
  if (!dataset) return [];
  if (Array.isArray(dataset)) {
    if (!dataset.length) return [];
    if (dataset.every((f) => f && typeof f === "object" && Array.isArray(f.rows))) return dataset; // files
    if (dataset.every((f) => f && typeof f === "object" && typeof f.text === "string")) return parseInput(dataset).files;
    // plain rows: one anonymous file
    const headers = []; for (const r of dataset) for (const k of Object.keys(r || {})) if (!headers.includes(k)) headers.push(k);
    const cls = classifyFile(headers, { rows: dataset });
    return [{ name: "rows", format: "rows", headers, rows: dataset, rowCount: dataset.length, text: toCsvRenamed(headers, dataset, {}), isJson: false, ...cls, app: cls.app || "SaaS app" }];
  }
  if (Array.isArray(dataset.files)) return dataset.files;
  if (Array.isArray(dataset.rows)) return normalizeFiles(dataset.rows);
  return [];
}

/**
 * Analyze a parsed dataset ({files} from parseInput, an array of files, or plain rows).
 * opts overrides DEFAULTS; ctx.progress(i, n, label) every ~1000 rows.
 */
export function analyze(dataset, opts = {}, ctx) {
  const o = { ...DEFAULTS, ...opts, licenseCostMonthly: { ...(opts.licenseCostMonthly || {}) } };
  const skipped = [], findings = [];
  const files = normalizeFiles(dataset).map((f) => {
    const kind = f.kind && KINDS.includes(f.kind) ? f.kind : (f.kind === "unknown" ? "unknown" : null);
    if (kind) return f;
    const cls = classifyFile(f.headers || [], { name: f.name, isJson: !!f.isJson, rows: f.rows || [] });
    return { ...f, ...cls, app: f.app || cls.app };
  });
  const total = files.reduce((n, f) => n + (f.rows ? f.rows.length : 0), 0) || 1;
  let done = 0;
  const tick = (label) => { ctx?.progress?.(Math.min(done, total), total, label); };

  // 1. Load every file by kind -------------------------------------------------
  const loaded = { rosters: [], changes: [], idps: [], saas: [], devices: [] };
  const fileTable = [];
  for (const f of files) {
    const rows = f.rows ? f.rows.length : 0;
    fileTable.push({ file: f.name, kind: f.kind, vendor: f.vendor || "generic", app: f.app || "", confidence: f.confidence || "low", rows, format: f.format || "" });
    if (!rows) continue;
    if (f.kind === "ignore" || f.kind === "unknown") { done += rows; tick("skip " + f.name); continue; }
    if (f.kind === "hr-changes") loaded.changes.push(loadChanges(f));
    else if (f.kind === "saas") loaded.saas.push(loadSaas(f));
    else if (f.kind === "devices") loaded.devices.push(loadDevices(f));
    done += rows; tick("parse " + f.name);
  }
  const now = (() => {
    // rosters and IdPs need `now` for status inference; compute a provisional one from the cheap sources first.
    const prov = resolveNow(o, loaded);
    for (const f of files) if (f.rows && f.rows.length && f.kind === "hr") loaded.rosters.push(loadRoster(f, prov || Date.UTC(2100, 0, 1), o));
    for (const f of files) if (f.rows && f.rows.length && f.kind === "idp") loaded.idps.push(loadIdp(f, prov || Date.UTC(2100, 0, 1), o));
    return resolveNow(o, loaded);
  })();
  // Re-derive HR status against the real `now` (parseHR treated end dates <= provisional now as terminated).
  for (const r of loaded.rosters) for (const e of r.hr.employees) {
    if (e.endDate != null && e.endDate <= now && e.status !== "contractor" && e.status !== "leave") { if (e.status !== "terminated") { e.status = "terminated"; e.statusSource = "endDate"; } }
    else if (e.statusSource === "endDate" && e.endDate != null && e.endDate > now) { e.status = "active"; e.statusSource = "futureEndDate"; }
  }

  // 2. People model --------------------------------------------------------------
  const people = [];
  const seenEmp = new Map();
  for (const r of loaded.rosters) for (const e of r.hr.employees) {
    const key = e.emailKey && e.emailKey.includes("@") ? e.emailKey : (e.employeeId ? "id:" + low(e.employeeId) : "name:" + e.nameKey);
    if (seenEmp.has(key)) continue;
    const p = {
      key, name: e.name || e.email || e.employeeId, nameKey: e.nameKey, employeeId: e.employeeId, emails: uniq([e.emailKey]), email: e.email,
      hrStatus: e.status, hireDate: e.startDate, termDate: e.endDate, dept: e.dept, title: e.title, manager: e.manager, hrSource: r.file,
      idp: null, apps: [], devices: [], flags: [],
    };
    seenEmp.set(key, p); people.push(p);
  }
  const companyDomains = uniq(people.map((p) => emailDomain(p.email))).sort();
  const allowDomains = new Set((o.allowDomains || []).map(low).filter(Boolean));
  const idx = buildIndex(people);

  // IdP users
  const idpUnmatched = [];
  for (const i of loaded.idps) for (const u of i.users) {
    const m = matchPerson(idx, { email: u.emailKey || u.email, login: u.upn, name: u.name, employeeId: u.employeeId });
    const rec = { id: u.id, upn: u.upn, name: u.name, enabled: u.enabled, statusRaw: u.statusRaw, lastSignIn: u.lastSignIn, created: u.created, statusChanged: u.statusChanged, deleted: u.deleted, dept: u.dept, groups: u.groups, licensed: u.licensed, type: u.type, source: i.vendor, file: i.file, match: m ? m.method : null, matchConfidence: m ? m.confidence : null };
    if (m) { if (!m.person.idp) m.person.idp = rec; else m.person.idpExtra = [...(m.person.idpExtra || []), rec]; if (m.confidence === "review") m.person.flags.push("idp match needs review"); }
    else idpUnmatched.push(rec);
  }
  // SaaS accounts
  const appStats = new Map();
  for (const s of loaded.saas) {
    const st = appStats.get(s.app) || { app: s.app, vendor: s.vendor, file: s.file, total: 0, active: 0, leavers: [], orphans: [], external: [], waste: [], hasLastLogin: s.accounts.some((a) => a.hasLastLogin), hasLicense: s.accounts.some((a) => a.licensed != null) };
    appStats.set(s.app, st);
    for (const a of s.accounts) {
      st.total++; if (a.status === "active") st.active++;
      const m = matchPerson(idx, { email: a.emailKey || a.email, login: a.login, name: a.name });
      const rec = { app: s.app, email: a.email, login: a.login, name: a.name, status: a.status, role: a.role, lastLogin: a.lastLogin, licensed: a.licensed, match: m ? m.method : null, matchConfidence: m ? m.confidence : null };
      if (m) { m.person.apps.push(rec); if (m.confidence === "review") m.person.flags.push(s.app + " match needs review"); }
      else {
        // not in HR. In the IdP?
        const inIdp = idpUnmatched.some((u) => (a.emailKey && u.upn && normalizeEmail(u.upn) === a.emailKey) || (a.emailKey && u.id && normalizeEmail(u.id) === a.emailKey) || (a.nameKey && a.nameKey.includes(" ") && normalizeName(u.name) === a.nameKey));
        const svc = looksLikeServiceAccount({ id: a.login || a.email, email: a.email, name: a.name });
        const dom = emailDomain(a.email);
        const external = dom && companyDomains.length && !companyDomains.includes(dom);
        rec.inIdp = inIdp; rec.serviceLike = svc; rec.domain = dom;
        if (inIdp || svc || a.status !== "active") continue;
        if (dom && allowDomains.has(dom)) continue;
        if (external) st.external.push(rec); else st.orphans.push(rec);
      }
    }
  }
  // Devices
  const devUnmatched = [];
  for (const d of loaded.devices) for (const x of d.devices) {
    const m = x.user ? matchPerson(idx, { email: x.user, login: x.user, name: x.user.includes("@") ? "" : x.user }) : null;
    const rec = { device: x.device, user: x.user, lastCheckin: x.lastCheckin, compliance: x.compliance, os: x.os, source: d.vendor, file: d.file };
    if (m) m.person.devices.push(rec); else devUnmatched.push(rec);
  }
  done = total; tick("match");

  // Availability flags ----------------------------------------------------------
  const haveHR = loaded.rosters.length > 0, haveIdp = loaded.idps.length > 0, haveSaas = loaded.saas.length > 0, haveDev = loaded.devices.length > 0;
  const hrHasTerm = loaded.rosters.some((r) => r.hr.coverage.endDate);
  const hrHasHire = loaded.rosters.some((r) => r.hr.coverage.startDate);
  const hrHasManager = loaded.rosters.some((r) => r.hr.coverage.manager);
  const hrHasDept = loaded.rosters.some((r) => r.hr.coverage.dept);
  const idpHasEnabled = loaded.idps.some((i) => i.dir.coverage.enabled);
  const idpHasSignIn = loaded.idps.some((i) => i.dir.coverage.lastSignIn);
  const idpHasCreated = loaded.idps.some((i) => i.dir.coverage.created);
  const idpHasStatusChanged = loaded.idps.some((i) => i.extra.statusChanged || i.extra.deleted);
  const idpHasGroups = loaded.idps.some((i) => i.extra.groups);
  const idpHasLicenses = loaded.idps.some((i) => i.extra.licenses);
  const idpHasDept = loaded.idps.some((i) => i.dir.coverage.dept);
  const saasHasLastLogin = loaded.saas.some((s) => s.accounts.some((a) => a.hasLastLogin));
  const skip = (check, reason) => skipped.push({ check, reason });
  if (!haveHR) skip("all_hr_checks", "no HR roster file (headers with a hire/termination date and an employee id, name or email)");
  if (haveHR && !hrHasTerm) skip("leaver_checks", "HR roster has no termination date column");

  const leavers = people.filter((p) => p.hrStatus === "terminated" && p.termDate != null && p.termDate <= now);
  const sinceTerm = (p) => hours(p.termDate, now);
  const personAsset = (p, extra = {}) => ({ type: "IDENTITY", name: p.email || p.name, data: { status: p.hrStatus, termDate: day(p.termDate), apps: p.apps.map((a) => a.app).sort(), ...extra } });
  const appAsset = (st) => ({ type: "ASSET", name: st.app, data: { kind: "saas-app", users: st.total, leakage: st.leavers.length } });
  const push = (f) => { f.evidenceCount = f.evidenceCount == null ? (f.evidence || []).length : f.evidenceCount; f.evidence = (f.evidence || []).slice(0, 50); findings.push(f); };

  // 3. Leavers -----------------------------------------------------------------------
  const sla = [];
  if (haveHR && hrHasTerm) {
    if (!haveIdp) skip("leaver_idp_enabled", "no IdP users file");
    else if (!idpHasEnabled) skip("leaver_idp_enabled", "IdP export has no enabled/status column");
    for (const p of leavers) {
      const u = p.idp;
      if (!u) { if (haveIdp) p.flags.push("no IdP account"); continue; }
      const h = sinceTerm(p);
      if (u.enabled === true && idpHasEnabled) {
        p.flags.push("IdP enabled after termination");
        sla.push({ leaver: p.email || p.name, terminated: iso(p.termDate), disabledAt: null, hours: h, breach: h > o.disableSlaHours, status: "still enabled", idp: u.source });
        push({
          id: "leaver_idp_enabled:" + (p.email || p.name), title: "Leaver still enabled in the IdP", severity: "critical", confidence: u.matchConfidence === "review" ? "review" : "confirmed", category: "leaver",
          description: `${p.name} was terminated on ${day(p.termDate)} (${h} h ago) but ${u.upn || u.id} is still enabled in ${u.source}. SLA is ${o.disableSlaHours} h.` + (u.lastSignIn != null ? ` Last sign-in ${day(u.lastSignIn)}.` : ""),
          recommendation: "Disable the account now, revoke sessions and refresh tokens, then fix the HR-to-IdP deprovisioning trigger that missed this termination.",
          controls: [C.iso518, C.soc62, C.ac23, C.ps4, C.cis53, C.t1078],
          evidence: [{ person: p.name, email: p.email, employeeId: p.employeeId, terminated: day(p.termDate), hoursSinceTermination: h, idpAccount: u.upn || u.id, idpStatus: u.statusRaw || "enabled", lastSignIn: day(u.lastSignIn), match: u.match }],
          assets: [personAsset(p, { idpEnabled: true })], tags: ["leaver", "idp"],
        });
      } else if (u.enabled === false) {
        const at = u.statusChanged != null ? u.statusChanged : u.deleted;
        if (at != null) {
          const dh = hours(p.termDate, at);
          sla.push({ leaver: p.email || p.name, terminated: iso(p.termDate), disabledAt: iso(at), hours: dh, breach: dh > o.disableSlaHours, status: "disabled", idp: u.source });
        } else sla.push({ leaver: p.email || p.name, terminated: iso(p.termDate), disabledAt: null, hours: null, breach: null, status: "disabled (time unknown)", idp: u.source });
      }
      // signed in after termination (IdP)
      if (u.lastSignIn != null && u.lastSignIn > p.termDate) p._signInAfter = [...(p._signInAfter || []), { source: u.source, account: u.upn || u.id, lastSignIn: iso(u.lastSignIn) }];
    }
    // SLA breaches for disabled leavers
    if (haveIdp && !idpHasStatusChanged) skip("sla_time_to_disable", "IdP export has no statusChanged / deletedDateTime column; time-to-disable is only measured for leavers still enabled");
    const breaches = sla.filter((s) => s.status === "disabled" && s.breach);
    if (breaches.length) {
      push({
        id: "sla_breach", title: "Leavers disabled later than the SLA", severity: "medium", confidence: "confirmed", category: "sla",
        description: `${breaches.length} leaver account(s) were disabled more than ${o.disableSlaHours} h after the termination date (median ${median(breaches.map((b) => b.hours))} h).`,
        recommendation: "Automate deprovisioning from the HR termination event (SCIM or an HR-driven workflow) so the disable happens within the SLA without a ticket.",
        controls: [C.iso518, C.soc62, C.ac23, C.ps4, C.cis53],
        evidence: breaches.map((b) => ({ leaver: b.leaver, terminated: b.terminated, disabledAt: b.disabledAt, hours: b.hours, slaHours: o.disableSlaHours })),
        assets: breaches.slice(0, 50).map((b) => ({ type: "IDENTITY", name: b.leaver, data: { status: "terminated", termDate: b.terminated.slice(0, 10), apps: [] } })), tags: ["leaver", "sla"],
      });
    }
    // Leavers active per SaaS app
    if (!haveSaas) skip("leaver_saas_active", "no SaaS user list files");
    for (const st of [...appStats.values()].sort((a, b) => cmp(a.app, b.app))) {
      for (const p of leavers) for (const a of p.apps) if (a.app === st.app && a.status === "active") {
        st.leavers.push({ person: p.name, email: p.email, terminated: day(p.termDate), hoursSinceTermination: sinceTerm(p), account: a.email || a.login, status: a.status, role: a.role, lastLogin: day(a.lastLogin), licensed: a.licensed, match: a.match });
        p.flags.push(st.app + " active after termination");
        if (a.lastLogin != null && a.lastLogin > p.termDate) p._signInAfter = [...(p._signInAfter || []), { source: st.app, account: a.email || a.login, lastSignIn: iso(a.lastLogin) }];
      }
      if (st.leavers.length) {
        const review = st.leavers.some((l) => l.match === "name~1");
        push({
          id: "leaver_saas_active:" + st.app, title: `Leavers still active in ${st.app}`, severity: "high", confidence: review ? "review" : "confirmed", category: "leaver",
          description: `${st.leavers.length} terminated employee(s) still hold an active ${st.app} account (${st.total} accounts in the export).` + (review ? " At least one match is by near-identical name; confirm before acting." : ""),
          recommendation: `Deactivate the accounts in ${st.app}, transfer owned content, and connect ${st.app} to the IdP (SCIM or SSO-only) so IdP disablement removes access automatically.`,
          controls: [C.iso518, C.soc62, C.ac23, C.ps4, C.cis62, C.t1078],
          evidence: st.leavers, assets: [appAsset(st), ...leavers.filter((p) => p.apps.some((a) => a.app === st.app && a.status === "active")).slice(0, 49).map((p) => personAsset(p))], tags: ["leaver", "saas"],
        });
      }
    }
    // Signed in after termination
    if (!idpHasSignIn && !saasHasLastLogin) skip("leaver_signed_in_after_term", "no last sign-in column in the IdP or any SaaS list");
    for (const p of leavers) if (p._signInAfter && p._signInAfter.length) {
      p.flags.push("signed in after termination");
      const latest = p._signInAfter.map((s) => s.lastSignIn).sort().pop();
      push({
        id: "leaver_signed_in_after_term:" + (p.email || p.name), title: "Leaver signed in after termination", severity: "critical", confidence: p.idp && p.idp.matchConfidence === "review" ? "review" : "confirmed", category: "leaver",
        description: `${p.name} (terminated ${day(p.termDate)}) has sign-in activity up to ${latest.slice(0, 10)} in ${uniq(p._signInAfter.map((s) => s.source)).join(", ")}.`,
        recommendation: "Treat as a potential unauthorised access event: disable everywhere, revoke sessions, review what was accessed after the termination date and preserve logs.",
        controls: [C.t1078, C.iso518, C.soc62, C.ac23, C.ps4],
        evidence: p._signInAfter.map((s) => ({ person: p.name, terminated: day(p.termDate), source: s.source, account: s.account, lastSignIn: s.lastSignIn })),
        assets: [personAsset(p, { signedInAfterTermination: true })], tags: ["leaver", "activity"],
      });
    }
    // Devices still checking in
    if (!haveDev) skip("leaver_device_active", "no device inventory file");
    for (const p of leavers) {
      const live = p.devices.filter((d) => d.lastCheckin != null && d.lastCheckin > p.termDate);
      if (!live.length) continue;
      p.flags.push("device active after termination");
      push({
        id: "leaver_device_active:" + (p.email || p.name), title: "Leaver's device still checking in", severity: "high", confidence: "confirmed", category: "leaver",
        description: `${live.length} device(s) assigned to ${p.name} (terminated ${day(p.termDate)}) checked in after the termination date, most recently ${day(live.map((d) => d.lastCheckin).sort().pop())}.`,
        recommendation: "Confirm the device was returned or remotely wipe/retire it; reassign or remove the primary user in the MDM.",
        controls: [C.ps4, C.iso518, C.soc62, { framework: "CIS", id: "1.1" }],
        evidence: live.map((d) => ({ person: p.name, device: d.device, lastCheckin: iso(d.lastCheckin), compliance: d.compliance, os: d.os, source: d.source })),
        assets: [personAsset(p), ...live.slice(0, 10).map((d) => ({ type: "ASSET", name: d.device, data: { kind: "device", user: d.user } }))], tags: ["leaver", "device"],
      });
    }
    // Terminated managers of record
    if (!hrHasManager) skip("orphaned_reports", "HR roster has no manager column");
    else {
      const active = people.filter((p) => p.hrStatus !== "terminated");
      for (const mgr of leavers) {
        const keys = new Set([low(mgr.email), low(mgr.employeeId), mgr.nameKey].filter(Boolean));
        const reports = active.filter((p) => { const m = str(p.manager); return m && (keys.has(low(m)) || keys.has(normalizeName(m))); });
        if (!reports.length) continue;
        mgr.flags.push("still manager of record");
        push({
          id: "orphaned_reports:" + (mgr.email || mgr.name), title: "Terminated manager still manager of record", severity: "medium", confidence: "confirmed", category: "hr-hygiene",
          description: `${mgr.name} was terminated on ${day(mgr.termDate)} but is still the manager of record for ${reports.length} active employee(s). Approvals and access reviews routed to this person will stall or be auto-approved.`,
          recommendation: "Reassign the direct reports in HR and in any approval workflows (access requests, expense, access review campaigns) that key off the manager field.",
          controls: [C.iso518, C.soc63, C.ps5, C.cis53],
          evidence: reports.map((p) => ({ report: p.name, email: p.email, department: p.dept, managerOfRecord: p.manager, managerTerminated: day(mgr.termDate) })),
          assets: [personAsset(mgr)], tags: ["leaver", "hr"],
        });
      }
    }
  }

  // 4. Movers -------------------------------------------------------------------------
  const movers = [];
  if (haveHR) {
    for (const c of loaded.changes) for (const ch of c.rows) {
      if (!/transfer|promotion|department|move|reorg|change/i.test(ch.changeType) && !(ch.fromDept && ch.toDept)) continue;
      const m = matchPerson(idx, { email: ch.email, name: ch.name, employeeId: ch.employeeId });
      if (!m) continue;
      movers.push({ person: m.person, effectiveDate: ch.effectiveDate, changeType: ch.changeType, fromDept: ch.fromDept, toDept: ch.toDept, fromManager: ch.fromManager, toManager: ch.toManager, source: "changes file" });
    }
    if (!loaded.changes.length && haveIdp && hrHasDept && idpHasDept) {
      for (const p of people) if (p.idp && p.hrStatus === "active" && str(p.dept) && str(p.idp.dept) && norm(p.dept) !== norm(p.idp.dept)) {
        movers.push({ person: p, effectiveDate: null, changeType: "department mismatch", fromDept: p.idp.dept, toDept: p.dept, source: "HR vs IdP department" });
      }
    }
    if (!loaded.changes.length && !(haveIdp && hrHasDept && idpHasDept)) skip("mover_stale_access", "no HR changes file and no department column in both HR and IdP");
    else if (!idpHasGroups) skip("mover_stale_groups", "IdP export has no memberOf/groups column; movers are only reported as department mismatches");
    for (const mv of movers.sort((a, b) => cmp(a.person.key, b.person.key))) {
      const p = mv.person;
      const past = mv.effectiveDate == null || now - mv.effectiveDate >= o.moverGraceDays * DAY;
      if (!past) continue;
      const u = p.idp;
      const oldTokens = str(mv.fromDept).toLowerCase().split(/[^a-z0-9]+/).filter((t) => t.length >= 3);
      const stale = u ? u.groups.filter((g) => { const gl = g.toLowerCase(); return oldTokens.length && oldTokens.every((t) => gl.includes(t)); }) : [];
      const deptMismatch = u && str(u.dept) && norm(u.dept) === norm(mv.fromDept) && norm(mv.toDept) !== norm(mv.fromDept);
      if (!stale.length && !deptMismatch) continue;
      p.flags.push("mover with stale access");
      const daysSince = mv.effectiveDate == null ? null : Math.floor((now - mv.effectiveDate) / DAY);
      push({
        id: "mover_stale_access:" + (p.email || p.name), title: stale.length ? "Mover still in old department's groups" : "Mover's IdP department not updated", severity: stale.length ? "medium" : "low", confidence: "review", category: "mover",
        description: `${p.name} moved from ${mv.fromDept || "?"} to ${mv.toDept || "?"} (${mv.changeType}${daysSince != null ? ", " + daysSince + " days ago" : ""}, grace ${o.moverGraceDays} days).` + (stale.length ? ` Still a member of ${stale.length} group(s) named for the old department: ${stale.slice(0, 5).join(", ")}.` : ` The IdP still lists department "${u.dept}".`),
        recommendation: "Review the mover's entitlements against the new role; remove old-department groups and application roles, and make transfers trigger a re-certification rather than additive access.",
        controls: [C.iso518, C.soc63, C.ps5, C.cis53, { framework: "NIST-800-53", id: "AC-6" }],
        evidence: [{ person: p.name, email: p.email, changeType: mv.changeType, effectiveDate: day(mv.effectiveDate), fromDepartment: mv.fromDept, toDepartment: mv.toDept, idpDepartment: u ? u.dept : "", staleGroups: stale.join("; "), source: mv.source }],
        assets: [personAsset(p, { mover: true })], tags: ["mover"],
      });
    }
  }

  // 5. Joiners ------------------------------------------------------------------------
  if (haveHR && haveIdp) {
    if (!hrHasHire) skip("joiner_checks", "HR roster has no hire date column");
    else {
      if (!idpHasCreated) skip("joiner_early_account", "IdP export has no created date column");
      const early = [], missing = [];
      for (const p of people) {
        if (p.hrStatus !== "active" || p.hireDate == null) continue;
        if (!p.idp) { if (p.hireDate <= now) missing.push(p); continue; }
        if (idpHasCreated && p.idp.created != null && p.hireDate - p.idp.created > o.joinerLeadDays * DAY) early.push({ p, days: Math.floor((p.hireDate - p.idp.created) / DAY) });
      }
      if (early.length) {
        for (const e of early) e.p.flags.push("account created " + e.days + " days before hire");
        push({
          id: "joiner_early_account", title: "Accounts created long before the hire date", severity: "low", confidence: "likely", category: "joiner",
          description: `${early.length} active employee(s) had an IdP account more than ${o.joinerLeadDays} days before their hire date (max ${Math.max(...early.map((e) => e.days))} days). Pre-hire accounts are a window for credential misuse and often never get the joiner baseline applied.`,
          recommendation: "Provision from the HR hire event with a start-date trigger, keep pre-hire accounts disabled until day one, and check whether these accounts were reused from a previous worker.",
          controls: [C.iso518, C.soc62, { framework: "NIST-800-53", id: "AC-2" }, C.cis53],
          evidence: early.map((e) => ({ person: e.p.name, email: e.p.email, hireDate: day(e.p.hireDate), accountCreated: day(e.p.idp.created), daysBeforeHire: e.days, idpAccount: e.p.idp.upn })),
          assets: early.slice(0, 50).map((e) => personAsset(e.p)), tags: ["joiner"],
        });
      }
      if (missing.length) {
        for (const p of missing) p.flags.push("no IdP account");
        push({
          id: "joiner_no_account", title: "Active employees with no IdP account", severity: "medium", confidence: "review", category: "joiner",
          description: `${missing.length} active employee(s) past their hire date have no matching account in the IdP export. Either provisioning failed or the roster and IdP use different identifiers (matching tried email, UPN local-part and name).`,
          recommendation: "Verify each person's status with HR; provision missing accounts through the standard joiner flow and fix identifier mismatches (set employeeId/mail in the IdP) so matching is exact.",
          controls: [C.iso518, { framework: "NIST-800-53", id: "AC-2" }, C.cis53],
          evidence: missing.map((p) => ({ person: p.name, email: p.email, employeeId: p.employeeId, hireDate: day(p.hireDate), department: p.dept, status: p.hrStatus })),
          assets: missing.slice(0, 50).map((p) => personAsset(p)), tags: ["joiner"],
        });
      }
    }
  }

  // 6. Orphan and external SaaS accounts ------------------------------------------
  if (haveSaas && !haveHR) skip("orphan_saas", "no HR roster to compare SaaS accounts against");
  if (haveSaas && haveHR) for (const st of [...appStats.values()].sort((a, b) => cmp(a.app, b.app))) {
    if (st.orphans.length) {
      push({
        id: "orphan_saas:" + st.app, title: `Orphan accounts in ${st.app}`, severity: "medium", confidence: "review", category: "orphan",
        description: `${st.orphans.length} active ${st.app} account(s) on a company domain match nobody in HR${haveIdp ? " or the IdP" : ""} and do not look like service accounts.`,
        recommendation: `Identify an owner for each account or deactivate it; require ${st.app} accounts to be provisioned through the IdP so every seat maps to a person or a registered service identity.`,
        controls: [C.iso518, C.soc62, C.ac23, C.cis53, C.t1078],
        evidence: st.orphans.map((a) => ({ account: a.email || a.login, name: a.name, role: a.role, status: a.status, lastLogin: day(a.lastLogin), licensed: a.licensed })),
        assets: [appAsset(st), ...st.orphans.slice(0, 49).map((a) => ({ type: "IDENTITY", name: a.email || a.login, data: { status: "orphan", termDate: null, apps: [st.app] } }))], tags: ["orphan", "saas"],
      });
    }
    if (st.external.length) {
      push({
        id: "external_guest_saas:" + st.app, title: `External accounts in ${st.app}`, severity: "low", confidence: "review", category: "external",
        description: `${st.external.length} active ${st.app} account(s) use a domain outside the company domains (${companyDomains.join(", ")}) and are not in the allowed external domains list.`,
        recommendation: "Confirm each external account has a sponsor and an end date; add legitimate partner domains to the allowed list so they stop appearing here.",
        controls: [C.iso518, C.soc62, C.ac23, { framework: "CIS", id: "6.1" }],
        evidence: st.external.map((a) => ({ account: a.email || a.login, domain: a.domain, name: a.name, role: a.role, lastLogin: day(a.lastLogin) })),
        assets: [appAsset(st)], tags: ["external", "saas"],
      });
    }
  }

  // 7. Licence waste --------------------------------------------------------------------
  let wasteSeats = 0, wasteCost = 0, costKnown = false;
  if (haveSaas) {
    if (![...appStats.values()].some((s) => s.hasLicense)) skip("license_waste", "no licence column in any SaaS list (M365 Licenses, Zoom Type, Salesforce User License, Slack billing-active)");
    for (const st of [...appStats.values()].sort((a, b) => cmp(a.app, b.app))) {
      if (!st.hasLicense) continue;
      const rows = [];
      for (const p of people) for (const a of p.apps) if (a.app === st.app && a.licensed === true) {
        if (p.hrStatus === "terminated" && p.termDate != null && p.termDate <= now) rows.push({ account: a.email || a.login, person: p.name, reason: "terminated " + day(p.termDate), status: a.status, lastLogin: day(a.lastLogin) });
        else if (st.hasLastLogin && a.lastLogin == null && a.status === "active") rows.push({ account: a.email || a.login, person: p.name, reason: "never signed in", status: a.status, lastLogin: null });
      }
      for (const a of [...st.orphans, ...st.external]) if (a.licensed === true) rows.push({ account: a.email || a.login, person: a.name, reason: "no matching employee", status: a.status, lastLogin: day(a.lastLogin) });
      if (!rows.length) continue;
      rows.sort((x, y) => cmp(x.account, y.account));
      const price = Number(o.licenseCostMonthly[st.app]);
      const hasPrice = Number.isFinite(price) && price > 0;
      const monthly = hasPrice ? Math.round(rows.length * price * 100) / 100 : null;
      st.waste = rows; wasteSeats += rows.length; if (hasPrice) { wasteCost += monthly; costKnown = true; }
      push({
        id: "license_waste:" + st.app, title: `Paid ${st.app} licences held by leavers or never-used accounts`, severity: hasPrice && monthly >= 500 ? "medium" : "low", confidence: "likely", category: "licence",
        description: `${rows.length} licensed ${st.app} seat(s) belong to terminated employees, accounts that never signed in, or accounts with no matching employee.` + (hasPrice ? ` At the entered ${price}/seat/month that is ${monthly} per month.` : " Enter a per-seat monthly cost to see the spend."),
        recommendation: `Reclaim the licences in ${st.app} and tie licence removal to the leaver workflow; review never-used seats with the business owner before the next renewal.`,
        controls: [C.iso518, C.soc62, C.cis53],
        evidence: rows, assets: [appAsset(st)], tags: ["licence", "saas"],
      });
    }
  }

  // 8. Shared mailbox / resource accounts with sign-in enabled ---------------------------
  const RESOURCE_RE = /mailbox|shared|room|resource|conference|meeting ?room|equipment/i;
  const m365Lists = loaded.saas.filter((s) => s.vendor === "m365" && s.columns.licensed && s.columns.status);
  if (haveIdp || m365Lists.length) {
    if (!idpHasLicenses && !m365Lists.length) skip("shared_mailbox_signin", "IdP export has no assignedLicenses column and no Microsoft 365 licence export was loaded (needed to tell a shared mailbox from a licensed user)");
    else {
      const rows = [];
      if (idpHasLicenses) for (const i of loaded.idps) for (const u of i.users) if (u.enabled === true && u.licensed === false && RESOURCE_RE.test(u.name + " " + u.upn)) rows.push({ account: u.upn || u.id, displayName: u.name, enabled: true, licensed: false, lastSignIn: day(u.lastSignIn), source: i.vendor });
      for (const s of m365Lists) for (const a of s.accounts) if (a.status === "active" && a.licensed === false && RESOURCE_RE.test(a.name + " " + a.email)) rows.push({ account: a.email || a.login, displayName: a.name, enabled: true, licensed: false, lastSignIn: day(a.lastLogin), source: s.app });
      if (rows.length) {
        rows.sort((x, y) => cmp(x.account, y.account));
        push({
          id: "shared_mailbox_signin", title: "Shared mailbox or resource accounts with sign-in enabled", severity: "medium", confidence: "likely", category: "resource-account",
          description: `${rows.length} unlicensed account(s) named like a shared mailbox, room or resource are sign-in enabled. Shared mailboxes do not need a sign-in; an enabled one is a password-only identity that leavers and attackers can keep using.`,
          recommendation: "Block sign-in on shared mailbox and resource accounts (Entra: accountEnabled=false), access them through delegated permissions, and exclude them from password-only authentication.",
          controls: [{ framework: "CIS Microsoft 365 Benchmark", id: "1.2.2" }, C.iso518, C.soc62, C.t1078],
          evidence: rows, assets: rows.slice(0, 50).map((r) => ({ type: "IDENTITY", name: r.account, data: { status: "resource", termDate: null, apps: [] } })), tags: ["resource", "idp"],
        });
      }
    }
  }

  // 9. Tables -----------------------------------------------------------------------------
  for (const p of people) p.flags = uniq(p.flags).sort();
  const peopleTable = people.map((p) => ({
    person: p.name, email: p.email, employeeId: p.employeeId, department: p.dept, hrStatus: p.hrStatus, hireDate: day(p.hireDate), termDate: day(p.termDate),
    idpStatus: p.idp ? (p.idp.enabled === false ? "disabled" : p.idp.enabled === true ? "enabled" : "unknown") : (haveIdp ? "none" : ""),
    idpAccount: p.idp ? p.idp.upn : "", lastSignIn: day(p.idp ? p.idp.lastSignIn : null),
    apps: p.apps.map((a) => ({ app: a.app, status: a.status, licensed: a.licensed, lastLogin: day(a.lastLogin) })).sort((a, b) => cmp(a.app, b.app)),
    devices: p.devices.map((d) => d.device).sort(), flags: p.flags,
  })).sort((a, b) => cmp(a.person.toLowerCase(), b.person.toLowerCase()) || cmp(a.email, b.email));
  const appsTable = [...appStats.values()].map((st) => ({
    app: st.app, vendor: st.vendor, file: st.file, total: st.total, active: st.active, activeLeavers: st.leavers.length, orphans: st.orphans.length, external: st.external.length,
    licensedWaste: st.waste.length, monthlyWaste: Number.isFinite(Number(o.licenseCostMonthly[st.app])) && Number(o.licenseCostMonthly[st.app]) > 0 ? Math.round(st.waste.length * Number(o.licenseCostMonthly[st.app]) * 100) / 100 : null,
  })).sort((a, b) => cmp(a.app, b.app));
  sla.sort((a, b) => cmp(a.leaver, b.leaver));

  findings.sort((a, b) => (SEV_RANK[b.severity] - SEV_RANK[a.severity]) || cmp(a.title, b.title) || cmp(a.id || "", b.id || ""));
  const leaversStillActive = leavers.filter((p) => p.flags.some((f) => /after termination/.test(f))).length;
  const measured = sla.filter((s) => s.status === "disabled" && s.hours != null).map((s) => s.hours);
  const summary = {
    files: files.length, people: people.length, leavers: leavers.length, leaversStillActive,
    appsWithLeakage: appsTable.filter((a) => a.activeLeavers > 0).length, apps: appsTable.length,
    medianHoursToDisable: median(measured), slaBreaches: sla.filter((s) => s.breach === true).length,
    movers: movers.length, orphans: appsTable.reduce((n, a) => n + a.orphans, 0), external: appsTable.reduce((n, a) => n + a.external, 0),
    licenseWasteSeats: wasteSeats, licenseWasteMonthly: costKnown ? Math.round(wasteCost * 100) / 100 : null,
    idpUnmatched: idpUnmatched.length, companyDomains, findings: findings.length, bySeverity: countBy(findings, "severity"),
  };
  ctx?.progress?.(total, total, "done");
  return {
    summary, findings, tables: { people: peopleTable, apps: appsTable, sla, files: fileTable }, skipped,
    meta: { tool: TOOL_ID, version: VERSION, rows: total === 1 && !files.length ? 0 : files.reduce((n, f) => n + (f.rows ? f.rows.length : 0), 0), now: iso(now), options: { disableSlaHours: o.disableSlaHours, moverGraceDays: o.moverGraceDays, joinerLeadDays: o.joinerLeadDays, allowDomains: [...allowDomains].sort() } },
  };
}

function countBy(items, key) {
  const out = {};
  for (const it of items) out[it[key]] = (out[it[key]] || 0) + 1;
  return out;
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
const FINDING_COLS = ["severity", "confidence", "category", "title", "description", "recommendation", "controls", "evidenceCount"];
const q = (v) => '"' + String(v ?? "").replace(/"/g, '""') + '"';

/** Findings as CSV with fixed columns. */
export function findingsToCsv(findings) {
  const head = FINDING_COLS.join(",");
  const body = (findings || []).map((f) => [
    f.severity, f.confidence, f.category, f.title, f.description, f.recommendation,
    (f.controls || []).map((c) => c.framework + " " + c.id).join("; "), f.evidenceCount != null ? f.evidenceCount : (f.evidence || []).length,
  ].map(q).join(","));
  return [head, ...body].join("\n");
}

/** Offboarding worklist: one row per (person, app, action). */
export function worklistCsv(result) {
  const rows = [];
  for (const p of (result && result.tables && result.tables.people) || []) {
    const leaver = p.hrStatus === "terminated";
    if (leaver && p.idpStatus === "enabled") rows.push([p.person, p.email, p.idpAccount ? "IdP (" + p.idpAccount + ")" : "IdP", "Disable account and revoke sessions", "terminated " + p.termDate]);
    for (const a of p.apps) {
      if (leaver && a.status === "active") rows.push([p.person, p.email, a.app, "Deactivate account", "terminated " + p.termDate]);
      if (a.licensed === true && (leaver || (a.status === "active" && a.lastLogin == null))) rows.push([p.person, p.email, a.app, "Reclaim licence", leaver ? "terminated " + p.termDate : "never signed in"]);
    }
    if (leaver && p.devices.length && p.flags.includes("device active after termination")) rows.push([p.person, p.email, "Devices (" + p.devices.join("; ") + ")", "Recover or wipe device", "terminated " + p.termDate]);
    if (p.flags.includes("still manager of record")) rows.push([p.person, p.email, "HR", "Reassign direct reports", "terminated " + p.termDate]);
    if (p.flags.includes("mover with stale access")) rows.push([p.person, p.email, "IdP groups", "Remove old-department groups", "mover"]);
  }
  for (const f of (result && result.findings) || []) if (f.category === "orphan" || f.category === "external") for (const e of f.evidence || []) rows.push([e.name || "", e.account, f.assets[0] ? f.assets[0].name : "", f.category === "orphan" ? "Find owner or deactivate" : "Confirm sponsor and end date", f.category]);
  rows.sort((a, b) => cmp(a[0], b[0]) || cmp(a[2], b[2]) || cmp(a[3], b[3]));
  return ["person,email,app,action,reason", ...rows.map((r) => r.map(q).join(","))].join("\n");
}

/** SLA report: one row per leaver with the time to disable. */
export function slaCsv(result) {
  const rows = ((result && result.tables && result.tables.sla) || []).map((s) => [s.leaver, s.terminated, s.disabledAt || "", s.hours == null ? "" : s.hours, s.breach == null ? "" : (s.breach ? "yes" : "no"), s.status, s.idp || ""]);
  return ["leaver,terminated,disabledAt,hours,breach,status,idp", ...rows.map((r) => r.map(q).join(","))].join("\n");
}

// ---------------------------------------------------------------------------
// Synthetic example (seeded; exact vendor headers; never real data)
// ---------------------------------------------------------------------------
const FIRST = ["Priya", "Dana", "Marcus", "Yuki", "Sofia", "Grace", "Tomas", "Hannah", "Ravi", "Elena", "Noah", "Amara", "Luca", "Mei", "Omar"];
const LAST = ["Natarajan", "Kowalski", "Reed", "Tanaka", "Alvarez", "Okafor", "Ferreira", "Schmidt", "Menon", "Petrova", "Lindqvist", "Diallo", "Moretti", "Chen", "Haddad"];

/** Seeded SYNTHETIC multi-file dataset for "Load example" and tests. */
export function exampleDataset(seed = 7) {
  let s = seed >>> 0;
  const rnd = () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 4294967296; };
  const NOW = Date.UTC(2026, 2, 31, 12, 0, 0); // 2026-03-31T12:00Z, also the latest timestamp in the data
  const d = (days) => new Date(NOW - days * DAY).toISOString().slice(0, 10);
  const dt = (days, h = 0) => new Date(NOW - days * DAY + h * HOUR).toISOString();
  const DOM = "test.darknode.ai";
  const depts = ["Engineering", "Finance", "Sales", "People", "IT", "Legal"];
  const people = [];
  const used = new Set();
  for (let i = 0; i < 12; i++) {
    let f, l, k;
    do { f = FIRST[Math.floor(rnd() * FIRST.length)]; l = LAST[Math.floor(rnd() * LAST.length)]; k = f + l; } while (used.has(k));
    used.add(k);
    people.push({ id: "E" + (1001 + i), first: f, last: l, email: (f + "." + l).toLowerCase() + "@" + DOM, dept: depts[i % depts.length], hire: 200 + Math.floor(rnd() * 900), term: null });
  }
  // three leavers on different dates; manager chain
  people[2].term = 10;  // leaver A: still ACTIVE in Okta, Slack, M365 (E3)
  people[5].term = 30;  // leaver B: DEPROVISIONED 3 days after termination (SLA breach)
  people[8].term = 60;  // leaver C: DEPROVISIONED within 2 hours, but still a GitHub member and manager of record
  people[11].hire = -3; // starts in 3 days; Okta account created 20 days before hire (early joiner)
  const mgr = (i) => (i === 0 ? "" : i < 4 ? people[0].first + " " + people[0].last : i < 8 ? people[8].first + " " + people[8].last : people[1].first + " " + people[1].last);

  const hr = ["Employee ID,Worker,Email - Primary Work,Hire Date,Termination Date,Active Status,Manager,Cost Center,Job Title,Business Title,Location"];
  people.forEach((p, i) => hr.push([p.id, p.first + " " + p.last, p.email, d(p.hire), p.term == null ? "" : d(p.term), p.term == null ? "Yes" : "No", mgr(i), p.dept, i % 3 ? "Analyst" : "Manager", i % 3 ? "Senior Analyst" : "Team Lead", i % 2 ? "Austin" : "Dublin"].map(csvQuote).join(",")));

  const changes = ["Employee ID,Effective Date,Change Type,From Department,To Department,From Manager,To Manager",
    [people[4].id, d(40), "Transfer", people[4].dept === "IT" ? "Finance" : "IT", people[4].dept, mgr(1), mgr(4)].join(",")];
  const oldDept = people[4].dept === "IT" ? "Finance" : "IT";

  const okta = people.map((p, i) => {
    const leaver = p.term != null;
    const status = i === 2 ? "ACTIVE" : leaver ? "DEPROVISIONED" : i === 11 ? "PROVISIONED" : "ACTIVE";
    const statusChanged = i === 5 ? dt(30, 72) : i === 8 ? dt(60, 2) : dt(i === 11 ? p.hire + 20 : p.hire);
    const groups = [p.dept + "-All", "Everyone"];
    if (i === 4) groups.push(oldDept + "-Finance-Approvers".replace("Finance-", ""), oldDept + "-All");
    return {
      id: "00u" + String(100000 + i * 7919).padStart(8, "0"), status, created: dt(i === 11 ? p.hire + 20 : p.hire), activated: dt(i === 11 ? p.hire + 20 : p.hire), statusChanged,
      lastLogin: i === 2 ? dt(4) : leaver ? dt(p.term + 1) : i === 11 ? null : dt(Math.floor(rnd() * 6)),
      profile: { login: p.email, email: p.email, firstName: p.first, lastName: p.last, department: i === 4 ? oldDept : p.dept, title: i % 3 ? "Analyst" : "Manager", managerId: i ? people[0].id : "" },
      groups: groups.map((g) => ({ id: "00g" + g.length, profile: { name: g } })),
    };
  });

  const slack = ["username,email,status,billing-active,has-2fa,has-sso,userid,fullname,displayname,expiration-timestamp"];
  people.forEach((p, i) => {
    if (i === 5 || i === 8) return; // leavers B and C were removed from Slack
    const status = i === 2 ? "Member" : i === 0 ? "Owner" : i === 1 ? "Admin" : "Member";
    slack.push([localPart(p.email), p.email, status, "1", i % 4 ? "1" : "0", "1", "U0" + (1000 + i), p.first + " " + p.last, p.first.toLowerCase(), ""].join(","));
  });
  slack.push(["jordan.blake", "jordan.blake@" + DOM, "Member", "1", "0", "0", "U09999", "Jordan Blake", "jordan", ""].join(",")); // orphan: not in HR or Okta
  slack.push(["agency.partner", "sam@agency-partner.example", "Member", "1", "1", "0", "U09998", "Sam Agency", "sam", ""].join(",")); // external guest
  slack.push(["former.user", "former.user@" + DOM, "Deactivated", "0", "0", "0", "U09997", "Former User", "former", ""].join(","));

  const github = ["Login,Name,Role,Two-factor,Saml identity"];
  people.forEach((p, i) => { if (i % 2 === 0 || i === 8) github.push([(p.first[0] + p.last).toLowerCase(), p.first + " " + p.last, i === 0 ? "Owner" : "Member", i === 8 ? "disabled" : "enabled", p.email].join(",")); });
  github.push(["ci-bot", "CI Bot", "Member", "enabled", ""].join(","));

  const m365 = ["Display name,User principal name,Licenses,Block credential,Last sign-in"];
  people.forEach((p, i) => {
    if (i === 8) return;
    const lic = i === 2 || i % 3 === 0 ? "Microsoft 365 E3" : i === 5 ? "" : "Microsoft 365 Business Standard";
    const blocked = i === 5 ? "True" : "False";
    const last = i === 2 ? d(3) : i === 5 ? d(31) : i === 7 ? "" : d(Math.floor(rnd() * 5));
    m365.push([p.first + " " + p.last, p.email, lic, blocked, last].map(csvQuote).join(","));
  });
  m365.push(["Finance Shared Mailbox", "finance.shared@" + DOM, "", "False", ""].join(","));

  return {
    label: "synthetic example (not real data)",
    now: new Date(NOW).toISOString(),
    files: [
      { name: "workday-roster.csv", text: hr.join("\n") },
      { name: "workday-changes.csv", text: changes.join("\n") },
      { name: "okta-users.json", text: JSON.stringify(okta, null, 1) },
      { name: "slack-members.csv", text: slack.join("\n") },
      { name: "github-people.csv", text: github.join("\n") },
      { name: "m365-active-users.csv", text: m365.join("\n") },
    ],
  };
}

/** Real deterministic checks of the engine over the synthetic example. */
export function selfTest() {
  const tests = [];
  const ex = exampleDataset();
  const parsed = parseInput(ex.files);
  const kinds = parsed.files.map((f) => f.kind + ":" + f.vendor);
  tests.push({ name: "example files classified", pass: JSON.stringify(kinds) === JSON.stringify(["hr:workday", "hr-changes:generic", "idp:okta", "saas:slack", "saas:github", "saas:m365"]) });
  const r = analyze(parsed, {});
  const titles = r.findings.map((f) => f.title);
  tests.push({ name: "leaver still enabled in IdP", pass: titles.includes("Leaver still enabled in the IdP") });
  tests.push({ name: "leavers active in Slack and Microsoft 365", pass: titles.includes("Leavers still active in Slack") && titles.includes("Leavers still active in Microsoft 365") });
  tests.push({ name: "SLA breach measured", pass: titles.includes("Leavers disabled later than the SLA") && r.summary.medianHoursToDisable != null });
  tests.push({ name: "orphan Slack account", pass: titles.includes("Orphan accounts in Slack") });
  tests.push({ name: "licence waste without price is a count", pass: r.findings.some((f) => f.category === "licence") && r.summary.licenseWasteMonthly === null });
  tests.push({ name: "deterministic", pass: JSON.stringify(analyze(parsed, {})) === JSON.stringify(r) });
  tests.push({ name: "empty input yields no findings", pass: analyze([]).findings.length === 0 && analyze(parseInput("")).findings.length === 0 });
  return { pass: tests.every((t) => t.pass), tests };
}
