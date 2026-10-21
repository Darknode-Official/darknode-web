// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Privileged Access Audit engine (privaudit). Pure: no DOM, no network, no clock.
// Runs inside a Blob module Worker and in node tests. Deterministic: the same input
// yields byte-identical JSON (everything is sorted; "now" is opts.now or the latest
// timestamp seen in the data, never Date.now()).
//
// Inputs (each optional, auto-detected per file):
//   - Microsoft Entra ID role assignments: portal "Roles and administrators > Download
//     assignments" CSV, or Graph JSON (roleManagement/directory/roleAssignments,
//     roleEligibilityScheduleInstances, roleAssignmentScheduleInstances).
//   - AWS IAM credential report CSV (aws iam get-credential-report).
//   - AWS account authorization details JSON (aws iam get-account-authorization-details).
//   - GCP project IAM policy JSON (gcloud projects get-iam-policy --format=json).
//   - Okta administrators (dashboard CSV export or role-assignment JSON).
//   - GitHub organisation members (people CSV export or gh api orgs/{org}/members JSON).
//
// Every finding cites a published control: CIS Microsoft 365 Foundations Benchmark,
// CISA SCuBA (MS.AAD.*), CIS AWS Foundations Benchmark, CIS Google Cloud Platform
// Foundation Benchmark, CIS Software Supply Chain Security Guide, NIST SP 800-53 Rev. 5,
// ISO/IEC 27001:2022 Annex A, MITRE ATT&CK.

import { sniff, parseCsv, findColumn, normHeader } from "../ingest/parse.js";

export const TOOL_ID = "privaudit";
export const VERSION = "1.0.0";

const DAY = 86400000;
export const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** Human labels for the detected input sources. */
export const SOURCES = {
  entra: "Microsoft Entra role assignments",
  "aws-credential-report": "AWS IAM credential report",
  "aws-auth-details": "AWS IAM authorization details",
  "gcp-iam": "GCP project IAM policy",
  "okta-admins": "Okta administrators",
  "github-members": "GitHub organization members",
};

/** Entra built-in directory role template ids -> display names. */
export const ENTRA_ROLE_IDS = {
  "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
  "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
  "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
  "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
  "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
  "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
  "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
  "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
  "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
  "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
  "3a2c62db-5318-420d-8d74-23affee5d9d5": "Intune Administrator",
  "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
  "966707d0-3269-4727-9be2-8c3a10f19b9d": "Password Administrator",
};
const ENTRA_TIER0 = new Set(["global administrator", "privileged role administrator"]);
const ENTRA_TIER1 = new Set(Object.values(ENTRA_ROLE_IDS).map((r) => r.toLowerCase()));

export const OKTA_ROLES = ["SUPER_ADMIN", "ORG_ADMIN", "APP_ADMIN", "USER_ADMIN", "GROUP_MEMBERSHIP_ADMIN", "READ_ONLY_ADMIN",
  "HELP_DESK_ADMIN", "API_ACCESS_MANAGEMENT_ADMIN", "REPORT_ADMIN", "MOBILE_ADMIN", "CUSTOM"];
const OKTA_ROLE_SET = new Set(OKTA_ROLES);

/** AWS credential report header, verbatim (aws iam get-credential-report). */
export const AWS_CRED_HEADERS = ["user", "arn", "user_creation_time", "password_enabled", "password_last_used", "password_last_changed",
  "password_next_rotation", "mfa_active", "access_key_1_active", "access_key_1_last_rotated", "access_key_1_last_used_date",
  "access_key_1_last_used_region", "access_key_1_last_used_service", "access_key_2_active", "access_key_2_last_rotated",
  "access_key_2_last_used_date", "access_key_2_last_used_region", "access_key_2_last_used_service", "cert_1_active",
  "cert_1_last_rotated", "cert_2_active", "cert_2_last_rotated"];

/** Column aliases per source (case/punctuation-insensitive). Override via parseInput(input, { columns }). */
export const COLUMNS = {
  entra: {
    role: ["Role", "Role name", "roleName", "roleDefinition.displayName", "Directory role"],
    displayName: ["Display name", "displayName", "Name"],
    principal: ["User principal name", "userPrincipalName", "UPN", "Principal", "Principal name", "Sign-in name"],
    objectId: ["Object ID", "objectId", "principalId", "id"],
    objectType: ["Object type", "objectType", "Type", "Principal type"],
    assignmentType: ["Assignment type", "assignmentType", "Assignment", "State"],
    scope: ["Scope", "directoryScopeId", "Scope type"],
    startDate: ["Start date", "startDateTime", "Start", "Start time"],
    endDate: ["End date", "endDateTime", "End", "End time"],
  },
  "okta-admins": {
    login: ["Login", "login", "Username", "User", "Email"],
    firstName: ["First name", "firstName"],
    lastName: ["Last name", "lastName"],
    role: ["Role", "Roles", "Admin role", "type", "Role type"],
    status: ["Status", "User status"],
    lastLogin: ["Last login", "lastLogin", "Last sign in", "Last signed in"],
  },
  "github-members": {
    login: ["Login", "login", "Username", "User"],
    name: ["Name", "name", "Display name"],
    role: ["Role", "role", "Org role", "Organization role"],
    twoFactor: ["Two-factor", "Two-factor authentication", "two_factor_authentication", "2FA", "Two factor", "has_2fa"],
    saml: ["Saml identity", "SAML identity", "SSO identity", "saml_identity"],
  },
  "aws-credential-report": Object.fromEntries(AWS_CRED_HEADERS.map((h) => [h, [h]])),
};

/** Tunable thresholds; the UI renders these as the settings panel. */
export const DEFAULTS = {
  staleDays: 90,           // privileged principal with no sign-in / credential use for longer than this
  maxGlobalAdmins: 4,      // CIS M365 1.1.3: fewer than five Global Administrators
  minGlobalAdmins: 2,      // CIS M365 1.1.3 / SCuBA MS.AAD.7.1: at least two (lockout risk below this)
  rootUsedDays: 30,        // AWS root password used within this window counts as "root in use"
  keyRotationDays: 90,     // CIS AWS 1.14: access keys rotated every 90 days or less
  unusedDays: 45,          // CIS AWS 1.12: credentials unused for 45 days or more are disabled
  maxSuperAdmins: 3,       // Okta SUPER_ADMIN cap
  maxOrgOwners: 3,         // GitHub organization owner cap
  trustedAccounts: "",     // comma-separated AWS account ids that may assume roles cross-account
};

const C = {
  cisM365_113: { framework: "CIS Microsoft 365", id: "1.1.3" },
  cisM365_111: { framework: "CIS Microsoft 365", id: "1.1.1" },
  scuba_71: { framework: "CISA SCuBA", id: "MS.AAD.7.1" },
  scuba_72: { framework: "CISA SCuBA", id: "MS.AAD.7.2" },
  scuba_74: { framework: "CISA SCuBA", id: "MS.AAD.7.4" },
  nistAC6_1: { framework: "NIST SP 800-53", id: "AC-6(1)" },
  nistAC6_5: { framework: "NIST SP 800-53", id: "AC-6(5)" },
  nistAC6: { framework: "NIST SP 800-53", id: "AC-6" },
  nistAC2_3: { framework: "NIST SP 800-53", id: "AC-2(3)" },
  nistAC2_9: { framework: "NIST SP 800-53", id: "AC-2(9)" },
  nistAC3: { framework: "NIST SP 800-53", id: "AC-3" },
  nistIA2_1: { framework: "NIST SP 800-53", id: "IA-2(1)" },
  nistIA5_1: { framework: "NIST SP 800-53", id: "IA-5(1)" },
  isoA82: { framework: "ISO 27001:2022", id: "A.8.2" },
  isoA516: { framework: "ISO 27001:2022", id: "A.5.16" },
  isoA518: { framework: "ISO 27001:2022", id: "A.5.18" },
  isoA515: { framework: "ISO 27001:2022", id: "A.5.15" },
  cisAws_14: { framework: "CIS AWS Foundations", id: "1.4" },
  cisAws_15: { framework: "CIS AWS Foundations", id: "1.5" },
  cisAws_17: { framework: "CIS AWS Foundations", id: "1.7" },
  cisAws_110: { framework: "CIS AWS Foundations", id: "1.10" },
  cisAws_112: { framework: "CIS AWS Foundations", id: "1.12" },
  cisAws_113: { framework: "CIS AWS Foundations", id: "1.13" },
  cisAws_114: { framework: "CIS AWS Foundations", id: "1.14" },
  cisAws_115: { framework: "CIS AWS Foundations", id: "1.15" },
  cisAws_116: { framework: "CIS AWS Foundations", id: "1.16" },
  cisGcp_15: { framework: "CIS GCP Foundations", id: "1.5" },
  cisGcp_16: { framework: "CIS GCP Foundations", id: "1.6" },
  cisSsc_133: { framework: "CIS Software Supply Chain", id: "1.3.3" },
  cisSsc_137: { framework: "CIS Software Supply Chain", id: "1.3.7" },
  mitreT1078_004: { framework: "MITRE ATT&CK", id: "T1078.004" },
  mitreT1098_003: { framework: "MITRE ATT&CK", id: "T1098.003" },
  mitreT1098: { framework: "MITRE ATT&CK", id: "T1098" },
  mitreT1110: { framework: "MITRE ATT&CK", id: "T1110" },
  soc2_61: { framework: "SOC 2", id: "CC6.1" },
  soc2_62: { framework: "SOC 2", id: "CC6.2" },
  soc2_63: { framework: "SOC 2", id: "CC6.3" },
};

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
const str = (v) => String(v == null ? "" : v).trim();
const low = (v) => str(v).toLowerCase();
const uniq = (a) => Array.from(new Set(a.filter((x) => x != null && x !== "")));
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const sortBy = (arr, ...keys) => arr.sort((x, y) => { for (const k of keys) { const r = cmp(str(x[k]).toLowerCase(), str(y[k]).toLowerCase()); if (r) return r; } return 0; });
const isGuid = (s) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(str(s));
const asArray = (v) => (v == null ? [] : Array.isArray(v) ? v : [v]);
const days = (from, to) => Math.floor((to - from) / DAY);

/** Parse the usual export date formats to epoch ms; null for blanks / N-A sentinels. */
export function parseDate(v) {
  if (v == null) return null;
  if (typeof v === "number") return numericDate(v);
  const s = str(v);
  if (!s) return null;
  const l = s.toLowerCase();
  if (/^(never|never logged in|n\/a|na|none|null|-|unknown|not set|not_supported|no_information|permanent|not applicable|false|true)$/.test(l)) return null;
  if (/^\d+$/.test(s)) return numericDate(Number(s));
  let m;
  if ((m = /^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?)?\s*(Z|UTC|GMT|[+-]\d{2}:?\d{2})?$/i.exec(s))) {
    const base = Date.UTC(+m[1], +m[2] - 1, +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0));
    return applyOffset(base, m[7]);
  }
  if ((m = /^(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})(?:,?[ T](\d{1,2}):(\d{2})(?::(\d{2}))?)?\s*([AP]M)?\s*(UTC|GMT|Z)?$/i.exec(s))) {
    let a = +m[1], b = +m[2], month, day;
    if (a > 12) { day = a; month = b; } else { month = a; day = b; }
    let hh = +(m[4] || 0);
    if (m[7]) { const pm = m[7].toUpperCase() === "PM"; if (pm && hh < 12) hh += 12; if (!pm && hh === 12) hh = 0; }
    return Date.UTC(+m[3], month - 1, day, hh, +(m[5] || 0), +(m[6] || 0));
  }
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : null;
}
function applyOffset(base, tz) {
  if (!tz || /^(z|utc|gmt)$/i.test(tz)) return base;
  const m = /^([+-])(\d{2}):?(\d{2})$/.exec(tz);
  if (!m) return base;
  return base - (+m[2] * 60 + +m[3]) * 60000 * (m[1] === "+" ? 1 : -1);
}
function numericDate(n) {
  if (!Number.isFinite(n) || n <= 0) return null;
  if (n >= 1e12) return n;
  if (n >= 1e9) return n * 1000;
  return null;
}
const iso = (ms) => (ms == null ? null : new Date(ms).toISOString());

/** true / false / null for the usual boolean spellings. */
export function parseBool(v) {
  if (v === true || v === false) return v;
  const l = low(v);
  if (!l) return null;
  if (/^(true|yes|y|1|enabled|on|active|enforced|registered|capable)$/.test(l)) return true;
  if (/^(false|no|n|0|disabled|off|inactive|not enforced|not registered|none)$/.test(l)) return false;
  return null;
}

/** Shared / generic account-name heuristic (local part or whole name). */
export const SHARED_NAME_RE = /^(admin|administrator|root|sysadmin|shared|it-?admin|svc[-_])/i;
const GENERIC_MAILBOX_RE = /^(info|office|support|helpdesk|help|noreply|no-reply|security|it|ops|accounts|billing|sales|contact|hello|team|postmaster|webmaster)$/i;
export function looksShared(principal) {
  const p = str(principal);
  if (!p || p === "<root_account>") return false;
  const local = p.includes("@") ? p.split("@")[0] : p;
  return SHARED_NAME_RE.test(local) || (p.includes("@") && GENERIC_MAILBOX_RE.test(local));
}

// ---------------------------------------------------------------------------
// Source detection
// ---------------------------------------------------------------------------
function hasHeaders(headers, ...names) {
  const n = new Set(headers.map(normHeader));
  return names.every((x) => n.has(normHeader(x)));
}
function anyHeader(headers, ...names) {
  const n = new Set(headers.map(normHeader));
  return names.some((x) => n.has(normHeader(x)));
}

/** Decide which export a CSV is from its headers (and role values when ambiguous). */
export function detectCsvSource(headers, rows = []) {
  if (hasHeaders(headers, "user", "arn", "mfa_active", "access_key_1_active")) return { source: "aws-credential-report", confidence: 1 };
  if (hasHeaders(headers, "Role") && anyHeader(headers, "User principal name", "Object ID", "Assignment type", "Object type")) return { source: "entra", confidence: 0.95 };
  if (anyHeader(headers, "Login", "login", "Username") && anyHeader(headers, "Role", "Roles", "role")) {
    if (anyHeader(headers, "Two-factor", "Saml identity", "two_factor_authentication")) return { source: "github-members", confidence: 0.95 };
    if (anyHeader(headers, "Status", "Last login", "First name", "Last name")) return { source: "okta-admins", confidence: 0.95 };
    const roleH = findColumn(headers, COLUMNS["okta-admins"].role);
    const vals = rows.slice(0, 200).map((r) => str(r[roleH]).toUpperCase());
    const okta = vals.filter((v) => v.split(/[;,|]/).some((x) => OKTA_ROLE_SET.has(x.trim()))).length;
    const gh = vals.filter((v) => /^(OWNER|MEMBER|ADMIN|BILLING MANAGER|OUTSIDE COLLABORATOR)$/.test(v)).length;
    if (okta && okta >= gh) return { source: "okta-admins", confidence: 0.8 };
    if (gh) return { source: "github-members", confidence: 0.8 };
    return { source: "okta-admins", confidence: 0.5 };
  }
  if (hasHeaders(headers, "Role") && anyHeader(headers, "Display name", "Scope", "Start date")) return { source: "entra", confidence: 0.7 };
  if (anyHeader(headers, "User principal name", "userPrincipalName") && anyHeader(headers, "Role", "roleName", "Directory role")) return { source: "entra", confidence: 0.7 };
  return { source: "unknown", confidence: 0 };
}

/** Decide which export a parsed JSON document is. */
export function detectJsonSource(doc, fileName = "") {
  if (!doc || typeof doc !== "object") return { source: "unknown", confidence: 0 };
  if (!Array.isArray(doc)) {
    if (Array.isArray(doc.UserDetailList) || Array.isArray(doc.RoleDetailList) || Array.isArray(doc.GroupDetailList) || Array.isArray(doc.Policies)) return { source: "aws-auth-details", confidence: 1 };
    if (Array.isArray(doc.bindings)) return { source: "gcp-iam", confidence: 1 };
    if (doc.policy && Array.isArray(doc.policy.bindings)) return { source: "gcp-iam", confidence: 1 };
  }
  const items = Array.isArray(doc) ? doc : Array.isArray(doc.value) ? doc.value : Array.isArray(doc.items) ? doc.items : null;
  if (!items) return { source: "unknown", confidence: 0 };
  const sample = items.filter((x) => x && typeof x === "object").slice(0, 50);
  if (!sample.length) return { source: "unknown", confidence: 0 };
  const share = (fn) => sample.filter(fn).length / sample.length;
  if (share((x) => Array.isArray(x.bindings) || (x.policy && Array.isArray(x.policy.bindings))) > 0.5) return { source: "gcp-iam", confidence: 1 };
  if (share((x) => "roleDefinitionId" in x || "principalId" in x) > 0.5) return { source: "entra", confidence: 1 };
  if (share((x) => OKTA_ROLE_SET.has(str(x.type)) || OKTA_ROLE_SET.has(str(x.role)) || (Array.isArray(x.roles) && x.roles.some((r) => OKTA_ROLE_SET.has(str(r && (r.type || r))))) || (x.profile && x.profile.login)) > 0.5) return { source: "okta-admins", confidence: 0.9 };
  if (share((x) => "login" in x) > 0.5) return { source: "github-members", confidence: /okta/i.test(fileName) ? 0.5 : 0.9 };
  return { source: "unknown", confidence: 0 };
}

// ---------------------------------------------------------------------------
// Normalisers: each returns records tagged with _source (and _kind where needed)
// ---------------------------------------------------------------------------
function entraRoleName(v) {
  const s = str(v);
  if (isGuid(s)) return ENTRA_ROLE_IDS[s.toLowerCase()] || s;
  return s;
}
function entraAssignmentType(typeValue, endValue, hintEligible) {
  const t = low(typeValue), e = low(endValue);
  if (hintEligible || /eligib/.test(t)) return "Eligible";
  if (/permanent|assigned/.test(t)) return "Permanent";
  if (/active|activated/.test(t)) return e && e !== "permanent" && e !== "-" ? "Active" : "Permanent";
  if (t) return "Permanent";
  return e && e !== "permanent" && parseDate(endValue) != null ? "Active" : "Permanent";
}
function entraTier(role) {
  const l = low(role);
  if (ENTRA_TIER0.has(l)) return 0;
  if (ENTRA_TIER1.has(l) || /administrator/.test(l)) return 1;
  return 2;
}

function normEntraCsv(headers, rows, cols, file) {
  const out = [];
  for (const r of rows) {
    const role = entraRoleName(r[cols.role]);
    if (!role) continue;
    const upn = str(r[cols.principal]), dn = str(r[cols.displayName]), oid = str(r[cols.objectId]);
    const principal = upn || dn || oid;
    if (!principal) continue;
    out.push({
      _source: "entra", _file: file, principal, displayName: dn || upn, objectId: oid || null,
      objectType: str(r[cols.objectType]) || "User", role, roleId: null,
      assignmentType: entraAssignmentType(r[cols.assignmentType], r[cols.endDate], false),
      scope: str(r[cols.scope]) || "/", startDate: iso(parseDate(r[cols.startDate])), endDate: iso(parseDate(r[cols.endDate])),
    });
  }
  return out;
}

function normEntraJson(doc, file) {
  const items = Array.isArray(doc) ? doc : Array.isArray(doc.value) ? doc.value : [];
  const ctx = str(doc && doc["@odata.context"]) + " " + str(file);
  const fileEligible = /eligib/i.test(ctx);
  const out = [];
  for (const it of items) {
    if (!it || typeof it !== "object") continue;
    const rd = it.roleDefinition || {};
    const role = str(rd.displayName) || entraRoleName(it.roleDefinitionId || rd.id || rd.templateId);
    const p = it.principal || {};
    const principal = str(p.userPrincipalName) || str(p.appId) || str(p.displayName) || str(it.principalId);
    if (!role || !principal) continue;
    const otype = low(p["@odata.type"]).replace("#microsoft.graph.", "");
    const eligible = fileEligible || /eligib/i.test(str(it["@odata.type"])) || "roleEligibilityScheduleId" in it;
    const typeVal = eligible ? "Eligible" : it.assignmentType === "Activated" ? "Active" : it.endDateTime ? "Active" : "Permanent";
    out.push({
      _source: "entra", _file: file, principal, displayName: str(p.displayName) || principal, objectId: str(it.principalId) || null,
      objectType: otype === "serviceprincipal" ? "ServicePrincipal" : otype === "group" ? "Group" : otype === "user" ? "User" : (str(p.objectType) || "User"),
      role, roleId: str(it.roleDefinitionId) || null, assignmentType: typeVal,
      scope: str(it.directoryScopeId) || "/", startDate: iso(parseDate(it.startDateTime)), endDate: iso(parseDate(it.endDateTime)),
    });
  }
  return out;
}

const NA = (v) => { const l = low(v); return !l || l === "n/a" || l === "no_information" || l === "not_supported" ? null : str(v); };
function normAwsCred(rows, file) {
  const out = [];
  for (const r of rows) {
    const user = str(r.user); if (!user) continue;
    const rec = { _source: "aws-credential-report", _file: file, user, arn: str(r.arn), isRoot: user === "<root_account>" };
    for (const h of AWS_CRED_HEADERS) if (h !== "user" && h !== "arn") rec[h] = NA(r[h]);
    out.push(rec);
  }
  return out;
}

/** PolicyDocument may be a URL-encoded JSON string or an object. */
export function decodePolicy(doc) {
  if (doc == null) return null;
  if (typeof doc === "object") return doc;
  let s = String(doc);
  try { s = decodeURIComponent(s); } catch (_) { /* already decoded */ }
  try { return JSON.parse(s); } catch (_) { return null; }
}
function normAwsAuth(doc, file) {
  const out = [];
  const inl = (list, nameKey) => asArray(list).map((p) => ({ name: str(p[nameKey] || p.PolicyName), doc: decodePolicy(p.PolicyDocument) }));
  const att = (list) => asArray(list).map((p) => ({ name: str(p.PolicyName), arn: str(p.PolicyArn) }));
  for (const u of asArray(doc.UserDetailList)) out.push({ _source: "aws-auth-details", _file: file, _kind: "user", name: str(u.UserName), arn: str(u.Arn), created: iso(parseDate(u.CreateDate)), groups: asArray(u.GroupList).map(str).sort(), inlinePolicies: inl(u.UserPolicyList, "PolicyName"), attached: att(u.AttachedManagedPolicies) });
  for (const g of asArray(doc.GroupDetailList)) out.push({ _source: "aws-auth-details", _file: file, _kind: "group", name: str(g.GroupName), arn: str(g.Arn), inlinePolicies: inl(g.GroupPolicyList, "PolicyName"), attached: att(g.AttachedManagedPolicies) });
  for (const r of asArray(doc.RoleDetailList)) out.push({ _source: "aws-auth-details", _file: file, _kind: "role", name: str(r.RoleName), arn: str(r.Arn), path: str(r.Path) || "/", created: iso(parseDate(r.CreateDate)), trust: decodePolicy(r.AssumeRolePolicyDocument), inlinePolicies: inl(r.RolePolicyList, "PolicyName"), attached: att(r.AttachedManagedPolicies), lastUsed: iso(parseDate(r.RoleLastUsed && r.RoleLastUsed.LastUsedDate)) });
  for (const p of asArray(doc.Policies)) {
    const def = asArray(p.PolicyVersionList).find((v) => v && v.IsDefaultVersion) || asArray(p.PolicyVersionList)[0] || {};
    out.push({ _source: "aws-auth-details", _file: file, _kind: "policy", name: str(p.PolicyName), arn: str(p.Arn), attachmentCount: Number(p.AttachmentCount || 0), awsManaged: /^arn:aws[a-z-]*:iam::aws:policy\//.test(str(p.Arn)), doc: decodePolicy(def.Document) });
  }
  return out;
}

function gcpMemberType(m) {
  const s = str(m);
  if (s === "allUsers" || s === "allAuthenticatedUsers") return s;
  const i = s.indexOf(":");
  return i > 0 ? s.slice(0, i) : "other";
}
function normGcp(doc, file) {
  const out = [];
  const policies = [];
  const push = (project, pol) => { if (pol && Array.isArray(pol.bindings)) policies.push({ project, bindings: pol.bindings }); };
  if (Array.isArray(doc)) {
    doc.forEach((d, i) => d && typeof d === "object" && push(str(d.projectId || d.project || d.resource || d.name) || "policy-" + (i + 1), d.policy || d));
  } else {
    push(str(doc.projectId || doc.project || doc.resource) || str(file).replace(/\.json$/i, "") || "project", doc.policy || doc);
  }
  for (const { project, bindings } of policies) {
    for (const b of bindings) {
      if (!b || typeof b !== "object") continue;
      const role = str(b.role); if (!role) continue;
      const cond = b.condition && typeof b.condition === "object" ? (str(b.condition.title) || str(b.condition.expression)) : null;
      for (const m of asArray(b.members)) {
        const member = str(m); if (!member) continue;
        out.push({ _source: "gcp-iam", _file: file, _kind: "binding", project, role, member, memberType: gcpMemberType(member), condition: cond || null });
      }
    }
  }
  return out;
}

function splitRoles(v) { return uniq(str(v).split(/[;,|\n]+/).map((x) => x.trim().toUpperCase().replace(/\s+/g, "_"))); }
function normOktaCsv(rows, cols, file) {
  const out = [];
  for (const r of rows) {
    const login = str(r[cols.login]); if (!login) continue;
    const name = [str(r[cols.firstName]), str(r[cols.lastName])].filter(Boolean).join(" ");
    const roles = splitRoles(r[cols.role]);
    for (const role of roles.length ? roles : [""]) out.push({ _source: "okta-admins", _file: file, login, name: name || login, role, status: str(r[cols.status]).toUpperCase() || null, lastLogin: iso(parseDate(r[cols.lastLogin])) });
  }
  return out;
}
function normOktaJson(doc, file) {
  const items = Array.isArray(doc) ? doc : Array.isArray(doc.value) ? doc.value : Array.isArray(doc.items) ? doc.items : [];
  const out = [];
  for (const it of items) {
    if (!it || typeof it !== "object") continue;
    const prof = it.profile || (it.user && it.user.profile) || {};
    const login = str(it.login || prof.login || prof.email || it.email || it.id);
    if (!login) continue;
    const name = [str(prof.firstName), str(prof.lastName)].filter(Boolean).join(" ") || str(it.displayName) || login;
    const roles = uniq([...(OKTA_ROLE_SET.has(str(it.type)) ? [str(it.type)] : []), ...splitRoles(it.role), ...asArray(it.roles).map((r) => str(r && (r.type || r.role || r)).toUpperCase())]);
    // Nested user lifecycle status wins over the role object's own assignment status.
    const status = str((it.user && it.user.status) || it.status).toUpperCase() || null;
    const lastLogin = iso(parseDate(it.lastLogin || (it.user && it.user.lastLogin)));
    for (const role of roles.length ? roles : [""]) out.push({ _source: "okta-admins", _file: file, login, name, role, status, lastLogin });
  }
  return out;
}

function ghRole(v) {
  const l = low(v);
  if (/^(owner|admin)$/.test(l)) return "owner";
  if (/^member$/.test(l)) return "member";
  return l || null;
}
function normGithubCsv(rows, cols, file) {
  const out = [];
  for (const r of rows) {
    const login = str(r[cols.login]); if (!login) continue;
    out.push({ _source: "github-members", _file: file, login, name: str(r[cols.name]) || login, role: ghRole(r[cols.role]), twoFactor: cols.twoFactor ? parseBool(r[cols.twoFactor]) : null, saml: str(r[cols.saml]) || null });
  }
  return out;
}
function normGithubJson(doc, file) {
  const items = Array.isArray(doc) ? doc : Array.isArray(doc.value) ? doc.value : [];
  const out = [];
  for (const it of items) {
    if (!it || typeof it !== "object") continue;
    const node = it.node || it;
    const login = str(node.login); if (!login) continue;
    out.push({ _source: "github-members", _file: file, login, name: str(node.name) || login, role: ghRole(it.role || node.role), twoFactor: typeof node.two_factor_authentication === "boolean" ? node.two_factor_authentication : parseBool(node.two_factor_authentication), saml: null });
  }
  return out;
}

// ---------------------------------------------------------------------------
// parseInput: one string, {name,text}, or an array of either. Each file is
// sniffed, its source detected and its rows normalised. Nothing is guessed:
// an unrecognised file is reported in skipped[] and contributes no rows.
// ---------------------------------------------------------------------------
export function parseInput(input, options = {}) {
  const list = (Array.isArray(input) ? input : [input]).map((f, i) => (typeof f === "string" ? { name: "input-" + (i + 1), text: f } : (f || {})));
  const overrides = options.columns || {};
  const forced = options.source || {};
  const files = [], rows = [], skipped = [];
  for (const f of list) {
    const name = str(f.name) || "input";
    const text = String(f.text == null ? "" : f.text);
    if (!text.trim()) { skipped.push({ file: name, reason: "empty file" }); continue; }
    const sn = sniff(text);
    const entry = { name, format: sn.format, source: "unknown", confidence: 0, headers: [], rows: 0, note: "" };
    try {
      if (sn.format === "json" || sn.format === "ndjson") {
        const doc = JSON.parse(text.replace(/^﻿/, ""));
        let det = detectJsonSource(doc, name);
        if (forced[name]) det = { source: forced[name], confidence: 1 };
        entry.source = det.source; entry.confidence = det.confidence;
        const recs = det.source === "entra" ? normEntraJson(doc, name)
          : det.source === "aws-auth-details" ? normAwsAuth(doc, name)
          : det.source === "gcp-iam" ? normGcp(doc, name)
          : det.source === "okta-admins" ? normOktaJson(doc, name)
          : det.source === "github-members" ? normGithubJson(doc, name) : [];
        if (det.source === "github-members" && recs.length && recs.every((r) => r.role == null)) entry.note = "no role field; owner checks need the people CSV export or a role-aware query";
        entry.headers = recs.length ? Object.keys(recs[0]).filter((k) => k[0] !== "_") : [];
        entry.rows = recs.length; rows.push(...recs);
        if (det.source === "unknown") skipped.push({ file: name, reason: "JSON shape not recognised (expected Entra roleAssignments, AWS authorization details, GCP IAM policy, Okta roles or GitHub members)" });
      } else if (sn.format === "csv" || sn.format === "tsv") {
        const { headers, rows: raw } = parseCsv(text, { delimiter: sn.delimiter });
        let det = detectCsvSource(headers, raw);
        if (forced[name]) det = { source: forced[name], confidence: 1 };
        entry.source = det.source; entry.confidence = det.confidence; entry.headers = headers;
        const spec = COLUMNS[det.source];
        const cols = {};
        if (spec) for (const k of Object.keys(spec)) cols[k] = (overrides[det.source] && overrides[det.source][k] && headers.includes(overrides[det.source][k])) ? overrides[det.source][k] : findColumn(headers, spec[k]);
        let recs = [];
        if (det.source === "entra") {
          if (!cols.role || !(cols.principal || cols.displayName || cols.objectId)) skipped.push({ file: name, reason: "Entra CSV needs Role plus User principal name / Display name / Object ID columns" });
          else recs = normEntraCsv(headers, raw, cols, name);
        } else if (det.source === "aws-credential-report") recs = normAwsCred(raw, name);
        else if (det.source === "okta-admins") {
          if (!cols.login || !cols.role) skipped.push({ file: name, reason: "Okta CSV needs Login and Role columns" }); else recs = normOktaCsv(raw, cols, name);
        } else if (det.source === "github-members") {
          if (!cols.login) skipped.push({ file: name, reason: "GitHub CSV needs a Login column" }); else recs = normGithubCsv(raw, cols, name);
          if (!cols.twoFactor && recs.length) entry.note = "no Two-factor column; 2FA checks skipped";
        } else skipped.push({ file: name, reason: "CSV headers not recognised: " + headers.slice(0, 8).join(", ") });
        entry.columns = cols; entry.rows = recs.length; rows.push(...recs);
      } else {
        skipped.push({ file: name, reason: "unsupported format: " + sn.format });
      }
    } catch (e) {
      skipped.push({ file: name, reason: "could not parse: " + String(e && e.message || e) });
    }
    files.push(entry);
  }
  const sources = uniq(files.map((f) => f.source).filter((s) => s !== "unknown")).sort();
  return { format: sources.join("+") || "unknown", headers: files.length === 1 ? files[0].headers : uniq(files.flatMap((f) => f.headers)), rows, skipped, files };
}

// ---------------------------------------------------------------------------
// Policy analysis helpers (AWS)
// ---------------------------------------------------------------------------
function statements(doc) { return doc && typeof doc === "object" ? asArray(doc.Statement).filter((s) => s && typeof s === "object") : []; }
const matchesAction = (list, re) => list.some((a) => re.test(str(a)));
const starResource = (res) => asArray(res).some((r) => str(r) === "*");

/** Over-broad statements in an identity policy document. */
export function policyRisks(doc) {
  const out = [];
  for (const s of statements(doc)) {
    if (low(s.Effect) !== "allow") continue;
    const actions = asArray(s.Action).map(str), res = s.Resource;
    if (s.NotAction != null && s.Action == null) { out.push({ kind: "not_action_allow", detail: "Allow with NotAction " + JSON.stringify(asArray(s.NotAction)).slice(0, 120) }); continue; }
    if (matchesAction(actions, /^\*$|^\*:\*$/) && starResource(res)) { out.push({ kind: "full_admin", detail: 'Action "*" on Resource "*"' }); continue; }
    if (matchesAction(actions, /^iam:\*$/i) && starResource(res)) out.push({ kind: "iam_star", detail: 'iam:* on Resource "*"' });
    if (matchesAction(actions, /^sts:(AssumeRole|\*)$/i) && starResource(res)) out.push({ kind: "assume_role_star", detail: 'sts:AssumeRole on Resource "*"' });
  }
  return out;
}

function accountOf(arn) { const m = /^arn:aws[a-z-]*:iam::(\d{12}|aws):/.exec(str(arn)); return m ? m[1] : null; }
function principalAccounts(aws) {
  return asArray(aws).map(str).map((p) => (/^\d{12}$/.test(p) ? p : accountOf(p))).filter(Boolean);
}
function hasExternalId(cond) {
  if (!cond || typeof cond !== "object") return false;
  return Object.values(cond).some((block) => block && typeof block === "object" && Object.keys(block).some((k) => low(k) === "sts:externalid"));
}

/** Trust-policy risks for a role: public trust, untrusted accounts, missing ExternalId. */
export function trustRisks(trust, ownAccount, trusted) {
  const out = [];
  for (const s of statements(trust)) {
    if (low(s.Effect) !== "allow") continue;
    const P = s.Principal;
    if (P === "*" || (P && typeof P === "object" && asArray(P.AWS).some((a) => str(a) === "*"))) {
      out.push({ kind: "public_trust", detail: s.Condition ? 'Principal "*" with a Condition' : 'Principal "*" without Condition', conditioned: !!s.Condition });
      continue;
    }
    if (!P || typeof P !== "object" || P.AWS == null) continue;
    const accounts = uniq(principalAccounts(P.AWS)).filter((a) => a !== ownAccount);
    for (const a of accounts) {
      if (!trusted.has(a)) out.push({ kind: "untrusted_account", detail: "trusts account " + a, account: a });
      if (!hasExternalId(s.Condition)) out.push({ kind: "no_external_id", detail: "cross-account trust to " + a + " without sts:ExternalId", account: a });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// analyze
// ---------------------------------------------------------------------------
const ADMIN_POLICY_ARN_RE = /^arn:aws[a-z-]*:iam::aws:policy\/AdministratorAccess$/;
const GCP_HIGH_ROLE_RE = /^roles\/(owner|editor|iam\..*|resourcemanager\..*|.*[aA]dmin)$/;
const GCP_SA_RISK_RE = /^roles\/(owner|editor|iam\.serviceAccountTokenCreator|iam\.serviceAccountUser|iam\.securityAdmin|.*[aA]dmin)$/;

function latestTimestamp(rows) {
  let max = null;
  const take = (v) => { const t = parseDate(v); if (t != null && (max == null || t > max)) max = t; };
  for (const r of rows) {
    for (const k of Object.keys(r)) {
      if (k[0] === "_") continue;
      const v = r[k];
      if (typeof v === "string" && /\d{4}/.test(v) && /date|time|used|rotated|login|created|start|end/i.test(k)) take(v);
    }
  }
  return max;
}

/**
 * Analyze normalised rows (from parseInput) or a parseInput result.
 * opts overrides DEFAULTS; opts.now (ISO) fixes the clock, else the newest
 * timestamp in the data is used. ctx.progress(i, n, label) is optional.
 */
export function analyze(dataset, opts = {}, ctx) {
  const o = { ...DEFAULTS, ...(opts || {}) };
  const rows = Array.isArray(dataset) ? dataset : dataset && Array.isArray(dataset.rows) ? dataset.rows : [];
  const inputSkipped = (!Array.isArray(dataset) && dataset && Array.isArray(dataset.skipped)) ? dataset.skipped.map((s) => ({ check: "input", reason: (s.file ? s.file + ": " : "") + s.reason })) : [];
  const n = rows.length;
  const prog = (i, label) => { if (ctx && typeof ctx.progress === "function" && (i % 1000 === 0 || i === n)) ctx.progress(i, n, label); };
  const findings = [], skipped = [...inputSkipped];
  const trusted = new Set(String(o.trustedAccounts == null ? "" : Array.isArray(o.trustedAccounts) ? o.trustedAccounts.join(",") : o.trustedAccounts).split(/[\s,;]+/).filter((x) => /^\d{12}$/.test(x)));

  const by = {};
  for (let i = 0; i < n; i++) { const r = rows[i]; (by[r._source] = by[r._source] || []).push(r); prog(i, "indexing"); }
  const has = (s) => Array.isArray(by[s]) && by[s].length > 0;
  const now = o.now ? parseDate(o.now) : latestTimestamp(rows);
  const nowIso = iso(now);

  // Principal inventory ----------------------------------------------------
  const principals = new Map();
  const P = (source, principal, patch = {}) => {
    const key = source + "|" + principal;
    let p = principals.get(key);
    if (!p) { p = { source, principal, name: principal, type: "User", roles: [], assignmentType: null, lastUsed: null, mfa: null, privileged: false, flags: [] }; principals.set(key, p); }
    if (patch.name) p.name = patch.name;
    if (patch.type) p.type = patch.type;
    if (patch.role) p.roles = uniq([...p.roles, patch.role]).sort();
    if (patch.assignmentType) p.assignmentType = p.assignmentType && p.assignmentType !== patch.assignmentType ? "Mixed" : patch.assignmentType;
    if (patch.lastUsed && (!p.lastUsed || patch.lastUsed > p.lastUsed)) p.lastUsed = patch.lastUsed;
    if (patch.mfa != null) p.mfa = p.mfa === false ? false : patch.mfa;
    if (patch.privileged) p.privileged = true;
    if (patch.flag) p.flags = uniq([...p.flags, patch.flag]).sort();
    return p;
  };
  const flag = (source, principal, f) => P(source, principal, { flag: f });
  const ident = (p) => ({ type: "IDENTITY", name: p.principal, data: { roles: p.roles, source: p.source, privileged: p.privileged, mfa: p.mfa } });

  const push = (f) => {
    const ev = f.evidence || [];
    findings.push({ ...f, evidence: ev.slice(0, 50), evidenceCount: ev.length, assets: (f.assets || []).slice(0, 200) });
  };
  const skip = (check, reason) => skipped.push({ check, reason });

  // ---------------------------------------------------------------- Entra --
  let entraStats = null;
  if (!has("entra")) {
    skip("entra_permanent_tier0", "no Entra role assignment input");
    skip("entra_global_admin_count", "no Entra role assignment input");
    skip("entra_standing_privileged", "no Entra role assignment input");
  } else {
    const E = by.entra;
    for (const r of E) P("entra", r.principal, { name: r.displayName, type: r.objectType, role: r.role, assignmentType: r.assignmentType, privileged: true });
    const ga = E.filter((r) => low(r.role) === "global administrator");
    const gaStanding = uniq(ga.filter((r) => r.assignmentType !== "Eligible").map((r) => r.principal));
    const gaAll = uniq(ga.map((r) => r.principal));
    const eligible = E.filter((r) => r.assignmentType === "Eligible").length;
    entraStats = { assignments: E.length, eligible, standing: E.length - eligible, jitRatio: E.length ? Math.round((eligible / E.length) * 1000) / 1000 : null, globalAdmins: gaAll.length, globalAdminsStanding: gaStanding.length };

    const permT0 = E.filter((r) => entraTier(r.role) === 0 && r.assignmentType === "Permanent");
    if (permT0.length) {
      const ps = uniq(permT0.map((r) => r.principal)).sort();
      ps.forEach((p) => flag("entra", p, "permanent-tier0"));
      push({
        id: "entra_permanent_tier0", title: "Permanent Global Administrator / Privileged Role Administrator assignments", severity: "high", confidence: "confirmed", category: "standing-privilege",
        description: ps.length + " principal(s) hold Global Administrator or Privileged Role Administrator as a permanent (non-PIM, non-expiring) assignment: " + ps.slice(0, 6).join(", ") + (ps.length > 6 ? ", ..." : "") + ".",
        recommendation: "Convert these to PIM-eligible assignments with activation approval and a maximum duration; keep at most two break-glass accounts as permanent and exclude them from Conditional Access only by design.",
        controls: [C.scuba_74, C.cisM365_113, C.nistAC6_1, C.nistAC6_5, C.isoA82],
        evidence: sortBy(permT0.map((r) => ({ principal: r.principal, displayName: r.displayName, role: r.role, assignmentType: r.assignmentType, scope: r.scope, startDate: r.startDate })), "principal", "role"),
        assets: ps.map((p) => ident(principals.get("entra|" + p))), tags: ["entra", "pim"],
      });
    }
    if (gaStanding.length > o.maxGlobalAdmins) {
      push({
        id: "entra_global_admin_count", title: "More than " + o.maxGlobalAdmins + " standing Global Administrators", severity: "medium", confidence: "confirmed", category: "role-sprawl",
        description: gaStanding.length + " distinct principals hold Global Administrator as a standing (permanent or active) assignment; CIS recommends fewer than five and SCuBA at most eight, and that most administrators use finer-grained roles.",
        recommendation: "Reduce standing Global Administrators to 2-4; move the others to scoped roles (Exchange, SharePoint, User Administrator) or to PIM-eligible assignments.",
        controls: [C.cisM365_113, C.scuba_71, C.scuba_72, C.nistAC6_1],
        evidence: gaStanding.sort().map((p) => ({ principal: p, assignmentType: ga.filter((r) => r.principal === p).map((r) => r.assignmentType).sort().join("/") })),
        assets: gaStanding.map((p) => ident(principals.get("entra|" + p))), tags: ["entra"],
      });
    }
    if (gaAll.length < o.minGlobalAdmins) {
      push({
        id: "entra_global_admin_lockout", title: "Fewer than " + o.minGlobalAdmins + " Global Administrators (lockout risk)", severity: gaAll.length === 0 ? "low" : "medium", confidence: gaAll.length === 0 ? "review" : "likely", category: "resilience",
        description: gaAll.length + " principal(s) hold Global Administrator in this export (eligible included). " + (gaAll.length === 0 ? "If the export is a per-role download for another role this is expected; otherwise the tenant cannot recover from loss of a single admin." : "A single administrator is a single point of failure for tenant recovery."),
        recommendation: "Provision a second, cloud-only emergency access account with a phishing-resistant method, stored offline and monitored for use.",
        controls: [C.cisM365_113, C.scuba_71, C.isoA82],
        evidence: gaAll.sort().map((p) => ({ principal: p })), assets: gaAll.map((p) => ident(principals.get("entra|" + p))), tags: ["entra"],
      });
    }
    const permT1 = E.filter((r) => entraTier(r.role) === 1 && r.assignmentType === "Permanent");
    if (permT1.length) {
      const ps = uniq(permT1.map((r) => r.principal)).sort();
      ps.forEach((p) => flag("entra", p, "permanent-admin"));
      push({
        id: "entra_standing_privileged", title: "Permanent assignments on privileged administrator roles", severity: "medium", confidence: "confirmed", category: "standing-privilege",
        description: permT1.length + " permanent assignment(s) across " + uniq(permT1.map((r) => r.role)).sort().join(", ") + " for " + ps.length + " principal(s). Standing privilege is what credential theft turns into tenant compromise.",
        recommendation: "Make these roles PIM-eligible with time-bound activation, MFA on activation and justification; review quarterly.",
        controls: [C.scuba_74, C.nistAC6_1, C.isoA82, C.soc2_63],
        evidence: sortBy(permT1.map((r) => ({ principal: r.principal, displayName: r.displayName, role: r.role, objectType: r.objectType, scope: r.scope })), "principal", "role"),
        assets: ps.map((p) => ident(principals.get("entra|" + p))), tags: ["entra", "pim"],
      });
    }
    const spAdmins = E.filter((r) => r.objectType === "ServicePrincipal" && entraTier(r.role) <= 1);
    if (spAdmins.length) {
      const ps = uniq(spAdmins.map((r) => r.principal)).sort();
      ps.forEach((p) => flag("entra", p, "sp-admin"));
      push({
        id: "entra_sp_admin", title: "Service principals holding administrator roles", severity: "medium", confidence: "likely", category: "non-human-privilege",
        description: ps.length + " service principal(s) hold directory administrator roles. Application credentials cannot use MFA or PIM activation and are a favoured persistence path.",
        recommendation: "Replace with least-privilege Graph application permissions; if a role is required, scope it to an administrative unit and rotate the credential to a certificate or managed identity.",
        controls: [C.nistAC6_1, C.mitreT1098_003, C.isoA82],
        evidence: sortBy(spAdmins.map((r) => ({ principal: r.principal, displayName: r.displayName, role: r.role, assignmentType: r.assignmentType })), "principal", "role"),
        assets: ps.map((p) => ident(principals.get("entra|" + p))), tags: ["entra"],
      });
    }
  }

  // --------------------------------------------------- AWS credential report --
  if (!has("aws-credential-report")) {
    for (const c of ["aws_root_mfa", "aws_root_used", "aws_root_keys", "aws_user_no_mfa", "aws_key_rotation", "aws_unused_credentials", "aws_two_keys"]) skip(c, "no AWS credential report input");
  } else {
    const R = by["aws-credential-report"];
    const root = R.find((r) => r.isRoot);
    const users = R.filter((r) => !r.isRoot);
    for (const r of R) {
      const lastUsed = [r.password_last_used, r.access_key_1_last_used_date, r.access_key_2_last_used_date].map(parseDate).filter((t) => t != null).sort((a, b) => b - a)[0];
      P("aws-credential-report", r.user, { name: r.user, type: r.isRoot ? "Root" : "IAM user", role: r.isRoot ? "root" : null, assignmentType: "Permanent", lastUsed: iso(lastUsed), mfa: parseBool(r.mfa_active), privileged: r.isRoot });
    }
    if (!root) skip("aws_root_mfa", "no <root_account> row in the credential report");
    else {
      const rootEv = [{ user: root.user, arn: root.arn, mfa_active: root.mfa_active, password_last_used: root.password_last_used, access_key_1_active: root.access_key_1_active, access_key_2_active: root.access_key_2_active }];
      if (parseBool(root.mfa_active) === false) {
        flag("aws-credential-report", root.user, "root-no-mfa");
        push({ id: "aws_root_mfa", title: "AWS root account has no MFA", severity: "critical", confidence: "confirmed", category: "authentication",
          description: "mfa_active is false for <root_account>. The root user bypasses every IAM policy; a phished or guessed password is full account takeover.",
          recommendation: "Enable a hardware MFA device on the root user today (CIS 1.6 prefers hardware), then stop using root for daily work.",
          controls: [C.cisAws_15, C.nistIA2_1, C.mitreT1078_004, C.soc2_61], evidence: rootEv, assets: [ident(principals.get("aws-credential-report|<root_account>"))], tags: ["aws", "root"] });
      }
      const rootPw = parseDate(root.password_last_used);
      if (rootPw != null && now != null && days(rootPw, now) <= o.rootUsedDays) {
        flag("aws-credential-report", root.user, "root-used");
        push({ id: "aws_root_used", title: "AWS root account used in the last " + o.rootUsedDays + " days", severity: "high", confidence: "confirmed", category: "privileged-use",
          description: "The root password was last used " + days(rootPw, now) + " day(s) before " + nowIso.slice(0, 10) + ". Root should be reserved for the handful of tasks that require it.",
          recommendation: "Identify who used root and why; create IAM Identity Center administrators for routine work and alert on every ConsoleLogin by root (CloudTrail).",
          controls: [C.cisAws_17, C.nistAC6_5, C.mitreT1078_004], evidence: rootEv, assets: [ident(principals.get("aws-credential-report|<root_account>"))], tags: ["aws", "root"] });
      } else if (rootPw != null && now == null) skip("aws_root_used", "no reference date available (pass opts.now)");
      if (parseBool(root.access_key_1_active) === true || parseBool(root.access_key_2_active) === true) {
        flag("aws-credential-report", root.user, "root-access-key");
        push({ id: "aws_root_keys", title: "AWS root account has active access keys", severity: "critical", confidence: "confirmed", category: "credentials",
          description: "Programmatic keys exist for <root_account>. Root keys cannot be restricted by policy and are a permanent full-account credential.",
          recommendation: "Delete the root access keys; use IAM roles for automation.",
          controls: [C.cisAws_14, C.nistAC6, C.mitreT1078_004], evidence: rootEv, assets: [ident(principals.get("aws-credential-report|<root_account>"))], tags: ["aws", "root"] });
      }
    }
    const noMfa = users.filter((r) => parseBool(r.password_enabled) === true && parseBool(r.mfa_active) === false);
    if (noMfa.length) {
      noMfa.forEach((r) => flag("aws-credential-report", r.user, "no-mfa"));
      push({ id: "aws_user_no_mfa", title: "IAM users with console password and no MFA", severity: "high", confidence: "confirmed", category: "authentication",
        description: noMfa.length + " IAM user(s) can sign in to the console with a password alone.",
        recommendation: "Require MFA for all console users (an IAM policy that denies everything except MFA setup until aws:MultiFactorAuthPresent is true), or move console access to IAM Identity Center.",
        controls: [C.cisAws_110, C.nistIA2_1, C.mitreT1110, C.soc2_61],
        evidence: sortBy(noMfa.map((r) => ({ user: r.user, arn: r.arn, password_enabled: r.password_enabled, mfa_active: r.mfa_active, password_last_used: r.password_last_used })), "user"),
        assets: noMfa.map((r) => ident(principals.get("aws-credential-report|" + r.user))), tags: ["aws"] });
    }
    if (now == null) { skip("aws_key_rotation", "no reference date available (pass opts.now)"); skip("aws_unused_credentials", "no reference date available (pass opts.now)"); }
    else {
      const stale = [], unused = [];
      for (const r of users) {
        for (const k of [1, 2]) {
          if (parseBool(r["access_key_" + k + "_active"]) !== true) continue;
          const rot = parseDate(r["access_key_" + k + "_last_rotated"]);
          if (rot != null && days(rot, now) > o.keyRotationDays) stale.push({ user: r.user, key: "access_key_" + k, last_rotated: r["access_key_" + k + "_last_rotated"], ageDays: days(rot, now) });
          const used = parseDate(r["access_key_" + k + "_last_used_date"]);
          const ref = used != null ? used : rot;
          if (ref != null && days(ref, now) >= o.unusedDays) unused.push({ user: r.user, credential: "access_key_" + k, last_used: r["access_key_" + k + "_last_used_date"] || "never", last_rotated: r["access_key_" + k + "_last_rotated"], idleDays: days(ref, now) });
        }
        if (parseBool(r.password_enabled) === true) {
          const used = parseDate(r.password_last_used);
          const ref = used != null ? used : parseDate(r.password_last_changed) || parseDate(r.user_creation_time);
          if (ref != null && days(ref, now) >= o.unusedDays) unused.push({ user: r.user, credential: "password", last_used: r.password_last_used || "never", last_rotated: r.password_last_changed, idleDays: days(ref, now) });
        }
      }
      if (stale.length) {
        stale.forEach((e) => flag("aws-credential-report", e.user, "key-not-rotated"));
        push({ id: "aws_key_rotation", title: "Access keys older than " + o.keyRotationDays + " days", severity: "medium", confidence: "confirmed", category: "credentials",
          description: stale.length + " active access key(s) have not been rotated within " + o.keyRotationDays + " days (oldest " + Math.max(...stale.map((e) => e.ageDays)) + " days).",
          recommendation: "Rotate the keys (create second key, cut over, deactivate, delete) and prefer short-lived role credentials for automation.",
          controls: [C.cisAws_114, C.nistIA5_1, C.isoA516], evidence: sortBy(stale, "user", "key"),
          assets: uniq(stale.map((e) => e.user)).map((u) => ident(principals.get("aws-credential-report|" + u))), tags: ["aws"] });
      }
      if (unused.length) {
        unused.forEach((e) => flag("aws-credential-report", e.user, "unused-credential"));
        push({ id: "aws_unused_credentials", title: "Credentials unused for " + o.unusedDays + " days or more", severity: "medium", confidence: "confirmed", category: "stale-access",
          description: unused.length + " enabled credential(s) (passwords or active access keys) have not been used for " + o.unusedDays + " days or more.",
          recommendation: "Deactivate the idle credentials; delete them after a grace period if nothing breaks.",
          controls: [C.cisAws_112, C.nistAC2_3, C.isoA518], evidence: sortBy(unused, "user", "credential"),
          assets: uniq(unused.map((e) => e.user)).map((u) => ident(principals.get("aws-credential-report|" + u))), tags: ["aws"] });
      }
    }
    const twoKeys = users.filter((r) => parseBool(r.access_key_1_active) === true && parseBool(r.access_key_2_active) === true);
    if (twoKeys.length) {
      twoKeys.forEach((r) => flag("aws-credential-report", r.user, "two-keys"));
      push({ id: "aws_two_keys", title: "IAM users with two active access keys", severity: "low", confidence: "confirmed", category: "credentials",
        description: twoKeys.length + " user(s) have both access keys active. Two live keys are expected only during a rotation window.",
        recommendation: "Deactivate the key that is not in use (compare last-used dates) and finish the rotation.",
        controls: [C.cisAws_113, C.nistIA5_1], evidence: sortBy(twoKeys.map((r) => ({ user: r.user, access_key_1_last_used_date: r.access_key_1_last_used_date, access_key_2_last_used_date: r.access_key_2_last_used_date })), "user"),
        assets: twoKeys.map((r) => ident(principals.get("aws-credential-report|" + r.user))), tags: ["aws"] });
    }
  }

  // ------------------------------------------------ AWS authorization details --
  if (!has("aws-auth-details")) {
    for (const c of ["aws_admin_access", "aws_wildcard_policy", "aws_role_trust", "aws_direct_user_policies"]) skip(c, "no AWS authorization details input");
  } else {
    const A = by["aws-auth-details"];
    const policies = new Map(A.filter((r) => r._kind === "policy").map((p) => [p.arn, p]));
    const groups = new Map(A.filter((r) => r._kind === "group").map((g) => [g.name, g]));
    const adminEv = [], wildEv = [], trustEv = [], directEv = [];
    const riskOfAttached = (att) => {
      const out = [];
      for (const a of att) {
        if (ADMIN_POLICY_ARN_RE.test(a.arn)) out.push({ via: a.name, kind: "full_admin", detail: "AdministratorAccess managed policy" });
        const p = policies.get(a.arn);
        if (p && !p.awsManaged) for (const r of policyRisks(p.doc)) out.push({ via: a.name, ...r });
      }
      return out;
    };
    const riskOfInline = (inl) => inl.flatMap((p) => policyRisks(p.doc).map((r) => ({ via: p.name + " (inline)", ...r })));
    const entities = A.filter((r) => r._kind === "user" || r._kind === "role" || r._kind === "group");
    for (const e of entities) {
      const risks = [...riskOfAttached(e.attached), ...riskOfInline(e.inlinePolicies)];
      if (e._kind === "user") for (const g of e.groups) { const G = groups.get(g); if (G) risks.push(...[...riskOfAttached(G.attached), ...riskOfInline(G.inlinePolicies)].map((r) => ({ ...r, via: r.via + " (group " + g + ")" }))); }
      const privileged = risks.length > 0;
      const roleLabel = e._kind === "role" ? "IAM role" : e._kind === "group" ? "IAM group" : "IAM user";
      P("aws-auth-details", e.name, { name: e.name, type: roleLabel, role: privileged ? (risks.some((r) => r.kind === "full_admin") ? "AdministratorAccess" : "broad-policy") : null, assignmentType: "Permanent", privileged, lastUsed: e.lastUsed || null });
      if (has("aws-credential-report") && e._kind === "user" && privileged) P("aws-credential-report", e.name, { privileged: true, role: risks.some((r) => r.kind === "full_admin") ? "AdministratorAccess" : "broad-policy" });
      for (const r of risks) {
        const row = { entity: e.name, kind: e._kind, arn: e.arn, via: r.via, risk: r.kind, detail: r.detail };
        if (r.kind === "full_admin") adminEv.push(row); else wildEv.push(row);
      }
      if (e._kind === "user" && (e.attached.length || e.inlinePolicies.length)) directEv.push({ user: e.name, attached: e.attached.map((a) => a.name).sort().join("; "), inline: e.inlinePolicies.map((p) => p.name).sort().join("; ") });
      if (e._kind === "role" && !/^\/aws-service-role\//.test(e.path)) {
        for (const t of trustRisks(e.trust, accountOf(e.arn), trusted)) trustEv.push({ role: e.name, arn: e.arn, risk: t.kind, detail: t.detail, account: t.account || null, conditioned: !!t.conditioned });
      }
    }
    if (adminEv.length) {
      const names = uniq(adminEv.map((r) => r.entity)).sort();
      names.forEach((p) => flag("aws-auth-details", p, "admin-access"));
      push({ id: "aws_admin_access", title: "Full administrative access (AdministratorAccess or *:* on *)", severity: "high", confidence: "confirmed", category: "over-broad-policy",
        description: names.length + " IAM identit(y/ies) have unrestricted administrative permissions through AdministratorAccess or a policy allowing every action on every resource: " + names.slice(0, 6).join(", ") + (names.length > 6 ? ", ..." : "") + ".",
        recommendation: "Replace with least-privilege policies or job-function roles; keep administrative access behind an assumable role with MFA and session limits.",
        controls: [C.cisAws_116, C.nistAC6_1, C.mitreT1078_004, C.soc2_63], evidence: sortBy(adminEv, "entity", "via"),
        assets: names.map((p) => ident(principals.get("aws-auth-details|" + p))), tags: ["aws", "iam"] });
    }
    if (wildEv.length) {
      const names = uniq(wildEv.map((r) => r.entity)).sort();
      names.forEach((p) => flag("aws-auth-details", p, "broad-policy"));
      push({ id: "aws_wildcard_policy", title: "Over-broad IAM policies (iam:*, sts:AssumeRole on *, NotAction allows)", severity: "high", confidence: "likely", category: "over-broad-policy",
        description: wildEv.length + " statement(s) grant privilege-escalation-capable permissions: iam:* or sts:AssumeRole on every resource, or Allow with NotAction (which permits everything not listed).",
        recommendation: "Scope iam:* and sts:AssumeRole to specific ARNs; rewrite NotAction allows as explicit Action lists; add permission boundaries to delegated administrators.",
        controls: [C.cisAws_116, C.mitreT1098_003, C.nistAC6, C.isoA82], evidence: sortBy(wildEv, "entity", "via", "risk"),
        assets: names.map((p) => ident(principals.get("aws-auth-details|" + p))), tags: ["aws", "iam"] });
    }
    if (trustEv.length) {
      const names = uniq(trustEv.map((r) => r.role)).sort();
      names.forEach((p) => flag("aws-auth-details", p, "trust-risk"));
      const pub = trustEv.filter((t) => t.risk === "public_trust" && !t.conditioned).length;
      push({ id: "aws_role_trust", title: pub ? "IAM roles assumable by any AWS principal or by unlisted accounts" : "IAM roles trusting accounts outside the trusted list", severity: pub ? "critical" : "medium", confidence: pub ? "confirmed" : "review", category: "cross-account-trust",
        description: trustEv.length + " trust-policy issue(s) across " + names.length + " role(s): " + uniq(trustEv.map((t) => t.risk)).sort().join(", ") + ". " + (trusted.size ? "Trusted accounts: " + [...trusted].sort().join(", ") + "." : "No trusted account list was given, so every foreign account is reported for review."),
        recommendation: "Restrict Principal to specific account ids or role ARNs, require sts:ExternalId for third-party trusts, and remove Principal \"*\" unless a tight Condition makes it an OIDC/SAML federation.",
        controls: [C.mitreT1078_004, C.nistAC3, C.nistAC6, C.isoA515], evidence: sortBy(trustEv, "role", "risk"),
        assets: names.map((p) => ident(principals.get("aws-auth-details|" + p))), tags: ["aws", "iam", "trust"] });
    }
    if (directEv.length) {
      push({ id: "aws_direct_user_policies", title: "IAM users with directly attached or inline policies", severity: "low", confidence: "confirmed", category: "hygiene",
        description: directEv.length + " user(s) receive permissions directly instead of through groups, which makes access reviews and offboarding error-prone.",
        recommendation: "Move permissions to groups (or to roles via IAM Identity Center) and detach the user-level policies.",
        controls: [C.cisAws_115, C.nistAC6, C.isoA518], evidence: sortBy(directEv, "user"),
        assets: directEv.map((d) => ident(principals.get("aws-auth-details|" + d.user))), tags: ["aws", "iam"] });
    }
  }

  // ------------------------------------------------------------------- GCP --
  if (!has("gcp-iam")) {
    for (const c of ["gcp_public_binding", "gcp_primitive_roles", "gcp_sa_privileged", "gcp_unconditional_high_roles"]) skip(c, "no GCP IAM policy input");
  } else {
    const G = by["gcp-iam"];
    for (const r of G) if (GCP_HIGH_ROLE_RE.test(r.role)) P("gcp-iam", r.member, { name: r.member, type: r.memberType, role: r.role + (r.project ? " @" + r.project : ""), assignmentType: r.condition ? "Conditional" : "Permanent", privileged: true });
    const pub = G.filter((r) => r.memberType === "allUsers" || r.memberType === "allAuthenticatedUsers");
    if (pub.length) {
      pub.forEach((r) => flag("gcp-iam", r.member, "public"));
      pub.forEach((r) => P("gcp-iam", r.member, { name: r.member, type: r.memberType, role: r.role + " @" + r.project, privileged: true }));
      push({ id: "gcp_public_binding", title: "GCP IAM binding grants access to allUsers / allAuthenticatedUsers", severity: "critical", confidence: "confirmed", category: "public-access",
        description: pub.length + " project-level binding(s) grant " + uniq(pub.map((r) => r.role)).sort().join(", ") + " to anonymous or any-Google-account principals.",
        recommendation: "Remove the public member from the binding; if a resource must be public, grant it on the specific resource (bucket, function) rather than at project level.",
        controls: [C.nistAC3, C.nistAC6, C.mitreT1078_004, C.isoA515], evidence: sortBy(pub.map((r) => ({ project: r.project, role: r.role, member: r.member, condition: r.condition })), "project", "role", "member"),
        assets: uniq(pub.map((r) => r.member)).map((m) => ident(principals.get("gcp-iam|" + m))), tags: ["gcp"] });
    }
    const prim = G.filter((r) => /^roles\/(owner|editor)$/.test(r.role) && (r.memberType === "user" || r.memberType === "group" || r.memberType === "domain"));
    if (prim.length) {
      prim.forEach((r) => flag("gcp-iam", r.member, "primitive-role"));
      push({ id: "gcp_primitive_roles", title: "Basic roles (owner / editor) granted to users or groups", severity: "high", confidence: "confirmed", category: "over-broad-policy",
        description: prim.length + " binding(s) give roles/owner or roles/editor to " + uniq(prim.map((r) => r.member)).length + " human principal(s). Basic roles span every service in the project.",
        recommendation: "Replace basic roles with predefined or custom roles scoped to the services used; keep roles/owner for break-glass only, ideally via a group with approval-gated membership.",
        controls: [C.nistAC6_1, C.isoA82, C.soc2_63, C.mitreT1078_004], evidence: sortBy(prim.map((r) => ({ project: r.project, role: r.role, member: r.member, condition: r.condition })), "project", "member", "role"),
        assets: uniq(prim.map((r) => r.member)).map((m) => ident(principals.get("gcp-iam|" + m))), tags: ["gcp"] });
    }
    const saRisk = G.filter((r) => r.memberType === "serviceAccount" && GCP_SA_RISK_RE.test(r.role));
    const saUserRoles = G.filter((r) => /^roles\/iam\.(serviceAccountUser|serviceAccountTokenCreator)$/.test(r.role) && (r.memberType === "user" || r.memberType === "group"));
    if (saRisk.length || saUserRoles.length) {
      const ev = [...saRisk, ...saUserRoles];
      ev.forEach((r) => flag("gcp-iam", r.member, "sa-privilege"));
      push({ id: "gcp_sa_privileged", title: "Service-account privilege: admin roles on service accounts or impersonation rights at project level", severity: "high", confidence: "confirmed", category: "non-human-privilege",
        description: saRisk.length + " service account(s) hold owner/editor/admin roles and " + saUserRoles.length + " human principal(s) hold Service Account User / Token Creator at project level, which lets them act as every service account in the project.",
        recommendation: "Give service accounts only the predefined roles their workload needs; grant Service Account User / Token Creator on individual service accounts rather than the project.",
        controls: [C.cisGcp_15, C.cisGcp_16, C.mitreT1098_003, C.nistAC6_1], evidence: sortBy(ev.map((r) => ({ project: r.project, role: r.role, member: r.member, memberType: r.memberType, condition: r.condition })), "project", "member", "role"),
        assets: uniq(ev.map((r) => r.member)).map((m) => ident(principals.get("gcp-iam|" + m))), tags: ["gcp"] });
    }
    const uncond = G.filter((r) => GCP_HIGH_ROLE_RE.test(r.role) && !r.condition && r.memberType !== "allUsers" && r.memberType !== "allAuthenticatedUsers");
    if (uncond.length) {
      push({ id: "gcp_unconditional_high_roles", title: "High-privilege GCP roles granted without an IAM condition", severity: "low", confidence: "review", category: "standing-privilege",
        description: uncond.length + " high-privilege binding(s) have no condition (no expiry, no resource restriction). Review whether these are standing grants that should be time-bound.",
        recommendation: "Add IAM Conditions (request.time expiry or resource name constraints) to privileged grants, or move them to just-in-time access via Privileged Access Manager.",
        controls: [C.nistAC6_1, C.isoA82], evidence: sortBy(uncond.map((r) => ({ project: r.project, role: r.role, member: r.member })), "project", "role", "member"),
        assets: uniq(uncond.map((r) => r.member)).map((m) => ident(principals.get("gcp-iam|" + m))), tags: ["gcp"] });
    }
  }

  // ------------------------------------------------------------------ Okta --
  if (!has("okta-admins")) {
    for (const c of ["okta_super_admin_count", "okta_inactive_admins"]) skip(c, "no Okta administrators input");
  } else {
    const K = by["okta-admins"];
    for (const r of K) P("okta-admins", r.login, { name: r.name, type: "User", role: r.role || "ADMIN", assignmentType: "Permanent", lastUsed: r.lastLogin, privileged: true });
    const supers = uniq(K.filter((r) => r.role === "SUPER_ADMIN").map((r) => r.login)).sort();
    if (supers.length > o.maxSuperAdmins) {
      supers.forEach((p) => flag("okta-admins", p, "super-admin"));
      push({ id: "okta_super_admin_count", title: "More than " + o.maxSuperAdmins + " Okta Super Administrators", severity: "medium", confidence: "confirmed", category: "role-sprawl",
        description: supers.length + " users hold SUPER_ADMIN, which can change every policy, app and admin in the org.",
        recommendation: "Reduce Super Administrators to the minimum; delegate with ORG_ADMIN, APP_ADMIN, HELP_DESK_ADMIN or custom admin roles scoped to resource sets.",
        controls: [C.nistAC6_1, C.nistAC6_5, C.isoA82, C.soc2_63], evidence: supers.map((p) => ({ login: p })),
        assets: supers.map((p) => ident(principals.get("okta-admins|" + p))), tags: ["okta"] });
    }
    const inactive = K.filter((r) => r.status && r.status !== "ACTIVE");
    if (inactive.length) {
      inactive.forEach((r) => flag("okta-admins", r.login, "not-active"));
      const deprov = inactive.filter((r) => /DEPROVISIONED|SUSPENDED|LOCKED_OUT/.test(r.status)).length;
      push({ id: "okta_inactive_admins", title: "Okta administrator roles held by non-active users", severity: deprov ? "high" : "medium", confidence: "confirmed", category: "stale-access",
        description: inactive.length + " admin role assignment(s) belong to users whose status is " + uniq(inactive.map((r) => r.status)).sort().join(", ") + ". Roles on deprovisioned or suspended users are reactivated with the user.",
        recommendation: "Remove admin roles from any user that is not ACTIVE; add role removal to the offboarding workflow.",
        controls: [C.nistAC2_3, C.isoA518, C.soc2_62], evidence: sortBy(inactive.map((r) => ({ login: r.login, name: r.name, role: r.role, status: r.status, lastLogin: r.lastLogin })), "login", "role"),
        assets: uniq(inactive.map((r) => r.login)).map((p) => ident(principals.get("okta-admins|" + p))), tags: ["okta"] });
    }
  }

  // ---------------------------------------------------------------- GitHub --
  if (!has("github-members")) {
    for (const c of ["github_owner_count", "github_no_2fa"]) skip(c, "no GitHub organization members input");
  } else {
    const H = by["github-members"];
    const owners = uniq(H.filter((r) => r.role === "owner").map((r) => r.login)).sort();
    for (const r of H) if (r.role === "owner") P("github-members", r.login, { name: r.name, type: "User", role: "owner", assignmentType: "Permanent", mfa: r.twoFactor, privileged: true });
    if (H.every((r) => r.role == null)) skip("github_owner_count", "GitHub input has no role column (use the people CSV export or a role-aware query)");
    else if (owners.length > o.maxOrgOwners) {
      owners.forEach((p) => flag("github-members", p, "owner"));
      push({ id: "github_owner_count", title: "More than " + o.maxOrgOwners + " GitHub organization owners", severity: "medium", confidence: "confirmed", category: "role-sprawl",
        description: owners.length + " members are organization owners. Owners can change billing, security settings, delete repositories and remove other owners.",
        recommendation: "Keep owners to 2-3; grant repository or team maintainer roles instead, and use a security-manager team for policy visibility.",
        controls: [C.cisSsc_133, C.nistAC6_1, C.isoA82], evidence: owners.map((p) => ({ login: p })),
        assets: owners.map((p) => ident(principals.get("github-members|" + p))), tags: ["github"] });
    }
    if (H.every((r) => r.twoFactor == null)) skip("github_no_2fa", "GitHub input has no two-factor column");
    else {
      const no2fa = H.filter((r) => r.twoFactor === false);
      if (no2fa.length) {
        const ownersNo = no2fa.filter((r) => r.role === "owner");
        no2fa.forEach((r) => { if (r.role === "owner") flag("github-members", r.login, "no-2fa"); });
        push({ id: "github_no_2fa", title: "GitHub members without two-factor authentication", severity: ownersNo.length ? "high" : "medium", confidence: "confirmed", category: "authentication",
          description: no2fa.length + " member(s) have 2FA disabled" + (ownersNo.length ? ", including " + ownersNo.length + " organization owner(s)" : "") + ". Source code and CI secrets are one password away.",
          recommendation: "Enforce 2FA at the organization level (Settings > Authentication security); members without it are removed and must re-enrol.",
          controls: [C.cisSsc_137, C.nistIA2_1, C.mitreT1078_004, C.soc2_61], evidence: sortBy(no2fa.map((r) => ({ login: r.login, name: r.name, role: r.role, twoFactor: r.twoFactor, saml: r.saml })), "login"),
          assets: ownersNo.map((r) => ident(principals.get("github-members|" + r.login))), tags: ["github"] });
      }
    }
  }

  // --------------------------------------------------- Cross-source checks --
  const all = Array.from(principals.values());
  const withLast = all.filter((p) => p.privileged && p.lastUsed);
  if (!withLast.length) skip("stale_admins", "no input provides a last sign-in / last-used field for privileged principals (Okta Last login, AWS credential report with authorization details)");
  else if (now == null) skip("stale_admins", "no reference date available (pass opts.now)");
  else {
    const stale = withLast.filter((p) => days(parseDate(p.lastUsed), now) > o.staleDays);
    if (stale.length) {
      stale.forEach((p) => flag(p.source, p.principal, "stale"));
      push({ id: "stale_admins", title: "Privileged principals inactive for more than " + o.staleDays + " days", severity: "medium", confidence: "likely", category: "stale-access",
        description: stale.length + " privileged principal(s) have not signed in or used a credential within " + o.staleDays + " days of " + nowIso.slice(0, 10) + ".",
        recommendation: "Confirm the account is still needed; remove the privileged role or disable the account, and require re-approval to restore it.",
        controls: [C.nistAC2_3, C.isoA518, C.cisM365_111, C.soc2_62],
        evidence: sortBy(stale.map((p) => ({ source: p.source, principal: p.principal, roles: p.roles.join("; "), lastUsed: p.lastUsed, idleDays: days(parseDate(p.lastUsed), now) })), "source", "principal"),
        assets: stale.map(ident), tags: ["stale"] });
    }
  }
  const shared = all.filter((p) => p.privileged && looksShared(p.principal));
  if (shared.length) {
    shared.forEach((p) => flag(p.source, p.principal, "shared-name"));
    push({ id: "shared_admin_accounts", title: "Privileged accounts with shared or generic names", severity: "medium", confidence: "review", category: "accountability",
      description: shared.length + " privileged principal(s) are named like shared, generic or service accounts (" + shared.map((p) => p.principal).sort().slice(0, 5).join(", ") + (shared.length > 5 ? ", ..." : "") + "). Shared credentials defeat attribution and MFA.",
      recommendation: "Confirm each is a single-person or documented break-glass account; replace shared logins with named administrator accounts and vaulted, checked-out break-glass credentials.",
      controls: [C.nistAC2_9, C.isoA516, C.nistIA2_1, C.soc2_61],
      evidence: sortBy(shared.map((p) => ({ source: p.source, principal: p.principal, roles: p.roles.join("; ") })), "source", "principal"),
      assets: shared.map(ident), tags: ["shared"] });
  }

  // -------------------------------------------------------------- Results --
  findings.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || cmp(a.title, b.title));
  const principalRows = sortBy(all.map((p) => ({ source: p.source, principal: p.principal, name: p.name, type: p.type, roles: p.roles, assignmentType: p.assignmentType, lastUsed: p.lastUsed, mfa: p.mfa, privileged: p.privileged, flags: p.flags })), "source", "principal");
  skipped.sort((a, b) => cmp(a.check, b.check) || cmp(a.reason, b.reason));
  const privileged = principalRows.filter((p) => p.privileged);
  const sources = Object.keys(by).sort();
  const summary = {
    rows: n, sources, findings: findings.length, bySeverity: countBy(findings, "severity"), byConfidence: countBy(findings, "confidence"),
    principals: principalRows.length, privileged: privileged.length, flagged: privileged.filter((p) => p.flags.length).length,
    noMfa: privileged.filter((p) => p.mfa === false).length,
    standing: entraStats ? entraStats.standing : null, eligible: entraStats ? entraStats.eligible : null, jitRatio: entraStats ? entraStats.jitRatio : null,
    globalAdmins: entraStats ? entraStats.globalAdmins : null, now: nowIso,
  };
  prog(n, "done");
  return { summary, findings, tables: { principals: principalRows }, skipped, meta: { tool: TOOL_ID, version: VERSION, rows: n, sources, now: nowIso, thresholds: { ...o, trustedAccounts: [...trusted].sort().join(",") } } };
}

function countBy(items, key) {
  const out = {};
  for (const it of items) out[it[key]] = (out[it[key]] || 0) + 1;
  return Object.fromEntries(Object.keys(out).sort().map((k) => [k, out[k]]));
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
const q = (v) => '"' + String(v == null ? "" : v).replace(/"/g, '""') + '"';
const FINDING_COLS = ["severity", "confidence", "category", "title", "description", "recommendation", "controls", "evidenceCount", "assets"];

/** Findings as CSV with fixed columns. */
export function findingsToCsv(findings) {
  const body = (findings || []).map((f) => [
    f.severity, f.confidence, f.category, f.title, f.description, f.recommendation,
    (f.controls || []).map((c) => c.framework + " " + c.id).join("; "),
    f.evidenceCount != null ? f.evidenceCount : (f.evidence || []).length,
    (f.assets || []).map((a) => a.name).join("; "),
  ].map(q).join(","));
  return [FINDING_COLS.join(","), ...body].join("\n");
}

const PRINCIPAL_COLS = ["source", "principal", "name", "type", "roles", "assignmentType", "lastUsed", "mfa", "privileged", "flags"];

/** Privileged principal inventory as CSV. */
export function principalsToCsv(principals) {
  const body = (principals || []).map((p) => PRINCIPAL_COLS.map((k) => Array.isArray(p[k]) ? p[k].join("; ") : p[k] === null ? "" : p[k]).map(q).join(","));
  return [PRINCIPAL_COLS.join(","), ...body].join("\n");
}

/**
 * Attestation text for the review packet. `meta.date` must be supplied by the
 * caller (the UI uses new Date()); the engine never reads a clock.
 */
export function attestationText(result, meta = {}) {
  const s = result.summary, t = result.meta.thresholds || {};
  const bySev = (k) => s.bySeverity[k] || 0;
  const lines = [
    "PRIVILEGED ACCESS REVIEW ATTESTATION",
    "",
    "Reviewer: " + (meta.reviewer || "(not provided)"),
    "Review date: " + (meta.date || "(not provided)"),
    "Scope: " + (meta.scope || (result.meta.sources.map((x) => SOURCES[x] || x).join("; ") || "no recognised input")),
    "Dataset: " + (meta.dataset || "(not named)") + "; reference date for age calculations: " + (result.meta.now || "none"),
    "Parameters: stale after " + t.staleDays + " days; Global Administrators " + t.minGlobalAdmins + "-" + t.maxGlobalAdmins + "; root use window " + t.rootUsedDays + " days; key rotation " + t.keyRotationDays + " days; unused credentials " + t.unusedDays + " days; Okta super admins <= " + t.maxSuperAdmins + "; GitHub owners <= " + t.maxOrgOwners + "; trusted AWS accounts: " + (t.trustedAccounts || "none"),
    "",
    "POPULATION",
    "Principals inventoried: " + s.principals + " (" + s.privileged + " privileged, " + s.flagged + " with at least one flag, " + s.noMfa + " privileged without MFA where known)",
    s.jitRatio != null ? "Entra assignments: " + (s.standing + s.eligible) + " (" + s.eligible + " PIM-eligible, " + s.standing + " standing; JIT ratio " + Math.round(s.jitRatio * 100) + "%); Global Administrators: " + s.globalAdmins : "Entra assignments: not provided",
    "",
    "FINDINGS",
    "Critical " + bySev("critical") + ", High " + bySev("high") + ", Medium " + bySev("medium") + ", Low " + bySev("low") + ", Info " + bySev("info"),
    ...result.findings.map((f) => "- [" + f.severity + "/" + f.confidence + "] " + f.title + " (" + f.evidenceCount + " evidence row(s); " + f.controls.map((c) => c.framework + " " + c.id).join(", ") + ")"),
    "",
    "CHECKS NOT RUN",
    ...(result.skipped.length ? result.skipped.map((k) => "- " + k.check + ": " + k.reason) : ["- none"]),
    "",
    meta.reviewer
      ? "I confirm that I reviewed the privileged principal inventory and the findings above, and that the exported CSV/JSON files are the complete output of this review."
      : "Reviewer name not recorded; this attestation is a draft.",
    "",
    "Method: deterministic rules over the exports named above, run in the reviewer's browser; no data left the machine. Controls referenced: CIS Microsoft 365 Foundations Benchmark; CISA SCuBA MS.AAD; CIS AWS Foundations Benchmark; CIS Google Cloud Platform Foundation Benchmark; CIS Software Supply Chain Security Guide; NIST SP 800-53 Rev. 5; ISO/IEC 27001:2022 Annex A; MITRE ATT&CK.",
  ];
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Synthetic example (format-faithful, clearly labelled, never real data)
// ---------------------------------------------------------------------------
const EX_DOMAIN = "test.darknode.ai";

/** Seeded synthetic exports: Entra assignments CSV, AWS credential report, GCP IAM policy. */
export function exampleDataset(seed = 7) {
  let s = (seed >>> 0) || 1;
  const rnd = () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 4294967296; };
  const guid = () => { const h = () => Math.floor(rnd() * 0x10000).toString(16).padStart(4, "0"); return h() + h() + "-" + h() + "-" + h() + "-" + h() + "-" + h() + h() + h(); };
  const people = ["user01", "user02", "user03", "user04", "admin", "user05", "user06", "user07"];
  const entraRows = [
    ["Global Administrator", "User 01", people[0] + "@" + EX_DOMAIN, guid(), "User", "Permanent", "Directory", "1/12/2025 09:14:00", ""],
    ["Global Administrator", "User 02", people[1] + "@" + EX_DOMAIN, guid(), "User", "Permanent", "Directory", "3/02/2025 14:30:00", ""],
    ["Global Administrator", "User 03", people[2] + "@" + EX_DOMAIN, guid(), "User", "Permanent", "Directory", "5/20/2025 11:02:00", ""],
    ["Global Administrator", "User 04", people[3] + "@" + EX_DOMAIN, guid(), "User", "Permanent", "Directory", "6/01/2025 08:45:00", ""],
    ["Global Administrator", "Admin (shared)", people[4] + "@" + EX_DOMAIN, guid(), "User", "Permanent", "Directory", "11/15/2024 16:20:00", ""],
    ["Global Administrator", "User 05", people[5] + "@" + EX_DOMAIN, guid(), "User", "Eligible", "Directory", "7/10/2025 10:00:00", "7/10/2026 10:00:00"],
    ["Exchange Administrator", "User 06", people[6] + "@" + EX_DOMAIN, guid(), "User", "Permanent", "Directory", "2/14/2025 13:05:00", ""],
    ["Security Administrator", "User 07", people[7] + "@" + EX_DOMAIN, guid(), "User", "Active", "Directory", "9/28/2026 09:00:00", "9/28/2026 17:00:00"],
  ];
  const entraCsv = ["Role,Display name,User principal name,Object ID,Object type,Assignment type,Scope,Start date,End date", ...entraRows.map((r) => r.map((v) => (/[,"]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v)).join(","))].join("\n");

  const acct = "123456789012";
  const credRows = [
    ["<root_account>", "arn:aws:iam::" + acct + ":root", "2021-03-04T10:11:12+00:00", "not_supported", "2026-09-20T08:02:44+00:00", "not_supported", "not_supported", "false", "false", "N/A", "N/A", "N/A", "N/A", "false", "N/A", "N/A", "N/A", "N/A", "false", "N/A", "false", "N/A"],
    ["ops-admin", "arn:aws:iam::" + acct + ":user/ops-admin", "2024-01-15T09:00:00+00:00", "true", "2026-09-29T07:40:11+00:00", "2026-07-01T10:00:00+00:00", "2026-09-29T10:00:00+00:00", "true", "true", "2025-08-27T12:00:00+00:00", "2026-09-30T06:15:00+00:00", "us-east-1", "sts", "false", "N/A", "N/A", "N/A", "N/A", "false", "N/A", "false", "N/A"],
    ["deploy-bot", "arn:aws:iam::" + acct + ":user/deploy-bot", "2023-06-10T12:00:00+00:00", "false", "N/A", "N/A", "N/A", "false", "true", "2026-09-01T00:00:00+00:00", "2026-09-30T23:10:00+00:00", "eu-west-1", "ecr", "true", "2026-08-01T00:00:00+00:00", "2026-09-30T23:11:00+00:00", "eu-west-1", "ecr", "false", "N/A", "false", "N/A"],
    ["user08", "arn:aws:iam::" + acct + ":user/user08", "2025-02-01T08:30:00+00:00", "true", "2026-09-25T15:22:09+00:00", "2026-08-15T09:00:00+00:00", "2026-11-13T09:00:00+00:00", "false", "false", "N/A", "N/A", "N/A", "N/A", "false", "N/A", "N/A", "N/A", "N/A", "false", "N/A", "false", "N/A"],
    ["legacy-svc", "arn:aws:iam::" + acct + ":user/legacy-svc", "2022-11-20T10:00:00+00:00", "false", "N/A", "N/A", "N/A", "false", "true", "2026-08-20T00:00:00+00:00", "2025-12-02T04:00:00+00:00", "us-east-1", "s3", "false", "N/A", "N/A", "N/A", "N/A", "false", "N/A", "false", "N/A"],
    ["analyst", "arn:aws:iam::" + acct + ":user/analyst", "2025-09-01T08:00:00+00:00", "true", "2026-10-01T09:12:00+00:00", "2026-09-10T09:00:00+00:00", "2026-12-09T09:00:00+00:00", "true", "false", "N/A", "N/A", "N/A", "N/A", "false", "N/A", "N/A", "N/A", "N/A", "false", "N/A", "false", "N/A"],
  ];
  const credCsv = [AWS_CRED_HEADERS.join(","), ...credRows.map((r) => r.join(","))].join("\n");

  const gcp = {
    bindings: [
      { role: "roles/owner", members: ["user:" + people[2] + "@" + EX_DOMAIN] },
      { role: "roles/editor", members: ["serviceAccount:ci-runner@synthetic-proj.iam.gserviceaccount.com"] },
      { role: "roles/viewer", members: ["allUsers", "group:analysts@" + EX_DOMAIN] },
      { role: "roles/iam.serviceAccountTokenCreator", members: ["user:" + people[3] + "@" + EX_DOMAIN] },
    ],
    etag: "BwY" + Math.floor(rnd() * 1e9).toString(36),
    version: 1,
  };
  const files = [
    { name: "entra-role-assignments.csv", text: entraCsv },
    { name: "aws-credential-report.csv", text: credCsv },
    { name: "gcp-synthetic-proj-iam-policy.json", text: JSON.stringify(gcp, null, 2) },
  ];
  const parsed = parseInput(files);
  return { label: "synthetic example (not real data)", files, rows: parsed.rows, parsed };
}

/** Real deterministic checks of the engine over the synthetic example. */
export function selfTest() {
  const tests = [];
  const ex = exampleDataset();
  const r = analyze(ex.parsed, { now: "2026-10-01T12:00:00Z" });
  const byId = Object.fromEntries(r.findings.map((f) => [f.id, f]));
  tests.push({ name: "three sources detected", pass: r.meta.sources.join(",") === "aws-credential-report,entra,gcp-iam" });
  tests.push({ name: "permanent GA finding lists five principals", pass: !!byId.entra_permanent_tier0 && byId.entra_permanent_tier0.evidenceCount === 5 });
  tests.push({ name: "more than four standing global admins", pass: !!byId.entra_global_admin_count });
  tests.push({ name: "root without MFA is critical", pass: !!byId.aws_root_mfa && byId.aws_root_mfa.severity === "critical" });
  tests.push({ name: "400-day-old key is flagged", pass: !!byId.aws_key_rotation && byId.aws_key_rotation.evidence.some((e) => e.user === "ops-admin" && e.ageDays >= 400) });
  tests.push({ name: "allUsers binding is critical", pass: !!byId.gcp_public_binding && byId.gcp_public_binding.severity === "critical" });
  tests.push({ name: "shared admin name is review confidence", pass: !!byId.shared_admin_accounts && byId.shared_admin_accounts.confidence === "review" });
  tests.push({ name: "JIT ratio is 1 eligible of 8", pass: r.summary.eligible === 1 && r.summary.jitRatio === 0.125 });
  tests.push({ name: "missing sources are reported, not guessed", pass: r.skipped.some((s) => s.check === "okta_super_admin_count") && r.skipped.some((s) => s.check === "github_owner_count") });
  tests.push({ name: "deterministic", pass: JSON.stringify(analyze(ex.parsed, { now: "2026-10-01T12:00:00Z" })) === JSON.stringify(r) });
  tests.push({ name: "empty input yields no findings", pass: analyze([]).findings.length === 0 });
  return { pass: tests.every((t) => t.pass), tests };
}
