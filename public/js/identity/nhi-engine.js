// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Non-Human Identity Lifecycle engine (nhi). Pure: no DOM, no network, no clock
// (the reference time is opts.now or the latest timestamp in the data). Runs in a
// Blob module Worker and in node tests.
//
// Inventories every machine credential found in the exports it is given:
//   aws     IAM credential report CSV (access keys, signing certs, root keys)
//   entra   Graph /applications JSON, Get-MgApplication JSON, portal "App registrations"
//           CSV, /servicePrincipals JSON (client secrets, certificates, app roles, owners)
//   gcp     gcloud iam service-accounts keys list / service-accounts list JSON
//   okta    API tokens CSV export and GET /api/v1/api-tokens JSON
//   k8s     kubectl get serviceaccounts / secrets / clusterrolebindings -o json
//   github  gh api orgs/{org}/installations JSON and deploy keys JSON
//   generic any CSV/JSON with principal / credential / created / last used / expires columns
//
// Every credential is scored by age, last use, expiry, ownership and scope, and the
// engine emits a rotation calendar (expires / rotate by / review). Nothing is
// inferred from outside the inputs. Control references used in findings:
//   NIST SP 800-57 Part 1 Rev. 5 s5.3 (cryptoperiods)
//   NIST SP 800-53 Rev. 5 IA-5(1), AC-2, AC-2(3), AC-6
//   CIS AWS Foundations Benchmark 1.4 (root access keys), 1.12 (unused credentials),
//     1.13 (one active access key), 1.14 (rotate access keys <= 90 days)
//   CIS Google Cloud Foundations Benchmark 1.4 (no user-managed SA keys), 1.7 (rotate SA keys <= 90 days)
//   CIS Kubernetes Benchmark 5.1.1 (cluster-admin), 5.1.5 (default SA), 5.1.6 (token automount)
//   CA/Browser Forum Baseline Requirements 6.3.2 (certificate validity <= 398 days)
//   ISO/IEC 27001:2022 A.5.16 (identity management), A.5.17 (authentication information), A.8.2 (privileged access)
//   SOC 2 CC6.1 / CC6.3
//   MITRE ATT&CK T1078.004, T1098.001, T1528, T1552.001, T1552.004

import { sniff, parseCsv, findColumn, normHeader } from "../ingest/parse.js";

export const TOOL_ID = "nhi";
export const VERSION = "1.0.0";

const DAY = 86400000;
const NEVER_MS = Date.UTC(9999, 0, 1);

/** Logical columns for the generic CSV/JSON fallback: key -> accepted header names. */
export const COLUMNS = {
  principal: ["principal", "user", "username", "user name", "service account", "serviceaccount", "account", "application", "app", "identity", "name"],
  credential: ["credential", "credential id", "key id", "keyid", "access key id", "token id", "secret id", "client secret id", "id"],
  kind: ["kind", "credential type", "type", "credential kind"],
  created: ["created", "created on", "created at", "creation date", "create date", "start", "start date", "valid from", "last rotated", "issued"],
  lastUsed: ["last used", "last used date", "lastused", "last activity", "last access", "last accessed", "last sign in"],
  expires: ["expires", "expiry", "expiration", "expires at", "expiration date", "end", "end date", "valid to", "valid until"],
  owner: ["owner", "created by", "owner email", "team", "responsible", "contact"],
  source: ["source", "provider", "platform", "cloud", "system"],
  status: ["status", "active", "state", "enabled"],
};

/** Tunable thresholds; the UI renders these as the settings panel. */
export const DEFAULTS = {
  maxKeyAgeDays: 90,            // active secret older than this is overdue for rotation
  unusedDays: 90,               // no use for this long (or never used after this age) is stale
  expiryWarnDays: [30, 60, 90], // expiry windows -> high / medium / low
  maxCertDays: 397,             // certificate validity longer than this is flagged
};

export const SOURCES = ["aws", "entra", "gcp", "okta", "k8s", "github", "generic"];
export const STATUSES = ["expired", "expiring", "overdue", "never-used", "unused", "ok", "managed", "inactive", "unknown"];
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const AWS_HEADERS = "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated".split(",");
const SERVICE_NAME_RE = /^(svc|sa|service|app|ci|deploy|jenkins|github|terraform|bot)[-_.]/i;

const GRAPH_APP = "00000003-0000-0000-c000-000000000000";
const EXO_APP = "00000002-0000-0ff1-ce00-000000000000";
/** Application (Role-type) permission ids whose grant to a daemon app is high risk. */
export const HIGH_RISK_APP_ROLES = {
  "19dbc75e-c2e2-444c-a770-ec69d8559fc7": "Directory.ReadWrite.All",
  "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
  "06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
  "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
  "741f803b-c850-494e-b5df-cde7c675a1ca": "User.ReadWrite.All",
  "62a82d76-70ea-41e2-9197-370581804d09": "Group.ReadWrite.All",
  "e2a3a72e-5f79-4c64-b1b1-878b674786c9": "Mail.ReadWrite",
  "810c84a8-4a9e-49e6-bf7d-12d183f40d01": "Mail.Read",
  "b633e1c5-b582-4048-a93e-9f11b44c7e96": "Mail.Send",
  "75359482-048d-4bc3-8d64-9b1b5b2e7f7b": "Files.ReadWrite.All",
  "a82116e5-55eb-4c33-a434-cff2e21e6ad8": "Sites.FullControl.All",
  "dc50a0fb-09a3-484d-be87-e023b12c6440": "Exchange.ManageAsApp",
};
const HIGH_RISK_VALUES = new Set(Object.values(HIGH_RISK_APP_ROLES).map((v) => v.toLowerCase()));

const C = {
  crypto: { framework: "NIST SP 800-57", id: "Part 1 s5.3" },
  ia5: { framework: "NIST-800-53", id: "IA-5(1)" },
  ac2: { framework: "NIST-800-53", id: "AC-2" },
  ac23: { framework: "NIST-800-53", id: "AC-2(3)" },
  ac6: { framework: "NIST-800-53", id: "AC-6" },
  cisAws14: { framework: "CIS AWS Foundations", id: "1.4" },
  cisAws112: { framework: "CIS AWS Foundations", id: "1.12" },
  cisAws113: { framework: "CIS AWS Foundations", id: "1.13" },
  cisAws114: { framework: "CIS AWS Foundations", id: "1.14" },
  cisGcp14: { framework: "CIS GCP Foundations", id: "1.4" },
  cisGcp17: { framework: "CIS GCP Foundations", id: "1.7" },
  cisK8s511: { framework: "CIS Kubernetes", id: "5.1.1" },
  cisK8s515: { framework: "CIS Kubernetes", id: "5.1.5" },
  cisK8s516: { framework: "CIS Kubernetes", id: "5.1.6" },
  cabf: { framework: "CA/Browser Forum BR", id: "6.3.2" },
  iso516: { framework: "ISO27001", id: "A.5.16" },
  iso517: { framework: "ISO27001", id: "A.5.17" },
  iso82: { framework: "ISO27001", id: "A.8.2" },
  soc61: { framework: "SOC2", id: "CC6.1" },
  soc63: { framework: "SOC2", id: "CC6.3" },
  t1078: { framework: "MITRE", id: "T1078.004" },
  t1098: { framework: "MITRE", id: "T1098.001" },
  t1528: { framework: "MITRE", id: "T1528" },
  t1552: { framework: "MITRE", id: "T1552.001" },
  t1552k: { framework: "MITRE", id: "T1552.004" },
};

// ---------------------------------------------------------------------------
// Time helpers
// ---------------------------------------------------------------------------

const NULLISH = /^(|n\/a|na|no_information|not_supported|never|none|null|undefined|-|false|0001-01-01t00:00:00z?)$/i;

/** Parse a vendor timestamp to epoch ms, or null. ISO 8601, AWS "+00:00", Entra portal M/D/YYYY, "YYYY-MM-DD HH:MM UTC", PowerShell /Date(ms)/. */
export function toTime(v) {
  if (v == null) return null;
  if (typeof v === "number") return Number.isFinite(v) ? (v < 1e11 ? v * 1000 : v) : null;
  const s = String(v).trim();
  if (NULLISH.test(s)) return null;
  let m;
  if ((m = /^\/Date\((-?\d+)(?:[+-]\d{4})?\)\/$/.exec(s))) return Number(m[1]);
  if ((m = /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?)?\s*(Z|UTC|GMT|[+-]\d{2}:?\d{2})?$/i.exec(s))) {
    let t = Date.UTC(+m[1], +m[2] - 1, +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0));
    const tz = m[7];
    if (tz && /^[+-]/.test(tz)) { const sign = tz[0] === "-" ? -1 : 1; const hh = +tz.slice(1, 3), mm = +tz.slice(-2); t -= sign * (hh * 60 + mm) * 60000; }
    return Number.isFinite(t) ? t : null;
  }
  if ((m = /^(\d{1,2})\/(\d{1,2})\/(\d{4})(?:,?\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM)?)?$/i.exec(s))) {
    let h = +(m[4] || 0); const ap = (m[7] || "").toUpperCase();
    if (ap === "PM" && h < 12) h += 12; if (ap === "AM" && h === 12) h = 0;
    return Date.UTC(+m[3], +m[1] - 1, +m[2], h, +(m[5] || 0), +(m[6] || 0));
  }
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : t;
}

const iso = (ms) => (ms == null ? null : new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z"));
const isoDay = (ms) => new Date(ms).toISOString().slice(0, 10);
const isNever = (ms) => ms != null && ms >= NEVER_MS;
const days = (ms) => Math.floor(ms / DAY);

/** ISO 8601 duration (P30D, PT12H) to ms, or null. */
export function parseDuration(s) {
  const m = /^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/i.exec(String(s || "").trim());
  if (!m) return null;
  return (+(m[1] || 0)) * DAY + (+(m[2] || 0)) * 3600000 + (+(m[3] || 0)) * 60000 + (+(m[4] || 0)) * 1000;
}

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

const str = (v) => (v == null ? "" : String(v)).trim();
const truthy = (v) => v === true || /^(true|yes|1|active|enabled)$/i.test(str(v));
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/** Case-insensitive property lookup (Graph camelCase vs PowerShell PascalCase). */
function gk(o, ...keys) {
  if (!o || typeof o !== "object") return undefined;
  for (const k of keys) if (o[k] !== undefined) return o[k];
  const low = {};
  for (const k of Object.keys(o)) low[k.toLowerCase()] = o[k];
  for (const k of keys) { const v = low[k.toLowerCase()]; if (v !== undefined) return v; }
  return undefined;
}
const arr = (v) => (Array.isArray(v) ? v : v == null ? [] : [v]);

function unwrap(o) {
  if (Array.isArray(o)) return o;
  if (!o || typeof o !== "object") return [];
  for (const k of ["value", "items", "installations", "data", "records", "results"]) if (Array.isArray(o[k])) return o[k];
  return [o];
}

function parseJsonLoose(text) {
  const s = String(text || "").replace(/^﻿/, "");
  try { return JSON.parse(s); } catch (_) {}
  const out = [];
  for (const line of s.split(/\r?\n/)) {
    const l = line.trim(); if (!l) continue;
    try { out.push(JSON.parse(l)); } catch (_) { return null; }
  }
  return out.length ? out : null;
}

function ownerOf(list) {
  const names = [];
  for (const o of arr(list)) {
    if (o == null) continue;
    if (typeof o === "string") { if (o.trim()) names.push(o.trim()); continue; }
    const n = str(gk(o, "userPrincipalName", "mail", "displayName", "appDisplayName", "id"));
    if (n) names.push(n);
  }
  return names.length ? [...new Set(names)].sort(cmp).join("; ") : null;
}

const shortId = (id) => { const s = str(id); return s.length > 12 ? s.slice(0, 8) + "..." : s; };

// ---------------------------------------------------------------------------
// Format detection
// ---------------------------------------------------------------------------

/**
 * Detect the vendor export in one text. Returns { source, format, confidence, label, sniff }.
 * Unknown shapes fall back to the generic column mapping with low confidence.
 */
export function detectFormat(text, name = "") {
  const t = String(text || "");
  const sn = sniff(t);
  const out = (source, format, confidence, label, extra) => Object.assign({ source, format, confidence, label, sniff: sn.format }, extra || {});
  if (!t.trim()) return out("none", "empty", 0, "empty file");
  if (sn.format === "json" || sn.format === "ndjson" || /^\s*[[{]/.test(t)) {
    const obj = parseJsonLoose(t);
    if (obj == null) return out("none", "invalid-json", 0, "unreadable JSON");
    const list = unwrap(obj);
    const first = list.find((r) => r && typeof r === "object") || {};
    const kinds = new Set(list.map((r) => str(gk(r, "kind"))).filter(Boolean));
    if ((obj && !Array.isArray(obj) && str(obj.kind) === "List") || [...kinds].some((k) => /^(ServiceAccount|Secret|ClusterRoleBinding|RoleBinding)$/.test(k))) {
      const k = [...kinds].filter((x) => /^(ServiceAccount|Secret|ClusterRoleBinding|RoleBinding)$/.test(x));
      return out("k8s", "k8s-" + (k[0] || "list").toLowerCase(), k.length ? 1 : 0.6, "Kubernetes " + (k.join("/") || "List"));
    }
    if ((obj && Array.isArray(obj.installations)) || (gk(first, "app_slug") !== undefined && gk(first, "repository_selection") !== undefined)) return out("github", "github-installations", 1, "GitHub App installations");
    if (gk(first, "read_only") !== undefined && /^(ssh-|ecdsa-|sk-)/.test(str(gk(first, "key")))) return out("github", "github-deploy-keys", 1, "GitHub deploy keys");
    if (/\/serviceAccounts\/[^/]+\/keys\//.test(str(gk(first, "name"))) && gk(first, "keyType") !== undefined) return out("gcp", "gcp-keys", 1, "GCP service account keys");
    if (/\.gserviceaccount\.com$/i.test(str(gk(first, "email"))) || (gk(first, "uniqueId") !== undefined && gk(first, "oauth2ClientId") !== undefined)) return out("gcp", "gcp-service-accounts", 1, "GCP service accounts");
    if (gk(first, "servicePrincipalType") !== undefined || gk(first, "appRoleAssignedTo") !== undefined) return out("entra", "entra-service-principals", 1, "Entra service principals");
    if (gk(first, "appId") !== undefined && (gk(first, "passwordCredentials") !== undefined || gk(first, "keyCredentials") !== undefined || gk(first, "displayName") !== undefined)) return out("entra", "entra-applications", 1, "Entra app registrations");
    if (gk(first, "tokenWindow") !== undefined || (gk(first, "userId") !== undefined && gk(first, "expiresAt") !== undefined)) return out("okta", "okta-tokens-json", 1, "Okta API tokens (JSON)");
    const headers = Object.keys(first);
    const map = resolveGeneric(headers);
    return out("generic", "generic-json", map.principal && (map.created || map.expires || map.lastUsed) ? 0.6 : 0.3, "generic JSON", { headers, mapping: map });
  }
  if (sn.format === "csv" || sn.format === "tsv" || sn.format === "unknown") {
    const { headers } = parseCsv(t);
    const norm = new Set(headers.map(normHeader));
    const has = (...h) => h.every((x) => norm.has(normHeader(x)));
    if (has("user", "arn", "access_key_1_active", "access_key_1_last_rotated")) {
      const all = AWS_HEADERS.every((h) => norm.has(normHeader(h)));
      return out("aws", "aws-credential-report", all ? 1 : 0.85, "AWS IAM credential report", { headers });
    }
    if (has("Display name", "Application (client) ID") && (norm.has("objectid") || norm.has("createdon"))) return out("entra", "entra-portal-csv", 0.9, "Entra portal App registrations CSV", { headers });
    if (has("Token ID", "Created by") && (norm.has("lastused") || norm.has("expires"))) return out("okta", "okta-tokens-csv", 1, "Okta API tokens (CSV)", { headers });
    if (!headers.length) return out("none", "empty", 0, "no rows");
    const map = resolveGeneric(headers);
    return out("generic", "generic-csv", map.principal && (map.created || map.expires || map.lastUsed) ? 0.6 : 0.3, "generic CSV", { headers, mapping: map });
  }
  return out("none", sn.format, 0, "unsupported format (" + sn.format + ")");
}

function resolveGeneric(headers) {
  const map = {};
  for (const [key, aliases] of Object.entries(COLUMNS)) { const h = findColumn(headers, aliases); if (h) map[key] = h; }
  // "name" and "id" are weak aliases: only accept them when nothing better exists.
  return map;
}

// ---------------------------------------------------------------------------
// Parsers: each returns normalized rows { rec: "credential"|"principal"|"binding", ... }
// ---------------------------------------------------------------------------

const cred = (o) => Object.assign({ rec: "credential", source: "", principal: "", principalId: null, principalType: "service", kind: "", credential: "", created: null, lastUsed: null, expires: null, active: true, owner: null, usageKnown: false, managed: false, scope: null, meta: {} }, o);
const prin = (o) => Object.assign({ rec: "principal", source: "", principal: "", principalId: null, principalType: "service", enabled: true, owner: null, created: null, meta: {} }, o);

function parseAws(text, file) {
  const { rows } = parseCsv(text);
  const out = [];
  for (const r of rows) {
    const user = str(r.user); if (!user) continue;
    const root = user === "<root_account>";
    const pwEnabled = truthy(r.password_enabled);
    const neverHadPassword = !pwEnabled && toTime(r.password_last_changed) == null;
    const principalType = root ? "root" : SERVICE_NAME_RE.test(user) || neverHadPassword ? "service" : "human";
    const owner = principalType === "human" ? user : null;
    out.push(prin({ source: "aws", principal: user, principalId: str(r.arn) || null, principalType, owner, created: iso(toTime(r.user_creation_time)), meta: { passwordEnabled: pwEnabled, mfa: truthy(r.mfa_active), file } }));
    for (const k of [1, 2]) {
      const active = truthy(r["access_key_" + k + "_active"]);
      const rotated = toTime(r["access_key_" + k + "_last_rotated"]);
      if (!active && rotated == null) continue;
      out.push(cred({
        source: "aws", principal: user, principalId: str(r.arn) || null, principalType, kind: "access_key", credential: "access_key_" + k,
        created: iso(rotated), lastUsed: iso(toTime(r["access_key_" + k + "_last_used_date"])), expires: null, active, owner, usageKnown: true,
        scope: str(r["access_key_" + k + "_last_used_service"]) || null,
        meta: { lastUsedRegion: str(r["access_key_" + k + "_last_used_region"]) || null, lastUsedService: str(r["access_key_" + k + "_last_used_service"]) || null, file },
      }));
    }
    for (const k of [1, 2]) {
      if (!truthy(r["cert_" + k + "_active"])) continue;
      out.push(cred({ source: "aws", principal: user, principalId: str(r.arn) || null, principalType, kind: "signing_cert", credential: "cert_" + k, created: iso(toTime(r["cert_" + k + "_last_rotated"])), active: true, owner, meta: { file } }));
    }
  }
  return out;
}

function appRoles(record) {
  const roles = [], scopes = [];
  for (const rra of arr(gk(record, "requiredResourceAccess"))) {
    const res = str(gk(rra, "resourceAppId")).toLowerCase();
    for (const ra of arr(gk(rra, "resourceAccess"))) {
      const id = str(gk(ra, "id")).toLowerCase(), type = str(gk(ra, "type")), value = str(gk(ra, "value"));
      const entry = { id, value: value || null, resource: res };
      if (/^role$/i.test(type)) roles.push(entry); else scopes.push(entry);
    }
  }
  const highRisk = [];
  for (const r of roles) {
    const name = HIGH_RISK_APP_ROLES[r.id];
    const okRes = !r.resource || r.resource === GRAPH_APP || r.resource === EXO_APP;
    if (name && okRes) highRisk.push(name);
    else if (r.value && HIGH_RISK_VALUES.has(r.value.toLowerCase())) highRisk.push(r.value);
  }
  return { roles: roles.length, scopes: scopes.length, highRisk: [...new Set(highRisk)].sort(cmp) };
}

function entraCreds(record, base, file) {
  const out = [];
  for (const pc of arr(gk(record, "passwordCredentials"))) {
    const keyId = str(gk(pc, "keyId"));
    out.push(cred(Object.assign({}, base, {
      kind: "client_secret", credential: str(gk(pc, "displayName")) || shortId(keyId) || "secret",
      created: iso(toTime(gk(pc, "startDateTime"))), expires: iso(toTime(gk(pc, "endDateTime"))), meta: { keyId: keyId || null, hint: str(gk(pc, "hint")) || null, file },
    })));
  }
  for (const kc of arr(gk(record, "keyCredentials"))) {
    const keyId = str(gk(kc, "keyId"));
    out.push(cred(Object.assign({}, base, {
      kind: "certificate", credential: str(gk(kc, "displayName")) || shortId(keyId) || "certificate",
      created: iso(toTime(gk(kc, "startDateTime"))), expires: iso(toTime(gk(kc, "endDateTime"))), meta: { keyId: keyId || null, usage: str(gk(kc, "usage")) || null, type: str(gk(kc, "type")) || null, file },
    })));
  }
  return out;
}

function parseEntraApps(text, file) {
  const out = [];
  for (const a of unwrap(parseJsonLoose(text))) {
    if (!a || typeof a !== "object") continue;
    const name = str(gk(a, "displayName")) || str(gk(a, "appId")); if (!name) continue;
    const appId = str(gk(a, "appId")) || null, objectId = str(gk(a, "id")) || null;
    const owner = ownerOf(gk(a, "owners"));
    const roles = appRoles(a);
    const base = { source: "entra", principal: name, principalId: appId, principalType: "application", owner, scope: roles.roles ? roles.roles + " app role(s)" + (roles.highRisk.length ? ": " + roles.highRisk.join(", ") : "") : null };
    out.push(prin({ source: "entra", principal: name, principalId: appId, principalType: "application", owner, created: iso(toTime(gk(a, "createdDateTime"))), meta: { objectId, signInAudience: str(gk(a, "signInAudience")) || null, ownersKnown: gk(a, "owners") !== undefined, appRoles: roles.roles, delegatedScopes: roles.scopes, highRiskRoles: roles.highRisk, file } }));
    out.push(...entraCreds(a, base, file));
  }
  return out;
}

function parseEntraServicePrincipals(text, file) {
  const out = [];
  for (const sp of unwrap(parseJsonLoose(text))) {
    if (!sp || typeof sp !== "object") continue;
    const name = str(gk(sp, "displayName")) || str(gk(sp, "appId")); if (!name) continue;
    const appId = str(gk(sp, "appId")) || null;
    const type = str(gk(sp, "servicePrincipalType")) || "Application";
    const enabled = gk(sp, "accountEnabled") === undefined ? true : truthy(gk(sp, "accountEnabled"));
    const owner = ownerOf(gk(sp, "owners"));
    out.push(prin({ source: "entra", principal: name, principalId: appId, principalType: type === "ManagedIdentity" ? "managed-identity" : type.toLowerCase(), enabled, owner, created: iso(toTime(gk(sp, "createdDateTime"))), meta: { servicePrincipalType: type, objectId: str(gk(sp, "id")) || null, appRoleAssignments: arr(gk(sp, "appRoleAssignedTo")).length, ownersKnown: gk(sp, "owners") !== undefined, file } }));
    out.push(...entraCreds(sp, { source: "entra", principal: name, principalId: appId, principalType: "service-principal", owner, active: enabled }, file));
  }
  return out;
}

function parseEntraPortalCsv(text, file) {
  const { headers, rows } = parseCsv(text);
  const hName = findColumn(headers, ["Display name"]), hApp = findColumn(headers, ["Application (client) ID"]), hObj = findColumn(headers, ["Object ID"]);
  const hCreated = findColumn(headers, ["Created on"]), hCerts = findColumn(headers, ["Certificates & secrets", "Certificates and secrets"]);
  const out = [];
  for (const r of rows) {
    const name = str(r[hName]); if (!name) continue;
    const appId = hApp ? str(r[hApp]) || null : null;
    out.push(prin({ source: "entra", principal: name, principalId: appId, principalType: "application", owner: null, created: hCreated ? iso(toTime(r[hCreated])) : null, meta: { objectId: hObj ? str(r[hObj]) || null : null, ownersKnown: false, portalCsv: true, file } }));
    if (!hCerts) continue;
    const s = str(r[hCerts]);
    if (!s || /^(none|no credentials|-)$/i.test(s)) continue;
    const portalStatus = /expired/i.test(s) ? "expired" : /expir/i.test(s) ? "expiring" : /current/i.test(s) ? "ok" : "unknown";
    out.push(cred({ source: "entra", principal: name, principalId: appId, principalType: "application", kind: "credential", credential: "portal status: " + s, created: hCreated ? iso(toTime(r[hCreated])) : null, active: true, meta: { portalStatus, file } }));
  }
  return out;
}

function parseGcpKeys(text, file) {
  const out = [];
  for (const k of unwrap(parseJsonLoose(text))) {
    if (!k || typeof k !== "object") continue;
    const m = /serviceAccounts\/([^/]+)\/keys\/([^/]+)$/.exec(str(gk(k, "name"))); if (!m) continue;
    const managed = str(gk(k, "keyType")).toUpperCase() === "SYSTEM_MANAGED";
    const before = toTime(gk(k, "validBeforeTime"));
    out.push(cred({
      source: "gcp", principal: m[1], principalId: m[1], principalType: "service-account", kind: managed ? "sa_key (google-managed)" : "sa_key", credential: shortId(m[2]),
      created: iso(toTime(gk(k, "validAfterTime"))), expires: isNever(before) ? "never" : iso(before), active: !truthy(gk(k, "disabled")), managed,
      meta: { keyId: m[2], keyType: str(gk(k, "keyType")) || null, keyOrigin: str(gk(k, "keyOrigin")) || null, keyAlgorithm: str(gk(k, "keyAlgorithm")) || null, file },
    }));
  }
  return out;
}

function parseGcpServiceAccounts(text, file) {
  const out = [];
  for (const sa of unwrap(parseJsonLoose(text))) {
    const email = str(gk(sa, "email")); if (!email) continue;
    out.push(prin({ source: "gcp", principal: email, principalId: str(gk(sa, "uniqueId")) || email, principalType: "service-account", enabled: !truthy(gk(sa, "disabled")), owner: null, meta: { displayName: str(gk(sa, "displayName")) || null, oauth2ClientId: str(gk(sa, "oauth2ClientId")) || null, file } }));
  }
  return out;
}

function parseOktaCsv(text, file) {
  const { headers, rows } = parseCsv(text);
  const h = (a) => findColumn(headers, a);
  const hName = h(["Name"]), hCreated = h(["Created"]), hBy = h(["Created by"]), hUsed = h(["Last used"]), hExp = h(["Expires"]), hId = h(["Token ID"]), hStatus = h(["Status"]);
  const out = [];
  for (const r of rows) {
    const name = str(r[hName]) || str(r[hId]); if (!name) continue;
    const status = hStatus ? str(r[hStatus]) : "";
    out.push(cred({
      source: "okta", principal: name, principalId: hId ? str(r[hId]) || null : null, principalType: "api-token", kind: "api_token", credential: hId ? shortId(r[hId]) || name : name,
      created: hCreated ? iso(toTime(r[hCreated])) : null, lastUsed: hUsed ? iso(toTime(r[hUsed])) : null, expires: hExp ? iso(toTime(r[hExp])) : null,
      active: !status || !/^(revoked|inactive|deactivated|disabled)$/i.test(status), owner: hBy ? str(r[hBy]) || null : null, usageKnown: !!hUsed,
      meta: { status: status || null, createdBy: hBy ? str(r[hBy]) || null : null, file },
    }));
  }
  return out;
}

function parseOktaJson(text, file) {
  const out = [];
  for (const t of unwrap(parseJsonLoose(text))) {
    if (!t || typeof t !== "object") continue;
    const name = str(gk(t, "name")) || str(gk(t, "id")); if (!name) continue;
    const exp = toTime(gk(t, "expiresAt")), win = parseDuration(gk(t, "tokenWindow"));
    // Okta API tokens expire a fixed window after last use; last use = expiresAt - tokenWindow.
    const lastUsed = exp != null && win != null ? exp - win : null;
    out.push(cred({
      source: "okta", principal: name, principalId: str(gk(t, "id")) || null, principalType: "api-token", kind: "api_token", credential: shortId(gk(t, "id")) || name,
      created: iso(toTime(gk(t, "created"))), lastUsed: iso(lastUsed), expires: iso(exp), active: true, owner: str(gk(t, "userId")) || null, usageKnown: lastUsed != null,
      meta: { userId: str(gk(t, "userId")) || null, tokenWindow: str(gk(t, "tokenWindow")) || null, lastUpdated: iso(toTime(gk(t, "lastUpdated"))), lastUsedDerived: lastUsed != null, file },
    }));
  }
  return out;
}

function k8sOwner(meta) {
  const labels = (meta && meta.labels) || {}, ann = (meta && meta.annotations) || {};
  for (const k of ["owner", "team", "app.kubernetes.io/managed-by"]) { if (str(labels[k])) return str(labels[k]); }
  for (const k of ["owner", "team", "contact"]) { if (str(ann[k])) return str(ann[k]); }
  return null;
}

function parseK8s(text, file) {
  const obj = parseJsonLoose(text);
  const items = obj && !Array.isArray(obj) && Array.isArray(obj.items) ? obj.items : Array.isArray(obj) ? obj : obj ? [obj] : [];
  const out = [];
  for (const it of items) {
    if (!it || typeof it !== "object") continue;
    const kind = str(it.kind), md = it.metadata || {}, ns = str(md.namespace) || "default", name = str(md.name);
    if (kind === "ServiceAccount" && name) {
      const automount = it.automountServiceAccountToken === undefined ? true : !!it.automountServiceAccountToken;
      out.push(prin({ source: "k8s", principal: ns + "/" + name, principalId: str(md.uid) || null, principalType: "service-account", owner: k8sOwner(md), created: iso(toTime(md.creationTimestamp)), meta: { namespace: ns, name, automount, automountExplicit: it.automountServiceAccountToken !== undefined, isDefault: name === "default", secretRefs: arr(it.secrets).length, file } }));
    } else if (kind === "Secret" && str(it.type) === "kubernetes.io/service-account-token") {
      const sa = str((md.annotations || {})["kubernetes.io/service-account.name"]) || "unknown";
      out.push(cred({ source: "k8s", principal: ns + "/" + sa, principalId: null, principalType: "service-account", kind: "sa_token", credential: name || "token", created: iso(toTime(md.creationTimestamp)), expires: null, active: true, owner: k8sOwner(md), meta: { namespace: ns, secret: name, file } }));
    } else if ((kind === "ClusterRoleBinding" || kind === "RoleBinding") && it.roleRef) {
      const role = str(it.roleRef.name);
      for (const s of arr(it.subjects)) {
        if (str(s.kind) !== "ServiceAccount") continue;
        out.push({ rec: "binding", source: "k8s", principal: (str(s.namespace) || "default") + "/" + str(s.name), role, bindingKind: kind, binding: name, meta: { file } });
      }
    }
  }
  return out;
}

function parseGithubInstallations(text, file) {
  const obj = parseJsonLoose(text);
  const out = [];
  for (const i of unwrap(obj)) {
    if (!i || typeof i !== "object" || gk(i, "app_slug") === undefined) continue;
    const perms = gk(i, "permissions") || {};
    const writes = Object.keys(perms).filter((k) => /^(write|admin)$/i.test(str(perms[k]))).sort(cmp);
    const slug = str(gk(i, "app_slug")) || str(gk(i, "app_id"));
    out.push(cred({
      source: "github", principal: slug, principalId: str(gk(i, "app_id")) || null, principalType: "github-app", kind: "app_installation", credential: "installation " + str(gk(i, "id")),
      created: iso(toTime(gk(i, "created_at"))), lastUsed: null, expires: null, active: !gk(i, "suspended_at"), owner: null,
      scope: str(gk(i, "repository_selection")) + " repos" + (writes.length ? "; write: " + writes.join(", ") : ""),
      meta: { installationId: str(gk(i, "id")) || null, repositorySelection: str(gk(i, "repository_selection")) || null, writePermissions: writes, permissions: Object.keys(perms).length, updatedAt: iso(toTime(gk(i, "updated_at"))), file },
    }));
  }
  return out;
}

function parseGithubDeployKeys(text, file) {
  const out = [];
  for (const k of unwrap(parseJsonLoose(text))) {
    if (!k || typeof k !== "object" || gk(k, "read_only") === undefined) continue;
    const title = str(gk(k, "title")) || "deploy key " + str(gk(k, "id"));
    const keyType = (str(gk(k, "key")).split(/\s+/)[0]) || null;
    out.push(cred({
      source: "github", principal: title, principalId: str(gk(k, "id")) || null, principalType: "deploy-key", kind: "deploy_key", credential: "deploy key " + str(gk(k, "id")),
      created: iso(toTime(gk(k, "created_at"))), lastUsed: iso(toTime(gk(k, "last_used"))), expires: null, active: true, owner: str(gk(k, "added_by")) || null,
      usageKnown: gk(k, "last_used") !== undefined, scope: truthy(gk(k, "read_only")) ? "read-only" : "read-write",
      meta: { readOnly: truthy(gk(k, "read_only")), keyType, verified: gk(k, "verified"), file },
    }));
  }
  return out;
}

function parseGeneric(text, file, det, mapping) {
  const map = Object.assign({}, det.mapping || {}, mapping || {});
  const rows = det.format === "generic-json" ? unwrap(parseJsonLoose(text)) : parseCsv(text).rows;
  const out = [];
  if (!map.principal) return out;
  for (const r of rows) {
    if (!r || typeof r !== "object") continue;
    const principal = str(r[map.principal]); if (!principal) continue;
    const status = map.status ? str(r[map.status]) : "";
    out.push(cred({
      source: map.source && str(r[map.source]) ? "generic:" + str(r[map.source]).toLowerCase() : "generic", principal, principalType: "service",
      kind: map.kind ? str(r[map.kind]) || "credential" : "credential", credential: map.credential ? shortId(r[map.credential]) || principal : principal,
      created: map.created ? iso(toTime(r[map.created])) : null, lastUsed: map.lastUsed ? iso(toTime(r[map.lastUsed])) : null, expires: map.expires ? iso(toTime(r[map.expires])) : null,
      active: !status || truthy(status) || !/^(inactive|disabled|revoked|expired|false|no|0)$/i.test(status), owner: map.owner ? str(r[map.owner]) || null : null, usageKnown: !!map.lastUsed,
      meta: { file },
    }));
  }
  return out;
}

const PARSERS = {
  "aws-credential-report": parseAws,
  "entra-applications": parseEntraApps,
  "entra-service-principals": parseEntraServicePrincipals,
  "entra-portal-csv": parseEntraPortalCsv,
  "gcp-keys": parseGcpKeys,
  "gcp-service-accounts": parseGcpServiceAccounts,
  "okta-tokens-csv": parseOktaCsv,
  "okta-tokens-json": parseOktaJson,
  "github-installations": parseGithubInstallations,
  "github-deploy-keys": parseGithubDeployKeys,
};

/**
 * Parse one text or several files ({name, text}[]) into normalized rows.
 * opts.mapping: { [fileName]: { principal: header, created: header, ... } } for generic files.
 * Never throws on bad input; problems are listed in skipped.
 */
export function parseInput(input, opts = {}) {
  const files = Array.isArray(input) ? input : [{ name: "input", text: input }];
  const rows = [], skipped = [], detected = [];
  const mapping = opts.mapping || {};
  files.forEach((f, idx) => {
    const name = str(f && f.name) || "file-" + (idx + 1);
    const text = typeof f === "string" ? f : String((f && f.text) || "");
    const det = detectFormat(text, name);
    const entry = { name, source: det.source, format: det.format, label: det.label, confidence: det.confidence, headers: det.headers || [], mapping: det.mapping || null, records: 0 };
    if (det.source === "none") { skipped.push({ check: "parse:" + name, reason: det.label }); detected.push(entry); return; }
    let out = [];
    try {
      if (det.format === "k8s-serviceaccount" || det.format === "k8s-secret" || det.format === "k8s-clusterrolebinding" || det.format === "k8s-rolebinding" || det.format === "k8s-list") out = parseK8s(text, name);
      else if (PARSERS[det.format]) out = PARSERS[det.format](text, name);
      else out = parseGeneric(text, name, det, mapping[name] || mapping[idx]);
    } catch (e) { skipped.push({ check: "parse:" + name, reason: "parser error: " + (e && e.message || e) }); }
    if (det.source === "generic" && !out.length) skipped.push({ check: "parse:" + name, reason: det.mapping && det.mapping.principal ? "no rows with a principal value" : "no principal column found; map columns to use this file" });
    entry.records = out.length;
    rows.push(...out);
    detected.push(entry);
  });
  const headers = [...new Set(rows.flatMap((r) => Object.keys(r)))];
  const format = detected.length === 1 ? detected[0].format : detected.length ? "multi" : "empty";
  return { format, headers, rows, skipped, files: detected };
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

function normOpts(opts) {
  const o = Object.assign({}, DEFAULTS, opts || {});
  const warn = arr(o.expiryWarnDays).map(Number).filter((n) => Number.isFinite(n) && n > 0).sort((a, b) => a - b);
  o.expiryWarnDays = warn.length ? [...new Set(warn)] : DEFAULTS.expiryWarnDays.slice();
  o.maxKeyAgeDays = Number(o.maxKeyAgeDays) > 0 ? Number(o.maxKeyAgeDays) : DEFAULTS.maxKeyAgeDays;
  o.unusedDays = Number(o.unusedDays) > 0 ? Number(o.unusedDays) : DEFAULTS.unusedDays;
  o.maxCertDays = Number(o.maxCertDays) > 0 ? Number(o.maxCertDays) : DEFAULTS.maxCertDays;
  o.departed = arr(o.departed).map((d) => str(d).toLowerCase()).filter(Boolean);
  return o;
}

/** Latest non-expiry timestamp in the data (deterministic reference time). */
export function latestTimestamp(rows) {
  let max = null;
  for (const r of rows || []) {
    for (const v of [r.created, r.lastUsed, r.meta && r.meta.updatedAt, r.meta && r.meta.lastUpdated]) {
      const t = toTime(v);
      if (t != null && !isNever(t) && (max == null || t > max)) max = t;
    }
  }
  return max;
}

const ROTATABLE = new Set(["access_key", "client_secret", "sa_key", "api_token", "sa_token", "deploy_key", "signing_cert", "credential"]);

function compact(c) {
  return { source: c.source, principal: c.principal, kind: c.kind, credential: c.credential, created: c.created, lastUsed: c.lastUsed, expires: c.expires, ageDays: c.ageDays, unusedDays: c.unusedDays, expiresInDays: c.expiresInDays, status: c.status, owner: c.owner, scope: c.scope, score: c.score };
}

/**
 * Analyze normalized rows (from parseInput) or the parseInput result itself.
 * opts: DEFAULTS overrides + now (ISO) + departed (string[]). ctx.progress(i, n, label) optional.
 */
export function analyze(dataset, opts = {}, ctx) {
  const o = normOpts(opts);
  const rows = Array.isArray(dataset) ? dataset : dataset && Array.isArray(dataset.rows) ? dataset.rows : [];
  const files = (dataset && !Array.isArray(dataset) && dataset.files) || [];
  const skipped = (dataset && !Array.isArray(dataset) && Array.isArray(dataset.skipped) ? dataset.skipped : []).slice();
  const creds = rows.filter((r) => r && r.rec === "credential");
  const prins = rows.filter((r) => r && r.rec === "principal");
  const binds = rows.filter((r) => r && r.rec === "binding");
  const nowOpt = toTime(o.now);
  const dataNow = latestTimestamp(rows);
  const now = nowOpt != null ? nowOpt : dataNow != null ? dataNow : 0;
  const nowSource = nowOpt != null ? "opts" : dataNow != null ? "data" : "none";
  const warnMax = o.expiryWarnDays[o.expiryWarnDays.length - 1];

  // Principals: merge rows per source|principal, attach bindings.
  const pmap = new Map();
  const pkey = (r) => r.source + "|" + r.principal;
  for (const p of prins) {
    const k = pkey(p);
    const cur = pmap.get(k) || { source: p.source, principal: p.principal, principalId: null, principalType: p.principalType, enabled: true, owner: null, created: null, meta: {}, credentials: 0, oldestDays: null, roles: [] };
    cur.principalId = cur.principalId || p.principalId;
    cur.owner = cur.owner || p.owner;
    cur.created = cur.created || p.created;
    cur.enabled = cur.enabled && p.enabled !== false;
    if (p.principalType && p.principalType !== "service") cur.principalType = p.principalType;
    Object.assign(cur.meta, p.meta);
    pmap.set(k, cur);
  }
  for (const b of binds) {
    const k = pkey(b);
    const cur = pmap.get(k) || { source: b.source, principal: b.principal, principalId: null, principalType: "service-account", enabled: true, owner: null, created: null, meta: {}, credentials: 0, oldestDays: null, roles: [] };
    cur.roles.push(b.role + " (" + b.bindingKind + " " + b.binding + ")");
    cur.roles.sort(cmp);
    pmap.set(k, cur);
  }

  // Credentials: enrich.
  const n = creds.length;
  const enriched = [];
  const usageSources = new Set(), noUsageSources = new Set();
  for (let i = 0; i < n; i++) {
    if (i % 1000 === 0) ctx?.progress?.(i, n, "scoring credentials");
    const c = Object.assign({}, creds[i]);
    const k = pkey(c);
    const p = pmap.get(k) || (pmap.set(k, { source: c.source, principal: c.principal, principalId: c.principalId, principalType: c.principalType, enabled: true, owner: null, created: null, meta: {}, credentials: 0, oldestDays: null, roles: [] }), pmap.get(k));
    p.credentials++;
    const created = toTime(c.created), lastUsed = toTime(c.lastUsed);
    const expires = c.expires === "never" ? "never" : toTime(c.expires);
    const never = expires === "never" || isNever(expires);
    c.ageDays = created != null && now ? Math.max(0, days(now - created)) : null;
    c.unusedDays = lastUsed != null && now ? Math.max(0, days(now - lastUsed)) : null;
    c.expiresInDays = !never && expires != null && now ? Math.ceil((expires - now) / DAY) : null;
    c.neverExpires = never;
    c.owner = c.owner || p.owner || (c.principalType === "human" ? c.principal : null) || "unassigned";
    if (!p.enabled) c.active = false;
    if (c.usageKnown) usageSources.add(c.source); else noUsageSources.add(c.source);
    if (p.oldestDays == null || (c.ageDays != null && c.ageDays > p.oldestDays)) p.oldestDays = c.ageDays;
    if (p.meta.highRiskRoles && p.meta.highRiskRoles.length) c.scope = c.scope || p.meta.appRoles + " app role(s): " + p.meta.highRiskRoles.join(", ");
    if (p.roles.length) c.scope = (c.scope ? c.scope + "; " : "") + p.roles.join("; ");
    const rotatable = ROTATABLE.has(c.kind) && !c.managed;
    const portal = c.meta && c.meta.portalStatus;
    let status;
    if (!c.active) status = "inactive";
    else if (c.managed) status = "managed";
    else if (portal) status = portal === "expired" ? "expired" : portal === "expiring" ? "expiring" : portal === "ok" ? "ok" : "unknown";
    else if (c.expiresInDays != null && c.expiresInDays <= 0) status = "expired";
    else if (c.expiresInDays != null && c.expiresInDays <= warnMax) status = "expiring";
    else if (c.usageKnown && lastUsed == null && c.ageDays != null && c.ageDays > o.unusedDays) status = "never-used";
    else if (rotatable && c.ageDays != null && c.ageDays > o.maxKeyAgeDays) status = "overdue";
    else if (c.usageKnown && c.unusedDays != null && c.unusedDays > o.unusedDays) status = "unused";
    else status = "ok";
    c.status = status;
    c.flags = [];
    c.score = 0;
    enriched.push(c);
  }

  // Detections.
  const findings = [];
  const flag = (c, f, pts) => { if (!c.flags.includes(f)) c.flags.push(f); c.score = Math.min(100, c.score + (pts || 0)); };
  const emit = (id, def, list) => {
    if (!list.length) return;
    const ev = list.map(compact);
    const byP = new Map();
    for (const c of list) {
      const k = pkey(c), p = pmap.get(k);
      if (!byP.has(k)) byP.set(k, { type: "IDENTITY", name: c.principal, data: { kind: "non-human", source: c.source, credentials: p ? p.credentials : 1, oldestDays: p ? p.oldestDays : c.ageDays, owner: c.owner } });
    }
    const assets = [...byP.values()].sort((a, b) => cmp(a.name, b.name)).slice(0, 50);
    findings.push(Object.assign({ id: TOOL_ID + ":" + id, controls: [], evidence: ev.slice(0, 50), evidenceCount: ev.length, assets, tags: [id] }, def));
  };
  const active = enriched.filter((c) => c.active && !c.managed);
  const sevForWindow = (idx) => (idx === 0 ? "high" : idx === 1 ? "medium" : "low");

  // Expired / expiring (dated).
  const expired = active.filter((c) => c.expiresInDays != null && c.expiresInDays <= 0);
  const expiredEntra = expired.filter((c) => c.source === "entra"), expiredOther = expired.filter((c) => c.source !== "entra");
  for (const c of expired) flag(c, "expired", c.source === "entra" ? 35 : 25);
  emit("entra_expired", { title: "Expired Entra app credential still registered", severity: "critical", confidence: "confirmed", category: "expiry",
    description: expiredEntra.length + " client secret(s)/certificate(s) on Entra app registrations are past endDateTime. Any integration still presenting them is failing, and the stale credential remains an unreviewed artefact on the app.",
    recommendation: "Confirm the integration has a replacement credential, then remove the expired secret or certificate from the app registration and record the owner who confirmed it.",
    controls: [C.ia5, C.crypto, C.iso517] }, expiredEntra);
  emit("cred_expired", { title: "Expired credential still present", severity: "low", confidence: "confirmed", category: "expiry",
    description: expiredOther.length + " credential(s) are past their expiry but still listed in the export. They cannot authenticate, but they clutter the inventory and hide the live set.",
    recommendation: "Delete expired keys and tokens so the inventory reflects only credentials that can authenticate.", controls: [C.ac2, C.iso516] }, expiredOther);
  o.expiryWarnDays.forEach((w, idx) => {
    const lo = idx === 0 ? 0 : o.expiryWarnDays[idx - 1];
    const list = active.filter((c) => c.expiresInDays != null && c.expiresInDays > lo && c.expiresInDays <= w);
    for (const c of list) flag(c, "expires<=" + w + "d", idx === 0 ? 20 : idx === 1 ? 10 : 5);
    emit("cred_expiring_" + w, { title: "Credential expires within " + w + " days", severity: sevForWindow(idx), confidence: "confirmed", category: "expiry",
      description: list.length + " credential(s) expire " + (lo ? "in " + (lo + 1) + "-" + w : "within " + w) + " days. Rotate before expiry to avoid an outage and to keep the rotation on schedule.",
      recommendation: "Issue the replacement credential now, cut the integration over, then remove the old one on the calendar date.", controls: [C.ia5, C.crypto, C.soc61] }, list);
  });
  // Portal-CSV status only (no dates).
  const portalExpired = active.filter((c) => c.meta.portalStatus === "expired"), portalExpiring = active.filter((c) => c.meta.portalStatus === "expiring");
  for (const c of portalExpired) flag(c, "expired", 35);
  for (const c of portalExpiring) flag(c, "expiring", 20);
  emit("entra_portal_expired", { title: "Entra portal reports an expired credential", severity: "critical", confidence: "likely", category: "expiry",
    description: portalExpired.length + " app registration(s) show \"Expired\" in the Certificates & secrets column of the portal export. Exact dates are not in this CSV; export GET /applications JSON for per-credential dates.",
    recommendation: "Open each app registration, remove the expired credential and confirm the replacement is in use.", controls: [C.ia5, C.iso517] }, portalExpired);
  emit("entra_portal_expiring", { title: "Entra portal reports a credential expiring soon", severity: "high", confidence: "likely", category: "expiry",
    description: portalExpiring.length + " app registration(s) show \"Expiring soon\" in the portal export (no exact date in this CSV).",
    recommendation: "Rotate the secret or certificate before it lapses; export /applications JSON to get the date onto the calendar.", controls: [C.ia5, C.crypto] }, portalExpiring);

  // Rotation age.
  const overdue = active.filter((c) => ROTATABLE.has(c.kind) && c.ageDays != null && c.ageDays > o.maxKeyAgeDays && !(c.expiresInDays != null && c.expiresInDays <= 0));
  for (const c of overdue) flag(c, "age>" + o.maxKeyAgeDays + "d", Math.min(40, Math.round(40 * c.ageDays / o.maxKeyAgeDays)));
  const ctl = [C.crypto, C.ia5];
  if (overdue.some((c) => c.source === "aws")) ctl.push(C.cisAws114);
  if (overdue.some((c) => c.source === "gcp")) ctl.push(C.cisGcp17);
  emit("key_overdue", { title: "Active credential older than " + o.maxKeyAgeDays + " days", severity: "high", confidence: "confirmed", category: "rotation",
    description: overdue.length + " active key(s)/secret(s)/token(s) exceed the " + o.maxKeyAgeDays + "-day cryptoperiod (oldest " + Math.max(...overdue.map((c) => c.ageDays || 0), 0) + " days). The longer a static secret lives, the more copies exist in CI logs, laptops and backups.",
    recommendation: "Rotate on the calendar dates below; prefer workload identity federation or managed identities so the secret disappears entirely.", controls: ctl }, overdue);

  // Usage.
  const neverUsed = active.filter((c) => c.usageKnown && c.lastUsed == null && c.ageDays != null && c.ageDays > o.unusedDays);
  const unused = active.filter((c) => c.usageKnown && c.unusedDays != null && c.unusedDays > o.unusedDays);
  for (const c of neverUsed) flag(c, "never-used", 20);
  for (const c of unused) flag(c, "unused>" + o.unusedDays + "d", 15);
  const usageCtl = (list) => [C.ac23, C.t1078].concat(list.some((c) => c.source === "aws") ? [C.cisAws112] : []);
  emit("key_never_used", { title: "Credential never used since creation", severity: "medium", confidence: "confirmed", category: "usage",
    description: neverUsed.length + " active credential(s) older than " + o.unusedDays + " days have never authenticated. They serve no workload and are pure attack surface.",
    recommendation: "Disable now, delete after a grace period; if the credential is genuinely needed, document the owner and consumer.", controls: usageCtl(neverUsed) }, neverUsed);
  emit("key_unused", { title: "Credential unused for more than " + o.unusedDays + " days", severity: "medium", confidence: "confirmed", category: "usage",
    description: unused.length + " active credential(s) have not been used in over " + o.unusedDays + " days (longest " + Math.max(...unused.map((c) => c.unusedDays || 0), 0) + " days).",
    recommendation: "Disable the credential; if nothing breaks within the grace period, delete it.", controls: usageCtl(unused) }, unused);
  for (const s of noUsageSources) if (!usageSources.has(s)) skipped.push({ check: "key_never_used/key_unused", reason: s + " export carries no last-used data" });

  // AWS specifics.
  const awsKeys = active.filter((c) => c.source === "aws" && c.kind === "access_key");
  const byUser = new Map();
  for (const c of awsKeys) { const l = byUser.get(c.principal) || []; l.push(c); byUser.set(c.principal, l); }
  const twoKeys = [...byUser.values()].filter((l) => l.length >= 2).flat();
  for (const c of twoKeys) flag(c, "two-active-keys", 5);
  emit("aws_two_active_keys", { title: "IAM user with two active access keys", severity: "low", confidence: "confirmed", category: "hygiene",
    description: twoKeys.length / 2 + " IAM user(s) have both access keys active. Two keys are only legitimate during a rotation window.",
    recommendation: "Finish the rotation: confirm the new key is in use, deactivate then delete the old one.", controls: [C.cisAws113, C.ia5] }, twoKeys);
  const rootKeys = awsKeys.filter((c) => c.principalType === "root");
  for (const c of rootKeys) flag(c, "root-key", 30);
  emit("aws_root_access_key", { title: "Root account has an active access key", severity: "critical", confidence: "confirmed", category: "privilege",
    description: "The AWS root user has " + rootKeys.length + " active access key(s). Root keys bypass every IAM policy and cannot be scoped.",
    recommendation: "Delete the root access keys and use an IAM role or identity-center user for any automation.", controls: [C.cisAws14, C.ac6, C.t1078] }, rootKeys);

  // GCP specifics.
  const gcpUser = active.filter((c) => c.source === "gcp" && c.kind === "sa_key" && str(c.meta.keyType).toUpperCase() === "USER_MANAGED");
  for (const c of gcpUser) flag(c, "user-managed", 10);
  emit("gcp_user_managed_key", { title: "User-managed GCP service account key", severity: "medium", confidence: "confirmed", category: "hygiene",
    description: gcpUser.length + " user-managed key(s) exist. Google cannot rotate these; they are downloadable JSON files that live wherever the user put them.",
    recommendation: "Replace with workload identity federation, attached service accounts or short-lived tokens; delete the key once the workload no longer uses it.", controls: [C.cisGcp14, C.ia5, C.t1552] }, gcpUser);
  const gcpNever = active.filter((c) => c.source === "gcp" && !c.managed && c.neverExpires);
  for (const c of gcpNever) flag(c, "never-expires", 5);
  emit("gcp_key_never_expires", { title: "GCP service account key never expires", severity: "low", confidence: "confirmed", category: "rotation",
    description: gcpNever.length + " key(s) have validBeforeTime 9999-12-31, so nothing forces a rotation.",
    recommendation: "Set an organization policy (constraints/iam.serviceAccountKeyExpiryHours) and rotate on the " + o.maxKeyAgeDays + "-day calendar below.", controls: [C.crypto, C.cisGcp17] }, gcpNever);

  // Certificates.
  const longCerts = enriched.filter((c) => (c.kind === "certificate" || c.kind === "signing_cert") && c.created && c.expires && c.expires !== "never" && days(toTime(c.expires) - toTime(c.created)) > o.maxCertDays);
  for (const c of longCerts) flag(c, "cert>" + o.maxCertDays + "d", 10);
  emit("cert_validity_too_long", { title: "Certificate valid for more than " + o.maxCertDays + " days", severity: "medium", confidence: "confirmed", category: "rotation",
    description: longCerts.length + " certificate(s) have a validity period over " + o.maxCertDays + " days (longest " + Math.max(...longCerts.map((c) => days(toTime(c.expires) - toTime(c.created))), 0) + " days). Long-lived certificates widen the window in which a stolen private key stays useful.",
    recommendation: "Re-issue with a validity of at most " + o.maxCertDays + " days and put the renewal on the calendar.", controls: [C.cabf, C.crypto] }, longCerts);
  if (enriched.some((c) => c.source === "entra" && c.meta.portalStatus)) skipped.push({ check: "cert_validity_too_long", reason: "Entra portal CSV has no credential dates" });

  // Entra app governance.
  const entraP = [...pmap.values()].filter((p) => p.source === "entra" && (p.principalType === "application" || p.principalType === "service-principal"));
  const ownerless = entraP.filter((p) => !p.owner && p.meta.ownersKnown);
  const ownerlessCreds = enriched.filter((c) => c.source === "entra" && ownerless.some((p) => p.principal === c.principal));
  for (const c of ownerlessCreds) flag(c, "no-owner", 10);
  const ownerlessRows = ownerless.map((p) => ({ rec: "credential", source: p.source, principal: p.principal, principalType: p.principalType, kind: "app", credential: p.principalId || p.principal, created: p.created, lastUsed: null, expires: null, ageDays: p.created && now ? days(now - toTime(p.created)) : null, unusedDays: null, expiresInDays: null, status: "unknown", owner: "unassigned", scope: p.meta.appRoles ? p.meta.appRoles + " app role(s)" : null, score: 0, flags: ["no-owner"], meta: {}, active: true }));
  emit("entra_app_no_owner", { title: "App registration without an owner", severity: "medium", confidence: "confirmed", category: "ownership",
    description: ownerless.length + " Entra app registration(s) have no owner. Nobody is accountable for its credentials or permissions, and expiry notices go nowhere.",
    recommendation: "Assign at least two owners (a team group where possible) and record the business owner in the app notes.", controls: [C.ac2, C.iso516, C.soc63] }, ownerlessRows);
  if (entraP.length && entraP.every((p) => !p.meta.ownersKnown)) skipped.push({ check: "entra_app_no_owner", reason: "no owners data in the Entra export (add GET /applications/{id}/owners as owners[])" });
  const secretsByApp = new Map();
  for (const c of active) if (c.source === "entra" && c.kind === "client_secret" && !(c.expiresInDays != null && c.expiresInDays <= 0)) { const l = secretsByApp.get(c.principal) || []; l.push(c); secretsByApp.set(c.principal, l); }
  const multi = [...secretsByApp.values()].filter((l) => l.length >= 2).flat();
  for (const c of multi) flag(c, "multi-secret", 5);
  emit("entra_app_multiple_secrets", { title: "App registration with multiple live client secrets", severity: "low", confidence: "confirmed", category: "hygiene",
    description: [...secretsByApp.values()].filter((l) => l.length >= 2).length + " app(s) carry two or more unexpired client secrets. Outside a rotation window this is how an added attacker credential hides in plain sight.",
    recommendation: "Keep one live secret per app (two only during cut-over); remove the rest and check the audit log for who added them.", controls: [C.t1098, C.ia5] }, multi);
  const highRisk = enriched.filter((c) => c.source === "entra" && pmap.get(pkey(c)) && (pmap.get(pkey(c)).meta.highRiskRoles || []).length);
  const hrApps = entraP.filter((p) => (p.meta.highRiskRoles || []).length);
  for (const c of highRisk) flag(c, "high-risk-app-role", 20);
  const hrRows = highRisk.length ? highRisk : hrApps.map((p) => ({ source: p.source, principal: p.principal, kind: "app", credential: p.principalId || p.principal, created: p.created, lastUsed: null, expires: null, ageDays: null, unusedDays: null, expiresInDays: null, status: "unknown", owner: p.owner || "unassigned", scope: p.meta.highRiskRoles.join(", "), score: 0, flags: ["high-risk-app-role"], meta: {} }));
  emit("entra_app_high_risk_role", { title: "App holds tenant-wide application permissions", severity: "high", confidence: "confirmed", category: "privilege",
    description: hrApps.length + " app(s) request Role-type (application) permissions such as " + [...new Set(hrApps.flatMap((p) => p.meta.highRiskRoles))].sort(cmp).slice(0, 4).join(", ") + ". Combined with a leaked secret this is tenant takeover without any user interaction.",
    recommendation: "Reduce to the narrowest Graph permission that works (resource-specific consent where available), move the credential to a certificate or managed identity, and review the grant quarterly.", controls: [C.ac6, C.t1528, C.iso82] }, hrRows);

  // Okta.
  if (o.departed.length) {
    const dep = active.filter((c) => c.source === "okta" && c.owner && o.departed.includes(str(c.owner).toLowerCase()) && !(c.expiresInDays != null && c.expiresInDays <= 0));
    for (const c of dep) flag(c, "departed-creator", 30);
    emit("okta_token_departed_creator", { title: "API token created by a departed user", severity: "high", confidence: "review", category: "ownership",
      description: dep.length + " Okta API token(s) were created by users on the departed list. Okta API tokens inherit the creator's permissions and keep working after the user is deactivated only if the account is still active; either way the token has no living owner.",
      recommendation: "Revoke the token and re-issue it from a service account owned by the team.", controls: [C.ac23, C.t1078, C.iso516] }, dep);
  } else if (enriched.some((c) => c.source === "okta")) skipped.push({ check: "okta_token_departed_creator", reason: "no departed-user list supplied" });

  // Kubernetes.
  const k8sP = [...pmap.values()].filter((p) => p.source === "k8s");
  const clusterAdmin = k8sP.filter((p) => p.roles.some((r) => /^cluster-admin /.test(r)));
  const caRows = clusterAdmin.map((p) => ({ source: "k8s", principal: p.principal, kind: "service_account", credential: p.principal, created: p.created, lastUsed: null, expires: null, ageDays: null, unusedDays: null, expiresInDays: null, status: "unknown", owner: p.owner || "unassigned", scope: p.roles.join("; "), score: 0, flags: ["cluster-admin"], meta: {} }));
  for (const c of enriched) if (c.source === "k8s" && clusterAdmin.some((p) => p.principal === c.principal)) flag(c, "cluster-admin", 20);
  emit("k8s_sa_cluster_admin", { title: "Service account bound to cluster-admin", severity: "high", confidence: "confirmed", category: "privilege",
    description: clusterAdmin.length + " Kubernetes service account(s) are subjects of a cluster-admin binding. Any pod that mounts their token owns the cluster.",
    recommendation: "Replace with a least-privilege ClusterRole or namespaced Role; keep cluster-admin for break-glass humans only.", controls: [C.cisK8s511, C.ac6, C.t1528] }, caRows);
  if (k8sP.length && !binds.length) skipped.push({ check: "k8s_sa_cluster_admin", reason: "no clusterrolebindings export" });
  const saTokens = active.filter((c) => c.source === "k8s" && c.kind === "sa_token");
  for (const c of saTokens) flag(c, "long-lived-token", 10);
  emit("k8s_long_lived_sa_token", { title: "Long-lived service account token secret", severity: "medium", confidence: "confirmed", category: "rotation",
    description: saTokens.length + " kubernetes.io/service-account-token secret(s) exist. These tokens never expire and survive pod restarts; since Kubernetes 1.24 they are only created on request.",
    recommendation: "Delete the secret and let workloads use projected, time-bound tokens (TokenRequest API); rotate any external consumer to short-lived credentials.", controls: [C.crypto, C.t1528, C.ia5] }, saTokens);
  if (k8sP.length && !saTokens.length && !enriched.some((c) => c.source === "k8s")) skipped.push({ check: "k8s_long_lived_sa_token", reason: "no secrets export (kubectl get secrets -A -o json)" });
  const defAuto = k8sP.filter((p) => p.meta.isDefault && p.meta.automount !== false);
  const defRows = defAuto.map((p) => ({ source: "k8s", principal: p.principal, kind: "service_account", credential: p.principal, created: p.created, lastUsed: null, expires: null, ageDays: null, unusedDays: null, expiresInDays: null, status: "unknown", owner: p.owner || "unassigned", scope: "automountServiceAccountToken " + (p.meta.automountExplicit ? "true" : "unset (defaults to true)"), score: 0, flags: ["automount-default"], meta: {} }));
  emit("k8s_default_sa_automount", { title: "Default service account auto-mounts its token", severity: "low", confidence: "confirmed", category: "hygiene",
    description: defAuto.length + " namespace default service account(s) do not set automountServiceAccountToken: false, so every pod without an explicit SA gets an API token it rarely needs.",
    recommendation: "Set automountServiceAccountToken: false on the default SA in each namespace and give workloads their own SA.", controls: [C.cisK8s515, C.cisK8s516] }, defRows);

  // GitHub.
  const writeKeys = active.filter((c) => c.source === "github" && c.kind === "deploy_key" && c.meta.readOnly === false);
  for (const c of writeKeys) flag(c, "write-access", 15);
  emit("github_deploy_key_write", { title: "Deploy key with write access", severity: "medium", confidence: "confirmed", category: "privilege",
    description: writeKeys.length + " deploy key(s) can push to the repository. A deploy key is an unattributed SSH key: commits made with it carry no user identity.",
    recommendation: "Make deploy keys read-only; use a GitHub App installation or fine-grained token for pushes so actions are attributable.", controls: [C.ac6, C.t1552k, C.soc61] }, writeKeys);
  const allRepos = active.filter((c) => c.source === "github" && c.kind === "app_installation" && str(c.meta.repositorySelection).toLowerCase() === "all");
  for (const c of allRepos) flag(c, "all-repos", c.meta.writePermissions && c.meta.writePermissions.length ? 15 : 5);
  emit("github_installation_all_repos", { title: "GitHub App installed on all repositories", severity: allRepos.some((c) => c.meta.writePermissions && c.meta.writePermissions.length) ? "medium" : "low", confidence: "confirmed", category: "privilege",
    description: allRepos.length + " installation(s) use repository_selection \"all\", so new repositories are exposed to the app automatically" + (allRepos.some((c) => c.meta.writePermissions && c.meta.writePermissions.length) ? ", including write permissions (" + [...new Set(allRepos.flatMap((c) => c.meta.writePermissions))].sort(cmp).join(", ") + ")" : "") + ".",
    recommendation: "Switch to selected repositories and review the permission set against what the app actually does.", controls: [C.ac6, C.soc63] }, allRepos);

  // Ownership KPI flag on everything unassigned.
  for (const c of enriched) if (c.owner === "unassigned") flag(c, "unassigned-owner", 10);
  for (const c of enriched) c.flags.sort(cmp);

  // Calendar.
  const calendar = [];
  for (const c of enriched) {
    if (!c.active || c.managed) continue;
    const created = toTime(c.created), expires = c.expires === "never" ? null : toTime(c.expires);
    const base = { principal: c.principal, credential: c.credential, source: c.source, kind: c.kind, owner: c.owner };
    if (expires != null && expires <= now) continue;
    if (expires != null && !isNever(expires)) calendar.push(Object.assign({ date: isoDay(expires), action: "expires", daysFromNow: c.expiresInDays }, base));
    if (created != null && ROTATABLE.has(c.kind)) {
      const by = created + o.maxKeyAgeDays * DAY;
      if (expires == null || isNever(expires) || by < expires) calendar.push(Object.assign({ date: isoDay(by), action: "rotate by", daysFromNow: Math.ceil((by - now) / DAY) }, base));
    }
    if (c.meta.portalStatus === "expired" || c.meta.portalStatus === "expiring") calendar.push(Object.assign({ date: isoDay(now), action: "review", daysFromNow: 0 }, base));
  }
  calendar.sort((a, b) => cmp(a.date, b.date) || cmp(a.action, b.action) || cmp(a.source, b.source) || cmp(a.principal, b.principal) || cmp(a.credential, b.credential));

  // Tables.
  const credentials = enriched.map((c) => ({ source: c.source, principal: c.principal, principalType: c.principalType, kind: c.kind, credential: c.credential, created: c.created, lastUsed: c.lastUsed, expires: c.expires, ageDays: c.ageDays, unusedDays: c.unusedDays, expiresInDays: c.expiresInDays, active: c.active, status: c.status, owner: c.owner, scope: c.scope, score: c.score, flags: c.flags.slice() }))
    .sort((a, b) => b.score - a.score || cmp(a.source, b.source) || cmp(a.principal, b.principal) || cmp(a.kind, b.kind) || cmp(a.credential, b.credential));
  const principals = [...pmap.values()].map((p) => ({ source: p.source, principal: p.principal, principalId: p.principalId, principalType: p.principalType, enabled: p.enabled, owner: p.owner || "unassigned", created: p.created, credentials: p.credentials, oldestDays: p.oldestDays, roles: p.roles.slice(), highRiskRoles: (p.meta.highRiskRoles || []).slice() }))
    .sort((a, b) => cmp(a.source, b.source) || cmp(a.principal, b.principal));
  const bySource = {};
  for (const c of credentials) { const s = bySource[c.source] || (bySource[c.source] = { credentials: 0, principals: 0, flagged: 0 }); s.credentials++; if (c.flags.length) s.flagged++; }
  for (const p of principals) { const s = bySource[p.source] || (bySource[p.source] = { credentials: 0, principals: 0, flagged: 0 }); s.principals++; }
  const byStatus = {};
  for (const c of credentials) byStatus[c.status] = (byStatus[c.status] || 0) + 1;

  findings.sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || b.evidenceCount - a.evidenceCount || cmp(a.title, b.title));
  ctx?.progress?.(n, n, "done");
  const ownerlessCount = credentials.filter((c) => c.owner === "unassigned").length;
  const summary = {
    rows: rows.length, credentials: credentials.length, principals: principals.length, findings: findings.length,
    bySeverity: countBy(findings, "severity"), bySource: sortObj(bySource), byStatus: sortObj(byStatus),
    ownerless: ownerlessCount, expired: (byStatus.expired || 0), expiringSoon: credentials.filter((c) => c.expiresInDays != null && c.expiresInDays > 0 && c.expiresInDays <= o.expiryWarnDays[0]).length,
    overdue: byStatus.overdue || 0, neverUsed: byStatus["never-used"] || 0, unused: byStatus.unused || 0,
    nextExpiry: calendar.find((e) => e.action === "expires" && e.daysFromNow > 0) || null,
    calendarEntries: calendar.length,
  };
  return {
    summary, findings, tables: { credentials, principals, calendar }, skipped,
    meta: { tool: TOOL_ID, version: VERSION, rows: rows.length, now: now ? iso(now) : null, nowSource, options: { maxKeyAgeDays: o.maxKeyAgeDays, unusedDays: o.unusedDays, expiryWarnDays: o.expiryWarnDays, maxCertDays: o.maxCertDays, departed: o.departed.length }, files: files.map((f) => ({ name: f.name, format: f.format, confidence: f.confidence, records: f.records })) },
  };
}

function countBy(items, key) { const out = {}; for (const it of items) out[it[key]] = (out[it[key]] || 0) + 1; return sortObj(out); }
function sortObj(o) { const out = {}; for (const k of Object.keys(o).sort(cmp)) out[k] = o[k]; return out; }

// ---------------------------------------------------------------------------
// Exports: CSV / ICS events
// ---------------------------------------------------------------------------

function csvOf(rows, cols) {
  const cell = (v) => {
    let s = Array.isArray(v) ? v.join("; ") : v == null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  return [cols.join(","), ...(rows || []).map((r) => cols.map((c) => cell(r[c])).join(","))].join("\r\n") + "\r\n";
}

const FINDING_COLS = ["severity", "confidence", "category", "title", "description", "recommendation", "controls", "evidenceCount", "assets"];
/** Findings as CSV with fixed columns. */
export function findingsToCsv(findings) {
  return csvOf((findings || []).map((f) => ({
    severity: f.severity, confidence: f.confidence, category: f.category, title: f.title, description: f.description, recommendation: f.recommendation,
    controls: (f.controls || []).map((c) => c.framework + " " + c.id).join("; "), evidenceCount: f.evidenceCount != null ? f.evidenceCount : (f.evidence || []).length,
    assets: (f.assets || []).map((a) => a.name).join("; "),
  })), FINDING_COLS);
}

export const CREDENTIAL_COLS = ["source", "principal", "principalType", "kind", "credential", "created", "lastUsed", "expires", "ageDays", "unusedDays", "expiresInDays", "status", "owner", "scope", "score", "flags"];
/** Inventory table as CSV. */
export function credentialsToCsv(credentials) { return csvOf(credentials, CREDENTIAL_COLS); }

export const CALENDAR_COLS = ["date", "action", "daysFromNow", "source", "principal", "credential", "kind", "owner"];
/** Rotation calendar as CSV. */
export function calendarToCsv(calendar) { return csvOf(calendar, CALENDAR_COLS); }

const slug = (s) => String(s || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 60);

/** Calendar entries -> events for core/export.js toIcs (all-day, deterministic uid and stamp). */
export function calendarToEvents(calendar, now) {
  const stamp = toTime(now) != null ? iso(toTime(now)) : "1970-01-01T00:00:00Z";
  return (calendar || []).map((e, i) => ({
    uid: "nhi-" + slug(e.source + "-" + e.principal + "-" + e.credential + "-" + e.action) + "-" + i + "@darknode.ai",
    start: e.date, allDay: true, stamp,
    summary: "[" + e.action + "] " + e.principal + " - " + e.credential,
    description: "Source: " + e.source + "; kind: " + e.kind + "; owner: " + (e.owner || "unassigned") + "; action: " + e.action + ". Generated by Darknode Non-Human Identity Lifecycle.",
  }));
}

// ---------------------------------------------------------------------------
// Synthetic example (seeded, format-faithful) and self-test
// ---------------------------------------------------------------------------

const ANCHOR = Date.UTC(2026, 9, 1, 9, 0, 0); // 2026-10-01T09:00:00Z, the latest timestamp in the example

/** Synthetic multi-source dataset for "Load example (synthetic)" and tests. Not real data. */
export function exampleDataset(seed = 7) {
  let s = seed >>> 0;
  const rnd = () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 4294967296; };
  const hex = (n) => { let out = ""; for (let i = 0; i < n; i++) out += Math.floor(rnd() * 16).toString(16); return out; };
  const guid = () => hex(8) + "-" + hex(4) + "-4" + hex(3) + "-a" + hex(3) + "-" + hex(12);
  const at = (daysAgo, h = 9) => new Date(ANCHOR - daysAgo * DAY + (h - 9) * 3600000).toISOString().replace(/\.\d{3}Z$/, "+00:00");
  const atZ = (daysAgo) => new Date(ANCHOR - daysAgo * DAY).toISOString().replace(/\.\d{3}Z$/, "Z");
  const acct = "123456789012";
  const aws = [AWS_HEADERS.join(",")];
  const row = (o) => aws.push(AWS_HEADERS.map((h) => (o[h] === undefined ? "N/A" : o[h])).join(","));
  row({ user: "<root_account>", arn: "arn:aws:iam::" + acct + ":root", user_creation_time: at(1500), password_enabled: "not_supported", password_last_used: at(200), password_last_changed: "not_supported", password_next_rotation: "not_supported", mfa_active: "true", access_key_1_active: "false", access_key_2_active: "false", cert_1_active: "false", cert_2_active: "false" });
  row({ user: "svc-backup", arn: "arn:aws:iam::" + acct + ":user/svc-backup", user_creation_time: at(420), password_enabled: "false", password_last_used: "no_information", password_next_rotation: "N/A", mfa_active: "false", access_key_1_active: "true", access_key_1_last_rotated: at(400), access_key_1_last_used_date: at(0), access_key_1_last_used_region: "us-east-1", access_key_1_last_used_service: "s3", access_key_2_active: "false", cert_1_active: "false", cert_2_active: "false" });
  row({ user: "ci-deploy", arn: "arn:aws:iam::" + acct + ":user/ci-deploy", user_creation_time: at(130), password_enabled: "false", password_last_used: "no_information", password_next_rotation: "N/A", mfa_active: "false", access_key_1_active: "true", access_key_1_last_rotated: at(130), access_key_1_last_used_date: "N/A", access_key_1_last_used_region: "N/A", access_key_1_last_used_service: "N/A", access_key_2_active: "true", access_key_2_last_rotated: at(12), access_key_2_last_used_date: at(1), access_key_2_last_used_region: "eu-west-1", access_key_2_last_used_service: "ecr", cert_1_active: "false", cert_2_active: "false" });
  row({ user: "user01", arn: "arn:aws:iam::" + acct + ":user/user01", user_creation_time: at(700), password_enabled: "true", password_last_used: at(2), password_last_changed: at(60), password_next_rotation: at(-30), mfa_active: "true", access_key_1_active: "true", access_key_1_last_rotated: at(40), access_key_1_last_used_date: at(3), access_key_1_last_used_region: "us-east-1", access_key_1_last_used_service: "sts", access_key_2_active: "false", cert_1_active: "false", cert_2_active: "false" });
  row({ user: "terraform-prod", arn: "arn:aws:iam::" + acct + ":user/terraform-prod", user_creation_time: at(300), password_enabled: "false", password_last_used: "no_information", password_next_rotation: "N/A", mfa_active: "false", access_key_1_active: "true", access_key_1_last_rotated: at(80), access_key_1_last_used_date: at(100), access_key_1_last_used_region: "us-west-2", access_key_1_last_used_service: "ec2", access_key_2_active: "false", cert_1_active: "false", cert_2_active: "false" });
  row({ user: "app-ingest", arn: "arn:aws:iam::" + acct + ":user/app-ingest", user_creation_time: at(600), password_enabled: "false", password_last_used: "no_information", password_next_rotation: "N/A", mfa_active: "false", access_key_1_active: "false", access_key_1_last_rotated: at(500), access_key_1_last_used_date: at(300), access_key_1_last_used_region: "us-east-1", access_key_1_last_used_service: "kinesis", access_key_2_active: "false", cert_1_active: "false", cert_2_active: "false" });

  const app = (name, createdAgo, owners, pw, keys, roles) => ({
    id: guid(), appId: guid(), displayName: name, createdDateTime: atZ(createdAgo), signInAudience: "AzureADMyOrg",
    passwordCredentials: pw.map(([label, startAgo, endAgo]) => ({ keyId: guid(), displayName: label, startDateTime: atZ(startAgo), endDateTime: atZ(endAgo), hint: hex(3), customKeyIdentifier: null, secretText: null })),
    keyCredentials: keys.map(([label, startAgo, endAgo]) => ({ keyId: guid(), type: "AsymmetricX509Cert", usage: "Verify", startDateTime: atZ(startAgo), endDateTime: atZ(endAgo), displayName: label, customKeyIdentifier: hex(20).toUpperCase(), key: null })),
    requiredResourceAccess: roles.length ? [{ resourceAppId: GRAPH_APP, resourceAccess: roles.map((id) => ({ id, type: "Role" })) }] : [{ resourceAppId: GRAPH_APP, resourceAccess: [{ id: "e1fe6dd8-ba31-4d61-89e7-88639da4683d", type: "Scope" }] }],
    owners: owners.map((u) => ({ "@odata.type": "#microsoft.graph.user", userPrincipalName: u, displayName: u.split("@")[0] })),
  });
  const entra = { "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#applications", value: [
    app("Payroll Sync", 800, ["test@darknode.ai"], [["payroll-prod", 380, 15]], [], []),
    app("HR Connector", 400, ["test+hr@darknode.ai"], [["hr-2026", 345, -20]], [], []),
    app("Legacy Reporting", 1200, [], [["report-key", 500, -230], ["report-key-2", 120, -610]], [["reporting-cert", 400, -695]], ["19dbc75e-c2e2-444c-a770-ec69d8559fc7"]),
    app("Intranet Bot", 90, ["test+ops@darknode.ai"], [["bot-secret", 20, -345]], [], []),
  ] };

  const project = "testorg-prod-1234";
  const sa = (n) => n + "@" + project + ".iam.gserviceaccount.com";
  const gkey = (email, ageDays, origin) => ({ name: "projects/" + project + "/serviceAccounts/" + email + "/keys/" + hex(40), keyAlgorithm: "KEY_ALG_RSA_2048", keyOrigin: origin, keyType: "USER_MANAGED", validAfterTime: atZ(ageDays), validBeforeTime: "9999-12-31T23:59:59Z" });
  const gcpKeys = [gkey(sa("etl-runner"), 200, "GOOGLE_PROVIDED"), gkey(sa("bq-export"), 10, "USER_PROVIDED")];
  const gcpSas = [
    { displayName: "ETL runner", email: sa("etl-runner"), etag: "MDEwMjE5MjA=", name: "projects/" + project + "/serviceAccounts/" + sa("etl-runner"), oauth2ClientId: String(Math.floor(rnd() * 1e20)), projectId: project, uniqueId: String(Math.floor(rnd() * 1e20)) },
    { displayName: "BigQuery export", email: sa("bq-export"), etag: "MDEwMjE5MjA=", name: "projects/" + project + "/serviceAccounts/" + sa("bq-export"), oauth2ClientId: String(Math.floor(rnd() * 1e20)), projectId: project, uniqueId: String(Math.floor(rnd() * 1e20)) },
  ];

  const oktaDate = (daysAgo) => new Date(ANCHOR - daysAgo * DAY).toISOString().slice(0, 16).replace("T", " ") + " UTC";
  const okta = ["Name,Created,Created by,Last used,Expires,Token ID,Status",
    ["Terraform Okta provider", oktaDate(45), "test@darknode.ai", oktaDate(1), oktaDate(-29), "00T" + hex(20), "Active"].join(","),
    ["Old SIEM pull", oktaDate(400), "test+siem@darknode.ai", oktaDate(60), oktaDate(30), "00T" + hex(20), "Expired"].join(","),
    ["Onboarding script", oktaDate(20), "test+former@darknode.ai", "Never", oktaDate(-10), "00T" + hex(20), "Active"].join(","),
  ].join("\n");

  return {
    label: "synthetic example (not real data)",
    files: [
      { name: "credential-report.csv", text: aws.join("\n") + "\n" },
      { name: "entra-applications.json", text: JSON.stringify(entra, null, 2) },
      { name: "gcp-sa-keys.json", text: JSON.stringify(gcpKeys, null, 2) },
      { name: "gcp-service-accounts.json", text: JSON.stringify(gcpSas, null, 2) },
      { name: "okta-api-tokens.csv", text: okta + "\n" },
    ],
  };
}

/** Deterministic in-engine checks over the synthetic example. */
export function selfTest() {
  const tests = [];
  const t = (name, pass) => tests.push({ name, pass: !!pass });
  const ex = exampleDataset();
  const parsed = parseInput(ex.files);
  const r = analyze(parsed, { departed: ["test+former@darknode.ai"] });
  const has = (id) => r.findings.find((f) => f.id === TOOL_ID + ":" + id);
  const credOf = (principal, credential) => r.tables.credentials.find((c) => c.principal === principal && (!credential || c.credential === credential));
  t("all five example files detected with high confidence", parsed.files.length === 5 && parsed.files.every((f) => f.confidence >= 0.85));
  t("reference time is the latest timestamp in the data", r.meta.now === "2026-10-01T09:00:00Z" && r.meta.nowSource === "data");
  t("400-day AWS key is overdue", credOf("svc-backup", "access_key_1").status === "overdue" && !!has("key_overdue"));
  t("never-used AWS key detected", credOf("ci-deploy", "access_key_1").status === "never-used" && !!has("key_never_used"));
  t("two active keys on one user", !!has("aws_two_active_keys"));
  t("unused key beyond threshold", credOf("terraform-prod", "access_key_1").status === "unused");
  t("inactive key is not flagged for rotation", credOf("app-ingest", "access_key_1").status === "inactive");
  t("expired Entra secret is critical", has("entra_expired") && has("entra_expired").severity === "critical" && credOf("Payroll Sync").status === "expired");
  t("secret expiring in 20 days is high", has("cred_expiring_30") && has("cred_expiring_30").severity === "high" && credOf("HR Connector").expiresInDays === 20);
  t("ownerless app detected", has("entra_app_no_owner") && has("entra_app_no_owner").assets.some((a) => a.name === "Legacy Reporting"));
  t("multiple live secrets detected", !!has("entra_app_multiple_secrets"));
  t("Directory.ReadWrite.All app role detected", has("entra_app_high_risk_role") && /Directory\.ReadWrite\.All/.test(has("entra_app_high_risk_role").description));
  t("3-year certificate exceeds max validity", !!has("cert_validity_too_long"));
  t("healthy Intranet Bot has no flags", credOf("Intranet Bot").flags.length === 0 && credOf("Intranet Bot").status === "ok");
  t("user-managed never-expiring GCP keys", has("gcp_user_managed_key") && has("gcp_user_managed_key").evidenceCount === 2 && has("gcp_key_never_expires").evidenceCount === 2);
  t("departed-creator Okta token", has("okta_token_departed_creator") && has("okta_token_departed_creator").evidenceCount === 1);
  t("expired Okta token is low", has("cred_expired") && has("cred_expired").evidence.some((e) => e.principal === "Old SIEM pull"));
  t("calendar sorted ascending with no past expiry dates", r.tables.calendar.every((e, i, a) => (i === 0 || a[i - 1].date <= e.date) && (e.action !== "expires" || e.daysFromNow > 0)));
  t("every finding cites a control", r.findings.every((f) => f.controls.length >= 1 && f.severity && f.confidence && f.recommendation));
  t("ownerless KPI counts unassigned credentials", r.summary.ownerless === r.tables.credentials.filter((c) => c.owner === "unassigned").length && r.summary.ownerless > 0);
  t("deterministic", JSON.stringify(analyze(parsed)) === JSON.stringify(analyze(parseInput(exampleDataset().files))));
  t("empty input yields no findings", analyze([]).findings.length === 0);
  return { pass: tests.every((x) => x.pass), tests };
}
