// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Conditional Access Audit engine (caaudit). Pure: no DOM, no network, no clock;
// deterministic (same input -> byte-identical JSON). Runs inside a Blob module
// Worker and in node tests.
//
// Inputs (each optional, auto-detected per file):
//   1. Microsoft Entra Conditional Access policies JSON
//      (Graph GET /identity/conditionalAccess/policies, or
//       Get-MgIdentityConditionalAccessPolicy | ConvertTo-Json, PascalCase tolerated)
//   2. Entra "Authentication methods - User registration details" CSV (portal export)
//      or the Graph reports/authenticationMethods/userRegistrationDetails JSON
//   3. Okta policies JSON (GET /api/v1/policies?type=OKTA_SIGN_ON | MFA_ENROLL | ACCESS_POLICY,
//      with rules inline, under _embedded.rules, or a bare rules array)
//   4. Google Workspace 2-Step Verification user report CSV (Admin console > Reports > Users)
//
// Control references used in findings (real standards only):
//   CIS Microsoft 365 Foundations Benchmark 5.2.2.1-5.2.2.4
//   CISA SCuBA Secure Configuration Baseline for Entra ID: MS.AAD.1.1, 2.1, 2.3, 3.1, 3.2, 3.5, 3.6, 3.7
//   NIST SP 800-63B 4.2 (AAL2), 4.2.3 (AAL2 reauthentication), 4.3 (AAL3)
//   CIS Controls v8 6.3 / 6.5, CIS Google Workspace Foundations Benchmark 1.1 (2-Step Verification)
//   MITRE ATT&CK T1078, T1110, T1556.006, T1566, T1621
//   ISO/IEC 27001:2022 A.5.17, A.8.5 ; SOC 2 CC6.1

import { sniff, parseCsv, iterJson, findColumn, normHeader } from "../ingest/parse.js";

export const TOOL_ID = "caaudit";
export const VERSION = "1.0.0";

export const KINDS = {
  ENTRA_CA: "entra-ca",
  ENTRA_REG: "entra-registration",
  OKTA: "okta-policies",
  GOOGLE: "google-2sv",
  UNKNOWN: "unknown",
};

export const KIND_LABELS = {
  "entra-ca": "Entra Conditional Access policies (JSON)",
  "entra-registration": "Entra authentication-method registration (CSV/JSON)",
  "okta-policies": "Okta sign-on / enrollment policies (JSON)",
  "google-2sv": "Google Workspace 2-Step Verification report (CSV)",
  unknown: "Unrecognised export",
};

/** Column aliases per logical column, grouped by input kind (CSV-shaped inputs). */
export const COLUMNS = {
  registration: {
    upn: ["User principal name", "userPrincipalName", "upn", "user"],
    displayName: ["User display name", "userDisplayName", "display name", "name"],
    isAdmin: ["Is admin", "isAdmin", "admin"],
    isMfaCapable: ["Is MFA capable", "isMfaCapable", "mfa capable"],
    isMfaRegistered: ["Is MFA registered", "isMfaRegistered", "mfa registered"],
    isSsprRegistered: ["Is SSPR registered", "isSsprRegistered"],
    isSsprEnabled: ["Is SSPR enabled", "isSsprEnabled"],
    isSsprCapable: ["Is SSPR capable", "isSsprCapable"],
    isPasswordlessCapable: ["Is passwordless capable", "isPasswordlessCapable"],
    methodsRegistered: ["Methods registered", "methodsRegistered", "authentication methods", "methods"],
    defaultMfaMethod: ["Default MFA method", "defaultMfaMethod", "default method"],
    systemPreferredMethod: ["System preferred method", "systemPreferredAuthenticationMethods", "system preferred"],
    lastUpdated: ["Last updated", "lastUpdatedDateTime"],
  },
  google: {
    userName: ["User Name", "full name", "user_name"],
    email: ["Email", "user email", "primary email", "user_email", "email address"],
    enrolled: ["2-Step Verification Enrollment", "2SV Enrollment", "2sv_enrolled", "is_2sv_enrolled", "2sv enrollment", "2-Step Verification enrolled"],
    enforced: ["2-Step Verification Enforcement", "2SV Enforcement", "2sv_enforced", "is_2sv_enforced", "2sv enforcement"],
    adminStatus: ["Admin Status", "is_admin", "isAdmin", "admin", "role"],
    lastLogin: ["Last Login", "last_login_time", "last sign in", "last login time"],
    suspended: ["Is Suspended", "suspended", "is_suspended"],
  },
};

/** Tunable thresholds; the UI renders these as the settings panel. */
export const DEFAULTS = {
  breakGlassMax: 2,            // excluded named users allowed on an all-users MFA policy
  oktaMaxSessionHours: 24,     // Okta maxSessionLifetimeMinutes above this is weak
  oktaMaxIdleMinutes: 120,     // Okta maxSessionIdleMinutes above this is weak
  maxFactorLifetimeHours: 12,  // Okta factor lifetime / Entra sign-in frequency above this is weak (NIST AAL2: 12 h)
  evidenceRows: 50,            // evidence rows kept per finding (full count in evidenceCount)
};

// ---------------------------------------------------------------------------
// Controls
// ---------------------------------------------------------------------------
const C = {
  cis5221: { framework: "CIS M365", id: "5.2.2.1" },
  cis5222: { framework: "CIS M365", id: "5.2.2.2" },
  cis5223: { framework: "CIS M365", id: "5.2.2.3" },
  cis5224: { framework: "CIS M365", id: "5.2.2.4" },
  scuba11: { framework: "CISA SCuBA", id: "MS.AAD.1.1" },
  scuba21: { framework: "CISA SCuBA", id: "MS.AAD.2.1" },
  scuba23: { framework: "CISA SCuBA", id: "MS.AAD.2.3" },
  scuba31: { framework: "CISA SCuBA", id: "MS.AAD.3.1" },
  scuba32: { framework: "CISA SCuBA", id: "MS.AAD.3.2" },
  scuba35: { framework: "CISA SCuBA", id: "MS.AAD.3.5" },
  scuba36: { framework: "CISA SCuBA", id: "MS.AAD.3.6" },
  scuba37: { framework: "CISA SCuBA", id: "MS.AAD.3.7" },
  nistAal2: { framework: "NIST SP 800-63B", id: "4.2 (AAL2)" },
  nistReauth: { framework: "NIST SP 800-63B", id: "4.2.3" },
  nistAal3: { framework: "NIST SP 800-63B", id: "4.3 (AAL3)" },
  cisc63: { framework: "CIS Controls v8", id: "6.3" },
  cisc65: { framework: "CIS Controls v8", id: "6.5" },
  cisGws: { framework: "CIS Google Workspace", id: "1.1" },
  t1078: { framework: "MITRE", id: "T1078" },
  t1110: { framework: "MITRE", id: "T1110" },
  t1556: { framework: "MITRE", id: "T1556.006" },
  t1566: { framework: "MITRE", id: "T1566" },
  t1621: { framework: "MITRE", id: "T1621" },
  iso517: { framework: "ISO27001", id: "A.5.17" },
  iso85: { framework: "ISO27001", id: "A.8.5" },
  soc2: { framework: "SOC2", id: "CC6.1" },
};

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
const str = (v) => (v == null ? "" : String(v)).trim();
const lower = (v) => str(v).toLowerCase();
const upper = (v) => str(v).toUpperCase();
const arr = (v) => (Array.isArray(v) ? v.filter((x) => x != null).map((x) => (typeof x === "object" ? JSON.stringify(x) : String(x))) : v == null || v === "" ? [] : [String(v)]);
const num = (v) => { const n = Number(v); return Number.isFinite(n) ? n : null; };
const uniqSorted = (list) => Array.from(new Set(list)).sort();
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/** Loose boolean: true / false / null (unknown). Understands vendor words. */
export function bool(v) {
  if (v === true || v === false) return v;
  const s = lower(v);
  if (!s) return null;
  if (/^(true|yes|y|1|enrolled|enforced|enabled|registered|capable|on)$/.test(s)) return true;
  if (/^(false|no|n|0|not enrolled|not enforced|disabled|not registered|none|off|n\/a)$/.test(s)) return false;
  if (/^not\s/.test(s)) return false;
  return null;
}

/** Split a vendor method list ("a;b", "a, b", "a|b", or an array). */
export function splitList(v) {
  if (Array.isArray(v)) return v.map(str).filter(Boolean);
  const s = str(v);
  if (!s) return [];
  return s.split(/[;,|]+/).map((x) => x.trim()).filter(Boolean);
}

// Phishing-resistant registered methods (Entra authentication-method names).
const PR_METHOD_RE = /^(fido2|passkey|windowshelloforbusiness|certificatebasedauthentication|x509|macossecureenclavekey|microsoftauthenticatorpasskey)/;
export function isPhishingResistantMethod(m) {
  return PR_METHOD_RE.test(lower(m).replace(/[^a-z0-9]/g, ""));
}
// Weak default methods: SMS / voice / email (SCuBA MS.AAD.3.5).
const WEAK_DEFAULT_RE = /^(mobilephone|alternatemobilephone|officephone|sms|voice|voicecall|email|phone|textmessage)/;
export function isWeakDefaultMethod(m) {
  const s = lower(m).replace(/[^a-z0-9]/g, "");
  return !!s && WEAK_DEFAULT_RE.test(s);
}
// Phishing-resistant authentication-strength combinations (Entra).
const PR_COMBOS = new Set(["fido2", "windowshelloforbusiness", "x509certificatemultifactor", "x509certificatesinglefactor"]);
export function isPhishingResistantStrength(s) {
  if (!s) return false;
  if (/000000000004$/.test(str(s.id))) return true;
  if (/phishing/i.test(str(s.displayName))) return true;
  const combos = (s.allowedCombinations || []).map((c) => lower(c).replace(/[^a-z0-9]/g, ""));
  return combos.length > 0 && combos.every((c) => PR_COMBOS.has(c));
}

/** Lower-case the first character of every key, recursively (PowerShell PascalCase tolerance). */
export function camelKeys(o) {
  if (Array.isArray(o)) return o.map(camelKeys);
  if (o === null || typeof o !== "object") return o;
  const out = {};
  for (const k of Object.keys(o)) out[k.charAt(0).toLowerCase() + k.slice(1)] = camelKeys(o[k]);
  return out;
}

function normState(s) {
  const v = lower(s).replace(/[^a-z]/g, "");
  if (v === "enabled" || v === "on" || v === "active") return "enabled";
  if (v === "disabled" || v === "off" || v === "inactive") return "disabled";
  if (v.startsWith("enabledforreporting") || v === "reportonly") return "report-only";
  return v || "unknown";
}

// ---------------------------------------------------------------------------
// Source classification
// ---------------------------------------------------------------------------
function keyset(row) {
  const out = new Set();
  const walk = (o, depth) => {
    if (!o || typeof o !== "object" || depth > 2) return;
    for (const k of Object.keys(o)) { out.add(k.charAt(0).toLowerCase() + k.slice(1)); if (depth < 2 && o[k] && typeof o[k] === "object" && !Array.isArray(o[k])) walk(o[k], depth + 1); }
  };
  walk(row, 0);
  return out;
}

/** Decide which vendor export a parsed source is. Returns { kind, confidence: "high"|"medium"|"low" }. */
export function classify(headers, rows) {
  const hs = (headers || []).map(normHeader);
  const has = (aliases) => aliases.some((a) => hs.includes(normHeader(a)));
  const first = (rows || []).find((r) => r && typeof r === "object") || {};
  const ks = keyset(first);
  const c = camelKeys(first);

  // Entra Conditional Access policy object
  if (ks.has("conditions") && (ks.has("grantControls") || ks.has("sessionControls"))) return { kind: KINDS.ENTRA_CA, confidence: "high" };
  if (ks.has("conditions") && ks.has("displayName") && ks.has("state")) return { kind: KINDS.ENTRA_CA, confidence: "high" };
  // Okta policy / rule objects
  const oktaType = upper(c.type);
  if (/^(OKTA_SIGN_ON|MFA_ENROLL|ACCESS_POLICY|PASSWORD|IDP_DISCOVERY|PROFILE_ENROLLMENT)$/.test(oktaType)) return { kind: KINDS.OKTA, confidence: "high" };
  if (c.actions && (c.actions.signon || c.actions.appSignOn)) return { kind: KINDS.OKTA, confidence: "high" };
  if (Array.isArray(c.rules) || (c._embedded && Array.isArray(c._embedded.rules))) return { kind: KINDS.OKTA, confidence: "medium" };
  if (c.conditions && c.conditions.people) return { kind: KINDS.OKTA, confidence: "medium" };
  if (ks.has("conditions") && (ks.has("users") || ks.has("applications"))) return { kind: KINDS.ENTRA_CA, confidence: "medium" };
  // Entra registration details (CSV or Graph JSON)
  const regUpn = has(COLUMNS.registration.upn), regMfa = has(COLUMNS.registration.isMfaRegistered), regMethods = has(COLUMNS.registration.methodsRegistered);
  if (regUpn && (regMfa || regMethods) && (has(COLUMNS.registration.isAdmin) || has(COLUMNS.registration.isMfaCapable))) return { kind: KINDS.ENTRA_REG, confidence: "high" };
  if ((regMfa || regMethods) && regUpn) return { kind: KINDS.ENTRA_REG, confidence: "medium" };
  // Google 2SV report
  const gEnr = has(COLUMNS.google.enrolled), gMail = has(COLUMNS.google.email);
  if (gEnr && gMail) return { kind: KINDS.GOOGLE, confidence: "high" };
  if (gEnr || has(COLUMNS.google.enforced)) return { kind: KINDS.GOOGLE, confidence: "medium" };
  if (regMfa || regMethods) return { kind: KINDS.ENTRA_REG, confidence: "low" };
  return { kind: KINDS.UNKNOWN, confidence: "low" };
}

// ---------------------------------------------------------------------------
// parseInput: string | {name,text} | array of either -> dataset
// ---------------------------------------------------------------------------
function parseOne(name, text) {
  const t = String(text || "");
  const skipped = [];
  if (!t.trim()) return { name, format: "empty", confidence: 0, headers: [], rows: [], kind: KINDS.UNKNOWN, kindConfidence: "low", skipped };
  const sn = sniff(t);
  let headers = [], rows = [], format = sn.format;
  if (sn.format === "json" || sn.format === "ndjson" || /^\s*[[{]/.test(t)) {
    try {
      for (const r of iterJson(t)) if (r && typeof r === "object") rows.push(r);
      format = "json";
      const keys = new Set(); for (const r of rows) for (const k of Object.keys(r)) keys.add(k);
      headers = Array.from(keys);
    } catch (e) {
      skipped.push({ check: "parse", reason: name + ": invalid JSON (" + String(e && e.message || e) + ")" });
      return { name, format: "json", confidence: 0, headers: [], rows: [], kind: KINDS.UNKNOWN, kindConfidence: "low", skipped };
    }
  } else if (sn.format === "csv" || sn.format === "tsv" || sn.format === "unknown") {
    const p = parseCsv(t, sn.delimiter ? { delimiter: sn.delimiter } : {});
    headers = p.headers; rows = p.rows; format = sn.format === "tsv" ? "tsv" : "csv";
  } else {
    skipped.push({ check: "parse", reason: name + ": " + sn.format + " is not a supported export for this tool" });
    return { name, format: sn.format, confidence: sn.confidence, headers: [], rows: [], kind: KINDS.UNKNOWN, kindConfidence: "low", skipped };
  }
  // Graph userRegistrationDetails JSON: arrays of methods -> joined string so the CSV path applies.
  if (format === "json" && rows.length && rows.some((r) => Array.isArray(r.methodsRegistered) || Array.isArray(r.MethodsRegistered))) {
    rows = rows.map((r) => { const o = { ...r }; for (const k of Object.keys(o)) if (Array.isArray(o[k]) && o[k].every((x) => typeof x !== "object")) o[k] = o[k].join(";"); return o; });
  }
  const cls = classify(headers, rows);
  return { name, format, confidence: sn.confidence == null ? 1 : sn.confidence, headers, rows, kind: cls.kind, kindConfidence: cls.confidence, skipped };
}

/**
 * Parse one or many exports. Accepts a string, {name,text}, or an array of either.
 * Returns { format, headers, rows, skipped, sources: [{ name, format, confidence, kind, kindConfidence, headers, rows }] }.
 * Never throws on bad input; problems land in skipped.
 */
export function parseInput(input) {
  const list = Array.isArray(input) ? input : [input];
  const sources = [];
  let i = 0;
  for (const it of list) {
    i++;
    if (it == null) continue;
    const name = typeof it === "object" ? str(it.name) || "file-" + i : "file-" + i;
    const text = typeof it === "object" ? it.text : it;
    sources.push(parseOne(name, text));
  }
  sources.sort((a, b) => cmp(a.name, b.name));
  const skipped = sources.flatMap((s) => s.skipped);
  const first = sources.find((s) => s.rows.length) || sources[0] || { format: "empty", headers: [], rows: [] };
  const rows = sources.flatMap((s) => s.rows);
  return { format: sources.length > 1 ? "multi" : first.format, headers: first.headers, rows, skipped, sources };
}

// ---------------------------------------------------------------------------
// Normalisers
// ---------------------------------------------------------------------------
/** Normalise one Entra CA policy object (camel or Pascal case). */
export function normEntraPolicy(p0) {
  const p = camelKeys(p0 || {});
  const c = p.conditions || {}, u = c.users || {}, a = c.applications || {}, g = p.grantControls || {}, s = p.sessionControls || {};
  const loc = c.locations || {}, plat = c.platforms || {};
  const as = g.authenticationStrength;
  const sif = s.signInFrequency, pb = s.persistentBrowser;
  const builtIn = arr(g.builtInControls).map(lower);
  const out = {
    id: str(p.id), name: str(p.displayName || p.name) || str(p.id) || "(unnamed policy)",
    state: normState(p.state),
    includeUsers: arr(u.includeUsers), excludeUsers: arr(u.excludeUsers),
    includeGroups: arr(u.includeGroups), excludeGroups: arr(u.excludeGroups),
    includeRoles: arr(u.includeRoles), excludeRoles: arr(u.excludeRoles),
    includeGuests: !!(u.includeGuestsOrExternalUsers && (u.includeGuestsOrExternalUsers.guestOrExternalUserTypes || typeof u.includeGuestsOrExternalUsers === "string")),
    includeApps: arr(a.includeApplications), excludeApps: arr(a.excludeApplications), userActions: arr(a.includeUserActions),
    clientAppTypes: arr(c.clientAppTypes).map(lower), clientAppTypesRaw: arr(c.clientAppTypes),
    platforms: arr(plat.includePlatforms).map(lower),
    includeLocations: arr(loc.includeLocations), excludeLocations: arr(loc.excludeLocations),
    signInRiskLevels: arr(c.signInRiskLevels).map(lower), userRiskLevels: arr(c.userRiskLevels).map(lower),
    deviceFilter: c.devices && c.devices.deviceFilter ? str(c.devices.deviceFilter.rule) : "",
    grantOperator: upper(g.operator) || "OR",
    builtInControls: builtIn,
    authStrength: as && typeof as === "object" ? { id: str(as.id), displayName: str(as.displayName), allowedCombinations: arr(as.allowedCombinations) } : null,
    signInFrequency: sif && typeof sif === "object" ? { isEnabled: bool(sif.isEnabled) === true, value: num(sif.value), type: lower(sif.type), interval: lower(sif.frequencyInterval) } : null,
    persistentBrowser: pb && typeof pb === "object" ? { isEnabled: bool(pb.isEnabled) === true, mode: lower(pb.mode) } : null,
    appEnforcedRestrictions: !!(s.applicationEnforcedRestrictions && bool(s.applicationEnforcedRestrictions.isEnabled)),
    cloudAppSecurity: s.cloudAppSecurity && bool(s.cloudAppSecurity.isEnabled) ? lower(s.cloudAppSecurity.cloudAppSecurityType) || "enabled" : "",
  };
  out.allUsers = out.includeUsers.some((x) => lower(x) === "all");
  out.allApps = out.includeApps.some((x) => lower(x) === "all");
  out.requiresMfa = builtIn.includes("mfa") || !!out.authStrength;
  out.phishingResistant = isPhishingResistantStrength(out.authStrength);
  out.blocks = builtIn.includes("block");
  out.requiresManagedDevice = builtIn.includes("compliantdevice") || builtIn.includes("domainjoineddevice");
  out.targetsLegacy = out.clientAppTypes.includes("exchangeactivesync") || out.clientAppTypes.includes("other");
  out.riskBased = out.signInRiskLevels.length > 0 || out.userRiskLevels.length > 0;
  out.securityRelevant = out.requiresMfa || out.blocks || out.requiresManagedDevice || out.riskBased || /mfa|block|legacy|compliant|risk|phish|admin|privileg/i.test(out.name);
  out.sifHours = out.signInFrequency && out.signInFrequency.isEnabled && out.signInFrequency.value != null
    ? out.signInFrequency.value * (out.signInFrequency.type === "days" ? 24 : 1) : null;
  return out;
}

function normOktaRule(r0, policyName) {
  const r = r0 || {};
  const act = r.actions || {}, so = act.signon || {}, app = act.appSignOn || {};
  const vm = app.verificationMethod || {};
  const cond = r.conditions || {}, net = cond.network || {}, ac = cond.authContext || {}, ppl = cond.people || {};
  const sess = so.session || {};
  const access = upper(so.access || app.access) || "ALLOW";
  const requireFactor = so.requireFactor === true || (vm.factorMode != null && upper(vm.factorMode) === "2FA");
  return {
    id: str(r.id), name: str(r.name) || "(unnamed rule)", policy: policyName,
    status: upper(r.status) || "ACTIVE", priority: num(r.priority), system: r.system === true,
    access, requireFactor,
    factorPromptMode: upper(so.factorPromptMode), factorLifetime: num(so.factorLifetime),
    reauthenticateIn: str(vm.reauthenticateIn),
    sessionIdle: num(sess.maxSessionIdleMinutes), sessionLifetime: num(sess.maxSessionLifetimeMinutes), persistentCookie: sess.usePersistentCookie === true,
    network: { connection: upper(net.connection) || "ANYWHERE", include: arr(net.include), exclude: arr(net.exclude) },
    authType: upper(ac.authType) || "ANY",
    usersInclude: arr(ppl.users && ppl.users.include), usersExclude: arr(ppl.users && ppl.users.exclude),
    groupsInclude: arr(ppl.groups && ppl.groups.include), groupsExclude: arr(ppl.groups && ppl.groups.exclude),
  };
}

function normOktaEnroll(settings) {
  const s = settings || {};
  const out = [];
  if (s.factors && typeof s.factors === "object") for (const k of Object.keys(s.factors)) out.push({ name: k, self: upper(s.factors[k] && s.factors[k].enroll && s.factors[k].enroll.self) || "OPTIONAL" });
  if (Array.isArray(s.authenticators)) for (const a of s.authenticators) out.push({ name: str(a.key || a.name), self: upper(a.enroll && a.enroll.self) || "OPTIONAL" });
  return out.sort((a, b) => cmp(a.name, b.name));
}

/** Normalise one Okta policy object (or a bare rule, wrapped). */
export function normOktaPolicy(p0) {
  const p = p0 || {};
  const isRule = !!(p.actions && (p.actions.signon || p.actions.appSignOn));
  if (isRule) {
    const r = normOktaRule(p, "(rules export)");
    return { id: "", name: "(rules export)", type: "OKTA_SIGN_ON", status: "ACTIVE", priority: null, system: false, everyone: true, usersInclude: [], usersExclude: [], groupsInclude: [], groupsExclude: [], rules: [r], enroll: [], fromRules: true };
  }
  const cond = p.conditions || {}, ppl = cond.people || {};
  const rulesRaw = Array.isArray(p.rules) ? p.rules : p._embedded && Array.isArray(p._embedded.rules) ? p._embedded.rules : [];
  const name = str(p.name) || str(p.id) || "(unnamed policy)";
  const groupsInclude = arr(ppl.groups && ppl.groups.include), usersInclude = arr(ppl.users && ppl.users.include);
  const out = {
    id: str(p.id), name, type: upper(p.type) || "OKTA_SIGN_ON", status: upper(p.status) || "ACTIVE", priority: num(p.priority), system: p.system === true,
    usersInclude, usersExclude: arr(ppl.users && ppl.users.exclude), groupsInclude, groupsExclude: arr(ppl.groups && ppl.groups.exclude),
    rules: rulesRaw.map((r) => normOktaRule(r, name)).sort((a, b) => cmp(a.priority == null ? 1e9 : a.priority, b.priority == null ? 1e9 : b.priority) || cmp(a.name, b.name)),
    enroll: normOktaEnroll(p.settings),
    fromRules: false,
  };
  out.everyone = out.system || /^default policy$/i.test(name) || (groupsInclude.length === 0 && usersInclude.length === 0);
  return out;
}

// ---------------------------------------------------------------------------
// Column resolution for CSV-shaped inputs
// ---------------------------------------------------------------------------
function resolveCols(headers, spec, override) {
  const cols = {};
  for (const k of Object.keys(spec)) {
    const forced = override && override[k] && headers.includes(override[k]) ? override[k] : null;
    const h = forced || findColumn(headers, spec[k]);
    if (h) cols[k] = h;
  }
  return cols;
}

// ---------------------------------------------------------------------------
// analyze
// ---------------------------------------------------------------------------
function makeFinding(f, o) {
  const ev = Array.isArray(f.evidence) ? f.evidence : [];
  return {
    id: f.id, title: f.title, severity: f.severity, confidence: f.confidence, category: f.category,
    description: f.description, recommendation: f.recommendation, controls: f.controls,
    evidence: ev.slice(0, o.evidenceRows), evidenceCount: f.evidenceCount != null ? f.evidenceCount : ev.length,
    assets: (f.assets || []).slice(0, 200), tags: f.tags || [],
  };
}

function policyAsset(p, source) {
  return { type: "ASSET", name: p.name, data: { kind: "ca-policy", source, state: p.state || p.status, id: p.id } };
}
function identityAsset(name, data) { return { type: "IDENTITY", name, data }; }

function entraPolicyRow(p) {
  const grant = [];
  if (p.blocks) grant.push("block");
  if (p.builtInControls.includes("mfa")) grant.push("mfa");
  if (p.authStrength) grant.push("auth strength: " + (p.authStrength.displayName || p.authStrength.id || "custom") + (p.phishingResistant ? " (phishing-resistant)" : ""));
  for (const c of p.builtInControls) if (!["block", "mfa"].includes(c)) grant.push(c);
  const session = [];
  if (p.signInFrequency && p.signInFrequency.isEnabled) session.push("sign-in frequency " + (p.signInFrequency.value != null ? p.signInFrequency.value + " " + p.signInFrequency.type : p.signInFrequency.interval || "on"));
  if (p.persistentBrowser && p.persistentBrowser.isEnabled) session.push("persistent browser: " + (p.persistentBrowser.mode || "on"));
  if (p.appEnforcedRestrictions) session.push("app-enforced restrictions");
  if (p.cloudAppSecurity) session.push("cloud app security: " + p.cloudAppSecurity);
  const who = (list, all) => (all ? "All users" : list.length ? list.join("; ") : "");
  return {
    source: "Entra", policy: p.name, state: p.state,
    includedUsers: who(p.includeUsers, p.allUsers), includedGroups: p.includeGroups.join("; "), includedRoles: p.includeRoles.join("; "),
    excludedUsers: p.excludeUsers.join("; "), excludedGroups: p.excludeGroups.join("; "), excludedRoles: p.excludeRoles.join("; "),
    apps: p.allApps ? "All cloud apps" : p.includeApps.concat(p.userActions).join("; "), excludedApps: p.excludeApps.join("; "),
    clientApps: p.clientAppTypesRaw.join("; "), platforms: p.platforms.join("; "),
    locations: [p.includeLocations.length ? "include " + p.includeLocations.join("; ") : "", p.excludeLocations.length ? "exclude " + p.excludeLocations.join("; ") : ""].filter(Boolean).join(" / "),
    risk: [p.signInRiskLevels.length ? "sign-in " + p.signInRiskLevels.join("/") : "", p.userRiskLevels.length ? "user " + p.userRiskLevels.join("/") : ""].filter(Boolean).join("; "),
    grant: grant.join(p.grantOperator === "AND" ? " AND " : " OR "),
    session: session.join("; "),
    excludedUserCount: p.excludeUsers.length,
  };
}

function oktaPolicyRow(p, r) {
  const grant = [];
  if (r) {
    grant.push(r.access);
    if (r.requireFactor) grant.push("require factor");
    if (r.factorPromptMode) grant.push("prompt " + r.factorPromptMode + (r.factorLifetime != null ? " " + r.factorLifetime + " min" : ""));
  } else if (p.enroll.length) grant.push(p.enroll.map((e) => e.name + ": " + e.self).join("; "));
  const session = r ? [r.sessionLifetime != null ? "lifetime " + r.sessionLifetime + " min" : "", r.sessionIdle != null ? "idle " + r.sessionIdle + " min" : "", r.persistentCookie ? "persistent cookie" : "", r.reauthenticateIn ? "re-auth " + r.reauthenticateIn : ""].filter(Boolean).join("; ") : "";
  return {
    source: "Okta", policy: p.name + (r ? " / " + r.name : ""), state: (r ? r.status : p.status).toLowerCase() + (p.type ? " (" + p.type + ")" : ""),
    includedUsers: p.everyone && !(r && (r.usersInclude.length || r.groupsInclude.length)) ? "Everyone" : (r ? r.usersInclude : p.usersInclude).join("; "),
    includedGroups: (r && r.groupsInclude.length ? r.groupsInclude : p.groupsInclude).join("; "), includedRoles: "",
    excludedUsers: (r ? r.usersExclude : p.usersExclude).join("; "), excludedGroups: (r ? r.groupsExclude : p.groupsExclude).join("; "), excludedRoles: "",
    apps: p.type === "ACCESS_POLICY" ? "app sign-on" : p.type === "MFA_ENROLL" ? "enrollment" : "Okta session", excludedApps: "",
    clientApps: r ? r.authType : "", platforms: "",
    locations: r ? r.network.connection + (r.network.include.length ? " include " + r.network.include.join("; ") : "") + (r.network.exclude.length ? " exclude " + r.network.exclude.join("; ") : "") : "",
    risk: "", grant: grant.join("; "), session, excludedUserCount: (r ? r.usersExclude : p.usersExclude).length,
  };
}

/**
 * Analyse a dataset from parseInput (or a plain array of rows, which is classified as one source).
 * opts overrides DEFAULTS; opts.columnMap = { registration: {upn: "<header>", ...}, google: {...} } forces columns.
 * ctx.progress(done, total, label) is optional and is called every ~1000 rows.
 */
export function analyze(dataset, opts = {}, ctx) {
  const o = { ...DEFAULTS, ...(opts || {}) };
  for (const k of Object.keys(DEFAULTS)) if (!Number.isFinite(Number(o[k]))) o[k] = DEFAULTS[k]; else o[k] = Number(o[k]);
  const colMap = (opts && opts.columnMap) || {};
  const skipped = [];
  const findings = [];
  const tables = { policies: [], registrations: [], googleUsers: [], oktaEnrollment: [] };
  const summary = { rows: 0, sources: [], findings: 0, bySeverity: {}, entra: null, registration: null, okta: null, google: null };

  let sources;
  if (Array.isArray(dataset)) {
    const rows = dataset.filter((r) => r && typeof r === "object");
    const keys = new Set(); for (const r of rows) for (const k of Object.keys(r)) keys.add(k);
    const cls = classify(Array.from(keys), rows);
    sources = [{ name: "input", format: "rows", confidence: 1, headers: Array.from(keys), rows, kind: cls.kind, kindConfidence: cls.confidence, skipped: [] }];
  } else {
    sources = (dataset && Array.isArray(dataset.sources) ? dataset.sources : []).map((s) => ({ ...s, rows: Array.isArray(s.rows) ? s.rows : [], headers: Array.isArray(s.headers) ? s.headers : [] }));
    for (const s of dataset && Array.isArray(dataset.skipped) ? dataset.skipped : []) skipped.push(s);
  }
  if (opts && opts.kindOverride && typeof opts.kindOverride === "object") {
    for (const s of sources) if (opts.kindOverride[s.name] && KIND_LABELS[opts.kindOverride[s.name]]) { s.kind = opts.kindOverride[s.name]; s.kindConfidence = "high"; }
  }
  const total = sources.reduce((n, s) => n + s.rows.length, 0);
  let done = 0;
  const tick = (label) => { if ((done - 1) % 1000 === 0) ctx?.progress?.(done - 1, total, label); };
  const push = (f) => findings.push(makeFinding(f, o));

  for (const s of sources) {
    summary.sources.push({ name: s.name, kind: s.kind, rows: s.rows.length });
    if (s.kind === KINDS.UNKNOWN && s.rows.length) skipped.push({ check: "classify", reason: s.name + ": export format not recognised (expected Entra CA policies JSON, Entra registration CSV, Okta policies JSON or Google 2SV CSV)" });
  }
  summary.rows = total;

  // ----- Entra Conditional Access policies ---------------------------------
  const entraPolicies = [];
  for (const s of sources) if (s.kind === KINDS.ENTRA_CA) for (const r of s.rows) { entraPolicies.push(normEntraPolicy(r)); done++; tick("Entra policies"); }
  entraPolicies.sort((a, b) => cmp(a.name, b.name) || cmp(a.id, b.id));
  if (!entraPolicies.length) {
    skipped.push({ check: "entra_policies", reason: "no Entra Conditional Access policies JSON loaded (MFA-for-all, legacy auth, exclusions, risk, device and session checks skipped)" });
  } else {
    const enabled = entraPolicies.filter((p) => p.state === "enabled");
    const reportOnly = entraPolicies.filter((p) => p.state === "report-only");
    for (const p of entraPolicies) tables.policies.push(entraPolicyRow(p));
    const row = (p) => entraPolicyRow(p);

    // 1. MFA for all users
    const mfaAll = enabled.filter((p) => p.allUsers && p.requiresMfa && !p.blocks);
    const mfaAllReport = reportOnly.filter((p) => p.allUsers && p.requiresMfa && !p.blocks);
    const mfaAny = entraPolicies.filter((p) => p.requiresMfa && !p.blocks);
    if (!mfaAll.length) {
      push({
        id: "no_mfa_all_users", title: "No enforced Conditional Access policy requires MFA for all users", severity: "critical", confidence: "likely", category: "mfa",
        description: entraPolicies.length + " polic" + (entraPolicies.length === 1 ? "y" : "ies") + " loaded; none that is enabled targets All users with an MFA grant or authentication strength." +
          (mfaAllReport.length ? " " + mfaAllReport.length + " all-users MFA polic" + (mfaAllReport.length === 1 ? "y is" : "ies are") + " in report-only mode (" + mfaAllReport.map((p) => p.name).join(", ") + ")." : "") +
          " Per-user MFA or Security Defaults are not visible in this export; confirm them before closing.",
        recommendation: "Create an enabled policy: Users = All users (exclude only break-glass accounts), Cloud apps = All, Grant = Require authentication strength (phishing-resistant preferred) or Require MFA.",
        controls: [C.cis5222, C.scuba32, C.nistAal2, C.cisc63, C.t1078, C.t1110],
        evidence: mfaAny.map(row), assets: mfaAny.map((p) => policyAsset(p, "Entra")),
      });
    }
    // 2. Legacy authentication
    const legacyBlock = enabled.filter((p) => p.blocks && p.targetsLegacy);
    const legacyAll = legacyBlock.filter((p) => p.allUsers);
    const legacyReport = reportOnly.filter((p) => p.blocks && p.targetsLegacy);
    if (!legacyAll.length) {
      push({
        id: "legacy_auth_not_blocked", title: "Legacy authentication is not blocked for all users", severity: "high", confidence: "likely", category: "legacy-auth",
        description: legacyBlock.length
          ? "Only " + legacyBlock.map((p) => p.name).join(", ") + " block" + (legacyBlock.length === 1 ? "s" : "") + " Exchange ActiveSync / other clients, and " + (legacyBlock.length === 1 ? "it" : "they") + " do" + (legacyBlock.length === 1 ? "es" : "") + " not target All users."
          : "No enabled policy has Client apps = Exchange ActiveSync clients + Other clients with Grant = Block." +
            (legacyReport.length ? " Report-only: " + legacyReport.map((p) => p.name).join(", ") + "." : "") +
            " Basic authentication may still be disabled tenant-wide in Exchange Online; that setting is outside this export.",
        recommendation: "Enable a policy with Users = All users, Cloud apps = All, Client apps = Exchange ActiveSync clients and Other clients, Grant = Block access.",
        controls: [C.cis5223, C.scuba11, C.t1110, C.t1078],
        evidence: legacyBlock.concat(legacyReport).map(row), assets: legacyBlock.concat(legacyReport).map((p) => policyAsset(p, "Entra")),
      });
    }
    // 3. Report-only MFA policies
    if (mfaAny.length && mfaAny.every((p) => p.state === "report-only")) {
      push({
        id: "mfa_report_only", title: "Every MFA policy is in report-only mode", severity: "medium", confidence: "confirmed", category: "mfa",
        description: mfaAny.length + " polic" + (mfaAny.length === 1 ? "y" : "ies") + " require MFA but all are enabledForReportingButNotEnforced, so no sign-in is actually challenged by Conditional Access.",
        recommendation: "Review the report-only sign-in log results, then switch the policies to On.",
        controls: [C.cis5222, C.scuba32, C.nistAal2],
        evidence: mfaAny.map(row), assets: mfaAny.map((p) => policyAsset(p, "Entra")),
      });
    } else if (mfaAllReport.length && mfaAll.length) {
      // informative: enforced coverage exists; report-only duplicates are fine.
    }
    // 4. Disabled security-relevant policies
    const disabledSec = entraPolicies.filter((p) => p.state === "disabled" && p.securityRelevant);
    if (disabledSec.length) {
      push({
        id: "disabled_security_policy", title: "Security-relevant Conditional Access policies are disabled", severity: "low", confidence: "confirmed", category: "hygiene",
        description: disabledSec.length + " disabled polic" + (disabledSec.length === 1 ? "y" : "ies") + " require MFA, block access, require a managed device, act on risk or are named like a control: " + disabledSec.map((p) => p.name).join(", ") + ".",
        recommendation: "Delete policies that are no longer needed or document why each remains off; a disabled control is easy to mistake for coverage.",
        controls: [C.cis5222, C.iso517],
        evidence: disabledSec.map(row), assets: disabledSec.map((p) => policyAsset(p, "Entra")),
      });
    }
    // 5. Over-broad exclusions on enabled MFA / block policies
    for (const p of enabled.filter((q) => q.requiresMfa || q.blocks || q.requiresManagedDevice)) {
      const reasons = [];
      if (p.excludeUsers.length > o.breakGlassMax) reasons.push(p.excludeUsers.length + " excluded users (break-glass allowance " + o.breakGlassMax + ")");
      if (p.excludeGroups.length && p.allUsers && p.requiresMfa) reasons.push(p.excludeGroups.length + " excluded group" + (p.excludeGroups.length === 1 ? "" : "s") + " on an all-users MFA policy");
      if (p.excludeRoles.length) reasons.push(p.excludeRoles.length + " excluded directory role" + (p.excludeRoles.length === 1 ? "" : "s"));
      if (!reasons.length) continue;
      push({
        id: "broad_exclusions", title: "Over-broad exclusions on " + p.name, severity: "medium",
        confidence: p.excludeGroups.length && !p.excludeRoles.length && p.excludeUsers.length <= o.breakGlassMax ? "likely" : "confirmed", category: "exclusions",
        description: "Policy " + p.name + " (" + p.state + ") excludes: " + reasons.join("; ") + ". Every excluded principal signs in without this control.",
        recommendation: "Keep at most " + o.breakGlassMax + " named break-glass accounts excluded; move group-based exceptions to a separate time-bound policy with access reviews; never exclude directory roles from MFA.",
        controls: [C.scuba31, C.scuba32, C.cis5222, C.t1078],
        evidence: [row(p)], assets: [policyAsset(p, "Entra")].concat(p.excludeUsers.map((u) => identityAsset(u, { excludedFrom: p.name }))),
      });
    }
    // 6. Phishing-resistant MFA for privileged roles
    const prAdmin = enabled.filter((p) => p.phishingResistant && (p.allUsers || p.includeRoles.length));
    if (!prAdmin.length) {
      push({
        id: "no_phishing_resistant_admin_policy", title: "No enabled policy requires phishing-resistant MFA for privileged roles", severity: "medium", confidence: "review", category: "mfa",
        description: "No enabled policy applies an authentication strength limited to FIDO2 / passkeys, Windows Hello for Business or certificate-based authentication to directory roles or all users.",
        recommendation: "Add a policy: Users = Directory roles (Global Administrator and other privileged roles), Grant = Require authentication strength = Phishing-resistant MFA.",
        controls: [C.scuba36, C.cis5221, C.nistAal3, C.cisc65, C.t1566],
        evidence: enabled.filter((p) => p.includeRoles.length).map(row), assets: enabled.filter((p) => p.includeRoles.length).map((p) => policyAsset(p, "Entra")),
      });
    }
    // 7. Risk-based policies (P2)
    if (!enabled.some((p) => p.riskBased)) {
      push({
        id: "no_risk_policy", title: "No enabled sign-in-risk or user-risk policy", severity: "medium", confidence: "review", category: "risk",
        description: "No enabled policy sets signInRiskLevels or userRiskLevels. Requires Entra ID P2; legacy Identity Protection risk policies are not part of this export.",
        recommendation: "With P2: block or require password change for High user risk and block or require MFA for High sign-in risk.",
        controls: [C.scuba21, C.scuba23, C.t1078],
        evidence: reportOnly.filter((p) => p.riskBased).map(row), assets: [],
      });
    }
    // 8. Device compliance
    if (!enabled.some((p) => p.requiresManagedDevice)) {
      push({
        id: "no_device_compliance", title: "No enabled policy requires a compliant or managed device", severity: "medium", confidence: "review", category: "device",
        description: "No enabled policy grants access only from a compliant (Intune) or hybrid-joined device, so any device that completes MFA can reach every app.",
        recommendation: "Require a compliant or hybrid-joined device for privileged roles first, then for all users on managed platforms.",
        controls: [C.scuba37, C.iso85],
        evidence: [], assets: [],
      });
    }
    // 9. Session controls
    const persistentAlways = enabled.filter((p) => p.persistentBrowser && p.persistentBrowser.isEnabled && p.persistentBrowser.mode === "always" && (p.allUsers || p.includeRoles.length));
    for (const p of persistentAlways) {
      push({
        id: "entra_persistent_browser", title: "Persistent browser session always allowed by " + p.name, severity: "medium", confidence: "confirmed", category: "session",
        description: "Policy " + p.name + " sets Persistent browser session = Always persistent" + (p.sifHours == null ? " with no sign-in frequency" : " with sign-in frequency " + p.sifHours + " h") + " for " + (p.allUsers ? "all users" : "directory roles") + ".",
        recommendation: "Set Persistent browser session = Never persistent and Sign-in frequency to at most " + o.maxFactorLifetimeHours + " hours for administrators.",
        controls: [C.cis5224, C.nistReauth],
        evidence: [row(p)], assets: [policyAsset(p, "Entra")],
      });
    }
    const sifLong = enabled.filter((p) => p.sifHours != null && p.sifHours > o.maxFactorLifetimeHours);
    for (const p of sifLong) {
      push({
        id: "entra_long_signin_frequency", title: "Sign-in frequency above " + o.maxFactorLifetimeHours + " h in " + p.name, severity: "low", confidence: "confirmed", category: "session",
        description: "Policy " + p.name + " re-authenticates every " + p.sifHours + " hours.",
        recommendation: "NIST SP 800-63B AAL2 expects reauthentication at least every 12 hours; shorten the interval for privileged roles.",
        controls: [C.nistReauth, C.cis5224],
        evidence: [row(p)], assets: [policyAsset(p, "Entra")],
      });
    }
    if (!enabled.some((p) => p.sifHours != null)) {
      push({
        id: "entra_no_signin_frequency", title: "No enabled policy sets a sign-in frequency", severity: "low", confidence: "review", category: "session",
        description: "Without a sign-in frequency the Entra default rolling 90-day refresh token lifetime applies; administrators are never forced to re-authenticate.",
        recommendation: "Add Sign-in frequency (hours) for directory roles and set Persistent browser session = Never persistent.",
        controls: [C.cis5224, C.nistReauth],
        evidence: [], assets: [],
      });
    }
    summary.entra = { policies: entraPolicies.length, enabled: enabled.length, reportOnly: reportOnly.length, disabled: entraPolicies.filter((p) => p.state === "disabled").length, mfaAllUsers: mfaAll.length, legacyBlocked: legacyAll.length };
  }

  // ----- Entra registration details ----------------------------------------
  const regSources = sources.filter((s) => s.kind === KINDS.ENTRA_REG);
  if (!regSources.length) {
    skipped.push({ check: "registration", reason: "no Entra user registration details CSV loaded (MFA registration, admin phishing-resistant and default-method checks skipped)" });
  } else {
    const users = [];
    let adminCol = true, capableCol = true, methodsCol = true, defaultCol = true, regCol = true;
    for (const s of regSources) {
      const cols = resolveCols(s.headers, COLUMNS.registration, colMap.registration);
      if (!cols.upn) { skipped.push({ check: "registration", reason: s.name + ": no user principal name column (" + COLUMNS.registration.upn.join(", ") + ")" }); continue; }
      if (!cols.isAdmin) adminCol = false;
      if (!cols.isMfaCapable) capableCol = false;
      if (!cols.methodsRegistered) methodsCol = false;
      if (!cols.defaultMfaMethod) defaultCol = false;
      if (!cols.isMfaRegistered) regCol = false;
      for (const r of s.rows) {
        done++; tick("Registration details");
        const upn = str(r[cols.upn]); if (!upn) continue;
        const methods = cols.methodsRegistered ? splitList(r[cols.methodsRegistered]) : [];
        const reg = cols.isMfaRegistered ? bool(r[cols.isMfaRegistered]) : (cols.methodsRegistered ? methods.length > 0 : null);
        users.push({
          upn, displayName: cols.displayName ? str(r[cols.displayName]) : "",
          isAdmin: cols.isAdmin ? bool(r[cols.isAdmin]) === true : null,
          mfaRegistered: reg, mfaCapable: cols.isMfaCapable ? bool(r[cols.isMfaCapable]) : null,
          passwordless: cols.isPasswordlessCapable ? bool(r[cols.isPasswordlessCapable]) : null,
          phishingResistant: methods.some(isPhishingResistantMethod),
          methods: methods.slice().sort().join("; "), defaultMethod: cols.defaultMfaMethod ? str(r[cols.defaultMfaMethod]) : "",
          lastUpdated: cols.lastUpdated ? str(r[cols.lastUpdated]) : "",
        });
      }
    }
    users.sort((a, b) => cmp(lower(a.upn), lower(b.upn)));
    tables.registrations = users;
    const evRow = (u) => ({ user: u.upn, displayName: u.displayName, isAdmin: u.isAdmin === null ? "" : u.isAdmin, mfaRegistered: u.mfaRegistered === null ? "" : u.mfaRegistered, mfaCapable: u.mfaCapable === null ? "" : u.mfaCapable, phishingResistant: u.phishingResistant, methods: u.methods, defaultMethod: u.defaultMethod });
    const admins = users.filter((u) => u.isAdmin === true);
    if (!adminCol) skipped.push({ check: "admin_registration", reason: "no 'Is admin' column; admin-specific registration checks skipped" });
    if (!methodsCol) skipped.push({ check: "admin_no_phishing_resistant", reason: "no 'Methods registered' column; phishing-resistant method check skipped" });
    if (!regCol && !methodsCol) skipped.push({ check: "users_not_mfa_registered", reason: "no 'Is MFA registered' or 'Methods registered' column" });
    if (!capableCol) skipped.push({ check: "users_registered_not_capable", reason: "no 'Is MFA capable' column" });
    if (!defaultCol) skipped.push({ check: "weak_default_method", reason: "no 'Default MFA method' column" });

    if (adminCol && methodsCol) {
      const noPr = admins.filter((u) => !u.phishingResistant);
      if (noPr.length) {
        push({
          id: "admin_no_phishing_resistant", title: "Administrators without a phishing-resistant authentication method", severity: "high", confidence: "confirmed", category: "mfa",
          description: noPr.length + " of " + admins.length + " admin account" + (admins.length === 1 ? "" : "s") + " ha" + (noPr.length === 1 ? "s" : "ve") + " no FIDO2 security key, device-bound passkey, Windows Hello for Business or certificate registered.",
          recommendation: "Issue FIDO2 keys or device-bound passkeys to every privileged account and enforce them with a phishing-resistant authentication strength policy.",
          controls: [C.scuba36, C.nistAal3, C.cisc65, C.t1566, C.t1621],
          evidence: noPr.map(evRow), assets: noPr.map((u) => identityAsset(u.upn, { isAdmin: true, methods: u.methods })),
        });
      }
    }
    if (adminCol && (regCol || methodsCol)) {
      const adminsNoMfa = admins.filter((u) => u.mfaRegistered === false);
      if (adminsNoMfa.length) {
        push({
          id: "admin_not_mfa_registered", title: "Administrators not registered for MFA", severity: "critical", confidence: "confirmed", category: "mfa",
          description: adminsNoMfa.length + " admin account" + (adminsNoMfa.length === 1 ? "" : "s") + " ha" + (adminsNoMfa.length === 1 ? "s" : "ve") + " no MFA method registered at all.",
          recommendation: "Register a phishing-resistant method for each admin now; until then a Conditional Access policy requiring MFA will block them, which is the correct failure mode.",
          controls: [C.cis5221, C.scuba36, C.nistAal2, C.cisc65, C.t1078],
          evidence: adminsNoMfa.map(evRow), assets: adminsNoMfa.map((u) => identityAsset(u.upn, { isAdmin: true })),
        });
      }
    }
    if (regCol || methodsCol) {
      const notReg = users.filter((u) => u.mfaRegistered === false && u.isAdmin !== true);
      if (notReg.length) {
        const pct = users.length ? Math.round(notReg.length / users.length * 100) : 0;
        push({
          id: "users_not_mfa_registered", title: "Users not registered for MFA", severity: pct >= 25 ? "high" : "medium", confidence: "confirmed", category: "mfa",
          description: notReg.length + " of " + users.length + " users (" + pct + "%) have no MFA method registered; an MFA policy cannot protect an account that has nothing to challenge, and the first registration can be hijacked.",
          recommendation: "Run a registration campaign; require registration from a compliant device or trusted location; use Temporary Access Pass for onboarding.",
          controls: [C.cis5222, C.scuba32, C.nistAal2, C.cisc63],
          evidence: notReg.map(evRow), assets: notReg.slice(0, 200).map((u) => identityAsset(u.upn, {})),
        });
      }
    }
    if (capableCol) {
      const regNotCap = users.filter((u) => u.mfaRegistered === true && u.mfaCapable === false);
      if (regNotCap.length) {
        push({
          id: "users_registered_not_capable", title: "Users registered for MFA but not MFA-capable under current policy", severity: "low", confidence: "confirmed", category: "mfa",
          description: regNotCap.length + " user" + (regNotCap.length === 1 ? "" : "s") + " registered methods that the authentication methods policy no longer allows for MFA, so they will be blocked or fall back on first challenge.",
          recommendation: "Check the authentication methods policy and migrate these users to an allowed method.",
          controls: [C.scuba32, C.nistAal2],
          evidence: regNotCap.map(evRow), assets: regNotCap.map((u) => identityAsset(u.upn, {})),
        });
      }
    }
    if (defaultCol) {
      const weak = users.filter((u) => isWeakDefaultMethod(u.defaultMethod));
      if (weak.length) {
        const weakAdmins = weak.filter((u) => u.isAdmin === true);
        push({
          id: "weak_default_method", title: "SMS, voice or email is the default MFA method", severity: weakAdmins.length ? "high" : "medium", confidence: "confirmed", category: "mfa",
          description: weak.length + " user" + (weak.length === 1 ? "" : "s") + (weakAdmins.length ? " (" + weakAdmins.length + " admin" + (weakAdmins.length === 1 ? "" : "s") + ")" : "") + " default to a phone- or email-based method, which is vulnerable to SIM swap and interception.",
          recommendation: "Disable SMS and voice in the authentication methods policy and enable system-preferred MFA so the strongest registered method is prompted first.",
          controls: [C.scuba35, C.nistAal2, C.t1556],
          evidence: weak.map(evRow), assets: weak.slice(0, 200).map((u) => identityAsset(u.upn, { defaultMethod: u.defaultMethod })),
        });
      }
    }
    summary.registration = { users: users.length, admins: admins.length, mfaRegistered: users.filter((u) => u.mfaRegistered === true).length, notRegistered: users.filter((u) => u.mfaRegistered === false).length, adminsPhishingResistant: admins.filter((u) => u.phishingResistant).length, phishingResistant: users.filter((u) => u.phishingResistant).length };
  }

  // ----- Okta policies -------------------------------------------------------
  const oktaRaw = [];
  for (const s of sources) if (s.kind === KINDS.OKTA) for (const r of s.rows) { oktaRaw.push(normOktaPolicy(r)); done++; tick("Okta policies"); }
  if (!oktaRaw.length) {
    skipped.push({ check: "okta_policies", reason: "no Okta policies JSON loaded (Okta sign-on, enrollment and session checks skipped)" });
  } else {
    // merge bare rules exports into one pseudo policy
    const bare = oktaRaw.filter((p) => p.fromRules);
    const okta = oktaRaw.filter((p) => !p.fromRules);
    if (bare.length) okta.push({ ...bare[0], rules: bare.flatMap((p) => p.rules).sort((a, b) => cmp(a.priority == null ? 1e9 : a.priority, b.priority == null ? 1e9 : b.priority) || cmp(a.name, b.name)) });
    okta.sort((a, b) => cmp(a.type, b.type) || cmp(a.priority == null ? 1e9 : a.priority, b.priority == null ? 1e9 : b.priority) || cmp(a.name, b.name));
    for (const p of okta) {
      if (p.type === "MFA_ENROLL") { tables.policies.push(oktaPolicyRow(p, null)); for (const e of p.enroll) tables.oktaEnrollment.push({ policy: p.name, status: p.status, authenticator: e.name, enrollment: e.self }); continue; }
      if (!p.rules.length) tables.policies.push(oktaPolicyRow(p, null));
      for (const r of p.rules) tables.policies.push(oktaPolicyRow(p, r));
    }
    const signOn = okta.filter((p) => p.type === "OKTA_SIGN_ON" || p.type === "ACCESS_POLICY");
    const enroll = okta.filter((p) => p.type === "MFA_ENROLL");
    const active = (x) => x.status === "ACTIVE";
    const anywhere = (r) => r.network.connection !== "ZONE" || (!r.network.include.length && !r.network.exclude.length);
    const everyoneRule = (p, r) => p.everyone && !r.usersInclude.length && !r.groupsInclude.length && !r.usersExclude.length && !r.groupsExclude.length;

    const mfaEveryone = [];
    for (const p of signOn.filter(active)) for (const r of p.rules.filter(active)) if (r.access === "ALLOW" && r.requireFactor && anywhere(r) && everyoneRule(p, r) && r.authType === "ANY") mfaEveryone.push({ p, r });
    if (signOn.length && !mfaEveryone.length) {
      const ev = signOn.flatMap((p) => p.rules.map((r) => oktaPolicyRow(p, r)));
      push({
        id: "okta_no_mfa_everyone", title: "No active Okta sign-on rule requires a factor for everyone", severity: "critical", confidence: "likely", category: "mfa",
        description: signOn.length + " sign-on polic" + (signOn.length === 1 ? "y" : "ies") + " loaded; no ACTIVE rule applying to Everyone from any network allows access with requireFactor = true. Application sign-on policies not included in this export may still prompt.",
        recommendation: "In the default (Everyone) global session policy add a top-priority ACTIVE rule: access ALLOW, Prompt for factor, network Anywhere; or require 2FA in every application sign-on policy.",
        controls: [C.nistAal2, C.cisc63, C.iso517, C.t1078, C.t1110],
        evidence: ev, assets: signOn.map((p) => policyAsset({ id: p.id, name: p.name, state: p.status.toLowerCase() }, "Okta")),
      });
    }
    for (const p of signOn.filter(active)) for (const r of p.rules.filter(active)) {
      if (r.access === "ALLOW" && !r.requireFactor && anywhere(r)) {
        push({
          id: "okta_allow_without_factor", title: "Okta rule allows sign-in from anywhere without a factor: " + p.name + " / " + r.name, severity: "high", confidence: "confirmed", category: "mfa",
          description: "Rule " + r.name + " in " + p.name + " (" + (p.everyone ? "Everyone" : "scoped groups") + ") grants ALLOW with requireFactor = false and network = " + r.network.connection + ".",
          recommendation: "Set Prompt for factor on the rule, or restrict it to a trusted network zone and keep a factor-required rule for Anywhere.",
          controls: [C.nistAal2, C.cisc63, C.t1078, C.t1110],
          evidence: [oktaPolicyRow(p, r)], assets: [policyAsset({ id: p.id, name: p.name, state: p.status.toLowerCase() }, "Okta")],
        });
      }
      const reasons = [];
      if (r.sessionLifetime != null && r.sessionLifetime > o.oktaMaxSessionHours * 60) reasons.push("session lifetime " + r.sessionLifetime + " min (> " + o.oktaMaxSessionHours + " h)");
      if (r.sessionIdle != null && r.sessionIdle > o.oktaMaxIdleMinutes) reasons.push("idle timeout " + r.sessionIdle + " min (> " + o.oktaMaxIdleMinutes + " min)");
      if (r.requireFactor && r.factorPromptMode === "DEVICE" && r.factorLifetime != null && r.factorLifetime > o.maxFactorLifetimeHours * 60) reasons.push("factor remembered per device for " + r.factorLifetime + " min (> " + o.maxFactorLifetimeHours + " h)");
      if (r.requireFactor && r.factorPromptMode === "SESSION" && r.sessionLifetime != null && r.sessionLifetime > o.maxFactorLifetimeHours * 60) reasons.push("factor prompted once per session with a " + r.sessionLifetime + " min session (> " + o.maxFactorLifetimeHours + " h)");
      if (r.persistentCookie) reasons.push("persistent session cookie");
      if (reasons.length) {
        push({
          id: "okta_weak_session", title: "Weak session controls in " + p.name + " / " + r.name, severity: reasons.some((x) => x.startsWith("session lifetime") || x.startsWith("factor")) ? "medium" : "low", confidence: "confirmed", category: "session",
          description: "Rule " + r.name + ": " + reasons.join("; ") + ".",
          recommendation: "Set session lifetime to at most " + o.oktaMaxSessionHours + " h, idle timeout to at most " + o.oktaMaxIdleMinutes + " min, prompt for factor at least every " + o.maxFactorLifetimeHours + " h, and disable persistent cookies.",
          controls: [C.nistReauth, C.iso517],
          evidence: [oktaPolicyRow(p, r)], assets: [policyAsset({ id: p.id, name: p.name, state: p.status.toLowerCase() }, "Okta")],
        });
      }
    }
    for (const p of enroll.filter(active)) {
      if (p.enroll.length && !p.enroll.some((e) => e.self === "REQUIRED")) {
        push({
          id: "okta_mfa_enroll_optional", title: "Okta enrollment policy requires no authenticator: " + p.name, severity: "high", confidence: "confirmed", category: "mfa",
          description: p.name + " lists " + p.enroll.length + " authenticator" + (p.enroll.length === 1 ? "" : "s") + ", all OPTIONAL or NOT_ALLOWED (" + p.enroll.map((e) => e.name + "=" + e.self).join(", ") + "); users can finish onboarding with no second factor.",
          recommendation: "Set at least one phishing-resistant authenticator (FIDO2 / Okta FastPass) to REQUIRED in the enrollment policy that applies to Everyone.",
          controls: [C.nistAal2, C.cisc63, C.t1078],
          evidence: p.enroll.map((e) => ({ policy: p.name, authenticator: e.name, enrollment: e.self })), assets: [policyAsset({ id: p.id, name: p.name, state: p.status.toLowerCase() }, "Okta")],
        });
      }
    }
    const inactive = okta.filter((p) => !active(p)).map((p) => oktaPolicyRow(p, null)).concat(okta.filter(active).flatMap((p) => p.rules.filter((r) => !active(r) && (r.requireFactor || r.access === "DENY")).map((r) => oktaPolicyRow(p, r))));
    if (inactive.length) {
      push({
        id: "okta_inactive_policy", title: "Inactive Okta policies or rules that would enforce a factor", severity: "low", confidence: "confirmed", category: "hygiene",
        description: inactive.length + " inactive polic" + (inactive.length === 1 ? "y/rule" : "ies/rules") + " exist: " + inactive.map((x) => x.policy).join(", ") + ".",
        recommendation: "Activate or delete them; an inactive deny or factor rule is easy to mistake for coverage.",
        controls: [C.iso517, C.soc2],
        evidence: inactive, assets: [],
      });
    }
    summary.okta = { policies: okta.length, signOn: signOn.length, enrollment: enroll.length, rules: okta.reduce((n, p) => n + p.rules.length, 0), mfaEveryoneRules: mfaEveryone.length };
  }

  // ----- Google Workspace 2SV ----------------------------------------------
  const gSources = sources.filter((s) => s.kind === KINDS.GOOGLE);
  if (!gSources.length) {
    skipped.push({ check: "google_2sv", reason: "no Google Workspace 2-Step Verification report loaded" });
  } else {
    const gusers = [];
    let enfCol = true, adminColG = true, suspCol = true;
    for (const s of gSources) {
      const cols = resolveCols(s.headers, COLUMNS.google, colMap.google);
      if (!cols.email && !cols.userName) { skipped.push({ check: "google_2sv", reason: s.name + ": no Email or User Name column" }); continue; }
      if (!cols.enrolled) { skipped.push({ check: "google_2sv", reason: s.name + ": no 2-Step Verification Enrollment column (" + COLUMNS.google.enrolled.join(", ") + ")" }); continue; }
      if (!cols.enforced) enfCol = false;
      if (!cols.adminStatus) adminColG = false;
      if (!cols.suspended) suspCol = false;
      for (const r of s.rows) {
        done++; tick("Google 2SV");
        const email = str(cols.email ? r[cols.email] : r[cols.userName]); if (!email) continue;
        const adminRaw = cols.adminStatus ? str(r[cols.adminStatus]) : "";
        const adminB = bool(adminRaw);
        gusers.push({
          email, name: cols.userName ? str(r[cols.userName]) : "",
          enrolled: bool(r[cols.enrolled]), enforced: cols.enforced ? bool(r[cols.enforced]) : null,
          admin: adminB !== null ? adminB : /admin/i.test(adminRaw) && !/not an admin|none/i.test(adminRaw), adminStatus: adminRaw,
          suspended: cols.suspended ? bool(r[cols.suspended]) === true : false, lastLogin: cols.lastLogin ? str(r[cols.lastLogin]) : "",
        });
      }
    }
    gusers.sort((a, b) => cmp(lower(a.email), lower(b.email)));
    tables.googleUsers = gusers;
    const activeU = gusers.filter((u) => !u.suspended);
    const gRow = (u) => ({ user: u.email, name: u.name, admin: u.adminStatus || u.admin, enrolled: u.enrolled === null ? "" : u.enrolled, enforced: u.enforced === null ? "" : u.enforced, suspended: u.suspended, lastLogin: u.lastLogin });
    if (!suspCol) skipped.push({ check: "google_2sv", reason: "no Is Suspended column; suspended accounts are counted as active" });
    if (!adminColG) skipped.push({ check: "google_admin_no_2sv", reason: "no Admin Status column" });
    if (adminColG) {
      const adm = activeU.filter((u) => u.admin && u.enrolled === false);
      if (adm.length) {
        push({
          id: "google_admin_no_2sv", title: "Google Workspace administrators without 2-Step Verification", severity: "critical", confidence: "confirmed", category: "mfa",
          description: adm.length + " active admin account" + (adm.length === 1 ? "" : "s") + " (" + adm.map((u) => u.adminStatus || "admin").filter((v, i, a) => a.indexOf(v) === i).join(", ") + ") are not enrolled in 2SV.",
          recommendation: "Enroll every admin with a security key and enforce 2SV for the admin organisational unit with security keys only.",
          controls: [C.cisGws, C.nistAal3, C.cisc65, C.t1078],
          evidence: adm.map(gRow), assets: adm.map((u) => identityAsset(u.email, { admin: true })),
        });
      }
    }
    const notEnrolled = activeU.filter((u) => u.enrolled === false && !u.admin);
    if (notEnrolled.length) {
      const pct = activeU.length ? Math.round(notEnrolled.length / activeU.length * 100) : 0;
      push({
        id: "google_2sv_not_enrolled", title: "Active Google Workspace users not enrolled in 2-Step Verification", severity: pct >= 25 ? "high" : "medium", confidence: "confirmed", category: "mfa",
        description: notEnrolled.length + " of " + activeU.length + " active users (" + pct + "%) have not enrolled in 2SV.",
        recommendation: "Turn on 2SV enforcement with an enrollment period, then enforce; prefer security keys or passkeys over SMS.",
        controls: [C.cisGws, C.nistAal2, C.cisc63],
        evidence: notEnrolled.map(gRow), assets: notEnrolled.slice(0, 200).map((u) => identityAsset(u.email, {})),
      });
    }
    if (!enfCol) skipped.push({ check: "google_2sv_not_enforced", reason: "no 2-Step Verification Enforcement column" });
    else {
      const notEnf = activeU.filter((u) => u.enforced === false);
      if (notEnf.length) {
        push({
          id: "google_2sv_not_enforced", title: "2-Step Verification not enforced for active Google Workspace users", severity: "high", confidence: "confirmed", category: "mfa",
          description: notEnf.length + " of " + activeU.length + " active users are not under 2SV enforcement, so they can disable it themselves" + (notEnf.some((u) => u.enrolled) ? " (" + notEnf.filter((u) => u.enrolled).length + " currently enrolled voluntarily)" : "") + ".",
          recommendation: "Admin console > Security > 2-Step Verification: set Enforcement = On for every organisational unit.",
          controls: [C.cisGws, C.nistAal2, C.cisc63],
          evidence: notEnf.map(gRow), assets: notEnf.slice(0, 200).map((u) => identityAsset(u.email, {})),
        });
      }
    }
    summary.google = { users: gusers.length, active: activeU.length, enrolled: activeU.filter((u) => u.enrolled === true).length, notEnrolled: activeU.filter((u) => u.enrolled === false).length, admins: activeU.filter((u) => u.admin).length, enforced: activeU.filter((u) => u.enforced === true).length };
  }

  ctx?.progress?.(total, total, "done");

  // deterministic order
  findings.sort((a, b) => cmp(SEV_RANK[a.severity], SEV_RANK[b.severity]) || cmp(a.id, b.id) || cmp(a.title, b.title));
  for (const f of findings) {
    f.assets.sort((a, b) => cmp(a.type, b.type) || cmp(a.name, b.name));
    f.controls = f.controls.slice();
  }
  tables.policies.sort((a, b) => cmp(a.source, b.source) || cmp(a.policy, b.policy));
  tables.oktaEnrollment.sort((a, b) => cmp(a.policy, b.policy) || cmp(a.authenticator, b.authenticator));
  skipped.sort((a, b) => cmp(a.check, b.check) || cmp(a.reason, b.reason));
  summary.sources.sort((a, b) => cmp(a.name, b.name));
  summary.findings = findings.length;
  summary.bySeverity = countBy(findings, "severity");
  return { summary, findings, tables, skipped, meta: { tool: TOOL_ID, version: VERSION, rows: total, sources: sources.length, options: Object.fromEntries(Object.keys(DEFAULTS).map((k) => [k, o[k]])) } };
}

function countBy(items, key) {
  const out = {};
  for (const it of items) out[it[key]] = (out[it[key]] || 0) + 1;
  return Object.fromEntries(Object.keys(out).sort().map((k) => [k, out[k]]));
}

// ---------------------------------------------------------------------------
// CSV serialisers
// ---------------------------------------------------------------------------
const q = (v) => '"' + String(v ?? "").replace(/"/g, '""') + '"';
const FINDING_COLS = ["severity", "confidence", "category", "id", "title", "description", "recommendation", "controls", "assets", "evidenceCount"];

/** Findings as CSV with fixed columns. */
export function findingsToCsv(findings) {
  const head = FINDING_COLS.join(",");
  const body = (findings || []).map((f) => [
    f.severity, f.confidence, f.category, f.id, f.title, f.description, f.recommendation,
    (f.controls || []).map((c) => c.framework + " " + c.id).join("; "),
    (f.assets || []).map((a) => a.name).join("; "),
    f.evidenceCount != null ? f.evidenceCount : (f.evidence || []).length,
  ].map(q).join(","));
  return [head, ...body].join("\n");
}

export const MATRIX_COLS = ["source", "policy", "state", "includedUsers", "includedGroups", "includedRoles", "excludedUsers", "excludedGroups", "excludedRoles", "apps", "excludedApps", "clientApps", "platforms", "locations", "risk", "grant", "session"];

/** Policy coverage matrix (tables.policies) as CSV. */
export function policyMatrixCsv(rows) {
  return [MATRIX_COLS.join(",")].concat((rows || []).map((r) => MATRIX_COLS.map((k) => q(r[k])).join(","))).join("\n");
}

export const NO_PR_COLS = ["upn", "displayName", "isAdmin", "mfaRegistered", "mfaCapable", "methods", "defaultMethod"];

/** Users without a phishing-resistant method (from tables.registrations) as CSV. */
export function noPhishingResistantCsv(registrations) {
  const list = (registrations || []).filter((u) => !u.phishingResistant);
  return [NO_PR_COLS.join(",")].concat(list.map((u) => NO_PR_COLS.map((k) => q(u[k] === null ? "" : u[k])).join(","))).join("\n");
}

// ---------------------------------------------------------------------------
// Synthetic example (seeded, format-faithful, never real data)
// ---------------------------------------------------------------------------
function rng(seed) {
  let s = (seed >>> 0) || 1;
  return () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 4294967296; };
}
function guid(rnd) {
  const h = "0123456789abcdef"; let out = "";
  for (let i = 0; i < 32; i++) { out += h[Math.floor(rnd() * 16)]; if (i === 7 || i === 11 || i === 15 || i === 19) out += "-"; }
  return out;
}

/** Seeded SYNTHETIC dataset: Entra policies JSON, registration CSV and Okta policies JSON. */
export function exampleDataset(seed = 7) {
  const rnd = rng(seed);
  const g = () => guid(rnd);
  const bg1 = g(), bg2 = g(), bg3 = g(), svcGroup = g(), gaRole = "62e90394-69f5-4237-9190-012177145e10";
  const policies = {
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies",
    value: [
      {
        id: g(), displayName: "CA001: Require MFA for all users", createdDateTime: "2025-03-02T09:14:00Z", modifiedDateTime: "2026-01-11T16:02:00Z", state: "enabled",
        conditions: { users: { includeUsers: ["All"], excludeUsers: [bg1, bg2], includeGroups: [], excludeGroups: [svcGroup], includeRoles: [], excludeRoles: [] },
          applications: { includeApplications: ["All"], excludeApplications: [], includeUserActions: [] }, clientAppTypes: ["browser", "mobileAppsAndDesktopClients"], platforms: null,
          locations: null, signInRiskLevels: [], userRiskLevels: [], devices: null },
        grantControls: { operator: "OR", builtInControls: ["mfa"], customAuthenticationFactors: [], termsOfUse: [], authenticationStrength: null },
        sessionControls: { signInFrequency: null, persistentBrowser: { isEnabled: true, mode: "always" }, applicationEnforcedRestrictions: null, cloudAppSecurity: null },
      },
      {
        id: g(), displayName: "CA002: Block legacy authentication", createdDateTime: "2025-03-02T09:20:00Z", modifiedDateTime: "2025-03-02T09:20:00Z", state: "enabledForReportingButNotEnforced",
        conditions: { users: { includeUsers: ["All"], excludeUsers: [bg1, bg2], includeGroups: [], excludeGroups: [], includeRoles: [], excludeRoles: [] },
          applications: { includeApplications: ["All"], excludeApplications: [], includeUserActions: [] }, clientAppTypes: ["exchangeActiveSync", "other"], platforms: null,
          locations: null, signInRiskLevels: [], userRiskLevels: [], devices: null },
        grantControls: { operator: "OR", builtInControls: ["block"], customAuthenticationFactors: [], termsOfUse: [], authenticationStrength: null },
        sessionControls: null,
      },
      {
        id: g(), displayName: "CA003: Require compliant device for admins", createdDateTime: "2025-06-18T13:00:00Z", modifiedDateTime: "2025-11-30T08:45:00Z", state: "disabled",
        conditions: { users: { includeUsers: [], excludeUsers: [bg1, bg2], includeGroups: [], excludeGroups: [], includeRoles: [gaRole], excludeRoles: [] },
          applications: { includeApplications: ["All"], excludeApplications: [], includeUserActions: [] }, clientAppTypes: ["all"], platforms: null,
          locations: null, signInRiskLevels: [], userRiskLevels: [], devices: null },
        grantControls: { operator: "OR", builtInControls: ["compliantDevice", "domainJoinedDevice"], customAuthenticationFactors: [], termsOfUse: [], authenticationStrength: null },
        sessionControls: null,
      },
      {
        id: g(), displayName: "CA004: Phishing-resistant MFA for admins", createdDateTime: "2025-09-01T10:00:00Z", modifiedDateTime: "2026-02-14T11:30:00Z", state: "enabled",
        conditions: { users: { includeUsers: [], excludeUsers: [bg1, bg2, bg3], includeGroups: [], excludeGroups: [], includeRoles: [gaRole, "e8611ab8-c189-46e8-94e1-60213ab1f814", "194ae4cb-b126-40b2-bd5b-6091b380977d"], excludeRoles: [] },
          applications: { includeApplications: ["All"], excludeApplications: [], includeUserActions: [] }, clientAppTypes: ["all"], platforms: null,
          locations: null, signInRiskLevels: [], userRiskLevels: [], devices: null },
        grantControls: { operator: "OR", builtInControls: [], customAuthenticationFactors: [], termsOfUse: [],
          authenticationStrength: { id: "00000000-0000-0000-0000-000000000004", displayName: "Phishing-resistant MFA", policyType: "builtIn", requirementsSatisfied: "mfa", allowedCombinations: ["windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor"] } },
        sessionControls: { signInFrequency: { value: 12, type: "hours", isEnabled: true, frequencyInterval: "timeBased", authenticationType: "primaryAndSecondaryAuthentication" }, persistentBrowser: { isEnabled: true, mode: "never" }, applicationEnforcedRestrictions: null, cloudAppSecurity: null },
      },
    ],
  };

  const people = [
    ["user01", "User 01", true, "fido2SecurityKey;microsoftAuthenticatorPush;windowsHelloForBusiness", "fido2SecurityKey", true, true, true],
    ["user02", "User 02", true, "microsoftAuthenticatorPush;mobilePhone", "microsoftAuthenticatorPush", true, true, false],
    ["user03", "User 03", false, "microsoftAuthenticatorPush;softwareOneTimePasscode", "microsoftAuthenticatorPush", true, true, false],
    ["user04", "User 04", false, "mobilePhone", "mobilePhone", true, true, false],
    ["user05", "User 05", false, "fido2SecurityKey;microsoftAuthenticatorPush", "fido2SecurityKey", true, true, true],
    ["user06", "User 06", false, "", "", false, false, false],
    ["user07", "User 07", false, "microsoftAuthenticatorPush;email", "microsoftAuthenticatorPush", true, true, false],
    ["user08", "User 08", false, "email", "", false, false, false],
    ["user09", "User 09", false, "windowsHelloForBusiness;microsoftAuthenticatorPush;temporaryAccessPass", "windowsHelloForBusiness", true, true, true],
    ["user10", "User 10", false, "softwareOneTimePasscode;mobilePhone", "mobilePhone", true, true, false],
  ];
  const csvHead = "Id,User principal name,User display name,Is admin,Is MFA capable,Is MFA registered,Is SSPR registered,Is SSPR enabled,Is SSPR capable,Is passwordless capable,Methods registered,Default MFA method,System preferred method,Last updated";
  const csvRows = people.map(([u, n, admin, methods, def, cap, reg, pwl], i) => [
    g(), u + "@test.darknode.ai", n, admin ? "True" : "False", cap ? "True" : "False", reg ? "True" : "False", reg ? "True" : "False", "True", cap ? "True" : "False", pwl ? "True" : "False",
    methods, def, pwl ? def : (def === "mobilePhone" ? "" : def), "2026-0" + (1 + (i % 9)) + "-1" + (i % 10) + "T0" + (i % 9) + ":2" + (i % 10) + ":00Z",
  ].map((v) => (/[",\n]/.test(String(v)) ? '"' + String(v).replace(/"/g, '""') + '"' : String(v))).join(","));
  const registrationCsv = [csvHead].concat(csvRows).join("\r\n") + "\r\n";

  const oktaId = () => "00p" + Array.from({ length: 17 }, () => "abcdefghijklmnopqrstuvwxyz0123456789"[Math.floor(rnd() * 36)]).join("");
  const everyoneGroup = "00g" + Array.from({ length: 17 }, () => "abcdefghijklmnopqrstuvwxyz0123456789"[Math.floor(rnd() * 36)]).join("");
  const zone = "nzo" + Array.from({ length: 17 }, () => "abcdefghijklmnopqrstuvwxyz0123456789"[Math.floor(rnd() * 36)]).join("");
  const oktaPolicies = [
    {
      id: oktaId(), status: "ACTIVE", name: "Default Policy", description: "The default policy applies in all situations if no other policy applies.", priority: 1, system: true, type: "OKTA_SIGN_ON",
      conditions: { people: { groups: { include: [everyoneGroup] } } },
      created: "2024-05-13T08:00:00.000Z", lastUpdated: "2026-01-20T10:11:00.000Z",
      rules: [
        {
          id: "0pr" + oktaId().slice(3), status: "ACTIVE", name: "Corporate network - no factor", priority: 1, system: false, type: "SIGN_ON",
          conditions: { network: { connection: "ZONE", include: [zone] }, authContext: { authType: "ANY" }, people: { users: { exclude: [] } } },
          actions: { signon: { access: "ALLOW", requireFactor: false, primaryFactor: "PASSWORD_IDP_ANY_FACTOR", rememberDeviceByDefault: false, session: { usePersistentCookie: false, maxSessionIdleMinutes: 120, maxSessionLifetimeMinutes: 0 } } },
        },
        {
          id: "0pr" + oktaId().slice(3), status: "ACTIVE", name: "Default Rule", priority: 2, system: true, type: "SIGN_ON",
          conditions: { network: { connection: "ANYWHERE" }, authContext: { authType: "ANY" }, people: { users: { exclude: [] } } },
          actions: { signon: { access: "ALLOW", requireFactor: true, factorPromptMode: "SESSION", factorLifetime: 0, primaryFactor: "PASSWORD_IDP_ANY_FACTOR", rememberDeviceByDefault: false,
            session: { usePersistentCookie: true, maxSessionIdleMinutes: 240, maxSessionLifetimeMinutes: 10080 } } },
        },
      ],
    },
  ];

  const files = [
    { name: "conditionalAccessPolicies.json", text: JSON.stringify(policies, null, 2) },
    { name: "UserRegistrationDetails.csv", text: registrationCsv },
    { name: "okta-sign-on-policies.json", text: JSON.stringify(oktaPolicies, null, 2) },
  ];
  const dataset = parseInput(files);
  return { label: "synthetic example (not real data)", files, dataset, rows: dataset.rows };
}

/** Deterministic in-engine checks over the synthetic example. */
export function selfTest() {
  const tests = [];
  const ex = exampleDataset();
  const r = analyze(ex.dataset);
  const ids = (id) => r.findings.filter((f) => f.id === id);
  tests.push({ name: "three sources classified", pass: ex.dataset.sources.map((s) => s.kind).sort().join() === [KINDS.ENTRA_CA, KINDS.ENTRA_REG, KINDS.OKTA].sort().join() });
  tests.push({ name: "all-users MFA policy recognised (no no_mfa_all_users)", pass: ids("no_mfa_all_users").length === 0 });
  tests.push({ name: "report-only legacy block flagged", pass: ids("legacy_auth_not_blocked").length === 1 });
  tests.push({ name: "excluded group on all-users MFA flagged", pass: ids("broad_exclusions").some((f) => /CA001/.test(f.title)) });
  tests.push({ name: "three excluded users exceed break-glass allowance", pass: ids("broad_exclusions").some((f) => /CA004/.test(f.title)) });
  tests.push({ name: "disabled compliant-device policy reported", pass: ids("disabled_security_policy").length === 1 });
  tests.push({ name: "one admin without phishing-resistant method", pass: ids("admin_no_phishing_resistant").length === 1 && ids("admin_no_phishing_resistant")[0].evidenceCount === 1 && ids("admin_no_phishing_resistant")[0].assets[0].name === "user02@test.darknode.ai" });
  tests.push({ name: "two users not MFA registered", pass: ids("users_not_mfa_registered").length === 1 && ids("users_not_mfa_registered")[0].evidenceCount === 2 });
  tests.push({ name: "Okta everyone factor rule found (no okta_no_mfa_everyone)", pass: ids("okta_no_mfa_everyone").length === 0 });
  tests.push({ name: "Okta 7-day session flagged", pass: ids("okta_weak_session").length === 1 });
  tests.push({ name: "deterministic", pass: JSON.stringify(analyze(ex.dataset)) === JSON.stringify(r) });
  tests.push({ name: "missing inputs reported as skipped, not guessed", pass: analyze([{ x: 1 }]).skipped.some((s) => s.check === "entra_policies") });
  tests.push({ name: "empty input yields no findings", pass: analyze([]).findings.length === 0 });
  return { pass: tests.every((t) => t.pass), tests };
}
