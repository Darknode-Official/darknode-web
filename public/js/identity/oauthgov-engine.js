// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// OAuth App Governance engine (oauthgov). Pure logic: no DOM, no network, no timers.
//
// Takes the OAuth / enterprise-app exports an administrator can pull from Microsoft
// Entra ID, Google Workspace, Okta, Slack and GitHub, builds one normalised app
// inventory (the shadow-SaaS view derived from grants), classifies every granted
// scope with a fixed risk table, separates user consent from admin consent and runs
// deterministic detections. Every detection declares the data it needs; when an
// export lacks it the detection is skipped and the reason reported, never guessed.
//
// Inputs (each optional, auto-detected per file, several files at once):
//   Entra   GET /servicePrincipals JSON, GET /oauth2PermissionGrants JSON,
//           GET /servicePrincipals/{id}/appRoleAssignments JSON,
//           "Enterprise applications" CSV, "Sign-in logs (service principal)" CSV
//   Google  Admin console "Manage third-party app access" CSV, Reports API tokens.list JSON
//   Okta    GET /api/v1/apps JSON, "Apps" CSV
//   Slack   Admin "Manage apps" CSV, admin.apps.approved.list JSON
//   GitHub  gh api orgs/{org}/installations JSON, "Third-party access" CSV
//
// Same input -> byte-identical output: everything is sorted, no clock is read
// (opts.now, default = the latest timestamp in the data).

import { sniff, parseCsv, iterJson, findColumn, normHeader } from "../ingest/parse.js";
import { levenshtein } from "../identity/access-review-engine.js";

export const TOOL_ID = "oauthgov";
export const VERSION = "1.0.0";

export const MS_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000";
export const MS_FIRST_PARTY_TENANT = "f8cdef31-a31e-4b4a-93e4-5f571e91255a";

export const RISK_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const RISK_UP = { low: "medium", medium: "high", high: "critical", critical: "critical", info: "info" };
const DATA_CLASSES = ["mail", "files", "directory", "chat", "code", "admin"];

/** Tunable thresholds; the UI renders these as the settings panel. */
export const DEFAULTS = {
  unusedDays: 90,          // broad-scope app with no use for this many days
  sanctioned: [],          // app names / client ids the organisation has approved (blank by default)
  tenantId: "",            // own Entra tenant id (optional): single-tenant apps you own are not "unverified publishers"
  now: null,               // ISO reference date; default = latest timestamp in the data
  columns: {},             // header overrides for generic CSV files: { appName: "Header", ... }
};

/** Column aliases for generic CSV files (key -> accepted header names, case-insensitive). */
export const COLUMNS = {
  appName: ["App name", "displayName", "Application", "Name", "label", "app", "application name", "displayText", "app_slug"],
  appId: ["Client ID", "Application ID", "appId", "App ID", "clientId", "app_id", "client"],
  publisher: ["publisherName", "Publisher", "Owner", "vendor", "developer"],
  scopes: ["Scopes", "scope", "permissions", "permission"],
  consent: ["consentType", "Consent", "Access", "Approved by", "Installed by", "consent type"],
  users: ["Users", "user count", "principalId", "userKey", "user"],
  verified: ["Verified", "verified publisher", "is_app_directory_approved", "publisher verified"],
  status: ["Status", "accountEnabled", "enabled", "state"],
  created: ["createdDateTime", "Created on", "created", "Installation date", "created_at", "Requested", "first seen"],
  lastUsed: ["Last used", "lastSignInDateTime", "last sign-in", "last activity", "lastUsed"],
};

/** Recognised file formats with the vendor's own column signature (CSV) or record shape (JSON). */
export const FORMATS = {
  "entra-sp": { source: "entra", label: "Entra servicePrincipals (JSON)" },
  "entra-sp-csv": { source: "entra", label: "Entra Enterprise applications (CSV)", headers: ["Name", "Application ID", "Object ID", "Created on", "Homepage URL", "Certificate expiry status", "Application type"] },
  "entra-grant": { source: "entra", label: "Entra oauth2PermissionGrants (JSON)" },
  "entra-approle": { source: "entra", label: "Entra appRoleAssignments (JSON)" },
  "entra-spsignin": { source: "entra", label: "Entra service principal sign-ins (CSV)", headers: ["Date (UTC)", "Service principal name", "Service principal ID", "Resource", "Status"] },
  "google-apps": { source: "google", label: "Google third-party app access (CSV)", headers: ["App name", "Client ID", "App type", "Verified", "Access", "Users"] },
  "google-token": { source: "google", label: "Google tokens.list (JSON)" },
  "okta-app": { source: "okta", label: "Okta apps (JSON)" },
  "okta-csv": { source: "okta", label: "Okta Apps (CSV)", headers: ["App name", "Label", "Status", "Sign on mode", "Created"] },
  "slack-app": { source: "slack", label: "Slack admin.apps.approved.list (JSON)" },
  "slack-csv": { source: "slack", label: "Slack Manage apps (CSV)", headers: ["App name", "App ID", "Installed by", "Installation date", "Scopes", "Approved by", "Status", "Last used"] },
  "github-install": { source: "github", label: "GitHub app installations (JSON)" },
  "github-oauth": { source: "github", label: "GitHub third-party access (CSV)", headers: ["Application", "Owner", "Requested", "Status"] },
  generic: { source: "generic", label: "Generic app list (CSV/JSON)" },
};

export const SOURCE_LABEL = { entra: "Microsoft Entra", google: "Google Workspace", okta: "Okta", slack: "Slack", github: "GitHub", generic: "Generic" };

// ---------------------------------------------------------------------------
// Scope risk model
// ---------------------------------------------------------------------------
const R = (risk, cls, reason) => ({ risk, class: cls, reason });

/** scope -> { risk, class, reason }. Delegated meaning; application permissions are elevated one level by scopeRisk(). */
export const SCOPE_RISK = {
  // Microsoft Graph (delegated)
  "Mail.ReadWrite": R("critical", "mail", "Read, create, modify and delete mail in the mailbox"),
  "Mail.Read": R("high", "mail", "Read all mail in the mailbox"),
  "Mail.ReadBasic": R("medium", "mail", "Read mail headers (no body or attachments)"),
  "Mail.Send": R("high", "mail", "Send mail as the user (business email compromise, internal phishing)"),
  "MailboxSettings.ReadWrite": R("high", "mail", "Change mailbox rules and forwarding (classic persistence)"),
  "MailboxSettings.Read": R("medium", "mail", "Read mailbox rules and settings"),
  "Files.ReadWrite.All": R("critical", "files", "Read and write every file reachable in OneDrive and SharePoint"),
  "Files.Read.All": R("high", "files", "Read every reachable file"),
  "Files.ReadWrite": R("medium", "files", "Read and write the user's own files"),
  "Files.Read": R("low", "files", "Read the user's own files"),
  "Sites.ReadWrite.All": R("critical", "files", "Read and write all SharePoint sites"),
  "Sites.Read.All": R("high", "files", "Read all SharePoint sites"),
  "Sites.FullControl.All": R("critical", "files", "Full control of all SharePoint sites"),
  "Sites.Manage.All": R("high", "files", "Create and manage SharePoint sites and lists"),
  "Directory.ReadWrite.All": R("critical", "directory", "Write directory data: users, groups, apps"),
  "Directory.Read.All": R("high", "directory", "Read the whole directory (users, groups, devices, roles)"),
  "Directory.AccessAsUser.All": R("critical", "directory", "Act as the signed-in user against the directory"),
  "User.ReadWrite.All": R("critical", "directory", "Read and write every user profile"),
  "User.Read.All": R("high", "directory", "Read every user profile"),
  "User.ReadBasic.All": R("medium", "directory", "Read the basic profile of every user"),
  "Group.ReadWrite.All": R("critical", "directory", "Read and write all groups and memberships"),
  "Group.Read.All": R("high", "directory", "Read all groups and memberships"),
  "GroupMember.Read.All": R("medium", "directory", "Read group memberships"),
  "RoleManagement.ReadWrite.Directory": R("critical", "admin", "Assign directory roles: a direct path to Global Administrator"),
  "RoleManagement.Read.Directory": R("medium", "admin", "Read role assignments"),
  "Application.ReadWrite.All": R("critical", "admin", "Create apps and add credentials to any app (backdoor path)"),
  "Application.Read.All": R("medium", "admin", "Read all app registrations"),
  "AppRoleAssignment.ReadWrite.All": R("critical", "admin", "Grant app permissions without consent prompts"),
  "Policy.ReadWrite.ConditionalAccess": R("critical", "admin", "Change Conditional Access policies (disable MFA enforcement)"),
  "Policy.Read.All": R("medium", "admin", "Read tenant policies"),
  "UserAuthenticationMethod.ReadWrite.All": R("critical", "admin", "Reset MFA methods for any user"),
  "DeviceManagementConfiguration.ReadWrite.All": R("critical", "admin", "Change Intune device configuration"),
  "AuditLog.Read.All": R("medium", "admin", "Read audit and sign-in logs"),
  "SecurityEvents.ReadWrite.All": R("high", "admin", "Read and update security alerts"),
  "Chat.ReadWrite": R("high", "chat", "Read and send the user's Teams chats"),
  "Chat.Read": R("high", "chat", "Read the user's Teams chats"),
  "Chat.ReadWrite.All": R("critical", "chat", "Read and write all Teams chats in the tenant"),
  "Chat.Read.All": R("critical", "chat", "Read all Teams chats in the tenant"),
  "ChannelMessage.Read.All": R("high", "chat", "Read all Teams channel messages"),
  "ChannelMessage.Send": R("medium", "chat", "Post Teams channel messages as the user"),
  "Calendars.ReadWrite": R("medium", "basic", "Read and write calendars"),
  "Calendars.Read": R("medium", "basic", "Read calendars"),
  "Contacts.ReadWrite": R("medium", "directory", "Read and write contacts"),
  "Contacts.Read": R("medium", "directory", "Read contacts"),
  "Notes.ReadWrite.All": R("high", "files", "Read and write all reachable OneNote notebooks"),
  "Notes.Read.All": R("medium", "files", "Read all reachable OneNote notebooks"),
  "Tasks.ReadWrite": R("low", "basic", "Read and write the user's tasks"),
  "People.Read": R("low", "basic", "Read the user's relevant-people list"),
  "Team.ReadBasic.All": R("low", "basic", "Read names and descriptions of teams"),
  "offline_access": R("low", "basic", "Refresh tokens: access persists after the session ends"),
  "User.Read": R("low", "basic", "Sign in and read the user's own profile"),
  "User.ReadWrite": R("low", "basic", "Read and update the user's own profile"),
  "openid": R("low", "identity", "Sign in (OpenID Connect)"),
  "profile": R("low", "identity", "Basic profile claims"),
  "email": R("low", "identity", "Email address claim"),
  // Google Workspace
  "https://mail.google.com/": R("critical", "mail", "Full Gmail access including permanent delete"),
  "https://www.googleapis.com/auth/gmail.readonly": R("high", "mail", "Read all Gmail messages"),
  "https://www.googleapis.com/auth/gmail.modify": R("critical", "mail", "Read, send, delete and manage Gmail"),
  "https://www.googleapis.com/auth/gmail.send": R("high", "mail", "Send mail as the user"),
  "https://www.googleapis.com/auth/gmail.compose": R("high", "mail", "Create and send drafts"),
  "https://www.googleapis.com/auth/gmail.metadata": R("medium", "mail", "Read message headers"),
  "https://www.googleapis.com/auth/gmail.labels": R("low", "mail", "Manage labels"),
  "https://www.googleapis.com/auth/gmail.settings.basic": R("high", "mail", "Change Gmail settings including filters and forwarding"),
  "https://www.googleapis.com/auth/drive": R("critical", "files", "Full access to every reachable Drive file"),
  "https://www.googleapis.com/auth/drive.readonly": R("high", "files", "Read every reachable Drive file"),
  "https://www.googleapis.com/auth/drive.file": R("low", "files", "Only files the user opens or creates with this app"),
  "https://www.googleapis.com/auth/drive.metadata.readonly": R("low", "files", "Read file metadata only"),
  "https://www.googleapis.com/auth/drive.appdata": R("low", "files", "The app's own hidden folder"),
  "https://www.googleapis.com/auth/spreadsheets": R("high", "files", "Read and write all Google Sheets"),
  "https://www.googleapis.com/auth/documents": R("high", "files", "Read and write all Google Docs"),
  "https://www.googleapis.com/auth/admin.directory.user": R("critical", "directory", "Create, modify and delete Workspace users"),
  "https://www.googleapis.com/auth/admin.directory.user.readonly": R("high", "directory", "Read every Workspace user"),
  "https://www.googleapis.com/auth/admin.directory.group": R("high", "directory", "Manage Workspace groups"),
  "https://www.googleapis.com/auth/admin.directory.group.readonly": R("medium", "directory", "Read Workspace groups"),
  "https://www.googleapis.com/auth/admin.reports.audit.readonly": R("medium", "admin", "Read Workspace audit logs"),
  "https://www.googleapis.com/auth/cloud-platform": R("critical", "admin", "Full access to Google Cloud resources"),
  "https://www.googleapis.com/auth/calendar": R("medium", "basic", "Read and write calendars"),
  "https://www.googleapis.com/auth/calendar.readonly": R("medium", "basic", "Read calendars"),
  "https://www.googleapis.com/auth/calendar.events": R("medium", "basic", "Read and write calendar events"),
  "https://www.googleapis.com/auth/contacts": R("medium", "directory", "Read and write contacts"),
  "https://www.googleapis.com/auth/contacts.readonly": R("medium", "directory", "Read contacts"),
  "https://www.googleapis.com/auth/chat.messages": R("high", "chat", "Read and send Google Chat messages"),
  "https://www.googleapis.com/auth/chat.messages.readonly": R("high", "chat", "Read Google Chat messages"),
  "https://www.googleapis.com/auth/userinfo.email": R("low", "identity", "Email address"),
  "https://www.googleapis.com/auth/userinfo.profile": R("low", "identity", "Basic profile"),
  // Slack
  "admin": R("critical", "admin", "Administer the workspace"),
  "channels:history": R("high", "chat", "Read messages in public channels"),
  "groups:history": R("high", "chat", "Read messages in private channels"),
  "im:history": R("high", "chat", "Read direct messages"),
  "mpim:history": R("high", "chat", "Read group direct messages"),
  "search:read": R("high", "chat", "Search all messages and files"),
  "files:read": R("high", "files", "Read all shared files"),
  "files:write": R("medium", "files", "Upload and delete files"),
  "remote_files:read": R("medium", "files", "Read remote files"),
  "users:read.email": R("medium", "directory", "Read member email addresses"),
  "users:read": R("low", "directory", "Read member names and profiles"),
  "users.profile:read": R("low", "directory", "Read profile fields"),
  "chat:write": R("medium", "chat", "Post messages as the app or user (impersonation)"),
  "chat:write.customize": R("medium", "chat", "Post with a custom name and icon"),
  "channels:read": R("low", "basic", "List public channels"),
  "groups:read": R("low", "basic", "List private channels"),
  "team:read": R("low", "basic", "Read workspace name and domain"),
  "commands": R("low", "basic", "Slash commands"),
  "incoming-webhook": R("low", "basic", "Post to one channel through a webhook"),
  // GitHub app installation permissions (permission:level)
  "contents:write": R("high", "code", "Push code to repositories"),
  "contents:read": R("medium", "code", "Read repository source"),
  "administration:write": R("critical", "admin", "Change repository settings, collaborators and protections"),
  "administration:read": R("medium", "admin", "Read repository settings"),
  "organization_administration:write": R("critical", "admin", "Change organization settings"),
  "members:write": R("high", "directory", "Manage organization members and teams"),
  "members:read": R("medium", "directory", "Read organization members and teams"),
  "secrets:write": R("critical", "admin", "Create and update Actions secrets"),
  "secrets:read": R("high", "admin", "List Actions secrets"),
  "actions:write": R("high", "code", "Manage Actions workflows and runs"),
  "actions:read": R("low", "code", "Read Actions runs"),
  "workflows:write": R("high", "code", "Modify workflow files"),
  "pull_requests:write": R("medium", "code", "Create and merge pull requests"),
  "pull_requests:read": R("low", "code", "Read pull requests"),
  "issues:write": R("low", "basic", "Manage issues"),
  "issues:read": R("low", "basic", "Read issues"),
  "packages:write": R("medium", "code", "Publish packages"),
  "metadata:read": R("low", "basic", "Read repository metadata (always granted)"),
};

const SCOPE_INDEX = new Map(Object.keys(SCOPE_RISK).map((k) => [k.toLowerCase(), SCOPE_RISK[k]]));
const GOOGLE_PREFIX = "https://www.googleapis.com/auth/";

/** Scope classes shown in the UI legend, in display order. */
export const SCOPE_CLASSES = ["mail", "files", "directory", "identity", "chat", "code", "admin", "basic"];

/** One level more severe (application permissions act without a signed-in user). */
export function elevate(risk) { return RISK_UP[risk] || risk; }

/**
 * Classify one scope. kind: "delegated" | "application" | "installation".
 * Unknown scopes are medium / review (high when the vendor flags them sensitive).
 */
export function scopeRisk(scope, kind = "delegated", hint = {}) {
  const raw = String(scope == null ? "" : scope).trim();
  let lc = raw.toLowerCase();
  if (lc === "https://mail.google.com") lc += "/";
  let e = SCOPE_INDEX.get(lc);
  if (!e && lc && !lc.includes("/") && !lc.includes(":")) e = SCOPE_INDEX.get(GOOGLE_PREFIX + lc);
  const out = e
    ? { scope: raw, risk: e.risk, class: e.class, reason: e.reason, known: true, confidence: "confirmed" }
    : { scope: raw, risk: hint.sensitive ? "high" : "medium", class: "unknown", known: false, confidence: "review",
        reason: hint.sensitive ? "Not in the risk table; the vendor marks it sensitive" : "Not in the risk table: review manually" };
  out.kind = kind;
  if (kind === "application") { out.risk = elevate(out.risk); out.reason += " (application permission: runs without a signed-in user)"; }
  return out;
}

/** Microsoft Graph application permission ids (appRoleId -> permission value). */
export const GRAPH_APP_ROLES = {
  "7ab1d382-f21e-4acd-a863-ba3e13f7da61": "Directory.Read.All",
  "19dbc75e-c2e2-444c-a770-ec69d8559fc7": "Directory.ReadWrite.All",
  "810c84a8-4a9e-49e6-bf7d-12d183f40d01": "Mail.Read",
  "e2a3a72e-5f79-4c64-b1b1-878b674786c9": "Mail.ReadWrite",
  "b633e1c5-b582-4048-a93e-9f11b44c7e96": "Mail.Send",
  "6931bccd-447a-43d1-b442-00a195474933": "MailboxSettings.ReadWrite",
  "df021288-bdef-4463-88db-98f22de89214": "User.Read.All",
  "741f803b-c850-494e-b5df-cde7c675a1ca": "User.ReadWrite.All",
  "5b567255-7703-4780-807c-7be8301ae99b": "Group.Read.All",
  "62a82d76-70ea-41e2-9197-370581804d09": "Group.ReadWrite.All",
  "01d4889c-1287-42c6-ac1f-5d1e02578ef6": "Files.Read.All",
  "75359482-378d-4052-8f01-80520e7db3cd": "Files.ReadWrite.All",
  "332a536c-c7ef-4017-ab91-336970924f0d": "Sites.Read.All",
  "9492366f-7969-46a4-8d15-ed1a20078fff": "Sites.ReadWrite.All",
  "a82116e5-55eb-4c41-a434-62fe8a61c773": "Sites.FullControl.All",
  "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
  "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
  "06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
  "01c0a623-fc9b-48e9-b794-0756f8e8f067": "Policy.ReadWrite.ConditionalAccess",
  "294ce7c9-31ba-490a-ad7d-97a7d075e4ed": "Chat.ReadWrite.All",
  "6b7d71aa-70aa-4810-a8d9-5d9fb2830017": "Chat.Read.All",
  "7b2449af-6ccd-4f4d-9f78-e550c193f0d1": "ChannelMessage.Read.All",
  "ef54d2bf-783f-4e0f-bca1-3210c0444d99": "Calendars.ReadWrite",
  "6918b873-d17a-4dc1-b314-35f528134491": "Contacts.ReadWrite",
  "b0afded3-3588-46d8-8b3d-9842eff778da": "AuditLog.Read.All",
  "50483e42-d915-4231-9639-7fdb7fd190e5": "UserAuthenticationMethod.ReadWrite.All",
};

// ---------------------------------------------------------------------------
// Lookalike model
// ---------------------------------------------------------------------------
/** Well-known app names and the publisher keywords that legitimately ship them. */
export const WELL_KNOWN_APPS = [
  ["Microsoft Teams", ["microsoft"]], ["Outlook", ["microsoft"]], ["OneDrive", ["microsoft"]], ["SharePoint", ["microsoft"]],
  ["Zoom", ["zoom"]], ["Slack", ["slack"]], ["Salesforce", ["salesforce"]], ["DocuSign", ["docusign"]], ["Adobe Acrobat", ["adobe"]],
  ["Google Drive", ["google"]], ["Dropbox", ["dropbox"]], ["Box", ["box"]], ["GitHub", ["github"]], ["Jira", ["atlassian"]], ["Confluence", ["atlassian"]],
];
/** Brand words that imply a first-party publisher. */
export const BRAND_WORDS = [["microsoft", ["microsoft"]], ["google", ["google"]], ["office 365", ["microsoft"]], ["outlook", ["microsoft"]], ["onedrive", ["microsoft"]], ["sharepoint", ["microsoft"]]];

const normName = (s) => String(s == null ? "" : s).toLowerCase().replace(/[^a-z0-9 ]+/g, " ").replace(/\s+/g, " ").trim();
const tight = (s) => normName(s).replace(/ /g, "");

/** Edit-distance budget scaled to the target's length so "Box" cannot match "Bob". */
export function lookalikeBudget(target) { const n = tight(target).length; return n <= 4 ? 0 : n <= 7 ? 1 : 2; }

/**
 * Does `app` impersonate a well-known product? Returns { target, distance, basis } or null.
 * app: { name, publisher, publisherVerified, firstParty, oinKey? }
 */
export function lookalike(app) {
  const name = normName(app.name);
  if (!name) return null;
  const pub = normName(app.publisher || "");
  const pubHas = (kws) => kws.some((k) => pub.includes(k));
  const oin = tight(app.oinKey || "");
  let best = null;
  for (const [target, kws] of WELL_KNOWN_APPS) {
    const d = levenshtein(tight(name), tight(target), 2);
    if (d > lookalikeBudget(target)) continue;
    if (app.firstParty && kws.includes("microsoft")) continue;
    if (pubHas(kws)) continue;
    if (d === 0 && (app.publisherVerified === true || (oin && oin === tight(target)))) continue;
    const basis = d === 0 ? "same name as " + target + ", publisher differs or is unknown" : "edit distance " + d + " from " + target;
    if (!best || d < best.distance) best = { target, distance: d, basis };
  }
  if (best) return best;
  for (const [word, kws] of BRAND_WORDS) {
    if (!name.includes(word)) continue;
    if (app.firstParty || pubHas(kws)) continue;
    if (oin && oin.includes(word.replace(/ /g, ""))) continue;
    return { target: word, distance: -1, basis: "name contains \"" + word + "\" but the publisher is not " + kws.join("/") };
  }
  return null;
}

// ---------------------------------------------------------------------------
// Value parsers (UTC only: never the host time zone)
// ---------------------------------------------------------------------------
export function parseTs(v) {
  if (v == null || v === "") return null;
  if (typeof v === "number") return Number.isFinite(v) ? (v < 1e11 ? v * 1000 : v) : null;
  const s = String(v).trim();
  if (!s) return null;
  if (/^\d{9,13}$/.test(s)) { const n = Number(s); return n < 1e11 ? n * 1000 : n; }
  let m = /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?)?\s*(Z|UTC|[+-]\d{2}:?\d{2})?$/i.exec(s);
  if (m) {
    let t = Date.UTC(+m[1], +m[2] - 1, +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0));
    const z = m[7];
    if (z && /^[+-]/.test(z)) { const sign = z[0] === "-" ? -1 : 1; const hh = +z.slice(1, 3), mm = +z.slice(-2); t -= sign * (hh * 60 + mm) * 60000; }
    return t;
  }
  m = /^(\d{1,2})\/(\d{1,2})\/(\d{4})(?:,?\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM)?)?/i.exec(s);
  if (m) {
    let h = +(m[4] || 0);
    if (m[7]) { const pm = m[7].toUpperCase() === "PM"; if (pm && h < 12) h += 12; if (!pm && h === 12) h = 0; }
    let mo = +m[1], d = +m[2]; if (mo > 12 && d <= 12) [mo, d] = [d, mo]; if (mo < 1 || mo > 12 || d < 1 || d > new Date(Date.UTC(+m[3], mo, 0)).getUTCDate()) return null; // 25/12/2024 is day-first; reject instead of rolling over
    return Date.UTC(+m[3], mo - 1, d, h, +(m[5] || 0), +(m[6] || 0));
  }
  if (/(Z|GMT|UTC|[+-]\d{2}:?\d{2})\s*$/i.test(s)) { const d = Date.parse(s); return Number.isFinite(d) ? d : null; }
  return null;
}

export function iso(ms) { return Number.isFinite(ms) ? new Date(ms).toISOString().replace(".000Z", "Z") : null; }

export function parseBool(v) {
  if (typeof v === "boolean") return v;
  if (v == null) return null;
  const s = String(v).trim().toLowerCase();
  if (!s) return null;
  if (["true", "yes", "y", "1", "enabled", "active", "approved", "verified"].includes(s)) return true;
  if (["false", "no", "n", "0", "disabled", "inactive", "unverified", "not verified", "blocked", "restricted", "denied"].includes(s)) return false;
  return null;
}

const splitScopes = (v) => {
  if (Array.isArray(v)) return v.map((x) => (x && typeof x === "object" ? x.name || x.value || "" : String(x == null ? "" : x))).map((s) => s.trim()).filter(Boolean);
  return String(v == null ? "" : v).split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean);
};
const str = (v) => (v == null ? "" : String(v)).trim();
const lc = (v) => str(v).toLowerCase();
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

// ---------------------------------------------------------------------------
// Input parsing: one or many files -> tagged raw records
// ---------------------------------------------------------------------------
const CSV_KEYS = Object.keys(FORMATS).filter((k) => FORMATS[k].headers);

/** Classify a CSV header row -> { format, confidence }. */
export function classifyHeaders(headers) {
  const set = new Set((headers || []).map(normHeader));
  let best = { format: "generic", confidence: 0 };
  for (const k of CSV_KEYS) {
    const sig = FORMATS[k].headers;
    const hit = sig.filter((h) => set.has(normHeader(h))).length;
    const share = hit / sig.length;
    if (share > best.confidence) best = { format: k, confidence: Math.round(share * 100) / 100 };
  }
  if (best.confidence >= 0.6) return best;
  // Generic: do we at least see an app name/id column?
  const name = findColumn(headers, COLUMNS.appName), id = findColumn(headers, COLUMNS.appId);
  return { format: "generic", confidence: name && id ? 0.5 : name || id ? 0.3 : 0 };
}

/** Classify one JSON record by shape. `wrapper` is the array key it came from, when any. */
export function classifyRecord(o, wrapper = "") {
  if (!o || typeof o !== "object") return "generic";
  if (wrapper === "approved_apps" || wrapper === "restricted_apps") return "slack-app";
  if (wrapper === "installations") return "github-install";
  if ("consentType" in o && "clientId" in o && "scope" in o) return "entra-grant";
  if ("appRoleId" in o && ("resourceId" in o || "principalId" in o)) return "entra-approle";
  if ("appId" in o && ("servicePrincipalType" in o || "appOwnerOrganizationId" in o || "oauth2PermissionScopes" in o || "verifiedPublisher" in o || "displayName" in o)) return "entra-sp";
  if (Array.isArray(o.scopes) && ("userKey" in o || "displayText" in o || /token/i.test(str(o.kind)))) return "google-token";
  if ("app_slug" in o || ("permissions" in o && "repository_selection" in o)) return "github-install";
  if (o.app && typeof o.app === "object" && Array.isArray(o.scopes)) return "slack-app";
  if ("signOnMode" in o || (o.settings && o.settings.oauthClient) || ("label" in o && "status" in o && "id" in o)) return "okta-app";
  return "generic";
}

const JSON_WRAPPERS = ["value", "approved_apps", "restricted_apps", "installations", "items", "apps", "data", "records", "results", "events"];

function unwrapJson(text) {
  let o;
  try { o = JSON.parse(String(text).replace(/^﻿/, "")); } catch (_) { return { records: iterJson(text), wrapper: "" }; }
  if (Array.isArray(o)) return { records: o, wrapper: "" };
  if (!o || typeof o !== "object") return { records: [], wrapper: "" };
  for (const k of JSON_WRAPPERS) if (Array.isArray(o[k])) return { records: o[k], wrapper: k };
  return { records: [o], wrapper: "" };
}

function parseOne(name, text) {
  const t = String(text || "");
  const file = { name: name || "input", format: "empty", confidence: 0, headers: [], rows: 0, source: "" };
  if (!t.trim()) return { file, rows: [] };
  const sn = sniff(t);
  const out = [];
  if (sn.format === "json" || sn.format === "ndjson") {
    const { records, wrapper } = unwrapJson(t);
    const types = new Map();
    for (const r of records) {
      if (!r || typeof r !== "object") continue;
      const type = classifyRecord(r, wrapper);
      types.set(type, (types.get(type) || 0) + 1);
      out.push({ ...r, _type: type, _file: file.name });
    }
    const top = [...types].sort((a, b) => b[1] - a[1] || cmp(a[0], b[0]))[0];
    file.format = top ? top[0] : "generic";
    file.confidence = top ? Math.round((top[1] / out.length) * 100) / 100 : 0;
    if (file.format === "generic") file.confidence = Math.min(file.confidence, 0.4);
    file.headers = out.length ? Object.keys(out[0]).filter((k) => k[0] !== "_") : [];
  } else {
    const { headers, rows } = parseCsv(t);
    const c = classifyHeaders(headers);
    file.format = c.format; file.confidence = c.confidence; file.headers = headers;
    for (const r of rows) out.push({ ...r, _type: c.format, _file: file.name });
  }
  file.rows = out.length;
  file.source = (FORMATS[file.format] || FORMATS.generic).source;
  return { file, rows: out };
}

/**
 * Parse one text, one { name, text } or an array of them. Never throws on bad
 * input. Rows are the vendor's raw records tagged with _type / _file.
 */
export function parseInput(input) {
  const list = Array.isArray(input) ? input : [input];
  const files = [], rows = [], skipped = [];
  let i = 0;
  for (const it of list) {
    i++;
    const name = it && typeof it === "object" ? it.name || "file " + i : "file " + i;
    const text = it && typeof it === "object" ? it.text : it;
    let r;
    try { r = parseOne(name, text); } catch (e) { skipped.push({ check: "parse", reason: name + ": " + (e && e.message || e) }); continue; }
    if (!r.rows.length) { skipped.push({ check: "parse", reason: name + ": no records recognised" }); continue; }
    files.push(r.file);
    for (const x of r.rows) rows.push(x);
  }
  const format = files.length === 1 ? files[0].format : files.length ? "multi" : "empty";
  const confidence = files.length ? Math.min(...files.map((f) => f.confidence)) : 0;
  const headers = files.length === 1 ? files[0].headers : [];
  return { format, confidence, headers, rows, skipped, files };
}

// ---------------------------------------------------------------------------
// Inventory assembly
// ---------------------------------------------------------------------------
function newApp(source, key) {
  return {
    key, source, name: "", appId: "", objectId: "", publisher: "", publisherVerified: null, firstParty: false, enabled: null,
    created: null, lastUsed: null, scopes: [], grants: [], consentAdmin: false, consentUser: false, users: new Set(), assigned: new Set(),
    userCount: null, replyUrls: [], flags: new Set(), classes: new Set(), kinds: new Set(), oinKey: "", raw: [], notes: new Set(),
  };
}

function addScope(app, scope, kind, extra = {}) {
  const s = str(scope);
  if (!s) return;
  const r = scopeRisk(s, kind, extra);
  const id = (r.kind + "|" + s).toLowerCase();
  if (app.scopes.some((x) => x._id === id)) { if (extra.grantId) { const e = app.scopes.find((x) => x._id === id); if (!e.grantIds.includes(extra.grantId)) e.grantIds.push(extra.grantId); } return; }
  app.scopes.push({ _id: id, scope: s, kind: r.kind, risk: r.risk, class: r.class, reason: r.reason, known: r.known, confidence: r.confidence, grantIds: extra.grantId ? [extra.grantId] : [] });
  app.kinds.add(r.kind);
}

const maxTs = (a, b) => (a == null ? b : b == null ? a : Math.max(a, b));
const minTs = (a, b) => (a == null ? b : b == null ? a : Math.min(a, b));

function genericCols(headers, override) {
  const cols = {};
  for (const k of Object.keys(COLUMNS)) {
    const ov = override && override[k];
    if (ov && headers.includes(ov)) { cols[k] = ov; continue; }
    const h = findColumn(headers, COLUMNS[k]);
    if (h) cols[k] = h;
  }
  return cols;
}

/**
 * Build the app inventory from tagged raw rows. Returns { apps: Map, stats, skipped, tsMax }.
 */
export function buildInventory(rows, o, progress) {
  const apps = new Map();
  const skipped = [];
  const stats = { files: new Set(), types: {}, grants: 0, appRoles: 0, tokens: 0, signins: 0 };
  const roleNames = new Map();     // resource SP object id -> Map(appRoleId -> value)
  const graphResourceIds = new Set();
  const signins = new Map();       // SP object id -> last ts
  const pendingGrants = [], pendingRoles = [], pendingTokens = [];
  const genericHeaders = new Map(); // file -> cols
  const get = (source, key, init) => {
    const k = source + ":" + key;
    let a = apps.get(k);
    if (!a) { a = newApp(source, k); apps.set(k, a); if (init) init(a); }
    return a;
  };
  const n = rows.length;
  let tsMax = null;
  const seen = (t) => { tsMax = maxTs(tsMax, t); return t; };

  for (let i = 0; i < n; i++) {
    if (i % 1000 === 0) progress?.(i, n, "reading records");
    const r = rows[i];
    if (!r || typeof r !== "object") continue;
    const type = r._type || classifyRecord(r);
    stats.types[type] = (stats.types[type] || 0) + 1;
    if (r._file) stats.files.add(r._file);
    switch (type) {
      case "entra-sp": {
        const oid = str(r.id), appId = lc(r.appId);
        if (Array.isArray(r.appRoles) && oid) {
          const m = new Map();
          for (const role of r.appRoles) if (role && role.id && role.value) m.set(lc(role.id), str(role.value));
          roleNames.set(oid, m);
        }
        if (appId === MS_GRAPH_APP_ID && oid) graphResourceIds.add(oid);
        const a = get("entra", oid || appId || lc(r.displayName));
        a.name = a.name || str(r.displayName); a.appId = a.appId || appId; a.objectId = a.objectId || oid;
        const vp = r.verifiedPublisher && typeof r.verifiedPublisher === "object" ? r.verifiedPublisher : null;
        const owner = lc(r.appOwnerOrganizationId);
        a.firstParty = a.firstParty || owner === MS_FIRST_PARTY_TENANT || (Array.isArray(r.tags) && r.tags.includes("WindowsAzureActiveDirectoryIntegratedApp") && owner === MS_FIRST_PARTY_TENANT);
        if (owner && o.tenantId && owner === lc(o.tenantId)) { a.notes.add("owned by your tenant"); a.ownTenant = true; }
        if (vp && (vp.verifiedPublisherId || vp.displayName)) { a.publisherVerified = true; a.publisher = str(vp.displayName) || a.publisher; }
        else if ("verifiedPublisher" in r || "publisherName" in r) { if (a.publisherVerified !== true) a.publisherVerified = false; }
        if (!a.publisher && r.publisherName) a.publisher = str(r.publisherName);
        if (!a.publisher && a.firstParty) a.publisher = "Microsoft";
        if (typeof r.accountEnabled === "boolean") a.enabled = r.accountEnabled; else if (r.accountEnabled != null) a.enabled = parseBool(r.accountEnabled);
        a.created = minTs(a.created, seen(parseTs(r.createdDateTime)));
        if (r.signInActivity && typeof r.signInActivity === "object") a.lastUsed = maxTs(a.lastUsed, seen(parseTs(r.signInActivity.lastSignInDateTime)));
        if (Array.isArray(r.replyUrls)) for (const u of r.replyUrls) if (str(u) && !a.replyUrls.includes(str(u))) a.replyUrls.push(str(u));
        if (r.servicePrincipalType) a.spType = str(r.servicePrincipalType);
        if (a.raw.length < 3) a.raw.push(r);
        break;
      }
      case "entra-sp-csv": {
        const oid = str(r["Object ID"]), appId = lc(r["Application ID"]);
        const a = get("entra", oid || appId || lc(r.Name));
        a.name = a.name || str(r.Name); a.appId = a.appId || appId; a.objectId = a.objectId || oid;
        if (/microsoft applications/i.test(str(r["Application type"]))) { a.firstParty = true; a.publisher = a.publisher || "Microsoft"; }
        a.created = minTs(a.created, seen(parseTs(r["Created on"])));
        if (str(r["Homepage URL"])) a.homepage = str(r["Homepage URL"]);
        a.notes.add("portal CSV: no publisher or consent data");
        if (a.raw.length < 3) a.raw.push(r);
        break;
      }
      case "entra-grant": pendingGrants.push(r); stats.grants++; break;
      case "entra-approle": pendingRoles.push(r); stats.appRoles++; break;
      case "entra-spsignin": {
        const sp = str(r["Service principal ID"]);
        if (!sp) break;
        if (/fail/i.test(str(r.Status))) break;
        const t = seen(parseTs(r["Date (UTC)"]));
        if (t != null) { signins.set(sp, maxTs(signins.get(sp), t)); stats.signins++; }
        break;
      }
      case "google-apps": {
        const cid = lc(r["Client ID"]);
        const a = get("google", cid || lc(r["App name"]));
        a.name = a.name || str(r["App name"]); a.appId = a.appId || cid;
        a.appType = str(r["App type"]);
        const v = parseBool(r.Verified); if (v != null) a.publisherVerified = v;
        const access = lc(r.Access);
        a.access = access;
        if (access === "trusted") a.consentAdmin = true;
        if (access === "blocked") a.enabled = false; else if (access) a.enabled = true;
        const users = Number(String(r.Users || "").replace(/[^0-9]/g, ""));
        if (Number.isFinite(users) && str(r.Users) !== "") { a.userCount = Math.max(a.userCount || 0, users); if (users > 0 && access !== "trusted") a.consentUser = true; }
        if (a.raw.length < 3) a.raw.push(r);
        break;
      }
      case "google-token": pendingTokens.push(r); stats.tokens++; break;
      case "okta-app": {
        const id = str(r.id);
        const a = get("okta", id || lc(r.label || r.name));
        a.name = a.name || str(r.label || r.name); a.appId = a.appId || id; a.oinKey = str(r.name);
        const st = lc(r.status); if (st) a.enabled = st === "active";
        a.created = minTs(a.created, seen(parseTs(r.created)));
        seen(parseTs(r.lastUpdated));
        a.signOnMode = str(r.signOnMode);
        a.classes.add("identity");
        const oc = r.settings && r.settings.oauthClient;
        if (oc) {
          if (Array.isArray(oc.grant_types)) { a.grantTypes = oc.grant_types.map(str); if (a.grantTypes.includes("implicit")) a.flags.add("implicit-grant"); }
          if (Array.isArray(oc.redirect_uris)) for (const u of oc.redirect_uris) if (str(u) && !a.replyUrls.includes(str(u))) a.replyUrls.push(str(u));
        }
        if (/^(BROWSER_PLUGIN|AUTO_LOGIN)$/i.test(a.signOnMode)) a.flags.add("stored-password");
        if (a.raw.length < 3) a.raw.push(r);
        break;
      }
      case "okta-csv": {
        const a = get("okta", lc(r.Label || r["App name"]));
        a.name = a.name || str(r.Label || r["App name"]); a.oinKey = str(r["App name"]);
        const st = lc(r.Status); if (st) a.enabled = st === "active";
        a.created = minTs(a.created, seen(parseTs(r.Created)));
        a.signOnMode = str(r["Sign on mode"]).toUpperCase().replace(/[\s-]+/g, "_");
        a.classes.add("identity");
        if (/^(BROWSER_PLUGIN|AUTO_LOGIN|SWA)/i.test(a.signOnMode) || /secure web auth/i.test(str(r["Sign on mode"]))) a.flags.add("stored-password");
        if (a.raw.length < 3) a.raw.push(r);
        break;
      }
      case "slack-csv": {
        const id = str(r["App ID"]);
        const a = get("slack", id || lc(r["App name"]));
        a.name = a.name || str(r["App name"]); a.appId = a.appId || id;
        const installer = str(r["Installed by"]), approver = str(r["Approved by"]);
        if (installer) a.users.add(installer);
        if (approver) a.consentAdmin = true; else if (installer) a.consentUser = true;
        const st = lc(r.Status); if (st) a.enabled = !/restricted|blocked|denied/.test(st);
        a.created = minTs(a.created, seen(parseTs(r["Installation date"])));
        a.lastUsed = maxTs(a.lastUsed, seen(parseTs(r["Last used"])));
        for (const s of splitScopes(r.Scopes)) addScope(a, s, "delegated", { grantId: id || undefined });
        if (a.raw.length < 3) a.raw.push(r);
        break;
      }
      case "slack-app": {
        const app = r.app && typeof r.app === "object" ? r.app : {};
        const id = str(app.id);
        const a = get("slack", id || lc(app.name));
        a.name = a.name || str(app.name); a.appId = a.appId || id;
        if (typeof app.is_app_directory_approved === "boolean") a.publisherVerified = app.is_app_directory_approved;
        if (app.is_internal === true) { a.publisher = a.publisher || "internal"; a.notes.add("internal Slack app"); }
        a.consentAdmin = true;
        if (r.last_resolved_by && r.last_resolved_by.actor_id) a.approver = str(r.last_resolved_by.actor_id);
        const t = seen(parseTs(r.date_updated)); a.created = minTs(a.created, t);
        if (Array.isArray(r.scopes)) for (const s of r.scopes) addScope(a, s && typeof s === "object" ? s.name : s, "delegated", { sensitive: !!(s && s.is_sensitive), grantId: id || undefined });
        if (a.raw.length < 3) a.raw.push(r);
        break;
      }
      case "github-install": {
        const slug = str(r.app_slug), id = str(r.id);
        const a = get("github", slug || str(r.app_id) || id);
        a.name = a.name || slug || ("app " + str(r.app_id)); a.appId = a.appId || str(r.app_id); a.objectId = a.objectId || id; a.oinKey = slug;
        a.consentAdmin = true;
        a.enabled = r.suspended_at ? false : true;
        a.created = minTs(a.created, seen(parseTs(r.created_at)));
        a.lastUsed = maxTs(a.lastUsed, seen(parseTs(r.updated_at)));
        a.repoSelection = str(r.repository_selection);
        if (r.permissions && typeof r.permissions === "object") {
          for (const k of Object.keys(r.permissions).sort()) addScope(a, k + ":" + str(r.permissions[k]), "installation", { grantId: id || undefined });
          if (a.repoSelection === "all" && Object.values(r.permissions).some((v) => lc(v) === "write" || lc(v) === "admin")) a.flags.add("all-repos-write");
        }
        if (a.raw.length < 3) a.raw.push(r);
        break;
      }
      case "github-oauth": {
        const a = get("github", lc(r.Application));
        a.name = a.name || str(r.Application); a.publisher = a.publisher || str(r.Owner);
        const st = lc(r.Status);
        if (st) { a.enabled = st === "approved"; if (st === "approved") a.consentAdmin = true; }
        a.created = minTs(a.created, seen(parseTs(r.Requested)));
        a.notes.add("OAuth app: scopes are per-user and not in this export");
        if (a.raw.length < 3) a.raw.push(r);
        break;
      }
      default: {
        const fileKey = r._file || "";
        let cols = genericHeaders.get(fileKey);
        if (!cols) { cols = genericCols(Object.keys(r).filter((k) => k[0] !== "_"), o.columns); genericHeaders.set(fileKey, cols); }
        if (!cols.appName && !cols.appId) break;
        const name = str(r[cols.appName]), id = lc(r[cols.appId]);
        const a = get("generic", id || lc(name));
        a.name = a.name || name; a.appId = a.appId || id;
        if (cols.publisher) a.publisher = a.publisher || str(r[cols.publisher]);
        if (cols.verified) { const v = parseBool(r[cols.verified]); if (v != null) a.publisherVerified = v; }
        if (cols.status) { const v = parseBool(r[cols.status]); if (v != null) a.enabled = v; }
        if (cols.created) a.created = minTs(a.created, seen(parseTs(r[cols.created])));
        if (cols.lastUsed) a.lastUsed = maxTs(a.lastUsed, seen(parseTs(r[cols.lastUsed])));
        if (cols.scopes) for (const s of splitScopes(r[cols.scopes])) addScope(a, s, "delegated");
        if (cols.consent) { const c = lc(r[cols.consent]); if (/admin|allprincipals|trusted/.test(c)) a.consentAdmin = true; else if (/user|principal/.test(c)) a.consentUser = true; }
        if (cols.users) { const u = str(r[cols.users]); if (/^\d+$/.test(u)) a.userCount = Math.max(a.userCount || 0, Number(u)); else if (u) a.users.add(u); }
        a.genericCols = cols;
        if (a.raw.length < 3) a.raw.push(r);
      }
    }
  }

  // Entra: delegated grants -> apps (clientId is the SP object id).
  const entraByOid = new Map();
  for (const a of apps.values()) if (a.source === "entra" && a.objectId) entraByOid.set(a.objectId, a);
  const findEntra = (oid) => entraByOid.get(oid) || get("entra", oid, (a) => { a.objectId = oid; a.name = "(unknown app " + oid.slice(0, 8) + ")"; a.notes.add("grant references a service principal not in the export"); });
  for (const g of pendingGrants) {
    const client = str(g.clientId);
    if (!client) continue;
    const a = findEntra(client);
    const gid = str(g.id);
    if (gid && !a.grants.includes(gid)) a.grants.push(gid);
    const ct = lc(g.consentType);
    if (ct === "allprincipals") a.consentAdmin = true;
    else if (ct === "principal") { a.consentUser = true; if (str(g.principalId)) a.users.add(str(g.principalId)); }
    for (const s of splitScopes(g.scope)) addScope(a, s, "delegated", { grantId: gid || undefined });
    seen(parseTs(g.createdDateTime));
  }
  // Entra: app role assignments -> application permissions (or user assignments to an app).
  for (const ar of pendingRoles) {
    const pt = lc(ar.principalType), rid = str(ar.resourceId), pid = str(ar.principalId), roleId = lc(ar.appRoleId), aid = str(ar.id);
    seen(parseTs(ar.createdDateTime));
    if (pt === "user" || pt === "group") {
      if (!rid) continue;
      const a = findEntra(rid);
      if (pid) a.assigned.add(pid);
      continue;
    }
    if (!pid) continue;
    const a = findEntra(pid);
    if (aid && !a.grants.includes(aid)) a.grants.push(aid);
    a.consentAdmin = true;
    if (!roleId || roleId === "00000000-0000-0000-0000-000000000000") continue;
    const resName = str(ar.resourceDisplayName);
    const isGraph = graphResourceIds.has(rid) || /^microsoft graph$/i.test(resName);
    // roleId is attacker-controlled; guard the plain-object lookup so "constructor"/
    // "__proto__" can't resolve to an inherited member (garbled scope + lost note).
    const graphRole = Object.prototype.hasOwnProperty.call(GRAPH_APP_ROLES, roleId) ? GRAPH_APP_ROLES[roleId] : "";
    const named = (roleNames.get(rid) || new Map()).get(roleId) || ((isGraph || !resName) ? graphRole : "") || str(ar.appRoleValue || ar.permission || ar.scope);
    addScope(a, named || ("appRole:" + roleId), "application", { grantId: aid || undefined });
    if (!named) a.notes.add("appRoleId " + roleId + " not resolved (resource " + (resName || rid) + ")");
  }
  for (const [sp, t] of signins) { const a = entraByOid.get(sp); if (a) a.lastUsed = maxTs(a.lastUsed, t); }
  // Google tokens -> scopes + consenting users.
  for (const t of pendingTokens) {
    const cid = lc(t.clientId);
    if (!cid) continue;
    const a = get("google", cid, (x) => { x.appId = cid; });
    a.name = a.name || str(t.displayText) || (t.anonymous ? "(anonymous app " + cid.slice(0, 12) + ")" : cid);
    if (str(t.userKey)) a.users.add(str(t.userKey));
    if (!a.consentAdmin) a.consentUser = true;
    if (t.nativeApp === true) a.appType = a.appType || "Native";
    for (const s of splitScopes(t.scopes)) addScope(a, s, "delegated", { grantId: str(t.userKey) ? str(t.userKey) + ":" + cid : undefined });
  }

  // Finalise each app.
  const sanctioned = new Set((Array.isArray(o.sanctioned) ? o.sanctioned : String(o.sanctioned || "").split(/\r?\n|,/)).map(lc).filter(Boolean));
  for (const a of apps.values()) {
    a.scopes.sort((x, y) => RISK_RANK[y.risk] - RISK_RANK[x.risk] || cmp(x.scope.toLowerCase(), y.scope.toLowerCase()) || cmp(x.kind, y.kind));
    for (const s of a.scopes) { a.classes.add(s.class); s.grantIds.sort(); }
    a.maxRisk = a.scopes.length ? a.scopes[0].risk : "info";
    a.consent = a.consentAdmin && a.consentUser ? "mixed" : a.consentAdmin ? "admin" : a.consentUser ? "user" : "unknown";
    a.usersList = [...a.users].sort();
    a.assignedList = [...a.assigned].sort();
    a.userCount = a.userCount != null ? Math.max(a.userCount, a.usersList.length) : (a.usersList.length || null);
    a.classList = [...a.classes].sort();
    a.flagList = [...a.flags].sort();
    if (a.firstParty) { a.publisherVerified = true; a.publisher = a.publisher || "Microsoft"; }
    if (a.source === "entra" && (a.appId === MS_GRAPH_APP_ID || roleNames.has(a.objectId))) a.notes.add("resource API (exposes permissions to other apps)");
    a.noteList = [...a.notes].sort();
    a.sanctioned = sanctioned.size > 0 && [a.name, a.appId, a.objectId, a.key, a.oinKey].some((v) => v && sanctioned.has(lc(v)));
    a.dataAccess = a.classList.some((c) => DATA_CLASSES.includes(c));
    a.unknownOnly = a.scopes.length > 0 && a.scopes.every((s) => !s.known);
  }
  progress?.(n, n, "inventory built");
  return { apps, stats, skipped, tsMax };
}

// ---------------------------------------------------------------------------
// Detections
// ---------------------------------------------------------------------------
const C = {
  scubaConsent: { framework: "CISA SCuBA", id: "MS.AAD.5.2" },
  scubaWorkflow: { framework: "CISA SCuBA", id: "MS.AAD.5.3" },
  scubaRegister: { framework: "CISA SCuBA", id: "MS.AAD.5.1" },
  cisConsent: { framework: "CIS Microsoft 365", id: "5.1.5.1" },
  cisWorkflow: { framework: "CIS Microsoft 365", id: "5.1.5.2" },
  cisGoogle: { framework: "CIS Google Workspace", id: "2.x (third-party app access)" },
  t1528: { framework: "MITRE", id: "T1528" },
  t1550: { framework: "MITRE", id: "T1550.001" },
  t1098: { framework: "MITRE", id: "T1098.003" },
  t1566: { framework: "MITRE", id: "T1566" },
  ac6: { framework: "NIST-800-53", id: "AC-6" },
  cm7: { framework: "NIST-800-53", id: "CM-7" },
  cm8: { framework: "NIST-800-53", id: "CM-8" },
  ia5: { framework: "NIST-800-53", id: "IA-5" },
  isoAssets: { framework: "ISO27001", id: "A.5.9" },
  isoAccess: { framework: "ISO27001", id: "A.5.18" },
};

/** Detection catalogue (ids are stable; the UI lists them with their controls). */
export const DETECTIONS = [
  { id: "high_risk_scopes", title: "App holds high-risk permissions", severity: "high", controls: [C.ac6, C.t1528, C.t1550, C.scubaConsent, C.cisGoogle], needs: "scopes (grants, tokens, app scopes or installation permissions)" },
  { id: "user_consent_high", title: "User-consented app with high-risk permissions", severity: "high", controls: [C.scubaConsent, C.scubaWorkflow, C.cisConsent, C.cisWorkflow, C.cisGoogle, C.t1566, C.t1528], needs: "consent type (oauth2PermissionGrants consentType, Google Access/Users, Slack Approved by)" },
  { id: "consent_workflow", title: "Admin consent workflow not enforced", severity: "high", controls: [C.scubaWorkflow, C.cisConsent, C.cisWorkflow, C.cisGoogle, C.t1566], needs: "consent type" },
  { id: "unverified_publisher", title: "Unverified publisher with data access", severity: "high", controls: [C.scubaConsent, C.cisConsent, C.cisGoogle, C.t1566, C.t1528], needs: "servicePrincipals verifiedPublisher, Google Verified column or Slack is_app_directory_approved" },
  { id: "unused_broad", title: "Broad-scope app unused", severity: "medium", controls: [C.ac6, C.cm7, C.isoAccess], needs: "last-used data (signInActivity, service principal sign-in CSV, Slack Last used, GitHub updated_at)" },
  { id: "lookalike_name", title: "Lookalike or impersonating app name", severity: "high", controls: [C.t1566, C.t1528, C.scubaConsent, C.cisConsent], needs: "app names" },
  { id: "disabled_with_grants", title: "Disabled app still holds grants", severity: "low", controls: [C.ac6, C.isoAccess], needs: "accountEnabled / status plus grants" },
  { id: "insecure_reply_url", title: "Insecure redirect URI", severity: "medium", controls: [C.t1528, C.cm7], needs: "replyUrls / redirect_uris" },
  { id: "github_all_repos_write", title: "GitHub app writes to all repositories", severity: "medium", controls: [C.ac6, C.cm7, C.t1550], needs: "installations JSON" },
  { id: "okta_weak_grant", title: "Okta app uses implicit grant or stored passwords", severity: "medium", controls: [C.ia5, C.t1528, C.t1550], needs: "Okta apps export" },
  { id: "unsanctioned_apps", title: "Unsanctioned apps with data access", severity: "medium", controls: [C.cm7, C.cm8, C.isoAssets], needs: "inventory" },
];
const DET = Object.fromEntries(DETECTIONS.map((d) => [d.id, d]));
const DET_ORDER = Object.fromEntries(DETECTIONS.map((d, i) => [d.id, i]));

const EVIDENCE_CAP = 50;
const cap = (rows) => rows.slice(0, EVIDENCE_CAP);

function appAsset(a) {
  return { type: "ASSET", name: a.name || a.appId || a.key, data: { kind: "oauth-app", publisher: a.publisher || "", source: a.source, maxRisk: a.maxRisk, scopes: a.scopes.length, consent: a.consent, appId: a.appId || "" } };
}
function userAssets(a, limit = 25) { return a.usersList.slice(0, limit).map((u) => ({ type: "IDENTITY", name: u })); }
function scopeRows(a) { return a.scopes.map((s) => ({ app: a.name, appId: a.appId, source: a.source, scope: s.scope, kind: s.kind, risk: s.risk, class: s.class, reason: s.reason, grantIds: s.grantIds.join(" ") })); }
const appRow = (a) => ({ app: a.name, appId: a.appId, source: a.source, publisher: a.publisher, publisherVerified: a.publisherVerified, consent: a.consent, maxRisk: a.maxRisk, users: a.userCount || 0, lastUsed: iso(a.lastUsed), enabled: a.enabled });

function mk(id, a, over) {
  const d = DET[id];
  return {
    id: id + ":" + (a ? a.key : "all"), check: id, title: d.title, severity: d.severity, confidence: "likely", category: "oauth",
    controls: d.controls, tags: a ? [a.source] : [], assets: a ? [appAsset(a)] : [], evidence: [], evidenceCount: 0,
    ...over,
  };
}

/**
 * Analyze tagged rows (from parseInput). opts overrides DEFAULTS; ctx.progress(i, n, label)
 * is optional. Returns { summary, findings, tables, skipped, meta }.
 */
export function analyze(rows, opts = {}, ctx) {
  const o = { ...DEFAULTS, ...(opts || {}) };
  const unusedDays = Number.isFinite(Number(o.unusedDays)) && Number(o.unusedDays) >= 0 ? Number(o.unusedDays) : DEFAULTS.unusedDays;
  const list = Array.isArray(rows) ? rows : (rows && Array.isArray(rows.rows) ? rows.rows : []);
  const progress = ctx && typeof ctx.progress === "function" ? ctx.progress : null;
  const inv = buildInventory(list, o, progress);
  const skipped = [...inv.skipped];
  const findings = [];
  const apps = [...inv.apps.values()].sort((a, b) => cmp(a.key, b.key));
  const now = parseTs(o.now) ?? inv.tsMax;
  const sources = {};
  for (const a of apps) sources[a.source] = (sources[a.source] || 0) + 1;

  if (!apps.length) skipped.push({ check: "all", reason: list.length ? "no app records recognised in the input" : "no input" });

  // 1. High-risk scopes
  const withScopes = apps.filter((a) => a.scopes.length);
  if (!withScopes.length && apps.length) skipped.push({ check: "high_risk_scopes", reason: "no scope data: needs " + DET.high_risk_scopes.needs });
  for (const a of withScopes) {
    if (RISK_RANK[a.maxRisk] < RISK_RANK.high) continue;
    const top = a.scopes.filter((s) => s.risk === a.maxRisk);
    const appOnly = top.some((s) => s.kind === "application");
    findings.push(mk("high_risk_scopes", a, {
      severity: a.maxRisk,
      confidence: top.some((s) => s.known) ? "confirmed" : "review",
      description: (a.name || a.appId) + " (" + SOURCE_LABEL[a.source] + ") holds " + top.length + " " + a.maxRisk + "-risk permission" + (top.length === 1 ? "" : "s") + " [" + a.classList.join(", ") + "]" + (appOnly ? ", including application permissions that run without a signed-in user" : "") + ". Consent: " + a.consent + ".",
      recommendation: "Confirm a business owner for the app and reduce to the least permission that still works (prefer read-only, per-item scopes such as Files.ReadWrite over *.All). Revoke the grant if no owner claims it.",
      evidence: cap(scopeRows(a)), evidenceCount: a.scopes.length,
      tags: [a.source, ...a.classList],
    }));
  }

  // 2. User consent to high-risk permissions (+ tenant-level workflow finding per source)
  const consentKnown = apps.some((a) => a.consent !== "unknown");
  const userHigh = apps.filter((a) => (a.consent === "user" || a.consent === "mixed") && RISK_RANK[a.maxRisk] >= RISK_RANK.high);
  if (!consentKnown && apps.length) skipped.push({ check: "user_consent_high", reason: "no consent data: needs " + DET.user_consent_high.needs });
  for (const a of userHigh) {
    const n = Math.max(a.usersList.length, a.userCount || 0);
    findings.push(mk("user_consent_high", a, {
      severity: "high",
      confidence: a.source === "entra" ? "confirmed" : "likely",
      description: (a.name || a.appId) + " was consented by " + n + " user" + (n === 1 ? "" : "s") + " (not by an administrator) and holds " + a.maxRisk + "-risk permissions: " + a.scopes.filter((s) => RISK_RANK[s.risk] >= RISK_RANK.high).map((s) => s.scope).join(", ") + ".",
      recommendation: "Revoke the user grants, then require the admin consent workflow so users request access instead of granting it (Entra: Enterprise applications > Consent and permissions; Google: API controls > restrict unconfigured third-party apps).",
      evidence: cap(a.usersList.length ? a.usersList.map((u) => ({ app: a.name, appId: a.appId, source: a.source, consentingUser: u, grantIds: a.grants.filter((g) => a.scopes.some((s) => s.grantIds.includes(g))).join(" "), maxRisk: a.maxRisk })) : [{ app: a.name, appId: a.appId, source: a.source, users: a.userCount, maxRisk: a.maxRisk }]),
      evidenceCount: a.usersList.length || 1,
      assets: [appAsset(a), ...userAssets(a)],
    }));
  }
  for (const src of Object.keys(sources).sort()) {
    const hit = userHigh.filter((a) => a.source === src);
    if (!hit.length) continue;
    findings.push(mk("consent_workflow", null, {
      id: "consent_workflow:" + src, severity: "high", confidence: "likely", tags: [src],
      description: "In " + SOURCE_LABEL[src] + ", " + hit.length + " app" + (hit.length === 1 ? "" : "s") + " with high-risk permissions were granted by end users. User consent to data-access permissions is possible, which is the entry point for consent phishing.",
      recommendation: src === "entra" ? "Set user consent to 'Do not allow' or 'verified publishers, selected permissions' and enable the admin consent request workflow (CIS M365 5.1.5.1 / 5.1.5.2, SCuBA MS.AAD.5.2-5.3)."
        : src === "google" ? "In Google Admin > Security > API controls, block or limit unconfigured third-party apps and allowlist (Trusted) only reviewed apps."
        : "Require admin approval for app installs (" + SOURCE_LABEL[src] + ") and review the apps listed.",
      evidence: cap(hit.map(appRow)), evidenceCount: hit.length,
      assets: hit.slice(0, 25).map(appAsset),
    }));
  }

  // 3. Unverified publisher
  for (const src of Object.keys(sources).sort()) {
    const blind = apps.filter((a) => a.source === src && a.publisherVerified == null && !a.firstParty);
    if (blind.length) skipped.push({ check: "unverified_publisher", reason: SOURCE_LABEL[src] + ": " + blind.length + " app" + (blind.length === 1 ? "" : "s") + " without publisher verification data were not evaluated (needs " + DET.unverified_publisher.needs + ")" });
  }
  for (const a of apps) {
    if (a.publisherVerified !== false || a.firstParty || a.ownTenant) continue;
    if (RISK_RANK[a.maxRisk] < RISK_RANK.medium) continue;
    const singleTenantGuess = a.source === "entra" && !o.tenantId;
    findings.push(mk("unverified_publisher", a, {
      severity: "high",
      confidence: singleTenantGuess ? "review" : "likely",
      description: (a.name || a.appId) + " (" + SOURCE_LABEL[a.source] + ") has no verified publisher" + (a.publisher ? " (self-declared: " + a.publisher + ")" : "") + " yet holds " + a.maxRisk + "-risk permissions [" + a.classList.join(", ") + "]." + (singleTenantGuess ? " If this is your own single-tenant app, enter your tenant id in the settings to exclude it." : ""),
      recommendation: "Verify who publishes the app before keeping it; prefer apps with a verified publisher (Entra MPN verification, Google OAuth verification, Slack App Directory). Revoke if the publisher cannot be established.",
      evidence: cap([{ ...appRow(a), scopes: a.scopes.map((s) => s.scope).join(" ") }]), evidenceCount: 1,
    }));
  }

  // 4. Unused broad-scope apps
  const anyLastUsed = apps.some((a) => a.lastUsed != null);
  if (!anyLastUsed && apps.length) skipped.push({ check: "unused_broad", reason: "no last-used data: needs " + DET.unused_broad.needs });
  else if (now == null) skipped.push({ check: "unused_broad", reason: "no reference date (no timestamps in the data and opts.now not set)" });
  else {
    const broad = apps.filter((a) => RISK_RANK[a.maxRisk] >= RISK_RANK.high);
    const noData = broad.filter((a) => a.lastUsed == null);
    if (noData.length) skipped.push({ check: "unused_broad", reason: noData.length + " broad-scope app" + (noData.length === 1 ? "" : "s") + " without last-used data were not evaluated: " + noData.slice(0, 5).map((a) => a.name).join(", ") + (noData.length > 5 ? ", ..." : "") });
    for (const a of broad) {
      if (a.lastUsed == null) continue;
      const days = Math.floor((now - a.lastUsed) / 86400000);
      if (days <= unusedDays) continue;
      findings.push(mk("unused_broad", a, {
        severity: "medium", confidence: "confirmed",
        description: (a.name || a.appId) + " holds " + a.maxRisk + "-risk permissions but was last used " + days + " days before the reference date (" + iso(now) + "); threshold " + unusedDays + " days.",
        recommendation: "Remove the grants (or disable the app) and re-consent only if someone asks. Dormant broad-scope grants are pure attack surface.",
        evidence: cap([{ ...appRow(a), daysUnused: days, referenceDate: iso(now), scopes: a.scopes.map((s) => s.scope).join(" ") }]), evidenceCount: 1,
      }));
    }
  }

  // 5. Lookalike names
  for (const a of apps) {
    const m = lookalike(a);
    if (!m) continue;
    findings.push(mk("lookalike_name", a, {
      severity: "high", confidence: "review",
      description: "\"" + a.name + "\" (" + SOURCE_LABEL[a.source] + ") looks like " + (m.distance >= 0 ? "the well-known app \"" + m.target + "\"" : "a first-party " + m.target + " product") + " but " + (a.publisher ? "is published by \"" + a.publisher + "\"" : "has no identifiable publisher") + " (" + m.basis + ").",
      recommendation: "Confirm the publisher with the vendor's official listing. Impersonating names are the standard lure in consent-phishing campaigns; revoke if the publisher cannot be confirmed.",
      evidence: cap([{ ...appRow(a), resembles: m.target, distance: m.distance >= 0 ? m.distance : "brand word", basis: m.basis, scopes: a.scopes.map((s) => s.scope).join(" ") }]), evidenceCount: 1,
    }));
  }

  // 6. Disabled with grants
  for (const a of apps) {
    if (a.enabled !== false) continue;
    if (!a.grants.length && !a.scopes.length) continue;
    findings.push(mk("disabled_with_grants", a, {
      severity: "low", confidence: "confirmed",
      description: (a.name || a.appId) + " is disabled/blocked but still holds " + (a.grants.length || a.scopes.length) + " grant" + ((a.grants.length || a.scopes.length) === 1 ? "" : "s") + ". Re-enabling the app would restore access instantly.",
      recommendation: "Delete the grants (and the service principal if the app is retired) rather than leaving it disabled.",
      evidence: cap(scopeRows(a).length ? scopeRows(a) : [appRow(a)]), evidenceCount: a.scopes.length || 1,
    }));
  }

  // 7. Insecure reply URLs
  for (const a of apps) {
    const bad = a.replyUrls.filter((u) => /^http:\/\//i.test(u) || /^[a-z]+:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0)([:/]|$)/i.test(u) || /\*/.test(u));
    if (!bad.length) continue;
    findings.push(mk("insecure_reply_url", a, {
      severity: "medium", confidence: "confirmed",
      description: (a.name || a.appId) + " registers " + bad.length + " redirect URI" + (bad.length === 1 ? "" : "s") + " over plain http, on localhost or with a wildcard. Authorization codes and tokens sent there can be intercepted or redirected.",
      recommendation: "Keep only exact https:// redirect URIs; remove localhost and wildcard entries from production apps.",
      evidence: cap(bad.map((u) => ({ app: a.name, appId: a.appId, source: a.source, redirectUri: u }))), evidenceCount: bad.length,
    }));
  }

  // 8. GitHub all-repos write
  for (const a of apps) {
    if (!a.flags.has("all-repos-write")) continue;
    const w = a.scopes.filter((s) => /:(write|admin)$/.test(s.scope));
    findings.push(mk("github_all_repos_write", a, {
      severity: RISK_RANK[a.maxRisk] >= RISK_RANK.critical ? "high" : "medium", confidence: "confirmed",
      description: "GitHub app " + a.name + " is installed on all repositories with write permissions: " + w.map((s) => s.scope).join(", ") + ".",
      recommendation: "Switch the installation to selected repositories and drop write permissions the integration does not need.",
      evidence: cap(scopeRows(a)), evidenceCount: a.scopes.length,
    }));
  }

  // 9. Okta weak grant / stored passwords
  for (const a of apps) {
    if (a.source !== "okta") continue;
    const reasons = [];
    if (a.flags.has("implicit-grant")) reasons.push("implicit grant type (tokens in the URL fragment)");
    if (a.flags.has("stored-password")) reasons.push("sign-on mode " + a.signOnMode + " stores a password instead of federating");
    if (!reasons.length) continue;
    findings.push(mk("okta_weak_grant", a, {
      severity: "medium", confidence: "confirmed",
      description: "Okta app " + a.name + ": " + reasons.join("; ") + ".",
      recommendation: reasons.length > 1 || a.flags.has("implicit-grant") ? "Move to authorization code with PKCE; disable the implicit grant. For password-vaulted apps, migrate to SAML or OIDC where the vendor supports it." : "Migrate the app to SAML or OIDC so Okta never stores a reusable password.",
      evidence: cap([{ ...appRow(a), signOnMode: a.signOnMode, grantTypes: (a.grantTypes || []).join(" "), redirectUris: a.replyUrls.join(" ") }]), evidenceCount: 1,
    }));
  }

  // 10. Shadow-SaaS: unsanctioned apps with data access
  const sanctionedGiven = (Array.isArray(o.sanctioned) ? o.sanctioned : String(o.sanctioned || "").split(/\r?\n|,/)).some((s) => str(s));
  const unsanctioned = apps.filter((a) => !a.sanctioned && a.dataAccess && !a.firstParty);
  if (unsanctioned.length) {
    findings.push(mk("unsanctioned_apps", null, {
      id: "unsanctioned_apps:all", severity: unsanctioned.some((a) => a.maxRisk === "critical") ? "high" : "medium", confidence: sanctionedGiven ? "likely" : "review",
      description: unsanctioned.length + " app" + (unsanctioned.length === 1 ? "" : "s") + " with mail, file, directory, chat, code or admin access " + (sanctionedGiven ? "are not on your sanctioned list" : "were found; no sanctioned-app list was provided, so every data-access app is listed") + ". This is the shadow-SaaS inventory derived from OAuth grants.",
      recommendation: sanctionedGiven ? "Review each app: add it to the sanctioned list with an owner, or revoke its grants." : "Paste your approved apps (names or client ids) into the sanctioned list and re-run to narrow this to true shadow SaaS.",
      evidence: cap(unsanctioned.map((a) => ({ ...appRow(a), classes: a.classList.join(" "), scopes: a.scopes.length }))), evidenceCount: unsanctioned.length,
      assets: unsanctioned.slice(0, 40).map(appAsset),
      tags: [...new Set(unsanctioned.map((a) => a.source))].sort(),
    }));
  }

  findings.sort((x, y) => RISK_RANK[y.severity] - RISK_RANK[x.severity] || DET_ORDER[x.check] - DET_ORDER[y.check] || cmp(x.id, y.id));
  skipped.sort((x, y) => cmp(x.check, y.check) || cmp(x.reason, y.reason));

  // Tables
  const flaggedChecks = new Set(["high_risk_scopes", "user_consent_high", "unverified_publisher", "unused_broad", "lookalike_name", "disabled_with_grants"]);
  const flagged = new Map();
  for (const f of findings) if (flaggedChecks.has(f.check) && f.id.includes(":")) { const k = f.id.slice(f.id.indexOf(":") + 1); if (!flagged.has(k)) flagged.set(k, []); flagged.get(k).push(f.check); }
  const tables = {
    apps: apps.map((a) => ({
      key: a.key, app: a.name, appId: a.appId, objectId: a.objectId, source: a.source, publisher: a.publisher, publisherVerified: a.publisherVerified, firstParty: a.firstParty,
      enabled: a.enabled, consent: a.consent, users: a.userCount || 0, consentingUsers: a.usersList.slice(0, 10).join(" "), assignedUsers: a.assignedList.length,
      scopes: a.scopes.length, scopeClasses: a.classList.join(" "), maxRisk: a.maxRisk, grants: a.grants.length, lastUsed: iso(a.lastUsed), firstSeen: iso(a.created),
      sanctioned: a.sanctioned, flags: a.flagList.join(" "), notes: a.noteList.join("; "), findings: (flagged.get(a.key) || []).join(" "),
    })),
    scopes: apps.flatMap((a) => a.scopes.map((s) => ({ key: a.key, app: a.name, appId: a.appId, source: a.source, scope: s.scope, kind: s.kind, risk: s.risk, class: s.class, known: s.known, reason: s.reason, grantIds: s.grantIds.join(" ") }))),
    revoke: apps.filter((a) => flagged.has(a.key)).map((a) => ({ app: a.name, appId: a.appId, objectId: a.objectId, source: a.source, grantIds: a.grants.join(" "), scopes: a.scopes.map((s) => s.scope).join(" "), reasons: flagged.get(a.key).join(" ") })),
    users: (() => {
      const m = new Map();
      for (const a of apps) for (const u of a.usersList) { const e = m.get(u) || { user: u, apps: [], maxRisk: "info" }; e.apps.push(a.name || a.appId); if (RISK_RANK[a.maxRisk] > RISK_RANK[e.maxRisk]) e.maxRisk = a.maxRisk; m.set(u, e); }
      return [...m.values()].sort((x, y) => cmp(x.user, y.user)).map((e) => ({ user: e.user, apps: e.apps.sort().join(" "), appCount: e.apps.length, maxRisk: e.maxRisk }));
    })(),
  };

  const kpi = (check) => new Set(findings.filter((f) => f.check === check).map((f) => f.id)).size;
  const summary = {
    rows: list.length, files: inv.stats.files.size, apps: apps.length, sources,
    highRiskApps: apps.filter((a) => RISK_RANK[a.maxRisk] >= RISK_RANK.high).length,
    userConsentedHighRisk: kpi("user_consent_high"), unverifiedPublishers: kpi("unverified_publisher"), unusedBroad: kpi("unused_broad"),
    unsanctioned: unsanctioned.length, lookalikes: kpi("lookalike_name"),
    grants: inv.stats.grants, appRoleAssignments: inv.stats.appRoles, tokens: inv.stats.tokens,
    findings: findings.length, bySeverity: countBy(findings, "severity"), now: iso(now),
  };
  const meta = { tool: TOOL_ID, version: VERSION, rows: list.length, apps: apps.length, now: iso(now), unusedDays, sanctioned: sanctionedGiven, tenantId: str(o.tenantId) ? "set" : "", recordTypes: inv.stats.types };
  progress?.(list.length, list.length, "done");
  return { summary, findings, tables, skipped, meta };
}

/** Parse a list of { name, text } files and analyze them in one step (worker entry point). */
export function analyzeFiles(files, opts = {}, ctx) {
  const p = parseInput(files);
  const r = analyze(p.rows, opts, ctx);
  r.skipped = [...p.skipped, ...r.skipped];
  r.files = p.files;
  return r;
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
const csv = (cols, rows, pick) => [cols.join(","), ...(rows || []).map((r) => pick(r).map(q).join(","))].join("\n");

const FINDING_COLS = ["severity", "confidence", "category", "check", "title", "description", "recommendation", "controls", "assets", "evidenceCount"];
/** Findings as CSV with fixed columns. */
export function findingsToCsv(findings) {
  return csv(FINDING_COLS, findings, (f) => [
    f.severity, f.confidence, f.category, f.check, f.title, f.description, f.recommendation,
    (f.controls || []).map((c) => c.framework + " " + c.id).join("; "), (f.assets || []).map((a) => a.name).join("; "),
    f.evidenceCount != null ? f.evidenceCount : (f.evidence || []).length,
  ]);
}

const APP_COLS = ["app", "appId", "objectId", "source", "publisher", "publisherVerified", "firstParty", "enabled", "consent", "users", "consentingUsers", "scopes", "scopeClasses", "maxRisk", "grants", "lastUsed", "firstSeen", "sanctioned", "flags", "findings", "notes"];
/** App inventory (tables.apps) as CSV. */
export function appsToCsv(apps) { return csv(APP_COLS, apps, (a) => APP_COLS.map((k) => (a[k] === null || a[k] === undefined ? "" : a[k]))); }

const REVOKE_COLS = ["app", "appId", "objectId", "source", "grantIds", "scopes", "reasons"];
/** Revoke list (tables.revoke) as CSV: one row per flagged app with its grant ids. */
export function revokeToCsv(revoke) { return csv(REVOKE_COLS, revoke, (r) => REVOKE_COLS.map((k) => r[k])); }

/** Plain-text summary for the TXT export. */
export function summaryText(result) {
  const s = result.summary, lines = [
    "OAuth App Governance summary (" + TOOL_ID + " v" + VERSION + ")",
    "Reference date: " + (s.now || "n/a"),
    "Records: " + s.rows + " in " + s.files + " file(s); apps: " + s.apps + " (" + Object.keys(s.sources).sort().map((k) => SOURCE_LABEL[k] + " " + s.sources[k]).join(", ") + ")",
    "High-risk apps: " + s.highRiskApps + "; user-consented high-risk: " + s.userConsentedHighRisk + "; unverified publishers: " + s.unverifiedPublishers + "; unused broad-scope: " + s.unusedBroad + "; unsanctioned: " + s.unsanctioned,
    "Findings: " + s.findings + " " + JSON.stringify(s.bySeverity),
    "",
  ];
  for (const f of result.findings) lines.push("- [" + f.severity + "/" + f.confidence + "] " + f.title + (f.assets && f.assets[0] ? " - " + f.assets[0].name : "") + ": " + f.recommendation);
  if (result.skipped.length) { lines.push("", "Skipped:"); for (const k of result.skipped) lines.push("- " + k.check + ": " + k.reason); }
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Synthetic example (seeded; format-faithful; labelled)
// ---------------------------------------------------------------------------
function guidFrom(rnd) {
  const h = () => Math.floor(rnd() * 16).toString(16);
  const s = (n) => Array.from({ length: n }, h).join("");
  return s(8) + "-" + s(4) + "-4" + s(3) + "-a" + s(3) + "-" + s(12);
}

/** Example files in the exact vendor layouts. Not real data. */
export function exampleDataset(seed = 7) {
  let s = seed >>> 0;
  const rnd = () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 4294967296; };
  const g = () => guidFrom(rnd);
  const OWN = g(), GRAPH_SP = g(), TEAMS = g(), SYNC = g(), CRM = g(), OLD = g(), NOTES = g();
  const u = [g(), g(), g()];
  const sps = {
    value: [
      { id: GRAPH_SP, appId: MS_GRAPH_APP_ID, displayName: "Microsoft Graph", appOwnerOrganizationId: MS_FIRST_PARTY_TENANT, servicePrincipalType: "Application", accountEnabled: true, createdDateTime: "2023-02-10T09:12:44Z", verifiedPublisher: { displayName: null, verifiedPublisherId: null, addedDateTime: null }, publisherName: "Microsoft Services", signInAudience: "AzureADMultipleOrgs", tags: [], homepage: null, replyUrls: [],
        appRoles: [{ id: "7ab1d382-f21e-4acd-a863-ba3e13f7da61", value: "Directory.Read.All", displayName: "Read directory data" }, { id: "810c84a8-4a9e-49e6-bf7d-12d183f40d01", value: "Mail.Read", displayName: "Read mail in all mailboxes" }], oauth2PermissionScopes: [] },
      { id: TEAMS, appId: g(), displayName: "Microsoft Teams", appOwnerOrganizationId: MS_FIRST_PARTY_TENANT, servicePrincipalType: "Application", accountEnabled: true, createdDateTime: "2023-02-10T09:12:50Z", verifiedPublisher: { displayName: null, verifiedPublisherId: null, addedDateTime: null }, publisherName: "Microsoft Services", signInAudience: "AzureADMultipleOrgs", tags: ["WindowsAzureActiveDirectoryIntegratedApp"], homepage: "https://teams.microsoft.com", replyUrls: ["https://teams.microsoft.com/go"], appRoles: [], oauth2PermissionScopes: [],
        signInActivity: { lastSignInDateTime: "2026-10-01T07:40:12Z" } },
      { id: SYNC, appId: g(), displayName: "Outlook Mail Sync", appOwnerOrganizationId: g(), servicePrincipalType: "Application", accountEnabled: true, createdDateTime: "2026-08-19T15:03:21Z", verifiedPublisher: { displayName: null, verifiedPublisherId: null, addedDateTime: null }, publisherName: "Vendor B Labs", signInAudience: "AzureADandPersonalMicrosoftAccount", tags: ["WindowsAzureActiveDirectoryIntegratedApp"], homepage: "http://vendor-b.test.darknode.ai", replyUrls: ["http://vendor-b.test.darknode.ai/callback", "https://vendor-b.test.darknode.ai/callback"], appRoles: [], oauth2PermissionScopes: [],
        signInActivity: { lastSignInDateTime: "2026-10-02T11:15:09Z" } },
      { id: CRM, appId: g(), displayName: "Vendor A CRM Connector", appOwnerOrganizationId: g(), servicePrincipalType: "Application", accountEnabled: true, createdDateTime: "2025-03-04T10:00:00Z", verifiedPublisher: { displayName: "Vendor A Software Ltd", verifiedPublisherId: "1234567", addedDateTime: "2024-11-01T00:00:00Z" }, publisherName: "Vendor A Software Ltd", signInAudience: "AzureADMultipleOrgs", tags: ["WindowsAzureActiveDirectoryIntegratedApp"], homepage: "https://crm.vendor-a.test.darknode.ai", replyUrls: ["https://crm.vendor-a.test.darknode.ai/auth"], appRoles: [], oauth2PermissionScopes: [],
        signInActivity: { lastSignInDateTime: "2026-05-14T03:00:00Z" } },
      { id: OLD, appId: g(), displayName: "Legacy Expense Importer", appOwnerOrganizationId: g(), servicePrincipalType: "Application", accountEnabled: false, createdDateTime: "2022-06-30T08:00:00Z", verifiedPublisher: { displayName: "Vendor C Finance Apps", verifiedPublisherId: "7654321", addedDateTime: "2022-01-15T00:00:00Z" }, publisherName: "Vendor C Finance Apps", signInAudience: "AzureADMultipleOrgs", tags: ["WindowsAzureActiveDirectoryIntegratedApp"], homepage: "https://expenses.vendor-c.test.darknode.ai", replyUrls: ["https://expenses.vendor-c.test.darknode.ai/cb"], appRoles: [], oauth2PermissionScopes: [],
        signInActivity: { lastSignInDateTime: "2025-09-01T12:00:00Z" } },
      { id: NOTES, appId: g(), displayName: "Vendor D Meeting Notes", appOwnerOrganizationId: g(), servicePrincipalType: "Application", accountEnabled: true, createdDateTime: "2026-01-20T14:22:00Z", verifiedPublisher: { displayName: "Vendor D Inc", verifiedPublisherId: "2468101", addedDateTime: "2025-10-10T00:00:00Z" }, publisherName: "Vendor D Inc", signInAudience: "AzureADMultipleOrgs", tags: ["WindowsAzureActiveDirectoryIntegratedApp"], homepage: "https://notes.vendor-d.test.darknode.ai", replyUrls: ["https://notes.vendor-d.test.darknode.ai/oauth"], appRoles: [], oauth2PermissionScopes: [],
        signInActivity: { lastSignInDateTime: "2026-10-03T16:05:44Z" } },
    ],
  };
  const grants = {
    value: [
      { id: g(), clientId: TEAMS, consentType: "AllPrincipals", principalId: null, resourceId: GRAPH_SP, scope: "User.Read openid profile offline_access" },
      { id: g(), clientId: SYNC, consentType: "Principal", principalId: u[0], resourceId: GRAPH_SP, scope: "Mail.ReadWrite Mail.Send MailboxSettings.ReadWrite offline_access User.Read" },
      { id: g(), clientId: SYNC, consentType: "Principal", principalId: u[1], resourceId: GRAPH_SP, scope: "Mail.ReadWrite Mail.Send offline_access User.Read" },
      { id: g(), clientId: SYNC, consentType: "Principal", principalId: u[2], resourceId: GRAPH_SP, scope: "Mail.ReadWrite offline_access User.Read" },
      { id: g(), clientId: CRM, consentType: "AllPrincipals", principalId: null, resourceId: GRAPH_SP, scope: "User.Read Contacts.Read offline_access" },
      { id: g(), clientId: OLD, consentType: "AllPrincipals", principalId: null, resourceId: GRAPH_SP, scope: "Files.ReadWrite.All User.Read" },
      { id: g(), clientId: NOTES, consentType: "AllPrincipals", principalId: null, resourceId: GRAPH_SP, scope: "User.Read Calendars.Read openid profile" },
    ],
  };
  const appRoles = {
    value: [
      { id: g(), appRoleId: "7ab1d382-f21e-4acd-a863-ba3e13f7da61", principalId: CRM, principalDisplayName: "Vendor A CRM Connector", principalType: "ServicePrincipal", resourceId: GRAPH_SP, resourceDisplayName: "Microsoft Graph", createdDateTime: "2025-03-04T10:05:00Z" },
    ],
  };
  const googleApps = [
    "App name,Client ID,App type,Verified,Access,Users",
    "Grammar Helper,412093817263-ab3hu7e2.apps.googleusercontent.com,Web application,Yes,Limited,48",
    "PDF Merge Pro,884120077311-pdfmerge.apps.googleusercontent.com,Web application,No,Limited,6",
    "Vendor A CRM Connector,201177431908-vendora.apps.googleusercontent.com,Web application,Yes,Trusted,120",
  ].join("\n");
  const googleTokens = {
    kind: "admin#reports#tokens",
    items: [
      { kind: "admin#reports#token", clientId: "412093817263-ab3hu7e2.apps.googleusercontent.com", displayText: "Grammar Helper", anonymous: false, nativeApp: false, userKey: "test@darknode.ai", scopes: ["https://www.googleapis.com/auth/documents", "https://www.googleapis.com/auth/userinfo.email", "openid"] },
      { kind: "admin#reports#token", clientId: "884120077311-pdfmerge.apps.googleusercontent.com", displayText: "PDF Merge Pro", anonymous: false, nativeApp: false, userKey: "finance@darknode.ai", scopes: ["https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/userinfo.email"] },
      { kind: "admin#reports#token", clientId: "884120077311-pdfmerge.apps.googleusercontent.com", displayText: "PDF Merge Pro", anonymous: false, nativeApp: false, userKey: "ops@darknode.ai", scopes: ["https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/userinfo.email"] },
      { kind: "admin#reports#token", clientId: "201177431908-vendora.apps.googleusercontent.com", displayText: "Vendor A CRM Connector", anonymous: false, nativeApp: false, userKey: "sales@darknode.ai", scopes: ["https://www.googleapis.com/auth/contacts.readonly", "https://www.googleapis.com/auth/calendar.readonly", "https://www.googleapis.com/auth/userinfo.email"] },
    ],
  };
  const slack = [
    "App name,App ID,Installed by,Installation date,Scopes,Approved by,Status,Last used",
    "Standup Bot,A0F7XDUAZ,test@darknode.ai,2026-03-02,\"chat:write,commands,users:read\",admin@darknode.ai,Approved,2026-10-03",
    "Channel Archiver,A08J2K3L4,ops@darknode.ai,2026-06-11,\"channels:history,groups:history,files:read,users:read.email\",,Approved,2026-06-20",
  ].join("\n");
  const files = [
    { name: "servicePrincipals.json", text: JSON.stringify(sps, null, 2) },
    { name: "oauth2PermissionGrants.json", text: JSON.stringify(grants, null, 2) },
    { name: "appRoleAssignments.json", text: JSON.stringify(appRoles, null, 2) },
    { name: "google-third-party-apps.csv", text: googleApps },
    { name: "google-tokens.json", text: JSON.stringify(googleTokens, null, 2) },
    { name: "slack-apps.csv", text: slack },
  ];
  const parsed = parseInput(files);
  return { label: "synthetic example (not real data)", files, rows: parsed.rows, parsed, ids: { OWN, GRAPH_SP, TEAMS, SYNC, CRM, OLD, NOTES, users: u } };
}

/** Real deterministic checks of the engine on the synthetic example. */
export function selfTest() {
  const tests = [];
  const ex = exampleDataset();
  const r = analyze(ex.rows, { now: "2026-10-05T00:00:00Z" });
  const by = (check) => r.findings.filter((f) => f.check === check);
  const named = (check, name) => by(check).find((f) => f.assets && f.assets[0] && f.assets[0].name === name);
  tests.push({ name: "six formats parsed", pass: ex.parsed.files.length === 6 && ex.parsed.files.every((f) => f.format !== "generic") });
  tests.push({ name: "inventory lists 11 apps", pass: r.summary.apps === 11 });
  tests.push({ name: "app-only Directory.Read.All is critical", pass: !!named("high_risk_scopes", "Vendor A CRM Connector") && named("high_risk_scopes", "Vendor A CRM Connector").severity === "critical" });
  tests.push({ name: "user-consented Mail.ReadWrite flagged with 3 users", pass: !!named("user_consent_high", "Outlook Mail Sync") && named("user_consent_high", "Outlook Mail Sync").evidenceCount === 3 });
  tests.push({ name: "unverified publisher flagged", pass: !!named("unverified_publisher", "Outlook Mail Sync") });
  tests.push({ name: "first-party Teams never flagged", pass: !r.findings.some((f) => f.assets && f.assets.some((a) => a.name === "Microsoft Teams")) });
  tests.push({ name: "lookalike brand word flagged", pass: !!named("lookalike_name", "Outlook Mail Sync") });
  tests.push({ name: "disabled app with grants is low", pass: !!named("disabled_with_grants", "Legacy Expense Importer") && named("disabled_with_grants", "Legacy Expense Importer").severity === "low" });
  tests.push({ name: "http reply url flagged", pass: !!named("insecure_reply_url", "Outlook Mail Sync") });
  tests.push({ name: "unused broad-scope CRM flagged (144 days)", pass: !!named("unused_broad", "Vendor A CRM Connector") });
  tests.push({ name: "deterministic", pass: JSON.stringify(analyze(ex.rows, { now: "2026-10-05T00:00:00Z" })) === JSON.stringify(r) });
  tests.push({ name: "empty input yields no findings", pass: analyze([]).findings.length === 0 });
  return { pass: tests.every((t) => t.pass), tests };
}
