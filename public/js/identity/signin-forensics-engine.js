// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Sign-in Forensics engine. Pure logic: no DOM, no network, no timers.
//
// Takes identity-provider sign-in log exports (Microsoft Entra ID sign-in CSV,
// Google Workspace Login audit CSV, Okta System Log JSON, or any CSV/JSON with
// recognisable column names), normalises every row to one record shape, then runs
// deterministic detections for account-compromise patterns. Every detection
// declares the columns it needs; when the export lacks one the detection is
// skipped and the reason is reported, never guessed.
//
// Normalised record:
//   { ts, user, ip, success, app, clientApp, mfa, country, city, lat, lon,
//     userAgent, failureReason, isAdmin, adminBasis, asn, isp, isProxy, riskFlag, raw }
//   ts: epoch ms; success: true | false | null (null = not an authentication
//   outcome, e.g. logout); mfa / isAdmin / isProxy: true | false | null (unknown).

import { controlsFromRefs } from "../core/sink-map.js";

// ---------------------------------------------------------------------------
// CSV tokenizer (RFC 4180-ish): quoted fields, doubled quotes, embedded commas
// and newlines, CRLF, optional UTF-8 BOM. Generator so callers can parse large
// files in slices and yield to the event loop between slices.
// ---------------------------------------------------------------------------
export function* iterCsvRows(text, delimiter) {
  let s = String(text || "");
  if (s.charCodeAt(0) === 0xfeff) s = s.slice(1);
  const d = delimiter || sniffDelimiter(s);
  const n = s.length;
  let i = 0, row = [], field = "", quoted = false, any = false;
  while (i < n) {
    const c = s[i];
    if (quoted) {
      if (c === '"') {
        if (s[i + 1] === '"') { field += '"'; i += 2; continue; }
        quoted = false; i++; continue;
      }
      field += c; i++; continue;
    }
    if (c === '"') { quoted = true; any = true; i++; continue; }
    if (c === d) { row.push(field); field = ""; any = true; i++; continue; }
    if (c === "\r") { i++; continue; }
    if (c === "\n") {
      row.push(field); field = ""; i++;
      if (any || row.length > 1 || row[0] !== "") yield row;
      row = []; any = false; continue;
    }
    field += c; any = true; i++;
  }
  if (any || field !== "" || row.length) { row.push(field); if (row.some((f) => f !== "")) yield row; }
}

export function sniffDelimiter(text) {
  const head = String(text || "").split(/\r?\n/, 1)[0] || "";
  const counts = { ",": 0, ";": 0, "\t": 0 };
  let q = false;
  for (const c of head) { if (c === '"') q = !q; else if (!q && c in counts) counts[c]++; }
  let best = ",", bestN = -1;
  for (const k of Object.keys(counts)) if (counts[k] > bestN) { best = k; bestN = counts[k]; }
  return bestN > 0 ? best : ",";
}

export function parseCsv(text) {
  const rows = [...iterCsvRows(text)];
  if (!rows.length) return { headers: [], rows: [] };
  return { headers: rows[0].map((h) => String(h).trim()), rows: rows.slice(1) };
}

// ---------------------------------------------------------------------------
// Header synonyms. Keys are normalised (lowercase, alphanumerics only) so that
// "IP address", "ipAddress", "client.ipAddress" and "IP_Address" all match.
// Order matters: earlier entries win when several columns are present.
// ---------------------------------------------------------------------------
const FIELD_SYNONYMS = {
  ts: ["dateutc", "date", "createddatetime", "timestamp", "time", "published", "eventtime", "datetime", "created", "createdutc", "logintime", "signintime", "timegenerated", "activitydatetime"],
  user: ["username", "userprincipalname", "upn", "actoralternateid", "useremail", "email", "principal", "account", "user", "accountname", "login", "subject", "actordisplayname"],
  userId: ["userid", "actorid", "objectid"],
  ip: ["ipaddress", "clientipaddress", "ip", "sourceip", "sourceipaddress", "callerip", "remoteip", "clientip", "ipaddr"],
  status: ["status", "result", "outcomeresult", "outcome", "loginresult", "statuserrorcode", "errorcode", "resulttype", "eventname", "eventtype", "action"],
  app: ["application", "appdisplayname", "app", "resource", "resourcedisplayname", "targetdisplayname", "service", "applicationname"],
  clientApp: ["clientapp", "clientappused", "logintype", "clienttype", "protocol", "authprotocol", "clientappname"],
  authRequirement: ["authenticationrequirement", "authrequirement"],
  mfaResult: ["multifactorauthenticationresult", "mfaresult", "mfadetailauthmethod", "mfa", "issecondfactor", "secondfactor", "mfaused", "authenticationmethodsused", "authenticationcontextcredentialtype", "credentialtype"],
  country: ["countryregion", "country", "locationcountryorregion", "countryorregion", "clientgeographicalcontextcountry", "geocountry", "countrycode"],
  city: ["city", "locationcity", "clientgeographicalcontextcity", "geocity"],
  state: ["stateprovince", "state", "locationstate", "region"],
  lat: ["latitude", "lat", "locationgeocoordinateslatitude", "clientgeographicalcontextgeolocationlat", "geolat"],
  lon: ["longitude", "lon", "lng", "long", "locationgeocoordinateslongitude", "clientgeographicalcontextgeolocationlon", "geolon"],
  userAgent: ["useragent", "clientuseragentrawuseragent", "rawuseragent", "ua"],
  browser: ["browser", "clientuseragentbrowser"],
  os: ["operatingsystem", "os", "clientuseragentos"],
  failureReason: ["failurereason", "outcomereason", "loginfailuretype", "statusfailurereason", "errordescription", "reason", "eventdescription", "signinerrorcode"],
  role: ["role", "roles", "isadmin", "admin", "privileged", "userrole", "roleassignment", "isprivileged", "usertype"],
  asn: ["autonomoussystemnumber", "asn", "securitycontextasnumber", "asnumber"],
  isp: ["isp", "asorg", "securitycontextasorg", "securitycontextisp", "organization", "org", "asorganization"],
  isProxy: ["securitycontextisproxy", "isproxy", "proxy", "anonymizer"],
  riskFlag: ["riskstate", "issuspicious", "risklevelduringsignin", "risklevel", "riskdetail", "suspicious", "riskeventtypes"],
  deviceId: ["deviceid", "deviceid"],
};

export function normHeader(h) { return String(h == null ? "" : h).toLowerCase().replace(/[^a-z0-9]/g, ""); }

// Resolve each logical field to a column index (or object key) from a header list.
export function mapHeaders(headers) {
  const norm = headers.map(normHeader);
  const map = {};
  for (const [field, syns] of Object.entries(FIELD_SYNONYMS)) {
    for (const s of syns) {
      const idx = norm.indexOf(s);
      if (idx >= 0) { map[field] = idx; break; }
    }
  }
  // Entra: the "Status" column is the outcome; "Event Name" (Google) is also the
  // outcome carrier. If both "status" and a Google-style event name exist, prefer status.
  return map;
}

// ---------------------------------------------------------------------------
// Source detection
// ---------------------------------------------------------------------------
export function detectSourceFromHeaders(headers) {
  const set = new Set(headers.map(normHeader));
  const has = (...k) => k.some((x) => set.has(x));
  if (has("eventtype") && has("actoralternateid", "clientipaddress", "outcomeresult")) return "okta";
  if (has("eventname") && (has("eventdescription") || has("logintype") || has("issuspicious"))) return "google";
  if (has("clientapp", "clientappused", "conditionalaccess", "requestid", "authenticationrequirement", "userprincipalname", "multifactorauthenticationresult")) return "entra";
  if (has("dateutc") && has("status") && has("ipaddress")) return "entra";
  if (has("status", "result", "outcome", "eventname") && has("ipaddress", "ip", "sourceip", "clientip") && has("user", "username", "email", "userprincipalname", "account")) return "generic";
  return "unknown";
}

export function detectSourceFromObject(o) {
  if (!o || typeof o !== "object") return "unknown";
  if (o.eventType && (o.actor || o.client || o.outcome)) return "okta";
  if (o.userPrincipalName !== undefined || o.createdDateTime !== undefined || o.clientAppUsed !== undefined) return "entra";
  if (o.events && o.id && o.id.applicationName === "login") return "google"; // Reports API shape
  return "generic";
}

// ---------------------------------------------------------------------------
// Value parsers
// ---------------------------------------------------------------------------
export function parseTs(v) {
  if (v == null || v === "") return NaN;
  if (typeof v === "number") return v < 1e11 ? v * 1000 : v;
  let s = String(v).trim();
  if (/^\d{9,13}$/.test(s)) { const n = Number(s); return n < 1e11 ? n * 1000 : n; }
  // "2026-10-05 14:03:22" / "2026-10-05T14:03:22.123" with no zone: the exports label
  // these columns UTC, so read them as UTC rather than the browser's local zone.
  const m = s.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,3})\d*)?)?$/);
  if (m) return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0), +((m[7] || "0").padEnd(3, "0")));
  // Date-only ISO: Date.parse already reads it as UTC, so it must not get the local shift below.
  const dm = s.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (dm) { const t = Date.UTC(+dm[1], +dm[2] - 1, +dm[3]); return new Date(t).getUTCDate() === +dm[3] ? t : NaN; }
  // Slash dates: month-first, but 25/12/2024 can only be day-first (EU-locale Excel re-save).
  const sm = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4}),?(?:[ T]+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([AP]M)?)?$/i);
  if (sm) {
    let mo = +sm[1], d = +sm[2], h = +(sm[4] || 0);
    if (mo > 12) { const x = mo; mo = d; d = x; }
    if (sm[7]) { if (h < 1 || h > 12) return NaN; h = (h % 12) + (/p/i.test(sm[7]) ? 12 : 0); }
    const t = Date.UTC(+sm[3], mo - 1, d, h, +(sm[5] || 0), +(sm[6] || 0));
    const c = new Date(t);
    return mo >= 1 && mo <= 12 && c.getUTCDate() === d && h < 24 && +(sm[5] || 0) < 60 && +(sm[6] || 0) < 60 ? t : NaN;
  }
  // "GMT+5:30" / "UTC-4" (Google console): Date.parse misreads a one-digit offset hour.
  s = s.replace(/\b(?:GMT|UTC)([+-])(\d{1,2})(?::?(\d{2}))?\s*$/i, (_, sg, hh, mm) => sg + hh.padStart(2, "0") + ":" + (mm || "00"));
  // "October 5, 2026 at 2:03:22 PM UTC" (Google console)
  s = s.replace(/\bat\b/i, "").replace(/\s{2,}/g, " ").trim();
  const t = Date.parse(s);
  if (Number.isNaN(t)) return NaN;
  // Any other zone-less form ("10/5/2026, 2:03:22 PM"): Date.parse used the local zone; shift to UTC.
  if (!/(z|utc|gmt|[+-]\d{2}:?\d{2}|\b[A-Z]{2,5}T\b)\s*$/i.test(s) && !/^\d{4}-\d{2}-\d{2}T/.test(s)) return t - new Date(t).getTimezoneOffset() * 60000;
  return t;
}

export function parseBool(v) {
  if (v === true || v === false) return v;
  if (v == null) return null;
  const s = String(v).trim().toLowerCase();
  if (!s) return null;
  if (["true", "yes", "1", "y", "t"].includes(s)) return true;
  if (["false", "no", "0", "n", "f"].includes(s)) return false;
  return null;
}

const ENTRA_INTERRUPT_CODES = new Set(["50058", "50074", "50076", "50079", "50097", "50125", "50129", "50140", "50158"]);

// true = successful authentication, false = failed authentication, null = not an
// authentication outcome (logout, token refresh, "interrupted", unknown).
export function parseOutcome(v) {
  if (v === true) return true;
  if (v === false) return false;
  if (v == null) return null;
  const s = String(v).trim().toLowerCase();
  if (!s) return null;
  if (s === "0" || s === "success" || s === "succeeded" || s === "successful" || s === "ok" || s === "allow" || s === "allowed" || s === "pass" || s === "passed") return true;
  if (s === "login_success" || s === "suspicious_login" || s === "suspicious_login_less_secure_app" || s === "login_success_sso") return true;
  if (s === "user.session.start" || s === "user.authentication.sso") return true; // only used when no outcome column
  if (s === "login_failure" || s === "failure" || s === "failed" || s === "fail" || s === "deny" || s === "denied" || s === "blocked" || s === "locked_out" || s === "lockedout") return false;
  if (s === "interrupted" || s === "logout" || s === "login_verification" || s === "login_challenge" || s === "account_disabled_password_leak" || s === "account_disabled_generic" || s === "skipped" || s === "unknown") return null;
  // Entra interrupts (MFA/KMSI/device prompts after a correct password): the portal CSV says "Interrupted", Graph JSON only the code.
  if (ENTRA_INTERRUPT_CODES.has(s)) return null;
  if (/^\d+$/.test(s)) return false; // non-zero Entra error code
  if (/fail|denied|invalid|error|reject/.test(s)) return false;
  if (/success/.test(s)) return true;
  return null;
}

// Entra "Multifactor authentication result" free text + "Authentication requirement".
export function parseMfa(result, requirement) {
  // The portal CSV writes "Single-factor authentication"; Graph writes "singleFactorAuthentication".
  const req = String(requirement == null ? "" : requirement).toLowerCase().replace(/[^a-z]/g, "");
  if (req.includes("multifactor")) return true;
  if (req.includes("singlefactor")) return false;
  const b = parseBool(result);
  if (b !== null) return b;
  const r = String(result == null ? "" : result).toLowerCase();
  if (!r) return null;
  if (/satisfied|completed|success|passed|approved|mfa requirement/.test(r)) return true;
  if (/denied|failed|not completed|user declined|timed out|expired/.test(r)) return false;
  if (/password|none|single/.test(r)) return false;
  return null;
}

// Legacy (basic-auth) protocols cannot carry a second factor.
const LEGACY_RE = /activesync|\bimap4?\b|\bpop3?\b|\bsmtp\b|authenticated smtp|other clients|mapi|autodiscover|exchange web services|\bews\b|offline address book|exchange online powershell|reporting web services|^exchange$|legacy/i;
export function isLegacyClient(clientApp) { return !!clientApp && LEGACY_RE.test(String(clientApp)); }

const ADMIN_APP_RE = /azure portal|entra admin|admin center|admin console|azure cli|azure powershell|graph powershell|exchange admin|security center|microsoft defender|intune|google admin|admin\.google|okta admin|cloud shell/i;
const ADMIN_USER_RE = /(^|[._-])(admin|administrator|root|superuser|breakglass|break-glass|sysadmin|globaladmin)([._-]|$)|^adm[._-]|[._-]adm$|^svc[._-]?admin/i;
const ADMIN_ROLE_RE = /admin|administrator|owner|privileged|superuser|super user|global|security operator|helpdesk|user access/i;

export function adminHint(user, app, role) {
  if (role != null && String(role).trim() !== "") {
    const b = parseBool(role);
    if (b !== null) return { isAdmin: b, basis: "role" };
    const r = String(role).toLowerCase();
    if (r === "member" || r === "guest" || r === "user" || r === "none" || r === "standard") return { isAdmin: false, basis: "role" };
    return { isAdmin: ADMIN_ROLE_RE.test(r), basis: "role" };
  }
  if (app && ADMIN_APP_RE.test(String(app))) return { isAdmin: true, basis: "admin application" };
  if (user && ADMIN_USER_RE.test(String(user).split("@")[0])) return { isAdmin: true, basis: "username pattern" };
  return { isAdmin: null, basis: null };
}

const HOSTING_RE = /digitalocean|digital ocean|amazon|aws|ec2|google cloud|google llc|microsoft azure|azure|ovh|hetzner|linode|akamai connected cloud|vultr|choopa|contabo|m247|datacamp|cdn77|leaseweb|hostinger|psychz|quadranet|serverius|zenlayer|packet host|oracle cloud|alibaba|tencent cloud|scaleway|online s\.a\.s|ionos|godaddy|namecheap|hostwinds|colocrossing|frantech|buyvm|ramnode|ipxo|nordvpn|nord vpn|expressvpn|surfshark|mullvad|private internet access|proton|windscribe|cyberghost|ipvanish|tunnelbear|hide\.?me|purevpn|torguard|tor exit|tor-exit|the onion router|vpn/i;
export function hostingHint(isp, asn) {
  const s = `${isp || ""} ${asn || ""}`.trim();
  if (!s) return null;
  const m = s.match(HOSTING_RE);
  return m ? m[0] : null;
}

export function subnet24(ip) {
  const s = String(ip || "").trim();
  const m = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$/);
  if (m) return `${m[1]}.${m[2]}.${m[3]}.0/24`;
  if (s.includes(":")) {
    // expand "::" first: a plain split put 2001:db8::1 in "2001:db8::1::/64", and the same /64
    // written two ways (2001:db8:0:0:... vs 2001:0db8::...) never grouped
    const v6 = s.replace(/%.*$/, "").toLowerCase();
    const mapped = v6.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
    if (mapped) return subnet24(mapped[1]);
    const halves = v6.split("::");
    if (halves.length <= 2) {
      const head = halves[0] ? halves[0].split(":") : [], tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
      const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
      const g = [...head, ...Array(Math.max(0, fill)).fill("0"), ...tail];
      if (g.length === 8 && g.every((x) => /^[0-9a-f]{1,4}$/.test(x))) return g.slice(0, 4).map((x) => x.replace(/^0+(?=.)/, "")).join(":") + "::/64";
    }
    return s;
  }
  return s;
}

function num(v) { if (v == null || v === "") return null; const n = Number(v); return Number.isFinite(n) ? n : null; }
function str(v) { if (v == null) return ""; return String(v).trim(); }
function nonEmpty(v) { const s = str(v); return s ? s : null; }

// ---------------------------------------------------------------------------
// Row normalisers
// ---------------------------------------------------------------------------
function baseRecord(raw) {
  return { ts: NaN, user: null, ip: null, success: null, app: null, clientApp: null, mfa: null, country: null, city: null,
    lat: null, lon: null, userAgent: null, failureReason: null, isAdmin: null, adminBasis: null, asn: null, isp: null,
    isProxy: null, riskFlag: null, raw };
}

// Tabular row (CSV array or flattened JSON object) via header map.
export function normalizeTabular(get, map, source, raw) {
  const r = baseRecord(raw);
  const g = (f) => (map[f] === undefined ? undefined : get(map[f]));
  r.ts = parseTs(g("ts"));
  r.user = nonEmpty(g("user")) || nonEmpty(g("userId"));
  if (r.user) r.user = r.user.toLowerCase();
  r.ip = nonEmpty(g("ip"));
  const statusRaw = g("status");
  r.success = parseOutcome(statusRaw);
  if (source === "google") {
    const ev = str(statusRaw).toLowerCase();
    if (ev === "suspicious_login" || ev === "suspicious_login_less_secure_app") r.riskFlag = "suspicious_login";
  }
  r.app = nonEmpty(g("app"));
  r.clientApp = nonEmpty(g("clientApp"));
  r.mfa = parseMfa(g("mfaResult"), g("authRequirement"));
  r.country = nonEmpty(g("country"));
  r.city = nonEmpty(g("city"));
  r.lat = num(g("lat")); r.lon = num(g("lon"));
  if (r.lat !== null && r.lon !== null && (Math.abs(r.lat) > 90 || Math.abs(r.lon) > 180 || (r.lat === 0 && r.lon === 0))) { r.lat = null; r.lon = null; }
  r.userAgent = nonEmpty(g("userAgent")) || [nonEmpty(g("browser")), nonEmpty(g("os"))].filter(Boolean).join(" / ") || null;
  r.failureReason = r.success === false ? (nonEmpty(g("failureReason")) || null) : null;
  const ah = adminHint(r.user, r.app, g("role"));
  r.isAdmin = ah.isAdmin; r.adminBasis = ah.basis;
  r.asn = nonEmpty(g("asn")); r.isp = nonEmpty(g("isp"));
  r.isProxy = parseBool(g("isProxy"));
  const rf = g("riskFlag");
  if (rf !== undefined) {
    const rs = str(rf).toLowerCase();
    if (rs && rs !== "none" && rs !== "false" && rs !== "no" && rs !== "0" && rs !== "hidden" && rs !== "remediated" && rs !== "dismissed" && rs !== "confirmedsafe") r.riskFlag = r.riskFlag || str(rf);
  }
  return r;
}

// Okta System Log event object.
export function normalizeOkta(ev) {
  const r = baseRecord(ev);
  const type = str(ev.eventType);
  r.ts = parseTs(ev.published);
  r.user = nonEmpty(ev.actor && ev.actor.alternateId) || nonEmpty(ev.actor && ev.actor.displayName);
  if (r.user) r.user = r.user.toLowerCase();
  const c = ev.client || {};
  r.ip = nonEmpty(c.ipAddress);
  const res = str(ev.outcome && ev.outcome.result).toUpperCase();
  // NOTE: user.mfa.factor.deactivate is an MFA settings change, NOT an authentication — mapping it
  // to a successful sign-in made its (admin's) IP/geo flow into the travel/concurrency detections
  // and fabricate impossible-travel alerts. It is deliberately excluded here.
  const isAuth = /^user\.session\.start$|^user\.authentication\.|^user\.session\.access_admin_app$/.test(type) || type === "user.account.lock";
  if (isAuth) {
    if (res === "SUCCESS" || res === "ALLOW") r.success = true;
    else if (res === "FAILURE" || res === "DENY" || res === "LOCKED_OUT" || type === "user.account.lock") r.success = false;
    else r.success = null; // CHALLENGE, SKIPPED, UNKNOWN
  }
  r.failureReason = r.success === false ? nonEmpty(ev.outcome && ev.outcome.reason) : null;
  const targets = Array.isArray(ev.target) ? ev.target : [];
  const appT = targets.find((t) => t && (t.type === "AppInstance" || t.type === "App"));
  r.app = appT ? nonEmpty(appT.displayName) || nonEmpty(appT.alternateId) : (type === "user.session.access_admin_app" ? "Okta Admin Console" : null);
  r.clientApp = nonEmpty(c.device) ? `${c.device}` : null;
  if (type === "user.authentication.auth_via_richclient") r.clientApp = "Rich client (legacy)";
  const cred = str(ev.authenticationContext && ev.authenticationContext.credentialType).toUpperCase();
  if (type === "user.authentication.auth_via_mfa") r.mfa = true;
  else if (type === "user.authentication.auth_via_richclient") r.mfa = false;
  else if (cred && cred !== "PASSWORD" && cred !== "ASSERTION") r.mfa = true;
  else r.mfa = null; // resolved by correlateOktaMfa()
  const geo = c.geographicalContext || {};
  r.country = nonEmpty(geo.country); r.city = nonEmpty(geo.city);
  const gl = geo.geolocation || {};
  r.lat = num(gl.lat); r.lon = num(gl.lon);
  if (r.lat === 0 && r.lon === 0) { r.lat = null; r.lon = null; }
  r.userAgent = nonEmpty(c.userAgent && c.userAgent.rawUserAgent) || [nonEmpty(c.userAgent && c.userAgent.browser), nonEmpty(c.userAgent && c.userAgent.os)].filter(Boolean).join(" / ") || null;
  const sc = ev.securityContext || {};
  r.asn = sc.asNumber != null ? String(sc.asNumber) : null;
  r.isp = nonEmpty(sc.asOrg) || nonEmpty(sc.isp);
  r.isProxy = typeof sc.isProxy === "boolean" ? sc.isProxy : null;
  const adminApp = type === "user.session.access_admin_app" || (appT && /admin console/i.test(str(appT.displayName)));
  const ah = adminHint(r.user, adminApp ? "Okta Admin Console" : r.app, null);
  r.isAdmin = ah.isAdmin; r.adminBasis = ah.basis;
  const dbg = ev.debugContext && ev.debugContext.debugData;
  if (dbg && (dbg.threatSuspected === "true" || dbg.threatSuspected === true)) r.riskFlag = "threatSuspected";
  return r;
}

// Okta logs MFA as its own event after the password step. A session start with
// an auth_via_mfa success for the same user within the correlation window is MFA'd.
export function correlateOktaMfa(records, windowMs = 5 * 60 * 1000) {
  const mfaByUser = new Map();
  for (const r of records) {
    if (r.mfa === true && r.user && r.success === true) {
      if (!mfaByUser.has(r.user)) mfaByUser.set(r.user, []);
      mfaByUser.get(r.user).push(r.ts);
    }
  }
  for (const arr of mfaByUser.values()) arr.sort((a, b) => a - b);
  for (const r of records) {
    if (r.mfa !== null || r.success !== true || !r.user) continue;
    const arr = mfaByUser.get(r.user);
    if (!arr) { r.mfa = false; continue; }
    // binary search for first ts >= r.ts - 2min
    let lo = 0, hi = arr.length;
    const from = r.ts - 2 * 60 * 1000;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (arr[mid] < from) lo = mid + 1; else hi = mid; }
    r.mfa = lo < arr.length && arr[lo] <= r.ts + windowMs;
  }
  return records;
}

// Flatten nested JSON objects to "a.b.c" keys (arrays joined by index) for the
// header-synonym mapper.
export function flatten(o, prefix = "", out = {}) {
  if (o == null || typeof o !== "object") { out[prefix] = o; return out; }
  if (Array.isArray(o)) { o.forEach((v, i) => flatten(v, prefix ? `${prefix}.${i}` : String(i), out)); return out; }
  for (const k of Object.keys(o)) flatten(o[k], prefix ? `${prefix}.${k}` : k, out);
  return out;
}

// ---------------------------------------------------------------------------
// Parser session: detects format and source, exposes a chunked `next(n)` so a
// UI can process 100k rows without blocking. `parseAll` is the sync convenience.
// ---------------------------------------------------------------------------
export function createParser(text) {
  let s = String(text || "");
  if (s.charCodeAt(0) === 0xfeff) s = s.slice(1);
  const first = s.search(/\S/);
  const c0 = first >= 0 ? s[first] : "";
  const stats = { total: 0, kept: 0, badTs: 0, nonAuth: 0, noUser: 0 };
  const warnings = [];

  if (c0 === "[" || c0 === "{") {
    let arr = null;
    if (c0 === "[") {
      arr = JSON.parse(s);
    } else {
      // A wrapper object with its array under value/events/items/data, a single
      // event object, or NDJSON (one object per line). Try the whole document as
      // one object first — a pretty-printed export spans many lines — and fall
      // back to per-line NDJSON only when that fails (two+ objects, no wrapper).
      let o = null;
      try { o = JSON.parse(s); } catch (_) { o = null; }
      if (o && typeof o === "object") {
        arr = o.value || o.events || o.items || o.data || o.records || [o];
      } else {
        arr = s.split(/\r?\n/).filter((l) => l.trim()).map((l) => JSON.parse(l));
      }
    }
    if (!Array.isArray(arr)) throw new Error("JSON must be an array of events, NDJSON, or an object with a value/events/items array.");
    const sample = arr.find((x) => x && typeof x === "object") || {};
    let source = detectSourceFromObject(sample);
    let headers = [], map = {};
    if (source !== "okta") {
      headers = Object.keys(flatten(sample));
      map = mapHeaders(headers);
      if (source === "generic" && detectSourceFromHeaders(headers) === "unknown") source = "unknown";
    }
    // For flattened objects the header map holds indexes; translate to key lookups.
    const keyMap = {};
    for (const [f, idx] of Object.entries(map)) keyMap[f] = headers[idx];
    let pos = 0;
    return { format: "json", source, headers, map: source === "okta" ? {} : keyMap, total: arr.length, stats, warnings, columns: columnsFor(source, map, headers),
      done: () => pos >= arr.length,
      next(n = 2000) {
        const out = [];
        const end = Math.min(arr.length, pos + n);
        for (; pos < end; pos++) {
          const ev = arr[pos]; stats.total++;
          if (!ev || typeof ev !== "object") continue;
          let r;
          if (source === "okta") r = normalizeOkta(ev);
          else { const flat = flatten(ev); r = normalizeTabular((k) => flat[k], keyMap, source, ev); }
          if (keep(r, stats)) out.push(r);
        }
        return out;
      } };
  }

  // CSV
  const it = iterCsvRows(s);
  const h = it.next();
  if (h.done) throw new Error("The input is empty.");
  const headers = h.value.map((x) => String(x).trim());
  const source = detectSourceFromHeaders(headers);
  const map = mapHeaders(headers);
  // Google: the outcome carrier is Event Name, not a Status column.
  if (source === "google") {
    const en = headers.map(normHeader).indexOf("eventname");
    if (en >= 0) map.status = en;
    const lf = headers.map(normHeader).indexOf("loginfailuretype");
    if (lf >= 0) map.failureReason = lf;
    const sf = headers.map(normHeader).indexOf("issecondfactor");
    if (sf >= 0) map.mfaResult = sf;
  }
  let finished = false;
  const rowCount = Math.max(0, (s.match(/\n/g) || []).length - 1);
  return { format: "csv", source, headers, map, total: rowCount, stats, warnings, columns: columnsFor(source, map, headers),
    done: () => finished,
    next(n = 2000) {
      const out = [];
      for (let i = 0; i < n; i++) {
        const nx = it.next();
        if (nx.done) { finished = true; break; }
        const row = nx.value; stats.total++;
        const r = normalizeTabular((idx) => row[idx], map, source, row);
        if (keep(r, stats)) out.push(r);
      }
      return out;
    } };
}

function keep(r, stats) {
  if (!Number.isFinite(r.ts)) { stats.badTs++; return false; }
  if (!r.user) { stats.noUser++; return false; }
  if (r.success === null) { stats.nonAuth++; return false; }
  stats.kept++;
  return true;
}

// Which logical columns the export provides. Drives the honest coverage panel.
export function columnsFor(source, map, headers) {
  const has = (f) => map[f] !== undefined;
  if (source === "okta") {
    return { ts: true, user: true, ip: true, status: true, app: true, clientApp: true, mfa: true, country: true, city: true, latlon: true,
      role: false, asn: true, riskFlag: true, mfaNote: "MFA inferred by correlating user.authentication.auth_via_mfa events within 5 minutes of each session start." };
  }
  return {
    ts: has("ts"), user: has("user") || has("userId"), ip: has("ip"), status: has("status"), app: has("app"), clientApp: has("clientApp"),
    mfa: has("mfaResult") || has("authRequirement"), country: has("country"), city: has("city"), latlon: has("lat") && has("lon"),
    role: has("role"), asn: has("asn") || has("isp") || has("isProxy"), riskFlag: has("riskFlag"),
    mfaNote: source === "google" && has("mfaResult") ? "MFA read from the 'Is Second Factor' column." : null,
  };
}

export function parseAll(text) {
  const p = createParser(text);
  const records = [];
  while (!p.done()) { const chunk = p.next(5000); if (!chunk.length && p.done()) break; records.push(...chunk); }
  if (p.source === "okta") correlateOktaMfa(records);
  return { source: p.source, format: p.format, headers: p.headers, columns: p.columns, stats: p.stats, warnings: p.warnings, records };
}

// ---------------------------------------------------------------------------
// Geography
// ---------------------------------------------------------------------------
export function haversineKm(lat1, lon1, lat2, lon2) {
  const R = 6371.0088;
  const toRad = (d) => (d * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1), dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.min(1, Math.sqrt(a)));
}

// Compact gazetteer: major cities (used when an export has city+country but no
// coordinates) and country centroids (coarse fallback). City-level positions are
// approximate to tens of km; centroids to hundreds. Confidence is downgraded
// accordingly and the UI says which was used.
const CITIES = {
  "new york": [40.71, -74.01], "los angeles": [34.05, -118.24], "chicago": [41.88, -87.63], "houston": [29.76, -95.37], "dallas": [32.78, -96.8],
  "seattle": [47.61, -122.33], "san francisco": [37.77, -122.42], "san jose": [37.34, -121.89], "boston": [42.36, -71.06], "washington": [38.9, -77.04],
  "atlanta": [33.75, -84.39], "miami": [25.76, -80.19], "denver": [39.74, -104.99], "phoenix": [33.45, -112.07], "ashburn": [39.04, -77.49],
  "toronto": [43.65, -79.38], "vancouver": [49.28, -123.12], "montreal": [45.5, -73.57], "mexico city": [19.43, -99.13], "sao paulo": [-23.55, -46.63],
  "são paulo": [-23.55, -46.63], "rio de janeiro": [-22.91, -43.17], "buenos aires": [-34.6, -58.38], "bogota": [4.71, -74.07], "lima": [-12.05, -77.04], "santiago": [-33.45, -70.67],
  "london": [51.51, -0.13], "manchester": [53.48, -2.24], "dublin": [53.35, -6.26], "paris": [48.86, 2.35], "berlin": [52.52, 13.41], "frankfurt": [50.11, 8.68],
  "munich": [48.14, 11.58], "amsterdam": [52.37, 4.9], "brussels": [50.85, 4.35], "madrid": [40.42, -3.7], "barcelona": [41.39, 2.17], "lisbon": [38.72, -9.14],
  "rome": [41.9, 12.5], "milan": [45.46, 9.19], "zurich": [47.38, 8.54], "vienna": [48.21, 16.37], "prague": [50.08, 14.44], "warsaw": [52.23, 21.01],
  "stockholm": [59.33, 18.07], "oslo": [59.91, 10.75], "copenhagen": [55.68, 12.57], "helsinki": [60.17, 24.94], "athens": [37.98, 23.73], "istanbul": [41.01, 28.98],
  "moscow": [55.76, 37.62], "saint petersburg": [59.93, 30.34], "kyiv": [50.45, 30.52], "kiev": [50.45, 30.52], "bucharest": [44.43, 26.1], "budapest": [47.5, 19.04],
  "dubai": [25.2, 55.27], "abu dhabi": [24.45, 54.38], "riyadh": [24.71, 46.68], "tel aviv": [32.09, 34.78], "cairo": [30.04, 31.24], "lagos": [6.52, 3.38],
  "nairobi": [-1.29, 36.82], "johannesburg": [-26.2, 28.05], "cape town": [-33.92, 18.42], "mumbai": [19.08, 72.88], "delhi": [28.61, 77.21], "new delhi": [28.61, 77.21],
  "bangalore": [12.97, 77.59], "bengaluru": [12.97, 77.59], "hyderabad": [17.39, 78.49], "chennai": [13.08, 80.27], "karachi": [24.86, 67.01], "lahore": [31.55, 74.34],
  "dhaka": [23.81, 90.41], "singapore": [1.35, 103.82], "kuala lumpur": [3.14, 101.69], "jakarta": [-6.21, 106.85], "bangkok": [13.76, 100.5], "manila": [14.6, 120.98],
  "ho chi minh city": [10.82, 106.63], "hanoi": [21.03, 105.85], "hong kong": [22.32, 114.17], "shanghai": [31.23, 121.47], "beijing": [39.9, 116.4], "shenzhen": [22.54, 114.06],
  "taipei": [25.03, 121.57], "seoul": [37.57, 126.98], "tokyo": [35.68, 139.69], "osaka": [34.69, 135.5], "sydney": [-33.87, 151.21], "melbourne": [-37.81, 144.96],
  "brisbane": [-27.47, 153.03], "perth": [-31.95, 115.86], "auckland": [-36.85, 174.76], "accra": [5.6, -0.19], "tehran": [35.69, 51.39],
  "baghdad": [33.31, 44.37], "pyongyang": [39.02, 125.75], "minsk": [53.9, 27.57], "reykjavik": [64.15, -21.94],
};
const COUNTRIES = {
  us: [39.8, -98.6], "united states": [39.8, -98.6], usa: [39.8, -98.6], ca: [56.1, -106.3], canada: [56.1, -106.3], mx: [23.6, -102.5], mexico: [23.6, -102.5],
  br: [-14.2, -51.9], brazil: [-14.2, -51.9], ar: [-38.4, -63.6], argentina: [-38.4, -63.6], co: [4.6, -74.3], colombia: [4.6, -74.3], cl: [-35.7, -71.5], chile: [-35.7, -71.5], pe: [-9.2, -75], peru: [-9.2, -75],
  gb: [54, -2.5], uk: [54, -2.5], "united kingdom": [54, -2.5], ie: [53.4, -8.2], ireland: [53.4, -8.2], fr: [46.2, 2.2], france: [46.2, 2.2], de: [51.2, 10.4], germany: [51.2, 10.4],
  nl: [52.1, 5.3], netherlands: [52.1, 5.3], be: [50.5, 4.5], belgium: [50.5, 4.5], es: [40.5, -3.7], spain: [40.5, -3.7], pt: [39.4, -8.2], portugal: [39.4, -8.2], it: [41.9, 12.6], italy: [41.9, 12.6],
  ch: [46.8, 8.2], switzerland: [46.8, 8.2], at: [47.5, 14.6], austria: [47.5, 14.6], cz: [49.8, 15.5], "czech republic": [49.8, 15.5], czechia: [49.8, 15.5], pl: [51.9, 19.1], poland: [51.9, 19.1],
  se: [60.1, 18.6], sweden: [60.1, 18.6], no: [60.5, 8.5], norway: [60.5, 8.5], dk: [56.3, 9.5], denmark: [56.3, 9.5], fi: [61.9, 25.7], finland: [61.9, 25.7], gr: [39.1, 21.8], greece: [39.1, 21.8],
  tr: [39, 35.2], turkey: [39, 35.2], türkiye: [39, 35.2], ru: [61.5, 105.3], russia: [61.5, 105.3], "russian federation": [61.5, 105.3], ua: [48.4, 31.2], ukraine: [48.4, 31.2], ro: [45.9, 25], romania: [45.9, 25],
  hu: [47.2, 19.5], hungary: [47.2, 19.5], by: [53.7, 27.9], belarus: [53.7, 27.9], ae: [23.4, 53.8], "united arab emirates": [23.4, 53.8], sa: [23.9, 45.1], "saudi arabia": [23.9, 45.1],
  il: [31, 34.9], israel: [31, 34.9], eg: [26.8, 30.8], egypt: [26.8, 30.8], ng: [9.1, 8.7], nigeria: [9.1, 8.7], ke: [-0.02, 37.9], kenya: [-0.02, 37.9], za: [-30.6, 22.9], "south africa": [-30.6, 22.9],
  gh: [7.9, -1], ghana: [7.9, -1], in: [20.6, 79], india: [20.6, 79], pk: [30.4, 69.3], pakistan: [30.4, 69.3], bd: [23.7, 90.4], bangladesh: [23.7, 90.4], sg: [1.35, 103.8], singapore: [1.35, 103.8],
  my: [4.2, 101.9], malaysia: [4.2, 101.9], id: [-0.8, 113.9], indonesia: [-0.8, 113.9], th: [15.9, 100.9], thailand: [15.9, 100.9], ph: [12.9, 121.8], philippines: [12.9, 121.8], vn: [14.1, 108.3], vietnam: [14.1, 108.3],
  hk: [22.3, 114.2], "hong kong": [22.3, 114.2], cn: [35.9, 104.2], china: [35.9, 104.2], tw: [23.7, 121], taiwan: [23.7, 121], kr: [35.9, 127.8], "south korea": [35.9, 127.8], "korea, republic of": [35.9, 127.8],
  jp: [36.2, 138.3], japan: [36.2, 138.3], au: [-25.3, 133.8], australia: [-25.3, 133.8], nz: [-40.9, 174.9], "new zealand": [-40.9, 174.9], ir: [32.4, 53.7], iran: [32.4, 53.7],
  iq: [33.2, 43.7], iraq: [33.2, 43.7], kp: [40.3, 127.5], "north korea": [40.3, 127.5], is: [64.96, -19.02], iceland: [64.96, -19.02],
};

const countryPos = (c) => (c ? COUNTRIES[String(c).trim().toLowerCase()] || null : null);

// Resolve a record's position. Returns { lat, lon, basis } or null.
// basis: "coordinates" (from the export), "city" (gazetteer), "country" (centroid).
export function resolvePlace(r) {
  if (r.lat !== null && r.lon !== null && r.lat !== undefined && r.lon !== undefined) return { lat: r.lat, lon: r.lon, basis: "coordinates" };
  const city = r.city ? String(r.city).trim().toLowerCase() : "";
  if (city && CITIES[city]) return { lat: CITIES[city][0], lon: CITIES[city][1], basis: "city" };
  const country = r.country ? String(r.country).trim().toLowerCase() : "";
  if (country && COUNTRIES[country]) return { lat: COUNTRIES[country][0], lon: COUNTRIES[country][1], basis: "country" };
  return null;
}

// ---------------------------------------------------------------------------
// Detections
// ---------------------------------------------------------------------------
export const DEFAULTS = Object.freeze({
  sprayUsers: 10, sprayWindowMin: 60,
  bruteFailures: 20, bruteWindowMin: 30,
  stuffFailures: 5, stuffWindowMin: 60,
  travelSpeedKmh: 900, travelMinKm: 500,
  newCountryMinDays: 7,
  bizStartHour: 7, bizEndHour: 20, utcOffsetMin: 0, weekendIsAfterHours: true,
  concurrentWindowMin: 30, concurrentMinKm: 500,
  evidenceCap: 50,
});

export const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const SEV_WEIGHT = { critical: 40, high: 25, medium: 10, low: 3 };

export const DETECTIONS = [
  { id: "password_spray", name: "Password spraying", technique: "T1110.003", techniqueName: "Brute Force: Password Spraying", needs: ["ts", "user", "ip", "status"] },
  { id: "brute_force", name: "Brute force on one account", technique: "T1110.001", techniqueName: "Brute Force: Password Guessing", needs: ["ts", "user", "status"] },
  { id: "cred_stuffing_success", name: "Failures followed by success from the same source", technique: "T1110.004 / T1078.004", techniqueName: "Credential Stuffing leading to Valid Accounts: Cloud Accounts", needs: ["ts", "user", "ip", "status"] },
  { id: "impossible_travel", name: "Impossible travel", technique: "T1078.004", techniqueName: "Valid Accounts: Cloud Accounts", needs: ["ts", "user", "status", "location"] },
  { id: "new_country", name: "First sign-in from a new country", technique: "T1078", techniqueName: "Valid Accounts", needs: ["ts", "user", "status", "country", "span7d"] },
  { id: "legacy_auth", name: "Legacy authentication success", technique: "T1078", techniqueName: "Valid Accounts (basic auth bypasses MFA)", needs: ["user", "status", "clientApp"] },
  { id: "admin_no_mfa", name: "Admin sign-in without MFA", technique: "T1556.006", techniqueName: "Modify Authentication Process: Multi-Factor Authentication (CIS Control 6.5)", needs: ["user", "status", "mfa", "admin"] },
  { id: "after_hours_admin", name: "Admin sign-in outside business hours", technique: "T1078", techniqueName: "Valid Accounts", needs: ["ts", "user", "status", "admin"] },
  { id: "concurrent_distant", name: "Concurrent sessions from distant locations", technique: "T1078.004", techniqueName: "Valid Accounts: Cloud Accounts", needs: ["ts", "user", "ip", "status", "country"] },
  { id: "anonymizer_asn", name: "Sign-in from hosting, VPN or proxy network", technique: "T1090 / T1078", techniqueName: "Proxy; Valid Accounts", needs: ["user", "status", "asn"] },
  { id: "provider_risk_flag", name: "Provider-flagged risky sign-in", technique: "T1078", techniqueName: "Valid Accounts", needs: ["user", "riskFlag"] },
];

const ACTIONS = {
  password_spray: "Block the source IP or range at the identity provider or firewall, enable smart lockout and MFA for every targeted account, and check whether any of the sprayed users later signed in successfully from the same source.",
  brute_force: "Confirm the account is locked out or protected by MFA, reset the password if any attempt succeeded, and block the attacking source. Review whether the account is a shared or service identity that cannot use MFA.",
  cred_stuffing_success: "Treat as a likely compromise: revoke all sessions and refresh tokens for the user, reset the password, review mailbox rules, OAuth consents and MFA device changes made after the success, and block the source.",
  impossible_travel: "Contact the user through a channel other than email. If one location is not theirs, revoke sessions, reset credentials and re-register MFA. If they use a VPN, record it to tune future reviews.",
  new_country: "Verify with the user whether they travelled or used a VPN. If not, revoke sessions and reset credentials. Consider Conditional Access country restrictions for this account group.",
  legacy_auth: "Disable basic authentication for the protocol at the tenant level (Entra: block legacy authentication via Conditional Access; Google: turn off less secure app access), then migrate the client to modern authentication.",
  admin_no_mfa: "Require phishing-resistant MFA for every administrative role with no exceptions, and review what the account did during these sessions.",
  after_hours_admin: "Confirm the activity matches a change record or on-call shift. Unexplained administrative sign-ins outside working hours deserve a session review.",
  concurrent_distant: "Check whether one of the sessions belongs to a VPN or a shared device. If not, revoke all sessions and reset credentials; concurrent sessions from two countries typically indicate a stolen token or shared password.",
  anonymizer_asn: "Decide whether this network is sanctioned for this user (corporate VPN egress, cloud bastion). If not, revoke sessions and tighten Conditional Access to trusted networks or compliant devices.",
  provider_risk_flag: "The identity provider marked this sign-in as risky with signals you cannot see in the export. Review the provider's risk detail and remediate per its guidance.",
};

function opts(o) { return Object.assign({}, DEFAULTS, o || {}); }
function fmtWindow(min) { return min >= 60 && min % 60 === 0 ? `${min / 60} h` : `${min} min`; }
function ev(r, note) {
  return { ts: r.ts, user: r.user, ip: r.ip, success: r.success, app: r.app, clientApp: r.clientApp, country: r.country, city: r.city, mfa: r.mfa, failureReason: r.failureReason, isAdmin: r.isAdmin, idx: r._i, note: note || "" };
}
function cap(arr, n) { return arr.length > n ? arr.slice(0, n) : arr; }
function finding(f) {
  const meta = DETECTIONS.find((d) => d.id === f.id);
  return Object.assign({ technique: meta.technique, techniqueName: meta.techniqueName, name: meta.name, action: ACTIONS[f.id], user: null, ip: null, confidence: "high" }, f);
}

// Densest sliding window helper: items sorted by ts; `key(item)` distinct key or
// null for plain count. Returns { count, start, end, i, j } for the best window.
function bestWindow(items, windowMs, key) {
  let best = { count: 0, start: 0, end: 0, i: 0, j: 0 };
  const counts = new Map(); let distinct = 0, j = 0;
  for (let i = 0; i < items.length; i++) {
    while (j < items.length && items[j].ts - items[i].ts <= windowMs) {
      const k = key ? key(items[j]) : j;
      const c = counts.get(k) || 0; if (c === 0) distinct++; counts.set(k, c + 1); j++;
    }
    if (distinct > best.count) best = { count: distinct, start: items[i].ts, end: items[j - 1].ts, i, j };
    const k = key ? key(items[i]) : i;
    const c = counts.get(k) || 0; if (c <= 1) { counts.delete(k); distinct--; } else counts.set(k, c - 1);
  }
  return best;
}

export function analyze(records, options, meta) {
  const o = opts(options);
  const columns = (meta && meta.columns) || inferColumns(records);
  const source = (meta && meta.source) || "unknown";
  const recs = records.filter((r) => Number.isFinite(r.ts) && r.user && r.success !== null).slice().sort((a, b) => a.ts - b.ts);
  recs.forEach((r, i) => { r._i = i; });

  // KPIs
  const users = new Map(); const ips = new Set(); const countries = new Set();
  let successes = 0, failures = 0;
  for (const r of recs) {
    if (r.success) successes++; else failures++;
    if (r.ip) ips.add(r.ip);
    if (r.country) countries.add(r.country);
    let u = users.get(r.user);
    if (!u) { u = { user: r.user, successes: 0, failures: 0, ips: new Set(), countries: new Set(), first: r.ts, last: r.ts, isAdmin: false, adminBasis: null, findings: [], score: 0 }; users.set(r.user, u); }
    if (r.success) u.successes++; else u.failures++;
    if (r.ip) u.ips.add(r.ip); if (r.country) u.countries.add(r.country);
    if (r.ts < u.first) u.first = r.ts; if (r.ts > u.last) u.last = r.ts;
    if (r.isAdmin === true) { u.isAdmin = true; u.adminBasis = u.adminBasis || r.adminBasis; }
  }
  const spanStart = recs.length ? recs[0].ts : null, spanEnd = recs.length ? recs[recs.length - 1].ts : null;
  const spanDays = recs.length ? (spanEnd - spanStart) / 86400000 : 0;
  const hasLocation = recs.some((r) => resolvePlace(r));
  const hasAdmin = recs.some((r) => r.isAdmin === true);
  const hasAsn = recs.some((r) => r.asn || r.isp || r.isProxy !== null);
  const hasRisk = recs.some((r) => r.riskFlag);

  // Coverage: decide which detections can run
  const coverage = [];
  const canRun = {};
  const reasons = {
    ts: "no timestamp column was found", user: "no user column was found", ip: "no IP address column was found", status: "no outcome/status column was found",
    clientApp: "no client application / protocol column in this export (Entra: 'Client app'; Google: 'Login Type')",
    mfa: "no MFA column in this export (Entra: 'Authentication requirement' or 'Multifactor authentication result'; Google: 'Is Second Factor'; Okta: auth_via_mfa events)",
    country: "no country column in this export (the Google Login audit CSV does not include location)",
    location: "no coordinates, city or country column that resolves to a position",
    span7d: `the dataset spans ${spanDays.toFixed(1)} days; a baseline needs at least ${o.newCountryMinDays} days`,
    admin: "no account in the export is identified as an administrator (no role column, and no username or admin-application hint matched)",
    asn: "no ASN / ISP / proxy column in this export; the tool makes no network lookups, so this detection is skipped rather than guessed",
    riskFlag: "no provider risk column in this export (Entra: 'Risk state'; Google: 'Is Suspicious'; Okta: securityContext)",
  };
  for (const d of DETECTIONS) {
    const missing = d.needs.filter((n) => {
      if (n === "span7d") return spanDays < o.newCountryMinDays;
      if (n === "location") return !hasLocation;
      if (n === "admin") return !hasAdmin;
      if (n === "asn") return !(columns.asn && hasAsn);
      if (n === "riskFlag") return !(columns.riskFlag || hasRisk) || !hasRisk;
      if (n === "country") return !columns.country && !recs.some((r) => r.country);
      if (n === "mfa") return !columns.mfa && !recs.some((r) => r.mfa !== null);
      if (n === "clientApp") return !columns.clientApp && !recs.some((r) => r.clientApp);
      if (n === "ip") return !columns.ip && !recs.some((r) => r.ip);
      return columns[n] === false && !recs.some((r) => n === "ts" ? Number.isFinite(r.ts) : r[n] != null);
    });
    canRun[d.id] = missing.length === 0;
    coverage.push({ id: d.id, name: d.name, technique: d.technique, ran: missing.length === 0, reason: missing.length ? `Skipped: ${missing.map((m) => reasons[m]).join("; ")}.` : "", findings: 0 });
  }
  const findings = [];
  const push = (f) => { findings.push(finding(f)); };

  // Group helpers
  const byUser = new Map();
  for (const r of recs) { let a = byUser.get(r.user); if (!a) { a = []; byUser.set(r.user, a); } a.push(r); }

  // 1. Password spraying (per IP, then per /24 where no single IP already qualifies)
  const sprayNets = new Set();
  if (canRun.password_spray) {
    const failsByIp = new Map(), failsByNet = new Map();
    for (const r of recs) {
      if (r.success || !r.ip) continue;
      let a = failsByIp.get(r.ip); if (!a) { a = []; failsByIp.set(r.ip, a); } a.push(r);
      const n = subnet24(r.ip); let b = failsByNet.get(n); if (!b) { b = []; failsByNet.set(n, b); } b.push(r);
    }
    const W = o.sprayWindowMin * 60000;
    const flaggedNets = new Set();
    const emit = (src, items, isNet) => {
      const bw = bestWindow(items, W, (x) => x.user);
      if (bw.count < o.sprayUsers) return false;
      const win = items.slice(bw.i, bw.j);
      const distinctUsers = new Set(win.map((x) => x.user));
      const reasonsSeen = new Set(win.map((x) => (x.failureReason || "").toLowerCase()).filter(Boolean));
      const credReason = [...reasonsSeen].some((x) => /password|credential|50126|invalid/.test(x));
      const net = isNet ? src : subnet24(src);
      sprayNets.add(net); flaggedNets.add(net);
      push({ id: "password_spray", key: `spray:${src}`, severity: "high", confidence: credReason || !reasonsSeen.size ? "high" : "medium", ip: src,
        title: `${isNet ? "Range" : "IP"} ${src} failed against ${distinctUsers.size} accounts in ${fmtWindow(o.sprayWindowMin)}`,
        description: `${bw.count} distinct users had failed sign-ins from ${isNet ? "the range" : "the address"} ${src} between ${iso(bw.start)} and ${iso(bw.end)} (${win.length} failures in that window, ${items.length} total from this source). One source failing across many accounts is the signature of password spraying: a few common passwords tried against a user list.${reasonsSeen.size ? ` Failure reasons seen: ${[...reasonsSeen].slice(0, 3).join("; ")}.` : ""}`,
        counts: { distinctUsers: bw.count, failuresInWindow: win.length, failuresTotal: items.length, windowStart: bw.start, windowEnd: bw.end },
        evidence: cap(win, o.evidenceCap).map((x) => ev(x)), evidenceTotal: win.length });
      return true;
    };
    for (const [ip, items] of failsByIp) emit(ip, items, false);
    for (const [net, items] of failsByNet) { if (flaggedNets.has(net)) continue; if (new Set(items.map((x) => x.ip)).size < 2) continue; emit(net, items, true); }
  }

  // 2. Brute force on one account
  if (canRun.brute_force) {
    const W = o.bruteWindowMin * 60000;
    for (const [user, arr] of byUser) {
      const fails = arr.filter((r) => !r.success);
      if (fails.length < o.bruteFailures) continue;
      const bw = bestWindow(fails, W, null);
      if (bw.count < o.bruteFailures) continue;
      const win = fails.slice(bw.i, bw.j);
      const srcIps = new Set(win.map((x) => x.ip).filter(Boolean));
      const laterSuccess = arr.find((r) => r.success && r.ts >= bw.start && r.ts <= bw.end + W);
      push({ id: "brute_force", key: `brute:${user}`, severity: laterSuccess ? "high" : "medium", confidence: "high", user, ip: srcIps.size === 1 ? [...srcIps][0] : null,
        title: `${bw.count} failed sign-ins for ${user} in ${fmtWindow(o.bruteWindowMin)}`,
        description: `${bw.count} failures between ${iso(bw.start)} and ${iso(bw.end)} from ${srcIps.size || "an unknown number of"} source address${srcIps.size === 1 ? "" : "es"} (${fails.length} failures for this account in the whole export).${laterSuccess ? ` A SUCCESSFUL sign-in followed at ${iso(laterSuccess.ts)} from ${laterSuccess.ip || "an unrecorded IP"}; see the related finding.` : " No success followed inside the window."} A user mistyping a password rarely exceeds a handful of attempts; sustained failures are automated guessing or a misconfigured client with a stale password.`,
        counts: { failuresInWindow: bw.count, failuresTotal: fails.length, sourceIps: srcIps.size, windowStart: bw.start, windowEnd: bw.end },
        evidence: cap(win, o.evidenceCap).map((x) => ev(x)).concat(laterSuccess ? [ev(laterSuccess, "success after failures")] : []), evidenceTotal: win.length + (laterSuccess ? 1 : 0) });
    }
  }

  // 3. Failures then success from the same IP or /24
  if (canRun.cred_stuffing_success) {
    const W = o.stuffWindowMin * 60000;
    for (const [user, arr] of byUser) {
      const seenNets = new Set();
      for (let s = 0; s < arr.length; s++) {
        const r = arr[s];
        if (!r.success || !r.ip) continue;
        const net = subnet24(r.ip);
        if (seenNets.has(net)) continue;
        const prior = [];
        for (let k = s - 1; k >= 0 && r.ts - arr[k].ts <= W; k--) {
          const p = arr[k];
          if (!p.success && p.ip && subnet24(p.ip) === net) prior.push(p);
        }
        if (prior.length < o.stuffFailures) continue;
        seenNets.add(net);
        prior.reverse();
        const sameIp = prior.every((p) => p.ip === r.ip);
        const spray = sprayNets.has(net);
        push({ id: "cred_stuffing_success", key: `stuff:${user}:${net}`, severity: "critical", confidence: prior.length >= o.stuffFailures * 2 || spray ? "high" : "medium", user, ip: r.ip,
          title: `${user}: ${prior.length} failures then a success from ${sameIp ? r.ip : net}${spray ? " (a spraying source)" : ""}`,
          description: `${prior.length} failed sign-ins from ${sameIp ? "the same address" : "the same /24 range"} in the ${fmtWindow(o.stuffWindowMin)} before a successful sign-in at ${iso(r.ts)} (${r.app || "application not recorded"}${r.mfa === true ? ", MFA satisfied" : r.mfa === false ? ", NO MFA" : ""}).${spray ? " The source was also spraying other accounts, which makes a legitimate explanation unlikely." : " A user who forgot a password produces this shape too; the failure count and reasons decide."} Reasons: ${[...new Set(prior.map((p) => p.failureReason).filter(Boolean))].slice(0, 3).join("; ") || "not recorded"}.`,
          counts: { priorFailures: prior.length, successAt: r.ts, mfa: r.mfa, sprayingSource: spray },
          evidence: cap(prior, o.evidenceCap - 1).map((x) => ev(x)).concat([ev(r, "SUCCESS after failures")]), evidenceTotal: prior.length + 1 });
      }
    }
  }

  // 4. Impossible travel (consecutive successes per user)
  const travelPairs = new Set(), travelIpPairs = new Set();
  if (canRun.impossible_travel) {
    let unresolved = 0;
    const travelFindings = new Map();
    for (const [user, arr] of byUser) {
      let prev = null, prevPos = null;
      for (const r of arr) {
        if (!r.success) continue;
        const pos = resolvePlace(r);
        if (!pos) { unresolved++; continue; }
        // a country-level fix is only a centroid: measured against a city or coordinates it put
        // New York -> "US" (Kansas, ~1,800 km) or Moscow -> "RU" (~3,700 km) a few minutes apart as
        // impossible travel. When either side is country-level, compare country to country only.
        let a1 = prevPos, a2 = pos;
        if (prev && r.ip !== prev.ip && (pos.basis === "country" || prevPos.basis === "country")) {
          const c1 = countryPos(prev.country), c2 = countryPos(r.country);
          a1 = c1 && c2 && (c1[0] !== c2[0] || c1[1] !== c2[1]) ? { lat: c1[0], lon: c1[1] } : null; a2 = a1 && { lat: c2[0], lon: c2[1] };
        }
        if (prev && r.ip !== prev.ip && a1) {
          const km = haversineKm(a1.lat, a1.lon, a2.lat, a2.lon);
          const hours = Math.max(1 / 60, (r.ts - prev.ts) / 3600000);
          const kmh = km / hours;
          if (km >= o.travelMinKm && kmh > o.travelSpeedKmh) {
            const basis = pos.basis === "coordinates" && prevPos.basis === "coordinates" ? "coordinates" : pos.basis === "country" || prevPos.basis === "country" ? "country" : "city";
            travelPairs.add(`${prev._i}|${r._i}`);
            travelIpPairs.add(`${user}|${prev.ip}|${r.ip}`); travelIpPairs.add(`${user}|${r.ip}|${prev.ip}`);
            const pairKey = `travel:${user}:${[place(prev), place(r)].sort().join("<>")}`;
            const existing = travelFindings.get(pairKey);
            if (existing) {
              // The same two places alternating (user still working at home while a stolen session is used elsewhere):
              // one finding, every hop as evidence.
              existing.counts.hops++;
              existing.evidenceTotal += 1;
              if (existing.evidence.length < o.evidenceCap) existing.evidence.push(ev(r, `hop ${existing.counts.hops}: ${place(r)}`));
              existing.title = `${user}: ${existing.counts.hops} impossible hops between ${place(prev)} and ${place(r)} (fastest ${Math.max(existing.counts.kmh, Math.round(kmh)).toLocaleString()} km/h)`;
              existing.counts.kmh = Math.max(existing.counts.kmh, Math.round(kmh));
              existing.counts.minutes = Math.min(existing.counts.minutes, Math.round((r.ts - prev.ts) / 60000));
            } else {
              const f = finding({ id: "impossible_travel", key: pairKey, severity: "high", confidence: basis === "coordinates" ? "high" : "medium", user, ip: r.ip,
                title: `${user}: ${place(prev)} to ${place(r)} in ${durationText(r.ts - prev.ts)} (${Math.round(km).toLocaleString()} km)`,
                description: `Two successful sign-ins ${durationText(r.ts - prev.ts)} apart from locations about ${Math.round(km).toLocaleString()} km apart, which implies ${Math.round(kmh).toLocaleString()} km/h (threshold ${o.travelSpeedKmh} km/h). ${basis === "coordinates" ? "Distance computed from the coordinates in the export." : basis === "city" ? "Distance estimated from city centres (no coordinates in the export); accurate to tens of kilometres." : "Distance estimated from country centroids because no city or coordinates were available; treat as coarse."} Corporate VPN egress and mobile carrier geolocation are the common benign causes. Repeated hops between the same two places while the user keeps working from one of them is the shape of a stolen session being used elsewhere.`,
                counts: { km: Math.round(km), minutes: Math.round((r.ts - prev.ts) / 60000), kmh: Math.round(kmh), basis, hops: 1 },
                evidence: [ev(prev, "earlier sign-in"), ev(r, "later sign-in")], evidenceTotal: 2 });
              travelFindings.set(pairKey, f); findings.push(f);
            }
          }
        }
        prev = r; prevPos = pos;
      }
    }
    const cov = coverage.find((c) => c.id === "impossible_travel");
    if (unresolved) cov.note = `${unresolved.toLocaleString()} successful sign-ins had no resolvable location and were not compared.`;
  }

  // 5. New country for a user (needs a baseline of >= N days of history for that user)
  if (canRun.new_country) {
    const minMs = o.newCountryMinDays * 86400000;
    for (const [user, arr] of byUser) {
      const seen = new Set(); const firstTs = arr[0].ts; const flagged = new Set();
      for (const r of arr) {
        if (!r.success || !r.country) continue;
        const c = r.country.toLowerCase();
        if (!seen.has(c)) {
          // require at least one PRIOR country as the baseline — a user's first-ever geolocated
          // sign-in is not a deviation from anything and must not be flagged as a "new" country.
          if (seen.size > 0 && r.ts - firstTs >= minMs && !flagged.has(c)) {
            flagged.add(c);
            const later = arr.filter((x) => x.success && x.country && x.country.toLowerCase() === c);
            push({ id: "new_country", key: `newc:${user}:${c}`, severity: "medium", confidence: "medium", user, ip: r.ip,
              title: `${user}: first sign-in from ${r.country} after ${Math.floor((r.ts - firstTs) / 86400000)} days of history`,
              description: `The account had ${Math.floor((r.ts - firstTs) / 86400000)} days of sign-ins from ${[...seen].map(cap1).join(", ") || "other countries"} before the first success from ${r.country} at ${iso(r.ts)} (${later.length} sign-in${later.length === 1 ? "" : "s"} from this country in total). A new country is only a signal; travel and VPNs explain most cases, which is why this is rated medium.`,
              counts: { baselineDays: Math.floor((r.ts - firstTs) / 86400000), priorCountries: [...seen], newCountry: r.country, signinsFromNew: later.length },
              evidence: cap(later, o.evidenceCap).map((x) => ev(x)), evidenceTotal: later.length });
          }
          seen.add(c);
        }
      }
    }
  }

  // 6. Legacy authentication successes (per user + protocol)
  if (canRun.legacy_auth) {
    const groups = new Map();
    for (const r of recs) {
      if (!r.success || !isLegacyClient(r.clientApp)) continue;
      const k = `${r.user}|${r.clientApp.toLowerCase()}`;
      let g = groups.get(k); if (!g) { g = []; groups.set(k, g); } g.push(r);
    }
    for (const [k, arr] of groups) {
      const r = arr[0];
      const admin = arr.some((x) => x.isAdmin === true);
      push({ id: "legacy_auth", key: `legacy:${k}`, severity: admin ? "high" : "medium", confidence: "high", user: r.user, ip: arr.length === 1 ? r.ip : null,
        title: `${r.user}: ${arr.length} success${arr.length === 1 ? "" : "es"} over ${r.clientApp}${admin ? " (administrator)" : ""}`,
        description: `${arr.length} successful sign-in${arr.length === 1 ? "" : "s"} used ${r.clientApp}, a basic-authentication protocol that sends the password with every request and cannot carry a second factor. Any MFA policy is bypassed on this path, and the credential is replayable if intercepted or leaked.${admin ? " The account is identified as an administrator." : ""} Source addresses: ${[...new Set(arr.map((x) => x.ip).filter(Boolean))].slice(0, 5).join(", ") || "not recorded"}.`,
        counts: { successes: arr.length, protocol: r.clientApp, admin },
        evidence: cap(arr, o.evidenceCap).map((x) => ev(x)), evidenceTotal: arr.length });
    }
  }

  // 7. Admin without MFA
  if (canRun.admin_no_mfa) {
    const groups = new Map();
    for (const r of recs) {
      if (!r.success || r.isAdmin !== true || r.mfa !== false) continue;
      let g = groups.get(r.user); if (!g) { g = []; groups.set(r.user, g); } g.push(r);
    }
    for (const [user, arr] of groups) {
      const basis = arr[0].adminBasis;
      push({ id: "admin_no_mfa", key: `adminmfa:${user}`, severity: basis === "role" ? "critical" : "high", confidence: basis === "role" ? "high" : "medium", user, ip: null,
        title: `${user}: ${arr.length} administrative sign-in${arr.length === 1 ? "" : "s"} without MFA`,
        description: `${arr.length} successful sign-in${arr.length === 1 ? "" : "s"} recorded single-factor authentication for an account identified as an administrator by ${basis === "role" ? "the role column in the export" : basis === "admin application" ? "the application signed into (an administrative console)" : "its username pattern"}.${basis !== "role" ? " Confirm the account really holds a privileged role; the export has no role column." : ""} Applications: ${[...new Set(arr.map((x) => x.app).filter(Boolean))].slice(0, 5).join(", ") || "not recorded"}. Source addresses: ${[...new Set(arr.map((x) => x.ip).filter(Boolean))].slice(0, 5).join(", ") || "not recorded"}.`,
        counts: { signins: arr.length, basis },
        evidence: cap(arr, o.evidenceCap).map((x) => ev(x)), evidenceTotal: arr.length });
    }
  }

  // 8. After-hours admin activity (local time via UTC offset)
  if (canRun.after_hours_admin) {
    const groups = new Map();
    for (const r of recs) {
      if (!r.success || r.isAdmin !== true) continue;
      if (!isAfterHours(r.ts, o)) continue;
      let g = groups.get(r.user); if (!g) { g = []; groups.set(r.user, g); } g.push(r);
    }
    for (const [user, arr] of groups) {
      const total = byUser.get(user).filter((x) => x.success).length;
      push({ id: "after_hours_admin", key: `afterhrs:${user}`, severity: "medium", confidence: arr[0].adminBasis === "role" ? "high" : "medium", user, ip: null,
        title: `${user}: ${arr.length} administrative sign-in${arr.length === 1 ? "" : "s"} outside ${pad(o.bizStartHour)}:00 to ${pad(o.bizEndHour)}:00 (UTC${offsetText(o.utcOffsetMin)})`,
        description: `${arr.length} of ${total} successful sign-ins for this administrator fell outside the configured business hours${o.weekendIsAfterHours ? " or on a weekend" : ""}, evaluated at UTC${offsetText(o.utcOffsetMin)}. Out-of-hours administration is normal for on-call staff and change windows; the point is to reconcile each one against a ticket.`,
        counts: { afterHours: arr.length, totalSuccesses: total, bizStartHour: o.bizStartHour, bizEndHour: o.bizEndHour, utcOffsetMin: o.utcOffsetMin },
        evidence: cap(arr, o.evidenceCap).map((x) => ev(x, localTimeText(x.ts, o.utcOffsetMin))), evidenceTotal: arr.length });
    }
  }

  // 9. Concurrent sessions from distant locations (country or distance), excluding pairs already reported as impossible travel
  if (canRun.concurrent_distant) {
    const W = o.concurrentWindowMin * 60000;
    for (const [user, arr] of byUser) {
      const succ = arr.filter((r) => r.success && r.ip && (r.country || resolvePlace(r)));
      const pairs = [];
      for (let i = 0; i < succ.length && pairs.length < 10; i++) {
        for (let j = i + 1; j < succ.length && succ[j].ts - succ[i].ts <= W; j++) {
          const a = succ[i], b = succ[j];
          if (a.ip === b.ip) continue;
          if (travelPairs.has(`${a._i}|${b._i}`) || travelIpPairs.has(`${user}|${a.ip}|${b.ip}`)) continue;
          const pa = resolvePlace(a), pb = resolvePlace(b);
          let distant = false, km = null;
          if (pa && pb) { km = haversineKm(pa.lat, pa.lon, pb.lat, pb.lon); distant = km >= o.concurrentMinKm; }
          else if (a.country && b.country) distant = a.country.toLowerCase() !== b.country.toLowerCase();
          if (distant) pairs.push({ a, b, km });
        }
      }
      if (!pairs.length) continue;
      const locs = new Set(); pairs.forEach((p) => { locs.add(place(p.a)); locs.add(place(p.b)); });
      push({ id: "concurrent_distant", key: `conc:${user}`, severity: "high", confidence: pairs.some((p) => p.km !== null) ? "high" : "medium", user, ip: null,
        title: `${user}: active from ${locs.size} distant locations within ${fmtWindow(o.concurrentWindowMin)}`,
        description: `${pairs.length} pair${pairs.length === 1 ? "" : "s"} of successful sign-ins less than ${fmtWindow(o.concurrentWindowMin)} apart came from different addresses in ${[...locs].slice(0, 4).join(" and ")}${pairs[0].km !== null ? ` (about ${Math.round(pairs[0].km).toLocaleString()} km apart)` : ""}. Overlapping sessions from distant places point to a shared password, a stolen session token, or a VPN that moved egress mid-session.`,
        counts: { pairs: pairs.length, locations: [...locs] },
        evidence: cap(pairs.flatMap((p) => [ev(p.a, "session A"), ev(p.b, "session B")]), o.evidenceCap), evidenceTotal: pairs.length * 2 });
    }
  }

  // 10. Hosting / VPN / proxy ASN (only when the export carries ASN/ISP/proxy data)
  if (canRun.anonymizer_asn) {
    const groups = new Map();
    for (const r of recs) {
      if (!r.success) continue;
      const hit = r.isProxy === true ? "provider-marked proxy" : hostingHint(r.isp, r.asn);
      if (!hit) continue;
      const k = `${r.user}|${r.ip || r.isp}`;
      let g = groups.get(k); if (!g) { g = { hit, arr: [] }; groups.set(k, g); } g.arr.push(r);
    }
    for (const [k, g] of groups) {
      const r = g.arr[0];
      const admin = g.arr.some((x) => x.isAdmin === true);
      push({ id: "anonymizer_asn", key: `asn:${k}`, severity: admin || r.isProxy === true ? "high" : "medium", confidence: r.isProxy === true ? "high" : "medium", user: r.user, ip: r.ip,
        title: `${r.user}: ${g.arr.length} success${g.arr.length === 1 ? "" : "es"} from ${r.isp || r.asn || r.ip} (${g.hit})`,
        description: `Successful sign-ins came from a network the export labels "${r.isp || r.asn}"${r.asn ? ` (AS${String(r.asn).replace(/^as/i, "")})` : ""}, which matches a hosting provider, VPN or proxy service${r.isProxy === true ? "; the provider itself marked the address as a proxy" : ""}. Attackers rent cloud hosts and VPN exits to avoid geolocation controls; employees use VPNs too, so confirm whether this network is expected for the user.${admin ? " The account is identified as an administrator." : ""}`,
        counts: { successes: g.arr.length, isp: r.isp, asn: r.asn, isProxy: r.isProxy, matched: g.hit },
        evidence: cap(g.arr, o.evidenceCap).map((x) => ev(x)), evidenceTotal: g.arr.length });
    }
  }

  // 11. Provider risk flags present in the export
  if (canRun.provider_risk_flag) {
    const groups = new Map();
    for (const r of recs) {
      if (!r.riskFlag) continue;
      let g = groups.get(r.user); if (!g) { g = []; groups.set(r.user, g); } g.push(r);
    }
    for (const [user, arr] of groups) {
      const flags = [...new Set(arr.map((x) => x.riskFlag))];
      const confirmed = flags.some((f) => /confirmed|compromised|high/i.test(f));
      push({ id: "provider_risk_flag", key: `risk:${user}`, severity: confirmed ? "high" : "medium", confidence: "high", user, ip: null,
        title: `${user}: ${arr.length} sign-in${arr.length === 1 ? "" : "s"} flagged by the identity provider (${flags.slice(0, 3).join(", ")})`,
        description: `The export itself marks ${arr.length} sign-in${arr.length === 1 ? "" : "s"} for this account as risky (${flags.join(", ")}). The provider's risk engine uses signals such as leaked-credential matches and anonymiser intelligence that are not in the export, so this is reported as the provider's finding, not this tool's.`,
        counts: { flagged: arr.length, flags },
        evidence: cap(arr, o.evidenceCap).map((x) => ev(x, x.riskFlag)), evidenceTotal: arr.length });
    }
  }

  // Sort and count
  const CONF_RANK = { high: 0, medium: 1, low: 2 };
  findings.sort((a, b) => (SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]) || ((CONF_RANK[a.confidence] ?? 9) - (CONF_RANK[b.confidence] ?? 9)) || a.title.localeCompare(b.title));
  for (const f of findings) {
    const c = coverage.find((x) => x.id === f.id); if (c) c.findings++;
    if (f.user && users.has(f.user)) users.get(f.user).findings.push(f.key);
  }
  // Findings keyed to an IP but no single user (spray): attribute to every sprayed user for scoring
  for (const f of findings) if (f.id === "password_spray") for (const e of f.evidence) { const u = users.get(e.user); if (u && !u.findings.includes(f.key)) u.findings.push(f.key); }

  const byKey = new Map(findings.map((f) => [f.key, f]));
  const userRows = [...users.values()].map((u) => {
    let w = 0; const sev = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const k of u.findings) { const f = byKey.get(k); if (!f) continue; const weight = f.id === "password_spray" ? 5 : SEV_WEIGHT[f.severity]; w += f.confidence === "medium" && f.id !== "password_spray" ? Math.round(weight * 0.7) : weight; sev[f.severity]++; }
    u.score = Math.min(100, w);
    return { user: u.user, score: u.score, severities: sev, findings: u.findings, successes: u.successes, failures: u.failures, ips: u.ips.size, countries: [...u.countries], first: u.first, last: u.last, isAdmin: u.isAdmin, adminBasis: u.adminBasis };
  }).sort((a, b) => b.score - a.score || b.failures - a.failures || a.user.localeCompare(b.user));

  const sevCount = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) sevCount[f.severity]++;
  const top = userRows[0] ? userRows[0].score : 0;
  const elevated = userRows.filter((u) => u.score >= 50).length;
  const overall = Math.min(100, top + Math.max(0, elevated - 1) * 5);
  const label = overall >= 80 ? "Critical" : overall >= 50 ? "High" : overall >= 20 ? "Elevated" : findings.length ? "Low" : "No findings";
  const explanation = !findings.length
    ? "No detection produced a finding on this dataset with the current thresholds. Check the coverage panel for detections that were skipped."
    : `Overall ${overall}/100 (${label}). The highest per-user score is ${top} (${userRows[0].user}); ${elevated} account${elevated === 1 ? "" : "s"} score 50 or more, each adding 5. Per-user scores sum finding weights (critical 40, high 25, medium 10, low 3; medium-confidence findings count 70%; being one of many sprayed targets counts 5) and cap at 100.`;

  return {
    source, kpis: { records: recs.length, successes, failures, users: users.size, ips: ips.size, countries: countries.size, spanStart, spanEnd, spanDays: Math.round(spanDays * 10) / 10 },
    findings, coverage, users: userRows, score: { overall, label, explanation, severities: sevCount }, options: o,
  };
}

function inferColumns(records) {
  const any = (f) => records.some((r) => r[f] !== null && r[f] !== undefined && r[f] !== "");
  return { ts: true, user: true, ip: any("ip"), status: true, app: any("app"), clientApp: any("clientApp"), mfa: records.some((r) => r.mfa !== null), country: any("country"), city: any("city"),
    latlon: records.some((r) => r.lat !== null && r.lon !== null), role: records.some((r) => r.adminBasis === "role"), asn: any("asn") || any("isp") || records.some((r) => r.isProxy !== null), riskFlag: any("riskFlag") };
}

export function isAfterHours(ts, o) {
  const local = new Date(ts + (o.utcOffsetMin || 0) * 60000);
  const h = local.getUTCHours() + local.getUTCMinutes() / 60;
  const day = local.getUTCDay();
  if (o.weekendIsAfterHours && (day === 0 || day === 6)) return true;
  return h < o.bizStartHour || h >= o.bizEndHour;
}

// Per-user timeline rows (sorted) with which findings reference each row.
export function userTimeline(result, records, user) {
  const refs = new Map();
  for (const f of result.findings) for (const e of f.evidence) if (e.user === user) { if (!refs.has(e.idx)) refs.set(e.idx, []); refs.get(e.idx).push(f.key); }
  return records.filter((r) => r.user === user && Number.isFinite(r.ts) && r.success !== null).sort((a, b) => a.ts - b.ts)
    .map((r) => ({ ts: r.ts, ip: r.ip, success: r.success, app: r.app, clientApp: r.clientApp, mfa: r.mfa, country: r.country, city: r.city, failureReason: r.failureReason, userAgent: r.userAgent, flags: refs.get(r._i) || [] }));
}

// ---------------------------------------------------------------------------
// Exports / text
// ---------------------------------------------------------------------------
export function findingsToCsv(findings) {
  const q = (v) => { let s = String(v == null ? "" : v); if (/^[=+@\t\r-]/.test(s) && !/^-\d+(\.\d+)?$/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; }; // a leading = + - @ would run as a spreadsheet formula
  const lines = ["severity,confidence,detection,technique,user,ip,title,description,recommended_action,evidence_count"];
  for (const f of findings) lines.push([f.severity, f.confidence, f.id, q(f.technique), q(f.user), q(f.ip), q(f.title), q(f.description), q(f.action), f.evidenceTotal].join(","));
  return lines.join("\n") + "\n";
}

export function evidenceToCsv(findings) {
  const q = (v) => { let s = String(v == null ? "" : v); if (/^[=+@\t\r-]/.test(s) && !/^-\d+(\.\d+)?$/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; }; // a leading = + - @ would run as a spreadsheet formula
  const lines = ["finding_key,detection,severity,timestamp_utc,user,ip,outcome,app,client_app,mfa,country,city,failure_reason,note"];
  for (const f of findings) for (const e of f.evidence) lines.push([q(f.key), f.id, f.severity, q(iso(e.ts)), q(e.user), q(e.ip), e.success ? "success" : "failure", q(e.app), q(e.clientApp), e.mfa === null ? "" : e.mfa, q(e.country), q(e.city), q(e.failureReason), q(e.note)].join(","));
  return lines.join("\n") + "\n";
}

export function summaryText(result) {
  const k = result.kpis, s = result.score;
  const lines = [];
  lines.push(`Sign-in Forensics summary (${sourceName(result.source)} export)`);
  lines.push(`Records analysed: ${k.records.toLocaleString()} authentication events (${k.successes.toLocaleString()} successes, ${k.failures.toLocaleString()} failures) for ${k.users.toLocaleString()} users from ${k.ips.toLocaleString()} IPs${k.countries ? ` across ${k.countries} countries` : ""}; ${k.spanStart ? `${iso(k.spanStart)} to ${iso(k.spanEnd)} (${k.spanDays} days)` : "no time span"}.`);
  lines.push(`Overall risk: ${s.overall}/100 (${s.label}). Findings: ${s.severities.critical} critical, ${s.severities.high} high, ${s.severities.medium} medium, ${s.severities.low} low.`);
  const skipped = result.coverage.filter((c) => !c.ran);
  lines.push(`Detections run: ${result.coverage.length - skipped.length}/${result.coverage.length}${skipped.length ? ` (skipped: ${skipped.map((c) => c.name).join("; ")})` : ""}.`);
  lines.push("");
  for (const f of result.findings.slice(0, 25)) lines.push(`[${f.severity.toUpperCase()} / ${f.confidence} confidence] ${f.technique} ${f.title}`);
  if (result.findings.length > 25) lines.push(`... and ${result.findings.length - 25} more findings.`);
  return lines.join("\n");
}

export function sourceName(src) {
  return { entra: "Microsoft Entra ID sign-in logs", google: "Google Workspace Login audit", okta: "Okta System Log", generic: "Generic sign-in log", unknown: "Unrecognised" }[src] || String(src);
}

export function iso(ts) { if (!Number.isFinite(ts)) return ""; return new Date(ts).toISOString().replace(".000Z", "Z"); }
function pad(n) { return String(n).padStart(2, "0"); }
function offsetText(min) { if (!min) return "+00:00"; const s = min < 0 ? "-" : "+"; const a = Math.abs(min); return `${s}${pad(Math.floor(a / 60))}:${pad(a % 60)}`; }
function localTimeText(ts, offMin) { const d = new Date(ts + (offMin || 0) * 60000); const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]; return `local ${days[d.getUTCDay()]} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`; }
function durationText(ms) { const m = Math.round(ms / 60000); if (m < 60) return `${m} min`; const h = Math.floor(m / 60); return `${h} h ${pad(m % 60)} min`; }
function place(r) { return [r.city, r.country].filter(Boolean).join(", ") || (r.lat !== null && r.lat !== undefined ? `${r.lat},${r.lon}` : "unknown location"); }
function cap1(s) { return s ? s.charAt(0).toUpperCase() + s.slice(1) : s; }

// ---------------------------------------------------------------------------
// Security Graph sink: analyze() findings -> common Finding shape (core/sink-map.js).
// The engine's titles carry counts that change between runs, so the graph title is
// the detection name + the subject from the stable key; the counted title leads the
// description instead.
// ---------------------------------------------------------------------------
export function toSinkFindings(result) {
  return ((result && result.findings) || []).map((f) => {
    let subject = f.key.slice(f.key.indexOf(":") + 1);
    if (f.user && subject.startsWith(f.user + ":")) subject = f.user + " / " + subject.slice(f.user.length + 1);
    subject = subject.replace(/<>|\|/g, " / ");
    const users = f.id === "password_spray" ? [...new Set(f.evidence.map((e) => e.user).filter(Boolean))].slice(0, 25) : f.user ? [f.user] : [];
    return {
      id: f.key, title: `${f.name}: ${subject}`, severity: f.severity, confidence: f.confidence, category: f.id,
      description: `${f.title}. ${f.description || ""}`.trim(), recommendation: f.action,
      controls: controlsFromRefs([f.technique]),
      evidence: f.evidence.slice(0, 50).map((e) => ({ ts: iso(e.ts), user: e.user, ip: e.ip, outcome: e.success ? "success" : "failure", app: e.app || "", clientApp: e.clientApp || "", country: e.country || "", city: e.city || "", mfa: e.mfa, note: e.note || "" })),
      evidenceCount: f.evidenceTotal != null ? f.evidenceTotal : f.evidence.length,
      assets: [...users.map((u) => ({ type: "IDENTITY", name: u })), ...(f.ip ? [{ type: "IP", name: f.ip }] : [])],
      tags: ["signin"],
    };
  });
}
