// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Access Review engine (pure: no DOM, no network).
//
// Reconciles an HR roster against a directory / IdP export (Entra ID, Google
// Workspace, Okta, Active Directory, or a generic CSV) and produces the
// deterministic findings a periodic user-access review needs: leavers still
// enabled, orphan accounts, stale accounts, admins without MFA, guests, and so
// on. Every number comes from the two inputs; nothing is inferred from outside.
//
// Control references used in findings:
//   ISO 27001:2022 A.5.18 (access rights review), A.8.2 (privileged access)
//   NIST SP 800-53 AC-2 (account management), AC-6 (least privilege), IA-2(1)
//   CIS Controls v8 5.1 / 5.3 / 5.4 / 6.2 / 6.5
//   SOX ITGC: periodic user access review (logical access)
//   MITRE ATT&CK T1078 Valid Accounts (where the finding is an abuse path)

const DAY = 86400000;

export const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

// ---------------------------------------------------------------------------
// CSV parsing: RFC 4180 quotes, doubled quotes, embedded newlines, CRLF, BOM,
// and delimiter autodetection (comma / semicolon / tab).
// ---------------------------------------------------------------------------
export function detectDelimiter(text) {
  const firstLine = String(text || "").split(/\r?\n/, 1)[0] || "";
  const counts = { ",": 0, ";": 0, "\t": 0 };
  let inQ = false;
  for (const ch of firstLine) {
    if (ch === '"') inQ = !inQ;
    else if (!inQ && ch in counts) counts[ch]++;
  }
  let best = ",", n = -1;
  for (const d of [",", ";", "\t"]) if (counts[d] > n) { n = counts[d]; best = d; }
  return best;
}

export function parseCSV(text, opts = {}) {
  let s = String(text || "");
  if (s.charCodeAt(0) === 0xfeff) s = s.slice(1);
  const delim = opts.delimiter || detectDelimiter(s);
  const records = [];
  let row = [], field = "", inQ = false, i = 0;
  const n = s.length;
  while (i < n) {
    const ch = s[i];
    if (inQ) {
      if (ch === '"') {
        if (s[i + 1] === '"') { field += '"'; i += 2; continue; }
        inQ = false; i++; continue;
      }
      field += ch; i++; continue;
    }
    if (ch === '"') { inQ = true; i++; continue; }
    if (ch === delim) { row.push(field); field = ""; i++; continue; }
    if (ch === "\r") { i++; continue; }
    if (ch === "\n") { row.push(field); records.push(row); row = []; field = ""; i++; continue; }
    field += ch; i++;
  }
  if (field.length || row.length) { row.push(field); records.push(row); }
  // drop fully empty trailing rows
  while (records.length && records[records.length - 1].every((c) => c.trim() === "")) records.pop();
  if (!records.length) return { headers: [], rows: [], delimiter: delim };
  const headers = records[0].map((h) => String(h).trim());
  const rows = [];
  for (let r = 1; r < records.length; r++) {
    const rec = records[r];
    if (rec.every((c) => c.trim() === "")) continue;
    const obj = {};
    for (let c = 0; c < headers.length; c++) obj[headers[c] || `col${c}`] = (rec[c] == null ? "" : rec[c]).trim();
    rows.push(obj);
  }
  return { headers, rows, delimiter: delim };
}

// ---------------------------------------------------------------------------
// Header matching. Headers are normalised (lower-case, bracketed suffixes such
// as Google's "[Required]" removed, non-alphanumerics dropped) and compared
// against synonym lists. The first header matching any synonym wins.
// ---------------------------------------------------------------------------
export function normHeader(h) {
  return String(h || "").toLowerCase().replace(/\[[^\]]*\]/g, "").replace(/\([^)]*\)/g, "").replace(/[^a-z0-9]/g, "");
}

export function findColumn(headers, synonyms) {
  const norm = headers.map((h) => ({ h, n: normHeader(h) }));
  for (const syn of synonyms) {
    const hit = norm.find((x) => x.n === syn);
    if (hit) return hit.h;
  }
  return null;
}

const HR_COLS = {
  employeeId: ["employeeid", "employeenumber", "employeeno", "empid", "empno", "emplid", "personnelnumber", "workerid", "staffid", "personid", "associateid", "employee", "id"],
  name: ["fullname", "employeename", "workername", "displayname", "name", "legalname", "preferredname"],
  firstName: ["firstname", "givenname", "legalfirstname", "first", "forename"],
  lastName: ["lastname", "surname", "familyname", "legallastname", "last"],
  email: ["workemail", "businessemail", "companyemail", "corporateemail", "emailaddress", "email", "primaryemail", "mail", "emailwork"],
  dept: ["department", "departmentname", "dept", "orgunit", "organizationalunit", "division", "businessunit", "team"],
  title: ["jobtitle", "title", "position", "role", "job", "positiontitle", "businesstitle"],
  manager: ["manager", "managername", "supervisor", "reportsto", "manageremail", "supervisorname", "managerid"],
  status: ["employmentstatus", "employeestatus", "workerstatus", "status", "state", "employmentstate", "active"],
  startDate: ["startdate", "hiredate", "dateofhire", "originalhiredate", "joindate", "joiningdate", "employmentstartdate", "hired", "start", "datejoined"],
  endDate: ["terminationdate", "termdate", "enddate", "separationdate", "dateofseparation", "lastday", "lastdayofwork", "lastworkingday", "exitdate", "leavedate", "terminated", "employmentenddate", "dateofleaving"],
  type: ["workertype", "employeetype", "employmenttype", "workercategory", "contingenttype"],
};

const DIR_COLS = {
  upn: ["userprincipalname", "upn", "login", "username", "samaccountname", "accountname", "user", "userid", "logonname"],
  email: ["mail", "emailaddress", "primaryemail", "email", "workemail", "proxyaddress"],
  name: ["displayname", "fullname", "name", "cn", "commonname"],
  firstName: ["firstname", "givenname", "first"],
  lastName: ["lastname", "surname", "sn", "familyname", "last"],
  enabled: ["accountenabled", "enabled", "isenabled", "accountstatus", "status", "active", "isactive", "state"],
  disabled: ["disabled", "isdisabled", "suspended", "issuspended", "blocked", "archived"],
  uac: ["useraccountcontrol"],
  userType: ["usertype", "accounttype", "type", "memberkind"],
  roles: ["directoryroles", "assignedroles", "adminroles", "roles", "role", "adminrole", "privilegedroles", "rolename"],
  adminFlag: ["adminstatus", "isadmin", "admin", "superadmin", "issuperadmin", "isdelegatedadmin", "delegatedadmin", "admincount"],
  memberOf: ["memberof", "groups", "groupmemberships", "groupmembership", "groupnames", "group"],
  mfa: ["perusermfa", "perusermfastatus", "mfastatus", "mfa", "strongauthenticationrequirements", "ismfaregistered", "mfaregistered", "ismfacapable", "mfacapable", "2svenrolled", "2stepverificationenrollment", "2stepverificationenrolled", "twostepverificationenrollment", "isenrolledin2sv", "mfaenrolled", "mfaenabled", "multifactorenabled", "strongauthstatus"],
  lastSignIn: ["lastsignindatetime", "lastsignin", "lastsignintime", "lastinteractivesignindatetime", "lastsuccessfulsignindatetime", "lastlogin", "lastlogon", "lastlogontimestamp", "lastlogondate", "lastlogondatetime", "lastactivity", "lastactive", "lastloginat", "lastloginiso"],
  created: ["createddatetime", "created", "creationtime", "whencreated", "createdon", "createdate", "creationdate", "datecreated", "createdat", "activated"],
  dept: ["department", "dept", "orgdepartment"],
  title: ["jobtitle", "title", "position"],
  employeeId: ["employeeid", "employeenumber", "employeeno", "empid", "emplid", "workerid", "staffid", "personnelnumber", "employee"],
  pwdLastSet: ["pwdlastset", "passwordlastset", "passwordlastchanged", "lastpasswordchange", "lastpasswordchangedatetime", "passwordlastchangetime", "passwordchanged", "lastpasswordchangetime"],
  pwdNeverExpires: ["passwordneverexpires", "pwdneverexpires", "neverexpires", "passwordneverexpire"],
  orgUnit: ["orgunitpath", "orgunit", "ou", "organizationalunit"],
  dn: ["distinguishedname", "dn"],
  status: ["status"],
};

// ---------------------------------------------------------------------------
// Value parsing
// ---------------------------------------------------------------------------
export function parseBool(v) {
  if (v === true) return true;
  if (v === false) return false;
  const s = String(v == null ? "" : v).trim().toLowerCase();
  if (!s) return null;
  if (["true", "yes", "y", "1", "enabled", "enforced", "on", "active", "registered", "enrolled", "capable", "t"].includes(s)) return true;
  if (["false", "no", "n", "0", "disabled", "off", "inactive", "notregistered", "not registered", "notenrolled", "not enrolled", "none", "f"].includes(s)) return false;
  return null;
}

// Returns epoch ms or null. Accepts ISO 8601, "YYYY/MM/DD HH:mm:ss", US and
// day-first slash dates, AD generalized time (20240102153000.0Z), Windows
// FILETIME (18 digits), epoch seconds/milliseconds. "Never" and blanks -> null.
export function parseDate(v) {
  if (v == null) return null;
  if (typeof v === "number") return numericDate(v);
  const s = String(v).trim();
  if (!s) return null;
  const low = s.toLowerCase();
  if (/^(never|never logged in|n\/a|na|none|null|-|unknown|not set)$/.test(low)) return null;
  if (/^\d+$/.test(s)) return numericDate(Number(s));
  let m;
  if ((m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z?$/.exec(s))) {
    return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
  }
  if ((m = /^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?)?\s*(Z|UTC|[+-]\d{2}:?\d{2})?$/i.exec(s))) {
    const base = Date.UTC(+m[1], +m[2] - 1, +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0));
    return applyOffset(base, m[7]);
  }
  if ((m = /^(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?)?\s*([AP]M)?$/i.exec(s))) {
    let a = +m[1], b = +m[2];
    let month, day;
    if (a > 12) { day = a; month = b; } else { month = a; day = b; } // US default, day-first when unambiguous
    let hh = +(m[4] || 0);
    if (m[7]) { const pm = m[7].toUpperCase() === "PM"; if (pm && hh < 12) hh += 12; if (!pm && hh === 12) hh = 0; }
    return Date.UTC(+m[3], month - 1, day, hh, +(m[5] || 0), +(m[6] || 0));
  }
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : null;
}

function applyOffset(base, tz) {
  if (!tz || /^(z|utc)$/i.test(tz)) return base;
  const m = /^([+-])(\d{2}):?(\d{2})$/.exec(tz);
  if (!m) return base;
  const off = (+m[2] * 60 + +m[3]) * 60000 * (m[1] === "+" ? 1 : -1);
  return base - off;
}

function numericDate(n) {
  if (!Number.isFinite(n) || n <= 0) return null;
  if (n >= 1e17) return Math.round(n / 10000 - 11644473600000); // Windows FILETIME (100ns since 1601)
  if (n >= 1e12) return n;                                        // epoch ms
  if (n >= 1e9) return n * 1000;                                  // epoch s
  return null;
}

export function normalizeEmail(email, opts = {}) {
  let s = String(email || "").trim().toLowerCase();
  if (!s || !s.includes("@")) return s || "";
  let [local, domain] = s.split("@");
  if (!domain) return s;
  // Entra guest UPNs: name_ext.com#EXT#@tenant.onmicrosoft.com
  if (local.includes("#ext#")) {
    const orig = local.replace(/#ext#.*$/, "");
    const idx = orig.lastIndexOf("_");
    if (idx > 0) { local = orig.slice(0, idx); domain = orig.slice(idx + 1); }
  }
  local = local.replace(/\+.*$/, "");
  const aliases = (opts.aliasDomains || []).map((d) => String(d).trim().toLowerCase()).filter(Boolean);
  if (aliases.length > 1 && aliases.includes(domain)) domain = aliases[0];
  return `${local}@${domain}`;
}

export function normalizeName(name) {
  let s = String(name || "").toLowerCase();
  if (s.includes(",")) { const [a, b] = s.split(","); s = `${b || ""} ${a || ""}`; } // "Last, First"
  s = s.normalize("NFD").replace(/[̀-ͯ]/g, "");
  s = s.replace(/\([^)]*\)/g, " ").replace(/[^a-z\s]/g, " ").replace(/\s+/g, " ").trim();
  // drop single-letter initials ("J. Doe" -> "doe") so they do not break fuzzy matching
  return s.split(" ").filter((p) => p.length > 1).join(" ");
}

export function levenshtein(a, b, max = Infinity) {
  a = String(a || ""); b = String(b || "");
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > max) return max + 1;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
      if (cur[j] < rowMin) rowMin = cur[j];
    }
    if (rowMin > max) return max + 1;
    prev = cur;
  }
  return prev[b.length];
}

// FNV-1a over the two inputs; used to key reviewer decisions to a dataset.
export function datasetHash(hrText, dirText) {
  const s = String(hrText || "") + "\u0000" + String(dirText || "");
  let h1 = 0x811c9dc5, h2 = 0x01000193 ^ 0x5bd1e995;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    h1 ^= c; h1 = Math.imul(h1, 0x01000193) >>> 0;
    h2 ^= c; h2 = Math.imul(h2, 0x9e3779b1) >>> 0;
  }
  return "acr-" + h1.toString(16).padStart(8, "0") + h2.toString(16).padStart(8, "0") + "-" + s.length.toString(36);
}

// ---------------------------------------------------------------------------
// HR roster
// ---------------------------------------------------------------------------
export function parseHRStatus(v, hint) {
  const s = String(v == null ? "" : v).trim().toLowerCase();
  const h = String(hint == null ? "" : hint).trim().toLowerCase();
  if (/contract|contingent|vendor|temp|consultant|intern/.test(h) && !/terminat|inactive/.test(s)) return "contractor";
  if (!s) return "unknown";
  if (/terminat|^term$|inactive|separat|ended|^left$|resign|retir|dismiss|offboard|^t$|^i$|former|exited|^ex$|departed|^false$|^no$|^0$/.test(s)) return "terminated";
  if (/leave|^loa$|parental|sabbatical|furlough|suspend/.test(s)) return "leave";
  if (/contract|contingent|vendor|temp|consultant|intern/.test(s)) return "contractor";
  if (/active|^a$|employed|current|hired|regular|^true$|^yes$|^1$|fulltime|parttime|full-time|part-time/.test(s)) return "active";
  return "unknown";
}

export function parseHR(text, opts = {}) {
  const { headers, rows } = parseCSV(text);
  const col = {};
  for (const k of Object.keys(HR_COLS)) col[k] = findColumn(headers, HR_COLS[k]);
  // "id" alone is weak; only accept generic "id" when nothing better exists (already ordered).
  const employees = [];
  const warnings = [];
  const now = opts.now || Date.now();
  const seen = new Set();
  let dupIds = 0;
  for (const r of rows) {
    const get = (k) => (col[k] ? r[col[k]] : "");
    let name = get("name");
    if (!name && (col.firstName || col.lastName)) name = `${get("firstName")} ${get("lastName")}`.trim();
    const endDate = parseDate(get("endDate"));
    let status = parseHRStatus(get("status"), get("type"));
    let statusSource = col.status ? "column" : "none";
    if (status === "unknown" || status === "active") {
      if (endDate != null && endDate <= now && (status === "unknown" || !col.status)) { status = "terminated"; statusSource = "endDate"; }
      else if (status === "unknown") { status = col.status ? "unknown" : "active"; statusSource = col.status ? "column" : "assumed"; }
    }
    const employeeId = String(get("employeeId") || "").trim();
    if (employeeId) { if (seen.has(employeeId.toLowerCase())) dupIds++; seen.add(employeeId.toLowerCase()); }
    employees.push({
      employeeId,
      name: name.trim(),
      nameKey: normalizeName(name),
      email: String(get("email") || "").trim(),
      emailKey: normalizeEmail(get("email"), opts),
      dept: get("dept"), title: get("title"), manager: get("manager"),
      status, statusSource, statusRaw: get("status"),
      startDate: parseDate(get("startDate")),
      endDate,
      raw: r,
    });
  }
  if (!employees.length) warnings.push("The HR roster has no data rows.");
  if (!col.employeeId && !col.email) warnings.push("No employee id or email column found in the roster. Matching will rely on names only.");
  if (!col.status && !col.endDate) warnings.push("No employment status or termination date column: every roster row is treated as active.");
  if (dupIds) warnings.push(`${dupIds} duplicate employee id(s) in the roster.`);
  const coverage = {
    employeeId: !!col.employeeId, name: !!(col.name || col.firstName), email: !!col.email, dept: !!col.dept,
    title: !!col.title, manager: !!col.manager, status: !!col.status, startDate: !!col.startDate, endDate: !!col.endDate,
  };
  return { employees, coverage, columns: col, warnings, rowCount: rows.length };
}

// ---------------------------------------------------------------------------
// Directory / IdP export
// ---------------------------------------------------------------------------
const PRIV_AD_GROUPS = new Set(["domain admins", "enterprise admins", "schema admins", "administrators", "account operators",
  "server operators", "backup operators", "print operators", "dnsadmins", "group policy creator owners", "enterprise key admins",
  "key admins", "cert publishers", "remote desktop users", "exchange organization administrators", "organization management"]);

export const SERVICE_PATTERNS = [/^svc[-_.]/i, /^sa[-_.]/i, /^service[-_.]?/i, /[-_.]svc(@|$|[-_.])/i, /shared/i, /mailbox/i,
  /^no[-_.]?reply/i, /donotreply/i, /^do[-_.]not[-_.]reply/i, /^sys[-_.]/i, /^system[-_.]/i, /^bot[-_.]/i, /[-_.]bot(@|$)/i,
  /^automation/i, /^integration/i, /^api[-_.]/i, /^app[-_.]/i, /^scanner/i, /^backup/i, /^monitor/i, /^printer/i,
  /^conference/i, /^room[-_.]/i, /^meetingroom/i, /^reception@/i, /^info@/i, /^support@/i, /^sales@/i, /^billing@/i,
  /^helpdesk@/i, /^it@/i, /^hr@/i, /^admin@/i, /^security@/i, /^alerts?@/i, /^notifications?@/i];

export function looksLikeServiceAccount(acct) {
  const probes = [acct.id, acct.email, acct.name].filter(Boolean).map(String);
  for (const p of probes) for (const re of SERVICE_PATTERNS) if (re.test(p)) return true;
  const ou = String(acct.orgUnit || "").toLowerCase();
  if (/service|shared|resource|mailbox|automation|system/.test(ou)) return true;
  return false;
}

export function detectSource(headers, isJson) {
  const n = new Set(headers.map(normHeader));
  const score = { entra: 0, google: 0, okta: 0, ad: 0 };
  const hit = (k, ...keys) => { for (const x of keys) if (n.has(x)) score[k] += 2; };
  hit("entra", "userprincipalname", "accountenabled", "usertype", "createddatetime", "lastsignindatetime", "perusermfastatus", "onpremisessyncenabled", "objectid", "directoryroles", "assignedroles");
  hit("google", "emailaddress", "2svenrolled", "2svenforced", "2stepverificationenrollment", "2stepverificationenforcement", "orgunitpath", "lastsignin", "recoveryemail", "recoveryphone", "passwordhashfunction", "newprimaryemail");
  hit("okta", "login", "lastlogin", "employeenumber", "statuschanged", "passwordchanged", "activated", "secondemail", "mobilephone", "lastupdated", "profilelogin");
  hit("ad", "samaccountname", "lastlogontimestamp", "memberof", "whencreated", "pwdlastset", "useraccountcontrol", "distinguishedname", "objectguid", "objectsid", "passwordneverexpires", "lastlogondate", "whenchanged");
  if (isJson && n.has("login")) score.okta += 3;
  let best = "generic", bestScore = 3;
  for (const k of Object.keys(score)) if (score[k] > bestScore) { best = k; bestScore = score[k]; }
  return best;
}

function splitList(v) {
  return String(v == null ? "" : v).split(/[;|,\n]+/).map((x) => x.trim()).filter((x) => x && !/^(none|null|false|n\/a|-)$/i.test(x));
}

function adGroupName(dn) {
  const m = /^cn=([^,]+)/i.exec(dn);
  return (m ? m[1] : dn).trim();
}

function adminFromRoles(list, source) {
  const roles = [];
  for (const g of list) {
    const name = adGroupName(g);
    const low = name.toLowerCase();
    if (source === "ad") { if (PRIV_AD_GROUPS.has(low) || /admin/.test(low)) roles.push(name); }
    else if (/admin|administrator|owner|global|privileged|superuser|root/.test(low)) roles.push(name);
  }
  return roles;
}

function flattenJson(obj, prefix, out) {
  for (const [k, v] of Object.entries(obj || {})) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === "object" && !Array.isArray(v)) flattenJson(v, key, out);
    else out[key] = Array.isArray(v) ? v.map((x) => (x && typeof x === "object" ? (x.profile && x.profile.name) || x.displayName || x.name || x.id || JSON.stringify(x) : x)).join(";") : (v == null ? "" : String(v));
  }
  return out;
}

// Okta (array of users, or {users:[...]}), Entra Graph ({value:[...]}), or any array of flat objects.
export function parseJSONUsers(text) {
  let data = JSON.parse(text);
  if (data && !Array.isArray(data)) data = data.value || data.users || data.data || data.items || data.members || [];
  if (!Array.isArray(data)) throw new Error("JSON must be an array of users.");
  const rows = data.map((u) => {
    const flat = flattenJson(u, "", {});
    // Promote Okta profile.* keys to top-level names
    const out = {};
    for (const [k, v] of Object.entries(flat)) out[k.replace(/^profile\./, "")] = v;
    if (u && Array.isArray(u.groups)) out.groups = u.groups.map((g) => (g && g.profile && g.profile.name) || (g && g.name) || String(g)).join(";");
    if (u && Array.isArray(u.roles)) out.roles = u.roles.map((r) => (r && (r.label || r.type || r.displayName)) || String(r)).join(";");
    return out;
  });
  const headerSet = new Set();
  rows.forEach((r) => Object.keys(r).forEach((k) => headerSet.add(k)));
  return { headers: [...headerSet], rows };
}

export function parseDirectory(text, opts = {}) {
  const src = String(text || "").trim();
  let parsed, isJson = false;
  if (src.startsWith("[") || src.startsWith("{")) { parsed = parseJSONUsers(src); isJson = true; }
  else parsed = parseCSV(src);
  const { headers, rows } = parsed;
  const source = opts.source || detectSource(headers, isJson);
  const col = {};
  for (const k of Object.keys(DIR_COLS)) col[k] = findColumn(headers, DIR_COLS[k]);
  // Google's "Status" means account state; Okta "status" likewise. Keep enabled column separate from generic status.
  if (!col.enabled && col.status) col.enabled = col.status;
  const users = [];
  const warnings = [];
  const have = (k) => !!col[k];
  const populated = {};
  const bump = (k) => { populated[k] = (populated[k] || 0) + 1; };

  for (const r of rows) {
    const get = (k) => (col[k] ? r[col[k]] : "");
    const upn = String(get("upn") || "").trim();
    let email = String(get("email") || "").trim();
    if (!email && upn.includes("@")) email = upn;
    let name = String(get("name") || "").trim();
    if (!name && (col.firstName || col.lastName)) name = `${get("firstName")} ${get("lastName")}`.trim();
    const id = upn || email || name;
    if (!id) continue;

    // enabled
    let enabled = null, statusRaw = "";
    if (col.enabled) {
      statusRaw = String(get("enabled") || "").trim();
      const low = statusRaw.toLowerCase();
      if (source === "okta" || /^(active|suspended|deprovisioned|provisioned|staged|recovery|locked_out|password_expired)$/.test(low)) {
        if (["active", "provisioned", "staged", "recovery", "locked_out", "password_expired"].includes(low)) enabled = true;
        else if (["suspended", "deprovisioned", "deactivated"].includes(low)) enabled = false;
        else enabled = parseBool(low);
      } else if (/^(archived|blocked|suspended|disabled|deleted|deprovisioned)$/.test(low)) enabled = false;
      else enabled = parseBool(low);
    }
    if (enabled == null && col.disabled) { const d = parseBool(get("disabled")); if (d != null) enabled = !d; }
    if (col.uac) {
      const uac = parseInt(get("uac"), 10);
      if (Number.isFinite(uac)) enabled = (uac & 0x2) === 0;
    }
    if (enabled != null) bump("enabled");

    // type
    let type = "member", typeSource = "default";
    const ut = String(get("userType") || "").trim().toLowerCase();
    if (ut) {
      typeSource = "column";
      if (/guest|external|b2b|partner/.test(ut)) type = "guest";
      else if (/service|shared|resource|room|equipment|mailbox|system|bot|application/.test(ut)) type = "service";
      else type = "member";
      bump("type");
    }
    if (type === "member" && /#ext#/i.test(upn)) { type = "guest"; typeSource = "upn"; }
    const serviceHeuristic = type === "member" && looksLikeServiceAccount({ id, email, name, orgUnit: get("orgUnit") });
    if (serviceHeuristic) { type = "service"; typeSource = "heuristic"; }

    // admin
    let adminRoles = [];
    if (col.roles) adminRoles.push(...adminFromRoles(splitList(get("roles")), source === "ad" ? "ad" : "roles"));
    if (col.memberOf) adminRoles.push(...adminFromRoles(splitList(get("memberOf")), source === "ad" ? "ad" : "groups"));
    if (col.adminFlag) {
      const v = String(get("adminFlag") || "").trim();
      const b = parseBool(v);
      if (b === true) adminRoles.push(normHeader(col.adminFlag) === "admincount" ? "adminCount=1" : (col.adminFlag));
      else if (b == null && v && !/^(none|no|false|0|-|user|member|notadmin|not admin)$/i.test(v)) adminRoles.push(v); // "Super Admin", "Delegated Admin"
    }
    adminRoles = [...new Set(adminRoles)];
    if (col.roles || col.memberOf || col.adminFlag) bump("admin");

    // mfa
    let mfa = null;
    if (col.mfa) {
      const v = String(get("mfa") || "").trim().toLowerCase();
      if (v) {
        if (/^(enforced|enabled|true|yes|registered|enrolled|capable|1|on)$/.test(v)) mfa = true;
        else if (/^(disabled|false|no|not ?registered|not ?enrolled|none|0|off)$/.test(v)) mfa = false;
        bump("mfa");
      }
    }

    const lastSignIn = parseDate(get("lastSignIn")); if (col.lastSignIn) bump("lastSignIn");
    const created = parseDate(get("created")); if (created != null) bump("created");
    const pwdRaw = String(get("pwdLastSet") || "").trim();
    const pwdLastSet = parseDate(pwdRaw);
    const pwdNeverSet = col.pwdLastSet ? (pwdRaw === "0" || /^(never|not set|n\/a)$/i.test(pwdRaw)) : false;
    if (col.pwdLastSet) bump("pwdLastSet");
    let pwdNeverExpires = col.pwdNeverExpires ? parseBool(get("pwdNeverExpires")) : null;
    if (col.uac) { const uac = parseInt(get("uac"), 10); if (Number.isFinite(uac)) pwdNeverExpires = (uac & 0x10000) !== 0; }
    if (pwdNeverExpires != null) bump("pwdNeverExpires");
    const employeeId = String(get("employeeId") || "").trim(); if (employeeId) bump("employeeId");

    users.push({
      id, email, emailKey: normalizeEmail(email || upn, opts), name, nameKey: normalizeName(name),
      enabled, statusRaw, type, typeSource, serviceHeuristic,
      isAdmin: adminRoles.length > 0, adminRoles, mfa, lastSignIn, created,
      dept: get("dept"), title: get("title"), employeeId, orgUnit: get("orgUnit"),
      pwdLastSet, pwdNeverSet, pwdNeverExpires,
      raw: r,
    });
  }

  const coverage = {
    email: have("email") || have("upn"), name: have("name") || have("firstName"), enabled: have("enabled") || have("disabled") || have("uac"),
    type: have("userType"), admin: have("roles") || have("memberOf") || have("adminFlag"), mfa: have("mfa"),
    lastSignIn: have("lastSignIn"), created: have("created"), employeeId: have("employeeId"), dept: have("dept"), title: have("title"),
    pwdLastSet: have("pwdLastSet"), pwdNeverExpires: have("pwdNeverExpires") || have("uac"),
  };
  if (!users.length) warnings.push("The directory export has no user rows.");
  if (!coverage.enabled) warnings.push("No enabled/status column: every account is treated as enabled.");
  if (!coverage.lastSignIn) warnings.push("No last sign-in column: stale-account checks are skipped.");
  if (!coverage.admin) warnings.push("No roles/admin column: privileged-account checks are skipped.");
  if (!coverage.mfa) warnings.push("No MFA column: MFA checks are skipped.");
  return { source, users, coverage, populated, columns: col, warnings, rowCount: rows.length, format: isJson ? "json" : "csv" };
}

// ---------------------------------------------------------------------------
// Matching: employee id > normalised email > fuzzy name (flagged)
// ---------------------------------------------------------------------------
export function reconcile(hr, dir, opts = {}) {
  const fuzzyMax = opts.fuzzyMax == null ? 2 : opts.fuzzyMax;
  const byId = new Map(), byEmail = new Map();
  for (const e of hr.employees) {
    if (e.employeeId) { const k = e.employeeId.toLowerCase(); if (!byId.has(k)) byId.set(k, e); }
    if (e.emailKey && e.emailKey.includes("@")) { if (!byEmail.has(e.emailKey)) byEmail.set(e.emailKey, e); }
  }
  const rows = [];
  const matchedEmp = new Map(); // employee -> rows
  const unmatchedAccounts = [];
  for (const a of dir.users) {
    let emp = null, method = null;
    if (a.employeeId && byId.has(a.employeeId.toLowerCase())) { emp = byId.get(a.employeeId.toLowerCase()); method = "employeeId"; }
    else if (a.emailKey && byEmail.has(a.emailKey)) { emp = byEmail.get(a.emailKey); method = "email"; }
    const row = { key: a.id, account: a, employee: emp, matchMethod: method, matchDistance: emp ? 0 : null, needsConfirmation: false, findings: [], maxSeverity: null, disposition: "Keep" };
    rows.push(row);
    if (emp) { if (!matchedEmp.has(emp)) matchedEmp.set(emp, []); matchedEmp.get(emp).push(row); }
    else unmatchedAccounts.push(row);
  }
  // Fuzzy pass: block candidates by surname and by first name to keep it O(n) in practice.
  const unmatchedEmps = hr.employees.filter((e) => !matchedEmp.has(e) && e.nameKey);
  const block = new Map();
  for (const e of unmatchedEmps) {
    for (const tok of new Set(e.nameKey.split(" "))) {
      if (tok.length < 2) continue;
      const k = tok.slice(0, 3);
      if (!block.has(k)) block.set(k, []);
      block.get(k).push(e);
    }
  }
  const fuzzyTaken = new Set();
  for (const row of unmatchedAccounts) {
    const nk = row.account.nameKey;
    if (!nk || nk.length < 4 || row.account.type === "service") continue;
    let best = null, bestD = fuzzyMax + 1, ties = 0;
    const cands = new Set();
    for (const tok of new Set(nk.split(" "))) { const list = block.get(tok.slice(0, 3)); if (list) list.forEach((e) => cands.add(e)); }
    for (const e of cands) {
      if (fuzzyTaken.has(e)) continue;
      const d = levenshtein(nk, e.nameKey, fuzzyMax);
      if (d < bestD) { bestD = d; best = e; ties = 0; }
      else if (d === bestD && best) ties++;
    }
    if (best && bestD <= fuzzyMax && ties === 0) {
      row.employee = best; row.matchMethod = "fuzzy"; row.matchDistance = bestD; row.needsConfirmation = true;
      fuzzyTaken.add(best);
      if (!matchedEmp.has(best)) matchedEmp.set(best, []);
      matchedEmp.get(best).push(row);
    }
  }
  const unmatchedEmployees = hr.employees.filter((e) => !matchedEmp.has(e));
  return { rows, matchedEmp, unmatchedEmployees };
}

// ---------------------------------------------------------------------------
// Finding catalogue (control references + default actions)
// ---------------------------------------------------------------------------
export const FINDING_TYPES = {
  leaver_enabled: { title: "Leaver still enabled", severity: "critical",
    controls: ["ISO 27001 A.5.18", "NIST 800-53 AC-2(3)", "CIS v8 6.2", "SOX ITGC: user access review", "ATT&CK T1078"],
    action: "Disable the account now, revoke sessions and tokens, then confirm the offboarding ticket. Investigate any sign-in after the termination date." },
  activity_after_termination: { title: "Account created or used after termination", severity: "critical",
    controls: ["ISO 27001 A.5.18", "NIST 800-53 AC-2(3)", "CIS v8 6.2", "SOX ITGC: user access review", "ATT&CK T1078"],
    action: "Treat as a potential incident: pull sign-in logs for the account, confirm with HR whether this is a rehire, and disable until confirmed." },
  admin_not_on_roster: { title: "Privileged account not tied to an active employee", severity: "critical",
    controls: ["ISO 27001 A.8.2", "NIST 800-53 AC-2(7)", "CIS v8 5.4", "SOX ITGC: privileged access", "ATT&CK T1078"],
    action: "Identify an accountable owner or disable. Privileged accounts without a named, employed owner fail the review." },
  admin_no_mfa: { title: "Admin without MFA", severity: "critical",
    controls: ["ISO 27001 A.8.5", "NIST 800-53 IA-2(1)", "CIS v8 6.5", "SOX ITGC: privileged access"],
    action: "Enforce MFA for the account before the next sign-in (conditional access or per-user MFA). Confirm registration, not only the policy." },
  orphan_enabled: { title: "Enabled account not on the HR roster", severity: "high",
    controls: ["ISO 27001 A.5.18", "NIST 800-53 AC-2", "CIS v8 5.1", "SOX ITGC: user access review"],
    action: "Find the owner. If no employee or approved contractor claims it, disable it and record the decision." },
  stale_account: { title: "Stale account", severity: "medium",
    controls: ["ISO 27001 A.5.18", "NIST 800-53 AC-2(3)", "CIS v8 5.3"],
    action: "Disable accounts with no sign-in inside the dormancy window; re-enable on request with manager approval." },
  guest_admin: { title: "Guest account with admin roles", severity: "high",
    controls: ["ISO 27001 A.8.2", "NIST 800-53 AC-6", "CIS v8 5.4"],
    action: "Remove the role; external identities should not hold tenant-wide privileges. Use a managed account for that work." },
  guest_stale: { title: "Guest account past its review window", severity: "medium",
    controls: ["ISO 27001 A.5.18", "NIST 800-53 AC-2", "CIS v8 5.3"],
    action: "Ask the sponsor to re-approve or remove the guest. Set an expiry policy for external identities." },
  admin_count_excessive: { title: "Too many privileged accounts", severity: "medium",
    controls: ["ISO 27001 A.8.2", "NIST 800-53 AC-6(5)", "CIS v8 5.4"],
    action: "Reduce standing admins to the few who need them; move the rest to just-in-time elevation or scoped roles." },
  duplicate_identity: { title: "Duplicate identity", severity: "low",
    controls: ["ISO 27001 A.5.16", "NIST 800-53 AC-2", "CIS v8 5.1"],
    action: "One person, one account. Keep the primary, disable the duplicate, or document why two are needed." },
  password_never_expires: { title: "Password never expires", severity: "medium",
    controls: ["ISO 27001 A.5.17", "NIST 800-53 IA-5", "CIS v8 5.2"],
    action: "Clear the flag unless the account is a documented service account with a managed credential." },
  password_old: { title: "Password not changed in over a year", severity: "medium",
    controls: ["ISO 27001 A.5.17", "NIST 800-53 IA-5", "CIS v8 5.2"],
    action: "Rotate the credential, or move the account to passwordless or a managed service identity." },
  service_account: { title: "Service-like account (naming heuristic)", severity: "info",
    controls: ["ISO 27001 A.5.16", "NIST 800-53 AC-2", "CIS v8 5.1"],
    action: "Confirm this is a service or shared account, record its owner, and exclude it from roster matching. The label is a naming guess, not a fact." },
  fuzzy_match: { title: "Matched by name only", severity: "info",
    controls: ["ISO 27001 A.5.16", "SOX ITGC: user access review"],
    action: "Confirm or reject the match. Nothing is merged until a reviewer confirms." },
  onboarding_gap: { title: "Active employee without a directory account", severity: "info",
    controls: ["ISO 27001 A.5.16", "NIST 800-53 AC-2", "CIS v8 6.1"],
    action: "Expected for pre-start hires or non-IT roles. Otherwise, check the joiner process or the roster email." },
  admin_mfa_unknown: { title: "MFA status missing for admins", severity: "low",
    controls: ["NIST 800-53 IA-2(1)", "CIS v8 6.5"],
    action: "Export MFA registration (authentication methods report) and re-run the review." },
};

export const DEFAULT_OPTIONS = {
  graceDays: 1, staleDays: 90, guestDays: 180, adminMaxCount: 5, adminMaxPct: 5, pwdAgeDays: 365, aliasDomains: [], fuzzyMax: 2,
};

const fmtDate = (t) => (t == null ? "never" : new Date(t).toISOString().slice(0, 10));
const daysAgo = (t, now) => Math.floor((now - t) / DAY);

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------
export function analyze(hr, dir, options = {}) {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const now = opts.now || Date.now();
  const rec = reconcile(hr, dir, opts);
  const findings = [];
  const cov = dir.coverage;
  const acctRef = (a) => ({ id: a.id, email: a.email, name: a.name });
  const empRef = (e) => (e ? { employeeId: e.employeeId, name: e.name, email: e.email, status: e.status, endDate: fmtDate(e.endDate), dept: e.dept } : null);

  function add(row, type, over = {}) {
    const def = FINDING_TYPES[type];
    const f = {
      id: `${type}:${row ? row.key : "aggregate"}`,
      type, title: def.title, severity: over.severity || def.severity,
      confidence: over.confidence || "high",
      account: row ? acctRef(row.account) : null,
      employee: row ? empRef(row.employee) : null,
      matchMethod: row ? row.matchMethod : null,
      explanation: over.explanation || "",
      evidence: over.evidence || [],
      action: over.action || def.action,
      controls: def.controls,
    };
    findings.push(f);
    if (row) row.findings.push(type);
    return f;
  }

  const isOn = (a) => a.enabled !== false;
  const enabledConf = (a, base = "high") => (a.enabled == null ? (base === "high" ? "medium" : "low") : base);
  const matchConf = (row, base) => (row.matchMethod === "fuzzy" ? "low" : enabledConf(row.account, base));
  const terminated = (e) => e && (e.status === "terminated" || (e.endDate != null && now - e.endDate >= opts.graceDays * DAY));

  let adminCount = 0, enabledMembers = 0, adminsNoMfaKnown = 0;
  for (const row of rec.rows) {
    const a = row.account, e = row.employee;
    if (isOn(a) && a.type === "member") enabledMembers++;
    if (isOn(a) && a.isAdmin) adminCount++;

    const left = terminated(e);
    const leftEvidence = e ? [
      { label: "HR status", value: e.statusRaw || e.status },
      { label: "HR end date", value: fmtDate(e.endDate) },
      { label: "Account enabled", value: a.enabled == null ? "unknown (no column)" : String(a.enabled) },
      { label: "Last sign-in", value: fmtDate(a.lastSignIn) },
      { label: "Matched by", value: row.matchMethod },
    ] : [];

    // 1. Leaver / admin-leaver / admin orphan
    if (e && left && isOn(a)) {
      if (a.isAdmin) {
        add(row, "admin_not_on_roster", { confidence: matchConf(row, "high"),
          explanation: `${a.id} holds ${a.adminRoles.join(", ")} and is matched to ${e.name || e.employeeId}, who HR lists as ${e.status}${e.endDate != null ? ` (end date ${fmtDate(e.endDate)})` : ""}. The account is still enabled.`,
          evidence: [...leftEvidence, { label: "Admin roles", value: a.adminRoles.join("; ") }] });
      } else {
        add(row, "leaver_enabled", { confidence: matchConf(row, "high"),
          explanation: `HR lists ${e.name || e.employeeId} as ${e.status}${e.endDate != null ? ` with an end date of ${fmtDate(e.endDate)} (${daysAgo(e.endDate, now)} days ago)` : ""}, but ${a.id} is still enabled.${a.enabled == null ? " The export has no enabled column, so the account is assumed active." : ""}${row.matchMethod === "fuzzy" ? " The match is by name only; confirm it first." : ""}`,
          evidence: leftEvidence });
      }
    }
    // 2. Created or used after termination (independent of current enabled state)
    if (e && e.endDate != null && left) {
      const ev = [];
      if (a.created != null && a.created > e.endDate) ev.push({ label: "Account created", value: `${fmtDate(a.created)} (${Math.floor((a.created - e.endDate) / DAY)} days after end date)` });
      if (a.lastSignIn != null && a.lastSignIn - e.endDate >= opts.graceDays * DAY) ev.push({ label: "Last sign-in", value: `${fmtDate(a.lastSignIn)} (${Math.floor((a.lastSignIn - e.endDate) / DAY)} days after end date)` });
      if (ev.length) {
        add(row, "activity_after_termination", { confidence: row.matchMethod === "fuzzy" ? "low" : "high",
          explanation: `HR end date for ${e.name || e.employeeId} is ${fmtDate(e.endDate)}, yet ${a.id} shows ${ev.map((x) => x.label.toLowerCase()).join(" and ")} after that date. Either a rehire that HR has not recorded, or access that outlived the person.`,
          evidence: [...ev, { label: "HR status", value: e.statusRaw || e.status }, { label: "Account enabled", value: String(a.enabled) }, { label: "Matched by", value: row.matchMethod }] });
      }
    }
    // 3. Orphans (members) and admin orphans
    if (!e && isOn(a)) {
      if (a.isAdmin) {
        add(row, "admin_not_on_roster", { confidence: enabledConf(a),
          explanation: `${a.id} holds ${a.adminRoles.join(", ")} but matches no roster entry by employee id, email or name.${a.serviceHeuristic ? " Its name looks like a service account; it still needs a named owner." : ""}`,
          evidence: [{ label: "Admin roles", value: a.adminRoles.join("; ") }, { label: "Type", value: a.type + (a.typeSource === "heuristic" ? " (heuristic)" : "") }, { label: "Last sign-in", value: fmtDate(a.lastSignIn) }, { label: "Created", value: fmtDate(a.created) }] });
      } else if (a.type === "member") {
        add(row, "orphan_enabled", { confidence: enabledConf(a),
          explanation: `${a.id} is enabled but no roster row matches it by employee id, email or name. Contractors missing from HR, forgotten test accounts and leavers purged from HR all look like this.`,
          evidence: [{ label: "Email", value: a.email || "" }, { label: "Department", value: a.dept || "" }, { label: "Title", value: a.title || "" }, { label: "Created", value: fmtDate(a.created) }, { label: "Last sign-in", value: fmtDate(a.lastSignIn) }] });
      } else if (a.type === "service" && a.typeSource === "heuristic") {
        add(row, "service_account", { confidence: "low",
          explanation: `${a.id} is not on the roster and its name matches a service or shared-mailbox pattern. It is excluded from the orphan rule on that guess alone.`,
          evidence: [{ label: "Pattern source", value: "name / email / org unit" }, { label: "Last sign-in", value: fmtDate(a.lastSignIn) }, { label: "Admin roles", value: a.adminRoles.join("; ") || "none" }] });
      }
    }
    // 4. Admin without MFA
    if (isOn(a) && a.isAdmin) {
      if (a.mfa === false) {
        add(row, "admin_no_mfa", { confidence: enabledConf(a),
          explanation: `${a.id} holds ${a.adminRoles.join(", ")} and the export reports MFA as not registered or disabled.`,
          evidence: [{ label: "Admin roles", value: a.adminRoles.join("; ") }, { label: "MFA", value: a.raw[dir.columns.mfa] || "false" }, { label: "Last sign-in", value: fmtDate(a.lastSignIn) }] });
      } else if (a.mfa == null && cov.mfa) adminsNoMfaKnown++;
    }
    // 5. Stale (only when the export carries sign-in data)
    if (cov.lastSignIn && isOn(a) && !left) {
      const never = a.lastSignIn == null;
      const ageDays = never ? null : daysAgo(a.lastSignIn, now);
      const newAccount = never && a.created != null && now - a.created < opts.staleDays * DAY;
      if (!newAccount && (never || ageDays > opts.staleDays)) {
        add(row, "stale_account", { severity: a.isAdmin ? "high" : "medium", confidence: enabledConf(a),
          explanation: never
            ? `${a.id} is enabled and has never signed in${a.created != null ? ` since it was created on ${fmtDate(a.created)}` : ""}.${a.isAdmin ? " It also holds admin roles." : ""}`
            : `${a.id} is enabled but last signed in ${ageDays} days ago (${fmtDate(a.lastSignIn)}), beyond the ${opts.staleDays}-day window.${a.isAdmin ? " It also holds admin roles." : ""}`,
          evidence: [{ label: "Last sign-in", value: fmtDate(a.lastSignIn) }, { label: "Created", value: fmtDate(a.created) }, { label: "Type", value: a.type }, { label: "Admin roles", value: a.adminRoles.join("; ") || "none" }, { label: "Window", value: `${opts.staleDays} days` }] });
      }
    }
    // 6. Guests
    if (a.type === "guest" && isOn(a)) {
      if (a.isAdmin) {
        add(row, "guest_admin", { confidence: enabledConf(a),
          explanation: `${a.id} is a guest (external) identity holding ${a.adminRoles.join(", ")}.`,
          evidence: [{ label: "Admin roles", value: a.adminRoles.join("; ") }, { label: "Created", value: fmtDate(a.created) }, { label: "Last sign-in", value: fmtDate(a.lastSignIn) }] });
      }
      const ref = a.created != null ? a.created : null;
      if (ref != null && now - ref > opts.guestDays * DAY) {
        add(row, "guest_stale", { confidence: enabledConf(a),
          explanation: `Guest ${a.id} was invited ${daysAgo(ref, now)} days ago (${fmtDate(ref)}) and is still enabled, beyond the ${opts.guestDays}-day review window.${a.lastSignIn == null ? " It has never signed in." : ""}`,
          evidence: [{ label: "Created", value: fmtDate(ref) }, { label: "Last sign-in", value: fmtDate(a.lastSignIn) }, { label: "Window", value: `${opts.guestDays} days` }] });
      }
    }
    // 7. Password hygiene (AD fields)
    if (isOn(a) && a.pwdNeverExpires === true) {
      add(row, "password_never_expires", { confidence: "high",
        explanation: `${a.id} has the password-never-expires flag set${a.type === "service" ? " (service-like account; acceptable only with a managed credential)" : ""}.`,
        evidence: [{ label: "Password last set", value: a.pwdNeverSet ? "never" : fmtDate(a.pwdLastSet) }, { label: "Type", value: a.type + (a.typeSource === "heuristic" ? " (heuristic)" : "") }, { label: "Admin roles", value: a.adminRoles.join("; ") || "none" }] });
    }
    if (isOn(a) && cov.pwdLastSet && (a.pwdNeverSet || (a.pwdLastSet != null && daysAgo(a.pwdLastSet, now) >= opts.pwdAgeDays))) {
      add(row, "password_old", { confidence: "high",
        explanation: a.pwdNeverSet ? `${a.id} has never set a password (pwdLastSet = 0) but the account is enabled.` : `${a.id} last changed its password ${daysAgo(a.pwdLastSet, now)} days ago (${fmtDate(a.pwdLastSet)}).`,
        evidence: [{ label: "Password last set", value: a.pwdNeverSet ? "never" : fmtDate(a.pwdLastSet) }, { label: "Threshold", value: `${opts.pwdAgeDays} days` }, { label: "Admin roles", value: a.adminRoles.join("; ") || "none" }] });
    }
    // 8. Fuzzy match (needs confirmation)
    if (row.matchMethod === "fuzzy") {
      add(row, "fuzzy_match", { confidence: "low",
        explanation: `${a.id} ("${a.name}") matched ${e.name} (${e.employeeId || e.email || "no id"}) by name with edit distance ${row.matchDistance}. No employee id or email tied them together.`,
        evidence: [{ label: "Directory name", value: a.name }, { label: "HR name", value: e.name }, { label: "Edit distance", value: String(row.matchDistance) }, { label: "HR status", value: e.status }] });
    }
  }

  // 9. Duplicates: two accounts tied to one employee (exact methods only), or identical normalised emails.
  for (const [emp, rows] of rec.matchedEmp) {
    const exact = rows.filter((r) => r.matchMethod !== "fuzzy");
    if (exact.length > 1) {
      const enabledN = exact.filter((r) => isOn(r.account)).length;
      for (const r of exact) {
        add(r, "duplicate_identity", { severity: enabledN > 1 ? "medium" : "low", confidence: "high",
          explanation: `${exact.length} directory accounts resolve to ${emp.name || emp.employeeId}: ${exact.map((x) => x.account.id).join(", ")}. ${enabledN} enabled.`,
          evidence: [{ label: "Accounts", value: exact.map((x) => x.account.id).join("; ") }, { label: "Enabled", value: String(enabledN) }, { label: "HR status", value: emp.status }] });
      }
    }
  }
  const emailGroups = new Map();
  for (const r of rec.rows) if (!r.employee && r.account.emailKey && r.account.emailKey.includes("@")) {
    if (!emailGroups.has(r.account.emailKey)) emailGroups.set(r.account.emailKey, []);
    emailGroups.get(r.account.emailKey).push(r);
  }
  for (const [k, rows] of emailGroups) if (rows.length > 1) {
    const enabledN = rows.filter((r) => isOn(r.account)).length;
    for (const r of rows) if (!r.findings.includes("duplicate_identity")) add(r, "duplicate_identity", { severity: enabledN > 1 ? "medium" : "low",
      explanation: `${rows.length} accounts share the normalised email ${k}: ${rows.map((x) => x.account.id).join(", ")}.`,
      evidence: [{ label: "Accounts", value: rows.map((x) => x.account.id).join("; ") }, { label: "Enabled", value: String(enabledN) }] });
  }

  // 10. Aggregates
  if (cov.admin && adminCount > 0) {
    const pct = enabledMembers ? (adminCount / enabledMembers) * 100 : 0;
    const overCount = adminCount > opts.adminMaxCount;
    const overPct = enabledMembers >= 20 && pct > opts.adminMaxPct;
    if (overCount || overPct) {
      add(null, "admin_count_excessive", {
        explanation: `${adminCount} enabled accounts hold admin roles across ${enabledMembers} enabled member accounts (${pct.toFixed(1)}%). Threshold: ${opts.adminMaxCount} accounts or ${opts.adminMaxPct}% of users.`,
        evidence: [{ label: "Admin accounts", value: String(adminCount) }, { label: "Enabled members", value: String(enabledMembers) }, { label: "Share", value: pct.toFixed(1) + "%" }] });
    }
  }
  if (adminsNoMfaKnown > 0) {
    add(null, "admin_mfa_unknown", { confidence: "high",
      explanation: `${adminsNoMfaKnown} admin account(s) have an empty MFA value in the export, so their MFA state could not be checked.`,
      evidence: [{ label: "Admins with unknown MFA", value: String(adminsNoMfaKnown) }] });
  }
  if (!cov.mfa && adminCount > 0) {
    add(null, "admin_mfa_unknown", { confidence: "high",
      explanation: `The export has no MFA column; ${adminCount} admin account(s) could not be checked for MFA.`,
      evidence: [{ label: "Admin accounts", value: String(adminCount) }] });
  }
  // 11. Onboarding gaps
  const hrNoAccount = [];
  for (const e of rec.unmatchedEmployees) {
    if (e.status !== "active") continue;
    if (e.startDate != null && e.startDate > now) continue;
    hrNoAccount.push(e);
  }
  if (hrNoAccount.length) {
    add(null, "onboarding_gap", { confidence: hr.coverage.email || hr.coverage.employeeId ? "medium" : "low",
      explanation: `${hrNoAccount.length} active roster employee(s) have no directory account by employee id, email or name. Expected for staff without IT access; otherwise a joiner or data-quality gap.`,
      evidence: hrNoAccount.slice(0, 50).map((e) => ({ label: e.employeeId || e.email || "employee", value: `${e.name}${e.dept ? " (" + e.dept + ")" : ""}` })) });
  }

  // Disposition per row
  for (const row of rec.rows) {
    const t = new Set(row.findings);
    let d = "Keep";
    if (t.has("leaver_enabled") || (t.has("admin_not_on_roster") && row.employee)) d = "Disable";
    else if (t.has("activity_after_termination") && isOn(row.account)) d = "Disable";
    else if (t.has("admin_not_on_roster") || t.has("orphan_enabled") || t.has("admin_no_mfa") || t.has("guest_admin") || t.has("stale_account")
      || t.has("guest_stale") || t.has("password_never_expires") || t.has("password_old") || t.has("activity_after_termination")
      || (t.has("duplicate_identity") && isOn(row.account))) d = "Investigate";
    else if (row.needsConfirmation || t.has("service_account")) d = "Confirm match";
    if (row.needsConfirmation && d === "Keep") d = "Confirm match";
    row.disposition = d;
    row.maxSeverity = row.findings.reduce((m, ty) => {
      const f = findings.find((x) => x.type === ty && x.account && x.account.id === row.key);
      const s = f ? f.severity : FINDING_TYPES[ty].severity;
      return !m || SEVERITY_RANK[s] > SEVERITY_RANK[m] ? s : m;
    }, null);
  }

  findings.sort((x, y) => SEVERITY_RANK[y.severity] - SEVERITY_RANK[x.severity] || x.type.localeCompare(y.type) || String(x.account ? x.account.id : "").localeCompare(String(y.account ? y.account.id : "")));

  const bySev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) bySev[f.severity]++;
  const rows = rec.rows;
  const kpis = {
    accounts: rows.length,
    enabled: rows.filter((r) => isOn(r.account)).length,
    disabled: rows.filter((r) => r.account.enabled === false).length,
    matched: rows.filter((r) => r.employee && r.matchMethod !== "fuzzy").length,
    fuzzy: rows.filter((r) => r.matchMethod === "fuzzy").length,
    orphans: rows.filter((r) => r.findings.includes("orphan_enabled")).length,
    leaversEnabled: rows.filter((r) => r.findings.includes("leaver_enabled") || (r.findings.includes("admin_not_on_roster") && r.employee)).length,
    admins: adminCount,
    adminsNoMfa: rows.filter((r) => r.findings.includes("admin_no_mfa")).length,
    stale: rows.filter((r) => r.findings.includes("stale_account")).length,
    guests: rows.filter((r) => r.account.type === "guest" && isOn(r.account)).length,
    serviceLike: rows.filter((r) => r.account.type === "service").length,
    hrActive: hr.employees.filter((e) => e.status === "active").length,
    hrTerminated: hr.employees.filter((e) => e.status === "terminated").length,
    hrNoAccount: hrNoAccount.length,
    dispositions: { Keep: 0, Disable: 0, Investigate: 0, "Confirm match": 0 },
    bySeverity: bySev,
  };
  for (const r of rows) kpis.dispositions[r.disposition]++;

  return { findings, rows, kpis, hrNoAccount, source: dir.source, coverage: { directory: dir.coverage, hr: hr.coverage }, warnings: [...hr.warnings, ...dir.warnings], options: { ...opts, now }, generatedAt: now };
}

// ---------------------------------------------------------------------------
// Review packet exports
// ---------------------------------------------------------------------------
export const DECISIONS = ["Keep", "Disable", "Investigate", "Match confirmed", "Not a match"];

const q = (s) => `"${String(s == null ? "" : s).replace(/"/g, '""')}"`;

export function toReviewCSV(result, decisions = {}) {
  const head = ["account", "name", "email", "type", "enabled", "admin_roles", "mfa", "last_sign_in", "created", "employee_id", "hr_name", "hr_status", "hr_end_date", "match_method", "needs_confirmation", "findings", "max_severity", "suggested_disposition", "reviewer_decision", "reviewer_note", "decided_at"];
  const lines = [head.join(",")];
  for (const r of result.rows) {
    const a = r.account, e = r.employee, d = decisions[r.key] || {};
    lines.push([q(a.id), q(a.name), q(a.email), q(a.type + (a.typeSource === "heuristic" ? " (heuristic)" : "")), q(a.enabled == null ? "unknown" : a.enabled), q(a.adminRoles.join("; ")),
      q(a.mfa == null ? "unknown" : a.mfa), q(fmtDate(a.lastSignIn)), q(fmtDate(a.created)), q(e ? e.employeeId : a.employeeId), q(e ? e.name : ""), q(e ? e.status : "not on roster"),
      q(e ? fmtDate(e.endDate) : ""), q(r.matchMethod || "none"), q(r.needsConfirmation), q(r.findings.join("; ")), q(r.maxSeverity || ""), q(r.disposition),
      q(d.decision || ""), q(d.note || ""), q(d.at ? new Date(d.at).toISOString() : "")].join(","));
  }
  return lines.join("\n") + "\n";
}

export function toFindingsCSV(result) {
  const head = ["id", "severity", "confidence", "type", "title", "account", "employee_id", "hr_status", "match_method", "explanation", "recommended_action", "controls"];
  const lines = [head.join(",")];
  for (const f of result.findings) lines.push([q(f.id), q(f.severity), q(f.confidence), q(f.type), q(f.title), q(f.account ? f.account.id : ""), q(f.employee ? f.employee.employeeId : ""), q(f.employee ? f.employee.status : ""), q(f.matchMethod || ""), q(f.explanation), q(f.action), q(f.controls.join("; "))].join(","));
  return lines.join("\n") + "\n";
}

export function summarizeDecisions(result, decisions = {}) {
  const counts = { Keep: 0, Disable: 0, Investigate: 0, "Match confirmed": 0, "Not a match": 0, undecided: 0 };
  for (const r of result.rows) { const d = decisions[r.key]; if (d && d.decision && counts[d.decision] != null) counts[d.decision]++; else counts.undecided++; }
  return counts;
}

export function attestationText(result, decisions, meta = {}) {
  const c = summarizeDecisions(result, decisions);
  const k = result.kpis, when = meta.date || new Date(result.generatedAt).toISOString().slice(0, 10);
  const lines = [
    "USER ACCESS REVIEW ATTESTATION",
    "",
    `Reviewer: ${meta.reviewer || "(not provided)"}`,
    `Review date: ${when}`,
    `Scope: ${meta.scope || result.source + " directory export reconciled against HR roster"}`,
    `Dataset hash: ${meta.hash || "(not computed)"}`,
    `Period parameters: leaver grace ${result.options.graceDays} day(s), dormancy ${result.options.staleDays} days, guest window ${result.options.guestDays} days, password age ${result.options.pwdAgeDays} days`,
    "",
    "POPULATION",
    `Directory accounts reviewed: ${k.accounts} (${k.enabled} enabled, ${k.disabled} disabled)`,
    `Matched to roster by employee id or email: ${k.matched}`,
    `Matched by name only (confirmation required): ${k.fuzzy}`,
    `Enabled accounts not on roster: ${k.orphans}`,
    `Privileged accounts: ${k.admins} (${k.adminsNoMfa} without MFA)`,
    `Roster: ${k.hrActive} active, ${k.hrTerminated} terminated, ${k.hrNoAccount} active without a directory account`,
    "",
    "FINDINGS",
    `Critical ${k.bySeverity.critical}, High ${k.bySeverity.high}, Medium ${k.bySeverity.medium}, Low ${k.bySeverity.low}, Info ${k.bySeverity.info}`,
    "",
    "REVIEWER DECISIONS",
    `Keep ${c.Keep}, Disable ${c.Disable}, Investigate ${c.Investigate}, Match confirmed ${c["Match confirmed"]}, Not a match ${c["Not a match"]}, Undecided ${c.undecided}`,
    "",
    c.undecided === 0
      ? "I confirm that every account listed in the attached reconciliation was reviewed and that the decisions recorded reflect my determination of whether the access remains appropriate."
      : `This review is incomplete: ${c.undecided} account(s) have no recorded decision.`,
    "",
    "Controls: ISO/IEC 27001:2022 A.5.18; NIST SP 800-53 AC-2; CIS Controls v8 5.1, 5.3, 5.4, 6.2, 6.5; SOX ITGC logical access (periodic user access review).",
    "Method: deterministic reconciliation in the browser; no data left the reviewer's machine. Matching by employee id, then normalised email, then flagged name similarity.",
  ];
  return lines.join("\n");
}

export function toReviewJSON(result, decisions = {}, meta = {}) {
  return {
    packet: "darknode-access-review", version: 1,
    generatedAt: new Date(result.generatedAt).toISOString(),
    reviewer: meta.reviewer || null, reviewDate: meta.date || null, datasetHash: meta.hash || null,
    source: result.source, options: result.options, coverage: result.coverage, warnings: result.warnings,
    kpis: result.kpis, decisionSummary: summarizeDecisions(result, decisions),
    findings: result.findings,
    accounts: result.rows.map((r) => ({
      account: r.account.id, name: r.account.name, email: r.account.email, type: r.account.type, typeSource: r.account.typeSource,
      enabled: r.account.enabled, adminRoles: r.account.adminRoles, mfa: r.account.mfa,
      lastSignIn: r.account.lastSignIn == null ? null : new Date(r.account.lastSignIn).toISOString(),
      created: r.account.created == null ? null : new Date(r.account.created).toISOString(),
      employee: r.employee ? { employeeId: r.employee.employeeId, name: r.employee.name, email: r.employee.email, status: r.employee.status, endDate: r.employee.endDate == null ? null : new Date(r.employee.endDate).toISOString() } : null,
      matchMethod: r.matchMethod, needsConfirmation: r.needsConfirmation, findings: r.findings, maxSeverity: r.maxSeverity,
      suggestedDisposition: r.disposition, decision: (decisions[r.key] || {}).decision || null, note: (decisions[r.key] || {}).note || "",
      decidedAt: (decisions[r.key] || {}).at ? new Date(decisions[r.key].at).toISOString() : null,
    })),
    hrWithoutAccount: result.hrNoAccount.map((e) => ({ employeeId: e.employeeId, name: e.name, email: e.email, dept: e.dept, startDate: e.startDate == null ? null : new Date(e.startDate).toISOString() })),
    attestation: attestationText(result, decisions, meta),
  };
}

// ---------------------------------------------------------------------------
// Synthetic example (clearly labelled in the UI). Dates are relative to `now`.
// ---------------------------------------------------------------------------
export function exampleData(now = Date.now()) {
  const d = (days) => new Date(now - days * DAY).toISOString().slice(0, 10);
  const dt = (days) => new Date(now - days * DAY).toISOString();
  const hr = [
    "Employee ID,Full Name,Work Email,Department,Job Title,Manager,Employment Status,Start Date,Termination Date",
    `E1001,Priya Natarajan,priya.natarajan@example.com,Engineering,Staff Engineer,Dana Kowalski,Active,${d(900)},`,
    `E1002,Dana Kowalski,dana.kowalski@example.com,Engineering,VP Engineering,CEO,Active,${d(1500)},`,
    `E1003,Marcus Reed,marcus.reed@example.com,Finance,Controller,CFO,Terminated,${d(1200)},${d(45)}`,
    `E1004,Yuki Tanaka,yuki.tanaka@example.com,IT,Systems Administrator,Dana Kowalski,Terminated,${d(800)},${d(10)}`,
    `E1005,Sofia Alvarez,sofia.alvarez@example.com,Sales,Account Executive,Lee Chen,Active,${d(400)},`,
    `E1006,Lee Chen,lee.chen@example.com,Sales,Sales Director,CEO,Active,${d(2000)},`,
    `E1007,Omar Haddad,omar.haddad@example.com,Finance,Analyst,Marcus Reed,Leave,${d(600)},`,
    `E1008,Ingrid Larsen,ingrid.larsen@example.com,Marketing,Content Lead,Lee Chen,Active,${d(5)},`,
    `E1009,Tomás Ferreira,tomas.ferreira@example.com,Engineering,Backend Engineer,Dana Kowalski,Active,${d(300)},`,
    `E1010,Grace Okafor,grace.okafor@example.com,People,HR Business Partner,CEO,Active,${d(700)},`,
    `E1011,Noah Williams,noah.williams@example.com,Engineering,Intern,Priya Natarajan,Terminated,${d(120)},${d(1)}`,
    `E1012,Hannah Schmidt,hannah.schmidt@example.com,Legal,Counsel,CEO,Active,${d(-14)},`,
    `E1013,Ravi Menon,ravi.menon@example.com,Finance,Senior Analyst,CFO,Active,${d(500)},`,
  ].join("\n");
  const dir = [
    "userPrincipalName,displayName,accountEnabled,userType,createdDateTime,lastSignInDateTime,department,jobTitle,employeeId,assignedRoles,Per-user MFA status",
    `priya.natarajan@example.com,Priya Natarajan,TRUE,Member,${dt(900)},${dt(1)},Engineering,Staff Engineer,E1001,,Enforced`,
    `dana.kowalski@example.com,Dana Kowalski,TRUE,Member,${dt(1500)},${dt(2)},Engineering,VP Engineering,E1002,Global Administrator,Enforced`,
    `marcus.reed@example.com,Marcus Reed,TRUE,Member,${dt(1200)},${dt(30)},Finance,Controller,E1003,,Enabled`,
    `yuki.tanaka@example.com,Yuki Tanaka,TRUE,Member,${dt(800)},${dt(3)},IT,Systems Administrator,E1004,Global Administrator;Exchange Administrator,Enforced`,
    `sofia.alvarez@example.com,Sofia Alvarez,TRUE,Member,${dt(400)},${dt(140)},Sales,Account Executive,E1005,,Enforced`,
    `lee.chen@example.com,Lee Chen,TRUE,Member,${dt(2000)},${dt(1)},Sales,Sales Director,E1006,User Administrator,Disabled`,
    `omar.haddad@example.com,Omar Haddad,TRUE,Member,${dt(600)},${dt(95)},Finance,Analyst,E1007,,Enforced`,
    `tferreira@example.com,Tomas Ferreira,TRUE,Member,${dt(300)},${dt(4)},Engineering,Backend Engineer,,,Enforced`,
    `grace.okafor@example.com,Grace Okafor,TRUE,Member,${dt(700)},${dt(1)},People,HR Business Partner,E1010,,Enforced`,
    `noah.williams@example.com,Noah Williams,TRUE,Member,${dt(120)},${dt(0)},Engineering,Intern,E1011,,Enforced`,
    `jdoe-contractor@example.com,J. Doe,TRUE,Member,${dt(400)},${dt(2)},Engineering,Contractor,,,Enforced`,
    `svc-backup@example.com,svc-backup,TRUE,Member,${dt(1000)},${dt(1)},,,,,`,
    `ext.partner_vendor.io#EXT#@example.onmicrosoft.com,Ext Partner (vendor.io),TRUE,Guest,${dt(400)},${dt(200)},,,,,`,
    `auditor_bigfour.com#EXT#@example.onmicrosoft.com,Auditor (bigfour.com),TRUE,Guest,${dt(30)},${dt(1)},,,,Global Reader,`,
    `oldadmin@example.com,Legacy Admin,TRUE,Member,${dt(2500)},,IT,,,Global Administrator,Disabled`,
    `ravi.menon@example.com,Ravi Menon,FALSE,Member,${dt(500)},${dt(60)},Finance,Senior Analyst,E1013,,Enforced`,
    `ravi.menon2@example.com,Ravi Menon,TRUE,Member,${dt(40)},${dt(1)},Finance,Senior Analyst,E1013,,Enforced`,
  ].join("\n");
  return { hr, dir };
}
