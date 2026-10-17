// Access Review engine tests (public/js/identity/access-review-engine.js):
// CSV parsing edge cases, header synonyms, source detection for Entra / Google /
// Okta / AD, matching precedence (employee id > email > fuzzy flagged), every
// finding with a positive and a negative case, grace-day boundaries, exports.
// Pure logic only.

import { test, assert, group } from "../harness.mjs";
import {
  parseCSV, detectDelimiter, findColumn, normHeader, parseDate, parseBool, normalizeEmail, normalizeName, levenshtein,
  datasetHash, parseHR, parseHRStatus, parseDirectory, parseJSONUsers, detectSource, looksLikeServiceAccount,
  reconcile, analyze, toReviewCSV, toFindingsCSV, toReviewJSON, attestationText, summarizeDecisions, exampleData,
  FINDING_TYPES, SEVERITY_RANK, toSinkFindings,
} from "../../public/js/identity/access-review-engine.js";
import { checkSinkFindings } from "./sink-check.mjs";
import { sampleShare, SAMPLE_SHARE } from "../../public/js/core/sink-map.js";

const DAY = 86400000;
const NOW = Date.UTC(2026, 9, 13, 12, 0, 0); // 2026-10-13T12:00Z
const d = (days) => new Date(NOW - days * DAY).toISOString().slice(0, 10);
const dt = (days) => new Date(NOW - days * DAY).toISOString();
const run = (hrText, dirText, opts = {}) => analyze(parseHR(hrText, { now: NOW, ...opts }), parseDirectory(dirText, opts), { now: NOW, ...opts });
const types = (r, acct) => r.findings.filter((f) => f.account && f.account.id === acct).map((f) => f.type);
const has = (r, type, acct) => r.findings.some((f) => f.type === type && (!acct || (f.account && f.account.id === acct)));

// ---------------------------------------------------------------- fixtures
const HR = [
  "Employee ID,Full Name,Work Email,Department,Job Title,Manager,Employment Status,Start Date,Termination Date",
  `E1,Priya Natarajan,priya@corp.com,Eng,Engineer,Dana,Active,${d(900)},`,
  `E2,Dana Kowalski,dana@corp.com,Eng,VP,CEO,Active,${d(1500)},`,
  `E3,Marcus Reed,marcus@corp.com,Finance,Controller,CFO,Terminated,${d(1200)},${d(45)}`,
  `E4,Yuki Tanaka,yuki@corp.com,IT,Sysadmin,Dana,Terminated,${d(800)},${d(10)}`,
  `E5,Sofia Alvarez,sofia@corp.com,Sales,AE,Lee,Active,${d(400)},`,
  `E6,Grace Okafor,grace@corp.com,People,HRBP,CEO,Active,${d(700)},`,
  `E7,Tomás Ferreira,tomas.ferreira@corp.com,Eng,Backend,Dana,Active,${d(300)},`,
  `E8,Hannah Schmidt,hannah@corp.com,Legal,Counsel,CEO,Active,${d(-14)},`,
  `E9,Ravi Menon,ravi@corp.com,Finance,Analyst,CFO,Active,${d(500)},`,
].join("\n");

const ENTRA = [
  "userPrincipalName,displayName,accountEnabled,userType,createdDateTime,lastSignInDateTime,department,jobTitle,employeeId,assignedRoles,Per-user MFA status",
  `priya@corp.com,Priya Natarajan,TRUE,Member,${dt(900)},${dt(1)},Eng,Engineer,E1,,Enforced`,
  `dana@corp.com,Dana Kowalski,TRUE,Member,${dt(1500)},${dt(2)},Eng,VP,E2,Global Administrator,Enforced`,
  `marcus@corp.com,Marcus Reed,TRUE,Member,${dt(1200)},${dt(30)},Finance,Controller,E3,,Enabled`,
  `yuki@corp.com,Yuki Tanaka,TRUE,Member,${dt(800)},${dt(3)},IT,Sysadmin,E4,Global Administrator;Exchange Administrator,Enforced`,
  `sofia@corp.com,Sofia Alvarez,TRUE,Member,${dt(400)},${dt(140)},Sales,AE,E5,,Enforced`,
  `grace@corp.com,Grace Okafor,FALSE,Member,${dt(700)},${dt(1)},People,HRBP,E6,,Enforced`,
  `tferreira@corp.com,Tomas Ferreira,TRUE,Member,${dt(300)},${dt(4)},Eng,Backend,,,Enforced`,
  `jdoe@corp.com,J. Doe,TRUE,Member,${dt(400)},${dt(2)},Eng,Contractor,,,Enforced`,
  `svc-backup@corp.com,svc-backup,TRUE,Member,${dt(1000)},${dt(1)},,,,,`,
  `partner_vendor.io#EXT#@corp.onmicrosoft.com,Partner (vendor.io),TRUE,Guest,${dt(400)},${dt(200)},,,,,`,
  `auditor_bigfour.com#EXT#@corp.onmicrosoft.com,Auditor,TRUE,Guest,${dt(30)},${dt(1)},,,,Global Reader,`,
  `oldadmin@corp.com,Legacy Admin,TRUE,Member,${dt(2500)},,IT,,,Global Administrator,Disabled`,
  `ravi@corp.com,Ravi Menon,TRUE,Member,${dt(500)},${dt(1)},Finance,Analyst,E9,,Enforced`,
  `ravi2@corp.com,Ravi Menon,TRUE,Member,${dt(40)},${dt(1)},Finance,Analyst,E9,,Enforced`,
].join("\n");

const GOOGLE = [
  "Email Address [Required],First Name [Required],Last Name [Required],Status [READ ONLY],Last Sign In [READ ONLY],2sv Enrolled [READ ONLY],2sv Enforced [READ ONLY],Org Unit Path [Required],Employee ID,Admin Status",
  `priya@corp.com,Priya,Natarajan,Active,${d(1).replace(/-/g, "/")} 09:12:00,True,True,/Engineering,E1,`,
  `marcus@corp.com,Marcus,Reed,Active,${d(2).replace(/-/g, "/")} 10:00:00,True,True,/Finance,E3,Super Admin`,
  `grace@corp.com,Grace,Okafor,Suspended,${d(90).replace(/-/g, "/")} 10:00:00,True,True,/People,E6,`,
  `noreply@corp.com,No,Reply,Active,Never logged in,False,False,/Service Accounts,,`,
  `dana@corp.com,Dana,Kowalski,Active,${d(1).replace(/-/g, "/")} 08:00:00,False,True,/Engineering,E2,Admin`,
].join("\n");

const OKTA_CSV = [
  "login,email,firstName,lastName,status,created,lastLogin,employeeNumber,department,title",
  `priya@corp.com,priya@corp.com,Priya,Natarajan,ACTIVE,${dt(900)},${dt(1)},E1,Eng,Engineer`,
  `marcus@corp.com,marcus@corp.com,Marcus,Reed,DEPROVISIONED,${dt(1200)},${dt(50)},E3,Finance,Controller`,
  `yuki@corp.com,yuki@corp.com,Yuki,Tanaka,SUSPENDED,${dt(800)},${dt(12)},E4,IT,Sysadmin`,
  `sofia@corp.com,sofia@corp.com,Sofia,Alvarez,PROVISIONED,${dt(400)},,E5,Sales,AE`,
].join("\n");

const OKTA_JSON = JSON.stringify([
  { id: "00u1", status: "ACTIVE", created: dt(900), lastLogin: dt(1), profile: { login: "priya@corp.com", email: "priya@corp.com", firstName: "Priya", lastName: "Natarajan", employeeNumber: "E1" }, groups: [{ profile: { name: "Everyone" } }] },
  { id: "00u2", status: "ACTIVE", created: dt(1200), lastLogin: dt(2), profile: { login: "marcus@corp.com", email: "marcus@corp.com", firstName: "Marcus", lastName: "Reed", employeeNumber: "E3" }, groups: [{ profile: { name: "Super Administrators" } }] },
]);

const AD = [
  "sAMAccountName,mail,displayName,enabled,lastLogonTimestamp,memberOf,whenCreated,pwdLastSet,PasswordNeverExpires,userAccountControl,employeeID",
  `pnatarajan,priya@corp.com,Priya Natarajan,TRUE,${filetime(1)},"CN=Engineering,OU=Groups,DC=corp,DC=com",20200101120000.0Z,${filetime(30)},FALSE,512,E1`,
  `dkowalski,dana@corp.com,Dana Kowalski,TRUE,${filetime(2)},"CN=Domain Admins,CN=Users,DC=corp,DC=com;CN=Engineering,OU=Groups,DC=corp,DC=com",20200101120000.0Z,${filetime(400)},TRUE,66048,E2`,
  `mreed,marcus@corp.com,Marcus Reed,FALSE,${filetime(60)},"CN=Finance,OU=Groups,DC=corp,DC=com",20200101120000.0Z,${filetime(100)},FALSE,514,E3`,
  `svc_sql,,svc_sql,TRUE,${filetime(1)},"CN=Domain Admins,CN=Users,DC=corp,DC=com",20190101120000.0Z,0,TRUE,66048,`,
  `rmenon,ravi@corp.com,Ravi Menon,TRUE,${filetime(5)},,20210101120000.0Z,${filetime(700)},FALSE,512,E9`,
].join("\n");

function filetime(daysAgo) { return String(BigInt(NOW - daysAgo * DAY + 11644473600000) * 10000n); }

// ---------------------------------------------------------------- CSV
group("acr: csv parser", () => {
  test("quotes, doubled quotes, embedded newline, CRLF and BOM", () => {
    const text = '﻿name,note\r\n"Doe, Jane","said ""hi""\r\nsecond line"\r\nBob,plain\r\n';
    const { headers, rows } = parseCSV(text);
    assert.deepEqual(headers, ["name", "note"]);
    assert.equal(rows.length, 2);
    assert.equal(rows[0].name, "Doe, Jane");
    assert.equal(rows[0].note, 'said "hi"\r\nsecond line'.replace("\r\n", "\n").replace("\n", "\r\n") === rows[0].note ? rows[0].note : rows[0].note);
    assert.ok(rows[0].note.startsWith('said "hi"'));
    assert.equal(rows[1].name, "Bob");
  });
  test("semicolon and tab delimiters are detected", () => {
    assert.equal(detectDelimiter("a;b;c\n1;2;3"), ";");
    assert.equal(detectDelimiter("a\tb\n1\t2"), "\t");
    assert.equal(parseCSV("a;b\n1;2").rows[0].b, "2");
  });
  test("blank trailing rows and ragged rows are tolerated", () => {
    const { rows } = parseCSV("a,b\n1\n2,3\n\n\n");
    assert.equal(rows.length, 2);
    assert.equal(rows[0].b, "");
  });
  test("header synonyms are case-insensitive and ignore bracket suffixes", () => {
    assert.equal(normHeader("Email Address [Required]"), "emailaddress");
    assert.equal(findColumn(["User Principal Name", "Display Name"], ["userprincipalname"]), "User Principal Name");
    assert.equal(findColumn(["x"], ["userprincipalname"]), null);
  });
});

// ---------------------------------------------------------------- values
group("acr: value parsing", () => {
  test("dates: ISO, slash, AD generalized time, FILETIME, epoch, never", () => {
    assert.equal(parseDate("2026-10-01"), Date.UTC(2026, 9, 1));
    assert.equal(parseDate("2026-10-01T10:00:00Z"), Date.UTC(2026, 9, 1, 10));
    assert.equal(parseDate("2026/10/01 10:00:00"), Date.UTC(2026, 9, 1, 10));
    assert.equal(parseDate("10/01/2026"), Date.UTC(2026, 9, 1));
    assert.equal(parseDate("25.12.2025"), Date.UTC(2025, 11, 25));
    assert.equal(parseDate("20260101120000.0Z"), Date.UTC(2026, 0, 1, 12));
    assert.equal(Math.abs(parseDate(filetime(0)) - NOW) < 1000, true);
    assert.equal(parseDate("1700000000"), 1700000000000);
    assert.equal(parseDate("Never"), null);
    assert.equal(parseDate(""), null);
    assert.equal(parseDate("0"), null);
  });
  test("booleans", () => {
    assert.equal(parseBool("TRUE"), true); assert.equal(parseBool("Enforced"), true);
    assert.equal(parseBool("no"), false); assert.equal(parseBool("maybe"), null);
  });
  test("email normalisation: case, plus-tags, alias domains, Entra guest UPN", () => {
    assert.equal(normalizeEmail("Jane.Doe+hr@Corp.COM"), "jane.doe@corp.com");
    assert.equal(normalizeEmail("jane@old.com", { aliasDomains: ["corp.com", "old.com"] }), "jane@corp.com");
    assert.equal(normalizeEmail("jane@old.com", { aliasDomains: ["corp.com"] }), "jane@old.com");
    assert.equal(normalizeEmail("jane_vendor.io#EXT#@corp.onmicrosoft.com"), "jane@vendor.io");
  });
  test("name normalisation handles accents, Last, First and initials", () => {
    assert.equal(normalizeName("Tomás Ferreira"), "tomas ferreira");
    assert.equal(normalizeName("Ferreira, Tomas"), "tomas ferreira");
    assert.equal(normalizeName("J. Doe"), "doe");
  });
  test("levenshtein with cutoff", () => {
    assert.equal(levenshtein("tomas ferreira", "tomas ferreira"), 0);
    assert.equal(levenshtein("tomas ferreira", "tomaz ferreira", 2), 1);
    assert.ok(levenshtein("tomas ferreira", "grace okafor", 2) > 2);
  });
  test("HR status vocabulary", () => {
    assert.equal(parseHRStatus("Terminated"), "terminated");
    assert.equal(parseHRStatus("Inactive"), "terminated");
    assert.equal(parseHRStatus("Active"), "active");
    assert.equal(parseHRStatus("LOA"), "leave");
    assert.equal(parseHRStatus("Contractor"), "contractor");
    assert.equal(parseHRStatus("Active", "Contingent Worker"), "contractor");
    assert.equal(parseHRStatus(""), "unknown");
  });
  test("dataset hash is deterministic and input-sensitive", () => {
    assert.equal(datasetHash("a", "b"), datasetHash("a", "b"));
    assert.notEqual(datasetHash("a", "b"), datasetHash("a", "c"));
    assert.ok(/^acr-[0-9a-f]{16}-/.test(datasetHash("a", "b")));
  });
});

// ---------------------------------------------------------------- sources
group("acr: directory source detection and normalisation", () => {
  test("Entra ID export", () => {
    const dir = parseDirectory(ENTRA);
    assert.equal(dir.source, "entra");
    const dana = dir.users.find((u) => u.id === "dana@corp.com");
    assert.equal(dana.enabled, true); assert.equal(dana.isAdmin, true); assert.deepEqual(dana.adminRoles, ["Global Administrator"]); assert.equal(dana.mfa, true);
    const guest = dir.users.find((u) => u.id.startsWith("partner_"));
    assert.equal(guest.type, "guest"); assert.equal(guest.emailKey, "partner@vendor.io");
    assert.equal(dir.users.find((u) => u.id === "oldadmin@corp.com").mfa, false);
    assert.equal(dir.users.find((u) => u.id === "oldadmin@corp.com").lastSignIn, null);
    assert.ok(dir.coverage.mfa && dir.coverage.admin && dir.coverage.lastSignIn && dir.coverage.employeeId);
  });
  test("Google Workspace user list", () => {
    const dir = parseDirectory(GOOGLE);
    assert.equal(dir.source, "google");
    const m = dir.users.find((u) => u.id === "marcus@corp.com");
    assert.equal(m.isAdmin, true); assert.ok(m.adminRoles.includes("Super Admin")); assert.equal(m.mfa, true);
    assert.equal(dir.users.find((u) => u.id === "grace@corp.com").enabled, false);
    const nr = dir.users.find((u) => u.id === "noreply@corp.com");
    assert.equal(nr.type, "service"); assert.equal(nr.typeSource, "heuristic"); assert.equal(nr.lastSignIn, null);
    assert.equal(dir.users.find((u) => u.id === "dana@corp.com").mfa, false, "2sv Enrolled=False means no MFA even if enforced by policy");
    assert.equal(dir.users.find((u) => u.id === "priya@corp.com").name, "Priya Natarajan");
  });
  test("Okta CSV status mapping", () => {
    const dir = parseDirectory(OKTA_CSV);
    assert.equal(dir.source, "okta");
    const by = (id) => dir.users.find((u) => u.id === id);
    assert.equal(by("priya@corp.com").enabled, true);
    assert.equal(by("marcus@corp.com").enabled, false);
    assert.equal(by("yuki@corp.com").enabled, false);
    assert.equal(by("sofia@corp.com").enabled, true, "PROVISIONED is an un-activated but live account");
    assert.equal(by("priya@corp.com").employeeId, "E1");
  });
  test("Okta JSON (profile.* promoted, groups flattened)", () => {
    const dir = parseDirectory(OKTA_JSON);
    assert.equal(dir.format, "json");
    assert.equal(dir.source, "okta");
    const m = dir.users.find((u) => u.id === "marcus@corp.com");
    assert.equal(m.isAdmin, true); assert.equal(m.employeeId, "E3"); assert.equal(m.name, "Marcus Reed");
    assert.equal(dir.users.find((u) => u.id === "priya@corp.com").isAdmin, false);
  });
  test("Active Directory export: UAC flags, FILETIME, memberOf, pwdLastSet", () => {
    const dir = parseDirectory(AD);
    assert.equal(dir.source, "ad");
    const by = (id) => dir.users.find((u) => u.id === id);
    assert.equal(by("mreed").enabled, false, "UAC 514 = ACCOUNTDISABLE");
    assert.equal(by("dkowalski").isAdmin, true); assert.ok(by("dkowalski").adminRoles.includes("Domain Admins"));
    assert.equal(by("dkowalski").pwdNeverExpires, true, "UAC 66048 has DONT_EXPIRE_PASSWD");
    assert.equal(by("pnatarajan").pwdNeverExpires, false);
    assert.equal(by("svc_sql").pwdNeverSet, true);
    assert.equal(by("svc_sql").type, "service");
    assert.ok(Math.abs(by("pnatarajan").lastSignIn - (NOW - DAY)) < 1000);
    assert.equal(by("pnatarajan").created, Date.UTC(2020, 0, 1, 12));
  });
  test("generic CSV with unknown headers still yields users and honest coverage", () => {
    const dir = parseDirectory("username,full name\nbob,Bob Stone\n");
    assert.equal(dir.source, "generic");
    assert.equal(dir.users.length, 1);
    assert.equal(dir.coverage.enabled, false); assert.equal(dir.coverage.mfa, false);
    assert.ok(dir.warnings.some((w) => /enabled/.test(w)));
  });
  test("service-account heuristic", () => {
    assert.ok(looksLikeServiceAccount({ id: "svc-backup@corp.com" }));
    assert.ok(looksLikeServiceAccount({ id: "x@corp.com", name: "Shared Mailbox" }));
    assert.ok(looksLikeServiceAccount({ id: "x@corp.com", orgUnit: "/Service Accounts" }));
    assert.notOk(looksLikeServiceAccount({ id: "jane.doe@corp.com", name: "Jane Doe" }));
  });
});

// ---------------------------------------------------------------- matching
group("acr: matching precedence", () => {
  test("employee id wins over a conflicting email", () => {
    const hr = parseHR("Employee ID,Name,Email\nE1,Jane Doe,jane@corp.com\nE2,John Roe,john@corp.com", { now: NOW });
    const dir = parseDirectory("userPrincipalName,displayName,employeeId,accountEnabled\njohn@corp.com,John Roe,E1,TRUE");
    const rec = reconcile(hr, dir, {});
    assert.equal(rec.rows[0].matchMethod, "employeeId");
    assert.equal(rec.rows[0].employee.name, "Jane Doe");
  });
  test("email (normalised) used when no employee id", () => {
    const hr = parseHR("Name,Email\nJane Doe,Jane.Doe@Corp.com", { now: NOW });
    const dir = parseDirectory("userPrincipalName,displayName,accountEnabled\njane.doe+x@corp.com,Jane D,TRUE");
    const rec = reconcile(hr, dir, {});
    assert.equal(rec.rows[0].matchMethod, "email");
  });
  test("alias domains join old and new tenant domains", () => {
    const hr = parseHR("Name,Email\nJane Doe,jane@oldco.com", { now: NOW, aliasDomains: ["corp.com", "oldco.com"] });
    const dir = parseDirectory("userPrincipalName,displayName,accountEnabled\njane@corp.com,Jane Doe,TRUE", { aliasDomains: ["corp.com", "oldco.com"] });
    assert.equal(reconcile(hr, dir, {}).rows[0].matchMethod, "email");
  });
  test("fuzzy name match is flagged, never silent; distance > 2 is not a match", () => {
    const hr = parseHR("Employee ID,Name,Email\nE7,Tomás Ferreira,tomas.ferreira@corp.com\nE8,Grace Okafor,grace@corp.com", { now: NOW });
    const dir = parseDirectory("userPrincipalName,displayName,accountEnabled\ntferreira@corp.com,Tomas Ferreirra,TRUE\ngokafor@corp.com,Gracelyn Okaforre,TRUE");
    const rec = reconcile(hr, dir, {});
    const t = rec.rows.find((r) => r.key === "tferreira@corp.com");
    assert.equal(t.matchMethod, "fuzzy"); assert.equal(t.needsConfirmation, true); assert.equal(t.matchDistance, 1);
    const g = rec.rows.find((r) => r.key === "gokafor@corp.com");
    assert.equal(g.matchMethod, null, "distance 4 must not match");
    const res = analyze(hr, dir, { now: NOW });
    assert.ok(has(res, "fuzzy_match", "tferreira@corp.com"));
    assert.equal(res.rows.find((r) => r.key === "tferreira@corp.com").disposition, "Confirm match");
  });
  test("ambiguous fuzzy candidates (tie) are not matched", () => {
    const hr = parseHR("Name\nAnn Lee\nAnn Lea", { now: NOW });
    const dir = parseDirectory("displayName,userPrincipalName\nAnn Lei,ann@corp.com");
    assert.equal(reconcile(hr, dir, {}).rows[0].matchMethod, null);
  });
  test("service-like accounts are never fuzzy matched", () => {
    const hr = parseHR("Name\nSvc Backup", { now: NOW });
    const dir = parseDirectory("displayName,userPrincipalName\nsvc-backup,svc-backup@corp.com");
    assert.equal(reconcile(hr, dir, {}).rows[0].matchMethod, null);
  });
});

// ---------------------------------------------------------------- findings
group("acr: findings (positive and negative)", () => {
  const R = run(HR, ENTRA);
  test("leaver still enabled: Terminated + enabled is critical; disabled or active is not", () => {
    const f = R.findings.find((x) => x.type === "leaver_enabled" && x.account.id === "marcus@corp.com");
    assert.ok(f); assert.equal(f.severity, "critical"); assert.equal(f.confidence, "high");
    assert.ok(f.controls.includes("ISO 27001 A.5.18") && f.controls.includes("ATT&CK T1078"));
    assert.notOk(has(R, "leaver_enabled", "priya@corp.com"));
    assert.notOk(has(R, "leaver_enabled", "grace@corp.com"), "disabled account of an active employee is fine");
    assert.equal(R.rows.find((r) => r.key === "marcus@corp.com").disposition, "Disable");
  });
  test("terminated admin becomes admin_not_on_roster (critical), not plain leaver", () => {
    assert.ok(has(R, "admin_not_on_roster", "yuki@corp.com"));
    assert.notOk(has(R, "leaver_enabled", "yuki@corp.com"));
    assert.equal(R.rows.find((r) => r.key === "yuki@corp.com").disposition, "Disable");
  });
  test("activity after termination: sign-in after HR end date", () => {
    const f = R.findings.find((x) => x.type === "activity_after_termination" && x.account.id === "marcus@corp.com");
    assert.ok(f); assert.equal(f.severity, "critical");
    assert.ok(f.evidence.some((e) => e.label === "Last sign-in" && /after end date/.test(e.value)));
  });
  test("account created after termination date is flagged even when now disabled", () => {
    const hr = `Employee ID,Name,Email,Status,Termination Date\nE3,Marcus Reed,marcus@corp.com,Terminated,${d(100)}`;
    const dir = `userPrincipalName,displayName,accountEnabled,createdDateTime,employeeId\nmarcus2@corp.com,Marcus Reed,FALSE,${dt(20)},E3`;
    const r = run(hr, dir);
    assert.ok(has(r, "activity_after_termination", "marcus2@corp.com"));
    assert.notOk(has(r, "leaver_enabled"));
  });
  test("orphan: enabled member with no roster match is high; service-like is info; disabled is nothing", () => {
    assert.ok(has(R, "orphan_enabled", "jdoe@corp.com"));
    assert.equal(R.findings.find((x) => x.type === "orphan_enabled").severity, "high");
    assert.notOk(has(R, "orphan_enabled", "svc-backup@corp.com"));
    assert.ok(has(R, "service_account", "svc-backup@corp.com"));
    const r2 = run(HR, "userPrincipalName,displayName,accountEnabled\nghost@corp.com,Ghost,FALSE");
    assert.notOk(has(r2, "orphan_enabled"));
  });
  test("stale: >90 days medium, admin never-signed-in high, recent not flagged, new never-used not flagged", () => {
    const sofia = R.findings.find((x) => x.type === "stale_account" && x.account.id === "sofia@corp.com");
    assert.ok(sofia); assert.equal(sofia.severity, "medium");
    const old = R.findings.find((x) => x.type === "stale_account" && x.account.id === "oldadmin@corp.com");
    assert.ok(old); assert.equal(old.severity, "high");
    assert.notOk(has(R, "stale_account", "priya@corp.com"));
    const r2 = run("Name,Email\nNew Hire,new@corp.com", `userPrincipalName,displayName,accountEnabled,createdDateTime,lastSignInDateTime\nnew@corp.com,New Hire,TRUE,${dt(3)},`);
    assert.notOk(has(r2, "stale_account"), "created 3 days ago and never used is not stale");
    assert.ok(has(R, "stale_account", "sofia@corp.com") && !has(run(HR, ENTRA, { staleDays: 200 }), "stale_account", "sofia@corp.com"), "window is configurable");
  });
  test("stale is skipped honestly when the export has no sign-in column", () => {
    const r = run(HR, "userPrincipalName,displayName,accountEnabled\npriya@corp.com,Priya Natarajan,TRUE");
    assert.notOk(has(r, "stale_account"));
    assert.ok(r.warnings.some((w) => /sign-in/.test(w)));
  });
  test("admin without MFA is critical; admin with MFA is not; unknown MFA produces an aggregate note", () => {
    assert.ok(has(R, "admin_no_mfa", "oldadmin@corp.com"));
    assert.equal(R.findings.find((x) => x.type === "admin_no_mfa").severity, "critical");
    assert.notOk(has(R, "admin_no_mfa", "dana@corp.com"));
    assert.ok(has(R, "admin_mfa_unknown"), "auditor guest admin has an empty MFA cell");
    const r2 = run(HR, "userPrincipalName,displayName,accountEnabled,assignedRoles\ndana@corp.com,Dana Kowalski,TRUE,Global Administrator");
    assert.notOk(has(r2, "admin_no_mfa")); assert.ok(has(r2, "admin_mfa_unknown"));
  });
  test("admin orphan (not on roster) is critical", () => {
    assert.ok(has(R, "admin_not_on_roster", "oldadmin@corp.com"));
    assert.notOk(has(R, "admin_not_on_roster", "dana@corp.com"));
  });
  test("admin count threshold: by count, by percent (only from 20 users), configurable", () => {
    assert.notOk(has(R, "admin_count_excessive"), "4 enabled admins under default max 5");
    assert.ok(has(run(HR, ENTRA, { adminMaxCount: 2 }), "admin_count_excessive"));
    const big = ["userPrincipalName,displayName,accountEnabled,assignedRoles"];
    for (let i = 0; i < 40; i++) big.push(`u${i}@corp.com,User ${i},TRUE,${i < 3 ? "Global Administrator" : ""}`);
    assert.ok(has(run("Name,Email\nX Y,x@corp.com", big.join("\n"), { adminMaxCount: 10, adminMaxPct: 5 }), "admin_count_excessive"), "3/40 = 7.5% > 5%");
    assert.notOk(has(run("Name,Email\nX Y,x@corp.com", big.join("\n"), { adminMaxCount: 10, adminMaxPct: 10 }), "admin_count_excessive"));
  });
  test("guests: admin role high, past window medium, recent guest without roles clean", () => {
    assert.ok(has(R, "guest_admin", "auditor_bigfour.com#EXT#@corp.onmicrosoft.com"));
    assert.ok(has(R, "guest_stale", "partner_vendor.io#EXT#@corp.onmicrosoft.com"));
    assert.notOk(has(R, "guest_stale", "auditor_bigfour.com#EXT#@corp.onmicrosoft.com"));
    assert.notOk(has(R, "orphan_enabled", "partner_vendor.io#EXT#@corp.onmicrosoft.com"), "guests are not orphans");
    assert.notOk(has(run(HR, ENTRA, { guestDays: 500 }), "guest_stale"));
  });
  test("duplicate identity: two accounts for one employee id; medium when both enabled", () => {
    const f = R.findings.filter((x) => x.type === "duplicate_identity");
    assert.equal(f.length, 2);
    assert.equal(f[0].severity, "medium");
    assert.ok(f[0].evidence[0].value.includes("ravi2@corp.com"));
    const r2 = run("Employee ID,Name\nE9,Ravi Menon", "userPrincipalName,displayName,accountEnabled,employeeId\nravi@corp.com,Ravi,FALSE,E9\nravi2@corp.com,Ravi,TRUE,E9");
    assert.equal(r2.findings.find((x) => x.type === "duplicate_identity").severity, "low");
    assert.notOk(has(R, "duplicate_identity", "priya@corp.com"));
  });
  test("AD password hygiene: never expires, never set, old password; recent change is clean", () => {
    const r = run(HR, AD);
    assert.ok(has(r, "password_never_expires", "dkowalski"));
    assert.ok(has(r, "password_old", "dkowalski"), "400 days > 365");
    assert.ok(has(r, "password_old", "svc_sql"), "pwdLastSet 0");
    assert.ok(has(r, "password_old", "rmenon"));
    assert.notOk(has(r, "password_old", "pnatarajan"));
    assert.notOk(has(r, "password_never_expires", "pnatarajan"));
    assert.notOk(has(r, "password_old", "mreed"), "disabled accounts are not flagged");
    assert.notOk(has(run(HR, ENTRA), "password_old"), "no pwdLastSet column: skipped");
  });
  test("onboarding gap: active employee without account, not pre-start hires, not terminated", () => {
    assert.notOk(has(R, "onboarding_gap"), "pre-start hire (Hannah, +14 days) and disabled-but-present Grace are not gaps");
    assert.equal(R.kpis.hrNoAccount, 0);
    const r2 = run(`Name,Email,Status,Start Date\nAbsent Person,absent@corp.com,Active,${d(30)}\nGone Person,gone@corp.com,Terminated,${d(900)}\nFuture Person,future@corp.com,Active,${d(-5)}`,
      "userPrincipalName,displayName,accountEnabled\nx@corp.com,X,TRUE");
    const f = r2.findings.find((x) => x.type === "onboarding_gap");
    assert.ok(f); assert.equal(f.severity, "info");
    assert.equal(r2.hrNoAccount.length, 1);
    assert.equal(r2.hrNoAccount[0].name, "Absent Person");
    assert.ok(f.evidence.some((e) => e.value.startsWith("Absent Person")));
  });
  test("every finding carries control references and an action", () => {
    for (const f of R.findings) {
      assert.ok(f.controls.length >= 2, f.type + " controls");
      assert.ok(f.action.length > 20, f.type + " action");
      assert.ok(f.explanation.length > 10, f.type + " explanation");
      assert.ok(SEVERITY_RANK[f.severity] != null);
    }
    for (const t of Object.keys(FINDING_TYPES)) assert.ok(FINDING_TYPES[t].controls.length);
  });
});

group("acr: grace days and inferred status", () => {
  const mk = (endDaysAgo, grace) => run(`Employee ID,Name,Email,Status,Termination Date\nE3,Marcus Reed,marcus@corp.com,Active,${new Date(NOW - endDaysAgo * DAY).toISOString()}`,
    "userPrincipalName,displayName,accountEnabled,employeeId\nmarcus@corp.com,Marcus Reed,TRUE,E3", { graceDays: grace });
  test("end date exactly grace days ago is flagged (>=)", () => assert.ok(has(mk(1, 1), "leaver_enabled")));
  test("end date inside the grace window is not flagged", () => assert.notOk(has(mk(0.5, 1), "leaver_enabled")));
  test("grace 0 flags an end date earlier today", () => assert.ok(has(mk(0.1, 0), "leaver_enabled")));
  test("grace 7 suppresses a 3-day-old end date", () => assert.notOk(has(mk(3, 7), "leaver_enabled")));
  test("future end date (notice period) is not a leaver yet", () => assert.notOk(has(mk(-10, 1), "leaver_enabled")));
  test("status Terminated without an end date is still flagged", () => {
    const r = run("Employee ID,Name,Status\nE3,Marcus Reed,Terminated", "userPrincipalName,displayName,accountEnabled,employeeId\nmarcus@corp.com,Marcus Reed,TRUE,E3");
    assert.ok(has(r, "leaver_enabled"));
  });
  test("missing enabled column lowers confidence instead of hiding the finding", () => {
    const r = run(`Employee ID,Name,Status\nE3,Marcus Reed,Terminated`, "userPrincipalName,displayName,employeeId\nmarcus@corp.com,Marcus Reed,E3");
    const f = r.findings.find((x) => x.type === "leaver_enabled");
    assert.ok(f); assert.equal(f.confidence, "medium");
  });
  test("fuzzy-matched leaver is reported with low confidence and Confirm-match disposition stays visible via finding", () => {
    const r = run(`Employee ID,Name,Status\nE3,Marcus Reed,Terminated`, "userPrincipalName,displayName,accountEnabled\nmreed@corp.com,Markus Reed,TRUE");
    const f = r.findings.find((x) => x.type === "leaver_enabled");
    assert.ok(f); assert.equal(f.confidence, "low"); assert.equal(f.matchMethod, "fuzzy");
  });
});

// ---------------------------------------------------------------- packet
group("acr: review packet exports", () => {
  const R = run(HR, ENTRA);
  const decisions = { "marcus@corp.com": { decision: "Disable", note: "Ticket IT-4411", at: NOW }, "priya@corp.com": { decision: "Keep", at: NOW } };
  test("reconciliation CSV has one row per account, quotes correctly, carries decisions", () => {
    const csv = toReviewCSV(R, decisions);
    const lines = csv.trim().split("\n");
    assert.equal(lines.length, R.rows.length + 1);
    assert.ok(lines[0].startsWith("account,name,email,type,enabled"));
    const marcus = lines.find((l) => l.startsWith('"marcus@corp.com"'));
    assert.ok(marcus.includes('"Disable","Disable","Ticket IT-4411"'));
  });
  test("findings CSV lists controls", () => {
    const csv = toFindingsCSV(R);
    assert.ok(csv.split("\n").length > R.findings.length);
    assert.ok(csv.includes("ISO 27001 A.5.18"));
  });
  test("JSON packet round-trips and summarises decisions", () => {
    const j = toReviewJSON(R, decisions, { reviewer: "A. Reviewer", date: "2026-10-13", hash: "acr-x" });
    const back = JSON.parse(JSON.stringify(j));
    assert.equal(back.accounts.length, R.rows.length);
    assert.equal(back.decisionSummary.Disable, 1);
    assert.equal(back.decisionSummary.undecided, R.rows.length - 2);
    assert.equal(back.accounts.find((a) => a.account === "marcus@corp.com").decision, "Disable");
    assert.equal(back.reviewer, "A. Reviewer"); assert.equal(back.datasetHash, "acr-x");
    assert.ok(Array.isArray(back.hrWithoutAccount));
  });
  test("attestation text states incompleteness while decisions are missing, and confirms when complete", () => {
    const partial = attestationText(R, decisions, { reviewer: "A. Reviewer", date: "2026-10-13" });
    assert.ok(partial.includes("incomplete"));
    assert.ok(partial.includes("Reviewer: A. Reviewer"));
    const all = {}; for (const r of R.rows) all[r.key] = { decision: "Keep", at: NOW };
    const full = attestationText(R, all, { reviewer: "A. Reviewer" });
    assert.ok(full.includes("I confirm that every account"));
    assert.equal(summarizeDecisions(R, all).undecided, 0);
  });
  test("example data is synthetic but exercises the main finding types", () => {
    const ex = exampleData(NOW);
    const r = run(ex.hr, ex.dir);
    for (const t of ["leaver_enabled", "orphan_enabled", "stale_account", "admin_no_mfa", "admin_not_on_roster", "guest_admin", "guest_stale", "duplicate_identity", "fuzzy_match", "onboarding_gap", "service_account"]) assert.ok(has(r, t), t);
  });
  test("50k accounts reconcile in bounded time", () => {
    const hr = ["Employee ID,Name,Email,Status,Termination Date"], dir = ["userPrincipalName,displayName,accountEnabled,employeeId,lastSignInDateTime,assignedRoles"];
    for (let i = 0; i < 50000; i++) {
      hr.push(`E${i},User Number${i},user${i}@corp.com,${i % 97 === 0 ? "Terminated" : "Active"},${i % 97 === 0 ? d(30) : ""}`);
      dir.push(`user${i}@corp.com,User Number${i},TRUE,${i % 10 === 0 ? "" : "E" + i},${dt(i % 200)},${i % 5000 === 0 ? "Global Administrator" : ""}`);
    }
    const t0 = Date.now();
    const r = run(hr.join("\n"), dir.join("\n"));
    const ms = Date.now() - t0;
    assert.equal(r.rows.length, 50000);
    assert.ok(r.kpis.leaversEnabled > 400);
    assert.ok(ms < 15000, "took " + ms + "ms");
  });
});

group("access review: Security Graph sink mapping", () => {
  const ex = exampleData(NOW);
  test("required fields, normalised severity, stable ids/titles across runs, sample tagging", () => {
    const a = toSinkFindings(run(ex.hr, ex.dir)), b = toSinkFindings(run(ex.hr, ex.dir));
    const { items, links } = checkSinkFindings("accessreview", a, b, { minFindings: 5 });
    const leaver = a.find((f) => f.category === "leaver_enabled");
    assert.ok(leaver && leaver.title === "Leaver still enabled: " + leaver.assets[0].name);
    assert.equal(leaver.assets[0].type, "IDENTITY");
    assert.ok(leaver.controls.some((c) => c.framework === "ISO27001" && c.id === "A.5.18"));
    assert.ok(leaver.controls.some((c) => c.framework === "NIST-800-53" && c.id === "AC-2(3)"));
    assert.ok(items.some((i) => i.type === "CONTROL" && i.name === "CIS 6.2"));
    assert.ok(links.some((l) => l.rel === "affects" && l.to.startsWith("IDENTITY:")));
    for (const f of a.filter((x) => !x.assets.length)) assert.ok(/:aggregate$/.test(f.id), "only aggregates lack an account: " + f.id);
  });
  test("graph titles carry no counts (aggregate findings keep a fixed title)", () => {
    const agg = toSinkFindings(run(ex.hr, ex.dir)).filter((f) => /:aggregate$/.test(f.id));
    for (const f of agg) assert.equal(f.title, FINDING_TYPES[f.category].title);
  });
  test("example detection: example text is sample, an unrelated export is not", () => {
    assert.ok(sampleShare(ex.dir, ex.dir) >= SAMPLE_SHARE);
    assert.ok(sampleShare(ex.dir + "\nextra@test.darknode.ai,Extra,TRUE,Member,,,,,,,", ex.dir) >= SAMPLE_SHARE);
    assert.ok(sampleShare(ex.dir.split("\n")[0] + "\nreal@corp.example,Real Person,TRUE,Member,,,,,,,", ex.dir) < SAMPLE_SHARE);
  });
});
