// Lifecycle & Offboarding Verifier engine tests (public/js/identity/jml-engine.js):
// file classification for every vendor header set, one parser fixture per export
// format (headers verbatim), matching precedence, every detection on a positive
// and a negative, SLA / grace / lead edges, skipped-column reporting, determinism
// and the exports. Pure logic only.

import { test, assert, group } from "../harness.mjs";
import {
  TOOL_ID, VERSION, COLUMNS, DEFAULTS, KINDS, parseInput, classifyFile, appFromName, analyze, findingsToCsv, worklistCsv, slaCsv, exampleDataset, selfTest,
} from "../../public/js/identity/jml-engine.js";

const DAY = 86400000, HOUR = 3600000;
const NOW = Date.UTC(2026, 9, 13, 12, 0, 0); // 2026-10-13T12:00Z
const NOW_ISO = new Date(NOW).toISOString();
const d = (days) => new Date(NOW - days * DAY).toISOString().slice(0, 10);
const dt = (days, h = 0) => new Date(NOW - days * DAY + h * HOUR).toISOString();
const run = (files, opts = {}) => analyze(parseInput(files), { now: NOW_ISO, ...opts });
const titles = (r) => r.findings.map((f) => f.title);
const find = (r, re) => r.findings.find((f) => re.test(f.title));
const skippedChecks = (r) => r.skipped.map((s) => s.check);

// ------------------------------------------------------------------ fixtures
const WORKDAY = [
  "Employee ID,Worker,Email - Primary Work,Hire Date,Termination Date,Active Status,Manager,Cost Center,Job Title,Business Title,Location",
  `E1,Priya Natarajan,priya.natarajan@corp.com,${d(900)},,Yes,,Engineering,Engineer,Staff Engineer,Dublin`,
  `E2,Dana Kowalski,dana.kowalski@corp.com,${d(1500)},,Yes,Priya Natarajan,Engineering,VP,VP Engineering,Dublin`,
  `E3,Marcus Reed,marcus.reed@corp.com,${d(1200)},${d(5)},No,Priya Natarajan,Finance,Controller,Controller,Austin`,
  `E4,Yuki Tanaka,yuki.tanaka@corp.com,${d(800)},${d(40)},No,Marcus Reed,Finance,Analyst,Analyst,Austin`,
  `E5,Sofia Alvarez,sofia.alvarez@corp.com,${d(400)},,Yes,Marcus Reed,Sales,AE,Account Executive,Austin`,
  `E6,Grace Okafor,grace.okafor@corp.com,${d(-3)},,Yes,Dana Kowalski,People,HRBP,HR Business Partner,Dublin`,
  `E7,Tomas Ferreira,tomas.ferreira@corp.com,${d(300)},,Yes,Dana Kowalski,IT,Sysadmin,Sysadmin,Dublin`,
].join("\n");

const BAMBOO = [
  "Employee #,First Name,Last Name,Work Email,Hire Date,Termination Date,Status,Department,Job Title,Reports To",
  `101,Priya,Natarajan,priya.natarajan@corp.com,${d(900)},,Active,Engineering,Engineer,Marcus Reed`,
  `102,Marcus,Reed,marcus.reed@corp.com,${d(1200)},${d(5)},Terminated,Finance,Controller,`,
].join("\n");

const GUSTO = [
  "Employee,Email,Start date,Termination date,Status,Department,Manager",
  `Priya Natarajan,priya.natarajan@corp.com,${d(900)},,Active,Engineering,`,
  `Marcus Reed,marcus.reed@corp.com,${d(1200)},${d(5)},Terminated,Finance,Priya Natarajan`,
].join("\n");

const RIPPLING = [
  "Employee ID,First name,Last name,Work email,Start date,End date,Employment status,Department,Manager,Title",
  `R1,Priya,Natarajan,priya.natarajan@corp.com,${d(900)},,Active,Engineering,,Engineer`,
  `R3,Marcus,Reed,marcus.reed@corp.com,${d(1200)},${d(5)},Terminated,Finance,Priya Natarajan,Controller`,
].join("\n");

const CHANGES = [
  "Employee ID,Effective Date,Change Type,From Department,To Department,From Manager,To Manager",
  `E7,${d(30)},Transfer,Finance,IT,Marcus Reed,Dana Kowalski`,
].join("\n");

const ENTRA_CSV = [
  "userPrincipalName,displayName,accountEnabled,createdDateTime,lastSignInDateTime,department,jobTitle,assignedLicenses,memberOf,deletedDateTime",
  `priya.natarajan@corp.com,Priya Natarajan,True,${dt(900)},${dt(1)},Engineering,Engineer,ENTERPRISEPACK,Engineering-All;Everyone,`,
  `dana.kowalski@corp.com,Dana Kowalski,True,${dt(1500)},${dt(2)},Engineering,VP,ENTERPRISEPACK,Engineering-All;Everyone,`,
  `marcus.reed@corp.com,Marcus Reed,True,${dt(1200)},${dt(2)},Finance,Controller,ENTERPRISEPACK,Finance-All;Everyone,`,
  `yuki.tanaka@corp.com,Yuki Tanaka,False,${dt(800)},${dt(41)},Finance,Analyst,,Finance-All,${dt(40, 30)}`,
  `sofia.alvarez@corp.com,Sofia Alvarez,True,${dt(400)},${dt(3)},Sales,AE,ENTERPRISEPACK,Sales-All,`,
  `grace.okafor@corp.com,Grace Okafor,True,${dt(20)},,People,HRBP,ENTERPRISEPACK,People-All,`,
  `tferreira@corp.com,Tomas Ferreira,True,${dt(300)},${dt(1)},Finance,Sysadmin,ENTERPRISEPACK,Finance-All;Finance-Approvers;IT-All,`,
  `finance.shared@corp.com,Finance Shared Mailbox,True,${dt(600)},,,,,,`,
  `room.dublin1@corp.com,Dublin 1 Conference Room,False,${dt(600)},,,,,,`,
].join("\n");

const ENTRA_JSON = JSON.stringify({ value: [
  { userPrincipalName: "priya.natarajan@corp.com", displayName: "Priya Natarajan", accountEnabled: true, createdDateTime: dt(900), department: "Engineering", signInActivity: { lastSignInDateTime: dt(1) } },
  { userPrincipalName: "marcus.reed@corp.com", displayName: "Marcus Reed", accountEnabled: true, createdDateTime: dt(1200), department: "Finance", signInActivity: { lastSignInDateTime: dt(2) } },
] });

const OKTA = JSON.stringify([
  { id: "00u1", status: "ACTIVE", created: dt(900), activated: dt(900), statusChanged: dt(900), lastLogin: dt(1), profile: { login: "priya.natarajan@corp.com", email: "priya.natarajan@corp.com", firstName: "Priya", lastName: "Natarajan", department: "Engineering", title: "Engineer", managerId: "" }, groups: [{ id: "g1", profile: { name: "Engineering-All" } }] },
  { id: "00u3", status: "ACTIVE", created: dt(1200), activated: dt(1200), statusChanged: dt(1200), lastLogin: dt(2), profile: { login: "marcus.reed@corp.com", email: "marcus.reed@corp.com", firstName: "Marcus", lastName: "Reed", department: "Finance", title: "Controller", managerId: "00u1" }, groups: [{ id: "g2", profile: { name: "Finance-All" } }] },
  { id: "00u4", status: "DEPROVISIONED", created: dt(800), activated: dt(800), statusChanged: dt(40, 60), lastLogin: dt(41), profile: { login: "yuki.tanaka@corp.com", email: "yuki.tanaka@corp.com", firstName: "Yuki", lastName: "Tanaka", department: "Finance", title: "Analyst", managerId: "00u3" }, groups: [] },
  { id: "00u7", status: "ACTIVE", created: dt(300), activated: dt(300), statusChanged: dt(300), lastLogin: dt(1), profile: { login: "tomas.ferreira@corp.com", email: "tomas.ferreira@corp.com", firstName: "Tomas", lastName: "Ferreira", department: "Finance", title: "Sysadmin", managerId: "00u1" }, groups: [{ id: "g3", profile: { name: "Finance-Approvers" } }, { id: "g4", profile: { name: "IT-All" } }] },
]);

const GOOGLE = [
  "First Name [Required],Last Name [Required],Email Address [Required],Status [READ ONLY],Last Sign In [READ ONLY],Org Unit Path [Required],Suspended",
  `Priya,Natarajan,priya.natarajan@corp.com,Active,${d(1).replace(/-/g, "/")} 09:12:00,/Engineering,False`,
  `Marcus,Reed,marcus.reed@corp.com,Active,${d(2).replace(/-/g, "/")} 10:00:00,/Finance,False`,
  `Yuki,Tanaka,yuki.tanaka@corp.com,Suspended,${d(41).replace(/-/g, "/")} 10:00:00,/Finance,True`,
].join("\n");

const SLACK = [
  "username,email,status,billing-active,has-2fa,has-sso,userid,fullname,displayname,expiration-timestamp",
  "priya.natarajan,priya.natarajan@corp.com,Owner,1,1,1,U01,Priya Natarajan,priya,",
  "marcus.reed,marcus.reed@corp.com,Member,1,1,1,U03,Marcus Reed,marcus,",
  "yuki.tanaka,yuki.tanaka@corp.com,Deactivated,0,0,0,U04,Yuki Tanaka,yuki,",
  "jordan.blake,jordan.blake@corp.com,Member,1,0,0,U99,Jordan Blake,jordan,",
  "sam,sam@agency-partner.example,Member,1,1,0,U98,Sam Agency,sam,",
  "svc-deploy,svc-deploy@corp.com,Member,0,0,0,U97,Deploy Bot,deploy,",
].join("\n");

const GITHUB = [
  "Login,Name,Role,Two-factor,Saml identity",
  "pnatarajan,Priya Natarajan,Owner,enabled,priya.natarajan@corp.com",
  "mreed,Marcus Reed,Member,disabled,marcus.reed@corp.com",
  "ci-bot,CI Bot,Member,enabled,",
].join("\n");

const GITHUB_JSON = JSON.stringify([
  { login: "pnatarajan", id: 1, node_id: "MDQ6VXNlcjE=", avatar_url: "https://avatars.githubusercontent.com/u/1", html_url: "https://github.com/pnatarajan", type: "User", site_admin: false },
  { login: "mreed", id: 3, node_id: "MDQ6VXNlcjM=", avatar_url: "https://avatars.githubusercontent.com/u/3", html_url: "https://github.com/mreed", type: "User", site_admin: false },
]);

const M365 = [
  "Display name,User principal name,Licenses,Block credential,Last sign-in",
  `Priya Natarajan,priya.natarajan@corp.com,Microsoft 365 E3,False,${d(1)}`,
  `Marcus Reed,marcus.reed@corp.com,Microsoft 365 E3,False,${d(2)}`,
  `Yuki Tanaka,yuki.tanaka@corp.com,,True,${d(41)}`,
  `Sofia Alvarez,sofia.alvarez@corp.com,Microsoft 365 E3,False,`,
  "Finance Shared Mailbox,finance.shared@corp.com,,False,",
].join("\n");

const ZOOM = [
  "Email,First Name,Last Name,Type,Dept,Last Login,Status",
  `priya.natarajan@corp.com,Priya,Natarajan,Licensed,Engineering,${d(1)},Active`,
  `marcus.reed@corp.com,Marcus,Reed,Licensed,Finance,${d(2)},Active`,
  `sofia.alvarez@corp.com,Sofia,Alvarez,Basic,Sales,${d(9)},Active`,
].join("\n");

const SALESFORCE = [
  "Username,Email,Active,Profile,Last Login,User License",
  `priya.natarajan@corp.com,priya.natarajan@corp.com,true,System Administrator,${d(1)},Salesforce`,
  `marcus.reed@corp.com,marcus.reed@corp.com,true,Standard User,${d(2)},Salesforce`,
  `yuki.tanaka@corp.com,yuki.tanaka@corp.com,false,Standard User,${d(41)},Salesforce`,
].join("\n");

const ATLASSIAN = [
  "User name,email,Active,Last seen in Jira Software",
  `Priya Natarajan,priya.natarajan@corp.com,Yes,${d(1)}`,
  `Marcus Reed,marcus.reed@corp.com,Yes,${d(2)}`,
].join("\n");

const ZENDESK = [
  "Id,Name,Email,Role,Organization,Time zone,Last login,Suspended",
  `1,Priya Natarajan,priya.natarajan@corp.com,admin,Corp,Dublin,${d(1)},false`,
  `3,Marcus Reed,marcus.reed@corp.com,agent,Corp,Austin,${d(2)},false`,
].join("\n");

const GENERIC_SAAS = [
  "email,status,last login",
  `priya.natarajan@corp.com,active,${d(1)}`,
  `marcus.reed@corp.com,active,${d(2)}`,
].join("\n");

const INTUNE = [
  "Device name,Primary user UPN,Last check-in,Compliance state,OS",
  `LT-PRIYA,priya.natarajan@corp.com,${dt(0, -3)},Compliant,Windows`,
  `LT-MARCUS,marcus.reed@corp.com,${dt(1)},Compliant,Windows`,
  `LT-YUKI,yuki.tanaka@corp.com,${dt(45)},Noncompliant,Windows`,
].join("\n");

const JAMF = [
  "Computer Name,Username,Last Check-in",
  `MBP-PRIYA,priya.natarajan,${dt(0, -3)}`,
  `MBP-MARCUS,marcus.reed@corp.com,${dt(2)}`,
].join("\n");

const f = (name, text) => ({ name, text });
const BASE = [f("workday.csv", WORKDAY), f("entra-users.csv", ENTRA_CSV)];

// ------------------------------------------------------------------ classification
group("jml: file classification", () => {
  const cls = (text, name = "x.csv") => { const p = parseInput([f(name, text)]).files[0]; return p.kind + "/" + p.vendor + "/" + (p.app || "") + "/" + p.confidence; };
  test("Workday roster", () => assert.equal(cls(WORKDAY), "hr/workday/Workday/high"));
  test("BambooHR roster", () => assert.equal(cls(BAMBOO), "hr/bamboohr/BambooHR/high"));
  test("Gusto roster", () => assert.equal(cls(GUSTO), "hr/gusto/Gusto/high"));
  test("Rippling roster", () => assert.equal(cls(RIPPLING), "hr/rippling/Rippling/high"));
  test("HR changes file", () => assert.equal(cls(CHANGES), "hr-changes/generic//high"));
  test("Entra Get-MgUser CSV", () => assert.equal(cls(ENTRA_CSV), "idp/entra/Entra ID/high"));
  test("Entra Graph JSON ({value:[...]}, signInActivity nested)", () => assert.equal(cls(ENTRA_JSON, "mguser.json"), "idp/entra/Entra ID/high"));
  test("Okta users JSON", () => assert.equal(cls(OKTA, "okta.json"), "idp/okta/Okta/high"));
  test("Google Workspace users CSV ([Required] / [READ ONLY] suffixes)", () => assert.equal(cls(GOOGLE), "idp/google/Google Workspace/high"));
  test("Slack members export", () => assert.equal(cls(SLACK), "saas/slack/Slack/high"));
  test("GitHub org people CSV", () => assert.equal(cls(GITHUB), "saas/github/GitHub/high"));
  test("GitHub gh api members JSON", () => assert.equal(cls(GITHUB_JSON, "members.json"), "saas/github/GitHub/high"));
  test("Microsoft 365 active users export", () => assert.equal(cls(M365), "saas/m365/Microsoft 365/high"));
  test("Zoom users CSV", () => assert.equal(cls(ZOOM), "saas/zoom/Zoom/high"));
  test("Salesforce users report", () => assert.equal(cls(SALESFORCE), "saas/salesforce/Salesforce/high"));
  test("Atlassian user export", () => assert.equal(cls(ATLASSIAN), "saas/atlassian/Atlassian/high"));
  test("Zendesk user export (heuristic, medium)", () => assert.equal(cls(ZENDESK), "saas/zendesk/Zendesk/medium"));
  test("generic email+status list takes the app name from the file name", () => assert.equal(cls(GENERIC_SAAS, "notion-members.csv"), "saas/generic/Notion/medium"));
  test("Intune device inventory", () => assert.equal(cls(INTUNE), "devices/intune/Intune/high"));
  test("Jamf device inventory", () => assert.equal(cls(JAMF), "devices/jamf/Jamf/high"));
  test("unrecognised headers are reported, not guessed", () => {
    const p = parseInput([f("x.csv", "a,b\n1,2")]);
    assert.equal(p.files[0].kind, "unknown");
    assert.ok(p.skipped.some((s) => s.check === "classify"));
  });
  test("appFromName strips noise words and maps known vendors", () => {
    assert.equal(appFromName("slack-members-export.csv"), "Slack");
    assert.equal(appFromName("acme_users.csv"), "acme");
    assert.equal(classifyFile(["email", "status"], { name: "figma-users.csv" }).app, "Figma");
  });
  test("parseInput of a single string keeps the single-file contract shape", () => {
    const p = parseInput(SLACK);
    assert.equal(p.format, "csv"); assert.equal(p.rows.length, 6); assert.ok(p.headers.includes("billing-active")); assert.equal(p.files.length, 1);
  });
  test("empty input yields no rows and no findings", () => {
    const p = parseInput("");
    assert.equal(p.rows.length, 0);
    const r = analyze(p);
    assert.equal(r.findings.length, 0); assert.equal(r.meta.rows, 0);
  });
});

// ------------------------------------------------------------------ parsing per format
group("jml: parsers", () => {
  test("Workday roster: Worker / Email - Primary Work / Active Status / Cost Center are mapped", () => {
    const r = run([f("workday.csv", WORKDAY)]);
    const marcus = r.tables.people.find((p) => p.person === "Marcus Reed");
    assert.equal(r.summary.people, 7); assert.equal(marcus.hrStatus, "terminated"); assert.equal(marcus.termDate, d(5)); assert.equal(marcus.department, "Finance"); assert.equal(marcus.email, "marcus.reed@corp.com");
  });
  test("BambooHR roster: first/last name joined, Reports To is the manager", () => {
    const r = run([f("bamboo.csv", BAMBOO), f("entra.csv", ENTRA_CSV)]);
    assert.ok(r.tables.people.some((p) => p.person === "Marcus Reed" && p.hrStatus === "terminated"));
    assert.ok(find(r, /manager of record/), "BambooHR Reports To drives the orphaned-reports check");
  });
  test("Gusto roster: Employee column is the name, not the id", () => {
    const r = run([f("gusto.csv", GUSTO)]);
    assert.ok(r.tables.people.some((p) => p.person === "Marcus Reed" && p.hrStatus === "terminated" && p.email === "marcus.reed@corp.com"));
  });
  test("Rippling roster: End date / Employment status", () => {
    const r = run([f("rippling.csv", RIPPLING)]);
    assert.equal(r.tables.people.find((p) => p.person === "Marcus Reed").termDate, d(5));
  });
  test("Entra CSV: accountEnabled, lastSignInDateTime, memberOf, assignedLicenses, deletedDateTime are read", () => {
    const r = run(BASE);
    const yuki = r.tables.people.find((p) => p.person === "Yuki Tanaka");
    assert.equal(yuki.idpStatus, "disabled");
    const sla = r.tables.sla.find((s) => s.leaver === "yuki.tanaka@corp.com");
    assert.ok(sla.disabledAt, "deletedDateTime used as disable time");
  });
  test("Entra JSON with signInActivity.lastSignInDateTime", () => {
    const r = run([f("workday.csv", WORKDAY), f("mguser.json", ENTRA_JSON)]);
    assert.equal(r.tables.people.find((p) => p.person === "Marcus Reed").idpStatus, "enabled");
    assert.equal(r.tables.people.find((p) => p.person === "Marcus Reed").lastSignIn, d(2));
  });
  test("Okta JSON: profile.* promoted, status, statusChanged and groups read", () => {
    const r = run([f("workday.csv", WORKDAY), f("okta.json", OKTA)]);
    const yuki = r.tables.sla.find((s) => s.leaver === "yuki.tanaka@corp.com");
    assert.equal(yuki.status, "disabled"); assert.equal(yuki.hours, 72); assert.equal(yuki.breach, true);
    assert.ok(find(r, /old department/), "Okta groups feed the mover check");
  });
  test("Google Workspace CSV: Suspended column drives enabled, slash dates parse", () => {
    const r = run([f("workday.csv", WORKDAY), f("google.csv", GOOGLE)]);
    assert.equal(r.tables.people.find((p) => p.person === "Yuki Tanaka").idpStatus, "disabled");
    assert.equal(r.tables.people.find((p) => p.person === "Marcus Reed").idpStatus, "enabled");
  });
  test("Slack: Member/Owner/Admin active, Deactivated inactive, billing-active is the licence", () => {
    const r = run([...BASE, f("slack.csv", SLACK)]);
    const app = r.tables.apps.find((a) => a.app === "Slack");
    assert.equal(app.total, 6); assert.equal(app.active, 5);
    assert.equal(r.tables.people.find((p) => p.person === "Yuki Tanaka").apps[0].status, "inactive");
  });
  test("GitHub CSV: SAML identity matches the person; a people list has no status so members are active", () => {
    const r = run([...BASE, f("github.csv", GITHUB)]);
    assert.equal(r.tables.people.find((p) => p.person === "Marcus Reed").apps[0].status, "active");
    assert.equal(r.tables.apps.find((a) => a.app === "GitHub").orphans, 0, "ci-bot looks like a service account");
  });
  test("GitHub JSON members list: login only, matched by local-part when unique", () => {
    const r = run([...BASE, f("gh-members.json", GITHUB_JSON)]);
    assert.equal(r.tables.apps.find((a) => a.app === "GitHub").total, 2);
  });
  test("M365: Licenses non-empty is licensed, Block credential True is inactive", () => {
    const r = run([...BASE, f("m365.csv", M365)]);
    const yuki = r.tables.people.find((p) => p.person === "Yuki Tanaka").apps[0];
    assert.equal(yuki.status, "inactive"); assert.equal(yuki.licensed, false);
    assert.equal(r.tables.people.find((p) => p.person === "Marcus Reed").apps[0].licensed, true);
  });
  test("Zoom: Type Licensed vs Basic", () => {
    const r = run([...BASE, f("zoom.csv", ZOOM)]);
    assert.equal(r.tables.people.find((p) => p.person === "Sofia Alvarez").apps[0].licensed, false);
    assert.equal(r.tables.people.find((p) => p.person === "Marcus Reed").apps[0].licensed, true);
  });
  test("Salesforce: Active false is inactive, User License is a paid licence", () => {
    const r = run([...BASE, f("sfdc.csv", SALESFORCE)]);
    assert.equal(r.tables.people.find((p) => p.person === "Yuki Tanaka").apps[0].status, "inactive");
    assert.equal(r.tables.people.find((p) => p.person === "Marcus Reed").apps[0].licensed, true);
  });
  test("Atlassian: Active Yes and Last seen in Jira Software", () => {
    const r = run([...BASE, f("atlassian.csv", ATLASSIAN)]);
    const m = r.tables.people.find((p) => p.person === "Marcus Reed").apps[0];
    assert.equal(m.status, "active"); assert.equal(m.lastLogin, d(2));
  });
  test("Zendesk: Suspended false is active", () => {
    const r = run([...BASE, f("zendesk.csv", ZENDESK)]);
    assert.equal(r.tables.people.find((p) => p.person === "Marcus Reed").apps[0].status, "active");
  });
  test("Intune and Jamf inventories attach devices to people (UPN or local-part user)", () => {
    const r = run([...BASE, f("intune.csv", INTUNE), f("jamf.csv", JAMF)]);
    assert.deepEqual(r.tables.people.find((p) => p.person === "Priya Natarajan").devices, ["LT-PRIYA", "MBP-PRIYA"]);
  });
});

// ------------------------------------------------------------------ detections
group("jml: leaver detections", () => {
  test("leaver still enabled in the IdP fires (critical) with hours since termination", () => {
    const r = run(BASE);
    const fd = find(r, /still enabled in the IdP/);
    assert.ok(fd); assert.equal(fd.severity, "critical"); assert.equal(fd.evidence[0].person, "Marcus Reed"); assert.equal(fd.evidence[0].hoursSinceTermination, 5 * 24 + 12);
    assert.ok(fd.controls.some((c) => c.framework === "NIST-800-53" && c.id === "PS-4"));
  });
  test("leaver disabled in the IdP does not fire", () => {
    const r = run(BASE);
    assert.ok(!r.findings.some((x) => /still enabled/.test(x.title) && x.evidence[0].person === "Yuki Tanaka"));
  });
  test("leavers still active per SaaS app: one finding per app, users as evidence", () => {
    const r = run([...BASE, f("slack.csv", SLACK), f("github.csv", GITHUB)]);
    const slack = find(r, /still active in Slack/), gh = find(r, /still active in GitHub/);
    assert.ok(slack && gh); assert.equal(slack.severity, "high"); assert.equal(slack.evidence.length, 1); assert.equal(slack.evidence[0].person, "Marcus Reed");
    assert.ok(slack.assets.some((a) => a.type === "ASSET" && a.data.kind === "saas-app" && a.data.leakage === 1));
    assert.equal(r.summary.appsWithLeakage, 2);
  });
  test("deactivated leaver in a SaaS app is silent", () => {
    const r = run([...BASE, f("sfdc.csv", SALESFORCE.split("\n").filter((l) => !/marcus/.test(l)).join("\n"))]);
    assert.ok(!find(r, /still active in Salesforce/));
  });
  test("leaver signed in after termination fires from IdP or SaaS last login", () => {
    const r = run([...BASE, f("slack.csv", SLACK)]);
    const fd = find(r, /signed in after termination/);
    assert.ok(fd); assert.equal(fd.severity, "critical"); assert.ok(fd.controls.some((c) => c.framework === "MITRE" && c.id === "T1078"));
    assert.ok(fd.evidence.every((e) => e.person === "Marcus Reed"));
  });
  test("leaver whose last sign-in predates termination is silent", () => {
    const r = run(BASE);
    assert.ok(!r.findings.some((x) => /signed in after/.test(x.title) && x.evidence[0].person === "Yuki Tanaka"));
  });
  test("leaver device still checking in fires only for check-ins after the termination date", () => {
    const r = run([...BASE, f("intune.csv", INTUNE)]);
    const fd = find(r, /device still checking in/);
    assert.ok(fd); assert.equal(fd.evidence[0].person, "Marcus Reed"); assert.equal(fd.evidence[0].device, "LT-MARCUS");
    assert.ok(!r.findings.some((x) => /device still/.test(x.title) && x.evidence[0].person === "Yuki Tanaka"), "Yuki's device last checked in before termination");
  });
  test("terminated manager still manager of record lists the orphaned reports", () => {
    const r = run(BASE);
    const fd = find(r, /manager of record/);
    assert.ok(fd); assert.equal(fd.evidence.length, 1, "Yuki also reports to Marcus but is terminated herself");
    assert.equal(fd.evidence[0].report, "Sofia Alvarez");
  });
  test("no manager column: orphaned_reports skipped", () => {
    const hr = WORKDAY.split("\n").map((l) => l.split(",").filter((_, i) => i !== 6).join(",")).join("\n");
    const r = run([f("hr.csv", hr), f("entra.csv", ENTRA_CSV)]);
    assert.ok(skippedChecks(r).includes("orphaned_reports"));
  });
});

group("jml: time to disable", () => {
  test("SLA breach when disable happened after the SLA; median KPI is computed", () => {
    const r = run([f("workday.csv", WORKDAY), f("okta.json", OKTA)]);
    const fd = find(r, /disabled later than the SLA/);
    assert.ok(fd); assert.equal(fd.evidence[0].hours, 72); assert.equal(r.summary.medianHoursToDisable, 72);
  });
  test("disable exactly at the SLA is not a breach (edge)", () => {
    const r = run([f("workday.csv", WORKDAY), f("okta.json", OKTA)], { disableSlaHours: 72 });
    assert.ok(!find(r, /disabled later than the SLA/));
    assert.equal(r.tables.sla.find((s) => s.leaver === "yuki.tanaka@corp.com").breach, false);
  });
  test("still-enabled leaver counts open hours against the SLA", () => {
    const r = run(BASE);
    const s = r.tables.sla.find((s) => s.leaver === "marcus.reed@corp.com");
    assert.equal(s.status, "still enabled"); assert.equal(s.disabledAt, null); assert.equal(s.breach, true);
  });
  test("IdP without statusChanged/deletedDateTime reports the skipped measurement", () => {
    const entra = ENTRA_CSV.split("\n").map((l) => l.split(",").slice(0, 9).join(",")).join("\n");
    const r = run([f("workday.csv", WORKDAY), f("entra.csv", entra)]);
    assert.ok(skippedChecks(r).includes("sla_time_to_disable"));
    assert.equal(r.summary.medianHoursToDisable, null);
  });
});

group("jml: movers and joiners", () => {
  test("mover from the changes file still in old-department groups after the grace period (review)", () => {
    const r = run([f("workday.csv", WORKDAY), f("changes.csv", CHANGES), f("entra.csv", ENTRA_CSV)]);
    const fd = find(r, /old department/);
    assert.ok(fd); assert.equal(fd.confidence, "review"); assert.ok(/Finance-All/.test(fd.evidence[0].staleGroups)); assert.ok(/Finance-Approvers/.test(fd.evidence[0].staleGroups)); assert.ok(!/IT-All/.test(fd.evidence[0].staleGroups));
  });
  test("a mover out of a short-named department (IT) still in its groups is flagged", () => {
    const wd = ["Employee ID,Worker,Email - Primary Work,Hire Date,Termination Date,Active Status,Manager,Cost Center,Job Title,Business Title,Location",
      `E9,Omar Said,omar.said@corp.com,${d(500)},,Yes,,Security,Analyst,Analyst,Dublin`].join("\n");
    const ch = ["Employee ID,Effective Date,Change Type,From Department,To Department,From Manager,To Manager",
      `E9,${d(30)},Transfer,IT,Security,,`].join("\n");
    const en = ["userPrincipalName,displayName,accountEnabled,createdDateTime,lastSignInDateTime,department,jobTitle,assignedLicenses,memberOf,deletedDateTime",
      `omar.said@corp.com,Omar Said,True,${dt(500)},${dt(1)},Security,Analyst,ENTERPRISEPACK,IT-All;Security-Team,`].join("\n");
    const r = run([f("workday.csv", wd), f("changes.csv", ch), f("entra.csv", en)]);
    const fd = find(r, /old department/);
    assert.ok(fd, "a 2-char department name is no longer dropped, so the stale group is flagged");
    assert.ok(/IT-All/.test(fd.evidence[0].staleGroups) && !/Security-Team/.test(fd.evidence[0].staleGroups));
  });
  test("mover inside the grace period is silent (edge)", () => {
    const r = run([f("workday.csv", WORKDAY), f("changes.csv", CHANGES), f("entra.csv", ENTRA_CSV)], { moverGraceDays: 31 });
    assert.ok(!find(r, /old department/));
  });
  test("without a changes file, HR vs IdP department mismatch is the mover signal", () => {
    const r = run([f("workday.csv", WORKDAY), f("entra.csv", ENTRA_CSV)]);
    const fd = find(r, /old department|department not updated/);
    assert.ok(fd); assert.equal(fd.evidence[0].person, "Tomas Ferreira"); assert.equal(fd.evidence[0].source, "HR vs IdP department");
  });
  test("joiner account created more than the lead time before hire fires; within the lead time is silent", () => {
    const r = run(BASE);
    const fd = find(r, /created long before the hire date/);
    assert.ok(fd); assert.equal(fd.evidence[0].person, "Grace Okafor"); assert.equal(fd.evidence[0].daysBeforeHire, 22);
    assert.ok(!find(run(BASE, { joinerLeadDays: 23 }), /created long before/), "22.5 days is not more than 23");
    assert.ok(find(run(BASE, { joinerLeadDays: 22 }), /created long before/), "22.5 days is more than 22");
  });
  test("hired employee with no IdP account is a joiner gap (review)", () => {
    const entra = ENTRA_CSV.split("\n").filter((l) => !/sofia/.test(l)).join("\n");
    const r = run([f("workday.csv", WORKDAY), f("entra.csv", entra)]);
    const fd = find(r, /no IdP account/);
    assert.ok(fd); assert.equal(fd.confidence, "review"); assert.equal(fd.evidence[0].person, "Sofia Alvarez");
    assert.ok(!find(run(BASE), /no IdP account/));
  });
});

group("jml: orphans, external accounts and licences", () => {
  test("orphan SaaS account on a company domain (not in HR, not in IdP, not service-like)", () => {
    const r = run([...BASE, f("slack.csv", SLACK)]);
    const fd = find(r, /Orphan accounts in Slack/);
    assert.ok(fd); assert.equal(fd.evidence.length, 1); assert.equal(fd.evidence[0].account, "jordan.blake@corp.com"); assert.equal(fd.confidence, "review");
  });
  test("account present in the IdP but not HR is not an orphan (Access Review's job)", () => {
    const entra = ENTRA_CSV + `\njordan.blake@corp.com,Jordan Blake,True,${dt(100)},${dt(1)},IT,Contractor,,,`;
    const r = run([f("workday.csv", WORKDAY), f("entra.csv", entra), f("slack.csv", SLACK)]);
    assert.ok(!find(r, /Orphan accounts in Slack/));
  });
  test("external domain is a separate low/review finding and allowDomains suppresses it", () => {
    const r = run([...BASE, f("slack.csv", SLACK)]);
    const fd = find(r, /External accounts in Slack/);
    assert.ok(fd); assert.equal(fd.severity, "low"); assert.equal(fd.evidence[0].domain, "agency-partner.example");
    assert.ok(!find(run([...BASE, f("slack.csv", SLACK)], { allowDomains: ["agency-partner.example"] }), /External accounts/));
  });
  test("licence waste counts seats and never invents a price", () => {
    const r = run([...BASE, f("m365.csv", M365)]);
    const fd = find(r, /Paid Microsoft 365 licences/);
    assert.ok(fd); assert.equal(fd.evidence.length, 2, "leaver Marcus + never-signed-in Sofia");
    assert.ok(/Enter a per-seat monthly cost/.test(fd.description)); assert.equal(r.summary.licenseWasteMonthly, null); assert.equal(r.summary.licenseWasteSeats, 2);
  });
  test("licence waste prices seats only with the entered cost", () => {
    const r = run([...BASE, f("m365.csv", M365)], { licenseCostMonthly: { "Microsoft 365": 36 } });
    assert.equal(r.summary.licenseWasteMonthly, 72);
    assert.equal(r.tables.apps.find((a) => a.app === "Microsoft 365").monthlyWaste, 72);
  });
  test("no licence column anywhere: license_waste skipped", () => {
    const r = run([...BASE, f("atlassian.csv", ATLASSIAN)]);
    assert.ok(skippedChecks(r).includes("license_waste"));
  });
  test("shared mailbox with sign-in enabled (Entra assignedLicenses) fires; disabled room is silent", () => {
    const r = run(BASE);
    const fd = find(r, /Shared mailbox or resource accounts/);
    assert.ok(fd); assert.equal(fd.evidence.length, 1); assert.equal(fd.evidence[0].account, "finance.shared@corp.com");
  });
  test("shared mailbox check also runs on the Microsoft 365 export when the IdP has no licence column", () => {
    const entra = ENTRA_CSV.split("\n").map((l) => l.split(",").slice(0, 7).join(",")).join("\n");
    const r = run([f("workday.csv", WORKDAY), f("entra.csv", entra), f("m365.csv", M365)]);
    const fd = find(r, /Shared mailbox or resource accounts/);
    assert.ok(fd); assert.equal(fd.evidence[0].source, "Microsoft 365");
    assert.ok(!skippedChecks(r).includes("shared_mailbox_signin"));
  });
});

group("jml: matching", () => {
  test("exact email is confirmed; UPN local-part is likely; near-identical name is review", () => {
    const slack = ["username,email,status,billing-active,has-2fa,has-sso,userid,fullname,displayname,expiration-timestamp",
      "m.reed,mreed@other-alias.corp.com,Member,1,1,1,U1,Marcus Reed,marcus,",       // name match (exact normalised)
      "marcusr,mr@legacy.corp,Member,1,1,1,U2,Marcus Read,m,",                       // local-part too short; name lev 1 -> review
      "dana,dana.kowalski@corp.com,Member,1,1,1,U3,Dana K,dana,"].join("\n");          // exact email
    const r = run([...BASE, f("slack.csv", slack)]);
    const marcus = r.tables.people.find((p) => p.person === "Marcus Reed");
    assert.ok(marcus.flags.includes("Slack match needs review"));
    const fd = find(r, /still active in Slack/);
    assert.equal(fd.confidence, "review");
    assert.equal(r.tables.people.find((p) => p.person === "Dana Kowalski").apps.length, 1);
  });
  test("local-part match only when it is unique", () => {
    const hr = WORKDAY + `\nE8,Dana Kowalski,dana.kowalski@corp.ie,${d(100)},,Yes,,Sales,AE,AE,Dublin`;
    const r = run([f("hr.csv", hr), f("entra.csv", ENTRA_CSV), f("gh.json", GITHUB_JSON)]);
    assert.equal(r.tables.apps.find((a) => a.app === "GitHub").total, 2);
    assert.equal(r.tables.people.filter((p) => p.person === "Dana Kowalski").length, 2);
  });
});

group("jml: contract", () => {
  test("constants and KINDS", () => {
    assert.equal(TOOL_ID, "jml"); assert.ok(/^\d+\.\d+\.\d+$/.test(VERSION));
    assert.deepEqual(KINDS, ["hr", "hr-changes", "idp", "saas", "devices", "ignore"]);
    assert.equal(DEFAULTS.disableSlaHours, 24); assert.equal(DEFAULTS.moverGraceDays, 14); assert.equal(DEFAULTS.joinerLeadDays, 7);
    assert.ok(COLUMNS.hr.termDate.includes("termination date"));
  });
  test("every finding carries controls, confidence class, recommendation, assets and evidenceCount", () => {
    const r = run([...BASE, f("slack.csv", SLACK), f("m365.csv", M365), f("changes.csv", CHANGES), f("intune.csv", INTUNE)]);
    assert.ok(r.findings.length >= 10);
    for (const x of r.findings) {
      assert.ok(x.controls.length >= 1, x.title); assert.ok(["confirmed", "likely", "review"].includes(x.confidence), x.title);
      assert.ok(x.recommendation && x.description, x.title); assert.ok(x.assets.length >= 1, x.title); assert.equal(typeof x.evidenceCount, "number", x.title);
      assert.ok(x.evidence.length <= 50);
    }
  });
  test("graph assets: IDENTITY per flagged person with status/termDate/apps, ASSET per app with kind saas-app", () => {
    const r = run([...BASE, f("slack.csv", SLACK)]);
    const idn = find(r, /still enabled in the IdP/).assets[0];
    assert.equal(idn.type, "IDENTITY"); assert.equal(idn.data.status, "terminated"); assert.equal(idn.data.termDate, d(5)); assert.ok(Array.isArray(idn.data.apps));
    const app = find(r, /still active in Slack/).assets.find((a) => a.type === "ASSET");
    assert.equal(app.data.kind, "saas-app"); assert.equal(app.data.users, 6);
  });
  test("files table records kind, app and confidence per input", () => {
    const r = run([...BASE, f("slack.csv", SLACK)]);
    assert.deepEqual(r.tables.files.map((x) => x.kind), ["hr", "idp", "saas"]);
    assert.equal(r.tables.files[2].app, "Slack");
  });
  test("edited kind/app and column overrides are honoured", () => {
    const p = parseInput([f("workday.csv", WORKDAY), f("entra.csv", ENTRA_CSV), f("list.csv", "mail,state,when\nmarcus.reed@corp.com,yes,2026-01-01")]);
    const lf = p.files[2]; lf.kind = "saas"; lf.app = "Acme"; lf.columns = { email: "mail", status: "state", lastLogin: "when" };
    const r = analyze(p, { now: NOW_ISO });
    assert.ok(find(r, /still active in Acme/));
    const ignored = parseInput([f("workday.csv", WORKDAY), f("entra.csv", ENTRA_CSV), f("slack.csv", SLACK)]);
    ignored.files[2].kind = "ignore";
    assert.equal(analyze(ignored, { now: NOW_ISO }).tables.apps.length, 0);
  });
  test("as-of date defaults to the latest timestamp in the data and ignores future hire dates", () => {
    const r = analyze(parseInput(BASE), {});
    assert.equal(r.meta.now, dt(1), "latest sign-in in the Entra export");
    assert.ok(new Date(r.meta.now).getTime() < NOW + 2 * DAY, "future hire date (Grace, +3 days) must not move the clock");
  });
  test("missing files are reported in skipped, never guessed", () => {
    const r = run([f("workday.csv", WORKDAY)]);
    assert.ok(skippedChecks(r).includes("leaver_idp_enabled")); assert.ok(skippedChecks(r).includes("leaver_saas_active")); assert.ok(skippedChecks(r).includes("leaver_device_active"));
    assert.ok(skippedChecks(run([f("slack.csv", SLACK)])).includes("all_hr_checks"));
  });
  test("progress callback is called and ends at total", () => {
    const calls = [];
    analyze(parseInput(BASE), { now: NOW_ISO }, { progress: (i, n, l) => calls.push([i, n, l]) });
    assert.ok(calls.length >= 2); const last = calls[calls.length - 1]; assert.equal(last[0], last[1]); assert.equal(last[2], "done");
  });
  test("analyze is deterministic (byte-identical JSON) across runs and input order", () => {
    const a = JSON.stringify(run([...BASE, f("slack.csv", SLACK), f("m365.csv", M365)]));
    const b = JSON.stringify(run([...BASE, f("slack.csv", SLACK), f("m365.csv", M365)]));
    assert.equal(a, b);
    const c = run([f("m365.csv", M365), f("slack.csv", SLACK), ...BASE]);
    assert.deepEqual(JSON.parse(a).findings.map((x) => x.title), c.findings.map((x) => x.title));
  });
  test("synthetic example is seeded, format-faithful and reproduces the headline detections", () => {
    const ex = exampleDataset();
    assert.equal(ex.files.length, 6); assert.ok(/synthetic/.test(ex.label));
    assert.ok(ex.files[0].text.startsWith("Employee ID,Worker,Email - Primary Work,Hire Date,Termination Date,Active Status,Manager,Cost Center,Job Title,Business Title,Location"));
    assert.ok(ex.files[3].text.startsWith("username,email,status,billing-active,has-2fa,has-sso,userid,fullname,displayname,expiration-timestamp"));
    assert.ok(ex.files[4].text.startsWith("Login,Name,Role,Two-factor,Saml identity"));
    assert.ok(ex.files[5].text.startsWith("Display name,User principal name,Licenses,Block credential,Last sign-in"));
    assert.equal(JSON.stringify(exampleDataset(7)), JSON.stringify(exampleDataset(7)));
    assert.notEqual(JSON.stringify(exampleDataset(7)), JSON.stringify(exampleDataset(8)));
    const r = analyze(parseInput(ex.files), {});
    assert.equal(r.summary.leavers, 3); assert.ok(find(r, /still enabled in the IdP/)); assert.ok(find(r, /Orphan accounts in Slack/)); assert.ok(find(r, /disabled later than the SLA/));
  });
  test("in-engine self-test passes", () => {
    const r = selfTest();
    assert.ok(r.pass, "failed: " + r.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });
  test("findingsToCsv header row and quoting", () => {
    const csv = findingsToCsv(run(BASE).findings);
    assert.equal(csv.split("\n")[0], "severity,confidence,category,title,description,recommendation,controls,evidenceCount");
    assert.ok(csv.split("\n").length > 1); assert.ok(/"critical"/.test(csv));
  });
  test("offboarding worklist CSV: person, app, action rows for leavers", () => {
    const csv = worklistCsv(run([...BASE, f("slack.csv", SLACK), f("m365.csv", M365)]));
    const lines = csv.split("\n");
    assert.equal(lines[0], "person,email,app,action,reason");
    assert.ok(lines.some((l) => /Marcus Reed.*Slack.*Deactivate account/.test(l)));
    assert.ok(lines.some((l) => /Marcus Reed.*IdP.*Disable account/.test(l)));
    assert.ok(lines.some((l) => /Marcus Reed.*Microsoft 365.*Reclaim licence/.test(l)));
    assert.ok(lines.some((l) => /jordan.blake@corp.com.*Find owner or deactivate/.test(l)));
  });
  test("SLA report CSV", () => {
    const csv = slaCsv(run([f("workday.csv", WORKDAY), f("okta.json", OKTA)]));
    const lines = csv.split("\n");
    assert.equal(lines[0], "leaver,terminated,disabledAt,hours,breach,status,idp");
    assert.ok(lines.some((l) => /yuki.tanaka@corp.com.*"72","yes","disabled","okta"/.test(l)));
  });
});
