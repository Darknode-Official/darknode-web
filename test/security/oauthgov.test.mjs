// OAuth App Governance engine tests (public/js/identity/oauthgov-engine.js).
// One parser fixture per vendor export in its exact layout, the scope risk table,
// every detection on a crafted positive and a silent negative, thresholds,
// skipped-check reporting, determinism and the export serialisers.

import { test, assert, group } from "../harness.mjs";
import {
  TOOL_ID, VERSION, COLUMNS, DEFAULTS, SCOPE_RISK, SCOPE_CLASSES, FORMATS, DETECTIONS, GRAPH_APP_ROLES, WELL_KNOWN_APPS,
  MS_GRAPH_APP_ID, MS_FIRST_PARTY_TENANT,
  parseInput, analyze, analyzeFiles, findingsToCsv, appsToCsv, revokeToCsv, summaryText, exampleDataset, selfTest,
  scopeRisk, elevate, lookalike, lookalikeBudget, parseTs, iso, classifyHeaders, classifyRecord, buildInventory,
} from "../../public/js/identity/oauthgov-engine.js";

// ---------------------------------------------------------------------------
// Fixtures in the exact vendor layouts
// ---------------------------------------------------------------------------
const GRAPH_SP = "11111111-aaaa-4bbb-8ccc-000000000001";
const sp = (over) => ({
  id: "22222222-aaaa-4bbb-8ccc-000000000002", appId: "33333333-aaaa-4bbb-8ccc-000000000003", displayName: "Acme Sync", appOwnerOrganizationId: "44444444-aaaa-4bbb-8ccc-000000000004",
  servicePrincipalType: "Application", accountEnabled: true, createdDateTime: "2026-01-10T10:00:00Z",
  verifiedPublisher: { displayName: null, verifiedPublisherId: null, addedDateTime: null }, publisherName: "Acme", signInAudience: "AzureADMultipleOrgs",
  appRoles: [], oauth2PermissionScopes: [], tags: ["WindowsAzureActiveDirectoryIntegratedApp"], homepage: "https://acme.example", replyUrls: ["https://acme.example/cb"], ...over,
});
const graphSp = () => sp({ id: GRAPH_SP, appId: MS_GRAPH_APP_ID, displayName: "Microsoft Graph", appOwnerOrganizationId: MS_FIRST_PARTY_TENANT, appRoles: [{ id: "7ab1d382-f21e-4acd-a863-ba3e13f7da61", value: "Directory.Read.All", displayName: "Read directory data" }] });
const grant = (over) => ({ id: "g1", clientId: "22222222-aaaa-4bbb-8ccc-000000000002", consentType: "AllPrincipals", principalId: null, resourceId: GRAPH_SP, scope: "User.Read openid profile", ...over });
const appRole = (over) => ({ id: "ar1", appRoleId: "7ab1d382-f21e-4acd-a863-ba3e13f7da61", principalId: "22222222-aaaa-4bbb-8ccc-000000000002", principalDisplayName: "Acme Sync", principalType: "ServicePrincipal", resourceId: GRAPH_SP, resourceDisplayName: "Microsoft Graph", createdDateTime: "2026-01-11T10:00:00Z", ...over });
const J = (v) => JSON.stringify(v);
const entraFiles = (sps, grants, roles) => [
  { name: "servicePrincipals.json", text: J({ "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#servicePrincipals", value: sps }) },
  grants && { name: "oauth2PermissionGrants.json", text: J({ value: grants }) },
  roles && { name: "appRoleAssignments.json", text: J({ value: roles }) },
].filter(Boolean);
const run = (files, opts = {}) => analyzeFiles(files, { now: "2026-10-01T00:00:00Z", ...opts });
const by = (r, check) => r.findings.filter((f) => f.check === check);

const ENTRA_CSV = [
  "Name,Application ID,Object ID,Created on,Homepage URL,Certificate expiry status,Application type",
  "Acme Sync,33333333-aaaa-4bbb-8ccc-000000000003,22222222-aaaa-4bbb-8ccc-000000000002,1/10/2026,https://acme.example,Current,Enterprise Applications",
  "Microsoft Teams,1fec8e78-bce4-4aaf-ab1b-5451cc387264,55555555-aaaa-4bbb-8ccc-000000000005,2/1/2023,https://teams.microsoft.com,None,Microsoft Applications",
].join("\r\n");
const SPSIGNIN_CSV = [
  "Date (UTC),Service principal name,Service principal ID,Resource,Status",
  "2026-03-01T08:00:00Z,Acme Sync,22222222-aaaa-4bbb-8ccc-000000000002,Microsoft Graph,Success",
  "2026-04-15T08:00:00Z,Acme Sync,22222222-aaaa-4bbb-8ccc-000000000002,Microsoft Graph,Success",
  "2026-09-30T08:00:00Z,Acme Sync,22222222-aaaa-4bbb-8ccc-000000000002,Microsoft Graph,Failure",
].join("\n");
const GOOGLE_CSV = [
  "App name,Client ID,App type,Verified,Access,Users",
  "PDF Merge Pro,884120077311-pdfmerge.apps.googleusercontent.com,Web application,No,Limited,6",
  "Grammar Helper,412093817263-ab3hu7e2.apps.googleusercontent.com,Web application,Yes,Trusted,48",
].join("\n");
const GOOGLE_TOKENS = J({ kind: "admin#reports#tokens", etag: "x", items: [
  { kind: "admin#reports#token", etag: "y", clientId: "884120077311-pdfmerge.apps.googleusercontent.com", displayText: "PDF Merge Pro", anonymous: false, nativeApp: false, userKey: "finance@darknode.ai", scopes: ["https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/userinfo.email"] },
  { kind: "admin#reports#token", etag: "z", clientId: "412093817263-ab3hu7e2.apps.googleusercontent.com", displayText: "Grammar Helper", anonymous: false, nativeApp: false, userKey: "test@darknode.ai", scopes: ["https://www.googleapis.com/auth/documents", "openid"] },
] });
const oktaApp = (over) => ({ id: "0oa1abcd2EFGHIJKL3m4", name: "oidc_client", label: "Expense Portal", status: "ACTIVE", lastUpdated: "2026-06-01T00:00:00.000Z", created: "2025-06-01T00:00:00.000Z", signOnMode: "OPENID_CONNECT",
  settings: { oauthClient: { client_uri: null, redirect_uris: ["https://expenses.example/cb"], response_types: ["code"], grant_types: ["authorization_code", "refresh_token"], application_type: "web" } }, ...over });
const OKTA_CSV = [
  "App name,Label,Status,Sign on mode,Created",
  "zoom,Zoom,ACTIVE,SAML 2.0,2024-02-02T00:00:00.000Z",
  "template_swa,Legacy Payroll Portal,ACTIVE,Secure Web Authentication,2023-02-02T00:00:00.000Z",
].join("\n");
const SLACK_CSV = [
  "App name,App ID,Installed by,Installation date,Scopes,Approved by,Status,Last used",
  "Channel Archiver,A08J2K3L4,ops@darknode.ai,2026-06-11,\"channels:history,files:read,users:read.email\",,Approved,2026-06-20",
  "Standup Bot,A0F7XDUAZ,test@darknode.ai,2026-03-02,\"chat:write,commands\",admin@darknode.ai,Approved,2026-09-28",
].join("\n");
const SLACK_JSON = J({ ok: true, approved_apps: [
  { app: { id: "A0F7XDUAZ", name: "Standup Bot", description: "", help_url: "", privacy_policy_url: "", app_homepage_url: "", app_directory_url: "", is_app_directory_approved: true, is_internal: false, additional_info: "" },
    scopes: [{ name: "chat:write", description: "Send messages", is_sensitive: false, token_type: "bot" }, { name: "weird:scope", description: "x", is_sensitive: true, token_type: "bot" }], date_updated: 1759000000, last_resolved_by: { actor_id: "U0ADMIN1", actor_type: "user" } },
] });
const ghInstall = (over) => ({ id: 90210, account: { login: "darknode-official", type: "Organization" }, app_slug: "deploy-bot", app_id: 4242, target_type: "Organization",
  permissions: { contents: "write", metadata: "read", pull_requests: "write" }, events: ["push"], repository_selection: "all", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-09-01T00:00:00Z", suspended_at: null, ...over });
const GH_INSTALL = J({ total_count: 1, installations: [ghInstall()] });
const GH_OAUTH_CSV = ["Application,Owner,Requested,Status", "Travis CI,travis-ci,2025-05-05,Approved", "Sketchy Linter,unknown-dev,2026-07-07,Denied"].join("\n");

// ---------------------------------------------------------------------------
group("oauthgov: parsers (vendor layouts)", () => {
  test("Entra servicePrincipals JSON ($metadata wrapper, value[])", () => {
    const p = parseInput({ name: "sp.json", text: J({ value: [sp(), graphSp()] }) });
    assert.equal(p.format, "entra-sp"); assert.equal(p.confidence, 1); assert.equal(p.rows.length, 2);
    assert.equal(p.rows[0]._type, "entra-sp");
  });
  test("Entra Enterprise applications CSV (portal export headers)", () => {
    const p = parseInput({ name: "apps.csv", text: ENTRA_CSV });
    assert.equal(p.format, "entra-sp-csv"); assert.equal(p.confidence, 1); assert.equal(p.rows.length, 2);
    assert.equal(p.rows[1]["Application type"], "Microsoft Applications");
  });
  test("Entra oauth2PermissionGrants JSON", () => {
    const p = parseInput(J({ value: [grant(), grant({ id: "g2", consentType: "Principal", principalId: "u1" })] }));
    assert.equal(p.format, "entra-grant"); assert.equal(p.rows.length, 2);
  });
  test("Entra appRoleAssignments JSON", () => {
    const p = parseInput(J({ value: [appRole()] }));
    assert.equal(p.format, "entra-approle"); assert.equal(p.rows[0].appRoleId, "7ab1d382-f21e-4acd-a863-ba3e13f7da61");
  });
  test("Entra service principal sign-in CSV", () => {
    const p = parseInput({ name: "spsignins.csv", text: SPSIGNIN_CSV });
    assert.equal(p.format, "entra-spsignin"); assert.equal(p.rows.length, 3);
  });
  test("Google third-party app access CSV", () => {
    const p = parseInput({ name: "g.csv", text: GOOGLE_CSV });
    assert.equal(p.format, "google-apps"); assert.equal(p.confidence, 1); assert.equal(p.rows[0].Verified, "No");
  });
  test("Google tokens.list JSON (items[] with kind admin#reports#token)", () => {
    const p = parseInput(GOOGLE_TOKENS);
    assert.equal(p.format, "google-token"); assert.equal(p.rows.length, 2); assert.equal(p.rows[0].scopes.length, 2);
  });
  test("Okta /api/v1/apps JSON (bare array)", () => {
    const p = parseInput(J([oktaApp(), oktaApp({ id: "0oa2", label: "Wiki", signOnMode: "SAML_2_0", settings: {} })]));
    assert.equal(p.format, "okta-app"); assert.equal(p.rows.length, 2);
  });
  test("Okta Apps CSV", () => {
    const p = parseInput({ name: "okta.csv", text: OKTA_CSV });
    assert.equal(p.format, "okta-csv"); assert.equal(p.rows[0]["Sign on mode"], "SAML 2.0");
  });
  test("Slack Manage apps CSV (quoted scope list)", () => {
    const p = parseInput({ name: "slack.csv", text: SLACK_CSV });
    assert.equal(p.format, "slack-csv"); assert.equal(p.rows[0].Scopes, "channels:history,files:read,users:read.email");
  });
  test("Slack admin.apps.approved.list JSON (approved_apps wrapper)", () => {
    const p = parseInput(SLACK_JSON);
    assert.equal(p.format, "slack-app"); assert.equal(p.rows[0].app.id, "A0F7XDUAZ");
  });
  test("GitHub installations JSON (installations wrapper)", () => {
    const p = parseInput(GH_INSTALL);
    assert.equal(p.format, "github-install"); assert.equal(p.rows[0].permissions.contents, "write");
  });
  test("GitHub third-party access CSV", () => {
    const p = parseInput({ name: "gh.csv", text: GH_OAUTH_CSV });
    assert.equal(p.format, "github-oauth"); assert.equal(p.rows.length, 2);
  });
  test("generic CSV is low confidence and maps through COLUMNS / opts.columns", () => {
    const text = "Tool,Vendor,Granted scopes,Approval\nMailThing,Someone,Mail.Read offline_access,user\n";
    const p = parseInput({ name: "x.csv", text });
    assert.equal(p.format, "generic"); assert.ok(p.confidence < 0.8);
    const r = analyze(p.rows, { columns: { appName: "Tool", publisher: "Vendor", scopes: "Granted scopes", consent: "Approval" } });
    assert.equal(r.tables.apps.length, 1);
    assert.equal(r.tables.apps[0].app, "MailThing"); assert.equal(r.tables.apps[0].maxRisk, "high"); assert.equal(r.tables.apps[0].consent, "user");
    assert.ok(Object.keys(COLUMNS).includes("appName"));
  });
  test("multi-file input tags each record with its file and reports per-file format", () => {
    const p = parseInput([...entraFiles([sp(), graphSp()], [grant()], [appRole()]), { name: "slack.csv", text: SLACK_CSV }]);
    assert.equal(p.format, "multi"); assert.equal(p.files.length, 4);
    assert.deepEqual(p.files.map((f) => f.format), ["entra-sp", "entra-grant", "entra-approle", "slack-csv"]);
    assert.ok(p.rows.every((r) => r._file));
  });
  test("empty and unreadable input never throws", () => {
    const p = parseInput("");
    assert.equal(p.rows.length, 0); assert.equal(p.format, "empty");
    const q = parseInput([{ name: "junk.bin", text: "\u0000\u0001\u0002" }, { name: "blank.csv", text: "   " }]);
    assert.equal(q.rows.length, 0); assert.ok(q.skipped.length >= 1);
    assert.equal(analyze(p.rows).findings.length, 0);
  });
  test("classifyHeaders / classifyRecord disambiguate shared 'App name' headers", () => {
    assert.equal(classifyHeaders(["App name", "Client ID", "App type", "Verified", "Access", "Users"]).format, "google-apps");
    assert.equal(classifyHeaders(["App name", "Label", "Status", "Sign on mode", "Created"]).format, "okta-csv");
    assert.equal(classifyHeaders(["App name", "App ID", "Installed by", "Installation date", "Scopes", "Approved by", "Status", "Last used"]).format, "slack-csv");
    assert.equal(classifyRecord(grant()), "entra-grant"); assert.equal(classifyRecord(appRole()), "entra-approle"); assert.equal(classifyRecord(sp()), "entra-sp");
    assert.equal(classifyRecord(oktaApp()), "okta-app"); assert.equal(classifyRecord(ghInstall()), "github-install");
  });
});

// ---------------------------------------------------------------------------
group("oauthgov: scope risk model", () => {
  const SPEC_SCOPES = [
    "Mail.ReadWrite", "Mail.Read", "Mail.Send", "MailboxSettings.ReadWrite", "Files.ReadWrite.All", "Files.Read.All", "Sites.ReadWrite.All", "Sites.FullControl.All",
    "Directory.ReadWrite.All", "Directory.Read.All", "User.ReadWrite.All", "User.Read.All", "Group.ReadWrite.All", "RoleManagement.ReadWrite.Directory", "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All", "Policy.ReadWrite.ConditionalAccess", "Chat.ReadWrite", "ChannelMessage.Read.All", "Calendars.ReadWrite", "Contacts.ReadWrite", "offline_access", "User.Read", "openid", "profile", "email",
    "https://mail.google.com/", "gmail.readonly", "gmail.modify", "gmail.send", "drive", "drive.readonly", "drive.file", "admin.directory.user", "admin.directory.group", "calendar", "contacts", "userinfo.email",
    "admin", "channels:history", "im:history", "files:read", "users:read.email", "chat:write",
    "contents:write", "administration:write", "members:write", "secrets:write", "actions:write",
  ];
  test("every scope in the brief has a known class and risk", () => {
    for (const s of SPEC_SCOPES) {
      const r = scopeRisk(s);
      assert.ok(r.known, "unknown scope " + s);
      assert.ok(SCOPE_CLASSES.includes(r.class), s + " class " + r.class);
      assert.ok(["critical", "high", "medium", "low"].includes(r.risk), s + " risk " + r.risk);
    }
    assert.ok(Object.values(SCOPE_RISK).every((e) => SCOPE_CLASSES.includes(e.class) && e.reason));
  });
  test("spot values: mail/files/directory/admin/basic", () => {
    assert.equal(scopeRisk("Mail.ReadWrite").risk, "critical"); assert.equal(scopeRisk("Mail.ReadWrite").class, "mail");
    assert.equal(scopeRisk("drive.file").risk, "low"); assert.equal(scopeRisk("userinfo.email").risk, "low");
    assert.equal(scopeRisk("https://www.googleapis.com/auth/gmail.readonly").risk, "high");
    assert.equal(scopeRisk("https://mail.google.com").risk, "critical", "trailing slash normalised");
    assert.equal(scopeRisk("admin").class, "admin"); assert.equal(scopeRisk("contents:write").class, "code");
    assert.equal(scopeRisk("offline_access").class, "basic"); assert.equal(scopeRisk("MAIL.READ").risk, "high", "case-insensitive");
  });
  test("application permissions are one level more severe; unknown scopes are medium/review", () => {
    assert.equal(elevate("low"), "medium"); assert.equal(elevate("high"), "critical"); assert.equal(elevate("critical"), "critical");
    assert.equal(scopeRisk("Directory.Read.All").risk, "high");
    assert.equal(scopeRisk("Directory.Read.All", "application").risk, "critical");
    const u = scopeRisk("Totally.Unknown.Scope");
    assert.equal(u.risk, "medium"); assert.equal(u.confidence, "review"); assert.equal(u.known, false); assert.equal(u.class, "unknown");
    assert.equal(scopeRisk("Totally.Unknown.Scope", "application").risk, "high");
    assert.equal(scopeRisk("weird:scope", "delegated", { sensitive: true }).risk, "high");
  });
  test("Graph appRoleId table resolves well-known application permissions", () => {
    assert.equal(GRAPH_APP_ROLES["7ab1d382-f21e-4acd-a863-ba3e13f7da61"], "Directory.Read.All");
    assert.equal(GRAPH_APP_ROLES["e2a3a72e-5f79-4c64-b1b1-878b674786c9"], "Mail.ReadWrite");
    assert.ok(Object.keys(GRAPH_APP_ROLES).every((k) => /^[0-9a-f-]{36}$/.test(k)));
  });
});

// ---------------------------------------------------------------------------
group("oauthgov: lookalike names", () => {
  test("edit distance within budget and foreign publisher fires; first-party and matching publisher stay silent", () => {
    assert.ok(lookalike({ name: "Micros0ft Teams", publisher: "Shady Corp", publisherVerified: false, firstParty: false }));
    assert.equal(lookalike({ name: "Microsoft Teams", publisher: "Microsoft", publisherVerified: true, firstParty: true }), null);
    assert.ok(lookalike({ name: "Salesforse", publisher: "", publisherVerified: null, firstParty: false }));
    assert.equal(lookalike({ name: "Salesforce", publisher: "Salesforce.com, inc.", publisherVerified: true, firstParty: false }), null);
    assert.equal(lookalike({ name: "Zoom", publisher: "Zoom Video Communications", publisherVerified: false, firstParty: false }), null);
  });
  test("short names need an exact match (budget scales with length) and OIN keys vouch for Okta/GitHub", () => {
    assert.equal(lookalikeBudget("Box"), 0); assert.equal(lookalikeBudget("Zoom"), 0); assert.equal(lookalikeBudget("Dropbox"), 1); assert.equal(lookalikeBudget("Microsoft Teams"), 2);
    assert.equal(lookalike({ name: "Zoon", publisher: "", publisherVerified: null, firstParty: false }), null);
    assert.equal(lookalike({ name: "Zoom", publisher: "", publisherVerified: null, firstParty: false, oinKey: "zoom" }), null);
    const m = lookalike({ name: "Zoom", publisher: "", publisherVerified: null, firstParty: false, oinKey: "oidc_client" });
    assert.ok(m && m.distance === 0);
    assert.ok(WELL_KNOWN_APPS.length >= 15);
  });
  test("brand words with a non-first-party owner fire with distance -1", () => {
    const m = lookalike({ name: "Outlook Mail Sync", publisher: "MailSync Labs", publisherVerified: false, firstParty: false });
    assert.ok(m && m.distance === -1 && m.target === "outlook");
    assert.equal(lookalike({ name: "Google Drive Backup", publisher: "Google LLC", publisherVerified: true, firstParty: false }), null);
    assert.ok(lookalike({ name: "Google Drive Backup", publisher: "BackupCo", publisherVerified: false, firstParty: false }));
  });
  test("detection: lookalike finding is high / review and silent for a verified brand", () => {
    const pos = run(entraFiles([sp({ displayName: "Micr0soft Teams", publisherName: "Shady" }), graphSp()], [grant()]));
    const f = by(pos, "lookalike_name");
    assert.equal(f.length, 1); assert.equal(f[0].severity, "high"); assert.equal(f[0].confidence, "review");
    const neg = run(entraFiles([sp({ displayName: "Microsoft Teams", appOwnerOrganizationId: MS_FIRST_PARTY_TENANT }), graphSp()], [grant()]));
    assert.equal(by(neg, "lookalike_name").length, 0);
  });
});

// ---------------------------------------------------------------------------
group("oauthgov: detections", () => {
  test("high_risk_scopes: delegated Mail.ReadWrite is critical with scope evidence; low-only app is silent", () => {
    const pos = run(entraFiles([sp(), graphSp()], [grant({ scope: "Mail.ReadWrite User.Read offline_access" })]));
    const f = by(pos, "high_risk_scopes");
    assert.equal(f.length, 1); assert.equal(f[0].severity, "critical"); assert.equal(f[0].confidence, "confirmed");
    assert.equal(f[0].evidence[0].scope, "Mail.ReadWrite"); assert.equal(f[0].evidence[0].class, "mail"); assert.equal(f[0].evidenceCount, 3);
    assert.ok(f[0].controls.length >= 1 && f[0].controls.some((c) => c.framework === "MITRE" && c.id === "T1528"));
    const neg = run(entraFiles([sp(), graphSp()], [grant({ scope: "User.Read openid profile offline_access" })]));
    assert.equal(by(neg, "high_risk_scopes").length, 0);
  });
  test("high_risk_scopes: app-only Directory.Read.All (appRoleAssignment) elevates to critical", () => {
    const r = run(entraFiles([sp(), graphSp()], [], [appRole()]));
    const f = by(r, "high_risk_scopes");
    assert.equal(f.length, 1); assert.equal(f[0].severity, "critical");
    assert.equal(f[0].evidence[0].kind, "application"); assert.equal(f[0].evidence[0].scope, "Directory.Read.All");
    assert.ok(/application permissions/.test(f[0].description));
  });
  test("appRoleAssignments: unresolved role id is review, Graph table resolves without the Graph SP, user assignments are not scopes", () => {
    const r = run(entraFiles([sp()], [], [appRole({ appRoleId: "e2a3a72e-5f79-4c64-b1b1-878b674786c9", resourceDisplayName: "Microsoft Graph" }), appRole({ id: "ar2", appRoleId: "deadbeef-0000-4000-8000-000000000000", resourceDisplayName: "Contoso API", resourceId: "99999999-aaaa-4bbb-8ccc-000000000009" }),
      appRole({ id: "ar3", principalType: "User", principalId: "u-77", resourceId: "22222222-aaaa-4bbb-8ccc-000000000002", appRoleId: "00000000-0000-0000-0000-000000000000" })]));
    const a = r.tables.apps.find((x) => x.app === "Acme Sync");
    assert.equal(a.scopes, 2); assert.equal(a.assignedUsers, 1);
    const sc = r.tables.scopes.filter((s) => s.app === "Acme Sync");
    assert.ok(sc.some((s) => s.scope === "Mail.ReadWrite" && s.kind === "application" && s.risk === "critical"));
    assert.ok(sc.some((s) => s.scope.startsWith("appRole:") && s.known === false && s.risk === "high"));
  });
  test("user_consent_high: Principal grants fire with one evidence row per user and IDENTITY assets; AllPrincipals is silent", () => {
    const pos = run(entraFiles([sp(), graphSp()], [grant({ id: "g1", consentType: "Principal", principalId: "u1", scope: "Mail.Read offline_access" }), grant({ id: "g2", consentType: "Principal", principalId: "u2", scope: "Mail.Read" })]));
    const f = by(pos, "user_consent_high");
    assert.equal(f.length, 1); assert.equal(f[0].severity, "high"); assert.equal(f[0].confidence, "confirmed"); assert.equal(f[0].evidenceCount, 2);
    assert.deepEqual(f[0].evidence.map((e) => e.consentingUser), ["u1", "u2"]);
    assert.deepEqual(f[0].assets.filter((a) => a.type === "IDENTITY").map((a) => a.name), ["u1", "u2"]);
    assert.equal(f[0].assets[0].type, "ASSET"); assert.equal(f[0].assets[0].data.kind, "oauth-app"); assert.equal(f[0].assets[0].data.consent, "user");
    assert.ok(/admin consent workflow/.test(f[0].recommendation));
    assert.equal(by(pos, "consent_workflow").length, 1);
    const neg = run(entraFiles([sp(), graphSp()], [grant({ consentType: "AllPrincipals", scope: "Mail.Read" })]));
    assert.equal(by(neg, "user_consent_high").length, 0); assert.equal(by(neg, "consent_workflow").length, 0);
  });
  test("user_consent_high: Google users without Trusted access are user consent; Trusted is admin", () => {
    const r = run([{ name: "g.csv", text: GOOGLE_CSV }, { name: "t.json", text: GOOGLE_TOKENS }]);
    const apps = Object.fromEntries(r.tables.apps.map((a) => [a.app, a]));
    assert.equal(apps["PDF Merge Pro"].consent, "user"); assert.equal(apps["PDF Merge Pro"].users, 6); assert.equal(apps["PDF Merge Pro"].maxRisk, "critical");
    assert.equal(apps["Grammar Helper"].consent, "admin"); assert.equal(apps["Grammar Helper"].users, 48);
    const f = by(r, "user_consent_high");
    assert.equal(f.length, 1); assert.equal(f[0].assets[0].name, "PDF Merge Pro"); assert.equal(f[0].confidence, "likely");
    assert.ok(/6 users/.test(f[0].description));
  });
  test("unverified_publisher: Entra null verifiedPublisher fires (review without tenant id, likely with), own tenant and first-party are excluded", () => {
    const files = entraFiles([sp(), graphSp()], [grant({ scope: "Files.Read.All User.Read" })]);
    const a = by(run(files), "unverified_publisher");
    assert.equal(a.length, 1); assert.equal(a[0].severity, "high"); assert.equal(a[0].confidence, "review");
    const b = by(run(files, { tenantId: "00000000-1111-2222-3333-444444444444" }), "unverified_publisher");
    assert.equal(b[0].confidence, "likely");
    assert.equal(by(run(files, { tenantId: "44444444-aaaa-4bbb-8ccc-000000000004" }), "unverified_publisher").length, 0, "own tenant excluded");
    const fp = run(entraFiles([sp({ appOwnerOrganizationId: MS_FIRST_PARTY_TENANT }), graphSp()], [grant({ scope: "Files.Read.All" })]));
    assert.equal(by(fp, "unverified_publisher").length, 0, "first-party excluded");
    const verified = run(entraFiles([sp({ verifiedPublisher: { displayName: "Acme Ltd", verifiedPublisherId: "123", addedDateTime: "2025-01-01T00:00:00Z" } }), graphSp()], [grant({ scope: "Files.Read.All" })]));
    assert.equal(by(verified, "unverified_publisher").length, 0);
    const lowOnly = run(entraFiles([sp(), graphSp()], [grant({ scope: "User.Read openid" })]));
    assert.equal(by(lowOnly, "unverified_publisher").length, 0, "needs medium+ scopes");
  });
  test("unverified_publisher: Google Verified=No with Drive access fires; Verified=Yes is silent", () => {
    const r = run([{ name: "g.csv", text: GOOGLE_CSV }, { name: "t.json", text: GOOGLE_TOKENS }]);
    const f = by(r, "unverified_publisher");
    assert.equal(f.length, 1); assert.equal(f[0].assets[0].name, "PDF Merge Pro"); assert.equal(f[0].confidence, "likely");
  });
  test("unused_broad: fires past the threshold, silent at exactly the threshold, honours opts.unusedDays", () => {
    const mk = (last) => entraFiles([sp({ signInActivity: { lastSignInDateTime: last } }), graphSp()], [grant({ scope: "Mail.Read" })]);
    assert.equal(by(run(mk("2026-07-02T00:00:00Z")), "unused_broad").length, 1, "91 days");
    assert.equal(by(run(mk("2026-07-03T00:00:00Z")), "unused_broad").length, 0, "exactly 90 days");
    assert.equal(by(run(mk("2026-09-20T00:00:00Z"), { unusedDays: 10 }), "unused_broad").length, 1, "11 days > 10");
    assert.equal(by(run(mk("2026-09-20T00:00:00Z"), { unusedDays: 30 }), "unused_broad").length, 0);
    assert.equal(DEFAULTS.unusedDays, 90);
  });
  test("unused_broad: skipped (not guessed) without last-used data; service principal sign-in CSV supplies it", () => {
    const none = run(entraFiles([sp(), graphSp()], [grant({ scope: "Mail.Read" })]));
    assert.equal(by(none, "unused_broad").length, 0);
    assert.ok(none.skipped.some((k) => k.check === "unused_broad" && /last-used/.test(k.reason)));
    const withLog = run([...entraFiles([sp(), graphSp()], [grant({ scope: "Mail.Read" })]), { name: "spsignins.csv", text: SPSIGNIN_CSV }]);
    const a = withLog.tables.apps.find((x) => x.app === "Acme Sync");
    assert.equal(a.lastUsed, "2026-04-15T08:00:00Z", "failures ignored, max success kept");
    assert.equal(by(withLog, "unused_broad").length, 1);
  });
  test("disabled_with_grants: disabled SP with a grant is low; enabled is silent", () => {
    const pos = run(entraFiles([sp({ accountEnabled: false }), graphSp()], [grant()]));
    const f = by(pos, "disabled_with_grants");
    assert.equal(f.length, 1); assert.equal(f[0].severity, "low");
    assert.equal(by(run(entraFiles([sp(), graphSp()], [grant()])), "disabled_with_grants").length, 0);
  });
  test("insecure_reply_url: http, localhost and wildcard fire; https-only is silent", () => {
    const pos = run(entraFiles([sp({ replyUrls: ["http://acme.example/cb", "https://localhost:3000/cb", "https://*.acme.example/cb", "https://acme.example/ok"] }), graphSp()]));
    const f = by(pos, "insecure_reply_url");
    assert.equal(f.length, 1); assert.equal(f[0].evidenceCount, 3); assert.equal(f[0].severity, "medium");
    assert.equal(by(run(entraFiles([sp(), graphSp()])), "insecure_reply_url").length, 0);
  });
  test("github_all_repos_write fires for all-repo write installs and stays silent for selected repos", () => {
    const pos = run([{ name: "inst.json", text: GH_INSTALL }]);
    const f = by(pos, "github_all_repos_write");
    assert.equal(f.length, 1); assert.equal(f[0].severity, "medium");
    assert.ok(pos.tables.apps[0].scopeClasses.includes("code"));
    const neg = run([{ name: "inst.json", text: J({ installations: [ghInstall({ repository_selection: "selected" })] }) }]);
    assert.equal(by(neg, "github_all_repos_write").length, 0);
    const ro = run([{ name: "inst.json", text: J({ installations: [ghInstall({ permissions: { contents: "read", metadata: "read" } })] }) }]);
    assert.equal(by(ro, "github_all_repos_write").length, 0);
  });
  test("okta_weak_grant: implicit grant and BROWSER_PLUGIN / SWA fire; OIDC code flow is silent", () => {
    const imp = run([{ name: "okta.json", text: J([oktaApp({ settings: { oauthClient: { grant_types: ["implicit"], redirect_uris: ["https://x.example/cb"] } } })]) }]);
    assert.equal(by(imp, "okta_weak_grant").length, 1);
    const swa = run([{ name: "okta.json", text: J([oktaApp({ signOnMode: "BROWSER_PLUGIN", settings: {} })]) }]);
    assert.equal(by(swa, "okta_weak_grant").length, 1);
    const csv = run([{ name: "okta.csv", text: OKTA_CSV }]);
    assert.equal(by(csv, "okta_weak_grant").length, 1); assert.equal(by(csv, "okta_weak_grant")[0].assets[0].name, "Legacy Payroll Portal");
    assert.equal(by(csv, "lookalike_name").length, 0, "OIN key zoom vouches for the Zoom label");
    assert.equal(by(run([{ name: "okta.json", text: J([oktaApp()]) }]), "okta_weak_grant").length, 0);
  });
  test("unsanctioned_apps: sanctioned list (name or client id) narrows the shadow-SaaS finding; confidence review when blank", () => {
    const files = [{ name: "g.csv", text: GOOGLE_CSV }, { name: "t.json", text: GOOGLE_TOKENS }];
    const blank = by(run(files), "unsanctioned_apps");
    assert.equal(blank.length, 1); assert.equal(blank[0].confidence, "review"); assert.equal(blank[0].evidenceCount, 2); assert.equal(blank[0].severity, "high");
    const narrowed = by(run(files, { sanctioned: ["pdf merge pro", "412093817263-ab3hu7e2.apps.googleusercontent.com"] }), "unsanctioned_apps");
    assert.equal(narrowed.length, 0);
    const half = run(files, { sanctioned: "Grammar Helper" });
    assert.equal(by(half, "unsanctioned_apps")[0].confidence, "likely"); assert.equal(by(half, "unsanctioned_apps")[0].evidence[0].app, "PDF Merge Pro");
    assert.equal(half.tables.apps.find((a) => a.app === "Grammar Helper").sanctioned, true);
    assert.equal(half.summary.unsanctioned, 1);
  });
  test("Slack: CSV without approver is user consent; JSON directory approval and sensitive unknown scopes", () => {
    const csv = run([{ name: "slack.csv", text: SLACK_CSV }]);
    const arch = csv.tables.apps.find((a) => a.app === "Channel Archiver"), bot = csv.tables.apps.find((a) => a.app === "Standup Bot");
    assert.equal(arch.consent, "user"); assert.equal(arch.maxRisk, "high"); assert.equal(bot.consent, "admin");
    assert.equal(by(csv, "user_consent_high").length, 1);
    assert.ok(csv.skipped.some((k) => k.check === "unverified_publisher" && /Slack/.test(k.reason)), "publisher data absent in CSV is reported");
    const json = run([{ name: "approved.json", text: SLACK_JSON }]);
    const j = json.tables.apps[0];
    assert.equal(j.publisherVerified, true); assert.equal(j.consent, "admin"); assert.equal(j.maxRisk, "high");
    assert.ok(json.tables.scopes.some((s) => s.scope === "weird:scope" && s.known === false && s.risk === "high"));
  });
  test("skipped reporting: no scope data and no consent data are declared, not guessed", () => {
    const r = run([{ name: "apps.csv", text: ENTRA_CSV }]);
    assert.equal(r.findings.filter((f) => f.check === "high_risk_scopes").length, 0);
    assert.ok(r.skipped.some((k) => k.check === "high_risk_scopes"));
    assert.ok(r.skipped.some((k) => k.check === "user_consent_high"));
    assert.ok(r.skipped.some((k) => k.check === "unverified_publisher"));
    assert.equal(r.tables.apps.find((a) => a.app === "Microsoft Teams").firstParty, true);
    const junk = analyze([{ foo: 1, bar: 2 }]);
    assert.ok(junk.skipped.some((k) => k.check === "all"));
  });
});

// ---------------------------------------------------------------------------
group("oauthgov: engine contract", () => {
  test("in-engine self-test passes", () => {
    const r = selfTest();
    assert.ok(r.pass, "failed: " + r.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
    assert.ok(r.tests.length >= 10);
  });
  test("analyze is byte-deterministic across runs and input order", () => {
    const { rows } = exampleDataset();
    const a = JSON.stringify(analyze(rows, { now: "2026-10-05T00:00:00Z" }));
    assert.equal(a, JSON.stringify(analyze(rows, { now: "2026-10-05T00:00:00Z" })));
    const shuffled = rows.slice().reverse();
    const b = analyze(shuffled, { now: "2026-10-05T00:00:00Z" });
    assert.deepEqual(b.findings.map((f) => f.id), JSON.parse(a).findings.map((f) => f.id));
  });
  test("example dataset is format-faithful and seeded", () => {
    const ex = exampleDataset(), ex2 = exampleDataset();
    assert.equal(ex.files.length, 6); assert.ok(/synthetic/.test(ex.label));
    assert.deepEqual(ex.parsed.files.map((f) => f.format), ["entra-sp", "entra-grant", "entra-approle", "google-apps", "google-token", "slack-csv"]);
    assert.ok(ex.files[3].text.startsWith("App name,Client ID,App type,Verified,Access,Users"));
    assert.ok(ex.files[5].text.startsWith("App name,App ID,Installed by,Installation date,Scopes,Approved by,Status,Last used"));
    assert.equal(ex.ids.SYNC, ex2.ids.SYNC);
    assert.ok(ex.rows.length === 23);
  });
  test("every finding carries the common shape: controls, confidence, recommendation, assets, capped evidence", () => {
    const r = analyze(exampleDataset().rows, { now: "2026-10-05T00:00:00Z" });
    assert.ok(r.findings.length >= 10);
    for (const f of r.findings) {
      assert.ok(["critical", "high", "medium", "low", "info"].includes(f.severity), f.title);
      assert.ok(["confirmed", "likely", "review"].includes(f.confidence), f.title);
      assert.ok(Array.isArray(f.controls) && f.controls.length >= 1 && f.controls.every((c) => c.framework && c.id), f.title);
      assert.ok(f.recommendation && f.description && f.id && f.check, f.title);
      assert.ok(Array.isArray(f.evidence) && f.evidence.length <= 50 && f.evidenceCount >= f.evidence.length, f.title);
      assert.ok(f.assets.every((a) => ["ASSET", "IDENTITY"].includes(a.type) && a.name), f.title);
    }
    assert.ok(DETECTIONS.length === 11 && DETECTIONS.every((d) => d.controls.length && d.needs));
  });
  test("summary KPIs and default reference date (latest timestamp in data)", () => {
    const r = analyze(exampleDataset().rows);
    assert.equal(r.summary.now, "2026-10-03T16:05:44Z");
    assert.equal(r.summary.apps, 11); assert.deepEqual(r.summary.sources, { entra: 6, google: 3, slack: 2 });
    for (const k of ["highRiskApps", "userConsentedHighRisk", "unverifiedPublishers", "unusedBroad", "unsanctioned"]) assert.ok(typeof r.summary[k] === "number", k);
    assert.equal(r.meta.tool, TOOL_ID); assert.equal(r.meta.version, VERSION); assert.equal(r.meta.rows, 23);
    assert.ok(Object.keys(FORMATS).length >= 13);
  });
  test("progress callback is invoked and optional", () => {
    const calls = [];
    const { rows } = exampleDataset();
    analyze(rows, {}, { progress: (i, n, l) => calls.push([i, n, l]) });
    assert.ok(calls.length >= 2); assert.equal(calls[calls.length - 1][0], rows.length);
    analyze(rows, {}, {}); analyze(rows, {}, null);
  });
  test("tables: inventory, scopes, revoke list with grant ids, consenting users", () => {
    const r = run(entraFiles([sp(), graphSp()], [grant({ id: "grant-A", consentType: "Principal", principalId: "u1", scope: "Mail.ReadWrite" }), grant({ id: "grant-B", consentType: "Principal", principalId: "u2", scope: "Mail.ReadWrite" })], [appRole({ id: "role-C" })]));
    const a = r.tables.apps.find((x) => x.app === "Acme Sync");
    assert.equal(a.grants, 3); assert.equal(a.consent, "mixed"); assert.equal(a.users, 2); assert.equal(a.consentingUsers, "u1 u2");
    assert.ok(a.findings.includes("high_risk_scopes") && a.findings.includes("user_consent_high"));
    const rv = r.tables.revoke.find((x) => x.app === "Acme Sync");
    assert.ok(rv && rv.grantIds.split(" ").sort().join(" ") === "grant-A grant-B role-C");
    assert.ok(r.tables.scopes.some((s) => s.scope === "Mail.ReadWrite" && s.grantIds === "grant-A grant-B"));
    assert.deepEqual(r.tables.users.map((u) => u.user), ["u1", "u2"]);
    assert.equal(r.tables.users[0].maxRisk, "critical");
  });
  test("parseTs is UTC-only: ISO, offsets, US dates, epoch seconds/ms, and rejects zone-less free text", () => {
    assert.equal(parseTs("2026-03-01T08:00:00Z"), Date.UTC(2026, 2, 1, 8));
    assert.equal(parseTs("2026-03-01T08:00:00"), Date.UTC(2026, 2, 1, 8), "no zone = UTC");
    assert.equal(parseTs("2026-03-01T08:00:00+02:00"), Date.UTC(2026, 2, 1, 6));
    assert.equal(parseTs("3/1/2026, 2:05:00 PM"), Date.UTC(2026, 2, 1, 14, 5));
    assert.equal(parseTs("3/1/2026"), Date.UTC(2026, 2, 1));
    assert.equal(parseTs(1759000000), 1759000000000); assert.equal(parseTs("1759000000000"), 1759000000000);
    assert.equal(parseTs("last Tuesday"), null); assert.equal(parseTs(""), null); assert.equal(parseTs(null), null);
    assert.equal(iso(Date.UTC(2026, 2, 1, 8)), "2026-03-01T08:00:00Z");
  });
  test("buildInventory merges servicePrincipals JSON and portal CSV for the same object id", () => {
    const p = parseInput([...entraFiles([sp()]), { name: "apps.csv", text: ENTRA_CSV }]);
    const inv = buildInventory(p.rows, { ...DEFAULTS }, null);
    const a = inv.apps.get("entra:22222222-aaaa-4bbb-8ccc-000000000002");
    assert.ok(a); assert.equal(a.name, "Acme Sync"); assert.equal(a.publisherVerified, false);
    assert.equal(inv.apps.size, 2);
  });
  test("buildInventory ignores a reserved-word appRoleId (prototype-key safety)", () => {
    // appRoleId "constructor" indexed GRAPH_APP_ROLES's inherited Object member before the
    // guard: the scope was garbled to "function Object(){…}" and the "not resolved" note lost.
    const p = parseInput(entraFiles([sp()], null, [appRole({ appRoleId: "constructor", resourceDisplayName: "" })]));
    const inv = buildInventory(p.rows, { ...DEFAULTS }, null);
    const a = inv.apps.get("entra:22222222-aaaa-4bbb-8ccc-000000000002");
    assert.ok(a);
    assert.ok(!(a.scopes || []).some((s) => /native code|object Object/.test(String(s && s.scope))));
    assert.ok([...(a.notes || [])].some((n) => /not resolved/.test(String(n))));
  });
  test("findingsToCsv / appsToCsv / revokeToCsv header rows and quoting", () => {
    const r = analyze(exampleDataset().rows, { now: "2026-10-05T00:00:00Z" });
    const csv = findingsToCsv(r.findings);
    assert.equal(csv.split("\n")[0], "severity,confidence,category,check,title,description,recommendation,controls,assets,evidenceCount");
    assert.equal(csv.split("\n").length, r.findings.length + 1);
    assert.ok(appsToCsv(r.tables.apps).startsWith("app,appId,objectId,source,publisher,publisherVerified,firstParty,enabled,consent,users,consentingUsers,scopes,scopeClasses,maxRisk,grants,lastUsed,firstSeen,sanctioned,flags,findings,notes"));
    assert.equal(appsToCsv(r.tables.apps).split("\n").length, r.tables.apps.length + 1);
    assert.equal(revokeToCsv(r.tables.revoke).split("\n")[0], "app,appId,objectId,source,grantIds,scopes,reasons");
    assert.ok(revokeToCsv([{ app: 'He said "hi"', appId: "", objectId: "", source: "x", grantIds: "", scopes: "", reasons: "" }]).includes('"He said ""hi"""'));
    assert.ok(/^OAuth App Governance summary/.test(summaryText(r)) && /Reference date: 2026-10-05T00:00:00Z/.test(summaryText(r)));
  });
  test("analyzeFiles merges parse skips and reports per-file formats", () => {
    const r = analyzeFiles([{ name: "slack.csv", text: SLACK_CSV }, { name: "empty.csv", text: "" }], { now: "2026-10-01T00:00:00Z" });
    assert.equal(r.files.length, 1); assert.equal(r.files[0].format, "slack-csv");
    assert.ok(r.skipped.some((k) => k.check === "parse" && /empty\.csv/.test(k.reason)));
    assert.equal(r.summary.apps, 2);
  });
});
