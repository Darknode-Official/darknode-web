// Conditional Access Audit engine tests (public/js/identity/caaudit-engine.js).
// Fixtures follow the exact vendor layouts: Graph conditionalAccess/policies JSON,
// Get-MgIdentityConditionalAccessPolicy | ConvertTo-Json (PascalCase), the Entra
// "User registration details" CSV export, Graph userRegistrationDetails JSON, Okta
// /api/v1/policies JSON (OKTA_SIGN_ON, MFA_ENROLL, bare rules) and the Google
// Workspace 2-Step Verification user report CSV (three header spellings).

import { test, assert, group } from "../harness.mjs";
import {
  TOOL_ID, VERSION, COLUMNS, DEFAULTS, KINDS, selfTest, analyze, parseInput, exampleDataset, findingsToCsv,
  policyMatrixCsv, noPhishingResistantCsv, classify, camelKeys, bool, splitList, isPhishingResistantMethod,
  isWeakDefaultMethod, isPhishingResistantStrength, normEntraPolicy, normOktaPolicy, MATRIX_COLS,
} from "../../public/js/identity/caaudit-engine.js";

const ids = (r, id) => r.findings.filter((f) => f.id === id);
const has = (r, id) => ids(r, id).length > 0;
const run = (files, opts) => analyze(parseInput(files), opts);

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------
const BG = ["a1b2c3d4-0000-4000-8000-000000000001", "a1b2c3d4-0000-4000-8000-000000000002"];
const GA_ROLE = "62e90394-69f5-4237-9190-012177145e10";

function entraPolicy(over = {}) {
  return {
    id: over.id || "p-" + (over.displayName || "x").replace(/\W+/g, "-").toLowerCase(),
    displayName: over.displayName || "Policy", createdDateTime: "2025-01-01T00:00:00Z", modifiedDateTime: null,
    state: over.state || "enabled",
    conditions: {
      users: { includeUsers: over.includeUsers || ["All"], excludeUsers: over.excludeUsers || [], includeGroups: over.includeGroups || [], excludeGroups: over.excludeGroups || [], includeRoles: over.includeRoles || [], excludeRoles: over.excludeRoles || [] },
      applications: { includeApplications: over.includeApplications || ["All"], excludeApplications: [], includeUserActions: [] },
      clientAppTypes: over.clientAppTypes || ["all"], platforms: null, locations: null,
      signInRiskLevels: over.signInRiskLevels || [], userRiskLevels: over.userRiskLevels || [], devices: null,
    },
    grantControls: over.grantControls === null ? null : { operator: "OR", builtInControls: over.builtInControls || ["mfa"], customAuthenticationFactors: [], termsOfUse: [], authenticationStrength: over.authenticationStrength || null },
    sessionControls: over.sessionControls || null,
  };
}
const graphJson = (policies) => JSON.stringify({ "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies", value: policies });

// Baseline healthy tenant: enforced all-users MFA, legacy block, risk, device, PR admins, sign-in frequency.
const GOOD_ENTRA = [
  entraPolicy({ displayName: "CA001 MFA all users", excludeUsers: BG, sessionControls: { signInFrequency: { value: 12, type: "hours", isEnabled: true }, persistentBrowser: { isEnabled: true, mode: "never" } } }),
  entraPolicy({ displayName: "CA002 Block legacy", clientAppTypes: ["exchangeActiveSync", "other"], builtInControls: ["block"], excludeUsers: BG }),
  entraPolicy({ displayName: "CA003 Risk", signInRiskLevels: ["high"], userRiskLevels: ["high"], builtInControls: ["block"] }),
  entraPolicy({ displayName: "CA004 Compliant device", includeUsers: [], includeRoles: [GA_ROLE], builtInControls: ["compliantDevice"] }),
  entraPolicy({ displayName: "CA005 PR admins", includeUsers: [], includeRoles: [GA_ROLE], builtInControls: [], authenticationStrength: { id: "00000000-0000-0000-0000-000000000004", displayName: "Phishing-resistant MFA", allowedCombinations: ["windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor"] } }),
];

const REG_HEAD = "Id,User principal name,User display name,Is admin,Is MFA capable,Is MFA registered,Is SSPR registered,Is SSPR enabled,Is SSPR capable,Is passwordless capable,Methods registered,Default MFA method,System preferred method,Last updated";
const regRow = (upn, name, admin, cap, reg, methods, def) => ["00000000-0000-0000-0000-00000000000" + (upn.length % 10), upn, name, admin, cap, reg, reg, "True", cap, "False", methods, def, "", "2026-02-01T10:00:00Z"].join(",");
const REG_CSV = [REG_HEAD,
  regRow("admin.fido@test.darknode.ai", "Admin Fido", "True", "True", "True", "fido2SecurityKey;microsoftAuthenticatorPush", "fido2SecurityKey"),
  regRow("admin.push@test.darknode.ai", "Admin Push", "True", "True", "True", "microsoftAuthenticatorPush;mobilePhone", "microsoftAuthenticatorPush"),
  regRow("admin.none@test.darknode.ai", "Admin None", "True", "False", "False", "", ""),
  regRow("user.sms@test.darknode.ai", "User Sms", "False", "True", "True", "mobilePhone", "mobilePhone"),
  regRow("user.none@test.darknode.ai", "User None", "False", "False", "False", "", ""),
  regRow("user.hello@test.darknode.ai", "User Hello", "False", "True", "True", "windowsHelloForBusiness;microsoftAuthenticatorPush", "windowsHelloForBusiness"),
  regRow("user.stuck@test.darknode.ai", "User Stuck", "False", "False", "True", "email", ""),
].join("\r\n") + "\r\n";

function oktaSignOn({ rules, name = "Default Policy", system = true, status = "ACTIVE" } = {}) {
  return { id: "00pdefault000000001", status, name, description: "The default policy applies in all situations if no other policy applies.", priority: 1, system, type: "OKTA_SIGN_ON",
    conditions: { people: { groups: { include: ["00geveryone00000001"] } } }, created: "2024-01-01T00:00:00.000Z", lastUpdated: "2026-01-01T00:00:00.000Z",
    _links: { self: { href: "https://example.okta.com/api/v1/policies/00pdefault000000001" } }, rules };
}
const oktaRule = (over = {}) => ({
  id: over.id || "0prrule000000000001", status: over.status || "ACTIVE", name: over.name || "Default Rule", priority: over.priority || 1, system: !!over.system, type: "SIGN_ON",
  conditions: { network: over.network || { connection: "ANYWHERE" }, authContext: { authType: over.authType || "ANY" }, people: { users: { exclude: over.usersExclude || [] } } },
  actions: { signon: { access: over.access || "ALLOW", requireFactor: over.requireFactor !== false, factorPromptMode: over.factorPromptMode || "ALWAYS", factorLifetime: over.factorLifetime ?? 0, primaryFactor: "PASSWORD_IDP_ANY_FACTOR", rememberDeviceByDefault: false,
    session: { usePersistentCookie: !!over.persistentCookie, maxSessionIdleMinutes: over.idle ?? 120, maxSessionLifetimeMinutes: over.lifetime ?? 0 } } },
});
const OKTA_GOOD = JSON.stringify([oktaSignOn({ rules: [oktaRule()] })]);

const oktaEnroll = (factors, status = "ACTIVE") => ({ id: "00pmfaenroll0000001", status, name: "Default Policy", priority: 1, system: true, type: "MFA_ENROLL",
  conditions: { people: { groups: { include: ["00geveryone00000001"] } } }, settings: { type: "FACTORS", factors } });

const GWS_HEAD = "User Name,Email,2-Step Verification Enrollment,2-Step Verification Enforcement,Admin Status,Last Login,Is Suspended";
const GWS_CSV = [GWS_HEAD,
  "Ana Admin,ana@test.darknode.ai,Enrolled,Enforced,Super Admin,2026-02-11T08:10:00Z,False",
  "Ben Admin,ben@test.darknode.ai,Not enrolled,Not enforced,Delegated Admin,2026-02-10T08:10:00Z,False",
  "Cy User,cy@test.darknode.ai,Not enrolled,Not enforced,None,2026-02-09T08:10:00Z,False",
  "Di User,di@test.darknode.ai,Enrolled,Not enforced,None,2026-02-08T08:10:00Z,False",
  "Ed Gone,ed@test.darknode.ai,Not enrolled,Not enforced,None,2025-01-01T00:00:00Z,True",
].join("\n") + "\n";

// ---------------------------------------------------------------------------
group("caaudit: engine basics", () => {
  test("exports and constants", () => {
    assert.equal(TOOL_ID, "caaudit");
    assert.ok(/^\d+\.\d+\.\d+$/.test(VERSION));
    assert.ok(COLUMNS.registration.upn.includes("User principal name"));
    assert.equal(DEFAULTS.breakGlassMax, 2);
  });

  test("in-engine self-test passes", () => {
    const r = selfTest();
    assert.ok(r.pass, "failed: " + r.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
    assert.ok(r.tests.length >= 10);
  });

  test("analyze is deterministic (byte-identical JSON)", () => {
    const ex = exampleDataset();
    assert.equal(JSON.stringify(analyze(ex.dataset)), JSON.stringify(analyze(ex.dataset)));
    const a = run([{ name: "z.json", text: graphJson(GOOD_ENTRA) }, { name: "a.csv", text: REG_CSV }]);
    const b = run([{ name: "a.csv", text: REG_CSV }, { name: "z.json", text: graphJson(GOOD_ENTRA) }]);
    assert.equal(JSON.stringify(a), JSON.stringify(b), "file order must not change the result");
  });

  test("empty input yields zero findings and does not throw", () => {
    const parsed = parseInput("");
    assert.equal(parsed.rows.length, 0);
    const r = analyze(parsed);
    assert.equal(r.findings.length, 0);
    assert.equal(r.meta.rows, 0);
    assert.equal(analyze([]).findings.length, 0);
    assert.equal(analyze(null).findings.length, 0);
  });

  test("invalid JSON is reported in skipped, never thrown", () => {
    const p = parseInput({ name: "bad.json", text: "{ this is not json" });
    assert.equal(p.sources[0].rows.length, 0);
    assert.ok(p.skipped.some((s) => s.check === "parse" && /invalid JSON/.test(s.reason)));
  });

  test("synthetic example is seeded and labelled", () => {
    const a = exampleDataset(7), b = exampleDataset(7), c = exampleDataset(8);
    assert.equal(a.files[0].text, b.files[0].text);
    assert.notEqual(a.files[0].text, c.files[0].text);
    assert.ok(/synthetic/.test(a.label));
    assert.equal(a.files.length, 3);
    assert.ok(a.files[1].text.startsWith(REG_HEAD), "registration CSV must carry the exact portal headers");
  });

  test("progress callback is called with totals", () => {
    const calls = [];
    analyze(exampleDataset().dataset, {}, { progress: (i, n, l) => calls.push([i, n, l]) });
    assert.ok(calls.length >= 2);
    const last = calls[calls.length - 1];
    assert.equal(last[0], last[1]);
    assert.equal(last[2], "done");
  });

  test("helpers: bool, splitList, camelKeys, method classes", () => {
    assert.equal(bool("True"), true); assert.equal(bool("Not enrolled"), false); assert.equal(bool("Enforced"), true); assert.equal(bool(""), null); assert.equal(bool("maybe"), null);
    assert.deepEqual(splitList("a;b, c|d"), ["a", "b", "c", "d"]);
    assert.deepEqual(splitList(["x", "y"]), ["x", "y"]);
    assert.deepEqual(camelKeys({ DisplayName: "x", Conditions: { Users: { IncludeUsers: ["All"] } } }), { displayName: "x", conditions: { users: { includeUsers: ["All"] } } });
    // A crafted "__proto__" key (JSON.parse makes it an OWN key) must not poison the output's prototype → fail-open.
    const poisoned = camelKeys(JSON.parse('{"displayName":"x","__proto__":{"grantControls":"PWNED"}}'));
    assert.equal(poisoned.displayName, "x");
    assert.equal(poisoned.grantControls, undefined);
    for (const m of ["fido2SecurityKey", "passKeyDeviceBound", "passKeyDeviceBoundAuthenticator", "windowsHelloForBusiness", "certificateBasedAuthentication"]) assert.ok(isPhishingResistantMethod(m), m);
    for (const m of ["microsoftAuthenticatorPush", "mobilePhone", "softwareOneTimePasscode", "email", "temporaryAccessPass"]) assert.notOk(isPhishingResistantMethod(m), m);
    assert.ok(isWeakDefaultMethod("mobilePhone")); assert.ok(isWeakDefaultMethod("email")); assert.notOk(isWeakDefaultMethod("microsoftAuthenticatorPush")); assert.notOk(isWeakDefaultMethod(""));
    assert.notOk(isWeakDefaultMethod("PhoneAppNotification")); assert.notOk(isWeakDefaultMethod("PhoneAppOTP")); assert.ok(isWeakDefaultMethod("phoneCall")); // legacy MSOL app methods are not weak phone defaults
    assert.ok(isPhishingResistantStrength({ id: "00000000-0000-0000-0000-000000000004", displayName: "", allowedCombinations: [] }));
    assert.ok(isPhishingResistantStrength({ id: "custom", displayName: "Keys only", allowedCombinations: ["fido2", "windowsHelloForBusiness"] }));
    assert.notOk(isPhishingResistantStrength({ id: "00000000-0000-0000-0000-000000000002", displayName: "Multifactor authentication", allowedCombinations: ["password,sms", "fido2"] }));
  });
});

// ---------------------------------------------------------------------------
group("caaudit: parsers (vendor fixtures)", () => {
  test("Entra Graph conditionalAccess/policies JSON is detected and normalised", () => {
    const p = parseInput({ name: "policies.json", text: graphJson(GOOD_ENTRA) });
    const s = p.sources[0];
    assert.equal(s.format, "json"); assert.equal(s.kind, KINDS.ENTRA_CA); assert.equal(s.kindConfidence, "high"); assert.equal(s.rows.length, 5);
    const n = normEntraPolicy(s.rows[0]);
    assert.equal(n.state, "enabled"); assert.ok(n.allUsers); assert.ok(n.allApps); assert.ok(n.requiresMfa); assert.notOk(n.blocks);
    assert.equal(n.sifHours, 12); assert.deepEqual(n.excludeUsers, BG);
  });

  test("Get-MgIdentityConditionalAccessPolicy | ConvertTo-Json (PascalCase) is tolerated", () => {
    const ps = JSON.stringify([{
      Id: "11111111-aaaa-4bbb-8ccc-000000000001", DisplayName: "Require MFA (PowerShell export)", State: "enabledForReportingButNotEnforced",
      Conditions: { Users: { IncludeUsers: ["All"], ExcludeUsers: [], IncludeGroups: [], ExcludeGroups: [], IncludeRoles: [], ExcludeRoles: [] }, Applications: { IncludeApplications: ["All"], ExcludeApplications: [] }, ClientAppTypes: ["browser", "mobileAppsAndDesktopClients"], SignInRiskLevels: [], UserRiskLevels: [] },
      GrantControls: { Operator: "OR", BuiltInControls: ["mfa"], AuthenticationStrength: null }, SessionControls: null,
    }]);
    const p = parseInput({ name: "ca.json", text: ps });
    assert.equal(p.sources[0].kind, KINDS.ENTRA_CA);
    const n = normEntraPolicy(p.sources[0].rows[0]);
    assert.equal(n.name, "Require MFA (PowerShell export)"); assert.equal(n.state, "report-only"); assert.ok(n.requiresMfa); assert.ok(n.allUsers);
    const r = analyze(p);
    assert.ok(has(r, "mfa_report_only")); assert.ok(has(r, "no_mfa_all_users"));
  });

  test("Entra User registration details CSV (portal headers, CRLF) is detected with high confidence", () => {
    const p = parseInput({ name: "UserRegistrationDetails.csv", text: REG_CSV });
    const s = p.sources[0];
    assert.equal(s.format, "csv"); assert.equal(s.kind, KINDS.ENTRA_REG); assert.equal(s.kindConfidence, "high"); assert.equal(s.rows.length, 7);
    assert.deepEqual(s.headers, REG_HEAD.split(","));
    const r = analyze(p);
    assert.equal(r.tables.registrations.length, 7);
    assert.equal(r.tables.registrations[0].upn, "admin.fido@test.darknode.ai");
    assert.ok(r.tables.registrations[0].phishingResistant);
  });

  test("Graph reports/authenticationMethods/userRegistrationDetails JSON works via the same path", () => {
    const j = JSON.stringify({ value: [
      { id: "u1", userPrincipalName: "a@test.darknode.ai", userDisplayName: "A", isAdmin: true, isMfaRegistered: true, isMfaCapable: true, methodsRegistered: ["microsoftAuthenticatorPush", "mobilePhone"], defaultMfaMethod: "mobilePhone", lastUpdatedDateTime: "2026-01-01T00:00:00Z" },
      { id: "u2", userPrincipalName: "b@test.darknode.ai", userDisplayName: "B", isAdmin: false, isMfaRegistered: false, isMfaCapable: false, methodsRegistered: [], defaultMfaMethod: "none", lastUpdatedDateTime: "2026-01-01T00:00:00Z" },
    ] });
    const p = parseInput({ name: "reg.json", text: j });
    assert.equal(p.sources[0].kind, KINDS.ENTRA_REG);
    const r = analyze(p);
    assert.ok(has(r, "admin_no_phishing_resistant"));
    assert.ok(has(r, "users_not_mfa_registered"));
    assert.equal(r.tables.registrations[0].methods, "microsoftAuthenticatorPush; mobilePhone");
  });

  test("Okta /api/v1/policies?type=OKTA_SIGN_ON JSON with inline rules is detected", () => {
    const p = parseInput({ name: "okta.json", text: OKTA_GOOD });
    assert.equal(p.sources[0].kind, KINDS.OKTA); assert.equal(p.sources[0].kindConfidence, "high");
    const n = normOktaPolicy(p.sources[0].rows[0]);
    assert.equal(n.type, "OKTA_SIGN_ON"); assert.ok(n.everyone); assert.equal(n.rules.length, 1); assert.ok(n.rules[0].requireFactor); assert.equal(n.rules[0].network.connection, "ANYWHERE");
  });

  test("Okta expand=rules (_embedded.rules) and bare rules arrays are both accepted", () => {
    const emb = { ...oktaSignOn({ rules: undefined }) }; delete emb.rules; emb._embedded = { rules: [oktaRule()] };
    const n = normOktaPolicy(emb);
    assert.equal(n.rules.length, 1);
    const bare = parseInput({ name: "rules.json", text: JSON.stringify([oktaRule({ requireFactor: false, name: "Open" }), oktaRule({ name: "Factor", priority: 2 })]) });
    assert.equal(bare.sources[0].kind, KINDS.OKTA);
    const r = analyze(bare);
    assert.ok(has(r, "okta_allow_without_factor"));
    assert.equal(r.summary.okta.rules, 2);
  });

  test("Okta MFA_ENROLL policy JSON is detected and its authenticators tabulated", () => {
    const p = parseInput({ name: "enroll.json", text: JSON.stringify([oktaEnroll({ okta_verify: { enroll: { self: "REQUIRED" } }, okta_sms: { enroll: { self: "OPTIONAL" } } })]) });
    assert.equal(p.sources[0].kind, KINDS.OKTA);
    const r = analyze(p);
    assert.equal(r.tables.oktaEnrollment.length, 2);
    assert.deepEqual(r.tables.oktaEnrollment.map((e) => e.authenticator), ["okta_sms", "okta_verify"]);
    assert.notOk(has(r, "okta_mfa_enroll_optional"));
  });

  test("Google Workspace 2SV report CSV (Admin console headers) is detected", () => {
    const p = parseInput({ name: "Users.csv", text: GWS_CSV });
    const s = p.sources[0];
    assert.equal(s.kind, KINDS.GOOGLE); assert.equal(s.kindConfidence, "high"); assert.equal(s.rows.length, 5);
    assert.deepEqual(s.headers, GWS_HEAD.split(","));
    const r = analyze(p);
    assert.equal(r.tables.googleUsers.length, 5);
    assert.equal(r.summary.google.active, 4);
  });

  test("Google alternate header spellings (2SV Enrollment / 2sv_enrolled) are detected", () => {
    const a = parseInput({ name: "a.csv", text: "Email,2SV Enrollment,2SV Enforcement,Admin Status\nx@test.darknode.ai,Not enrolled,Not enforced,None\n" });
    assert.equal(a.sources[0].kind, KINDS.GOOGLE);
    const b = parseInput({ name: "b.csv", text: "user_email,2sv_enrolled,2sv_enforced,is_admin,is_suspended\ny@test.darknode.ai,false,false,true,false\n" });
    assert.equal(b.sources[0].kind, KINDS.GOOGLE);
    const r = analyze(b);
    assert.ok(has(r, "google_admin_no_2sv"));
  });

  test("classify() returns unknown for unrelated tables and reports it", () => {
    assert.equal(classify(["timestamp", "actor"], [{ timestamp: "x", actor: "y" }]).kind, KINDS.UNKNOWN);
    const r = analyze([{ timestamp: "2026-01-01", actor: "bob" }]);
    assert.ok(r.skipped.some((s) => s.check === "classify"));
    assert.equal(r.findings.length, 0);
  });

  test("multiple files of different kinds are parsed into separate sources sorted by name", () => {
    const p = parseInput([{ name: "okta.json", text: OKTA_GOOD }, { name: "ca.json", text: graphJson(GOOD_ENTRA) }, { name: "reg.csv", text: REG_CSV }, { name: "gws.csv", text: GWS_CSV }]);
    assert.deepEqual(p.sources.map((s) => s.name), ["ca.json", "gws.csv", "okta.json", "reg.csv"]);
    assert.equal(p.format, "multi");
    assert.deepEqual(p.sources.map((s) => s.kind), [KINDS.ENTRA_CA, KINDS.GOOGLE, KINDS.OKTA, KINDS.ENTRA_REG]);
    const r = analyze(p);
    assert.equal(r.skipped.filter((s) => /no .* loaded/.test(s.reason)).length, 0, "nothing should be skipped for a missing input when all four are present");
  });
});

// ---------------------------------------------------------------------------
group("caaudit: Entra detections", () => {
  const good = () => run({ name: "ca.json", text: graphJson(GOOD_ENTRA) });

  test("healthy tenant: no MFA, legacy, risk, device, PR-admin or session findings", () => {
    const r = good();
    for (const id of ["no_mfa_all_users", "legacy_auth_not_blocked", "mfa_report_only", "no_risk_policy", "no_device_compliance", "no_phishing_resistant_admin_policy", "entra_no_signin_frequency", "entra_persistent_browser", "broad_exclusions", "disabled_security_policy"]) assert.notOk(has(r, id), id + " should not fire");
    assert.equal(r.summary.entra.mfaAllUsers, 1); assert.equal(r.summary.entra.legacyBlocked, 1);
  });

  test("no_mfa_all_users fires when the only MFA policy targets a group, and is critical", () => {
    const r = run({ name: "ca.json", text: graphJson([entraPolicy({ displayName: "MFA for Sales", includeUsers: [], includeGroups: ["g1"] })]) });
    const f = ids(r, "no_mfa_all_users");
    assert.equal(f.length, 1); assert.equal(f[0].severity, "critical"); assert.equal(f[0].confidence, "likely");
    assert.ok(f[0].controls.some((c) => c.framework === "CIS M365" && c.id === "5.2.2.2"));
    assert.ok(f[0].controls.some((c) => c.framework === "CISA SCuBA" && c.id === "MS.AAD.3.2"));
    assert.equal(f[0].assets[0].type, "ASSET"); assert.equal(f[0].assets[0].data.kind, "ca-policy");
  });

  test("a block policy with mfa-like scope does not count as MFA coverage", () => {
    const r = run({ name: "ca.json", text: graphJson([entraPolicy({ displayName: "Block all", builtInControls: ["block"] })]) });
    assert.ok(has(r, "no_mfa_all_users"));
  });

  test("authentication strength alone satisfies the all-users MFA requirement", () => {
    const r = run({ name: "ca.json", text: graphJson([entraPolicy({ displayName: "Strength", builtInControls: [], authenticationStrength: { id: "00000000-0000-0000-0000-000000000002", displayName: "Multifactor authentication", allowedCombinations: ["fido2", "password,sms"] } })]) });
    assert.notOk(has(r, "no_mfa_all_users"));
  });

  test("legacy_auth_not_blocked: fires when absent, report-only, or scoped to a group; silent when enforced for All", () => {
    const none = run({ name: "ca.json", text: graphJson([GOOD_ENTRA[0]]) });
    assert.ok(has(none, "legacy_auth_not_blocked"));
    const ro = run({ name: "ca.json", text: graphJson([GOOD_ENTRA[0], entraPolicy({ displayName: "Block legacy RO", state: "enabledForReportingButNotEnforced", clientAppTypes: ["exchangeActiveSync", "other"], builtInControls: ["block"] })]) });
    const f = ids(ro, "legacy_auth_not_blocked");
    assert.equal(f.length, 1); assert.ok(/Report-only/.test(f[0].description)); assert.equal(f[0].evidenceCount, 1);
    assert.ok(f[0].controls.some((c) => c.id === "5.2.2.3") && f[0].controls.some((c) => c.id === "MS.AAD.1.1") && f[0].controls.some((c) => c.id === "T1110"));
    const grp = run({ name: "ca.json", text: graphJson([GOOD_ENTRA[0], entraPolicy({ displayName: "Block legacy group", includeUsers: [], includeGroups: ["g"], clientAppTypes: ["exchangeActiveSync", "other"], builtInControls: ["block"] })]) });
    assert.ok(/not target All users/.test(ids(grp, "legacy_auth_not_blocked")[0].description));
    assert.notOk(has(good(), "legacy_auth_not_blocked"));
  });

  test("mfa_report_only fires only when every MFA policy is report-only", () => {
    const all = run({ name: "ca.json", text: graphJson([entraPolicy({ displayName: "A", state: "enabledForReportingButNotEnforced" }), entraPolicy({ displayName: "B", state: "enabledForReportingButNotEnforced", includeUsers: [], includeRoles: [GA_ROLE] })]) });
    assert.equal(ids(all, "mfa_report_only").length, 1); assert.equal(ids(all, "mfa_report_only")[0].severity, "medium"); assert.equal(ids(all, "mfa_report_only")[0].evidenceCount, 2);
    const mixed = run({ name: "ca.json", text: graphJson([GOOD_ENTRA[0], entraPolicy({ displayName: "B", state: "enabledForReportingButNotEnforced" })]) });
    assert.notOk(has(mixed, "mfa_report_only"));
  });

  test("disabled_security_policy is low and lists only security-relevant disabled policies", () => {
    const r = run({ name: "ca.json", text: graphJson(GOOD_ENTRA.concat([
      entraPolicy({ displayName: "Old MFA policy", state: "disabled" }),
      entraPolicy({ displayName: "Terms of use banner", state: "disabled", builtInControls: [] , grantControls: null }),
    ])) });
    const f = ids(r, "disabled_security_policy");
    assert.equal(f.length, 1); assert.equal(f[0].severity, "low"); assert.equal(f[0].evidenceCount, 1); assert.equal(f[0].evidence[0].policy, "Old MFA policy");
  });

  test("broad_exclusions: excludeUsers threshold edge (2 passes, 3 fires) and the breakGlassMax option", () => {
    const two = run({ name: "ca.json", text: graphJson([entraPolicy({ displayName: "MFA", excludeUsers: BG })]) });
    assert.notOk(has(two, "broad_exclusions"));
    const three = run({ name: "ca.json", text: graphJson([entraPolicy({ displayName: "MFA", excludeUsers: BG.concat(["a1b2c3d4-0000-4000-8000-000000000003"]) })]) });
    const f = ids(three, "broad_exclusions");
    assert.equal(f.length, 1); assert.equal(f[0].confidence, "confirmed"); assert.ok(/3 excluded users/.test(f[0].description));
    assert.equal(f[0].assets.filter((a) => a.type === "IDENTITY").length, 3);
    const relaxed = run({ name: "ca.json", text: graphJson([entraPolicy({ displayName: "MFA", excludeUsers: BG.concat(["a1b2c3d4-0000-4000-8000-000000000003"]) })]) }, { breakGlassMax: 3 });
    assert.notOk(has(relaxed, "broad_exclusions"));
  });

  test("broad_exclusions: excluded groups on the all-users MFA policy and excluded roles anywhere", () => {
    const grp = run({ name: "ca.json", text: graphJson([entraPolicy({ displayName: "MFA", excludeGroups: ["g1"] })]) });
    assert.ok(/excluded group on an all-users MFA policy/.test(ids(grp, "broad_exclusions")[0].description));
    assert.equal(ids(grp, "broad_exclusions")[0].confidence, "likely");
    const role = run({ name: "ca.json", text: graphJson([entraPolicy({ displayName: "Block legacy", clientAppTypes: ["exchangeActiveSync", "other"], builtInControls: ["block"], excludeRoles: [GA_ROLE] })]) });
    assert.ok(/excluded directory role/.test(ids(role, "broad_exclusions")[0].description));
    const scoped = run({ name: "ca.json", text: graphJson([entraPolicy({ displayName: "MFA group", includeUsers: [], includeGroups: ["g"], excludeGroups: ["g2"] })]) });
    assert.notOk(has(scoped, "broad_exclusions"), "excluded groups on a group-scoped policy are not flagged");
  });

  test("no_phishing_resistant_admin_policy, no_risk_policy and no_device_compliance are review-confidence absences", () => {
    const r = run({ name: "ca.json", text: graphJson([GOOD_ENTRA[0], GOOD_ENTRA[1]]) });
    for (const id of ["no_phishing_resistant_admin_policy", "no_risk_policy", "no_device_compliance"]) {
      const f = ids(r, id); assert.equal(f.length, 1, id); assert.equal(f[0].confidence, "review", id); assert.equal(f[0].severity, "medium", id);
    }
    assert.ok(ids(r, "no_risk_policy")[0].controls.some((c) => c.id === "MS.AAD.2.1"));
    assert.ok(ids(r, "no_device_compliance")[0].controls.some((c) => c.id === "MS.AAD.3.7"));
    assert.ok(ids(r, "no_phishing_resistant_admin_policy")[0].controls.some((c) => c.id === "MS.AAD.3.6"));
    const ro = run({ name: "ca.json", text: graphJson([GOOD_ENTRA[0], GOOD_ENTRA[1], entraPolicy({ displayName: "Risk RO", state: "enabledForReportingButNotEnforced", signInRiskLevels: ["high"], builtInControls: ["block"] })]) });
    assert.ok(has(ro, "no_risk_policy"), "a report-only risk policy does not count");
  });

  test("session: persistent browser always, long sign-in frequency and missing frequency", () => {
    const pb = run({ name: "ca.json", text: graphJson([entraPolicy({ displayName: "MFA", sessionControls: { persistentBrowser: { isEnabled: true, mode: "always" }, signInFrequency: null } })]) });
    assert.equal(ids(pb, "entra_persistent_browser").length, 1); assert.ok(has(pb, "entra_no_signin_frequency"));
    assert.ok(ids(pb, "entra_persistent_browser")[0].controls.some((c) => c.id === "5.2.2.4"));
    const long = run({ name: "ca.json", text: graphJson([entraPolicy({ displayName: "MFA", sessionControls: { signInFrequency: { value: 30, type: "days", isEnabled: true } } })]) });
    assert.equal(ids(long, "entra_long_signin_frequency").length, 1); assert.ok(/720 hours/.test(ids(long, "entra_long_signin_frequency")[0].description)); assert.notOk(has(long, "entra_no_signin_frequency"));
    const edge = run({ name: "ca.json", text: graphJson([entraPolicy({ displayName: "MFA", sessionControls: { signInFrequency: { value: 12, type: "hours", isEnabled: true } } })]) });
    assert.notOk(has(edge, "entra_long_signin_frequency"), "12 h equals the default threshold and passes");
    const disabledSif = run({ name: "ca.json", text: graphJson([entraPolicy({ displayName: "MFA", sessionControls: { signInFrequency: { value: 1, type: "hours", isEnabled: false } } })]) });
    assert.ok(has(disabledSif, "entra_no_signin_frequency"), "isEnabled=false is not a frequency");
  });

  test("policy coverage matrix lists every Entra policy with state and grant", () => {
    const r = good();
    assert.equal(r.tables.policies.length, 5);
    const row = r.tables.policies.find((p) => p.policy === "CA002 Block legacy");
    assert.equal(row.state, "enabled"); assert.equal(row.grant, "block"); assert.equal(row.clientApps, "exchangeActiveSync; other"); assert.equal(row.includedUsers, "All users");
    assert.ok(/Phishing-resistant MFA \(phishing-resistant\)/.test(r.tables.policies.find((p) => p.policy === "CA005 PR admins").grant));
  });
});

// ---------------------------------------------------------------------------
group("caaudit: registration detections", () => {
  const reg = () => run({ name: "reg.csv", text: REG_CSV });

  test("admin_no_phishing_resistant: high, confirmed, cites SCuBA MS.AAD.3.6 and names the admins", () => {
    const f = ids(reg(), "admin_no_phishing_resistant");
    assert.equal(f.length, 1); assert.equal(f[0].severity, "high"); assert.equal(f[0].confidence, "confirmed"); assert.equal(f[0].evidenceCount, 2);
    assert.deepEqual(f[0].assets.map((a) => a.name), ["admin.none@test.darknode.ai", "admin.push@test.darknode.ai"]);
    assert.ok(f[0].assets.every((a) => a.type === "IDENTITY"));
    assert.ok(f[0].controls.some((c) => c.id === "MS.AAD.3.6") && f[0].controls.some((c) => c.framework === "NIST SP 800-63B"));
  });

  test("admin_not_mfa_registered is critical; users_not_mfa_registered counts non-admins only", () => {
    const r = reg();
    const a = ids(r, "admin_not_mfa_registered"); assert.equal(a.length, 1); assert.equal(a[0].severity, "critical"); assert.equal(a[0].evidence[0].user, "admin.none@test.darknode.ai");
    const u = ids(r, "users_not_mfa_registered"); assert.equal(u.length, 1); assert.equal(u[0].evidenceCount, 1); assert.equal(u[0].evidence[0].user, "user.none@test.darknode.ai");
  });

  test("users_not_mfa_registered severity rises to high at 25% of users", () => {
    const many = [REG_HEAD, regRow("a@test.darknode.ai", "A", "False", "True", "True", "microsoftAuthenticatorPush", "microsoftAuthenticatorPush"), regRow("b@test.darknode.ai", "B", "False", "False", "False", "", ""), regRow("c@test.darknode.ai", "C", "False", "False", "False", "", ""), regRow("d@test.darknode.ai", "D", "False", "True", "True", "microsoftAuthenticatorPush", "microsoftAuthenticatorPush")].join("\n");
    assert.equal(ids(run({ name: "r.csv", text: many }), "users_not_mfa_registered")[0].severity, "high");
    const few = [REG_HEAD, regRow("a@test.darknode.ai", "A", "False", "True", "True", "microsoftAuthenticatorPush", "microsoftAuthenticatorPush"), regRow("b@test.darknode.ai", "B", "False", "False", "False", "", ""), regRow("c@test.darknode.ai", "C", "False", "True", "True", "microsoftAuthenticatorPush", "microsoftAuthenticatorPush"), regRow("d@test.darknode.ai", "D", "False", "True", "True", "microsoftAuthenticatorPush", "microsoftAuthenticatorPush"), regRow("e@test.darknode.ai", "E", "False", "True", "True", "microsoftAuthenticatorPush", "microsoftAuthenticatorPush")].join("\n");
    assert.equal(ids(run({ name: "r.csv", text: few }), "users_not_mfa_registered")[0].severity, "medium");
  });

  test("users_registered_not_capable and weak_default_method (SMS default) fire with correct counts", () => {
    const r = reg();
    const nc = ids(r, "users_registered_not_capable"); assert.equal(nc.length, 1); assert.equal(nc[0].evidence[0].user, "user.stuck@test.darknode.ai"); assert.equal(nc[0].severity, "low");
    const wd = ids(r, "weak_default_method"); assert.equal(wd.length, 1); assert.equal(wd[0].evidenceCount, 1); assert.equal(wd[0].severity, "medium");
    assert.ok(wd[0].controls.some((c) => c.id === "MS.AAD.3.5"));
    const adminSms = run({ name: "r.csv", text: [REG_HEAD, regRow("a@test.darknode.ai", "A", "True", "True", "True", "mobilePhone", "mobilePhone")].join("\n") });
    assert.equal(ids(adminSms, "weak_default_method")[0].severity, "high");
  });

  test("registration negatives: fully phishing-resistant tenant produces no registration findings", () => {
    const r = run({ name: "r.csv", text: [REG_HEAD, regRow("a@test.darknode.ai", "A", "True", "True", "True", "fido2SecurityKey", "fido2SecurityKey"), regRow("b@test.darknode.ai", "B", "False", "True", "True", "passKeyDeviceBound;microsoftAuthenticatorPush", "passKeyDeviceBound")].join("\n") });
    for (const id of ["admin_no_phishing_resistant", "admin_not_mfa_registered", "users_not_mfa_registered", "users_registered_not_capable", "weak_default_method"]) assert.notOk(has(r, id), id);
    assert.equal(r.summary.registration.adminsPhishingResistant, 1);
  });

  test("missing columns are skipped with a reason, never guessed", () => {
    const r = run({ name: "r.csv", text: "User principal name,Is MFA registered\na@test.darknode.ai,False\nb@test.darknode.ai,True\n" });
    assert.ok(r.skipped.some((s) => s.check === "admin_registration"));
    assert.ok(r.skipped.some((s) => s.check === "admin_no_phishing_resistant"));
    assert.ok(r.skipped.some((s) => s.check === "weak_default_method"));
    assert.ok(r.skipped.some((s) => s.check === "users_registered_not_capable"));
    assert.notOk(has(r, "admin_no_phishing_resistant")); assert.notOk(has(r, "admin_not_mfa_registered"));
    assert.ok(has(r, "users_not_mfa_registered"), "the check whose columns exist still runs");
    const noUpn = run({ name: "r.csv", text: "Is MFA registered,Methods registered\nFalse,\n" }, { kindOverride: { "r.csv": KINDS.ENTRA_REG } });
    assert.ok(noUpn.skipped.some((s) => s.check === "registration" && /user principal name/.test(s.reason)));
  });

  test("columnMap override forces a column; kindOverride forces a kind", () => {
    const text = "Login,Role,Factors\nx@test.darknode.ai,True,fido2SecurityKey\ny@test.darknode.ai,True,mobilePhone\n";
    const auto = run({ name: "odd.csv", text });
    assert.ok(auto.skipped.some((s) => s.check === "classify"));
    const forced = run({ name: "odd.csv", text }, { kindOverride: { "odd.csv": KINDS.ENTRA_REG }, columnMap: { registration: { upn: "Login", isAdmin: "Role", methodsRegistered: "Factors" } } });
    const f = ids(forced, "admin_no_phishing_resistant");
    assert.equal(f.length, 1); assert.equal(f[0].assets[0].name, "y@test.darknode.ai");
  });

  test("evidence is capped at evidenceRows while evidenceCount keeps the full total", () => {
    const rows = [REG_HEAD]; for (let i = 0; i < 60; i++) rows.push(regRow("u" + i + "@test.darknode.ai", "U" + i, "False", "False", "False", "", ""));
    const r = run({ name: "r.csv", text: rows.join("\n") });
    const f = ids(r, "users_not_mfa_registered")[0];
    assert.equal(f.evidence.length, 50); assert.equal(f.evidenceCount, 60);
    const small = run({ name: "r.csv", text: rows.join("\n") }, { evidenceRows: 5 });
    assert.equal(ids(small, "users_not_mfa_registered")[0].evidence.length, 5);
  });
});

// ---------------------------------------------------------------------------
group("caaudit: Okta detections", () => {
  test("okta_no_mfa_everyone fires when the Everyone rule does not require a factor; silent when it does", () => {
    const bad = run({ name: "o.json", text: JSON.stringify([oktaSignOn({ rules: [oktaRule({ requireFactor: false })] })]) });
    const f = ids(bad, "okta_no_mfa_everyone");
    assert.equal(f.length, 1); assert.equal(f[0].severity, "critical"); assert.ok(f[0].controls.some((c) => c.framework === "NIST SP 800-63B"));
    assert.notOk(has(run({ name: "o.json", text: OKTA_GOOD }), "okta_no_mfa_everyone"));
    const zoneOnly = run({ name: "o.json", text: JSON.stringify([oktaSignOn({ rules: [oktaRule({ network: { connection: "ZONE", include: ["nzo1"] } })] })]) });
    assert.ok(has(zoneOnly, "okta_no_mfa_everyone"), "a factor rule limited to a zone does not cover Anywhere");
    const inactiveRule = run({ name: "o.json", text: JSON.stringify([oktaSignOn({ rules: [oktaRule({ status: "INACTIVE" })] })]) });
    assert.ok(has(inactiveRule, "okta_no_mfa_everyone"));
  });

  test("okta_allow_without_factor: ALLOW + ANYWHERE + requireFactor false, per rule; zone-scoped rule is exempt", () => {
    const r = run({ name: "o.json", text: JSON.stringify([oktaSignOn({ rules: [oktaRule({ name: "Open", requireFactor: false }), oktaRule({ name: "Zone", priority: 2, requireFactor: false, network: { connection: "ZONE", include: ["nzo1"] } }), oktaRule({ name: "Factor", priority: 3 })] })]) });
    const f = ids(r, "okta_allow_without_factor");
    assert.equal(f.length, 1); assert.ok(/Open/.test(f[0].title)); assert.equal(f[0].severity, "high"); assert.equal(f[0].confidence, "confirmed");
    assert.notOk(has(r, "okta_no_mfa_everyone"), "the Factor rule still covers everyone");
  });

  test("okta_weak_session: lifetime, idle, DEVICE factor lifetime, SESSION prompt mode and persistent cookie; threshold edges", () => {
    const life = run({ name: "o.json", text: JSON.stringify([oktaSignOn({ rules: [oktaRule({ lifetime: 1441 })] })]) });
    assert.equal(ids(life, "okta_weak_session").length, 1); assert.equal(ids(life, "okta_weak_session")[0].severity, "medium"); assert.ok(/session lifetime 1441/.test(ids(life, "okta_weak_session")[0].description));
    assert.notOk(has(run({ name: "o.json", text: JSON.stringify([oktaSignOn({ rules: [oktaRule({ lifetime: 1440 })] })]) }), "okta_weak_session"), "24 h exactly passes");
    const idle = run({ name: "o.json", text: JSON.stringify([oktaSignOn({ rules: [oktaRule({ idle: 121 })] })]) });
    assert.equal(ids(idle, "okta_weak_session")[0].severity, "low");
    assert.notOk(has(run({ name: "o.json", text: JSON.stringify([oktaSignOn({ rules: [oktaRule({ idle: 120 })] })]) }), "okta_weak_session"));
    const dev = run({ name: "o.json", text: JSON.stringify([oktaSignOn({ rules: [oktaRule({ factorPromptMode: "DEVICE", factorLifetime: 43200 })] })]) });
    assert.ok(/per device for 43200/.test(ids(dev, "okta_weak_session")[0].description));
    const sess = run({ name: "o.json", text: JSON.stringify([oktaSignOn({ rules: [oktaRule({ factorPromptMode: "SESSION", lifetime: 1000 })] })]) });
    assert.ok(/once per session/.test(ids(sess, "okta_weak_session")[0].description));
    const cookie = run({ name: "o.json", text: JSON.stringify([oktaSignOn({ rules: [oktaRule({ persistentCookie: true })] })]) });
    assert.ok(/persistent session cookie/.test(ids(cookie, "okta_weak_session")[0].description));
    const custom = run({ name: "o.json", text: JSON.stringify([oktaSignOn({ rules: [oktaRule({ lifetime: 600 })] })]) }, { oktaMaxSessionHours: 8 });
    assert.ok(has(custom, "okta_weak_session"), "custom threshold applies");
  });

  test("okta_mfa_enroll_optional fires when no authenticator is REQUIRED (factors map and authenticators array)", () => {
    const f1 = run({ name: "e.json", text: JSON.stringify([oktaEnroll({ okta_verify: { enroll: { self: "OPTIONAL" } }, okta_sms: { enroll: { self: "NOT_ALLOWED" } } })]) });
    const f = ids(f1, "okta_mfa_enroll_optional");
    assert.equal(f.length, 1); assert.equal(f[0].severity, "high"); assert.equal(f[0].evidenceCount, 2);
    const oie = run({ name: "e.json", text: JSON.stringify([{ id: "00pX", type: "MFA_ENROLL", status: "ACTIVE", name: "Default Policy", system: true, settings: { type: "AUTHENTICATORS", authenticators: [{ key: "okta_verify", enroll: { self: "OPTIONAL" } }, { key: "webauthn", enroll: { self: "OPTIONAL" } }] } }]) });
    assert.ok(has(oie, "okta_mfa_enroll_optional"));
    const req = run({ name: "e.json", text: JSON.stringify([{ id: "00pX", type: "MFA_ENROLL", status: "ACTIVE", name: "Default Policy", system: true, settings: { type: "AUTHENTICATORS", authenticators: [{ key: "webauthn", enroll: { self: "REQUIRED" } }] } }]) });
    assert.notOk(has(req, "okta_mfa_enroll_optional"));
    const inactive = run({ name: "e.json", text: JSON.stringify([oktaEnroll({ okta_verify: { enroll: { self: "OPTIONAL" } } }, "INACTIVE")]) });
    assert.notOk(has(inactive, "okta_mfa_enroll_optional"), "inactive enrollment policy is reported as inactive, not optional");
    assert.ok(has(inactive, "okta_inactive_policy"));
  });

  test("okta_inactive_policy lists inactive policies and inactive factor/deny rules", () => {
    const r = run({ name: "o.json", text: JSON.stringify([oktaSignOn({ rules: [oktaRule(), oktaRule({ name: "Old deny", priority: 2, status: "INACTIVE", access: "DENY" }), oktaRule({ name: "Old open", priority: 3, status: "INACTIVE", requireFactor: false })] }), oktaSignOn({ name: "Contractors", system: false, status: "INACTIVE", rules: [oktaRule()] })]) });
    const f = ids(r, "okta_inactive_policy");
    assert.equal(f.length, 1); assert.equal(f[0].severity, "low"); assert.equal(f[0].evidenceCount, 2);
    assert.notOk(has(run({ name: "o.json", text: OKTA_GOOD }), "okta_inactive_policy"));
  });

  test("Okta coverage matrix rows: one per rule, Everyone scope, network and session columns", () => {
    const r = run({ name: "o.json", text: JSON.stringify([oktaSignOn({ rules: [oktaRule({ lifetime: 720, idle: 60 })] })]) });
    const rows = r.tables.policies.filter((p) => p.source === "Okta");
    assert.equal(rows.length, 1); assert.equal(rows[0].includedUsers, "Everyone"); assert.equal(rows[0].locations, "ANYWHERE"); assert.ok(/lifetime 720 min; idle 60 min/.test(rows[0].session)); assert.ok(/require factor/.test(rows[0].grant));
  });
});

// ---------------------------------------------------------------------------
group("caaudit: Google Workspace detections", () => {
  const gws = () => run({ name: "Users.csv", text: GWS_CSV });

  test("google_admin_no_2sv is critical and ignores suspended accounts", () => {
    const f = ids(gws(), "google_admin_no_2sv");
    assert.equal(f.length, 1); assert.equal(f[0].severity, "critical"); assert.equal(f[0].assets[0].name, "ben@test.darknode.ai");
    assert.ok(f[0].controls.some((c) => c.framework === "CIS Google Workspace"));
  });

  test("google_2sv_not_enrolled counts active non-admins; google_2sv_not_enforced counts active users without enforcement", () => {
    const r = gws();
    const ne = ids(r, "google_2sv_not_enrolled"); assert.equal(ne.length, 1); assert.equal(ne[0].evidenceCount, 1); assert.equal(ne[0].evidence[0].user, "cy@test.darknode.ai");
    const nf = ids(r, "google_2sv_not_enforced"); assert.equal(nf.length, 1); assert.equal(nf[0].evidenceCount, 3); assert.equal(nf[0].severity, "high"); assert.ok(/1 currently enrolled voluntarily/.test(nf[0].description));
    assert.equal(r.summary.google.admins, 2);
  });

  test("Google negatives and missing columns", () => {
    const clean = run({ name: "u.csv", text: GWS_HEAD + "\nA,a@test.darknode.ai,Enrolled,Enforced,Super Admin,2026-01-01T00:00:00Z,False\nB,b@test.darknode.ai,Enrolled,Enforced,None,2026-01-01T00:00:00Z,False\n" });
    for (const id of ["google_admin_no_2sv", "google_2sv_not_enrolled", "google_2sv_not_enforced"]) assert.notOk(has(clean, id), id);
    const noEnf = run({ name: "u.csv", text: "Email,2-Step Verification Enrollment\na@test.darknode.ai,Not enrolled\n" });
    assert.ok(noEnf.skipped.some((s) => s.check === "google_2sv_not_enforced"));
    assert.ok(noEnf.skipped.some((s) => s.check === "google_admin_no_2sv"));
    assert.ok(has(noEnf, "google_2sv_not_enrolled"));
  });
});

// ---------------------------------------------------------------------------
group("caaudit: outputs", () => {
  test("findings are sorted by severity then id, and every finding carries controls, confidence and recommendation", () => {
    const r = analyze(exampleDataset().dataset);
    const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    for (let i = 1; i < r.findings.length; i++) assert.ok(rank[r.findings[i - 1].severity] <= rank[r.findings[i].severity]);
    for (const f of r.findings) {
      assert.ok(f.controls.length >= 1, f.id); assert.ok(["confirmed", "likely", "review"].includes(f.confidence), f.id);
      assert.ok(f.recommendation && f.description && f.title, f.id); assert.ok(typeof f.evidenceCount === "number", f.id);
      for (const a of f.assets) assert.ok(["IDENTITY", "ASSET"].includes(a.type), f.id);
    }
  });

  test("findingsToCsv header row and quoting", () => {
    const csv = findingsToCsv(analyze(exampleDataset().dataset).findings);
    const lines = csv.split("\n");
    assert.equal(lines[0], "severity,confidence,category,id,title,description,recommendation,controls,assets,evidenceCount");
    assert.ok(lines.length > 5);
    assert.ok(lines[1].startsWith('"high"'));
    assert.equal(findingsToCsv([]).split("\n").length, 1);
    assert.equal(findingsToCsv([{ title: 'say "hi"', severity: "low" }]).split("\n")[1].split(",")[4], '"say ""hi"""');
  });

  test("policyMatrixCsv and noPhishingResistantCsv have fixed headers and the right rows", () => {
    const r = analyze(exampleDataset().dataset);
    const m = policyMatrixCsv(r.tables.policies).split("\n");
    assert.equal(m[0], MATRIX_COLS.join(","));
    assert.equal(m.length, 1 + 4 + 2, "4 Entra policies + 2 Okta rules");
    const n = noPhishingResistantCsv(r.tables.registrations).split("\n");
    assert.equal(n[0], "upn,displayName,isAdmin,mfaRegistered,mfaCapable,methods,defaultMethod");
    assert.equal(n.length, 1 + 7, "7 of 10 synthetic users lack a phishing-resistant method");
    assert.equal(policyMatrixCsv([]).split("\n").length, 1);
  });

  test("meta records the options actually used, with invalid values replaced by defaults", () => {
    const r = analyze(exampleDataset().dataset, { breakGlassMax: "abc", oktaMaxIdleMinutes: 30 });
    assert.equal(r.meta.options.breakGlassMax, DEFAULTS.breakGlassMax);
    assert.equal(r.meta.options.oktaMaxIdleMinutes, 30);
    assert.equal(r.meta.tool, "caaudit"); assert.equal(r.meta.sources, 3);
  });
});
