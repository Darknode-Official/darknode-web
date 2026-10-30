// Identity tools audit regressions (public/js/identity/*-engine.js): vendor-format
// verdicts (Entra portal CSV spellings, Graph interrupt codes, PIM end dates,
// Microsoft-owned apps, non-unique Entra display names, scoped CA policies),
// IPv6 /48 grouping, and large-upload crashes / quadratic loops. Pure logic only.

import { test, assert, group } from "../harness.mjs";
import { parseMfa, parseOutcome, parseAll, analyze as sfAnalyze } from "../../public/js/identity/signin-forensics-engine.js";
import { analyze as vpnAnalyze } from "../../public/js/identity/vpnaudit-engine.js";
import { analyze as paAnalyze, parseInput as paParse } from "../../public/js/identity/privaudit-engine.js";
import { analyze as caAnalyze, parseInput as caParse } from "../../public/js/identity/caaudit-engine.js";
import { analyze as nhiAnalyze, parseInput as nhiParse } from "../../public/js/identity/nhi-engine.js";
import { analyzeFiles as ogAnalyzeFiles } from "../../public/js/identity/oauthgov-engine.js";
import { parseHRStatus } from "../../public/js/identity/access-review-engine.js";
import { parseInput as jmlParse, analyze as jmlAnalyze } from "../../public/js/identity/jml-engine.js";

const NOW = "2026-10-01T00:00:00Z";
const AWS_H = "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated";

group("identity audit: signin-forensics", () => {
  test("portal CSV 'Single-factor authentication' reads as no MFA", () => {
    assert.equal(parseMfa("", "Single-factor authentication"), false);
    assert.equal(parseMfa("", "Multi-factor authentication"), true);
  });
  test("Graph interrupt codes (MFA prompt after a correct password) are not failures", () => {
    assert.equal(parseOutcome("50074"), null);
    assert.equal(parseOutcome("50126"), false);
    const T = Date.UTC(2026, 9, 5, 9);
    const ev = (i, code, reason) => ({ id: "r" + i, createdDateTime: new Date(T + i * 60000).toISOString(), userPrincipalName: "test@darknode.ai", appDisplayName: "Office 365 Exchange Online",
      ipAddress: "198.51.100.7", clientAppUsed: "Browser", authenticationRequirement: "multiFactorAuthentication", status: { errorCode: code, failureReason: reason }, location: { city: "Dublin", countryOrRegion: "IE" } });
    const arr = []; for (let i = 0; i < 6; i++) arr.push(ev(i, 50074, "Strong Authentication is required.")); arr.push(ev(7, 0, "Other."));
    const p = parseAll(JSON.stringify({ value: arr }));
    const r = sfAnalyze(p.records, {}, { columns: p.columns, source: p.source });
    assert.notOk(r.findings.some((f) => f.id === "cred_stuffing_success"));
  });
});

group("identity audit: vpnaudit", () => {
  test("IPv6 addresses written in different compressed forms share one /48", () => {
    const rows = [], day = 86400000, T = Date.UTC(2026, 9, 1, 9);
    for (let d = 0; d < 20; d++) rows.push(new Date(T + d * day).toISOString() + ",test@darknode.ai,login,2001:db8:0:1::5,success");
    for (let d = 20; d < 30; d++) rows.push(new Date(T + d * day).toISOString() + ",test@darknode.ai,login,2001:db8::9,success");
    const r = vpnAnalyze({ files: [{ name: "vpn.csv", text: "timestamp,user,event,src_ip,result\n" + rows.join("\n") }] }, {});
    assert.notOk(r.findings.some((f) => /^newnet:/.test(f.id)));
  });
});

group("identity audit: privaudit", () => {
  test("a future PIM end date does not become the analysis clock", () => {
    const entra = "Role,User principal name,Display name,Object type,Assignment type,Start date,End date\nGlobal Administrator,test@darknode.ai,Test,User,Eligible,2026-01-01T00:00:00Z,2027-09-30T00:00:00Z\n";
    const aws = AWS_H + "\nsvc,arn:aws:iam::111122223333:user/svc,2026-09-01T00:00:00+00:00,false,N/A,N/A,N/A,false,true,2026-09-01T00:00:00+00:00,2026-10-01T00:00:00+00:00,us-east-1,s3,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A\n";
    const r = paAnalyze(paParse([{ name: "e.csv", text: entra }, { name: "cred.csv", text: aws }]));
    assert.equal(r.summary.now, "2026-10-01T00:00:00.000Z");
    assert.notOk(r.findings.some((f) => f.id === "aws_key_rotation" || f.id === "aws_unused_credentials"));
  });
  test("portal CSV object type 'Service principal' is recognised", () => {
    const entra = "Role,User principal name,Display name,Object type,Assignment type\nGlobal Administrator,,ci-automation,Service principal,Active\n";
    const r = paAnalyze(paParse([{ name: "e.csv", text: entra }]), { now: NOW });
    assert.ok(r.findings.some((f) => f.id === "entra_sp_admin"));
  });
});

group("identity audit: caaudit", () => {
  test("an all-users policy scoped to one app or a user action is not 'MFA for all users' / 'legacy blocked'", () => {
    const pol = { id: "p1", displayName: "Require MFA to register security info", state: "enabled",
      conditions: { users: { includeUsers: ["All"], excludeUsers: [] }, applications: { includeApplications: [], includeUserActions: ["urn:user:registersecurityinfo"] }, clientAppTypes: ["all"] },
      grantControls: { operator: "OR", builtInControls: ["mfa"] }, sessionControls: null };
    const leg = { id: "p2", displayName: "Block legacy for one app", state: "enabled",
      conditions: { users: { includeUsers: ["All"] }, applications: { includeApplications: ["00000002-0000-0ff1-ce00-000000000000"] }, clientAppTypes: ["exchangeActiveSync", "other"] },
      grantControls: { operator: "OR", builtInControls: ["block"] } };
    const r = caAnalyze(caParse([{ name: "ca.json", text: JSON.stringify({ value: [pol, leg] }) }]));
    assert.ok(r.findings.some((f) => f.id === "no_mfa_all_users"));
    assert.ok(r.findings.some((f) => f.id === "legacy_auth_not_blocked"));
  });
});

group("identity audit: nhi", () => {
  test("two Entra apps with the same display name stay separate principals", () => {
    const app = (appId, owners, secretName) => ({ id: "obj-" + appId, appId, displayName: "Sync Service", createdDateTime: "2026-01-01T00:00:00Z", owners,
      passwordCredentials: [{ keyId: appId + "-k", displayName: secretName, startDateTime: "2026-09-01T00:00:00Z", endDateTime: "2027-03-01T00:00:00Z" }], keyCredentials: [] });
    const text = JSON.stringify({ value: [app("11111111-0000-4000-8000-000000000001", [{ userPrincipalName: "test@darknode.ai" }], "s1"), app("11111111-0000-4000-8000-000000000002", [], "s2")] });
    const r = nhiAnalyze(nhiParse([{ name: "apps.json", text }]), { now: NOW });
    assert.equal(r.tables.principals.length, 2);
    assert.ok(r.findings.some((f) => f.id === "nhi:entra_app_no_owner"));
    assert.notOk(r.findings.some((f) => f.id === "nhi:entra_app_multiple_secrets"));
  });
  test("a large AWS credential report (over 120k rows) parses without a stack overflow", () => {
    const rows = [];
    for (let i = 0; i < 42000; i++) rows.push(`svc-${i},arn:aws:iam::123456789012:user/svc-${i},2020-01-01T00:00:00+00:00,false,N/A,N/A,N/A,false,true,2020-01-01T00:00:00+00:00,N/A,N/A,N/A,true,2020-01-01T00:00:00+00:00,N/A,N/A,N/A,false,N/A,false,N/A`);
    const p = nhiParse([{ name: "cr.csv", text: AWS_H + "\n" + rows.join("\n") }]);
    assert.ok(p.rows.length > 120000);
  });
});

group("identity audit: oauthgov", () => {
  test("apps owned by the Microsoft corporate tenant are first-party", () => {
    const sp = { id: "aaaaaaaa-0000-4000-8000-000000000001", appId: "de8bc8b5-d9f9-48b1-a8ad-b748da725064", displayName: "Graph Explorer", appOwnerOrganizationId: "72f988bf-86f1-41af-91ab-2d7cd011db47",
      servicePrincipalType: "Application", accountEnabled: true, verifiedPublisher: { displayName: null, verifiedPublisherId: null, addedDateTime: null }, publisherName: "Microsoft Services", tags: [], replyUrls: [], appRoles: [] };
    const grant = { id: "g1", clientId: sp.id, consentType: "AllPrincipals", principalId: null, resourceId: "r1", scope: "Mail.Read" };
    const r = ogAnalyzeFiles([{ name: "sp.json", text: JSON.stringify({ value: [sp] }) }, { name: "grants.json", text: JSON.stringify({ value: [grant] }) }], { now: NOW });
    assert.ok(r.tables.apps[0].firstParty);
    assert.notOk(r.findings.some((f) => f.check === "unverified_publisher" || f.check === "unsanctioned_apps"));
  });
});

group("identity audit: access-review + jml", () => {
  test("HR status 'Not Active' / 'Leaver' / 'Deceased' is terminated, not active", () => {
    assert.equal(parseHRStatus("Not Active"), "terminated");
    assert.equal(parseHRStatus("Leaver"), "terminated");
    assert.equal(parseHRStatus("Deceased"), "terminated");
    assert.equal(parseHRStatus("On Leave"), "leave");
  });
  test("SaaS accounts are checked against the IdP in linear time", () => {
    const N = 2000;
    let hr = "Employee ID,Full Name,Work Email,Start Date,Termination Date,Employment Status\n";
    let idp = "userPrincipalName,displayName,accountEnabled,lastSignInDateTime\n";
    let saas = "Email,Name,Status,Last Login\n";
    for (let i = 0; i < N; i++) {
      hr += `E${i},Alpha Person${i},a${i}@example.com,2020-01-01,,Active\n`;
      idp += `x${i}@example.com,Bravo Other${i},TRUE,2026-09-01T00:00:00Z\n`;
      saas += `y${i}@example.com,Charlie Third${i},Active,2026-09-01\n`;
    }
    saas += "x7@example.com,Bravo Other7,Active,2026-09-01\n";
    const t = Date.now();
    const r = jmlAnalyze(jmlParse([{ name: "hr.csv", text: hr }, { name: "entra.csv", text: idp }, { name: "notion-users.csv", text: saas }]), { now: NOW });
    assert.ok(Date.now() - t < 4000, "took " + (Date.now() - t) + "ms");
    assert.ok(r.findings.length > 0);
  });
});
