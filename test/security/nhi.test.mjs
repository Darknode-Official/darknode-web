// Non-Human Identity Lifecycle engine tests (public/js/identity/nhi-engine.js).
// One parser fixture per vendor export in the exact vendor layout, every detection on a
// crafted positive and a negative, threshold edges, skipped reporting, determinism,
// calendar ordering and ICS output shape.

import { test, assert, group } from "../harness.mjs";
import {
  TOOL_ID, VERSION, COLUMNS, DEFAULTS, HIGH_RISK_APP_ROLES,
  parseInput, detectFormat, analyze, findingsToCsv, credentialsToCsv, calendarToCsv, calendarToEvents, exampleDataset, selfTest, toTime, parseDuration, latestTimestamp,
} from "../../public/js/identity/nhi-engine.js";
import { toIcs } from "../../public/js/core/export.js";

const NOW = "2026-10-01T00:00:00Z";
const T = Date.parse(NOW);
const DAY = 86400000;
const ago = (d) => new Date(T - d * DAY).toISOString().replace(/\.\d{3}Z$/, "Z");
const awsAgo = (d) => new Date(T - d * DAY).toISOString().replace(/\.\d{3}Z$/, "+00:00");
const run = (files, opts = {}) => analyze(parseInput(files), Object.assign({ now: NOW }, opts));
const find = (r, id) => r.findings.find((f) => f.id === TOOL_ID + ":" + id);

const AWS_HEAD = "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated";
function awsRow(user, { k1 = "false", k1rot = "N/A", k1used = "N/A", k2 = "false", k2rot = "N/A", k2used = "N/A", pw = "false", pwChanged = "N/A" } = {}) {
  const root = user === "<root_account>";
  return [user, root ? "arn:aws:iam::123456789012:root" : "arn:aws:iam::123456789012:user/" + user, awsAgo(900), pw, pw === "true" ? awsAgo(1) : "no_information", pwChanged, "N/A", "false",
    k1, k1rot, k1used, k1used === "N/A" ? "N/A" : "us-east-1", k1used === "N/A" ? "N/A" : "s3", k2, k2rot, k2used, k2used === "N/A" ? "N/A" : "us-east-1", k2used === "N/A" ? "N/A" : "ec2", "false", "N/A", "false", "N/A"].join(",");
}
const awsCsv = (...rows) => ({ name: "credential-report.csv", text: AWS_HEAD + "\n" + rows.join("\n") + "\n" });

const GRAPH = "00000003-0000-0000-c000-000000000000";
function entraApp(name, { secrets = [], certs = [], owners = [], roles = [], ownersKnown = true } = {}) {
  const o = {
    id: "0b1f3c2e-1111-4a0e-9c1b-00000000000" + name.length % 10, appId: "6e2d9f3a-2222-4e4b-8d2a-00000000000" + name.length % 10, displayName: name, createdDateTime: ago(500), signInAudience: "AzureADMyOrg",
    passwordCredentials: secrets.map(([label, startAgo, endAgo], i) => ({ customKeyIdentifier: null, displayName: label, endDateTime: ago(endAgo), hint: "Q~k", keyId: "aaaa000" + i + "-3333-4cc3-9a1d-000000000000", secretText: null, startDateTime: ago(startAgo) })),
    keyCredentials: certs.map(([label, startAgo, endAgo], i) => ({ customKeyIdentifier: "ABCDEF", displayName: label, endDateTime: ago(endAgo), key: null, keyId: "bbbb000" + i + "-4444-4cc3-9a1d-000000000000", startDateTime: ago(startAgo), type: "AsymmetricX509Cert", usage: "Verify" })),
    requiredResourceAccess: [{ resourceAppId: GRAPH, resourceAccess: roles.map((id) => ({ id, type: "Role" })).concat([{ id: "e1fe6dd8-ba31-4d61-89e7-88639da4683d", type: "Scope" }]) }],
  };
  if (ownersKnown) o.owners = owners.map((u) => ({ "@odata.type": "#microsoft.graph.user", userPrincipalName: u }));
  return o;
}
const entraJson = (...apps) => ({ name: "applications.json", text: JSON.stringify({ "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#applications", value: apps }) });

const gcpKey = (sa, ageDays, { keyType = "USER_MANAGED", origin = "GOOGLE_PROVIDED", before = "9999-12-31T23:59:59Z", disabled } = {}) => Object.assign({
  keyAlgorithm: "KEY_ALG_RSA_2048", keyOrigin: origin, keyType, name: "projects/demo-prj/serviceAccounts/" + sa + "/keys/0123456789abcdef0123456789abcdef01234567", validAfterTime: ago(ageDays), validBeforeTime: before,
}, disabled === undefined ? {} : { disabled });
const gcpKeysFile = (...keys) => ({ name: "keys.json", text: JSON.stringify(keys) });

const OKTA_HEAD = "Name,Created,Created by,Last used,Expires,Token ID,Status";
const oktaDate = (d) => new Date(T - d * DAY).toISOString().slice(0, 16).replace("T", " ") + " UTC";
const oktaCsv = (...rows) => ({ name: "api-tokens.csv", text: OKTA_HEAD + "\n" + rows.map((r) => r.join(",")).join("\n") + "\n" });

const k8sList = (kind, items) => ({ name: kind.toLowerCase() + "s.json", text: JSON.stringify({ apiVersion: "v1", kind: "List", metadata: { resourceVersion: "" }, items }) });
const sa = (ns, name, extra = {}) => Object.assign({ apiVersion: "v1", kind: "ServiceAccount", metadata: { creationTimestamp: ago(300), name, namespace: ns, uid: "u-" + ns + "-" + name } }, extra);
const saToken = (ns, saName, name, ageDays) => ({ apiVersion: "v1", kind: "Secret", type: "kubernetes.io/service-account-token", data: { token: "ZmFrZQ==" }, metadata: { annotations: { "kubernetes.io/service-account.name": saName, "kubernetes.io/service-account.uid": "x" }, creationTimestamp: ago(ageDays), name, namespace: ns } });
const crb = (name, role, subjects) => ({ apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRoleBinding", metadata: { name }, roleRef: { apiGroup: "rbac.authorization.k8s.io", kind: "ClusterRole", name: role }, subjects });

group("nhi: parsers (vendor fixtures)", () => {
  test("AWS IAM credential report CSV: exact 22 headers detected with confidence 1, keys and principals extracted", () => {
    const p = parseInput([awsCsv(awsRow("svc-etl", { k1: "true", k1rot: awsAgo(10), k1used: awsAgo(1) }), awsRow("alice", { pw: "true", pwChanged: awsAgo(30), k1: "true", k1rot: awsAgo(5), k1used: awsAgo(2) }))]);
    assert.equal(p.files[0].format, "aws-credential-report");
    assert.equal(p.files[0].confidence, 1);
    const creds = p.rows.filter((r) => r.rec === "credential");
    assert.equal(creds.length, 2);
    assert.equal(creds[0].kind, "access_key");
    assert.equal(creds[0].principalType, "service");
    assert.equal(creds[1].principalType, "human");
    assert.ok(creds[0].usageKnown);
  });

  test("AWS: never-had-password user without service prefix is still non-human; root is root", () => {
    const p = parseInput([awsCsv(awsRow("<root_account>"), awsRow("ingest01", { k1: "true", k1rot: awsAgo(3) }))]);
    const prins = p.rows.filter((r) => r.rec === "principal");
    assert.equal(prins.find((x) => x.principal === "<root_account>").principalType, "root");
    assert.equal(prins.find((x) => x.principal === "ingest01").principalType, "service");
  });

  test("Entra GET /applications JSON ({value:[...]}) yields secrets, certificates, owners and app roles", () => {
    const p = parseInput([entraJson(entraApp("Sync", { secrets: [["s1", 100, -200]], certs: [["c1", 100, -265]], owners: ["test@darknode.ai"], roles: ["19dbc75e-c2e2-444c-a770-ec69d8559fc7"] }))]);
    assert.equal(p.files[0].format, "entra-applications");
    const creds = p.rows.filter((r) => r.rec === "credential");
    assert.deepEqual(creds.map((c) => c.kind), ["client_secret", "certificate"]);
    assert.equal(creds[0].owner, "test@darknode.ai");
    const prin = p.rows.find((r) => r.rec === "principal");
    assert.deepEqual(prin.meta.highRiskRoles, ["Directory.ReadWrite.All"]);
  });

  test("Entra Get-MgApplication | ConvertTo-Json (PascalCase, single object) is accepted", () => {
    const text = JSON.stringify({ AppId: "6e2d9f3a-0000-4e4b-8d2a-000000000001", DisplayName: "PS App", CreatedDateTime: "/Date(1700000000000)/", PasswordCredentials: [{ KeyId: "k", DisplayName: "ps-secret", StartDateTime: "/Date(1700000000000)/", EndDateTime: "/Date(1800000000000)/" }], KeyCredentials: [], RequiredResourceAccess: [] });
    const p = parseInput([{ name: "app.json", text }]);
    assert.equal(p.files[0].format, "entra-applications");
    const c = p.rows.find((r) => r.rec === "credential");
    assert.equal(c.kind, "client_secret");
    assert.equal(c.created, "2023-11-14T22:13:20Z");
  });

  test("Entra portal App registrations CSV: status-only credentials, M/D/YYYY dates", () => {
    const text = "Display name,Application (client) ID,Object ID,Created on,Certificates & secrets\nPortal App,6e2d9f3a-aaaa-4e4b-8d2a-000000000001,0b1f3c2e-bbbb-4a0e-9c1b-000000000001,8/14/2024,Expired\nOther App,6e2d9f3a-aaaa-4e4b-8d2a-000000000002,0b1f3c2e-bbbb-4a0e-9c1b-000000000002,1/3/2025,Current\n";
    const p = parseInput([{ name: "AppRegistrations.csv", text }]);
    assert.equal(p.files[0].format, "entra-portal-csv");
    const creds = p.rows.filter((r) => r.rec === "credential");
    assert.equal(creds.length, 2);
    assert.equal(creds[0].meta.portalStatus, "expired");
    assert.equal(creds[0].created, "2024-08-14T00:00:00Z");
    const r = analyze(p, { now: NOW });
    assert.ok(find(r, "entra_portal_expired"));
    assert.ok(r.skipped.some((s) => s.check === "cert_validity_too_long"));
  });

  test("Entra servicePrincipals JSON: ManagedIdentity type and accountEnabled respected", () => {
    const text = JSON.stringify({ value: [{ id: "sp1", appId: "a1", displayName: "mi-vm", servicePrincipalType: "ManagedIdentity", accountEnabled: true, appRoleAssignedTo: [] }, { id: "sp2", appId: "a2", displayName: "legacy", servicePrincipalType: "Legacy", accountEnabled: false, passwordCredentials: [{ keyId: "k", startDateTime: ago(10), endDateTime: ago(-100) }] }] });
    const p = parseInput([{ name: "sps.json", text }]);
    assert.equal(p.files[0].format, "entra-service-principals");
    const prins = p.rows.filter((r) => r.rec === "principal");
    assert.equal(prins[0].principalType, "managed-identity");
    assert.equal(prins[1].enabled, false);
    const r = analyze(p, { now: NOW });
    assert.equal(r.tables.credentials[0].status, "inactive");
  });

  test("GCP keys list JSON: SA email and key id from name, never-expiring sentinel, SYSTEM_MANAGED marked managed", () => {
    const p = parseInput([gcpKeysFile(gcpKey("etl@demo-prj.iam.gserviceaccount.com", 20), gcpKey("etl@demo-prj.iam.gserviceaccount.com", 3, { keyType: "SYSTEM_MANAGED", before: ago(-11) }))]);
    assert.equal(p.files[0].format, "gcp-keys");
    const creds = p.rows.filter((r) => r.rec === "credential");
    assert.equal(creds[0].principal, "etl@demo-prj.iam.gserviceaccount.com");
    assert.equal(creds[0].expires, "never");
    assert.equal(creds[1].managed, true);
    assert.equal(analyze(p, { now: NOW }).tables.credentials.find((c) => c.kind.includes("google")).status, "managed");
  });

  test("GCP service-accounts list JSON merges principal metadata (disabled SA makes its key inactive)", () => {
    const sas = { name: "sas.json", text: JSON.stringify([{ displayName: "ETL", email: "etl@demo-prj.iam.gserviceaccount.com", disabled: true, etag: "x", name: "projects/demo-prj/serviceAccounts/etl@demo-prj.iam.gserviceaccount.com", oauth2ClientId: "1", projectId: "demo-prj", uniqueId: "2" }]) };
    const p = parseInput([sas, gcpKeysFile(gcpKey("etl@demo-prj.iam.gserviceaccount.com", 500))]);
    assert.equal(p.files[0].format, "gcp-service-accounts");
    const r = analyze(p, { now: NOW });
    assert.equal(r.tables.credentials[0].status, "inactive");
    assert.equal(r.tables.principals[0].enabled, false);
  });

  test("Okta API tokens CSV export: Created by becomes owner, Never -> no last use", () => {
    const p = parseInput([oktaCsv(["Terraform", oktaDate(40), "test@darknode.ai", oktaDate(1), oktaDate(-29), "00Tabc", "Active"], ["Script", oktaDate(100), "test+x@darknode.ai", "Never", oktaDate(-29), "00Tdef", "Active"])]);
    assert.equal(p.files[0].format, "okta-tokens-csv");
    const creds = p.rows.filter((r) => r.rec === "credential");
    assert.equal(creds[0].owner, "test@darknode.ai");
    assert.equal(creds[0].lastUsed, ago(1));
    assert.equal(creds[1].lastUsed, null);
    assert.ok(creds[1].usageKnown);
  });

  test("Okta GET /api/v1/api-tokens JSON: last use derived from expiresAt - tokenWindow", () => {
    const text = JSON.stringify([{ id: "00Tabc", name: "ci", userId: "00u1", created: ago(90), lastUpdated: ago(5), expiresAt: ago(-25), tokenWindow: "P30D", clientName: "Okta API", network: { connection: "ANYWHERE" } }]);
    const p = parseInput([{ name: "tokens.json", text }]);
    assert.equal(p.files[0].format, "okta-tokens-json");
    const c = p.rows[0];
    assert.equal(c.lastUsed, ago(5));
    assert.equal(c.meta.lastUsedDerived, true);
    assert.equal(c.owner, "00u1");
  });

  test("kubectl serviceaccounts / secrets / clusterrolebindings Lists are each detected and merged", () => {
    const p = parseInput([
      k8sList("ServiceAccount", [sa("prod", "default"), sa("prod", "deployer", { automountServiceAccountToken: false })]),
      k8sList("Secret", [saToken("prod", "deployer", "deployer-token-abc12", 400), { apiVersion: "v1", kind: "Secret", type: "Opaque", metadata: { name: "cfg", namespace: "prod", creationTimestamp: ago(1) } }]),
      k8sList("ClusterRoleBinding", [crb("deployer-admin", "cluster-admin", [{ kind: "ServiceAccount", name: "deployer", namespace: "prod" }, { kind: "User", name: "ops" }])]),
    ]);
    assert.deepEqual(p.files.map((f) => f.format), ["k8s-serviceaccount", "k8s-secret", "k8s-clusterrolebinding"]);
    assert.equal(p.rows.filter((r) => r.rec === "credential").length, 1, "only SA token secrets become credentials");
    assert.equal(p.rows.filter((r) => r.rec === "binding").length, 1, "only ServiceAccount subjects become bindings");
    assert.ok(!JSON.stringify(p.rows).includes("ZmFrZQ"), "token material is never retained");
  });

  test("gh api orgs/{org}/installations JSON and deploy keys JSON", () => {
    const inst = { name: "installations.json", text: JSON.stringify({ total_count: 1, installations: [{ id: 101, app_id: 7, app_slug: "ci-bot", created_at: ago(200), updated_at: ago(2), repository_selection: "all", permissions: { contents: "write", metadata: "read" }, events: ["push"], suspended_at: null }] }) };
    const keys = { name: "deploy-keys.json", text: JSON.stringify([{ id: 9, key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample", url: "https://api.github.com/repos/o/r/keys/9", title: "build-box", verified: true, created_at: ago(400), read_only: false, added_by: "test@darknode.ai", last_used: ago(3) }]) };
    const p = parseInput([inst, keys]);
    assert.deepEqual(p.files.map((f) => f.format), ["github-installations", "github-deploy-keys"]);
    const [i, k] = p.rows;
    assert.deepEqual(i.meta.writePermissions, ["contents"]);
    assert.equal(k.meta.readOnly, false);
    assert.equal(k.meta.keyType, "ssh-ed25519");
    assert.ok(!JSON.stringify(p.rows).includes("AAAAC3Nz"), "public key material is not retained");
  });

  test("generic CSV maps columns through COLUMNS with reduced confidence; override mapping honoured", () => {
    const text = "Service,Key ID,Issued,Last activity,Valid until,Team\npayments-api,KEY-1,2026-01-01,2026-09-30,2027-01-01,platform\n";
    const p = parseInput([{ name: "inv.csv", text }]);
    assert.equal(p.files[0].source, "generic");
    assert.ok(p.files[0].confidence < 0.85);
    assert.equal(p.rows.length, 0, "Service is not an alias; no principal -> no rows");
    assert.ok(p.skipped.some((s) => s.reason.includes("principal")));
    const p2 = parseInput([{ name: "inv.csv", text }], { mapping: { "inv.csv": { principal: "Service" } } });
    assert.equal(p2.rows.length, 1);
    assert.equal(p2.rows[0].owner, "platform");
    assert.equal(p2.rows[0].expires, "2027-01-01T00:00:00Z");
    assert.ok(Object.keys(COLUMNS).includes("principal"));
  });

  test("unreadable and empty files are reported in skipped, never thrown", () => {
    const p = parseInput([{ name: "bad.json", text: "{not json" }, { name: "empty.csv", text: "" }, { name: "x.txt", text: "hello world" }]);
    assert.equal(p.rows.length, 0);
    assert.equal(p.skipped.length, 3);
    assert.equal(detectFormat("").source, "none");
  });
});

group("nhi: time parsing", () => {
  test("toTime handles AWS +00:00, Z, date-only, M/D/YYYY, 'YYYY-MM-DD HH:MM UTC', /Date()/ and sentinels", () => {
    assert.equal(toTime("2026-01-15T10:00:00+00:00"), Date.UTC(2026, 0, 15, 10));
    assert.equal(toTime("2026-01-15T12:00:00+02:00"), Date.UTC(2026, 0, 15, 10));
    assert.equal(toTime("2026-01-15"), Date.UTC(2026, 0, 15));
    assert.equal(toTime("8/14/2024"), Date.UTC(2024, 7, 14));
    assert.equal(toTime("2026-01-15 10:30 UTC"), Date.UTC(2026, 0, 15, 10, 30));
    assert.equal(toTime("/Date(1700000000000)/"), 1700000000000);
    assert.equal(toTime("N/A"), null);
    assert.equal(toTime("no_information"), null);
    assert.equal(toTime("not_supported"), null);
    assert.equal(toTime("Never"), null);
    assert.equal(parseDuration("P30D"), 30 * DAY);
    assert.equal(parseDuration("PT12H"), 12 * 3600000);
  });

  test("reference time defaults to the latest non-expiry timestamp and can be overridden", () => {
    const files = [awsCsv(awsRow("svc-a", { k1: "true", k1rot: "2026-03-01T00:00:00+00:00", k1used: "2026-06-01T00:00:00+00:00" }))];
    const auto = analyze(parseInput(files));
    assert.equal(auto.meta.now, "2026-06-01T00:00:00Z");
    assert.equal(auto.meta.nowSource, "data");
    const forced = analyze(parseInput(files), { now: "2026-12-31T00:00:00Z" });
    assert.equal(forced.meta.nowSource, "opts");
    assert.equal(forced.tables.credentials[0].ageDays, 305);
    assert.equal(latestTimestamp([{ created: "2020-01-01", expires: "9999-12-31T23:59:59Z" }]), Date.UTC(2020, 0, 1));
  });
});

group("nhi: detections", () => {
  test("key_overdue fires on a 91-day key and not on a 90-day key (edge)", () => {
    const pos = run([awsCsv(awsRow("svc-a", { k1: "true", k1rot: awsAgo(91), k1used: awsAgo(1) }))]);
    assert.ok(find(pos, "key_overdue"));
    assert.equal(pos.tables.credentials[0].status, "overdue");
    assert.ok(find(pos, "key_overdue").controls.some((c) => c.framework === "CIS AWS Foundations" && c.id === "1.14"));
    const neg = run([awsCsv(awsRow("svc-a", { k1: "true", k1rot: awsAgo(90), k1used: awsAgo(1) }))]);
    assert.ok(!find(neg, "key_overdue"));
    assert.equal(neg.tables.credentials[0].status, "ok");
  });

  test("maxKeyAgeDays threshold is honoured", () => {
    const r = run([awsCsv(awsRow("svc-a", { k1: "true", k1rot: awsAgo(40), k1used: awsAgo(1) }))], { maxKeyAgeDays: 30 });
    assert.ok(find(r, "key_overdue"));
    assert.equal(r.meta.options.maxKeyAgeDays, 30);
  });

  test("key_never_used fires only past unusedDays and takes priority over overdue", () => {
    const pos = run([awsCsv(awsRow("svc-a", { k1: "true", k1rot: awsAgo(120) }))]);
    assert.equal(pos.tables.credentials[0].status, "never-used");
    assert.ok(find(pos, "key_never_used"));
    assert.ok(find(pos, "key_never_used").controls.some((c) => c.id === "1.12"));
    const young = run([awsCsv(awsRow("svc-a", { k1: "true", k1rot: awsAgo(30) }))]);
    assert.ok(!find(young, "key_never_used"));
  });

  test("key_unused fires at 91 unused days, silent at 90", () => {
    assert.ok(find(run([awsCsv(awsRow("svc-a", { k1: "true", k1rot: awsAgo(10), k1used: awsAgo(91) }))]), "key_unused"));
    assert.ok(!find(run([awsCsv(awsRow("svc-a", { k1: "true", k1rot: awsAgo(10), k1used: awsAgo(90) }))]), "key_unused"));
  });

  test("usage checks are skipped (not guessed) for sources without last-used data", () => {
    const r = run([gcpKeysFile(gcpKey("a@demo-prj.iam.gserviceaccount.com", 500))]);
    assert.ok(!find(r, "key_never_used"));
    assert.ok(r.skipped.some((s) => s.check === "key_never_used/key_unused" && s.reason.includes("gcp")));
  });

  test("aws_two_active_keys and inactive keys", () => {
    const pos = run([awsCsv(awsRow("svc-a", { k1: "true", k1rot: awsAgo(10), k1used: awsAgo(1), k2: "true", k2rot: awsAgo(5), k2used: awsAgo(1) }))]);
    assert.ok(find(pos, "aws_two_active_keys"));
    assert.equal(find(pos, "aws_two_active_keys").evidenceCount, 2);
    const neg = run([awsCsv(awsRow("svc-a", { k1: "true", k1rot: awsAgo(10), k1used: awsAgo(1), k2: "false", k2rot: awsAgo(400) }))]);
    assert.ok(!find(neg, "aws_two_active_keys"));
    assert.equal(neg.tables.credentials.find((c) => c.credential === "access_key_2").status, "inactive");
  });

  test("aws_root_access_key is critical", () => {
    const r = run([awsCsv(awsRow("<root_account>", { k1: "true", k1rot: awsAgo(10), k1used: awsAgo(1) }))]);
    const f = find(r, "aws_root_access_key");
    assert.ok(f && f.severity === "critical");
    assert.ok(f.controls.some((c) => c.id === "1.4"));
  });

  test("gcp_user_managed_key and gcp_key_never_expires; google-managed keys stay silent", () => {
    const pos = run([gcpKeysFile(gcpKey("a@demo-prj.iam.gserviceaccount.com", 10))]);
    assert.ok(find(pos, "gcp_user_managed_key") && find(pos, "gcp_user_managed_key").controls.some((c) => c.framework === "CIS GCP Foundations" && c.id === "1.4"));
    assert.ok(find(pos, "gcp_key_never_expires"));
    const neg = run([gcpKeysFile(gcpKey("a@demo-prj.iam.gserviceaccount.com", 3, { keyType: "SYSTEM_MANAGED", before: ago(-11) }))]);
    assert.equal(neg.findings.length, 0);
  });

  test("Entra expired secret is critical; expiring buckets map 30/60/90 to high/medium/low", () => {
    const r = run([entraJson(entraApp("A", { secrets: [["dead", 400, 1]], owners: ["test@darknode.ai"] }), entraApp("B", { secrets: [["s30", 10, -30]], owners: ["test@darknode.ai"] }), entraApp("C", { secrets: [["s60", 10, -31]], owners: ["test@darknode.ai"] }), entraApp("D", { secrets: [["s90", 10, -90]], owners: ["test@darknode.ai"] }), entraApp("E", { secrets: [["s91", 10, -91]], owners: ["test@darknode.ai"] }))]);
    assert.equal(find(r, "entra_expired").severity, "critical");
    assert.equal(find(r, "cred_expiring_30").severity, "high");
    assert.equal(find(r, "cred_expiring_30").evidenceCount, 1);
    assert.equal(find(r, "cred_expiring_60").severity, "medium");
    assert.equal(find(r, "cred_expiring_90").severity, "low");
    assert.equal(r.tables.credentials.find((c) => c.credential === "s91").status, "ok");
  });

  test("custom expiryWarnDays windows are honoured and sorted", () => {
    const r = run([entraJson(entraApp("B", { secrets: [["s", 10, -12]], owners: ["test@darknode.ai"] }))], { expiryWarnDays: [45, 14] });
    assert.deepEqual(r.meta.options.expiryWarnDays, [14, 45]);
    assert.ok(find(r, "cred_expiring_14") && find(r, "cred_expiring_14").severity === "high");
  });

  test("cert_validity_too_long at 398 days, silent at 397", () => {
    assert.ok(find(run([entraJson(entraApp("A", { certs: [["c", 10, -388]], owners: ["x"] }))]), "cert_validity_too_long"));
    assert.ok(!find(run([entraJson(entraApp("A", { certs: [["c", 10, -387]], owners: ["x"] }))]), "cert_validity_too_long"));
    const f = find(run([entraJson(entraApp("A", { certs: [["c", 10, -388]], owners: ["x"] }))]), "cert_validity_too_long");
    assert.ok(f.controls.some((c) => c.framework === "CA/Browser Forum BR"));
  });

  test("entra_app_no_owner fires when owners[] is present but empty; skipped when owners were never exported", () => {
    const pos = run([entraJson(entraApp("Orphan", { secrets: [["s", 10, -200]] }))]);
    assert.ok(find(pos, "entra_app_no_owner"));
    assert.equal(pos.tables.credentials[0].owner, "unassigned");
    assert.equal(pos.summary.ownerless, 1);
    const unknown = run([entraJson(entraApp("NoData", { secrets: [["s", 10, -200]], ownersKnown: false }))]);
    assert.ok(!find(unknown, "entra_app_no_owner"));
    assert.ok(unknown.skipped.some((s) => s.check === "entra_app_no_owner"));
  });

  test("entra_app_multiple_secrets counts only unexpired secrets", () => {
    assert.ok(find(run([entraJson(entraApp("A", { secrets: [["a", 10, -200], ["b", 5, -300]], owners: ["x"] }))]), "entra_app_multiple_secrets"));
    assert.ok(!find(run([entraJson(entraApp("A", { secrets: [["a", 10, -200], ["b", 500, 5]], owners: ["x"] }))]), "entra_app_multiple_secrets"));
  });

  test("entra_app_high_risk_role matches known Graph app-role ids and value strings, not delegated scopes", () => {
    const pos = run([entraJson(entraApp("A", { secrets: [["a", 10, -200]], owners: ["x"], roles: ["e2a3a72e-5f79-4c64-b1b1-878b674786c9"] }))]);
    assert.ok(find(pos, "entra_app_high_risk_role") && /Mail\.ReadWrite/.test(find(pos, "entra_app_high_risk_role").description));
    assert.equal(HIGH_RISK_APP_ROLES["19dbc75e-c2e2-444c-a770-ec69d8559fc7"], "Directory.ReadWrite.All");
    const byValue = { name: "a.json", text: JSON.stringify({ value: [{ appId: "a", displayName: "V", owners: [{ userPrincipalName: "x" }], requiredResourceAccess: [{ resourceAppId: GRAPH, resourceAccess: [{ id: "00000000-0000-0000-0000-000000000000", type: "Role", value: "Application.ReadWrite.All" }] }] }] }) };
    assert.ok(find(analyze(parseInput([byValue]), { now: NOW }), "entra_app_high_risk_role"));
    const neg = run([entraJson(entraApp("A", { secrets: [["a", 10, -200]], owners: ["x"] }))]);
    assert.ok(!find(neg, "entra_app_high_risk_role"));
  });

  test("entra_app_high_risk_role ignores a reserved-word role id (prototype-key safety)", () => {
    // "constructor"/"__proto__" index Object.prototype members; before the guard they
    // resolved to the native Object function and were pushed as a bogus tenant-wide role.
    assert.ok(!find(run([entraJson(entraApp("A", { secrets: [["a", 10, -200]], owners: ["x"], roles: ["constructor"] }))]), "entra_app_high_risk_role"));
    assert.ok(!find(run([entraJson(entraApp("B", { secrets: [["a", 10, -200]], owners: ["x"], roles: ["__proto__"] }))]), "entra_app_high_risk_role"));
  });

  test("Okta: departed creator (opts.departed, case-insensitive), skipped when no list; expired token is low; never-used token", () => {
    const files = [oktaCsv(["Old", oktaDate(400), "Former.User@darknode.ai", oktaDate(100), oktaDate(70), "00T1", "Expired"], ["Idle", oktaDate(120), "test@darknode.ai", "Never", oktaDate(-10), "00T2", "Active"])];
    const r = run(files, { departed: ["former.user@darknode.ai"] });
    assert.ok(!find(r, "okta_token_departed_creator"), "expired token is no longer active");
    assert.equal(find(r, "cred_expired").severity, "low");
    assert.ok(find(r, "key_never_used") && find(r, "key_never_used").evidence[0].principal === "Idle");
    const r2 = run([oktaCsv(["Live", oktaDate(40), "Former.User@darknode.ai", oktaDate(1), oktaDate(-29), "00T3", "Active"])], { departed: ["FORMER.USER@darknode.ai"] });
    assert.equal(find(r2, "okta_token_departed_creator").severity, "high");
    const none = run(files);
    assert.ok(none.skipped.some((s) => s.check === "okta_token_departed_creator"));
  });

  test("k8s_sa_cluster_admin fires for SA subjects of a cluster-admin binding only", () => {
    const pos = run([k8sList("ServiceAccount", [sa("prod", "deployer")]), k8sList("ClusterRoleBinding", [crb("x", "cluster-admin", [{ kind: "ServiceAccount", name: "deployer", namespace: "prod" }])])]);
    const f = find(pos, "k8s_sa_cluster_admin");
    assert.ok(f && f.severity === "high" && f.controls.some((c) => c.framework === "CIS Kubernetes" && c.id === "5.1.1"));
    assert.equal(f.evidence[0].principal, "prod/deployer");
    const neg = run([k8sList("ServiceAccount", [sa("prod", "deployer")]), k8sList("ClusterRoleBinding", [crb("x", "view", [{ kind: "ServiceAccount", name: "deployer", namespace: "prod" }])])]);
    assert.ok(!find(neg, "k8s_sa_cluster_admin"));
    const noBind = run([k8sList("ServiceAccount", [sa("prod", "deployer")])]);
    assert.ok(noBind.skipped.some((s) => s.check === "k8s_sa_cluster_admin"));
  });

  test("k8s_long_lived_sa_token and k8s_default_sa_automount; explicit automount:false is silent", () => {
    const pos = run([k8sList("ServiceAccount", [sa("prod", "default"), sa("dev", "default", { automountServiceAccountToken: false })]), k8sList("Secret", [saToken("prod", "default", "default-token-x", 10)])]);
    assert.ok(find(pos, "k8s_long_lived_sa_token"));
    const d = find(pos, "k8s_default_sa_automount");
    assert.equal(d.evidenceCount, 1);
    assert.equal(d.evidence[0].principal, "prod/default");
    assert.ok(d.controls.some((c) => c.id === "5.1.5") && d.controls.some((c) => c.id === "5.1.6"));
  });

  test("github_deploy_key_write and github_installation_all_repos (medium with write perms, low without)", () => {
    const keys = (ro) => ({ name: "keys.json", text: JSON.stringify([{ id: 1, key: "ssh-rsa AAAAB3", title: "k", verified: true, created_at: ago(10), read_only: ro }]) });
    assert.ok(find(run([keys(false)]), "github_deploy_key_write"));
    assert.ok(!find(run([keys(true)]), "github_deploy_key_write"));
    const inst = (sel, perms) => ({ name: "i.json", text: JSON.stringify({ installations: [{ id: 1, app_slug: "bot", created_at: ago(10), updated_at: ago(1), repository_selection: sel, permissions: perms }] }) });
    assert.equal(find(run([inst("all", { contents: "write" })]), "github_installation_all_repos").severity, "medium");
    assert.equal(find(run([inst("all", { metadata: "read" })]), "github_installation_all_repos").severity, "low");
    assert.ok(!find(run([inst("selected", { contents: "write" })]), "github_installation_all_repos"));
  });

  test("every finding has the contract shape and real control references", () => {
    const r = analyze(parseInput(exampleDataset().files), { departed: ["test+former@darknode.ai"] });
    const sev = new Set(["critical", "high", "medium", "low", "info"]), conf = new Set(["confirmed", "likely", "review"]);
    assert.ok(r.findings.length >= 12);
    for (const f of r.findings) {
      assert.ok(sev.has(f.severity) && conf.has(f.confidence), f.id);
      assert.ok(f.controls.length >= 1 && f.controls.every((c) => c.framework && c.id), f.id);
      assert.ok(f.evidence.length <= 50 && f.evidenceCount >= f.evidence.length, f.id);
      assert.ok(f.assets.length >= 1 && f.assets.every((a) => a.type === "IDENTITY" && a.data.kind === "non-human" && a.data.source), f.id);
      assert.ok(f.recommendation && f.description && f.category, f.id);
    }
  });

  test("ownership: owner comes from owners / created by / human self; unassigned otherwise; KPI counts them", () => {
    const r = run([awsCsv(awsRow("alice", { pw: "true", pwChanged: awsAgo(30), k1: "true", k1rot: awsAgo(5), k1used: awsAgo(2) }), awsRow("svc-x", { k1: "true", k1rot: awsAgo(5), k1used: awsAgo(2) }))]);
    assert.equal(r.tables.credentials.find((c) => c.principal === "alice").owner, "alice");
    assert.equal(r.tables.credentials.find((c) => c.principal === "svc-x").owner, "unassigned");
    assert.equal(r.summary.ownerless, 1);
    assert.ok(r.tables.credentials.find((c) => c.principal === "svc-x").flags.includes("unassigned-owner"));
  });
});

group("nhi: calendar, exports, engine", () => {
  test("calendar: sorted ascending, 'rotate by' = created + maxKeyAgeDays, expiry governs when earlier, no past expiry entries", () => {
    const r = run([awsCsv(awsRow("svc-a", { k1: "true", k1rot: awsAgo(10), k1used: awsAgo(1) })), entraJson(entraApp("A", { secrets: [["soon", 10, -20], ["gone", 400, 5]], owners: ["x"] }))]);
    const cal = r.tables.calendar;
    assert.ok(cal.every((e, i) => i === 0 || cal[i - 1].date <= e.date));
    const rot = cal.find((e) => e.principal === "svc-a" && e.action === "rotate by");
    assert.equal(rot.date, ago(-80).slice(0, 10));
    assert.equal(rot.daysFromNow, 80);
    assert.ok(cal.some((e) => e.credential === "soon" && e.action === "expires"));
    assert.ok(!cal.some((e) => e.credential === "soon" && e.action === "rotate by"), "expiry before rotate-by date suppresses the rotate entry");
    assert.ok(!cal.some((e) => e.credential === "gone"), "expired credentials carry no calendar date");
  });

  test("calendarToEvents + toIcs: BEGIN:VCALENDAR, one all-day VEVENT per entry, deterministic uids", () => {
    const r = run([awsCsv(awsRow("svc-a", { k1: "true", k1rot: awsAgo(10), k1used: awsAgo(1) })), gcpKeysFile(gcpKey("b@demo-prj.iam.gserviceaccount.com", 20))]);
    const events = calendarToEvents(r.tables.calendar, r.meta.now);
    assert.equal(events.length, r.tables.calendar.length);
    assert.ok(events.every((e) => e.allDay && e.uid.endsWith("@darknode.ai") && e.start && e.summary.startsWith("[rotate by]")));
    const ics = toIcs(events);
    assert.ok(ics.startsWith("BEGIN:VCALENDAR\r\n"));
    assert.ok(ics.trimEnd().endsWith("END:VCALENDAR"));
    assert.equal((ics.match(/BEGIN:VEVENT/g) || []).length, r.tables.calendar.length);
    assert.ok(ics.includes("DTSTART;VALUE=DATE:" + ago(-80).slice(0, 10).replace(/-/g, "")));
    assert.equal(toIcs(events), toIcs(calendarToEvents(r.tables.calendar, r.meta.now)));
  });

  test("findingsToCsv header row and quoting; inventory and calendar CSVs", () => {
    const r = analyze(parseInput(exampleDataset().files));
    const csv = findingsToCsv(r.findings);
    assert.equal(csv.split("\r\n")[0], "severity,confidence,category,title,description,recommendation,controls,evidenceCount,assets");
    assert.equal(csv.split("\r\n").filter(Boolean).length, r.findings.length + 1);
    assert.ok(credentialsToCsv(r.tables.credentials).startsWith("source,principal,principalType,kind,credential,created,lastUsed,expires,ageDays"));
    assert.ok(calendarToCsv(r.tables.calendar).startsWith("date,action,daysFromNow,source,principal,credential,kind,owner"));
    assert.ok(credentialsToCsv([{ source: "x", principal: "=cmd()", flags: ["a", "b"] }]).includes("'=cmd()"), "formula injection guard");
  });

  test("analyze is deterministic (byte-identical JSON) and sorts findings by severity", () => {
    const files = exampleDataset().files;
    const a = JSON.stringify(analyze(parseInput(files))), b = JSON.stringify(analyze(parseInput(exampleDataset().files)));
    assert.equal(a, b);
    const r = JSON.parse(a);
    const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    assert.ok(r.findings.every((f, i) => i === 0 || rank[r.findings[i - 1].severity] <= rank[f.severity]));
  });

  test("example dataset is format-faithful: exact vendor headers and sample label", () => {
    const ex = exampleDataset();
    assert.ok(/synthetic/.test(ex.label));
    assert.equal(ex.files.length, 5);
    assert.equal(ex.files[0].text.split("\n")[0], AWS_HEAD);
    assert.equal(ex.files[4].text.split("\n")[0], OKTA_HEAD);
    assert.equal(ex.files[0].text.trim().split("\n").length, 7, "6 AWS rows plus header");
    assert.equal(JSON.parse(ex.files[1].text).value.length, 4);
    assert.equal(JSON.parse(ex.files[2].text).length, 2);
  });

  test("progress callback is invoked and optional", () => {
    const calls = [];
    analyze(parseInput(exampleDataset().files), {}, { progress: (i, n, l) => calls.push([i, n, l]) });
    assert.ok(calls.length >= 2);
    assert.equal(calls[calls.length - 1][2], "done");
    analyze(parseInput(exampleDataset().files));
  });

  test("empty input yields zero findings, zero rows, no throw; analyze accepts both rows[] and parseInput result", () => {
    const p = parseInput("");
    assert.equal(p.rows.length, 0);
    const r = analyze(p);
    assert.equal(r.findings.length, 0);
    assert.equal(r.meta.rows, 0);
    assert.equal(r.meta.nowSource, "none");
    assert.equal(analyze([]).tables.calendar.length, 0);
    const rows = parseInput(exampleDataset().files).rows;
    assert.equal(JSON.stringify(analyze(rows).findings), JSON.stringify(analyze(parseInput(exampleDataset().files)).findings));
  });

  test("in-engine self-test passes; constants exported", () => {
    const r = selfTest();
    assert.ok(r.pass, "failed: " + r.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
    assert.ok(r.tests.length >= 20);
    assert.equal(TOOL_ID, "nhi");
    assert.ok(/^\d+\.\d+\.\d+$/.test(VERSION));
    assert.deepEqual(DEFAULTS.expiryWarnDays, [30, 60, 90]);
    assert.equal(DEFAULTS.maxCertDays, 397);
  });
});
