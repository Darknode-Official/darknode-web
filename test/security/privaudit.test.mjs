// Privileged Access Audit engine tests (public/js/identity/privaudit-engine.js).
// Fixtures are in the exact vendor layouts: Entra "Download assignments" CSV and Graph
// roleAssignments JSON, AWS credential report CSV, aws iam get-account-authorization-details
// JSON, gcloud projects get-iam-policy JSON, Okta administrators CSV / role JSON, GitHub
// organization people CSV / gh api members JSON.

import { test, assert, group } from "../harness.mjs";
import {
  selfTest, analyze, parseInput, exampleDataset, findingsToCsv, principalsToCsv, attestationText,
  detectCsvSource, detectJsonSource, parseDate, parseBool, looksShared, policyRisks, trustRisks, decodePolicy,
  DEFAULTS, COLUMNS, AWS_CRED_HEADERS, ENTRA_ROLE_IDS, VERSION, TOOL_ID,
} from "../../public/js/identity/privaudit-engine.js";

const NOW = "2026-10-01T12:00:00Z";
const run = (files, opts = {}) => analyze(parseInput(files), { now: NOW, ...opts });
const byId = (r) => Object.fromEntries(r.findings.map((f) => [f.id, f]));
const skippedChecks = (r) => r.skipped.map((s) => s.check);

// ---------------------------------------------------------------- fixtures --
const ENTRA_CSV = [
  "Role,Display name,User principal name,Object ID,Object type,Assignment type,Scope,Start date,End date",
  "Global Administrator,Alice Moreno,alice.m@test.darknode.ai,0f1e2d3c-4b5a-4697-8877-665544332211,User,Permanent,Directory,1/12/2025 09:14:00,",
  "Global Administrator,Bob Kahn,bob.k@test.darknode.ai,1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9,User,Permanent,Directory,3/02/2025 14:30:00,",
  "Global Administrator,Carol Singh,carol.s@test.darknode.ai,2b3c4d5e-6f70-4182-93a4-b5c6d7e8f901,User,Permanent,Directory,5/20/2025 11:02:00,",
  "Global Administrator,Dave Rossi,dave.r@test.darknode.ai,3c4d5e6f-7081-4293-a4b5-c6d7e8f90112,User,Permanent,Directory,6/01/2025 08:45:00,",
  "Global Administrator,Admin (shared),admin@test.darknode.ai,4d5e6f70-8192-43a4-b5c6-d7e8f9011223,User,Permanent,Directory,11/15/2024 16:20:00,",
  "Global Administrator,Erin Lau,erin.l@test.darknode.ai,5e6f7081-92a3-44b5-c6d7-e8f901122334,User,Eligible,Directory,7/10/2025 10:00:00,7/10/2026 10:00:00",
  "Exchange Administrator,Frank Okafor,frank.o@test.darknode.ai,6f708192-a3b4-45c6-d7e8-f90112233445,User,Permanent,Directory,2/14/2025 13:05:00,",
  "Security Administrator,Grace Tan,grace.t@test.darknode.ai,708192a3-b4c5-46d7-e8f9-011223344556,User,Active,Directory,9/28/2026 09:00:00,9/28/2026 17:00:00",
].join("\r\n");

const ENTRA_JSON = JSON.stringify({
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#roleManagement/directory/roleAssignments(principal(),roleDefinition())",
  value: [
    { id: "lAPpYvVpN0CRAAAAAAAAADv8Iq6Q_6xHnHqZwJt3B0g-1", principalId: "3bfc22ae-90ff-47ac-9c7a-99c09b770748", roleDefinitionId: "62e90394-69f5-4237-9190-012177145e10", directoryScopeId: "/",
      principal: { "@odata.type": "#microsoft.graph.user", id: "3bfc22ae-90ff-47ac-9c7a-99c09b770748", displayName: "Hana Ito", userPrincipalName: "hana.i@test.darknode.ai" } },
    { id: "lAPpYvVpN0CRAAAAAAAAADv8Iq6Q_6xHnHqZwJt3B0g-2", principalId: "77ab10cf-2211-4e3f-9f0a-8b2c6d4e5f60", roleDefinitionId: "e8611ab8-c189-46e8-94e1-60213ab1f814", directoryScopeId: "/",
      principal: { "@odata.type": "#microsoft.graph.servicePrincipal", id: "77ab10cf-2211-4e3f-9f0a-8b2c6d4e5f60", displayName: "Automation App", appId: "9c1f0e2d-3b4a-4c5d-8e6f-7a8b9c0d1e2f" } },
    { id: "lAPpYvVpN0CRAAAAAAAAADv8Iq6Q_6xHnHqZwJt3B0g-3", principalId: "aa0b1c2d-3e4f-4051-8263-74859607a8b9", roleDefinitionId: "fe930be7-5e62-47db-91af-98c3a49a38b1", directoryScopeId: "/",
      roleDefinition: { displayName: "User Administrator" }, principal: { "@odata.type": "#microsoft.graph.user", displayName: "Ivan Petrov", userPrincipalName: "ivan.p@test.darknode.ai" } },
  ],
});

const ENTRA_ELIGIBLE_JSON = JSON.stringify({
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#roleManagement/directory/roleEligibilityScheduleInstances(principal(),roleDefinition())",
  value: [
    { id: "x-1", principalId: "3bfc22ae-90ff-47ac-9c7a-99c09b770748", roleDefinitionId: "62e90394-69f5-4237-9190-012177145e10", directoryScopeId: "/", memberType: "Direct", startDateTime: "2026-01-01T00:00:00Z", endDateTime: "2026-12-31T00:00:00Z", roleEligibilityScheduleId: "sched-1",
      principal: { "@odata.type": "#microsoft.graph.user", displayName: "Hana Ito", userPrincipalName: "hana.i@test.darknode.ai" } },
    { id: "x-2", principalId: "bbbb0000-1111-4222-8333-444455556666", roleDefinitionId: "62e90394-69f5-4237-9190-012177145e10", directoryScopeId: "/", memberType: "Direct", startDateTime: "2026-01-01T00:00:00Z", endDateTime: null, roleEligibilityScheduleId: "sched-2",
      principal: { "@odata.type": "#microsoft.graph.user", displayName: "Jun Park", userPrincipalName: "jun.p@test.darknode.ai" } },
  ],
});

const AWS_CRED = [
  AWS_CRED_HEADERS.join(","),
  "<root_account>,arn:aws:iam::123456789012:root,2021-03-04T10:11:12+00:00,not_supported,2026-09-20T08:02:44+00:00,not_supported,not_supported,false,true,2022-01-01T00:00:00+00:00,2026-09-01T00:00:00+00:00,us-east-1,s3,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
  "ops-admin,arn:aws:iam::123456789012:user/ops-admin,2024-01-15T09:00:00+00:00,true,2026-09-29T07:40:11+00:00,2026-07-01T10:00:00+00:00,2026-09-29T10:00:00+00:00,true,true,2025-08-27T12:00:00+00:00,2026-09-30T06:15:00+00:00,us-east-1,sts,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
  "deploy-bot,arn:aws:iam::123456789012:user/deploy-bot,2023-06-10T12:00:00+00:00,false,N/A,N/A,N/A,false,true,2026-09-01T00:00:00+00:00,2026-09-30T23:10:00+00:00,eu-west-1,ecr,true,2026-08-01T00:00:00+00:00,2026-09-30T23:11:00+00:00,eu-west-1,ecr,false,N/A,false,N/A",
  "jsmith,arn:aws:iam::123456789012:user/jsmith,2025-02-01T08:30:00+00:00,true,2026-09-25T15:22:09+00:00,2026-08-15T09:00:00+00:00,2026-11-13T09:00:00+00:00,false,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
  "legacy-svc,arn:aws:iam::123456789012:user/legacy-svc,2022-11-20T10:00:00+00:00,false,N/A,N/A,N/A,false,true,2026-08-20T00:00:00+00:00,2025-12-02T04:00:00+00:00,us-east-1,s3,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
  "analyst,arn:aws:iam::123456789012:user/analyst,2025-09-01T08:00:00+00:00,true,2026-10-01T09:12:00+00:00,2026-09-10T09:00:00+00:00,2026-12-09T09:00:00+00:00,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
].join("\n");

const AWS_CRED_CLEAN = [
  AWS_CRED_HEADERS.join(","),
  "<root_account>,arn:aws:iam::123456789012:root,2021-03-04T10:11:12+00:00,not_supported,2025-01-02T08:02:44+00:00,not_supported,not_supported,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
  "analyst,arn:aws:iam::123456789012:user/analyst,2025-09-01T08:00:00+00:00,true,2026-10-01T09:12:00+00:00,2026-09-10T09:00:00+00:00,2026-12-09T09:00:00+00:00,true,true,2026-09-10T00:00:00+00:00,2026-09-30T00:00:00+00:00,us-east-1,s3,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
].join("\n");

const ADMIN_DOC = { Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }] };
const AWS_AUTH = JSON.stringify({
  UserDetailList: [
    { Path: "/", UserName: "ops-admin", UserId: "AIDAEXAMPLE1", Arn: "arn:aws:iam::123456789012:user/ops-admin", CreateDate: "2024-01-15T09:00:00Z", UserPolicyList: [], GroupList: ["admins"], AttachedManagedPolicies: [] },
    { Path: "/", UserName: "jsmith", UserId: "AIDAEXAMPLE2", Arn: "arn:aws:iam::123456789012:user/jsmith", CreateDate: "2025-02-01T08:30:00Z",
      UserPolicyList: [{ PolicyName: "inline-iam", PolicyDocument: encodeURIComponent(JSON.stringify({ Version: "2012-10-17", Statement: { Effect: "Allow", Action: ["iam:*"], Resource: "*" } })) }], GroupList: [], AttachedManagedPolicies: [{ PolicyName: "ReadOnlyAccess", PolicyArn: "arn:aws:iam::aws:policy/ReadOnlyAccess" }] },
    { Path: "/", UserName: "analyst", UserId: "AIDAEXAMPLE3", Arn: "arn:aws:iam::123456789012:user/analyst", CreateDate: "2025-09-01T08:00:00Z", UserPolicyList: [], GroupList: ["readers"], AttachedManagedPolicies: [] },
  ],
  GroupDetailList: [
    { Path: "/", GroupName: "admins", GroupId: "AGPAEXAMPLE1", Arn: "arn:aws:iam::123456789012:group/admins", CreateDate: "2023-01-01T00:00:00Z", GroupPolicyList: [], AttachedManagedPolicies: [{ PolicyName: "AdministratorAccess", PolicyArn: "arn:aws:iam::aws:policy/AdministratorAccess" }] },
    { Path: "/", GroupName: "readers", GroupId: "AGPAEXAMPLE2", Arn: "arn:aws:iam::123456789012:group/readers", CreateDate: "2023-01-01T00:00:00Z", GroupPolicyList: [], AttachedManagedPolicies: [{ PolicyName: "ReadOnlyAccess", PolicyArn: "arn:aws:iam::aws:policy/ReadOnlyAccess" }] },
  ],
  RoleDetailList: [
    { Path: "/", RoleName: "OpenRole", RoleId: "AROAEXAMPLE1", Arn: "arn:aws:iam::123456789012:role/OpenRole", CreateDate: "2024-05-01T00:00:00Z",
      AssumeRolePolicyDocument: { Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: "*" }, Action: "sts:AssumeRole" }] }, AttachedManagedPolicies: [], RolePolicyList: [] },
    { Path: "/", RoleName: "VendorRole", RoleId: "AROAEXAMPLE2", Arn: "arn:aws:iam::123456789012:role/VendorRole", CreateDate: "2024-05-01T00:00:00Z",
      AssumeRolePolicyDocument: encodeURIComponent(JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: "arn:aws:iam::999988887777:root" }, Action: "sts:AssumeRole" }] })), AttachedManagedPolicies: [], RolePolicyList: [] },
    { Path: "/", RoleName: "PartnerRole", RoleId: "AROAEXAMPLE3", Arn: "arn:aws:iam::123456789012:role/PartnerRole", CreateDate: "2024-05-01T00:00:00Z",
      AssumeRolePolicyDocument: { Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: "arn:aws:iam::111122223333:root" }, Action: "sts:AssumeRole", Condition: { StringEquals: { "sts:ExternalId": "abc-123" } } }] }, AttachedManagedPolicies: [], RolePolicyList: [] },
    { Path: "/aws-service-role/", RoleName: "AWSServiceRoleForSupport", RoleId: "AROAEXAMPLE4", Arn: "arn:aws:iam::123456789012:role/aws-service-role/AWSServiceRoleForSupport", CreateDate: "2021-01-01T00:00:00Z",
      AssumeRolePolicyDocument: { Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { Service: "support.amazonaws.com" }, Action: "sts:AssumeRole" }] }, AttachedManagedPolicies: [], RolePolicyList: [] },
  ],
  Policies: [
    { PolicyName: "CustomNotAction", PolicyId: "ANPAEXAMPLE1", Arn: "arn:aws:iam::123456789012:policy/CustomNotAction", AttachmentCount: 1, IsAttachable: true, DefaultVersionId: "v1",
      PolicyVersionList: [{ Document: { Version: "2012-10-17", Statement: [{ Effect: "Allow", NotAction: ["iam:*", "organizations:*"], Resource: "*" }] }, VersionId: "v1", IsDefaultVersion: true }] },
  ],
});

const GCP_IAM = JSON.stringify({
  bindings: [
    { role: "roles/owner", members: ["user:carol.s@test.darknode.ai"] },
    { role: "roles/editor", members: ["serviceAccount:ci-runner@synthetic-proj.iam.gserviceaccount.com"] },
    { role: "roles/viewer", members: ["allUsers", "group:analysts@test.darknode.ai"] },
    { role: "roles/iam.serviceAccountTokenCreator", members: ["user:dave.r@test.darknode.ai"] },
    { role: "roles/storage.admin", members: ["user:erin.l@test.darknode.ai"], condition: { title: "expires", expression: "request.time < timestamp(\"2026-12-31T00:00:00Z\")" } },
  ],
  etag: "BwYk9z2abcd=",
  version: 3,
});

const GCP_CLEAN = JSON.stringify({ bindings: [{ role: "roles/viewer", members: ["group:analysts@test.darknode.ai"] }, { role: "roles/logging.viewer", members: ["user:erin.l@test.darknode.ai"] }], etag: "BwYk9z2efgh=", version: 1 });

const OKTA_CSV = [
  "Login,First name,Last name,Role,Status,Last login",
  "kara.n@test.darknode.ai,Kara,Nilsen,SUPER_ADMIN,ACTIVE,2026-09-30 08:12:44 UTC",
  "liam.o@test.darknode.ai,Liam,Ortega,SUPER_ADMIN,ACTIVE,2026-09-29 17:01:02 UTC",
  "maya.q@test.darknode.ai,Maya,Quinn,SUPER_ADMIN,ACTIVE,2026-05-01 09:00:00 UTC",
  "noah.r@test.darknode.ai,Noah,Reyes,SUPER_ADMIN,ACTIVE,2026-09-28 12:00:00 UTC",
  "olga.s@test.darknode.ai,Olga,Sato,APP_ADMIN,DEPROVISIONED,2025-11-02 10:30:00 UTC",
  "it-admin@test.darknode.ai,IT,Admin,ORG_ADMIN,ACTIVE,2026-09-30 07:00:00 UTC",
].join("\n");

const OKTA_JSON = JSON.stringify([
  { id: "ra1", label: "Super Organization Administrator", type: "SUPER_ADMIN", status: "ACTIVE", created: "2025-01-01T00:00:00.000Z", lastUpdated: "2025-01-01T00:00:00.000Z", assignmentType: "USER", user: { id: "00u1", status: "ACTIVE", lastLogin: "2026-09-30T08:12:44.000Z", profile: { login: "kara.n@test.darknode.ai", firstName: "Kara", lastName: "Nilsen" } } },
  { id: "ra2", label: "Application Administrator", type: "APP_ADMIN", status: "ACTIVE", created: "2025-01-01T00:00:00.000Z", lastUpdated: "2025-01-01T00:00:00.000Z", assignmentType: "USER", user: { id: "00u2", status: "SUSPENDED", lastLogin: "2025-11-02T10:30:00.000Z", profile: { login: "olga.s@test.darknode.ai", firstName: "Olga", lastName: "Sato" } } },
]);

const GITHUB_CSV = [
  "Login,Name,Role,Two-factor,Saml identity",
  "pat-dev,Pat Devlin,Owner,Enabled,pat.d@test.darknode.ai",
  "quinn-ops,Quinn Osei,Owner,Disabled,quinn.o@test.darknode.ai",
  "rae-sec,Rae Sun,Owner,Enabled,rae.s@test.darknode.ai",
  "sam-ci,Sam Cho,Owner,Enabled,sam.c@test.darknode.ai",
  "tess-fe,Tess Faro,Member,Disabled,",
  "uma-be,Uma Baek,Member,Enabled,uma.b@test.darknode.ai",
].join("\n");

const GITHUB_JSON = JSON.stringify([
  { login: "pat-dev", id: 1001, node_id: "MDQ6VXNlcjEwMDE=", avatar_url: "https://avatars.githubusercontent.com/u/1001?v=4", type: "User", site_admin: false },
  { login: "quinn-ops", id: 1002, node_id: "MDQ6VXNlcjEwMDI=", avatar_url: "https://avatars.githubusercontent.com/u/1002?v=4", type: "User", site_admin: false },
]);

// ------------------------------------------------------------------ tests --
group("privaudit: self-test, determinism, empty input", () => {
  test("in-engine self-test passes", () => {
    const r = selfTest();
    assert.ok(r.pass, "failed: " + r.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
    assert.ok(r.tests.length >= 8);
  });
  test("analyze is byte-identical across runs (multi-source example)", () => {
    const ex = exampleDataset();
    assert.equal(JSON.stringify(analyze(ex.parsed, { now: NOW })), JSON.stringify(analyze(ex.parsed, { now: NOW })));
  });
  test("analyze is byte-identical regardless of file order", () => {
    const a = run([{ name: "a.csv", text: ENTRA_CSV }, { name: "b.csv", text: AWS_CRED }, { name: "c.json", text: GCP_IAM }]);
    const b = run([{ name: "c.json", text: GCP_IAM }, { name: "b.csv", text: AWS_CRED }, { name: "a.csv", text: ENTRA_CSV }]);
    assert.equal(JSON.stringify(a.findings), JSON.stringify(b.findings));
    assert.equal(JSON.stringify(a.tables), JSON.stringify(b.tables));
  });
  test("empty input yields zero findings and does not throw", () => {
    const parsed = parseInput("");
    assert.equal(parsed.rows.length, 0);
    assert.equal(parsed.skipped[0].reason, "empty file");
    const r = analyze(parsed.rows);
    assert.equal(r.findings.length, 0);
    assert.equal(r.meta.rows, 0);
    assert.equal(r.meta.tool, TOOL_ID);
    assert.ok(VERSION.length > 0);
  });
  test("without opts.now the reference date is the newest timestamp in the data", () => {
    const r = analyze(parseInput([{ name: "aws.csv", text: AWS_CRED }]));
    assert.equal(r.meta.now, "2026-10-01T09:12:00.000Z");
  });
  test("example dataset is labelled synthetic and parses into three recognised sources", () => {
    const ex = exampleDataset();
    assert.ok(/synthetic/.test(ex.label));
    assert.deepEqual(ex.parsed.files.map((f) => f.source), ["entra", "aws-credential-report", "gcp-iam"]);
    assert.equal(ex.parsed.skipped.length, 0);
  });
});

group("privaudit: parsers (one per vendor format)", () => {
  test("Entra portal 'Download assignments' CSV", () => {
    const p = parseInput([{ name: "RoleAssignments.csv", text: ENTRA_CSV }]);
    assert.equal(p.files[0].source, "entra");
    assert.ok(p.files[0].confidence >= 0.9);
    assert.equal(p.rows.length, 8);
    const erin = p.rows.find((r) => r.principal === "erin.l@test.darknode.ai");
    assert.equal(erin.assignmentType, "Eligible");
    assert.equal(p.rows.find((r) => r.principal === "grace.t@test.darknode.ai").assignmentType, "Active");
    assert.equal(p.rows[0].assignmentType, "Permanent");
    assert.equal(p.rows[0].startDate, "2025-01-12T09:14:00.000Z");
  });
  test("Entra Graph roleAssignments JSON (role GUID mapped, service principal typed)", () => {
    const p = parseInput([{ name: "roleAssignments.json", text: ENTRA_JSON }]);
    assert.equal(p.files[0].source, "entra");
    assert.equal(p.rows.length, 3);
    assert.equal(p.rows[0].role, "Global Administrator");
    assert.equal(p.rows[1].role, ENTRA_ROLE_IDS["e8611ab8-c189-46e8-94e1-60213ab1f814"]);
    assert.equal(p.rows[1].objectType, "ServicePrincipal");
    assert.equal(p.rows[2].role, "User Administrator");
    assert.ok(p.rows.every((r) => r.assignmentType === "Permanent"));
  });
  test("Entra Graph roleEligibilityScheduleInstances JSON is read as Eligible", () => {
    const p = parseInput([{ name: "eligibility.json", text: ENTRA_ELIGIBLE_JSON }]);
    assert.equal(p.rows.length, 2);
    assert.ok(p.rows.every((r) => r.assignmentType === "Eligible"));
    assert.equal(p.rows[0].endDate, "2026-12-31T00:00:00.000Z");
  });
  test("AWS credential report CSV (exact 22 headers, N/A sentinels, root row)", () => {
    const p = parseInput([{ name: "credential-report.csv", text: AWS_CRED }]);
    assert.equal(p.files[0].source, "aws-credential-report");
    assert.equal(p.files[0].confidence, 1);
    assert.equal(p.rows.length, 6);
    const root = p.rows.find((r) => r.isRoot);
    assert.equal(root.user, "<root_account>");
    assert.equal(root.password_enabled, null, "not_supported becomes null");
    assert.equal(p.rows.find((r) => r.user === "jsmith").access_key_1_last_rotated, null);
    assert.equal(p.rows.find((r) => r.user === "ops-admin").access_key_1_last_rotated, "2025-08-27T12:00:00+00:00");
  });
  test("AWS get-account-authorization-details JSON (URL-encoded and object policy documents)", () => {
    const p = parseInput([{ name: "auth-details.json", text: AWS_AUTH }]);
    assert.equal(p.files[0].source, "aws-auth-details");
    const kinds = p.rows.reduce((m, r) => ((m[r._kind] = (m[r._kind] || 0) + 1), m), {});
    assert.deepEqual(kinds, { user: 3, group: 2, role: 4, policy: 1 });
    const js = p.rows.find((r) => r._kind === "user" && r.name === "jsmith");
    assert.deepEqual(js.inlinePolicies[0].doc.Statement.Action, ["iam:*"]);
    const vendor = p.rows.find((r) => r._kind === "role" && r.name === "VendorRole");
    assert.equal(vendor.trust.Statement[0].Principal.AWS, "arn:aws:iam::999988887777:root");
  });
  test("GCP get-iam-policy JSON (bindings expanded per member, condition kept)", () => {
    const p = parseInput([{ name: "my-proj-policy.json", text: GCP_IAM }]);
    assert.equal(p.files[0].source, "gcp-iam");
    assert.equal(p.rows.length, 6);
    assert.equal(p.rows.find((r) => r.member === "allUsers").memberType, "allUsers");
    assert.equal(p.rows.find((r) => r.member.startsWith("serviceAccount:")).memberType, "serviceAccount");
    assert.equal(p.rows.find((r) => r.role === "roles/storage.admin").condition, "expires");
    assert.equal(p.rows[0].project, "my-proj-policy");
  });
  test("GCP: array of {projectId, bindings} policies", () => {
    const p = parseInput([{ name: "all.json", text: JSON.stringify([{ projectId: "p1", bindings: [{ role: "roles/owner", members: ["user:a@test.darknode.ai"] }] }, { projectId: "p2", bindings: [{ role: "roles/viewer", members: ["user:b@test.darknode.ai"] }] }]) }]);
    assert.equal(p.files[0].source, "gcp-iam");
    assert.deepEqual(p.rows.map((r) => r.project), ["p1", "p2"]);
  });
  test("Okta administrators dashboard CSV", () => {
    const p = parseInput([{ name: "okta-admins.csv", text: OKTA_CSV }]);
    assert.equal(p.files[0].source, "okta-admins");
    assert.equal(p.rows.length, 6);
    assert.equal(p.rows[0].role, "SUPER_ADMIN");
    assert.equal(p.rows[0].lastLogin, "2026-09-30T08:12:44.000Z");
    assert.equal(p.rows[4].status, "DEPROVISIONED");
    assert.equal(p.rows[0].name, "Kara Nilsen");
  });
  test("Okta role-assignment JSON (type + nested user profile)", () => {
    const p = parseInput([{ name: "okta-roles.json", text: OKTA_JSON }]);
    assert.equal(p.files[0].source, "okta-admins");
    assert.equal(p.rows.length, 2);
    assert.equal(p.rows[0].login, "kara.n@test.darknode.ai");
    assert.equal(p.rows[0].role, "SUPER_ADMIN");
    assert.equal(p.rows[1].status, "SUSPENDED");
    assert.equal(p.rows[1].lastLogin, "2025-11-02T10:30:00.000Z");
  });
  test("GitHub organization people CSV export", () => {
    const p = parseInput([{ name: "export-members.csv", text: GITHUB_CSV }]);
    assert.equal(p.files[0].source, "github-members");
    assert.equal(p.rows.length, 6);
    assert.equal(p.rows[0].role, "owner");
    assert.equal(p.rows[0].twoFactor, true);
    assert.equal(p.rows[1].twoFactor, false);
    assert.equal(p.rows[4].role, "member");
    assert.equal(p.rows[4].saml, null);
  });
  test("GitHub gh api orgs/{org}/members JSON (no role field is reported, not guessed)", () => {
    const p = parseInput([{ name: "members.json", text: GITHUB_JSON }]);
    assert.equal(p.files[0].source, "github-members");
    assert.equal(p.rows.length, 2);
    assert.equal(p.rows[0].role, null);
    assert.ok(/no role field/.test(p.files[0].note));
    const r = analyze(p, { now: NOW });
    assert.ok(r.skipped.some((s) => s.check === "github_owner_count" && /no role/.test(s.reason)));
    assert.ok(r.skipped.some((s) => s.check === "github_no_2fa"));
  });
  test("ambiguous Login/Role CSV is resolved from role values (Okta names vs owner/member)", () => {
    assert.equal(detectCsvSource(["Login", "Role"], [{ Login: "a", Role: "SUPER_ADMIN" }]).source, "okta-admins");
    assert.equal(detectCsvSource(["Login", "Role"], [{ Login: "a", Role: "Owner" }]).source, "github-members");
    assert.ok(detectCsvSource(["Login", "Role"], [{ Login: "a", Role: "Owner" }]).confidence < 0.9, "ambiguous layout gets non-high confidence");
  });
  test("unknown CSV and unknown JSON are reported in skipped and contribute no rows", () => {
    const p = parseInput([{ name: "x.csv", text: "a,b\n1,2" }, { name: "y.json", text: '{"foo":[1,2]}' }]);
    assert.equal(p.rows.length, 0);
    assert.equal(p.skipped.length, 2);
    assert.ok(/not recognised/.test(p.skipped[0].reason));
    assert.equal(detectJsonSource({ foo: 1 }).source, "unknown");
  });
  test("column overrides and forced source are honoured", () => {
    const text = "Who,Which,Kind\nzed@test.darknode.ai,Global Administrator,Permanent";
    const p0 = parseInput([{ name: "odd.csv", text }]);
    assert.equal(p0.rows.length, 0);
    const p = parseInput([{ name: "odd.csv", text }], { source: { "odd.csv": "entra" }, columns: { entra: { principal: "Who", role: "Which", assignmentType: "Kind" } } });
    assert.equal(p.rows.length, 1);
    assert.equal(p.rows[0].role, "Global Administrator");
    assert.equal(p.rows[0].assignmentType, "Permanent");
  });
  test("value helpers: parseDate formats, parseBool spellings, shared-name heuristic, policy decoding", () => {
    assert.equal(parseDate("2026-09-30 08:12:44 UTC"), Date.UTC(2026, 8, 30, 8, 12, 44));
    assert.equal(parseDate("1/12/2025 09:14:00"), Date.UTC(2025, 0, 12, 9, 14));
    assert.equal(parseDate("2026-09-20T08:02:44+00:00"), Date.UTC(2026, 8, 20, 8, 2, 44));
    assert.equal(parseDate("2026-09-20T10:02:44+02:00"), Date.UTC(2026, 8, 20, 8, 2, 44));
    assert.equal(parseDate("N/A"), null);
    assert.equal(parseDate("no_information"), null);
    assert.equal(parseBool("Enabled"), true);
    assert.equal(parseBool("Disabled"), false);
    assert.equal(parseBool("maybe"), null);
    assert.ok(looksShared("admin@test.darknode.ai"));
    assert.ok(looksShared("it-admin"));
    assert.ok(looksShared("svc_backup"));
    assert.ok(!looksShared("alice.m@test.darknode.ai"));
    assert.ok(!looksShared("<root_account>"));
    assert.deepEqual(decodePolicy(encodeURIComponent('{"a":1}')), { a: 1 });
    assert.equal(decodePolicy("not json"), null);
  });
});

group("privaudit: Entra detections", () => {
  const r = run([{ name: "entra.csv", text: ENTRA_CSV }]);
  const f = byId(r);
  test("permanent Global Administrator assignments fire with five principals and SCuBA/CIS controls", () => {
    assert.ok(f.entra_permanent_tier0);
    assert.equal(f.entra_permanent_tier0.severity, "high");
    assert.equal(f.entra_permanent_tier0.evidenceCount, 5);
    assert.ok(f.entra_permanent_tier0.controls.some((c) => c.framework === "CISA SCuBA" && c.id === "MS.AAD.7.4"));
    assert.ok(f.entra_permanent_tier0.controls.some((c) => c.framework === "CIS Microsoft 365" && c.id === "1.1.3"));
    assert.ok(f.entra_permanent_tier0.assets.every((a) => a.type === "IDENTITY" && a.data.privileged === true));
  });
  test("more than four standing Global Admins fires; eligible admin is not counted as standing", () => {
    assert.ok(f.entra_global_admin_count);
    assert.equal(f.entra_global_admin_count.evidenceCount, 5);
    assert.ok(!f.entra_global_admin_count.evidence.some((e) => e.principal === "erin.l@test.darknode.ai"));
  });
  test("threshold edge: maxGlobalAdmins 5 silences the count finding, 4 fires it", () => {
    assert.ok(!byId(run([{ name: "e.csv", text: ENTRA_CSV }], { maxGlobalAdmins: 5 })).entra_global_admin_count);
    assert.ok(byId(run([{ name: "e.csv", text: ENTRA_CSV }], { maxGlobalAdmins: 4 })).entra_global_admin_count);
  });
  test("lockout risk fires with a single Global Admin and stays silent with two", () => {
    const one = "Role,Display name,User principal name,Object ID,Object type,Assignment type,Scope,Start date,End date\nGlobal Administrator,Solo,solo@test.darknode.ai,,User,Eligible,Directory,,";
    const r1 = byId(run([{ name: "e.csv", text: one }]));
    assert.ok(r1.entra_global_admin_lockout);
    assert.equal(r1.entra_global_admin_lockout.severity, "medium");
    assert.ok(!f.entra_global_admin_lockout);
  });
  test("permanent assignments on other admin roles fire (Exchange) but an Active time-bound one does not", () => {
    assert.ok(f.entra_standing_privileged);
    assert.equal(f.entra_standing_privileged.evidenceCount, 1);
    assert.equal(f.entra_standing_privileged.evidence[0].role, "Exchange Administrator");
  });
  test("JIT ratio and Entra KPIs in summary", () => {
    assert.equal(r.summary.eligible, 1);
    assert.equal(r.summary.standing, 7);
    assert.equal(r.summary.jitRatio, 0.125);
    assert.equal(r.summary.globalAdmins, 6);
  });
  test("service principal holding Privileged Role Administrator is reported from Graph JSON", () => {
    const g = byId(run([{ name: "roleAssignments.json", text: ENTRA_JSON }]));
    assert.ok(g.entra_sp_admin);
    assert.equal(g.entra_sp_admin.evidence[0].principal, "9c1f0e2d-3b4a-4c5d-8e6f-7a8b9c0d1e2f");
    assert.ok(g.entra_permanent_tier0, "permanent GA + PRA from plain roleAssignments");
    assert.equal(g.entra_permanent_tier0.evidenceCount, 2);
  });
  test("an eligibility-only export produces no standing-privilege findings", () => {
    const g = run([{ name: "roleEligibilityScheduleInstances.json", text: ENTRA_ELIGIBLE_JSON }]);
    assert.ok(!byId(g).entra_permanent_tier0);
    assert.ok(!byId(g).entra_standing_privileged);
    assert.equal(g.summary.jitRatio, 1);
  });
  test("Entra checks are skipped with a reason when no Entra input is present", () => {
    const s = skippedChecks(run([{ name: "aws.csv", text: AWS_CRED }]));
    assert.ok(s.includes("entra_permanent_tier0") && s.includes("entra_global_admin_count"));
  });
});

group("privaudit: AWS credential report detections", () => {
  const r = run([{ name: "credential-report.csv", text: AWS_CRED }]);
  const f = byId(r);
  test("root without MFA is critical and cites CIS AWS 1.5", () => {
    assert.ok(f.aws_root_mfa);
    assert.equal(f.aws_root_mfa.severity, "critical");
    assert.ok(f.aws_root_mfa.controls.some((c) => c.framework === "CIS AWS Foundations" && c.id === "1.5"));
  });
  test("root used within 30 days fires (CIS AWS 1.7); edge: 11 days old vs rootUsedDays 10 stays silent", () => {
    assert.ok(f.aws_root_used);
    assert.ok(f.aws_root_used.controls.some((c) => c.id === "1.7"));
    assert.ok(!byId(run([{ name: "c.csv", text: AWS_CRED }], { rootUsedDays: 10 })).aws_root_used);
  });
  test("root active access key is critical (CIS AWS 1.4)", () => {
    assert.ok(f.aws_root_keys);
    assert.equal(f.aws_root_keys.severity, "critical");
  });
  test("console user without MFA fires for exactly jsmith (CIS AWS 1.10)", () => {
    assert.ok(f.aws_user_no_mfa);
    assert.deepEqual(f.aws_user_no_mfa.evidence.map((e) => e.user), ["jsmith"]);
  });
  test("key older than 90 days fires for ops-admin at 400 days; edge: keyRotationDays 401 silences it", () => {
    assert.ok(f.aws_key_rotation);
    assert.equal(f.aws_key_rotation.evidence[0].user, "ops-admin");
    assert.equal(f.aws_key_rotation.evidence[0].ageDays, 400);
    assert.ok(!byId(run([{ name: "c.csv", text: AWS_CRED }], { keyRotationDays: 401 })).aws_key_rotation);
    assert.ok(byId(run([{ name: "c.csv", text: AWS_CRED }], { keyRotationDays: 399 })).aws_key_rotation);
  });
  test("unused credential > 45 days fires for legacy-svc only (CIS AWS 1.12)", () => {
    assert.ok(f.aws_unused_credentials);
    assert.deepEqual(f.aws_unused_credentials.evidence.map((e) => e.user), ["legacy-svc"]);
    assert.equal(f.aws_unused_credentials.evidence[0].credential, "access_key_1");
  });
  test("two active access keys fires for deploy-bot (CIS AWS 1.13)", () => {
    assert.ok(f.aws_two_keys);
    assert.deepEqual(f.aws_two_keys.evidence.map((e) => e.user), ["deploy-bot"]);
  });
  test("a clean credential report produces no AWS findings", () => {
    const c = run([{ name: "c.csv", text: AWS_CRED_CLEAN }]);
    assert.equal(c.findings.filter((x) => x.id.startsWith("aws_")).length, 0);
    assert.ok(!skippedChecks(c).includes("aws_root_mfa"));
  });
  test("age checks are skipped (not guessed) when no reference date can be derived", () => {
    const noDates = AWS_CRED_HEADERS.join(",") + "\nbob,arn:aws:iam::123456789012:user/bob,N/A,true,N/A,N/A,N/A,false,true,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A";
    const r2 = analyze(parseInput([{ name: "c.csv", text: noDates }]));
    assert.equal(r2.meta.now, null);
    assert.ok(r2.skipped.some((s) => s.check === "aws_key_rotation" && /reference date/.test(s.reason)));
    assert.ok(byId(r2).aws_user_no_mfa, "non-date checks still run");
  });
  test("principal inventory marks root privileged with MFA false and lists IAM users", () => {
    const root = r.tables.principals.find((p) => p.principal === "<root_account>");
    assert.equal(root.privileged, true);
    assert.equal(root.mfa, false);
    assert.ok(root.flags.includes("root-no-mfa") && root.flags.includes("root-access-key"));
    assert.equal(r.tables.principals.filter((p) => p.source === "aws-credential-report").length, 6);
  });
});

group("privaudit: AWS authorization details detections", () => {
  const r = run([{ name: "auth.json", text: AWS_AUTH }]);
  const f = byId(r);
  test("AdministratorAccess via group membership fires for ops-admin and the admins group (CIS AWS 1.16)", () => {
    assert.ok(f.aws_admin_access);
    assert.deepEqual([...new Set(f.aws_admin_access.evidence.map((e) => e.entity))].sort(), ["admins", "ops-admin"]);
    assert.ok(f.aws_admin_access.controls.some((c) => c.id === "1.16"));
  });
  test("iam:* inline policy and NotAction managed policy are over-broad (T1098.003)", () => {
    assert.ok(f.aws_wildcard_policy);
    const kinds = f.aws_wildcard_policy.evidence.map((e) => e.risk);
    assert.ok(kinds.includes("iam_star"));
    assert.ok(f.aws_wildcard_policy.controls.some((c) => c.id === "T1098.003"));
  });
  test("policyRisks classifies full admin, iam:*, sts:AssumeRole on * and NotAction", () => {
    assert.deepEqual(policyRisks(ADMIN_DOC).map((x) => x.kind), ["full_admin"]);
    assert.deepEqual(policyRisks({ Statement: { Effect: "Allow", Action: "sts:AssumeRole", Resource: "*" } }).map((x) => x.kind), ["assume_role_star"]);
    assert.deepEqual(policyRisks({ Statement: [{ Effect: "Allow", NotAction: "iam:*", Resource: "*" }] }).map((x) => x.kind), ["not_action_allow"]);
    assert.deepEqual(policyRisks({ Statement: [{ Effect: "Deny", Action: "*", Resource: "*" }, { Effect: "Allow", Action: "s3:GetObject", Resource: "arn:aws:s3:::b/*" }] }), []);
  });
  test("role trust: Principal * is critical; foreign account without ExternalId is reported; ExternalId + trusted list silences; service-linked roles are ignored", () => {
    assert.ok(f.aws_role_trust);
    assert.equal(f.aws_role_trust.severity, "critical");
    const roles = f.aws_role_trust.evidence.map((e) => e.role);
    assert.ok(roles.includes("OpenRole") && roles.includes("VendorRole"));
    assert.ok(!roles.includes("AWSServiceRoleForSupport"));
    assert.ok(f.aws_role_trust.evidence.some((e) => e.role === "PartnerRole" && e.risk === "untrusted_account"), "PartnerRole account not in trusted list");
    assert.ok(!f.aws_role_trust.evidence.some((e) => e.role === "PartnerRole" && e.risk === "no_external_id"));
    const trusted = run([{ name: "auth.json", text: AWS_AUTH }], { trustedAccounts: "111122223333, 999988887777" });
    const ev = byId(trusted).aws_role_trust.evidence;
    assert.ok(!ev.some((e) => e.role === "PartnerRole"));
    assert.ok(ev.some((e) => e.role === "VendorRole" && e.risk === "no_external_id"));
    assert.deepEqual(trustRisks({ Statement: [{ Effect: "Allow", Principal: { AWS: "arn:aws:iam::123456789012:root" }, Action: "sts:AssumeRole" }] }, "123456789012", new Set()), []);
  });
  test("directly attached / inline user policies fire (CIS AWS 1.15) for jsmith only", () => {
    assert.ok(f.aws_direct_user_policies);
    assert.deepEqual(f.aws_direct_user_policies.evidence.map((e) => e.user), ["jsmith"]);
  });
  test("credential report + authorization details: privileged AWS user becomes stale-eligible and privileged in inventory", () => {
    const both = run([{ name: "auth.json", text: AWS_AUTH }, { name: "cred.csv", text: AWS_CRED }]);
    const ops = both.tables.principals.find((p) => p.source === "aws-credential-report" && p.principal === "ops-admin");
    assert.equal(ops.privileged, true);
    assert.ok(ops.roles.includes("AdministratorAccess"));
    assert.ok(!skippedChecks(both).includes("stale_admins"));
  });
});

group("privaudit: GCP detections", () => {
  const r = run([{ name: "policy.json", text: GCP_IAM }]);
  const f = byId(r);
  test("allUsers binding is critical", () => {
    assert.ok(f.gcp_public_binding);
    assert.equal(f.gcp_public_binding.severity, "critical");
    assert.equal(f.gcp_public_binding.evidence[0].member, "allUsers");
  });
  test("roles/owner on a user fires; group viewer does not", () => {
    assert.ok(f.gcp_primitive_roles);
    assert.deepEqual(f.gcp_primitive_roles.evidence.map((e) => e.member), ["user:carol.s@test.darknode.ai"]);
  });
  test("service account editor and user Token Creator fire (CIS GCP 1.5 / 1.6)", () => {
    assert.ok(f.gcp_sa_privileged);
    const members = f.gcp_sa_privileged.evidence.map((e) => e.member).sort();
    assert.deepEqual(members, ["serviceAccount:ci-runner@synthetic-proj.iam.gserviceaccount.com", "user:dave.r@test.darknode.ai"]);
    assert.ok(f.gcp_sa_privileged.controls.some((c) => c.framework === "CIS GCP Foundations" && c.id === "1.6"));
  });
  test("unconditional high roles are review-confidence and exclude the conditioned storage.admin grant", () => {
    assert.ok(f.gcp_unconditional_high_roles);
    assert.equal(f.gcp_unconditional_high_roles.confidence, "review");
    assert.ok(!f.gcp_unconditional_high_roles.evidence.some((e) => e.role === "roles/storage.admin"));
  });
  test("a clean policy produces no GCP findings", () => {
    const c = run([{ name: "policy.json", text: GCP_CLEAN }]);
    assert.equal(c.findings.filter((x) => x.id.startsWith("gcp_")).length, 0);
  });
});

group("privaudit: Okta and GitHub detections", () => {
  const ok = byId(run([{ name: "okta-admins.csv", text: OKTA_CSV }]));
  test("more than three Okta SUPER_ADMINs fires; edge: maxSuperAdmins 4 silences", () => {
    assert.ok(ok.okta_super_admin_count);
    assert.equal(ok.okta_super_admin_count.evidenceCount, 4);
    assert.ok(!byId(run([{ name: "o.csv", text: OKTA_CSV }], { maxSuperAdmins: 4 })).okta_super_admin_count);
  });
  test("deprovisioned admin is high severity", () => {
    assert.ok(ok.okta_inactive_admins);
    assert.equal(ok.okta_inactive_admins.severity, "high");
    assert.equal(ok.okta_inactive_admins.evidence[0].login, "olga.s@test.darknode.ai");
  });
  test("stale admins from Okta last login (> 90 days) and shared-name heuristic for it-admin", () => {
    assert.ok(ok.stale_admins);
    const logins = ok.stale_admins.evidence.map((e) => e.principal);
    assert.ok(logins.includes("maya.q@test.darknode.ai") && logins.includes("olga.s@test.darknode.ai"));
    assert.ok(!logins.includes("kara.n@test.darknode.ai"));
    assert.ok(ok.shared_admin_accounts);
    assert.equal(ok.shared_admin_accounts.confidence, "review");
    assert.ok(ok.shared_admin_accounts.evidence.some((e) => e.principal === "it-admin@test.darknode.ai"));
  });
  test("threshold edge: staleDays 200 keeps maya (153 days) but still reports olga", () => {
    const s = byId(run([{ name: "o.csv", text: OKTA_CSV }], { staleDays: 200 })).stale_admins;
    assert.ok(s);
    assert.deepEqual(s.evidence.map((e) => e.principal), ["olga.s@test.darknode.ai"]);
  });
  test("Okta JSON: suspended admin fires, super-admin count does not", () => {
    const j = byId(run([{ name: "okta-roles.json", text: OKTA_JSON }]));
    assert.ok(j.okta_inactive_admins);
    assert.ok(!j.okta_super_admin_count);
  });
  const gh = byId(run([{ name: "members.csv", text: GITHUB_CSV }]));
  test("more than three GitHub owners fires (CIS SSC 1.3.3); edge: maxOrgOwners 4 silences", () => {
    assert.ok(gh.github_owner_count);
    assert.equal(gh.github_owner_count.evidenceCount, 4);
    assert.ok(gh.github_owner_count.controls.some((c) => c.framework === "CIS Software Supply Chain" && c.id === "1.3.3"));
    assert.ok(!byId(run([{ name: "m.csv", text: GITHUB_CSV }], { maxOrgOwners: 4 })).github_owner_count);
  });
  test("members without 2FA fire and are high when an owner is among them", () => {
    assert.ok(gh.github_no_2fa);
    assert.equal(gh.github_no_2fa.severity, "high");
    assert.deepEqual(gh.github_no_2fa.evidence.map((e) => e.login), ["quinn-ops", "tess-fe"]);
    assert.deepEqual(gh.github_no_2fa.assets.map((a) => a.name), ["quinn-ops"], "only owners are graph assets");
  });
  test("stale check is skipped with a reason when no source carries a last-login field", () => {
    const r = run([{ name: "m.csv", text: GITHUB_CSV }]);
    assert.ok(r.skipped.some((s) => s.check === "stale_admins" && /last sign-in/.test(s.reason)));
  });
});

group("privaudit: finding shape, tables and exports", () => {
  const r = analyze(exampleDataset().parsed, { now: NOW });
  test("every finding has the contract fields, >= 1 control, capped evidence and IDENTITY assets", () => {
    assert.ok(r.findings.length >= 10);
    for (const f of r.findings) {
      assert.ok(["critical", "high", "medium", "low", "info"].includes(f.severity), f.id);
      assert.ok(["confirmed", "likely", "review"].includes(f.confidence), f.id);
      assert.ok(f.controls.length >= 1 && f.controls.every((c) => c.framework && c.id), f.id);
      assert.ok(f.title && f.description && f.recommendation && f.category, f.id);
      assert.ok(f.evidence.length <= 50 && f.evidenceCount >= f.evidence.length, f.id);
      assert.ok(f.assets.every((a) => a.type === "IDENTITY" && a.name && a.data && "roles" in a.data && "source" in a.data), f.id);
    }
  });
  test("findings are sorted by severity then title", () => {
    const rank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    for (let i = 1; i < r.findings.length; i++) {
      const a = r.findings[i - 1], b = r.findings[i];
      assert.ok(rank[a.severity] > rank[b.severity] || (rank[a.severity] === rank[b.severity] && a.title <= b.title));
    }
  });
  test("principals table has one row per (source, principal) with roles, flags and MFA", () => {
    const keys = r.tables.principals.map((p) => p.source + "|" + p.principal);
    assert.equal(new Set(keys).size, keys.length);
    const admin = r.tables.principals.find((p) => p.principal === "admin@test.darknode.ai");
    assert.deepEqual(admin.roles, ["Global Administrator"]);
    assert.ok(admin.flags.includes("shared-name") && admin.flags.includes("permanent-tier0"));
    assert.equal(admin.assignmentType, "Permanent");
  });
  test("findingsToCsv has the fixed header row and one line per finding", () => {
    const csv = findingsToCsv(r.findings);
    const lines = csv.split("\n");
    assert.equal(lines[0], "severity,confidence,category,title,description,recommendation,controls,evidenceCount,assets");
    assert.equal(lines.length, r.findings.length + 1);
    assert.equal(findingsToCsv([]), lines[0]);
  });
  test("principalsToCsv has the inventory header and quotes list columns", () => {
    const lines = principalsToCsv(r.tables.principals).split("\n");
    assert.equal(lines[0], "source,principal,name,type,roles,assignmentType,lastUsed,mfa,privileged,flags");
    assert.equal(lines.length, r.tables.principals.length + 1);
    assert.ok(lines.some((l) => l.includes('"Global Administrator"')));
  });
  test("attestationText records reviewer, date, parameters, findings and skipped checks; engine never reads a clock", () => {
    const t = attestationText(r, { reviewer: "Reviewer One", date: "2026-10-16T10:00:00Z", dataset: "example" });
    assert.ok(t.includes("Reviewer: Reviewer One"));
    assert.ok(t.includes("Review date: 2026-10-16T10:00:00Z"));
    assert.ok(t.includes("stale after " + DEFAULTS.staleDays + " days"));
    assert.ok(t.includes("CHECKS NOT RUN") && t.includes("okta_super_admin_count"));
    assert.ok(t.includes("I confirm"));
    assert.ok(attestationText(r, {}).includes("draft"));
  });
  test("thresholds are echoed in meta and skipped list is sorted", () => {
    assert.equal(r.meta.thresholds.staleDays, DEFAULTS.staleDays);
    assert.equal(r.meta.thresholds.trustedAccounts, "");
    const checks = skippedChecks(r);
    assert.deepEqual(checks, checks.slice().sort());
  });
  test("progress callback is invoked and optional", () => {
    const calls = [];
    analyze(exampleDataset().parsed, { now: NOW }, { progress: (i, n, l) => calls.push([i, n, l]) });
    assert.ok(calls.length >= 2);
    assert.equal(calls[calls.length - 1][2], "done");
    assert.ok(analyze(exampleDataset().parsed, { now: NOW }, {}).findings.length > 0);
  });
  test("COLUMNS cover every detected tabular source", () => {
    assert.ok(COLUMNS.entra.role.includes("Role"));
    assert.ok(COLUMNS["okta-admins"].lastLogin.includes("Last login"));
    assert.ok(COLUMNS["github-members"].twoFactor.includes("Two-factor"));
    assert.equal(Object.keys(COLUMNS["aws-credential-report"]).length, 22);
  });
});
