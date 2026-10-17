// Backup Readiness engine tests (public/js/risk/backupready-engine.js): one parser test per
// vendor export with verbatim headers / JSON shapes, asset matching, RPO maths against a fixed
// `now`, every detection positive and negative, 3-2-1-1-0 with unknowns, score maths,
// determinism, selfTest and the CSV / report exports.

import { test, assert, group } from "../harness.mjs";
import {
  selfTest, analyze, parseInput, detectFile, classifyHeaders, exampleDataset, findingsToCsv, recoveryToCsv, readinessReport, summaryText,
  parseTime, parseArn, parseAzureId, normStatus, normResult, aliasesOf, parseDurationMinutes, DEFAULTS, FINDING_COLS, RECOVERY_COLS, EXAMPLE_NOW,
} from "../../public/js/risk/backupready-engine.js";
import { toEntities } from "../../public/js/core/sink-map.js";

// ---------------------------------------------------------------------------
// Fixtures (headers verbatim from the vendor exports)
// ---------------------------------------------------------------------------
const NOW = "2026-10-15T12:00:00Z";
const T = (h) => new Date(Date.parse(NOW) - h * 3600000).toISOString(); // h hours before NOW

// Get-VBRBackupSession | Export-Csv (PowerShell 5 writes the #TYPE line without -NoTypeInformation)
const VEEAM_SESSIONS = [
  "#TYPE Veeam.Backup.Core.CBackupSession",
  '"JobName","JobType","Name","CreationTime","EndTime","State","Result","IsRetryMode","Progress.TransferedSize"',
  '"SQL-PROD","Backup","SQL-PROD (Incremental)","10/14/2026 10:00:03 PM","10/14/2026 10:41:19 PM","Stopped","Success","False","5368709120"',
  '"SQL-PROD","Backup","SQL-PROD (Incremental)","10/13/2026 10:00:02 PM","10/13/2026 10:39:55 PM","Stopped","Warning","False","5100273664"',
  '"SQL-PROD","Backup","SQL-PROD (Full)","10/12/2026 10:00:01 PM","10/12/2026 11:58:12 PM","Stopped","Failed","False","0"',
  '"SQL-PROD","Backup","SQL-PROD (Incremental)","10/15/2026 10:00:00 AM","","Working","None","False","0"',
].join("\r\n");

// Get-VBRRestorePoint | Export-Csv -NoTypeInformation
const VEEAM_POINTS = [
  '"VmName","CreationTime","Type","Algorithm","IsConsistent","IsCorrupted","BackupId","Name"',
  '"fin-sql-01","10/14/2026 10:12:44 PM","Increment","Increment","True","False","a1b2c3d4-0000-4000-8000-000000000001","fin-sql-01"',
  '"fin-sql-01","9/1/2026 10:10:01 PM","Full","Full","True","False","a1b2c3d4-0000-4000-8000-000000000001","fin-sql-01"',
  '"hr-app-01","10/13/2026 10:20:00 PM","Increment","Increment","True","True","a1b2c3d4-0000-4000-8000-000000000002","hr-app-01"',
].join("\n");

// Get-VBRBackupRepository | Export-Csv -NoTypeInformation
const VEEAM_REPOS = [
  '"Name","Description","Type","Host","HostId","Path","FriendlyPath","IsUnavailable","Id"',
  '"Repo-Hardened-01","Hardened repo","LinuxHardened","Veeam.Backup.Core.Common.CHost","11111111-1111-4111-8111-111111111111","/mnt/veeam","/mnt/veeam","False","22222222-2222-4222-8222-222222222222"',
  '"Repo-NAS","NAS share","CifsShare","Veeam.Backup.Core.Common.CHost","33333333-3333-4333-8333-333333333333","\\\\nas01\\veeam","\\\\nas01\\veeam","False","44444444-4444-4444-8444-444444444444"',
].join("\n");

const A = "210987654321", B = "345678901234";
const arnDb = (acct, reg, n) => "arn:aws:rds:" + reg + ":" + acct + ":db:" + n;
const vArn = (acct, reg, n) => "arn:aws:backup:" + reg + ":" + acct + ":backup-vault:" + n;
const awsJob = (res, vault, state, hoursAgo, extra = {}) => {
  const p = parseArn(res), v = parseArn(vault);
  return {
    AccountId: p.account, BackupJobId: "job-" + hoursAgo + "-" + p.id, BackupVaultName: v.id, BackupVaultArn: vault,
    RecoveryPointArn: state === "COMPLETED" ? "arn:aws:rds:" + p.region + ":" + p.account + ":snapshot:awsbackup:job-" + hoursAgo + p.id : undefined,
    ResourceArn: res, CreationDate: T(hoursAgo + 1).replace("Z", "+00:00"), CompletionDate: state === "COMPLETED" ? T(hoursAgo).replace("Z", "+00:00") : undefined,
    State: state, StatusMessage: state === "FAILED" ? "Insufficient privileges to perform this action." : undefined, PercentDone: "100.0", BackupSizeInBytes: 1024,
    IamRoleArn: "arn:aws:iam::" + p.account + ":role/service-role/AWSBackupDefaultServiceRole", ResourceType: "RDS", BackupType: "", IsParent: false, ...extra,
  };
};
const jobsJson = (jobs) => JSON.stringify({ BackupJobs: jobs });
const vaultsJson = (vaults) => JSON.stringify({ BackupVaultList: vaults });
const vault = (acct, reg, name, lock) => ({
  BackupVaultName: name, BackupVaultArn: vArn(acct, reg, name), VaultType: "BACKUP_VAULT", CreationDate: "2025-01-01T00:00:00.000000+00:00",
  EncryptionKeyArn: "arn:aws:kms:" + reg + ":" + acct + ":key/abcd", CreatorRequestId: "", NumberOfRecoveryPoints: 5,
  Locked: !!lock, ...(lock === "compliance" ? { MinRetentionDays: 7, MaxRetentionDays: 365, LockDate: "2025-02-01T00:00:00.000000+00:00" } : lock === "governance" ? { MinRetentionDays: 7, MaxRetentionDays: 365 } : {}),
});

const GEN_H = "system,job,status,start,end,size_bytes,target,target_type,target_account,target_region,immutable,offline,encrypted,retention_days";
const gen = (rows) => [GEN_H, ...rows.map((r) => r.join(","))].join("\n");
const genRow = (sys, status, hoursAgo, o = {}) => [sys, o.job || sys + "-job", status, T(hoursAgo + 1), T(hoursAgo), "1000", o.target || "nas01", o.type ?? "disk", o.acct ?? "", o.region ?? "", o.imm ?? "", o.off ?? "", o.enc ?? "", o.ret ?? ""];
const ASSET_H = "name,type,criticality,owner,rpo_hours,rto_hours,environment";
const assets = (rows) => [ASSET_H, ...rows].join("\n");
const RT_H = "system,tested_at,result,restore_point_age_hours,duration_minutes,rto_minutes_target,tester,notes";
const rt = (rows) => [RT_H, ...rows].join("\n");

const run = (files, opts = {}) => analyze(files, { now: NOW, ...opts });
const F = (name, text) => ({ name, text });
const byId = (r, prefix) => r.findings.filter((f) => f.id.startsWith(prefix));
const rec = (r, name) => r.tables.recovery.find((x) => x.asset === name);

// ---------------------------------------------------------------------------
group("backupready: parsers (verbatim vendor layouts)", () => {
  test("Veeam Get-VBRBackupSession CSV with #TYPE line: sessions, US timestamps, results", () => {
    const d = detectFile("sessions.csv", VEEAM_SESSIONS);
    assert.equal(d.kind, "veeam-sessions");
    assert.ok(d.confidence >= 0.8);
    const p = parseInput([F("sessions.csv", VEEAM_SESSIONS)]);
    const ev = p.records.events;
    assert.equal(ev.length, 4);
    assert.equal(ev.filter((e) => e.status === "running").length, 1);
    const ok = ev.find((e) => e.status === "success");
    assert.equal(new Date(ok.time).toISOString(), "2026-10-14T22:41:19.000Z");
    assert.equal(ok.job, "veeam:sql-prod");
  });

  test("Veeam Get-VBRRestorePoint CSV: VmName points, corrupted point counted as failed", () => {
    const d = detectFile("points.csv", VEEAM_POINTS);
    assert.equal(d.kind, "veeam-points");
    assert.ok(d.confidence >= 0.9);
    const ev = parseInput([F("points.csv", VEEAM_POINTS)]).records.events;
    assert.equal(ev.length, 3);
    assert.equal(ev.filter((e) => e.status === "failed").length, 1);
    assert.equal(ev[0].kind, "point");
  });

  test("Veeam Get-VBRBackupRepository CSV: hardened = immutable, CIFS = not immutable", () => {
    const d = detectFile("repos.csv", VEEAM_REPOS);
    assert.equal(d.kind, "veeam-repos");
    const locs = parseInput([F("repos.csv", VEEAM_REPOS)]).records.locations;
    assert.equal(locs.find((l) => l.name === "Repo-Hardened-01").immutable, true);
    assert.equal(locs.find((l) => l.name === "Repo-NAS").immutable, false);
    assert.equal(locs.find((l) => l.name === "Repo-NAS").targetType, "disk");
  });

  test("AWS list-backup-jobs JSON: BackupJobs[] states and ARN-derived account / region", () => {
    const res = arnDb(A, "us-east-1", "orders-db"), v = vArn(A, "us-east-1", "prod");
    const text = jobsJson([awsJob(res, v, "COMPLETED", 5), awsJob(res, v, "FAILED", 29), awsJob(res, v, "EXPIRED", 53), awsJob(res, v, "RUNNING", 1)]);
    const d = detectFile("jobs.json", text);
    assert.equal(d.kind, "aws-backup-jobs");
    assert.equal(d.confidence, 1);
    const p = parseInput([F("jobs.json", text)]);
    assert.deepEqual(p.records.events.map((e) => e.status), ["success", "failed", "failed", "running"]);
    assert.equal(p.records.events[0].account, A);
    assert.equal(p.records.events[0].region, "us-east-1");
    assert.equal(p.records.events[0].loc, "aws:" + A + ":us-east-1:prod");
  });

  test("AWS list-copy-jobs JSON: destination vault becomes a cross-account location", () => {
    const res = arnDb(A, "us-east-1", "orders-db");
    const text = JSON.stringify({ CopyJobs: [{ AccountId: A, CopyJobId: "c1", SourceBackupVaultArn: vArn(A, "us-east-1", "prod"), SourceRecoveryPointArn: "arn:aws:rds:us-east-1:" + A + ":snapshot:awsbackup:x", DestinationBackupVaultArn: vArn(B, "us-west-2", "dr"), DestinationRecoveryPointArn: "arn:aws:backup:us-west-2:" + B + ":recovery-point:y", ResourceArn: res, CreationDate: T(3), CompletionDate: T(2), State: "COMPLETED", BackupSizeInBytes: 10, ResourceType: "RDS" }] });
    assert.equal(detectFile("copy.json", text).kind, "aws-copy-jobs");
    const e = parseInput([F("copy.json", text)]).records.events[0];
    assert.equal(e.kind, "copy");
    assert.equal(e.loc, "aws:" + B + ":us-west-2:dr");
  });

  test("AWS list-backup-vaults JSON: compliance, governance and unlocked vaults", () => {
    const text = vaultsJson([vault(A, "us-east-1", "plain"), vault(A, "us-east-1", "gov", "governance"), vault(A, "us-east-1", "comp", "compliance")]);
    assert.equal(detectFile("vaults.json", text).kind, "aws-vaults");
    const r = run([F("vaults.json", text)]);
    const L = Object.fromEntries(r.tables.locations.map((l) => [l.name, l]));
    assert.equal(L.plain.immutable, "no");
    assert.equal(L.gov.immMode || L.gov.immutMode, "governance");
    assert.equal(L.comp.immutMode, "compliance");
    assert.equal(L.comp.deletionProtection, "yes");
  });

  test("AWS describe-backup-vault JSON (single object) is read as a vault", () => {
    const text = JSON.stringify({ BackupVaultName: "dr", BackupVaultArn: vArn(B, "us-west-2", "dr"), VaultType: "LOGICALLY_AIR_GAPPED_BACKUP_VAULT", VaultState: "AVAILABLE", CreationDate: "2025-01-01T00:00:00Z", NumberOfRecoveryPoints: 1, Locked: true, MinRetentionDays: 7, MaxRetentionDays: 30 });
    const d = detectFile("dv.json", text);
    assert.equal(d.kind, "aws-vaults");
    const l = run([F("dv.json", text)]).tables.locations[0];
    assert.equal(l.immutMode, "air-gapped");
    assert.equal(l.offline, "yes");
  });

  test("AWS list-protected-resources JSON: Results[] with LastBackupTime", () => {
    const text = JSON.stringify({ Results: [{ ResourceArn: "arn:aws:ec2:us-east-1:" + A + ":instance/i-0abc", ResourceType: "EC2", LastBackupTime: T(10), ResourceName: "web-01", LastBackupVaultArn: vArn(A, "us-east-1", "prod"), LastRecoveryPointArn: "arn:aws:ec2:us-east-1::image/ami-1" }] });
    assert.equal(detectFile("pr.json", text).kind, "aws-protected");
    const r = run([F("pr.json", text), F("assets.csv", assets(["web-01,server,high,,,,prod"]))]);
    assert.equal(rec(r, "web-01").ageHours, 10);
    assert.equal(rec(r, "web-01").rpoMet, "yes");
  });

  test("AWS list-restore-jobs JSON: mapped to the source through the recovery point ARN", () => {
    const res = arnDb(A, "us-east-1", "orders-db"), v = vArn(A, "us-east-1", "prod");
    const job = awsJob(res, v, "COMPLETED", 30);
    const restores = JSON.stringify({ RestoreJobs: [{ AccountId: A, RestoreJobId: "r1", RecoveryPointArn: job.RecoveryPointArn, CreationDate: T(20), CompletionDate: T(19), Status: "COMPLETED", StatusMessage: "", PercentDone: "100.00%", BackupSizeInBytes: 1, IamRoleArn: "x", CreatedResourceArn: "arn:aws:rds:us-east-1:" + A + ":db:orders-db-restore", ResourceType: "RDS", RecoveryPointCreationDate: T(30), ValidationStatus: "SUCCESSFUL" }] });
    assert.equal(detectFile("rj.json", restores).kind, "aws-restore-jobs");
    const r = run([F("jobs.json", jobsJson([job])), F("rj.json", restores)]);
    const row = r.tables.restores[0];
    assert.equal(row.system, "orders-db");
    assert.equal(row.result, "pass");
    assert.equal(row.durationMin, 60);
    assert.equal(row.pointAgeHours, 10);
  });

  test("AWS list-recovery-points-by-backup-vault JSON: Lifecycle.DeleteAfterDays feeds retention", () => {
    const res = arnDb(A, "us-east-1", "orders-db");
    const text = JSON.stringify({ RecoveryPoints: [{ RecoveryPointArn: "arn:aws:rds:us-east-1:" + A + ":snapshot:awsbackup:z", BackupVaultName: "prod", BackupVaultArn: vArn(A, "us-east-1", "prod"), ResourceArn: res, ResourceType: "RDS", CreationDate: T(6), CompletionDate: T(5), Status: "COMPLETED", Lifecycle: { DeleteAfterDays: 14 }, IsEncrypted: true }] });
    assert.equal(detectFile("rp.json", text).kind, "aws-recovery-points");
    const r = run([F("rp.json", text)], { minRetentionDays: 30 });
    assert.equal(r.tables.recovery[0].retentionDays, 14);
    assert.equal(byId(r, "retention:").length, 1);
  });

  test("Azure Backup center jobs CSV: medium confidence, backup and restore operations split", () => {
    const text = ["Backup instance,Datasource type,Operation,Status,Start time,Duration,Vault,Subscription,Resource group",
      "vm-sql-01,Azure Virtual machines,Backup,Completed,10/15/2026 2:00:11 AM,00:24:10,rsv-prod-eus,11111111-2222-3333-4444-555555555555,rg-prod",
      "vm-sql-01,Azure Virtual machines,Backup,Failed,10/14/2026 2:00:09 AM,00:01:02,rsv-prod-eus,11111111-2222-3333-4444-555555555555,rg-prod",
      "vm-sql-01,Azure Virtual machines,Restore,Completed,10/01/2026 9:00:00 AM,01:10:00,rsv-prod-eus,11111111-2222-3333-4444-555555555555,rg-prod"].join("\n");
    const d = detectFile("az-jobs.csv", text);
    assert.equal(d.kind, "azure-jobs");
    assert.ok(d.confidence >= 0.5 && d.confidence < 0.8, "medium");
    const p = parseInput([F("az-jobs.csv", text)]);
    assert.equal(p.records.events.length, 2);
    assert.equal(p.records.restores.length, 1);
    assert.equal(p.records.restores[0].durationMin, 70);
  });

  test("Azure Backup center backup instances CSV: instance id names resolved", () => {
    const text = ["Backup instance,Datasource type,Vault,Subscription,Resource group,Protection status",
      "iaasvmcontainerv2;rg-prod;vm-web-01,Azure Virtual machines,rsv-prod-eus,11111111-2222-3333-4444-555555555555,rg-prod,Protected"].join("\n");
    const d = detectFile("az-inst.csv", text);
    assert.equal(d.kind, "azure-instances");
    const p = parseInput([F("az-inst.csv", text)]);
    assert.equal(p.records.events[0].sys, "vm-web-01");
  });

  test("Azure vault properties JSON: locked immutability, soft delete disabled, geo redundancy", () => {
    const text = JSON.stringify({ id: "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-prod/providers/Microsoft.RecoveryServices/vaults/rsv-prod-eus", name: "rsv-prod-eus", type: "Microsoft.RecoveryServices/vaults", location: "eastus",
      properties: { securitySettings: { immutabilitySettings: { state: "Locked" }, softDeleteSettings: { softDeleteState: "Disabled", softDeleteRetentionPeriodInDays: 14 } }, redundancySettings: { standardTierStorageRedundancy: "GeoRedundant", crossRegionRestore: "Enabled" } } });
    assert.equal(detectFile("vault.json", text).kind, "azure-vaults");
    const r = run([F("vault.json", text)]);
    const l = r.tables.locations[0];
    assert.equal(l.immutable, "yes");
    assert.equal(l.account, "11111111-2222-3333-4444-555555555555");
    assert.equal(byId(r, "vault-softdelete:").length, 1);
  });

  // Recovery Services JobResource (learn.microsoft.com/rest/api/backup/job-details/get), as printed by az backup job list.
  const SUB = "11111111-2222-3333-4444-555555555555";
  const rsvJob = (id, op, status, start, end, duration, name = "vm-sql-01") => ({
    id: "/Subscriptions/" + SUB + "/resourceGroups/rg-larkspur/providers/Microsoft.RecoveryServices/vaults/rsv-larkspur-eus/backupJobs/" + id,
    name: id, type: "Microsoft.RecoveryServices/vaults/backupJobs",
    properties: { activityId: id, backupManagementType: "AzureIaasVM", duration, endTime: end, entityFriendlyName: name, jobType: "AzureIaaSVMJob", operation: op, startTime: start, status, virtualMachineVersion: "Compute" },
  });

  test("Azure az backup job list JSON (Recovery Services JobResource): ISO durations, vault from id", () => {
    const text = JSON.stringify([
      rsvJob("00000000-0000-4000-8000-000000000001", "Backup", "Completed", "2026-10-15T02:00:11.0146040Z", "2026-10-15T02:24:21.5000000Z", "PT24M10.4853960S"),
      rsvJob("00000000-0000-4000-8000-000000000002", "Backup", "Failed", "2026-10-14T02:00:09Z", "2026-10-14T02:01:11Z", "PT1M2S"),
      rsvJob("00000000-0000-4000-8000-000000000003", "Restore", "Completed", "2026-10-01T09:00:00Z", "2026-10-01T10:10:00Z", "PT1H10M"),
      rsvJob("00000000-0000-4000-8000-000000000004", "ConfigureBackup", "Completed", "2026-09-01T09:00:00Z", "2026-09-01T09:01:00Z", "PT1M"),
    ]);
    const d = detectFile("az-jobs.json", text);
    assert.equal(d.kind, "azure-jobs-json");
    const p = parseInput([F("az-jobs.json", text)]);
    assert.equal(p.records.events.length, 2);
    assert.equal(p.records.events[0].loc, "azure:rsv-larkspur-eus");
    assert.equal(p.records.events[0].account, SUB);
    assert.equal(new Date(p.records.events[0].time).toISOString(), "2026-10-15T02:24:21.500Z");
    assert.equal(p.records.events[1].status, "failed");
    assert.equal(p.records.restores.length, 1);
    assert.equal(p.records.restores[0].durationMin, 70);
  });

  test("Azure az dataprotection job list JSON (AzureBackupJob, {value:[]}): dataSourceName, vaultName, Succeeded", () => {
    const text = JSON.stringify({ value: [{
      name: "8989416e-7573-4836-8cf1-0e90954f1002", type: "Microsoft.DataProtection/Backupvaults/backupJobs",
      id: "/subscriptions/" + SUB + "/resourceGroups/rg-larkspur/providers/Microsoft.DataProtection/Backupvaults/bv-larkspur/backupJobs/8989416e-7573-4836-8cf1-0e90954f1002",
      properties: { activityID: "932925c4-3d81-4550-8105-c7f7b0a934c5", backupInstanceFriendlyName: "pg-larkspur\\orders", dataSourceLocation: "eastus", dataSourceName: "orders",
        dataSourceSetName: "pg-larkspur", dataSourceType: "Microsoft.DBforPostgreSQL/servers/databases", duration: "00:02:11.9724387", endTime: "2026-10-15T11:14:02.5319646Z",
        isUserTriggered: true, operation: "Backup", operationCategory: "Backup", policyName: "daily", sourceResourceGroup: "rg-larkspur-data", sourceSubscriptionID: SUB,
        startTime: "2026-10-15T11:11:50.5595259Z", status: "Succeeded", subscriptionId: SUB, supportedActions: [""], vaultName: "bv-larkspur" },
    }] });
    assert.equal(detectFile("dpp.json", text).kind, "azure-jobs-json");
    const e = parseInput([F("dpp.json", text)]).records.events;
    assert.equal(e.length, 1);
    assert.deepEqual([e[0].sys, e[0].status, e[0].loc, e[0].region], ["orders", "success", "azure:bv-larkspur", "eastus"]);
  });

  test("Azure Resource Graph backup jobs ({count, data:[]}, lowercase type) detected", () => {
    const j = rsvJob("00000000-0000-4000-8000-000000000009", "Backup", "InProgress", "2026-10-15T10:00:00Z", undefined, "PT5M");
    const text = JSON.stringify({ count: 1, data: [{ ...j, type: "microsoft.recoveryservices/vaults/backupjobs" }], skip_token: null, total_records: 1 });
    assert.equal(detectFile("arg.json", text).kind, "azure-jobs-json");
    assert.equal(parseInput([F("arg.json", text)]).records.events[0].status, "running");
  });

  // Veeam B&R REST (helpcenter.veeam.com/references/vbr/13/rest): RepositoriesResult / JobsResult {data, pagination}
  const VREST_REPOS = JSON.stringify({ data: [
    { id: "88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec", name: "Repo-Hardened-01", description: "", uniqueId: "u1", type: "LinuxHardened", hostId: "a1b2c3d4-e5f6-4890-abcd-ef1234567890",
      repository: { path: "/mnt/veeam", taskLimitEnabled: false, maxTaskCount: 4, useFastCloningOnXFSVolumes: true, makeRecentBackupsImmutableDays: 14 } },
    { id: "c3b0f1d2-0000-4000-8000-000000000002", name: "S3-Larkspur", description: "", uniqueId: "u2", type: "AmazonS3",
      bucket: { regionId: "us-east-1", bucketName: "larkspur-veeam", folderName: "vbr", immutability: { isEnabled: true, daysCount: 30, immutabilityMode: "RepositorySettings" } } },
    { id: "c3b0f1d2-0000-4000-8000-000000000003", name: "Repo-Win", description: "", uniqueId: "u3", type: "WinLocal", hostId: "a1b2c3d4-e5f6-4890-abcd-ef1234567891", repository: { path: "D:\\Backups" } },
  ], pagination: { total: 3, count: 3, skip: 0, limit: 200 } });
  const VREST_JOBS = JSON.stringify({ data: [
    { id: "j1", name: "SQL-PROD", type: "VSphereBackup", isDisabled: false, description: "", isHighPriority: false,
      storage: { backupRepositoryId: "88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec", backupProxies: { autoSelectEnabled: true, proxyIds: [] }, retentionPolicy: { type: "RestorePoints", quantity: 7 } } },
  ], pagination: { total: 1, count: 1, skip: 0, limit: 200 } });

  test("Veeam REST repositories JSON: hardened days, object storage immutability, WinLocal not immutable", () => {
    assert.equal(detectFile("repos.json", VREST_REPOS).kind, "veeam-rest-repos");
    const locs = parseInput([F("repos.json", VREST_REPOS)]).records.locations;
    const L = (n) => locs.find((l) => l.name === n);
    assert.deepEqual([L("Repo-Hardened-01").immutable, L("Repo-Hardened-01").immutDays], [true, 14]);
    assert.deepEqual([L("S3-Larkspur").immutable, L("S3-Larkspur").immutDays, L("S3-Larkspur").targetType], [true, 30, "object"]);
    assert.equal(L("Repo-Win").immutable, false);
  });

  test("Veeam REST jobs JSON links Get-VBRBackupSession jobs to their repository (immutability no longer unknown)", () => {
    assert.equal(detectFile("jobs.json", VREST_JOBS).kind, "veeam-rest-jobs");
    const r = run([F("sessions.csv", VEEAM_SESSIONS), F("repos.json", VREST_REPOS), F("vjobs.json", VREST_JOBS)]);
    const x = r.tables.recovery.find((y) => /sql-prod/i.test(y.asset));
    assert.ok(x, "SQL-PROD row");
    assert.equal(x.immutable, "yes");
    const noLink = run([F("sessions.csv", VEEAM_SESSIONS), F("repos.json", VREST_REPOS)]);
    assert.notEqual(noLink.tables.recovery.find((y) => /sql-prod/i.test(y.asset)).immutable, "yes");
  });

  test("Veeam Get-VBRObjectStorageRepository CSV: BackupImmutabilityEnabled / ImmutabilityPeriod", () => {
    const text = ['"Name","Description","Type","BackupImmutabilityEnabled","ImmutabilityPeriod","Id"',
      '"S3-Larkspur","","AmazonS3","True","30","c3b0f1d2-0000-4000-8000-000000000002"',
      '"Blob-Larkspur","","AzureBlob","False","0","c3b0f1d2-0000-4000-8000-000000000004"'].join("\n");
    const d = detectFile("osr.csv", text);
    assert.equal(d.kind, "veeam-repos");
    assert.ok(d.confidence >= 0.8);
    const locs = parseInput([F("osr.csv", text)]).records.locations;
    assert.equal(locs.find((l) => l.name === "S3-Larkspur").immutable, true);
    assert.equal(locs.find((l) => l.name === "Blob-Larkspur").immutable, false);
  });

  test("generic job log CSV: exact headers detected with high confidence", () => {
    const text = gen([genRow("srv-01", "Success", 5, { target: "s3-lock", type: "object", acct: "999", region: "eu-west-1", imm: "yes", enc: "yes", ret: "30" })]);
    const d = detectFile("jobs.csv", text);
    assert.equal(d.kind, "generic-jobs");
    assert.ok(d.confidence >= 0.9);
    const p = parseInput([F("jobs.csv", text)]);
    assert.equal(p.records.locations[0].immutable, true);
    assert.equal(p.records.locations[0].targetType, "object");
    assert.equal(p.records.locations[0].retentionDays, 30);
  });

  test("restore-test log and asset list CSV detected", () => {
    assert.equal(detectFile("rt.csv", rt(["db1," + T(5) + ",pass,4,30,60,ops@test.darknode.ai,ok"])).kind, "restore-tests");
    const a = detectFile("assets.csv", assets(["db1,database,critical,ops@test.darknode.ai,4,2,production"]));
    assert.equal(a.kind, "assets");
    const p = parseInput([F("assets.csv", assets(["db1,database,Tier 0,,4,2,production"]))]);
    assert.equal(p.records.assets[0].criticality, "critical");
    assert.equal(p.records.assets[0].rpoHours, 4);
  });

  test("unrecognised CSV is skipped with a reason, then parsed through a column mapping", () => {
    const text = ["Client,Policy,Outcome,Began,Finished", "srv-09,Daily,Completed," + T(3) + "," + T(2)].join("\n");
    assert.equal(classifyHeaders(["Client", "Policy", "Outcome", "Began", "Finished"]).kind, "unknown");
    const r0 = run([F("x.csv", text)]);
    assert.ok(r0.skipped.some((s) => s.check === "file x.csv"));
    const r1 = run([F("x.csv", text)], { mappings: { "x.csv": { kind: "generic-jobs", cols: { system: "Client", job: "Policy", status: "Outcome", start: "Began", end: "Finished" } } } });
    assert.equal(rec(r1, "srv-09").lastGood, T(2));
  });

  test("zero-byte and malformed JSON files are reported, not thrown", () => {
    const r = run([F("e.csv", ""), F("bad.json", "{oops")]);
    assert.equal(r.findings.length, 0);
    assert.equal(r.skipped.filter((s) => s.check.startsWith("file ")).length, 2);
  });
});

group("backupready: value parsing", () => {
  test("parseTime: ISO with offset, US AM/PM, D/M swap, dotted, epoch and /Date()/", () => {
    assert.equal(parseTime("2026-10-14T05:00:00.123000+02:00"), Date.UTC(2026, 9, 14, 3, 0, 0, 123));
    assert.equal(parseTime("10/14/2026 10:00:03 PM"), Date.UTC(2026, 9, 14, 22, 0, 3));
    assert.equal(parseTime("10/14/2026 12:05:00 AM"), Date.UTC(2026, 9, 14, 0, 5, 0));
    assert.equal(parseTime("25/10/2026 08:00"), Date.UTC(2026, 9, 25, 8, 0, 0));
    assert.equal(parseTime("14.10.2026 22:00:03"), Date.UTC(2026, 9, 14, 22, 0, 3));
    assert.equal(parseTime(1760400000), 1760400000000);
    assert.equal(parseTime("/Date(1760400000000)/"), 1760400000000);
    assert.equal(parseTime("not a date"), null);
  });

  test("parseArn / parseAzureId / aliasesOf", () => {
    assert.deepEqual(parseArn("arn:aws:ec2:us-east-1:111122223333:instance/i-0abc"), { service: "ec2", region: "us-east-1", account: "111122223333", resource: "instance/i-0abc", id: "i-0abc" });
    assert.equal(parseArn("arn:aws:s3:::my-bucket").id, "my-bucket");
    assert.equal(parseArn("nope"), null);
    assert.equal(parseAzureId("/subscriptions/ABC/resourceGroups/RG/providers/Microsoft.Compute/virtualMachines/vm1").name, "vm1");
    assert.deepEqual(aliasesOf("FIN-SQL-01.corp.test.darknode.ai"), ["fin-sql-01.corp.test.darknode.ai", "fin-sql-01"]);
    assert.deepEqual(aliasesOf("10.0.0.5"), ["10.0.0.5"]);
  });

  test("normStatus / normResult / parseDurationMinutes", () => {
    assert.equal(normStatus("Success"), "success");
    assert.equal(normStatus("CompletedWithWarnings"), "warning");
    assert.equal(normStatus("Completed with warnings"), "warning");
    assert.equal(normStatus("Failed"), "failed");
    assert.equal(normStatus("ABORTED"), "failed");
    assert.equal(normStatus("None"), "running");
    assert.equal(normResult("PASS"), "pass");
    assert.equal(normResult("partial"), "partial");
    assert.equal(normResult("failed"), "fail");
    assert.equal(parseDurationMinutes("01:30:00"), 90);
    assert.equal(parseDurationMinutes("1.00:00:00"), 1440);
    assert.equal(parseDurationMinutes("45"), 45);
    assert.equal(parseDurationMinutes("PT1H10M"), 70);
    assert.equal(parseDurationMinutes("PT9.8782791S"), 0.2);
    assert.equal(parseDurationMinutes("00:02:11.9724387"), 2.2);
    assert.equal(parseDurationMinutes("PT"), null);
  });
});

group("backupready: asset matching", () => {
  test("FQDN in the backup export matches a short asset name", () => {
    const r = run([F("j.csv", gen([genRow("fin-sql-01.corp.test.darknode.ai", "Success", 2)])), F("a.csv", assets(["FIN-SQL-01,database,high,,,,prod"]))]);
    assert.equal(rec(r, "FIN-SQL-01").rpoMet, "yes");
    assert.equal(r.tables.unmatchedSystems.length, 0);
  });

  test("AWS ARN matches by resource id and by ResourceName", () => {
    const res = "arn:aws:ec2:us-east-1:" + A + ":instance/i-0aaa";
    const j = awsJob(res, vArn(A, "us-east-1", "prod"), "COMPLETED", 3, { ResourceName: "web-01", ResourceType: "EC2" });
    const r = run([F("j.json", jobsJson([j])), F("a.csv", assets(["web-01,server,high,,,,prod", "i-0aaa,server,low,,,,prod"]))]);
    assert.equal(rec(r, "web-01").copies, 2);
    assert.equal(rec(r, "i-0aaa").copies, 2);
  });

  test("manual assetMap matches an asset to a differently named object", () => {
    const files = [F("j.csv", gen([genRow("VM-4471", "Success", 2)])), F("a.csv", assets(["payroll-app,server,critical,,,,prod"]))];
    const r0 = run(files);
    assert.equal(byId(r0, "no-backup:payroll-app").length, 1);
    assert.equal(r0.tables.unmatchedSystems[0].name, "VM-4471");
    assert.ok(r0.findings.some((f) => f.id === "unmatched-objects" && f.severity === "info"));
    const r1 = run(files, { assetMap: { "payroll-app": ["vm-4471"] } });
    assert.equal(byId(r1, "no-backup:").length, 0);
    assert.equal(rec(r1, "payroll-app").matched, "manual");
    assert.equal(r1.tables.unmatchedSystems.length, 0);
  });

  test("assets from the Security Graph (dataset.assets) are used like an asset list", () => {
    const r = analyze({ files: [F("j.csv", gen([genRow("db1", "Success", 2)]))], assets: [{ name: "db1", criticality: "critical" }, { name: "db2", criticality: "low" }] }, { now: NOW });
    assert.equal(r.summary.assets, 2);
    assert.equal(byId(r, "no-backup:db2")[0].severity, "high");
  });

  test("without an asset list every backup object becomes an asset and the check is reported skipped", () => {
    const r = run([F("j.csv", gen([genRow("db1", "Success", 2)]))]);
    assert.equal(r.summary.assetListGiven, false);
    assert.ok(r.skipped.some((s) => s.check === "unprotected assets"));
    assert.equal(rec(r, "db1").criticality, "medium");
  });
});

group("backupready: RPO maths", () => {
  const files = (h, crit = "high", rpo = "") => [F("j.csv", gen([genRow("db1", "Success", h)])), F("a.csv", assets(["db1,database," + crit + ",," + rpo + ",,prod"]))];
  test("age equal to the RPO is met; one hour more is a breach", () => {
    assert.equal(byId(run(files(24)), "rpo:").length, 0);
    const r = run(files(25));
    assert.equal(byId(r, "rpo:").length, 1);
    assert.equal(rec(r, "db1").ageHours, 25);
  });
  test("severity scales with criticality and breach size (2x)", () => {
    assert.equal(byId(run(files(30, "critical")), "rpo:")[0].severity, "high");
    assert.equal(byId(run(files(48, "critical")), "rpo:")[0].severity, "critical");
    assert.equal(byId(run(files(60, "medium")), "rpo:")[0].severity, "low");
    assert.equal(byId(run(files(100, "medium")), "rpo:")[0].severity, "medium");
  });
  test("asset rpo_hours overrides the policy; policy is editable", () => {
    assert.equal(byId(run(files(10, "high", "8")), "rpo:").length, 1);
    assert.equal(byId(run(files(30, "high"), { rpoHigh: 36 }), "rpo:").length, 0);
  });
  test("as-of defaults to the newest timestamp in the data", () => {
    const r = analyze([F("j.csv", gen([genRow("db1", "Success", 50), genRow("db2", "Success", 2)]))], {});
    assert.equal(r.summary.asOf, new Date(Date.parse(T(2))).toISOString());
    assert.equal(r.summary.asOfSource, "newest timestamp in the data");
    assert.equal(rec(r, "db1").ageHours, 48);
  });
  test("only failed records: no successful backup finding", () => {
    const r = run([F("j.csv", gen([genRow("db1", "Failed", 2)])), F("a.csv", assets(["db1,database,critical,,,,prod"]))]);
    assert.equal(byId(r, "no-good-backup:")[0].severity, "critical");
  });
});

group("backupready: detections", () => {
  test("no backup: critical for critical assets, high otherwise; silent when matched", () => {
    const r = run([F("j.csv", gen([genRow("db1", "Success", 2)])), F("a.csv", assets(["db1,database,critical,,,,prod", "db2,database,critical,,,,prod", "app3,server,medium,,,,prod"]))]);
    assert.equal(byId(r, "no-backup:db2")[0].severity, "critical");
    assert.equal(byId(r, "no-backup:app3")[0].severity, "high");
    assert.equal(byId(r, "no-backup:db1").length, 0);
  });

  test("consecutive failures: fires at the threshold, not below", () => {
    const rows = (n) => gen([genRow("db1", "Success", 100), ...Array.from({ length: n }, (_, i) => genRow("db1", "Failed", 70 - i * 24))]);
    assert.equal(byId(run([F("j.csv", rows(2))]), "job-failing:").length, 0);
    const r = run([F("j.csv", rows(3))]);
    assert.equal(byId(r, "job-failing:").length, 1);
    assert.equal(byId(r, "job-failing:")[0].severity, "high");
    assert.equal(byId(run([F("j.csv", rows(3))], { maxConsecutiveFailures: 4 }), "job-failing:").length, 0);
  });

  test("success rate: below 90% fires, exactly 90% does not", () => {
    const rows = (fails) => gen(Array.from({ length: 10 }, (_, i) => genRow("db1", i < fails ? "Failed" : "Success", 200 - i * 12)));
    assert.equal(byId(run([F("j.csv", rows(1))]), "job-rate:").length, 0);
    const r = run([F("j.csv", rows(2))]);
    assert.equal(byId(r, "job-rate:").length, 1);
    assert.ok(byId(r, "job-rate:")[0].title.includes("80%"));
  });

  test("warnings ignored for more than 7 days fire; a recent warning streak does not", () => {
    const rows = (days) => gen([genRow("db1", "Success", days * 24 + 30), ...Array.from({ length: days + 1 }, (_, i) => genRow("db1", "Warning", (days - i) * 24 + 1))]);
    assert.equal(byId(run([F("j.csv", rows(5))]), "job-warn:").length, 0);
    assert.equal(byId(run([F("j.csv", rows(9))]), "job-warn:").length, 1);
  });

  test("no immutable copy for a critical asset (unlocked vault) vs compliance-locked copy", () => {
    const res = arnDb(A, "us-east-1", "db1");
    const asset = F("a.csv", assets(["db1,database,critical,,,,prod"]));
    const bad = run([F("j.json", jobsJson([awsJob(res, vArn(A, "us-east-1", "plain"), "COMPLETED", 2)])), F("v.json", vaultsJson([vault(A, "us-east-1", "plain")])), asset]);
    assert.equal(byId(bad, "no-immutable:")[0].severity, "high");
    assert.equal(byId(bad, "vault-nolock:")[0].severity, "high");
    const good = run([F("j.json", jobsJson([awsJob(res, vArn(A, "us-east-1", "comp"), "COMPLETED", 2)])), F("v.json", vaultsJson([vault(A, "us-east-1", "comp", "compliance")])), asset]);
    assert.equal(byId(good, "no-immutable:").length, 0);
    assert.equal(byId(good, "vault-nolock:").length, 0);
    assert.equal(rec(good, "db1").immutable, "yes");
  });

  test("governance-mode lock is flagged for review; immutability unknown without vault properties", () => {
    const res = arnDb(A, "us-east-1", "db1");
    const asset = F("a.csv", assets(["db1,database,critical,,,,prod"]));
    const gov = run([F("j.json", jobsJson([awsJob(res, vArn(A, "us-east-1", "gov"), "COMPLETED", 2)])), F("v.json", vaultsJson([vault(A, "us-east-1", "gov", "governance")])), asset]);
    const g = byId(gov, "vault-governance:")[0];
    assert.equal(g.confidence, "review");
    assert.equal(rec(gov, "db1").immutable, "partial");
    assert.equal(byId(gov, "immutable-weak:").length, 1);
    const unk = run([F("j.json", jobsJson([awsJob(res, vArn(A, "us-east-1", "gov"), "COMPLETED", 2)])), asset]);
    assert.equal(rec(unk, "db1").immutable, "unknown");
    assert.equal(byId(unk, "immutable-unknown:")[0].confidence, "review");
  });

  test("same account and region only (high) vs cross-account copy", () => {
    const res = arnDb(A, "us-east-1", "db1"), v = vArn(A, "us-east-1", "prod");
    const asset = F("a.csv", assets(["db1,database,high,,,,prod"]));
    const only = run([F("j.json", jobsJson([awsJob(res, v, "COMPLETED", 2)])), asset]);
    assert.equal(byId(only, "same-acct:")[0].severity, "high");
    assert.equal(rec(only, "db1").offsite, "no");
    const copy = JSON.stringify({ CopyJobs: [{ AccountId: A, CopyJobId: "c", SourceBackupVaultArn: v, DestinationBackupVaultArn: vArn(B, "us-west-2", "dr"), ResourceArn: res, CreationDate: T(2), CompletionDate: T(1), State: "COMPLETED", ResourceType: "RDS" }] });
    const ok = run([F("j.json", jobsJson([awsJob(res, v, "COMPLETED", 2)])), F("c.json", copy), asset]);
    assert.equal(byId(ok, "same-acct:").length, 0);
    assert.equal(rec(ok, "db1").offsite, "yes");
    assert.equal(rec(ok, "db1").copies, 3);
  });

  test("other region but same account and nothing offline: no isolated copy", () => {
    const res = arnDb(A, "us-east-1", "db1");
    const copy = JSON.stringify({ CopyJobs: [{ AccountId: A, CopyJobId: "c", SourceBackupVaultArn: vArn(A, "us-east-1", "prod"), DestinationBackupVaultArn: vArn(A, "us-west-2", "dr"), ResourceArn: res, CreationDate: T(2), CompletionDate: T(1), State: "COMPLETED", ResourceType: "RDS" }] });
    const r = run([F("j.json", jobsJson([awsJob(res, vArn(A, "us-east-1", "prod"), "COMPLETED", 2)])), F("c.json", copy), F("a.csv", assets(["db1,database,critical,,,,prod"]))]);
    assert.equal(byId(r, "same-acct:").length, 0);
    assert.equal(byId(r, "no-isolated:")[0].severity, "high");
    assert.equal(rec(r, "db1").offsite, "yes");
  });

  test("retention below policy and dwell window; blank policy skips with a reason", () => {
    const files = [F("j.csv", gen([genRow("db1", "Success", 2, { ret: "14" })])), F("a.csv", assets(["db1,database,critical,,,,prod"]))];
    const r0 = run(files);
    assert.equal(byId(r0, "retention:").length + byId(r0, "dwell:").length, 0);
    assert.ok(r0.skipped.some((s) => s.check === "minimum retention") && r0.skipped.some((s) => s.check === "dwell-window retention"));
    const r1 = run(files, { minRetentionDays: 30, dwellDays: 21 });
    assert.equal(byId(r1, "retention:").length, 1);
    assert.equal(byId(r1, "dwell:")[0].severity, "high");
    assert.equal(byId(run(files, { minRetentionDays: 14, dwellDays: 14 }), "retention:").length, 0);
  });

  test("restore tests: never tested, failed, stale, RTO exceeded; skipped without a restore source", () => {
    const jobs = F("j.csv", gen(["db1", "db2", "db3", "db4", "db5"].map((s) => genRow(s, "Success", 2))));
    const as = F("a.csv", assets(["db1,database,critical,,,4,prod", "db2,database,high,,,,prod", "db3,database,critical,,,,prod", "db4,database,medium,,,,prod", "db5,database,high,,,1,prod"]));
    const none = run([jobs, as]);
    assert.ok(none.skipped.some((s) => s.check === "restore tests"));
    assert.equal(byId(none, "never-tested:").length, 0);
    const log = F("rt.csv", rt(["db2," + T(100) + ",pass,4,30,,a,", "db2," + T(50) + ",fail,4,30,,a,could not mount", "db3," + T(24 * 120) + ",pass,4,30,,a,", "db4," + T(24 * 10) + ",pass,4,30,,a,", "db5," + T(24 * 3) + ",pass,4,90,,a,"]));
    const r = run([jobs, as, log]);
    assert.equal(byId(r, "never-tested:db1")[0].severity, "high");
    assert.equal(byId(r, "test-failed:db2")[0].severity, "high");
    assert.equal(byId(r, "test-stale:db3")[0].severity, "high");
    assert.equal(byId(r, "test-stale:db4").length + byId(r, "test-failed:db4").length + byId(r, "never-tested:db4").length, 0);
    assert.equal(byId(r, "rto:db5").length, 1);
    assert.equal(rec(r, "db5").rtoMet, "no");
    assert.equal(rec(r, "db4").rtoMet, "yes");
    assert.equal(byId(run([jobs, as, log], { restoreTestDays: 130 }), "test-stale:db3").length, 0);
  });

  test("rto_minutes_target in the test log overrides the asset RTO", () => {
    const r = run([F("j.csv", gen([genRow("db1", "Success", 2)])), F("a.csv", assets(["db1,database,high,,,1,prod"])), F("rt.csv", rt(["db1," + T(5) + ",pass,4,90,120,a,"]))]);
    assert.equal(byId(r, "rto:").length, 0);
  });

  test("encryption off is reported; encrypted targets are silent", () => {
    const r = run([F("j.csv", gen([genRow("db1", "Success", 2, { enc: "no" }), genRow("db2", "Success", 2, { target: "nas02", enc: "yes" })]))]);
    assert.equal(byId(r, "enc-off:").length, 1);
    assert.equal(rec(r, "db1").encrypted, "no");
    assert.equal(rec(r, "db2").encrypted, "yes");
  });

  test("Veeam repository without immutability holding a critical asset", () => {
    const sess = ['"JobName","JobType","Name","CreationTime","EndTime","State","Result","Repository"', '"db1","Backup","db1 (Incremental)","10/15/2026 1:00:00 AM","10/15/2026 1:30:00 AM","Stopped","Success","Repo-NAS"'].join("\n");
    const r = run([F("s.csv", sess), F("repos.csv", VEEAM_REPOS), F("a.csv", assets(["db1,database,critical,,,,prod"]))]);
    assert.equal(byId(r, "repo-mutable:")[0].severity, "high");
    assert.equal(rec(r, "db1").immutable, "no");
  });
});

group("backupready: 3-2-1-1-0, score, exports", () => {
  test("3-2-1-1-0 with unknowns when target type and accounts are not stated", () => {
    const r = run([F("j.csv", gen([genRow("db1", "Success", 2, { type: "" })]))]);
    const x = r.tables.rule[0];
    assert.equal(x.copies, 2);
    assert.equal(x.copiesMet, "no");
    assert.equal(x.media, "unknown");
    assert.equal(x.offsite, "unknown");
    assert.equal(x.immutableOrOffline, "unknown");
    assert.equal(x.zeroErrors, "unknown");
  });

  test("3-2-1-1-0 fully met: disk + immutable offline object copy in another account, test passed", () => {
    const rows = [genRow("db1", "Success", 2, { target: "nas01", type: "disk", acct: "100", region: "r1", imm: "no", off: "no" }), genRow("db1", "Success", 1, { target: "vault-x", type: "object", acct: "200", region: "r2", imm: "yes", off: "yes" })];
    const text = "source_account,source_region," + GEN_H + "\n" + rows.map((r) => "100,r1," + r.join(",")).join("\n");
    const r = run([F("j.csv", text), F("rt.csv", rt(["db1," + T(5) + ",pass,4,30,,a,"]))]);
    const x = r.tables.rule[0];
    assert.deepEqual([x.copies, x.copiesMet, x.media, x.offsite, x.immutableOrOffline, x.zeroErrors], [3, "yes", "yes", "yes", "yes", "yes"]);
  });

  test("score is the weighted share of passed items and follows custom weights", () => {
    const files = [F("j.csv", gen([genRow("db1", "Success", 2, { type: "" })]))];
    const r = run(files);
    // backup + rpo + jobs pass (20+20+10 of 100); immutable/offsite/restore/encryption unknown
    assert.equal(rec(r, "db1").score, 50);
    const r2 = run(files, { wBackup: 1, wRpo: 1, wJobs: 0, wImmutable: 0, wOffsite: 0, wRestore: 0, wEncryption: 2 });
    assert.equal(rec(r2, "db1").score, 50);
    assert.equal(r2.tables.weights.find((w) => w.item === "encryption").weight, 2);
    assert.equal(r.summary.readiness, 50);
  });

  test("analyze is deterministic and independent of file order", () => {
    const ex = exampleDataset();
    const a = JSON.stringify(analyze(ex.files, { now: ex.now }));
    assert.equal(a, JSON.stringify(analyze(ex.files, { now: ex.now })));
    assert.equal(a, JSON.stringify(analyze(ex.files.slice().reverse(), { now: ex.now })));
  });

  test("example: 12 assets with the advertised problems", () => {
    const ex = exampleDataset();
    assert.equal(ex.now, EXAMPLE_NOW);
    const r = analyze(ex.files, { now: ex.now });
    assert.equal(r.summary.assets, 12);
    for (const id of ["no-backup:payments-db", "rpo:web-02", "same-acct:web-01", "test-failed:fin-sql-01", "rto:dc-01"]) assert.ok(r.findings.some((f) => f.id === id), id);
    assert.ok(r.findings.some((f) => f.category === "deletion-protection" && f.subject === "prod-default"));
  });

  test("finding shape: controls, confidence class, evidence cap and assets", () => {
    const ex = exampleDataset();
    const r = analyze(ex.files, { now: ex.now });
    for (const f of r.findings) {
      assert.ok(f.controls.length >= 1, f.id);
      assert.ok(["confirmed", "likely", "review"].includes(f.confidence), f.id);
      assert.ok(["critical", "high", "medium", "low", "info"].includes(f.severity), f.id);
      assert.ok(f.evidence.length <= 50 && f.evidenceCount >= f.evidence.length, f.id);
      assert.ok(f.recommendation && f.description, f.id);
    }
    const { items } = toEntities("backupready", r.findings, { dataset: "t" });
    assert.ok(items.some((i) => i.type === "ASSET" && i.name === "payments-db"));
    assert.ok(items.some((i) => i.type === "FINDING"));
  });

  test("progress callback is called and optional", () => {
    const calls = [];
    analyze(exampleDataset().files, { now: EXAMPLE_NOW }, { progress: (i, n, l) => calls.push(l) });
    assert.ok(calls.length >= 2);
    assert.ok(analyze([]).findings.length === 0);
  });

  test("selfTest passes", () => {
    const s = selfTest();
    assert.ok(s.pass, s.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });

  test("findingsToCsv header row, quoting and formula guard", () => {
    const csv = findingsToCsv([{ id: "x", severity: "high", confidence: "confirmed", category: "c", title: '=cmd "a"', assets: [{ name: "db1" }], description: "d", recommendation: "r", controls: [{ framework: "CIS Controls v8", id: "11.3" }], evidence: [], evidenceCount: 3 }]);
    const lines = csv.trim().split("\n");
    assert.equal(lines[0], FINDING_COLS.join(","));
    assert.ok(lines[1].includes('"\'=cmd ""a"""'));
    assert.ok(lines[1].includes('"CIS Controls v8 11.3"'));
    assert.ok(lines[1].endsWith('"3"'));
  });

  test("recovery CSV, readiness report and summary text", () => {
    const ex = exampleDataset();
    const r = analyze(ex.files, { now: ex.now });
    const csv = recoveryToCsv(r.tables.recovery);
    assert.equal(csv.split("\n")[0], RECOVERY_COLS.join(","));
    assert.equal(csv.trim().split("\n").length, 13);
    const rep = readinessReport(r);
    assert.ok(rep.includes("Readiness score (all assets): " + r.summary.readiness));
    assert.ok(rep.includes("3-2-1-1-0"));
    assert.ok(summaryText(r).startsWith("Backup Readiness summary"));
  });

  test("DEFAULTS: retention and dwell are blank (skipped) by default", () => {
    assert.equal(DEFAULTS.minRetentionDays, null);
    assert.equal(DEFAULTS.dwellDays, null);
    assert.equal(DEFAULTS.maxConsecutiveFailures, 3);
    assert.equal(DEFAULTS.restoreTestDays, 90);
  });
});
