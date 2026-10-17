// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Backup Readiness engine (backupready). Proves (or disproves) that a company can
// recover from ransomware, from the exports it already has: Veeam Backup &
// Replication (sessions, restore points, repositories), AWS Backup (backup, copy and
// restore jobs, vaults, protected resources, recovery points), Azure Backup (Backup
// center jobs / instances CSV, vault properties JSON), a generic job log covering
// any other product, a restore-test log and an asset list with RPO / RTO.
//
// Per asset it answers: is it backed up, is the newest good backup inside the RPO,
// are the jobs healthy, is at least one copy immutable, is a copy in another account
// or region (or offline), has a restore been tested inside the window and within RTO,
// and the 3-2-1-1-0 components. The readiness score is a transparent weighted
// checklist; weights are options.
//
// Pure ESM: no DOM, no network, no clock (the "as of" time is opts.now or the newest
// timestamp in the data). Deterministic: same input -> byte-identical JSON.

import { parseCsv, findColumn, normHeader } from "../ingest/parse.js";

export const TOOL_ID = "backupready";
export const VERSION = "1.0.0";

// ---------------------------------------------------------------------------
// Input kinds and their columns (aliases are matched case/punctuation-insensitively)
// ---------------------------------------------------------------------------

export const KINDS = {
  "veeam-sessions": {
    label: "Veeam B&R backup sessions (Get-VBRBackupSession)",
    cols: {
      job: ["JobName", "Job Name", "Job"], name: ["Name", "Session Name"], jobType: ["JobType", "Job Type"],
      result: ["Result"], state: ["State"], start: ["CreationTime", "Creation Time", "Start Time", "StartTime"],
      end: ["EndTime", "End Time"], size: ["Progress.TransferedSize", "TransferedSize", "Transferred", "Progress.ReadSize"],
      repo: ["Repository", "RepositoryName", "TargetRepository", "BackupRepository"],
    },
    required: ["job", "result", "start"],
  },
  "veeam-points": {
    label: "Veeam B&R restore points (Get-VBRRestorePoint)",
    cols: {
      system: ["VmName", "VM Name", "Name"], start: ["CreationTime", "Creation Time"], type: ["Type"],
      corrupted: ["IsCorrupted"], consistent: ["IsConsistent"], job: ["JobName", "Job Name", "BackupName"],
      repo: ["Repository", "RepositoryName", "TargetRepository", "BackupRepository"],
    },
    required: ["system", "start"],
  },
  "veeam-repos": {
    label: "Veeam B&R repositories (Get-VBRBackupRepository)",
    cols: {
      name: ["Name"], type: ["Type", "TypeDisplay"], path: ["Path", "FriendlyPath"],
      immutable: ["IsImmutabilityEnabled", "ImmutabilityEnabled", "Immutable", "MakeRecentBackupsImmutable"],
      immutDays: ["ImmutabilityPeriod", "ImmutabilityDays", "MakeRecentBackupsImmutableDays"],
      encrypted: ["Encrypted", "EncryptionEnabled", "IsEncrypted"], region: ["Region"], account: ["Account", "Subscription"],
    },
    required: ["name", "type"],
  },
  "azure-jobs": {
    label: "Azure Backup center jobs (CSV export)",
    cols: {
      system: ["Backup instance", "BackupInstance", "Backup item", "Datasource name", "Item name"],
      dsType: ["Datasource type", "DataSourceType", "Workload type"], operation: ["Operation"], status: ["Status"],
      start: ["Start time", "StartTime", "Start Time (UTC)"], duration: ["Duration"], vault: ["Vault", "Vault name"],
      sub: ["Subscription", "Datasource subscription", "Subscription Id"], rg: ["Resource group", "Datasource resource group"],
      location: ["Datasource location", "Location", "Region"],
    },
    required: ["system", "status", "start"],
  },
  "azure-instances": {
    label: "Azure Backup center backup instances (CSV export)",
    cols: {
      system: ["Backup instance", "BackupInstance", "Backup item", "Datasource name"], dsType: ["Datasource type", "DataSourceType"],
      vault: ["Vault", "Vault name"], sub: ["Subscription", "Datasource subscription"], rg: ["Resource group", "Datasource resource group"],
      location: ["Datasource location", "Location", "Region"], protection: ["Protection status", "Protection state"],
      lastBackup: ["Last backup time", "LastBackupTime"], lastStatus: ["Last backup status", "LastBackupStatus"],
    },
    required: ["system"],
  },
  "generic-jobs": {
    label: "Generic backup job log (CSV)",
    cols: {
      system: ["system", "server", "hostname", "host", "vm", "vmname", "client", "protected object", "workload", "object"],
      job: ["job", "jobname", "job name", "policy", "plan", "backup set", "sla domain"],
      status: ["status", "result", "outcome", "state"], start: ["start", "start time", "started", "starttime", "begin"],
      end: ["end", "end time", "endtime", "finished", "completed"], size: ["size_bytes", "size", "bytes"],
      target: ["target", "destination", "repository", "vault", "storage"], targetType: ["target_type", "media", "media type", "storage type"],
      targetAccount: ["target_account", "destination account"], targetRegion: ["target_region", "destination region"],
      sourceAccount: ["source_account", "account"], sourceRegion: ["source_region", "region"],
      immutable: ["immutable", "immutability", "object lock"], offline: ["offline", "air_gapped", "airgapped", "air gapped"],
      encrypted: ["encrypted", "encryption"], retention: ["retention_days", "retention", "retention (days)"],
    },
    required: ["status", "start"],
  },
  "restore-tests": {
    label: "Restore-test log (CSV)",
    cols: {
      system: ["system", "server", "host", "asset", "vm"], testedAt: ["tested_at", "test_date", "tested", "date"],
      result: ["result", "outcome", "status"], pointAge: ["restore_point_age_hours", "point_age_hours"],
      duration: ["duration_minutes", "duration"], rto: ["rto_minutes_target", "rto_minutes", "rto_target"],
      tester: ["tester", "tested_by"], notes: ["notes", "comment", "comments"],
    },
    required: ["system", "testedAt", "result"],
  },
  assets: {
    label: "Asset list (CSV)",
    cols: {
      name: ["name", "asset", "asset name", "hostname", "system"], type: ["type", "asset_type"],
      criticality: ["criticality", "tier", "business criticality", "priority"], owner: ["owner", "asset owner"],
      rpo: ["rpo_hours", "rpo"], rto: ["rto_hours", "rto"], environment: ["environment", "env"],
    },
    required: ["name"],
  },
};

/** Human labels for the mapping panel. */
export const MAP_LABEL = {
  job: "Job name", name: "Name", jobType: "Job type", result: "Result", state: "State", start: "Start / time", end: "End time",
  size: "Size (bytes)", repo: "Repository", system: "System / object", type: "Type", corrupted: "Corrupted flag",
  consistent: "Consistent flag", path: "Path", immutable: "Immutable (yes/no)", immutDays: "Immutability days",
  encrypted: "Encrypted (yes/no)", region: "Region", account: "Account", dsType: "Datasource type", operation: "Operation",
  status: "Status", duration: "Duration", vault: "Vault", sub: "Subscription", rg: "Resource group", location: "Location",
  protection: "Protection status", lastBackup: "Last backup time", lastStatus: "Last backup status", target: "Target",
  targetType: "Target type", targetAccount: "Target account", targetRegion: "Target region", sourceAccount: "Source account",
  sourceRegion: "Source region", offline: "Offline (yes/no)", retention: "Retention days", testedAt: "Tested at",
  pointAge: "Restore point age (h)", rto: "RTO target (min)", tester: "Tester", notes: "Notes", criticality: "Criticality",
  owner: "Owner", environment: "Environment",
};

/** Kept for the stub contract: the generic job-log aliases. */
export const COLUMNS = KINDS["generic-jobs"].cols;

export const CRITICALITIES = ["critical", "high", "medium", "low"];

/** Policy and thresholds; the UI renders these as the policy panel. Blank (null) = check skipped. */
export const DEFAULTS = {
  now: "",
  rpoCritical: 24, rpoHigh: 24, rpoMedium: 48, rpoLow: 168,
  rtoCritical: 4, rtoHigh: 8, rtoMedium: 24, rtoLow: 72,
  maxConsecutiveFailures: 3,
  minSuccessRate: 90,
  successWindowDays: 30,
  warningDays: 7,
  restoreTestDays: 90,
  minRetentionDays: null,
  dwellDays: null,
  wBackup: 20, wRpo: 20, wJobs: 10, wImmutable: 15, wOffsite: 15, wRestore: 15, wEncryption: 5,
};

export const WEIGHT_KEYS = [
  ["backup", "wBackup", "Backed up"], ["rpo", "wRpo", "RPO met"], ["jobs", "wJobs", "Jobs healthy"],
  ["immutable", "wImmutable", "Immutable copy"], ["offsite", "wOffsite", "Offsite / separate account"],
  ["restore", "wRestore", "Restore tested"], ["encryption", "wEncryption", "Encrypted"],
];

export const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
export const CONF_RANK = { confirmed: 2, likely: 1, review: 0 };

// Control references (only ids we are sure of; otherwise framework + section).
const C = {
  csf: { framework: "NIST CSF 2.0", id: "PR.DS-11" },
  cp9: { framework: "NIST SP 800-53", id: "CP-9" },
  cp9_1: { framework: "NIST SP 800-53", id: "CP-9(1)" },
  cp9_3: { framework: "NIST SP 800-53", id: "CP-9(3)" },
  cp9_8: { framework: "NIST SP 800-53", id: "CP-9(8)" },
  cp6: { framework: "NIST SP 800-53", id: "CP-6" },
  cp10: { framework: "NIST SP 800-53", id: "CP-10" },
  cis111: { framework: "CIS Controls v8", id: "11.1" },
  cis112: { framework: "CIS Controls v8", id: "11.2" },
  cis113: { framework: "CIS Controls v8", id: "11.3" },
  cis114: { framework: "CIS Controls v8", id: "11.4" },
  cis115: { framework: "CIS Controls v8", id: "11.5" },
  iso: { framework: "ISO 27001:2022", id: "A.8.13" },
  iso530: { framework: "ISO 27001:2022", id: "A.5.30" },
  cisa: { framework: "CISA #StopRansomware Guide", id: "Part 1: maintain offline, encrypted backups; test them" },
  sp209: { framework: "NIST SP 800-209", id: "Data protection (backup) recommendations" },
  soc2a12: { framework: "SOC 2", id: "A1.2" },
  soc2a13: { framework: "SOC 2", id: "A1.3" },
  t1490: { framework: "MITRE ATT&CK", id: "T1490" },
  t1485: { framework: "MITRE ATT&CK", id: "T1485" },
  t1486: { framework: "MITRE ATT&CK", id: "T1486" },
};

// ---------------------------------------------------------------------------
// Small pure helpers
// ---------------------------------------------------------------------------
const str = (v) => (v == null ? "" : String(v)).trim();
const lc = (v) => str(v).toLowerCase();
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const HOUR = 3600000, DAY = 86400000;
const r1 = (n) => Math.round(n * 10) / 10;
const iso = (t) => (t == null ? "" : new Date(t).toISOString());
const isoDay = (t) => (t == null ? "" : new Date(t).toISOString().slice(0, 10));
const num = (v) => { if (v == null || v === "") return null; const n = Number(String(v).replace(/[, ]/g, "")); return Number.isFinite(n) ? n : null; };

/** Lower-case, collapse whitespace. */
export function normName(s) { return lc(s).replace(/\s+/g, " "); }

/** Name aliases used for matching: full normalized name and the short host (before the first dot). */
export function aliasesOf(name) {
  const n = normName(name);
  if (!n) return [];
  const out = [n];
  if (/^[a-z0-9][a-z0-9_-]*\.[a-z0-9.-]+$/.test(n) && !/^\d+\.\d+\.\d+\.\d+$/.test(n)) out.push(n.split(".")[0]);
  return out;
}

/** Parse an AWS ARN into { service, region, account, resource, id } or null. */
export function parseArn(arn) {
  const s = str(arn);
  if (!/^arn:aws[a-z-]*:/.test(s)) return null;
  const p = s.split(":");
  if (p.length < 6) return null;
  const resource = p.slice(5).join(":");
  const segs = resource.split(/[/:]/).filter(Boolean);
  return { service: p[2], region: p[3] || "", account: p[4] || "", resource, id: segs.length ? segs[segs.length - 1] : resource };
}

/** Parse an Azure resource id into { subscription, resourceGroup, name } or null. */
export function parseAzureId(id) {
  const s = str(id);
  const m = /^\/subscriptions\/([^/]+)(?:\/resourceGroups\/([^/]+))?/i.exec(s);
  if (!m) return null;
  const segs = s.split("/").filter(Boolean);
  return { subscription: m[1].toLowerCase(), resourceGroup: (m[2] || "").toLowerCase(), name: segs[segs.length - 1] };
}

/** Azure backup instance display strings like "iaasvmcontainerv2;rg;vm-01" -> "vm-01". */
function azureInstanceName(s) {
  const t = str(s);
  if (t.startsWith("/subscriptions/")) return parseAzureId(t).name;
  if (t.includes(";")) { const p = t.split(";").filter(Boolean); return p[p.length - 1]; }
  return t;
}

const MONTHS = { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12 };

/**
 * Timestamp -> epoch ms (UTC), or null. Accepts ISO 8601 (with or without offset; no
 * offset = UTC), epoch seconds / ms, PowerShell "/Date(ms)/", US "M/D/YYYY h:mm:ss AM/PM"
 * (Export-Csv on en-US; D/M when the first part is > 12), "DD.MM.YYYY HH:MM:SS" and
 * "14 Oct 2026 10:00". Local times without an offset are read as UTC.
 */
export function parseTime(v) {
  if (v == null || v === "") return null;
  if (typeof v === "number") return Number.isFinite(v) ? (v > 1e11 ? v : v * 1000) : null;
  const s = str(v);
  if (!s) return null;
  let m = /^\/Date\((-?\d+)([+-]\d{4})?\)\/$/.exec(s);
  if (m) return Number(m[1]);
  if (/^\d{9,13}(\.\d+)?$/.test(s)) { const n = Number(s); return n > 1e11 ? Math.round(n) : Math.round(n * 1000); }
  m = /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{1,2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?)?\s*(Z|[+-]\d{2}:?\d{2})?$/i.exec(s);
  if (m) {
    let t = Date.UTC(+m[1], +m[2] - 1, +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0), m[7] ? Math.round(Number("0." + m[7]) * 1000) : 0);
    if (m[8] && m[8].toUpperCase() !== "Z") {
      const o = m[8].replace(":", ""), sign = o[0] === "-" ? -1 : 1;
      t -= sign * (Number(o.slice(1, 3)) * 60 + Number(o.slice(3, 5))) * 60000;
    }
    return Number.isFinite(t) ? t : null;
  }
  m = /^(\d{1,2})\/(\d{1,2})\/(\d{4}),?(?:\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM)?)?$/i.exec(s);
  if (m) {
    let mo = +m[1], d = +m[2];
    if (mo > 12 && d <= 12) { const x = mo; mo = d; d = x; }
    let h = +(m[4] || 0);
    if (m[7]) { const pm = m[7].toUpperCase() === "PM"; if (h === 12) h = pm ? 12 : 0; else if (pm) h += 12; }
    const t = Date.UTC(+m[3], mo - 1, d, h, +(m[5] || 0), +(m[6] || 0));
    return Number.isFinite(t) ? t : null;
  }
  m = /^(\d{1,2})\.(\d{1,2})\.(\d{4})(?:\s+(\d{1,2}):(\d{2})(?::(\d{2}))?)?$/.exec(s);
  if (m) return Date.UTC(+m[3], +m[2] - 1, +m[1], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0));
  m = /^(\d{1,2})[ -]([A-Za-z]{3})[a-z]*[ -](\d{4})(?:[ T,]+(\d{1,2}):(\d{2})(?::(\d{2}))?)?$/.exec(s);
  if (m && MONTHS[m[2].toLowerCase()]) return Date.UTC(+m[3], MONTHS[m[2].toLowerCase()] - 1, +m[1], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0));
  return null;
}

/** "hh:mm:ss", "1.02:03:04", "12 min", "90" (minutes) -> minutes, or null. */
export function parseDurationMinutes(v) {
  const s = str(v);
  if (!s) return null;
  let m = /^(?:(\d+)\.)?(\d{1,2}):(\d{2})(?::(\d{2}))?$/.exec(s);
  if (m) return r1((+(m[1] || 0)) * 1440 + (+m[2]) * 60 + (+m[3]) + (+(m[4] || 0)) / 60);
  m = /^(\d+(?:\.\d+)?)\s*(m|min|mins|minutes)?$/i.exec(s);
  if (m) return Number(m[1]);
  m = /^(\d+(?:\.\d+)?)\s*(h|hr|hrs|hours)$/i.exec(s);
  if (m) return Number(m[1]) * 60;
  return null;
}

/** yes/no-ish -> true/false/null. */
export function yesNo(v) {
  if (v === true || v === false) return v;
  const s = lc(v);
  if (!s) return null;
  if (["yes", "y", "true", "1", "on", "enabled", "locked", "immutable", "compliance", "governance"].includes(s)) return true;
  if (["no", "n", "false", "0", "off", "disabled", "none", "unlocked"].includes(s)) return false;
  return null;
}

/** Job / run status -> success | warning | failed | running | other. */
export function normStatus(v) {
  const s = lc(v).replace(/[_-]+/g, " ");
  if (!s) return "other";
  if (/^(success|succeeded|successful|completed|complete|ok|pass|passed|completed successfully|done)$/.test(s)) return "success";
  if (/warning|with warnings|partial|partially/.test(s)) return "warning";
  if (/fail|error|abort|expired|cancel|missed|unsuccessful/.test(s)) return "failed";
  if (/running|progress|pending|created|queued|started|active|working|waiting|none|aborting/.test(s)) return "running";
  return "other";
}

/** Restore test result -> pass | fail | partial | null. */
export function normResult(v) {
  const s = lc(v);
  if (/^(pass|passed|success|succeeded|successful|ok|completed|complete|green)$/.test(s)) return "pass";
  if (/partial|warning/.test(s)) return "partial";
  if (/fail|error|abort|red/.test(s)) return "fail";
  return null;
}

function normCrit(v) {
  const s = lc(v);
  if (!s) return null;
  if (/^(critical|crit|tier ?0|t0|p0|mission critical|1)$/.test(s)) return "critical";
  if (/^(high|tier ?1|t1|p1|2)$/.test(s)) return "high";
  if (/^(medium|med|moderate|tier ?2|t2|p2|3)$/.test(s)) return "medium";
  if (/^(low|tier ?3|t3|p3|4|non critical|noncritical)$/.test(s)) return "low";
  return null;
}

/** Target type words -> disk | tape | object | cloud | null. */
export function normTargetType(v) {
  const s = lc(v);
  if (!s) return null;
  if (/tape|lto|vtl/.test(s)) return "tape";
  if (/s3|blob|object|wasabi|glacier|gcs|immutable bucket/.test(s)) return "object";
  if (/cloud|vault|saas/.test(s)) return "cloud";
  if (/disk|nas|san|local|cifs|smb|nfs|hardened|linux|windows|dedup|storeonce|datadomain|data domain|exagrid|ddboost|appliance/.test(s)) return "disk";
  return null;
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------
function stripPsType(text) {
  // PowerShell 5 Export-Csv without -NoTypeInformation writes "#TYPE <type>" first.
  return String(text || "").replace(/^﻿/, "").replace(/^#TYPE[^\n]*\n/, "");
}

function hdrSet(headers) { return new Set((headers || []).map(normHeader)); }
const has = (set, ...names) => names.every((n) => set.has(normHeader(n)));
const any = (set, ...names) => names.some((n) => set.has(normHeader(n)));

/** Classify a CSV header row. Returns { kind, confidence }. */
export function classifyHeaders(headers) {
  const H = hdrSet(headers);
  if (has(H, "JobName", "Result") && any(H, "CreationTime")) return { kind: "veeam-sessions", confidence: any(H, "JobType", "EndTime", "State") ? 0.95 : 0.85 };
  if (has(H, "JobName", "Result")) return { kind: "veeam-sessions", confidence: 0.6 };
  if (has(H, "VmName", "CreationTime")) return { kind: "veeam-points", confidence: any(H, "IsCorrupted", "IsConsistent", "Algorithm", "BackupId") ? 0.95 : 0.8 };
  if (has(H, "Name", "Type", "Path") && any(H, "FriendlyPath", "IsUnavailable", "HostId", "Host", "IsImmutabilitySupported", "TypeDisplay")) return { kind: "veeam-repos", confidence: 0.9 };
  if (has(H, "system", "tested_at", "result")) return { kind: "restore-tests", confidence: 0.95 };
  if (has(H, "tested_at", "result")) return { kind: "restore-tests", confidence: 0.6 };
  if (has(H, "name", "criticality")) return { kind: "assets", confidence: any(H, "rpo_hours", "rto_hours", "owner") ? 0.95 : 0.8 };
  if (has(H, "system", "job", "status", "start")) return { kind: "generic-jobs", confidence: any(H, "target", "target_type", "end") ? 0.95 : 0.85 };
  if (any(H, "Backup instance", "BackupInstance") && has(H, "Operation", "Status")) return { kind: "azure-jobs", confidence: any(H, "Start time") ? 0.7 : 0.55 };
  if (any(H, "Backup instance", "BackupInstance")) return { kind: "azure-instances", confidence: any(H, "Datasource type", "Vault") ? 0.65 : 0.5 };
  if (has(H, "Name", "Type", "Path")) return { kind: "veeam-repos", confidence: 0.55 };
  const statusish = any(H, "status", "result", "outcome", "state");
  const timeish = any(H, "start", "start time", "started", "starttime", "date", "time", "timestamp", "end", "end time");
  const objish = any(H, "system", "server", "hostname", "host", "vm", "vmname", "client", "job", "jobname", "job name", "policy", "object", "workload");
  if (statusish && timeish && objish) return { kind: "generic-jobs", confidence: 0.5 };
  return { kind: "unknown", confidence: 0 };
}

/** Classify a parsed JSON document. Returns { kind, confidence, records }. */
function classifyJson(doc) {
  const pick = (k) => (doc && typeof doc === "object" && !Array.isArray(doc) && Array.isArray(doc[k]) ? doc[k] : null);
  let a;
  if ((a = pick("BackupJobs"))) return { kind: "aws-backup-jobs", confidence: 1, records: a };
  if ((a = pick("CopyJobs"))) return { kind: "aws-copy-jobs", confidence: 1, records: a };
  if ((a = pick("RestoreJobs"))) return { kind: "aws-restore-jobs", confidence: 1, records: a };
  if ((a = pick("BackupVaultList"))) return { kind: "aws-vaults", confidence: 1, records: a };
  if ((a = pick("RecoveryPoints"))) return { kind: "aws-recovery-points", confidence: 1, records: a };
  if ((a = pick("Results")) && a.some((r) => r && r.ResourceArn)) return { kind: "aws-protected", confidence: 1, records: a };
  if (doc && !Array.isArray(doc) && doc.BackupVaultArn && doc.BackupVaultName) return { kind: "aws-vaults", confidence: 0.95, records: [doc] };
  const azv = (o) => o && typeof o === "object" && (/microsoft\.recoveryservices\/vaults|microsoft\.dataprotection\/backupvaults/i.test(str(o.type)) || (o.properties && (o.properties.securitySettings || o.properties.redundancySettings)));
  if (Array.isArray(doc) && doc.length && doc.every(azv)) return { kind: "azure-vaults", confidence: 0.95, records: doc };
  if ((a = pick("value")) && a.length && a.every(azv)) return { kind: "azure-vaults", confidence: 0.95, records: a };
  if (azv(doc)) return { kind: "azure-vaults", confidence: 0.95, records: [doc] };
  return { kind: "unknown", confidence: 0, records: [] };
}

export const JSON_LABEL = {
  "aws-backup-jobs": "AWS Backup jobs (list-backup-jobs)",
  "aws-copy-jobs": "AWS Backup copy jobs (list-copy-jobs)",
  "aws-restore-jobs": "AWS Backup restore jobs (list-restore-jobs)",
  "aws-vaults": "AWS Backup vaults (list-backup-vaults / describe-backup-vault)",
  "aws-recovery-points": "AWS Backup recovery points (list-recovery-points-by-backup-vault)",
  "aws-protected": "AWS Backup protected resources (list-protected-resources)",
  "azure-vaults": "Azure vault properties (JSON)",
};

/**
 * Detect one file. Returns { name, kind, label, confidence, format, headers, cols, rows }.
 * rows are raw CSV objects or raw JSON records.
 */
export function detectFile(name, text) {
  const t = stripPsType(text);
  const base = { name: str(name) || "input", headers: [], cols: {}, rows: [], bytes: String(text || "").length };
  if (!t.trim()) return { ...base, kind: "empty", label: "empty", confidence: 0, format: "empty" };
  const c0 = t.trimStart()[0];
  if (c0 === "{" || c0 === "[") {
    let doc;
    try { doc = JSON.parse(t); } catch (_) { return { ...base, kind: "unknown", label: "JSON that does not parse", confidence: 0, format: "json" }; }
    const r = classifyJson(doc);
    return { ...base, kind: r.kind, label: JSON_LABEL[r.kind] || "unrecognised JSON", confidence: r.confidence, format: "json", rows: r.records, headers: r.records.length && typeof r.records[0] === "object" ? Object.keys(r.records[0]).sort() : [] };
  }
  const { headers, rows } = parseCsv(t);
  const cls = classifyHeaders(headers);
  const cols = cls.kind !== "unknown" ? resolveCols(headers, cls.kind) : {};
  return { ...base, kind: cls.kind, label: cls.kind === "unknown" ? "unrecognised CSV" : KINDS[cls.kind].label, confidence: cls.confidence, format: "csv", headers, rows, cols };
}

function resolveCols(headers, kind, override) {
  const spec = KINDS[kind];
  const out = {};
  if (!spec) return out;
  for (const [k, aliases] of Object.entries(spec.cols)) {
    const ov = override && Object.prototype.hasOwnProperty.call(override, k) ? override[k] : undefined;
    if (ov !== undefined) { if (ov && headers.includes(ov)) out[k] = ov; continue; }
    const h = findColumn(headers, aliases);
    if (h) out[k] = h;
  }
  return out;
}

/**
 * Parse one text or many files into normalized records.
 * parseInput(text | {name,text}[], mappings?) -> { format, headers, rows, skipped, files, records }.
 * format/headers/rows describe the first file (stub contract); records is the normalized model.
 */
export function parseInput(input, mappings = {}) {
  const list = typeof input === "string" || input == null ? [{ name: "input", text: input || "" }] : Array.isArray(input) ? input : [input];
  const files = list.map((f) => ({ name: str(f && f.name) || "input", text: String((f && f.text) || "") }))
    .sort((a, b) => cmp(a.name, b.name) || cmp(a.text.length, b.text.length));
  const skipped = [];
  const dets = [];
  const records = emptyRecords();
  for (const f of files) {
    const d = detectFile(f.name, f.text);
    const mp = mappings && mappings[f.name];
    if (mp && mp.kind && KINDS[mp.kind] && d.format === "csv") {
      d.kind = mp.kind; d.label = KINDS[mp.kind].label; d.confidence = Math.max(d.confidence, 0.8); d.mapped = true;
    }
    if (d.format === "csv" && KINDS[d.kind]) d.cols = resolveCols(d.headers, d.kind, mp && mp.cols);
    dets.push(d);
    if (d.kind === "empty") { skipped.push({ check: "file " + d.name, reason: "empty file" }); continue; }
    if (d.kind === "unknown") { skipped.push({ check: "file " + d.name, reason: d.label + "; choose its kind in the mapping panel" }); continue; }
    if (KINDS[d.kind]) {
      const miss = KINDS[d.kind].required.filter((k) => !d.cols[k]);
      if (miss.length) { skipped.push({ check: "file " + d.name, reason: "required column(s) not mapped: " + miss.map((k) => MAP_LABEL[k] || k).join(", ") }); continue; }
    }
    ingest(d, records, skipped);
  }
  const first = dets[0];
  return {
    format: dets.length === 1 && first ? first.kind : dets.length ? "multi" : "empty",
    headers: first ? first.headers : [],
    rows: first ? first.rows : [],
    skipped,
    files: dets.map((d) => ({ name: d.name, kind: d.kind, label: d.label, confidence: d.confidence, format: d.format, headers: d.headers, cols: d.cols, rows: d.rows.length, bytes: d.bytes, mapped: !!d.mapped })),
    records,
  };
}

function emptyRecords() {
  return { events: [], locations: [], restores: [], assets: [], rpLinks: [], pendingRestores: [], sysInfo: [] };
}

// ---------------------------------------------------------------------------
// Ingest: vendor rows -> events / locations / restores / assets
// ---------------------------------------------------------------------------
const cell = (row, cols, k) => (cols[k] ? row[cols[k]] : undefined);

function veeamRepoType(t) {
  const s = lc(t);
  if (!s) return null;
  if (/tape/.test(s)) return "tape";
  if (/s3|azureblob|blob|googlecloud|wasabi|object|archive/.test(s)) return "object";
  return "disk";
}

function ingest(d, R, skipped) {
  const k = d.kind, cols = d.cols, file = d.name;
  if (k === "veeam-sessions") {
    for (const row of d.rows) {
      const job = str(cell(row, cols, "job")) || str(cell(row, cols, "name")).replace(/\s*\([^)]*\)\s*$/, "");
      if (!job) continue;
      const start = parseTime(cell(row, cols, "start")), end = parseTime(cell(row, cols, "end"));
      let status = normStatus(cell(row, cols, "result"));
      if (status === "running" && /stopped|completed/i.test(str(cell(row, cols, "state"))) && end) status = "other";
      const jt = str(cell(row, cols, "jobType"));
      const repo = str(cell(row, cols, "repo"));
      R.events.push({
        sys: job, sysSource: "veeam", job: "veeam:" + normName(job), jobName: job, kind: /sync|copy/i.test(jt) ? "copy" : "backup",
        status, time: end != null && status !== "running" ? end : start, start, loc: repo ? "veeam:" + normName(repo) : null, file,
        ev: { file, source: "Veeam session", job, type: jt, result: str(cell(row, cols, "result")), start: iso(start), end: iso(end) },
      });
      if (repo) R.locations.push({ key: "veeam:" + normName(repo), name: repo, kind: "veeam-repo", source: "veeam" });
    }
  } else if (k === "veeam-points") {
    for (const row of d.rows) {
      const sys = str(cell(row, cols, "system"));
      const t = parseTime(cell(row, cols, "start"));
      if (!sys || t == null) continue;
      const corrupt = yesNo(cell(row, cols, "corrupted")) === true;
      const job = str(cell(row, cols, "job")), repo = str(cell(row, cols, "repo"));
      R.events.push({
        sys, sysSource: "veeam", job: job ? "veeam:" + normName(job) : null, jobName: job || null, kind: "point",
        status: corrupt ? "failed" : "success", time: t, start: t, loc: repo ? "veeam:" + normName(repo) : null, file,
        ev: { file, source: "Veeam restore point", system: sys, type: str(cell(row, cols, "type")), created: iso(t), corrupted: corrupt ? "yes" : "" },
      });
      if (job) R.sysInfo.push({ sys, jobLink: "veeam:" + normName(job) });
      if (repo) R.locations.push({ key: "veeam:" + normName(repo), name: repo, kind: "veeam-repo", source: "veeam" });
    }
  } else if (k === "veeam-repos") {
    for (const row of d.rows) {
      const name = str(cell(row, cols, "name"));
      if (!name) continue;
      const type = str(cell(row, cols, "type"));
      const flag = yesNo(cell(row, cols, "immutable"));
      const days = num(cell(row, cols, "immutDays"));
      const hardened = /hardened/i.test(type);
      let immutable = null, mode = null;
      if (hardened || flag === true || (days != null && days > 0)) { immutable = true; mode = hardened ? "hardened" : "flag"; }
      else if (flag === false || (days != null && days === 0)) immutable = false;
      // Windows, SMB/CIFS, NFS and plain (non-hardened) Linux repositories have no Veeam immutability.
      else if (/^(WinLocal|CifsShare|Nfs|LinuxLocal)$/i.test(type)) immutable = false;
      R.locations.push({
        key: "veeam:" + normName(name), name, kind: "veeam-repo", source: "veeam", props: true, repoType: type,
        targetType: veeamRepoType(type), immutable, immutMode: mode, immutDays: days,
        encrypted: yesNo(cell(row, cols, "encrypted")), region: str(cell(row, cols, "region")) || null, account: str(cell(row, cols, "account")) || null,
        deletionProtection: immutable, ev: { file, source: "Veeam repository", name, type, path: str(cell(row, cols, "path")), immutable: immutable == null ? "not stated" : immutable ? "yes" : "no" },
      });
    }
  } else if (k === "azure-jobs" || k === "azure-instances") {
    for (const row of d.rows) {
      const raw = str(cell(row, cols, "system"));
      const sys = azureInstanceName(raw);
      if (!sys) continue;
      const vault = str(cell(row, cols, "vault"));
      const sub = lc(cell(row, cols, "sub")) || null, region = lc(cell(row, cols, "location")).replace(/\s+/g, "") || null;
      const loc = vault ? "azure:" + normName(vault) : null;
      if (vault) R.locations.push({ key: loc, name: vault, kind: "azure-vault", source: "azure", account: sub, targetType: "cloud" });
      R.sysInfo.push({ sys, account: sub, region, source: "azure" });
      if (k === "azure-jobs") {
        const op = lc(cell(row, cols, "operation"));
        const t = parseTime(cell(row, cols, "start"));
        const status = normStatus(cell(row, cols, "status"));
        if (/restore|recover/.test(op)) {
          const res = status === "success" ? "pass" : status === "warning" ? "partial" : status === "failed" ? "fail" : null;
          if (res && t != null) R.restores.push({ sys, time: t, result: res, durationMin: parseDurationMinutes(cell(row, cols, "duration")), rtoMin: null, pointAgeHours: null, tester: "", notes: "Azure Backup restore job (" + str(cell(row, cols, "operation")) + ")", source: "Azure restore job", file });
          continue;
        }
        if (op && !/backup/.test(op)) continue;
        R.events.push({
          sys, sysSource: "azure", job: "azure:" + normName(vault) + ":" + normName(sys), jobName: sys + (vault ? " @ " + vault : ""), kind: "backup",
          status, time: t, start: t, loc, file, account: sub, region,
          ev: { file, source: "Azure Backup job", instance: raw, operation: str(cell(row, cols, "operation")), status: str(cell(row, cols, "status")), start: iso(t), vault },
        });
      } else {
        const t = parseTime(cell(row, cols, "lastBackup"));
        const ls = cell(row, cols, "lastStatus");
        R.events.push({
          sys, sysSource: "azure", job: null, kind: "inventory", status: t != null ? (ls != null && str(ls) ? normStatus(ls) : "success") : "other",
          time: t, start: t, loc, file, account: sub, region,
          ev: { file, source: "Azure backup instance", instance: raw, protection: str(cell(row, cols, "protection")), lastBackup: iso(t), vault },
        });
      }
    }
  } else if (k === "generic-jobs") {
    for (const row of d.rows) {
      const sys = str(cell(row, cols, "system")) || str(cell(row, cols, "job"));
      if (!sys) continue;
      const job = str(cell(row, cols, "job")) || sys;
      const start = parseTime(cell(row, cols, "start")), end = parseTime(cell(row, cols, "end"));
      const status = normStatus(cell(row, cols, "status"));
      const target = str(cell(row, cols, "target"));
      const tAcct = lc(cell(row, cols, "targetAccount")) || null, tReg = lc(cell(row, cols, "targetRegion")) || null;
      const loc = target ? "gen:" + normName(target) + "|" + (tAcct || "") + "|" + (tReg || "") : null;
      const time = end != null && status !== "running" ? end : start;
      if (loc) R.locations.push({
        key: loc, name: target, kind: "generic", source: "generic", account: tAcct, region: tReg, targetType: normTargetType(cell(row, cols, "targetType")),
        immutable: yesNo(cell(row, cols, "immutable")), immutMode: yesNo(cell(row, cols, "immutable")) ? "flag" : null, offline: yesNo(cell(row, cols, "offline")),
        encrypted: yesNo(cell(row, cols, "encrypted")), retentionDays: num(cell(row, cols, "retention")), at: time,
      });
      R.events.push({
        sys, sysSource: "generic", job: "gen:" + normName(job) + ":" + normName(sys), jobName: job, kind: "backup", status, time, start, loc, file,
        account: lc(cell(row, cols, "sourceAccount")) || null, region: lc(cell(row, cols, "sourceRegion")) || null,
        ev: { file, source: "job log", system: sys, job, status: str(cell(row, cols, "status")), start: iso(start), end: iso(end), target },
      });
    }
  } else if (k === "restore-tests") {
    for (const row of d.rows) {
      const sys = str(cell(row, cols, "system"));
      const t = parseTime(cell(row, cols, "testedAt"));
      const res = normResult(cell(row, cols, "result"));
      if (!sys || t == null || !res) { continue; }
      R.restores.push({
        sys, time: t, result: res, pointAgeHours: num(cell(row, cols, "pointAge")), durationMin: num(cell(row, cols, "duration")),
        rtoMin: num(cell(row, cols, "rto")), tester: str(cell(row, cols, "tester")), notes: str(cell(row, cols, "notes")), source: "restore-test log", file,
      });
    }
  } else if (k === "assets") {
    for (const row of d.rows) {
      const name = str(cell(row, cols, "name"));
      if (!name) continue;
      R.assets.push({
        name, type: str(cell(row, cols, "type")), criticality: normCrit(cell(row, cols, "criticality")), owner: str(cell(row, cols, "owner")),
        rpoHours: num(cell(row, cols, "rpo")), rtoHours: num(cell(row, cols, "rto")), environment: str(cell(row, cols, "environment")), source: file,
      });
    }
  } else if (k === "aws-backup-jobs" || k === "aws-copy-jobs" || k === "aws-protected" || k === "aws-recovery-points") {
    for (const j of d.rows) {
      if (!j || typeof j !== "object") continue;
      const arn = parseArn(j.ResourceArn);
      if (!arn) continue;
      const sysName = str(j.ResourceArn);
      const res = { sys: sysName, sysSource: "aws", account: arn.account || str(j.AccountId) || null, region: arn.region || null, resId: arn.id, resName: str(j.ResourceName) || null, resType: str(j.ResourceType) || arn.service };
      R.sysInfo.push({ sys: sysName, account: res.account, region: res.region, aliases: [arn.id, res.resName].filter(Boolean), resType: res.resType, source: "aws" });
      if (k === "aws-backup-jobs") {
        const vArn = parseArn(j.BackupVaultArn);
        const vacct = vArn ? vArn.account : str(j.AccountId) || res.account, vreg = vArn ? vArn.region : res.region;
        const vname = str(j.BackupVaultName) || (vArn ? vArn.id : "");
        const loc = vname ? "aws:" + vacct + ":" + vreg + ":" + normName(vname) : null;
        if (loc) R.locations.push({ key: loc, name: vname, kind: "aws-vault", source: "aws", account: vacct, region: vreg, targetType: "cloud" });
        const t = parseTime(j.CompletionDate) ?? parseTime(j.CreationDate);
        const st = awsState(j.State);
        if (j.RecoveryPointArn) R.rpLinks.push({ rp: str(j.RecoveryPointArn), sys: sysName });
        R.events.push({ ...res, job: "aws:" + sysName, jobName: (res.resName || arn.id) + " (" + res.resType + ")", kind: "backup", status: st, time: st === "running" ? parseTime(j.CreationDate) : t, start: parseTime(j.CreationDate), loc, file,
          ev: { file, source: "AWS Backup job", resource: str(j.ResourceArn), state: str(j.State), created: iso(parseTime(j.CreationDate)), completed: iso(parseTime(j.CompletionDate)), vault: vname, message: str(j.StatusMessage) } });
      } else if (k === "aws-copy-jobs") {
        const dArn = parseArn(j.DestinationBackupVaultArn);
        if (!dArn) continue;
        const loc = "aws:" + dArn.account + ":" + dArn.region + ":" + normName(dArn.id);
        R.locations.push({ key: loc, name: dArn.id, kind: "aws-vault", source: "aws", account: dArn.account, region: dArn.region, targetType: "cloud" });
        if (j.DestinationRecoveryPointArn) R.rpLinks.push({ rp: str(j.DestinationRecoveryPointArn), sys: sysName });
        const st = awsState(j.State);
        R.events.push({ ...res, job: "aws-copy:" + sysName + ">" + loc, jobName: "copy " + (res.resName || arn.id) + " to " + dArn.id + " (" + dArn.account + "/" + dArn.region + ")", kind: "copy", status: st,
          time: parseTime(j.CompletionDate) ?? parseTime(j.CreationDate), start: parseTime(j.CreationDate), loc, file,
          ev: { file, source: "AWS Backup copy job", resource: str(j.ResourceArn), state: str(j.State), destination: str(j.DestinationBackupVaultArn), completed: iso(parseTime(j.CompletionDate)) } });
      } else if (k === "aws-protected") {
        const vArn = parseArn(j.LastBackupVaultArn);
        const loc = vArn ? "aws:" + vArn.account + ":" + vArn.region + ":" + normName(vArn.id) : null;
        if (loc) R.locations.push({ key: loc, name: vArn.id, kind: "aws-vault", source: "aws", account: vArn.account, region: vArn.region, targetType: "cloud" });
        const t = parseTime(j.LastBackupTime);
        R.events.push({ ...res, job: null, kind: "inventory", status: t != null ? "success" : "other", time: t, start: t, loc, file,
          ev: { file, source: "AWS protected resource", resource: str(j.ResourceArn), lastBackup: iso(t), vault: vArn ? vArn.id : "" } });
      } else {
        const vArn = parseArn(j.BackupVaultArn);
        const vname = str(j.BackupVaultName) || (vArn ? vArn.id : "");
        const vacct = vArn ? vArn.account : res.account, vreg = vArn ? vArn.region : res.region;
        const loc = vname ? "aws:" + vacct + ":" + vreg + ":" + normName(vname) : null;
        const life = j.Lifecycle && typeof j.Lifecycle === "object" ? num(j.Lifecycle.DeleteAfterDays) : null;
        if (loc) R.locations.push({ key: loc, name: vname, kind: "aws-vault", source: "aws", account: vacct, region: vreg, targetType: "cloud" });
        if (j.RecoveryPointArn) R.rpLinks.push({ rp: str(j.RecoveryPointArn), sys: sysName });
        const st = /^COMPLETED$/i.test(str(j.Status)) ? "success" : /PARTIAL/i.test(str(j.Status)) ? "warning" : /EXPIRED|DELETING|STOPPED/i.test(str(j.Status)) ? "other" : "running";
        const t = parseTime(j.CompletionDate) ?? parseTime(j.CreationDate);
        R.events.push({ ...res, job: null, kind: "point", status: st, time: t, start: parseTime(j.CreationDate), loc, file, retentionDays: life,
          encrypted: typeof j.IsEncrypted === "boolean" ? j.IsEncrypted : null,
          ev: { file, source: "AWS recovery point", resource: str(j.ResourceArn), status: str(j.Status), created: iso(parseTime(j.CreationDate)), vault: vname, deleteAfterDays: life == null ? "" : life } });
      }
    }
  } else if (k === "aws-restore-jobs") {
    for (const j of d.rows) {
      if (!j || typeof j !== "object") continue;
      const st = str(j.Status).toUpperCase();
      if (!/^(COMPLETED|FAILED|ABORTED)$/.test(st)) continue;
      const vs = str(j.ValidationStatus).toUpperCase();
      const result = st === "COMPLETED" ? (/FAILED|TIMED_OUT/.test(vs) ? "fail" : "pass") : "fail";
      const c = parseTime(j.CreationDate), e = parseTime(j.CompletionDate), rpc = parseTime(j.RecoveryPointCreationDate);
      R.pendingRestores.push({
        rp: str(j.RecoveryPointArn), time: e ?? c, result, durationMin: c != null && e != null ? r1((e - c) / 60000) : null,
        pointAgeHours: rpc != null && c != null ? r1((c - rpc) / HOUR) : null, rtoMin: null, tester: j.CreatedBy && j.CreatedBy.RestoreTestingPlanArn ? "AWS Backup restore testing" : "",
        notes: "AWS restore job " + str(j.RestoreJobId) + " " + st + (vs ? " / validation " + vs : "") + (j.StatusMessage ? ": " + str(j.StatusMessage) : ""),
        source: "AWS restore job", file, resType: str(j.ResourceType),
      });
    }
  } else if (k === "aws-vaults") {
    for (const v of d.rows) {
      if (!v || typeof v !== "object") continue;
      const a = parseArn(v.BackupVaultArn);
      const name = str(v.BackupVaultName) || (a ? a.id : "");
      if (!name) continue;
      const acct = a ? a.account : null, reg = a ? a.region : null;
      const locked = v.Locked === true || str(v.Locked).toLowerCase() === "true";
      const lag = /LOGICALLY_AIR_GAPPED/i.test(str(v.VaultType));
      const lockDate = parseTime(v.LockDate);
      R.locations.push({
        key: "aws:" + acct + ":" + reg + ":" + normName(name), name, kind: "aws-vault", source: "aws", props: true, account: acct, region: reg, targetType: "cloud",
        locked, lag, lockDate, minRetentionDays: num(v.MinRetentionDays), maxRetentionDays: num(v.MaxRetentionDays),
        encrypted: v.EncryptionKeyArn ? true : null, vaultType: str(v.VaultType) || "BACKUP_VAULT", vaultState: str(v.VaultState),
        ev: { file, source: "AWS Backup vault", vault: name, account: acct, region: reg, locked: locked ? "true" : "false", lockDate: iso(lockDate), minRetentionDays: v.MinRetentionDays ?? "", vaultType: str(v.VaultType) },
      });
    }
  } else if (k === "azure-vaults") {
    for (const v of d.rows) {
      const p = (v && v.properties) || {};
      const name = str(v.name);
      if (!name) continue;
      const az = parseAzureId(v.id);
      const sec = p.securitySettings || {};
      const imm = lc(sec.immutabilitySettings && sec.immutabilitySettings.state);
      const sd = sec.softDeleteSettings || {};
      const sdState = lc(sd.softDeleteState);
      const red = p.redundancySettings || {};
      const storage = str(red.standardTierStorageRedundancy);
      const crr = lc(red.crossRegionRestore);
      R.locations.push({
        key: "azure:" + normName(name), name, kind: "azure-vault", source: "azure", props: true, account: az ? az.subscription : null,
        region: lc(v.location).replace(/\s+/g, "") || null, targetType: "cloud",
        azImm: imm || null, softDelete: sdState || null, softDeleteDays: num(sd.softDeleteRetentionPeriodInDays), redundancy: storage || null, crr: crr || null,
        encrypted: null,
        ev: { file, source: "Azure vault properties", vault: name, location: str(v.location), immutability: imm || "not stated", softDelete: sdState || "not stated", redundancy: storage || "not stated", crossRegionRestore: crr || "not stated" },
      });
    }
  }
}

function awsState(s) {
  const t = str(s).toUpperCase();
  if (t === "COMPLETED") return "success";
  if (t === "PARTIAL") return "warning";
  if (/FAILED|ABORTED|EXPIRED/.test(t)) return "failed";
  if (/CREATED|PENDING|RUNNING|ABORTING/.test(t)) return "running";
  return "other";
}

// ---------------------------------------------------------------------------
// Model building
// ---------------------------------------------------------------------------
function mergeLocations(list) {
  const map = new Map();
  const ordered = list.slice().sort((a, b) => cmp(a.key, b.key) || (a.at ?? 0) - (b.at ?? 0));
  for (const l of ordered) {
    const prev = map.get(l.key);
    if (!prev) { map.set(l.key, { ...l }); continue; }
    for (const [k, v] of Object.entries(l)) {
      if (v == null || v === "") continue;
      if (prev[k] == null || prev[k] === "" || l.props || k === "at" || ["immutable", "offline", "encrypted", "retentionDays", "immutMode"].includes(k)) {
        if (prev.props && !l.props && ["immutable", "immutMode", "encrypted"].includes(k) && prev[k] != null) continue;
        prev[k] = v;
      }
    }
    if (l.props) prev.props = true;
  }
  for (const l of map.values()) finalizeLocation(l);
  return map;
}

/** Derive immutability / deletion protection / offsite flags for a location. */
function finalizeLocation(l) {
  if (l.kind === "aws-vault") {
    if (l.props) {
      if (l.lag) { l.immutable = true; l.immutMode = "air-gapped"; l.deletionProtection = true; l.offline = true; }
      else if (l.locked && l.lockDate != null) { l.immutable = true; l.immutMode = "compliance"; l.deletionProtection = true; }
      else if (l.locked) { l.immutable = true; l.immutMode = "governance"; l.deletionProtection = true; }
      else { l.immutable = false; l.immutMode = null; l.deletionProtection = false; }
    } else { l.immutable = null; l.deletionProtection = null; }
  } else if (l.kind === "azure-vault") {
    if (l.props) {
      l.immutable = l.azImm === "locked" ? true : l.azImm === "unlocked" ? true : l.azImm === "disabled" ? false : null;
      l.immutMode = l.azImm === "locked" ? "locked" : l.azImm === "unlocked" ? "unlocked" : null;
      l.deletionProtection = l.softDelete ? !/disabled/.test(l.softDelete) : null;
      l.geo = /geo/i.test(l.redundancy || "");
    } else { l.immutable = null; l.deletionProtection = null; }
  } else if (l.kind === "veeam-repo") {
    if (!l.props) { l.immutable = null; l.deletionProtection = null; }
  } else if (l.kind === "generic") {
    l.deletionProtection = l.immutable === true ? true : null;
  }
  if (l.offline == null) l.offline = l.kind === "generic" ? null : l.targetType === "tape" ? true : null;
  if (l.kind === "aws-vault" && l.offline == null) l.offline = false;
  if (l.kind === "azure-vault" && l.offline == null) l.offline = false;
}

function lockedCompliance(l) { return l.immutable === true && ["compliance", "air-gapped", "hardened", "locked", "flag"].includes(l.immutMode); }

/** Build systems, jobs, and the asset model. Pure. */
function buildModel(records, assetsIn, opts, ctx) {
  const locs = mergeLocations(records.locations);
  // resolve AWS restore jobs to resources through recovery point links
  const rpMap = new Map();
  for (const l of records.rpLinks.slice().sort((a, b) => cmp(a.rp, b.rp) || cmp(a.sys, b.sys))) if (!rpMap.has(l.rp)) rpMap.set(l.rp, l.sys);
  const unresolvedRestores = [];
  const restores = records.restores.slice();
  for (const r of records.pendingRestores) {
    const sys = rpMap.get(r.rp);
    if (sys) restores.push({ ...r, sys }); else unresolvedRestores.push(r);
  }

  // systems
  const systems = new Map();
  const sysKey = (name) => (parseArn(name) ? "arn:" + str(name).toLowerCase() : normName(name));
  const getSys = (name) => {
    const k = sysKey(name);
    let s = systems.get(k);
    if (!s) {
      const a = parseArn(name);
      s = { key: k, name: a ? (a.id) : str(name), arn: a ? str(name) : "", aliases: new Set(aliasesOf(a ? a.id : name)), sources: new Set(), events: [], restores: [], jobs: new Set(), account: null, region: null, resType: "" };
      systems.set(k, s);
    }
    return s;
  };
  for (const i of records.sysInfo) {
    const s = getSys(i.sys);
    if (i.account && !s.account) s.account = i.account;
    if (i.region && !s.region) s.region = i.region;
    if (i.resType && !s.resType) s.resType = i.resType;
    for (const a of i.aliases || []) for (const x of aliasesOf(a)) s.aliases.add(x);
    if (i.source) s.sources.add(i.source);
    if (i.jobLink) s.jobs.add(i.jobLink);
  }
  const evs = records.events;
  const n = evs.length;
  for (let i = 0; i < n; i++) {
    if (i % 1000 === 0) ctx?.progress?.(i, n, "grouping backup events");
    const e = evs[i];
    const s = getSys(e.sys);
    s.events.push(e);
    if (e.sysSource) s.sources.add(e.sysSource);
    if (e.job) s.jobs.add(e.job);
    if (e.account && !s.account) s.account = e.account;
    if (e.region && !s.region) s.region = e.region;
  }
  for (const r of restores) { const s = getSys(r.sys); s.restores.push(r); }

  // Azure: a vault protects resources in its own region; use the vault region when the source region is not stated.
  for (const s of systems.values()) {
    if (!s.region && s.sources.has("azure")) {
      const lk = s.events.map((e) => e.loc).filter(Boolean).sort()[0];
      const l = lk && locs.get(lk);
      if (l && l.region) { s.region = l.region; s.regionInferred = true; }
      if (l && l.account && !s.account) s.account = l.account;
    }
  }

  // jobs
  const jobs = new Map();
  for (const s of systems.values()) for (const e of s.events) {
    if (!e.job || (e.kind !== "backup" && e.kind !== "copy")) continue;
    let j = jobs.get(e.job);
    if (!j) { j = { key: e.job, name: e.jobName || e.job, kind: e.kind, systems: new Set(), runs: [] }; jobs.set(e.job, j); }
    j.systems.add(s.key);
    if (e.time != null) j.runs.push(e);
  }
  for (const j of jobs.values()) j.runs.sort((a, b) => a.time - b.time || cmp(a.status, b.status) || cmp(a.file, b.file));

  // as-of time
  let now = parseTime(opts.now);
  let nowSource = "set";
  if (now == null) {
    let mx = null;
    for (const e of evs) if (e.time != null && (mx == null || e.time > mx)) mx = e.time;
    for (const r of restores) if (r.time != null && (mx == null || r.time > mx)) mx = r.time;
    now = mx; nowSource = "newest timestamp in the data";
  }

  // assets
  const alias = new Map();
  const sysList = [...systems.values()].sort((a, b) => cmp(a.key, b.key));
  for (const s of sysList) for (const a of [...s.aliases].sort()) { if (!alias.has(a)) alias.set(a, []); alias.get(a).push(s.key); }
  let assets;
  const listGiven = assetsIn.length > 0;
  if (listGiven) {
    const seen = new Map();
    for (const a of assetsIn) { const k = normName(a.name); if (!seen.has(k)) seen.set(k, a); }
    assets = [...seen.values()].map((a) => ({ ...a, criticalitySource: a.criticality ? "list" : "policy default", criticality: a.criticality || "medium" }));
  } else {
    assets = sysList.filter((s) => s.events.length).map((s) => ({ name: s.name, type: s.resType, criticality: "medium", criticalitySource: "not stated (no asset list)", owner: "", rpoHours: null, rtoHours: null, environment: "", implicit: s.key }));
  }
  const manual = (opts.assetMap && typeof opts.assetMap === "object") ? opts.assetMap : {};
  const matchedSys = new Set();
  for (const a of assets) {
    const ks = new Set();
    if (a.implicit) ks.add(a.implicit);
    else {
      for (const x of aliasesOf(a.name)) for (const k of alias.get(x) || []) ks.add(k);
      const m = manual[a.name] || manual[normName(a.name)];
      for (const k of Array.isArray(m) ? m : m ? [m] : []) if (systems.has(k)) ks.add(k);
    }
    a.systems = [...ks].sort();
    a.manual = !a.implicit && !!(manual[a.name] || manual[normName(a.name)]);
    for (const k of ks) matchedSys.add(k);
    const pol = (p) => opts[p + a.criticality[0].toUpperCase() + a.criticality.slice(1)];
    a.rpo = a.rpoHours != null ? a.rpoHours : pol("rpo");
    a.rto = a.rtoHours != null ? a.rtoHours : pol("rto");
  }
  assets.sort((a, b) => SEV_RANK[b.criticality] - SEV_RANK[a.criticality] || cmp(normName(a.name), normName(b.name)));
  const unmatchedSystems = listGiven ? sysList.filter((s) => !matchedSys.has(s.key) && (s.events.length || s.restores.length)) : [];
  return { locs, systems, sysList, jobs, assets, listGiven, unmatchedSystems, unresolvedRestores, restores, now, nowSource };
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------
function mkFinding(o) {
  const ev = o.evidence || [];
  return {
    id: o.id, title: o.title, severity: o.severity, confidence: o.confidence, category: o.category,
    description: o.description, recommendation: o.recommendation, controls: o.controls,
    evidence: ev.slice(0, 50), evidenceCount: o.evidenceCount != null ? o.evidenceCount : ev.length,
    assets: o.assets || [], tags: o.tags || [], subject: o.subject || "",
  };
}

const assetRef = (a) => ({ type: "ASSET", name: a.name, data: { criticality: a.criticality, owner: a.owner || undefined, rpoHours: a.rpo, rtoHours: a.rto } });
const evRow = (e) => ({ ...e.ev });

function jobStats(j, o, now) {
  const runs = j.runs.filter((r) => r.status === "success" || r.status === "warning" || r.status === "failed");
  let streak = 0;
  for (let i = runs.length - 1; i >= 0 && runs[i].status === "failed"; i--) streak++;
  const win = now != null ? runs.filter((r) => r.time >= now - o.successWindowDays * DAY && r.time <= now) : runs;
  const ok = win.filter((r) => r.status !== "failed").length;
  const rate = win.length ? Math.round((ok / win.length) * 1000) / 10 : null;
  // current warning streak (newest runs all "warning")
  let warnFrom = null, wcount = 0;
  for (let i = runs.length - 1; i >= 0 && runs[i].status === "warning"; i--) { warnFrom = runs[i].time; wcount++; }
  const last = runs[runs.length - 1] || null;
  return {
    runs: runs.length, windowRuns: win.length, success: win.filter((r) => r.status === "success").length, warning: win.filter((r) => r.status === "warning").length,
    failed: win.filter((r) => r.status === "failed").length, rate, streak, warnStreak: wcount, warnSinceDays: warnFrom != null && now != null ? r1((now - warnFrom) / DAY) : null,
    lastStatus: last ? last.status : null, lastTime: last ? last.time : null,
  };
}

/**
 * Analyze a dataset. dataset = {name,text}[] | { files: {name,text}[], assets?: [{name,criticality,...}] }.
 * opts overrides DEFAULTS; opts.mappings = { fileName: { kind?, cols: {key: header} } };
 * opts.assetMap = { assetName: [systemKey] } manual matches.
 */
export function analyze(dataset, opts = {}, ctx) {
  const o = { ...DEFAULTS, ...(opts || {}) };
  for (const [k, v] of Object.entries(DEFAULTS)) if (typeof v === "number" && !(typeof o[k] === "number" && Number.isFinite(o[k]))) o[k] = v;
  for (const k of ["minRetentionDays", "dwellDays"]) o[k] = typeof o[k] === "number" && Number.isFinite(o[k]) && o[k] > 0 ? o[k] : null;
  const files = Array.isArray(dataset) ? dataset : (dataset && Array.isArray(dataset.files) ? dataset.files : []);
  const extraAssets = dataset && !Array.isArray(dataset) && Array.isArray(dataset.assets) ? dataset.assets : [];
  ctx?.progress?.(0, 1, "parsing files");
  const parsed = parseInput(files, o.mappings || {});
  const skipped = parsed.skipped.slice();
  const assetsIn = parsed.records.assets.concat(extraAssets.filter((a) => a && str(a.name)).map((a) => ({
    name: str(a.name), type: str(a.type), criticality: normCrit(a.criticality), owner: str(a.owner), rpoHours: num(a.rpoHours ?? a.rpo_hours), rtoHours: num(a.rtoHours ?? a.rto_hours), environment: str(a.environment), source: "Security Graph",
  })));
  const M = buildModel(parsed.records, assetsIn, o, ctx);
  const { locs, systems, jobs, assets, now } = M;
  const findings = [];
  const hasRestoreSource = parsed.files.some((f) => f.kind === "restore-tests" || f.kind === "aws-restore-jobs") || M.restores.some((r) => r.source === "Azure restore job");
  const hasJobRuns = [...jobs.values()].some((j) => j.runs.length);
  const anyLocProps = [...locs.values()].some((l) => l.props || l.immutable != null);

  if (!M.listGiven) skipped.push({ check: "unprotected assets", reason: "no asset list loaded (CSV or Security Graph); every backup object is treated as an asset with the medium policy" });
  if (now == null) skipped.push({ check: "RPO", reason: "no timestamps in the data and no as-of date set" });
  if (!hasRestoreSource) skipped.push({ check: "restore tests", reason: "no restore-test log, AWS restore jobs or Azure restore jobs loaded; restore checks were not run" });
  if (!hasJobRuns) skipped.push({ check: "job health", reason: "no job run history (Veeam sessions, AWS Backup jobs, Azure jobs or a job log)" });
  if (!anyLocProps) skipped.push({ check: "immutability / deletion protection", reason: "no vault or repository properties (AWS list-backup-vaults, Azure vault JSON, Veeam repositories or an immutable column)" });
  if (o.minRetentionDays == null) skipped.push({ check: "minimum retention", reason: "minimum retention (days) is blank in the policy panel" });
  if (o.dwellDays == null) skipped.push({ check: "dwell-window retention", reason: "ransomware dwell window (days) is blank in the policy panel" });

  // --- per-job health -------------------------------------------------------
  const jobRows = [];
  const assetsBySys = new Map();
  for (const a of assets) for (const k of a.systems) { if (!assetsBySys.has(k)) assetsBySys.set(k, []); assetsBySys.get(k).push(a); }
  const jobAssets = (j) => { const out = new Map(); for (const k of j.systems) for (const a of assetsBySys.get(k) || []) out.set(a.name, a); return [...out.values()].sort((x, y) => cmp(x.name, y.name)); };
  const badJobs = new Set();
  const jobList = [...jobs.values()].sort((a, b) => cmp(a.key, b.key));
  for (const j of jobList) {
    const st = jobStats(j, o, now);
    const as = jobAssets(j);
    const crit = as.some((a) => a.criticality === "critical");
    jobRows.push({ job: j.name, key: j.key, kind: j.kind, systems: [...j.systems].map((k) => systems.get(k).name).sort().join(", "), assets: as.map((a) => a.name).join(", "), ...st, lastTime: iso(st.lastTime) });
    const evid = j.runs.slice(-50).reverse().map(evRow);
    if (st.streak >= o.maxConsecutiveFailures) {
      badJobs.add(j.key);
      findings.push(mkFinding({
        id: "job-failing:" + j.key, subject: j.name, category: "job-failures",
        title: "Backup job failing " + st.streak + " times in a row", severity: crit ? "critical" : "high", confidence: "confirmed",
        description: j.name + " has failed on its last " + st.streak + " runs (threshold " + o.maxConsecutiveFailures + "). Last run " + iso(st.lastTime) + ". Repeated failures leave the data without new restore points.",
        recommendation: "Fix the cause in the job log, run the job manually and confirm a successful restore point. Alert on the first failure, not the third.",
        controls: [C.cis112, C.cp9, C.csf, C.iso, C.t1490], evidence: evid, evidenceCount: j.runs.length, assets: as.map(assetRef),
      }));
    }
    if (st.rate != null && st.windowRuns >= 3 && st.rate < o.minSuccessRate) {
      badJobs.add(j.key);
      findings.push(mkFinding({
        id: "job-rate:" + j.key, subject: j.name, category: "job-success-rate",
        title: "Backup job success rate " + st.rate + "% (below " + o.minSuccessRate + "%)", severity: "medium", confidence: "confirmed",
        description: j.name + ": " + (st.success + st.warning) + " of " + st.windowRuns + " runs completed in the last " + o.successWindowDays + " days before " + isoDay(now) + " (" + st.failed + " failed).",
        recommendation: "Review the failing runs for a recurring cause (capacity, credentials, snapshot errors, network) and fix it.",
        controls: [C.cis112, C.cp9, C.csf], evidence: evid, evidenceCount: j.runs.length, assets: as.map(assetRef),
      }));
    }
    if (st.warnSinceDays != null && st.warnSinceDays > o.warningDays) {
      findings.push(mkFinding({
        id: "job-warn:" + j.key, subject: j.name, category: "job-warnings",
        title: "Backup job warnings ignored for " + st.warnSinceDays + " days", severity: crit ? "medium" : "low", confidence: "confirmed",
        description: j.name + " has ended with a warning on its last " + st.warnStreak + " runs, the first of them " + st.warnSinceDays + " days before " + isoDay(now) + " (threshold " + o.warningDays + " days). Warnings often mean some objects or files were skipped.",
        recommendation: "Read the warning detail and resolve it; confirm every object in the job has a current restore point.",
        controls: [C.cis112, C.cp9, C.iso], evidence: evid, evidenceCount: j.runs.length, assets: as.map(assetRef),
      }));
    }
  }

  // --- per-location checks ---------------------------------------------------
  const locList = [...locs.values()].sort((a, b) => cmp(a.key, b.key));
  const sysByLoc = new Map();
  for (const s of systems.values()) for (const e of s.events) if (e.loc) { if (!sysByLoc.has(e.loc)) sysByLoc.set(e.loc, new Set()); sysByLoc.get(e.loc).add(s.key); }
  const locAssets = (l) => { const out = new Map(); for (const k of sysByLoc.get(l.key) || []) for (const a of assetsBySys.get(k) || []) out.set(a.name, a); return [...out.values()].sort((x, y) => cmp(x.name, y.name)); };
  const locRows = [];
  for (const l of locList) {
    const as = locAssets(l);
    const crit = as.some((a) => a.criticality === "critical");
    const vaultAsset = { type: "ASSET", name: (l.kind === "aws-vault" ? "AWS Backup vault " : l.kind === "azure-vault" ? "Azure vault " : l.kind === "veeam-repo" ? "Veeam repository " : "Backup target ") + l.name + (l.account ? " (" + l.account + (l.region ? "/" + l.region : "") + ")" : ""), data: { kind: l.kind, account: l.account, region: l.region } };
    locRows.push({ key: l.key, name: l.name, kind: l.kind, account: l.account || "", region: l.region || "", targetType: l.targetType || "", immutable: tri(l.immutable), immutMode: l.immutMode || "", deletionProtection: tri(l.deletionProtection), offline: tri(l.offline), encrypted: tri(l.encrypted), propertiesLoaded: l.props ? "yes" : "no", objects: (sysByLoc.get(l.key) || new Set()).size, assets: as.map((a) => a.name).join(", ") });
    const ev = l.ev ? [l.ev] : [{ location: l.name, kind: l.kind, account: l.account || "", region: l.region || "" }];
    if (l.kind === "aws-vault" && l.props && !l.locked && !l.lag) {
      findings.push(mkFinding({
        id: "vault-nolock:" + l.key, subject: l.name, category: "deletion-protection", title: "AWS Backup vault without Vault Lock", severity: crit ? "high" : "medium", confidence: "confirmed",
        description: "Vault " + l.name + " in " + l.account + "/" + l.region + " is not locked. A principal with backup delete permissions (or a ransomware operator holding them) can delete its recovery points and change retention." + (as.length ? " Holds backups of: " + as.map((a) => a.name).join(", ") + "." : ""),
        recommendation: "Enable AWS Backup Vault Lock in compliance mode (set a grace period, then let it lock), or copy to a locked vault in a separate account.",
        controls: [C.cis113, C.cp9, C.sp209, C.csf, C.t1490], evidence: ev, assets: [vaultAsset, ...as.map(assetRef)],
      }));
    }
    if (l.kind === "aws-vault" && l.props && l.locked && l.immutMode === "governance") {
      findings.push(mkFinding({
        id: "vault-governance:" + l.key, subject: l.name, category: "immutability-mode", title: "Vault Lock in governance mode only", severity: "medium", confidence: "review",
        description: "Vault " + l.name + " is locked without a LockDate, which is governance mode: principals with the right IAM permissions can still remove the lock and delete recovery points.",
        recommendation: "Confirm whether governance mode is intended. For ransomware resilience use compliance mode (a lock with a ChangeableForDays grace period that becomes immutable).",
        controls: [C.cis113, C.sp209, C.csf, C.t1490], evidence: ev, assets: [vaultAsset, ...as.map(assetRef)],
      }));
    }
    if (l.kind === "aws-vault" && l.props && l.locked && l.lockDate != null && now != null && l.lockDate > now) {
      findings.push(mkFinding({
        id: "vault-grace:" + l.key, subject: l.name, category: "immutability-mode", title: "Vault Lock still in its grace period", severity: "low", confidence: "confirmed",
        description: "Vault " + l.name + " will become immutable on " + iso(l.lockDate) + "; until then the lock can be removed.",
        recommendation: "No action if intended; re-check after the lock date.", controls: [C.cis113, C.sp209], evidence: ev, assets: [vaultAsset],
      }));
    }
    if (l.kind === "azure-vault" && l.props && l.deletionProtection === false) {
      findings.push(mkFinding({
        id: "vault-softdelete:" + l.key, subject: l.name, category: "deletion-protection", title: "Azure vault soft delete disabled", severity: "high", confidence: "confirmed",
        description: "Vault " + l.name + " reports softDeleteState " + l.softDelete + ": deleted backup data is purged immediately instead of being kept for recovery.",
        recommendation: "Enable soft delete (prefer always-on) and multi-user authorization for the vault.",
        controls: [C.cis113, C.cp9, C.sp209, C.t1490, C.t1485], evidence: ev, assets: [vaultAsset, ...as.map(assetRef)],
      }));
    }
    if (l.kind === "azure-vault" && l.props && l.azImm === "unlocked") {
      findings.push(mkFinding({
        id: "vault-unlocked:" + l.key, subject: l.name, category: "immutability-mode", title: "Azure vault immutability enabled but not locked", severity: "medium", confidence: "review",
        description: "Vault " + l.name + " has immutability state Unlocked; it can still be turned off by an administrator.",
        recommendation: "Lock immutability once retention settings are final (this is irreversible).",
        controls: [C.cis113, C.sp209, C.t1490], evidence: ev, assets: [vaultAsset, ...as.map(assetRef)],
      }));
    }
    if (l.kind === "veeam-repo" && l.props && l.immutable === false) {
      findings.push(mkFinding({
        id: "repo-mutable:" + l.key, subject: l.name, category: "deletion-protection", title: "Veeam repository without immutability", severity: crit ? "high" : "medium", confidence: "confirmed",
        description: "Repository " + l.name + " (" + (l.repoType || "type not stated") + ") reports no immutability. Backups on it can be deleted or encrypted by anyone holding the backup server's credentials.",
        recommendation: "Use a hardened Linux repository or object storage with immutability for at least one copy.",
        controls: [C.cis113, C.cis114, C.sp209, C.t1490], evidence: ev, assets: [vaultAsset, ...as.map(assetRef)],
      }));
    }
    if (l.encrypted === false) {
      findings.push(mkFinding({
        id: "enc-off:" + l.key, subject: l.name, category: "encryption", title: "Backup target reports encryption off", severity: crit ? "high" : "medium", confidence: "confirmed",
        description: "Backups on " + l.name + " are reported as not encrypted. Stolen backup media or bucket contents are readable, which feeds data-extortion.",
        recommendation: "Enable backup encryption with keys held outside the backup system.",
        controls: [C.cp9_8, C.cis113, C.cisa, C.iso], evidence: ev, assets: [vaultAsset, ...as.map(assetRef)],
      }));
    }
  }

  // --- per-asset checks -------------------------------------------------------
  const W = Object.fromEntries(WEIGHT_KEYS.map(([k, ok]) => [k, Math.max(0, Number(o[ok]) || 0)]));
  const wSum = Object.values(W).reduce((x, y) => x + y, 0) || 1;
  const recovery = [];
  const rule = [];
  let retentionData = false, accountData = false, encData = false;
  const restoreWin = now != null ? now - o.restoreTestDays * DAY : null;
  const na = assets.length;
  for (let ai = 0; ai < na; ai++) {
    if (ai % 200 === 0) ctx?.progress?.(ai, na, "assessing assets");
    const a = assets[ai];
    const sys = a.systems.map((k) => systems.get(k));
    const events = sys.flatMap((s) => s.events).sort((x, y) => (x.time ?? 0) - (y.time ?? 0) || cmp(x.file, y.file));
    const good = events.filter((e) => (e.status === "success" || e.status === "warning") && e.time != null && (now == null || e.time <= now));
    const lastGood = good.length ? good[good.length - 1].time : null;
    const crit = a.criticality;
    const ref = assetRef(a);
    const srcAccount = sys.map((s) => s.account).find(Boolean) || null;
    const srcRegion = sys.map((s) => s.region).find(Boolean) || null;
    const locKeys = [...new Set(good.map((e) => e.loc).filter(Boolean))].sort();
    const L = locKeys.map((k) => locs.get(k)).filter(Boolean);
    const restoresA = sys.flatMap((s) => s.restores).filter((r) => now == null || r.time <= now).sort((x, y) => x.time - y.time || cmp(x.file, y.file));
    const aJobs = [...new Set(sys.flatMap((s) => [...s.jobs]))].sort();

    // 1. no backup at all
    if (M.listGiven && !events.length && !restoresA.length) {
      findings.push(mkFinding({
        id: "no-backup:" + normName(a.name), subject: a.name, category: "unprotected", title: "No backup found for " + crit + " asset", severity: crit === "critical" ? "critical" : "high", confidence: "likely",
        description: a.name + " (" + crit + (a.type ? ", " + a.type : "") + ") does not match any backup object in the loaded exports. If it is backed up by a product whose export was not loaded, or under another name, map it manually in the asset matching panel.",
        recommendation: "Add the asset to a backup policy, or load the export that covers it and map it.",
        controls: [C.cis111, C.cis112, C.cp9, C.csf, C.iso, C.t1485, C.t1486], evidence: [{ asset: a.name, criticality: crit, type: a.type, owner: a.owner, source: a.source || "" }], assets: [ref],
      }));
    }
    // 2. RPO
    let ageH = lastGood != null && now != null ? r1((now - lastGood) / HOUR) : null;
    const rpoMet = now == null ? null : lastGood != null && ageH <= a.rpo;
    if (now != null && events.length && lastGood == null) {
      findings.push(mkFinding({
        id: "no-good-backup:" + normName(a.name), subject: a.name, category: "rpo", title: "No successful backup for " + crit + " asset", severity: crit === "critical" ? "critical" : "high", confidence: "confirmed",
        description: a.name + " has " + events.length + " backup record(s) in the exports but none completed successfully up to " + iso(now) + ".",
        recommendation: "Fix the backup job and confirm a successful restore point.", controls: [C.cis112, C.cp9, C.csf, C.iso, C.t1490],
        evidence: events.slice(-50).reverse().map(evRow), evidenceCount: events.length, assets: [ref],
      }));
    } else if (now != null && lastGood != null && !rpoMet) {
      const ratio = ageH / Math.max(a.rpo, 0.01);
      const big = ratio >= 2;
      const sev = crit === "critical" ? (big ? "critical" : "high") : crit === "high" ? (big ? "high" : "medium") : crit === "medium" ? (big ? "medium" : "low") : "low";
      findings.push(mkFinding({
        id: "rpo:" + normName(a.name), subject: a.name, category: "rpo", title: "RPO breached: newest good backup " + ageH + " h old (RPO " + a.rpo + " h)", severity: sev, confidence: "confirmed",
        description: a.name + " (" + crit + "): newest successful backup " + iso(lastGood) + ", " + ageH + " hours before " + iso(now) + " (" + M.nowSource + "). RPO " + a.rpo + " h" + (a.rpoHours != null ? " from the asset list" : " from the " + crit + " policy") + "; " + r1(ratio) + "x over.",
        recommendation: "Restore the schedule and confirm the next run succeeds; alert when the newest restore point is older than the RPO.",
        controls: [C.cis112, C.cp9, C.csf, C.iso, C.soc2a12], evidence: good.slice(-25).reverse().map(evRow).concat(events.filter((e) => e.status === "failed").slice(-25).reverse().map(evRow)),
        evidenceCount: events.length, assets: [ref],
      }));
    }
    // 3. immutability
    const immKnown = L.some((l) => l.immutable != null);
    const immStrong = L.some(lockedCompliance);
    const immWeak = L.some((l) => l.immutable === true && !lockedCompliance(l));
    const immAllFalse = L.length > 0 && L.every((l) => l.immutable === false);
    let immState = !L.length ? (good.length ? "unknown" : "no") : immStrong ? "yes" : immWeak ? "partial" : immAllFalse ? "no" : "unknown";
    if (!good.length) immState = "no";
    const locEv = L.map((l) => ({ location: l.name, kind: l.kind, account: l.account || "", region: l.region || "", immutable: tri(l.immutable), mode: l.immutMode || "", offline: tri(l.offline), encrypted: tri(l.encrypted) }));
    if (crit === "critical" && good.length) {
      if (immState === "no") {
        findings.push(mkFinding({
          id: "no-immutable:" + normName(a.name), subject: a.name, category: "immutability", title: "No immutable copy of a critical asset", severity: "high", confidence: "confirmed",
          description: "Every backup location of " + a.name + " reports no immutability (no vault lock, hardened repository, object lock or immutable flag). Ransomware operators target backups first (MITRE T1490).",
          recommendation: "Keep at least one copy in an immutable store: AWS Vault Lock (compliance), Azure locked immutability, Veeam hardened repository or object lock.",
          controls: [C.cis113, C.cis114, C.cisa, C.sp209, C.csf, C.t1490], evidence: locEv, assets: [ref],
        }));
      } else if (immState === "partial") {
        findings.push(mkFinding({
          id: "immutable-weak:" + normName(a.name), subject: a.name, category: "immutability-mode", title: "Critical asset's only immutable copy is in governance / unlocked mode", severity: "medium", confidence: "review",
          description: a.name + " has an immutable copy, but only in a mode an administrator can reverse (" + L.filter((l) => l.immutable === true).map((l) => l.name + ": " + l.immutMode).join("; ") + ").",
          recommendation: "Move one copy to compliance-mode / locked immutability.", controls: [C.cis113, C.sp209, C.t1490], evidence: locEv, assets: [ref],
        }));
      } else if (immState === "unknown") {
        findings.push(mkFinding({
          id: "immutable-unknown:" + normName(a.name), subject: a.name, category: "immutability", title: "Immutability of a critical asset's backups not evidenced", severity: "medium", confidence: "review",
          description: "None of the loaded exports state whether the backup locations of " + a.name + " are immutable (" + (L.map((l) => l.name).join(", ") || "location not stated in the export") + ").",
          recommendation: "Load the vault / repository properties (AWS list-backup-vaults, Azure vault JSON, Veeam repositories) or mark the target in the job log.",
          controls: [C.cis113, C.csf], evidence: locEv.length ? locEv : [{ asset: a.name, note: "no backup location in the export" }], assets: [ref],
        }));
      }
    }
    // 4. offsite / separate account / offline
    const sepAcct = L.some((l) => l.account && srcAccount && l.account !== srcAccount);
    const otherRegion = L.some((l) => (l.region && srcRegion && l.region !== srcRegion) || (l.kind === "azure-vault" && l.geo));
    const offline = L.some((l) => l.offline === true);
    if (L.some((l) => l.account || l.region) || srcAccount) accountData = true;
    const allSame = L.length > 0 && srcAccount && srcRegion && L.every((l) => l.account === srcAccount && l.region === srcRegion && !(l.kind === "azure-vault" && l.geo) && l.offline !== true);
    let offState = sepAcct || otherRegion || offline ? "yes" : allSame ? "no" : "unknown";
    if (!good.length) offState = "no";
    if (allSame && good.length) {
      findings.push(mkFinding({
        id: "same-acct:" + normName(a.name), subject: a.name, category: "isolation", title: "Backups only in the same account and region as the source", severity: crit === "low" ? "medium" : "high", confidence: sys.some((s) => s.regionInferred) ? "likely" : "confirmed",
        description: a.name + " runs in " + srcAccount + "/" + srcRegion + " and every backup location is in the same account and region" + (sys.some((s) => s.regionInferred) ? " (source region taken from its Azure vault, which protects resources in its own region)" : "") + ". A compromise of that account or an outage of that region takes the backups with it.",
        recommendation: "Copy backups to a vault in a separate account (AWS Backup cross-account copy / logically air-gapped vault) and another region, or enable geo-redundancy with cross-region restore.",
        controls: [C.cis114, C.cp9_3, C.cp6, C.cisa, C.csf, C.t1490], evidence: [{ asset: a.name, sourceAccount: srcAccount, sourceRegion: srcRegion }].concat(locEv), assets: [ref],
      }));
    } else if ((crit === "critical" || crit === "high") && good.length && L.length && !sepAcct && !offline && L.every((l) => l.offline === false || l.offline == null) && L.some((l) => l.offline === false) && srcAccount && L.every((l) => l.account === srcAccount)) {
      findings.push(mkFinding({
        id: "no-isolated:" + normName(a.name), subject: a.name, category: "isolation", title: "No offline or separate-account copy", severity: crit === "critical" ? "high" : "medium", confidence: "confirmed",
        description: a.name + " has no copy that is offline/air-gapped or held in a different account than " + srcAccount + " (3-2-1-1-0: one copy isolated).",
        recommendation: "Add an isolated copy: separate-account vault, logically air-gapped vault, tape or offline media.",
        controls: [C.cis114, C.cp9_3, C.cisa, C.t1490], evidence: locEv, assets: [ref],
      }));
    }
    // 5. retention
    const retVals = L.map((l) => l.retentionDays).filter((v) => v != null).concat(events.map((e) => e.retentionDays).filter((v) => v != null));
    const veeamPts = events.filter((e) => e.kind === "point" && e.sysSource === "veeam" && e.status === "success" && e.time != null);
    if (veeamPts.length && now != null) retVals.push(r1((now - veeamPts[0].time) / DAY));
    const maxRet = retVals.length ? Math.max(...retVals) : null;
    if (maxRet != null) retentionData = true;
    if (o.minRetentionDays != null && maxRet != null && maxRet < o.minRetentionDays && good.length) {
      findings.push(mkFinding({
        id: "retention:" + normName(a.name), subject: a.name, category: "retention", title: "Retention " + maxRet + " days is below policy (" + o.minRetentionDays + ")", severity: crit === "critical" || crit === "high" ? "medium" : "low", confidence: "confirmed",
        description: "The longest retention evidenced for " + a.name + " is " + maxRet + " days (retention settings, recovery-point lifecycle or oldest Veeam restore point); the policy minimum is " + o.minRetentionDays + " days.",
        recommendation: "Extend retention on at least one copy (ideally the immutable one).", controls: [C.cp9, C.iso, C.cis111], evidence: locEv.concat([{ asset: a.name, longestRetentionDays: maxRet }]), assets: [ref],
      }));
    }
    if (o.dwellDays != null && maxRet != null && maxRet < o.dwellDays && good.length) {
      findings.push(mkFinding({
        id: "dwell:" + normName(a.name), subject: a.name, category: "retention", title: "Retention " + maxRet + " days cannot cover the dwell window you set (" + o.dwellDays + " days)", severity: crit === "critical" ? "high" : "medium", confidence: "confirmed",
        description: "If an attacker was present for " + o.dwellDays + " days (the window set in the policy panel) before detonation, every restore point of " + a.name + " could already contain the compromise.",
        recommendation: "Keep at least one immutable copy longer than the dwell window you plan for.", controls: [C.cp9, C.cis113, C.t1486], evidence: locEv.concat([{ asset: a.name, longestRetentionDays: maxRet, dwellWindowDays: o.dwellDays }]), assets: [ref],
      }));
    }
    // 6. restore tests
    const passes = restoresA.filter((r) => r.result === "pass");
    const lastTest = restoresA[restoresA.length - 1] || null;
    const lastPass = passes[passes.length - 1] || null;
    let restoreState = hasRestoreSource && !good.length ? "no" : "unknown";
    const restoreEv = restoresA.slice(-50).reverse().map((r) => ({ system: r.sys, testedAt: iso(r.time), result: r.result, durationMin: r.durationMin ?? "", rtoMin: r.rtoMin ?? "", pointAgeHours: r.pointAgeHours ?? "", tester: r.tester, notes: r.notes, source: r.source }));
    if (hasRestoreSource && good.length) {
      if (!restoresA.length) {
        restoreState = "no";
        findings.push(mkFinding({
          id: "never-tested:" + normName(a.name), subject: a.name, category: "restore-testing", title: "Restore never tested", severity: crit === "critical" || crit === "high" ? "high" : "medium", confidence: "likely",
          description: "No restore test or restore job for " + a.name + " appears in the loaded restore sources. A backup that has never been restored is not proven recoverable.",
          recommendation: "Run and record a restore test (file-level and full system) and measure its duration against the RTO.",
          controls: [C.cis115, C.cp9_1, C.cp10, C.csf, C.iso530, C.soc2a13], evidence: [{ asset: a.name, criticality: crit, restoreSources: parsed.files.filter((f) => f.kind === "restore-tests" || f.kind === "aws-restore-jobs" || f.kind === "azure-jobs").map((f) => f.name).join(", ") }], assets: [ref],
        }));
      } else {
        const fresh = lastPass && restoreWin != null && lastPass.time >= restoreWin;
        restoreState = fresh && lastTest.result === "pass" ? "yes" : "no";
        if (lastTest.result !== "pass") {
          findings.push(mkFinding({
            id: "test-failed:" + normName(a.name), subject: a.name, category: "restore-testing", title: "Latest restore test " + (lastTest.result === "partial" ? "only partially succeeded" : "failed"), severity: crit === "critical" || crit === "high" ? "high" : "medium", confidence: "confirmed",
            description: "The most recent restore test of " + a.name + " on " + iso(lastTest.time) + " was " + lastTest.result + (lastTest.notes ? ": " + lastTest.notes : "") + ".",
            recommendation: "Fix the cause and repeat the test until a full restore succeeds.", controls: [C.cis115, C.cp9_1, C.cp10, C.csf], evidence: restoreEv, assets: [ref],
          }));
        } else if (!fresh && now != null) {
          const age = lastPass ? r1((now - lastPass.time) / DAY) : null;
          findings.push(mkFinding({
            id: "test-stale:" + normName(a.name), subject: a.name, category: "restore-testing", title: "Last successful restore test " + age + " days ago (window " + o.restoreTestDays + ")", severity: crit === "critical" ? "high" : "medium", confidence: "confirmed",
            description: "The newest passing restore test of " + a.name + " was on " + iso(lastPass.time) + ", outside the " + o.restoreTestDays + "-day window before " + isoDay(now) + ".",
            recommendation: "Schedule recurring restore tests (AWS Backup restore testing, Veeam SureBackup, or a documented manual test).", controls: [C.cis115, C.cp9_1, C.csf], evidence: restoreEv, assets: [ref],
          }));
        }
      }
    }
    // RTO from tests
    const rtoBreaches = restoresA.filter((r) => r.result === "pass" && r.durationMin != null && r.durationMin > (r.rtoMin != null ? r.rtoMin : a.rto * 60));
    const lastPassRto = lastPass && lastPass.durationMin != null ? lastPass.durationMin <= (lastPass.rtoMin != null ? lastPass.rtoMin : a.rto * 60) : null;
    if (lastPass && lastPassRto === false) {
      const tgt = lastPass.rtoMin != null ? lastPass.rtoMin : a.rto * 60;
      findings.push(mkFinding({
        id: "rto:" + normName(a.name), subject: a.name, category: "rto", title: "Tested restore took " + lastPass.durationMin + " min (RTO " + tgt + " min)", severity: crit === "critical" ? "high" : "medium", confidence: "confirmed",
        description: "The latest passing restore test of " + a.name + " (" + iso(lastPass.time) + ") took " + lastPass.durationMin + " minutes against an RTO of " + tgt + " minutes" + (lastPass.rtoMin != null ? " stated in the test log" : " from the asset's RTO") + ". Restore duration only; rebuild and validation add to it.",
        recommendation: "Shorten recovery (instant recovery, smaller restore scope, pre-staged infrastructure) or agree a realistic RTO with the business.",
        controls: [C.cp10, C.cis115, C.iso530, C.soc2a13], evidence: rtoBreaches.slice(-50).reverse().map((r) => ({ testedAt: iso(r.time), durationMin: r.durationMin, rtoMin: r.rtoMin != null ? r.rtoMin : a.rto * 60, source: r.source })), assets: [ref],
      }));
    }
    // 7. encryption per asset
    const encVals = L.map((l) => l.encrypted).concat(good.map((e) => e.encrypted)).filter((v) => v != null);
    if (encVals.length) encData = true;
    const encState = !good.length ? "no" : encVals.some((v) => v === false) ? "no" : encVals.length && L.every((l) => l.encrypted === true || good.some((e) => e.loc === l.key && e.encrypted === true)) ? "yes" : "unknown";

    // jobs state
    const jobsState = !aJobs.length || !aJobs.some((k) => jobs.has(k) && jobs.get(k).runs.length) ? (good.length ? "unknown" : "no") : aJobs.some((k) => badJobs.has(k)) ? "no" : "yes";

    const items = {
      backup: good.length ? "yes" : "no",
      rpo: rpoMet == null ? "unknown" : rpoMet ? "yes" : "no",
      jobs: jobsState, immutable: immState, offsite: offState, restore: restoreState, encryption: encState,
    };
    const val = (s) => (s === "yes" ? 1 : s === "partial" ? 0.5 : 0);
    const score = Math.round((WEIGHT_KEYS.reduce((acc, [k]) => acc + W[k] * val(items[k]), 0) / wSum) * 100);

    // 3-2-1-1-0
    const types = L.map((l) => l.targetType);
    const knownTypes = new Set(types.filter(Boolean));
    const copies = 1 + L.length;
    const media = knownTypes.size >= 2 ? "yes" : types.some((t) => !t) ? "unknown" : "no";
    const zero = !hasRestoreSource ? "unknown" : lastTest ? (lastTest.result === "pass" ? "yes" : "no") : "no";
    const immOff = L.some((l) => lockedCompliance(l) || l.offline === true) ? "yes" : L.some((l) => l.immutable == null && l.offline == null) ? "unknown" : immWeak ? "partial" : "no";
    rule.push({
      asset: a.name, criticality: crit, copies, copiesMet: copies >= 3 ? "yes" : "no", mediaTypes: [...knownTypes].sort().join(", "), media, offsite: offState,
      immutableOrOffline: good.length ? immOff : "no", zeroErrors: zero, locations: L.map((l) => l.name).join(", "),
    });
    recovery.push({
      asset: a.name, criticality: crit, criticalitySource: a.criticalitySource, owner: a.owner || "", type: a.type || "", objects: sys.map((s) => s.arn || s.name).join(", "), matched: a.manual ? "manual" : sys.length ? "name" : "",
      lastGood: iso(lastGood), ageHours: ageH, rpoHours: a.rpo, rpoMet: items.rpo, rtoHours: a.rto, copies, locations: L.map((l) => l.name).join(", "),
      immutable: immState, offsite: offState, encrypted: encState, jobs: jobsState, lastTest: lastTest ? iso(lastTest.time) : "", lastTestResult: lastTest ? lastTest.result : "",
      lastPass: lastPass ? iso(lastPass.time) : "", rtoMet: lastPassRto == null ? "unknown" : lastPassRto ? "yes" : "no", restoreTested: restoreState, retentionDays: maxRet,
      account: srcAccount || "", region: srcRegion || "", score, items,
    });
  }
  if (!accountData) skipped.push({ check: "same account / region", reason: "no source or target account / region in the data (AWS ARNs, Azure subscription, or target_account / source_account columns)" });
  if (!retentionData && (o.minRetentionDays != null || o.dwellDays != null)) skipped.push({ check: "retention", reason: "no retention data (retention_days column, AWS recovery point lifecycle or Veeam restore points)" });
  if (!encData) skipped.push({ check: "encryption", reason: "no encryption flag in the data" });

  // unmatched backup objects (info)
  if (M.unmatchedSystems.length) {
    findings.push(mkFinding({
      id: "unmatched-objects", subject: "backup objects", category: "inventory", title: M.unmatchedSystems.length + " backup object(s) not in the asset list", severity: "info", confidence: "confirmed",
      description: "These backup objects did not match any asset by name. They are either missing from the inventory or named differently (map them in the asset matching panel).",
      recommendation: "Add them to the asset inventory with a criticality and RPO, or map them to an existing asset.", controls: [C.cis111, C.iso],
      evidence: M.unmatchedSystems.map((s) => ({ object: s.arn || s.name, sources: [...s.sources].sort().join(", "), records: s.events.length })), assets: [],
    }));
  }

  findings.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || cmp(a.category, b.category) || cmp(a.subject, b.subject) || cmp(a.id, b.id));

  // daily job chart
  const daily = new Map();
  for (const j of jobList) for (const r of j.runs) {
    if (!["success", "warning", "failed"].includes(r.status)) continue;
    const d = isoDay(r.time);
    if (!daily.has(d)) daily.set(d, { date: d, success: 0, warning: 0, failed: 0 });
    daily.get(d)[r.status]++;
  }
  const dailyRows = [...daily.values()].sort((a, b) => cmp(a.date, b.date));

  const restoreRows = M.restores.slice().sort((a, b) => a.time - b.time || cmp(a.sys, b.sys)).map((r) => {
    const s = systems.get(parseArn(r.sys) ? "arn:" + r.sys.toLowerCase() : normName(r.sys));
    const as = s ? (assetsBySys.get(s.key) || []).map((x) => x.name).join(", ") : "";
    return { system: s ? s.name : r.sys, asset: as, testedAt: iso(r.time), result: r.result, durationMin: r.durationMin ?? "", rtoMin: r.rtoMin ?? "", pointAgeHours: r.pointAgeHours ?? "", tester: r.tester, notes: r.notes, source: r.source, file: r.file };
  }).concat(M.unresolvedRestores.map((r) => ({ system: "(recovery point not in the loaded backup jobs)", asset: "", testedAt: iso(r.time), result: r.result, durationMin: r.durationMin ?? "", rtoMin: "", pointAgeHours: r.pointAgeHours ?? "", tester: r.tester, notes: r.notes + " " + r.rp, source: r.source, file: r.file })));

  const crits = recovery.filter((r) => r.criticality === "critical");
  const mean = (xs) => (xs.length ? r1(xs.reduce((x, y) => x + y, 0) / xs.length) : null);
  const summary = {
    asOf: iso(now), asOfSource: M.nowSource, assets: recovery.length, assetListGiven: M.listGiven,
    protected: recovery.filter((r) => r.items.backup === "yes").length,
    rpoBreaches: recovery.filter((r) => r.items.rpo === "no").length,
    critical: crits.length,
    immutableCriticalPct: crits.length ? Math.round((crits.filter((r) => r.immutable === "yes").length / crits.length) * 1000) / 10 : null,
    restoreTestsInWindow: restoreWin == null ? 0 : M.restores.filter((r) => r.time >= restoreWin && r.time <= now).length,
    readiness: mean(recovery.map((r) => r.score)), readinessCritical: mean(crits.map((r) => r.score)),
    findings: findings.length, bySeverity: countBy(findings, "severity"),
    systems: M.sysList.length, unmatchedSystems: M.unmatchedSystems.length, unmatchedAssets: recovery.filter((r) => !r.objects).length,
    jobs: jobRows.length, locations: locRows.length, restoreRecords: restoreRows.length, events: parsed.records.events.length,
  };
  ctx?.progress?.(1, 1, "done");
  const weights = WEIGHT_KEYS.map(([k, ok, label]) => ({ item: k, label, weight: W[k] }));
  return {
    summary, findings,
    tables: {
      recovery, rule, jobs: jobRows, daily: dailyRows, restores: restoreRows, locations: locRows, weights,
      systems: M.sysList.map((s) => ({ key: s.key, name: s.name, arn: s.arn, sources: [...s.sources].sort().join(", "), account: s.account || "", region: s.region || "", records: s.events.length, restores: s.restores.length, assets: (assetsBySys.get(s.key) || []).map((a) => a.name).join(", ") })),
      unmatchedSystems: M.unmatchedSystems.map((s) => ({ key: s.key, name: s.arn || s.name, sources: [...s.sources].sort().join(", "), records: s.events.length })),
      unmatchedAssets: recovery.filter((r) => !r.objects).map((r) => ({ asset: r.asset, criticality: r.criticality })),
    },
    skipped,
    meta: { tool: TOOL_ID, version: VERSION, rows: parsed.records.events.length + parsed.records.restores.length + parsed.records.pendingRestores.length, files: parsed.files.map(({ headers, ...f }) => ({ ...f, headers: headers.slice(0, 80) })), options: stripOpts(o) },
  };
}

function stripOpts(o) {
  const out = {};
  for (const k of Object.keys(DEFAULTS)) out[k] = o[k];
  return out;
}

const tri = (v) => (v === true ? "yes" : v === false ? "no" : "unknown");

function countBy(items, key) {
  const out = {};
  for (const it of items) out[it[key]] = (out[it[key]] || 0) + 1;
  return Object.fromEntries(Object.entries(out).sort((a, b) => cmp(a[0], b[0])));
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
const q = (v) => {
  let s = v == null ? "" : Array.isArray(v) ? v.join("; ") : String(v);
  if (/^[=+@\t\r]/.test(s) || /^-[^\d]/.test(s)) s = "'" + s;
  return '"' + s.replace(/"/g, '""') + '"';
};

export const FINDING_COLS = ["id", "severity", "confidence", "category", "title", "assets", "description", "recommendation", "controls", "evidenceCount"];

/** Findings as CSV with fixed columns (formula-injection safe). */
export function findingsToCsv(findings) {
  const body = (findings || []).map((f) => [
    f.id, f.severity, f.confidence, f.category, f.title, (f.assets || []).map((a) => a.name), f.description, f.recommendation,
    (f.controls || []).map((c) => c.framework + " " + c.id), f.evidenceCount != null ? f.evidenceCount : (f.evidence || []).length,
  ].map(q).join(","));
  return [FINDING_COLS.join(","), ...body].join("\n") + "\n";
}

export const RECOVERY_COLS = ["asset", "criticality", "owner", "objects", "lastGood", "ageHours", "rpoHours", "rpoMet", "rtoHours", "copies", "locations", "immutable", "offsite", "encrypted", "jobs", "lastTest", "lastTestResult", "lastPass", "rtoMet", "retentionDays", "score"];

/** Recovery-confidence table as CSV. */
export function recoveryToCsv(rows) {
  return [RECOVERY_COLS.join(","), ...(rows || []).map((r) => RECOVERY_COLS.map((k) => q(r[k])).join(","))].join("\n") + "\n";
}

/** Plain-text readiness report. */
export function readinessReport(r) {
  const s = r.summary, L = [];
  L.push("Backup and Ransomware Readiness report");
  L.push("As of: " + (s.asOf || "n/a") + " (" + s.asOfSource + ")");
  L.push("Engine: " + TOOL_ID + " " + VERSION);
  L.push("");
  L.push("Readiness score (all assets): " + (s.readiness == null ? "n/a" : s.readiness + " / 100"));
  L.push("Readiness score (critical assets): " + (s.readinessCritical == null ? "n/a" : s.readinessCritical + " / 100"));
  L.push("Assets: " + s.assets + (s.assetListGiven ? "" : " (no asset list; backup objects used)") + " | protected: " + s.protected + " | RPO breaches: " + s.rpoBreaches);
  L.push("Immutable coverage of critical assets: " + (s.immutableCriticalPct == null ? "n/a" : s.immutableCriticalPct + "%") + " | restore tests in window: " + s.restoreTestsInWindow);
  L.push("");
  L.push("Score weights (item: weight). Pass = full weight, partial = half, fail or unknown = 0:");
  for (const w of r.tables.weights) L.push("  " + w.label + ": " + w.weight);
  L.push("");
  L.push("Recovery confidence per asset:");
  for (const a of r.tables.recovery) {
    L.push("- " + a.asset + " [" + a.criticality + "] score " + a.score + ": last good " + (a.lastGood || "none") + (a.ageHours != null ? " (" + a.ageHours + " h, RPO " + a.rpoHours + " h, " + a.rpoMet + ")" : "") +
      "; copies " + a.copies + "; immutable " + a.immutable + "; offsite " + a.offsite + "; restore tested " + a.restoreTested + (a.lastTest ? " (last " + a.lastTest.slice(0, 10) + " " + a.lastTestResult + ")" : "") + "; RTO met " + a.rtoMet);
  }
  L.push("");
  L.push("3-2-1-1-0 (copies include production):");
  for (const x of r.tables.rule) L.push("- " + x.asset + ": copies " + x.copies + " (" + x.copiesMet + "), media " + x.media + (x.mediaTypes ? " [" + x.mediaTypes + "]" : "") + ", offsite " + x.offsite + ", immutable/offline " + x.immutableOrOffline + ", 0 errors " + x.zeroErrors);
  L.push("");
  L.push("Findings (" + r.findings.length + "):");
  for (const f of r.findings) L.push("- [" + f.severity + "/" + f.confidence + "] " + f.title + (f.subject ? " - " + f.subject : "") + "\n    " + f.recommendation + "\n    Controls: " + f.controls.map((c) => c.framework + " " + c.id).join("; "));
  if (r.skipped.length) { L.push(""); L.push("Checks skipped or limited:"); for (const k of r.skipped) L.push("- " + k.check + ": " + k.reason); }
  return L.join("\n") + "\n";
}

/** Short summary TXT. */
export function summaryText(r) {
  const s = r.summary;
  return ["Backup Readiness summary", "As of: " + (s.asOf || "n/a"), "Assets: " + s.assets + ", protected " + s.protected + ", RPO breaches " + s.rpoBreaches,
    "Readiness: " + (s.readiness == null ? "n/a" : s.readiness) + " / 100", "Findings: " + r.findings.length + " " + JSON.stringify(s.bySeverity), ""]
    .concat(r.findings.map((f) => "- [" + f.severity + "] " + f.title + (f.subject ? " (" + f.subject + ")" : "") + " - " + f.recommendation)).join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// Synthetic example (format-faithful; fictional accounts and names)
// ---------------------------------------------------------------------------
export const EXAMPLE_NOW = "2026-10-15T12:00:00Z";

/** Seeded SYNTHETIC dataset for "Load example (synthetic)" and the tests. */
export function exampleDataset(seed = 7) {
  let s = seed >>> 0 || 7;
  const rnd = () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 4294967296; };
  const NOW = Date.parse(EXAMPLE_NOW);
  const A = "210987654321", B = "345678901234", RA = "us-east-1", RB = "us-west-2";
  const isoZ = (t) => new Date(t).toISOString().replace(/\.000Z$/, ".000000+00:00");
  const vaultArn = (acct, reg, n) => "arn:aws:backup:" + reg + ":" + acct + ":backup-vault:" + n;
  const res = [
    { arn: "arn:aws:rds:" + RA + ":" + A + ":db:orders-db", type: "RDS", name: "orders-db", vault: "prod-default", copy: true },
    { arn: "arn:aws:ec2:" + RA + ":" + A + ":instance/i-0a1b2c3d4e5f60001", type: "EC2", name: "web-01", vault: "prod-default" },
    { arn: "arn:aws:ec2:" + RA + ":" + A + ":instance/i-0a1b2c3d4e5f60002", type: "EC2", name: "web-02", vault: "prod-default", failLast: 3, stopDays: 4 },
    { arn: "arn:aws:elasticfilesystem:" + RA + ":" + A + ":file-system/fs-0f1e2d3c", type: "EFS", name: "files-efs", vault: "prod-default", copy: true },
    { arn: "arn:aws:dynamodb:" + RA + ":" + A + ":table/analytics-ddb", type: "DynamoDB", name: "analytics-ddb", vault: "prod-default", weekly: true },
    { arn: "arn:aws:rds:" + RB + ":" + B + ":db:crm-db", type: "RDS", name: "crm-db", vault: "crm-vault", acct: B, reg: RB },
  ];
  const jobs = [], copies = [];
  let id = 0;
  const hex = () => Math.floor(rnd() * 0xffffffff).toString(16).padStart(8, "0");
  for (const r of res) {
    const acct = r.acct || A, reg = r.reg || RA;
    for (let d = 14; d >= 1; d--) {
      if (r.weekly && d % 7 !== 2) continue;
      const start = NOW - (d - 1) * DAY - 7 * HOUR; // 05:00 UTC daily, d = 1 is today
      const fromEnd = d; // 1 = yesterday
      let state = "COMPLETED";
      if (r.stopDays && fromEnd < r.stopDays) state = "FAILED";
      if (r.stopDays && fromEnd >= r.stopDays) state = "COMPLETED";
      const end = start + Math.round((20 + rnd() * 40) * 60000);
      const rp = "arn:aws:rds:" + reg + ":" + acct + ":snapshot:awsbackup:job-" + hex() + hex();
      const job = {
        AccountId: acct, BackupJobId: hex() + "-" + hex().slice(0, 4) + "-4" + hex().slice(0, 3) + "-8" + hex().slice(0, 3) + "-" + hex() + hex().slice(0, 4),
        BackupVaultName: r.vault, BackupVaultArn: vaultArn(acct, reg, r.vault), RecoveryPointArn: state === "COMPLETED" ? rp : undefined,
        ResourceArn: r.arn, CreationDate: isoZ(start), CompletionDate: state === "COMPLETED" ? isoZ(end) : undefined, State: state,
        StatusMessage: state === "FAILED" ? "Insufficient privileges to perform this action." : undefined, PercentDone: state === "COMPLETED" ? "100.0" : "0.0",
        BackupSizeInBytes: state === "COMPLETED" ? Math.round(2e9 + rnd() * 8e9) : 0, IamRoleArn: "arn:aws:iam::" + acct + ":role/service-role/AWSBackupDefaultServiceRole",
        CreatedBy: { BackupPlanId: "plan-" + hex(), BackupPlanArn: "arn:aws:backup:" + reg + ":" + acct + ":backup-plan:plan-" + hex(), BackupPlanVersion: hex() + hex(), BackupRuleId: "rule-" + hex() },
        ResourceType: r.type, BytesTransferred: 0, BackupType: "", IsParent: false, ResourceName: r.name, InitiationDate: isoZ(start),
      };
      for (const k of Object.keys(job)) if (job[k] === undefined) delete job[k];
      jobs.push(job);
      if (r.copy && state === "COMPLETED") {
        copies.push({
          AccountId: acct, CopyJobId: hex() + "-" + hex().slice(0, 4) + "-" + hex().slice(0, 4) + "-" + hex().slice(0, 4) + "-" + hex() + hex().slice(0, 4),
          SourceBackupVaultArn: vaultArn(acct, reg, r.vault), SourceRecoveryPointArn: rp,
          DestinationBackupVaultArn: vaultArn(B, RB, "dr-locked"), DestinationRecoveryPointArn: "arn:aws:backup:" + RB + ":" + B + ":recovery-point:" + hex() + "-" + hex(),
          ResourceArn: r.arn, CreationDate: isoZ(end + 5 * 60000), CompletionDate: isoZ(end + 45 * 60000), State: "COMPLETED", BackupSizeInBytes: job.BackupSizeInBytes,
          IamRoleArn: job.IamRoleArn, ResourceType: r.type, ResourceName: r.name,
        });
      }
      id++;
    }
  }
  jobs.sort((a, b) => cmp(b.CreationDate, a.CreationDate) || cmp(a.ResourceArn, b.ResourceArn));
  copies.sort((a, b) => cmp(b.CreationDate, a.CreationDate) || cmp(a.ResourceArn, b.ResourceArn));
  const vaultsA = { BackupVaultList: [
    { BackupVaultName: "prod-default", BackupVaultArn: vaultArn(A, RA, "prod-default"), VaultType: "BACKUP_VAULT", CreationDate: "2025-02-11T09:12:40.512000+00:00", EncryptionKeyArn: "arn:aws:kms:" + RA + ":" + A + ":key/0b7e1f3c-1111-4a2b-9c3d-5e6f7a8b9c0d", CreatorRequestId: "", NumberOfRecoveryPoints: 112, Locked: false },
  ] };
  const vaultsB = { BackupVaultList: [
    { BackupVaultName: "crm-vault", BackupVaultArn: vaultArn(B, RB, "crm-vault"), VaultType: "BACKUP_VAULT", CreationDate: "2025-06-02T14:01:09.220000+00:00", EncryptionKeyArn: "arn:aws:kms:" + RB + ":" + B + ":key/6a2d9e41-2222-4c5d-8e9f-0a1b2c3d4e5f", NumberOfRecoveryPoints: 28, Locked: true, MinRetentionDays: 14, MaxRetentionDays: 120 },
    { BackupVaultName: "dr-locked", BackupVaultArn: vaultArn(B, RB, "dr-locked"), VaultType: "BACKUP_VAULT", CreationDate: "2025-03-01T08:00:00.000000+00:00", EncryptionKeyArn: "arn:aws:kms:" + RB + ":" + B + ":key/9c8b7a65-3333-4f4e-8d7c-6b5a4f3e2d1c", NumberOfRecoveryPoints: 54, Locked: true, MinRetentionDays: 35, MaxRetentionDays: 365, LockDate: "2025-03-04T08:00:00.000000+00:00" },
  ] };
  // Veeam sessions: per-VM jobs (job name = VM name), US-format timestamps as Export-Csv writes them on en-US.
  const vm = [
    { job: "fin-sql-01", pattern: () => "Success" },
    { job: "hr-app-01", pattern: (d) => (d <= 10 ? "Warning" : "Success") },
    { job: "dc-01", pattern: () => "Success" },
    { job: "file-srv-01", pattern: (d) => (d % 3 === 0 ? "Failed" : "Success") },
    { job: "build-01", pattern: () => "Success" },
  ];
  const us = (t) => { const x = new Date(t); let h = x.getUTCHours(); const ap = h >= 12 ? "PM" : "AM"; h = h % 12 || 12; return (x.getUTCMonth() + 1) + "/" + x.getUTCDate() + "/" + x.getUTCFullYear() + " " + h + ":" + String(x.getUTCMinutes()).padStart(2, "0") + ":" + String(x.getUTCSeconds()).padStart(2, "0") + " " + ap; };
  const vrows = ['"JobName","JobType","Name","CreationTime","EndTime","State","Result","IsRetryMode","Progress.TransferedSize"'];
  for (let d = 21; d >= 1; d--) for (const v of vm) {
    const st = NOW - d * DAY + 10 * HOUR; // 22:00 UTC previous day
    const result = v.pattern(d);
    const en = st + Math.round((15 + rnd() * 50) * 60000);
    vrows.push(['"' + v.job + '"', '"Backup"', '"' + v.job + ' (Incremental)"', '"' + us(st) + '"', '"' + us(en) + '"', '"Stopped"', '"' + result + '"', '"False"', '"' + (result === "Failed" ? 0 : Math.round(1e8 + rnd() * 9e8)) + '"'].join(","));
  }
  const restoreLog = [
    "system,tested_at,result,restore_point_age_hours,duration_minutes,rto_minutes_target,tester,notes",
    "orders-db,2026-10-05T14:00:00Z,pass,9,38,240,ops.lead@test.darknode.ai,Point-in-time restore to isolated subnet; row counts verified",
    "fin-sql-01,2026-10-10T09:30:00Z,fail,11,95,240,dba@test.darknode.ai,Restore completed but database would not mount (log chain broken)",
    "dc-01,2026-09-28T07:00:00Z,pass,14,300,240,infra@test.darknode.ai,Authoritative restore in isolated lab; took 5 h",
    "files-efs,2026-03-20T10:00:00Z,pass,20,25,1440,storage@test.darknode.ai,Sample of 200 files restored and hashed",
    "web-01,2026-09-15T16:00:00Z,pass,6,20,480,web.team@test.darknode.ai,AMI launched and health check passed",
  ].join("\n");
  const assetsCsv = [
    "name,type,criticality,owner,rpo_hours,rto_hours,environment",
    "orders-db,database,critical,ops.lead@test.darknode.ai,24,4,production",
    "payments-db,database,critical,payments@test.darknode.ai,4,2,production",
    "web-01,server,high,web.team@test.darknode.ai,,,production",
    "web-02,server,high,web.team@test.darknode.ai,,,production",
    "files-efs,file share,medium,storage@test.darknode.ai,,,production",
    "analytics-ddb,database,low,data@test.darknode.ai,,,production",
    "fin-sql-01,database,critical,dba@test.darknode.ai,24,4,production",
    "hr-app-01,server,high,hr.it@test.darknode.ai,,,production",
    "dc-01,server,critical,infra@test.darknode.ai,24,4,production",
    "file-srv-01,file share,medium,storage@test.darknode.ai,,,production",
    "build-01,server,low,devops@test.darknode.ai,,,development",
    "crm-db,database,high,sales.ops@test.darknode.ai,,,production",
  ].join("\n");
  return {
    label: "synthetic example (fictional Larkspur Freight: two AWS accounts, one Veeam server; not real data)",
    now: EXAMPLE_NOW,
    files: [
      { name: "aws-backup-jobs-prod-and-dr.json", text: JSON.stringify({ BackupJobs: jobs }, null, 4) },
      { name: "aws-copy-jobs-prod.json", text: JSON.stringify({ CopyJobs: copies }, null, 4) },
      { name: "aws-vaults-210987654321.json", text: JSON.stringify(vaultsA, null, 4) },
      { name: "aws-vaults-345678901234.json", text: JSON.stringify(vaultsB, null, 4) },
      { name: "veeam-backup-sessions.csv", text: vrows.join("\r\n") + "\r\n" },
      { name: "restore-tests.csv", text: restoreLog + "\n" },
      { name: "assets.csv", text: assetsCsv + "\n" },
    ],
  };
}

/** Deterministic self-test of the engine on the synthetic example. */
export function selfTest() {
  const tests = [];
  const ex = exampleDataset();
  const r = analyze(ex.files, { now: ex.now });
  const has = (cat, subj) => r.findings.some((f) => f.category === cat && (!subj || f.subject === subj));
  tests.push({ name: "unprotected critical DB detected", pass: r.findings.some((f) => f.id === "no-backup:payments-db" && f.severity === "critical") });
  tests.push({ name: "RPO breach on web-02", pass: has("rpo", "web-02") });
  tests.push({ name: "vault without lock detected", pass: has("deletion-protection", "prod-default") });
  tests.push({ name: "same-account-only backups detected", pass: has("isolation", "web-01") });
  tests.push({ name: "failed restore test detected", pass: has("restore-testing", "fin-sql-01") });
  tests.push({ name: "orders-db has an immutable offsite copy", pass: r.tables.recovery.some((x) => x.asset === "orders-db" && x.immutable === "yes" && x.offsite === "yes") });
  tests.push({ name: "deterministic", pass: JSON.stringify(r) === JSON.stringify(analyze(exampleDataset().files, { now: ex.now })) });
  tests.push({ name: "empty input yields no findings", pass: analyze([]).findings.length === 0 });
  return { pass: tests.every((t) => t.pass), tests };
}
