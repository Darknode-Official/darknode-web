// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Cloud Audit Log Hunter engine (cloudtrail). Pure logic: no DOM, no network, no timers.
//
// Takes the audit-log exports a cloud administrator can pull without any agent:
//   AWS CloudTrail   {"Records":[...]} digest files, NDJSON (one record per line),
//                    Athena / CSV export (struct columns as {k=v, ...} or JSON strings)
//   Azure            Activity Log export JSON ({"value":[...]}) and the Log Analytics
//                    AzureActivity CSV (TimeGenerated,OperationNameValue,Caller,...)
//   GCP              Cloud Audit Logs LogEntry NDJSON / JSON array (protoPayload AuditLog)
//   Microsoft 365    Search-UnifiedAuditLog | Export-Csv (RecordType,CreationDate,UserIds,
//                    Operations,AuditData), the Purview portal CSV and raw AuditData JSON
// normalises every record to one event shape and runs deterministic hunting rules
// (RULES) mapped to MITRE ATT&CK and the CIS benchmarks. Rules whose fields the source
// format lacks are skipped and reported, never guessed.
//
// Normalised event:
//   { i, ts, platform, account, principal, principalType, action, service, region, ip, ua,
//     status ("success"|"failure"|"other"), error, target, mfa (true|false|null), readOnly,
//     logType, req, res, add, raw (index into dataset.raw or -1) }
//
// Same input -> byte-identical output: events are sorted by (ts, file order), every map is
// emitted in sorted key order, no clock is read (opts.now, default = newest timestamp).

import { sniff, iterCsv, iterJson, findColumn, decodeText } from "../ingest/parse.js";
import { haversineKm } from "../identity/signin-forensics-engine.js";

export const TOOL_ID = "cloudtrail";
export const VERSION = "1.0.0";

export const PLATFORMS = ["aws", "azure", "gcp", "m365", "generic"];
export const PLATFORM_LABEL = { aws: "AWS CloudTrail", azure: "Azure Activity Log", gcp: "GCP Cloud Audit Logs", m365: "Microsoft 365 Unified Audit Log", generic: "Generic audit CSV/JSON", mixed: "Mixed" };
export const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
export const CONF_RANK = { confirmed: 3, likely: 2, review: 1 };
export const EVIDENCE_CAP = 50;

/** Column aliases for generic CSV / JSON (key -> accepted header names, case-insensitive). */
export const COLUMNS = {
  timestamp: ["eventTime", "timestamp", "time", "TimeGenerated", "eventTimestamp", "CreationDate", "CreationTime", "date", "datetime", "@timestamp"],
  principal: ["principal", "user", "userName", "UserIds", "UserId", "caller", "Caller", "principalEmail", "actor", "identity", "arn"],
  action: ["eventName", "action", "operation", "Operations", "OperationNameValue", "methodName", "event", "activity"],
  service: ["eventSource", "service", "serviceName", "Workload", "resourceProvider", "category"],
  ip: ["sourceIPAddress", "ip", "ClientIP", "CallerIpAddress", "callerIp", "clientIpAddress", "source ip", "src_ip", "ipAddress"],
  status: ["errorCode", "status", "ResultStatus", "ActivityStatusValue", "result", "outcome"],
  region: ["awsRegion", "region", "location", "zone"],
  account: ["recipientAccountId", "account", "accountId", "subscriptionId", "project", "project_id", "OrganizationId", "tenant"],
  target: ["target", "resource", "resourceId", "_ResourceId", "resourceName", "ObjectId", "object"],
  userAgent: ["userAgent", "user agent", "callerSuppliedUserAgent", "ClientInfoString", "ua"],
};

/** Tunable thresholds; the UI renders these grouped (identity / logging / data / recon). */
export const DEFAULTS = {
  // identity
  consoleFailN: 10, consoleFailWindowMin: 10,        // console login failures per IP before it is a burst
  failureBurstN: 25, failureBurstWindowMin: 10,      // AccessDenied / Failed operations per principal
  trustedAccounts: [],                               // AWS account ids allowed to assume roles / be trusted
  adminNamePattern: "admin|administrator|^root$|adm$|^svc|^sa$|da$|global admin|break ?glass",
  travelKmh: 900,                                    // faster than this between two IPs with geo = impossible travel
  afterHours: { enabled: true, start: 20, end: 6, utcOffset: 0, weekends: true }, // local hour window counted as after hours
  // logging / baseline
  baselineMinEvents: 100,                            // events a principal / account needs before "first seen" means anything
  // data
  secretsBurstN: 20, secretsBurstWindowMin: 5,       // GetSecretValue / GetParameter / getSecret
  downloadBurstN: 100, downloadBurstWindowMin: 10,   // M365 FileDownloaded
  mailAccessBurstN: 50, mailAccessBurstWindowMin: 10, // M365 MailItemsAccessed
  storageListBurstN: 100, storageListBurstWindowMin: 5, // GCP storage.objects.list / get (data_access)
  purgeBurstN: 50, purgeBurstWindowMin: 10,          // M365 HardDelete / Search-Mailbox purge
  // recon
  reconBurstN: 50, reconBurstWindowMin: 5,           // Describe* / List* / Get* per principal
  // joins supplied by the UI
  maliciousIps: null,                                // mirrored /data/feeds/malicious-ips.json object or array of ips
  geo: null,                                         // { "1.2.3.4": { lat, lon, country } } optional
  now: null,                                         // ISO reference date; default = newest timestamp in the data
  columns: {},                                       // header overrides for generic CSV files
  rawBudgetBytes: 64 * 1024 * 1024,                  // raw record JSON retained for the evidence drawer, then dropped
};

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
const str = (v) => (v == null ? "" : String(v));
const low = (v) => str(v).toLowerCase();
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const uniq = (arr) => Array.from(new Set(arr.filter((x) => x != null && x !== ""))).sort();
const byTs = (a, b) => a.ts - b.ts || a.i - b.i;
const isObj = (v) => v != null && typeof v === "object" && !Array.isArray(v);
const MIN = 60 * 1000;
const sortKeys = (o) => Object.fromEntries(Object.keys(o).sort().map((k) => [k, o[k]]));

export function parseTs(v) {
  if (v == null || v === "") return NaN;
  if (typeof v === "number") return v < 1e12 ? v * 1000 : v;
  const s = str(v).trim();
  if (/^\d{10}(\.\d+)?$/.test(s)) return Math.round(Number(s) * 1000);
  if (/^\d{13}$/.test(s)) return Number(s);
  // zone-less ISO ("2026-10-05T13:04:05", "2026-10-05 13:04:05.123") is UTC in every export handled here
  if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(s)) return Date.parse(s.replace(" ", "T") + "Z");
  const m = /^(\d{1,2})\/(\d{1,2})\/(\d{4})[ ,T]+(\d{1,2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?\s*(AM|PM)?$/i.exec(s);
  if (m) {
    let h = Number(m[4]);
    if (m[7]) { const pm = m[7].toUpperCase() === "PM"; if (pm && h < 12) h += 12; if (!pm && h === 12) h = 0; }
    let mo = Number(m[1]), d = Number(m[2]); if (mo > 12 && d <= 12) [mo, d] = [d, mo]; if (mo < 1 || mo > 12 || d < 1 || d > new Date(Date.UTC(Number(m[3]), mo, 0)).getUTCDate()) return null; // 25/12/2024 is day-first; reject instead of rolling over
    return Date.UTC(Number(m[3]), mo - 1, d, h, Number(m[5]), Number(m[6] || 0));
  }
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : NaN;
}
export function iso(ms) { return Number.isFinite(ms) ? new Date(ms).toISOString().replace(".000Z", "Z") : ""; }

/** Parse a JSON string field leniently; returns null when it is not JSON. */
export function jsonField(v) {
  if (v == null || v === "") return null;
  if (typeof v === "object") return v;
  const s = str(v).trim();
  if (!(s.startsWith("{") || s.startsWith("["))) return null;
  try { return JSON.parse(s); } catch (_) { return null; }
}

/** Athena CSV renders struct columns as "{type=IAMUser, principalid=AIDA..., arn=arn:aws:iam::1:user/x}". */
export function parseAthenaStruct(s) {
  const t = str(s).trim();
  if (!t.startsWith("{") || !t.endsWith("}")) return null;
  if (t.includes('"')) { const j = jsonField(t); if (j) return j; }
  const out = {};
  let depth = 0, key = "", val = "", inKey = true, i = 1;
  const flush = () => { const k = key.trim(); const v = val.trim(); if (k) out[k] = v === "null" ? null : v.startsWith("{") ? parseAthenaStruct(v) ?? v : v; key = ""; val = ""; inKey = true; };
  for (; i < t.length - 1; i++) {
    const c = t[i];
    if (inKey) { if (c === "=") { inKey = false; continue; } key += c; continue; }
    if (c === "{") depth++;
    if (c === "}") depth--;
    if (c === "," && depth === 0) { flush(); continue; }
    val += c;
  }
  flush();
  return out;
}

/** Strip the ":port" from "1.2.3.4:443" and "[2001:db8::1]:443"; keep bare IPv6. */
export function cleanIp(v) {
  let s = str(v).trim();
  if (!s) return "";
  const m6 = /^\[([0-9a-f:.]+)\](?::\d+)?$/i.exec(s);
  if (m6) return m6[1].toLowerCase();
  const m4 = /^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/.exec(s);
  if (m4) return m4[1];
  return s.toLowerCase();
}
export const isIpv4 = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(str(s));
export const looksLikeIp = (s) => isIpv4(s) || /^[0-9a-f:]+:[0-9a-f:]*$/i.test(str(s));
const isGuid = (s) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(str(s).trim());

function deepFind(o, pred, depth = 0) {
  if (o == null || depth > 6) return undefined;
  if (Array.isArray(o)) { for (const v of o) { const r = deepFind(v, pred, depth + 1); if (r !== undefined) return r; } return undefined; }
  if (typeof o !== "object") return undefined;
  for (const k of Object.keys(o)) { if (pred(k, o[k])) return o[k]; const r = deepFind(o[k], pred, depth + 1); if (r !== undefined) return r; }
  return undefined;
}
const pick = (o, ...keys) => { for (const k of keys) { if (o && o[k] != null && o[k] !== "") return o[k]; } return undefined; };
const ci = (o, key) => { if (!isObj(o)) return undefined; const k = Object.keys(o).find((x) => x.toLowerCase() === key.toLowerCase()); return k === undefined ? undefined : o[k]; };
const asText = (v) => (v == null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v));

/** Memory-friendly line iterator: no split() of the whole text into an array. */
export function* iterLines(text) {
  const s = str(text);
  let i = s.charCodeAt(0) === 0xfeff ? 1 : 0;
  const n = s.length;
  while (i < n) {
    let j = s.indexOf("\n", i);
    if (j < 0) j = n;
    const line = s.charCodeAt(j - 1) === 13 ? s.slice(i, j - 1) : s.slice(i, j);
    yield { line, offset: j };
    i = j + 1;
  }
}

// ---------------------------------------------------------------------------
// Platform detection
// ---------------------------------------------------------------------------
const AWS_CSV_KEYS = ["eventname", "eventsource", "useridentity", "eventtime"];
const AZ_LA_KEYS = ["timegenerated", "operationnamevalue", "caller"];
const M365_KEYS = ["auditdata"];
const normH = (h) => low(h).replace(/\[[^\]]*\]/g, "").replace(/[^a-z0-9_@]/g, "");
/** Case- and punctuation-insensitive field read ("TimeGenerated [UTC]" == "timegenerated"). */
const nget = (o, k) => { if (!o) return undefined; if (o[k] != null) return o[k]; const want = normH(k); for (const key of Object.keys(o)) if (normH(key) === want) return o[key]; return undefined; };

/** Classify one parsed record object. Returns { platform, confidence }. */
export function classifyRecord(o) {
  if (!isObj(o)) return { platform: "generic", confidence: 0 };
  const keys = new Set(Object.keys(o).map(normH));
  const has = (...ks) => ks.every((k) => keys.has(k));
  if (has("eventsource", "eventname") && (keys.has("useridentity") || keys.has("eventtime"))) return { platform: "aws", confidence: 1 };
  if (keys.has("protopayload") || (keys.has("logname") && /cloudaudit\.googleapis\.com/.test(str(o.logName)))) return { platform: "gcp", confidence: keys.has("protopayload") ? 1 : 0.8 };
  if (keys.has("auditdata") || (has("operation", "workload") && (keys.has("creationtime") || keys.has("recordtype")))) return { platform: "m365", confidence: 1 };
  if (has("operationname") && (keys.has("caller") || keys.has("eventtimestamp") || keys.has("resourceid"))) return { platform: "azure", confidence: 1 };
  if (has("operationnamevalue") || (has("timegenerated") && keys.has("caller"))) return { platform: "azure", confidence: 0.95 };
  if (has("operations", "userids")) return { platform: "m365", confidence: 0.7 };
  if (keys.has("eventname") && keys.has("awsregion")) return { platform: "aws", confidence: 0.8 };
  if (keys.has("methodname") && keys.has("servicename")) return { platform: "gcp", confidence: 0.7 };
  if (has("operation", "userid") && keys.has("clientip")) return { platform: "m365", confidence: 0.7 };
  const generic = ["timestamp", "principal", "action"].filter((k) => findColumn(Object.keys(o), COLUMNS[k])).length;
  return { platform: "generic", confidence: generic >= 3 ? 0.5 : generic === 2 ? 0.35 : 0.1 };
}

/** Classify CSV headers (exact vendor layouts first). */
export function classifyHeaders(headers) {
  const hs = (headers || []).map(normH);
  const has = (...ks) => ks.every((k) => hs.includes(k));
  if (has(...M365_KEYS)) return { platform: "m365", confidence: has("recordtype", "creationdate", "userids", "operations") ? 1 : 0.9, layout: has("userids", "operations") ? "m365-ual-csv" : "m365-purview-csv" };
  if (has(...AWS_CSV_KEYS)) return { platform: "aws", confidence: 1, layout: "aws-athena-csv" };
  if (has(...AZ_LA_KEYS)) return { platform: "azure", confidence: 1, layout: "azure-la-csv" };
  if (has("eventname", "eventsource")) return { platform: "aws", confidence: 0.8, layout: "aws-csv" };
  if (has("operationnamevalue") || has("operationname", "caller")) return { platform: "azure", confidence: 0.8, layout: "azure-csv" };
  if (has("methodname", "principalemail")) return { platform: "gcp", confidence: 0.8, layout: "gcp-csv" };
  const generic = ["timestamp", "principal", "action"].filter((k) => findColumn(headers, COLUMNS[k])).length;
  return { platform: "generic", confidence: generic >= 3 ? 0.5 : generic === 2 ? 0.35 : 0.1, layout: "generic-csv" };
}

// ---------------------------------------------------------------------------
// Normalisers (one per platform). Each returns a normalised event or null.
// ---------------------------------------------------------------------------
const AWS_TARGET_KEYS = ["bucketName", "name", "trailName", "userName", "roleName", "groupName", "policyArn", "policyName", "keyId", "secretId", "functionName", "instanceId", "instancesSet", "groupId", "snapshotId", "imageId", "dBInstanceIdentifier", "dBSnapshotIdentifier", "detectorId", "logGroupName", "alarmNames", "clusterName", "tableName", "topicArn", "queueUrl", "stackName", "domainName", "repositoryName", "fileSystemId", "volumeId", "vpcId", "subnetId", "flowLogIds", "resourceArn", "resourceId", "targetId", "accountId"];
const AWS_UA_CLASS = (ua) => {
  const u = low(ua);
  if (!u) return "unknown";
  if (/console\.amazonaws\.com|signin\.amazonaws\.com|aws internal|cloudformation\.amazonaws\.com/.test(u)) return "console";
  if (/^aws-cli|aws-cli\//.test(u)) return "cli";
  if (/boto|botocore|aws-sdk|aws-sdk-|python-requests|go-http-client|okhttp|java\/|axios|curl|powershell|aws-powershell/.test(u)) return "sdk";
  if (/mozilla|chrome|safari|edge|firefox/.test(u)) return "browser";
  return "other";
};

function awsPrincipal(u) {
  const ui = new Proxy(u || {}, { get: (o, k) => (typeof k === "string" ? nget(o, k) : undefined) });
  const type = str(ui.type);
  const arn = str(ui.arn);
  if (type === "Root") return { principal: "root@" + str(ui.accountId), type: "Root" };
  if (type === "IAMUser") return { principal: str(ui.userName) || arn.split("/").pop() || str(ui.principalId), type: "IAMUser" };
  if (type === "AssumedRole") {
    const sc = nget(u, "sessionContext");
    const issuer = isObj(sc) && isObj(nget(sc, "sessionIssuer")) ? nget(sc, "sessionIssuer") : {};
    const role = str(nget(issuer, "userName")) || (arn.includes(":assumed-role/") ? arn.split(":assumed-role/")[1].split("/")[0] : "");
    const session = arn.includes(":assumed-role/") ? arn.split(":assumed-role/")[1].split("/").slice(1).join("/") : "";
    return { principal: role ? "role/" + role + (session ? "/" + session : "") : arn || str(ui.principalId), type: "AssumedRole" };
  }
  if (type === "FederatedUser") return { principal: arn.split(":federated-user/")[1] || str(ui.principalId), type: "FederatedUser" };
  if (type === "AWSService") return { principal: str(ui.invokedBy) || "aws-service", type: "AWSService" };
  if (type === "AWSAccount") return { principal: "account:" + str(ui.accountId || ui.principalId), type: "AWSAccount" };
  if (type === "SAMLUser" || type === "WebIdentityUser") return { principal: str(ui.userName) || str(ui.principalId), type };
  if (type === "IdentityCenterUser") return { principal: str(nget(nget(u, "onBehalfOf"), "userId")) || str(ui.principalId), type };
  return { principal: str(ui.userName) || arn || str(ui.principalId) || "unknown", type: type || "unknown" };
}

function awsTarget(req, res, name) {
  if (!isObj(req)) return "";
  for (const k of AWS_TARGET_KEYS) {
    const v = ci(req, k);
    if (v == null) continue;
    if (typeof v === "string" || typeof v === "number") return str(v);
    if (isObj(v) && Array.isArray(v.items) && v.items.length) { const it = v.items[0]; return str(it.instanceId || it.groupId || it.resourceId || it.name || asText(it)); }
    if (Array.isArray(v) && v.length) return str(v[0]);
  }
  return "";
}

export function normalizeAws(o, i) {
  const ui = isObj(o.userIdentity) ? o.userIdentity : parseAthenaStruct(o.userIdentity || o.useridentity) || {};
  // Athena lower-cases everything; accept both spellings
  const g = (k) => pick(o, k, k.toLowerCase());
  const ts = parseTs(g("eventTime"));
  const req = jsonField(g("requestParameters")) || parseAthenaStruct(g("requestParameters")) || (isObj(g("requestParameters")) ? g("requestParameters") : null);
  const res = jsonField(g("responseElements")) || parseAthenaStruct(g("responseElements")) || (isObj(g("responseElements")) ? g("responseElements") : null);
  const add = jsonField(g("additionalEventData")) || parseAthenaStruct(g("additionalEventData")) || (isObj(g("additionalEventData")) ? g("additionalEventData") : null);
  const p = awsPrincipal(ui);
  const sc = isObj(nget(ui, "sessionContext")) ? nget(ui, "sessionContext") : null;
  const attrs = sc && isObj(nget(sc, "attributes")) ? nget(sc, "attributes") : null;
  let mfa = null;
  if (attrs && nget(attrs, "mfaAuthenticated") != null) mfa = low(nget(attrs, "mfaAuthenticated")) === "true";
  if (add && nget(add, "MFAUsed") != null) mfa = low(nget(add, "MFAUsed")) === "yes";
  const errorCode = str(g("errorCode"));
  const action = str(g("eventName"));
  let status = errorCode ? "failure" : "success";
  if (action === "ConsoleLogin" && res && low(ci(res, "ConsoleLogin")) === "failure") status = "failure";
  const ro = g("readOnly");
  const ev = {
    i, ts, platform: "aws",
    account: str(g("recipientAccountId") || nget(ui, "accountId") || ""),
    principal: p.principal, principalType: p.type, principalId: str(nget(ui, "arn") || nget(ui, "principalId") || ""),
    callerAccount: str(nget(ui, "accountId") || ""),
    action, service: str(g("eventSource")).replace(/\.amazonaws\.com$/, ""),
    region: str(g("awsRegion")), ip: cleanIp(g("sourceIPAddress")), ua: str(g("userAgent")),
    status, error: errorCode || (status === "failure" ? "ConsoleLogin Failure" : ""), errorMessage: str(g("errorMessage")),
    target: awsTarget(req, res, action), mfa,
    readOnly: ro === true || low(ro) === "true" ? true : ro === false || low(ro) === "false" ? false : null,
    logType: str(g("eventType") || "AwsApiCall"), req, res, add, raw: -1,
  };
  if (!ev.account && ev.callerAccount) ev.account = ev.callerAccount;
  return ev;
}

const AZ_STATUS = (v) => { const s = low(v); return /succeeded|success|accept|start|ok/.test(s) ? (/fail/.test(s) ? "failure" : "success") : /fail|error|denied|forbidden|unauthorized/.test(s) ? "failure" : "other"; };
const azSubscription = (rid) => { const m = /\/subscriptions\/([0-9a-f-]{36})/i.exec(str(rid)); return m ? m[1].toLowerCase() : ""; };

export function normalizeAzure(o, i) {
  const g = (k) => { const v = nget(o, k); return v === "" ? undefined : v; };
  const op = g("operationName");
  const action = isObj(op) ? str(op.value) : str(g("OperationNameValue") || op);
  const status = g("status");
  const statusText = isObj(status) ? str(status.value) : str(g("ActivityStatusValue") || status);
  const http = isObj(g("httpRequest")) ? g("httpRequest") : jsonField(g("HTTPRequest")) || {};
  const claims = isObj(g("claims")) ? g("claims") : jsonField(g("Claims")) || {};
  const auth = isObj(g("authorization")) ? g("authorization") : jsonField(g("Authorization")) || {};
  const props = isObj(g("properties")) ? g("properties") : jsonField(g("Properties")) || jsonField(g("Properties_d")) || {};
  // Activity Log puts the request body as a JSON string inside properties
  const body = jsonField(ci(props, "requestbody")) || jsonField(ci(props, "requestBody"));
  const caller = str(g("caller") || ci(claims, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn") || ci(claims, "appid") || "");
  const idtyp = low(ci(claims, "idtyp"));
  const principalType = idtyp === "app" || (!idtyp && isGuid(caller)) ? "ServicePrincipal" : idtyp === "user" || /@/.test(caller) ? "User" : caller ? "Unknown" : "Unknown";
  const resourceId = str(g("resourceId") || g("_ResourceId") || auth.scope || "");
  const ev = {
    i, ts: parseTs(g("eventTimestamp") || g("TimeGenerated") || g("submissionTimestamp")), platform: "azure",
    account: azSubscription(resourceId) || str(g("subscriptionId") || g("SubscriptionId") || ""),
    principal: caller || "unknown", principalType, principalId: str(ci(claims, "http://schemas.microsoft.com/identity/claims/objectidentifier") || ""),
    action, service: action.split("/")[0], region: str(g("location") || ""),
    ip: cleanIp(ci(http, "clientIpAddress") || g("CallerIpAddress") || g("callerIpAddress")), ua: "",
    status: AZ_STATUS(statusText), error: AZ_STATUS(statusText) === "failure" ? statusText || str(g("subStatus") || "") : "", errorMessage: str(isObj(g("subStatus")) ? g("subStatus").value : g("subStatus") || ""),
    target: resourceId, mfa: null, readOnly: /\/read$|\/list|\/get/i.test(action) ? true : /\/(write|delete|action)$/i.test(action) ? false : null,
    logType: str(g("category") && isObj(g("category")) ? g("category").value : g("Category") || g("category") || "Administrative"),
    req: body || (Object.keys(props).length ? props : null), res: null, add: { authorizationAction: str(auth.action || ""), authorizationScope: str(auth.scope || ""), resourceGroup: str(g("resourceGroupName") || g("ResourceGroup") || ""), correlationId: str(g("correlationId") || g("CorrelationId") || "") }, raw: -1,
  };
  return ev;
}

export function normalizeGcp(o, i) {
  const pp = isObj(o.protoPayload) ? o.protoPayload : jsonField(o.protoPayload) || {};
  const auth = isObj(pp.authenticationInfo) ? pp.authenticationInfo : {};
  const meta = isObj(pp.requestMetadata) ? pp.requestMetadata : {};
  const st = isObj(pp.status) ? pp.status : {};
  const res = isObj(o.resource) ? o.resource : {};
  const labels = isObj(res.labels) ? res.labels : {};
  const principal = str(auth.principalEmail || (isObj(auth.thirdPartyPrincipal) ? "third-party" : "") || pick(o, "principalEmail") || "unknown");
  const logName = str(o.logName || "");
  const logType = /%2Fdata_access|\/data_access/.test(logName) ? "data_access" : /system_event/.test(logName) ? "system_event" : /policy/.test(logName) ? "policy" : "activity";
  const authz = Array.isArray(pp.authorizationInfo) ? pp.authorizationInfo : [];
  const denied = authz.length > 0 && authz.every((a) => a && a.granted === false);
  const code = st.code == null ? 0 : Number(st.code);
  const action = str(pp.methodName || pick(o, "methodName") || "");
  const ev = {
    i, ts: parseTs(o.timestamp || o.receiveTimestamp), platform: "gcp",
    account: str(labels.project_id || labels.organization_id || labels.folder_id || (isObj(pp.resourceLocation) ? "" : "") || ""),
    principal, principalType: /gserviceaccount\.com$/.test(principal) ? "ServiceAccount" : principal.includes("@") ? "User" : "Unknown", principalId: str(auth.principalSubject || ""),
    action, service: str(pp.serviceName || pick(o, "serviceName") || ""),
    region: str(labels.location || labels.zone || labels.region || ""),
    ip: cleanIp(meta.callerIp), ua: str(meta.callerSuppliedUserAgent || ""),
    status: code !== 0 || denied ? "failure" : "success", error: code !== 0 ? "status.code " + code : denied ? "PERMISSION_DENIED" : "", errorMessage: str(st.message || ""),
    target: str(pp.resourceName || ""), mfa: null, readOnly: /\.(get|list|aggregatedList|testIamPermissions|getIamPolicy)$|\.ListLogEntries$/i.test(action) ? true : logType === "activity" ? false : null,
    logType, req: isObj(pp.request) ? pp.request : null, res: isObj(pp.response) ? pp.response : null,
    add: { permissions: authz.map((a) => str(a && a.permission)).filter(Boolean).sort(), granted: !denied, serviceData: isObj(pp.serviceData) ? pp.serviceData : (isObj(pp.metadata) ? pp.metadata : null), severity: str(o.severity || ""), resourceType: str(res.type || "") }, raw: -1,
  };
  return ev;
}

// null-proto: UserType comes from the record, so a value like "constructor" must
// fall through to str(typeNum), not resolve to a native Object.prototype member.
const M365_USER_TYPE = Object.assign(Object.create(null), { 0: "Regular", 1: "Reserved", 2: "Admin", 3: "DcAdmin", 4: "System", 5: "Application", 6: "ServicePrincipal", 7: "CustomPolicy", 8: "SystemPolicy" });
const M365_STATUS = (v) => { const s = low(v); if (!s) return "success"; return /^(succeeded|success|true|partiallysucceeded|ok)$/.test(s) ? "success" : /fail|false|denied/.test(s) ? "failure" : "other"; };

export function normalizeM365(o, i) {
  // o is either a CSV row ({RecordType, CreationDate, UserIds, Operations, AuditData}) or an AuditData object
  let ad = isObj(o.AuditData) ? o.AuditData : jsonField(o.AuditData || o.auditdata);
  if (!ad && ("Operation" in o || "Workload" in o)) ad = o;
  if (!ad) ad = {};
  const params = Array.isArray(ad.Parameters) ? Object.fromEntries(ad.Parameters.filter((p) => p && p.Name != null).map((p) => [str(p.Name), p.Value])) : (isObj(ad.Parameters) ? ad.Parameters : {});
  const principal = str(ad.UserId || o.UserIds || ad.UserKey || "unknown");
  const typeNum = ad.UserType;
  const principalType = typeNum == null ? (/#ext#/i.test(principal) ? "Guest" : principal.includes("@") ? "Regular" : "Unknown") : (M365_USER_TYPE[typeNum] || str(typeNum));
  const action = str(ad.Operation || o.Operations || "");
  const result = str(ad.ResultStatus || ad.ResultStatusDetail || "");
  const ev = {
    i, ts: parseTs(ad.CreationTime || nget(o, "CreationDate")), platform: "m365",
    account: str(ad.OrganizationId || ""),
    principal, principalType, principalId: str(ad.UserKey || ""),
    action, service: str(ad.Workload || o.RecordType || ""), region: "",
    ip: cleanIp(ad.ClientIP || ad.ClientIPAddress || ad.ActorIpAddress), ua: str(ad.ClientInfoString || ad.UserAgent || (isObj(ad.ExtendedProperties) ? "" : "") || ""),
    status: M365_STATUS(result), error: M365_STATUS(result) === "failure" ? result : "", errorMessage: str(ad.LogonError || ""),
    target: str(ad.ObjectId || ad.TargetUserOrGroupName || (Array.isArray(ad.Target) && ad.Target[0] ? ad.Target[0].ID : "") || ""), mfa: null,
    readOnly: /^(UserLoggedIn|MailItemsAccessed|FileAccessed|FilePreviewed|SearchQueryPerformed|Get-|Search-)/.test(action) ? true : false,
    logType: str(ad.RecordType != null ? ad.RecordType : o.RecordType || ""),
    req: Object.keys(params).length ? params : null, res: null,
    add: { modified: Array.isArray(ad.ModifiedProperties) ? ad.ModifiedProperties : null, extended: Array.isArray(ad.ExtendedProperties) ? Object.fromEntries(ad.ExtendedProperties.filter((p) => p && p.Name).map((p) => [str(p.Name), p.Value])) : null, actor: Array.isArray(ad.Actor) ? ad.Actor.map((a) => str(a && a.ID)) : null, targets: Array.isArray(ad.Target) ? ad.Target.map((t) => str(t && t.ID)) : null, workload: str(ad.Workload || ""), operationCount: ad.OperationCount != null ? Number(ad.OperationCount) : null, folders: Array.isArray(ad.Folders) ? ad.Folders.length : null, sharingType: str(ad.SharingType || ""), eventData: str(ad.EventData || ""), appAccessContext: isObj(ad.AppAccessContext) ? ad.AppAccessContext : null, siteUrl: str(ad.SiteUrl || ""), sourceFileName: str(ad.SourceFileName || ""), targetUser: str(ad.TargetUserOrGroupName || ""), targetType: ad.TargetUserOrGroupType != null ? str(ad.TargetUserOrGroupType) : "" }, raw: -1,
  };
  return ev;
}

export function normalizeGeneric(o, i, cols) {
  const get = (k) => (cols[k] ? o[cols[k]] : undefined);
  const statusRaw = str(get("status"));
  const ev = {
    i, ts: parseTs(get("timestamp")), platform: "generic",
    account: str(get("account") || ""), principal: str(get("principal") || "unknown"), principalType: "Unknown", principalId: "",
    action: str(get("action") || ""), service: str(get("service") || ""), region: str(get("region") || ""),
    ip: cleanIp(get("ip")), ua: str(get("userAgent") || ""),
    status: !statusRaw ? "success" : /fail|denied|error|unauthori|forbidden|false/i.test(statusRaw) ? "failure" : "success", error: /fail|denied|error|unauthori|forbidden/i.test(statusRaw) ? statusRaw : "", errorMessage: "",
    target: str(get("target") || ""), mfa: null, readOnly: null, logType: "", req: null, res: null, add: null, raw: -1,
  };
  return ev;
}

/** Normalise one record of a known platform. */
export function normalizeRecord(o, platform, i, cols) {
  switch (platform) {
    case "aws": return normalizeAws(o, i);
    case "azure": return normalizeAzure(o, i);
    case "gcp": return normalizeGcp(o, i);
    case "m365": return normalizeM365(o, i);
    default: return normalizeGeneric(o, i, cols || {});
  }
}

// ---------------------------------------------------------------------------
// parseInput: files -> dataset (streams NDJSON / CSV; JSON arrays are parsed whole)
// ---------------------------------------------------------------------------
function genericColumns(headers, overrides) {
  const cols = {};
  for (const k of Object.keys(COLUMNS)) {
    const o = overrides && overrides[k];
    if (o && headers.includes(o)) { cols[k] = o; continue; }
    const h = findColumn(headers, COLUMNS[k]);
    if (h) cols[k] = h;
  }
  return cols;
}

/**
 * Parse text or files into a dataset.
 * @param {string|{name,text}|{name,bytes}|Array} input
 * @param {{ columns?: object, rawBudgetBytes?: number }} [opts]
 * @param {{ progress?: Function }} [ctx]
 * @returns {{ platform, platforms, files, events, raw, stats, skipped }}
 */
export function parseInput(input, opts = {}, ctx) {
  const files = Array.isArray(input) ? input : [typeof input === "string" ? { name: "input", text: input } : (input || { name: "input", text: "" })];
  const events = [], raw = [], fileInfos = [], skipped = [];
  const perPlatform = {};
  const budget = Number.isFinite(opts.rawBudgetBytes) ? opts.rawBudgetBytes : DEFAULTS.rawBudgetBytes;
  let rawBytes = 0, rawDropped = 0, idx = 0, invalid = 0;
  const totalBytes = files.reduce((n, f) => n + (f.bytes ? f.bytes.length : str(f.text).length), 0) || 1;
  let doneBytes = 0;
  const progress = (off, label) => { if (ctx && ctx.progress) ctx.progress(doneBytes + off, totalBytes, label); };

  const keep = (o, ev) => {
    if (!ev) return;
    if (!Number.isFinite(ev.ts)) { invalid++; return; }
    ev.i = idx;
    const s = JSON.stringify(o);
    if (rawBytes + s.length <= budget) { ev.raw = raw.length; raw.push(s); rawBytes += s.length; } else rawDropped++;
    events.push(ev); idx++;
    perPlatform[ev.platform] = (perPlatform[ev.platform] || 0) + 1;
  };

  for (const f of files) {
    const name = str(f.name || "input");
    let text = f.text != null ? (typeof f.text === "function" ? f.text() : str(f.text)) : decodeText(f.bytes || "");
    // Windows PowerShell 5.1 Export-Csv without -NoTypeInformation writes "#TYPE <class>" first
    if (/^\uFEFF?#TYPE /.test(text)) text = text.slice(text.indexOf("\n") + 1);
    const size = text.length;
    const info = { name, bytes: size, format: "unknown", platform: "generic", confidence: 0, records: 0, headers: [], layout: "" };
    fileInfos.push(info);
    if (!text.trim()) { info.format = "empty"; skipped.push({ check: "file:" + name, reason: "empty file" }); doneBytes += size; continue; }
    const sn = sniff(text);
    info.format = sn.format;
    let count = 0;
    const tick = (off) => { if (++count % 1000 === 0) progress(off, name + ": " + count + " records"); };
    try {
      if (sn.format === "csv" || sn.format === "tsv") {
        let headers = null, cols = null, cls = null, avgRow = 0;
        for (const row of iterCsv(text, { delimiter: sn.delimiter })) {
          if (!headers) {
            headers = Object.keys(row); info.headers = headers;
            cls = classifyHeaders(headers); info.platform = cls.platform; info.confidence = cls.confidence; info.layout = cls.layout;
            if (cls.platform === "generic") cols = genericColumns(headers, opts.columns);
            avgRow = Math.max(40, JSON.stringify(row).length);
          }
          const ev = normalizeRecord(row, cls.platform, 0, cols);
          keep(row, ev); info.records++;
          tick(Math.min(size, (count + 1) * avgRow));
        }
        if (!headers) { skipped.push({ check: "file:" + name, reason: "CSV without rows" }); }
        else if (cls.platform === "generic" && (!cols.timestamp || !cols.principal || !cols.action)) {
          skipped.push({ check: "file:" + name, reason: "generic CSV: map the timestamp, principal and action columns (missing: " + ["timestamp", "principal", "action"].filter((k) => !cols[k]).join(", ") + ")" });
        }
      } else if (sn.format === "ndjson") {
        let cls = null, cols = null;
        for (const { line, offset } of iterLines(text)) {
          if (!line.trim()) continue;
          let o;
          try { o = JSON.parse(line); } catch (_) { invalid++; continue; }
          if (!isObj(o)) { invalid++; continue; }
          // a digest file may be NDJSON of {"Records":[...]} wrappers too
          if (Array.isArray(o.Records)) { for (const r of o.Records) { keep(r, normalizeRecord(r, "aws", 0)); info.records++; } info.platform = "aws"; info.confidence = 1; info.layout = "aws-digest-ndjson"; continue; }
          if (!cls) { cls = classifyRecord(o); info.platform = cls.platform; info.confidence = cls.confidence; info.layout = cls.platform + "-ndjson"; info.headers = Object.keys(o); if (cls.platform === "generic") cols = genericColumns(info.headers, opts.columns); }
          keep(o, normalizeRecord(o, cls.platform, 0, cols)); info.records++;
          tick(offset);
        }
      } else if (sn.format === "json") {
        const list = iterJson(text);
        const recs = Array.isArray(list) ? list : [];
        let cls = null, cols = null;
        for (let k = 0; k < recs.length; k++) {
          const o = recs[k];
          if (!isObj(o)) { invalid++; continue; }
          if (!cls) { cls = classifyRecord(o); info.platform = cls.platform; info.confidence = cls.confidence; info.layout = cls.platform + "-json"; info.headers = Object.keys(o); if (cls.platform === "generic") cols = genericColumns(info.headers, opts.columns); }
          keep(o, normalizeRecord(o, cls.platform, 0, cols)); info.records++;
          tick(Math.round(size * (k + 1) / recs.length));
        }
        if (!recs.length) skipped.push({ check: "file:" + name, reason: "JSON without an array of records" });
      } else {
        skipped.push({ check: "file:" + name, reason: "unsupported format (" + sn.format + "); expected CloudTrail / Activity Log / Audit Log JSON, NDJSON or CSV" });
      }
    } catch (e) {
      skipped.push({ check: "file:" + name, reason: "parse error: " + str(e && e.message || e) });
    }
    doneBytes += size;
    progress(0, name + ": " + info.records + " records");
  }
  if (invalid) skipped.push({ check: "records", reason: invalid + " record(s) without a parseable timestamp or JSON were ignored" });
  if (rawDropped) skipped.push({ check: "raw-records", reason: rawDropped + " raw record(s) not retained for the evidence drawer (over the " + Math.round(budget / 1048576) + " MB raw budget); normalised fields are still analysed" });

  // Sort once: (ts, insertion). Re-index so i is the sorted position; raw keeps the original pointer.
  events.sort(byTs);
  events.forEach((e, k) => { e.i = k; });
  const plats = Object.keys(perPlatform).sort();
  const platform = plats.length === 0 ? "none" : plats.length === 1 ? plats[0] : "mixed";
  const stats = {
    total: events.length, perPlatform: sortKeys(perPlatform),
    firstTs: events.length ? iso(events[0].ts) : "", lastTs: events.length ? iso(events[events.length - 1].ts) : "",
    files: fileInfos.length, invalid, rawRetained: raw.length,
  };
  return { platform, platforms: sortKeys(perPlatform), files: fileInfos, events, raw, stats, skipped };
}


// ---------------------------------------------------------------------------
// Rule helpers
// ---------------------------------------------------------------------------
/** Decode an IAM policy document delivered as an object, a JSON string or URL-encoded JSON. */
export function policyDoc(v) {
  if (v == null) return null;
  if (isObj(v)) return v;
  const s = str(v).trim();
  if (!s) return null;
  try { return JSON.parse(s); } catch (_) {}
  try { return JSON.parse(decodeURIComponent(s)); } catch (_) {}
  return null;
}
const statements = (doc) => (doc && doc.Statement ? (Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement]) : []);
const listOf = (v) => (v == null ? [] : Array.isArray(v) ? v : [v]);
/** true when an Allow statement names Principal "*" (or {"AWS":"*"}). */
export function publicPrincipal(stmt) {
  if (!isObj(stmt) || low(stmt.Effect) !== "allow") return false;
  const p = stmt.Principal;
  if (p === "*") return true;
  if (isObj(p)) for (const k of Object.keys(p)) if (listOf(p[k]).some((x) => str(x) === "*")) return true;
  return false;
}
const publicPrincipalInPolicy = (v) => statements(policyDoc(v)).some(publicPrincipal);
/** Allow Action "*" on Resource "*". */
export function adminStatement(doc) {
  return statements(doc).some((st) => isObj(st) && low(st.Effect) === "allow" && listOf(st.Action).some((a) => str(a) === "*" || str(a) === "*:*") && listOf(st.Resource).some((r) => str(r) === "*"));
}
/** AWS account ids named by Principal.AWS in a trust policy. */
export function trustAccounts(doc) {
  const out = new Set();
  let wildcard = false;
  for (const st of statements(doc)) {
    if (!isObj(st) || low(st.Effect) !== "allow") continue;
    const p = st.Principal;
    if (p === "*") { wildcard = true; continue; }
    if (!isObj(p)) continue;
    for (const v of listOf(p.AWS)) {
      const s = str(v);
      if (s === "*") { wildcard = true; continue; }
      const m = /^(\d{12})$/.exec(s) || /arn:aws[^:]*:(?:iam|sts)::(\d{12}):/.exec(s);
      if (m) out.add(m[1]);
    }
  }
  return { accounts: Array.from(out).sort(), wildcard };
}
const sgRules = (req) => {
  if (!isObj(req)) return [];
  const out = [];
  const perms = ci(req, "ipPermissions");
  const items = isObj(perms) && Array.isArray(perms.items) ? perms.items : [];
  for (const it of items) {
    const v4 = isObj(it.ipRanges) && Array.isArray(it.ipRanges.items) ? it.ipRanges.items.map((r) => str(r.cidrIp)) : [];
    const v6 = isObj(it.ipv6Ranges) && Array.isArray(it.ipv6Ranges.items) ? it.ipv6Ranges.items.map((r) => str(r.cidrIpv6)) : [];
    out.push({ proto: str(it.ipProtocol), from: it.fromPort, to: it.toPort, cidrs: v4.concat(v6) });
  }
  if (!items.length && req.cidrIp) out.push({ proto: str(req.ipProtocol), from: req.fromPort, to: req.toPort, cidrs: [str(req.cidrIp)] });
  return out;
};
const OPEN_CIDR = (c) => c === "0.0.0.0/0" || c === "::/0";
const ADMIN_PORTS = [22, 3389];
const portHit = (from, to, p) => (from == null || to == null ? false : Number(from) === -1 || (Number(from) <= p && Number(to) >= p));
const rangeHasAdmin = (p) => p === "*" || p === "22" || p === "3389" || (/^(\d+)-(\d+)$/.test(p) && ADMIN_PORTS.some((ap) => ap >= Number(p.split("-")[0]) && ap <= Number(p.split("-")[1])));
const PRIV_AZ_ROLES = { "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner", "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor", "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator", "f58310d9-a9f6-439a-9e8d-f62e7b41a168": "Role Based Access Control Administrator" };
const GCP_PRIV_ROLES = ["roles/owner", "roles/editor", "roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountKeyAdmin", "roles/iam.serviceAccountAdmin", "roles/resourcemanager.organizationAdmin", "roles/iam.securityAdmin", "roles/resourcemanager.projectIamAdmin"];
const PUBLIC_MEMBERS = ["allusers", "allauthenticatedusers"];
const SUSPICIOUS_UA = /python-requests|kali|parrot|sqlmap|nikto|masscan|nmap|zgrab|pacu|scoutsuite|prowler|cloudfox|rclone|curl\//i;

/** Bindings added by a GCP SetIamPolicy: [{ role, member }] from serviceData.policyDelta, else request.policy. */
export function gcpBindingAdds(ev) {
  const out = [];
  const sd = ev.add && ev.add.serviceData;
  const delta = sd && isObj(sd.policyDelta) && Array.isArray(sd.policyDelta.bindingDeltas) ? sd.policyDelta.bindingDeltas : null;
  if (delta) { for (const d of delta) if (d && low(d.action) === "add") out.push({ role: str(d.role), member: str(d.member) }); return out; }
  const pol = ev.req && isObj(ev.req.policy) ? ev.req.policy : null;
  if (pol && Array.isArray(pol.bindings)) for (const b of pol.bindings) for (const m of listOf(b && b.members)) out.push({ role: str(b.role), member: str(m) });
  return out;
}
const azProps = (ev) => { const b = ev.req; if (!isObj(b)) return {}; const p = ci(b, "properties"); return isObj(p) ? p : b; };
const azRole = (ev) => { const g = str(ci(azProps(ev), "roleDefinitionId")).split("/").pop().toLowerCase(); return { id: g, name: PRIV_AZ_ROLES[g] || "" }; };
const azScope = (ev) => str(ci(azProps(ev), "scope") || (ev.add && ev.add.authorizationScope) || ev.target);
export const azScopeLevel = (scope) => (/\/resourcegroups\//i.test(scope) ? (/\/providers\//i.test(scope) ? "resource" : "resourceGroup") : /^\/subscriptions\/[^/]+\/?$/i.test(scope) ? "subscription" : /managementgroups/i.test(scope) ? "managementGroup" : "other");
const truthy = (v) => v === true || /^(true|yes|1|\$true)$/i.test(str(v).trim());
const last = (s, n = 1) => str(s).split("/").slice(-n).join("/");

const isMutating = (e) => e.readOnly === false || (e.readOnly == null && !/^(Describe|List|Get|Head|Lookup|Search|Query|BatchGet|Decrypt|GenerateDataKey)/.test(e.action) && !/\/read$|\/list|\.get$|\.list$/i.test(e.action));
const isHuman = (e) => !/^(AWSService|AWSAccount|ServicePrincipal|ServiceAccount|Application|System|SystemPolicy|CustomPolicy|DcAdmin|Reserved)$/.test(e.principalType);

// ---------------------------------------------------------------------------
// Rule factory. `mitre` ids become MITRE controls; `controls` adds benchmark refs.
// match(e, o) -> false | { severity, note, iocs?, confidence? }   (one event)
// aggregate { where, group, n, windowMin }                            (sliding window per key)
// run(events, o) -> [{ key, events, count, note, severity?, confidence?, iocs? }]  (sequence rules)
// ---------------------------------------------------------------------------
let RULE_ORDER = 0;
function rule(id, platform, severity, confidence, category, title, o) {
  const mitre = o.mitre || [];
  return Object.freeze({
    id, platform, severity, confidence, category, title, mitre: Object.freeze(mitre.slice()),
    controls: Object.freeze(mitre.map((t) => ({ framework: "MITRE", id: t })).concat(o.controls || [])),
    description: o.description, recommendation: o.recommendation,
    needs: Object.freeze((o.needs || []).slice()), ops: Object.freeze((o.ops || []).slice()), source: o.source || "",
    kind: o.aggregate ? "aggregate" : o.run ? "sequence" : "match",
    match: o.match || null, aggregate: o.aggregate || null, run: o.run || null,
    groupBy: o.groupBy || "principal", requires: o.requires || null, order: RULE_ORDER++,
  });
}
const hit = (severity, note, extra) => Object.assign({ severity, note }, extra || {});
const inSet = (v, arr) => arr.includes(str(v));
const CIS_AWS = (id) => ({ framework: "CIS AWS Foundations", id });
const CIS_AZ = (id) => ({ framework: "CIS Azure Foundations", id });
const CIS_GCP = (id) => ({ framework: "CIS GCP Foundations", id });
const CIS_M365 = (id) => ({ framework: "CIS Microsoft 365", id });
const SCUBA = (id) => ({ framework: "CISA SCuBA", id });
const NIST = (id) => ({ framework: "NIST-800-53", id });
const ISO = (id) => ({ framework: "ISO27001", id });
const SOC2 = (id) => ({ framework: "SOC2", id });
const acct = (a) => ({ type: "aws-account-id", value: a });

// ---------------------------------------------------------------------------
// RULES
// ---------------------------------------------------------------------------
export const RULES = [
  // ---------------- AWS: identity ----------------
  rule("aws-root-console-login", "aws", "critical", "confirmed", "identity", "Root account console sign-in", {
    mitre: ["T1078.004"], controls: [CIS_AWS("1.7"), NIST("AC-6(5)"), ISO("A.8.2"), SOC2("CC6.1")],
    description: "The AWS account root user signed in to the console. Root should never be used for daily work; any root sign-in must be confirmed with the account owner.",
    recommendation: "Confirm the sign-in with the account owner. If unexpected, rotate the root password, enrol hardware MFA, delete root access keys and review every call that followed.",
    ops: ["ConsoleLogin"], source: "signin.amazonaws.com", needs: ["principalType"],
    match: (e) => e.action === "ConsoleLogin" && e.principalType === "Root" && e.status === "success" && hit("critical", e.mfa === false ? "root sign-in WITHOUT MFA from " + e.ip : "root sign-in from " + e.ip + (e.mfa ? " (MFA used)" : "")),
  }),
  rule("aws-root-api", "aws", "high", "likely", "identity", "Root account API activity", {
    mitre: ["T1078.004"], controls: [CIS_AWS("1.4"), CIS_AWS("1.7"), NIST("AC-6(5)"), SOC2("CC6.1")],
    description: "API calls were made with root credentials. Root access keys or a root session doing API work is a strong misuse or compromise indicator.",
    recommendation: "Delete root access keys (CIS AWS 1.4), confirm every call with the owner and move the work to an IAM role.",
    needs: ["principalType"],
    match: (e) => e.principalType === "Root" && e.action !== "ConsoleLogin" && e.service !== "signin" && (isMutating(e) ? hit("high", "root called " + e.action) : hit("medium", "root read " + e.action)),
  }),
  rule("aws-console-login-nomfa", "aws", "high", "confirmed", "identity", "Console sign-in without MFA", {
    mitre: ["T1078.004"], controls: [CIS_AWS("1.10"), NIST("IA-2(1)"), ISO("A.8.5"), SOC2("CC6.1")],
    description: "A successful IAM-user console sign-in reported MFAUsed = No. Federated (SAML) sign-ins carry MFA at the IdP and are excluded; root sign-ins are reported by the root rule.",
    recommendation: "Require MFA for every IAM user with a console password, or move console access to IAM Identity Center / SAML federation.",
    ops: ["ConsoleLogin"], source: "signin.amazonaws.com", needs: ["mfa"],
    match: (e) => e.action === "ConsoleLogin" && e.status === "success" && e.mfa === false && e.principalType !== "Root" && !(e.add && (nget(e.add, "SamlProviderArn"))) && hit("high", "MFAUsed = No for " + e.principal),
  }),
  rule("aws-console-fail-burst", "aws", "high", "likely", "identity", "Console sign-in failure burst from one IP", {
    mitre: ["T1110"], controls: [NIST("AC-7"), ISO("A.8.5"), SOC2("CC6.1")],
    description: "Repeated failed console sign-ins from one source IP inside the window: password guessing or credential stuffing. A success from the same IP within the window after the burst raises it to critical.",
    recommendation: "Block the source IP, reset passwords and enforce MFA for the targeted users, and review any session that succeeded.",
    ops: ["ConsoleLogin"], source: "signin.amazonaws.com", needs: ["ip"], groupBy: "ip",
    run: (events, o) => {
      const fails = events.filter((e) => e.platform === "aws" && e.action === "ConsoleLogin" && e.status === "failure" && e.ip);
      return windows(fails, (e) => e.ip, o.consoleFailN, o.consoleFailWindowMin).map((g) => {
        const lastTs = g.events[g.events.length - 1].ts;
        const ok = events.find((e) => e.platform === "aws" && e.action === "ConsoleLogin" && e.status === "success" && e.ip === g.key && e.ts >= lastTs && e.ts <= lastTs + o.consoleFailWindowMin * MIN);
        return { key: g.key, events: ok ? g.events.concat([ok]) : g.events, count: g.total + (ok ? 1 : 0), severity: ok ? "critical" : "high", confidence: ok ? "confirmed" : "likely",
          note: g.peak + " failures within " + o.consoleFailWindowMin + " min from " + g.key + (ok ? "; then a SUCCESSFUL sign-in as " + ok.principal + " at " + iso(ok.ts) : ""), iocs: [{ type: "ip", value: g.key }] };
      });
    },
  }),
  rule("aws-iam-create-user", "aws", "high", "likely", "identity", "IAM user created", {
    mitre: ["T1136.003"], controls: [NIST("AC-2"), ISO("A.5.16"), SOC2("CC6.2")],
    description: "CreateUser added an IAM user. New users are a classic persistence step; they should only come from the identity pipeline.",
    recommendation: "Match each new user to a change ticket; delete unrequested users and review what the creating principal did next.",
    ops: ["CreateUser"], source: "iam.amazonaws.com",
    match: (e) => e.action === "CreateUser" && e.service === "iam" && e.status === "success" && hit("high", e.principal + " created user " + str(e.req && ci(e.req, "userName"))),
  }),
  rule("aws-iam-access-key-other", "aws", "high", "likely", "identity", "Access key created for a different user", {
    mitre: ["T1098.001"], controls: [CIS_AWS("1.13"), NIST("AC-2"), ISO("A.5.17"), SOC2("CC6.2")],
    description: "CreateAccessKey named a user other than the caller. Minting keys for someone else gives a long-lived credential that survives the caller's session.",
    recommendation: "Deactivate the key (its id is in the IOC export), confirm with both users and review everything the key did.",
    ops: ["CreateAccessKey"], source: "iam.amazonaws.com",
    match: (e) => {
      if (e.action !== "CreateAccessKey" || e.status !== "success") return false;
      const target = str(e.req && ci(e.req, "userName"));
      const ak = e.res && ci(e.res, "accessKey");
      const keyId = str(isObj(ak) ? ci(ak, "accessKeyId") : "");
      const iocs = keyId ? [{ type: "aws-access-key-id", value: keyId }] : [];
      if (!target || target === e.principal || e.principal.endsWith("/" + target)) return false;
      return hit("high", e.principal + " created access key " + (keyId || "(id not in export)") + " for user " + target, { iocs });
    },
  }),
  rule("aws-iam-login-profile-other", "aws", "high", "likely", "identity", "Console password set for another user", {
    mitre: ["T1098"], controls: [NIST("AC-2"), ISO("A.5.17"), SOC2("CC6.2")],
    description: "CreateLoginProfile / UpdateLoginProfile gave a console password to a user other than the caller: a second way in.",
    recommendation: "Reset the target user's password, require MFA and confirm the request with its owner.",
    ops: ["CreateLoginProfile", "UpdateLoginProfile"], source: "iam.amazonaws.com",
    match: (e) => { if (!inSet(e.action, ["CreateLoginProfile", "UpdateLoginProfile"]) || e.status !== "success") return false; const t = str(e.req && ci(e.req, "userName")); return !!t && t !== e.principal && !e.principal.endsWith("/" + t) && hit("high", e.action + " for " + t); },
  }),
  rule("aws-iam-admin-policy", "aws", "critical", "confirmed", "identity", "Administrator or wildcard policy granted", {
    mitre: ["T1098.003"], controls: [CIS_AWS("1.16"), NIST("AC-6"), ISO("A.8.2"), SOC2("CC6.3")],
    description: "AdministratorAccess / IAMFullAccess / PowerUserAccess was attached, or a policy allowing Action \"*\" on Resource \"*\" was written. Full admin grants are the fastest privilege escalation.",
    recommendation: "Detach the policy, scope permissions to the task and review the principal that granted it.",
    ops: ["AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy", "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy", "CreatePolicy", "CreatePolicyVersion"], source: "iam.amazonaws.com",
    match: (e) => {
      if (e.status !== "success" || !e.req) return false;
      const who = str(ci(e.req, "userName") || ci(e.req, "roleName") || ci(e.req, "groupName") || ci(e.req, "policyName"));
      if (/^Attach(User|Role|Group)Policy$/.test(e.action)) { const arn = str(ci(e.req, "policyArn")); return /:policy\/(AdministratorAccess|IAMFullAccess|PowerUserAccess)$/.test(arn) && hit(/PowerUserAccess/.test(arn) ? "high" : "critical", last(arn) + " attached to " + who); }
      if (/^Put(User|Role|Group)Policy$|^CreatePolicy(Version)?$/.test(e.action)) return adminStatement(policyDoc(ci(e.req, "policyDocument"))) && hit("critical", "policy on " + who + " allows Action * on Resource *");
      return false;
    },
  }),
  rule("aws-iam-trust-policy", "aws", "high", "likely", "identity", "Role trust policy changed", {
    mitre: ["T1098.003"], controls: [NIST("AC-6"), ISO("A.8.2"), SOC2("CC6.3")],
    description: "UpdateAssumeRolePolicy rewrote who may assume a role. A foreign account or wildcard principal is a quiet, durable backdoor.",
    recommendation: "Diff the trust policy against the approved one; remove external or wildcard principals.",
    ops: ["UpdateAssumeRolePolicy"], source: "iam.amazonaws.com",
    match: (e, o) => {
      if (e.action !== "UpdateAssumeRolePolicy" || e.status !== "success") return false;
      const role = str(e.req && ci(e.req, "roleName"));
      const t = trustAccounts(policyDoc(e.req && ci(e.req, "policyDocument")));
      const foreign = t.accounts.filter((a) => a !== e.account && !o.trustedAccounts.includes(a));
      if (t.wildcard) return hit("critical", "trust policy of " + role + " allows Principal *");
      if (foreign.length) return hit("critical", "trust of " + role + " extended to external account(s) " + foreign.join(", "), { iocs: foreign.map(acct) });
      return hit("medium", "trust policy of " + role + " changed (same-account or trusted principals)");
    },
  }),
  rule("aws-iam-role-external-trust", "aws", "high", "likely", "identity", "Role created trusting an external account", {
    mitre: ["T1098.003", "T1199"], controls: [NIST("AC-6"), ISO("A.5.19"), SOC2("CC6.3")],
    description: "CreateRole with a trust policy naming an AWS account that is neither this account nor in Trusted accounts. With Trusted accounts blank every foreign account is reported for review.",
    recommendation: "Verify the external account with its owner; if unknown delete the role and search for AssumeRole calls against it.",
    ops: ["CreateRole"], source: "iam.amazonaws.com",
    match: (e, o) => {
      if (e.action !== "CreateRole" || e.status !== "success") return false;
      const role = str(e.req && ci(e.req, "roleName"));
      const t = trustAccounts(policyDoc(e.req && ci(e.req, "assumeRolePolicyDocument")));
      if (t.wildcard) return hit("critical", "role " + role + " trusts Principal *");
      const foreign = t.accounts.filter((a) => a !== e.account && !o.trustedAccounts.includes(a));
      return foreign.length > 0 && hit(o.trustedAccounts.length ? "high" : "medium", "role " + role + " trusts account(s) " + foreign.join(", "), { iocs: foreign.map(acct), confidence: o.trustedAccounts.length ? "likely" : "review" });
    },
  }),
  rule("aws-assume-role-untrusted", "aws", "medium", "review", "identity", "AssumeRole from an account outside the trusted list", {
    mitre: ["T1078.004", "T1199"], controls: [NIST("AC-3"), ISO("A.5.19"), SOC2("CC6.1")],
    description: "A principal from another AWS account assumed a role here. Cross-account access is expected only from accounts listed under Trusted accounts; with the list blank every foreign account is reported for review.",
    recommendation: "List your organisation's account ids under Trusted accounts, then confirm each remaining caller account with its owner.",
    ops: ["AssumeRole"], source: "sts.amazonaws.com", needs: ["callerAccount"], groupBy: "callerAccount",
    match: (e, o) => e.action === "AssumeRole" && e.status === "success" && e.callerAccount && e.account && e.callerAccount !== e.account && !o.trustedAccounts.includes(e.callerAccount) && e.principalType !== "AWSService" &&
      hit(o.trustedAccounts.length ? "high" : "medium", "account " + e.callerAccount + " assumed " + str(e.req && ci(e.req, "roleArn")), { iocs: [acct(e.callerAccount)], confidence: o.trustedAccounts.length ? "likely" : "review" }),
  }),
  rule("aws-mfa-removed", "aws", "high", "confirmed", "identity", "MFA device deactivated or deleted", {
    mitre: ["T1556.006"], controls: [CIS_AWS("1.10"), NIST("IA-2(1)"), SOC2("CC6.1")],
    description: "DeactivateMFADevice / DeleteVirtualMFADevice removed a second factor from an IAM user.",
    recommendation: "Confirm the device change with the user, re-enrol MFA and check sign-ins between removal and re-enrolment.",
    ops: ["DeactivateMFADevice", "DeleteVirtualMFADevice"], source: "iam.amazonaws.com",
    match: (e) => inSet(e.action, ["DeactivateMFADevice", "DeleteVirtualMFADevice"]) && e.status === "success" && hit("high", e.action + " " + str(e.req && (ci(e.req, "userName") || ci(e.req, "serialNumber")))),
  }),
  rule("aws-password-policy", "aws", "medium", "confirmed", "identity", "Account password policy changed or deleted", {
    mitre: ["T1562"], controls: [CIS_AWS("1.8"), CIS_AWS("1.9"), NIST("IA-5(1)")],
    description: "UpdateAccountPasswordPolicy / DeleteAccountPasswordPolicy changed the IAM password rules.",
    recommendation: "Restore the policy (minimum length 14, reuse prevention 24) and confirm the change was approved.",
    ops: ["UpdateAccountPasswordPolicy", "DeleteAccountPasswordPolicy"], source: "iam.amazonaws.com",
    match: (e) => inSet(e.action, ["UpdateAccountPasswordPolicy", "DeleteAccountPasswordPolicy"]) && e.status === "success" && hit(e.action === "DeleteAccountPasswordPolicy" ? "high" : "medium", e.action),
  }),
  rule("aws-idp-trust", "aws", "high", "likely", "identity", "Identity provider trust created or changed", {
    mitre: ["T1484.002"], controls: [NIST("IA-8"), ISO("A.5.16"), SOC2("CC6.1")],
    description: "CreateSAMLProvider / UpdateSAMLProvider / CreateOpenIDConnectProvider adds a federation trust: whoever controls that IdP can mint sessions.",
    recommendation: "Verify provider metadata and issuer with the identity team; remove unknown providers.",
    ops: ["CreateSAMLProvider", "UpdateSAMLProvider", "CreateOpenIDConnectProvider", "AddClientIDToOpenIDConnectProvider"], source: "iam.amazonaws.com",
    match: (e) => inSet(e.action, ["CreateSAMLProvider", "UpdateSAMLProvider", "CreateOpenIDConnectProvider", "AddClientIDToOpenIDConnectProvider"]) && e.status === "success" && hit("high", e.action),
  }),
  rule("aws-org-detach", "aws", "high", "confirmed", "logging", "Account left the organisation or SCP removed", {
    mitre: ["T1562"], controls: [NIST("CM-5"), ISO("A.5.15"), SOC2("CC6.3")],
    description: "LeaveOrganization / RemoveAccountFromOrganization detaches an account from SCPs and central logging; DetachPolicy / DeletePolicy removes a guardrail.",
    recommendation: "Re-invite the account or re-attach the SCP and confirm the actor.",
    ops: ["LeaveOrganization", "RemoveAccountFromOrganization", "DetachPolicy", "DeletePolicy"], source: "organizations.amazonaws.com",
    match: (e) => e.service === "organizations" && inSet(e.action, ["LeaveOrganization", "RemoveAccountFromOrganization", "DetachPolicy", "DeletePolicy"]) && e.status === "success" && hit(/Policy$/.test(e.action) ? "medium" : "high", e.action),
  }),

  // ---------------- AWS: logging / defence evasion ----------------
  rule("aws-trail-tamper", "aws", "critical", "confirmed", "logging", "CloudTrail stopped, deleted or narrowed", {
    mitre: ["T1562.008"], controls: [CIS_AWS("3.1"), NIST("AU-9"), ISO("A.8.15"), SOC2("CC7.2")],
    description: "StopLogging, DeleteTrail, UpdateTrail or PutEventSelectors changed what CloudTrail records. Attackers do this first so later actions leave no trace.",
    recommendation: "Re-enable the trail (multi-region, management events), deny cloudtrail:StopLogging/DeleteTrail with an SCP and treat the actor as compromised until proven otherwise.",
    ops: ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"], source: "cloudtrail.amazonaws.com", groupBy: "target",
    match: (e) => e.service === "cloudtrail" && inSet(e.action, ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"]) && e.status === "success" && hit(e.action === "UpdateTrail" || e.action === "PutEventSelectors" ? "high" : "critical", e.action + " " + last(e.target) + " by " + e.principal),
  }),
  rule("aws-trail-created", "aws", "info", "review", "logging", "New CloudTrail trail created", {
    mitre: [], controls: [CIS_AWS("3.1"), NIST("AU-2")],
    description: "CreateTrail: normal for the platform team; occasionally an attacker creates a trail delivering to a bucket they control.",
    recommendation: "Confirm the destination bucket belongs to your organisation.",
    ops: ["CreateTrail"], source: "cloudtrail.amazonaws.com",
    match: (e) => e.service === "cloudtrail" && e.action === "CreateTrail" && e.status === "success" && hit("info", "trail " + last(e.target) + " to s3://" + str(e.req && ci(e.req, "s3BucketName"))),
  }),
  rule("aws-flowlogs-delete", "aws", "high", "confirmed", "logging", "VPC flow logs deleted", {
    mitre: ["T1562.008"], controls: [CIS_AWS("3 Logging"), NIST("AU-12"), SOC2("CC7.2")],
    description: "DeleteFlowLogs removed network telemetry for a VPC.",
    recommendation: "Recreate the flow logs and confirm the change was planned.",
    ops: ["DeleteFlowLogs"], source: "ec2.amazonaws.com",
    match: (e) => e.action === "DeleteFlowLogs" && e.status === "success" && hit("high", "DeleteFlowLogs " + e.target),
  }),
  rule("aws-config-disable", "aws", "high", "confirmed", "logging", "AWS Config recorder stopped or deleted", {
    mitre: ["T1562.008"], controls: [CIS_AWS("3.3"), NIST("CM-8"), SOC2("CC7.1")],
    description: "StopConfigurationRecorder / DeleteConfigurationRecorder / DeleteDeliveryChannel blinds configuration-drift detection.",
    recommendation: "Restart the recorder and review changes made while it was off.",
    ops: ["StopConfigurationRecorder", "DeleteConfigurationRecorder", "DeleteDeliveryChannel"], source: "config.amazonaws.com",
    match: (e) => e.service === "config" && inSet(e.action, ["StopConfigurationRecorder", "DeleteConfigurationRecorder", "DeleteDeliveryChannel"]) && e.status === "success" && hit("high", e.action),
  }),
  rule("aws-guardduty-disable", "aws", "high", "confirmed", "logging", "GuardDuty detector disabled or trusted IP list changed", {
    mitre: ["T1562.001"], controls: [NIST("SI-4"), ISO("A.8.16"), SOC2("CC7.2")],
    description: "DeleteDetector, UpdateDetector with enable=false, member disassociation or a new trusted IP set (CreateIPSet / UpdateIPSet) weakens threat detection.",
    recommendation: "Re-enable the detector, review the IP set contents and confirm with the security team.",
    ops: ["DeleteDetector", "UpdateDetector", "DeleteMembers", "DisassociateFromMasterAccount", "DisassociateFromAdministratorAccount", "CreateIPSet", "UpdateIPSet", "DeletePublishingDestination"], source: "guardduty.amazonaws.com",
    match: (e) => e.service === "guardduty" && e.status === "success" && (inSet(e.action, ["DeleteDetector", "DeleteMembers", "DisassociateFromMasterAccount", "DisassociateFromAdministratorAccount", "DeletePublishingDestination"]) ? hit("high", e.action) : e.action === "UpdateDetector" && e.req && (ci(e.req, "enable") === false || low(ci(e.req, "enable")) === "false") ? hit("high", "UpdateDetector enable=false") : inSet(e.action, ["CreateIPSet", "UpdateIPSet"]) ? hit("medium", e.action + " (trusted IP list)") : false),
  }),
  rule("aws-cloudwatch-tamper", "aws", "medium", "confirmed", "logging", "CloudWatch alarms or log groups removed", {
    mitre: ["T1562.008"], controls: [CIS_AWS("4 Monitoring"), NIST("AU-9"), SOC2("CC7.2")],
    description: "DeleteAlarms, DisableAlarmActions, DeleteLogGroup, DeleteLogStream, DeleteSubscriptionFilter or a 1-day retention removes alerting and history.",
    recommendation: "Restore alarms and log groups; review who removed them and what happened in the gap.",
    ops: ["DeleteAlarms", "DisableAlarmActions", "DeleteLogGroup", "DeleteLogStream", "DeleteSubscriptionFilter", "PutRetentionPolicy"], source: "logs.amazonaws.com",
    match: (e) => (e.service === "monitoring" || e.service === "logs") && e.status === "success" && (inSet(e.action, ["DeleteAlarms", "DisableAlarmActions", "DeleteLogGroup", "DeleteLogStream", "DeleteSubscriptionFilter"]) ? hit(e.action === "DeleteLogGroup" ? "high" : "medium", e.action + " " + e.target) : e.action === "PutRetentionPolicy" && Number(ci(e.req || {}, "retentionInDays")) <= 1 ? hit("medium", "log retention set to 1 day on " + e.target) : false),
  }),
  rule("aws-waf-disable", "aws", "medium", "confirmed", "network", "WAF web ACL deleted or detached", {
    mitre: ["T1562.007"], controls: [NIST("SC-7"), SOC2("CC6.6")],
    description: "DeleteWebACL / DisassociateWebACL removed edge protection from an application.",
    recommendation: "Re-associate the web ACL and confirm the change.",
    ops: ["DeleteWebACL", "DisassociateWebACL"], source: "wafv2.amazonaws.com",
    match: (e) => /^waf/.test(e.service) && inSet(e.action, ["DeleteWebACL", "DisassociateWebACL"]) && e.status === "success" && hit("medium", e.action),
  }),
  rule("aws-kms-destroy", "aws", "high", "confirmed", "data", "KMS key disabled, scheduled for deletion or made public", {
    mitre: ["T1485"], controls: [NIST("SC-12"), ISO("A.8.24"), SOC2("CC6.7")],
    description: "DisableKey / ScheduleKeyDeletion makes every object encrypted under the key unreadable once the waiting period ends (a ransomware precursor); a key policy with Principal * opens the key to anyone.",
    recommendation: "CancelKeyDeletion and re-enable unless the retirement was approved; inventory what the key protects.",
    ops: ["DisableKey", "ScheduleKeyDeletion", "PutKeyPolicy"], source: "kms.amazonaws.com", groupBy: "target",
    match: (e) => e.service === "kms" && e.status === "success" && (inSet(e.action, ["DisableKey", "ScheduleKeyDeletion"]) ? hit(e.action === "ScheduleKeyDeletion" ? "critical" : "high", e.action + " " + e.target) : e.action === "PutKeyPolicy" && publicPrincipalInPolicy(e.req && ci(e.req, "policy")) ? hit("critical", "key policy grants Principal * on " + e.target) : false),
  }),
  rule("aws-ebs-encryption-off", "aws", "medium", "confirmed", "data", "EBS encryption-by-default disabled", {
    mitre: ["T1562"], controls: [CIS_AWS("2.2.1"), NIST("SC-28")],
    description: "DisableEbsEncryptionByDefault turns off automatic volume encryption for the region.",
    recommendation: "Re-enable it and confirm the change.",
    ops: ["DisableEbsEncryptionByDefault"], source: "ec2.amazonaws.com",
    match: (e) => e.action === "DisableEbsEncryptionByDefault" && e.status === "success" && hit("medium", "DisableEbsEncryptionByDefault in " + e.region),
  }),

  // ---------------- AWS: data / network exposure ----------------
  rule("aws-s3-public", "aws", "critical", "confirmed", "data", "S3 bucket opened to the public", {
    mitre: ["T1530"], controls: [CIS_AWS("2.1.4"), NIST("AC-3"), ISO("A.5.15"), SOC2("CC6.1")],
    description: "A bucket policy or ACL granted access to everyone (Principal *, AllUsers / AuthenticatedUsers), or Block Public Access was removed or relaxed.",
    recommendation: "Restore account-level Block Public Access, remove the public statement or grant and review access logs for the exposure window.",
    ops: ["PutBucketPolicy", "PutBucketAcl", "PutObjectAcl", "DeletePublicAccessBlock", "PutPublicAccessBlock", "DeleteAccountPublicAccessBlock", "PutAccountPublicAccessBlock"], source: "s3.amazonaws.com", groupBy: "target",
    match: (e) => {
      if (e.service !== "s3" || e.status !== "success") return false;
      if (e.action === "PutBucketPolicy") return publicPrincipalInPolicy(e.req && ci(e.req, "bucketPolicy")) && hit("critical", "bucket policy with Principal * on " + e.target);
      if (e.action === "PutBucketAcl" || e.action === "PutObjectAcl") {
        const acl = listOf(e.req && ci(e.req, "x-amz-acl")).map(low);
        const pub = acl.some((a) => /public|authenticated-read/.test(a)) || /AllUsers|AuthenticatedUsers/.test(JSON.stringify(e.req || {}));
        return pub && hit(e.action === "PutObjectAcl" ? "high" : "critical", "public ACL on " + e.target);
      }
      if (/^Delete(Account)?PublicAccessBlock$/.test(e.action)) return hit("high", e.action + " " + (e.target || "(account)"));
      if (/^Put(Account)?PublicAccessBlock$/.test(e.action)) { const c = e.req && ci(e.req, "PublicAccessBlockConfiguration"); return isObj(c) && Object.keys(c).filter((k) => k !== "xmlns").some((k) => c[k] === false || low(c[k]) === "false") && hit("high", e.action + " with a setting turned off on " + (e.target || "(account)")); }
      return false;
    },
  }),
  rule("aws-s3-destroy", "aws", "medium", "likely", "data", "S3 bucket deleted, versioning suspended or objects set to expire", {
    mitre: ["T1485"], controls: [NIST("CP-9"), ISO("A.8.13"), SOC2("A1.2")],
    description: "DeleteBucket, versioning suspended, or a lifecycle rule expiring objects after one day destroys data quietly.",
    recommendation: "Confirm with the owning team, restore from versions or backups and enable MFA delete on critical buckets.",
    ops: ["DeleteBucket", "PutBucketLifecycle", "PutBucketLifecycleConfiguration", "PutBucketVersioning"], source: "s3.amazonaws.com", groupBy: "target",
    match: (e) => {
      if (e.service !== "s3" || e.status !== "success") return false;
      if (e.action === "DeleteBucket") return hit("medium", "DeleteBucket " + e.target);
      if (/^PutBucketLifecycle/.test(e.action)) { const d = deepFind(e.req, (k, v) => /^Days$/i.test(k) && Number(v) <= 1); return d !== undefined && hit("high", "lifecycle expires objects after " + d + " day on " + e.target); }
      if (e.action === "PutBucketVersioning") return low(deepFind(e.req, (k) => /^Status$/i.test(k))) === "suspended" && hit("medium", "versioning suspended on " + e.target);
      return false;
    },
  }),
  rule("aws-sg-open-ingress", "aws", "high", "confirmed", "network", "Security group opened to the internet", {
    mitre: ["T1562.007"], controls: [CIS_AWS("5.2"), CIS_AWS("5.3"), NIST("SC-7"), SOC2("CC6.6")],
    description: "AuthorizeSecurityGroupIngress added a rule from 0.0.0.0/0 or ::/0. SSH / RDP or all ports open to the world is critical.",
    recommendation: "Revoke the rule; restrict to known CIDRs or use SSM Session Manager.",
    ops: ["AuthorizeSecurityGroupIngress"], source: "ec2.amazonaws.com", groupBy: "target",
    match: (e) => {
      if (e.action !== "AuthorizeSecurityGroupIngress" || e.status !== "success") return false;
      const open = sgRules(e.req).filter((r) => r.cidrs.some(OPEN_CIDR));
      if (!open.length) return false;
      const admin = open.some((r) => r.proto === "-1" || ADMIN_PORTS.some((p) => portHit(r.from, r.to, p)));
      return hit(admin ? "critical" : "high", "ingress from " + uniq(open.flatMap((r) => r.cidrs.filter(OPEN_CIDR))).join(",") + " ports " + open.map((r) => (r.proto === "-1" ? "all" : r.from === r.to ? str(r.from) : r.from + "-" + r.to)).join(",") + " on " + e.target);
    },
  }),
  rule("aws-secrets-burst", "aws", "high", "likely", "data", "Secrets / parameter read burst by one principal", {
    mitre: ["T1552.005", "T1552"], controls: [NIST("AC-6(9)"), ISO("A.8.12"), SOC2("CC6.1")],
    description: "GetSecretValue / BatchGetSecretValue / GetParameter(s) calls by one principal reached the threshold inside the window: bulk credential harvesting.",
    recommendation: "Confirm the workload, rotate every secret read in the window and alarm on the per-principal GetSecretValue rate.",
    ops: ["GetSecretValue", "BatchGetSecretValue", "GetParameter", "GetParameters", "GetParametersByPath"], source: "secretsmanager.amazonaws.com",
    aggregate: { where: (e) => e.platform === "aws" && inSet(e.action, ["GetSecretValue", "BatchGetSecretValue", "GetParameter", "GetParameters", "GetParametersByPath"]), n: "secretsBurstN", windowMin: "secretsBurstWindowMin" },
  }),
  rule("aws-get-password-data", "aws", "medium", "likely", "data", "Windows instance password retrieved", {
    mitre: ["T1552"], controls: [NIST("IA-5"), SOC2("CC6.1")],
    description: "GetPasswordData fetched the initial administrator password of an EC2 Windows instance.",
    recommendation: "Confirm the operator and rotate the local administrator password.",
    ops: ["GetPasswordData"], source: "ec2.amazonaws.com",
    match: (e) => e.action === "GetPasswordData" && e.status === "success" && hit("medium", "GetPasswordData " + e.target),
  }),
  rule("aws-ec2-userdata", "aws", "high", "likely", "execution", "Instance user data modified", {
    mitre: ["T1059"], controls: [NIST("CM-5"), ISO("A.8.9"), SOC2("CC8.1")],
    description: "ModifyInstanceAttribute changed userData: a script that runs as root / SYSTEM at the next boot.",
    recommendation: "Decode and review the new user data, confirm with the owner and snapshot the instance before rebooting.",
    ops: ["ModifyInstanceAttribute"], source: "ec2.amazonaws.com",
    match: (e) => e.action === "ModifyInstanceAttribute" && e.status === "success" && e.req && (ci(e.req, "userData") != null || low(ci(e.req, "attribute")) === "userdata") && hit("high", "userData changed on " + e.target),
  }),
  rule("aws-remote-access", "aws", "low", "review", "execution", "Interactive access to an instance (SSH key push, SSM command or session)", {
    mitre: ["T1021.004", "T1059"], controls: [NIST("AC-17"), ISO("A.8.20"), SOC2("CC6.6")],
    description: "SendSSHPublicKey, SendSerialConsoleSSHPublicKey, EnableSerialConsoleAccess, SendCommand or StartSession gave hands-on access to an instance.",
    recommendation: "Confirm the operator and instance; restrict ec2-instance-connect and ssm:StartSession / SendCommand by tag.",
    ops: ["SendSSHPublicKey", "SendSerialConsoleSSHPublicKey", "EnableSerialConsoleAccess", "SendCommand", "StartSession"], source: "ssm.amazonaws.com",
    match: (e) => inSet(e.action, ["SendSSHPublicKey", "SendSerialConsoleSSHPublicKey", "EnableSerialConsoleAccess", "SendCommand", "StartSession"]) && e.status === "success" && hit(e.action === "SendCommand" || e.action === "EnableSerialConsoleAccess" ? "medium" : "low", e.action + " " + (e.target || "")),
  }),
  rule("aws-run-instances-new-region", "aws", "medium", "likely", "recon", "Instances launched in a never-seen region", {
    mitre: ["T1578.002", "T1496"], controls: [NIST("CM-8"), SOC2("CC6.6")],
    description: "RunInstances in a region where the account had no earlier activity in this dataset (the account needs at least the baseline number of prior events). Crypto-miners favour quiet regions.",
    recommendation: "Confirm the launch, terminate unknown instances and deny unused regions with an SCP.",
    ops: ["RunInstances"], source: "ec2.amazonaws.com", needs: ["region"], groupBy: "account",
    run: (events, o) => {
      const seen = new Map(), count = new Map(), out = new Map();
      for (const e of events) {
        if (e.platform !== "aws" || !e.region || !e.account) continue;
        const k = e.account, n = count.get(k) || 0, regs = seen.get(k) || new Set();
        if (e.action === "RunInstances" && e.status === "success" && n >= o.baselineMinEvents && !regs.has(e.region)) {
          const key = k + " " + e.region;
          const g = out.get(key) || { key, events: [], note: "account " + k + " first used " + e.region + " for RunInstances after " + n + " events in " + Array.from(regs).sort().join(", ") };
          g.events.push(e); out.set(key, g);
          continue; // keep the region unseen so every launch in the burst is evidence
        }
        if (e.action !== "RunInstances" || !out.has(k + " " + e.region)) regs.add(e.region);
        seen.set(k, regs); count.set(k, n + 1);
      }
      return Array.from(out.values()).map((g) => ({ ...g, count: g.events.length }));
    },
  }),
  rule("aws-gpu-instances", "aws", "medium", "review", "recon", "GPU / accelerated instance types launched", {
    mitre: ["T1496"], controls: [NIST("CM-8"), SOC2("CC6.6")],
    description: "RunInstances requested a p*, g*, inf*, trn* or dl* instance type: the hardware crypto-miners want.",
    recommendation: "Confirm an ML / graphics workload exists; otherwise terminate and investigate the principal.",
    ops: ["RunInstances"], source: "ec2.amazonaws.com",
    match: (e) => { if (e.action !== "RunInstances" || e.status !== "success") return false; const t = str(e.req && (ci(e.req, "instanceType") || deepFind(e.req, (k) => k === "instanceType"))); return /^(p[2-5]|g[3-6]|inf[12]|trn[12]|dl[12])[a-z0-9-]*\./i.test(t) && hit("medium", "instanceType " + t + " in " + e.region); },
  }),
  rule("aws-snapshot-share", "aws", "critical", "confirmed", "exfil", "Snapshot or AMI shared with another account", {
    mitre: ["T1537"], controls: [NIST("AC-3"), ISO("A.8.12"), SOC2("CC6.7")],
    description: "ModifySnapshotAttribute / ModifyImageAttribute / ModifyDBSnapshotAttribute added a foreign account or 'all': the disk image can now be copied out.",
    recommendation: "Remove the permission, confirm the account id with its owner and treat the data as exposed.",
    ops: ["ModifySnapshotAttribute", "ModifyImageAttribute", "ModifyDBSnapshotAttribute", "ModifyDBClusterSnapshotAttribute"], source: "ec2.amazonaws.com", groupBy: "target",
    match: (e, o) => {
      if (e.status !== "success" || !e.req) return false;
      let adds = [];
      if (e.action === "ModifySnapshotAttribute" || e.action === "ModifyImageAttribute") {
        const perm = ci(e.req, e.action === "ModifySnapshotAttribute" ? "createVolumePermission" : "launchPermission");
        const items = isObj(perm) && isObj(perm.add) && Array.isArray(perm.add.items) ? perm.add.items : [];
        adds = items.map((it) => (it.group ? "group:" + it.group : str(it.userId)));
      } else if (/^ModifyDB(Cluster)?SnapshotAttribute$/.test(e.action)) adds = listOf(ci(e.req, "valuesToAdd")).map(str);
      else return false;
      const foreign = adds.filter((a) => a && a !== e.account && !o.trustedAccounts.includes(a));
      if (!foreign.length) return false;
      const pub = foreign.some((a) => /^(group:)?all$/i.test(a));
      return hit(pub ? "critical" : "high", e.action + " " + e.target + " shared with " + foreign.join(", "), { iocs: foreign.filter((a) => /^\d{12}$/.test(a)).map(acct) });
    },
  }),
  rule("aws-rds-public", "aws", "high", "confirmed", "network", "RDS database made publicly accessible", {
    mitre: ["T1190"], controls: [CIS_AWS("2.3.3"), NIST("SC-7"), SOC2("CC6.6")],
    description: "ModifyDBInstance / CreateDBInstance / RestoreDBInstanceFromDBSnapshot with publiclyAccessible = true.",
    recommendation: "Set PubliclyAccessible to false and keep databases in private subnets.",
    ops: ["ModifyDBInstance", "CreateDBInstance", "RestoreDBInstanceFromDBSnapshot"], source: "rds.amazonaws.com", groupBy: "target",
    match: (e) => e.service === "rds" && e.status === "success" && e.req && truthy(ci(e.req, "publiclyAccessible")) && hit("high", e.action + " publiclyAccessible=true on " + e.target),
  }),
  rule("aws-lambda-unusual-principal", "aws", "info", "review", "execution", "Lambda code changed by a principal with no Lambda history", {
    mitre: ["T1648"], controls: [NIST("CM-5"), SOC2("CC8.1")],
    description: "UpdateFunctionCode / UpdateFunctionConfiguration / CreateFunction / AddPermission by a principal whose earlier events in this dataset (at least the baseline count) never touched Lambda.",
    recommendation: "Review the function diff and restrict lambda:UpdateFunctionCode to the deployment pipeline.",
    ops: ["UpdateFunctionCode20150331v2", "UpdateFunctionConfiguration20150331v2", "CreateFunction20150331", "AddPermission20150331v2"], source: "lambda.amazonaws.com",
    run: (events, o) => {
      const hist = new Map(), out = new Map();
      for (const e of events) {
        if (e.platform !== "aws") continue;
        const n = hist.get(e.principal) || { lambda: 0, total: 0 };
        if (e.service === "lambda" && /^(UpdateFunctionCode|UpdateFunctionConfiguration|CreateFunction|AddPermission)/.test(e.action) && e.status === "success" && n.lambda === 0 && n.total >= o.baselineMinEvents) {
          const g = out.get(e.principal) || { key: e.principal, events: [], note: e.principal + " had " + n.total + " earlier events, none on Lambda, before " + e.action };
          g.events.push(e); out.set(e.principal, g);
        } else if (e.service === "lambda") n.lambda++;
        n.total++; hist.set(e.principal, n);
      }
      return Array.from(out.values()).map((g) => ({ ...g, count: g.events.length }));
    },
  }),
  rule("aws-recon-burst", "aws", "medium", "likely", "recon", "Enumeration burst (Describe / List / Get) by one principal", {
    mitre: ["T1580", "T1526", "T1087.004"], controls: [NIST("SI-4"), ISO("A.8.16"), SOC2("CC7.2")],
    description: "One principal issued many discovery calls (Describe*, List*, GetCallerIdentity, GetAccountAuthorizationDetails, GetBucketPolicy ...) inside the window: the pattern of pacu, ScoutSuite or a person mapping the account.",
    recommendation: "Confirm the scanner is yours (security tooling, IaC drift checks); otherwise revoke the session and review the principal's later calls.",
    ops: ["Describe*", "List*", "GetCallerIdentity", "GetAccountAuthorizationDetails"], source: "",
    aggregate: { where: (e) => e.platform === "aws" && /^(Describe|List|GetCallerIdentity$|GetAccountAuthorizationDetails$|GetAccountSummary$|GetBucket(Policy|Acl)$|GetUser$|GetRole$|GetPolicy|GetAccountPasswordPolicy$|LookupEvents$|SimulatePrincipalPolicy$)/.test(e.action), n: "reconBurstN", windowMin: "reconBurstWindowMin" },
  }),
  rule("aws-access-denied-burst", "aws", "medium", "likely", "identity", "AccessDenied burst by one principal", {
    mitre: ["T1078"], controls: [NIST("AC-7"), NIST("SI-4"), SOC2("CC7.2")],
    description: "Many AccessDenied / UnauthorizedOperation errors for one principal inside the window: a stolen credential probing what it can do, or broken automation worth fixing.",
    recommendation: "Review the denied calls; if the principal is a person confirm the activity, otherwise rotate the credential.",
    needs: ["error"],
    aggregate: { where: (e) => e.platform === "aws" && /AccessDenied|UnauthorizedOperation|UnauthorizedAccess|AuthorizationError|Forbidden/i.test(e.error), n: "failureBurstN", windowMin: "failureBurstWindowMin" },
  }),
  rule("aws-ua-anomaly", "aws", "medium", "likely", "identity", "Unusual user agent for the principal", {
    mitre: ["T1078.004"], controls: [NIST("SI-4"), SOC2("CC6.1")],
    description: "Root using the CLI or an SDK, a principal that only ever used the console switching to aws-cli / an SDK, or an offensive / scripted agent (python-requests, Kali, pacu, ScoutSuite, rclone, curl).",
    recommendation: "Confirm the tooling with the user. For root, delete access keys immediately.",
    needs: ["ua"],
    run: (events, o) => {
      const hist = new Map(), out = new Map();
      const add = (e, note, severity) => { const g = out.get(e.principal) || { key: e.principal, events: [], notes: [], severity }; g.events.push(e); if (!g.notes.includes(note)) g.notes.push(note); if (SEV_RANK[severity] > SEV_RANK[g.severity]) g.severity = severity; out.set(e.principal, g); };
      for (const e of events) {
        if (e.platform !== "aws" || !e.ua) continue;
        const cls = AWS_UA_CLASS(e.ua);
        const h = hist.get(e.principal) || { console: 0, other: 0 };
        if (e.principalType === "Root" && (cls === "cli" || cls === "sdk")) add(e, "root used a programmatic agent: " + e.ua.slice(0, 80), "high");
        else if (SUSPICIOUS_UA.test(e.ua)) add(e, "offensive / scripted user agent: " + e.ua.slice(0, 80), "medium");
        else if ((cls === "cli" || cls === "sdk") && h.other === 0 && h.console >= o.baselineMinEvents) add(e, "console-only for " + h.console + " events, then " + cls + ": " + e.ua.slice(0, 60), "medium");
        if (cls === "console" || cls === "browser") h.console++; else if (cls !== "unknown") h.other++;
        hist.set(e.principal, h);
      }
      return Array.from(out.values()).map((g) => ({ key: g.key, events: g.events, count: g.events.length, severity: g.severity, note: g.notes.slice(0, 3).join("; ") }));
    },
  }),

  // ---------------- Azure ----------------
  rule("az-privileged-role-assignment", "azure", "critical", "confirmed", "identity", "Privileged Azure role assigned", {
    mitre: ["T1098.003"], controls: [CIS_AZ("1 Identity and Access Management"), NIST("AC-6"), ISO("A.8.2"), SOC2("CC6.3")],
    description: "Microsoft.Authorization/roleAssignments/write granted Owner, Contributor, User Access Administrator or RBAC Administrator. At subscription or management-group scope this is control of everything below it.",
    recommendation: "Confirm the assignment through PIM / change control, prefer eligible (just-in-time) assignments and remove standing Owner grants.",
    ops: ["Microsoft.Authorization/roleAssignments/write"], source: "Administrative",
    match: (e) => {
      if (low(e.action) !== "microsoft.authorization/roleassignments/write" || e.status !== "success") return false;
      const r = azRole(e), scope = azScope(e), lvl = azScopeLevel(scope), pid = str(ci(azProps(e), "principalId"));
      if (!r.name) return false;
      return hit(lvl === "subscription" || lvl === "managementGroup" ? "critical" : "high", r.name + " assigned at " + lvl + " scope" + (pid ? " to principal " + pid : "") + " by " + e.principal, { iocs: pid ? [{ type: "azure-principal-id", value: pid }] : [] });
    },
  }),
  rule("az-custom-role-wildcard", "azure", "high", "confirmed", "identity", "Custom role with wildcard actions", {
    mitre: ["T1098.003"], controls: [CIS_AZ("1.23"), NIST("AC-6"), SOC2("CC6.3")],
    description: "Microsoft.Authorization/roleDefinitions/write created or changed a custom role whose actions include \"*\": a home-made Owner.",
    recommendation: "Delete the role or scope its actions (CIS Azure 1.23: no custom subscription administrator roles).",
    ops: ["Microsoft.Authorization/roleDefinitions/write"], source: "Administrative",
    match: (e) => { if (low(e.action) !== "microsoft.authorization/roledefinitions/write" || e.status !== "success") return false; const perms = listOf(ci(azProps(e), "permissions")); return perms.some((p) => isObj(p) && listOf(ci(p, "actions")).some((a) => str(a) === "*")) && hit("high", "custom role " + str(ci(azProps(e), "roleName")) + " allows \"*\""); },
  }),
  rule("az-vm-run-command", "azure", "high", "likely", "execution", "Command run on a VM through the control plane", {
    mitre: ["T1059"], controls: [NIST("AC-17"), ISO("A.8.20"), SOC2("CC6.6")],
    description: "virtualMachines/runCommand/action or a CustomScript / VMAccess extension write executes code as SYSTEM / root using only Azure permissions.",
    recommendation: "Confirm the operator and script; restrict runCommand with a custom role and alert on it.",
    ops: ["Microsoft.Compute/virtualMachines/runCommand/action", "Microsoft.Compute/virtualMachines/extensions/write"], source: "Administrative",
    match: (e) => e.status !== "failure" && (low(e.action) === "microsoft.compute/virtualmachines/runcommand/action" ? hit("high", "runCommand on " + last(e.target, 3)) : low(e.action) === "microsoft.compute/virtualmachines/extensions/write" && /customscript|vmaccess/i.test(JSON.stringify(e.req || "") + e.target) ? hit("medium", "script / VMAccess extension on " + last(e.target, 3)) : false),
  }),
  rule("az-keyvault-access-policy", "azure", "medium", "likely", "data", "Key Vault access policy changed", {
    mitre: ["T1552"], controls: [CIS_AZ("8 Key Vault"), NIST("AC-3"), SOC2("CC6.1")],
    description: "vaults/accessPolicies/write (or a vault write carrying accessPolicies) changed who can read secrets, keys and certificates.",
    recommendation: "Diff the policy, confirm the principal added and consider Azure RBAC for Key Vault.",
    ops: ["Microsoft.KeyVault/vaults/accessPolicies/write", "Microsoft.KeyVault/vaults/write"], source: "Administrative", groupBy: "target",
    match: (e) => e.status === "success" && (low(e.action) === "microsoft.keyvault/vaults/accesspolicies/write" || (low(e.action) === "microsoft.keyvault/vaults/write" && /accesspolicies/i.test(JSON.stringify(e.req || "")))) && hit("medium", "access policy changed on vault " + str(e.target.split(/\/vaults\//i)[1] || e.target).split("/")[0]),
  }),
  rule("az-keyvault-secret-burst", "azure", "high", "likely", "data", "Key Vault secret read burst", {
    mitre: ["T1552"], controls: [NIST("AC-6(9)"), ISO("A.8.12"), SOC2("CC6.1")],
    description: "secrets/getSecret / SecretGet operations by one caller reached the threshold inside the window (needs Key Vault data-plane entries in the export).",
    recommendation: "Confirm the application, rotate the secrets read and alert on per-caller getSecret rate.",
    ops: ["Microsoft.KeyVault/vaults/secrets/getSecret/action", "SecretGet"], source: "AzureDiagnostics",
    aggregate: { where: (e) => e.platform === "azure" && /^microsoft\.keyvault\/vaults\/secrets\/(getsecret\/action|read)$|^secretget$/i.test(e.action), n: "secretsBurstN", windowMin: "secretsBurstWindowMin" },
  }),
  rule("az-nsg-open", "azure", "high", "confirmed", "network", "NSG rule allows inbound from any source", {
    mitre: ["T1562.007"], controls: [CIS_AZ("6 Networking"), NIST("SC-7"), SOC2("CC6.6")],
    description: "networkSecurityGroups/securityRules/write with source * / Internet / 0.0.0.0/0, access Allow, direction Inbound. RDP or SSH from the internet is critical.",
    recommendation: "Restrict the source to known ranges or use Azure Bastion / just-in-time VM access.",
    ops: ["Microsoft.Network/networkSecurityGroups/securityRules/write"], source: "Administrative", groupBy: "target",
    match: (e) => {
      if (!/^microsoft\.network\/networksecuritygroups\/(securityrules\/)?write$/i.test(e.action) || e.status !== "success") return false;
      const rules = [];
      const collect = (p) => { if (!isObj(p)) return; const src = listOf(ci(p, "sourceAddressPrefix")).concat(listOf(ci(p, "sourceAddressPrefixes"))).map(low); if (low(ci(p, "access")) === "allow" && low(ci(p, "direction")) === "inbound" && src.some((s) => s === "*" || s === "internet" || s === "0.0.0.0/0" || s === "any")) rules.push(listOf(ci(p, "destinationPortRange")).concat(listOf(ci(p, "destinationPortRanges"))).map(str)); };
      collect(azProps(e));
      const sr = ci(azProps(e), "securityRules"); if (Array.isArray(sr)) for (const r of sr) collect(isObj(r) ? ci(r, "properties") || r : null);
      if (!rules.length) return false;
      const ports = rules.flat();
      return hit(ports.some(rangeHasAdmin) ? "critical" : "high", "inbound Allow from any source on ports " + (ports.join(",") || "?") + " (" + last(e.target, 3) + ")");
    },
  }),
  rule("az-storage-public", "azure", "high", "confirmed", "data", "Storage account allows public blob access", {
    mitre: ["T1530"], controls: [CIS_AZ("3 Storage Accounts"), NIST("AC-3"), SOC2("CC6.1")],
    description: "storageAccounts/write with allowBlobPublicAccess = true, or a container write with publicAccess Blob / Container.",
    recommendation: "Set allowBlobPublicAccess to false and remove anonymous container access.",
    ops: ["Microsoft.Storage/storageAccounts/write", "Microsoft.Storage/storageAccounts/blobServices/containers/write"], source: "Administrative", groupBy: "target",
    match: (e) => e.status === "success" && /^microsoft\.storage\/storageaccounts\//i.test(e.action) && (truthy(ci(azProps(e), "allowBlobPublicAccess")) ? hit("high", "allowBlobPublicAccess=true on " + last(e.target)) : /^(blob|container)$/i.test(str(ci(azProps(e), "publicAccess"))) ? hit("high", "container publicAccess=" + str(ci(azProps(e), "publicAccess")) + " on " + last(e.target)) : false),
  }),
  rule("az-diagnostics-delete", "azure", "critical", "confirmed", "logging", "Diagnostic settings, log profile or activity log alert removed", {
    mitre: ["T1562.008"], controls: [CIS_AZ("5 Logging and Monitoring"), NIST("AU-9"), ISO("A.8.15"), SOC2("CC7.2")],
    description: "diagnosticSettings/delete, logProfiles/delete or activityLogAlerts/delete (or an alert disabled) stops the activity log from reaching your SIEM and alerting.",
    recommendation: "Recreate the setting, protect it with a CanNotDelete lock and review the actor.",
    ops: ["Microsoft.Insights/diagnosticSettings/delete", "Microsoft.Insights/logProfiles/delete", "Microsoft.Insights/activityLogAlerts/delete", "Microsoft.Insights/activityLogAlerts/write"], source: "Administrative",
    match: (e) => e.status === "success" && (/^microsoft\.insights\/(diagnosticsettings|activitylogalerts|logprofiles)\/delete$/i.test(e.action) ? hit("critical", e.action.split("/").slice(1).join("/") + " " + last(e.target)) : /^microsoft\.insights\/activitylogalerts\/write$/i.test(e.action) && (ci(azProps(e), "enabled") === false || low(ci(azProps(e), "enabled")) === "false") ? hit("high", "activity log alert disabled: " + last(e.target)) : false),
  }),
  rule("az-disk-export", "azure", "high", "likely", "exfil", "Disk or snapshot export URL generated", {
    mitre: ["T1005", "T1537"], controls: [NIST("AC-3"), ISO("A.8.12"), SOC2("CC6.7")],
    description: "disks/beginGetAccess/action or snapshots/beginGetAccess/action issues a SAS URL that downloads the whole VHD.",
    recommendation: "Confirm the export, revoke the SAS (endGetAccess) and treat the disk contents as copied.",
    ops: ["Microsoft.Compute/disks/beginGetAccess/action", "Microsoft.Compute/snapshots/beginGetAccess/action"], source: "Administrative",
    match: (e) => e.status !== "failure" && /^microsoft\.compute\/(disks|snapshots)\/begingetaccess\/action$/i.test(e.action) && hit("high", "export URL for " + last(e.target)),
  }),
  rule("az-resource-group-delete", "azure", "high", "confirmed", "data", "Resource group deleted", {
    mitre: ["T1485"], controls: [NIST("CP-9"), SOC2("A1.2")],
    description: "resourceGroups/delete removes every resource in the group at once.",
    recommendation: "Confirm the deletion, restore from backups and put CanNotDelete locks on production groups.",
    ops: ["Microsoft.Resources/subscriptions/resourceGroups/delete"], source: "Administrative", groupBy: "target",
    match: (e) => low(e.action) === "microsoft.resources/subscriptions/resourcegroups/delete" && e.status !== "failure" && hit("high", "resource group " + last(e.target) + " deleted"),
  }),
  rule("az-lock-delete", "azure", "medium", "likely", "data", "Resource lock removed", {
    mitre: ["T1485"], controls: [NIST("CM-5"), SOC2("CC8.1")],
    description: "locks/delete removed a CanNotDelete / ReadOnly lock: the step before destroying a protected resource.",
    recommendation: "Confirm the change and re-apply the lock.",
    ops: ["Microsoft.Authorization/locks/delete"], source: "Administrative",
    match: (e) => low(e.action) === "microsoft.authorization/locks/delete" && e.status === "success" && hit("medium", "lock removed: " + last(e.target, 3)),
  }),
  rule("az-guardrail-tamper", "azure", "medium", "confirmed", "logging", "Policy assignment deleted or Defender plan set to Free", {
    mitre: ["T1562.001"], controls: [CIS_AZ("2 Microsoft Defender"), NIST("CM-6"), SOC2("CC7.1")],
    description: "policyAssignments/delete removes a guardrail; Microsoft.Security/pricings/write with pricingTier Free turns Defender for Cloud off for a resource type.",
    recommendation: "Re-apply the assignment / plan and confirm the actor.",
    ops: ["Microsoft.Authorization/policyAssignments/delete", "Microsoft.Security/pricings/write"], source: "Administrative",
    match: (e) => e.status === "success" && (low(e.action) === "microsoft.authorization/policyassignments/delete" ? hit("medium", "policy assignment deleted: " + last(e.target)) : low(e.action) === "microsoft.security/pricings/write" && /^free$/i.test(str(ci(azProps(e), "pricingTier"))) ? hit("medium", "Defender plan set to Free: " + last(e.target)) : false),
  }),
  rule("az-sql-firewall-open", "azure", "high", "confirmed", "network", "SQL server firewall open to all addresses", {
    mitre: ["T1190"], controls: [CIS_AZ("4.1.2"), NIST("SC-7"), SOC2("CC6.6")],
    description: "Microsoft.Sql/servers/firewallRules/write with startIpAddress 0.0.0.0 and endIpAddress 255.255.255.255 (or 0.0.0.0, the 'Allow Azure services' rule).",
    recommendation: "Delete the rule and use private endpoints or explicit client ranges.",
    ops: ["Microsoft.Sql/servers/firewallRules/write"], source: "Administrative", groupBy: "target",
    match: (e) => low(e.action) === "microsoft.sql/servers/firewallrules/write" && e.status === "success" && str(ci(azProps(e), "startIpAddress")) === "0.0.0.0" && hit(str(ci(azProps(e), "endIpAddress")) === "255.255.255.255" ? "high" : "medium", "firewall rule " + str(ci(azProps(e), "startIpAddress")) + "-" + str(ci(azProps(e), "endIpAddress")) + " on " + last(e.target, 3)),
  }),
  rule("az-sp-privileged-write", "azure", "medium", "review", "identity", "Service principal performing privileged writes", {
    mitre: ["T1078.004"], controls: [NIST("AC-6"), SOC2("CC6.3")],
    description: "An application (service principal) caller wrote role assignments or definitions, Key Vault policies, NSG rules or ran VM commands. Automation does this legitimately; so does a stolen app secret.",
    recommendation: "Match the app id to a known automation identity, narrow its role and rotate its credential if unknown.",
    needs: ["principalType"], source: "Administrative",
    match: (e) => e.principalType === "ServicePrincipal" && e.status === "success" && /^microsoft\.(authorization\/(roleassignments|roledefinitions)\/write|keyvault\/vaults\/accesspolicies\/write|network\/networksecuritygroups\/securityrules\/write|compute\/virtualmachines\/runcommand\/action)$/i.test(e.action) && hit("medium", "service principal " + e.principal + ": " + e.action.split("/").slice(1).join("/")),
  }),
  rule("az-failed-burst", "azure", "medium", "likely", "identity", "Failed operations burst by one caller", {
    mitre: ["T1078"], controls: [NIST("SI-4"), SOC2("CC7.2")],
    description: "Many Failed / Forbidden operations by one caller inside the window: permission probing with a stolen identity, or broken automation.",
    recommendation: "Review the operations attempted and confirm the activity with the caller.",
    source: "Administrative",
    aggregate: { where: (e) => e.platform === "azure" && e.status === "failure", n: "failureBurstN", windowMin: "failureBurstWindowMin" },
  }),

  // ---------------- GCP ----------------
  rule("gcp-iam-privileged-binding", "gcp", "critical", "confirmed", "identity", "Privileged or public IAM binding added", {
    mitre: ["T1098.003"], controls: [CIS_GCP("1 Identity and Access Management"), NIST("AC-6"), ISO("A.8.2"), SOC2("CC6.3")],
    description: "SetIamPolicy added roles/owner, roles/editor, a service-account token / key / admin role, an IAM admin role, or a binding for allUsers / allAuthenticatedUsers.",
    recommendation: "Remove the binding, use predefined least-privilege roles and alert on bindingDeltas with these roles.",
    ops: ["SetIamPolicy"], source: "activity",
    match: (e) => {
      if (!/SetIamPolicy$/i.test(e.action) || e.status !== "success" || e.service === "storage.googleapis.com") return false;
      const adds = gcpBindingAdds(e);
      const pub = adds.filter((b) => PUBLIC_MEMBERS.includes(low(b.member)));
      const priv = adds.filter((b) => GCP_PRIV_ROLES.includes(b.role));
      if (pub.length) return hit("critical", uniq(pub.map((b) => b.member + " " + b.role)).join(", ") + " on " + e.target);
      if (!priv.length) return false;
      return hit(priv.some((b) => /roles\/(owner|resourcemanager\.organizationAdmin)$/.test(b.role)) ? "critical" : "high", uniq(priv.map((b) => b.role + " to " + b.member)).join(", ") + " on " + e.target + " by " + e.principal, { iocs: uniq(priv.map((b) => b.member)).map((m) => ({ type: "gcp-member", value: m })) });
    },
  }),
  rule("gcp-sa-key-created", "gcp", "high", "confirmed", "identity", "Service account key created", {
    mitre: ["T1098.001"], controls: [CIS_GCP("1.4"), NIST("IA-5"), ISO("A.5.17"), SOC2("CC6.2")],
    description: "CreateServiceAccountKey / UploadServiceAccountKey minted a user-managed key: a long-lived credential that leaves the platform.",
    recommendation: "Delete the key unless it is tracked, use Workload Identity or short-lived tokens and enforce iam.disableServiceAccountKeyCreation.",
    ops: ["google.iam.admin.v1.CreateServiceAccountKey", "google.iam.admin.v1.UploadServiceAccountKey"], source: "activity",
    match: (e) => /(CreateServiceAccountKey|UploadServiceAccountKey)$/.test(e.action) && e.status === "success" && hit("high", e.principal + " created a key for " + (e.target.split("/serviceAccounts/")[1] || e.target).split("/")[0], { iocs: e.res && e.res.name ? [{ type: "gcp-sa-key", value: str(e.res.name).split("/keys/")[1] || str(e.res.name) }] : [] }),
  }),
  rule("gcp-impersonation", "gcp", "medium", "likely", "identity", "Service account impersonation token minted", {
    mitre: ["T1550.001"], controls: [NIST("AC-6"), SOC2("CC6.1")],
    description: "GenerateAccessToken / GenerateIdToken / SignJwt / SignBlob on iamcredentials: the caller acted as a service account. Rated high when the caller is a person.",
    recommendation: "Confirm the need; grant roles/iam.serviceAccountTokenCreator on specific accounts only.",
    ops: ["GenerateAccessToken", "GenerateIdToken", "SignJwt", "SignBlob"], source: "data_access",
    match: (e) => /(^|\.)(GenerateAccessToken|GenerateIdToken|SignJwt|SignBlob)$/.test(e.action) && e.status === "success" && hit(e.principalType === "User" ? "high" : "medium", e.principal + " impersonated " + (e.target.split("/serviceAccounts/")[1] || e.target)),
  }),
  rule("gcp-log-sink-tamper", "gcp", "critical", "confirmed", "logging", "Log sink, exclusion or bucket changed", {
    mitre: ["T1562.008"], controls: [CIS_GCP("2 Logging and Monitoring"), NIST("AU-9"), ISO("A.8.15"), SOC2("CC7.2")],
    description: "ConfigServiceV2.DeleteSink / UpdateSink / CreateExclusion / UpdateExclusion / UpdateBucket / DeleteBucket changes what reaches log storage and your SIEM.",
    recommendation: "Restore the sink, review the gap and restrict logging.sinks.* to the platform team.",
    ops: ["google.logging.v2.ConfigServiceV2.DeleteSink", "google.logging.v2.ConfigServiceV2.UpdateSink", "google.logging.v2.ConfigServiceV2.CreateExclusion", "google.logging.v2.ConfigServiceV2.UpdateExclusion", "google.logging.v2.ConfigServiceV2.UpdateBucket", "google.logging.v2.ConfigServiceV2.DeleteBucket"], source: "activity",
    match: (e) => /ConfigServiceV2\.(DeleteSink|UpdateSink|CreateExclusion|UpdateExclusion|UpdateBucket|DeleteBucket)$/.test(e.action) && e.status === "success" && hit(/Delete(Sink|Bucket)$/.test(e.action) ? "critical" : "high", e.action.split(".").pop() + " " + e.target),
  }),
  rule("gcp-firewall-open", "gcp", "high", "confirmed", "network", "Firewall rule allows ingress from 0.0.0.0/0", {
    mitre: ["T1562.007"], controls: [CIS_GCP("3.6"), CIS_GCP("3.7"), NIST("SC-7"), SOC2("CC6.6")],
    description: "compute.firewalls.insert / patch / update with sourceRanges 0.0.0.0/0 and an allow list. SSH (22), RDP (3389) or all ports from anywhere is critical.",
    recommendation: "Restrict sourceRanges and use IAP TCP forwarding for administrative access.",
    ops: ["v1.compute.firewalls.insert", "v1.compute.firewalls.patch", "v1.compute.firewalls.update"], source: "activity", groupBy: "target",
    match: (e) => {
      if (!/compute\.firewalls\.(insert|patch|update)$/.test(e.action) || e.status === "failure" || !e.req) return false;
      if (!listOf(e.req.sourceRanges).map(str).some(OPEN_CIDR) || low(e.req.direction || "INGRESS") !== "ingress") return false;
      const allowed = listOf(e.req.alloweds || e.req.allowed);
      if (!allowed.length) return false;
      const ports = allowed.flatMap((a) => (isObj(a) ? (a.ports ? listOf(a.ports).map(str) : ["*"]) : []));
      return hit(ports.some(rangeHasAdmin) ? "critical" : "high", "ingress from 0.0.0.0/0 on ports " + ports.join(",") + " (" + last(e.target) + ")");
    },
  }),
  rule("gcp-storage-public", "gcp", "critical", "confirmed", "data", "Cloud Storage bucket made public", {
    mitre: ["T1530"], controls: [CIS_GCP("5.1"), NIST("AC-3"), SOC2("CC6.1")],
    description: "storage.setIamPermissions bound allUsers / allAuthenticatedUsers to a bucket.",
    recommendation: "Remove the public binding and enforce storage.publicAccessPrevention.",
    ops: ["storage.setIamPermissions"], source: "activity", groupBy: "target",
    match: (e) => { if (e.service !== "storage.googleapis.com" || !/(setIamPermissions|SetIamPolicy)$/.test(e.action) || e.status !== "success") return false; const pub = gcpBindingAdds(e).filter((b) => PUBLIC_MEMBERS.includes(low(b.member))); return pub.length > 0 && hit("critical", uniq(pub.map((b) => b.member + " " + b.role)).join(", ") + " on " + e.target); },
  }),
  rule("gcp-instance-metadata", "gcp", "high", "likely", "execution", "Startup script, SSH keys or OS Login change in instance metadata", {
    mitre: ["T1059", "T1098.004"], controls: [CIS_GCP("4.4"), NIST("CM-5"), SOC2("CC8.1")],
    description: "compute.instances.setMetadata / projects.setCommonInstanceMetadata set a startup script, ssh-keys, or enable-oslogin=false.",
    recommendation: "Review the script or key, enforce OS Login and restrict compute.instances.setMetadata.",
    ops: ["v1.compute.instances.setMetadata", "v1.compute.projects.setCommonInstanceMetadata"], source: "activity",
    match: (e) => {
      if (!/compute\.(instances\.setMetadata|projects\.setCommonInstanceMetadata)$/.test(e.action) || e.status === "failure") return false;
      const md = e.req && isObj(e.req.metadata) ? e.req.metadata : e.req;
      const items = listOf(md && md.items);
      const keys = items.filter((it) => isObj(it) && (/^(startup-script|startup-script-url|windows-startup-script-(ps1|cmd|bat|url)|ssh-keys|sshKeys)$/i.test(str(it.key)) || (/^enable-oslogin$/i.test(str(it.key)) && /^false$/i.test(str(it.value))))).map((it) => str(it.key));
      return keys.length > 0 && hit(keys.some((k) => /script/i.test(k)) ? "high" : "medium", "metadata " + uniq(keys).join(",") + " on " + last(e.target));
    },
  }),
  rule("gcp-cloudsql-public", "gcp", "high", "confirmed", "network", "Cloud SQL instance reachable from public networks", {
    mitre: ["T1190"], controls: [CIS_GCP("6.5"), CIS_GCP("6.6"), NIST("SC-7"), SOC2("CC6.6")],
    description: "cloudsql.instances.update / create / patch with ipv4Enabled and authorizedNetworks 0.0.0.0/0 (critical) or other public ranges.",
    recommendation: "Disable the public IP and connect through private IP and the Cloud SQL Auth Proxy.",
    ops: ["cloudsql.instances.update", "cloudsql.instances.create", "cloudsql.instances.patch"], source: "activity", groupBy: "target",
    match: (e) => {
      if (!/^cloudsql\.instances\.(update|create|patch)$/.test(e.action) || e.status === "failure") return false;
      const ipc = deepFind(e.req, (k) => k === "ipConfiguration");
      if (!isObj(ipc)) return false;
      const nets = listOf(ipc.authorizedNetworks).map((n) => str(isObj(n) ? n.value : n));
      if (nets.some(OPEN_CIDR)) return hit("critical", "authorizedNetworks 0.0.0.0/0 on " + last(e.target));
      return truthy(ipc.ipv4Enabled) && nets.length > 0 && hit("medium", "public IPv4 with authorizedNetworks " + nets.join(",") + " on " + last(e.target));
    },
  }),
  rule("gcp-snapshot-export", "gcp", "medium", "likely", "exfil", "Disk snapshot followed by image creation, export or sharing", {
    mitre: ["T1537"], controls: [NIST("AC-3"), ISO("A.8.12"), SOC2("CC6.7")],
    description: "compute.disks.createSnapshot by a principal followed within 60 minutes by images.insert / images.export / snapshots.setIamPolicy: the sequence used to copy a disk out of the project.",
    recommendation: "Confirm the backup job and restrict compute.images.export and snapshot sharing.",
    ops: ["v1.compute.disks.createSnapshot", "v1.compute.images.insert", "v1.compute.snapshots.setIamPolicy"], source: "activity",
    run: (events) => {
      const snaps = new Map(), out = new Map();
      for (const e of events) {
        if (e.platform !== "gcp" || e.status === "failure") continue;
        if (/compute\.(disks\.createSnapshot|snapshots\.insert)$/.test(e.action)) { const l = snaps.get(e.principal) || []; l.push(e); snaps.set(e.principal, l); continue; }
        if (/compute\.images\.(insert|export)$|compute\.snapshots\.setIamPolicy$/.test(e.action)) {
          const prior = (snaps.get(e.principal) || []).filter((s) => e.ts - s.ts <= 60 * MIN);
          if (!prior.length) continue;
          const g = out.get(e.principal) || { key: e.principal, events: [], note: e.principal + ": snapshot, then " + e.action.split(".").slice(-2).join(".") + " within 60 min" };
          for (const s of prior) if (!g.events.includes(s)) g.events.push(s);
          g.events.push(e); out.set(e.principal, g);
        }
      }
      return Array.from(out.values()).map((g) => ({ ...g, events: g.events.slice().sort(byTs), count: g.events.length }));
    },
  }),
  rule("gcp-api-enabled", "gcp", "info", "review", "recon", "APIs enabled on a project", {
    mitre: ["T1526"], controls: [NIST("CM-7"), SOC2("CC6.8")],
    description: "ServiceUsage.EnableService / BatchEnableServices turned on APIs. Compute, Cloud Build or ML APIs enabled by an unfamiliar principal often precede resource hijacking.",
    recommendation: "Confirm the services are needed and restrict serviceusage.services.enable.",
    ops: ["google.api.serviceusage.v1.ServiceUsage.EnableService", "google.api.serviceusage.v1.ServiceUsage.BatchEnableServices"], source: "activity",
    match: (e) => /ServiceUsage\.(EnableService|BatchEnableServices)$/.test(e.action) && e.status === "success" && hit("info", "enabled " + ((e.req && e.req.serviceIds ? listOf(e.req.serviceIds).join(",") : "") || e.target.split("/services/")[1] || e.target)),
  }),
  rule("gcp-gpu-instances", "gcp", "medium", "review", "recon", "GPU / accelerator instance created", {
    mitre: ["T1496"], controls: [NIST("CM-8"), SOC2("CC6.6")],
    description: "compute.instances.insert with an accelerator-optimised machine type (a2-, a3-, g2-) or guestAccelerators attached: crypto-mining hardware.",
    recommendation: "Confirm the ML workload; otherwise delete it, investigate the principal and set GPU quota to zero in unused projects.",
    ops: ["v1.compute.instances.insert"], source: "activity",
    match: (e) => /compute\.instances\.insert$/.test(e.action) && e.status !== "failure" && e.req && (/(^|\/)(a2|a3|g2)-/.test(str(e.req.machineType)) || listOf(e.req.guestAccelerators).length > 0) && hit("medium", "machineType " + last(e.req.machineType) + (listOf(e.req.guestAccelerators).length ? " + " + listOf(e.req.guestAccelerators).length + " accelerator(s)" : "") + " (" + last(e.target) + ")"),
  }),
  rule("gcp-storage-list-burst", "gcp", "medium", "likely", "data", "Cloud Storage listing / reading burst", {
    mitre: ["T1530", "T1619"], controls: [NIST("SI-4"), ISO("A.8.16"), SOC2("CC7.2")],
    description: "storage.objects.list / storage.objects.get / storage.buckets.list (data_access log) by one principal reached the threshold inside the window: enumeration or bulk download.",
    recommendation: "Confirm the job, check egress and narrow the principal's storage roles.",
    ops: ["storage.objects.list", "storage.objects.get", "storage.buckets.list"], source: "data_access",
    aggregate: { where: (e) => e.platform === "gcp" && /^storage\.(objects\.(list|get)|buckets\.list)$/.test(e.action), n: "storageListBurstN", windowMin: "storageListBurstWindowMin" },
  }),
  rule("gcp-actas-by-user", "gcp", "low", "review", "identity", "Person acting as a service account", {
    mitre: ["T1548"], controls: [NIST("AC-6"), SOC2("CC6.3")],
    description: "A human principal exercised iam.serviceAccounts.actAs (attaching or running as a service account): legitimate for deployers, and also the path to that service account's permissions.",
    recommendation: "Confirm the person's role; prefer dedicated deploy identities.",
    needs: ["permissions"], source: "activity",
    match: (e) => e.principalType === "User" && e.status === "success" && e.add && Array.isArray(e.add.permissions) && e.add.permissions.includes("iam.serviceAccounts.actAs") && hit("low", e.action + " with iam.serviceAccounts.actAs"),
  }),
  rule("gcp-org-policy", "gcp", "medium", "confirmed", "logging", "Organization policy constraint changed", {
    mitre: ["T1562"], controls: [NIST("CM-6"), SOC2("CC6.8")],
    description: "SetOrgPolicy / ClearOrgPolicy or orgpolicy v2 Create/Update/DeletePolicy changes guardrails such as public access prevention, SA key creation or domain restriction.",
    recommendation: "Diff the constraint and restrict orgpolicy.policy.set to the platform team.",
    ops: ["SetOrgPolicy", "ClearOrgPolicy", "google.cloud.orgpolicy.v2.OrgPolicy.UpdatePolicy", "google.cloud.orgpolicy.v2.OrgPolicy.DeletePolicy"], source: "activity",
    match: (e) => /(SetOrgPolicy|ClearOrgPolicy|OrgPolicy\.(UpdatePolicy|DeletePolicy|CreatePolicy))$/.test(e.action) && e.status === "success" && hit(/Delete|Clear/.test(e.action) ? "high" : "medium", e.action.split(".").pop() + " " + e.target),
  }),
  rule("gcp-denied-burst", "gcp", "medium", "likely", "identity", "Permission-denied burst by one principal", {
    mitre: ["T1078"], controls: [NIST("SI-4"), SOC2("CC7.2")],
    description: "Many calls with status.code 7 (PERMISSION_DENIED) or ungranted authorizationInfo by one principal inside the window.",
    recommendation: "Review the denied methods; confirm the activity with the principal's owner.",
    source: "activity",
    aggregate: { where: (e) => e.platform === "gcp" && e.status === "failure", n: "failureBurstN", windowMin: "failureBurstWindowMin" },
  }),

  // ---------------- Microsoft 365 ----------------
  rule("m365-inbox-rule", "m365", "high", "likely", "exfil", "Inbox rule forwards, redirects or hides mail", {
    mitre: ["T1114.003", "T1564.008"], controls: [CIS_M365("6 Exchange admin center"), SCUBA("MS.EXO.1.1v1"), NIST("SI-4"), SOC2("CC6.7")],
    description: "New-InboxRule / Set-InboxRule with ForwardTo, ForwardAsAttachmentTo or RedirectTo sends mail outside the mailbox; a rule that deletes or files mail into RSS / Archive / Conversation History hides replies from the victim. Both are standard business-email-compromise steps.",
    recommendation: "Remove the rule (Remove-InboxRule), reset the user's password, revoke sessions and search for the same rule name across mailboxes.",
    ops: ["New-InboxRule", "Set-InboxRule", "UpdateInboxRules"], source: "Exchange",
    match: (e) => {
      if (!inSet(e.action, ["New-InboxRule", "Set-InboxRule", "UpdateInboxRules"]) || e.status === "failure") return false;
      if (e.action === "UpdateInboxRules") return hit("low", "inbox rules changed from an Outlook client (rule body is in OperationProperties)", { confidence: "review" });
      const p = e.req || {};
      const fwd = ["ForwardTo", "ForwardAsAttachmentTo", "RedirectTo"].map((k) => str(ci(p, k))).filter(Boolean);
      if (fwd.length) return hit("high", "rule '" + str(ci(p, "Name")) + "' forwards to " + fwd.join(", "), { iocs: fwd.flatMap((v) => v.split(/[;,]/)).map((v) => v.trim()).filter((v) => v.includes("@")).map((v) => ({ type: "email", value: v.toLowerCase() })) });
      const folder = str(ci(p, "MoveToFolder"));
      if (truthy(ci(p, "DeleteMessage")) || /rss|archive|conversation history|deleted items|junk/i.test(folder)) return hit("medium", "rule '" + str(ci(p, "Name")) + "' " + (truthy(ci(p, "DeleteMessage")) ? "deletes" : "moves to " + folder) + " mail" + (ci(p, "SubjectOrBodyContainsWords") ? " containing '" + str(ci(p, "SubjectOrBodyContainsWords")) + "'" : ""));
      return false;
    },
  }),
  rule("m365-mailbox-forwarding", "m365", "high", "confirmed", "exfil", "Mailbox-level forwarding set", {
    mitre: ["T1114.003"], controls: [CIS_M365("6 Exchange admin center"), SCUBA("MS.EXO.1.1v1"), SOC2("CC6.7")],
    description: "Set-Mailbox with ForwardingSmtpAddress or ForwardingAddress copies every message to another address without an inbox rule.",
    recommendation: "Clear the forwarding (Set-Mailbox -ForwardingSmtpAddress $null) and block automatic external forwarding in the outbound spam policy.",
    ops: ["Set-Mailbox"], source: "Exchange",
    match: (e) => { if (e.action !== "Set-Mailbox" || e.status === "failure" || !e.req) return false; const f = str(ci(e.req, "ForwardingSmtpAddress") || ci(e.req, "ForwardingAddress")); return !!f && hit("high", "mailbox " + e.target + " forwards to " + f, { iocs: f.includes("@") ? [{ type: "email", value: f.replace(/^smtp:/i, "").toLowerCase() }] : [] }); },
  }),
  rule("m365-transport-rule", "m365", "high", "likely", "exfil", "Transport rule copies or redirects mail", {
    mitre: ["T1114.003"], controls: [CIS_M365("6 Exchange admin center"), SCUBA("MS.EXO.1.1v1"), SOC2("CC6.7")],
    description: "New-TransportRule / Set-TransportRule with BlindCopyTo, RedirectMessageTo, AddToRecipients or CopyTo copies organisation mail; SetSCL -1 lets spam / phishing bypass filtering.",
    recommendation: "Review and remove the rule; restrict the Transport Rules role to the mail team.",
    ops: ["New-TransportRule", "Set-TransportRule"], source: "Exchange",
    match: (e) => {
      if (!inSet(e.action, ["New-TransportRule", "Set-TransportRule"]) || e.status === "failure" || !e.req) return false;
      const to = ["BlindCopyTo", "RedirectMessageTo", "AddToRecipients", "CopyTo"].map((k) => str(ci(e.req, k))).filter(Boolean);
      if (to.length) return hit("high", "transport rule '" + str(ci(e.req, "Name") || e.target) + "' sends to " + to.join(", "));
      return str(ci(e.req, "SetSCL")) === "-1" && hit("medium", "transport rule '" + str(ci(e.req, "Name") || e.target) + "' bypasses spam filtering (SetSCL -1)");
    },
  }),
  rule("m365-mailbox-delegation", "m365", "medium", "likely", "identity", "Mailbox full access, send-as or folder permission granted", {
    mitre: ["T1098.002"], controls: [NIST("AC-6"), ISO("A.5.15"), SOC2("CC6.3")],
    description: "Add-MailboxPermission (FullAccess), Add-RecipientPermission (SendAs) or Add-MailboxFolderPermission gave one identity another mailbox.",
    recommendation: "Confirm the delegation with the mailbox owner and remove it if unexpected.",
    ops: ["Add-MailboxPermission", "Add-RecipientPermission", "Add-MailboxFolderPermission"], source: "Exchange", groupBy: "target",
    match: (e) => { if (!inSet(e.action, ["Add-MailboxPermission", "Add-RecipientPermission", "Add-MailboxFolderPermission"]) || e.status === "failure") return false; const p = e.req || {}; const who = str(ci(p, "User") || ci(p, "Trustee")); const rights = str(ci(p, "AccessRights")); return hit(/fullaccess|sendas|owner|editor/i.test(rights) ? "medium" : "low", e.action + " " + rights + " on " + str(ci(p, "Identity") || e.target) + (who ? " to " + who : "")); },
  }),
  rule("m365-exchange-role", "m365", "high", "likely", "identity", "Exchange impersonation or powerful role group granted", {
    mitre: ["T1098.002", "T1098.003"], controls: [NIST("AC-6"), ISO("A.8.2"), SOC2("CC6.3")],
    description: "New-ManagementRoleAssignment for ApplicationImpersonation (read any mailbox) or Add-RoleGroupMember to Organization Management / Discovery Management / eDiscovery / Compliance Management.",
    recommendation: "Remove the assignment, scope impersonation with a management scope and confirm with the mail team.",
    ops: ["New-ManagementRoleAssignment", "Add-RoleGroupMember"], source: "Exchange",
    match: (e) => { if (e.status === "failure") return false; const p = e.req || {}; if (e.action === "New-ManagementRoleAssignment" && /ApplicationImpersonation|Mailbox Import Export/i.test(str(ci(p, "Role")))) return hit("high", str(ci(p, "Role")) + " to " + str(ci(p, "User") || ci(p, "SecurityGroup") || ci(p, "App"))); if (e.action === "Add-RoleGroupMember" && /organization management|discovery management|ediscovery|compliance management|security administrator/i.test(str(ci(p, "Identity")))) return hit("high", str(ci(p, "Member")) + " added to " + str(ci(p, "Identity"))); return false; },
  }),
  rule("m365-app-consent", "m365", "high", "likely", "identity", "OAuth consent granted to an application", {
    mitre: ["T1528"], controls: [SCUBA("MS.AAD.5.2v1"), CIS_M365("5 Microsoft Entra admin center"), NIST("AC-6"), SOC2("CC6.1")],
    description: "'Consent to application.' gave an app delegated or tenant-wide access. Consent to mail, files or directory scopes is the core of an illicit-consent attack.",
    recommendation: "Review the app's permissions and publisher, revoke the grant if unknown and allow users to consent only to verified, low-risk apps.",
    ops: ["Consent to application."], source: "AzureActiveDirectory",
    match: (e) => {
      if (e.action !== "Consent to application." || e.status === "failure") return false;
      const perms = mprop(e, "ConsentAction.Permissions");
      const admin = /^true$/i.test(mprop(e, "ConsentContext.IsAdminConsent")) || /^true$/i.test(mprop(e, "ConsentContext.OnBehalfOfAll"));
      const scopes = uniq((perms.match(/Scope:\s*([^,\]]*)/g) || []).flatMap((s) => s.replace(/^Scope:\s*/, "").trim().split(/\s+/)));
      const risky = scopes.filter((s) => /^(Mail\.|MailboxSettings|Files\.ReadWrite|Files\.Read\.All|Sites\.|Directory\.|User\.ReadWrite\.All|full_access_as_|EWS\.|Contacts\.|Notes\.|offline_access$)/i.test(s));
      const app = appName(e);
      return hit(admin || risky.length ? "high" : "medium", (admin ? "tenant-wide " : "") + "consent to " + app + (scopes.length ? " (" + scopes.slice(0, 8).join(" ") + ")" : ""));
    },
  }),
  rule("m365-sp-credential", "m365", "high", "likely", "identity", "Credential added to an application or service principal", {
    mitre: ["T1098.001"], controls: [NIST("IA-5"), ISO("A.5.17"), SOC2("CC6.2")],
    description: "'Add service principal credentials.' or 'Update application - Certificates and secrets management' added a secret or certificate: anyone holding it signs in as the app with all of its permissions.",
    recommendation: "Confirm the new credential with the app owner, remove unknown keys and alert on credential changes for privileged apps.",
    ops: ["Add service principal credentials.", "Update application – Certificates and secrets management "], source: "AzureActiveDirectory",
    match: (e) => /^(Add service principal credentials\.|Update application . Certificates and secrets management)/.test(e.action) && e.status !== "failure" && hit("high", e.action.trim() + " on " + appName(e)),
  }),
  rule("m365-role-add", "m365", "critical", "confirmed", "identity", "Privileged Entra ID role assigned", {
    mitre: ["T1098.003"], controls: [SCUBA("MS.AAD.7.1v1"), CIS_M365("1 Microsoft 365 admin center"), NIST("AC-6"), ISO("A.8.2"), SOC2("CC6.3")],
    description: "'Add member to role.' (or a PIM permanent assignment) added a user or app to Global Administrator, Privileged Role Administrator or another tenant-wide admin role.",
    recommendation: "Confirm through PIM / change control, prefer eligible assignments and keep Global Administrator to two to eight accounts.",
    ops: ["Add member to role.", "Add eligible member to role in PIM completed (permanent)", "Add member to role in PIM completed (permanent)"], source: "AzureActiveDirectory",
    match: (e) => {
      if (!/^Add (eligible )?member to role/.test(e.action) || e.status === "failure") return false;
      const role = mprop(e, "Role.DisplayName") || mprop(e, "Role.TemplateId");
      const crit = /^(Global Administrator|Privileged Role Administrator|Privileged Authentication Administrator|Company Administrator)$/i.test(role);
      const high = /administrator/i.test(role);
      if (!crit && !high) return false;
      return hit(crit ? "critical" : "high", ((e.add && e.add.targetUser) || e.target) + " added to " + role + " by " + e.principal);
    },
  }),
  rule("m365-ca-policy", "m365", "high", "likely", "identity", "Conditional Access policy changed or deleted", {
    mitre: ["T1556.009"], controls: [SCUBA("MS.AAD.3.1v1"), NIST("AC-2"), SOC2("CC6.1")],
    description: "Update / Delete conditional access policy weakens MFA and device requirements for every sign-in it covered.",
    recommendation: "Diff the policy, restore from your exported baseline and restrict Conditional Access Administrator.",
    ops: ["Update conditional access policy", "Delete conditional access policy", "Update policy"], source: "AzureActiveDirectory",
    match: (e) => /^(Update|Delete) conditional access policy$/i.test(e.action) && e.status !== "failure" && hit(/^Delete/i.test(e.action) ? "high" : "medium", e.action + " " + appName(e)),
  }),
  rule("m365-federation", "m365", "critical", "likely", "identity", "Domain federation or authentication changed", {
    mitre: ["T1484.002"], controls: [NIST("IA-8"), ISO("A.5.16"), SOC2("CC6.1")],
    description: "'Set domain authentication.' / 'Set federation settings on domain.' changes which identity provider can sign users in: the Golden SAML / backdoor-federation technique.",
    recommendation: "Verify the issuer and signing certificate with the identity team immediately; revert unknown federation.",
    ops: ["Set domain authentication.", "Set federation settings on domain."], source: "AzureActiveDirectory",
    match: (e) => inSet(e.action, ["Set domain authentication.", "Set federation settings on domain."]) && e.status !== "failure" && hit("critical", e.action + " " + e.target),
  }),
  rule("m365-audit-disable", "m365", "critical", "confirmed", "logging", "Auditing disabled or bypassed", {
    mitre: ["T1562.008"], controls: [CIS_M365("3.1.1"), SCUBA("MS.EXO.17.1v1"), NIST("AU-9"), ISO("A.8.15"), SOC2("CC7.2")],
    description: "Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled False, Set-OrganizationConfig -AuditDisabled True, Set-Mailbox -AuditEnabled False or Set-MailboxAuditBypassAssociation -AuditBypassEnabled True stops audit records.",
    recommendation: "Re-enable auditing, find what happened in the gap from other logs and treat the actor as compromised.",
    ops: ["Set-AdminAuditLogConfig", "Set-OrganizationConfig", "Set-Mailbox", "Set-MailboxAuditBypassAssociation"], source: "Exchange",
    match: (e) => {
      if (e.status === "failure" || !e.req) return false;
      const v = (k) => str(ci(e.req, k));
      if (e.action === "Set-AdminAuditLogConfig" && /^false$/i.test(v("UnifiedAuditLogIngestionEnabled"))) return hit("critical", "unified audit log ingestion disabled");
      if (e.action === "Set-OrganizationConfig" && /^true$/i.test(v("AuditDisabled"))) return hit("critical", "mailbox auditing disabled organisation-wide");
      if (e.action === "Set-Mailbox" && /^false$/i.test(v("AuditEnabled"))) return hit("high", "auditing disabled on " + (v("Identity") || e.target));
      if (e.action === "Set-MailboxAuditBypassAssociation" && /^true$/i.test(v("AuditBypassEnabled"))) return hit("high", "audit bypass for " + (v("Identity") || e.target));
      return false;
    },
  }),
  rule("m365-mfa-disabled", "m365", "high", "confirmed", "identity", "MFA disabled for a user", {
    mitre: ["T1556.006"], controls: [SCUBA("MS.AAD.3.2v1"), NIST("IA-2(1)"), SOC2("CC6.1")],
    description: "'Disable Strong Authentication.' turned off per-user MFA.",
    recommendation: "Re-enable MFA (preferably through Conditional Access) and confirm with the user's manager.",
    ops: ["Disable Strong Authentication."], source: "AzureActiveDirectory",
    match: (e) => e.action === "Disable Strong Authentication." && e.status !== "failure" && hit("high", "MFA disabled for " + ((e.add && e.add.targetUser) || e.target)),
  }),
  rule("m365-anonymous-link", "m365", "medium", "likely", "exfil", "Anonymous (Anyone) sharing link created", {
    mitre: ["T1567"], controls: [SCUBA("MS.SHAREPOINT.1.1v1"), NIST("AC-21"), SOC2("CC6.7")],
    description: "AnonymousLinkCreated: a SharePoint / OneDrive item can now be opened by anyone with the link, without signing in.",
    recommendation: "Remove the link, set Anyone links to expire and restrict external sharing to authenticated guests.",
    ops: ["AnonymousLinkCreated"], source: "SharePoint",
    match: (e) => e.action === "AnonymousLinkCreated" && e.status !== "failure" && hit("medium", "Anyone link on " + ((e.add && e.add.sourceFileName) || e.target)),
  }),
  rule("m365-download-burst", "m365", "high", "likely", "exfil", "Mass file download from SharePoint / OneDrive", {
    mitre: ["T1530", "T1213.002"], controls: [NIST("SI-4"), ISO("A.8.12"), SOC2("CC6.7")],
    description: "FileDownloaded / FileSyncDownloadedFull events by one user reached the threshold inside the window.",
    recommendation: "Confirm with the user (departing employees, sync setups), check the client IP and device and revoke sessions if unknown.",
    ops: ["FileDownloaded", "FileSyncDownloadedFull"], source: "SharePoint",
    aggregate: { where: (e) => e.platform === "m365" && (e.action === "FileDownloaded" || e.action === "FileSyncDownloadedFull"), n: "downloadBurstN", windowMin: "downloadBurstWindowMin" },
  }),
  rule("m365-mail-access-burst", "m365", "high", "likely", "exfil", "MailItemsAccessed burst", {
    mitre: ["T1114.002"], controls: [NIST("SI-4"), ISO("A.8.16"), SOC2("CC7.2")],
    description: "MailItemsAccessed records for one identity reached the threshold inside the window: bulk mail reading by a client or an app (needs Audit Premium / E5 logging).",
    recommendation: "Identify the client app (AppId) and IP; revoke the app or the session if unknown.",
    ops: ["MailItemsAccessed"], source: "Exchange",
    aggregate: { where: (e) => e.platform === "m365" && e.action === "MailItemsAccessed", n: "mailAccessBurstN", windowMin: "mailAccessBurstWindowMin" },
  }),
  rule("m365-purge-burst", "m365", "high", "likely", "data", "Mass mail deletion", {
    mitre: ["T1070.008", "T1485"], controls: [NIST("AU-9"), SOC2("A1.2")],
    description: "HardDelete / SoftDelete / MoveToDeletedItems by one identity reached the threshold inside the window: cleanup after BEC or destruction.",
    recommendation: "Recover from Recoverable Items, confirm with the mailbox owner and review rules and sessions on the mailbox.",
    ops: ["HardDelete", "SoftDelete", "MoveToDeletedItems"], source: "Exchange",
    aggregate: { where: (e) => e.platform === "m365" && inSet(e.action, ["HardDelete", "SoftDelete", "MoveToDeletedItems"]), n: "purgeBurstN", windowMin: "purgeBurstWindowMin" },
  }),
  rule("m365-ediscovery-export", "m365", "high", "likely", "exfil", "Content search purge / export or mailbox export", {
    mitre: ["T1114.002", "T1070.008"], controls: [NIST("AC-6"), ISO("A.8.12"), SOC2("CC6.7")],
    description: "New-ComplianceSearchAction (purge or export) or New-MailboxExportRequest pulls or deletes mail across mailboxes with eDiscovery rights.",
    recommendation: "Confirm with legal / compliance, and restrict eDiscovery Manager and Mailbox Import Export roles.",
    ops: ["New-ComplianceSearchAction", "New-MailboxExportRequest"], source: "SecurityComplianceCenter",
    match: (e) => e.status !== "failure" && (e.action === "New-MailboxExportRequest" ? hit("high", "mailbox export of " + str(e.req && ci(e.req, "Mailbox") || e.target) + (e.req && ci(e.req, "FilePath") ? " to " + str(ci(e.req, "FilePath")) : "")) : e.action === "New-ComplianceSearchAction" ? hit(e.req && (ci(e.req, "Purge") != null || ci(e.req, "Export") != null) ? "high" : "medium", "compliance search action " + str(e.req && (ci(e.req, "SearchName") || "")) + (e.req && ci(e.req, "Purge") != null ? " (purge)" : e.req && ci(e.req, "Export") != null ? " (export)" : "")) : false),
  }),
  rule("m365-login-fail-burst", "m365", "high", "likely", "identity", "Sign-in failure burst from one IP", {
    mitre: ["T1110.003", "T1110"], controls: [NIST("AC-7"), SCUBA("MS.AAD.3.1v1"), SOC2("CC6.1")],
    description: "UserLoginFailed records from one client IP reached the threshold inside the window: password spraying or guessing.",
    recommendation: "Block the IP, check the targeted accounts for any successful sign-in and enforce phishing-resistant MFA.",
    ops: ["UserLoginFailed"], source: "AzureActiveDirectory", groupBy: "ip", needs: ["ip"],
    aggregate: { where: (e) => e.platform === "m365" && e.action === "UserLoginFailed", group: (e) => e.ip, n: "consoleFailN", windowMin: "consoleFailWindowMin" },
  }),

  // ---------------- Cross-platform ----------------
  rule("x-malicious-ip", "any", "high", "likely", "threat-intel", "Activity from an IP on the malicious-IP feed", {
    mitre: ["T1078"], controls: [NIST("SI-4"), NIST("SI-5"), ISO("A.5.7"), SOC2("CC7.2")],
    description: "A source IP appears in the supplied malicious-IP list (the mirrored, dated feed or your own). Successful calls from it are high; only failed calls are medium.",
    recommendation: "Block the IP, rotate credentials for every principal that used it successfully and review their actions.",
    groupBy: "ip", requires: "maliciousIps", needs: ["ip"],
    match: (e, o) => { if (!e.ip) return false; const f = o.maliciousIps.get(e.ip); if (!f) return false; return hit(e.status === "failure" ? "medium" : "high", e.ip + " is listed" + (f.source ? " by " + f.source : "") + (f.score != null ? " (score " + f.score + ")" : ""), { iocs: [{ type: "ip", value: e.ip }] }); },
  }),
  rule("x-impossible-travel", "any", "high", "likely", "identity", "Impossible travel between source IPs", {
    mitre: ["T1078"], controls: [NIST("AC-2(12)"), NIST("SI-4"), SOC2("CC6.1")],
    description: "Consecutive successful events of one principal came from IPs whose supplied locations are further apart than the travel speed allows. Needs IP geolocation passed in opts.geo; VPN and cloud egress cause false positives.",
    recommendation: "Confirm both locations with the user; if one is unknown, revoke sessions and reset credentials.",
    requires: "geo", needs: ["ip"],
    run: (events, o) => {
      const last = new Map(), out = new Map();
      for (const e of events) {
        if (!e.ip || e.status !== "success" || !isHuman(e)) continue;
        const g = geoOf(o.geo, e.ip);
        if (!g) continue;
        const k = e.platform + "|" + e.principal;
        const p = last.get(k);
        last.set(k, { e, g });
        if (!p || p.e.ip === e.ip) continue;
        const km = haversineKm(p.g.lat, p.g.lon, g.lat, g.lon);
        if (km < 500) continue;
        const hours = (e.ts - p.e.ts) / 3600000;
        const kmh = hours > 0 ? km / hours : Infinity;
        if (kmh <= o.travelKmh) continue;
        const grp = out.get(k) || { key: e.principal, events: [], notes: [], iocs: [] };
        if (!grp.events.includes(p.e)) grp.events.push(p.e);
        grp.events.push(e);
        grp.notes.push(p.e.ip + (p.g.country ? " (" + p.g.country + ")" : "") + " to " + e.ip + (g.country ? " (" + g.country + ")" : "") + ": " + Math.round(km) + " km in " + Math.round(hours * 60) + " min" + (Number.isFinite(kmh) ? " = " + Math.round(kmh) + " km/h" : ""));
        grp.iocs.push({ type: "ip", value: e.ip });
        out.set(k, grp);
      }
      return Array.from(out.values()).map((g) => ({ key: g.key, events: g.events, count: g.events.length, note: g.notes.slice(0, 3).join("; "), iocs: g.iocs }));
    },
  }),
  rule("x-after-hours-admin", "any", "low", "review", "identity", "Administrative change outside working hours", {
    mitre: ["T1078"], controls: [NIST("AC-2(12)"), NIST("AU-6"), SOC2("CC7.2")],
    description: "A person made an identity, logging, key or policy change inside the after-hours window (local hours and weekends as configured). Severity rises to medium for root / admin accounts.",
    recommendation: "Confirm the change against on-call or change records.",
    requires: "afterHours",
    match: (e, o) => isHuman(e) && e.status === "success" && isSensitiveAdmin(e) && isAfterHours(e.ts, o.afterHours) && hit(e.principalType === "Root" || e.principalType === "Admin" || new RegExp(o.adminNamePattern, "i").test(e.principal.split("@")[0].split("/").pop()) ? "medium" : "low", e.action + " at " + iso(e.ts)),
  }),
  rule("x-first-seen-service", "any", "low", "review", "recon", "Principal changed a service it never used before", {
    mitre: ["T1078"], controls: [NIST("SI-4"), NIST("AC-2(12)"), SOC2("CC7.2")],
    description: "After at least the baseline number of events, a principal made a successful change in a service (AWS eventSource, Azure provider, GCP serviceName, M365 workload) it had not touched earlier in this dataset.",
    recommendation: "Confirm the new duty with the owner; unexpected expansion of a credential's footprint is a compromise signal.",
    run: (events, o) => {
      const hist = new Map(), out = new Map();
      for (const e of events) {
        if (!e.service || e.principalType === "AWSService") continue;
        const k = e.platform + "|" + e.principal;
        const h = hist.get(k) || { n: 0, svc: new Set() };
        const svc = low(e.service);
        if (h.n >= o.baselineMinEvents && !h.svc.has(svc) && e.status === "success" && isMutating(e)) {
          const g = out.get(k) || { key: e.principal, events: [], svcs: [] };
          g.events.push(e); if (!g.svcs.includes(svc)) g.svcs.push(svc); out.set(k, g);
        }
        h.svc.add(svc); h.n++; hist.set(k, h);
      }
      return Array.from(out.values()).map((g) => ({ key: g.key, events: g.events, count: g.events.length, note: "first change in " + g.svcs.join(", ") }));
    },
  }),
];
Object.freeze(RULES);

function mprop(e, name) { const m = e.add && e.add.modified; if (!m) return ""; const p = m.find((x) => x && str(x.Name) === name); return p ? str(p.NewValue).trim() : ""; }
function appName(e) { const t = (e.add && e.add.targets) || []; const n = t.find((x) => x && !/^(ServicePrincipal_|Application_|User_|Policy_)/.test(x) && !isGuid(x)); return n || e.target || "(unknown app)"; }
function geoOf(geo, ip) { const g = geo && geo[ip]; if (!isObj(g)) return null; const lat = Number(g.lat != null ? g.lat : g.latitude), lon = Number(g.lon != null ? g.lon : g.lng != null ? g.lng : g.longitude); return Number.isFinite(lat) && Number.isFinite(lon) ? { lat, lon, country: str(g.country || g.countryCode || "") } : null; }
export function isAfterHours(ts, ah) {
  if (!ah || !ah.enabled) return false;
  const d = new Date(ts + (Number(ah.utcOffset) || 0) * 3600000);
  const h = d.getUTCHours(), day = d.getUTCDay();
  if (ah.weekends && (day === 0 || day === 6)) return true;
  const s = Number(ah.start), en = Number(ah.end);
  return s > en ? h >= s || h < en : h >= s && h < en;
}
function isSensitiveAdmin(e) {
  switch (e.platform) {
    case "aws": return /^(iam|organizations|cloudtrail|kms|secretsmanager|guardduty|config|sso|identitystore)$/.test(e.service) && isMutating(e);
    case "azure": return /^microsoft\.(authorization|keyvault|insights|security|managedidentity|aadiam)\//i.test(e.action) && /\/(write|delete|action)$/i.test(e.action);
    case "gcp": return /SetIamPolicy$|iam\.admin|ConfigServiceV2|OrgPolicy|SetOrgPolicy|iamcredentials/.test(e.action) && e.readOnly !== true;
    case "m365": return /^(New|Set|Add|Remove|Enable|Disable)-/.test(e.action) || /role|application|policy|domain|credential|consent|password|strong authentication/i.test(e.action) && e.service === "AzureActiveDirectory";
    default: return isMutating(e) && /admin|role|policy|key|secret|permission/i.test(e.action);
  }
}

// ---------------------------------------------------------------------------
// Sliding windows: groups of events by key where >= n fall inside windowMin (inclusive).
// ---------------------------------------------------------------------------
export function windows(events, keyFn, n, windowMin) {
  const W = windowMin * MIN, groups = new Map();
  for (const e of events) { const k = keyFn(e); if (k == null || k === "") continue; let g = groups.get(k); if (!g) { g = []; groups.set(k, g); } g.push(e); }
  const out = [];
  for (const [key, arr] of groups) {
    if (arr.length < n) continue;
    arr.sort(byTs);
    const mark = new Uint8Array(arr.length);
    let i = 0, peak = 0, lastMarked = -1;
    for (let j = 0; j < arr.length; j++) {
      while (arr[j].ts - arr[i].ts > W) i++;
      const c = j - i + 1;
      if (c > peak) peak = c;
      if (c >= n) { for (let k = Math.max(i, lastMarked + 1); k <= j; k++) mark[k] = 1; lastMarked = j; }
    }
    if (lastMarked >= 0) { const evs = arr.filter((_, k) => mark[k]); out.push({ key: str(key), events: evs, total: evs.length, peak }); }
  }
  return out.sort((a, b) => cmp(a.key, b.key));
}

// ---------------------------------------------------------------------------
// analyze
// ---------------------------------------------------------------------------
const SEV_WEIGHT = { critical: 40, high: 20, medium: 8, low: 3, info: 1 };
const HOUR = 3600000, DAY = 24 * HOUR;
export const isPrivateIp = (ip) => /^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(ip) || /^(::1$|fc|fd|fe80:)/i.test(ip);
const publicIp = (ip) => !!ip && looksLikeIp(ip) && !isPrivateIp(ip);

/** Normalise a malicious-IP feed ({updated, data:[{ip,score,source}]}, an array of ips / objects, or {ip: info}) into a Map. */
export function feedMap(feed) {
  if (feed == null) return null;
  if (feed instanceof Map) return feed;
  const m = new Map();
  const put = (x) => { if (typeof x === "string") { const ip = cleanIp(x); if (ip) m.set(ip, {}); } else if (isObj(x) && x.ip) m.set(cleanIp(x.ip), { score: x.score != null ? x.score : null, source: str(x.source || "") }); };
  if (Array.isArray(feed)) feed.forEach(put);
  else if (isObj(feed) && Array.isArray(feed.data)) feed.data.forEach(put);
  else if (isObj(feed) && Array.isArray(feed.ips)) feed.ips.forEach(put);
  else if (isObj(feed)) for (const k of Object.keys(feed)) put(isObj(feed[k]) ? Object.assign({ ip: k }, feed[k]) : k);
  return m;
}

function mergeOpts(opts) {
  const src = opts || {};
  const o = Object.assign({}, DEFAULTS, src);
  o.afterHours = Object.assign({}, DEFAULTS.afterHours, isObj(src.afterHours) ? src.afterHours : {});
  const ta = o.trustedAccounts;
  o.trustedAccounts = uniq((Array.isArray(ta) ? ta : str(ta).split(/[\s,;]+/)).map((x) => str(x).trim()));
  for (const k of Object.keys(DEFAULTS)) if (typeof DEFAULTS[k] === "number") { const n = Number(o[k]); o[k] = Number.isFinite(n) && n > 0 ? n : DEFAULTS[k]; }
  try { new RegExp(o.adminNamePattern, "i"); } catch (_) { o.adminNamePattern = DEFAULTS.adminNamePattern; }
  o.maliciousIps = feedMap(o.maliciousIps);
  o.geo = isObj(o.geo) && Object.keys(o.geo).length ? o.geo : null;
  return o;
}

const opMatches = (op, a) => { const lo = low(op).trim(), la = low(a); return lo.endsWith("*") ? la.startsWith(lo.slice(0, -1)) : la === lo || la.endsWith("." + lo) || la.endsWith(lo) || /^[a-z]+$/i.test(op) && la.startsWith(lo); };
function hasField(e, f) {
  if (f === "permissions") return !!(e.add && Array.isArray(e.add.permissions) && e.add.permissions.length);
  const v = e[f];
  return v != null && v !== "" && v !== "unknown" && v !== "Unknown";
}
const groupKeyOf = (r, e) => {
  switch (r.groupBy) {
    case "ip": return e.ip;
    case "target": return e.target || e.principal;
    case "account": return e.account;
    case "callerAccount": return e.callerAccount;
    default: return e.principal;
  }
};
const evRow = (e) => ({ time: iso(e.ts), platform: e.platform, account: e.account, principal: e.principal, principalType: e.principalType, action: e.action, service: e.service, region: e.region, ip: e.ip, status: e.status, error: e.error, target: e.target, ua: e.ua, event: e.i, raw: e.raw });

/**
 * Run every rule over a parsed dataset (or raw input, which is parsed first).
 * @returns {{ summary, findings, tables:{principals, ips, timeline, rules}, iocs, skipped, meta, rawRecords }}
 */
export function analyze(dataset, opts = {}, ctx) {
  const o = mergeOpts(opts);
  const ds = dataset && Array.isArray(dataset.events) && dataset.stats ? dataset : parseInput(dataset == null ? [] : dataset, o, ctx);
  const events = ds.events;
  const skipped = (ds.skipped || []).slice();
  const n = events.length;
  const nowTs = parseTs(o.now) || (n ? events[n - 1].ts : 0);
  const present = PLATFORMS.filter((p) => ds.platforms && ds.platforms[p]);

  // per-platform action index for applicability checks
  const actions = {};
  for (const e of events) (actions[e.platform] = actions[e.platform] || new Set()).add(e.action);

  const ruleStatus = new Map();
  const active = [];
  for (const r of RULES) {
    const plats = r.platform === "any" ? present : present.filter((p) => p === r.platform);
    if (!plats.length) { ruleStatus.set(r.id, { status: "n/a", reason: r.platform === "any" ? "no events" : "no " + PLATFORM_LABEL[r.platform] + " events" }); continue; }
    if (r.requires === "maliciousIps" && !o.maliciousIps) { const reason = "no malicious-IP list supplied; turn on the mirrored feed or pass your own"; ruleStatus.set(r.id, { status: "skipped", reason }); skipped.push({ check: r.id, reason }); continue; }
    if (r.requires === "geo" && !o.geo) { const reason = "no IP geolocation supplied (opts.geo); impossible travel is not guessed"; ruleStatus.set(r.id, { status: "skipped", reason }); skipped.push({ check: r.id, reason }); continue; }
    if (r.requires === "afterHours" && !o.afterHours.enabled) { ruleStatus.set(r.id, { status: "skipped", reason: "after-hours window turned off" }); continue; }
    if (r.platform !== "any" && r.ops.length) {
      const acts = Array.from(actions[r.platform] || []);
      if (!r.ops.some((op) => acts.some((a) => opMatches(op, a)))) { ruleStatus.set(r.id, { status: "n/a", reason: "no " + r.ops.slice(0, 4).join(" / ") + (r.ops.length > 4 ? " ..." : "") + " events" }); continue; }
    }
    const scope = r.platform === "any" ? events : events.filter((e) => e.platform === r.platform && (!r.ops.length || r.ops.some((op) => opMatches(op, e.action))));
    const missing = r.needs.filter((f) => !scope.some((e) => hasField(e, f)));
    if (missing.length) {
      const reason = (r.platform === "any" ? "input" : PLATFORM_LABEL[r.platform] + " input") + " has no " + missing.join(", ") + " field" + (missing.length > 1 ? "s" : "");
      ruleStatus.set(r.id, { status: "skipped", reason }); skipped.push({ check: r.id, reason }); continue;
    }
    active.push(r);
  }

  // groups: rule id -> Map(key -> { key, events, count, severity, confidence, notes, iocs })
  const groups = new Map();
  const errored = new Set();
  const addGroup = (r, key, evs, count, severity, confidence, notes, iocs) => {
    let m = groups.get(r.id); if (!m) { m = new Map(); groups.set(r.id, m); }
    const k = str(key);
    let g = m.get(k);
    if (!g) { g = { key: k, events: [], count: 0, severity, confidence, notes: [], iocs: [] }; m.set(k, g); }
    for (const e of evs) g.events.push(e);
    g.count += count;
    if (SEV_RANK[severity] > SEV_RANK[g.severity]) { g.severity = severity; g.confidence = confidence; }
    for (const nt of notes) if (nt && !g.notes.includes(nt)) g.notes.push(nt);
    for (const x of iocs || []) g.iocs.push(x);
  };
  const fail = (r, err) => { if (!errored.has(r.id)) { errored.add(r.id); skipped.push({ check: r.id, reason: "rule error: " + str(err && err.message || err) }); } };

  const byPlat = { any: [] };
  for (const r of active) if (r.kind === "match") (byPlat[r.platform] = byPlat[r.platform] || []).push(r);
  for (let i = 0; i < n; i++) {
    const e = events[i];
    if (ctx && ctx.progress && i % 1000 === 0) ctx.progress(i, n, "rules: " + i + " / " + n + " events");
    const list = (byPlat[e.platform] || []).concat(byPlat.any);
    for (const r of list) {
      if (errored.has(r.id)) continue;
      let h;
      try { h = r.match(e, o); } catch (err) { fail(r, err); continue; }
      if (!h) continue;
      addGroup(r, groupKeyOf(r, e) || e.principal, [e], 1, h.severity || r.severity, h.confidence || r.confidence, [h.note], h.iocs);
    }
  }
  for (const r of active) {
    if (r.kind === "match") continue;
    try {
      if (r.kind === "aggregate") {
        const a = r.aggregate, N = o[a.n], W = o[a.windowMin];
        const gfn = typeof a.group === "function" ? a.group : (e) => e.principal;
        for (const g of windows(events.filter(a.where), gfn, N, W)) {
          const acts = Object.create(null); for (const e of g.events) acts[e.action] = (acts[e.action] || 0) + 1; // null-proto: action name is operator-controlled; a plain {} makes acts["constructor"] a function → NaN ordering
          const top = Object.keys(acts).sort((x, y) => acts[y] - acts[x] || cmp(x, y)).slice(0, 3).map((k) => k + " x" + acts[k]).join(", ");
          addGroup(r, g.key, g.events, g.total, r.severity, r.confidence, [g.peak + " events within " + W + " min (threshold " + N + "); " + g.total + " in burst windows: " + top], looksLikeIp(g.key) ? [{ type: "ip", value: g.key }] : []);
        }
      } else {
        for (const g of r.run(events, o)) addGroup(r, g.key, g.events, g.count != null ? g.count : g.events.length, g.severity || r.severity, g.confidence || r.confidence, [g.note], g.iocs);
      }
    } catch (err) { fail(r, err); }
  }
  if (ctx && ctx.progress) ctx.progress(n, n, "building findings");

  // principal / ip stats
  const pstats = new Map(), istats = new Map();
  for (const e of events) {
    const pk = e.platform + "|" + e.principal;
    let p = pstats.get(pk);
    if (!p) { p = { principal: e.principal, platform: e.platform, type: e.principalType, account: e.account, events: 0, failures: 0, ips: new Set(), services: new Set(), first: e.ts, last: e.ts, findings: 0, maxSeverity: "", risk: 0, flags: new Set() }; pstats.set(pk, p); }
    p.events++; if (e.status === "failure") p.failures++; if (e.ip) p.ips.add(e.ip); if (e.service) p.services.add(e.service); p.last = e.ts;
    if (e.ip && looksLikeIp(e.ip)) {
      let s = istats.get(e.ip);
      if (!s) { s = { ip: e.ip, events: 0, failures: 0, principals: new Set(), platforms: new Set(), first: e.ts, last: e.ts, findings: 0, maxSeverity: "", flags: new Set() }; istats.set(e.ip, s); }
      s.events++; if (e.status === "failure") s.failures++; s.principals.add(e.principal); s.platforms.add(e.platform); s.last = e.ts;
    }
  }

  // raw findings
  const raw = [];
  for (const r of RULES) {
    const m = groups.get(r.id);
    if (!m) continue;
    for (const g of m.values()) {
      const evs = Array.from(new Set(g.events)).sort(byTs);
      raw.push({ r, g, evs });
    }
  }
  raw.sort((a, b) => SEV_RANK[b.g.severity] - SEV_RANK[a.g.severity] || CONF_RANK[b.g.confidence] - CONF_RANK[a.g.confidence] || a.r.order - b.r.order || cmp(a.g.key, b.g.key));
  const flagged = new Set();
  for (const { r, g, evs } of raw) {
    const pks = new Set(), ips = new Set();
    for (const e of evs) { flagged.add(e.i); pks.add(e.platform + "|" + e.principal); if (e.ip && istats.has(e.ip)) ips.add(e.ip); }
    for (const pk of pks) { const p = pstats.get(pk); p.findings++; p.risk += SEV_WEIGHT[g.severity]; p.flags.add(r.id); if (!p.maxSeverity || SEV_RANK[g.severity] > SEV_RANK[p.maxSeverity]) p.maxSeverity = g.severity; }
    for (const ip of ips) { const s = istats.get(ip); s.findings++; s.flags.add(r.id); if (!s.maxSeverity || SEV_RANK[g.severity] > SEV_RANK[s.maxSeverity]) s.maxSeverity = g.severity; }
  }

  const iocMap = new Map();
  const addIoc = (type, value, ctxId) => { if (!value) return; const k = type + "\u0000" + value; const x = iocMap.get(k) || { type, value, context: new Set() }; x.context.add(ctxId); iocMap.set(k, x); };
  const rawRecords = {};
  const findings = raw.map(({ r, g, evs }) => {
    const plats = uniq(evs.map((e) => e.platform));
    const principals = uniq(evs.map((e) => e.principal));
    const ips = uniq(evs.map((e) => e.ip).filter((ip) => looksLikeIp(ip)));
    const targets = uniq(evs.map((e) => e.target).filter((t) => t && !principals.includes(t)));
    const evidence = evs.slice(0, EVIDENCE_CAP).map(evRow);
    if (ds.raw) for (const e of evs.slice(0, EVIDENCE_CAP)) if (e.raw >= 0 && rawRecords[e.raw] === undefined) rawRecords[e.raw] = ds.raw[e.raw];
    const assets = [];
    for (const pr of principals.slice(0, 10)) {
      const e0 = evs.find((e) => e.principal === pr);
      const p = pstats.get(e0.platform + "|" + pr);
      assets.push({ type: "IDENTITY", name: pr, data: { platform: e0.platform, account: p.account, events: p.events, flags: Array.from(p.flags).sort() } });
    }
    for (const ip of ips.filter(publicIp).slice(0, 10)) { const s = istats.get(ip); const f = o.maliciousIps && o.maliciousIps.get(ip); assets.push({ type: "IP", name: ip, data: { events: s.events, principals: s.principals.size, malicious: !!f } }); }
    for (const t of targets.slice(0, 10)) { const e0 = evs.find((e) => e.target === t); assets.push({ type: "ASSET", name: t, data: { platform: e0.platform, account: e0.account } }); }
    for (const x of g.iocs) addIoc(x.type, x.value, r.id);
    if (SEV_RANK[g.severity] >= SEV_RANK.high) for (const ip of ips.filter(publicIp)) addIoc("ip", ip, r.id);
    const notes = g.notes.slice(0, 5);
    const tags = [r.category, r.platform === "any" ? "cross-platform" : r.platform, r.id];
    if (g.severity === "critical") tags.push("incident-candidate");
    return {
      id: r.id + ":" + g.key, ruleId: r.id, title: r.title + (g.key ? ": " + g.key : ""),
      severity: g.severity, confidence: g.confidence, category: r.category,
      platform: plats.length === 1 ? plats[0] : r.platform === "any" ? "mixed" : r.platform,
      description: r.description + (notes.length ? " Observed: " + notes.join("; ") + (g.notes.length > 5 ? "; and " + (g.notes.length - 5) + " more" : "") + "." : ""),
      recommendation: r.recommendation, controls: r.controls.map((c) => ({ framework: c.framework, id: c.id })), mitre: r.mitre.slice(),
      key: g.key, note: notes[0] || "", evidence, evidenceCount: Math.max(g.count, evs.length),
      firstSeen: iso(evs[0].ts), lastSeen: iso(evs[evs.length - 1].ts),
      principals: principals.slice(0, 25), ips: ips.slice(0, 25), assets, tags,
    };
  });
  for (const f of findings) if (f.severity === "critical") for (const p of f.principals.slice(0, 5)) if (!/^(HIDDEN_DUE_TO_SECURITY_REASONS|unknown)$/.test(p)) addIoc("principal", p, f.ruleId);
  const iocs = Array.from(iocMap.values()).map((x) => ({ type: x.type, value: x.value, context: Array.from(x.context).sort().join(";") })).sort((a, b) => cmp(a.type, b.type) || cmp(a.value, b.value));

  // tables
  const principals = Array.from(pstats.values()).map((p) => ({
    principal: p.principal, platform: p.platform, type: p.type, account: p.account, events: p.events, failures: p.failures,
    ips: p.ips.size, services: p.services.size, first: iso(p.first), last: iso(p.last), findings: p.findings, maxSeverity: p.maxSeverity,
    risk: Math.min(100, p.risk), flags: Array.from(p.flags).sort(),
  })).sort((a, b) => b.risk - a.risk || b.events - a.events || cmp(a.platform, b.platform) || cmp(a.principal, b.principal));
  const ipsTable = Array.from(istats.values()).map((s) => {
    const f = o.maliciousIps && o.maliciousIps.get(s.ip); const g = geoOf(o.geo, s.ip);
    return { ip: s.ip, events: s.events, failures: s.failures, principals: s.principals.size, platforms: Array.from(s.platforms).sort(), first: iso(s.first), last: iso(s.last), private: isPrivateIp(s.ip), malicious: f ? (f.source || "listed") + (f.score != null ? " " + f.score : "") : "", country: g ? g.country : "", findings: s.findings, maxSeverity: s.maxSeverity, flags: Array.from(s.flags).sort() };
  }).sort((a, b) => b.findings - a.findings || b.events - a.events || cmp(a.ip, b.ip));

  let timeline = [], unit = HOUR;
  if (n) {
    const first = events[0].ts, lastTs = events[n - 1].ts;
    if (lastTs - first > 60 * DAY) unit = DAY;
    if ((lastTs - first) / unit > 2000) unit = 7 * DAY;
    const start = Math.floor(first / unit) * unit;
    const count = Math.floor((lastTs - start) / unit) + 1;
    timeline = Array.from({ length: count }, (_, k) => ({ t: iso(start + k * unit), events: 0, failures: 0, flagged: 0 }));
    for (const e of events) { const b = timeline[Math.floor((e.ts - start) / unit)]; b.events++; if (e.status === "failure") b.failures++; if (flagged.has(e.i)) b.flagged++; }
  }

  const rulesTable = RULES.map((r) => {
    const fs = findings.filter((f) => f.ruleId === r.id);
    const st = fs.length ? { status: "fired", reason: "" } : ruleStatus.get(r.id) || { status: errored.has(r.id) ? "skipped" : "silent", reason: errored.has(r.id) ? "rule error" : "" };
    return { id: r.id, title: r.title, platform: r.platform, severity: r.severity, category: r.category, kind: r.kind, mitre: r.mitre.slice(), status: st.status, reason: st.reason, hits: fs.length, events: fs.reduce((s, f) => s + f.evidenceCount, 0) };
  });

  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) bySeverity[f.severity]++;
  const firstTs = n ? events[0].ts : 0, lastTs = n ? events[n - 1].ts : 0;
  const summary = {
    events: n, principals: principals.length, ips: ipsTable.length, platforms: ds.platforms || {}, platform: ds.platform, files: (ds.files || []).length,
    findings: findings.length, bySeverity, critical: bySeverity.critical, high: bySeverity.high, criticalHigh: bySeverity.critical + bySeverity.high,
    firstTs: iso(firstTs), lastTs: iso(lastTs), spanHours: n ? Math.round((lastTs - firstTs) / HOUR * 10) / 10 : 0,
    timelineUnit: unit === HOUR ? "hour" : unit === DAY ? "day" : "week",
    rulesTotal: RULES.length, rulesFired: rulesTable.filter((r) => r.status === "fired").length, rulesSilent: rulesTable.filter((r) => r.status === "silent").length,
    rulesSkipped: rulesTable.filter((r) => r.status === "skipped").length, rulesNa: rulesTable.filter((r) => r.status === "n/a").length,
    maliciousFeed: !!o.maliciousIps, maliciousFeedSize: o.maliciousIps ? o.maliciousIps.size : 0, geo: !!o.geo, iocs: iocs.length,
  };
  return {
    summary, findings, tables: { principals, ips: ipsTable, timeline, rules: rulesTable }, iocs, skipped, rawRecords,
    meta: { tool: TOOL_ID, version: VERSION, rows: n, now: iso(nowTs), platforms: present, files: ds.files || [], stats: ds.stats || null, rules: RULES.length },
  };
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
const cell = (v) => {
  let s = Array.isArray(v) ? v.join("; ") : v == null ? "" : String(v);
  if (/^[=+@\t\r]/.test(s) || (/^-/.test(s) && !/^-\d+(\.\d+)?$/.test(s))) s = "'" + s; // spreadsheet formula guard
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
};
const csv = (cols, rows, fn) => [cols.join(",")].concat((rows || []).map((r) => fn(r).map(cell).join(","))).join("\n") + "\n";

export const FINDING_COLS = ["id", "severity", "confidence", "platform", "category", "title", "evidence_count", "first_seen", "last_seen", "principals", "ips", "mitre", "controls", "description", "recommendation"];
/** Findings as CSV (one row per finding). */
export function findingsToCsv(findings) {
  return csv(FINDING_COLS, findings, (f) => [
    f.id, f.severity, f.confidence, f.platform, f.category, f.title, f.evidenceCount != null ? f.evidenceCount : (f.evidence || []).length,
    f.firstSeen, f.lastSeen, f.principals || [], f.ips || [], f.mitre || [],
    (f.controls || []).map((c) => c.framework + " " + c.id), f.description, f.recommendation,
  ]);
}
/** IOC list as CSV: type,value,context. */
export function iocsToCsv(iocs) { return csv(["type", "value", "context"], iocs, (x) => [x.type, x.value, x.context]); }
const PRINCIPAL_COLS = ["principal", "platform", "type", "account", "events", "failures", "ips", "services", "first", "last", "findings", "maxSeverity", "risk", "flags"];
/** Principal inventory (tables.principals) as CSV. */
export function principalsToCsv(rows) { return csv(PRINCIPAL_COLS, rows, (p) => PRINCIPAL_COLS.map((k) => p[k])); }
const IP_COLS = ["ip", "events", "failures", "principals", "platforms", "first", "last", "private", "malicious", "country", "findings", "maxSeverity", "flags"];
/** Source IP table as CSV. */
export function ipsToCsv(rows) { return csv(IP_COLS, rows, (p) => IP_COLS.map((k) => p[k])); }
/** Timeline (tables.timeline) as CSV. */
export function timelineToCsv(rows) { return csv(["bucket_start", "events", "failures", "flagged"], rows, (b) => [b.t, b.events, b.failures, b.flagged]); }

const sq = (s) => "'" + str(s).replace(/'/g, "''") + "'";
const dq = (s) => '"' + str(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
const QUERY_HINT = {
  "aws-root-api": { aws: "useridentity.type = 'Root' AND eventname <> 'ConsoleLogin'" },
  "aws-access-denied-burst": { aws: "(errorcode LIKE '%AccessDenied%' OR errorcode LIKE '%Unauthorized%')" },
  "aws-recon-burst": { aws: "regexp_like(eventname, '^(Describe|List|GetCallerIdentity|GetAccountAuthorizationDetails|GetBucketPolicy|GetBucketAcl)')" },
  "az-failed-burst": { azure: "ActivityStatusValue =~ \"Failure\"" },
  "az-sp-privileged-write": { azure: "OperationNameValue in~ (\"Microsoft.Authorization/roleAssignments/write\", \"Microsoft.Authorization/roleDefinitions/write\", \"Microsoft.KeyVault/vaults/accessPolicies/write\", \"Microsoft.Network/networkSecurityGroups/securityRules/write\", \"Microsoft.Compute/virtualMachines/runCommand/action\")" },
  "az-keyvault-secret-burst": { azureTable: "AzureDiagnostics", azure: "ResourceProvider == \"MICROSOFT.KEYVAULT\" and OperationName == \"SecretGet\"", azureBy: "CallerIPAddress, identity_claim_upn_s" },
  "gcp-denied-burst": { gcp: "protoPayload.status.code=7" },
  "gcp-actas-by-user": { gcp: "protoPayload.authorizationInfo.permission=\"iam.serviceAccounts.actAs\"" },
};
function fmtPs(ts) { const s = iso(parseTs(ts)); return s ? s.slice(0, 16).replace("T", " ") : ""; }

function queryFor(r, plat, fs, from, to, o) {
  const hint = QUERY_HINT[r.id] || {};
  const exact = r.ops.filter((op) => !op.endsWith("*")), glob = r.ops.filter((op) => op.endsWith("*")).map((op) => op.slice(0, -1));
  const principals = uniq(fs.flatMap((f) => f.principals)).slice(0, 20);
  const ips = uniq(fs.flatMap((f) => f.ips)).slice(0, 20);
  const agg = r.aggregate ? { n: o[r.aggregate.n], w: o[r.aggregate.windowMin] } : null;
  if (plat === "aws") {
    const where = ["eventtime BETWEEN " + sq(from) + " AND " + sq(to)];
    if (hint.aws) where.push(hint.aws);
    else if (r.ops.length) { const parts = []; if (exact.length) parts.push("eventname IN (" + exact.map(sq).join(", ") + ")"); if (glob.length) parts.push("regexp_like(eventname, " + sq("^(" + glob.join("|") + ")") + ")"); where.push(parts.length > 1 ? "(" + parts.join(" OR ") + ")" : parts[0]); }
    else if (r.groupBy === "ip" && ips.length) where.push("sourceipaddress IN (" + ips.map(sq).join(", ") + ")");
    else if (principals.length) where.push("(" + principals.map((p) => "useridentity.arn LIKE " + sq("%" + p.replace(/^role\//, "").split("/")[0] + "%")).join(" OR ") + ")");
    if (/amazonaws\.com$/.test(r.source)) where.push("eventsource = " + sq(r.source));
    if (agg) return "-- Athena (replace cloudtrail_logs with your table); threshold " + agg.n + " in " + agg.w + " min\nSELECT useridentity.arn, floor(to_unixtime(from_iso8601_timestamp(eventtime)) / (" + agg.w + " * 60)) AS win, count(*) AS n, min(eventtime) AS first_seen\nFROM cloudtrail_logs\nWHERE " + where.join("\n  AND ") + "\nGROUP BY 1, 2\nHAVING count(*) >= " + agg.n + "\nORDER BY n DESC;";
    return "-- Athena (replace cloudtrail_logs with your table)\nSELECT eventtime, useridentity.type, useridentity.arn, eventname, eventsource, sourceipaddress, awsregion, errorcode, requestparameters\nFROM cloudtrail_logs\nWHERE " + where.join("\n  AND ") + "\nORDER BY eventtime;";
  }
  if (plat === "azure") {
    const table = hint.azureTable || "AzureActivity";
    const lines = [table, "| where TimeGenerated between (datetime(" + from + ") .. datetime(" + to + "))"];
    if (hint.azure) lines.push("| where " + hint.azure);
    else if (r.ops.length) lines.push("| where OperationNameValue in~ (" + r.ops.map(dq).join(", ") + ")");
    else if (r.groupBy === "ip" && ips.length) lines.push("| where CallerIpAddress in (" + ips.map(dq).join(", ") + ")");
    else if (principals.length) lines.push("| where Caller in~ (" + principals.map(dq).join(", ") + ")");
    if (agg) lines.push("| summarize n = count(), first_seen = min(TimeGenerated) by " + (hint.azureBy || "Caller") + ", bin(TimeGenerated, " + agg.w + "m)", "| where n >= " + agg.n, "| order by n desc");
    else lines.push("| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ActivityStatusValue, _ResourceId, Properties", "| order by TimeGenerated asc");
    return "// KQL (Log Analytics)\n" + lines.join("\n");
  }
  if (plat === "gcp") {
    const lines = ['logName:"cloudaudit.googleapis.com"', 'timestamp>="' + from + '" AND timestamp<="' + to + '"'];
    if (hint.gcp) lines.push(hint.gcp);
    else if (r.ops.length) lines.push("protoPayload.methodName:(" + r.ops.map(dq).join(" OR ") + ")");
    else if (r.groupBy === "ip" && ips.length) lines.push("protoPayload.requestMetadata.callerIp=(" + ips.map(dq).join(" OR ") + ")");
    else if (principals.length) lines.push("protoPayload.authenticationInfo.principalEmail=(" + principals.map(dq).join(" OR ") + ")");
    return "# Cloud Logging query (Logs Explorer)" + (agg ? "; count per principal per " + agg.w + " min, threshold " + agg.n : "") + "\n" + lines.join("\n");
  }
  if (plat === "m365") {
    const parts = ["Search-UnifiedAuditLog", "-StartDate " + dq(fmtPs(from)), "-EndDate " + dq(fmtPs(to))];
    if (r.ops.length) parts.push("-Operations " + r.ops.map((op) => dq(op.trim())).join(","));
    else if (r.groupBy === "ip" && ips.length) parts.push("-IPAddresses " + ips.map(dq).join(","));
    else if (principals.length) parts.push("-UserIds " + principals.map(dq).join(","));
    parts.push("-ResultSize 5000", "-SessionCommand ReturnLargeSet");
    return "# Exchange Online PowerShell (dates are UTC)" + (agg ? "; group the output by UserIds per " + agg.w + " min, threshold " + agg.n : "") + "\n" + parts.join(" ") + " | Export-Csv -NoTypeInformation -Encoding UTF8 " + r.id + ".csv";
  }
  return "";
}

/** Re-express every fired rule as a hunt query for its platform (Athena SQL, KQL, Logging query, Search-UnifiedAuditLog). */
export function queriesText(result, opts = {}) {
  const o = mergeOpts(opts);
  const from = (result && result.summary && result.summary.firstTs) || "", to = (result && result.summary && result.summary.lastTs) || "";
  const out = ["Cloud Audit Log Hunter: hunt queries for fired rules", "Range " + from + " to " + to + " (UTC). Generated by " + TOOL_ID + " " + VERSION + ".", ""];
  for (const r of RULES) {
    const fs = (result.findings || []).filter((f) => f.ruleId === r.id);
    if (!fs.length) continue;
    const plats = r.platform === "any" ? uniq(fs.flatMap((f) => (f.evidence || []).map((e) => e.platform))) : [r.platform];
    out.push("== " + r.id + ": " + r.title + " (" + fs.length + " finding" + (fs.length === 1 ? "" : "s") + ")");
    for (const p of plats) {
      if (p === "generic") { out.push("# generic input: no vendor query language"); continue; }
      out.push(queryFor(r, p, fs, from, to, o));
    }
    out.push("");
  }
  if (out.length === 3) out.push("No rule fired, so there is nothing to re-run.");
  return out.join("\n") + "\n";
}

/** Human-readable summary. */
export function summaryText(result) {
  const s = result.summary;
  const lines = [
    "Cloud Audit Log Hunter (" + TOOL_ID + " " + VERSION + ")",
    "Events: " + s.events + " from " + s.files + " file(s); " + Object.keys(s.platforms || {}).map((p) => (PLATFORM_LABEL[p] || p) + " " + s.platforms[p]).join(", "),
    "Span: " + (s.firstTs || "-") + " to " + (s.lastTs || "-") + " (" + s.spanHours + " h)",
    "Principals: " + s.principals + "; source IPs: " + s.ips,
    "Findings: " + s.findings + " (critical " + s.bySeverity.critical + ", high " + s.bySeverity.high + ", medium " + s.bySeverity.medium + ", low " + s.bySeverity.low + ", info " + s.bySeverity.info + ")",
    "Rules: " + s.rulesTotal + " total; fired " + s.rulesFired + ", silent " + s.rulesSilent + ", skipped " + s.rulesSkipped + ", not applicable " + s.rulesNa,
    "Malicious-IP list: " + (s.maliciousFeed ? s.maliciousFeedSize + " entries" : "not used") + "; geolocation: " + (s.geo ? "supplied" : "not supplied"),
    "",
  ];
  for (const f of result.findings) {
    lines.push("[" + f.severity.toUpperCase() + "/" + f.confidence + "] " + f.title + " (" + f.evidenceCount + " event" + (f.evidenceCount === 1 ? "" : "s") + ", " + f.firstSeen + ")");
    if (f.note) lines.push("  " + f.note);
    lines.push("  Controls: " + f.controls.map((c) => c.framework + " " + c.id).join("; "));
    lines.push("  Action: " + f.recommendation);
  }
  if (result.skipped && result.skipped.length) { lines.push("", "Skipped checks:"); for (const k of result.skipped) lines.push("  " + k.check + ": " + k.reason); }
  return lines.join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// Synthetic example (seeded; exact vendor layouts). Everything here is fictional:
// account 111122223333 and the IPs are AWS / RFC 5737 documentation values.
// ---------------------------------------------------------------------------
function lcg(seed) { let s = (seed >>> 0) || 1; return () => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s / 4294967296; }; }
const hex = (rnd, n) => { let s = ""; for (let k = 0; k < n; k++) s += "0123456789abcdef"[Math.floor(rnd() * 16)]; return s; };
const uuid = (rnd) => hex(rnd, 8) + "-" + hex(rnd, 4) + "-4" + hex(rnd, 3) + "-a" + hex(rnd, 3) + "-" + hex(rnd, 12);
const ctTime = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");

export function exampleDataset(seed = 7) {
  const rnd = lcg(seed);
  const ACCT = "111122223333";
  const T0 = Date.UTC(2026, 9, 1, 8, 0, 0);
  const iamUser = (name, mfa, key) => ({ type: "IAMUser", principalId: "AIDA" + hex(rnd, 16).toUpperCase(), arn: "arn:aws:iam::" + ACCT + ":user/" + name, accountId: ACCT, accessKeyId: key || "ASIA" + hex(rnd, 16).toUpperCase(), userName: name, ...(mfa == null ? {} : { sessionContext: { sessionIssuer: {}, webIdFederationData: {}, attributes: { creationDate: ctTime(T0), mfaAuthenticated: String(mfa) } } }) });
  const ci = () => ({ type: "AssumedRole", principalId: "AROAEXAMPLECIDEPLOY01:gh-actions", arn: "arn:aws:sts::" + ACCT + ":assumed-role/ci-deploy/gh-actions", accountId: ACCT, accessKeyId: "ASIA" + hex(rnd, 16).toUpperCase(), sessionContext: { sessionIssuer: { type: "Role", principalId: "AROAEXAMPLECIDEPLOY01", arn: "arn:aws:iam::" + ACCT + ":role/ci-deploy", accountId: ACCT, userName: "ci-deploy" }, webIdFederationData: {}, attributes: { creationDate: ctTime(T0), mfaAuthenticated: "false" } } });
  const root = () => ({ type: "Root", principalId: ACCT, arn: "arn:aws:iam::" + ACCT + ":root", accountId: ACCT, accessKeyId: "" });
  const recs = [];
  const rec = (t, ident, src, name, ip, ua, req, res, extra) => recs.push(Object.assign({
    eventVersion: "1.09", userIdentity: ident, eventTime: ctTime(t), eventSource: src, eventName: name, awsRegion: (extra && extra.awsRegion) || "us-east-1",
    sourceIPAddress: ip, userAgent: ua, requestParameters: req === undefined ? null : req, responseElements: res === undefined ? null : res,
    requestID: uuid(rnd), eventID: uuid(rnd), readOnly: /^(Describe|List|Get)/.test(name), eventType: "AwsApiCall", managementEvent: true, recipientAccountId: ACCT, eventCategory: "Management",
  }, extra || {}));
  const UA_CON = "AWS Internal", UA_CLI = "aws-cli/2.17.20 md/awscrt#0.20.11 ua/2.0 os/linux#6.5.0 md/arch#x86_64 lang/python#3.11.9 md/pyimpl#CPython cfg/retry-mode#standard md/installer#exe md/distrib#ubuntu.22 md/prompt#off md/command#ec2.describe-instances";
  const UA_BOTO = "Boto3/1.34.69 md/Botocore#1.34.69 ua/2.0 os/linux#6.1.0 md/arch#x86_64 lang/python#3.11.8 md/pyimpl#CPython cfg/retry-mode#legacy Botocore/1.34.69";
  const BENIGN = [["ec2.amazonaws.com", "DescribeInstances", null], ["s3.amazonaws.com", "ListBuckets", { Host: "s3.amazonaws.com" }], ["ec2.amazonaws.com", "DescribeVolumes", null], ["sts.amazonaws.com", "GetCallerIdentity", null], ["cloudformation.amazonaws.com", "DescribeStacks", null], ["lambda.amazonaws.com", "ListFunctions20150331", null], ["ecr.amazonaws.com", "GetAuthorizationToken", null], ["ssm.amazonaws.com", "GetParameter", { name: "/app/feature-flags", withDecryption: false }]];
  const svc = iamUser("svc-reporting", null, "AKIAEXAMPLESVCREPORT");
  // 300 baseline events across three working days
  for (let k = 0; k < 300; k++) {
    const day = Math.floor(k / 100), t = T0 + day * 86400000 + Math.floor((k % 100) * 6.3 * 60000 + rnd() * 120000);
    const who = k % 3;
    if (who === 0 && k % 100 === 0) { recs.push({ eventVersion: "1.09", userIdentity: { type: "IAMUser", principalId: "AIDAEXAMPLEUSER01001", arn: "arn:aws:iam::" + ACCT + ":user/user01", accountId: ACCT, userName: "user01" }, eventTime: ctTime(t), eventSource: "signin.amazonaws.com", eventName: "ConsoleLogin", awsRegion: "us-east-1", sourceIPAddress: "198.51.100.10", userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36", requestParameters: null, responseElements: { ConsoleLogin: "Success" }, additionalEventData: { LoginTo: "https://console.aws.amazon.com/console/home", MobileVersion: "No", MFAUsed: "Yes" }, eventID: uuid(rnd), readOnly: false, eventType: "AwsConsoleSignIn", managementEvent: true, recipientAccountId: ACCT, eventCategory: "Management" }); continue; }
    const b = BENIGN[Math.floor(rnd() * BENIGN.length)];
    if (who === 0) rec(t, iamUser("user01", true), b[0], b[1], "198.51.100.10", UA_CON, b[2]);
    else if (who === 1) { if (k % 25 === 1) rec(t, ci(), "ec2.amazonaws.com", "RunInstances", "192.0.2.44", UA_CLI, { instancesSet: { items: [{ imageId: "ami-0abcdef1234567890", minCount: 1, maxCount: 1 }] }, instanceType: "t3.medium" }, { instancesSet: { items: [{ instanceId: "i-0" + hex(rnd, 16) }] } }); else rec(t, ci(), b[0], b[1], "192.0.2.44", UA_CLI, b[2]); }
    else rec(t, svc, b[0], b[1], "192.0.2.80", UA_BOTO, b[2]);
  }
  // the incident (03-Oct 21:00 local working days are over; 04-Oct 02:00 UTC)
  const A = Date.UTC(2026, 9, 4, 2, 0, 0), BAD = "203.0.113.50", FF = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";
  for (let k = 0; k < 12; k++) recs.push({ eventVersion: "1.09", userIdentity: { type: "IAMUser", principalId: ACCT, accountId: ACCT, accessKeyId: "", userName: "HIDDEN_DUE_TO_SECURITY_REASONS" }, eventTime: ctTime(A + k * 27000), eventSource: "signin.amazonaws.com", eventName: "ConsoleLogin", awsRegion: "us-east-1", sourceIPAddress: BAD, userAgent: FF, errorMessage: "Failed authentication", requestParameters: null, responseElements: { ConsoleLogin: "Failure" }, additionalEventData: { LoginTo: "https://console.aws.amazon.com/console/home", MobileVersion: "No", MFAUsed: "No" }, eventID: uuid(rnd), readOnly: false, eventType: "AwsConsoleSignIn", managementEvent: true, recipientAccountId: ACCT, eventCategory: "Management" });
  recs.push({ eventVersion: "1.09", userIdentity: root(), eventTime: ctTime(A + 7 * 60000), eventSource: "signin.amazonaws.com", eventName: "ConsoleLogin", awsRegion: "us-east-1", sourceIPAddress: BAD, userAgent: FF, requestParameters: null, responseElements: { ConsoleLogin: "Success" }, additionalEventData: { LoginTo: "https://console.aws.amazon.com/console/home", MobileVersion: "No", MFAUsed: "No" }, eventID: uuid(rnd), readOnly: false, eventType: "AwsConsoleSignIn", managementEvent: true, recipientAccountId: ACCT, eventCategory: "Management" });
  rec(A + 9 * 60000, root(), "cloudtrail.amazonaws.com", "StopLogging", BAD, "AWS Internal", { name: "arn:aws:cloudtrail:us-east-1:" + ACCT + ":trail/org-trail" });
  rec(A + 11 * 60000, root(), "s3.amazonaws.com", "PutBucketPolicy", BAD, "AWS Internal", { bucketName: "testorg-finance-exports", Host: "testorg-finance-exports.s3.amazonaws.com", bucketPolicy: { Version: "2012-10-17", Statement: [{ Sid: "PublicRead", Effect: "Allow", Principal: "*", Action: "s3:GetObject", Resource: "arn:aws:s3:::testorg-finance-exports/*" }] }, policy: [""] });
  rec(A + 13 * 60000, root(), "iam.amazonaws.com", "CreateAccessKey", BAD, "AWS Internal", { userName: "svc-reporting" }, { accessKey: { accessKeyId: "AKIAIOSFODNN7EXAMPLE", status: "Active", userName: "svc-reporting", createDate: "Oct 4, 2026, 2:13:00 AM" } });
  const PY = "python-requests/2.31.0", BAD2 = "198.51.100.23";
  const svc2 = iamUser("svc-reporting", null, "AKIAIOSFODNN7EXAMPLE");
  const RECON = [["iam.amazonaws.com", "ListUsers"], ["iam.amazonaws.com", "ListRoles"], ["iam.amazonaws.com", "GetAccountAuthorizationDetails"], ["ec2.amazonaws.com", "DescribeInstances"], ["ec2.amazonaws.com", "DescribeSecurityGroups"], ["s3.amazonaws.com", "ListBuckets"], ["s3.amazonaws.com", "GetBucketPolicy"], ["secretsmanager.amazonaws.com", "ListSecrets"], ["lambda.amazonaws.com", "ListFunctions20150331"], ["sts.amazonaws.com", "GetCallerIdentity"], ["rds.amazonaws.com", "DescribeDBInstances"], ["kms.amazonaws.com", "ListKeys"]];
  for (let k = 0; k < 60; k++) { const r = RECON[k % RECON.length]; rec(A + 20 * 60000 + k * 4000, svc2, r[0], r[1], BAD2, PY, r[1] === "GetBucketPolicy" ? { bucketName: "testorg-finance-exports" } : null); }
  for (let k = 0; k < 25; k++) rec(A + 25 * 60000 + k * 7000, svc2, "secretsmanager.amazonaws.com", "GetSecretValue", BAD2, PY, { secretId: "prod/app/secret-" + String(k + 1).padStart(2, "0") });
  for (let k = 0; k < 2; k++) rec(A + 30 * 60000 + k * 50000, svc2, "ec2.amazonaws.com", "RunInstances", BAD2, PY, { instancesSet: { items: [{ imageId: "ami-0fedcba9876543210", minCount: 4, maxCount: 4 }] }, instanceType: "p3.2xlarge" }, { instancesSet: { items: [{ instanceId: "i-0" + hex(rnd, 16) }] } }, { awsRegion: "ap-southeast-3" });
  recs.sort((a, b) => cmp(a.eventTime, b.eventTime));
  const cloudtrail = JSON.stringify({ Records: recs });

  // Azure Activity Log (REST / "Export" JSON: {"value": [...]})
  const SUB = "00000000-1111-2222-3333-444444444444", TEN = "99999999-8888-7777-6666-555555555555", AZ = Date.UTC(2026, 9, 4, 3, 0, 0);
  const azEv = (t, op, status, rid, caller, body, extra) => ({
    authorization: { action: op, scope: rid }, caller, channels: "Operation",
    claims: { "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": caller, idtyp: "user", ipaddr: BAD },
    correlationId: uuid(rnd), description: "", eventDataId: uuid(rnd), eventName: { value: status === "Started" ? "BeginRequest" : "EndRequest", localizedValue: status === "Started" ? "Begin request" : "End request" },
    category: { value: "Administrative", localizedValue: "Administrative" }, eventTimestamp: new Date(t).toISOString().replace("Z", "0000Z"),
    id: rid + "/events/" + uuid(rnd) + "/ticks/" + (t * 10000 + 621355968000000000), level: "Informational", operationId: uuid(rnd),
    operationName: { value: op, localizedValue: op }, resourceGroupName: (/resourceGroups\/([^/]+)/i.exec(rid) || [])[1] || "",
    resourceProviderName: { value: op.split("/")[0], localizedValue: op.split("/")[0] }, resourceType: { value: op.split("/").slice(0, -1).join("/"), localizedValue: op.split("/").slice(0, -1).join("/") },
    resourceId: rid, status: { value: status, localizedValue: status }, subStatus: { value: status === "Succeeded" ? "OK" : "", localizedValue: "" },
    submissionTimestamp: new Date(t + 15000).toISOString(), subscriptionId: SUB, tenantId: TEN,
    properties: Object.assign({ eventCategory: "Administrative", entity: rid, message: op, hierarchy: TEN + "/" + SUB }, body ? { requestbody: JSON.stringify(body) } : {}, extra || {}),
    httpRequest: { clientRequestId: uuid(rnd), clientIpAddress: BAD, method: /delete$/.test(op) ? "DELETE" : "PUT" }, relatedEvents: [],
  });
  const SUBR = "/subscriptions/" + SUB;
  const raId = SUBR + "/providers/Microsoft.Authorization/roleAssignments/" + uuid(rnd);
  const azure = JSON.stringify({ value: [
    azEv(AZ - 3600000, "Microsoft.Compute/virtualMachines/start/action", "Succeeded", SUBR + "/resourceGroups/rg-web/providers/Microsoft.Compute/virtualMachines/web-01", "ops@test.darknode.ai"),
    azEv(AZ - 1800000, "Microsoft.Resources/deployments/write", "Succeeded", SUBR + "/resourceGroups/rg-web/providers/Microsoft.Resources/deployments/web-release", "ops@test.darknode.ai"),
    azEv(AZ, "Microsoft.Authorization/roleAssignments/write", "Started", raId, "ops-temp@test.darknode.ai", { Id: raId.split("/").pop(), Properties: { PrincipalId: "a1b2c3d4-0000-4000-8000-00000000beef", PrincipalType: "User", RoleDefinitionId: SUBR + "/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635", Scope: SUBR, Condition: null, ConditionVersion: null } }),
    azEv(AZ + 2000, "Microsoft.Authorization/roleAssignments/write", "Succeeded", raId, "ops-temp@test.darknode.ai", null, { statusCode: "Created" }),
    azEv(AZ + 240000, "Microsoft.Insights/diagnosticSettings/delete", "Succeeded", SUBR + "/providers/microsoft.insights/diagnosticSettings/send-to-sentinel", "ops-temp@test.darknode.ai"),
    azEv(AZ + 420000, "Microsoft.Network/networkSecurityGroups/securityRules/write", "Started", SUBR + "/resourceGroups/rg-web/providers/Microsoft.Network/networkSecurityGroups/nsg-web/securityRules/allow-rdp", "ops-temp@test.darknode.ai", { properties: { protocol: "Tcp", sourcePortRange: "*", destinationPortRange: "3389", sourceAddressPrefix: "*", destinationAddressPrefix: "*", access: "Allow", priority: 100, direction: "Inbound" } }),
  ] });

  // GCP Cloud Audit Logs (LogEntry NDJSON, as exported by `gcloud logging read --format=json` per line)
  const G = Date.UTC(2026, 9, 4, 3, 30, 0), PROJ = "testorg-prod-4821", ACTLOG = "projects/" + PROJ + "/logs/cloudaudit.googleapis.com%2Factivity";
  const gEv = (t, svcName, method, resName, who, extra, resType) => JSON.stringify({
    protoPayload: Object.assign({ "@type": "type.googleapis.com/google.cloud.audit.AuditLog", status: {}, authenticationInfo: { principalEmail: who }, requestMetadata: { callerIp: BAD, callerSuppliedUserAgent: "google-cloud-sdk gcloud/495.0.0 command/gcloud.projects.add-iam-policy-binding,gzip(gfe)", requestAttributes: { time: new Date(t).toISOString(), auth: {} }, destinationAttributes: {} }, serviceName: svcName, methodName: method, resourceName: resName }, extra),
    insertId: hex(rnd, 12), resource: { type: resType || "project", labels: { project_id: PROJ } }, timestamp: new Date(t).toISOString().replace(".000Z", ".123456Z"), severity: "NOTICE", logName: ACTLOG, receiveTimestamp: new Date(t + 900).toISOString(),
  });
  const gcp = [
    gEv(G - 600000, "compute.googleapis.com", "v1.compute.instances.start", "projects/" + PROJ + "/zones/us-central1-a/instances/api-1", "deployer@testorg-prod-4821.iam.gserviceaccount.com", { authorizationInfo: [{ permission: "compute.instances.start", granted: true, resourceAttributes: {} }], request: { "@type": "type.googleapis.com/compute.instances.start" } }, "gce_instance"),
    gEv(G, "cloudresourcemanager.googleapis.com", "SetIamPolicy", "projects/" + PROJ, "ops-temp@test.darknode.ai", { authorizationInfo: [{ resource: "projects/" + PROJ, permission: "resourcemanager.projects.setIamPolicy", granted: true, resourceAttributes: {} }], request: { "@type": "type.googleapis.com/google.iam.v1.SetIamPolicyRequest", resource: PROJ, policy: { bindings: [{ role: "roles/owner", members: ["user:ops-temp@test.darknode.ai", "user:contractor@partner.test.darknode.ai"] }], etag: "BwYxyz1=" } }, response: { "@type": "type.googleapis.com/google.iam.v1.Policy", bindings: [{ role: "roles/owner", members: ["user:ops-temp@test.darknode.ai", "user:contractor@partner.test.darknode.ai"] }] }, serviceData: { "@type": "type.googleapis.com/google.iam.v1.logging.AuditData", policyDelta: { bindingDeltas: [{ action: "ADD", role: "roles/owner", member: "user:contractor@partner.test.darknode.ai" }] } } }),
    gEv(G + 180000, "iam.googleapis.com", "google.iam.admin.v1.CreateServiceAccountKey", "projects/-/serviceAccounts/104857600000000000001", "ops-temp@test.darknode.ai", { authorizationInfo: [{ resource: "projects/-/serviceAccounts/104857600000000000001", permission: "iam.serviceAccountKeys.create", granted: true, resourceAttributes: {} }], request: { "@type": "type.googleapis.com/google.iam.admin.v1.CreateServiceAccountKeyRequest", name: "projects/-/serviceAccounts/deployer@testorg-prod-4821.iam.gserviceaccount.com", private_key_type: 2 }, response: { "@type": "type.googleapis.com/google.iam.admin.v1.ServiceAccountKey", name: "projects/" + PROJ + "/serviceAccounts/deployer@testorg-prod-4821.iam.gserviceaccount.com/keys/3f9c2e1d0a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d", valid_after_time: { seconds: Math.floor(G / 1000) }, key_algorithm: 2, key_origin: 2, key_type: 1 } }, "service_account"),
    gEv(G + 300000, "logging.googleapis.com", "google.logging.v2.ConfigServiceV2.DeleteSink", "projects/" + PROJ + "/sinks/siem-export", "ops-temp@test.darknode.ai", { authorizationInfo: [{ resource: "projects/" + PROJ + "/sinks/siem-export", permission: "logging.sinks.delete", granted: true, resourceAttributes: {} }], request: { "@type": "type.googleapis.com/google.logging.v2.DeleteSinkRequest", sinkName: "projects/" + PROJ + "/sinks/siem-export" } }, "logging_sink"),
  ].join("\n") + "\n";

  // Microsoft 365: Search-UnifiedAuditLog ... | Export-Csv -NoTypeInformation (Exchange Online PowerShell)
  const M = Date.UTC(2026, 9, 4, 4, 0, 0), ORG = "5b7e1c2d-0000-4000-8000-0000000c0de0";
  const mTime = (t) => new Date(t).toISOString().slice(0, 19);
  const usDate = (t) => { const d = new Date(t); const h = d.getUTCHours(); return (d.getUTCMonth() + 1) + "/" + d.getUTCDate() + "/" + d.getUTCFullYear() + " " + (h % 12 || 12) + ":" + String(d.getUTCMinutes()).padStart(2, "0") + ":" + String(d.getUTCSeconds()).padStart(2, "0") + " " + (h < 12 ? "AM" : "PM"); };
  const mRows = [];
  const mRec = (t, recType, recTypeNum, user, op, ad) => mRows.push({ RecordType: recType, CreationDate: usDate(t), UserIds: user, Operations: op, AuditData: JSON.stringify(Object.assign({ CreationTime: mTime(t), Id: uuid(rnd), Operation: op, OrganizationId: ORG, RecordType: recTypeNum, UserKey: hex(rnd, 16).toUpperCase(), UserType: 0, Version: 1, UserId: user }, ad)) });
  mRec(M - 7200000, "AzureActiveDirectoryStsLogon", 15, "finance@test.darknode.ai", "UserLoggedIn", { ResultStatus: "Success", Workload: "AzureActiveDirectory", ClientIP: "198.51.100.10", ObjectId: "00000002-0000-0ff1-ce00-000000000000", AzureActiveDirectoryEventType: 1, ExtendedProperties: [{ Name: "ResultStatusDetail", Value: "Success" }, { Name: "UserAgent", Value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" }, { Name: "RequestType", Value: "OAuth2:Authorize" }], ModifiedProperties: [], Actor: [{ ID: "finance@test.darknode.ai", Type: 5 }], Target: [{ ID: "00000002-0000-0ff1-ce00-000000000000", Type: 0 }], ApplicationId: "00000002-0000-0ff1-ce00-000000000000", ErrorNumber: "0" });
  mRec(M, "AzureActiveDirectoryStsLogon", 15, "finance@test.darknode.ai", "UserLoggedIn", { ResultStatus: "Success", Workload: "AzureActiveDirectory", ClientIP: BAD, ObjectId: "00000002-0000-0ff1-ce00-000000000000", AzureActiveDirectoryEventType: 1, ExtendedProperties: [{ Name: "ResultStatusDetail", Value: "Success" }, { Name: "UserAgent", Value: FF }, { Name: "RequestType", Value: "OAuth2:Authorize" }], ModifiedProperties: [], Actor: [{ ID: "finance@test.darknode.ai", Type: 5 }], Target: [{ ID: "00000002-0000-0ff1-ce00-000000000000", Type: 0 }], ApplicationId: "00000002-0000-0ff1-ce00-000000000000", ErrorNumber: "0" });
  mRec(M + 120000, "ExchangeAdmin", 1, "finance@test.darknode.ai", "New-InboxRule", { ResultStatus: "True", Workload: "Exchange", ClientIP: BAD + ":51234", ObjectId: "finance@test.darknode.ai\\.", ExternalAccess: false, OrganizationName: "test.darknode.ai", OriginatingServer: "BN0PR04MB0000 (15.20.8000.000)", Parameters: [{ Name: "AlwaysDeleteOutlookRulesBlob", Value: "False" }, { Name: "Force", Value: "False" }, { Name: "Name", Value: "." }, { Name: "SubjectOrBodyContainsWords", Value: "invoice;payment;wire" }, { Name: "ForwardTo", Value: "collect@partner.test.darknode.ai" }, { Name: "MarkAsRead", Value: "True" }, { Name: "StopProcessingRules", Value: "True" }], SessionId: uuid(rnd) });
  mRec(M + 600000, "AzureActiveDirectory", 8, "it-ops@test.darknode.ai", "Add member to role.", { ResultStatus: "Success", Workload: "AzureActiveDirectory", ClientIP: BAD, ObjectId: "backup-admin@test.darknode.ai", AzureActiveDirectoryEventType: 1, ExtendedProperties: [{ Name: "additionalDetails", Value: "{}" }, { Name: "extendedAuditEventCategory", Value: "User" }], ModifiedProperties: [{ Name: "Role.ObjectID", NewValue: "62e90394-69f5-4237-9190-012177145e10", OldValue: "" }, { Name: "Role.DisplayName", NewValue: "Global Administrator", OldValue: "" }, { Name: "Role.TemplateId", NewValue: "62e90394-69f5-4237-9190-012177145e10", OldValue: "" }, { Name: "Role.WellKnownObjectName", NewValue: "TenantAdmins", OldValue: "" }], Actor: [{ ID: "it-ops@test.darknode.ai", Type: 5 }, { ID: "User_" + uuid(rnd), Type: 2 }], Target: [{ ID: "User_" + uuid(rnd), Type: 2 }, { ID: "backup-admin@test.darknode.ai", Type: 5 }], TargetUserOrGroupName: "backup-admin@test.darknode.ai" });
  mRec(M + 900000, "AzureActiveDirectory", 8, "finance@test.darknode.ai", "Consent to application.", { ResultStatus: "Success", Workload: "AzureActiveDirectory", ClientIP: BAD, ObjectId: "ServicePrincipal_" + uuid(rnd), AzureActiveDirectoryEventType: 1, ExtendedProperties: [{ Name: "additionalDetails", Value: "{\"User-Agent\":\"" + FF + "\"}" }, { Name: "extendedAuditEventCategory", Value: "ServicePrincipal" }], ModifiedProperties: [{ Name: "ConsentContext.IsAdminConsent", NewValue: "False", OldValue: "" }, { Name: "ConsentContext.IsAppOnly", NewValue: "False", OldValue: "" }, { Name: "ConsentContext.OnBehalfOfAll", NewValue: "False", OldValue: "" }, { Name: "ConsentAction.Permissions", NewValue: "[] => [[Id: " + hex(rnd, 22) + ", ClientId: " + uuid(rnd) + ", PrincipalId: " + uuid(rnd) + ", ResourceId: " + uuid(rnd) + ", ConsentType: Principal, Scope:  Mail.Read Mail.Send offline_access User.Read, CreatedDateTime: , LastModifiedDateTime ]]; ", OldValue: "" }], Actor: [{ ID: "finance@test.darknode.ai", Type: 5 }], Target: [{ ID: "ServicePrincipal_" + uuid(rnd), Type: 2 }, { ID: "Mail Sync Pro", Type: 1 }] });
  const UAL_COLS = ["RunspaceId", "RecordType", "CreationDate", "UserIds", "Operations", "AuditData", "ResultIndex", "ResultCount", "Identity", "IsValid", "ObjectState"];
  const runspace = uuid(rnd);
  const q = (v) => '"' + String(v).replace(/"/g, '""') + '"';
  const m365 = [UAL_COLS.map(q).join(",")].concat(mRows.map((r, k) => [runspace, r.RecordType, r.CreationDate, r.UserIds, r.Operations, r.AuditData, k + 1, mRows.length, JSON.parse(r.AuditData).Id, "True", "Unchanged"].map(q).join(","))).join("\r\n") + "\r\n";

  return {
    files: [
      { name: "111122223333_CloudTrail_us-east-1_20261004T0230Z_example.json", text: cloudtrail },
      { name: "azure-activity-log-example.json", text: azure },
      { name: "gcp-audit-activity-example.ndjson", text: gcp },
      { name: "m365-unified-audit-log-example.csv", text: m365 },
    ],
    now: "2026-10-04T06:00:00Z",
    note: "Synthetic, seeded example. Account 111122223333, test.darknode.ai and the 192.0.2.x / 198.51.100.x / 203.0.113.x addresses are documentation values.",
  };
}

// ---------------------------------------------------------------------------
// selfTest
// ---------------------------------------------------------------------------
export function selfTest() {
  const tests = [];
  const ex = exampleDataset();
  const ds = parseInput(ex.files);
  const r = analyze(ds, { now: ex.now });
  const fired = (id) => r.findings.filter((f) => f.ruleId === id);
  tests.push({ name: "four vendor formats detected", pass: ds.files.map((f) => f.platform).join(",") === "aws,azure,gcp,m365" });
  tests.push({ name: "403 CloudTrail records parsed", pass: ds.stats.perPlatform.aws === 403 });
  tests.push({ name: "at least 60 rules", pass: RULES.length >= 60 && new Set(RULES.map((x) => x.id)).size === RULES.length });
  tests.push({ name: "every rule cites a control", pass: RULES.every((x) => x.controls.length > 0) });
  for (const id of ["aws-root-console-login", "aws-console-fail-burst", "aws-trail-tamper", "aws-s3-public", "aws-iam-access-key-other", "aws-secrets-burst", "aws-recon-burst", "aws-run-instances-new-region", "az-privileged-role-assignment", "az-diagnostics-delete", "az-nsg-open", "gcp-iam-privileged-binding", "gcp-sa-key-created", "gcp-log-sink-tamper", "m365-inbox-rule", "m365-role-add", "m365-app-consent"]) tests.push({ name: id + " fires on the example", pass: fired(id).length > 0 });
  tests.push({ name: "failed burst then success is critical", pass: fired("aws-console-fail-burst").some((f) => f.severity === "critical") });
  tests.push({ name: "critical findings carry incident-candidate", pass: r.findings.filter((f) => f.severity === "critical").every((f) => f.tags.includes("incident-candidate")) });
  tests.push({ name: "travel and malicious-IP skipped without inputs", pass: r.skipped.some((s) => s.check === "x-impossible-travel") && r.skipped.some((s) => s.check === "x-malicious-ip") });
  tests.push({ name: "deterministic", pass: JSON.stringify(analyze(parseInput(ex.files), { now: ex.now })) === JSON.stringify(r) });
  tests.push({ name: "empty input yields no findings", pass: analyze("").findings.length === 0 });
  return { pass: tests.every((t) => t.pass), tests };
}

/**
 * Cheap per-file detection for the UI (reads at most 256 KB; never parses a big file whole).
 * @returns {{ name, bytes, format, platform, confidence, layout, headers }}
 */
export function detectFile(name, text) {
  const full = str(text);
  let s = full.slice(0, 262144);
  if (/^﻿?#TYPE /.test(s)) s = s.slice(s.indexOf("\n") + 1);
  const out = { name: str(name), bytes: full.length, format: "unknown", platform: "generic", confidence: 0, layout: "", headers: [] };
  if (!s.trim()) { out.format = "empty"; return out; }
  const sn = sniff(s);
  out.format = sn.format;
  try {
    if (sn.format === "csv" || sn.format === "tsv") {
      const first = iterCsv(s, { delimiter: sn.delimiter }).next().value;
      out.headers = first ? Object.keys(first) : s.split(/\r?\n/)[0].split(sn.delimiter || ",").map((h) => h.replace(/^"|"$/g, "").trim());
      Object.assign(out, classifyHeaders(out.headers));
    } else if (sn.format === "ndjson") {
      const line = s.split(/\r?\n/).find((l) => l.trim());
      const o = JSON.parse(line);
      if (isObj(o) && Array.isArray(o.Records)) Object.assign(out, { platform: "aws", confidence: 1, layout: "aws-digest-ndjson" });
      else { Object.assign(out, classifyRecord(o)); out.layout = out.platform + "-ndjson"; out.headers = isObj(o) ? Object.keys(o) : []; }
    } else if (sn.format === "json") {
      if (full.length <= 2 * 1024 * 1024) {
        const recs = iterJson(full);
        const o = Array.isArray(recs) ? recs.find(isObj) : null;
        if (o) { Object.assign(out, classifyRecord(o)); out.layout = out.platform + "-json"; out.headers = Object.keys(o); }
      } else {
        const has = (re) => re.test(s);
        if (has(/"eventSource"\s*:/) && has(/"eventName"\s*:/)) Object.assign(out, { platform: "aws", confidence: 0.9 });
        else if (has(/"protoPayload"\s*:/)) Object.assign(out, { platform: "gcp", confidence: 0.9 });
        else if (has(/"Workload"\s*:/) && has(/"Operation"\s*:/)) Object.assign(out, { platform: "m365", confidence: 0.9 });
        else if (has(/"operationName"\s*:/) && has(/"(caller|resourceId)"\s*:/i)) Object.assign(out, { platform: "azure", confidence: 0.9 });
        out.layout = out.platform + "-json";
      }
    }
  } catch (_) { /* left as unknown / generic; parseInput reports the real error */ }
  return out;
}
