// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Cloud Spend Anomaly engine (cloudspend). Reads cloud billing exports (AWS Cost and
// Usage Report legacy + CUR 2.0, AWS Cost Explorer CSV, Azure Cost Management cost
// details, GCP billing export to BigQuery as CSV/JSON and the console cost table) and
// finds spend patterns that indicate abuse or runaway cost: daily spikes per account and
// service, new GPU / accelerator families, new regions, egress spikes, serverless bursts,
// dormant accounts waking up, new marketplace charges and resource-id churn. Anomalies
// can be joined to the Cloud Audit Log Hunter's JSON export (tool "cloudtrail") by
// account + region + time window.
//
// Pure: no DOM, no network, no clock. Deterministic: the same input gives byte-identical
// JSON. Money is held as integer micro-units of the file's currency for sums and compared
// as integers; output is in cents. Currencies are never converted or summed together.
// Statistics: median / MAD robust z-score over a trailing window, with a stated minimum
// spread so a flat or zero baseline does not turn cents into alerts.

import { sniff, iterCsv, iterJson, iterNdjson, findColumn, normHeader, flatten } from "../ingest/parse.js";
import { findingKey } from "../core/sink-map.js";

export const TOOL_ID = "cloudspend";
export const VERSION = "1.0.0";
export const EVIDENCE_CAP = 50;
export const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
export const CONF_RANK = { confirmed: 3, likely: 2, review: 1 };
export const PROVIDER_LABEL = { aws: "AWS", azure: "Azure", gcp: "GCP", other: "Other" };
const DAY = 86400000;

/** Logical column -> accepted headers (vendor headers first; matched after normHeader). */
export const COLUMNS = {
  date: ["lineItem/UsageStartDate", "line_item_usage_start_date", "usage_start_time", "Usage start date", "Date", "UsageDate", "date", "usageStartTime", "UsageDateTime", "day"],
  account: ["lineItem/UsageAccountId", "line_item_usage_account_id", "SubscriptionId", "subscriptionGuid", "SubscriptionGuid", "project.id", "project_id", "Project ID", "account", "account_id", "linked_account"],
  accountName: ["lineItem/UsageAccountName", "line_item_usage_account_name", "SubscriptionName", "subscriptionName", "project.name", "project_name", "Project name", "account_name"],
  service: ["lineItem/ProductCode", "line_item_product_code", "MeterCategory", "meterCategory", "service.description", "service_description", "Service description", "Service", "ServiceName", "service_name"],
  sku: ["lineItem/UsageType", "line_item_usage_type", "sku.description", "sku_description", "SKU description", "UsageType", "usage_type", "sku"],
  meterSub: ["MeterSubCategory", "meterSubCategory"],
  meterName: ["MeterName", "meterName"],
  operation: ["lineItem/Operation", "line_item_operation", "operation"],
  region: ["product/region", "product/regionCode", "product_region_code", "product_region", "ResourceLocation", "resourceLocation", "location.region", "location_region", "Location", "region"],
  zone: ["lineItem/AvailabilityZone", "line_item_availability_zone", "location.zone"],
  resourceId: ["lineItem/ResourceId", "line_item_resource_id", "ResourceId", "resourceId", "InstanceId", "resource.name", "resource_name", "resource.global_name", "resource_id"],
  instanceType: ["product/instanceType", "product_instance_type", "instance_type", "machine_type"],
  productFamily: ["product/productFamily", "product_product_family"],
  usage: ["lineItem/UsageAmount", "line_item_usage_amount", "Quantity", "quantity", "usage.amount", "usage_amount", "Usage amount"],
  unit: ["pricing/unit", "pricing_unit", "UnitOfMeasure", "unitOfMeasure", "usage.unit", "usage_unit", "Usage unit"],
  cost: ["lineItem/UnblendedCost", "line_item_unblended_cost", "CostInBillingCurrency", "costInBillingCurrency", "cost", "Unrounded cost", "Cost", "PreTaxCost", "lineItem/BlendedCost", "amount"],
  currency: ["lineItem/CurrencyCode", "line_item_currency_code", "BillingCurrency", "billingCurrency", "BillingCurrencyCode", "billingCurrencyCode", "currency", "Currency"],
  lineType: ["lineItem/LineItemType", "line_item_line_item_type", "ChargeType", "chargeType", "cost_type", "Cost type"],
  billingEntity: ["bill/BillingEntity", "bill_billing_entity", "PublisherType", "publisherType", "seller_name", "Seller name"],
  seller: ["lineItem/LegalEntity", "line_item_legal_entity", "product/ProductName", "product_product_name", "PublisherName", "publisherName", "ProductName", "productName"],
};
/** Columns the mapping panel offers (the rest are vendor-specific helpers). */
export const MAP_KEYS = ["date", "account", "service", "sku", "region", "resourceId", "instanceType", "usage", "unit", "cost", "currency", "billingEntity"];
export const MAP_LABEL = {
  date: "Usage date", account: "Account / subscription / project", service: "Service", sku: "SKU / usage type", region: "Region",
  resourceId: "Resource id", instanceType: "Instance / machine type", usage: "Usage amount", unit: "Usage unit", cost: "Cost", currency: "Currency",
  billingEntity: "Marketplace marker (billing entity / publisher type)",
};

/** Tunable thresholds; the UI renders these as the settings panel. */
export const DEFAULTS = {
  baselineDays: 28,          // trailing window for the median / MAD baseline
  minHistoryDays: 14,        // days of history before a day can be tested
  spikeZ: 4,                 // robust z above which a day is a spike
  minIncrease: null,         // cents above the baseline median a spike must add (blank = 0)
  minSpreadCents: 100,       // floor for the robust spread (cents): flat/zero baselines need this much change per z unit
  dormantDailyCents: 100,    // an account whose baseline average per day is at or below this is dormant
  dormantWakeCents: 2500,    // a dormant account spending at least this in one day is reported
  newFamilyShare: 0.25,      // a new non-GPU compute family is reported when its peak day is at least this share of the account's baseline median day
  minNewResources: 10,       // resource-id churn: at least this many new resource ids in one day
  correlationHours: 24,      // +/- window for joining to Cloud Audit Log Hunter findings
};

const MITRE = (id) => ({ framework: "MITRE", id });
const C_MON = [{ framework: "NIST-800-53", id: "SI-4" }, { framework: "ISO27001", id: "A.8.16" }, { framework: "SOC2", id: "CC7.2" }];
const CTRL = {
  spike: [MITRE("T1496"), ...C_MON],
  gpu: [MITRE("T1496"), MITRE("T1578.002"), ...C_MON],
  family: [MITRE("T1578.002"), MITRE("T1496"), ...C_MON],
  region: [MITRE("T1535"), MITRE("T1578.002"), ...C_MON],
  egress: [MITRE("T1537"), MITRE("T1530"), { framework: "NIST-800-53", id: "SC-7" }, ...C_MON],
  serverless: [MITRE("T1496"), ...C_MON],
  dormant: [MITRE("T1078.004"), MITRE("T1496"), { framework: "NIST-800-53", id: "AC-2" }, ...C_MON],
  marketplace: [{ framework: "NIST-800-53", id: "SA-9" }, { framework: "ISO27001", id: "A.5.19" }, ...C_MON],
  churn: [MITRE("T1578.002"), ...C_MON],
};

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
const str = (v) => (v == null ? "" : String(v)).trim();
const low = (v) => str(v).toLowerCase();
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const uniq = (a) => Array.from(new Set(a.filter((x) => x !== "" && x != null))).sort(cmp);
const SEVS = ["info", "low", "medium", "high", "critical"];
const bump = (s) => SEVS[Math.min(SEVS.length - 1, SEVS.indexOf(s) + 1)];
const r2 = (x) => (Number.isFinite(x) ? Math.round(x * 100) / 100 : x > 0 ? 999 : 0);

/** Exact decimal string -> integer micro-units (1e-6) of the currency. NaN when unparseable. */
export function toMicros(v) {
  if (typeof v === "number") return Number.isFinite(v) ? Math.round(v * 1e6) : NaN;
  let t = str(v);
  if (!t) return NaN;
  let neg = false;
  if (/^\(.*\)$/.test(t)) { neg = true; t = t.slice(1, -1).trim(); }
  if (/^[-−]/.test(t)) { neg = !neg; t = t.slice(1); }
  t = t.replace(/[,\s]/g, "");
  const m = t.match(/(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?/);
  if (!m) return NaN;
  if (t.slice(0, m.index).includes("-")) neg = !neg;
  let out;
  if (m[2]) { const n = Number(m[0]); if (!Number.isFinite(n)) return NaN; out = Math.round(n * 1e6); }
  else {
    const [ip, fp = ""] = m[1].split(".");
    const f = (fp + "0000000").slice(0, 7);
    out = Number(ip || "0") * 1e6 + Number(f.slice(0, 6)) + (Number(f[6]) >= 5 ? 1 : 0);
  }
  return neg ? -out : out;
}
/** Micro-units -> integer cents (half away from zero). */
export const microsToCents = (m) => (m < 0 ? -Math.round(-m / 1e4) : Math.round(m / 1e4));
const CENT = 1e4;

/** Integer cents -> "1234.56 USD" (no locale, deterministic). */
export function fmtMoney(cents, cur) {
  const c = Math.round(Number(cents) || 0), s = c < 0 ? "-" : "", a = Math.abs(c);
  return s + Math.floor(a / 100) + "." + String(a % 100).padStart(2, "0") + (cur ? " " + cur : "");
}

/** Date-ish value -> "YYYY-MM-DD" (UTC). ISO, "YYYY-MM-DD hh:mm:ss UTC", offsets and US M/D/YYYY. */
export function dayOf(v) {
  const t = str(v);
  if (!t) return "";
  let m = t.match(/^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?\s*(Z|UTC|[+-]\d{2}:?\d{2})?)?/i);
  if (m) {
    const z = m[7];
    if (z && !/^(z|utc)$/i.test(z) && m[4] != null) {
      const off = z.replace(":", ""), sign = off[0] === "-" ? -1 : 1, mins = sign * (Number(off.slice(1, 3)) * 60 + Number(off.slice(3, 5)));
      const ms = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0)) - mins * 60000;
      return Number.isFinite(ms) ? new Date(ms).toISOString().slice(0, 10) : "";
    }
    return m[1] + "-" + m[2] + "-" + m[3];
  }
  m = t.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})/);
  if (m) return m[3] + "-" + m[1].padStart(2, "0") + "-" + m[2].padStart(2, "0");
  m = t.match(/^(\d{4})(\d{2})(\d{2})$/);
  if (m) return m[1] + "-" + m[2] + "-" + m[3];
  return "";
}
const dayNum = (d) => Math.floor(Date.UTC(+d.slice(0, 4), +d.slice(5, 7) - 1, +d.slice(8, 10)) / DAY);
const numDay = (n) => new Date(n * DAY).toISOString().slice(0, 10);

/** Median of a numeric array (copy sorted). */
export function median(a) {
  if (!a.length) return 0;
  const s = a.slice().sort((x, y) => x - y), h = s.length >> 1;
  return s.length % 2 ? s[h] : (s[h - 1] + s[h]) / 2;
}
/**
 * Robust baseline: median, MAD, and the spread used for z (1.4826 * MAD, falling back to
 * 1.2533 * mean absolute deviation when MAD is 0, never below `floor`).
 */
export function robust(values, floor = 0) {
  const med = median(values);
  const dev = values.map((x) => Math.abs(x - med));
  const mad = median(dev);
  const meanAd = dev.length ? dev.reduce((s, x) => s + x, 0) / dev.length : 0;
  let scale = 1.4826 * mad;
  if (!(scale > 0)) scale = 1.2533 * meanAd;
  if (!(scale > floor)) scale = floor;
  return { median: med, mad, scale, n: values.length };
}
/** Robust z of x against a baseline from robust(); Infinity-safe. */
export const robustZ = (x, b) => (b.scale > 0 ? (x - b.median) / b.scale : x > b.median ? Infinity : 0);

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------
const AWS_GPU = /^(p[2-6][a-z0-9]*|g[3-6][a-z0-9]*|gr6|inf[12][a-z]*|trn[12][a-z]*|dl[12][a-z]*)$/;
const AZ_GPU = /^N[CDVG]/i;
const GCP_GPU = /^(a2|a3|a4|g2|g4|gpu .*)$/;

/** Instance family + compute/gpu flags for one normalized record (provider-aware). */
export function classifyFamily(provider, r) {
  const sku = str(r.sku), it = low(r.instanceType);
  if (provider === "aws" || provider === "other") {
    let t = it;
    if (!t) { const m = sku.match(/(?:BoxUsage|SpotUsage|DedicatedUsage|HostBoxUsage|UnusedBox|DedicatedRes|HeavyUsage|Usage|Instance)[^:]*:((?:ml\.|db\.|cache\.)?[a-z][a-z0-9-]*\.[a-z0-9-]+)/i); if (m) t = m[1].toLowerCase(); }
    if (t && /\./.test(t)) {
      const parts = t.split(".");
      const pre = /^(ml|db|cache)$/.test(parts[0]) ? parts[0] + "." : "";
      const fam = pre ? parts[1] : parts[0];
      const full = pre + fam;
      if (fam) return { family: full, gpu: AWS_GPU.test(fam), compute: true };
    }
    if (provider === "aws") return { family: "", gpu: false, compute: false };
  }
  if (provider === "azure" || provider === "other") {
    const cat = low(r.service);
    if (provider === "azure" && !/virtual machines|cloud services|batch|machine learning/.test(cat)) return { family: "", gpu: false, compute: false };
    let fam = "";
    const sub = str(r.meterSub);
    if (sub) { const m = sub.match(/^([A-Za-z]+[0-9]*[A-Za-z]*(?:\s?v\d+)?)/); fam = m ? m[1].replace(/\s/g, "") : ""; if (/^(Virtual|Windows|Linux)$/i.test(fam)) fam = ""; }
    if (!fam) { const m = str(r.meterName).match(/^([A-Z]+)\d/); if (m) fam = m[1]; }
    if (!fam && it) { const m = it.match(/^standard_([a-z]+)/); if (m) fam = m[1].toUpperCase(); }
    if (fam) return { family: fam, gpu: AZ_GPU.test(fam), compute: true };
    if (provider === "azure") return { family: "", gpu: false, compute: /virtual machines/.test(cat) };
  }
  if (provider === "gcp" || provider === "other") {
    let m = sku.match(/^(?:Spot Preemptible |Preemptible |Spot |Commitment v\d+: )?(?:Nvidia |NVIDIA )?(.+?) GPU\b/);
    if (m) return { family: "gpu " + m[1].toLowerCase().replace(/^nvidia\s+/, ""), gpu: true, compute: true };
    m = sku.match(/^(?:Spot Preemptible |Preemptible |Spot |Commitment v\d+: )?([A-Z][0-9][A-Z0-9]*)\s+(?:AMD |Arm |Intel )?(?:Predefined |Custom |Memory-optimized |Compute-optimized )?(?:Extended )?Instance (?:Core|Ram)/i);
    if (m) { const fam = m[1].toLowerCase(); return { family: fam, gpu: GCP_GPU.test(fam), compute: true }; }
    if (it) { const fam = it.split("-")[0]; return { family: fam, gpu: GCP_GPU.test(fam), compute: true }; }
  }
  return { family: "", gpu: false, compute: false };
}

/** Egress (data transfer out) line? */
export function isEgress(provider, r) {
  const sku = str(r.sku), svc = low(r.service), mn = low(r.meterName), sub = low(r.meterSub);
  const aws = /DataTransfer-Out-Bytes|-AWS-Out-Bytes|CloudFront-Out-Bytes/i.test(sku);
  const az = svc === "bandwidth" && !/\b(in|ingress|data transfer in)\b/.test(mn + " " + sub);
  const gcp = /egress/i.test(sku) && !/ingress/i.test(sku);
  if (provider === "aws") return aws;
  if (provider === "azure") return az || (/egress|data transfer out/.test(mn) && !/ingress/.test(mn));
  if (provider === "gcp") return gcp;
  return aws || az || gcp;
}
/** Serverless / function line? */
export function isServerless(provider, r) {
  const svc = low(r.service), sku = str(r.sku);
  if (provider === "aws") return svc === "awslambda" || /^aws ?lambda$/.test(svc) || /Lambda-GB-Second|Lambda-Provisioned/i.test(sku);
  if (provider === "azure") return /^(functions|azure functions)$/.test(svc);
  if (provider === "gcp") return /^(cloud run|cloud functions|cloud run functions)$/.test(svc);
  return /lambda|^functions$|azure functions|cloud run|cloud functions/.test(svc);
}
/** Marketplace line? (needs a billing-entity / publisher-type column) */
export function isMarketplace(r) { return /marketplace/i.test(str(r.billingEntity)); }

const REGION_SKIP = /^(|global|none|noregion|unknown|unassigned|n\/a|all regions|multi-region|intercontinental|zone ?\d*)$/i;
/** Region key: lower case, spaces removed, AZ / zone suffix stripped. "" when not a real region. */
export function normRegion(provider, v, zone) {
  let r = low(v).replace(/\s+/g, "");
  if (!r && zone) r = low(zone);
  if (!r || REGION_SKIP.test(r)) return "";
  if (/^[a-z]{2}(-gov|-iso[a-z]?)?-[a-z]+-\d[a-z]$/.test(r)) r = r.slice(0, -1);   // us-east-1a -> us-east-1
  if (/^[a-z]+-[a-z]+\d-[a-z]$/.test(r)) r = r.slice(0, -2);                       // us-central1-a -> us-central1
  return r;
}
/** Account key used for joins. */
export function normAccount(provider, v) {
  const a = low(v);
  if (provider === "aws" && /^[\d-]{12,14}$/.test(a)) return a.replace(/-/g, "");
  return a;
}

// ---------------------------------------------------------------------------
// Format detection
// ---------------------------------------------------------------------------
const DATE_HDR = /^\d{4}-\d{2}(-\d{2})?$|^\d{1,2}\/\d{1,2}\/\d{4}$/;
const CUR_SYM = { "$": "USD", "€": "EUR", "£": "GBP", "¥": "JPY", "₹": "INR" };
function headerCurrency(h) {
  const m = String(h || "").match(/\(([^)]*)\)/);
  if (!m) return "";
  const x = m[1].trim();
  if (CUR_SYM[x]) return CUR_SYM[x];
  if (/^[A-Z]{3}$/.test(x)) return x;
  return "";
}

/**
 * Classify a header list. Returns { provider, format, label, confidence (0..1), cols, missing }.
 * Exact vendor header sets score high; alias-only matches are medium and show the mapping panel.
 */
export function classifyHeaders(headers) {
  const H = (headers || []).map(String);
  const N = new Set(H.map(normHeader));
  const has = (...xs) => xs.every((x) => N.has(normHeader(x)));
  // Cost Explorer: wide layouts.
  const first = H[0] || "";
  const restDates = H.slice(1).filter((h) => DATE_HDR.test(h.trim())).length;
  const dollarCols = H.slice(1).filter((h) => /\(\s*[$€£¥₹A-Z]{1,3}\s*\)\s*$/.test(h)).length;
  // normHeader folds "lineItem/UnblendedCost" and "line_item_unblended_cost" together; the raw "/" tells them apart.
  if (has("lineItem/UnblendedCost", "lineItem/UsageStartDate") && has("lineItem/UsageAccountId") && H.some((h) => /^lineItem\//i.test(h)))
    return withCols(H, { provider: "aws", format: "aws-cur", label: "AWS Cost and Usage Report (legacy)", confidence: 1 });
  if (has("line_item_unblended_cost", "line_item_usage_start_date") && has("line_item_usage_account_id"))
    return withCols(H, { provider: "aws", format: "aws-cur2", label: "AWS CUR 2.0 (Data Exports)", confidence: 1 });
  if (has("MeterCategory") && has("Date") && (has("CostInBillingCurrency") || has("Cost") || has("PreTaxCost")) && (has("SubscriptionId") || has("SubscriptionGuid")))
    return withCols(H, { provider: "azure", format: "azure-cost", label: "Azure cost details", confidence: has("CostInBillingCurrency") ? 1 : 0.7 });
  if (has("service.description", "usage_start_time", "cost") || has("service_description", "usage_start_time", "cost"))
    return withCols(H, { provider: "gcp", format: "gcp-billing", label: "GCP billing export (BigQuery)", confidence: has("project.id") || has("project_id") ? 1 : 0.7 });
  if (has("Service description", "SKU description") && (has("Usage start date") || has("Usage start time")))
    return withCols(H, { provider: "gcp", format: "gcp-cost-table", label: "GCP console cost table", confidence: 0.7 });
  if (H.length >= 2 && restDates >= 1 && restDates >= (H.length - 1) * 0.6)
    return { provider: "aws", format: "aws-ce-bydate", label: "AWS Cost Explorer (dates as columns)", confidence: 0.9, dimension: first, cols: {}, missing: [] };
  if (H.length >= 2 && dollarCols >= Math.max(1, (H.length - 1) * 0.6))
    return { provider: "aws", format: "aws-ce", label: "AWS Cost Explorer (" + (first || "Service") + " columns)", confidence: 0.9, dimension: first, cols: {}, missing: [] };
  const g = withCols(H, { provider: "other", format: "generic", label: "Generic billing table", confidence: 0.3 });
  if (g.cols.date && g.cols.cost && g.cols.account) g.confidence = 0.5;
  return g;
}
function withCols(H, d) {
  const cols = {};
  for (const k of Object.keys(COLUMNS)) { const h = findColumn(H, COLUMNS[k]); if (h) cols[k] = h; }
  // CUR legacy BlendedCost alias must not shadow UnblendedCost; already ordered. Cost table: prefer unrounded.
  const missing = ["date", "account", "service", "cost"].filter((k) => !cols[k]);
  return { ...d, cols, missing };
}

function looksLikeCloudtrail(o) { return o && typeof o === "object" && o.meta && o.meta.tool === "cloudtrail" && Array.isArray(o.findings); }

/**
 * Cheap detection for one file (header row only for CSV). Used by the UI files panel.
 * @returns {{ name, kind: "billing"|"cloudtrail"|"empty"|"unknown", provider, format, label, confidence, headers, cols, missing, bytes }}
 */
export function detectFile(name, text) {
  if (name && typeof name === "object") { text = name.text; name = name.name; }
  const t = String(text || "");
  const base = { name: str(name) || "input", bytes: t.length, headers: [], cols: {}, missing: [] };
  if (!t.trim()) return { ...base, kind: "empty", provider: "", format: "empty", label: "Empty", confidence: 0 };
  const fmt = sniff(t.slice(0, 65536)).format;
  if (fmt === "json" || fmt === "ndjson") {
    let first = null;
    if (fmt === "json" || /^\s*\{/.test(t) && t.length < 64 * 1048576) {
      try { const o = JSON.parse(t); if (looksLikeCloudtrail(o)) return { ...base, kind: "cloudtrail", provider: "", format: "cloudtrail-export", label: "Cloud Audit Log Hunter export (" + o.findings.length + " findings)", confidence: 1 }; first = Array.isArray(o) ? o[0] : o; } catch (_) { /* ndjson */ }
    }
    if (!first) { try { const line = t.slice(0, 1 << 20).split(/\r?\n/).find((l) => l.trim()); first = JSON.parse(line); } catch (_) { first = null; } }
    if (!first || typeof first !== "object") return { ...base, kind: "unknown", provider: "", format: "json", label: "Unrecognised JSON", confidence: 0 };
    const headers = Object.keys(flatten(first));
    const d = classifyHeaders(headers);
    return { ...base, ...d, kind: "billing", headers, format: d.format === "gcp-billing" ? "gcp-billing-json" : d.format, label: d.format === "gcp-billing" ? "GCP billing export (BigQuery JSON)" : d.label };
  }
  const nl = t.indexOf("\n");
  const headLine = (nl < 0 ? t : t.slice(0, nl + 1)) + "";
  const it = iterCsv(headLine + "\n", { header: false });
  const h = it.next();
  const headers = h.done ? [] : h.value.map((x) => String(x).replace(/^﻿/, "").trim());
  const d = classifyHeaders(headers);
  return { ...base, ...d, kind: "billing", headers };
}

// ---------------------------------------------------------------------------
// Record streaming
// ---------------------------------------------------------------------------
const EXCLUDE_LINE = /^(credit|refund|tax|edpdiscount|privateratediscount|bundleddiscount|savingsplannegation|discount|distributordiscount|rounding|roundingadjustment|purchase)$/i;

function rowGetter(cols, mapping) {
  const m = { ...cols, ...(mapping || {}) };
  for (const k of Object.keys(m)) if (!m[k]) delete m[k];
  return { m, get: (row, k) => (m[k] ? row[m[k]] : undefined) };
}

/**
 * Turn one parsed row into a normalized record (or null with a reason).
 * Record: { date, provider, account, accountName, service, sku, region, resourceId, family, gpu, compute,
 *           egress, serverless, marketplace, seller, usage, unit, micros, currency }
 */
export function normalizeRow(row, det, g, fileCurrency) {
  const p = det.provider === "other" ? (det.providerOverride || "other") : det.provider;
  const date = dayOf(g.get(row, "date"));
  if (!date) return { skip: "no usable date" };
  const lt = str(g.get(row, "lineType")).replace(/\s+/g, "");
  if (lt && EXCLUDE_LINE.test(lt)) return { skip: "line type " + lt + " (credits, refunds, tax and discounts are not usage)" };
  const micros = toMicros(g.get(row, "cost"));
  if (!Number.isFinite(micros)) return { skip: "no usable cost" };
  let account = str(g.get(row, "account"));
  const rid = str(g.get(row, "resourceId"));
  if (!account && p === "azure") { const m = rid.match(/\/subscriptions\/([^/]+)/i); if (m) account = m[1]; }
  if (!account) return { skip: "no account / subscription / project" };
  const r = {
    date, provider: p, account: p === "aws" ? normAccount("aws", account) : p === "azure" ? account.toLowerCase() : account,
    accountName: str(g.get(row, "accountName")),
    service: str(g.get(row, "service")) || "(unknown service)",
    sku: str(g.get(row, "sku")), meterSub: str(g.get(row, "meterSub")), meterName: str(g.get(row, "meterName")),
    instanceType: str(g.get(row, "instanceType")),
    region: normRegion(p, g.get(row, "region"), g.get(row, "zone")),
    resourceId: p === "azure" ? rid.toLowerCase() : rid,
    usage: Number(str(g.get(row, "usage")).replace(/,/g, "")) || 0, unit: str(g.get(row, "unit")),
    micros, currency: str(g.get(row, "currency")).toUpperCase() || fileCurrency || "",
    billingEntity: str(g.get(row, "billingEntity")), seller: str(g.get(row, "seller")),
  };
  if (p === "azure" && !r.sku) r.sku = [r.meterSub, r.meterName].filter(Boolean).join(" / ");
  const f = classifyFamily(p, r);
  r.family = f.family; r.gpu = f.gpu; r.compute = f.compute;
  r.egress = isEgress(p, r); r.serverless = isServerless(p, r); r.marketplace = isMarketplace(r);
  if (r.egress && !r.unit && p === "aws") r.unit = "GB";
  return r;
}

/** Unpivot a Cost Explorer CSV into records. */
function* costExplorerRecords(text, det, fileName, opts) {
  const it = iterCsv(text, { header: false });
  const h = it.next();
  if (h.done) return;
  const H = h.value.map((x) => String(x).replace(/^﻿/, "").trim());
  const dim = low(H[0]);
  const account = str((opts.ceAccount && opts.ceAccount[fileName]) || "") || "cost-explorer:" + fileName;
  const asRec = (date, label, cell, hdr) => {
    const d = dayOf(date);
    if (!d) return null;
    if (/^(total|.*\btotal\b.*)$/i.test(label)) return null;
    const micros = toMicros(cell);
    if (!Number.isFinite(micros) || micros === 0) return null;
    const cur = headerCurrency(hdr) || headerCurrency(H[H.length - 1]) || "USD";
    const name = label.replace(/\s*\([^)]*\)\s*$/, "").trim();
    const r = { date: d, provider: "aws", account, accountName: "", service: "(all services)", sku: "", meterSub: "", meterName: "", instanceType: "", region: "", resourceId: "", usage: 0, unit: "", micros, currency: cur, billingEntity: "", seller: "" };
    if (/linked ?account|account/.test(dim)) { const m = name.match(/(\d{12})/); r.account = m ? m[1] : name; }
    else if (/region/.test(dim)) r.region = normRegion("aws", name);
    else if (/instance ?type/.test(dim)) { r.instanceType = name; }
    else if (/usage ?type/.test(dim)) r.sku = name;
    else r.service = name;
    const f = classifyFamily("aws", r);
    r.family = f.family; r.gpu = f.gpu; r.compute = f.compute;
    r.egress = isEgress("aws", r); r.serverless = /lambda/i.test(r.service); r.marketplace = false;
    return r;
  };
  if (det.format === "aws-ce-bydate") {
    for (const row of it) {
      const label = str(row[0]);
      for (let i = 1; i < H.length; i++) { const r = asRec(H[i], label, row[i], H[0]); if (r) yield r; }
    }
  } else {
    for (const row of it) {
      const date = str(row[0]);
      for (let i = 1; i < H.length; i++) { const r = asRec(date, H[i], row[i], H[i]); if (r) yield r; }
    }
  }
}

function fileRecordIter(file, det, opts) {
  const text = String(file.text || "");
  if (det.format === "aws-ce" || det.format === "aws-ce-bydate") return { kind: "ce", it: costExplorerRecords(text, det, det.name, opts) };
  const fmt = det.format === "gcp-billing-json" || /json/.test(det.format) ? "json" : sniff(text.slice(0, 65536)).format;
  if (fmt === "json" || fmt === "ndjson") {
    let it;
    try { it = iterJson(text); } catch (_) { it = iterNdjson(text); }
    return { kind: "rows", it: (function* () { for (const o of it) if (o && typeof o === "object") yield flatten(o); })() };
  }
  return { kind: "rows", it: iterCsv(text) };
}

function toFiles(input) {
  if (input == null) return [];
  if (typeof input === "string") return [{ name: "input.csv", text: input }];
  if (Array.isArray(input)) return input.flatMap((x) => (typeof x === "string" ? [{ name: "input.csv", text: x }] : x && typeof x === "object" && "text" in x ? [{ name: str(x.name) || "input", text: String(x.text || "") }] : []));
  if (typeof input === "object" && "text" in input) return [{ name: str(input.name) || "input", text: String(input.text || "") }];
  if (typeof input === "object" && Array.isArray(input.files)) return toFiles(input.files);
  return [];
}

/**
 * Parse one or more billing files into normalized records (convenience / tests; analyze()
 * streams the same way without holding the records). Cloud Audit Log Hunter exports found
 * among the files are returned under `cloudtrail`.
 */
export function parseInput(input, opts = {}) {
  const files = toFiles(input);
  const records = [], skipped = [], meta = [], cloudtrail = [];
  let headers = [], format = files.length ? "" : "empty";
  for (const f of files) {
    const fm = { ...opts, onRecord: (r) => records.push(r) };
    const st = ingestFile(f, fm, skipped, cloudtrail);
    meta.push(st);
    if (!headers.length) headers = st.headers || [];
    format = format ? (format === st.format ? format : "mixed") : st.format;
  }
  return { format: format || "empty", headers, rows: records, records, skipped, files: meta, cloudtrail };
}

function ingestFile(f, o, skipped, cloudtrail, ctx, base = 0, total = 0) {
  const det = detectFile(f.name, f.text);
  const st = { name: det.name, kind: det.kind, provider: det.provider, format: det.format, label: det.label, confidence: det.confidence, headers: det.headers.slice(0, 200), rows: 0, used: 0, excluded: 0, excludedReasons: {}, firstDate: "", lastDate: "", currencies: [], columns: {}, missing: [] };
  if (det.kind === "empty") { skipped.push({ check: "file " + det.name, reason: "empty file" }); return st; }
  if (det.kind === "cloudtrail") {
    try { const j = JSON.parse(f.text); cloudtrail.push({ name: det.name, data: j }); st.rows = j.findings.length; } catch (e) { skipped.push({ check: "file " + det.name, reason: "could not read the Cloud Audit Log Hunter export: " + str(e && e.message) }); }
    return st;
  }
  if (det.kind === "unknown") { skipped.push({ check: "file " + det.name, reason: "not a recognised billing export" }); return st; }
  const mapping = (o.mappings && o.mappings[det.name]) || null;
  const prov = o.providers && o.providers[det.name];
  if (prov && det.provider === "other") det.providerOverride = prov;
  const g = rowGetter(det.cols, mapping);
  st.columns = { ...g.m };
  const ce = det.format === "aws-ce" || det.format === "aws-ce-bydate";
  if (!ce) {
    const miss = ["date", "account", "cost"].filter((k) => !g.m[k]);
    st.missing = ["date", "account", "service", "cost", "region", "resourceId", "sku", "currency"].filter((k) => !g.m[k]);
    if (miss.length) { skipped.push({ check: "file " + det.name, reason: "required column(s) not found or mapped: " + miss.map((k) => MAP_LABEL[k]).join(", ") }); return st; }
  } else st.missing = ["account", "region", "resourceId"];
  const fileCurrency = headerCurrency(g.m.cost || "") || "";
  const curs = new Set();
  const { kind, it } = fileRecordIter(f, det, o);
  let first = "", last = "";
  for (const x of it) {
    st.rows++;
    if (ctx && ctx.progress && (base + st.rows) % 1000 === 0) ctx.progress(Math.min(base + st.rows, total || base + st.rows), total || base + st.rows, "reading " + det.name + ": " + (st.rows) + " rows");
    const r = kind === "ce" ? x : normalizeRow(x, det, g, fileCurrency);
    if (r.skip) { st.excluded++; st.excludedReasons[r.skip] = (st.excludedReasons[r.skip] || 0) + 1; continue; }
    if (!r.currency) r.currency = "(unstated)";
    st.used++;
    curs.add(r.currency);
    if (!first || r.date < first) first = r.date;
    if (!last || r.date > last) last = r.date;
    o.onRecord(r, st);
  }
  st.firstDate = first; st.lastDate = last; st.currencies = Array.from(curs).sort(cmp);
  st.provider = det.providerOverride || det.provider;
  return st;
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------
const K = "\u0001";
const addMap = (m, k, v) => m.set(k, (m.get(k) || 0) + v);
function newAcct(r) {
  return {
    provider: r.provider, account: r.account, accountName: r.accountName, currency: r.currency,
    days: new Map(), services: new Map(), regions: new Map(), families: new Map(),
    egress: new Map(), egressUsage: new Map(), egressUnit: new Set(), serverless: new Map(), serverlessUsage: new Map(),
    market: new Map(), resFirst: new Map(), resDay: new Map(), hasRes: false, hasRegion: false, hasFamilyInput: false,
    rows: 0,
  };
}
function aggregate(acc, r) {
  const ak = r.provider + K + r.account + K + r.currency;
  let a = acc.accts.get(ak);
  if (!a) { a = newAcct(r); acc.accts.set(ak, a); }
  if (!a.accountName && r.accountName) a.accountName = r.accountName;
  a.rows++;
  const d = dayNum(r.date);
  const pv = acc.cover.get(r.provider) || { min: d, max: d };
  if (d < pv.min) pv.min = d; if (d > pv.max) pv.max = d;
  acc.cover.set(r.provider, pv);
  const dk = r.date + K + r.currency;
  const drow = acc.daily.get(dk) || { date: r.date, currency: r.currency, aws: 0, azure: 0, gcp: 0, other: 0 };
  drow[r.provider] = (drow[r.provider] || 0) + r.micros; acc.daily.set(dk, drow);
  addMap(a.days, d, r.micros);
  let s = a.services.get(r.service); if (!s) { s = new Map(); a.services.set(r.service, s); } addMap(s, d, r.micros);
  if (r.region) {
    a.hasRegion = true;
    let rg = a.regions.get(r.region); if (!rg) { rg = { days: new Map(), compute: new Map() }; a.regions.set(r.region, rg); }
    addMap(rg.days, d, r.micros); if (r.compute) addMap(rg.compute, d, r.micros);
  }
  if (r.family) {
    let fm = a.families.get(r.family); if (!fm) { fm = { gpu: r.gpu, compute: r.compute, days: new Map() }; a.families.set(r.family, fm); }
    if (r.gpu) fm.gpu = true;
    addMap(fm.days, d, r.micros);
  }
  if (r.instanceType || r.sku) a.hasFamilyInput = true;
  if (r.egress) { addMap(a.egress, d, r.micros); addMap(a.egressUsage, d, r.usage); if (r.unit) a.egressUnit.add(r.unit); }
  if (r.serverless) { addMap(a.serverless, d, r.micros); addMap(a.serverlessUsage, d, r.usage); }
  if (r.marketplace) {
    const name = r.seller || r.service;
    let mk = a.market.get(name); if (!mk) { mk = new Map(); a.market.set(name, mk); } addMap(mk, d, r.micros);
  }
  if (r.resourceId) {
    a.hasRes = true;
    const f0 = a.resFirst.get(r.resourceId);
    if (f0 == null || d < f0) a.resFirst.set(r.resourceId, d);
  }
  // per-day resource ledger for evidence (resource + usage type)
  let rd = a.resDay.get(d); if (!rd) { rd = new Map(); a.resDay.set(d, rd); }
  const rk = (r.resourceId || "(no resource id)") + K + r.sku + K + r.region;
  let e = rd.get(rk);
  if (!e) { e = { resourceId: r.resourceId || "", service: r.service, sku: r.sku, region: r.region, family: r.family, gpu: r.gpu, compute: r.compute, egress: r.egress, serverless: r.serverless, marketplace: r.marketplace, seller: r.seller, micros: 0, usage: 0, unit: r.unit }; rd.set(rk, e); }
  e.micros += r.micros; e.usage += r.usage;
}

// ---------------------------------------------------------------------------
// Detection helpers
// ---------------------------------------------------------------------------
/** Dense series for days [d0..d1] from a Map(day -> value). */
const dense = (m, d0, d1) => { const out = new Array(d1 - d0 + 1).fill(0); for (const [d, v] of m) if (d >= d0 && d <= d1) out[d - d0] += v; return out; };

/**
 * Evaluate a dense series. Returns per-day stats where testable and runs of flagged days.
 * floor/minInc are in the series' unit (micros for money, counts for churn).
 */
export function scanSeries(series, o, floor, minInc) {
  const points = [], runs = [];
  let cur = null;
  for (let i = 0; i < series.length; i++) {
    if (i < o.minHistoryDays) { points.push(null); if (cur) { runs.push(cur); cur = null; } continue; }
    const win = series.slice(Math.max(0, i - o.baselineDays), i);
    const b = robust(win, floor);
    const z = robustZ(series[i], b);
    const inc = series[i] - b.median;
    const p = { i, x: series[i], median: b.median, scale: b.scale, z, inc, n: win.length };
    points.push(p);
    const hit = z > o.spikeZ && inc > minInc;
    if (hit) { if (!cur) cur = { start: i, end: i, pts: [] }; cur.end = i; cur.pts.push(p); }
    else if (cur) { runs.push(cur); cur = null; }
  }
  if (cur) runs.push(cur);
  return { points, runs };
}

/**
 * Severity from z and amount: high needs z >= 3x threshold, observed >= 3x its baseline and an
 * increase at least the account's baseline day; medium needs z >= 2x threshold or a doubling,
 * and an increase of at least a quarter of the account's baseline day.
 */
export function spikeSeverity(z, obs, med, o, inc = obs - med, acctMed = med) {
  const ratio = med > 0 ? obs / med : Infinity;
  if (z >= 3 * o.spikeZ && ratio >= 3 && inc >= acctMed) return "high";
  if ((z >= 2 * o.spikeZ || ratio >= 2) && inc >= 0.25 * acctMed) return "medium";
  return "low";
}

// ---------------------------------------------------------------------------
// Cloud Audit Log Hunter correlation
// ---------------------------------------------------------------------------
const parseTs = (v) => { const t = Date.parse(str(v)); return Number.isFinite(t) ? t : NaN; };
/** Pull joinable facts from a cloudtrail export finding. */
export function ctFacts(f) {
  const ev = Array.isArray(f.evidence) ? f.evidence : [];
  const plat = low(f.platform);
  const accounts = new Set(), regions = new Set();
  for (const e of ev) { if (e && e.account) accounts.add(normAccount(low(e.platform) || plat, e.account)); if (e && e.region) { const r = normRegion(low(e.platform) || plat, e.region); if (r) regions.add(r); } }
  for (const a of f.assets || []) if (a && a.data && a.data.account) accounts.add(normAccount(low(a.data.platform) || plat, a.data.account));
  let first = parseTs(f.firstSeen), last = parseTs(f.lastSeen);
  if (!Number.isFinite(first) || !Number.isFinite(last)) {
    const ts = ev.map((e) => parseTs(e && e.time)).filter(Number.isFinite).sort((x, y) => x - y);
    if (ts.length) { if (!Number.isFinite(first)) first = ts[0]; if (!Number.isFinite(last)) last = ts[ts.length - 1]; }
  }
  if (Number.isFinite(first) && !Number.isFinite(last)) last = first;
  return { platform: plat, accounts: Array.from(accounts).sort(cmp), regions: Array.from(regions).sort(cmp), first, last };
}
/** Graph entity name the Cloud Audit Log Hunter gives this finding (sink-map naming). */
export const ctGraphName = (f) => str(f.title) + " (cloudtrail:" + findingKey("cloudtrail", f) + ")";

/** Gap in ms between an anomaly day window [startDay, endDay] (inclusive days) and [first, last]. */
export function windowGap(startDay, endDay, first, last) {
  const a0 = dayNum(startDay) * DAY, a1 = (dayNum(endDay) + 1) * DAY; // exclusive end
  if (last < a0) return a0 - last;
  if (first >= a1) return first - a1;
  return 0;
}

// ---------------------------------------------------------------------------
// analyze
// ---------------------------------------------------------------------------
function mergeOpts(opts) {
  const o = { ...DEFAULTS };
  for (const k of Object.keys(DEFAULTS)) {
    const v = opts && opts[k];
    if (v === null || v === "" || v === undefined) continue;
    const n = Number(v);
    if (Number.isFinite(n) && n >= 0) o[k] = n;
  }
  o.baselineDays = Math.max(1, Math.round(o.baselineDays));
  o.minHistoryDays = Math.max(1, Math.round(o.minHistoryDays));
  o.minIncrease = o.minIncrease == null ? 0 : o.minIncrease;
  o.mappings = (opts && opts.mappings) || {};
  o.providers = (opts && opts.providers) || {};
  o.ceAccount = (opts && opts.ceAccount) || {};
  o.cloudtrail = opts && opts.cloudtrail;
  return o;
}

const acctLabel = (a) => (a.provider === "aws" ? "AWS account " : a.provider === "azure" ? "Azure subscription " : a.provider === "gcp" ? "GCP project " : "Cloud account ") + a.account;

/**
 * Analyze billing exports.
 * @param {string|{name,text}[]|{records}} dataset raw files (streamed) or parseInput() output
 * @param {object} opts DEFAULTS overrides + { mappings, providers, ceAccount, cloudtrail }
 * @param {{progress?:Function}} [ctx]
 * @returns {{ summary, findings, tables, skipped, meta }}
 */
export function analyze(dataset, opts = {}, ctx) {
  const o = mergeOpts(opts);
  const skipped = [];
  const acc = { accts: new Map(), cover: new Map(), daily: new Map() };
  const cloudtrail = [];
  let filesMeta = [];
  let rows = 0;
  if (dataset && Array.isArray(dataset.records)) {
    for (const r of dataset.records) { aggregate(acc, r); rows++; }
    filesMeta = dataset.files || [];
    for (const c of dataset.cloudtrail || []) cloudtrail.push(c);
    for (const s of dataset.skipped || []) skipped.push(s);
  } else {
    const files = toFiles(dataset);
    const total = files.reduce((n, f) => n + Math.max(1, (String(f.text).match(/\n/g) || []).length), 0);
    let base = 0;
    for (const f of files) {
      const st = ingestFile(f, { ...o, onRecord: (r) => aggregate(acc, r) }, skipped, cloudtrail, ctx, base, total);
      base += st.rows; rows += st.used;
      filesMeta.push(st);
    }
  }
  if (o.cloudtrail) {
    try { const j = typeof o.cloudtrail === "string" ? JSON.parse(o.cloudtrail) : o.cloudtrail; if (looksLikeCloudtrail(j)) cloudtrail.push({ name: "opts.cloudtrail", data: j }); else skipped.push({ check: "correlation", reason: "the correlation input is not a Cloud Audit Log Hunter export (meta.tool must be \"cloudtrail\")" }); }
    catch (e) { skipped.push({ check: "correlation", reason: "could not read the correlation export: " + str(e && e.message) }); }
  }
  if (ctx && ctx.progress) ctx.progress(1, 1, "detecting anomalies");

  const findings = [];
  const accountsT = [], servicesT = [], regionsT = [], familiesT = [], timeline = [], seriesT = [];
  const minInc = o.minIncrease * CENT, floor = o.minSpreadCents * CENT;
  const accts = Array.from(acc.accts.values()).sort((x, y) => cmp(x.provider, y.provider) || cmp(x.account, y.account) || cmp(x.currency, y.currency));
  const curPerAcct = new Map();
  for (const a of accts) { const k = a.provider + K + a.account; curPerAcct.set(k, (curPerAcct.get(k) || 0) + 1); }
  const flagsBy = new Map(); // ak -> Set
  const maxZBy = new Map();
  const ak = (a) => a.provider + K + a.account + K + a.currency;
  const flag = (a, f, z) => { const k = ak(a); (flagsBy.get(k) || flagsBy.set(k, new Set()).get(k)).add(f); if (z != null && Number.isFinite(z)) maxZBy.set(k, Math.max(maxZBy.get(k) || 0, z)); };
  const checkState = { spike: 0, service: 0, gpu: 0, region: 0, egress: 0, serverless: 0, dormant: 0, marketplace: 0, churn: 0 };
  let insufficient = 0;

  const topResources = (a, d0, d1, pred) => {
    const sum = new Map();
    for (let d = d0; d <= d1; d++) {
      const rd = a.resDay.get(d); if (!rd) continue;
      for (const [k, e] of rd) {
        if (!pred(e)) continue;
        const kk = e.resourceId ? e.resourceId + K + e.sku : k;
        const x = sum.get(kk) || { resourceId: e.resourceId || "(no resource id)", service: e.service, sku: e.sku, region: e.region, family: e.family, micros: 0, usage: 0, unit: e.unit };
        x.micros += e.micros; x.usage += e.usage; sum.set(kk, x);
      }
    }
    const all = Array.from(sum.values()).sort((x, y) => y.micros - x.micros || cmp(x.resourceId, y.resourceId) || cmp(x.sku, y.sku));
    return {
      count: all.length,
      rows: all.slice(0, EVIDENCE_CAP).map((x) => ({ window: numDay(d0) + (d1 > d0 ? " to " + numDay(d1) : ""), resourceId: x.resourceId, service: x.service, sku: x.sku, region: x.region, family: x.family, costCents: microsToCents(x.micros), cost: fmtMoney(microsToCents(x.micros), a.currency), usage: Math.round(x.usage * 1000) / 1000, unit: x.unit })),
      regions: uniq(all.slice(0, EVIDENCE_CAP).map((x) => x.region)),
    };
  };

  const mk = (a, p) => {
    const regs = p.regions || [];
    const f = {
      id: p.id, title: p.title, severity: p.severity, confidence: p.confidence, category: p.category,
      provider: a.provider, account: a.account, accountName: a.accountName, currency: a.currency,
      scope: p.scope || "", windowStart: p.start, windowEnd: p.end,
      baselinePerDayCents: microsToCents(p.baseline || 0), observedCents: microsToCents(p.observed || 0), increaseCents: microsToCents(p.increase || 0),
      z: p.z == null ? null : r2(p.z), mitre: p.controls.filter((c) => c.framework === "MITRE").map((c) => c.id),
      regions: regs,
      description: p.description, recommendation: p.recommendation, controls: p.controls.map((c) => ({ ...c })),
      evidence: p.evidence.rows, evidenceCount: p.evidence.count, days: p.days || [],
      assets: [{ type: "ASSET", name: acctLabel(a), data: null }], tags: [TOOL_ID, a.provider, p.category].concat(p.tags || []),
      correlated: [],
    };
    findings.push(f);
    for (const d of p.days || []) timeline.push({ date: d.date, provider: a.provider, account: a.account, currency: a.currency, kind: p.category, scope: p.scope || "", observedCents: d.observedCents, baselineCents: d.baselineCents, z: d.z, findingId: p.id });
    return f;
  };
  const dayRows = (pts, d0) => pts.map((p) => ({ date: numDay(d0 + p.i), observedCents: microsToCents(p.x), baselineCents: microsToCents(p.median), z: r2(p.z) }));
  const runFacts = (run, d0) => {
    let peak = run.pts[0];
    let inc = 0, obs = 0;
    for (const p of run.pts) { if (p.z > peak.z) peak = p; inc += p.inc; obs += p.x; }
    return { start: numDay(d0 + run.start), end: numDay(d0 + run.end), peak, inc, obs, d0r: d0 + run.start, d1r: d0 + run.end };
  };
  const zTxt = (z) => (Number.isFinite(z) ? z.toFixed(1) : "very high (flat baseline)");
  const statTxt = (p, a) => "baseline median " + fmtMoney(microsToCents(p.median), a.currency) + "/day over " + p.n + " days, robust spread " + fmtMoney(microsToCents(p.scale), a.currency) + ", z " + zTxt(p.z) + " (threshold " + o.spikeZ + ")";

  for (const a of accts) {
    const cov = acc.cover.get(a.provider);
    const d0 = cov.min, d1 = cov.max, nDays = d1 - d0 + 1;
    const series = dense(a.days, d0, d1);
    const enough = nDays > o.minHistoryDays;
    if (!enough) insufficient++;
    const scan = enough ? scanSeries(series, o, floor, minInc) : { points: series.map(() => null), runs: [] };
    // tables: daily series with baseline band
    const lastPt = scan.points.filter(Boolean).pop();
    seriesT.push({
      provider: a.provider, account: a.account, accountName: a.accountName, currency: a.currency, start: numDay(d0),
      points: series.map((x, i) => { const p = scan.points[i]; return [numDay(d0 + i), microsToCents(x), p ? microsToCents(p.median) : null, p ? microsToCents(p.median + o.spikeZ * p.scale) : null]; }),
    });
    const totalMicros = series.reduce((s, x) => s + x, 0);
    const last7 = series.slice(-7).reduce((s, x) => s + x, 0);
    const baseWin = series.slice(Math.max(0, nDays - 7 - o.baselineDays), Math.max(0, nDays - 7));
    const baseMed = baseWin.length ? median(baseWin) : 0;

    // 1. account-level spend spike
    for (const run of scan.runs) {
      const rf = runFacts(run, d0);
      checkState.spike++;
      const sev = spikeSeverity(rf.peak.z, rf.peak.x, rf.peak.median, o);
      const ev = topResources(a, rf.d0r, rf.d1r, () => true);
      mk(a, {
        id: "spend-spike:" + a.provider + ":" + a.account + ":" + a.currency + ":" + rf.start, category: "spend-spike", severity: sev, confidence: "review",
        title: "Daily spend spike: " + acctLabel(a) + " (" + rf.start + (rf.end !== rf.start ? " to " + rf.end : "") + ")",
        scope: "all services", start: rf.start, end: rf.end, baseline: rf.peak.median, observed: rf.obs, increase: rf.inc, z: rf.peak.z, regions: ev.regions,
        description: "Total daily spend rose above the robust baseline on " + run.pts.length + " day(s). Peak " + numDay(d0 + rf.peak.i) + ": " + fmtMoney(microsToCents(rf.peak.x), a.currency) + " vs " + statTxt(rf.peak, a) + ". Increase over baseline across the window: " + fmtMoney(microsToCents(rf.inc), a.currency) + ". A spike is a pattern consistent with resource hijacking or runaway spend; it needs review, it is not proof of either.",
        recommendation: "Open the top resources below, confirm each with its owner and the change record. Terminate anything unexplained, rotate credentials used to create it and set a budget alert at the baseline level.",
        controls: CTRL.spike, evidence: ev, days: dayRows(run.pts, d0),
      });
      flag(a, "spike", rf.peak.z);
    }
    for (const p of scan.points) if (p && Number.isFinite(p.z)) maxZBy.set(ak(a), Math.max(maxZBy.get(ak(a)) || 0, p.z));

    // 2. per-service spike
    const svcNames = Array.from(a.services.keys()).sort(cmp);
    for (const svc of svcNames) {
      const s = dense(a.services.get(svc), d0, d1);
      const sc = enough ? scanSeries(s, o, floor, minInc) : { points: [], runs: [] };
      const tot = s.reduce((x, y) => x + y, 0);
      const sb = s.slice(Math.max(0, nDays - 7 - o.baselineDays), Math.max(0, nDays - 7));
      let mz = 0; for (const p of sc.points) if (p && Number.isFinite(p.z)) mz = Math.max(mz, p.z); else if (p && p.z === Infinity) mz = Infinity;
      const sflags = [];
      for (const run of sc.runs) {
        const rf = runFacts(run, d0);
        checkState.service++;
        if (svcNames.length === 1) { sflags.push("spike"); continue; } // same series as the account spike
        sflags.push("spike");
        const ev = topResources(a, rf.d0r, rf.d1r, (e) => e.service === svc);
        mk(a, {
          id: "service-spike:" + a.provider + ":" + a.account + ":" + a.currency + ":" + svc + ":" + rf.start, category: "service-spike", severity: spikeSeverity(rf.peak.z, rf.peak.x, rf.peak.median, o, rf.peak.inc, scan.points[rf.peak.i] ? scan.points[rf.peak.i].median : rf.peak.median), confidence: "review",
          title: "Service spend spike: " + svc + " in " + acctLabel(a) + " (" + rf.start + (rf.end !== rf.start ? " to " + rf.end : "") + ")",
          scope: svc, start: rf.start, end: rf.end, baseline: rf.peak.median, observed: rf.obs, increase: rf.inc, z: rf.peak.z, regions: ev.regions,
          description: svc + " spend rose above its robust baseline on " + run.pts.length + " day(s). Peak " + numDay(d0 + rf.peak.i) + ": " + fmtMoney(microsToCents(rf.peak.x), a.currency) + " vs " + statTxt(rf.peak, a) + ". Increase: " + fmtMoney(microsToCents(rf.inc), a.currency) + ". Pattern consistent with resource hijacking or runaway spend; needs review.",
          recommendation: "Identify who created the top " + svc + " resources below (Cloud Audit Log Hunter or the provider's activity log), confirm the business reason and tag the owner. Remove unexplained resources.",
          controls: CTRL.spike, evidence: ev, days: dayRows(run.pts, d0),
        });
      }
      servicesT.push({ provider: a.provider, account: a.account, currency: a.currency, service: svc, totalCents: microsToCents(tot), last7Cents: microsToCents(s.slice(-7).reduce((x, y) => x + y, 0)), baselinePerDayCents: microsToCents(sb.length ? median(sb) : 0), maxZ: r2(mz), flags: sflags.sort(cmp) });
    }

    // 3. new GPU / accelerator families and new compute families
    const fams = Array.from(a.families.entries()).map(([name, fm]) => {
      let f0 = Infinity, f1 = -Infinity, tot = 0, peak = 0;
      for (const [d, v] of fm.days) if (v !== 0) { if (d < f0) f0 = d; if (d > f1) f1 = d; tot += v; if (v > peak) peak = v; }
      return { name, gpu: fm.gpu, compute: fm.compute, f0, f1, tot, peak };
    }).filter((x) => Number.isFinite(x.f0)).sort((x, y) => x.f0 - y.f0 || cmp(x.name, y.name));
    const famNew = new Map();
    for (const fm of fams) {
      const hist = fm.f0 - d0;
      const isNew = hist >= o.minHistoryDays;
      famNew.set(fm.name, isNew);
      if (!isNew) continue;
      const earlierGpu = fams.filter((x) => x.gpu && x.f0 < fm.f0).map((x) => x.name);
      const baseSlice = series.slice(Math.max(0, fm.f0 - d0 - o.baselineDays), fm.f0 - d0);
      const bmed = median(baseSlice);
      if (fm.gpu) {
        checkState.gpu++;
        const ev = topResources(a, fm.f0, fm.f1, (e) => e.family === fm.name);
        const sev = earlierGpu.length ? "medium" : "high";
        mk(a, {
          id: "gpu-family:" + a.provider + ":" + a.account + ":" + a.currency + ":" + fm.name, category: "gpu-family", severity: sev, confidence: earlierGpu.length ? "review" : "likely",
          title: "New GPU / accelerator family " + fm.name + " in " + acctLabel(a),
          scope: fm.name, start: numDay(fm.f0), end: numDay(fm.f1), baseline: bmed, observed: fm.tot, increase: fm.tot, z: null, regions: ev.regions, tags: ["gpu"],
          description: "Accelerator family " + fm.name + " first billed on " + numDay(fm.f0) + " after " + hist + " days of history " + (earlierGpu.length ? "(the account already used GPU families " + earlierGpu.join(", ") + ")" : "with no GPU or accelerator usage in the baseline") + ". Spend on it: " + fmtMoney(microsToCents(fm.tot), a.currency) + " through " + numDay(fm.f1) + " (peak day " + fmtMoney(microsToCents(fm.peak), a.currency) + "). New GPU capacity is the most common footprint of crypto-mining with stolen cloud credentials; this is a pattern match that needs review.",
          recommendation: "Confirm the GPU instances with their owner and a change ticket. If unknown: stop the instances (keep the disks for forensics), find the creating principal in the audit log, rotate its credentials, and restrict GPU instance types with an SCP / Azure Policy / organization policy.",
          controls: CTRL.gpu, evidence: ev, days: [{ date: numDay(fm.f0), observedCents: microsToCents(fm.peak), baselineCents: microsToCents(bmed), z: null }],
        });
        flag(a, "new-gpu");
      } else if (fm.compute) {
        const need = Math.max(minInc, o.newFamilyShare * bmed);
        if (fm.peak >= need && fm.peak > 0) {
          checkState.gpu++;
          const ev = topResources(a, fm.f0, fm.f1, (e) => e.family === fm.name);
          mk(a, {
            id: "new-family:" + a.provider + ":" + a.account + ":" + a.currency + ":" + fm.name, category: "new-family", severity: "medium", confidence: "review",
            title: "New compute family " + fm.name + " with large spend in " + acctLabel(a),
            scope: fm.name, start: numDay(fm.f0), end: numDay(fm.f1), baseline: bmed, observed: fm.tot, increase: fm.tot, z: null, regions: ev.regions,
            description: "Instance family " + fm.name + " first billed on " + numDay(fm.f0) + " after " + hist + " days of history. Its peak day (" + fmtMoney(microsToCents(fm.peak), a.currency) + ") is at least " + Math.round(o.newFamilyShare * 100) + "% of the account's baseline median day (" + fmtMoney(microsToCents(bmed), a.currency) + "). Sudden large compute in a new family is consistent with unauthorised instance creation; needs review.",
            recommendation: "Confirm the new instances with their owner; if unexplained, stop them and trace the creating principal in the audit log.",
            controls: CTRL.family, evidence: ev, days: [{ date: numDay(fm.f0), observedCents: microsToCents(fm.peak), baselineCents: microsToCents(bmed), z: null }],
          });
          flag(a, "new-family");
        }
      }
    }
    for (const fm of fams) familiesT.push({ provider: a.provider, account: a.account, currency: a.currency, family: fm.name, gpu: fm.gpu, compute: fm.compute, totalCents: microsToCents(fm.tot), firstSeen: numDay(fm.f0), lastSeen: numDay(fm.f1), isNew: famNew.get(fm.name) });

    // 4. new regions
    const regs = Array.from(a.regions.entries()).map(([name, rg]) => {
      let f0 = Infinity, f1 = -Infinity, tot = 0, ctot = 0;
      for (const [d, v] of rg.days) if (v !== 0) { if (d < f0) f0 = d; if (d > f1) f1 = d; tot += v; }
      for (const [, v] of rg.compute) ctot += v;
      return { name, f0, f1, tot, ctot };
    }).filter((x) => Number.isFinite(x.f0)).sort((x, y) => x.f0 - y.f0 || cmp(x.name, y.name));
    for (const rg of regs) {
      const hist = rg.f0 - d0;
      const isNew = hist >= o.minHistoryDays;
      regionsT.push({ provider: a.provider, account: a.account, currency: a.currency, region: rg.name, totalCents: microsToCents(rg.tot), computeCents: microsToCents(rg.ctot), firstSeen: numDay(rg.f0), lastSeen: numDay(rg.f1), isNew });
      if (!isNew) continue;
      if (rg.tot <= minInc || rg.tot <= 0) continue;
      checkState.region++;
      const before = regs.filter((x) => x.f0 < rg.f0).map((x) => x.name);
      const compute = rg.ctot > 0;
      const ev = topResources(a, rg.f0, rg.f1, (e) => e.region === rg.name);
      mk(a, {
        id: "new-region:" + a.provider + ":" + a.account + ":" + a.currency + ":" + rg.name, category: "new-region", severity: compute ? "high" : "low", confidence: compute ? "likely" : "review",
        title: "Spend in a new region " + rg.name + " in " + acctLabel(a) + (compute ? " (compute)" : ""),
        scope: rg.name, start: numDay(rg.f0), end: numDay(rg.f1), baseline: 0, observed: rg.tot, increase: rg.tot, z: null, regions: [rg.name], tags: compute ? ["new-region", "compute"] : ["new-region"],
        description: "Region " + rg.name + " first billed on " + numDay(rg.f0) + " after " + hist + " days of history in " + (before.length ? before.join(", ") : "no other region") + ". Spend there: " + fmtMoney(microsToCents(rg.tot), a.currency) + (compute ? ", of which compute " + fmtMoney(microsToCents(rg.ctot), a.currency) : "") + ". Attackers launch resources in regions the owner does not watch (MITRE T1535); a pattern match that needs review.",
        recommendation: "Confirm the resources in " + rg.name + " with their owner. Deny unused regions with an SCP (aws:RequestedRegion) / Azure Policy allowed locations / GCP resource-location constraint and enable billing alerts per region.",
        controls: CTRL.region, evidence: ev, days: [{ date: numDay(rg.f0), observedCents: microsToCents(rg.tot), baselineCents: 0, z: null }],
      });
      flag(a, "new-region");
    }

    // 5. egress spike
    if (enough && a.egress.size) {
      const s = dense(a.egress, d0, d1), us = dense(a.egressUsage, d0, d1);
      const sc = scanSeries(s, o, floor, minInc);
      for (const run of sc.runs) {
        const rf = runFacts(run, d0);
        checkState.egress++;
        const ratio = rf.peak.median > 0 ? rf.peak.x / rf.peak.median : Infinity;
        const ev = topResources(a, rf.d0r, rf.d1r, (e) => e.egress);
        const vol = run.pts.reduce((x, p) => x + us[p.i], 0);
        const unit = Array.from(a.egressUnit).sort(cmp).join("/");
        mk(a, {
          id: "egress-spike:" + a.provider + ":" + a.account + ":" + a.currency + ":" + rf.start, category: "egress-spike", severity: ratio >= 3 ? "high" : "medium", confidence: "review",
          title: "Data-transfer-out (egress) spike in " + acctLabel(a) + " (" + rf.start + (rf.end !== rf.start ? " to " + rf.end : "") + ")",
          scope: "egress", start: rf.start, end: rf.end, baseline: rf.peak.median, observed: rf.obs, increase: rf.inc, z: rf.peak.z, regions: ev.regions, tags: ["egress"],
          description: "Egress charges peaked at " + fmtMoney(microsToCents(rf.peak.x), a.currency) + " on " + numDay(d0 + rf.peak.i) + " vs " + statTxt(rf.peak, a) + (vol ? "; billed volume in the window " + Math.round(vol * 100) / 100 + (unit ? " " + unit : "") : "") + ". An egress spike is a signal of bulk data leaving the account (MITRE T1537 / T1530) or of bandwidth hijacking; needs review.",
          recommendation: "Find the resources and destinations behind the transfer (VPC flow logs, storage access logs, CDN logs). If unexplained, block the path, preserve logs and treat the data as potentially exposed.",
          controls: CTRL.egress, evidence: ev, days: dayRows(run.pts, d0),
        });
        flag(a, "egress", rf.peak.z);
      }
    }

    // 6. serverless burst
    if (enough && a.serverless.size) {
      const s = dense(a.serverless, d0, d1);
      const sc = scanSeries(s, o, floor, minInc);
      for (const run of sc.runs) {
        const rf = runFacts(run, d0);
        checkState.serverless++;
        const ev = topResources(a, rf.d0r, rf.d1r, (e) => e.serverless);
        mk(a, {
          id: "serverless-burst:" + a.provider + ":" + a.account + ":" + a.currency + ":" + rf.start, category: "serverless-burst", severity: "medium", confidence: "review",
          title: "Serverless burst in " + acctLabel(a) + " (" + rf.start + (rf.end !== rf.start ? " to " + rf.end : "") + ")",
          scope: "serverless", start: rf.start, end: rf.end, baseline: rf.peak.median, observed: rf.obs, increase: rf.inc, z: rf.peak.z, regions: ev.regions,
          description: "Function / serverless charges (invocations, GB-seconds) peaked at " + fmtMoney(microsToCents(rf.peak.x), a.currency) + " on " + numDay(d0 + rf.peak.i) + " vs " + statTxt(rf.peak, a) + ". Consistent with abuse of functions for compute or a runaway trigger loop; needs review.",
          recommendation: "Check the top functions below for new deployments, recursive triggers or public invocation URLs; set concurrency limits and budget alerts.",
          controls: CTRL.serverless, evidence: ev, days: dayRows(run.pts, d0),
        });
        flag(a, "serverless", rf.peak.z);
      }
    }

    // 7. dormant account waking up
    if (enough) {
      for (let i = o.minHistoryDays; i < series.length; i++) {
        const win = series.slice(Math.max(0, i - o.baselineDays), i);
        const avg = win.reduce((x, y) => x + y, 0) / win.length;
        if (avg > o.dormantDailyCents * CENT) continue;
        if (series[i] < o.dormantWakeCents * CENT || series[i] - avg <= minInc) continue;
        let j = i; while (j + 1 < series.length && series[j + 1] >= o.dormantWakeCents * CENT) j++;
        checkState.dormant++;
        const tot = series.slice(i, j + 1).reduce((x, y) => x + y, 0);
        const ev = topResources(a, d0 + i, d0 + j, () => true);
        mk(a, {
          id: "dormant:" + a.provider + ":" + a.account + ":" + a.currency + ":" + numDay(d0 + i), category: "dormant-account", severity: "high", confidence: "likely",
          title: "Dormant " + acctLabel(a).replace(/^(AWS|Azure|GCP|Cloud) /, "$1 ") + " started spending (" + numDay(d0 + i) + ")",
          scope: "all services", start: numDay(d0 + i), end: numDay(d0 + j), baseline: avg, observed: tot, increase: tot - avg * (j - i + 1), z: null, regions: ev.regions, tags: ["dormant"],
          description: "Average spend over the " + win.length + " days before " + numDay(d0 + i) + " was " + fmtMoney(microsToCents(avg), a.currency) + "/day (dormant threshold " + fmtMoney(o.dormantDailyCents, a.currency) + "). From " + numDay(d0 + i) + " to " + numDay(d0 + j) + " it spent " + fmtMoney(microsToCents(tot), a.currency) + " (wake threshold " + fmtMoney(o.dormantWakeCents, a.currency) + "/day). Unused accounts and projects are a favoured target for stolen credentials because nobody watches them; needs review.",
          recommendation: "Confirm with the account owner whether the account is in use. If not: stop all resources, review IAM users / keys / service principals in it, and close or quarantine the account (SCP deny-all / disable the subscription or project).",
          controls: CTRL.dormant, evidence: ev, days: series.slice(i, j + 1).map((x, k) => ({ date: numDay(d0 + i + k), observedCents: microsToCents(x), baselineCents: microsToCents(avg), z: null })),
        });
        flag(a, "dormant");
        i = j;
      }
    }

    // 8. marketplace charges appearing
    for (const [name, m] of Array.from(a.market.entries()).sort((x, y) => cmp(x[0], y[0]))) {
      let f0 = Infinity, f1 = -Infinity, tot = 0;
      for (const [d, v] of m) if (v !== 0) { if (d < f0) f0 = d; if (d > f1) f1 = d; tot += v; }
      if (!Number.isFinite(f0) || f0 - d0 < o.minHistoryDays || tot <= minInc) continue;
      checkState.marketplace++;
      const ev = topResources(a, f0, f1, (e) => e.marketplace && (e.seller || e.service) === name);
      mk(a, {
        id: "marketplace:" + a.provider + ":" + a.account + ":" + a.currency + ":" + name, category: "marketplace", severity: "medium", confidence: "review",
        title: "New marketplace charge: " + name + " in " + acctLabel(a),
        scope: name, start: numDay(f0), end: numDay(f1), baseline: 0, observed: tot, increase: tot, z: null, regions: ev.regions,
        description: "Third-party marketplace product " + name + " first billed on " + numDay(f0) + " after " + (f0 - d0) + " days of history; " + fmtMoney(microsToCents(tot), a.currency) + " so far. New marketplace subscriptions bypass normal procurement; needs review.",
        recommendation: "Confirm the subscription was approved through procurement and vendor review; restrict marketplace purchases to an approved private catalogue.",
        controls: CTRL.marketplace, evidence: ev, days: [{ date: numDay(f0), observedCents: microsToCents(tot), baselineCents: 0, z: null }],
      });
      flag(a, "marketplace");
    }

    // 9. resource-id churn
    if (enough && a.hasRes) {
      const newPer = new Map();
      for (const [, d] of a.resFirst) if (d > d0) addMap(newPer, d, 1);
      const s = dense(newPer, d0, d1);
      const sc = scanSeries(s, o, 1, 0);
      for (const run of sc.runs) {
        const pts = run.pts.filter((p) => p.x >= o.minNewResources);
        if (!pts.length) continue;
        checkState.churn++;
        const r0 = d0 + pts[0].i, r1 = d0 + pts[pts.length - 1].i;
        const newIds = new Set(); for (const [id, d] of a.resFirst) if (d >= r0 && d <= r1) newIds.add(id);
        const ev = topResources(a, r0, r1, (e) => newIds.has(e.resourceId));
        const peak = pts.reduce((m, p) => (p.x > m.x ? p : m), pts[0]);
        mk(a, {
          id: "resource-churn:" + a.provider + ":" + a.account + ":" + a.currency + ":" + numDay(r0), category: "resource-churn", severity: "medium", confidence: "review",
          title: "Unusual number of new resources in " + acctLabel(a) + " (" + numDay(r0) + (r1 !== r0 ? " to " + numDay(r1) : "") + ")",
          scope: "resources", start: numDay(r0), end: numDay(r1), baseline: 0, observed: ev.rows.reduce((x, y) => x + y.costCents * CENT, 0), increase: 0, z: peak.z, regions: ev.regions,
          description: newIds.size + " resource ids were billed for the first time (peak " + peak.x + " on " + numDay(d0 + peak.i) + " vs a median of " + peak.median + " new ids/day, z " + zTxt(peak.z) + ", minimum " + o.minNewResources + "). Mass creation is consistent with automated abuse of stolen credentials; needs review.",
          recommendation: "List the creating principals for these resources in the audit log and confirm the deployment that explains them.",
          controls: CTRL.churn, evidence: ev, days: pts.map((p) => ({ date: numDay(d0 + p.i), observedCents: 0, baselineCents: 0, z: r2(p.z), newResources: p.x })),
        });
        flag(a, "churn", peak.z);
      }
    }

    accountsT.push({
      provider: a.provider, account: a.account, accountName: a.accountName, currency: a.currency, days: nDays, firstDate: numDay(d0), lastDate: numDay(d1),
      totalCents: microsToCents(totalMicros), baselinePerDayCents: microsToCents(baseMed), last7Cents: microsToCents(last7), lastDayCents: microsToCents(series[series.length - 1]),
      maxZ: r2(maxZBy.get(ak(a)) || 0), status: enough ? "tested" : "insufficient history (" + nDays + " of " + (o.minHistoryDays + 1) + " days)",
      flags: [], findings: 0, multiCurrency: curPerAcct.get(a.provider + K + a.account) > 1,
      _ref: a, _cur: lastPt ? microsToCents(lastPt.median) : 0,
    });
  }

  // skipped / limited checks (column-driven, never guessed)
  const billing = filesMeta.filter((f) => f.kind === "billing" && f.used > 0);
  const anyAcct = accts.length > 0;
  if (anyAcct && insufficient === accts.length) skipped.push({ check: "spend-spike", reason: "every account has at most " + Math.max(...accts.map((a) => { const c = acc.cover.get(a.provider); return c.max - c.min + 1; })) + " days of data; " + (o.minHistoryDays + 1) + " are needed (minimum history " + o.minHistoryDays + " days + the tested day)" });
  else if (insufficient) skipped.push({ check: "spend-spike", reason: insufficient + " account series have fewer than " + (o.minHistoryDays + 1) + " days and were not tested" });
  const noCol = (k) => billing.filter((f) => !/^aws-ce/.test(f.format) && !(f.columns || {})[k]).map((f) => f.name);
  const ceFiles = billing.filter((f) => /^aws-ce/.test(f.format)).map((f) => f.name);
  const lacks = (k, check, why) => { const l = noCol(k).concat(k === "billingEntity" || k === "resourceId" ? ceFiles : []); if (l.length) skipped.push({ check, reason: why + ": " + l.join(", ") }); };
  if (anyAcct) {
    lacks("region", "new-region", "no region column in");
    lacks("resourceId", "resource-churn", "no resource id column in");
    lacks("billingEntity", "marketplace", "no billing-entity / publisher-type column (marketplace marker) in");
    if (billing.some((f) => f.provider === "aws" && !/^aws-ce/.test(f.format) && !(f.columns || {}).sku && !(f.columns || {}).instanceType)) skipped.push({ check: "gpu-family", reason: "AWS file(s) without usage type or instance type: " + billing.filter((f) => f.provider === "aws" && !(f.columns || {}).sku && !(f.columns || {}).instanceType).map((f) => f.name).join(", ") });
    if (ceFiles.length) skipped.push({ check: "per-account checks", reason: "Cost Explorer exports carry no account, region or resource columns unless grouped by them; GPU, egress and region checks only run on the dimension the export was grouped by: " + ceFiles.join(", ") });
  }
  if (!anyAcct && billing.length === 0 && !skipped.some((s) => /^file /.test(s.check))) skipped.push({ check: "input", reason: "no billing rows to analyze" });

  // correlation with the Cloud Audit Log Hunter export
  const correlations = [];
  let ctTotal = 0, ctJoinable = 0;
  if (cloudtrail.length) {
    const W = o.correlationHours * 3600000;
    const ctFindings = [];
    for (const c of cloudtrail) for (const f of c.data.findings || []) { ctTotal++; const fx = ctFacts(f); if (fx.accounts.length && Number.isFinite(fx.first)) { ctJoinable++; ctFindings.push({ f, fx, file: c.name }); } }
    if (ctTotal && !ctJoinable) skipped.push({ check: "correlation", reason: "no finding in the Cloud Audit Log Hunter export carries an account and a time" });
    const ctOut = new Map();
    for (const an of findings) {
      for (const { f, fx } of ctFindings) {
        if (fx.platform && ["aws", "azure", "gcp"].includes(fx.platform) && fx.platform !== an.provider) continue;
        if (!fx.accounts.includes(normAccount(an.provider, an.account))) continue;
        const gap = windowGap(an.windowStart, an.windowEnd, fx.first, fx.last);
        if (gap > W) continue;
        const regionCompared = an.regions.length > 0 && fx.regions.length > 0;
        if (regionCompared && !an.regions.some((r) => fx.regions.includes(r))) continue;
        const gname = ctGraphName(f);
        correlations.push({ anomalyId: an.id, anomalyTitle: an.title, cloudtrailId: str(f.id), cloudtrailTitle: str(f.title), cloudtrailSeverity: str(f.severity), account: an.account, provider: an.provider, regions: regionCompared ? an.regions.filter((r) => fx.regions.includes(r)) : [], regionCompared, gapHours: Math.round(gap / 36000) / 100, cloudtrailFirstSeen: str(f.firstSeen), cloudtrailLastSeen: str(f.lastSeen), graphName: gname });
        an.correlated.push({ id: str(f.id), title: str(f.title), severity: str(f.severity), graphName: gname });
        an.evidence.unshift({ correlatedWith: "Cloud Audit Log Hunter: " + str(f.title), cloudtrailSeverity: str(f.severity), firstSeen: str(f.firstSeen), lastSeen: str(f.lastSeen), account: an.account, region: regionCompared ? an.regions.filter((r) => fx.regions.includes(r)).join(", ") : "(not compared)", gapHours: Math.round(gap / 36000) / 100, graphEntity: gname });
        const key = str(f.id) || gname;
        const cur = ctOut.get(key) || { f, fx, anomalies: [] };
        cur.anomalies.push(an);
        ctOut.set(key, cur);
      }
    }
    for (const an of findings) {
      if (!an.correlated.length) continue;
      an.severity = bump(an.severity);
      if (an.confidence === "review") an.confidence = "likely";
      if (an.evidence.length > EVIDENCE_CAP) an.evidence = an.evidence.slice(0, EVIDENCE_CAP);
      an.evidenceCount += an.correlated.length;
      an.tags.push("correlated");
      an.description += " Correlated with " + an.correlated.length + " Cloud Audit Log Hunter finding(s) on the same account" + " within " + o.correlationHours + " h: " + an.correlated.map((c) => c.title).join("; ") + ". Severity raised one step.";
      for (const [, x] of ctOut) if (x.anomalies.includes(an)) for (const as of x.f.assets || []) if (as && as.type === "IDENTITY" && as.name && !an.assets.some((y) => y.type === "IDENTITY" && y.name === as.name) && an.assets.length < 12) an.assets.push({ type: "IDENTITY", name: str(as.name) });
    }
    for (const [key, x] of Array.from(ctOut.entries()).sort((p, q) => cmp(p[0], q[0]))) {
      const f = x.f, ans = x.anomalies.slice().sort((p, q) => cmp(p.id, q.id));
      const sev = bump(SEV_RANK[low(f.severity)] != null ? low(f.severity) : "medium");
      const accts2 = uniq(ans.map((an) => an.provider + ":" + an.account));
      const assets = [];
      for (const an of ans) if (!assets.some((y) => y.name === an.assets[0].name)) assets.push({ type: "ASSET", name: an.assets[0].name, data: null });
      for (const as of f.assets || []) if (as && as.name && ["IDENTITY", "IP", "ASSET"].includes(str(as.type).toUpperCase()) && assets.length < 20) assets.push({ type: str(as.type).toUpperCase(), name: str(as.name) });
      const ctEv = (Array.isArray(f.evidence) ? f.evidence : []).slice(0, EVIDENCE_CAP - ans.length).map((e) => ({ time: str(e.time), account: str(e.account), region: str(e.region), principal: str(e.principal), action: str(e.action), ip: str(e.ip), status: str(e.status) }));
      const ctrls = (Array.isArray(f.controls) && f.controls.length ? f.controls : []).map((c) => ({ framework: str(c.framework), id: str(c.id) })).filter((c) => c.id);
      for (const m of CTRL.spike) if (!ctrls.some((c) => c.framework === m.framework && c.id === m.id)) ctrls.push({ ...m });
      findings.push({
        id: "correlated:" + key, title: "Audit finding coincides with a spend anomaly: " + str(f.title), severity: sev, confidence: "likely", category: "correlated-audit",
        provider: ans[0].provider, account: ans[0].account, accountName: ans[0].accountName, currency: ans[0].currency, scope: "cloudtrail", windowStart: str(f.firstSeen).slice(0, 10), windowEnd: str(f.lastSeen).slice(0, 10),
        baselinePerDayCents: 0, observedCents: 0, increaseCents: ans.reduce((s, an) => Math.max(s, an.currency === ans[0].currency ? an.increaseCents : 0), 0), z: null, mitre: uniq((f.mitre || []).concat(ctrls.filter((c) => c.framework === "MITRE").map((c) => c.id))), regions: x.fx.regions,
        description: "The Cloud Audit Log Hunter finding \"" + str(f.title) + "\" (" + str(f.severity) + ", " + str(f.firstSeen) + " to " + str(f.lastSeen) + ") falls within " + o.correlationHours + " h of " + ans.length + " spend anomal" + (ans.length === 1 ? "y" : "ies") + " on " + accts2.join(", ") + ". Severity raised one step from the audit finding because the activity has a matching cost footprint. Correlation is time + account (+ region where both sides state one), not proof of cause.",
        recommendation: str(f.recommendation) || "Treat the principal as potentially compromised: review its sessions, rotate credentials and remove resources it created.",
        controls: ctrls, evidence: ans.map((an) => ({ correlatedWith: "Spend anomaly: " + an.title, window: an.windowStart + (an.windowEnd !== an.windowStart ? " to " + an.windowEnd : ""), increase: fmtMoney(an.increaseCents, an.currency), account: an.account, regions: an.regions.join(", ") })).concat(ctEv),
        evidenceCount: ans.length + (Number(f.evidenceCount) || ctEv.length), days: [], assets, tags: [TOOL_ID, "correlated", "cloudtrail"],
        correlated: ans.map((an) => ({ id: an.id, title: an.title, severity: an.severity })), cloudtrailGraphName: ctGraphName(f),
      });
    }
  }

  // account asset data (identical across findings so graph merges are stable)
  const acctRow = new Map(accountsT.map((r) => [r.provider + K + r.account + K + r.currency, r]));
  for (const f of findings) {
    const r = acctRow.get(f.provider + K + f.account + K + f.currency);
    if (r) { r.findings++; for (const t of [f.category]) if (!r.flags.includes(t)) r.flags.push(t); }
  }
  for (const r of accountsT) r.flags.sort(cmp);
  for (const f of findings) {
    const r = acctRow.get(f.provider + K + f.account + K + f.currency);
    for (const as of f.assets) if (as.type === "ASSET" && as.data === null) {
      const rr = r || accountsT.find((x) => acctLabel(x) === as.name);
      as.data = rr ? { kind: "cloud-account", provider: rr.provider, account: rr.account, currency: rr.currency, baselinePerDay: fmtMoney(rr.baselinePerDayCents, rr.currency), observed: fmtMoney(rr.last7Cents, rr.currency) + " last 7 days", flags: rr.flags.slice() } : { kind: "cloud-account" };
    }
  }
  for (const r of accountsT) { delete r._ref; delete r._cur; }

  findings.sort((x, y) => SEV_RANK[y.severity] - SEV_RANK[x.severity] || CONF_RANK[y.confidence] - CONF_RANK[x.confidence] || y.increaseCents - x.increaseCents || cmp(x.id, y.id));
  timeline.sort((x, y) => cmp(x.date, y.date) || cmp(x.provider, y.provider) || cmp(x.account, y.account) || cmp(x.kind, y.kind) || cmp(x.findingId, y.findingId));
  const sevOf = new Map(findings.map((f) => [f.id, f.severity]));
  for (const t of timeline) t.severity = sevOf.get(t.findingId) || "";
  correlations.sort((x, y) => cmp(x.anomalyId, y.anomalyId) || cmp(x.cloudtrailId, y.cloudtrailId));

  const daily = Array.from(acc.daily.values()).map((d) => ({ date: d.date, currency: d.currency, totalCents: microsToCents(d.aws + d.azure + d.gcp + d.other), awsCents: microsToCents(d.aws), azureCents: microsToCents(d.azure), gcpCents: microsToCents(d.gcp), otherCents: microsToCents(d.other) }))
    .sort((x, y) => cmp(x.date, y.date) || cmp(x.currency, y.currency));
  const totals = {};
  for (const d of daily) totals[d.currency] = (totals[d.currency] || 0) + d.totalCents;
  servicesT.sort((x, y) => cmp(x.currency, y.currency) || y.totalCents - x.totalCents || cmp(x.provider + x.account + x.service, y.provider + y.account + y.service));
  regionsT.sort((x, y) => Number(y.isNew) - Number(x.isNew) || cmp(x.currency, y.currency) || y.totalCents - x.totalCents || cmp(x.provider + x.account + x.region, y.provider + y.account + y.region));
  familiesT.sort((x, y) => Number(y.gpu) - Number(x.gpu) || Number(y.isNew) - Number(x.isNew) || cmp(x.currency, y.currency) || y.totalCents - x.totalCents || cmp(x.provider + x.account + x.family, y.provider + y.account + y.family));
  accountsT.sort((x, y) => y.findings - x.findings || cmp(x.currency, y.currency) || y.totalCents - x.totalCents || cmp(x.provider + x.account, y.provider + y.account));

  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) bySeverity[f.severity]++;
  const dates = daily.map((d) => d.date);
  const firstDate = dates.length ? dates[0] : "", lastDate = dates.length ? dates[dates.length - 1] : "";
  const summary = {
    rows, accounts: accountsT.length, providers: uniq(accts.map((a) => a.provider)), currencies: Object.keys(totals).sort(cmp),
    totals: Object.keys(totals).sort(cmp).map((c) => ({ currency: c, cents: totals[c] })),
    firstDate, lastDate, days: dates.length ? dayNum(lastDate) - dayNum(firstDate) + 1 : 0,
    findings: findings.length, anomalies: findings.filter((f) => f.category !== "correlated-audit").length, bySeverity,
    gpuAlerts: findings.filter((f) => f.category === "gpu-family").length, newRegionAlerts: findings.filter((f) => f.category === "new-region").length,
    correlated: findings.filter((f) => f.category !== "correlated-audit" && f.correlated.length).length,
    cloudtrailFindings: ctTotal, cloudtrailJoinable: ctJoinable, testedAccounts: accts.length - insufficient,
    checks: checkState,
  };
  if (ctx && ctx.progress) ctx.progress(1, 1, "done");
  return {
    summary, findings,
    tables: { daily, accounts: accountsT, services: servicesT, regions: regionsT, families: familiesT, timeline, series: seriesT, correlations },
    skipped,
    meta: { tool: TOOL_ID, version: VERSION, rows, files: filesMeta, options: { baselineDays: o.baselineDays, minHistoryDays: o.minHistoryDays, spikeZ: o.spikeZ, minIncrease: o.minIncrease, minSpreadCents: o.minSpreadCents, dormantDailyCents: o.dormantDailyCents, dormantWakeCents: o.dormantWakeCents, newFamilyShare: o.newFamilyShare, minNewResources: o.minNewResources, correlationHours: o.correlationHours }, cloudtrail: cloudtrail.map((c) => ({ name: c.name, findings: (c.data.findings || []).length })) },
  };
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
const cell = (v) => {
  let s = Array.isArray(v) ? v.join("; ") : v == null ? "" : String(v);
  if (/^[=+@\t\r]/.test(s) || /^-[^\d]/.test(s)) s = "'" + s;
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
};
const csv = (cols, rows, fn) => [cols.join(",")].concat((rows || []).map((r) => fn(r).map(cell).join(","))).join("\n") + "\n";
const money = (c) => (c == null ? "" : fmtMoney(c, ""));

export const FINDING_COLS = ["id", "severity", "confidence", "category", "provider", "account", "currency", "scope", "window_start", "window_end", "baseline_per_day", "observed", "increase", "z", "mitre", "controls", "correlated_with", "evidence_count", "title", "description", "recommendation"];
/** Findings as CSV (one row per finding; money in the file's currency, never converted). */
export function findingsToCsv(findings) {
  return csv(FINDING_COLS, findings, (f) => [
    f.id, f.severity, f.confidence, f.category, f.provider, f.account, f.currency, f.scope, f.windowStart, f.windowEnd,
    money(f.baselinePerDayCents), money(f.observedCents), money(f.increaseCents), f.z == null ? "" : f.z, f.mitre || [],
    (f.controls || []).map((c) => c.framework + " " + c.id), (f.correlated || []).map((c) => c.title),
    f.evidenceCount != null ? f.evidenceCount : (f.evidence || []).length, f.title, f.description, f.recommendation,
  ]);
}
/** Anomaly timeline (tables.timeline) as CSV. */
export function timelineToCsv(rows) {
  return csv(["date", "provider", "account", "currency", "kind", "scope", "severity", "observed", "baseline", "z", "finding_id"], rows, (t) => [t.date, t.provider, t.account, t.currency, t.kind, t.scope, t.severity, money(t.observedCents), money(t.baselineCents), t.z == null ? "" : t.z, t.findingId]);
}
/** Top resources across findings as CSV. */
export function resourcesToCsv(findings) {
  const rows = [];
  for (const f of findings || []) for (const e of f.evidence || []) if (e.resourceId != null && e.costCents != null) rows.push({ f, e });
  return csv(["finding_id", "severity", "provider", "account", "currency", "window", "resource_id", "service", "sku", "region", "family", "cost", "usage", "unit"], rows, ({ f, e }) => [f.id, f.severity, f.provider, f.account, f.currency, e.window, e.resourceId, e.service, e.sku, e.region, e.family, money(e.costCents), e.usage, e.unit]);
}
/** Accounts table as CSV. */
export function accountsToCsv(rows) {
  return csv(["provider", "account", "account_name", "currency", "days", "first", "last", "total", "baseline_per_day", "last_7_days", "max_z", "findings", "flags", "status"], rows, (r) => [r.provider, r.account, r.accountName, r.currency, r.days, r.firstDate, r.lastDate, money(r.totalCents), money(r.baselinePerDayCents), money(r.last7Cents), r.maxZ, r.findings, r.flags, r.status]);
}
/** Plain-text summary. */
export function summaryText(r) {
  const s = r.summary, L = [];
  L.push("Cloud Spend Anomaly summary (" + TOOL_ID + " " + VERSION + ")");
  L.push("Data: " + s.rows + " billing rows, " + s.accounts + " account series, " + (s.firstDate ? s.firstDate + " to " + s.lastDate + " (" + s.days + " days)" : "no dates"));
  L.push("Spend: " + (s.totals.map((t) => fmtMoney(t.cents, t.currency)).join("; ") || "-") + " (currencies are never converted or summed together)");
  const op = r.meta.options;
  L.push("Thresholds: baseline " + op.baselineDays + " days, minimum history " + op.minHistoryDays + " days, spike z > " + op.spikeZ + ", minimum increase " + fmtMoney(op.minIncrease, "") + ", minimum spread " + fmtMoney(op.minSpreadCents, "") + ", correlation +/- " + op.correlationHours + " h");
  L.push("Findings: " + s.findings + " (critical " + s.bySeverity.critical + ", high " + s.bySeverity.high + ", medium " + s.bySeverity.medium + ", low " + s.bySeverity.low + "); GPU alerts " + s.gpuAlerts + ", new-region alerts " + s.newRegionAlerts + ", correlated " + s.correlated);
  L.push("These are screens, not proof: every finding is a pattern that needs review with the account owner.");
  L.push("");
  for (const f of r.findings) {
    L.push("[" + f.severity.toUpperCase() + "/" + f.confidence + "] " + f.title);
    L.push("  " + f.description);
    L.push("  Action: " + f.recommendation);
    L.push("  Controls: " + f.controls.map((c) => c.framework + " " + c.id).join(", "));
  }
  if (r.skipped.length) { L.push(""); L.push("Skipped or limited checks:"); for (const k of r.skipped) L.push("- " + k.check + ": " + k.reason); }
  return L.join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// Synthetic example
// ---------------------------------------------------------------------------
const CUR_HEADERS = ["identity/LineItemId", "identity/TimeInterval", "bill/PayerAccountId", "bill/BillingEntity", "lineItem/UsageAccountId", "lineItem/LineItemType", "lineItem/UsageStartDate", "lineItem/UsageEndDate", "lineItem/ProductCode", "lineItem/UsageType", "lineItem/Operation", "lineItem/AvailabilityZone", "lineItem/ResourceId", "lineItem/UsageAmount", "lineItem/CurrencyCode", "lineItem/UnblendedCost", "lineItem/BlendedCost", "lineItem/LegalEntity", "product/ProductName", "product/region", "product/instanceType", "product/productFamily", "pricing/unit"];

/**
 * Seeded SYNTHETIC 60-day CUR (3 fictional accounts) + a small Cloud Audit Log Hunter-style
 * export. Account 333333333333 is dormant, then runs p3.16xlarge in sa-east-1 (a new region);
 * account 111111111111 has an egress spike. Not real data.
 */
export function exampleDataset(seed = 7) {
  let s = seed >>> 0;
  const rnd = () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 4294967296; };
  const START = dayNum("2026-07-01"), N = 60, PAYER = "999999999999";
  const lines = [CUR_HEADERS.join(",")];
  let id = 0;
  const add = (d, acct, type, prod, usageType, op, az, res, amount, cost, region, it, fam, unit, entity = "AWS", seller = "Amazon Web Services, Inc.", pname = "") => {
    const day = numDay(d);
    const row = { "identity/LineItemId": "syn" + String(++id).padStart(6, "0"), "identity/TimeInterval": day + "T00:00:00Z/" + numDay(d + 1) + "T00:00:00Z", "bill/PayerAccountId": PAYER, "bill/BillingEntity": entity, "lineItem/UsageAccountId": acct, "lineItem/LineItemType": type, "lineItem/UsageStartDate": day + "T00:00:00Z", "lineItem/UsageEndDate": numDay(d + 1) + "T00:00:00Z", "lineItem/ProductCode": prod, "lineItem/UsageType": usageType, "lineItem/Operation": op, "lineItem/AvailabilityZone": az, "lineItem/ResourceId": res, "lineItem/UsageAmount": amount.toFixed(6), "lineItem/CurrencyCode": "USD", "lineItem/UnblendedCost": cost.toFixed(8), "lineItem/BlendedCost": cost.toFixed(8), "lineItem/LegalEntity": seller, "product/ProductName": pname, "product/region": region, "product/instanceType": it, "product/productFamily": fam, "pricing/unit": unit };
    lines.push(CUR_HEADERS.map((h) => cell(row[h])).join(","));
  };
  for (let i = 0; i < N; i++) {
    const d = START + i, j = () => 0.9 + rnd() * 0.2;
    // 111111111111 production: steady EC2 m5 + S3 + egress (spike days 52-53)
    for (let k = 1; k <= 4; k++) add(d, "111111111111", "Usage", "AmazonEC2", "BoxUsage:m5.2xlarge", "RunInstances", "us-east-1" + "abcd"[k - 1], "i-0prod00000000000" + k, 24, 24 * 0.384 * j(), "us-east-1", "m5.2xlarge", "Compute Instance", "Hrs");
    add(d, "111111111111", "Usage", "AmazonS3", "TimedStorage-ByteHrs", "StandardStorage", "", "prod-assets-test-darknode", 4100 * j(), 94 * j(), "us-east-1", "", "Storage", "GB-Mo");
    const eg = i === 52 || i === 53 ? 2100 + rnd() * 200 : 55 + rnd() * 10;
    add(d, "111111111111", "Usage", "AmazonEC2", "DataTransfer-Out-Bytes", "RunInstances", "", "i-0prod000000000001", eg, eg * 0.09, "us-east-1", "", "Data Transfer", "GB");
    add(d, "111111111111", "Credit", "AmazonEC2", "BoxUsage:m5.2xlarge", "RunInstances", "", "", 0, -5, "us-east-1", "m5.2xlarge", "Compute Instance", "Hrs");
    // 222222222222 analytics: Lambda + RDS
    add(d, "222222222222", "Usage", "AWSLambda", "Lambda-GB-Second", "Invoke", "", "arn:aws:lambda:us-west-2:222222222222:function:etl-nightly", 1.6e6 * j(), 26 * j(), "us-west-2", "", "Serverless", "Lambda-GB-Second");
    add(d, "222222222222", "Usage", "AmazonRDS", "InstanceUsage:db.r5.large", "CreateDBInstance", "us-west-2a", "arn:aws:rds:us-west-2:222222222222:db:analytics", 24, 24 * 0.25, "us-west-2", "db.r5.large", "Database Instance", "Hrs");
    if (i === 20) add(d, "222222222222", "Usage", "AWSMarketplace", "SoftwareUsage", "Subscribe", "", "", 1, 49, "us-west-2", "", "", "Units", "AWS Marketplace", "Vendor A", "Log Shipper");
    // 333333333333 sandbox: dormant (tiny S3) then p3.16xlarge burst in sa-east-1 on days 55-57
    add(d, "333333333333", "Usage", "AmazonS3", "TimedStorage-ByteHrs", "StandardStorage", "", "sandbox-scratch-test-darknode", 2.1, 0.05, "us-east-1", "", "Storage", "GB-Mo");
    if (i >= 55 && i <= 57) for (let k = 1; k <= 6; k++) add(d, "333333333333", "Usage", "AmazonEC2", "SAE1-BoxUsage:p3.16xlarge", "RunInstances", "sa-east-1a", "i-0gpu0000000000" + String(k).padStart(2, "0"), 24, 24 * 36.97, "sa-east-1", "p3.16xlarge", "Compute Instance", "Hrs");
  }
  const runAt = numDay(START + 55) + "T02:14:09Z";
  const ct = {
    summary: { events: 3, findings: 1 },
    findings: [{
      id: "aws-run-instances-new-region:333333333333 sa-east-1", ruleId: "aws-run-instances-new-region",
      title: "Instances launched in a never-seen region: 333333333333 sa-east-1", severity: "medium", confidence: "likely", category: "recon", platform: "aws",
      description: "RunInstances in a region where the account had no earlier activity in this dataset.", recommendation: "Confirm the launch, terminate unknown instances and deny unused regions with an SCP.",
      controls: [{ framework: "MITRE", id: "T1535" }, { framework: "MITRE", id: "T1578.002" }], mitre: ["T1535", "T1578.002"],
      key: "333333333333 sa-east-1", evidenceCount: 2, firstSeen: runAt, lastSeen: numDay(START + 55) + "T02:15:41Z",
      principals: ["arn:aws:iam::333333333333:user/sandbox-ci@test.darknode.ai"], ips: ["203.0.113.77"],
      evidence: [
        { time: runAt, platform: "aws", account: "333333333333", principal: "arn:aws:iam::333333333333:user/sandbox-ci@test.darknode.ai", principalType: "IAMUser", action: "RunInstances", service: "ec2.amazonaws.com", region: "sa-east-1", ip: "203.0.113.77", status: "success", error: "", target: "i-0gpu000000000001", ua: "aws-cli/2.15.0" },
        { time: numDay(START + 55) + "T02:15:41Z", platform: "aws", account: "333333333333", principal: "arn:aws:iam::333333333333:user/sandbox-ci@test.darknode.ai", principalType: "IAMUser", action: "RunInstances", service: "ec2.amazonaws.com", region: "sa-east-1", ip: "203.0.113.77", status: "success", error: "", target: "i-0gpu000000000004", ua: "aws-cli/2.15.0" },
      ],
      assets: [{ type: "IDENTITY", name: "arn:aws:iam::333333333333:user/sandbox-ci@test.darknode.ai", data: { platform: "aws", account: "333333333333", events: 3, flags: ["aws-run-instances-new-region"] } }, { type: "IP", name: "203.0.113.77", data: { events: 3 } }],
      tags: ["recon", "aws", "aws-run-instances-new-region"],
    }],
    meta: { tool: "cloudtrail", version: "1.0.0", rows: 3, now: numDay(START + 55) + "T02:15:41Z", platforms: ["aws"] },
  };
  return {
    label: "synthetic example (not real data)",
    files: [{ name: "synthetic-cur-2026-07-08.csv", text: lines.join("\n") + "\n" }, { name: "synthetic-cloudtrail-export.json", text: JSON.stringify(ct, null, 2) }],
  };
}

/** Real deterministic checks of the engine. */
export function selfTest() {
  const tests = [];
  const ex = exampleDataset();
  const r = analyze(ex.files);
  const has = (cat, acct) => r.findings.some((f) => f.category === cat && f.account === acct);
  tests.push({ name: "CUR example detected as aws-cur", pass: r.meta.files[0].format === "aws-cur" });
  tests.push({ name: "GPU family p3 in dormant account", pass: has("gpu-family", "333333333333") });
  tests.push({ name: "new region sa-east-1 (compute, high or above)", pass: r.findings.some((f) => f.category === "new-region" && f.scope === "sa-east-1" && SEV_RANK[f.severity] >= 3) });
  tests.push({ name: "dormant account wake-up", pass: has("dormant-account", "333333333333") });
  tests.push({ name: "egress spike in 111111111111", pass: has("egress-spike", "111111111111") });
  tests.push({ name: "correlated with the cloudtrail export", pass: r.summary.correlated > 0 && r.findings.some((f) => f.category === "correlated-audit") });
  tests.push({ name: "credits excluded from usage", pass: r.meta.files[0].excluded === 60 });
  tests.push({ name: "deterministic", pass: JSON.stringify(analyze(ex.files)) === JSON.stringify(r) });
  tests.push({ name: "robust z of flat baseline uses floor", pass: robustZ(5, robust([1, 1, 1], 1)) === 4 });
  tests.push({ name: "exact decimal parsing", pass: toMicros("0.0000015") === 2 && toMicros("(12.50)") === -12500000 && toMicros("1,234.5") === 1234500000 });
  tests.push({ name: "empty input yields no findings", pass: analyze([]).findings.length === 0 });
  return { pass: tests.every((t) => t.pass), tests };
}
