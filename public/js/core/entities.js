// Darknode entity schema + validation layer.
//
// security-graph.js owns the *storage* of entities (the 25 ENTITY_TYPES, the
// relationship graph, persistence). What it does NOT do is describe or validate
// the *shape* of each entity's `data` payload — every producer (graph-bridge,
// individual tools, importers) pushes an ad-hoc `data` object and hopes the
// consumer understands it. This module closes that gap:
//
//   - A declarative field schema per entity type: what fields a VULNERABILITY,
//     an IP, a THREAT_ACTOR, etc. carry, their types, which are required, and a
//     human/AI-readable description + example for each.
//   - A reusable library of field validators (ip, cidr, domain, url, email,
//     cve, cvss, hash, port, timestamp, enum, ...) that both coerce and check.
//   - validateEntity(): returns { ok, errors, normalized } — normalized is a
//     cleaned, type-coerced payload safe to hand to security-graph.createEntity.
//   - Relationship semantics: which relationship types may connect which entity
//     types, so `THREAT_ACTOR --exploits--> VULNERABILITY` is accepted but
//     `REPORT --exploits--> PORT` is rejected.
//   - describeType() / catalog(): machine-readable schema for building forms and
//     for grounding the AI's structured context (it can be told exactly what a
//     valid entity of each type looks like).
//
// The canonical enumerations (ENTITY_TYPES, SEVERITIES, STATUSES,
// RELATIONSHIP_TYPES) are imported from security-graph.js so there is exactly
// one source of truth; this module never redefines them.

import {
  ENTITY_TYPES,
  RELATIONSHIP_TYPES,
  SEVERITIES,
  STATUSES,
} from "../security-graph.js";

export { ENTITY_TYPES, RELATIONSHIP_TYPES, SEVERITIES, STATUSES };

// ---------------------------------------------------------------------------
// Field validators. Each validator is { test, coerce, describe }.
//   test(value)   -> boolean : is this an acceptable value?
//   coerce(value) -> value   : normalize (trim, lowercase, Number(), ...)
// A field is validated as: coerce first, then test the coerced value.
// ---------------------------------------------------------------------------

const RE = {
  // Dotted-quad IPv4 with per-octet range check, or a compact IPv6.
  ipv4: /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/,
  ipv6: /^(([0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,7}:|:(:[0-9a-f]{1,4}){1,7}|([0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4})$/i,
  domain: /^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,63}$/i,
  email: /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/,
  cve: /^CVE-\d{4}-\d{4,}$/i,
  cwe: /^CWE-\d+$/i,
  md5: /^[a-f0-9]{32}$/i,
  sha1: /^[a-f0-9]{40}$/i,
  sha256: /^[a-f0-9]{64}$/i,
  mac: /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i,
  // MITRE ATT&CK technique id, e.g. T1059 or T1059.001
  attack: /^T\d{4}(\.\d{3})?$/i,
  iso: /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?)?$/,
};

const asStr = (v) => (v === null || v === undefined ? "" : String(v)).trim();

export const FIELD_TYPES = {
  string: {
    coerce: (v) => asStr(v),
    test: (v) => typeof v === "string",
    describe: "free text",
  },
  text: {
    coerce: (v) => (v === null || v === undefined ? "" : String(v)),
    test: (v) => typeof v === "string",
    describe: "multi-line text (whitespace preserved)",
  },
  number: {
    coerce: (v) => (v === "" || v === null || v === undefined ? NaN : Number(v)),
    test: (v) => typeof v === "number" && Number.isFinite(v),
    describe: "finite number",
  },
  integer: {
    coerce: (v) => (v === "" || v === null || v === undefined ? NaN : Math.trunc(Number(v))),
    test: (v) => Number.isInteger(v),
    describe: "whole number",
  },
  boolean: {
    coerce: (v) => (typeof v === "boolean" ? v : /^(true|yes|1|on)$/i.test(asStr(v)) ? true : /^(false|no|0|off)$/i.test(asStr(v)) ? false : v),
    test: (v) => typeof v === "boolean",
    describe: "true/false",
  },
  ip: {
    coerce: (v) => asStr(v).toLowerCase(),
    test: (v) => RE.ipv4.test(v) || RE.ipv6.test(v),
    describe: "IPv4 or IPv6 address",
  },
  ipv4: {
    coerce: (v) => asStr(v),
    test: (v) => RE.ipv4.test(v),
    describe: "IPv4 address",
  },
  cidr: {
    coerce: (v) => asStr(v).toLowerCase(),
    test: (v) => {
      const m = /^(.+)\/(\d{1,3})$/.exec(v);
      if (!m) return false;
      const bits = Number(m[2]);
      if (RE.ipv4.test(m[1])) return bits >= 0 && bits <= 32;
      if (RE.ipv6.test(m[1])) return bits >= 0 && bits <= 128;
      return false;
    },
    describe: "CIDR range, e.g. 10.0.0.0/8",
  },
  domain: {
    coerce: (v) => asStr(v).toLowerCase().replace(/\.$/, ""),
    test: (v) => RE.domain.test(v),
    describe: "fully-qualified domain name",
  },
  url: {
    coerce: (v) => asStr(v),
    test: (v) => {
      try { const u = new URL(v); return !!u.protocol && !!u.host; } catch (_) { return false; }
    },
    describe: "absolute URL",
  },
  email: {
    coerce: (v) => asStr(v).toLowerCase(),
    test: (v) => RE.email.test(v),
    describe: "email address",
  },
  port: {
    coerce: (v) => Math.trunc(Number(v)),
    test: (v) => Number.isInteger(v) && v >= 0 && v <= 65535,
    describe: "TCP/UDP port (0-65535)",
  },
  cve: {
    coerce: (v) => asStr(v).toUpperCase(),
    test: (v) => RE.cve.test(v),
    describe: "CVE identifier, e.g. CVE-2024-3094",
  },
  cwe: {
    coerce: (v) => asStr(v).toUpperCase(),
    test: (v) => RE.cwe.test(v),
    describe: "CWE identifier, e.g. CWE-79",
  },
  cvss: {
    coerce: (v) => Number(v),
    test: (v) => typeof v === "number" && v >= 0 && v <= 10,
    describe: "CVSS base score (0.0-10.0)",
  },
  hash: {
    coerce: (v) => asStr(v).toLowerCase(),
    test: (v) => RE.md5.test(v) || RE.sha1.test(v) || RE.sha256.test(v),
    describe: "MD5, SHA-1 or SHA-256 file hash",
  },
  mac: {
    coerce: (v) => asStr(v).toLowerCase(),
    test: (v) => RE.mac.test(v),
    describe: "MAC address",
  },
  attack: {
    coerce: (v) => asStr(v).toUpperCase(),
    test: (v) => RE.attack.test(v),
    describe: "MITRE ATT&CK technique id, e.g. T1059.001",
  },
  timestamp: {
    coerce: (v) => {
      if (typeof v === "number") return new Date(v).toISOString();
      const s = asStr(v);
      const d = new Date(s);
      return Number.isNaN(d.getTime()) ? s : d.toISOString();
    },
    test: (v) => typeof v === "string" && RE.iso.test(v),
    describe: "ISO-8601 timestamp",
  },
  array: {
    coerce: (v) => (Array.isArray(v) ? v : v === "" || v === null || v === undefined ? [] : String(v).split(",").map((s) => s.trim()).filter(Boolean)),
    test: (v) => Array.isArray(v),
    describe: "list of values (comma-separated string accepted)",
  },
  object: {
    coerce: (v) => v,
    test: (v) => v !== null && typeof v === "object" && !Array.isArray(v),
    describe: "nested object",
  },
  severity: {
    coerce: (v) => (v === null ? null : asStr(v).toLowerCase()),
    test: (v) => SEVERITIES.includes(v),
    describe: `one of: ${SEVERITIES.filter(Boolean).join(", ")}`,
  },
  enum: {
    coerce: (v) => asStr(v),
    test: () => true, // enum membership is checked against field.values in validateField
    describe: "one of an enumerated set",
  },
};

// ---------------------------------------------------------------------------
// Per-type field schemas. `f(name, type, opts)` builds a field descriptor.
// opts: { required, values (for enum), desc, example, default }
// ---------------------------------------------------------------------------

function f(name, type, opts = {}) {
  return {
    name,
    type,
    required: !!opts.required,
    values: opts.values || null,
    desc: opts.desc || (FIELD_TYPES[type] ? FIELD_TYPES[type].describe : ""),
    example: opts.example,
    default: opts.default,
  };
}

// Common building blocks reused across several entity types.
const F = {
  confidence: () => f("confidence", "enum", { values: ["low", "medium", "high", "confirmed"], desc: "analyst confidence" }),
  firstSeen: () => f("firstSeen", "timestamp", { desc: "first observation" }),
  lastSeen: () => f("lastSeen", "timestamp", { desc: "most recent observation" }),
  refs: () => f("references", "array", { desc: "external reference URLs / IDs" }),
};

export const TYPE_SCHEMAS = {
  ASSET: {
    label: "Asset",
    summary: "A managed device, host, or system under defense.",
    fields: [
      f("hostname", "string", { desc: "primary hostname" }),
      f("ipAddresses", "array", { desc: "known IPs" }),
      f("os", "string", { desc: "operating system" }),
      f("owner", "string", { desc: "responsible team / person (role, not PII)" }),
      f("criticality", "enum", { values: ["low", "medium", "high", "crown-jewel"] }),
      f("environment", "enum", { values: ["prod", "staging", "dev", "dr"] }),
      f("location", "string"),
    ],
  },
  ENDPOINT: {
    label: "Endpoint",
    summary: "A workstation/server endpoint with EDR telemetry.",
    fields: [
      f("hostname", "string", { required: true }),
      f("ip", "ip"),
      f("os", "string"),
      f("agentVersion", "string", { desc: "EDR agent version" }),
      f("lastCheckIn", "timestamp"),
      f("isolated", "boolean", { desc: "network-isolated by response action" }),
    ],
  },
  DOMAIN: {
    label: "Domain",
    summary: "A DNS domain or hostname of interest.",
    fields: [
      f("fqdn", "domain", { required: true, example: "malicious.example.com" }),
      f("registrar", "string"),
      f("createdDate", "timestamp", { desc: "domain registration date" }),
      f("resolvesTo", "array", { desc: "resolved IPs" }),
      F.firstSeen(), F.lastSeen(),
    ],
  },
  IP: {
    label: "IP Address",
    summary: "An IPv4/IPv6 address observed in telemetry.",
    fields: [
      f("address", "ip", { required: true, example: "203.0.113.42" }),
      f("asn", "integer", { desc: "autonomous system number" }),
      f("asnOrg", "string"),
      f("country", "string", { desc: "ISO country code" }),
      f("reputation", "enum", { values: ["clean", "suspicious", "malicious", "unknown"] }),
      F.firstSeen(), F.lastSeen(),
    ],
  },
  PORT: {
    label: "Port",
    summary: "An open network port on a host.",
    fields: [
      f("number", "port", { required: true, example: 443 }),
      f("protocol", "enum", { values: ["tcp", "udp"], default: "tcp" }),
      f("state", "enum", { values: ["open", "closed", "filtered"], default: "open" }),
      f("banner", "text"),
    ],
  },
  SERVICE: {
    label: "Service",
    summary: "A network service running on a host/port.",
    fields: [
      f("name", "string", { required: true, example: "nginx" }),
      f("product", "string"),
      f("version", "string"),
      f("port", "port"),
      f("protocol", "enum", { values: ["tcp", "udp"] }),
    ],
  },
  CERTIFICATE: {
    label: "Certificate",
    summary: "A TLS/X.509 certificate.",
    fields: [
      f("subject", "string", { required: true }),
      f("issuer", "string"),
      f("serial", "string"),
      f("fingerprint", "hash"),
      f("notBefore", "timestamp"),
      f("notAfter", "timestamp"),
      f("selfSigned", "boolean"),
    ],
  },
  SOFTWARE: {
    label: "Software",
    summary: "An installed software package / component (SBOM item).",
    fields: [
      f("name", "string", { required: true }),
      f("vendor", "string"),
      f("version", "string"),
      f("cpe", "string", { desc: "CPE identifier" }),
      f("license", "string"),
    ],
  },
  VULNERABILITY: {
    label: "Vulnerability",
    summary: "A known weakness (CVE) affecting an asset/software.",
    fields: [
      f("cveId", "cve", { example: "CVE-2024-3094" }),
      f("cwe", "cwe"),
      f("cvss", "cvss", { example: 9.8 }),
      f("vector", "string", { desc: "CVSS vector string" }),
      f("exploitAvailable", "boolean"),
      f("patchAvailable", "boolean"),
      f("description", "text"),
      F.refs(),
    ],
  },
  INDICATOR: {
    label: "Indicator",
    summary: "An indicator of compromise (IOC).",
    fields: [
      f("iocType", "enum", { required: true, values: ["ip", "domain", "url", "hash", "email", "filename", "registry", "mutex"] }),
      f("value", "string", { required: true }),
      f("hash", "hash"),
      F.confidence(),
      F.firstSeen(), F.lastSeen(),
      F.refs(),
    ],
  },
  ALERT: {
    label: "Alert",
    summary: "A detection alert raised by a sensor/rule.",
    fields: [
      f("title", "string", { required: true }),
      f("rule", "string", { desc: "rule / signature name" }),
      f("source", "string", { desc: "sensor / product" }),
      f("count", "integer", { desc: "aggregated hit count" }),
      f("firstTriggered", "timestamp"),
      f("description", "text"),
    ],
  },
  EVENT: {
    label: "Event",
    summary: "A discrete log/telemetry event.",
    fields: [
      f("category", "string"),
      f("action", "string"),
      f("timestamp", "timestamp"),
      f("host", "string"),
      f("user", "string", { desc: "actor account (role/handle, not PII)" }),
      f("raw", "text", { desc: "raw log line" }),
    ],
  },
  INCIDENT: {
    label: "Incident",
    summary: "A confirmed security incident being managed.",
    fields: [
      f("title", "string", { required: true }),
      f("phase", "enum", { values: ["identification", "containment", "eradication", "recovery", "lessons-learned"] }),
      f("priority", "enum", { values: ["p1", "p2", "p3", "p4"] }),
      f("assignee", "string", { desc: "responder role/handle" }),
      f("openedAt", "timestamp"),
      f("summary", "text"),
    ],
  },
  CASE: {
    label: "Case",
    summary: "An investigative case file.",
    fields: [
      f("title", "string", { required: true }),
      f("caseNumber", "string"),
      f("owner", "string"),
      f("state", "enum", { values: ["open", "active", "pending", "closed"] }),
      f("summary", "text"),
    ],
  },
  INVESTIGATION: {
    label: "Investigation",
    summary: "An active investigation workspace.",
    fields: [
      f("title", "string", { required: true }),
      f("hypothesis", "text"),
      f("lead", "string"),
      f("startedAt", "timestamp"),
    ],
  },
  EVIDENCE: {
    label: "Evidence",
    summary: "A collected artifact supporting a finding/case.",
    fields: [
      f("kind", "enum", { values: ["file", "memory", "pcap", "log", "screenshot", "disk-image", "note"] }),
      f("description", "text", { required: true }),
      f("hash", "hash"),
      f("collectedAt", "timestamp"),
      f("collectedBy", "string", { desc: "collector role/handle" }),
      f("chainOfCustody", "array"),
    ],
  },
  THREAT_ACTOR: {
    label: "Threat Actor",
    summary: "An adversary group or individual.",
    fields: [
      f("aliases", "array"),
      f("motivation", "enum", { values: ["financial", "espionage", "hacktivism", "destruction", "unknown"] }),
      f("sophistication", "enum", { values: ["low", "medium", "high", "advanced"] }),
      f("origin", "string", { desc: "attributed region/country" }),
      f("techniques", "array", { desc: "MITRE ATT&CK technique ids" }),
      F.refs(),
    ],
  },
  MALWARE: {
    label: "Malware",
    summary: "A malicious software family or sample.",
    fields: [
      f("family", "string"),
      f("category", "enum", { values: ["ransomware", "trojan", "rat", "worm", "loader", "stealer", "rootkit", "wiper", "other"] }),
      f("hash", "hash"),
      f("platform", "string"),
      f("capabilities", "array"),
    ],
  },
  CAMPAIGN: {
    label: "Campaign",
    summary: "A set of related intrusion activity over time.",
    fields: [
      f("name", "string", { required: true }),
      f("objective", "text"),
      f("startDate", "timestamp"),
      f("endDate", "timestamp"),
      f("targetSectors", "array"),
    ],
  },
  TECHNIQUE: {
    label: "Technique",
    summary: "An adversary technique (MITRE ATT&CK).",
    fields: [
      f("attackId", "attack", { required: true, example: "T1059.001" }),
      f("name", "string"),
      f("tactic", "string", { desc: "kill-chain phase / tactic" }),
      f("description", "text"),
    ],
  },
  FINDING: {
    label: "Finding",
    summary: "An assessment/audit finding.",
    fields: [
      f("title", "string", { required: true }),
      f("category", "string"),
      f("recommendation", "text"),
      f("affected", "array", { desc: "affected assets" }),
      f("status", "enum", { values: ["open", "in-progress", "remediated", "accepted", "false-positive"] }),
    ],
  },
  DETECTION: {
    label: "Detection",
    summary: "A detection rule / analytic.",
    fields: [
      f("name", "string", { required: true }),
      f("language", "enum", { values: ["sigma", "yara", "snort", "kql", "spl", "eql", "regex", "other"] }),
      f("logic", "text", { desc: "rule body" }),
      f("mitre", "array", { desc: "ATT&CK technique ids covered" }),
      f("enabled", "boolean", { default: true }),
    ],
  },
  PLAYBOOK: {
    label: "Playbook",
    summary: "A response runbook / SOAR playbook.",
    fields: [
      f("name", "string", { required: true }),
      f("trigger", "string"),
      f("steps", "array", { desc: "ordered response steps" }),
      f("automated", "boolean"),
    ],
  },
  CONTROL: {
    label: "Control",
    summary: "A security control mapped to a framework.",
    fields: [
      f("controlId", "string", { required: true, example: "AC-2" }),
      f("framework", "string", { desc: "e.g. NIST 800-53, CIS, ISO 27001" }),
      f("title", "string"),
      f("implementation", "enum", { values: ["not-implemented", "partial", "implemented", "not-applicable"] }),
    ],
  },
  REPORT: {
    label: "Report",
    summary: "A generated report / deliverable.",
    fields: [
      f("title", "string", { required: true }),
      f("kind", "enum", { values: ["assessment", "incident", "threat-intel", "compliance", "executive"] }),
      f("author", "string"),
      f("generatedAt", "timestamp"),
    ],
  },
};

// ---------------------------------------------------------------------------
// Relationship semantics: constrain which entity types a relationship may join.
// A rule is { from: [types]|"*", to: [types]|"*" }. "*" means any entity type.
// This turns the flat RELATIONSHIP_TYPES list into a typed, checkable graph.
// ---------------------------------------------------------------------------

const ANY = "*";

export const RELATIONSHIP_RULES = {
  related_to: { from: ANY, to: ANY },
  contains: {
    from: ["ASSET", "ENDPOINT", "DOMAIN", "IP", "CASE", "INVESTIGATION", "INCIDENT", "CAMPAIGN"],
    to: ANY,
  },
  affects: {
    from: ["VULNERABILITY", "MALWARE", "TECHNIQUE", "CAMPAIGN", "THREAT_ACTOR", "INCIDENT"],
    to: ["ASSET", "ENDPOINT", "SOFTWARE", "SERVICE", "DOMAIN", "IP"],
  },
  observed_in: {
    from: ["INDICATOR", "MALWARE", "TECHNIQUE", "IP", "DOMAIN"],
    to: ["EVENT", "ALERT", "INCIDENT", "CASE", "ASSET", "ENDPOINT"],
  },
  attributed_to: {
    from: ["CAMPAIGN", "MALWARE", "INCIDENT", "TECHNIQUE", "INDICATOR"],
    to: ["THREAT_ACTOR"],
  },
  mitigates: {
    from: ["CONTROL", "DETECTION", "PLAYBOOK"],
    to: ["VULNERABILITY", "TECHNIQUE", "MALWARE", "THREAT_ACTOR", "FINDING"],
  },
  exploits: {
    from: ["THREAT_ACTOR", "MALWARE", "CAMPAIGN", "TECHNIQUE"],
    to: ["VULNERABILITY", "SOFTWARE", "SERVICE"],
  },
  targets: {
    from: ["THREAT_ACTOR", "CAMPAIGN", "MALWARE"],
    to: ["ASSET", "ENDPOINT", "DOMAIN", "IP", "SOFTWARE"],
  },
  part_of: { from: ANY, to: ["CASE", "INVESTIGATION", "INCIDENT", "CAMPAIGN", "REPORT"] },
  detected_by: {
    from: ["MALWARE", "TECHNIQUE", "INDICATOR", "VULNERABILITY", "THREAT_ACTOR"],
    to: ["DETECTION", "ALERT", "CONTROL"],
  },
  evidence_for: {
    from: ["EVIDENCE", "EVENT", "ALERT", "INDICATOR", "FINDING"],
    to: ["INCIDENT", "CASE", "INVESTIGATION", "FINDING", "THREAT_ACTOR"],
  },
};

// ---------------------------------------------------------------------------
// Public API.
// ---------------------------------------------------------------------------

export function isEntityType(type) { return ENTITY_TYPES.includes(type); }

/** Return the schema descriptor for an entity type (or null). */
export function describeType(type) {
  const s = TYPE_SCHEMAS[type];
  if (!s) return null;
  return { type, label: s.label, summary: s.summary, fields: s.fields.map((x) => ({ ...x })) };
}

/** Machine-readable catalog of every entity type's schema — for form builders
 *  and for grounding the AI's structured context. */
export function catalog() {
  return ENTITY_TYPES.map((t) => describeType(t)).filter(Boolean);
}

/** Validate + coerce a single field value against a field descriptor.
 *  Returns { ok, value, error }. */
export function validateField(field, value) {
  const vt = FIELD_TYPES[field.type];
  if (!vt) return { ok: false, value, error: `unknown field type "${field.type}"` };
  const missing = value === undefined || value === null || value === "";
  if (missing) {
    if (field.required) return { ok: false, value, error: `"${field.name}" is required` };
    return { ok: true, value: undefined }; // absent optional field: drop it
  }
  const coerced = vt.coerce(value);
  if (field.type === "enum") {
    const set = field.values || [];
    if (!set.includes(coerced)) return { ok: false, value: coerced, error: `"${field.name}" must be one of: ${set.join(", ")}` };
    return { ok: true, value: coerced };
  }
  if (!vt.test(coerced)) return { ok: false, value: coerced, error: `"${field.name}" is not a valid ${field.type} (${vt.describe})` };
  return { ok: true, value: coerced };
}

/**
 * Validate an entity's data payload against its type schema.
 * @returns {{ ok:boolean, errors:string[], normalized:object, unknown:string[] }}
 *   normalized  — coerced data with only known, valid fields (safe to persist)
 *   unknown     — field names present in `data` but not in the schema (kept
 *                 verbatim in normalized under `normalized[name]`, but reported
 *                 so producers can be tightened over time)
 */
export function validateData(type, data = {}) {
  const schema = TYPE_SCHEMAS[type];
  if (!schema) return { ok: false, errors: [`unknown entity type "${type}"`], normalized: {}, unknown: [] };
  const errors = [];
  const normalized = {};
  const known = new Set();
  for (const field of schema.fields) {
    known.add(field.name);
    const has = Object.prototype.hasOwnProperty.call(data, field.name);
    const raw = has ? data[field.name] : field.default;
    const res = validateField(field, raw);
    if (!res.ok) { errors.push(res.error); continue; }
    if (res.value !== undefined) normalized[field.name] = res.value;
  }
  const unknown = Object.keys(data).filter((k) => !known.has(k));
  for (const k of unknown) normalized[k] = data[k]; // preserve, but flag
  return { ok: errors.length === 0, errors, normalized, unknown };
}

/**
 * Validate a full entity (type + name + data + opts), producing a payload ready
 * for security-graph.createEntity. Does NOT persist anything.
 * @returns {{ ok, errors, entity:{ type, name, data, tags, severity, status, source } }}
 */
export function validateEntity(type, name, data = {}, opts = {}) {
  const errors = [];
  if (!ENTITY_TYPES.includes(type)) errors.push(`unknown entity type "${type}"`);
  const cleanName = asStr(name);
  if (!cleanName) errors.push("entity name is required");
  const sev = opts.severity === undefined ? null : opts.severity;
  if (!SEVERITIES.includes(sev)) errors.push(`severity must be one of: ${SEVERITIES.filter(Boolean).join(", ")}`);
  const status = opts.status === undefined ? "new" : opts.status;
  if (!STATUSES.includes(status)) errors.push(`status must be one of: ${STATUSES.filter(Boolean).join(", ")}`);

  let normalized = {};
  if (ENTITY_TYPES.includes(type)) {
    const dv = validateData(type, data);
    normalized = dv.normalized;
    errors.push(...dv.errors);
  }
  const tags = Array.isArray(opts.tags)
    ? [...new Set(opts.tags.map((t) => asStr(t).toLowerCase()).filter(Boolean))]
    : [];

  return {
    ok: errors.length === 0,
    errors,
    entity: {
      type,
      name: cleanName,
      data: normalized,
      tags,
      severity: sev,
      status,
      source: asStr(opts.source) || "manual",
    },
  };
}

/** Is `relType` allowed to connect an entity of `fromType` to one of `toType`? */
export function isValidRelationship(relType, fromType, toType) {
  const rule = RELATIONSHIP_RULES[relType];
  if (!rule) return false;
  if (!ENTITY_TYPES.includes(fromType) || !ENTITY_TYPES.includes(toType)) return false;
  const okFrom = rule.from === ANY || rule.from.includes(fromType);
  const okTo = rule.to === ANY || rule.to.includes(toType);
  return okFrom && okTo;
}

/** Which relationship types can originate from a given entity type. */
export function relationshipsFrom(fromType) {
  return RELATIONSHIP_TYPES.filter((rt) => {
    const rule = RELATIONSHIP_RULES[rt];
    return rule && (rule.from === ANY || rule.from.includes(fromType));
  });
}

/** Human/AI-readable one-line description of a relationship's domain/range. */
export function describeRelationship(relType) {
  const rule = RELATIONSHIP_RULES[relType];
  if (!rule) return null;
  const fmt = (x) => (x === ANY ? "any" : x.join("|"));
  return `${fmt(rule.from)} --${relType}--> ${fmt(rule.to)}`;
}
