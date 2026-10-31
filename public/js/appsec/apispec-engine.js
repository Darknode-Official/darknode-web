// API Security Review engine (apispec). Static review of API definitions against the
// OWASP API Security Top 10 2023: OpenAPI 3.0 / 3.1 (JSON or YAML), Swagger 2.0,
// Postman collection v2.1 / v2.0 and GraphQL (SDL or introspection JSON).
// Pure: no DOM, no network; deterministic. Safe to run inside a Worker.
//
// Every finding names the operation ("METHOD /path", "Mutation.field", or the Postman
// request) and a JSON pointer into the uploaded file, plus a line number when the
// pointer can be located in the source text. Local $ref values (#/...) are resolved
// with a cycle guard; external refs are reported in skipped[], never fetched.

import { parseYamlSubset } from "../ingest/parse.js";
import { DETECTORS, scan as dlpScan, maskValue } from "../dataprotect/dlp-engine.js";

export const TOOL_ID = "apispec";
export const VERSION = "1.0.0";

/** Not a tabular tool: inputs are structured API definitions, so no column aliases apply. */
export const COLUMNS = {};

/** Tunable settings; the UI renders these with DEFAULT_LABELS. */
export const DEFAULTS = {
  minSeverity: "info",
  boundStrings: true,
  boundIntegers: true,
  boundArrays: true,
  adminPathPattern: "admin|internal|manage|management|backoffice|superuser|sudo|ops|debug",
  nonProdHostPattern: "dev|develop|development|staging|stage|stg|test|testing|qa|uat|sandbox|preprod|demo|localhost",
  objectIdPattern: "id|uuid|guid|[A-Za-z0-9]+(?:Id|ID|_id|-id|Uuid|UUID|_uuid|Guid)",
  maxRefDepth: 40,
};

export const DEFAULT_LABELS = {
  minSeverity: "Lowest severity to report",
  boundStrings: "Flag request strings without maxLength",
  boundIntegers: "Flag request integers without maximum",
  boundArrays: "Flag request arrays without maxItems",
  adminPathPattern: "Admin path words (regex alternation)",
  nonProdHostPattern: "Non-production host labels (regex alternation)",
  objectIdPattern: "Object-id path parameter names (regex)",
  maxRefDepth: "Maximum schema nesting depth",
};

export const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export const OWASP_API_2023 = {
  API1: "Broken Object Level Authorization",
  API2: "Broken Authentication",
  API3: "Broken Object Property Level Authorization",
  API4: "Unrestricted Resource Consumption",
  API5: "Broken Function Level Authorization",
  API6: "Unrestricted Access to Sensitive Business Flows",
  API7: "Server Side Request Forgery",
  API8: "Security Misconfiguration",
  API9: "Improper Inventory Management",
  API10: "Unsafe Consumption of APIs",
};

const ASVS_TLS = { framework: "OWASP ASVS 4.0.3", id: "V9.1" };
const ASVS_GQL = { framework: "OWASP ASVS 4.0.3", id: "V13.4" };
const RFC9700 = { framework: "IETF RFC 9700 (OAuth 2.0 Security BCP)", id: "RFC 9700" };

/** Rule catalog. Every finding carries one of these ids. */
export const RULES = [
  { id: "APISPEC-AUTH-NO-SCHEMES", owasp: "API2", cwe: "CWE-306", severity: "high", confidence: "likely", title: "No security schemes defined", recommendation: "Declare the authentication schemes the API uses (components.securitySchemes / securityDefinitions) and apply them globally or per operation. If the API is intentionally public, document that decision." },
  { id: "APISPEC-AUTH-OP-NONE", owasp: "API2", cwe: "CWE-306", severity: "high", confidence: "likely", title: "Write operation without authentication", recommendation: "Require authentication on every state-changing operation. Public write endpoints (sign-up, password reset) need rate limiting and abuse controls instead." },
  { id: "APISPEC-AUTH-OPT-OUT", owasp: "API2", cwe: "CWE-306", severity: "medium", confidence: "review", title: "Operation opts out of global security", recommendation: "Confirm the operation is meant to be anonymous. Remove the empty security: [] override if not." },
  { id: "APISPEC-AUTH-OPTIONAL", owasp: "API2", cwe: "CWE-306", severity: "medium", confidence: "likely", title: "Authentication is optional (empty requirement {})", recommendation: "Remove the empty {} security requirement unless anonymous access is intended for this operation." },
  { id: "APISPEC-BASIC-NO-TLS", owasp: "API2", cwe: "CWE-319", severity: "high", confidence: "confirmed", title: "HTTP Basic authentication offered over plain HTTP", recommendation: "Serve the API over HTTPS only and remove http:// servers. Prefer token-based authentication over Basic.", extra: [ASVS_TLS] },
  { id: "APISPEC-APIKEY-IN-QUERY", owasp: "API2", cwe: "CWE-598", severity: "medium", confidence: "confirmed", title: "API key sent in the query string", recommendation: "Move the API key to a request header. Query strings are written to proxy, server and browser logs." },
  { id: "APISPEC-OAUTH-IMPLICIT", owasp: "API2", cwe: null, severity: "medium", confidence: "confirmed", title: "OAuth implicit flow allowed", recommendation: "Replace the implicit flow with the authorization code flow plus PKCE.", extra: [RFC9700] },
  { id: "APISPEC-OAUTH-PASSWORD", owasp: "API2", cwe: null, severity: "medium", confidence: "confirmed", title: "OAuth resource owner password flow allowed", recommendation: "Remove the password grant; use the authorization code flow plus PKCE (or client credentials for machine clients).", extra: [RFC9700] },
  { id: "APISPEC-WRITE-NO-SCOPES", owasp: "API5", cwe: "CWE-285", severity: "medium", confidence: "likely", title: "Write operation requires OAuth without any scope", recommendation: "Require a write scope on state-changing operations so read-only tokens cannot call them." },
  { id: "APISPEC-ADMIN-NO-AUTH", owasp: "API5", cwe: "CWE-285", severity: "high", confidence: "likely", title: "Administrative path without authentication", recommendation: "Require authentication and an administrative role or scope on admin and internal paths, or remove them from the public definition." },
  { id: "APISPEC-ADMIN-GLOBAL-ONLY", owasp: "API5", cwe: "CWE-285", severity: "medium", confidence: "review", title: "Administrative path uses only the global security", recommendation: "Give admin operations a distinct security requirement (admin scope, separate scheme) so ordinary user tokens cannot call them." },
  { id: "APISPEC-BOLA-CANDIDATE", owasp: "API1", cwe: "CWE-639", severity: "medium", confidence: "review", title: "Object-id endpoint without operation-level authorization", recommendation: "Check in code that the caller owns or may access the object named by the id on every request. Document the required scope at operation level." },
  { id: "APISPEC-MASS-ASSIGNMENT", owasp: "API3", cwe: "CWE-915", severity: "medium", confidence: "likely", title: "Request body accepts privileged properties", recommendation: "Remove privileged properties from writable request schemas (or mark them readOnly) and bind requests to an allow-list of fields." },
  { id: "APISPEC-ADDITIONAL-PROPS", owasp: "API3", cwe: "CWE-915", severity: "low", confidence: "likely", title: "Request object allows additional properties", recommendation: "Set additionalProperties: false on request objects and reject unknown fields server-side." },
  { id: "APISPEC-SENSITIVE-RESPONSE", owasp: "API3", cwe: "CWE-200", severity: "high", confidence: "likely", title: "Response exposes sensitive properties", recommendation: "Remove secrets and regulated data from response schemas, or mark write-only fields writeOnly and filter them server-side." },
  { id: "APISPEC-UNBOUNDED-STRING", owasp: "API4", cwe: "CWE-770", severity: "low", confidence: "confirmed", title: "Request strings without maxLength", recommendation: "Set maxLength on request strings and enforce it server-side." },
  { id: "APISPEC-UNBOUNDED-ARRAY", owasp: "API4", cwe: "CWE-770", severity: "low", confidence: "confirmed", title: "Request arrays without maxItems", recommendation: "Set maxItems on request arrays and enforce it server-side." },
  { id: "APISPEC-UNBOUNDED-INTEGER", owasp: "API4", cwe: "CWE-770", severity: "low", confidence: "confirmed", title: "Request integers without maximum", recommendation: "Set maximum (and minimum) on request integers such as page sizes and quantities." },
  { id: "APISPEC-UPLOAD-NO-LIMIT", owasp: "API4", cwe: "CWE-770", severity: "medium", confidence: "likely", title: "File upload without a documented size limit", recommendation: "Document and enforce a maximum upload size (maxLength on the binary field, a 413 response, or a stated limit)." },
  { id: "APISPEC-NO-PAGINATION", owasp: "API4", cwe: "CWE-770", severity: "low", confidence: "likely", title: "List endpoint without a page-size limit parameter", recommendation: "Add a bounded limit / pageSize parameter (with maximum) and paginate list responses." },
  { id: "APISPEC-NO-429", owasp: "API4", cwe: "CWE-770", severity: "low", confidence: "confirmed", title: "No rate limiting documented (no 429 responses)", recommendation: "Rate-limit the API and document 429 responses and RateLimit headers so clients can back off." },
  { id: "APISPEC-BUSINESS-FLOW", owasp: "API6", cwe: "CWE-799", severity: "low", confidence: "review", title: "Sensitive business flow without documented rate limit", recommendation: "Protect the flow against automation: per-user and per-IP limits, bot detection, step-up verification. Document 429 responses." },
  { id: "APISPEC-SSRF-PARAM", owasp: "API7", cwe: "CWE-918", severity: "medium", confidence: "review", title: "Parameter accepts a URL", recommendation: "Validate server-fetched URLs against an allow-list of schemes and hosts, block private and link-local ranges, and disable redirects when fetching." },
  { id: "APISPEC-HTTP-SERVER", owasp: "API8", cwe: "CWE-319", severity: "medium", confidence: "confirmed", title: "Server URL uses plain HTTP", recommendation: "Serve the API over HTTPS only and redirect or refuse plain HTTP.", extra: [ASVS_TLS] },
  { id: "APISPEC-CORS-WILDCARD", owasp: "API8", cwe: "CWE-942", severity: "medium", confidence: "likely", title: "Wildcard CORS origin documented", recommendation: "Return an explicit allow-list of origins. Never combine a wildcard origin with credentials." },
  { id: "APISPEC-VERBOSE-ERROR", owasp: "API8", cwe: "CWE-209", severity: "low", confidence: "likely", title: "Error response schema exposes internals", recommendation: "Return a generic error body (code, message, correlation id) and keep stack traces and SQL in server logs." },
  { id: "APISPEC-MULTI-VERSION", owasp: "API9", cwe: null, severity: "medium", confidence: "likely", title: "Several API versions exposed", recommendation: "Inventory every live version, set retirement dates for old ones and apply the same security controls to all of them." },
  { id: "APISPEC-DEPRECATED-OP", owasp: "API9", cwe: null, severity: "low", confidence: "confirmed", title: "Deprecated operation still published", recommendation: "Set a removal date, monitor remaining callers and retire the operation." },
  { id: "APISPEC-NONPROD-SERVER", owasp: "API9", cwe: null, severity: "low", confidence: "likely", title: "Non-production server in the definition", recommendation: "Publish separate definitions per environment, and make sure non-production hosts are not reachable from the internet with production data." },
  { id: "APISPEC-GQL-INTROSPECTION", owasp: "API8", cwe: "CWE-200", severity: "medium", confidence: "review", title: "GraphQL introspection result (introspection enabled)", recommendation: "If this came from a production endpoint, disable introspection for unauthenticated clients." },
  { id: "APISPEC-GQL-NO-COST-LIMIT", owasp: "API4", cwe: "CWE-770", severity: "low", confidence: "review", title: "No GraphQL depth or cost controls in the schema", recommendation: "Enforce query depth, complexity or cost limits (and persisted queries where possible) in the GraphQL server.", extra: [ASVS_GQL] },
  { id: "APISPEC-GQL-MUTATION-NO-AUTH", owasp: "API5", cwe: "CWE-285", severity: "high", confidence: "likely", title: "GraphQL mutation without an auth directive", recommendation: "Apply the schema's auth directive to the mutation (or its type), or enforce authorization in the resolver and document it.", extra: [ASVS_GQL] },
  { id: "APISPEC-GQL-ID-ARG", owasp: "API1", cwe: "CWE-639", severity: "medium", confidence: "review", title: "GraphQL query fetches an object by id", recommendation: "Check in the resolver that the caller may access the object named by the id argument.", extra: [ASVS_GQL] },
  { id: "APISPEC-GQL-SENSITIVE-FIELD", owasp: "API3", cwe: "CWE-200", severity: "high", confidence: "likely", title: "GraphQL type exposes sensitive fields", recommendation: "Remove secrets and regulated data from output types or protect the fields with field-level authorization." },
  { id: "APISPEC-GQL-LIST-NO-LIMIT", owasp: "API4", cwe: "CWE-770", severity: "low", confidence: "likely", title: "GraphQL list query without a page-size argument", recommendation: "Add first/last or limit arguments with a server-enforced maximum (for example connection-style pagination)." },
  { id: "APISPEC-PM-SECRET", owasp: "API2", cwe: "CWE-798", severity: "high", confidence: "likely", title: "Credential stored in Postman collection", recommendation: "Remove the value from the collection, rotate it, and reference a Postman environment or vault variable instead." },
  { id: "APISPEC-PM-HTTP", owasp: "API8", cwe: "CWE-319", severity: "medium", confidence: "confirmed", title: "Postman requests use plain HTTP", recommendation: "Call the API over HTTPS only.", extra: [ASVS_TLS] },
];
const RULE = Object.fromEntries(RULES.map((r) => [r.id, r]));

function controlsFor(rule) {
  const c = [{ framework: "OWASP API Security Top 10 2023", id: rule.owasp + ":2023" }];
  if (rule.cwe) c.push({ framework: "CWE", id: rule.cwe });
  c.push({ framework: "NIST SSDF (SP 800-218)", id: "PW.1" });
  for (const x of rule.extra || []) c.push(x);
  return c;
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
const pe = (s) => String(s).replace(/~/g, "~0").replace(/\//g, "~1");
const pu = (s) => String(s).replace(/~1/g, "/").replace(/~0/g, "~");
const isObj = (v) => v != null && typeof v === "object" && !Array.isArray(v);
const norm = (s) => String(s || "").toLowerCase().replace(/[^a-z0-9]/g, "");
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const METHODS = ["get", "put", "post", "delete", "options", "head", "patch", "trace"];
const WRITE = new Set(["post", "put", "patch", "delete"]);

function getPtr(doc, ptr) {
  if (ptr === "" || ptr === "/") return ptr === "" ? doc : doc && doc[""];
  let cur = doc;
  for (const raw of ptr.split("/").slice(1)) {
    let k = pu(raw);
    try { k = decodeURIComponent(k); } catch (_) {}
    if (cur == null || typeof cur !== "object" || !(k in cur)) return undefined;
    cur = cur[k];
  }
  return cur;
}

function safeRegex(src, fallback, flags, skipped, label) {
  try { return new RegExp(src, flags); } catch (_) {
    skipped.push({ check: label, reason: "invalid pattern \"" + String(src).slice(0, 60) + "\"; the default was used" });
    return new RegExp(fallback, flags);
  }
}

// ---------------------------------------------------------------------------
// source location maps (JSON pointer -> 1-based line)
// ---------------------------------------------------------------------------
/** Map every JSON value's pointer to the line it starts on. */
export function jsonLineMap(text) {
  const map = new Map();
  const t = String(text || "");
  const n = t.length;
  let i = t.charCodeAt(0) === 0xfeff ? 1 : 0, line = 1;
  const ws = () => { for (; i < n; i++) { const c = t.charCodeAt(i); if (c === 10) line++; else if (c !== 32 && c !== 9 && c !== 13) break; } };
  const str = () => {
    let j = i + 1;
    while (j < n && t[j] !== '"') j += t[j] === "\\" ? 2 : 1;
    const raw = t.slice(i, j + 1); i = j + 1;
    try { return JSON.parse(raw); } catch (_) { return raw.slice(1, -1); }
  };
  const val = (ptr, depth) => {
    ws(); if (!map.has(ptr)) map.set(ptr, line);
    if (depth > 512 || i >= n) return;
    const c = t[i];
    if (c === "{") {
      i++; ws(); if (t[i] === "}") { i++; return; }
      for (;;) { ws(); if (t[i] !== '"') return; const k = str(); ws(); if (t[i] === ":") i++; val(ptr + "/" + pe(k), depth + 1); ws(); if (t[i] === ",") { i++; continue; } i++; return; }
    }
    if (c === "[") {
      i++; ws(); if (t[i] === "]") { i++; return; }
      for (let k = 0; ; k++) { val(ptr + "/" + k, depth + 1); ws(); if (t[i] === ",") { i++; continue; } i++; return; }
    }
    if (c === '"') { str(); return; }
    while (i < n && !/[,\]}\s]/.test(t[i])) i++;
  };
  try { val("", 0); } catch (_) {}
  return map;
}

function yUnquote(k) {
  const s = k.trim();
  if ((s[0] === '"' && s[s.length - 1] === '"') || (s[0] === "'" && s[s.length - 1] === "'")) return s.slice(1, -1);
  return s;
}

/** Map block-style YAML keys and sequence items to their line. Flow content maps to its parent. */
export function yamlLineMap(text) {
  const map = new Map();
  const lines = String(text || "").replace(/^﻿/, "").split(/\r?\n/);
  const stack = [{ indent: -1, ptr: "", kind: "root", n: -1 }];
  let blockIndent = -1;
  for (let li = 0; li < lines.length; li++) {
    const raw = lines[li].replace(/\t/g, "  ");
    if (!raw.trim() || /^\s*#/.test(raw) || /^(---|\.\.\.)(\s|$)/.test(raw)) continue;
    const ind = raw.length - raw.replace(/^ +/, "").length;
    if (blockIndent >= 0) { if (ind > blockIndent) continue; blockIndent = -1; }
    let col = ind, c = raw.slice(ind);
    const isSeq = c === "-" || c.startsWith("- ");
    while (stack.length > 1) {
      const top = stack[stack.length - 1];
      if (top.indent < ind) break;
      if (top.indent === ind && isSeq && top.kind === "key" && top.open) break;
      stack.pop();
    }
    if (isSeq) {
      const parent = stack[stack.length - 1];
      parent.n = (parent.n == null ? -1 : parent.n) + 1;
      const ptr = parent.ptr + "/" + parent.n;
      if (!map.has(ptr)) map.set(ptr, li + 1);
      stack.push({ indent: ind, ptr, kind: "item", n: -1 });
      const rest = c.slice(1).replace(/^ +/, "");
      if (!rest) continue;
      col = ind + (c.length - rest.length); c = rest;
    }
    const m = /^("(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s#'"\[{][^#]*?)\s*:(?:\s+(.*)|\s*)$/.exec(c);
    if (!m) continue;
    const parent = stack[stack.length - 1];
    const ptr = parent.ptr + "/" + pe(yUnquote(m[1]));
    if (!map.has(ptr)) map.set(ptr, li + 1);
    const rest = (m[2] || "").replace(/\s+#.*$/, "").trim();
    stack.push({ indent: col, ptr, kind: "key", open: rest === "" || /^&\S+$/.test(rest), n: -1 });
    if (/^[|>]/.test(rest)) blockIndent = col;
  }
  return map;
}

function lineOf(map, ptr) {
  let p = ptr || "";
  for (;;) {
    if (map.has(p)) return map.get(p);
    const k = p.lastIndexOf("/");
    if (k < 0) return 1;
    p = p.slice(0, k);
  }
}

// ---------------------------------------------------------------------------
// YAML: anchors / aliases / merge keys (the shared subset parser rejects them)
// ---------------------------------------------------------------------------
const Y_PREFIX = "((?:- +)?(?:(?:\"[^\"]*\"|'[^']*'|[^\\s#'\"&*][^#]*?):[ ]+)?)";
const Y_DEF = new RegExp("^( *)" + Y_PREFIX + "&([\\w.\\-]+)(?:[ ]+(\\S.*))?$");
const Y_ALIAS = new RegExp("^( *)" + Y_PREFIX + "\\*([\\w.\\-]+)\\s*$");

/** Expand block-style anchors, aliases and "<<: *x" merges into plain YAML text. */
export function expandYamlAnchors(text) {
  let lines = String(text || "").replace(/^﻿/, "").split(/\r?\n/);
  const anchors = new Map();
  const indentOf = (l) => l.length - l.replace(/^ +/, "").length;
  for (let pass = 0; pass < 8; pass++) {
    let changed = false;
    const out = [];
    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      let m = Y_DEF.exec(l);
      if (m) {
        const [, ind, prefix, name, inline] = m;
        if (inline != null) { anchors.set(name, { inline }); out.push(ind + prefix + inline); changed = true; continue; }
        const base = ind.length;
        const block = [];
        for (let j = i + 1; j < lines.length && (!lines[j].trim() || indentOf(lines[j]) > base); j++) block.push(lines[j]);
        while (block.length && !block[block.length - 1].trim()) block.pop();
        const min = Math.min(...block.filter((x) => x.trim()).map(indentOf), Infinity);
        anchors.set(name, { block: block.map((x) => (x.trim() ? x.slice(Number.isFinite(min) ? min : 0) : "")) });
        out.push(ind + prefix.trimEnd());
        changed = true; continue;
      }
      m = Y_ALIAS.exec(l);
      if (m && anchors.has(m[3])) {
        const [, ind, prefix, name] = m;
        const a = anchors.get(name);
        changed = true;
        if (/^(- +)?<<:\s*$/.test(prefix.trim() + " ") || /<<:[ ]+$/.test(prefix)) {
          const dash = /^- +/.exec(prefix);
          const col = ind.length + (dash ? dash[0].length : 0);
          if (!a.block) continue;
          // Keys written in the mapping override merged ones (YAML merge spec) and the
          // parser keeps the last duplicate, so splice the merged block in at the start
          // of the mapping rather than after keys already written above it.
          let at = out.length, lead = "";
          if (!dash) {
            while (at > 0 && (!out[at - 1].trim() || indentOf(out[at - 1]) >= col)) at--;
            const d = at > 0 ? /^( *- +)/.exec(out[at - 1]) : null;
            if (d && d[1].length === col) { at--; lead = d[1]; out[at] = " ".repeat(col) + out[at].slice(col); }
          }
          out.splice(at, 0, ...a.block.map((x, k) => (k === 0 && (dash || lead) ? (lead || ind + dash[0]) + x : x ? " ".repeat(col) + x : "")));
          continue;
        }
        if (a.inline != null) { out.push(ind + prefix + a.inline); continue; }
        const dash = /^- +/.exec(prefix);
        const keyPart = prefix.slice(dash ? dash[0].length : 0);
        if (!keyPart) {
          const col = ind.length + dash[0].length;
          a.block.forEach((x, k) => out.push(k === 0 ? ind + dash[0] + x : x ? " ".repeat(col) + x : ""));
        } else {
          const col = ind.length + (dash ? dash[0].length : 0) + 2;
          out.push(ind + prefix.trimEnd());
          for (const x of a.block) out.push(x ? " ".repeat(col) + x : "");
        }
        continue;
      }
      out.push(l);
    }
    lines = out;
    if (!changed) break;
  }
  return lines.join("\n");
}

/** Parse YAML with the shared subset parser, expanding anchors locally when needed. */
export function parseYaml(text) {
  try { return parseYamlSubset(text); } catch (e) {
    if (!/anchor|alias/i.test(String(e && e.message))) throw e;
    return parseYamlSubset(expandYamlAnchors(text));
  }
}

// ---------------------------------------------------------------------------
// GraphQL SDL parser (types, fields, arguments, applied directives)
// ---------------------------------------------------------------------------
function gqlTokens(src) {
  const toks = [];
  const n = src.length;
  let i = 0, line = 1;
  while (i < n) {
    const c = src[i];
    if (c === "\n") { line++; i++; continue; }
    if (c === " " || c === "\t" || c === "\r" || c === "," || c === "﻿") { i++; continue; }
    if (c === "#") { while (i < n && src[i] !== "\n") i++; continue; }
    if (src.startsWith('"""', i)) {
      let e = i + 3;
      while (e < n && !(src.startsWith('"""', e) && src[e - 1] !== "\\")) e++;
      const end = Math.min(n, e + 3);
      toks.push({ t: "str", line });
      for (let k = i; k < end; k++) if (src[k] === "\n") line++;
      i = end; continue;
    }
    if (c === '"') {
      let j = i + 1;
      while (j < n && src[j] !== '"' && src[j] !== "\n") j += src[j] === "\\" ? 2 : 1;
      toks.push({ t: "str", line }); i = j + 1; continue;
    }
    if (src.startsWith("...", i)) { toks.push({ t: "p", v: "...", line }); i += 3; continue; }
    if ("!$&()=:@[]{}|".indexOf(c) >= 0) { toks.push({ t: "p", v: c, line }); i++; continue; }
    const nm = /^[_A-Za-z][_0-9A-Za-z]*/.exec(src.slice(i, i + 256));
    if (nm) { toks.push({ t: "n", v: nm[0], line }); i += nm[0].length; continue; }
    const num = /^-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(src.slice(i, i + 64));
    if (num) { toks.push({ t: "num", v: num[0], line }); i += num[0].length; continue; }
    throw new Error("GraphQL: unexpected character \"" + c + "\" (line " + line + ")");
  }
  return toks;
}

/** Parse GraphQL SDL into { types, directiveDefs, applied, schema }. Throws on syntax errors. */
export function parseGraphqlSdl(src) {
  const T = gqlTokens(String(src || ""));
  let p = 0;
  const lineNow = () => (T[p] || T[T.length - 1] || { line: 1 }).line;
  const err = (m) => new Error("GraphQL: " + m + " (line " + lineNow() + ")");
  const isP = (v) => T[p] && T[p].t === "p" && T[p].v === v;
  const isN = (v) => T[p] && T[p].t === "n" && T[p].v === v;
  const expectP = (v) => { if (!isP(v)) throw err("expected \"" + v + "\""); p++; };
  const name = () => { const t = T[p]; if (!t || t.t !== "n") throw err("expected a name"); p++; return t.v; };
  const skipDesc = () => { while (T[p] && T[p].t === "str") p++; };
  const model = { types: {}, directiveDefs: [], applied: [], schema: { query: "Query", mutation: "Mutation", subscription: "Subscription" } };
  const applied = new Set();
  const skipValue = () => {
    if (isP("[") || isP("{")) {
      const open = T[p].v, close = open === "[" ? "]" : "}";
      let d = 0;
      do { if (isP(open)) d++; else if (isP(close)) d--; p++; } while (p < T.length && d > 0);
      if (d > 0) throw err("unterminated value");
      return;
    }
    if (isP("$")) { p += 2; return; }
    if (p >= T.length) throw err("expected a value");
    p++;
  };
  const directives = () => {
    const out = [];
    while (isP("@")) {
      p++; const d = name(); out.push(d); applied.add(d);
      if (isP("(")) { p++; while (!isP(")")) { name(); expectP(":"); skipValue(); } p++; }
    }
    return out;
  };
  const typeRef = () => {
    if (isP("[")) { p++; const inner = typeRef(); expectP("]"); let nn = false; if (isP("!")) { p++; nn = true; } return { name: inner.name, list: true, nonNull: nn }; }
    const n = name(); let nn = false; if (isP("!")) { p++; nn = true; }
    return { name: n, list: false, nonNull: nn };
  };
  const args = () => {
    const out = [];
    if (!isP("(")) return out;
    p++;
    while (!isP(")")) { skipDesc(); const n = name(); expectP(":"); const t = typeRef(); if (isP("=")) { p++; skipValue(); } directives(); out.push({ name: n, type: t }); }
    p++;
    return out;
  };
  const fieldsOf = (input) => {
    const out = [];
    if (!isP("{")) return out;
    p++;
    while (!isP("}")) {
      skipDesc(); const line = lineNow(); const n = name(); const a = input ? [] : args(); expectP(":"); const t = typeRef();
      if (isP("=")) { p++; skipValue(); }
      out.push({ name: n, args: a, type: t, directives: directives(), line });
    }
    p++;
    return out;
  };
  const addType = (kind, n, line) => (model.types[n] = model.types[n] || { kind, name: n, fields: [], directives: [], line });
  while (p < T.length) {
    skipDesc(); if (p >= T.length) break;
    const line = lineNow();
    let kw = name(); if (kw === "extend") kw = name();
    if (kw === "schema") {
      directives(); expectP("{");
      while (!isP("}")) { const op = name(); expectP(":"); model.schema[op] = name(); }
      p++; continue;
    }
    if (kw === "directive") {
      expectP("@"); const n = name(); args(); if (isN("repeatable")) p++;
      if (name() !== "on") throw err("expected \"on\"");
      if (isP("|")) p++; name(); while (isP("|")) { p++; name(); }
      model.directiveDefs.push(n); continue;
    }
    if (kw === "type" || kw === "interface" || kw === "input") {
      const n = name();
      if (isN("implements")) { p++; if (isP("&")) p++; name(); while (isP("&")) { p++; name(); } }
      const t = addType(kw === "input" ? "INPUT_OBJECT" : kw === "interface" ? "INTERFACE" : "OBJECT", n, line);
      t.directives.push(...directives());
      t.fields.push(...fieldsOf(kw === "input"));
      continue;
    }
    if (kw === "enum") { const n = name(); directives(); if (isP("{")) { p++; while (!isP("}")) { skipDesc(); name(); directives(); } p++; } addType("ENUM", n, line); continue; }
    if (kw === "scalar") { const n = name(); directives(); addType("SCALAR", n, line); continue; }
    if (kw === "union") { const n = name(); directives(); if (isP("=")) { p++; if (isP("|")) p++; name(); while (isP("|")) { p++; name(); } } addType("UNION", n, line); continue; }
    throw err("unexpected \"" + kw + "\"");
  }
  model.applied = [...applied].sort();
  model.directiveDefs.sort();
  return model;
}

function unwrapIntro(t) {
  let list = false, nonNull = false, cur = t, guard = 0;
  while (cur && cur.ofType && guard++ < 16) { if (cur.kind === "LIST") list = true; if (cur.kind === "NON_NULL" && !list) nonNull = true; cur = cur.ofType; }
  if (cur && cur.kind === "LIST") list = true;
  return { name: (cur && cur.name) || "", list, nonNull };
}

/** Normalize an introspection result ({__schema} or {data:{__schema}}) to the SDL model shape. */
export function introspectionToModel(obj) {
  const root = obj && obj.__schema ? { s: obj.__schema, base: "/__schema" } : { s: obj && obj.data && obj.data.__schema, base: "/data/__schema" };
  const s = root.s || {};
  const model = {
    types: {}, directiveDefs: (s.directives || []).map((d) => d && d.name).filter(Boolean).sort(), applied: [], introspection: true,
    schema: { query: (s.queryType && s.queryType.name) || "Query", mutation: (s.mutationType && s.mutationType.name) || "", subscription: (s.subscriptionType && s.subscriptionType.name) || "" },
  };
  (s.types || []).forEach((t, ti) => {
    if (!t || !t.name || /^__/.test(t.name)) return;
    const tp = root.base + "/types/" + ti;
    const fl = t.kind === "INPUT_OBJECT" ? t.inputFields || [] : t.fields || [];
    const fkey = t.kind === "INPUT_OBJECT" ? "inputFields" : "fields";
    model.types[t.name] = {
      kind: t.kind, name: t.name, directives: [], ptr: tp,
      fields: fl.filter(Boolean).map((f, fi) => ({ name: f.name, type: unwrapIntro(f.type), args: (f.args || []).map((a) => ({ name: a.name, type: unwrapIntro(a.type) })), directives: [], ptr: tp + "/" + fkey + "/" + fi })),
    };
  });
  return model;
}

// ---------------------------------------------------------------------------
// detection + parsing
// ---------------------------------------------------------------------------
const FORMAT_LABEL = {
  "openapi-3.0": "OpenAPI 3.0", "openapi-3.1": "OpenAPI 3.1", "openapi-3": "OpenAPI 3.x", "swagger-2.0": "Swagger 2.0",
  "postman-2.1": "Postman collection v2.1", "postman-2.0": "Postman collection v2.0", "graphql-sdl": "GraphQL SDL",
  "graphql-introspection": "GraphQL introspection JSON", unknown: "Not an API definition", empty: "Empty", error: "Unreadable",
};
export { FORMAT_LABEL };

function classifyObject(o) {
  if (!isObj(o)) return { format: "unknown", confidence: "low", reason: "not a JSON/YAML object" };
  if (typeof o.openapi === "string" || typeof o.openapi === "number") {
    const v = String(o.openapi);
    if (/^3\.0(\.|$)/.test(v)) return { format: "openapi-3.0", confidence: isObj(o.paths) || isObj(o.components) ? "high" : "medium" };
    if (/^3\.1(\.|$)/.test(v)) return { format: "openapi-3.1", confidence: isObj(o.paths) || isObj(o.webhooks) || isObj(o.components) ? "high" : "medium" };
    if (/^3\./.test(v)) return { format: "openapi-3", confidence: "medium", reason: "OpenAPI " + v + " treated as 3.x" };
  }
  if (String(o.swagger) === "2.0" || o.swagger === 2) return { format: "swagger-2.0", confidence: isObj(o.paths) ? "high" : "medium" };
  if (isObj(o.info) && Array.isArray(o.item)) {
    const sch = String(o.info.schema || "");
    if (/collection\/v2\.1/.test(sch)) return { format: "postman-2.1", confidence: "high" };
    if (/collection\/v2\.0/.test(sch)) return { format: "postman-2.0", confidence: "high" };
    return { format: "postman-2.1", confidence: "medium", reason: "info.schema missing; read as v2.1" };
  }
  if (isObj(o.__schema) || (isObj(o.data) && isObj(o.data.__schema))) return { format: "graphql-introspection", confidence: "high" };
  return { format: "unknown", confidence: "low", reason: "no openapi, swagger, Postman info/item or __schema key" };
}

// Does the text open like GraphQL SDL (after descriptions and comments)? A scanner, not one
// regex: the regex form let a run of quote marks split into "" and """ pieces in exponentially
// many ways, so a file opening with ~60 quotes froze the tab.
function sdlStart(t) {
  let i = 0;
  const n = t.length;
  for (;;) {
    while (i < n && /\s/.test(t[i])) i++;
    if (t.startsWith('"""', i)) { const j = t.indexOf('"""', i + 3); if (j < 0) return false; i = j + 3; continue; }
    if (t[i] === '"') { const j = t.indexOf('"', i + 1), nl = t.indexOf("\n", i + 1); if (j < 0 || (nl >= 0 && nl < j)) return false; i = j + 1; continue; }
    if (t[i] === "#") { const nl = t.indexOf("\n", i); if (nl < 0) return false; i = nl + 1; continue; }
    break;
  }
  return /^(?:extend\s+)?(?:type|schema|input|enum|interface|scalar|union|directive)\b/.test(t.slice(i, i + 200));
}

/** Parse one file into a document model. Never throws. */
export function parseFile(name, text) {
  const nm = String(name || "input");
  const t = String(text == null ? "" : text).replace(/^﻿/, "");
  const base = { name: nm, size: t.length };
  if (!t.trim()) return { ...base, format: "empty", confidence: "high", error: "" };
  const head = t.trimStart()[0];
  const isGqlName = /\.(graphql|graphqls|gql|sdl)$/i.test(nm);
  if (head === "{" || head === "[") {
    let o;
    try { o = JSON.parse(t); } catch (e) { return { ...base, format: "error", confidence: "high", syntax: "json", error: "JSON parse error: " + String(e.message || e).slice(0, 160) }; }
    const c = classifyObject(o);
    return { ...base, ...c, syntax: "json", spec: o };
  }
  if (isGqlName || sdlStart(t)) {
    try {
      const gql = parseGraphqlSdl(t);
      return { ...base, format: "graphql-sdl", confidence: isGqlName || Object.keys(gql.types).length ? "high" : "medium", syntax: "graphql", gql };
    } catch (e) {
      if (isGqlName) return { ...base, format: "error", confidence: "high", syntax: "graphql", error: String(e.message || e).slice(0, 200) };
    }
  }
  let o;
  try { o = parseYaml(t); } catch (e) { return { ...base, format: "error", confidence: "medium", syntax: "yaml", error: String(e.message || e).slice(0, 200) }; }
  if (Array.isArray(o)) o = o.find((d) => isObj(d)) || null;
  const c = classifyObject(o);
  return { ...base, ...c, syntax: "yaml", spec: o };
}

function normFiles(input) {
  if (input == null) return [];
  if (typeof input === "string") return [{ name: "input", text: input }];
  if (Array.isArray(input)) return input.filter(Boolean).map((f, i) => (typeof f === "string" ? { name: "input-" + (i + 1), text: f } : { name: f.name || "input-" + (i + 1), text: f.text == null ? "" : String(f.text) }));
  if (Array.isArray(input.files)) return normFiles(input.files);
  if (Array.isArray(input.rows)) return normFiles(input.rows);
  if (typeof input.text === "string") return [{ name: input.name || "input", text: input.text }];
  return [];
}

/**
 * Detect and parse one or more files. Returns rows = one document per file
 * ({ name, format, label, confidence, error?, text, endpoints }).
 */
export function parseInput(input) {
  const files = normFiles(input);
  const rows = [];
  const skipped = [];
  for (const f of files) {
    const d = parseFile(f.name, f.text);
    if (d.error) skipped.push({ check: "parse:" + d.name, reason: d.error });
    else if (d.format === "unknown") skipped.push({ check: "parse:" + d.name, reason: "not recognised as an API definition (" + (d.reason || "unknown format") + ")" });
    rows.push({ name: d.name, format: d.format, label: FORMAT_LABEL[d.format] || d.format, confidence: d.confidence, error: d.error || "", reason: d.reason || "", text: f.text });
  }
  const format = rows.length === 1 ? rows[0].format : rows.length ? "multi" : "empty";
  return { format, headers: [], rows, skipped };
}

// ---------------------------------------------------------------------------
// OpenAPI / Swagger model
// ---------------------------------------------------------------------------
function serverHost(url) {
  const m = /^[a-z][a-z0-9+.-]*:\/\/([^/?#:]+|\[[^\]]+\])/i.exec(url);
  return m ? m[1].toLowerCase() : "";
}
const isLocalHost = (h) => /^(localhost|127\.\d+\.\d+\.\d+|\[::1\]|0\.0\.0\.0)$/.test(h) || /\.localhost$/.test(h);

function oasServers(spec, swagger) {
  const out = [];
  if (swagger) {
    const host = typeof spec.host === "string" ? spec.host : "";
    const basePath = typeof spec.basePath === "string" ? spec.basePath : "";
    const schemes = Array.isArray(spec.schemes) ? spec.schemes.map(String) : [];
    if (host) {
      if (schemes.length) schemes.forEach((s, i) => out.push({ url: s.toLowerCase() + "://" + host + basePath, ptr: "/schemes/" + i }));
      else out.push({ url: "//" + host + basePath, ptr: "/host" });
    } else if (basePath) out.push({ url: basePath, ptr: "/basePath" });
    return out;
  }
  (Array.isArray(spec.servers) ? spec.servers : []).forEach((s, i) => {
    if (!isObj(s) || typeof s.url !== "string") return;
    let url = s.url;
    if (isObj(s.variables)) url = url.replace(/\{([^}]+)\}/g, (m0, v) => (isObj(s.variables[v]) && s.variables[v].default != null ? String(s.variables[v].default) : m0));
    out.push({ url, ptr: "/servers/" + i + "/url" });
  });
  return out;
}

function schemesOf(spec, swagger) {
  const src = swagger ? spec.securityDefinitions : spec.components && spec.components.securitySchemes;
  const base = swagger ? "/securityDefinitions" : "/components/securitySchemes";
  const out = {};
  if (!isObj(src)) return out;
  for (const name of Object.keys(src)) {
    let s = src[name], ptr = base + "/" + pe(name);
    if (isObj(s) && typeof s.$ref === "string" && s.$ref.startsWith("#")) { const t = getPtr(spec, s.$ref.slice(1)); if (isObj(t)) { s = t; ptr = s.$ref ? ptr : ptr; } }
    if (!isObj(s)) continue;
    const type = String(s.type || "");
    const x = { name, ptr, raw: s, type: type, scheme: String(s.scheme || "").toLowerCase(), in: String(s.in || ""), flows: [] };
    if (swagger && type === "basic") { x.type = "http"; x.scheme = "basic"; }
    if (type === "oauth2") {
      if (swagger) { if (s.flow) x.flows.push({ flow: String(s.flow), ptr: ptr + "/flow" }); }
      else if (isObj(s.flows)) for (const f of Object.keys(s.flows)) x.flows.push({ flow: f, ptr: ptr + "/flows/" + pe(f) });
    }
    out[name] = x;
  }
  return out;
}

function authLabel(reqs, schemes) {
  if (!Array.isArray(reqs) || !reqs.length) return "none";
  const parts = reqs.map((r) => {
    if (!isObj(r) || !Object.keys(r).length) return "anonymous";
    return Object.keys(r).sort().map((k) => {
      const sc = Array.isArray(r[k]) && r[k].length ? "[" + r[k].join(" ") + "]" : "";
      const s = schemes[k];
      return k + (s ? " (" + (s.type === "http" ? s.scheme || "http" : s.type) + ")" : "") + sc;
    }).join(" + ");
  });
  return parts.join(" | ");
}

const LIMIT_PARAMS = new Set(["limit", "pagesize", "perpage", "size", "first", "last", "top", "max", "maxresults", "maxitems", "count", "take", "pagelimit", "batchsize", "num"]);
const MASS_NAMES = new Set(["role", "roles", "isadmin", "admin", "issuperuser", "superuser", "issuperadmin", "isstaff", "permissions", "permission", "privileges", "privilege", "scopes", "accesslevel", "usertype", "accounttype", "isverified", "verified", "emailverified", "isapproved", "approved", "balance", "accountbalance", "walletbalance", "credit", "credits", "ownerid", "owner", "tenantid", "creatorid", "createdby"]);
const SENS_HIGH = new Set(["password", "passwd", "pwd", "passwordhash", "hashedpassword", "ssn", "socialsecuritynumber", "cardnumber", "creditcardnumber", "pan", "cvv", "cvc", "cvv2", "securitycode", "cardverificationvalue", "privatekey", "mfasecret", "totpsecret", "otpsecret", "pin"]);
const SENS_TOKEN = new Set(["secret", "clientsecret", "apisecret", "token", "accesstoken", "refreshtoken", "idtoken", "sessiontoken", "authtoken", "apikey", "apitoken", "secretkey", "signingkey"]);
const TOKEN_PATH = /token|login|signin|sign-in|logon|auth|oauth|session|api-?keys?|credential|secret/i;
const VERBOSE_NAMES = new Set(["stack", "stacktrace", "trace", "traceback", "exception", "exceptionmessage", "innerexception", "debug", "debuginfo", "sql", "sqlstate", "query", "sourcefile"]);
const URL_NAME = /^(?:url|uri|link|href|callback|webhook|redirect|next|target|dest|destination|endpoint|proxy|feed|returnto)$|(?:url|uri|callback|webhook|redirect)$/i;
const URI_FORMATS = new Set(["uri", "url", "uri-reference", "iri", "iri-reference"]);
const BOUNDED_STRING_FORMATS = new Set(["date", "date-time", "time", "uuid", "ipv4", "ipv6", "int32", "int64", "duration", "binary"]);
const SIZE_HINT = /\b(max(?:imum)?[\s_-]*(?:file[\s_-]*)?size|size[\s_-]*limit|up to \d+|\d+(?:\.\d+)?\s*(?:kb|mb|gb|kib|mib|gib|bytes?))\b/i;
const BUSINESS_FLOW = /checkout|purchase|payment|payout|transfer|withdraw|refund|redeem|coupon|voucher|gift-?card|sign-?up|register|password-?reset|reset-?password|forgot-?password|otp|vote|invite|booking|reservation/i;
const RATE_HEADER = /^(x-)?rate-?limit|^retry-after$/i;

function typesOf(s) {
  if (!isObj(s)) return [];
  if (Array.isArray(s.type)) return s.type.map(String);
  if (s.type) return [String(s.type)];
  if (isObj(s.properties)) return ["object"];
  if (s.items) return ["array"];
  return [];
}

function buildOas(doc, file, o, skipped, ctxTotals) {
  const spec = doc.spec;
  const swagger = doc.format === "swagger-2.0";
  const info = isObj(spec.info) ? spec.info : {};
  const title = String(info.title || file).trim();
  const version = info.version != null ? String(info.version) : "";
  const asset = { type: "ASSET", name: (title + (version ? " " + version : "")).slice(0, 200), data: { file, format: doc.format } };
  const servers = oasServers(spec, swagger);
  const schemes = schemesOf(spec, swagger);
  const globalSec = Array.isArray(spec.security) ? spec.security : null;
  const refIssues = new Map();
  const deref = (node, ptr) => {
    let cur = node, cp = ptr;
    const seen = new Set();
    while (isObj(cur) && typeof cur.$ref === "string") {
      const ref = cur.$ref;
      if (!ref.startsWith("#")) { if (!refIssues.has("ext:" + ref)) refIssues.set("ext:" + ref, { check: "external-ref:" + file, reason: "external $ref not fetched: " + ref + " (at " + cp + ")" }); return { node: null, ptr: cp }; }
      if (seen.has(ref)) { if (!refIssues.has("cyc:" + ref)) refIssues.set("cyc:" + ref, { check: "ref-cycle:" + file, reason: "$ref chain loops at " + ref }); return { node: null, ptr: cp }; }
      seen.add(ref);
      const target = getPtr(spec, ref.slice(1));
      if (target === undefined) { if (!refIssues.has("bad:" + ref)) refIssues.set("bad:" + ref, { check: "broken-ref:" + file, reason: "$ref target not found: " + ref + " (at " + cp + ")" }); return { node: null, ptr: cp }; }
      cur = target; cp = ref.slice(1);
    }
    return { node: cur, ptr: cp };
  };
  const st = { budget: 200000, hit: false };
  const walk = (schema, ptr, path, visit, flags = {}, depth = 0, stack = new Set()) => {
    if (st.budget-- <= 0) { st.hit = true; return; }
    const r = deref(schema, ptr);
    const s = r.node;
    if (!isObj(s)) return;
    if (stack.has(r.ptr) || depth > o.maxRefDepth) return;
    stack.add(r.ptr);
    const raw = isObj(schema) ? schema : {};
    const f = { ro: !!(flags.ro || s.readOnly || raw.readOnly), wo: !!(flags.wo || s.writeOnly || raw.writeOnly) };
    visit(s, r.ptr, path, f);
    for (const k of ["allOf", "oneOf", "anyOf"]) if (Array.isArray(s[k])) s[k].forEach((x, i) => walk(x, r.ptr + "/" + k + "/" + i, path, visit, f, depth + 1, stack));
    if (isObj(s.properties)) for (const nm of Object.keys(s.properties)) walk(s.properties[nm], r.ptr + "/properties/" + pe(nm), path ? path + "." + nm : nm, visit, f, depth + 1, stack);
    if (isObj(s.items)) walk(s.items, r.ptr + "/items", path + "[]", visit, f, depth + 1, stack);
    if (isObj(s.additionalProperties)) walk(s.additionalProperties, r.ptr + "/additionalProperties", path + ".*", visit, f, depth + 1, stack);
    stack.delete(r.ptr);
  };

  const ops = [];
  const paths = isObj(spec.paths) ? spec.paths : {};
  for (const p of Object.keys(paths)) {
    const basePtr = "/paths/" + pe(p);
    const ir = deref(paths[p], basePtr);
    const item = ir.node;
    if (!isObj(item)) continue;
    const itemPtr = ir.ptr;
    const pathParams = Array.isArray(item.parameters) ? item.parameters.map((x, i) => [x, itemPtr + "/parameters/" + i]) : [];
    for (const m of METHODS) {
      if (!isObj(item[m])) continue;
      const op = item[m];
      const opPtr = itemPtr + "/" + m;
      const pmap = new Map();
      const opParams = Array.isArray(op.parameters) ? op.parameters.map((x, i) => [x, opPtr + "/parameters/" + i]) : [];
      for (const [raw, ptr] of [...pathParams, ...opParams]) {
        const r = deref(raw, ptr);
        if (!isObj(r.node) || !r.node.name) continue;
        pmap.set(String(r.node.in) + ":" + r.node.name, { name: String(r.node.name), in: String(r.node.in || ""), node: r.node, ptr: r.ptr });
      }
      const params = [...pmap.values()];
      const bodies = [];
      if (swagger) {
        const consumes = Array.isArray(op.consumes) ? op.consumes : Array.isArray(spec.consumes) ? spec.consumes : [];
        for (const pr of params) if (pr.in === "body" && pr.node.schema) bodies.push({ mediaType: String(consumes[0] || "application/json"), schema: pr.node.schema, ptr: pr.ptr + "/schema" });
      } else if (op.requestBody) {
        const rb = deref(op.requestBody, opPtr + "/requestBody");
        if (isObj(rb.node) && isObj(rb.node.content)) for (const mt of Object.keys(rb.node.content)) {
          const c = rb.node.content[mt];
          bodies.push({ mediaType: mt, schema: isObj(c) ? c.schema : null, ptr: rb.ptr + "/content/" + pe(mt) + "/schema", encoding: isObj(c) ? c.encoding : null, desc: String(rb.node.description || "") });
        }
      }
      const responses = [];
      if (isObj(op.responses)) for (const code of Object.keys(op.responses)) {
        const rr = deref(op.responses[code], opPtr + "/responses/" + pe(code));
        if (!isObj(rr.node)) continue;
        const schemas = [];
        if (swagger) { if (rr.node.schema) schemas.push({ mediaType: "application/json", schema: rr.node.schema, ptr: rr.ptr + "/schema" }); }
        else if (isObj(rr.node.content)) for (const mt of Object.keys(rr.node.content)) { const c = rr.node.content[mt]; if (isObj(c) && c.schema) schemas.push({ mediaType: mt, schema: c.schema, ptr: rr.ptr + "/content/" + pe(mt) + "/schema" }); }
        responses.push({ code: String(code), node: rr.node, ptr: rr.ptr, schemas, headers: isObj(rr.node.headers) ? rr.node.headers : {} });
      }
      const declared = Array.isArray(op.security);
      const security = declared ? op.security : globalSec;
      const opServers = !swagger && Array.isArray(op.servers) ? oasServers({ servers: op.servers }, false) : !swagger && Array.isArray(item.servers) ? oasServers({ servers: item.servers }, false) : servers;
      const absServer = opServers.find((s) => /^https?:\/\//i.test(s.url));
      ops.push({
        method: m.toUpperCase(), m, path: p, ptr: opPtr, op, params, bodies, responses, declared, security,
        operation: m.toUpperCase() + " " + p, operationId: String(op.operationId || ""),
        deprecated: op.deprecated === true, url: absServer ? absServer.url.replace(/\/+$/, "") + p : "",
        tags: Array.isArray(op.tags) ? op.tags.map(String) : [],
      });
    }
  }
  ctxTotals.ops += ops.length;
  return { kind: "oas", file, swagger, spec, title, version, asset, servers, schemes, globalSec, ops, walk, deref, st, refIssues };
}

// ---------------------------------------------------------------------------
// finding builder
// ---------------------------------------------------------------------------
function mkFinding(ruleId, x) {
  const rule = RULE[ruleId];
  const ev = x.evidence || [];
  return {
    id: ruleId + ":" + x.file + ":" + (x.pointer || "") + (x.key ? ":" + x.key : ""),
    ruleId, title: x.title || rule.title,
    severity: x.severity || rule.severity,
    confidence: x.confidence || rule.confidence,
    category: rule.owasp + ":2023 " + OWASP_API_2023[rule.owasp],
    owasp: rule.owasp + ":2023",
    file: x.file, operation: x.operation || "", pointer: x.pointer || "", line: x.line || 1, url: x.url || "",
    description: x.description,
    recommendation: x.recommendation || rule.recommendation,
    controls: controlsFor(rule),
    evidence: ev.slice(0, 50), evidenceCount: ev.length,
    assets: x.assets || [],
    tags: ["api", rule.owasp.toLowerCase()],
  };
}

// ---------------------------------------------------------------------------
// OpenAPI / Swagger checks
// ---------------------------------------------------------------------------
function checkOas(M, o, rx, lines, out, skipped) {
  const { file, ops, schemes, globalSec, servers, spec, asset } = M;
  const L = (ptr) => lineOf(lines, ptr);
  const ev = (op, ptr, field, detail) => ({ file, operation: op ? op.operation : "", pointer: ptr, line: L(ptr), field: field || "", detail: detail || "" });
  const push = (rule, x) => out.push(mkFinding(rule, { file, assets: [asset], line: L(x.pointer), ...x }));
  const schemeList = Object.values(schemes);

  // ---- authentication model
  if (!schemeList.length && ops.length) {
    push("APISPEC-AUTH-NO-SCHEMES", { pointer: M.swagger ? "/securityDefinitions" : "/components/securitySchemes", description: "The definition declares " + ops.length + " operation(s) and no security schemes, so no operation documents any authentication.", evidence: ops.slice(0, 50).map((op) => ev(op, op.ptr, "", "no security")) });
  }
  const httpServers = servers.filter((s) => /^http:\/\//i.test(s.url) && !isLocalHost(serverHost(s.url)));
  for (const s of schemeList) {
    if (s.type === "http" && s.scheme === "basic" && httpServers.length) {
      push("APISPEC-BASIC-NO-TLS", { pointer: s.ptr, key: s.name, description: "Security scheme \"" + s.name + "\" is HTTP Basic and the definition lists plain-HTTP server(s): " + httpServers.map((x) => x.url).join(", ") + ". Credentials would cross the network base64-encoded, not encrypted.", evidence: httpServers.map((x) => ev(null, x.ptr, "server", x.url)) });
    }
    if (s.type === "apiKey" && s.in === "query") {
      push("APISPEC-APIKEY-IN-QUERY", { pointer: s.ptr, key: s.name, description: "Security scheme \"" + s.name + "\" sends the API key as query parameter \"" + (s.raw.name || "") + "\".", evidence: [ev(null, s.ptr + "/in", "in", "query")] });
    }
    for (const f of s.flows) {
      if (f.flow === "implicit") push("APISPEC-OAUTH-IMPLICIT", { pointer: f.ptr, key: s.name, description: "OAuth scheme \"" + s.name + "\" offers the implicit flow, which returns access tokens in the redirect URL.", evidence: [ev(null, f.ptr, "flow", "implicit")] });
      if (f.flow === "password") push("APISPEC-OAUTH-PASSWORD", { pointer: f.ptr, key: s.name, description: "OAuth scheme \"" + s.name + "\" offers the resource owner password flow, which hands user passwords to the client.", evidence: [ev(null, f.ptr, "flow", "password")] });
    }
  }
  const authSafe = /login|log-in|signin|sign-in|signup|sign-up|register|token|oauth|health|healthz|status|ping|ready|live|version|public|docs|openapi|swagger|well-known|password-?reset|forgot/i;
  const hasAuth = (reqs) => Array.isArray(reqs) && reqs.length && reqs.some((r) => isObj(r) && Object.keys(r).length);
  const optional = (reqs) => Array.isArray(reqs) && reqs.some((r) => isObj(r) && !Object.keys(r).length);
  const globalHas = hasAuth(globalSec);
  const sameAsGlobal = (op) => !op.declared || JSON.stringify(op.security) === JSON.stringify(globalSec);

  for (const op of ops) {
    const safe = authSafe.test(op.path) || authSafe.test(op.operationId);
    const authed = hasAuth(op.security);
    if (schemeList.length && !authed && WRITE.has(op.m)) {
      push("APISPEC-AUTH-OP-NONE", { pointer: op.ptr, operation: op.operation, url: op.url, severity: safe ? "low" : "high", confidence: safe ? "review" : "likely", description: op.operation + " changes state and has no security requirement" + (op.declared ? " (security: [] at operation level)" : "") + "." + (safe ? " The path looks like a public auth or utility endpoint; confirm and rate-limit it." : ""), evidence: [ev(op, op.declared ? op.ptr + "/security" : op.ptr, "security", authLabel(op.security, schemes))] });
    } else if (op.declared && Array.isArray(op.op.security) && !op.op.security.length && globalHas) {
      push("APISPEC-AUTH-OPT-OUT", { pointer: op.ptr + "/security", operation: op.operation, url: op.url, severity: safe ? "low" : "medium", description: op.operation + " sets security: [] and so drops the global requirement (" + authLabel(globalSec, schemes) + ").", evidence: [ev(op, op.ptr + "/security", "security", "[]")] });
    }
    if (optional(op.security) && authed) {
      const ptr = op.declared ? op.ptr + "/security" : "/security";
      push("APISPEC-AUTH-OPTIONAL", { pointer: ptr, operation: op.operation, url: op.url, description: op.operation + " lists an empty security requirement {}, so anonymous calls are accepted alongside " + authLabel(op.security.filter((r) => isObj(r) && Object.keys(r).length), schemes) + ".", evidence: [ev(op, ptr, "security", authLabel(op.security, schemes))] });
    }
    // admin paths
    const segs = op.path.split("/").filter(Boolean).map((s) => s.replace(/[{}]/g, "").toLowerCase());
    const adminSeg = segs.find((s) => rx.admin.test(s));
    if (adminSeg) {
      if (!authed) push("APISPEC-ADMIN-NO-AUTH", { pointer: op.ptr, operation: op.operation, url: op.url, description: op.operation + " is under an administrative path segment (\"" + adminSeg + "\") and has no security requirement.", evidence: [ev(op, op.ptr, "path segment", adminSeg)] });
      else if (sameAsGlobal(op)) push("APISPEC-ADMIN-GLOBAL-ONLY", { pointer: op.ptr, operation: op.operation, url: op.url, description: op.operation + " is under an administrative path segment (\"" + adminSeg + "\") but only inherits the global security (" + authLabel(op.security, schemes) + "), the same as ordinary operations.", evidence: [ev(op, op.ptr, "security", authLabel(op.security, schemes))] });
    }
    // write without scopes
    if (WRITE.has(op.m) && authed) {
      const oauthReqs = op.security.filter((r) => isObj(r) && Object.keys(r).length && Object.keys(r).every((k) => schemes[k] && (schemes[k].type === "oauth2" || schemes[k].type === "openIdConnect")));
      if (oauthReqs.length && oauthReqs.every((r) => Object.keys(r).every((k) => !Array.isArray(r[k]) || !r[k].length))) {
        const ptr = op.declared ? op.ptr + "/security" : "/security";
        push("APISPEC-WRITE-NO-SCOPES", { pointer: ptr, operation: op.operation, url: op.url, description: op.operation + " changes state and its OAuth requirement lists no scopes (" + authLabel(op.security, schemes) + "), so any valid token is accepted.", evidence: [ev(op, ptr, "scopes", "[]")] });
      }
    }
    // BOLA candidates
    if (["get", "put", "patch", "delete"].includes(op.m)) {
      const tmpl = [...op.path.matchAll(/\{([^}]+)\}/g)].map((x) => x[1]);
      const idParams = tmpl.filter((n) => rx.objectId.test(n));
      const opScoped = op.declared && hasAuth(op.op.security) && op.op.security.some((r) => isObj(r) && Object.values(r).some((v) => Array.isArray(v) && v.length));
      if (idParams.length && !opScoped) {
        const pr = op.params.find((x) => x.in === "path" && idParams.includes(x.name));
        const ptr = pr ? pr.ptr : op.ptr;
        push("APISPEC-BOLA-CANDIDATE", {
          pointer: ptr, operation: op.operation, url: op.url, severity: authed ? "medium" : "high", confidence: authed ? "review" : "likely",
          description: op.operation + " addresses an object by {" + idParams.join("}, {") + "} and " + (authed ? "has no operation-level security or scopes (" + authLabel(op.security, schemes) + " inherited)" : "has no security requirement at all") + ". Object-level authorization cannot be read from the definition.",
          evidence: idParams.map((n) => ev(op, ptr, n, "path parameter")),
        });
      }
    }
    if (op.deprecated) push("APISPEC-DEPRECATED-OP", { pointer: op.ptr + "/deprecated", operation: op.operation, url: op.url, description: op.operation + " is marked deprecated but is still in the published definition.", evidence: [ev(op, op.ptr + "/deprecated", "deprecated", "true")] });
  }

  // ---- property-level checks (request + response schemas)
  for (const op of ops) {
    const reqEv = { mass: [], addl: [], str: [], arr: [], int: [], upload: [], ssrf: [] };
    const seen = new Set();
    const once = (k) => (seen.has(k) ? false : (seen.add(k), true));
    const isWrite = WRITE.has(op.m);
    const lastSeg = norm(op.path.split("/").filter((x) => x && !/^\{.*\}$/.test(x)).pop() || "");
    const has413 = op.responses.some((r) => r.code === "413");
    const opText = String(op.op.description || "") + " " + String(op.op.summary || "");
    const fieldCheck = (s, ptr, path, f, where, mediaType) => {
      const name = path.split(/[.\[\]*]+/).filter(Boolean).pop() || "";
      const nn = norm(name);
      const ty = typesOf(s);
      if (f.ro) return;
      if (isWrite && where === "body" && name && MASS_NAMES.has(nn) && lastSeg !== nn && lastSeg !== nn + "s" && once("mass:" + ptr)) reqEv.mass.push(ev(op, ptr, path, "writable" + (ty.length ? " " + ty.join("|") : "")));
      if (where === "body" && (s.additionalProperties === true || (ty.includes("object") && isObj(s.additionalProperties) && !Object.keys(s.additionalProperties).length)) && once("addl:" + ptr)) reqEv.addl.push(ev(op, ptr, path || "(body)", "additionalProperties: " + JSON.stringify(s.additionalProperties)));
      const isFile = (ty.includes("string") && (s.format === "binary" || s.format === "base64" || s.contentMediaType || s.contentEncoding)) || ty.includes("file") || (/octet-stream|^image\/|^video\/|^audio\//.test(mediaType || "") && (!ty.length || ty.includes("string")));
      if (isFile) {
        const hint = s.maxLength != null || SIZE_HINT.test(String(s.description || "")) || Object.keys(s).some((k) => /^x-.*size/i.test(k)) || has413 || SIZE_HINT.test(opText);
        if (!hint && once("up:" + ptr)) reqEv.upload.push(ev(op, ptr, path || "(body)", (mediaType || "") + " " + (s.format || s.type || "")));
        return;
      }
      if (ty.includes("string") && !ty.includes("object")) {
        const uriFmt = URI_FORMATS.has(String(s.format || ""));
        if ((URL_NAME.test(name) || uriFmt) && once("ssrf:" + ptr)) reqEv.ssrf.push({ ...ev(op, ptr, path, "string" + (s.format ? " format " + s.format : "")), strong: URL_NAME.test(name) && uriFmt });
        if (o.boundStrings && s.maxLength == null && !Array.isArray(s.enum) && s.const === undefined && !BOUNDED_STRING_FORMATS.has(String(s.format || "")) && once("str:" + ptr)) reqEv.str.push(ev(op, ptr, path || "(body)", "string" + (s.format ? " (" + s.format + ")" : "")));
      }
      if (o.boundArrays && ty.includes("array") && s.maxItems == null && once("arr:" + ptr)) reqEv.arr.push(ev(op, ptr, path || "(body)", "array"));
      if (o.boundIntegers && ty.includes("integer") && s.maximum == null && typeof s.exclusiveMaximum !== "number" && !Array.isArray(s.enum) && once("int:" + ptr)) reqEv.int.push(ev(op, ptr, path || "(body)", "integer" + (s.format ? " (" + s.format + ")" : "")));
    };
    for (const pr of op.params) {
      if (pr.in === "body") continue;
      const sch = pr.node.schema ? pr.node.schema : pr.node; // Swagger 2 non-body params carry type inline
      const sptr = pr.node.schema ? pr.ptr + "/schema" : pr.ptr;
      const label = pr.in + " " + pr.name;
      if (pr.node.schema) M.walk(sch, sptr, label, (s, ptr, path, f) => fieldCheck(s, ptr, path, f, "param", pr.in === "formData" ? "multipart/form-data" : ""));
      else fieldCheck(sch, sptr, label, { ro: false }, "param", pr.in === "formData" && pr.node.type === "file" ? "multipart/form-data" : "");
    }
    for (const b of op.bodies) {
      if (!b.schema) { if (/octet-stream/.test(b.mediaType) && !has413 && !SIZE_HINT.test(opText + " " + (b.desc || "")) && once("up:" + b.ptr)) reqEv.upload.push(ev(op, b.ptr, "(body)", b.mediaType)); continue; }
      M.walk(b.schema, b.ptr, "", (s, ptr, path, f) => fieldCheck(s, ptr, path, f, "body", b.mediaType));
    }
    const first = (arr) => arr[0].pointer;
    const fields = (arr) => arr.slice(0, 8).map((e) => e.field).join(", ") + (arr.length > 8 ? " and " + (arr.length - 8) + " more" : "");
    if (reqEv.mass.length) out.push(mkFinding("APISPEC-MASS-ASSIGNMENT", { file, assets: [asset], operation: op.operation, url: op.url, pointer: first(reqEv.mass), line: L(first(reqEv.mass)), description: op.operation + " accepts privileged properties in its request body: " + fields(reqEv.mass) + ". A client could set them directly unless the server ignores them.", evidence: reqEv.mass }));
    if (reqEv.addl.length) out.push(mkFinding("APISPEC-ADDITIONAL-PROPS", { file, assets: [asset], operation: op.operation, url: op.url, pointer: first(reqEv.addl), line: L(first(reqEv.addl)), description: op.operation + " request objects accept arbitrary extra properties: " + fields(reqEv.addl) + ".", evidence: reqEv.addl }));
    if (reqEv.str.length) out.push(mkFinding("APISPEC-UNBOUNDED-STRING", { file, assets: [asset], operation: op.operation, url: op.url, pointer: first(reqEv.str), line: L(first(reqEv.str)), description: op.operation + " has " + reqEv.str.length + " request string(s) without maxLength: " + fields(reqEv.str) + ".", evidence: reqEv.str }));
    if (reqEv.arr.length) out.push(mkFinding("APISPEC-UNBOUNDED-ARRAY", { file, assets: [asset], operation: op.operation, url: op.url, pointer: first(reqEv.arr), line: L(first(reqEv.arr)), description: op.operation + " has " + reqEv.arr.length + " request array(s) without maxItems: " + fields(reqEv.arr) + ".", evidence: reqEv.arr }));
    if (reqEv.int.length) out.push(mkFinding("APISPEC-UNBOUNDED-INTEGER", { file, assets: [asset], operation: op.operation, url: op.url, pointer: first(reqEv.int), line: L(first(reqEv.int)), description: op.operation + " has " + reqEv.int.length + " request integer(s) without maximum: " + fields(reqEv.int) + ".", evidence: reqEv.int }));
    if (reqEv.upload.length) out.push(mkFinding("APISPEC-UPLOAD-NO-LIMIT", { file, assets: [asset], operation: op.operation, url: op.url, pointer: first(reqEv.upload), line: L(first(reqEv.upload)), description: op.operation + " accepts file content (" + fields(reqEv.upload) + ") with no maxLength, size statement or 413 response.", evidence: reqEv.upload }));
    if (reqEv.ssrf.length) {
      const strong = reqEv.ssrf.some((e) => e.strong);
      const evs = reqEv.ssrf.map(({ strong: _s, ...e }) => e);
      out.push(mkFinding("APISPEC-SSRF-PARAM", { file, assets: [asset], operation: op.operation, url: op.url, pointer: evs[0].pointer, line: L(evs[0].pointer), severity: strong ? "medium" : "low", description: op.operation + " accepts URL-like input (" + fields(evs) + "). If the server fetches or redirects to it, it can be steered to internal hosts.", evidence: evs }));
    }

    // responses
    const sens = [], verbose = [], cors = [];
    const tokenish = TOKEN_PATH.test(op.path) || TOKEN_PATH.test(op.operationId);
    for (const r of op.responses) {
      const isErr = /^5/.test(r.code) || r.code === "default";
      for (const sc of r.schemas) {
        M.walk(sc.schema, sc.ptr, "", (s, ptr, path, f) => {
          if (f.wo || !path) return;
          const name = path.split(/[.\[\]*]+/).filter(Boolean).pop() || "";
          const nn = norm(name);
          if (SENS_HIGH.has(nn) || (SENS_TOKEN.has(nn) && !tokenish)) { if (once("sens:" + ptr)) sens.push({ ...ev(op, ptr, r.code + " " + path, SENS_HIGH.has(nn) ? "regulated or credential data" : "secret or token"), high: SENS_HIGH.has(nn) }); }
          if (isErr && VERBOSE_NAMES.has(nn) && once("vb:" + ptr)) verbose.push(ev(op, ptr, r.code + " " + path, "error body property"));
        });
      }
      for (const hn of Object.keys(r.headers)) {
        if (!/^access-control-allow-origin$/i.test(hn)) continue;
        const hr = M.deref(r.headers[hn], r.ptr + "/headers/" + pe(hn));
        const h = hr.node;
        if (!isObj(h)) continue;
        const s = isObj(h.schema) ? h.schema : h;
        const vals = [h.example, h["x-example"], s.example, s.default, s.const, ...(Array.isArray(s.enum) ? s.enum : []), ...(isObj(h.examples) ? Object.values(h.examples).map((e) => (isObj(e) ? e.value : e)) : [])];
        if (vals.some((v) => v === "*")) {
          const cred = Object.keys(r.headers).some((k) => /^access-control-allow-credentials$/i.test(k) && JSON.stringify(r.headers[k]).includes("true"));
          if (once("cors:" + hr.ptr)) cors.push({ ...ev(op, hr.ptr, r.code + " " + hn, "*" + (cred ? " with Access-Control-Allow-Credentials true" : "")), cred });
        }
      }
    }
    if (sens.length) {
      const hi = sens.some((e) => e.high);
      const evs = sens.map(({ high: _h, ...e }) => e);
      out.push(mkFinding("APISPEC-SENSITIVE-RESPONSE", { file, assets: [asset], operation: op.operation, url: op.url, pointer: evs[0].pointer, line: L(evs[0].pointer), severity: hi ? "high" : "medium", description: op.operation + " returns sensitive properties: " + fields(evs) + ".", evidence: evs }));
    }
    if (verbose.length) out.push(mkFinding("APISPEC-VERBOSE-ERROR", { file, assets: [asset], operation: op.operation, url: op.url, pointer: verbose[0].pointer, line: L(verbose[0].pointer), description: op.operation + " documents error bodies with internal details: " + fields(verbose) + ".", evidence: verbose }));
    if (cors.length) {
      const cred = cors.some((e) => e.cred);
      const evs = cors.map(({ cred: _c, ...e }) => e);
      out.push(mkFinding("APISPEC-CORS-WILDCARD", { file, assets: [asset], operation: op.operation, url: op.url, pointer: evs[0].pointer, line: L(evs[0].pointer), severity: cred ? "high" : "medium", description: op.operation + " documents Access-Control-Allow-Origin: *" + (cred ? " together with Access-Control-Allow-Credentials: true" : "") + ".", evidence: evs }));
    }

    // pagination
    if (op.m === "get" && !/\}\/?$/.test(op.path)) {
      const ok = op.responses.filter((r) => /^2/.test(r.code));
      let listy = null;
      for (const r of ok) for (const sc of r.schemas) {
        const d = M.deref(sc.schema, sc.ptr);
        const s = d.node;
        if (!isObj(s)) continue;
        if (typesOf(s).includes("array")) { listy = listy || { ptr: d.ptr, what: "array response" }; continue; }
        if (isObj(s.properties)) for (const k of Object.keys(s.properties)) {
          const pd = M.deref(s.properties[k], d.ptr + "/properties/" + pe(k));
          if (isObj(pd.node) && typesOf(pd.node).includes("array")) { listy = listy || { ptr: pd.ptr, what: "array property " + k }; break; }
        }
      }
      if (listy && !op.params.some((pr) => pr.in === "query" && LIMIT_PARAMS.has(norm(pr.name)))) {
        out.push(mkFinding("APISPEC-NO-PAGINATION", { file, assets: [asset], operation: op.operation, url: op.url, pointer: op.ptr, line: L(op.ptr), description: op.operation + " returns a list (" + listy.what + ") and takes no page-size parameter (limit, pageSize, per_page, first, top...).", evidence: [ev(op, listy.ptr, listy.what, "query params: " + (op.params.filter((pr) => pr.in === "query").map((pr) => pr.name).join(", ") || "none"))] }));
      }
    }
    // business flows
    const limited = op.responses.some((r) => r.code === "429" || Object.keys(r.headers).some((h) => RATE_HEADER.test(h)));
    if (["post", "put", "patch"].includes(op.m) && (BUSINESS_FLOW.test(op.path) || BUSINESS_FLOW.test(op.operationId)) && !limited) {
      const word = (BUSINESS_FLOW.exec(op.path) || BUSINESS_FLOW.exec(op.operationId))[0];
      out.push(mkFinding("APISPEC-BUSINESS-FLOW", { file, assets: [asset], operation: op.operation, url: op.url, pointer: op.ptr, line: L(op.ptr), description: op.operation + " looks like a sensitive business flow (\"" + word + "\") and documents no 429 response or rate-limit header.", evidence: [ev(op, op.ptr + "/responses", "responses", op.responses.map((r) => r.code).join(", ") || "none")] }));
    }
  }

  // ---- doc-level: 429, servers, versions
  if (ops.length) {
    const any429 = ops.some((op) => op.responses.some((r) => r.code === "429" || Object.keys(r.headers).some((h) => RATE_HEADER.test(h))));
    if (!any429) push("APISPEC-NO-429", { pointer: "/paths", description: "None of the " + ops.length + " operation(s) documents a 429 Too Many Requests response or a rate-limit header.", evidence: ops.map((op) => ev(op, op.ptr + "/responses", "responses", op.responses.map((r) => r.code).join(", ") || "none")) });
  }
  const seenSrv = new Set();
  for (const s of httpServers) {
    if (seenSrv.has(s.url)) continue; seenSrv.add(s.url);
    push("APISPEC-HTTP-SERVER", { pointer: s.ptr, key: s.url, description: "Server " + s.url + " uses plain HTTP; traffic and credentials are readable on the network path.", evidence: [ev(null, s.ptr, "server", s.url)] });
  }
  if (M.swagger && Array.isArray(spec.schemes) && spec.schemes.includes("http") && !httpServers.length && !spec.host) {
    push("APISPEC-HTTP-SERVER", { pointer: "/schemes", description: "schemes lists http, so the API is offered over plain HTTP.", evidence: [ev(null, "/schemes", "schemes", spec.schemes.join(", "))] });
  }
  const allServers = [...servers];
  for (const op of ops) if (!M.swagger && (Array.isArray(op.op.servers))) allServers.push(...oasServers({ servers: op.op.servers }, false).map((s) => ({ ...s, ptr: op.ptr + s.ptr })));
  const np = new Set();
  for (const s of allServers) {
    const host = serverHost(s.url);
    if (!host) continue;
    const label = host.split(/[.\-]/).find((x) => rx.nonProd.test(x));
    if (label && !np.has(s.url)) {
      np.add(s.url);
      push("APISPEC-NONPROD-SERVER", { pointer: s.ptr, key: s.url, description: "Server " + s.url + " has a non-production host label (\"" + label + "\").", evidence: [ev(null, s.ptr, "server", s.url)] });
    }
  }
  const versions = new Map();
  const addV = (v, where, ptr) => { const k = "v" + v; if (!versions.has(k)) versions.set(k, []); versions.get(k).push({ where, ptr }); };
  for (const s of allServers) { const m = /\/v(\d+)(?:\.\d+)*(?:\/|$)/i.exec(s.url.replace(/^[a-z]+:\/\/[^/]+/i, "")); if (m) addV(m[1], s.url, s.ptr); }
  for (const op of ops) { const m = /^\/v(\d+)(?:\.\d+)*(?:\/|$)/i.exec(op.path); if (m) addV(m[1], op.operation, op.ptr); }
  if (versions.size > 1) {
    const keys = [...versions.keys()].sort((a, b) => Number(a.slice(1)) - Number(b.slice(1)));
    push("APISPEC-MULTI-VERSION", { pointer: versions.get(keys[0])[0].ptr, description: "The definition exposes " + keys.length + " API versions (" + keys.map((k) => k + ": " + versions.get(k).length + " place(s)").join(", ") + "). Older versions are often left with weaker controls.", evidence: keys.flatMap((k) => versions.get(k).map((x) => ev(null, x.ptr, k, x.where))) });
  }
  for (const v of M.refIssues.values()) skipped.push(v);
  if (M.st.hit) skipped.push({ check: "schema-walk:" + file, reason: "schema traversal budget reached; some deeply shared schemas were not fully checked" });
}

// ---------------------------------------------------------------------------
// GraphQL checks
// ---------------------------------------------------------------------------
const AUTH_DIRECTIVE = /^(auth|authenticated|authorized|authorize|requireauth|requiresauth|isauthenticated|hasrole|hasroles|hasscope|hasscopes|haspermission|haspermissions|requiresscopes|requirespolicy|policy|private|protected|secured|role|roles|permission|permissions|scope|scopes|access|aws_auth|aws_iam|aws_cognito_user_pools|aws_oidc|aws_lambda|aws_api_key)$/i;
const COST_DIRECTIVE = /cost|complexity|depth|ratelimit|rate_limit|throttle|listsize/i;
const GQL_LIMIT_ARGS = new Set(["first", "last", "limit", "take", "top", "pagesize", "perpage", "max", "count", "size"]);

function checkGraphql(doc, lines, out, skipped, inventory) {
  const file = doc.name;
  const g = doc.gql;
  const intro = !!g.introspection;
  const asset = { type: "ASSET", name: file.replace(/\.[^.]+$/, "") + " (GraphQL)", data: { file, format: doc.format } };
  const loc = (x) => (intro ? { pointer: x.ptr || "", line: lineOf(lines, x.ptr || "") } : { pointer: "", line: x.line || 1 });
  const ev = (opName, x, field, detail) => ({ file, operation: opName, ...loc(x), field, detail });
  const push = (rule, x) => out.push(mkFinding(rule, { file, assets: [asset], ...x }));
  const q = g.types[g.schema.query || "Query"];
  const mu = g.schema.mutation ? g.types[g.schema.mutation] : null;
  const sub = g.schema.subscription ? g.types[g.schema.subscription] : null;
  const counts = new Map();
  const roots = [["QUERY", q], ["MUTATION", mu], ["SUBSCRIPTION", sub]];
  for (const [kind, t] of roots) if (t) for (const f of t.fields) inventory.push({ file, method: kind, path: t.name + "." + f.name, operation: t.name + "." + f.name, operationId: f.name, auth: intro ? "not in introspection" : (f.directives.concat(t.directives).filter((d) => AUTH_DIRECTIVE.test(d)).map((d) => "@" + d).join(" ") || "none"), deprecated: false, url: "", pointer: loc(f).pointer, line: loc(f).line });

  if (intro) {
    const ptr = doc.spec && doc.spec.__schema ? "/__schema" : "/data/__schema";
    push("APISPEC-GQL-INTROSPECTION", { pointer: ptr, line: lineOf(lines, ptr), description: "This file is a GraphQL introspection result (" + Object.keys(g.types).length + " types), so introspection was enabled on the endpoint it was taken from. If that endpoint serves production traffic, anyone can enumerate the full schema.", evidence: [{ file, operation: "", pointer: ptr, line: lineOf(lines, ptr), field: "__schema", detail: "query " + (g.schema.query || "-") + ", mutation " + (g.schema.mutation || "-") }] });
  }
  const costDirs = g.directiveDefs.concat(g.applied).filter((d) => COST_DIRECTIVE.test(d));
  if (!costDirs.length && (q || mu)) {
    push("APISPEC-GQL-NO-COST-LIMIT", { pointer: intro ? (doc.spec.__schema ? "/__schema/directives" : "/data/__schema/directives") : "", line: intro ? lineOf(lines, doc.spec.__schema ? "/__schema/directives" : "/data/__schema/directives") : 1, description: "No depth, complexity, cost or rate-limit directive is defined or applied (" + (g.directiveDefs.length ? "defined: @" + g.directiveDefs.join(", @") : "no directive definitions") + "). Limits may still be enforced in server configuration; confirm they are.", evidence: [{ file, operation: "", pointer: "", line: 1, field: "directives", detail: g.directiveDefs.length + " defined, " + g.applied.length + " applied" }] });
  }
  const authDirs = g.applied.filter((d) => AUTH_DIRECTIVE.test(d));
  const hasAuthDir = (t, f) => f.directives.concat(t.directives).some((d) => AUTH_DIRECTIVE.test(d));
  if (mu) {
    if (intro) skipped.push({ check: "graphql-mutation-auth:" + file, reason: "introspection results do not include applied directives; upload the SDL to check mutation auth directives" });
    else if (authDirs.length) {
      for (const f of mu.fields) {
        if (hasAuthDir(mu, f)) continue;
        const opName = mu.name + "." + f.name;
        counts.set(opName, (counts.get(opName) || 0) + 1);
        push("APISPEC-GQL-MUTATION-NO-AUTH", { operation: opName, key: f.name, ...loc(f), description: "Mutation field " + opName + " has no auth directive while the schema uses @" + authDirs.join(", @") + " elsewhere.", evidence: [ev(opName, f, f.name, "directives: " + (f.directives.length ? "@" + f.directives.join(" @") : "none"))] });
      }
    }
  }
  if (q) {
    for (const f of q.fields) {
      const opName = q.name + "." + f.name;
      const idArgs = f.args.filter((a) => a.type.name === "ID" || /^(id|uuid|guid)$|(Id|ID|_id)$/.test(a.name));
      if (idArgs.length && !(authDirs.length && hasAuthDir(q, f) && f.directives.some((d) => AUTH_DIRECTIVE.test(d)))) {
        push("APISPEC-GQL-ID-ARG", { operation: opName, key: f.name, ...loc(f), description: "Query field " + opName + " fetches " + (f.type.name || "an object") + " by " + idArgs.map((a) => a.name + ": " + a.type.name).join(", ") + ". Object-level authorization must be enforced in the resolver.", evidence: idArgs.map((a) => ev(opName, f, a.name, a.type.name + (a.type.nonNull ? "!" : ""))) });
      }
      if (f.type.list && !f.args.some((a) => GQL_LIMIT_ARGS.has(norm(a.name)))) {
        push("APISPEC-GQL-LIST-NO-LIMIT", { operation: opName, key: f.name, ...loc(f), description: "Query field " + opName + " returns a list of " + f.type.name + " and takes no first/last/limit argument.", evidence: [ev(opName, f, f.name, "[" + f.type.name + "] args: " + (f.args.map((a) => a.name).join(", ") || "none"))] });
      }
    }
  }
  const rootNames = new Set([q && q.name, mu && mu.name, sub && sub.name].filter(Boolean));
  for (const name of Object.keys(g.types).sort()) {
    const t = g.types[name];
    if (t.kind !== "OBJECT" && t.kind !== "INTERFACE") continue;
    if (rootNames.has(name)) continue;
    const hits = t.fields.filter((f) => SENS_HIGH.has(norm(f.name)) || SENS_TOKEN.has(norm(f.name)));
    if (!hits.length) continue;
    const hi = hits.some((f) => SENS_HIGH.has(norm(f.name)));
    push("APISPEC-GQL-SENSITIVE-FIELD", { operation: name, key: name, ...loc(hits[0]), severity: hi ? "high" : "medium", description: "Type " + name + " exposes " + hits.map((f) => f.name).join(", ") + " to any query that can reach it.", evidence: hits.map((f) => ev(name, f, f.name, (f.type.list ? "[" + f.type.name + "]" : f.type.name) + (f.directives.length ? " @" + f.directives.join(" @") : ""))) });
  }
}

// ---------------------------------------------------------------------------
// Postman checks
// ---------------------------------------------------------------------------
const SECRET_DET = DETECTORS.filter((d) => d.kind === "secret").map((d) => d.id);
const PM_SECRET_NAME = /(token|secret|password|passwd|pwd|api[-_]?key|apikey|access[-_]?key|private[-_]?key|client[-_]?secret|bearer|session|cookie|credential|auth)/i;
const PM_AUTH_KEYS = /^(token|password|accesstoken|refreshtoken|clientsecret|consumersecret|tokensecret|privatekey|secretkey|sessiontoken|accesskey|secret|jwtsecret)$/i;
const PM_HEADERS = /^(authorization|proxy-authorization|cookie|x-api-key|api-key|apikey|x-auth-token|x-access-token|x-amz-security-token|x-api-token|private-token|x-functions-key)$/i;
const isTemplate = (v) => /^\s*\{\{[^}]+\}\}\s*$/.test(v);
const literalPart = (v) => String(v).replace(/\{\{[^}]+\}\}/g, "").trim();

function pmSecretCheck(value, nameHint, forceName) {
  const v = String(value == null ? "" : value);
  if (!v.trim() || isTemplate(v)) return null;
  const lit = literalPart(v);
  if (!lit || /^(bearer|basic|token|digest|apikey)$/i.test(lit)) return null;
  const det = dlpScan(v, { detectors: SECRET_DET }).findings[0];
  if (det) return { masked: det.masked, detector: det.label, severity: det.severity === "critical" ? "critical" : "high", confirmed: true };
  if (forceName || PM_SECRET_NAME.test(nameHint || "")) return { masked: maskValue(v), detector: "credential field", severity: "high", confirmed: false };
  return null;
}

function authEntries(auth) {
  if (!isObj(auth) || !auth.type || auth.type === "noauth" || auth.type === "inherit") return [];
  const body = auth[auth.type];
  const out = [];
  if (Array.isArray(body)) body.forEach((kv, i) => { if (isObj(kv)) out.push({ key: String(kv.key || ""), value: kv.value, sub: "/" + pe(auth.type) + "/" + i + "/value" }); });
  else if (isObj(body)) for (const k of Object.keys(body)) out.push({ key: k, value: body[k], sub: "/" + pe(auth.type) + "/" + pe(k) });
  return out.filter((e) => typeof e.value === "string" || typeof e.value === "number");
}

function checkPostman(doc, lines, out, inventory) {
  const file = doc.name;
  const c = doc.spec;
  const info = c.info || {};
  const asset = { type: "ASSET", name: String(info.name || file).slice(0, 200) + (info.version ? " " + (isObj(info.version) ? [info.version.major, info.version.minor, info.version.patch].join(".") : info.version) : ""), data: { file, format: doc.format } };
  const L = (ptr) => lineOf(lines, ptr);
  const vars = {};
  (Array.isArray(c.variable) ? c.variable : []).forEach((v) => { if (isObj(v) && v.key != null) vars[v.key] = v.value; });
  const subst = (s) => String(s || "").replace(/\{\{([^}]+)\}\}/g, (m0, k) => (typeof vars[k] === "string" ? vars[k] : m0));
  const secretGroups = [];
  const collEv = [];
  (Array.isArray(c.variable) ? c.variable : []).forEach((v, i) => {
    if (!isObj(v)) return;
    const hit = pmSecretCheck(v.value, v.key, v.type === "secret");
    if (hit) collEv.push({ file, operation: "", pointer: "/variable/" + i + "/value", line: L("/variable/" + i + "/value"), field: "variable " + v.key, detail: hit.masked + " (" + hit.detector + ")", _h: hit });
  });
  for (const e of authEntries(c.auth)) {
    if (!(PM_AUTH_KEYS.test(e.key) || (c.auth.type === "apikey" && e.key === "value"))) continue;
    const hit = pmSecretCheck(e.value, e.key, true);
    if (hit) collEv.push({ file, operation: "", pointer: "/auth" + e.sub, line: L("/auth" + e.sub), field: "collection auth " + c.auth.type + "." + e.key, detail: hit.masked + " (" + hit.detector + ")", _h: hit });
  }
  if (collEv.length) secretGroups.push({ operation: "", where: "collection variables and auth", evs: collEv });
  const httpByHost = new Map();
  const walkItems = (items, base, inheritedAuth, folder) => {
    (Array.isArray(items) ? items : []).forEach((it, i) => {
      if (!isObj(it)) return;
      const ptr = base + "/" + i;
      const auth = isObj(it.auth) && it.auth.type !== "inherit" ? { a: it.auth, ptr: ptr + "/auth" } : inheritedAuth;
      if (Array.isArray(it.item)) {
        const evs = [];
        for (const e of authEntries(it.auth)) {
          if (!(PM_AUTH_KEYS.test(e.key) || (it.auth.type === "apikey" && e.key === "value"))) continue;
          const hit = pmSecretCheck(e.value, e.key, true);
          if (hit) evs.push({ file, operation: "", pointer: ptr + "/auth" + e.sub, line: L(ptr + "/auth" + e.sub), field: "folder auth " + it.auth.type + "." + e.key, detail: hit.masked + " (" + hit.detector + ")", _h: hit });
        }
        if (evs.length) secretGroups.push({ operation: "folder " + (it.name || i), evs });
        walkItems(it.item, ptr + "/item", auth, (folder ? folder + " / " : "") + (it.name || ""));
        return;
      }
      const reqRaw = it.request;
      if (reqRaw == null) return;
      const req = typeof reqRaw === "string" ? { url: reqRaw, method: "GET" } : reqRaw;
      const rptr = ptr + "/request";
      const method = String(req.method || "GET").toUpperCase();
      const urlRaw = typeof req.url === "string" ? req.url : isObj(req.url) ? String(req.url.raw || ((req.url.protocol ? req.url.protocol + "://" : "") + (Array.isArray(req.url.host) ? req.url.host.join(".") : req.url.host || "") + "/" + (Array.isArray(req.url.path) ? req.url.path.join("/") : req.url.path || ""))) : "";
      const opName = method + " " + urlRaw;
      const evs = [];
      const ownAuth = isObj(req.auth) && req.auth.type !== "inherit" ? { a: req.auth, ptr: rptr + "/auth" } : auth;
      if (isObj(req.auth)) for (const e of authEntries(req.auth)) {
        if (!(PM_AUTH_KEYS.test(e.key) || (req.auth.type === "apikey" && e.key === "value"))) continue;
        const hit = pmSecretCheck(e.value, e.key, true);
        if (hit) evs.push({ file, operation: opName, pointer: rptr + "/auth" + e.sub, line: L(rptr + "/auth" + e.sub), field: "auth " + req.auth.type + "." + e.key, detail: hit.masked + " (" + hit.detector + ")", _h: hit });
      }
      let authHeader = "";
      (Array.isArray(req.header) ? req.header : []).forEach((h, hi) => {
        if (!isObj(h)) return;
        const k = String(h.key || "");
        if (/^authorization$/i.test(k) && !h.disabled) authHeader = (literalPart(String(h.value || "")).split(/\s+/)[0] || "header") + " header";
        if (!PM_HEADERS.test(k) && !PM_SECRET_NAME.test(k)) return;
        const hit = pmSecretCheck(h.value, k, PM_HEADERS.test(k));
        if (hit) evs.push({ file, operation: opName, pointer: rptr + "/header/" + hi + "/value", line: L(rptr + "/header/" + hi + "/value"), field: "header " + k + (h.disabled ? " (disabled)" : ""), detail: hit.masked + " (" + hit.detector + ")", _h: hit });
      });
      if (isObj(req.url) && Array.isArray(req.url.query)) req.url.query.forEach((qp, qi) => {
        if (!isObj(qp) || !PM_SECRET_NAME.test(String(qp.key || ""))) return;
        const hit = pmSecretCheck(qp.value, qp.key, true);
        if (hit) evs.push({ file, operation: opName, pointer: rptr + "/url/query/" + qi + "/value", line: L(rptr + "/url/query/" + qi + "/value"), field: "query " + qp.key, detail: hit.masked + " (" + hit.detector + ")", _h: hit });
      });
      if (evs.length) secretGroups.push({ operation: opName, evs });
      const resolved = subst(urlRaw);
      const host = serverHost(resolved);
      if (/^http:\/\//i.test(resolved) && host && !isLocalHost(host)) {
        if (!httpByHost.has(host)) httpByHost.set(host, []);
        httpByHost.get(host).push({ file, operation: opName, pointer: rptr + "/url", line: L(rptr + "/url"), field: it.name || "", detail: resolved });
      }
      inventory.push({ file, method, path: urlRaw, operation: opName, operationId: String(it.name || ""), auth: ownAuth ? ownAuth.a.type : authHeader || "none", deprecated: false, url: /^https?:\/\//i.test(resolved) ? resolved : "", pointer: rptr, line: L(rptr), folder: folder || "" });
    });
  };
  walkItems(c.item, "/item", isObj(c.auth) ? { a: c.auth, ptr: "/auth" } : null, "");
  for (const g of secretGroups) {
    const sev = g.evs.some((e) => e._h.severity === "critical") ? "critical" : "high";
    const conf = g.evs.some((e) => e._h.confirmed) ? "confirmed" : "likely";
    const evs = g.evs.map(({ _h, ...e }) => e);
    out.push(mkFinding("APISPEC-PM-SECRET", { file, assets: [asset], operation: g.operation, pointer: evs[0].pointer, line: evs[0].line, severity: sev, confidence: conf, description: (g.operation || g.where) + " stores " + evs.length + " credential value(s) in the collection file: " + evs.map((e) => e.field).join(", ") + ". Anyone the collection is shared or exported to can use them. Values are masked here.", evidence: evs }));
  }
  for (const host of [...httpByHost.keys()].sort()) {
    const evs = httpByHost.get(host);
    out.push(mkFinding("APISPEC-PM-HTTP", { file, assets: [asset], operation: evs[0].operation, url: evs[0].detail, pointer: evs[0].pointer, line: evs[0].line, key: host, description: evs.length + " request(s) call " + host + " over plain HTTP.", evidence: evs }));
  }
}

// ---------------------------------------------------------------------------
// analyze
// ---------------------------------------------------------------------------
/**
 * Analyze API definitions. `dataset`: [{name, text}] | parseInput() result | string.
 * opts overrides DEFAULTS. ctx.progress(i, n, label) is optional.
 */
export function analyze(dataset, opts = {}, ctx) {
  const o = { ...DEFAULTS, ...(opts || {}) };
  o.maxRefDepth = Math.max(1, Math.min(200, Number(o.maxRefDepth) || DEFAULTS.maxRefDepth));
  const skipped = [];
  const rx = {
    admin: safeRegex("^(?:" + o.adminPathPattern + ")(?:[-_.].*)?$", "^(?:" + DEFAULTS.adminPathPattern + ")(?:[-_.].*)?$", "i", skipped, "admin-path-pattern"),
    nonProd: safeRegex("^(?:" + o.nonProdHostPattern + ")\\d*$", "^(?:" + DEFAULTS.nonProdHostPattern + ")\\d*$", "i", skipped, "nonprod-host-pattern"),
    objectId: safeRegex("^(?:" + o.objectIdPattern + ")$", "^(?:" + DEFAULTS.objectIdPattern + ")$", "", skipped, "object-id-pattern"),
  };
  const files = normFiles(dataset);
  const all = [];
  const inventory = [];
  const fileRows = [];
  const totals = { ops: 0 };
  const n = files.length;
  for (let fi = 0; fi < n; fi++) {
    const f = files[fi];
    ctx?.progress?.(fi, n, f.name);
    const doc = parseFile(f.name, f.text);
    const row = { name: doc.name, format: doc.format, label: FORMAT_LABEL[doc.format] || doc.format, confidence: doc.confidence, endpoints: 0, findings: 0, title: "", version: "", note: doc.error || doc.reason || "" };
    fileRows.push(row);
    if (doc.error) { skipped.push({ check: "parse:" + doc.name, reason: doc.error }); continue; }
    if (doc.format === "empty") { skipped.push({ check: "parse:" + doc.name, reason: "empty file" }); continue; }
    if (doc.format === "unknown") { skipped.push({ check: "parse:" + doc.name, reason: "not recognised as an API definition (" + (doc.reason || "") + ")" }); continue; }
    const lines = doc.syntax === "json" ? jsonLineMap(f.text) : doc.syntax === "yaml" ? yamlLineMap(f.text) : new Map();
    const before = all.length, invBefore = inventory.length;
    if (doc.format.startsWith("openapi") || doc.format === "swagger-2.0") {
      const M = buildOas(doc, doc.name, o, skipped, totals);
      row.title = M.title; row.version = M.version;
      checkOas(M, o, rx, lines, all, skipped);
      for (const op of M.ops) inventory.push({ file: doc.name, method: op.method, path: op.path, operation: op.operation, operationId: op.operationId, auth: authLabel(op.security, M.schemes), deprecated: op.deprecated, url: op.url, pointer: op.ptr, line: lineOf(lines, op.ptr) });
      if (!M.ops.length) skipped.push({ check: "operations:" + doc.name, reason: "no operations under paths; only document-level checks ran" });
    } else if (doc.format.startsWith("graphql")) {
      if (doc.format === "graphql-introspection") doc.gql = introspectionToModel(doc.spec);
      checkGraphql(doc, lines, all, skipped, inventory);
    } else if (doc.format.startsWith("postman")) {
      row.title = String((doc.spec.info || {}).name || "");
      checkPostman(doc, lines, all, inventory);
    }
    row.findings = all.length - before;
    row.endpoints = inventory.length - invBefore;
  }
  ctx?.progress?.(n, n, "done");

  // dedupe ids, sort deterministically, filter by severity
  const seen = new Map();
  for (const f of all) { const k = f.id; seen.set(k, (seen.get(k) || 0) + 1); if (seen.get(k) > 1) f.id = k + "#" + seen.get(k); }
  all.sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || cmp(a.ruleId, b.ruleId) || cmp(a.file, b.file) || cmp(a.operation, b.operation) || cmp(a.pointer, b.pointer) || cmp(a.id, b.id));
  const min = SEV_RANK[o.minSeverity] != null ? SEV_RANK[o.minSeverity] : 4;
  const findings = all.filter((f) => SEV_RANK[f.severity] <= min);

  const perOp = new Map();
  for (const f of findings) if (f.operation) { const k = f.file + "\u0000" + f.operation; perOp.set(k, (perOp.get(k) || 0) + 1); }
  const endpoints = inventory.map((e) => ({ ...e, findings: perOp.get(e.file + "\u0000" + e.operation) || 0 }))
    .sort((a, b) => cmp(a.file, b.file) || cmp(a.path, b.path) || cmp(a.method, b.method));
  const byOwasp = Object.fromEntries(Object.keys(OWASP_API_2023).map((k) => [k + ":2023", 0]));
  for (const f of findings) byOwasp[f.owasp]++;
  const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const f of findings) bySeverity[f.severity]++;
  const ruleHits = RULES.map((r) => ({ id: r.id, title: r.title, owasp: r.owasp + ":2023", severity: r.severity, hits: findings.filter((f) => f.ruleId === r.id).length }));
  skipped.sort((a, b) => cmp(a.check, b.check) || cmp(a.reason, b.reason));
  const summary = {
    files: n, parsed: fileRows.filter((r) => !r.note || r.endpoints).length,
    endpoints: endpoints.length, unauthenticated: endpoints.filter((e) => e.auth === "none").length,
    findings: findings.length, filteredOut: all.length - findings.length, bySeverity, byOwasp,
  };
  return {
    summary, findings,
    tables: { files: fileRows, endpoints, rules: ruleHits, owasp: Object.keys(OWASP_API_2023).map((k) => ({ id: k + ":2023", name: OWASP_API_2023[k], findings: byOwasp[k + ":2023"] })) },
    skipped,
    meta: { tool: TOOL_ID, version: VERSION, rows: endpoints.length, files: n, options: o },
  };
}

// ---------------------------------------------------------------------------
// exports
// ---------------------------------------------------------------------------
const csvQ = (v) => { const s = String(v == null ? "" : v); return /[",\n\r]|^[=+\-@\t\r]/.test(s) ? '"' + (/^[=+\-@\t\r]/.test(s) ? "'" : "") + s.replace(/"/g, '""') + '"' : s; };
export const FINDING_COLS = ["severity", "confidence", "ruleId", "owasp", "title", "file", "operation", "pointer", "line", "controls", "description", "recommendation", "evidenceCount"];

/** Findings as CSV with fixed columns. */
export function findingsToCsv(findings) {
  const body = (findings || []).map((f) => [f.severity, f.confidence, f.ruleId, f.owasp, f.title, f.file, f.operation, f.pointer, f.line,
    (f.controls || []).map((c) => c.framework + " " + c.id).join("; "), f.description, f.recommendation, f.evidenceCount != null ? f.evidenceCount : (f.evidence || []).length].map(csvQ).join(","));
  return [FINDING_COLS.join(","), ...body].join("\n") + "\n";
}

export const INVENTORY_COLS = ["file", "method", "path", "operationId", "auth", "deprecated", "findings", "url", "pointer", "line"];
/** Endpoint inventory as CSV. */
export function inventoryToCsv(endpoints) {
  return [INVENTORY_COLS.join(","), ...(endpoints || []).map((e) => INVENTORY_COLS.map((k) => csvQ(e[k])).join(","))].join("\n") + "\n";
}

const SARIF_LEVEL = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };
const SEC_SEVERITY = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", info: "1.0" };

/** SARIF 2.1.0 log: one rule per check, locations are the uploaded file + line, JSON pointer as logical location. */
export function toSarif(result) {
  const findings = (result && result.findings) || [];
  const rules = RULES.map((r) => ({
    id: r.id, name: r.id.replace(/[^A-Za-z0-9]/g, ""),
    shortDescription: { text: r.title }, fullDescription: { text: r.title + " (OWASP " + r.owasp + ":2023 " + OWASP_API_2023[r.owasp] + ")" },
    help: { text: r.recommendation + "\nReferences: " + controlsFor(r).map((c) => c.framework + " " + c.id).join("; ") },
    defaultConfiguration: { level: SARIF_LEVEL[r.severity] },
    properties: { tags: ["security", "api", "owasp-" + r.owasp.toLowerCase()].concat(r.cwe ? ["external/cwe/" + r.cwe.toLowerCase()] : []), "security-severity": SEC_SEVERITY[r.severity], precision: r.confidence === "confirmed" ? "high" : r.confidence === "likely" ? "medium" : "low" },
  }));
  const index = new Map(rules.map((r, i) => [r.id, i]));
  const results = findings.map((f) => ({
    ruleId: f.ruleId, ruleIndex: index.has(f.ruleId) ? index.get(f.ruleId) : -1, level: SARIF_LEVEL[f.severity] || "warning",
    message: { text: f.description },
    locations: [{
      physicalLocation: { artifactLocation: { uri: String(f.file).replace(/\\/g, "/").replace(/^\/+/, "").split("/").map(encodeURIComponent).join("/") }, region: { startLine: Math.max(1, f.line || 1) } },
      logicalLocations: [{ fullyQualifiedName: f.pointer || "#", kind: "member" }].concat(f.operation ? [{ name: f.operation, kind: "function" }] : []),
    }],
    partialFingerprints: { "apispec/v1": f.id },
    properties: { severity: f.severity, confidence: f.confidence, owasp: f.owasp, jsonPointer: f.pointer, operation: f.operation, evidenceCount: f.evidenceCount },
  }));
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json", version: "2.1.0",
    runs: [{ tool: { driver: { name: "Darknode API Security Review", semanticVersion: VERSION, version: VERSION, informationUri: "https://darknode.ai", rules } }, columnKind: "utf16CodeUnits", results }],
  };
}

/** Plain-text summary. */
export function toTxt(result) {
  const r = result || { summary: {}, findings: [], skipped: [], tables: {} };
  const s = r.summary || {};
  const out = ["API Security Review summary (" + TOOL_ID + " " + VERSION + ")", "",
    "Files: " + (s.files || 0) + ", endpoints: " + (s.endpoints || 0) + " (" + (s.unauthenticated || 0) + " with no documented auth)",
    "Findings: " + (s.findings || 0) + (s.filteredOut ? " (" + s.filteredOut + " below the severity threshold hidden)" : ""),
    "By severity: " + SEVERITIES.map((k) => k + " " + ((s.bySeverity || {})[k] || 0)).join(", "),
    "OWASP API Security Top 10 2023: " + Object.entries(s.byOwasp || {}).map(([k, v]) => k + " " + v).join(", "), ""];
  for (const f of r.findings || []) out.push("[" + f.severity.toUpperCase() + "] " + f.ruleId + " " + f.title + " (" + f.owasp + ", " + f.confidence + ")", "  " + f.file + ":" + f.line + "  " + (f.operation || "-") + "  " + (f.pointer || ""), "  " + f.description, "  Fix: " + f.recommendation, "");
  if ((r.skipped || []).length) { out.push("Not evaluated:"); for (const k of r.skipped) out.push("  - " + k.check + ": " + k.reason); }
  return out.join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// synthetic example (fictional company; test.darknode.ai hosts)
// ---------------------------------------------------------------------------
const EXAMPLE_OPENAPI = `openapi: 3.0.3
info:
  title: Payments API
  version: 2.4.0
  description: Synthetic example for Darknode API Security Review. Not a real API.
servers:
  - url: https://api.test.darknode.ai/v2
  - url: http://staging.test.darknode.ai/v1
security:
  - bearerAuth: []
paths:
  /auth/token:
    post:
      operationId: issueToken
      security: []
      requestBody:
        required: true
        content:
          application/x-www-form-urlencoded:
            schema:
              type: object
              properties:
                username: { type: string, maxLength: 128 }
                password: { type: string, maxLength: 128 }
      responses:
        '200':
          description: Token issued
          content:
            application/json:
              schema:
                type: object
                properties:
                  access_token: { type: string }
                  expires_in: { type: integer, maximum: 3600 }
  /accounts:
    get:
      operationId: listAccounts
      parameters:
        - name: page
          in: query
          schema: { type: integer }
      responses:
        '200':
          description: Accounts
          content:
            application/json:
              schema:
                type: object
                properties:
                  data:
                    type: array
                    items:
                      $ref: '#/components/schemas/Account'
    post:
      operationId: createAccount
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/AccountInput'
      responses:
        '201':
          description: Created
          headers:
            Access-Control-Allow-Origin:
              schema:
                type: string
                example: '*'
  /accounts/{accountId}:
    parameters:
      - name: accountId
        in: path
        required: true
        schema: { type: string, format: uuid }
    get:
      operationId: getAccount
      responses:
        '200':
          description: Account
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Account'
        '500':
          description: Server error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    delete:
      operationId: closeAccount
      security:
        - oauth: []
      responses:
        '204':
          description: Closed
  /payments/transfer:
    post:
      operationId: createTransfer
      security:
        - oauth: [payments:write]
      requestBody:
        content:
          application/json:
            schema:
              type: object
              required: [from, to, amount]
              properties:
                from: { type: string, maxLength: 36 }
                to: { type: string, maxLength: 36 }
                amount: { type: integer, minimum: 1 }
                memo: { type: string }
                callbackUrl: { type: string, format: uri }
      responses:
        '202':
          description: Accepted
  /documents:
    post:
      operationId: uploadDocument
      requestBody:
        content:
          multipart/form-data:
            schema:
              type: object
              properties:
                file: { type: string, format: binary }
      responses:
        '201':
          description: Stored
  /admin/users/{userId}/role:
    put:
      operationId: setUserRole
      parameters:
        - name: userId
          in: path
          required: true
          schema: { type: string, maxLength: 36 }
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                role: { type: string, enum: [viewer, operator, admin] }
      responses:
        '200':
          description: Updated
  /v1/reports/export:
    get:
      operationId: exportReportLegacy
      deprecated: true
      security:
        - apiKeyQuery: []
      responses:
        '200':
          description: CSV export
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
    oauth:
      type: oauth2
      flows:
        implicit:
          authorizationUrl: https://login.test.darknode.ai/authorize
          scopes:
            payments:write: Move money
        authorizationCode:
          authorizationUrl: https://login.test.darknode.ai/authorize
          tokenUrl: https://login.test.darknode.ai/token
          scopes:
            payments:write: Move money
    apiKeyQuery:
      type: apiKey
      in: query
      name: api_key
  schemas:
    Account:
      type: object
      properties:
        id: { type: string, format: uuid }
        holderName: { type: string }
        balance: { type: integer }
        cardNumber: { type: string }
        owner:
          $ref: '#/components/schemas/Account'
    AccountInput:
      type: object
      additionalProperties: true
      properties:
        holderName: { type: string }
        balance: { type: integer }
        tags:
          type: array
          items: { type: string, maxLength: 32 }
    Error:
      type: object
      properties:
        message: { type: string }
        stackTrace: { type: string }
`;

const EXAMPLE_GRAPHQL = `# Ledger GraphQL schema - synthetic example, not a real API.
directive @auth(requires: Role = USER) on OBJECT | FIELD_DEFINITION

enum Role { USER ADMIN }

type Query {
  ledger(id: ID!): Ledger @auth
  ledgers: [Ledger!]!
  entry(entryId: ID!): Entry
}

type Mutation {
  postEntry(ledgerId: ID!, amount: Int!, memo: String): Entry @auth(requires: ADMIN)
  deleteLedger(id: ID!): Boolean
}

type Ledger {
  id: ID!
  name: String!
  entries(first: Int): [Entry!]!
}

type Entry {
  id: ID!
  amount: Int!
  memo: String
  approverToken: String
}
`;

/** Small SYNTHETIC dataset for the "Load example" button and tests. Offline; no live calls. */
export function exampleDataset(seed = 7) {
  void seed;
  return {
    label: "synthetic example (not real data)",
    files: [
      { name: "payments.openapi.yaml", text: EXAMPLE_OPENAPI },
      { name: "ledger.graphql", text: EXAMPLE_GRAPHQL },
    ],
  };
}

/** Deterministic checks of the engine against the example. */
export function selfTest() {
  const tests = [];
  const ex = exampleDataset();
  const r = analyze(ex.files);
  const has = (id) => r.findings.some((f) => f.ruleId === id);
  tests.push({ name: "example parses as OpenAPI 3.0 and GraphQL SDL", pass: r.tables.files[0].format === "openapi-3.0" && r.tables.files[1].format === "graphql-sdl" });
  for (const id of ["APISPEC-BOLA-CANDIDATE", "APISPEC-MASS-ASSIGNMENT", "APISPEC-SENSITIVE-RESPONSE", "APISPEC-OAUTH-IMPLICIT", "APISPEC-APIKEY-IN-QUERY", "APISPEC-HTTP-SERVER", "APISPEC-NONPROD-SERVER", "APISPEC-GQL-MUTATION-NO-AUTH", "APISPEC-GQL-ID-ARG"]) tests.push({ name: id + " fires on the example", pass: has(id) });
  tests.push({ name: "deterministic", pass: JSON.stringify(analyze(ex.files)) === JSON.stringify(r) });
  tests.push({ name: "empty input yields no findings", pass: analyze([]).findings.length === 0 });
  tests.push({ name: "every finding has controls and a recommendation", pass: r.findings.every((f) => f.controls.length >= 1 && f.recommendation && f.evidenceCount >= 1) });
  return { pass: tests.every((t) => t.pass), tests };
}
