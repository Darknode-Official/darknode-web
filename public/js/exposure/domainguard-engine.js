// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Domain Guard engine (domainguard): domain portfolio guard. Grades the live
// DNS / RDAP / certificate-transparency answers the UI fetched for every owned
// domain: NS health, SOA, MX / null MX, SPF (with nested include counting),
// DMARC, the M3AAWG parked-domain lock-down trio, MTA-STS, TLS-RPT, BIMI,
// DNSSEC, CAA, wildcard DNS, registration expiry and registrar lock, and the
// newest CT certificate. It also parses DNS zone exports (BIND / Cloudflare,
// Route 53 JSON, Azure DNS JSON), finds dangling CNAMEs against a documented
// subdomain-takeover fingerprint table, generates lookalike domains
// deterministically (with a tested RFC 3492 Punycode encoder) and grades the
// registration answers fetched for them, and diffs a run against the previous one.
//
// Pure: no DOM, no network, no clock (time comes in as opts.now). Every input is a
// plain object in the exact shape the services return (dns.google JSON, rdap.org
// domain JSON, crt.sh rows). Network failures stay "error" - never a pass or fail.

import { parseCsv, findColumn } from "../ingest/parse.js";
import { parseDMARC, spfLookupCount, parseMtaSts, certDaysLeft, newestCert, letterGrade } from "../dataprotect/posture-engine.js";

export const TOOL_ID = "domainguard";
export const VERSION = "1.0.0";

/** Column aliases for a domain-portfolio CSV: key -> accepted headers (case-insensitive). */
export const COLUMNS = {
  domain: ["domain", "domain_name", "domainname", "name", "fqdn", "zone", "hostname"],
  sendsMail: ["sends_mail", "sendsmail", "mail", "email", "sends mail"],
  parked: ["parked", "is_parked", "parked_domain"],
  role: ["role", "type", "usage", "purpose"],
};

/** Tunable thresholds; the UI renders these as the settings panel. */
export const DEFAULTS = {
  expiryCriticalDays: 7, // registration expiring within this many days: critical
  expiryWarnDays: 30, // ... within this many days: high
  certWarnDays: 14, // newest CT certificate expiring within this many days: medium
  newlyRegisteredDays: 30, // lookalike created within this many days counts as newly registered
  maxCandidates: 300, // lookalike candidates generated per domain (UI allows up to 2000)
  spfLookupLimit: 10, // RFC 7208 4.6.4
  concurrency: 4, // UI: parallel lanes
  spacingMs: 150, // UI: pause between requests per lane
};

export const LIMITS = { maxCandidates: 2000, maxHosts: 5000, maxDomains: 1000 };

// ---------------------------------------------------------------------------
// Controls (real references only)
// ---------------------------------------------------------------------------
const C = {
  bod1801: { framework: "CISA", id: "BOD 18-01" },
  sp800177: { framework: "NIST SP 800-177 Rev.1", id: "Trustworthy Email (SPF/DKIM/DMARC)" },
  rfc7489: { framework: "RFC", id: "7489 (DMARC)" },
  rfc7208: { framework: "RFC", id: "7208 (SPF)" },
  rfc8461: { framework: "RFC", id: "8461 (MTA-STS)" },
  rfc8460: { framework: "RFC", id: "8460 (TLS-RPT)" },
  rfc8659: { framework: "RFC", id: "8659 (CAA)" },
  rfc7505: { framework: "RFC", id: "7505 (Null MX)" },
  rfc4033: { framework: "RFC", id: "4033 (DNSSEC)" },
  m3parked: { framework: "M3AAWG", id: "Protecting Parked Domains BCP" },
  m3auth: { framework: "M3AAWG", id: "Email Authentication Recommended Best Practices" },
  icannLock: { framework: "ICANN", id: "EPP status codes (clientTransferProhibited)" },
  t1583: { framework: "MITRE", id: "T1583.001" },
  t1584: { framework: "MITRE", id: "T1584.001" },
  t1584dns: { framework: "MITRE", id: "T1584.002" },
  t1566: { framework: "MITRE", id: "T1566" },
  sc20: { framework: "NIST-800-53", id: "SC-20" },
  sc22: { framework: "NIST-800-53", id: "SC-22" },
  sc17: { framework: "NIST-800-53", id: "SC-17" },
  cm8: { framework: "NIST-800-53", id: "CM-8" },
  iso59: { framework: "ISO27001", id: "A.5.9" },
};

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------
const DAY = 86400000;
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const uniq = (a) => [...new Set(a)];
export function normName(s) {
  return String(s == null ? "" : s).trim().toLowerCase().replace(/\.+$/, "");
}
const LABEL_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
export function isDomainName(s) {
  const d = normName(s);
  if (!d || d.length > 253 || d.indexOf(".") < 0) return false;
  return d.split(".").every((l) => LABEL_RE.test(l)) && /[a-z]/.test(d.split(".").pop());
}

// RR type numbers (RFC 1035, 3596, 4034, 8659).
export const RR = { A: 1, NS: 2, CNAME: 5, SOA: 6, MX: 15, TXT: 16, AAAA: 28, DS: 43, RRSIG: 46, DNSKEY: 48, CAA: 257 };

// ---------------------------------------------------------------------------
// Punycode (RFC 3492) and IDNA-style ASCII conversion
// ---------------------------------------------------------------------------
function pcAdapt(delta, numPoints, first) {
  let k = 0;
  delta = first ? Math.floor(delta / 700) : delta >> 1;
  delta += Math.floor(delta / numPoints);
  for (; delta > 455; k += 36) delta = Math.floor(delta / 35); // ((base - tMin) * tMax) / 2 = 455
  return Math.floor(k + (36 * delta) / (delta + 38));
}
const pcDigit = (d) => String.fromCharCode(d + 22 + (d < 26 ? 75 : 0));

/** RFC 3492 Punycode encode of one label (no "xn--" prefix). */
export function punycodeEncode(input) {
  const cps = Array.from(String(input)).map((c) => c.codePointAt(0));
  let n = 128, delta = 0, bias = 72;
  let out = cps.filter((c) => c < 128).map((c) => String.fromCharCode(c)).join("");
  const b = out.length;
  let h = b;
  if (b) out += "-";
  while (h < cps.length) {
    let m = Infinity;
    for (const c of cps) if (c >= n && c < m) m = c;
    delta += (m - n) * (h + 1);
    n = m;
    for (const c of cps) {
      if (c < n) delta++;
      if (c === n) {
        let q = delta;
        for (let k = 36; ; k += 36) {
          const t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
          if (q < t) break;
          out += pcDigit(t + ((q - t) % (36 - t)));
          q = Math.floor((q - t) / (36 - t));
        }
        out += pcDigit(q);
        bias = pcAdapt(delta, h + 1, h === b);
        delta = 0;
        h++;
      }
    }
    delta++;
    n++;
  }
  return out;
}

/** Domain to ASCII: lowercases, NFC-normalises and Punycode-encodes non-ASCII labels. */
export function toAsciiDomain(domain) {
  return normName(domain).normalize("NFC").split(".").map((l) => (/[^\x00-\x7f]/.test(l) ? "xn--" + punycodeEncode(l) : l)).join(".");
}

// ---------------------------------------------------------------------------
// Domain splitting (registrable label + suffix)
// ---------------------------------------------------------------------------
// A short list of common multi-label public suffixes. `test.darknode.ai` is
// treated as a private suffix so the synthetic example stays inside it.
export const MULTI_SUFFIXES = [
  "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "org.nz",
  "co.jp", "co.kr", "co.in", "co.za", "com.br", "com.mx", "com.ar", "com.cn", "com.sg", "com.hk", "com.tr", "com.tw",
  "co.il", "com.my", "com.ph", "com.vn", "com.co", "com.pe", "com.ua", "com.pl", "co.id", "co.th", "test.darknode.ai",
];
const PRIVATE_SUFFIXES = new Set(["test.darknode.ai"]);

/** Split a domain into { prefix, label, suffix }. */
export function splitDomain(domain) {
  const d = normName(domain);
  const suffix = MULTI_SUFFIXES.filter((s) => d.endsWith("." + s)).sort((a, b) => b.length - a.length)[0] || d.split(".").slice(-1)[0];
  const rest = d.slice(0, d.length - suffix.length - 1);
  const parts = rest ? rest.split(".") : [];
  const label = parts.pop() || "";
  return { prefix: parts.join("."), label, suffix };
}

/** Registrable domain (label + public suffix) - what RDAP knows about. */
export function registrableDomain(domain) {
  const { label, suffix } = splitDomain(domain);
  return label ? label + "." + suffix : normName(domain);
}

// ---------------------------------------------------------------------------
// DoH (dns.google / cloudflare-dns.com JSON) helpers
// ---------------------------------------------------------------------------
/** "ok" | "nxdomain" | "servfail" | "refused" | "error" | "missing" for one DoH answer. */
export function dohStatus(j) {
  if (j == null) return "missing";
  if (typeof j !== "object" || j.error) return "error";
  if (j.Status === 0) return "ok";
  if (j.Status === 3) return "nxdomain";
  if (j.Status === 2) return "servfail";
  if (j.Status === 5) return "refused";
  return "error";
}
const isErr = (s) => s === "error" || s === "servfail" || s === "refused" || s === "missing";

/** Answer rdata strings of one type. */
export function rrData(j, type) {
  const t = typeof type === "number" ? type : RR[type];
  return ((j && Array.isArray(j.Answer)) ? j.Answer : []).filter((a) => a && Number(a.type) === t).map((a) => String(a.data == null ? "" : a.data));
}

/** TXT rdata -> strings; joins the character-strings of one record (RFC 7208 3.3). */
export function txtStrings(j) {
  return rrData(j, "TXT").map((d) => {
    const s = d.trim();
    if (!s.startsWith('"')) return s;
    const parts = s.match(/"((?:[^"\\]|\\.)*)"/g) || [];
    return parts.map((p) => p.slice(1, -1).replace(/\\(.)/g, "$1")).join("");
  });
}

/** CAA rdata, both dns.google presentation ("0 issue \"ca\"") and RFC 3597 hex ("\# 19 00 05 ..."). */
export function parseCaaData(data) {
  const s = String(data || "").trim();
  if (s.startsWith("\\#")) {
    const hex = s.split(/\s+/).slice(2).join("");
    const bytes = [];
    for (let i = 0; i + 1 < hex.length; i += 2) bytes.push(parseInt(hex.slice(i, i + 2), 16));
    if (bytes.length < 2) return null;
    const tl = bytes[1];
    const tag = String.fromCharCode(...bytes.slice(2, 2 + tl)).toLowerCase();
    const value = String.fromCharCode(...bytes.slice(2 + tl));
    return { flags: bytes[0], tag, value };
  }
  const m = s.match(/^(\d+)\s+([a-z0-9]+)\s+(.*)$/i);
  if (!m) return null;
  return { flags: Number(m[1]), tag: m[2].toLowerCase(), value: m[3].replace(/^"|"$/g, "") };
}

/** MX rdata -> [{ pref, host }] ; null MX is { pref: 0, host: "" }. */
export function parseMx(j) {
  return rrData(j, "MX").map((d) => {
    const m = d.trim().match(/^(\d+)\s+(\S+)$/);
    return m ? { pref: Number(m[1]), host: normName(m[2]) } : null;
  }).filter(Boolean).sort((a, b) => a.pref - b.pref || cmp(a.host, b.host));
}

/** SOA rdata -> { mname, rname, email, serial, refresh, retry, expire, minimum }. */
export function parseSoa(j) {
  const d = rrData(j, "SOA")[0] || (j && Array.isArray(j.Authority) ? (j.Authority.find((a) => Number(a.type) === 6) || {}).data : null);
  if (!d) return null;
  const p = String(d).trim().split(/\s+/);
  if (p.length < 7) return null;
  const rname = normName(p[1]);
  const at = rname.replace(/\\\./g, "\u0000").replace(".", "@").replace(/\u0000/g, ".");
  return { mname: normName(p[0]), rname, email: at, serial: Number(p[2]), refresh: Number(p[3]), retry: Number(p[4]), expire: Number(p[5]), minimum: Number(p[6]) };
}

// Name-server provider grouping (best known operators; otherwise the NS host's registrable domain).
const NS_PROVIDERS = [
  [/\.awsdns-\d+\.(com|net|org|co\.uk)$/, "AWS Route 53"], [/\.ns\.cloudflare\.com$/, "Cloudflare"],
  [/\.azure-dns\.(com|net|org|info)$/, "Azure DNS"], [/\.googledomains\.com$|\.google\.com$/, "Google"],
  [/\.domaincontrol\.com$/, "GoDaddy"], [/\.nsone\.net$/, "NS1"], [/\.ultradns\.(com|net|org|biz)$/, "UltraDNS"],
  [/\.dynect\.net$/, "Dyn"], [/\.akam\.net$|\.akamaiedge\.net$/, "Akamai"], [/\.registrar-servers\.com$/, "Namecheap"],
];
export function nsProvider(host) {
  const h = normName(host);
  for (const [re, name] of NS_PROVIDERS) if (re.test(h)) return name;
  const s = splitDomain(h);
  if (PRIVATE_SUFFIXES.has(s.suffix)) return s.suffix;
  return s.label ? s.label + "." + s.suffix : h;
}

// ---------------------------------------------------------------------------
// SPF / DMARC / MTA-STS / TLS-RPT / BIMI parsers
// ---------------------------------------------------------------------------
/** Full SPF view of a TXT set: every v=spf1 record, qualifier on all, includes, redirect. */
export function parseSpfRecords(txts) {
  const records = (txts || []).map((t) => String(t).trim()).filter((t) => /^v=spf1(\s|$)/i.test(t));
  if (!records.length) return { present: false, multiple: false, records };
  const rec = records[0];
  const toks = rec.split(/\s+/).slice(1);
  let all = null;
  const includes = [];
  let redirect = null;
  for (const raw of toks) {
    const q = /^[-~?+]/.test(raw) ? raw[0] : "+";
    const t = raw.replace(/^[-~?+]/, "").toLowerCase();
    if (t === "all") all = q;
    else if (t.startsWith("include:")) includes.push(t.slice(8));
    else if (t.startsWith("redirect=")) redirect = t.slice(9);
  }
  return { present: true, multiple: records.length > 1, records, record: rec, all, includes, redirect, directLookups: spfLookupCount(rec) };
}

/** Domains the UI must resolve (TXT) to count nested SPF lookups; macros are skipped. */
export function spfIncludeTargets(record) {
  const p = parseSpfRecords([record]);
  if (!p.present) return [];
  return uniq([...p.includes, ...(p.redirect ? [p.redirect] : [])].filter((d) => d && d.indexOf("%{") < 0).map(normName)).sort();
}

/**
 * Count DNS-querying SPF terms across nested include/redirect (RFC 7208 4.6.4, limit 10).
 * lookup(domain) -> { status: "ok"|"none"|"missing", txts? } where "none" means the
 * target has no SPF record (RFC 7208 5.2: include of a domain without SPF is permerror).
 */
export function spfLookupTree(record, lookup, { maxDepth = 10 } = {}) {
  const tree = [], missing = [], noSpf = [], loops = [];
  let count = 0;
  const seen = new Set();
  const walk = (rec, domain, depth) => {
    const p = parseSpfRecords([rec]);
    if (!p.present) return;
    count += p.directLookups;
    tree.push({ domain, depth, lookups: p.directLookups, record: rec });
    if (depth >= maxDepth) return;
    for (const t of [...p.includes, ...(p.redirect ? [p.redirect] : [])]) {
      const d = normName(t);
      if (!d || d.indexOf("%{") >= 0) continue;
      if (seen.has(d)) { loops.push(d); continue; }
      seen.add(d);
      const r = lookup ? lookup(d) : { status: "missing" };
      if (!r || r.status === "missing") { missing.push(d); continue; }
      const sub = parseSpfRecords(r.txts || []);
      if (r.status === "none" || !sub.present) { noSpf.push(d); continue; }
      walk(sub.record, d, depth + 1);
    }
  };
  walk(record, "(root)", 0);
  return { count, tree, missing: missing.sort(), noSpf: noSpf.sort(), loops: uniq(loops).sort(), complete: missing.length === 0 };
}

/** Strict DMARC view: parseDMARC plus multiple-record and syntax checks (RFC 7489 6.3, 6.6.3). */
export function parseDmarcStrict(txts) {
  const records = (txts || []).map((t) => String(t).trim()).filter((t) => /^v\s*=\s*dmarc1/i.test(t));
  if (!records.length) return { present: false, multiple: false, errors: [], records };
  const base = parseDMARC([records[0]]);
  const errors = [];
  const tags = records[0].split(";").map((x) => x.trim()).filter(Boolean);
  const kv = tags.map((t) => { const i = t.indexOf("="); return i < 0 ? [t.toLowerCase(), null] : [t.slice(0, i).trim().toLowerCase(), t.slice(i + 1).trim()]; });
  if (!kv.length || kv[0][0] !== "v" || !/^dmarc1$/i.test(kv[0][1] || "")) errors.push("v=DMARC1 must be the first tag");
  const map = Object.fromEntries(kv);
  if (!("p" in map)) errors.push("required p= tag missing");
  else if (!/^(none|quarantine|reject)$/i.test(map.p || "")) errors.push("p= must be none, quarantine or reject (got " + map.p + ")");
  if ("sp" in map && !/^(none|quarantine|reject)$/i.test(map.sp || "")) errors.push("sp= must be none, quarantine or reject");
  if ("pct" in map && !(/^\d+$/.test(map.pct || "") && Number(map.pct) <= 100)) errors.push("pct= must be an integer 0-100");
  for (const k of ["rua", "ruf"]) if (map[k]) for (const u of map[k].split(",")) if (!/^mailto:/i.test(u.trim())) errors.push(k + "= URI must be mailto: (" + u.trim() + ")");
  for (const [k, v] of kv) if (v == null) errors.push("malformed tag '" + k + "'");
  return { ...base, present: true, multiple: records.length > 1, records, errors, pTagPresent: "p" in map };
}

/** MTA-STS policy mx: patterns and whether they cover the domain's MX hosts. */
export function mtaStsCoverage(policyBody, mxHosts) {
  const pats = String(policyBody || "").split(/\r?\n/).map((l) => l.match(/^\s*mx\s*:\s*(\S+)/i)).filter(Boolean).map((m) => normName(m[1]));
  const covers = (h) => pats.some((p) => (p.startsWith("*.") ? h.endsWith(p.slice(1)) && h.slice(0, h.length - p.length + 1).indexOf(".") < 0 : h === p));
  const uncovered = (mxHosts || []).filter((h) => h && !covers(h));
  return { patterns: pats, uncovered };
}

// ---------------------------------------------------------------------------
// RDAP (rdap.org domain JSON)
// ---------------------------------------------------------------------------
const eppNorm = (s) => String(s || "").toLowerCase().replace(/[^a-z]/g, "");
function vcardFn(ent) {
  const v = ent && Array.isArray(ent.vcardArray) ? ent.vcardArray[1] : null;
  if (!Array.isArray(v)) return null;
  const fn = v.find((x) => Array.isArray(x) && x[0] === "fn");
  return fn ? String(fn[3]) : null;
}

/** Parse rdap.org domain JSON: expiry, creation, registrar, EPP status and lock flags. */
export function parseRdap(j, nowMs) {
  if (!j || typeof j !== "object" || j.error) return { ok: false, error: (j && j.error) || "no RDAP data" };
  if (j.errorCode) return { ok: false, error: "RDAP " + j.errorCode + (j.title ? " " + j.title : "") };
  const ev = (a) => ((j.events || []).find((e) => String(e.eventAction).toLowerCase() === a) || {}).eventDate || null;
  const expires = ev("expiration"), created = ev("registration"), updated = ev("last changed");
  const ents = [];
  const walk = (arr) => { for (const e of arr || []) { ents.push(e); walk(e.entities); } };
  walk(j.entities);
  const reg = ents.find((e) => (e.roles || []).includes("registrar"));
  const statuses = (j.status || []).map(String).sort();
  const s = new Set(statuses.map(eppNorm));
  const days = (iso) => (iso && nowMs != null && !isNaN(Date.parse(iso)) ? Math.floor((Date.parse(iso) - nowMs) / DAY) : null);
  return {
    ok: true, ldhName: normName(j.ldhName || ""), registrar: reg ? vcardFn(reg) || reg.handle || null : null,
    registrarIanaId: reg && Array.isArray(reg.publicIds) ? ((reg.publicIds.find((p) => /iana/i.test(p.type)) || {}).identifier || null) : null,
    expires, created, updated, daysLeft: days(expires), ageDays: created && nowMs != null ? -days(created) : null,
    statuses,
    transferLock: s.has("clienttransferprohibited") || s.has("servertransferprohibited"),
    deleteLock: s.has("clientdeleteprohibited") || s.has("serverdeleteprohibited"),
    updateLock: s.has("clientupdateprohibited") || s.has("serverupdateprohibited"),
    redemption: s.has("redemptionperiod") || s.has("pendingdelete"),
    nameservers: (j.nameservers || []).map((n) => normName(n.ldhName)).filter(Boolean).sort(),
  };
}

// ---------------------------------------------------------------------------
// Zone exports: BIND / Cloudflare, Route 53 JSON, Azure DNS JSON, domain lists
// ---------------------------------------------------------------------------
const ZONE_TYPES = new Set(["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA", "SRV", "PTR", "DS", "DNSKEY", "ALIAS", "SPF", "HTTPS", "SVCB", "NAPTR", "TLSA", "SSHFP", "LOC", "URI"]);
const NAME_RDATA = new Set(["CNAME", "NS", "PTR", "ALIAS"]);
function qualify(name, origin) {
  const n = String(name || "").trim();
  if (n === "@" || n === "") return normName(origin);
  if (n.endsWith(".")) return normName(n);
  return origin ? normName(n + "." + origin) : normName(n);
}
function bindLogicalLines(text) {
  const out = [];
  let cur = "", depth = 0, inQ = false, lead = null;
  const s = String(text || "").replace(/\r\n?/g, "\n");
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (lead === null && ch !== "\n") lead = ch === " " || ch === "\t";
    if (inQ) { cur += ch; if (ch === "\\" && i + 1 < s.length) { cur += s[++i]; } else if (ch === '"') inQ = false; continue; }
    if (ch === '"') { inQ = true; cur += ch; continue; }
    if (ch === ";") { while (i + 1 < s.length && s[i + 1] !== "\n") i++; continue; }
    if (ch === "(") { depth++; cur += " "; continue; }
    if (ch === ")") { depth = Math.max(0, depth - 1); cur += " "; continue; }
    if (ch === "\n") {
      if (depth > 0) { cur += " "; continue; }
      if (cur.trim()) out.push({ text: cur, lead: !!lead });
      cur = ""; lead = null; continue;
    }
    cur += ch;
  }
  if (cur.trim()) out.push({ text: cur, lead: !!lead });
  return out;
}
function bindTokens(line) {
  const out = [];
  const re = /"((?:[^"\\]|\\.)*)"|(\S+)/g;
  let m;
  while ((m = re.exec(line))) out.push(m[1] != null ? { q: true, v: m[1].replace(/\\(.)/g, "$1") } : { q: false, v: m[2] });
  return out;
}
const TTL_RE = /^\d+[smhdw]?(\d+[smhdw])*$/i;

/** Parse a BIND master file (also Cloudflare's export): $ORIGIN, $TTL, relative names, ( ) continuation. */
export function parseBindZone(text, defaultOrigin = "") {
  const errors = [];
  let origin = normName(defaultOrigin);
  const cf = String(text || "").match(/^;;\s*Domain:\s*(\S+)/m);
  if (!origin && cf) origin = normName(cf[1]);
  let ttl = null, last = origin;
  const records = [];
  for (const { text: line, lead } of bindLogicalLines(text)) {
    const toks = bindTokens(line.trim());
    if (!toks.length) continue;
    const head = toks[0].v.toUpperCase();
    if (head === "$ORIGIN") { origin = normName(toks[1] ? toks[1].v : origin); last = origin; continue; }
    if (head === "$TTL") { ttl = toks[1] ? toks[1].v : ttl; continue; }
    if (head.startsWith("$")) { errors.push("unsupported directive " + head); continue; }
    let i = 0, owner;
    if (lead) owner = last;
    else { owner = qualify(toks[0].v, origin); i = 1; }
    let rttl = ttl, type = null;
    for (; i < toks.length && i < 4; i++) {
      const v = toks[i].v, u = v.toUpperCase();
      if (!toks[i].q && TTL_RE.test(v)) { rttl = v; continue; }
      if (!toks[i].q && (u === "IN" || u === "CH" || u === "HS" || u === "CS")) continue;
      if (!toks[i].q && ZONE_TYPES.has(u)) { type = u; i++; break; }
      break;
    }
    if (!type) { errors.push("unparsed line: " + line.trim().slice(0, 80)); continue; }
    last = owner;
    const rd = toks.slice(i);
    let value;
    if (type === "TXT" || type === "SPF") value = rd.map((t) => t.v).join("");
    else if (NAME_RDATA.has(type)) value = qualify(rd[0] ? rd[0].v : "", origin);
    else if (type === "MX") value = (rd[0] ? rd[0].v : "") + " " + qualify(rd[1] ? rd[1].v : "", origin);
    else value = rd.map((t) => (t.q ? '"' + t.v + '"' : t.v)).join(" ");
    records.push({ name: owner, type, ttl: rttl == null ? null : String(rttl), value, source: "bind" });
  }
  if (!origin) { const soa = records.find((r) => r.type === "SOA"); if (soa) origin = soa.name; }
  return { origin, records, errors };
}

/** Parse `aws route53 list-resource-record-sets` JSON. Alias targets become type ALIAS. */
export function parseRoute53(json) {
  const j = typeof json === "string" ? JSON.parse(json) : json;
  const sets = (j && j.ResourceRecordSets) || [];
  const records = [];
  for (const s of sets) {
    const name = normName(String(s.Name || "").replace(/\\052/g, "*"));
    const type = String(s.Type || "").toUpperCase();
    if (s.AliasTarget) { records.push({ name, type: "ALIAS", aliasType: type, ttl: null, value: normName(s.AliasTarget.DNSName), source: "route53" }); continue; }
    for (const rr of s.ResourceRecords || []) {
      let v = String(rr.Value || "");
      if (type === "TXT" || type === "SPF") v = (v.match(/"((?:[^"\\]|\\.)*)"/g) || [v]).map((p) => p.replace(/^"|"$/g, "").replace(/\\(.)/g, "$1")).join("");
      else if (NAME_RDATA.has(type)) v = normName(v);
      else if (type === "MX") { const m = v.trim().split(/\s+/); v = m[0] + " " + normName(m[1]); }
      records.push({ name, type, ttl: s.TTL == null ? null : String(s.TTL), value: v, source: "route53" });
    }
  }
  const soa = records.find((r) => r.type === "SOA");
  const origin = soa ? soa.name : records.length ? records.map((r) => r.name).sort((a, b) => a.length - b.length)[0] : "";
  return { origin, records, errors: [] };
}

/** Parse `az network dns record-set list` JSON (any key casing, old and new CLI). */
export function parseAzureDns(json) {
  const arr = typeof json === "string" ? JSON.parse(json) : json;
  const records = [];
  const lower = (o) => (o && typeof o === "object" && !Array.isArray(o) ? Object.fromEntries(Object.entries(o).map(([k, v]) => [k.toLowerCase(), v])) : o);
  let origin = "";
  for (const raw of Array.isArray(arr) ? arr : []) {
    const s = lower(raw);
    const type = String(s.type || "").split("/").pop().toUpperCase();
    const fqdn = normName(s.fqdn || "");
    if (s.id) { const m = String(s.id).match(/dnszones\/([^/]+)\//i); if (m && !origin) origin = normName(m[1]); }
    const name = fqdn || qualify(s.name || "@", origin);
    const ttl = s.ttl == null ? null : String(s.ttl);
    const push = (t, v) => records.push({ name, type: t, ttl, value: v, source: "azure" });
    const tr = lower(s.targetresource);
    if (tr && tr.id) push("ALIAS", String(tr.id));
    for (const r of s.arecords || []) push("A", String(lower(r).ipv4address || ""));
    for (const r of s.aaaarecords || []) push("AAAA", String(lower(r).ipv6address || ""));
    const cn = lower(s.cnamerecord);
    if (cn && cn.cname) push("CNAME", normName(cn.cname));
    for (const r of s.mxrecords || []) { const x = lower(r); push("MX", x.preference + " " + normName(x.exchange)); }
    for (const r of s.nsrecords || []) push("NS", normName(lower(r).nsdname));
    for (const r of s.txtrecords || []) { const x = lower(r); push("TXT", (Array.isArray(x.value) ? x.value : [x.value]).join("")); }
    for (const r of s.caarecords || []) { const x = lower(r); push("CAA", x.flags + " " + x.tag + ' "' + x.value + '"'); }
    if (type === "SOA" && !origin) origin = name;
  }
  return { origin, records, errors: [] };
}

const truthy = (v) => /^(1|y|yes|true|mail|sends?)$/i.test(String(v == null ? "" : v).trim());
function cleanDomain(s) {
  let d = String(s || "").trim().replace(/^[a-z]+:\/\//i, "").split(/[\/?#\s]/)[0].replace(/:\d+$/, "");
  d = toAsciiDomain(d.replace(/^\*\./, ""));
  return isDomainName(d) ? d : null;
}

/** Domain list: one per line ("domain[, parked|mail]") or a CSV with a domain column. */
export function parseDomainList(text, mapping = {}) {
  const t = String(text || "").replace(/^﻿/, "");
  const lines = t.split(/\r?\n/).filter((l) => l.trim() && !/^\s*#/.test(l));
  const skipped = [], domains = [];
  if (!lines.length) return { format: "empty", headers: [], domains, skipped };
  const first = lines[0];
  const looksCsv = /[,;\t]/.test(first) && !cleanDomain(first.split(/[,;\t]/)[0]);
  if (looksCsv) {
    const { headers, rows } = parseCsv(t);
    const dc = mapping.domain || findColumn(headers, COLUMNS.domain);
    if (!dc) return { format: "csv", headers, domains, skipped: [{ check: "domain list", reason: "no domain column (" + COLUMNS.domain.join(", ") + ")" }], needsMapping: true };
    const mc = mapping.sendsMail || findColumn(headers, COLUMNS.sendsMail), pc = mapping.parked || findColumn(headers, COLUMNS.parked), rc = findColumn(headers, COLUMNS.role);
    for (const r of rows) {
      const d = cleanDomain(r[dc]);
      if (!d) { if (String(r[dc] || "").trim()) skipped.push({ check: "domain list", reason: "not a domain: " + String(r[dc]).slice(0, 60) }); continue; }
      const role = rc ? String(r[rc] || "").toLowerCase() : "";
      domains.push({ domain: d, sendsMail: mc ? truthy(r[mc]) : null, parked: (pc ? truthy(r[pc]) : false) || /parked/.test(role) });
    }
    return { format: "csv", headers, domains: dedupeDomains(domains), skipped, columns: { domain: dc, sendsMail: mc, parked: pc } };
  }
  for (const l of lines) {
    const parts = l.split(/[\s,;\t]+/).filter(Boolean);
    const d = cleanDomain(parts[0]);
    if (!d) { skipped.push({ check: "domain list", reason: "not a domain: " + l.trim().slice(0, 60) }); continue; }
    const flags = parts.slice(1).join(" ").toLowerCase();
    domains.push({ domain: d, sendsMail: /\bno-?mail\b|\bparked\b/.test(flags) ? false : /\bmail\b|\bsends\b/.test(flags) ? true : null, parked: /\bparked\b/.test(flags) });
  }
  return { format: "list", headers: [], domains: dedupeDomains(domains), skipped };
}
function dedupeDomains(list) {
  const m = new Map();
  for (const d of list) if (!m.has(d.domain)) m.set(d.domain, d);
  return [...m.values()].sort((a, b) => cmp(a.domain, b.domain));
}

/** Detect the format of one file. Returns { format, confidence }. */
export function detectFormat(text, name = "") {
  const t = String(text || "").replace(/^﻿/, "").trim();
  if (!t) return { format: "empty", confidence: "high" };
  if (t[0] === "{" || t[0] === "[") {
    try {
      const j = JSON.parse(t);
      if (j && Array.isArray(j.ResourceRecordSets)) return { format: "route53-json", confidence: "high" };
      if (Array.isArray(j) && j.some((x) => x && /dnszones\//i.test(String(x.type || x.Type || "")))) return { format: "azure-dns-json", confidence: "high" };
      return { format: "json-unknown", confidence: "low" };
    } catch (_) { return { format: "json-invalid", confidence: "low" }; }
  }
  if (/^\$(ORIGIN|TTL)\b/im.test(t) || /^\S*\s+(\d+\s+)?(IN\s+)?(\d+\s+)?(SOA|NS|A|AAAA|CNAME|MX|TXT|CAA)\s+\S/m.test(t) && /\bIN\b/.test(t)) {
    return { format: /^;;\s*Domain:/m.test(t) || /cf_tags=/.test(t) ? "cloudflare-bind" : "bind-zone", confidence: "high" };
  }
  const dl = parseDomainList(t);
  if (dl.domains.length) return { format: dl.format === "csv" ? "domain-csv" : "domain-list", confidence: dl.skipped.length > dl.domains.length ? "medium" : "high" };
  if (dl.needsMapping) return { format: "domain-csv", confidence: "low" };
  return { format: "unknown", confidence: "low" };
}

/**
 * Parse one text or a list of { name, text } files into domains + zone records.
 * Returns { format, headers, rows (zone records), skipped, files, domains, hosts }.
 */
export function parseInput(input, mapping = {}) {
  const files = Array.isArray(input) ? input : [{ name: "input", text: input }];
  const skipped = [], outFiles = [], records = [], domains = [];
  let headers = [];
  for (const f of files) {
    const text = String((f && f.text) || "");
    const det = detectFormat(text, f && f.name);
    const info = { name: (f && f.name) || "input", format: det.format, confidence: det.confidence, domains: 0, records: 0 };
    try {
      if (det.format === "route53-json" || det.format === "azure-dns-json" || det.format === "bind-zone" || det.format === "cloudflare-bind") {
        const z = det.format === "route53-json" ? parseRoute53(text) : det.format === "azure-dns-json" ? parseAzureDns(text) : parseBindZone(text);
        for (const r of z.records) records.push({ ...r, file: info.name });
        if (z.origin && isDomainName(z.origin)) { domains.push({ domain: z.origin, sendsMail: null, parked: false, fromZone: true }); info.origin = z.origin; }
        for (const e of z.errors.slice(0, 20)) skipped.push({ check: "zone parse", reason: info.name + ": " + e });
        info.records = z.records.length;
      } else if (det.format === "domain-list" || det.format === "domain-csv") {
        const dl = parseDomainList(text, mapping);
        domains.push(...dl.domains); skipped.push(...dl.skipped);
        if (dl.headers.length) { headers = dl.headers; info.headers = dl.headers; }
        if (dl.needsMapping) info.needsMapping = true;
        info.domains = dl.domains.length;
      } else if (det.format !== "empty") {
        skipped.push({ check: "input", reason: info.name + ": unrecognised format (" + det.format + ")" });
      }
    } catch (e) {
      skipped.push({ check: "input", reason: info.name + ": " + String((e && e.message) || e) });
    }
    outFiles.push(info);
  }
  const format = outFiles.length === 1 ? outFiles[0].format : "multi";
  return { format, headers, rows: records, skipped, files: outFiles, domains: dedupeDomains(domains), hosts: hostsFromRecords(records) };
}

/** Hostnames worth a takeover check: owners of CNAME / ALIAS / A / AAAA records. */
export function hostsFromRecords(records) {
  const m = new Map();
  for (const r of records || []) {
    if (!["CNAME", "ALIAS", "A", "AAAA"].includes(r.type)) continue;
    if (!r.name || r.name.startsWith("*.")) continue;
    const h = m.get(r.name) || { host: r.name, types: [], target: null, source: r.source || "zone" };
    if (!h.types.includes(r.type)) h.types.push(r.type);
    if ((r.type === "CNAME" || r.type === "ALIAS") && !h.target) h.target = normName(r.value);
    m.set(r.name, h);
  }
  return [...m.values()].map((h) => ({ ...h, types: h.types.sort() })).sort((a, b) => cmp(a.host, b.host));
}

// ---------------------------------------------------------------------------
// Query plan (UI fetches exactly these keys; the example uses the same keys)
// ---------------------------------------------------------------------------
/** DoH queries per domain: key -> { name, type, resolver }. */
export function planDomainQueries(domain, wildcardName) {
  const d = normName(domain);
  return [
    { key: "NS", name: d, type: "NS", resolver: "google" },
    { key: "NS_CF", name: d, type: "NS", resolver: "cloudflare" },
    { key: "SOA", name: d, type: "SOA" },
    { key: "MX", name: d, type: "MX" },
    { key: "TXT", name: d, type: "TXT" },
    { key: "DMARC", name: "_dmarc." + d, type: "TXT" },
    { key: "MTASTS", name: "_mta-sts." + d, type: "TXT" },
    { key: "TLSRPT", name: "_smtp._tls." + d, type: "TXT" },
    { key: "BIMI", name: "default._bimi." + d, type: "TXT" },
    { key: "DS", name: d, type: "DS" },
    { key: "CAA", name: d, type: "CAA" },
    { key: "A", name: d, type: "A" },
    ...(wildcardName ? [{ key: "WILDCARD", name: wildcardName, type: "A" }] : []),
  ];
}

// ---------------------------------------------------------------------------
// Subdomain takeover fingerprints
// ---------------------------------------------------------------------------
// Provider -> CNAME suffix patterns -> takeover signal, from public knowledge of the
// "can-i-take-over-xyz" project (EdOverflow). status mirrors that project's
// classification as understood when this table was written; where unsure it is
// "edge case". nxdomain = a dangling CNAME to this provider shows as NXDOMAIN.
// http = body text shown when the resource behind the CNAME no longer exists.
export const TAKEOVER_FINGERPRINTS = [
  { id: "aws-s3", provider: "AWS S3 (website/bucket endpoint)", cname: ["\\.s3-website[.-][a-z0-9-]+\\.amazonaws\\.com$", "\\.s3\\.amazonaws\\.com$", "\\.s3[.-][a-z0-9-]+\\.amazonaws\\.com$"], status: "vulnerable", nxdomain: false, http: ["NoSuchBucket", "The specified bucket does not exist"] },
  { id: "azure-app", provider: "Azure App Service", cname: ["\\.azurewebsites\\.net$"], status: "vulnerable", nxdomain: true, http: [] },
  { id: "azure-cloudapp", provider: "Azure Cloud Services / VM DNS", cname: ["\\.cloudapp\\.net$", "\\.cloudapp\\.azure\\.com$"], status: "vulnerable", nxdomain: true, http: [] },
  { id: "azure-tm", provider: "Azure Traffic Manager", cname: ["\\.trafficmanager\\.net$"], status: "vulnerable", nxdomain: true, http: [] },
  { id: "azure-blob", provider: "Azure Blob Storage", cname: ["\\.blob\\.core\\.windows\\.net$"], status: "vulnerable", nxdomain: true, http: [] },
  { id: "github-pages", provider: "GitHub Pages", cname: ["\\.github\\.io$"], status: "edge case", nxdomain: false, http: ["There isn't a GitHub Pages site here"] },
  { id: "heroku", provider: "Heroku", cname: ["\\.herokudns\\.com$", "\\.herokuapp\\.com$"], status: "edge case", nxdomain: false, http: ["No such app", "There's nothing here, yet"] },
  { id: "shopify", provider: "Shopify", cname: ["\\.myshopify\\.com$"], status: "edge case", nxdomain: false, http: ["Sorry, this shop is currently unavailable"] },
  { id: "fastly", provider: "Fastly", cname: ["\\.fastly\\.net$", "\\.fastlylb\\.net$"], status: "edge case", nxdomain: false, http: ["Fastly error: unknown domain"] },
  { id: "netlify", provider: "Netlify", cname: ["\\.netlify\\.app$", "\\.netlify\\.com$"], status: "edge case", nxdomain: false, http: ["Not Found - Request ID"] },
  { id: "vercel", provider: "Vercel", cname: ["\\.vercel\\.app$", "\\.vercel-dns\\.com$", "\\.now\\.sh$"], status: "edge case", nxdomain: false, http: ["DEPLOYMENT_NOT_FOUND", "The deployment could not be found on Vercel"] },
  { id: "zendesk", provider: "Zendesk", cname: ["\\.zendesk\\.com$"], status: "edge case", nxdomain: false, http: ["Help Center Closed"] },
  { id: "unbounce", provider: "Unbounce", cname: ["\\.unbouncepages\\.com$"], status: "edge case", nxdomain: false, http: ["The requested URL was not found on this server"] },
  { id: "pantheon", provider: "Pantheon", cname: ["\\.pantheonsite\\.io$"], status: "vulnerable", nxdomain: false, http: ["The gods are wise, but do not know of the site which you seek"] },
  { id: "ghost", provider: "Ghost", cname: ["\\.ghost\\.io$"], status: "vulnerable", nxdomain: false, http: ["Site unavailable", "Failed to resolve DNS path for this host"] },
  { id: "surge", provider: "Surge.sh", cname: ["\\.surge\\.sh$"], status: "vulnerable", nxdomain: false, http: ["project not found"] },
  { id: "bitbucket", provider: "Bitbucket", cname: ["\\.bitbucket\\.io$"], status: "vulnerable", nxdomain: false, http: ["Repository not found"] },
  { id: "helpscout", provider: "Help Scout", cname: ["\\.helpscoutdocs\\.com$"], status: "vulnerable", nxdomain: false, http: ["No settings were found for this company"] },
  { id: "readme", provider: "ReadMe", cname: ["\\.readme\\.io$"], status: "vulnerable", nxdomain: false, http: ["Project doesnt exist... yet!"] },
  { id: "webflow", provider: "Webflow", cname: ["(^|\\.)proxy\\.webflow\\.com$", "(^|\\.)proxy-ssl\\.webflow\\.com$"], status: "edge case", nxdomain: false, http: ["The page you are looking for doesn't exist or has been moved"] },
];
const FP_RES = TAKEOVER_FINGERPRINTS.map((f) => ({ ...f, res: f.cname.map((p) => new RegExp(p, "i")) }));

/** Provider fingerprint for a CNAME target, or null. */
export function matchTakeoverProvider(target) {
  const t = normName(target);
  if (!t) return null;
  const f = FP_RES.find((x) => x.res.some((r) => r.test(t)));
  if (!f) return null;
  const { res, ...rest } = f;
  return rest;
}

/** Does an HTTP response body carry the provider's "resource gone" fingerprint? */
export function matchHttpFingerprint(provider, http) {
  if (!provider || !http || http.error || !http.body) return null;
  const body = String(http.body).toLowerCase();
  const hit = (provider.http || []).find((s) => body.includes(s.toLowerCase()));
  return hit || null;
}

/** CNAME chain + final status from a DoH A answer for a host. */
export function cnameChain(j) {
  const chain = ((j && j.Answer) || []).filter((a) => Number(a.type) === RR.CNAME).map((a) => ({ from: normName(a.name), to: normName(a.data) }));
  return { chain, target: chain.length ? chain[chain.length - 1].to : null, status: dohStatus(j), addrs: rrData(j, "A").concat(rrData(j, "AAAA")) };
}

/** Grade one host for dangling-record / takeover risk. */
export function gradeHost(h, ho) {
  const row = { host: h.host, source: h.source || "zone", zoneTypes: (h.types || []).join(" "), zoneTarget: h.target || "", liveStatus: "unchecked", target: "", provider: "", providerStatus: "", signal: "", verdict: "not checked", severity: null, confidence: null };
  const live = ho && ho.A ? cnameChain(ho.A) : null;
  const aliasOnly = (h.types || []).includes("ALIAS") && !(h.types || []).includes("CNAME");
  if (live) row.liveStatus = live.status;
  const target = (live && live.target) || h.target || "";
  row.target = target;
  const prov = matchTakeoverProvider(target);
  if (prov) { row.provider = prov.provider; row.providerStatus = prov.status; }
  if (!live) {
    if (!target) row.verdict = "A/AAAA only - not checked (ownership of cloud IP addresses cannot be verified)";
    return row;
  }
  if (isErr(live.status)) { row.verdict = "lookup error"; return row; }
  if (!target) {
    row.verdict = live.status === "nxdomain" ? "host no longer resolves (record removed)" : "A/AAAA only - not checked (ownership of cloud IP addresses cannot be verified)";
    return row;
  }
  if (live.status === "nxdomain" && live.chain.length) {
    if (prov) { row.signal = "CNAME target " + target + " is NXDOMAIN"; row.verdict = "takeover candidate: " + prov.provider + " resource is gone"; row.severity = "high"; row.confidence = "likely"; return row; }
    row.signal = "CNAME target " + target + " is NXDOMAIN"; row.verdict = "dangling CNAME (target does not exist)"; row.severity = "medium"; row.confidence = "likely"; return row;
  }
  if (live.status === "nxdomain" && !live.chain.length && h.target) {
    row.verdict = aliasOnly ? "alias host does not resolve" : "host no longer resolves (zone export may be stale)"; return row;
  }
  if (prov) {
    const hit = matchHttpFingerprint(prov, ho.http);
    if (hit) {
      row.signal = 'HTTP body contains "' + hit + '"' + (ho.http.status ? " (HTTP " + ho.http.status + ")" : "");
      row.verdict = "takeover fingerprint matched: " + prov.provider;
      row.severity = prov.status === "vulnerable" ? "critical" : "high";
      row.confidence = prov.status === "vulnerable" ? "confirmed" : "likely";
      return row;
    }
    row.verdict = ho.http ? (ho.http.error ? "points at " + prov.provider + "; HTTP check failed" : "points at " + prov.provider + "; no takeover fingerprint") : "points at " + prov.provider + "; HTTP not checked";
    return row;
  }
  row.verdict = "resolves; no takeover signal";
  return row;
}

// ---------------------------------------------------------------------------
// Lookalike generation
// ---------------------------------------------------------------------------
const KB = {
  q: "12wa", w: "23qeas", e: "34wrds", r: "45etfd", t: "56rygf", y: "67tuhg", u: "78yijh", i: "89uokj", o: "90iplk", p: "0ol",
  a: "qwsz", s: "wedxza", d: "erfcxs", f: "rtgvcd", g: "tyhbvf", h: "yujnbg", j: "uikmnh", k: "iolmj", l: "opk",
  z: "asx", x: "zsdc", c: "xdfv", v: "cfgb", b: "vghn", n: "bhjm", m: "njk",
  1: "2q", 2: "13wq", 3: "24ew", 4: "35re", 5: "46tr", 6: "57yt", 7: "68uy", 8: "79iu", 9: "80oi", 0: "9po",
};
// ASCII homoglyphs (single character or digraph look-alikes).
const ASCII_GLYPHS = [["o", "0"], ["0", "o"], ["l", "1"], ["1", "l"], ["i", "1"], ["l", "i"], ["i", "l"], ["m", "rn"], ["rn", "m"], ["w", "vv"], ["vv", "w"], ["d", "cl"], ["cl", "d"], ["g", "q"], ["q", "g"], ["u", "v"], ["v", "u"], ["s", "5"], ["e", "3"], ["a", "4"], ["b", "6"]];
// Small IDN confusables table (Cyrillic look-alikes and common Latin diacritics).
const IDN_GLYPHS = {
  a: ["а", "à", "á"], c: ["с", "ç"], e: ["е", "é", "è"], i: ["і", "í"],
  o: ["о", "ö", "ó"], p: ["р"], s: ["ѕ"], u: ["ü", "ú"], x: ["х"], y: ["у", "ý"], n: ["ñ"],
};
export const SWAP_TLDS = ["com", "net", "org", "co", "io", "ai", "app", "dev", "info", "biz", "us", "uk", "de"];
export const BRAND_SUFFIX_WORDS = ["login", "secure", "support", "billing", "pay", "hr", "portal", "sso", "mail"];
const validLabel = (l) => LABEL_RE.test(l) && !(l.length >= 4 && l[2] === "-" && l[3] === "-" && !l.startsWith("xn--"));

/**
 * Deterministic lookalike candidates for a domain. Order is fixed by kind then
 * position, duplicates and the domain itself are removed, then the list is capped.
 * Returns [{ domain (ASCII/Punycode), display (Unicode), kind }].
 */
export function generateLookalikes(domain, { keywords = [], max = DEFAULTS.maxCandidates } = {}) {
  const { prefix, label, suffix } = splitDomain(toAsciiDomain(domain));
  if (!label) return [];
  const cap = Math.max(0, Math.min(LIMITS.maxCandidates, Number(max) || 0));
  const pre = prefix ? prefix + "." : "";
  const own = pre + label + "." + suffix;
  const out = [], seen = new Set([own]);
  const add = (lab, kind, suf = suffix, display = null) => {
    if (out.length >= cap) return;
    const l = String(lab).toLowerCase();
    const ascii = /[^\x00-\x7f]/.test(l) ? "xn--" + punycodeEncode(l.normalize("NFC")) : l;
    if (!validLabel(ascii)) return;
    const d = pre + ascii + "." + suf;
    if (seen.has(d)) return;
    seen.add(d);
    out.push({ domain: d, display: display || (pre + l + "." + suf), kind });
  };
  const L = label, n = L.length;
  // 1. ASCII homoglyphs
  for (const [from, to] of ASCII_GLYPHS) {
    for (let i = L.indexOf(from); i >= 0; i = L.indexOf(from, i + 1)) add(L.slice(0, i) + to + L.slice(i + from.length), "homoglyph");
  }
  // 2. omission
  for (let i = 0; i < n; i++) add(L.slice(0, i) + L.slice(i + 1), "omission");
  // 3. transposition
  for (let i = 0; i < n - 1; i++) if (L[i] !== L[i + 1]) add(L.slice(0, i) + L[i + 1] + L[i] + L.slice(i + 2), "transposition");
  // 4. repetition
  for (let i = 0; i < n; i++) if (/[a-z0-9]/.test(L[i])) add(L.slice(0, i + 1) + L[i] + L.slice(i + 1), "repetition");
  // 5. replacement (keyboard adjacency)
  for (let i = 0; i < n; i++) for (const c of KB[L[i]] || "") add(L.slice(0, i) + c + L.slice(i + 1), "replacement");
  // 6. TLD swap (public suffixes only)
  if (!PRIVATE_SUFFIXES.has(suffix)) {
    const tlds = uniq([...SWAP_TLDS, ...(suffix.split(".").pop().length === 2 ? [suffix.split(".").pop()] : [])]);
    for (const t of tlds) if (t !== suffix) add(L, "tld-swap", t);
  }
  // 7. hyphenation
  for (let i = 1; i < n; i++) if (L[i - 1] !== "-" && L[i] !== "-") add(L.slice(0, i) + "-" + L.slice(i), "hyphenation");
  // 8. subdomain-style (dot dropped into the label) and brand-word combos
  const sufFlat = suffix.replace(/\./g, "-"), sufTarget = PRIVATE_SUFFIXES.has(suffix) ? suffix : "com";
  add(L + sufFlat.replace(/-/g, ""), "subdomain-style", sufTarget);
  add(L + "-" + sufFlat, "subdomain-style", sufTarget);
  const bases = uniq([L, ...(keywords || []).map((k) => String(k).trim().toLowerCase()).filter((k) => /^[a-z0-9-]+$/.test(k))]);
  const sufs = uniq([suffix, ...(PRIVATE_SUFFIXES.has(suffix) ? [] : ["com"])]);
  for (const b of bases) for (const w of BRAND_SUFFIX_WORDS) for (const s of sufs) {
    add(b + "-" + w, "keyword", s);
    add(b + w, "keyword", s);
    add(w + "-" + b, "keyword", s);
  }
  // 9. bit-squatting (one flipped bit that is still a hostname character)
  for (let i = 0; i < n; i++) {
    const code = L.charCodeAt(i);
    for (let b = 0; b < 8; b++) {
      const c = String.fromCharCode(code ^ (1 << b));
      if (/^[a-z0-9-]$/.test(c)) add(L.slice(0, i) + c + L.slice(i + 1), "bitsquat");
    }
  }
  // 10. IDN homoglyphs (Punycode)
  for (let i = 0; i < n; i++) for (const g of IDN_GLYPHS[L[i]] || []) add(L.slice(0, i) + g + L.slice(i + 1), "idn-homoglyph");
  return out;
}

/** Grade the registration answers fetched for one lookalike candidate. */
export function gradeLookalike(obs, nowMs, o = DEFAULTS) {
  if (!obs) return { status: "unchecked" };
  const ns = dohStatus(obs.NS), a = obs.A ? dohStatus(obs.A) : "missing";
  const hasNs = rrData(obs.NS, "NS").length > 0;
  const aRecs = obs.A ? rrData(obs.A, "A").concat(rrData(obs.A, "AAAA")) : [];
  const mx = obs.MX ? parseMx(obs.MX).filter((m) => m.host) : [];
  let status;
  if (ns === "nxdomain" && (a === "nxdomain" || a === "missing")) status = "unregistered";
  else if (ns === "ok" || hasNs || aRecs.length || mx.length) status = "registered";
  else status = "error";
  const rd = obs.rdap ? parseRdap(obs.rdap, nowMs) : null;
  const ageDays = rd && rd.ok ? rd.ageDays : null;
  return {
    status, mx: mx.length > 0, mxHosts: mx.map((m) => m.host), web: aRecs.length > 0, addrs: aRecs.slice(0, 4),
    created: rd && rd.ok ? rd.created : null, ageDays, registrar: rd && rd.ok ? rd.registrar : null,
    newlyRegistered: ageDays != null && ageDays >= 0 && ageDays < o.newlyRegisteredDays,
    rdapError: rd && !rd.ok ? rd.error : null,
  };
}

// ---------------------------------------------------------------------------
// Per-domain grading
// ---------------------------------------------------------------------------
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV_PENALTY = { critical: 40, high: 25, medium: 12, low: 5, info: 0 };

/** Issue catalog: id -> finding template. */
const ISSUES = {
  expiry_critical: { title: "Domain registration expires within days (or has expired)", severity: "critical", confidence: "confirmed", category: "registration", controls: [C.t1583, C.icannLock, C.iso59], recommendation: "Renew now and enable auto-renew with a valid payment method; an expired domain can be re-registered by anyone and inherits your mail and web traffic." },
  expiry_soon: { title: "Domain registration expires within the warning window", severity: "high", confidence: "confirmed", category: "registration", controls: [C.t1583, C.iso59], recommendation: "Renew for multiple years and turn on auto-renew; assign an owner for registrar notices." },
  rdap_redemption: { title: "Domain is in redemption or pending delete", severity: "critical", confidence: "confirmed", category: "registration", controls: [C.t1583, C.icannLock], recommendation: "Restore the domain through the registrar immediately before it is released." },
  no_transfer_lock: { title: "Registrar transfer lock not set", severity: "medium", confidence: "confirmed", category: "registration", controls: [C.icannLock, C.t1584], recommendation: "Enable the registrar lock (clientTransferProhibited, plus clientDeleteProhibited/clientUpdateProhibited) or a registry lock for high-value domains." },
  ns_dangling: { title: "Delegated name server hostname does not resolve", severity: "high", confidence: "likely", category: "dns", controls: [C.t1584dns, C.sc20, C.sc22], recommendation: "Remove the broken NS from the delegation at the registrar. If the NS hostname's own domain has lapsed, anyone who registers it can answer for your zone." },
  ns_count: { title: "Fewer than two name servers", severity: "medium", confidence: "confirmed", category: "dns", controls: [C.sc22], recommendation: "Publish at least two name servers on separate networks (RFC 1034 4.1)." },
  ns_single_provider: { title: "All name servers at one DNS provider", severity: "low", confidence: "confirmed", category: "dns", controls: [C.sc22], recommendation: "Consider a secondary DNS provider for critical domains so a single provider outage does not take mail and web down." },
  ns_inconsistent: { title: "Name server set differs between resolvers", severity: "low", confidence: "review", category: "dns", controls: [C.sc22], recommendation: "Compare the registrar delegation with the NS records in the zone; a recent change or a lame server can cause this." },
  dmarc_missing: { title: "No DMARC record", severity: "high", confidence: "confirmed", category: "email-auth", controls: [C.bod1801, C.rfc7489, C.sp800177, C.t1566], recommendation: "Publish _dmarc TXT with rua reporting, then progress p=none to quarantine to reject." },
  dmarc_multiple: { title: "Multiple DMARC records (policy ignored)", severity: "high", confidence: "confirmed", category: "email-auth", controls: [C.rfc7489, C.bod1801], recommendation: "Keep exactly one v=DMARC1 TXT record at _dmarc; with several, receivers apply no DMARC policy (RFC 7489 6.6.3)." },
  dmarc_syntax: { title: "DMARC record has syntax errors", severity: "medium", confidence: "confirmed", category: "email-auth", controls: [C.rfc7489], recommendation: "Fix the record so v=DMARC1 is first and p= is present and valid." },
  dmarc_none: { title: "DMARC policy is p=none (monitor only)", severity: "medium", confidence: "confirmed", category: "email-auth", controls: [C.bod1801, C.rfc7489, C.t1566], recommendation: "Move to p=quarantine and then p=reject once aggregate reports show legitimate senders aligned (BOD 18-01 requires reject)." },
  dmarc_pct: { title: "DMARC enforcement applies to only part of mail (pct<100)", severity: "low", confidence: "confirmed", category: "email-auth", controls: [C.bod1801, C.rfc7489], recommendation: "Raise pct to 100." },
  dmarc_sp_none: { title: "DMARC subdomain policy weaker than domain policy (sp=none)", severity: "low", confidence: "confirmed", category: "email-auth", controls: [C.rfc7489], recommendation: "Set sp=reject or remove sp so subdomains inherit p." },
  dmarc_no_rua: { title: "DMARC has no aggregate report address (rua)", severity: "low", confidence: "confirmed", category: "email-auth", controls: [C.bod1801, C.rfc7489], recommendation: "Add rua=mailto:... so you can see who sends as the domain (BOD 18-01 asks for the CISA reporting address on federal domains)." },
  spf_missing: { title: "No SPF record on a mail domain", severity: "medium", confidence: "confirmed", category: "email-auth", controls: [C.bod1801, C.rfc7208, C.sp800177], recommendation: "Publish v=spf1 listing your senders and ending in -all (or ~all while DMARC enforces)." },
  spf_multiple: { title: "Multiple SPF records (permerror)", severity: "high", confidence: "confirmed", category: "email-auth", controls: [C.rfc7208], recommendation: "Merge into one v=spf1 record; two or more is a permerror (RFC 7208 3.2) and SPF fails for every message." },
  spf_plus_all: { title: "SPF allows any sender (+all)", severity: "high", confidence: "confirmed", category: "email-auth", controls: [C.rfc7208, C.bod1801, C.t1566], recommendation: "Replace +all with -all; +all authorises the whole internet to send as the domain." },
  spf_neutral: { title: "SPF ends in ?all (neutral)", severity: "medium", confidence: "confirmed", category: "email-auth", controls: [C.rfc7208], recommendation: "Use -all (or ~all with DMARC p=reject); ?all asserts nothing." },
  spf_permerror: { title: "SPF exceeds the 10 DNS-lookup limit (permerror)", severity: "high", confidence: "confirmed", category: "email-auth", controls: [C.rfc7208, C.m3auth], recommendation: "Remove unused includes, replace includes with ip4/ip6 ranges, or split senders onto subdomains to get to 10 lookups or fewer (RFC 7208 4.6.4)." },
  spf_include_nospf: { title: "SPF include points at a domain without SPF (permerror)", severity: "medium", confidence: "confirmed", category: "email-auth", controls: [C.rfc7208], recommendation: "Remove or correct the include; including a domain with no SPF record is a permerror (RFC 7208 5.2)." },
  parked_unlocked: { title: "Parked (non-mail) domain without lock-down records", severity: "high", confidence: "confirmed", category: "email-auth", controls: [C.m3parked, C.rfc7505, C.bod1801, C.t1566], recommendation: "Publish the parked-domain trio: null MX (MX 0 .), v=spf1 -all, and _dmarc v=DMARC1; p=reject. Attackers favour parked domains because nobody watches them." },
  mtasts_absent: { title: "MTA-STS not deployed on a mail-receiving domain", severity: "low", confidence: "confirmed", category: "transport", controls: [C.rfc8461, C.sp800177], recommendation: "Publish _mta-sts TXT and https://mta-sts.<domain>/.well-known/mta-sts.txt so senders require TLS to your MX." },
  mtasts_testing: { title: "MTA-STS in testing mode", severity: "info", confidence: "confirmed", category: "transport", controls: [C.rfc8461], recommendation: "Move to mode: enforce once TLS-RPT reports are clean." },
  mtasts_broken: { title: "MTA-STS record present but the policy is unusable", severity: "low", confidence: "likely", category: "transport", controls: [C.rfc8461], recommendation: "Serve a valid policy over HTTPS at mta-sts.<domain> whose mx: lines cover every MX host." },
  tlsrpt_absent: { title: "No TLS-RPT reporting on a mail-receiving domain", severity: "info", confidence: "confirmed", category: "transport", controls: [C.rfc8460], recommendation: "Publish _smtp._tls TXT v=TLSRPTv1; rua=mailto:..." },
  dnssec_absent: { title: "DNSSEC not enabled (no DS at parent)", severity: "low", confidence: "confirmed", category: "dns", controls: [C.rfc4033, C.sc20], recommendation: "Sign the zone and publish the DS record at the registrar." },
  dnssec_unvalidated: { title: "DS published but answers are not validated", severity: "medium", confidence: "review", category: "dns", controls: [C.rfc4033, C.sc20], recommendation: "Check that the DS matches the zone's DNSKEY; a mismatch makes validating resolvers fail the whole domain." },
  caa_absent: { title: "No CAA record", severity: "low", confidence: "confirmed", category: "pki", controls: [C.rfc8659, C.sc17], recommendation: "Publish CAA issue records for the CAs you use, plus iodef for violation reports." },
  wildcard: { title: "Wildcard DNS: any subdomain resolves", severity: "low", confidence: "review", category: "dns", controls: [C.sc20, C.t1584], recommendation: "Confirm the wildcard is intended; it makes typo'd and phishing subdomains look legitimate and widens any takeover." },
  cert_expiring: { title: "Newest certificate expires soon", severity: "medium", confidence: "likely", category: "pki", controls: [C.sc17], recommendation: "Renew the certificate (the newest CT-logged certificate is close to expiry; confirm the one actually served)." },
  takeover: { title: "Subdomain takeover candidate", severity: "high", confidence: "likely", category: "takeover", controls: [C.t1584, C.cm8], recommendation: "Delete the DNS record or re-claim the resource at the provider immediately." },
  dangling_cname: { title: "Dangling CNAME (target does not exist)", severity: "medium", confidence: "likely", category: "takeover", controls: [C.t1584, C.cm8], recommendation: "Delete the record; if the target's domain is registrable, whoever registers it controls this hostname." },
  lookalike_mx_new: { title: "Newly registered lookalike domain with mail (MX)", severity: "high", confidence: "likely", category: "lookalike", controls: [C.t1583, C.t1566], recommendation: "Block the domain at the mail gateway and proxy, warn finance/AP about BEC, and consider a registrar/UDRP takedown." },
  lookalike_mx: { title: "Registered lookalike domain with mail (MX)", severity: "medium", confidence: "likely", category: "lookalike", controls: [C.t1583, C.t1566], recommendation: "Review the owner; block at the mail gateway if it is not yours." },
  lookalike_web: { title: "Registered lookalike domain with a website", severity: "medium", confidence: "likely", category: "lookalike", controls: [C.t1583, C.t1566], recommendation: "Review the site; add to proxy blocklists and pursue takedown if it imitates the brand." },
  lookalike_parked: { title: "Registered lookalike domain (no mail, no web)", severity: "low", confidence: "review", category: "lookalike", controls: [C.t1583], recommendation: "Monitor; consider defensive registration of the closest variants." },
};

function chk(status, detail, extra) { return { status, detail, ...(extra || {}) }; }
const MAILROLE = { mail: "sends/receives mail", parked: "parked (no mail)", unknown: "unknown" };

/** Grade one domain from its observations. Returns { row, issues: [{ id, detail, extra }] }. */
export function gradeDomain(spec, obs, o, nowMs) {
  const d = spec.domain;
  const dns = (obs && obs.dns) || {};
  const issues = [];
  const checks = {};
  const raise = (id, detail, extra) => issues.push({ id, detail, extra: extra || {} });
  if (!obs) {
    return { row: { domain: d, role: "unchecked", grade: "N/A", score: null, checks: {}, errors: 0, checkedAt: null }, issues };
  }
  // --- NS
  const nsS = dohStatus(dns.NS);
  const ns = rrData(dns.NS, "NS").map(normName).sort();
  const nsCf = rrData(dns.NS_CF, "NS").map(normName).sort();
  if (isErr(nsS)) checks.ns = chk("error", "NS lookup failed (" + nsS + ")");
  else if (nsS === "nxdomain") checks.ns = chk("fail", "Domain does not exist in DNS (NXDOMAIN)");
  else {
    const provs = uniq(ns.map(nsProvider)).sort();
    const parts = [ns.length + " NS (" + provs.join(", ") + ")"];
    let st = "pass";
    if (ns.length < 2) { st = "fail"; raise("ns_count", ns.length + " name server(s): " + ns.join(", ")); }
    else if (provs.length === 1) { st = "warn"; raise("ns_single_provider", "all " + ns.length + " NS at " + provs[0], { providers: provs.join(", ") }); }
    if (dns.NS_CF && dohStatus(dns.NS_CF) === "ok" && nsCf.length && nsCf.join(",") !== ns.join(",")) {
      st = st === "pass" ? "warn" : st; parts.push("differs between resolvers");
      raise("ns_inconsistent", "dns.google: " + ns.join(" ") + " / cloudflare-dns.com: " + nsCf.join(" "));
    }
    const nsh = (obs.nsHosts) || {};
    const dead = ns.filter((h) => nsh[h] && dohStatus(nsh[h]) === "nxdomain");
    if (dead.length) { st = "fail"; parts.push(dead.length + " NS host(s) NXDOMAIN"); raise("ns_dangling", "NS host(s) not resolving: " + dead.join(", "), { nsHosts: dead.join(" ") }); }
    checks.ns = chk(st, parts.join("; "), { values: ns });
  }
  // --- SOA
  const soa = parseSoa(dns.SOA);
  checks.soa = isErr(dohStatus(dns.SOA)) ? chk("error", "SOA lookup failed") : soa ? chk("info", "serial " + soa.serial + ", contact " + soa.email + ", primary " + soa.mname, { soa }) : chk("warn", "No SOA in the answer");
  // --- MX / role
  const mxS = dohStatus(dns.MX);
  const mx = parseMx(dns.MX);
  const nullMx = mx.length === 1 && mx[0].pref === 0 && mx[0].host === "";
  const realMx = mx.filter((m) => m.host);
  const txtS = dohStatus(dns.TXT);
  const txts = txtStrings(dns.TXT);
  const spf = parseSpfRecords(txts);
  // Send-only domains (no MX, but an SPF record that authorises senders) still count as mail domains.
  const spfAuthorises = spf.present && (spf.directLookups > 0 || /\b(ip4|ip6):/i.test(spf.record));
  let role;
  if (spec.parked) role = "parked";
  else if (spec.sendsMail === true) role = "mail";
  else if (spec.sendsMail === false) role = "parked";
  else if (isErr(mxS)) role = "unknown";
  else role = realMx.length || (!nullMx && spfAuthorises) ? "mail" : "parked";
  if (isErr(mxS)) checks.mx = chk("error", "MX lookup failed (" + mxS + ")");
  else if (nullMx) checks.mx = chk(role === "parked" ? "pass" : "warn", "Null MX (RFC 7505): domain accepts no mail");
  else if (realMx.length) checks.mx = chk(role === "parked" ? "warn" : "pass", realMx.map((m) => m.pref + " " + m.host).join(", "), { values: realMx.map((m) => m.host) });
  else checks.mx = chk(role === "parked" ? "warn" : "info", "No MX records" + (role === "parked" ? " (publish null MX to refuse mail explicitly)" : ""));
  // --- SPF
  let spfTree = null;
  if (isErr(txtS)) checks.spf = chk("error", "TXT lookup failed (" + txtS + ")");
  else if (!spf.present) {
    checks.spf = chk(role === "parked" ? "fail" : role === "mail" ? "fail" : "warn", "No SPF record");
    if (role === "mail") raise("spf_missing", "no v=spf1 TXT record");
  } else {
    const parts = [];
    let st = "pass";
    if (spf.multiple) { st = "fail"; raise("spf_multiple", spf.records.length + " v=spf1 records", { records: spf.records.join(" | ") }); parts.push(spf.records.length + " SPF records"); }
    if (spf.all === "+") { st = "fail"; raise("spf_plus_all", spf.record); parts.push("+all"); }
    else if (spf.all === "?") { st = "warn"; raise("spf_neutral", spf.record); parts.push("?all"); }
    else if (spf.all === "~") { parts.push("~all (softfail)"); }
    else if (spf.all === "-") parts.push("-all");
    else if (!spf.redirect) { st = st === "pass" ? "warn" : st; parts.push("no all mechanism"); }
    const lk = (dom) => {
      const j = obs.spf && obs.spf[dom];
      if (j == null) return { status: "missing" };
      const s = dohStatus(j);
      if (isErr(s)) return { status: "missing" };
      const t = txtStrings(j);
      return parseSpfRecords(t).present ? { status: "ok", txts: t } : { status: "none" };
    };
    spfTree = spfLookupTree(spf.record, lk);
    const lim = o.spfLookupLimit;
    parts.push(spfTree.count + (spfTree.complete ? "" : "+") + " DNS lookups" + (spfTree.complete ? "" : " (" + spfTree.missing.length + " include(s) not resolved)"));
    if (spfTree.count > lim) { st = "fail"; raise("spf_permerror", spfTree.count + " lookups (limit " + lim + ")" + (spfTree.complete ? "" : ", at least"), { tree: spfTree.tree.map((t) => "  ".repeat(t.depth) + t.domain + " +" + t.lookups).join("\n") }); }
    if (spfTree.noSpf.length) { st = st === "pass" ? "warn" : st; raise("spf_include_nospf", "include target(s) without SPF: " + spfTree.noSpf.join(", ")); }
    checks.spf = chk(st, parts.join("; "), { record: spf.record, lookups: spfTree.count, complete: spfTree.complete });
  }
  // --- DMARC
  const dmS = dohStatus(dns.DMARC);
  const dm = parseDmarcStrict(txtStrings(dns.DMARC));
  if (isErr(dmS)) checks.dmarc = chk("error", "_dmarc lookup failed (" + dmS + ")");
  else if (!dm.present) {
    checks.dmarc = chk("fail", "No DMARC record");
    if (role !== "parked") raise("dmarc_missing", "no v=DMARC1 TXT at _dmarc." + d);
  } else {
    const parts = ["p=" + dm.policy + (dm.pct !== 100 ? " pct=" + dm.pct : "") + (dm.sp ? " sp=" + dm.sp : "")];
    let st = dm.policy === "reject" ? "pass" : dm.policy === "quarantine" ? "warn" : "fail";
    if (dm.multiple) { st = "fail"; raise("dmarc_multiple", dm.records.length + " records", { records: dm.records.join(" | ") }); parts.push(dm.records.length + " records"); }
    if (dm.errors.length) { st = "fail"; raise("dmarc_syntax", dm.errors.join("; "), { record: dm.record }); parts.push("syntax: " + dm.errors[0]); }
    if (dm.policy === "none" && role !== "parked") raise("dmarc_none", dm.record);
    if (dm.policy !== "none" && dm.pct < 100) { st = st === "pass" ? "warn" : st; raise("dmarc_pct", "pct=" + dm.pct, { record: dm.record }); }
    if (dm.sp === "none" && dm.policy !== "none") { st = st === "pass" ? "warn" : st; raise("dmarc_sp_none", dm.record); }
    if (!dm.rua && role !== "parked") { raise("dmarc_no_rua", dm.record); parts.push("no rua"); } else if (dm.rua) parts.push("rua");
    if (dm.ruf) parts.push("ruf");
    checks.dmarc = chk(st, parts.join("; "), { record: dm.record, policy: dm.policy, pct: dm.pct });
  }
  // --- Parked-domain lock-down (M3AAWG)
  if (role === "parked") {
    const miss = [];
    if (!isErr(mxS) && !nullMx) miss.push("null MX (MX 0 .)");
    if (!isErr(txtS) && !(spf.present && !spf.multiple && spf.all === "-" && spfLookupCount(spf.record) === 0 && !/\b(ip4|ip6):/i.test(spf.record))) miss.push("v=spf1 -all");
    if (!isErr(dmS) && !(dm.present && dm.policy === "reject" && !dm.multiple)) miss.push("DMARC p=reject");
    if (isErr(mxS) || isErr(txtS) || isErr(dmS)) checks.parked = chk("error", "could not read all of MX/SPF/DMARC");
    else if (miss.length) { checks.parked = chk("fail", "missing: " + miss.join(", ")); raise("parked_unlocked", "missing " + miss.join(", "), { missing: miss.join("; ") }); }
    else checks.parked = chk("pass", "null MX + v=spf1 -all + DMARC p=reject");
  } else checks.parked = chk("na", role === "unknown" ? "mail role unknown (MX lookup failed)" : "mail domain");
  // --- MTA-STS / TLS-RPT / BIMI (mail-receiving domains only)
  const receives = realMx.length > 0;
  const mtsS = dohStatus(dns.MTASTS);
  const mtsTxt = txtStrings(dns.MTASTS);
  const pol = obs.mtaStsPolicy;
  const polBody = pol && !pol.error && (!pol.status || pol.status === 200) ? pol.body : null;
  const mts = parseMtaSts(mtsTxt, polBody);
  if (!receives) checks.mtasts = chk("na", "no MX hosts");
  else if (isErr(mtsS)) checks.mtasts = chk("error", "_mta-sts lookup failed");
  else if (!mts.present) { checks.mtasts = chk("warn", "No _mta-sts record"); raise("mtasts_absent", "no _mta-sts TXT"); }
  else if (!polBody) {
    const why = pol ? (pol.error ? "policy fetch failed: " + pol.error : "policy HTTP " + pol.status) : "policy not fetched";
    if (pol && !pol.error) { checks.mtasts = chk("fail", why); raise("mtasts_broken", why); } else checks.mtasts = chk("error", why);
  } else {
    const cov = mtaStsCoverage(polBody, realMx.map((m) => m.host));
    const parts = ["mode=" + (mts.mode || "?"), "max_age=" + (mts.maxAge == null ? "?" : mts.maxAge)];
    let st = mts.mode === "enforce" ? "pass" : "warn";
    if (mts.mode === "testing") raise("mtasts_testing", "mode: testing, max_age " + mts.maxAge);
    if (!mts.mode || mts.mode === "none") { st = "fail"; raise("mtasts_broken", "policy mode " + (mts.mode || "missing")); }
    if (cov.uncovered.length) { st = "fail"; parts.push("MX not covered: " + cov.uncovered.join(", ")); raise("mtasts_broken", "policy mx: lines do not cover " + cov.uncovered.join(", ")); }
    checks.mtasts = chk(st, parts.join("; "), { record: mts.record });
  }
  const tlsS = dohStatus(dns.TLSRPT);
  const tlsRec = txtStrings(dns.TLSRPT).find((t) => /^v=tlsrptv1/i.test(t));
  if (!receives) checks.tlsrpt = chk("na", "no MX hosts");
  else if (isErr(tlsS)) checks.tlsrpt = chk("error", "_smtp._tls lookup failed");
  else if (tlsRec) checks.tlsrpt = chk("pass", tlsRec);
  else { checks.tlsrpt = chk("warn", "No TLS-RPT record"); raise("tlsrpt_absent", "no _smtp._tls TXT"); }
  const bimi = txtStrings(dns.BIMI).find((t) => /^v=bimi1/i.test(t));
  checks.bimi = isErr(dohStatus(dns.BIMI)) ? chk("error", "BIMI lookup failed") : chk("info", bimi ? bimi : "No BIMI record (optional)");
  // --- DNSSEC
  const dsS = dohStatus(dns.DS);
  const ds = rrData(dns.DS, "DS");
  if (isErr(dsS) && dsS !== "servfail") checks.dnssec = chk("error", "DS lookup failed");
  else if (dsS === "servfail") { checks.dnssec = chk("fail", "SERVFAIL from a validating resolver (possible broken DNSSEC chain)"); raise("dnssec_unvalidated", "DS query returned SERVFAIL"); }
  else if (!ds.length) { checks.dnssec = chk("warn", "No DS record at the parent"); raise("dnssec_absent", "no DS"); }
  else {
    // AD on the zone's own answers (SOA / A) shows the child zone validated, not just the parent's DS.
    const ad = (dns.SOA && dns.SOA.AD) || (dns.A && dns.A.AD);
    if (ad) checks.dnssec = chk("pass", ds.length + " DS record(s); answers validated (AD)");
    else { checks.dnssec = chk("warn", ds.length + " DS record(s) but AD flag not set"); raise("dnssec_unvalidated", "DS present, AD=false"); }
  }
  // --- CAA
  const caaS = dohStatus(dns.CAA);
  const caa = rrData(dns.CAA, "CAA").map(parseCaaData).filter(Boolean);
  if (isErr(caaS)) checks.caa = chk("error", "CAA lookup failed");
  else if (!caa.length) { checks.caa = chk("warn", "No CAA records"); raise("caa_absent", "no CAA"); }
  else {
    const iss = uniq(caa.filter((c) => c.tag === "issue" || c.tag === "issuewild").map((c) => c.value.split(";")[0].trim() || "(none)")).sort();
    const iodef = caa.some((c) => c.tag === "iodef");
    checks.caa = chk("pass", "issuers: " + (iss.join(", ") || "none") + (iodef ? "; iodef set" : "; no iodef"));
  }
  // --- Wildcard
  if (dns.WILDCARD) {
    const wS = dohStatus(dns.WILDCARD);
    const w = rrData(dns.WILDCARD, "A").concat(rrData(dns.WILDCARD, "CNAME"));
    if (isErr(wS)) checks.wildcard = chk("error", "wildcard probe failed");
    else if (wS === "ok" && w.length) { checks.wildcard = chk("warn", "random label " + (obs.wildcardName || "") + " resolves to " + w.slice(0, 3).join(", ")); raise("wildcard", "random label resolves: " + w.slice(0, 3).join(", ")); }
    else checks.wildcard = chk("pass", "random label does not resolve");
  } else checks.wildcard = chk("na", "not probed");
  // --- RDAP
  const rd = obs.rdap ? parseRdap(obs.rdap, nowMs) : null;
  if (!rd) { checks.expiry = chk("na", "RDAP not fetched"); checks.lock = chk("na", "RDAP not fetched"); }
  else if (!rd.ok) { checks.expiry = chk("error", rd.error); checks.lock = chk("error", rd.error); }
  else {
    if (rd.redemption) { checks.expiry = chk("fail", "status " + rd.statuses.join(", ")); raise("rdap_redemption", rd.statuses.join(", "), { registrar: rd.registrar }); }
    else if (rd.daysLeft == null) checks.expiry = chk(nowMs == null ? "na" : "warn", rd.expires ? "expires " + rd.expires + " (no reference date)" : "no expiration event in RDAP");
    else if (rd.daysLeft < o.expiryCriticalDays) { checks.expiry = chk("fail", (rd.daysLeft < 0 ? "expired " + -rd.daysLeft + " days ago" : rd.daysLeft + " days left") + " (" + rd.expires.slice(0, 10) + ")"); raise("expiry_critical", rd.daysLeft + " days (" + rd.expires.slice(0, 10) + ")", { expires: rd.expires, daysLeft: rd.daysLeft, registrar: rd.registrar }); }
    else if (rd.daysLeft < o.expiryWarnDays) { checks.expiry = chk("warn", rd.daysLeft + " days left (" + rd.expires.slice(0, 10) + ")"); raise("expiry_soon", rd.daysLeft + " days (" + rd.expires.slice(0, 10) + ")", { expires: rd.expires, daysLeft: rd.daysLeft, registrar: rd.registrar }); }
    else checks.expiry = chk("pass", rd.daysLeft + " days left (" + rd.expires.slice(0, 10) + ")" + (rd.registrar ? ", " + rd.registrar : ""));
    if (rd.transferLock) checks.lock = chk("pass", rd.statuses.filter((s) => /prohibited/i.test(s)).join(", "));
    else { checks.lock = chk("fail", "no transfer lock; status: " + (rd.statuses.join(", ") || "none")); raise("no_transfer_lock", "status: " + (rd.statuses.join(", ") || "none"), { registrar: rd.registrar }); }
  }
  // --- Certificate (newest CT entry)
  if (!obs.cert) checks.cert = chk("na", "CT not fetched");
  else if (obs.cert.error) checks.cert = chk("error", obs.cert.error);
  else {
    const nc = newestCert(obs.cert.rows || [], nowMs == null ? 0 : nowMs);
    const left = nc && nowMs != null ? certDaysLeft(nc.notAfter, nowMs) : null;
    if (!nc) checks.cert = chk("info", "no certificate found in CT logs (crt.sh and certspotter return nothing, or both were unavailable)");
    else if (left == null) checks.cert = chk("info", "newest cert not after " + nc.notAfter);
    else if (left < o.certWarnDays) { checks.cert = chk("warn", left + " days left (" + String(nc.notAfter).slice(0, 10) + ")"); raise("cert_expiring", left + " days left (not after " + String(nc.notAfter).slice(0, 10) + ")", { issuer: nc.issuer }); }
    else checks.cert = chk("pass", left + " days left (" + String(nc.notAfter).slice(0, 10) + ")");
  }
  const errors = Object.values(checks).filter((c) => c.status === "error").length;
  const graded = Object.values(checks).filter((c) => c.status !== "error" && c.status !== "na").length;
  const penalty = issues.reduce((s, i) => s + (SEV_PENALTY[ISSUES[i.id].severity] || 0), 0);
  const score = graded ? Math.max(0, 100 - penalty) : null;
  const row = {
    domain: d, role, roleLabel: MAILROLE[role], grade: letterGrade(score), score, errors, checkedAt: obs.at || null, checks,
    mail: {
      mx: realMx.map((m) => m.host).join(" "), nullMx, spf: spf.present ? spf.record : "", spfAll: spf.all || "", spfLookups: spfTree ? spfTree.count : null,
      spfComplete: spfTree ? spfTree.complete : null, dmarc: dm.present ? dm.record : "", dmarcPolicy: dm.present ? dm.policy : "", dmarcPct: dm.present ? dm.pct : null,
      mtaStsMode: mts.mode || (mts.present ? "?" : ""), tlsRpt: !!tlsRec, bimi: !!bimi,
    },
    rdap: rd && rd.ok ? { registrar: rd.registrar, expires: rd.expires, daysLeft: rd.daysLeft, statuses: rd.statuses, created: rd.created } : null,
  };
  return { row, issues };
}

// ---------------------------------------------------------------------------
// Snapshots and change diff
// ---------------------------------------------------------------------------
/** Compact snapshot of a result for storage and the next run's diff. */
export function snapshotOf(result) {
  const t = (result && result.tables) || {};
  const domains = {};
  for (const r of t.domains || []) domains[r.domain] = { grade: r.grade, checks: Object.fromEntries(Object.entries(r.checks || {}).map(([k, v]) => [k, v.status])) };
  const lookalikes = {};
  for (const l of t.lookalikes || []) if (l.status === "registered") lookalikes[l.domain] = { owner: l.owner, mx: !!l.mx, web: !!l.web };
  const takeover = (t.subdomains || []).filter((h) => h.severity).map((h) => h.host).sort();
  return { at: (result && result.meta && result.meta.now) || null, domains, lookalikes, takeover };
}

/** Changes between two snapshots: new failures, fixes, newly registered lookalikes, takeover changes. */
export function diffSnapshots(prev, curr) {
  const rows = [];
  if (!prev || !curr) return rows;
  const bad = (s) => s === "fail" || s === "warn";
  const good = (s) => s === "pass";
  for (const d of Object.keys(curr.domains || {}).sort()) {
    const a = (prev.domains || {})[d], b = curr.domains[d];
    if (!a) { rows.push({ kind: "new domain", domain: d, check: "", from: "", to: b.grade }); continue; }
    for (const k of Object.keys(b.checks || {}).sort()) {
      const x = (a.checks || {})[k], y = b.checks[k];
      if (!x || x === y) continue;
      if (good(x) && bad(y)) rows.push({ kind: "new failure", domain: d, check: k, from: x, to: y });
      else if (x === "warn" && y === "fail") rows.push({ kind: "new failure", domain: d, check: k, from: x, to: y });
      else if (bad(x) && good(y)) rows.push({ kind: "fixed", domain: d, check: k, from: x, to: y });
      else if (x === "fail" && y === "warn") rows.push({ kind: "improved", domain: d, check: k, from: x, to: y });
    }
    if (a.grade !== b.grade && a.grade !== "N/A" && b.grade !== "N/A") rows.push({ kind: "grade change", domain: d, check: "grade", from: a.grade, to: b.grade });
  }
  for (const d of Object.keys(prev.domains || {}).sort()) if (!(curr.domains || {})[d]) rows.push({ kind: "domain removed", domain: d, check: "", from: prev.domains[d].grade, to: "" });
  for (const l of Object.keys(curr.lookalikes || {}).sort()) if (!(prev.lookalikes || {})[l]) rows.push({ kind: "lookalike newly registered", domain: curr.lookalikes[l].owner, check: l, from: "", to: (curr.lookalikes[l].mx ? "MX " : "") + (curr.lookalikes[l].web ? "web" : "") });
  for (const l of Object.keys(prev.lookalikes || {}).sort()) if (!(curr.lookalikes || {})[l]) rows.push({ kind: "lookalike no longer resolves", domain: prev.lookalikes[l].owner, check: l, from: "registered", to: "" });
  const pt = new Set(prev.takeover || []), ct = new Set(curr.takeover || []);
  for (const h of [...ct].sort()) if (!pt.has(h)) rows.push({ kind: "new takeover candidate", domain: h, check: "subdomain", from: "", to: "candidate" });
  for (const h of [...pt].sort()) if (!ct.has(h)) rows.push({ kind: "takeover candidate resolved", domain: h, check: "subdomain", from: "candidate", to: "" });
  return rows;
}

// ---------------------------------------------------------------------------
// analyze
// ---------------------------------------------------------------------------
function normalizeDataset(ds) {
  if (Array.isArray(ds)) ds = { domains: ds };
  ds = ds && typeof ds === "object" ? ds : {};
  const domains = dedupeDomains((ds.domains || []).map((x) => (typeof x === "string" ? { domain: x } : x)).map((x) => ({ domain: cleanDomain(x && x.domain), sendsMail: x && x.sendsMail != null ? !!x.sendsMail : null, parked: !!(x && x.parked) })).filter((x) => x.domain));
  const hostMap = new Map();
  for (const h of ds.hosts || []) {
    const name = normName(typeof h === "string" ? h : h.host);
    if (!name) continue;
    const prev = hostMap.get(name);
    const v = typeof h === "string" ? { host: name, types: [], target: null, source: "list" } : { host: name, types: h.types || [], target: h.target ? normName(h.target) : null, source: h.source || "list" };
    hostMap.set(name, prev ? { ...prev, types: uniq([...prev.types, ...v.types]).sort(), target: prev.target || v.target } : v);
  }
  return {
    domains, hosts: [...hostMap.values()].sort((a, b) => cmp(a.host, b.host)),
    keywords: uniq((ds.keywords || []).map((k) => String(k).trim().toLowerCase()).filter(Boolean)).sort(),
    observations: ds.observations || {}, hostObs: ds.hostObs || {}, lookalikes: ds.lookalikes || {}, previous: ds.previous || null, at: ds.at || null,
  };
}

function resolveNow(o, ds) {
  if (o.now != null && !isNaN(Date.parse(o.now))) return Date.parse(o.now);
  if (ds.at && !isNaN(Date.parse(ds.at))) return Date.parse(ds.at);
  const ts = Object.values(ds.observations).map((x) => x && x.at).filter((t) => t && !isNaN(Date.parse(t))).sort();
  return ts.length ? Date.parse(ts[ts.length - 1]) : null;
}

/**
 * Analyze a portfolio. dataset = { domains, hosts, keywords, observations, hostObs,
 * lookalikes: { owner: { at, results: { candidate: { NS, A, MX, rdap } } } }, previous }.
 */
export function analyze(dataset, opts = {}, ctx) {
  const o = { ...DEFAULTS, ...opts };
  o.maxCandidates = Math.max(1, Math.min(LIMITS.maxCandidates, Number(o.maxCandidates) || DEFAULTS.maxCandidates));
  const ds = normalizeDataset(dataset);
  const nowMs = resolveNow(o, ds);
  const skipped = [];
  const groups = new Map(); // issue id -> { rows, assets }
  const push = (id, domain, detail, extra) => {
    const g = groups.get(id) || { rows: [], assets: new Map() };
    g.rows.push({ domain, detail, ...extra });
    if (!g.assets.has(domain)) g.assets.set(domain, { type: "DOMAIN", name: domain });
    groups.set(id, g);
  };
  if (nowMs == null) skipped.push({ check: "expiry, certificate and lookalike age", reason: "no reference date (pass opts.now or run live checks)" });
  const total = ds.domains.length + ds.hosts.length;
  let done = 0;
  // Domains
  const domainRows = [];
  const unchecked = [];
  for (const spec of ds.domains) {
    if (done % 50 === 0) ctx?.progress?.(done, total, "domains");
    done++;
    const obs = ds.observations[spec.domain];
    if (!obs) { unchecked.push(spec.domain); domainRows.push(gradeDomain(spec, null, o, nowMs).row); continue; }
    const { row, issues } = gradeDomain(spec, obs, o, nowMs);
    domainRows.push(row);
    for (const i of issues) push(i.id, spec.domain, i.detail, i.extra);
  }
  if (unchecked.length) skipped.push({ check: "live DNS checks", reason: unchecked.length + " domain(s) have no live results yet: " + unchecked.slice(0, 8).join(", ") + (unchecked.length > 8 ? ", ..." : "") });
  // Hosts (takeover)
  const hostRows = [];
  const hostFindings = [];
  for (const h of ds.hosts.slice(0, LIMITS.maxHosts)) {
    if (done % 200 === 0) ctx?.progress?.(done, total, "hosts");
    done++;
    const row = gradeHost(h, ds.hostObs[h.host]);
    hostRows.push(row);
    if (row.severity) {
      const fp = row.provider ? TAKEOVER_FINGERPRINTS.find((f) => f.provider === row.provider) : null;
      const base = row.provider ? ISSUES.takeover : ISSUES.dangling_cname;
      hostFindings.push({
        id: "takeover:" + row.host, title: (row.provider ? "Subdomain takeover candidate: " : "Dangling CNAME: ") + row.host,
        severity: row.severity, confidence: row.confidence, category: base.category,
        description: row.host + " -> " + row.target + ". " + row.signal + "." + (fp ? " " + fp.provider + " is classified '" + fp.status + "' for takeover in the public can-i-take-over-xyz knowledge." : "") +
          (row.severity === "high" && row.provider && !/fingerprint/.test(row.verdict) ? " NXDOMAIN shows the resource is gone; whether the name can be claimed depends on the provider's domain-verification rules." : ""),
        recommendation: base.recommendation, controls: base.controls,
        evidence: [{ host: row.host, source: row.source, target: row.target, liveStatus: row.liveStatus, provider: row.provider, providerStatus: row.providerStatus, signal: row.signal, verdict: row.verdict }],
        evidenceCount: 1, assets: [{ type: "DOMAIN", name: row.host, data: { target: row.target, provider: row.provider } }], tags: ["subdomain-takeover"],
      });
    }
  }
  if (ds.hosts.length > LIMITS.maxHosts) skipped.push({ check: "subdomain takeover", reason: "only the first " + LIMITS.maxHosts + " of " + ds.hosts.length + " hostnames were graded" });
  if (!ds.hosts.length) skipped.push({ check: "subdomain takeover", reason: "no hostnames supplied (add a zone export or a host list)" });
  if (hostRows.some((r) => /A\/AAAA only/.test(r.verdict))) skipped.push({ check: "dangling A records", reason: "A/AAAA records into cloud ranges are not checked: ownership of a cloud IP cannot be verified from outside" });
  // Lookalikes
  const owned = new Set(ds.domains.map((x) => x.domain));
  const lookRows = [];
  const lookFindings = new Map(); // key owner|class
  for (const owner of Object.keys(ds.lookalikes).sort()) {
    const L = ds.lookalikes[owner] || {};
    const results = L.results || {};
    const cands = generateLookalikes(owner, { keywords: ds.keywords, max: o.maxCandidates });
    const extra = Object.keys(results).filter((k) => !cands.some((c) => c.domain === k)).sort();
    for (const c of [...cands, ...extra.map((k) => ({ domain: k, display: k, kind: "checked earlier" }))]) {
      const g = owned.has(c.domain) ? { status: "owned" } : gradeLookalike(results[c.domain], nowMs, o);
      const row = { owner, domain: c.domain, display: c.display, kind: c.kind, status: g.status, mx: !!g.mx, web: !!g.web, mxHosts: (g.mxHosts || []).join(" "), addrs: (g.addrs || []).join(" "), created: g.created || "", ageDays: g.ageDays == null ? null : g.ageDays, registrar: g.registrar || "", newlyRegistered: !!g.newlyRegistered };
      lookRows.push(row);
      if (g.status !== "registered") continue;
      const cls = g.mx && g.newlyRegistered ? "lookalike_mx_new" : g.mx ? "lookalike_mx" : g.web ? "lookalike_web" : "lookalike_parked";
      const key = owner + "|" + cls;
      const f = lookFindings.get(key) || { owner, cls, rows: [] };
      f.rows.push(row);
      lookFindings.set(key, f);
    }
  }
  // Findings
  const findings = [];
  for (const [id, g] of [...groups].sort((a, b) => SEV_RANK[ISSUES[a[0]].severity] - SEV_RANK[ISSUES[b[0]].severity] || cmp(a[0], b[0]))) {
    const t = ISSUES[id];
    const rows = g.rows.sort((a, b) => cmp(a.domain, b.domain));
    const names = rows.map((r) => r.domain);
    findings.push({
      id: "domainguard:" + id, title: t.title, severity: t.severity, confidence: t.confidence, category: t.category,
      description: rows.length + " domain(s): " + names.slice(0, 6).join(", ") + (names.length > 6 ? ", ..." : "") + ". " + rows[0].domain + ": " + rows[0].detail + ".",
      recommendation: t.recommendation, controls: t.controls, evidence: rows.slice(0, 50), evidenceCount: rows.length,
      assets: [...g.assets.values()].slice(0, 50), tags: [t.category],
    });
  }
  findings.push(...hostFindings);
  for (const f of [...lookFindings.values()].sort((a, b) => SEV_RANK[ISSUES[a.cls].severity] - SEV_RANK[ISSUES[b.cls].severity] || cmp(a.owner, b.owner))) {
    const t = ISSUES[f.cls];
    const rows = f.rows.sort((a, b) => cmp(a.domain, b.domain));
    findings.push({
      id: "domainguard:" + f.cls + ":" + f.owner, title: t.title + " (" + f.owner + ")", severity: t.severity, confidence: t.confidence, category: t.category,
      description: rows.length + " lookalike(s) of " + f.owner + ": " + rows.slice(0, 6).map((r) => r.display + (r.ageDays != null ? " (" + r.ageDays + "d old)" : "")).join(", ") + (rows.length > 6 ? ", ..." : "") + ".",
      recommendation: t.recommendation, controls: t.controls,
      evidence: rows.slice(0, 50).map((r) => ({ lookalike: r.domain, unicode: r.display, kind: r.kind, mx: r.mxHosts, addresses: r.addrs, created: r.created, ageDays: r.ageDays, registrar: r.registrar })),
      evidenceCount: rows.length, assets: [{ type: "DOMAIN", name: f.owner }, ...rows.slice(0, 49).map((r) => ({ type: "DOMAIN", name: r.domain, data: { lookalikeOf: f.owner, kind: r.kind } }))], tags: ["lookalike"],
    });
  }
  findings.sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || cmp(a.category, b.category) || cmp(a.id, b.id));
  ctx?.progress?.(total, total, "done");
  // Summary / KPIs
  const gradeDist = {};
  for (const r of domainRows) gradeDist[r.grade] = (gradeDist[r.grade] || 0) + 1;
  const dmarcEval = domainRows.filter((r) => r.checks.dmarc && r.checks.dmarc.status !== "error" && r.checks.dmarc.status !== "na");
  const dmarcEnf = dmarcEval.filter((r) => (r.mail.dmarcPolicy === "reject" || r.mail.dmarcPolicy === "quarantine") && r.mail.dmarcPct === 100);
  const bySeverity = {};
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  const expiring = domainRows.filter((r) => r.rdap && r.rdap.daysLeft != null && r.rdap.daysLeft < o.expiryWarnDays).length;
  const result = {
    summary: {
      domains: domainRows.length, checked: domainRows.length - unchecked.length, grades: gradeDist, expiring30: expiring,
      dmarcEnforcingPct: dmarcEval.length ? Math.round((dmarcEnf.length / dmarcEval.length) * 100) : null, dmarcEvaluated: dmarcEval.length,
      takeoverCandidates: hostRows.filter((h) => h.severity).length, hosts: hostRows.length,
      lookalikesChecked: lookRows.filter((l) => l.status !== "unchecked" && l.status !== "owned").length,
      lookalikesRegistered: lookRows.filter((l) => l.status === "registered").length,
      findings: findings.length, bySeverity, errors: domainRows.reduce((s, r) => s + (r.errors || 0), 0),
    },
    findings,
    tables: { domains: domainRows, subdomains: hostRows, lookalikes: lookRows, changes: [] },
    skipped,
    meta: { tool: TOOL_ID, version: VERSION, now: nowMs == null ? null : new Date(nowMs).toISOString(), rows: domainRows.length, thresholds: { expiryCriticalDays: o.expiryCriticalDays, expiryWarnDays: o.expiryWarnDays, certWarnDays: o.certWarnDays, newlyRegisteredDays: o.newlyRegisteredDays, maxCandidates: o.maxCandidates, spfLookupLimit: o.spfLookupLimit } },
  };
  if (ds.previous) {
    result.tables.changes = diffSnapshots(ds.previous, snapshotOf(result));
    result.summary.changes = result.tables.changes.length;
    result.meta.previousAt = ds.previous.at || null;
  } else skipped.push({ check: "changes since previous run", reason: "no previous run stored for this workspace" });
  return result;
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
const FINDING_COLS = ["severity", "confidence", "category", "title", "description", "recommendation", "controls", "evidenceCount", "assets"];
const q = (v) => '"' + String(v == null ? "" : v).replace(/"/g, '""') + '"';

/** Findings as CSV with fixed columns. */
export function findingsToCsv(findings) {
  const body = (findings || []).map((f) => [
    f.severity, f.confidence, f.category, f.title, f.description, f.recommendation,
    (f.controls || []).map((c) => c.framework + " " + c.id).join("; "), f.evidenceCount != null ? f.evidenceCount : (f.evidence || []).length,
    (f.assets || []).map((a) => a.name).join(" "),
  ].map(q).join(","));
  return [FINDING_COLS.join(","), ...body].join("\n");
}

/** Lookalikes CSV (registered first) for blocklists and takedown requests. */
export function lookalikesToCsv(rows, { registeredOnly = false } = {}) {
  const cols = ["owner", "lookalike", "unicode", "kind", "status", "mx", "web", "mx_hosts", "addresses", "created", "age_days", "registrar"];
  const order = { registered: 0, error: 1, unregistered: 2, unchecked: 3, owned: 4 };
  const list = (rows || []).filter((r) => !registeredOnly || r.status === "registered").slice().sort((a, b) => (order[a.status] ?? 9) - (order[b.status] ?? 9) || cmp(a.owner, b.owner) || cmp(a.domain, b.domain));
  return [cols.join(","), ...list.map((r) => [r.owner, r.domain, r.display, r.kind, r.status, r.mx ? "yes" : "no", r.web ? "yes" : "no", r.mxHosts, r.addrs, r.created, r.ageDays == null ? "" : r.ageDays, r.registrar].map(q).join(","))].join("\n");
}

/** Exact DNS records to publish / remove, per domain, from a result. */
export function dnsFixList(result) {
  const out = ["Domain Guard - DNS fix list", "Generated from the run at " + ((result && result.meta && result.meta.now) || "unknown time") + ". Review every record before publishing.", ""];
  const t = (result && result.tables) || {};
  for (const r of t.domains || []) {
    const c = r.checks || {}, d = r.domain, lines = [];
    const bad = (k) => c[k] && (c[k].status === "fail" || c[k].status === "warn");
    if (r.role === "parked" && bad("parked")) {
      lines.push("; parked-domain lock-down (M3AAWG Protecting Parked Domains, RFC 7505)");
      lines.push(d + ".\t3600\tIN\tMX\t0 .");
      lines.push(d + '.\t3600\tIN\tTXT\t"v=spf1 -all"');
      lines.push("_dmarc." + d + '.\t3600\tIN\tTXT\t"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s"');
      lines.push("*._domainkey." + d + '.\t3600\tIN\tTXT\t"v=DKIM1; p="');
    } else if (r.role !== "parked") {
      if (c.dmarc && (c.dmarc.status === "fail" || c.dmarc.status === "warn")) {
        lines.push("; DMARC progression (RFC 7489): publish step 1, watch rua reports, then step 2 and 3");
        lines.push("_dmarc." + d + '.\t3600\tIN\tTXT\t"v=DMARC1; p=none; rua=mailto:dmarc-reports@' + d + '"   ; step 1 (monitor)');
        lines.push("_dmarc." + d + '.\t3600\tIN\tTXT\t"v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc-reports@' + d + '"   ; step 2');
        lines.push("_dmarc." + d + '.\t3600\tIN\tTXT\t"v=DMARC1; p=reject; rua=mailto:dmarc-reports@' + d + '"   ; step 3 (BOD 18-01 target)');
      }
      if (c.spf && c.spf.status === "fail" && !r.mail.spf) lines.push(d + '.\t3600\tIN\tTXT\t"v=spf1 <your senders: include:... ip4:...> -all"');
      if (c.spf && c.spf.status === "fail" && r.mail.spfLookups > 10) lines.push("; SPF uses " + r.mail.spfLookups + " lookups: flatten includes into ip4:/ip6: ranges or move senders to subdomains (limit 10)");
      if (c.mtasts && c.mtasts.status !== "pass" && c.mtasts.status !== "na") {
        lines.push("; MTA-STS (RFC 8461): TXT + policy file at https://mta-sts." + d + "/.well-known/mta-sts.txt");
        lines.push("_mta-sts." + d + '.\t3600\tIN\tTXT\t"v=STSv1; id=' + ((result.meta.now || "").slice(0, 10).replace(/-/g, "") || "1") + '01"');
        lines.push(";   policy file:  version: STSv1 / mode: testing (then enforce) / " + (r.mail.mx ? r.mail.mx.split(" ").map((h) => "mx: " + h).join(" / ") : "mx: <mx host>") + " / max_age: 604800");
      }
      if (c.tlsrpt && c.tlsrpt.status === "warn") lines.push("_smtp._tls." + d + '.\t3600\tIN\tTXT\t"v=TLSRPTv1; rua=mailto:tlsrpt@' + d + '"');
    }
    if (c.caa && c.caa.status === "warn") {
      lines.push(d + '.\t3600\tIN\tCAA\t0 issue "<your-ca-domain, e.g. the issuer of your current certificate>"');
      lines.push(d + '.\t3600\tIN\tCAA\t0 iodef "mailto:security@' + d + '"');
    }
    if (c.dnssec && c.dnssec.status === "warn" && /No DS/.test(c.dnssec.detail)) lines.push("; DNSSEC: sign the zone at your DNS provider, then publish the DS record it gives you at the registrar");
    if (c.lock && c.lock.status === "fail") lines.push("; registrar: enable transfer lock (clientTransferProhibited) and delete/update locks");
    if (c.expiry && (c.expiry.status === "fail" || c.expiry.status === "warn")) lines.push("; registrar: renew now (" + c.expiry.detail + ") and enable auto-renew");
    if (lines.length) out.push("== " + d + " (" + r.roleLabel + ", grade " + r.grade + ")", ...lines, "");
  }
  const hosts = (t.subdomains || []).filter((h) => h.severity);
  if (hosts.length) {
    out.push("== Dangling records to delete (or re-claim the resource)");
    for (const h of hosts) out.push("; " + h.verdict + " - " + h.signal, "; DELETE  " + h.host + ".\tIN\tCNAME\t" + h.target + ".");
    out.push("");
  }
  if (out.length === 3) out.push("No DNS changes suggested by this run.");
  return out.join("\n");
}

/** Plain-text summary for the TXT export. */
export function summaryText(result) {
  const s = result.summary;
  const lines = [
    "Domain Guard summary", "Reference time: " + (result.meta.now || "n/a"),
    "Domains: " + s.domains + " (" + s.checked + " checked), grades " + Object.entries(s.grades).sort().map(([g, n]) => g + "=" + n).join(" "),
    "Expiring < 30 days: " + s.expiring30, "DMARC enforcing: " + (s.dmarcEnforcingPct == null ? "n/a" : s.dmarcEnforcingPct + "% of " + s.dmarcEvaluated),
    "Takeover candidates: " + s.takeoverCandidates + " of " + s.hosts + " hosts", "Registered lookalikes: " + s.lookalikesRegistered + " of " + s.lookalikesChecked + " checked",
    "Findings: " + s.findings + " " + JSON.stringify(s.bySeverity), "",
  ];
  for (const f of result.findings) lines.push("[" + f.severity.toUpperCase() + "] " + f.title + " (" + f.evidenceCount + ")", "  " + f.description, "  Fix: " + f.recommendation, "  Controls: " + f.controls.map((c) => c.framework + " " + c.id).join("; "), "");
  if (result.skipped.length) lines.push("Skipped:", ...result.skipped.map((k) => "- " + k.check + ": " + k.reason));
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Synthetic example (precomputed answers; Load example makes no network calls)
// ---------------------------------------------------------------------------
/** Build a dns.google-shaped JSON answer. */
export function dohJson(name, type, datas = [], { status = 0, ad = false, ttl = 300, cname = null } = {}) {
  const t = RR[type];
  const qn = normName(name) + ".";
  const Answer = [];
  if (cname) for (const [from, to] of cname) Answer.push({ name: normName(from) + ".", type: RR.CNAME, TTL: ttl, data: normName(to) + "." });
  for (const d of datas) Answer.push({ name: cname ? normName(cname[cname.length - 1][1]) + "." : qn, type: t, TTL: ttl, data: d });
  const j = { Status: status, TC: false, RD: true, RA: true, AD: !!ad, CD: false, Question: [{ name: qn, type: t }] };
  if (Answer.length) j.Answer = Answer;
  if (status === 3 || (!Answer.length && status === 0)) j.Authority = [{ name: "test.darknode.ai.", type: 6, TTL: 1800, data: "ns1.test.darknode.ai. hostmaster.test.darknode.ai. 2026101601 7200 3600 1209600 300" }];
  return j;
}
function rdapJson(domain, { created, expires, statuses, registrar = "Test Registrar A (synthetic)" }) {
  return {
    objectClassName: "domain", ldhName: domain.toUpperCase(), handle: "SYN-" + domain.length,
    links: [{ value: "https://rdap.test.darknode.ai/domain/" + domain, rel: "self", href: "https://rdap.test.darknode.ai/domain/" + domain, type: "application/rdap+json" }],
    status: statuses,
    entities: [{ objectClassName: "entity", handle: "9999", roles: ["registrar"], publicIds: [{ type: "IANA Registrar ID", identifier: "9999" }], vcardArray: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", registrar]]] }],
    events: [{ eventAction: "registration", eventDate: created }, { eventAction: "expiration", eventDate: expires }, { eventAction: "last update of RDAP database", eventDate: "2026-10-15T22:01:00Z" }],
    nameservers: [{ objectClassName: "nameserver", ldhName: "NS1.TEST.DARKNODE.AI" }, { objectClassName: "nameserver", ldhName: "NS2.TEST.DARKNODE.AI" }],
    secureDNS: { delegationSigned: false }, rdapConformance: ["rdap_level_0", "icann_rdap_technical_implementation_guide_0", "icann_rdap_response_profile_0"],
  };
}

const EXAMPLE_ZONE = `;; Domain:     darknode-acq.test.darknode.ai.
;; Exported (synthetic) zone of an acquired company
$ORIGIN darknode-acq.test.darknode.ai.
$TTL 3600
@\tIN\tSOA\tns1.test.darknode.ai. hostmaster.darknode-acq.test.darknode.ai. (
\t\t2026101601 ; serial
\t\t7200 3600 1209600 300 )
\tIN\tNS\tns1.test.darknode.ai.
\tIN\tNS\tns2.test.darknode.ai.
@\tIN\tMX\t10 mx1.darknode-acq.test.darknode.ai.
@\tIN\tTXT\t"v=spf1 ip4:198.51.100.25 -all"
www\t300\tIN\tA\t203.0.113.40
mx1\tIN\tA\t198.51.100.25
careers\tIN\tCNAME\tdn-careers-old.azurewebsites.net.
assets\tIN\tCNAME\tdn-assets-legacy.s3-website-us-east-1.amazonaws.com.
docs\tIN\tCNAME\tdarknode-acq.github.io.
shop 600 IN CNAME dn-old-shop.cdn.test.darknode.ai. ; cf_tags=cf-proxied:false
`;

/** Small seeded SYNTHETIC dataset: 6 domains under test.darknode.ai with precomputed answers. */
export function exampleDataset(seed = 7) {
  void seed;
  const now = "2026-10-16T00:00:00Z";
  const at = "2026-10-16T00:00:00Z";
  const NS2 = ["ns1.test.darknode.ai.", "ns2.test.darknode.ai."];
  const nsGood = ["ns-212.awsdns-26.com.", "ns-1650.awsdns-14.co.uk.", "a.ns-dual.test.darknode.ai.", "b.ns-dual.test.darknode.ai."];
  const caa = ['0 issue "letsencrypt.org"', '0 iodef "mailto:security@darknode.test.darknode.ai"'];
  const rows = (notAfter) => [{ issuer_name: "C=US, O=Let's Encrypt, CN=R11", not_before: "2026-08-01T00:00:00", not_after: notAfter, name_value: "synthetic" }];
  const nsHosts = (list) => Object.fromEntries(list.map((h) => [normName(h), dohJson(h, "A", ["192.0.2.53"])]));
  const domainObs = (d, x) => {
    const wild = "dmg-probe-7f3a." + d;
    const dns = {
      NS: dohJson(d, "NS", x.ns || NS2, { ad: !!x.ds }), NS_CF: dohJson(d, "NS", x.nsCf || x.ns || NS2, { ad: !!x.ds }),
      SOA: dohJson(d, "SOA", ["ns1.test.darknode.ai. hostmaster." + d + ". 2026101601 7200 3600 1209600 300"], { ad: !!x.ds }),
      MX: dohJson(d, "MX", x.mx || [], { ad: !!x.ds }), TXT: dohJson(d, "TXT", x.txt || [], { ad: !!x.ds }),
      DMARC: x.dmarc ? dohJson("_dmarc." + d, "TXT", x.dmarc, { ad: !!x.ds }) : dohJson("_dmarc." + d, "TXT", [], { status: 3 }),
      MTASTS: x.mtasts ? dohJson("_mta-sts." + d, "TXT", x.mtasts) : dohJson("_mta-sts." + d, "TXT", [], { status: 3 }),
      TLSRPT: x.tlsrpt ? dohJson("_smtp._tls." + d, "TXT", x.tlsrpt) : dohJson("_smtp._tls." + d, "TXT", [], { status: 3 }),
      BIMI: dohJson("default._bimi." + d, "TXT", [], { status: 3 }),
      DS: dohJson(d, "DS", x.ds || [], { ad: !!x.ds }), CAA: dohJson(d, "CAA", x.caa || [], { ad: !!x.ds }),
      A: dohJson(d, "A", ["203.0.113.10"], { ad: !!x.ds }), WILDCARD: x.wildcard ? dohJson(wild, "A", ["203.0.113.10"]) : dohJson(wild, "A", [], { status: 3 }),
    };
    return { at, dns, wildcardName: wild, nsHosts: nsHosts(x.ns || NS2), spf: x.spfIncludes || {}, mtaStsPolicy: x.policy || undefined, rdap: x.rdap, cert: { rows: rows(x.certNotAfter || "2026-12-20T00:00:00") } };
  };
  const D = {
    main: "darknode.test.darknode.ai", eu: "darknode-eu.test.darknode.ai", parked: "darknode-parked.test.darknode.ai",
    promo: "darknode-promo.test.darknode.ai", acq: "darknode-acq.test.darknode.ai", hold: "darknode-hold.test.darknode.ai",
  };
  const lock = ["client delete prohibited", "client transfer prohibited", "client update prohibited"];
  const inc = (d, txt) => dohJson(d, "TXT", [txt]);
  const observations = {
    [D.main]: domainObs(D.main, {
      ns: nsGood, mx: ["10 mx1.darknode.test.darknode.ai.", "20 mx2.darknode.test.darknode.ai."], txt: ['"v=spf1 include:_spf.darknode.test.darknode.ai -all"'],
      spfIncludes: { "_spf.darknode.test.darknode.ai": inc("_spf.darknode.test.darknode.ai", '"v=spf1 ip4:198.51.100.0/27 ip6:2001:db8:10::/48 -all"') },
      dmarc: ['"v=DMARC1; p=reject; rua=mailto:dmarc@darknode.test.darknode.ai; ruf=mailto:dmarc-f@darknode.test.darknode.ai"'],
      mtasts: ['"v=STSv1; id=2026090101"'], tlsrpt: ['"v=TLSRPTv1; rua=mailto:tlsrpt@darknode.test.darknode.ai"'],
      policy: { status: 200, body: "version: STSv1\nmode: enforce\nmx: mx1.darknode.test.darknode.ai\nmx: mx2.darknode.test.darknode.ai\nmax_age: 604800\n" },
      ds: ["2371 13 2 1F987CC6583E92DF0890718C42A3C08D2B0E5C9A3E4E1E9B8A3C2D1F0E9D8C7B"], caa,
      rdap: rdapJson(D.main, { created: "2014-03-02T10:00:00Z", expires: "2029-03-02T10:00:00Z", statuses: lock }),
    }),
    [D.eu]: domainObs(D.eu, {
      mx: ["10 mx1.darknode.test.darknode.ai."],
      txt: ['"v=spf1 include:_spf1.darknode-eu.test.darknode.ai include:_spf2.darknode-eu.test.darknode.ai include:mailer.mail.test.darknode.ai ~all"'],
      spfIncludes: {
        "_spf1.darknode-eu.test.darknode.ai": inc("_spf1.darknode-eu.test.darknode.ai", '"v=spf1 a mx include:crm.mail.test.darknode.ai include:hr.mail.test.darknode.ai ~all"'),
        "_spf2.darknode-eu.test.darknode.ai": inc("_spf2.darknode-eu.test.darknode.ai", '"v=spf1 include:news.mail.test.darknode.ai include:tickets.mail.test.darknode.ai exists:%{i}.rbl.test.darknode.ai ~all"'),
        "mailer.mail.test.darknode.ai": inc("mailer.mail.test.darknode.ai", '"v=spf1 include:pool-a.mail.test.darknode.ai include:pool-b.mail.test.darknode.ai ~all"'),
        "crm.mail.test.darknode.ai": inc("crm.mail.test.darknode.ai", '"v=spf1 ip4:203.0.113.64/26 ~all"'),
        "hr.mail.test.darknode.ai": inc("hr.mail.test.darknode.ai", '"v=spf1 ip4:203.0.113.128/26 ~all"'),
        "news.mail.test.darknode.ai": inc("news.mail.test.darknode.ai", '"v=spf1 ip4:198.51.100.128/25 ~all"'),
        "tickets.mail.test.darknode.ai": dohJson("tickets.mail.test.darknode.ai", "TXT", ['"google-site-verification=synthetic"']),
        "pool-a.mail.test.darknode.ai": inc("pool-a.mail.test.darknode.ai", '"v=spf1 a mx ip4:192.0.2.0/25 ~all"'),
        "pool-b.mail.test.darknode.ai": inc("pool-b.mail.test.darknode.ai", '"v=spf1 a ip4:192.0.2.128/25 ~all"'),
      },
      dmarc: ['"v=DMARC1; p=none; pct=50; rua=mailto:dmarc@darknode.test.darknode.ai"'],
      rdap: rdapJson(D.eu, { created: "2019-05-11T09:00:00Z", expires: "2027-05-11T09:00:00Z", statuses: lock }),
    }),
    [D.parked]: domainObs(D.parked, {
      rdap: rdapJson(D.parked, { created: "2021-01-20T12:00:00Z", expires: "2027-01-20T12:00:00Z", statuses: lock }), wildcard: true,
    }),
    [D.promo]: domainObs(D.promo, {
      mx: ["10 mx1.darknode.test.darknode.ai."], txt: ['"v=spf1 include:_spf.darknode.test.darknode.ai -all"'],
      spfIncludes: { "_spf.darknode.test.darknode.ai": inc("_spf.darknode.test.darknode.ai", '"v=spf1 ip4:198.51.100.0/27 ip6:2001:db8:10::/48 -all"') },
      dmarc: ['"v=DMARC1; p=quarantine; rua=mailto:dmarc@darknode.test.darknode.ai"'],
      mtasts: ['"v=STSv1; id=2026070101"'], tlsrpt: ['"v=TLSRPTv1; rua=mailto:tlsrpt@darknode.test.darknode.ai"'],
      policy: { status: 200, body: "version: STSv1\nmode: testing\nmx: mx1.darknode.test.darknode.ai\nmax_age: 86400\n" }, caa,
      rdap: rdapJson(D.promo, { created: "2023-10-21T08:00:00Z", expires: "2026-10-21T08:00:00Z", statuses: ["active"] }), certNotAfter: "2026-10-26T00:00:00",
    }),
    [D.acq]: domainObs(D.acq, {
      ns: ["ns1.test.darknode.ai.", "ns2.test.darknode.ai."], nsCf: ["ns1.test.darknode.ai.", "ns2.test.darknode.ai."],
      mx: ["10 mx1.darknode-acq.test.darknode.ai."], txt: ['"v=spf1 ip4:198.51.100.25 -all"'],
      rdap: rdapJson(D.acq, { created: "2012-06-30T00:00:00Z", expires: "2027-06-30T00:00:00Z", statuses: ["client transfer prohibited"] }),
    }),
    [D.hold]: domainObs(D.hold, {
      mx: ["0 ."], txt: ['"v=spf1 -all"'], dmarc: ['"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s"'], caa,
      rdap: rdapJson(D.hold, { created: "2020-02-02T00:00:00Z", expires: "2028-02-02T00:00:00Z", statuses: lock }),
    }),
  };
  const zone = parseBindZone(EXAMPLE_ZONE);
  const hosts = hostsFromRecords(zone.records);
  const hostObs = {
    "careers.darknode-acq.test.darknode.ai": { A: dohJson("careers.darknode-acq.test.darknode.ai", "A", [], { status: 3, cname: [["careers.darknode-acq.test.darknode.ai", "dn-careers-old.azurewebsites.net"]] }) },
    "assets.darknode-acq.test.darknode.ai": {
      A: dohJson("assets.darknode-acq.test.darknode.ai", "A", ["192.0.2.80"], { cname: [["assets.darknode-acq.test.darknode.ai", "dn-assets-legacy.s3-website-us-east-1.amazonaws.com"]] }),
      http: { status: 404, body: "404 Not Found\nCode: NoSuchBucket\nMessage: The specified bucket does not exist\nBucketName: assets.darknode-acq.test.darknode.ai\nRequestId: SYNTHETIC0001" },
    },
    "docs.darknode-acq.test.darknode.ai": {
      A: dohJson("docs.darknode-acq.test.darknode.ai", "A", ["192.0.2.153"], { cname: [["docs.darknode-acq.test.darknode.ai", "darknode-acq.github.io"]] }),
      http: { status: 200, body: "Darknode docs (synthetic) - welcome" },
    },
    "shop.darknode-acq.test.darknode.ai": { A: dohJson("shop.darknode-acq.test.darknode.ai", "A", [], { status: 3, cname: [["shop.darknode-acq.test.darknode.ai", "dn-old-shop.cdn.test.darknode.ai"]] }) },
    "www.darknode-acq.test.darknode.ai": { A: dohJson("www.darknode-acq.test.darknode.ai", "A", ["203.0.113.40"]) },
    "mx1.darknode-acq.test.darknode.ai": { A: dohJson("mx1.darknode-acq.test.darknode.ai", "A", ["198.51.100.25"]) },
  };
  const la = (d, { ns = true, mx = [], a = [], created }) => ({
    NS: ns ? dohJson(d, "NS", ["ns1.parking.test.darknode.ai."]) : dohJson(d, "NS", [], { status: 3 }),
    A: ns ? dohJson(d, "A", a, {}) : dohJson(d, "A", [], { status: 3 }),
    ...(ns ? { MX: dohJson(d, "MX", mx), rdap: rdapJson(d, { created, expires: "2027-10-01T00:00:00Z", statuses: ["client transfer prohibited"], registrar: "Test Registrar B (synthetic)" }) } : {}),
  });
  const lookalikes = {
    [D.main]: {
      at,
      results: {
        "darnode.test.darknode.ai": la("darnode.test.darknode.ai", { mx: ["10 mail.darnode.test.darknode.ai."], a: ["198.51.100.77"], created: "2026-10-04T13:12:00Z" }),
        "darknode-login.test.darknode.ai": la("darknode-login.test.darknode.ai", { a: ["203.0.113.199"], created: "2026-06-02T00:00:00Z" }),
        "darkn0de.test.darknode.ai": la("darkn0de.test.darknode.ai", { created: "2025-01-15T00:00:00Z" }),
        "clarknode.test.darknode.ai": la("clarknode.test.darknode.ai", { ns: false }),
        "draknode.test.darknode.ai": la("draknode.test.darknode.ai", { ns: false }),
        "darknoed.test.darknode.ai": la("darknoed.test.darknode.ai", { ns: false }),
        "darknode-sso.test.darknode.ai": la("darknode-sso.test.darknode.ai", { ns: false }),
      },
    },
  };
  const previous = {
    at: "2026-10-09T00:00:00.000Z",
    domains: {
      [D.main]: { grade: "A", checks: { dmarc: "pass", spf: "pass", mtasts: "pass" } },
      [D.eu]: { grade: "D", checks: { dmarc: "fail", spf: "fail" } },
      [D.parked]: { grade: "D", checks: { parked: "fail" } },
      [D.promo]: { grade: "B", checks: { expiry: "pass", lock: "pass", cert: "pass" } },
      [D.acq]: { grade: "D", checks: { dmarc: "fail" } },
      [D.hold]: { grade: "B", checks: { caa: "warn" } },
    },
    lookalikes: { "darkn0de.test.darknode.ai": { owner: D.main, mx: false, web: false } },
    takeover: ["careers.darknode-acq.test.darknode.ai"],
  };
  return {
    label: "synthetic example (not real data)", now,
    domainsText: [D.main + " mail", D.eu + " mail", D.parked + " parked", D.promo, D.acq, D.hold + " parked"].join("\n"),
    zoneFile: { name: "darknode-acq.zone", text: EXAMPLE_ZONE },
    dataset: {
      domains: [
        { domain: D.main, sendsMail: true }, { domain: D.eu, sendsMail: true }, { domain: D.parked, parked: true },
        { domain: D.promo }, { domain: D.acq }, { domain: D.hold, parked: true },
      ],
      hosts, keywords: ["darknode"], observations, hostObs, lookalikes, previous, at,
    },
    rows: zone.records,
  };
}

/** Deterministic self-check of the engine. */
export function selfTest() {
  const tests = [];
  const t = (name, fn) => { let pass = false; try { pass = !!fn(); } catch (_) { pass = false; } tests.push({ name, pass }); };
  const ex = exampleDataset();
  const r = analyze(ex.dataset, { now: ex.now });
  const has = (id) => r.findings.some((f) => f.id === "domainguard:" + id);
  t("punycode bucher vector", () => punycodeEncode("bücher") === "bcher-kva");
  t("parked domain without lock-down flagged", () => has("parked_unlocked"));
  t("expiring domain is critical", () => has("expiry_critical"));
  t("Azure dangling CNAME is a takeover candidate", () => r.findings.some((f) => f.id === "takeover:careers.darknode-acq.test.darknode.ai" && f.severity === "high"));
  t("S3 NoSuchBucket fingerprint is critical", () => r.findings.some((f) => f.id === "takeover:assets.darknode-acq.test.darknode.ai" && f.severity === "critical"));
  t("new lookalike with MX is high", () => r.findings.some((f) => f.id.startsWith("domainguard:lookalike_mx_new") && f.severity === "high"));
  t("SPF nested includes exceed 10", () => has("spf_permerror"));
  t("deterministic", () => JSON.stringify(analyze(ex.dataset, { now: ex.now })) === JSON.stringify(r));
  t("empty input yields no findings", () => analyze({}, {}).findings.length === 0);
  return { pass: tests.every((x) => x.pass), tests };
}
