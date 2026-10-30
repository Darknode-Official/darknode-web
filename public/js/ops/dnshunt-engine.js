// DNS Hunt engine (dnshunt). Reads DNS resolver query logs (Zeek dns.log TSV/JSON,
// BIND query log, Windows DNS debug log, dnsmasq/Pi-hole, Unbound, Route 53
// Resolver query logs, Cisco Umbrella DNS CSV, or any CSV via column mapping) and
// hunts for patterns defenders look for in DNS telemetry: algorithmically generated
// names, DNS tunnelling, periodic beaconing, NXDOMAIN storms, lookalikes of the
// organisation's own domains, encrypted-DNS bypass and resolver bypass.
// Pure: no DOM, no network; deterministic. Safe to run inside a Worker.
// Logs are streamed line by line and folded into bounded per-entity aggregates.

import { sniff, iterCsv, iterNdjson, iterJson, findColumn, sniffDelimiter } from "../ingest/parse.js";
import { compileCidrs, isInternalIp, isIp } from "./log-hunter-engine.js";
import { MULTI_SUFFIXES } from "../exposure/domainguard-engine.js";

// Public multi-label suffixes (subset). The domainguard list also holds a private suffix for its
// own example; it is left out here so subdomains of an organisation fold into one domain.
const SUFFIXES = MULTI_SUFFIXES.filter((x) => x !== "test.darknode.ai");

export const TOOL_ID = "dnshunt";
export const VERSION = "1.0.0";

/** Column aliases for CSV/JSON input that needs mapping (case-insensitive). */
export const COLUMNS = {
  timestamp: ["timestamp", "ts", "time", "datetime", "date", "query_timestamp", "eventtime", "event_time"],
  client: ["client", "client_ip", "clientip", "src", "src_ip", "srcaddr", "source_ip", "source ip", "id.orig_h", "internal ip"],
  query: ["query", "query_name", "qname", "domain", "name", "question", "fqdn", "query name"],
  qtype: ["qtype", "qtype_name", "query_type", "querytype", "record type", "type"],
  rcode: ["rcode", "rcode_name", "response_code", "responsecode", "response code", "result"],
  answers: ["answers", "answer", "rdata", "resolved_ip", "response"],
  server: ["server", "resolver", "id.resp_h", "dst", "dst_ip", "destination_ip", "server_ip"],
  user: ["user", "username", "identity", "most granular identity", "user_name"],
};

/** Tunable thresholds; the UI renders these as the settings panel. */
export const DEFAULTS = {
  dgaMinLength: 10,        // shortest registrable label scored for DGA traits
  dgaScoreMin: 4,          // of 6 traits (see dgaTraits) before a name counts as DGA-like
  dgaClientMin: 10,        // distinct DGA-like failed names from one client before it is reported
  tunnelMinSubdomains: 200,// distinct subdomains under one domain before tunnelling is considered
  tunnelAvgLen: 40,        // mean query length (chars) that adds tunnelling weight
  tunnelEncodedRatio: 0.5, // share of encoded-looking labels that adds tunnelling weight
  beaconMinEvents: 20,     // minimum queries from one client to one domain for periodicity
  beaconMaxCv: 0.15,       // coefficient of variation of intervals at or below = periodic
  beaconMinIntervalSec: 10,
  beaconMaxIntervalSec: 21600,
  beaconPopularShare: 0.3, // domains queried by this share of clients (5+ clients) are treated as common
  nxMin: 200,              // NXDOMAIN answers to one client before an NXDOMAIN storm is reported
  nxRatio: 0.4,            // and this share of its answers are NXDOMAIN
  baselineDays: 7,         // first days of the log used as the "known domains" baseline
  internalCidrs: "",       // blank = RFC 1918 + RFC 4193 + loopback/link-local
  ownDomains: "",          // one per line; used for lookalike checks and exclusions
  allowDomains: "",        // one per line; never reported (suffix match)
  approvedResolvers: "",   // one IP per line; blank = any internal IP is an approved resolver
  assumeYear: 0,           // year for syslog-style timestamps without a year (0 = from opts.now, else 2026)
};

export const LIMITS = { maxDomains: 200000, maxSubPerDomain: 20000, maxPairs: 150000, maxTsPerPair: 4000, maxClients: 100000, evidence: 50 };

// Suffixes of services that legitimately encode data in many unique subdomains
// (reputation lookups, CDNs, reverse DNS). Editable via allowDomains; shown in the UI.
export const HIGH_CARDINALITY_DEFAULTS = [
  "in-addr.arpa", "ip6.arpa", "spamhaus.org", "spamcop.net", "sorbs.net", "barracudacentral.org", "surbl.org", "uribl.com",
  "sophosxl.net", "mcafee.com", "trendmicro.com", "akadns.net", "akamaiedge.net", "akamai.net", "cloudfront.net",
  "amazonaws.com", "azureedge.net", "googleusercontent.com", "e5.sk", "local",
];

// Public DNS-over-HTTPS / DNS-over-TLS endpoints. A lookup of one of these through the
// company resolver usually means a browser or app is about to send DNS around it.
export const ENCRYPTED_DNS_HOSTS = [
  "dns.google", "dns.google.com", "8888.google", "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "chrome.cloudflare-dns.com",
  "one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com", "security.cloudflare-dns.com", "family.cloudflare-dns.com",
  "dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net", "doh.opendns.com", "doh.familyshield.opendns.com",
  "dns.nextdns.io", "doh.cleanbrowsing.org", "dns.adguard.com", "dns.adguard-dns.com", "dns-unfiltered.adguard.com",
  "doh.mullvad.net", "dns.mullvad.net", "doh.dns.sb", "dns.controld.com", "freedns.controld.com", "doh.libredns.gr",
];
// Firefox checks this canary name; NXDOMAIN from the company resolver disables its default DoH.
export const DOH_CANARY = "use-application-dns.net";

const C = {
  dga: [{ framework: "MITRE", id: "T1568.002" }, { framework: "CIS", id: "v8 9.2" }, { framework: "NIST-800-53", id: "SI-4" }],
  tunnel: [{ framework: "MITRE", id: "T1071.004" }, { framework: "MITRE", id: "T1048.003" }, { framework: "CIS", id: "v8 13.3" }, { framework: "NIST-800-53", id: "SC-7" }],
  beacon: [{ framework: "MITRE", id: "T1071.004" }, { framework: "NIST-800-53", id: "SI-4" }],
  nx: [{ framework: "MITRE", id: "T1568.002" }, { framework: "NIST-800-53", id: "SI-4" }],
  look: [{ framework: "MITRE", id: "T1583.001" }, { framework: "MITRE", id: "T1566" }, { framework: "CIS", id: "v8 9.2" }],
  doh: [{ framework: "MITRE", id: "T1572" }, { framework: "CIS", id: "v8 9.2" }, { framework: "NIST-800-53", id: "SC-7" }],
  resolver: [{ framework: "CIS", id: "v8 9.2" }, { framework: "CIS", id: "v8 8.6" }, { framework: "NIST-800-53", id: "SC-7" }],
  intel: [{ framework: "MITRE", id: "T1071.004" }, { framework: "NIST-800-53", id: "SI-4" }, { framework: "CIS", id: "v8 9.2" }],
  newdom: [{ framework: "CIS", id: "v8 8.6" }, { framework: "NIST-800-53", id: "SI-4" }],
};

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/** Lines of a string without building one giant array. Strips \r. */
export function* iterLines(text) {
  const t = String(text || "");
  let i = 0;
  while (i < t.length) {
    let j = t.indexOf("\n", i);
    if (j < 0) j = t.length;
    let line = t.slice(i, j);
    if (line.endsWith("\r")) line = line.slice(0, -1);
    yield line;
    i = j + 1;
  }
}

/** Lower-case, strip trailing dot and surrounding whitespace. */
export function normName(s) {
  let n = String(s == null ? "" : s).trim().toLowerCase();
  while (n.endsWith(".")) n = n.slice(0, -1);
  return n;
}

function listOpt(v) {
  if (Array.isArray(v)) return v.map((x) => normName(x)).filter(Boolean);
  return String(v || "").split(/[\n,]+/).map((x) => normName(x)).filter(Boolean);
}

/** True when name equals or is a subdomain of any suffix in list. */
export function suffixMatch(name, list) {
  for (const s of list) if (name === s || name.endsWith("." + s)) return true;
  return false;
}

/** Registrable domain (eTLD+1, embedded suffix subset) or the name itself for single labels. */
export function regDomain(name) {
  const n = normName(name);
  if (!n || !n.includes(".")) return n;
  if (n.endsWith(".arpa")) return n.split(".").slice(-3).join(".");
  if (isIp(n)) return n;
  const parts = n.split(".");
  const suf = SUFFIXES.find((x) => n.endsWith("." + x));
  const keep = suf ? suf.split(".").length + 1 : 2;
  return parts.length <= keep ? n : parts.slice(-keep).join(".");
}

/** Shannon entropy in bits per character: H = -sum(p_i * log2 p_i). */
export function entropy(s) {
  const str = String(s || "");
  if (!str) return 0;
  const f = new Map();
  for (const ch of str) f.set(ch, (f.get(ch) || 0) + 1);
  let h = 0;
  for (const c of f.values()) { const p = c / str.length; h -= p * Math.log2(p); }
  return h;
}

// The 200 most frequent English letter pairs. Human-chosen names reuse these heavily;
// algorithmically generated labels mostly do not.
const COMMON_BIGRAMS = new Set((
  "th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve co me de hi ri ro ic ne ea ra ce " +
  "li ch ll be ma si om ur ca el ta la ns di fo ho pe ec pr no ct us ac ot il tr ly nc et ut ss so rs un lo wa ge ie wh ee wi em " +
  "ad ol rt po we na ul ni ts mo ow pa im mi ai sh ir su id os iv ia am fi ci vi pl ig tu ev ld ry mp fe bl ab gh ty op wo sa ay " +
  "ex ke fr oo av ag if ap gr od bo sp rd do uc bu ei ov by rm ep tt oc fa ef cu rn sc gi da yo cr cl du ga qu ue ff ba ey ls va " +
  "um pp ua up lu go ht ru ug ds lt pi rc rr eg au ck ew mu br bi pt ak pu ui rg ib tl ny ki rk ys ob mm fu ph og ms ye ud mb ip"
).split(" "));

const VOWELS = new Set(["a", "e", "i", "o", "u", "y"]);

/**
 * DGA traits of one label (letters/digits only, hyphens removed). Each trait is one point:
 *  1. entropy >= 3.3 bits/char         2. common-bigram share < 0.45
 *  3. vowel share of letters < 0.25    4. longest consonant run >= 5
 *  5. digits 15-60% mixed into 5+ letters   6. length >= 16
 * The score is the count of traits present (0-6). Documented in the UI help.
 */
export function dgaTraits(label) {
  const s = String(label || "").toLowerCase().replace(/[^a-z0-9]/g, "");
  const letters = s.replace(/[0-9]/g, "");
  const digits = s.length - letters.length;
  let pairs = 0, common = 0;
  for (let i = 0; i + 1 < letters.length; i++) { pairs++; if (COMMON_BIGRAMS.has(letters.slice(i, i + 2))) common++; }
  let vowels = 0, run = 0, maxRun = 0;
  for (const ch of letters) {
    if (VOWELS.has(ch)) { vowels++; run = 0; } else { run++; if (run > maxRun) maxRun = run; }
  }
  const h = entropy(s);
  const bigram = pairs ? common / pairs : 1;
  const vowelShare = letters.length ? vowels / letters.length : 1;
  const digitShare = s.length ? digits / s.length : 0;
  const traits = [];
  if (h >= 3.3) traits.push("entropy");
  if (bigram < 0.45) traits.push("rare letter pairs");
  if (vowelShare < 0.25) traits.push("few vowels");
  if (maxRun >= 5) traits.push("long consonant run");
  if (digitShare >= 0.15 && digitShare <= 0.6 && letters.length >= 5) traits.push("mixed digits");
  if (s.length >= 16) traits.push("long label");
  return { label: s, length: s.length, entropy: round(h, 2), bigram: round(bigram, 2), vowelShare: round(vowelShare, 2), digitShare: round(digitShare, 2), maxConsonantRun: maxRun, score: traits.length, traits };
}

/** The label scored for DGA traits: the left-most label of the registrable domain. */
export function dgaLabel(reg) {
  const first = String(reg || "").split(".")[0] || "";
  return first.startsWith("xn--") ? "" : first;
}

/**
 * Encoded-looking label: hex (16+), base32 (16+, a-z2-7 with digits present), or a long
 * high-entropy token (24+ chars, entropy >= 3.8). Used for tunnelling weight only.
 */
export function looksEncoded(label) {
  const l = String(label || "").toLowerCase();
  if (l.length >= 16 && /^[0-9a-f]+$/.test(l) && /[0-9]/.test(l) && /[a-f]/.test(l)) return "hex";
  if (l.length >= 16 && /^[a-z2-7]+=*$/.test(l) && /[2-7]/.test(l)) return "base32";
  if (l.length >= 24 && /^[a-z0-9_-]+$/.test(l) && entropy(l) >= 3.8) return "high-entropy";
  return "";
}

/** RFC 3492 Punycode decode of one label body (without "xn--"). Returns null on bad input. */
export function punycodeDecode(input) {
  const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
  const s = String(input || "");
  const out = [];
  let b = s.lastIndexOf("-");
  if (b < 0) b = 0;
  for (let j = 0; j < b; j++) { if (s.charCodeAt(j) >= 0x80) return null; out.push(s.charCodeAt(j)); }
  const adapt = (delta, numPoints, first) => {
    let k = 0;
    delta = first ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    while (delta > ((base - tMin) * tMax) >> 1) { delta = Math.floor(delta / (base - tMin)); k += base; }
    return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew));
  };
  const digit = (c) => (c >= 48 && c <= 57 ? c - 22 : c >= 65 && c <= 90 ? c - 65 : c >= 97 && c <= 122 ? c - 97 : base);
  let n = 128, i = 0, bias = 72;
  for (let idx = b > 0 ? b + 1 : 0; idx < s.length;) {
    const oldi = i;
    for (let w = 1, k = base; ; k += base) {
      if (idx >= s.length) return null;
      const d = digit(s.charCodeAt(idx++));
      if (d >= base) return null;
      i += d * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (d < t) break;
      w *= base - t;
      if (w > 1e9) return null;
    }
    bias = adapt(i - oldi, out.length + 1, oldi === 0);
    n += Math.floor(i / (out.length + 1));
    i %= out.length + 1;
    if (n > 0x10ffff) return null;
    out.splice(i++, 0, n);
  }
  return String.fromCodePoint(...out);
}

/** Unicode form of a name with xn-- labels decoded (labels that fail stay as-is). */
export function toUnicodeName(name) {
  return String(name || "").split(".").map((l) => (l.startsWith("xn--") ? punycodeDecode(l.slice(4)) ?? l : l)).join(".");
}

// Characters commonly swapped in lookalike names, folded to one canonical letter.
const HOMOGLYPH = [["rn", "m"], ["vv", "w"], ["cl", "d"], ["0", "o"], ["1", "l"], ["i", "l"], ["3", "e"], ["5", "s"], ["4", "a"], ["7", "t"], ["8", "b"], ["9", "g"], ["$", "s"]];
// Unicode confusables seen in IDN lookalikes (Cyrillic/Greek/Latin-extended) to ASCII.
const CONFUSABLE = { "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ο": "o", "α": "a", "ν": "v", "ρ": "p", "τ": "t", "κ": "k", "ı": "i", "à": "a", "á": "a", "â": "a", "ä": "a", "å": "a", "è": "e", "é": "e", "ê": "e", "ë": "e", "ì": "i", "í": "i", "î": "i", "ï": "i", "ò": "o", "ó": "o", "ô": "o", "ö": "o", "ù": "u", "ú": "u", "û": "u", "ü": "u", "ç": "c", "ñ": "n" };

/** Fold a label to a canonical skeleton so visually similar labels compare equal. */
export function skeleton(label) {
  let s = [...String(label || "").toLowerCase()].map((ch) => CONFUSABLE[ch] || ch).join("");
  for (const [a, b] of HOMOGLYPH) s = s.split(a).join(b);
  return s.replace(/-/g, "");
}

/** Damerau-Levenshtein (optimal string alignment) distance, capped at max+1. */
export function editDistance(a, b, max = 3) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const d = [];
  for (let i = 0; i <= a.length; i++) { d[i] = [i]; }
  for (let j = 0; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  }
  return Math.min(d[a.length][b.length], max + 1);
}

/**
 * Compare a queried registrable domain against the organisation's own domains.
 * Returns { own, kind } for the closest match or null. Kinds: "homoglyph", "edit-1",
 * "edit-2", "other TLD", "contains brand", "IDN".
 */
export function lookalikeOf(reg, own) {
  if (!reg || !own.length || own.includes(reg)) return null; // a second own domain (example.net next to example.com) is not a lookalike
  const uni = toUnicodeName(reg);
  const label = uni.split(".")[0];
  const tld = reg.split(".").slice(1).join(".");
  for (const o of own) {
    if (reg === o) return null;
    const ol = o.split(".")[0];
    const otld = o.split(".").slice(1).join(".");
    if (ol.length < 4) continue;
    if (label === ol && tld !== otld) return { own: o, kind: "other TLD" };
    if (reg.includes("xn--") && skeleton(label) === skeleton(ol)) return { own: o, kind: "IDN" };
    if (label !== ol && skeleton(label) === skeleton(ol)) return { own: o, kind: "homoglyph" };
    const dist = editDistance(label, ol, 2);
    if (dist === 1 && ol.length >= 5) return { own: o, kind: "edit-1" };
    if (dist === 2 && ol.length >= 8) return { own: o, kind: "edit-2" };
    if (label !== ol && label.includes(ol) && ol.length >= 5) return { own: o, kind: "contains brand" };
  }
  return null;
}

function round(n, d) { const f = 10 ** d; return Math.round(n * f) / f; }

// ---------------------------------------------------------------------------
// Formats. Each parser yields normalized events:
//   { kind: "q" | "r", ts: ms|null, client, query, qtype, rcode, answers: [], server, user }
// kind "q" = a client query (rcode filled when the format logs it on the same line);
// kind "r" = a response line that only carries the result code (Windows debug, dnsmasq).
// ---------------------------------------------------------------------------

export const FORMAT_LABELS = {
  "zeek-tsv": "Zeek dns.log (TSV)",
  "zeek-json": "Zeek dns.log (JSON)",
  "bind": "BIND query log",
  "windns": "Windows DNS debug log",
  "dnsmasq": "dnsmasq / Pi-hole log",
  "unbound": "Unbound query log",
  "route53": "Route 53 Resolver query log",
  "umbrella": "Cisco Umbrella DNS log (CSV)",
  "csv": "CSV (column mapping)",
  "json": "JSON (column mapping)",
  "unknown": "Not recognised",
};

const RE_BIND = /client (?:@\S+ )?([0-9a-fA-F.:]+)#\d+(?: \(([^)]*)\))?: (?:view [^:]+: )?query: (\S+) (\S+) (\S+)/;
const RE_BIND_TS = /^(\d{2})-([A-Za-z]{3})-(\d{4}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?/;
const RE_WIN = /^(\d{1,2}\/\d{1,2}\/\d{4}) (\d{1,2}:\d{2}:\d{2})(?: ([AP]M))? +\S+ +PACKET +\S+ +(UDP|TCP) +(Rcv|Snd) +(\S+) +\S+ +(R?) ?Q \[([^\]]*)\] +(\S+) +(\S+)/;
const RE_DNSMASQ = /^(\w{3}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (?:\S+ )?dnsmasq\[\d+\]: (?:\d+ [0-9a-fA-F.:]+\/\d+ )?(query\[([A-Za-z0-9]+)\] (\S+) from (\S+)|(reply|cached|config|gravity blocked|regex blacklisted|exactly blacklisted|blacklisted) (\S+) is (\S+))/;
const RE_UNBOUND = /(?:^\[(\d+)\] )?(?:^(\w{3}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) \S+ )?unbound(?:\[\d+:\d+\])?:? (?:\[\d+:\d+\] )?info: ([0-9a-fA-F.:]+) (\S+) ([A-Z0-9]+) IN(?: ([A-Z]+))?/;
const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
// Umbrella DNS log field order (all versions; later versions append columns): timestamp, most
// granular identity, identities, internal ip, external ip, action, query type, response code, domain,
// categories. The optional header row spells "Query Type" / "Response Code"; compared without spaces.
const UMBRELLA_HEAD = ["timestamp", "mostgranularidentity", "identities", "internalip", "externalip", "action", "querytype", "responsecode", "domain", "categories"];

/** Detect a file's format from its head. Returns { format, confidence, label, headers? }. */
export function detectFormat(text, name = "") {
  const head = String(text || "").slice(0, 65536);
  const out = (format, confidence, extra = {}) => ({ format, confidence, label: FORMAT_LABELS[format], ...extra });
  if (!head.trim()) return out("unknown", "low");
  if (/^#separator /m.test(head) && /^#fields\t.*\bquery\b/m.test(head)) return out("zeek-tsv", "high");
  const firstLines = [];
  for (const l of iterLines(head)) { if (l.trim()) firstLines.push(l); if (firstLines.length >= 20) break; }
  const t0 = firstLines[0] ? firstLines[0].trim() : "";
  if (t0.startsWith("{") || t0.startsWith("[")) {
    let obj = null;
    try { for (const r of (t0.startsWith("[") ? iterJson(head.length < 65536 ? head : head + "]") : iterNdjson(firstLines.join("\n")))) { obj = r; break; } } catch (_) { obj = null; }
    if (obj && typeof obj === "object") {
      if ("query_name" in obj && "srcaddr" in obj) return out("route53", "high");
      if ("id.orig_h" in obj && "query" in obj) return out("zeek-json", "high");
      return out("json", "low", { headers: Object.keys(obj).sort() });
    }
  }
  let bind = 0, win = 0, dm = 0, ub = 0;
  for (const l of firstLines.length ? scanSample(head) : []) {
    if (RE_BIND.test(l)) bind++;
    else if (RE_WIN.test(l)) win++;
    else if (RE_DNSMASQ.test(l)) dm++;
    else if (RE_UNBOUND.test(l)) ub++;
  }
  const best = Math.max(bind, win, dm, ub);
  if (best > 0) {
    const fmt = best === bind ? "bind" : best === win ? "windns" : best === dm ? "dnsmasq" : "unbound";
    return out(fmt, "high");
  }
  // Delimited text: Umbrella (with or without header) or generic CSV.
  const delim = sniffDelimiter(head) || ",";
  let first = null;
  for (const row of iterCsv(firstLines.slice(0, 2).join("\n"), { delimiter: delim, header: false })) { first = row; break; }
  if (first) {
    const lower = first.map((h) => String(h).toLowerCase().replace(/\s+/g, ""));
    if (UMBRELLA_HEAD.every((h, i) => lower[i] === h)) return out("umbrella", "high", { header: true });
    if (first.length >= 10 && /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(String(first[0]).trim()) && /^(allowed|blocked|proxied)$/i.test(String(first[5]).trim()) && /^\d+ \([A-Z0-9]+\)$/.test(String(first[6]).trim())) {
      return out("umbrella", "medium", { header: false });
    }
    const headers = first.map((h) => String(h).trim());
    const map = guessMapping(headers);
    const conf = map.query && map.client && map.timestamp ? "high" : map.query ? "medium" : "low";
    return out("csv", conf, { headers, delimiter: delim, mapping: map });
  }
  return out("unknown", "low");
}

function scanSample(head) {
  const lines = [];
  for (const l of iterLines(head)) { if (l.trim() && !l.startsWith("#")) lines.push(l); if (lines.length >= 200) break; }
  return lines;
}

/** Best-effort column mapping from header names (used when confidence is not high). */
export function guessMapping(headers) {
  const map = {};
  for (const [key, aliases] of Object.entries(COLUMNS)) {
    const h = findColumn(headers, aliases);
    if (h) map[key] = h;
  }
  return map;
}

function syslogTs(mon, day, hh, mm, ss, year) {
  const m = MONTHS[String(mon).toLowerCase()];
  if (m == null) return null;
  return Date.UTC(year, m, +day, +hh, +mm, +ss);
}

function isoTs(s) {
  if (s == null || s === "") return null;
  const str = String(s).trim();
  if (/^\d+(\.\d+)?$/.test(str)) {
    const n = Number(str);
    return n > 1e14 ? Math.floor(n / 1000) : n > 1e11 ? Math.floor(n) : Math.floor(n * 1000);
  }
  const m = str.match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d+))?\s*(Z|[+-]\d{2}:?\d{2})?$/);
  if (m) {
    const ms = m[7] ? Math.round(Number("0." + m[7]) * 1000) : 0;
    let off = 0;
    if (m[8] && m[8] !== "Z") { const z = m[8].match(/([+-])(\d{2}):?(\d{2})/); off = (z[1] === "-" ? -1 : 1) * (+z[2] * 60 + +z[3]) * 60000; }
    return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6], ms) - off;
  }
  const w = str.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4}),? (\d{1,2}):(\d{2}):(\d{2})(?: ?([AP])M)?$/i);
  if (w) {
    let h = +w[4];
    if (w[7]) { const pm = w[7].toUpperCase() === "P"; if (pm && h < 12) h += 12; if (!pm && h === 12) h = 0; }
    let mo = +w[1], d = +w[2]; if (mo > 12 && d <= 12) [mo, d] = [d, mo]; if (mo < 1 || mo > 12 || d < 1 || d > new Date(Date.UTC(+w[3], mo, 0)).getUTCDate()) return null; // 25/12/2024 is day-first; reject instead of rolling over
    return Date.UTC(+w[3], mo - 1, d, h, +w[5], +w[6]);
  }
  return null;
}

/** "(3)www(6)google(3)com(0)" -> "www.google.com" (Windows DNS debug log question format). */
export function winName(s) {
  const parts = [];
  const re = /\((\d+)\)([^()]*)/g;
  let m;
  while ((m = re.exec(String(s || "")))) if (m[2]) parts.push(m[2]);
  return parts.length ? parts.join(".") : normName(s);
}

function splitAnswers(v) {
  if (v == null || v === "" || v === "-") return [];
  if (Array.isArray(v)) return v.map((a) => (a && typeof a === "object" ? String(a.Rdata ?? a.rdata ?? a.data ?? "") : String(a))).filter(Boolean);
  return String(v).split(/[,;| ]+/).map((x) => x.trim()).filter((x) => x && x !== "-");
}

const ev = (kind, ts, client, query, qtype, rcode, answers, server, user) => ({
  kind, ts: Number.isFinite(ts) ? ts : null, client: String(client || "").trim(), query: normName(query),
  qtype: String(qtype || "").toUpperCase(), rcode: String(rcode || "").toUpperCase(), answers: answers || [], server: String(server || "").trim(), user: String(user || "").trim(),
});

/**
 * Stream normalized events from one file. det = detectFormat() result (optionally with a
 * user mapping in det.mapping). year = assumed year for syslog timestamps.
 */
export function* iterEvents(text, det, year) {
  const fmt = det.format;
  if (fmt === "zeek-tsv") {
    let fields = null, sep = "\t", unset = "-";
    for (const line of iterLines(text)) {
      if (!line) continue;
      if (line.startsWith("#")) {
        if (line.startsWith("#separator ")) sep = line.slice(11).replace(/\\x([0-9a-f]{2})/gi, (m, h) => String.fromCharCode(parseInt(h, 16)));
        else if (line.startsWith("#unset_field")) unset = line.split(sep)[1] || "-";
        else if (line.startsWith("#fields")) fields = line.split(sep).slice(1);
        continue;
      }
      if (!fields) continue;
      const v = line.split(sep);
      const r = {};
      for (let i = 0; i < fields.length; i++) r[fields[i]] = v[i] === unset ? "" : v[i];
      yield ev("q", isoTs(r.ts), r["id.orig_h"], r.query, r.qtype_name, r.rcode_name, splitAnswers(r.answers), r["id.resp_h"], "");
    }
    return;
  }
  if (fmt === "zeek-json" || fmt === "route53" || fmt === "json") {
    const t0 = String(text).trimStart();
    const it = t0.startsWith("[") ? iterJson(text) : iterNdjson(text);
    for (const r of it) {
      if (!r || typeof r !== "object") continue;
      if (fmt === "zeek-json") yield ev("q", isoTs(r.ts), r["id.orig_h"], r.query, r.qtype_name, r.rcode_name, splitAnswers(r.answers), r["id.resp_h"], "");
      else if (fmt === "route53") yield ev("q", isoTs(r.query_timestamp), r.srcaddr, r.query_name, r.query_type, r.rcode, splitAnswers(r.answers), "", (r.srcids && (r.srcids.instance || r.srcids.resolver_endpoint)) || "");
      else yield mapped(r, det.mapping || {});
    }
    return;
  }
  if (fmt === "bind") {
    for (const line of iterLines(text)) {
      const m = RE_BIND.exec(line);
      if (!m) continue;
      const t = RE_BIND_TS.exec(line);
      const ts = t ? Date.UTC(+t[3], MONTHS[t[2].toLowerCase()], +t[1], +t[4], +t[5], +t[6], t[7] ? Math.round(Number("0." + t[7]) * 1000) : 0) : null;
      yield ev("q", ts, m[1], m[3], m[5], "", [], "", "");
    }
    return;
  }
  if (fmt === "windns") {
    for (const line of iterLines(text)) {
      const m = RE_WIN.exec(line);
      if (!m) continue;
      const ts = isoTs(m[1] + " " + m[2] + (m[3] ? " " + m[3] : ""));
      const isResp = m[7] === "R";
      const flags = m[8].trim().split(/\s+/);
      const rcode = flags[flags.length - 1];
      const name = winName(m[10]);
      if (m[5] === "Rcv" && !isResp) yield ev("q", ts, m[6], name, m[9], "", [], "", "");
      else if (m[5] === "Snd" && isResp) yield ev("r", ts, m[6], name, m[9], /^[A-Z]+$/.test(rcode) ? rcode : "", [], "", "");
    }
    return;
  }
  if (fmt === "dnsmasq") {
    // dnsmasq logs replies without the client; attribute each reply to the client that most
    // recently asked for that name (bounded map), which is how Pi-hole's own UI pairs them.
    const lastAsker = new Map();
    for (const line of iterLines(text)) {
      const m = RE_DNSMASQ.exec(line);
      if (!m) continue;
      const ts = syslogTs(m[1], m[2], m[3], m[4], m[5], year);
      if (m[7]) {
        const name = normName(m[8]);
        lastAsker.set(name, m[9]);
        if (lastAsker.size > 50000) lastAsker.delete(lastAsker.keys().next().value);
        yield ev("q", ts, m[9], name, m[7], "", [], "", "");
      } else {
        const name = normName(m[11]);
        const client = lastAsker.get(name);
        if (!client) continue;
        const val = m[12];
        const rcode = val === "NXDOMAIN" || val === "SERVFAIL" ? val : "NOERROR";
        yield ev("r", ts, client, name, "", rcode, isIp(val) ? [val] : [], "", "");
      }
    }
    return;
  }
  if (fmt === "unbound") {
    for (const line of iterLines(text)) {
      const m = RE_UNBOUND.exec(line);
      if (!m) continue;
      const ts = m[1] ? Number(m[1]) * 1000 : m[2] ? syslogTs(m[2], m[3], m[4], m[5], m[6], year) : null;
      yield ev("q", ts, m[7], m[8], m[9], m[10] || "", [], "", "");
    }
    return;
  }
  if (fmt === "umbrella") {
    let first = true;
    for (const row of iterCsv(text, { delimiter: ",", header: false })) {
      if (first && det.header) { first = false; continue; }
      first = false;
      if (!row || row.length < 9) continue;
      const qt = String(row[6] || "").match(/\(([A-Z0-9]+)\)/);
      const user = String(row[1] || "").trim();
      yield ev("q", isoTs(row[0]), row[3], row[8], qt ? qt[1] : row[6], row[7], [], "", user);
    }
    return;
  }
  if (fmt === "csv") {
    for (const r of iterCsv(text, { delimiter: det.delimiter || sniffDelimiter(String(text).slice(0, 65536)) || ",", header: true })) yield mapped(r, det.mapping || {});
  }
}

function mapped(r, map) {
  const g = (k) => (map[k] ? r[map[k]] : undefined);
  const q = g("query");
  const rc = String(g("rcode") ?? "").trim();
  return ev("q", isoTs(g("timestamp")), g("client"), q, g("qtype"), /^\d+$/.test(rc) ? RCODE_NUM[rc] || rc : rc, splitAnswers(g("answers")), g("server"), g("user"));
}
const RCODE_NUM = { 0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED" };

/**
 * Detect formats for the UI without materialising events. Accepts a string or
 * [{name, text}]. Returns { files: [{ name, format, label, confidence, headers?, mapping?, sample }] }.
 */
export function parseInput(input) {
  const list = Array.isArray(input) ? input : [{ name: "input", text: String(input || "") }];
  const files = [];
  for (const f of list) {
    const text = String(f.text || "");
    const det = detectFormat(text, f.name);
    const sample = [];
    if (det.format !== "unknown" && (det.confidence !== "low")) {
      for (const e of iterEvents(text, det, 2026)) { if (e.query) sample.push(e); if (sample.length >= 5) break; }
    }
    files.push({ name: f.name || "input", ...det, bytes: text.length, sample });
  }
  return { files, rows: files.flatMap((f) => f.sample) };
}

// ---------------------------------------------------------------------------
// Aggregation. Everything is folded into bounded maps so multi-million-line logs fit.
// ---------------------------------------------------------------------------

const iso = (ts) => (ts == null ? "" : new Date(ts).toISOString().replace(".000Z", "Z"));
const evRow = (e) => ({ time: iso(e.ts), client: e.client, query: e.query, type: e.qtype, result: e.rcode, answers: e.answers.slice(0, 4).join(" ") });
const addCapped = (set, v, cap) => { if (set.size < cap) set.add(v); };
const pushCapped = (arr, v, cap = LIMITS.evidence) => { if (arr.length < cap) arr.push(v); };

function newAgg() {
  return {
    events: 0, queries: 0, responses: 0, minTs: null, maxTs: null,
    has: { ts: false, rcode: false, answers: false, server: false, user: false },
    domains: new Map(), clients: new Map(), pairs: new Map(), pairsCapped: false, domainsCapped: false,
    encrypted: new Map(), external: new Map(), resolvers: new Set(), intel: new Map(), canary: { q: 0, nx: 0, ok: 0, clients: new Set(), rows: [] },
  };
}

function domainEntry(A, reg) {
  let d = A.domains.get(reg);
  if (!d) {
    if (A.domains.size >= LIMITS.maxDomains) { A.domainsCapped = true; return null; }
    d = { q: 0, nx: 0, ok: 0, clients: new Set(), clientCount: 0, subs: new Set(), subCapped: false, lenSum: 0, maxLabel: 0, encoded: 0, txtNull: 0, first: null, last: null, rows: [], nxRows: [] };
    A.domains.set(reg, d);
  }
  return d;
}

function clientEntry(A, c) {
  let x = A.clients.get(c);
  if (!x) {
    if (A.clients.size >= LIMITS.maxClients) return null;
    x = { q: 0, resp: 0, nx: 0, nxDomains: new Set(), users: new Set(), first: null, last: null };
    A.clients.set(c, x);
  }
  return x;
}

function foldEvent(A, e, ctxOpts) {
  A.events++;
  if (!e.query) return;
  if (e.ts != null) { A.has.ts = true; if (A.minTs == null || e.ts < A.minTs) A.minTs = e.ts; if (A.maxTs == null || e.ts > A.maxTs) A.maxTs = e.ts; }
  if (e.rcode) A.has.rcode = true;
  if (e.answers.length) A.has.answers = true;
  if (e.server) A.has.server = true;
  if (e.user) A.has.user = true;
  const reg = regDomain(e.query);
  const d = domainEntry(A, reg);
  const c = e.client ? clientEntry(A, e.client) : null;
  if (e.kind === "q") {
    A.queries++;
    if (d) {
      d.q++;
      if (e.client) { if (d.clients.size < 2000) d.clients.add(e.client); }
      if (e.ts != null) { if (d.first == null || e.ts < d.first) d.first = e.ts; if (d.last == null || e.ts > d.last) d.last = e.ts; }
      if (e.query !== reg && e.query.endsWith("." + reg)) {
        const sub = e.query.slice(0, -(reg.length + 1));
        if (d.subs.size < LIMITS.maxSubPerDomain) {
          if (!d.subs.has(sub)) {
            d.subs.add(sub);
            const labels = sub.split(".");
            let longest = "";
            for (const l of labels) if (l.length > longest.length) longest = l;
            if (longest.length > d.maxLabel) d.maxLabel = longest.length;
            if (looksEncoded(longest)) d.encoded++;
            d.lenSum += e.query.length;
          }
        } else d.subCapped = true;
      }
      if (e.qtype === "TXT" || e.qtype === "NULL" || e.qtype === "10" || e.qtype === "16") d.txtNull++;
      pushCapped(d.rows, e);
    }
    if (c) {
      c.q++;
      if (e.user) addCapped(c.users, e.user, 5);
      if (e.ts != null) { if (c.first == null || e.ts < c.first) c.first = e.ts; if (c.last == null || e.ts > c.last) c.last = e.ts; }
    }
    // Per (client, domain) timestamps for periodicity.
    if (e.client && e.ts != null) {
      const key = e.client + "\u0001" + reg;
      let p = A.pairs.get(key);
      if (!p) {
        if (A.pairs.size >= LIMITS.maxPairs) A.pairsCapped = true;
        else { p = []; A.pairs.set(key, p); }
      }
      if (p && p.length < LIMITS.maxTsPerPair) p.push(e.ts);
    }
    if (suffixMatch(e.query, ENCRYPTED_DNS_HOSTS)) {
      let x = A.encrypted.get(e.query);
      if (!x) { x = { q: 0, clients: new Set(), rows: [] }; A.encrypted.set(e.query, x); }
      x.q++; if (e.client) addCapped(x.clients, e.client, 5000); pushCapped(x.rows, e);
    }
    if (e.query === DOH_CANARY || e.query.endsWith("." + DOH_CANARY)) {
      A.canary.q++; if (e.client) addCapped(A.canary.clients, e.client, 5000); pushCapped(A.canary.rows, e);
      if (e.rcode === "NXDOMAIN") A.canary.nx++; else if (e.rcode) A.canary.ok++;
    }
    if (e.server && e.client) {
      const approved = ctxOpts.approved.length ? ctxOpts.approved.includes(e.server) : isInternalIp(e.server, ctxOpts.cidrs);
      if (approved) addCapped(A.resolvers, e.server, 5000);
      else if (e.server !== e.client) {
        let x = A.external.get(e.client);
        if (!x) { x = { q: 0, servers: new Map(), rows: [] }; A.external.set(e.client, x); }
        x.q++; x.servers.set(e.server, (x.servers.get(e.server) || 0) + 1); pushCapped(x.rows, e);
      }
    }
  } else A.responses++;
  if (e.rcode) {
    if (d) { if (e.rcode === "NXDOMAIN") { d.nx++; pushCapped(d.nxRows, e); } else if (e.rcode === "NOERROR") d.ok++; }
    if (c) { c.resp++; if (e.rcode === "NXDOMAIN") { c.nx++; addCapped(c.nxDomains, reg, 5000); } }
  }
  if (e.answers.length && ctxOpts.intel.size) {
    for (const a of e.answers) {
      if (!ctxOpts.intel.has(a)) continue;
      let x = A.intel.get(a);
      if (!x) { x = { q: 0, domains: new Set(), clients: new Set(), rows: [] }; A.intel.set(a, x); }
      x.q++; addCapped(x.domains, e.query, 200); if (e.client) addCapped(x.clients, e.client, 2000); pushCapped(x.rows, e);
    }
  }
}

/** Periodicity of sorted timestamps. Intervals under 1 s (resolver retries) are merged. */
export function periodicity(tss) {
  const ts = [...tss].sort((a, b) => a - b);
  const gaps = [];
  for (let i = 1; i < ts.length; i++) { const g = (ts[i] - ts[i - 1]) / 1000; if (g >= 1) gaps.push(g); }
  if (gaps.length < 2) return null;
  // Trim the top and bottom 10% so a single sleep/wake gap does not hide a steady rhythm.
  const s = [...gaps].sort((a, b) => a - b);
  const cut = Math.floor(s.length * 0.1);
  const core = s.slice(cut, s.length - cut || s.length);
  const mean = core.reduce((a, b) => a + b, 0) / core.length;
  const sd = Math.sqrt(core.reduce((a, b) => a + (b - mean) ** 2, 0) / core.length);
  return { intervals: gaps.length, medianSec: round(s[Math.floor(s.length / 2)], 1), meanSec: round(mean, 1), cv: round(mean ? sd / mean : 0, 3), spanSec: round((ts[ts.length - 1] - ts[0]) / 1000, 0) };
}

function finding(f) {
  const ev = f.evidence || [];
  return {
    title: f.title, severity: f.severity, confidence: f.confidence, category: f.category,
    description: f.description, recommendation: f.recommendation, controls: f.controls,
    evidence: ev.slice(0, LIMITS.evidence).map((e) => (e && e.kind ? evRow(e) : e)), evidenceCount: f.evidenceCount ?? ev.length,
    assets: f.assets, tags: f.tags || [],
  };
}

/**
 * Analyze DNS logs. dataset = { files: [{ name, text, format?, mapping? }] } or { events: [...] }
 * (events already normalized, used by tests). opts overrides DEFAULTS and may carry:
 *   maliciousIps: string[] (from the mirrored /data/feeds/malicious-ips.json), knownDomains: string[]
 *   (a baseline list from an earlier period), now: ISO.
 */
export function analyze(dataset, opts = {}, ctx) {
  const o = { ...DEFAULTS, ...opts };
  const year = Number(o.assumeYear) || (o.now ? new Date(o.now).getUTCFullYear() : 2026);
  const cidrList = String(o.internalCidrs || "").split(/[\n,]+/).map((s) => s.trim()).filter(Boolean);
  const ctxOpts = {
    cidrs: compileCidrs(cidrList.length ? cidrList : ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128"]),
    approved: String(o.approvedResolvers || "").split(/[\n,]+/).map((s) => s.trim()).filter(Boolean),
    intel: new Set((o.maliciousIps || []).map((x) => String(typeof x === "object" && x ? x.ip : x).trim()).filter(Boolean)),
  };
  const own = listOpt(o.ownDomains).map(regDomain);
  const allow = listOpt(o.allowDomains);
  const quiet = [...allow, ...HIGH_CARDINALITY_DEFAULTS];
  const A = newAgg();
  const files = [];
  const skipped = [];

  const ds = dataset && typeof dataset === "object" ? dataset : {};
  if (Array.isArray(ds.events)) {
    for (const e of ds.events) foldEvent(A, ev(e.kind || "q", e.ts ?? isoTs(e.time), e.client, e.query, e.qtype, e.rcode, e.answers || [], e.server, e.user), ctxOpts);
  }
  const list = Array.isArray(ds.files) ? ds.files : Array.isArray(dataset) ? dataset : [];
  const totalBytes = list.reduce((a, f) => a + String(f.text || "").length, 0) || 1;
  let doneBytes = 0;
  for (const f of list) {
    const text = String(f.text || "");
    const det = f.format ? { ...detectFormat(text, f.name), format: f.format, mapping: f.mapping || guessMapping(f.headers || []) } : detectFormat(text, f.name);
    if (f.mapping) det.mapping = f.mapping;
    const before = A.events;
    if (det.format === "unknown" || ((det.format === "csv" || det.format === "json") && !(det.mapping && det.mapping.query))) {
      skipped.push({ check: "file " + (f.name || "input"), reason: det.format === "unknown" ? "format not recognised" : "no query/domain column mapped" });
      files.push({ name: f.name || "input", format: det.format, label: det.label, confidence: det.confidence, events: 0 });
      doneBytes += text.length;
      continue;
    }
    let i = 0;
    for (const e of iterEvents(text, det, year)) {
      foldEvent(A, e, ctxOpts);
      if (++i % 5000 === 0) ctx?.progress?.(Math.min(doneBytes + Math.round(text.length * 0.5), totalBytes), totalBytes, "Reading " + (f.name || "input"));
    }
    doneBytes += text.length;
    ctx?.progress?.(doneBytes, totalBytes, "Read " + (f.name || "input"));
    files.push({ name: f.name || "input", format: det.format, label: det.label, confidence: det.confidence, events: A.events - before });
  }
  return buildReport(A, o, { own, allow, quiet, files, skipped, ctxOpts }, ctx);
}

function buildReport(A, o, X, ctx) {
  const { own, allow, quiet, files, skipped } = X;
  const findings = [];
  const tables = {};
  const totalClients = A.clients.size;
  const isOwn = (reg) => own.some((d) => reg === d || reg.endsWith("." + d));
  const isAllowed = (name) => suffixMatch(name, allow);
  const domains = [...A.domains.entries()].sort((a, b) => b[1].q - a[1].q || cmp(a[0], b[0]));
  ctx?.progress?.(1, 1, "Scoring");

  // --- DGA-like names -----------------------------------------------------
  const dga = new Map();
  for (const [reg, d] of domains) {
    if (isOwn(reg) || isAllowed(reg) || suffixMatch(reg, HIGH_CARDINALITY_DEFAULTS)) continue;
    const label = dgaLabel(reg);
    if (label.length < o.dgaMinLength) continue;
    const t = dgaTraits(label);
    if (t.score >= o.dgaScoreMin) dga.set(reg, t);
  }
  tables.dga = [...dga.entries()].slice(0, 500).map(([reg, t]) => {
    const d = A.domains.get(reg);
    return { domain: reg, queries: d.q, clients: d.clients.size, resolved: d.ok, nxdomain: d.nx, score: t.score, traits: t.traits.join(", "), entropy: t.entropy };
  });
  const dgaClients = [];
  if (!A.has.rcode) skipped.push({ check: "Clients failing to resolve many DGA-like names", reason: "the log has no response code (NXDOMAIN) field" });
  else {
    for (const [client, c] of A.clients) {
      const hits = [...c.nxDomains].filter((r) => dga.has(r)).sort();
      if (hits.length >= o.dgaClientMin) dgaClients.push({ client, hits, c });
    }
    dgaClients.sort((a, b) => b.hits.length - a.hits.length || cmp(a.client, b.client));
    for (const { client, hits, c } of dgaClients.slice(0, 50)) {
      const ev = [];
      for (const r of hits) for (const e of A.domains.get(r).nxRows) if (e.client === client) pushCapped(ev, e);
      findings.push(finding({
        title: "Client failed to resolve many algorithmically generated-looking names", severity: "high", confidence: "likely", category: "dga",
        description: client + " received NXDOMAIN for " + hits.length + " distinct DGA-like domains (threshold " + o.dgaClientMin + "; " + c.nx + " NXDOMAIN of " + c.resp + " answers). Malware that uses domain generation tries many names until one resolves; the ones that fail show up as NXDOMAIN.",
        recommendation: "Isolate or examine " + client + " with EDR: find the process making these lookups (Sysmon event 22 or EDR DNS telemetry), and block the resolved domains at the DNS filter.",
        controls: C.dga, evidence: ev, evidenceCount: hits.length,
        assets: [{ type: "IP", name: client }, ...hits.slice(0, 10).map((h) => ({ type: "DOMAIN", name: h }))],
      }));
    }
  }
  const dgaResolved = [...dga.entries()].filter(([reg]) => { const d = A.domains.get(reg); return !A.has.rcode || d.ok > 0; });
  for (const [reg, t] of dgaResolved.slice(0, 25)) {
    const d = A.domains.get(reg);
    findings.push(finding({
      title: A.has.rcode ? "DGA-like domain resolved" : "DGA-like domain queried", severity: "medium", confidence: "review", category: "dga",
      description: reg + " scores " + t.score + " of 6 DGA traits (" + t.traits.join(", ") + "; entropy " + t.entropy + " bits/char, common letter pairs " + Math.round(t.bigram * 100) + "%). Queried " + d.q + " times by " + d.clients.size + " client(s)" + (A.has.rcode ? ", resolved " + d.ok + " times" : "") + ". Some legitimate services use random-looking names, so this needs review.",
      recommendation: "Check the domain's registration date and reputation, find the querying process on the clients, and block it at the DNS filter if it is not a known service. Add known-good names to the allow list.",
      controls: C.dga, evidence: d.rows, evidenceCount: d.q,
      assets: [{ type: "DOMAIN", name: reg }, ...[...d.clients].slice(0, 10).map((c) => ({ type: "IP", name: c }))],
    }));
  }
  if (dgaResolved.length > 25) {
    findings.push(finding({
      title: "More DGA-like domains (see the DGA table)", severity: "low", confidence: "review", category: "dga",
      description: (dgaResolved.length - 25) + " further DGA-like domains were seen; they are listed in the DGA table.",
      recommendation: "Review the DGA table and add known-good names to the allow list.", controls: C.dga,
      evidence: dgaResolved.slice(25, 75).map(([reg, t]) => ({ domain: reg, score: t.score, traits: t.traits.join(", ") })), evidenceCount: dgaResolved.length - 25,
      assets: dgaResolved.slice(25, 35).map(([reg]) => ({ type: "DOMAIN", name: reg })),
    }));
  }

  // --- Tunnelling ---------------------------------------------------------
  const tunnel = [];
  for (const [reg, d] of domains) {
    if (d.subs.size < o.tunnelMinSubdomains || isOwn(reg) || suffixMatch(reg, quiet)) continue;
    const avgLen = d.subs.size ? d.lenSum / d.subs.size : 0;
    const encRatio = d.subs.size ? d.encoded / d.subs.size : 0;
    const txtShare = d.q ? d.txtNull / d.q : 0;
    const weights = [];
    if (avgLen >= o.tunnelAvgLen) weights.push("mean query length " + round(avgLen, 1));
    if (encRatio >= o.tunnelEncodedRatio) weights.push(Math.round(encRatio * 100) + "% encoded-looking labels");
    if (txtShare >= 0.3) weights.push(Math.round(txtShare * 100) + "% TXT/NULL queries");
    if (d.maxLabel >= 50) weights.push("labels up to " + d.maxLabel + " chars");
    tunnel.push({ reg, d, avgLen, encRatio, txtShare, weights });
  }
  tunnel.sort((a, b) => b.weights.length - a.weights.length || b.d.subs.size - a.d.subs.size || cmp(a.reg, b.reg));
  tables.tunnel = tunnel.map((t) => ({ domain: t.reg, queries: t.d.q, uniqueSubdomains: t.d.subs.size + (t.d.subCapped ? "+" : ""), meanLength: round(t.avgLen, 1), encodedShare: round(t.encRatio, 2), txtNullShare: round(t.txtShare, 2), longestLabel: t.d.maxLabel, clients: t.d.clients.size, signals: t.weights.join("; ") }));
  for (const t of tunnel.filter((x) => x.weights.length >= 1).slice(0, 30)) {
    const strong = t.weights.length >= 2;
    findings.push(finding({
      title: strong ? "Possible DNS tunnelling" : "High-cardinality subdomains under one domain", severity: strong ? "high" : "medium", confidence: strong ? "likely" : "review", category: "tunnel",
      description: t.reg + " received " + t.d.q + " queries with " + t.d.subs.size + (t.d.subCapped ? "+" : "") + " unique subdomains (threshold " + o.tunnelMinSubdomains + ") from " + t.d.clients.size + " client(s). Signals: " + t.weights.join("; ") + ". Data carried inside DNS names shows up as many unique, long, encoded-looking labels under one domain.",
      recommendation: "Identify the process on the querying clients, block " + t.reg + " at the DNS filter, and only allow clients to use the internal resolvers (block outbound 53/853 elsewhere). Security products that do reputation lookups over DNS look similar: add them to the allow list if confirmed.",
      controls: C.tunnel, evidence: t.d.rows, evidenceCount: t.d.q,
      assets: [{ type: "DOMAIN", name: t.reg }, ...[...t.d.clients].slice(0, 10).map((c) => ({ type: "IP", name: c }))],
    }));
  }

  // --- Beaconing ----------------------------------------------------------
  const beacons = [];
  if (!A.has.ts) skipped.push({ check: "Beaconing (periodic queries)", reason: "the log has no usable timestamps" });
  else {
    const popularMin = Math.max(5, Math.ceil(o.beaconPopularShare * totalClients));
    let popularSkipped = 0;
    for (const [key, tss] of [...A.pairs.entries()].sort((a, b) => cmp(a[0], b[0]))) {
      if (tss.length < o.beaconMinEvents) continue;
      const [client, reg] = key.split("\u0001");
      if (isOwn(reg) || suffixMatch(reg, quiet)) continue;
      const d = A.domains.get(reg);
      if (d && totalClients >= 5 && d.clients.size >= popularMin) { popularSkipped++; continue; }
      const p = periodicity(tss);
      if (!p || p.cv > o.beaconMaxCv || p.medianSec < o.beaconMinIntervalSec || p.medianSec > o.beaconMaxIntervalSec) continue;
      if (p.spanSec < 3600) continue;
      beacons.push({ client, reg, n: tss.length, ...p });
    }
    beacons.sort((a, b) => a.cv - b.cv || b.n - a.n || cmp(a.client + a.reg, b.client + b.reg));
    if (popularSkipped) skipped.push({ check: "Beaconing on common domains", reason: popularSkipped + " client/domain pairs skipped because the domain is queried by at least " + popularMin + " clients (common services)" });
    if (A.pairsCapped) skipped.push({ check: "Beaconing (partial)", reason: "more than " + LIMITS.maxPairs + " client/domain pairs; later pairs were not tracked" });
  }
  tables.beacons = beacons.slice(0, 500).map((b) => ({ client: b.client, domain: b.reg, queries: b.n, medianIntervalSec: b.medianSec, cv: b.cv, spanHours: round(b.spanSec / 3600, 1) }));
  for (const b of beacons.slice(0, 40)) {
    const d = A.domains.get(b.reg);
    findings.push(finding({
      title: "Periodic DNS queries (beaconing pattern)", severity: dga.has(b.reg) ? "high" : "medium", confidence: "review", category: "beacon",
      description: b.client + " queried " + b.reg + " " + b.n + " times over " + round(b.spanSec / 3600, 1) + " h at a steady interval (median " + b.medianSec + " s, coefficient of variation " + b.cv + " <= " + o.beaconMaxCv + ", n = " + b.intervals + " intervals)." + (dga.has(b.reg) ? " The domain is also DGA-like." : "") + " Command-and-control implants check in on a timer; so do update agents and telemetry, so confirm the process.",
      recommendation: "Find the process on " + b.client + " making the lookups. If it is not a known agent, block the domain and investigate the host; if it is, add the domain to the allow list.",
      controls: C.beacon, evidence: (d ? d.rows.filter((e) => e.client === b.client) : []), evidenceCount: b.n,
      assets: [{ type: "IP", name: b.client }, { type: "DOMAIN", name: b.reg }],
    }));
  }

  // --- NXDOMAIN storms ----------------------------------------------------
  const nxClients = [];
  if (A.has.rcode) {
    const flagged = new Set(dgaClients.map((x) => x.client));
    for (const [client, c] of A.clients) {
      if (c.nx >= o.nxMin && c.resp && c.nx / c.resp >= o.nxRatio) nxClients.push({ client, c });
    }
    nxClients.sort((a, b) => b.c.nx - a.c.nx || cmp(a.client, b.client));
    for (const { client, c } of nxClients.filter((x) => !flagged.has(x.client)).slice(0, 30)) {
      // skip DGA-flagged clients BEFORE the top-30 cap — otherwise a flagged client in the
      // top 30 consumes a slot and a real non-DGA storm ranked below 30 is silently dropped.
      const ev = [];
      for (const r of [...c.nxDomains].sort()) { const d = A.domains.get(r); if (d) for (const e of d.nxRows) if (e.client === client) pushCapped(ev, e); }
      findings.push(finding({
        title: "NXDOMAIN storm from one client", severity: "medium", confidence: "likely", category: "nxdomain",
        description: client + " received " + c.nx + " NXDOMAIN answers out of " + c.resp + " (" + Math.round((c.nx / c.resp) * 100) + "%; thresholds " + o.nxMin + " and " + Math.round(o.nxRatio * 100) + "%) across " + c.nxDomains.size + " domains. Causes include domain generation, a misconfigured search suffix, or a broken application.",
        recommendation: "Look at the failed names in the evidence: random-looking names point to malware; repeated internal names point to a configuration problem.",
        controls: C.nx, evidence: ev, evidenceCount: c.nx, assets: [{ type: "IP", name: client }],
      }));
    }
  }
  tables.nxClients = nxClients.slice(0, 200).map(({ client, c }) => ({ client, nxdomain: c.nx, answers: c.resp, share: round(c.nx / c.resp, 2), domains: c.nxDomains.size }));

  // --- Lookalikes of own domains -----------------------------------------
  const looks = [];
  if (!own.length) skipped.push({ check: "Lookalikes of your domains", reason: "no own domains entered in settings" });
  else {
    for (const [reg, d] of domains) {
      if (isAllowed(reg)) continue;
      const m = lookalikeOf(reg, own);
      if (m) looks.push({ reg, d, ...m });
    }
  }
  tables.lookalikes = looks.map((l) => ({ domain: l.reg, unicode: toUnicodeName(l.reg), resembles: l.own, kind: l.kind, queries: l.d.q, clients: l.d.clients.size, resolved: l.d.ok, nxdomain: l.d.nx }));
  for (const l of looks.slice(0, 30)) {
    const resolved = !A.has.rcode || l.d.ok > 0;
    findings.push(finding({
      title: "Lookalike of your domain was queried", severity: resolved ? "high" : "low", confidence: "review", category: "lookalike",
      description: l.reg + (l.reg.includes("xn--") ? " (" + toUnicodeName(l.reg) + ")" : "") + " resembles " + l.own + " (" + l.kind + ") and was queried " + l.d.q + " times by " + l.d.clients.size + " client(s)" + (A.has.rcode ? ", resolving " + l.d.ok + " times" : "") + ". Lookalike domains are used for phishing and credential theft against your staff.",
      recommendation: "Check who registered " + l.reg + ", block it at the DNS filter and mail gateway, and ask the users on the querying clients what they opened. Consider registering close variants yourself.",
      controls: C.look, evidence: l.d.rows, evidenceCount: l.d.q,
      assets: [{ type: "DOMAIN", name: l.reg }, ...[...l.d.clients].slice(0, 10).map((c) => ({ type: "IP", name: c }))],
    }));
  }

  // --- Encrypted DNS bypass ----------------------------------------------
  const enc = [...A.encrypted.entries()].sort((a, b) => b[1].q - a[1].q || cmp(a[0], b[0]));
  tables.encryptedDns = enc.map(([host, x]) => ({ host, queries: x.q, clients: x.clients.size }));
  if (enc.length) {
    const clients = new Set(); const rows = [];
    for (const [, x] of enc) { for (const c of x.clients) clients.add(c); for (const e of x.rows) pushCapped(rows, e); }
    findings.push(finding({
      title: "Clients looked up public encrypted-DNS resolvers", severity: clients.size >= 10 ? "medium" : "low", confidence: "likely", category: "encrypted-dns",
      description: clients.size + " client(s) resolved " + enc.length + " DNS-over-HTTPS/TLS endpoint(s): " + enc.slice(0, 8).map(([h]) => h).join(", ") + ". After this lookup their DNS can go around the company resolver, so it is no longer filtered or logged.",
      recommendation: "Disable DoH in managed browsers by policy, return NXDOMAIN for " + DOH_CANARY + ", and block these resolvers' DoH/DoT endpoints at the firewall or proxy unless they are approved.",
      controls: C.doh, evidence: rows, evidenceCount: enc.reduce((a, [, x]) => a + x.q, 0),
      assets: [...clients].sort().slice(0, 20).map((c) => ({ type: "IP", name: c })),
    }));
  }
  if (A.canary.q && A.has.rcode && A.canary.ok > 0) {
    findings.push(finding({
      title: "Firefox DoH canary domain is not blocked", severity: "low", confidence: "confirmed", category: "encrypted-dns",
      description: DOH_CANARY + " was answered " + A.canary.ok + " times without NXDOMAIN. Firefox treats an answer as permission to turn on its own DNS-over-HTTPS by default, bypassing this resolver.",
      recommendation: "Configure the resolver to return NXDOMAIN for " + DOH_CANARY + " (Mozilla's documented canary), or disable DoH by enterprise policy.",
      controls: C.doh, evidence: A.canary.rows, evidenceCount: A.canary.q, assets: [...A.canary.clients].sort().slice(0, 20).map((c) => ({ type: "IP", name: c })),
    }));
  }

  // --- Resolver bypass ----------------------------------------------------
  // A resolver's own recursive lookups (a Zeek sensor sees 10.0.0.2 -> root/authoritative
  // servers) are not a bypass: drop clients that are approved or were seen answering others.
  const ext = [...A.external.entries()].filter(([client]) => !X.ctxOpts.approved.includes(client) && !A.resolvers.has(client)).sort((a, b) => b[1].q - a[1].q || cmp(a[0], b[0]));
  if (!A.has.server) skipped.push({ check: "Clients using unapproved resolvers", reason: "the log has no resolver/server address (Zeek id.resp_h or a mapped server column)" });
  tables.externalResolvers = ext.map(([client, x]) => ({ client, queries: x.q, resolvers: [...x.servers.keys()].sort().join(" ") }));
  if (ext.length) {
    const rows = []; for (const [, x] of ext) for (const e of x.rows) pushCapped(rows, e);
    findings.push(finding({
      title: "Clients sent DNS straight to unapproved resolvers", severity: "medium", confidence: "likely", category: "resolver",
      description: ext.length + " client(s) sent " + ext.reduce((a, [, x]) => a + x.q, 0) + " queries to resolvers that are not " + (X.ctxOpts.approved.length ? "on the approved list" : "internal") + " (" + [...new Set(ext.flatMap(([, x]) => [...x.servers.keys()]))].sort().slice(0, 8).join(", ") + "). That traffic skips DNS filtering and logging.",
      recommendation: "Block outbound TCP/UDP 53 and TCP 853 except from the approved resolvers, and point DHCP and endpoint configuration at them.",
      controls: C.resolver, evidence: rows, evidenceCount: ext.reduce((a, [, x]) => a + x.q, 0), assets: ext.slice(0, 20).map(([c]) => ({ type: "IP", name: c })),
    }));
  }

  // --- Threat-intel answers ----------------------------------------------
  if (!X.ctxOpts.intel.size) skipped.push({ check: "Answers pointing at known-malicious IPs", reason: "malicious-IP feed not loaded" });
  else if (!A.has.answers) skipped.push({ check: "Answers pointing at known-malicious IPs", reason: "the log has no answer (resolved IP) field" });
  const intel = [...A.intel.entries()].sort((a, b) => b[1].q - a[1].q || cmp(a[0], b[0]));
  tables.intel = intel.map(([ip, x]) => ({ ip, answers: x.q, domains: [...x.domains].sort().slice(0, 10).join(" "), clients: x.clients.size }));
  for (const [ip, x] of intel.slice(0, 30)) {
    findings.push(finding({
      title: "Domain resolved to an IP on the malicious-IP feed", severity: "high", confidence: "likely", category: "intel",
      description: [...x.domains].sort().slice(0, 5).join(", ") + " resolved to " + ip + " " + x.q + " times for " + x.clients.size + " client(s). The IP is on the mirrored malicious-IP feed" + (o.feedUpdated ? " (updated " + o.feedUpdated + ")" : "") + ". Shared hosting can put benign sites on listed IPs, so confirm.",
      recommendation: "Block the domain(s) and IP, and check the querying clients for follow-on connections in proxy or firewall logs.",
      controls: C.intel, evidence: x.rows, evidenceCount: x.q,
      assets: [{ type: "IP", name: ip }, ...[...x.domains].sort().slice(0, 10).map((d) => ({ type: "DOMAIN", name: regDomain(d) }))],
    }));
  }

  // --- Newly observed domains --------------------------------------------
  const known = listOpt(o.knownDomains);
  const spanDays = A.has.ts ? (A.maxTs - A.minTs) / 86400000 : 0;
  let newDomains = [];
  if (known.length) {
    newDomains = domains.filter(([reg]) => !suffixMatch(reg, known) && !isOwn(reg) && !isAllowed(reg));
  } else if (!A.has.ts) skipped.push({ check: "Newly observed domains", reason: "no timestamps and no baseline domain list" });
  else if (spanDays < o.baselineDays + 1) skipped.push({ check: "Newly observed domains", reason: "the log covers " + round(spanDays, 1) + " days; needs at least " + (o.baselineDays + 1) + " (baseline " + o.baselineDays + " days) or a baseline domain list" });
  else {
    const cut = A.minTs + o.baselineDays * 86400000;
    newDomains = domains.filter(([reg, d]) => d.first != null && d.first > cut && !isOwn(reg) && !isAllowed(reg) && !reg.endsWith(".arpa"));
  }
  newDomains.sort((a, b) => (a[1].first ?? 0) - (b[1].first ?? 0) || cmp(a[0], b[0]));
  tables.newDomains = newDomains.slice(0, 1000).map(([reg, d]) => ({ domain: reg, firstSeen: iso(d.first), queries: d.q, clients: d.clients.size, dgaLike: dga.has(reg) ? "yes" : "", lookalike: looks.some((l) => l.reg === reg) ? "yes" : "" }));
  if (newDomains.length) {
    const flagged = newDomains.filter(([reg]) => dga.has(reg) || looks.some((l) => l.reg === reg));
    findings.push(finding({
      title: "Newly observed domains", severity: flagged.length ? "low" : "info", confidence: "review", category: "new-domain",
      description: newDomains.length + " registrable domains appear for the first time " + (known.length ? "compared with the baseline list (" + known.length + " entries)" : "after the first " + o.baselineDays + " days of this log") + (flagged.length ? "; " + flagged.length + " of them are also DGA-like or lookalikes" : "") + ". New destinations are where most new threats first show up.",
      recommendation: "Review the newly observed table, starting with names queried by a single client. Feed confirmed-bad names into the DNS filter.",
      controls: C.newdom, evidence: newDomains.slice(0, 50).map(([reg, d]) => ({ domain: reg, firstSeen: iso(d.first), queries: d.q, clients: d.clients.size })), evidenceCount: newDomains.length,
      assets: (flagged.length ? flagged : newDomains).slice(0, 10).map(([reg]) => ({ type: "DOMAIN", name: reg })),
    }));
  }

  // --- Wrap up ------------------------------------------------------------
  tables.topDomains = domains.slice(0, 200).map(([reg, d]) => ({ domain: reg, queries: d.q, clients: d.clients.size, uniqueSubdomains: d.subs.size + (d.subCapped ? "+" : ""), nxdomain: d.nx, firstSeen: iso(d.first), lastSeen: iso(d.last) }));
  tables.clients = [...A.clients.entries()].sort((a, b) => b[1].q - a[1].q || cmp(a[0], b[0])).slice(0, 500).map(([client, c]) => ({ client, users: [...c.users].sort().join(" "), queries: c.q, nxdomain: c.nx, firstSeen: iso(c.first), lastSeen: iso(c.last) }));
  tables.files = files;
  if (A.domainsCapped) skipped.push({ check: "Domain tracking (partial)", reason: "more than " + LIMITS.maxDomains + " registrable domains; later new domains were not tracked" });

  findings.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || cmp(a.category, b.category) || b.evidenceCount - a.evidenceCount || cmp(a.title + a.description, b.title + b.description));
  findings.forEach((f, i) => { f.id = "dnh-" + String(i + 1).padStart(3, "0"); });
  const bySeverity = {};
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  const summary = {
    events: A.events, queries: A.queries, responses: A.responses, clients: A.clients.size, domains: A.domains.size,
    start: iso(A.minTs), end: iso(A.maxTs), spanDays: round(spanDays, 2), findings: findings.length, bySeverity,
    dgaDomains: dga.size, tunnelCandidates: tunnel.length, beacons: beacons.length, lookalikes: looks.length, newDomains: newDomains.length,
    fields: { ...A.has },
  };
  ctx?.progress?.(1, 1, "Done");
  return { summary, findings, tables, skipped, meta: { tool: TOOL_ID, version: VERSION, rows: A.events, files: files.map((f) => f.name + ": " + f.format) } };
}

const FINDING_COLS = ["id", "severity", "confidence", "category", "title", "description", "recommendation", "controls", "assets", "evidenceCount"];

/** Findings as CSV with fixed columns (formula-injection safe). */
export function findingsToCsv(findings) {
  const q = (v) => { let s = String(v ?? ""); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };
  const body = (findings || []).map((f) => [
    f.id, f.severity, f.confidence, f.category, f.title, f.description, f.recommendation,
    (f.controls || []).map((c) => c.framework + " " + c.id).join("; "), (f.assets || []).map((a) => a.type + ":" + a.name).join("; "), f.evidenceCount ?? (f.evidence || []).length,
  ].map(q).join(","));
  return [FINDING_COLS.join(","), ...body].join("\n");
}

// ---------------------------------------------------------------------------
// Synthetic example: a Zeek dns.log and a BIND query log for a fictional company.
// Internal hosts are RFC 1918; outside addresses are documentation ranges; every
// suspicious-looking name is generated here at runtime under the reserved .invalid
// or .test TLDs (RFC 2606 / RFC 6761). Nothing is real traffic.
// ---------------------------------------------------------------------------

const EX_NORMAL = ["www.google.com", "outlook.office365.com", "login.microsoftonline.com", "slack.com", "api.github.com", "zoom.us", "www.dropbox.com", "testorg.my.salesforce.com", "cdn.test.darknode.ai", "intranet.test.darknode.ai", "time.windows.com", "update.googleapis.com"];

/** Seeded SYNTHETIC dataset for "Load example" and tests. */
export function exampleDataset(seed = 11) {
  let s = seed >>> 0;
  const rnd = () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 4294967296; };
  const pick = (arr) => arr[Math.floor(rnd() * arr.length)];
  const hex = (n) => { let o = ""; for (let i = 0; i < n; i++) o += "0123456789abcdef"[Math.floor(rnd() * 16)]; return o; };
  const cons = "bcdfghjklmnpqrstvwxz";
  const genLabel = () => { let o = ""; const n = 14 + Math.floor(rnd() * 5); for (let i = 0; i < n; i++) o += i === 6 ? String(Math.floor(rnd() * 10)) : rnd() < 0.08 ? "a" : cons[Math.floor(rnd() * cons.length)]; return o; };
  const start = Date.UTC(2026, 9, 6, 0, 0, 0);
  const DAY = 86400000;
  const events = [];
  const add = (ts, client, query, qtype, rcode, answers = "-", server = "10.20.0.2") => events.push({ ts, client, query, qtype, rcode, answers, server });
  const clients = Array.from({ length: 36 }, (_, i) => "10.20.0." + (10 + i));

  // Ordinary traffic over nine days.
  for (let day = 0; day < 9; day++) {
    for (const c of clients) {
      const n = 18 + Math.floor(rnd() * 10);
      for (let k = 0; k < n; k++) {
        const ts = start + day * DAY + Math.floor((7 + rnd() * 11) * 3600000);
        const q = pick(EX_NORMAL);
        add(ts, c, q, rnd() < 0.85 ? "A" : "AAAA", "NOERROR", "198.51.100." + (1 + Math.floor(rnd() * 200)));
      }
    }
  }
  // Day 8: one workstation tries many generated names; most fail, one resolves.
  const dgaClient = "10.20.0.31";
  for (let k = 0; k < 40; k++) add(start + 8 * DAY + 3600000 * 9 + k * 7000, dgaClient, genLabel() + ".test", "A", k === 39 ? "NOERROR" : "NXDOMAIN", k === 39 ? "203.0.113.66" : "-");
  // Days 6-8: a host sends hex-encoded chunks as TXT lookups under one domain.
  const tunClient = "10.20.0.44";
  for (let k = 0; k < 320; k++) add(start + 6 * DAY + k * 600000, tunClient, hex(32) + "." + hex(12) + ".sync.sync-relay.invalid", "TXT", "NOERROR", "-");
  // Days 3-4: a host checks in every five minutes (+-3 s) for 30 hours.
  const beaconClient = "10.20.0.17";
  for (let k = 0; k < 360; k++) add(start + 3 * DAY + k * 300000 + Math.floor((rnd() - 0.5) * 6000), beaconClient, "telemetry-relay.invalid", "A", "NOERROR", "203.0.113.40");
  // Day 8: a lookalike of the company domain is opened by two users.
  for (const c of ["10.20.0.21", "10.20.0.22"]) add(start + 8 * DAY + 3600000 * 14, c, "login.darkn0de.test", "A", "NOERROR", "203.0.113.77");
  // Browsers fetching encrypted-DNS endpoints and the Firefox canary.
  for (const c of ["10.20.0.12", "10.20.0.13", "10.20.0.14"]) {
    add(start + 2 * DAY + 3600000 * 10, c, "mozilla.cloudflare-dns.com", "A", "NOERROR", "198.51.100.250");
    add(start + 2 * DAY + 3600000 * 10 + 500, c, "use-application-dns.net", "A", "NOERROR", "198.51.100.251");
  }
  add(start + 5 * DAY + 3600000 * 11, "10.20.0.15", "dns.google", "A", "NOERROR", "198.51.100.252");
  // A host that sends its DNS straight to an outside resolver.
  for (let k = 0; k < 25; k++) add(start + 4 * DAY + k * 120000, "10.20.0.52", pick(EX_NORMAL), "A", "NOERROR", "198.51.100.9", "198.51.100.53");
  // A misconfigured search suffix: hundreds of failed internal names.
  for (let k = 0; k < 260; k++) add(start + 5 * DAY + k * 30000, "10.20.0.60", "printer" + (k % 12) + ".corp.local.test.darknode.ai", "A", "NXDOMAIN", "-");

  events.sort((a, b) => a.ts - b.ts || cmp(a.client, b.client));
  const zeekHead = ["#separator \\x09", "#set_separator\t,", "#empty_field\t(empty)", "#unset_field\t-", "#path\tdns", "#open\t2026-10-06-00-00-00",
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\trtt\tquery\tqclass\tqclass_name\tqtype\tqtype_name\trcode\trcode_name\tAA\tTC\tRD\tRA\tZ\tanswers\tTTLs\trejected",
    "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tcount\tinterval\tstring\tcount\tstring\tcount\tstring\tcount\tstring\tbool\tbool\tbool\tbool\tcount\tvector[string]\tvector[interval]\tbool"];
  const QT = { A: 1, AAAA: 28, TXT: 16 };
  const RC = { NOERROR: 0, NXDOMAIN: 3 };
  const lines = events.map((e, i) => [(e.ts / 1000).toFixed(6), "C" + hex(17), e.client, 49152 + (i % 16000), e.server, 53, "udp", i % 65536, "0.0" + Math.floor(rnd() * 90 + 10), e.query, 1, "C_INTERNET", QT[e.qtype], e.qtype, RC[e.rcode], e.rcode, "F", "F", "T", "T", 0, e.answers, e.answers === "-" ? "-" : "300.000000", "F"].join("\t"));
  const zeek = [...zeekHead, ...lines, "#close\t2026-10-15-00-00-00"].join("\n") + "\n";

  // A short BIND query log from a branch-office resolver on the last day.
  const mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const bindTs = (t) => { const d = new Date(t); return String(d.getUTCDate()).padStart(2, "0") + "-" + mon[d.getUTCMonth()] + "-" + d.getUTCFullYear() + " " + d.toISOString().slice(11, 23); };
  const bind = [];
  for (let k = 0; k < 30; k++) {
    const t = start + 8 * DAY + 3600000 * 15 + k * 61000;
    const c = "192.168.40." + (20 + (k % 6));
    const q = k === 7 ? "login.darkn0de.test" : pick(EX_NORMAL);
    bind.push(bindTs(t) + " queries: info: client @0x7f3a2c0e1b20 " + c + "#" + (50000 + k) + " (" + q + "): query: " + q + " IN A +E(0)K (192.168.40.2)");
  }
  return {
    label: "synthetic example (not real data)",
    files: [{ name: "dns.log", text: zeek }, { name: "named-queries.log", text: bind.join("\n") + "\n" }],
    opts: { ownDomains: "darknode.ai", maliciousIps: ["203.0.113.66"], feedUpdated: "synthetic" },
  };
}

/** Real deterministic checks of the engine on the synthetic example. */
export function selfTest() {
  const tests = [];
  const ex = exampleDataset();
  const r = analyze({ files: ex.files }, ex.opts);
  const has = (cat, pred = () => true) => r.findings.some((f) => f.category === cat && pred(f));
  tests.push({ name: "both example files detected", pass: r.tables.files.map((f) => f.format).join(",") === "zeek-tsv,bind" });
  tests.push({ name: "DGA client found", pass: has("dga", (f) => f.assets[0].name === "10.20.0.31" && f.severity === "high") });
  tests.push({ name: "tunnelling found", pass: has("tunnel", (f) => f.assets[0].name === "sync-relay.invalid" && f.severity === "high") });
  tests.push({ name: "beacon found", pass: has("beacon", (f) => f.assets[0].name === "10.20.0.17") });
  tests.push({ name: "lookalike found", pass: has("lookalike", (f) => f.assets[0].name === "darkn0de.test") });
  tests.push({ name: "encrypted DNS and canary", pass: has("encrypted-dns", (f) => /canary/.test(f.title)) && has("encrypted-dns", (f) => /encrypted-DNS/.test(f.title)) });
  tests.push({ name: "resolver bypass", pass: has("resolver", (f) => f.assets[0].name === "10.20.0.52") });
  tests.push({ name: "intel answer", pass: has("intel", (f) => f.assets[0].name === "203.0.113.66") });
  tests.push({ name: "NXDOMAIN storm", pass: has("nxdomain", (f) => f.assets[0].name === "10.20.0.60") });
  tests.push({ name: "deterministic", pass: JSON.stringify(r) === JSON.stringify(analyze({ files: ex.files }, ex.opts)) });
  return { pass: tests.every((t) => t.pass), tests };
}

/** Any table (array of flat objects) as CSV, formula-injection safe. */
export function tableToCsv(rows) {
  const list = rows || [];
  const keys = [];
  for (const r of list) for (const k of Object.keys(r)) if (!keys.includes(k)) keys.push(k);
  const q = (v) => { let s = String(v ?? ""); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };
  return [keys.join(","), ...list.map((r) => keys.map((k) => q(r[k])).join(","))].join("\n") + "\n";
}

/** Domains from high/medium findings with likely or confirmed confidence, one per line, for a DNS filter. */
export function blocklistText(findings) {
  const set = new Set();
  for (const f of findings || []) {
    if (!(f.severity === "high" || f.severity === "critical" || f.severity === "medium") || f.confidence === "review") continue;
    if (!["dga", "tunnel", "intel", "lookalike"].includes(f.category)) continue;
    for (const a of f.assets || []) if (a.type === "DOMAIN") set.add(a.name);
  }
  return "# DNS Hunt blocklist (likely/confirmed findings only). Review before deploying.\n" + [...set].sort().join("\n") + "\n";
}

/** Plain-text summary for tickets and reports. */
export function summaryText(r) {
  const s = r.summary;
  const lines = [
    "DNS Hunt summary", "",
    "Events: " + s.events + "  Clients: " + s.clients + "  Registrable domains: " + s.domains,
    "Window: " + (s.start || "n/a") + " to " + (s.end || "n/a") + " (" + s.spanDays + " days)",
    "Files: " + (r.meta.files || []).join("; "),
    "Findings: " + s.findings + " (" + Object.entries(s.bySeverity).map(([k, v]) => k + " " + v).join(", ") + ")", "",
  ];
  for (const f of r.findings) {
    lines.push("[" + f.severity.toUpperCase() + "/" + f.confidence + "] " + f.title);
    lines.push("  " + f.description);
    lines.push("  Fix: " + f.recommendation);
    lines.push("  Controls: " + f.controls.map((c) => c.framework + " " + c.id).join(", "));
    lines.push("");
  }
  if (r.skipped.length) { lines.push("Skipped or limited checks:"); for (const k of r.skipped) lines.push("  - " + k.check + ": " + k.reason); }
  return lines.join("\n") + "\n";
}
