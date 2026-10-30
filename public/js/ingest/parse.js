// Shared ingest kit for Deck business tools: format sniffing, CSV / JSON /
// NDJSON record iteration, a dependency-free XML tree, CEF / LEEF headers, a
// YAML subset and an HCL2 subset. Pure ESM, deterministic, touches no globals
// at module scope, so it loads in Node, in the page and in a Blob-module
// Worker. Log line formats (iis / clf / syslog) are detected here but parsed by
// public/js/ops/log-hunter-engine.js `parseText`; iterRecords returns null for
// them so callers can delegate.
//
// Lifted from identity/signin-forensics-engine.js (iterCsvRows, sniffDelimiter,
// flatten, JSON wrapper handling), identity/access-review-engine.js
// (normHeader / findColumn) and ops/log-hunter-engine.js (detection regexes).

export const VERSION = "1.0.0";

// Keys come from the parsed file: set them as own data so "__proto__" is a key,
// not a prototype swap (which dropped the key and made its fields look inherited).
const put = (o, k, v) => { Object.defineProperty(o, k, { value: v, writable: true, enumerable: true, configurable: true }); return v; };

export const FORMATS = ["zip", "gzip", "json", "ndjson", "evtx-xml", "xml", "cef", "leef", "iis", "clf", "syslog", "hcl", "yaml", "csv", "tsv", "unknown"];

const WRAP_KEYS = ["value", "events", "items", "data", "records", "results"];
const DELIMS = [",", ";", "\t", "|"];

const RE = {
  cef: /^(?:[^|]*[|\s])?CEF:\d\|/,
  leef: /^(?:[^|]*[|\s])?LEEF:\d/,
  iisHead: /^#(Fields|Software):/,
  iisLine: /^(?:#[\w-]+:|\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \S+ )/,
  clf: /^(?:\S+ )?\S+ \S+ \S+ \[\d{1,2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\] "/,
  // BSD "prog[pid]:" and RFC 5424 "app procid msgid" shapes
  syslog: /^(?:<\d+>\d?\s*)?(?:\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+) \S+ \S+?(?:\[\d+\])?(?::|\s(?:-|\d+)\s)/,
  hclBlock: /^\s*(resource|variable|module|provider|terraform|data|output|locals)\s+("[^"]+"\s*){0,2}\{/,
  hclLine: /^\s*(?:[\w.-]+\s*=|[\w-]+(?:\s+"[^"]*")*\s*\{|[}\])],?\s*$|#|\/\/|\/\*|\*|"|[\w.-]+,?\s*$)/,
  yamlHard: /^(apiVersion|kind|openapi|swagger|AWSTemplateFormatVersion|Resources|services|version):/,
  yamlKey: /^[A-Za-z_][\w-]*:\s/,
  yamlLine: /^\s*(?:-(?:\s|$)|#|(?:"[^"]*"|'[^']*'|[^\s:#\[\]{}][^:#]*?)\s*:(?:\s|$)|\s\S)/,
  evt: /<Event[\s>]/,
};

// ---------------------------------------------------------------------------
// Bytes and text
// ---------------------------------------------------------------------------
function toU8(b) {
  if (b instanceof Uint8Array) return b;
  if (typeof ArrayBuffer !== "undefined") {
    if (b instanceof ArrayBuffer) return new Uint8Array(b);
    if (b && b.buffer instanceof ArrayBuffer && typeof b.byteLength === "number") return new Uint8Array(b.buffer, b.byteOffset || 0, b.byteLength);
  }
  if (Array.isArray(b)) return Uint8Array.from(b);
  return new Uint8Array(0);
}

// BOM first, then an even/odd NUL-byte heuristic for BOM-less UTF-16.
function detectEncoding(u8) {
  if (u8.length >= 3 && u8[0] === 0xef && u8[1] === 0xbb && u8[2] === 0xbf) return { encoding: "utf-8", bom: true, bomLength: 3 };
  if (u8.length >= 2 && u8[0] === 0xff && u8[1] === 0xfe) return { encoding: "utf-16le", bom: true, bomLength: 2 };
  if (u8.length >= 2 && u8[0] === 0xfe && u8[1] === 0xff) return { encoding: "utf-16be", bom: true, bomLength: 2 };
  const n = Math.min(u8.length, 1024) & ~1;
  if (n >= 8) {
    let even = 0, odd = 0;
    for (let i = 0; i < n; i += 2) { if (u8[i] === 0) even++; if (u8[i + 1] === 0) odd++; }
    const pairs = n / 2;
    if (odd > pairs * 0.3 && even < pairs * 0.05) return { encoding: "utf-16le", bom: false, bomLength: 0 };
    if (even > pairs * 0.3 && odd < pairs * 0.05) return { encoding: "utf-16be", bom: false, bomLength: 0 };
  }
  return { encoding: "utf-8", bom: false, bomLength: 0 };
}

function decodeUtf8(u8, start) {
  const sub = start ? u8.subarray(start) : u8;
  if (typeof TextDecoder !== "undefined") {
    try { return new TextDecoder("utf-8").decode(sub); } catch (_) { /* fall through */ }
  }
  const parts = []; let out = "", i = 0; const n = sub.length;
  while (i < n) {
    const b = sub[i++]; let cp;
    if (b < 0x80) cp = b;
    else if (b >= 0xc0 && b < 0xe0 && i < n) cp = ((b & 0x1f) << 6) | (sub[i++] & 0x3f);
    else if (b >= 0xe0 && b < 0xf0 && i + 1 < n) { cp = ((b & 0x0f) << 12) | ((sub[i] & 0x3f) << 6) | (sub[i + 1] & 0x3f); i += 2; }
    else if (b >= 0xf0 && i + 2 < n) { cp = ((b & 0x07) << 18) | ((sub[i] & 0x3f) << 12) | ((sub[i + 1] & 0x3f) << 6) | (sub[i + 2] & 0x3f); i += 3; }
    else cp = 0xfffd;
    parts.push(String.fromCodePoint(cp > 0x10ffff ? 0xfffd : cp));
    if (parts.length >= 8192) { out += parts.join(""); parts.length = 0; }
  }
  return out + parts.join("");
}

function decodeUtf16(u8, start, be) {
  const parts = []; let out = "";
  for (let i = start; i + 1 < u8.length; i += 2) {
    parts.push(String.fromCharCode(be ? (u8[i] << 8) | u8[i + 1] : u8[i] | (u8[i + 1] << 8)));
    if (parts.length >= 8192) { out += parts.join(""); parts.length = 0; }
  }
  return out + parts.join("");
}

// Decode bytes to a string: UTF-8 by default, UTF-16 LE/BE by BOM (or NUL
// pattern). The BOM is stripped. Strings pass through (BOM stripped).
export function decodeText(bytes) {
  if (typeof bytes === "string") return bytes.charCodeAt(0) === 0xfeff ? bytes.slice(1) : bytes;
  const u8 = toU8(bytes);
  const enc = detectEncoding(u8);
  let s = enc.encoding === "utf-8" ? decodeUtf8(u8, enc.bomLength) : decodeUtf16(u8, enc.bomLength, enc.encoding === "utf-16be");
  if (s.charCodeAt(0) === 0xfeff) s = s.slice(1);
  return s;
}

// ---------------------------------------------------------------------------
// Format sniffing
// ---------------------------------------------------------------------------
function nonEmptyLines(text, max) {
  const out = [];
  const lines = text.split(/\r\n|\r|\n/); // a lone CR ends a line too (classic Mac / old Excel-for-Mac CSV)
  for (const l of lines) { if (l.trim()) { out.push(l); if (max && out.length >= max) break; } }
  return out;
}

function share(lines, re) {
  if (!lines.length) return 0;
  let n = 0;
  for (const l of lines) if (re.test(l)) n++;
  return n / lines.length;
}

// Quote-aware count of a delimiter on one line.
function countDelim(line, d) {
  let n = 0, q = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') q = !q;
    else if (!q && c === d) n++;
  }
  return n;
}

// Delimiter vote over the first 20 non-empty lines. Winner must give the same
// field count (>= 2) on >= 80% of lines. Returns null without consensus.
function voteDelimiter(lines) {
  let best = null;
  for (const d of DELIMS) {
    const counts = {};
    for (const l of lines) { const k = countDelim(l, d) + 1; counts[k] = (counts[k] || 0) + 1; }
    let mode = 0, modeN = 0;
    for (const k of Object.keys(counts)) { const c = counts[k]; if (c > modeN || (c === modeN && Number(k) > mode)) { mode = Number(k); modeN = c; } }
    const sh = modeN / lines.length;
    if (mode < 2 || sh < 0.8) continue;
    if (!best || sh > best.share || (sh === best.share && mode > best.fields)) best = { delimiter: d, share: sh, fields: mode };
  }
  return best;
}

function looksBinary(text) {
  const n = Math.min(text.length, 2048);
  if (!n) return false;
  let bad = 0;
  for (let i = 0; i < n; i++) {
    const c = text.charCodeAt(i);
    if ((c < 0x20 && c !== 9 && c !== 10 && c !== 13) || c === 0xfffd) bad++;
  }
  return bad / n > 0.02;
}

function tryJson(s) { try { return JSON.parse(s); } catch (_) { return undefined; } }

// Detect the format of a string / Uint8Array / ArrayBuffer. Only the first
// `sample` bytes (or chars) are inspected. Returns
// { format, confidence (0..1), delimiter?, bom, encoding }.
export function sniff(input, { sample = 65536 } = {}) {
  let bom = false, encoding = "string", text, truncated = false;
  if (typeof input === "string") {
    if (input.charCodeAt(0) === 0xfeff) { bom = true; input = input.slice(1); }
    if (input.length >= 4 && input.charCodeAt(0) === 0x50 && input.charCodeAt(1) === 0x4b && input.charCodeAt(2) === 3 && input.charCodeAt(3) === 4) return { format: "zip", confidence: 1, bom, encoding };
    if (input.length >= 2 && input.charCodeAt(0) === 0x1f && input.charCodeAt(1) === 0x8b) return { format: "gzip", confidence: 1, bom, encoding };
    truncated = input.length > sample;
    text = truncated ? input.slice(0, sample) : input;
  } else {
    const u8 = toU8(input);
    if (u8.length >= 4 && u8[0] === 0x50 && u8[1] === 0x4b && u8[2] === 3 && u8[3] === 4) return { format: "zip", confidence: 1, bom: false, encoding: "binary" };
    if (u8.length >= 2 && u8[0] === 0x1f && u8[1] === 0x8b) return { format: "gzip", confidence: 1, bom: false, encoding: "binary" };
    const enc = detectEncoding(u8);
    bom = enc.bom; encoding = enc.encoding;
    truncated = u8.length > sample;
    text = decodeText(truncated ? u8.subarray(0, sample) : u8);
  }
  const res = (format, confidence, extra) => Object.assign({ format, confidence: Math.round(confidence * 1000) / 1000, bom, encoding }, extra || {});

  if (!text.trim()) return res("unknown", 0);
  if (looksBinary(text)) return res("unknown", 0);

  const first = text.search(/\S/);
  const c0 = text[first];
  const lines = nonEmptyLines(text);

  // JSON / NDJSON
  if (c0 === "[" || c0 === "{") {
    const whole = truncated ? undefined : tryJson(text);
    if (whole !== undefined) return res("json", 1);
    const cand = truncated ? lines.slice(0, -1) : lines;
    if (cand.length >= 2) {
      let ok = 0, firstOk = false;
      cand.forEach((l, i) => { const v = tryJson(l); const good = v !== null && typeof v === "object"; if (good) { ok++; if (i === 0) firstOk = true; } });
      const sh = ok / cand.length;
      if (sh === 1 || (firstOk && sh >= 0.8)) return res("ndjson", sh);
    }
    if (truncated) return res("json", 0.6);
  }

  // XML
  if (/^\s*<\?xml/.test(text) || RE.evt.test(text) || /^\s*<[A-Za-z!]/.test(text)) return res(RE.evt.test(text) ? "evtx-xml" : "xml", 1);

  // Line-oriented security / web / system logs
  if (lines.some((l) => RE.cef.test(l))) return res("cef", share(lines, RE.cef));
  if (lines.some((l) => RE.leef.test(l))) return res("leef", share(lines, RE.leef));
  if (/^#(Fields|Software):/m.test(text)) return res("iis", share(lines, RE.iisLine));
  if (lines.some((l) => RE.clf.test(l))) return res("clf", share(lines, RE.clf));
  if (lines.some((l) => RE.syslog.test(l))) return res("syslog", share(lines, RE.syslog));

  // Config / IaC
  if (lines.some((l) => RE.hclBlock.test(l))) return res("hcl", share(lines, RE.hclLine));
  const vote = voteDelimiter(lines.slice(0, 20));
  if (lines.some((l) => RE.yamlHard.test(l))) return res("yaml", share(lines, RE.yamlLine));
  if (!vote && lines.filter((l) => RE.yamlKey.test(l)).length >= 3) return res("yaml", share(lines, RE.yamlLine));

  // Delimited
  if (vote) return res(vote.delimiter === "\t" ? "tsv" : "csv", vote.share, { delimiter: vote.delimiter });

  return res("unknown", 0);
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------
// Pick the delimiter with the most unquoted occurrences on the first line.
export function sniffDelimiter(text) {
  const head = String(text || "").split(/\r?\n/, 1)[0] || "";
  const counts = { ",": 0, ";": 0, "\t": 0, "|": 0 };
  let q = false;
  for (const c of head) { if (c === '"') q = !q; else if (!q && c in counts) counts[c]++; }
  let best = ",", bestN = -1;
  for (const k of Object.keys(counts)) if (counts[k] > bestN) { best = k; bestN = counts[k]; }
  return bestN > 0 ? best : ",";
}

// RFC 4180 row generator: quoted fields with embedded delimiters, quotes and
// newlines, CRLF, optional UTF-8 BOM. All-empty rows are skipped.
function* iterCsvRows(text, delimiter) {
  let s = String(text || "");
  if (s.charCodeAt(0) === 0xfeff) s = s.slice(1);
  const d = delimiter || sniffDelimiter(s);
  const n = s.length;
  let i = 0, row = [], field = "", quoted = false, any = false, sawQuote = false, fstart = true;
  while (i < n) {
    const c = s[i];
    if (quoted) {
      if (c === '"') {
        if (s[i + 1] === '"') { field += '"'; i += 2; continue; }
        quoted = false; i++; continue;
      }
      field += c; i++; continue;
    }
    // A quote opens a quoted field only at the field's start; mid-field (5" rack) it is literal,
    // or it would swallow every following row up to the next quote.
    if (c === '"' && fstart) { quoted = true; any = true; sawQuote = true; fstart = false; i++; continue; }
    if (c === d) { row.push(field); field = ""; any = true; fstart = true; i++; continue; }
    if (c === "\r" || c === "\n") { // CRLF, LF, or a lone CR (classic Mac line endings) ends the record
      if (c === "\r" && s[i + 1] === "\n") i++;
      row.push(field); field = ""; i++;
      // Skip a truly blank line, but keep a row of explicitly-quoted empty fields ("","")
      // — the quote marks it as a real record, unlike a bare `,` or an empty line.
      if (any || row.length > 1 || row[0] !== "") { if (sawQuote || row.some((f) => f !== "")) yield row; }
      row = []; any = false; sawQuote = false; fstart = true; continue;
    }
    field += c; any = true; fstart = false; i++;
  }
  if (any || field !== "" || row.length) { row.push(field); if (sawQuote || row.some((f) => f !== "")) yield row; }
}

// Trimmed, de-duplicated header keys ("a", "a_2", "a_3").
function headerKeys(row) {
  const seen = Object.create(null), last = Object.create(null), out = []; // a "__proto__" header must count as seen
  for (const h of row) {
    const base = String(h).trim();
    // resume after the last suffix tried for this name: restarting at _2 each time made 8000 repeats quadratic
    let k = base, n = Object.prototype.hasOwnProperty.call(last, base) ? last[base] : 1;
    while (Object.prototype.hasOwnProperty.call(seen, k)) k = `${base}_${++n}`; // a,a,a_2 -> a, a_2, a_2_2 (never a repeat)
    seen[k] = 1; last[base] = n; out.push(k);
  }
  return out;
}

function rowToObject(keys, row) {
  const o = {};
  // defineProperty, so a "__proto__" column is kept as data instead of setting the prototype
  for (let i = 0; i < keys.length; i++) Object.defineProperty(o, keys[i], { value: row[i] === undefined ? "" : row[i], enumerable: true, writable: true, configurable: true });
  for (let i = keys.length; i < row.length; i++) o[`_${i + 1}`] = row[i];
  return o;
}

// Iterate CSV rows. `header=true` yields objects keyed by the first row,
// `header=false` yields arrays. Delimiter auto-detected when omitted.
export function* iterCsv(text, { delimiter, header = true } = {}) {
  const it = iterCsvRows(text, delimiter);
  if (!header) { yield* it; return; }
  const h = it.next();
  if (h.done) return;
  const keys = headerKeys(h.value);
  for (const row of it) yield rowToObject(keys, row);
}

// Convenience: { headers, rows } with rows as objects.
export function parseCsv(text, opts = {}) {
  const it = iterCsvRows(text, opts.delimiter);
  const h = it.next();
  if (h.done) return { headers: [], rows: [] };
  const headers = headerKeys(h.value);
  const rows = [];
  for (const row of it) rows.push(rowToObject(headers, row));
  return { headers, rows };
}

// ---------------------------------------------------------------------------
// JSON / NDJSON
// ---------------------------------------------------------------------------
// One JSON value per line; blank lines skipped; errors carry the 1-based line.
export function* iterNdjson(text) {
  const lines = String(text || "").replace(/^\uFEFF/, "").split(/\r\n|\r|\n/);
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (!l.trim()) continue;
    let v;
    try { v = JSON.parse(l); } catch (e) { throw new Error(`NDJSON parse error at line ${i + 1}: ${e.message}`); }
    yield v;
  }
}

// Unwrap the common export shapes: a bare array, or an object carrying the
// array under value / events / items / data / records / results (any case,
// e.g. CloudTrail "Records"). A plain object becomes [obj]. Multi-line input
// that is not one JSON document is read as NDJSON.
export function iterJson(text) {
  const s = String(text || "").replace(/^\uFEFF/, "");
  let o;
  try { o = JSON.parse(s); } catch (e) {
    if (nonEmptyLines(s, 2).length >= 2) return Array.from(iterNdjson(s));
    throw e;
  }
  if (Array.isArray(o)) return o;
  if (o === null || typeof o !== "object") return [o];
  for (const k of Object.keys(o)) if (WRAP_KEYS.includes(k.toLowerCase()) && Array.isArray(o[k])) return o[k];
  return [o];
}

// Dispatch on format (sniffed when omitted). Returns an iterable of records
// for csv / tsv / json / ndjson, or null for formats this kit does not
// turn into records (logs, xml, config) so callers can delegate.
export function iterRecords(text, fmt) {
  const s = decodeText(text);
  let delimiter;
  if (!fmt) { const r = sniff(s); fmt = r.format; delimiter = r.delimiter; }
  else if (fmt === "tsv") delimiter = "\t";
  switch (fmt) {
    case "csv": case "tsv": return iterCsv(s, { delimiter });
    case "json": return iterJson(s);
    case "ndjson": return iterNdjson(s);
    default: return null;
  }
}

// ---------------------------------------------------------------------------
// XML
// ---------------------------------------------------------------------------
const ENTITY = /&(amp|lt|gt|quot|apos|#x[0-9a-fA-F]+|#\d+);/g;
const ENT_MAP = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };

function decodeEntities(s) {
  if (s.indexOf("&") < 0) return s;
  return s.replace(ENTITY, (_, e) => {
    if (e in ENT_MAP) return ENT_MAP[e];
    const cp = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
    return Number.isFinite(cp) && cp >= 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : "";
  });
}

function parseAttrs(s) {
  const attrs = {};
  const re = /([^\s=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g;
  let m;
  while ((m = re.exec(s))) put(attrs, m[1], decodeEntities(m[2] !== undefined ? m[2] : m[3] !== undefined ? m[3] : m[4] !== undefined ? m[4] : ""));
  return attrs;
}

function mkNode(tag) { return { tag, attrs: {}, children: [], text: "" }; }

// Tolerant XML tree: {tag, attrs, children, text}. Handles prolog, comments,
// DOCTYPE, CDATA, self-closing tags and the five named entities plus numeric
// ones; namespace prefixes are kept in the tag name. `text` is the trimmed
// direct text of the element. Several top-level elements (concatenated
// <Event> dumps) are returned under a synthetic "#document" node.
export function xmlLite(text) {
  const s = String(text || "").replace(/^\uFEFF/, "");
  const n = s.length;
  const root = mkNode("#document");
  const stack = [root];
  let i = 0;
  while (i < n) {
    const top = stack[stack.length - 1];
    const lt = s.indexOf("<", i);
    if (lt < 0) { top.text += decodeEntities(s.slice(i)); break; }
    if (lt > i) top.text += decodeEntities(s.slice(i, lt));
    if (s.startsWith("<!--", lt)) { const e = s.indexOf("-->", lt + 4); i = e < 0 ? n : e + 3; continue; }
    if (s.startsWith("<![CDATA[", lt)) { const e = s.indexOf("]]>", lt + 9); top.text += s.slice(lt + 9, e < 0 ? n : e); i = e < 0 ? n : e + 3; continue; }
    if (s.startsWith("<?", lt)) { const e = s.indexOf("?>", lt + 2); i = e < 0 ? n : e + 2; continue; }
    if (s.startsWith("<!", lt)) {
      let j = lt + 2, depth = 0;
      while (j < n) { const c = s[j]; if (c === "[") depth++; else if (c === "]") depth--; else if (c === ">" && depth <= 0) break; j++; }
      i = j + 1; continue;
    }
    if (s[lt + 1] === "/") {
      const e = s.indexOf(">", lt);
      const name = s.slice(lt + 2, e < 0 ? n : e).trim();
      for (let k = stack.length - 1; k > 0; k--) if (stack[k].tag === name) { stack.length = k; break; }
      i = e < 0 ? n : e + 1; continue;
    }
    let j = lt + 1, q = null;
    while (j < n) { const c = s[j]; if (q) { if (c === q) q = null; } else if (c === '"' || c === "'") q = c; else if (c === ">") break; j++; }
    const inner = s.slice(lt + 1, j);
    const selfClose = inner.endsWith("/");
    const body = selfClose ? inner.slice(0, -1) : inner;
    const m = body.match(/^\s*([^\s/>]+)([\s\S]*)$/);
    i = j + 1;
    if (!m) continue;
    const node = mkNode(m[1]);
    node.attrs = parseAttrs(m[2]);
    top.children.push(node);
    if (!selfClose) stack.push(node);
  }
  const trim = (nd) => { nd.text = nd.text.trim(); nd.children.forEach(trim); };
  trim(root);
  return root.children.length === 1 && !root.text ? root.children[0] : root;
}

// DOMParser when the runtime has one (falls back to xmlLite on parser errors
// such as concatenated roots); xmlLite otherwise.
export function parseXml(text) {
  if (typeof DOMParser !== "undefined") {
    const doc = new DOMParser().parseFromString(String(text || "").replace(/^\uFEFF/, ""), "application/xml");
    if (!doc.getElementsByTagName("parsererror").length) return doc;
  }
  return xmlLite(text);
}

const isDom = (node) => !!node && typeof node.nodeType === "number";
const tagMatches = (name, tag) => name === tag || (name.indexOf(":") > 0 && name.slice(name.indexOf(":") + 1) === tag);

function* walkLite(node) {
  for (const c of node.children || []) { yield c; yield* walkLite(c); }
}

// Descendant lookups that accept both xmlLite nodes and DOM nodes.
export function xmlFindAll(node, tag) {
  if (!node) return [];
  const out = [];
  if (isDom(node)) {
    const all = node.getElementsByTagName ? node.getElementsByTagName("*") : [];
    for (let i = 0; i < all.length; i++) { const el = all[i]; if (tagMatches(el.nodeName, tag) || el.localName === tag) out.push(el); }
    return out;
  }
  for (const c of walkLite(node)) if (tagMatches(c.tag, tag)) out.push(c);
  return out;
}

export function xmlFind(node, tag) {
  if (!node) return null;
  if (isDom(node)) { const all = xmlFindAll(node, tag); return all.length ? all[0] : null; }
  for (const c of walkLite(node)) if (tagMatches(c.tag, tag)) return c;
  return null;
}

export function xmlText(node) {
  if (!node) return "";
  if (isDom(node)) return String(node.textContent || "").trim();
  if (!node.children || !node.children.length) return node.text || "";
  return [node.text, ...node.children.map(xmlText)].filter(Boolean).join("").trim();
}

// ---------------------------------------------------------------------------
// Header matching
// ---------------------------------------------------------------------------
// Lower-case, drop bracketed / parenthesised suffixes ("[Required]"), drop
// non-alphanumerics.
export function normHeader(h) {
  return String(h || "").toLowerCase().replace(/\[[^\]]*\]/g, "").replace(/\([^)]*\)/g, "").replace(/[^a-z0-9]/g, "");
}

// First header matching any alias, alias order wins. Returns the original header.
export function findColumn(headers, aliases) {
  const norm = (headers || []).map((h) => ({ h, n: normHeader(h) }));
  for (const a of aliases || []) {
    const want = normHeader(a);
    if (!want) continue;
    const hit = norm.find((x) => x.n === want);
    if (hit) return hit.h;
  }
  return null;
}

// spec = { key: [aliases] } -> { found: { key: header }, missing: [key] }.
export function mapColumns(headers, spec) {
  const found = {}, missing = [];
  for (const k of Object.keys(spec || {})) {
    const h = findColumn(headers, spec[k]);
    if (h === null) missing.push(k); else found[k] = h;
  }
  return { found, missing };
}

// Flatten nested objects to dot-path keys. Arrays of primitives are joined
// with ", "; arrays holding objects are indexed ("a.0.b").
export function flatten(o, prefix = "", out = {}) {
  if (o == null || typeof o !== "object") { put(out, prefix, o); return out; }
  if (Array.isArray(o)) {
    if (o.every((v) => v == null || typeof v !== "object")) { put(out, prefix, o.map((v) => (v == null ? "" : String(v))).join(", ")); return out; }
    o.forEach((v, i) => flatten(v, prefix ? `${prefix}.${i}` : String(i), out));
    return out;
  }
  for (const k of Object.keys(o)) flatten(o[k], prefix ? `${prefix}.${k}` : k, out);
  return out;
}

// ---------------------------------------------------------------------------
// CEF / LEEF
// ---------------------------------------------------------------------------
// Split on unescaped "|" (backslash escapes kept for a later unescape pass).
function splitPipes(s, max) {
  const parts = []; let cur = "";
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "\\" && i + 1 < s.length) { cur += c + s[i + 1]; i++; continue; }
    if (c === "|" && (!max || parts.length < max - 1)) { parts.push(cur); cur = ""; continue; }
    cur += c;
  }
  parts.push(cur);
  return parts;
}

const unescHeader = (s) => s.replace(/\\(.)/g, (_, c) => (c === "n" ? "\n" : c === "r" ? "\r" : c));
const unescExt = (s) => s.replace(/\\(.)/g, (_, c) => (c === "n" ? "\n" : c === "r" ? "\r" : c === "t" ? "\t" : c));

// key=value pairs separated by whitespace; values may contain spaces, "\=" and
// "\\" escapes. The key of each pair is the token just before an unescaped "=".
function parseKvExtension(s) {
  const ext = {};
  const eqs = [];
  for (let i = 0; i < s.length; i++) { if (s[i] === "\\") { i++; continue; } if (s[i] === "=") eqs.push(i); }
  const keyStart = (p) => { let k = p - 1; while (k >= 0 && !/\s/.test(s[k])) k--; return k + 1; };
  // many vendors leave "=" inside values unescaped (request=http://x/?a=b): an "=" only starts a
  // new pair when the word before it is a key, otherwise it belongs to the current value
  for (let e = eqs.length - 1; e >= 0; e--) if (!/^[A-Za-z0-9_.\-[\]]+$/.test(s.slice(keyStart(eqs[e]), eqs[e]))) eqs.splice(e, 1);
  for (let e = 0; e < eqs.length; e++) {
    const p = eqs[e];
    const ks = keyStart(p);
    const key = s.slice(ks, p);
    if (!key) continue;
    const end = e + 1 < eqs.length ? keyStart(eqs[e + 1]) : s.length;
    put(ext, unescExt(key), unescExt(s.slice(p + 1, end).replace(/\s+$/, "")));
  }
  return ext;
}

const sevNum = (s) => (/^\d+$/.test(s) ? Number(s) : s);

// ArcSight CEF: [prefix|]CEF:V|vendor|product|version|sigId|name|severity|ext
export function parseCef(line) {
  const s = String(line || "").trim();
  const m = s.match(/^(?:(.*?)[|\s])?CEF:(\d+)\|/);
  if (!m) return null;
  const start = m[0].length;
  const parts = splitPipes(s.slice(start), 7);
  if (parts.length < 7) return null;
  const [vendor, product, deviceVersion, signatureId, name, severity, ext] = parts;
  return {
    prefix: m[1] || null,
    version: Number(m[2]),
    vendor: unescHeader(vendor), product: unescHeader(product), deviceVersion: unescHeader(deviceVersion),
    signatureId: unescHeader(signatureId), name: unescHeader(name), severity: sevNum(unescHeader(severity)),
    ext: parseKvExtension(ext || ""),
  };
}

// IBM LEEF: [prefix|]LEEF:V|vendor|product|version|eventId|[delimiter|]attrs
// LEEF 2.0 carries an optional delimiter field (a literal char or "x09"/"0x09");
// LEEF 1.0 and an empty field mean tab.
export function parseLeef(line) {
  const s = String(line || "").trim();
  const m = s.match(/^(?:(.*?)[|\s])?LEEF:(\d+(?:\.\d+)?)\|/);
  if (!m) return null;
  const version = m[2];
  const rest = s.slice(m[0].length);
  const is2 = parseFloat(version) >= 2;
  const parts = splitPipes(rest, is2 ? 6 : 5);
  if (parts.length < 5) return null;
  const [vendor, product, deviceVersion, eventId] = parts;
  let delimiter = "\t", attrs;
  // the 2.0 delimiter field is optional: a sixth field means attrs held a "|" when parts[4] is itself attrs (has "=")
  if (is2 && parts.length === 6 && parts[4].includes("=")) attrs = parts[4] + "|" + parts[5];
  else if (is2 && parts.length === 6) {
    const d = parts[4];
    attrs = parts[5];
    if (d === "") delimiter = "\t";
    else if (/^(0?x)[0-9a-fA-F]{1,4}$/.test(d)) delimiter = String.fromCharCode(parseInt(d.replace(/^0?x/, ""), 16));
    else delimiter = d.length === 1 ? d : "\t";
  } else attrs = parts[4] || "";
  const ext = {};
  for (const tok of attrs.split(delimiter)) {
    if (!tok.trim()) continue;
    const eq = tok.indexOf("=");
    if (eq < 0) continue;
    put(ext, tok.slice(0, eq).trim(), unescExt(tok.slice(eq + 1)));
  }
  return {
    prefix: m[1] || null, version, vendor: unescHeader(vendor), product: unescHeader(product),
    deviceVersion: unescHeader(deviceVersion), eventId: unescHeader(eventId), delimiter, ext,
  };
}

// ---------------------------------------------------------------------------
// YAML subset
// ---------------------------------------------------------------------------
// Block mappings and sequences by indentation, one-level-or-deeper flow
// collections, quoted / plain scalars, "|" and ">" block scalars, comments,
// "---" documents. Local tags ("!Ref x", CloudFormation) become
// { "!Ref": x }. Anchors, aliases and "!!" tags throw.
const yErr = (msg, ln) => new Error(`YAML: ${msg} (line ${ln})`);
const indentOf = (l) => l.length - l.replace(/^ */, "").length;
const isBlankOrComment = (l) => !l.trim() || /^\s*#/.test(l);

// Remove a trailing " # comment" outside quotes. Quotes only count when they
// open a token, so apostrophes inside plain scalars do not confuse it.
function stripComment(s) {
  let q = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { if (c === q) q = null; continue; }
    if ((c === '"' || c === "'") && (i === 0 || /[\s:,\[{-]/.test(s[i - 1]))) { q = c; continue; }
    if (c === "#" && (i === 0 || /\s/.test(s[i - 1]))) return s.slice(0, i).trimEnd();
  }
  return s.trimEnd(); // same \s set as /\s+$/, which was quadratic on a long run of inner whitespace
}

function closingQuote(s, from) {
  const q = s[from];
  for (let i = from + 1; i < s.length; i++) {
    if (q === '"' && s[i] === "\\") { i++; continue; }
    if (s[i] === q) { if (q === "'" && s[i + 1] === "'") { i++; continue; } return i; }
  }
  return -1;
}

// "key: rest" / "key:" detection on a comment-stripped line fragment.
function keyMatch(c) {
  if (!c) return null;
  const f = c[0];
  if (f === '"' || f === "'") {
    const e = closingQuote(c, 0);
    if (e < 0) return null;
    const after = c.slice(e + 1);
    const m = after.match(/^\s*:(?:\s+(.*)|\s*)$/);
    if (!m) return null;
    return { key: yScalar(c.slice(0, e + 1)), rest: (m[1] || "").trim() };
  }
  if ("[{&*!|>%@`".indexOf(f) >= 0 || (f === "-" && (c.length === 1 || /\s/.test(c[1])))) return null;
  for (let j = 0; j < c.length; j++) {
    if (c[j] === ":" && (j + 1 === c.length || /\s/.test(c[j + 1]))) {
      const key = c.slice(0, j).trim();
      if (!key) return null;
      return { key, rest: c.slice(j + 1).trim() };
    }
  }
  return null;
}

const isSeqItem = (c) => c === "-" || c.startsWith("- ") || c.startsWith("-\t");

function unquoteDouble(s) {
  return s.replace(/\\(u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)/g, (_, e) => {
    if (e[0] === "u" || e[0] === "x") return String.fromCharCode(parseInt(e.slice(1), 16));
    return { n: "\n", t: "\t", r: "\r", "0": "\0", b: "\b", f: "\f", "/": "/", "\\": "\\", '"': '"', " ": " " }[e] ?? e;
  });
}

function yScalar(s) {
  s = s.trim();
  if (s === "") return null;
  if (s[0] === '"') { const e = closingQuote(s, 0); return unquoteDouble(s.slice(1, e < 0 ? s.length : e)); }
  if (s[0] === "'") { const e = closingQuote(s, 0); return s.slice(1, e < 0 ? s.length : e).replace(/''/g, "'"); }
  if (/^(true|True|TRUE)$/.test(s)) return true;
  if (/^(false|False|FALSE)$/.test(s)) return false;
  if (/^(null|Null|NULL|~)$/.test(s)) return null;
  if (/^[-+]?(0|[1-9][0-9]*)$/.test(s)) return parseInt(s, 10);
  if (/^0x[0-9a-fA-F]+$/.test(s)) return parseInt(s.slice(2), 16);
  if (/^0o[0-7]+$/.test(s)) return parseInt(s.slice(2), 8);
  if (/^[-+]?0\d+$/.test(s)) return s;                      // zero-padded (zip code, id, version pin) — keep as string, not a number
  if (/^[-+]?(\d+\.\d*|\.\d+|\d+)([eE][-+]?\d+)?$/.test(s)) return parseFloat(s);
  if (/^[-+]?\.(inf|Inf|INF)$/.test(s)) return s[0] === "-" ? -Infinity : Infinity;
  if (/^\.(nan|NaN|NAN)$/.test(s)) return NaN;
  return s;
}

// Flow collections: [a, b, {k: v}] and {k: v, k2: [x]}; nests freely.
function parseFlow(src, ln) {
  let p = 0;
  const ws = () => { while (p < src.length && /\s/.test(src[p])) p++; };
  const plainUntil = (stops) => { const a = p; while (p < src.length && stops.indexOf(src[p]) < 0) p++; return src.slice(a, p); };
  const value = (inMap) => {
    ws();
    const c = src[p];
    if (c === "[") {
      p++; const out = [];
      for (;;) { ws(); if (p >= src.length) throw yErr("unterminated flow sequence", ln); if (src[p] === "]") { p++; break; } out.push(value(false)); ws(); if (src[p] === ",") p++; else if (src[p] !== "]") throw yErr("expected , or ] in flow sequence", ln); }
      return out;
    }
    if (c === "{") {
      p++; const out = {};
      for (;;) {
        ws(); if (p >= src.length) throw yErr("unterminated flow mapping", ln); if (src[p] === "}") { p++; break; }
        let key;
        if (src[p] === '"' || src[p] === "'") { const e = closingQuote(src, p); key = yScalar(src.slice(p, e + 1)); p = e + 1; }
        else key = plainUntil(":,}").trim();
        ws();
        put(out, key, src[p] === ":" ? (p++, value(true)) : null);
        ws(); if (src[p] === ",") p++; else if (src[p] !== "}") throw yErr("expected , or } in flow mapping", ln);
      }
      return out;
    }
    if (c === '"' || c === "'") { const e = closingQuote(src, p); if (e < 0) throw yErr("unterminated quoted scalar", ln); const v = yScalar(src.slice(p, e + 1)); p = e + 1; return v; }
    if (c === "&" || c === "*") throw yErr("anchors and aliases are not supported", ln);
    if (src.startsWith("!!", p)) throw yErr("!! tags are not supported", ln);
    return yScalar(plainUntil(inMap ? ",}" : ",]}"));
  };
  const v = value(false);
  ws();
  if (p < src.length) throw yErr("trailing content after flow collection", ln);
  return v;
}

function flowBalanced(s) {
  let depth = 0, q = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { if (c === "\\" && q === '"') i++; else if (c === q) q = null; continue; }
    if (c === '"' || c === "'") q = c;
    else if (c === "[" || c === "{") depth++;
    else if (c === "]" || c === "}") depth--;
  }
  return depth <= 0 && !q;
}

function skipBlank(L, i) { while (i < L.length && isBlankOrComment(L[i])) i++; return i; }

// Block scalar after "|" / ">" with chomping and indentation indicators.
function parseBlockScalar(L, i, indent, indicator, ln) {
  const m = indicator.match(/^([|>])([+-]?)(\d*)([+-]?)\s*$/);
  if (!m) throw yErr("bad block scalar indicator", ln);
  const literal = m[1] === "|";
  const chomp = m[2] || m[4] || "";
  const explicit = m[3] ? indent + parseInt(m[3], 10) : 0;
  const raw = [];
  while (i < L.length && (!L[i].trim() || indentOf(L[i]) > indent)) raw.push(L[i]), i++;
  let bi = explicit;
  if (!bi) { const f = raw.find((l) => l.trim()); bi = f ? indentOf(f) : indent + 1; }
  const lines = raw.map((l) => (l.trim() ? l.slice(bi) : ""));
  let trailing = 0;
  while (lines.length && lines[lines.length - 1] === "") { lines.pop(); trailing++; }
  let body = "";
  if (literal) body = lines.join("\n");
  else {
    let pending = 0, started = false, prevMore = false;
    for (const l of lines) {
      if (l === "") { pending++; continue; }
      const more = /^[ \t]/.test(l);
      if (!started) body = l;
      else if (pending === 0 && !more && !prevMore) body += " " + l;
      else body += "\n".repeat(pending + (more || prevMore ? 1 : 0)) + l;
      pending = 0; started = true; prevMore = more;
    }
  }
  if (chomp === "-") return [body, i];
  if (chomp === "+") return [body + "\n" + "\n".repeat(trailing), i];
  return [body ? body + "\n" : "", i];
}

// Value after "key:" or "- ". `rest` is the inline part; nested blocks follow
// on deeper lines (or a sequence at the same indent when `sameSeq`).
function parseValue(L, i, indent, rest, ln, sameSeq) {
  if (rest === "") {
    const j = skipBlank(L, i);
    if (j < L.length) {
      const ind = indentOf(L[j]);
      if (ind > indent) return parseBlock(L, j, ind);
      if (sameSeq && ind === indent && isSeqItem(stripComment(L[j].slice(ind)))) return parseSeq(L, j, indent);
    }
    return [null, i];
  }
  const f = rest[0];
  if (f === "|" || f === ">") return parseBlockScalar(L, i, indent, rest, ln);
  if (f === "&" || f === "*") throw yErr("anchors and aliases are not supported", ln);
  if (rest.startsWith("!!")) throw yErr("!! tags are not supported", ln);
  if (f === "!") {
    const m = rest.match(/^(![\w:/.-]*)(?:\s+(.*))?$/);
    if (!m) throw yErr("bad tag", ln);
    const [v, ni] = parseValue(L, i, indent, (m[2] || "").trim(), ln, sameSeq);
    return [{ [m[1]]: v }, ni];
  }
  if (f === "[" || f === "{") {
    let s = rest, j = i;
    while (!flowBalanced(s) && j < L.length) { s += " " + stripComment(L[j].trim()); j++; }
    return [parseFlow(s, ln), j];
  }
  if (f !== '"' && f !== "'") {
    // plain multi-line scalar: continuation lines indented deeper, no key shape
    let j = i, acc = rest;
    while (j < L.length && L[j].trim() && indentOf(L[j]) > indent) {
      const c = stripComment(L[j].trim());
      if (keyMatch(c) || isSeqItem(c)) break;
      acc += " " + c; j++;
    }
    return [yScalar(acc), j];
  }
  return [yScalar(rest), i];
}

function parseMap(L, i, indent) {
  const out = {};
  for (;;) {
    i = skipBlank(L, i);
    if (i >= L.length) break;
    const ind = indentOf(L[i]);
    if (ind < indent) break;
    if (ind > indent) throw yErr("bad indentation", i + 1);
    const c = stripComment(L[i].slice(ind));
    if (isSeqItem(c)) break;
    const m = keyMatch(c);
    if (!m) throw yErr(`expected "key:" but found "${c.slice(0, 40)}"`, i + 1);
    const ln = i + 1;
    const [v, ni] = parseValue(L, i + 1, indent, m.rest, ln, true);
    put(out, m.key, v);
    i = ni;
  }
  return [out, i];
}

function parseSeq(L, i, indent) {
  const out = [];
  for (;;) {
    i = skipBlank(L, i);
    if (i >= L.length) break;
    const ind = indentOf(L[i]);
    if (ind < indent) break;
    if (ind > indent) throw yErr("bad indentation", i + 1);
    const c = stripComment(L[i].slice(ind));
    if (!isSeqItem(c)) break;
    const rest = c.slice(1).trim();
    const ln = i + 1;
    if (rest && (isSeqItem(rest) || keyMatch(rest))) {
      // compact nested collection: blank out the dash and re-read the line as a deeper block
      const off = L[i].indexOf(rest, ind + 1);
      L[i] = " ".repeat(off) + L[i].slice(off);
      const [v, ni] = parseBlock(L, i, off);
      out.push(v); i = ni; continue;
    }
    const [v, ni] = parseValue(L, i + 1, indent, rest, ln, false);
    out.push(v); i = ni;
  }
  return [out, i];
}

function parseBlock(L, i, indent) {
  const c = stripComment(L[i].slice(indent));
  if (isSeqItem(c)) return parseSeq(L, i, indent);
  if (keyMatch(c)) return parseMap(L, i, indent);
  return parseValue(L, i + 1, indent - 1, c, i + 1, false);
}

function parseYamlDoc(lines) {
  const L = lines.slice();
  const i = skipBlank(L, 0);
  if (i >= L.length) return null;
  const [v, ni] = parseBlock(L, i, indentOf(L[i]));
  const rest = skipBlank(L, ni);
  if (rest < L.length) throw yErr(`unexpected content "${L[rest].trim().slice(0, 40)}"`, rest + 1);
  return v;
}

export function parseYamlSubset(text) {
  const src = String(text || "").replace(/^\uFEFF/, "").split(/\r?\n/);
  const docs = []; let cur = [];
  for (const raw of src) {
    if (/^---(\s|$)/.test(raw)) { docs.push(cur); cur = []; const rest = raw.slice(3).trim(); if (rest && !rest.startsWith("#")) cur.push(rest); continue; }
    if (/^\.\.\.(\s|$)/.test(raw)) { docs.push(cur); cur = []; continue; }
    if (raw[0] === "%" && cur.every((l) => !l.trim())) continue;
    cur.push(raw.replace(/\t/g, "  "));
  }
  docs.push(cur);
  const parsed = docs.filter((d) => d.some((l) => !isBlankOrComment(l))).map(parseYamlDoc);
  return parsed.length > 1 ? parsed : parsed.length ? parsed[0] : null;
}

// ---------------------------------------------------------------------------
// HCL2 subset (Terraform)
// ---------------------------------------------------------------------------
const hErr = (msg, ln) => new Error(`HCL: ${msg} (line ${ln})`);
const HCL_OPS2 = ["==", "!=", "<=", ">=", "&&", "||", "=>"];

function hclTokens(src) {
  const toks = [];
  const n = src.length;
  let i = 0, line = 1;
  const push = (t, v, s, e, extra) => toks.push(Object.assign({ t, v, s, e, line }, extra || {}));
  while (i < n) {
    const c = src[i];
    if (c === "\n") { push("nl", "\n", i, i + 1); line++; i++; continue; }
    if (c === " " || c === "\t" || c === "\r") { i++; continue; }
    if (c === "#" || (c === "/" && src[i + 1] === "/")) { while (i < n && src[i] !== "\n") i++; continue; }
    if (c === "/" && src[i + 1] === "*") {
      const e = src.indexOf("*/", i + 2); const end = e < 0 ? n : e + 2;
      for (let k = i; k < end; k++) if (src[k] === "\n") line++;
      i = end; continue;
    }
    if (c === "<" && src[i + 1] === "<") {
      const m = /^<<(-?)([A-Za-z_][\w-]*)[ \t]*\r?\n/.exec(src.slice(i));
      if (m) {
        const start = i;
        let p = i + m[0].length;
        const marker = m[2];
        const body = [];
        let closed = false;
        for (;;) {
          if (p >= n) break;
          const eol = src.indexOf("\n", p);
          const ln = src.slice(p, eol < 0 ? n : eol).replace(/\r$/, "");
          if (ln.trim() === marker) { closed = true; p = eol < 0 ? n : eol; break; }
          body.push(ln); p = eol < 0 ? n : eol + 1;
          if (eol < 0) break;
        }
        if (!closed) throw hErr(`unterminated heredoc <<${marker}`, line);
        let lines = body;
        if (m[1] === "-") {
          const ind = Math.min(...lines.filter((l) => l.trim()).map(indentOf), Infinity);
          if (Number.isFinite(ind)) lines = lines.map((l) => l.slice(Math.min(ind, indentOf(l))));
        }
        push("str", lines.join("\n") + "\n", start, p, { heredoc: true });
        line += body.length + 1;
        i = p; continue;
      }
    }
    if (c === '"') {
      let j = i + 1, depth = 0, out = "";
      while (j < n) {
        const ch = src[j];
        if (depth === 0 && ch === '"') break;
        if (ch === "\n") line++;
        if (depth === 0 && ch === "\\") {
          const nx = src[j + 1];
          out += nx === "n" ? "\n" : nx === "t" ? "\t" : nx === "r" ? "\r" : nx === undefined ? "" : nx;
          j += 2; continue;
        }
        if ((ch === "$" || ch === "%") && src[j + 1] === ch && src[j + 2] === "{") { out += ch + "{"; j += 3; continue; }
        if ((ch === "$" || ch === "%") && src[j + 1] === "{") { depth++; out += ch + "{"; j += 2; continue; }
        if (depth > 0 && ch === "{") depth++;
        if (depth > 0 && ch === "}") depth--;
        out += ch; j++;
      }
      if (j >= n) throw hErr("unterminated string", line);
      push("str", out, i, j + 1);
      i = j + 1; continue;
    }
    const num = /^\d+(?:\.\d+)?(?:[eE][-+]?\d+)?/.exec(src.slice(i, i + 64));
    if (num) { push("num", Number(num[0]), i, i + num[0].length); i += num[0].length; continue; }
    const id = /^[A-Za-z_][\w-]*/.exec(src.slice(i, i + 256));
    if (id) { push("id", id[0], i, i + id[0].length); i += id[0].length; continue; }
    const two = src.slice(i, i + 2);
    if (src.slice(i, i + 3) === "...") { push("p", "...", i, i + 3); i += 3; continue; }
    if (HCL_OPS2.includes(two)) { push("p", two, i, i + 2); i += 2; continue; }
    push("p", c, i, i + 1); i++;
  }
  push("eof", "", n, n);
  return toks;
}

const isOpen = (t) => t.t === "p" && (t.v === "(" || t.v === "[" || t.v === "{");
const isClose = (t) => t.t === "p" && (t.v === ")" || t.v === "]" || t.v === "}");

// Index just past an expression starting at p: stops at a depth-0 newline,
// ",", closing bracket or EOF.
function exprEnd(toks, p) {
  let depth = 0;
  for (let q = p; q < toks.length; q++) {
    const t = toks[q];
    if (t.t === "eof") return q;
    if (depth === 0 && (t.t === "nl" || (t.t === "p" && (t.v === "," || isClose(t))))) return q;
    if (isOpen(t)) depth++;
    else if (isClose(t)) depth--;
  }
  return toks.length - 1;
}

// Split [a, b) on depth-0 "," and newlines into non-empty sub-ranges.
function splitItems(toks, a, b) {
  const out = []; let depth = 0, start = a;
  for (let q = a; q < b; q++) {
    const t = toks[q];
    if (depth === 0 && (t.t === "nl" || (t.t === "p" && t.v === ","))) { if (q > start) out.push([start, q]); start = q + 1; continue; }
    if (isOpen(t)) depth++; else if (isClose(t)) depth--;
  }
  if (b > start) out.push([start, b]);
  return out;
}

const REF_RE = /^[A-Za-z_][\w-]*(?:\.(?:[\w-]+|\*)|\[(?:\d+|"[^"]*"|\*)\])*$/;

function parseExprRange(src, toks, a, b) {
  while (a < b && toks[a].t === "nl") a++;
  while (b > a && toks[b - 1].t === "nl") b--;
  if (a >= b) return null;
  const first = toks[a], last = toks[b - 1];
  const raw = src.slice(first.s, last.e).trim();
  if (b - a === 1) {
    if (first.t === "str") return first.v;
    if (first.t === "num") return first.v;
    if (first.t === "id") return first.v === "true" ? true : first.v === "false" ? false : first.v === "null" ? null : { ref: first.v };
    return { raw };
  }
  if (b - a === 2 && first.t === "p" && first.v === "-" && last.t === "num") return -last.v;
  const wraps = (o, c) => first.t === "p" && first.v === o && last.t === "p" && last.v === c && exprEnd(toks, a) === b;
  if (wraps("[", "]")) {
    if (toks[a + 1] && toks[a + 1].t === "id" && toks[a + 1].v === "for") return { raw };
    return splitItems(toks, a + 1, b - 1).map(([x, y]) => parseExprRange(src, toks, x, y));
  }
  if (wraps("{", "}")) {
    if (toks[a + 1] && toks[a + 1].t === "id" && toks[a + 1].v === "for") return { raw };
    const obj = {};
    for (const [x, y] of splitItems(toks, a + 1, b - 1)) {
      const k = toks[x], sep = toks[x + 1];
      if (!(k.t === "id" || k.t === "str" || k.t === "num") || !sep || sep.t !== "p" || (sep.v !== "=" && sep.v !== ":")) return { raw };
      put(obj, String(k.v), parseExprRange(src, toks, x + 2, y));
    }
    return obj;
  }
  if (REF_RE.test(raw)) return { ref: raw };
  return { raw: raw.replace(/\s*\n\s*/g, " ") };
}

function parseHclBody(src, toks, p, closed) {
  const attrs = {}, blocks = [];
  for (;;) {
    while (toks[p].t === "nl") p++;
    const t = toks[p];
    if (t.t === "eof") { if (closed) throw hErr("unexpected end of input, expected }", t.line); return [{ attrs, blocks }, p]; }
    if (t.t === "p" && t.v === "}") { if (!closed) throw hErr("unexpected }", t.line); return [{ attrs, blocks }, p + 1]; }
    if (t.t !== "id") throw hErr(`unexpected token "${src.slice(t.s, t.e)}"`, t.line);
    const nx = toks[p + 1];
    if (nx.t === "p" && nx.v === "=") {
      const end = exprEnd(toks, p + 2);
      put(attrs, t.v, parseExprRange(src, toks, p + 2, end));
      p = end;
      if (toks[p].t === "p" && toks[p].v === ",") p++;
      continue;
    }
    const labels = [];
    let q = p + 1;
    while (toks[q].t === "str" || toks[q].t === "id") labels.push(String(toks[q].v)), q++;
    if (!(toks[q].t === "p" && toks[q].v === "{")) throw hErr(`expected "=" or "{" after "${t.v}"`, t.line);
    const [body, np] = parseHclBody(src, toks, q + 1, true);
    blocks.push({ type: t.v, labels, attrs: body.attrs, blocks: body.blocks });
    p = np;
  }
}

// Terraform-style HCL2: blocks (type "label" ... { }), attributes, strings
// (interpolation kept raw), heredocs, lists, objects, numbers, booleans, null.
// Bare traversals become { ref }, anything else { raw }.
export function parseHcl(text) {
  const src = String(text || "").replace(/^\uFEFF/, "");
  const toks = hclTokens(src);
  const [body] = parseHclBody(src, toks, 0, false);
  return { blocks: body.blocks, attrs: body.attrs };
}
