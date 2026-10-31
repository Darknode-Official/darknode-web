// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Developer mini-tools. See _schema.md for the contract.
const S = (v) => (v == null ? "" : String(v));

function tryParseJSON(text) {
  try { return { ok: true, val: JSON.parse(text) }; } catch (e) { return { ok: false, err: e.message }; }
}

// Simple JSON path parser: a.b[0].c["x y"]
function parsePath(path) {
  const parts = [];
  let i = 0, n = path.length;
  let cur = "";
  const flush = () => { if (cur !== "") { parts.push(cur); cur = ""; } };
  while (i < n) {
    const c = path[i];
    if (c === ".") { flush(); i++; }
    else if (c === "[") {
      flush();
      let j = i + 1;
      if (path[j] === '"' || path[j] === "'") {
        const q = path[j]; j++;
        let s = "";
        while (j < n && path[j] !== q) { s += path[j]; j++; }
        parts.push(s);
        j++; // closing quote
      } else {
        let s = "";
        while (j < n && path[j] !== "]") { s += path[j]; j++; }
        parts.push(/^\d+$/.test(s) ? Number(s) : s);
      }
      if (path[j] === "]") j++;
      i = j;
    } else { cur += c; i++; }
  }
  flush();
  return parts;
}

// A key that would read as path syntax (a.b, x[0], "", a quote) is written ["a.b"], so
// {"a":{"b":1}} and {"a.b":1} flatten to different paths. Keys are set as own properties,
// so a "__proto__" key is kept; an empty root adds nothing.
function flattenObj(obj, prefix, out) {
  const put = (k, v) => Object.defineProperty(out, k, { value: v, writable: true, enumerable: true, configurable: true });
  if (obj !== null && typeof obj === "object") {
    const keys = Array.isArray(obj) ? obj.map((_, i) => i) : Object.keys(obj);
    if (keys.length === 0) { if (prefix) put(prefix, Array.isArray(obj) ? [] : {}); return out; }
    for (const k of keys) {
      const nk = Array.isArray(obj) ? `${prefix}[${k}]` : /^$|[.[\]"]/.test(k) ? `${prefix}[${JSON.stringify(k)}]` : (prefix ? `${prefix}.${k}` : String(k));
      flattenObj(obj[k], nk, out);
    }
  } else {
    put(prefix, obj);
  }
  return out;
}

function sortKeysDeep(obj, desc) {
  if (Array.isArray(obj)) return obj.map((x) => sortKeysDeep(x, desc));
  if (obj !== null && typeof obj === "object") {
    const keys = Object.keys(obj).sort((a, b) => desc ? b.localeCompare(a) : a.localeCompare(b));
    const out = {};
    for (const k of keys) out[k] = sortKeysDeep(obj[k], desc);
    return out;
  }
  return obj;
}

function xmlPretty(xml, indent) {
  const pad = " ".repeat(indent);
  let formatted = "";
  let level = 0;
  const nodes = xml.replace(/>\s*</g, "><").trim().split(/(?=<)/g);
  for (let node of nodes) {
    if (!node) continue;
    if (/^<\/\w/.test(node)) {
      level = Math.max(0, level - 1);
      formatted += pad.repeat(level) + node + "\n";
    } else if (/^<\w[^>]*[^/]>$/.test(node) && !/^<\?/.test(node) && !/<\/[^>]+>$/.test(node)) {
      formatted += pad.repeat(level) + node + "\n";
      if (!/\/>$/.test(node)) level++;
    } else {
      formatted += pad.repeat(level) + node + "\n";
    }
  }
  return formatted.trim();
}

function xmlWellFormed(xml) {
  const stack = [];
  const tagRe = /<(\/?)([a-zA-Z_][\w:.-]*)([^>]*?)(\/?)>/g;
  let m;
  let pos = 0;
  while ((m = tagRe.exec(xml))) {
    pos = m.index + m[0].length;
    const [, closing, name, , selfClose] = m;
    if (xml.slice(m.index, m.index + 2) === "<?" || xml.slice(m.index, m.index + 4) === "<!--") continue;
    if (closing) {
      if (stack.length === 0 || stack[stack.length - 1] !== name) {
        return { ok: false, error: `Mismatched closing tag </${name}> at position ${m.index}` };
      }
      stack.pop();
    } else if (!selfClose) {
      stack.push(name);
    }
  }
  if (stack.length > 0) return { ok: false, error: `Unclosed tag(s): ${stack.join(", ")}` };
  return { ok: true };
}

const SQL_KEYWORDS = ["select", "from", "where", "insert", "into", "values", "update", "set", "delete", "join", "inner join", "left join", "right join", "outer join", "on", "group by", "order by", "having", "limit", "offset", "and", "or", "not", "as", "distinct", "union", "create table", "alter table", "drop table", "primary key", "foreign key", "references", "in", "is", "null", "like", "between", "exists", "desc", "asc"];
const SQL_NEWLINE_BEFORE = ["select", "from", "where", "insert", "into", "values", "update", "set", "delete", "join", "inner join", "left join", "right join", "outer join", "group by", "order by", "having", "limit", "offset", "union", "and", "or"];

function formatSQL(sql) {
  let s = sql.replace(/\s+/g, " ").trim();
  // uppercase keywords (longest first to catch multi-word)
  const sorted = [...SQL_KEYWORDS].sort((a, b) => b.length - a.length);
  for (const kw of sorted) {
    const re = new RegExp(`\\b${kw.replace(/ /g, "\\s+")}\\b`, "gi");
    s = s.replace(re, kw.toUpperCase());
  }
  for (const kw of SQL_NEWLINE_BEFORE) {
    const re = new RegExp(`\\s+(${kw.toUpperCase().replace(/ /g, "\\s+")})\\b`, "g");
    s = s.replace(re, "\n$1");
  }
  s = s.replace(/,\s*/g, ",\n  ");
  return s.split("\n").map((l) => l.trim()).join("\n");
}

function parseEnv(text) {
  // As the dotenv package reads it: optional export, KEY=value or KEY: value, a # comment after an
  // unquoted value, quoted values (double quotes may span lines and expand \n), and the last value wins.
  const LINE = /^[^\S\n\r\u2028\u2029]*(?:export\s+)?([\w.-]+)(?:\s*=\s*?|:\s+?)(\s*'(?:\\'|[^'])*'|\s*"(?:\\"|[^"])*"|\s*`(?:\\`|[^`])*`|[^#\r\n]+)?\s*(?:#.*)?$/mg;
  const src = String(text).replace(/\r\n?/g, "\n");
  const out = {};
  const dupes = [];
  const blanks = [];
  let m;
  while ((m = LINE.exec(src))) {
    const k = m[1], line = src.slice(0, m.index).split("\n").length + (/^\s*\n/.exec(m[0]) || [""])[0].split("\n").length - 1;
    let val = (m[2] || "").trim();
    const q = val[0];
    val = val.replace(/^(['"`])([\s\S]*)\1$/mg, "$2");
    if (q === '"') val = val.replace(/\\n/g, "\n").replace(/\\r/g, "\r");
    if (Object.hasOwn(out, k)) dupes.push({ key: k, line });
    if (val === "") blanks.push({ key: k, line });
    Object.defineProperty(out, k, { value: val, enumerable: true, writable: true, configurable: true });
  }
  return { out, dupes, blanks };
}

function parseINI(text) {
  // As Python's configparser reads it: [section] (a trailing ; or # comment allowed), key = value
  // or key: value split at the first = or :, an indented line continues the previous value,
  // and a bare key has no value (null).
  const lines = String(text).split(/\r?\n/);
  const out = {};
  let section = null, last = null;
  const put = (o, k, v) => Object.defineProperty(o, k, { value: v, writable: true, enumerable: true, configurable: true });
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith(";") || line.startsWith("#")) continue;
    if (last && /^[ \t]/.test(raw)) { const o = section ? out[section] : out; o[last] = (o[last] == null ? "" : o[last] + "\n") + line; continue; }
    const sec = line.match(/^\[([^\]]+)\]\s*(?:[;#].*)?$/);
    // own keys only: a [__proto__] or [constructor] section must not reach the prototype or Object itself
    if (sec) { section = sec[1].trim(); last = null; if (!Object.hasOwn(out, section)) put(out, section, {}); continue; }
    const kv = line.match(/^([^=:]+)[=:](.*)$/);
    const k = (kv ? kv[1] : line).trim();
    put(section ? out[section] : out, k, kv ? kv[2].trim() : null);
    last = k;
  }
  return out;
}

function mdToHtml(md) {
  let html = S(md);
  html = html.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
  html = html.replace(/^######\s?(.*)$/gm, "<h6>$1</h6>")
             .replace(/^#####\s?(.*)$/gm, "<h5>$1</h5>")
             .replace(/^####\s?(.*)$/gm, "<h4>$1</h4>")
             .replace(/^###\s?(.*)$/gm, "<h3>$1</h3>")
             .replace(/^##\s?(.*)$/gm, "<h2>$1</h2>")
             .replace(/^#\s?(.*)$/gm, "<h1>$1</h1>");
  html = html.replace(/`([^`]+)`/g, "<code>$1</code>");
  html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  html = html.replace(/\*([^*]+)\*/g, "<em>$1</em>");
  html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');
  html = html.replace(/^(?:-|\*)\s+(.*)$/gm, "<li>$1</li>");
  html = html.replace(/(<li>.*<\/li>\n?)+/g, (m) => "<ul>\n" + m.trim() + "\n</ul>\n");
  html = html.split(/\n{2,}/).map((block) => {
    if (/^<(h\d|ul|li)/.test(block.trim())) return block;
    return block.trim() ? `<p>${block.trim()}</p>` : "";
  }).join("\n");
  return html.trim();
}

// Line diff as a shortest edit script (Myers, "An O(ND) Difference Algorithm"): time and memory
// grow with the number of changed lines, not with the file size. The n*m LCS table it replaces
// took a second and 576 MB for two 12,000-line files with two edits. Past MAX_D changes (two
// unrelated texts) the rest is shown as one block replaced. ops: [" "|"-"|"+", line].
const MAX_D = 3000;
function lineDiff(A, B) {
  const n = A.length, m = B.length, max = Math.min(n + m, MAX_D), off = max + 1;
  const V = new Int32Array(2 * max + 3), trace = [];
  let found = -1;
  for (let d = 0; d <= max && found < 0; d++) {
    trace.push(V.slice(off - d, off + d + 1)); // V as it was before step d, indexed k + d
    for (let k = -d; k <= d; k += 2) {
      let x = k === -d || (k !== d && V[off + k - 1] < V[off + k + 1]) ? V[off + k + 1] : V[off + k - 1] + 1, y = x - k;
      while (x < n && y < m && A[x] === B[y]) { x++; y++; }
      V[off + k] = x;
      if (x >= n && y >= m) { found = d; break; }
    }
  }
  if (found < 0) { // too many changes: common head and tail, the middle as one block
    let pre = 0; while (pre < n && pre < m && A[pre] === B[pre]) pre++;
    let suf = 0; while (suf < n - pre && suf < m - pre && A[n - 1 - suf] === B[m - 1 - suf]) suf++;
    return { capped: true, ops: [...A.slice(0, pre).map((l) => [" ", l]), ...A.slice(pre, n - suf).map((l) => ["-", l]), ...B.slice(pre, m - suf).map((l) => ["+", l]), ...A.slice(n - suf).map((l) => [" ", l])] };
  }
  const ops = []; let x = n, y = m;
  for (let d = found; d > 0; d--) {
    const v = trace[d], k = x - y;
    const pk = k === -d || (k !== d && v[k - 1 + d] < v[k + 1 + d]) ? k + 1 : k - 1;
    const px = v[pk + d], py = px - pk;
    while (x > px && y > py) { ops.push([" ", A[--x]]); y--; }
    if (x === px) ops.push(["+", B[--y]]); else ops.push(["-", A[--x]]);
  }
  while (x > 0) { ops.push([" ", A[--x]]); y--; }
  return { capped: false, ops: ops.reverse() };
}

export const TOOLS = [
  { id: "d-diff", name: "Text Diff", cat: "dev", desc: "Line-by-line diff of two texts, showing +/- changed lines.", tags: ["diff", "compare", "text"],
    inputs: [{ k: "a", label: "Original", type: "textarea", rows: 6 }, { k: "b", label: "Changed", type: "textarea", rows: 6 }],
    run(v) {
      const A = S(v.a).split(/\r?\n/), B = S(v.b).split(/\r?\n/);
      if (A.length === B.length && A.every((l, k) => l === B[k])) return "(identical)";
      const { ops, capped } = lineDiff(A, B);
      return (capped ? "(over " + MAX_D + " changed lines: the changed middle is shown as one block replaced)\n" : "") + ops.map((o) => (o[0] === " " ? "  " : o[0] + " ") + o[1]).join("\n");
    } },

  { id: "d-json-path", name: "JSON Path Extractor", cat: "dev", desc: "Extract a value from JSON using a dot/bracket path like a.b[0].c.", tags: ["json", "path", "jsonpath"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 6 }, { k: "path", label: "Path", type: "text", placeholder: "a.b[0].c" }],
    run(v) {
      const p = tryParseJSON(v.json || ""); if (!p.ok) return { error: "Invalid JSON: " + p.err };
      const parts = parsePath(S(v.path));
      let cur = p.val;
      // the data's own keys only: a.constructor or s.length name no value in the JSON
      for (const key of parts) { if (cur == null || typeof cur !== "object" || !Object.prototype.hasOwnProperty.call(cur, key)) return { error: "Path not found." }; cur = cur[key]; }
      if (cur === undefined) return { error: "Path not found." };
      return typeof cur === "string" ? cur : JSON.stringify(cur, null, 2);
    } },

  { id: "d-json-flatten", name: "JSON Flattener", cat: "dev", desc: "Flatten nested JSON into dot/bracket-notation keys.", tags: ["json", "flatten"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8 }],
    run(v) {
      const p = tryParseJSON(v.json || ""); if (!p.ok) return { error: "Invalid JSON: " + p.err };
      const flat = flattenObj(p.val, "", {});
      return JSON.stringify(flat, null, 2);
    } },

  { id: "d-json-sort-keys", name: "JSON Key Sorter", cat: "dev", desc: "Recursively sort object keys alphabetically (A-Z or Z-A).", tags: ["json", "sort"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8 }, { k: "order", label: "Order", type: "select", opts: ["A-Z", "Z-A"], value: "A-Z" }, { k: "indent", label: "Indent", type: "range", min: 0, max: 8, step: 1, value: 2 }],
    run(v) {
      const p = tryParseJSON(v.json || ""); if (!p.ok) return { error: "Invalid JSON: " + p.err };
      return JSON.stringify(sortKeysDeep(p.val, v.order === "Z-A"), null, +v.indent || 0);
    } },

  { id: "d-xml-pretty", name: "XML Pretty-Printer", cat: "dev", desc: "Reformat XML with consistent indentation.", tags: ["xml", "format"],
    inputs: [{ k: "xml", label: "XML", type: "textarea", rows: 8 }, { k: "indent", label: "Indent spaces", type: "range", min: 1, max: 8, step: 1, value: 2 }],
    run(v) { if (!v.xml) return ""; try { return xmlPretty(v.xml, +v.indent || 2); } catch (e) { return { error: "Could not format XML." }; } } },

  { id: "d-xml-validate", name: "XML Well-Formed Checker", cat: "dev", desc: "Check that XML tags are properly nested and closed.", tags: ["xml", "validate"],
    inputs: [{ k: "xml", label: "XML", type: "textarea", rows: 8 }],
    run(v) { if (!v.xml) return ""; const r = xmlWellFormed(v.xml); return r.ok ? "Well-formed: all tags match and nest correctly." : { error: r.error }; } },

  { id: "d-sql-format", name: "SQL Formatter", cat: "dev", desc: "Uppercase SQL keywords and break clauses onto new lines.", tags: ["sql", "format"],
    inputs: [{ k: "sql", label: "SQL", type: "textarea", rows: 6, placeholder: "select * from users where id=1" }],
    run(v) { if (!v.sql) return ""; return formatSQL(v.sql); } },

  { id: "d-env-to-json", name: ".env → JSON", cat: "dev", desc: "Convert a .env file into a JSON object.", tags: ["env", "json", "dotenv"],
    inputs: [{ k: "env", label: ".env content", type: "textarea", rows: 8, placeholder: "KEY=value" }],
    run(v) { if (!v.env) return ""; const { out } = parseEnv(v.env); return JSON.stringify(out, null, 2); } },

  { id: "d-env-validate", name: ".env Validator", cat: "dev", desc: "Check a .env file for duplicate keys and blank values.", tags: ["env", "validate", "dotenv"],
    inputs: [{ k: "env", label: ".env content", type: "textarea", rows: 8 }],
    run(v) {
      if (!v.env) return "";
      const { out, dupes, blanks } = parseEnv(v.env);
      const lines = [];
      lines.push(`${Object.keys(out).length} unique key(s) found.`);
      if (dupes.length) lines.push("Duplicate keys: " + dupes.map((d) => `${d.key} (line ${d.line})`).join(", "));
      else lines.push("No duplicate keys.");
      if (blanks.length) lines.push("Blank values: " + blanks.map((b) => `${b.key} (line ${b.line})`).join(", "));
      else lines.push("No blank values.");
      return lines.join("\n");
    } },

  { id: "d-ini-to-json", name: "INI Parser → JSON", cat: "dev", desc: "Parse an INI file (with [sections]) into JSON.", tags: ["ini", "json"],
    inputs: [{ k: "ini", label: "INI content", type: "textarea", rows: 8, placeholder: "[section]\nkey=value" }],
    run(v) { if (!v.ini) return ""; return JSON.stringify(parseINI(v.ini), null, 2); } },

  { id: "d-regex-tester", name: "Regex Tester", cat: "dev", desc: "Test a regex pattern against text and see matches + capture groups.", tags: ["regex", "test"],
    inputs: [{ k: "pattern", label: "Pattern", type: "text", placeholder: "(\\w+)@(\\w+)" }, { k: "flags", label: "Flags", type: "text", placeholder: "g" }, { k: "text", label: "Text", type: "textarea", rows: 6 }],
    run(v) {
      if (!v.pattern) return "";
      let re;
      try { re = new RegExp(v.pattern, v.flags || ""); } catch (e) { return { error: "Invalid regex: " + e.message }; }
      const text = S(v.text);
      if (!re.global) {
        const m = re.exec(text);
        if (!m) return "No match.";
        return `Match: "${m[0]}" at index ${m.index}` + (m.length > 1 ? "\nGroups: " + JSON.stringify(m.slice(1)) : "");
      }
      const matches = [...text.matchAll(re)];
      if (!matches.length) return "No matches.";
      return matches.map((m, i) => `#${i + 1}: "${m[0]}" at index ${m.index}` + (m.length > 1 ? " groups=" + JSON.stringify(m.slice(1)) : "")).join("\n");
    } },

  { id: "d-regex-cheatsheet", name: "Regex Reference Cheatsheet", cat: "dev", desc: "Searchable quick reference of common regex tokens.", tags: ["regex", "cheatsheet", "reference"], live: true,
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "e.g. group, anchor, digit" }],
    run(v) {
      const rows = [
        [".", "Any character except newline"], ["\\d", "Digit [0-9]"], ["\\D", "Non-digit"], ["\\w", "Word char [A-Za-z0-9_]"], ["\\W", "Non-word char"],
        ["\\s", "Whitespace"], ["\\S", "Non-whitespace"], ["^", "Start of string/line"], ["$", "End of string/line"], ["*", "0 or more"],
        ["+", "1 or more"], ["?", "0 or 1 (optional)"], ["{n,m}", "Between n and m repetitions"], ["[abc]", "Character class"], ["[^abc]", "Negated class"],
        ["(abc)", "Capture group"], ["(?:abc)", "Non-capture group"], ["(?<name>abc)", "Named group"], ["a|b", "Alternation"], ["\\b", "Word boundary"],
        ["\\B", "Non-word boundary"], ["(?=abc)", "Positive lookahead"], ["(?!abc)", "Negative lookahead"], ["(?<=abc)", "Positive lookbehind"], ["(?<!abc)", "Negative lookbehind"],
        ["g flag", "Global match (all matches)"], ["i flag", "Case-insensitive"], ["m flag", "Multiline (^$ per line)"], ["s flag", "Dotall (. matches newline)"], ["u flag", "Unicode mode"],
      ];
      const q = (v.q || "").toLowerCase();
      const filtered = q ? rows.filter(([a, b]) => a.toLowerCase().includes(q) || b.toLowerCase().includes(q)) : rows;
      if (!filtered.length) return "No matches for that filter.";
      return filtered.map(([a, b]) => `${a.padEnd(16)} ${b}`).join("\n");
    } },

  { id: "d-md-to-html", name: "Markdown → HTML", cat: "dev", desc: "Convert basic Markdown (headings, bold, italic, code, links, lists) to HTML.", tags: ["markdown", "html"],
    inputs: [{ k: "md", label: "Markdown", type: "textarea", rows: 8, placeholder: "# Title\n\n**bold** and *italic*" }],
    run(v) { if (!v.md) return ""; return mdToHtml(v.md); } },

  

  { id: "d-multi-escape", name: "Multi-Target Escaper", cat: "dev", desc: "Escape text for shell, JSON, regex, or HTML context.", tags: ["escape", "shell", "regex", "html", "json"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }, { k: "target", label: "Target", type: "select", opts: ["Shell", "JSON", "Regex", "HTML"], value: "Shell" }],
    run(v) {
      if (!v.text) return "";
      const t = v.text;
      if (v.target === "Shell") return "'" + t.replace(/'/g, "'\\''") + "'";
      if (v.target === "JSON") return JSON.stringify(t);
      if (v.target === "Regex") return t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      return t.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
    } },

  { id: "d-uuid-v5", name: "UUID v5 Generator", cat: "dev", desc: "Deterministic namespace UUID v5 from a namespace UUID and name (SHA-1 based).", tags: ["uuid", "v5", "namespace"],
    inputs: [{ k: "namespace", label: "Namespace UUID", type: "text", placeholder: "6ba7b810-9dad-11d1-80b4-00c04fd430c8" }, { k: "name", label: "Name", type: "text", placeholder: "example.com" }],
    async run(v, H) {
      const ns = S(v.namespace).trim();
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(ns)) return { error: "Enter a valid namespace UUID." };
      if (!v.name) return { error: "Enter a name." };
      const nsHex = ns.replace(/-/g, "");
      const nsBytes = H.fromHex(nsHex);
      const nameBytes = H.bytes(v.name);
      const combined = new Uint8Array(nsBytes.length + nameBytes.length);
      combined.set(nsBytes, 0); combined.set(nameBytes, nsBytes.length);
      const digest = await crypto.subtle.digest("SHA-1", combined);
      const bytesArr = new Uint8Array(digest).slice(0, 16);
      bytesArr[6] = (bytesArr[6] & 0x0f) | 0x50; // version 5
      bytesArr[8] = (bytesArr[8] & 0x3f) | 0x80; // variant
      const h = H.toHex(bytesArr);
      return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
    } },

  { id: "d-uuid-namespaces", name: "UUID Namespace Reference", cat: "dev", desc: "Standard RFC 4122 namespace UUIDs (DNS, URL, OID, X.500) for use with UUID v3/v5.", tags: ["uuid", "namespace", "reference"], button: false, live: true,
    inputs: [],
    run() {
      return [
        "DNS  : 6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        "URL  : 6ba7b811-9dad-11d1-80b4-00c04fd430c8",
        "OID  : 6ba7b812-9dad-11d1-80b4-00c04fd430c8",
        "X.500: 6ba7b814-9dad-11d1-80b4-00c04fd430c8",
      ].join("\n");
    } },

  { id: "d-timestamp-diff", name: "Timestamp Difference", cat: "dev", desc: "Compute the duration between two datetimes.", tags: ["time", "duration", "diff"],
    inputs: [{ k: "a", label: "Start (ISO or any parseable date)", type: "text", placeholder: "2026-01-01T00:00:00Z" }, { k: "b", label: "End", type: "text", placeholder: "2026-03-15T12:30:00Z" }],
    run(v) {
      const a = new Date(v.a), b = new Date(v.b);
      if (isNaN(a) || isNaN(b)) return { error: "Enter valid dates." };
      let ms = Math.abs(b - a);
      const days = Math.floor(ms / 86400000); ms -= days * 86400000;
      const hrs = Math.floor(ms / 3600000); ms -= hrs * 3600000;
      const mins = Math.floor(ms / 60000); ms -= mins * 60000;
      const secs = Math.floor(ms / 1000);
      return `${days}d ${hrs}h ${mins}m ${secs}s\nTotal seconds: ${Math.floor(Math.abs(b - a) / 1000)}\nTotal ms: ${Math.abs(b - a)}`;
    } },

  

  

  { id: "d-text-templater", name: "Text Templater", cat: "dev", desc: "Fill {{placeholders}} in a template using JSON values.", tags: ["template", "mustache", "placeholder"],
    inputs: [{ k: "template", label: "Template", type: "textarea", rows: 5, placeholder: "Hello {{name}}, you are {{age}}." }, { k: "data", label: "JSON values", type: "textarea", rows: 4, placeholder: '{"name": "Alex", "age": 30}' }],
    run(v) {
      if (!v.template) return "";
      const p = tryParseJSON(v.data || "{}"); if (!p.ok) return { error: "Invalid JSON values: " + p.err };
      return v.template.replace(/\{\{\s*([\w.]+)\s*\}\}/g, (m, key) => {
        const parts = key.split(".");
        let cur = p.val;
        for (const k of parts) { if (cur == null || !Object.hasOwn(Object(cur), k)) return m; cur = cur[k]; } // own keys only: {{constructor}} is not Object's source
        return cur === undefined ? m : String(cur);
      });
    } },

  { id: "d-json-diff", name: "JSON Diff", cat: "dev", desc: "Compare two JSON objects and list added, removed, and changed keys.", tags: ["json", "diff", "compare"],
    inputs: [{ k: "a", label: "JSON A", type: "textarea", rows: 6 }, { k: "b", label: "JSON B", type: "textarea", rows: 6 }],
    run(v) {
      const pa = tryParseJSON(v.a || ""), pb = tryParseJSON(v.b || "");
      if (!pa.ok) return { error: "Invalid JSON A: " + pa.err };
      if (!pb.ok) return { error: "Invalid JSON B: " + pb.err };
      const kind = (x) => Array.isArray(x) ? "array" : x === null ? "null" : typeof x;
      if (kind(pa.val) !== kind(pb.val) || (typeof pa.val !== "object" && pa.val !== pb.val)) return `~ (root): ${JSON.stringify(pa.val)} -> ${JSON.stringify(pb.val)}`;
      const fa = flattenObj(pa.val, "", {}), fb = flattenObj(pb.val, "", {});
      const keys = new Set([...Object.keys(fa), ...Object.keys(fb)]);
      const added = [], removed = [], changed = [];
      for (const k of [...keys].sort()) {
        const inA = Object.hasOwn(fa, k), inB = Object.hasOwn(fb, k); // "constructor" in {} is true
        if (inA && !inB) removed.push(`- ${k}: ${JSON.stringify(fa[k])}`);
        else if (!inA && inB) added.push(`+ ${k}: ${JSON.stringify(fb[k])}`);
        else if (JSON.stringify(fa[k]) !== JSON.stringify(fb[k])) changed.push(`~ ${k}: ${JSON.stringify(fa[k])} -> ${JSON.stringify(fb[k])}`);
      }
      const out = [...added, ...removed, ...changed];
      return out.length ? out.join("\n") : "No differences.";
    } },

  

  { id: "d-list-set-ops", name: "List Intersection / Difference", cat: "dev", desc: "Compare two newline-separated lists: intersection, union, and differences.", tags: ["list", "set", "compare"],
    inputs: [{ k: "a", label: "List A", type: "textarea", rows: 6 }, { k: "b", label: "List B", type: "textarea", rows: 6 }],
    run(v) {
      const A = new Set(S(v.a).split(/\r?\n/).map((s) => s.trim()).filter(Boolean));
      const B = new Set(S(v.b).split(/\r?\n/).map((s) => s.trim()).filter(Boolean));
      const inter = [...A].filter((x) => B.has(x));
      const onlyA = [...A].filter((x) => !B.has(x));
      const onlyB = [...B].filter((x) => !A.has(x));
      const union = [...new Set([...A, ...B])];
      return [
        `Intersection (${inter.length}):`, inter.join(", ") || "(none)",
        `Only in A (${onlyA.length}):`, onlyA.join(", ") || "(none)",
        `Only in B (${onlyB.length}):`, onlyB.join(", ") || "(none)",
        `Union (${union.length}):`, union.join(", ") || "(none)",
      ].join("\n");
    } },

  { id: "d-csv-inspect", name: "CSV Row/Column Detector", cat: "dev", desc: "Count rows and columns in CSV text and detect the delimiter.", tags: ["csv", "columns", "rows"],
    inputs: [{ k: "csv", label: "CSV text", type: "textarea", rows: 8 }],
    run(v) {
      if (!v.csv) return "";
      const lines = v.csv.split(/\r?\n/).filter((l) => l.length > 0);
      if (!lines.length) return "No data.";
      const candidates = [",", ";", "\t", "|"];
      const delim = candidates.reduce((best, d) => (lines[0].split(d).length > lines[0].split(best).length ? d : best), ",");
      const parseRow = (line) => { const out = []; let cur = "", inQ = false; for (let i = 0; i < line.length; i++) { const c = line[i]; if (c === '"') inQ = !inQ; else if (c === delim && !inQ) { out.push(cur); cur = ""; } else cur += c; } out.push(cur); return out; };
      const header = parseRow(lines[0]);
      const colCounts = lines.map((l) => parseRow(l).length);
      const consistent = colCounts.every((c) => c === colCounts[0]);
      const delimName = { ",": "comma", ";": "semicolon", "\t": "tab", "|": "pipe" }[delim];
      return [`Delimiter: ${delimName} (${JSON.stringify(delim)})`, `Rows (incl. header): ${lines.length}`, `Data rows: ${lines.length - 1}`, `Columns: ${header.length}`, `Header: ${header.join(" | ")}`, `Consistent column count: ${consistent ? "yes" : "no"}`].join("\n");
    } },

  { id: "d-http-header-explain", name: "HTTP Header Explainer", cat: "dev", desc: "Paste raw HTTP headers and get a plain-English description of each.", tags: ["http", "headers", "explain"],
    inputs: [{ k: "headers", label: "Headers (one per line)", type: "textarea", rows: 8, placeholder: "Content-Type: application/json\nCache-Control: no-cache" }],
    run(v) {
      if (!v.headers) return "";
      const DESC = {
        "content-type": "The media type of the body.", "content-length": "Size of the body in bytes.",
        "cache-control": "Caching directives for browsers/proxies.", "authorization": "Credentials for authenticating the request.",
        "user-agent": "Identifies the client software making the request.", "accept": "Media types the client can handle.",
        "accept-encoding": "Compression formats the client supports.", "accept-language": "Preferred natural languages.",
        "set-cookie": "Sets a cookie in the client.", "cookie": "Cookies sent by the client.",
        "location": "Redirect target URL.", "host": "Target host and port of the request.",
        "referer": "URL of the page that linked to the requested resource.", "origin": "Origin of a cross-site request.",
        "access-control-allow-origin": "CORS: which origins may access the response.", "x-frame-options": "Controls whether the page can be framed (clickjacking defense).",
        "strict-transport-security": "Forces HTTPS for future requests (HSTS).", "content-security-policy": "Restricts allowed sources for scripts/styles/etc.",
        "x-content-type-options": "nosniff prevents MIME-type sniffing.", "etag": "Opaque validator for cache revalidation.",
        "last-modified": "When the resource was last changed.", "vary": "Which request headers affect the cached response.",
        "connection": "Controls whether the connection stays open (keep-alive/close).", "transfer-encoding": "How the body is encoded for transfer (e.g. chunked).",
        "server": "Software identifying the origin server.", "x-powered-by": "Framework/technology serving the response.",
        "retry-after": "Seconds/date to wait before retrying.", "www-authenticate": "Auth scheme required to access the resource.",
        "if-none-match": "Conditional request based on ETag.", "if-modified-since": "Conditional request based on date.",
      };
      return v.headers.split(/\r?\n/).filter(Boolean).map((line) => {
        const m = line.match(/^([^:]+):\s*(.*)$/);
        if (!m) return `${line} -- (not a valid "Name: value" header)`;
        const name = m[1].trim();
        const desc = (Object.hasOwn(DESC, name.toLowerCase()) && DESC[name.toLowerCase()]) || "No description available for this header.";
        return `${name}: ${desc}`;
      }).join("\n");
    } },

  { id: "d-query-builder", name: "Key=Value Query Builder", cat: "dev", desc: "Build a URL query string from key/value pairs (one per line).", tags: ["query", "url", "params"],
    inputs: [{ k: "pairs", label: "key=value pairs (one per line)", type: "textarea", rows: 6, placeholder: "q=hello world\npage=2" }],
    run(v) {
      if (!v.pairs) return "";
      const parts = v.pairs.split(/\r?\n/).map((l) => l.trim()).filter(Boolean).map((l) => {
        const idx = l.indexOf("=");
        const k = idx === -1 ? l : l.slice(0, idx);
        const val = idx === -1 ? "" : l.slice(idx + 1);
        return `${encodeURIComponent(k)}=${encodeURIComponent(val)}`;
      });
      return "?" + parts.join("&");
    } },

  { id: "d-json-to-table", name: "JSON → Pretty Table", cat: "dev", desc: "Render a JSON array of objects as an ASCII table.", tags: ["json", "table", "ascii"],
    inputs: [{ k: "json", label: "JSON array of objects", type: "textarea", rows: 8, placeholder: '[{"id":1,"name":"a"},{"id":2,"name":"b"}]' }],
    run(v) {
      const p = tryParseJSON(v.json || ""); if (!p.ok) return { error: "Invalid JSON: " + p.err };
      if (!Array.isArray(p.val) || !p.val.length) return { error: "Provide a non-empty JSON array of objects." };
      const cols = [...new Set(p.val.flatMap((r) => Object.keys(r || {})))];
      const cell = (r, c) => (!r || !Object.hasOwn(r, c) || r[c] === undefined ? "" : typeof r[c] === "object" ? JSON.stringify(r[c]) : String(r[c]));
      const widths = cols.map((c) => Math.max(c.length, ...p.val.map((r) => cell(r, c).length)));
      const row = (vals) => "| " + vals.map((s, i) => s.padEnd(widths[i])).join(" | ") + " |";
      const sep = "|-" + widths.map((w) => "-".repeat(w)).join("-|-") + "-|";
      const lines = [row(cols), sep, ...p.val.map((r) => row(cols.map((c) => cell(r, c))))];
      return lines.join("\n");
    } },

  { id: "d-epoch-now", name: "Epoch Now", cat: "dev", desc: "Current Unix time (seconds & ms) and ISO 8601 timestamp.", tags: ["epoch", "unix", "time", "now"], button: false, live: true,
    inputs: [],
    run() {
      const d = new Date();
      return [`Unix seconds: ${Math.floor(d.getTime() / 1000)}`, `Unix ms: ${d.getTime()}`, `ISO 8601: ${d.toISOString()}`, `Local: ${d.toString()}`].join("\n");
    } },

  { id: "d-backslash-join", name: "Backslash Line Joiner", cat: "dev", desc: "Join multiple lines into one with trailing backslashes (shell continuation), or split them back apart.", tags: ["shell", "lines", "join"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }, { k: "mode", label: "Mode", type: "select", opts: ["Join with \\", "Split on \\"], value: "Join with \\" }],
    run(v) {
      if (!v.text) return "";
      if (v.mode === "Join with \\") return v.text.split(/\r?\n/).filter((l) => l.length).join(" \\\n");
      return v.text.split(/\\\s*\r?\n/).join("\n");
    } },

  { id: "d-indent-dedent", name: "Indent / Dedent Converter", cat: "dev", desc: "Add or remove leading whitespace from every line of text.", tags: ["indent", "dedent", "whitespace"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "mode", label: "Mode", type: "select", opts: ["Indent", "Dedent (strip common leading whitespace)"], value: "Indent" }, { k: "size", label: "Indent size (spaces)", type: "range", min: 1, max: 8, step: 1, value: 2 }],
    run(v) {
      if (!v.text) return "";
      const lines = v.text.split(/\r?\n/);
      if (v.mode === "Indent") { const pad = " ".repeat(+v.size || 2); return lines.map((l) => (l.length ? pad + l : l)).join("\n"); }
      const nonEmpty = lines.filter((l) => l.trim().length);
      if (!nonEmpty.length) return v.text;
      const minIndent = Math.min(...nonEmpty.map((l) => l.match(/^[ \t]*/)[0].length));
      return lines.map((l) => l.slice(0, minIndent).trim() === "" ? l.slice(minIndent) : l).join("\n");
    } },

  

  

  

  

  

  

  

  { id: "d-diff-stats", name: "Diff Summary Stats", cat: "dev", desc: "Count added/removed/unchanged lines between two texts without printing the full diff.", tags: ["diff", "stats", "summary"],
    inputs: [{ k: "a", label: "Original", type: "textarea", rows: 6 }, { k: "b", label: "Changed", type: "textarea", rows: 6 }],
    run(v) {
      const { ops, capped } = lineDiff(S(v.a).split(/\r?\n/), S(v.b).split(/\r?\n/));
      const c = (t) => ops.filter((o) => o[0] === t).length;
      return `Added: ${c("+")}\nRemoved: ${c("-")}\nUnchanged: ${c(" ")}` + (capped ? "\n(over " + MAX_D + " changed lines: counted as one block replaced, so these are upper bounds)" : "");
    } },

  

  

  { id: "d-json-schema-infer", name: "JSON Schema Inferrer", cat: "dev", desc: "Infer a basic JSON Schema (types) from a sample JSON value.", tags: ["json", "schema", "infer"],
    inputs: [{ k: "json", label: "Sample JSON", type: "textarea", rows: 8 }],
    run(v) {
      const p = tryParseJSON(v.json || ""); if (!p.ok) return { error: "Invalid JSON: " + p.err };
      const infer = (val) => {
        if (val === null) return { type: "null" };
        if (Array.isArray(val)) return { type: "array", items: val.length ? val.map(infer).reduce(merge) : {} }; // every item, not just the first
        const t = typeof val;
        if (t === "object") { const props = {}; for (const k of Object.keys(val)) Object.defineProperty(props, k, { value: infer(val[k]), enumerable: true, writable: true, configurable: true }); return { type: "object", properties: props, required: Object.keys(val) }; }
        if (t === "number") return { type: Number.isInteger(val) ? "integer" : "number" };
        return { type: t };
      };
      // Two schemas for values at the same place: objects merge their properties (required = keys
      // every item has), integer widens to number, other differing types become a type list.
      function merge(x, y) {
        const tx = [].concat(x.type), ty = [].concat(y.type);
        if (x.type === "object" && y.type === "object") {
          const props = {};
          for (const k of new Set([...Object.keys(x.properties), ...Object.keys(y.properties)])) Object.defineProperty(props, k, { value: Object.hasOwn(x.properties, k) && Object.hasOwn(y.properties, k) ? merge(x.properties[k], y.properties[k]) : (Object.hasOwn(x.properties, k) ? x.properties[k] : y.properties[k]), enumerable: true, writable: true, configurable: true });
          return { type: "object", properties: props, required: x.required.filter((k) => y.required.includes(k)) };
        }
        if (x.type === "array" && y.type === "array") return { type: "array", items: !Object.keys(x.items).length ? y.items : !Object.keys(y.items).length ? x.items : merge(x.items, y.items) };
        let types = [...new Set([...tx, ...ty])];
        if (types.includes("number")) types = types.filter((u) => u !== "integer");
        return { type: types.length === 1 ? types[0] : types };
      }
      return JSON.stringify(infer(p.val), null, 2);
    } },

  
];
