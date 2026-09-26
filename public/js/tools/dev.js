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

function flattenObj(obj, prefix, out) {
  if (obj !== null && typeof obj === "object") {
    const keys = Array.isArray(obj) ? obj.map((_, i) => i) : Object.keys(obj);
    if (keys.length === 0) { out[prefix || "$"] = Array.isArray(obj) ? [] : {}; return out; }
    for (const k of keys) {
      const nk = Array.isArray(obj) ? `${prefix}[${k}]` : (prefix ? `${prefix}.${k}` : String(k));
      flattenObj(obj[k], nk, out);
    }
  } else {
    out[prefix] = obj;
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
  const lines = String(text).split(/\r?\n/);
  const out = {};
  const dupes = [];
  const blanks = [];
  lines.forEach((line, idx) => {
    const t = line.trim();
    if (!t || t.startsWith("#")) return;
    const m = t.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!m) return;
    let [, k, val] = m;
    if (val && ((val[0] === '"' && val[val.length - 1] === '"') || (val[0] === "'" && val[val.length - 1] === "'"))) {
      val = val.slice(1, -1);
    }
    if (k in out) dupes.push({ key: k, line: idx + 1 });
    if (val === "") blanks.push({ key: k, line: idx + 1 });
    out[k] = val;
  });
  return { out, dupes, blanks };
}

function parseINI(text) {
  const lines = String(text).split(/\r?\n/);
  const out = {};
  let section = null;
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith(";") || line.startsWith("#")) continue;
    const sec = line.match(/^\[(.+)\]$/);
    if (sec) { section = sec[1]; if (!out[section]) out[section] = {}; continue; }
    const kv = line.match(/^([^=]+)=(.*)$/);
    if (!kv) continue;
    const k = kv[1].trim(), val = kv[2].trim();
    if (section) out[section][k] = val; else out[k] = val;
  }
  return out;
}

function parseSemver(v) {
  const m = String(v).trim().replace(/^v/, "").match(/^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/);
  if (!m) return null;
  return { major: +m[1], minor: +m[2], patch: +m[3], pre: m[4] || "", build: m[5] || "" };
}

function cmpSemver(a, b) {
  for (const k of ["major", "minor", "patch"]) { if (a[k] !== b[k]) return a[k] - b[k]; }
  if (!a.pre && !b.pre) return 0;
  if (!a.pre) return 1;
  if (!b.pre) return -1;
  return a.pre < b.pre ? -1 : a.pre > b.pre ? 1 : 0;
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

export const TOOLS = [
  { id: "d-diff", name: "Text Diff", cat: "dev", desc: "Line-by-line diff of two texts, showing +/- changed lines.", tags: ["diff", "compare", "text"],
    inputs: [{ k: "a", label: "Original", type: "textarea", rows: 6 }, { k: "b", label: "Changed", type: "textarea", rows: 6 }],
    run(v) {
      const A = S(v.a).split(/\r?\n/), B = S(v.b).split(/\r?\n/);
      const n = A.length, m = B.length;
      const dp = Array.from({ length: n + 1 }, () => new Int32Array(m + 1));
      for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = A[i] === B[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
      let i = 0, j = 0; const out = [];
      while (i < n && j < m) {
        if (A[i] === B[j]) { out.push("  " + A[i]); i++; j++; }
        else if (dp[i + 1][j] >= dp[i][j + 1]) { out.push("- " + A[i]); i++; }
        else { out.push("+ " + B[j]); j++; }
      }
      while (i < n) { out.push("- " + A[i]); i++; }
      while (j < m) { out.push("+ " + B[j]); j++; }
      return out.join("\n") || "(identical)";
    } },

  { id: "d-json-path", name: "JSON Path Extractor", cat: "dev", desc: "Extract a value from JSON using a dot/bracket path like a.b[0].c.", tags: ["json", "path", "jsonpath"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 6 }, { k: "path", label: "Path", type: "text", placeholder: "a.b[0].c" }],
    run(v) {
      const p = tryParseJSON(v.json || ""); if (!p.ok) return { error: "Invalid JSON: " + p.err };
      const parts = parsePath(S(v.path));
      let cur = p.val;
      for (const key of parts) { if (cur == null) return { error: "Path not found." }; cur = cur[key]; }
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

  { id: "d-semver-compare", name: "Semver Compare", cat: "dev", desc: "Compare two semantic versions: <, =, or >.", tags: ["semver", "version"],
    inputs: [{ k: "a", label: "Version A", type: "text", placeholder: "1.2.3" }, { k: "b", label: "Version B", type: "text", placeholder: "1.3.0" }],
    run(v) {
      const a = parseSemver(v.a), b = parseSemver(v.b);
      if (!a || !b) return { error: "Enter valid semver strings, e.g. 1.2.3" };
      const c = cmpSemver(a, b);
      return `${v.a} ${c < 0 ? "<" : c > 0 ? ">" : "="} ${v.b}`;
    } },

  { id: "d-semver-bump", name: "Semver Bump", cat: "dev", desc: "Bump a semantic version's major, minor, or patch component.", tags: ["semver", "version", "bump"],
    inputs: [{ k: "ver", label: "Version", type: "text", placeholder: "1.2.3" }, { k: "part", label: "Bump", type: "select", opts: ["patch", "minor", "major"], value: "patch" }],
    run(v) {
      const s = parseSemver(v.ver);
      if (!s) return { error: "Enter a valid semver string, e.g. 1.2.3" };
      if (v.part === "major") return `${s.major + 1}.0.0`;
      if (v.part === "minor") return `${s.major}.${s.minor + 1}.0`;
      return `${s.major}.${s.minor}.${s.patch + 1}`;
    } },

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

  { id: "d-contrast-checker", name: "Color Contrast Checker", cat: "dev", desc: "WCAG contrast ratio between two hex colors, with AA/AAA pass/fail.", tags: ["color", "wcag", "accessibility", "contrast"],
    inputs: [{ k: "fg", label: "Foreground (hex)", type: "text", placeholder: "#000000" }, { k: "bg", label: "Background (hex)", type: "text", placeholder: "#ffffff" }],
    run(v) {
      const parse = (h) => { const m = S(h).trim().replace(/^#/, "").match(/^([0-9a-f]{3}|[0-9a-f]{6})$/i); if (!m) return null; let s = m[1]; if (s.length === 3) s = s.split("").map((c) => c + c).join(""); return [0, 2, 4].map((i) => parseInt(s.substr(i, 2), 16)); };
      const fg = parse(v.fg), bg = parse(v.bg);
      if (!fg || !bg) return { error: "Enter valid hex colors, e.g. #333 or #ff00aa." };
      const lum = ([r, g, b]) => { const f = (c) => { c /= 255; return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4); }; return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b); };
      const L1 = lum(fg), L2 = lum(bg);
      const ratio = (Math.max(L1, L2) + 0.05) / (Math.min(L1, L2) + 0.05);
      const r2 = Math.round(ratio * 100) / 100;
      return `Contrast ratio: ${r2}:1\nAA (normal text, 4.5:1): ${ratio >= 4.5 ? "PASS" : "FAIL"}\nAA (large text, 3:1): ${ratio >= 3 ? "PASS" : "FAIL"}\nAAA (normal text, 7:1): ${ratio >= 7 ? "PASS" : "FAIL"}\nAAA (large text, 4.5:1): ${ratio >= 4.5 ? "PASS" : "FAIL"}`;
    } },

  { id: "d-md-to-html", name: "Markdown → HTML", cat: "dev", desc: "Convert basic Markdown (headings, bold, italic, code, links, lists) to HTML.", tags: ["markdown", "html"],
    inputs: [{ k: "md", label: "Markdown", type: "textarea", rows: 8, placeholder: "# Title\n\n**bold** and *italic*" }],
    run(v) { if (!v.md) return ""; return mdToHtml(v.md); } },

  { id: "d-html-to-text", name: "HTML → Plain Text", cat: "dev", desc: "Strip tags from HTML and decode entities, leaving plain text.", tags: ["html", "text", "strip"],
    inputs: [{ k: "html", label: "HTML", type: "textarea", rows: 8 }],
    run(v) {
      if (!v.html) return "";
      let s = String(v.html);
      s = s.replace(/<(script|style)[^>]*>[\s\S]*?<\/\1>/gi, "");
      s = s.replace(/<br\s*\/?>/gi, "\n").replace(/<\/(p|div|li|h[1-6]|tr)>/gi, "\n").replace(/<[^>]+>/g, "");
      const map = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };
      s = s.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (m, e) => { if (e[0] === "#") { const n = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); return isNaN(n) ? m : String.fromCodePoint(n); } return map[e] != null ? map[e] : m; });
      return s.replace(/[ \t]+/g, " ").replace(/\n{3,}/g, "\n\n").trim();
    } },

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

  { id: "d-cron-next", name: "Cron Next Run Times", cat: "dev", desc: "Parse a standard 5-field cron expression and compute the next N run times.", tags: ["cron", "schedule"],
    inputs: [{ k: "expr", label: "Cron expression", type: "text", placeholder: "*/15 9-17 * * 1-5" }, { k: "count", label: "How many", type: "range", min: 1, max: 20, step: 1, value: 5 }],
    run(v) {
      if (!v.expr) return "";
      const fields = S(v.expr).trim().split(/\s+/);
      if (fields.length !== 5) return { error: "Expected 5 fields: minute hour day month weekday." };
      const ranges = [[0, 59], [0, 23], [1, 31], [1, 12], [0, 6]];
      const parseField = (f, [lo, hi]) => {
        const set = new Set();
        for (const part of f.split(",")) {
          let step = 1, base = part;
          if (part.includes("/")) { [base, step] = part.split("/"); step = parseInt(step, 10); }
          let start = lo, end = hi;
          if (base !== "*") {
            if (base.includes("-")) { const [a, b] = base.split("-").map(Number); start = a; end = b; }
            else { start = end = Number(base); }
          }
          if (isNaN(start) || isNaN(end) || isNaN(step)) return null;
          for (let x = start; x <= end; x += step) set.add(x);
        }
        return set;
      };
      const sets = fields.map((f, i) => parseField(f, ranges[i]));
      if (sets.some((s) => !s)) return { error: "Could not parse cron field(s)." };
      const [mins, hrs, doms, mons, dows] = sets;
      const count = Math.max(1, Math.min(20, parseInt(v.count, 10) || 5));
      const out = [];
      let d = new Date();
      d.setSeconds(0, 0);
      d.setMinutes(d.getMinutes() + 1);
      let guard = 0;
      while (out.length < count && guard < 600000) {
        guard++;
        if (!mons.has(d.getMonth() + 1)) { d.setMonth(d.getMonth() + 1, 1); d.setHours(0, 0, 0, 0); continue; }
        if (!doms.has(d.getDate())) { d.setDate(d.getDate() + 1); d.setHours(0, 0, 0, 0); continue; }
        if (!dows.has(d.getDay())) { d.setDate(d.getDate() + 1); d.setHours(0, 0, 0, 0); continue; }
        if (!hrs.has(d.getHours())) { d.setHours(d.getHours() + 1, 0, 0, 0); continue; }
        if (!mins.has(d.getMinutes())) { d.setMinutes(d.getMinutes() + 1, 0, 0); continue; }
        out.push(new Date(d).toISOString());
        d.setMinutes(d.getMinutes() + 1);
      }
      return out.length ? out.join("\n") : "No matching run times found (check field ranges).";
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

  { id: "d-useragent-builder", name: "User-Agent String Builder", cat: "dev", desc: "Build a browser/OS user-agent string.", tags: ["useragent", "http", "browser"],
    inputs: [
      { k: "browser", label: "Browser", type: "select", opts: ["Chrome", "Firefox", "Safari", "Edge"], value: "Chrome" },
      { k: "version", label: "Version", type: "text", placeholder: "128.0.0.0" },
      { k: "os", label: "OS", type: "select", opts: ["Windows 10/11", "macOS", "Linux", "Android", "iOS"], value: "Windows 10/11" },
    ],
    run(v) {
      const ver = v.version || "128.0.0.0";
      const osStr = { "Windows 10/11": "Windows NT 10.0; Win64; x64", "macOS": "Macintosh; Intel Mac OS X 10_15_7", "Linux": "X11; Linux x86_64", "Android": "Linux; Android 14; Pixel 8", "iOS": "iPhone; CPU iPhone OS 17_0 like Mac OS X" }[v.os] || "Windows NT 10.0; Win64; x64";
      if (v.browser === "Firefox") return `Mozilla/5.0 (${osStr}; rv:${ver}) Gecko/20100101 Firefox/${ver}`;
      if (v.browser === "Safari") return `Mozilla/5.0 (${osStr}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${ver} Safari/605.1.15`;
      if (v.browser === "Edge") return `Mozilla/5.0 (${osStr}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${ver} Safari/537.36 Edg/${ver}`;
      return `Mozilla/5.0 (${osStr}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${ver} Safari/537.36`;
    } },

  { id: "d-htaccess-redirect", name: ".htaccess Redirect Generator", cat: "dev", desc: "Generate an Apache .htaccess Redirect directive.", tags: ["htaccess", "apache", "redirect"],
    inputs: [{ k: "from", label: "From path", type: "text", placeholder: "/old-page" }, { k: "to", label: "To URL", type: "text", placeholder: "https://example.com/new-page" }, { k: "code", label: "Status", type: "select", opts: ["301", "302"], value: "301" }],
    run(v) {
      if (!v.from || !v.to) return { error: "Enter both a from-path and to-URL." };
      return `Redirect ${v.code} ${v.from} ${v.to}`;
    } },

  { id: "d-json-to-env", name: "JSON → .env", cat: "dev", desc: "Convert a flat JSON object into .env KEY=value lines.", tags: ["json", "env", "dotenv"],
    inputs: [{ k: "json", label: "JSON object", type: "textarea", rows: 6, placeholder: '{"PORT": 3000, "NAME": "app"}' }],
    run(v) {
      const p = tryParseJSON(v.json || ""); if (!p.ok) return { error: "Invalid JSON: " + p.err };
      if (typeof p.val !== "object" || p.val === null || Array.isArray(p.val)) return { error: "Provide a flat JSON object." };
      return Object.entries(p.val).map(([k, val]) => {
        let s = typeof val === "string" ? val : JSON.stringify(val);
        if (/\s/.test(s)) s = `"${s}"`;
        return `${k}=${s}`;
      }).join("\n");
    } },

  { id: "d-number-format", name: "Number Formatter", cat: "dev", desc: "Add thousands separators and fix decimal places.", tags: ["number", "format", "locale"],
    inputs: [{ k: "num", label: "Number", type: "text", placeholder: "1234567.891" }, { k: "decimals", label: "Decimal places", type: "range", min: 0, max: 10, step: 1, value: 2 }],
    run(v) {
      const n = parseFloat(v.num);
      if (isNaN(n)) return { error: "Enter a valid number." };
      return n.toLocaleString("en-US", { minimumFractionDigits: +v.decimals, maximumFractionDigits: +v.decimals });
    } },

  { id: "d-percentage-calc", name: "Percentage Calculator", cat: "dev", desc: "Compute 'x is what % of y' and 'x% of y'.", tags: ["percentage", "math"],
    inputs: [{ k: "x", label: "X", type: "text", placeholder: "25" }, { k: "y", label: "Y", type: "text", placeholder: "80" }],
    run(v) {
      const x = parseFloat(v.x), y = parseFloat(v.y);
      if (isNaN(x) || isNaN(y)) return { error: "Enter valid numbers for X and Y." };
      const lines = [];
      if (y !== 0) lines.push(`${x} is ${(x / y * 100).toFixed(4).replace(/\.?0+$/, "")}% of ${y}`);
      else lines.push(`${x} is undefined % of 0`);
      lines.push(`${x}% of ${y} = ${(x / 100 * y).toFixed(4).replace(/\.?0+$/, "")}`);
      return lines.join("\n");
    } },

  { id: "d-aspect-ratio", name: "Aspect Ratio Calculator", cat: "dev", desc: "Simplify a width:height ratio and fit dimensions to a target width or height.", tags: ["aspect", "ratio", "resolution"],
    inputs: [{ k: "w", label: "Width", type: "text", placeholder: "1920" }, { k: "h", label: "Height", type: "text", placeholder: "1080" }, { k: "targetW", label: "Fit to width (optional)", type: "text", placeholder: "800" }],
    run(v) {
      const w = parseFloat(v.w), h = parseFloat(v.h);
      if (!w || !h) return { error: "Enter width and height." };
      const gcd = (a, b) => b ? gcd(b, a % b) : a;
      const g = gcd(Math.round(w), Math.round(h)) || 1;
      const lines = [`Simplified ratio: ${Math.round(w) / g}:${Math.round(h) / g}`];
      if (v.targetW) { const tw = parseFloat(v.targetW); if (!isNaN(tw)) lines.push(`At width ${tw}: height = ${(tw * h / w).toFixed(2)}`); }
      return lines.join("\n");
    } },

  { id: "d-text-templater", name: "Text Templater", cat: "dev", desc: "Fill {{placeholders}} in a template using JSON values.", tags: ["template", "mustache", "placeholder"],
    inputs: [{ k: "template", label: "Template", type: "textarea", rows: 5, placeholder: "Hello {{name}}, you are {{age}}." }, { k: "data", label: "JSON values", type: "textarea", rows: 4, placeholder: '{"name": "Alex", "age": 30}' }],
    run(v) {
      if (!v.template) return "";
      const p = tryParseJSON(v.data || "{}"); if (!p.ok) return { error: "Invalid JSON values: " + p.err };
      return v.template.replace(/\{\{\s*([\w.]+)\s*\}\}/g, (m, key) => {
        const parts = key.split(".");
        let cur = p.val;
        for (const k of parts) { if (cur == null) return m; cur = cur[k]; }
        return cur === undefined ? m : String(cur);
      });
    } },

  { id: "d-json-diff", name: "JSON Diff", cat: "dev", desc: "Compare two JSON objects and list added, removed, and changed keys.", tags: ["json", "diff", "compare"],
    inputs: [{ k: "a", label: "JSON A", type: "textarea", rows: 6 }, { k: "b", label: "JSON B", type: "textarea", rows: 6 }],
    run(v) {
      const pa = tryParseJSON(v.a || ""), pb = tryParseJSON(v.b || "");
      if (!pa.ok) return { error: "Invalid JSON A: " + pa.err };
      if (!pb.ok) return { error: "Invalid JSON B: " + pb.err };
      const fa = flattenObj(pa.val, "", {}), fb = flattenObj(pb.val, "", {});
      const keys = new Set([...Object.keys(fa), ...Object.keys(fb)]);
      const added = [], removed = [], changed = [];
      for (const k of [...keys].sort()) {
        const inA = k in fa, inB = k in fb;
        if (inA && !inB) removed.push(`- ${k}: ${JSON.stringify(fa[k])}`);
        else if (!inA && inB) added.push(`+ ${k}: ${JSON.stringify(fb[k])}`);
        else if (JSON.stringify(fa[k]) !== JSON.stringify(fb[k])) changed.push(`~ ${k}: ${JSON.stringify(fa[k])} -> ${JSON.stringify(fb[k])}`);
      }
      const out = [...added, ...removed, ...changed];
      return out.length ? out.join("\n") : "No differences.";
    } },

  { id: "d-string-stats", name: "String Statistics", cat: "dev", desc: "Character/byte/line/word counts for a text block.", tags: ["stats", "count", "length"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }],
    run(v, H) {
      const t = S(v.text);
      const lines = t.length ? t.split(/\r?\n/).length : 0;
      const words = t.trim() ? t.trim().split(/\s+/).length : 0;
      const bytes = H.bytes(t).length;
      return [`Characters: ${t.length}`, `Bytes (UTF-8): ${bytes}`, `Words: ${words}`, `Lines: ${lines}`].join("\n");
    } },

  { id: "d-dup-lines", name: "Duplicate Line Finder", cat: "dev", desc: "Find and count duplicate lines in a block of text.", tags: ["duplicate", "lines", "dedupe"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "trim", label: "Trim whitespace before comparing", type: "checkbox", value: true }],
    run(v) {
      if (!v.text) return "";
      const lines = v.text.split(/\r?\n/);
      const counts = new Map();
      for (const l of lines) { const key = v.trim ? l.trim() : l; if (key === "") continue; counts.set(key, (counts.get(key) || 0) + 1); }
      const dups = [...counts.entries()].filter(([, c]) => c > 1);
      if (!dups.length) return "No duplicate lines found.";
      return dups.map(([l, c]) => `${c}x  ${l}`).join("\n");
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
        const desc = DESC[name.toLowerCase()] || "No description available for this header.";
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
      const cell = (r, c) => (r[c] === undefined ? "" : typeof r[c] === "object" ? JSON.stringify(r[c]) : String(r[c]));
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

  { id: "d-slugify", name: "Slugify", cat: "dev", desc: "Convert text into a URL-friendly slug.", tags: ["slug", "url", "kebab-case"],
    inputs: [{ k: "text", label: "Text", type: "text", placeholder: "My Great Article Title!" }],
    run(v) {
      if (!v.text) return "";
      return v.text.toString().trim().toLowerCase().normalize("NFKD").replace(/[̀-ͯ]/g, "").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
    } },

  { id: "d-case-convert", name: "Identifier Case Converter", cat: "dev", desc: "Convert an identifier between camelCase, PascalCase, snake_case, kebab-case, and CONSTANT_CASE.", tags: ["case", "camelcase", "snakecase", "kebabcase"],
    inputs: [{ k: "text", label: "Identifier", type: "text", placeholder: "my_variable_name" }, { k: "target", label: "Target case", type: "select", opts: ["camelCase", "PascalCase", "snake_case", "kebab-case", "CONSTANT_CASE"], value: "camelCase" }],
    run(v) {
      if (!v.text) return "";
      const words = v.text.trim().replace(/([a-z0-9])([A-Z])/g, "$1 $2").split(/[\s_\-]+/).filter(Boolean).map((w) => w.toLowerCase());
      if (!words.length) return "";
      if (v.target === "camelCase") return words[0] + words.slice(1).map((w) => w[0].toUpperCase() + w.slice(1)).join("");
      if (v.target === "PascalCase") return words.map((w) => w[0].toUpperCase() + w.slice(1)).join("");
      if (v.target === "snake_case") return words.join("_");
      if (v.target === "kebab-case") return words.join("-");
      return words.join("_").toUpperCase();
    } },

  { id: "d-json-minify", name: "JSON Minifier", cat: "dev", desc: "Strip all insignificant whitespace from JSON.", tags: ["json", "minify", "compact"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8 }],
    run(v) { const p = tryParseJSON(v.json || ""); if (!p.ok) return { error: "Invalid JSON: " + p.err }; return JSON.stringify(p.val); } },

  { id: "d-lorem-ipsum", name: "Lorem Ipsum Generator", cat: "dev", desc: "Generate placeholder Lorem Ipsum text by paragraphs, sentences, or words.", tags: ["lorem", "placeholder", "dummy"],
    inputs: [{ k: "unit", label: "Unit", type: "select", opts: ["Words", "Sentences", "Paragraphs"], value: "Paragraphs" }, { k: "count", label: "Count", type: "range", min: 1, max: 20, step: 1, value: 3 }],
    run(v) {
      const WORDS = "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua ut enim ad minim veniam quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat".split(" ");
      const rnd = (n) => Math.floor(Math.random() * n);
      const genWords = (n) => Array.from({ length: n }, () => WORDS[rnd(WORDS.length)]).join(" ");
      const genSentence = () => { const s = genWords(6 + rnd(8)); return s[0].toUpperCase() + s.slice(1) + "."; };
      const genParagraph = () => Array.from({ length: 3 + rnd(4) }, genSentence).join(" ");
      const count = Math.max(1, Math.min(20, parseInt(v.count, 10) || 1));
      if (v.unit === "Words") return genWords(count);
      if (v.unit === "Sentences") return Array.from({ length: count }, genSentence).join(" ");
      return Array.from({ length: count }, genParagraph).join("\n\n");
    } },

  { id: "d-random-data", name: "Random Test Data Generator", cat: "dev", desc: "Generate random names, emails, or IDs for test fixtures.", tags: ["fake", "mock", "test-data", "fixture"],
    inputs: [{ k: "kind", label: "Kind", type: "select", opts: ["Name", "Email", "Username", "Phone (US)"], value: "Name" }, { k: "count", label: "How many", type: "range", min: 1, max: 50, step: 1, value: 5 }],
    run(v) {
      const first = ["Alex", "Jordan", "Sam", "Taylor", "Casey", "Morgan", "Riley", "Jamie", "Drew", "Quinn"];
      const last = ["Smith", "Johnson", "Lee", "Brown", "Garcia", "Davis", "Miller", "Wilson", "Clark", "Lewis"];
      const rnd = (arr) => arr[Math.floor(Math.random() * arr.length)];
      const count = Math.max(1, Math.min(50, parseInt(v.count, 10) || 1));
      const out = [];
      for (let i = 0; i < count; i++) {
        const f = rnd(first), l = rnd(last);
        if (v.kind === "Name") out.push(`${f} ${l}`);
        else if (v.kind === "Email") out.push(`${f.toLowerCase()}.${l.toLowerCase()}${Math.floor(Math.random() * 100)}@example.com`);
        else if (v.kind === "Username") out.push(`${f.toLowerCase()}${l.toLowerCase()}${Math.floor(Math.random() * 1000)}`);
        else out.push(`(${100 + Math.floor(Math.random() * 900)}) ${100 + Math.floor(Math.random() * 900)}-${1000 + Math.floor(Math.random() * 9000)}`);
      }
      return out.join("\n");
    } },

  { id: "d-csv-to-json", name: "CSV → JSON", cat: "dev", desc: "Convert CSV (with header row) into a JSON array of objects.", tags: ["csv", "json", "convert"],
    inputs: [{ k: "csv", label: "CSV", type: "textarea", rows: 8, placeholder: "id,name\n1,Alex" }],
    run(v) {
      if (!v.csv) return "";
      const lines = v.csv.split(/\r?\n/).filter((l) => l.length);
      if (lines.length < 1) return { error: "No CSV data." };
      const parseRow = (line) => { const out = []; let cur = "", inQ = false; for (let i = 0; i < line.length; i++) { const c = line[i]; if (c === '"') inQ = !inQ; else if (c === "," && !inQ) { out.push(cur); cur = ""; } else cur += c; } out.push(cur); return out; };
      const header = parseRow(lines[0]);
      const rows = lines.slice(1).map((l) => { const cells = parseRow(l); const o = {}; header.forEach((h, i) => o[h] = cells[i] !== undefined ? cells[i] : ""); return o; });
      return JSON.stringify(rows, null, 2);
    } },

  { id: "d-json-to-csv", name: "JSON → CSV", cat: "dev", desc: "Convert a JSON array of flat objects into CSV.", tags: ["json", "csv", "convert"],
    inputs: [{ k: "json", label: "JSON array", type: "textarea", rows: 8, placeholder: '[{"id":1,"name":"Alex"}]' }],
    run(v) {
      const p = tryParseJSON(v.json || ""); if (!p.ok) return { error: "Invalid JSON: " + p.err };
      if (!Array.isArray(p.val) || !p.val.length) return { error: "Provide a non-empty JSON array of objects." };
      const cols = [...new Set(p.val.flatMap((r) => Object.keys(r || {})))];
      const esc = (s) => { s = s === undefined || s === null ? "" : typeof s === "object" ? JSON.stringify(s) : String(s); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
      const lines = [cols.join(","), ...p.val.map((r) => cols.map((c) => esc(r[c])).join(","))];
      return lines.join("\n");
    } },

  { id: "d-diff-stats", name: "Diff Summary Stats", cat: "dev", desc: "Count added/removed/unchanged lines between two texts without printing the full diff.", tags: ["diff", "stats", "summary"],
    inputs: [{ k: "a", label: "Original", type: "textarea", rows: 6 }, { k: "b", label: "Changed", type: "textarea", rows: 6 }],
    run(v) {
      const A = S(v.a).split(/\r?\n/), B = S(v.b).split(/\r?\n/);
      const n = A.length, m = B.length;
      const dp = Array.from({ length: n + 1 }, () => new Int32Array(m + 1));
      for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = A[i] === B[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
      let i = 0, j = 0, added = 0, removed = 0, same = 0;
      while (i < n && j < m) {
        if (A[i] === B[j]) { same++; i++; j++; }
        else if (dp[i + 1][j] >= dp[i][j + 1]) { removed++; i++; }
        else { added++; j++; }
      }
      removed += n - i; added += m - j;
      return `Added: ${added}\nRemoved: ${removed}\nUnchanged: ${same}`;
    } },

  { id: "d-word-frequency", name: "Word Frequency Counter", cat: "dev", desc: "Count occurrences of each word in a text, sorted by frequency.", tags: ["word", "frequency", "count"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "top", label: "Show top N", type: "range", min: 1, max: 50, step: 1, value: 15 }],
    run(v) {
      if (!v.text) return "";
      const words = v.text.toLowerCase().match(/[a-z0-9']+/g) || [];
      const counts = new Map();
      for (const w of words) counts.set(w, (counts.get(w) || 0) + 1);
      const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, Math.max(1, Math.min(50, parseInt(v.top, 10) || 15)));
      return sorted.map(([w, c]) => `${c.toString().padStart(4)}  ${w}`).join("\n") || "(no words found)";
    } },

  { id: "d-ip-cidr-info", name: "IPv4 CIDR Calculator", cat: "dev", desc: "Compute network address, broadcast address, and host range from an IPv4 CIDR.", tags: ["ip", "cidr", "network", "subnet"],
    inputs: [{ k: "cidr", label: "CIDR", type: "text", placeholder: "192.168.1.10/24" }],
    run(v) {
      const m = S(v.cidr).trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
      if (!m) return { error: "Enter an IPv4 CIDR, e.g. 192.168.1.0/24" };
      const octs = [1, 2, 3, 4].map((i) => +m[i]);
      const prefix = +m[5];
      if (octs.some((o) => o > 255) || prefix > 32) return { error: "Invalid IPv4 CIDR values." };
      const ip = (octs[0] << 24) + (octs[1] << 16) + (octs[2] << 8) + octs[3];
      const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
      const network = (ip & mask) >>> 0;
      const broadcast = (network | (~mask >>> 0)) >>> 0;
      const toIp = (n) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
      const hostCount = prefix >= 31 ? Math.pow(2, 32 - prefix) : Math.max(0, Math.pow(2, 32 - prefix) - 2);
      return [
        `Network:    ${toIp(network)}/${prefix}`,
        `Broadcast:  ${toIp(broadcast)}`,
        `Netmask:    ${toIp(mask)}`,
        `First host: ${prefix >= 31 ? toIp(network) : toIp(network + 1)}`,
        `Last host:  ${prefix >= 31 ? toIp(broadcast) : toIp(broadcast - 1)}`,
        `Usable hosts: ${hostCount}`,
      ].join("\n");
    } },

  { id: "d-json-schema-infer", name: "JSON Schema Inferrer", cat: "dev", desc: "Infer a basic JSON Schema (types) from a sample JSON value.", tags: ["json", "schema", "infer"],
    inputs: [{ k: "json", label: "Sample JSON", type: "textarea", rows: 8 }],
    run(v) {
      const p = tryParseJSON(v.json || ""); if (!p.ok) return { error: "Invalid JSON: " + p.err };
      const infer = (val) => {
        if (val === null) return { type: "null" };
        if (Array.isArray(val)) return { type: "array", items: val.length ? infer(val[0]) : {} };
        const t = typeof val;
        if (t === "object") { const props = {}; for (const k of Object.keys(val)) props[k] = infer(val[k]); return { type: "object", properties: props, required: Object.keys(val) }; }
        if (t === "number") return { type: Number.isInteger(val) ? "integer" : "number" };
        return { type: t };
      };
      return JSON.stringify(infer(p.val), null, 2);
    } },

  { id: "d-text-wrap", name: "Text Line Wrapper", cat: "dev", desc: "Wrap text to a maximum line width (word-aware).", tags: ["wrap", "text", "width"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "width", label: "Max width", type: "range", min: 20, max: 200, step: 5, value: 80 }],
    run(v) {
      if (!v.text) return "";
      const width = +v.width || 80;
      return v.text.split(/\r?\n/).map((para) => {
        if (!para) return "";
        const words = para.split(/\s+/).filter(Boolean);
        const lines = [];
        let line = "";
        for (const w of words) {
          if ((line + " " + w).trim().length > width && line) { lines.push(line); line = w; }
          else line = (line ? line + " " : "") + w;
        }
        if (line) lines.push(line);
        return lines.join("\n");
      }).join("\n");
    } },
];
