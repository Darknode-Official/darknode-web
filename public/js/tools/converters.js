// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Converter mini-tools (data formats, number bases, units, code generation). See _schema.md for the contract.

const BASE_OPTS = Array.from({ length: 35 }, (_, i) => String(i + 2));

function tryParseJSON(text) {
  try { return { ok: true, val: JSON.parse(text) }; } catch (e) { return { ok: false, err: e.message }; }
}

function describeJsonValue(val) {
  if (Array.isArray(val)) return `array with ${val.length} item(s)`;
  if (val === null) return "null";
  if (typeof val === "object") return `object with ${Object.keys(val).length} key(s)`;
  return typeof val;
}

// ---- CSV ----
function parseCSV(text, delim) {
  const rows = []; let row = [], field = "", inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else inQuotes = false; }
      else field += c;
    } else {
      if (c === '"') inQuotes = true;
      else if (c === delim) { row.push(field); field = ""; }
      else if (c === "\n") { row.push(field); rows.push(row); row = []; field = ""; }
      else if (c === "\r") { /* skip */ }
      else field += c;
    }
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  return rows;
}
function csvField(s, delim) {
  s = s === undefined || s === null ? "" : String(s);
  if (/["\n\r]/.test(s) || s.includes(delim)) return '"' + s.replace(/"/g, '""') + '"';
  return s;
}
function cleanRows(rows) { return rows.filter((r) => !(r.length === 1 && r[0] === "")); }

// ---- JSON -> XML ----
function xmlEscape(s) { return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c])); }
function xmlNode(val, tag) {
  const safeTag = /^[A-Za-z_][A-Za-z0-9_.-]*$/.test(tag) ? tag : "item";
  if (val === null || val === undefined) return `<${safeTag}/>`;
  if (Array.isArray(val)) return val.map((item) => xmlNode(item, safeTag)).join("");
  if (typeof val === "object") {
    const keys = Object.keys(val);
    if (!keys.length) return `<${safeTag}/>`;
    return `<${safeTag}>` + keys.map((k) => xmlNode(val[k], k)).join("") + `</${safeTag}>`;
  }
  return `<${safeTag}>${xmlEscape(val)}</${safeTag}>`;
}

// ---- JSON -> TypeScript ----
function inferTs(val) {
  if (val === null) return "null";
  if (Array.isArray(val)) {
    if (!val.length) return "any[]";
    const types = Array.from(new Set(val.map(inferTs)));
    return (types.length === 1 ? types[0] : `(${types.join(" | ")})`) + "[]";
  }
  switch (typeof val) {
    case "string": return "string";
    case "number": return "number";
    case "boolean": return "boolean";
    case "object": {
      const keys = Object.keys(val);
      if (!keys.length) return "{}";
      const body = keys.map((k) => {
        const safeKey = /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(k) ? k : JSON.stringify(k);
        return `  ${safeKey}: ${inferTs(val[k]).replace(/\n/g, "\n  ")};`;
      }).join("\n");
      return `{\n${body}\n}`;
    }
    default: return "any";
  }
}

// ---- JSON -> Go struct ----
function goFieldName(k) {
  return k.split(/[_\-\s]+/).filter(Boolean).map((w) => w[0].toUpperCase() + w.slice(1)).join("") || "Field";
}
function goType(val) {
  if (val === null) return "interface{}";
  if (Array.isArray(val)) return val.length ? "[]" + goType(val[0]) : "[]interface{}";
  switch (typeof val) {
    case "string": return "string";
    case "boolean": return "bool";
    case "number": return Number.isInteger(val) ? "int" : "float64";
    case "object": return goStruct(val);
    default: return "interface{}";
  }
}
function goStruct(obj) {
  const keys = Object.keys(obj);
  if (!keys.length) return "struct{}";
  const body = keys.map((k) => `\t${goFieldName(k)} ${goType(obj[k]).replace(/\n/g, "\n\t")} \`json:"${k}"\``).join("\n");
  return `struct {\n${body}\n}`;
}

// ---- cron ----
function cronPart(val, unit, names) {
  if (val === "*") return `every ${unit}`;
  if (/^\*\/\d+$/.test(val)) return `every ${val.split("/")[1]} ${unit}(s)`;
  if (val.includes(",")) return val.split(",").map((x) => (names ? names[+x] || x : x)).join(", ");
  if (val.includes("-")) { const [a, b] = val.split("-"); return `${names ? names[+a] || a : a} through ${names ? names[+b] || b : b}`; }
  return names ? names[+val] || val : val;
}

// ---- identifier case ----
function splitIdentifier(s) {
  return String(s).trim().replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/[_\-\s]+/g, " ").trim().split(" ").filter(Boolean).map((w) => w.toLowerCase());
}
// Round a non-negative decimal given as separate integer/fraction digit strings to
// `places` fractional digits (half-up), string-based to preserve big-integer precision.
function roundDecimalParts(ip, dp, places) {
  const arr = (ip + (dp || "")).split("");
  const keepLen = ip.length + places;
  const roundUp = keepLen < arr.length && arr[keepLen] >= "5";
  let kept = arr.slice(0, keepLen);
  while (kept.length < keepLen) kept.push("0");
  if (roundUp) {
    let i = kept.length - 1;
    for (; i >= 0; i--) { if (kept[i] === "9") { kept[i] = "0"; } else { kept[i] = String(+kept[i] + 1); break; } }
    if (i < 0) kept.unshift("1");
  }
  const frac = places > 0 ? kept.slice(kept.length - places).join("") : "";
  const intPart = kept.slice(0, kept.length - places).join("") || "0";
  return { ip: intPart, dp: frac };
}
function simpleCase(mode, s) {
  s = String(s);
  if (mode === "UPPERCASE") return s.toUpperCase();
  if (mode === "lowercase") return s.toLowerCase();
  if (mode === "Title Case") return s.replace(/\w\S*/g, (t) => t[0].toUpperCase() + t.slice(1).toLowerCase());
  return s;
}

function makeRadixTool(id, name, radix, label, tags) {
  return {
    id, name, cat: "converters", desc: `Convert between decimal and ${label} (base ${radix}).`, tags,
    inputs: [
      { k: "value", label: "Value", type: "text", placeholder: radix === 16 ? "ff" : radix === 2 ? "11111111" : "377" },
      { k: "mode", label: "Mode", type: "select", opts: [`Decimal → ${label}`, `${label} → Decimal`], value: `Decimal → ${label}` },
    ],
    run(v) {
      const s = String(v.value || "").trim();
      if (!s) return "";
      if (v.mode.startsWith("Decimal")) {
        let neg = false, t = s;
        if (t[0] === "-") { neg = true; t = t.slice(1); }
        if (!/^\d+$/.test(t)) return { error: "Enter a valid decimal integer." };
        try { return (neg ? "-" : "") + BigInt(t).toString(radix); } catch (e) { return { error: "Invalid number." }; }
      }
      let neg = false, t = s.toLowerCase().replace(/^0x|^0o|^0b/, "");
      if (t[0] === "-") { neg = true; t = t.slice(1); }
      const re = radix === 16 ? /^[0-9a-f]+$/ : radix === 8 ? /^[0-7]+$/ : /^[01]+$/;
      if (!re.test(t)) return { error: `Enter a valid base-${radix} number.` };
      let n = 0n; const rb = BigInt(radix);
      for (const ch of t) n = n * rb + BigInt(parseInt(ch, radix));
      return (neg ? "-" : "") + n.toString(10);
    },
  };
}

export const TOOLS = [
  { id: "c-json-prettify", name: "JSON Prettifier", cat: "converters", desc: "Pretty-print JSON with a chosen indent width.", tags: ["json", "format"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8, placeholder: '{"a":1,"b":[2,3]}' }, { k: "indent", label: "Indent", type: "select", opts: ["2 spaces", "4 spaces", "Tab"], value: "2 spaces" }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = tryParseJSON(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; const ind = v.indent === "4 spaces" ? 4 : v.indent === "Tab" ? "\t" : 2; return JSON.stringify(p.val, null, ind); } },

  { id: "c-json-minify", name: "JSON Minifier", cat: "converters", desc: "Strip all insignificant whitespace from JSON.", tags: ["json", "minify"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8 }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = tryParseJSON(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; return JSON.stringify(p.val); } },

  { id: "c-json-validate", name: "JSON Validator", cat: "converters", desc: "Check JSON syntax and report the exact error message.", tags: ["json", "validate", "lint"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8 }],
    run(v) { if (!v.json || !v.json.trim()) return ""; try { const val = JSON.parse(v.json); return `Valid JSON - ${describeJsonValue(val)}.`; } catch (e) { return { error: e.message }; } } },

  { id: "c-json-csv", name: "JSON → CSV", cat: "converters", desc: "Convert a JSON array of flat objects into CSV rows.", tags: ["json", "csv"],
    inputs: [{ k: "json", label: "JSON array", type: "textarea", rows: 8, placeholder: '[{"a":1,"b":2}]' }, { k: "delim", label: "Delimiter", type: "text", value: "," }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = tryParseJSON(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; const arr = p.val; if (!Array.isArray(arr)) return { error: "Input must be a JSON array of objects." }; if (!arr.length) return ""; const delim = v.delim || ","; const keys = []; for (const row of arr) if (row && typeof row === "object" && !Array.isArray(row)) for (const k of Object.keys(row)) if (!keys.includes(k)) keys.push(k); if (!keys.length) return { error: "Array items must be flat objects." }; const lines = [keys.map((k) => csvField(k, delim)).join(delim)]; for (const row of arr) lines.push(keys.map((k) => { let val = row ? row[k] : undefined; if (val === undefined || val === null) val = ""; else if (typeof val === "object") val = JSON.stringify(val); return csvField(val, delim); }).join(delim)); return lines.join("\n"); } },

  { id: "c-csv-json", name: "CSV → JSON", cat: "converters", desc: "Parse CSV (header row = keys) into a JSON array of objects.", tags: ["csv", "json"],
    inputs: [{ k: "csv", label: "CSV", type: "textarea", rows: 8, placeholder: "a,b\n1,2" }, { k: "delim", label: "Delimiter", type: "text", value: "," }],
    run(v) { if (!v.csv) return ""; const delim = v.delim || ","; const rows = cleanRows(parseCSV(v.csv.replace(/\r\n/g, "\n"), delim)); if (!rows.length) return { error: "No data rows found." }; const header = rows[0]; const out = rows.slice(1).map((r) => { const o = {}; header.forEach((h, i) => { o[h || "col" + i] = r[i] !== undefined ? r[i] : ""; }); return o; }); return JSON.stringify(out, null, 2); } },

  { id: "c-json-xml", name: "JSON → XML", cat: "converters", desc: "Convert a JSON value into simple nested XML.", tags: ["json", "xml"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8, placeholder: '{"user":{"id":1,"name":"a"}}' }, { k: "root", label: "Root tag", type: "text", value: "root" }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = tryParseJSON(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; const root = (v.root || "root").trim() || "root"; let inner; if (Array.isArray(p.val)) inner = p.val.map((item) => xmlNode(item, "item")).join(""); else if (p.val !== null && typeof p.val === "object") inner = Object.keys(p.val).map((k) => xmlNode(p.val[k], k)).join(""); else inner = xmlEscape(p.val); return `<?xml version="1.0" encoding="UTF-8"?>\n<${root}>${inner}</${root}>`; } },

  { id: "c-json-qs", name: "JSON → Query String", cat: "converters", desc: "Convert a flat JSON object into a URL query string.", tags: ["json", "querystring", "url"],
    inputs: [{ k: "json", label: "JSON object", type: "textarea", rows: 6, placeholder: '{"q":"test","page":2}' }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = tryParseJSON(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; const obj = p.val; if (typeof obj !== "object" || obj === null || Array.isArray(obj)) return { error: "Input must be a flat JSON object." }; const parts = []; for (const k of Object.keys(obj)) { const val = obj[k]; if (Array.isArray(val)) val.forEach((x) => parts.push(encodeURIComponent(k) + "=" + encodeURIComponent(x))); else if (val !== null && typeof val === "object") parts.push(encodeURIComponent(k) + "=" + encodeURIComponent(JSON.stringify(val))); else parts.push(encodeURIComponent(k) + "=" + encodeURIComponent(val === null || val === undefined ? "" : val)); } return parts.join("&"); } },

  { id: "c-qs-json", name: "Query String → JSON", cat: "converters", desc: "Parse a URL query string into a JSON object (repeated keys become arrays).", tags: ["querystring", "json", "url"],
    inputs: [{ k: "qs", label: "Query string", type: "text", placeholder: "q=test&page=2" }],
    run(v) { if (!v.qs) return ""; let s = v.qs.trim(); if (s.startsWith("?")) s = s.slice(1); const obj = {}; if (s) s.split("&").forEach((pair) => { if (!pair) return; const idx = pair.indexOf("="); let k = idx < 0 ? pair : pair.slice(0, idx), val = idx < 0 ? "" : pair.slice(idx + 1); try { k = decodeURIComponent(k.replace(/\+/g, " ")); } catch (e) {} try { val = decodeURIComponent(val.replace(/\+/g, " ")); } catch (e) {} if (Object.prototype.hasOwnProperty.call(obj, k)) { if (Array.isArray(obj[k])) obj[k].push(val); else obj[k] = [obj[k], val]; } else obj[k] = val; }); return JSON.stringify(obj, null, 2); } },

  { id: "c-csv-md", name: "CSV → Markdown Table", cat: "converters", desc: "Render CSV as a Markdown table.", tags: ["csv", "markdown"],
    inputs: [{ k: "csv", label: "CSV", type: "textarea", rows: 8 }, { k: "delim", label: "Delimiter", type: "text", value: "," }],
    run(v) { if (!v.csv) return ""; const delim = v.delim || ","; const rows = cleanRows(parseCSV(v.csv.replace(/\r\n/g, "\n"), delim)); if (!rows.length) return { error: "No data found." }; const esc = (s) => String(s).replace(/\|/g, "\\|"); const header = rows[0]; const lines = ["| " + header.map(esc).join(" | ") + " |", "| " + header.map(() => "---").join(" | ") + " |"]; rows.slice(1).forEach((r) => lines.push("| " + header.map((_, i) => esc(r[i] !== undefined ? r[i] : "")).join(" | ") + " |")); return lines.join("\n"); } },

  { id: "c-md-csv", name: "Markdown Table → CSV", cat: "converters", desc: "Extract a Markdown table's cells into CSV.", tags: ["markdown", "csv"],
    inputs: [{ k: "md", label: "Markdown table", type: "textarea", rows: 8, placeholder: "| a | b |\n| --- | --- |\n| 1 | 2 |" }, { k: "delim", label: "Delimiter", type: "text", value: "," }],
    run(v) { if (!v.md) return ""; const isSep = (l) => /^[\s|:-]+$/.test(l) && l.includes("-"); const lines = v.md.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.includes("|") && !isSep(l)); if (!lines.length) return { error: "No markdown table rows found." }; const delim = v.delim || ","; const rows = lines.map((l) => l.replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim())); return rows.map((r) => r.map((c) => csvField(c, delim)).join(delim)).join("\n"); } },

  { id: "c-base-convert", name: "Number Base Converter", cat: "converters", desc: "Convert an integer between any two bases (2-36).", tags: ["radix", "base", "number"],
    inputs: [{ k: "value", label: "Value", type: "text", placeholder: "ff" }, { k: "fromBase", label: "From base", type: "select", opts: BASE_OPTS, value: "16" }, { k: "toBase", label: "To base", type: "select", opts: BASE_OPTS, value: "10" }],
    run(v, H) { const from = H.clampInt(v.fromBase, 2, 36, 10), to = H.clampInt(v.toBase, 2, 36, 16); let s = String(v.value || "").trim(); if (!s) return ""; let neg = false; if (s[0] === "-") { neg = true; s = s.slice(1); } else if (s[0] === "+") s = s.slice(1); if (!s) return { error: "Enter a number." }; s = s.toLowerCase(); let n = 0n; const fb = BigInt(from); for (const ch of s) { let d; if (ch >= "0" && ch <= "9") d = ch.charCodeAt(0) - 48; else if (ch >= "a" && ch <= "z") d = ch.charCodeAt(0) - 97 + 10; else return { error: `Invalid character '${ch}' for base ${from}.` }; if (d >= from) return { error: `Digit '${ch}' is not valid in base ${from}.` }; n = n * fb + BigInt(d); } return (neg ? "-" : "") + n.toString(to); } },

  makeRadixTool("c-dec-hex", "Decimal ↔ Hex", 16, "Hex", ["hex", "radix"]),
  makeRadixTool("c-dec-bin", "Decimal ↔ Binary", 2, "Binary", ["binary", "radix"]),
  makeRadixTool("c-dec-oct", "Decimal ↔ Octal", 8, "Octal", ["octal", "radix"]),

  { id: "c-byte-size", name: "Byte Size Converter", cat: "converters", desc: "Convert a byte size into all SI (1000-based) and IEC (1024-based) units.", tags: ["bytes", "storage", "size"],
    inputs: [{ k: "value", label: "Value", type: "text", placeholder: "1.5" }, { k: "unit", label: "Unit", type: "select", opts: ["B", "KB", "MB", "GB", "TB", "PB", "KiB", "MiB", "GiB", "TiB", "PiB"], value: "MB" }],
    run(v) { const n = parseFloat(v.value); if (isNaN(n)) return { error: "Enter a numeric value." }; const SI = { B: 1, KB: 1e3, MB: 1e6, GB: 1e9, TB: 1e12, PB: 1e15 }; const IEC = { B: 1, KiB: 1024, MiB: 1024 ** 2, GiB: 1024 ** 3, TiB: 1024 ** 4, PiB: 1024 ** 5 }; const factor = SI[v.unit] || IEC[v.unit]; if (!factor) return { error: "Unknown unit." }; const bytes = n * factor; const fmt = (x) => { if (!isFinite(x)) return String(x); const r = Math.round(x * 1e6) / 1e6; return String(r); }; return [`Bytes: ${fmt(bytes)}`, "-- SI (1000-based) --", `KB: ${fmt(bytes / SI.KB)}`, `MB: ${fmt(bytes / SI.MB)}`, `GB: ${fmt(bytes / SI.GB)}`, `TB: ${fmt(bytes / SI.TB)}`, `PB: ${fmt(bytes / SI.PB)}`, "-- IEC (1024-based) --", `KiB: ${fmt(bytes / IEC.KiB)}`, `MiB: ${fmt(bytes / IEC.MiB)}`, `GiB: ${fmt(bytes / IEC.GiB)}`, `TiB: ${fmt(bytes / IEC.TiB)}`, `PiB: ${fmt(bytes / IEC.PiB)}`].join("\n"); } },

  { id: "c-epoch-date", name: "Epoch → Human Date", cat: "converters", desc: "Convert a Unix epoch (seconds or milliseconds, auto-detected) to ISO/UTC date strings.", tags: ["epoch", "unix", "date", "time"],
    inputs: [{ k: "epoch", label: "Epoch value", type: "text", placeholder: "1700000000" }],
    run(v) { const raw = String(v.epoch || "").trim(); if (!raw) return ""; if (!/^-?\d+(\.\d+)?$/.test(raw)) return { error: "Enter a numeric epoch value." }; const n = parseFloat(raw); const ms = Math.abs(n) > 1e12 ? n : n * 1000; const d = new Date(ms); if (isNaN(d.getTime())) return { error: "Value out of range." }; return `ISO: ${d.toISOString()}\nUTC: ${d.toUTCString()}\nUnix (s): ${Math.floor(ms / 1000)}\nUnix (ms): ${Math.round(ms)}`; } },

  { id: "c-date-epoch", name: "Date/ISO → Epoch", cat: "converters", desc: "Parse a date or ISO-8601 string into Unix epoch seconds and milliseconds.", tags: ["date", "iso", "epoch", "unix"],
    inputs: [{ k: "date", label: "Date or ISO string", type: "text", placeholder: "2026-01-01T00:00:00Z" }],
    run(v) { if (!v.date) return ""; const t = Date.parse(v.date); if (isNaN(t)) return { error: "Could not parse date/ISO string." }; return `Epoch seconds: ${Math.floor(t / 1000)}\nEpoch ms: ${t}`; } },

  { id: "c-duration-sec", name: "ISO-8601 Duration → Seconds", cat: "converters", desc: "Convert an ISO-8601 duration (e.g. P1DT2H3M4S) to total seconds.", tags: ["duration", "iso8601", "time"],
    inputs: [{ k: "duration", label: "Duration", type: "text", placeholder: "P1DT2H3M4S" }],
    run(v) { const s = String(v.duration || "").trim(); if (!s) return ""; const m = /^P(?:(\d+(?:\.\d+)?)Y)?(?:(\d+(?:\.\d+)?)M)?(?:(\d+(?:\.\d+)?)W)?(?:(\d+(?:\.\d+)?)D)?(?:T(?:(\d+(?:\.\d+)?)H)?(?:(\d+(?:\.\d+)?)M)?(?:(\d+(?:\.\d+)?)S)?)?$/.exec(s); if (!m || s === "P") return { error: "Not a valid ISO-8601 duration (e.g. P1DT2H3M4S)." }; const g = m.slice(1).map((x) => (x ? parseFloat(x) : 0)); const [y, mo, w, d, h, mi, se] = g; const total = y * 365 * 86400 + mo * 30 * 86400 + w * 7 * 86400 + d * 86400 + h * 3600 + mi * 60 + se; return String(total); } },

  { id: "c-sec-duration", name: "Seconds → Human Duration", cat: "converters", desc: "Convert a number of seconds to \"Nd Nh Nm Ns\" format.", tags: ["duration", "time", "seconds"],
    inputs: [{ k: "seconds", label: "Seconds", type: "text", placeholder: "93784" }],
    run(v) { let n = parseFloat(v.seconds); if (isNaN(n)) return { error: "Enter seconds as a number." }; const neg = n < 0; n = Math.abs(n); const d = Math.floor(n / 86400); n -= d * 86400; const h = Math.floor(n / 3600); n -= h * 3600; const mi = Math.floor(n / 60); n -= mi * 60; const s = Math.round(n * 1000) / 1000; const parts = []; if (d) parts.push(d + "d"); if (h) parts.push(h + "h"); if (mi) parts.push(mi + "m"); if (s || !parts.length) parts.push(s + "s"); return (neg ? "-" : "") + parts.join(" "); } },

  { id: "c-ms-hhmmss", name: "Milliseconds → hh:mm:ss.mmm", cat: "converters", desc: "Format a millisecond count as hh:mm:ss.mmm.", tags: ["time", "duration", "milliseconds"],
    inputs: [{ k: "ms", label: "Milliseconds", type: "text", placeholder: "3661234" }],
    run(v) { let n = parseFloat(v.ms); if (isNaN(n)) return { error: "Enter milliseconds as a number." }; const neg = n < 0; n = Math.abs(Math.round(n)); const ms = n % 1000; const totalSec = Math.floor(n / 1000); const s = totalSec % 60; const totalMin = Math.floor(totalSec / 60); const mi = totalMin % 60; const h = Math.floor(totalMin / 60); const pad = (x, l = 2) => String(x).padStart(l, "0"); return (neg ? "-" : "") + `${pad(h)}:${pad(mi)}:${pad(s)}.${pad(ms, 3)}`; } },

  { id: "c-roman", name: "Roman Numerals ↔ Integer", cat: "converters", desc: "Convert between Roman numerals and integers (1-3999).", tags: ["roman", "numeral"],
    inputs: [{ k: "value", label: "Integer or Roman numeral", type: "text", placeholder: "MCMXCIV" }],
    run(v) { const s = String(v.value || "").trim(); if (!s) return ""; if (/^\d+$/.test(s)) { let n = parseInt(s, 10); if (n < 1 || n > 3999) return { error: "Integer must be 1-3999 for Roman numerals." }; const table = [[1000, "M"], [900, "CM"], [500, "D"], [400, "CD"], [100, "C"], [90, "XC"], [50, "L"], [40, "XL"], [10, "X"], [9, "IX"], [5, "V"], [4, "IV"], [1, "I"]]; let out = ""; for (const [val, sym] of table) while (n >= val) { out += sym; n -= val; } return out; } const R = { I: 1, V: 5, X: 10, L: 50, C: 100, D: 500, M: 1000 }; const up = s.toUpperCase(); if (!/^[IVXLCDM]+$/.test(up)) return { error: "Enter a positive integer or valid Roman numeral." }; let total = 0, prev = 0; for (let i = up.length - 1; i >= 0; i--) { const val = R[up[i]]; if (val < prev) total -= val; else { total += val; prev = val; } } return String(total); } },

  { id: "c-temperature", name: "Temperature Converter", cat: "converters", desc: "Convert Celsius, Fahrenheit and Kelvin.", tags: ["temperature", "celsius", "fahrenheit", "kelvin"],
    inputs: [{ k: "value", label: "Value", type: "text", placeholder: "100" }, { k: "from", label: "From", type: "select", opts: ["C", "F", "K"], value: "C" }],
    run(v) { const n = parseFloat(v.value); if (isNaN(n)) return { error: "Enter a numeric temperature." }; let c; if (v.from === "C") c = n; else if (v.from === "F") c = (n - 32) * 5 / 9; else c = n - 273.15; const f = c * 9 / 5 + 32; const k = c + 273.15; if (k < 0) return { error: "Below absolute zero." }; const r = (x) => Math.round(x * 100) / 100; return `Celsius: ${r(c)} C\nFahrenheit: ${r(f)} F\nKelvin: ${r(k)} K`; } },

  { id: "c-data-rate", name: "Data Rate Converter", cat: "converters", desc: "Convert network data rates (bps/Kbps/Mbps/Gbps/Tbps) and bytes/sec.", tags: ["bandwidth", "network", "bps"],
    inputs: [{ k: "value", label: "Value", type: "text", placeholder: "100" }, { k: "unit", label: "Unit", type: "select", opts: ["bps", "Kbps", "Mbps", "Gbps", "Tbps"], value: "Mbps" }],
    run(v) { const n = parseFloat(v.value); if (isNaN(n)) return { error: "Enter a numeric value." }; const units = { bps: 1, Kbps: 1e3, Mbps: 1e6, Gbps: 1e9, Tbps: 1e12 }; const factor = units[v.unit]; if (!factor) return { error: "Unknown unit." }; const bps = n * factor; const fmt = (x) => { if (!isFinite(x)) return String(x); return String(Math.round(x * 1e6) / 1e6); }; return `bps: ${fmt(bps)}\nKbps: ${fmt(bps / 1e3)}\nMbps: ${fmt(bps / 1e6)}\nGbps: ${fmt(bps / 1e9)}\nTbps: ${fmt(bps / 1e12)}\nBytes/s: ${fmt(bps / 8)}\nKB/s: ${fmt(bps / 8 / 1e3)}\nMB/s: ${fmt(bps / 8 / 1e6)}`; } },

  { id: "c-hex-rgb", name: "Color HEX ↔ RGB", cat: "converters", desc: "Convert between hex colors and rgb() notation.", tags: ["color", "hex", "rgb"],
    inputs: [{ k: "value", label: "Color", type: "text", placeholder: "#3366ff or 51,102,255" }, { k: "mode", label: "Mode", type: "select", opts: ["Hex → RGB", "RGB → Hex"], value: "Hex → RGB" }],
    run(v) { const s = String(v.value || "").trim(); if (!s) return ""; if (v.mode === "Hex → RGB") { let h = s.replace(/^#/, ""); if (h.length === 3) h = h.split("").map((c) => c + c).join(""); if (!/^[0-9a-fA-F]{6}$/.test(h)) return { error: "Enter a valid hex color (#RGB or #RRGGBB)." }; const r = parseInt(h.slice(0, 2), 16), g = parseInt(h.slice(2, 4), 16), b = parseInt(h.slice(4, 6), 16); return `rgb(${r}, ${g}, ${b})`; } const m = s.match(/(-?\d+(?:\.\d+)?)/g); if (!m || m.length < 3) return { error: "Enter RGB as r,g,b (e.g. 51,102,255)." }; const [r, g, b] = m.slice(0, 3).map((x) => Math.max(0, Math.min(255, Math.round(parseFloat(x))))); const h2 = (x) => x.toString(16).padStart(2, "0"); return ("#" + h2(r) + h2(g) + h2(b)).toUpperCase(); } },

  { id: "c-rgb-hsl", name: "RGB → HSL", cat: "converters", desc: "Convert an RGB color to HSL.", tags: ["color", "rgb", "hsl"],
    inputs: [{ k: "rgb", label: "RGB (r,g,b)", type: "text", placeholder: "51,102,255" }],
    run(v) { const m = String(v.rgb || "").match(/(-?\d+(?:\.\d+)?)/g); if (!m || m.length < 3) return { error: "Enter RGB as r,g,b." }; let [r, g, b] = m.slice(0, 3).map(Number); r /= 255; g /= 255; b /= 255; const max = Math.max(r, g, b), min = Math.min(r, g, b); let h = 0, s = 0; const l = (max + min) / 2; if (max !== min) { const d = max - min; s = l > 0.5 ? d / (2 - max - min) : d / (max + min); if (max === r) h = (g - b) / d + (g < b ? 6 : 0); else if (max === g) h = (b - r) / d + 2; else h = (r - g) / d + 4; h *= 60; } return `hsl(${Math.round(h)}, ${Math.round(s * 100)}%, ${Math.round(l * 100)}%)`; } },

  { id: "c-rgb-cmyk", name: "RGB → CMYK", cat: "converters", desc: "Convert an RGB color to CMYK percentages.", tags: ["color", "rgb", "cmyk", "print"],
    inputs: [{ k: "rgb", label: "RGB (r,g,b)", type: "text", placeholder: "51,102,255" }],
    run(v) { const m = String(v.rgb || "").match(/(-?\d+(?:\.\d+)?)/g); if (!m || m.length < 3) return { error: "Enter RGB as r,g,b." }; const [r, g, b] = m.slice(0, 3).map((x) => Math.max(0, Math.min(255, Number(x))) / 255); const k = 1 - Math.max(r, g, b); if (k >= 1) return "cmyk(0%, 0%, 0%, 100%)"; const c = (1 - r - k) / (1 - k), y2 = (1 - g - k) / (1 - k), ye = (1 - b - k) / (1 - k); const p = (x) => Math.round(x * 100); return `cmyk(${p(c)}%, ${p(y2)}%, ${p(ye)}%, ${p(k)}%)`; } },

  { id: "c-px-rem", name: "CSS px ↔ rem", cat: "converters", desc: "Convert between pixels and rem using a configurable base (default 16).", tags: ["css", "px", "rem"],
    inputs: [{ k: "value", label: "Value", type: "text", placeholder: "24" }, { k: "base", label: "Base font size (px)", type: "text", value: "16" }, { k: "mode", label: "Mode", type: "select", opts: ["px → rem", "rem → px"], value: "px → rem" }],
    run(v) { const n = parseFloat(v.value); if (isNaN(n)) return { error: "Enter a numeric value." }; const base = parseFloat(v.base) || 16; if (v.mode === "px → rem") return (n / base) + "rem"; return (n * base) + "px"; } },

  

  { id: "c-ascii-text", name: "ASCII Codes ↔ Text", cat: "converters", desc: "Convert text to space-separated decimal character codes and back.", tags: ["ascii", "codes"],
    inputs: [{ k: "text", label: "Text or codes", type: "textarea" }, { k: "mode", label: "Mode", type: "select", opts: ["Text → Codes", "Codes → Text"], value: "Text → Codes" }],
    run(v) { if (!v.text) return ""; if (v.mode === "Text → Codes") return Array.from(v.text).map((c) => c.codePointAt(0)).join(" "); const parts = v.text.trim().split(/[\s,]+/).filter(Boolean); if (!parts.every((p) => /^\d+$/.test(p))) return { error: "Enter space/comma separated decimal codes." }; try { return parts.map((p) => String.fromCodePoint(parseInt(p, 10))).join(""); } catch (e) { return { error: "Invalid code point." }; } } },

  { id: "c-utf8-inspect", name: "UTF-8 Byte Inspector", cat: "converters", desc: "Show each character's code point and raw UTF-8 bytes.", tags: ["utf8", "unicode", "bytes"],
    inputs: [{ k: "text", label: "Text", type: "textarea", placeholder: "café" }],
    run(v, H) { if (!v.text) return ""; return Array.from(v.text).map((ch) => { const cp = ch.codePointAt(0); const bytes = H.toHex(H.bytes(ch)).match(/.{2}/g).join(" "); return `'${ch}'  U+${cp.toString(16).toUpperCase().padStart(4, "0")}  dec:${cp}  utf8:${bytes}`; }).join("\n"); } },

  { id: "c-chmod", name: "Unix chmod (Octal ↔ Symbolic)", cat: "converters", desc: "Convert Unix file permissions between octal and symbolic rwx notation.", tags: ["chmod", "unix", "permissions"],
    inputs: [{ k: "value", label: "Permission", type: "text", placeholder: "755" }, { k: "mode", label: "Mode", type: "select", opts: ["Octal → Symbolic", "Symbolic → Octal"], value: "Octal → Symbolic" }],
    run(v) { const s = String(v.value || "").trim(); if (!s) return ""; if (v.mode === "Octal → Symbolic") { if (!/^[0-7]{3,4}$/.test(s)) return { error: "Enter a valid octal mode (e.g. 755 or 0755)." }; const digits = s.length === 4 ? s.slice(1) : s; const map = (d) => { const n = +d; return (n & 4 ? "r" : "-") + (n & 2 ? "w" : "-") + (n & 1 ? "x" : "-"); }; return digits.split("").map(map).join(""); } if (!/^([r-][w-][xstST-]){3}$/.test(s)) return { error: "Enter symbolic permissions (e.g. rwxr-xr-x)." }; const groups = [s.slice(0, 3), s.slice(3, 6), s.slice(6, 9)]; return groups.map((g) => { let n = 0; if (g[0] === "r") n += 4; if (g[1] === "w") n += 2; if (g[2] === "x" || g[2] === "s" || g[2] === "t") n += 1; return n; }).join(""); } },

  { id: "c-deg-rad", name: "Degrees ↔ Radians", cat: "converters", desc: "Convert between angle degrees and radians.", tags: ["angle", "degrees", "radians", "math"],
    inputs: [{ k: "value", label: "Value", type: "text", placeholder: "180" }, { k: "mode", label: "Mode", type: "select", opts: ["Degrees → Radians", "Radians → Degrees"], value: "Degrees → Radians" }],
    run(v) { const n = parseFloat(v.value); if (isNaN(n)) return { error: "Enter a numeric value." }; if (v.mode === "Degrees → Radians") return String(n * Math.PI / 180); return String(n * 180 / Math.PI); } },

  { id: "c-base64-hex", name: "Base64 ↔ Hex", cat: "converters", desc: "Convert raw bytes between Base64 and hex representation.", tags: ["base64", "hex", "bytes"],
    inputs: [{ k: "value", label: "Base64 or hex", type: "textarea" }, { k: "mode", label: "Mode", type: "select", opts: ["Base64 → Hex", "Hex → Base64"], value: "Base64 → Hex" }],
    run(v) { const s = String(v.value || "").trim(); if (!s) return ""; if (v.mode === "Base64 → Hex") { try { const bin = atob(s.replace(/\s+/g, "")); let hex = ""; for (let i = 0; i < bin.length; i++) hex += bin.charCodeAt(i).toString(16).padStart(2, "0"); return hex; } catch (e) { return { error: "Not valid Base64." }; } } const clean = s.replace(/[^0-9a-fA-F]/g, ""); if (clean.length % 2) return { error: "Hex string must have an even number of digits." }; let bin = ""; for (let i = 0; i < clean.length; i += 2) bin += String.fromCharCode(parseInt(clean.substr(i, 2), 16)); try { return btoa(bin); } catch (e) { return { error: "Could not encode to Base64." }; } } },

  { id: "c-json-ts", name: "JSON → TypeScript Interface", cat: "converters", desc: "Infer a TypeScript interface from a JSON value.", tags: ["json", "typescript", "codegen"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8, placeholder: '{"id":1,"name":"a","tags":["x"]}' }, { k: "name", label: "Interface name", type: "text", value: "Root" }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = tryParseJSON(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; const name = (v.name || "Root").trim() || "Root"; const t = inferTs(p.val); if (t.startsWith("{")) return `interface ${name} ${t}`; return `type ${name} = ${t};`; } },

  { id: "c-json-go", name: "JSON → Go Struct", cat: "converters", desc: "Infer a Go struct (with json tags) from a JSON object.", tags: ["json", "golang", "codegen"],
    inputs: [{ k: "json", label: "JSON object", type: "textarea", rows: 8, placeholder: '{"id":1,"name":"a"}' }, { k: "name", label: "Struct name", type: "text", value: "Root" }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = tryParseJSON(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; if (typeof p.val !== "object" || p.val === null || Array.isArray(p.val)) return { error: "Top-level JSON must be an object." }; const name = (v.name || "Root").trim() || "Root"; return `type ${name} ${goStruct(p.val)}`; } },

  { id: "c-sql-in", name: "SQL IN(...) Clause Builder", cat: "converters", desc: "Build a SQL IN (...) clause from a newline/comma separated list, quoting strings.", tags: ["sql", "query"],
    inputs: [{ k: "list", label: "Values (newline or comma separated)", type: "textarea", rows: 6, placeholder: "alice\nbob\ncarol" }, { k: "forceQuote", label: "Always quote as strings", type: "checkbox", value: false }],
    run(v) { const raw = String(v.list || "").trim(); if (!raw) return ""; const items = raw.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean); if (!items.length) return { error: "Enter at least one value." }; const allNumeric = items.every((x) => /^-?\d+(\.\d+)?$/.test(x)); const rendered = items.map((x) => (allNumeric && !v.forceQuote) ? x : `'${x.replace(/'/g, "''")}'`); return `IN (${rendered.join(", ")})`; } },

  { id: "c-list-json-array", name: "Newline List ↔ JSON String Array", cat: "converters", desc: "Convert a newline-separated list to a JSON string array and back.", tags: ["json", "list", "array"],
    inputs: [{ k: "text", label: "List or JSON array", type: "textarea", rows: 8 }, { k: "mode", label: "Mode", type: "select", opts: ["List → JSON", "JSON → List"], value: "List → JSON" }],
    run(v) { if (!v.text) return ""; if (v.mode === "List → JSON") { const items = v.text.split(/\r?\n/).map((s) => s.trim()).filter(Boolean); return JSON.stringify(items, null, 2); } const p = tryParseJSON(v.text); if (!p.ok) return { error: "Invalid JSON: " + p.err }; if (!Array.isArray(p.val)) return { error: "Input must be a JSON array." }; return p.val.map((x) => (typeof x === "string" ? x : JSON.stringify(x))).join("\n"); } },

  { id: "c-csv-column", name: "CSV Column Extractor", cat: "converters", desc: "Pick a single column (by 0-based index) out of CSV data.", tags: ["csv", "column"],
    inputs: [{ k: "csv", label: "CSV", type: "textarea", rows: 8 }, { k: "col", label: "Column index (0-based)", type: "text", value: "0" }, { k: "delim", label: "Delimiter", type: "text", value: "," }, { k: "skipHeader", label: "Skip header row", type: "checkbox", value: true }],
    run(v) { if (!v.csv) return ""; const delim = v.delim || ","; const rows = cleanRows(parseCSV(v.csv.replace(/\r\n/g, "\n"), delim)); if (!rows.length) return { error: "No data found." }; const idx = parseInt(v.col, 10); if (isNaN(idx) || idx < 0) return { error: "Enter a valid 0-based column index." }; const start = v.skipHeader ? 1 : 0; return rows.slice(start).map((r) => (r[idx] !== undefined ? r[idx] : "")).join("\n"); } },

  { id: "c-csv-case", name: "String Case for CSV Column", cat: "converters", desc: "Change the letter case of every value in one CSV column.", tags: ["csv", "case"],
    inputs: [{ k: "csv", label: "CSV", type: "textarea", rows: 8 }, { k: "col", label: "Column index (0-based)", type: "text", value: "0" }, { k: "delim", label: "Delimiter", type: "text", value: "," }, { k: "skipHeader", label: "Skip header row", type: "checkbox", value: true }, { k: "mode", label: "Case", type: "select", opts: ["UPPERCASE", "lowercase", "Title Case"], value: "UPPERCASE" }],
    run(v) { if (!v.csv) return ""; const delim = v.delim || ","; const rows = cleanRows(parseCSV(v.csv.replace(/\r\n/g, "\n"), delim)); if (!rows.length) return { error: "No data found." }; const idx = parseInt(v.col, 10); if (isNaN(idx) || idx < 0) return { error: "Enter a valid 0-based column index." }; const start = v.skipHeader ? 1 : 0; for (let i = start; i < rows.length; i++) if (rows[i][idx] !== undefined) rows[i][idx] = simpleCase(v.mode, rows[i][idx]); return rows.map((r) => r.map((c) => csvField(c, delim)).join(delim)).join("\n"); } },

  { id: "c-cron-human", name: "Cron Expression → Human Description", cat: "converters", desc: "Describe a standard 5-field cron expression in plain English.", tags: ["cron", "schedule"],
    inputs: [{ k: "cron", label: "Cron expression", type: "text", placeholder: "*/15 9-17 * * 1-5" }],
    run(v) { const s = String(v.cron || "").trim(); if (!s) return ""; const fields = s.split(/\s+/); if (fields.length !== 5) return { error: "Enter a standard 5-field cron expression (min hour dom mon dow)." }; const [min, hour, dom, mon, dow] = fields; const MON = ["", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]; const DOW = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]; return [`Minute: ${cronPart(min, "minute")}`, `Hour: ${cronPart(hour, "hour")}`, `Day of month: ${cronPart(dom, "day")}`, `Month: ${cronPart(mon, "month", MON)}`, `Day of week: ${cronPart(dow, "weekday", DOW)}`].join("\n"); } },

  { id: "c-hex-rgba", name: "Hex Color → rgba()", cat: "converters", desc: "Convert a hex color plus alpha into an rgba() string.", tags: ["color", "hex", "rgba", "alpha"],
    inputs: [{ k: "hex", label: "Hex color", type: "text", placeholder: "#3366ff" }, { k: "alpha", label: "Alpha", type: "range", min: 0, max: 1, step: 0.01, value: 1 }],
    run(v) { let h = String(v.hex || "").trim().replace(/^#/, ""); if (h.length === 3) h = h.split("").map((c) => c + c).join(""); if (!/^[0-9a-fA-F]{6}$/.test(h)) return { error: "Enter a valid hex color." }; const r = parseInt(h.slice(0, 2), 16), g = parseInt(h.slice(2, 4), 16), b = parseInt(h.slice(4, 6), 16); let a = parseFloat(v.alpha); if (isNaN(a)) a = 1; a = Math.max(0, Math.min(1, a)); return `rgba(${r}, ${g}, ${b}, ${a})`; } },

  { id: "c-identifier-case", name: "Identifier Case Converter", cat: "converters", desc: "Convert identifiers between camelCase, PascalCase, snake_case, kebab-case and CONSTANT_CASE.", tags: ["camelcase", "snakecase", "kebabcase", "identifier"],
    inputs: [{ k: "text", label: "Identifier", type: "text", placeholder: "my_variable-Name" }, { k: "mode", label: "Target case", type: "select", opts: ["camelCase", "PascalCase", "snake_case", "kebab-case", "CONSTANT_CASE"], value: "camelCase" }],
    run(v) { if (!v.text) return ""; const words = splitIdentifier(v.text); if (!words.length) return ""; switch (v.mode) { case "camelCase": return words.map((w, i) => (i === 0 ? w : w[0].toUpperCase() + w.slice(1))).join(""); case "PascalCase": return words.map((w) => w[0].toUpperCase() + w.slice(1)).join(""); case "snake_case": return words.join("_"); case "kebab-case": return words.join("-"); case "CONSTANT_CASE": return words.map((w) => w.toUpperCase()).join("_"); default: return words.join(" "); } } },

  { id: "c-thousands-sep", name: "Thousands Separator Formatter", cat: "converters", desc: "Format a number with a thousands separator and optional fixed decimals.", tags: ["number", "format"],
    inputs: [{ k: "value", label: "Number", type: "text", placeholder: "1234567.891" }, { k: "sep", label: "Separator", type: "select", opts: [",", ".", " ", "_"], value: "," }, { k: "decimals", label: "Decimal places (blank = as-is)", type: "text", placeholder: "auto" }],
    run(v) { const raw = String(v.value || "").trim(); if (!raw) return ""; if (!/^-?\d+(\.\d+)?$/.test(raw)) return { error: "Enter a valid number." }; const neg = raw[0] === "-"; const abs = neg ? raw.slice(1) : raw; const [ip, dp] = abs.split("."); const sep = v.sep || ","; let ipOut = ip, dec = ""; if (v.decimals !== undefined && v.decimals !== "") { const places = Math.max(0, parseInt(v.decimals, 10) || 0); const r = roundDecimalParts(ip, dp, places); ipOut = r.ip; dec = places > 0 ? "." + r.dp : ""; } else if (dp !== undefined) { dec = "." + dp; } const grouped = ipOut.replace(/\B(?=(\d{3})+(?!\d))/g, sep); return (neg ? "-" : "") + grouped + dec; } },

  { id: "c-sci-decimal", name: "Scientific Notation ↔ Decimal", cat: "converters", desc: "Convert between plain decimal and scientific (exponential) notation.", tags: ["scientific", "exponential", "number"],
    inputs: [{ k: "value", label: "Value", type: "text", placeholder: "123000" }, { k: "mode", label: "Mode", type: "select", opts: ["Decimal → Scientific", "Scientific → Decimal"], value: "Decimal → Scientific" }, { k: "digits", label: "Significant digits (Decimal → Scientific)", type: "text", value: "6" }],
    run(v) { const s = String(v.value || "").trim(); if (!s) return ""; if (v.mode === "Decimal → Scientific") { const n = Number(s); if (!isFinite(n)) return { error: "Enter a valid number." }; const digits = v.digits !== undefined && v.digits !== "" ? Math.max(1, parseInt(v.digits, 10) || 1) : 6; return n.toExponential(digits - 1); } const n = Number(s); if (!isFinite(n)) return { error: "Enter valid scientific notation (e.g. 1.23e5)." }; return n.toString(); } },

  { id: "c-csv-tsv", name: "CSV ↔ TSV", cat: "converters", desc: "Convert delimited data between comma-separated and tab-separated.", tags: ["csv", "tsv", "delimiter"],
    inputs: [{ k: "text", label: "Data", type: "textarea", rows: 8 }, { k: "mode", label: "Mode", type: "select", opts: ["CSV → TSV", "TSV → CSV"], value: "CSV → TSV" }],
    run(v) { if (!v.text) return ""; const from = v.mode === "CSV → TSV" ? "," : "\t"; const to = v.mode === "CSV → TSV" ? "\t" : ","; const rows = cleanRows(parseCSV(v.text.replace(/\r\n/g, "\n"), from)); return rows.map((r) => r.map((c) => csvField(c, to)).join(to)).join("\n"); } },

  

  

  
];
