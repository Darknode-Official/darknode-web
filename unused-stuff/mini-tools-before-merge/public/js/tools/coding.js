// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
// Coding & Data Formats mini-tools. See _schema.md for the contract.
// All tools are pure, client-side, deterministic. Converters/parsers cover the
// COMMON subset of each format (documented in help); accuracy over coverage.

const S = (v) => (v == null ? "" : String(v));
const isPlainObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const tryJSON = (t) => { try { return { ok: true, val: JSON.parse(t) }; } catch (e) { return { ok: false, err: e.message }; } };

// ---------- CSV (RFC 4180-ish) ----------
function parseCSV(text, delim) {
  delim = delim || ",";
  const s = String(text);
  const rows = []; let row = [], field = "", inQ = false, i = 0, started = false;
  for (; i < s.length; i++) {
    const c = s[i];
    if (inQ) {
      if (c === '"') { if (s[i + 1] === '"') { field += '"'; i++; } else inQ = false; }
      else field += c;
      continue;
    }
    if (c === '"') { inQ = true; started = true; }
    else if (c === delim) { row.push(field); field = ""; started = true; }
    else if (c === "\r") { /* skip */ }
    else if (c === "\n") { row.push(field); rows.push(row); row = []; field = ""; started = false; }
    else { field += c; started = true; }
  }
  if (started || field !== "" || row.length) { row.push(field); rows.push(row); }
  return rows;
}
function csvField(v, delim) {
  const s = v == null ? "" : String(v);
  if (s.includes(delim) || s.includes('"') || s.includes("\n") || s.includes("\r")) return '"' + s.replace(/"/g, '""') + '"';
  return s;
}
const csvRow = (arr, delim) => arr.map((c) => csvField(c, delim)).join(delim);
const sqlIdent = (name) => { const s = String(name).trim(); return /^[A-Za-z_][A-Za-z0-9_]*$/.test(s) ? s : '"' + s.replace(/"/g, '""') + '"'; };

// ---------- flatten / unflatten ----------
function flatten(obj, prefix, out) {
  out = out || {};
  if (isPlainObj(obj)) {
    const ks = Object.keys(obj);
    if (!ks.length && prefix) { out[prefix] = {}; return out; }
    for (const k of ks) flatten(obj[k], prefix ? prefix + "." + k : k, out);
  } else if (Array.isArray(obj)) {
    if (!obj.length && prefix) { out[prefix] = []; return out; }
    obj.forEach((v, idx) => flatten(v, prefix ? prefix + "." + idx : String(idx), out));
  } else { out[prefix] = obj; }
  return out;
}
function unflatten(flat) {
  const root = {};
  for (const key of Object.keys(flat)) {
    const parts = key.split(".");
    let cur = root;
    for (let i = 0; i < parts.length; i++) {
      const p = parts[i], last = i === parts.length - 1;
      const nextIsIdx = !last && /^\d+$/.test(parts[i + 1]);
      if (last) { cur[p] = flat[key]; }
      else { if (cur[p] == null || typeof cur[p] !== "object") cur[p] = nextIsIdx ? [] : {}; cur = cur[p]; }
    }
  }
  return normalizeArrays(root);
}
function normalizeArrays(o) {
  if (Array.isArray(o)) return o.map(normalizeArrays);
  if (isPlainObj(o)) {
    const ks = Object.keys(o);
    const allIdx = ks.length && ks.every((k) => /^\d+$/.test(k));
    if (allIdx) { const arr = []; ks.sort((a, b) => a - b).forEach((k) => { arr[+k] = normalizeArrays(o[k]); }); return arr; }
    const r = {}; for (const k of ks) r[k] = normalizeArrays(o[k]); return r;
  }
  return o;
}
function deepMerge(a, b) {
  if (isPlainObj(a) && isPlainObj(b)) {
    const r = {}; for (const k of Object.keys(a)) r[k] = a[k];
    for (const k of Object.keys(b)) r[k] = k in r ? deepMerge(r[k], b[k]) : b[k];
    return r;
  }
  return b;
}

// ---------- YAML emit ----------
function yamlScalar(v) {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return Number.isFinite(v) ? String(v) : "null";
  const s = String(v);
  if (s === "") return '""';
  const needs = /^[\s]|[\s]$/.test(s) || /[:#\[\]{}&*!|>'"%@`,]/.test(s) || /^[-?@`]/.test(s) ||
    /^(true|false|null|yes|no|on|off|~)$/i.test(s) || /^[-+]?(\d|\.\d)/.test(s) || /\n/.test(s) || /:\s/.test(s);
  if (needs) return '"' + s.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n").replace(/\t/g, "\\t").replace(/\r/g, "\\r") + '"';
  return s;
}
const yamlKey = (k) => yamlScalar(String(k));
function yamlEmpty(v) {
  if (Array.isArray(v) && !v.length) return "[]";
  if (isPlainObj(v) && !Object.keys(v).length) return "{}";
  return yamlScalar(v);
}
const hasEntries = (v) => Array.isArray(v) ? v.length > 0 : Object.keys(v).length > 0;
function yamlLines(val, indent) {
  const pad = "  ".repeat(indent), lines = [];
  if (Array.isArray(val)) {
    for (const item of val) {
      if ((isPlainObj(item) || Array.isArray(item)) && hasEntries(item)) {
        const sub = yamlLines(item, indent + 1);
        lines.push(pad + "- " + sub[0].slice((indent + 1) * 2));
        for (let k = 1; k < sub.length; k++) lines.push(sub[k]);
      } else lines.push(pad + "- " + yamlEmpty(item));
    }
    return lines;
  }
  if (isPlainObj(val)) {
    for (const key of Object.keys(val)) {
      const v = val[key];
      if ((isPlainObj(v) || Array.isArray(v)) && hasEntries(v)) {
        lines.push(pad + yamlKey(key) + ":");
        for (const l of yamlLines(v, indent + 1)) lines.push(l);
      } else lines.push(pad + yamlKey(key) + ": " + yamlEmpty(v));
    }
    return lines;
  }
  return [pad + yamlScalar(val)];
}
const toYAML = (v) => (hasEntries(v) || (!isPlainObj(v) && !Array.isArray(v))) ? yamlLines(v, 0).join("\n") + "\n" : yamlEmpty(v) + "\n";

// ---------- YAML parse (common block subset + simple flow) ----------
function parseYAML(text) {
  try {
    const raw = String(text).replace(/\r\n?/g, "\n").split("\n");
    const lines = [];
    for (let ln of raw) {
      let inS = false, inD = false, res = "";
      for (let i = 0; i < ln.length; i++) {
        const c = ln[i];
        if (c === "'" && !inD) inS = !inS;
        else if (c === '"' && !inS) inD = !inD;
        else if (c === "#" && !inS && !inD && (i === 0 || ln[i - 1] === " " || ln[i - 1] === "\t")) break;
        res += c;
      }
      ln = res.replace(/\s+$/, "");
      const t = ln.trim();
      if (t === "" || t === "---" || t === "...") continue;
      lines.push(ln);
    }
    if (!lines.length) return { ok: true, val: null };
    const [val] = yNode(lines, 0, indentOf(lines[0]));
    return { ok: true, val };
  } catch (e) { return { ok: false, err: e.message }; }
}
const indentOf = (l) => { let n = 0; while (l[n] === " ") n++; return n; };
function yMatchKey(s) {
  if (s[0] === '"' || s[0] === "'") {
    const q = s[0]; let i = 1, k = "";
    while (i < s.length && s[i] !== q) { if (q === '"' && s[i] === "\\") { k += s[i + 1]; i += 2; } else { k += s[i]; i++; } }
    i++; if (s[i] !== ":") return null;
    return { key: k, rest: s.slice(i + 1).replace(/^[ \t]+/, "") };
  }
  for (let i = 0; i < s.length; i++) if (s[i] === ":" && (i + 1 >= s.length || s[i + 1] === " ")) return { key: s.slice(0, i).trim(), rest: s.slice(i + 1).replace(/^[ \t]+/, "") };
  return null;
}
function yNode(lines, i, indent) {
  const t = lines[i].slice(indent);
  if (t === "-" || t.startsWith("- ")) return yArray(lines, i, indent);
  if (yMatchKey(t)) return yMap(lines, i, indent);
  return [yScalar(t), i + 1];
}
function yArray(lines, i, indent) {
  const arr = []; let j = i;
  while (j < lines.length) {
    const ind = indentOf(lines[j]); if (ind < indent) break;
    if (ind > indent) throw new Error("bad indentation at line " + (j + 1));
    const t = lines[j].slice(indent);
    if (!(t === "-" || t.startsWith("- "))) break;
    const after = t === "-" ? "" : t.slice(2);
    if (after.trim() === "") {
      if (j + 1 < lines.length && indentOf(lines[j + 1]) > indent) { const [v, nj] = yNode(lines, j + 1, indentOf(lines[j + 1])); arr.push(v); j = nj; }
      else { arr.push(null); j++; }
    } else if (yMatchKey(after)) {
      const ci = indent + 2; lines[j] = " ".repeat(ci) + after;
      const [v, nj] = yMap(lines, j, ci); arr.push(v); j = nj;
    } else { arr.push(yScalar(after)); j++; }
  }
  return [arr, j];
}
function yMap(lines, i, indent) {
  const obj = {}; let j = i;
  while (j < lines.length) {
    const ind = indentOf(lines[j]); if (ind < indent) break;
    if (ind > indent) throw new Error("bad indentation at line " + (j + 1));
    const t = lines[j].slice(indent);
    if (t === "-" || t.startsWith("- ")) break;
    const m = yMatchKey(t); if (!m) throw new Error("expected 'key:' at line " + (j + 1));
    if (m.rest !== "") { obj[m.key] = yScalar(m.rest); j++; }
    else if (j + 1 < lines.length && indentOf(lines[j + 1]) > indent) { const [v, nj] = yNode(lines, j + 1, indentOf(lines[j + 1])); obj[m.key] = v; j = nj; }
    else if (j + 1 < lines.length && indentOf(lines[j + 1]) === indent && (lines[j + 1].slice(indent) === "-" || lines[j + 1].slice(indent).startsWith("- "))) { const [v, nj] = yArray(lines, j + 1, indent); obj[m.key] = v; j = nj; }
    else { obj[m.key] = null; j++; }
  }
  return [obj, j];
}
function yScalar(s) {
  s = s.trim();
  if (s === "" || s === "~" || s === "null" || s === "Null" || s === "NULL") return s === "" ? null : null;
  if (s[0] === "[" || s[0] === "{") return yFlow({ s, i: 0 });
  if (s[0] === '"') { try { return JSON.parse(s); } catch (e) { return s.slice(1, -1); } }
  if (s[0] === "'") return s.slice(1, -1).replace(/''/g, "'");
  if (/^(true|True|TRUE)$/.test(s)) return true;
  if (/^(false|False|FALSE)$/.test(s)) return false;
  if (/^[-+]?\d+$/.test(s)) return Number(s);
  if (/^[-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?$/.test(s)) return Number(s);
  if (/^0x[0-9a-fA-F]+$/.test(s)) return parseInt(s, 16);
  return s;
}
function yFlow(p) {
  skipWs(p); const c = p.s[p.i];
  if (c === "[") { p.i++; const a = []; skipWs(p); if (p.s[p.i] === "]") { p.i++; return a; } while (true) { a.push(yFlow(p)); skipWs(p); if (p.s[p.i] === ",") { p.i++; continue; } if (p.s[p.i] === "]") { p.i++; break; } throw new Error("bad flow sequence"); } return a; }
  if (c === "{") { p.i++; const o = {}; skipWs(p); if (p.s[p.i] === "}") { p.i++; return o; } while (true) { skipWs(p); const k = yFlowScalarRaw(p, true); skipWs(p); if (p.s[p.i] !== ":") throw new Error("expected ':' in flow map"); p.i++; const v = yFlow(p); o[typeof k === "string" ? k : String(k)] = v; skipWs(p); if (p.s[p.i] === ",") { p.i++; continue; } if (p.s[p.i] === "}") { p.i++; break; } throw new Error("bad flow map"); } return o; }
  return yScalar(yFlowScalarRaw(p, false));
}
const skipWs = (p) => { while (/[ \t]/.test(p.s[p.i])) p.i++; };
function yFlowScalarRaw(p, isKey) {
  skipWs(p); let r = "";
  if (p.s[p.i] === '"' || p.s[p.i] === "'") { const q = p.s[p.i]; r += q; p.i++; while (p.i < p.s.length && p.s[p.i] !== q) { r += p.s[p.i]; p.i++; } r += q; p.i++; return isKey ? r.slice(1, -1) : r; }
  while (p.i < p.s.length && !",]}:".includes(p.s[p.i])) { r += p.s[p.i]; p.i++; }
  return r.trim();
}

// ---------- TOML emit ----------
const tomlBareKey = (k) => /^[A-Za-z0-9_-]+$/.test(k) ? k : '"' + String(k).replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
const tomlString = (s) => '"' + String(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n").replace(/\t/g, "\\t").replace(/\r/g, "\\r") + '"';
function tomlValue(v) {
  if (v === null) return '""';
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return Number.isFinite(v) ? String(v) : '""';
  if (typeof v === "string") return tomlString(v);
  if (Array.isArray(v)) return "[" + v.map(tomlValue).join(", ") + "]";
  if (isPlainObj(v)) return "{ " + Object.keys(v).map((k) => tomlBareKey(k) + " = " + tomlValue(v[k])).join(", ") + " }";
  return '""';
}
function tomlEmit(obj, prefix, out) {
  const simple = [], tables = [], arrTables = [];
  for (const k of Object.keys(obj)) {
    const v = obj[k];
    if (isPlainObj(v)) tables.push(k);
    else if (Array.isArray(v) && v.length && v.every(isPlainObj)) arrTables.push(k);
    else simple.push(k);
  }
  for (const k of simple) out.push(tomlBareKey(k) + " = " + tomlValue(obj[k]));
  for (const k of tables) { const full = prefix ? prefix + "." + tomlBareKey(k) : tomlBareKey(k); out.push(""); out.push("[" + full + "]"); tomlEmit(obj[k], full, out); }
  for (const k of arrTables) { const full = prefix ? prefix + "." + tomlBareKey(k) : tomlBareKey(k); for (const item of obj[k]) { out.push(""); out.push("[[" + full + "]]"); tomlEmit(item, full, out); } }
}
function toTOML(obj) {
  if (!isPlainObj(obj)) throw new Error("TOML root must be a JSON object.");
  const out = []; tomlEmit(obj, "", out);
  return out.join("\n").replace(/^\n+/, "").replace(/\n{3,}/g, "\n\n") + "\n";
}

// ---------- TOML parse (common single-line-value subset) ----------
function parseTOML(text) {
  try {
    const root = {}, arrTableSet = new Set(); let cur = root;
    const lines = String(text).replace(/\r\n?/g, "\n").split("\n");
    for (let raw of lines) {
      const line = stripTomlComment(raw).trim();
      if (!line) continue;
      if (line.startsWith("[[") && line.endsWith("]]")) { cur = tomlAddArrayTable(root, tomlKeyPath(line.slice(2, -2)), arrTableSet); }
      else if (line[0] === "[" && line.endsWith("]")) { cur = tomlAddTable(root, tomlKeyPath(line.slice(1, -1))); }
      else { const eq = tomlFindEq(line); if (eq < 0) throw new Error("expected key = value: " + line); tomlSetPath(cur, tomlKeyPath(line.slice(0, eq).trim()), tomlValueParse(line.slice(eq + 1).trim())); }
    }
    return { ok: true, val: root };
  } catch (e) { return { ok: false, err: e.message }; }
}
function stripTomlComment(s) { let inB = false, inL = false, o = ""; for (let i = 0; i < s.length; i++) { const c = s[i]; if (inB) { o += c; if (c === '"' && s[i - 1] !== "\\") inB = false; continue; } if (inL) { o += c; if (c === "'") inL = false; continue; } if (c === '"') inB = true; else if (c === "'") inL = true; else if (c === "#") break; o += c; } return o; }
function tomlFindEq(s) { let inB = false, inL = false; for (let i = 0; i < s.length; i++) { const c = s[i]; if (inB) { if (c === '"' && s[i - 1] !== "\\") inB = false; continue; } if (inL) { if (c === "'") inL = false; continue; } if (c === '"') inB = true; else if (c === "'") inL = true; else if (c === "=") return i; } return -1; }
function tomlKeyPath(s) {
  const parts = []; let i = 0;
  while (i < s.length) {
    while (/[ \t]/.test(s[i])) i++;
    if (s[i] === '"' || s[i] === "'") { const q = s[i]; i++; let k = ""; while (i < s.length && s[i] !== q) { if (q === '"' && s[i] === "\\") { k += s[i + 1]; i += 2; } else { k += s[i]; i++; } } i++; parts.push(k); }
    else { let k = ""; while (i < s.length && s[i] !== "." && !/[ \t]/.test(s[i])) { k += s[i]; i++; } if (k === "") throw new Error("empty key segment"); parts.push(k); }
    while (/[ \t]/.test(s[i])) i++;
    if (s[i] === ".") i++;
  }
  return parts;
}
function tomlAddTable(root, path) { let cur = root; for (const p of path) { if (cur[p] == null) cur[p] = {}; else if (Array.isArray(cur[p])) cur = cur[p][cur[p].length - 1]; if (isPlainObj(cur[p])) cur = cur[p]; } return cur; }
function tomlAddArrayTable(root, path, set) { let cur = root; for (let i = 0; i < path.length - 1; i++) { const p = path[i]; if (cur[p] == null) cur[p] = {}; if (Array.isArray(cur[p])) cur = cur[p][cur[p].length - 1]; else cur = cur[p]; } const last = path[path.length - 1]; if (!Array.isArray(cur[last])) cur[last] = []; const item = {}; cur[last].push(item); return item; }
function tomlSetPath(obj, path, val) { let cur = obj; for (let i = 0; i < path.length - 1; i++) { const p = path[i]; if (!isPlainObj(cur[p])) cur[p] = {}; cur = cur[p]; } cur[path[path.length - 1]] = val; }
function tomlValueParse(s) {
  s = s.trim();
  if (s === "") throw new Error("missing value");
  if (s[0] === '"') { return JSON.parse(s.replace(/\n/g, "\\n")); }
  if (s[0] === "'") { const e = s.indexOf("'", 1); return s.slice(1, e); }
  if (s[0] === "[") return tomlArrayParse(s);
  if (s[0] === "{") return tomlInlineParse(s);
  if (/^(true|false)$/.test(s)) return s === "true";
  const num = s.replace(/_/g, "");
  if (/^[+-]?\d+$/.test(num)) return Number(num);
  if (/^[+-]?(\d+\.\d+([eE][+-]?\d+)?|\d+[eE][+-]?\d+|\.\d+)$/.test(num)) return Number(num);
  if (/^0x[0-9a-fA-F]+$/.test(num)) return parseInt(num, 16);
  if (/^0o[0-7]+$/.test(num)) return parseInt(num.slice(2), 8);
  if (/^0b[01]+$/.test(num)) return parseInt(num.slice(2), 2);
  return s; // datetimes, inf/nan, bare -> keep as string (safe for JSON)
}
function tomlArrayParse(s) { const p = { s, i: 0 }; return tomlFlow(p); }
function tomlInlineParse(s) { const p = { s, i: 0 }; return tomlFlow(p); }
function tomlFlow(p) {
  while (/[ \t]/.test(p.s[p.i])) p.i++;
  const c = p.s[p.i];
  if (c === "[") { p.i++; const a = []; tws(p); if (p.s[p.i] === "]") { p.i++; return a; } while (true) { a.push(tomlFlow(p)); tws(p); if (p.s[p.i] === ",") { p.i++; tws(p); if (p.s[p.i] === "]") { p.i++; break; } continue; } if (p.s[p.i] === "]") { p.i++; break; } throw new Error("bad TOML array"); } return a; }
  if (c === "{") { p.i++; const o = {}; tws(p); if (p.s[p.i] === "}") { p.i++; return o; } while (true) { tws(p); const k = tomlFlowKey(p); tws(p); if (p.s[p.i] !== "=") throw new Error("expected = in inline table"); p.i++; o[k] = tomlFlow(p); tws(p); if (p.s[p.i] === ",") { p.i++; continue; } if (p.s[p.i] === "}") { p.i++; break; } throw new Error("bad inline table"); } return o; }
  let r = ""; if (c === '"' || c === "'") { const q = c; r += q; p.i++; while (p.i < p.s.length && p.s[p.i] !== q) { if (q === '"' && p.s[p.i] === "\\") { r += p.s[p.i] + p.s[p.i + 1]; p.i += 2; } else { r += p.s[p.i]; p.i++; } } r += q; p.i++; return tomlValueParse(r); }
  while (p.i < p.s.length && !",]}".includes(p.s[p.i])) { r += p.s[p.i]; p.i++; }
  return tomlValueParse(r.trim());
}
const tws = (p) => { while (/[ \t\n\r]/.test(p.s[p.i])) p.i++; };
function tomlFlowKey(p) { if (p.s[p.i] === '"' || p.s[p.i] === "'") { const q = p.s[p.i]; p.i++; let k = ""; while (p.i < p.s.length && p.s[p.i] !== q) { k += p.s[p.i]; p.i++; } p.i++; return k; } let k = ""; while (p.i < p.s.length && !/[ \t=]/.test(p.s[p.i])) { k += p.s[p.i]; p.i++; } return k; }

// ---------- JSON Pointer (RFC 6901) ----------
function jsonPointerGet(doc, pointer) {
  if (pointer === "") return { ok: true, val: doc };
  if (pointer[0] !== "/") return { ok: false, err: "A JSON Pointer must be empty or start with '/'." };
  const tokens = pointer.split("/").slice(1).map((t) => t.replace(/~1/g, "/").replace(/~0/g, "~"));
  let cur = doc;
  for (const tk of tokens) {
    if (Array.isArray(cur)) { if (!/^\d+$/.test(tk)) return { ok: false, err: "Array index expected at '" + tk + "'." }; cur = cur[Number(tk)]; }
    else if (isPlainObj(cur)) { if (!(tk in cur)) return { ok: false, err: "No key '" + tk + "'." }; cur = cur[tk]; }
    else return { ok: false, err: "Cannot descend into a primitive at '" + tk + "'." };
    if (cur === undefined) return { ok: false, err: "Path not found at '" + tk + "'." };
  }
  return { ok: true, val: cur };
}
function listPointers(doc) {
  const out = [];
  (function walk(v, ptr) {
    out.push([ptr === "" ? "" : ptr, Array.isArray(v) ? "array[" + v.length + "]" : isPlainObj(v) ? "object{" + Object.keys(v).length + "}" : v === null ? "null" : typeof v]);
    if (Array.isArray(v)) v.forEach((x, i) => walk(x, ptr + "/" + i));
    else if (isPlainObj(v)) for (const k of Object.keys(v)) walk(v[k], ptr + "/" + k.replace(/~/g, "~0").replace(/\//g, "~1"));
  })(doc, "");
  return out;
}

// ---------- type inference (JSON -> TS / Go) ----------
const pascal = (s) => String(s).replace(/[^A-Za-z0-9]+/g, " ").trim().split(/\s+/).map((w) => w ? w[0].toUpperCase() + w.slice(1) : "").join("") || "T";
const singular = (s) => s.replace(/ies$/, "y").replace(/s$/, "") || s;
const tsKey = (k) => /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(k) ? k : JSON.stringify(k);
function mergeSamples(arr) {
  const keys = []; const seen = new Set(); const present = {};
  for (const o of arr) if (isPlainObj(o)) for (const k of Object.keys(o)) { if (!seen.has(k)) { seen.add(k); keys.push(k); present[k] = 0; } present[k]++; }
  const merged = {};
  for (const k of keys) merged[k] = arr.filter((o) => isPlainObj(o) && k in o).map((o) => o[k]);
  return { keys, merged, total: arr.filter(isPlainObj).length, present };
}
function jsonToTS(val, rootName) {
  const defs = [], names = new Set();
  const uniq = (n) => { let x = n, i = 2; while (names.has(x)) x = n + (i++); names.add(x); return x; };
  function expr(v, hint) {
    if (v === null) return "null";
    if (Array.isArray(v)) { if (!v.length) return "unknown[]"; const types = [...new Set(v.map((e) => expr(e, singular(hint))))]; let u = types.join(" | "); if (types.length > 1) u = "(" + u + ")"; return u + "[]"; }
    if (isPlainObj(v)) { const nm = uniq(pascal(hint)); const fields = Object.keys(v).map((k) => "  " + tsKey(k) + ": " + expr(v[k], k) + ";").join("\n"); defs.push("interface " + nm + " {\n" + fields + "\n}"); return nm; }
    if (typeof v === "number") return "number"; if (typeof v === "boolean") return "boolean"; if (typeof v === "string") return "string"; return "unknown";
  }
  const root = expr(val, rootName || "Root");
  let out = defs.reverse().join("\n\n");
  if (!isPlainObj(val)) out += (out ? "\n\n" : "") + "type " + pascal(rootName || "Root") + " = " + root + ";";
  return out;
}
function jsonToGo(val, rootName) {
  const defs = [], names = new Set();
  const uniq = (n) => { let x = n, i = 2; while (names.has(x)) x = n + (i++); names.add(x); return x; };
  function typ(v, hint) {
    if (v === null) return "interface{}";
    if (Array.isArray(v)) { if (!v.length) return "[]interface{}"; const t = typ(v[0], singular(hint)); return "[]" + t; }
    if (isPlainObj(v)) { const nm = uniq(pascal(hint)); const fields = Object.keys(v).map((k) => "\t" + pascal(k) + " " + typ(v[k], k) + " `json:\"" + k + "\"`").join("\n"); defs.push("type " + nm + " struct {\n" + fields + "\n}"); return nm; }
    if (typeof v === "number") return Number.isInteger(v) ? "int" : "float64";
    if (typeof v === "boolean") return "bool"; if (typeof v === "string") return "string"; return "interface{}";
  }
  const root = typ(val, rootName || "Root");
  let out = defs.reverse().join("\n\n");
  if (!isPlainObj(val)) out += (out ? "\n\n" : "") + "type " + pascal(rootName || "Root") + " " + root;
  return out;
}

// ---------- numbers ----------
function parseBig(str) {
  let s = String(str).trim().replace(/_/g, "");
  if (s === "") return null;
  let neg = false;
  if (s[0] === "+") s = s.slice(1); else if (s[0] === "-") { neg = true; s = s.slice(1); }
  let v;
  try {
    if (/^0x[0-9a-fA-F]+$/.test(s)) v = BigInt(s);
    else if (/^0b[01]+$/.test(s)) v = BigInt(s);
    else if (/^0o[0-7]+$/.test(s)) v = BigInt(s);
    else if (/^\d+$/.test(s)) v = BigInt(s);
    else return null;
  } catch (e) { return null; }
  return neg ? -v : v;
}

// ---------- regex explain ----------
function descEscape(ch) {
  const map = { d: "any digit (0-9)", D: "any non-digit", w: "any word character (letter, digit or _)", W: "any non-word character", s: "any whitespace", S: "any non-whitespace", b: "a word boundary", B: "a non-word-boundary", n: "a newline", r: "a carriage return", t: "a tab", f: "a form feed", v: "a vertical tab", 0: "a NUL character", A: "start of the string", Z: "end of the string", z: "very end of the string" };
  if (ch in map) return map[ch];
  if (/[1-9]/.test(ch)) return "back-reference to group " + ch;
  if (ch === "\\") return "a literal backslash";
  return "a literal '" + ch + "'";
}
function flagDesc(f) { return ({ g: "g = global (all matches)", i: "i = case-insensitive", m: "m = multiline (^ and $ at line breaks)", s: "s = dotAll (. matches newlines)", u: "u = unicode", y: "y = sticky", d: "d = has indices" })[f] || f; }
function explainRegex(src, flags) {
  let pat = src, fl = flags || "";
  const m = /^\/(.*)\/([gimsuyd]*)$/.exec(String(src).trim());
  if (m) { pat = m[1]; fl = m[2] || fl; }
  const out = []; let i = 0;
  function cls() {
    i++; let neg = false; const items = [];
    if (pat[i] === "^") { neg = true; i++; }
    if (pat[i] === "]") { items.push("literal ']'"); i++; }
    while (i < pat.length && pat[i] !== "]") {
      if (pat[i] === "\\") { items.push(descEscape(pat[i + 1])); i += 2; continue; }
      if (pat[i + 1] === "-" && pat[i + 2] && pat[i + 2] !== "]") { items.push("'" + pat[i] + "' to '" + pat[i + 2] + "'"); i += 3; continue; }
      items.push("'" + pat[i] + "'"); i++;
    }
    i++;
    return (neg ? "any character except: " : "any one of: ") + items.join(", ");
  }
  while (i < pat.length) {
    const c = pat[i]; let desc = "";
    if (c === "\\") { desc = descEscape(pat[i + 1]); i += 2; }
    else if (c === "[") desc = cls();
    else if (c === "^") { desc = "anchor: start of string/line"; i++; }
    else if (c === "$") { desc = "anchor: end of string/line"; i++; }
    else if (c === ".") { desc = "any character (except newline unless s flag)"; i++; }
    else if (c === "(") {
      const rest = pat.slice(i);
      if (rest.startsWith("(?:")) { desc = "start of non-capturing group"; i += 3; }
      else if (rest.startsWith("(?=")) { desc = "start of positive lookahead"; i += 3; }
      else if (rest.startsWith("(?!")) { desc = "start of negative lookahead"; i += 3; }
      else if (rest.startsWith("(?<=")) { desc = "start of positive lookbehind"; i += 4; }
      else if (rest.startsWith("(?<!")) { desc = "start of negative lookbehind"; i += 4; }
      else { const nm = /^\(\?<([A-Za-z0-9_]+)>/.exec(rest); if (nm) { desc = "start of named capturing group '" + nm[1] + "'"; i += nm[0].length; } else { desc = "start of capturing group"; i++; } }
    }
    else if (c === ")") { desc = "end of group"; i++; }
    else if (c === "|") { desc = "OR (alternation)"; i++; }
    else if (c === "*" || c === "+" || c === "?") { let q = c === "*" ? "zero or more times" : c === "+" ? "one or more times" : "zero or one time (optional)"; i++; if (pat[i] === "?") { q += " (lazy)"; i++; } else if (pat[i] === "+") { q += " (possessive)"; i++; } desc = "quantifier: repeat previous " + q; }
    else if (c === "{") { const q = /^\{(\d+)(,(\d*))?\}/.exec(pat.slice(i)); if (q) { const a = q[1], hasComma = q[2] !== undefined, b = q[3]; desc = !hasComma ? "quantifier: exactly " + a + " times" : (b === undefined || b === "" ? "quantifier: " + a + " or more times" : "quantifier: between " + a + " and " + b + " times"); i += q[0].length; if (pat[i] === "?") { desc += " (lazy)"; i++; } } else { desc = "literal '{'"; i++; } }
    else { desc = "literal character '" + c + "'"; i++; }
    out.push(desc);
  }
  let res = out.map((d, n) => (n + 1) + ". " + d).join("\n");
  if (fl) res += "\n\nFlags: " + fl.split("").map(flagDesc).join("; ");
  return res;
}
function globToRegex(glob) {
  let re = "", i = 0; const g = String(glob);
  while (i < g.length) {
    const c = g[i];
    if (c === "*") { if (g[i + 1] === "*") { re += ".*"; i += 2; if (g[i] === "/") i++; } else { re += "[^/]*"; i++; } }
    else if (c === "?") { re += "[^/]"; i++; }
    else if (c === "[") { let j = i + 1, neg = false; if (g[j] === "!" || g[j] === "^") { neg = true; j++; } let body = ""; while (j < g.length && g[j] !== "]") { body += g[j]; j++; } re += "[" + (neg ? "^" : "") + body + "]"; i = j + 1; }
    else if (c === "{") { let j = i + 1, body = ""; while (j < g.length && g[j] !== "}") { body += g[j]; j++; } re += "(" + body.split(",").map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|") + ")"; i = j + 1; }
    else { re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&"); i++; }
  }
  return "^" + re + "$";
}

// ---------- string case ----------
function splitWords(s) {
  return String(s)
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .replace(/[_\-.\s]+/g, " ")
    .trim().split(/\s+/).filter(Boolean).map((w) => w.toLowerCase());
}

export const TOOLS = [
  {
    id: "cd-json-format", name: "JSON Formatter / Minifier / Validator", cat: "coding",
    desc: "Pretty-print, minify or validate JSON. Reports the exact parse error with position when invalid.",
    tags: ["json", "pretty", "beautify", "minify", "validate", "lint"],
    inputs: [
      { k: "json", label: "JSON", type: "textarea", rows: 8, placeholder: '{"a":1,"b":[2,3]}' },
      { k: "mode", label: "Mode", type: "select", opts: ["Pretty", "Minify", "Validate"], value: "Pretty" },
      { k: "indent", label: "Indent", type: "select", opts: ["2", "4", "Tab"], value: "2" },
    ],
    run(v) {
      if (!S(v.json).trim()) return "";
      const r = tryJSON(v.json);
      if (!r.ok) return { error: "Invalid JSON: " + r.err };
      if (v.mode === "Validate") return "Valid JSON. Top-level type: " + (Array.isArray(r.val) ? "array (" + r.val.length + " items)" : r.val === null ? "null" : typeof r.val === "object" ? "object (" + Object.keys(r.val).length + " keys)" : typeof r.val);
      if (v.mode === "Minify") return JSON.stringify(r.val);
      const ind = v.indent === "Tab" ? "\t" : Number(v.indent || 2);
      return JSON.stringify(r.val, null, ind);
    },
  },
  {
    id: "cd-jsonc-strip", name: "JSONC / Comment Stripper", cat: "coding",
    desc: "Remove // and /* */ comments and trailing commas from JSONC/JSON5-style text to produce strict JSON. String-aware.",
    tags: ["jsonc", "json5", "comments", "trailing comma", "strict json"],
    inputs: [
      { k: "text", label: "JSONC", type: "textarea", rows: 8, placeholder: '{\n  // config\n  "a": 1,\n}' },
      { k: "pretty", label: "Re-format output", type: "checkbox", value: true },
    ],
    run(v) {
      const s = S(v.text); if (!s.trim()) return "";
      let out = "", i = 0, inS = false, q = "";
      while (i < s.length) {
        const c = s[i], n = s[i + 1];
        if (inS) { out += c; if (c === "\\") { out += n; i += 2; continue; } if (c === q) inS = false; i++; continue; }
        if (c === '"' || c === "'") { inS = true; q = c; out += c; i++; continue; }
        if (c === "/" && n === "/") { while (i < s.length && s[i] !== "\n") i++; continue; }
        if (c === "/" && n === "*") { i += 2; while (i < s.length && !(s[i] === "*" && s[i + 1] === "/")) i++; i += 2; continue; }
        out += c; i++;
      }
      out = out.replace(/,(\s*[}\]])/g, "$1");
      const r = tryJSON(out);
      if (!r.ok) return { error: "After stripping, still invalid JSON: " + r.err + "\n---\n" + out };
      return v.pretty ? JSON.stringify(r.val, null, 2) : out.trim();
    },
  },
  {
    id: "cd-json-to-yaml", name: "JSON to YAML", cat: "coding",
    desc: "Convert JSON into block-style YAML. Keys and values are quoted only when YAML requires it.",
    tags: ["json", "yaml", "convert", "config"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8, placeholder: '{"name":"api","ports":[80,443]}' }],
    run(v) { if (!S(v.json).trim()) return ""; const r = tryJSON(v.json); if (!r.ok) return { error: "Invalid JSON: " + r.err }; try { return toYAML(r.val); } catch (e) { return { error: e.message }; } },
  },
  {
    id: "cd-yaml-to-json", name: "YAML to JSON", cat: "coding",
    desc: "Parse the common block subset of YAML (mappings, sequences, scalars, # comments, simple flow [] and {}) into JSON.",
    tags: ["yaml", "json", "convert", "config", "parse"],
    inputs: [
      { k: "yaml", label: "YAML", type: "textarea", rows: 8, placeholder: "name: api\nports:\n  - 80\n  - 443" },
      { k: "indent", label: "Indent", type: "select", opts: ["2", "4", "Minify"], value: "2" },
    ],
    run(v) {
      if (!S(v.yaml).trim()) return "";
      const r = parseYAML(v.yaml); if (!r.ok) return { error: "YAML parse error: " + r.err };
      const ind = v.indent === "Minify" ? undefined : Number(v.indent || 2);
      return JSON.stringify(r.val, null, ind);
    },
  },
  {
    id: "cd-json-to-toml", name: "JSON to TOML", cat: "coding",
    desc: "Convert a JSON object into TOML using tables, arrays-of-tables and inline tables. JSON null becomes an empty string (TOML has no null).",
    tags: ["json", "toml", "convert", "config"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8, placeholder: '{"title":"demo","server":{"port":8080}}' }],
    run(v) { if (!S(v.json).trim()) return ""; const r = tryJSON(v.json); if (!r.ok) return { error: "Invalid JSON: " + r.err }; try { return toTOML(r.val); } catch (e) { return { error: e.message }; } },
  },
  {
    id: "cd-toml-to-json", name: "TOML to JSON", cat: "coding",
    desc: "Parse the common TOML subset (key = value, [tables], [[arrays of tables]], strings, numbers, booleans, single-line arrays and inline tables) into JSON. Datetimes are kept as strings.",
    tags: ["toml", "json", "convert", "config", "parse"],
    inputs: [
      { k: "toml", label: "TOML", type: "textarea", rows: 8, placeholder: 'title = "demo"\n[server]\nport = 8080' },
      { k: "indent", label: "Indent", type: "select", opts: ["2", "4", "Minify"], value: "2" },
    ],
    run(v) { if (!S(v.toml).trim()) return ""; const r = parseTOML(v.toml); if (!r.ok) return { error: "TOML parse error: " + r.err }; const ind = v.indent === "Minify" ? undefined : Number(v.indent || 2); return JSON.stringify(r.val, null, ind); },
  },
  {
    id: "cd-json-to-xml", name: "JSON to XML", cat: "coding",
    desc: "Emit a simple XML document from JSON. Objects become nested elements, arrays repeat the element, primitives become text. Names are sanitised to valid XML element names.",
    tags: ["json", "xml", "convert", "serialize"],
    inputs: [
      { k: "json", label: "JSON", type: "textarea", rows: 7, placeholder: '{"book":{"title":"X","tags":["a","b"]}}' },
      { k: "root", label: "Root element", type: "text", value: "root" },
      { k: "decl", label: "Add <?xml ?> declaration", type: "checkbox", value: true },
    ],
    run(v) {
      if (!S(v.json).trim()) return "";
      const r = tryJSON(v.json); if (!r.ok) return { error: "Invalid JSON: " + r.err };
      const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
      const name = (n) => { let x = String(n).replace(/[^A-Za-z0-9_.-]/g, "_"); if (!/^[A-Za-z_]/.test(x)) x = "_" + x; return x; };
      function emit(val, tag, depth) {
        const pad = "  ".repeat(depth);
        if (Array.isArray(val)) return val.map((x) => emit(x, tag, depth)).join("\n");
        if (isPlainObj(val)) { const inner = Object.keys(val).map((k) => emit(val[k], name(k), depth + 1)).join("\n"); return pad + "<" + tag + ">\n" + inner + "\n" + pad + "</" + tag + ">"; }
        if (val === null) return pad + "<" + tag + "/>";
        return pad + "<" + tag + ">" + esc(val) + "</" + tag + ">";
      }
      const root = name(v.root || "root");
      const body = emit(r.val, root, 0);
      return (v.decl ? '<?xml version="1.0" encoding="UTF-8"?>\n' : "") + body + "\n";
    },
  },
  {
    id: "cd-json-to-csv", name: "JSON to CSV", cat: "coding",
    desc: "Turn a JSON array of objects into CSV. Column order is the union of all keys (first-seen order); nested values are JSON-encoded.",
    tags: ["json", "csv", "convert", "table", "export"],
    inputs: [
      { k: "json", label: "JSON array", type: "textarea", rows: 7, placeholder: '[{"id":1,"name":"a"},{"id":2,"name":"b"}]' },
      { k: "delim", label: "Delimiter", type: "select", opts: [[",", "Comma"], ["\t", "Tab"], [";", "Semicolon"], ["|", "Pipe"]], value: "," },
      { k: "header", label: "Include header row", type: "checkbox", value: true },
    ],
    run(v) {
      if (!S(v.json).trim()) return "";
      const r = tryJSON(v.json); if (!r.ok) return { error: "Invalid JSON: " + r.err };
      let arr = r.val; if (isPlainObj(arr)) arr = [arr];
      if (!Array.isArray(arr)) return { error: "Expected a JSON array of objects." };
      const cols = []; const seen = new Set();
      for (const row of arr) { if (!isPlainObj(row)) return { error: "Every array item must be an object." }; for (const k of Object.keys(row)) if (!seen.has(k)) { seen.add(k); cols.push(k); } }
      const d = v.delim || ",";
      const cell = (x) => x == null ? "" : (typeof x === "object" ? JSON.stringify(x) : String(x));
      const lines = [];
      if (v.header) lines.push(csvRow(cols, d));
      for (const row of arr) lines.push(csvRow(cols.map((c) => cell(row[c])), d));
      return lines.join("\n") + "\n";
    },
  },
  {
    id: "cd-csv-to-json", name: "CSV to JSON", cat: "coding",
    desc: "Parse CSV (quoted fields, embedded commas/newlines, \"\" escapes) into JSON. Uses the first row as keys, or emits arrays of cells when there is no header.",
    tags: ["csv", "json", "convert", "parse", "import"],
    inputs: [
      { k: "csv", label: "CSV", type: "textarea", rows: 7, placeholder: "id,name\n1,Jane\n2,John" },
      { k: "delim", label: "Delimiter", type: "select", opts: [[",", "Comma"], ["\t", "Tab"], [";", "Semicolon"], ["|", "Pipe"]], value: "," },
      { k: "header", label: "First row is header", type: "checkbox", value: true },
      { k: "numbers", label: "Convert numeric cells to numbers", type: "checkbox", value: true },
    ],
    run(v) {
      if (!S(v.csv).trim()) return "";
      const rows = parseCSV(v.csv, v.delim || ",");
      if (!rows.length) return "[]";
      const conv = (c) => { if (!v.numbers) return c; if (c !== "" && /^[-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?$/.test(c)) return Number(c); return c; };
      let data;
      if (v.header) { const keys = rows[0]; data = rows.slice(1).map((r) => { const o = {}; keys.forEach((k, i) => { o[k] = conv(r[i] == null ? "" : r[i]); }); return o; }); }
      else data = rows.map((r) => r.map(conv));
      return JSON.stringify(data, null, 2);
    },
  },
  {
    id: "cd-ndjson", name: "JSON Array to / from NDJSON", cat: "coding",
    desc: "Convert between a JSON array and NDJSON (newline-delimited JSON, one compact JSON value per line) used by logs and streaming APIs.",
    tags: ["ndjson", "jsonl", "json lines", "array", "logs"],
    inputs: [
      { k: "text", label: "Input", type: "textarea", rows: 7, placeholder: '[{"a":1},{"a":2}]' },
      { k: "mode", label: "Direction", type: "select", opts: ["Array to NDJSON", "NDJSON to Array"], value: "Array to NDJSON" },
    ],
    run(v) {
      if (!S(v.text).trim()) return "";
      if (v.mode === "Array to NDJSON") { const r = tryJSON(v.text); if (!r.ok) return { error: "Invalid JSON: " + r.err }; if (!Array.isArray(r.val)) return { error: "Expected a JSON array." }; return r.val.map((x) => JSON.stringify(x)).join("\n") + "\n"; }
      const out = []; const lines = S(v.text).split("\n");
      for (let i = 0; i < lines.length; i++) { const t = lines[i].trim(); if (!t) continue; const r = tryJSON(t); if (!r.ok) return { error: "Line " + (i + 1) + " is not valid JSON: " + r.err }; out.push(r.val); }
      return JSON.stringify(out, null, 2);
    },
  },
  {
    id: "cd-json-to-ini", name: "JSON to INI", cat: "coding",
    desc: "Emit an INI config from a JSON object. Top-level primitives become global keys; nested objects become [sections]; arrays/deeper values are JSON-encoded.",
    tags: ["json", "ini", "config", "convert"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 7, placeholder: '{"debug":true,"db":{"host":"localhost","port":5432}}' }],
    run(v) {
      if (!S(v.json).trim()) return "";
      const r = tryJSON(v.json); if (!r.ok) return { error: "Invalid JSON: " + r.err };
      if (!isPlainObj(r.val)) return { error: "INI needs a JSON object at the top level." };
      const kv = (k, val) => val == null ? k + "=" : (typeof val === "object" ? k + "=" + JSON.stringify(val) : k + "=" + String(val));
      const top = [], sections = [];
      for (const k of Object.keys(r.val)) { const val = r.val[k]; if (isPlainObj(val)) sections.push(k); else top.push(kv(k, val)); }
      let out = top.join("\n");
      for (const s of sections) { out += (out ? "\n\n" : "") + "[" + s + "]\n" + Object.keys(r.val[s]).map((k) => kv(k, r.val[s][k])).join("\n"); }
      return out + "\n";
    },
  },
  {
    id: "cd-properties-json", name: "Java .properties to / from JSON", cat: "coding",
    desc: "Parse a Java/Spring .properties file (key=value, : or space separators, # or ! comments, backslash line continuations, \\uXXXX escapes) into JSON, or emit .properties from flat JSON.",
    tags: ["properties", "java", "spring", "json", "config"],
    inputs: [
      { k: "text", label: "Input", type: "textarea", rows: 7, placeholder: "db.host=localhost\ndb.port=5432" },
      { k: "mode", label: "Direction", type: "select", opts: [".properties to JSON", "JSON to .properties"], value: ".properties to JSON" },
    ],
    run(v) {
      if (!S(v.text).trim()) return "";
      if (v.mode === "JSON to .properties") {
        const r = tryJSON(v.text); if (!r.ok) return { error: "Invalid JSON: " + r.err };
        const flat = flatten(r.val, "", {});
        const esc = (s, key) => String(s).replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/\t/g, "\\t").replace(/\r/g, "\\r").replace(key ? /[=:#!\s]/g : /^\s|[\n]/g, (m) => "\\" + m);
        return Object.keys(flat).map((k) => esc(k, true) + "=" + String(flat[k] == null ? "" : flat[k]).replace(/\\/g, "\\\\").replace(/\n/g, "\\n")).join("\n") + "\n";
      }
      const unesc = (s) => { let o = ""; for (let i = 0; i < s.length; i++) { if (s[i] === "\\") { const n = s[i + 1]; if (n === "t") { o += "\t"; i++; } else if (n === "n") { o += "\n"; i++; } else if (n === "r") { o += "\r"; i++; } else if (n === "f") { o += "\f"; i++; } else if (n === "u") { o += String.fromCharCode(parseInt(s.substr(i + 2, 4), 16) || 0); i += 5; } else { o += n; i++; } } else o += s[i]; } return o; };
      const endsOdd = (l) => { const m = /\\+$/.exec(l); return m ? m[0].length % 2 === 1 : false; };
      const lines = S(v.text).replace(/\r\n?/g, "\n").split("\n");
      const obj = {};
      for (let li = 0; li < lines.length; li++) {
        let first = lines[li].replace(/^[ \t\f]+/, "");
        if (first === "" || first[0] === "#" || first[0] === "!") continue;
        let full = lines[li];
        while (endsOdd(full) && li + 1 < lines.length) { full = full.replace(/\\$/, ""); full += lines[++li].replace(/^[ \t\f]+/, ""); }
        full = full.replace(/^[ \t\f]+/, "");
        let i = 0, keyRaw = "";
        while (i < full.length) { const c = full[i]; if (c === "\\") { keyRaw += c + (full[i + 1] || ""); i += 2; continue; } if (c === "=" || c === ":") { i++; break; } if (c === " " || c === "\t" || c === "\f") { let j = i; while (/[ \t\f]/.test(full[j])) j++; if (full[j] === "=" || full[j] === ":") j++; i = j; break; } keyRaw += c; i++; }
        while (/[ \t\f]/.test(full[i])) i++;
        obj[unesc(keyRaw)] = unesc(full.slice(i));
      }
      return JSON.stringify(obj, null, 2);
    },
  },
  {
    id: "cd-json-pointer", name: "JSON Pointer (RFC 6901) Resolver", cat: "coding",
    desc: "Resolve an RFC 6901 JSON Pointer such as /users/0/name against a JSON document. Handles ~0 (for ~) and ~1 (for /) token escapes.",
    tags: ["json pointer", "rfc6901", "json", "extract", "path"],
    inputs: [
      { k: "json", label: "JSON", type: "textarea", rows: 6, placeholder: '{"users":[{"name":"Jane"}]}' },
      { k: "pointer", label: "Pointer", type: "text", placeholder: "/users/0/name" },
    ],
    run(v) {
      if (!S(v.json).trim()) return "";
      const r = tryJSON(v.json); if (!r.ok) return { error: "Invalid JSON: " + r.err };
      const g = jsonPointerGet(r.val, S(v.pointer)); if (!g.ok) return { error: g.err };
      return typeof g.val === "object" ? JSON.stringify(g.val, null, 2) : String(g.val);
    },
  },
  {
    id: "cd-json-paths", name: "JSON Pointer Path Lister", cat: "coding",
    desc: "List every location in a JSON document as an RFC 6901 pointer, with the value type at each. Useful for discovering the shape of an API response.",
    tags: ["json", "paths", "pointer", "explore", "schema"],
    inputs: [
      { k: "json", label: "JSON", type: "textarea", rows: 7, placeholder: '{"a":1,"b":{"c":[true]}}' },
      { k: "leaves", label: "Leaf values only", type: "checkbox", value: false },
    ],
    run(v) {
      if (!S(v.json).trim()) return "";
      const r = tryJSON(v.json); if (!r.ok) return { error: "Invalid JSON: " + r.err };
      let rows = listPointers(r.val);
      if (v.leaves) rows = rows.filter(([, t]) => !t.startsWith("array[") && !t.startsWith("object{"));
      return rows.map(([p, t]) => (p === "" ? "(root)" : p) + "  ->  " + t).join("\n");
    },
  },
  {
    id: "cd-json-unflatten", name: "JSON Unflatten (dotted keys to nested)", cat: "coding",
    desc: "Rebuild nested JSON from a flat object whose keys use dot paths like user.address.city or tags.0. Numeric segments become array indexes.",
    tags: ["json", "unflatten", "nest", "dot path", "expand"],
    inputs: [{ k: "json", label: "Flat JSON", type: "textarea", rows: 7, placeholder: '{"user.name":"Jane","tags.0":"a","tags.1":"b"}' }],
    run(v) {
      if (!S(v.json).trim()) return "";
      const r = tryJSON(v.json); if (!r.ok) return { error: "Invalid JSON: " + r.err };
      if (!isPlainObj(r.val)) return { error: "Expected a flat JSON object." };
      return JSON.stringify(unflatten(r.val), null, 2);
    },
  },
  {
    id: "cd-json-merge", name: "JSON Deep Merge", cat: "coding",
    desc: "Deep-merge two JSON values. Objects merge key by key (recursively); for everything else, and for arrays, the second value wins.",
    tags: ["json", "merge", "deep", "override", "config"],
    inputs: [
      { k: "base", label: "Base JSON", type: "textarea", rows: 5, placeholder: '{"a":1,"b":{"x":1}}' },
      { k: "over", label: "Override JSON", type: "textarea", rows: 5, placeholder: '{"b":{"y":2},"c":3}' },
    ],
    run(v) {
      if (!S(v.base).trim() || !S(v.over).trim()) return "";
      const a = tryJSON(v.base); if (!a.ok) return { error: "Base is invalid JSON: " + a.err };
      const b = tryJSON(v.over); if (!b.ok) return { error: "Override is invalid JSON: " + b.err };
      return JSON.stringify(deepMerge(a.val, b.val), null, 2);
    },
  },
  {
    id: "cd-json-pick", name: "JSON Pick / Omit Keys", cat: "coding",
    desc: "Keep only the listed top-level keys (pick) or drop them (omit) from a JSON object, or from every object in a JSON array.",
    tags: ["json", "pick", "omit", "select", "filter keys"],
    inputs: [
      { k: "json", label: "JSON", type: "textarea", rows: 6, placeholder: '{"id":1,"name":"a","secret":"x"}' },
      { k: "keys", label: "Keys (comma or space separated)", type: "text", placeholder: "id, name" },
      { k: "mode", label: "Mode", type: "select", opts: ["Pick", "Omit"], value: "Pick" },
    ],
    run(v) {
      if (!S(v.json).trim()) return "";
      const r = tryJSON(v.json); if (!r.ok) return { error: "Invalid JSON: " + r.err };
      const keys = S(v.keys).split(/[,\s]+/).filter(Boolean);
      if (!keys.length) return { error: "List at least one key." };
      const set = new Set(keys);
      const apply = (o) => { if (!isPlainObj(o)) return o; const out = {}; for (const k of Object.keys(o)) { const inList = set.has(k); if ((v.mode === "Pick") === inList) out[k] = o[k]; } return out; };
      const res = Array.isArray(r.val) ? r.val.map(apply) : apply(r.val);
      return JSON.stringify(res, null, 2);
    },
  },
  {
    id: "cd-json-stats", name: "JSON Structure Stats", cat: "coding",
    desc: "Report structural metrics for a JSON document: object/array/string/number/boolean/null counts, total keys, maximum nesting depth and size.",
    tags: ["json", "stats", "analyze", "depth", "metrics"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 7, placeholder: '{"a":[1,2,{"b":true}],"c":null}' }],
    run(v) {
      if (!S(v.json).trim()) return "";
      const r = tryJSON(v.json); if (!r.ok) return { error: "Invalid JSON: " + r.err };
      const c = { object: 0, array: 0, string: 0, number: 0, boolean: 0, null: 0 };
      let keys = 0, maxDepth = 0;
      (function walk(x, d) {
        maxDepth = Math.max(maxDepth, d);
        if (x === null) c.null++;
        else if (Array.isArray(x)) { c.array++; x.forEach((e) => walk(e, d + 1)); }
        else if (typeof x === "object") { c.object++; const ks = Object.keys(x); keys += ks.length; ks.forEach((k) => walk(x[k], d + 1)); }
        else c[typeof x]++;
      })(r.val, 1);
      const size = JSON.stringify(r.val).length;
      return [
        "Max nesting depth : " + maxDepth,
        "Total object keys : " + keys,
        "Objects           : " + c.object,
        "Arrays            : " + c.array,
        "Strings           : " + c.string,
        "Numbers           : " + c.number,
        "Booleans          : " + c.boolean,
        "Nulls             : " + c.null,
        "Minified size     : " + size + " chars",
      ].join("\n");
    },
  },
  {
    id: "cd-json-keyby", name: "JSON Array Key-By / Group-By", cat: "coding",
    desc: "Turn a JSON array of objects into an object keyed by one field (like lodash keyBy), or group items into arrays by that field.",
    tags: ["json", "keyby", "groupby", "index", "array to object"],
    inputs: [
      { k: "json", label: "JSON array", type: "textarea", rows: 6, placeholder: '[{"id":1,"t":"a"},{"id":2,"t":"a"}]' },
      { k: "field", label: "Field", type: "text", placeholder: "id" },
      { k: "mode", label: "Mode", type: "select", opts: ["Key by (last wins)", "Group by (array)"], value: "Key by (last wins)" },
    ],
    run(v) {
      if (!S(v.json).trim()) return "";
      const r = tryJSON(v.json); if (!r.ok) return { error: "Invalid JSON: " + r.err };
      if (!Array.isArray(r.val)) return { error: "Expected a JSON array of objects." };
      const f = S(v.field); if (!f) return { error: "Name the field to key by." };
      const out = {};
      for (const item of r.val) {
        if (!isPlainObj(item)) return { error: "Every item must be an object." };
        const key = String(item[f]);
        if (v.mode.startsWith("Group")) { (out[key] = out[key] || []).push(item); } else out[key] = item;
      }
      return JSON.stringify(out, null, 2);
    },
  },
  {
    id: "cd-json-to-ts", name: "JSON to TypeScript Interfaces", cat: "coding",
    desc: "Generate TypeScript interfaces from a sample JSON value. Nested objects become named interfaces; arrays become unions of element types. Best-effort from one sample.",
    tags: ["json", "typescript", "types", "interface", "codegen"],
    inputs: [
      { k: "json", label: "Sample JSON", type: "textarea", rows: 7, placeholder: '{"id":1,"name":"a","tags":["x"]}' },
      { k: "name", label: "Root type name", type: "text", value: "Root" },
    ],
    run(v) {
      if (!S(v.json).trim()) return "";
      const r = tryJSON(v.json); if (!r.ok) return { error: "Invalid JSON: " + r.err };
      try { return jsonToTS(r.val, v.name || "Root"); } catch (e) { return { error: e.message }; }
    },
  },
  {
    id: "cd-json-to-go", name: "JSON to Go Struct", cat: "coding",
    desc: "Generate Go struct definitions with json tags from a sample JSON object. Whole numbers map to int, decimals to float64. Best-effort from one sample.",
    tags: ["json", "golang", "struct", "types", "codegen"],
    inputs: [
      { k: "json", label: "Sample JSON", type: "textarea", rows: 7, placeholder: '{"id":1,"name":"a","active":true}' },
      { k: "name", label: "Root type name", type: "text", value: "Root" },
    ],
    run(v) {
      if (!S(v.json).trim()) return "";
      const r = tryJSON(v.json); if (!r.ok) return { error: "Invalid JSON: " + r.err };
      try { return jsonToGo(r.val, v.name || "Root"); } catch (e) { return { error: e.message }; }
    },
  },
  {
    id: "cd-csv-clean", name: "CSV Cleaner", cat: "coding",
    desc: "Tidy CSV: trim whitespace in every cell, drop fully-empty rows, optionally collapse internal whitespace and remove duplicate rows. Re-quotes fields correctly.",
    tags: ["csv", "clean", "trim", "dedupe", "normalize"],
    inputs: [
      { k: "csv", label: "CSV", type: "textarea", rows: 7, placeholder: " id , name \n1, Jane \n\n1, Jane " },
      { k: "delim", label: "Delimiter", type: "select", opts: [[",", "Comma"], ["\t", "Tab"], [";", "Semicolon"], ["|", "Pipe"]], value: "," },
      { k: "collapse", label: "Collapse internal whitespace", type: "checkbox", value: false },
      { k: "dedupe", label: "Remove duplicate rows", type: "checkbox", value: true },
    ],
    run(v) {
      if (!S(v.csv).trim()) return "";
      const d = v.delim || ",";
      let rows = parseCSV(v.csv, d).map((r) => r.map((c) => { let x = String(c).trim(); if (v.collapse) x = x.replace(/\s+/g, " "); return x; }));
      rows = rows.filter((r) => r.some((c) => c !== ""));
      if (v.dedupe) { const seen = new Set(); rows = rows.filter((r) => { const k = JSON.stringify(r); if (seen.has(k)) return false; seen.add(k); return true; }); }
      return rows.map((r) => csvRow(r, d)).join("\n") + "\n";
    },
  },
  {
    id: "cd-csv-to-md", name: "CSV to Markdown Table", cat: "coding",
    desc: "Render CSV as a GitHub-flavoured Markdown table, with optional per-column alignment (left/center/right).",
    tags: ["csv", "markdown", "table", "md", "convert"],
    inputs: [
      { k: "csv", label: "CSV", type: "textarea", rows: 7, placeholder: "name,score\nJane,42\nJohn,7" },
      { k: "delim", label: "Delimiter", type: "select", opts: [[",", "Comma"], ["\t", "Tab"], [";", "Semicolon"], ["|", "Pipe"]], value: "," },
      { k: "align", label: "Align", type: "select", opts: ["Left", "Center", "Right"], value: "Left" },
    ],
    run(v) {
      if (!S(v.csv).trim()) return "";
      const rows = parseCSV(v.csv, v.delim || ",").filter((r) => r.some((c) => c !== ""));
      if (!rows.length) return "";
      const cols = Math.max(...rows.map((r) => r.length));
      const esc = (c) => String(c).replace(/\|/g, "\\|").replace(/\n/g, " ");
      const sep = { Left: ":---", Center: ":--:", Right: "---:" }[v.align] || "---";
      const pad = (r) => { const a = r.slice(); while (a.length < cols) a.push(""); return a; };
      const out = ["| " + pad(rows[0]).map(esc).join(" | ") + " |", "| " + Array(cols).fill(sep).join(" | ") + " |"];
      for (const r of rows.slice(1)) out.push("| " + pad(r).map(esc).join(" | ") + " |");
      return out.join("\n") + "\n";
    },
  },
  {
    id: "cd-csv-transpose", name: "CSV Transpose", cat: "coding",
    desc: "Flip a CSV table on its diagonal so rows become columns and columns become rows. Short rows are padded with empty cells.",
    tags: ["csv", "transpose", "pivot", "rows", "columns"],
    inputs: [
      { k: "csv", label: "CSV", type: "textarea", rows: 7, placeholder: "a,b,c\n1,2,3\n4,5,6" },
      { k: "delim", label: "Delimiter", type: "select", opts: [[",", "Comma"], ["\t", "Tab"], [";", "Semicolon"], ["|", "Pipe"]], value: "," },
    ],
    run(v) {
      if (!S(v.csv).trim()) return "";
      const d = v.delim || ",";
      const rows = parseCSV(v.csv, d).filter((r) => r.some((c) => c !== ""));
      if (!rows.length) return "";
      const cols = Math.max(...rows.map((r) => r.length));
      const out = [];
      for (let c = 0; c < cols; c++) out.push(csvRow(rows.map((r) => r[c] == null ? "" : r[c]), d));
      return out.join("\n") + "\n";
    },
  },
  {
    id: "cd-delim-convert", name: "Delimiter Converter (CSV/TSV/...)", cat: "coding",
    desc: "Re-delimit tabular text, for example CSV to TSV or pipe-separated. Parses with the source delimiter (quote-aware) and re-quotes for the target.",
    tags: ["csv", "tsv", "delimiter", "convert", "psv"],
    inputs: [
      { k: "text", label: "Input", type: "textarea", rows: 7, placeholder: "id,name\n1,Jane" },
      { k: "from", label: "From", type: "select", opts: [[",", "Comma"], ["\t", "Tab"], [";", "Semicolon"], ["|", "Pipe"]], value: "," },
      { k: "to", label: "To", type: "select", opts: [["\t", "Tab"], [",", "Comma"], [";", "Semicolon"], ["|", "Pipe"]], value: "\t" },
    ],
    run(v) {
      if (!S(v.text).trim()) return "";
      const rows = parseCSV(v.text, v.from || ",");
      return rows.map((r) => csvRow(r, v.to || "\t")).join("\n") + "\n";
    },
  },
  {
    id: "cd-csv-stats", name: "CSV Column Stats", cat: "coding",
    desc: "Per-column summary of a CSV: how many cells are filled, how many are numeric, and min/max/sum/mean/unique for numeric columns.",
    tags: ["csv", "stats", "summary", "columns", "profile"],
    inputs: [
      { k: "csv", label: "CSV", type: "textarea", rows: 7, placeholder: "name,score\nJane,42\nJohn,7\nAmy,50" },
      { k: "delim", label: "Delimiter", type: "select", opts: [[",", "Comma"], ["\t", "Tab"], [";", "Semicolon"], ["|", "Pipe"]], value: "," },
      { k: "header", label: "First row is header", type: "checkbox", value: true },
    ],
    run(v) {
      if (!S(v.csv).trim()) return "";
      const rows = parseCSV(v.csv, v.delim || ",").filter((r) => r.some((c) => c !== ""));
      if (!rows.length) return "";
      const head = v.header ? rows[0] : rows[0].map((_, i) => "col" + (i + 1));
      const data = v.header ? rows.slice(1) : rows;
      const cols = Math.max(...rows.map((r) => r.length));
      const out = [];
      for (let c = 0; c < cols; c++) {
        const cells = data.map((r) => r[c] == null ? "" : r[c]);
        const filled = cells.filter((x) => x !== "");
        const nums = filled.filter((x) => /^[-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?$/.test(x)).map(Number);
        const uniq = new Set(filled).size;
        let line = (head[c] || "col" + (c + 1)) + ": " + filled.length + "/" + data.length + " filled, " + uniq + " unique";
        if (nums.length === filled.length && nums.length) {
          const sum = nums.reduce((a, b) => a + b, 0);
          line += " | numeric min=" + Math.min(...nums) + " max=" + Math.max(...nums) + " sum=" + sum + " mean=" + (sum / nums.length).toFixed(4).replace(/\.?0+$/, "");
        }
        out.push(line);
      }
      return out.join("\n");
    },
  },
  {
    id: "cd-csv-filter", name: "CSV Row Filter", cat: "coding",
    desc: "Keep CSV rows where a chosen column matches a condition: equals, not equals, contains, regex, or numeric > / <. Header row is preserved.",
    tags: ["csv", "filter", "where", "grep", "rows"],
    inputs: [
      { k: "csv", label: "CSV", type: "textarea", rows: 7, placeholder: "name,score\nJane,42\nJohn,7" },
      { k: "col", label: "Column (name or 1-based index)", type: "text", placeholder: "score" },
      { k: "op", label: "Condition", type: "select", opts: ["equals", "not equals", "contains", "regex", "> (number)", "< (number)"], value: "contains" },
      { k: "value", label: "Value", type: "text", placeholder: "40" },
      { k: "delim", label: "Delimiter", type: "select", opts: [[",", "Comma"], ["\t", "Tab"], [";", "Semicolon"], ["|", "Pipe"]], value: "," },
    ],
    run(v) {
      if (!S(v.csv).trim()) return "";
      const d = v.delim || ",";
      const rows = parseCSV(v.csv, d).filter((r) => r.some((c) => c !== ""));
      if (!rows.length) return "";
      const head = rows[0];
      let ci = /^\d+$/.test(S(v.col)) ? Number(v.col) - 1 : head.indexOf(S(v.col));
      if (ci < 0 || ci >= head.length) return { error: "Column '" + v.col + "' not found. Available: " + head.join(", ") };
      const val = S(v.value);
      let re = null; if (v.op === "regex") { try { re = new RegExp(val); } catch (e) { return { error: "Bad regex: " + e.message }; } }
      const test = (cell) => {
        const c = cell == null ? "" : String(cell);
        switch (v.op) {
          case "equals": return c === val;
          case "not equals": return c !== val;
          case "contains": return c.includes(val);
          case "regex": return re.test(c);
          case "> (number)": return parseFloat(c) > parseFloat(val);
          case "< (number)": return parseFloat(c) < parseFloat(val);
        }
        return false;
      };
      const kept = rows.slice(1).filter((r) => test(r[ci]));
      return [csvRow(head, d), ...kept.map((r) => csvRow(r, d))].join("\n") + "\n";
    },
  },
  {
    id: "cd-column-extract", name: "Column Extractor", cat: "coding",
    desc: "Pull out and reorder specific columns from delimited text by 1-based index (for example 1,3,2), quote-aware, with a chosen output delimiter.",
    tags: ["csv", "cut", "columns", "extract", "select"],
    inputs: [
      { k: "text", label: "Input", type: "textarea", rows: 7, placeholder: "id,name,email\n1,Jane,jane@example.com" },
      { k: "cols", label: "Columns (1-based, comma separated)", type: "text", placeholder: "1,2" },
      { k: "delim", label: "Input delimiter", type: "select", opts: [[",", "Comma"], ["\t", "Tab"], [";", "Semicolon"], ["|", "Pipe"]], value: "," },
      { k: "out", label: "Output delimiter", type: "select", opts: [[",", "Comma"], ["\t", "Tab"], [";", "Semicolon"], ["|", "Pipe"]], value: "," },
    ],
    run(v) {
      if (!S(v.text).trim()) return "";
      const idx = S(v.cols).split(/[,\s]+/).filter(Boolean).map((x) => Number(x) - 1);
      if (!idx.length || idx.some((i) => isNaN(i) || i < 0)) return { error: "List 1-based column numbers, e.g. 1,3." };
      const rows = parseCSV(v.text, v.delim || ",");
      return rows.map((r) => csvRow(idx.map((i) => r[i] == null ? "" : r[i]), v.out || ",")).join("\n") + "\n";
    },
  },
  {
    id: "cd-csv-to-sql", name: "CSV to SQL INSERT", cat: "coding",
    desc: "Generate INSERT statements from CSV using the header row as column names. Numeric cells stay unquoted, empty cells become NULL, strings are single-quoted with '' escaping.",
    tags: ["csv", "sql", "insert", "import", "convert"],
    inputs: [
      { k: "csv", label: "CSV (with header)", type: "textarea", rows: 7, placeholder: "id,name\n1,Jane\n2,John" },
      { k: "table", label: "Table name", type: "text", value: "my_table" },
      { k: "delim", label: "Delimiter", type: "select", opts: [[",", "Comma"], ["\t", "Tab"], [";", "Semicolon"], ["|", "Pipe"]], value: "," },
      { k: "multi", label: "Single multi-row INSERT", type: "checkbox", value: false },
    ],
    run(v) {
      if (!S(v.csv).trim()) return "";
      const rows = parseCSV(v.csv, v.delim || ",").filter((r) => r.some((c) => c !== ""));
      if (rows.length < 2) return { error: "Need a header row and at least one data row." };
      const cols = rows[0];
      const tbl = S(v.table).trim() || "my_table";
      const lit = (c) => { const s = c == null ? "" : String(c); if (s === "") return "NULL"; if (/^[-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?$/.test(s)) return s; return "'" + s.replace(/'/g, "''") + "'"; };
      const colList = "(" + cols.map((c) => sqlIdent(c)).join(", ") + ")";
      const tuples = rows.slice(1).map((r) => "(" + cols.map((_, i) => lit(r[i])).join(", ") + ")");
      if (v.multi) return "INSERT INTO " + tbl + " " + colList + " VALUES\n  " + tuples.join(",\n  ") + ";\n";
      return tuples.map((t) => "INSERT INTO " + tbl + " " + colList + " VALUES " + t + ";").join("\n") + "\n";
    },
  },
  {
    id: "cd-csv-create-table", name: "CSV to CREATE TABLE", cat: "coding",
    desc: "Infer a SQL CREATE TABLE from CSV by sampling each column: all-integer becomes INTEGER, all-decimal REAL, true/false BOOLEAN, otherwise TEXT (VARCHAR with the max observed length).",
    tags: ["csv", "sql", "schema", "create table", "ddl"],
    inputs: [
      { k: "csv", label: "CSV (with header)", type: "textarea", rows: 7, placeholder: "id,name,active\n1,Jane,true" },
      { k: "table", label: "Table name", type: "text", value: "my_table" },
      { k: "delim", label: "Delimiter", type: "select", opts: [[",", "Comma"], ["\t", "Tab"], [";", "Semicolon"], ["|", "Pipe"]], value: "," },
    ],
    run(v) {
      if (!S(v.csv).trim()) return "";
      const rows = parseCSV(v.csv, v.delim || ",").filter((r) => r.some((c) => c !== ""));
      if (rows.length < 2) return { error: "Need a header row and at least one data row." };
      const cols = rows[0], data = rows.slice(1);
      const defs = cols.map((name, i) => {
        const cells = data.map((r) => (r[i] == null ? "" : String(r[i]))).filter((x) => x !== "");
        let type = "TEXT";
        if (cells.length && cells.every((x) => /^[-+]?\d+$/.test(x))) type = "INTEGER";
        else if (cells.length && cells.every((x) => /^[-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?$/.test(x))) type = "REAL";
        else if (cells.length && cells.every((x) => /^(true|false)$/i.test(x))) type = "BOOLEAN";
        else { const max = cells.reduce((m, x) => Math.max(m, x.length), 1); type = "VARCHAR(" + Math.max(max, 1) + ")"; }
        return "  " + sqlIdent(name) + " " + type;
      });
      return "CREATE TABLE " + (S(v.table).trim() || "my_table") + " (\n" + defs.join(",\n") + "\n);\n";
    },
  },
  {
    id: "cd-sql-in-clause", name: "SQL IN-Clause Builder", cat: "coding",
    desc: "Turn a list (lines, commas or spaces) into a SQL IN (...) clause. Auto mode quotes non-numeric values and leaves numbers bare; strings are escaped with ''.",
    tags: ["sql", "in", "clause", "query", "list"],
    inputs: [
      { k: "list", label: "Values (one per line or comma separated)", type: "textarea", rows: 6, placeholder: "alice\nbob\n42" },
      { k: "col", label: "Column (optional)", type: "text", placeholder: "username" },
      { k: "quote", label: "Quoting", type: "select", opts: ["Auto", "Always quote", "Never quote"], value: "Auto" },
    ],
    run(v) {
      if (!S(v.list).trim()) return "";
      const items = S(v.list).split(/[\n,]+/).map((x) => x.trim()).filter((x) => x !== "");
      if (!items.length) return "";
      const q = (x) => { if (v.quote === "Never quote") return x; if (v.quote === "Auto" && /^[-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?$/.test(x)) return x; return "'" + x.replace(/'/g, "''") + "'"; };
      const body = "IN (" + items.map(q).join(", ") + ")";
      return (S(v.col).trim() ? sqlIdent(v.col.trim()) + " " : "") + body;
    },
  },
  {
    id: "cd-sql-minify", name: "SQL Minifier", cat: "coding",
    desc: "Strip -- and /* */ comments and collapse runs of whitespace into single spaces to put a SQL statement on one line. String literals are preserved.",
    tags: ["sql", "minify", "compress", "one-line", "strip comments"],
    inputs: [{ k: "sql", label: "SQL", type: "textarea", rows: 7, placeholder: "SELECT id -- key\nFROM users\nWHERE active = 1;" }],
    run(v) {
      const s = S(v.sql); if (!s.trim()) return "";
      let out = "", i = 0, inS = false, q = "";
      while (i < s.length) {
        const c = s[i], n = s[i + 1];
        if (inS) { out += c; if (c === q) { if (n === q) { out += n; i += 2; continue; } inS = false; } i++; continue; }
        if (c === "'" || c === '"') { inS = true; q = c; out += c; i++; continue; }
        if (c === "-" && n === "-") { while (i < s.length && s[i] !== "\n") i++; out += " "; continue; }
        if (c === "/" && n === "*") { i += 2; while (i < s.length && !(s[i] === "*" && s[i + 1] === "/")) i++; i += 2; out += " "; continue; }
        out += c; i++;
      }
      return out.replace(/\s+/g, " ").trim();
    },
  },
  {
    id: "cd-sql-like-escape", name: "SQL LIKE Pattern Escaper", cat: "coding",
    desc: "Escape the LIKE wildcards % and _ (and the escape character) in a literal search string, and show the pattern with the right ESCAPE clause.",
    tags: ["sql", "like", "escape", "wildcard", "search"],
    inputs: [
      { k: "text", label: "Literal text to search for", type: "text", placeholder: "100%_off" },
      { k: "pos", label: "Match", type: "select", opts: ["Contains", "Starts with", "Exact"], value: "Contains" },
      { k: "esc", label: "Escape character", type: "text", value: "\\" },
    ],
    run(v) {
      const t = S(v.text); if (t === "") return "";
      const e = (S(v.esc) || "\\")[0];
      const escaped = t.split("").map((c) => (c === e || c === "%" || c === "_") ? e + c : c).join("");
      const pat = v.pos === "Exact" ? escaped : v.pos === "Starts with" ? escaped + "%" : "%" + escaped + "%";
      return "LIKE '" + pat.replace(/'/g, "''") + "' ESCAPE '" + (e === "'" ? "''" : e) + "'";
    },
  },
  {
    id: "cd-regex-explain", name: "Regex Explainer", cat: "coding",
    desc: "Describe, token by token in plain English, what a regular expression matches: anchors, character classes, groups, quantifiers, look-arounds and flags.",
    tags: ["regex", "explain", "describe", "pattern", "cheatsheet"],
    inputs: [
      { k: "pattern", label: "Regex", type: "textarea", rows: 3, placeholder: "^\\d{3}-\\d{4}$  or  /foo(bar)?/i" },
      { k: "flags", label: "Flags (if not using /.../ )", type: "text", placeholder: "gi" },
    ],
    run(v) {
      const p = S(v.pattern).trim(); if (!p) return "";
      try { const out = explainRegex(p, v.flags); return out || { error: "Nothing to explain." }; } catch (e) { return { error: "Could not parse: " + e.message }; }
    },
  },
  {
    id: "cd-glob-to-regex", name: "Glob to Regex", cat: "coding",
    desc: "Convert a shell/gitignore glob to an anchored regular expression: * matches within a path segment, ** crosses segments, ? one character, [abc]/[!abc] classes, {a,b} alternation.",
    tags: ["glob", "regex", "wildcard", "gitignore", "convert"],
    inputs: [{ k: "glob", label: "Glob pattern", type: "text", placeholder: "src/**/*.{js,ts}" }],
    run(v) { const g = S(v.glob).trim(); if (!g) return ""; try { return globToRegex(g); } catch (e) { return { error: e.message }; } },
  },
  {
    id: "cd-case-convert", name: "String Case Converter", cat: "coding",
    desc: "Convert an identifier or phrase between camelCase, PascalCase, snake_case, SCREAMING_SNAKE, kebab-case, Title Case, Sentence case and more. Shows all forms at once.",
    tags: ["case", "camel", "snake", "kebab", "pascal", "identifier"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 3, placeholder: "user profile ID" }],
    run(v) {
      const w = splitWords(v.text); if (!w.length) return "";
      const cap = (s) => s[0].toUpperCase() + s.slice(1);
      const camel = w.map((x, i) => i ? cap(x) : x).join("");
      return [
        "camelCase       : " + camel,
        "PascalCase      : " + w.map(cap).join(""),
        "snake_case      : " + w.join("_"),
        "SCREAMING_SNAKE : " + w.join("_").toUpperCase(),
        "kebab-case      : " + w.join("-"),
        "SCREAMING-KEBAB : " + w.join("-").toUpperCase(),
        "dot.case        : " + w.join("."),
        "path/case       : " + w.join("/"),
        "Title Case      : " + w.map(cap).join(" "),
        "Sentence case   : " + cap(w.join(" ")),
        "lower case      : " + w.join(" "),
        "UPPER CASE      : " + w.join(" ").toUpperCase(),
      ].join("\n");
    },
  },
  {
    id: "cd-ws-normalize", name: "Whitespace Normalizer", cat: "coding",
    desc: "Clean up whitespace: trim each line, collapse internal runs of spaces/tabs to one space, and optionally remove blank lines. Good for pasted text and logs.",
    tags: ["whitespace", "trim", "normalize", "spaces", "clean"],
    inputs: [
      { k: "text", label: "Text", type: "textarea", rows: 7, placeholder: "  hello   world  \n\n\n  foo " },
      { k: "collapse", label: "Collapse internal runs", type: "checkbox", value: true },
      { k: "blanks", label: "Remove blank lines", type: "checkbox", value: false },
      { k: "squeeze", label: "Squeeze multiple blank lines to one", type: "checkbox", value: true },
    ],
    run(v) {
      let s = S(v.text); if (!s.trim() && !s) return "";
      let lines = s.replace(/\r\n?/g, "\n").split("\n").map((l) => { let x = l.replace(/^\s+|\s+$/g, ""); if (v.collapse) x = x.replace(/[ \t]+/g, " "); return x; });
      if (v.blanks) lines = lines.filter((l) => l !== "");
      else if (v.squeeze) { const out = []; for (const l of lines) { if (l === "" && out[out.length - 1] === "") continue; out.push(l); } lines = out; }
      return lines.join("\n").replace(/^\n+|\n+$/g, "");
    },
  },
  {
    id: "cd-sort-lines", name: "Line Sorter", cat: "coding",
    desc: "Sort lines alphabetically, by number, by length, or naturally (file2 before file10). Keeps duplicates; supports reverse and case-insensitive order.",
    tags: ["sort", "lines", "order", "natural", "numeric"],
    inputs: [
      { k: "text", label: "Lines", type: "textarea", rows: 7, placeholder: "file10\nfile2\nfile1" },
      { k: "by", label: "Sort by", type: "select", opts: ["Alphabetical", "Natural", "Numeric", "Length"], value: "Alphabetical" },
      { k: "ci", label: "Case-insensitive", type: "checkbox", value: false },
      { k: "rev", label: "Reverse", type: "checkbox", value: false },
    ],
    run(v) {
      const s = S(v.text); if (!s.trim()) return "";
      let lines = s.replace(/\r\n?/g, "\n").split("\n");
      const keep = lines.length && lines[lines.length - 1] === "" ? (lines.pop(), true) : false;
      const key = (x) => v.ci ? x.toLowerCase() : x;
      let cmp;
      if (v.by === "Numeric") cmp = (a, b) => (parseFloat(a) || 0) - (parseFloat(b) || 0);
      else if (v.by === "Length") cmp = (a, b) => a.length - b.length || key(a).localeCompare(key(b));
      else if (v.by === "Natural") cmp = (a, b) => key(a).localeCompare(key(b), undefined, { numeric: true, sensitivity: "base" });
      else cmp = (a, b) => key(a).localeCompare(key(b));
      lines.sort(cmp);
      if (v.rev) lines.reverse();
      return lines.join("\n") + (keep ? "\n" : "");
    },
  },
  {
    id: "cd-reverse-lines", name: "Line Reverser", cat: "coding",
    desc: "Reverse the order of lines in a block of text (last line first). Different from reversing characters within a line.",
    tags: ["reverse", "lines", "flip", "tac", "order"],
    inputs: [{ k: "text", label: "Lines", type: "textarea", rows: 7, placeholder: "first\nsecond\nthird" }],
    run(v) { const s = S(v.text); if (!s.trim()) return ""; const lines = s.replace(/\r\n?/g, "\n").replace(/\n$/, "").split("\n"); return lines.reverse().join("\n"); },
  },
  {
    id: "cd-wrap-lines", name: "Line Wrapper", cat: "coding",
    desc: "Hard-wrap text to a maximum width, breaking on spaces (word wrap). Useful for commit messages and comment blocks. Existing single newlines are treated as paragraph breaks.",
    tags: ["wrap", "fold", "width", "columns", "commit"],
    inputs: [
      { k: "text", label: "Text", type: "textarea", rows: 6, placeholder: "a long sentence that should be wrapped to a fixed width" },
      { k: "width", label: "Width", type: "range", min: 20, max: 120, step: 1, value: 72 },
    ],
    run(v) {
      const s = S(v.text); if (!s.trim()) return "";
      const w = Math.max(10, Number(v.width) || 72);
      return s.replace(/\r\n?/g, "\n").split("\n").map((para) => {
        if (para.trim() === "") return "";
        const words = para.split(/\s+/); const lines = []; let cur = "";
        for (const word of words) { if (cur === "") cur = word; else if ((cur + " " + word).length <= w) cur += " " + word; else { lines.push(cur); cur = word; } }
        if (cur) lines.push(cur);
        return lines.join("\n");
      }).join("\n");
    },
  },
  {
    id: "cd-join-split", name: "Join / Split Lines", cat: "coding",
    desc: "Join lines into one string with a chosen separator, or split a string on a separator into one item per line. Handy for building or breaking apart lists.",
    tags: ["join", "split", "lines", "delimiter", "list"],
    inputs: [
      { k: "text", label: "Input", type: "textarea", rows: 6, placeholder: "a\nb\nc" },
      { k: "mode", label: "Mode", type: "select", opts: ["Join lines", "Split to lines"], value: "Join lines" },
      { k: "sep", label: "Separator", type: "text", value: ", " },
      { k: "wrap", label: "Wrap each (join only), e.g. ' or \"", type: "text", placeholder: "'" },
    ],
    run(v) {
      const s = S(v.text); if (!s) return "";
      const sep = S(v.sep);
      if (v.mode === "Join lines") { const wrap = S(v.wrap); const items = s.replace(/\r\n?/g, "\n").replace(/\n$/, "").split("\n"); return items.map((x) => wrap ? wrap + x + wrap : x).join(sep); }
      if (sep === "") return { error: "Give a separator to split on." };
      return s.split(sep).join("\n");
    },
  },
  {
    id: "cd-grep-lines", name: "Line Grep (keep / drop by regex)", cat: "coding",
    desc: "Keep only the lines that match a regular expression, or drop them (invert). Optional case-insensitive match and line numbering of results.",
    tags: ["grep", "filter", "regex", "lines", "search"],
    inputs: [
      { k: "text", label: "Text", type: "textarea", rows: 7, placeholder: "INFO ok\nERROR boom\nINFO done" },
      { k: "pattern", label: "Pattern (regex)", type: "text", placeholder: "ERROR|WARN" },
      { k: "invert", label: "Drop matching (invert)", type: "checkbox", value: false },
      { k: "ci", label: "Case-insensitive", type: "checkbox", value: false },
    ],
    run(v) {
      const s = S(v.text); if (!s.trim()) return "";
      const p = S(v.pattern); if (!p) return s;
      let re; try { re = new RegExp(p, v.ci ? "i" : ""); } catch (e) { return { error: "Bad regex: " + e.message }; }
      const lines = s.replace(/\r\n?/g, "\n").replace(/\n$/, "").split("\n");
      const kept = lines.filter((l) => re.test(l) !== !!v.invert);
      return kept.join("\n");
    },
  },
  {
    id: "cd-uniq-count", name: "Unique Line Counter", cat: "coding",
    desc: "Count how many times each distinct line appears (like sort | uniq -c), sorted by frequency. Useful for log analysis and finding top offenders.",
    tags: ["uniq", "count", "frequency", "lines", "logs"],
    inputs: [
      { k: "text", label: "Lines", type: "textarea", rows: 7, placeholder: "200\n200\n404\n200\n500" },
      { k: "ci", label: "Case-insensitive", type: "checkbox", value: false },
      { k: "order", label: "Order", type: "select", opts: ["Most frequent first", "Least frequent first", "Alphabetical"], value: "Most frequent first" },
    ],
    run(v) {
      const s = S(v.text); if (!s.trim()) return "";
      const lines = s.replace(/\r\n?/g, "\n").replace(/\n$/, "").split("\n");
      const map = new Map();
      for (const l of lines) { const k = v.ci ? l.toLowerCase() : l; const e = map.get(k) || { n: 0, label: l }; e.n++; map.set(k, e); }
      let arr = [...map.values()];
      if (v.order === "Alphabetical") arr.sort((a, b) => a.label.localeCompare(b.label));
      else if (v.order === "Least frequent first") arr.sort((a, b) => a.n - b.n);
      else arr.sort((a, b) => b.n - a.n);
      const wN = Math.max(...arr.map((e) => String(e.n).length));
      return arr.map((e) => String(e.n).padStart(wN) + "  " + e.label).join("\n");
    },
  },
  {
    id: "cd-prefix-suffix", name: "Line Prefix / Suffix", cat: "coding",
    desc: "Add a prefix and/or suffix to every non-empty line - for example to quote and comma-join a list, comment out code, or build HTML/SQL fragments.",
    tags: ["prefix", "suffix", "wrap", "lines", "quote"],
    inputs: [
      { k: "text", label: "Lines", type: "textarea", rows: 6, placeholder: "alice\nbob" },
      { k: "prefix", label: "Prefix", type: "text", placeholder: "'" },
      { k: "suffix", label: "Suffix", type: "text", placeholder: "'," },
      { k: "skipEmpty", label: "Skip empty lines", type: "checkbox", value: true },
    ],
    run(v) {
      const s = S(v.text); if (!s) return "";
      const pre = S(v.prefix), suf = S(v.suffix);
      return s.replace(/\r\n?/g, "\n").replace(/\n$/, "").split("\n").map((l) => (v.skipEmpty && l === "") ? l : pre + l + suf).join("\n");
    },
  },
  {
    id: "cd-text-stats", name: "Text Stats", cat: "coding",
    desc: "Count characters (with and without whitespace), words, lines and UTF-8 bytes of a block of text. Handy for sizing payloads, tweets or commit subjects.",
    tags: ["count", "characters", "words", "lines", "bytes"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 7, placeholder: "Hello world\nsecond line" }],
    run(v, H) {
      const s = S(v.text); if (s === "") return "";
      const chars = [...s].length;
      const noWs = [...s.replace(/\s/g, "")].length;
      const words = (s.match(/\S+/g) || []).length;
      const lines = s === "" ? 0 : s.replace(/\r\n?/g, "\n").split("\n").length;
      const bytes = H.bytes(s).length;
      return [
        "Characters          : " + chars,
        "Characters (no ws)  : " + noWs,
        "Words               : " + words,
        "Lines               : " + lines,
        "UTF-8 bytes         : " + bytes,
      ].join("\n");
    },
  },
  {
    id: "cd-regex-replace", name: "Regex Find & Replace", cat: "coding",
    desc: "Run a regular-expression substitution over text, with $1/$2 (or $<name>) back-references. Choose global and case-insensitive. A sed-style transform in the browser.",
    tags: ["regex", "replace", "substitute", "sed", "transform"],
    inputs: [
      { k: "text", label: "Text", type: "textarea", rows: 6, placeholder: "2024-01-31" },
      { k: "pattern", label: "Find (regex)", type: "text", placeholder: "(\\d{4})-(\\d{2})-(\\d{2})" },
      { k: "replace", label: "Replace with", type: "text", placeholder: "$3/$2/$1" },
      { k: "global", label: "Global", type: "checkbox", value: true },
      { k: "ci", label: "Case-insensitive", type: "checkbox", value: false },
    ],
    run(v) {
      const s = S(v.text); if (s === "") return "";
      const p = S(v.pattern); if (!p) return s;
      let re; try { re = new RegExp(p, (v.global ? "g" : "") + (v.ci ? "i" : "")); } catch (e) { return { error: "Bad regex: " + e.message }; }
      try { return s.replace(re, S(v.replace)); } catch (e) { return { error: e.message }; }
    },
  },
  {
    id: "cd-align-cols", name: "Column Aligner", cat: "coding",
    desc: "Align whitespace- or delimiter-separated fields into neat columns (like column -t), padding each column to its widest cell. Great for tidying tables in comments or output.",
    tags: ["align", "columns", "table", "format", "pad"],
    inputs: [
      { k: "text", label: "Rows", type: "textarea", rows: 7, placeholder: "name age city\nJane 30 Springfield\nJohn 7 Ogdenville" },
      { k: "delim", label: "Field separator", type: "select", opts: ["Whitespace", "Comma", "Tab", "Pipe"], value: "Whitespace" },
      { k: "gap", label: "Gap between columns", type: "range", min: 1, max: 6, step: 1, value: 2 },
    ],
    run(v) {
      const s = S(v.text); if (!s.trim()) return "";
      const split = v.delim === "Comma" ? (l) => l.split(",").map((x) => x.trim()) : v.delim === "Tab" ? (l) => l.split("\t") : v.delim === "Pipe" ? (l) => l.split("|").map((x) => x.trim()) : (l) => l.trim().split(/\s+/);
      const rows = s.replace(/\r\n?/g, "\n").replace(/\n$/, "").split("\n").map(split);
      const cols = Math.max(...rows.map((r) => r.length));
      const w = []; for (let c = 0; c < cols; c++) w[c] = Math.max(...rows.map((r) => (r[c] || "").length));
      const gap = " ".repeat(Math.max(1, Number(v.gap) || 2));
      return rows.map((r) => r.map((cell, c) => c === cols - 1 ? (cell || "") : (cell || "").padEnd(w[c])).join(gap).replace(/\s+$/, "")).join("\n");
    },
  },
  {
    id: "cd-char-freq", name: "Character Frequency Counter", cat: "coding",
    desc: "Count how often each character appears, sorted by frequency with percentages - the first step in classic-cipher frequency analysis. Optionally fold case and ignore spaces.",
    tags: ["frequency", "characters", "cryptanalysis", "histogram", "cipher"],
    inputs: [
      { k: "text", label: "Text", type: "textarea", rows: 6, placeholder: "ETAOIN SHRDLU..." },
      { k: "ci", label: "Ignore case", type: "checkbox", value: true },
      { k: "lettersOnly", label: "Letters only", type: "checkbox", value: false },
    ],
    run(v) {
      let s = S(v.text); if (s === "") return "";
      if (v.ci) s = s.toUpperCase();
      const map = new Map(); let total = 0;
      for (const ch of s) { if (v.lettersOnly && !/[A-Za-z]/.test(ch)) continue; map.set(ch, (map.get(ch) || 0) + 1); total++; }
      if (!total) return "";
      const arr = [...map.entries()].sort((a, b) => b[1] - a[1]);
      const name = (c) => c === " " ? "(space)" : c === "\n" ? "(newline)" : c === "\t" ? "(tab)" : c;
      return arr.map(([c, n]) => name(c) + "\t" + n + "\t" + (100 * n / total).toFixed(2) + "%").join("\n");
    },
  },
  {
    id: "cd-strip-ansi", name: "Strip ANSI Escape Codes", cat: "coding",
    desc: "Remove ANSI/VT100 escape sequences (colour and cursor codes) from captured terminal output, leaving clean plain text for logs or docs.",
    tags: ["ansi", "strip", "terminal", "colors", "escape"],
    inputs: [{ k: "text", label: "Text with escape codes", type: "textarea", rows: 6, placeholder: "\\u001b[31mred\\u001b[0m text" }],
    run(v) {
      let s = S(v.text); if (s === "") return "";
      s = s.replace(/\\u001b|\\x1b|\\033|\\e/gi, "\u001b");
      return s.replace(/\u001b[@-_][0-?]*[ -/]*[@-~]/g, "").replace(/\u001b[@-Z\\-_]/g, "");
    },
  },
  {
    id: "cd-envsubst", name: "Environment Variable Substituter", cat: "coding",
    desc: "Expand ${VAR} and $VAR references in a template using a set of KEY=value lines, like envsubst. Unknown variables are left untouched or blanked, your choice.",
    tags: ["envsubst", "template", "interpolate", "variables", "config"],
    inputs: [
      { k: "template", label: "Template", type: "textarea", rows: 5, placeholder: "server ${HOST}:${PORT}" },
      { k: "vars", label: "Variables (KEY=value per line)", type: "textarea", rows: 4, placeholder: "HOST=example.com\nPORT=443" },
      { k: "blank", label: "Blank out unknown variables", type: "checkbox", value: false },
    ],
    run(v) {
      const t = S(v.template); if (t === "") return "";
      const env = {};
      S(v.vars).replace(/\r\n?/g, "\n").split("\n").forEach((l) => { const m = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(l); if (m) env[m[1]] = m[2]; });
      const sub = (name, braced) => { if (name in env) return env[name]; return v.blank ? "" : (braced ? "${" + name + "}" : "$" + name); };
      return t.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_, n) => sub(n, true)).replace(/\$([A-Za-z_][A-Za-z0-9_]*)/g, (_, n) => sub(n, false));
    },
  },
  {
    id: "cd-md-table-gen", name: "Markdown Table Generator", cat: "coding",
    desc: "Build a GitHub-flavoured Markdown table from rows of text (pick the field separator). The first row is the header; column widths are padded so the source lines up.",
    tags: ["markdown", "table", "generator", "md", "gfm"],
    inputs: [
      { k: "text", label: "Rows", type: "textarea", rows: 7, placeholder: "Name | Role\nJane | Admin\nJohn | User" },
      { k: "sep", label: "Field separator", type: "select", opts: ["Pipe", "Tab", "Comma"], value: "Pipe" },
      { k: "align", label: "Align", type: "select", opts: ["Left", "Center", "Right"], value: "Left" },
    ],
    run(v) {
      const s = S(v.text); if (!s.trim()) return "";
      const split = v.sep === "Tab" ? (l) => l.split("\t") : v.sep === "Comma" ? (l) => l.split(",") : (l) => l.split("|");
      const rows = s.replace(/\r\n?/g, "\n").replace(/\n$/, "").split("\n").filter((l) => l.trim() !== "").map((l) => split(l).map((c) => c.trim().replace(/\|/g, "\\|")));
      if (!rows.length) return "";
      const cols = Math.max(...rows.map((r) => r.length));
      const w = []; for (let c = 0; c < cols; c++) w[c] = Math.max(3, ...rows.map((r) => (r[c] || "").length));
      const sepCell = (width) => v.align === "Center" ? ":" + "-".repeat(Math.max(1, width - 2)) + ":" : v.align === "Right" ? "-".repeat(Math.max(1, width - 1)) + ":" : ":" + "-".repeat(Math.max(1, width - 1));
      const line = (r) => "| " + Array.from({ length: cols }, (_, c) => (r[c] || "").padEnd(w[c])).join(" | ") + " |";
      const out = [line(rows[0]), "| " + w.map(sepCell).join(" | ") + " |"];
      for (const r of rows.slice(1)) out.push(line(r));
      return out.join("\n") + "\n";
    },
  },
  {
    id: "cd-md-toc", name: "Markdown Table of Contents", cat: "coding",
    desc: "Scan Markdown headings (# .. ######) and build a nested, linked table of contents with GitHub-style anchor slugs. Fenced code blocks are ignored.",
    tags: ["markdown", "toc", "headings", "anchors", "index"],
    inputs: [
      { k: "md", label: "Markdown", type: "textarea", rows: 8, placeholder: "# Title\n## Setup\n## Usage\n### Flags" },
      { k: "minLevel", label: "Minimum heading level to include", type: "select", opts: ["1", "2"], value: "1" },
    ],
    run(v) {
      const s = S(v.md); if (!s.trim()) return "";
      const lines = s.replace(/\r\n?/g, "\n").split("\n");
      const min = Number(v.minLevel) || 1;
      const out = []; let inFence = false; const used = {};
      for (const l of lines) {
        if (/^\s*(```|~~~)/.test(l)) { inFence = !inFence; continue; }
        if (inFence) continue;
        const m = /^(#{1,6})\s+(.*?)\s*#*\s*$/.exec(l);
        if (!m) continue;
        const level = m[1].length; if (level < min) continue;
        const text = m[2].trim();
        let slug = text.toLowerCase().replace(/[^\w\s-]/g, "").trim().replace(/\s+/g, "-");
        if (used[slug] != null) { used[slug]++; slug = slug + "-" + used[slug]; } else used[slug] = 0;
        out.push("  ".repeat(level - min) + "- [" + text + "](#" + slug + ")");
      }
      return out.length ? out.join("\n") : { error: "No Markdown headings found." };
    },
  },
  {
    id: "cd-md-to-text", name: "Markdown to Plain Text", cat: "coding",
    desc: "Strip Markdown formatting (headings, emphasis, links, code fences, list markers, blockquotes) down to readable plain text. Link text is kept, URLs dropped.",
    tags: ["markdown", "plain text", "strip", "unformat", "md"],
    inputs: [{ k: "md", label: "Markdown", type: "textarea", rows: 8, placeholder: "# Title\n\nSome **bold** and a [link](https://example.com)." }],
    run(v) {
      let s = S(v.md); if (!s.trim()) return "";
      s = s.replace(/\r\n?/g, "\n");
      s = s.replace(/```[\s\S]*?```/g, (b) => b.replace(/```[^\n]*\n?/g, "").replace(/```/g, ""));
      s = s.replace(/^\s{0,3}#{1,6}\s+/gm, "");
      s = s.replace(/^\s{0,3}>\s?/gm, "");
      s = s.replace(/^\s*([-*+]|\d+\.)\s+/gm, "");
      s = s.replace(/!\[([^\]]*)\]\([^)]*\)/g, "$1");
      s = s.replace(/\[([^\]]*)\]\([^)]*\)/g, "$1");
      s = s.replace(/(\*\*|__)(.*?)\1/g, "$2").replace(/(\*|_)(.*?)\1/g, "$2");
      s = s.replace(/`([^`]*)`/g, "$1");
      s = s.replace(/^\s*([-*_])\1{2,}\s*$/gm, "");
      return s.replace(/\n{3,}/g, "\n\n").trim() + "\n";
    },
  },
  {
    id: "cd-html-to-text", name: "HTML to Plain Text", cat: "coding",
    desc: "Convert an HTML fragment to plain text: drop script/style, turn block tags and <br> into line breaks, decode common entities, collapse extra whitespace. No DOM used.",
    tags: ["html", "plain text", "strip tags", "convert", "entities"],
    inputs: [{ k: "html", label: "HTML", type: "textarea", rows: 8, placeholder: "<h1>Hi</h1><p>Some <b>bold</b> text.</p>" }],
    run(v) {
      let s = S(v.html); if (!s.trim()) return "";
      s = s.replace(/<!--[\s\S]*?-->/g, "");
      s = s.replace(/<(script|style)[\s\S]*?<\/\1>/gi, "");
      s = s.replace(/<\s*br\s*\/?>/gi, "\n");
      s = s.replace(/<\s*\/?\s*(p|div|h[1-6]|li|tr|table|ul|ol|section|article|header|footer|blockquote|pre)\b[^>]*>/gi, "\n");
      s = s.replace(/<li\b[^>]*>/gi, "- ");
      s = s.replace(/<[^>]+>/g, "");
      const ent = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", "#39": "'", "#34": '"' };
      s = s.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (m, e) => { if (e[0] === "#") { const code = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); return isNaN(code) ? m : String.fromCodePoint(code); } return e in ent ? ent[e] : m; });
      return s.replace(/[ \t]+\n/g, "\n").replace(/\n{3,}/g, "\n\n").replace(/[ \t]{2,}/g, " ").trim() + "\n";
    },
  },
  {
    id: "cd-css-minify", name: "CSS Minifier", cat: "coding",
    desc: "Shrink CSS by removing comments and unnecessary whitespace and the last semicolon in each block. String and url() contents are preserved.",
    tags: ["css", "minify", "compress", "stylesheet", "optimize"],
    inputs: [{ k: "css", label: "CSS", type: "textarea", rows: 8, placeholder: "body {\n  margin: 0; /* reset */\n  color: #fff;\n}" }],
    run(v) {
      let s = S(v.css); if (!s.trim()) return "";
      s = s.replace(/\/\*[\s\S]*?\*\//g, "");
      s = s.replace(/\s+/g, " ");
      s = s.replace(/\s*([{}:;,>~+])\s*/g, "$1");
      s = s.replace(/;}/g, "}");
      return s.trim();
    },
  },
  {
    id: "cd-css-format", name: "CSS Beautifier", cat: "coding",
    desc: "Pretty-print minified CSS: one declaration per line, braces and indentation restored. A readable counterpart to the minifier (simple brace/semicolon formatter).",
    tags: ["css", "format", "beautify", "pretty", "indent"],
    inputs: [
      { k: "css", label: "CSS", type: "textarea", rows: 7, placeholder: "body{margin:0;color:#fff}a{color:red}" },
      { k: "indent", label: "Indent", type: "select", opts: ["2", "4", "Tab"], value: "2" },
    ],
    run(v) {
      let s = S(v.css); if (!s.trim()) return "";
      s = s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\s+/g, " ").trim();
      const ind = v.indent === "Tab" ? "\t" : " ".repeat(Number(v.indent) || 2);
      let out = "", depth = 0;
      for (let i = 0; i < s.length; i++) {
        const c = s[i];
        if (c === "{") { out = out.replace(/\s*$/, "") + " {\n"; depth++; out += ind.repeat(depth); }
        else if (c === "}") { out = out.replace(/\s*$/, ""); depth = Math.max(0, depth - 1); out += "\n" + ind.repeat(depth) + "}\n" + ind.repeat(depth); }
        else if (c === ";") { out += ";\n" + ind.repeat(depth); }
        else out += c;
      }
      return out.split("\n").map((l) => l.replace(/\s+$/, "")).filter((l, i, a) => !(l === "" && a[i - 1] === "")).join("\n").trim() + "\n";
    },
  },
  {
    id: "cd-html-minify", name: "HTML Minifier", cat: "coding",
    desc: "Lightly minify HTML: remove comments (keeping conditional ones) and collapse whitespace between tags. Content inside <pre>, <textarea>, <script> and <style> is left alone.",
    tags: ["html", "minify", "compress", "whitespace", "optimize"],
    inputs: [{ k: "html", label: "HTML", type: "textarea", rows: 8, placeholder: "<ul>\n  <li> one </li>\n  <li> two </li>\n</ul>" }],
    run(v) {
      let s = S(v.html); if (!s.trim()) return "";
      const keep = [];
      s = s.replace(/<(pre|textarea|script|style)\b[\s\S]*?<\/\1>/gi, (m) => { keep.push(m); return "\u0000" + (keep.length - 1) + "\u0000"; });
      s = s.replace(/<!--(?!\[if)[\s\S]*?-->/g, "");
      s = s.replace(/>\s+</g, "><");
      s = s.replace(/\s{2,}/g, " ");
      s = s.replace(/\u0000(\d+)\u0000/g, (_, i) => keep[Number(i)]);
      return s.trim();
    },
  },
  {
    id: "cd-xml-minify", name: "XML Minifier", cat: "coding",
    desc: "Compact XML by removing comments and whitespace between tags. Text inside elements and CDATA sections is preserved.",
    tags: ["xml", "minify", "compress", "whitespace", "strip"],
    inputs: [{ k: "xml", label: "XML", type: "textarea", rows: 8, placeholder: "<order>\n  <id>1</id>\n  <qty>3</qty>\n</order>" }],
    run(v) {
      let s = S(v.xml); if (!s.trim()) return "";
      const cdata = []; s = s.replace(/<!\[CDATA\[[\s\S]*?\]\]>/g, (m) => { cdata.push(m); return "\u0000" + (cdata.length - 1) + "\u0000"; });
      s = s.replace(/<!--[\s\S]*?-->/g, "");
      s = s.replace(/>\s+</g, "><").trim();
      s = s.replace(/\u0000(\d+)\u0000/g, (_, i) => cdata[Number(i)]);
      return s;
    },
  },
  {
    id: "cd-js-strip-comments", name: "JS / JSON Comment Stripper", cat: "coding",
    desc: "Remove // and /* */ comments from JavaScript-like source while preserving string and template literals and regex literals. A safe, lite cleanup (not a full minifier).",
    tags: ["javascript", "comments", "strip", "minify-lite", "clean"],
    inputs: [
      { k: "js", label: "Source", type: "textarea", rows: 8, placeholder: "const a = 1; // count\n/* block */ const b = '//not a comment';" },
      { k: "blankLines", label: "Remove resulting blank lines", type: "checkbox", value: true },
    ],
    run(v) {
      const s = S(v.js); if (!s.trim()) return "";
      let out = "", i = 0, prev = "";
      const n = s.length;
      while (i < n) {
        const c = s[i], d = s[i + 1];
        if (c === "/" && d === "/") { while (i < n && s[i] !== "\n") i++; continue; }
        if (c === "/" && d === "*") { i += 2; while (i < n && !(s[i] === "*" && s[i + 1] === "/")) i++; i += 2; continue; }
        if (c === '"' || c === "'" || c === "`") { out += c; i++; while (i < n) { out += s[i]; if (s[i] === "\\") { out += s[i + 1]; i += 2; continue; } if (s[i] === c) { i++; break; } i++; } prev = c; continue; }
        if (c === "/" && /[(,=:[!&|?{;]|return|typeof/.test(prev.slice(-6).trim() || "(")) {
          // likely a regex literal: copy to closing /
          out += c; i++; let inCls = false;
          while (i < n) { out += s[i]; if (s[i] === "\\") { out += s[i + 1]; i += 2; continue; } if (s[i] === "[") inCls = true; else if (s[i] === "]") inCls = false; else if (s[i] === "/" && !inCls) { i++; break; } i++; }
          prev = "/"; continue;
        }
        out += c; if (!/\s/.test(c)) prev = (prev + c).slice(-8); i++;
      }
      if (v.blankLines) out = out.replace(/[ \t]+\n/g, "\n").replace(/\n{2,}/g, "\n");
      return out.replace(/[ \t]+$/gm, "").trim() + "\n";
    },
  },
  {
    id: "cd-int-bases", name: "Integer Base Viewer", cat: "coding",
    desc: "Show one integer at once in decimal, hex, octal and binary (arbitrary size via BigInt), plus its two's-complement signed/unsigned interpretation at 8/16/32/64 bits. Accepts 0x, 0o, 0b and negatives.",
    tags: ["base", "hex", "binary", "twos complement", "integer"],
    inputs: [
      { k: "num", label: "Integer", type: "text", placeholder: "0xFF  or  -42  or  0b1011" },
      { k: "group", label: "Group binary into nibbles", type: "checkbox", value: true },
    ],
    run(v) {
      const n = parseBig(v.num);
      if (n === null) return S(v.num).trim() ? { error: "Enter an integer. Prefixes 0x, 0o, 0b and a leading - are allowed." } : "";
      const groupBin = (b) => v.group ? b.replace(/\B(?=(.{4})+$)/g, "_") : b;
      const lines = [];
      lines.push("Decimal : " + n.toString(10));
      if (n >= 0n) { lines.push("Hex     : 0x" + n.toString(16).toUpperCase()); lines.push("Octal   : 0o" + n.toString(8)); lines.push("Binary  : 0b" + groupBin(n.toString(2))); }
      else { lines.push("Hex     : -0x" + (-n).toString(16).toUpperCase() + "  (sign-magnitude)"); lines.push("Octal   : -0o" + (-n).toString(8)); lines.push("Binary  : -0b" + groupBin((-n).toString(2))); }
      lines.push("");
      lines.push("Two's complement by width:");
      for (const w of [8, 16, 32, 64]) {
        const mod = 1n << BigInt(w);
        const half = 1n << BigInt(w - 1);
        const lo = -half, hi = half - 1n, umax = mod - 1n;
        if (n < lo || n > umax) { lines.push("  " + ("int" + w + "/uint" + w).padEnd(14) + ": out of range"); continue; }
        const u = ((n % mod) + mod) % mod;
        const signed = u >= half ? u - mod : u;
        const hex = "0x" + u.toString(16).toUpperCase().padStart(w / 4, "0");
        lines.push("  " + ("int" + w).padEnd(6) + "= " + signed.toString().padStart(21) + "   uint" + w + " = " + u.toString().padStart(20) + "   " + hex);
      }
      return lines.join("\n");
    },
  },
  {
    id: "cd-bitwise-calc", name: "Bitwise Calculator", cat: "coding",
    desc: "Compute AND, OR, XOR, NOT, left/right shift and rotate on integers (BigInt), masked to a chosen width. Results are shown in decimal, hex and binary. Accepts 0x, 0o, 0b.",
    tags: ["bitwise", "and", "or", "xor", "shift"],
    inputs: [
      { k: "a", label: "A", type: "text", placeholder: "0b1100" },
      { k: "op", label: "Operation", type: "select", opts: ["AND", "OR", "XOR", "NOT (A)", "SHL", "SHR", "ROL", "ROR"], value: "AND" },
      { k: "b", label: "B / shift amount", type: "text", placeholder: "0b1010" },
      { k: "width", label: "Width (bits)", type: "select", opts: ["8", "16", "32", "64"], value: "32" },
    ],
    run(v) {
      const w = BigInt(Number(v.width) || 32); const mod = 1n << w; const mask = mod - 1n;
      const a = parseBig(v.a); if (a === null) return S(v.a).trim() ? { error: "A is not a valid integer." } : "";
      const norm = (x) => ((x % mod) + mod) % mod;
      const A = norm(a);
      let r;
      if (v.op === "NOT (A)") r = norm(~A);
      else {
        const b = parseBig(v.b); if (b === null) return { error: "B / shift amount is required for " + v.op + "." };
        const B = norm(b);
        if (v.op === "AND") r = A & B;
        else if (v.op === "OR") r = A | B;
        else if (v.op === "XOR") r = A ^ B;
        else if (v.op === "SHL") r = norm(A << (b % w < 0n ? 0n : b));
        else if (v.op === "SHR") r = A >> (b < 0n ? 0n : b);
        else if (v.op === "ROL") { const s = ((b % w) + w) % w; r = norm((A << s) | (A >> (w - s))); }
        else { const s = ((b % w) + w) % w; r = norm((A >> s) | (A << (w - s))); }
        r = norm(r);
      }
      const bin = r.toString(2).padStart(Number(w), "0").replace(/\B(?=(.{4})+$)/g, "_");
      return [
        "Result (dec) : " + r.toString(10),
        "Result (hex) : 0x" + r.toString(16).toUpperCase().padStart(Number(w) / 4, "0"),
        "Result (bin) : 0b" + bin,
      ].join("\n");
    },
  },
  {
    id: "cd-ieee754", name: "IEEE-754 Float Inspector", cat: "coding",
    desc: "Break a floating-point number into its IEEE-754 sign, exponent and mantissa bits (32-bit single or 64-bit double), with the hex encoding; or decode a hex pattern back to a value.",
    tags: ["ieee754", "float", "double", "bits", "mantissa"],
    inputs: [
      { k: "value", label: "Number or 0x hex pattern", type: "text", placeholder: "0.1  or  0x3DCCCCCD" },
      { k: "prec", label: "Precision", type: "select", opts: ["64-bit (double)", "32-bit (single)"], value: "64-bit (double)" },
    ],
    run(v) {
      const raw = S(v.value).trim(); if (!raw) return "";
      const single = v.prec.startsWith("32");
      const buf = new ArrayBuffer(8);
      const dv = new DataView(buf);
      let num;
      const isHex = /^0x[0-9a-fA-F]+$/.test(raw);
      if (isHex) {
        const hex = raw.slice(2);
        if (single) { dv.setUint32(0, parseInt(hex.padStart(8, "0").slice(-8), 16)); num = dv.getFloat32(0); }
        else { const bi = BigInt(raw); dv.setBigUint64(0, bi & ((1n << 64n) - 1n)); num = dv.getFloat64(0); }
      } else { num = Number(raw); if (!isFinite(num) && !/^[-+]?(inf|infinity|nan)$/i.test(raw)) return { error: "Not a number or hex pattern." }; if (/nan/i.test(raw)) num = NaN; else if (/inf/i.test(raw)) num = raw[0] === "-" ? -Infinity : Infinity; }
      let bits, totalBits, expBits, manBits, bias;
      if (single) { dv.setFloat32(0, num); bits = BigInt(dv.getUint32(0) >>> 0); totalBits = 32; expBits = 8; manBits = 23; bias = 127; }
      else { dv.setFloat64(0, num); bits = dv.getBigUint64(0); totalBits = 64; expBits = 11; manBits = 52; bias = 1023; }
      const b = bits.toString(2).padStart(totalBits, "0");
      const sign = b[0], exp = b.slice(1, 1 + expBits), man = b.slice(1 + expBits);
      const expVal = parseInt(exp, 2);
      const hex = "0x" + bits.toString(16).toUpperCase().padStart(totalBits / 4, "0");
      let cls = "normal"; if (expVal === 0) cls = man.includes("1") ? "subnormal" : "zero"; else if (expVal === (1 << expBits) - 1) cls = man.includes("1") ? "NaN" : "infinity";
      return [
        "Value        : " + num,
        "Encoding     : " + (single ? "32-bit single" : "64-bit double"),
        "Hex          : " + hex,
        "Bits         : " + sign + " " + exp + " " + man,
        "Sign         : " + sign + " (" + (sign === "1" ? "negative" : "positive") + ")",
        "Exponent     : " + exp + " = " + expVal + " (unbiased " + (cls === "zero" || cls === "subnormal" ? 1 - bias : expVal - bias) + ", bias " + bias + ")",
        "Mantissa     : " + man,
        "Class        : " + cls,
      ].join("\n");
    },
  },
  {
    id: "cd-hexdump", name: "Hex Dump", cat: "coding",
    desc: "Show text as a classic hex dump: byte offset, hex bytes, and an ASCII gutter (non-printable bytes shown as a dot). Bytes come from the UTF-8 encoding of the input.",
    tags: ["hexdump", "hex", "bytes", "xxd", "ascii"],
    inputs: [
      { k: "text", label: "Text", type: "textarea", rows: 5, placeholder: "Hello, world!" },
      { k: "width", label: "Bytes per row", type: "select", opts: ["16", "8", "32"], value: "16" },
    ],
    run(v, H) {
      const s = S(v.text); if (s === "") return "";
      const u = H.bytes(s); const w = Number(v.width) || 16; const out = [];
      for (let off = 0; off < u.length; off += w) {
        const slice = u.slice(off, off + w);
        const hex = Array.from(slice, (b) => b.toString(16).padStart(2, "0")).join(" ").padEnd(w * 3 - 1, " ");
        const ascii = Array.from(slice, (b) => b >= 32 && b < 127 ? String.fromCharCode(b) : ".").join("");
        out.push(off.toString(16).padStart(8, "0") + "  " + hex + "  |" + ascii + "|");
      }
      out.push(u.length.toString(16).padStart(8, "0") + "  (" + u.length + " bytes)");
      return out.join("\n");
    },
  },
  {
    id: "cd-byte-array", name: "Byte Array Literal Formatter", cat: "coding",
    desc: "Turn text (or a hex string) into a source-code byte-array literal for C, Rust, Go, Java, Python, a JS Uint8Array, a 0x-comma list, or plain hex.",
    tags: ["byte array", "literal", "shellcode", "c array", "codegen"],
    inputs: [
      { k: "input", label: "Input", type: "textarea", rows: 4, placeholder: "ABC  or  41 42 43" },
      { k: "from", label: "Interpret input as", type: "select", opts: ["Text (UTF-8)", "Hex bytes"], value: "Text (UTF-8)" },
      { k: "lang", label: "Output format", type: "select", opts: ["C", "Rust", "Go", "Java", "Python", "JS Uint8Array", "0x list", "Hex string"], value: "C" },
    ],
    run(v, H) {
      const s = S(v.input); if (s.trim() === "") return "";
      const u = v.from === "Hex bytes" ? H.fromHex(s) : H.bytes(s);
      const hx = Array.from(u, (b) => "0x" + b.toString(16).padStart(2, "0"));
      const dec = Array.from(u, (b) => String(b));
      switch (v.lang) {
        case "Rust": return "let data: [u8; " + u.length + "] = [" + hx.join(", ") + "];";
        case "Go": return "data := []byte{" + hx.join(", ") + "}";
        case "Java": return "byte[] data = {" + Array.from(u, (b) => "(byte)0x" + b.toString(16).padStart(2, "0")).join(", ") + "};";
        case "Python": return "data = bytes([" + dec.join(", ") + "])";
        case "JS Uint8Array": return "const data = new Uint8Array([" + hx.join(", ") + "]);";
        case "0x list": return hx.join(", ");
        case "Hex string": return H.toHex(u);
        default: return "unsigned char data[" + u.length + "] = {" + hx.join(", ") + "};";
      }
    },
  },
  {
    id: "cd-codepoint", name: "Unicode Code Point Inspector", cat: "coding",
    desc: "List each character of the input with its Unicode code point (U+XXXX), decimal value, UTF-8 byte sequence and UTF-16 code units. Useful for spotting hidden or look-alike characters.",
    tags: ["unicode", "codepoint", "utf-8", "utf-16", "inspect"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 4, placeholder: "Aé€" }],
    run(v, H) {
      const s = S(v.text); if (s === "") return "";
      const out = ["char  code point  dec       UTF-8           UTF-16"];
      for (const ch of s) {
        const cp = ch.codePointAt(0);
        const u8 = H.toHex(H.bytes(ch)).replace(/(..)/g, "$1 ").trim();
        const u16 = Array.from({ length: ch.length }, (_, i) => ch.charCodeAt(i).toString(16).toUpperCase().padStart(4, "0")).join(" ");
        const disp = cp < 32 || (cp >= 127 && cp < 160) ? "." : ch;
        out.push(disp.padEnd(6) + ("U+" + cp.toString(16).toUpperCase().padStart(4, "0")).padEnd(11) + " " + String(cp).padEnd(9) + " " + u8.padEnd(15) + " " + u16);
      }
      return out.join("\n");
    },
  },
  {
    id: "cd-duration", name: "Duration Parser / Formatter", cat: "coding",
    desc: "Convert between a human duration (like 1h30m, 90s, 2d) and a total number of seconds or milliseconds. Understands w/d/h/m/s/ms units.",
    tags: ["duration", "time", "seconds", "parse", "humanize"],
    inputs: [
      { k: "input", label: "Duration or number", type: "text", placeholder: "1h30m  or  5400" },
      { k: "mode", label: "Direction", type: "select", opts: ["Parse to seconds", "Seconds to human", "Milliseconds to human"], value: "Parse to seconds" },
    ],
    run(v) {
      const s = S(v.input).trim(); if (!s) return "";
      const units = { w: 604800, d: 86400, h: 3600, m: 60, s: 1, ms: 0.001 };
      if (v.mode === "Parse to seconds") {
        if (/^-?\d+(\.\d+)?$/.test(s)) return s + " seconds";
        const re = /(\d+(?:\.\d+)?)\s*(ms|w|d|h|m|s)/gi; let total = 0, matched = false, m;
        while ((m = re.exec(s))) { matched = true; total += parseFloat(m[1]) * units[m[2].toLowerCase()]; }
        if (!matched) return { error: "Could not parse. Use units like 1h30m, 2d, 500ms." };
        return "Total seconds : " + (total % 1 ? total : total) + "\nMilliseconds  : " + Math.round(total * 1000);
      }
      const num = parseFloat(s); if (isNaN(num)) return { error: "Enter a number." };
      let secs = v.mode.startsWith("Milliseconds") ? num / 1000 : num;
      const neg = secs < 0; secs = Math.abs(secs);
      const parts = []; let rem = Math.floor(secs);
      for (const [u, size] of [["w", 604800], ["d", 86400], ["h", 3600], ["m", 60], ["s", 1]]) { if (rem >= size) { parts.push(Math.floor(rem / size) + u); rem %= size; } }
      const ms = Math.round((secs - Math.floor(secs)) * 1000); if (ms) parts.push(ms + "ms");
      return (neg ? "-" : "") + (parts.join(" ") || "0s");
    },
  },
  {
    id: "cd-exit-codes", name: "Exit Code & Signal Reference", cat: "coding",
    desc: "Reference for shell/bash exit status conventions (0, 1, 2, 126, 127, 128, 128+N, 130, 255) and standard Linux signal numbers. Type to filter by number or name.",
    tags: ["exit code", "signal", "bash", "sigterm", "reference"],
    inputs: [{ k: "filter", label: "Filter (optional)", type: "text", placeholder: "127 or SIGKILL" }],
    run(v) {
      const rows = [
        ["0", "Success / no error"],
        ["1", "General / catchall error"],
        ["2", "Misuse of shell builtin (e.g. bad option or syntax)"],
        ["126", "Command found but not executable (permission problem)"],
        ["127", "Command not found"],
        ["128", "Invalid argument to exit (status out of 0-255)"],
        ["128+N", "Terminated by signal N (e.g. 137 = 128+9 = SIGKILL)"],
        ["130", "Terminated by Ctrl-C (SIGINT, 128+2)"],
        ["143", "Terminated by SIGTERM (128+15)"],
        ["255", "Exit status out of range / -1 wrapped"],
        ["SIGHUP (1)", "Hangup; terminal closed"],
        ["SIGINT (2)", "Interrupt from keyboard (Ctrl-C)"],
        ["SIGQUIT (3)", "Quit from keyboard (Ctrl-\\), core dump"],
        ["SIGILL (4)", "Illegal instruction"],
        ["SIGTRAP (5)", "Trace/breakpoint trap"],
        ["SIGABRT (6)", "Abort signal from abort()"],
        ["SIGFPE (8)", "Floating-point / arithmetic exception"],
        ["SIGKILL (9)", "Kill, cannot be caught or ignored"],
        ["SIGSEGV (11)", "Invalid memory reference (segfault)"],
        ["SIGPIPE (13)", "Broken pipe; write with no reader"],
        ["SIGALRM (14)", "Timer signal from alarm()"],
        ["SIGTERM (15)", "Termination request (default kill)"],
        ["SIGSTOP (19)", "Stop process; cannot be caught"],
        ["SIGTSTP (20)", "Stop typed at terminal (Ctrl-Z)"],
        ["SIGCONT (18)", "Continue if stopped"],
      ];
      const f = S(v.filter).trim().toLowerCase();
      const sel = f ? rows.filter((r) => (r[0] + " " + r[1]).toLowerCase().includes(f)) : rows;
      if (!sel.length) return { error: "No exit code or signal matches '" + v.filter + "'." };
      return "Note: signal numbers shown are the usual Linux values.\n\n" + sel.map((r) => r[0].padEnd(13) + " " + r[1]).join("\n");
    },
  },
  {
    id: "cd-strftime-ref", name: "strftime Format Reference", cat: "coding",
    desc: "Reference for C/Python/date strftime conversion codes (%Y, %m, %d, %H, %M, %S and friends). Type to filter by code or meaning.",
    tags: ["strftime", "date", "format", "time", "reference"],
    inputs: [{ k: "filter", label: "Filter (optional)", type: "text", placeholder: "year or %H" }],
    run(v) {
      const rows = [
        ["%Y", "Year with century (2026)"], ["%y", "Year without century, 00-99"], ["%C", "Century (year/100)"],
        ["%m", "Month as number, 01-12"], ["%B", "Full month name (January)"], ["%b / %h", "Abbreviated month (Jan)"],
        ["%d", "Day of month, 01-31"], ["%e", "Day of month, space-padded ( 1-31)"], ["%j", "Day of year, 001-366"],
        ["%A", "Full weekday name (Monday)"], ["%a", "Abbreviated weekday (Mon)"], ["%w", "Weekday 0-6, Sunday=0"], ["%u", "Weekday 1-7, Monday=1"],
        ["%H", "Hour 00-23 (24-hour)"], ["%I", "Hour 01-12 (12-hour)"], ["%p", "AM or PM"], ["%M", "Minute 00-59"], ["%S", "Second 00-60"],
        ["%f", "Microseconds, 000000-999999 (Python)"], ["%Z", "Time zone name"], ["%z", "UTC offset +hhmm"],
        ["%U", "Week of year, Sunday first, 00-53"], ["%W", "Week of year, Monday first, 00-53"], ["%V", "ISO week number, 01-53"], ["%G", "ISO week-numbering year"],
        ["%s", "Unix timestamp (seconds, GNU)"], ["%D", "Equivalent to %m/%d/%y"], ["%F", "Equivalent to %Y-%m-%d"], ["%T", "Equivalent to %H:%M:%S"], ["%R", "Equivalent to %H:%M"], ["%c", "Locale date and time"], ["%x", "Locale date"], ["%X", "Locale time"],
        ["%n", "Newline"], ["%t", "Tab"], ["%%", "A literal percent sign"],
      ];
      const f = S(v.filter).trim().toLowerCase();
      const sel = f ? rows.filter((r) => (r[0] + " " + r[1]).toLowerCase().includes(f)) : rows;
      if (!sel.length) return { error: "No strftime code matches '" + v.filter + "'." };
      return sel.map((r) => r[0].padEnd(9) + " " + r[1]).join("\n");
    },
  },
  {
    id: "cd-printf-ref", name: "printf Format Reference", cat: "coding",
    desc: "Reference for C/printf format specifiers: conversions (%d %s %x %f ...), flags (- + space # 0), width, precision and length modifiers. Type to filter.",
    tags: ["printf", "format", "specifier", "c", "reference"],
    inputs: [{ k: "filter", label: "Filter (optional)", type: "text", placeholder: "hex or %f" }],
    run(v) {
      const groups = [
        ["Conversions", [
          ["%d / %i", "Signed decimal integer"], ["%u", "Unsigned decimal integer"], ["%o", "Unsigned octal"],
          ["%x / %X", "Unsigned hex (lower / UPPER)"], ["%f / %F", "Decimal floating point"], ["%e / %E", "Scientific notation"],
          ["%g / %G", "Shortest of %f or %e"], ["%a / %A", "Hexadecimal floating point"], ["%c", "Single character"],
          ["%s", "String"], ["%p", "Pointer address"], ["%%", "A literal percent sign"], ["%n", "Store chars-written count (avoid; unsafe)"],
        ]],
        ["Flags", [
          ["-", "Left-justify within the field width"], ["+", "Always show sign on numbers"], ["(space)", "Leave a space before a positive number"],
          ["#", "Alternate form (0x for hex, keep decimal point)"], ["0", "Pad numbers with leading zeros"],
        ]],
        ["Width / precision", [
          ["N", "Minimum field width of N"], ["*", "Take width/precision from an argument"], [".N", "Precision: digits or max string chars"],
        ]],
        ["Length modifiers", [
          ["hh / h", "char / short"], ["l / ll", "long / long long"], ["L", "long double"], ["z", "size_t"], ["j", "intmax_t"], ["t", "ptrdiff_t"],
        ]],
      ];
      const f = S(v.filter).trim().toLowerCase();
      const out = [];
      for (const [title, rows] of groups) {
        const sel = f ? rows.filter((r) => (r[0] + " " + r[1]).toLowerCase().includes(f)) : rows;
        if (sel.length) out.push(title + ":\n" + sel.map((r) => "  " + r[0].padEnd(9) + " " + r[1]).join("\n"));
      }
      if (!out.length) return { error: "No printf item matches '" + v.filter + "'." };
      return out.join("\n\n");
    },
  },
  {
    id: "cd-escape-ref", name: "Escape Sequence Reference", cat: "coding",
    desc: "Reference for backslash escape sequences in C/C++/Java and JSON strings (\\n, \\t, \\xHH, \\uXXXX and more), with their meaning and byte value. Type to filter.",
    tags: ["escape", "sequence", "string", "json", "reference"],
    inputs: [{ k: "filter", label: "Filter (optional)", type: "text", placeholder: "tab or \\u" }],
    run(v) {
      const rows = [
        ["\\n", "Line feed / newline (0x0A)", "C, JSON"],
        ["\\r", "Carriage return (0x0D)", "C, JSON"],
        ["\\t", "Horizontal tab (0x09)", "C, JSON"],
        ["\\b", "Backspace (0x08)", "C, JSON"],
        ["\\f", "Form feed (0x0C)", "C, JSON"],
        ["\\v", "Vertical tab (0x0B)", "C only"],
        ["\\a", "Alert / bell (0x07)", "C only"],
        ["\\0", "Null character (0x00)", "C only"],
        ["\\\\", "A literal backslash", "C, JSON"],
        ["\\\"", "A literal double quote", "C, JSON"],
        ["\\'", "A literal single quote", "C only"],
        ["\\?", "A literal question mark (avoids trigraphs)", "C only"],
        ["\\/", "A literal slash (optional)", "JSON only"],
        ["\\xHH", "Byte from two hex digits", "C only"],
        ["\\ooo", "Byte from one to three octal digits", "C only"],
        ["\\uXXXX", "Unicode code unit from four hex digits", "C, JSON, Java"],
        ["\\u{...}", "Unicode code point (ES6 / Rust)", "JS, Rust"],
        ["\\UXXXXXXXX", "Unicode code point, eight hex digits", "C only"],
      ];
      const f = S(v.filter).trim().toLowerCase();
      const sel = f ? rows.filter((r) => (r[0] + " " + r[1] + " " + r[2]).toLowerCase().includes(f)) : rows;
      if (!sel.length) return { error: "No escape sequence matches '" + v.filter + "'." };
      return "sequence     meaning (where valid)\n" + sel.map((r) => r[0].padEnd(12) + " " + r[1] + "  [" + r[2] + "]").join("\n");
    },
  },
];
