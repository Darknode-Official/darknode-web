// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Data-format mini-tools.

// ---- shared helpers (pure, no imports) ----
const S = (v) => (v === undefined || v === null ? "" : String(v));
function pj(text) {
  try { return { ok: true, val: JSON.parse(text) }; } catch (e) { return { ok: false, err: e.message }; }
}
function typeOf(v) { if (v === null) return "null"; if (Array.isArray(v)) return "array"; return typeof v; }
function describe(v) {
  if (Array.isArray(v)) return `array (${v.length} item${v.length === 1 ? "" : "s"})`;
  if (v === null) return "null";
  if (typeof v === "object") return `object (${Object.keys(v).length} key${Object.keys(v).length === 1 ? "" : "s"})`;
  return typeof v;
}

// CSV
function parseCSV(text, delim) {
  delim = delim || ",";
  const rows = []; let row = [], field = "", q = false;
  text = S(text).replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else q = false; }
      else field += c;
    } else {
      if (c === '"') q = true;
      else if (c === delim) { row.push(field); field = ""; }
      else if (c === "\n") { row.push(field); rows.push(row); row = []; field = ""; }
      else field += c;
    }
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  return rows;
}
function cleanRows(rows) { return rows.filter((r) => !(r.length === 1 && r[0] === "")); }
function csvField(s, delim) {
  s = s === undefined || s === null ? "" : String(s);
  if (/["\n\r]/.test(s) || s.indexOf(delim) >= 0) return '"' + s.replace(/"/g, '""') + '"';
  return s;
}
function serializeCSV(rows, delim) {
  return rows.map((r) => r.map((c) => csvField(c, delim)).join(delim)).join("\n");
}

// flatten / unflatten
function flatten(obj, prefix, res) {
  res = res || {};
  if (obj === null || typeof obj !== "object") { if (prefix !== "") res[prefix] = obj; return res; }
  if (Array.isArray(obj)) {
    if (!obj.length && prefix !== "") res[prefix] = [];
    obj.forEach((v, i) => flatten(v, prefix ? prefix + "." + i : String(i), res));
  } else {
    const ks = Object.keys(obj);
    if (!ks.length && prefix !== "") res[prefix] = {};
    ks.forEach((k) => flatten(obj[k], prefix ? prefix + "." + k : k, res));
  }
  return res;
}
function unflatten(flat) {
  const res = {};
  Object.keys(flat).forEach((key) => {
    const parts = key.split(".");
    let cur = res;
    parts.forEach((p, idx) => {
      if (idx === parts.length - 1) { cur[p] = flat[key]; }
      else {
        const nextIndex = /^\d+$/.test(parts[idx + 1]);
        if (cur[p] === undefined || cur[p] === null || typeof cur[p] !== "object") cur[p] = nextIndex ? [] : {};
        cur = cur[p];
      }
    });
  });
  return res;
}

function sortKeys(v) {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === "object") { const o = {}; Object.keys(v).sort().forEach((k) => { o[k] = sortKeys(v[k]); }); return o; }
  return v;
}
function isEmptyVal(v) {
  return v === null || v === undefined || v === "" ||
    (Array.isArray(v) && v.length === 0) ||
    (v && typeof v === "object" && !Array.isArray(v) && Object.keys(v).length === 0);
}
function removeEmpty(v) {
  if (Array.isArray(v)) return v.map(removeEmpty).filter((x) => !isEmptyVal(x));
  if (v && typeof v === "object") {
    const o = {};
    Object.keys(v).forEach((k) => { const nv = removeEmpty(v[k]); if (!isEmptyVal(nv)) o[k] = nv; });
    return o;
  }
  return v;
}
function depthOf(v) {
  if (Array.isArray(v)) return 1 + (v.length ? Math.max.apply(null, v.map(depthOf)) : 0);
  if (v && typeof v === "object") { const ks = Object.keys(v); return 1 + (ks.length ? Math.max.apply(null, ks.map((k) => depthOf(v[k]))) : 0); }
  return 0;
}
function typeSummary(v) {
  if (Array.isArray(v)) return v.length ? [typeSummary(v[0])] : [];
  if (v && typeof v === "object") { const o = {}; Object.keys(v).forEach((k) => { o[k] = typeSummary(v[k]); }); return o; }
  return typeOf(v);
}
function countKeysDeep(v) {
  let n = 0;
  if (Array.isArray(v)) v.forEach((x) => { n += countKeysDeep(x); });
  else if (v && typeof v === "object") { const ks = Object.keys(v); n += ks.length; ks.forEach((k) => { n += countKeysDeep(v[k]); }); }
  return n;
}
function deepMerge(a, b) {
  if (a && typeof a === "object" && !Array.isArray(a) && b && typeof b === "object" && !Array.isArray(b)) {
    const o = Object.assign({}, a);
    Object.keys(b).forEach((k) => { o[k] = k in a ? deepMerge(a[k], b[k]) : b[k]; });
    return o;
  }
  return b;
}
function getPath(obj, path) {
  const parts = []; let i = 0;
  while (i < path.length) {
    const c = path[i];
    if (c === ".") { i++; }
    else if (c === "[") {
      const e = path.indexOf("]", i);
      if (e < 0) { parts.push(path.slice(i + 1)); break; }
      let k = path.slice(i + 1, e).replace(/^['"]|['"]$/g, "");
      parts.push(k); i = e + 1;
    } else {
      let j = i; while (j < path.length && path[j] !== "." && path[j] !== "[") j++;
      parts.push(path.slice(i, j)); i = j;
    }
  }
  let cur = obj;
  for (const p of parts) { if (cur === null || cur === undefined) return undefined; cur = cur[p]; }
  return cur;
}

// XML
function xmlEscape(s) { return S(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
function xmlDecode(s) {
  return S(s).replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'").replace(/&apos;/g, "'").replace(/&amp;/g, "&");
}
function xmlNode(val, tag) {
  if (val === null || val === undefined) return `<${tag}/>`;
  if (Array.isArray(val)) return val.map((x) => xmlNode(x, tag)).join("");
  if (typeof val === "object") {
    const inner = Object.keys(val).map((k) => xmlNode(val[k], k)).join("");
    return `<${tag}>${inner}</${tag}>`;
  }
  return `<${tag}>${xmlEscape(val)}</${tag}>`;
}
function parseXml(xml) {
  xml = S(xml).replace(/<\?[\s\S]*?\?>/g, "").replace(/<!--[\s\S]*?-->/g, "");
  let pos = 0;
  function parseNodes() {
    const nodes = [];
    while (pos < xml.length) {
      if (xml[pos] === "<") {
        if (xml[pos + 1] === "/") break;
        const close = xml.indexOf(">", pos);
        if (close < 0) throw new Error("unclosed tag");
        let tc = xml.slice(pos + 1, close);
        const selfClose = tc.endsWith("/");
        if (selfClose) tc = tc.slice(0, -1);
        const name = tc.trim().split(/\s+/)[0];
        pos = close + 1;
        if (selfClose) { nodes.push({ name: name, children: [] }); continue; }
        const children = parseNodes();
        const cl = xml.indexOf(">", pos);
        pos = cl < 0 ? xml.length : cl + 1;
        nodes.push({ name: name, children: children });
      } else {
        const next = xml.indexOf("<", pos);
        const text = xml.slice(pos, next < 0 ? xml.length : next);
        pos = next < 0 ? xml.length : next;
        if (text.trim()) nodes.push({ text: text });
      }
    }
    return nodes;
  }
  const nodes = parseNodes();
  return nodes;
}
function elemValue(node) {
  const elems = node.children.filter((c) => c.name);
  const texts = node.children.filter((c) => c.text !== undefined);
  if (!elems.length) return xmlDecode(texts.map((c) => c.text).join("").trim());
  const obj = {};
  elems.forEach((c) => {
    const v = elemValue(c);
    if (Object.prototype.hasOwnProperty.call(obj, c.name)) {
      if (Array.isArray(obj[c.name])) obj[c.name].push(v);
      else obj[c.name] = [obj[c.name], v];
    } else obj[c.name] = v;
  });
  return obj;
}
function prettyXml(xml, unit) {
  xml = S(xml).replace(/<\?[\s\S]*?\?>/g, "").replace(/<!--[\s\S]*?-->/g, "").replace(/>\s+</g, "><").trim();
  const tokens = xml.split(/(<[^>]+>)/).filter((t) => t !== "" && t !== undefined);
  const out = []; let depth = 0;
  tokens.forEach((tok) => {
    if (/^<\//.test(tok)) { depth = Math.max(depth - 1, 0); out.push(unit.repeat(depth) + tok); }
    else if (/^<[!?]/.test(tok) || /\/>$/.test(tok)) { out.push(unit.repeat(depth) + tok); }
    else if (/^</.test(tok)) { out.push(unit.repeat(depth) + tok); depth++; }
    else { const t = tok.trim(); if (t) out.push(unit.repeat(depth) + t); }
  });
  return out.join("\n");
}

// YAML dump
function yamlScalar(v) {
  if (v === null || v === undefined) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return String(v);
  const s = String(v);
  if (s === "") return '""';
  if (/[:#\-?\[\]{}&*!|>'"%@`,]/.test(s) || /^\s|\s$/.test(s) || /\n/.test(s) ||
    /^(true|false|null|yes|no|~)$/i.test(s) || (/^-?\d/.test(s) && !isNaN(Number(s)))) {
    return JSON.stringify(s);
  }
  return s;
}
function yamlKey(k) { const s = String(k); return /^[A-Za-z0-9_][\w.-]*$/.test(s) ? s : JSON.stringify(s); }
function dumpYaml(val, indent) {
  const pad = "  ".repeat(indent);
  if (Array.isArray(val)) {
    if (!val.length) return pad + "[]";
    return val.map((item) => {
      if (item !== null && typeof item === "object" && (Array.isArray(item) ? item.length : Object.keys(item).length)) {
        return pad + "-\n" + dumpYaml(item, indent + 1);
      }
      return pad + "- " + yamlScalar(item);
    }).join("\n");
  }
  if (val !== null && typeof val === "object") {
    const keys = Object.keys(val);
    if (!keys.length) return pad + "{}";
    return keys.map((k) => {
      const v = val[k];
      if (v !== null && typeof v === "object" && (Array.isArray(v) ? v.length : Object.keys(v).length)) {
        return pad + yamlKey(k) + ":\n" + dumpYaml(v, indent + 1);
      }
      if (v !== null && typeof v === "object") return pad + yamlKey(k) + ": " + (Array.isArray(v) ? "[]" : "{}");
      return pad + yamlKey(k) + ": " + yamlScalar(v);
    }).join("\n");
  }
  return pad + yamlScalar(val);
}

// YAML parse (practical subset)
function yScalar(s) {
  s = s.trim();
  if (s === "" || s === "~" || s === "null") return null;
  if (s === "true") return true;
  if (s === "false") return false;
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    if (s[0] === '"') { try { return JSON.parse(s); } catch (e) { return s.slice(1, -1); } }
    return s.slice(1, -1).replace(/''/g, "'");
  }
  if (/^-?\d+$/.test(s)) return parseInt(s, 10);
  if (/^-?\d*\.\d+$/.test(s) || /^-?\d+\.?\d*[eE][+-]?\d+$/.test(s)) return parseFloat(s);
  return s;
}
function yFindColon(s) {
  let inS = false, inD = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "'" && !inD) inS = !inS;
    else if (c === '"' && !inS) inD = !inD;
    else if (c === ":" && !inS && !inD) { if (i + 1 >= s.length || s[i + 1] === " ") return i; }
  }
  return -1;
}
function ySplitKV(content) {
  const idx = yFindColon(content);
  if (idx < 0) return null;
  let key = content.slice(0, idx).trim();
  if ((key.startsWith('"') && key.endsWith('"')) || (key.startsWith("'") && key.endsWith("'"))) key = key.slice(1, -1);
  return { key: key, rest: content.slice(idx + 1).trim() };
}
function parseYaml(text) {
  const lines = [];
  S(text).replace(/\r\n/g, "\n").split("\n").forEach((raw) => {
    const t = raw.replace(/\t/g, "  ").replace(/\s+$/, "");
    const trimmed = t.trim();
    if (trimmed === "" || trimmed.startsWith("#")) return;
    if (trimmed === "---" || trimmed === "...") return;
    const indent = t.length - t.replace(/^ +/, "").length;
    lines.push({ indent: indent, content: trimmed });
  });
  if (!lines.length) return null;
  let i = 0;
  function isSeq(l) { return l.content === "-" || l.content.startsWith("- "); }
  function parseNode() {
    const base = lines[i].indent;
    if (isSeq(lines[i])) return parseSeq(base);
    return parseMap(base);
  }
  function parseMap(base) {
    const obj = {};
    while (i < lines.length && lines[i].indent === base && !isSeq(lines[i])) {
      const kv = ySplitKV(lines[i].content);
      if (!kv) { i++; continue; }
      if (kv.rest === "") {
        i++;
        if (i < lines.length && lines[i].indent > base) obj[kv.key] = parseNode();
        else obj[kv.key] = null;
      } else { obj[kv.key] = yScalar(kv.rest); i++; }
    }
    return obj;
  }
  function parseSeq(base) {
    const arr = [];
    while (i < lines.length && lines[i].indent === base && isSeq(lines[i])) {
      const after = lines[i].content === "-" ? "" : lines[i].content.slice(2).trim();
      if (after === "") {
        i++;
        if (i < lines.length && lines[i].indent > base) arr.push(parseNode());
        else arr.push(null);
        continue;
      }
      const kv = ySplitKV(after);
      if (kv) {
        const obj = {};
        if (kv.rest === "") { i++; if (i < lines.length && lines[i].indent > base) obj[kv.key] = parseNode(); else obj[kv.key] = null; }
        else { obj[kv.key] = yScalar(kv.rest); i++; }
        while (i < lines.length && lines[i].indent > base && !isSeq(lines[i])) {
          const kv2 = ySplitKV(lines[i].content);
          if (!kv2) { i++; continue; }
          const cur = lines[i].indent;
          if (kv2.rest === "") { i++; if (i < lines.length && lines[i].indent > cur) obj[kv2.key] = parseNode(); else obj[kv2.key] = null; }
          else { obj[kv2.key] = yScalar(kv2.rest); i++; }
        }
        arr.push(obj);
      } else { arr.push(yScalar(after)); i++; }
    }
    return arr;
  }
  if (lines.length === 1 && !isSeq(lines[0]) && ySplitKV(lines[0].content) === null) return yScalar(lines[0].content);
  return parseNode();
}

// TOML
function tomlKey(k) { const s = String(k); return /^[A-Za-z0-9_-]+$/.test(s) ? s : JSON.stringify(s); }
function tomlVal(v) {
  if (v === null || v === undefined) return '""';
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return String(v);
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(tomlVal).join(", ") + "]";
  return JSON.stringify(JSON.stringify(v));
}
function tomlSection(obj, path) {
  let out = ""; const scalars = [], tables = [], arrTables = [];
  Object.keys(obj).forEach((k) => {
    const v = obj[k];
    if (v !== null && typeof v === "object" && !Array.isArray(v)) tables.push(k);
    else if (Array.isArray(v) && v.length && v.every((x) => x !== null && typeof x === "object" && !Array.isArray(x))) arrTables.push(k);
    else scalars.push(k);
  });
  scalars.forEach((k) => { out += tomlKey(k) + " = " + tomlVal(obj[k]) + "\n"; });
  tables.forEach((k) => { const p = path ? path + "." + tomlKey(k) : tomlKey(k); out += "\n[" + p + "]\n" + tomlSection(obj[k], p); });
  arrTables.forEach((k) => { const p = path ? path + "." + tomlKey(k) : tomlKey(k); obj[k].forEach((item) => { out += "\n[[" + p + "]]\n" + tomlSection(item, p); }); });
  return out;
}

// naming for code-gen
function pascal(s) {
  const p = String(s).replace(/[^A-Za-z0-9]+/g, " ").trim().split(/\s+/).map((w) => (w ? w[0].toUpperCase() + w.slice(1) : "")).join("");
  return p || "Field";
}
function singular(s) { s = String(s); return s.length > 1 && s.endsWith("s") ? s.slice(0, -1) : s; }
function goType(v, name, structs) {
  if (v === null || v === undefined) return "interface{}";
  if (typeof v === "boolean") return "bool";
  if (typeof v === "number") return Number.isInteger(v) ? "int" : "float64";
  if (typeof v === "string") return "string";
  if (Array.isArray(v)) { if (!v.length) return "[]interface{}"; return "[]" + goType(v[0], singular(name), structs); }
  const sname = pascal(name);
  const fields = Object.keys(v).map((k) => "\t" + pascal(k) + " " + goType(v[k], k, structs) + " `json:\"" + k + "\"`");
  structs.push("type " + sname + " struct {\n" + fields.join("\n") + "\n}");
  return sname;
}
function tsKey(k) { return /^[A-Za-z_$][\w$]*$/.test(k) ? k : JSON.stringify(k); }
function tsType(v, name, out) {
  if (v === null || v === undefined) return "null";
  if (typeof v === "boolean") return "boolean";
  if (typeof v === "number") return "number";
  if (typeof v === "string") return "string";
  if (Array.isArray(v)) { if (!v.length) return "any[]"; return tsType(v[0], singular(name), out) + "[]"; }
  const iname = pascal(name);
  const fields = Object.keys(v).map((k) => "  " + tsKey(k) + ": " + tsType(v[k], k, out) + ";");
  out.push("interface " + iname + " {\n" + fields.join("\n") + "\n}");
  return iname;
}

// query strings
function toQueryFlat(obj) {
  const parts = [];
  Object.keys(obj).forEach((k) => {
    const val = obj[k];
    if (Array.isArray(val)) val.forEach((x) => parts.push(encodeURIComponent(k) + "=" + encodeURIComponent(x === null || x === undefined ? "" : x)));
    else if (val !== null && typeof val === "object") parts.push(encodeURIComponent(k) + "=" + encodeURIComponent(JSON.stringify(val)));
    else parts.push(encodeURIComponent(k) + "=" + encodeURIComponent(val === null || val === undefined ? "" : val));
  });
  return parts.join("&");
}
function toBracket(v, prefix, parts) {
  parts = parts || [];
  if (v === null || v === undefined || typeof v !== "object") { parts.push(encodeURIComponent(prefix) + "=" + encodeURIComponent(v === null || v === undefined ? "" : v)); return parts; }
  if (Array.isArray(v)) v.forEach((x, idx) => toBracket(x, prefix + "[" + idx + "]", parts));
  else Object.keys(v).forEach((k) => toBracket(v[k], prefix ? prefix + "[" + k + "]" : k, parts));
  return parts;
}

// misc parsers
function parseEnv(text) {
  const o = {};
  S(text).split(/\r?\n/).forEach((line) => {
    let l = line.trim();
    if (!l || l.startsWith("#")) return;
    if (l.startsWith("export ")) l = l.slice(7).trim();
    const i = l.indexOf("=");
    if (i < 0) return;
    const k = l.slice(0, i).trim();
    let v = l.slice(i + 1).trim();
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
    o[k] = v;
  });
  return o;
}
function coerce(s) {
  const t = s.trim();
  if (t === "") return "";
  if (t === "true") return true;
  if (t === "false") return false;
  if (t === "null") return null;
  if (/^-?\d+$/.test(t)) return parseInt(t, 10);
  if (/^-?\d*\.\d+$/.test(t)) return parseFloat(t);
  return s;
}
function sqlVal(v) {
  if (v === null || v === undefined || v === "") return "NULL";
  if (typeof v === "number") return String(v);
  if (typeof v === "boolean") return v ? "TRUE" : "FALSE";
  if (typeof v === "object") v = JSON.stringify(v);
  const s = String(v);
  if (/^-?\d+(\.\d+)?$/.test(s)) return s;
  return "'" + s.replace(/'/g, "''") + "'";
}

function indentOf(sel) { return sel === "4 spaces" ? 4 : sel === "8 spaces" ? 8 : sel === "Tab" ? "\t" : 2; }

// ---- tools ----
export const TOOLS = [
  { id: "df-json-pretty", name: "JSON Pretty-Print", cat: "data", desc: "Format JSON with a chosen indent width.", tags: ["json", "format", "beautify"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8, placeholder: '{"a":1,"b":[2,3]}' }, { k: "indent", label: "Indent", type: "select", opts: ["2 spaces", "4 spaces", "8 spaces", "Tab"], value: "2 spaces" }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; return JSON.stringify(p.val, null, indentOf(v.indent)); } },

  { id: "df-json-minify", name: "JSON Minify", cat: "data", desc: "Strip all insignificant whitespace from JSON.", tags: ["json", "minify", "compact"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8 }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; return JSON.stringify(p.val); } },

  { id: "df-json-validate", name: "JSON Validate", cat: "data", desc: "Check JSON syntax and report whether it is valid, with any error.", tags: ["json", "validate", "lint"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8 }],
    run(v) { if (!v.json || !v.json.trim()) return ""; try { const val = JSON.parse(v.json); return "Valid JSON — " + describe(val) + "."; } catch (e) { const m = /position (\d+)/.exec(e.message); return { error: e.message + (m ? " (offset " + m[1] + ")" : "") }; } } },

  { id: "df-json-sort-keys", name: "JSON Sort Keys (deep)", cat: "data", desc: "Recursively sort every object's keys alphabetically.", tags: ["json", "sort", "keys"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8 }, { k: "indent", label: "Indent", type: "select", opts: ["2 spaces", "4 spaces", "Tab"], value: "2 spaces" }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; return JSON.stringify(sortKeys(p.val), null, indentOf(v.indent)); } },

  { id: "df-json-flatten", name: "JSON Flatten (dot keys)", cat: "data", desc: "Collapse nested JSON into a single object with dot/index paths.", tags: ["json", "flatten", "dot"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8, placeholder: '{"a":{"b":1},"c":[2,3]}' }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; return JSON.stringify(flatten(p.val, "", {}), null, 2); } },

  { id: "df-json-unflatten", name: "JSON Unflatten", cat: "data", desc: "Rebuild nested JSON from a flat object with dot/index paths.", tags: ["json", "unflatten", "nest"],
    inputs: [{ k: "json", label: "Flat JSON", type: "textarea", rows: 8, placeholder: '{"a.b":1,"c.0":2}' }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; if (p.val === null || typeof p.val !== "object" || Array.isArray(p.val)) return { error: "Input must be a flat JSON object." }; return JSON.stringify(unflatten(p.val), null, 2); } },

  { id: "df-json-escape", name: "JSON Escape to String Literal", cat: "data", desc: "Turn JSON (or any text) into an escaped JSON string literal.", tags: ["json", "escape", "string"],
    inputs: [{ k: "text", label: "Text / JSON", type: "textarea", rows: 8 }],
    run(v) { if (!v.text) return ""; return JSON.stringify(v.text); } },

  { id: "df-json-oneline", name: "JSON Stringify One-Line", cat: "data", desc: "Re-serialize JSON as a single compact line.", tags: ["json", "oneline", "compact"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8 }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; return JSON.stringify(p.val).replace(/\n/g, ""); } },

  { id: "df-json-to-qs", name: "JSON → Query String", cat: "data", desc: "Convert a flat JSON object into a URL query string.", tags: ["json", "querystring", "url"],
    inputs: [{ k: "json", label: "JSON object", type: "textarea", rows: 6, placeholder: '{"q":"test","page":2}' }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; if (p.val === null || typeof p.val !== "object" || Array.isArray(p.val)) return { error: "Input must be a JSON object." }; return toQueryFlat(p.val); } },

  { id: "df-qs-to-json", name: "Query String → JSON", cat: "data", desc: "Parse a URL query string into JSON (repeated keys become arrays).", tags: ["querystring", "json", "url"],
    inputs: [{ k: "qs", label: "Query string", type: "text", placeholder: "q=test&page=2" }],
    run(v) { if (!v.qs) return ""; let s = v.qs.trim(); const qi = s.indexOf("?"); if (qi >= 0) s = s.slice(qi + 1); const obj = {}; if (s) s.split("&").forEach((pair) => { if (!pair) return; const idx = pair.indexOf("="); let k = idx < 0 ? pair : pair.slice(0, idx), val = idx < 0 ? "" : pair.slice(idx + 1); try { k = decodeURIComponent(k.replace(/\+/g, " ")); } catch (e) {} try { val = decodeURIComponent(val.replace(/\+/g, " ")); } catch (e) {} if (Object.prototype.hasOwnProperty.call(obj, k)) { if (Array.isArray(obj[k])) obj[k].push(val); else obj[k] = [obj[k], val]; } else obj[k] = val; }); return JSON.stringify(obj, null, 2); } },

  { id: "df-json-merge", name: "JSON Deep-Merge", cat: "data", desc: "Deep-merge two JSON objects (second wins on conflicts).", tags: ["json", "merge", "combine"],
    inputs: [{ k: "a", label: "Base JSON", type: "textarea", rows: 6, placeholder: '{"a":1,"b":{"x":1}}' }, { k: "b", label: "Overlay JSON", type: "textarea", rows: 6, placeholder: '{"b":{"y":2}}' }],
    run(v) { if (!(v.a && v.a.trim()) && !(v.b && v.b.trim())) return ""; const pa = pj(v.a || "{}"); if (!pa.ok) return { error: "Invalid base JSON: " + pa.err }; const pb = pj(v.b || "{}"); if (!pb.ok) return { error: "Invalid overlay JSON: " + pb.err }; return JSON.stringify(deepMerge(pa.val, pb.val), null, 2); } },

  { id: "df-json-remove-empty", name: "JSON Remove Null/Empty", cat: "data", desc: "Recursively drop null, empty string, empty object and empty array values.", tags: ["json", "clean", "null"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8 }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; return JSON.stringify(removeEmpty(p.val), null, 2); } },

  { id: "df-json-keys", name: "JSON Keys List (deep paths)", cat: "data", desc: "List every leaf path in the JSON, one per line.", tags: ["json", "keys", "paths"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8 }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; const keys = Object.keys(flatten(p.val, "", {})); return keys.join("\n"); } },

  { id: "df-json-values", name: "JSON Values List", cat: "data", desc: "List every leaf value in the JSON, one per line.", tags: ["json", "values", "leaves"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8 }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; const flat = flatten(p.val, "", {}); return Object.keys(flat).map((k) => (typeof flat[k] === "object" ? JSON.stringify(flat[k]) : String(flat[k]))).join("\n"); } },

  { id: "df-json-depth", name: "JSON Depth", cat: "data", desc: "Report the maximum nesting depth of a JSON value.", tags: ["json", "depth", "nesting"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8 }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; return "Max depth: " + depthOf(p.val); } },

  { id: "df-json-type-summary", name: "JSON Type Summary", cat: "data", desc: "Replace every value with its type to reveal the shape.", tags: ["json", "types", "shape"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8 }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; return JSON.stringify(typeSummary(p.val), null, 2); } },

  { id: "df-json-to-csv", name: "JSON → CSV", cat: "data", desc: "Convert a JSON array of flat objects into CSV rows.", tags: ["json", "csv"],
    inputs: [{ k: "json", label: "JSON array", type: "textarea", rows: 8, placeholder: '[{"a":1,"b":2}]' }, { k: "delim", label: "Delimiter", type: "text", value: "," }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; const arr = p.val; if (!Array.isArray(arr)) return { error: "Input must be a JSON array." }; if (!arr.length) return ""; const delim = v.delim || ","; const keys = []; arr.forEach((row) => { if (row && typeof row === "object" && !Array.isArray(row)) Object.keys(row).forEach((k) => { if (keys.indexOf(k) < 0) keys.push(k); }); }); if (!keys.length) return { error: "Array items must be objects." }; const lines = [keys.map((k) => csvField(k, delim)).join(delim)]; arr.forEach((row) => { lines.push(keys.map((k) => { let val = row ? row[k] : undefined; if (val === undefined || val === null) val = ""; else if (typeof val === "object") val = JSON.stringify(val); return csvField(val, delim); }).join(delim)); }); return lines.join("\n"); } },

  { id: "df-csv-to-json", name: "CSV → JSON", cat: "data", desc: "Parse CSV (header row = keys) into a JSON array of objects.", tags: ["csv", "json"],
    inputs: [{ k: "csv", label: "CSV", type: "textarea", rows: 8, placeholder: "a,b\n1,2" }, { k: "delim", label: "Delimiter", type: "text", value: "," }],
    run(v) { if (!v.csv) return ""; const delim = v.delim || ","; const rows = cleanRows(parseCSV(v.csv, delim)); if (!rows.length) return { error: "No data rows found." }; const header = rows[0]; const out = rows.slice(1).map((r) => { const o = {}; header.forEach((h, i) => { o[h || "col" + i] = r[i] !== undefined ? r[i] : ""; }); return o; }); return JSON.stringify(out, null, 2); } },

  { id: "df-json-path", name: "JSON Path Get", cat: "data", desc: "Read a value from JSON via a dot/bracket path like a.b[0].c.", tags: ["json", "path", "get"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 7 }, { k: "path", label: "Path", type: "text", placeholder: "a.b[0].c" }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; if (!v.path) return { error: "Enter a path." }; const r = getPath(p.val, v.path.trim()); if (r === undefined) return { error: "No value at path: " + v.path }; return typeof r === "object" ? JSON.stringify(r, null, 2) : String(r); } },

  { id: "df-json-diff", name: "JSON Diff", cat: "data", desc: "Compare two JSON values and report added, removed and changed leaves.", tags: ["json", "diff", "compare"],
    inputs: [{ k: "a", label: "JSON A", type: "textarea", rows: 6 }, { k: "b", label: "JSON B", type: "textarea", rows: 6 }],
    run(v) { if (!(v.a && v.a.trim()) || !(v.b && v.b.trim())) return ""; const pa = pj(v.a); if (!pa.ok) return { error: "Invalid JSON A: " + pa.err }; const pb = pj(v.b); if (!pb.ok) return { error: "Invalid JSON B: " + pb.err }; const fa = flatten(pa.val, "", {}), fb = flatten(pb.val, "", {}); const added = {}, removed = {}, changed = {}; Object.keys(fb).forEach((k) => { if (!(k in fa)) added[k] = fb[k]; else if (JSON.stringify(fa[k]) !== JSON.stringify(fb[k])) changed[k] = { from: fa[k], to: fb[k] }; }); Object.keys(fa).forEach((k) => { if (!(k in fb)) removed[k] = fa[k]; }); return JSON.stringify({ added: added, removed: removed, changed: changed }, null, 2); } },

  { id: "df-json-to-yaml", name: "JSON → YAML", cat: "data", desc: "Convert JSON into YAML (objects, arrays and scalars).", tags: ["json", "yaml"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8 }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; return dumpYaml(p.val, 0); } },

  { id: "df-yaml-to-json", name: "YAML → JSON", cat: "data", desc: "Parse a practical subset of YAML (mappings, sequences, nesting) into JSON.", tags: ["yaml", "json"],
    inputs: [{ k: "yaml", label: "YAML", type: "textarea", rows: 8, placeholder: "name: test\nlist:\n  - a\n  - b" }, { k: "indent", label: "Indent", type: "select", opts: ["2 spaces", "4 spaces", "Tab"], value: "2 spaces" }],
    run(v) { if (!v.yaml || !v.yaml.trim()) return ""; try { const val = parseYaml(v.yaml); return JSON.stringify(val, null, indentOf(v.indent)); } catch (e) { return { error: "Invalid YAML: " + e.message }; } } },

  { id: "df-json-to-xml", name: "JSON → XML", cat: "data", desc: "Convert a JSON value into simple nested XML.", tags: ["json", "xml"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8, placeholder: '{"user":{"id":1,"name":"a"}}' }, { k: "root", label: "Root tag", type: "text", value: "root" }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; const root = (v.root || "root").trim() || "root"; let inner; if (Array.isArray(p.val)) inner = p.val.map((x) => xmlNode(x, "item")).join(""); else if (p.val !== null && typeof p.val === "object") inner = Object.keys(p.val).map((k) => xmlNode(p.val[k], k)).join(""); else inner = xmlEscape(p.val); return `<?xml version="1.0" encoding="UTF-8"?>\n<${root}>${inner}</${root}>`; } },

  { id: "df-xml-to-json", name: "XML → JSON", cat: "data", desc: "Parse simple element/text XML into JSON (repeated tags become arrays).", tags: ["xml", "json"],
    inputs: [{ k: "xml", label: "XML", type: "textarea", rows: 8, placeholder: "<root><id>1</id><name>a</name></root>" }],
    run(v) { if (!v.xml || !v.xml.trim()) return ""; try { const nodes = parseXml(v.xml); const root = nodes.filter((n) => n.name)[0]; if (!root) return { error: "No XML element found." }; const obj = {}; obj[root.name] = elemValue(root); return JSON.stringify(obj, null, 2); } catch (e) { return { error: "Invalid XML: " + e.message }; } } },

  { id: "df-json-to-toml", name: "JSON → TOML", cat: "data", desc: "Convert JSON into TOML with tables and arrays of tables.", tags: ["json", "toml", "config"],
    inputs: [{ k: "json", label: "JSON object", type: "textarea", rows: 8, placeholder: '{"title":"x","db":{"port":5432}}' }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; if (p.val === null || typeof p.val !== "object" || Array.isArray(p.val)) return { error: "Input must be a JSON object." }; return tomlSection(p.val, "").trim(); } },

  { id: "df-json-to-go", name: "JSON → Go Struct", cat: "data", desc: "Generate Go struct definitions from a JSON sample.", tags: ["json", "go", "struct"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8, placeholder: '{"id":1,"name":"a"}' }, { k: "name", label: "Root name", type: "text", value: "AutoGenerated" }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; const structs = []; const t = goType(p.val, v.name || "AutoGenerated", structs); if (!structs.length) return "// root type: " + t; return structs.reverse().join("\n\n"); } },

  { id: "df-json-to-ts", name: "JSON → TypeScript Interface", cat: "data", desc: "Generate TypeScript interfaces from a JSON sample.", tags: ["json", "typescript", "interface"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8, placeholder: '{"id":1,"name":"a"}' }, { k: "name", label: "Root name", type: "text", value: "Root" }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; const out = []; const t = tsType(p.val, v.name || "Root", out); if (!out.length) return "type " + pascal(v.name || "Root") + " = " + t + ";"; return out.reverse().join("\n\n"); } },

  { id: "df-json-to-env", name: "JSON → .env", cat: "data", desc: "Convert a flat JSON object into .env KEY=VALUE lines.", tags: ["json", "env", "dotenv"],
    inputs: [{ k: "json", label: "JSON object", type: "textarea", rows: 8, placeholder: '{"PORT":3000,"NAME":"app"}' }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; if (p.val === null || typeof p.val !== "object" || Array.isArray(p.val)) return { error: "Input must be a JSON object." }; return Object.keys(p.val).map((k) => { let val = p.val[k]; if (val === null || val === undefined) val = ""; else if (typeof val === "object") val = JSON.stringify(val); const s = String(val); return k + "=" + (/[\s"#]/.test(s) ? '"' + s.replace(/"/g, '\\"') + '"' : s); }).join("\n"); } },

  { id: "df-env-to-json", name: ".env → JSON", cat: "data", desc: "Parse .env lines (KEY=VALUE, export, quotes, comments) into JSON.", tags: ["env", "dotenv", "json"],
    inputs: [{ k: "env", label: ".env", type: "textarea", rows: 8, placeholder: "PORT=3000\nNAME=\"my app\"" }],
    run(v) { if (!v.env || !v.env.trim()) return ""; return JSON.stringify(parseEnv(v.env), null, 2); } },

  { id: "df-ini-to-json", name: "INI → JSON", cat: "data", desc: "Parse an INI file with [sections] into nested JSON.", tags: ["ini", "json", "config"],
    inputs: [{ k: "ini", label: "INI", type: "textarea", rows: 8, placeholder: "[server]\nport=8080" }],
    run(v) { if (!v.ini || !v.ini.trim()) return ""; const root = {}; let section = root; v.ini.split(/\r?\n/).forEach((line) => { let l = line.trim(); if (!l || l.startsWith(";") || l.startsWith("#")) return; const sm = l.match(/^\[(.+)\]$/); if (sm) { section = {}; root[sm[1].trim()] = section; return; } const i = l.indexOf("="); if (i < 0) return; section[l.slice(0, i).trim()] = coerce(l.slice(i + 1).trim()); }); return JSON.stringify(root, null, 2); } },

  { id: "df-json-to-ini", name: "JSON → INI", cat: "data", desc: "Convert a JSON object into INI, nested objects become [sections].", tags: ["json", "ini", "config"],
    inputs: [{ k: "json", label: "JSON object", type: "textarea", rows: 8, placeholder: '{"port":80,"db":{"host":"x"}}' }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; const obj = p.val; if (obj === null || typeof obj !== "object" || Array.isArray(obj)) return { error: "Input must be a JSON object." }; const iniScalar = (x) => (x === null || x === undefined ? "" : typeof x === "object" ? JSON.stringify(x) : String(x)); let top = "", sections = ""; Object.keys(obj).forEach((k) => { const val = obj[k]; if (val !== null && typeof val === "object" && !Array.isArray(val)) { sections += "\n[" + k + "]\n"; Object.keys(val).forEach((kk) => { sections += kk + "=" + iniScalar(val[kk]) + "\n"; }); } else top += k + "=" + iniScalar(val) + "\n"; }); return (top + sections).trim(); } },

  { id: "df-props-to-json", name: ".properties → JSON", cat: "data", desc: "Parse Java .properties (key=value or key:value) into a flat JSON object.", tags: ["properties", "json", "java"],
    inputs: [{ k: "props", label: ".properties", type: "textarea", rows: 8, placeholder: "app.name=demo\napp.port: 8080" }],
    run(v) { if (!v.props || !v.props.trim()) return ""; const o = {}; v.props.split(/\r?\n/).forEach((line) => { const l = line.trim(); if (!l || l.startsWith("#") || l.startsWith("!")) return; const m = l.match(/^([^=:\s]+)\s*[=:]\s*(.*)$/); if (m) { o[m[1]] = m[2]; return; } const sp = l.search(/\s/); if (sp > 0) o[l.slice(0, sp)] = l.slice(sp + 1).trim(); }); return JSON.stringify(o, null, 2); } },

  { id: "df-csv-align", name: "CSV Format / Align", cat: "data", desc: "Pad CSV columns to equal width for readable, aligned output.", tags: ["csv", "align", "format"],
    inputs: [{ k: "csv", label: "CSV", type: "textarea", rows: 8 }, { k: "delim", label: "Delimiter", type: "text", value: "," }],
    run(v) { if (!v.csv) return ""; const delim = v.delim || ","; const rows = cleanRows(parseCSV(v.csv, delim)); if (!rows.length) return { error: "No data found." }; const widths = []; rows.forEach((r) => r.forEach((c, i) => { widths[i] = Math.max(widths[i] || 0, S(c).length); })); return rows.map((r) => r.map((c, i) => S(c).padEnd(widths[i])).join(delim + " ").replace(/\s+$/, "")).join("\n"); } },

  { id: "df-csv-to-md", name: "CSV → Markdown Table", cat: "data", desc: "Render CSV as a Markdown table.", tags: ["csv", "markdown", "table"],
    inputs: [{ k: "csv", label: "CSV", type: "textarea", rows: 8 }, { k: "delim", label: "Delimiter", type: "text", value: "," }],
    run(v) { if (!v.csv) return ""; const delim = v.delim || ","; const rows = cleanRows(parseCSV(v.csv, delim)); if (!rows.length) return { error: "No data found." }; const esc = (s) => S(s).replace(/\|/g, "\\|"); const header = rows[0]; const lines = ["| " + header.map(esc).join(" | ") + " |", "| " + header.map(() => "---").join(" | ") + " |"]; rows.slice(1).forEach((r) => lines.push("| " + header.map((_, i) => esc(r[i] !== undefined ? r[i] : "")).join(" | ") + " |")); return lines.join("\n"); } },

  { id: "df-csv-to-html", name: "CSV → HTML Table", cat: "data", desc: "Render CSV as an HTML <table> with a header row.", tags: ["csv", "html", "table"],
    inputs: [{ k: "csv", label: "CSV", type: "textarea", rows: 8 }, { k: "delim", label: "Delimiter", type: "text", value: "," }],
    run(v, H) { if (!v.csv) return ""; const delim = v.delim || ","; const rows = cleanRows(parseCSV(v.csv, delim)); if (!rows.length) return { error: "No data found." }; const esc = H && H.escapeHtml ? H.escapeHtml : (s) => S(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); const head = "  <thead>\n    <tr>" + rows[0].map((c) => "<th>" + esc(c) + "</th>").join("") + "</tr>\n  </thead>"; const body = "  <tbody>\n" + rows.slice(1).map((r) => "    <tr>" + rows[0].map((_, i) => "<td>" + esc(r[i] !== undefined ? r[i] : "") + "</td>").join("") + "</tr>").join("\n") + "\n  </tbody>"; return "<table>\n" + head + "\n" + body + "\n</table>"; } },

  { id: "df-md-to-csv", name: "Markdown Table → CSV", cat: "data", desc: "Extract a Markdown table's cells into CSV.", tags: ["markdown", "csv", "table"],
    inputs: [{ k: "md", label: "Markdown table", type: "textarea", rows: 8, placeholder: "| a | b |\n| --- | --- |\n| 1 | 2 |" }, { k: "delim", label: "Delimiter", type: "text", value: "," }],
    run(v) { if (!v.md) return ""; const isSep = (l) => /^[\s|:-]+$/.test(l) && l.indexOf("-") >= 0; const lines = v.md.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.indexOf("|") >= 0 && !isSep(l)); if (!lines.length) return { error: "No Markdown table rows found." }; const delim = v.delim || ","; const rows = lines.map((l) => l.replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim().replace(/\\\|/g, "|"))); return serializeCSV(rows, delim); } },

  { id: "df-csv-transpose", name: "CSV Transpose", cat: "data", desc: "Swap rows and columns of a CSV.", tags: ["csv", "transpose", "pivot"],
    inputs: [{ k: "csv", label: "CSV", type: "textarea", rows: 8 }, { k: "delim", label: "Delimiter", type: "text", value: "," }],
    run(v) { if (!v.csv) return ""; const delim = v.delim || ","; const rows = cleanRows(parseCSV(v.csv, delim)); if (!rows.length) return { error: "No data found." }; const cols = Math.max.apply(null, rows.map((r) => r.length)); const out = []; for (let c = 0; c < cols; c++) out.push(rows.map((r) => r[c] !== undefined ? r[c] : "")); return serializeCSV(out, delim); } },

  { id: "df-csv-dedupe", name: "CSV Dedupe Rows", cat: "data", desc: "Remove duplicate rows, keeping the first occurrence.", tags: ["csv", "dedupe", "unique"],
    inputs: [{ k: "csv", label: "CSV", type: "textarea", rows: 8 }, { k: "delim", label: "Delimiter", type: "text", value: "," }, { k: "header", label: "Keep header row", type: "checkbox", value: true }],
    run(v) { if (!v.csv) return ""; const delim = v.delim || ","; const rows = cleanRows(parseCSV(v.csv, delim)); if (!rows.length) return { error: "No data found." }; const head = v.header ? rows.slice(0, 1) : []; const body = v.header ? rows.slice(1) : rows; const seen = {}; const out = body.filter((r) => { const key = JSON.stringify(r); if (seen[key]) return false; seen[key] = 1; return true; }); return serializeCSV(head.concat(out), delim); } },

  { id: "df-csv-sort", name: "CSV Sort by Column", cat: "data", desc: "Sort CSV data rows by a column (name or index), keeping the header.", tags: ["csv", "sort", "order"],
    inputs: [{ k: "csv", label: "CSV", type: "textarea", rows: 8 }, { k: "col", label: "Column (name or index)", type: "text", placeholder: "0" }, { k: "delim", label: "Delimiter", type: "text", value: "," }, { k: "numeric", label: "Numeric", type: "checkbox", value: false }, { k: "desc", label: "Descending", type: "checkbox", value: false }],
    run(v) { if (!v.csv) return ""; const delim = v.delim || ","; const rows = cleanRows(parseCSV(v.csv, delim)); if (rows.length < 2) return v.csv.trim(); const header = rows[0]; let ci = header.indexOf(v.col); if (ci < 0 && /^\d+$/.test(S(v.col).trim())) ci = parseInt(v.col, 10); if (ci < 0 || ci >= header.length) return { error: "Column not found: " + v.col }; const body = rows.slice(1).slice(); body.sort((a, b) => { let x = a[ci] !== undefined ? a[ci] : "", y = b[ci] !== undefined ? b[ci] : ""; if (v.numeric) { x = parseFloat(x) || 0; y = parseFloat(y) || 0; return x - y; } return String(x) < String(y) ? -1 : String(x) > String(y) ? 1 : 0; }); if (v.desc) body.reverse(); return serializeCSV([header].concat(body), delim); } },

  { id: "df-csv-select", name: "CSV Select Columns", cat: "data", desc: "Keep only the listed columns (by name or index).", tags: ["csv", "columns", "project"],
    inputs: [{ k: "csv", label: "CSV", type: "textarea", rows: 8 }, { k: "cols", label: "Columns (comma list)", type: "text", placeholder: "name,age or 0,2" }, { k: "delim", label: "Delimiter", type: "text", value: "," }],
    run(v) { if (!v.csv) return ""; if (!v.cols || !v.cols.trim()) return { error: "List the columns to keep." }; const delim = v.delim || ","; const rows = cleanRows(parseCSV(v.csv, delim)); if (!rows.length) return { error: "No data found." }; const header = rows[0]; const idxs = v.cols.split(",").map((c) => c.trim()).map((c) => { let i = header.indexOf(c); if (i < 0 && /^\d+$/.test(c)) i = parseInt(c, 10); return i; }); if (idxs.some((i) => i < 0)) return { error: "One or more columns not found." }; return rows.map((r) => idxs.map((i) => r[i] !== undefined ? r[i] : "")).map((r) => r.map((c) => csvField(c, delim)).join(delim)).join("\n"); } },

  { id: "df-csv-filter", name: "CSV Filter Rows", cat: "data", desc: "Keep rows where a column contains a value (header preserved).", tags: ["csv", "filter", "where"],
    inputs: [{ k: "csv", label: "CSV", type: "textarea", rows: 8 }, { k: "col", label: "Column (name or index)", type: "text", placeholder: "status" }, { k: "val", label: "Contains", type: "text", placeholder: "active" }, { k: "delim", label: "Delimiter", type: "text", value: "," }, { k: "ci", label: "Case-insensitive", type: "checkbox", value: true }],
    run(v) { if (!v.csv) return ""; const delim = v.delim || ","; const rows = cleanRows(parseCSV(v.csv, delim)); if (rows.length < 2) return v.csv.trim(); const header = rows[0]; let ci = header.indexOf(v.col); if (ci < 0 && /^\d+$/.test(S(v.col).trim())) ci = parseInt(v.col, 10); if (ci < 0 || ci >= header.length) return { error: "Column not found: " + v.col }; let needle = S(v.val); if (v.ci) needle = needle.toLowerCase(); const body = rows.slice(1).filter((r) => { let cell = S(r[ci]); if (v.ci) cell = cell.toLowerCase(); return cell.indexOf(needle) >= 0; }); return serializeCSV([header].concat(body), delim); } },

  { id: "df-csv-count", name: "CSV Count Rows / Columns", cat: "data", desc: "Report the number of data rows and columns in a CSV.", tags: ["csv", "count", "stats"],
    inputs: [{ k: "csv", label: "CSV", type: "textarea", rows: 8 }, { k: "delim", label: "Delimiter", type: "text", value: "," }, { k: "header", label: "First row is header", type: "checkbox", value: true }],
    run(v) { if (!v.csv) return ""; const delim = v.delim || ","; const rows = cleanRows(parseCSV(v.csv, delim)); if (!rows.length) return "Rows: 0\nColumns: 0"; const cols = Math.max.apply(null, rows.map((r) => r.length)); const dataRows = v.header ? rows.length - 1 : rows.length; return "Total lines: " + rows.length + "\nData rows: " + Math.max(dataRows, 0) + "\nColumns: " + cols; } },

  { id: "df-csv-add-header", name: "CSV Add Header", cat: "data", desc: "Prepend a header row (given, or auto col1,col2,...) to a CSV.", tags: ["csv", "header"],
    inputs: [{ k: "csv", label: "CSV (no header)", type: "textarea", rows: 8 }, { k: "header", label: "Header (comma list, blank = auto)", type: "text", placeholder: "id,name,age" }, { k: "delim", label: "Delimiter", type: "text", value: "," }],
    run(v) { if (!v.csv) return ""; const delim = v.delim || ","; const rows = cleanRows(parseCSV(v.csv, delim)); if (!rows.length) return { error: "No data found." }; const cols = Math.max.apply(null, rows.map((r) => r.length)); let header; if (v.header && v.header.trim()) header = v.header.split(",").map((c) => c.trim()); else { header = []; for (let i = 1; i <= cols; i++) header.push("col" + i); } return serializeCSV([header].concat(rows), delim); } },

  { id: "df-tsv-to-csv", name: "TSV → CSV", cat: "data", desc: "Convert tab-separated values into comma-separated values.", tags: ["tsv", "csv", "tab"],
    inputs: [{ k: "tsv", label: "TSV", type: "textarea", rows: 8, placeholder: "a\tb\n1\t2" }],
    run(v) { if (!v.tsv) return ""; const rows = cleanRows(parseCSV(v.tsv, "\t")); if (!rows.length) return { error: "No data found." }; return serializeCSV(rows, ","); } },

  { id: "df-csv-to-tsv", name: "CSV → TSV", cat: "data", desc: "Convert comma-separated values into tab-separated values.", tags: ["csv", "tsv", "tab"],
    inputs: [{ k: "csv", label: "CSV", type: "textarea", rows: 8, placeholder: "a,b\n1,2" }],
    run(v) { if (!v.csv) return ""; const rows = cleanRows(parseCSV(v.csv, ",")); if (!rows.length) return { error: "No data found." }; return rows.map((r) => r.map((c) => S(c).replace(/\t/g, " ")).join("\t")).join("\n"); } },

  { id: "df-ndjson-to-json", name: "NDJSON → JSON Array", cat: "data", desc: "Combine newline-delimited JSON objects into one JSON array.", tags: ["ndjson", "jsonl", "json"],
    inputs: [{ k: "nd", label: "NDJSON", type: "textarea", rows: 8, placeholder: '{"a":1}\n{"a":2}' }],
    run(v) { if (!v.nd || !v.nd.trim()) return ""; const out = []; const lines = v.nd.split(/\r?\n/); for (let i = 0; i < lines.length; i++) { const l = lines[i].trim(); if (!l) continue; const p = pj(l); if (!p.ok) return { error: "Invalid JSON on line " + (i + 1) + ": " + p.err }; out.push(p.val); } return JSON.stringify(out, null, 2); } },

  { id: "df-json-to-ndjson", name: "JSON Array → NDJSON", cat: "data", desc: "Emit each item of a JSON array as one line (newline-delimited JSON).", tags: ["json", "ndjson", "jsonl"],
    inputs: [{ k: "json", label: "JSON array", type: "textarea", rows: 8, placeholder: '[{"a":1},{"a":2}]' }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; if (!Array.isArray(p.val)) return { error: "Input must be a JSON array." }; return p.val.map((x) => JSON.stringify(x)).join("\n"); } },

  { id: "df-json-to-base64", name: "JSON → Base64", cat: "data", desc: "Minify JSON and encode it as Base64.", tags: ["json", "base64", "encode"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8 }],
    run(v, H) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; return H.b64encode(JSON.stringify(p.val)); } },

  { id: "df-base64-to-json", name: "Base64 → JSON", cat: "data", desc: "Decode Base64 and pretty-print the JSON inside.", tags: ["base64", "json", "decode"],
    inputs: [{ k: "b64", label: "Base64", type: "textarea", rows: 8 }, { k: "indent", label: "Indent", type: "select", opts: ["2 spaces", "4 spaces", "Tab"], value: "2 spaces" }],
    run(v, H) { if (!v.b64 || !v.b64.trim()) return ""; let decoded; try { decoded = H.b64decode(v.b64.trim()); } catch (e) { return { error: "Invalid Base64: " + e.message }; } const p = pj(decoded); if (!p.ok) return { error: "Decoded text is not JSON: " + p.err }; return JSON.stringify(p.val, null, indentOf(v.indent)); } },

  { id: "df-json-count-keys", name: "JSON Count Keys", cat: "data", desc: "Count keys at the top level and across all nested objects.", tags: ["json", "count", "keys"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8 }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; const top = p.val && typeof p.val === "object" && !Array.isArray(p.val) ? Object.keys(p.val).length : 0; return "Top-level keys: " + top + "\nTotal keys (deep): " + countKeysDeep(p.val); } },

  { id: "df-json-pick", name: "JSON Pick Keys", cat: "data", desc: "Keep only the listed top-level keys of a JSON object.", tags: ["json", "pick", "select"],
    inputs: [{ k: "json", label: "JSON object", type: "textarea", rows: 8 }, { k: "keys", label: "Keys (comma list)", type: "text", placeholder: "id,name" }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; if (p.val === null || typeof p.val !== "object" || Array.isArray(p.val)) return { error: "Input must be a JSON object." }; const keys = (v.keys || "").split(",").map((k) => k.trim()).filter(Boolean); const o = {}; keys.forEach((k) => { if (k in p.val) o[k] = p.val[k]; }); return JSON.stringify(o, null, 2); } },

  { id: "df-json-omit", name: "JSON Omit Keys", cat: "data", desc: "Remove the listed top-level keys from a JSON object.", tags: ["json", "omit", "remove"],
    inputs: [{ k: "json", label: "JSON object", type: "textarea", rows: 8 }, { k: "keys", label: "Keys (comma list)", type: "text", placeholder: "password,token" }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; if (p.val === null || typeof p.val !== "object" || Array.isArray(p.val)) return { error: "Input must be a JSON object." }; const drop = (v.keys || "").split(",").map((k) => k.trim()).filter(Boolean); const o = {}; Object.keys(p.val).forEach((k) => { if (drop.indexOf(k) < 0) o[k] = p.val[k]; }); return JSON.stringify(o, null, 2); } },

  { id: "df-json-rename-key", name: "JSON Rename Key", cat: "data", desc: "Rename a top-level key in a JSON object, keeping order where possible.", tags: ["json", "rename", "key"],
    inputs: [{ k: "json", label: "JSON object", type: "textarea", rows: 8 }, { k: "from", label: "From key", type: "text", placeholder: "old" }, { k: "to", label: "To key", type: "text", placeholder: "new" }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; if (p.val === null || typeof p.val !== "object" || Array.isArray(p.val)) return { error: "Input must be a JSON object." }; if (!v.from) return { error: "Enter the key to rename." }; if (!(v.from in p.val)) return { error: "Key not found: " + v.from }; const to = v.to || v.from; const o = {}; Object.keys(p.val).forEach((k) => { o[k === v.from ? to : k] = p.val[k]; }); return JSON.stringify(o, null, 2); } },

  { id: "df-commalist-to-json", name: "Comma List → JSON Array", cat: "data", desc: "Split a comma-separated list into a JSON array (numbers/bools auto-typed).", tags: ["array", "json", "list"],
    inputs: [{ k: "list", label: "Comma list", type: "textarea", rows: 5, placeholder: "1, two, true, 3.5" }, { k: "typed", label: "Auto-type values", type: "checkbox", value: true }, { k: "trim", label: "Trim items", type: "checkbox", value: true }],
    run(v) { if (!v.list || !v.list.trim()) return ""; let items = v.list.split(","); if (v.trim) items = items.map((s) => s.trim()); items = items.filter((s) => s !== ""); if (v.typed) items = items.map(coerce); return JSON.stringify(items); } },

  { id: "df-json-flatten-array", name: "JSON Array Flatten", cat: "data", desc: "Deep-flatten nested arrays into a single flat JSON array.", tags: ["json", "array", "flatten"],
    inputs: [{ k: "json", label: "JSON array", type: "textarea", rows: 8, placeholder: "[1,[2,[3,4]],5]" }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; if (!Array.isArray(p.val)) return { error: "Input must be a JSON array." }; const out = []; const walk = (a) => a.forEach((x) => { if (Array.isArray(x)) walk(x); else out.push(x); }); walk(p.val); return JSON.stringify(out); } },

  { id: "df-json-group-by", name: "JSON Group-By Key", cat: "data", desc: "Group a JSON array of objects into buckets keyed by a field.", tags: ["json", "group", "aggregate"],
    inputs: [{ k: "json", label: "JSON array", type: "textarea", rows: 8, placeholder: '[{"type":"a"},{"type":"b"}]' }, { k: "key", label: "Group by key", type: "text", placeholder: "type" }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; if (!Array.isArray(p.val)) return { error: "Input must be a JSON array." }; if (!v.key) return { error: "Enter the key to group by." }; const out = {}; p.val.forEach((item) => { const k = item && typeof item === "object" ? String(item[v.key]) : "undefined"; (out[k] = out[k] || []).push(item); }); return JSON.stringify(out, null, 2); } },

  { id: "df-json-unique-by", name: "JSON Unique By Key", cat: "data", desc: "Deduplicate a JSON array of objects by a key, keeping the first.", tags: ["json", "unique", "dedupe"],
    inputs: [{ k: "json", label: "JSON array", type: "textarea", rows: 8, placeholder: '[{"id":1},{"id":1},{"id":2}]' }, { k: "key", label: "Key", type: "text", placeholder: "id" }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; if (!Array.isArray(p.val)) return { error: "Input must be a JSON array." }; if (!v.key) return { error: "Enter the dedupe key." }; const seen = {}; const out = p.val.filter((item) => { const k = item && typeof item === "object" ? JSON.stringify(item[v.key]) : JSON.stringify(item); if (seen[k]) return false; seen[k] = 1; return true; }); return JSON.stringify(out, null, 2); } },

  { id: "df-csv-to-json-typed", name: "CSV → JSON (typed)", cat: "data", desc: "CSV to JSON, coercing numbers, booleans and null in each cell.", tags: ["csv", "json", "typed"],
    inputs: [{ k: "csv", label: "CSV", type: "textarea", rows: 8, placeholder: "id,active\n1,true" }, { k: "delim", label: "Delimiter", type: "text", value: "," }],
    run(v) { if (!v.csv) return ""; const delim = v.delim || ","; const rows = cleanRows(parseCSV(v.csv, delim)); if (!rows.length) return { error: "No data found." }; const header = rows[0]; const out = rows.slice(1).map((r) => { const o = {}; header.forEach((h, i) => { o[h || "col" + i] = coerce(r[i] !== undefined ? r[i] : ""); }); return o; }); return JSON.stringify(out, null, 2); } },

  { id: "df-xml-pretty", name: "Pretty XML", cat: "data", desc: "Reformat XML with indentation.", tags: ["xml", "pretty", "format"],
    inputs: [{ k: "xml", label: "XML", type: "textarea", rows: 8 }, { k: "indent", label: "Indent", type: "select", opts: ["2 spaces", "4 spaces", "Tab"], value: "2 spaces" }],
    run(v) { if (!v.xml || !v.xml.trim()) return ""; const unit = v.indent === "Tab" ? "\t" : v.indent === "4 spaces" ? "    " : "  "; try { return prettyXml(v.xml, unit); } catch (e) { return { error: "Could not format XML: " + e.message }; } } },

  { id: "df-xml-minify", name: "Minify XML", cat: "data", desc: "Strip whitespace between XML tags and remove comments.", tags: ["xml", "minify", "compact"],
    inputs: [{ k: "xml", label: "XML", type: "textarea", rows: 8 }],
    run(v) { if (!v.xml || !v.xml.trim()) return ""; return v.xml.replace(/<!--[\s\S]*?-->/g, "").replace(/>\s+</g, "><").replace(/\s+/g, " ").replace(/> </g, "><").trim(); } },

  { id: "df-html-table-to-json", name: "HTML Table → JSON", cat: "data", desc: "Parse the first HTML <table> into a JSON array of objects.", tags: ["html", "table", "json"],
    inputs: [{ k: "html", label: "HTML table", type: "textarea", rows: 8, placeholder: "<table><tr><th>a</th></tr><tr><td>1</td></tr></table>" }],
    run(v) { if (!v.html || !v.html.trim()) return ""; const strip = (s) => s.replace(/<[^>]+>/g, "").replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").trim(); const rows = []; const trRe = /<tr[^>]*>([\s\S]*?)<\/tr>/gi; let m; while ((m = trRe.exec(v.html))) { const cells = []; const cellRe = /<t[hd][^>]*>([\s\S]*?)<\/t[hd]>/gi; let c; while ((c = cellRe.exec(m[1]))) cells.push(strip(c[1])); if (cells.length) rows.push(cells); } if (!rows.length) return { error: "No table rows found." }; const header = rows[0]; const out = rows.slice(1).map((r) => { const o = {}; header.forEach((h, i) => { o[h || "col" + i] = r[i] !== undefined ? r[i] : ""; }); return o; }); return JSON.stringify(out, null, 2); } },

  { id: "df-lines-to-json", name: "Lines → JSON Array", cat: "data", desc: "Turn each non-empty line into a JSON string array element.", tags: ["lines", "json", "array"],
    inputs: [{ k: "text", label: "Lines", type: "textarea", rows: 8, placeholder: "apple\nbanana" }, { k: "trim", label: "Trim lines", type: "checkbox", value: true }, { k: "skipEmpty", label: "Skip empty", type: "checkbox", value: true }],
    run(v) { if (!v.text) return ""; let lines = v.text.split(/\r?\n/); if (v.trim) lines = lines.map((l) => l.trim()); if (v.skipEmpty) lines = lines.filter((l) => l !== ""); return JSON.stringify(lines, null, 2); } },

  { id: "df-kv-lines-to-json", name: "Key=Value Lines → JSON", cat: "data", desc: "Parse lines of key=value or key: value into a JSON object.", tags: ["keyvalue", "json", "config"],
    inputs: [{ k: "text", label: "Lines", type: "textarea", rows: 8, placeholder: "host = localhost\nport: 8080" }, { k: "typed", label: "Auto-type values", type: "checkbox", value: true }],
    run(v) { if (!v.text || !v.text.trim()) return ""; const o = {}; v.text.split(/\r?\n/).forEach((line) => { const l = line.trim(); if (!l || l.startsWith("#") || l.startsWith(";")) return; const m = l.match(/^([^=:]+)[=:](.*)$/); if (!m) return; const k = m[1].trim(); const raw = m[2].trim(); o[k] = v.typed ? coerce(raw) : raw; }); return JSON.stringify(o, null, 2); } },

  { id: "df-json-to-bracket-qs", name: "JSON → Query Params (bracket)", cat: "data", desc: "Serialize nested JSON to bracket-notation query params like a[b][0]=1.", tags: ["json", "querystring", "bracket"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8, placeholder: '{"a":{"b":1},"c":[1,2]}' }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; if (p.val === null || typeof p.val !== "object") return { error: "Input must be a JSON object or array." }; return toBracket(p.val, "", []).join("&"); } },

  { id: "df-json-to-flat-csv", name: "Flatten JSON → CSV", cat: "data", desc: "Flatten each object in a JSON array to dotted paths, then output CSV.", tags: ["json", "csv", "flatten"],
    inputs: [{ k: "json", label: "JSON array", type: "textarea", rows: 8, placeholder: '[{"a":{"b":1}},{"a":{"b":2}}]' }, { k: "delim", label: "Delimiter", type: "text", value: "," }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; if (!Array.isArray(p.val)) return { error: "Input must be a JSON array." }; if (!p.val.length) return ""; const delim = v.delim || ","; const flats = p.val.map((x) => flatten(x, "", {})); const keys = []; flats.forEach((f) => Object.keys(f).forEach((k) => { if (keys.indexOf(k) < 0) keys.push(k); })); const lines = [keys.map((k) => csvField(k, delim)).join(delim)]; flats.forEach((f) => lines.push(keys.map((k) => { let val = f[k]; if (val === undefined || val === null) val = ""; else if (typeof val === "object") val = JSON.stringify(val); return csvField(val, delim); }).join(delim))); return lines.join("\n"); } },

  { id: "df-json-schema", name: "JSON Schema (infer)", cat: "data", desc: "Infer a basic JSON Schema (types, properties, items) from a sample.", tags: ["json", "schema", "infer"],
    inputs: [{ k: "json", label: "JSON sample", type: "textarea", rows: 8 }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; const infer = (val) => { const t = typeOf(val); if (t === "object") { const props = {}; Object.keys(val).forEach((k) => { props[k] = infer(val[k]); }); return { type: "object", properties: props }; } if (t === "array") return { type: "array", items: val.length ? infer(val[0]) : {} }; if (t === "number") return { type: Number.isInteger(val) ? "integer" : "number" }; return { type: t }; }; return JSON.stringify(Object.assign({ $schema: "http://json-schema.org/schema#" }, infer(p.val)), null, 2); } },

  { id: "df-json-stats", name: "JSON Stats", cat: "data", desc: "Count objects, arrays, strings, numbers, booleans and nulls in JSON.", tags: ["json", "stats", "count"],
    inputs: [{ k: "json", label: "JSON", type: "textarea", rows: 8 }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; const acc = { objects: 0, arrays: 0, strings: 0, numbers: 0, booleans: 0, nulls: 0 }; const walk = (val) => { const t = typeOf(val); if (t === "object") { acc.objects++; Object.keys(val).forEach((k) => walk(val[k])); } else if (t === "array") { acc.arrays++; val.forEach(walk); } else if (t === "string") acc.strings++; else if (t === "number") acc.numbers++; else if (t === "boolean") acc.booleans++; else if (t === "null") acc.nulls++; }; walk(p.val); return JSON.stringify(acc, null, 2); } },

  { id: "df-json-to-md-table", name: "JSON Array → Markdown Table", cat: "data", desc: "Render a JSON array of objects as a Markdown table.", tags: ["json", "markdown", "table"],
    inputs: [{ k: "json", label: "JSON array", type: "textarea", rows: 8, placeholder: '[{"id":1,"name":"a"}]' }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; if (!Array.isArray(p.val)) return { error: "Input must be a JSON array." }; if (!p.val.length) return ""; const keys = []; p.val.forEach((row) => { if (row && typeof row === "object" && !Array.isArray(row)) Object.keys(row).forEach((k) => { if (keys.indexOf(k) < 0) keys.push(k); }); }); if (!keys.length) return { error: "Array items must be objects." }; const esc = (s) => S(s).replace(/\|/g, "\\|"); const lines = ["| " + keys.map(esc).join(" | ") + " |", "| " + keys.map(() => "---").join(" | ") + " |"]; p.val.forEach((row) => { lines.push("| " + keys.map((k) => { let val = row ? row[k] : undefined; if (val === undefined || val === null) val = ""; else if (typeof val === "object") val = JSON.stringify(val); return esc(val); }).join(" | ") + " |"); }); return lines.join("\n"); } },

  { id: "df-json-to-sql", name: "JSON → SQL INSERT", cat: "data", desc: "Generate SQL INSERT statements from a JSON array of objects.", tags: ["json", "sql", "insert"],
    inputs: [{ k: "json", label: "JSON array", type: "textarea", rows: 8, placeholder: '[{"id":1,"name":"a"}]' }, { k: "table", label: "Table name", type: "text", value: "my_table" }],
    run(v) { if (!v.json || !v.json.trim()) return ""; const p = pj(v.json); if (!p.ok) return { error: "Invalid JSON: " + p.err }; if (!Array.isArray(p.val)) return { error: "Input must be a JSON array." }; if (!p.val.length) return ""; const table = (v.table || "my_table").trim() || "my_table"; const keys = []; p.val.forEach((row) => { if (row && typeof row === "object" && !Array.isArray(row)) Object.keys(row).forEach((k) => { if (keys.indexOf(k) < 0) keys.push(k); }); }); if (!keys.length) return { error: "Array items must be objects." }; return p.val.map((row) => "INSERT INTO " + table + " (" + keys.join(", ") + ") VALUES (" + keys.map((k) => sqlVal(row ? row[k] : null)).join(", ") + ");").join("\n"); } },

  { id: "df-csv-to-sql", name: "CSV → SQL INSERT", cat: "data", desc: "Generate SQL INSERT statements from CSV (header row = columns).", tags: ["csv", "sql", "insert"],
    inputs: [{ k: "csv", label: "CSV", type: "textarea", rows: 8, placeholder: "id,name\n1,alice" }, { k: "table", label: "Table name", type: "text", value: "my_table" }, { k: "delim", label: "Delimiter", type: "text", value: "," }],
    run(v) { if (!v.csv) return ""; const delim = v.delim || ","; const rows = cleanRows(parseCSV(v.csv, delim)); if (rows.length < 2) return { error: "Need a header row and at least one data row." }; const table = (v.table || "my_table").trim() || "my_table"; const header = rows[0]; return rows.slice(1).map((r) => "INSERT INTO " + table + " (" + header.join(", ") + ") VALUES (" + header.map((_, i) => sqlVal(r[i] !== undefined ? r[i] : null)).join(", ") + ");").join("\n"); } }
];
