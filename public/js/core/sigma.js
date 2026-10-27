// Sigma-subset detection evaluator (Deck D9). PURE — no DOM, no network, deterministic. It
// compiles a Sigma-style rule (YAML) and runs it against an array of log events, returning the
// matches. Sigma is an open specification; this is a clean-room implementation of a practical
// subset of it (field maps, keyword lists, field modifiers, and the common `condition` forms),
// so per-workspace custom detections can be written once and tested against real log samples
// before they are relied on. It invents nothing — an event matches only if the rule says so.
import { parseYamlSubset } from "../ingest/parse.js";

const str = (v) => (v == null ? "" : String(v));
const lc = (v) => str(v).toLowerCase();

// Flatten an event object to a map of lower-cased field path -> array of string values, so a
// Sigma field name matches regardless of nesting or case. Arrays and nested objects are walked.
function flatten(ev) {
  const out = new Map();
  const add = (k, v) => { const key = lc(k); if (!out.has(key)) out.set(key, []); out.get(key).push(v); };
  const walk = (obj, prefix) => {
    if (obj == null) return;
    if (Array.isArray(obj)) { for (const x of obj) walk(x, prefix); return; }
    if (typeof obj === "object") {
      for (const k of Object.keys(obj)) {
        const path = prefix ? prefix + "." + k : k;
        const v = obj[k];
        if (v != null && typeof v === "object") walk(v, path);
        else { add(path, v); add(k, v); } // match by full path or by leaf name
      }
      return;
    }
    if (prefix) add(prefix, obj);
  };
  walk(ev, "");
  return out;
}
const valuesFor = (flat, field) => flat.get(lc(field)) || [];
// All scalar string values of an event, for keyword (fieldless) matching.
function allValues(flat) { const out = []; for (const arr of flat.values()) for (const v of arr) out.push(v); return out; }

// Sigma wildcards (as pySigma reads them): * = any run, ? = one character; \* \? \\ are the
// literal characters. Returns null when the value has no wildcard or escape (plain compare).
const escRe = (c) => c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
function wildRe(sv, mods) {
  let re = "", wild = false;
  for (let i = 0; i < sv.length; i++) {
    const c = sv[i];
    if (c === "\\" && (sv[i + 1] === "*" || sv[i + 1] === "?" || sv[i + 1] === "\\")) { re += escRe(sv[++i]); wild = true; continue; } // an escape also needs the pattern path (a\*b is the literal a*b)
    if (c === "*") { re += "[\\s\\S]*"; wild = true; } else if (c === "?") { re += "[\\s\\S]"; wild = true; } else re += escRe(c);
  }
  if (!wild) return null;
  const head = mods.includes("contains") || mods.includes("endswith") ? "" : "^", tail = mods.includes("contains") || mods.includes("startswith") ? "" : "$";
  return new RegExp(head + re + tail, mods.includes("cased") ? "" : "i");
}
// Modifiers this evaluator implements; compileRule refuses anything else rather than mis-match.
const MODS = new Set(["contains", "startswith", "endswith", "all", "re", "cased", "exists"]);

// Match one spec value against one event value under the given modifiers.
function matchValue(eventVal, specVal, mods) {
  if (specVal === null) return eventVal == null || eventVal === "";
  if (eventVal == null) return false;
  const ev = str(eventVal), sv = str(specVal);
  if (mods.includes("re")) { try { return new RegExp(sv, mods.includes("cased") ? "" : "i").test(ev); } catch (_) { return false; } }
  if (typeof specVal === "string") { const w = wildRe(sv, mods); if (w) return w.test(ev); }
  const a = mods.includes("cased") ? ev : ev.toLowerCase();
  const b = mods.includes("cased") ? sv : sv.toLowerCase();
  if (mods.includes("contains")) return a.includes(b);
  if (mods.includes("startswith")) return a.startsWith(b);
  if (mods.includes("endswith")) return a.endsWith(b);
  // plain equality — numbers compare loosely, strings case-insensitively
  if (typeof specVal === "number" || typeof eventVal === "number") return Number(eventVal) === Number(specVal) || a === b;
  return a === b;
}

// One "field: value(s)" clause. list of spec values => OR, unless |all => AND.
function matchField(flat, rawKey, spec) {
  const parts = str(rawKey).split("|");
  const field = parts[0];
  const mods = parts.slice(1).map(lc);
  const evVals = valuesFor(flat, field);
  if (mods.includes("exists")) { const has = evVals.some((v) => v != null && v !== ""); return (spec === true || lc(spec) === "true") ? has : !has; }
  const specVals = Array.isArray(spec) ? spec : [spec];
  const need = mods.includes("all");
  const test = (sv) => (spec === null ? matchValue(evVals.length ? evVals[0] : null, null, mods) : evVals.some((ev) => matchValue(ev, sv, mods)));
  return need ? specVals.every(test) : specVals.some(test);
}

// One selection: a map (all fields AND), a list of maps (OR), or a list of strings (keyword OR).
function matchSelection(flat, sel) {
  if (sel == null) return false;
  if (Array.isArray(sel)) {
    if (sel.every((x) => x == null || typeof x !== "object")) { // keyword list
      const hay = allValues(flat).map(lc);
      return sel.some((kw) => { const k = lc(kw); return hay.some((h) => h.includes(k)); });
    }
    return sel.some((m) => matchSelection(flat, m)); // list of maps -> OR
  }
  if (typeof sel === "object") return Object.keys(sel).every((k) => matchField(flat, k, sel[k])); // map -> AND
  // a bare scalar selection is treated as a single keyword
  { const k = lc(sel); return allValues(flat).map(lc).some((h) => h.includes(k)); }
}

// ---- condition expression ----
// Supports: identifiers, and, or, not, parentheses, "all of them", "N of them",
// "all of <prefix>*", "N of <prefix>*". "N of" matches when at least N of the named
// selections are true (Sigma semantics); "1 of" is the N=1 case (any).
function tokenizeCond(s) {
  const toks = []; const re = /\(|\)|\ball of them\b|\b\d+ of them\b|\ball of [A-Za-z0-9_*]+|\b\d+ of [A-Za-z0-9_*]+|\band\b|\bor\b|\bnot\b|[A-Za-z0-9_*]+/gi;
  let m; while ((m = re.exec(s))) toks.push(m[0]);
  return toks;
}
function evalCondition(cond, selResults, selNames) {
  const toks = tokenizeCond(str(cond || "").trim());
  let i = 0;
  const peek = () => toks[i], next = () => toks[i++];
  const ofPrefix = (word) => { // "all of foo*" / "N of them"
    const m = /^(all|\d+) of (.+)$/i.exec(word); if (!m) return false;
    const which = m[1].toLowerCase(), target = m[2].trim();
    const names = target === "them" ? selNames : selNames.filter((n) => matchPrefix(n, target));
    if (!names.length) return false;
    const nMatch = names.filter((n) => !!selResults[n]).length;
    if (which === "all") return nMatch === names.length;
    return nMatch >= Math.max(1, parseInt(which, 10) || 1); // "N of": at least N selections true
  };
  function primary() {
    const t = peek();
    if (t === "(") { next(); const v = orExpr(); if (peek() === ")") next(); return v; }
    if (/^(all|\d+) of /i.test(t)) { next(); return ofPrefix(t); }
    next(); return !!selResults[t];
  }
  function notExpr() { if (lc(peek()) === "not") { next(); return !notExpr(); } return primary(); }
  function andExpr() { let v = notExpr(); while (lc(peek()) === "and") { next(); v = notExpr() && v; } return v; }
  function orExpr() { let v = andExpr(); while (lc(peek()) === "or") { next(); const r = andExpr(); v = v || r; } return v; }
  if (!toks.length) return false;
  return orExpr();
}
function matchPrefix(name, pattern) {
  if (pattern.endsWith("*")) return name.startsWith(pattern.slice(0, -1));
  return name === pattern;
}

/**
 * compileRule(yamlText) -> { ok:true, rule } | { ok:false, error }
 * rule = { title, id, level, description, detection, condition, selectionNames }
 */
export function compileRule(yamlText) {
  let doc;
  try { doc = parseYamlSubset(yamlText); } catch (e) { return { ok: false, error: "YAML: " + (e && e.message ? e.message : "could not parse") }; }
  if (Array.isArray(doc)) doc = doc[0];
  if (!doc || typeof doc !== "object") return { ok: false, error: "The rule is empty or not a mapping." };
  const detection = doc.detection;
  if (!detection || typeof detection !== "object") return { ok: false, error: "Missing a `detection:` block." };
  const condition = detection.condition;
  if (!condition || typeof condition !== "string") return { ok: false, error: "Missing a `condition:` under detection." };
  const selectionNames = Object.keys(detection).filter((k) => k !== "condition");
  if (!selectionNames.length) return { ok: false, error: "The detection has no search identifiers." };
  // an unimplemented modifier (cidr, base64, windash, gt...) must not silently fall back to plain equality
  const bad = new Set(), scan = (sel) => { if (Array.isArray(sel)) sel.forEach(scan); else if (sel && typeof sel === "object") for (const k of Object.keys(sel)) for (const m of str(k).split("|").slice(1)) if (!MODS.has(lc(m))) bad.add(lc(m)); };
  for (const n of selectionNames) scan(detection[n]);
  if (bad.size) return { ok: false, error: "Unsupported field modifier" + (bad.size > 1 ? "s" : "") + ": " + [...bad].join(", ") + ". Supported: contains, startswith, endswith, all, re, cased, exists." };
  return { ok: true, rule: { title: str(doc.title || "Untitled rule"), id: str(doc.id || ""), level: lc(doc.level || ""), description: str(doc.description || ""), detection, condition, selectionNames } };
}

/**
 * evaluateRule(compiledRuleOrYaml, events) -> { ok, title, level, count, matches:[{index,event}], error? }
 * Accepts either a compiled rule (from compileRule().rule) or a raw YAML string.
 */
export function evaluateRule(ruleOrYaml, events) {
  let rule = ruleOrYaml;
  if (typeof ruleOrYaml === "string") { const c = compileRule(ruleOrYaml); if (!c.ok) return { ok: false, error: c.error, matches: [], count: 0 }; rule = c.rule; }
  if (!rule || !rule.detection) return { ok: false, error: "Not a compiled rule.", matches: [], count: 0 };
  const list = Array.isArray(events) ? events : [];
  const matches = [];
  for (let idx = 0; idx < list.length; idx++) {
    const flat = flatten(list[idx]);
    const selResults = Object.create(null); // null-proto: a condition naming "toString"/"constructor" (not a real selection) must be false, not an inherited member
    for (const name of rule.selectionNames) selResults[name] = matchSelection(flat, rule.detection[name]);
    if (evalCondition(rule.condition, selResults, rule.selectionNames)) matches.push({ index: idx, event: list[idx] });
  }
  return { ok: true, title: rule.title, level: rule.level, count: matches.length, matches };
}
