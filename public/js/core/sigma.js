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

// Match one spec value against one event value under the given modifiers.
function matchValue(eventVal, specVal, mods) {
  if (specVal === null) return eventVal == null || eventVal === "";
  if (eventVal == null) return false;
  const ev = str(eventVal), sv = str(specVal);
  if (mods.includes("re")) { try { return new RegExp(sv, mods.includes("cased") ? "" : "i").test(ev); } catch (_) { return false; } }
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
// Supports: identifiers, and, or, not, parentheses, "all of them", "1 of them",
// "all of <prefix>*", "1 of <prefix>*". ("x of" with x>1 is treated as "1 of" i.e. any.)
function tokenizeCond(s) {
  const toks = []; const re = /\(|\)|\ball of them\b|\b1 of them\b|\ball of [A-Za-z0-9_*]+|\b1 of [A-Za-z0-9_*]+|\band\b|\bor\b|\bnot\b|[A-Za-z0-9_*]+/gi;
  let m; while ((m = re.exec(s))) toks.push(m[0]);
  return toks;
}
function evalCondition(cond, selResults, selNames) {
  const toks = tokenizeCond(str(cond || "").trim());
  let i = 0;
  const peek = () => toks[i], next = () => toks[i++];
  const ofPrefix = (word) => { // "all of foo*" / "1 of them"
    const m = /^(all|1) of (.+)$/i.exec(word); if (!m) return false;
    const which = m[1].toLowerCase(), target = m[2].trim();
    const names = target === "them" ? selNames : selNames.filter((n) => matchPrefix(n, target));
    if (!names.length) return false;
    return which === "all" ? names.every((n) => !!selResults[n]) : names.some((n) => !!selResults[n]);
  };
  function primary() {
    const t = peek();
    if (t === "(") { next(); const v = orExpr(); if (peek() === ")") next(); return v; }
    if (/^(all|1) of /i.test(t)) { next(); return ofPrefix(t); }
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
    const selResults = {};
    for (const name of rule.selectionNames) selResults[name] = matchSelection(flat, rule.detection[name]);
    if (evalCondition(rule.condition, selResults, rule.selectionNames)) matches.push({ index: idx, event: list[idx] });
  }
  return { ok: true, title: rule.title, level: rule.level, count: matches.length, matches };
}
