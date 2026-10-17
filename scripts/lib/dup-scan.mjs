// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Duplicate-definition scanner (no AST library). A small JS tokenizer tracks
// braces, decides whether each `{` opens a block, an object literal or a class
// body, and reports:
//   - duplicate keys in one object literal (the later value silently wins),
//   - duplicate methods in one class body (same: the later one wins),
//   - duplicate `function name` declarations in one block / function body
//     (the last declaration silently wins, so earlier copies are dead code).
// Heuristic, but tuned to under-report: anything it cannot classify is ignored.

const PUNCS = [">>>=", "...", "===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??=",
  "=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "++", "--", "+=", "-=", "*=", "/=", "%=",
  "&=", "|=", "^=", "**", "<<", ">>"];
const REGEX_AFTER_KW = new Set(["return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
  "throw", "case", "do", "else", "yield", "await"]);
const OBJECT_AFTER_KW = new Set(["return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
  "throw", "case", "yield", "await"]);
const BLOCK_AFTER_KW = new Set(["else", "try", "finally", "do"]);
const PATTERN_AFTER_KW = new Set(["const", "let", "var", "import", "export", "catch"]);
const MODIFIERS = new Set(["get", "set", "async", "static"]);
const NUM_RE = /(?:0[xXbBoO][\da-fA-F_]+n?|(?:\d[\d_]*\.?[\d_]*|\.\d[\d_]*)(?:[eE][+-]?\d+)?n?)/y;
const isIdStart = (c) => /[A-Za-z_$#\\]/.test(c) || c.charCodeAt(0) > 127;
const isIdPart = (c) => /[\w$\\]/.test(c) || c.charCodeAt(0) > 127;
const isWs = (c) => c === " " || c === "\t" || c === "\n" || c === "\r" || c === "\f" || c === "\v" || c === " " || c === "﻿" || c === " " || c === " ";

function normKey(tok) {
  if (tok.t === "str") return tok.v.slice(1, -1);
  if (tok.t === "num") { const n = Number(tok.v.replace(/_/g, "")); return Number.isFinite(n) ? String(n) : tok.v; }
  return tok.v;
}

/**
 * Scan one source text. Returns [{ kind: "key"|"method"|"function", name, line, firstLine }].
 * Lines are 1-based. `line` is the later (winning) definition, `firstLine` the earlier one.
 */
export function scanDuplicates(src) {
  const out = [];
  const n = src.length;
  let i = 0, line = 1;
  let prev = null, prev2 = null;          // last two significant tokens
  let nl = false;                          // newline since prev token
  const root = { kind: "block", fns: new Map(), tern: 0 };
  const stack = [root];
  let lastParenFn = false;                 // the `)` just closed a function parameter list
  let lastColonTernary = false;
  let pendingClass = null;                 // stack depth at which `class` was seen
  const top = () => stack[stack.length - 1];

  function closeFrame(f) {
    if (f.kind === "block") for (const [name, lines] of f.fns) for (let k = 1; k < lines.length; k++) out.push({ kind: "function", name, line: lines[k], firstLine: lines[0] });
  }
  function recordKey(f, key, ln) {
    if (key === "__proto__") return;
    const name = key;
    if (f.keys.has(name)) out.push({ kind: f.kind === "class" ? "method" : "key", name: key, line: ln, firstLine: f.keys.get(name) });
    else f.keys.set(name, ln);
  }

  // Object/class member-key state machine, fed every significant token.
  // pending = { prefix, key, isMod }: `key` is the candidate key token, `prefix` the
  // get/set/static words before it; isMod means `key` itself may still be a modifier.
  const modWord = (w) => (w === "get" || w === "set" || w === "static" ? w + " " : "");
  const keyable = (tok) => tok.t === "name" || tok.t === "str" || tok.t === "num";
  function memberToken(f, tok) {
    const v = tok.v;
    if (f.pending) {
      const p = f.pending; f.pending = null;
      if (p.isMod && (keyable(tok) || v === "[" || v === "*")) {
        const prefix = p.prefix + (p.key ? modWord(p.key.v) : "");
        if (v === "[") { f.expect = false; return; }
        if (v === "*") { f.pending = { prefix, key: null, isMod: true }; return; }
        f.pending = { prefix, key: tok, isMod: tok.t === "name" && MODIFIERS.has(v) };
        return;
      }
      if (p.key && (f.kind === "object" ? (v === ":" || v === "(" || v === "," || v === "}") : v === "(")) recordKey(f, p.prefix + normKey(p.key), p.key.line);
      f.expect = false;
      return;
    }
    if (!f.expect) return;
    if (v === "*") { f.pending = { prefix: "", key: null, isMod: true }; return; }
    if (keyable(tok)) { f.pending = { prefix: "", key: tok, isMod: tok.t === "name" && MODIFIERS.has(v) }; return; }
    if (v !== ";") f.expect = false;
  }

  function classifyBrace() {
    const p = prev;
    const f = top();
    if (pendingClass !== null && pendingClass === stack.length) { pendingClass = null; return "class"; }
    if (!p) return "block";
    if (p.t === "punc") {
      if (p.v === ";" || p.v === "{" || p.v === "}") return "block";
      if (p.v === "=>") return "fnblock";
      if (p.v === ")") return lastParenFn ? "fnblock" : "block";
      if (p.v === ":") {
        if (f.kind === "object" || f.kind === "paren" || f.kind === "tpl") return "object";
        return lastColonTernary ? "object" : "block";
      }
      if (p.v === "]" || p.v === "}tpl" || p.v === "++" || p.v === "--") return "block";
      return "object";
    }
    if (p.t === "name") {
      if (BLOCK_AFTER_KW.has(p.v)) return "block";
      if (OBJECT_AFTER_KW.has(p.v)) return "object";
      if (p.v === "default") return prev2 && prev2.v === "export" ? "object" : "block";
      if (PATTERN_AFTER_KW.has(p.v)) return "pattern";
      return "block";
    }
    return "block";
  }

  function push(tok) {
    const f = top();
    if (f.kind === "object" || f.kind === "class") memberToken(f, tok);
    if (tok.t === "punc") {
      const v = tok.v;
      if (v === "?") f.tern = (f.tern || 0) + 1;
      if (v === ":") {
        lastColonTernary = false;
        if (f.tern > 0 && !(f.kind === "object" && f.lastWasKey)) { f.tern--; lastColonTernary = true; }
      }
      if (f.kind === "object") f.lastWasKey = false;
      if (v === "," && f.kind === "object") f.expect = true;
      if (v === ";" && f.kind === "class") f.expect = true;
    }
    if (tok.t === "name" && tok.v === "class" && !(prev && (prev.v === "." || prev.v === "?."))) pendingClass = stack.length;
    else if (pendingClass === stack.length && tok.t === "punc" && /^(?:[,:;=)]|=>)$/.test(tok.v)) pendingClass = null;
    prev2 = prev; prev = tok; nl = false;
  }

  function isDeclPosition(p, before) {
    if (!p) return true;
    if (p.t === "punc") return p.v === ";" || p.v === "{" || p.v === "}" || (p.v === ":" && !lastColonTernary) ||
      (before && (p.v === ")" || p.v === "]" || p.v === "}tpl"));
    if (p.t === "name") return p.v === "export" || p.v === "else" || (before && !REGEX_AFTER_KW.has(p.v) && !OBJECT_AFTER_KW.has(p.v) && p.v !== "default");
    return before; // str/num/regex followed by a newline: ASI
  }

  function regexAllowed() {
    const p = prev;
    if (!p) return true;
    if (p.t === "num" || p.t === "str" || p.t === "regex") return false;
    if (p.t === "name") return REGEX_AFTER_KW.has(p.v);
    if (p.v === ")" || p.v === "]" || p.v === "}tpl" || p.v === "++" || p.v === "--") return false;
    if (p.v === "}") return !p.objClose;
    return true;
  }

  function scanTemplate() { // i is just past "`" or past the "}" of a substitution
    while (i < n) {
      const c = src[i];
      if (c === "\\") { if (src[i + 1] === "\n") line++; i += 2; continue; }
      if (c === "\n") line++;
      if (c === "`") { i++; return push({ t: "str", v: "``", line }); }
      if (c === "$" && src[i + 1] === "{") {
        i += 2;
        push({ t: "punc", v: "${", line });
        stack.push({ kind: "tpl", tern: 0 });
        return;
      }
      i++;
    }
  }

  if (src.startsWith("#!")) { while (i < n && src[i] !== "\n") i++; }
  let pendingFnDecl = null; // { frame } after a declaration-position `function`, awaiting the name

  while (i < n) {
    const c = src[i];
    if (isWs(c)) { if (c === "\n") { line++; nl = true; } i++; continue; }
    if (c === "/" && src[i + 1] === "/") { while (i < n && src[i] !== "\n") i++; continue; }
    if (c === "/" && src[i + 1] === "*") {
      const e = src.indexOf("*/", i + 2); const end = e < 0 ? n : e + 2;
      for (let k = i; k < end; k++) if (src[k] === "\n") { line++; nl = true; }
      i = end; continue;
    }
    const startLine = line;
    if (c === "\"" || c === "'") {
      let j = i + 1;
      while (j < n && src[j] !== c && src[j] !== "\n") { if (src[j] === "\\") { if (src[j + 1] === "\n") line++; j++; } j++; }
      push({ t: "str", v: src.slice(i, j + 1), line: startLine });
      i = src[j] === c ? j + 1 : j; continue;
    }
    if (c === "`") { i++; scanTemplate(); continue; }
    if (c === "/" && regexAllowed()) {
      let j = i + 1, cls = false, ok = false;
      while (j < n && src[j] !== "\n") {
        const d = src[j];
        if (d === "\\") { j += 2; continue; }
        if (d === "[") cls = true; else if (d === "]") cls = false;
        else if (d === "/" && !cls) { ok = true; break; }
        j++;
      }
      if (ok) {
        j++; while (j < n && /[a-z]/i.test(src[j])) j++;
        push({ t: "regex", v: src.slice(i, j), line: startLine });
        i = j; continue;
      }
    }
    if (/\d/.test(c) || (c === "." && /\d/.test(src[i + 1] || ""))) {
      NUM_RE.lastIndex = i; const m = NUM_RE.exec(src);
      const v = m ? m[0] : c;
      push({ t: "num", v, line: startLine });
      i += v.length; continue;
    }
    if (isIdStart(c)) {
      let j = i + 1; while (j < n && isIdPart(src[j])) j++;
      const v = src.slice(i, j);
      const before = nl;
      const f = top();
      if (pendingFnDecl) {
        if (v !== "function") { const fr = pendingFnDecl.frame; (fr.fns.get(v) || fr.fns.set(v, []).get(v)).push(startLine); }
        pendingFnDecl = null;
      }
      if (v === "function" && f.kind === "block") {
        let p = prev, pb = before;
        if (p && p.t === "name" && p.v === "async") { p = prev2; pb = p ? p.nlAfter : true; }
        if (isDeclPosition(p, pb)) pendingFnDecl = { frame: f };
      }
      const tok = { t: "name", v, line: startLine };
      if (prev) prev.nlAfter = before;
      push(tok);
      i = j; continue;
    }
    // punctuators
    let v = c;
    for (const pz of PUNCS) if (src.startsWith(pz, i)) { v = pz; break; }
    if (v === "?." && /\d/.test(src[i + 2] || "")) v = "?";
    i += v.length;
    if (pendingFnDecl && v !== "*") pendingFnDecl = null;
    if (prev) prev.nlAfter = nl;
    const f = top();
    if (v === "{") {
      const kind = classifyBrace();
      const tok = { t: "punc", v, line: startLine };
      if (f.kind === "object" || f.kind === "class") memberToken(f, tok);
      prev2 = prev; prev = tok; nl = false; lastParenFn = false;
      if (kind === "object") stack.push({ kind: "object", keys: new Map(), expect: true, tern: 0 });
      else if (kind === "class") stack.push({ kind: "class", keys: new Map(), expect: true, tern: 0 });
      else if (kind === "pattern") stack.push({ kind: "pattern", tern: 0 });
      else stack.push({ kind: "block", fns: new Map(), tern: 0 });
      continue;
    }
    if (v === "}") {
      if (f.kind === "tpl") { stack.pop(); push({ t: "punc", v: "}tpl", line: startLine }); scanTemplate(); continue; }
      if (stack.length > 1) { stack.pop(); closeFrame(f); }
      const tok = { t: "punc", v, line: startLine, objClose: f.kind === "object" || f.kind === "pattern" };
      const g = top();
      if (g.kind === "object") { memberToken(g, tok); }
      else if (g.kind === "class") { g.pending = null; g.expect = true; }
      prev2 = prev; prev = tok; nl = false; lastParenFn = false;
      continue;
    }
    if (v === "(" || v === "[") {
      let isFn = false;
      if (v === "(") {
        const p = prev, p2 = prev2;
        if (p && p.t === "name" && (p.v === "function" || (p2 && (p2.v === "function" || p2.v === "*")))) isFn = true;
        else if (p && p.v === "*" && p2 && p2.v === "function") isFn = true;
        else if ((f.kind === "object" || f.kind === "class") && f.pending && f.pending.key) isFn = true;
      }
      push({ t: "punc", v, line: startLine });
      stack.push({ kind: v === "(" ? "paren" : "bracket", tern: 0, fnParams: isFn });
      continue;
    }
    if (v === ")" || v === "]") {
      lastParenFn = false;
      if (stack.length > 1 && (f.kind === "paren" || f.kind === "bracket")) { stack.pop(); lastParenFn = !!f.fnParams && v === ")"; }
      const save = lastParenFn;
      push({ t: "punc", v, line: startLine });
      lastParenFn = save;
      continue;
    }
    if (f.kind === "object" && v === ":" && f.pending && f.pending.key) f.lastWasKey = true;
    push({ t: "punc", v, line: startLine });
    if (v !== ")") lastParenFn = false;
  }
  while (stack.length) closeFrame(stack.pop());
  return out.sort((a, b) => a.line - b.line);
}
