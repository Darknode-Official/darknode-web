// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Code Scanner: JavaScript / TypeScript data-flow (taint) engine. Pure, DOM-free, no network.
//
// Line rules can only say "this line looks risky". This engine follows untrusted input
// (request parameters, URL parts, postMessage data) through variables, object
// paths, destructuring, string building and same-file function calls, and reports a
// sink only when it can show every step of the path. Validation, numeric conversion
// and the right escaping function stop the flow, so properly guarded code stays quiet.
//
// Original work written from the CWE definitions; no third-party rules or code.
//
// taintScan(text) → [{ kind, ruleId, title, sev, cwe, line, col, why, fix, flow: [{line, col, label}] }]

// ── Tokenizer ──────────────────────────────────────────────────────────────────
const PUNCT = [">>>=", "...", "===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??=",
  "=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "++", "--", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "**", "<<", ">>"];
const BEFORE_EXPR = new Set(["return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do", "else", "yield", "await"]);
const ID_START = /[A-Za-z_$\u0080-￿]/;
const ID_PART = /[\w$\u0080-￿]/;

// Tokens: { t: "id" | "num" | "str" | "tpl" | "re" | "p", v, line, col, nl }. A template
// literal carries `parts`, one token list per ${…} substitution. `nl` marks a token that
// starts a new line (needed for automatic semicolon insertion).
export function tokenize(src) {
  src = String(src || "");
  const n = src.length;
  let i = 0, line = 1, col = 1, nl = true;
  const adv = (k) => { for (let j = 0; j < k && i < n; j++) { if (src[i] === "\n") { line++; col = 1; } else col++; i++; } };
  const regexOk = (p) => !p || (p.t === "p" && !")]}".includes(p.v)) || (p.t === "id" && BEFORE_EXPR.has(p.v));
  function run(stop) {
    const out = [];
    let depth = 0;
    while (i < n) {
      const c = src[i];
      if (c === "\n") { nl = true; adv(1); continue; }
      if (c === " " || c === "\t" || c === "\r" || c === "\f" || c === "\v" || c === "﻿" || c === " ") { adv(1); continue; }
      if (c === "/" && src[i + 1] === "/") { while (i < n && src[i] !== "\n") adv(1); continue; }
      if (c === "/" && src[i + 1] === "*") {
        const e = src.indexOf("*/", i + 2), end = e < 0 ? n : e + 2;
        while (i < end) { if (src[i] === "\n") nl = true; adv(1); }
        continue;
      }
      if (stop && c === "}" && depth === 0) { adv(1); return out; }
      const tok = { line, col, nl };
      nl = false;
      if (ID_START.test(c)) {
        let j = i + 1;
        while (j < n && ID_PART.test(src[j])) j++;
        tok.t = "id"; tok.v = src.slice(i, j); adv(j - i);
      } else if (/[0-9]/.test(c) || (c === "." && /[0-9]/.test(src[i + 1] || ""))) {
        let j = i + 1;
        while (j < n && /[\w.]/.test(src[j])) j++;
        tok.t = "num"; tok.v = src.slice(i, j); adv(j - i);
      } else if (c === '"' || c === "'") {
        let j = i + 1;
        while (j < n && src[j] !== c && src[j] !== "\n") { if (src[j] === "\\") j++; j++; }
        tok.t = "str"; tok.v = src.slice(i + 1, Math.min(j, n)); adv(Math.min(j + 1, n) - i);
      } else if (c === "`") {
        adv(1);
        tok.t = "tpl"; tok.v = ""; tok.parts = [];
        while (i < n && src[i] !== "`") {
          if (src[i] === "\\") { tok.v += src.slice(i, i + 2); adv(2); continue; }
          if (src[i] === "$" && src[i + 1] === "{") { adv(2); tok.parts.push(run(true)); tok.v += "${}"; continue; }
          tok.v += src[i]; adv(1);
        }
        adv(1);
      } else if (c === "/" && regexOk(out[out.length - 1])) {
        let j = i + 1, cls = false;
        while (j < n && src[j] !== "\n") {
          const d = src[j];
          if (d === "\\") { j += 2; continue; }
          if (d === "[") cls = true; else if (d === "]") cls = false; else if (d === "/" && !cls) break;
          j++;
        }
        j++;
        while (j < n && /[a-z]/i.test(src[j])) j++;
        tok.t = "re"; tok.v = src.slice(i, j); adv(j - i);
      } else {
        let v = c;
        for (const p of PUNCT) if (src.startsWith(p, i)) { v = p; break; }
        if (v === "?." && /[0-9]/.test(src[i + 2] || "")) v = "?";
        if (v === "{") depth++; else if (v === "}") depth--;
        tok.t = "p"; tok.v = v; adv(v.length);
      }
      out.push(tok);
    }
    return out;
  }
  return run(false);
}

// ── Token helpers ──────────────────────────────────────────────────────────────
const isP = (t, v) => !!t && t.t === "p" && t.v === v;
const OPEN = { "(": ")", "[": "]", "{": "}" };
const KEYWORDS = new Set(["if", "for", "while", "switch", "catch", "with", "return", "typeof", "new", "function", "await", "async", "yield", "throw", "case", "else", "do", "in", "of", "instanceof", "delete", "void", "const", "let", "var", "class", "extends", "import", "export", "default", "this", "super", "null", "undefined", "true", "false"]);

// Work budget for one taintScan: every scan of a token range pays its length. Nested or
// unbalanced brackets (a truncated file, TSX the tokenizer misreads) made the analysis
// cubic, so a 40 KB file could hold the tab for minutes; past the budget the scan stops
// and keeps the flows it has already proven.
const OUT_OF_BUDGET = { budget: true };
let budget = Infinity;
const spend = (n) => { if ((budget -= n) < 0) throw OUT_OF_BUDGET; };

function matchClose(T, i) {
  const o = T[i].v, c = OPEN[o];
  let d = 0;
  for (let j = i; j < T.length; j++) {
    if (T[j].t !== "p") continue;
    if (T[j].v === o) d++;
    else if (T[j].v === c && --d === 0) { spend(j - i); return j; }
  }
  spend(T.length - i);
  return T.length - 1;
}
function matchOpen(T, i) {
  const c = T[i].v, o = c === ")" ? "(" : c === "]" ? "[" : "{";
  let d = 0;
  for (let j = i; j >= 0; j--) {
    if (T[j].t !== "p") continue;
    if (T[j].v === c) d++;
    else if (T[j].v === o && --d === 0) { spend(i - j); return j; }
  }
  spend(i);
  return 0;
}

const endsStmt = (t) => !!t && (t.t === "id" || t.t === "num" || t.t === "str" || t.t === "tpl" || t.t === "re" || (t.t === "p" && (t.v === ")" || t.v === "]" || t.v === "}" || t.v === "++" || t.v === "--")));
const startsStmt = (t) => !!t && t.t === "id" && !["in", "of", "instanceof"].includes(t.v);

// End (exclusive) of the expression starting at a: stops at a depth-0 ; or , or an
// unmatched closer, or where a new statement begins on a new line.
function exprEnd(T, a, lim = T.length) {
  let d = 0;
  for (let j = a; j < lim; j++) {
    const t = T[j];
    if (j > a && d === 0 && t.nl && endsStmt(T[j - 1]) && startsStmt(t)) return j;
    if (t.t !== "p") continue;
    if (t.v === "(" || t.v === "[" || t.v === "{") d++;
    else if (t.v === ")" || t.v === "]" || t.v === "}") { if (d === 0) return j; d--; }
    else if (d === 0 && (t.v === ";" || t.v === ",")) return j;
  }
  return lim;
}

// Dotted access path starting at T[i] (an identifier that is not itself a member).
// Returns { path, end } where end is the index just past the path.
function pathAt(T, i) {
  if (!T[i] || T[i].t !== "id") return null;
  let path = T[i].v, j = i + 1;
  for (;;) {
    if ((isP(T[j], ".") || isP(T[j], "?.")) && T[j + 1] && T[j + 1].t === "id") { path += "." + T[j + 1].v; j += 2; continue; }
    if (isP(T[j], "[") && T[j + 1] && (T[j + 1].t === "str") && isP(T[j + 2], "]")) { path += "." + T[j + 1].v; j += 3; continue; }
    break;
  }
  return { path, end: j };
}
const isMember = (T, i) => isP(T[i - 1], ".") || isP(T[i - 1], "?.");

// Split call arguments: [open, close] of the parens → array of [a, b) ranges.
function args(T, open, close) {
  spend(close - open);
  const out = [];
  let a = open + 1, d = 0;
  for (let j = open + 1; j < close; j++) {
    const v = T[j].t === "p" ? T[j].v : "";
    if (v === "(" || v === "[" || v === "{") d++;
    else if (v === ")" || v === "]" || v === "}") d--;
    else if (v === "," && d === 0) { out.push([a, j]); a = j + 1; }
  }
  if (a < close) out.push([a, close]);
  return out;
}

// The identifier a method chain starts from: `res.status(400).send(x)` → "res".
function chainBase(T, dot) {
  let j = dot - 1;
  for (;;) {
    if (!T[j]) return { base: "", text: "" };
    if (isP(T[j], ")") || isP(T[j], "]")) { j = matchOpen(T, j) - 1; continue; }
    if (T[j].t === "id") {
      if (isP(T[j - 1], ".") || isP(T[j - 1], "?.")) { j -= 2; continue; }
      return { base: T[j].v, idx: j, text: T.slice(j, dot + 2).map((k) => (k.t === "str" ? JSON.stringify(k.v) : k.v)).join("") };
    }
    return { base: "", text: "" };
  }
}

// Parameter names of a function whose parameter list is the paren group ending at `close`.
function paramNames(T, close) {
  const open = matchOpen(T, close);
  const out = [];
  let d = 0, pos = 0;
  for (let j = open + 1; j < close; j++) {
    const t = T[j];
    if (d === 0 && isP(t, ",")) pos++;
    if (t.t === "p" && "([{".includes(t.v)) d++;
    else if (t.t === "p" && ")]}".includes(t.v)) d--;
    else if (t.t === "id" && !KEYWORDS.has(t.v) && (d === 0 || (d === 1 && T[open + 1] && isP(T[open + 1], "{")))) {
      const prev = T[j - 1], next = T[j + 1];
      const okPrev = j === open + 1 || isP(prev, ",") || isP(prev, "...") || isP(prev, "{") || isP(prev, "(") || (isP(prev, ":") && d === 1);
      const okNext = !next || isP(next, ",") || isP(next, ")") || isP(next, "=") || isP(next, ":") || isP(next, "?") || isP(next, "}");
      if (okPrev && okNext && !(isP(next, ":") && d === 1)) out.push({ name: t.v, i: pos, top: d === 0 });
    }
  }
  return out;
}

// ── Sources ────────────────────────────────────────────────────────────────────
const SERVER_SRC = /^(?:req|request|ctx\.request|ctx)\.(?:query|body|params|headers|cookies|signedCookies|files?|url|originalUrl|path|querystring|search|rawBody|nextUrl)(?:\.|$)/;
const SERVER_SRC_CALL = /^(?:req|request)\.(?:get|header|param)$|^request\.(?:json|text|formData)$/;
const LAMBDA_SRC = /^event\.(?:queryStringParameters|multiValueQueryStringParameters|pathParameters|body|headers)(?:\.|$)/;
const CLIENT_SRC = /^(?:(?:window|document|self|globalThis)\.)?location\.(?:hash|search|href|pathname)(?:\.|$)|^(?:window\.|self\.)?location$|^document\.(?:URL|documentURI|referrer|cookie|baseURI)(?:\.|$)|^window\.name$/;
const MSG_SRC = /^(?:e|ev|evt|event|msg|message)\.data(?:\.|$)/;

function sourceOf(path, isCall, ctx) {
  if (SERVER_SRC.test(path)) return { side: "server" };
  if (isCall && SERVER_SRC_CALL.test(path)) return { side: "server" };
  if (ctx.lambda && LAMBDA_SRC.test(path)) return { side: "server" };
  if (CLIENT_SRC.test(path) || /^router\.(?:query|asPath)(?:\.|$)/.test(path)) return { side: "client" };
  if (isCall && /^(?:useParams|useSearchParams|useLocation)$/.test(path)) return { side: "client" };
  if (ctx.messages && MSG_SRC.test(path)) return { side: "client" };
  return null;
}

// ── Sanitizers (which sink kinds each one makes safe) ──────────────────────────
const ALL = ["code", "cmd", "sql", "nosql", "xss", "redirect", "path", "ssrf", "regex", "module"];
const SANITIZERS = [
  [/^(?:parseInt|parseFloat|Number|Boolean|BigInt|Math\.\w+|isNaN|isFinite|Number\.\w+|Date\.parse|crypto\.\w+|uuid\w*)$/, ALL],
  [/^(?:escapeHtml|escapeHTML|htmlEscape|escape|esc|encodeHTML|encodeHtml|he\.(?:encode|escape)|DOMPurify\.sanitize|\w+\.sanitize|sanitizeHtml|sanitizeHTML|xss|filterXSS|validator\.escape|_\.escape|lodash\.escape)$/, ["xss"]],
  // Not "code": letters, digits and ( ) ' . ! ~ * pass through unencoded, so eval(encodeURIComponent(x)) still runs alert(1).
  [/^(?:encodeURIComponent|querystring\.escape|qs\.escape)$/, ["xss", "cmd", "path", "redirect", "ssrf"]],
  [/^(?:\w+\.escape|sqlstring\.escape|SqlString\.escape|\w+\.escapeId|\w+\.escapeLiteral|\w+\.escapeIdentifier|format\.literal|pgFormat)$/, ["sql"]],
  [/^(?:shellescape|shellEscape|escapeShellArg|shellQuote\.quote|quote)$/, ["cmd"]],
  [/^(?:path\.basename|basename|sanitizeFilename|sanitize)$/, ["path"]],
  [/^(?:\w+\.escapeRegExp|escapeRegExp|escapeRegex|_\.escapeRegExp|lodash\.escapeRegExp)$/, ["regex"]],
  [/^(?:String|JSON\.stringify)$/, ["nosql"]],
];
const sanitizerKinds = (path) => { for (const [re, kinds] of SANITIZERS) if (re.test(path)) return kinds; return null; };
// Calls whose result is a boolean or a number whatever the input.
const SCALAR_RESULT = /\.(?:includes|has|test|indexOf|lastIndexOf|startsWith|endsWith|some|every|localeCompare|findIndex|isArray)$/;
// x.replace(/[^a-z0-9_-]/g, "") keeps only safe characters.
const ALLOWLIST_STRIP = /^\/\[\^(?:[A-Za-z0-9_]|\\[wd-]|[a-zA-Z0-9]-[a-zA-Z0-9]|-)*\]\+?\/[gimsuy]*g[gimsuy]*$/;
// Existence probes: `if (!fs.existsSync(p)) return` proves the file is there, not that p is safe.
const FS_PROBE = /(?:^|\.)(?:exists|existsSync|access|accessSync|stat|statSync|lstat|lstatSync)$/;
const VALIDATOR = /^(?:is[A-Z]\w*|validate\w*|\w+\.is[A-Z]\w*|\w+\.validate\w*|\w+\.test|\w+\.includes|\w+\.has|\w+\.match|Number\.isInteger|Number\.isSafeInteger|Array\.isArray)$/;

// ── Sinks ──────────────────────────────────────────────────────────────────────
export const SINK_INFO = {
  code: { title: "User input reaches code evaluation", sev: "critical", cwe: 95,
    why: "Untrusted input flows into a function that runs strings as JavaScript, so an attacker can run any code with the application's privileges.",
    fix: "Never evaluate input. Parse data with JSON.parse and pick behaviour from a fixed lookup table instead of building code." },
  cmd: { title: "User input reaches a shell command", sev: "critical", cwe: 78,
    why: "Untrusted input is built into an operating-system command; shell metacharacters such as ; | $( ) run extra commands on the server.",
    fix: "Use execFile/spawn with a fixed program and an argument array (no shell), and allowlist every argument." },
  sql: { title: "User input reaches a SQL query", sev: "critical", cwe: 89,
    why: "Untrusted input is concatenated into SQL text, so quotes in it can rewrite the query (SQL injection): read, change or delete any row.",
    fix: "Use parameterised queries: pass the SQL with placeholders ($1, ?) and the values as a separate array." },
  nosql: { title: "User input used as a database query object", sev: "medium", cwe: 943,
    why: "A request body field can be an object such as {\"$ne\": null}, which turns an equality check into an operator and bypasses the filter (NoSQL injection).",
    fix: "Cast fields to the expected type (String(x)) or validate the body with a schema before querying; enable your driver's sanitizeFilter option." },
  xss: { title: "User input reaches an HTML sink (XSS)", sev: "high", cwe: 79,
    why: "Untrusted input is inserted as HTML, so markup and script in it run in the victim's browser with their session (cross-site scripting).",
    fix: "Insert text with textContent, or escape it for HTML / sanitise it with DOMPurify before using an HTML sink." },
  redirect: { title: "User input controls a redirect", sev: "medium", cwe: 601,
    why: "The redirect target comes from the request or URL, so attackers can send victims through your domain to a phishing page, or to a javascript: URL.",
    fix: "Redirect only to relative paths you build, or check the destination against an allowlist of exact URLs." },
  path: { title: "User input reaches a file path", sev: "high", cwe: 22,
    why: "Untrusted input selects a file, so sequences like ../../ read or overwrite files outside the intended directory (path traversal).",
    fix: "Use path.basename for file names, or resolve the path and reject it unless it starts with the allowed base directory." },
  ssrf: { title: "User input controls a server-side request (SSRF)", sev: "high", cwe: 918,
    why: "The server fetches a URL taken from the request, so attackers can reach internal services, cloud metadata endpoints and private networks.",
    fix: "Fix the host in code and only pass validated path parts, or check the URL's host against an allowlist and block private address ranges." },
  regex: { title: "User input compiled as a regular expression", sev: "medium", cwe: 1333,
    why: "An attacker-chosen pattern can backtrack catastrophically and freeze the event loop for every user (ReDoS).",
    fix: "Escape the input before building a RegExp, or match it with plain string methods." },
  module: { title: "User input chooses a module to load", sev: "high", cwe: 829,
    why: "Loading a module path taken from input lets an attacker run code from any file the process can read.",
    fix: "Map the input to a fixed allowlist of module names." },
};

const FS_METHODS = /^(?:readFile|readFileSync|createReadStream|createWriteStream|writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync|readdir|readdirSync|open|openSync|copyFile|copyFileSync|rename|renameSync|mkdir|mkdirSync)$/;
const HTTP_CLIENT = /^(?:fetch|axios|got|needle|ky|superagent|undici\.request|request)$|^(?:axios|got|needle|ky|superagent|http|https|undici)\.(?:get|post|put|patch|delete|head|request|fetch)$/;
const SQL_METHODS = /^(?:query|execute|raw|unsafe|prepare|\$queryRawUnsafe|\$executeRawUnsafe|queryRaw|exec)$/;
const NOSQL_METHODS = /^(?:find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|countDocuments|where)$/;

// Returns [{ arg: index | "any" | "last", kind, ctorOnly? }] for a call.
function sinksForCall(callee, ctx, isNew) {
  const { path, meth, base } = callee;
  const out = [];
  const add = (arg, kind, extra) => out.push({ arg, kind, ...extra });
  if (path) {
    if (/^(?:window\.|globalThis\.)?eval$/.test(path)) add(0, "code");
    if (path === "Function" && isNew) add("any", "code");
    if (/^(?:window\.)?set(?:Timeout|Interval)$/.test(path)) add(0, "code", { strOnly: true });
    if (/^vm\.(?:runInContext|runInNewContext|runInThisContext|compileFunction)$/.test(path)) add(0, "code");
    if (path === "vm.Script" && isNew) add(0, "code");
    if (path === "require" || path === "import") add(0, "module", { server: true });
    if ((path === "RegExp") ) add(0, "regex", { server: true });
    if (/^document\.write(?:ln)?$/.test(path)) add("any", "xss");
    if (/^(?:window\.|document\.)?location\.(?:assign|replace)$/.test(path) || path === "window.open") add(0, "redirect");
    if (HTTP_CLIENT.test(path)) add(0, "ssrf", { server: true });
  }
  // child_process / shelljs / execa, by import alias or destructured name
  if (path && ctx.cpNames.has(path)) add(0, "cmd");
  if (meth && base && ctx.cpModules.has(base) && /^(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)$/.test(meth)) add(0, "cmd");
  if (meth && base && ctx.fsModules.has(base) && FS_METHODS.test(meth)) add(0, "path", { server: true });
  if (path && ctx.fsNames.has(path)) add(0, "path", { server: true });
  if (meth === "insertAdjacentHTML") add(1, "xss");
  if (meth === "html" && ctx.jquery && path !== "html") add(0, "xss");
  if (meth && SQL_METHODS.test(meth) && base && !/^(?:re|regex|regexp|pattern|rx|[A-Z_]+_RE)$/i.test(base) && !(meth === "exec" && !/db|sql|conn|client|pool|knex|sequelize|prisma/i.test(base))) add(0, "sql", { server: true });
  if (meth && NOSQL_METHODS.test(meth) && base && (/^[A-Z]/.test(base) || /collection|model/i.test(callee.text || path || base))) add(0, "nosql", { server: true, direct: true });
  if (base && /^(?:res|response|reply)$/.test(base)) {
    if (/^(?:send|write|end)$/.test(meth)) add(0, "xss", { server: true, reflected: true });
    if (meth === "redirect") add("last", "redirect");
    if (/^(?:sendFile|download)$/.test(meth)) add(0, "path", { server: true, noRoot: true });
  }
  return out;
}
const ASSIGN_SINK = (pathOrProp) => {
  if (/(?:^|\.)(?:innerHTML|outerHTML)$/.test(pathOrProp)) return "xss";
  if (/^(?:(?:window|document|self|top)\.)?location(?:\.href)?$/.test(pathOrProp)) return "redirect";
  if (/(?:^|\.)srcdoc$/.test(pathOrProp)) return "xss";
  return null;
};

// ── Environment (lexical scopes of access-path → taint record) ─────────────────
const CLEAN = Object.freeze({ clean: true });
class Env {
  constructor() { this.stack = [{ own: new Set(), vars: new Map() }]; }
  push() { this.stack.push({ own: new Set(), vars: new Map() }); }
  pop() { if (this.stack.length > 1) this.stack.pop(); }
  declare(name, rec) { const s = this.stack[this.stack.length - 1]; s.own.add(name); this.set(s, name, rec); }
  set(s, path, rec) {
    for (const k of [...s.vars.keys()]) if (k.startsWith(path + ".")) s.vars.delete(k);
    s.vars.set(path, rec || null);
  }
  scopeOf(base) { for (let s = this.stack.length - 1; s >= 0; s--) if (this.stack[s].own.has(base)) return this.stack[s]; return null; }
  assign(path, rec) { const base = path.split(".")[0]; const s = this.scopeOf(base) || this.stack[0]; s.own.add(base); this.set(s, path, rec); }
  // The record for the longest declared prefix of path: a taint record, CLEAN (proven
  // safe by a guard), or null (not tainted).
  lookup(path) {
    const segs = path.split(".");
    const s = this.scopeOf(segs[0]);
    if (!s) return null;
    for (let k = segs.length; k > 0; k--) { const p = segs.slice(0, k).join("."); if (s.vars.has(p)) return s.vars.get(p); }
    return null;
  }
  // Inside `if (valid(x)) { … }`: x is clean in this block only.
  shadowClean(path) {
    const base = path.split(".")[0], s = this.stack[this.stack.length - 1];
    const outer = this.scopeOf(base);
    s.own.add(base);
    if (outer) for (const [k, v] of outer.vars) if (k === base || k.startsWith(base + ".")) s.vars.set(k, v);
    this.set(s, path, CLEAN);
  }
}

const step = (tok, label) => ({ line: tok.line, col: tok.col, label });
// Long flows keep their source step plus the most recent ones.
const trim = (steps, n = 14) => (steps.length <= n ? steps : [steps[0], ...steps.slice(-(n - 1))]);
const extend = (rec, tok, label) => rec && { ...rec, steps: trim([...rec.steps, step(tok, label)]) };
const clearKinds = (rec, kinds) => rec && { ...rec, cleared: new Set([...rec.cleared, ...kinds]) };
const CMP = new Set(["===", "!==", "==", "!=", "<", ">", "<=", ">=", "instanceof", "in"]);

// ── Analysis ───────────────────────────────────────────────────────────────────
export function taintScan(text, opts = {}) {
  const src = String(text || "");
  if (!src || src.length > (opts.maxBytes || 600000)) return [];
  let T;
  try { T = tokenize(src); } catch (_) { return []; }
  const ctx = scanContext(src);
  const findings = [];
  const seen = new Set();
  budget = opts.budget || 500 * T.length + 2e6; // real files spend under 40 per token
  try {
    const fns = collectFunctions(T);
    const summaries = new Map();
    // Two rounds so a function that calls another one sees its callee's summary.
    for (let round = 0; round < 2; round++) for (const f of fns) {
      const sum = { sinks: [], retParams: new Set(), retSrc: null, params: f.params };
      walk(T, f.bodyOpen + 1, f.bodyClose, { ctx, summaries, mode: "summary", sum, params: f.params, findings, seen });
      summaries.set(f.name, sum);
    }
    walk(T, 0, T.length, { ctx, summaries, mode: "main", findings, seen });
  } catch (e) { if (e !== OUT_OF_BUDGET) throw e; }
  finally { budget = Infinity; }
  return findings.sort((a, b) => a.line - b.line || a.col - b.col);
}

function scanContext(src) {
  const ctx = { cpModules: new Set(), cpNames: new Set(), fsModules: new Set(["fs"]), fsNames: new Set(), jquery: /\$\(|jQuery/.test(src),
    messages: /addEventListener\s*\(\s*["'`]message["'`]|\bonmessage\s*=/.test(src),
    lambda: /exports\.handler\s*=|export\s+(?:const|async\s+function|function)\s+handler\b/.test(src) };
  const modRe = /(?:const|let|var)\s+(\{[^}]{0,2000}\}|[\w$]+)\s*=\s*(?:await\s+)?(?:require|import)\s*\(\s*["'`](?:node:)?([\w./@-]+)["'`]\s*\)(\.promises)?|import\s+(?:\*\s+as\s+([\w$]+)|([\w$]+)(?:\s*,\s*(\{[^}]{0,2000}\}))?|(\{[^}]{0,2000}\}))\s+from\s+["'`](?:node:)?([\w./@-]+)["'`]/g;
  for (const m of src.matchAll(modRe)) {
    const mod = m[2] || m[8];
    const binding = m[1] || m[4] || m[5];
    const named = (m[1] && m[1].startsWith("{") ? m[1] : "") || m[6] || m[7] || "";
    const isCp = /^(?:child_process|shelljs|execa)$/.test(mod), isFs = /^(?:fs|fs\/promises|fs-extra|graceful-fs)$/.test(mod);
    if (!isCp && !isFs) continue;
    if (binding && !binding.startsWith("{")) (isCp ? ctx.cpModules : ctx.fsModules).add(binding);
    for (const part of named.replace(/[{}]/g, "").split(",")) {
      const [orig, alias] = part.split(/\s*(?::|\bas\b)\s*/).map((x) => (x || "").trim());
      const name = alias || orig;
      if (!name) continue;
      if (isCp && /^(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|execa|execaCommand|execaSync|execaCommandSync|\$)$/.test(orig)) ctx.cpNames.add(name);
      if (isFs && FS_METHODS.test(orig)) ctx.fsNames.add(name);
    }
    if (mod === "execa" && binding && !binding.startsWith("{")) ctx.cpNames.add(binding);
    if (mod === "shelljs" && binding) ctx.cpNames.add(binding + ".exec");
  }
  return ctx;
}

// Named functions: `function f(a){}`, `const f = (a) => {}`, `const f = function (a) {}`.
function collectFunctions(T) {
  const out = [];
  for (let i = 0; i < T.length; i++) {
    let name = "", close = -1;
    if (T[i].t === "id" && T[i].v === "function" && T[i + 1] && T[i + 1].t === "id" && isP(T[i + 2], "(")) { name = T[i + 1].v; close = matchClose(T, i + 2); }
    else if (T[i].t === "id" && ["const", "let", "var"].includes(T[i].v) && T[i + 1] && T[i + 1].t === "id" && isP(T[i + 2], "=")) {
      let j = i + 3;
      if (T[j] && T[j].v === "async") j++;
      if (T[j] && T[j].v === "function") { j++; if (T[j] && T[j].t === "id") j++; }
      if (isP(T[j], "(")) { const c = matchClose(T, j); if (isP(T[c + 1], "=>") || T[i + 3].v === "function" || T[j - 1].v === "function" || (T[j - 2] && T[j - 2].v === "function")) { name = T[i + 1].v; close = c; } }
      else if (T[j] && T[j].t === "id" && isP(T[j + 1], "=>")) { name = T[i + 1].v; close = -2; out.push(fnFrom(T, name, [{ name: T[j].v, i: 0, top: true }], j + 2)); continue; }
    }
    if (!name || close < 0) continue;
    let k = close + 1;
    if (isP(T[k], ":")) { while (k < T.length && !isP(T[k], "{") && !isP(T[k], "=>")) k++; }
    if (isP(T[k], "=>")) k++;
    const f = fnFrom(T, name, paramNames(T, close).filter((p) => p.top), k);
    if (f) out.push(f);
  }
  return out.filter(Boolean);
}
function fnFrom(T, name, params, k) {
  if (!isP(T[k], "{")) return null;
  return { name, params, bodyOpen: k, bodyClose: matchClose(T, k) };
}

// Evaluates T[a, b) and returns the taint record that reaches its value, or null.
function evalRange(T, a, b, env, st) {
  if (a >= b) return null;
  spend(b - a);
  let d = 0, q = -1, cmp = false;
  for (let j = a; j < b; j++) {
    const v = T[j].t === "p" ? T[j].v : T[j].t === "id" && (T[j].v === "instanceof" || T[j].v === "in") ? T[j].v : "";
    if (!v) continue;
    if (v === "(" || v === "[" || v === "{") d++;
    else if (v === ")" || v === "]" || v === "}") d--;
    else if (d === 0 && v === "?") { q = j; break; }
    else if (d === 0 && CMP.has(v)) cmp = true;
  }
  if (q >= 0) return evalRange(T, q + 1, b, env, st);
  if (cmp) return null;
  // list.map(cb): the result is what the callback returns for each element
  d = 0;
  let m = -1;
  for (let j = a; j < b; j++) {
    const v = T[j].t === "p" ? T[j].v : "";
    if (v === "(" || v === "[" || v === "{") d++;
    else if (v === ")" || v === "]" || v === "}") d--;
    else if (d === 0 && (v === "." || v === "?.") && T[j + 1] && /^(?:map|flatMap)$/.test(T[j + 1].v) && isP(T[j + 2], "(")) m = j;
  }
  if (m > a) {
    const cl = matchClose(T, m + 2);
    const res = callbackResult(T, m + 3, cl, evalRange(T, a, m, env, st), env, st);
    if (res !== undefined) return res || evalRange(T, cl + 1, b, env, st);
  }
  if (T[a].t === "id" && (T[a].v === "typeof" || T[a].v === "void") || isP(T[a], "!")) return null;
  let found = null;
  for (let j = a; j < b && !found; j++) {
    const t = T[j];
    if (t.t === "id" && t.v === "function") {
      let k = j + 1;
      while (k < b && !isP(T[k], "{")) k++;
      j = k < b ? matchClose(T, k) : k;
      continue;
    }
    if (isP(t, "=>") && isP(T[j + 1], "{")) { j = matchClose(T, j + 1); continue; }
    if (t.t === "tpl") { for (const part of t.parts) { const r = evalRange(part, 0, part.length, env, st); if (r) { found = r; break; } } continue; }
    if (t.t !== "id" || isMember(T, j) || KEYWORDS.has(t.v)) continue;
    const p = pathAt(T, j);
    if (isP(T[p.end], ":") && (isP(T[j - 1], "{") || isP(T[j - 1], ","))) { j = p.end; continue; } // object key, not a value
    const isCall = isP(T[p.end], "(");
    if (isCall) {
      const close = matchClose(T, p.end);
      if (SCALAR_RESULT.test(p.path) || HTTP_CLIENT.test(p.path) || /\.(?:query|execute|readFile|readFileSync)$/.test(p.path)) { j = close; continue; }
      if (/\.(?:replace|replaceAll)$/.test(p.path) && T[p.end + 1] && T[p.end + 1].t === "re" && ALLOWLIST_STRIP.test(T[p.end + 1].v)) { j = close; continue; }
      const kinds = sanitizerKinds(p.path);
      if (kinds) { const inner = evalRange(T, p.end + 1, close, env, st); if (inner) found = clearKinds(inner, kinds); j = close; continue; }
      const sum = st.summaries.get(p.path);
      if (sum) {
        const as = args(T, p.end, close);
        let r = sum.retSrc ? extend(sum.retSrc, t, "returned by " + p.path + "()") : null;
        for (const i of sum.retParams) if (!r && as[i]) { const ar = evalRange(T, as[i][0], as[i][1], env, st); if (ar) r = extend(ar, t, "passed through " + p.path + "()"); }
        if (r) found = r;
        j = close;
        continue;
      }
    }
    if (/\.length$/.test(p.path)) { j = p.end - 1; continue; }
    const r = env.lookup(p.path);
    if (isP(T[p.end], "[") && !r && !sourceOf(p.path, false, st.ctx) && /^[A-Z][A-Z0-9_]*$/.test(p.path.split(".").pop())) { j = matchClose(T, p.end); continue; }
    if (r === CLEAN) { j = p.end - 1; continue; }
    const s = sourceOf(p.path, isCall, st.ctx);
    if (s) { found = { origin: "src", side: s.side, label: p.path, steps: [step(t, "untrusted input: " + p.path + (isCall ? "()" : ""))], cleared: new Set() }; break; }
    if (r) { found = r; break; }
    j = p.end - 1;
  }
  return found;
}

// Taint carried by the element parameter of an inline callback: list.forEach(x => …),
// promise.then(v => …), arr.reduce((acc, x) => …). Returns { rec, index } or null.
const ITER = /^(?:map|flatMap|forEach|filter|find|findLast|some|every|then|reduce|sort)$/;
function callbackRecv(T, start, env, st) {
  if (T[start] && T[start].v === "async") start--;
  if (!isP(T[start - 1], "(")) return null;
  const meth = T[start - 2];
  if (!meth || meth.t !== "id" || !ITER.test(meth.v) || !(isP(T[start - 3], ".") || isP(T[start - 3], "?."))) return null;
  const cb = chainBase(T, start - 3);
  if (cb.idx == null) return null;
  const rec = evalRange(T, cb.idx, start - 3, env, st);
  return rec ? { rec, index: meth.v === "reduce" ? 1 : 0 } : null;
}
function bindCallbackParams(T, start, ps, env, st) {
  const cr = callbackRecv(T, start, env, st);
  if (cr && ps[cr.index]) ps[cr.index] = { ...ps[cr.index], rec: extend(cr.rec, T[start], "each element as " + ps[cr.index].name) };
  return ps;
}

// What an inline callback returns, given the taint of the list it is called on.
// undefined when the argument is not an inline function.
function callbackResult(T, x, y, recv, env, st) {
  let k = x, params, arrow;
  if (T[k] && T[k].v === "async") k++;
  if (T[k] && T[k].t === "id" && isP(T[k + 1], "=>")) { params = [{ name: T[k].v }]; arrow = k + 1; }
  else if (isP(T[k], "(")) { const c = matchClose(T, k); if (!isP(T[c + 1], "=>")) return undefined; params = paramNames(T, c); arrow = c + 1; }
  else return undefined;
  const first = params[0];
  const rec = first && recv ? extend(recv, T[k], "each element as " + first.name) : null;
  if (isP(T[arrow + 1], "{")) {
    const open = arrow + 1, close = matchClose(T, open);
    const sum = { sinks: [], retParams: new Set(), retSrc: null, retRec: null, params: [] };
    walk(T, open + 1, close, { ...st, mode: "summary", sum, params: first ? [{ name: first.name, i: 0, rec }] : [], parentEnv: env });
    return sum.retRec;
  }
  env.push();
  if (first) env.declare(first.name, rec);
  const r = evalRange(T, arrow + 1, y, env, st);
  env.pop();
  return r;
}

function walk(T, a, b, st) {
  spend(b - a);
  const env = st.parentEnv || new Env();
  const depth0 = env.stack.length; // restored at the end, so a shared parent env stays balanced
  const popAt = new Map();
  const pendingParams = new Map();
  if (st.mode === "summary") {
    env.push();
    for (const p of st.params) env.declare(p.name, "rec" in p ? p.rec : { origin: "param", i: p.i, label: p.name, steps: [step(T[a - 1] || T[a], "parameter " + p.name)], cleared: new Set() });
  }
  const report = (rec, sink, tok, extraSteps = []) => {
    if (!rec || rec.cleared.has(sink.kind)) return;
    if (sink.server && rec.origin === "src" && rec.side !== "server") return;
    if (rec.origin === "param") {
      if (st.mode === "summary") st.sum.sinks.push({ i: rec.i, kind: sink.kind, steps: [...rec.steps, ...extraSteps, step(tok, sinkLabel(sink.kind))], tok, reflected: sink.reflected });
      return;
    }
    if (st.mode !== "main") return;
    const info = SINK_INFO[sink.kind];
    const key = sink.kind + ":" + tok.line + ":" + rec.steps[0].line;
    if (st.seen.has(key)) return;
    st.seen.add(key);
    let sev = info.sev;
    if (sink.kind === "xss" && sink.reflected) sev = "medium";
    if (sink.kind === "redirect" && rec.side === "client") sev = "medium";
    st.findings.push({ kind: sink.kind, ruleId: "js.taint." + sink.kind, title: info.title, sev, cwe: info.cwe, line: tok.line, col: tok.col, why: info.why, fix: info.fix,
      flow: trim([...rec.steps, ...extraSteps, step(tok, sinkLabel(sink.kind))], 16) });
  };

  for (let j = a; j < b; j++) {
    const t = T[j];
    if (popAt.has(j)) { for (let k = popAt.get(j); k > 0; k--) env.pop(); popAt.delete(j); }
    // Scope tracking
    if (isP(t, "{")) {
      env.push();
      const ps = pendingParams.get(j);
      if (ps) for (const p of ps) p.guard ? env.shadowClean(p.guard) : env.declare(p.name, p.rec || null);
      else if (isP(T[j - 1], ")")) {
        const open = matchOpen(T, j - 1);
        const before = T[open - 1];
        if (!(before && before.t === "id" && ["if", "for", "while", "switch", "with"].includes(before.v))) {
          const fnAt = before && before.v === "function" ? open - 1 : T[open - 2] && T[open - 2].v === "function" ? open - 2 : -1;
          const ps = paramNames(T, j - 1);
          for (const p of fnAt >= 0 ? bindCallbackParams(T, fnAt, ps, env, st) : ps) env.declare(p.name, p.rec || null);
        }
      }
      continue;
    }
    if (isP(t, "}")) { env.pop(); continue; }
    if (isP(t, "=>")) {
      const start = isP(T[j - 1], ")") ? matchOpen(T, j - 1) : j - 1;
      const ps = bindCallbackParams(T, start, isP(T[j - 1], ")") ? paramNames(T, j - 1) : T[j - 1] && T[j - 1].t === "id" ? [{ name: T[j - 1].v }] : [], env, st);
      if (isP(T[j + 1], "{")) pendingParams.set(j + 1, ps);
      else { env.push(); for (const p of ps) env.declare(p.name, p.rec || null); const e = exprEnd(T, j + 1, b); popAt.set(e, (popAt.get(e) || 0) + 1); }
      continue;
    }
    if (t.t !== "id") {
      // `.prop = value` on a call result, e.g. document.getElementById("x").innerHTML = v
      if (isP(t, ".") && T[j + 1] && T[j + 1].t === "id" && (isP(T[j + 2], "=") || isP(T[j + 2], "+=")) && !isP(T[j - 1], ".")) {
        const kind = ASSIGN_SINK(T[j + 1].v);
        if (kind && (isP(T[j - 1], ")") || isP(T[j - 1], "]"))) report(evalRange(T, j + 3, exprEnd(T, j + 3, b), env, st), { kind }, T[j + 1]);
      }
      // method call on a call result: foo().bar(x)
      if (isP(t, ".") && T[j + 1] && T[j + 1].t === "id" && isP(T[j + 2], "(") && (isP(T[j - 1], ")") || isP(T[j - 1], "]"))) {
        const cb = chainBase(T, j);
        if (cb.base !== "require") handleCall(T, j + 1, j + 2, { path: "", meth: T[j + 1].v, base: cb.base, text: cb.text }, false, env, st, report, b);
      }
      continue;
    }
    // Declarations (the walk then continues into the initialiser, so calls and
    // function bodies inside it are analysed too)
    if (t.v === "const" || t.v === "let" || t.v === "var") { j = declaration(T, j, b, env, st) - 1; continue; }
    if (t.v === "import" && isP(T[j + 1], "(")) { handleCall(T, j, j + 1, { path: "import", meth: "", base: "" }, false, env, st, report, b); continue; }
    if (t.v === "dangerouslySetInnerHTML" && isP(T[j + 1], "=")) {
      const k = T.findIndex((x, m) => m > j && m < j + 8 && x.t === "id" && x.v === "__html");
      if (k > 0 && isP(T[k + 1], ":")) report(evalRange(T, k + 2, exprEnd(T, k + 2, b), env, st), { kind: "xss" }, t);
      continue;
    }
    // Guards: if (!valid(x)) return/throw;  if (valid(x)) { …x is clean here… }
    if (t.v === "if" && isP(T[j + 1], "(")) { guard(T, j, env, pendingParams); continue; }
    if (t.v === "return" && st.mode === "summary") {
      const r = evalRange(T, j + 1, exprEnd(T, j + 1, b), env, st);
      if (r && !st.sum.retRec) st.sum.retRec = r;
      if (r && r.origin === "param") st.sum.retParams.add(r.i);
      else if (r && !st.sum.retSrc) st.sum.retSrc = r;
      continue;
    }
    if (isMember(T, j) || KEYWORDS.has(t.v)) continue;
    const p = pathAt(T, j);
    const op = T[p.end];
    // Assignment
    if (op && op.t === "p" && ["=", "+=", "||=", "??="].includes(op.v)) {
      const e = exprEnd(T, p.end + 1, b);
      const rec = evalRange(T, p.end + 1, e, env, st);
      const kind = ASSIGN_SINK(p.path);
      if (kind) report(rec, { kind }, T[p.end - 1] || t);
      if (op.v === "=") env.assign(p.path, rec ? extend(rec, t, "assigned to " + p.path) : null);
      else if (rec) env.assign(p.path, extend(rec, t, "appended to " + p.path));
      continue;
    }
    // Call
    // A call, unless this is a declaration: `function f(…) {` or a method `f(…) {`
    if (isP(op, "(") && !(T[j - 1] && T[j - 1].v === "function") && !isP(T[matchClose(T, p.end) + 1], "{")) {
      const isNew = T[j - 1] && T[j - 1].t === "id" && T[j - 1].v === "new";
      const segs = p.path.split(".");
      handleCall(T, j, p.end, { path: p.path, meth: segs.length > 1 ? segs[segs.length - 1] : "", base: segs.length > 1 ? segs[0] : "" }, isNew, env, st, report, b);
    }
    j = p.end - 1;
  }
  env.stack.length = depth0;
}

function sinkLabel(kind) {
  return { code: "evaluated as code", cmd: "run as a shell command", sql: "executed as SQL", nosql: "used as a query object", xss: "rendered as HTML",
    redirect: "used as a redirect target", path: "used as a file path", ssrf: "fetched by the server", regex: "compiled as a RegExp", module: "loaded as a module" }[kind];
}

function handleCall(T, j, open, callee, isNew, env, st, report, b) {
  const close = matchClose(T, open);
  const as = args(T, open, close);
  for (const sink of sinksForCall(callee, st.ctx, isNew)) {
    const idx = sink.arg === "any" ? as.map((_, i) => i) : sink.arg === "last" ? [as.length - 1] : [sink.arg];
    for (const i of idx) {
      if (!as[i]) continue;
      const [x, y] = as[i];
      if (sink.strOnly && (isP(T[x], "(") || T[x].v === "function" || T.slice(x, y).some((k) => isP(k, "=>")))) continue;
      if (sink.kind === "ssrf" && (T[x].t === "str" || T[x].t === "tpl") && /^https?:\/\/[^/$]+\//i.test(T[x].v)) continue;
      if (sink.kind === "path" && sink.noRoot && as.length > 1) continue;
      if (sink.kind === "nosql" && sink.direct && !(T[x].t === "id" || isP(T[x], "{"))) continue;
      const rec = evalRange(T, x, y, env, st);
      if (sink.kind === "nosql" && rec && rec.origin === "src" && !/body|query/.test(rec.label)) continue;
      report(rec, sink, T[j]);
    }
  }
  // Calls into same-file functions whose parameters reach a sink.
  const sum = callee.path && st.summaries.get(callee.path);
  if (sum) for (const s of sum.sinks) {
    if (!as[s.i]) continue;
    const rec = evalRange(T, as[s.i][0], as[s.i][1], env, st);
    if (!rec) continue;
    report(rec, { kind: s.kind, reflected: s.reflected, server: ["sql", "nosql", "ssrf", "regex", "module", "path"].includes(s.kind) },
      s.tok, [step(T[j], "passed to " + callee.path + "() as " + (sum.params[s.i] ? sum.params[s.i].name : "argument " + (s.i + 1))), ...s.steps.slice(0, -1)]);
  }
}

function declaration(T, j, b, env, st) {
  let k = j + 1, resume = -1;
  for (;;) {
    const tgt = T[k];
    if (!tgt) return resume >= 0 ? resume : k;
    let names = [], afterBind;
    if (tgt.t === "id") { names = [{ name: tgt.v, sub: "" }]; afterBind = k + 1; }
    else if (isP(tgt, "{") || isP(tgt, "[")) {
      const close = matchClose(T, k);
      let idx = 0;
      for (let m = k + 1; m < close; m++) {
        if (T[m].t !== "id") continue;
        const prev = T[m - 1], next = T[m + 1];
        if (isP(prev, ":") || isP(prev, "=") ) { if (isP(prev, ":")) names[names.length - 1] && (names[names.length - 1].name = T[m].v); continue; }
        if (isP(prev, "{") || isP(prev, ",") || isP(prev, "[") || isP(prev, "...")) names.push({ name: T[m].v, sub: isP(tgt, "{") && !isP(prev, "...") ? "." + T[m].v : isP(tgt, "[") ? "." + idx++ : "" });
        if (isP(next, "=")) { let d = 0; while (m < close && !(d === 0 && isP(T[m + 1], ","))) { m++; if (T[m].t === "p" && "([{".includes(T[m].v)) d++; else if (T[m].t === "p" && ")]}".includes(T[m].v)) d--; } }
      }
      afterBind = close + 1;
    } else return resume >= 0 ? resume : k;
    if (isP(T[afterBind], ":")) { let d = 0; while (afterBind < b && !(d === 0 && (isP(T[afterBind], "=") || isP(T[afterBind], ";") || isP(T[afterBind], ",") || T[afterBind].nl && afterBind > k + 2))) { const v = T[afterBind].t === "p" ? T[afterBind].v : ""; if ("([{<".includes(v) && v) d++; else if (")]}>".includes(v) && v) d--; afterBind++; } }
    let end = afterBind, rec = null;
    if (resume < 0) resume = afterBind + (isP(T[afterBind], "=") || (T[afterBind] && (T[afterBind].v === "of" || T[afterBind].v === "in")) ? 1 : 0);
    if (isP(T[afterBind], "=")) {
      end = exprEnd(T, afterBind + 1, b);
      rec = evalRange(T, afterBind + 1, end, env, st);
    } else if (T[afterBind] && T[afterBind].t === "id" && (T[afterBind].v === "of" || T[afterBind].v === "in")) {
      end = exprEnd(T, afterBind + 1, b);
      rec = T[afterBind].v === "of" ? evalRange(T, afterBind + 1, end, env, st) : null;
    }
    // Declared names live in the scope the for-loop body will open; declare now.
    for (const nm of names) env.declare(nm.name, rec ? extend(rec, T[k], "assigned to " + nm.name) : null);
    if (isP(T[end], ",")) { k = end + 1; continue; }
    return resume;
  }
}

function guard(T, j, env, pendingParams) {
  const open = j + 1, close = matchClose(T, open);
  let a = open + 1, neg = false;
  if (isP(T[a], "!")) { neg = true; a++; }
  if (isP(T[a], "(") && matchClose(T, a) === close - 1) a++;
  // the condition is a single validator call on one path
  let p = T[a] && T[a].t === "id" ? pathAt(T, a) : null;
  let callOpen = p && p.end;
  if (T[a] && T[a].t === "re" && isP(T[a + 1], ".") && T[a + 2] && T[a + 2].v === "test") { p = { path: "re.test", end: a + 3 }; callOpen = a + 3; }
  if (!p || !isP(T[callOpen], "(") || (!neg && !VALIDATOR.test(p.path)) || (neg && FS_PROBE.test(p.path))) return;
  const cl = matchClose(T, callOpen);
  const as = args(T, callOpen, cl);
  const target = as.length === 1 && T[as[0][0]].t === "id" ? pathAt(T, as[0][0]) : null;
  if (!target || target.end !== as[0][1]) return;
  if (neg) {
    // if (!valid(x)) return / throw / { …; return }
    let k = close + 1;
    const exits = (m) => T[m] && T[m].t === "id" && (T[m].v === "return" || T[m].v === "throw");
    let ok = exits(k);
    if (!ok && isP(T[k], "{")) { const e = matchClose(T, k); for (let m = k + 1; m < e; m++) if (exits(m)) { ok = true; break; } }
    if (ok) env.assign(target.path, CLEAN);
  } else if (isP(T[close + 1], "{")) {
    pendingParams.set(close + 1, [{ guard: target.path }]);
  }
}
