// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Reading modes — rewrites the interface's wording in place so the same screen
// can read three ways:
//   normal     — the text exactly as written (default; no transform, no cost).
//   stupid      — plain, everyday language: jargon swapped for the simplest word.
//   confusing   — dense technical register: plain words swapped for jargon.
//
// There is no central string table in this app — copy is written inline across
// hundreds of render functions — so this works on the rendered DOM instead: it
// walks visible text nodes and rewrites whole words/phrases, caching each node's
// original so switching back is exact and switching between modes never chains
// one translation on top of another (every transform starts from the original).
//
// Safety: only text nodes are touched (never attributes, ids, classes or values),
// so click handlers, copy buttons and the terminal keep working. Code, inputs,
// the live terminal and anything marked [data-noreading] are skipped. When the
// mode is "normal" the observer is disconnected and originals restored, so the
// default costs nothing. Zero dependencies.

const KEY = "dn_read_mode";
const MODES = ["normal", "stupid", "confusing"];

// Elements whose text is code, input, or machine-read — never rewritten.
const SKIP_TAGS = new Set([
  "SCRIPT", "STYLE", "NOSCRIPT", "CODE", "PRE", "KBD", "SAMP", "VAR",
  "TEXTAREA", "INPUT", "SELECT", "OPTION", "SVG", "CANVAS", "MATH",
]);
// Regions that carry live/technical text we must not touch.
const SKIP_SELECTOR = "[data-noreading],.mono,[contenteditable=''],[contenteditable='true'],#term,.xterm,.terminal,.cm-editor,.cli,.code,pre";

// jargon -> plain (stupid / "simple" mode): swap every hard word for the
// easiest word a young child would know. Keep phrases tiny and literal.
const SIMPLIFY = {
  // security jargon
  "reconnaissance": "looking around", "reconnoiter": "scout", "reconnoitre": "scout",
  "enumeration": "listing things out", "enumerate": "list out",
  "authentication": "login", "authenticate": "log in", "authenticated": "logged in", "authorization": "permission", "authorize": "allow",
  "credentials": "passwords", "credential": "password",
  "vulnerability": "weak spot", "vulnerabilities": "weak spots", "exploit": "attack trick", "exploits": "attack tricks", "exploitation": "attacking",
  "mitigation": "fix", "mitigate": "fix", "remediation": "fix", "remediate": "fix",
  "configuration": "settings", "configure": "set up", "configured": "set up", "initialize": "start", "initialise": "start", "initialization": "start",
  "terminal": "command box", "repository": "code folder", "repositories": "code folders",
  "deploy": "put live", "deployment": "going live", "encryption": "scrambling", "encrypt": "scramble", "encrypted": "scrambled", "decrypt": "unscramble",
  "payload": "attack code", "dashboard": "main screen", "malware": "bad program", "ransomware": "lock-up virus",
  "firewall": "safety wall", "phishing": "fake email trap", "malicious": "bad", "benign": "safe",
  "parameters": "settings", "parameter": "setting", "execute": "run", "execution": "running", "invoke": "run",
  "generate": "make", "generated": "made", "regenerate": "make a new one", "revoke": "cancel", "documentation": "guides",
  "subdomain": "sub-site", "subdomains": "sub-sites", "reputation": "trust score",
  "threat intelligence": "danger info", "intelligence": "info", "adversary": "attacker", "adversaries": "attackers",
  "persistence": "staying in", "privilege escalation": "getting more power", "lateral movement": "spreading sideways",
  "obfuscate": "hide", "obfuscation": "hiding", "artifact": "leftover file", "artifacts": "leftover files",
  "query": "ask", "queries": "asks", "aggregate": "add up", "concatenate": "join", "instantiate": "make",
  "latency": "delay", "throughput": "speed", "endpoint": "web address", "token": "pass code",
  // everyday computer words
  "utilize": "use", "utilise": "use", "leverage": "use", "implement": "build", "implementation": "build",
  "configuration file": "settings file", "directory": "folder", "directories": "folders",
  "navigate": "go", "navigation": "menu", "interface": "screen", "functionality": "features", "feature": "thing it does",
  "component": "part", "components": "parts", "module": "part", "modules": "parts",
  "retrieve": "get", "retrieval": "getting", "validate": "check", "validation": "check", "verify": "check", "verification": "check",
  "optimize": "speed up", "optimise": "speed up", "optimization": "speed-up",
  "synchronize": "match up", "synchronise": "match up", "asynchronous": "at its own pace",
  "prioritize": "put first", "prioritise": "put first", "facilitate": "help", "demonstrate": "show",
  "approximately": "about", "subsequently": "then", "additionally": "also", "furthermore": "also", "however": "but", "therefore": "so",
  "sufficient": "enough", "insufficient": "not enough", "require": "need", "requires": "needs", "required": "needed", "requirement": "need",
  "numerous": "many", "various": "different", "multiple": "many", "individual": "single", "entire": "whole",
  "commence": "start", "terminate": "stop", "modify": "change", "modification": "change", "eliminate": "remove", "acquire": "get",
  "assistance": "help", "attempt": "try", "purchase": "buy", "obtain": "get", "provide": "give", "construct": "build",
  "comprehend": "understand", "ascertain": "find out", "indicate": "show", "permit": "let", "prohibit": "stop",
  "fundamental": "basic", "essential": "needed", "critical": "very important", "significant": "big", "minimal": "tiny",
  "advanced": "fancy", "comprehensive": "full", "capabilities": "powers", "capability": "power",
  "automatically": "on its own", "manually": "by hand", "simultaneously": "at the same time", "immediately": "right away",
};

// plain -> jargon (confusing mode): swap every plain word for the most
// confusing, longest, most show-off word a human could pick. Go big.
const COMPLICATE = {
  // security / app jargon
  "login": "authentication handshake", "log in": "authenticate against the identity provider", "sign in": "establish an authenticated session",
  "logout": "tear down the authenticated session", "log out": "invalidate the session principal", "sign out": "deprovision the active session",
  "password": "cryptographic credential material", "passwords": "cryptographic credential material", "settings": "configuration parameterizations",
  "options": "parameterized preference affordances", "start": "inaugurate the operational lifecycle of", "run": "execute to completion", "running": "undergoing execution",
  "make": "instantiate", "made": "instantiated", "new": "freshly provisioned", "save": "durably persist", "saved": "durably persisted",
  "delete": "irrevocably expurgate", "deleted": "irrevocably expurgated", "remove": "decommission",
  "copy": "serialize into the clipboard buffer", "paste": "deserialize from the clipboard buffer", "search": "interrogate the inverted index",
  "find": "resolve against the canonical index", "tools": "instrumented capability surfaces", "tool": "instrumented capability surface",
  "home": "primary operational nexus", "fix": "remediate", "scan": "forensically enumerate", "scan for": "forensically enumerate the attack surface for", "check": "perform a conformance verification pass upon",
  "look around": "conduct reconnaissance", "attacker": "malicious threat actor", "attackers": "malicious threat actors",
  "weak spot": "latent exploitable vulnerability", "weak spots": "latent exploitable vulnerabilities", "info": "actionable intelligence",
  "danger": "materialized threat vector", "hide": "obfuscate", "join": "concatenate", "add up": "aggregate",
  "speed": "aggregate throughput", "delay": "end-to-end latency", "report": "synthesized intelligence artifact",
  "key": "cryptographic keying material", "connect": "establish a bidirectional session with", "download": "retrieve the distribution bundle for",
  "upload": "transmit to the ingestion endpoint", "error": "unhandled exception condition", "warning": "non-fatal advisory notification",
  "page": "rendered presentation surface", "screen": "operational presentation surface", "account": "principal identity object",
  // flamboyant everyday swaps — the "most confusing words in history"
  "use": "leverage", "used": "leveraged", "using": "leveraging", "help": "furnish adjuvant facilitation to", "helps": "furnishes adjuvant facilitation to",
  "show": "surface for visual apprehension", "shows": "surfaces for visual apprehension", "see": "visually apprehend",
  "get": "procure", "got": "procured", "give": "disburse", "put": "emplace", "add": "augment with", "build": "architect",
  "change": "effectuate a mutation upon", "fast": "expeditious", "slow": "dilatory", "easy": "frictionless", "hard": "non-trivial",
  "simple": "parsimonious", "small": "diminutive", "big": "voluminous", "many": "a multiplicity of", "few": "a paucity of",
  "good": "efficacious", "bad": "deleterious", "best": "optimal", "better": "ameliorated", "important": "of paramount salience",
  "basic": "rudimentary", "main": "preeminent", "about": "with respect to", "also": "furthermore", "but": "notwithstanding",
  "so": "ergo", "then": "subsequently", "now": "at the present juncture", "always": "invariably", "never": "under no circumstances",
  "free": "gratis and unencumbered", "safe": "security-hardened", "open": "unencapsulated", "private": "hermetically siloed",
  "learn": "assimilate knowledge regarding", "understand": "achieve cognitive apprehension of", "think": "cogitate", "know": "possess epistemic certainty of",
  "need": "necessitate", "want": "harbor a predilection for", "try": "endeavor to", "work": "be operationally efficacious",
  "data": "informational payload corpus", "file": "serialized data artifact", "folder": "hierarchical storage container",
  "list": "enumerated manifest", "menu": "navigational affordance matrix", "button": "interactive actuation control",
  "name": "canonical designator", "question": "interrogative proposition", "answer": "dispositive resolution",
};

function escRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

// Preserve the casing of what was matched: Capitalized -> Capitalized,
// ALL CAPS -> ALL CAPS, anything else -> the replacement's own (lower) casing.
function matchCase(orig, repl) {
  if (orig === orig.toUpperCase() && /[A-Z]/.test(orig)) return repl.toUpperCase();
  if (/^[A-Z]/.test(orig)) return repl.charAt(0).toUpperCase() + repl.slice(1);
  return repl;
}

// One alternation regex over the whole map (longest keys first), so each span is
// rewritten exactly once and later keys never re-hit an earlier replacement.
function buildReplacer(map) {
  const keys = Object.keys(map).sort((a, b) => b.length - a.length);
  const re = new RegExp("\\b(" + keys.map(escRe).join("|") + ")\\b", "gi");
  const lut = {}; for (const k of keys) lut[k.toLowerCase()] = map[k];
  return (text) => text.replace(re, (m) => matchCase(m, lut[m.toLowerCase()] || m));
}

const SIMPLIFY_RE = buildReplacer(SIMPLIFY);
const COMPLICATE_RE = buildReplacer(COMPLICATE);

function transform(text, mode) {
  if (mode === "stupid") return SIMPLIFY_RE(text);
  if (mode === "confusing") return COMPLICATE_RE(text);
  return text;
}

// --- DOM plumbing ------------------------------------------------------------
const originals = new WeakMap(); // text node -> its untransformed value
let mode = read();
let observer = null;
let applying = false;        // re-entrancy guard against our own writes
let scheduled = 0;

function read() {
  try { const m = localStorage.getItem(KEY); return MODES.includes(m) ? m : "normal"; } catch (_) { return "normal"; }
}

function rootEl() { return document.getElementById("app") || document.body; }

function skip(node) {
  const p = node.parentElement;
  if (!p) return true;
  for (let el = p; el; el = el.parentElement) { if (SKIP_TAGS.has(el.tagName)) return true; if (el.id === "app") break; }
  return !!(p.closest && p.closest(SKIP_SELECTOR));
}

function processNode(tn) {
  const raw = tn.nodeValue;
  if (!raw || !/[A-Za-z]/.test(raw)) return;        // whitespace / numeric only
  let orig = originals.get(tn);
  if (orig === undefined) { orig = raw; originals.set(tn, orig); }
  const next = transform(orig, mode);
  if (next !== tn.nodeValue) tn.nodeValue = next;
}

function walkAndApply(root) {
  const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
    acceptNode: (n) => (n.nodeValue && /[A-Za-z]/.test(n.nodeValue) && !skip(n))
      ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT,
  });
  const nodes = [];
  for (let n = w.nextNode(); n; n = w.nextNode()) nodes.push(n);
  applying = true;
  try { for (const n of nodes) processNode(n); } finally { applying = false; }
}

function restoreAll(root) {
  const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
  applying = true;
  try {
    for (let n = w.nextNode(); n; n = w.nextNode()) {
      const o = originals.get(n);
      if (o !== undefined && n.nodeValue !== o) n.nodeValue = o;
    }
  } finally { applying = false; }
}

function schedule() {
  if (scheduled) return;
  scheduled = (window.requestAnimationFrame || window.setTimeout)(() => {
    scheduled = 0;
    if (mode !== "normal") walkAndApply(rootEl());
  }, 120);
}

function startObserver() {
  if (observer || !window.MutationObserver) return;
  observer = new MutationObserver((muts) => {
    if (applying) return;
    for (const m of muts) {
      if (m.type === "childList" && m.addedNodes.length) { schedule(); return; }
      if (m.type === "characterData") { schedule(); return; }
    }
  });
  try { observer.observe(rootEl(), { childList: true, characterData: true, subtree: true }); } catch (_) {}
}

function stopObserver() { if (observer) { try { observer.disconnect(); } catch (_) {} observer = null; } }

// --- public API --------------------------------------------------------------
export function getReadMode() { return mode; }

export function setReadMode(next) {
  if (!MODES.includes(next)) next = "normal";
  mode = next;
  try { localStorage.setItem(KEY, next); } catch (_) {}
  const root = rootEl();
  if (mode === "normal") { stopObserver(); restoreAll(root); }
  else { walkAndApply(root); startObserver(); }
  return mode;
}

let inited = false;
export function initReadingModes() {
  if (inited) { if (mode !== "normal") walkAndApply(rootEl()); return; } // idempotent
  inited = true;
  mode = read();
  if (mode !== "normal") {
    const go = () => { walkAndApply(rootEl()); startObserver(); };
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", go, { once: true });
    else go();
  }
}

// Re-apply after a full-page re-render that replaced the root (SPA navigation).
export function reapplyReadingMode() { if (mode !== "normal") walkAndApply(rootEl()); }
