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

// jargon -> plain (stupid / "simple" mode)
const SIMPLIFY = {
  "reconnaissance": "looking around", "enumeration": "listing things out", "enumerate": "list out",
  "authentication": "login", "authenticate": "log in", "credentials": "passwords", "credential": "password",
  "vulnerability": "weak spot", "vulnerabilities": "weak spots", "exploit": "attack trick", "exploits": "attack tricks",
  "mitigation": "fix", "mitigate": "fix", "remediation": "fix", "remediate": "fix",
  "configuration": "settings", "configure": "set up", "initialize": "start", "initialise": "start",
  "terminal": "command box", "repository": "code folder", "repositories": "code folders",
  "deploy": "put live", "deployment": "going live", "encryption": "scrambling", "encrypt": "scramble", "decrypt": "unscramble",
  "payload": "attack code", "reconnoiter": "scout", "dashboard": "main screen",
  "parameters": "settings", "parameter": "setting", "execute": "run", "invoke": "run",
  "generate": "make", "regenerate": "make a new one", "revoke": "cancel", "documentation": "guides",
  "subdomain": "sub-site", "subdomains": "sub-sites", "reputation": "trust score",
  "threat intelligence": "danger info", "intelligence": "info", "adversary": "attacker", "adversaries": "attackers",
  "persistence": "staying in", "privilege escalation": "getting more power", "lateral movement": "spreading sideways",
  "obfuscate": "hide", "obfuscation": "hiding", "artifact": "leftover file", "artifacts": "leftover files",
  "query": "ask", "aggregate": "add up", "concatenate": "join", "instantiate": "make",
  "latency": "delay", "throughput": "speed", "endpoint": "web address", "token": "pass code",
};

// plain -> jargon (confusing mode)
const COMPLICATE = {
  "login": "authentication handshake", "log in": "authenticate", "sign in": "establish an authenticated session",
  "password": "credential material", "passwords": "credential material", "settings": "configuration parameters",
  "options": "parameterized preferences", "start": "initialize", "run": "execute", "make": "instantiate",
  "new": "freshly provisioned", "save": "persist", "saved": "persisted", "delete": "irrevocably purge",
  "copy": "duplicate to the clipboard buffer", "search": "query the index", "find": "resolve against the index",
  "tools": "instrumented capabilities", "tool": "instrumented capability", "home": "primary operational nexus",
  "fix": "remediate", "scan": "enumerate the attack surface of", "check": "perform a verification pass on",
  "look around": "conduct reconnaissance", "attacker": "threat actor", "attackers": "threat actors",
  "weak spot": "latent vulnerability", "weak spots": "latent vulnerabilities", "info": "intelligence",
  "danger": "threat vector", "hide": "obfuscate", "join": "concatenate", "add up": "aggregate",
  "speed": "throughput", "delay": "latency", "report": "generated intelligence artifact",
  "key": "cryptographic key material", "connect": "establish a session with", "download": "retrieve the distribution bundle for",
  "upload": "transmit to the ingestion endpoint", "error": "unhandled exception condition", "warning": "non-fatal advisory",
  "page": "rendered view", "screen": "operational surface", "account": "principal identity",
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
