// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
(function(){var _h=location.hostname,_a=["darknode.ai","www.darknode.ai","darknode-official.github.io","sentinel-b4194.web.app","sentinel-b4194-6173e.web.app","localhost","127.0.0.1"];if(!_a.some(function(d){return _h===d}))throw document.body.innerHTML="",new Error("unlicensed")}());
import { auth, db, googleProvider, githubProvider, OWNER_EMAIL } from "/js/firebase.js";
import "/js/scroll-top.js?v=20260924b";
import "/js/shortcuts.js";
import "/js/mobile-nav.js";
import { showToast } from "/js/toast.js?v=20260924a";
import { collection as fbCollection, addDoc as fbAddDoc, serverTimestamp as fbServerTimestamp } from "https://www.gstatic.com/firebasejs/12.17.0/firebase-firestore.js";
import {
  onAuthStateChanged, signInWithRedirect, getRedirectResult, signOut,
  createUserWithEmailAndPassword, signInWithEmailAndPassword,
  sendEmailVerification, sendPasswordResetEmail, reload,
  setPersistence, browserLocalPersistence
} from "https://www.gstatic.com/firebasejs/12.17.0/firebase-auth.js";
import {
  doc, getDoc, setDoc, serverTimestamp
} from "https://www.gstatic.com/firebasejs/12.17.0/firebase-firestore.js";
let MORE = [], CATALOG = [], CATEGORIES = [];
import("/js/toolkit.js").then(m => { MORE = m.MORE; CATALOG = m.CATALOG; CATEGORIES = m.CATEGORIES; });
import { startTour, tourDone } from "/js/tour.js";
let _landing = null;
async function loadLanding() { if (!_landing) _landing = await import("/js/landing.js?v=20260924a"); return _landing; }

// Plain-language, newbie-friendly one-liners for every sidebar item + group.
// Surfaced as a hover tooltip so the sidebar stays visually neat while every
// jargony tool name explains itself. Keyed by data-sec (items) / label (groups).
const SIDE_DESC = {
  home: "Your home base — activity, stats and quick links. Start here.",
  // Mission Control
  prometheus: "Live threat-intelligence feed — new CVEs and vulnerabilities as they break.",
  sentineleye: "A 3D world map of live cyber threats, aircraft, satellites and attacks.",
  hydra: "Automated recon and vulnerability scanning across many targets at once.",
  aegis: "Command center for planning and coordinating your security work.",
  vanguard: "Threat hunting with attack kill-chain visualization.",
  phantom: "Network traffic analysis — read packet captures and spot anomalies.",
  citadel: "SOC operations — correlate logs, write detection rules, triage alerts.",
  oracle: "Threat-intel platform — manage indicators (IOCs) and track attacker campaigns.",
  spectre: "Cloud security posture checks for AWS, Azure and GCP.",
  crucible: "Cyber wargaming range — run and score simulated attack-vs-defense exercises.",
  navarch: "Naval & maritime cyber-defense — fleet integrity and AIS anti-spoofing.",
  secdash: "One screen showing your overall security posture at a glance.",
  // Offensive Security
  attacksim: "Safely simulate real attacker techniques (MITRE ATT&CK).",
  cracklab: "Password-cracking lab — test how strong password hashes really are.",
  exploitdb: "Searchable database of known exploits and vulnerabilities.",
  exploitdev: "Workspace for security research and building proof-of-concepts.",
  packetcraft: "Hand-craft custom network packets for testing.",
  passwordtools: "Generate, hash and check passwords.",
  payloads: "Build test payloads (reverse/web shells) for authorized testing.",
  payloadgen: "Generate ready-made test scripts and payloads.",
  pentestconsole: "Interactive workspace for running a security assessment.",
  privesc: "Checklists to find privilege-escalation paths on Linux and Windows.",
  reverseshell: "Generate remote-access (reverse shell) one-liners in 15+ languages.",
  // Security Labs
  firewall: "Build and check firewall rules (iptables, pf, Windows Firewall).",
  webshell: "An in-browser command terminal.",
  wirelesslab: "Wi-Fi security testing workflows (WPA/WPA2).",
  xsslab: "Practice finding and fixing cross-site scripting (XSS) bugs.",
  socialeng: "Phishing-simulation and social-engineering templates.",
  // Reconnaissance
  addressintel: "Look up an IP or domain — location, owner and reputation.",
  asnexplorer: "See which networks (ASNs) own a range of IP addresses.",
  attacksurf: "Map everything your organization exposes to the internet.",
  dns: "DNS lookup and enumeration toolkit.",
  dnsenum: "Pull every DNS record for a domain (A, MX, TXT, and more).",
  dnsrecon: "Deeper DNS recon — zone transfers and subdomain discovery.",
  ghdb: "Google 'dorks' — clever search queries that surface exposed data.",
  netmap: "Map a network and scan it for open ports.",
  reconplanner: "Plan your recon step-by-step with methodology templates.",
  securityscanner: "Point-and-scan a target for common security issues.",
  subdomains: "Discover all of a domain's subdomains.",
  tools: "A suite of quick scanners gathered in one place.",
  wayback: "Browse old snapshots of any website (the Wayback Machine).",
  // OSINT
  corstester: "Check a site's cross-origin (CORS) rules for misconfiguration.",
  emailintel: "Investigate an email address — breaches, links and footprint.",
  favicon: "Identify sites by their favicon hash (Shodan/Censys).",
  headeranalyzer: "Inspect a website's HTTP response headers.",
  httpinspector: "See a full HTTP request/response with header analysis.",
  httpprobe: "Quickly probe a list of URLs to see what's live.",
  ipgeolocation: "Find the likely physical location behind an IP address.",
  iptools: "Handy IP utilities — lookup, convert and subnet.",
  osint: "Your OSINT hub for gathering public intelligence on a target.",
  osintemail: "Email intelligence — breach lookup and account discovery.",
  techfingerprint: "Detect what technologies a website is built with.",
  whoisrecon: "WHOIS lookup — who registered a domain, and when.",
  // Forensics
  binanalyze: "Analyze a binary (PE/ELF) — strings, entropy and structure.",
  forensicstoolkit: "A collection of digital-forensics utilities.",
  ftimeline: "Build an investigation timeline from your evidence.",
  loganalyze: "Parse and search system, application and security logs.",
  memforensics: "Analyze a RAM dump — processes and hidden malware.",
  reveng: "A reverse-engineering workspace.",
  stego: "Hide or extract data inside images and files (steganography).",
  timelineviz: "Plot events on an interactive timeline.",
  // Threat Analysis
  malclass: "Classify suspicious files and identify malware families.",
  phishing: "Analyze suspected phishing emails and pages.",
  sandbox: "Detonate and study suspicious files safely.",
  // Blue Team
  adversary: "Emulate real adversary playbooks to test your defenses.",
  breachsim: "Simulate a breach end-to-end to find the gaps.",
  containers: "Scan Docker and Kubernetes for security issues.",
  deception: "Plan honeypots and honeytokens to catch intruders.",
  huntlab: "A hands-on threat-hunting workspace.",
  identitymatrix: "Map identities and access across your organization.",
  incidents: "Track and manage security incidents.",
  mobilesec: "Test the security of Android and iOS apps.",
  purpleteam: "Run collaborative red-vs-blue team exercises.",
  riskcalculator: "Estimate and compare security risks.",
  threatmodel: "Model threats to a system (STRIDE / DREAD).",
  // Threat Intelligence
  breachlookup: "Check whether an email or password appeared in a breach.",
  cvesearch: "Search the CVE vulnerability database.",
  cvetimeline: "Browse CVEs on an interactive timeline.",
  darknetradar: "Monitor dark-web chatter and marketplaces.",
  darkwebosint: "Investigate .onion sites and deep-web sources.",
  ipreputation: "Check an IP address against threat blocklists.",
  threat: "A live, aggregated threat feed.",
  threatdashboard: "A visual overview of the current threat landscape.",
  threatfeed: "A curated threat-intelligence feed.",
  // Vulnerability Mgmt
  vulndb: "Searchable database of known vulnerabilities.",
  vulnprio: "Rank vulnerabilities by real-world risk (CVSS, EPSS, KEV).",
  vulntriage: "Decide which vulnerabilities to fix first.",
  secchecklist: "A step-by-step security-hardening checklist.",
  supplychain: "Assess the risk in your software supply chain.",
  // Network Analysis
  networkscanner: "Scan a network for live hosts and open ports.",
  networktools: "General-purpose networking utilities.",
  networktraffic: "Analyze live network traffic for anomalies.",
  packetanalyzer: "Break captured packets down protocol-by-protocol.",
  packetinspector: "Deep packet inspection.",
  sslinspector: "Check a site's SSL/TLS certificate and cipher suites.",
  subnetvisualizer: "Visualize and plan IP subnets.",
  trafficanalyzer: "Spot patterns and anomalies in network traffic.",
  websockettester: "Test and inspect WebSocket connections.",
  // Security Operations
  adversaryplaybook: "Prebuilt attacker playbooks to exercise your SOC.",
  apifuzzer: "Fuzz API endpoints to uncover weaknesses.",
  apitester: "Interactive API testing, like Postman.",
  apiscan: "Discover and security-test API endpoints.",
  incidentcost: "Estimate what a security breach would cost.",
  incidentresponse: "Build and follow incident-response playbooks.",
  siemdash: "A SIEM-style dashboard of security events.",
  // Compliance & GRC
  compliance: "Check systems against CIS and other compliance benchmarks.",
  cyberbriefing: "Your daily cybersecurity news briefing.",
  emailheader: "Analyze email headers (SPF/DKIM/DMARC) to trace origin.",
  fedcompliance: "NIST, FedRAMP and FISMA compliance checklists.",
  iocextractor: "Pull indicators of compromise (IOCs) out of text and logs.",
  zerotrust: "Plan a zero-trust security architecture.",
  // Crypto & Encoding
  credaudit: "Audit credentials against breach lists and password policy.",
  cryptotools: "Encrypt, decrypt and work with crypto primitives.",
  cspevaluator: "Build and validate a Content-Security-Policy (CSP).",
  encoding: "Encode and decode Base64, hex, URL and more.",
  hashsuite: "Generate and identify hashes (MD5, SHA, bcrypt…).",
  jwtanalyzer: "Decode, verify and attack JSON Web Tokens (JWT).",
  regexlab: "Build and test regular expressions.",
  urldissect: "Break a URL apart and spot suspicious pieces.",
  // Nexus AI
  ai: "Chat with the built-in AI about security, code and tooling.",
  coder: "An AI agent that can carry out multi-step tasks for you.",
  dataviz: "Turn raw data into charts and visualizations.",
  engines: "Configure the security-analysis engines.",
  report: "Generate professional penetration-test reports.",
  // Training
  cheats: "Quick-reference cheat sheets.",
  cyberrange: "A hands-on virtual training range.",
  learn: "Guided lessons — the Academy.",
  refs: "A reference library of security material.",
  secquiz: "Assess your skills with graded quizzes.",
  securityquiz: "Test your security knowledge.",
  snippets: "Save and reuse handy code snippets.",
  targets: "Legal, safe practice targets to hack on.",
  training: "Guided, hands-on training labs.",
  utils: "A grab-bag of small, handy tools.",
  // Labs & VMs
  vms: "Downloadable, intentionally-vulnerable VMs to practice on.",
  vmlab: "Manage your practice virtual machines.",
  // Investigations
  investigation: "A case workspace to collect findings and evidence.",
  secgraph: "A visual graph linking assets, indicators and incidents.",
  casemgmt: "Manage your investigation case files.",
  // Infrastructure
  api: "Your Darknode API keys and usage.",
  docs: "Documentation.",
  education: "Learning resources and courses.",
  downloads: "Get the Darknode OS and desktop app.",
  dlguide: "A step-by-step install guide.",
  privatecloud: "Private-cloud security architecture (beta).",
  setup: "Connect the local Darknode CLI to this browser.",
  admin: "Owner-only admin console.",
};
const GROUP_DESC = {
  "Mission Control": "Flagship, real-time operations tools — the big dashboards.",
  "Offensive Security": "Red-team / attack-side tools for authorized testing.",
  "Security Labs": "Hands-on practice labs.",
  "Reconnaissance": "Discover and map a target before testing.",
  "OSINT": "Open-source intelligence — dig up public info on a target.",
  "Forensics": "Investigate files, memory and evidence after the fact.",
  "Threat Analysis": "Analyze suspicious files and messages.",
  "Blue Team": "Defensive security — protect and detect.",
  "Threat Intelligence": "Track threats, breaches and CVEs.",
  "Vulnerability Mgmt": "Find, rank and fix vulnerabilities.",
  "Network Analysis": "Inspect networks, packets and traffic.",
  "Security Operations": "SOC workflows and API-security tooling.",
  "Compliance & GRC": "Compliance, governance and risk.",
  "Crypto & Encoding": "Hashing, encoding and cryptography.",
  "Nexus AI": "AI assistants, data viz and reporting.",
  "Training": "Learn and practice your skills.",
  "Labs & VMs": "Practice virtual machines.",
  "Investigations": "Case management and link analysis.",
  "Infrastructure": "Account, docs, downloads and setup.",
  "Admin": "Owner-only controls.",
};
function applySidebarHelp(view) {
  const nav = view.querySelector(".side-nav");
  if (!nav || nav.dataset.helpWired) return;
  const escT = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const cleanName = (el, sel) => { const b = el.querySelector(sel); let t = el.textContent || ""; if (b) t = t.replace(b.textContent, ""); return t.trim(); };
  // Stamp name + description onto each item and group.
  nav.querySelectorAll(".side-item[data-sec]").forEach((it) => {
    const d = SIDE_DESC[it.dataset.sec]; if (!d) return;
    it.dataset.name = cleanName(it, ".side-badge"); it.dataset.desc = d;
    it.setAttribute("title", it.dataset.name + " — " + d); // a11y / fallback
  });
  nav.querySelectorAll(".side-group").forEach((g) => {
    const nm = cleanName(g, ".side-cnt"); const d = GROUP_DESC[nm]; if (!d) return;
    g.dataset.name = nm; g.dataset.desc = d;
  });
  // One shared, styled tooltip for the whole sidebar.
  let tip = document.getElementById("side-tip");
  if (!tip) { tip = document.createElement("div"); tip.id = "side-tip"; tip.className = "side-tip"; tip.hidden = true; document.body.appendChild(tip); }
  const place = (el) => {
    const name = el.dataset.name, desc = el.dataset.desc; if (!desc) return;
    tip.innerHTML = `<b>${escT(name)}</b><span>${escT(desc)}</span>`;
    tip.hidden = false;
    const r = el.getBoundingClientRect();
    tip.style.top = Math.min(Math.max(8, r.top), window.innerHeight - tip.offsetHeight - 8) + "px";
    let left = r.right + 10;
    if (left + tip.offsetWidth > window.innerWidth - 8) left = r.left - tip.offsetWidth - 10; // flip to the left if it would overflow
    tip.style.left = Math.max(8, left) + "px";
  };
  const hide = () => { tip.hidden = true; };
  nav.addEventListener("mouseover", (e) => { const el = e.target.closest(".side-item[data-desc],.side-group[data-desc]"); if (el) { el._savedTitle = el.getAttribute("title"); el.removeAttribute("title"); place(el); } });
  nav.addEventListener("mouseout", (e) => { const el = e.target.closest(".side-item[data-desc],.side-group[data-desc]"); if (el) { if (el._savedTitle != null) el.setAttribute("title", el._savedTitle); hide(); } });
  nav.addEventListener("scroll", hide, true);
  nav.addEventListener("click", hide);
  window.addEventListener("blur", hide);
  nav.dataset.helpWired = "1";
}
import {
  renderThreat, renderCheats, renderLearn, homeWidgetsHTML, wireHome, COUNTS,
  CHEATS, RESOURCES,
} from "/js/cyber.js";
let _learnHub = null;
async function loadLearnHub() { if (!_learnHub) { _learnHub = await import("/js/learn-hub.js"); } return _learnHub; }
import { emailConfigured, sendCode, sendLoginAlert, genCode, hashCode, deviceInfo } from "/js/notify.js";
import { initSaved } from "/js/saved.js";
import("/js/shell-bridge.js").then(m => {
  window.shellIsConnected = m.shellIsConnected;
  window.shellConnect = m.shellConnect;
  window.shellStatus = m.shellStatus;
  window.shellExec = m.shellExec;
});

if (window.__boot) window.__boot.set(40);

const _errSeen = new Set();
function _logError(data) {
  const key = data.message + (data.source || '') + (data.line || '');
  if (_errSeen.has(key) || _errSeen.size >= 20) return;
  _errSeen.add(key);
  fbAddDoc(fbCollection(db, "errors"), {
    ...data, email: auth.currentUser?.email || "anonymous",
    uid: auth.currentUser?.uid || "", ts: fbServerTimestamp(),
  }).catch(() => {});
}
if (window.__errorQueue) { window.__errorQueue.splice(0).forEach(e => _logError(e)); window.__errorQueue = null; }
window.addEventListener("error", (ev) => {
  _logError({ message: String(ev.message || ""), source: ev.filename || "", line: ev.lineno, col: ev.colno, stack: ev.error?.stack?.slice(0, 2000) || "", url: location.href, ua: navigator.userAgent, clientTs: Date.now() });
});
window.addEventListener("unhandledrejection", (ev) => {
  const r = ev.reason || {};
  _logError({ message: r.message || String(r), source: "unhandledrejection", stack: r.stack?.slice(0, 2000) || "", url: location.href, ua: navigator.userAgent, clientTs: Date.now() });
});

const userSlot = document.getElementById("user-slot");
const view = document.getElementById("view");
let appShow = null;   // set by renderApp so the command palette can navigate
const _bootStart = performance.now();
function dismissBoot() {
  if (window.__boot) window.__boot.set(100);
  const b = document.getElementById("bootscreen"); if (!b) return;
  const elapsed = performance.now() - _bootStart;
  const isPro = document.documentElement.getAttribute("data-boot") === "pro";
  const delay = Math.max(0, (isPro ? 1200 : 2200) - elapsed);
  setTimeout(() => {
    const inner = b.querySelector(".boot-inner"); if (inner) inner.classList.add("exit");
    setTimeout(() => { b.style.opacity = "0"; }, 150);
    setTimeout(() => b.remove(), 650);
  }, delay);
}
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// Shared CSS dialog (replaces native prompt/confirm/alert). Exposed on window
// so any tool module can use it. Resolves field values (array), true/false for
// confirm, or null on cancel.
function dnModal({ title, desc, fields = [], submitText = "Confirm", cancelText = "Cancel", danger = false } = {}) {
  return new Promise((resolve) => {
    const ov = document.createElement("div");
    ov.className = "dn-modal-ov";
    ov.innerHTML = `<div class="dn-modal" role="dialog" aria-modal="true" aria-label="${esc(title || "Dialog")}">
      <div class="dn-modal-h">${esc(title || "")}</div>
      ${desc ? `<p class="dn-modal-d">${esc(desc)}</p>` : ""}
      <div class="dn-modal-body">${fields.map((f, i) => {
        const lab = f.label ? `<span class="dn-modal-lbl">${esc(f.label)}</span>` : "";
        return f.type === "textarea"
          ? `<label class="dn-modal-field">${lab}<textarea class="dn-modal-ta" data-f="${i}" rows="${f.rows || 5}" placeholder="${esc(f.placeholder || "")}">${esc(f.value || "")}</textarea></label>`
          : `<label class="dn-modal-field">${lab}<input class="dn-modal-in" data-f="${i}" type="${esc(f.inputType || "text")}" placeholder="${esc(f.placeholder || "")}" value="${esc(f.value || "")}"></label>`;
      }).join("")}</div>
      <div class="dn-modal-actions"><div class="dn-modal-extra"></div><div class="dn-modal-main">
        <button class="btn ghost sm" data-cancel>${esc(cancelText)}</button>
        <button class="btn sm${danger ? " dn-modal-danger" : ""}" data-ok>${esc(submitText)}</button>
      </div></div>
    </div>`;
    document.body.appendChild(ov);
    requestAnimationFrame(() => ov.classList.add("open"));
    const vals = () => fields.map((_, i) => { const el = ov.querySelector(`[data-f="${i}"]`); return el ? el.value : ""; });
    const close = (r) => { ov.classList.remove("open"); document.removeEventListener("keydown", onKey); setTimeout(() => ov.remove(), 150); resolve(r); };
    ov.querySelector("[data-ok]").onclick = () => close(fields.length ? vals() : true);
    ov.querySelector("[data-cancel]").onclick = () => close(fields.length ? null : false);
    ov.addEventListener("mousedown", (e) => { if (e.target === ov) close(fields.length ? null : false); });
    const onKey = (e) => { if (e.key === "Escape") close(fields.length ? null : false); if (e.key === "Enter" && (e.metaKey || e.ctrlKey || !fields.some((f) => f.type === "textarea"))) { if (e.key === "Enter") { e.preventDefault(); close(fields.length ? vals() : true); } } };
    document.addEventListener("keydown", onKey);
    const first = ov.querySelector("[data-f]"); if (first) { first.focus(); try { first.setSelectionRange(first.value.length, first.value.length); } catch (_) {} }
  });
}
try {
  window.dnModal = dnModal;
  window.dnConfirm = (title, desc, opts = {}) => dnModal({ title, desc, submitText: opts.submitText || "Confirm", cancelText: opts.cancelText || "Cancel", danger: opts.danger }).then((r) => r === true);
  window.dnPrompt = (title, opts = {}) => dnModal({ title, desc: opts.desc, fields: [{ value: opts.value || "", placeholder: opts.placeholder || "", inputType: opts.inputType || "text", type: opts.textarea ? "textarea" : "text" }], submitText: opts.submitText || "OK" }).then((r) => (r ? r[0] : null));
} catch (_) {}

// Password-reset "continue" target: bring users back to Darknode after they
// finish. NOTE: the email's sender name ("Darknode"), the link domain
// (sentinel-b4194.firebaseapp.com → darknode.ai) and a button-style template
// are set in the Firebase console (Authentication → Templates + a custom
// action domain), not here — this only controls where the reset returns to.
const RESET_ACS = { url: (location.hostname === "localhost" || location.hostname === "127.0.0.1") ? location.origin + "/" : "https://darknode.ai/", handleCodeInApp: false };

const errText = (e) => {
  const map = {
    "auth/invalid-credential": "Wrong email or password.",
    "auth/wrong-password": "Wrong email or password.",
    "auth/user-not-found": "No account with that email.",
    "auth/email-already-in-use": "That email already has an account — try signing in.",
    "auth/weak-password": "Password must be at least 6 characters.",
    "auth/invalid-email": "That doesn't look like a valid email.",
    "auth/popup-closed-by-user": "Sign-in was cancelled.",
    "auth/operation-not-allowed": "This sign-in method isn't enabled in Firebase yet.",
    "auth/too-many-requests": "Too many attempts — wait a bit and retry.",
    "auth/account-exists-with-different-credential": "That email is already registered with a different sign-in method — use that one.",
  };
  return map[e?.code] || e?.message || String(e);
};

async function ensureUserDoc(user) {
  try {
    const providers = user.providerData.map(p => p.providerId.replace('.com', '')).join(', ') || 'email';
    await setDoc(doc(db, "users", user.uid), {
      email: user.email, name: user.displayName || "", lastSeen: serverTimestamp(),
      provider: providers, photoURL: user.photoURL || "",
      createdAt: user.metadata?.creationTime || null,
      lastLoginAt: user.metadata?.lastSignInTime || null,
    }, { merge: true });
  } catch (_) { /* rules/offline - non-fatal */ }
}

// ---------- views ----------
function openFeedback(user) {
  const old = document.getElementById("fbModal"); if (old) old.remove();
  const wrap = document.createElement("div");
  wrap.id = "fbModal"; wrap.className = "fb-modal";
  wrap.innerHTML = `
    <div class="fb-box">
      <div class="fb-h">Send feedback / report a bug</div>
      <div class="fb-types" id="fbTypes">
        <button class="fb-type on" data-t="bug">Bug</button>
        <button class="fb-type" data-t="feedback">Feedback</button>
        <button class="fb-type" data-t="idea">Idea</button>
      </div>
      <textarea id="fbMsg" class="tk-in" rows="5" placeholder="What happened, or what would you like to see? The more detail the better."></textarea>
      <div class="fb-foot"><span class="fb-status" id="fbStatus"></span><span style="flex:1"></span><button class="btn ghost" id="fbCancel">Cancel</button><button class="btn" id="fbSend">Send</button></div>
    </div>`;
  document.body.appendChild(wrap);
  const q = (s) => wrap.querySelector(s);
  let type = "bug";
  q("#fbTypes").onclick = (e) => { const b = e.target.closest("[data-t]"); if (!b) return; type = b.dataset.t; q("#fbTypes").querySelectorAll(".fb-type").forEach((x) => x.classList.toggle("on", x === b)); };
  const close = () => wrap.remove();
  q("#fbCancel").onclick = close;
  wrap.onclick = (e) => { if (e.target === wrap) close(); };
  q("#fbSend").onclick = async () => {
    const msg = q("#fbMsg").value.trim();
    if (!msg) { q("#fbStatus").textContent = "please write a message first"; return; }
    q("#fbSend").disabled = true; q("#fbStatus").textContent = "sending…";
    try {
      await fbAddDoc(fbCollection(db, "feedback"), {
        type, message: msg.slice(0, 4000),
        email: (user && user.email) || "anonymous", uid: (user && user.uid) || "",
        ts: fbServerTimestamp(), userAgent: navigator.userAgent, url: location.href, resolved: false,
      });
      q("#fbStatus").textContent = "Sent — thank you!";
      setTimeout(close, 900);
    } catch (err) { q("#fbSend").disabled = false; q("#fbStatus").textContent = "failed: " + err.message; }
  };
  q("#fbMsg").focus();
}

function showLanding() {
  dismissBoot();
  document.body.classList.remove("app");
  document.body.classList.add("landing");
  userSlot.innerHTML = `
    <div class="nav-dd" data-dd="products">
      <button class="nav-dd-btn">Products <svg width="10" height="6" viewBox="0 0 10 6"><path d="M1 1l4 4 4-4" stroke="currentColor" stroke-width="1.5" fill="none" stroke-linecap="round"/></svg></button>
      <div class="nav-dd-menu">
        <a class="nav-dd-item" href="/get-started" data-nav="auth"><span class="nav-dd-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="3" width="18" height="18" rx="3"/><path d="M7 8h10M7 12h6M7 16h8"/></svg></span><span><strong>Web App</strong><span class="nav-dd-desc">Tools and labs in your browser</span></span></a>
        <a class="nav-dd-item" href="https://github.com/Darknode-Official/darknode-cli" target="_blank" rel="noopener"><span class="nav-dd-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg></span><span><strong>CLI</strong><span class="nav-dd-desc">Install via npm</span></span></a>
        <a class="nav-dd-item" href="https://github.com/Darknode-Official/darknode-os" target="_blank" rel="noopener"><span class="nav-dd-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M2 8h20"/></svg></span><span><strong>Linux VM</strong><span class="nav-dd-desc">Pre-built Darknode OS</span></span></a>
      </div>
    </div>
    <div class="nav-dd" data-dd="features">
      <button class="nav-dd-btn">Features <svg width="10" height="6" viewBox="0 0 10 6"><path d="M1 1l4 4 4-4" stroke="currentColor" stroke-width="1.5" fill="none" stroke-linecap="round"/></svg></button>
      <div class="nav-dd-menu">
        <a class="nav-dd-item" href="/features" data-nav="section" data-section="features"><span class="nav-dd-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5M2 12l10 5 10-5"/></svg></span><span><strong>Overview</strong><span class="nav-dd-desc">Everything you need to learn security</span></span></a>
        <a class="nav-dd-item" href="/arsenal" data-nav="auth"><span class="nav-dd-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z"/></svg></span><span><strong>120+ Tools</strong><span class="nav-dd-desc">Security tools and utilities</span></span></a>
        <a class="nav-dd-item" href="/ai" data-nav="auth"><span class="nav-dd-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83"/></svg></span><span><strong>Nexus AI</strong><span class="nav-dd-desc">AI-powered security agent</span></span></a>
        <a class="nav-dd-item" href="/cyberrange" data-nav="auth"><span class="nav-dd-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 3h6v4l4 8H5l4-8V3z"/><path d="M5 15h14v2a4 4 0 01-4 4H9a4 4 0 01-4-4v-2z"/></svg></span><span><strong>Practice Labs</strong><span class="nav-dd-desc">Hands-on CTF challenges</span></span></a>
      </div>
    </div>
    <div class="nav-dd" data-dd="resources">
      <button class="nav-dd-btn">Resources <svg width="10" height="6" viewBox="0 0 10 6"><path d="M1 1l4 4 4-4" stroke="currentColor" stroke-width="1.5" fill="none" stroke-linecap="round"/></svg></button>
      <div class="nav-dd-menu">
        <a class="nav-dd-item" href="/pricing" data-nav="section" data-section="pricing"><span class="nav-dd-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M12 8v8M8 12h8"/></svg></span><span><strong>Pricing</strong><span class="nav-dd-desc">Free forever, upgrade anytime</span></span></a>
        <a class="nav-dd-item" href="/faq" data-nav="section" data-section="faq"><span class="nav-dd-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><path d="M9 9a3 3 0 115.12 2.13c-.6.53-1.12 1.28-1.12 2.37M12 17h.01"/></svg></span><span><strong>FAQ</strong><span class="nav-dd-desc">Common questions answered</span></span></a>
        <a class="nav-dd-item" href="https://github.com/Darknode-Official" target="_blank" rel="noopener"><span class="nav-dd-icon"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.44 9.8 8.2 11.39.6.11.82-.26.82-.58v-2.23c-3.34.73-4.04-1.42-4.04-1.42-.55-1.39-1.34-1.76-1.34-1.76-1.08-.74.08-.73.08-.73 1.2.08 1.84 1.23 1.84 1.23 1.07 1.83 2.81 1.3 3.5 1 .1-.78.42-1.3.76-1.6-2.67-.3-5.47-1.33-5.47-5.93 0-1.31.47-2.38 1.24-3.22-.14-.3-.54-1.52.1-3.18 0 0 1-.32 3.3 1.23a11.5 11.5 0 016.02 0c2.28-1.55 3.29-1.23 3.29-1.23.64 1.66.24 2.88.12 3.18.77.84 1.23 1.91 1.23 3.22 0 4.61-2.8 5.63-5.48 5.92.42.37.81 1.1.81 2.22v3.29c0 .32.22.7.82.58A12.01 12.01 0 0024 12c0-6.63-5.37-12-12-12z"/></svg></span><span><strong>GitHub</strong><span class="nav-dd-desc">Source code and releases</span></span></a>
      </div>
    </div>
    <span class="nav-spacer"></span>
    <a class="nav-link" id="nav-signin">Log in</a>
    <button class="btn" id="nav-start">Get Started</button>`;
  document.querySelectorAll(".nav-dd").forEach(dd => {
    const btn = dd.querySelector(".nav-dd-btn");
    let closeTimer;
    const show = () => { clearTimeout(closeTimer); document.querySelectorAll(".nav-dd.open").forEach(d => { if (d !== dd) d.classList.remove("open"); }); dd.classList.add("open"); };
    const hide = () => { closeTimer = setTimeout(() => dd.classList.remove("open"), 120); };
    btn.addEventListener("mouseenter", show);
    btn.addEventListener("mouseleave", hide);
    dd.querySelector(".nav-dd-menu").addEventListener("mouseenter", () => clearTimeout(closeTimer));
    dd.querySelector(".nav-dd-menu").addEventListener("mouseleave", hide);
    btn.addEventListener("click", (e) => { e.stopPropagation(); dd.classList.toggle("open"); });
  });
  document.addEventListener("click", () => document.querySelectorAll(".nav-dd.open").forEach(d => d.classList.remove("open")));
  document.querySelectorAll(".nav-dd-item[data-nav]").forEach(item => {
    item.addEventListener("click", (e) => {
      e.preventDefault();
      document.querySelectorAll(".nav-dd.open").forEach(d => d.classList.remove("open"));
      const nav = item.dataset.nav;
      if (nav === "auth") {
        history.pushState(null, "", item.getAttribute("href"));
        renderAuth("signup");
      } else if (nav === "section") {
        window.location.href = item.getAttribute("href");
      }
    });
  });
  document.getElementById("nav-signin").onclick = () => renderAuth("signin");
  document.getElementById("nav-start").onclick = () => renderAuth("signup");
  loadLanding().then(m => m.renderLanding(view, {
    onGetStarted: () => renderAuth("signup"),
    onSignIn: () => renderAuth("signin"),
  }));
}

function renderAuth(mode = "signin") {
  document.body.classList.remove("landing", "app");
  userSlot.innerHTML = "";
  const isSignup = mode === "signup";
  view.innerHTML = `
    <div class="auth-page">
      <section class="card auth-card">
        <a class="auth-back" id="authBack">&larr; Back</a>
        <div class="auth-logo"><img src="/logo-light.svg" alt=""></div>
        <h1>${isSignup ? "Create your account" : "Welcome back"}</h1>
        <p class="auth-subtitle">${isSignup ? "Set up your Darknode console in seconds." : "Sign in to your Darknode console."}</p>
        <button class="btn google" id="google"><svg width="18" height="18" viewBox="0 0 24 24"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 01-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18A10.96 10.96 0 001 12c0 1.77.42 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>Continue with Google</button>
        <button class="btn github" id="github"><svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.44 9.8 8.2 11.39.6.11.82-.26.82-.58v-2.23c-3.34.73-4.04-1.42-4.04-1.42-.55-1.39-1.34-1.76-1.34-1.76-1.08-.74.08-.73.08-.73 1.2.08 1.84 1.23 1.84 1.23 1.07 1.83 2.81 1.3 3.5 1 .1-.78.42-1.3.76-1.6-2.67-.3-5.47-1.33-5.47-5.93 0-1.31.47-2.38 1.24-3.22-.14-.3-.54-1.52.1-3.18 0 0 1-.32 3.3 1.23a11.5 11.5 0 016.02 0c2.28-1.55 3.29-1.23 3.29-1.23.64 1.66.24 2.88.12 3.18.77.84 1.23 1.91 1.23 3.22 0 4.61-2.8 5.63-5.48 5.92.42.37.81 1.1.81 2.22v3.29c0 .32.22.7.82.58A12.01 12.01 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>Continue with GitHub</button>
        <div class="or"><span></span>or<span></span></div>
        <form id="pwform" autocomplete="on">
          <input type="email" id="email" placeholder="Email address" autocomplete="email" required>
          <input type="password" id="password" placeholder="Password" autocomplete="${isSignup ? "new-password" : "current-password"}" required>
          <button class="btn" type="submit">${isSignup ? "Create account" : "Sign in"}</button>
        </form>
        <div class="auth-links">
          ${isSignup
            ? `<a id="toSignin">Already have an account? <strong>Sign in</strong></a>`
            : `<a id="toSignup">New here? <strong>Create account</strong></a><a id="forgot">Forgot password?</a>`}
        </div>
        <p id="err" class="auth-err"></p>
        <div class="auth-test"><a id="testMode">Test Mode (no account)</a></div>
      </section>
      <div class="auth-footer">darknode.ai &mdash; cybersecurity platform</div>
    </div>`;

  const err = (m) => { document.getElementById("err").textContent = m; };
  document.getElementById("testMode").onclick = () => {
    const fakeUser = { uid: "test-user", email: "test@darknode.ai", displayName: "Test User", providerData: [{ providerId: "test" }], metadata: { creationTime: new Date().toISOString() }, refreshToken: "", getIdToken: () => Promise.resolve("") };
    renderApp(fakeUser);
  };
  document.getElementById("google").onclick = async () => {
    err("");
    try { try { sessionStorage.setItem("sw_fresh_signin", "1"); } catch (_) {} await signInWithRedirect(auth, googleProvider); }
    catch (e) { try { sessionStorage.removeItem("sw_fresh_signin"); } catch (_) {} err(errText(e)); }
  };
  document.getElementById("github").onclick = async () => {
    err("");
    try { try { sessionStorage.setItem("sw_fresh_signin", "1"); } catch (_) {} await signInWithRedirect(auth, githubProvider); }
    catch (e) { try { sessionStorage.removeItem("sw_fresh_signin"); } catch (_) {} err(errText(e)); }
  };
  document.getElementById("pwform").onsubmit = async (ev) => {
    ev.preventDefault(); err("");
    const email = document.getElementById("email").value.trim();
    const pw = document.getElementById("password").value;
    try {
      if (isSignup) {
        const cred = await createUserWithEmailAndPassword(auth, email, pw);
        if (emailConfigured()) {
          const code = genCode();
          await setDoc(doc(db, "users", cred.user.uid), { email, codeVerified: false, pendingCodeHash: await hashCode(code), pendingCodeExp: Date.now() + 10 * 60 * 1000 }, { merge: true });
          const r = await sendCode(email, code, "");
          if (!r.ok) { await sendEmailVerification(cred.user); }
        } else {
          await sendEmailVerification(cred.user);
        }
      } else {
        try { sessionStorage.setItem("sw_fresh_signin", "1"); } catch (_) {}
        await signInWithEmailAndPassword(auth, email, pw);
      }
    } catch (e) { try { sessionStorage.removeItem("sw_fresh_signin"); } catch (_) {} err(errText(e)); }
  };
  const on = (id, fn) => { const el = document.getElementById(id); if (el) el.onclick = fn; };
  on("authBack", showLanding);
  on("toSignup", () => renderAuth("signup"));
  on("toSignin", () => renderAuth("signin"));
  on("forgot", async () => {
    const email = document.getElementById("email").value.trim();
    if (!email) return err("Enter your email above first, then click Forgot password.");
    try { await sendPasswordResetEmail(auth, email, RESET_ACS); err(""); document.getElementById("err").className = "auth-ok"; document.getElementById("err").textContent = "Password reset email sent — check your inbox."; }
    catch (e) { err(errText(e)); }
  });
}

function renderVerify(user) {
  dismissBoot();
  document.body.classList.remove("landing", "app");
  userSlot.innerHTML = `<button class="btn ghost" id="signout">Sign out</button>`;
  document.getElementById("signout").onclick = () => signOut(auth);
  view.innerHTML = `
    <section class="card auth-card">
      <h1>Verify your email</h1>
      <p class="muted">We sent a verification link to <strong>${esc(user.email)}</strong>. Open it, then click Reload.</p>
      <button class="btn" id="reload">I've verified — reload</button>
      <button class="btn ghost" id="resend">Resend email</button>
      <p id="err" class="auth-err"></p>
    </section>`;
  document.getElementById("reload").onclick = async () => {
    await reload(user);
    if (user.emailVerified) location.reload();
    else document.getElementById("err").textContent = "Still not verified — check the link in your email.";
  };
  document.getElementById("resend").onclick = async () => {
    try { await sendEmailVerification(user); document.getElementById("err").className = "auth-ok"; document.getElementById("err").textContent = "Sent again."; }
    catch (e) { document.getElementById("err").textContent = errText(e); }
  };
}

// Email-code verification (used when EmailJS is configured).
function renderCodeVerify(user) {
  dismissBoot();
  document.body.classList.remove("landing", "app");
  userSlot.innerHTML = `<button class="btn ghost" id="signout">Sign out</button>`;
  document.getElementById("signout").onclick = () => signOut(auth);
  view.innerHTML = `
    <section class="card auth-card">
      <div class="auth-logo"><img src="/logo-light.svg" alt=""></div>
      <h1>Enter your code</h1>
      <p class="muted">We emailed a 6-digit code to <strong>${esc(user.email)}</strong>. Enter it to finish signing up.</p>
      <input id="code" inputmode="numeric" maxlength="6" placeholder="123456" autocomplete="one-time-code" style="text-align:center;letter-spacing:.4em;font-size:1.3rem">
      <button class="btn" id="verify">Verify</button>
      <button class="btn ghost" id="resend">Resend code</button>
      <p id="err" class="auth-err"></p>`;
  const setMsg = (m, ok) => { const e = document.getElementById("err"); e.textContent = m; e.className = ok ? "auth-ok" : "auth-err"; };
  const resendBtn = document.getElementById("resend");
  let cd = 0, timer = null;
  const startCooldown = (sec) => { cd = sec; resendBtn.disabled = true; clearInterval(timer); timer = setInterval(() => { cd--; if (cd <= 0) { clearInterval(timer); resendBtn.disabled = false; resendBtn.textContent = "Resend code"; } else resendBtn.textContent = "Resend in " + cd + "s"; }, 1000); };
  startCooldown(45); // a code was just sent at sign-up
  document.getElementById("verify").onclick = async () => {
    const code = (document.getElementById("code").value || "").trim();
    try {
      const snap = await getDoc(doc(db, "users", user.uid));
      const d = snap.exists() ? snap.data() : {};
      if (!d.pendingCodeHash || (d.pendingCodeExp && Date.now() > d.pendingCodeExp)) return setMsg("Code expired — tap Resend for a new one.");
      if ((await hashCode(code)) !== d.pendingCodeHash) return setMsg("Incorrect code.");
      await setDoc(doc(db, "users", user.uid), { codeVerified: true, pendingCodeHash: null, pendingCodeExp: null }, { merge: true });
      location.reload();
    } catch (e) { setMsg(errText(e)); }
  };
  resendBtn.onclick = async () => {
    startCooldown(45);
    try {
      const code = genCode();
      await setDoc(doc(db, "users", user.uid), { pendingCodeHash: await hashCode(code), pendingCodeExp: Date.now() + 10 * 60 * 1000 }, { merge: true });
      const r = await sendCode(user.email, code, user.displayName);
      setMsg(r.ok ? "New code sent." : "Couldn't send: " + r.error, r.ok);
    } catch (e) { setMsg(errText(e)); }
  };
}

// New-device sign-in: record it (for the admin log) and, if EmailJS is set up, email an alert.
async function checkLoginDevice(user) {
  try {
    const dev = deviceInfo();
    const ref = doc(db, "users", user.uid);
    const snap = await getDoc(ref);
    const data = snap.exists() ? snap.data() : {};
    const known = data.devices || [];
    if (known.includes(dev.id)) return;
    if (emailConfigured()) await sendLoginAlert(user.email, { name: user.displayName || user.email, time: new Date().toLocaleString(), device: dev.label });
    const logins = (data.logins || []).slice(-9);
    logins.push({ device: dev.label, ts: Date.now() });
    await setDoc(ref, { devices: [...known, dev.id], logins }, { merge: true });
  } catch (_) { /* non-fatal */ }
}

// ---------- appearance ----------
const ACCENTS = ["#00d4ff", "#7c5cff", "#22c55e", "#f59e0b", "#ef4444", "#ec4899"];
function applyAccent(c) {
  document.documentElement.style.setProperty("--acc", c);
  try { localStorage.setItem("sw_accent", c); } catch (_) {}
}
(function () { let a = null; try { a = localStorage.getItem("sw_accent"); } catch (_) {} if (a) applyAccent(a); })();
function applyTheme(m) { document.documentElement.setAttribute("data-theme", m); try { localStorage.setItem("sw_theme", m); } catch (_) {} }
const STYLES = ["pro", "command", "dark", "classic"];
// "command" is the Command Center skin layered on the Professional style (css/theme-command.css).
function currentStyle() {
  const s = document.documentElement.getAttribute("data-style") || "pro";
  return s === "pro" && document.documentElement.getAttribute("data-skin") === "command" ? "command" : s;
}
function setStyle(name) {
  const root = document.documentElement;
  root.setAttribute("data-style", name === "command" ? "pro" : name);
  if (name === "command") root.setAttribute("data-skin", "command"); else root.removeAttribute("data-skin");
  try { localStorage.setItem("sw_style", name); } catch (_) {}
}
function cycleStyle() {
  const next = STYLES[(STYLES.indexOf(currentStyle()) + 1) % STYLES.length];
  setStyle(next);
  const btn = document.getElementById("styleToggle");
  if (btn) { btn.title = "Theme: " + next; btn.setAttribute("aria-label", "Theme: " + next); btn.dataset.style = next; }
}
(function () { let t = "dark"; try { t = localStorage.getItem("sw_theme") || "dark"; } catch (_) {} applyTheme(t); })();
function crtOn() { try { return localStorage.getItem("sw_crt") === "1"; } catch (_) { return false; } }
function applyCrt(on) { document.documentElement.classList.toggle("crt", on); try { localStorage.setItem("sw_crt", on ? "1" : "0"); } catch (_) {} }
applyCrt(crtOn());
// UI preference appliers (density / motion / live topbar) — set an attribute on
// <html> so CSS can react, and persist the choice.
function _pref(k, d) { try { return localStorage.getItem(k) || d; } catch (_) { return d; } }
function applyDensity(v) { document.documentElement.setAttribute("data-density", v); try { localStorage.setItem("sw_density", v); } catch (_) {} }
function applyMotion(v) { document.documentElement.setAttribute("data-motion", v); try { localStorage.setItem("sw_motion", v); } catch (_) {} }
function applyTopbarPref(v) { document.documentElement.setAttribute("data-topbar", v); try { localStorage.setItem("sw_topbar", v); } catch (_) {} }
function applyUiPrefs() { applyDensity(_pref("sw_density", "comfortable")); applyMotion(_pref("sw_motion", "on")); applyTopbarPref(_pref("sw_topbar", "on")); }
applyUiPrefs();

const LOGO_VARIANTS = {
  "outer-radius": {
    label: "Outer radius",
    svg: '<path d="M10,22 A12,12 0 0 1 22,10 H42 V42 H10 Z" fill="none" stroke="currentColor" stroke-width="6" stroke-linejoin="miter"/><path d="M58,10 H78 A12,12 0 0 1 90,22 V42 H58 Z" fill="none" stroke="currentColor" stroke-width="6" stroke-linejoin="miter"/><path d="M10,58 H42 V90 H22 A12,12 0 0 1 10,78 Z" fill="none" stroke="currentColor" stroke-width="6" stroke-linejoin="miter"/><path d="M58,58 H90 V78 A12,12 0 0 1 78,90 H58 Z" fill="#E09A2B"/>',
  },
  "nested-accent": {
    label: "Nested accent",
    svg: '<rect x="10" y="10" width="32" height="32" rx="7" fill="none" stroke="currentColor" stroke-width="6"/><rect x="58" y="10" width="32" height="32" rx="7" fill="none" stroke="currentColor" stroke-width="6"/><rect x="10" y="58" width="32" height="32" rx="7" fill="none" stroke="currentColor" stroke-width="6"/><rect x="58" y="58" width="32" height="32" rx="7" fill="none" stroke="currentColor" stroke-width="6"/><rect x="66.96" y="66.96" width="14.08" height="14.08" rx="3.5" fill="#E09A2B"/>',
  },
  "thin": {
    label: "Thin",
    svg: '<rect x="10" y="10" width="32" height="32" rx="7" fill="none" stroke="currentColor" stroke-width="6"/><rect x="58" y="10" width="32" height="32" rx="7" fill="none" stroke="currentColor" stroke-width="6"/><rect x="10" y="58" width="32" height="32" rx="7" fill="none" stroke="currentColor" stroke-width="6"/><rect x="58" y="58" width="32" height="32" rx="7" fill="#E09A2B"/>',
  },
  "solid": {
    label: "Solid",
    svg: '<rect x="9" y="9" width="36" height="36" rx="8" fill="currentColor"/><rect x="55" y="9" width="36" height="36" rx="8" fill="currentColor"/><rect x="9" y="55" width="36" height="36" rx="8" fill="currentColor"/><rect x="55" y="55" width="36" height="36" rx="8" fill="#E09A2B"/>',
  },
  "missing": {
    label: "Missing cell",
    svg: '<rect x="10" y="10" width="32" height="32" rx="7" fill="none" stroke="currentColor" stroke-width="6"/><rect x="58" y="10" width="32" height="32" rx="7" fill="none" stroke="currentColor" stroke-width="6"/><rect x="10" y="58" width="32" height="32" rx="7" fill="none" stroke="currentColor" stroke-width="6"/>',
  },
};
function logoSvg(key) { const v = LOGO_VARIANTS[key]; if (!v) return ""; return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">${v.svg}</svg>`; }
function logoFavSvg(key) {
  const v = LOGO_VARIANTS[key]; if (!v) return "";
  const style = '<style>*{--c:#101722}@media(prefers-color-scheme:dark){*{--c:#F2F5F9}}</style>';
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">${style}${v.svg.replace(/currentColor/g, "var(--c)")}</svg>`;
}
function applyLogo(key) {
  if (!LOGO_VARIANTS[key]) return;
  try { localStorage.setItem("sw_logo", key); } catch (_) {}
  const mark = document.querySelector(".brand-mark");
  if (mark) { mark.src = "data:image/svg+xml," + encodeURIComponent(logoSvg(key).replace(/currentColor/g, "#F2F5F9")); }
  let fav = document.querySelector('link[rel="icon"]');
  if (!fav) { fav = document.createElement("link"); fav.rel = "icon"; document.head.appendChild(fav); }
  fav.href = "data:image/svg+xml," + encodeURIComponent(logoFavSvg(key));
}
(function () { let l = null; try { l = localStorage.getItem("sw_logo"); } catch (_) {} if (l && LOGO_VARIANTS[l]) applyLogo(l); })();

// ---------- app sections ----------
function _dashDateTime() {
  const now = new Date();
  const opts = { weekday: "long", year: "numeric", month: "long", day: "numeric" };
  const date = now.toLocaleDateString(undefined, opts);
  const time = now.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  return { date, time };
}

function _dashRecentActivity() {
  const KEY = "dn_recent_activity";
  let items;
  try { items = JSON.parse(localStorage.getItem(KEY)); } catch (_) {}
  if (!Array.isArray(items) || items.length === 0) {
    // Seed with placeholder entries so the section isn't empty on first load
    items = [
      { text: "Scanned 10.10.14.7", ts: Date.now() - 3600000 },
      { text: "Queried CVE-2024-1234", ts: Date.now() - 7200000 },
      { text: "Generated report", ts: Date.now() - 18000000 },
    ];
    try { localStorage.setItem(KEY, JSON.stringify(items)); } catch (_) {}
  }
  return items.slice(0, 8);
}

function _dashSessionStats() {
  let sessions = 0, aiConvos = 0, toolsUsed = 0;
  try { sessions = parseInt(localStorage.getItem("dn_stat_sessions") || "0", 10) || 0; } catch (_) {}
  try { aiConvos = parseInt(localStorage.getItem("dn_stat_ai_convos") || "0", 10) || 0; } catch (_) {}
  try { toolsUsed = parseInt(localStorage.getItem("dn_stat_tools_used") || "0", 10) || 0; } catch (_) {}
  // Bump session count on each home render (deduplicated per page load)
  if (!window._dnSessionCounted) {
    window._dnSessionCounted = true;
    sessions++;
    try { localStorage.setItem("dn_stat_sessions", String(sessions)); } catch (_) {}
  }
  return { sessions, aiConvos, toolsUsed };
}

function renderContact(main) {
  main.innerHTML = `
    <h1 class="pg-h1">Contact</h1>
    <p class="muted pg-sub">Get in touch with the Darknode team.</p>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:24px;max-width:800px">
      <div class="panel">
        <h2 class="pg-h2" style="margin:0 0 16px">Send a Message</h2>
        <form id="contactForm">
          <div style="display:flex;flex-direction:column;gap:12px">
            <div>
              <label style="font-size:.82rem;color:var(--mut);display:block;margin-bottom:4px">Name</label>
              <input class="tk-f" type="text" id="cfName" placeholder="Your name" required style="width:100%">
            </div>
            <div>
              <label style="font-size:.82rem;color:var(--mut);display:block;margin-bottom:4px">Email</label>
              <input class="tk-f" type="email" id="cfEmail" placeholder="you@example.com" required style="width:100%">
            </div>
            <div>
              <label style="font-size:.82rem;color:var(--mut);display:block;margin-bottom:4px">Subject</label>
              <select class="tk-f" id="cfSubject" style="width:100%">
                <option>General Inquiry</option>
                <option>Bug Report</option>
                <option>Feature Request</option>
                <option>Partnership</option>
                <option>Security Issue</option>
                <option>Billing</option>
                <option>Other</option>
              </select>
            </div>
            <div>
              <label style="font-size:.82rem;color:var(--mut);display:block;margin-bottom:4px">Message</label>
              <textarea class="tk-in" id="cfMessage" rows="6" placeholder="How can we help?" required></textarea>
            </div>
            <button class="btn lg" type="submit" id="cfSubmit" style="margin-top:4px">Send Message</button>
            <p id="cfStatus" style="font-size:.82rem;margin:0"></p>
          </div>
        </form>
        <p class="muted" style="font-size:.72rem;margin-top:12px">Powered by Web3Forms. We typically respond within 24 hours.</p>
      </div>
      <div>
        <div class="panel" style="margin-bottom:16px">
          <h2 class="pg-h2" style="margin:0 0 12px">Other Ways to Reach Us</h2>
          <div style="display:flex;flex-direction:column;gap:12px;font-size:.88rem">
            <div><span class="muted">Email</span><br><strong>contact@darknode.ai</strong></div>
            <div><span class="muted">GitHub</span><br><a href="https://github.com/cashzombs-stack" target="_blank" rel="noopener" style="color:var(--acc)">github.com/cashzombs-stack</a></div>
            <div><span class="muted">Response Time</span><br><strong>Within 24 hours</strong></div>
          </div>
        </div>
        <div class="panel">
          <h2 class="pg-h2" style="margin:0 0 12px">Report a Security Issue</h2>
          <p class="muted" style="font-size:.84rem;margin:0 0 8px">Found a vulnerability? Please disclose responsibly.</p>
          <p style="font-size:.84rem;margin:0">Email <strong>security@darknode.ai</strong> with details. Do not open a public issue.</p>
        </div>
      </div>
    </div>`;
  document.getElementById("contactForm").onsubmit = async (e) => {
    e.preventDefault();
    const btn = document.getElementById("cfSubmit");
    const status = document.getElementById("cfStatus");
    const name = document.getElementById("cfName").value.trim();
    const email = document.getElementById("cfEmail").value.trim();
    const subject = document.getElementById("cfSubject").value;
    const message = document.getElementById("cfMessage").value.trim();
    if (!name || !email || !message) { status.textContent = "Please fill in all fields."; status.style.color = "var(--bad,red)"; return; }
    btn.disabled = true; btn.textContent = "Sending..."; status.textContent = "";
    try {
      const res = await fetch("https://api.web3forms.com/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ access_key: "f64b2617-cee3-4a87-b94c-fb667baab7cc", name, email, subject, message, from_name: "Darknode Contact Form" })
      });
      const data = await res.json();
      if (data.success) {
        status.textContent = "Message sent! We'll get back to you within 24 hours.";
        status.style.color = "var(--ok,#3fb950)";
        document.getElementById("cfName").value = "";
        document.getElementById("cfEmail").value = "";
        document.getElementById("cfMessage").value = "";
        btn.textContent = "Sent!";
      } else {
        status.textContent = "Failed to send. Try emailing contact@darknode.ai directly.";
        status.style.color = "var(--bad,red)";
        btn.disabled = false; btn.textContent = "Send Message";
      }
    } catch (err) {
      status.textContent = "Network error. Try emailing contact@darknode.ai directly.";
      status.style.color = "var(--bad,red)";
      btn.disabled = false; btn.textContent = "Send Message";
    }
  };
}

function renderHome(main, user, isOwner, show) {
  const name = user.displayName ? user.displayName.split(" ")[0] : "";
  const browsers = CATALOG.filter((t) => t.kind === "browser").length;
  const stat = (n, l, s) => `<div class="stat"><div class="stat-n">${n}</div><div class="stat-l">${l}</div>${s ? `<div class="stat-s">${s}</div>` : ""}</div>`;
  const qa = (sec, more, title, desc) => `<button class="qa" data-sec="${sec}" data-more="${more}"><div class="qa-title">${title}</div><div class="qa-desc">${desc}</div></button>`;
  const dt = _dashDateTime();
  const recentItems = _dashRecentActivity();
  const sStats = _dashSessionStats();

  const timeAgo = (ts) => {
    const diff = Date.now() - ts;
    if (diff < 60000) return "just now";
    if (diff < 3600000) return Math.floor(diff / 60000) + "m ago";
    if (diff < 86400000) return Math.floor(diff / 3600000) + "h ago";
    return Math.floor(diff / 86400000) + "d ago";
  };

  main.innerHTML = `
    <div class="dash-hero">
      <div class="dash-hero-top">
        <div class="dash-hero-left">
          <div class="eyebrow">SECURITY CONSOLE</div>
          <span class="dash-clock" id="dashClock">${esc(dt.date)} &bull; ${esc(dt.time)}</span>
        </div>
        <div class="dash-meta">
          <span class="dash-status"><span class="dash-status-dot"></span>All systems operational</span>
          <span class="dash-threat-level"><span class="dash-threat-pip t1"></span><span class="dash-threat-pip t2"></span><span class="dash-threat-pip t3"></span><span class="dash-threat-pip t4 dim"></span><span class="dash-threat-pip t5 dim"></span><span class="dash-threat-label">ELEVATED</span></span>
        </div>
      </div>
      <h1 class="pg-h1">Welcome back${name ? ", " + esc(name) : ""}</h1>
      <p class="muted pg-sub">192+ security tools, threat intel, local AI and training labs &mdash; your complete cybersecurity workflow.</p>
      <div class="hero-actions">
        <button class="btn" data-sec="tools">Browse tools</button>
        <button class="btn ghost" data-sec="ai">Nexus AI</button>
        <button class="btn ghost" data-sec="sentineleye">Sentinel Eye</button>
        <button class="btn ghost" data-sec="threat">Threat intel</button>
      </div>
    </div>
    <div class="stat-row">
      ${stat(CATALOG.length, "tools", browsers + " run in-browser")}
      ${stat(COUNTS.cheats, "cheat sheets")}
      ${stat(COUNTS.cves, "tracked CVEs")}
      ${stat(COUNTS.resources, "resources")}
      ${stat(CATEGORIES.length, "categories")}
      ${stat(59, "AI modules", "Ollama + cloud")}
      ${stat("378K+", "lines of code", "this web platform")}
    </div>
    <div class="dash-changelog">
      <div class="dash-cl-header">
        <h2 class="pg-h2">What's new</h2>
        <span class="dash-cl-viewall muted" data-sec="docs" data-more="">View all updates</span>
      </div>
      <div class="cl-items">
        <div class="cl-item"><span class="cl-tag new">NEW</span><span class="cl-text">PHANTOM &mdash; network traffic analysis with PCAP parsing, protocol dissection, anomaly detection</span><span class="cl-date muted">Sep 2026</span></div>
        <div class="cl-item"><span class="cl-tag new">NEW</span><span class="cl-text">CITADEL &mdash; SOC operations center with log correlation, detection rules, alert triage</span><span class="cl-date muted">Sep 2026</span></div>
        <div class="cl-item"><span class="cl-tag new">NEW</span><span class="cl-text">ORACLE &mdash; threat intelligence platform with IOC management and campaign tracking</span><span class="cl-date muted">Sep 2026</span></div>
        <div class="cl-item"><span class="cl-tag new">NEW</span><span class="cl-text">SPECTRE &mdash; cloud security posture management for AWS, Azure, and GCP</span><span class="cl-date muted">Sep 2026</span></div>
        <div class="cl-item"><span class="cl-tag new">NEW</span><span class="cl-text">Security Graph &mdash; unified entity store linking assets, indicators, incidents across all tools</span><span class="cl-date muted">Sep 2026</span></div>
        <div class="cl-item"><span class="cl-tag new">NEW</span><span class="cl-text">Investigation Workspace &mdash; case management, timelines, findings, and evidence collection</span><span class="cl-date muted">Sep 2026</span></div>
        <div class="cl-item"><span class="cl-tag imp">IMPROVED</span><span class="cl-text">Pro theme visual overhaul &mdash; refined sidebar, topbar, cards, command palette, AI chat</span><span class="cl-date muted">Sep 2026</span></div>
        <div class="cl-item"><span class="cl-tag fix">FIX</span><span class="cl-text">Sentinel Eye globe &mdash; satellite imagery, deeper zoom, sharper tiles</span><span class="cl-date muted">Sep 2026</span></div>
      </div>
    </div>
    <h2 class="pg-h2">Jump in</h2>
    <div class="dash-section">
      <h3 class="dash-cat-label">Flagship Tools</h3>
      <div class="qa-grid">
        ${qa("investigation", "", "Investigation Workspace", "Collect entities, build timelines, create findings &mdash; unified analyst workspace.")}
        ${qa("ai", "", "Nexus AI", "Chat with Ollama, Claude, GPT, Gemini &mdash; security &amp; coding help.")}
        ${qa("sentineleye", "", "Sentinel Eye", "Global threat visualization with live CesiumJS globe &amp; 14 intelligence tabs.")}
        ${qa("prometheus", "", "Prometheus", "AI-powered incident response engine with 40+ playbooks.")}
        ${qa("secdash", "", "Security Dashboard", "Unified dashboard for threat intel, alerts and system health.")}
        ${qa("phantom", "", "PHANTOM", "Deep packet inspection, protocol dissection &amp; network traffic analysis.")}
        ${qa("citadel", "", "CITADEL", "SOC operations center with log correlation, detection rules &amp; alert triage.")}
        ${qa("oracle", "", "ORACLE", "Threat intelligence platform with IOC management &amp; campaign tracking.")}
        ${qa("spectre", "", "SPECTRE", "Cloud security posture management for AWS, Azure &amp; GCP.")}
      </div>
    </div>
    <div class="dash-section">
      <h3 class="dash-cat-label">Security Operations</h3>
      <div class="qa-grid">
        ${qa("secgraph", "", "Security Graph", "Unified entity store &mdash; assets, indicators, incidents, and their relationships.")}
        ${qa("casemgmt", "", "Case Manager", "Track cases and incidents with priority, status, and linked entities.")}
      </div>
    </div>
    <div class="dash-section">
      <h3 class="dash-cat-label">Offensive Security</h3>
      <div class="qa-grid">
        ${qa("tools", "", "Scanner Suite", "Nmap, Nikto, Gobuster and 192+ security tools in one catalog.")}
        ${qa("payloads", "", "Test Script Forge", "Copy-ready security test scripts for common vulnerability classes.")}
        ${qa("exploitdev", "", "Security Research Lab", "Study and test vulnerability proofs-of-concept with built-in templates.")}
        ${qa("pentestconsole", "", "Security Assessment", "Interactive security assessment workflow with scoping and notes.")}
      </div>
    </div>
    <div class="dash-section">
      <h3 class="dash-cat-label">Intel &amp; Analysis</h3>
      <div class="qa-grid">
        ${qa("threat", "", "Threat Feed", "Notable CVEs, IOCs and a common-ports attack-surface reference.")}
        ${qa("breachlookup", "", "Breach Lookup", "Search major data breaches by company, year and severity.")}
        ${qa("netmap", "", "Network Mapper", "Visualize network topology, open ports and service fingerprints.")}
        ${qa("sandbox", "", "Threat Analysis Lab", "Analyze suspicious files and samples in an isolated environment.")}
      </div>
    </div>
    <div class="dash-section">
      <h3 class="dash-cat-label">Learn &amp; Practice</h3>
      <div class="qa-grid">
        ${qa("learn", "", "Academy", "Curated hubs: OWASP, security references, and learning resources.")}
        ${qa("cyberrange", "", "Cyber Range", "Hands-on security labs with guided walkthroughs.")}
        ${qa("cheats", "", "Cheat Sheets", "Copy-paste one-liners for recon, networking, security and more.")}
        ${qa("snippets", "", "Snippet Vault", "Everyday one-liners for bash, Python, JS, git, docker, SQL.")}
      </div>
    </div>
    <div class="dash-section">
      <h3 class="dash-cat-label">Utilities</h3>
      <div class="qa-grid">
        ${qa("utils", "", "Toolbox", "Run tools in your browser &mdash; encode, hash, decode JWTs, gen shells.")}
        ${qa("report", "", "Report Generator", "Generate professional pentest reports from your findings.")}
        ${qa("setup", "aicoding", "Local AI Setup", "Run Ollama models on your machine, in the terminal or a browser UI.")}
        ${qa("coder", "", "Nexus Agent", "AI-powered code generation and security analysis agent.")}
      </div>
    </div>
    <div class="dash-extras">
      <div class="dash-extra-col">
        <div class="panel dash-activity-panel">
          <div class="panel-h"><h2 class="pg-h2" style="margin:0">Recent activity</h2></div>
          <div class="dash-timeline" id="dashTimeline">
            ${recentItems.map((item) => `<div class="dash-tl-item"><span class="dash-tl-dot"></span><span class="dash-tl-text">${esc(item.text)}</span><span class="dash-tl-time muted">${timeAgo(item.ts)}</span></div>`).join("")}
          </div>
        </div>
      </div>
      <div class="dash-extra-col">
        <div class="panel dash-qstats-panel">
          <div class="panel-h"><h2 class="pg-h2" style="margin:0">Quick stats</h2></div>
          <div class="dash-qstats">
            <div class="dash-qs-item"><div class="dash-qs-n">${sStats.sessions}</div><div class="dash-qs-l">Total sessions</div></div>
            <div class="dash-qs-item"><div class="dash-qs-n">${sStats.aiConvos}</div><div class="dash-qs-l">AI conversations</div></div>
            <div class="dash-qs-item"><div class="dash-qs-n">${sStats.toolsUsed}</div><div class="dash-qs-l">Tools used</div></div>
          </div>
        </div>
      </div>
    </div>
    ${isOwner ? `<div class="admin-card"><strong>Owner controls</strong><p class="muted">You're the owner &mdash; admin features live under Admin in the sidebar.</p></div>` : ""}
    ${homeWidgetsHTML()}`;
  main.addEventListener("click", (e) => { const b = e.target.closest("[data-sec]"); if (b) show(b.dataset.sec, b.dataset.more || ""); });
  wireHome(main, show);
  // Recently used tools
  try {
    const recent = JSON.parse(localStorage.getItem("dn_recent") || "[]").slice(0, 6);
    if (recent.length) {
      const recentEl = document.createElement("div");
      recentEl.style.cssText = "margin:0 0 20px;display:flex;flex-wrap:wrap;align-items:center;gap:8px";
      recentEl.innerHTML = '<span style="font-size:.75rem;font-weight:600;color:var(--mut);text-transform:uppercase;letter-spacing:.05em;margin-right:4px">Recent</span>' +
        recent.map(s => `<button class="btn sm ghost" data-sec="${esc(s)}" style="font-size:.72rem;padding:4px 12px">${esc(labelOf(s))}</button>`).join("");
      const qaGrid = main.querySelector(".qa-grid");
      if (qaGrid) qaGrid.parentNode.insertBefore(recentEl, qaGrid);
    }
  } catch (_) {}

  // Live clock update
  const clockEl = main.querySelector("#dashClock");
  if (clockEl) {
    const tickClock = () => {
      const d = _dashDateTime();
      clockEl.textContent = d.date + " -- " + d.time;
    };
    const clockTimer = setInterval(tickClock, 30000);
    // Clean up when the element is removed from DOM
    const obs = new MutationObserver(() => { if (!document.contains(clockEl)) { clearInterval(clockTimer); obs.disconnect(); } });
    obs.observe(document.body, { childList: true, subtree: true });
  }
}

function renderSetup(main, openTo) {
  main.innerHTML = `
    <h1 class="pg-h1">Local setup</h1>
    <p class="muted pg-sub">A website can't run these &mdash; spin them up on your own machine with one copy-paste.</p>
    ${MORE.map((m) => `<div class="card" id="setup-${m.id}"><h3 style="margin:0 0 6px">${esc(m.name)}</h3><p class="muted" style="margin:0 0 12px">${esc(m.desc)}</p>
      <div class="dl-cmd-row"><code class="dl-cmd cmd-block">${esc(m.body)}</code><button class="dl-copy" data-copy="${m.id}">copy</button></div></div>`).join("")}`;
  main.onclick = (e) => {
    const b = e.target.closest("[data-copy]"); if (!b) return;
    const m = MORE.find((x) => x.id === b.dataset.copy);
    navigator.clipboard?.writeText(m.body).then(() => { b.textContent = "copied"; setTimeout(() => (b.textContent = "copy"), 1200); });
  };
  if (openTo) { const el = main.querySelector("#setup-" + openTo); if (el) el.scrollIntoView({ behavior: "smooth", block: "center" }); }
}

function renderSettingsPage(main, user, isOwner) {
  const providers = user.providerData.map((p) => p.providerId.replace(".com", "")).join(", ") || "password";
  const created = user.metadata?.creationTime ? new Date(user.metadata.creationTime).toLocaleDateString() : "—";
  const row = (k, v) => `<div class="set-row"><span class="muted">${k}</span><span>${v}</span></div>`;
  const SET_TABS = [["account", "Account"], ["appearance", "Appearance"], ["security", "Security"], ["apikeys", "API Keys"], ["darknode", "Darknode API"], ["mcp", "MCP Server"], ["nexus", "Nexus CLI"], ["about", "About"]];
  // Local Darknode API key — client-side generated token so tools, the CLI and
  // an MCP client can authenticate to this workspace. Stored only in this browser.
  const dnKey = (() => {
    try {
      let k = localStorage.getItem("dn_api_key");
      if (!k) {
        const b = new Uint8Array(24); (crypto || window.crypto).getRandomValues(b);
        k = "dn_live_" + Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
        localStorage.setItem("dn_api_key", k);
      }
      return k;
    } catch (_) { return "dn_live_0000000000000000000000000000000000000000000000"; }
  })();
  const dnMask = dnKey.slice(0, 12) + "…" + dnKey.slice(-4);
  const curLogo = (() => { try { return localStorage.getItem("sw_logo") || "nested-accent"; } catch (_) { return "nested-accent"; } })();
  const panels = {
    account: `<h2 class="set-panel-h">Account</h2>
      ${row("Name", esc(user.displayName || "—"))}
      ${row("Email", esc(user.email) + (isOwner ? ' <span class="owner-badge">OWNER</span>' : ""))}
      ${row("Signed in via", esc(providers))}
      ${row("Member since", esc(created))}
      ${row("User ID", '<span class="mono">' + esc(user.uid) + "</span>")}`,
    appearance: `<h2 class="set-panel-h">Appearance</h2>
      <div class="set-row"><span class="muted">Style</span>
        <span class="seg" id="sw-style"><button data-style="pro">Professional</button><button data-style="command">Command Center</button><button data-style="dark">Dark</button><button data-style="classic">Classic</button></span></div>
      <div class="set-row"><span class="muted">Accent color</span>
        <span class="swatches" id="sw-acc">${ACCENTS.map((c) => `<button class="swatch" style="background:${c}" data-c="${c}" title="${c}"></button>`).join("")}</span></div>
      <div class="set-row"><span class="muted">Logo</span>
        <span class="logo-picks" id="sw-logo">${Object.entries(LOGO_VARIANTS).map(([k, v]) => `<button class="logo-pick${k === curLogo ? " on" : ""}" data-logo="${k}" title="${v.label}"><svg viewBox="0 0 100 100" width="28" height="28">${v.svg.replace(/currentColor/g, "#F2F5F9")}</svg></button>`).join("")}</span></div>
      <div class="set-row"><span class="muted">Boot screen</span>
        <span class="seg" id="sw-boot"><button data-boot="pro">Professional</button><button data-boot="classic">Classic</button></span></div>
      <div class="set-row"><span class="muted">CRT scanlines</span>
        <span class="seg" id="sw-crt"><button data-crt="1">On</button><button data-crt="0">Off</button></span></div>
      <div class="set-row"><span class="muted">Shell mode</span>
        <span class="seg" id="sw-shell"><button data-shell="education">Education</button><button data-shell="real">Real Terminal</button></span></div>
      <p class="muted" style="font-size:.72rem;margin-top:4px">Education mode uses a simulated filesystem. Real Terminal connects to a local agent on your machine via WebSocket.</p>
      <h3 class="set-sub-h">Layout &amp; motion</h3>
      <div class="set-row"><span class="muted">Density</span>
        <span class="seg" id="sw-density"><button data-density="comfortable">Comfortable</button><button data-density="compact">Compact</button></span></div>
      <div class="set-row"><span class="muted">Sidebar default</span>
        <span class="seg" id="sw-sidew"><button data-sidew="expanded">Expanded</button><button data-sidew="rail">Icon rail</button></span></div>
      <div class="set-row"><span class="muted">Animations</span>
        <span class="seg" id="sw-motion"><button data-motion="on">On</button><button data-motion="off">Reduced</button></span></div>
      <div class="set-row"><span class="muted">Live topbar</span>
        <span class="seg" id="sw-topbar"><button data-topbar="on">Show</button><button data-topbar="off">Hide</button></span></div>
      <p class="muted" style="font-size:.72rem;margin-top:4px">Compact tightens padding across the app. Icon rail starts the sidebar collapsed. Reduced turns off transitions and animations.</p>`,
    security: `<h2 class="set-panel-h">Security</h2>
      <div class="set-btns" style="margin-top:8px">
        <button class="btn ghost" id="set-pw">Change password</button>
        <button class="btn ghost" id="set-tour">Replay walkthrough</button>
        <button class="btn danger" id="set-out">Log out</button>
      </div>`,
    apikeys: `<h2 class="set-panel-h">API Keys</h2>
      <p class="muted" style="font-size:.84rem;margin-bottom:16px">Add your own API keys to power AI and threat intelligence. Keys are stored locally in your browser — never sent to our servers.</p>
      <div id="set-apikeys-form" style="display:flex;flex-direction:column;gap:12px;max-width:500px">
        <h3 style="font-size:.92rem;margin:0;opacity:.7">AI Engines</h3>
        <div class="set-row" style="flex-direction:column;align-items:stretch;gap:4px"><span class="muted">Groq (free)</span><input class="tk-f" id="ak-groq" type="password" placeholder="gsk_..." autocomplete="off" spellcheck="false" style="width:100%"><span class="muted" style="font-size:.72rem">Free at <a href="https://console.groq.com" target="_blank" rel="noopener" style="color:var(--acc)">console.groq.com</a> — Llama 3.3 70B, Gemma, Mixtral (no credit card)</span></div>
        <div class="set-row" style="flex-direction:column;align-items:stretch;gap:4px"><span class="muted">OpenRouter</span><input class="tk-f" id="ak-openrouter" type="password" placeholder="sk-or-..." autocomplete="off" spellcheck="false" style="width:100%"><span class="muted" style="font-size:.72rem">Get a key at <a href="https://openrouter.ai/keys" target="_blank" rel="noopener" style="color:var(--acc)">openrouter.ai</a> — one key, 100+ models (Claude, GPT, Llama, DeepSeek)</span></div>
        <div class="set-row" style="flex-direction:column;align-items:stretch;gap:4px"><span class="muted">Anthropic (Claude)</span><input class="tk-f" id="ak-anthropic" type="password" placeholder="sk-ant-..." autocomplete="off" spellcheck="false" style="width:100%"><span class="muted" style="font-size:.72rem">Get a key at <a href="https://console.anthropic.com/settings/keys" target="_blank" rel="noopener" style="color:var(--acc)">console.anthropic.com</a> — powers AI Assistant (Claude)</span></div>
        <div class="set-row" style="flex-direction:column;align-items:stretch;gap:4px"><span class="muted">OpenAI (GPT)</span><input class="tk-f" id="ak-openai" type="password" placeholder="sk-..." autocomplete="off" spellcheck="false" style="width:100%"><span class="muted" style="font-size:.72rem">Get a key at <a href="https://platform.openai.com/api-keys" target="_blank" rel="noopener" style="color:var(--acc)">platform.openai.com</a> — powers AI Assistant (GPT)</span></div>
        <div class="set-row" style="flex-direction:column;align-items:stretch;gap:4px"><span class="muted">Google (Gemini)</span><input class="tk-f" id="ak-gemini" type="password" placeholder="AI..." autocomplete="off" spellcheck="false" style="width:100%"><span class="muted" style="font-size:.72rem">Get a key at <a href="https://aistudio.google.com/apikey" target="_blank" rel="noopener" style="color:var(--acc)">aistudio.google.com</a> — powers AI Assistant (Gemini)</span></div>
        <h3 style="font-size:.92rem;margin:8px 0 0;opacity:.7">Threat Intelligence</h3>
        <div class="set-row" style="flex-direction:column;align-items:stretch;gap:4px"><span class="muted">AbuseIPDB</span><input class="tk-f" id="ak-abuseipdb" type="password" placeholder="Your AbuseIPDB API key" autocomplete="off" spellcheck="false" style="width:100%"><span class="muted" style="font-size:.72rem">Free at <a href="https://www.abuseipdb.com/account/api" target="_blank" rel="noopener" style="color:var(--acc)">abuseipdb.com</a> — IP reputation checks</span></div>
        <div class="set-row" style="flex-direction:column;align-items:stretch;gap:4px"><span class="muted">VirusTotal</span><input class="tk-f" id="ak-virustotal" type="password" placeholder="Your VirusTotal API key" autocomplete="off" spellcheck="false" style="width:100%"><span class="muted" style="font-size:.72rem">Free at <a href="https://www.virustotal.com/gui/my-apikey" target="_blank" rel="noopener" style="color:var(--acc)">virustotal.com</a> — file/URL/IP analysis</span></div>
        <div class="set-row" style="flex-direction:column;align-items:stretch;gap:4px"><span class="muted">Shodan</span><input class="tk-f" id="ak-shodan" type="password" placeholder="Your Shodan API key" autocomplete="off" spellcheck="false" style="width:100%"><span class="muted" style="font-size:.72rem">Free at <a href="https://account.shodan.io" target="_blank" rel="noopener" style="color:var(--acc)">shodan.io</a> — internet-wide scanning data</span></div>
        <div class="set-row" style="flex-direction:column;align-items:stretch;gap:4px"><span class="muted">AlienVault OTX</span><input class="tk-f" id="ak-otx" type="password" placeholder="Your OTX API key" autocomplete="off" spellcheck="false" style="width:100%"><span class="muted" style="font-size:.72rem">Free at <a href="https://otx.alienvault.com/accounts/signup" target="_blank" rel="noopener" style="color:var(--acc)">otx.alienvault.com</a> — threat intelligence pulses</span></div>
        <div style="display:flex;gap:8px;margin-top:4px">
          <button class="btn" id="ak-save">Save Keys</button>
          <button class="btn ghost" id="ak-clear">Clear All</button>
          <span id="ak-status" style="font-size:.82rem;align-self:center"></span>
        </div>
      </div>`,
    darknode: `<h2 class="set-panel-h">Darknode API</h2>
      <p class="muted" style="font-size:.84rem;margin-bottom:14px">Your personal Darknode API key. It lets the CLI, the MCP server, and your own scripts authenticate to this workspace and drive its 192+ tools. Generated and stored locally in your browser — never sent to our servers.</p>
      <div class="dn-keycard">
        <div class="dn-keycard-top"><span class="dn-keycard-label">Secret key</span><span class="dn-keycard-scope">full-access</span></div>
        <div class="dn-key-row">
          <input id="dn-key" class="mono" type="password" readonly value="${esc(dnKey)}" autocomplete="off" spellcheck="false">
          <button class="btn ghost" id="dn-key-reveal" type="button">Reveal</button>
          <button class="btn ghost" id="dn-key-copy" type="button">Copy</button>
          <button class="btn ghost" id="dn-key-regen" type="button">Regenerate</button>
        </div>
        <div class="dn-key-fine muted">Preview: <span class="mono">${esc(dnMask)}</span> · treat this like a password. Regenerating immediately revokes the old key.</div>
      </div>
      <h3 class="set-sub-h">Quick start</h3>
      <p class="muted" style="font-size:.8rem;margin:0 0 6px">Call any tool over HTTPS with your key as a Bearer token:</p>
      <pre class="set-code"><button class="set-code-copy" data-code="dn-curl">copy</button><code id="dn-curl">curl https://api.darknode.ai/v1/scan \\
  -H "Authorization: Bearer ${esc(dnKey)}" \\
  -H "Content-Type: application/json" \\
  -d '{"tool":"subdomain-enum","target":"example.com"}'</code></pre>
      <h3 class="set-sub-h">Scopes &amp; limits</h3>
      <div class="dn-scopes">
        <div class="dn-scope"><b>recon:read</b><span>DNS, subdomains, ASN, WHOIS, favicon</span></div>
        <div class="dn-scope"><b>intel:read</b><span>CVE, threat feeds, IOC, reputation</span></div>
        <div class="dn-scope"><b>tools:run</b><span>Execute any of the 192+ platform tools</span></div>
        <div class="dn-scope"><b>ai:invoke</b><span>Nexus AI completions &amp; analysis</span></div>
        <div class="dn-scope"><b>graph:write</b><span>Push findings to the Security Graph</span></div>
        <div class="dn-scope"><b>rate</b><span>1000 requests / hour (local tier)</span></div>
      </div>
      <p class="muted" style="font-size:.72rem;margin-top:10px">Note: the hosted API endpoint is part of the Darknode CLI / self-host bundle. In the browser-only build this key authenticates the local CLI bridge and MCP server.</p>`,
    mcp: `<h2 class="set-panel-h">MCP Server</h2>
      <p class="muted" style="font-size:.84rem;margin-bottom:14px">Connect Darknode to any MCP-compatible AI client (Claude Desktop, Claude Code, Cursor, and others) so the model can run Darknode's tools directly. Paste the config below and restart your client.</p>
      <h3 class="set-sub-h">Claude Desktop / Claude Code config</h3>
      <pre class="set-code"><button class="set-code-copy" data-code="dn-mcp">copy</button><code id="dn-mcp">{
  "mcpServers": {
    "darknode": {
      "command": "npx",
      "args": ["-y", "@darknode/mcp"],
      "env": {
        "DARKNODE_API_KEY": "${esc(dnKey)}"
      }
    }
  }
}</code></pre>
      <p class="muted" style="font-size:.75rem;margin:2px 0 0">Config path — macOS: <span class="mono">~/Library/Application Support/Claude/claude_desktop_config.json</span> · Windows: <span class="mono">%APPDATA%\\Claude\\claude_desktop_config.json</span></p>
      <h3 class="set-sub-h">Tools exposed to the model</h3>
      <div class="dn-scopes">
        <div class="dn-scope"><b>darknode.recon</b><span>Subdomains, DNS, ASN, ports, favicon hash</span></div>
        <div class="dn-scope"><b>darknode.intel</b><span>CVE lookup, threat feeds, IOC extraction</span></div>
        <div class="dn-scope"><b>darknode.scan</b><span>SSL/TLS, headers, CSP, CORS, API security</span></div>
        <div class="dn-scope"><b>darknode.analyze</b><span>Hashes, JWTs, emails, logs, packets</span></div>
        <div class="dn-scope"><b>darknode.graph</b><span>Query &amp; write the Security Graph</span></div>
        <div class="dn-scope"><b>darknode.ai</b><span>Delegate reasoning to Nexus AI</span></div>
      </div>
      <div class="set-btns" style="margin-top:14px">
        <button class="btn" id="dn-mcp-copy2">Copy config</button>
        <a class="btn ghost" data-foot="downloads">Get the CLI bundle</a>
      </div>
      <p class="muted" style="font-size:.72rem;margin-top:10px">The <span class="mono">@darknode/mcp</span> package ships with the Darknode CLI. It bridges to this workspace using the API key above, so the model acts with your access only.</p>`,
    nexus: `<h2 class="set-panel-h">Nexus CLI</h2>
      <p class="muted">Sign in to the Nexus terminal agent with this code. In Nexus, run <span class="mono">/login</span> and paste it.</p>
      <div class="set-row"><span class="muted">Your code</span>
        <span class="nexus-code-row">
          <input id="nexus-code" class="mono" type="password" readonly value="${esc(user.refreshToken || "")}" autocomplete="off" spellcheck="false">
          <button class="btn ghost" id="nexus-reveal" type="button">Reveal</button>
          <button class="btn ghost" id="nexus-copy" type="button">Copy</button>
        </span></div>
      <p class="muted" style="font-size:.75rem">Treat this like a password. Changing your password revokes it.</p>`,
    about: `<h2 class="set-panel-h">About</h2>
      <p class="muted">Darknode -- your security workspace. In-browser tools plus install commands for everything that runs on your machine.</p>
      <p class="muted" style="font-size:.75rem">Version 1.0</p>`,
  };
  main.innerHTML = `
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:4px">
      <button class="btn ghost" id="set-back" style="padding:4px 12px;font-size:.82rem">&larr; Back</button>
      <h1 class="pg-h1" style="margin:0">Settings</h1>
    </div>
    <div class="set-layout">
      <nav class="set-nav">${SET_TABS.map(([k, l]) => `<button class="set-tab${k === "account" ? " active" : ""}" data-stab="${k}">${l}</button>`).join("")}</nav>
      <div class="set-panel" id="set-panel">${panels.account}</div>
    </div>`;
  const backBtn = main.querySelector("#set-back");
  if (backBtn) backBtn.onclick = () => appShow && appShow("home");
  let curTab = "account";
  function showSetTab(tab) {
    curTab = tab;
    const panel = main.querySelector("#set-panel"); if (!panel) return;
    panel.innerHTML = panels[tab] || "";
    main.querySelectorAll(".set-tab").forEach(b => b.classList.toggle("active", b.dataset.stab === tab));
    wireSetPanel();
  }
  function wireSetPanel() {
    const acc = main.querySelector("#sw-acc");
    if (acc) acc.onclick = (e) => { const b = e.target.closest(".swatch"); if (b) applyAccent(b.dataset.c); };
    const logoSeg = main.querySelector("#sw-logo");
    if (logoSeg) logoSeg.onclick = (e) => { const b = e.target.closest(".logo-pick"); if (!b) return; applyLogo(b.dataset.logo); logoSeg.querySelectorAll(".logo-pick").forEach((x) => x.classList.toggle("on", x === b)); };
    const themeSeg = main.querySelector("#sw-theme");
    if (themeSeg) { const curTheme = document.documentElement.getAttribute("data-theme") || "dark"; themeSeg.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.t === curTheme)); themeSeg.onclick = (e) => { const b = e.target.closest("button[data-t]"); if (!b) return; applyTheme(b.dataset.t); themeSeg.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b)); }; }
    const styleSeg = main.querySelector("#sw-style");
    if (styleSeg) { let curStyle = "pro"; try { curStyle = localStorage.getItem("sw_style") || "pro"; } catch (_) {} styleSeg.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.style === curStyle)); styleSeg.onclick = (e) => { const b = e.target.closest("button[data-style]"); if (!b) return; setStyle(b.dataset.style); styleSeg.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b)); }; }
    const bootSeg = main.querySelector("#sw-boot");
    if (bootSeg) { let curBoot = "pro"; try { curBoot = localStorage.getItem("sw_boot_theme") || "pro"; } catch (_) {} bootSeg.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.boot === curBoot)); bootSeg.onclick = (e) => { const b = e.target.closest("button[data-boot]"); if (!b) return; try { localStorage.setItem("sw_boot_theme", b.dataset.boot); } catch (_) {} bootSeg.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b)); }; }
    const crtSeg = main.querySelector("#sw-crt");
    if (crtSeg) { crtSeg.querySelectorAll("button").forEach((b) => b.classList.toggle("on", (b.dataset.crt === "1") === crtOn())); crtSeg.onclick = (e) => { const b = e.target.closest("button[data-crt]"); if (!b) return; applyCrt(b.dataset.crt === "1"); crtSeg.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b)); }; }
    const shellSeg = main.querySelector("#sw-shell");
    if (shellSeg) { const curShell = (() => { try { return localStorage.getItem("dn_shell_mode") || "education"; } catch (_) { return "education"; } })(); shellSeg.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.shell === curShell)); shellSeg.onclick = (e) => { const b = e.target.closest("button[data-shell]"); if (!b) return; try { localStorage.setItem("dn_shell_mode", b.dataset.shell); } catch (_) {} shellSeg.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b)); }; }
    const segWire = (id, attr, applier) => {
      const seg = main.querySelector(id); if (!seg) return;
      const cur = document.documentElement.getAttribute("data-" + attr) || seg.querySelector("button").dataset[attr];
      seg.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset[attr] === cur));
      seg.onclick = (e) => { const b = e.target.closest("button[data-" + attr + "]"); if (!b) return; applier(b.dataset[attr]); seg.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b)); };
    };
    segWire("#sw-density", "density", applyDensity);
    segWire("#sw-motion", "motion", applyMotion);
    segWire("#sw-topbar", "topbar", applyTopbarPref);
    const sidewSeg = main.querySelector("#sw-sidew");
    if (sidewSeg) {
      let cur = "expanded"; try { cur = localStorage.getItem("sw_sidebar_collapsed") === "1" ? "rail" : "expanded"; } catch (_) {}
      sidewSeg.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.sidew === cur));
      sidewSeg.onclick = (e) => { const b = e.target.closest("button[data-sidew]"); if (!b) return; const rail = b.dataset.sidew === "rail"; try { localStorage.setItem("sw_sidebar_collapsed", rail ? "1" : "0"); } catch (_) {} const sb = document.getElementById("sidebar"); if (sb) sb.classList.toggle("collapsed", rail); sidewSeg.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b)); };
    }
    // Darknode API key controls
    const dnKeyEl = main.querySelector("#dn-key");
    if (dnKeyEl) {
      const rev = main.querySelector("#dn-key-reveal"); if (rev) rev.onclick = () => { const h = dnKeyEl.type === "password"; dnKeyEl.type = h ? "text" : "password"; rev.textContent = h ? "Hide" : "Reveal"; };
      const cp = main.querySelector("#dn-key-copy"); if (cp) cp.onclick = async () => { try { await navigator.clipboard.writeText(dnKeyEl.value); } catch (_) {} const o = cp.textContent; cp.textContent = "Copied"; setTimeout(() => { cp.textContent = o; }, 1200); };
      const rg = main.querySelector("#dn-key-regen"); if (rg) rg.onclick = () => {
        if (!confirm("Regenerate your Darknode API key? The current key stops working immediately.")) return;
        try { const b = new Uint8Array(24); crypto.getRandomValues(b); const nk = "dn_live_" + Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join(""); localStorage.setItem("dn_api_key", nk); } catch (_) {}
        showSetTab("darknode");
      };
    }
    // MCP + code-block copy buttons
    const mcpCopy = main.querySelector("#dn-mcp-copy2");
    if (mcpCopy) mcpCopy.onclick = async () => { const c = main.querySelector("#dn-mcp"); if (c) { try { await navigator.clipboard.writeText(c.textContent); } catch (_) {} const o = mcpCopy.textContent; mcpCopy.textContent = "Copied"; setTimeout(() => { mcpCopy.textContent = o; }, 1200); } };
    main.querySelectorAll(".set-code-copy").forEach((btn) => { btn.onclick = async () => { const c = main.querySelector("#" + btn.dataset.code); if (!c) return; try { await navigator.clipboard.writeText(c.textContent); } catch (_) {} const o = btn.textContent; btn.textContent = "copied"; setTimeout(() => { btn.textContent = o; }, 1200); }; });
    const akSave = main.querySelector("#ak-save");
    if (akSave) {
      const akFields = [["groq", "#ak-groq"], ["openrouter", "#ak-openrouter"], ["anthropic", "#ak-anthropic"], ["openai", "#ak-openai"], ["gemini", "#ak-gemini"], ["abuseipdb", "#ak-abuseipdb"], ["virustotal", "#ak-virustotal"], ["shodan", "#ak-shodan"], ["otx", "#ak-otx"]];
      try {
        const keys = JSON.parse(localStorage.getItem("dn_api_keys") || "{}");
        akFields.forEach(([svc, sel]) => { const el = main.querySelector(sel); if (el && keys[svc]) el.value = keys[svc]; });
        const qk = (localStorage.getItem("sw_groq_key") || "").trim(); if (qk && !keys.groq) { const el = main.querySelector("#ak-groq"); if (el) el.value = qk; }
        const ork = (localStorage.getItem("sw_openrouter_key") || "").trim(); if (ork && !keys.openrouter) { const el = main.querySelector("#ak-openrouter"); if (el) el.value = ork; }
        const ck = (localStorage.getItem("sw_claude_key") || "").trim(); if (ck && !keys.anthropic) { const el = main.querySelector("#ak-anthropic"); if (el) el.value = ck; }
        const ok = (localStorage.getItem("sw_openai_key") || "").trim(); if (ok && !keys.openai) { const el = main.querySelector("#ak-openai"); if (el) el.value = ok; }
        const gk = (localStorage.getItem("sw_gemini_key") || "").trim(); if (gk && !keys.gemini) { const el = main.querySelector("#ak-gemini"); if (el) el.value = gk; }
      } catch (_) {}
      akSave.onclick = () => {
        try {
          const keys = JSON.parse(localStorage.getItem("dn_api_keys") || "{}");
          akFields.forEach(([svc, sel]) => { const el = main.querySelector(sel); if (el) { const v = el.value.trim(); if (v) keys[svc] = v; else delete keys[svc]; } });
          localStorage.setItem("dn_api_keys", JSON.stringify(keys));
          if (keys.groq) localStorage.setItem("sw_groq_key", keys.groq); else localStorage.removeItem("sw_groq_key");
          if (keys.openrouter) localStorage.setItem("sw_openrouter_key", keys.openrouter); else localStorage.removeItem("sw_openrouter_key");
          if (keys.anthropic) localStorage.setItem("sw_claude_key", keys.anthropic); else localStorage.removeItem("sw_claude_key");
          if (keys.openai) localStorage.setItem("sw_openai_key", keys.openai); else localStorage.removeItem("sw_openai_key");
          if (keys.gemini) localStorage.setItem("sw_gemini_key", keys.gemini); else localStorage.removeItem("sw_gemini_key");
          const st = main.querySelector("#ak-status"); if (st) { st.textContent = "Keys saved."; st.style.color = "var(--ok,#3fb950)"; setTimeout(() => { st.textContent = ""; }, 2000); }
        } catch (e) { const st = main.querySelector("#ak-status"); if (st) { st.textContent = "Error: " + e.message; st.style.color = "var(--bad,red)"; } }
      };
    }
    const akClear = main.querySelector("#ak-clear");
    if (akClear) {
      akClear.onclick = () => {
        try { localStorage.removeItem("dn_api_keys"); localStorage.removeItem("sw_groq_key"); localStorage.removeItem("sw_openrouter_key"); localStorage.removeItem("sw_claude_key"); localStorage.removeItem("sw_openai_key"); localStorage.removeItem("sw_gemini_key"); } catch (_) {}
        const inputs = main.querySelectorAll("#set-apikeys-form input"); inputs.forEach((el) => { el.value = ""; });
        const st = main.querySelector("#ak-status"); if (st) { st.textContent = "All keys cleared."; st.style.color = "var(--ok,#3fb950)"; setTimeout(() => { st.textContent = ""; }, 2000); }
      };
    }
    const out = main.querySelector("#set-out"); if (out) out.onclick = () => signOut(auth);
    const tour = main.querySelector("#set-tour"); if (tour) tour.onclick = () => startTour(tourSteps(isOwner));
    const pwBtn = main.querySelector("#set-pw");
    if (pwBtn) pwBtn.onclick = async () => { try { await sendPasswordResetEmail(auth, user.email, RESET_ACS); showToast("Password reset link sent to " + user.email, "success"); } catch (e) { showToast(errText(e), "error"); } };
    const codeInput = main.querySelector("#nexus-code");
    if (codeInput) {
      if (!codeInput.value) { user.getIdToken().then(() => { codeInput.value = user.refreshToken || ""; }).catch(() => {}); }
      const rev = main.querySelector("#nexus-reveal"); if (rev) rev.onclick = (e) => { const hidden = codeInput.type === "password"; codeInput.type = hidden ? "text" : "password"; e.target.textContent = hidden ? "Hide" : "Reveal"; };
      const cp = main.querySelector("#nexus-copy"); if (cp) cp.onclick = async (e) => { try { await navigator.clipboard.writeText(codeInput.value); } catch (_) { const t = codeInput.type; codeInput.type = "text"; codeInput.select(); try { document.execCommand("copy"); } catch (__) {} codeInput.type = t; } const b = e.target, o = b.textContent; b.textContent = "Copied"; setTimeout(() => { b.textContent = o; }, 1200); };
    }
  }
  main.querySelector(".set-nav").onclick = (e) => { const b = e.target.closest(".set-tab"); if (b) showSetTab(b.dataset.stab); };
  wireSetPanel();
}

// Gamer "ACCESS GRANTED" neon-portal transition, played once on a FRESH sign-in
// (never on a session-restore page load). Renders the app under the overlay
// mid-animation so it's ready as the portal clears. Falls straight through when
// the visitor prefers reduced motion.
function playAccessGranted(name, cb) {
  try {
    if (window.matchMedia && window.matchMedia("(prefers-reduced-motion:reduce)").matches) { cb(); return; }
  } catch (_) {}
  const safe = String(name || "").replace(/[<>&"']/g, "").slice(0, 24);
  const o = document.createElement("div");
  o.id = "xfer";
  o.innerHTML = '<div class="xgrid"></div><div class="xring"></div><div class="xring b"></div>'
    + '<div class="xmsg"><div class="xgranted">Welcome Operator</div><div class="xwho">'
    + (safe ? safe : "Access Granted") + '</div></div><div class="xflash"></div>';
  document.body.appendChild(o);
  let ran = false; const go = () => { if (ran) return; ran = true; try { cb(); } catch (_) {} };
  setTimeout(go, 720);                    // build the app beneath the portal
  setTimeout(() => { try { o.remove(); } catch (_) {} }, 1800); // remove after it fades
}

function renderApp(user) {
  dismissBoot();
  document.body.classList.remove("landing");
  document.body.classList.add("app");
  const isOwner = user.email === OWNER_EMAIL;
  const avatar = user.photoURL
    ? `<img class="p-avatar" src="${esc(user.photoURL)}" alt="">`
    : `<span class="p-avatar p-initials">${esc((user.email || "?")[0].toUpperCase())}</span>`;
  const name = user.displayName || user.email;

  view.innerHTML = `
    <div class="app-shell">
      <aside class="sidebar" id="sidebar" role="complementary" aria-label="Main navigation">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;padding:0 4px">
          <button class="side-toggle" id="sideToggle" aria-label="Toggle sidebar" title="Toggle sidebar">
            <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><line x1="3" y1="4" x2="13" y2="4"/><line x1="3" y1="8" x2="13" y2="8"/><line x1="3" y1="12" x2="13" y2="12"/></svg>
          </button>
          <span class="side-brand" style="margin:0;padding:0;font-size:.72rem">DARKNODE</span>
        </div>
        <nav class="side-nav" role="navigation" aria-label="Application sections">
          <div class="side-search-wrap"><input class="side-search" placeholder="Search 192+ tools..." id="sideSearch" spellcheck="false" autocomplete="off"><svg class="side-search-icon" viewBox="0 0 16 16" width="13" height="13"><circle cx="6.5" cy="6.5" r="5" fill="none" stroke="currentColor" stroke-width="1.5"/><line x1="10" y1="10" x2="14" y2="14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg></div>
          <button class="side-item" data-sec="home">Dashboard</button>

          <div class="side-group side-collapse" data-open="1" data-color="blue">Mission Control <span class="side-cnt">12</span></div>
          <button class="side-item" data-sec="prometheus">PROMETHEUS <span class="side-badge live">LIVE</span></button>
          <button class="side-item" data-sec="sentineleye">SENTINEL EYE <span class="side-badge live">LIVE</span></button>
          <button class="side-item" data-sec="hydra">HYDRA Engine</button>
          <button class="side-item" data-sec="aegis">AEGIS Ops Center</button>
          <button class="side-item" data-sec="vanguard">VANGUARD</button>
          <button class="side-item" data-sec="phantom">PHANTOM <span class="side-badge live">LIVE</span></button>
          <button class="side-item" data-sec="citadel">CITADEL <span class="side-badge live">LIVE</span></button>
          <button class="side-item" data-sec="oracle">ORACLE <span class="side-badge live">LIVE</span></button>
          <button class="side-item" data-sec="spectre">SPECTRE <span class="side-badge live">LIVE</span></button>
          <button class="side-item" data-sec="crucible">CRUCIBLE <span class="side-badge live">LIVE</span></button>
          <button class="side-item" data-sec="navarch">NAVARCH <span class="side-badge live">LIVE</span></button>
          <button class="side-item" data-sec="secdash">Security Dashboard</button>

          <div class="side-group side-collapse" data-color="red">Offensive Security <span class="side-cnt">11</span></div>
          <button class="side-item" data-sec="attacksim">Threat Simulator</button>
          <button class="side-item" data-sec="cracklab">Password Security Lab</button>
          <button class="side-item" data-sec="exploitdb">Vulnerability Database</button>
          <button class="side-item" data-sec="exploitdev">Security Research Lab</button>
          <button class="side-item" data-sec="packetcraft">Packet Crafter</button>
          <button class="side-item" data-sec="passwordtools">Password Tools</button>
          <button class="side-item" data-sec="payloads">Test Script Forge</button>
          <button class="side-item" data-sec="payloadgen">Test Script Generator</button>
          <button class="side-item" data-sec="pentestconsole">Security Assessment</button>
          <button class="side-item" data-sec="privesc">Privilege Analysis</button>
          <button class="side-item" data-sec="reverseshell">Remote Access Testing</button>

          <div class="side-group side-collapse" data-color="red">Security Labs <span class="side-cnt">5</span></div>
          <button class="side-item" data-sec="firewall">Firewall Rules</button>
          <button class="side-item" data-sec="webshell">Terminal</button>
          <button class="side-item" data-sec="wirelesslab">Wireless Lab</button>
          <button class="side-item" data-sec="xsslab">Web Security Lab</button>
          <button class="side-item" data-sec="socialeng">Social Engineering</button>

          <div class="side-group side-collapse" data-color="cyan">Reconnaissance <span class="side-cnt">13</span></div>
          <button class="side-item" data-sec="addressintel">Address Intel</button>
          <button class="side-item" data-sec="asnexplorer">ASN Explorer</button>
          <button class="side-item" data-sec="attacksurf">Exposure Mapping</button>
          <button class="side-item" data-sec="dns">DNS Toolkit</button>
          <button class="side-item" data-sec="dnsenum">DNS Enumeration</button>
          <button class="side-item" data-sec="dnsrecon">DNS Recon</button>
          <button class="side-item" data-sec="ghdb">Google Dorking</button>
          <button class="side-item" data-sec="netmap">Network Mapper</button>
          <button class="side-item" data-sec="reconplanner">Recon Planner</button>
          <button class="side-item" data-sec="securityscanner">Security Scanner</button>
          <button class="side-item" data-sec="subdomains">Subdomain Enum</button>
          <button class="side-item" data-sec="tools">Scanner Suite</button>
          <button class="side-item" data-sec="wayback">Wayback Machine</button>

          <div class="side-group side-collapse" data-color="cyan">OSINT <span class="side-cnt">12</span></div>
          <button class="side-item" data-sec="corstester">CORS Tester</button>
          <button class="side-item" data-sec="emailintel">Email Intel</button>
          <button class="side-item" data-sec="favicon">Favicon Hasher</button>
          <button class="side-item" data-sec="headeranalyzer">Header Analyzer</button>
          <button class="side-item" data-sec="httpinspector">HTTP Inspector</button>
          <button class="side-item" data-sec="httpprobe">HTTP Probe</button>
          <button class="side-item" data-sec="ipgeolocation">IP Geolocation</button>
          <button class="side-item" data-sec="iptools">IP Tools</button>
          <button class="side-item" data-sec="osint">OSINT Dashboard</button>
          <button class="side-item" data-sec="osintemail">OSINT Email Intel</button>
          <button class="side-item" data-sec="techfingerprint">Tech Fingerprint</button>
          <button class="side-item" data-sec="whoisrecon">WHOIS Recon</button>

          <div class="side-group side-collapse" data-color="purple">Forensics <span class="side-cnt">8</span></div>
          <button class="side-item" data-sec="binanalyze">Binary Analyzer</button>
          <button class="side-item" data-sec="forensicstoolkit">Forensics Toolkit</button>
          <button class="side-item" data-sec="ftimeline">Forensic Timeline</button>
          <button class="side-item" data-sec="loganalyze">Log Analyzer</button>
          <button class="side-item" data-sec="memforensics">Memory Forensics</button>
          <button class="side-item" data-sec="reveng">Reverse Engineering</button>
          <button class="side-item" data-sec="stego">Steganography</button>
          <button class="side-item" data-sec="timelineviz">Timeline Visualization</button>

          <div class="side-group side-collapse" data-color="purple">Threat Analysis <span class="side-cnt">3</span></div>
          <button class="side-item" data-sec="malclass">Threat Classifier</button>
          <button class="side-item" data-sec="phishing">Phishing Analyzer</button>
          <button class="side-item" data-sec="sandbox">Threat Analysis Lab</button>

          <div class="side-group side-collapse" data-color="green">Blue Team <span class="side-cnt">11</span></div>
          <button class="side-item" data-sec="adversary">Adversary Emulation</button>
          <button class="side-item" data-sec="breachsim">Breach Simulator</button>
          <button class="side-item" data-sec="containers">Container Security</button>
          <button class="side-item" data-sec="deception">Deception Architect</button>
          <button class="side-item" data-sec="huntlab">Threat Hunt Lab</button>
          <button class="side-item" data-sec="identitymatrix">Identity Matrix</button>
          <button class="side-item" data-sec="incidents">Incident Tracker</button>
          <button class="side-item" data-sec="mobilesec">Mobile Security</button>
          <button class="side-item" data-sec="purpleteam">Purple Team Ops</button>
          <button class="side-item" data-sec="riskcalculator">Risk Calculator</button>
          <button class="side-item" data-sec="threatmodel">Threat Modeler</button>

          <div class="side-group side-collapse" data-color="orange">Threat Intelligence <span class="side-cnt">9</span></div>
          <button class="side-item" data-sec="breachlookup">Breach Lookup</button>
          <button class="side-item" data-sec="cvesearch">CVE Search</button>
          <button class="side-item" data-sec="cvetimeline">CVE Timeline</button>
          <button class="side-item" data-sec="darknetradar">Darknet Radar</button>
          <button class="side-item" data-sec="darkwebosint">Deep Web Intel</button>
          <button class="side-item" data-sec="ipreputation">IP Reputation</button>
          <button class="side-item" data-sec="threat">Threat Feed</button>
          <button class="side-item" data-sec="threatdashboard">Threat Dashboard</button>
          <button class="side-item" data-sec="threatfeed">Threat Intel Feed</button>

          <div class="side-group side-collapse" data-color="orange">Vulnerability Mgmt <span class="side-cnt">5</span></div>
          <button class="side-item" data-sec="vulndb">Vulnerability DB</button>
          <button class="side-item" data-sec="vulnprio">Vuln Prioritizer</button>
          <button class="side-item" data-sec="vulntriage">Vuln Triage Engine</button>
          <button class="side-item" data-sec="secchecklist">Security Checklist</button>
          <button class="side-item" data-sec="supplychain">Supply Chain</button>

          <div class="side-group side-collapse" data-color="teal">Network Analysis <span class="side-cnt">9</span></div>
          <button class="side-item" data-sec="networkscanner">Network Scanner</button>
          <button class="side-item" data-sec="networktools">Network Tools</button>
          <button class="side-item" data-sec="networktraffic">Network Traffic</button>
          <button class="side-item" data-sec="packetanalyzer">Packet Analyzer</button>
          <button class="side-item" data-sec="packetinspector">Packet Inspector</button>
          <button class="side-item" data-sec="sslinspector">SSL Inspector</button>
          <button class="side-item" data-sec="subnetvisualizer">Subnet Visualizer</button>
          <button class="side-item" data-sec="trafficanalyzer">Traffic Analyzer</button>
          <button class="side-item" data-sec="websockettester">WebSocket Tester</button>

          <div class="side-group side-collapse" data-color="teal">Security Operations <span class="side-cnt">7</span></div>
          <button class="side-item" data-sec="adversaryplaybook">Adversary Playbook</button>
          <button class="side-item" data-sec="apifuzzer">API Fuzzer</button>
          <button class="side-item" data-sec="apitester">API Tester</button>
          <button class="side-item" data-sec="apiscan">API Scanner</button>
          <button class="side-item" data-sec="incidentcost">Incident Cost Calc</button>
          <button class="side-item" data-sec="incidentresponse">Incident Response</button>
          <button class="side-item" data-sec="siemdash">SIEM Dashboard</button>

          <div class="side-group side-collapse" data-color="yellow">Compliance &amp; GRC <span class="side-cnt">6</span></div>
          <button class="side-item" data-sec="compliance">Compliance Checker</button>
          <button class="side-item" data-sec="cyberbriefing">Cyber Briefing</button>
          <button class="side-item" data-sec="emailheader">Email Header Analyzer</button>
          <button class="side-item" data-sec="fedcompliance">Federal Compliance</button>
          <button class="side-item" data-sec="iocextractor">IOC Extractor</button>
          <button class="side-item" data-sec="zerotrust">Zero Trust Planner</button>

          <div class="side-group side-collapse" data-color="indigo">Crypto &amp; Encoding <span class="side-cnt">8</span></div>
          <button class="side-item" data-sec="credaudit">Credential Auditor</button>
          <button class="side-item" data-sec="cryptotools">Crypto Toolkit</button>
          <button class="side-item" data-sec="cspevaluator">CSP Evaluator</button>
          <button class="side-item" data-sec="encoding">Encoding Suite</button>
          <button class="side-item" data-sec="hashsuite">Hash Suite</button>
          <button class="side-item" data-sec="jwtanalyzer">JWT Analyzer</button>
          <button class="side-item" data-sec="regexlab">Regex Lab</button>
          <button class="side-item" data-sec="urldissect">URL Dissector</button>

          <div class="side-group side-collapse" data-color="violet">Nexus AI <span class="side-cnt">5</span></div>
          <button class="side-item" data-sec="ai">AI Chat</button>
          <button class="side-item" data-sec="coder">Nexus Agent <span class="side-badge ai">AI</span></button>
          <button class="side-item" data-sec="dataviz">Data Visualization</button>
          <button class="side-item" data-sec="engines">Security Engines</button>
          <button class="side-item" data-sec="report">Report Generator</button>

          <div class="side-group side-collapse" data-color="emerald">Training <span class="side-cnt">10</span></div>
          <button class="side-item" data-sec="cheats">Cheat Sheets</button>
          <button class="side-item" data-sec="cyberrange">Cyber Range</button>
          <button class="side-item" data-sec="learn">Academy</button>
          <button class="side-item" data-sec="refs">Reference Library</button>
          <button class="side-item" data-sec="secquiz">Skill Assessments</button>
          <button class="side-item" data-sec="securityquiz">Security Quiz</button>
          <button class="side-item" data-sec="snippets">Snippet Vault</button>
          <button class="side-item" data-sec="targets">Practice Targets</button>
          <button class="side-item" data-sec="training">Training Labs</button>
          <button class="side-item" data-sec="utils">Toolbox</button>

          <div class="side-group side-collapse" data-color="emerald">Labs &amp; VMs <span class="side-cnt">2</span></div>
          <button class="side-item" data-sec="vms">Vulnerable VMs</button>
          <button class="side-item" data-sec="vmlab">VM Lab</button>

          <div class="side-group side-collapse" data-open="1" data-color="rose">Investigations <span class="side-cnt">3</span></div>
          <button class="side-item" data-sec="investigation">Investigation Workspace</button>
          <button class="side-item" data-sec="secgraph">Security Graph</button>
          <button class="side-item" data-sec="casemgmt">Case Manager</button>

          <div class="side-group side-collapse" data-color="slate">Infrastructure <span class="side-cnt">7</span></div>
          <button class="side-item" data-sec="api">API</button>
          <button class="side-item" data-sec="docs">Docs</button>
          <button class="side-item" data-sec="education">Education</button>
          <button class="side-item" data-sec="downloads">Darknode OS</button>
          <button class="side-item" data-sec="dlguide">Download Guide</button>
          <button class="side-item" data-sec="privatecloud">Private Cloud <span class="side-badge beta">BETA</span></button>
          <button class="side-item" data-sec="setup">Local Setup</button>

          ${isOwner ? `<div class="side-group side-collapse">Admin</div><button class="side-item" data-sec="admin">Admin Console</button>` : ""}
        </nav>
        <div class="side-foot">${avatar}<div class="side-user"><div class="su-name">${esc(name)}</div><div class="su-mail muted">${esc(user.email)}</div></div></div>
      </aside>
      <main class="app-main" id="app-main" role="main"><div id="crumbs" class="crumbs" aria-label="Breadcrumb" role="navigation"></div><div id="app-content"></div>
        <footer class="app-foot">
          <div class="app-foot-grid">
            <div class="app-foot-col app-foot-brandcol">
              <div class="app-foot-brandline"><span class="app-foot-brand">Darknode</span><span class="app-foot-ver">v3.1</span></div>
              <p class="app-foot-tag">Unified cybersecurity operations platform — 192+ tools, live global intel, and AI in a single console.</p>
              <div class="app-foot-status"><span class="afs-dot"></span>All systems operational</div>
              <div class="app-foot-social">
                <a data-goto="ai" class="afs-chip">Nexus AI</a>
                <a data-foot="downloads" class="afs-chip">Get the CLI</a>
                <a data-goto="settings" class="afs-chip">API &amp; MCP</a>
              </div>
            </div>
            <div class="app-foot-col">
              <h4>Mission Control</h4>
              <a data-goto="home">Dashboard</a><a data-goto="sentineleye">Sentinel Eye</a><a data-goto="prometheus">Prometheus</a><a data-goto="crucible">Crucible</a><a data-goto="vanguard">Vanguard</a>
            </div>
            <div class="app-foot-col">
              <h4>Flagships</h4>
              <a data-goto="citadel">Citadel SOC</a><a data-goto="phantom">Phantom</a><a data-goto="oracle">Oracle</a><a data-goto="spectre">Spectre</a><a data-goto="hydra">Hydra Engine</a>
            </div>
            <div class="app-foot-col">
              <h4>Workspace</h4>
              <a data-goto="ai">Nexus AI</a><a data-goto="settings">Settings</a><a data-goto="saved">Saved Items</a><a data-foot="docs">Docs</a><a data-foot="downloads">Downloads</a>
            </div>
            <div class="app-foot-col">
              <h4>Legal</h4>
              <a data-foot="terms">Terms</a><a data-foot="privacy">Privacy</a><a data-foot="aup">Acceptable Use</a><a data-foot="license">License</a><a data-goto="contact">Contact / Feedback</a>
            </div>
          </div>
          <div class="app-foot-bar">
            <span class="app-foot-fine">Use only on systems you own or are authorized to test.</span>
            <span class="app-foot-copy">&copy; 2026 Darknode-Official · All rights reserved</span>
          </div>
        </footer>
      </main>
    </div>`;

  const main = document.getElementById("app-content");
  const labelOf = (s) => { const b = view.querySelector('.side-item[data-sec="' + s + '"]'); if (!b) return s.charAt(0).toUpperCase() + s.slice(1); const badge = b.querySelector(".side-badge"); return badge ? b.textContent.replace(badge.textContent, "").trim() : b.textContent.trim(); };
  let trail = [], curSec = "home";
  function renderCrumbs(sec) {
    const i = trail.indexOf(sec);
    if (i >= 0) trail = trail.slice(0, i + 1); else trail.push(sec);
    if (trail.length > 5) trail = trail.slice(-5);
    const cr = document.getElementById("crumbs"); if (!cr) return;
    cr.innerHTML = trail.map((s, idx) => `<button class="crumb${idx === trail.length - 1 ? " cur" : ""}" data-crumb="${esc(s)}">${esc(labelOf(s))}</button>`).join('<span class="crumb-sep">›</span>');
  }
  // URL path <-> section mapping
  const secToPath = (s) => s === "home" ? "/" : "/" + s.replace(/([A-Z])/g, "-$1").toLowerCase();
  const pathToSec = (p) => {
    if (!p || p === "/") return "home";
    const s = p.replace(/^\//, "").replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    return s || "home";
  };

  let _prevCleanup = null;
  function show(sec, more, skipPush) {
    if (_prevCleanup) { try { _prevCleanup(); } catch (_) {} _prevCleanup = null; }
    curSec = sec; renderCrumbs(sec);
    // Update browser URL
    const path = secToPath(sec);
    if (!skipPush && path !== location.pathname) {
      history.pushState({ sec }, "", path);
    }
    view.querySelectorAll(".side-item").forEach((x) => x.classList.toggle("active", x.dataset.sec === sec));
    // Auto-expand the active tool's parent group, collapse others
    const activeItem = view.querySelector('.side-item[data-sec="' + sec + '"]');
    if (activeItem) {
      let parentGroup = activeItem.previousElementSibling;
      while (parentGroup && !parentGroup.classList.contains("side-group")) parentGroup = parentGroup.previousElementSibling;
      if (parentGroup && parentGroup.dataset.open !== "1") {
        view.querySelectorAll(".side-collapse").forEach((g) => {
          if (g !== parentGroup && g.dataset.open === "1") {
            g.dataset.open = "0";
            let el = g.nextElementSibling;
            while (el && !el.classList.contains("side-group")) { el.style.display = "none"; el = el.nextElementSibling; }
          }
        });
        parentGroup.dataset.open = "1";
        let el = parentGroup.nextElementSibling;
        while (el && !el.classList.contains("side-group")) { el.style.display = ""; el = el.nextElementSibling; }
      }
      requestAnimationFrame(() => { try { activeItem.scrollIntoView({ block: "nearest" }); } catch (_) {} });
    }
    const shell = view.querySelector(".app-shell");
    if (shell) shell.classList.toggle("no-sidebar", sec === "settings" || sec === "docs");
    const prevH = main.offsetHeight;
    if (prevH > 200) main.style.minHeight = prevH + "px";
    requestAnimationFrame(() => { main.style.minHeight = ""; });
    if (sec && sec !== "home" && sec !== "settings") { try { let r = JSON.parse(localStorage.getItem("dn_recent")||"[]"); r = r.filter(s=>s!==sec); r.unshift(sec); r = r.slice(0,8); localStorage.setItem("dn_recent", JSON.stringify(r)); } catch(_){} }
    if (sec === "tools") { main.innerHTML = `<h1 class="pg-h1">Tools</h1><p class="muted pg-sub">Search the catalog and expand any tool.</p><div id="tools"></div>`; import("/js/tools.js").then(m => m.renderTools(document.getElementById("tools"))); }
    else if (sec === "utils") { import("/js/utils.js").then(m => m.renderUtils(main)); }
    else if (sec === "ai") { import("/js/webai.js?v=20260924h").then(m => m.renderAI(main)); }
    else if (sec === "payloads") { import("/js/labs.js").then(m => m.renderPayloads(main)); }
    else if (sec === "targets") { import("/js/labs.js").then(m => m.renderTargets(main)); }
    else if (sec === "ghdb") { import("/js/ghdb.js").then(m => m.renderGHDB(main)); }
    else if (sec === "exploitdb") { import("/js/exploitdb.js").then(m => m.renderExploitDB(main)); }
    else if (sec === "vms") { import("/js/vms.js").then(m => m.renderVMs(main)); }
    else if (sec === "webshell") { import("/js/webshell.js").then(m => m.renderWebshell(main)); }
    else if (sec === "vmlab") { import("/js/vmlab.js").then(m => m.renderVMLab(main)); }
    else if (sec === "privatecloud") { import("/js/privatecloud.js").then(m => m.renderPrivateCloud(main)); }
    else if (sec === "saved") { import("/js/saved.js").then(m => m.renderSaved(main, show)); }
    else if (sec === "report") { import("/js/report.js").then(m => m.renderReport(main)); }
    else if (sec === "snippets") { import("/js/labs.js").then(m => m.renderSnippets(main)); }
    else if (sec === "refs") { import("/js/labs.js").then(m => m.renderRefs(main)); }
    else if (sec === "arsenal") { show("home"); return; }
    else if (sec === "engines") { import("/js/arsenal.js").then(m => m.renderEngines(main)); }
    else if (sec === "packetcraft") { import("/js/packet-crafter.js").then(m => m.renderPacketCrafter(main)); }
    else if (sec === "binanalyze") { import("/js/binary-analyzer.js").then(m => m.renderBinaryAnalyzer(main)); }
    else if (sec === "netmap") { import("/js/network-mapper.js").then(m => m.renderNetworkMapper(main)); }
    else if (sec === "loganalyze") { import("/js/log-analyzer.js").then(m => m.renderLogAnalyzer(main)); }
    else if (sec === "credaudit") { import("/js/credential-auditor.js").then(m => m.renderCredentialAuditor(main)); }
    else if (sec === "memforensics") { import("/js/memory-forensics.js?v=20260924b").then(m => m.renderMemoryForensics(main)); }
    else if (sec === "stego") { import("/js/steganography.js").then(m => m.renderSteganography(main)); }
    else if (sec === "regexlab") { import("/js/regex-lab.js").then(m => m.renderRegexLab(main)); }
    else if (sec === "encoding") { import("/js/encoding-suite.js?v=20260924b").then(m => m.renderEncodingSuite(main)); }
    else if (sec === "threatmodel") { import("/js/threat-modeler.js?v=20260924b").then(m => m.renderThreatModeler(main)); }
    else if (sec === "osint") { import("/js/osint-dashboard.js").then(m => m.renderOSINTDashboard(main)); }
    else if (sec === "addressintel") { import("/js/address-intel.js?v=20260924b").then(m => m.renderAddressIntel(main)); }
    else if (sec === "incidents") { import("/js/incident-tracker.js").then(m => m.renderIncidentTracker(main)); }
    else if (sec === "firewall") { import("/js/firewall-builder.js").then(m => m.renderFirewallBuilder(main)); }
    else if (sec === "apitester") { import("/js/api-tester.js").then(m => m.renderAPITester(main)); }
    else if (sec === "sandbox") { import("/js/malware-sandbox.js").then(m => m.renderMalwareSandbox(main)); }
    else if (sec === "compliance") { import("/js/compliance-checker.js").then(m => m.renderComplianceChecker(main)); }
    else if (sec === "attacksim") { import("/js/attack-simulator.js").then(m => m.renderAttackSimulator(main)); }
    else if (sec === "dns") { import("/js/dns-toolkit.js").then(m => m.renderDNSToolkit(main)); }
    else if (sec === "subdomains") { import("/js/subdomain-finder.js?v=20260923d").then(m => m.renderSubdomainFinder(main)); }
    else if (sec === "mobilesec") { import("/js/mobile-security-lab.js").then(m => m.renderMobileSecurityLab(main)); }
    else if (sec === "apiscan") { import("/js/api-security-scanner.js?v=20260924b").then(m => m.renderAPISecurityScanner(main)); }
    else if (sec === "wirelesslab") { import("/js/wireless-lab.js").then(m => m.renderWirelessLab(main)); }
    else if (sec === "pentestconsole") { import("/js/pentest-console.js?v=20260924b").then(m => m.renderPentestConsole(main)); }
    else if (sec === "reveng") { import("/js/reverse-engineering.js").then(m => m.renderReverseEngineering(main)); }
    else if (sec === "darkwebosint") { import("/js/darkweb-osint.js").then(m => m.renderDarkwebOsint(main)); }
    else if (sec === "cyberrange") { import("/js/cyber-range.js").then(m => m.renderCyberRange(main)); }
    else if (sec === "prometheus") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading PROMETHEUS...</p>"; const _s=sec; import("/js/prometheus-web.js?v=20260924c").then(m => { if(curSec!==_s)return; m.renderPrometheus(main); _prevCleanup = m.cleanupPrometheus; }); }
    else if (sec === "sentineleye") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading SENTINEL EYE...</p>"; if(!document.querySelector('script[src="/js/threat-api.js"]')){var s1=document.createElement("script");s1.src="/js/threat-api.js";document.head.appendChild(s1)}if(!document.querySelector('script[src="/js/threat-map.js"]')){var s2=document.createElement("script");s2.src="/js/threat-map.js";document.head.appendChild(s2)} const _s=sec; import("/js/sentinel-eye.js?v=20260924c").then(m => { if(curSec!==_s)return; m.renderSentinelEye(main); _prevCleanup = m.cleanupSentinelEye; }); }
    else if (sec === "exploitdev") { import("/js/exploit-writer.js").then(m => m.renderExploitWriter(main)); }
    else if (sec === "secdash") { import("/js/security-dashboard.js").then(m => m.renderSecurityDashboard(main)); }
    else if (sec === "phishing") { import("/js/phishing-analyzer.js").then(m => m.renderPhishingAnalyzer(main)); }
    else if (sec === "containers") { import("/js/container-security.js").then(m => m.renderContainerSecurity(main)); }
    else if (sec === "cracklab") { import("/js/password-cracking-lab.js").then(m => m.renderPasswordCrackingLab(main)); }
    else if (sec === "hydra") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading HYDRA...</p>"; import("/js/hydra-engine.js?v=20260924b").then(m => m.renderHydra(main)); }
    else if (sec === "aegis") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading AEGIS...</p>"; import("/js/aegis-web.js?v=20260924b").then(m => m.renderAegis(main)); }
    else if (sec === "vanguard") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading VANGUARD...</p>"; import("/js/vanguard.js?v=20260924c").then(m => m.renderVanguard(main)); }
    else if (sec === "phantom") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading PHANTOM...</p>"; const _s=sec; import("/js/phantom.js?v=20260923d").then(m => { if(curSec!==_s)return; m.renderPhantom(main); _prevCleanup = m.cleanupPhantom; }); }
    else if (sec === "citadel") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading CITADEL...</p>"; const _s=sec; import("/js/citadel.js?v=20260924c").then(m => { if(curSec!==_s)return; m.renderCitadel(main); _prevCleanup = m.cleanupCitadel; }); }
    else if (sec === "oracle") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading ORACLE...</p>"; const _s=sec; import("/js/oracle.js?v=20260923d").then(m => { if(curSec!==_s)return; m.renderOracle(main); _prevCleanup = m.cleanupOracle; }); }
    else if (sec === "spectre") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading SPECTRE...</p>"; const _s=sec; import("/js/spectre.js?v=20260924c").then(m => { if(curSec!==_s)return; m.renderSpectre(main); _prevCleanup = m.cleanupSpectre; }); }
    else if (sec === "crucible") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading CRUCIBLE...</p>"; const _s=sec; import("/js/crucible.js?v=20260924b").then(m => { if(curSec!==_s)return; m.renderCrucible(main); _prevCleanup = m.cleanupCrucible; }); }
    else if (sec === "navarch") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading NAVARCH...</p>"; const _s=sec; import("/js/navarch.js?v=20260924c").then(m => { if(curSec!==_s)return; m.renderNavarch(main); _prevCleanup = m.cleanupNavarch; }); }
    else if (sec === "jwtanalyzer") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading JWT Analyzer...</p>"; import("/js/jwt-analyzer.js").then(m => m.renderJwtAnalyzer(main)); }
    else if (sec === "cspevaluator") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading CSP Evaluator...</p>"; import("/js/csp-evaluator.js?v=20260924b").then(m => m.renderCspEvaluator(main)); }
    else if (sec === "wayback") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading Wayback Recon...</p>"; import("/js/wayback-recon.js").then(m => m.renderWaybackRecon(main)); }
    else if (sec === "urldissect") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading URL Dissector...</p>"; import("/js/url-dissector.js").then(m => m.renderUrlDissector(main)); }
    else if (sec === "favicon") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading Favicon Hasher...</p>"; import("/js/favicon-hasher.js?v=20260924b").then(m => m.renderFaviconHasher(main)); }
    else if (sec === "adversary") { import("/js/adversary-ai.js").then(m => m.renderAdversaryAI(main)); }
    else if (sec === "breachsim") { import("/js/breach-simulator.js").then(m => m.renderBreachSimulator(main)); }
    else if (sec === "huntlab") { import("/js/threat-hunt-lab.js").then(m => m.renderThreatHuntLab(main)); }
    else if (sec === "attacksurf") { import("/js/attack-surface-mapper.js").then(m => m.renderAttackSurfaceMapper(main)); }
    else if (sec === "deception") { import("/js/deception-architect.js").then(m => m.renderDeceptionArchitect(main)); }
    else if (sec === "purpleteam") { import("/js/purple-team-ops.js").then(m => m.renderPurpleTeamOps(main)); }
    else if (sec === "malclass") { import("/js/malware-classifier.js").then(m => m.renderMalwareClassifier(main)); }
    else if (sec === "zerotrust") { import("/js/zero-trust-designer.js?v=20260924b").then(m => m.renderZeroTrustDesigner(main)); }
    else if (sec === "vulnprio") { import("/js/vulnerability-prioritizer.js").then(m => m.renderVulnPrioritizer(main)); }
    else if (sec === "vulntriage") { import("/js/vuln-triage.js?v=20260924b").then(m => m.renderVulnTriage(main)); }
    else if (sec === "secquiz") { import("/js/security-awareness-quiz.js?v=20260924b").then(m => m.renderSecurityQuiz(main)); }
    else if (sec === "supplychain") { import("/js/supply-chain-analyzer.js").then(m => m.renderSupplyChainAnalyzer(main)); }
    else if (sec === "cryptotools") { import("/js/crypto-tools.js").then(m => m.renderCryptoTools(main)); }
    else if (sec === "ftimeline") { import("/js/forensic-timeline.js").then(m => m.renderForensicTimeline(main)); }
    else if (sec === "socialeng") { import("/js/social-engineering-sim.js").then(m => m.renderSocialEngSim(main)); }
    else if (sec === "training") { import("/js/arsenal.js").then(m => m.renderTraining(main)); }
    else if (sec === "apikeys") { show("settings"); return; }
    else if (sec === "cheats") renderCheats(main);
    else if (sec === "threat") renderThreat(main);
    else if (sec === "ipreputation") { import("/js/ip-reputation.js").then(m => m.renderIPReputation(main)); }
    else if (sec === "cyberbriefing") { import("/js/cyber-briefing.js?v=20260924b").then(m => m.renderCyberBriefing(main)); }
    else if (sec === "incidentcost") { import("/js/incident-cost.js?v=20260924b").then(m => m.renderIncidentCost(main)); }
    else if (sec === "fedcompliance") { import("/js/fed-compliance.js").then(m => m.renderFedCompliance(main)); }
    else if (sec === "adversaryplaybook") { import("/js/adversary-playbook.js").then(m => m.renderAdversaryPlaybook(main)); }
    else if (sec === "emailheader") { import("/js/email-header.js?v=20260924b").then(m => m.renderEmailHeader(main)); }
    else if (sec === "iocextractor") { import("/js/ioc-extractor.js?v=20260924b").then(m => m.renderIOCExtractor(main)); }
    else if (sec === "reconplanner") { import("/js/recon-planner.js").then(m => m.renderReconPlanner(main)); }
    else if (sec === "packetinspector") { import("/js/packet-inspector.js?v=20260924b").then(m => m.renderPacketInspector(main)); }
    else if (sec === "siemdash") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading SIEM...</p>"; import("/js/siem-dash.js?v=20260924b").then(m => m.renderSiemDash(main)); }
    else if (sec === "apifuzzer") { import("/js/api-fuzzer.js").then(m => m.renderAPIFuzzer(main)); }
    else if (sec === "incidentresponse") { import("/js/incident-response.js").then(m => m.renderIncidentResponse(main)); }
    else if (sec === "networktraffic") { import("/js/network-traffic.js?v=20260924b").then(m => m.renderNetworkTraffic(main)); }
    else if (sec === "privesc") { import("/js/privesc-toolkit.js?v=20260924b").then(m => m.renderPrivescToolkit(main)); }
    else if (sec === "reverseshell") { import("/js/reverse-shell.js?v=20260924b").then(m => m.renderReverseShell(main)); }
    else if (sec === "xsslab") { import("/js/xss-lab.js").then(m => m.renderXSSLab(main)); }
    else if (sec === "osintemail") { import("/js/osint-email.js").then(m => m.renderOSINTEmail(main)); }
    else if (sec === "threatfeed") { import("/js/threat-feed.js?v=20260924b").then(m => m.renderThreatFeed(main)); }
    else if (sec === "secchecklist") { import("/js/sec-checklist.js?v=20260924b").then(m => m.renderSecChecklist(main)); }
    else if (sec === "investigation") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading Investigation Workspace...</p>"; const _s=sec; import("/js/investigation.js?v=20260924b").then(m => { if(curSec!==_s)return; m.renderInvestigation(main); _prevCleanup = m.cleanupInvestigation; }); }
    else if (sec === "secgraph") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading Security Graph...</p>"; import("/js/security-graph-ui.js?v=20260924b").then(m => m.renderSecurityGraphUI(main)); }
    else if (sec === "casemgmt") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading Case Manager...</p>"; import("/js/case-manager.js?v=20260924b").then(m => m.renderCaseManager(main)); }

    else if (sec === "cvetimeline") { import("/js/cve-timeline.js?v=20260924b").then(m => m.renderCveTimeline(main)); }
    else if (sec === "dataviz") { import("/js/data-viz.js").then(m => m.renderDataViz(main)); }
    else if (sec === "forensicstoolkit") { import("/js/forensics-toolkit.js").then(m => m.renderForensicsToolkit(main)); }
    else if (sec === "hashsuite") { import("/js/hash-suite.js").then(m => m.renderHashSuite(main)); }
    else if (sec === "httpinspector") { import("/js/http-inspector.js?v=20260924b").then(m => m.renderHttpInspector(main)); }
    else if (sec === "iptools") { import("/js/ip-tools.js").then(m => m.renderIPTools(main)); }
    else if (sec === "networktools") { import("/js/network-tools.js").then(m => m.renderNetworkTools(main)); }
    else if (sec === "packetanalyzer") { import("/js/packet-analyzer.js?v=20260924b").then(m => m.renderPacketAnalyzer(main)); }
    else if (sec === "passwordtools") { import("/js/password-tools.js?v=20260924b").then(m => m.renderPasswordTools(main)); }
    else if (sec === "payloadgen") { import("/js/payload-gen.js?v=20260924b").then(m => m.renderPayloadGen(main)); }
    else if (sec === "riskcalculator") { import("/js/risk-calculator.js?v=20260924b").then(m => m.renderRiskCalculator(main)); }
    else if (sec === "securityquiz") { import("/js/security-quiz.js").then(m => m.renderSecurityQuiz(main)); }
    else if (sec === "securityscanner") { import("/js/security-scanner.js?v=20260924b").then(m => m.renderSecurityScanner(main)); }
    else if (sec === "subnetvisualizer") { import("/js/subnet-visualizer.js?v=20260924b").then(m => m.renderSubnetVisualizer(main)); }
    else if (sec === "threatdashboard") { import("/js/threat-dashboard.js").then(m => m.renderThreatDashboard(main)); }
    else if (sec === "timelineviz") { import("/js/timeline-viz.js").then(m => m.renderTimelineViz(main)); }
    else if (sec === "vulndb") { import("/js/vulnerability-db.js?v=20260924b").then(m => m.renderVulnerabilityDB(main)); }
    else if (sec === "asnexplorer") { import("/js/asn-explorer.js?v=20260924b").then(m => m.renderAsnExplorer(main)); }
    else if (sec === "breachlookup") { import("/js/breach-lookup.js").then(m => m.renderBreachLookup(main)); }
    else if (sec === "corstester") { import("/js/cors-tester.js?v=20260924b").then(m => m.renderCorsTester(main)); }
    else if (sec === "cvesearch") { import("/js/cve-search.js?v=20260924b").then(m => m.renderCveSearch(main)); }
    else if (sec === "darknetradar") { import("/js/darknet-radar.js").then(m => m.renderDarknetRadar(main)); }
    else if (sec === "dnsenum") { import("/js/dns-enum.js?v=20260924b").then(m => m.renderDNSEnum(main)); }
    else if (sec === "dnsrecon") { import("/js/dns-recon.js").then(m => m.renderDNSRecon(main)); }
    else if (sec === "emailintel") { import("/js/email-intel.js").then(m => m.renderEmailIntel(main)); }
    else if (sec === "headeranalyzer") { import("/js/header-analyzer.js?v=20260924b").then(m => m.renderHeaderAnalyzer(main)); }
    else if (sec === "httpprobe") { import("/js/http-probe.js").then(m => m.renderHttpProbe(main)); }
    else if (sec === "identitymatrix") { import("/js/identity-matrix.js?v=20260924b").then(m => m.renderIdentityMatrix(main)); }
    else if (sec === "ipgeolocation") { import("/js/ip-geolocation.js").then(m => m.renderIPGeolocation(main)); }
    else if (sec === "networkscanner") { import("/js/network-scanner.js").then(m => m.renderNetworkScanner(main)); }
    else if (sec === "sslinspector") { import("/js/ssl-inspector.js?v=20260923c").then(m => m.renderSSLInspector(main)); }
    else if (sec === "techfingerprint") { import("/js/tech-fingerprint.js").then(m => m.renderTechFingerprint(main)); }
    else if (sec === "trafficanalyzer") { import("/js/traffic-analyzer.js").then(m => m.renderTrafficAnalyzer(main)); }
    else if (sec === "websockettester") { import("/js/websocket-tester.js").then(m => m.renderWebSocketTester(main)); }
    else if (sec === "whoisrecon") { import("/js/whois-recon.js?v=20260924b").then(m => m.renderWhoisRecon(main)); }
    else if (sec === "learn") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading Learn Hub...</p>"; loadLearnHub().then(m => m.renderLearnHub(main)); }
    else if (sec === "github") { show("settings"); return; }
    else if (sec === "gmail") { show("settings"); return; }
    else if (sec === "coder") { import("/js/coder.js").then(m => m.renderCliCoder(main)); }
    else if (sec === "downloads") { import("/js/getapp.js?v=20260924c").then(m => m.renderDownloads(main)); }
    else if (sec === "dlguide") { import("/js/getapp.js?v=20260924c").then(m => m.renderDownloadDocs(main)); }
    else if (sec === "api") { import("/js/api.js?v=20260924a").then(m => m.renderAPI(main, user)); }
    else if (sec === "docs") { import("/js/docs.js?v=20260924b").then(m => m.renderDocs(main)); }
    else if (sec === "setup") renderSetup(main, more);
    else if (sec === "settings") renderSettingsPage(main, user, isOwner);
    else if (sec === "admin") { import("/js/admin.js?v=20260924").then(m => m.renderAdmin(main, user)); }
    else if (sec === "contact") renderContact(main);
    else if (sec === "education") { main.innerHTML = `<div class="panel" style="max-width:800px;margin:40px auto"><div class="panel-h">About Darknode Education</div><div style="padding:18px;line-height:1.8;font-size:.9rem"><p><strong>Darknode is a cybersecurity education platform</strong> designed for students, educators, and security professionals to learn information security through hands-on practice in a safe, controlled environment.</p><p style="margin-top:16px"><strong>Our Mission:</strong> To make cybersecurity education accessible, interactive, and practical. Every tool on this platform runs locally in your browser or on your own machine -- no data ever leaves your computer.</p><p style="margin-top:16px"><strong>Who Uses Darknode:</strong></p><ul style="margin:8px 0 0 20px;line-height:2"><li>Computer science and cybersecurity students</li><li>IT professionals studying for certifications (CompTIA Security+, CISSP, CEH, OSCP)</li><li>University professors and instructors teaching security courses</li><li>Security operations center (SOC) analysts in training</li><li>Career changers learning cybersecurity fundamentals</li></ul><p style="margin-top:16px"><strong>Educational Standards:</strong> Our curriculum aligns with NIST NICE Framework, NSA CAE-CD requirements, and CompTIA Security+ objectives. All practice environments are isolated, legal, and designed for authorized educational use only.</p><p style="margin-top:16px"><strong>Responsible Use:</strong> Darknode tools are designed exclusively for educational purposes and authorized security testing. Users must comply with all applicable laws and obtain proper authorization before testing any system they do not own.</p><p style="margin-top:16px;color:var(--mut);font-size:.82rem">Darknode is a product of Darknode-Official. For questions about our educational programs, visit darknode.ai.</p></div></div>`; }
    else renderHome(main, user, isOwner, show);
    if (more === undefined) { try { localStorage.setItem("sw_last_sec", sec); } catch (_) {} }
    main.scrollTop = 0;
  }
  // Handle browser back/forward
  window.addEventListener("popstate", (e) => {
    const sec = (e.state && e.state.sec) || pathToSec(location.pathname);
    show(sec, undefined, true);
  });
  // Handle keyboard shortcut navigation (from shortcuts.js)
  document.addEventListener("dn:navigate", (e) => { if (e.detail) show(e.detail); });

  view.querySelector(".side-nav").onclick = (e) => {
    const b = e.target.closest(".side-item");
    if (b) { show(b.dataset.sec); closeSidebar(); return; }
    const g = e.target.closest(".side-collapse");
    if (g) {
      const isOpen = g.dataset.open === "1";
      if (!isOpen) {
        view.querySelectorAll(".side-collapse").forEach((other) => {
          if (other !== g && other.dataset.open === "1") {
            other.dataset.open = "0";
            let oel = other.nextElementSibling;
            while (oel && !oel.classList.contains("side-group")) {
              oel.style.display = "none";
              oel = oel.nextElementSibling;
            }
          }
        });
      }
      g.dataset.open = isOpen ? "0" : "1";
      let el = g.nextElementSibling;
      while (el && !el.classList.contains("side-group")) {
        if (isOpen) {
          el.style.display = "none";
        } else {
          el.style.display = "";
        }
        el = el.nextElementSibling;
      }
    }
  };
  // Handle data-sec clicks anywhere in the view (dashboard cards, hero buttons, etc.)
  view.addEventListener("click", (e) => {
    const sec = e.target.closest("[data-sec]");
    if (sec && !sec.closest(".side-nav")) { show(sec.dataset.sec); }
  });

  // Initialize collapsed groups (data-open not set = collapsed)
  view.querySelectorAll(".side-collapse").forEach((g) => {
    if (g.dataset.open !== "1") {
      let el = g.nextElementSibling;
      while (el && !el.classList.contains("side-group")) {
        el.style.display = "none";
        el = el.nextElementSibling;
      }
    }
  });

  // Newbie help: attach a plain-language description to every tool + group and
  // show it in one shared, styled tooltip on hover (keeps the sidebar neat).
  applySidebarHelp(view);
  // Sidebar collapse toggle — the collapsed rail shows a 2-letter token per
  // tool (items have no icons) plus the full name as a tooltip, so it reads as
  // a proper icon rail instead of empty boxes.
  const setSideAbbrs = (sb) => {
    sb.querySelectorAll(".side-item").forEach((it) => {
      if (it.dataset.abbr) return;
      const badge = it.querySelector(".side-badge");
      let t = it.textContent || "";
      if (badge) t = t.replace(badge.textContent, "");
      t = t.trim();
      const w = t.split(/\s+/).filter(Boolean);
      const ab = (w.length >= 2 ? (w[0][0] + w[1][0]) : t.slice(0, 2)) || "?";
      it.dataset.abbr = ab.toUpperCase();
      if (!it.title) it.title = t;
    });
    sb.querySelectorAll(".side-group").forEach((g) => {
      if (g.dataset.abbr) return;
      const cnt = g.querySelector(".side-cnt");
      let t = g.textContent || "";
      if (cnt) t = t.replace(cnt.textContent, "");
      g.dataset.abbr = (t.trim()[0] || "•").toUpperCase();
    });
  };
  const sideToggleBtn = view.querySelector("#sideToggle");
  if (sideToggleBtn) {
    const sb = view.querySelector("#sidebar");
    if (sb) setSideAbbrs(sb);
    const savedCollapsed = localStorage.getItem("sw_sidebar_collapsed");
    if (savedCollapsed === "1" && sb) sb.classList.add("collapsed");
    sideToggleBtn.onclick = () => {
      if (sb) {
        sb.classList.toggle("collapsed");
        localStorage.setItem("sw_sidebar_collapsed", sb.classList.contains("collapsed") ? "1" : "0");
      }
    };
  }
  // Sidebar search filter
  const sideSearch = view.querySelector("#sideSearch");
  if (sideSearch) {
    sideSearch.oninput = () => {
      const q = sideSearch.value.toLowerCase().trim();
      const nav = view.querySelector(".side-nav");
      nav.querySelectorAll(".side-item").forEach(item => {
        if (item.dataset.sec === "home") return;
        item.style.display = !q || item.textContent.toLowerCase().includes(q) ? "" : "none";
      });
      nav.querySelectorAll(".side-group").forEach(g => {
        if (!q) {
          g.style.display = "";
          let el = g.nextElementSibling;
          const open = g.dataset.open === "1";
          while (el && !el.classList.contains("side-group")) { el.style.display = open ? "" : "none"; el = el.nextElementSibling; }
          return;
        }
        let hasVisible = false; let el = g.nextElementSibling;
        while (el && !el.classList.contains("side-group")) { if (el.style.display !== "none") hasVisible = true; el = el.nextElementSibling; }
        g.style.display = hasVisible ? "" : "none";
      });
    };
  }
  // Hamburger toggle for mobile sidebar
  const hamburger = document.getElementById("hamburger");
  const sidebar = document.getElementById("sidebar");
  if (hamburger) {
    hamburger.hidden = false;
    hamburger.onclick = () => {
      const open = sidebar.classList.toggle("open");
      hamburger.classList.toggle("active", open);
      hamburger.setAttribute("aria-expanded", String(open));
    };
  }
  function closeSidebar() { if (sidebar) { sidebar.classList.remove("open"); if (hamburger) { hamburger.classList.remove("active"); hamburger.setAttribute("aria-expanded", "false"); } } }

  userSlot.innerHTML = `
    <button class="style-toggle" id="styleToggle" data-style="${currentStyle()}" title="Theme: ${currentStyle()}" aria-label="Cycle theme style"><svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="8" cy="8" r="5.5"/><path d="M8 2.5v11M2.5 8h11"/></svg></button>
    <button class="cmdk-btn" id="cmdkBtn" title="Search (Ctrl+K)"><span>Search</span><kbd>Ctrl K</kbd></button>
    <span id="cli-dot" style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#71717a;margin:0 10px;cursor:pointer;vertical-align:middle;transition:background .3s" title="CLI not connected" onclick="window.dnPrompt('Connect Darknode CLI',{desc:'Paste the auth token shown in your terminal after you run the Darknode CLI. It links this browser to your local tools and models.',placeholder:'darknode auth token'}).then(function(t){if(t&&window._bridge)window._bridge.connect(t.trim()).then(function(r){var d=document.getElementById('cli-dot');if(d){d.style.background='#22c55e';d.title='CLI connected: '+(r.hostname||'local')}showToast('Connected to '+(r.hostname||'CLI')+' — '+((r.tools||[]).length)+' tools, '+((r.ollama||[]).length)+' AI models','success')}).catch(function(e){showToast('Failed: '+e.message,'error')})})"></span>
    <div class="tb-item">
      <button class="icon-btn" id="moreBtn" title="More" aria-label="More">&#8943;</button>
      <div class="menu" id="moreMenu" hidden>
        ${MORE.map((m) => `<button class="menu-item col" data-more="${m.id}"><strong>${esc(m.name)}</strong><span class="menu-sub">${esc(m.desc)}</span></button>`).join("")}
      </div>
    </div>
    <div class="tb-item">
      <button class="profile-btn" id="profileBtn">${avatar}<span class="p-email">${esc(user.email)}</span></button>
      <div class="menu menu-wide" id="profileMenu" hidden>
        <div class="menu-prof">${avatar}<div style="min-width:0"><div class="su-name">${esc(name)}</div><div class="su-mail muted">${esc(user.email)}${isOwner ? ' <span class="owner-badge">OWNER</span>' : ""}</div></div></div>
        <div class="menu-lbl">Account</div>
        <button class="menu-item" data-nav="settings">Settings</button>
        <button class="menu-item" data-nav="saved">Saved items</button>
        <button class="menu-item" data-nav="api">API keys &amp; MCP</button>
        <div class="menu-div"></div>
        <div class="menu-lbl">Workspace</div>
        <div class="menu-grid">
          <button class="menu-tile" data-nav="ai"><strong>Nexus AI</strong><span>Chat assistant</span></button>
          <button class="menu-tile" data-nav="coder"><strong>Nexus Agent</strong><span>AI coder</span></button>
          <button class="menu-tile" data-nav="downloads"><strong>Downloads</strong><span>App &amp; CLI</span></button>
          <button class="menu-tile" data-nav="docs"><strong>Docs</strong><span>Guides &amp; API</span></button>
        </div>
        <div class="menu-div"></div>
        <div class="menu-lbl">Preferences</div>
        <button class="menu-item menu-item-kbd" data-a="palette">Command palette<kbd>Ctrl K</kbd></button>
        <button class="menu-item" data-a="style">Switch theme style</button>
        <button class="menu-item" data-a="theme">Toggle light / dark</button>
        <button class="menu-item" data-a="tour">Replay walkthrough</button>
        <div class="menu-div"></div>
        <button class="menu-item" data-nav="contact">Contact / Feedback</button>
        <button class="menu-item menu-item-danger" data-a="logout">Log out</button>
      </div>
    </div>`;
  const profileMenu = document.getElementById("profileMenu");
  const moreMenu = document.getElementById("moreMenu");
  const closeMenus = () => { if (profileMenu) profileMenu.hidden = true; if (moreMenu) moreMenu.hidden = true; };
  const profileBtn = document.getElementById("profileBtn");
  const moreBtn = document.getElementById("moreBtn");
  if (profileBtn) profileBtn.onclick = (e) => { e.stopPropagation(); const h = profileMenu.hidden; closeMenus(); profileMenu.hidden = !h; };
  if (moreBtn) moreBtn.onclick = (e) => { e.stopPropagation(); const h = moreMenu.hidden; closeMenus(); moreMenu.hidden = !h; };
  document.addEventListener("click", closeMenus);
  if (profileMenu) profileMenu.onclick = (e) => {
    const nb = e.target.closest("[data-nav]"), lb = e.target.closest("[data-a]"); if (!nb && !lb) return;
    closeMenus();
    if (nb) return show(nb.dataset.nav);
    const a = lb.dataset.a;
    if (a === "logout") signOut(auth);
    else if (a === "theme") { const cur = document.documentElement.getAttribute("data-theme") || "dark"; applyTheme(cur === "dark" ? "light" : "dark"); }
    else if (a === "style") cycleStyle();
    else if (a === "palette") openPalette();
    else if (a === "tour") startTour(tourSteps(isOwner));
    else if (a === "feedback") openFeedback(user);
  };
  if (moreMenu) moreMenu.onclick = (e) => { const b = e.target.closest("[data-more]"); if (!b) return; closeMenus(); show("setup", b.dataset.more); };
  const cmdkBtn = document.getElementById("cmdkBtn");
  if (cmdkBtn) cmdkBtn.onclick = openPalette;
  const styleToggle = document.getElementById("styleToggle");
  if (styleToggle) styleToggle.onclick = cycleStyle;

  view.querySelectorAll("[data-foot]").forEach((a) => a.addEventListener("click", () => {
    const f = a.dataset.foot;
    if (f === "downloads") return show("downloads");
    show("docs");
    if (f !== "docs") setTimeout(() => { const t = document.getElementById("doc-" + f); if (t) t.scrollIntoView({ behavior: "smooth", block: "start" }); }, 60);
  }));
  // Quick-nav links (footer, topbar strip) that jump straight to a section.
  view.querySelectorAll("[data-goto]").forEach((a) => a.addEventListener("click", () => show(a.dataset.goto)));

  // Topbar live ops strip — fills the empty center of the header with a status
  // line, a ticking UTC clock, headline threat metrics and quick launchers.
  const tbCenter = document.getElementById("topbar-center");
  if (tbCenter) {
    tbCenter.innerHTML = `
      <span class="tbx tbx-status" title="All systems operational"><span class="tbx-dot"></span>OPERATIONAL</span>
      <span class="tbx-sep tbx-amb"></span>
      <span class="tbx tbx-clock tbx-amb" id="tb-clock" title="System time (UTC)">--:--:-- UTC</span>
      <span class="tbx-sep tbx-amb"></span>
      <span class="tbx tbx-amb" title="Active threats being tracked"><b>17</b>&nbsp;threats</span>
      <span class="tbx tbx-amb" title="Advanced Persistent Threat groups monitored"><b>38</b>&nbsp;APTs</span>
      <span class="tbx tbx-defcon tbx-amb" title="Current defense readiness posture">DEFCON 3</span>
      <span class="tbx-sep"></span>
      <div class="tb-pop-wrap">
        <button class="tbx tbx-btn tb-pop-btn" data-pop="tbCreate" title="Quick create" aria-haspopup="true">+ New</button>
        <div class="tb-pop" id="tbCreate" hidden>
          <div class="tb-pop-h">Quick create</div>
          <button class="tb-pop-i" data-goto="securityscanner"><b>New scan</b><span>Run the security scanner against a target</span></button>
          <button class="tb-pop-i" data-goto="casemgmt"><b>New case</b><span>Open an investigation case file</span></button>
          <button class="tb-pop-i" data-goto="report"><b>New report</b><span>Draft a findings report</span></button>
          <button class="tb-pop-i" data-goto="payloads"><b>New payload</b><span>Build a payload in the Forge</span></button>
          <button class="tb-pop-i" data-goto="saved"><b>Quick note</b><span>Jump to your saved items</span></button>
        </div>
      </div>
      <div class="tb-pop-wrap">
        <button class="tbx tbx-btn tb-pop-btn" data-pop="tbAlerts" title="Live alerts" aria-haspopup="true">Alerts <span class="tb-badge" id="tbAlertBadge">3</span></button>
        <div class="tb-pop tb-pop-wide" id="tbAlerts" hidden>
          <div class="tb-pop-h">Live alerts <button class="tb-pop-clear" id="tbAlertClear">Mark all read</button></div>
          <div id="tbAlertList">
            <button class="tb-alert" data-goto="networktraffic"><span class="tb-alert-sev high">HIGH</span><div><b>Anomalous outbound traffic</b><span>198.51.100.23 &middot; 3 min ago</span></div></button>
            <button class="tb-alert" data-goto="vulntriage"><span class="tb-alert-sev med">MED</span><div><b>New CVE affecting a tracked stack</b><span>CVE-2026-38292 &middot; 21 min ago</span></div></button>
            <button class="tb-alert" data-goto="citadel"><span class="tb-alert-sev low">LOW</span><div><b>Failed-auth burst auto-mitigated</b><span>auth-gateway &middot; 1 hr ago</span></div></button>
          </div>
        </div>
      </div>
      <button class="tbx tbx-btn" id="tbFocus" title="Focus mode — hide the sidebar &amp; chrome" aria-pressed="false">Focus</button>
      <button class="tbx tbx-btn" id="tbDensity" title="Toggle density (comfortable / compact)">Density</button>`;
    const closeTbPops = () => tbCenter.querySelectorAll(".tb-pop").forEach((p) => (p.hidden = true));
    tbCenter.querySelectorAll(".tb-pop-btn").forEach((btn) => btn.addEventListener("click", (e) => {
      e.stopPropagation(); const pop = document.getElementById(btn.dataset.pop); if (!pop) return;
      const wasHidden = pop.hidden; closeTbPops(); pop.hidden = !wasHidden;
    }));
    try { if (window._tbPopClose) document.removeEventListener("click", window._tbPopClose); } catch (_) {}
    window._tbPopClose = closeTbPops; document.addEventListener("click", closeTbPops);
    tbCenter.querySelectorAll("[data-goto]").forEach((b) => b.addEventListener("click", () => { closeTbPops(); show(b.dataset.goto); }));
    const alertBadge = document.getElementById("tbAlertBadge");
    const alertClear = document.getElementById("tbAlertClear");
    if (alertClear) alertClear.addEventListener("click", (e) => { e.stopPropagation(); if (alertBadge) alertBadge.style.display = "none"; tbCenter.querySelectorAll("#tbAlertList .tb-alert").forEach((a) => a.classList.add("read")); });
    const focusBtn = document.getElementById("tbFocus");
    if (focusBtn) focusBtn.addEventListener("click", () => { const on = document.body.classList.toggle("focus-mode"); focusBtn.setAttribute("aria-pressed", on ? "true" : "false"); focusBtn.classList.toggle("active", on); });
    const densBtn = document.getElementById("tbDensity");
    if (densBtn) { const sync = () => densBtn.classList.toggle("active", document.documentElement.getAttribute("data-density") === "compact"); densBtn.addEventListener("click", () => { const next = document.documentElement.getAttribute("data-density") === "compact" ? "comfortable" : "compact"; applyDensity(next); sync(); try { showToast("Density: " + next, "info"); } catch (_) {} }); sync(); }
    try { if (window._tbClock) clearInterval(window._tbClock); } catch (_) {}
    const tick = () => { const el = document.getElementById("tb-clock"); if (el) el.textContent = new Date().toISOString().slice(11, 19) + " UTC"; };
    tick(); try { window._tbClock = setInterval(tick, 1000); } catch (_) {}
  }

  appShow = show;
  initSaved(user);

  import('/js/security-graph.js').then(function(sg) {
    window._securityGraphContext = function() {
      try {
        var stats = sg.getStats();
        if (stats.totalEntities === 0) return '';
        var lines = ['The platform security graph contains ' + stats.totalEntities + ' entities.'];
        var byType = stats.byType || {};
        var types = Object.entries(byType).filter(function(e){return e[1] > 0}).sort(function(a,b){return b[1]-a[1]});
        if (types.length) lines.push('By type: ' + types.map(function(e){return e[0] + '(' + e[1] + ')'}).join(', '));
        var bySev = stats.bySeverity || {};
        if (bySev.critical) lines.push('CRITICAL items: ' + bySev.critical);
        if (bySev.high) lines.push('HIGH items: ' + bySev.high);
        var recent = sg.listEntities({ limit: 5 });
        if (recent.length) {
          lines.push('Recent entities:');
          recent.forEach(function(e) { lines.push('- [' + e.type + '] ' + e.name + (e.severity ? ' (' + e.severity + ')' : '') + (e.status ? ' [' + e.status + ']' : '')); });
        }
        return lines.join('\n');
      } catch(_) { return ''; }
    };
  }).catch(function(){});

  import('/js/context-bar.js').then(function(mod) {
    mod.initContextBar('#app-main', show);
    const style = document.createElement('style');
    style.textContent = mod.getContextBarCSS();
    document.head.appendChild(style);
  }).catch(function() {});

  import('/js/bridge.js').then(function(mod) {
    window._bridge = mod.bridge;
    var dot = document.getElementById('cli-dot');
    mod.bridge.probe().then(function(ok) { if (ok && dot) { dot.style.background = '#f59e0b'; dot.title = 'CLI detected — click to connect'; } });
    mod.bridge.addEventListener('connect', function() { if (dot) { dot.style.background = '#22c55e'; dot.title = 'CLI connected: ' + mod.bridge.hostname; } });
    mod.bridge.addEventListener('disconnect', function() { if (dot) { dot.style.background = '#71717a'; dot.title = 'CLI disconnected'; } });
  }).catch(function() {});

  // ---- breadcrumb navigation ----
  document.getElementById("crumbs").onclick = (e) => { const b = e.target.closest("[data-crumb]"); if (b) show(b.dataset.crumb); };

  // ---- save the exact frame (Ctrl+S) so you resume where you left off ----
  const FRAME = "sw_frame";
  const toast = (msg, ms) => { const t = document.createElement("div"); t.className = "toast"; t.textContent = msg; document.body.appendChild(t); requestAnimationFrame(() => t.classList.add("in")); setTimeout(() => { t.classList.remove("in"); setTimeout(() => t.remove(), 300); }, ms || 2600); };
  const editableFields = () => [...main.querySelectorAll("input,textarea,select")].filter((el) => el.id && el.type !== "password" && el.type !== "file");
  const hasTyped = () => editableFields().some((el) => (el.tagName !== "SELECT") && el.value && el.value.trim());
  function saveFrame() {
    const fields = {}; editableFields().forEach((el) => { if (el.value) fields[el.id] = el.value; });
    try { localStorage.setItem(FRAME, JSON.stringify({ sec: curSec, fields, ts: Date.now() })); } catch (_) {}
    toast("Frame saved — you'll resume right here.");
  }
  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && (e.key === "s" || e.key === "S") && document.body.classList.contains("app")) { e.preventDefault(); saveFrame(); }
  });
  // gentle exit-intent hint (once per session) + native unsaved-changes guard
  let exitHinted = false;
  document.addEventListener("mouseout", (e) => { if (e.clientY <= 0 && !exitHinted && hasTyped()) { exitHinted = true; toast("Leaving? Press Ctrl+S to save this exact frame so you resume right here.", 5000); } });
  window.addEventListener("beforeunload", (e) => { if (hasTyped()) { e.preventDefault(); e.returnValue = ""; } });

  // ---- restore last frame (section + typed text), else last section ----
  let frame = null; try { frame = JSON.parse(localStorage.getItem(FRAME)); } catch (_) {}
  let lastSec; try { lastSec = localStorage.getItem("sw_last_sec"); } catch (_) {}
  const pathSec = location.pathname !== "/" ? pathToSec(location.pathname) : null;
  const HEAVY = new Set(["sentineleye","prometheus","hydra","aegis","vanguard","phantom","citadel","oracle","spectre","crucible","navarch"]);
  const startSec = pathSec || (frame && frame.sec) || lastSec || "home";
  const okSec = startSec && startSec !== "setup" && (startSec !== "admin" || isOwner) && !HEAVY.has(startSec);
  show(okSec ? startSec : "home");
  if (frame && frame.fields && frame.sec === startSec) {
    setTimeout(() => { Object.entries(frame.fields).forEach(([id, v]) => { const el = main.querySelector("#" + (window.CSS && CSS.escape ? CSS.escape(id) : id)); if (el && v != null) { el.value = v; el.dispatchEvent(new Event("input", { bubbles: true })); el.dispatchEvent(new Event("change", { bubbles: true })); } }); }, 120);
  }
  if (!tourDone()) setTimeout(() => startTour(tourSteps(isOwner)), 450);
}

// ---- command palette (Ctrl/Cmd+K) ----
// Subsequence fuzzy score: -1 if `needle` isn't a subsequence of `hay`, else a
// score rewarding contiguous runs, word-boundary hits, and early matches.
function fuzzyScore(hay, needle) {
  hay = hay.toLowerCase(); needle = needle.toLowerCase();
  if (!needle) return 0;
  let hi = 0, score = 0, streak = 0;
  for (const ch of needle) {
    const idx = hay.indexOf(ch, hi);
    if (idx < 0) return -1;
    if (idx === 0 || /[\s·.\-\/&]/.test(hay[idx - 1] || "")) score += 4;
    if (idx === hi) { streak++; score += streak; } else streak = 0;
    score += 1; hi = idx + 1;
  }
  return score + Math.max(0, 12 - hi);
}
const paletteRecents = () => { try { return JSON.parse(localStorage.getItem("sw_recent")) || []; } catch (_) { return []; } };
function pushRecent(id) { let r = paletteRecents().filter((x) => x !== id); r.unshift(id); r = r.slice(0, 6); try { localStorage.setItem("sw_recent", JSON.stringify(r)); } catch (_) {} }

function highlightMatch(text, query) {
  if (!query) return esc(text);
  const lt = text.toLowerCase(), lq = query.toLowerCase();
  let out = "", hi = 0;
  for (const ch of lq) {
    const idx = lt.indexOf(ch, hi);
    if (idx < 0) break;
    out += esc(text.slice(hi, idx)) + "<mark>" + esc(text[idx]) + "</mark>";
    hi = idx + 1;
  }
  return out + esc(text.slice(hi));
}
function openPalette() {
  if (document.getElementById("cmdk")) return;
  const sections = [["home", "Dashboard"], ["investigation", "Investigation Workspace"], ["secgraph", "Security Graph"], ["casemgmt", "Case Manager"], ["ai", "AI Chat"], ["tools", "Scanner Suite"], ["saved", "Saved"], ["utils", "Toolbox"], ["payloads", "Payload Forge"], ["exploitdb", "Exploit Database"], ["ghdb", "Google Dorking"], ["targets", "Practice Targets"], ["vms", "Vulnerable VMs"], ["threat", "Threat Feed"], ["threatfeed", "Threat Intel Feed"], ["secchecklist", "Security Checklist"], ["cheats", "Cheat Sheets"], ["snippets", "Snippet Vault"], ["refs", "Reference Library"], ["training", "Training Labs"], ["privatecloud", "Private Cloud"], ["report", "Report Generator"], ["learn", "Academy"], ["setup", "Local Setup"], ["coder", "Nexus Agent"], ["downloads", "Darknode OS"], ["dlguide", "Download Guide"], ["api", "API"], ["docs", "Docs"], ["education", "Education"], ["settings", "Settings"], ["admin", "Admin"], ["vanguard", "VANGUARD"], ["prometheus", "PROMETHEUS"], ["sentineleye", "SENTINEL EYE"], ["hydra", "HYDRA Engine"], ["aegis", "AEGIS Ops Center"], ["phantom", "PHANTOM"], ["citadel", "CITADEL"], ["oracle", "ORACLE"], ["spectre", "SPECTRE"], ["crucible", "CRUCIBLE"], ["navarch", "NAVARCH"], ["secdash", "Security Dashboard"], ["jwtanalyzer", "JWT Analyzer"], ["cspevaluator", "CSP Evaluator"], ["wayback", "Wayback Machine"], ["urldissect", "URL Dissector"], ["favicon", "Favicon Hasher"], ["cyberrange", "Cyber Range"], ["sandbox", "Threat Analysis Lab"], ["netmap", "Network Mapper"], ["exploitdev", "Security Research Lab"], ["cracklab", "Password Security Lab"], ["osint", "OSINT Dashboard"], ["darkwebosint", "Deep Web Intel"], ["cyberbriefing", "Cyber Briefing"], ["vulntriage", "Vuln Triage Engine"], ["incidentcost", "Incident Cost Calculator"], ["fedcompliance", "Federal Compliance"], ["adversaryplaybook", "Adversary Playbook"], ["emailheader", "Email Header Analyzer"], ["iocextractor", "IOC Extractor"], ["reconplanner", "Recon Planner"], ["packetinspector", "Packet Inspector"], ["siemdash", "SIEM Dashboard"], ["apifuzzer", "API Fuzzer"], ["incidentresponse", "Incident Response"], ["networktraffic", "Network Traffic"], ["privesc", "Privilege Analysis"], ["reverseshell", "Remote Access Testing"], ["xsslab", "Web Security Lab"], ["osintemail", "OSINT Email Intel"], ["cvetimeline", "CVE Timeline"], ["dataviz", "Data Visualization"], ["forensicstoolkit", "Forensics Toolkit"], ["hashsuite", "Hash Suite"], ["httpinspector", "HTTP Inspector"], ["iptools", "IP Tools"], ["networktools", "Network Tools"], ["packetanalyzer", "Packet Analyzer"], ["passwordtools", "Password Tools"], ["payloadgen", "Test Script Generator"], ["riskcalculator", "Risk Calculator"], ["securityquiz", "Security Quiz"], ["securityscanner", "Security Scanner"], ["subnetvisualizer", "Subnet Visualizer"], ["threatdashboard", "Threat Dashboard"], ["timelineviz", "Timeline Visualization"], ["vulndb", "Vulnerability Database"], ["asnexplorer", "ASN Explorer"], ["breachlookup", "Breach Lookup"], ["corstester", "CORS Tester"], ["cvesearch", "CVE Search"], ["darknetradar", "Darknet Radar"], ["dnsenum", "DNS Enumeration"], ["dnsrecon", "DNS Recon"], ["emailintel", "Email Intel"], ["headeranalyzer", "Header Analyzer"], ["httpprobe", "HTTP Probe"], ["identitymatrix", "Identity Matrix"], ["ipgeolocation", "IP Geolocation"], ["networkscanner", "Network Scanner"], ["sslinspector", "SSL Inspector"], ["techfingerprint", "Tech Fingerprint"], ["trafficanalyzer", "Traffic Analyzer"], ["websockettester", "WebSocket Tester"], ["whoisrecon", "WHOIS Recon"]];
  const actions = [
    { type: "action", id: "cycle-style", name: "Cycle theme style", desc: "Switch between Pro, Dark, Classic", action: cycleStyle },
    { type: "action", id: "toggle-dark", name: "Toggle light / dark", desc: "Switch light and dark mode", action: () => { const cur = document.documentElement.getAttribute("data-theme") || "dark"; applyTheme(cur === "dark" ? "light" : "dark"); } },
    { type: "action", id: "toggle-crt", name: "Toggle CRT effect", desc: "Turn scanline overlay on or off", action: () => applyCrt(!crtOn()) },
    { type: "action", id: "copy-url", name: "Copy current URL", desc: "Copy page link to clipboard", action: () => { navigator.clipboard.writeText(location.href).then(() => showToast("URL copied", "success")).catch(() => {}); } },
    { type: "action", id: "replay-tour", name: "Replay walkthrough", desc: "Start the guided tour again", action: () => startTour(tourSteps(isOwner)) },
  ];
  const items = [
    ...actions,
    ...sections.map(([s, n]) => ({ type: "section", id: s, name: n, desc: "Go to " + n })),
    ...CATALOG.map((t) => ({ type: "tool", id: t.id, name: t.name, desc: t.cat + " · " + t.desc })),
    ...CHEATS.map((c) => ({ type: "section", id: "cheats", name: c.name + " cheat sheet", desc: "Cheat sheet · " + c.cat })),
    ...RESOURCES.map((r) => ({ type: "link", id: r.url, name: r.name, desc: "Resource · " + r.tag })),
  ];
  const ov = document.createElement("div");
  ov.id = "cmdk"; ov.className = "cmdk";
  ov.innerHTML = `<div class="cmdk-box"><input class="cmdk-input" id="cmdk-in" placeholder="Search sections, tools, actions..." autocomplete="off" spellcheck="false"><div class="cmdk-list" id="cmdk-list"></div><div class="cmdk-foot"><span><kbd>↑</kbd><kbd>↓</kbd> navigate</span><span><kbd>↵</kbd> open</span><span><kbd>esc</kbd> close</span></div></div>`;
  document.body.appendChild(ov);
  const inp = ov.querySelector("#cmdk-in"), list = ov.querySelector("#cmdk-list");
  const BADGE = { section: "go", tool: "tool", link: "link", action: "run" };
  let sel = 0, filtered = items, recentMode = false, _query = "";
  const close = () => ov.remove();
  function render(q) {
    _query = q.trim();
    if (!_query) {
      const rec = paletteRecents().map((id) => items.find((x) => x.type === "section" && x.id === id)).filter(Boolean);
      const recIds = new Set(rec.map((x) => x.id));
      filtered = [...rec, ...items.filter((x) => !(x.type === "section" && recIds.has(x.id)))].slice(0, 80);
      recentMode = rec.length;
    } else {
      filtered = items.map((x) => ({ x, s: fuzzyScore(x.name + " " + x.desc, _query) })).filter((o) => o.s >= 0).sort((a, b) => b.s - a.s).slice(0, 60).map((o) => o.x);
      recentMode = 0;
    }
    if (sel >= filtered.length) sel = 0;
    list.innerHTML = filtered.map((x, i) => {
      const hdr = (i === 0 && recentMode) ? `<div class="cmdk-group">Recent</div>` : (i === recentMode && recentMode) ? `<div class="cmdk-group">All</div>` : "";
      const nameHtml = _query ? highlightMatch(x.name, _query) : esc(x.name);
      return `${hdr}<div class="cmdk-item${i === sel ? " sel" : ""}" data-i="${i}"><span class="cmdk-badge ${x.type}">${BADGE[x.type]}</span><span class="cmdk-name">${nameHtml}</span><span class="cmdk-desc">${esc(x.desc)}</span></div>`;
    }).join("") || `<div class="cmdk-empty">No results</div>`;
    const a = list.querySelector(".cmdk-item.sel"); if (a) a.scrollIntoView({ block: "nearest" });
  }
  function run(i) {
    const x = filtered[i]; if (!x) return; close();
    if (x.type === "action") { x.action(); return; }
    if (x.type === "link") { window.open(x.id, "_blank", "noopener"); return; }
    if (x.type === "section") { pushRecent(x.id); appShow && appShow(x.id); return; }
    appShow && appShow("tools");
    setTimeout(() => { const it = document.querySelector(`.tk-item[data-id="${x.id}"]`); if (it) { if (!it.classList.contains("open")) it.querySelector(".tk-head").click(); it.scrollIntoView({ block: "center" }); } }, 70);
  }
  inp.oninput = () => { sel = 0; render(inp.value); };
  inp.onkeydown = (e) => {
    if (e.key === "ArrowDown" || (e.ctrlKey && e.key === "j")) { e.preventDefault(); sel = Math.min(sel + 1, filtered.length - 1); render(inp.value); }
    else if (e.key === "ArrowUp" || (e.ctrlKey && e.key === "k")) { e.preventDefault(); sel = Math.max(sel - 1, 0); render(inp.value); }
    else if (e.key === "Enter") { e.preventDefault(); run(sel); }
    else if (e.key === "Escape") { close(); }
  };
  list.onclick = (e) => { const it = e.target.closest(".cmdk-item[data-i]"); if (it) run(+it.dataset.i); };
  ov.onclick = (e) => { if (e.target === ov) close(); };
  render(""); inp.focus();
}
document.addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && (e.key === "k" || e.key === "K")) {
    if (!document.body.classList.contains("app")) return;
    e.preventDefault();
    const ex = document.getElementById("cmdk"); if (ex) ex.remove(); else openPalette();
  }
});

function tourSteps(isOwner) {
  const steps = [
    { title: "Welcome to Darknode", text: "A quick tour of the console. You can skip anytime." },
    { sel: ".side-nav", title: "Navigate", text: "Move between Home, Tools, Local setup, and Settings here." },
    { sel: ".qa-grid", title: "Quick actions", text: "Jump straight into browsing tools or setting up local AI." },
    { sel: "#moreBtn", title: "The … menu", text: "Spin up the full local toolkit + SSH, or a local AI coding setup with Ollama." },
    { sel: "#profileBtn", title: "Your profile", text: "Navigation, settings, change password, and log out live here." },
  ];
  if (isOwner) steps.push({ sel: ".admin-card", title: "Owner controls", text: "Admin-only features live here — just for you." });
  steps.push({ title: "You're set", text: "That's it. Replay this anytime with the 'Replay walkthrough' button." });
  return steps;
}

// Whitelist enforcement: if the owner turned it on, only allow-listed emails may use the site.
async function accessAllowed(user) {
  if (user.email === OWNER_EMAIL) return true;
  try {
    const { getWhitelist } = await import("/js/admin.js");
    const wl = await getWhitelist();
    if (wl && wl.enforce) {
      const list = (wl.emails || []).map((e) => e.toLowerCase());
      return list.includes((user.email || "").toLowerCase());
    }
  } catch (_) { /* if we can't read, don't lock anyone out */ }
  return true;
}

// Site-wide announcement banner (published from Admin).
async function loadAnnouncement() {
  const el = document.getElementById("announcement");
  if (!el) return;
  try {
    const snap = await getDoc(doc(db, "announcements", "current"));
    const d = snap.exists() ? snap.data() : null;
    if (d && d.active && d.text) {
      el.textContent = d.text;
      el.classList.toggle("banner-info", d.type !== "warn");
      el.hidden = false;
    } else { el.hidden = true; }
  } catch (_) { el.hidden = true; }
}

// ---------- boot ----------
setPersistence(auth, browserLocalPersistence).catch(() => {});
getRedirectResult(auth).then((result) => {
  if (result && result.user) {
    try { sessionStorage.setItem("sw_fresh_signin", "1"); } catch (_) {}
  }
}).catch(() => {});
onAuthStateChanged(auth, async (user) => {
  if (window.__boot) window.__boot.set(70);
  // license verification
  const _hn = [0x64,0x61,0x72,0x6b,0x6e,0x6f,0x64,0x65,0x2e,0x61,0x69].map(c=>String.fromCharCode(c)).join("");
  if(location.hostname!==_hn&&location.hostname!=="www."+_hn&&location.hostname!=="localhost"&&location.hostname!=="127.0.0.1"){document.body.innerHTML="";return}
  let fresh = false; try { fresh = sessionStorage.getItem("sw_fresh_signin") === "1"; if (fresh) sessionStorage.removeItem("sw_fresh_signin"); } catch (_) {}
  if (!user) { showLanding(); return; }
  // Email/password users must verify — a 6-digit code when EmailJS is configured, else the Firebase link.
  const providerEmailPw = user.providerData.some((p) => p.providerId === "password");
  if (providerEmailPw) {
    if (emailConfigured()) {
      const udoc = await getDoc(doc(db, "users", user.uid)).catch(() => null);
      if (!(udoc && udoc.exists() && udoc.data().codeVerified)) { renderCodeVerify(user); return; }
    } else if (!user.emailVerified) { renderVerify(user); return; }
  }
  if (!(await accessAllowed(user))) {
    showToast("Access restricted — your email isn't on the allow-list. Contact the owner.", "error", 6000);
    await signOut(auth); return;
  }
  await ensureUserDoc(user);
  checkLoginDevice(user);

  // TOS acceptance check — must agree before using the platform
  const udoc = await getDoc(doc(db, "users", user.uid)).catch(() => null);
  const tosAccepted = udoc && udoc.exists() && udoc.data().tosAccepted;
  if (!tosAccepted) {
    view.innerHTML = `
      <div style="max-width:640px;margin:60px auto;padding:24px;font-family:var(--font-body,system-ui)">
        <h1 style="font-size:1.6rem;margin-bottom:8px">Terms of Service</h1>
        <p style="color:var(--mut,#888);margin-bottom:20px">Please read and accept before continuing.</p>
        <div style="background:var(--card,#1a1a1a);border:1px solid var(--line,#333);padding:20px;max-height:400px;overflow-y:auto;font-size:.85rem;line-height:1.7;margin-bottom:20px;border-radius:4px" id="tosBox">
          <h3>Darknode Terms of Service</h3>
          <p><strong>Last updated:</strong> September 21, 2026</p>
          <p>By using Darknode ("the Platform"), including darknode.ai, Darknode CLI, Nexus AI agent, Darknode OS, and all associated tools, you agree to these terms. If you do not agree, do not use the Platform.</p>

          <h4>1. Ethical Use Only</h4>
          <p>Darknode is built for <strong>ethical hacking, authorized penetration testing, cybersecurity education, and legitimate security research</strong>. All tools, intelligence data, exploit references, payloads, and operational platforms (including AEGIS, PROMETHEUS, HYDRA, and all CLI/VM tools) are designed to help security professionals protect systems — not attack them illegally.</p>
          <p><strong>You MUST have explicit written authorization before testing any system, network, or application you do not own.</strong> This includes but is not limited to: penetration tests, vulnerability scans, social engineering assessments, wireless audits, and red team engagements. Unauthorized access to computer systems is a criminal offense under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and equivalent laws worldwide.</p>

          <h4>2. Disclaimer of Warranties &amp; Limitation of Liability</h4>
          <p>The Platform is provided <strong>"as-is" and "as-available"</strong> without warranties of any kind, express or implied, including but not limited to merchantability, fitness for a particular purpose, non-infringement, accuracy, or availability.</p>
          <p><strong>Darknode, its creators, owners, contributors, affiliates, and partners are NOT liable for any damages, losses, legal consequences, criminal charges, civil actions, fines, penalties, or harm of any kind</strong> resulting from your use or misuse of the Platform. This includes but is not limited to:</p>
          <ul>
            <li>Unauthorized access to systems, networks, or data</li>
            <li>Data loss, corruption, theft, or exposure</li>
            <li>Criminal prosecution or legal action taken against you</li>
            <li>Damage to hardware, software, infrastructure, or third-party systems</li>
            <li>Consequences of AI-generated code, commands, exploits, or recommendations</li>
            <li>Actions taken by the Nexus AI agent, AEGIS, PROMETHEUS, or any automated tool</li>
            <li>Financial losses, business disruption, or reputational harm</li>
            <li>Use of real CVE data, exploit code, or vulnerability information provided by the platform</li>
          </ul>
          <p><strong>To the maximum extent permitted by law, Darknode's total aggregate liability for any claim is limited to the amount you paid to Darknode in the 12 months before the claim arose, or $50 USD, whichever is greater.</strong> This cap applies regardless of the legal theory (contract, tort, strict liability, or otherwise).</p>
          <p>By using Darknode, you agree to <strong>indemnify and hold harmless</strong> Darknode and its team from any claims, damages, or expenses (including reasonable legal fees) arising from your use of the platform or violation of these terms.</p>

          <h4>3. Real Security Data</h4>
          <p>Darknode provides real-world security intelligence including CVE databases, exploit references, MITRE ATT&amp;CK mappings, APT group profiles, vulnerability data, and penetration testing methodologies. This information is sourced from publicly available databases and is provided for <strong>defensive security, education, and authorized testing purposes only</strong>. Darknode does not create exploits — it references publicly known vulnerabilities to help defenders understand and mitigate threats.</p>

          <h4>4. BYOK (Bring Your Own Key)</h4>
          <p>AI features require your own API keys. Darknode does not execute AI on its hosted servers and does not proxy, store, or log your prompts or API responses. You are solely responsible for your API usage, costs, compliance with your AI provider's terms, and any actions taken by AI agents operating with your keys.</p>

          <h4>5. User Responsibility</h4>
          <p><strong>You are solely and entirely responsible for:</strong></p>
          <ul>
            <li>Obtaining proper written authorization before any security testing</li>
            <li>Complying with all applicable local, state, national, and international laws</li>
            <li>Any code, payloads, exploits, or tools you generate, modify, or execute</li>
            <li>Securing your own API keys, credentials, and sensitive data</li>
            <li>Understanding the legal implications of your actions in your jurisdiction</li>
            <li>Any damage caused to systems, networks, or data during authorized testing</li>
          </ul>

          <h4>6. Prohibited Activities</h4>
          <p>You agree NOT to use Darknode for:</p>
          <ul>
            <li>Attacking systems without explicit written authorization</li>
            <li>Creating, distributing, or deploying malware for malicious purposes</li>
            <li>Conducting denial-of-service attacks against unauthorized targets</li>
            <li>Stealing, selling, or exposing personal data or credentials</li>
            <li>Reverse-engineering, reselling, or redistributing the Platform or its source code in violation of the license</li>
            <li>Any activity that violates applicable cybercrime laws</li>
          </ul>
          <p>Violation of these terms may result in immediate account termination and reporting to appropriate authorities.</p>

          <h4>7. Intellectual Property</h4>
          <p>The Platform, its design, code, branding, documentation, and all related assets are the intellectual property of Darknode and its contributors, protected by copyright and trademark law. You may not copy, modify, distribute, or create derivative works from the Platform except as expressly permitted by the applicable open-source license.</p>
          <p><strong>Your content:</strong> You retain all rights to data, reports, scan results, and other outputs you create using the Platform. By using collaborative or cloud features, you grant Darknode a limited, non-exclusive license to process that content solely to provide the service.</p>
          <p>The Platform incorporates open-source components distributed under their respective licenses. A list is available in the project repository.</p>

          <h4>8. Educational Purpose</h4>
          <p>Darknode is fundamentally a cybersecurity <strong>education and training platform</strong>. Tools, labs, simulations, and resources exist to train the next generation of ethical hackers, penetration testers, incident responders, and security engineers. We do not endorse, encourage, or condone any illegal activity whatsoever.</p>

          <h4>9. Data &amp; Privacy</h4>
          <p>We store minimal user data in Firebase (Google Cloud):</p>
          <ul>
            <li><strong>What we collect:</strong> email address, display name, profile photo URL, login timestamps, and ToS acceptance records.</li>
            <li><strong>Legal basis:</strong> legitimate interest (providing the service) and your consent (accepting these terms).</li>
            <li><strong>Data retention:</strong> your data is retained while your account is active. After deletion, data is purged within 30 days, except where retention is required by law.</li>
            <li><strong>No selling or sharing:</strong> we do not sell, rent, or share your personal data with third parties for marketing purposes.</li>
            <li><strong>Cookies:</strong> we use only essential cookies and localStorage for session management and user preferences. We do not use tracking cookies or third-party analytics.</li>
            <li><strong>International transfers:</strong> data is processed and stored in Google Cloud data centers. By using the Platform, you consent to transfer of data to servers that may be outside your country of residence.</li>
          </ul>
          <p><strong>Your rights (GDPR, CCPA, and similar laws):</strong> depending on your jurisdiction, you may have the right to access, correct, delete, or export your personal data, restrict processing, object to processing, or withdraw consent. To exercise any of these rights, email <strong>contact@darknode.ai</strong>. We will respond within 30 days. You also have the right to lodge a complaint with your local data protection authority.</p>

          <h4>10. Account Termination</h4>
          <p><strong>By you:</strong> you may stop using the Platform and request account deletion at any time by emailing contact@darknode.ai. Upon deletion, your data will be removed in accordance with Section 10.</p>
          <p><strong>By us:</strong> we may suspend or terminate your account immediately, without prior notice, if we reasonably believe you have violated these terms. We may also discontinue the Platform or any feature at any time with reasonable notice.</p>

          <h4>11. Paid Plans &amp; Pricing</h4>
          <p>The core Platform is free. Paid plans (when available) unlock additional professional features. Prices are listed on the pricing page and may change with at least <strong>30 days' notice</strong> before your next billing cycle. Refunds are handled on a case-by-case basis. Cancellation takes effect at the end of the current billing period. You are responsible for any applicable taxes.</p>

          <h4>12. Service Availability</h4>
          <p>We aim for high availability but do not guarantee uninterrupted access. We are not liable for downtime caused by events beyond our reasonable control, including but not limited to: natural disasters, internet outages, hosting provider failures, government actions, cyberattacks, or other force majeure events. Scheduled maintenance will be announced when feasible.</p>

          <h4>13. Dispute Resolution</h4>
          <p>If a dispute arises, you agree to first attempt resolution by emailing contact@darknode.ai. If we cannot resolve it within 60 days, either party may pursue binding arbitration under the rules of a mutually agreed arbitration provider, conducted in English. <strong>You agree to resolve disputes on an individual basis and waive the right to participate in a class action.</strong> Nothing in this section prevents either party from seeking injunctive relief in court for intellectual property violations or imminent harm.</p>

          <h4>14. Governing Law</h4>
          <p>These terms are governed by and construed in accordance with the laws of the State of California, United States, without regard to conflict-of-law principles. Any legal proceedings not subject to arbitration shall be brought in the state or federal courts located in California.</p>

          <h4>15. Changes to These Terms</h4>
          <p>We may update these terms from time to time. When we make material changes, we will notify you by email or by posting a notice on the Platform at least <strong>14 days before</strong> the changes take effect. If you continue to use the Platform after the effective date, you accept the updated terms. If you disagree, you may close your account before the changes take effect.</p>

          <h4>16. General Provisions</h4>
          <ul>
            <li><strong>Entire agreement:</strong> these terms, together with any referenced policies, constitute the entire agreement between you and Darknode regarding the Platform and supersede all prior agreements.</li>
            <li><strong>Severability:</strong> if any provision of these terms is found to be unenforceable or invalid, that provision will be limited or eliminated to the minimum extent necessary, and the remaining provisions will remain in full force.</li>
            <li><strong>No waiver:</strong> failure to enforce any right or provision does not constitute a waiver of that right or provision.</li>
            <li><strong>Assignment:</strong> you may not assign these terms without our written consent. We may assign our rights and obligations without restriction.</li>
          </ul>

          <h4>Contact</h4>
          <p>Questions about these terms? Email <strong>contact@darknode.ai</strong>.</p>

          <p style="margin-top:20px"><strong>By clicking "I Agree" below, you acknowledge that you have read, understood, and agree to be bound by these terms.</strong></p>
        </div>
        <div style="display:flex;gap:12px;align-items:center">
          <button class="btn lg" id="tosAgree" style="min-width:140px">I Agree</button>
          <button class="btn lg ghost" id="tosDecline">Decline &amp; Sign Out</button>
        </div>
      </div>`;
    document.getElementById("tosAgree").onclick = async () => {
      await setDoc(doc(db, "users", user.uid), { tosAccepted: true, tosAcceptedAt: serverTimestamp() }, { merge: true });
      const enter = () => { renderApp(user); loadAnnouncement(); };
      if (fresh) playAccessGranted(user.displayName || ((user.email || "").split("@")[0]), enter);
      else enter();
    };
    document.getElementById("tosDecline").onclick = async () => {
      await signOut(auth);
    };
    return;
  }

  // Fresh sign-in (flag captured up top)? Play the gamer "Access Granted" portal,
  // then reveal the app. A session-restore page load has no flag → boots straight in.
  const enter = () => { renderApp(user); loadAnnouncement(); };
  if (fresh) playAccessGranted(user.displayName || ((user.email || "").split("@")[0]), enter);
  else enter();
});
