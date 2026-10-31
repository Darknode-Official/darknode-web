// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
(function(){var _h=location.hostname,_a=["darknode.ai","www.darknode.ai","darknode-official.github.io","sentinel-b4194.web.app","sentinel-b4194-6173e.web.app","localhost","127.0.0.1"];if(!_a.some(function(d){return _h===d})&&!/^darknode-web-[a-z0-9]+\.onrender\.com$/.test(_h))throw document.body.innerHTML="",new Error("unlicensed")}());
import { auth, db, googleProvider, githubProvider, isAdminUser, GOOGLE_CLIENT_ID } from "/js/firebase.js?v=20261021a";

// Finish an OpenRouter account-link if we've just returned from its consent page
// (?code in the URL). Runs once on load, independent of auth; stores the user's
// minted key before anything renders. The promise lets the deck re-open cleanly.
window.__orConnect = import("/js/openrouter-connect.js?v=20261028c")
  .then((m) => m.completeOpenRouterConnect()).catch(() => ({ done: false }));

// Cached super-admin flag for the current session, read from the signed ID token
// custom claim (set during the auth-state handler below). A guest/Test-Mode user
// has no token, so this stays false. Never derived from a client-visible email.
let _isAdmin = false;
// A Deck tool frame: the same-origin top window's resolved admin flag (UI only; rules enforce access).
const _parentAdmin = () => { try { return document.documentElement.hasAttribute("data-embed") && window.parent !== window && window.parent.__dnAdmin === true; } catch (_) { return false; } };

// Universal log-out. Real Firebase sessions sign out and onAuthStateChanged
// re-renders the login page. Test-Mode / app-guest sessions are fake user
// objects with NO Firebase session, so signOut() is a no-op and the auth-state
// listener never fires — we must hard-reset to the login screen ourselves.
// Going to origin "/" (dropping any ?app=1 guest deep-link) covers every case.
async function doLogout() {
  try { sessionStorage.removeItem("dn_guest"); } catch (_) {}
  const hadSession = !!(auth && auth.currentUser);
  try { await signOut(auth); } catch (_) {}
  // Guest/test (no real session) OR signOut that didn't flip auth state: reset.
  if (!hadSession || (auth && auth.currentUser)) { location.href = location.origin + "/"; }
}

import "/js/net.js?v=20261011a";
import "/js/scroll-top.js?v=20260926a";
import "/js/shortcuts.js";
import "/js/mobile-nav.js";
import { consoleHTML, directoryHTML, wireConsole, labelOf as navLabel, groupOf as navGroup, recentSecs as navRecent, favSecs as navFavs, RETIRED } from "/js/console-nav.js?v=20261029d";
// Only the tool count is needed here; the manifest carries ids/names/categories without the
// tool code (js/tools/*), which loads when the Toolbox opens.
import { TOOL_META as _MINI_TOOLS } from "/js/tools-manifest.js?v=20261006a";
const MINI_COUNT = _MINI_TOOLS.length;
import { showToast } from "/js/toast.js?v=20261027c";
// Expose the toast helper globally: inline handlers and dynamically-imported
// tool modules call window.showToast rather than importing it.
try { window.showToast = showToast; } catch (_) {}
import { collection as fbCollection, addDoc as fbAddDoc, serverTimestamp as fbServerTimestamp } from "https://www.gstatic.com/firebasejs/12.17.0/firebase-firestore.js";
import {
  onAuthStateChanged, signInWithRedirect, signInWithPopup, getRedirectResult, signOut,
  createUserWithEmailAndPassword, signInWithEmailAndPassword, signInWithCredential, GoogleAuthProvider,
  sendEmailVerification, sendPasswordResetEmail, reload
} from "https://www.gstatic.com/firebasejs/12.17.0/firebase-auth.js";
import {
  doc, getDoc, setDoc, serverTimestamp
} from "https://www.gstatic.com/firebasejs/12.17.0/firebase-firestore.js";
let MORE = [], CATALOG = [], CATEGORIES = [];
import("/js/toolkit.js").then(m => { MORE = m.MORE; CATALOG = m.CATALOG; CATEGORIES = m.CATEGORIES; });
import { startTour, tourDone } from "/js/tour.js";
// Desktop app (packaged site on the app's own origin): no marketing landing, native
// Google sign-in, title bar tinted to match. See js/core/desktop.js.
import { isDesktop, has as desktopHas, syncTitlebar } from "/js/core/desktop.js";
if (isDesktop()) syncTitlebar();
let _landing = null;
async function loadLanding() { if (!_landing) _landing = await import("/js/landing.js?v=20261029d"); return _landing; }
// No-account identities (Test Mode / app guest) get a RANDOM, per-session uid, not a
// fixed shared one. The old fixed "test-user"/"app-guest" uids put every such session
// into one shared dnk:<uid>:* key namespace, so two people could land on the same
// stored API key. A fresh random uid per session isolates them; sessionStorage keeps
// it stable across in-tab navigation and clears when the tab closes.
function _guestUid(prefix) {
  const ss = prefix + "_uid";
  try { const v = sessionStorage.getItem(ss); if (v) return v; } catch (_) {}
  const b = new Uint8Array(12); (crypto || window.crypto).getRandomValues(b);
  const uid = prefix + "-" + Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
  try { sessionStorage.setItem(ss, uid); } catch (_) {}
  return uid;
}
// The active team-workspace pointer (dn_active_ws) lives in localStorage, which every account
// on this browser shares. Remember which account set it (dn_ws_uid; guests and Test Mode count
// as one "guest" account) and fall back to the personal workspace when a different account
// signs in, so it never opens the previous account's team store. A browser with no owner
// recorded yet keeps its pointer and records the current account.
function _claimWorkspacePointer(uid) {
  if (!uid) return;
  const who = /^(test|app-guest)-/.test(uid) ? "guest" : uid;
  try {
    const prev = localStorage.getItem("dn_ws_uid");
    if (prev && prev !== who) localStorage.removeItem("dn_active_ws");
    if (prev !== who) localStorage.setItem("dn_ws_uid", who);
  } catch (_) {}
}

// Plain-language, newbie-friendly one-liners for every sidebar item + group.
// Surfaced as a hover tooltip so the sidebar stays visually neat while every
// jargony tool name explains itself. Keyed by data-sec (items) / label (groups).
const SIDE_DESC = {
  home: "Your home base — activity, stats and quick links. Start here.",
  // Mission Control
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
  exploitdb: "One search box that opens a term in external exploit and vulnerability databases.",
  exploitdev: "Workspace for security research and building proof-of-concepts.",
  packetcraft: "Hand-craft custom network packets for testing.",
  payloads: "Build test payloads (reverse/web shells) for authorized testing.",
  payloadgen: "Generate ready-made test scripts and payloads.",
  pentestconsole: "Interactive workspace for running a security assessment.",
  privesc: "Checklists to find privilege-escalation paths on Linux and Windows.",
  reverseshell: "Generate remote-access (reverse shell) one-liners in 15+ languages.",
  // Security Labs
  firewall: "Build and check firewall rules (iptables, pf, Windows Firewall).",
  wirelesslab: "Wi-Fi security testing workflows (WPA/WPA2).",
  xsslab: "Practice finding and fixing cross-site scripting (XSS) bugs.",
  socialeng: "Phishing-simulation and social-engineering templates.",
  // Reconnaissance
  addressintel: "Look up an IP or domain — location, owner and reputation.",
  asnexplorer: "See which networks (ASNs) own a range of IP addresses.",
  dns: "DNS lookup and enumeration toolkit.",
  ghdb: "Google 'dorks' — clever search queries that surface exposed data.",
  netmap: "Map a network and scan it for open ports.",
  reconplanner: "Plan your recon step-by-step with methodology templates.",
  subdomains: "Discover all of a domain's subdomains.",
  tools: "A suite of quick scanners gathered in one place.",
  wayback: "Browse old snapshots of any website (the Wayback Machine).",
  // OSINT
  corstester: "Check a site's cross-origin (CORS) rules for misconfiguration.",
  favicon: "Identify sites by their favicon hash (Shodan/Censys).",
  headeranalyzer: "Inspect a website's HTTP response headers.",
  osint: "Your OSINT hub for gathering public intelligence on a target.",
  techfingerprint: "Detect what technologies a website is built with.",
  // Forensics
  binanalyze: "Analyze a binary (PE/ELF) — strings, entropy and structure.",
  forensicstoolkit: "A collection of digital-forensics utilities.",
  ftimeline: "Build an investigation timeline from your evidence.",
  loganalyze: "Parse and search system, application and security logs.",
  memforensics: "Analyze a RAM dump — processes and hidden malware.",
  stego: "Hide or extract data inside images and files (steganography).",
  // Threat Analysis
  malclass: "Classify suspicious files and identify malware families.",
  // Blue Team
  adversary: "Describe your infrastructure and get an AI analysis of likely attack paths and the defenses that stop them.",
  deception: "Plan honeypots and honeytokens to catch intruders.",
  huntlab: "A hands-on threat-hunting workspace.",
  identitymatrix: "Map identities and access across your organization.",
  incidents: "Track and manage security incidents.",
  mobilesec: "Test the security of Android and iOS apps.",
  threatmodel: "Model threats to a system (STRIDE / DREAD).",
  // Threat Intelligence
  breachlookup: "Check whether an email or password appeared in a breach.",
  cvesearch: "Search the CVE vulnerability database.",
  cvetimeline: "Browse CVEs on an interactive timeline.",
  darknetradar: "Monitor dark-web chatter and marketplaces.",
  // Vulnerability Mgmt
  vulndb: "Searchable database of known vulnerabilities.",
  supplychain: "Assess the risk in your software supply chain.",
  // Network Analysis
  networkscanner: "Scan a network for live hosts and open ports.",
  networktools: "General-purpose networking utilities.",
  packetanalyzer: "Break captured packets down protocol-by-protocol.",
  sslinspector: "Check a site's SSL/TLS certificate and cipher suites.",
  websockettester: "Test and inspect WebSocket connections.",
  // Security Operations
  adversaryplaybook: "Prebuilt attacker playbooks to exercise your SOC.",
  apifuzzer: "Fuzz API endpoints to uncover weaknesses.",
  apitester: "Interactive API testing, like Postman.",
  incidentcost: "Estimate what a security breach would cost.",
  // Compliance & GRC
  compliance: "Check systems against CIS and other compliance benchmarks.",
  crosswalk: "Map OWASP GenAI risks to 26 security & compliance frameworks.",
  cyberbriefing: "Your daily cybersecurity news briefing.",
  emailheader: "Analyze email headers (SPF/DKIM/DMARC) to trace origin.",
  fedcompliance: "NIST, FedRAMP and FISMA compliance checklists.",
  dossier: "One-shot recon dossier: subdomains, DNS, certs, ASN and WHOIS in one exportable report.",
  payloadstudio: "Chain encoders, hashes and reverse-shell templates into one build-and-export flow.",
  sigma: "Build, validate and export Sigma detection rules with ATT&CK mapping.",
  iocenrich: "Extract, defang, classify, score and enrich indicators of compromise, then export.",
  cvsscalc: "Interactive CVSS 3.1 base-score calculator with live vector string and severity rating.",
  yarabuilder: "Build, validate and export YARA detection rules with strings, modifiers and conditions.",
  emailauth: "Analyze a domain's SPF, DMARC and DKIM records live over DNS-over-HTTPS and grade them.",
  cookieinspect: "Parse and grade Set-Cookie headers for Secure, HttpOnly, SameSite and prefix issues.",
  securitytxt: "Generate and validate an RFC 9116 security.txt disclosure file.",
  codescan: "Scan a GitHub repository or local folder for leaked secrets, risky code and vulnerable dependencies, then jump to the exact line.",
  threatforest: "Turn weaknesses found in source code into attack trees mapped to CWE, CAPEC, MITRE ATT&CK and STRIDE.",
  embedsdk: "Generate an iframe or snippet to embed any Darknode tool in another site.",
  mcpconnect: "Connect other apps and AI agents to Darknode tools via MCP, embeds and a read-only API.",
  zerotrust: "Plan a zero-trust security architecture.",
  // Crypto & Encoding
  credaudit: "Audit credentials against breach lists and password policy.",
  cryptotools: "Encrypt, decrypt and work with crypto primitives.",
  cspevaluator: "Build and validate a Content-Security-Policy (CSP).",
  encoding: "Encode and decode Base64, hex, URL and more.",
  hashsuite: "Generate and identify hashes (MD5, SHA, bcrypt…).",
  regexlab: "Build and test regular expressions.",
  urldissect: "Break a URL apart and spot suspicious pieces.",
  // Darknode AI
  ai: "Chat with the built-in AI about security, code and tooling.",
  coder: "An AI agent that can carry out multi-step tasks for you.",
  dataviz: "Turn raw data into charts and visualizations.",
  engines: "Reference list of the bundled security-analysis engine modules.",
  report: "Generate professional penetration-test reports.",
  // Training
  cheats: "Quick-reference cheat sheets.",
  cyberrange: "A hands-on virtual training range.",
  learn: "Guided lessons — Learn Hub.",
  refs: "A reference library of security material.",
  secquiz: "Assess your skills with graded quizzes.",
  snippets: "Save and reuse handy code snippets.",
  targets: "Legal, safe practice targets to hack on.",
  // Labs & VMs
  vmlab: "Manage your practice virtual machines.",
  // Investigations
  investigation: "A case workspace to collect findings and evidence.",
  secgraph: "A visual graph linking assets, indicators and incidents.",
  // Infrastructure
  api: "Your Darknode API keys and usage.",
  docs: "Documentation.",
  veil: "Hands-on onion-routing demo running real in-browser crypto.",
  strongroom: "Fund Protection — deterministic fraud screens on your ledger, plus cyber-financial fusion to catch intrusion-to-theft chains. Runs in your browser.",
  signins: "Sign-in Forensics: load your Entra ID, Google Workspace or Okta sign-in export and find password spraying, impossible travel, legacy authentication and admins signing in without MFA. Runs in your browser; the log is never uploaded.",
  accessreview: "Access Review: reconcile your HR roster against your directory export to find leavers still enabled, stale logins, admins without MFA and accounts that belong to nobody on payroll. Produces the sign-off packet auditors ask for. Runs in your browser.",
  fwaudit: "Firewall Rule Audit: paste an iptables, Cisco ASA, pfSense, FortiGate or Windows Firewall export and get shadowed rules, any-to-any permits, exposed admin ports and missing default-deny, each with the fix. Runs in your browser.",
  loghunt: "Log Threat Hunter: paste web server, SSH or Windows Security logs and surface brute force, credential stuffing, scanner and injection probes, web shells, new admin accounts and cleared logs, mapped to MITRE ATT&CK. Runs in your browser.",
  payees: "Payee Control — a vendor register with real bank-detail validation (IBAN/ABA/BIC) and bank-change control: a second approver, a recorded callback and a new-account hold stop vendor-bank-change (BEC) fraud.",
  dlp: "Data Protection Scanner — find exposed secrets (API keys, tokens, private keys, connection strings) and personal data (cards, IBANs, SSNs, emails) in text, logs, config and exports. Runs entirely in your browser and produces a redacted copy; nothing is uploaded.",
  posture: "External Posture Scorecard — enter one domain to run live HTTPS, security-header, SPF/DMARC, certificate and security.txt checks, rolled into one executive posture grade with prioritised fixes. Reads only publicly observable signals.",
  tlsfleet: "Certificate & TLS Fleet Monitor — paste a list of domains and track certificate expiry, issuer and HSTS across all of them from certificate transparency logs. Keeps a persistent watchlist and flags certificates nearing expiry.",
  phishtriage: "Phishing & URL Triage — paste a suspicious link or a full email to get a risk read-out: live redirect unfurling, domain age, lookalike/homograph and obfuscation detection, SPF/DKIM/DMARC alignment and IOC extraction. Links are fetched server-side, never in your browser.",
  leakprobe: "Secret Exposure & Backend Leak Scanner — point it at a property you own to prove whether an API key or token (e.g. your Gemini key) is reachable from the browser or kept server-side. It scans the page's scripts, module graph, source maps and config for secrets, then GET-probes your backend endpoints, their error pages and common debug routes, and returns a placement verdict: client-exposed, backend-leaked, or server-side only. It shows the exact key values it finds (your own property) and no key is ever spent to test it.",
  education: "Learning resources and courses.",
  downloads: "Get the Darknode OS and desktop app.",
  dlguide: "A step-by-step install guide.",
  privatecloud: "Private-cloud security architecture (beta).",
  setup: "Connect the local Darknode CLI to this browser.",
  admin: "Owner-only admin console.",
  caaudit: "Audit Entra, Okta and Google sign-on policies for MFA gaps, legacy auth, exclusions and admins without phishing-resistant methods.",
  privaudit: "Find standing, stale and over-broad administrator access across Entra, AWS, GCP, Okta and GitHub exports.",
  nhi: "Track service principals, access keys, certificates and API tokens: age, last use, expiry and ownership, with a rotation calendar.",
  jml: "Reconcile HR joiners, movers and leavers against your identity provider and every SaaS user list to catch accounts that outlive employment.",
  oauthgov: "Inventory third-party OAuth and enterprise apps, flag high-risk scopes, user consents and unverified publishers across Microsoft 365, Google and Slack.",
  iacscan: "Scan Terraform, CloudFormation, Kubernetes, Helm, Docker, Compose, ARM and GitHub Actions files for misconfigurations against the CIS benchmarks before they reach production.",
  cloudtrail: "Hunt AWS CloudTrail, Azure Activity, GCP Audit and Microsoft 365 audit logs for the API calls attackers make: logging disabled, keys created, policies widened, mailboxes forwarded.",
  vulnimport: "Import Nessus, Qualys, OpenVAS, Rapid7, Trivy, Grype, Snyk and Defender scans; dedupe, enrich with KEV and EPSS, prioritise and track remediation SLAs across imports.",
  fleetcomply: "Check Intune, Jamf, CrowdStrike, Defender and workstation audit exports for missing encryption, stale EDR, end-of-life operating systems, patch age and local admins.",
  k8saudit: "Audit a Kubernetes cluster dump for RBAC, pod security and network isolation gaps against the CIS Kubernetes Benchmark.",
  cloudspend: "Spot cloud bill spikes, new GPU families, new regions and dormant-account spend that signal abuse or crypto-mining.",
  breachclock: "Work out which breach notification deadlines apply to an incident and track each regulator clock to the hour.",
  riskreg: "Team risk register with Open FAIR-style Monte Carlo loss estimates, loss-exceedance curves, heatmap and treatment tracking.",
  toolbox: "Hundreds of small in-browser utilities (encoders, hashes, parsers, network math and more) in one searchable place.",
  evidence: "Control evidence calendar for SOC 2, ISO 27001, PCI DSS, CIS and NIST CSF: owners, due dates, hashed evidence, readiness and auditor packages.",
  vendorrisk: "Vendor register with live external posture checks, assurance-document expiry, inherent and residual risk, and regressions since the last check.",
  backupready: "Backup and ransomware readiness from Veeam, AWS Backup, Azure Backup and restore-test exports: coverage, RPO breaches, immutability and 3-2-1-1-0.",
  dmarcreports: "DMARC aggregate report analyzer: per-source alignment, sending-service classification, spoofing volume and a safe path to p=reject.",
  domainguard: "Domain portfolio guard: live DNS, email-auth, DNSSEC, CAA and registration-expiry checks, dangling-CNAME takeover risk and registered lookalike domains.",
  dnshunt: "DNS log threat hunter for Windows DNS, BIND, Zeek, Route 53 Resolver, Umbrella and Pi-hole logs: DGA, tunneling, beaconing and newly seen domains.",
  proxyhunt: "Web gateway and proxy log hunter for Zscaler, Squid, Palo Alto, Netskope and Umbrella: upload exfiltration, shadow SaaS, anonymizers and scripted clients.",
  vpnaudit: "Remote access audit for FortiGate, GlobalProtect, AnyConnect, OpenVPN, Cloudflare Access and ZPA logs: leavers connecting, impossible travel and brute force.",
  netexposure: "Network exposure from nmap, masscan, naabu and Nessus scans: risky exposed services, end-of-life banners, weak certificates and scan-to-scan differences.",
  licenseaudit: "Open-source license compliance from lockfiles and incoming CycloneDX or SPDX SBOMs: SPDX expressions, copyleft obligations, conflicts and NOTICE files.",
  apispec: "API security review of OpenAPI, Swagger, Postman and GraphQL definitions against the OWASP API Security Top 10 2023, with SARIF and CSV exports.",
  dataflow: "Data inventory and GDPR Article 30 processing register: data categories, systems, vendors, transfers, retention, DPIA triggers and DSAR deadlines.",
  awareness: "Security awareness and phishing-simulation analytics from KnowBe4, GoPhish, Microsoft Attack Simulation and LMS exports: click, report and repeat-clicker trends.",
  pentestreg: "Pentest and audit finding tracker for Burp, ZAP, Nuclei, PlexTrac, HackerOne and audit reports: dedupe, CVSS, SLAs, retests and exceptions.",
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
  "Darknode AI": "AI assistants, data viz and reporting.",
  "Training": "Learn and practice your skills.",
  "Labs & VMs": "Practice virtual machines.",
  "Investigations": "Case management and link analysis.",
  "Infrastructure": "Account, docs, downloads and setup.",
  "Labs": "Experimental, opt-in builds that run real cryptography in your browser.",
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
  renderCheats, homeWidgetsHTML, wireHome, COUNTS,
  CHEATS, RESOURCES,
} from "/js/cyber.js";
let _learnHub = null;
async function loadLearnHub() { if (!_learnHub) { _learnHub = await import("/js/learn-hub.js?v=20261017f"); } return _learnHub; }
import { emailConfigured, sendCode, sendLoginAlert, genCode, hashCode, deviceInfo } from "/js/notify.js?v=20261017d";
import { initSaved } from "/js/saved.js";
import("/js/shell-bridge.js").then(m => {
  window.shellIsConnected = m.shellIsConnected;
  window.shellConnect = m.shellConnect;
  window.shellStatus = m.shellStatus;
  window.shellExec = m.shellExec;
});

if (window.__boot) window.__boot.set(40);

const whenIdle = (fn, timeout = 4000) =>
  ("requestIdleCallback" in window ? requestIdleCallback(fn, { timeout }) : setTimeout(fn, 1));

// DI's dictionary is 11.8 MB (about 4 MB on the wire). It is fetched only for a signed-in
// user, only after the shell is interactive and the browser is idle, and never on data-saver
// or 2G/3G links, so a visitor on the landing page pays nothing for the Engine tab. DI still
// downloads it on demand the first time it is asked about a word.
let _diPreloaded = false;
function preloadDictionary() {
  if (_diPreloaded) return;
  _diPreloaded = true;
  const c = navigator.connection || {};
  if (c.saveData || /(^|-)[23]g$/.test(c.effectiveType || "")) return;
  whenIdle(() => import("/js/engine/lexicon.js").then((m) => m.loadLexicon()).catch(() => {}), 8000);
}

// Prewarm the shared module spine that almost every tool imports (shared.js is
// pulled in by ~25 tools; the core store + mode switcher + graph by many more).
// Warming them on idle means a tool's first open no longer pays the full
// dependency waterfall — the shared deps are already parsed and in the SW cache.
// Bare URLs (no ?v=) so singletons like security-graph.js resolve to the same
// instance the tools use; errors are swallowed; skipped on data-saver / slow links.
let _spinePrewarmed = false;
function prewarmCommon() {
  if (_spinePrewarmed) return;
  _spinePrewarmed = true;
  const c = navigator.connection || {};
  if (c.saveData || /(^|-)[23]g$/.test(c.effectiveType || "")) return;
  const spine = ["/js/shared.js", "/js/core/store.js", "/js/core/tool-modes.js", "/js/security-graph.js", "/js/target.js"];
  whenIdle(() => { spine.forEach((u) => { import(u).catch(() => {}); }); }, 6000);
}

// The support chat is the in-house Darknode Assistant (no third-party script, nothing leaves
// darknode.ai). Loaded after boot on idle so it never holds up the app; idempotent; also
// called by the Help button. It streams Q&A from the Darknode AI proxy and resolves
// "open / go to X" requests locally through dnNavigate.
let _chatLoaded = false;
function loadSupportChat() {
  if (_chatLoaded) return;
  // Embedded tool frames (/<sec>?embed=1 inside the Deck or the desktop app) are a full app
  // load that shares the parent tab, which already hosts the assistant. Loading it again in
  // every tool iframe just spawns a stray launcher inside each frame and re-runs the chat
  // bootstrap N times (the duplicated "[darknode-agent] ready" log). The parent tab owns it.
  try { if (document.documentElement.hasAttribute("data-embed")) return; } catch (_) {}
  _chatLoaded = true;
  const s = document.createElement("script");
  s.src = "/js/darknode-chat.js?v=20261025d"; s.async = false;
  document.body.appendChild(s);
}
window.__loadSupportChat = loadSupportChat;
// Help button: open the chat if it is ready, else load it now and open once the bridge
// has registered openHelp (gives up quietly after 15 s if the CDN is blocked).
window.__openHelp = function () {
  const open = () => window.darknode && window.darknode.openHelp && (window.darknode.openHelp(), true);
  if (open()) return;
  loadSupportChat();
  const t0 = Date.now();
  const tick = () => { if (!open() && Date.now() - t0 < 15000) setTimeout(tick, 200); };
  setTimeout(tick, 200);
};

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
// Firebase Auth refreshes its persisted user in the background; when the browser
// closes IndexedDB for a hidden/frozen tab, that write rejects unhandled with
// "Database is closing/hidden". Auth reopens the database on its next use, so
// the error is harmless noise: silence it rather than log it.
const _benignIdb = /Database is closing|Database is closed|database connection is closing|InvalidStateError.*IDB/i;
window.addEventListener("unhandledrejection", (ev) => {
  const r = ev.reason || {};
  if (_benignIdb.test(String(r.message || r)) && /indexed_?db|PersistenceUserManager|firebase/i.test(String(r.stack || "") + String(r.message || ""))) { ev.preventDefault(); return; }
  _logError({ message: r.message || String(r), source: "unhandledrejection", stack: r.stack?.slice(0, 2000) || "", url: location.href, ua: navigator.userAgent, clientTs: Date.now() });
});

const userSlot = document.getElementById("user-slot");
const view = document.getElementById("view");
let appShow = null;   // set by renderApp so the command palette can navigate
const _bootStart = performance.now();
// Work that should follow the shell, never precede it: the support chat for everyone and
// the DI dictionary for signed-in users. Runs once, on idle, after the boot fade.
let _afterBootDone = false;
function afterBoot() {
  if (_afterBootDone) return;
  _afterBootDone = true;
  whenIdle(loadSupportChat, 6000);
  if (auth.currentUser) { preloadDictionary(); prewarmCommon(); }
}
function dismissBoot() {
  if (window.__boot) window.__boot.set(100);
  const b = document.getElementById("bootscreen"); if (!b) { afterBoot(); return; }
  const elapsed = performance.now() - _bootStart;
  const isPro = document.documentElement.getAttribute("data-boot") === "pro";
  // First visit keeps the full brand animation; a returning visitor gets the shell as
  // soon as it is ready (a short floor so the fade never cuts a frame).
  let returning = false;
  try { returning = localStorage.getItem("sw_booted") === "1"; localStorage.setItem("sw_booted", "1"); } catch (_) {}
  const floor = returning ? 250 : (isPro ? 1200 : 2200);
  const delay = Math.max(0, floor - elapsed);
  setTimeout(() => {
    const inner = b.querySelector(".boot-inner"); if (inner) inner.classList.add("exit");
    setTimeout(() => { b.style.opacity = "0"; }, 150);
    setTimeout(() => { b.remove(); afterBoot(); }, 650);
  }, delay);
}
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// Shared CSS dialog (replaces native prompt/confirm/alert). Exposed on window
// so any tool module can use it. Resolves field values (array), true/false for
// confirm, or null on cancel.
function dnModal({ title, desc, fields = [], submitText = "Confirm", cancelText = "Cancel", danger = false } = {}) {
  return new Promise((resolve) => {
    const prevFocus = document.activeElement;
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
    const close = (r) => { ov.classList.remove("open"); document.removeEventListener("keydown", onKey); setTimeout(() => ov.remove(), 150); if (prevFocus && typeof prevFocus.focus === "function" && document.contains(prevFocus)) { try { prevFocus.focus(); } catch (_) {} } resolve(r); };
    ov.querySelector("[data-ok]").onclick = () => close(fields.length ? vals() : true);
    ov.querySelector("[data-cancel]").onclick = () => close(fields.length ? null : false);
    ov.addEventListener("mousedown", (e) => { if (e.target === ov) close(fields.length ? null : false); });
    // Only the topmost modal reacts to keys, so a stacked dialog's Escape/Enter never
    // dismisses the one beneath it. Tab is trapped inside the dialog (it is aria-modal).
    const onKey = (e) => {
      const all = document.querySelectorAll(".dn-modal-ov");
      if (all.length && all[all.length - 1] !== ov) return;
      if (e.key === "Escape") { close(fields.length ? null : false); return; }
      if (e.key === "Tab") {
        const f = [...ov.querySelectorAll("button, input, textarea, select")].filter((el) => !el.disabled && el.offsetParent !== null);
        if (!f.length) return;
        const first = f[0], last = f[f.length - 1];
        if (!ov.contains(document.activeElement)) { e.preventDefault(); first.focus(); }
        else if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
        return;
      }
      if (e.key === "Enter" && (e.metaKey || e.ctrlKey || !fields.some((f) => f.type === "textarea"))) { e.preventDefault(); close(fields.length ? vals() : true); }
    };
    document.addEventListener("keydown", onKey);
    const first = ov.querySelector("[data-f]") || ov.querySelector("[data-ok]"); if (first) { first.focus(); try { first.setSelectionRange(first.value.length, first.value.length); } catch (_) {} }
  });
}
try {
  window.dnModal = dnModal;
  window.dnConfirm = (title, desc, opts = {}) => dnModal({ title, desc, submitText: opts.submitText || "Confirm", cancelText: opts.cancelText || "Cancel", danger: opts.danger }).then((r) => r === true);
  window.dnPrompt = (title, opts = {}) => dnModal({ title, desc: opts.desc, fields: [{ value: opts.value || "", placeholder: opts.placeholder || "", inputType: opts.inputType || "text", type: opts.textarea ? "textarea" : "text" }], submitText: opts.submitText || "OK" }).then((r) => (r ? r[0] : null));
  // Programmatic navigation entry point — lets the support agent (and any
  // host script) drive the app. `appShow` is the in-app router once signed in;
  // otherwise we scroll the landing or open the auth flow. Returns true on a
  // handled navigation.
  window.dnNavigate = function (target, opts = {}) {
    try {
      const t = String(target || "").trim().replace(/^\/+/, "").replace(/^#/, "");
      if (!t) return false;
      const more = opts.more || opts.tab || "";
      const inApp = document.body.classList.contains("app") && typeof appShow === "function";
      if (inApp) { appShow(t, more); return true; }
      // Logged-out / landing
      if (["signup", "get-started", "getstarted", "start", "register"].includes(t.toLowerCase())) { renderAuth("signup"); return true; }
      if (["signin", "login", "log-in"].includes(t.toLowerCase())) { renderAuth("signin"); return true; }
      const el = document.getElementById(t);
      if (el) { el.scrollIntoView({ behavior: "smooth", block: "start" }); return true; }
      window.location.href = "/" + t;
      return true;
    } catch (_) { return false; }
  };
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
  try { window.__dnCurrentUser = null; } catch (_) {}
  dismissBoot();
  document.body.classList.remove("app");
  document.body.classList.add("landing");
  // The landing page has no <main> of its own, so #view is the main landmark here; the
  // console renders its own <main class="app-main"> and takes the role off #view.
  view.setAttribute("role", "main");
  const skip = document.querySelector(".skip-link"); if (skip) skip.href = "#view";
  // Tear down the console's live ops strip so it can't overlap the landing nav.
  try {
    const tc = document.getElementById("topbar-center");
    if (tc) tc.innerHTML = "";
    if (window._tbClock) { clearInterval(window._tbClock); window._tbClock = null; }
    if (window._tbPopClose) { document.removeEventListener("click", window._tbPopClose); window._tbPopClose = null; }
    // wireConsole() relocates the console nav (.con-bar: Services / Dashboard / Darknode AI /
    // Docs / Settings) into the persistent #topbar. On return to the signed-out landing page it
    // must be torn down, or that app nav strands on the header for a user who is not signed in.
    // consoleHTML() rebuilds it fresh on the next renderApp(), so removing the stale one is safe.
    document.querySelectorAll("#topbar .con-bar").forEach((b) => b.remove());
  } catch (_) {}
  userSlot.innerHTML = `
    <div class="nav-dd" data-dd="products">
      <button class="nav-dd-btn">Products <svg width="10" height="6" viewBox="0 0 10 6"><path d="M1 1l4 4 4-4" stroke="currentColor" stroke-width="1.5" fill="none" stroke-linecap="round"/></svg></button>
      <div class="nav-dd-menu">
        <a class="nav-dd-item" href="/get-started" data-nav="auth"><span class="nav-dd-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="3" width="18" height="18" rx="3"/><path d="M7 8h10M7 12h6M7 16h8"/></svg></span><span><strong>Web App</strong><span class="nav-dd-desc">Tools and labs in your browser</span></span></a>
        <a class="nav-dd-item" href="/quelvra/"><span class="nav-dd-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M4 12h6M7 9v6M14 9h6M14 15h6"/><rect x="2" y="3" width="20" height="18" rx="3"/></svg></span><span><strong>Quelvra Math</strong><span class="nav-dd-desc">Verified math engine, works offline</span></span></a>
        <a class="nav-dd-item" href="https://github.com/Darknode-Official/darknode-cli" target="_blank" rel="noopener"><span class="nav-dd-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg></span><span><strong>CLI</strong><span class="nav-dd-desc">Install from GitHub</span></span></a><!-- NPM_SUSPENDED: restore "Install via npm" when the npm account is back -->
        <a class="nav-dd-item" href="https://github.com/Darknode-Official/darknode-os" target="_blank" rel="noopener"><span class="nav-dd-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M2 8h20"/></svg></span><span><strong>Linux VM</strong><span class="nav-dd-desc">Pre-built Darknode OS</span></span></a>
      </div>
    </div>
    <div class="nav-dd" data-dd="features">
      <button class="nav-dd-btn">Features <svg width="10" height="6" viewBox="0 0 10 6"><path d="M1 1l4 4 4-4" stroke="currentColor" stroke-width="1.5" fill="none" stroke-linecap="round"/></svg></button>
      <div class="nav-dd-menu">
        <a class="nav-dd-item" href="/features" data-nav="section" data-section="features"><span class="nav-dd-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5M2 12l10 5 10-5"/></svg></span><span><strong>Overview</strong><span class="nav-dd-desc">Everything you need to learn security</span></span></a>
        <a class="nav-dd-item" href="/arsenal" data-nav="auth"><span class="nav-dd-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z"/></svg></span><span><strong>Tools</strong><span class="nav-dd-desc">140+ tools plus 780 quick utilities</span></span></a>
        <a class="nav-dd-item" href="/ai" data-nav="auth"><span class="nav-dd-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83"/></svg></span><span><strong>Darknode AI</strong><span class="nav-dd-desc">AI-powered security agent</span></span></a>
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

// ---------- Google Identity Services: in-page FedCM / One Tap bubble ----------
// Shows the native "Sign in to darknode.ai with google.com" chooser inside the page
// (not a separate accounts.google.com window). The credential it returns is a Google ID
// token, exchanged for a Firebase session via signInWithCredential — the same path the
// desktop app already uses. If the bubble can't be shown, the caller falls back to the popup.
let _gisLoad = null;
function loadGis() {
  if (_gisLoad) return _gisLoad;
  _gisLoad = new Promise((resolve, reject) => {
    try { if (window.google && window.google.accounts && window.google.accounts.id) return resolve(); } catch (_) {}
    const s = document.createElement("script");
    s.src = "https://accounts.google.com/gsi/client";
    s.async = true; s.defer = true;
    s.onload = () => resolve();
    s.onerror = () => reject(new Error("gis-unavailable"));
    document.head.appendChild(s);
  });
  return _gisLoad;
}
let _gisInit = false;
async function initGis() {
  await loadGis();
  if (_gisInit) return;
  google.accounts.id.initialize({
    client_id: GOOGLE_CLIENT_ID,
    use_fedcm_for_prompt: true,
    auto_select: false,
    cancel_on_tap_outside: true,
    callback: async (resp) => {
      if (!resp || !resp.credential) return;
      const el = document.getElementById("err");
      try {
        try { sessionStorage.setItem("sw_fresh_signin", "1"); } catch (_) {}
        await signInWithCredential(auth, GoogleAuthProvider.credential(resp.credential));
      } catch (e) {
        try { sessionStorage.removeItem("sw_fresh_signin"); } catch (_) {}
        if (el) el.textContent = errText(e);
      }
    },
  });
  _gisInit = true;
}
// Show the bubble. onUnavailable() runs only when GIS can't display it (FedCM opted out,
// cooldown, library blocked), so the caller can fall back to the popup. Never throws.
async function googleOneTap(onUnavailable) {
  try {
    await initGis();
    google.accounts.id.prompt((notif) => {
      try {
        const gone = notif && ((notif.isNotDisplayed && notif.isNotDisplayed()) || (notif.isSkippedMoment && notif.isSkippedMoment()));
        if (gone && typeof onUnavailable === "function") onUnavailable();
      } catch (_) { /* under FedCM the moment methods are gone and the browser owns the UI */ }
    });
  } catch (_) { if (typeof onUnavailable === "function") onUnavailable(); }
}

function renderAuth(mode = "signin") {
  document.body.classList.remove("landing", "app");
  userSlot.innerHTML = "";
  const isSignup = mode === "signup";
  view.innerHTML = `
    <div class="auth-page">
      <section class="card auth-card">
        <a class="auth-back" id="authBack">&larr; Back</a>
        <div class="auth-logo"><img src="/logo-dark.svg?v=20261007b" alt=""></div>
        <h1>${isSignup ? "Create your account" : "Welcome back"}</h1>
        <p class="auth-subtitle">${isSignup ? "Create your Darknode account." : "Sign in to your Darknode account."}</p>
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
        <div class="auth-test"><a id="betaAsk">Request a tool for our Beta Lab</a></div>
        <div id="betaAskPanel" hidden style="margin-top:14px;text-align:left"></div>
      </section>
      <div class="auth-footer">darknode.ai &mdash; cybersecurity platform</div>
    </div>`;

  const err = (m) => { document.getElementById("err").textContent = m; };
  document.getElementById("testMode").onclick = () => {
    const tuid = _guestUid("test"); try { window.__dnUid = tuid; } catch (_) {} _claimWorkspacePointer(tuid); // keys saved this session stay per session (user-keys.js)
    const fakeUser = { uid: tuid, email: "test@darknode.ai", displayName: "Test User", providerData: [{ providerId: "test" }], metadata: { creationTime: new Date().toISOString() }, refreshToken: "", getIdToken: () => Promise.resolve("") };
    renderApp(fakeUser);
  };
  document.getElementById("google").onclick = async () => {
    err("");
    // Sign in with a popup so the user stays on darknode.ai (Google's chooser
    // opens as a window on top of the page) instead of being redirected away.
    // If the popup is blocked or unsupported, fall back to the redirect flow.
    try { sessionStorage.setItem("sw_fresh_signin", "1"); } catch (_) {}
    // Desktop app: Google refuses OAuth inside embedded browsers, so the app runs it in
    // the system browser and hands back only the Google ID token.
    if (desktopHas("auth.google")) {
      const note = document.getElementById("err"); note.className = "auth-ok"; note.textContent = "Continue in your browser to sign in with Google...";
      try {
        const r = await window.darknode.auth.google();
        if (!r || !r.ok) throw new Error((r && r.error) || "Google sign-in did not complete.");
        await signInWithCredential(auth, GoogleAuthProvider.credential(r.idToken));
        note.className = "auth-err"; err("");
      } catch (e) { try { sessionStorage.removeItem("sw_fresh_signin"); } catch (_) {} note.className = "auth-err"; err(errText(e)); }
      return;
    }
    // Browser: show the native in-page FedCM / One Tap bubble first (stays on darknode.ai,
    // no separate window). Fall back to the popup/redirect only if the bubble can't be shown.
    const popupSignIn = async () => {
      try {
        await signInWithPopup(auth, googleProvider);
      } catch (e) {
        const code = (e && e.code) || "";
        const popupIssue = /popup-blocked|popup-closed-by-user|cancelled-popup-request|operation-not-supported-in-this-environment|web-storage-unsupported/.test(code);
        if (popupIssue) {
          if (code === "auth/popup-closed-by-user" || code === "auth/cancelled-popup-request") {
            try { sessionStorage.removeItem("sw_fresh_signin"); } catch (_) {}
            return; // user dismissed the chooser — do nothing
          }
          try { await signInWithRedirect(auth, googleProvider); return; } catch (e2) { e = e2; }
        }
        try { sessionStorage.removeItem("sw_fresh_signin"); } catch (_) {}
        err(errText(e));
      }
    };
    googleOneTap(popupSignIn);
  };
  document.getElementById("github").onclick = async () => {
    err("");
    // The desktop app cannot follow a top-level redirect off its origin; use the popup.
    try { try { sessionStorage.setItem("sw_fresh_signin", "1"); } catch (_) {} if (isDesktop()) await signInWithPopup(auth, githubProvider); else await signInWithRedirect(auth, githubProvider); }
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
  if (isDesktop()) { const b = document.getElementById("authBack"); if (b) b.remove(); } else on("authBack", showLanding);
  on("betaAsk", async () => {
    const panel = document.getElementById("betaAskPanel");
    if (!panel) return;
    if (!panel.hidden) { panel.hidden = true; return; }
    panel.hidden = false;
    try { const m = await import("/js/beta-lab.js?v=20261029c"); m.mountRequestForm(panel, { user: null }); }
    catch (_) { panel.textContent = "Beta Lab is unavailable right now."; }
  });
  on("toSignup", () => renderAuth("signup"));
  on("toSignin", () => renderAuth("signin"));
  on("forgot", async () => {
    const email = document.getElementById("email").value.trim();
    if (!email) return err("Enter your email above first, then click Forgot password.");
    try { await sendPasswordResetEmail(auth, email, RESET_ACS); err(""); document.getElementById("err").className = "auth-ok"; document.getElementById("err").textContent = "Password reset email sent — check your inbox."; }
    catch (e) { err(errText(e)); }
  });
  // Auto-show the Google One Tap / FedCM bubble on the sign-in screen (browser only).
  // No popup fallback here — the explicit "Continue with Google" button handles that.
  if (!desktopHas("auth.google")) { try { googleOneTap(() => {}); } catch (_) {} }
}

function renderVerify(user) {
  dismissBoot();
  document.body.classList.remove("landing", "app");
  userSlot.innerHTML = `<button class="btn ghost" id="signout">Sign out</button>`;
  document.getElementById("signout").onclick = () => doLogout();
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
  document.getElementById("signout").onclick = () => doLogout();
  view.innerHTML = `
    <section class="card auth-card">
      <div class="auth-logo"><img src="/logo-dark.svg?v=20261007b" alt=""></div>
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
// Refreshed to match the modernized UI: a refined royal-blue lead (the Deck/core
// accent) instead of the old neon cyan, with a cohesive indigo/sky/emerald set.
const ACCENTS = ["#2563eb", "#0ea5e9", "#6467f2", "#10b981", "#f59e0b", "#f43f5e"];
function applyAccent(c) {
  document.documentElement.style.setProperty("--acc", c);
  // The pro/dark themes redefine --acc on `body.app` (aws.css), which shadows any
  // value set on <html> for the whole console subtree; set it inline on <body>
  // too so the user's chosen accent actually wins everywhere.
  if (document.body) document.body.style.setProperty("--acc", c);
  try { localStorage.setItem("sw_accent", c); } catch (_) {}
}
(function () { let a = null; try { a = localStorage.getItem("sw_accent"); } catch (_) {} if (a) applyAccent(a); })();
function applyTheme(m) { document.documentElement.setAttribute("data-theme", m); try { localStorage.setItem("sw_theme", m); } catch (_) {} }
const STYLES = ["pro", "dark", "classic"];
// "pro" is the default light theme; "dark" and "classic" are the alternatives.
function currentStyle() {
  return document.documentElement.getAttribute("data-style") || "pro";
}
function setStyle(name) {
  const root = document.documentElement;
  root.setAttribute("data-style", name);
  root.removeAttribute("data-skin"); // retired the Command Center skin
  try { localStorage.setItem("sw_style", name); } catch (_) {}
}
// The top-bar button is a plain light/dark switch: it never changes the layout,
// only the colour scheme. The full four-way style picker lives in Settings.
function cycleStyle() {
  const next = currentStyle() === "dark" ? "pro" : "dark";
  setStyle(next);
  const btn = document.getElementById("styleToggle");
  if (btn) { const lbl = next === "dark" ? "Switch to light" : "Switch to dark"; btn.title = lbl; btn.setAttribute("aria-label", lbl); btn.dataset.style = next; }
}
(function () { let embed = false; try { embed = new URLSearchParams(location.search).get("embed") === "1"; } catch (_) {} if (embed) { document.documentElement.setAttribute("data-theme", "light"); return; } /* embedded tools follow the light deck; set the attribute only, never persist into shared localStorage */ let t = "dark"; try { t = localStorage.getItem("sw_theme") || "dark"; } catch (_) {} applyTheme(t); })();
function crtOn() { try { return localStorage.getItem("sw_crt") === "1"; } catch (_) { return false; } }
function applyCrt(on) { document.documentElement.classList.toggle("crt", on); try { localStorage.setItem("sw_crt", on ? "1" : "0"); } catch (_) {} }
applyCrt(crtOn());
// Reading modes (normal / stupid / confusing) — rewrites UI wording in place.
// Loaded lazily; the module is a singleton (keeps a MutationObserver) so it is
// never cache-busted with ?v= (the service-worker cache version ships updates).
(function () { import("/js/reading-modes.js?v=20261010d").then((m) => { try { window.dnReading = m; m.initReadingModes(); } catch (_) {} }).catch(() => {}); })();
// Troll mode (opt-in): self-registers window.dnTroll and re-applies itself if left on.
(function () { import("/js/troll.js").then(() => {}).catch(() => {}); })();
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
  // per account, as activityKey() in security-graph.js (localStorage is shared by every account on the browser)
  const u = window.__dnUid || null;
  const KEY = "dn_recent_activity__" + (!u ? "nouser" : /^(test|app-guest)-/.test(u) ? "guest" : "u_" + u);
  // Older builds seeded three placeholder entries here; never show those as real activity.
  const SEED = new Set(["Scanned 10.10.14.7", "Queried CVE-2024-1234", "Generated report"]);
  let items = [];
  try { items = JSON.parse(localStorage.getItem(KEY)) || []; } catch (_) {}
  if (!Array.isArray(items)) items = [];
  const real = items.filter((i) => i && i.text && !SEED.has(i.text));
  if (real.length !== items.length) { try { localStorage.setItem(KEY, JSON.stringify(real)); } catch (_) {} }
  return real.slice(0, 6);
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
              <input class="tk-f" type="email" id="cfEmail" placeholder="Email" required style="width:100%">
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
            <div><span class="muted">GitHub</span><br><a href="https://github.com/Darknode-Official" target="_blank" rel="noopener" style="color:var(--acc)">github.com/Darknode-Official</a></div>
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
        body: JSON.stringify({ access_key: "f64b2617-cee3-4a87-b94c-fb667baab7cc", name, email, subject, message, from_name: "Darknode Contact Form" }) // darknode-ignore: Web3Forms access keys are public by design; they only submit this form
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
  const recentItems = _dashRecentActivity();
  const sStats = _dashSessionStats();
  const catCounts = CATEGORIES.map((c) => ({ c, n: CATALOG.filter((t) => t.cat === c).length })).sort((a, b) => b.n - a.n);
  const maxCat = catCounts.length ? catCounts[0].n : 1;
  const flagships = [["PHANTOM", "phantom"], ["CITADEL", "citadel"], ["ORACLE", "oracle"], ["SPECTRE", "spectre"], ["CRUCIBLE", "crucible"], ["NAVARCH", "navarch"], ["AEGIS", "aegis"], ["VANGUARD", "vanguard"], ["HYDRA", "hydra"], ["Investigation", "investigation"]];

  const timeAgo = (ts) => {
    const diff = Date.now() - ts;
    if (diff < 60000) return "just now";
    if (diff < 3600000) return Math.floor(diff / 60000) + "m ago";
    if (diff < 86400000) return Math.floor(diff / 3600000) + "h ago";
    return Math.floor(diff / 86400000) + "d ago";
  };

  const recentSecs = navRecent().slice(0, 8);
  const favSecs = navFavs().slice(0, 8);
  const svcRow = (sec) => `<button class="awh-link" data-sec="${esc(sec)}"><span class="awh-link-t">${esc(navLabel(sec))}</span><span class="awh-link-g">${esc(navGroup(sec))}</span></button>`;
  main.innerHTML = `
    <div class="awh-head">
      <div><h1 class="pg-h1">Console Home</h1><p class="awh-sub">${name ? "Signed in as " + esc(name) + ". " : ""}Offensive security, reconnaissance, OSINT, forensics, malware analysis, blue-team and threat intelligence in one console — with live threat intel, Darknode AI and hands-on training labs.</p></div>
      <div class="awh-actions"><button class="btn ghost" data-sec="docs">Documentation</button><button class="btn" data-sec="ai">Ask Darknode AI</button></div>
    </div>
    <div class="awh-grid">
      <section class="panel awh-w awh-span2">
        <div class="awh-wh"><h2>Recently visited</h2><button class="awh-more" data-open-services>View all services</button></div>
        <div class="awh-links">${recentSecs.length ? recentSecs.map(svcRow).join("") : `<p class="awh-empty">No recently visited services. Open one from the Services menu or the navigation on the left and it will show up here.</p>`}</div>
      </section>
      <section class="panel awh-w">
        <div class="awh-wh"><h2>Welcome to Darknode</h2></div>
        <div class="awh-list">
          <button class="awh-item" data-sec="engine"><b>Deterministic Intelligence (DI)</b><span>The deterministic counterpart to AI: answers and generates code with no AI, on your device. Try it in a chat.</span></button>
          <button class="awh-item" data-sec="learndo"><b>Learn &amp; Do</b><span>69 hands-on activities in 12 collections. Pick one and check it off.</span></button>
          <button class="awh-item" data-sec="learn"><b>Getting started</b><span>Learn the basics with curated guides and references.</span></button>
          <button class="awh-item" data-sec="targets"><b>Practice targets</b><span>Legal, intentionally vulnerable labs and ranges to practise on.</span></button>
          <button class="awh-item" data-sec="setup" data-more="aicoding"><b>Run AI locally</b><span>Set up Ollama so the AI runs on your own machine.</span></button>
          <button class="awh-item" data-sec="docs"><b>Documentation</b><span>How every part of the console works.</span></button>
        </div>
      </section>
      <section class="panel awh-w">
        <div class="awh-wh"><h2>Favorites</h2><button class="awh-more" data-open-services>Manage</button></div>
        <div class="awh-links">${favSecs.length ? favSecs.map(svcRow).join("") : `<p class="awh-empty">Nothing pinned yet. Open Services and select the star next to a service.</p>`}</div>
      </section>
      <section class="panel awh-w">
        <div class="awh-wh"><h2>Platform at a glance</h2></div>
        <dl class="awh-kv">
          <div><dt>Security platforms</dt><dd>${CATALOG.length}</dd></div>
          <div><dt>In-browser utilities</dt><dd>${MINI_COUNT}</dd></div>
          <div><dt>Categories</dt><dd>${CATEGORIES.length}</dd></div>
          <div><dt>Cheat sheets</dt><dd>${COUNTS.cheats}</dd></div>
          <div><dt>Learning resources</dt><dd>${COUNTS.resources}</dd></div>
        </dl>
      </section>
      <section class="panel awh-w">
        <div class="awh-wh"><h2>Your usage</h2><span class="awh-note">This browser</span></div>
        <dl class="awh-kv">
          <div><dt>Sessions</dt><dd>${sStats.sessions}</dd></div>
          <div><dt>AI conversations</dt><dd>${sStats.aiConvos}</dd></div>
          <div><dt>Tools used</dt><dd>${sStats.toolsUsed}</dd></div>
        </dl>
        <div class="awh-wh awh-wh-sub"><h3>Recent activity</h3></div>
        <div class="awh-activity">${recentItems.length ? recentItems.map((item) => `<div class="awh-act"><span>${esc(item.text)}</span><span class="awh-note">${timeAgo(item.ts)}</span></div>`).join("") : `<p class="awh-empty">No activity yet. Actions you take in investigations and the security graph appear here.</p>`}</div>
      </section>
      <section class="panel awh-w awh-span2">
        <div class="awh-wh"><h2>Catalog coverage</h2><span class="awh-note">${CATALOG.length} platforms in ${CATEGORIES.length} categories</span></div>
        <div class="dg-bars">
          ${catCounts.slice(0, 10).map(({ c, n }) => `<button class="dg-bar-row" data-sec="tools"><span class="dg-bar-l">${esc(c)}</span><span class="dg-bar-track"><span class="dg-bar-fill" style="width:${Math.max(6, Math.round((n / maxCat) * 100))}%"></span></span><span class="dg-bar-n">${n}</span></button>`).join("")}
        </div>
      </section>
      <section class="panel awh-w">
        <div class="awh-wh"><h2>Build with Darknode</h2></div>
        <div class="awh-list">
          <button class="awh-item" data-sec="settings" data-more="darknode"><b>REST API</b><span>One key for every tool and the agent over HTTP.</span></button>
          <button class="awh-item" data-sec="settings" data-more="mcp"><b>MCP server</b><span>Expose tools to Claude, Cursor and other clients.</span></button>
          <button class="awh-item" data-sec="settings" data-more="nexus"><b>Nexus CLI</b><span>Pair your terminal coding agent.</span></button>
          <button class="awh-item" data-sec="settings" data-more="apikeys"><b>AI provider keys</b><span>Bring your own Claude, GPT or Gemini key.</span></button>
        </div>
      </section>
      <section class="panel awh-w awh-span2">
        <div class="awh-wh"><h2>Flagship platforms</h2></div>
        <div class="awh-links">${flagships.map(([nm, sec]) => `<button class="awh-link" data-sec="${sec}"><span class="awh-link-t">${esc(nm)}</span><span class="awh-link-g">${esc(navGroup(sec))}</span></button>`).join("")}</div>
      </section>
      <section class="panel awh-w">
        <div class="awh-wh"><h2>What's new</h2><button class="awh-more" data-sec="docs">View all</button></div>
        <div class="cl-items">
          <div class="cl-item"><span class="cl-tag new">NEW</span><span class="cl-text">PHANTOM &mdash; network traffic analysis, PCAP parsing, protocol dissection</span><span class="cl-date muted">Sep 2026</span></div>
          <div class="cl-item"><span class="cl-tag new">NEW</span><span class="cl-text">CITADEL &mdash; SOC ops center: log correlation, detection rules, alert triage</span><span class="cl-date muted">Sep 2026</span></div>
          <div class="cl-item"><span class="cl-tag new">NEW</span><span class="cl-text">ORACLE &mdash; threat intel platform: IOC management &amp; campaign tracking</span><span class="cl-date muted">Sep 2026</span></div>
          <div class="cl-item"><span class="cl-tag new">NEW</span><span class="cl-text">Quelvra &mdash; offline math engine that verifies every answer</span><span class="cl-date muted">Sep 2026</span></div>
          <div class="cl-item"><span class="cl-tag imp">IMPROVED</span><span class="cl-text">Console layout &mdash; header search, side navigation, location breadcrumbs</span><span class="cl-date muted">Sep 2026</span></div>
        </div>
      </section>
    </div>
    ${isOwner ? `<div class="admin-card"><strong>Owner controls</strong><p class="muted">You're the owner &mdash; admin features live under Admin in the sidebar.</p></div>` : ""}
    ${homeWidgetsHTML()}`;
  // Card and widget clicks ([data-sec], [data-open-services]) are handled once by the
  // delegated listener on #view in renderApp; a per-render listener here would stack up
  // on the persistent #app-content and navigate twice.
  wireHome(main, show);

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

function renderSettingsPage(main, user, isOwner, initialTab) {
  const providers = user.providerData.map((p) => p.providerId.replace(".com", "")).join(", ") || "password";
  const created = user.metadata?.creationTime ? new Date(user.metadata.creationTime).toLocaleDateString() : "—";
  const row = (k, v) => `<div class="set-row"><span class="muted">${k}</span><span>${v}</span></div>`;
  // Test Mode / guest: a local-only session with no real account behind it. It has
  // no Darknode API key, no MCP credential and no Nexus CLI pairing (those bind to
  // a real signed-in uid), so we hide those panels rather than show a key that
  // authenticates nothing. Detected by the test provider or the fixed test email.
  const isGuest = !!(user && (((user.providerData || []).some((p) => p && p.providerId === "test")) || user.email === "test@darknode.ai"));
  let SET_TABS = [["account", "Account"], ["appearance", "Appearance"], ["security", "Security"], ["apikeys", "API Keys"], ["darknode", "Darknode API"], ["mcp", "MCP Server"], ["nexus", "Nexus CLI"], ["data", "Data &amp; privacy"], ["about", "About"]];
  if (isGuest) SET_TABS = SET_TABS.filter(([k]) => !["darknode", "mcp", "nexus"].includes(k));
  const startTab = SET_TABS.some(([k]) => k === initialTab) ? initialTab : "account";
  // Local Darknode API key — client-side generated token so tools, the CLI and
  // an MCP client can authenticate to this workspace. Stored only in this browser.
  // Per-account key (see user-keys.js): stored under the signed-in uid so two
  // users on one browser never share a key. No shared constant fallback — if
  // storage is unavailable we mint a fresh in-memory key, never a fixed one.
  // --- Nexus CLI pairing: a one-time, short-lived code that the exchange endpoint
  // swaps for the user's revocable Darknode API key. The Firebase refresh token is
  // never shown or handed out. Crockford-ish alphabet (no I/O/0/1) for clean typing.
  const PAIR_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const _genPairCode = () => { const b = new Uint8Array(16); (crypto || window.crypto).getRandomValues(b); let s = ""; for (const x of b) s += PAIR_ALPHABET[x & 31]; return s; };
  const _groupPairCode = (s) => s.replace(/(.{4})(?=.)/g, "$1-");
  const _getOrMintUserApiKey = async (uid) => {
    const ref = doc(db, "users", uid); let apiKey = "";
    try { const snap = await getDoc(ref); if (snap.exists()) apiKey = (snap.data() || {}).apiKey || ""; } catch (_) {}
    if (!apiKey) {
      const hex = Array.from((crypto || window.crypto).getRandomValues(new Uint8Array(16))).map((b) => b.toString(16).padStart(2, "0")).join("");
      apiKey = "sk-darknode-" + hex;
      try { await setDoc(ref, { apiKey }, { merge: true }); } catch (_) {}
    }
    return apiKey;
  };
  const _makePairingCode = async () => {
    if (!user || !user.uid) throw new Error("not signed in");
    const apiKey = await _getOrMintUserApiKey(user.uid);
    const code = _genPairCode();
    await setDoc(doc(db, "pairings", code), {
      uid: user.uid,
      email: user.email || "",
      name: user.displayName || user.email || "",
      apiKey,
      createdAt: serverTimestamp(),
      expiresAt: Date.now() + 5 * 60 * 1000,
    });
    return code;
  };
  const curLogo = (() => { try { return localStorage.getItem("sw_logo") || "nested-accent"; } catch (_) { return "nested-accent"; } })();
  const panels = {
    account: `<h2 class="set-panel-h">Account</h2>
      ${row("Name", esc(user.displayName || "—"))}
      ${row("Email", esc(user.email) + (isOwner ? ' <span class="owner-badge">OWNER</span>' : ""))}
      ${row("Signed in via", esc(providers))}
      ${row("Member since", esc(created))}
      ${row("User ID", '<span class="mono">' + esc(user.uid) + "</span>")}
      ${isGuest ? '<p class="muted" style="font-size:.78rem;margin-top:14px">This is a local <b>Test Mode</b> session &mdash; nothing is saved to an account. There is no Darknode API key, MCP credential or Nexus CLI pairing in Test Mode (those bind to a real sign-in). Create an account to unlock them.</p>' : ""}`,
    appearance: `<h2 class="set-panel-h">Appearance</h2>
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
      <p class="muted" style="font-size:.72rem;margin-top:4px">Compact tightens padding across the app. Icon rail starts the sidebar collapsed. Reduced turns off transitions and animations.</p>
      ${isOwner ? `<h3 class="set-sub-h">Deck (beta)</h3>
      <div class="set-row"><span class="muted">Cool tool UI</span>
        <span class="seg" id="sw-coolui"><button data-coolui="1">On</button><button data-coolui="0">Off</button></span></div>
      <p class="muted" style="font-size:.72rem;margin-top:4px">A more visual restyle of the tools inside the Deck — same colour scheme, with depth, rounded controls and a little motion. Open Deck tools reload to apply.</p>` : ""}
      <h3 class="set-sub-h">Reading mode</h3>
      <div class="set-row"><span class="muted">Wording</span>
        <span class="seg" id="sw-read"><button data-read="normal">Normal</button><button data-read="stupid">Stupid</button><button data-read="confusing">Confusing</button></span></div>
      <p class="muted" style="font-size:.72rem;margin-top:4px">Rewrites the interface wording live. <b>Stupid</b> uses plain, everyday words. <b>Confusing</b> uses dense technical jargon. <b>Normal</b> leaves every label exactly as written. Code, inputs and the terminal are never changed.</p>
      <h3 class="set-sub-h">Fun</h3>
      <div class="set-row" data-troll-safe><span class="muted">Troll mode</span>
        <span class="seg" id="sw-troll" data-troll-safe><button data-troll="off">Off</button><button data-troll="on">On</button></span></div>
      <p class="muted" style="font-size:.72rem;margin-top:4px">Makes the whole app deliberately infuriating — everything tilts, wobbles, goes Comic Sans and flinches away from your cursor. This switch and a pinned button always turn it back off.</p>`,
    security: `<h2 class="set-panel-h">Security</h2>
      <div class="set-btns" style="margin-top:8px">
        ${isGuest ? "" : '<button class="btn ghost" id="set-pw">Change password</button>'}
        <button class="btn ghost" id="set-tour">Replay walkthrough</button>
        <button class="btn danger" id="set-out">${isGuest ? "Exit Test Mode" : "Log out"}</button>
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
      <p class="muted" style="font-size:.84rem;margin-bottom:14px">Workspace API keys are issued by the server and shown once; only a hash is stored. Create one in the Deck under <b>API &amp; Ingest</b> to push findings in from CI (SARIF, CycloneDX, scanner exports) or to let an AI send its findings to your Deck.</p>`,
    mcp: `<h2 class="set-panel-h">MCP Server</h2>
      <p class="muted" style="font-size:.84rem;margin-bottom:14px">Let Claude Code, Claude Desktop, Codex, Cursor, Gemini CLI or any other MCP client run the Deck's analysis tools (Infrastructure as Code, Kubernetes, firewall configs, sign-ins, cloud audit logs and more). The server runs on your computer with the Deck's own engines, so the files your AI gives it stay local, and it offers the tools your plan includes.</p>
      <h3 class="set-sub-h">Claude Code</h3>
      <pre class="set-code"><button class="set-code-copy" data-code="dn-mcp">copy</button><code id="dn-mcp">git clone https://github.com/Darknode-Official/darknode-cli ~/darknode-cli
claude mcp add darknode -- node ~/darknode-cli/darknode.js mcp</code></pre>
      <p class="muted" style="font-size:.75rem;margin:2px 0 0">Setup for other AI clients, and keys for sending findings back to the Deck: Deck &gt; API &amp; Ingest &gt; Connect an AI. Sign in once with <span class="mono">node darknode.js nexus</span>, then <span class="mono">/login</span> with the code from the Nexus CLI tab.</p>`,
    nexus: `<h2 class="set-panel-h">Nexus CLI</h2>
      <p class="muted">Sign in to the Nexus terminal agent. Generate a one-time code below, then in Nexus run <span class="mono">/login</span> and paste it.</p>
      <div class="set-row"><span class="muted">Login code</span>
        <span class="nexus-code-row">
          <input id="nexus-code" class="mono" type="text" readonly value="" placeholder="Click Generate code" autocomplete="off" spellcheck="false">
          <button class="btn" id="nexus-gen" type="button">Generate code</button>
          <button class="btn ghost" id="nexus-copy" type="button">Copy</button>
        </span></div>
      <p class="muted" id="nexus-code-note" style="font-size:.75rem">The code is <b>one-time use</b> and expires in 5 minutes. It links the CLI to your account with a revocable API key &mdash; it is <b>not</b> your password and cannot change your account.</p>`,
    data: `<h2 class="set-panel-h">Data &amp; privacy</h2>
      <p class="muted" style="font-size:.84rem;margin-bottom:16px">Everything Darknode keeps for you lives in <b>this browser</b> &mdash; your settings, your saved API keys and your workspace preferences. Nothing here leaves your device unless you add a cloud key yourself. You control all of it from here.</p>
      <div style="display:flex;flex-direction:column;gap:2px;max-width:660px">
        <div class="set-row" style="align-items:center;gap:16px">
          <span style="display:flex;flex-direction:column;gap:3px"><b>Export my data</b><span class="muted" style="font-size:.76rem">Download a JSON copy of your preferences and which services have a key set. Secret values are redacted.</span></span>
          <button class="btn ghost" id="data-export" type="button" style="flex:none">Export JSON</button>
        </div>
        <div class="set-row" style="align-items:center;gap:16px">
          <span style="display:flex;flex-direction:column;gap:3px"><b>Clear local data</b><span class="muted" style="font-size:.76rem">Wipe every Darknode setting and saved key from this browser and sign out of this device.</span></span>
          <button class="btn ghost" id="data-clear" type="button" style="flex:none">Clear data</button>
        </div>
        ${isGuest ? "" : `<div class="set-row" style="align-items:center;gap:16px">
          <span style="display:flex;flex-direction:column;gap:3px"><b>Delete my account</b><span class="muted" style="font-size:.76rem">Request permanent deletion of your Darknode account and its records. We confirm by email.</span></span>
          <button class="btn danger" id="data-delete" type="button" style="flex:none">Request deletion</button>
        </div>`}
      </div>
      <p class="muted" style="font-size:.72rem;margin-top:14px">Questions about your data? Email <a href="mailto:contact@darknode.ai" style="color:var(--acc)">contact@darknode.ai</a>.</p>`,
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
      <nav class="set-nav">${SET_TABS.map(([k, l]) => `<button class="set-tab${k === startTab ? " active" : ""}" data-stab="${k}">${l}</button>`).join("")}</nav>
      <div class="set-panel" id="set-panel">${panels[startTab] || panels.account}</div>
    </div>`;
  const backBtn = main.querySelector("#set-back");
  if (backBtn) backBtn.onclick = () => appShow && appShow("home");
  let curTab = startTab;
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
    const coolSeg = main.querySelector("#sw-coolui");
    if (coolSeg) {
      // Writing dn_cool_ui fires a storage event in the parent Deck window, which
      // reloads its open tool frames with (or without) the cool skin. No console effect.
      let cur = "0"; try { cur = localStorage.getItem("dn_cool_ui") === "1" ? "1" : "0"; } catch (_) {}
      coolSeg.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.coolui === cur));
      coolSeg.onclick = (e) => {
        const b = e.target.closest("button[data-coolui]"); if (!b) return;
        try { localStorage.setItem("dn_cool_ui", b.dataset.coolui); } catch (_) {}
        coolSeg.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b));
        try { showToast("Cool tool UI " + (b.dataset.coolui === "1" ? "on" : "off") + " — open Deck tools will reload", "success"); } catch (_) {}
      };
    }
    const sidewSeg = main.querySelector("#sw-sidew");
    if (sidewSeg) {
      // Same preference the side navigation's own open/close buttons keep (console-nav.js
      // sw_awsside): "rail" is the collapsed column, and the change applies at once.
      let cur = "expanded"; try { cur = localStorage.getItem("sw_awsside") === "0" ? "rail" : "expanded"; } catch (_) {}
      sidewSeg.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.sidew === cur));
      sidewSeg.onclick = (e) => { const b = e.target.closest("button[data-sidew]"); if (!b) return; document.dispatchEvent(new CustomEvent("aws-side:set", { detail: { open: b.dataset.sidew !== "rail" } })); sidewSeg.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b)); };
    }
    // Reading mode (normal / stupid / confusing) — applies live across the app.
    const readSeg = main.querySelector("#sw-read");
    if (readSeg) {
      let cur = "normal"; try { cur = localStorage.getItem("dn_read_mode") || "normal"; } catch (_) {}
      readSeg.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.read === cur));
      readSeg.onclick = (e) => {
        const b = e.target.closest("button[data-read]"); if (!b) return;
        try { if (window.dnReading) window.dnReading.setReadMode(b.dataset.read); else localStorage.setItem("dn_read_mode", b.dataset.read); } catch (_) {}
        readSeg.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b));
      };
    }
    // Troll mode (opt-in chaos) — delegated to js/troll.js (window.dnTroll).
    const trollSeg = main.querySelector("#sw-troll");
    if (trollSeg) {
      const cur = (window.dnTroll && window.dnTroll.isOn && window.dnTroll.isOn()) ? "on" : "off";
      trollSeg.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.troll === cur));
      trollSeg.onclick = (e) => { const b = e.target.closest("button[data-troll]"); if (!b) return; try { if (window.dnTroll) window.dnTroll.set(b.dataset.troll === "on"); } catch (_) {} trollSeg.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b)); };
    }
    // Data & privacy controls
    const dataExport = main.querySelector("#data-export");
    if (dataExport) dataExport.onclick = () => {
      const out = { exportedAt: new Date().toISOString(), account: { uid: user.uid, email: user.email || "", name: user.displayName || "" }, preferences: {}, apiKeysPresent: {} };
      try { for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); if (!/^(sw_|dn_)/.test(k)) continue; let v = localStorage.getItem(k); if (/key|token|secret|api|pair/i.test(k)) v = v ? "[redacted]" : ""; out.preferences[k] = v; } } catch (_) {}
      try { const keys = window.dnKeys ? window.dnKeys.getJSON("dn_api_keys") : {}; Object.keys(keys || {}).forEach((svc) => { out.apiKeysPresent[svc] = !!keys[svc]; }); } catch (_) {}
      const blob = new Blob([JSON.stringify(out, null, 2)], { type: "application/json" });
      const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "darknode-data.json";
      document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
    };
    const dataClear = main.querySelector("#data-clear");
    if (dataClear) dataClear.onclick = async () => {
      const ok = window.dnConfirm ? await window.dnConfirm("Clear all local data?", "This wipes every Darknode setting and saved key from this browser and signs you out of this device. It cannot be undone.", { submitText: "Clear everything", danger: true }) : true;
      if (!ok) return;
      try { const rm = []; for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); if (/^(sw_|dn_)/.test(k)) rm.push(k); } rm.forEach((k) => localStorage.removeItem(k)); } catch (_) {}
      try { if (window.dnKeys && window.dnKeys.clearForUid) window.dnKeys.clearForUid(user.uid); } catch (_) {}
      try { await doLogout(); } catch (_) { location.reload(); }
    };
    const dataDelete = main.querySelector("#data-delete");
    if (dataDelete) dataDelete.onclick = async () => {
      const ok = window.dnConfirm ? await window.dnConfirm("Request account deletion?", "We'll permanently delete your Darknode account and its records, then confirm by email to " + (user.email || "your address") + ".", { submitText: "Request deletion", danger: true }) : true;
      if (!ok) return;
      try { await setDoc(doc(db, "deletionRequests", user.uid), { uid: user.uid, email: user.email || "", requestedAt: serverTimestamp() }, { merge: true }); showToast("Deletion request received. We'll confirm by email.", "success"); }
      catch (e) { showToast("Could not file the request: " + ((e && e.message) || "try emailing contact@darknode.ai"), "error"); }
    };
    // MCP + code-block copy buttons
    const mcpCopy = main.querySelector("#dn-mcp-copy2");
    if (mcpCopy) mcpCopy.onclick = async () => { const c = main.querySelector("#dn-mcp"); if (!c) return; try { await navigator.clipboard.writeText(c.textContent); } catch (_) { showToast("Copy failed", "error"); return; } if (mcpCopy.dataset.o === undefined) mcpCopy.dataset.o = mcpCopy.textContent; mcpCopy.textContent = "Copied"; clearTimeout(mcpCopy._swapT); mcpCopy._swapT = setTimeout(() => { mcpCopy.textContent = mcpCopy.dataset.o; delete mcpCopy.dataset.o; }, 1200); };
    main.querySelectorAll(".set-code-copy").forEach((btn) => { btn.onclick = async () => { const c = main.querySelector("#" + btn.dataset.code); if (!c) return; try { await navigator.clipboard.writeText(c.textContent); } catch (_) { showToast("Copy failed", "error"); return; } if (btn.dataset.o === undefined) btn.dataset.o = btn.textContent; btn.textContent = "copied"; clearTimeout(btn._swapT); btn._swapT = setTimeout(() => { btn.textContent = btn.dataset.o; delete btn.dataset.o; }, 1200); }; });
    const akSave = main.querySelector("#ak-save");
    if (akSave) {
      const akFields = [["groq", "#ak-groq"], ["openrouter", "#ak-openrouter"], ["anthropic", "#ak-anthropic"], ["openai", "#ak-openai"], ["gemini", "#ak-gemini"], ["abuseipdb", "#ak-abuseipdb"], ["virustotal", "#ak-virustotal"], ["shodan", "#ak-shodan"], ["otx", "#ak-otx"]];
      // All credentials are read/written per-account via window.dnKeys (see
      // user-keys.js) so one user never sees another's keys on a shared browser.
      try {
        const keys = window.dnKeys ? window.dnKeys.getJSON("dn_api_keys") : {};
        akFields.forEach(([svc, sel]) => { const el = main.querySelector(sel); if (el && keys[svc]) el.value = keys[svc]; });
      } catch (_) {}
      akSave.onclick = () => {
        try {
          const keys = window.dnKeys ? window.dnKeys.getJSON("dn_api_keys") : {};
          akFields.forEach(([svc, sel]) => { const el = main.querySelector(sel); if (el) { const v = el.value.trim(); if (v) keys[svc] = v; else delete keys[svc]; } });
          if (window.dnKeys) {
            window.dnKeys.setJSON("dn_api_keys", keys);
            // Mirror the AI-engine keys under the names webai.js reads (per-account).
            window.dnKeys.set("sw_groq_key", keys.groq || "");
            window.dnKeys.set("sw_openrouter_key", keys.openrouter || "");
            window.dnKeys.set("sw_claude_key", keys.anthropic || "");
            window.dnKeys.set("sw_openai_key", keys.openai || "");
            window.dnKeys.set("sw_gemini_key", keys.gemini || "");
          }
          const st = main.querySelector("#ak-status"); if (st) { st.textContent = "Keys saved."; st.style.color = "var(--ok,#3fb950)"; setTimeout(() => { st.textContent = ""; }, 2000); }
        } catch (e) { const st = main.querySelector("#ak-status"); if (st) { st.textContent = "Error: " + e.message; st.style.color = "var(--bad,red)"; } }
      };
    }
    const akClear = main.querySelector("#ak-clear");
    if (akClear) {
      akClear.onclick = () => {
        try { if (window.dnKeys) { ["dn_api_keys", "sw_groq_key", "sw_openrouter_key", "sw_claude_key", "sw_openai_key", "sw_gemini_key"].forEach((k) => window.dnKeys.del(k)); } } catch (_) {}
        const inputs = main.querySelectorAll("#set-apikeys-form input"); inputs.forEach((el) => { el.value = ""; });
        const st = main.querySelector("#ak-status"); if (st) { st.textContent = "All keys cleared."; st.style.color = "var(--ok,#3fb950)"; setTimeout(() => { st.textContent = ""; }, 2000); }
      };
    }
    const out = main.querySelector("#set-out"); if (out) out.onclick = () => doLogout();
    const tour = main.querySelector("#set-tour"); if (tour) tour.onclick = () => startTour(tourSteps(isOwner));
    const pwBtn = main.querySelector("#set-pw");
    if (pwBtn) pwBtn.onclick = async () => { pwBtn.disabled = true; try { await sendPasswordResetEmail(auth, user.email, RESET_ACS); showToast("Password reset link sent to " + user.email, "success"); } catch (e) { showToast(errText(e), "error"); } finally { pwBtn.disabled = false; } };
    const codeInput = main.querySelector("#nexus-code");
    if (codeInput) {
      const note = main.querySelector("#nexus-code-note");
      const gen = main.querySelector("#nexus-gen");
      if (gen) gen.onclick = async () => {
        const o = gen.textContent; gen.disabled = true; gen.textContent = "Generating…";
        try {
          const code = await _makePairingCode();
          codeInput.value = _groupPairCode(code);
          if (note) note.innerHTML = "This code is <b>one-time use</b> and expires in <b>5 minutes</b>. Paste it into Nexus with <span class=\"mono\">/login</span>. It carries only a revocable API key &mdash; not your password.";
        } catch (e) {
          if (note) note.textContent = "Could not generate a code: " + ((e && e.message) || "please try again.");
        } finally { gen.disabled = false; gen.textContent = o; }
      };
      const cp = main.querySelector("#nexus-copy"); if (cp) cp.onclick = async () => { if (!codeInput.value) { showToast("Generate a code first", "info"); return; } let okc = true; try { await navigator.clipboard.writeText(codeInput.value); } catch (_) { codeInput.select(); try { okc = document.execCommand("copy"); } catch (__) { okc = false; } } if (!okc) { showToast("Copy failed", "error"); return; } if (cp.dataset.o === undefined) cp.dataset.o = cp.textContent; cp.textContent = "Copied"; clearTimeout(cp._swapT); cp._swapT = setTimeout(() => { cp.textContent = cp.dataset.o; delete cp.dataset.o; }, 1200); };
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

// Which account the app is currently rendered for (see the onAuthStateChanged guard),
// and whether that is a no-Firebase guest/Test session.
let _appUid = null, _appGuest = false;
// Bumped on every show(): a lazy tool module that resolves after the user has already
// moved on must not paint over the newer section.
let _navTok = 0;
const _appH = { on: false, show: () => {}, saveFrame: () => {}, hasTyped: () => false };
// Desktop app home: the Deck, with no console behind it and no console exit (onSignOut
// puts the Deck in primary mode). Access keeps the web's rule, the admin custom claim
// (resolved into _isAdmin from the signed ID token; Security Rules enforce it server-side).
// Any other account gets an honest notice instead of a fallback UI.
function renderDesktopHome(user) {
  const note = (title, body, retry) => {
    view.innerHTML = `<div class="dsk-drag" aria-hidden="true"></div><div class="dsk-note" role="status"><h1>${title}</h1><p>${body}</p><div class="dsk-acts">${retry ? '<button class="btn" id="dskRetry">Try again</button>' : ""}<button class="btn ghost" id="dskOut">Sign out</button></div></div>`;
    view.querySelector("#dskOut").onclick = doLogout;
    const r = view.querySelector("#dskRetry"); if (r) r.onclick = () => renderDesktopHome(user);
  };
  if (!_isAdmin) {
    const who = auth.currentUser ? esc(user.email || "this account") : "Test Mode (no account)";
    note("Desktop workspace not available yet", `The Darknode desktop workspace is not enabled for ${who} yet. Nothing about your account or data has changed. Sign out to use a different account, or keep using Darknode at darknode.ai.`);
    return;
  }
  view.innerHTML = "";
  import("/js/deck/launch.js?v=20261030c")
    .then((m) => m.openDeck(user, { isOwner: true, onSignOut: () => { m.closeDeck(); doLogout(); } }))
    .catch((e) => note("The workspace did not load", esc((e && e.message) || "Unknown error"), true));
}
// Web home: the Deck is the only signed-in UI and owns every darknode.ai/<page> link.
// The console is not offered to anyone, admins included: an old /console/<page> link opens
// that page in the Deck. Its code still renders the Deck's embedded tool frames (/<sec>?embed=1).
const CONSOLE_BASE = "/console";
const isConsolePath = (p) => p === CONSOLE_BASE || p.startsWith(CONSOLE_BASE + "/");
try { localStorage.removeItem("dn_ui"); } catch (_) {} // the old sticky console switch; the path decides now
// The Deck is the only signed-in UI on the website, for admins too. The console renders only
// inside a Deck tool frame (?embed=1), where it draws that one tool.
function deckIsHome() {
  try {
    const q = new URLSearchParams(location.search);
    if (q.get("embed") === "1" || document.documentElement.hasAttribute("data-embed")) return false;
    // an old /console/<page> link opens that page in the Deck
    if (isConsolePath(location.pathname)) history.replaceState(history.state, "", (location.pathname.slice(CONSOLE_BASE.length) || "/") + location.search + location.hash);
    return true;
  } catch (_) { return true; }
}
function setUiPref() { location.assign("/"); }
function renderDeckHome(user) {
  view.innerHTML = "";
  // A deep link (/<sec>) opens that tool inside the Deck; the admin page only for the owner.
  // (same mapping as the console's pathToSec: hyphenated paths are camelCase secs,
  // except tool-<id> mini-tools, which stay as-is)
  const raw = location.pathname.replace(/^\/(console(\/|$))?/, "").replace(/\/$/, "");
  let startSec = !raw ? null : raw.startsWith("tool-") ? raw : raw.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
  if (startSec === "home" || (startSec === "admin" && !_isAdmin)) startSec = null;
  import("/js/deck/launch.js?v=20261030c")
    .then((m) => m.openDeck(user, {
      isOwner: _isAdmin,
      startSec: startSec || undefined,
      onSignOut: () => { m.closeDeck(); doLogout(); },
    }))
    .catch(() => {
      // the Deck is the only UI, so say what failed (no console fallback, admins included)
      view.innerHTML = `<div role="status" style="max-width:560px;margin:18vh auto 0;padding:28px 32px;border:1px solid var(--line,rgba(23,33,56,.14));border-radius:8px"><h1 style="font-size:22px;margin:0 0 8px">Your workspace did not load</h1><p style="margin:0 0 20px;overflow-wrap:anywhere">A network or browser error stopped it. Check your connection and try again.</p><div style="display:flex;gap:10px;flex-wrap:wrap"><button class="btn" id="dkRetry">Try again</button><button class="btn ghost" id="dkOut">Sign out</button></div></div>`;
      view.querySelector("#dkRetry").onclick = () => location.reload(); // a failed import stays failed for this page, so reload
      view.querySelector("#dkOut").onclick = doLogout;
    });
}
function renderApp(user) {
  _appUid = user && user.uid || null;
  _appGuest = !auth.currentUser;
  // Expose the live, authenticated user so an embedded tool frame (/<sec>?embed=1 inside
  // the Deck) can adopt the parent tab's session when its own Firebase persistence resolves
  // to null — otherwise every Deck tool paints the public landing page instead of the tool.
  try { window.__dnCurrentUser = user || null; } catch (_) {}
  dismissBoot();
  document.body.classList.remove("landing");
  document.body.classList.add("app");
  // Desktop app (top frame only; tool iframes never see the bridge): the Deck is the home screen.
  if (isDesktop()) { renderDesktopHome(user); return; }
  // ?embed=1 is only for tool frames inside the Deck. Opened directly in a tab (by anyone, admins
  // included) it would be the console, so drop it: the same /<sec> path then opens that tool in the Deck.
  try {
    const q = new URLSearchParams(location.search);
    if (q.get("embed") === "1" && window.parent === window) { q.delete("embed"); q.delete("ink"); const qs = q.toString(); location.replace(location.pathname + (qs ? "?" + qs : "") + location.hash); return; }
  } catch (_) {}
  if (deckIsHome()) { renderDeckHome(user); return; }
  // Embed mode: when loaded as /<sec>?embed=1 (e.g. inside Darknode Command's
  // in-deck workspace iframe), strip the console chrome so only the live tool
  // shows, full-bleed and transparent. Reused by any host that frames a tool.
  try {
    if (new URLSearchParams(location.search).get("embed") === "1") {
      document.body.classList.add("dn-embed");
      // Tool bridge (D8): forward in-frame tool results to the host for an instant refresh, and
      // let tools ask the host to open an entity/tool. Additive and same-origin; the storage-event
      // path still runs, so this is a speed-up, not a dependency.
      import("/js/deck/embed-bridge.js?v=20261018g").then((m) => { try { m.initEmbedBridge(window); } catch (_) {} }).catch(() => {});
      if (!document.getElementById("dn-embed-css")) {
        const st = document.createElement("style"); st.id = "dn-embed-css";
        st.textContent = "body.dn-embed{background:transparent!important}body.dn-embed .app-shell{display:block!important;min-height:100vh!important}body.dn-embed .con-wrap,body.dn-embed #topbar,body.dn-embed .aws-side,body.dn-embed .aws-side-bd,body.dn-embed #bootscreen,body.dn-embed .skip-link{display:none!important}body.dn-embed .app-main{margin:0!important;padding:16px!important;max-width:none!important;width:100%!important}body.dn-embed .crumbs,body.dn-embed #secIntro,body.dn-embed .app-foot{display:none!important}";
        document.head.appendChild(st);
        // zero-specificity designed defaults for any bare element a tool renders
        const bl = document.createElement("link"); bl.rel = "stylesheet"; bl.href = "/css/deck-base.css"; bl.id = "dn-deck-base"; document.head.appendChild(bl);
      }
      // ink=1: the admin Deck shows this page through an invert filter so it matches its dark
      // ink theme. Flip photos, video and map imagery back so they don't render as negatives.
      if (new URLSearchParams(location.search).get("ink") === "1" && !document.getElementById("dn-ink-css")) {
        const st = document.createElement("style"); st.id = "dn-ink-css";
        st.textContent = 'body.dn-embed :is(img:not([src$=".svg"]),video,.cesium-widget canvas,.leaflet-tile-pane,.maplibregl-canvas,.mapboxgl-canvas){filter:invert(1) hue-rotate(180deg)}'
          // one typeface with the Deck around it; every tool inherits the body font
          + 'body.dn-embed{font-family:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif!important;font-feature-settings:"cv11","ss01"}'
          // no console (AWS-style) colours inside the Deck: primary actions take the Deck's ink
          // button and its single accent instead of AWS orange and Cloudscape blue
          + 'html[data-style=pro] body.app.dn-embed{--acc:#2552c6;--acc-soft:rgba(37,82,198,.08);--aws-orange:#161514;--aws-orange-2:#000;--aws-crumb:#2552c6;--aws-side-on:#2552c6}'
          + 'html[data-embed] body.app.dn-embed :is(.btn:not(.ghost,.danger,.github),button[style*="background:#00aaff"],button[style*="background:#00d4ff"]):not(#dn-x):not(#dn-y):not(#dn-z){color:#fff!important}'
          // (three id-not()s outrank aws.css, which pins its skin with two)
          // let the Deck's own page tone show through behind every tool (ink or cyber)
          + 'html[data-embed] body.app.dn-embed:not(#dn-x):not(#dn-y):not(#dn-z),html[data-embed] body.app.dn-embed :is(#app,#view,.app-shell,.app-main):not(#dn-x):not(#dn-y):not(#dn-z){background:transparent!important}';
        document.head.appendChild(st);
        const fl = document.createElement("link"); fl.rel = "stylesheet"; fl.href = "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Source+Serif+4:opsz,wght@8..60,400;8..60,500&display=swap"; document.head.appendChild(fl);
      }
      // cool=1: an opt-in "cool UI" skin (set from Deck Settings) that keeps the colour
      // scheme but makes the tool chrome more visual — depth from gradients and borders
      // (box-shadow is stripped inside the Deck's invert layer), rounded controls, an
      // accent strip on cards and a little motion. Scoped to body.dn-cool so it only ever
      // touches framed tools that were opened with the flag on.
      if (new URLSearchParams(location.search).get("cool") === "1") {
        document.body.classList.add("dn-cool");
        if (!document.getElementById("dn-cool-css")) {
          const st = document.createElement("style"); st.id = "dn-cool-css";
          st.textContent =
            'body.dn-embed.dn-cool :is(input[type=text],input[type=search],input[type=url],input[type=email],input[type=number],input[type=password],input:not([type]),textarea,select){border-radius:10px!important;border:1.5px solid rgba(23,33,56,.16)!important;background:linear-gradient(180deg,rgba(255,255,255,.78),rgba(244,247,252,.55))!important;transition:border-color .15s ease,background .15s ease!important}'
            + 'body.dn-embed.dn-cool :is(input,textarea,select):focus{border-color:var(--acc)!important;outline:2px solid color-mix(in srgb,var(--acc) 45%,transparent)!important;outline-offset:1px!important}'
            + 'body.dn-embed.dn-cool :is(.btn,button):not(.ghost):not(.danger):not(.link):not(.github){border-radius:10px!important;transition:transform .12s ease,filter .15s ease!important}'
            + 'body.dn-embed.dn-cool :is(.btn,button):not(.ghost):not(.danger):not(.link):not(.github):hover{transform:translateY(-1px)!important;filter:brightness(1.07)!important}'
            + 'body.dn-embed.dn-cool :is(.btn,button):not(.ghost):not(.danger):not(.link):not(.github):active{transform:translateY(0)!important}'
            + 'body.dn-embed.dn-cool :is(.card,.panel,.box,.tool-card,.result-card,.sec-card,.pm-card,.dash-card){border-radius:14px!important;border:1px solid rgba(23,33,56,.1)!important;background:linear-gradient(180deg,rgba(255,255,255,.72),rgba(246,248,252,.5))!important;position:relative!important}'
            + 'body.dn-embed.dn-cool :is(.card,.panel,.box,.tool-card,.result-card,.sec-card,.pm-card,.dash-card)::before{content:""!important;position:absolute!important;left:0;right:0;top:0;height:3px!important;border-radius:14px 14px 0 0!important;background:linear-gradient(90deg,var(--acc),color-mix(in srgb,var(--acc) 35%,transparent))!important;pointer-events:none}'
            + 'body.dn-embed.dn-cool pre{border-radius:12px!important;border:1px solid rgba(23,33,56,.12)!important;background:linear-gradient(180deg,rgba(248,250,253,.92),rgba(238,242,249,.82))!important;padding:14px!important}';
          document.head.appendChild(st);
        }
      }
    }
  } catch (_) {}
  const isOwner = _isAdmin;
  const avatar = user.photoURL
    ? `<img class="p-avatar" src="${esc(user.photoURL)}" alt="">`
    : `<span class="p-avatar p-initials">${esc((user.email || "?")[0].toUpperCase())}</span>`;
  const name = user.displayName || user.email;

  // One main landmark: the console's <main class="app-main">. The skip link lands on the
  // section content itself (past the console bar, side nav and breadcrumbs).
  view.removeAttribute("role");
  { const skip = document.querySelector(".skip-link"); if (skip) skip.href = "#app-content"; }
  view.innerHTML = `
    <div class="app-shell">
      ${consoleHTML(isOwner)}
      <main class="app-main" id="app-main"><div id="crumbs" class="crumbs" aria-label="Breadcrumb" role="navigation"></div><div id="secIntro" class="sec-intro" hidden></div><div id="app-content" tabindex="-1"></div>
        <footer class="app-foot">
          <div class="app-foot-grid">
            <div class="app-foot-col app-foot-brandcol">
              <div class="app-foot-brandline"><span class="app-foot-brand">Darknode</span><span class="app-foot-ver">v3.1</span></div>
              <p class="app-foot-tag">Unified cybersecurity operations platform — offensive, defensive and intelligence operations, with live global intel and AI in a single console.</p>
              <div class="app-foot-status"><span class="afs-dot"></span>All systems operational</div>
              <div class="app-foot-social">
                <a data-goto="ai" class="afs-chip">Darknode AI</a>
                <a data-foot="downloads" class="afs-chip">Get the CLI</a>
                <a data-goto="settings" class="afs-chip">API &amp; MCP</a>
              </div>
            </div>
            <div class="app-foot-col">
              <h4>Monitoring</h4>
              <a data-goto="home">Dashboard</a><a data-goto="vanguard">Attack Surface Scanner</a><a data-goto="cvesearch">CVE Search</a><a data-goto="crucible">Cyber Exercise Range</a>
            </div>
            <div class="app-foot-col">
              <h4>Command Centers</h4>
              <a data-goto="citadel">SOC Console</a><a data-goto="phantom">Network Traffic Analyzer</a><a data-goto="oracle">Threat Intel Workbench</a><a data-goto="spectre">Cloud Posture Manager</a><a data-goto="codescan">Code Scanner</a>
            </div>
            <div class="app-foot-col">
              <h4>Workspace</h4>
              <a data-goto="ai">Darknode AI</a><a data-goto="settings">Settings</a><a data-goto="saved">Saved Items</a><a data-foot="docs">Docs</a><a data-foot="downloads">Downloads</a>
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
  // Smooth view transitions: fade each new section in instead of letting the text
  // "pop" into place. We watch only direct children of #app-content, so a full view
  // swap (main.innerHTML = ...) animates once, while inner updates inside a tool do
  // not. A short cooldown coalesces a render that sets innerHTML then appends a node.
  // Honors prefers-reduced-motion.
  const _reduceMotion = (() => { try { return matchMedia("(prefers-reduced-motion: reduce)").matches; } catch (_) { return false; } })();
  if (!_reduceMotion && typeof MutationObserver === "function" && main.animate) {
    let _fadeAt = 0;
    const fadeObs = new MutationObserver(() => {
      const now = (performance && performance.now) ? performance.now() : Date.now();
      if (now - _fadeAt < 220) return;
      _fadeAt = now;
      try { main.animate([{ opacity: 0, transform: "translateY(6px)" }, { opacity: 1, transform: "none" }], { duration: 170, easing: "cubic-bezier(.2,.6,.2,1)" }); } catch (_) {}
    });
    fadeObs.observe(main, { childList: true });
  }
  const labelOf = navLabel;
  const conNav = wireConsole(view);
  let curSec = "home";
  // Location breadcrumbs (Console > Category > Page), like a cloud console, rather than a visit history.
  function renderCrumbs(sec) {
    const cr = document.getElementById("crumbs"); if (!cr) return;
    const parts = [`<button class="crumb${sec === "home" ? " cur" : ""}" data-crumb="home">Darknode</button>`];
    if (sec !== "home") {
      const g = navGroup(sec);
      if (g) parts.push(`<span class="crumb crumb-grp">${esc(g)}</span>`);
      parts.push(`<span class="crumb cur" aria-current="page">${esc(labelOf(sec))}</span>`);
    }
    cr.innerHTML = parts.join('<span class="crumb-sep" aria-hidden="true">›</span>');
  }
  // Plain-English intro above each section: what the page is and when to use it (section-help.js).
  // Hiding it leaves a small "What is this page?" button; the choice is remembered per section.
  let _secHelp = null;
  function renderIntro(sec) {
    const box = document.getElementById("secIntro"); if (!box) return;
    box.hidden = true; box.innerHTML = "";
    if (!sec || sec === "home" || sec.indexOf("tool-") === 0) return;
    const key = "dn_intro_hide_" + sec;
    const paint = (all) => {
      const h = all && all[sec];
      if (curSec !== sec || !h) return;
      let hide = false; try { hide = localStorage.getItem(key) === "1"; } catch (_) {}
      box.innerHTML = hide
        ? `<button type="button" class="sec-intro-show" aria-expanded="false">What is this page?</button>`
        : `<div class="sec-intro-card" role="note" aria-label="About this page">
            <div class="sec-intro-body">
              <p><span class="mt-k">What this page is</span>${esc(h.what)}</p>
              ${h.when ? `<p class="sec-intro-when"><span class="mt-k">Use it when</span>${esc(h.when)}</p>` : ""}
              ${h.note ? `<p class="sec-intro-note">${esc(h.note)}</p>` : ""}
            </div>
            <button type="button" class="sec-intro-x" aria-label="Hide this explanation">Hide</button>
          </div>`;
      box.hidden = false;
      const set = (v) => { try { v ? localStorage.setItem(key, "1") : localStorage.removeItem(key); } catch (_) {} paint(all); };
      const x = box.querySelector(".sec-intro-x"); if (x) x.onclick = () => set(true);
      const o = box.querySelector(".sec-intro-show"); if (o) o.onclick = () => { set(false); const b = box.querySelector(".sec-intro-x"); if (b) b.focus(); };
    };
    if (_secHelp) paint(_secHelp);
    else import("/js/section-help.js?v=20261029d").then((m) => { _secHelp = m.SECTION_HELP; paint(_secHelp); }).catch(() => {});
  }
  // URL path <-> section mapping
  // The console's own links live under /console (the bare /<page> links belong to the Deck);
  // embedded tool frames keep the bare path the Deck opened them at.
  const conBase = new URLSearchParams(location.search).get("embed") === "1" ? "" : CONSOLE_BASE;
  const secToPath = (s) => s === "home" ? conBase || "/" : conBase + "/" + s.replace(/([A-Z])/g, "-$1").toLowerCase();
  const pathToSec = (p) => {
    if (p && isConsolePath(p)) p = p.slice(CONSOLE_BASE.length);
    if (!p || p === "/") return "home";
    const raw = p.replace(/^\//, "");
    // Toolbox mini-tool secs are literally hyphenated (e.g. tool-base64, tool-w-jwt-analyzer)
    // and must round-trip exactly — do NOT camelCase them (that yields an invalid sec and
    // falls back to home). secToPath leaves them unchanged, so pathToSec must too.
    if (raw.startsWith("tool-")) return raw;
    const s = raw.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    return s || "home";
  };

  // Quelvra (offline math engine, /quelvra/) inside the console. It runs in a same-origin iframe
  // so its own styles, worker and offline cache stay isolated; the theme follows the console.
  function renderQuelvra(main, problem) {
    const dark = () => {
      for (const el of [document.body, document.documentElement]) {
        const m = getComputedStyle(el).backgroundColor.match(/\d+(\.\d+)?/g);
        if (!m || (m.length > 3 && Number(m[3]) < 0.5)) continue; // transparent: look further out
        const [r, g, b] = m.map(Number);
        return 0.2126 * r + 0.7152 * g + 0.0722 * b < 128;
      }
      return false;
    };
    const q = typeof problem === "string" && problem.trim() ? "&q=" + encodeURIComponent(problem.trim().slice(0, 2000)) : "";
    main.innerHTML = `<div class="qv-embed"><iframe title="Quelvra math engine" src="/quelvra/?embed=1&theme=${dark() ? "dark" : "light"}${q}" allow="clipboard-write" loading="eager"></iframe></div>`;
    const frame = main.querySelector("iframe");
    const fit = () => { const top = frame.getBoundingClientRect().top; frame.style.height = Math.max(420, window.innerHeight - Math.max(0, top) - 12) + "px"; };
    fit();
    window.addEventListener("resize", fit);
    const sendTheme = () => { try { frame.contentWindow.postMessage({ type: "quelvra:theme", theme: dark() ? "dark" : "light" }, location.origin); } catch (_) {} };
    frame.addEventListener("load", sendTheme);
    const obs = new MutationObserver(() => { requestAnimationFrame(sendTheme); setTimeout(sendTheme, 400); setTimeout(sendTheme, 1500); });
    const onTrans = (e) => { if (e.target === document.body && e.propertyName === "background-color") sendTheme(); };
    document.body.addEventListener("transitionend", onTrans);
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ["data-style", "class", "data-theme"] });
    obs.observe(document.body, { attributes: true, attributeFilter: ["class", "data-style"] });
    return () => { window.removeEventListener("resize", fit); document.body.removeEventListener("transitionend", onTrans); obs.disconnect(); };
  }

  let _prevCleanup = null;
  // Sections that are really another section (with an optional tab). Resolved here, before
  // the URL is touched, so an alias pushes one history entry and Back never loops. The alias
  // path stays in the URL, so /apikeys remains a working deep link.
  const ALIAS = { arsenal: ["home"], apikeys: ["settings", "apikeys"], github: ["settings"], gmail: ["settings"],
    // Tools merged into the one that does the same job (duplicate-tool cleanup, 2026-10-17).
    threat: ["cvesearch"], threatfeed: ["cvesearch"], utils: ["toolbox"], dnsrecon: ["dns"], dnsenum: ["dns"],
    httpprobe: ["headeranalyzer"], securityscanner: ["headeranalyzer"], httpinspector: ["headeranalyzer"],
    incidentresponse: ["incidents"], casemgmt: ["investigation"], securityquiz: ["secquiz"],
    networktraffic: ["phantom"], trafficanalyzer: ["phantom"], jwtanalyzer: ["tool-w-jwt-analyzer"],
    vulnprio: ["vulnimport"], vulntriage: ["vulnimport"], iocextractor: ["iocenrich"],
    attacksurf: ["posture"], whoisrecon: ["dossier"], ipgeolocation: ["addressintel"], ipreputation: ["addressintel"],
    iptools: ["networktools"], subnetvisualizer: ["networktools"], packetinspector: ["packetanalyzer"],
    emailintel: ["emailheader"], osintemail: ["osint", "email"], phishing: ["phishtriage"], apiscan: ["apifuzzer"],
    siemdash: ["loghunt"], timelineviz: ["ftimeline"], sandbox: ["malclass"], reveng: ["binanalyze"],
    containers: ["iacscan"], vms: ["targets"], training: ["targets"], purpleteam: ["adversaryplaybook"],
    breachsim: ["incidentcost"], riskcalculator: ["riskreg"], secchecklist: ["compliance"], passwordtools: ["credaudit"],
    webshell: ["pentestconsole"], darkwebosint: ["darknetradar"], threatdashboard: ["cyberbriefing"] };
  function show(sec, more, skipPush) {
    const _tok = ++_navTok, live = () => _tok === _navTok;
    if (_prevCleanup) { try { _prevCleanup(); } catch (_) {} _prevCleanup = null; }
    // Update browser URL (from the requested section, alias or not)
    const path = secToPath(sec);
    if (!skipPush && path !== location.pathname) {
      history.pushState({ sec }, "", path);
    }
    const alias = ALIAS[sec];
    if (alias) { sec = alias[0]; if (alias[1] !== undefined) more = alias[1]; }
    curSec = sec; renderCrumbs(sec); renderIntro(sec); conNav.track(sec);
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
    if (sec === "tools") { main.innerHTML = `<div class="pg-head"><div><h1 class="pg-h1">Tools</h1><p class="muted pg-sub">Search, filter, and open any tool in the catalog.</p></div></div><div id="tools"></div>`; import("/js/tools.js?v=20261013c").then(m => live() && m.renderTools(document.getElementById("tools"))); }
    else if (sec === "ai") { import("/js/webai.js?v=20261029e").then(m => live() && m.renderAI(main)); }
    else if (sec === "math") { _prevCleanup = renderQuelvra(main, more); }
    else if (sec === "payloads") { import("/js/labs.js?v=20261028c").then(m => live() && m.renderPayloads(main)); }
    else if (sec === "targets") { import("/js/labs.js?v=20261028c").then(m => live() && m.renderTargets(main)); }
    else if (sec === "ghdb") { import("/js/ghdb.js?v=20261013b").then(m => live() && m.renderGHDB(main)); }
    else if (sec === "exploitdb") { import("/js/exploitdb.js?v=20261013b").then(m => live() && m.renderExploitDB(main)); }
    else if (sec === "vmlab") { import("/js/vmlab.js").then(m => live() && m.renderVMLab(main)); }
    else if (sec === "privatecloud") { import("/js/privatecloud.js").then(m => live() && m.renderPrivateCloud(main)); }
    else if (sec === "saved") { import("/js/saved.js").then(m => live() && m.renderSaved(main, show)); }
    else if (sec === "report") { import("/js/report.js?v=20261028c").then(m => live() && m.renderReport(main)); }
    else if (sec === "snippets") { import("/js/labs.js?v=20261028c").then(m => live() && m.renderSnippets(main)); }
    else if (sec === "refs") { import("/js/labs.js?v=20261028c").then(m => live() && m.renderRefs(main)); }
    else if (sec === "engines") { import("/js/arsenal.js?v=20261029c").then(m => live() && m.renderEngines(main)); }
    else if (sec === "packetcraft") { import("/js/packet-crafter.js?v=20261030b").then(m => live() && m.renderPacketCrafter(main)); }
    else if (sec === "binanalyze") { import("/js/binary-analyzer.js?v=20261030b").then(m => live() && m.renderBinaryAnalyzer(main)); }
    else if (sec === "netmap") { import("/js/network-mapper.js?v=20261030b").then(m => live() && m.renderNetworkMapper(main)); }
    else if (sec === "loganalyze") { import("/js/log-analyzer.js?v=20261030c").then(m => live() && m.renderLogAnalyzer(main)); }
    else if (sec === "credaudit") { import("/js/credential-auditor.js?v=20261029a").then(m => live() && m.renderCredentialAuditor(main)); }
    else if (sec === "memforensics") { import("/js/memory-forensics.js?v=20261030b").then(m => live() && m.renderMemoryForensics(main)); }
    else if (sec === "stego") { import("/js/steganography.js?v=20261030b").then(m => live() && m.renderSteganography(main)); }
    else if (sec === "regexlab") { import("/js/regex-lab.js?v=20261030c").then(m => live() && m.renderRegexLab(main)); }
    else if (sec === "encoding") { import("/js/encoding-suite.js?v=20261030b").then(m => live() && m.renderEncodingSuite(main)); }
    else if (sec === "threatmodel") { import("/js/threat-modeler.js?v=20261028c").then(m => live() && m.renderThreatModeler(main)); }
    else if (sec === "osint") { import("/js/osint-dashboard.js?v=20261029c").then(m => live() && m.renderOSINTDashboard(main, more)); }
    else if (sec === "addressintel") { import("/js/address-intel.js?v=20261029c").then(m => live() && m.renderAddressIntel(main)); }
    else if (sec === "incidents") { import("/js/incident-tracker.js?v=20261029c").then(m => live() && m.renderIncidentTracker(main)); }
    else if (sec === "firewall") { import("/js/firewall-builder.js?v=20261028c").then(m => live() && m.renderFirewallBuilder(main)); }
    else if (sec === "apitester") { import("/js/api-tester.js?v=20261029e").then(m => live() && m.renderAPITester(main)); }
    else if (sec === "compliance") { import("/js/compliance-checker.js?v=20261028c").then(m => live() && m.renderComplianceChecker(main)); }
    else if (sec === "attacksim") { import("/js/attack-simulator.js").then(m => live() && m.renderAttackSimulator(main)); }
    else if (sec === "dns") { import("/js/dns-enum.js?v=20261028a").then(m => live() && m.renderDNSEnum(main)); }
    else if (sec === "subdomains") { import("/js/subdomain-finder.js?v=20261030c").then(m => live() && m.renderSubdomainFinder(main)); }
    else if (sec === "mobilesec") { import("/js/mobile-security-lab.js").then(m => live() && m.renderMobileSecurityLab(main)); }
    else if (sec === "wirelesslab") { import("/js/wireless-lab.js?v=20261013m").then(m => live() && m.renderWirelessLab(main)); }
    else if (sec === "pentestconsole") { import("/js/pentest-console.js?v=20261013b").then(m => live() && m.renderPentestConsole(main)); }
    else if (sec === "cyberrange") { import("/js/cyber-range.js").then(m => live() && m.renderCyberRange(main)); }
    else if (sec === "exploitdev") { import("/js/exploit-writer.js").then(m => live() && m.renderExploitWriter(main)); }
    else if (sec === "secdash") { import("/js/security-dashboard.js?v=20261028c").then(m => live() && m.renderSecurityDashboard(main)); }
    else if (sec === "cracklab") { import("/js/password-cracking-lab.js").then(m => live() && m.renderPasswordCrackingLab(main)); }
    else if (sec === "hydra") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading…</p>"; import("/js/hydra-engine.js?v=20261029c").then(m => live() && m.renderHydra(main)); }
    else if (sec === "aegis") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading…</p>"; import("/js/aegis-web.js?v=20261029c").then(m => live() && m.renderAegis(main)); }
    else if (sec === "vanguard") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading…</p>"; import("/js/vanguard.js?v=20261029c").then(m => live() && m.renderVanguard(main)); }
    else if (sec === "phantom") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading…</p>"; const _s=sec; import("/js/phantom.js?v=20261017d").then(m => { if(curSec!==_s)return; m.renderPhantom(main); _prevCleanup = m.cleanupPhantom; }); }
    else if (sec === "citadel") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading…</p>"; const _s=sec; import("/js/citadel.js?v=20261017d").then(m => { if(curSec!==_s)return; m.renderCitadel(main); _prevCleanup = m.cleanupCitadel; }); }
    else if (sec === "oracle") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading…</p>"; const _s=sec; import("/js/oracle.js?v=20261029c").then(m => { if(curSec!==_s)return; m.renderOracle(main); _prevCleanup = m.cleanupOracle; }); }
    else if (sec === "spectre") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading…</p>"; const _s=sec; import("/js/spectre.js?v=20261028a").then(m => { if(curSec!==_s)return; m.renderSpectre(main); _prevCleanup = m.cleanupSpectre; }); }
    else if (sec === "crucible") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading…</p>"; const _s=sec; import("/js/crucible.js?v=20260924w").then(m => { if(curSec!==_s)return; m.renderCrucible(main); _prevCleanup = m.cleanupCrucible; }); }
    else if (sec === "navarch") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading…</p>"; const _s=sec; import("/js/navarch.js?v=20261014g").then(m => { if(curSec!==_s)return; m.renderNavarch(main); _prevCleanup = m.cleanupNavarch; }); }
    else if (sec === "threatforest") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading…</p>"; const _s=sec; import("/js/threatforest.js?v=20261029d").then(m => { if(curSec!==_s)return; m.renderThreatforest(main); _prevCleanup = m.cleanupThreatforest; }); }
    else if (sec === "beta") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading Beta Lab...</p>"; const _s=sec; import("/js/beta-lab.js?v=20261029c").then(m => { if(curSec!==_s)return; m.renderBetaLab(main); _prevCleanup = m.cleanupBetaLab; }); }
    else if (sec === "crosswalk") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading GenAI Security Crosswalk...</p>"; const _s=sec; import("/js/crosswalk.js?v=20261029c").then(m => { if(curSec!==_s)return; m.renderCrosswalk(main); _prevCleanup = m.cleanupCrosswalk; }); }
    else if (sec === "cspevaluator") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading CSP Evaluator...</p>"; import("/js/csp-evaluator.js?v=20261029e").then(m => live() && m.renderCspEvaluator(main)); }
    else if (sec === "wayback") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading Wayback Recon...</p>"; import("/js/wayback-recon.js?v=20261030c").then(m => live() && m.renderWaybackRecon(main)); }
    else if (sec === "urldissect") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading URL Dissector...</p>"; import("/js/url-dissector.js").then(m => live() && m.renderUrlDissector(main)); }
    else if (sec === "favicon") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading Favicon Hasher...</p>"; import("/js/favicon-hasher.js?v=20261030c").then(m => live() && m.renderFaviconHasher(main)); }
    else if (sec === "adversary") { import("/js/adversary-ai.js").then(m => live() && m.renderAdversaryAI(main)); }
    else if (sec === "huntlab") { import("/js/threat-hunt-lab.js?v=20261030b").then(m => live() && m.renderThreatHuntLab(main)); }
    else if (sec === "deception") { import("/js/deception-architect.js?v=20261030b").then(m => live() && m.renderDeceptionArchitect(main)); }
    else if (sec === "malclass") { import("/js/malware-classifier.js?v=20261030b").then(m => live() && m.renderMalwareClassifier(main)); }
    else if (sec === "zerotrust") { import("/js/zero-trust-designer.js?v=20261028c").then(m => live() && m.renderZeroTrustDesigner(main)); }
    else if (sec === "secquiz") { import("/js/security-awareness-quiz.js?v=20261029c").then(m => live() && m.renderSecurityQuiz(main)); }
    else if (sec === "supplychain") { import("/js/supply-chain-analyzer.js?v=20261029e").then(m => live() && m.renderSupplyChainAnalyzer(main)); }
    else if (sec === "cryptotools") { import("/js/crypto-tools.js?v=20261030b").then(m => live() && m.renderCryptoTools(main)); }
    else if (sec === "ftimeline") { import("/js/forensic-timeline.js").then(m => live() && m.renderForensicTimeline(main)); }
    else if (sec === "socialeng") { import("/js/social-engineering-sim.js").then(m => live() && m.renderSocialEngSim(main)); }
    else if (sec === "cheats") renderCheats(main);
    else if (sec === "cyberbriefing") { import("/js/cyber-briefing.js?v=20261007a").then(m => live() && m.renderCyberBriefing(main)); }
    else if (sec === "incidentcost") { import("/js/incident-cost.js?v=20261029c").then(m => live() && m.renderIncidentCost(main)); }
    else if (sec === "fedcompliance") { import("/js/fed-compliance.js").then(m => live() && m.renderFedCompliance(main)); }
    else if (sec === "adversaryplaybook") { import("/js/adversary-playbook.js?v=20261028c").then(m => live() && m.renderAdversaryPlaybook(main)); }
    else if (sec === "emailheader") { import("/js/email-header.js?v=20261029e").then(m => live() && m.renderEmailHeader(main)); }
    else if (sec === "dossier") { import("/js/target-dossier.js").then(m => live() && m.renderDossier(main)); }
    else if (sec === "payloadstudio") { import("/js/payload-studio.js?v=20261013m").then(m => live() && m.renderPayloadStudio(main)); }
    else if (sec === "sigma") { import("/js/sigma-builder.js?v=20261030c").then(m => live() && m.renderSigmaBuilder(main)); }
    else if (sec === "iocenrich") { import("/js/ioc-enrichment.js?v=20261030c").then(m => live() && m.renderIocEnrichment(main)); }
    else if (sec === "embedsdk") { import("/js/embed-sdk.js").then(m => live() && m.renderEmbedSDK(main)); }
    else if (sec === "mcpconnect") { import("/js/mcp-connector.js?v=20261029d").then(m => live() && m.renderMcpConnector(main)); }
    else if (sec === "cvsscalc") { import("/js/cvss-calculator.js?v=20261028c").then(m => live() && m.renderCvssCalculator(main)); }
    else if (sec === "yarabuilder") { import("/js/yara-builder.js?v=20261030c").then(m => live() && m.renderYaraBuilder(main)); }
    else if (sec === "emailauth") { import("/js/email-auth.js").then(m => live() && m.renderEmailAuth(main)); }
    else if (sec === "cookieinspect") { import("/js/cookie-inspector.js?v=20261029e").then(m => live() && m.renderCookieInspector(main)); }
    else if (sec === "securitytxt") { import("/js/security-txt.js?v=20261030b").then(m => live() && m.renderSecurityTxt(main)); }
    else if (sec === "codescan") { import("/js/code-scanner.js?v=20261029e").then(m => live() && m.renderCodeScanner(main)); }
    else if (sec === "reconplanner") { import("/js/recon-planner.js?v=20261013b").then(m => live() && m.renderReconPlanner(main)); }
    else if (sec === "apifuzzer") { import("/js/api-fuzzer.js?v=20261029e").then(m => live() && m.renderAPIFuzzer(main)); }
    else if (sec === "privesc") { import("/js/privesc-toolkit.js?v=20260928m").then(m => live() && m.renderPrivescToolkit(main)); }
    else if (sec === "reverseshell") { import("/js/reverse-shell.js?v=20260928m").then(m => live() && m.renderReverseShell(main)); }
    else if (sec === "xsslab") { import("/js/xss-lab.js?v=20261029e").then(m => live() && m.renderXSSLab(main)); }
    else if (sec === "investigation") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading Investigation Workspace...</p>"; const _s=sec; import("/js/investigation.js?v=20261029c").then(m => { if(curSec!==_s)return; m.renderInvestigation(main); _prevCleanup = m.cleanupInvestigation; }); }
    else if (sec === "secgraph") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading Security Graph...</p>"; import("/js/security-graph-ui.js?v=20261014f").then(m => live() && m.renderSecurityGraphUI(main)); }

    else if (sec === "cvetimeline") { import("/js/cve-timeline.js?v=20261029c").then(m => live() && m.renderCveTimeline(main)); }
    else if (sec === "dataviz") { import("/js/data-viz.js?v=20261029c").then(m => live() && m.renderDataViz(main)); }
    else if (sec === "forensicstoolkit") { import("/js/forensics-toolkit.js?v=20261030b").then(m => live() && m.renderForensicsToolkit(main)); }
    else if (sec === "hashsuite") { import("/js/hash-suite.js?v=20261030c").then(m => live() && m.renderHashSuite(main)); }
    else if (sec === "networktools") { import("/js/network-tools.js").then(m => live() && m.renderNetworkTools(main)); }
    else if (sec === "packetanalyzer") { import("/js/packet-analyzer.js?v=20261029c").then(m => live() && m.renderPacketAnalyzer(main)); }
    else if (sec === "payloadgen") { import("/js/payload-gen.js?v=20260924b").then(m => live() && m.renderPayloadGen(main)); }
    else if (sec === "vulndb") { import("/js/vulnerability-db.js?v=20261030b").then(m => live() && m.renderVulnerabilityDB(main)); }
    else if (sec === "asnexplorer") { import("/js/asn-explorer.js?v=20261030c").then(m => live() && m.renderAsnExplorer(main)); }
    else if (sec === "breachlookup") { import("/js/breach-lookup.js").then(m => live() && m.renderBreachLookup(main)); }
    else if (sec === "corstester") { import("/js/cors-tester.js?v=20261029e").then(m => live() && m.renderCorsTester(main)); }
    else if (sec === "cvesearch") { import("/js/cve-search.js?v=20261028a").then(m => live() && m.renderCveSearch(main)); }
    else if (sec === "darknetradar") { import("/js/darknet-radar.js?v=20261013c").then(m => live() && m.renderDarknetRadar(main)); }
    else if (sec === "headeranalyzer") { import("/js/header-analyzer.js?v=20261013b").then(m => live() && m.renderHeaderAnalyzer(main)); }
    else if (sec === "identitymatrix") { import("/js/identity-matrix.js?v=20260924b").then(m => live() && m.renderIdentityMatrix(main)); }
    else if (sec === "networkscanner") { import("/js/network-scanner.js").then(m => live() && m.renderNetworkScanner(main)); }
    else if (sec === "sslinspector") { import("/js/ssl-inspector.js?v=20261030c").then(m => live() && m.renderSSLInspector(main)); }
    else if (sec === "techfingerprint") { import("/js/tech-fingerprint.js").then(m => live() && m.renderTechFingerprint(main)); }
    else if (sec === "websockettester") { import("/js/websocket-tester.js?v=20261029e").then(m => live() && m.renderWebSocketTester(main)); }
    else if (sec === "learn") { main.innerHTML = "<p class=\"muted\" style=\"text-align:center;padding:40px\">Loading Learn Hub...</p>"; loadLearnHub().then(m => live() && m.renderLearnHub(main)); }
    else if (sec === "learndo") { import("/js/learndo.js?v=20261009a").then(m => live() && m.renderLearnDo(main)); }
    else if (sec === "engine") { import("/js/engine-tab.js?v=20260929t").then(m => live() && m.renderEngine(main)); }
    else if (sec === "coder") { import("/js/coder.js?v=20261021c").then(m => live() && m.renderCliCoder(main)); }
    else if (sec === "downloads") { import("/js/getapp.js?v=20261025h").then(m => live() && m.renderDownloads(main)); }
    else if (sec === "dlguide") { import("/js/getapp.js?v=20261025h").then(m => live() && m.renderDownloadDocs(main)); }
    else if (sec === "api") { import("/js/api.js?v=20261029c").then(m => live() && m.renderAPI(main, user)); }
    else if (sec === "docs") { import("/js/docs.js?v=20261029c").then(m => live() && m.renderDocs(main)); }
    else if (sec === "veil") { import("/js/labs/veil.js?v=20261013m").then(m => live() && m.renderVeil(main)); }
    else if (sec === "strongroom") { import("/js/strongroom.js?v=20261029c").then(m => live() && m.renderStrongroom(main)); }
    else if (sec === "signins") { import("/js/identity/signin-forensics.js?v=20261029e").then(m => live() && m.renderSigninForensics(main)); }
    else if (sec === "accessreview") { import("/js/identity/access-review.js?v=20261029e").then(m => live() && m.renderAccessReview(main)); }
    else if (sec === "fwaudit") { import("/js/infra/firewall-audit.js?v=20261029e").then(m => live() && m.renderFirewallAudit(main)); }
    else if (sec === "loghunt") { import("/js/ops/log-hunter.js?v=20261029c").then(m => live() && m.renderLogHunter(main)); }
    else if (sec === "payees") { import("/js/finsec/vendors.js?v=20261029c").then(m => live() && m.renderVendors(main)); }
    else if (sec === "dlp") { import("/js/dataprotect/dlp.js?v=20261030c").then(m => live() && m.renderDlp(main)); }
    else if (sec === "posture") { import("/js/dataprotect/posture.js?v=20261029c").then(m => live() && m.renderPosture(main)); }
    else if (sec === "tlsfleet") { import("/js/dataprotect/tlsfleet.js?v=20261029e").then(m => live() && m.renderTlsFleet(main)); }
    else if (sec === "phishtriage") { import("/js/dataprotect/phish.js?v=20261029c").then(m => live() && m.renderPhish(main)); }
    else if (sec === "leakprobe") { import("/js/dataprotect/leakprobe.js?v=20261029e").then(m => live() && m.renderLeakprobe(main)); }
    else if (sec === "caaudit") { import("/js/identity/caaudit.js?v=20261029e").then(m => live() && m.renderCaAudit(main)); }
    else if (sec === "privaudit") { import("/js/identity/privaudit.js?v=20261030c").then(m => live() && m.renderPrivAudit(main)); }
    else if (sec === "nhi") { import("/js/identity/nhi.js?v=20261029e").then(m => live() && m.renderNhi(main)); }
    else if (sec === "jml") { import("/js/identity/jml.js?v=20261029e").then(m => live() && m.renderJml(main)); }
    else if (sec === "oauthgov") { import("/js/identity/oauthgov.js?v=20261029e").then(m => live() && m.renderOauthGov(main)); }
    else if (sec === "iacscan") { import("/js/appsec/iacscan.js?v=20261029e").then(m => live() && m.renderIacScan(main)); }
    else if (sec === "cloudtrail") { import("/js/ops/cloudtrail.js?v=20261029c").then(m => live() && m.renderCloudTrail(main)); }
    else if (sec === "vulnimport") { import("/js/exposure/vulnimport.js?v=20261029e").then(m => live() && m.renderVulnImport(main)); }
    else if (sec === "fleetcomply") { import("/js/exposure/fleetcomply.js?v=20261029e").then(m => live() && m.renderFleetComply(main)); }
    else if (sec === "k8saudit") { import("/js/appsec/k8saudit.js?v=20261030c").then(m => live() && m.renderK8sAudit(main)); }
    else if (sec === "cloudspend") { import("/js/finsec/cloudspend.js?v=20261029c").then(m => live() && m.renderCloudSpend(main)); }
    else if (sec === "breachclock") { import("/js/risk/breachclock.js?v=20261030c").then(m => live() && m.renderBreachClock(main)); }
    else if (sec === "riskreg") { import("/js/risk/riskreg.js?v=20261030c").then(m => live() && m.renderRiskRegister(main)); }
    else if (sec === "evidence") { import("/js/compliance/evidence.js?v=20261029e").then(m => live() && m.renderEvidence(main)); }
    else if (sec === "vendorrisk") { import("/js/risk/vendorrisk.js?v=20261029e").then(m => live() && m.renderVendorRisk(main)); }
    else if (sec === "backupready") { import("/js/risk/backupready.js?v=20261029c").then(m => live() && m.renderBackupReady(main)); }
    else if (sec === "dmarcreports") { import("/js/exposure/dmarcreports.js?v=20261029e").then(m => live() && m.renderDmarcReports(main)); }
    else if (sec === "domainguard") { import("/js/exposure/domainguard.js?v=20261030c").then(m => live() && m.renderDomainGuard(main)); }
    else if (sec === "dnshunt") { import("/js/ops/dnshunt.js?v=20261029e").then(m => live() && m.renderDnsHunt(main)); }
    else if (sec === "proxyhunt") { import("/js/ops/proxyhunt.js?v=20261029c").then(m => live() && m.renderProxyHunt(main)); }
    else if (sec === "vpnaudit") { import("/js/identity/vpnaudit.js?v=20261029e").then(m => live() && m.renderVpnAudit(main)); }
    else if (sec === "netexposure") { import("/js/exposure/netexposure.js?v=20261029e").then(m => live() && m.renderNetExposure(main)); }
    else if (sec === "licenseaudit") { import("/js/appsec/licenseaudit.js?v=20261029c").then(m => live() && m.renderLicenseAudit(main)); }
    else if (sec === "apispec") { import("/js/appsec/apispec.js?v=20261029e").then(m => live() && m.renderApiSpec(main)); }
    else if (sec === "dataflow") { import("/js/compliance/dataflow.js?v=20261030c").then(m => live() && m.renderDataFlow(main)); }
    else if (sec === "awareness") { import("/js/compliance/awareness.js?v=20261030c").then(m => live() && m.renderAwareness(main)); }
    else if (sec === "pentestreg") { import("/js/ops/pentestreg.js?v=20261029e").then(m => live() && m.renderPentestReg(main)); }
    else if (sec === "setup") renderSetup(main, more);
    else if (sec === "settings") renderSettingsPage(main, user, isOwner, more);
    else if (sec === "admin") { import("/js/admin.js?v=20261030c").then(m => live() && m.renderAdmin(main, user)); }
    else if (sec === "contact") renderContact(main);
    else if (sec === "education") { main.innerHTML = `<div class="panel" style="max-width:800px;margin:40px auto"><div class="panel-h">About Darknode Education</div><div style="padding:18px;line-height:1.8;font-size:.9rem"><p><strong>Darknode is a cybersecurity education platform</strong> designed for students, educators, and security professionals to learn information security through hands-on practice in a safe, controlled environment.</p><p style="margin-top:16px"><strong>Our Mission:</strong> To make cybersecurity education accessible, interactive, and practical. Most tools run in your browser or on your own machine. Some features do send data out: AI chat goes through Darknode's server to the AI provider, some lookup pages query public services (for example NVD, crt.sh and DNS-over-HTTPS resolvers), and saved items and account data are stored in Google Firebase. Each page that contacts an outside service does so only when you run it.</p><p style="margin-top:16px"><strong>Who Uses Darknode:</strong></p><ul style="margin:8px 0 0 20px;line-height:2"><li>Computer science and cybersecurity students</li><li>IT professionals studying for certifications (CompTIA Security+, CISSP, CEH, OSCP)</li><li>University professors and instructors teaching security courses</li><li>Security operations center (SOC) analysts in training</li><li>Career changers learning cybersecurity fundamentals</li></ul><p style="margin-top:16px"><strong>Educational Standards:</strong> Our curriculum aligns with NIST NICE Framework, NSA CAE-CD requirements, and CompTIA Security+ objectives. All practice environments are isolated, legal, and designed for authorized educational use only.</p><p style="margin-top:16px"><strong>Responsible Use:</strong> Darknode tools are designed exclusively for educational purposes and authorized security testing. Users must comply with all applicable laws and obtain proper authorization before testing any system they do not own.</p><p style="margin-top:16px;color:var(--mut);font-size:.82rem">Darknode is a product of Darknode-Official. For questions about our educational programs, visit darknode.ai.</p></div></div>`; }
    else if (sec === "toolbox") { import("/js/mini-tools.js?v=20261029e").then(m => live() && m.renderToolbox(main, { onOpen: (id) => show("tool-" + id) })); }
    else if (sec.indexOf("tool-") === 0) { const _tid = sec.slice(5); import("/js/mini-tools.js?v=20261029e").then(m => live() && m.renderMiniTool(main, _tid, { onBack: () => show("toolbox") })); }
    else renderHome(main, user, isOwner, show);
    if (more === undefined) { try { localStorage.setItem("sw_last_sec", sec); } catch (_) {} }
    // Jump back to the top on every navigation. The page scrolls on the window
    // (not #app-content), and several routes mount their content in an async
    // import().then() a frame or two later, so reset the window now and again
    // after the new view has had a chance to mount. Force an INSTANT jump:
    // html has scroll-behavior:smooth, so a bare scrollTo(0,0) animates a long
    // slow scroll up before the new view shows — exactly the jank we don't want.
    const jumpTop = () => {
      main.scrollTop = 0;
      try { window.scrollTo({ top: 0, left: 0, behavior: "instant" }); }
      catch (_) { window.scrollTo(0, 0); }
    };
    jumpTop();
    requestAnimationFrame(jumpTop);
  }
  // Window/document listeners are registered ONCE per page and always dispatch to the
  // latest render's functions — a re-render must not leave stale handlers driving old DOM.
  _appH.show = show;
  if (!_appH.on) {
    _appH.on = true;
    // Handle browser back/forward
    window.addEventListener("popstate", (e) => {
      const sec = (e.state && e.state.sec) || pathToSec(location.pathname);
      _appH.show(sec, undefined, true);
    });
    // Handle keyboard shortcut navigation (from shortcuts.js)
    document.addEventListener("dn:navigate", (e) => { if (e.detail) _appH.show(e.detail); });
    document.addEventListener("keydown", (e) => {
      if ((e.metaKey || e.ctrlKey) && (e.key === "s" || e.key === "S") && document.body.classList.contains("app")) { e.preventDefault(); _appH.saveFrame(); }
    });
    // gentle exit-intent hint (once per session) + native unsaved-changes guard
    let exitHinted = false;
    document.addEventListener("mouseout", (e) => { if (e.clientY <= 0 && !exitHinted && _appH.hasTyped()) { exitHinted = true; toast("Leaving? Press Ctrl+S to save this exact frame so you resume right here.", 5000); } });
    window.addEventListener("beforeunload", (e) => { if (_appH.hasTyped()) { e.preventDefault(); e.returnValue = ""; } });
  }

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
  // Handle data-sec clicks anywhere in the view (dashboard cards, hero buttons, Home widgets).
  // data-more carries a tab or scroll target (e.g. settings -> apikeys) through to show().
  view.addEventListener("click", (e) => {
    if (e.target.closest("[data-open-services]")) { e.stopPropagation(); const sb = document.getElementById("conServices"); if (sb) sb.click(); return; }
    const sec = e.target.closest("[data-sec]");
    if (sec && !sec.closest(".side-nav")) { show(sec.dataset.sec, sec.dataset.more || undefined); }
  });
  // Keep internal navigation inside the SPA. A plain <a href="/section"> rendered by
  // any feature would otherwise do a full page reload — which replays the boot screen
  // and briefly throws the user off the app. Route same-tab, same-origin path links
  // through show() instead. External links, new-tab (_blank), downloads, in-page
  // anchors and explicit opt-outs (data-full / data-nav-skip) are left untouched so
  // genuine off-site actions (connections, manual logins, file downloads) still work.
  view.addEventListener("click", (e) => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    const a = e.target.closest("a[href]");
    if (!a || (a.target && a.target !== "_self")) return;
    if (a.hasAttribute("download") || a.dataset.full === "1" || a.dataset.navSkip === "1") return;
    const href = a.getAttribute("href") || "";
    if (!href.startsWith("/") || href.startsWith("//")) return;   // only same-origin absolute paths
    let url; try { url = new URL(href, location.origin); } catch (_) { return; }
    if (url.origin !== location.origin) return;
    if (url.pathname === location.pathname && url.hash) return;   // in-page hash anchor
    const target = pathToSec(url.pathname);
    if (!target) return;
    e.preventDefault();
    show(target);
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
    <button class="style-toggle" id="styleToggle" data-style="${currentStyle()}" title="${currentStyle() === "dark" ? "Switch to light" : "Switch to dark"}" aria-label="${currentStyle() === "dark" ? "Switch to light theme" : "Switch to dark theme"}"><svg class="ic-sun" viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="8" cy="8" r="3.2"/><path d="M8 1v2M8 13v2M1 8h2M13 8h2M3 3l1.4 1.4M11.6 11.6L13 13M13 3l-1.4 1.4M4.4 11.6L3 13" stroke-linecap="round"/></svg><svg class="ic-moon" viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M13.5 9.5A5.5 5.5 0 016.5 2.5a5.5 5.5 0 107 7z" stroke-linejoin="round"/></svg></button>
    <button class="cmdk-btn" id="cmdkBtn" title="Search (Ctrl+K)"><span>Search</span><kbd>Ctrl K</kbd></button>
    <button class="tb-help-btn" id="helpBtn" title="Help &amp; support" aria-label="Help and support" onclick="window.__openHelp&&window.__openHelp()"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M21 11.5a8.38 8.38 0 01-.9 3.8 8.5 8.5 0 01-7.6 4.7 8.38 8.38 0 01-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 01-.9-3.8 8.5 8.5 0 014.7-7.6 8.38 8.38 0 013.8-.9h.5a8.48 8.48 0 018 8v.5z"/></svg><span>Help</span></button>
    <span id="cli-dot" style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#71717a;margin:0 10px;cursor:pointer;vertical-align:middle;transition:background .3s" title="CLI not connected" onclick="window.dnPrompt('Connect Darknode CLI',{desc:'Paste the auth token shown in your terminal after you run the Darknode CLI. It links this browser to your local tools and models.',placeholder:'darknode auth token'}).then(function(t){if(t&&window._bridge)window._bridge.connect(t.trim()).then(function(r){var d=document.getElementById('cli-dot');if(d){d.style.background='#22c55e';d.title='CLI connected: '+(r.hostname||'local')}showToast('Connected to '+(r.hostname||'CLI')+' — '+((r.tools||[]).length)+' tools, '+((r.ollama||[]).length)+' AI models','success')}).catch(function(e){showToast('Failed: '+e.message,'error')})})"></span>
    <div class="tb-item">
      <button class="icon-btn" id="moreBtn" title="More" aria-label="More" aria-haspopup="true" aria-expanded="false" aria-controls="moreMenu">&#8943;</button>
      <div class="menu" id="moreMenu" hidden>
        ${MORE.map((m) => `<button class="menu-item col" data-more="${m.id}"><strong>${esc(m.name)}</strong><span class="menu-sub">${esc(m.desc)}</span></button>`).join("")}
      </div>
    </div>
    <div class="tb-item">
      <button class="profile-btn" id="profileBtn" aria-label="Account menu, ${esc(user.email)}" aria-haspopup="true" aria-expanded="false" aria-controls="profileMenu">${avatar}<span class="p-email" aria-hidden="true">${esc(user.email)}</span></button>
      <div class="menu menu-wide" id="profileMenu" hidden>
        <div class="menu-prof">${avatar}<div style="min-width:0"><div class="su-name">${esc(name)}</div><div class="su-mail muted">${esc(user.email)}${isOwner ? ' <span class="owner-badge">OWNER</span>' : ""}</div></div></div>
        <div class="menu-lbl">Account</div>
        <button class="menu-item" data-nav="settings">Settings</button>
        <button class="menu-item" data-nav="saved">Saved items</button>
        <button class="menu-item" data-nav="api">API keys &amp; MCP</button>
        <div class="menu-div"></div>
        <div class="menu-lbl">Workspace</div>
        <div class="menu-grid">
          <button class="menu-tile" data-nav="ai"><strong>Darknode AI</strong><span>Chat assistant</span></button>
          <button class="menu-tile" data-nav="coder"><strong>Nexus Agent</strong><span>AI coder</span></button>
          <button class="menu-tile" data-nav="downloads"><strong>Downloads</strong><span>App &amp; CLI</span></button>
          <button class="menu-tile" data-nav="docs"><strong>Docs</strong><span>Guides &amp; API</span></button>
          <button class="menu-tile" data-nav="beta"><strong>Beta Lab</strong><span>Preview prototypes</span></button>
        </div>
        <div class="menu-div"></div>
        <div class="menu-lbl">Preferences</div>
        <button class="menu-item menu-item-kbd" data-a="palette">Command palette<kbd>Ctrl K</kbd></button>
        <button class="menu-item" data-a="style">Switch theme style</button>
        <button class="menu-item" data-a="theme">Toggle light / dark</button>
        <button class="menu-item" data-a="deck">Switch to the Deck</button>
        <button class="menu-item" data-a="tour">Replay walkthrough</button>
        <button class="menu-item" data-a="betaask">Request a Beta Lab tool</button>
        <div class="menu-div"></div>
        <button class="menu-item" data-nav="contact">Contact / Feedback</button>
        <button class="menu-item menu-item-danger" data-a="logout">Log out</button>
      </div>
    </div>`;
  const profileMenu = document.getElementById("profileMenu");
  const moreMenu = document.getElementById("moreMenu");
  const profileBtn = document.getElementById("profileBtn");
  const moreBtn = document.getElementById("moreBtn");
  const menuOf = (btn) => btn === profileBtn ? profileMenu : moreMenu;
  // Escape closes an open topbar menu and puts focus back on its button; the menus are
  // plain popovers, so arrow keys walk their items like a native menu.
  const closeMenus = (refocus) => {
    for (const btn of [profileBtn, moreBtn]) {
      const m = menuOf(btn); if (!btn || !m || m.hidden) continue;
      if (refocus || m.contains(document.activeElement)) btn.focus();
      m.hidden = true; btn.setAttribute("aria-expanded", "false");
    }
  };
  const toggleMenu = (btn) => (e) => {
    e.stopPropagation();
    const m = menuOf(btn), wasHidden = m.hidden;
    closeMenus(false);
    m.hidden = !wasHidden; btn.setAttribute("aria-expanded", String(wasHidden));
  };
  const menuKeys = (btn) => (e) => {
    const m = menuOf(btn); if (!m || m.hidden) return;
    const items = [...m.querySelectorAll("button:not([hidden])")];
    if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); closeMenus(true); return; }
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    const i = items.indexOf(document.activeElement), d = e.key === "ArrowDown" ? 1 : -1;
    (items[i < 0 ? (d > 0 ? 0 : items.length - 1) : (i + d + items.length) % items.length] || items[0]).focus();
  };
  if (profileBtn) { profileBtn.onclick = toggleMenu(profileBtn); profileBtn.parentElement.addEventListener("keydown", menuKeys(profileBtn)); }
  if (moreBtn) { moreBtn.onclick = toggleMenu(moreBtn); moreBtn.parentElement.addEventListener("keydown", menuKeys(moreBtn)); }
  document.addEventListener("click", () => closeMenus(false));
  if (profileMenu) profileMenu.onclick = (e) => {
    const nb = e.target.closest("[data-nav]"), lb = e.target.closest("[data-a]"); if (!nb && !lb) return;
    closeMenus();
    if (nb) return show(nb.dataset.nav);
    const a = lb.dataset.a;
    if (a === "logout") doLogout();
    else if (a === "deck") setUiPref(null);
    else if (a === "theme") { const cur = document.documentElement.getAttribute("data-theme") || "dark"; applyTheme(cur === "dark" ? "light" : "dark"); }
    else if (a === "style") cycleStyle();
    else if (a === "palette") openPalette();
    else if (a === "tour") startTour(tourSteps(isOwner));
    else if (a === "feedback") openFeedback(user);
    else if (a === "betaask") {
      const ov = document.createElement("div");
      ov.style.cssText = "position:fixed;inset:0;z-index:9999;background:rgba(4,6,12,.72);display:flex;align-items:center;justify-content:center;padding:20px";
      ov.innerHTML = '<div style="background:#10131f;border:1px solid rgba(120,140,190,.3);border-radius:14px;padding:22px;max-width:460px;width:100%"><div class="beta-ask-mount"></div><div style="text-align:right;margin-top:12px"><button class="btn btn-ghost" id="betaAskClose">Close</button></div></div>';
      const close = () => ov.remove();
      ov.onclick = (ev) => { if (ev.target === ov) close(); };
      document.body.appendChild(ov);
      document.getElementById("betaAskClose").onclick = close;
      import("/js/beta-lab.js?v=20261029c").then((m) => m.mountRequestForm(ov.querySelector(".beta-ask-mount"), { user })).catch(() => { ov.querySelector(".beta-ask-mount").textContent = "Beta Lab is unavailable right now."; });
    }
  };
  if (moreMenu) moreMenu.onclick = (e) => { const b = e.target.closest("[data-more]"); if (!b) return; closeMenus(); show("setup", b.dataset.more); };
  const cmdkBtn = document.getElementById("cmdkBtn");
  if (cmdkBtn) cmdkBtn.onclick = openPalette;
  const styleToggle = document.getElementById("styleToggle");
  if (styleToggle) styleToggle.onclick = cycleStyle;

  // Footer and quick-nav links ([data-goto], [data-foot]) are real anchors with the section's
  // path, so they are keyboard-focusable and open in a new tab, and one delegated handler
  // routes them in place, including links rendered later (e.g. "Get the CLI bundle" in Settings).
  const footHref = (a) => a.dataset.goto ? secToPath(a.dataset.goto) : a.dataset.foot === "downloads" ? "/downloads" : a.dataset.foot === "docs" ? "/docs" : "/docs#doc-" + a.dataset.foot;
  const linkify = (root) => root.querySelectorAll("a[data-goto]:not([href]), a[data-foot]:not([href])").forEach((a) => { a.href = footHref(a); });
  linkify(view);
  new MutationObserver((recs) => recs.forEach((r) => r.addedNodes.forEach((n) => { if (n.nodeType === 1) linkify(n); }))).observe(main, { childList: true, subtree: true });
  view.addEventListener("click", (e) => {
    const a = e.target.closest("[data-goto], [data-foot]"); if (!a || !view.contains(a)) return;
    if (e.ctrlKey || e.metaKey || e.shiftKey || e.button !== 0) return;
    e.preventDefault();
    if (a.dataset.goto) return show(a.dataset.goto);
    const f = a.dataset.foot;
    if (f === "downloads") return show("downloads");
    show("docs");
    if (f !== "docs") setTimeout(() => { const t = document.getElementById("doc-" + f); if (t) t.scrollIntoView({ behavior: "smooth", block: "start" }); }, 60);
  });

  // Topbar live ops strip — fills the empty center of the header with a status
  // line, a ticking UTC clock, real security-graph posture metrics and quick launchers.
  const tbCenter = document.getElementById("topbar-center");
  if (tbCenter) {
    tbCenter.innerHTML = `
      <span class="tbx tbx-status" title="All systems operational"><span class="tbx-dot"></span>OPERATIONAL</span>
      <span class="tbx-sep tbx-amb"></span>
      <span class="tbx tbx-clock tbx-amb" id="tb-clock" title="System time (UTC)">--:--:-- UTC</span>
      <span class="tbx-sep tbx-amb" id="tb-posture-sep" hidden></span>
      <span class="tbx tbx-amb" id="tb-posture" title="Open findings in your security graph (real data only)" hidden></span>
      <span class="tbx-sep"></span>
      <div class="tb-pop-wrap">
        <button class="tbx tbx-btn tb-pop-btn" data-pop="tbCreate" title="Quick create" aria-haspopup="true">+ New</button>
        <div class="tb-pop" id="tbCreate" hidden>
          <div class="tb-pop-h">Quick create</div>
          <button class="tb-pop-i" data-goto="headeranalyzer"><b>New scan</b><span>Grade a site's HTTP security headers</span></button>
          <button class="tb-pop-i" data-goto="investigation"><b>New case</b><span>Open an investigation case file</span></button>
          <button class="tb-pop-i" data-goto="report"><b>New report</b><span>Draft a findings report</span></button>
          <button class="tb-pop-i" data-goto="payloads"><b>New payload</b><span>Build a payload in the Forge</span></button>
          <button class="tb-pop-i" data-goto="saved"><b>Quick note</b><span>Jump to your saved items</span></button>
        </div>
      </div>
      <div class="tb-pop-wrap">
        <button class="tbx tbx-btn tb-pop-btn" data-pop="tbAlerts" title="High-severity findings in your security graph" aria-haspopup="true">Alerts <span class="tb-badge" id="tbAlertBadge" style="display:none"></span></button>
        <div class="tb-pop tb-pop-wide" id="tbAlerts" hidden>
          <div class="tb-pop-h">High-severity findings <button class="tb-pop-clear" id="tbAlertClear">Mark all read</button></div>
          <div id="tbAlertList"></div>
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

    // Posture metric + alerts come from the real security graph (posture.js excludes
    // simulated/sample entities). No hardcoded numbers — empty graph shows nothing.
    const tbRelTime = (iso) => {
      const t = Date.parse(iso); if (!isFinite(t)) return "";
      const d = Date.now() - t;
      if (d < 60000) return "just now";
      if (d < 3600000) return Math.floor(d / 60000) + "m ago";
      if (d < 86400000) return Math.floor(d / 3600000) + "h ago";
      return Math.floor(d / 86400000) + "d ago";
    };
    const refreshTbOps = () => {
      Promise.all([import("/js/security-graph.js"), import("/js/core/posture.js")]).then(([sg, P]) => {
        let list; try { list = sg.listEntities(); } catch (_) { list = []; }
        const st = P.postureStats(list);
        const sev = st.bySeverity || {};
        const crit = sev.critical || 0, high = sev.high || 0, open = crit + high;
        const postEl = document.getElementById("tb-posture");
        const postSep = document.getElementById("tb-posture-sep");
        if (postEl) {
          if (st.totalEntities === 0) { postEl.hidden = true; if (postSep) postSep.hidden = true; }
          else {
            postEl.hidden = false; if (postSep) postSep.hidden = false;
            postEl.innerHTML = "<b>" + open + "</b>&nbsp;open &middot; <b>" + st.totalEntities + "</b> tracked";
            postEl.title = open + " open findings (critical " + crit + ", high " + high + ") across " + st.totalEntities + " real entities in your security graph";
          }
        }
        const alerts = P.realEntities(list)
          .filter((e) => e.severity === "critical" || e.severity === "high")
          .sort((a, b) => String(b.updatedAt || "").localeCompare(String(a.updatedAt || "")))
          .slice(0, 8);
        const listEl = document.getElementById("tbAlertList");
        const badge = document.getElementById("tbAlertBadge");
        if (listEl) {
          if (!alerts.length) {
            listEl.innerHTML = '<div class="tb-alert-empty">No open high-severity findings. Run a scan or open an investigation to populate this.</div>';
          } else {
            listEl.innerHTML = alerts.map((e) => {
              const cls = e.severity === "critical" ? "high" : "med";
              const lbl = e.severity === "critical" ? "CRIT" : "HIGH";
              const when = tbRelTime(e.updatedAt);
              return '<button class="tb-alert" data-goto="secgraph"><span class="tb-alert-sev ' + cls + '">' + lbl + "</span><div><b>" + esc(e.name || e.type) + "</b><span>" + esc(e.type) + (when ? " &middot; " + when : "") + "</span></div></button>";
            }).join("");
            listEl.querySelectorAll("[data-goto]").forEach((b) => b.addEventListener("click", () => { closeTbPops(); show(b.dataset.goto); }));
          }
        }
        if (badge) { if (alerts.length) { badge.textContent = String(alerts.length); badge.style.display = ""; } else { badge.style.display = "none"; } }
      }).catch(() => {});
    };
    refreshTbOps();
    try { if (window._tbOpsHandler) ["secgraph:entity:created", "secgraph:entity:updated", "secgraph:entity:deleted"].forEach((n) => document.removeEventListener(n, window._tbOpsHandler)); } catch (_) {}
    let tbOpsT = 0;
    window._tbOpsHandler = () => { clearTimeout(tbOpsT); tbOpsT = setTimeout(refreshTbOps, 400); };
    ["secgraph:entity:created", "secgraph:entity:updated", "secgraph:entity:deleted"].forEach((n) => document.addEventListener(n, window._tbOpsHandler));
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
    // No auto-probe of localhost: the web build is cloud-only, so we don't poll
    // 127.0.0.1 for a local CLI on every load (it only spammed the console with
    // connection-refused errors). The CLI dot still connects on demand via click.
    mod.bridge.addEventListener('connect', function() { if (dot) { dot.style.background = '#22c55e'; dot.title = 'CLI connected: ' + mod.bridge.hostname; } });
    mod.bridge.addEventListener('disconnect', function() { if (dot) { dot.style.background = '#71717a'; dot.title = 'CLI disconnected'; } });
  }).catch(function() {});

  // ---- breadcrumb navigation ----
  document.getElementById("crumbs").onclick = (e) => { const b = e.target.closest("[data-crumb]"); if (b) show(b.dataset.crumb); };

  // ---- save the exact frame (Ctrl+S) so you resume where you left off ----
  const FRAME = "sw_frame";
  const toast = (msg, ms) => { const t = document.createElement("div"); t.className = "toast"; t.textContent = msg; document.body.appendChild(t); requestAnimationFrame(() => t.classList.add("in")); setTimeout(() => { t.classList.remove("in"); setTimeout(() => t.remove(), 300); }, ms || 2600); };
  const editableFields = () => [...main.querySelectorAll("input,textarea,select")].filter((el) => el.id && el.type !== "password" && el.type !== "file");
  // only fields the user edited count: a tool's defaults (thresholds, a checkbox's "on") are not
  // unsaved work, and counting them made every reload or close of the Deck ask "Leave site?"
  const edited = new WeakSet();
  main.addEventListener("input", (e) => { if (e.isTrusted) edited.add(e.target); });
  const hasTyped = () => editableFields().some((el) => edited.has(el) && el.tagName !== "SELECT" && el.type !== "checkbox" && el.type !== "radio" && el.value && el.value.trim());
  function saveFrame() {
    const fields = {}; editableFields().forEach((el) => { if (el.value) fields[el.id] = el.value; });
    try { localStorage.setItem(FRAME, JSON.stringify({ sec: curSec, fields, ts: Date.now() })); } catch (_) {}
    toast("Frame saved — you'll resume right here.");
  }
  _appH.saveFrame = saveFrame; _appH.hasTyped = hasTyped;

  // ---- restore last frame (section + typed text), else last section ----
  let frame = null; try { frame = JSON.parse(localStorage.getItem(FRAME)); } catch (_) {}
  let lastSec; try { lastSec = localStorage.getItem("sw_last_sec"); } catch (_) {}
  const pathSec = location.pathname !== "/" && location.pathname !== CONSOLE_BASE ? pathToSec(location.pathname) : null;
  const HEAVY = new Set(["hydra","aegis","vanguard","phantom","citadel","oracle","spectre","crucible","navarch","beta"]);
  const startSec = pathSec || (frame && frame.sec) || lastSec || "home";
  // A restored/deep-linked `tool-<id>` sec must still exist in the manifest; mini-tools
  // get removed (e.g. the 2026-10 off-theme cull), and a stale sw_last_sec / bookmark
  // would otherwise cold-start straight into a bare "Tool not found." screen. Fall back
  // to home when the id is gone.
  const validToolSec = !startSec || startSec.indexOf("tool-") !== 0 || _MINI_TOOLS.some((t) => t.id === startSec.slice(5));
  // HEAVY dashboards are skipped on a cold restore (last-section / saved-frame) to avoid
  // loading heavy WebGL unprompted — but an explicit deep-link (pathSec, e.g. the app embed
  // opening /citadel) is a direct request for that tool, so honor it.
  const okSec = startSec && startSec !== "setup" && validToolSec && !RETIRED.has(startSec) && (startSec !== "admin" || isOwner) && (pathSec === startSec || !HEAVY.has(startSec));
  // The console is the signed-in UI; the Deck is an owner-only command center launched
  // from Admin (admin.js).
  // Inside the Deck a frame is one tool: falling back to the console home there shows the old
  // console dashboard under that tool's title, so say the page is unavailable instead.
  if (!okSec && document.documentElement.hasAttribute("data-embed") && startSec !== "home") main.innerHTML = '<div class="panel" style="margin:24px"><h2 class="pg-h2">Not available here</h2><p class="muted">This page could not be opened for this account. Reload the Deck and try again.</p></div>';
  else show(okSec ? startSec : "home");
  if (frame && frame.fields && frame.sec === startSec) {
    setTimeout(() => { Object.entries(frame.fields).forEach(([id, v]) => { const el = main.querySelector("#" + (window.CSS && CSS.escape ? CSS.escape(id) : id)); if (el && v != null) { el.value = v; el.dispatchEvent(new Event("input", { bubbles: true })); el.dispatchEvent(new Event("change", { bubbles: true })); } }); }, 120);
  }
  if (!tourDone() && !document.documentElement.hasAttribute("data-embed")) setTimeout(() => startTour(tourSteps(isOwner)), 450);
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
  const sections = [["home", "Dashboard"], ["investigation", "Investigation Workspace"], ["secgraph", "Security Graph"], ["ai", "AI Chat"], ["math", "Quelvra Math"], ["tools", "Scanner Suite"], ["saved", "Saved"], ["payloads", "Payload Forge"], ["exploitdb", "Exploit Search Launcher"], ["ghdb", "Google Dorking"], ["targets", "Practice Targets"], ["cheats", "Cheat Sheets"], ["snippets", "Snippet Vault"], ["refs", "Reference Library"], ["privatecloud", "Private Cloud"], ["report", "Report Generator"], ["learn", "Learn Hub"], ["setup", "Local Setup"], ["coder", "Nexus Agent"], ["downloads", "Darknode OS"], ["dlguide", "Download Guide"], ["api", "API"], ["docs", "Docs"], ["education", "Education"], ["settings", "Settings"], ["admin", "Admin"], ["vanguard", "VANGUARD"], ["hydra", "HYDRA Engine"], ["aegis", "AEGIS Ops Center"], ["phantom", "PHANTOM"], ["citadel", "CITADEL"], ["oracle", "ORACLE"], ["spectre", "SPECTRE"], ["crucible", "CRUCIBLE"], ["navarch", "NAVARCH"], ["beta", "Beta Lab"], ["secdash", "Security Dashboard"], ["cspevaluator", "CSP Evaluator"], ["wayback", "Wayback Machine"], ["urldissect", "URL Dissector"], ["favicon", "Favicon Hasher"], ["cyberrange", "Cyber Range"], ["netmap", "Network Mapper"], ["exploitdev", "Security Research Lab"], ["cracklab", "Password Security Lab"], ["osint", "OSINT Dashboard"], ["crosswalk", "GenAI Crosswalk"], ["cyberbriefing", "Cyber Briefing"], ["incidentcost", "Incident Cost Calculator"], ["fedcompliance", "Federal Compliance"], ["adversaryplaybook", "Adversary Playbook"], ["emailheader", "Email Header Analyzer"], ["reconplanner", "Recon Planner"], ["apifuzzer", "API Fuzzer"], ["privesc", "Privilege Analysis"], ["reverseshell", "Remote Access Testing"], ["xsslab", "Web Security Lab"], ["cvetimeline", "CVE Timeline"], ["dataviz", "Data Visualization"], ["forensicstoolkit", "Forensics Toolkit"], ["hashsuite", "Hash Suite"], ["networktools", "Network Tools"], ["packetanalyzer", "Packet Analyzer"], ["payloadgen", "Test Script Generator"], ["vulndb", "Vulnerability DB"], ["asnexplorer", "ASN Explorer"], ["breachlookup", "Breach Lookup"], ["corstester", "CORS Tester"], ["cvesearch", "CVE Search"], ["darknetradar", "Darknet Radar"], ["headeranalyzer", "Header Analyzer"], ["identitymatrix", "Identity Matrix"], ["networkscanner", "Network Scanner"], ["sslinspector", "SSL Inspector"], ["techfingerprint", "Tech Fingerprint"], ["websockettester", "WebSocket Tester"]].filter(([sec]) => !RETIRED.has(sec));
  const actions = [
    { type: "action", id: "cycle-style", name: "Toggle light / dark", desc: "Switch the console between light and dark", action: cycleStyle },
    { type: "action", id: "toggle-dark", name: "Toggle light / dark", desc: "Switch light and dark mode", action: () => { const cur = document.documentElement.getAttribute("data-theme") || "dark"; applyTheme(cur === "dark" ? "light" : "dark"); } },
    { type: "action", id: "toggle-crt", name: "Toggle CRT effect", desc: "Turn scanline overlay on or off", action: () => applyCrt(!crtOn()) },
    { type: "action", id: "copy-url", name: "Copy current URL", desc: "Copy page link to clipboard", action: () => { navigator.clipboard.writeText(location.href).then(() => showToast("URL copied", "success")).catch(() => {}); } },
    { type: "action", id: "replay-tour", name: "Replay walkthrough", desc: "Start the guided tour again", action: () => startTour(tourSteps(_isAdmin)) },
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
    // inside a Deck tool frame the shortcut belongs to the Deck's search, not this frame's palette
    if (document.body.classList.contains("dn-embed")) { if (window.dnBridge && window.dnBridge.palette) window.dnBridge.palette(); return; }
    const ex = document.getElementById("cmdk"); if (ex) ex.remove(); else openPalette();
  }
});
// Open-only palette signal (mobile search, etc.) — never toggles an open one.
document.addEventListener("dn:open-palette", () => { if (document.body.classList.contains("app") && !document.getElementById("cmdk")) openPalette(); });

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

// Access policy: the site is OPEN to everyone by default. The owner can block
// specific emails from the Admin console (a ban-list); only those are denied.
// The owner (admin claim) is never affected.
async function accessAllowed(user) {
  if (_isAdmin) return true;
  try {
    const { getWhitelist } = await import("/js/admin.js?v=20261030c");
    const cfg = await getWhitelist();
    const banned = ((cfg && cfg.banned) || []).map((e) => String(e).toLowerCase());
    if (banned.includes((user.email || "").toLowerCase())) return false;
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
// No setPersistence() here: the default (IndexedDB) already keeps users signed in.
// Calling it on every load migrated the session localStorage<->IndexedDB, and every
// embedded tool iframe (/<sec>?embed=1) is a full load — the resulting `storage`
// events flipped the TOP window's auth state null->user, flashing the landing page
// and re-mounting the Deck on a stale route (the "bounces back to Admin" bug).
getRedirectResult(auth).then((result) => {
  if (result && result.user) {
    try { sessionStorage.setItem("sw_fresh_signin", "1"); } catch (_) {}
  }
}).catch(() => {});
onAuthStateChanged(auth, async (user) => {
  // Idempotent: the same signed-in user while the app is up is a no-op (no re-render),
  // and a transient null (a cross-window storage sync) is re-checked before tearing
  // the app down to the landing page.
  if (user && _appUid === user.uid) return;
  if (!user && _appUid) {
    await new Promise((r) => setTimeout(r, 300));
    if (auth.currentUser || _appGuest) return;
    _appUid = null;
  }
  if (window.__boot) window.__boot.set(70);
  // Scope every client-side credential to this account (see user-keys.js): the
  // uid must be set before any key is read so one user never reads another's
  // keys on a shared browser. Scrub legacy un-namespaced keys once per load.
  try { window.__dnUid = user ? user.uid : null; } catch (_) {}
  if (user && !document.documentElement.hasAttribute("data-embed")) _claimWorkspacePointer(user.uid);
  try { if (!window.__dnScrubbed && window.dnKeys) { window.dnKeys.scrubLegacy(); window.__dnScrubbed = true; } } catch (_) {}
  // license verification
  const _hn = [0x64,0x61,0x72,0x6b,0x6e,0x6f,0x64,0x65,0x2e,0x61,0x69].map(c=>String.fromCharCode(c)).join("");
  if(location.hostname!==_hn&&location.hostname!=="www."+_hn&&location.hostname!=="localhost"&&location.hostname!=="127.0.0.1"){document.body.innerHTML="";return}
  let fresh = false; try { fresh = sessionStorage.getItem("sw_fresh_signin") === "1"; if (fresh) sessionStorage.removeItem("sw_fresh_signin"); } catch (_) {}
  if (!user) {
    // Embedded tool frame (/<sec>?embed=1 inside the Deck): the parent tab is signed in,
    // but this child frame's own Firebase persistence can resolve to null (the default
    // IndexedDB session is not reliably inherited into an iframe). Adopt the parent tab's
    // live user object — same-origin, so its methods (getIdToken, etc.) work here — so the
    // tool renders instead of the public landing page on every Deck tab.
    try {
      if (document.documentElement.hasAttribute("data-embed") && window.parent && window.parent !== window) {
        const pu = window.parent.__dnCurrentUser;
        if (pu && pu.uid) {
          try { _isAdmin = !!window.parent.__dnAdmin; } catch (_) { _isAdmin = false; }
          try { window.__dnAdmin = _isAdmin; window.__dnUid = pu.uid; } catch (_) {}
          renderApp(pu); return;
        }
      }
    } catch (_) {}
    // Only the top window owns dn_gate; an embedded frame's transient null must not wipe it.
    try { if (!document.documentElement.hasAttribute("data-embed")) sessionStorage.removeItem("dn_gate"); } catch (_) {}
    // Desktop-app embed / guest deep-link: the Darknode app embeds tools in a webview and
    // cannot sign in. A `?app=1` param (persisted to sessionStorage so in-console navigation
    // keeps it) enters the same public Test Mode the sign-in page offers and routes straight
    // to the requested tool. No new exposure — Test Mode is already a public no-account path.
    let guest = false;
    try { guest = new URLSearchParams(location.search).get("app") === "1" || sessionStorage.getItem("dn_guest") === "1"; } catch (_) {}
    if (guest) {
      try { sessionStorage.setItem("dn_guest", "1"); } catch (_) {}
      const guestUid = _guestUid("app-guest");
      try { window.__dnUid = guestUid; } catch (_) {}
      _claimWorkspacePointer(guestUid);
      renderApp({ uid: guestUid, email: "test@darknode.ai", displayName: "Guest", providerData: [{ providerId: "test" }], metadata: { creationTime: new Date().toISOString() }, refreshToken: "", getIdToken: () => Promise.resolve("") });
      return;
    }
    // The desktop app has no marketing landing: straight to sign-in (which keeps the
    // no-account Test Mode entry for local tools).
    if (isDesktop()) { dismissBoot(); renderAuth("signin"); return; }
    showLanding(); return;
  }
  // An embedded tool (/<sec>?embed=1 inside the Deck) shares this tab's sessionStorage with
  // the top window, which already passed every gate below for this uid. Re-running them
  // cost several Firestore round trips before each tool could paint.
  let gated = false; try { gated = document.documentElement.hasAttribute("data-embed") && sessionStorage.getItem("dn_gate") === user.uid; } catch (_) {}
  // the Deck (top window) already resolved the claim: a frame whose own token check comes back
  // false or late must not drop the owner to the console home inside the Deck's Admin window
  if (gated) { _isAdmin = (await isAdminUser(user)) || _parentAdmin(); try { window.__dnAdmin = _isAdmin; } catch (_) {} renderApp(user); return; }
  // Email/password users must verify — a 6-digit code when EmailJS is configured, else the Firebase link.
  const providerEmailPw = user.providerData.some((p) => p.providerId === "password");
  if (providerEmailPw) {
    if (emailConfigured()) {
      const udoc = await getDoc(doc(db, "users", user.uid)).catch(() => null);
      if (!(udoc && udoc.exists() && udoc.data().codeVerified)) { renderCodeVerify(user); return; }
    } else if (!user.emailVerified) { renderVerify(user); return; }
  }
  // Resolve the super-admin claim once per session from the signed ID token.
  _isAdmin = (await isAdminUser(user)) || _parentAdmin();
  try { window.__dnAdmin = _isAdmin; } catch (_) {}
  if (!(await accessAllowed(user))) {
    showToast("Your account has been suspended. Contact the owner for access.", "error", 6000);
    await signOut(auth); return;
  }
  await ensureUserDoc(user);
  checkLoginDevice(user);

  // TOS acceptance check — must agree before using the platform
  const udoc = await getDoc(doc(db, "users", user.uid)).catch(() => null);
  // Terms are versioned: bumping TOS_VERSION asks every account to accept the new text,
  // including accounts that accepted an earlier version (they also see what changed).
  const TOS_VERSION = "2026-10-29";
  const ud = udoc && udoc.exists() ? udoc.data() : {};
  const tosAccepted = !!ud.tosAccepted && ud.tosVersion === TOS_VERSION;
  const tosReturning = !!ud.tosAccepted && !tosAccepted;
  if (!tosAccepted) {
    view.innerHTML = `
      <div style="max-width:640px;margin:60px auto;padding:24px;font-family:var(--font-body,system-ui)">
        <h1 style="font-size:1.6rem;margin-bottom:8px">${tosReturning ? "We updated our Terms of Service" : "Terms of Service"}</h1>
        <p style="color:var(--mut,#888);margin-bottom:20px">${tosReturning ? "Please review the changes and accept to keep using Darknode." : "Please read and accept before continuing."}</p>
        ${tosReturning ? `<div style="border:1px solid var(--line,#333);border-left:4px solid var(--acc,#2552c6);padding:14px 18px;margin-bottom:16px;border-radius:4px;font-size:.88rem;line-height:1.6">
          <strong>What changed (October 29, 2026)</strong>
          <ul style="margin:8px 0 0;padding-left:20px">
            <li>Deck Integrations: a security integration counts as connected only after a live test of your key. Lookups for those providers go through Darknode's relay, which uses your key for that one request and does not store it or the result.</li>
            <li>The built-in assistant can run lookups on your connected integrations; it asks before each call unless you choose Always allow.</li>
          </ul></div>` : ""}
        <div style="background:var(--card,#1a1a1a);border:1px solid var(--line,#333);padding:20px;max-height:400px;overflow-y:auto;font-size:.85rem;line-height:1.7;margin-bottom:20px;border-radius:4px" id="tosBox">
          <h3>Darknode Terms of Service</h3>
          <p><strong>Last updated:</strong> October 29, 2026</p>
          <p>By using Darknode ("the Platform"), including darknode.ai, the Darknode command center, the Darknode Deck and its Personal and Organization spaces, the code, cloud, dependency and web-exposure analysis engines, the Darknode CLI, the Nexus agent, Darknode OS, the API and MCP server, and all associated tools, you (and, where you act for an organization, that organization) agree to these terms. If you do not agree, do not use the Platform.</p>

          <h4>1. Authorized Use Only</h4>
          <p>Darknode is a platform for <strong>authorized security operations, vulnerability assessment, compliance review, and legitimate security research</strong> — used by and for organizations on their own code, systems, and data, or on those of clients who have authorized the work in writing. Its tools are designed to help you find and fix problems in environments you are permitted to assess, not to attack systems you are not.</p>
          <p><strong>You MUST have explicit written authorization before testing any system, network, or application you do not own.</strong> This includes but is not limited to: penetration tests, vulnerability scans, social engineering assessments, wireless audits, and red team engagements. Unauthorized access to computer systems is a criminal offense under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and equivalent laws worldwide.</p>

          <h4>2. No Guarantee of Security, Detection, or Compliance</h4>
          <p>Darknode's tools perform <strong>automated analysis</strong> of code, dependencies, cloud configuration, systems and records. They identify <em>some</em> potential issues; they <strong>do not and cannot detect all vulnerabilities, misconfigurations, weaknesses, errors, or weaknesses</strong>, and may produce both false positives and false negatives.</p>
          <p><strong>A clean, passing, or "no findings" result is NOT a certification, warranty, or representation that your code, systems, or data are secure, correct, compliant, or free of defects.</strong> Severity scores, risk ratings and compliance or framework mappings are informational aids only and are not a certification of compliance with any law, standard, or framework. The tools are an aid to — never a substitute for — qualified human review, professional penetration testing, and independent audit. <strong>You remain solely responsible for the security, correctness, and compliance of your own code, systems, and data, and for any decision to act or not act on any result.</strong></p>

          <h4>3. No Professional Advice</h4>
          <p>Nothing Darknode provides — including scan results, findings, scores, compliance mappings, reports, or recommendations — constitutes legal, accounting, tax, financial, audit, regulatory, or other professional advice, or a certification of compliance. You are responsible for obtaining independent professional advice before relying on any output.</p>

          <h4>4. Disclaimer of Warranties</h4>
          <p>The Platform is provided <strong>"as is" and "as available"</strong> without warranties of any kind, express, implied, or statutory, including but not limited to merchantability, fitness for a particular purpose, title, non-infringement, accuracy, completeness, reliability, security, or availability. Darknode does not warrant that the Platform will be uninterrupted or error-free, that defects will be corrected, or that results will be accurate or complete.</p>

          <h4>5. Limitation of Liability</h4>
          <p><strong>To the maximum extent permitted by applicable law, Darknode, its owners, creators, contributors, affiliates, and suppliers shall NOT be liable for any indirect, incidental, special, consequential, exemplary, or punitive damages, or for any loss of profits, revenue, data, goodwill, or business, business interruption, security breach, or third-party claim, arising out of or relating to the Platform or any result it produces — even if advised of the possibility of such damages, and regardless of the legal theory (contract, tort, negligence, strict liability, statute, or otherwise).</strong> This includes, without limitation, damages arising from: any undetected vulnerability, misconfiguration, or error; reliance on, or any action or inaction based on, any finding or the absence of a finding; any security incident, breach, or loss affecting your systems or data; any business decision; and the output or behavior of any automated tool or AI feature.</p>
          <p><strong>In all cases, Darknode's total aggregate liability for all claims arising out of or relating to the Platform shall not exceed the greater of (a) the total fees you actually paid to Darknode for the Platform in the twelve (12) months immediately before the event giving rise to the claim, or (b) one hundred U.S. dollars (US$100).</strong> Some jurisdictions do not allow certain exclusions or limitations; in those jurisdictions the above applies to the maximum extent permitted, and nothing here limits liability that cannot lawfully be limited.</p>
          <p><strong>Indemnification.</strong> You agree to defend, indemnify, and hold harmless Darknode, its owners, creators, contributors, and affiliates from and against any and all claims, liabilities, damages, losses, and expenses (including reasonable legal fees) arising out of or related to: your use of the Platform; your reliance on any result; your code, systems, or data; or your violation of these terms or of any law or third-party right.</p>

          <h4>6. Self-Hosted and On-Premises Use</h4>
          <p>Where you install or run Darknode in your own browser, infrastructure, or environment (including self-hosted, on-premises, or air-gapped deployments), <strong>you alone control and are responsible for that deployment</strong> — its configuration, access controls, updates, and all data processed within it. Darknode has no access to, and accepts no responsibility or liability for, your self-hosted instance, its security, or the data you process with it. Darknode does not receive, store, or have access to the source code, systems, or data you analyze client-side or in your own environment.</p>

          <h4>7. Real Security Data</h4>
          <p>Darknode provides real-world security intelligence including CVE databases, exploit references, MITRE ATT&amp;CK mappings, APT group profiles, vulnerability data, and penetration testing methodologies. This information is sourced from publicly available databases and is provided for <strong>defensive security, education, and authorized testing purposes only</strong>. Darknode does not create exploits — it references publicly known vulnerabilities to help defenders understand and mitigate threats.</p>

          <h4>8. AI Features</h4>
          <p>The built-in web assistant sends your messages through Darknode's edge proxy to a third-party model provider (currently Google Gemini) and returns the answer. Darknode does not log or store those prompts or responses; the provider processes them under its own terms. In Nexus, the CLI, and the desktop app you choose the engine: local models (such as Ollama) keep everything on your machine, and cloud engines use your own account or API key with that provider. When you connect a security integration in the Deck, the assistant can run lookups on it (for example an IP, domain, hash or CVE); it shows each call and asks before sending it, unless you choose Always allow for that lookup. AI output can be wrong; review it before acting on it. You are responsible for your own API usage and costs and for any actions taken by AI agents you run.</p>

          <h4>9. Plans and Feature Availability</h4>
          <p>Which tools and spaces you can use depends on your plan. Features outside your plan are not shown. We may move features between plans, and features marked as coming soon may change before release.</p>

          <h4>10. User Responsibility</h4>
          <p><strong>You are solely and entirely responsible for:</strong></p>
          <ul>
            <li>Obtaining proper written authorization before any security testing</li>
            <li>Complying with all applicable local, state, national, and international laws</li>
            <li>Any code, payloads, exploits, or tools you generate, modify, or execute</li>
            <li>Securing your own API keys, credentials, and sensitive data</li>
            <li>Understanding the legal implications of your actions in your jurisdiction</li>
            <li>Any damage caused to systems, networks, or data during authorized testing</li>
          </ul>

          <h4>11. Prohibited Activities</h4>
          <p>You agree NOT to use Darknode for:</p>
          <ul>
            <li>Attacking, scanning, or probing systems without explicit written authorization, including with the web-security toolkit</li>
            <li>Creating, distributing, or deploying malware for malicious purposes</li>
            <li>Conducting denial-of-service attacks against unauthorized targets</li>
            <li>Stealing, selling, or exposing personal data or credentials</li>
            <li>Reverse-engineering, reselling, or redistributing the Platform or its source code in violation of the license</li>
            <li>Any activity that violates applicable cybercrime laws</li>
          </ul>
          <p>Violation of these terms may result in immediate account termination and reporting to appropriate authorities.</p>

          <h4>12. Intellectual Property</h4>
          <p>The Platform, its design, code, branding, documentation, and all related assets are the intellectual property of Darknode and its contributors, protected by copyright and trademark law. You may not copy, modify, distribute, or create derivative works from the Platform except as expressly permitted by the applicable open-source license.</p>
          <p><strong>Your content:</strong> You retain all rights to data, reports, scan results, and other outputs you create using the Platform. By using collaborative or cloud features, you grant Darknode a limited, non-exclusive license to process that content solely to provide the service.</p>
          <p>The Platform incorporates open-source components distributed under their respective licenses. A list is available in the project repository.</p>

          <h4>13. Intended Users</h4>
          <p>Darknode is intended for individuals, organizations, and security, engineering, and compliance professionals operating on systems, code, and data they own or are authorized to assess. Training, lab, and simulation features are provided for skills development within that authorized context. We do not endorse, encourage, or condone any unlawful activity.</p>

          <h4>14. Data &amp; Privacy</h4>
          <p>We store minimal user data in Firebase (Google Cloud):</p>
          <ul>
            <li><strong>What we collect:</strong> email address, display name, profile photo URL, login timestamps, and ToS acceptance records.</li>
            <li><strong>Legal basis:</strong> legitimate interest (providing the service) and your consent (accepting these terms).</li>
            <li><strong>Data retention:</strong> your data is retained while your account is active. After deletion, data is purged within 30 days, except where retention is required by law.</li>
            <li><strong>Integration relay:</strong> Deck integrations with providers that do not accept calls from a browser (such as VirusTotal, Shodan or AbuseIPDB) send your API key and the value you look up through Darknode's edge relay to that provider only. The relay uses the key for that one request and does not log or store the key, the value or the result; the provider processes them under its own terms. Keys stay in your browser, under your account.</li>
            <li><strong>No selling or sharing:</strong> we do not sell, rent, or share your personal data with third parties for marketing purposes.</li>
            <li><strong>Cookies:</strong> we use only essential cookies and localStorage for session management and user preferences. We do not use tracking cookies or third-party analytics.</li>
            <li><strong>International transfers:</strong> data is processed and stored in Google Cloud data centers. By using the Platform, you consent to transfer of data to servers that may be outside your country of residence.</li>
          </ul>
          <p><strong>Your rights (GDPR, CCPA, and similar laws):</strong> depending on your jurisdiction, you may have the right to access, correct, delete, or export your personal data, restrict processing, object to processing, or withdraw consent. To exercise any of these rights, email <strong>contact@darknode.ai</strong>. We will respond within 30 days. You also have the right to lodge a complaint with your local data protection authority.</p>

          <h4>15. Account Termination</h4>
          <p><strong>By you:</strong> you may stop using the Platform and request account deletion at any time by emailing contact@darknode.ai. Upon deletion, your data will be removed in accordance with Section 14.</p>
          <p><strong>By us:</strong> we may suspend or terminate your account immediately, without prior notice, if we reasonably believe you have violated these terms. We may also discontinue the Platform or any feature at any time with reasonable notice.</p>

          <h4>16. Paid Plans &amp; Pricing</h4>
          <p>The core Platform is free. Paid plans (when available) unlock additional professional features. Prices are listed on the pricing page and may change with at least <strong>30 days' notice</strong> before your next billing cycle. Refunds are handled on a case-by-case basis. Cancellation takes effect at the end of the current billing period. You are responsible for any applicable taxes.</p>

          <h4>17. Service Availability</h4>
          <p>We aim for high availability but do not guarantee uninterrupted access. We are not liable for downtime caused by events beyond our reasonable control, including but not limited to: natural disasters, internet outages, hosting provider failures, government actions, cyberattacks, or other force majeure events. Scheduled maintenance will be announced when feasible.</p>

          <h4>18. Dispute Resolution</h4>
          <p>If a dispute arises, you agree to first attempt resolution by emailing contact@darknode.ai. If we cannot resolve it within 60 days, either party may pursue binding arbitration under the rules of a mutually agreed arbitration provider, conducted in English. <strong>You agree to resolve disputes on an individual basis and waive the right to participate in a class action.</strong> Nothing in this section prevents either party from seeking injunctive relief in court for intellectual property violations or imminent harm.</p>

          <h4>19. Governing Law</h4>
          <p>These terms are governed by and construed in accordance with the laws of the State of California, United States, without regard to conflict-of-law principles. Any legal proceedings not subject to arbitration shall be brought in the state or federal courts located in California.</p>

          <h4>20. Changes to These Terms</h4>
          <p>We may update these terms from time to time. When we make material changes, we will notify you by email or by posting a notice on the Platform at least <strong>14 days before</strong> the changes take effect. If you continue to use the Platform after the effective date, you accept the updated terms. If you disagree, you may close your account before the changes take effect.</p>

          <h4>21. General Provisions</h4>
          <ul>
            <li><strong>Entire agreement:</strong> these terms, together with any referenced policies, constitute the entire agreement between you and Darknode regarding the Platform and supersede all prior agreements.</li>
            <li><strong>Severability:</strong> if any provision of these terms is found to be unenforceable or invalid, that provision will be limited or eliminated to the minimum extent necessary, and the remaining provisions will remain in full force.</li>
            <li><strong>No waiver:</strong> failure to enforce any right or provision does not constitute a waiver of that right or provision.</li>
            <li><strong>Assignment:</strong> you may not assign these terms without our written consent. We may assign our rights and obligations without restriction.</li>
          </ul>

          <h4>Contact</h4>
          <p>Questions about these terms? Email <strong>contact@darknode.ai</strong>.</p>

          <!-- The pointing-up emoji below is the one emoji the owner explicitly asked to keep here (points up at the terms); no other emojis in the UI. -->
          <p style="margin-top:18px;opacity:.8;font-style:italic">Our lawyers made us say all of that. <span aria-hidden="true">&#9757;&#65039;</span> They were, regrettably, correct. The short version, which changes none of the legally binding version above: the tools help, they are not magic, nothing here is a guarantee, and you are responsible for your own systems, data, and decisions. Read a real audit before you bet the company on anything.</p>

          <p style="margin-top:20px"><strong>By clicking "I Agree" below, you acknowledge that you have read, understood, and agree to be bound by these terms.</strong></p>
        </div>
        <div style="display:flex;gap:12px;align-items:center">
          <button class="btn lg" id="tosAgree" style="min-width:140px">I Agree</button>
          <button class="btn lg ghost" id="tosDecline">Decline &amp; Sign Out</button>
        </div>
      </div>`;
    document.getElementById("tosAgree").onclick = async () => {
      await setDoc(doc(db, "users", user.uid), { tosAccepted: true, tosVersion: TOS_VERSION, tosAcceptedAt: serverTimestamp() }, { merge: true });
      const enter = () => { try { sessionStorage.setItem("dn_gate", user.uid); } catch (_) {} renderApp(user); loadAnnouncement(); };
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
  const enter = () => { try { sessionStorage.setItem("dn_gate", user.uid); } catch (_) {} renderApp(user); loadAnnouncement(); };
  if (fresh) playAccessGranted(user.displayName || ((user.email || "").split("@")[0]), enter);
  else enter();
});
