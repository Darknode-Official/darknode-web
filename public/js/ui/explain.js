// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved.
// Hover explainers: rest the pointer (or keyboard focus) on a meaningful element for
// two seconds and a card says what it is, how it is worked out and where the data
// comes from. Only elements that resolve to an explanation ever trigger, so blank
// space and decoration stay quiet.
//
//   attachExplain(root, { resolve, delay }) -> detach()
//     root    : element whose subtree is watched (delegated listeners)
//     resolve : (el) => { title, body, src? } | null  for elements without data-explain
//   <el data-explain="kpi.exposure">  looks the id up in EXPLAIN.
//
// The card is appended to <body> with position:fixed, outside any zoomed container, so
// getBoundingClientRect() coordinates can be used as-is.

export const EXPLAIN_DELAY = 2000;
const LS_OFF = "dn_explain";

export const EXPLAIN = {
  // ---- Plans ----
  "plan.free": { title: "Free", body: "The full browser toolbox at no cost, for solo practitioners and evaluation. Data stays local to this browser. This is your current tier.", src: "Preview pricing — checkout is not live yet." },
  "plan.pro": { title: "Pro", body: "For professionals who need saved history, unlimited exports, cloud sync and priority access to Darknode AI.", src: "Preview pricing — checkout is not live yet." },
  "plan.team": { title: "Team", body: "Shared workspaces with roles, server-enforced Treasury Vault approvals and audit, integrations and Google SSO.", src: "Preview pricing — checkout is not live yet." },
  "plan.enterprise": { title: "Enterprise", body: "Self-hosted or private deployment, SAML SSO and SCIM, a compliance pack with DPA, and a dedicated support SLA. Priced per engagement.", src: "Contact sales — mailto link." },
  // ---- Overview KPIs ----
  "kpi.hot": { title: "Open critical and high", body: "How many critical or high severity findings in your security graph are still open (not resolved or closed). These drive most of the exposure score. Shows a dash until you have real findings.", src: "Your security graph. Sample and simulated data is excluded." },
  "kpi.exposure": { title: "Your exposure", body: "How exposed this workspace looks, from 0 to 100 (higher is worse). 65% comes from open critical and high findings in your security graph (25 or more counts as the maximum), 35% from how few integrations are connected. Shows a dash until you have real findings.", src: "Your security graph and integrations. Sample and simulated data is excluded. An indicator, not an audit." },
  "kpi.climate": { title: "Threat climate", body: "Global vulnerability pressure, the same for every customer: 60% is the share of the newest CVEs rated critical or high, 40% is the size of the CISA Known Exploited catalog. It does not describe your systems.", src: "NVD (latest 30 CVEs) and CISA KEV, fetched live." },
  "kpi.tools": { title: "Tools available", body: "The number of tools in the Darknode catalog you can open from the Tool Library or Ctrl K search.", src: "The built-in tool catalog." },
  "kpi.graph": { title: "Graph entities", body: "Assets, findings, indicators and other records your tools have written to the security graph. Simulated and sample entities are not counted.", src: "The security graph in this browser." },
  "kpi.cve": { title: "New CVEs", body: "Vulnerabilities published to the National Vulnerability Database in the last 7 days.", src: "NVD, fetched live." },
  "kpi.kev": { title: "Known exploited (KEV)", body: "Vulnerabilities that CISA has confirmed are being exploited in the wild. If one affects you, patch it first.", src: "CISA Known Exploited Vulnerabilities catalog, fetched live." },

  // ---- Navigation scenes ----
  "scene.overview": { title: "Security Overview", body: "Your home page: exposure, global threat climate, connected integrations, pinned tools and recent activity in one place." },
  "scene.plans": { title: "Plans & billing", body: "Compare the Darknode plans — Free, Pro, Team and Enterprise — and what each includes. Preview pricing; checkout is not live yet.", src: "Preview pricing." },
  "scene.surface": { title: "Attack Surface", body: "Enter a domain to map what the internet can see: DNS records, subdomains from certificate logs, mail security and web headers.", src: "Live public DNS and certificate-transparency lookups." },
  "scene.cloud": { title: "Cloud Posture", body: "Paste IAM policies, bucket policies, security groups, Kubernetes manifests or Dockerfiles and get misconfigurations with fixes. Runs in your browser." },
  "scene.threat": { title: "Threats & Vulnerabilities", body: "The newest CVEs with severity, CISA known-exploited status and EPSS exploit probability, ranked so you can see what to patch first.", src: "NVD, CISA KEV and FIRST EPSS, fetched live." },
  "scene.invest": { title: "Investigations", body: "Browse and filter every entity in your security graph, with severity, status and relationships. Sample data is hidden unless you include it." },
  "scene.reports": { title: "Reports", body: "Generate branded security reports from your own graph data: executive summary, findings register and attack-surface summary. Built in your browser; sample data is excluded and nothing is uploaded." },
  "scene.activity": { title: "Activity", body: "A time-ordered stream of what happened: tool results, graph changes, connections and AI use. Sample entries are labelled." },
  "scene.compliance": { title: "Frameworks", body: "Framework tools and self-assessments. Self-reported: they reflect what you enter, not an automated audit." },
  "scene.con": { title: "Integrations", body: "Connect AI models and threat-intelligence sources. Keys stay in this browser; status shows whether each connection actually works." },
  "scene.tools": { title: "Tool Library", body: "Every Darknode tool, grouped by category. Star a tool to pin it to your overview." },
  "scene.toolkit": { title: "Toolkit", body: "Quick in-browser utilities: encoders, hashes, converters and calculators. Nothing is sent to a server." },
  "scene.assistant": { title: "AI Assistant", body: "Chat with Darknode AI to triage a CVE, draft a runbook, explain a finding or review a config." },
  "scene.admin": { title: "Admin", body: "Owner-only controls: users, bans, announcements and platform settings." },
  "scene.settings": { title: "Settings", body: "Your account, appearance and preferences." },
  "scene.team": { title: "Team", body: "Members and roles for the active team workspace. Add people by the user id they share with you, set their role (owner, admin, analyst, responder or viewer), and review the append-only membership log. Roles are enforced server-side; your personal workspace has no members." },

  // ---- Sidebar tools (others fall back to the console's section help) ----
  "tool.codescan": { title: "Code Scanner", body: "Scan a GitHub repository or local folder for leaked secrets, risky code and vulnerable dependencies, then jump to the exact line.", src: "Pattern-based static analysis. Findings are leads to review, not proof of a vulnerability." },
  "tool.supplychain": { title: "Supply Chain", body: "Assess the risk in your software dependencies: known-vulnerable packages, licences and suspicious maintainers." },
  "tool.threatforest": { title: "Attack Tree Builder", body: "Analyse source code and turn its weaknesses into attack trees: the goals an attacker could reach and the steps to get there, mapped to CWE, CAPEC, MITRE ATT&CK and STRIDE.", src: "Heuristic and advisory; confidence is shown per finding." },
  "tool.secgraph": { title: "Security Graph", body: "A visual map of how your assets, findings, indicators and incidents connect, built from what your tools record." },
  "tool.incidents": { title: "Incident Tracker", body: "Log security incidents and track each one from detection through containment to closure." },
  "tool.casemgmt": { title: "Case Manager", body: "Organise investigations into case files with evidence, notes and status." },
  "tool.strongroom": { title: "Fund Protection", body: "Screen a ledger for fraud patterns and link them to cyber events, to catch intrusion-to-theft chains. Runs in your browser.", src: "Deterministic rules on the data you load. A screening aid, not an audit." },
  "tool.vault": { title: "Treasury Vault", body: "The control and record layer for funds held at your bank: a double-entry ledger, dual approvals, a tamper-evident audit chain and reconciliation.", src: "Holds no money. Figures are the book values you enter." },
  "tool.sanctions": { title: "Sanctions Screening", body: "Screen payees, vendors and counterparties against the official OFAC SDN list (names and aliases), with fuzzy matching for spelling variants.", src: "Live OFAC export, matched in your browser. A screening aid, not a compliance determination." },
  "tool.signins": { title: "Sign-in Forensics", body: "Load an Entra ID, Google Workspace or Okta sign-in export and find password spraying, brute force, impossible travel, legacy authentication and admin sign-ins without MFA, each mapped to MITRE ATT&CK.", src: "Your exported log, analysed in this browser. Nothing is uploaded. Detections run only when the export has the columns they need; skipped ones are listed with the reason." },
  "tool.accessreview": { title: "Access Review", body: "Reconcile your HR roster against a directory or identity-provider export: leavers still enabled, accounts nobody owns, stale logins, admins without MFA. Record a decision per account and export the signed-off packet.", src: "Both files stay in this browser. Matching uses employee ID, then email, then a flagged name match that needs your confirmation." },
  "tool.fwaudit": { title: "Firewall Rule Audit", body: "Paste a firewall rule export (iptables, Cisco ASA, pfSense, FortiGate, Windows Firewall) and get shadowed rules, any-to-any permits, admin ports open to the internet and missing default deny, with a fix for each.", src: "Deterministic rule-base analysis in this browser using real CIDR and port containment, not text matching." },
  "tool.loghunt": { title: "Log Threat Hunter", body: "Paste web server, SSH or Windows Security logs and surface brute force, credential stuffing, injection and scanner probes, web shells, new admin accounts and cleared logs, mapped to MITRE ATT&CK.", src: "Deterministic rules over your log lines in this browser. Thresholds are shown and adjustable; evidence lines are listed for every finding." },
  "tool.payees": { title: "Payee Control", body: "A vendor register with validated bank details and bank-change control: a change needs a second approver and a recorded callback, then the new account is held before its first payment.", src: "A local control register in your browser. Validation (IBAN/ABA/BIC) is real; the second approver is a distinct name, not a login." },
  "tool.dlp": { title: "Data Protection Scanner", body: "Finds exposed secrets (API keys, tokens, private keys, DB connection strings) and personal data (payment cards, IBANs, SSNs, emails) in pasted text or dropped files, and produces a redacted copy.", src: "Pattern + checksum + entropy detection running entirely in your browser. Nothing is uploaded. A clean result is not a guarantee." },
  "tool.posture": { title: "External Posture Scorecard", body: "Runs live HTTPS, security-header, SPF/DMARC, certificate and security.txt checks for one domain and rolls them into one weighted posture grade with prioritised fixes.", src: "Publicly observable signals via the Darknode proxy and public DNS. An external indicator, not a penetration test or audit." },
  "tool.tlsfleet": { title: "Certificate & TLS Fleet Monitor", body: "Tracks certificate expiry, issuer and HSTS across a list of domains, flagging anything nearing expiry, with a watchlist kept in this browser.", src: "Newest certificate per domain from certificate transparency (crt.sh) via the proxy. Observes issued certificates and headers; does not negotiate TLS ciphers." },
  "tool.phishtriage": { title: "Phishing & URL Triage", body: "Paste a link or a full email: links are unfurled server-side, domains checked for age and lookalikes, email authentication (SPF/DKIM/DMARC) verified, and IOCs extracted, with a plain-language risk read-out.", src: "Redirect chain + RDAP registration date + DNS via the proxy and public resolvers, plus deterministic lookalike/obfuscation heuristics. A triage aid, not a malware verdict." },
  "tool.crosswalk": { title: "GenAI Crosswalk", body: "Map the OWASP GenAI security risks to 26 security and compliance frameworks.", src: "OWASP GenAI Security Project data, CC BY-SA 4.0." },
  "tool.leakprobe": { title: "Secret Exposure & Backend Leak Scanner", body: "Points at a property you own and proves whether a secret (an API key, a token, your Gemini key) is reachable from the browser or kept server-side. It scans the page's scripts, module graph, source maps and config for secrets, then GET-probes backend endpoints, their error pages and common debug routes, and returns a placement verdict per secret.", src: "All fetches run server-side through the Darknode proxy. Secrets are masked; no provider API is called and no key is spent. A clean result means no exposure was observed, not a proof of absolute safety." },
  "lp.target": { title: "Target URL", body: "The page whose client bundle LEAKPROBE will fetch and scan — scripts, modules, source maps and config." },
  "lp.endpoints": { title: "Backend endpoints", body: "Backend URLs that get a bounded GET probe for echoed secrets, verbose errors and CORS exposure. Pre-filled with this site's AI backend when it is known." },
  "lp.secrets": { title: "Secrets to track", body: "Exact-match needles — paste a specific key (e.g. your Gemini key) to hunt for it everywhere. Kept in memory only and masked in the report; generic AI keys are detected automatically regardless." },
  "lp.capture": { title: "Capture live backend traffic", body: "Loads this site in a sandboxed frame, instruments fetch/XHR, sends a benign message to the assistant so the real /api/chat request fires, and opens tools to trigger their backend calls — then scans every captured request and response for leaked secrets. Runs only against this origin; destructive controls (delete, logout, pay, transfer) are never clicked." },

  // ---- Header ----
  "hdr.menu": { title: "Navigation", body: "Show or hide the sidebar. On small screens it opens as a drawer." },
  "hdr.collapse": { title: "Collapse navigation", body: "Shrink the sidebar to icons to give the workspace more room. Your choice is remembered." },
  "hdr.brand": { title: "Darknode", body: "Back to the Security Overview from anywhere in the Deck." },
  "hdr.workspace": { title: "Workspace", body: "Switch between your personal workspace and any team you belong to. Each workspace has its own security graph; a team's graph is shared with its members." },
  "hdr.search": { title: "Search", body: "Jump to any tool, page or action by typing part of its name. Shortcut: Ctrl K." },
  "hdr.health": { title: "Threat feed status", body: "Green when the live vulnerability feed loaded. If it is down, threat numbers show a dash rather than stale values." },
  "hdr.assistant": { title: "AI assistant", body: "Open Darknode AI in a side panel without leaving the page you are on." },
  "hdr.new": { title: "Quick create", body: "Start something new: scan a codebase, map a domain, open an investigation or connect a provider." },
  "hdr.bell": { title: "Notifications", body: "Recent events from your tools and connections. The badge counts what you have not seen." },
  "hdr.account": { title: "Account", body: "Your profile, settings, keyboard shortcuts, density, hover explanations and sign out." },

  // ---- Overview panels ----
  "panel.pins": { title: "Pinned tools", body: "Tools you starred for one-click access. Pin from the Tool Library or Ctrl K search." },
  "panel.system": { title: "System status", body: "Whether each data source the command center relies on is live right now." },
  "panel.integrations": { title: "Integrations", body: "How many of the available providers you have connected, and which ones." },
  "panel.activity": { title: "Recent activity", body: "The latest events in this workspace. Entries marked Sample came from simulations or demos and do not affect your metrics." },
  "panel.quick": { title: "Quick actions", body: "Common starting points. Each opens the real tool." },
  "panel.threat": { title: "Threat level", body: "How many of the 30 most recent CVEs are critical or high, split by severity.", src: "NVD, fetched live." },
  "panel.notes": { title: "Notes", body: "A scratchpad for IPs, hypotheses and to-dos. Saved in this browser only." },

  "panel.actions": { title: "Top actions", body: "The most important things to do next, ranked: open critical findings, known-exploited CVEs published this week, open high findings, critical CVEs, then gaps in your connected sources.", src: "Your security graph (sample data excluded), NVD and CISA KEV, fetched live." },

  // ---- Findings ----
  "scene.findings": { title: "Findings", body: "Every finding and vulnerability your tools have recorded, in one queue you can filter, triage and export." },
  "scene.section": { title: "Section overview", body: "A summary of one sidebar section: its records, its tools, its latest results and which data sources are connected." },
  "panel.findings": { title: "Finding queue", body: "Findings sorted by severity, then by most recent update. Select rows to set their status for all of them at once. Click a name to open it in the Security Graph." },
  "fnd.critical": { title: "Open critical", body: "Critical-severity findings that are new, open or being investigated. Fix these first." },
  "fnd.high": { title: "Open high", body: "High-severity findings that are new, open or being investigated." },
  "fnd.open": { title: "Open findings", body: "All findings not yet resolved or closed, at any severity." },
  "fnd.resolved": { title: "Resolved or closed", body: "Findings you have marked resolved or closed. They stay in the graph as a record." },

  // ---- Section pages ----
  "nav.section": { title: "Section overview", body: "Open a summary of this section: what it has recorded, its tools, its latest results and its connected data sources." },
  "panel.sectools": { title: "Tools in this section", body: "Every tool in this part of the sidebar, with what each one does." },
  "panel.latest": { title: "Latest results", body: "The most recently updated records that belong to this section, from the security graph. Sample data is excluded." },
  "panel.sources": { title: "Data sources", body: "External services that feed this section. Greyed-out sources are not connected, so their data is not available yet." },
  "sect.records": { title: "Records", body: "Real entities in the security graph that belong to this section, by type or by the tool that recorded them." },
  "sect.hot": { title: "Open critical / high", body: "Records in this section with critical or high severity that are not resolved or closed." },
  "sect.sources": { title: "Data sources connected", body: "How many of this section's key-based services you have connected. \"Public\" means it uses only free public sources that need no key; \"Local\" means its tools run in your browser on data you provide." },
  "sect.tools": { title: "Tools", body: "The number of tools listed under this section in the sidebar." },

  // ---- Compliance dashboard ----
  "comp.controls": { title: "Controls assessed", body: "How many control records your framework and self-assessment tools have written to the security graph. Each one is a control you have evaluated. Simulated and sample entities are excluded.", src: "The security graph in this browser. Self-reported, not an automated audit." },
  "comp.frameworks": { title: "Frameworks mapped", body: "The number of distinct frameworks (such as NIST CSF, ISO 27001, SOC 2, PCI DSS, HIPAA or GDPR) referenced by your recorded controls and reports.", src: "Derived from your control and report records. Sample data is excluded." },
  "comp.gaps": { title: "Open gaps", body: "Controls or reports with critical or high severity that are not yet resolved or closed — the compliance findings to close first.", src: "Your security graph. Sample and simulated data is excluded." },

  // ---- Badges and controls ----
  "badge.sample": { title: "Sample data", body: "Created by a simulation, war-game or built-in demo. Shown for context, excluded from every posture number." },
  "badge.kev": { title: "Known exploited", body: "On the CISA Known Exploited Vulnerabilities catalog: attackers are using it now. Patch it first.", src: "CISA KEV." },
  "badge.epss": { title: "EPSS", body: "The probability this CVE is exploited in the next 30 days, from the FIRST Exploit Prediction Scoring System. Higher means more likely.", src: "FIRST EPSS." },
  "btn.prioritize": { title: "Prioritize", body: "Order CVEs by real-world exploitation risk: known-exploited first, then EPSS probability, then CVSS severity." },
  "btn.pin": { title: "Pin to overview", body: "Add this tool to Pinned tools on your Security Overview." },
  "btn.copy": { title: "Copy tool link", body: "Copy a direct link to this tool." },
  "btn.newtab": { title: "Open in a new tab", body: "Open this tool on its own in a new browser tab." },
  "badge.live": { title: "Live data", body: "This tool pulls live data from an external source rather than a built-in dataset." },
  "inv.sim": { title: "Include simulated / sample", body: "Show entities written by simulations, war-games and demos. They are always labelled Sample and never count toward metrics." },
};

export function explainEnabled() { try { return localStorage.getItem(LS_OFF) !== "off"; } catch (_) { return true; } }
export function setExplainEnabled(on) { try { on ? localStorage.removeItem(LS_OFF) : localStorage.setItem(LS_OFF, "off"); } catch (_) {} }

// Where the card goes: below the anchor if it fits, else above; horizontally aligned to
// the anchor's left edge, clamped inside the viewport with an 8px margin.
export function tipPosition(a, tw, th, vw, vh, gap = 10) {
  const m = 8;
  let top = a.bottom + gap, side = "below";
  if (top + th > vh - m && a.top - gap - th >= m) { top = a.top - gap - th; side = "above"; }
  top = Math.max(m, Math.min(top, vh - th - m));
  const left = Math.max(m, Math.min(a.left, vw - tw - m));
  return { left: Math.round(left), top: Math.round(top), side };
}

const CSS = `
.dn-explain{position:fixed;z-index:2147483000;max-width:min(340px,calc(100vw - 16px));padding:12px 14px;border-radius:10px;
  background:#141c2e;color:#e8edf7;box-shadow:0 12px 32px rgba(10,16,30,.28);pointer-events:none;
  font:13px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,system-ui,Helvetica,Arial,sans-serif;
  opacity:0;transform:translateY(4px);transition:opacity .15s ease,transform .15s ease}
.dn-explain.on{opacity:1;transform:none}
.dn-explain b{display:block;font-size:13.5px;font-weight:700;color:#fff;margin:0 0 4px}
.dn-explain p{margin:0;color:#c9d2e3;overflow-wrap:anywhere}
.dn-explain .src{margin-top:8px;padding-top:7px;border-top:1px solid rgba(255,255,255,.12);font-size:11.5px;color:#93a0b8}`;

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

export function attachExplain(root, opts = {}) {
  const delay = opts.delay || EXPLAIN_DELAY;
  const resolve = typeof opts.resolve === "function" ? opts.resolve : () => null;
  if (!document.getElementById("dn-explain-css")) {
    const st = document.createElement("style"); st.id = "dn-explain-css"; st.textContent = CSS; document.head.appendChild(st);
  }
  const tip = document.createElement("div");
  tip.className = "dn-explain"; tip.id = "dnExplain" + Math.random().toString(36).slice(2, 8); tip.setAttribute("role", "tooltip"); tip.hidden = true;
  document.body.appendChild(tip);
  let cur = null, timer = 0;

  // Nearest element that has something to say, and what it says.
  function find(t) {
    for (let el = t instanceof Element ? t : null; el && el !== root.parentNode; el = el.parentElement) {
      const id = el.dataset && el.dataset.explain;
      if (id && EXPLAIN[id]) return { el, info: EXPLAIN[id] };
      const info = resolve(el);
      if (info) return { el, info };
      if (el === root) break;
    }
    return null;
  }
  function hide() {
    clearTimeout(timer); timer = 0;
    if (cur && cur.el.getAttribute("aria-describedby") === tip.id) cur.el.removeAttribute("aria-describedby");
    cur = null; tip.classList.remove("on"); tip.hidden = true;
  }
  function show() {
    if (!cur || !cur.el.isConnected) return hide();
    const { title, body, src } = cur.info;
    tip.innerHTML = `<b>${esc(title)}</b><p>${esc(body)}</p>${src ? `<div class="src">${esc(src)}</div>` : ""}`;
    tip.hidden = false;
    const p = tipPosition(cur.el.getBoundingClientRect(), tip.offsetWidth, tip.offsetHeight, window.innerWidth, window.innerHeight);
    tip.style.left = p.left + "px"; tip.style.top = p.top + "px";
    cur.el.setAttribute("aria-describedby", tip.id);
    requestAnimationFrame(() => tip.classList.add("on"));
  }
  function arm(target) {
    if (!explainEnabled()) return;
    const hit = find(target);
    if (hit && cur && hit.el === cur.el) return;
    hide();
    if (!hit) return;
    // A native title would pop up first and duplicate the card.
    if (hit.el.hasAttribute("title")) { hit.el.setAttribute("aria-label", hit.el.getAttribute("aria-label") || hit.el.title); hit.el.removeAttribute("title"); }
    cur = hit; timer = setTimeout(show, delay);
  }
  const onOver = (e) => { if (e.pointerType !== "touch") arm(e.target); };
  const onOut = (e) => { if (cur && !(e.relatedTarget && cur.el.contains(e.relatedTarget))) hide(); };
  const onFocus = (e) => { if (e.target.matches && e.target.matches(":focus-visible")) arm(e.target); };
  const onKey = (e) => { if (cur && (e.key === "Escape" || !timer)) hide(); };
  root.addEventListener("pointerover", onOver);
  root.addEventListener("pointerout", onOut);
  root.addEventListener("focusin", onFocus);
  root.addEventListener("focusout", hide);
  root.addEventListener("pointerdown", hide, true);
  document.addEventListener("keydown", onKey, true);
  window.addEventListener("scroll", hide, true);
  window.addEventListener("blur", hide);
  return function detach() {
    hide();
    root.removeEventListener("pointerover", onOver);
    root.removeEventListener("pointerout", onOut);
    root.removeEventListener("focusin", onFocus);
    root.removeEventListener("focusout", hide);
    root.removeEventListener("pointerdown", hide, true);
    document.removeEventListener("keydown", onKey, true);
    window.removeEventListener("scroll", hide, true);
    window.removeEventListener("blur", hide);
    tip.remove();
  };
}
