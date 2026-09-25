// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Console navigation: services bar, Services mega-menu, favorites + recents, and the
// home-page services directory. An AWS-console-style front end over the existing
// `.side-item[data-sec]` sections — every section still gets one of those buttons in
// the hidden menu, so routing, breadcrumbs and global search keep working unchanged.

const G = (id, name, color, items) => ({ id, name, color, items: items.map(([sec, label, badge]) => ({ sec, label, badge: badge || null })) });

export const NAV = [
  G("command", "Mission Control", "blue", [["prometheus","PROMETHEUS","live"],["sentineleye","SENTINEL EYE","live"],["hydra","HYDRA Engine"],["aegis","AEGIS Ops Center"],["vanguard","VANGUARD"],["phantom","PHANTOM","live"],["citadel","CITADEL","live"],["oracle","ORACLE","live"],["spectre","SPECTRE","live"],["crucible","CRUCIBLE","live"],["navarch","NAVARCH","live"],["secdash","Security Dashboard"]]),
  G("offense", "Offensive Security", "red", [["attacksim","Threat Simulator"],["cracklab","Password Security Lab"],["exploitdb","Vulnerability Database"],["exploitdev","Security Research Lab"],["packetcraft","Packet Crafter"],["passwordtools","Password Tools"],["payloads","Test Script Forge"],["payloadgen","Test Script Generator"],["pentestconsole","Security Assessment"],["privesc","Privilege Analysis"],["reverseshell","Remote Access Testing"]]),
  G("labs", "Security Labs", "red", [["firewall","Firewall Rules"],["webshell","Terminal"],["wirelesslab","Wireless Lab"],["xsslab","Web Security Lab"],["socialeng","Social Engineering"]]),
  G("recon", "Reconnaissance", "cyan", [["addressintel","Address Intel"],["asnexplorer","ASN Explorer"],["attacksurf","Exposure Mapping"],["dns","DNS Toolkit"],["dnsenum","DNS Enumeration"],["dnsrecon","DNS Recon"],["ghdb","Google Dorking"],["netmap","Network Mapper"],["reconplanner","Recon Planner"],["securityscanner","Security Scanner"],["subdomains","Subdomain Enum"],["tools","Scanner Suite"],["wayback","Wayback Machine"]]),
  G("osint", "OSINT", "cyan", [["corstester","CORS Tester"],["emailintel","Email Intel"],["favicon","Favicon Hasher"],["headeranalyzer","Header Analyzer"],["httpinspector","HTTP Inspector"],["httpprobe","HTTP Probe"],["ipgeolocation","IP Geolocation"],["iptools","IP Tools"],["osint","OSINT Dashboard"],["osintemail","OSINT Email Intel"],["techfingerprint","Tech Fingerprint"],["whoisrecon","WHOIS Recon"]]),
  G("forensics", "Forensics", "purple", [["binanalyze","Binary Analyzer"],["forensicstoolkit","Forensics Toolkit"],["ftimeline","Forensic Timeline"],["loganalyze","Log Analyzer"],["memforensics","Memory Forensics"],["reveng","Reverse Engineering"],["stego","Steganography"],["timelineviz","Timeline Visualization"]]),
  G("threatanalysis", "Threat Analysis", "purple", [["malclass","Threat Classifier"],["phishing","Phishing Analyzer"],["sandbox","Threat Analysis Lab"]]),
  G("blueteam", "Blue Team", "green", [["adversary","Adversary Emulation"],["breachsim","Breach Simulator"],["containers","Container Security"],["deception","Deception Architect"],["huntlab","Threat Hunt Lab"],["identitymatrix","Identity Matrix"],["incidents","Incident Tracker"],["mobilesec","Mobile Security"],["purpleteam","Purple Team Ops"],["riskcalculator","Risk Calculator"],["threatmodel","Threat Modeler"]]),
  G("threatintel", "Threat Intelligence", "orange", [["breachlookup","Breach Lookup"],["cvesearch","CVE Search"],["cvetimeline","CVE Timeline"],["darknetradar","Darknet Radar"],["darkwebosint","Deep Web Intel"],["ipreputation","IP Reputation"],["threat","Threat Feed"],["threatdashboard","Threat Dashboard"],["threatfeed","Threat Intel Feed"]]),
  G("vulnmgmt", "Vulnerability Mgmt", "orange", [["vulndb","Vulnerability DB"],["vulnprio","Vuln Prioritizer"],["vulntriage","Vuln Triage Engine"],["secchecklist","Security Checklist"],["supplychain","Supply Chain"]]),
  G("network", "Network Analysis", "teal", [["networkscanner","Network Scanner"],["networktools","Network Tools"],["networktraffic","Network Traffic"],["packetanalyzer","Packet Analyzer"],["packetinspector","Packet Inspector"],["sslinspector","SSL Inspector"],["subnetvisualizer","Subnet Visualizer"],["trafficanalyzer","Traffic Analyzer"],["websockettester","WebSocket Tester"]]),
  G("secops", "Security Operations", "teal", [["adversaryplaybook","Adversary Playbook"],["apifuzzer","API Fuzzer"],["apitester","API Tester"],["apiscan","API Scanner"],["incidentcost","Incident Cost Calc"],["incidentresponse","Incident Response"],["siemdash","SIEM Dashboard"]]),
  G("compliance", "Compliance & GRC", "yellow", [["compliance","Compliance Checker"],["cyberbriefing","Cyber Briefing"],["emailheader","Email Header Analyzer"],["fedcompliance","Federal Compliance"],["iocextractor","IOC Extractor"],["zerotrust","Zero Trust Planner"]]),
  G("crypto", "Crypto & Encoding", "indigo", [["credaudit","Credential Auditor"],["cryptotools","Crypto Toolkit"],["cspevaluator","CSP Evaluator"],["encoding","Encoding Suite"],["hashsuite","Hash Suite"],["jwtanalyzer","JWT Analyzer"],["regexlab","Regex Lab"],["urldissect","URL Dissector"]]),
  G("ai", "Nexus AI", "violet", [["ai","AI Chat"],["coder","Nexus Agent","ai"],["dataviz","Data Visualization"],["engines","Security Engines"],["report","Report Generator"]]),
  G("training", "Training", "emerald", [["cheats","Cheat Sheets"],["cyberrange","Cyber Range"],["learn","Learn Hub"],["refs","Reference Library"],["secquiz","Skill Assessments"],["securityquiz","Security Quiz"],["snippets","Snippet Vault"],["targets","Practice Targets"],["training","Training Labs"],["utils","Toolbox"]]),
  G("vms", "Labs & VMs", "emerald", [["vms","Vulnerable VMs"],["vmlab","VM Lab"]]),
  G("invest", "Investigations", "rose", [["investigation","Investigation Workspace"],["secgraph","Security Graph"],["casemgmt","Case Manager"]]),
  G("infra", "Infrastructure", "slate", [["api","API"],["docs","Docs"],["education","Education"],["downloads","Darknode OS"],["dlguide","Download Guide"],["privatecloud","Private Cloud","beta"],["setup","Local Setup"]]),
  G("workspace", "Workspace", "slate", [["saved","Saved Items"],["settings","Settings"],["apikeys","API Keys"],["contact","Contact / Feedback"]]),
];
const ADMIN = G("admin", "Admin", "slate", [["admin","Admin Console"]]);

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const groups = (isOwner) => (isOwner ? [...NAV, ADMIN] : NAV);
const ALL = [...NAV, ADMIN];
const LABELS = new Map(ALL.flatMap((g) => g.items.map((i) => [i.sec, i.label])));
const GROUP_OF = new Map(ALL.flatMap((g) => g.items.map((i) => [i.sec, g.name])));
const BADGE_OF = new Map(ALL.flatMap((g) => g.items.map((i) => [i.sec, i.badge])));
export const labelOf = (sec) => LABELS.get(sec) || sec.charAt(0).toUpperCase() + sec.slice(1);
const badgeHTML = (sec) => { const b = BADGE_OF.get(sec); return b ? ` <span class="svc-badge ${b}">${b === "live" ? "LIVE" : b === "ai" ? "AI" : "BETA"}</span>` : ""; };

const load = (k) => { try { const v = JSON.parse(localStorage.getItem(k) || "[]"); return Array.isArray(v) ? v.filter((s) => LABELS.has(s)) : []; } catch (_) { return []; } };
const save = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch (_) {} };
const FAV_KEY = "sw_favs", RECENT_KEY = "sw_recent";
const DEFAULT_FAVS = ["prometheus", "citadel", "ai", "cvesearch", "threat", "learn"];
const favTouched = () => { try { return localStorage.getItem(FAV_KEY) !== null; } catch (_) { return false; } };
const favs = () => { const f = load(FAV_KEY); return f.length || favTouched() ? f : DEFAULT_FAVS; };
const chip = (sec, cls = "") => `<button class="con-chip ${cls}" data-sec="${esc(sec)}" title="${esc(GROUP_OF.get(sec) || "")}">${esc(labelOf(sec))}${badgeHTML(sec)}</button>`;

export function consoleHTML(isOwner) {
  const gs = groups(isOwner);
  const total = gs.reduce((n, g) => n + g.items.length, 0);
  return `
  <div class="con-wrap">
  <div class="con-top">
    <div class="con-bar" role="navigation" aria-label="Console">
      <button class="con-services" id="conServices" aria-expanded="false" aria-controls="sidebar"><span class="con-grid-ic" aria-hidden="true"></span>Services<span class="con-caret" aria-hidden="true">▾</span></button>
      <label class="con-search"><span class="sr-only">Find a service</span>
        <input id="conSearch" type="search" placeholder="Search ${total} services — type a name, e.g. &quot;cve&quot;" autocomplete="off" spellcheck="false">
        <kbd>/</kbd>
      </label>
      <div class="con-quick" aria-label="Shortcuts">
        <button class="con-qbtn" data-sec="home">Dashboard</button>
        <button class="con-qbtn" data-sec="ai">Nexus AI</button>
        <button class="con-qbtn" data-sec="docs">Docs</button>
        <button class="con-qbtn" data-sec="settings">Settings</button>
      </div>
    </div>
    <div class="con-favbar" aria-label="Favorites">
      <span class="con-favlbl">★ Favorites</span><span class="con-favs" id="conFavs"></span>
      <span class="con-favlbl con-reclbl">Recent</span><span class="con-favs" id="conRecent"></span>
    </div>
  </div>
  <aside class="svc-menu" id="sidebar" aria-label="All services">
    <div class="svc-cols">
      <nav class="svc-cats" aria-label="Service categories">
        <button class="svc-cat on" data-cat="recent">Recently visited</button>
        <button class="svc-cat" data-cat="favs">Favorites</button>
        <button class="svc-cat" data-cat="all">All services <span class="svc-n">${total}</span></button>
        <div class="svc-cat-div"></div>
        ${gs.map((g) => `<button class="svc-cat" data-cat="${g.id}" data-color="${g.color}"><span class="svc-dot"></span>${esc(g.name)} <span class="svc-n">${g.items.length}</span></button>`).join("")}
      </nav>
      <div class="svc-pane">
        <div class="svc-hint" id="svcHint"></div>
        <div class="svc-list" id="svcSpecial"></div>
        <div class="side-nav svc-groups" id="svcGroups">
          ${gs.map((g) => `<section class="svc-group" data-g="${g.id}" data-color="${g.color}"><div class="svc-gh" role="heading" aria-level="3"><span class="svc-dot"></span>${esc(g.name)}</div><div class="svc-items">
            ${g.items.map((i) => `<div class="svc-card" data-card="${i.sec}"><button class="side-item" data-sec="${i.sec}">${esc(i.label)}${badgeHTML(i.sec)}</button><button class="svc-star" data-star="${i.sec}" aria-label="Pin ${esc(i.label)} to favorites">☆</button></div>`).join("")}
          </div></section>`).join("")}
        </div>
      </div>
    </div>
  </aside>
  </div>`;
}

export function directoryHTML(isOwner) {
  const gs = groups(isOwner);
  return `
  <div class="con-dir">
    <div class="con-dir-h"><h2 class="pg-h2">All services</h2><span class="muted">Click any service to open it. Star (☆) a service in the Services menu to pin it to your favorites bar.</span></div>
    <div class="con-dir-grid">
      ${gs.map((g) => `<div class="panel con-dir-panel" data-color="${g.color}"><div class="con-dir-ph"><span class="svc-dot"></span><strong>${esc(g.name)}</strong><span class="svc-n">${g.items.length}</span></div>
        <div class="con-dir-items">${g.items.map((i) => `<button class="con-dir-item" data-sec="${i.sec}"><span>${esc(i.label)}${badgeHTML(i.sec)}</span><span class="con-dir-arrow" aria-hidden="true">›</span></button>`).join("")}</div></div>`).join("")}
    </div>
  </div>`;
}

export function wireConsole(root) {
  const menu = root.querySelector("#sidebar");
  const btn = root.querySelector("#conServices");
  const search = root.querySelector("#conSearch");
  const special = root.querySelector("#svcSpecial");
  const groupsEl = root.querySelector("#svcGroups");
  const hint = root.querySelector("#svcHint");
  if (!menu || !btn) return { track() {} };
  let cat = "recent";

  const isOpen = () => menu.classList.contains("open");
  const setOpen = (o) => { menu.classList.toggle("open", o); btn.setAttribute("aria-expanded", String(o)); if (o) render(); };
  const renderBars = () => {
    const f = favs(), r = load(RECENT_KEY);
    root.querySelector("#conFavs").innerHTML = f.length ? f.map((s) => chip(s)).join("") : `<span class="con-empty">Open Services and click ☆ to pin tools here</span>`;
    root.querySelector("#conRecent").innerHTML = r.length ? r.slice(0, 6).map((s) => chip(s, "rec")).join("") : `<span class="con-empty">Tools you open show up here</span>`;
    const fs = new Set(f);
    menu.querySelectorAll(".svc-star").forEach((s) => { const on = fs.has(s.dataset.star); s.classList.toggle("on", on); s.textContent = on ? "★" : "☆"; });
  };
  const render = () => {
    const q = (search.value || "").trim().toLowerCase();
    menu.querySelectorAll(".svc-cat").forEach((c) => c.classList.toggle("on", !q && c.dataset.cat === cat));
    const showGroups = q || (cat !== "recent" && cat !== "favs");
    special.hidden = !!showGroups; groupsEl.hidden = !showGroups;
    if (!showGroups) {
      const list = cat === "favs" ? favs() : load(RECENT_KEY);
      hint.textContent = cat === "favs" ? "Your pinned services. Pin more with ☆ next to any service." : "Services you opened most recently.";
      special.innerHTML = list.length ? list.map((s) => chip(s, "big")).join("") : `<p class="con-empty">${cat === "favs" ? "Nothing pinned yet — choose a category on the left and click ☆." : "Nothing yet — open any service and it will appear here."}</p>`;
      return;
    }
    let shown = 0;
    menu.querySelectorAll(".svc-group").forEach((g) => {
      let any = false;
      g.querySelectorAll(".svc-card").forEach((c) => {
        const hit = !q || c.textContent.toLowerCase().includes(q) || (GROUP_OF.get(c.dataset.card) || "").toLowerCase().includes(q);
        c.hidden = !hit; if (hit) { any = true; shown++; }
      });
      g.hidden = !any || (!q && cat !== "all" && g.dataset.g !== cat);
    });
    hint.textContent = q ? `${shown} service${shown === 1 ? "" : "s"} match “${search.value.trim()}”. Press Enter to open the first one.` : cat === "all" ? "Every service, grouped by category." : "Pick a service to open it.";
  };

  btn.onclick = () => setOpen(!isOpen());
  menu.querySelector(".svc-cats").addEventListener("click", (e) => { const c = e.target.closest(".svc-cat"); if (!c) return; cat = c.dataset.cat; search.value = ""; render(); });
  menu.querySelector(".svc-cats").addEventListener("mouseover", (e) => { const c = e.target.closest(".svc-cat"); if (!c || search.value || !matchMedia("(hover:hover)").matches) return; if (cat !== c.dataset.cat) { cat = c.dataset.cat; render(); } });
  menu.addEventListener("click", (e) => {
    const s = e.target.closest(".svc-star"); if (!s) return;
    const f = favs(), i = f.indexOf(s.dataset.star);
    if (i >= 0) f.splice(i, 1); else f.push(s.dataset.star);
    save(FAV_KEY, f); renderBars();
  });
  search.addEventListener("focus", () => setOpen(true));
  search.addEventListener("input", () => { if (!isOpen()) setOpen(true); else render(); });
  search.addEventListener("keydown", (e) => {
    if (e.key === "Enter") { const first = menu.querySelector(".svc-group:not([hidden]) .svc-card:not([hidden]) .side-item"); if (first) first.click(); }
    if (e.key === "Escape") { search.value = ""; setOpen(false); search.blur(); }
  });
  document.addEventListener("keydown", (e) => {
    if (!document.body.contains(menu)) return;
    if (e.key === "Escape" && isOpen()) setOpen(false);
    const t = e.target, typing = t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName));
    if (e.key === "/" && !typing && !e.ctrlKey && !e.metaKey) { e.preventDefault(); search.focus(); }
  });
  document.addEventListener("click", (e) => { if (isOpen() && !e.target.closest("#sidebar, .con-bar, #hamburger")) setOpen(false); });
  renderBars();

  return {
    track(sec) {
      if (LABELS.has(sec) && sec !== "home") { const r = load(RECENT_KEY).filter((s) => s !== sec); r.unshift(sec); save(RECENT_KEY, r.slice(0, 12)); }
      search.value = ""; setOpen(false); renderBars();
    },
  };
}
