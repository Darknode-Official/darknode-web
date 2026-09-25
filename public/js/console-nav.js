// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Console navigation: services bar, Services mega-menu, favorites + recents, and the
// home-page services directory. Replaces the old left sidebar.
// Every section keeps a `.side-item[data-sec]` button in the menu — other modules click those.

const G = (id, name, items) => ({ id, name, items: items.map(([sec, label]) => ({ sec, label })) });

export const NAV = [
  G("command", "Command Centers", [["home", "Console Home"], ["prometheus", "PROMETHEUS"], ["sentineleye", "SENTINEL EYE"], ["hydra", "HYDRA Engine"], ["aegis", "AEGIS Ops Center"], ["vanguard", "VANGUARD"], ["secdash", "Security Dashboard"]]),
  G("offense", "Offensive Security", [["payloads", "Payload Generator"], ["exploitdb", "Exploit Database"], ["exploitdev", "Exploit Writer"], ["packetcraft", "Packet Crafter"], ["webshell", "Web Shell"], ["cracklab", "Password Cracking"], ["attacksim", "Attack Simulator"], ["firewall", "Firewall Builder"], ["wirelesslab", "Wireless Pentest Lab"], ["pentestconsole", "Pentest Console"]]),
  G("recon", "Reconnaissance", [["addressintel", "Address Intelligence"], ["tools", "Scanner Suite"], ["osint", "OSINT Dashboard"], ["subdomains", "Subdomain Finder"], ["dns", "DNS Toolkit"], ["netmap", "Network Mapper"], ["attacksurf", "Attack Surface Mapper"], ["ghdb", "Google Dorks"], ["apitester", "API Tester"], ["apiscan", "API Security Scanner"], ["wayback", "Wayback Recon"], ["favicon", "Favicon Hasher"]]),
  G("forensics", "Analysis & Forensics", [["binanalyze", "Binary Analyzer"], ["loganalyze", "Log Analyzer"], ["memforensics", "Memory Forensics"], ["ftimeline", "Forensic Timeline"], ["malclass", "Malware Classifier"], ["sandbox", "Malware Sandbox"], ["phishing", "Phishing Analyzer"], ["stego", "Steganography"], ["reveng", "Reverse Engineering"]]),
  G("defense", "Defense & Response", [["adversary", "Adversary Mind"], ["breachsim", "Breach Simulator"], ["huntlab", "Threat Hunt Lab"], ["purpleteam", "Purple Team Ops"], ["deception", "Deception Architect"], ["incidents", "Incident Tracker"], ["threatmodel", "Threat Modeler"], ["containers", "Container Security"], ["mobilesec", "Mobile Security Lab"]]),
  G("intel", "Intelligence & Compliance", [["threat", "Threat Intelligence"], ["ipreputation", "IP Reputation"], ["darkwebosint", "Dark Web OSINT"], ["vulnprio", "Vuln Prioritizer"], ["compliance", "Compliance Checker"], ["zerotrust", "Zero Trust Designer"], ["supplychain", "Supply Chain Analyzer"], ["socialeng", "Social Engineering Sim"]]),
  G("utils", "Tools & Utilities", [["credaudit", "Credential Auditor"], ["jwtanalyzer", "JWT Analyzer"], ["cspevaluator", "CSP Evaluator"], ["urldissect", "URL Dissector"], ["encoding", "Encoding Toolkit"], ["cryptotools", "Crypto Toolkit"], ["regexlab", "Regex Lab"], ["cheats", "Cheat Sheets"], ["utils", "Utilities"]]),
  G("ai", "AI & Automation", [["ai", "AI Assistant"], ["coder", "Nexus Agent"], ["engines", "Security Engines"], ["report", "Report Generator"]]),
  G("learn", "Learning", [["learn", "Learn Hub"], ["cyberrange", "Cyber Range"], ["training", "Training Labs"], ["secquiz", "Security Training"], ["refs", "References"], ["snippets", "Code Snippets"], ["targets", "Practice Targets"], ["vms", "Vulnerable VMs"], ["vmlab", "VM Lab"]]),
  G("platform", "Platform", [["arsenal", "External Resources"], ["downloads", "Darknode OS"], ["dlguide", "Download Guide"], ["setup", "Local Setup"], ["privatecloud", "Private Cloud"], ["github", "GitHub"], ["api", "API"], ["docs", "Documentation"], ["gmail", "Gmail"], ["settings", "Settings"], ["apikeys", "API Keys"], ["saved", "Saved Items"], ["contact", "Contact / Feedback"]]),
];
const ADMIN = G("admin", "Admin", [["admin", "Admin Console"]]);

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const groups = (isOwner) => (isOwner ? [...NAV, ADMIN] : NAV);
const LABELS = new Map([...NAV, ADMIN].flatMap((g) => g.items.map((i) => [i.sec, i.label])));
const GROUP_OF = new Map([...NAV, ADMIN].flatMap((g) => g.items.map((i) => [i.sec, g.name])));
export const labelOf = (sec) => LABELS.get(sec) || sec.charAt(0).toUpperCase() + sec.slice(1);

const load = (k) => { try { const v = JSON.parse(localStorage.getItem(k) || "[]"); return Array.isArray(v) ? v.filter((s) => LABELS.has(s)) : []; } catch (_) { return []; } };
const save = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch (_) {} };
const FAV_KEY = "sw_favs", RECENT_KEY = "sw_recent";
const DEFAULT_FAVS = ["tools", "threat", "ai", "cheats", "learn"];
const favs = () => { const f = load(FAV_KEY); return f.length || _favsTouched() ? f : DEFAULT_FAVS; };
const _favsTouched = () => { try { return localStorage.getItem(FAV_KEY) !== null; } catch (_) { return false; } };
const chip = (sec, cls = "") => `<button class="con-chip ${cls}" data-sec="${esc(sec)}" title="${esc(GROUP_OF.get(sec) || "")}">${esc(labelOf(sec))}</button>`;

export function consoleHTML(isOwner) {
  const gs = groups(isOwner);
  const total = gs.reduce((n, g) => n + g.items.length, 0);
  return `
  <div class="con-top">
    <div class="con-bar" role="navigation" aria-label="Console">
      <button class="con-services" id="conServices" aria-expanded="false" aria-controls="sidebar"><span class="con-grid-ic" aria-hidden="true"></span>Services<span class="con-caret" aria-hidden="true">▾</span></button>
      <label class="con-search"><span class="sr-only">Find a service</span>
        <input id="conSearch" type="search" placeholder="Search ${total} services — type a name, e.g. &quot;dns&quot;" autocomplete="off" spellcheck="false">
        <kbd>/</kbd>
      </label>
      <div class="con-quick" aria-label="Shortcuts">
        <button class="con-qbtn" data-sec="home" title="Console Home">Home</button>
        <button class="con-qbtn" data-sec="docs" title="Documentation">Docs</button>
        <button class="con-qbtn" data-sec="apikeys" title="API Keys">Keys</button>
        <button class="con-qbtn" data-sec="saved" title="Saved Items">Saved</button>
        <button class="con-qbtn" data-sec="settings" title="Settings">Settings</button>
      </div>
    </div>
    <div class="con-favbar" aria-label="Favorites">
      <span class="con-favlbl">★ Favorites</span><span class="con-favs" id="conFavs"></span>
      <span class="con-favlbl con-reclbl">Recent</span><span class="con-favs" id="conRecent"></span>
    </div>
  <aside class="svc-menu" id="sidebar" aria-label="All services">
    <div class="svc-cols">
      <nav class="svc-cats" aria-label="Service categories">
        <button class="svc-cat on" data-cat="recent">Recently visited</button>
        <button class="svc-cat" data-cat="favs">Favorites</button>
        <button class="svc-cat" data-cat="all">All services <span class="svc-n">${total}</span></button>
        <div class="svc-cat-div"></div>
        ${gs.map((g) => `<button class="svc-cat" data-cat="${g.id}">${esc(g.name)} <span class="svc-n">${g.items.length}</span></button>`).join("")}
      </nav>
      <div class="svc-pane">
        <div class="svc-hint" id="svcHint"></div>
        <div class="svc-list" id="svcSpecial"></div>
        <div class="side-nav svc-groups" id="svcGroups">
          ${gs.map((g) => `<section class="svc-group" data-g="${g.id}"><div class="svc-gh" role="heading" aria-level="3">${esc(g.name)}</div><div class="svc-items">
            ${g.items.map((i) => `<div class="svc-card" data-card="${i.sec}"><button class="side-item" data-sec="${i.sec}">${esc(i.label)}</button><button class="svc-star" data-star="${i.sec}" aria-label="Pin ${esc(i.label)} to favorites">☆</button></div>`).join("")}
          </div></section>`).join("")}
        </div>
      </div>
    </div>
  </aside>
  </div>`;
}

// Big home-page directory: every category as a panel, every service as a button.
export function directoryHTML(isOwner) {
  const gs = groups(isOwner);
  return `
  <div class="con-dir">
    <div class="con-dir-h"><h2 class="pg-h2">All services</h2><span class="muted">Click any service to open it. Click ☆ in the Services menu to pin it to your favorites bar.</span></div>
    <div class="con-dir-grid">
      ${gs.map((g) => `<div class="panel con-dir-panel"><div class="con-dir-ph"><strong>${esc(g.name)}</strong><span class="svc-n">${g.items.length}</span></div>
        <div class="con-dir-items">${g.items.map((i) => `<button class="con-dir-item" data-sec="${i.sec}">${esc(i.label)}<span aria-hidden="true">›</span></button>`).join("")}</div></div>`).join("")}
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
  const setOpen = (o) => {
    menu.classList.toggle("open", o);
    btn.setAttribute("aria-expanded", String(o));
    if (o) render();
  };
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
    special.hidden = !!showGroups;
    groupsEl.hidden = !showGroups;
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
  menu.querySelector(".svc-cats").addEventListener("click", (e) => {
    const c = e.target.closest(".svc-cat"); if (!c) return;
    cat = c.dataset.cat; search.value = ""; render();
  });
  menu.querySelector(".svc-cats").addEventListener("mouseover", (e) => {
    const c = e.target.closest(".svc-cat"); if (!c || search.value || !matchMedia("(hover:hover)").matches) return;
    if (cat !== c.dataset.cat) { cat = c.dataset.cat; render(); }
  });
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
  document.addEventListener("click", (e) => {
    if (isOpen() && !e.target.closest("#sidebar, .con-bar, #hamburger")) setOpen(false);
  });
  renderBars();

  return {
    // Called on every navigation: remember the visit, close the menu.
    track(sec) {
      if (LABELS.has(sec) && sec !== "home") {
        const r = load(RECENT_KEY).filter((s) => s !== sec); r.unshift(sec); save(RECENT_KEY, r.slice(0, 12));
      }
      search.value = ""; setOpen(false); renderBars();
    },
  };
}
