// ============================================================================
// Darknode Deck — a living command constellation (admin-only preview).
//
// NOT a desktop clone. The Deck is a spatial "connection hub": Darknode glows at
// the core and the services it can work with — AI models and cybersecurity
// platforms — orbit it as real-logo chips. Connect one and a luminous energy
// link is drawn to the core; the connection persists locally. A second scene
// organises every internal Darknode tool, and Spotlight (Ctrl/Cmd+K) jumps to
// anything. Self-contained, dependency-free, no emojis.
//
//   renderDeck(host, { groups, onOpen, onExit }) -> teardown()
//     groups : [{ name, color, items:[{sec,label,badge}] }]  (internal tools)
//     onOpen : (sec) => void   // navigate the real console to a tool
//     onExit : () => void      // leave the deck
// ============================================================================

const LS_CONN = "dn_deck_connections_v1";

// ---- the services Darknode can connect to. domain drives the live favicon ----
const INTEGRATIONS = [
  // AI models / agents
  { id: "claude",     name: "Claude",        domain: "claude.ai",          kind: "ai",  accent: "#d97757", connect: "key",  blurb: "Anthropic's Claude — reasoning, agentic coding, long-context analysis." },
  { id: "openai",     name: "OpenAI",        domain: "openai.com",         kind: "ai",  accent: "#10a37f", connect: "key",  blurb: "GPT models via the OpenAI API for generation and tool use." },
  { id: "gemini",     name: "Gemini",        domain: "gemini.google.com",  kind: "ai",  accent: "#4285f4", connect: "key",  blurb: "Google Gemini multimodal models through the Generative Language API." },
  { id: "perplexity", name: "Perplexity",    domain: "perplexity.ai",      kind: "ai",  accent: "#20b8cd", connect: "key",  blurb: "Answer engine with live web grounding and citations." },
  { id: "mistral",    name: "Mistral",       domain: "mistral.ai",         kind: "ai",  accent: "#fa5010", connect: "key",  blurb: "Open-weight European models via the Mistral API." },
  { id: "groq",       name: "Groq",          domain: "groq.com",           kind: "ai",  accent: "#f55036", connect: "key",  blurb: "Ultra-low-latency inference for open models." },
  { id: "openrouter", name: "OpenRouter",    domain: "openrouter.ai",      kind: "ai",  accent: "#6467f2", connect: "key",  blurb: "One key, hundreds of models routed on demand." },
  { id: "huggingface",name: "Hugging Face",  domain: "huggingface.co",     kind: "ai",  accent: "#ffcc4d", connect: "key",  blurb: "Open models and inference endpoints from the Hub." },
  { id: "ollama",     name: "Ollama",        domain: "ollama.com",         kind: "ai",  accent: "#ededed", connect: "link", blurb: "Run local open models through the Darknode CLI bridge." },
  { id: "xai",        name: "xAI Grok",      domain: "x.ai",               kind: "ai",  accent: "#ffffff", connect: "key",  blurb: "xAI Grok models via API." },
  // cybersecurity platforms / intel sources
  { id: "virustotal", name: "VirusTotal",    domain: "virustotal.com",     kind: "sec", accent: "#394eff", connect: "key",  blurb: "File, URL, domain and IP reputation across 70+ engines." },
  { id: "shodan",     name: "Shodan",        domain: "shodan.io",          kind: "sec", accent: "#e51e25", connect: "key",  blurb: "Internet-exposed host and service intelligence." },
  { id: "censys",     name: "Censys",        domain: "censys.io",          kind: "sec", accent: "#3c6df0", connect: "key",  blurb: "Attack-surface and certificate search." },
  { id: "hibp",       name: "Have I Been Pwned", domain: "haveibeenpwned.com", kind: "sec", accent: "#2a6bb3", connect: "key", blurb: "Breach and credential-exposure lookups." },
  { id: "greynoise",  name: "GreyNoise",     domain: "greynoise.io",       kind: "sec", accent: "#00c389", connect: "key",  blurb: "Context on internet background noise and mass scanners." },
  { id: "abuseipdb",  name: "AbuseIPDB",     domain: "abuseipdb.com",      kind: "sec", accent: "#1f9d55", connect: "key",  blurb: "Crowd-sourced IP abuse reporting and scoring." },
  { id: "otx",        name: "AlienVault OTX",domain: "otx.alienvault.com", kind: "sec", accent: "#00a4e4", connect: "key",  blurb: "Open Threat Exchange pulses and indicators." },
  { id: "abusech",    name: "abuse.ch",      domain: "abuse.ch",           kind: "sec", accent: "#e2001a", connect: "link", blurb: "URLhaus, ThreatFox and MalwareBazaar feeds." },
  { id: "urlscan",    name: "urlscan.io",    domain: "urlscan.io",         kind: "sec", accent: "#5a67d8", connect: "key",  blurb: "Scan and dissect any URL in a sandbox." },
  { id: "mitre",      name: "MITRE ATT&CK",  domain: "attack.mitre.org",   kind: "sec", accent: "#d93a3a", connect: "link", blurb: "Adversary tactics & techniques knowledge base." },
  { id: "nvd",        name: "NVD",           domain: "nvd.nist.gov",       kind: "sec", accent: "#1b6ec2", connect: "link", blurb: "National Vulnerability Database — CVE + CVSS." },
  { id: "circl",      name: "CIRCL CVE",     domain: "cve.circl.lu",       kind: "sec", accent: "#cc3333", connect: "link", blurb: "Fast CVE search and vulnerability metadata." },
];

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
function monogram(name) {
  const w = String(name).replace(/[^A-Za-z0-9 ]/g, " ").trim().split(/\s+/).filter(Boolean);
  if (!w.length) return "DN";
  if (w.length === 1) return w[0].slice(0, 2).toUpperCase();
  return (w[0][0] + w[1][0]).toUpperCase();
}
const COLORS = { blue:"#3f78ff", cyan:"#19b6d8", orange:"#f5920b", red:"#ef4444", green:"#22b765", purple:"#9b5cf0", violet:"#7b61ff", emerald:"#10b981", slate:"#6b7a90", teal:"#14b8a6", pink:"#ec4899", amber:"#f59e0b", indigo:"#5b6cf0", rose:"#f4466b", lime:"#84cc16", sky:"#0ea5e9" };
const hexOf = (c) => COLORS[c] || "#5b6cf0";
function shade(hex, pct){ const n=parseInt(hex.slice(1),16); let r=(n>>16)&255,g=(n>>8)&255,b=n&255; const f=pct/100; r=Math.round(r+(f<0?r:255-r)*f); g=Math.round(g+(f<0?g:255-g)*f); b=Math.round(b+(f<0?b:255-b)*f); return "#"+((1<<24)+(r<<16)+(g<<8)+b).toString(16).slice(1); }
const faviconURL = (domain) => `https://icons.duckduckgo.com/ip3/${domain}.ico`;

// logo chip: live favicon with monogram fallback on error
function logoHTML(it, cls){
  return `<img class="${cls} logo" src="${faviconURL(it.domain)}" alt="" loading="lazy" referrerpolicy="no-referrer"
    onerror="this.outerHTML='<span class=\\'${cls} mono\\' style=\\'--a:${it.accent}\\'>${esc(monogram(it.name))}</span>'">`;
}

function loadConns(){ try { return JSON.parse(localStorage.getItem(LS_CONN) || "{}") || {}; } catch (_) { return {}; } }
function saveConns(c){ try { localStorage.setItem(LS_CONN, JSON.stringify(c)); } catch (_) {} }

const CSS = `
.dk{position:fixed;inset:0;z-index:99999;overflow:hidden;isolation:isolate;color:#eaf0fb;background:#060912;
  font:14px/1.55 "Space Grotesk",-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;-webkit-font-smoothing:antialiased;user-select:none}
.dk *{box-sizing:border-box;margin:0}
.dk-sky{position:absolute;inset:0;z-index:0;pointer-events:none;
  background:
    radial-gradient(90% 60% at 50% 42%, #10203f 0%, rgba(16,32,63,0) 60%),
    radial-gradient(60% 50% at 82% 88%, #241048 0%, rgba(36,16,72,0) 55%),
    radial-gradient(60% 50% at 14% 12%, #07323f 0%, rgba(7,50,63,0) 55%),
    linear-gradient(160deg,#070b16,#05070f 72%,#04050b)}
.dk-stars{position:absolute;inset:0;z-index:0;pointer-events:none;opacity:.6}
/* ---------- top chrome ---------- */
.dk-top{position:absolute;top:0;left:0;right:0;height:56px;z-index:40;display:flex;align-items:center;gap:20px;padding:0 24px}
.dk-brand{display:flex;align-items:center;gap:11px;font-weight:700;letter-spacing:.14em;font-size:13px;text-transform:uppercase}
.dk-brand .orb{width:16px;height:16px;border-radius:50%;background:radial-gradient(circle at 35% 30%,#8fd0ff,#2f63ff 55%,#121a44);box-shadow:0 0 14px #3f78ff}
.dk-seg{display:flex;gap:4px;padding:4px;border-radius:13px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.08)}
.dk-seg button{appearance:none;border:0;background:transparent;color:#aab6cf;font:inherit;font-size:13px;font-weight:600;padding:6px 16px;border-radius:9px;cursor:pointer;letter-spacing:.02em}
.dk-seg button.on{background:linear-gradient(180deg,rgba(63,120,255,.9),rgba(47,99,255,.75));color:#fff;box-shadow:0 4px 14px rgba(47,99,255,.4)}
.dk-right{margin-left:auto;display:flex;align-items:center;gap:14px}
.dk-find{display:flex;align-items:center;gap:9px;padding:8px 14px;border-radius:11px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);color:#94a3bd;font-size:13px;cursor:pointer;min-width:220px}
.dk-find:hover{border-color:rgba(255,255,255,.22)}
.dk-find kbd{margin-left:auto;font:inherit;font-size:11px;background:rgba(255,255,255,.1);padding:2px 7px;border-radius:6px}
.dk-find svg{width:15px;height:15px}
.dk-clock{font-variant-numeric:tabular-nums;color:#9fb0cc;font-size:13px}
.dk-quit{cursor:pointer;color:#c3cde0;font-size:13px;font-weight:600;padding:7px 14px;border-radius:10px;border:1px solid rgba(255,255,255,.12)}
.dk-quit:hover{background:rgba(255,255,255,.08)}
.dk-scene{position:absolute;inset:56px 0 0;z-index:10}
.dk-scene[hidden]{display:none}
/* ---------- constellation ---------- */
.dk-con{position:absolute;inset:0;overflow:hidden}
.dk-links{position:absolute;inset:0;z-index:1;pointer-events:none}
.dk-links line{stroke-width:1.6;stroke-linecap:round;opacity:0;transition:opacity .5s}
.dk-links line.on{opacity:.85;stroke-dasharray:5 7;animation:dkFlow 1.1s linear infinite}
@keyframes dkFlow{to{stroke-dashoffset:-24}}
.dk-core{position:absolute;z-index:3;left:50%;top:50%;transform:translate(-50%,-50%);width:120px;height:120px;border-radius:50%;
  display:grid;place-items:center;text-align:center;cursor:default;
  background:radial-gradient(circle at 38% 32%,#bfe0ff 0%,#4f86ff 34%,#1f3b96 70%,#0b1444 100%);
  box-shadow:0 0 0 1px rgba(255,255,255,.2),0 0 60px rgba(63,120,255,.55),0 0 140px rgba(63,120,255,.3),inset 0 2px 14px rgba(255,255,255,.4)}
.dk-core b{font-size:13px;font-weight:700;letter-spacing:.1em;color:#fff;text-shadow:0 1px 6px rgba(0,0,0,.5)}
.dk-core span{font-size:10px;color:rgba(255,255,255,.78);letter-spacing:.14em}
.dk-core::after{content:"";position:absolute;inset:-18px;border-radius:50%;border:1px solid rgba(143,200,255,.3);animation:dkPulse 3.6s ease-out infinite}
@keyframes dkPulse{0%{transform:scale(.86);opacity:.7}100%{transform:scale(1.5);opacity:0}}
.dk-node{position:absolute;z-index:3;width:92px;transform:translate(-50%,-50%);display:flex;flex-direction:column;align-items:center;gap:7px;cursor:pointer;
  transition:transform .25s cubic-bezier(.2,.9,.3,1.3)}
.dk-node:hover{transform:translate(-50%,-50%) scale(1.14)}
.dk-chip{position:relative;width:64px;height:64px;border-radius:19px;display:grid;place-items:center;
  background:rgba(18,23,38,.72);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);
  border:1px solid rgba(255,255,255,.12);box-shadow:0 10px 26px rgba(0,0,0,.5);overflow:hidden}
.dk-chip .logo{width:36px;height:36px;border-radius:9px;object-fit:contain;background:#fff;padding:3px}
.dk-chip .mono{width:40px;height:40px;border-radius:11px;display:grid;place-items:center;font-weight:700;font-size:15px;color:#fff;
  background:linear-gradient(160deg,var(--a,#5b6cf0),rgba(0,0,0,.35))}
.dk-node.conn .dk-chip{border-color:rgba(120,220,170,.75);box-shadow:0 0 0 1px rgba(120,220,170,.5),0 10px 30px rgba(20,160,110,.35),0 0 22px rgba(40,200,140,.4)}
.dk-node .nm{font-size:11.5px;font-weight:500;color:#cdd8ec;text-align:center;text-shadow:0 1px 4px rgba(0,0,0,.7);line-height:1.2}
.dk-node .st{position:absolute;top:-4px;right:12px;width:14px;height:14px;border-radius:50%;background:#15c47e;border:2px solid #0a1220;display:none;box-shadow:0 0 8px #15c47e}
.dk-node.conn .st{display:block}
.dk-ringlbl{position:absolute;z-index:2;left:50%;transform:translateX(-50%);font-size:10.5px;letter-spacing:.3em;text-transform:uppercase;color:rgba(190,205,230,.4);font-weight:600}
/* mobile fallback list */
.dk-conlist{display:none;position:absolute;inset:0;overflow:auto;padding:18px}
.dk-conlist h4{margin:14px 6px 8px;font-size:11px;letter-spacing:.22em;text-transform:uppercase;color:#8795b3}
.dk-conlist .row{display:flex;align-items:center;gap:13px;padding:12px;border-radius:14px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);margin-bottom:8px;cursor:pointer}
.dk-conlist .row .logo{width:34px;height:34px;border-radius:9px;background:#fff;padding:3px;object-fit:contain}
.dk-conlist .row .mono{width:34px;height:34px;border-radius:9px;display:grid;place-items:center;font-weight:700;color:#fff;background:linear-gradient(160deg,var(--a,#5b6cf0),rgba(0,0,0,.35))}
.dk-conlist .row .meta{flex:1;min-width:0}
.dk-conlist .row .meta b{font-size:14px}.dk-conlist .row .meta p{font-size:11.5px;color:#93a0bb;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
/* ---------- detail drawer ---------- */
.dk-drawer{position:absolute;top:0;right:0;bottom:0;width:360px;max-width:90vw;z-index:30;transform:translateX(104%);transition:transform .34s cubic-bezier(.2,.9,.3,1.1);
  background:rgba(13,17,28,.9);backdrop-filter:blur(34px) saturate(170%);-webkit-backdrop-filter:blur(34px) saturate(170%);
  border-left:1px solid rgba(255,255,255,.12);box-shadow:-30px 0 80px rgba(0,0,0,.55);padding:26px 24px;overflow:auto}
.dk-drawer.on{transform:none}
.dk-drawer .x{position:absolute;top:16px;right:18px;cursor:pointer;color:#9fb0cc;font-size:20px;line-height:1}
.dk-dhead{display:flex;align-items:center;gap:14px;margin:6px 0 16px}
.dk-dhead .logo{width:54px;height:54px;border-radius:14px;background:#fff;padding:5px;object-fit:contain}
.dk-dhead .mono{width:54px;height:54px;border-radius:14px;display:grid;place-items:center;font-weight:700;font-size:20px;color:#fff;background:linear-gradient(160deg,var(--a,#5b6cf0),rgba(0,0,0,.4))}
.dk-dhead h3{font-size:19px}.dk-dhead .k{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:#8795b3}
.dk-drawer p.blurb{font-size:13px;color:#aeb9d2;margin-bottom:18px}
.dk-stat{display:inline-flex;align-items:center;gap:7px;font-size:12px;font-weight:600;padding:6px 12px;border-radius:999px;margin-bottom:18px}
.dk-stat.off{background:rgba(255,255,255,.07);color:#aab6cf}.dk-stat.on{background:rgba(21,196,126,.16);color:#54e3a6}
.dk-stat .d{width:7px;height:7px;border-radius:50%;background:currentColor}
.dk-drawer .act{display:flex;flex-direction:column;gap:10px}
.dk-b{display:flex;align-items:center;justify-content:center;gap:8px;padding:11px 16px;border-radius:12px;border:1px solid rgba(255,255,255,.14);background:rgba(255,255,255,.06);color:#eaf0fb;font:inherit;font-weight:600;font-size:13.5px;cursor:pointer}
.dk-b:hover{background:rgba(255,255,255,.12)}
.dk-b.pri{background:linear-gradient(180deg,#3f78ff,#2f5fff);border-color:#2f5fff;color:#fff;box-shadow:0 8px 22px rgba(47,95,255,.4)}
.dk-b.dis{background:rgba(239,68,68,.14);border-color:rgba(239,68,68,.4);color:#ff9b9b}
.dk-note{font-size:11.5px;color:#7e8aa6;margin-top:16px;line-height:1.5}
/* ---------- tools scene ---------- */
.dk-tools{position:absolute;inset:0;overflow:auto;padding:30px 5vw 60px;column-count:3;column-gap:22px}
@media(max-width:1100px){.dk-tools{column-count:2}}
@media(max-width:720px){.dk-tools{column-count:1}}
.dk-cat{break-inside:avoid;margin-bottom:22px;border-radius:18px;padding:18px 18px 14px;
  background:rgba(255,255,255,.035);border:1px solid rgba(255,255,255,.08);box-shadow:0 10px 30px rgba(0,0,0,.35)}
.dk-cat h3{display:flex;align-items:center;gap:10px;font-size:14px;margin-bottom:14px}
.dk-cat h3 .d{width:10px;height:10px;border-radius:3px}
.dk-cat h3 .c{margin-left:auto;font-size:11px;color:#7e8aa6;font-weight:500}
.dk-chiplist{display:flex;flex-wrap:wrap;gap:8px}
.dk-tool{font-size:12.5px;padding:7px 12px;border-radius:9px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.08);cursor:pointer;color:#d6deef;display:inline-flex;align-items:center;gap:6px}
.dk-tool:hover{background:rgba(63,120,255,.22);border-color:rgba(63,120,255,.5)}
.dk-tool .live{width:6px;height:6px;border-radius:50%;background:#30d158;box-shadow:0 0 6px #30d158}
/* ---------- spotlight ---------- */
.dk-spot{position:absolute;inset:0;z-index:90;display:none;align-items:flex-start;justify-content:center;padding-top:15vh;background:rgba(3,6,13,.5)}
.dk-spot.on{display:flex}
.dk-sbox{width:min(640px,92vw);border-radius:18px;overflow:hidden;background:rgba(17,22,36,.92);backdrop-filter:blur(40px) saturate(180%);-webkit-backdrop-filter:blur(40px) saturate(180%);border:1px solid rgba(255,255,255,.14);box-shadow:0 40px 120px rgba(0,0,0,.7)}
.dk-srow{display:flex;align-items:center;gap:12px;padding:16px 18px;border-bottom:1px solid rgba(255,255,255,.1)}
.dk-srow svg{width:20px;height:20px;opacity:.55}
.dk-sbox input{flex:1;border:0;outline:0;background:transparent;color:#fff;font:inherit;font-size:19px}
.dk-sres{max-height:48vh;overflow:auto;padding:6px}
.dk-sr{display:flex;align-items:center;gap:12px;padding:9px 12px;border-radius:11px;cursor:pointer}
.dk-sr.sel,.dk-sr:hover{background:rgba(63,120,255,.26)}
.dk-sr .ic{width:30px;height:30px;border-radius:8px;flex:none;display:grid;place-items:center;font-size:11px;font-weight:700;color:#fff;background:linear-gradient(160deg,var(--a,#5b6cf0),rgba(0,0,0,.35));overflow:hidden}
.dk-sr .ic img{width:22px;height:22px;object-fit:contain;background:#fff;border-radius:5px;padding:2px}
.dk-sr .ic .mono{width:100%;height:100%;display:grid;place-items:center}
.dk-sr .l{font-size:13.5px}.dk-sr .g{margin-left:auto;font-size:11px;color:#8795b3}
.dk-empty{padding:26px;text-align:center;color:#7e8aa6;font-size:13px}
`;
const IC_SEARCH = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.2-3.2"/></svg>';

export function renderDeck(host, opts) {
  opts = opts || {};
  const groups = (opts.groups || []).filter((g) => g.items && g.items.length);
  const onOpen = typeof opts.onOpen === "function" ? opts.onOpen : () => {};
  const onExit = typeof opts.onExit === "function" ? opts.onExit : () => {};
  const toast = (m) => { try { (window.showToast || window.dnToast)?.(m); } catch (_) {} };

  // flat index for spotlight: tools + integrations
  const index = [];
  for (const g of groups) for (const it of g.items) index.push({ type: "tool", sec: it.sec, label: it.label, group: g.name, color: g.color, badge: it.badge });
  for (const it of INTEGRATIONS) index.push({ type: "conn", id: it.id, label: it.name, group: it.kind === "ai" ? "AI model" : "Security", it });

  let conns = loadConns();

  if (!document.getElementById("dk-css")) { const st = document.createElement("style"); st.id = "dk-css"; st.textContent = CSS; document.head.appendChild(st); }
  // Space Grotesk is optional polish; falls back to system fonts if offline
  if (!document.getElementById("dk-font")) { const l = document.createElement("link"); l.id = "dk-font"; l.rel = "stylesheet"; l.href = "https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&display=swap"; document.head.appendChild(l); }

  const root = document.createElement("div");
  root.className = "dk";
  root.innerHTML = `
    <div class="dk-sky"></div>
    <canvas class="dk-stars" id="dkStars"></canvas>
    <div class="dk-top">
      <div class="dk-brand"><span class="orb"></span>Darknode Deck</div>
      <div class="dk-seg">
        <button data-scene="con" class="on">Connections</button>
        <button data-scene="tools">Tools</button>
      </div>
      <div class="dk-right">
        <div class="dk-find" id="dkFind">${IC_SEARCH}<span>Search tools &amp; services</span><kbd>Ctrl K</kbd></div>
        <span class="dk-clock" id="dkClock"></span>
        <span class="dk-quit" id="dkQuit">Exit</span>
      </div>
    </div>

    <div class="dk-scene" id="dkCon">
      <div class="dk-con" id="dkConCanvas">
        <svg class="dk-links" id="dkLinks"></svg>
        <div class="dk-core"><div><b>DARKNODE</b><br><span id="dkCoreCount"></span></div></div>
      </div>
      <div class="dk-conlist" id="dkConList"></div>
    </div>

    <div class="dk-scene dk-tools" id="dkTools" hidden></div>

    <aside class="dk-drawer" id="dkDrawer"><span class="x" id="dkDrawerX">&times;</span><div id="dkDrawerBody"></div></aside>

    <div class="dk-spot" id="dkSpot">
      <div class="dk-sbox">
        <div class="dk-srow">${IC_SEARCH}<input id="dkSpotIn" placeholder="Jump to a tool or a service…" autocomplete="off" spellcheck="false"></div>
        <div class="dk-sres" id="dkSpotRes"></div>
      </div>
    </div>`;
  (host || document.body).appendChild(root);
  const $ = (s) => root.querySelector(s);

  // clock
  const clock = $("#dkClock");
  const tick = () => { clock.textContent = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); };
  tick(); const clockId = setInterval(tick, 20000);

  // starfield
  const stars = $("#dkStars"); const sctx = stars.getContext("2d"); let pts = [], rafId = 0;
  function sizeStars(){ stars.width = root.clientWidth; stars.height = root.clientHeight; pts = Array.from({length: Math.min(140, Math.round(stars.width*stars.height/16000))}, () => ({ x: Math.random()*stars.width, y: Math.random()*stars.height, r: Math.random()*1.3+.2, a: Math.random()*6.28, s: Math.random()*.02+.004 })); }
  function drawStars(){ sctx.clearRect(0,0,stars.width,stars.height); for (const p of pts){ p.a += p.s; const a = .35 + Math.abs(Math.sin(p.a))*.5; sctx.beginPath(); sctx.arc(p.x,p.y,p.r,0,7); sctx.fillStyle = `rgba(180,210,255,${a})`; sctx.fill(); } rafId = requestAnimationFrame(drawStars); }
  sizeStars(); drawStars();

  // ---------- scene switching ----------
  const sceneCon = $("#dkCon"), sceneTools = $("#dkTools");
  root.querySelectorAll(".dk-seg button").forEach((b) => b.onclick = () => {
    root.querySelectorAll(".dk-seg button").forEach((x) => x.classList.toggle("on", x === b));
    const s = b.dataset.scene;
    sceneCon.hidden = s !== "con"; sceneTools.hidden = s !== "tools";
    if (s === "con") layoutConstellation();
  });

  // ---------- constellation ----------
  const canvas = $("#dkConCanvas"), links = $("#dkLinks"), coreCount = $("#dkCoreCount"), conList = $("#dkConList");
  const ai = INTEGRATIONS.filter((i) => i.kind === "ai");
  const sec = INTEGRATIONS.filter((i) => i.kind === "sec");

  function nodeHTML(it){
    const c = conns[it.id]?.connected;
    return `<div class="dk-node${c ? " conn" : ""}" data-id="${it.id}">
      <div class="dk-chip">${logoHTML(it, "")}<span class="st"></span></div>
      <div class="nm">${esc(it.name)}</div>
    </div>`;
  }
  function buildNodes(){
    canvas.querySelectorAll(".dk-node,.dk-ringlbl").forEach((n) => n.remove());
    const frag = document.createElement("div"); frag.innerHTML = ai.concat(sec).map(nodeHTML).join("");
    while (frag.firstChild) canvas.appendChild(frag.firstChild);
    canvas.querySelectorAll(".dk-node").forEach((n) => n.onclick = () => openDrawer(INTEGRATIONS.find((i) => i.id === n.dataset.id)));
  }
  buildNodes();

  function layoutConstellation(){
    const W = canvas.clientWidth, H = canvas.clientHeight;
    const narrow = W < 720;
    canvas.style.display = narrow ? "none" : "";
    conList.style.display = narrow ? "block" : "none";
    coreCount.textContent = `${countConnected()} linked`;
    if (narrow) { renderConList(); return; }
    const cx = W/2, cy = H/2;
    const R = Math.max(130, Math.min(W, H) * 0.5 - 90);
    const r1 = Math.min(R*0.62, 260), r2 = R;
    place(ai, r1, cx, cy); place(sec, r2, cx, cy);
    drawLinks(cx, cy);
  }
  function place(list, r, cx, cy){
    const n = list.length, start = -Math.PI/2;
    list.forEach((it, i) => {
      const ang = start + (i / n) * Math.PI * 2;
      const x = cx + Math.cos(ang) * r, y = cy + Math.sin(ang) * r;
      const el = canvas.querySelector(`.dk-node[data-id="${it.id}"]`);
      if (el){ el.style.left = x + "px"; el.style.top = y + "px"; el.__x = x; el.__y = y; }
    });
  }
  function drawLinks(cx, cy){
    links.setAttribute("viewBox", `0 0 ${canvas.clientWidth} ${canvas.clientHeight}`);
    links.innerHTML = INTEGRATIONS.map((it) => {
      const el = canvas.querySelector(`.dk-node[data-id="${it.id}"]`); if (!el) return "";
      const on = conns[it.id]?.connected;
      return `<line x1="${cx}" y1="${cy}" x2="${el.__x}" y2="${el.__y}" class="${on ? "on" : ""}" stroke="${on ? "#38d99a" : "rgba(255,255,255,.12)"}"/>`;
    }).join("");
  }
  function renderConList(){
    const grp = (title, list) => `<h4>${title}</h4>` + list.map((it) => {
      const c = conns[it.id]?.connected;
      return `<div class="row" data-id="${it.id}">${logoHTML(it, "")}<div class="meta"><b>${esc(it.name)}</b><p>${esc(it.blurb)}</p></div><span class="dk-stat ${c?"on":"off"}"><span class="d"></span>${c?"Linked":"Connect"}</span></div>`;
    }).join("");
    conList.innerHTML = grp("AI Models", ai) + grp("Cyber Intelligence", sec);
    conList.querySelectorAll(".row").forEach((r) => r.onclick = () => openDrawer(INTEGRATIONS.find((i) => i.id === r.dataset.id)));
  }
  const countConnected = () => INTEGRATIONS.reduce((a, i) => a + (conns[i.id]?.connected ? 1 : 0), 0);

  function refreshConnState(it){
    const c = conns[it.id]?.connected;
    const node = canvas.querySelector(`.dk-node[data-id="${it.id}"]`);
    if (node) node.classList.toggle("conn", !!c);
    coreCount.textContent = `${countConnected()} linked`;
    if (!sceneCon.hidden) { if (canvas.style.display === "none") renderConList(); else layoutConstellation(); }
  }

  // ---------- drawer ----------
  const drawer = $("#dkDrawer"), drawerBody = $("#dkDrawerBody");
  function openDrawer(it){
    if (!it) return;
    const rec = conns[it.id] || {};
    const connected = !!rec.connected;
    const kindTxt = it.kind === "ai" ? "AI Model" : "Cyber Intelligence";
    drawerBody.innerHTML = `
      <div class="dk-dhead">${logoHTML(it, "")}<div><h3>${esc(it.name)}</h3><div class="k">${kindTxt}</div></div></div>
      <span class="dk-stat ${connected ? "on" : "off"}"><span class="d"></span>${connected ? "Connected" : "Not connected"}</span>
      <p class="blurb">${esc(it.blurb)}</p>
      <div class="act">
        ${connected
          ? `<button class="dk-b dis" data-act="disc">Disconnect</button>`
          : `<button class="dk-b pri" data-act="conn">${it.connect === "key" ? "Connect with API key" : "Link to Darknode"}</button>`}
        <button class="dk-b" data-act="open">Open ${esc(it.domain)}</button>
        ${it.kind === "ai" && connected ? `<button class="dk-b" data-act="use">Use in Darknode AI</button>` : ""}
      </div>
      <p class="dk-note">${it.connect === "key"
          ? "Your key is stored only in this browser (localStorage) and never leaves your device from here. Darknode routes model calls through its own proxy."
          : "Linking records this service as available to Darknode. No credentials are stored."}</p>`;
    drawer.classList.add("on");
    drawerBody.querySelector('[data-act="open"]').onclick = () => window.open("https://" + it.domain, "_blank", "noopener");
    const connBtn = drawerBody.querySelector('[data-act="conn"]');
    if (connBtn) connBtn.onclick = async () => {
      if (it.connect === "key") {
        let key = "";
        try { key = await (window.dnPrompt ? window.dnPrompt(`Paste your ${it.name} API key`, { title: `Connect ${it.name}`, password: true }) : Promise.resolve("")); } catch (_) { key = ""; }
        if (key === null || key === undefined) return;        // cancelled
        conns[it.id] = { connected: true, hasKey: !!String(key).trim(), at: Date.now() };
        if (String(key).trim()) { try { localStorage.setItem("dn_key_" + it.id, String(key).trim()); } catch (_) {} }
      } else {
        conns[it.id] = { connected: true, at: Date.now() };
      }
      saveConns(conns); toast(`${it.name} connected`); refreshConnState(it); openDrawer(it);
    };
    const discBtn = drawerBody.querySelector('[data-act="disc"]');
    if (discBtn) discBtn.onclick = () => { delete conns[it.id]; saveConns(conns); try { localStorage.removeItem("dn_key_" + it.id); } catch (_) {} toast(`${it.name} disconnected`); refreshConnState(it); openDrawer(it); };
    const useBtn = drawerBody.querySelector('[data-act="use"]');
    if (useBtn) useBtn.onclick = () => { try { localStorage.setItem("dn_ai_pref_provider", it.id); } catch (_) {} toast(`Darknode AI will prefer ${it.name}`); teardown(); onOpen("ai"); };
  }
  $("#dkDrawerX").onclick = () => drawer.classList.remove("on");

  // ---------- tools scene ----------
  sceneTools.innerHTML = groups.map((g) => {
    const h = hexOf(g.color);
    return `<div class="dk-cat"><h3><span class="d" style="background:${h}"></span>${esc(g.name)}<span class="c">${g.items.length}</span></h3>
      <div class="dk-chiplist">${g.items.map((it) => `<span class="dk-tool" data-sec="${esc(it.sec)}">${it.badge === "live" ? '<span class="live"></span>' : ""}${esc(it.label)}</span>`).join("")}</div></div>`;
  }).join("");
  sceneTools.querySelectorAll(".dk-tool").forEach((t) => t.onclick = () => { teardown(); onOpen(t.dataset.sec); });

  // ---------- spotlight ----------
  const spot = $("#dkSpot"), spotIn = $("#dkSpotIn"), spotRes = $("#dkSpotRes");
  let selIdx = 0, matches = [];
  const openSpot = () => { spot.classList.add("on"); spotIn.value = ""; runSpot(""); spotIn.focus(); };
  const closeSpot = () => spot.classList.remove("on");
  function spotIcon(m){
    if (m.type === "conn") return `<span class="ic">${logoHTML(m.it, "")}</span>`;
    return `<span class="ic" style="--a:${hexOf(m.color)}">${esc(monogram(m.label))}</span>`;
  }
  function runSpot(q){
    q = q.trim().toLowerCase();
    matches = (q ? index.filter((t) => t.label.toLowerCase().includes(q) || (t.group||"").toLowerCase().includes(q)) : index).slice(0, 60);
    selIdx = 0;
    spotRes.innerHTML = matches.length ? matches.map((m, i) => `<div class="dk-sr${i===0?" sel":""}" data-i="${i}">${spotIcon(m)}<span class="l">${esc(m.label)}</span><span class="g">${esc(m.group||"")}</span></div>`).join("")
      : `<div class="dk-empty">Nothing matches "${esc(q)}"</div>`;
    spotRes.querySelectorAll(".dk-sr").forEach((r) => r.onclick = () => chooseSpot(+r.dataset.i));
  }
  function chooseSpot(i){ const m = matches[i]; if (!m) return; if (m.type === "conn") { closeSpot(); root.querySelector('.dk-seg button[data-scene="con"]').click(); openDrawer(m.it); } else { teardown(); onOpen(m.sec); } }
  function moveSel(d){ if (!matches.length) return; selIdx = (selIdx + d + matches.length) % matches.length; spotRes.querySelectorAll(".dk-sr").forEach((r, i) => r.classList.toggle("sel", i === selIdx)); spotRes.querySelector(".dk-sr.sel")?.scrollIntoView({ block: "nearest" }); }
  $("#dkFind").onclick = openSpot; spotIn.oninput = () => runSpot(spotIn.value);
  spot.addEventListener("click", (e) => { if (e.target === spot) closeSpot(); });

  // ---------- keyboard ----------
  function onKey(e){
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); spot.classList.contains("on") ? closeSpot() : openSpot(); return; }
    if (spot.classList.contains("on")) {
      if (e.key === "Escape") { e.preventDefault(); closeSpot(); }
      else if (e.key === "ArrowDown") { e.preventDefault(); moveSel(1); }
      else if (e.key === "ArrowUp") { e.preventDefault(); moveSel(-1); }
      else if (e.key === "Enter") { e.preventDefault(); chooseSpot(selIdx); }
      return;
    }
    if (e.key === "Escape") { if (drawer.classList.contains("on")) { drawer.classList.remove("on"); return; } teardown(); onExit(); }
  }
  document.addEventListener("keydown", onKey);
  $("#dkQuit").onclick = () => { teardown(); onExit(); };

  // ---------- resize ----------
  const onResize = () => { sizeStars(); if (!sceneCon.hidden) layoutConstellation(); };
  window.addEventListener("resize", onResize);
  requestAnimationFrame(layoutConstellation);

  function teardown(){ cancelAnimationFrame(rafId); clearInterval(clockId); document.removeEventListener("keydown", onKey); window.removeEventListener("resize", onResize); root.remove(); }
  return teardown;
}
