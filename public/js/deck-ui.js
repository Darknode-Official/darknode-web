// ============================================================================
// Darknode Command — a living command constellation (admin-only preview).
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

import { startOpenRouterConnect } from "/js/openrouter-connect.js?v=20261010c";
// Platform event bus (singleton — never version its import, or a second instance
// would miss every event the rest of the app emits). Drives the live Activity
// stream and the notifications bell.
import { bus, EVENTS } from "/js/core/bus.js";

const LS_CONN = "dn_deck_connections_v1";
const LS_SCENE = "dn_deck_scene";          // last workspace the operator was on
const LS_NOTIF_SEEN = "dn_deck_notif_seen"; // ts of the last notification they read

// ---- the services Darknode can connect to. domain drives the live favicon ----
const INTEGRATIONS = [
  // AI models / agents
  { id: "claude",     name: "Claude",        domain: "claude.ai",          kind: "ai",  accent: "#d97757", connect: "key", account: true,  blurb: "Anthropic's Claude — reasoning, agentic coding, long-context analysis." },
  { id: "openai",     name: "OpenAI",        domain: "openai.com",         kind: "ai",  accent: "#10a37f", connect: "key", account: true,  blurb: "GPT models via the OpenAI API for generation and tool use." },
  { id: "gemini",     name: "Gemini",        domain: "gemini.google.com",  kind: "ai",  accent: "#4285f4", connect: "key", account: true,  blurb: "Google Gemini multimodal models through the Generative Language API." },
  { id: "perplexity", name: "Perplexity",    domain: "perplexity.ai",      kind: "ai",  accent: "#20b8cd", connect: "key", account: true,  blurb: "Answer engine with live web grounding and citations." },
  { id: "mistral",    name: "Mistral",       domain: "mistral.ai",         kind: "ai",  accent: "#fa5010", connect: "key", account: true,  blurb: "Open-weight European models via the Mistral API." },
  { id: "groq",       name: "Groq",          domain: "groq.com",           kind: "ai",  accent: "#f55036", connect: "key",  blurb: "Ultra-low-latency inference for open models." },
  { id: "openrouter", name: "OpenRouter",    domain: "openrouter.ai",      kind: "ai",  accent: "#6467f2", connect: "key",  blurb: "One key, hundreds of models routed on demand." },
  { id: "huggingface",name: "Hugging Face",  domain: "huggingface.co",     kind: "ai",  accent: "#ffcc4d", connect: "key",  blurb: "Open models and inference endpoints from the Hub." },
  { id: "ollama",     name: "Ollama",        domain: "ollama.com",         kind: "ai",  accent: "#ededed", connect: "link", blurb: "Run local open models through the Darknode CLI bridge." },
  { id: "xai",        name: "xAI Grok",      domain: "x.ai",               kind: "ai",  accent: "#ffffff", connect: "key", account: true,  blurb: "xAI Grok models via API." },
  { id: "deepseek",   name: "DeepSeek",      domain: "deepseek.com",       kind: "ai",  accent: "#4d6bfe", connect: "key", account: true,  blurb: "DeepSeek V3 / R1 reasoning models via API or your account." },
  { id: "cohere",     name: "Cohere",        domain: "cohere.com",         kind: "ai",  accent: "#ff7759", connect: "key",  blurb: "Enterprise LLMs with best-in-class embeddings and rerank." },
  { id: "together",   name: "Together AI",   domain: "together.ai",        kind: "ai",  accent: "#0f6fff", connect: "key",  blurb: "Serverless inference for 200+ open models." },
  { id: "fireworks",  name: "Fireworks AI",  domain: "fireworks.ai",       kind: "ai",  accent: "#7c3aed", connect: "key",  blurb: "Fast, low-cost serving of open models (Llama, DeepSeek, Qwen)." },
  { id: "cerebras",   name: "Cerebras",      domain: "cerebras.ai",        kind: "ai",  accent: "#f97316", connect: "key",  blurb: "The fastest inference on open models, on wafer-scale hardware." },
  // cybersecurity platforms / intel sources
  { id: "virustotal", name: "VirusTotal",    domain: "virustotal.com",     kind: "sec", accent: "#394eff", connect: "key",  blurb: "File, URL, domain and IP reputation across 70+ engines." },
  { id: "shodan",     name: "Shodan",        domain: "shodan.io",          kind: "sec", accent: "#e51e25", connect: "key",  blurb: "Internet-exposed host and service intelligence." },
  { id: "censys",     name: "Censys",        domain: "censys.io",          kind: "sec", accent: "#3c6df0", connect: "key",  blurb: "Attack-surface and certificate search." },
  { id: "hibp",       name: "Have I Been Pwned", domain: "haveibeenpwned.com", kind: "sec", accent: "#2a6bb3", connect: "key", blurb: "Breach and credential-exposure lookups." },
  { id: "greynoise",  name: "GreyNoise",     domain: "greynoise.io",       kind: "sec", accent: "#00c389", connect: "key",  blurb: "Context on internet background noise and mass scanners." },
  { id: "abuseipdb",  name: "AbuseIPDB",     domain: "abuseipdb.com",      kind: "sec", accent: "#1f9d55", connect: "key",  blurb: "Crowd-sourced IP abuse reporting and scoring." },
  { id: "otx",        name: "AlienVault OTX",domain: "otx.alienvault.com", fav: "alienvault.com", kind: "sec", accent: "#00a4e4", connect: "key",  blurb: "Open Threat Exchange pulses and indicators." },
  { id: "abusech",    name: "abuse.ch",      domain: "abuse.ch",           kind: "sec", accent: "#e2001a", connect: "link", blurb: "URLhaus, ThreatFox and MalwareBazaar feeds." },
  { id: "urlscan",    name: "urlscan.io",    domain: "urlscan.io",         kind: "sec", accent: "#5a67d8", connect: "key",  blurb: "Scan and dissect any URL in a sandbox." },
  { id: "mitre",      name: "MITRE ATT&CK",  domain: "attack.mitre.org",   kind: "sec", accent: "#d93a3a", connect: "link", blurb: "Adversary tactics & techniques knowledge base." },
  { id: "nvd",        name: "NVD",           domain: "nvd.nist.gov",       kind: "sec", accent: "#1b6ec2", connect: "link", blurb: "National Vulnerability Database — CVE + CVSS." },
  { id: "circl",      name: "CIRCL CVE",     domain: "cve.circl.lu",       kind: "sec", accent: "#cc3333", connect: "link", blurb: "Fast CVE search and vulnerability metadata." },
  { id: "securitytrails", name: "SecurityTrails", domain: "securitytrails.com", kind: "sec", accent: "#28c76f", connect: "key", blurb: "Historical DNS, WHOIS and domain/IP intelligence." },
  { id: "ipinfo",     name: "IPinfo",        domain: "ipinfo.io",          kind: "sec", accent: "#1f8ceb", connect: "key",  blurb: "IP geolocation, ASN, company and privacy detection." },
  { id: "hybrid",     name: "Hybrid Analysis", domain: "hybrid-analysis.com", kind: "sec", accent: "#2b6cb0", connect: "key", blurb: "Free malware sandbox powered by CrowdStrike Falcon." },
  { id: "pulsedive",  name: "Pulsedive",     domain: "pulsedive.com",      kind: "sec", accent: "#5b53d6", connect: "key",  blurb: "Threat intelligence on indicators, feeds and risk scoring." },
  { id: "zoomeye",    name: "ZoomEye",       domain: "zoomeye.org",        kind: "sec", accent: "#3b5bdb", connect: "key",  blurb: "Cyberspace search engine for exposed hosts, services and devices." },
  { id: "binaryedge", name: "BinaryEdge",    domain: "binaryedge.io",      kind: "sec", accent: "#e8590c", connect: "key",  blurb: "Internet scanning data, exposed services and risk scoring." },
  { id: "netlas",     name: "Netlas",        domain: "netlas.io",          kind: "sec", accent: "#1098ad", connect: "key",  blurb: "Attack-surface discovery over internet-wide scan data." },
  { id: "fullhunt",   name: "FullHunt",      domain: "fullhunt.io",        kind: "sec", accent: "#f03e3e", connect: "key",  blurb: "Attack-surface management and exposure monitoring." },
  { id: "intelx",     name: "Intelligence X",domain: "intelx.io",          kind: "sec", accent: "#364fc7", connect: "key",  blurb: "OSINT search across leaks, darkweb, document and selector data." },
  { id: "hunter",     name: "Hunter",        domain: "hunter.io",          kind: "sec", accent: "#fd7e14", connect: "key",  blurb: "Find and verify professional email addresses for a domain." },
  { id: "dehashed",   name: "DeHashed",      domain: "dehashed.com",       kind: "sec", accent: "#9c36b5", connect: "key",  blurb: "Credential and breach-record search across exposed datasets." },
  { id: "anyrun",     name: "ANY.RUN",       domain: "any.run",            kind: "sec", accent: "#ff6b2c", connect: "key",  blurb: "Interactive malware sandbox for live behavioural analysis." },
  { id: "maltego",    name: "Maltego",       domain: "maltego.com",        kind: "sec", accent: "#12b886", connect: "link", blurb: "Link-analysis and OSINT graphing across entities." },
  { id: "misp",       name: "MISP",          domain: "misp-project.org",   kind: "sec", accent: "#2f7ed8", connect: "link", blurb: "Open threat-intelligence sharing platform and IOC feeds." },
  { id: "exploitdb",  name: "Exploit-DB",    domain: "exploit-db.com",     kind: "sec", accent: "#d6336c", connect: "link", blurb: "Archive of public exploits and proof-of-concept code." },
];

// Models each AI provider exposes. Picking one in the drawer stores its API model
// id as Darknode's preferred model for that provider (dn_model_<id>); webai uses it
// verbatim when the provider is connected. Top models per tier; {label, id}.
const MODELS = {
  claude:     [{ label: "Claude Opus 5.5", id: "claude-opus-5-5" }, { label: "Claude Sonnet 5.5", id: "claude-sonnet-5-5" }, { label: "Claude Haiku 5.5", id: "claude-haiku-5-5" }, { label: "Claude Fable 5.1", id: "claude-fable-5-1" }, { label: "Claude Opus 4.1", id: "claude-opus-4-1" }, { label: "Claude Sonnet 4.5", id: "claude-sonnet-4-5" }, { label: "Claude Haiku 4.5", id: "claude-haiku-4-5" }],
  openai:     [{ label: "GPT-5", id: "gpt-5" }, { label: "GPT-5 mini", id: "gpt-5-mini" }, { label: "GPT-5 nano", id: "gpt-5-nano" }, { label: "GPT-4.1", id: "gpt-4.1" }, { label: "GPT-4.1 mini", id: "gpt-4.1-mini" }, { label: "GPT-4o", id: "gpt-4o" }, { label: "o4-mini", id: "o4-mini" }, { label: "o3", id: "o3" }],
  gemini:     [{ label: "Gemini 2.5 Pro", id: "gemini-2.5-pro" }, { label: "Gemini 2.5 Flash", id: "gemini-2.5-flash" }, { label: "Gemini 2.5 Flash-Lite", id: "gemini-2.5-flash-lite" }, { label: "Gemini 2.0 Flash", id: "gemini-2.0-flash" }],
  perplexity: [{ label: "Sonar Pro", id: "sonar-pro" }, { label: "Sonar", id: "sonar" }, { label: "Sonar Reasoning", id: "sonar-reasoning" }],
  mistral:    [{ label: "Mistral Large", id: "mistral-large-latest" }, { label: "Mistral Medium", id: "mistral-medium-latest" }, { label: "Codestral", id: "codestral-latest" }],
  groq:       [{ label: "Llama 3.3 70B", id: "llama-3.3-70b-versatile" }, { label: "DeepSeek R1 Distill", id: "deepseek-r1-distill-llama-70b" }, { label: "Gemma 2 9B", id: "gemma2-9b-it" }],
  xai:        [{ label: "Grok 4", id: "grok-4" }, { label: "Grok 3", id: "grok-3" }, { label: "Grok 3 mini", id: "grok-3-mini" }],
  deepseek:   [{ label: "DeepSeek-V3", id: "deepseek-chat" }, { label: "DeepSeek-R1", id: "deepseek-reasoner" }],
  cohere:     [{ label: "Command A", id: "command-a-03-2025" }, { label: "Command R+", id: "command-r-plus" }, { label: "Command R", id: "command-r" }],
  together:   [{ label: "Llama 3.3 70B", id: "meta-llama/Llama-3.3-70B-Instruct-Turbo" }, { label: "Qwen2.5 72B", id: "Qwen/Qwen2.5-72B-Instruct-Turbo" }, { label: "Mixtral 8x22B", id: "mistralai/Mixtral-8x22B-Instruct-v0.1" }],
  fireworks:  [{ label: "Llama 3.3 70B", id: "accounts/fireworks/models/llama-v3p3-70b-instruct" }, { label: "DeepSeek V3", id: "accounts/fireworks/models/deepseek-v3" }, { label: "Qwen2.5 72B", id: "accounts/fireworks/models/qwen2p5-72b-instruct" }],
  cerebras:   [{ label: "Llama 3.3 70B", id: "llama-3.3-70b" }, { label: "Llama 3.1 8B", id: "llama3.1-8b" }],
  openrouter: [{ label: "DeepSeek V3 (free)", id: "deepseek/deepseek-chat-v3-0324:free" }, { label: "Llama 3.3 70B (free)", id: "meta-llama/llama-3.3-70b-instruct:free" }, { label: "Auto router (best available)", id: "openrouter/auto" }],
  huggingface:[{ label: "Any Hub model", id: "" }],
  ollama:     [{ label: "Any locally pulled model (via CLI bridge)", id: "" }],
};

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
// Google's favicon service has far wider coverage than DuckDuckGo's ip3 (which
// 404s on shodan.io and others) and returns crisp PNGs; monogram still covers misses.
const faviconURL = (domain) => `https://www.google.com/s2/favicons?domain=${domain}&sz=256`;

// logo chip: live favicon with monogram fallback on error
function logoHTML(it, cls){
  return `<img class="${cls} logo" src="${faviconURL(it.fav || it.domain)}" alt="" loading="lazy" referrerpolicy="no-referrer"
    onerror="this.outerHTML='<span class=\\'${cls} mono\\' style=\\'--a:${it.accent}\\'>${esc(monogram(it.name))}</span>'">`;
}

// Every tool gets a meaningful line-icon, routed from its label/category by
// keyword. Keeps the gallery readable at a glance without a hand-kept icon map.
const SVG = (p) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${p}</svg>`;
const ICONS = {
  network: SVG('<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3.5 3 14.5 0 18M12 3c-3 3.5-3 14.5 0 18"/>'),
  hash: SVG('<path d="M9 3 7 21M17 3l-2 18M4 8h16M3 16h16"/>'),
  lock: SVG('<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>'),
  bug: SVG('<rect x="8" y="7" width="8" height="12" rx="4"/><path d="M12 7V4M5 9l3 1M19 9l-3 1M4 14h4M16 14h4M6 19l2-2M18 19l-2-2"/>'),
  eye: SVG('<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>'),
  shield: SVG('<path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3Z"/><path d="m9 12 2 2 4-4"/>'),
  mail: SVG('<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m4 7 8 6 8-6"/>'),
  map: SVG('<path d="m9 4-6 2v14l6-2 6 2 6-2V4l-6 2-6-2Z"/><path d="M9 4v14M15 6v14"/>'),
  cpu: SVG('<rect x="6" y="6" width="12" height="12" rx="2"/><rect x="9" y="9" width="6" height="6" rx="1"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/>'),
  file: SVG('<path d="M6 2h8l4 4v16H6Z"/><path d="M14 2v4h4M9 13h6M9 17h6"/>'),
  graph: SVG('<circle cx="6" cy="18" r="2.5"/><circle cx="18" cy="6" r="2.5"/><circle cx="18" cy="17" r="2.5"/><path d="M8 16.5 16 7.5M8.3 17.3 15.6 16.6"/>'),
  search: SVG('<circle cx="11" cy="11" r="7"/><path d="m20 20-3.2-3.2"/>'),
  alert: SVG('<path d="M12 3 2 20h20L12 3Z"/><path d="M12 10v5M12 18h.01"/>'),
  server: SVG('<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>'),
  key: SVG('<circle cx="8" cy="8" r="4"/><path d="m11 11 9 9M17 17l2-2M15 19l2-2"/>'),
  terminal: SVG('<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3M13 15h4"/>'),
};
const ICON_RULES = [
  [/dns|domain|subnet|\bip\b|ipv|\basn\b|network|port|route|trace|cidr|whois|resolver|wifi|packet/i, "network"],
  [/hash|md5|sha|crc|checksum|encode|decode|base64|cipher|entropy|hex/i, "hash"],
  [/ssl|tls|cert|jwt|password|cred|login|auth|secret|pgp|rsa|vault/i, "lock"],
  [/cve|vuln|exploit|malware|ransom|payload|attack|adversary|\bc2\b|shell|xss|injection|csp|firewall-rule/i, "bug"],
  [/osint|recon|wayback|breach|leak|darkweb|dork|footprint|harvest|pwned/i, "eye"],
  [/firewall|siem|\brule|defen|blue|hunt|incident|\bsoc\b|triage|forensic|detect|purple|vanguard/i, "shield"],
  [/email|mail|spf|dmarc|dkim|phish/i, "mail"],
  [/\bmap\b|geo|globe|sentinel|satellite|\bsat\b|track|location|navarch|maritime/i, "map"],
  [/\bai\b|chat|assistant|oracle|prompt|\bllm\b|model|agent|spectre/i, "cpu"],
  [/doc|report|checklist|playbook|note|policy|template|guide|crosswalk|case/i, "file"],
  [/graph|visual|tree|chart|diagram|constellation|mapper/i, "graph"],
  [/search|lookup|query|enrich|investig/i, "search"],
  [/alert|risk|score|calc|cost|impact|cvss|severity/i, "alert"],
  [/server|host|scan|infra|cloud|service|\bapi\b|network-map/i, "server"],
  [/\bkey\b|token|crypto/i, "key"],
];
function toolIcon(label, group){
  const s = ((label || "") + " " + (group || "")).toLowerCase();
  for (let i = 0; i < ICON_RULES.length; i++) if (ICON_RULES[i][0].test(s)) return ICONS[ICON_RULES[i][1]];
  return ICONS.terminal;
}

function loadConns(){ try { return JSON.parse(localStorage.getItem(LS_CONN) || "{}") || {}; } catch (_) { return {}; } }
function saveConns(c){ try { localStorage.setItem(LS_CONN, JSON.stringify(c)); } catch (_) {} }

// ---- top-bar + workspace icons (kept tiny, stroked, on-theme) ----
const IC = {
  grid: SVG('<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>'),
  home: SVG('<path d="M3 11l9-7 9 7"/><path d="M5 10v10h14V10"/><path d="M10 20v-6h4v6"/>'),
  link: SVG('<path d="M9 12h6"/><path d="M8 8H6a4 4 0 0 0 0 8h2"/><path d="M16 8h2a4 4 0 0 1 0 8h-2"/>'),
  radar: SVG('<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4.5"/><path d="M12 12 19 7"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3"/>'),
  folder: SVG('<path d="M3 6h6l2 3h10v10H3Z"/><path d="M3 9h18"/>'),
  pulse: SVG('<path d="M3 12h4l2 6 4-14 2 8h6"/>'),
  spark: SVG('<path d="M12 3v4M12 17v4M3 12h4M17 12h4"/><path d="M12 8l1.4 2.6L16 12l-2.6 1.4L12 16l-1.4-2.6L8 12l2.6-1.4Z"/>'),
  bell: SVG('<path d="M18 8a6 6 0 1 0-12 0c0 7-3 8-3 8h18s-3-1-3-8"/><path d="M10.5 21a2 2 0 0 0 3 0"/>'),
  plus: SVG('<path d="M12 5v14M5 12h14"/>'),
  chevd: SVG('<path d="m6 9 6 6 6-6"/>'),
  gear: SVG('<circle cx="12" cy="12" r="3.2"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M19.1 4.9 17 7M7 17l-2.1 2.1"/>'),
  logout: SVG('<path d="M15 4h4v16h-4"/><path d="M10 8l-4 4 4 4"/><path d="M6 12h9"/>'),
  ext: SVG('<path d="M14 4h6v6"/><path d="M20 4 11 13"/><path d="M19 14v5H5V5h5"/>'),
};

// Platform severity palette (same thresholds the Threat Feed uses).
const SEV = { CRITICAL:{label:"Critical",color:"#f0484a"}, HIGH:{label:"High",color:"#ff7a2f"}, MEDIUM:{label:"Medium",color:"#f5b544"}, LOW:{label:"Low",color:"#38d99a"} };
const sevOf = (s) => s >= 9 ? "CRITICAL" : s >= 7 ? "HIGH" : s >= 4 ? "MEDIUM" : "LOW";

// Live CVE intel from the NIST NVD API 2.0 (public, keyless, CSP-allowed — the same
// source the Threat Feed tool uses). Cached per session so switching scenes doesn't
// re-hit NVD's 5-req/30s limit. Returns the newest `n` CVEs + a severity tally.
const NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
let _cveCache = null, _cveAt = 0, _cvePromise = null;
function _nvdDate(d){ return d.toISOString().slice(0, 19) + ".000"; }
async function _nvdJSON(days, startIndex, perPage){
  const end = new Date(), start = new Date(end.getTime() - days * 86400000);
  const url = NVD_API + "?pubStartDate=" + encodeURIComponent(_nvdDate(start)) + "&pubEndDate=" + encodeURIComponent(_nvdDate(end)) + "&noRejected&resultsPerPage=" + perPage + "&startIndex=" + startIndex;
  const r = await fetch(url);
  if (!r.ok) throw new Error("NVD HTTP " + r.status);
  return r.json();
}
function _mapCVE(v){
  const cve = v.cve || {}, m = cve.metrics || {};
  const pick = (m.cvssMetricV31 || [])[0] || (m.cvssMetricV30 || [])[0] || (m.cvssMetricV40 || [])[0] || (m.cvssMetricV2 || [])[0];
  const score = pick && pick.cvssData ? pick.cvssData.baseScore : null;
  const d = ((cve.descriptions || []).find((x) => x.lang === "en") || {}).value || "";
  const first = (d.split(/(?<=\.)\s/)[0] || d);
  return { id: cve.id, cvss: score, severity: score == null ? "LOW" : sevOf(score), title: first.length > 150 ? first.slice(0, 147) + "…" : first, date: String(cve.published || "").slice(0, 10) };
}
async function fetchIntel(n){
  n = n || 30;
  if (_cveCache && Date.now() - _cveAt < 600000) return _cveCache;  // 10-min cache
  if (_cvePromise) return _cvePromise;
  _cvePromise = (async () => {
    const days = 7;
    const head = await _nvdJSON(days, 0, 1);
    const total = head.totalResults || 0;
    if (!total) { const r = { cves: [], total: 0, counts: {} }; _cveCache = r; _cveAt = Date.now(); return r; }
    const page = await _nvdJSON(days, Math.max(0, total - 60), 60);
    const cves = (page.vulnerabilities || []).map(_mapCVE).filter((c) => c.id)
      .sort((a, b) => b.date.localeCompare(a.date) || String(b.id).localeCompare(String(a.id))).slice(0, n);
    const counts = cves.reduce((o, c) => (o[c.severity] = (o[c.severity] || 0) + 1, o), {});
    const r = { cves, total, counts, days }; _cveCache = r; _cveAt = Date.now(); return r;
  })().catch((e) => { _cvePromise = null; throw e; });
  return _cvePromise;
}

// Read-only views of the real usage counters the console home writes (auth.js).
function readStats(){
  const int = (k) => { try { return parseInt(localStorage.getItem(k) || "0", 10) || 0; } catch (_) { return 0; } };
  return { sessions: int("dn_stat_sessions"), aiConvos: int("dn_stat_ai_convos"), toolsUsed: int("dn_stat_tools_used") };
}
function readRecentActivity(){
  const SEED = new Set(["Scanned 10.10.14.7", "Queried CVE-2024-1234", "Generated report"]);
  let items = []; try { items = JSON.parse(localStorage.getItem("dn_recent_activity")) || []; } catch (_) {}
  return (Array.isArray(items) ? items : []).filter((i) => i && i.text && !SEED.has(i.text)).slice(0, 8);
}
function readNavRecent(){ try { const v = JSON.parse(localStorage.getItem("sw_recent") || "[]"); return Array.isArray(v) ? v : []; } catch (_) { return []; } }
const timeAgo = (ts) => { const d = Date.now() - ts; return d < 60000 ? "just now" : d < 3600000 ? Math.floor(d / 60000) + "m ago" : d < 86400000 ? Math.floor(d / 3600000) + "h ago" : Math.floor(d / 86400000) + "d ago"; };

const CSS = `
.dk{position:fixed;inset:0;z-index:99999;overflow:hidden;isolation:isolate;color:#eaf0fb;background:#060912;
  font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,system-ui,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased;user-select:none}
.dk *{box-sizing:border-box;margin:0}
.dk h1,.dk h2,.dk h3,.dk h4{color:#eef3ff !important}
.dk-sky{position:absolute;inset:0;z-index:0;pointer-events:none;
  background:
    radial-gradient(135% 95% at 50% -15%, #0f1724 0%, rgba(15,23,36,0) 58%),
    #080b12}
.dk-stars{position:absolute;inset:0;z-index:0;pointer-events:none;opacity:.28}
/* ---------- top chrome ---------- */
.dk-top{position:absolute;top:0;left:0;right:0;height:56px;z-index:40;display:flex;align-items:center;gap:20px;padding:0 24px}
.dk-brand{display:flex;align-items:center;gap:10px;color:#f3f7ff}
.dk-brand .dk-mark{height:22px;width:22px;display:block;flex:none}
.dk-brand .dk-wm{height:15px;width:auto;display:block;opacity:.96}
.dk-seg{display:flex;gap:4px;padding:4px;border-radius:13px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.08)}
.dk-seg button{appearance:none;border:0;background:transparent;color:#aab6cf;font:inherit;font-size:13px;font-weight:600;padding:6px 16px;border-radius:9px;cursor:pointer;letter-spacing:.02em}
.dk-seg button.on{background:#2f5fff;color:#fff;box-shadow:0 4px 14px rgba(47,99,255,.32)}
.dk-right{margin-left:auto;display:flex;align-items:center;gap:11px}
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
.dk-core{position:absolute;z-index:3;left:50%;top:50%;transform:translate(-50%,-50%);width:152px;height:152px;border-radius:50%;
  display:grid;place-items:center;text-align:center;cursor:default;
  background:radial-gradient(circle at 50% 40%,#1c2942 0%,#141d31 56%,#0c1322 100%);
  box-shadow:0 0 0 1px rgba(255,255,255,.12),0 0 0 7px rgba(79,134,255,.06),0 12px 42px rgba(0,0,0,.5),inset 0 1px 10px rgba(255,255,255,.1)}
.dk-core b{font-size:15px;font-weight:700;letter-spacing:.1em;color:#fff;text-shadow:0 1px 6px rgba(0,0,0,.5)}
.dk-core span{font-size:11px;color:rgba(255,255,255,.78);letter-spacing:.14em}
.dk-core::after{content:"";position:absolute;inset:-18px;border-radius:50%;border:1px solid rgba(120,150,210,.16);animation:dkPulse 4.4s ease-out infinite}
@keyframes dkPulse{0%{transform:scale(.86);opacity:.7}100%{transform:scale(1.5);opacity:0}}
.dk-node{position:absolute;z-index:3;width:92px;opacity:0;transform:translate(-50%,calc(-50% + var(--rise,22px)));display:flex;flex-direction:column;align-items:center;gap:7px;cursor:pointer;
  transition:transform .55s cubic-bezier(.18,.74,.2,1),opacity .5s ease}
.dk-node.in{opacity:1;--rise:0px}
.dk-node:hover{transform:translate(-50%,calc(-50% + var(--rise,0px))) scale(1.13);transition:transform .2s cubic-bezier(.2,.9,.3,1.3)}
.dk-chip{position:relative;width:64px;height:64px;border-radius:19px;display:grid;place-items:center;
  background:rgba(18,23,38,.72);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);
  border:1px solid rgba(255,255,255,.12);box-shadow:0 10px 26px rgba(0,0,0,.5);overflow:hidden}
.dk-chip .logo{width:36px;height:36px;border-radius:9px;object-fit:contain;background:#fff;padding:3px}
.dk-chip .mono{width:40px;height:40px;border-radius:11px;display:grid;place-items:center;font-weight:700;font-size:15px;color:#fff;
  background:linear-gradient(160deg,var(--a,#5b6cf0),rgba(0,0,0,.35))}
.dk-node.conn .dk-chip{border-color:rgba(120,220,170,.75);box-shadow:0 0 0 1px rgba(120,220,170,.5),0 10px 30px rgba(20,160,110,.35),0 0 22px rgba(40,200,140,.4)}
.dk-node .nm{font-size:11.5px;font-weight:500;color:#cdd8ec;text-align:center;text-shadow:0 1px 4px rgba(0,0,0,.7);line-height:1.2}
.dk-node .st{position:absolute;top:-5px;left:9px;width:14px;height:14px;border-radius:50%;background:#15c47e;border:2px solid #0a1220;display:none;box-shadow:0 0 8px #15c47e}
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
.dk-b.pri{background:#2f6bff;border-color:#2f6bff;color:#fff;box-shadow:0 8px 20px rgba(47,95,255,.3)}
.dk-b.pri:hover{background:#3f78ff}
.dk-keyform{display:flex;flex-direction:column;gap:9px}
.dk-keyform label{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:#8795b3}
.dk-keyform input{width:100%;padding:11px 13px;border-radius:11px;border:1px solid rgba(255,255,255,.16);background:rgba(255,255,255,.06);color:#eaf0fb;font:inherit;font-size:13.5px;outline:none}
.dk-keyform input:focus{border-color:#3f78ff;background:rgba(63,120,255,.1)}
.dk-formrow{display:flex;gap:9px}.dk-formrow .dk-b{flex:1}
.dk-b.dis{background:rgba(239,68,68,.14);border-color:rgba(239,68,68,.4);color:#ff9b9b}
.dk-note{font-size:11.5px;color:#7e8aa6;margin-top:16px;line-height:1.5}
/* models sub-tree inside the drawer */
.dk-models{margin:2px 0 16px;border:1px solid rgba(255,255,255,.1);border-radius:13px;overflow:hidden;background:rgba(255,255,255,.03)}
.dk-mhead{display:flex;align-items:center;gap:9px;padding:12px 14px;cursor:pointer;font-weight:600;font-size:13px;color:#eaf0fb}
.dk-mhead .cnt{font-size:11px;color:#8795b3;font-weight:500}
.dk-mhead .arw{margin-left:auto;color:#8795b3;transition:transform .25s}.dk-mhead .arw svg{width:14px;height:14px;display:block}
.dk-models.open .dk-mhead .arw{transform:rotate(90deg)}
.dk-mbody{max-height:0;overflow:hidden;transition:max-height .32s ease}
.dk-models.open .dk-mbody{max-height:340px;overflow:auto}
.dk-mrow{display:flex;align-items:center;gap:10px;padding:9px 14px;cursor:pointer;border-top:1px solid rgba(255,255,255,.06);font-size:13px;color:#cdd8ec}
.dk-mrow:hover{background:rgba(63,120,255,.16)}
.dk-mrow .dot{width:7px;height:7px;border-radius:50%;background:rgba(255,255,255,.22);flex:none}
.dk-mrow.sel{color:#fff}.dk-mrow.sel .dot{background:#38d99a;box-shadow:0 0 7px #38d99a}
.dk-mrow .tag{margin-left:auto;font-size:10px;font-weight:600;color:#54e3a6;letter-spacing:.04em;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dk-mcustom{display:flex;gap:8px;padding:10px 14px;border-top:1px solid rgba(255,255,255,.06)}
.dk-mcustom[hidden]{display:none}
.dk-mcustom input{flex:1;min-width:0;padding:8px 11px;border-radius:9px;border:1px solid rgba(255,255,255,.16);background:rgba(255,255,255,.06);color:#eaf0fb;font:inherit;font-size:12.5px;outline:none}
.dk-mcustom input:focus{border-color:#3f78ff;background:rgba(63,120,255,.1)}
.dk-mcset{appearance:none;border:1px solid #2f6bff;background:#2f6bff;color:#fff;font:inherit;font-weight:600;font-size:12.5px;padding:0 14px;border-radius:9px;cursor:pointer;flex:none}
.dk-mcset:hover{background:#3f78ff}
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
/* ---------- tools gallery (large, full-screen) ---------- */
.dk-gal{overflow:auto;padding:36px 5vw 72px}
.dk-gal .gcat{margin:0 0 36px}
.dk-gal .ghead{display:flex;align-items:center;gap:11px;margin:0 0 17px}
.dk-gal .ghead .gd{width:11px;height:11px;border-radius:3px;box-shadow:0 0 12px currentColor}
.dk-gal .ghead h3{font-size:16.5px;font-weight:700;letter-spacing:-.01em}
.dk-gal .ghead .gc{font-size:12px;color:#8795b3;font-weight:500}
.dk-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:14px}
.dk-gcard{position:relative;display:flex;flex-direction:column;gap:12px;min-height:128px;padding:18px;border-radius:17px;cursor:pointer;
  background:linear-gradient(165deg,rgba(255,255,255,.055),rgba(255,255,255,.018));border:1px solid rgba(255,255,255,.09);
  box-shadow:0 8px 24px rgba(0,0,0,.26);opacity:0;transform:translateY(10px);
  transition:transform .3s cubic-bezier(.2,.8,.2,1),opacity .3s ease,border-color .2s,box-shadow .2s}
.dk-gcard.in{opacity:1;transform:none}
.dk-gcard:hover{transform:translateY(-4px);border-color:var(--a,#5b6cf0);box-shadow:0 18px 40px rgba(0,0,0,.4),0 0 0 1px var(--a,#5b6cf0)}
.dk-gcard .gi{width:46px;height:46px;border-radius:13px;display:grid;place-items:center;color:#fff;
  background:linear-gradient(158deg,var(--a,#5b6cf0),rgba(0,0,0,.34));box-shadow:inset 0 1px 0 rgba(255,255,255,.22),0 6px 16px rgba(0,0,0,.3)}
.dk-gcard .gi svg{width:23px;height:23px}
.dk-gcard .gt{font-size:14px;font-weight:600;line-height:1.28;color:#eaf0fb}
.dk-gcard .glive{position:absolute;top:15px;right:15px;width:7px;height:7px;border-radius:50%;background:#30d158;box-shadow:0 0 7px #30d158}
.dk-gcard .garr{margin-top:auto;display:inline-flex;align-items:center;gap:5px;font-size:11.5px;font-weight:600;color:#9fb0cc;opacity:0;transform:translateX(-4px);transition:opacity .2s,transform .2s}
.dk-gcard .garr svg{width:13px;height:13px}
.dk-gcard:hover .garr{opacity:1;transform:none;color:#cdd8ec}
/* ---------- in-deck tool workspace ---------- */
.dk-work{position:absolute;inset:56px 0 0;z-index:35;display:flex;flex-direction:column;background:#070b15}
.dk-work[hidden]{display:none}
.dk-work.opening{animation:dkWorkIn .34s cubic-bezier(.2,.8,.2,1)}
@keyframes dkWorkIn{from{opacity:0;transform:scale(.99)}to{opacity:1;transform:none}}
.dk-wbar{flex:none;display:flex;align-items:center;gap:14px;padding:12px 20px;border-bottom:1px solid rgba(255,255,255,.08);background:rgba(10,14,24,.72);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px)}
.dk-wback{display:inline-flex;align-items:center;gap:7px;padding:8px 14px;border-radius:11px;border:1px solid rgba(255,255,255,.12);background:rgba(255,255,255,.05);color:#dbe4f4;font:inherit;font-weight:600;font-size:13px;cursor:pointer}
.dk-wback:hover{background:rgba(255,255,255,.1)}
.dk-wback svg{width:15px;height:15px;transform:rotate(180deg)}
.dk-wtitle{display:flex;align-items:center;gap:11px;font-weight:700;font-size:15px;min-width:0}
.dk-wtitle .wi{flex:none;width:30px;height:30px;border-radius:9px;display:grid;place-items:center;color:#fff;background:linear-gradient(158deg,var(--a,#5b6cf0),rgba(0,0,0,.34))}
.dk-wtitle .wi svg{width:16px;height:16px}
.dk-wtitle .wt{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dk-wfull{margin-left:auto;flex:none;font-size:12.5px;font-weight:600;color:#9fb0cc;cursor:pointer;padding:7px 12px;border-radius:10px;border:1px solid rgba(255,255,255,.1)}
.dk-wfull:hover{background:rgba(255,255,255,.07);color:#dbe4f4}
.dk-wframe{flex:1;position:relative;overflow:hidden}
.dk-wframe iframe{position:absolute;inset:0;width:100%;height:100%;border:0;background:#070b15;opacity:0;transition:opacity .4s ease}
.dk-wframe iframe.in{opacity:1}
.dk-wload{position:absolute;inset:0;display:grid;place-items:center;color:#7e8aa6;font-size:13px;letter-spacing:.03em;pointer-events:none}
.dk-wload .sp{width:30px;height:30px;border-radius:50%;border:2.5px solid rgba(255,255,255,.14);border-top-color:#4f86ff;animation:dkSpin .8s linear infinite;margin:0 auto 12px}
@keyframes dkSpin{to{transform:rotate(360deg)}}
/* ======================= command-center chrome ======================= */
.dk-top{display:grid;grid-template-columns:1fr auto 1fr;gap:14px;padding:0 18px;border-bottom:1px solid rgba(255,255,255,.08);background:#0a0e17;box-shadow:0 1px 0 rgba(0,0,0,.4)}
.dk-top>.dk-brand{justify-self:start}
.dk-top>.dk-tabs{justify-self:center}
.dk-top>.dk-right{justify-self:end;margin-left:0}
.dk-brand{appearance:none;border:0;background:transparent;cursor:pointer;flex:none}
.dk-brand .dk-wsname{margin-left:9px;padding-left:10px;border-left:1px solid rgba(255,255,255,.14);font-family:system-ui,sans-serif;font-weight:600;font-size:12px;letter-spacing:.02em;color:#93a2c0}
/* primary tab bar */
.dk-tabs{display:flex;gap:2px;align-items:center;overflow-x:auto;scrollbar-width:none;margin:0 2px}
.dk-tabs::-webkit-scrollbar{display:none}
.dk-tab{appearance:none;border:0;background:transparent;color:#9aa7c4;font:inherit;font-size:12.5px;font-weight:600;letter-spacing:.01em;padding:7px 10px;border-radius:9px;cursor:pointer;display:inline-flex;align-items:center;gap:7px;white-space:nowrap;position:relative;transition:color .15s,background .15s}
.dk-tab svg{width:15px;height:15px;opacity:.8}
.dk-tab:hover{color:#dbe4f4;background:rgba(255,255,255,.05)}
.dk-tab.on{color:#fff;background:rgba(47,95,255,.18)}
.dk-tab.on svg{opacity:1}
.dk-tab.on::after{content:"";position:absolute;left:13px;right:13px;bottom:-9px;height:2px;border-radius:2px;background:#4f86ff;box-shadow:0 0 10px #4f86ff}
/* right-side controls */
.dk-icbtn{appearance:none;border:1px solid rgba(255,255,255,.1);background:rgba(255,255,255,.04);color:#c3cde0;width:34px;height:34px;border-radius:10px;display:grid;place-items:center;cursor:pointer;position:relative;flex:none;transition:background .15s,border-color .15s}
.dk-icbtn:hover{background:rgba(255,255,255,.1);border-color:rgba(255,255,255,.2);color:#fff}
.dk-icbtn svg{width:17px;height:17px}
.dk-badge{position:absolute;top:-4px;right:-4px;min-width:16px;height:16px;padding:0 4px;border-radius:9px;background:#f0484a;color:#fff;font-size:10px;font-weight:700;display:grid;place-items:center;box-shadow:0 0 0 2px #0a0f1c}
.dk-health{appearance:none;cursor:default;border:1px solid rgba(255,255,255,.1);background:rgba(255,255,255,.04);color:#9fb0cc;font:inherit;font-size:12px;font-weight:600;padding:7px 12px;border-radius:999px;display:inline-flex;align-items:center;gap:8px;flex:none}
.dk-health .d{width:7px;height:7px;border-radius:50%;background:#38d99a;box-shadow:0 0 6px rgba(56,217,154,.55)}
.dk-health.warn{border-color:rgba(245,181,68,.35);background:rgba(245,181,68,.12);color:#f5cf86}
.dk-health.warn .d{background:#f5b544;box-shadow:0 0 8px #f5b544}
@media(max-width:1510px){.dk-brand .dk-wsname{display:none}}
@media(max-width:1420px){.dk-health .t,.dk-tab span{display:none}.dk-tab{padding:7px 9px}}
.dk-acct{appearance:none;border:1px solid rgba(255,255,255,.1);background:rgba(255,255,255,.04);cursor:pointer;height:34px;padding:0 8px 0 5px;border-radius:999px;display:inline-flex;align-items:center;gap:5px;flex:none}
.dk-acct:hover{background:rgba(255,255,255,.1)}
.dk-acct .av{width:26px;height:26px;border-radius:50%;display:grid;place-items:center;font-size:11px;font-weight:700;color:#fff;background:linear-gradient(150deg,#4f86ff,#7b61ff);overflow:hidden}
.dk-acct .av img{width:100%;height:100%;object-fit:cover;border-radius:50%}
.dk-acct svg{width:14px;height:14px;color:#8795b3}
/* popover menus (notifications / create / account) */
.dk-pop{position:absolute;top:52px;z-index:120;min-width:240px;max-width:360px;border-radius:15px;overflow:hidden;
  background:rgba(15,20,33,.96);backdrop-filter:blur(30px) saturate(170%);-webkit-backdrop-filter:blur(30px) saturate(170%);
  border:1px solid rgba(255,255,255,.12);box-shadow:0 30px 90px rgba(0,0,0,.6);display:none}
.dk-pop.on{display:block;animation:dkPop .18s ease}
@keyframes dkPop{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
.dk-pop-h{display:flex;align-items:center;justify-content:space-between;padding:13px 16px;border-bottom:1px solid rgba(255,255,255,.08);font-size:12px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:#aab6cf}
.dk-pop-h button{appearance:none;border:0;background:transparent;color:#7e8aa6;font:inherit;font-size:11px;cursor:pointer;text-transform:none;letter-spacing:0}
.dk-pop-h button:hover{color:#cdd8ec}
.dk-mi{display:flex;align-items:center;gap:11px;width:100%;padding:11px 16px;background:transparent;border:0;color:#dbe4f4;font:inherit;font-size:13.5px;cursor:pointer;text-align:left}
.dk-mi:hover{background:rgba(63,120,255,.16)}
.dk-mi svg{width:16px;height:16px;color:#9fb0cc;flex:none}
.dk-mi .sub{display:block;font-size:11.5px;color:#8795b3;margin-top:1px}
.dk-mi-div{height:1px;background:rgba(255,255,255,.08);margin:4px 0}
.dk-acctcard{padding:14px 16px;border-bottom:1px solid rgba(255,255,255,.08)}
.dk-acctcard b{font-size:14px;color:#eaf0fb}.dk-acctcard span{display:block;font-size:12px;color:#8795b3;margin-top:2px;word-break:break-all}
.dk-notif{max-height:60vh;overflow:auto}
.dk-nrow{display:flex;gap:11px;padding:12px 16px;border-bottom:1px solid rgba(255,255,255,.05)}
.dk-nrow .nd{width:8px;height:8px;border-radius:50%;background:#4f86ff;flex:none;margin-top:5px;box-shadow:0 0 7px #4f86ff}
.dk-nrow.seen .nd{background:rgba(255,255,255,.18);box-shadow:none}
.dk-nrow .nt{font-size:13px;color:#dbe4f4;line-height:1.35}
.dk-nrow .na{font-size:11px;color:#7e8aa6;margin-top:2px}
.dk-nempty{padding:26px 16px;text-align:center;color:#7e8aa6;font-size:13px}
/* ======================= Overview workspace ======================= */
.dk-ov{position:absolute;inset:56px 0 0;overflow:auto;padding:26px 4vw 60px}
.dk-ovhead{display:flex;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;gap:14px;margin-bottom:22px}
.dk-ovhead h1{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,system-ui,sans-serif;font-size:26px;font-weight:800;letter-spacing:-.02em;color:#f3f7ff}
.dk-ovhead p{font-size:13.5px;color:#93a2c0;margin-top:5px;max-width:620px}
.dk-ovhead .when{font-size:12.5px;color:#7e8aa6;text-align:right}
.dk-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(168px,1fr));gap:14px;margin-bottom:22px}
.dk-kpi{position:relative;padding:16px 16px 15px 18px;border-radius:12px;background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.08);cursor:pointer;transition:transform .16s,border-color .16s,background .16s;overflow:hidden;text-align:left}
.dk-kpi::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--a,#4f86ff)}
.dk-kpi:hover{transform:translateY(-2px);border-color:color-mix(in srgb,var(--a,#4f86ff) 55%,rgba(255,255,255,.08));background:rgba(255,255,255,.045)}
.dk-kpi .ki{position:absolute;top:13px;right:13px;width:25px;height:25px;border-radius:7px;display:grid;place-items:center;color:var(--a,#4f86ff);background:color-mix(in srgb,var(--a,#4f86ff) 16%,transparent)}
.dk-kpi .ki svg{width:14px;height:14px}
.dk-kpi .kn{font-size:28px;font-weight:800;line-height:1;letter-spacing:-.02em;color:#f3f7ff;font-variant-numeric:tabular-nums}
.dk-kpi .kl{font-size:10.5px;letter-spacing:.07em;text-transform:uppercase;color:#8795b3;margin-top:9px;font-weight:600}
.dk-kpi .ks{font-size:11px;font-weight:500;color:#6f7b96;margin-top:4px}
.dk-ovgrid{display:grid;grid-template-columns:1.5fr 1fr;gap:18px}
@media(max-width:900px){.dk-ovgrid{grid-template-columns:1fr}.dk-ov{padding:24px 18px 56px}}
.dk-ovp{border-radius:18px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);padding:18px 20px;box-shadow:0 10px 30px rgba(0,0,0,.3);margin-bottom:18px}
.dk-ovp h2{font-size:15px;font-weight:700;margin:0 0 14px;display:flex;align-items:center;gap:9px}
.dk-ovp h2 svg{width:17px;height:17px;flex:none;color:#8aa0ff}
.dk-ovp h2 .mo{margin-left:auto;font-size:12px;font-weight:600;color:#8aa0ff;cursor:pointer;white-space:nowrap}
.dk-ovp h2 .mo:hover{color:#b9c8ff}
.dk-ovact .r{display:flex;align-items:center;gap:11px;padding:9px 0;border-top:1px solid rgba(255,255,255,.055)}
.dk-ovact .r:first-child{border-top:0}
.dk-ovact .r .dot{width:7px;height:7px;border-radius:50%;background:#4f86ff;flex:none}
.dk-ovact .r .tx{font-size:13px;color:#cdd8ec;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dk-ovact .r .ag{font-size:11.5px;color:#7e8aa6;flex:none}
.dk-qa{display:grid;grid-template-columns:1fr 1fr;gap:11px}
.dk-qacard{display:flex;flex-direction:column;gap:7px;padding:15px;border-radius:14px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);cursor:pointer;transition:transform .18s,border-color .18s,background .18s}
.dk-qacard:hover{transform:translateY(-2px);background:rgba(63,120,255,.14);border-color:rgba(63,120,255,.4)}
.dk-qacard .qi{width:30px;height:30px;border-radius:8px;display:grid;place-items:center;color:var(--a,#4f86ff);background:color-mix(in srgb,var(--a,#4f86ff) 16%,transparent)}
.dk-qacard .qi svg{width:16px;height:16px}
.dk-qacard b{font-size:13.5px;color:#eaf0fb}
.dk-qacard span{font-size:11.5px;color:#8795b3;line-height:1.35}
.dk-gauge{display:flex;align-items:center;gap:16px}
.dk-gauge .ring{--p:0;--c:#38d99a;width:92px;height:92px;border-radius:50%;flex:none;display:grid;place-items:center;
  background:conic-gradient(var(--c) calc(var(--p)*1%),rgba(255,255,255,.08) 0)}
.dk-gauge .ring i{width:72px;height:72px;border-radius:50%;background:#0b1120;display:grid;place-items:center;font-style:normal;font-size:19px;font-weight:800;color:#f3f7ff}
.dk-gauge .gmeta b{font-size:15px;color:#eaf0fb}.dk-gauge .gmeta p{font-size:12px;color:#8795b3;margin-top:4px;line-height:1.4}
.dk-sevbar{display:flex;height:10px;border-radius:6px;overflow:hidden;margin:12px 0 10px;background:rgba(255,255,255,.06)}
.dk-sevbar span{height:100%}
.dk-sevleg{display:flex;flex-wrap:wrap;gap:12px;font-size:11.5px;color:#9aa7c4}
.dk-sevleg i{width:9px;height:9px;border-radius:2px;display:inline-block;margin-right:5px;vertical-align:-1px}
/* ======================= Tools workspace (rail + search) ======================= */
.dk-tools2{position:absolute;inset:56px 0 0;display:flex;flex-direction:column}
.dk-tbar{flex:none;display:flex;align-items:center;gap:14px;padding:18px 4vw 14px}
.dk-tsearch{flex:1;max-width:520px;display:flex;align-items:center;gap:10px;padding:11px 15px;border-radius:13px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1)}
.dk-tsearch:focus-within{border-color:rgba(79,134,255,.6);background:rgba(79,134,255,.08)}
.dk-tsearch svg{width:17px;height:17px;color:#8795b3;flex:none}
.dk-tsearch input{flex:1;border:0;outline:0;background:transparent;color:#fff;font:inherit;font-size:14px}
.dk-tcount{font-size:12.5px;color:#8795b3;margin-left:auto;flex:none}
.dk-tbody{flex:1;display:flex;min-height:0}
.dk-tnav{flex:none;width:232px;overflow:auto;padding:4px 10px 30px 4vw}
.dk-tcat{display:flex;align-items:center;gap:9px;width:100%;padding:9px 12px;margin-bottom:3px;border:0;border-radius:11px;background:transparent;color:#9aa7c4;font:inherit;font-size:13px;font-weight:600;cursor:pointer;text-align:left;transition:background .15s,color .15s}
.dk-tcat:hover{background:rgba(255,255,255,.05);color:#dbe4f4}
.dk-tcat.on{background:rgba(47,95,255,.16);color:#fff}
.dk-tcat .cd{width:9px;height:9px;border-radius:3px;flex:none;box-shadow:0 0 8px currentColor}
.dk-tcat .n{margin-left:auto;font-size:11.5px;font-weight:600;color:#7e8aa6;background:rgba(255,255,255,.06);padding:1px 8px;border-radius:999px}
.dk-tcat.on .n{color:#cdd8ec;background:rgba(255,255,255,.12)}
.dk-tmain{flex:1;overflow:auto;padding:4px 4vw 60px 24px}
@media(max-width:820px){.dk-tnav{display:none}.dk-tmain{padding:4px 18px 56px}}
.dk-tsec{margin:0 0 30px}
.dk-tsec .th{display:flex;align-items:center;gap:10px;margin:0 0 14px}
.dk-tsec .th .d{width:10px;height:10px;border-radius:3px;box-shadow:0 0 10px currentColor}
.dk-tsec .th h3{font-size:15px;font-weight:700;letter-spacing:-.01em}
.dk-tsec .th .c{font-size:12px;color:#8795b3;font-weight:500}
.dk-tnone{padding:40px;text-align:center;color:#7e8aa6;font-size:14px}
/* ======================= Threat Intel workspace ======================= */
.dk-ti{position:absolute;inset:56px 0 0;overflow:auto;padding:26px 4vw 60px}
.dk-ti-head{display:flex;align-items:center;flex-wrap:wrap;gap:14px;margin-bottom:18px}
.dk-ti-head h1{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,system-ui,sans-serif;font-size:22px;font-weight:800;letter-spacing:-.02em;color:#f3f7ff}
.dk-ti-head .mo{margin-left:auto;font-size:12.5px;font-weight:600;color:#8aa0ff;cursor:pointer;display:inline-flex;align-items:center;gap:6px}
.dk-ti-head .mo svg{width:14px;height:14px}
.dk-sevchips{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:18px}
.dk-sevchip{padding:12px 16px;border-radius:13px;background:rgba(255,255,255,.035);border:1px solid rgba(255,255,255,.08);min-width:104px}
.dk-sevchip .n{font-size:22px;font-weight:800;line-height:1;font-variant-numeric:tabular-nums}
.dk-sevchip .l{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:#8795b3;margin-top:6px}
.dk-cve{display:flex;gap:13px;padding:13px 16px;border-radius:13px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.07);margin-bottom:9px;cursor:pointer;transition:border-color .15s,background .15s}
.dk-cve:hover{background:rgba(255,255,255,.055);border-color:rgba(255,255,255,.18)}
.dk-cve .sv{flex:none;width:52px;text-align:center;font-weight:800;font-size:15px;font-variant-numeric:tabular-nums}
.dk-cve .sv small{display:block;font-size:9.5px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;margin-top:3px}
.dk-cve .bd{min-width:0}
.dk-cve .bd .id{font-size:13px;font-weight:700;color:#eaf0fb}
.dk-cve .bd .ti{font-size:12.5px;color:#aeb9d2;margin-top:3px;line-height:1.4;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.dk-cve .bd .dt{font-size:11px;color:#7e8aa6;margin-top:5px}
.dk-loading{display:flex;align-items:center;gap:12px;color:#8795b3;font-size:13.5px;padding:30px 4px}
.dk-loading .sp{width:22px;height:22px;border-radius:50%;border:2.5px solid rgba(255,255,255,.14);border-top-color:#4f86ff;animation:dkSpin .8s linear infinite}
.dk-errbox{padding:22px;border-radius:14px;background:rgba(240,72,74,.1);border:1px solid rgba(240,72,74,.3);color:#ffb3b4;font-size:13px;line-height:1.5}
.dk-errbox button{margin-top:12px}
/* ======================= Investigations workspace ======================= */
.dk-inv{position:absolute;inset:56px 0 0;overflow:auto;padding:26px 4vw 60px}
.dk-inv h1{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,system-ui,sans-serif;font-size:22px;font-weight:800;letter-spacing:-.02em;color:#f3f7ff;margin-bottom:6px}
.dk-inv .sub{font-size:13px;color:#93a2c0;margin-bottom:20px}
.dk-invtypes{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px;margin:14px 0 8px}
.dk-invtype{padding:14px 16px;border-radius:13px;background:rgba(255,255,255,.035);border:1px solid rgba(255,255,255,.08)}
.dk-invtype .n{font-size:24px;font-weight:800;color:#f3f7ff;font-variant-numeric:tabular-nums}
.dk-invtype .l{font-size:12px;color:#9aa7c4;margin-top:4px;text-transform:capitalize}
/* ======================= Assistant workspace ======================= */
.dk-asst{position:absolute;inset:56px 0 0;display:flex;flex-direction:column}
.dk-asst .dk-wframe{flex:1;position:relative}
`;
const IC_SEARCH = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.2-3.2"/></svg>';
const IC_CHEV = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="m9 6 6 6-6 6"/></svg>';

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

  const root = document.createElement("div");
  root.className = "dk";
  root.innerHTML = `
    <div class="dk-sky"></div>
    <canvas class="dk-stars" id="dkStars"></canvas>
    <div class="dk-top">
      <button class="dk-brand" id="dkBrand" title="Open full console"><img class="dk-mark" src="/logo-light.svg?v=20261007b" alt=""><img class="dk-wm" src="/wordmark.svg" alt="Darknode"><span class="dk-wsname">Command Center</span></button>
      <nav class="dk-tabs" id="dkTabs" aria-label="Workspaces">
        <button class="dk-tab on" data-scene="overview">${IC.home}<span>Overview</span></button>
        <button class="dk-tab" data-scene="con">${IC.link}<span>Connections</span></button>
        <button class="dk-tab" data-scene="tools">${IC.grid}<span>Tools</span></button>
        <button class="dk-tab" data-scene="threat">${IC.radar}<span>Threat Intel</span></button>
        <button class="dk-tab" data-scene="invest">${IC.folder}<span>Investigations</span></button>
        <button class="dk-tab" data-scene="activity">${IC.pulse}<span>Activity</span></button>
        <button class="dk-tab" data-scene="assistant">${IC.spark}<span>Assistant</span></button>
      </nav>
      <div class="dk-right">
        <button class="dk-health" id="dkHealth" title="Live CVE feed status"><span class="d"></span><span class="t">Threat feed live</span></button>
        <button class="dk-icbtn" id="dkFindBtn" title="Search (Ctrl K)" aria-label="Search">${IC_SEARCH}</button>
        <button class="dk-icbtn" id="dkNew" title="Quick create" aria-label="Quick create">${IC.plus}</button>
        <button class="dk-icbtn" id="dkBell" title="Notifications" aria-label="Notifications">${IC.bell}<span class="dk-badge" id="dkBadge" hidden></span></button>
        <span class="dk-clock" id="dkClock"></span>
        <button class="dk-acct" id="dkAcct" aria-label="Account"><span class="av" id="dkAvatar">DN</span>${IC.chevd}</button>
      </div>
    </div>

    <div class="dk-pop" id="dkNewPop"></div>
    <div class="dk-pop" id="dkBellPop"></div>
    <div class="dk-pop" id="dkAcctPop"></div>

    <div class="dk-scene dk-ov" id="dkOverview"></div>

    <div class="dk-scene" id="dkCon" hidden>
      <div class="dk-con" id="dkConCanvas">
        <svg class="dk-links" id="dkLinks"></svg>
        <div class="dk-core"><div><b>DARKNODE</b><br><span id="dkCoreCount"></span></div></div>
      </div>
      <div class="dk-conlist" id="dkConList"></div>
    </div>

    <div class="dk-scene dk-tools2" id="dkTools" hidden></div>

    <div class="dk-scene dk-ti" id="dkThreat" hidden></div>

    <div class="dk-scene dk-inv" id="dkInvest" hidden></div>

    <div class="dk-scene dk-ov" id="dkActivity" hidden></div>

    <div class="dk-scene dk-asst" id="dkAssistant" hidden>
      <div class="dk-wbar">
        <div class="dk-wtitle"><span class="wi">${IC.spark}</span><span class="wt">Darknode AI</span></div>
        <span class="dk-wfull" id="dkAsstFull">Open in full console</span>
      </div>
      <div class="dk-wframe" id="dkAsstFrame"></div>
    </div>

    <div class="dk-scene dk-work" id="dkWork" hidden>
      <div class="dk-wbar">
        <button class="dk-wback" id="dkWBack">${IC_CHEV}Back</button>
        <div class="dk-wtitle" id="dkWTitle"></div>
        <span class="dk-wfull" id="dkWFull">Open in full console</span>
      </div>
      <div class="dk-wframe" id="dkWFrame"></div>
    </div>

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

  // ---------- workspace router ----------
  const SCENES = { overview: "#dkOverview", con: "#dkCon", tools: "#dkTools", threat: "#dkThreat", invest: "#dkInvest", activity: "#dkActivity", assistant: "#dkAssistant" };
  const sceneEls = {}; for (const k in SCENES) sceneEls[k] = $(SCENES[k]);
  const sceneCon = sceneEls.con, sceneTools = sceneEls.tools;   // kept for the constellation + tools code
  // sec -> label, for activity lines and quick-action titles
  const secLabel = {}; for (const g of groups) for (const it of g.items) secLabel[it.sec] = it.label;
  let curScene = "overview";
  function go(scene){
    if (!SCENES[scene]) scene = "overview";
    curScene = scene;
    try { localStorage.setItem(LS_SCENE, scene); } catch (_) {}
    closeAllMenus();
    sceneWork.hidden = true; wFrame.innerHTML = ""; curSec = null;
    root.querySelectorAll(".dk-tab").forEach((t) => t.classList.toggle("on", t.dataset.scene === scene));
    for (const k in sceneEls) sceneEls[k].hidden = k !== scene;
    if (scene === "overview") renderOverview();
    else if (scene === "con") layoutConstellation();
    else if (scene === "tools") { buildTools(); applyTools(); revealGallery(); }
    else if (scene === "threat") renderThreat();
    else if (scene === "invest") renderInvest();
    else if (scene === "activity") renderActivity();
    else if (scene === "assistant") openAssistant();
  }
  root.querySelectorAll(".dk-tab").forEach((b) => b.onclick = () => go(b.dataset.scene));
  // Any element carrying data-scene (KPI cards, "view all" links, quick actions)
  // routes to that workspace; data-sec opens a tool in the in-deck workspace.
  root.addEventListener("click", (e) => {
    const nav = e.target.closest("[data-scene]");
    if (nav && !nav.classList.contains("dk-tab") && nav.dataset.scene) { go(nav.dataset.scene); return; }
  });

  // ---------- constellation ----------
  const canvas = $("#dkConCanvas"), links = $("#dkLinks"), coreCount = $("#dkCoreCount"), conList = $("#dkConList"), core = root.querySelector(".dk-core");
  let fanBloomed = false;
  const ai = INTEGRATIONS.filter((i) => i.kind === "ai");
  const sec = INTEGRATIONS.filter((i) => i.kind === "sec");

  function nodeHTML(it){
    const c = conns[it.id]?.connected;
    return `<div class="dk-node${c ? " conn" : ""}" data-id="${it.id}">
      <div class="dk-chip">${logoHTML(it, "")}</div><span class="st"></span>
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
    const narrow = W < 760;
    canvas.style.display = narrow ? "none" : "";
    conList.style.display = narrow ? "block" : "none";
    coreCount.textContent = `${countConnected()} linked`;
    if (narrow) { renderConList(); return; }
    const cx = W/2, coreY = Math.round(H * 0.82);
    if (core){ core.style.left = cx + "px"; core.style.top = coreY + "px"; }
    // Casual upward "stack fan" (Mac-downloads feel): services spray up from the
    // core in wide, shallow tiers with a little organic jitter — not a rigid orbit.
    fanPlace(ai.concat(sec), cx, coreY, W, H);
    drawLinks(cx, coreY);
    revealFan();
  }
  // deterministic per-id jitter in [-m, m] so the fan looks hand-placed, not mechanical
  function jit(seed, m){ let h = 2166136261; for (let i = 0; i < seed.length; i++){ h ^= seed.charCodeAt(i); h = Math.imul(h, 16777619); } return (((h >>> 0) % 1000) / 1000 - 0.5) * 2 * m; }
  function fanPlace(list, cx, coreY, W, H){
    const span = 128 * Math.PI / 180;            // total fan width (narrower = no edge spill)
    const mid = -Math.PI / 2;                    // straight up
    const a0 = mid - span / 2;
    const margin = 92;                           // keep chips (incl. label) off the viewport edges
    const rMin = 190, rStep = 126;
    // cap the radius so the widest/topmost chips can never reach past the margins
    const rMaxX = (W / 2 - margin) / Math.max(0.2, Math.sin(span / 2));
    const rMaxY = coreY - margin;
    const rMax = Math.min(rMaxY, rMaxX, W * 0.46);
    const spacing = 118;                         // min arc gap between chips
    let idx = 0, r = rMin, tier = 0;
    while (idx < list.length){
      const last = r + rStep > rMax;
      let cap = Math.max(3, Math.round((r * span) / spacing));
      if (last) cap = list.length - idx;         // remaining services ride the outer arc
      const items = list.slice(idx, idx + cap);
      const k = items.length;
      items.forEach((it, i) => {
        let ang = k === 1 ? mid : a0 + (i / (k - 1)) * span;
        ang += jit(it.id + "a" + tier, 0.02);
        const rr = r + jit(it.id + "r", 10);
        let x = cx + Math.cos(ang) * rr, y = coreY + Math.sin(ang) * rr;
        x = Math.max(margin, Math.min(W - margin, x));   // belt-and-suspenders: never spill off-screen
        y = Math.max(margin, Math.min(coreY - 24, y));
        const el = canvas.querySelector(`.dk-node[data-id="${it.id}"]`);
        if (el){ el.style.left = x + "px"; el.style.top = y + "px"; el.__x = x; el.__y = y; }
      });
      idx += k; r += rStep; tier++;
      if (last) break;
    }
  }
  function revealFan(){
    const nodes = [...canvas.querySelectorAll(".dk-node")];
    if (fanBloomed){ nodes.forEach((n) => n.classList.add("in")); return; }
    fanBloomed = true;
    nodes.forEach((n, i) => setTimeout(() => n.classList.add("in"), 50 + i * 20));
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
  function openDrawer(it, mode){
    if (!it) return;
    const rec = conns[it.id] || {};
    const connected = !!rec.connected;
    const method = rec.method;
    const kindTxt = it.kind === "ai" ? "AI Model" : "Cyber Intelligence";
    const methodTxt = method === "account" ? "Connected via your account" : method === "key" ? "Connected via API key" : "Connected";
    const keyForm = mode === "key" && !connected && it.connect === "key";
    // OpenRouter is the one AI provider with a real browser account-link (PKCE):
    // one login mints the user's own key, billed to their OpenRouter credits
    // (free models available), reaching Claude/GPT/Gemini/Llama. Shown as the
    // primary path; the raw API key is demoted to an advanced alternative.
    const oauthProv = it.id === "openrouter";
    // Not-connected actions. For AI providers with a consumer plan, account sign-in
    // is the primary path (uses the user's existing subscription — no per-token API
    // billing); the API key is demoted to an advanced alternative. The key is entered
    // inline here (no overlay popup) so it never sits over the drawer's own buttons.
    const actArea = connected
      ? `<button class="dk-b dis" data-act="disc">Disconnect</button>`
      : keyForm
        ? `<form class="dk-keyform" data-form="key">
             <label>${esc(it.name)} API key</label>
             <input type="password" id="dkKeyIn" placeholder="Paste your ${esc(it.name)} API key" autocomplete="off" spellcheck="false">
             <div class="dk-formrow"><button type="submit" class="dk-b pri">Save &amp; connect</button><button type="button" class="dk-b" data-act="cancel">Cancel</button></div>
           </form>`
        : [
            oauthProv ? `<button class="dk-b pri" data-act="oauth">Connect your ${esc(it.name)} account</button>` : "",
            it.account ? `<button class="dk-b pri" data-act="account">Connect your ${esc(it.name)} account</button>` : "",
            it.connect === "key" ? `<button class="dk-b${(it.account || oauthProv) ? "" : " pri"}" data-act="keyform">${(it.account || oauthProv) ? "Use an API key instead (advanced)" : "Connect with API key"}</button>` : "",
            it.connect === "link" ? `<button class="dk-b${it.account ? "" : " pri"}" data-act="conn">Link to Darknode</button>` : "",
          ].join("");
    const note = keyForm
      ? "Your key is stored only in this browser (localStorage) and never leaves your device from here. Darknode routes calls through its own proxy."
      : oauthProv
      ? "Connect signs you in to OpenRouter and creates a key tied to YOUR OpenRouter account — one login reaches Claude, GPT, Gemini, Llama and more. Calls spend your OpenRouter credits; the default model here is free, so it can cost nothing. No provider lets another site charge your Claude/ChatGPT subscription — this is the honest, lowest-cost alternative."
      : it.account
        ? `Signing in links your ${esc(it.name)} account and saves it as a preference. To actually run ${esc(it.name)} inside Darknode's assistant, add an API key below — no provider lets another site bill your existing subscription. Darknode trims each request (short context, capped output) so key usage stays close to using ${esc(it.name)} directly.`
        : it.connect === "key"
          ? "Your key is stored only in this browser (localStorage) and never leaves your device from here. Darknode routes calls through its own proxy."
          : "Linking records this service as available to Darknode. No credentials are stored.";
    const mlist = it.kind === "ai" && MODELS[it.id] ? MODELS[it.id] : null;
    let curModel = "";
    if (mlist) { try { curModel = localStorage.getItem("dn_model_" + it.id) || ""; } catch (_) {} }
    // Custom = a model id the operator typed that isn't one of our presets. BYOK means
    // their own plan may unlock models we don't list, so any id is allowed.
    const isCustom = !!curModel && mlist && !mlist.some((m) => m.id === curModel);
    const modelsHTML = mlist ? `
      <div class="dk-models open" id="dkModels">
        <div class="dk-mhead" data-act="mtoggle"><span>Models</span><span class="cnt">${mlist.length}</span><span class="arw">${IC_CHEV}</span></div>
        <div class="dk-mbody">
          ${mlist.map((m) => `<div class="dk-mrow${m.id === curModel ? " sel" : ""}" data-model="${esc(m.id)}"><span class="dot"></span>${esc(m.label)}${m.id === curModel ? '<span class="tag">Selected</span>' : ""}</div>`).join("")}
          <div class="dk-mrow mcustomrow${isCustom ? " sel" : ""}" data-act="mcustomrow"><span class="dot"></span>Custom model id…${isCustom ? `<span class="tag">${esc(curModel)}</span>` : ""}</div>
          <div class="dk-mcustom" id="dkMCustom"${isCustom ? "" : " hidden"}>
            <input id="dkModelCustom" placeholder="model id your plan unlocks" value="${isCustom ? esc(curModel) : ""}" autocomplete="off" spellcheck="false">
            <button type="button" class="dk-mcset" data-act="mcustomset">Set</button>
          </div>
        </div>
      </div>` : "";
    drawerBody.innerHTML = `
      <div class="dk-dhead">${logoHTML(it, "")}<div><h3>${esc(it.name)}</h3><div class="k">${kindTxt}</div></div></div>
      <span class="dk-stat ${connected ? "on" : "off"}"><span class="d"></span>${connected ? methodTxt : "Not connected"}</span>
      <p class="blurb">${esc(it.blurb)}</p>
      ${modelsHTML}
      <div class="act">
        ${actArea}
        <button class="dk-b" data-act="open">Open ${esc(it.domain)}</button>
        ${it.kind === "ai" && connected ? `<button class="dk-b" data-act="use">Use in Darknode AI</button>` : ""}
      </div>
      <p class="dk-note">${note}</p>`;
    drawer.classList.add("on");
    drawerBody.querySelector('[data-act="open"]').onclick = () => window.open("https://" + it.domain, "_blank", "noopener");
    const oauthBtn = drawerBody.querySelector('[data-act="oauth"]');
    if (oauthBtn) oauthBtn.onclick = () => {
      // Genuine browser account-link (OpenRouter PKCE). Full-page redirect to
      // OpenRouter; on return, openrouter-connect finishes the handshake, stores
      // the user's minted key, and this deck re-opens showing it connected.
      oauthBtn.disabled = true; oauthBtn.textContent = "Opening OpenRouter…";
      try { startOpenRouterConnect(); } catch (_) { oauthBtn.disabled = false; toast("Could not start OpenRouter connect"); }
    };
    const accBtn = drawerBody.querySelector('[data-act="account"]');
    if (accBtn) accBtn.onclick = () => {
      // Open the provider sign-in so Darknode can link the existing account.
      try { window.open("https://" + it.domain, "_blank", "noopener"); } catch (_) {}
      conns[it.id] = { connected: true, method: "account", at: Date.now() };
      saveConns(conns); toast(`${it.name} account connected`); refreshConnState(it); openDrawer(it);
    };
    const keyFormBtn = drawerBody.querySelector('[data-act="keyform"]');
    if (keyFormBtn) keyFormBtn.onclick = () => openDrawer(it, "key");
    const cancelBtn = drawerBody.querySelector('[data-act="cancel"]');
    if (cancelBtn) cancelBtn.onclick = () => openDrawer(it);
    const form = drawerBody.querySelector('form[data-form="key"]');
    if (form) {
      const inp = form.querySelector("#dkKeyIn");
      setTimeout(() => { try { inp.focus(); } catch (_) {} }, 40);
      form.onsubmit = (e) => {
        e.preventDefault();
        const key = String(inp.value || "").trim();
        conns[it.id] = { connected: true, method: "key", hasKey: !!key, at: Date.now() };
        if (key) { try { localStorage.setItem("dn_key_" + it.id, key); } catch (_) {} }
        saveConns(conns); toast(`${it.name} connected`); refreshConnState(it); openDrawer(it);
      };
    }
    const connBtn = drawerBody.querySelector('[data-act="conn"]');     // link-type only
    if (connBtn) connBtn.onclick = () => {
      conns[it.id] = { connected: true, method: "link", at: Date.now() };
      saveConns(conns); toast(`${it.name} connected`); refreshConnState(it); openDrawer(it);
    };
    const discBtn = drawerBody.querySelector('[data-act="disc"]');
    if (discBtn) discBtn.onclick = () => { delete conns[it.id]; saveConns(conns); try { localStorage.removeItem("dn_key_" + it.id); } catch (_) {} toast(`${it.name} disconnected`); refreshConnState(it); openDrawer(it); };
    const useBtn = drawerBody.querySelector('[data-act="use"]');
    if (useBtn) useBtn.onclick = () => {
      let hasKey = false;
      try {
        localStorage.setItem("dn_ai_pref_provider", it.id);
        hasKey = !!(localStorage.getItem("dn_key_" + it.id) || "").trim();
        // Ensure a concrete model is chosen so the assistant uses a definite one.
        if (mlist && !(localStorage.getItem("dn_model_" + it.id) || "").trim()) localStorage.setItem("dn_model_" + it.id, mlist[0].id);
      } catch (_) {}
      toast(hasKey ? `Darknode AI will use your ${it.name} connection` : `Add a ${it.name} API key to run it — Darknode AI (free) stays active for now`);
      openTool("ai", "Darknode AI");
    };
    const modelsEl = drawerBody.querySelector("#dkModels");
    if (modelsEl) {
      modelsEl.querySelector('[data-act="mtoggle"]').onclick = () => modelsEl.classList.toggle("open");
      const customRow = modelsEl.querySelector(".mcustomrow");
      const customBox = modelsEl.querySelector("#dkMCustom");
      const customIn = modelsEl.querySelector("#dkModelCustom");
      // Re-paint which row is selected. A preset id highlights its row; any other id
      // (a custom/paid-plan model) highlights the custom row and shows the id as its tag.
      const mark = (m) => {
        const preset = mlist.some((x) => x.id === m);
        modelsEl.querySelectorAll(".dk-mrow[data-model]").forEach((x) => {
          const on = x.dataset.model === m;
          x.classList.toggle("sel", on);
          const tag = x.querySelector(".tag");
          if (on && !tag) x.insertAdjacentHTML("beforeend", '<span class="tag">Selected</span>');
          else if (!on && tag) tag.remove();
        });
        if (customRow) {
          customRow.classList.toggle("sel", !preset && !!m);
          const ct = customRow.querySelector(".tag");
          if (!preset && m) { if (ct) ct.textContent = m; else customRow.insertAdjacentHTML("beforeend", `<span class="tag">${esc(m)}</span>`); }
          else if (ct) ct.remove();
        }
      };
      const setModel = (m) => { try { localStorage.setItem("dn_model_" + it.id, m); } catch (_) {} mark(m); toast(`${it.name}: ${m} selected`); };
      modelsEl.querySelectorAll(".dk-mrow[data-model]").forEach((r) => r.onclick = () => setModel(r.dataset.model));
      if (customRow && customBox) customRow.onclick = () => { customBox.hidden = !customBox.hidden; if (!customBox.hidden) setTimeout(() => { try { customIn.focus(); } catch (_) {} }, 20); };
      const applyCustom = () => { const m = String(customIn.value || "").trim(); if (!m) { toast("Enter a model id"); return; } setModel(m); };
      if (customIn) { modelsEl.querySelector('[data-act="mcustomset"]').onclick = applyCustom; customIn.onkeydown = (e) => { if (e.key === "Enter") { e.preventDefault(); applyCustom(); } }; }
    }
  }
  $("#dkDrawerX").onclick = () => drawer.classList.remove("on");

  // ---------- Tools workspace: AWS-style category rail + live search ----------
  const TOTAL_TOOLS = groups.reduce((n, g) => n + g.items.length, 0);
  let toolCat = "all", toolQ = "", toolsBuilt = false;
  try { toolCat = localStorage.getItem("dn_deck_toolcat") || "all"; } catch (_) {}
  if (toolCat !== "all" && !groups.some((g) => g.id === toolCat)) toolCat = "all";
  function buildTools(){
    if (toolsBuilt) return; toolsBuilt = true;
    sceneTools.innerHTML = `
      <div class="dk-tbar">
        <label class="dk-tsearch">${IC_SEARCH}<input id="dkToolSearch" type="search" placeholder="Search ${TOTAL_TOOLS} tools by name…" autocomplete="off" spellcheck="false"></label>
        <span class="dk-tcount" id="dkToolCount"></span>
      </div>
      <div class="dk-tbody">
        <nav class="dk-tnav" id="dkToolNav" aria-label="Tool categories">
          <button class="dk-tcat" data-cat="all"><span class="cd" style="background:#9aa7c4;color:#9aa7c4"></span>All tools<span class="n">${TOTAL_TOOLS}</span></button>
          ${groups.map((g) => { const h = hexOf(g.color); return `<button class="dk-tcat" data-cat="${g.id}"><span class="cd" style="background:${h};color:${h}"></span>${esc(g.name)}<span class="n">${g.items.length}</span></button>`; }).join("")}
        </nav>
        <div class="dk-tmain" id="dkToolMain">
          ${groups.map((g) => { const h = hexOf(g.color); return `<section class="dk-tsec" data-g="${g.id}"><div class="th" style="color:${h}"><span class="d"></span><h3>${esc(g.name)}</h3><span class="c">${g.items.length} tools</span></div>
            <div class="dk-grid">${g.items.map((it) => `<div class="dk-gcard" data-sec="${esc(it.sec)}" data-label="${esc(it.label)}" data-txt="${esc((it.label + " " + g.name).toLowerCase())}" style="--a:${h}">
              <span class="gi">${toolIcon(it.label, g.name)}</span>${it.badge === "live" ? '<span class="glive" title="Live data"></span>' : ""}
              <span class="gt">${esc(it.label)}</span><span class="garr">Open${IC_CHEV}</span></div>`).join("")}</div></section>`; }).join("")}
          <div class="dk-tnone" id="dkToolNone" hidden>No tools match your search.</div>
        </div>
      </div>`;
    sceneTools.querySelectorAll(".dk-gcard").forEach((c) => c.onclick = () => openTool(c.dataset.sec, c.dataset.label, c.style.getPropertyValue("--a")));
    sceneTools.querySelectorAll("#dkToolNav .dk-tcat").forEach((b) => b.onclick = () => {
      toolCat = b.dataset.cat; try { localStorage.setItem("dn_deck_toolcat", toolCat); } catch (_) {}
      const s = sceneTools.querySelector("#dkToolSearch"); if (s) s.value = ""; toolQ = "";
      applyTools(); revealGallery();
      sceneTools.querySelector("#dkToolMain").scrollTop = 0;
    });
    const search = sceneTools.querySelector("#dkToolSearch");
    search.oninput = () => { toolQ = search.value.trim().toLowerCase(); applyTools(); revealGallery(); };
  }
  function applyTools(){
    const q = toolQ; let shown = 0;
    sceneTools.querySelectorAll("#dkToolNav .dk-tcat").forEach((b) => b.classList.toggle("on", !q && b.dataset.cat === toolCat));
    sceneTools.querySelectorAll(".dk-tsec").forEach((sec) => {
      const inCat = !!q || toolCat === "all" || sec.dataset.g === toolCat;
      let any = false;
      sec.querySelectorAll(".dk-gcard").forEach((c) => {
        const hit = inCat && (!q || c.dataset.txt.includes(q));
        c.style.display = hit ? "" : "none";
        if (hit) { any = true; shown++; }
      });
      sec.hidden = !any;
    });
    const countEl = sceneTools.querySelector("#dkToolCount");
    if (countEl) countEl.textContent = q ? `${shown} match${shown === 1 ? "" : "es"}` : `${shown} tool${shown === 1 ? "" : "s"}`;
    const none = sceneTools.querySelector("#dkToolNone"); if (none) none.hidden = shown > 0;
  }
  function revealGallery(){
    const cards = [...sceneTools.querySelectorAll(".dk-gcard")].filter((c) => c.style.display !== "none" && !c.closest(".dk-tsec").hidden);
    cards.forEach((c) => c.classList.remove("in"));
    requestAnimationFrame(() => cards.forEach((c, i) => setTimeout(() => c.classList.add("in"), Math.min(i, 24) * 16)));
  }

  // ---------- in-deck tool workspace (tools open here, not the old console) ----------
  const sceneWork = $("#dkWork"), wFrame = $("#dkWFrame"), wTitle = $("#dkWTitle");
  let curSec = null;
  function openTool(sec, label, accent){
    if (!sec) return;
    label = label || sec; curSec = sec;
    wFrame.innerHTML = '<div class="dk-wload"><div><div class="sp"></div>Loading ' + esc(label) + '…</div></div>';
    const f = document.createElement("iframe");
    f.title = label; f.src = "/" + sec + "?embed=1"; f.loading = "eager"; f.setAttribute("allow", "clipboard-write; clipboard-read");
    f.onload = () => { f.classList.add("in"); const l = wFrame.querySelector(".dk-wload"); if (l) setTimeout(() => l.remove(), 180); };
    wFrame.appendChild(f);
    wTitle.innerHTML = '<span class="wi"' + (accent ? ' style="--a:' + accent + '"' : "") + '>' + toolIcon(label) + '</span><span class="wt">' + esc(label) + '</span>';
    drawer.classList.remove("on"); closeAllMenus();
    for (const k in sceneEls) sceneEls[k].hidden = true;
    sceneWork.hidden = false;
    sceneWork.classList.remove("opening"); void sceneWork.offsetWidth; sceneWork.classList.add("opening");
  }
  function closeTool(){
    sceneWork.hidden = true; wFrame.innerHTML = ""; curSec = null;
    go("tools");
  }
  $("#dkWBack").onclick = closeTool;
  $("#dkWFull").onclick = () => { const s = curSec; teardown(); onOpen(s); };

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
  function chooseSpot(i){ const m = matches[i]; if (!m) return; if (m.type === "conn") { closeSpot(); go("con"); openDrawer(m.it); } else { closeSpot(); openTool(m.sec, m.label); } }
  function moveSel(d){ if (!matches.length) return; selIdx = (selIdx + d + matches.length) % matches.length; spotRes.querySelectorAll(".dk-sr").forEach((r, i) => r.classList.toggle("sel", i === selIdx)); spotRes.querySelector(".dk-sr.sel")?.scrollIntoView({ block: "nearest" }); }
  $("#dkFindBtn").onclick = openSpot; spotIn.oninput = () => runSpot(spotIn.value);
  spot.addEventListener("click", (e) => { if (e.target === spot) closeSpot(); });

  // ---------- command-center chrome: status, quick-create, notifications, account ----------
  const popNew = $("#dkNewPop"), popBell = $("#dkBellPop"), popAcct = $("#dkAcctPop"), badge = $("#dkBadge"), health = $("#dkHealth");
  const user = opts.user || {};
  let notifs = readRecentActivity().map((a) => ({ text: a.text, ts: a.ts }));
  let notifSeen = 0, busOffs = [];
  try { notifSeen = parseInt(localStorage.getItem(LS_NOTIF_SEEN) || "0", 10) || 0; } catch (_) {}

  function closeAllMenus(){ [popNew, popBell, popAcct].forEach((p) => p && p.classList.remove("on")); }
  function toggleMenu(pop, btn, build){
    const open = pop.classList.contains("on");
    closeAllMenus();
    if (open) return;
    build();
    try { pop.style.right = Math.max(10, window.innerWidth - btn.getBoundingClientRect().right) + "px"; } catch (_) {}
    pop.classList.add("on");
  }
  function setHealth(ok, text){ health.classList.toggle("warn", !ok); const t = health.querySelector(".t"); if (t) t.textContent = text; }
  function updateBadge(){ const n = notifs.filter((x) => x.ts > notifSeen).length; if (n > 0) { badge.hidden = false; badge.textContent = n > 9 ? "9+" : String(n); } else badge.hidden = true; }
  function pushNotif(text){ if (!text) return; notifs.unshift({ text: String(text), ts: Date.now() }); if (notifs.length > 40) notifs.length = 40; updateBadge(); if (popBell.classList.contains("on")) buildBellMenu(); if (curScene === "activity") renderActivity(); }
  function buildNewMenu(){
    popNew.innerHTML = `<div class="dk-pop-h">Quick create</div>
      <button class="dk-mi" data-go="assistant">${IC.spark}<span>Ask Darknode AI<span class="sub">Open the assistant</span></span></button>
      <button class="dk-mi" data-go="con">${IC.link}<span>Connect a provider<span class="sub">Link an AI model or intel source</span></span></button>
      <button class="dk-mi" data-tool="investigation">${IC.folder}<span>New investigation<span class="sub">Start an investigation workspace</span></span></button>
      <button class="dk-mi" data-tool="secgraph">${IC.grid}<span>Open security graph<span class="sub">Entities &amp; relationships</span></span></button>`;
    popNew.querySelectorAll("[data-go]").forEach((b) => b.onclick = () => { closeAllMenus(); go(b.dataset.go); });
    popNew.querySelectorAll("[data-tool]").forEach((b) => b.onclick = () => { closeAllMenus(); openTool(b.dataset.tool, secLabel[b.dataset.tool] || b.dataset.tool); });
  }
  function buildBellMenu(){
    popBell.innerHTML = `<div class="dk-pop-h">Notifications <button id="dkNClear">Mark all read</button></div>
      <div class="dk-notif">${notifs.length ? notifs.map((x) => `<div class="dk-nrow${x.ts <= notifSeen ? " seen" : ""}"><span class="nd"></span><div><div class="nt">${esc(x.text)}</div><div class="na">${timeAgo(x.ts)}</div></div></div>`).join("") : `<div class="dk-nempty">No notifications yet. Platform events — tools run, graph entities added, providers connected — stream in here live.</div>`}</div>`;
    const clr = popBell.querySelector("#dkNClear");
    if (clr) clr.onclick = () => { notifSeen = Date.now(); try { localStorage.setItem(LS_NOTIF_SEEN, String(notifSeen)); } catch (_) {} updateBadge(); buildBellMenu(); };
  }
  function buildAcctMenu(){
    const nm = user.displayName || user.email || "Operator", em = user.email || "Signed in to Darknode";
    popAcct.innerHTML = `<div class="dk-acctcard"><b>${esc(nm)}</b><span>${esc(em)}</span></div>
      <button class="dk-mi" data-go="overview">${IC.home}<span>Command center home</span></button>
      <button class="dk-mi" data-tool="settings">${IC.gear}<span>Settings</span></button>
      <button class="dk-mi" id="dkMiConsole">${IC.ext}<span>Open full console</span></button>
      <div class="dk-mi-div"></div>
      <button class="dk-mi" id="dkMiExit">${IC.logout}<span>Exit command center</span></button>`;
    popAcct.querySelector("[data-go]").onclick = () => { closeAllMenus(); go("overview"); };
    popAcct.querySelector("[data-tool]").onclick = () => { closeAllMenus(); openTool("settings", "Settings"); };
    popAcct.querySelector("#dkMiConsole").onclick = exitDeck;
    popAcct.querySelector("#dkMiExit").onclick = exitDeck;
  }
  function exitDeck(){ teardown(); onExit(); }

  // avatar
  const avEl = $("#dkAvatar");
  if (avEl) { if (user.photoURL) avEl.innerHTML = `<img src="${esc(user.photoURL)}" alt="" referrerpolicy="no-referrer">`; else avEl.textContent = monogram(user.displayName || user.email || "Darknode"); }

  $("#dkNew").onclick = (e) => { e.stopPropagation(); toggleMenu(popNew, $("#dkNew"), buildNewMenu); };
  $("#dkBell").onclick = (e) => { e.stopPropagation(); const willOpen = !popBell.classList.contains("on"); toggleMenu(popBell, $("#dkBell"), buildBellMenu); if (willOpen) { notifSeen = Date.now(); try { localStorage.setItem(LS_NOTIF_SEEN, String(notifSeen)); } catch (_) {} updateBadge(); } };
  $("#dkAcct").onclick = (e) => { e.stopPropagation(); toggleMenu(popAcct, $("#dkAcct"), buildAcctMenu); };
  $("#dkBrand").onclick = exitDeck;
  root.addEventListener("pointerdown", (e) => { if (!e.target.closest(".dk-pop, .dk-icbtn, .dk-acct")) closeAllMenus(); });
  updateBadge();

  // live platform events -> notifications (and the Activity stream)
  busOffs.push(bus.on(EVENTS.ENTITY_CREATED, (p) => pushNotif(`Entity added to the graph${p && (p.label || p.name) ? `: ${p.label || p.name}` : p && p.type ? `: ${p.type}` : ""}`)));
  busOffs.push(bus.on(EVENTS.RELATIONSHIP_CREATED, () => pushNotif("New relationship created in the security graph")));
  busOffs.push(bus.on(EVENTS.TOOL_RESULT, (p) => pushNotif(`Result captured${p && p.tool ? ` from ${p.tool}` : ""}`)));
  busOffs.push(bus.on(EVENTS.NOTIFY, (p) => pushNotif(typeof p === "string" ? p : (p && p.message) || "")));

  // ---------- Overview workspace ----------
  function renderOverview(){
    const el = sceneEls.overview;
    const s = readStats();
    const linked = INTEGRATIONS.filter((i) => conns[i.id] && conns[i.id].connected);
    const kpi = (id, val, label, icon, accent, scene, sub) => `<button class="dk-kpi" data-k="${id}"${scene ? ` data-scene="${scene}"` : ""} style="--a:${accent}"><span class="ki">${icon}</span><div class="kn">${val}</div><div class="kl">${esc(label)}</div>${sub ? `<div class="ks">${esc(sub)}</div>` : ""}</button>`;
    const acts = notifs.slice(0, 6);
    const actRows = acts.length
      ? acts.map((a) => `<div class="r"><span class="dot"></span><span class="tx">${esc(a.text)}</span><span class="ag">${timeAgo(a.ts)}</span></div>`).join("")
      : `<div class="dk-nempty">No activity yet. Open a tool or connect a provider and it shows up here.</div>`;
    const pct = INTEGRATIONS.length ? Math.round(linked.length / INTEGRATIONS.length * 100) : 0;
    const now = new Date();
    const first = ((user.displayName || "").trim().split(/\s+/)[0]) || (user.email || "").split("@")[0] || "operator";
    const hr = now.getHours();
    const greet = hr < 5 ? "Still running" : hr < 12 ? "Good morning" : hr < 18 ? "Good afternoon" : "Good evening";
    el.innerHTML = `
      <div class="dk-ovhead">
        <div><h1>${esc(greet)}, ${esc(first)}</h1><p>${linked.length} of ${INTEGRATIONS.length} integrations linked &middot; ${TOTAL_TOOLS.toLocaleString()} tools ready &middot; live threat feed from NVD</p></div>
        <div class="when">${now.toLocaleDateString([], { weekday: "long", month: "long", day: "numeric" })}<br>${now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</div>
      </div>
      <div class="dk-kpis">
        ${kpi("conn", linked.length, "Integrations linked", IC.link, "#38d99a", "con", "of " + INTEGRATIONS.length)}
        ${kpi("tools", TOTAL_TOOLS, "Tools available", IC.grid, "#4f86ff", "tools")}
        ${kpi("graph", "—", "Graph entities", IC.folder, "#9b5cf0", "invest")}
        ${kpi("cve", "—", "New CVEs (7d)", IC.radar, "#f0484a", "threat")}
        ${kpi("tused", s.toolsUsed, "Tools used", IC.pulse, "#f5920b", null, "this browser")}
        ${kpi("ai", s.aiConvos, "AI conversations", IC.spark, "#7b61ff", "assistant", "this browser")}
      </div>
      <div class="dk-ovgrid">
        <div>
          <div class="dk-ovp"><h2>${IC.pulse} Recent activity <span class="mo" data-scene="activity">View all</span></h2><div class="dk-ovact">${actRows}</div></div>
          <div class="dk-ovp"><h2>${IC.grid} Quick actions</h2><div class="dk-qa">
            <button class="dk-qacard" data-scene="assistant"><span class="qi" style="--a:#7b61ff">${IC.spark}</span><b>Ask Darknode AI</b><span>Investigate with the assistant.</span></button>
            <button class="dk-qacard" data-scene="con"><span class="qi" style="--a:#38d99a">${IC.link}</span><b>Connect a provider</b><span>Link an AI model or intel source.</span></button>
            <button class="dk-qacard" data-tool="investigation"><span class="qi" style="--a:#9b5cf0">${IC.folder}</span><b>New investigation</b><span>Open the investigation workspace.</span></button>
            <button class="dk-qacard" data-tool="secgraph"><span class="qi" style="--a:#4f86ff">${IC.grid}</span><b>Security graph</b><span>Entities and their relationships.</span></button>
          </div></div>
        </div>
        <div>
          <div class="dk-ovp"><h2>${IC.radar} Threat level <span class="mo" data-scene="threat">Threat intel</span></h2><div id="dkOvThreat"><div class="dk-loading"><span class="sp"></span>Loading live CVE feed…</div></div></div>
          <div class="dk-ovp"><h2>${IC.link} Connections <span class="mo" data-scene="con">Manage</span></h2>
            <div class="dk-gauge"><div class="ring" style="--p:${pct};--c:#38d99a"><i>${linked.length}</i></div><div class="gmeta"><b>${linked.length} of ${INTEGRATIONS.length} linked</b><p>${linked.length ? esc(linked.slice(0, 5).map((i) => i.name).join(", ")) + (linked.length > 5 ? "…" : "") : "Connect AI models and threat-intel sources to power the console."}</p></div></div>
          </div>
        </div>
      </div>`;
    el.querySelectorAll(".dk-qacard[data-tool]").forEach((b) => b.onclick = () => openTool(b.dataset.tool, secLabel[b.dataset.tool] || b.dataset.tool));
    // async: graph entity count
    import("/js/security-graph.js").then((m) => {
      if (!m.getStats) return;
      const st = m.getStats();
      const kn = el.querySelector('[data-k="graph"] .kn'); if (kn) kn.textContent = (st.totalEntities || 0).toLocaleString();
    }).catch(() => { const kn = el.querySelector('[data-k="graph"] .kn'); if (kn) kn.textContent = "0"; });
    // async: live threat level + CVE KPI
    fetchIntel(30).then((d) => {
      setHealth(true, "Threat feed live");
      const kn = el.querySelector('[data-k="cve"] .kn'); if (kn) kn.textContent = (d.total || 0).toLocaleString();
      const box = el.querySelector("#dkOvThreat"); if (!box) return;
      const c = d.counts || {}, order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
      const sum = order.reduce((n, k) => n + (c[k] || 0), 0) || 1;
      const bar = order.map((k) => `<span style="width:${(c[k] || 0) / sum * 100}%;background:${SEV[k].color}"></span>`).join("");
      const leg = order.map((k) => `<span><i style="background:${SEV[k].color}"></i>${SEV[k].label} ${c[k] || 0}</span>`).join("");
      const hot = (c.CRITICAL || 0) + (c.HIGH || 0);
      const p = Math.round(hot / sum * 100);
      const level = p >= 50 ? "Elevated" : p >= 25 ? "Guarded" : "Low";
      const col = p >= 50 ? "#f0484a" : p >= 25 ? "#f5b544" : "#38d99a";
      box.innerHTML = `<div class="dk-gauge"><div class="ring" style="--p:${p};--c:${col}"><i>${p}%</i></div><div class="gmeta"><b>${level} — ${hot} critical/high</b><p>Across the ${d.cves.length} most-recent CVEs (NVD, last ${d.days} days).</p></div></div><div class="dk-sevbar">${bar}</div><div class="dk-sevleg">${leg}</div>`;
    }).catch(() => {
      setHealth(false, "Threat feed delayed");
      const box = el.querySelector("#dkOvThreat"); if (box) box.innerHTML = `<div class="dk-errbox">Couldn't reach the live CVE feed (NVD rate-limits keyless requests to ~5 / 30s). It refreshes automatically — try again shortly.</div>`;
      const kn = el.querySelector('[data-k="cve"] .kn'); if (kn) kn.textContent = "—";
    });
  }

  // ---------- Threat Intel workspace ----------
  function renderThreat(){
    const el = sceneEls.threat;
    el.innerHTML = `<div class="dk-ti-head"><h1>Threat Intelligence</h1><span class="mo" id="dkTiFull">Open full Threat Feed ${IC.ext}</span></div>
      <div id="dkTiBody"><div class="dk-loading"><span class="sp"></span>Fetching the latest CVEs from the NVD…</div></div>`;
    el.querySelector("#dkTiFull").onclick = () => openTool("threatfeed", "Threat Intel Feed");
    fetchIntel(40).then((d) => {
      setHealth(true, "Threat feed live");
      const c = d.counts || {};
      const chips = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((k) => `<div class="dk-sevchip"><div class="n" style="color:${SEV[k].color}">${c[k] || 0}</div><div class="l">${SEV[k].label}</div></div>`).join("")
        + `<div class="dk-sevchip"><div class="n">${(d.total || 0).toLocaleString()}</div><div class="l">Published 7d</div></div>`;
      const list = d.cves.map((v) => `<div class="dk-cve" data-id="${esc(v.id)}"><div class="sv" style="color:${SEV[v.severity].color}">${v.cvss == null ? "—" : v.cvss.toFixed(1)}<small>${SEV[v.severity].label}</small></div><div class="bd"><div class="id">${esc(v.id)}</div><div class="ti">${esc(v.title || "No description provided yet.")}</div><div class="dt">Published ${esc(v.date || "—")}</div></div></div>`).join("");
      el.querySelector("#dkTiBody").innerHTML = `<div class="dk-sevchips">${chips}</div>${list || '<div class="dk-tnone">No CVEs returned for this window.</div>'}`;
      el.querySelectorAll(".dk-cve").forEach((r) => r.onclick = () => window.open("https://nvd.nist.gov/vuln/detail/" + encodeURIComponent(r.dataset.id), "_blank", "noopener"));
    }).catch(() => {
      setHealth(false, "Threat feed delayed");
      el.querySelector("#dkTiBody").innerHTML = `<div class="dk-errbox">Couldn't reach the NVD CVE feed. Keyless requests are rate-limited to ~5 every 30 seconds — wait a moment and reopen this tab.<br><button class="dk-b" id="dkTiRetry" style="display:inline-flex;width:auto;margin-top:12px">Retry</button></div>`;
      const rt = el.querySelector("#dkTiRetry"); if (rt) rt.onclick = () => { _cveCache = null; _cveAt = 0; renderThreat(); };
    });
  }

  // ---------- Investigations workspace ----------
  function renderInvest(){
    const el = sceneEls.invest;
    el.innerHTML = `<h1>Investigations &amp; Graph</h1><p class="sub">Your security graph, cases and entity intelligence — built up as you work across the tools.</p>
      <div class="dk-kpis" id="dkInvKpis"><div class="dk-loading"><span class="sp"></span>Reading the security graph…</div></div>
      <div class="dk-invtypes" id="dkInvTypes"></div>
      <div class="dk-qa" style="max-width:720px;margin-top:8px">
        <button class="dk-qacard" data-tool="investigation"><span class="qi" style="--a:#9b5cf0">${IC.folder}</span><b>Open Investigation Workspace</b><span>Build and track a full investigation.</span></button>
        <button class="dk-qacard" data-tool="secgraph"><span class="qi" style="--a:#4f86ff">${IC.grid}</span><b>Open Security Graph</b><span>Visualise entities and their links.</span></button>
        <button class="dk-qacard" data-tool="casemgmt"><span class="qi" style="--a:#f5920b">${IC.folder}</span><b>Case Manager</b><span>Track cases and their status.</span></button>
      </div>`;
    el.querySelectorAll(".dk-qacard[data-tool]").forEach((b) => b.onclick = () => openTool(b.dataset.tool, secLabel[b.dataset.tool] || b.dataset.tool));
    import("/js/security-graph.js").then((m) => {
      const st = m.getStats ? m.getStats() : { totalEntities: 0, totalRelationships: 0, byType: {} };
      const label = m.getEntityTypeLabel || ((t) => t);
      const kpi = (val, lab, accent) => `<div class="dk-kpi" style="--a:${accent};cursor:default"><div class="kn">${(val || 0).toLocaleString()}</div><div class="kl">${esc(lab)}</div></div>`;
      el.querySelector("#dkInvKpis").innerHTML = kpi(st.totalEntities, "Entities", "#9b5cf0") + kpi(st.totalRelationships, "Relationships", "#4f86ff") + kpi((st.byType || {}).CASE, "Cases", "#f5920b") + kpi((st.byType || {}).INCIDENT, "Incidents", "#f0484a");
      const types = Object.entries(st.byType || {}).sort((a, b) => b[1] - a[1]).slice(0, 12);
      el.querySelector("#dkInvTypes").innerHTML = types.length ? types.map(([t, n]) => `<div class="dk-invtype"><div class="n">${n}</div><div class="l">${esc(label(t))}</div></div>`).join("") : `<div class="dk-nempty" style="grid-column:1/-1">The graph is empty. As recon, intel and forensic tools run, the entities they find are collected here.</div>`;
    }).catch(() => { el.querySelector("#dkInvKpis").innerHTML = `<div class="dk-nempty" style="grid-column:1/-1">Security graph unavailable in this context.</div>`; });
  }

  // ---------- Activity workspace ----------
  function renderActivity(){
    const el = sceneEls.activity;
    const rows = notifs.length
      ? notifs.map((x) => `<div class="r"><span class="dot"></span><span class="tx">${esc(x.text)}</span><span class="ag">${timeAgo(x.ts)}</span></div>`).join("")
      : `<div class="dk-nempty">No activity recorded yet in this browser. As you run tools, add graph entities or connect providers, events stream in here live.</div>`;
    el.innerHTML = `<div class="dk-ovhead"><div><h1>Activity</h1><p>A live stream of platform events in this session — tool results, graph changes and connections.</p></div></div>
      <div class="dk-ovp"><h2>${IC.pulse} Event stream</h2><div class="dk-ovact">${rows}</div></div>`;
  }

  // ---------- Assistant workspace (embedded Darknode AI) ----------
  const asstFrame = $("#dkAsstFrame");
  let asstLoaded = false;
  function openAssistant(){
    if (asstLoaded) return;
    asstLoaded = true;
    asstFrame.innerHTML = '<div class="dk-wload"><div><div class="sp"></div>Loading Darknode AI…</div></div>';
    const f = document.createElement("iframe");
    f.title = "Darknode AI"; f.src = "/ai?embed=1"; f.loading = "eager"; f.setAttribute("allow", "clipboard-write; clipboard-read");
    f.onload = () => { f.classList.add("in"); const l = asstFrame.querySelector(".dk-wload"); if (l) setTimeout(() => l.remove(), 180); };
    asstFrame.appendChild(f);
  }
  $("#dkAsstFull").onclick = () => { teardown(); onOpen("ai"); };

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
    if (e.key === "Escape") {
      if (popNew.classList.contains("on") || popBell.classList.contains("on") || popAcct.classList.contains("on")) { closeAllMenus(); return; }
      if (!sceneWork.hidden) { closeTool(); return; }
      if (drawer.classList.contains("on")) { drawer.classList.remove("on"); return; }
      if (curScene !== "overview") { go("overview"); return; }
      exitDeck();
    }
  }
  document.addEventListener("keydown", onKey);

  // ---------- resize ----------
  const onResize = () => { sizeStars(); if (!sceneCon.hidden) layoutConstellation(); try { closeAllMenus(); } catch (_) {} };
  window.addEventListener("resize", onResize);

  // ---------- boot: restore the last workspace ----------
  let initial = "overview";
  try { const sv = localStorage.getItem(LS_SCENE); if (sv && SCENES[sv]) initial = sv; } catch (_) {}
  requestAnimationFrame(() => go(initial));

  function teardown(){
    cancelAnimationFrame(rafId); clearInterval(clockId);
    busOffs.forEach((off) => { try { off(); } catch (_) {} }); busOffs = [];
    document.removeEventListener("keydown", onKey); window.removeEventListener("resize", onResize);
    root.remove();
  }
  return teardown;
}
