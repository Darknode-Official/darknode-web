// ============================================================================
// Darknode Command Center — the admin operations console (enterprise preview).
//
// A professional security command center: an executive posture home, external
// attack-surface mapping, live threat & vulnerability intelligence, cloud-posture
// checks, compliance frameworks, the investigation graph, the tool registry, and
// an embedded AI assistant. Every signal is traceable to a real source or is
// honestly labelled "coming" — nothing is simulated. Spotlight (Ctrl/Cmd+K) jumps
// to anything. Self-contained, dependency-free, no emojis.
//
//   renderDeck(host, { groups, onOpen, onExit }) -> teardown()
//     groups : [{ name, color, items:[{sec,label,badge}] }]  (internal tools)
//     onOpen : (sec) => void   // navigate the real console to a tool
//     onExit : () => void      // leave the deck
// ============================================================================

import { startOpenRouterConnect } from "/js/openrouter-connect.js?v=20261010c";
// Live-data layer: the SSRF-guarded worker proxy. dnFetchJSON routes keyless public
// feeds (CISA KEV, FIRST EPSS, ransomware.live, crt.sh, DoH, RDAP, BGPView) through
// /api/fetch; it throws on failure and never fabricates. net.js is stateless.
import { dnFetch, dnFetchJSON, proxyConfigured } from "/js/net.js";
// Attack-surface data wrappers (crt.sh / DoH / RDAP / Team Cymru ASN / HTTP probe),
// all through the proxy above. Data-only module; bump its ?v= when it changes.
import * as surface from "/js/deck-surface.js?v=20261011b";
// Platform event bus (singleton — never version its import, or a second instance
// would miss every event the rest of the app emits). Drives the live Activity
// stream and the notifications bell.
import { bus, EVENTS } from "/js/core/bus.js";
import { isSimulated } from "/js/core/posture.js";
import * as findings from "/js/core/findings.js?v=20261013e";
import { attachExplain, EXPLAIN, explainEnabled, setExplainEnabled } from "/js/ui/explain.js?v=20261014a";

const LS_CONN = "dn_deck_connections_v1";
const LS_SCENE = "dn_deck_scene";          // last workspace selected
const LS_NOTIF_SEEN = "dn_deck_notif_seen"; // ts of the last notification they read
const LS_PINS = "dn_deck_pins_v1";          // user-pinned tools (sec ids) shown on the overview
const LS_NOTES = "dn_deck_notes";           // notes scratchpad, persisted locally

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
  gemini:     [{ label: "Gemini 3.8 Flash", id: "gemini-3.8-flash" }, { label: "Gemini 3.5 Flash", id: "gemini-3.5-flash" }, { label: "Gemini 3.1 Pro", id: "gemini-3.1-pro-preview" }, { label: "Gemini 3.1 Flash-Lite", id: "gemini-3.1-flash-lite" }],
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
const COLORS = { blue:"#3f78ff", cyan:"#19b6d8", orange:"#f5920b", red:"#ef4444", green:"#22b765", purple:"#7d6fae", violet:"#6a74b8", emerald:"#10b981", slate:"#6b7a90", teal:"#14b8a6", pink:"#c75a9a", amber:"#f59e0b", indigo:"#3f78ff", rose:"#d05574", lime:"#84cc16", sky:"#0ea5e9", yellow:"#d9a400" };
const hexOf = (c) => COLORS[c] || "#3f78ff";
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
function loadPins(){ try { const v = JSON.parse(localStorage.getItem(LS_PINS) || "[]"); return Array.isArray(v) ? v : []; } catch (_) { return []; } }
function savePins(p){ try { localStorage.setItem(LS_PINS, JSON.stringify(p)); } catch (_) {} }
function loadNotes(){ try { return localStorage.getItem(LS_NOTES) || ""; } catch (_) { return ""; } }
function saveNotes(t){ try { localStorage.setItem(LS_NOTES, t); } catch (_) {} }

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
  star: SVG('<path d="M12 3.5l2.6 5.27 5.82.85-4.21 4.1.99 5.78L12 16.77l-5.2 2.73.99-5.78-4.21-4.1 5.82-.85Z"/>'),
  note: SVG('<path d="M5 3h10l4 4v14H5Z"/><path d="M15 3v4h4"/><path d="M9 12h6M9 16h4"/>'),
  bolt: SVG('<path d="M13 3 4 14h6l-1 7 9-11h-6l1-7Z"/>'),
  book: SVG('<path d="M4 5.5A2.5 2.5 0 0 1 6.5 3H20v15H6.5A2.5 2.5 0 0 0 4 20.5Z"/><path d="M4 20.5A2.5 2.5 0 0 1 6.5 18H20v3H6.5A2.5 2.5 0 0 1 4 20.5Z"/><path d="M8 7h8M8 10.5h6"/>'),
  copy: SVG('<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>'),
  term: SVG('<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3M13 15h4"/>'),
  // Shell navigation: one distinct glyph per destination.
  menu: SVG('<path d="M4 6h16M4 12h16M4 18h16"/>'),
  rail: SVG('<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M9 4v16"/><path d="m15 10-2 2 2 2"/>'),
  cloud: SVG('<path d="M7 18a4.5 4.5 0 0 1-.6-8.96A6 6 0 0 1 18 9.5a4 4 0 0 1-.5 8.5Z"/>'),
  alert: SVG('<path d="M12 3 2.5 20h19Z"/><path d="M12 10v4M12 17.2v.3"/>'),
  code: SVG('<path d="m8 8-4 4 4 4M16 8l4 4-4 4M14 5l-4 14"/>'),
  branch: SVG('<circle cx="6" cy="5" r="2"/><circle cx="6" cy="19" r="2"/><circle cx="18" cy="7" r="2"/><path d="M6 7v10M18 9c0 5-6 4-12 8"/>'),
  tree: SVG('<circle cx="12" cy="4.5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="12" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 6.5V17M12 11H5v6M12 11h7v6"/>'),
  search: SVG('<circle cx="11" cy="11" r="6.5"/><path d="m20 20-4.2-4.2"/><path d="M8.5 11h5M11 8.5v5"/>'),
  nodes: SVG('<circle cx="6" cy="6" r="2.5"/><circle cx="18" cy="8" r="2.5"/><circle cx="9" cy="18" r="2.5"/><path d="M8.3 7 15.6 7.6M7 8.3l1.4 7.3M16.5 10.1 10.8 16"/>'),
  shield: SVG('<path d="M12 3 4.5 6v6c0 4.5 3.2 7.6 7.5 9 4.3-1.4 7.5-4.5 7.5-9V6Z"/><path d="M12 8v5M12 15.8v.3"/>'),
  brief: SVG('<rect x="3" y="7" width="18" height="13" rx="2"/><path d="M9 7V5h6v2M3 12h18"/>'),
  coins: SVG('<ellipse cx="9" cy="7" rx="6" ry="3"/><path d="M3 7v5c0 1.7 2.7 3 6 3s6-1.3 6-3V7"/><path d="M15 11.2c3.4.2 6 1.4 6 2.8v4c0 1.7-2.7 3-6 3-2.3 0-4.3-.6-5.3-1.6"/>'),
  scale: SVG('<path d="M12 3v18M7 21h10"/><path d="M12 6 5 8l-2.5 6a3 3 0 0 0 5 0L5 8M19 8l-7-2M19 8l-2.5 6a3 3 0 0 0 5 0L19 8"/>'),
  lock: SVG('<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/><path d="M12 14.5v2.5"/>'),
  check: SVG('<path d="M12 3 4.5 6v6c0 4.5 3.2 7.6 7.5 9 4.3-1.4 7.5-4.5 7.5-9V6Z"/><path d="m8.8 12 2.2 2.2 4.4-4.4"/>'),
  map: SVG('<path d="M9 4 3 6.5v13.5L9 17.5l6 2.5 6-2.5V4L15 6.5Z"/><path d="M9 4v13.5M15 6.5V20"/>'),
  plug: SVG('<path d="M9 3v5M15 3v5"/><path d="M6 8h12v3a6 6 0 0 1-12 0Z"/><path d="M12 17v4"/>'),
  wrench: SVG('<path d="M14.7 6.3a4 4 0 0 0-5.2 5.2L3.5 17.5 6.5 20.5l6-6a4 4 0 0 0 5.2-5.2l-2.6 2.6-2.4-.6-.6-2.4Z"/>'),
  key: SVG('<circle cx="8" cy="15" r="4"/><path d="m11 12 9-9M17 6l3 3M14.5 8.5 17 11"/>'),
  eye: SVG('<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>'),
  gauge: SVG('<path d="M4 19a8 8 0 1 1 16 0"/><path d="M12 19l4.5-5.5"/><circle cx="12" cy="19" r="1.4"/><path d="M4 19h2M18 19h2M12 11v1.5"/>'),
  cert: SVG('<rect x="4" y="3" width="16" height="13" rx="2"/><circle cx="12" cy="8.5" r="3"/><path d="M9.6 11.4 8 21l4-2.2L16 21l-1.6-9.6"/>'),
  hook: SVG('<path d="M17 4v8a5 5 0 0 1-10 0v-1"/><circle cx="17" cy="3" r="1.4"/><path d="m4 11 3-3 3 3"/>'),
};

// Platform severity palette (same thresholds the Threat Feed uses).
const SEV = { CRITICAL:{label:"Critical",color:"#f0484a"}, HIGH:{label:"High",color:"#ff7a2f"}, MEDIUM:{label:"Medium",color:"#b7791f"}, LOW:{label:"Low",color:"#12a85f"} };

// ===================== built-in Toolkit (instant, client-side, private) =====================
// Every tool is a pure function of (input, opts). Nothing leaves the browser — ideal for a
// security console handling IOCs, tokens and samples. `run` returns a string or throws Error.
const _te = (s) => new TextEncoder().encode(s);
const _b64e = (s) => btoa(unescape(encodeURIComponent(s)));
const _b64d = (s) => decodeURIComponent(escape(atob(s.replace(/\s+/g, ""))));
const _b64urlToStd = (s) => s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
async function _digest(algo, s){ const b = await crypto.subtle.digest(algo, _te(s)); return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join(""); }
function _htmlDecode(s){ const t = document.createElement("textarea"); t.innerHTML = s; return t.value; }
function _ipToInt(ip){ const p = ip.split("."); return ((+p[0] << 24) >>> 0) + (+p[1] << 16) + (+p[2] << 8) + (+p[3]); }
function _intToIp(n){ return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join("."); }
function _isIPv4(ip){ return /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(ip) && ip.split(".").every((o) => +o >= 0 && +o <= 255); }
function _ipClass(n){ const a = (n >>> 24) & 255; if (a < 128) return "A"; if (a < 192) return "B"; if (a < 224) return "C"; if (a < 240) return "D (multicast)"; return "E (reserved)"; }
function _ipScope(ip){
  const o = ip.split(".").map(Number), n = _ipToInt(ip);
  if (o[0] === 10) return "Private (RFC1918)";
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return "Private (RFC1918)";
  if (o[0] === 192 && o[1] === 168) return "Private (RFC1918)";
  if (o[0] === 127) return "Loopback";
  if (o[0] === 169 && o[1] === 254) return "Link-local (APIPA)";
  if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return "Carrier-grade NAT (RFC6598)";
  if (o[0] >= 224) return "Multicast/Reserved";
  if (n === 0) return "\"This\" host (0.0.0.0)";
  return "Public";
}
function _refang(s){
  return s
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\s+dot\s+/gi, ".")
    .replace(/\[:\/\/\]/g, "://")
    .replace(/\[@\]|\[at\]/gi, "@")
    .replace(/hxxp/gi, "http");
}
function _defang(s){ return s.replace(/:\/\//g, "[://]").replace(/\bhttp/gi, "hxxp").replace(/\./g, "[.]").replace(/@/g, "[@]"); }
function _entropyBits(s){ if (!s) return 0; const f = {}; for (const c of s) f[c] = (f[c] || 0) + 1; let h = 0; for (const k in f){ const p = f[k] / s.length; h -= p * Math.log2(p); } return h * s.length; }

const TK_CATS = [
  { id: "encode", name: "Encoding", color: "#4f86ff" },
  { id: "hash", name: "Hashing", color: "#9b5cf0" },
  { id: "net", name: "Network & IOC", color: "#12a85f" },
  { id: "parse", name: "Parsing", color: "#f5920b" },
  { id: "text", name: "Text", color: "#5e9ed6" },
  { id: "gen", name: "Generators & Security", color: "#f0484a" },
];
const TOOLKIT = [
  { id: "b64e", cat: "encode", name: "Base64 encode", desc: "UTF-8 text to Base64.", run: (s) => _b64e(s) },
  { id: "b64d", cat: "encode", name: "Base64 decode", desc: "Base64 (or base64url) to text.", run: (s) => { try { return _b64d(s); } catch (_) { return _b64d(_b64urlToStd(s.trim())); } } },
  { id: "urle", cat: "encode", name: "URL encode", desc: "Percent-encode a component.", run: (s) => encodeURIComponent(s) },
  { id: "urld", cat: "encode", name: "URL decode", desc: "Decode percent-encoding.", run: (s) => decodeURIComponent(s.replace(/\+/g, " ")) },
  { id: "hexe", cat: "encode", name: "Hex encode", desc: "UTF-8 bytes to hex.", run: (s) => [..._te(s)].map((b) => b.toString(16).padStart(2, "0")).join("") },
  { id: "hexd", cat: "encode", name: "Hex decode", desc: "Hex to UTF-8 text.", run: (s) => { const h = s.replace(/[^0-9a-f]/gi, ""); if (!h) return ""; if (h.length % 2) throw new Error("Hex needs an even number of digits."); return new TextDecoder().decode(new Uint8Array(h.match(/../g).map((x) => parseInt(x, 16)))); } },
  { id: "htmle", cat: "encode", name: "HTML entity encode", desc: "Escape &, <, >, \", '.", run: (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;") },
  { id: "htmld", cat: "encode", name: "HTML entity decode", desc: "Decode HTML entities.", run: (s) => _htmlDecode(s) },
  { id: "rot13", cat: "encode", name: "ROT13", desc: "Classic letter rotation (its own inverse).", run: (s) => s.replace(/[a-z]/gi, (c) => { const base = c <= "Z" ? 65 : 97; return String.fromCharCode((c.charCodeAt(0) - base + 13) % 26 + base); }) },
  { id: "sha1", cat: "hash", name: "SHA-1", desc: "160-bit digest (hex).", async: true, run: (s) => _digest("SHA-1", s) },
  { id: "sha256", cat: "hash", name: "SHA-256", desc: "256-bit digest (hex).", async: true, run: (s) => _digest("SHA-256", s) },
  { id: "sha384", cat: "hash", name: "SHA-384", desc: "384-bit digest (hex).", async: true, run: (s) => _digest("SHA-384", s) },
  { id: "sha512", cat: "hash", name: "SHA-512", desc: "512-bit digest (hex).", async: true, run: (s) => _digest("SHA-512", s) },
  { id: "defang", cat: "net", name: "Defang IOCs", desc: "Make URLs/IPs safe to paste (hxxp, [.]).", run: (s) => _defang(s) },
  { id: "refang", cat: "net", name: "Refang IOCs", desc: "Undo defanging back to live IOCs.", run: (s) => _refang(s) },
  { id: "iocx", cat: "net", name: "Extract IOCs", desc: "Pull IPs, domains, URLs, emails, hashes and CVEs from text.", run: (s) => {
      const t = _refang(s); const uniq = (a) => [...new Set(a)];
      const grab = (re) => uniq((t.match(re) || []));
      const ipv4 = grab(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g).filter(_isIPv4);
      const urls = grab(/\bhttps?:\/\/[^\s"'<>]+/gi);
      const emails = grab(/\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi);
      const domains = grab(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi).filter((d) => !emails.some((e) => e.endsWith(d)) && !_isIPv4(d));
      const md5 = grab(/\b[a-f0-9]{32}\b/gi), sha1 = grab(/\b[a-f0-9]{40}\b/gi), sha256 = grab(/\b[a-f0-9]{64}\b/gi);
      const cves = grab(/\bCVE-\d{4}-\d{4,7}\b/gi);
      const sec = (title, arr) => arr.length ? title + " (" + arr.length + "):\n" + arr.join("\n") + "\n\n" : "";
      const out = sec("IPv4", ipv4) + sec("URLs", urls) + sec("Domains", domains) + sec("Emails", emails) + sec("MD5", md5) + sec("SHA-1", sha1) + sec("SHA-256", sha256) + sec("CVEs", cves);
      return out.trim() || "No indicators found.";
    } },
  { id: "ipinfo", cat: "net", name: "IP address info", desc: "Scope, class, integer and reverse-DNS form.", run: (s) => {
      const ip = s.trim(); if (!_isIPv4(ip)) throw new Error("Enter a valid IPv4 address, e.g. 10.0.0.1");
      const n = _ipToInt(ip);
      return `Address:    ${ip}\nScope:      ${_ipScope(ip)}\nClass:      ${_ipClass(n)}\nInteger:    ${n}\nHex:        0x${n.toString(16).toUpperCase()}\nBinary:     ${ip.split(".").map((o) => (+o).toString(2).padStart(8, "0")).join(".")}\nReverse:    ${ip.split(".").reverse().join(".")}.in-addr.arpa`;
    } },
  { id: "cidr", cat: "net", name: "CIDR calculator", desc: "Network, broadcast, host range and count.", run: (s) => {
      const m = s.trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/); if (!m || !_isIPv4(m[1]) || +m[2] > 32) throw new Error("Enter CIDR like 192.168.1.0/24");
      const bits = +m[2], mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
      const net = (_ipToInt(m[1]) & mask) >>> 0, bc = (net | (~mask >>> 0)) >>> 0, total = Math.pow(2, 32 - bits);
      const hosts = bits >= 31 ? total : total - 2;
      return `CIDR:       ${_intToIp(net)}/${bits}\nNetmask:    ${_intToIp(mask)}\nWildcard:   ${_intToIp(~mask >>> 0)}\nNetwork:    ${_intToIp(net)}\nBroadcast:  ${_intToIp(bc)}\nFirst host: ${_intToIp(bits >= 31 ? net : net + 1)}\nLast host:  ${_intToIp(bits >= 31 ? bc : bc - 1)}\nTotal IPs:  ${total.toLocaleString()}\nUsable:     ${hosts.toLocaleString()}`;
    } },
  { id: "jwt", cat: "parse", name: "JWT decoder", desc: "Decode header + payload (no signature check).", run: (s) => {
      const parts = s.trim().split("."); if (parts.length < 2) throw new Error("Not a JWT (needs header.payload.signature).");
      const dec = (p) => JSON.stringify(JSON.parse(_b64d(_b64urlToStd(p))), null, 2);
      let out = "HEADER:\n" + dec(parts[0]) + "\n\nPAYLOAD:\n" + dec(parts[1]);
      try { const pl = JSON.parse(_b64d(_b64urlToStd(parts[1]))); if (pl.exp) out += "\n\nexp: " + new Date(pl.exp * 1000).toISOString() + (pl.exp * 1000 < Date.now() ? "  (EXPIRED)" : "  (valid)"); if (pl.iat) out += "\niat: " + new Date(pl.iat * 1000).toISOString(); } catch (_) {}
      return out;
    } },
  { id: "jsonf", cat: "parse", name: "JSON format", desc: "Pretty-print and validate JSON.", run: (s) => JSON.stringify(JSON.parse(s), null, 2) },
  { id: "jsonm", cat: "parse", name: "JSON minify", desc: "Strip whitespace from JSON.", run: (s) => JSON.stringify(JSON.parse(s)) },
  { id: "ts", cat: "parse", name: "Timestamp convert", desc: "Epoch ⇄ ISO / local. Blank input = now.", run: (s) => {
      s = s.trim(); let d;
      if (!s) d = new Date();
      else if (/^\d+$/.test(s)) d = new Date(+s * (s.length > 11 ? 1 : 1000));
      else { d = new Date(s); if (isNaN(d)) throw new Error("Unrecognised date/time."); }
      if (isNaN(d)) throw new Error("Invalid timestamp.");
      return `Epoch (s):  ${Math.floor(d.getTime() / 1000)}\nEpoch (ms): ${d.getTime()}\nISO 8601:   ${d.toISOString()}\nUTC:        ${d.toUTCString()}\nLocal:      ${d.toString()}`;
    } },
  { id: "urlp", cat: "parse", name: "URL parser", desc: "Break a URL into its parts + query params.", run: (s) => {
      const u = new URL(s.trim());
      const q = [...u.searchParams.entries()].map(([k, v]) => "  " + k + " = " + v).join("\n");
      return `Protocol: ${u.protocol}\nHost:     ${u.hostname}\nPort:     ${u.port || "(default)"}\nPath:     ${u.pathname}\nQuery:    ${u.search || "(none)"}\nHash:     ${u.hash || "(none)"}\nOrigin:   ${u.origin}${q ? "\n\nParams:\n" + q : ""}`;
    } },
  { id: "case", cat: "text", name: "Case converter", desc: "Every common case at once.", run: (s) => {
      const words = s.trim().split(/[\s_-]+/).filter(Boolean);
      const cap = (w) => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase();
      return `UPPER:   ${s.toUpperCase()}\nlower:   ${s.toLowerCase()}\nTitle:   ${words.map(cap).join(" ")}\nSentence:${s.charAt(0).toUpperCase() + s.slice(1).toLowerCase()}\nsnake:   ${words.map((w) => w.toLowerCase()).join("_")}\nkebab:   ${words.map((w) => w.toLowerCase()).join("-")}\ncamel:   ${words.map((w, i) => i ? cap(w) : w.toLowerCase()).join("")}\nPascal:  ${words.map(cap).join("")}`;
    } },
  { id: "lines", cat: "text", name: "Line tools", desc: "Sort, de-duplicate, reverse or trim lines.", opts: [{ id: "op", label: "Operation", type: "select", options: [["unique", "Unique"], ["sort", "Sort A→Z"], ["sortd", "Sort Z→A"], ["reverse", "Reverse order"], ["trim", "Trim each"], ["nonblank", "Drop blank lines"]] }], run: (s, o) => {
      let L = s.replace(/\r/g, "").split("\n");
      switch (o.op) { case "sort": L.sort(); break; case "sortd": L.sort().reverse(); break; case "reverse": L.reverse(); break; case "trim": L = L.map((x) => x.trim()); break; case "nonblank": L = L.filter((x) => x.trim()); break; default: L = [...new Set(L)]; }
      return L.join("\n");
    } },
  { id: "count", cat: "text", name: "Count & stats", desc: "Characters, words, lines and byte size.", run: (s) => {
      const bytes = _te(s).length, words = (s.match(/\S+/g) || []).length;
      return `Characters:      ${s.length.toLocaleString()}\nNo whitespace:   ${s.replace(/\s/g, "").length.toLocaleString()}\nWords:           ${words.toLocaleString()}\nLines:           ${(s ? s.split(/\n/).length : 0).toLocaleString()}\nBytes (UTF-8):   ${bytes.toLocaleString()}`;
    } },
  { id: "uuid", cat: "gen", name: "UUID v4", desc: "Generate random UUIDs.", generate: true, opts: [{ id: "n", label: "How many", type: "select", options: [["1", "1"], ["5", "5"], ["10", "10"], ["25", "25"]] }], run: (_s, o) => Array.from({ length: +(o.n || 1) }, () => crypto.randomUUID()).join("\n") },
  { id: "pwgen", cat: "gen", name: "Password generator", desc: "Cryptographically-random passwords.", generate: true, opts: [{ id: "len", label: "Length", type: "select", options: [["16", "16"], ["24", "24"], ["32", "32"], ["48", "48"], ["64", "64"]] }, { id: "sym", label: "Include symbols", type: "select", options: [["1", "Yes"], ["0", "No"]] }], run: (_s, o) => {
      const base = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", sym = "!@#$%^&*()-_=+[]{};:,.?";
      const pool = base + (o.sym === "0" ? "" : sym), len = +(o.len || 24), a = new Uint32Array(len); crypto.getRandomValues(a);
      const pw = Array.from(a, (x) => pool[x % pool.length]).join("");
      return pw + "\n\nEntropy ≈ " + Math.round(len * Math.log2(pool.length)) + " bits";
    } },
  { id: "pwstr", cat: "gen", name: "Password strength", desc: "Entropy estimate and rating.", run: (s) => {
      if (!s) throw new Error("Enter a password to analyse.");
      let pool = 0; if (/[a-z]/.test(s)) pool += 26; if (/[A-Z]/.test(s)) pool += 26; if (/\d/.test(s)) pool += 10; if (/[^a-z0-9]/i.test(s)) pool += 32;
      const guessBits = Math.round(s.length * Math.log2(pool || 1)), shannon = Math.round(_entropyBits(s));
      const bits = Math.min(guessBits, shannon + 8);
      const rate = bits < 40 ? "Very weak" : bits < 60 ? "Weak" : bits < 80 ? "Reasonable" : bits < 110 ? "Strong" : "Very strong";
      return `Length:        ${s.length}\nCharset size:  ${pool}\nKeyspace bits: ~${guessBits}\nShannon bits:  ~${shannon}\nRating:        ${rate}`;
    } },
];
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

// ---- live exploitation intel: CISA KEV, FIRST EPSS, ransomware.live ----
// All through the worker proxy (dnFetchJSON); the exact URLs the Cyber Briefing and
// Threat Feed Aggregator tools already use, so this reuses proven, real sources.
const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_URL = "https://api.first.org/data/v1/epss?cve=";
const RANSOM_URL = "https://api.ransomware.live/v2/recentvictims";
let _kevCache = null, _kevAt = 0, _kevPromise = null;
// Returns { set:Set<cveID>, list:[...], total:N } or throws. 10-min cache.
async function fetchKev(){
  if (_kevCache && Date.now() - _kevAt < 600000) return _kevCache;
  if (_kevPromise) return _kevPromise;
  _kevPromise = (async () => {
    // The full catalog is ~1.8 MB, so request the proxy's large-body cap.
    let list = [], total = 0;
    try {
      const d = await dnFetchJSON(KEV_URL, { timeout: 30000, max: 4000000 });
      list = (d && d.vulnerabilities) || [];
      total = parseInt(d && d.count, 10) || list.length;
    } catch (_) {
      // Proxy without the large-body cap truncates the catalog, so the JSON won't
      // parse. Recover the real total from the "count" field near the top and any
      // whole CVE ids present — never fabricate; throw if nothing real is readable.
      const rawr = await dnFetch(KEV_URL, { raw: true, timeout: 30000, max: 4000000 });
      const body = String(rawr.body || "");
      total = parseInt((body.match(/"count"\s*:\s*(\d+)/) || [])[1] || "0", 10);
      const ids = [...new Set((body.match(/CVE-\d{4}-\d+/g) || []))];
      if (!total && !ids.length) throw new Error("KEV catalog unavailable");
      list = ids.map((id) => ({ cveID: id }));
    }
    const set = new Set(list.map((v) => v.cveID).filter(Boolean));
    const r = { set, list, total: total || set.size }; _kevCache = r; _kevAt = Date.now(); return r;
  })().catch((e) => { _kevPromise = null; throw e; });
  return _kevPromise;
}
// EPSS exploit-probability (0..1) keyed by CVE id, for up to ~100 ids. Never throws
// into the caller's critical path — returns {} if the feed is unavailable.
async function fetchEpss(ids){
  ids = (ids || []).filter(Boolean).slice(0, 100);
  if (!ids.length) return {};
  try {
    const er = await dnFetchJSON(EPSS_URL + encodeURIComponent(ids.join(",")), { timeout: 25000 });
    const out = {}; ((er && er.data) || []).forEach((d) => { if (d && d.cve) out[d.cve] = parseFloat(d.epss) || 0; });
    return out;
  } catch (_) { return {}; }
}
// Recent ransomware-leak victims (honest live feed). Returns [] on failure.
async function fetchRansom(limit){
  try {
    const d = await dnFetchJSON(RANSOM_URL, { timeout: 25000 });
    const arr = Array.isArray(d) ? d : (d && d.data) || [];
    return arr.slice(0, limit || 12);
  } catch (_) { return []; }
}

// Read-only views of the real usage counters the console home writes (auth.js).
function readStats(){
  const int = (k) => { try { return parseInt(localStorage.getItem(k) || "0", 10) || 0; } catch (_) { return 0; } };
  return { sessions: int("dn_stat_sessions"), aiConvos: int("dn_stat_ai_convos"), toolsUsed: int("dn_stat_tools_used") };
}
function readRecentActivity(){
  const SEED = new Set(["Scanned 10.10.14.7", "Queried CVE-2024-1234", "Generated report"]);
  let items = []; try { items = JSON.parse(localStorage.getItem("dn_recent_activity")) || []; } catch (_) {}
  items = (Array.isArray(items) ? items : []).filter((i) => i && i.text && !SEED.has(i.text)).slice(0, 20);
  // Entries written before activity carried a sim flag: recover it from the graph. A name
  // counts as sample only when every entity with that name is simulated.
  if (items.some((i) => i.sim === undefined)) {
    const sim = new Map();
    try {
      const ents = (JSON.parse(localStorage.getItem("dn_security_graph")) || {}).entities || {};
      for (const e of Object.values(ents)) { const k = (e.type || "") + ": " + e.name; sim.set(k, (sim.get(k) ?? true) && isSimulated(e)); }
    } catch (_) {}
    items = items.map((i) => { if (i.sim !== undefined) return i; const m = /^Created (.+)$/.exec(i.text); return { ...i, sim: !!(m && sim.get(m[1])) }; });
  }
  return items;
}
function readNavRecent(){ try { const v = JSON.parse(localStorage.getItem("sw_recent") || "[]"); return Array.isArray(v) ? v : []; } catch (_) { return []; } }
const timeAgo = (ts) => { const d = Date.now() - ts; return d < 60000 ? "just now" : d < 3600000 ? Math.floor(d / 60000) + "m ago" : d < 86400000 ? Math.floor(d / 3600000) + "h ago" : Math.floor(d / 86400000) + "d ago"; };

const CSS = `
.dk{position:fixed;inset:0;z-index:99999;overflow:hidden;isolation:isolate;color:#1a2233;background:#f4f6fa;
  font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,system-ui,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased;user-select:none}
.dk *{box-sizing:border-box;margin:0}
:where(.dk) :where(button,input,select,textarea){font-family:inherit}
.dk h1,.dk h2,.dk h3,.dk h4{color:#141c2e !important}
.dk-sky{position:absolute;inset:0;z-index:0;pointer-events:none;
  background:
    radial-gradient(135% 95% at 50% -15%, #e9eef6 0%, rgba(233,238,246,0) 58%),
    #f4f6fa}
.dk-stars{display:none}
/* ---------- top chrome ---------- */
.dk-top{position:absolute;top:0;left:0;right:0;height:56px;z-index:40;display:flex;align-items:center;gap:20px;padding:0 24px}
.dk-brand{display:flex;align-items:center;gap:10px;color:#141c2e}
.dk-brand .dk-mark{height:22px;width:22px;display:block;flex:none}
.dk-brand .dk-wm{height:15px;width:auto;display:block;opacity:.92;filter:brightness(0)}
.dk-seg{display:flex;gap:4px;padding:4px;border-radius:13px;background:rgba(23,33,56,.05);border:1px solid rgba(23,33,56,.08)}
.dk-seg button{appearance:none;border:0;background:transparent;color:#5a6680;font:inherit;font-size:13px;font-weight:600;padding:6px 16px;border-radius:9px;cursor:pointer;letter-spacing:.02em}
.dk-seg button.on{background:#2f63e0;color:#fff}
.dk-right{margin-left:auto;display:flex;align-items:center;gap:11px}
.dk-find{display:flex;align-items:center;gap:9px;padding:8px 14px;border-radius:11px;background:rgba(23,33,56,.05);border:1px solid rgba(23,33,56,.1);color:#687388;font-size:13px;cursor:pointer;min-width:220px}
.dk-find:hover{border-color:rgba(23,33,56,.22)}
.dk-find kbd{margin-left:auto;font:inherit;font-size:11px;background:rgba(23,33,56,.1);padding:2px 7px;border-radius:6px}
.dk-find svg{width:15px;height:15px}
.dk-clock{font-variant-numeric:tabular-nums;color:#5a6680;font-size:13px}
.dk-quit{cursor:pointer;color:#44506a;font-size:13px;font-weight:600;padding:7px 14px;border-radius:10px;border:1px solid rgba(23,33,56,.12)}
.dk-quit:hover{background:rgba(23,33,56,.08)}
.dk-scene{position:absolute;inset:56px 0 0;z-index:10}
.dk-scene[hidden]{display:none}
/* ---------- detail drawer ---------- */
.dk-drawer{position:absolute;top:0;right:0;bottom:0;width:360px;max-width:90vw;z-index:30;transform:translateX(104%);visibility:hidden;transition:transform .34s cubic-bezier(.2,.9,.3,1.1),visibility 0s linear .34s,box-shadow .34s;
  background:#ffffff;
  border-left:1px solid rgba(23,33,56,.12);box-shadow:none;padding:26px 24px;overflow:auto}
.dk-drawer.on{transform:none;visibility:visible;transition:transform .34s cubic-bezier(.2,.9,.3,1.1),visibility 0s,box-shadow .34s;box-shadow:-12px 0 32px rgba(16,24,40,.12)}
.dk-drawer .x{position:absolute;top:16px;right:18px;cursor:pointer;color:#5a6680;font-size:20px;line-height:1}
.dk-dhead{display:flex;align-items:center;gap:14px;margin:6px 0 16px}
.dk-dhead .logo{width:54px;height:54px;border-radius:14px;background:#fff;padding:5px;object-fit:contain}
.dk-dhead .mono{width:54px;height:54px;border-radius:14px;display:grid;place-items:center;font-weight:700;font-size:20px;color:#fff;background:linear-gradient(160deg,var(--a,#3f78ff),rgba(0,0,0,.4))}
.dk-dhead h3{font-size:19px}.dk-dhead .k{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:#687388}
.dk-drawer p.blurb{font-size:13px;color:#5a6680;margin-bottom:18px}
.dk-stat{display:inline-flex;align-items:center;gap:7px;font-size:12px;font-weight:600;padding:6px 12px;border-radius:999px;margin-bottom:18px}
.dk-stat.off{background:rgba(23,33,56,.07);color:#5a6680}.dk-stat.on{background:rgba(21,196,126,.16);color:#17a86a}
.dk-stat .d{width:7px;height:7px;border-radius:50%;background:currentColor}
.dk-drawer .act{display:flex;flex-direction:column;gap:10px}
.dk-b{display:flex;align-items:center;justify-content:center;gap:8px;padding:11px 16px;border-radius:12px;border:1px solid rgba(23,33,56,.14);background:rgba(23,33,56,.06);color:#1a2233;font:inherit;font-weight:600;font-size:13.5px;cursor:pointer}
.dk-b:hover{background:rgba(23,33,56,.12)}
.dk-b.pri{background:#2f6bff;border-color:#2f6bff;color:#fff;box-shadow:0 8px 20px rgba(47,95,255,.3)}
.dk-b.pri:hover{background:#3f78ff}
.dk-keyform{display:flex;flex-direction:column;gap:9px}
.dk-keyform label{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:#687388}
.dk-keyform input{width:100%;padding:11px 13px;border-radius:11px;border:1px solid rgba(23,33,56,.16);background:rgba(23,33,56,.06);color:#1a2233;font:inherit;font-size:13.5px;outline:none}
.dk-keyform input:focus{border-color:#3f78ff;background:rgba(63,120,255,.1)}
.dk-formrow{display:flex;gap:9px}.dk-formrow .dk-b{flex:1}
.dk-b.dis{background:rgba(239,68,68,.14);border-color:rgba(239,68,68,.4);color:#c0282a}
.dk-note{font-size:11.5px;color:#6a7488;margin-top:16px;line-height:1.5}
/* models sub-tree inside the drawer */
.dk-models{margin:2px 0 16px;border:1px solid rgba(23,33,56,.1);border-radius:13px;overflow:hidden;background:rgba(23,33,56,.03)}
.dk-mhead{display:flex;align-items:center;gap:9px;padding:12px 14px;cursor:pointer;font-weight:600;font-size:13px;color:#1a2233}
.dk-mhead .cnt{font-size:11px;color:#687388;font-weight:500}
.dk-mhead .arw{margin-left:auto;color:#687388;transition:transform .25s}.dk-mhead .arw svg{width:14px;height:14px;display:block}
.dk-models.open .dk-mhead .arw{transform:rotate(90deg)}
.dk-mbody{max-height:0;overflow:hidden;transition:max-height .32s ease}
.dk-models.open .dk-mbody{max-height:340px;overflow:auto}
.dk-mrow{display:flex;align-items:center;gap:10px;padding:9px 14px;cursor:pointer;border-top:1px solid rgba(23,33,56,.06);font-size:13px;color:#38435c}
.dk-mrow:hover{background:rgba(63,120,255,.16)}
.dk-mrow .dot{width:7px;height:7px;border-radius:50%;background:rgba(23,33,56,.22);flex:none}
.dk-mrow.sel{color:#2552c6}.dk-mrow.sel .dot{background:#12a85f}
.dk-mrow .tag{margin-left:auto;font-size:10px;font-weight:600;color:#17a86a;letter-spacing:.04em;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dk-mcustom{display:flex;gap:8px;padding:10px 14px;border-top:1px solid rgba(23,33,56,.06)}
.dk-mcustom[hidden]{display:none}
.dk-mcustom input{flex:1;min-width:0;padding:8px 11px;border-radius:9px;border:1px solid rgba(23,33,56,.16);background:rgba(23,33,56,.06);color:#1a2233;font:inherit;font-size:12.5px;outline:none}
.dk-mcustom input:focus{border-color:#3f78ff;background:rgba(63,120,255,.1)}
.dk-mcset{appearance:none;border:1px solid #2f6bff;background:#2f6bff;color:#fff;font:inherit;font-weight:600;font-size:12.5px;padding:0 14px;border-radius:9px;cursor:pointer;flex:none}
.dk-mcset:hover{background:#3f78ff}
/* ---------- tools scene ---------- */
.dk-tools{position:absolute;inset:0;overflow:auto;padding:30px 5vw 60px;column-count:3;column-gap:22px}
@media(max-width:1100px){.dk-tools{column-count:2}}
@media(max-width:720px){.dk-tools{column-count:1}}
.dk-cat{break-inside:avoid;margin-bottom:22px;border-radius:18px;padding:18px 18px 14px;
  background:rgba(23,33,56,.035);border:1px solid rgba(23,33,56,.08);box-shadow:0 1px 2px rgba(16,24,40,.05)}
.dk-cat h3{display:flex;align-items:center;gap:10px;font-size:14px;margin-bottom:14px}
.dk-cat h3 .d{width:10px;height:10px;border-radius:3px}
.dk-cat h3 .c{margin-left:auto;font-size:11px;color:#6a7488;font-weight:500}
.dk-chiplist{display:flex;flex-wrap:wrap;gap:8px}
.dk-tool{font-size:12.5px;padding:7px 12px;border-radius:9px;background:rgba(23,33,56,.05);border:1px solid rgba(23,33,56,.08);cursor:pointer;color:#44506a;display:inline-flex;align-items:center;gap:6px}
.dk-tool:hover{background:rgba(63,120,255,.22);border-color:rgba(63,120,255,.5)}
.dk-tool .live{width:6px;height:6px;border-radius:50%;background:#15a34a}
/* ---------- spotlight ---------- */
.dk-spot{position:absolute;inset:0;z-index:90;display:none;align-items:flex-start;justify-content:center;padding-top:15vh;background:rgba(3,6,13,.5)}
.dk-spot.on{display:flex}
.dk-sbox{width:min(640px,92vw);border-radius:14px;overflow:hidden;background:#ffffff;border:1px solid rgba(23,33,56,.14);box-shadow:0 24px 56px rgba(16,24,40,.18)}
.dk-srow{display:flex;align-items:center;gap:12px;padding:16px 18px;border-bottom:1px solid rgba(23,33,56,.1)}
.dk-srow svg{width:20px;height:20px;opacity:.55}
.dk-sbox input{flex:1;border:0;outline:0;background:transparent;color:#1a2233;font:inherit;font-size:19px}
.dk-sres{max-height:48vh;overflow:auto;padding:6px}
.dk-sr{display:flex;align-items:center;gap:12px;padding:9px 12px;border-radius:11px;cursor:pointer}
.dk-sr.sel,.dk-sr:hover{background:rgba(63,120,255,.26)}
.dk-sr .ic{width:30px;height:30px;border-radius:8px;flex:none;display:grid;place-items:center;font-size:11px;font-weight:700;color:#fff;background:linear-gradient(160deg,var(--a,#3f78ff),rgba(0,0,0,.35));overflow:hidden}
.dk-sr .ic img{width:22px;height:22px;object-fit:contain;background:#fff;border-radius:5px;padding:2px}
.dk-sr .ic .mono{width:100%;height:100%;display:grid;place-items:center}
.dk-sr .l{font-size:13.5px}.dk-sr .g{margin-left:auto;font-size:11px;color:#687388}
.dk-empty{padding:26px;text-align:center;color:#6a7488;font-size:13px}
/* ---------- tools gallery (large, full-screen) ---------- */
.dk-gal{overflow:auto;padding:36px 5vw 72px}
.dk-gal .gcat{margin:0 0 36px}
.dk-gal .ghead{display:flex;align-items:center;gap:11px;margin:0 0 17px}
.dk-gal .ghead .gd{width:11px;height:11px;border-radius:3px}
.dk-gal .ghead h3{font-size:16.5px;font-weight:700;letter-spacing:-.01em}
.dk-gal .ghead .gc{font-size:12px;color:#687388;font-weight:500}
.dk-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(236px,1fr));gap:10px}
.dk-gcard{position:relative;display:flex;flex-direction:row;align-items:center;gap:12px;min-height:60px;padding:11px 42px 11px 12px;border-radius:12px;cursor:pointer;
  background:#fff;border:1px solid rgba(23,33,56,.08);
  box-shadow:none;opacity:0;transform:translateY(6px);
  transition:transform .3s cubic-bezier(.2,.8,.2,1),opacity .3s ease,border-color .2s,box-shadow .2s}
.dk-gcard.in{opacity:1;transform:none}
.dk-gcard:hover{transform:translateY(-1px);border-color:var(--a,#3f78ff);box-shadow:0 4px 12px rgba(16,24,40,.06)}
.dk-gcard .gi{flex:none;width:34px;height:34px;border-radius:9px;display:grid;place-items:center;color:#fff;
  background:var(--a,#3f78ff)}
.dk-gcard .gi svg{width:18px;height:18px}
.dk-gcard .gt{min-width:0;font-size:13.5px;font-weight:600;line-height:1.3;color:#1a2233}
.dk-gcard .glive{position:absolute;top:8px;left:40px;width:8px;height:8px;border-radius:50%;background:#15a34a;box-shadow:0 0 0 2px #fff}
.dk-gcard .garr{display:none;align-items:center;gap:5px;font-size:11.5px;font-weight:600;color:#5a6680;opacity:0;transform:translateX(-4px);transition:opacity .2s,transform .2s}
.dk-gcard .garr svg{width:13px;height:13px}
.dk-gcard:hover .garr{opacity:1;transform:none;color:#38435c}
/* ---------- in-deck tool workspace ---------- */
.dk-work{position:absolute;inset:56px 0 0;z-index:35;display:flex;flex-direction:column;background:#f4f6fa}
.dk-work[hidden]{display:none}
.dk-work.opening{animation:dkWorkIn .34s cubic-bezier(.2,.8,.2,1)}
@keyframes dkWorkIn{from{opacity:0;transform:scale(.99)}to{opacity:1;transform:none}}
.dk-wbar{flex:none;display:flex;align-items:center;gap:14px;padding:12px 20px;border-bottom:1px solid rgba(23,33,56,.08);background:#eef1f7}
.dk-wback{display:inline-flex;align-items:center;gap:7px;padding:8px 14px;border-radius:11px;border:1px solid rgba(23,33,56,.12);background:rgba(23,33,56,.05);color:#38435c;font:inherit;font-weight:600;font-size:13px;cursor:pointer}
.dk-wback:hover{background:rgba(23,33,56,.1)}
.dk-wback svg{width:15px;height:15px;transform:rotate(180deg)}
.dk-wtitle{display:flex;align-items:center;gap:11px;font-weight:700;font-size:15px;min-width:0;flex:1}
.dk-wtitle .wi{flex:none;width:30px;height:30px;border-radius:9px;display:grid;place-items:center;color:#fff;background:linear-gradient(158deg,var(--a,#3f78ff),rgba(0,0,0,.34))}
.dk-wtitle .wi svg{width:16px;height:16px}
.dk-wtitle .wt{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dk-wact{flex:none}
.dk-wact.pinned{color:#b7791f;border-color:rgba(245,197,66,.4);background:rgba(245,197,66,.12)}
.dk-wfull{margin-left:0;flex:none;font-size:12.5px;font-weight:600;color:#5a6680;cursor:pointer;padding:7px 12px;border-radius:10px;border:1px solid rgba(23,33,56,.1)}
.dk-wfull:hover{background:rgba(23,33,56,.07);color:#38435c}
.dk-wframe{flex:1;position:relative;overflow:hidden}
.dk-wframe iframe{position:absolute;inset:0;width:100%;height:100%;border:0;background:#f4f6fa;opacity:0;transition:opacity .15s ease}
.dk-wframe iframe.off{visibility:hidden;pointer-events:none}
.dk-wframe iframe.in{opacity:1}
.dk-wload{position:absolute;inset:0;display:grid;place-items:center;color:#6a7488;font-size:13px;letter-spacing:.03em;pointer-events:none}
.dk-wload .sp{width:30px;height:30px;border-radius:50%;border:2.5px solid rgba(23,33,56,.14);border-top-color:#4f86ff;animation:dkSpin .8s linear infinite;margin:0 auto 12px}
@keyframes dkSpin{to{transform:rotate(360deg)}}
/* ======================= command-center chrome ======================= */
/* Three real columns: the brand and right clusters each keep their own space
   (minmax(max-content,1fr) — the two 1fr tracks stay equal, so the centre track
   is viewport-centred), and the tab strip lives in the middle auto track. When
   the tabs don't fit they scroll inside that track (min-width:0 + overflow on
   .dk-tabs) instead of spilling over and overlapping the right-side controls. */
/* Header: [nav toggle][brand][breadcrumb .... ][search][controls]. Every track can
   shrink (minmax(0,…)) and the search field gives way first, so nothing ever overlaps. */
.dk-top{display:grid;grid-template-columns:auto auto minmax(0,1fr) minmax(0,440px) auto;align-items:center;gap:14px;padding:0 16px 0 11px;border-bottom:1px solid rgba(23,33,56,.09);background:#fff}
.dk-top>.dk-brand{flex:none;justify-self:start;min-width:0}
.dk-top>.dk-right{flex:none;justify-self:end;margin-left:0;min-width:0}
.dk-brand{appearance:none;border:0;background:transparent;cursor:pointer;flex:none}
.dk-brand .dk-wsname{margin-left:9px;padding-left:10px;border-left:1px solid rgba(23,33,56,.14);font-family:system-ui,sans-serif;font-weight:600;font-size:12px;letter-spacing:.02em;color:#687388}
/* right-side controls */
.dk-icbtn{appearance:none;border:1px solid rgba(23,33,56,.1);background:rgba(23,33,56,.04);color:#44506a;width:34px;height:34px;border-radius:10px;display:grid;place-items:center;cursor:pointer;position:relative;flex:none;transition:background .15s,border-color .15s}
.dk-icbtn:hover{background:rgba(23,33,56,.1);border-color:rgba(23,33,56,.2);color:#141c2e}
.dk-icbtn svg{width:17px;height:17px}
.dk-icbtn.dk-lbtn{width:auto;padding:0 12px 0 9px;display:inline-flex;align-items:center;gap:6px;font:inherit;font-size:13px;font-weight:600;color:#26324a}
.dk-icbtn.dk-lbtn svg{width:16px;height:16px}
.dk-icbtn.dk-lbtn.ai{color:#1f5fd6;background:rgba(47,111,235,.08);border-color:rgba(47,111,235,.28)}
.dk-icbtn.dk-lbtn.ai:hover{background:rgba(47,111,235,.15);border-color:rgba(47,111,235,.45);color:#1748a8}
@media(max-width:1180px){.dk-icbtn.dk-lbtn{width:34px;padding:0;display:grid}.dk-icbtn.dk-lbtn .lb{display:none}}
.dk-badge{position:absolute;top:-4px;right:-4px;min-width:16px;height:16px;padding:0 4px;border-radius:9px;background:#f0484a;color:#fff;font-size:10px;font-weight:700;display:grid;place-items:center;box-shadow:0 0 0 2px #f4f6fa}
.dk-health{appearance:none;cursor:default;border:1px solid rgba(23,33,56,.1);background:rgba(23,33,56,.04);color:#5a6680;font:inherit;font-size:12px;font-weight:600;padding:7px 12px;border-radius:999px;display:inline-flex;align-items:center;gap:8px;flex:none}
.dk-health .d{width:7px;height:7px;border-radius:50%;background:#12a85f}
.dk-health.warn{border-color:rgba(245,181,68,.35);background:rgba(245,181,68,.12);color:#c99320}
.dk-health.warn .d{background:#b7791f}
@media(max-width:1510px){.dk-brand .dk-wsname{display:none}}
@media(max-width:1600px){.dk-clock{display:none}}
@media(max-width:1180px){.dk-health .t{display:none}.dk-crumb .cg,.dk-crumb .cs{display:none}}
/* ---------- application shell: sidebar, breadcrumb, header search ---------- */
.dk{--dk-sw:248px;zoom:var(--dkz,1)}
.dk.nav-rail{--dk-sw:64px}
.dk.nav-phone{--dk-sw:0px}
/* Larger screens get proportionally larger type and spacing instead of empty margins. */
@media(min-width:1800px){.dk{--dkz:1.08}}
@media(min-width:2200px){.dk{--dkz:1.18}}
@media(min-width:2800px){.dk{--dkz:1.3}}
.dk.dense{zoom:calc(var(--dkz,1) * .9)}
.dk td,.dk th{overflow-wrap:anywhere}
.dk-nvhb{appearance:none;border:0;background:none;font-family:inherit;cursor:pointer;width:100%;display:flex;align-items:center;gap:6px;text-align:left;border-radius:8px}
.dk-nvhb .ov{margin-left:auto;font-size:10px;font-weight:600;letter-spacing:0;text-transform:none;opacity:0;transition:opacity .15s}
.dk-nvhb:hover,.dk-nvhb.on,.dk-nvhb:focus-visible{color:#2552c6}
.dk-nvhb:hover .ov,.dk-nvhb.on .ov,.dk-nvhb:focus-visible .ov{opacity:1}
.dk.nav-rail .dk-nvhb{pointer-events:none}.dk.nav-rail .dk-nvhb .ov{display:none}
.dk-acts{display:flex;flex-direction:column;gap:8px}
.dk-act{display:flex;align-items:center;gap:14px;padding:12px 14px;border-radius:12px;background:#fff;border:1px solid rgba(23,33,56,.08)}
.dk-act .bar{width:4px;align-self:stretch;border-radius:4px;background:var(--c);flex:none}
.dk-act .tx{flex:1;min-width:0;display:flex;flex-direction:column;gap:2px}
.dk-act .tx b{font-size:13.5px;color:#141c2e;overflow-wrap:anywhere}
.dk-act .tx span{font-size:12.5px;color:#5a6680;overflow-wrap:anywhere;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.dk-act>.dk-tibtn{flex:none;height:34px}
.dk-actform{display:flex;gap:8px;flex-wrap:wrap;flex:none;align-items:center}
.dk-actform .dk-tibtn{height:34px}
.dk .dk-actform input{height:34px;border-radius:8px;border:1px solid rgba(23,33,56,.16);padding:0 10px;font:inherit;font-size:13px;width:190px;background:#fff;color:#1a2233;outline:none}
.dk .dk-actform input:focus{border-color:#4f86ff}
@media(max-width:720px){.dk-act{flex-wrap:wrap}.dk-actform{width:100%}.dk .dk-actform input{flex:1;width:auto;min-width:0}}
.dk-fndbulk{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:10px 12px;margin-bottom:10px;border-radius:10px;background:rgba(79,134,255,.08);border:1px solid rgba(79,134,255,.22);font-size:13px;color:#38435c}
.dk-fndbulk .dk-tibtn{height:32px}
.dk-fndt th.ck,.dk-fndt td.ck{width:36px}
.dk-fndt td.nm{cursor:pointer}
.dk-onb{padding:14px 2px}
.dk-onb>b{display:block;font-size:15px;color:#141c2e}
.dk-onb>p{color:#5a6680;font-size:13px;line-height:1.55;margin:6px 0 14px}
.dk-onb .dk-qa{grid-template-columns:repeat(auto-fill,minmax(220px,1fr))}
.dk-sectgrid{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(0,1fr);gap:18px;align-items:start}
@media(max-width:1100px){.dk-sectgrid{grid-template-columns:1fr}}
.dk-sect .dk-qa{grid-template-columns:repeat(auto-fill,minmax(230px,1fr))}
.dk-srcs{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:8px}
.dk-src{display:flex;flex-wrap:wrap;align-items:center;gap:6px 10px;padding:10px 12px;border-radius:10px;border:1px dashed rgba(23,33,56,.18);background:rgba(23,33,56,.02);color:#8a93a6;min-height:48px}
.dk-src .nm{flex:1 1 100%;min-width:0;font-weight:600;font-size:13px;overflow-wrap:break-word}
.dk-src .st{font-size:11.5px;flex:1}
.dk-srcpub{font-size:12.5px;color:#5a6680;line-height:1.55;margin:12px 0 0;overflow-wrap:break-word}.dk-srcpub b{color:#38435c}
.dk-src .dk-tibtn{height:30px;padding:0 10px;font-size:12px}
.dk-src.on{border-style:solid;border-color:rgba(18,168,95,.35);background:rgba(18,168,95,.06);color:#1a2233}
.dk-src.on .st{color:#12a85f;font-weight:700}
.dk[data-ui=deck] .dk-scene{top:56px;left:var(--dk-sw);transition:left .18s ease}
.dk-sbtog{border-color:transparent;background:transparent}
.dk-crumb{min-width:0;display:flex;align-items:center;gap:8px;font-size:13px;color:#6a7488;white-space:nowrap;overflow:hidden;padding-left:6px}
.dk-crumb b{color:#141c2e;font-weight:650;overflow:hidden;text-overflow:ellipsis}
.dk-crumb .cs{color:#b3bac8}
.dk-hsearch{appearance:none;display:flex;align-items:center;gap:10px;width:100%;min-width:0;height:36px;padding:0 10px 0 12px;border:1px solid rgba(23,33,56,.13);background:#f6f8fb;color:#6a7488;font:inherit;font-size:13px;cursor:pointer;transition:border-color .15s,background .15s}
.dk-hsearch:hover{border-color:rgba(47,99,224,.45);background:#fff}
.dk-hsearch svg{width:15px;height:15px;flex:none}
.dk-hsearch .hs{flex:1;min-width:0;text-align:left;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dk-hsearch kbd{flex:none;font:inherit;font-size:11px;font-weight:600;color:#5a6680;background:rgba(23,33,56,.07);border:1px solid rgba(23,33,56,.1);padding:1px 6px;border-radius:5px}
#dkFindBtn{display:none}
.dk-sidebar{position:absolute;top:56px;left:0;bottom:0;width:var(--dk-sw);z-index:35;display:flex;flex-direction:column;background:#fff;border-right:1px solid rgba(23,33,56,.09);transition:width .18s ease,transform .2s ease}
.dk-sbnav{flex:1;min-height:0;overflow-y:auto;overflow-x:hidden;padding:10px 12px 12px;scrollbar-width:thin}
.dk-nvh{font-size:10.5px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#8a93a6;padding:18px 10px 6px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dk-nv{appearance:none;border:0;background:transparent;width:100%;min-height:36px;display:flex;align-items:center;gap:11px;padding:7px 10px;margin:1px 0;color:#38435c;font:inherit;font-size:13.5px;font-weight:550;cursor:pointer;text-align:left;position:relative;transition:background .12s,color .12s}
.dk-nv svg{width:18px;height:18px;flex:none;color:#6a7488}
.dk-nv .nl{flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dk-nv .nc{flex:none;font-size:11px;font-weight:700;color:#5a6680;background:rgba(23,33,56,.06);border-radius:20px;padding:1px 8px}
.dk-nv:hover{background:rgba(23,33,56,.05);color:#141c2e}
.dk-nv:hover svg{color:#38435c}
.dk-nv:focus-visible{outline:2px solid #2f63e0;outline-offset:-2px}
.dk-nv.on{background:rgba(47,99,224,.1);color:#1f4fc4;font-weight:650}
.dk-nv.on svg{color:#2f63e0}
.dk-nv.on::before{content:"";position:absolute;left:-12px;top:6px;bottom:6px;width:3px;border-radius:0 3px 3px 0;background:#2f63e0}
.dk-sbfoot{flex:none;border-top:1px solid rgba(23,33,56,.08);padding:8px 12px}
.dk-sbfoot .dk-nv{color:#5a6680;font-size:12.5px}
/* icon rail */
.dk.nav-rail .dk-sbnav,.dk.nav-rail .dk-sbfoot{padding-left:10px;padding-right:10px}
.dk.nav-rail .dk-nv{justify-content:center;padding:9px 0}
.dk.nav-rail .dk-nv .nl,.dk.nav-rail .dk-nv .nc{display:none}
.dk.nav-rail .dk-nv.on::before{left:-10px}
.dk.nav-rail .dk-nvh{font-size:0;padding:9px 6px}
.dk.nav-rail .dk-nvh::after{content:"";display:block;height:1px;background:rgba(23,33,56,.1)}
.dk-fly{position:fixed;z-index:200;pointer-events:none;background:#141c2e;color:#fff;font-size:12.5px;font-weight:600;padding:6px 10px;border-radius:6px;white-space:nowrap;opacity:0;transform:translate(-4px,-50%);transition:opacity .12s,transform .12s}
.dk-fly.on{opacity:1;transform:translate(0,-50%)}
/* phones: off-canvas drawer */
.dk-sbshade{display:none}
.dk.nav-phone .dk-sidebar{top:0;width:min(290px,86vw);z-index:130;transform:translateX(-102%);box-shadow:0 16px 40px rgba(16,24,40,.22)}
.dk.nav-phone.nav-open .dk-sidebar{transform:none}
.dk.nav-phone.nav-open .dk-sbshade{display:block;position:absolute;inset:0;z-index:125;background:rgba(16,24,40,.38)}
.dk.nav-phone .dk-sbfoot{display:none}
@media(max-width:720px){
  .dk-top{grid-template-columns:auto auto 1fr auto;gap:8px;padding:0 10px}
  .dk-crumb,.dk-hsearch,.dk-health,#dkNew{display:none}
  #dkFindBtn{display:grid}
  .dk-right{gap:7px}
}
.dk-acct{appearance:none;border:1px solid rgba(23,33,56,.1);background:rgba(23,33,56,.04);cursor:pointer;height:34px;padding:0 8px 0 5px;border-radius:999px;display:inline-flex;align-items:center;gap:5px;flex:none}
.dk-acct:hover{background:rgba(23,33,56,.1)}
.dk-acct .av{width:26px;height:26px;border-radius:50%;display:grid;place-items:center;font-size:11px;font-weight:700;color:#fff;background:#2f63e0;overflow:hidden}
.dk-acct .av img{width:100%;height:100%;object-fit:cover;border-radius:50%}
.dk-acct svg{width:14px;height:14px;color:#687388}
/* popover menus (notifications / create / account) */
.dk-pop{position:absolute;top:52px;z-index:120;min-width:240px;max-width:360px;border-radius:15px;overflow:hidden;
  background:#ffffff;
  border:1px solid rgba(23,33,56,.12);box-shadow:0 12px 32px rgba(16,24,40,.14);display:none}
.dk-pop.on{display:block;animation:dkPop .18s ease}
@keyframes dkPop{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
.dk-pop-h{display:flex;align-items:center;justify-content:space-between;padding:13px 16px;border-bottom:1px solid rgba(23,33,56,.08);font-size:12px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:#5a6680}
.dk-pop-h button{appearance:none;border:0;background:transparent;color:#6a7488;font:inherit;font-size:11px;cursor:pointer;text-transform:none;letter-spacing:0}
.dk-pop-h button:hover{color:#38435c}
.dk-mi{display:flex;align-items:center;gap:11px;width:100%;padding:11px 16px;background:transparent;border:0;color:#38435c;font:inherit;font-size:13.5px;cursor:pointer;text-align:left}
.dk-mi:hover{background:rgba(63,120,255,.16)}
.dk-mi svg{width:16px;height:16px;color:#5a6680;flex:none}
.dk-mi .sub{display:block;font-size:11.5px;color:#687388;margin-top:1px}
.dk-mi-div{height:1px;background:rgba(23,33,56,.08);margin:4px 0}
.dk-acctcard{padding:14px 16px;border-bottom:1px solid rgba(23,33,56,.08)}
.dk-acctcard b{font-size:14px;color:#1a2233}.dk-acctcard span{display:block;font-size:12px;color:#687388;margin-top:2px;word-break:break-all}
.dk-notif{max-height:60vh;overflow:auto}
.dk-nrow{display:flex;gap:11px;padding:12px 16px;border-bottom:1px solid rgba(23,33,56,.05)}
.dk-nrow .nd{width:8px;height:8px;border-radius:50%;background:#4f86ff;flex:none;margin-top:5px}
.dk-nrow.seen .nd{background:rgba(23,33,56,.18);box-shadow:none}
.dk-nrow .nt{font-size:13px;color:#38435c;line-height:1.35}
.dk-nrow .na{font-size:11px;color:#6a7488;margin-top:2px}
.dk-nempty{padding:26px 16px;text-align:center;color:#6a7488;font-size:13px}
/* ======================= Overview workspace ======================= */
.dk-ov,.dk-surf,.dk-cloud,.dk-comp,.dk-con2,.dk-ti,.dk-inv{position:absolute;inset:56px 0 0;overflow:auto;padding:26px clamp(20px,2.6vw,44px) 60px}
.dk-ovhead{display:flex;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;gap:14px;margin-bottom:22px}
.dk-ovhead h1{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,system-ui,sans-serif;font-size:26px;font-weight:800;letter-spacing:-.02em;color:#141c2e}
.dk-ovhead p{font-size:13.5px;color:#687388;margin-top:5px;max-width:620px}
.dk-ovhead .when{font-size:12.5px;color:#6a7488;text-align:right}
@media(max-width:720px){.dk-ovhead .when{text-align:left}.dk-kpis{grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.dk-kpi .kn{font-size:24px}}
.dk-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(168px,1fr));gap:14px;margin-bottom:12px}
.dk-ov .dk-kpis:not(#dkInvKpis){grid-template-columns:repeat(4,minmax(0,1fr))}
@media(min-width:1600px){.dk-ov .dk-kpis:not(#dkInvKpis){grid-template-columns:repeat(7,minmax(0,1fr))}}
@media(min-width:721px) and (max-width:1599px){.dk-ov .dk-kpis:not(#dkInvKpis)>.dk-kpi:first-child{grid-row:span 2;display:flex;flex-direction:column;justify-content:center}.dk-ov .dk-kpis:not(#dkInvKpis)>.dk-kpi:first-child .kn{font-size:46px}}
@media(max-width:720px){.dk-ov .dk-kpis:not(#dkInvKpis)>.dk-kpi:first-child{grid-column:span 2}}
@media(max-width:720px){.dk-kpis,.dk-ov .dk-kpis:not(#dkInvKpis){grid-template-columns:repeat(2,minmax(0,1fr))}}
.dk-expnote{font-size:12px;color:#5a6680;line-height:1.5;margin:0 0 22px;padding:9px 13px;background:rgba(23,33,56,.03);border:1px solid rgba(23,33,56,.08);border-radius:9px}
.dk-expnote b{color:#141c2e;font-weight:700}
.dk-kpi{position:relative;padding:16px 16px 15px 18px;border-radius:12px;background:rgba(23,33,56,.025);border:1px solid rgba(23,33,56,.08);cursor:pointer;transition:transform .16s,border-color .16s,background .16s;overflow:hidden;text-align:left}
.dk-kpi::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--a,#4f86ff)}
.dk-kpi:hover{transform:translateY(-2px);border-color:color-mix(in srgb,var(--a,#4f86ff) 55%,rgba(23,33,56,.08));background:rgba(23,33,56,.045)}
.dk-kpi .ki{position:absolute;top:13px;right:13px;width:25px;height:25px;border-radius:7px;display:grid;place-items:center;color:var(--a,#4f86ff);background:color-mix(in srgb,var(--a,#4f86ff) 16%,transparent)}
.dk-kpi .ki svg{width:14px;height:14px}
.dk-kpi .kn{font-size:28px;font-weight:800;line-height:1;letter-spacing:-.02em;color:#141c2e;font-variant-numeric:tabular-nums}
.dk-kpi .kl{font-size:10.5px;letter-spacing:.07em;text-transform:uppercase;color:#687388;margin-top:9px;font-weight:600}
.dk-kpi .ks{font-size:11px;font-weight:500;color:#8a93a6;margin-top:4px}
.dk-ovgrid{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(0,1fr);gap:18px}
.dk-ovgrid>*{min-width:0}
@media(max-width:900px){.dk-ovgrid{grid-template-columns:1fr}.dk-ov,.dk-surf,.dk-cloud,.dk-comp,.dk-con2,.dk-ti,.dk-inv{padding:24px 16px 56px}}
.dk-ovp{border-radius:18px;background:rgba(23,33,56,.03);border:1px solid rgba(23,33,56,.08);padding:18px 20px;box-shadow:0 1px 2px rgba(16,24,40,.05);margin-bottom:18px}
.dk-ovp h2{font-size:15px;font-weight:700;margin:0 0 14px;display:flex;align-items:center;gap:9px}
.dk-ovp h2 svg{width:17px;height:17px;flex:none;color:#2552c6}
.dk-ovp h2 .mo{margin-left:auto;font-size:12px;font-weight:600;color:#2552c6;cursor:pointer;white-space:nowrap}
.dk-ovp h2 .mo:hover{color:#44506a}
.dk-ovact .r{display:flex;align-items:center;gap:11px;padding:9px 0;border-top:1px solid rgba(23,33,56,.055)}
.dk-ovact .r:first-child{border-top:0}
.dk-ovact .r .dot{width:7px;height:7px;border-radius:50%;background:#4f86ff;flex:none}
.dk-ovact .r .tx{font-size:13px;color:#38435c;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dk-ovact .r .ag{font-size:11.5px;color:#6a7488;flex:none}
.dk-qa{display:grid;grid-template-columns:1fr 1fr;gap:11px}
.dk-qacard{appearance:none;font:inherit;text-align:left;align-items:flex-start;display:flex;flex-direction:column;gap:7px;padding:15px;border-radius:14px;background:rgba(23,33,56,.04);border:1px solid rgba(23,33,56,.08);cursor:pointer;transition:transform .18s,border-color .18s,background .18s}
.dk-qacard:hover{transform:translateY(-2px);background:rgba(63,120,255,.14);border-color:rgba(63,120,255,.4)}
.dk-qacard .qi{width:30px;height:30px;border-radius:8px;display:grid;place-items:center;color:var(--a,#4f86ff);background:color-mix(in srgb,var(--a,#4f86ff) 16%,transparent)}
.dk-qacard .qi svg{width:16px;height:16px}
.dk-qacard b{font-size:13.5px;color:#1a2233}
.dk-qacard span{font-size:11.5px;color:#687388;line-height:1.35}
.dk-gauge{display:flex;align-items:center;gap:16px}
.dk-gauge .ring{--p:0;--c:#12a85f;width:92px;height:92px;border-radius:50%;flex:none;display:grid;place-items:center;
  background:conic-gradient(var(--c) calc(var(--p)*1%),rgba(23,33,56,.08) 0)}
.dk-gauge .ring i{width:72px;height:72px;border-radius:50%;background:#eef1f7;display:grid;place-items:center;font-style:normal;font-size:19px;font-weight:800;color:#141c2e}
.dk-gauge .gmeta b{font-size:15px;color:#1a2233}.dk-gauge .gmeta p{font-size:12px;color:#687388;margin-top:4px;line-height:1.4}
.dk-sevbar{display:flex;height:10px;border-radius:6px;overflow:hidden;margin:12px 0 10px;background:rgba(23,33,56,.06)}
.dk-sevbar span{height:100%}
.dk-sevleg{display:flex;flex-wrap:wrap;gap:12px;font-size:11.5px;color:#5a6680}
.dk-sevleg i{width:9px;height:9px;border-radius:2px;display:inline-block;margin-right:5px;vertical-align:-1px}
/* ======================= Tools workspace (rail + search) ======================= */
.dk-tools2{position:absolute;inset:56px 0 0;display:flex;flex-direction:column}
.dk-tbar{flex:none;display:flex;align-items:center;gap:14px;padding:18px 4vw 14px}
.dk-tsearch{flex:1;max-width:520px;height:40px;display:flex;align-items:center;gap:10px;padding:0 14px;border-radius:10px;background:rgba(23,33,56,.05);border:1px solid rgba(23,33,56,.1)}
.dk-tsearch:focus-within{border-color:rgba(79,134,255,.6);background:rgba(79,134,255,.08)}
.dk-tsearch svg{width:17px;height:17px;color:#687388;flex:none}
.dk .dk-tsearch input{flex:1;min-width:0;width:auto;height:100%;min-height:0!important;margin:0!important;padding:0!important;border:0!important;border-radius:0!important;outline:0;box-shadow:none!important;background:transparent!important;color:#1a2233;font:inherit;font-size:14px;-webkit-appearance:none;appearance:none}
.dk .dk-tsearch input::-webkit-search-decoration{-webkit-appearance:none}
@media(max-width:640px){.dk-tbar{padding:14px 16px 10px;gap:10px}.dk-tsearch{max-width:none}}
.dk-tcount{font-size:12.5px;color:#687388;margin-left:auto;flex:none}
.dk-tbody{flex:1;display:flex;min-height:0}
.dk-tnav{flex:none;width:calc(236px + 4vw);overflow-x:hidden;overflow-y:auto;padding:4px 12px 30px 4vw;scrollbar-width:thin;scrollbar-color:rgba(23,33,56,.16) transparent}
.dk-tcat{display:flex;align-items:center;gap:9px;width:100%;white-space:nowrap;padding:9px 12px;margin-bottom:3px;border:0;border-radius:11px;background:transparent;color:#5a6680;font:inherit;font-size:13px;font-weight:600;cursor:pointer;text-align:left;transition:background .15s,color .15s}
.dk-tcat:hover{background:rgba(23,33,56,.05);color:#38435c}
.dk-tcat.on{background:rgba(47,95,255,.16);color:#2552c6}
.dk-tcat .cd{width:9px;height:9px;border-radius:3px;flex:none}
.dk-tcat .tl{min-width:0;white-space:normal;overflow-wrap:anywhere;line-height:1.25}
.dk-tcat .n{flex:none;margin-left:auto;font-size:11.5px;font-weight:600;color:#6a7488;background:rgba(23,33,56,.06);padding:1px 8px;border-radius:999px}
.dk-tcat.on .n{color:#38435c;background:rgba(23,33,56,.12)}
.dk-tmain{flex:1;overflow:auto;padding:4px 4vw 60px 24px;scrollbar-width:thin;scrollbar-color:rgba(23,33,56,.16) transparent}
@media(max-width:820px){.dk-tnav{display:none}.dk-tmain{padding:4px 18px 56px}}
.dk-tsec{margin:0 0 30px}
.dk-tsec .th{display:flex;align-items:center;gap:10px;margin:0 0 14px}
.dk-tsec .th .d{flex:none;width:10px;height:10px;border-radius:3px;background:currentColor}
.dk-tsec .th h3{font-size:15px;font-weight:700;letter-spacing:-.01em}
.dk-tsec .th .c{font-size:12px;color:#687388;font-weight:500}
.dk-tnone{padding:40px;text-align:center;color:#6a7488;font-size:14px}
/* ======================= Threat Intel workspace ======================= */
.dk-ti-head{display:flex;align-items:center;flex-wrap:wrap;gap:14px;margin-bottom:18px}
.dk-ti-head h1{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,system-ui,sans-serif;font-size:22px;font-weight:800;letter-spacing:-.02em;color:#141c2e}
.dk-ti-head .mo{margin-left:auto;font-size:12.5px;font-weight:600;color:#2552c6;cursor:pointer;display:inline-flex;align-items:center;gap:6px}
.dk-ti-head .mo svg{width:14px;height:14px}
.dk-sevchips{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:18px}
.dk-sevchip{padding:12px 16px;border-radius:13px;background:rgba(23,33,56,.035);border:1px solid rgba(23,33,56,.08);min-width:104px}
.dk-sevchip .n{font-size:22px;font-weight:800;line-height:1;font-variant-numeric:tabular-nums}
.dk-sevchip .l{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:#687388;margin-top:6px}
.dk-cve{display:flex;gap:13px;padding:13px 16px;border-radius:13px;background:rgba(23,33,56,.03);border:1px solid rgba(23,33,56,.07);margin-bottom:9px;cursor:pointer;transition:border-color .15s,background .15s}
.dk-cve:hover{background:rgba(23,33,56,.055);border-color:rgba(23,33,56,.18)}
.dk-cve .sv{flex:none;width:52px;text-align:center;font-weight:800;font-size:15px;font-variant-numeric:tabular-nums}
.dk-cve .sv small{display:block;font-size:9.5px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;margin-top:3px}
.dk-cve .bd{min-width:0}
.dk-cve.kev{border-color:rgba(224,56,58,.35);background:rgba(224,56,58,.045)}
.dk-cve .bd .id{font-size:13px;font-weight:700;color:#1a2233;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.dk-kevb{font-size:10px;font-weight:700;letter-spacing:.03em;text-transform:uppercase;color:#fff;background:#e0383a;padding:2px 7px;border-radius:5px}
.dk-epssb{font-size:10.5px;font-weight:700;color:#8a5a00;background:rgba(245,146,11,.14);border:1px solid rgba(245,146,11,.3);padding:1px 7px;border-radius:5px}
.dk-ransom{margin:4px 0 18px}
.dk-ransom .ct .src{font-size:10.5px;font-weight:600;color:#12a85f;margin-left:8px;text-transform:none;letter-spacing:0}
.dk-rtab{width:100%;border-collapse:collapse;font-size:12.5px;margin-top:10px}
.dk-rtab th{text-align:left;padding:7px 10px;color:#6a7488;font-size:10.5px;letter-spacing:.05em;text-transform:uppercase;border-bottom:1px solid rgba(23,33,56,.1)}
.dk-rtab td{padding:8px 10px;border-bottom:1px solid rgba(23,33,56,.06);color:#38435c}
.dk-rtab tr:last-child td{border-bottom:0}
.dk-cve .bd .ti{font-size:12.5px;color:#5a6680;margin-top:3px;line-height:1.4;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.dk-cve .bd .dt{font-size:11px;color:#6a7488;margin-top:5px}
.dk-loading{display:flex;align-items:center;gap:12px;color:#687388;font-size:13.5px;padding:30px 4px}
.dk-loading .sp{width:22px;height:22px;border-radius:50%;border:2.5px solid rgba(23,33,56,.14);border-top-color:#4f86ff;animation:dkSpin .8s linear infinite}
.dk-errbox{padding:22px;border-radius:14px;background:rgba(240,72,74,.1);border:1px solid rgba(240,72,74,.3);color:#c0282a;font-size:13px;line-height:1.5}
.dk-errbox button{margin-top:12px}
.dk-surfp .dk-errbox{padding:12px 14px;border-radius:10px;font-size:12.5px}
/* ======================= Investigations workspace ======================= */
.dk-inv h1{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,system-ui,sans-serif;font-size:22px;font-weight:800;letter-spacing:-.02em;color:#141c2e;margin-bottom:6px}
.dk-inv .sub{font-size:13px;color:#687388;margin-bottom:20px}
.dk-invtypes{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px;margin:14px 0 8px}
.dk-invtype{padding:14px 16px;border-radius:13px;background:rgba(23,33,56,.035);border:1px solid rgba(23,33,56,.08)}
.dk-invtype .n{font-size:24px;font-weight:800;color:#141c2e;font-variant-numeric:tabular-nums}
.dk-invtype .l{font-size:12px;color:#5a6680;margin-top:4px;text-transform:capitalize}
/* ======================= Assistant workspace ======================= */
.dk-asst{position:absolute;inset:56px 0 0;display:flex;flex-direction:column}
.dk-asst .dk-wframe{flex:1;position:relative}
/* ======================= overview: added widgets ======================= */
.dk-ask{display:flex;align-items:center;gap:10px;margin:0 0 8px;padding:6px 6px 6px 16px;border-radius:12px;background:rgba(23,33,56,.04);border:1px solid rgba(23,33,56,.1)}
.dk-askhint{font-size:12px;color:#6a7488;line-height:1.5;margin:0 0 22px 2px}
.dk-ask:focus-within{border-color:rgba(63,120,255,.5);background:rgba(63,120,255,.07)}
.dk-ask .ai{flex:none;color:#2552c6;display:grid;place-items:center}.dk-ask .ai svg{width:18px;height:18px}
.dk-ask input{flex:1;min-width:0;border:0;outline:0;background:transparent;color:#141c2e;font:inherit;font-size:14px}
.dk-ask input::placeholder{color:#8a93a6}
.dk-ask button{flex:none;appearance:none;border:0;border-radius:9px;background:#2f6bff;color:#fff;font:inherit;font-weight:700;font-size:13px;padding:10px 16px;cursor:pointer;display:inline-flex;align-items:center;gap:7px}
.dk-ask button:hover{background:#3f78ff}.dk-ask button svg{width:15px;height:15px}
.dk-ovgrid3{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:18px;margin-bottom:18px}
.dk-ovgrid3>*{min-width:0}
@media(max-width:1100px){.dk-ovgrid3{grid-template-columns:1fr 1fr}}
@media(max-width:720px){.dk-ovgrid3{grid-template-columns:1fr}}
.dk-pins{display:flex;flex-direction:column;gap:7px}
.dk-pin{display:flex;align-items:center;gap:11px;padding:10px 12px;border-radius:11px;background:rgba(23,33,56,.04);border:1px solid rgba(23,33,56,.08);cursor:pointer;transition:background .15s,border-color .15s}
.dk-pin:hover{background:rgba(63,120,255,.14);border-color:rgba(63,120,255,.4)}
.dk-pin .pi{flex:none;width:28px;height:28px;border-radius:8px;display:grid;place-items:center;color:var(--a,#4f86ff);background:color-mix(in srgb,var(--a,#4f86ff) 16%,transparent)}
.dk-pin .pi svg{width:15px;height:15px}
.dk-pin .pl{flex:1;min-width:0;font-size:13px;font-weight:600;color:#1a2233;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dk-pin .px{flex:none;appearance:none;border:0;background:transparent;color:#8a93a6;font-size:17px;line-height:1;cursor:pointer;padding:2px 4px;border-radius:6px}
.dk-pin .px:hover{color:#c0282a;background:rgba(240,72,74,.14)}
.dk .dk-notes{display:block;box-sizing:border-box;width:100%!important;max-width:100%;margin:0!important;min-height:150px;resize:vertical;border-radius:12px;border:1px solid rgba(23,33,56,.1);background:#f5f7fb;color:#1a2233;font:inherit;font-size:13px;line-height:1.55;padding:13px 14px!important;outline:none}
.dk-notes:focus{border-color:rgba(79,134,255,.55);background:#eef1f7}
.dk-notes::placeholder{color:#8a93a6}
.dk-notef{display:flex;align-items:center;justify-content:space-between;margin-top:9px;font-size:11.5px;color:#6a7488}
.dk-sys{display:flex;flex-direction:column;gap:2px}
.dk-sysrow{display:flex;align-items:center;gap:11px;padding:10px 2px;border-bottom:1px solid rgba(23,33,56,.055)}
.dk-sysrow:last-child{border-bottom:0}
.dk-sysrow .sd{flex:none;width:8px;height:8px;border-radius:50%;background:#17a86a}
.dk-sysrow.warn .sd{background:#b7791f}.dk-sysrow.off .sd{background:#8a93a6;box-shadow:none}
.dk-sysrow .sl{flex:1;font-size:13px;color:#38435c}
.dk-sysrow .sv{flex:none;font-size:12px;font-weight:600;color:#5a6680;font-variant-numeric:tabular-nums}
/* threat charts */
/* ---- investigations + activity (wave 2) ---- */
.dk-invdash{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin:4px 0 18px}
@media(max-width:1050px){.dk-invdash{grid-template-columns:1fr}}
.dk-invb{background:#ffffff;border:1px solid rgba(23,33,56,.07);border-radius:12px;padding:14px 16px}
.dk-invb .t{font-size:11px;letter-spacing:.05em;text-transform:uppercase;color:#6a7488;font-weight:700;margin-bottom:10px}
.dk-invb .track{display:flex;height:10px;border-radius:6px;overflow:hidden;background:rgba(23,33,56,.05)}
.dk-invb .track span{display:block;min-width:2px}
.dk-invb .leg{display:flex;flex-wrap:wrap;gap:8px 14px;margin-top:10px}
.dk-invb .lg{display:inline-flex;align-items:center;gap:6px;font-size:11.5px;color:#5a6680}
.dk-invb .lg i{width:9px;height:9px;border-radius:2px;flex:none}
.dk-invtypes2{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}
.dk-invtypes2 .it{background:rgba(23,33,56,.03);border-radius:8px;padding:8px 6px;text-align:center}
.dk-invtypes2 .it b{display:block;font-size:17px;color:#141c2e;font-variant-numeric:tabular-nums}
.dk-invtypes2 .it span{font-size:10px;color:#687388;line-height:1.2;display:block;margin-top:2px}
.dk-invbar{display:flex;gap:9px;flex-wrap:wrap;margin-bottom:12px}
.dk-isearch{display:flex;align-items:center;gap:8px;background:#ffffff;border:1px solid rgba(23,33,56,.1);border-radius:9px;padding:0 11px;height:38px;flex:1;min-width:180px}
.dk-isearch svg{width:15px;height:15px;color:#687388;flex:none}
.dk .dk-isearch input{flex:1;min-width:0;width:auto;height:100%;min-height:0!important;margin:0!important;padding:0!important;border:0!important;border-radius:0!important;box-shadow:none!important;background:transparent!important;outline:none;color:#1a2233;font:inherit;font-size:12.5px;-webkit-appearance:none;appearance:none}
.dk-isel{height:38px;background:#ffffff;border:1px solid rgba(23,33,56,.1);border-radius:9px;color:#44506a;font-size:12.5px;padding:0 10px;outline:none;cursor:pointer;max-width:200px}
.dk-itwrap{overflow:auto;border:1px solid rgba(23,33,56,.07);border-radius:12px}
/* borderless horizontal scroll for tables that already sit inside a padded card */
.dk-tscroll{overflow-x:auto;overflow-y:hidden;max-width:100%}
.dk-simchip{display:inline-block;margin-left:6px;font-size:10px;font-weight:700;letter-spacing:.03em;color:#6a7488;background:rgba(23,33,56,.07);border-radius:20px;padding:1px 7px;vertical-align:1px}
.dk-invsim{display:inline-flex;align-items:center;gap:7px;font-size:12px;font-weight:600;color:#5a6680;white-space:nowrap;cursor:pointer}
.dk-invsim input{width:15px;height:15px;margin:0;accent-color:#3f78ff}
.dk-invsimnote{font-size:12px;color:#5a6680;margin:-2px 0 10px;padding:7px 11px;background:rgba(23,33,56,.035);border-radius:8px}
.dk-itable{width:100%;border-collapse:collapse;font-size:12.5px}
.dk-itable th{text-align:left;font-size:10.5px;letter-spacing:.05em;text-transform:uppercase;color:#6a7488;font-weight:700;padding:10px 14px;background:#ffffff;border-bottom:1px solid rgba(23,33,56,.08);position:sticky;top:0}
.dk-itable td{padding:9px 14px;border-bottom:1px solid rgba(23,33,56,.05);color:#44506a}
.dk-itable tr[data-eid]{cursor:pointer}
.dk-itable tr[data-eid]:hover td{background:rgba(63,120,255,.08)}
.dk-itable .nm{color:#141c2e;font-weight:600}
.dk-itable .num,.dk-itable .ag{color:#687388;font-variant-numeric:tabular-nums}
.dk-itable .pill{display:inline-block;font-size:10.5px;font-weight:700;color:var(--c);border:1px solid color-mix(in srgb,var(--c) 45%,transparent);background:color-mix(in srgb,var(--c) 14%,transparent);border-radius:20px;padding:1px 9px}
.dk-astats{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:2px 0 16px}
@media(max-width:760px){.dk-astats{grid-template-columns:1fr}.dk-invtypes2{grid-template-columns:repeat(2,1fr)}}
.dk-astat{background:#ffffff;border:1px solid rgba(23,33,56,.08);border-left:3px solid var(--a,#4f86ff);border-radius:12px;padding:14px 16px}
.dk-astat .n{font-size:24px;font-weight:700;color:#141c2e;line-height:1.1}
.dk-astat .l{font-size:11.5px;color:#687388;margin-top:3px}
.dk-afbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:14px}
.dk-afch{display:inline-flex;align-items:center;gap:7px;background:#f5f7fb;border:1px solid rgba(23,33,56,.1);color:#5a6680;border-radius:20px;padding:6px 12px;font-size:12px;font-weight:600;cursor:pointer}
.dk-afch i{width:8px;height:8px;border-radius:50%;flex:none}
.dk-afch span{color:#8a93a6;font-variant-numeric:tabular-nums}
.dk-afch:hover{border-color:rgba(23,33,56,.22);color:#141c2e}
.dk-afch.on{background:rgba(63,120,255,.16);border-color:#3f78ff;color:#2552c6}
.dk-afch.on span{color:#2552c6}
.dk-ovact .r .ct{font-size:10.5px;font-weight:700;letter-spacing:.03em;flex:none;margin-left:6px}
.dk-chart{margin:6px 0 4px}
.dk-chart .ct,.dk-ransom .ct{font-size:12px;font-weight:600;color:#5a6680;margin-bottom:12px;display:flex;align-items:center;gap:8px}
.dk-chart .ct svg,.dk-ransom .ct svg{width:15px;height:15px;flex:none;color:#2552c6}
.dk-trend{display:flex;align-items:flex-end;gap:10px;min-height:150px;padding-top:6px}
.dk-trend .col{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;gap:7px;min-width:0}
.dk-trend .stk{width:100%;max-width:46px;display:flex;flex-direction:column-reverse;border-radius:5px 5px 0 0;overflow:hidden;background:rgba(23,33,56,.05)}
.dk-trend .stk span{width:100%;display:block;transition:height .5s cubic-bezier(.2,.8,.2,1)}
.dk-trend .cx{font-size:10.5px;color:#6a7488;white-space:nowrap}
.dk-trend .cn{font-size:11px;font-weight:700;color:#38435c;font-variant-numeric:tabular-nums}
.dk-twrap{display:grid;grid-template-columns:1.4fr 1fr;gap:18px;margin-bottom:20px}
@media(max-width:900px){.dk-twrap{grid-template-columns:1fr}}
.dk-tpanel{border-radius:16px;background:rgba(23,33,56,.03);border:1px solid rgba(23,33,56,.08);padding:16px 18px}
.dk-bars{display:flex;flex-direction:column;gap:9px}
.dk-barrow{display:grid;grid-template-columns:62px 1fr 34px;align-items:center;gap:10px;font-size:12px}
.dk-barrow .bl{color:#5a6680}
.dk-barrow .bt{height:9px;border-radius:5px;background:rgba(23,33,56,.06);overflow:hidden}
.dk-barrow .bt i{display:block;height:100%;border-radius:5px;transition:width .5s cubic-bezier(.2,.8,.2,1)}
.dk-barrow .bn{text-align:right;font-weight:700;color:#1a2233;font-variant-numeric:tabular-nums}
/* spotlight: pin stars + actions + footer hint */
.dk-sr .ic.act{background:color-mix(in srgb,#3f78ff 22%,transparent);color:#2552c6;display:grid;place-items:center}
.dk-sr .ic.act svg{width:16px;height:16px}
.dk-srpin{flex:none;appearance:none;border:0;background:transparent;color:#9aa4ba;cursor:pointer;padding:5px;border-radius:7px;display:grid;place-items:center;opacity:0;transition:opacity .12s,color .12s}
.dk-sr:hover .dk-srpin{opacity:1}.dk-srpin.on{opacity:1;color:#b7791f}.dk-srpin:hover{color:#b7791f;background:rgba(245,197,66,.14)}
.dk-srpin svg{width:15px;height:15px;fill:currentColor;stroke:none}
.dk-sfoot{display:flex;align-items:center;gap:16px;padding:10px 16px;border-top:1px solid rgba(23,33,56,.08);font-size:11.5px;color:#6a7488}
.dk-sfoot b{color:#5a6680;font-weight:600}
.dk-sfoot kbd{font:inherit;font-size:10.5px;background:rgba(23,33,56,.08);border:1px solid rgba(23,33,56,.12);padding:1px 6px;border-radius:5px;color:#5a6680;margin-right:3px}
/* pin star on tool chips (tools scene) */
.dk-gcpin{position:absolute;top:50%;margin-top:-12px;right:10px;z-index:2;appearance:none;border:0;background:rgba(23,33,56,.08);color:#8a93a6;cursor:pointer;width:24px;height:24px;border-radius:8px;display:grid;place-items:center;opacity:0;transition:opacity .12s,color .12s,background .12s}
.dk-gcard:hover .dk-gcpin{opacity:1}.dk-gcpin.on{opacity:1;color:#b7791f}.dk-gcpin:hover{color:#b7791f;background:rgba(245,197,66,.16)}
.dk-gcpin svg{width:14px;height:14px;fill:currentColor;stroke:none}
/* ======================= Toolkit workspace ======================= */
.dk-kit{position:absolute;inset:56px 0 0;display:flex;min-height:0}
.dk-kitnav{flex:none;width:300px;display:flex;flex-direction:column;border-right:1px solid rgba(23,33,56,.08);padding:16px 12px 24px 4vw;overflow:auto}
.dk-kitsearch{margin-bottom:12px}
.dk-kitlist{display:flex;flex-direction:column;gap:2px}
.dk-kitcat{margin-bottom:12px}
.dk-kitcat .kc-h{display:flex;align-items:center;gap:8px;font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;margin:6px 6px}
.dk-kitcat .kc-h .kc-d{width:8px;height:8px;border-radius:2px;background:currentColor}
.dk-kititem{display:block;width:100%;text-align:left;appearance:none;border:0;background:transparent;color:#5a6680;font:inherit;font-size:13px;padding:8px 11px;border-radius:9px;cursor:pointer;transition:background .14s,color .14s}
.dk-kititem:hover{background:rgba(23,33,56,.05);color:#1a2233}
.dk-kititem.on{background:rgba(47,95,255,.18);color:#2552c6;font-weight:600}
.dk-kitmain{flex:1;min-width:0;display:flex;flex-direction:column;gap:14px;padding:22px 4vw 40px 26px;overflow:auto}
@media(max-width:820px){.dk-kitnav{width:200px;padding-left:18px}.dk-kitmain{padding:18px}}
.dk-kithead{display:flex;align-items:center;gap:14px}
.dk-kithead .ki{flex:none;width:42px;height:42px;border-radius:12px;display:grid;place-items:center;color:var(--a,#4f86ff);background:color-mix(in srgb,var(--a,#4f86ff) 18%,transparent)}
.dk-kithead .ki svg{width:21px;height:21px}
.dk-kithead h2{font-size:18px;font-weight:800;color:#141c2e}
.dk-kithead p{font-size:12.5px;color:#687388;margin-top:3px}
.dk-kopts{display:flex;flex-wrap:wrap;gap:12px}
.dk-kopts:empty{display:none}
.dk-kopt{display:flex;flex-direction:column;gap:5px;font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:#687388;font-weight:600}
.dk-kopt select{appearance:none;border:1px solid rgba(23,33,56,.16);background:rgba(23,33,56,.06);color:#1a2233;font:inherit;font-size:13px;padding:8px 30px 8px 12px;border-radius:9px;cursor:pointer;text-transform:none;letter-spacing:0}
.dk-kiofield{display:flex;flex-direction:column;gap:7px;flex:1;min-height:0}
.dk-klbl{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:#687388;font-weight:600}
.dk-kobar{display:flex;align-items:center;gap:14px}
.dk-kcopy{font-size:12px;font-weight:600;color:#2552c6;cursor:pointer}
.dk-kobar .dk-kcopy:first-of-type{margin-left:auto}
.dk-kcopy:hover{color:#44506a}
.dk-kitio{width:100%;border-radius:12px;border:1px solid rgba(23,33,56,.12);background:#f5f7fb;color:#1a2233;font:13px/1.55 ui-monospace,"SF Mono",Menlo,Consolas,monospace;padding:13px 15px;outline:none;resize:vertical}
.dk-kitio:focus{border-color:rgba(79,134,255,.55);background:#eef1f7}
textarea.dk-kitio{min-height:120px}
.dk-kitout{min-height:120px;white-space:pre-wrap;word-break:break-word;overflow:auto;margin:0}
.dk-kitout.err{color:#c0282a;border-color:rgba(240,72,74,.4);background:rgba(240,72,74,.08)}
/* keyboard-shortcuts overlay */
.dk-keys{position:absolute;inset:0;z-index:95;display:none;align-items:center;justify-content:center;padding:24px;background:rgba(3,6,13,.62)}
.dk-keys.on{display:flex}
.dk-keysbox{width:min(560px,94vw);max-height:84vh;overflow:auto;border-radius:14px;background:#ffffff;border:1px solid rgba(23,33,56,.14);box-shadow:0 24px 56px rgba(16,24,40,.18);padding:22px 24px 26px}
.dk-keysbox h3{font-size:16px;font-weight:800;margin-bottom:4px}
.dk-keysbox .sub{font-size:12.5px;color:#687388;margin-bottom:16px}
.dk-keysgrp{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:#6a7488;font-weight:700;margin:16px 0 8px}
.dk-keyrow{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:7px 0;border-bottom:1px solid rgba(23,33,56,.055);font-size:13.5px;color:#38435c}
.dk-keyrow:last-child{border-bottom:0}
.dk-keyrow .kb{display:flex;gap:5px;flex:none}
.dk-keyrow kbd{font:inherit;font-size:11px;background:rgba(23,33,56,.08);border:1px solid rgba(23,33,56,.14);border-radius:6px;padding:2px 8px;color:#38435c;font-weight:600}
/* threat filter bar + export */
.dk-sevfilter{appearance:none;cursor:pointer;font:inherit;text-align:left;transition:border-color .15s,background .15s}
.dk-sevfilter:hover{border-color:rgba(23,33,56,.22)}
.dk-sevfilter.on{border-color:rgba(79,134,255,.6);background:rgba(79,134,255,.12)}
.dk-tibar{display:flex;align-items:center;gap:12px;margin:4px 0 16px;flex-wrap:wrap}
.dk-tifind{flex:1;min-width:220px;max-width:460px;height:40px;padding-top:0;padding-bottom:0;border-radius:10px}
.dk-ticount{font-size:12.5px;color:#687388}
.dk-tibtn{appearance:none;cursor:pointer;border:1px solid rgba(23,33,56,.14);background:rgba(23,33,56,.05);color:#38435c;font:inherit;font-size:12.5px;font-weight:600;height:40px;padding:0 14px;border-radius:10px;display:inline-flex;align-items:center;justify-content:center;gap:6px}
.dk-tibtn svg{width:15px;height:15px;flex:none}
.dk-tibtn:hover{background:rgba(23,33,56,.1);border-color:rgba(23,33,56,.24)}
.dk-tibtn.on{background:#2f5fd0;border-color:#2f5fd0;color:#fff}
.dk-tibtn.on:hover{background:#3f78ff;border-color:#3f78ff}
/* shared lede + section intros */
.dk-sublede{font-size:13px;color:#5a6680;line-height:1.55;max-width:860px;margin:-6px 0 18px}
/* attack surface */
.dk-surfbar{display:flex;gap:10px;margin-bottom:8px;max-width:620px}
.dk-surfbar input{flex:1;min-width:0;height:40px;padding:0 15px;border-radius:10px;border:1px solid rgba(23,33,56,.14);background:#fff;color:#141c2e;font:inherit;font-size:14px;outline:none}
.dk-surfbar input:focus{border-color:#3f78ff}
.dk-surfbar button{flex:none}
.dk-surfhint{font-size:12px;color:#6a7488;margin-bottom:20px;line-height:1.5;max-width:720px}
.dk-surfgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:16px;align-items:start}
.dk-surfp{background:#fff;border:1px solid rgba(23,33,56,.08);border-radius:14px;padding:16px 17px;min-width:0}
.dk-surfp .hd{display:flex;align-items:center;gap:10px;margin-bottom:12px;min-height:26px}
.dk-surfp .hd h2{font-size:14px;font-weight:700;color:#141c2e;margin:0}
.dk-surfp .hd .hx{margin-left:auto}
.dk-surfp .hd .mo{cursor:pointer;font-size:11.5px;color:#2552c6;font-weight:600}
.dk-surfp .hd .hx+.mo{margin-left:10px}
.dk-graphadd{appearance:none;cursor:pointer;border:1px solid rgba(18,168,95,.4);background:rgba(18,168,95,.1);color:#0d7a44;font:inherit;font-size:11px;font-weight:700;padding:3px 9px;line-height:1.4;border-radius:7px}
.dk-graphadd:hover{background:rgba(18,168,95,.18)}
.dk-surfcount{font-size:12px;color:#6a7488;margin-bottom:9px}
.dk-chipv{font-size:11.5px;color:#38435c;background:rgba(23,33,56,.05);border:1px solid rgba(23,33,56,.08);border-radius:6px;padding:3px 8px;font-variant-numeric:tabular-nums;overflow-wrap:anywhere}
.dk-chipv.more{color:#687388;font-weight:600}
.dk-dnsrow{display:flex;gap:12px;padding:7px 0;border-bottom:1px solid rgba(23,33,56,.06);font-size:12.5px}
.dk-dnsrow:last-child{border-bottom:0}
.dk-dnsrow .t{flex:none;width:48px;font-weight:700;color:#2552c6}
.dk-dnsrow .v{flex:1;min-width:0;color:#38435c;overflow-wrap:anywhere;line-height:1.5}
.dk-dnsrow .v .ln{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dk-kv{display:flex;flex-direction:column;gap:0}
.dk-kv>div{display:flex;gap:12px;padding:7px 0;border-bottom:1px solid rgba(23,33,56,.06);font-size:12.5px}
.dk-kv>div:last-child{border-bottom:0}
.dk-kv span{flex:none;width:96px;color:#6a7488}
.dk-kv b{color:#141c2e;font-weight:600;overflow-wrap:anywhere;min-width:0}
.dk-shlist{display:flex;flex-direction:column;gap:3px;margin-top:4px}
.dk-shrow{display:flex;align-items:center;gap:9px;font-size:12.5px;padding:5px 0}
.dk-shrow .d{flex:none;width:8px;height:8px;border-radius:50%}
.dk-shrow.ok .d{background:#12a85f}.dk-shrow.no .d{background:#e0383a}
.dk-shrow .l{color:#38435c;font-weight:600}
.dk-shrow .v{margin-left:auto;font-size:11.5px;color:#6a7488}
.dk-shrow.ok .v{color:#0d7a44}.dk-shrow.no .v{color:#c0352f}
.dk-techline{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0}
.dk-rec{font-size:11px;color:#5a6680;background:rgba(23,33,56,.04);border-radius:7px;padding:7px 10px;margin-top:8px;overflow-wrap:anywhere;line-height:1.5;font-variant-numeric:tabular-nums}
/* cloud */
.dk-cloudtop{display:grid;grid-template-columns:1.4fr 1fr;gap:16px;margin-bottom:24px}
@media(max-width:900px){.dk-cloudtop{grid-template-columns:1fr}.dk-surfbar{max-width:none}}
.dk-cloudwb,.dk-cloudconn{background:#fff;border:1px solid rgba(23,33,56,.08);border-radius:14px;padding:18px}
.dk-cloudwb .wbh h2,.dk-cloudconn h2{font-size:15px;font-weight:700;color:#141c2e;margin:0 0 12px}
.dk-cloudsel{width:100%;height:40px;border-radius:9px;border:1px solid rgba(23,33,56,.14);background:#fff;color:#141c2e;font:inherit;font-size:13px;padding:0 12px;cursor:pointer}
.dk-clouddesc{font-size:12px;color:#6a7488;line-height:1.5;margin:9px 0}
.dk-cloudin{width:100%;box-sizing:border-box;min-height:150px;resize:vertical;border-radius:10px;border:1px solid rgba(23,33,56,.12);background:#fbfcfe;color:#141c2e;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;line-height:1.5;padding:11px 13px;outline:none}
.dk-cloudin:focus{border-color:#3f78ff}
.dk-cloudbtns{display:flex;align-items:center;gap:14px;margin-top:11px}
.dk-cloudbtns .mo{cursor:pointer;font-size:12px;color:#2552c6;font-weight:600}
.dk-cloudout{white-space:pre-wrap;word-break:break-word;background:#0f1626;color:#d7e2f2;border-radius:10px;padding:14px;margin-top:13px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;line-height:1.55;max-height:360px;overflow:auto}
.dk-cloudconn{position:relative}
.dk-cloudconn .cc-badge{position:absolute;top:16px;right:16px;font-size:10px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:#8a5a00;background:rgba(245,146,11,.14);border:1px solid rgba(245,146,11,.3);border-radius:6px;padding:3px 8px}
.dk-cloudconn p{font-size:12.5px;color:#5a6680;line-height:1.55;margin:0 0 13px}
.dk-cloudconn .cc-list{display:flex;flex-direction:column;gap:7px;margin-bottom:14px}
.dk-cloudconn .cc-list span{font-size:12.5px;color:#38435c;padding:8px 11px;background:rgba(23,33,56,.035);border:1px solid rgba(23,33,56,.07);border-radius:8px}
.dk-cloudgridh{font-size:15px;font-weight:700;color:#141c2e;margin:4px 0 14px;display:flex;align-items:baseline;gap:10px}
.dk-cloudgridh span{font-size:12px;font-weight:600;color:#6a7488}
.dk-cloudgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px}
.dk-cloudcard{appearance:none;font:inherit;display:flex;flex-direction:column;align-items:flex-start;justify-content:flex-start;text-align:left;cursor:pointer;background:#fff;border:1px solid rgba(23,33,56,.08);border-radius:12px;padding:13px 15px;transition:border-color .15s,transform .15s}
.dk-cloudcard:hover{border-color:#3f78ff;transform:translateY(-1px)}
.dk-cloudcard b{display:block;font-size:13px;font-weight:700;color:#141c2e;margin-bottom:4px}
.dk-cloudcard span{display:-webkit-box;align-self:stretch;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;font-size:11.5px;color:#687388;line-height:1.45}
/* compliance */
.dk-compnote{font-size:12.5px;color:#5a6680;line-height:1.55;padding:11px 14px;background:rgba(79,134,255,.06);border:1px solid rgba(79,134,255,.16);border-radius:10px;margin-bottom:20px;max-width:900px}
.dk-compgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px}
.dk-compcard{appearance:none;font:inherit;display:flex;flex-direction:column;align-items:flex-start;justify-content:flex-start;position:relative;text-align:left;cursor:pointer;background:#fff;border:1px solid rgba(23,33,56,.08);border-radius:14px;padding:17px 18px;transition:border-color .15s,transform .15s}
.dk-compcard:hover{border-color:#3f78ff;transform:translateY(-1px)}
.dk-compcard b{display:block;font-size:14.5px;font-weight:700;color:#141c2e;margin-bottom:6px}
.dk-compcard>span{display:block;font-size:12.5px;color:#5a6680;line-height:1.5}
.dk-compcard .go{margin-top:auto;padding-top:11px;color:#2552c6;font-weight:600;font-size:12px;display:inline-flex;align-items:center;gap:5px}
.dk-compcard .go svg{width:13px;height:13px}
/* integrations grid */
.dk-intmeta{font-size:12.5px;color:#687388}
.dk-intgrp{margin-bottom:24px}
.dk-intgrp h2{font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:#6a7488;font-weight:700;margin:0 0 11px;display:flex;align-items:center;gap:8px}
.dk-intgrp h2 span{color:#9aa3b5;font-weight:600}
.dk-intcards{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px}
.dk-intcard{appearance:none;font:inherit;display:flex;align-items:center;gap:13px;text-align:left;cursor:pointer;background:#fff;border:1px solid rgba(23,33,56,.08);border-radius:13px;padding:13px 15px;transition:border-color .15s,transform .15s}
.dk-intcard:hover{border-color:#3f78ff;transform:translateY(-1px)}
.dk-intcard .ic{flex:none;width:34px;height:34px;border-radius:9px;object-fit:contain;background:rgba(23,33,56,.04)}
.dk-intcard .ic.mono{display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:800;color:#fff;background:var(--a,#3f78ff)}
.dk-intcard .meta{min-width:0;flex:1}
.dk-intcard .meta b{display:block;font-size:13.5px;font-weight:700;color:#141c2e}
.dk-intcard .meta p{font-size:11.5px;color:#687388;line-height:1.4;margin:2px 0 0;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.dk-intcard .dk-stat{flex:none;display:inline-flex;align-items:center;gap:6px;font-size:10.5px;font-weight:700;padding:4px 9px;border-radius:20px;white-space:nowrap}
.dk-intcard .dk-stat .d{width:7px;height:7px;border-radius:50%}
.dk-intcard .dk-stat.on{color:#0d7a44;background:rgba(18,168,95,.12)}.dk-intcard .dk-stat.on .d{background:#12a85f}
.dk-intcard .dk-stat.ref{color:#8a5a00;background:rgba(245,146,11,.12)}.dk-intcard .dk-stat.ref .d{background:#f5920b}
.dk-intcard .dk-stat.off{color:#687388;background:rgba(23,33,56,.06)}.dk-intcard .dk-stat.off .d{background:#9aa3b5}
/* Isolation from legacy pro-theme.css hacks. Those rules match raw inline text such as
   [style*="background:#0"] / [style*="color:#e"] and class suffixes like [class$="-tabs"],
   recolouring/re-spacing Deck elements. So data colours are passed as --bg / --fg custom
   properties (never matched), and suffix-sensitive elements carry a trailing "dkx" class. */
.dk [style*="--bg:"]{background:var(--bg)!important}
.dk [style*="--fg:"]{color:var(--fg)!important}
.dk[data-ui=deck] tbody tr:nth-child(even) td:not([style*="background"]){background:transparent!important}
.dk[data-ui=deck] tbody tr:hover td:not([style*="background"]){background:rgba(63,120,255,.06)!important}
/* ======================= Design system (final layer) =======================
   Restrained by intent: warm neutral surfaces, one accent (--dk-acc), colour reserved
   for meaning (severity, status), regular-weight navigation, sentence-case labels and a
   serif display face for page titles. Declared last so it settles the older layers above. */
.dk[data-ui=deck]{--dk-bg:#f7f7f4;--dk-surf:#fff;--dk-line:#e6e4de;--dk-line2:#efeee9;--dk-tx:#1d1c1a;--dk-tx2:#56544f;--dk-mut:#86837c;--dk-acc:#2552c6;--dk-accbg:rgba(37,82,198,.08);
  background:var(--dk-bg);color:var(--dk-tx);font-family:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;font-feature-settings:"cv11","ss01";letter-spacing:-.003em}
.dk[data-ui=deck] .dk-sky{background:var(--dk-bg)}
.dk[data-ui=deck] h1,.dk[data-ui=deck] h2,.dk[data-ui=deck] h3,.dk[data-ui=deck] h4{color:var(--dk-tx)!important}
.dk[data-ui=deck] .dk-ovhead h1,.dk[data-ui=deck] .dk-lede h1,.dk[data-ui=deck] .dk-ti h1,.dk[data-ui=deck] .dk-inv h1,.dk[data-ui=deck] .dk-surf h1,.dk[data-ui=deck] .dk-cloud h1,.dk[data-ui=deck] .dk-comp h1,.dk[data-ui=deck] .dk-con2 h1{font-family:"Source Serif 4",Georgia,"Times New Roman",serif;font-weight:500;font-size:32px;letter-spacing:-.015em;line-height:1.15}
.dk[data-ui=deck] .dk-ovhead p{color:var(--dk-tx2);font-size:14px;max-width:none}
.dk[data-ui=deck] .dk-ovhead .when{color:var(--dk-mut);font-size:13px}
/* header: search, Ask AI, create, notifications, account. Nothing else. */
.dk[data-ui=deck] .dk-top{background:var(--dk-surf);border-bottom:1px solid var(--dk-line)}
.dk[data-ui=deck] .dk-clock,.dk[data-ui=deck] .dk-health,.dk[data-ui=deck] .dk-brand .dk-wsname{display:none}
.dk[data-ui=deck] #dkNew .lb{display:none}.dk[data-ui=deck] #dkNew{width:34px;padding:0;display:grid}
.dk[data-ui=deck] .dk-icbtn{background:transparent;border-color:transparent;color:var(--dk-tx2);border-radius:8px}
.dk[data-ui=deck] .dk-icbtn:hover{background:#f1f0ec;color:var(--dk-tx)}
.dk[data-ui=deck] .dk-icbtn.dk-lbtn.ai{background:var(--dk-tx);border-color:var(--dk-tx);color:#fff;font-weight:500;border-radius:8px}
.dk[data-ui=deck] .dk-icbtn.dk-lbtn.ai:hover{background:#000;color:#fff}
.dk[data-ui=deck] .dk-hsearch{background:#f4f3ef;border-color:transparent;border-radius:8px;color:var(--dk-mut)}
.dk[data-ui=deck] .dk-hsearch:hover{background:#efeee9;border-color:var(--dk-line)}
.dk[data-ui=deck] .dk-hsearch kbd{background:var(--dk-surf);border-color:var(--dk-line);color:var(--dk-mut);font-weight:500}
.dk[data-ui=deck] .dk-acct{background:transparent;border-color:transparent}
.dk[data-ui=deck] .dk-acct .av{background:var(--dk-tx)}
.dk[data-ui=deck] .dk-crumb{color:var(--dk-mut)}.dk[data-ui=deck] .dk-crumb b{color:var(--dk-tx);font-weight:500}
/* sidebar: the Deck's own "index". A dark ink panel laid out like a book's contents:
   numbered chapters (mono numerals, serif titles), items hanging off a hairline guide,
   and the current page marked on that guide rather than with a filled pill. */
.dk[data-ui=deck]:not(.nav-rail):not(.nav-phone){--dk-sw:268px}
.dk[data-ui=deck] .dk-sidebar{--ix-bg:#1a1917;--ix-tx:#d9d5cb;--ix-mut:#8c887e;--ix-dim:#5f5b53;--ix-line:rgba(255,255,255,.1);--ix-mark:#9db8ff;
  background:var(--ix-bg);border-right:0;color:var(--ix-tx)}
.dk[data-ui=deck] .dk-sbnav{padding:14px 14px 18px;scrollbar-color:rgba(255,255,255,.14) transparent}
.dk[data-ui=deck] .dk-nvg{margin:0 0 6px}
.dk[data-ui=deck] .dk-nvg0{padding-bottom:10px;margin-bottom:8px;border-bottom:1px solid var(--ix-line)}
.dk[data-ui=deck] .dk-nvh{display:flex;align-items:baseline;gap:10px;text-transform:none;letter-spacing:0;padding:16px 8px 8px;color:var(--ix-tx);font-size:15px;font-weight:400;font-family:"Source Serif 4",Georgia,serif;white-space:nowrap;overflow:hidden}
.dk[data-ui=deck] .dk-nvh .no{flex:none;width:18px;font:500 10.5px/1 ui-monospace,"JetBrains Mono",SFMono-Regular,Menlo,monospace;color:var(--ix-dim);letter-spacing:.04em}
.dk[data-ui=deck] .dk-nvh .gt{min-width:0;overflow:hidden;text-overflow:ellipsis}
.dk[data-ui=deck] .dk-nvhb{position:relative}
.dk[data-ui=deck] .dk-nvhb .ov{position:absolute;right:8px;top:19px;font-family:"Inter",system-ui,sans-serif;font-size:11px;color:var(--ix-mut);background:var(--ix-bg);padding-left:8px}
.dk[data-ui=deck] .dk-nvhb:hover,.dk[data-ui=deck] .dk-nvhb.on,.dk[data-ui=deck] .dk-nvhb:focus-visible{color:#fff}
.dk[data-ui=deck] .dk-nvhb.on .no{color:var(--ix-mark)}
.dk[data-ui=deck] .dk-nvi{margin-left:16px;padding-left:12px;border-left:1px solid var(--ix-line)}
.dk[data-ui=deck] .dk-nv{position:relative;font-weight:400;font-size:13.5px;color:var(--ix-mut);border-radius:6px;min-height:32px;padding:5px 8px;gap:10px;margin:0}
.dk[data-ui=deck] .dk-nv svg{color:var(--ix-dim);width:16px;height:16px}
.dk[data-ui=deck] .dk-nv:hover{background:rgba(255,255,255,.05);color:var(--ix-tx)}
.dk[data-ui=deck] .dk-nv:hover svg{color:var(--ix-mut)}
.dk[data-ui=deck] .dk-nv.on{background:transparent;color:#fff;font-weight:500}
.dk[data-ui=deck] .dk-nv.on svg{color:var(--ix-mark)}
.dk[data-ui=deck] .dk-nv.on::before{display:block;left:-13px;top:7px;bottom:7px;width:2px;border-radius:2px;background:var(--ix-mark)}
.dk[data-ui=deck] .dk-nvg0 .dk-nv.on{background:rgba(255,255,255,.07)}
.dk[data-ui=deck] .dk-nvg0 .dk-nv.on::before{display:none}
.dk[data-ui=deck] .dk-nv:focus-visible{outline:2px solid var(--ix-mark);outline-offset:-2px}
.dk[data-ui=deck] .dk-nv .nc{font:500 11px/1 ui-monospace,"JetBrains Mono",monospace;background:transparent;color:var(--ix-dim);padding:0}
.dk[data-ui=deck] .dk-sbfoot{border-top:1px solid var(--ix-line);padding:8px 14px}
.dk[data-ui=deck] .dk-sbfoot .dk-nv{color:var(--ix-mut)}
/* icon rail + phone drawer keep the index colours; the guide and numerals fold away in the rail */
.dk[data-ui=deck].nav-rail .dk-sbnav{padding:12px 10px}
.dk[data-ui=deck].nav-rail .dk-nvi{margin:0;padding:0;border:0}
.dk[data-ui=deck].nav-rail .dk-nvh{padding:9px 4px;font-size:0}
.dk[data-ui=deck].nav-rail .dk-nvh .no,.dk[data-ui=deck].nav-rail .dk-nvh .gt{display:none}
.dk[data-ui=deck].nav-rail .dk-nvh::after{flex:1;background:var(--ix-line)}
.dk[data-ui=deck].nav-rail .dk-nv.on{background:rgba(255,255,255,.08)}
.dk[data-ui=deck].nav-rail .dk-nv.on::before{display:none}
/* metrics: white tiles, label above a large tabular number, no stripes or icon chips */
.dk[data-ui=deck] .dk-ov .dk-kpis.dk-kpis4{grid-template-columns:repeat(4,minmax(0,1fr))!important;gap:12px;margin-bottom:12px}
@media(max-width:1100px){.dk[data-ui=deck] .dk-ov .dk-kpis.dk-kpis4{grid-template-columns:repeat(2,minmax(0,1fr))!important}}
@media(max-width:520px){.dk[data-ui=deck] .dk-ov .dk-kpis.dk-kpis4{grid-template-columns:1fr!important}.dk[data-ui=deck] .dk-kpis4>*{grid-column:auto!important}}
@media(max-width:1000px){.dk[data-ui=deck] .dk-crumb{display:none}}
@media(max-width:480px){.dk[data-ui=deck] .dk-brand .dk-wm{display:none}}
.dk[data-ui=deck] .dk-kpis4>.dk-kpi:first-child .kn{font-size:30px}
.dk[data-ui=deck] .dk-kpi{display:flex;flex-direction:column;background:var(--dk-surf);border:1px solid var(--dk-line);border-radius:10px;padding:16px 18px;grid-row:auto!important;justify-content:flex-start!important}
.dk[data-ui=deck] .dk-kpi[hidden]{display:none}
.dk[data-ui=deck] .dk-kpi::before,.dk[data-ui=deck] .dk-kpi .ki{display:none}
.dk[data-ui=deck] .dk-kpi:hover{transform:none;border-color:#d3d0c8;background:var(--dk-surf)}
.dk[data-ui=deck] .dk-kpi .kl{order:-1;margin:0 0 10px;text-transform:none;letter-spacing:0;font-size:13px;font-weight:500;color:var(--dk-tx2)}
.dk[data-ui=deck] .dk-kpi .kn{font-size:30px!important;font-weight:500;letter-spacing:-.02em;color:var(--dk-tx)}
.dk[data-ui=deck] .dk-kpi .ks{margin-top:8px;font-size:12px;color:var(--dk-mut);font-weight:400}
.dk[data-ui=deck] .dk-start{grid-column:span 2;background:var(--dk-surf);border:1px solid var(--dk-line);border-radius:10px;padding:16px 18px;display:flex;flex-direction:column;gap:6px;min-width:0}
.dk[data-ui=deck] .dk-start[hidden]{display:none}
.dk[data-ui=deck] .dk-start b{font-size:15px;font-weight:600}
.dk[data-ui=deck] .dk-start p{font-size:13px;color:var(--dk-tx2);line-height:1.5;margin:0 0 6px}
@media(max-width:520px){.dk[data-ui=deck] .dk-start{grid-column:auto}.dk[data-ui=deck] .dk-start .dk-actform input{flex:1 1 100%;width:100%}}
.dk[data-ui=deck] .dk-expnote{background:transparent;border:0;padding:0 2px;color:var(--dk-mut);font-size:12.5px}
.dk[data-ui=deck] .dk-expnote b{color:var(--dk-tx2);font-weight:600}
/* panels: flat white, quiet titles, no decorative icons */
.dk[data-ui=deck] .dk-ovp{background:var(--dk-surf);border:1px solid var(--dk-line);border-radius:10px;box-shadow:none;padding:18px 20px}
.dk[data-ui=deck] .dk-ovp h2{font-size:15px;font-weight:600}
.dk[data-ui=deck] .dk-ovp h2>svg{display:none}
.dk[data-ui=deck] .dk-ovp h2 .mo{color:var(--dk-acc);font-weight:500;font-size:13px}
.dk[data-ui=deck] .dk-qacard{background:transparent;border:1px solid var(--dk-line);border-radius:9px}
.dk[data-ui=deck] .dk-qacard:hover{transform:none;background:#faf9f6;border-color:#d3d0c8}
.dk[data-ui=deck] .dk-qacard .qi{color:var(--dk-tx2);background:#f1f0ec}
.dk[data-ui=deck] .dk-qacard b{font-weight:600;color:var(--dk-tx)}
.dk[data-ui=deck] .dk-qacard span{color:var(--dk-mut)}
.dk[data-ui=deck] .dk-ask{background:var(--dk-surf);border:1px solid var(--dk-line);border-radius:10px}
.dk[data-ui=deck] .dk-ask:focus-within{border-color:var(--dk-acc);background:var(--dk-surf);box-shadow:0 0 0 3px var(--dk-accbg)}
.dk[data-ui=deck] .dk-ask .ai{color:var(--dk-mut)}
.dk[data-ui=deck] .dk-ask button{background:var(--dk-tx)!important;border-color:var(--dk-tx)!important;color:#fff!important;font-weight:500;box-shadow:none!important}
.dk[data-ui=deck] .dk-askhint{color:var(--dk-mut)}
/* buttons */
.dk[data-ui=deck] .dk-tibtn{font-weight:500;border-radius:7px}
.dk[data-ui=deck] .dk-tibtn.on{background:var(--dk-tx);border-color:var(--dk-tx);color:#fff}
.dk[data-ui=deck] .dk-b{font-weight:500;border-radius:8px}
.dk[data-ui=deck] .dk-b.pri{background:var(--dk-tx);border-color:var(--dk-tx);box-shadow:none}
/* needs-attention table */
.dk[data-ui=deck] .dk-natbl{width:100%;border-collapse:collapse;font-size:13.5px}
.dk[data-ui=deck] .dk-natbl th{font-size:12px;font-weight:500;color:var(--dk-mut);text-align:left;padding:0 12px 8px;border-bottom:1px solid var(--dk-line);text-transform:none;letter-spacing:0;white-space:nowrap}
.dk[data-ui=deck] .dk-natbl,.dk[data-ui=deck] .dk-natbl thead,.dk[data-ui=deck] .dk-natbl tr,.dk[data-ui=deck] .dk-natbl th,.dk[data-ui=deck] .dk-natbl td{background:transparent!important;box-shadow:none!important}
.dk[data-ui=deck] .dk-natbl td{padding:12px;border-bottom:1px solid var(--dk-line2);vertical-align:middle}
.dk[data-ui=deck] .dk-natbl tr:last-child td{border-bottom:0}
.dk[data-ui=deck] .dk-natbl th:first-child,.dk[data-ui=deck] .dk-natbl td:first-child{padding-left:0}
.dk[data-ui=deck] .dk-natbl th:last-child,.dk[data-ui=deck] .dk-natbl td:last-child{padding-right:0}
.dk[data-ui=deck] .dk-natbl td.sv{width:1%;white-space:nowrap}
.dk[data-ui=deck] .dk-natbl td.it b{display:block;font-weight:500;color:var(--dk-tx);overflow-wrap:anywhere}
.dk[data-ui=deck] .dk-natbl td.it span{display:-webkit-box;-webkit-line-clamp:1;-webkit-box-orient:vertical;overflow:hidden;color:var(--dk-mut);font-size:12.5px;margin-top:2px}
.dk[data-ui=deck] .dk-natbl td.so{width:1%;white-space:nowrap;color:var(--dk-tx2);font-size:12.5px}
.dk[data-ui=deck] .dk-natbl td.ac{width:1%;text-align:right;white-space:nowrap}
.dk[data-ui=deck] .dk-natbl .dk-tibtn{height:30px}
.dk[data-ui=deck] .dk-sev{display:inline-flex;align-items:center;gap:7px;font-size:12.5px;font-weight:500;color:var(--dk-tx2)}
.dk[data-ui=deck] .dk-sev i{width:8px;height:8px;border-radius:50%;background:var(--c)}
@media(max-width:720px){.dk[data-ui=deck] .dk-natbl th:nth-child(3),.dk[data-ui=deck] .dk-natbl td.so{display:none}}
/* other scenes: neutral icon tiles and sentence-case labels */
.dk[data-ui=deck] .dk-gcard{border-color:var(--dk-line);border-radius:9px}
.dk[data-ui=deck] .dk-gcard:hover{border-color:#d3d0c8;transform:none;box-shadow:none}
.dk[data-ui=deck] .dk-gcard .gi,.dk[data-ui=deck] .dk-wtitle .wi{background:#f1f0ec;color:var(--dk-tx2)}
.dk[data-ui=deck] .dk-gcard .gt{font-weight:500}
.dk[data-ui=deck] .dk-wbar{background:var(--dk-surf);border-bottom-color:var(--dk-line)}
.dk[data-ui=deck] .dk-wtitle{font-weight:600}
.dk[data-ui=deck] .dk-wback{background:transparent;border-color:var(--dk-line);font-weight:500;border-radius:8px}
.dk[data-ui=deck] .dk-pop-h,.dk[data-ui=deck] .dk-intgrp h2,.dk[data-ui=deck] .dk-keyform label,.dk[data-ui=deck] .dk-dhead .k{text-transform:none;letter-spacing:0;font-weight:500}
.dk[data-ui=deck] .dk-intcard{border-color:var(--dk-line);border-radius:9px}
.dk[data-ui=deck] .dk-intcard:hover{border-color:#d3d0c8;transform:none}
.dk[data-ui=deck] .dk-intcard .meta b{font-weight:600}
.dk[data-ui=deck] :is(.dk-sevchip .l,.dk-invb .t,.dk-kitcat .kc-h,.dk-kopt,.dk-klbl,.dk-keysgrp){text-transform:none;letter-spacing:0;font-weight:500}
.dk[data-ui=deck] th{text-transform:none!important;letter-spacing:0!important;font-size:12.5px!important;font-weight:500!important;color:var(--dk-mut)!important;background:transparent!important;border-bottom:1px solid var(--dk-line)!important}
.dk[data-ui=deck] td{border-bottom-color:var(--dk-line2)!important}
.dk[data-ui=deck] .dk-tcat{font-weight:400;border-radius:7px}
.dk[data-ui=deck] .dk-tcat.on{background:rgba(29,28,26,.07);color:var(--dk-tx);font-weight:500}
/* ======================= Ink main screen =======================
   The main area matches the index sidebar's dark ink. Rather than re-colour hundreds of
   light rules (and every embedded tool page) one by one, the header, scenes, menus and the
   tool frame render their light design through invert + hue-rotate: lightness flips while
   hues (severity red, accent blue) stay put. The --dk-* tokens are therefore the PRE-inversion
   values, tuned so the result lands on the sidebar ink (#1a1917); photos and logos are
   flipped back so they look normal. */
.dk[data-ui=deck]{--dk-bg:#e6e5e2;--dk-surf:#dcdbd7;--dk-line:#cbc9c4;--dk-line2:#d5d3cf;--dk-tx:#161514;--dk-tx2:#3f3d3a;--dk-mut:#716e68;background:#1a1917}
.dk[data-ui=deck] .dk-sky{background:#1a1917}
.dk[data-ui=deck] :is(.dk-top,.dk-scene,.dk-pop,.dk-drawer,.dk-spot .dk-sbox){filter:invert(1) hue-rotate(180deg)}
.dk[data-ui=deck] .dk-scene,.dk[data-ui=deck] .dk-top,.dk[data-ui=deck] .dk-wframe iframe{background:var(--dk-bg)}
.dk[data-ui=deck] :is(.dk-pop,.dk-drawer,.dk-spot .dk-sbox){background:var(--dk-surf);border-color:var(--dk-line);box-shadow:none}
.dk[data-ui=deck] .dk-top{border-bottom-color:var(--dk-line)}
.dk[data-ui=deck] :is(.dk-scene,.dk-top,.dk-pop,.dk-drawer,.dk-spot) img:not(.dk-mark):not(.dk-wm),.dk[data-ui=deck] .dk-scene video{filter:invert(1) hue-rotate(180deg)}
.dk[data-ui=deck] .dk-brand .dk-wm{filter:brightness(0)}
.dk[data-ui=deck] .dk-scene *{box-shadow:none!important}
.dk[data-ui=deck] .dk-wframe iframe{filter:brightness(.92)}
.dk[data-ui=deck] .dk-wbar{background:var(--dk-bg)}
.dk[data-ui=deck] :is(.dk-gcard,.dk-intcard,.dk-act,.dk-qacard){background:var(--dk-surf)}
.dk[data-ui=deck] .dk-spot{background:rgba(0,0,0,.55)}
/* ======================= Polish =======================
   Fields sit inset on the page tone instead of glaring pure black; quick actions are
   compact two-line rows; empty states read as a quiet sentence, not a centred banner;
   integrations show a slim meter instead of a large ring. Tokens only, no new colours. */
.dk[data-ui=deck] :is(.dk-actform input,.dk-notes){background:var(--dk-bg)!important;border:1px solid var(--dk-line)!important;color:var(--dk-tx)!important;border-radius:8px}
.dk[data-ui=deck] :is(.dk-actform input,.dk-notes):focus{border-color:var(--dk-acc)!important;box-shadow:0 0 0 3px var(--dk-accbg)!important}
.dk[data-ui=deck] :is(.dk-actform input,.dk-notes)::placeholder{color:var(--dk-mut)}
.dk[data-ui=deck] .dk-notes{min-height:112px}
.dk[data-ui=deck] .dk-notef{color:var(--dk-mut);font-size:12px}
.dk[data-ui=deck] .dk-qa{grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:8px}
.dk[data-ui=deck] .dk-qacard{display:grid;grid-template-columns:30px minmax(0,1fr);column-gap:12px;row-gap:1px;align-items:center;padding:11px 14px}
.dk[data-ui=deck] .dk-qacard .qi{grid-row:span 2;width:30px;height:30px;border-radius:7px;background:var(--dk-bg)}
.dk[data-ui=deck] .dk-qacard b{font-size:13.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dk[data-ui=deck] .dk-qacard span:not(.qi){font-size:12px;line-height:1.4;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.dk[data-ui=deck] .dk-nempty{text-align:left;padding:2px 0;color:var(--dk-mut);font-size:13px;line-height:1.55}
.dk[data-ui=deck] .dk-nempty b{color:var(--dk-tx);font-weight:500;text-decoration:underline;text-underline-offset:3px;text-decoration-color:var(--dk-line)}
.dk[data-ui=deck] :is(.dk-sysrow,.dk-ovact .r){border-color:var(--dk-line2)}
.dk[data-ui=deck] :is(.dk-sysrow .sl,.dk-ovact .r .tx){color:var(--dk-tx2)}
.dk[data-ui=deck] .dk-sysrow .sv{color:var(--dk-tx2);font-weight:500}
.dk[data-ui=deck] .dk-ovact .r .ag{color:var(--dk-mut)}
.dk[data-ui=deck] .dk-intg{display:block}
.dk[data-ui=deck] .dk-intg .gmeta b{display:block;font-size:22px;font-weight:500;letter-spacing:-.01em;color:var(--dk-tx)}
.dk[data-ui=deck] .dk-intg .gmeta b small{font-size:13px;font-weight:400;color:var(--dk-mut);margin-left:4px;letter-spacing:0}
.dk[data-ui=deck] .dk-meter{height:6px;border-radius:3px;background:var(--dk-bg);margin:12px 0 10px;overflow:hidden}
.dk[data-ui=deck] .dk-meter i{display:block;height:100%;width:var(--p);min-width:2px;border-radius:3px;background:var(--dk-tx2)}
.dk[data-ui=deck] .dk-intg .gmeta p{font-size:12.5px;color:var(--dk-mut);margin:0;line-height:1.5}
.dk[data-ui=deck] .dk-ovgrid3>.dk-ovp,.dk[data-ui=deck] .dk-ovgrid .dk-ovp{margin-bottom:0}
.dk[data-ui=deck] .dk-ovgrid>div{display:flex;flex-direction:column;gap:18px}
.dk[data-ui=deck] :is(.dk-cloudcard,.dk-compcard,.dk-astat,.dk-cloudwb,.dk-cloudconn){background:var(--dk-surf)!important;border-color:var(--dk-line)!important}
.dk[data-ui=deck] :is(.dk-isel,.dk-isearch,.dk-isearch input,.dk-inv input,.dk-kitio,.dk-cloudin,.dk-cloudsel){background:var(--dk-bg)!important;border-color:var(--dk-line)!important;color:var(--dk-tx)!important}
.dk[data-ui=deck] .dk-isearch input{border:0!important}
.dk[data-ui=deck] .dk-astat{border-left-width:1px!important}
/* tool pages are transparent in embed mode; let the scene tone (ink or cyber) show behind them */
.dk[data-ui=deck] .dk-wframe iframe{background:transparent}
@media(max-width:520px){.dk[data-ui=deck] .dk-natbl thead{display:none}.dk[data-ui=deck] .dk-natbl td.sv{padding-right:2px}.dk[data-ui=deck] .dk-natbl .dk-sev{font-size:0;gap:0}}
`;
const IC_SEARCH = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.2-3.2"/></svg>';
const IC_CHEV = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="m9 6 6 6-6 6"/></svg>';

export function renderDeck(host, opts) {
  opts = opts || {};
  // Enterprise curation: the simulated themed dashboards and the script-kiddie
  // offensive toys stay in the codebase/NAV but are never surfaced in the business
  // Deck. This single filter cascades to the spotlight index, secLabel, TOTAL_TOOLS
  // and the Tools gallery, all of which read the filtered `groups` below.
  // Business focus: education/practice content, consumer extras, generic developer
  // utilities and simulated dashboards are left out; so are near-duplicate tools
  // (the kept one covers the job: dns covers dnsenum/dnsrecon, osint covers the
  // email/geo variants, threatfeed covers the static threat snapshots).
  // Generic developer/format toolkits (encoding, hashing, subnet math, packet decoders,
  // HTTP reference) hold no standalone value for a security team, so whole groups go.
  const DECK_DENY_GROUPS = new Set(["flagships", "learn", "labs", "tg-dev", "tg-devx", "tg-coding", "tg-encoding", "tg-web", "tg-network", "tg-hashing", "tg-netproto"]);
  // Within the groups we keep, drop the single-purpose converters, decoders, parsers,
  // calculators, generators and reference/cheat-sheet lookups — things a company can't
  // act on — plus offensive toys (payloads, forgers, crackers). Only tools that DO
  // something to the company's own estate (scanners, linters, builders, analyzers)
  // remain. DECK_KEEP_LABEL rescues the few business deliverables the broad rule catches.
  const DECK_DENY_LABEL = /payload|cheat ?sheet|forge|attack lab|cracker|hashcat|john the ripper|\bconvert(er)?\b|\bencoder\b|\bdecoder\b|pretty-?print|formatter|minif|beautif|\bescaper?\b|unescape|→|\bto (json|yaml|toml|xml|csv|pem|jwk|integer|ipv4|ipv6|cidr|table|fetch)\b|\breference\b|\bexplainer\b|\bcalculator\b|\bparser\b/i;
  const DECK_KEEP_LABEL = /\breport\b/i;
  const DECK_DENY_SECS = new Set([
    "attacksim", "reverseshell", "webshell", "wirelesslab", "socialeng", "exploitdev",
    "payloads", "payloadgen", "payloadstudio", "packetcraft", "privesc", "cracklab",
    "xsslab", "pentestconsole",
    "favicon", "iptools", "reconplanner", "netmap", "dnsenum", "dnsrecon", "osintemail", "emailintel", "ipgeolocation", "addressintel",
    "darkwebosint", "threatdashboard", "threat", "breachsim", "networktraffic", "trafficanalyzer", "apiscan", "stego",
    "math", "dataviz", "engines", "education", "downloads", "dlguide", "setup", "privatecloud"
  ]);
  const groups = (opts.groups || [])
    .filter((g) => g.items && g.items.length && !DECK_DENY_GROUPS.has(g.id))
    .map((g) => ({ ...g, items: g.items.filter((it) => !DECK_DENY_SECS.has(it.sec) && (DECK_KEEP_LABEL.test(it.label || "") || !DECK_DENY_LABEL.test(it.label || ""))) }))
    .filter((g) => g.items.length);
  const onOpen = typeof opts.onOpen === "function" ? opts.onOpen : () => {};
  const onExit = typeof opts.onExit === "function" ? opts.onExit : () => {};
  // Primary mode: the Deck IS the signed-in UI (no older console to fall back to),
  // so "exit" entries become sign-out and "full console" links open a new tab.
  const primary = typeof opts.onSignOut === "function";
  const toast = (m) => { try { (window.showToast || window.dnToast)?.(m); } catch (_) {} };

  // flat index for spotlight: tools + integrations
  const index = [];
  for (const g of groups) for (const it of g.items) index.push({ type: "tool", sec: it.sec, label: it.label, group: g.name, color: g.color, badge: it.badge });
  for (const it of INTEGRATIONS) index.push({ type: "conn", id: it.id, label: it.name, group: it.kind === "ai" ? "AI model" : "Security", it });

  let conns = loadConns();
  let pins = loadPins();

  if (!document.getElementById("dk-css")) { const st = document.createElement("style"); st.id = "dk-css"; st.textContent = CSS; document.head.appendChild(st); }
  if (!document.getElementById("dk-font")) { const fl = document.createElement("link"); fl.id = "dk-font"; fl.rel = "stylesheet"; fl.href = "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Source+Serif+4:opsz,wght@8..60,400;8..60,500&display=swap"; document.head.appendChild(fl); }

  const root = document.createElement("div");
  root.className = "dk"; root.dataset.ui = "deck";
  root.innerHTML = `
    <div class="dk-sky"></div>
    <canvas class="dk-stars" id="dkStars"></canvas>
    <div class="dk-top">
      <button class="dk-icbtn dk-sbtog" id="dkSbTog" data-explain="hdr.menu" aria-label="Toggle navigation" aria-controls="dkSide">${IC.menu}</button>
      <button class="dk-brand" id="dkBrand" data-explain="hdr.brand" title="Home"><img class="dk-mark" src="/logo-dark.svg?v=20261007b" alt=""><img class="dk-wm" src="/wordmark.svg" alt="Darknode"><span class="dk-wsname">Command Center</span></button>
      <div class="dk-crumb" id="dkCrumb" aria-live="polite"></div>
      <button class="dk-hsearch" id="dkHSearch" data-explain="hdr.search" aria-label="Search">${IC_SEARCH}<span class="hs">Search tools, scenes and actions</span><kbd>Ctrl K</kbd></button>
      <div class="dk-right">
        <button class="dk-health" id="dkHealth" data-explain="hdr.health" title="Live CVE feed status"><span class="d"></span><span class="t">Threat feed live</span></button>
        <button class="dk-icbtn dk-lbtn ai" id="dkAsstBtn" data-explain="hdr.assistant" title="Darknode AI assistant" aria-label="Darknode AI assistant">${IC.spark}<span class="lb">Ask AI</span></button>
        <button class="dk-icbtn" id="dkFindBtn" data-explain="hdr.search" title="Search (Ctrl K)" aria-label="Search">${IC_SEARCH}</button>
        <button class="dk-icbtn dk-lbtn" id="dkNew" data-explain="hdr.new" title="Quick create" aria-label="Quick create">${IC.plus}<span class="lb">New</span></button>
        <button class="dk-icbtn" id="dkBell" data-explain="hdr.bell" title="Notifications" aria-label="Notifications">${IC.bell}<span class="dk-badge dkx" id="dkBadge" hidden></span></button>
        <span class="dk-clock" id="dkClock"></span>
        <button class="dk-acct" id="dkAcct" data-explain="hdr.account" aria-label="Account"><span class="av" id="dkAvatar">DN</span>${IC.chevd}</button>
      </div>
    </div>

    <aside class="dk-sidebar" id="dkSide" aria-label="Main navigation">
      <nav class="dk-sbnav" id="dkSbNav"></nav>
      <div class="dk-sbfoot"><button class="dk-nv" id="dkSbCollapse" data-explain="hdr.collapse" data-l="Expand navigation">${IC.rail}<span class="nl">Collapse</span></button></div>
    </aside>
    <div class="dk-sbshade" id="dkSbShade"></div>
    <div class="dk-fly" id="dkFly" role="tooltip"></div>

    <div class="dk-pop" id="dkNewPop"></div>
    <div class="dk-pop" id="dkBellPop"></div>
    <div class="dk-pop" id="dkAcctPop"></div>

    <div class="dk-scene dk-ov" id="dkOverview"></div>

    <div class="dk-scene dk-con2" id="dkCon" hidden></div>

    <div class="dk-scene dk-tools2" id="dkTools" hidden></div>

    <div class="dk-scene dk-kit" id="dkToolkit" hidden></div>

    <div class="dk-scene dk-surf" id="dkSurface" hidden></div>

    <div class="dk-scene dk-cloud" id="dkCloud" hidden></div>

    <div class="dk-scene dk-comp" id="dkCompliance" hidden></div>

    <div class="dk-scene dk-ti" id="dkThreat" hidden></div>

    <div class="dk-scene dk-inv" id="dkInvest" hidden></div>

    <div class="dk-scene dk-inv dk-fnd" id="dkFindings" hidden></div>

    <div class="dk-scene dk-inv dk-sect" id="dkSection" hidden></div>

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
        <button class="dk-icbtn dk-wact" id="dkWPin" data-explain="btn.pin" title="Pin to overview" aria-label="Pin to overview">${IC.star}</button>
        <button class="dk-icbtn dk-wact" id="dkWCopy" data-explain="btn.copy" title="Copy tool link" aria-label="Copy tool link">${IC.link}</button>
        <button class="dk-icbtn dk-wact" id="dkWTab" data-explain="btn.newtab" title="Open in a new tab" aria-label="Open in a new tab">${IC.ext}</button>
        <span class="dk-wfull" id="dkWFull">Open in full console</span>
      </div>
      <div class="dk-wframe" id="dkWFrame"></div>
    </div>

    <aside class="dk-drawer" id="dkDrawer"><span class="x" id="dkDrawerX">&times;</span><div id="dkDrawerBody"></div></aside>

    <div class="dk-spot" id="dkSpot">
      <div class="dk-sbox">
        <div class="dk-srow">${IC_SEARCH}<input id="dkSpotIn" placeholder="Search tools, services or run a command…" autocomplete="off" spellcheck="false"></div>
        <div class="dk-sres" id="dkSpotRes"></div>
        <div class="dk-sfoot"><span><kbd>↑</kbd><kbd>↓</kbd> navigate</span><span><kbd>↵</kbd> open</span><span><kbd>esc</kbd> close</span><span style="margin-left:auto"><b>Tools, services &amp; actions</b></span></div>
      </div>
    </div>

    <div class="dk-keys" id="dkKeys"></div>`;
  (host || document.body).appendChild(root);
  const $ = (s) => root.querySelector(s);

  // clock
  const clock = $("#dkClock");
  const tick = () => { clock.textContent = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); };
  tick(); const clockId = setInterval(tick, 20000);

  // starfield
  // Decorative animated starfield removed — a flat dark surface reads as an ops
  // console, not an AI landing page. Kept as no-ops so resize/teardown stay valid.
  let rafId = 0;
  function sizeStars(){}
  function drawStars(){}

  // ---------- workspace router ----------
  const SCENES = { overview: "#dkOverview", surface: "#dkSurface", threat: "#dkThreat", cloud: "#dkCloud", compliance: "#dkCompliance", invest: "#dkInvest", findings: "#dkFindings", section: "#dkSection", con: "#dkCon", tools: "#dkTools", toolkit: "#dkToolkit", activity: "#dkActivity", assistant: "#dkAssistant" };
  const sceneEls = {}; for (const k in SCENES) sceneEls[k] = $(SCENES[k]);
  const sceneTools = sceneEls.tools;   // kept for the tools gallery code
  // sec -> label, for activity lines and quick-action titles
  const secLabel = {}; for (const g of groups) for (const it of g.items) secLabel[it.sec] = it.label;
  pins = pins.filter((s) => secLabel[s]);   // drop pins whose tool no longer exists
  // Toggle a tool's pinned state (shown on the overview). Returns the new state.
  function togglePin(sec){
    if (!sec) return false;
    const i = pins.indexOf(sec);
    if (i >= 0) pins.splice(i, 1); else pins.unshift(sec);
    if (pins.length > 12) pins.length = 12;
    savePins(pins);
    if (curScene === "overview") renderPins();   // keep the overview widget in sync
    buildSideNav();
    return pins.includes(sec);
  }
  let curScene = "overview";
  // Keep the address bar on what is actually showing, so a reload or a re-mount of
  // the Deck never reopens a stale tool (e.g. /admin). Scenes live at "/" (the scene
  // itself is restored from LS_SCENE); an open tool lives at "/<sec>".
  function syncUrl(path){
    if (!primary) return;
    try { if (location.pathname !== path) history.replaceState(history.state, "", path + location.search); } catch (_) {}
  }
  function go(scene, arg){
    if (!SCENES[scene]) scene = "overview";
    curScene = scene;
    if (scene === "section") { if (SECTIONS[arg]) curSect = arg; try { localStorage.setItem("dn_deck_sect", curSect); } catch (_) {} }
    syncUrl("/");
    try { localStorage.setItem(LS_SCENE, scene); } catch (_) {}
    closeAllMenus();
    sceneWork.hidden = true; hideTools();
    setNav(scene === "section" ? "section:" + curSect : "scene:" + scene);
    for (const k in sceneEls) sceneEls[k].hidden = k !== scene;
    if (scene === "overview") renderOverview();
    else if (scene === "surface") renderSurface();
    else if (scene === "threat") renderThreat();
    else if (scene === "cloud") renderCloud();
    else if (scene === "compliance") renderCompliance();
    else if (scene === "con") renderIntegrations();
    else if (scene === "tools") { buildTools(); applyTools(); revealGallery(); }
    else if (scene === "toolkit") renderToolkit();
    else if (scene === "invest") renderInvest();
    else if (scene === "findings") renderFindings();
    else if (scene === "section") renderSection();
    else if (scene === "activity") renderActivity();
    else if (scene === "assistant") openAssistant();
  }
  // Any element carrying data-scene (KPI cards, "view all" links, quick actions)
  // routes to that workspace; data-sec opens a tool in the in-deck workspace.
  root.addEventListener("click", (e) => {
    const nav = e.target.closest("[data-scene]");
    if (nav && !nav.classList.contains("dk-tab") && nav.dataset.scene) { go(nav.dataset.scene, nav.dataset.sect); return; }
    const tl = e.target.closest("span[data-tool],a[data-tool],.dk-nv[data-tool]");
    if (tl && tl.dataset.tool) { e.preventDefault(); openTool(tl.dataset.tool, secLabel[tl.dataset.tool] || tl.textContent.trim()); }
  });

  // ---------- integrations ----------
  const ai = INTEGRATIONS.filter((i) => i.kind === "ai");
  const sec = INTEGRATIONS.filter((i) => i.kind === "sec");
  const countConnected = () => INTEGRATIONS.reduce((a, i) => a + (conns[i.id]?.connected ? 1 : 0), 0);
  // Re-render the grid in place after a connect/disconnect and keep the Posture
  // KPI honest without a full scene rebuild.
  function refreshConnState(){
    if (curScene === "con") renderIntegrations();
    const k = root.querySelector('[data-k="conn"] .kn'); if (k) k.textContent = String(countConnected());
  }

  // ---------- drawer ----------
  const drawer = $("#dkDrawer"), drawerBody = $("#dkDrawerBody");
  function openDrawer(it, mode){
    if (!it) return;
    const rec = conns[it.id] || {};
    const connected = !!rec.connected;
    const method = rec.method;
    const kindTxt = it.kind === "ai" ? "AI Model" : "Cyber Intelligence";
    const methodTxt = method === "account" ? "Signed in — add an API key to run" : method === "key" ? "Connected via API key" : "Connected";
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
            // OpenRouter is the one real browser account-link (PKCE) and reaches
            // Claude/GPT/Gemini/Llama with one login, so it stays the primary path.
            // For direct providers an API key is the ONLY thing that can actually run
            // the model (no provider bills your subscription via API), so the key is
            // primary and the "account" button is demoted to an honest sign-in opener.
            oauthProv ? `<button class="dk-b pri" data-act="oauth">Connect your ${esc(it.name)} account</button>` : "",
            it.connect === "key" ? `<button class="dk-b${oauthProv ? "" : " pri"}" data-act="keyform">${oauthProv ? "Use an API key instead (advanced)" : "Connect with API key"}</button>` : "",
            it.account ? `<button class="dk-b" data-act="account">Open ${esc(it.name)} to sign in</button>` : "",
            it.connect === "link" ? `<button class="dk-b${it.account ? "" : " pri"}" data-act="conn">Link to Darknode</button>` : "",
          ].join("");
    const note = keyForm
      ? "Your key is stored only in this browser (localStorage) and never leaves your device from here. Darknode routes calls through its own proxy."
      : oauthProv
      ? "Connect signs you in to OpenRouter and creates a key tied to YOUR OpenRouter account — one login reaches Claude, GPT, Gemini, Llama and more. Calls spend your OpenRouter credits; the default model here is free, so it can cost nothing. No provider lets another site charge your Claude/ChatGPT subscription — this is the honest, lowest-cost alternative."
      : it.account
        ? `Darknode runs ${esc(it.name)} with your own API key — add one above. No provider lets another site bill your existing ${esc(it.name)} subscription, so the "Open to sign in" button only opens ${esc(it.name)}; it can't grant API access on its own. Tip: connect OpenRouter once to reach ${esc(it.name)}, GPT, Gemini and more through a single login.`
        : it.connect === "key"
          ? "Your key is stored only in this browser (localStorage) and never leaves your device from here. Darknode routes calls through its own proxy."
          : "Linking records this service as available to Darknode. No credentials are stored.";
    const mlist = it.kind === "ai" && MODELS[it.id] ? MODELS[it.id] : null;
    let curModel = "";
    if (mlist) { try { curModel = localStorage.getItem("dn_model_" + it.id) || ""; } catch (_) {} }
    // Custom = a model id the user typed that isn't one of our presets. BYOK means
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
      saveConns(conns); toast(`${it.name} sign-in opened — add an API key to run it here`); refreshConnState(it); openDrawer(it);
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
        <label class="dk-tsearch">${IC_SEARCH}<input id="dkToolSearch" type="search" placeholder="Search tools…" autocomplete="off" spellcheck="false"></label>
        <span class="dk-tcount" id="dkToolCount"></span>
      </div>
      <div class="dk-tbody">
        <nav class="dk-tnav" id="dkToolNav" aria-label="Tool categories">
          <button class="dk-tcat" data-cat="all"><span class="cd" style="--bg:#5a6680;--fg:#5a6680"></span><span class="tl">All tools</span><span class="n">${TOTAL_TOOLS.toLocaleString()}</span></button>
          ${groups.map((g) => { const h = hexOf(g.color); return `<button class="dk-tcat" data-cat="${g.id}" title="${esc(g.name)}"><span class="cd" style="--bg:${h};--fg:${h}"></span><span class="tl">${esc(g.name)}</span><span class="n">${g.items.length}</span></button>`; }).join("")}
        </nav>
        <div class="dk-tmain" id="dkToolMain">
          ${groups.map((g) => { const h = hexOf(g.color); return `<section class="dk-tsec" data-g="${g.id}"><div class="th" style="--fg:${h}"><span class="d"></span><h3>${esc(g.name)}</h3><span class="c">${g.items.length} tools</span></div>
            <div class="dk-grid dkx">${g.items.map((it) => `<div class="dk-gcard" data-sec="${esc(it.sec)}" data-label="${esc(it.label)}" data-txt="${esc((it.label + " " + g.name).toLowerCase())}" style="--a:${h}">
              <button class="dk-gcpin${pins.includes(it.sec) ? " on" : ""}" data-pin="${esc(it.sec)}" data-explain="btn.pin" title="Pin to overview" aria-label="Pin to overview">${IC.star}</button>
              <span class="gi">${toolIcon(it.label, g.name)}</span>${it.badge === "live" ? '<span class="glive" data-explain="badge.live" title="Live data"></span>' : ""}
              <span class="gt">${esc(it.label)}</span><span class="garr">Open${IC_CHEV}</span></div>`).join("")}</div></section>`; }).join("")}
          <div class="dk-tnone" id="dkToolNone" hidden>No tools match your search.</div>
        </div>
      </div>`;
    sceneTools.querySelectorAll(".dk-gcard").forEach((c) => c.onclick = (e) => {
      if (e.target.closest(".dk-gcpin")) return;   // pin toggle handled separately
      openTool(c.dataset.sec, c.dataset.label, c.style.getPropertyValue("--a"));
    });
    sceneTools.querySelectorAll(".dk-gcpin").forEach((b) => b.onclick = (e) => {
      e.stopPropagation();
      const on = togglePin(b.dataset.pin);
      b.classList.toggle("on", on);
    });
    sceneTools.querySelectorAll("#dkToolNav .dk-tcat").forEach((b) => b.onclick = () => {
      if (b.dataset.cat === "__toolkit") { go("toolkit"); return; }   // instant utilities live in their own scene
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
    // Instant render — no staggered entrance animation (reads as a real tool index).
    sceneTools.querySelectorAll(".dk-gcard").forEach((c) => c.classList.add("in"));
  }

  // ---------- in-deck tool workspace (tools open here, not the old console) ----------
  const sceneWork = $("#dkWork"), wFrame = $("#dkWFrame"), wTitle = $("#dkWTitle");
  let curSec = null;
  // Tools stay alive after you leave them (the KEEP most recent), so going back to one is
  // instant and keeps its state. Resting the pointer on a tool starts it loading early.
  const KEEP = 5, live = new Map(); // sec -> iframe, least recently used first
  const wLoad = document.createElement("div"); wLoad.className = "dk-wload";
  function toolFrame(sec, label){
    let f = live.get(sec);
    if (f) { live.delete(sec); live.set(sec, f); return f; }
    f = document.createElement("iframe");
    f.title = label; f.src = "/" + sec + "?embed=1&ink=1"; f.loading = "eager"; f.setAttribute("allow", "clipboard-write; clipboard-read");
    f.className = "off";
    f.onload = () => { f.dataset.ready = "1"; f.classList.add("in"); if (curSec === sec) wLoad.remove(); };
    wFrame.appendChild(f); live.set(sec, f);
    for (const [k, old] of live) { if (live.size <= KEEP) break; if (k !== sec && k !== curSec) { old.remove(); live.delete(k); } }
    return f;
  }
  function hideTools(){ live.forEach((x) => x.classList.add("off")); wLoad.remove(); curSec = null; }
  let warmT = 0;
  root.addEventListener("pointerover", (e) => {
    const t = e.target.closest("[data-tool],.dk-gcard[data-sec],.dk-pin[data-sec],.dk-compcard[data-sec]");
    clearTimeout(warmT);
    const sec = t && (t.dataset.tool || t.dataset.sec);
    if (!sec || live.has(sec) || !secLabel[sec]) return;
    // one background load at a time, so sweeping the pointer across a grid stays cheap
    warmT = setTimeout(() => { for (const x of live.values()) if (!x.dataset.ready) return; toolFrame(sec, secLabel[sec] || t.dataset.label || sec); }, 300);
  });
  function openTool(sec, label, accent){
    if (!sec) return;
    label = label || sec; curSec = sec;
    syncUrl("/" + sec);
    const f = toolFrame(sec, label);
    live.forEach((x) => x.classList.toggle("off", x !== f));
    if (f.dataset.ready) wLoad.remove();
    else { wLoad.innerHTML = '<div><div class="sp"></div>Loading ' + esc(label) + '…</div>'; wFrame.appendChild(wLoad); }
    wTitle.innerHTML = '<span class="wi"' + (accent ? ' style="--a:' + accent + '"' : "") + '>' + toolIcon(label) + '</span><span class="wt">' + esc(label) + '</span>';
    const pinBtn = $("#dkWPin"); if (pinBtn) pinBtn.classList.toggle("pinned", pins.includes(sec));
    drawer.classList.remove("on"); closeAllMenus();
    setNav("tool:" + sec, label);
    for (const k in sceneEls) sceneEls[k].hidden = true;
    sceneWork.hidden = false;
    sceneWork.classList.remove("opening"); void sceneWork.offsetWidth; sceneWork.classList.add("opening");
  }
  function closeTool(){
    sceneWork.hidden = true; hideTools();
    go(curScene || "overview");
  }
  $("#dkWBack").onclick = closeTool;
  $("#dkWFull").onclick = () => { const s = curSec; if (primary) { window.open("/" + s, "_blank", "noopener"); return; } teardown(); onOpen(s); };
  if (primary) { $("#dkWFull").hidden = true; $("#dkBrand").title = "Home"; $("#dkAsstFull").textContent = "Open in new tab"; }
  $("#dkWPin").onclick = () => { if (!curSec) return; const on = togglePin(curSec); $("#dkWPin").classList.toggle("pinned", on); toast(on ? "Pinned to overview" : "Unpinned"); };
  $("#dkWCopy").onclick = async () => { if (!curSec) return; try { await navigator.clipboard.writeText(location.origin + "/" + curSec); toast("Tool link copied"); } catch (_) { toast("Copy failed"); } };
  $("#dkWTab").onclick = () => { if (curSec) window.open("/" + curSec, "_blank", "noopener"); };

  // ---------- spotlight ----------
  const spot = $("#dkSpot"), spotIn = $("#dkSpotIn"), spotRes = $("#dkSpotRes");
  let selIdx = 0, matches = [];
  const openSpot = () => { spot.classList.add("on"); spotIn.value = ""; runSpot(""); spotIn.focus(); };
  const closeSpot = () => spot.classList.remove("on");
  // Runnable commands in the palette (not just navigation) — these run an action
  // rather than opening a tool, so Ctrl+K is a true command palette.
  const ACTIONS = [
    { type: "action", label: "Ask Darknode AI", group: "Action", icon: IC.spark, run: () => askAI("") },
    { type: "action", label: "Scan a codebase", group: "Action", icon: IC.term, run: () => openTool("codescan", secLabel["codescan"] || "Code Scanner") },
    { type: "action", label: "Protect the funds (analyze a ledger)", group: "Action", icon: IC.bolt, run: () => openTool("strongroom", secLabel["strongroom"] || "Fund Protection") },
    { type: "action", label: "Open the treasury vault", group: "Action", icon: IC.star, run: () => openTool("vault", secLabel["vault"] || "Treasury Vault") },
    { type: "action", label: "Map an attack surface", group: "Action", icon: IC.radar, run: () => go("surface") },
    { type: "action", label: "Connect a provider", group: "Action", icon: IC.link, run: () => go("con") },
    { type: "action", label: "New investigation", group: "Action", icon: IC.folder, run: () => openTool("investigation", secLabel["investigation"] || "Investigation") },
    { type: "action", label: "Open security graph", group: "Action", icon: IC.grid, run: () => openTool("secgraph", secLabel["secgraph"] || "Security Graph") },
    ...(primary ? [] : [{ type: "action", label: "Open full console", group: "Action", icon: IC.ext, run: () => exitDeck() }]),
    { type: "action", label: "Go to Security Overview", group: "Navigate", icon: IC.home, run: () => go("overview") },
    { type: "action", label: "Go to Attack Surface", group: "Navigate", icon: IC.radar, run: () => go("surface") },
    { type: "action", label: "Go to Threats & Vulnerabilities", group: "Navigate", icon: IC.alert, run: () => go("threat") },
    { type: "action", label: "Go to Cloud Posture", group: "Navigate", icon: IC.cloud, run: () => go("cloud") },
    { type: "action", label: "Go to Compliance", group: "Navigate", icon: IC.shield, run: () => go("compliance") },
    { type: "action", label: "Go to Findings", group: "Navigate", icon: IC.alert, run: () => go("findings") },
    { type: "action", label: "Go to Investigations", group: "Navigate", icon: IC.search, run: () => go("invest") },
    { type: "action", label: "Go to Integrations", group: "Navigate", icon: IC.plug, run: () => go("con") },
    { type: "action", label: "Go to Tool Library", group: "Navigate", icon: IC.grid, run: () => go("tools") },
    { type: "action", label: "Go to Activity", group: "Navigate", icon: IC.pulse, run: () => go("activity") },
    { type: "action", label: "Go to Assistant", group: "Navigate", icon: IC.spark, run: () => go("assistant") },
  ];
  function spotIcon(m){
    if (m.type === "conn") return `<span class="ic">${logoHTML(m.it, "")}</span>`;
    if (m.type === "action") return `<span class="ic act">${m.icon || IC.bolt}</span>`;
    return `<span class="ic" style="--a:${hexOf(m.color)}">${esc(monogram(m.label))}</span>`;
  }
  function runSpot(q){
    q = q.trim().toLowerCase();
    const pool = ACTIONS.concat(index);
    matches = (q ? pool.filter((t) => t.label.toLowerCase().includes(q) || (t.group||"").toLowerCase().includes(q)) : pool).slice(0, 80);
    selIdx = 0;
    spotRes.innerHTML = matches.length ? matches.map((m, i) => `<div class="dk-sr${i===0?" sel":""}" data-i="${i}">${spotIcon(m)}<span class="l">${esc(m.label)}</span><span class="g">${esc(m.group||"")}</span>${m.type === "tool" ? `<button class="dk-srpin${pins.includes(m.sec) ? " on" : ""}" data-pin="${esc(m.sec)}" title="Pin to overview" aria-label="Pin to overview">${IC.star}</button>` : ""}</div>`).join("")
      : `<div class="dk-empty">Nothing matches "${esc(q)}"</div>`;
    spotRes.querySelectorAll(".dk-sr").forEach((r) => r.onclick = (e) => { if (e.target.closest(".dk-srpin")) return; chooseSpot(+r.dataset.i); });
    spotRes.querySelectorAll(".dk-srpin").forEach((b) => b.onclick = (e) => { e.stopPropagation(); b.classList.toggle("on", togglePin(b.dataset.pin)); });
  }
  function chooseSpot(i){ const m = matches[i]; if (!m) return; if (m.type === "action") { closeSpot(); try { m.run(); } catch (_) {} } else if (m.type === "conn") { closeSpot(); go("con"); openDrawer(m.it); } else { closeSpot(); openTool(m.sec, m.label); } }
  function moveSel(d){ if (!matches.length) return; selIdx = (selIdx + d + matches.length) % matches.length; spotRes.querySelectorAll(".dk-sr").forEach((r, i) => r.classList.toggle("sel", i === selIdx)); spotRes.querySelector(".dk-sr.sel")?.scrollIntoView({ block: "nearest" }); }
  $("#dkFindBtn").onclick = openSpot; $("#dkHSearch").onclick = openSpot; spotIn.oninput = () => runSpot(spotIn.value);
  $("#dkAsstBtn").onclick = () => go("assistant");
  spot.addEventListener("click", (e) => { if (e.target === spot) closeSpot(); });

  // ---------- command-center chrome: status, quick-create, notifications, account ----------
  const popNew = $("#dkNewPop"), popBell = $("#dkBellPop"), popAcct = $("#dkAcctPop"), badge = $("#dkBadge"), health = $("#dkHealth");
  const user = opts.user || {};
  let notifs = readRecentActivity().map((a) => ({ text: a.text, ts: a.ts, sim: !!a.sim }));
  let notifSeen = 0, busOffs = [];
  try { notifSeen = parseInt(localStorage.getItem(LS_NOTIF_SEEN) || "0", 10) || 0; } catch (_) {}

  function closeAllMenus(){ [popNew, popBell, popAcct].forEach((p) => p && p.classList.remove("on")); }
  function toggleMenu(pop, btn, build){
    const open = pop.classList.contains("on");
    closeAllMenus();
    if (open) return;
    build();
    try { pop.style.right = Math.max(10, (window.innerWidth - btn.getBoundingClientRect().right) / zoomOf()) + "px"; } catch (_) {}
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
    const nm = user.displayName || user.email || "Account", em = user.email || "Signed in to Darknode";
    popAcct.innerHTML = `<div class="dk-acctcard"><b>${esc(nm)}</b><span>${esc(em)}</span></div>
      <button class="dk-mi" data-go="overview">${IC.home}<span>Command center home</span></button>
      <button class="dk-mi" data-tool="settings">${IC.gear}<span>Settings</span></button>
      <button class="dk-mi" id="dkMiKeys">${IC.bolt}<span>Keyboard shortcuts<span class="sub">Press ? anytime</span></span></button>
      <button class="dk-mi" id="dkMiDense">${IC.grid}<span>Density: ${root.classList.contains("dense") ? "Compact" : "Comfortable"}<span class="sub">Switch to ${root.classList.contains("dense") ? "comfortable" : "compact"} layout</span></span></button>
      <button class="dk-mi" id="dkMiExplain">${IC.spark}<span>Hover explanations: ${explainEnabled() ? "On" : "Off"}<span class="sub">Rest on anything for 3 seconds to see what it means</span></span></button>
      <div class="dk-mi-div"></div>
      <button class="dk-mi" id="dkMiExport">${IC.ext}<span>Export deck state<span class="sub">Connections, pins &amp; notes as JSON</span></span></button>
      <button class="dk-mi" id="dkMiImport">${IC.folder}<span>Import deck state</span></button>
      ${primary ? (opts.isOwner ? `<button class="dk-mi" id="dkMiAdmin">${IC.gear}<span>Admin</span></button>` : "") : `<button class="dk-mi" id="dkMiConsole">${IC.ext}<span>Open full console</span></button>`}
      <div class="dk-mi-div"></div>
      <button class="dk-mi" id="dkMiExit">${IC.logout}<span>${primary ? "Sign out" : "Exit command center"}</span></button>`;
    popAcct.querySelector("[data-go]").onclick = () => { closeAllMenus(); go("overview"); };
    popAcct.querySelector("[data-tool]").onclick = () => { closeAllMenus(); openTool("settings", "Settings"); };
    popAcct.querySelector("#dkMiKeys").onclick = () => { closeAllMenus(); toggleKeys(true); };
    popAcct.querySelector("#dkMiDense").onclick = () => { closeAllMenus(); const d = root.classList.toggle("dense"); try { localStorage.setItem("dn_deck_density", d ? "compact" : "comfortable"); } catch (_) {} };
    popAcct.querySelector("#dkMiExplain").onclick = () => { closeAllMenus(); const on = !explainEnabled(); setExplainEnabled(on); toast("Hover explanations " + (on ? "on" : "off")); };
    popAcct.querySelector("#dkMiExport").onclick = () => { closeAllMenus(); exportDeckState(); };
    popAcct.querySelector("#dkMiImport").onclick = () => { closeAllMenus(); importDeckState(); };
    const miCon = popAcct.querySelector("#dkMiConsole"); if (miCon) miCon.onclick = exitDeck;
    const miAdm = popAcct.querySelector("#dkMiAdmin"); if (miAdm) miAdm.onclick = () => { closeAllMenus(); openTool("admin", "Admin"); };
    popAcct.querySelector("#dkMiExit").onclick = primary ? () => { closeAllMenus(); opts.onSignOut(); } : exitDeck;
  }
  function exitDeck(){ teardown(); onExit(); }
  // Portable deck state: connections, pinned tools and notes (no secrets/API keys).
  function exportDeckState(){
    const state = { v: 1, exported: new Date().toISOString(), connections: conns, pins, notes: loadNotes() };
    const blob = new Blob([JSON.stringify(state, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob), a = document.createElement("a"); a.href = url; a.download = "darknode-deck-state.json"; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast("Deck state exported");
  }
  function importDeckState(){
    const inp = document.createElement("input"); inp.type = "file"; inp.accept = "application/json,.json";
    inp.onchange = () => {
      const f = inp.files && inp.files[0]; if (!f) return;
      const rd = new FileReader();
      rd.onload = () => {
        try {
          const s = JSON.parse(rd.result);
          if (s.connections && typeof s.connections === "object") { conns = s.connections; saveConns(conns); }
          if (Array.isArray(s.pins)) { pins = s.pins.filter((x) => secLabel[x]).slice(0, 12); savePins(pins); }
          if (typeof s.notes === "string") saveNotes(s.notes);
          toast("Deck state imported");
          go(curScene);
        } catch (e) { toast("Import failed: " + (e.message || "bad file")); }
      };
      rd.readAsText(f);
    };
    inp.click();
  }

  // avatar
  const avEl = $("#dkAvatar");
  if (avEl) { if (user.photoURL) avEl.innerHTML = `<img src="${esc(user.photoURL)}" alt="" referrerpolicy="no-referrer">`; else avEl.textContent = monogram(user.displayName || user.email || "Darknode"); }

  $("#dkNew").onclick = (e) => { e.stopPropagation(); toggleMenu(popNew, $("#dkNew"), buildNewMenu); };
  $("#dkBell").onclick = (e) => { e.stopPropagation(); const willOpen = !popBell.classList.contains("on"); toggleMenu(popBell, $("#dkBell"), buildBellMenu); if (willOpen) { notifSeen = Date.now(); try { localStorage.setItem(LS_NOTIF_SEEN, String(notifSeen)); } catch (_) {} updateBadge(); } };
  $("#dkAcct").onclick = (e) => { e.stopPropagation(); toggleMenu(popAcct, $("#dkAcct"), buildAcctMenu); };
  $("#dkBrand").onclick = () => { if (!sceneWork.hidden) closeTool(); go("overview"); };
  root.addEventListener("pointerdown", (e) => { if (!e.target.closest(".dk-pop, .dk-icbtn, .dk-acct")) closeAllMenus(); });
  updateBadge();

  // live platform events -> notifications (and the Activity stream)
  busOffs.push(bus.on(EVENTS.ENTITY_CREATED, (p) => pushNotif(`Entity added to the graph${p && (p.label || p.name) ? `: ${p.label || p.name}` : p && p.type ? `: ${p.type}` : ""}`)));
  busOffs.push(bus.on(EVENTS.RELATIONSHIP_CREATED, () => pushNotif("New relationship created in the security graph")));
  busOffs.push(bus.on(EVENTS.TOOL_RESULT, (p) => pushNotif(`Result captured${p && p.tool ? ` from ${p.tool}` : ""}`)));
  busOffs.push(bus.on(EVENTS.NOTIFY, (p) => pushNotif(typeof p === "string" ? p : (p && p.message) || "")));
  // Tools run in iframes (/<sec>?embed=1), so their graph writes reach this window only as
  // `storage` events. Pull new activity rows in and refresh whichever view shows the graph.
  let syncT = 0;
  const onStorage = (e) => {
    if (e.key !== "dn_recent_activity" && e.key !== "dn_security_graph") return;
    clearTimeout(syncT);
    syncT = setTimeout(() => {
      if (e.key === "dn_recent_activity") {
        const newest = notifs.reduce((n, x) => Math.max(n, x.ts || 0), 0);
        const fresh = readRecentActivity().filter((a) => a.ts > newest).map((a) => ({ text: a.text, ts: a.ts, sim: !!a.sim }));
        if (fresh.length) { notifs = fresh.concat(notifs).slice(0, 40); updateBadge(); if (popBell.classList.contains("on")) buildBellMenu(); }
      }
      if (!sceneWork.hidden) return;   // a tool is open; scenes refresh when the user returns
      const typing = document.activeElement && /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName) && root.contains(document.activeElement);
      if (typing) return;              // never re-render under the user's cursor
      if (curScene === "overview") renderOverview();
      else if (curScene === "invest") renderInvest();
      else if (curScene === "activity") renderActivity();
      else if (curScene === "findings") withGraph(paintFindings);
      else if (curScene === "section") renderSection();
    }, 400);
  };
  window.addEventListener("storage", onStorage);
  busOffs.push(() => { clearTimeout(syncT); window.removeEventListener("storage", onStorage); });

  // ---------- Overview workspace ----------
  function renderOverview(){
    const el = sceneEls.overview;
    const s = readStats();
    const linked = INTEGRATIONS.filter((i) => conns[i.id] && conns[i.id].connected);
    const kpi = (id, val, label, icon, accent, scene, sub) => `<button class="dk-kpi" data-k="${id}"${scene ? ` data-scene="${scene}"` : ""}${accent ? ` style="--a:${accent}"` : ""}><span class="ki">${icon}</span><div class="kn">${val}</div><div class="kl">${esc(label)}</div>${sub ? `<div class="ks">${esc(sub)}</div>` : ""}</button>`;
    const acts = notifs.slice(0, 6);
    const actRows = acts.length
      ? acts.map((a) => `<div class="r"><span class="dot"></span><span class="tx">${esc(a.text)}${a.sim ? ' <span class="dk-simchip">Sample</span>' : ""}</span><span class="ag">${timeAgo(a.ts)}</span></div>`).join("")
      : `<div class="dk-nempty">No activity yet. Open a tool or connect a provider and it shows up here.</div>`;
    const pct = INTEGRATIONS.length ? Math.round(linked.length / INTEGRATIONS.length * 100) : 0;
    const now = new Date();
    const first = ((user.displayName || "").trim().split(/\s+/)[0]) || (user.email || "").split("@")[0] || "there";
    const hr = now.getHours();
    const greet = hr < 12 ? "Good morning" : hr < 18 ? "Good afternoon" : "Good evening";
    el.innerHTML = `
      <div class="dk-ovhead">
        <div><h1>${esc(greet)}, ${esc(first)}</h1><p>Your security posture, with live vulnerability intelligence from NVD, CISA KEV and FIRST EPSS.</p></div>
        <div class="when">${now.toLocaleDateString([], { weekday: "long", month: "long", day: "numeric" })}</div>
      </div>
      <form class="dk-ask" id="dkAsk">
        <span class="ai">${IC.spark}</span>
        <input id="dkAskIn" placeholder="Ask Darknode AI…" autocomplete="off" spellcheck="false">
        <button type="submit">${IC.bolt}Ask</button>
      </form>
      <div class="dk-askhint">Triage a CVE, draft a runbook, explain a finding or review a config.</div>
      <div class="dk-kpis dk-kpis4">
        <div class="dk-start" id="dkStart" hidden>
          <b>Measure your exposure</b>
          <p>There are no real findings in this workspace yet, so there is nothing to score. Map a domain you own or scan a codebase to get a baseline.</p>
          <form class="dk-actform" id="dkStartForm"><input placeholder="yourdomain.com" aria-label="Domain to map" autocomplete="off" spellcheck="false"><button class="dk-tibtn on" type="submit">Map surface</button><button class="dk-tibtn" type="button" data-tool="codescan">Scan code</button></form>
        </div>
        ${kpi("exposure", "—", "Your exposure", IC.shield, "", "findings", "Out of 100, higher is worse")}
        ${kpi("hot", "—", "Open critical and high", IC.alert, "", "findings", "Real findings, samples excluded")}
        ${kpi("cve", "—", "New CVEs", IC.alert, "", "threat", "NVD, last 7 days")}
        ${kpi("kev", "—", "Known exploited", IC.radar, "", "threat", "CISA KEV catalog")}
      </div>
      <div class="dk-expnote" id="dkExpNote" hidden></div>
      <div class="dk-ovp"><h2 data-explain="panel.actions">${IC.bolt} Needs attention <span class="mo" data-scene="findings">All findings</span></h2><div id="dkTopAct"><div class="dk-loading"><span class="sp"></span>Ranking what needs attention…</div></div></div>
      <div class="dk-ovgrid3">
        <div class="dk-ovp"><h2 data-explain="panel.pins">${IC.star} Pinned tools <span class="mo" data-scene="tools">All tools</span></h2><div id="dkPins" class="dk-pins"></div></div>
        <div class="dk-ovp"><h2 data-explain="panel.system">${IC.radar} System status</h2><div id="dkSys" class="dk-sys"></div></div>
        <div class="dk-ovp"><h2 data-explain="panel.integrations">${IC.link} Integrations <span class="mo" data-scene="con">Manage</span></h2>
          <div class="dk-gauge dk-intg"><div class="gmeta"><b>${linked.length}<small>of ${INTEGRATIONS.length} linked</small></b><div class="dk-meter"><i style="--p:${pct}%"></i></div><p>${linked.length ? esc(linked.slice(0, 5).map((i) => i.name).join(", ")) + (linked.length > 5 ? "…" : "") : "Connect AI models and threat-intel sources to power the console."}</p></div></div>
        </div>
      </div>
      <div class="dk-ovgrid">
        <div>
          <div class="dk-ovp"><h2 data-explain="panel.activity">${IC.pulse} Recent activity <span class="mo" data-scene="activity">View all</span></h2><div class="dk-ovact">${actRows}</div></div>
          <div class="dk-ovp"><h2 data-explain="panel.quick">${IC.grid} Quick actions</h2><div class="dk-qa">
            <button class="dk-qacard" data-tool="codescan"><span class="qi" style="--a:#3f78ff">${IC.term}</span><b>Scan a codebase</b><span>Connect GitHub and jump to each vulnerable line.</span></button>
            <button class="dk-qacard" data-tool="strongroom"><span class="qi" style="--a:#f59e0b">${IC.bolt}</span><b>Protect the funds</b><span>Screen a ledger for fraud and intrusion-to-theft chains.</span></button>
            <button class="dk-qacard" data-tool="vault"><span class="qi" style="--a:#f59e0b">${IC.star}</span><b>Treasury vault</b><span>Controls and a tamper-evident ledger for funds at your bank.</span></button>
            <button class="dk-qacard" data-scene="con"><span class="qi" style="--a:#12a85f">${IC.link}</span><b>Connect a provider</b><span>Link an AI model or intel source.</span></button>
            <button class="dk-qacard" data-tool="investigation"><span class="qi" style="--a:#9b5cf0">${IC.folder}</span><b>New investigation</b><span>Open the investigation workspace.</span></button>
            <button class="dk-qacard" data-tool="secgraph"><span class="qi" style="--a:#4f86ff">${IC.grid}</span><b>Security graph</b><span>Entities and their relationships.</span></button>
            <button class="dk-qacard" data-scene="surface"><span class="qi" style="--a:#f0484a">${IC.radar}</span><b>Map an attack surface</b><span>Enter a domain for a real external footprint.</span></button>
            <button class="dk-qacard" data-scene="cloud"><span class="qi" style="--a:#12935a">${IC.grid}</span><b>Run a cloud posture check</b><span>Lint IAM, buckets, security groups, K8s and Dockerfiles.</span></button>
          </div></div>
        </div>
        <div>
          <div class="dk-ovp"><h2 data-explain="panel.threat">${IC.radar} Threat level <span class="mo" data-scene="threat">Threat &amp; vulns</span></h2><div id="dkOvThreat"><div class="dk-loading"><span class="sp"></span>Loading live CVE feed…</div></div></div>
          <div class="dk-ovp"><h2 data-explain="panel.notes">${IC.note} Notes <span class="mo" id="dkNotesClear">Clear</span></h2>
            <textarea class="dk-notes" id="dkNotes" placeholder="Jot an IP, a hypothesis, a to-do"></textarea>
            <div class="dk-notef"><span id="dkNotesSaved">Saved on this device</span><span id="dkNotesCount"></span></div>
          </div>
        </div>
      </div>`;
    el.querySelectorAll(".dk-qacard[data-tool]").forEach((b) => b.onclick = () => openTool(b.dataset.tool, secLabel[b.dataset.tool] || b.dataset.tool));
    // quick AI ask bar -> prefill + open the assistant
    const askForm = el.querySelector("#dkAsk"), askIn = el.querySelector("#dkAskIn");
    if (askForm) askForm.onsubmit = (e) => { e.preventDefault(); askAI(askIn.value); };
    const sf = el.querySelector("#dkStartForm");
    if (sf) {
      sf.onsubmit = (e) => { e.preventDefault(); const d = sf.querySelector("input").value.trim(); if (!d) return toast("Enter a domain you own, e.g. example.com"); go("surface"); renderSurface(d); };
      sf.querySelector("[data-tool]").onclick = () => openTool("codescan", secLabel.codescan || "Code Scanner");
    }
    // pinned tools + live system status
    renderPins();
    renderSystem();
    renderTopActions();
    // notes scratchpad (debounced autosave)
    const notesEl = el.querySelector("#dkNotes"), savedEl = el.querySelector("#dkNotesSaved"), cntEl = el.querySelector("#dkNotesCount");
    if (notesEl) {
      notesEl.value = loadNotes();
      const setCount = () => { if (cntEl) cntEl.textContent = notesEl.value.length ? notesEl.value.length + " chars" : ""; };
      setCount();
      let nt = 0;
      notesEl.oninput = () => { if (savedEl) savedEl.textContent = "Saving…"; clearTimeout(nt); nt = setTimeout(() => { saveNotes(notesEl.value); if (savedEl) savedEl.textContent = "Saved on this device"; setCount(); }, 450); };
      const clr = el.querySelector("#dkNotesClear");
      if (clr) clr.onclick = async () => { if (!notesEl.value.trim()) return; const ok = await (window.dnConfirm ? window.dnConfirm("Clear the scratchpad?") : Promise.resolve(true)); if (!ok) return; notesEl.value = ""; saveNotes(""); setCount(); if (savedEl) savedEl.textContent = "Cleared"; };
    }
    // Two separate, honest scores (inputs always shown):
    //  - Your exposure: ONLY this workspace's real data — open critical/high findings in the
    //    security graph (simulated/sample entities excluded) and integration coverage. With no
    //    real findings yet it shows "—" rather than inventing a number.
    //  - Threat climate: global pressure from the live NVD 7-day feed and the CISA KEV catalog.
    //    The same for every organisation; it is context, not your posture.
    const sig = { cveHot: null, cveTotal: null, kevTotal: null, real: null, hot: null, sim: 0, intCov: Math.round((linked.length / (INTEGRATIONS.length || 1)) * 100) };
    function recomputeExposure(){
      const note = el.querySelector("#dkExpNote"), lines = [];
      const kn = el.querySelector('[data-k="exposure"] .kn');
      if (sig.real != null) {
        if (!sig.real) {
          if (kn) kn.textContent = "—";
          lines.push(`<b>Your exposure: not measured yet</b> — no real findings in this workspace. Map your attack surface or scan a codebase to measure it.`);
        } else {
          const score = Math.round((0.65 * Math.min(1, sig.hot / 25) + 0.35 * (1 - Math.min(1, sig.intCov / 100))) * 100);
          if (kn) kn.textContent = String(score);
          lines.push(`<b>Your exposure ${score}/100</b> (higher is worse) — ${sig.hot} open critical/high finding${sig.hot === 1 ? "" : "s"} of ${sig.real.toLocaleString()} real entities &middot; ${sig.intCov}% integration coverage. Indicative, not an audit.`);
        }
        if (sig.sim) lines.push(`${sig.sim.toLocaleString()} simulated/sample entities (CRUCIBLE, demos) are excluded from every metric.`);
      }
      const parts = [], cn = [];
      if (sig.cveHot != null && sig.cveTotal != null) { parts.push({ w: 0.6, v: Math.min(1, sig.cveTotal ? sig.cveHot / sig.cveTotal : 0) }); cn.push(`${sig.cveHot} of the ${sig.cveTotal} newest CVEs are critical/high`); }
      if (sig.kevTotal != null) { parts.push({ w: 0.4, v: Math.min(1, sig.kevTotal / 1400) }); cn.push(`${sig.kevTotal.toLocaleString()} on the CISA KEV catalog`); }
      if (parts.length) {
        const wsum = parts.reduce((n, p) => n + p.w, 0);
        const c = Math.round((parts.reduce((n, p) => n + p.w * p.v, 0) / wsum) * 100);
        const ck = el.querySelector('[data-k="climate"] .kn'); if (ck) ck.textContent = String(c);
        lines.push(`<b>Threat climate ${c}/100</b> — global, the same for everyone: ${cn.map(esc).join(" &middot; ")}.`);
      }
      if (note && lines.length) { note.hidden = false; note.innerHTML = lines.join("<br>"); }
    }
    // async: real graph entities (simulated/sample excluded) + open high-severity findings
    Promise.all([import("/js/security-graph.js"), import("/js/core/posture.js")]).then(([m, P]) => {
      const all = m.exportAll ? (m.exportAll().entities || []) : [];
      const real = P.realEntities(all);
      const kn = el.querySelector('[data-k="graph"] .kn'); if (kn) kn.textContent = real.length.toLocaleString();
      sig.real = real.length; sig.sim = all.length - real.length;
      sig.hot = real.filter((e) => /^(critical|high)$/i.test(e.severity || "") && !/^(resolved|closed)$/i.test(e.status || "")).length;
      const hk = el.querySelector('[data-k="hot"] .kn'); if (hk) hk.textContent = real.length ? sig.hot.toLocaleString() : "—";
      // Nothing real to score yet: one get-started card replaces the two empty posture tiles.
      const st = el.querySelector("#dkStart"); if (st) { st.hidden = !!real.length; el.querySelectorAll('[data-k="exposure"],[data-k="hot"]').forEach((k) => { k.hidden = !real.length; }); }
      recomputeExposure();
    }).catch(() => { const kn = el.querySelector('[data-k="graph"] .kn'); if (kn) kn.textContent = "0"; sig.real = 0; recomputeExposure(); });
    // async: CISA KEV catalog size
    fetchKev().then((k) => {
      const kn = el.querySelector('[data-k="kev"] .kn'); if (kn) kn.textContent = (k.total || 0).toLocaleString();
      sig.kevTotal = k.total || 0; recomputeExposure();
    }).catch(() => { const kn = el.querySelector('[data-k="kev"] .kn'); if (kn) kn.textContent = "—"; });
    // async: live threat level + CVE KPI
    fetchIntel(30).then((d) => {
      setHealth(true, "Threat feed live");
      sysSet("feed", "", "Live");
      const kn = el.querySelector('[data-k="cve"] .kn'); if (kn) kn.textContent = (d.total || 0).toLocaleString();
      const c = d.counts || {}, order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
      const sum = order.reduce((n, k) => n + (c[k] || 0), 0) || 1;
      const hot = (c.CRITICAL || 0) + (c.HIGH || 0);
      sig.cveHot = hot; sig.cveTotal = (d.cves || []).length; recomputeExposure();
      const box = el.querySelector("#dkOvThreat"); if (!box) return;
      const bar = order.map((k) => `<span style="width:${(c[k] || 0) / sum * 100}%;--bg:${SEV[k].color}"></span>`).join("");
      const leg = order.map((k) => `<span><i style="--bg:${SEV[k].color}"></i>${SEV[k].label} ${c[k] || 0}</span>`).join("");
      const p = Math.round(hot / sum * 100);
      const level = p >= 50 ? "Elevated" : p >= 25 ? "Guarded" : "Low";
      const col = p >= 50 ? "#f0484a" : p >= 25 ? "#b7791f" : "#12a85f";
      box.innerHTML = `<div class="dk-gauge"><div class="ring" style="--p:${p};--c:${col}"><i>${p}%</i></div><div class="gmeta"><b>${level} — ${hot} critical/high</b><p>Across the ${d.cves.length} most-recent CVEs (NVD, last ${d.days} days).</p></div></div><div class="dk-sevbar">${bar}</div><div class="dk-sevleg">${leg}</div>`;
    }).catch(() => {
      setHealth(false, "Threat feed delayed");
      sysSet("feed", "warn", "Delayed");
      const box = el.querySelector("#dkOvThreat"); if (box) box.innerHTML = `<div class="dk-errbox">Couldn't reach the live CVE feed (NVD rate-limits keyless requests to ~5 / 30s). It refreshes automatically — try again shortly.</div>`;
      const kn = el.querySelector('[data-k="cve"] .kn'); if (kn) kn.textContent = "—";
    });
  }
  // update one System-status row (feed/graph/int/ai) by state class + value
  function sysSet(key, cls, val){
    const row = root.querySelector(`#dkSys [data-sys="${key}"]`); if (!row) return;
    row.classList.remove("warn", "off"); if (cls) row.classList.add(cls);
    const sv = row.querySelector(".sv"); if (sv) sv.textContent = val;
  }
  // Pinned-tools overview widget: launch on click, unpin via the ×.
  function renderPins(){
    const box = root.querySelector("#dkPins"); if (!box) return;
    if (!pins.length) { box.innerHTML = `<div class="dk-nempty">No pinned tools yet. Hover any tool in the <b data-scene="tools" style="cursor:pointer;--fg:#2552c6">Tool Library</b> and tap the star, or pin from the command palette (Ctrl K).</div>`; return; }
    box.innerHTML = pins.map((sec) => `<div class="dk-pin" data-sec="${esc(sec)}"><span class="pi">${toolIcon(secLabel[sec] || sec)}</span><span class="pl">${esc(secLabel[sec] || sec)}</span><button class="px" data-unpin="${esc(sec)}" title="Unpin" aria-label="Unpin">&times;</button></div>`).join("");
    box.querySelectorAll(".dk-pin").forEach((r) => r.onclick = (e) => { if (e.target.closest(".px")) return; openTool(r.dataset.sec, secLabel[r.dataset.sec] || r.dataset.sec); });
    box.querySelectorAll(".px").forEach((b) => b.onclick = (e) => { e.stopPropagation(); togglePin(b.dataset.unpin); });
  }
  // Live System-status widget: feed, graph, integrations, assistant.
  function renderSystem(){
    const box = root.querySelector("#dkSys"); if (!box) return;
    const linkedN = INTEGRATIONS.filter((i) => conns[i.id] && conns[i.id].connected).length;
    const prov = (() => { try { return localStorage.getItem("dn_ai_pref_provider") || ""; } catch (_) { return ""; } })();
    const aiName = prov ? (INTEGRATIONS.find((i) => i.id === prov) || {}).name || prov : "Darknode AI (free)";
    const row = (key, cls, label, val) => `<div class="dk-sysrow ${cls}" data-sys="${key}"><span class="sd"></span><span class="sl">${esc(label)}</span><span class="sv">${esc(val)}</span></div>`;
    box.innerHTML =
      row("feed", "warn", "Threat feed (NVD)", "Checking…") +
      row("graph", "off", "Security graph", "—") +
      row("int", linkedN ? "" : "off", "Integrations", linkedN + " / " + INTEGRATIONS.length) +
      row("ai", "", "Assistant", aiName);
    Promise.all([import("/js/security-graph.js"), import("/js/core/posture.js")]).then(([m, P]) => {
      const n = m.exportAll ? P.realEntities(m.exportAll().entities).length : 0;
      sysSet("graph", n ? "" : "off", n ? n.toLocaleString() + " entities" : "Empty");
    }).catch(() => sysSet("graph", "off", "N/A"));
  }

  // ---------- Threat & Vulnerabilities workspace ----------
  // Live NVD CVE feed, cross-referenced with the CISA KEV catalog (known-exploited)
  // and FIRST EPSS exploit-probability, plus a ransomware.live recent-victims panel.
  // Prioritisation is a real SSVC-style order on the LIVE set: KEV first, then EPSS,
  // then CVSS — never a hardcoded CVE map.
  let _tiCves = [], _tiSev = "", _tiQ = "", _tiKev = new Set(), _tiEpss = {}, _tiPrio = false;
  function renderThreat(){
    const el = sceneEls.threat;
    el.innerHTML = `<div class="dk-ti-head"><h1>Threat &amp; Vulnerabilities</h1><span class="mo" id="dkTiFull">Open full Threat Feed ${IC.ext}</span></div>
      <div id="dkTiBody"><div class="dk-loading"><span class="sp"></span>Fetching the latest CVEs from the NVD…</div></div>`;
    el.querySelector("#dkTiFull").onclick = () => openTool("threatfeed", "Threat Intel Feed");
    fetchIntel(40).then((d) => {
      setHealth(true, "Threat feed live");
      _tiCves = d.cves || []; _tiSev = ""; _tiQ = ""; _tiKev = new Set(); _tiEpss = {}; _tiPrio = true;
      const c = d.counts || {};
      const chips = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((k) => `<button class="dk-sevchip dk-sevfilter" data-sev="${k}"><div class="n" style="--fg:${SEV[k].color}">${c[k] || 0}</div><div class="l">${SEV[k].label}</div></button>`).join("")
        + `<div class="dk-sevchip"><div class="n">${(d.total || 0).toLocaleString()}</div><div class="l">Published 7d</div></div>`
        + `<div class="dk-sevchip" id="dkTiKevChip"><div class="n" style="--fg:#e0383a">—</div><div class="l">Known-exploited</div></div>`;
      const charts = buildThreatCharts(d.cves);
      el.querySelector("#dkTiBody").innerHTML = `<div class="dk-sublede">Severity counts and charts cover the ${_tiCves.length} most recent CVEs; ${(d.total || 0).toLocaleString()} were published to NVD in the last 7 days.</div><div class="dk-sevchips">${chips}</div>${charts}
        <div id="dkTiRansom"></div>
        <div class="dk-tibar">
          <label class="dk-tsearch dk-tifind">${IC_SEARCH}<input id="dkTiSearch" type="search" placeholder="Filter CVEs…" autocomplete="off" spellcheck="false"></label>
          <span class="dk-ticount" id="dkTiCount"></span>
          <button class="dk-tibtn on" id="dkTiPrio" data-explain="btn.prioritize" title="Order by exploitation risk: KEV, then EPSS, then CVSS">Prioritize</button>
          <button class="dk-tibtn" id="dkTiCsv">Export CSV</button>
          <button class="dk-tibtn" id="dkTiJson">Export JSON</button>
        </div>
        <div id="dkTiList"></div>`;
      const search = el.querySelector("#dkTiSearch");
      search.oninput = () => { _tiQ = search.value.trim().toLowerCase(); paintTiList(); };
      el.querySelectorAll(".dk-sevfilter").forEach((b) => b.onclick = () => { _tiSev = _tiSev === b.dataset.sev ? "" : b.dataset.sev; el.querySelectorAll(".dk-sevfilter").forEach((x) => x.classList.toggle("on", x.dataset.sev === _tiSev)); paintTiList(); });
      el.querySelector("#dkTiPrio").onclick = (e) => { _tiPrio = !_tiPrio; e.currentTarget.classList.toggle("on", _tiPrio); paintTiList(); };
      el.querySelector("#dkTiCsv").onclick = () => exportCves("csv");
      el.querySelector("#dkTiJson").onclick = () => exportCves("json");
      paintTiList();
      // Enrich with KEV + EPSS, then repaint so badges/ordering appear live.
      fetchKev().then((k) => {
        _tiKev = k.set || new Set();
        const n = _tiCves.filter((v) => _tiKev.has(v.id)).length;
        const chip = el.querySelector("#dkTiKevChip .n"); if (chip) chip.textContent = String(n);
        paintTiList();
      }).catch(() => { const chip = el.querySelector("#dkTiKevChip .n"); if (chip) chip.textContent = "—"; });
      fetchEpss(_tiCves.map((v) => v.id)).then((m) => { _tiEpss = m || {}; paintTiList(); });
      // Recent ransomware-leak activity — honest live feed, hidden if unavailable.
      fetchRansom(8).then((vics) => {
        const box = el.querySelector("#dkTiRansom"); if (!box || !vics.length) return;
        const rows = vics.map((v) => { const name = esc(v.victim || v.post_title || v.title || "—"); const grp = esc(v.group_name || v.group || "—"); const when = esc(String(v.discovered || v.published || v.attackdate || "").slice(0, 10)); return `<tr><td>${name}</td><td>${grp}</td><td>${when}</td></tr>`; }).join("");
        box.innerHTML = `<div class="dk-tpanel dk-ransom"><div class="ct">${IC.radar} Recent ransomware activity <span class="src">live · ransomware.live</span></div><div class="dk-tscroll"><table class="dk-rtab"><thead><tr><th>Organisation</th><th>Group</th><th>Listed</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
      }).catch(() => {});
    }).catch(() => {
      setHealth(false, "Threat feed delayed");
      el.querySelector("#dkTiBody").innerHTML = `<div class="dk-errbox">Couldn't reach the NVD CVE feed. Keyless requests are rate-limited to ~5 every 30 seconds — wait a moment and reopen this tab.<br><button class="dk-b" id="dkTiRetry" style="display:inline-flex;width:auto;margin-top:12px">Retry</button></div>`;
      const rt = el.querySelector("#dkTiRetry"); if (rt) rt.onclick = () => { _cveCache = null; _cveAt = 0; renderThreat(); };
    });
  }
  // Charts built purely from the fetched CVE set: a 7-day stacked-severity trend
  // and a CVSS-band distribution. No extra network calls, no fabricated data.
  function buildThreatCharts(cves){
    cves = cves || [];
    const ORD = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
    // 7-day trend
    const days = [];
    for (let i = 6; i >= 0; i--) { const dt = new Date(Date.now() - i * 86400000); days.push(dt.toISOString().slice(0, 10)); }
    const byDay = {}; days.forEach((k) => byDay[k] = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, total: 0 });
    cves.forEach((v) => { const b = byDay[v.date]; if (b) { b[v.severity] = (b[v.severity] || 0) + 1; b.total++; } });
    const maxDay = Math.max(1, ...days.map((k) => byDay[k].total));
    const cols = days.map((k) => {
      const b = byDay[k], barPx = Math.round(b.total / maxDay * 108);
      const segs = ORD.map((s) => b[s] ? `<span style="height:${(b[s] / b.total * 100).toFixed(1)}%;--bg:${SEV[s].color}"></span>` : "").join("");
      const dow = new Date(k + "T00:00:00").toLocaleDateString([], { weekday: "short" });
      return `<div class="col"><span class="cn">${b.total || ""}</span><div class="stk" style="height:${Math.max(b.total ? 6 : 2, barPx)}px">${segs}</div><span class="cx">${esc(dow)}</span></div>`;
    }).join("");
    // CVSS bands
    const bands = [{ l: "9.0–10", lo: 9, hi: 10.1, c: SEV.CRITICAL.color }, { l: "7.0–8.9", lo: 7, hi: 9, c: SEV.HIGH.color }, { l: "4.0–6.9", lo: 4, hi: 7, c: SEV.MEDIUM.color }, { l: "0.1–3.9", lo: 0, hi: 4, c: SEV.LOW.color }];
    const scored = cves.filter((v) => v.cvss != null);
    bands.forEach((bd) => bd.n = scored.filter((v) => v.cvss >= bd.lo && v.cvss < bd.hi).length);
    const maxBand = Math.max(1, ...bands.map((b) => b.n));
    const barRows = bands.map((b) => `<div class="dk-barrow"><span class="bl">${b.l}</span><span class="bt"><i style="width:${(b.n / maxBand * 100).toFixed(1)}%;--bg:${b.c}"></i></span><span class="bn">${b.n}</span></div>`).join("");
    // A day-by-day trend only means something when the sample spans several days;
    // otherwise the distribution gets the full width instead of six empty columns.
    const spread = days.filter((k) => byDay[k].total).length > 1;
    return `<div class="dk-twrap"${spread ? "" : ' style="grid-template-columns:1fr"'}>
      ${spread ? `<div class="dk-tpanel"><div class="dk-chart"><div class="ct">${IC.pulse} Latest ${cves.length} CVEs by publish day and severity</div><div class="dk-trend">${cols}</div></div></div>` : ""}
      <div class="dk-tpanel"><div class="dk-chart"><div class="ct">${IC.radar} CVSS score distribution (${scored.length} scored)</div><div class="dk-bars">${barRows}</div></div></div>
    </div>`;
  }
  // Exploitation-priority rank for a CVE on the LIVE set: KEV membership dominates,
  // then EPSS probability, then CVSS. Higher = patch sooner.
  const tiRank = (v) => (_tiKev.has(v.id) ? 1e6 : 0) + (_tiEpss[v.id] || 0) * 1000 + (v.cvss || 0);
  const tiFiltered = () => {
    let rows = _tiCves.filter((v) => (!_tiSev || v.severity === _tiSev) && (!_tiQ || (v.id + " " + (v.title || "")).toLowerCase().includes(_tiQ)));
    if (_tiPrio) rows = rows.slice().sort((a, b) => tiRank(b) - tiRank(a));
    return rows;
  };
  function paintTiList(){
    const box = root.querySelector("#dkTiList"); if (!box) return;
    const rows = tiFiltered();
    const cnt = root.querySelector("#dkTiCount"); if (cnt) cnt.textContent = rows.length + " of " + _tiCves.length;
    box.innerHTML = rows.length
      ? rows.map((v) => {
          const kev = _tiKev.has(v.id);
          const ep = _tiEpss[v.id];
          const badges = (kev ? `<span class="dk-kevb" title="On the CISA Known Exploited Vulnerabilities catalog">Known exploited</span>` : "")
            + (ep != null ? `<span class="dk-epssb" title="FIRST EPSS exploit probability (30-day)">EPSS ${(ep * 100).toFixed(1)}%</span>` : "");
          return `<div class="dk-cve${kev ? " kev" : ""}" data-id="${esc(v.id)}"><div class="sv" style="--fg:${SEV[v.severity].color}">${v.cvss == null ? "—" : v.cvss.toFixed(1)}<small>${SEV[v.severity].label}</small></div><div class="bd"><div class="id">${esc(v.id)}${badges}</div><div class="ti">${esc(v.title || "No description provided yet.")}</div><div class="dt">Published ${esc(v.date || "—")}</div></div></div>`;
        }).join("")
      : `<div class="dk-tnone">No CVEs match the filter.</div>`;
    box.querySelectorAll(".dk-cve").forEach((r) => r.onclick = () => window.open("https://nvd.nist.gov/vuln/detail/" + encodeURIComponent(r.dataset.id), "_blank", "noopener"));
  }
  function exportCves(fmt){
    const base = tiFiltered(); if (!base.length) { toast("Nothing to export"); return; }
    const rows = base.map((v) => ({ ...v, kev: _tiKev.has(v.id), epss: _tiEpss[v.id] != null ? _tiEpss[v.id] : null }));
    let blob, name;
    if (fmt === "json") { blob = new Blob([JSON.stringify(rows, null, 2)], { type: "application/json" }); name = "darknode-cves.json"; }
    else { const q = (x) => `"${String(x == null ? "" : x).replace(/"/g, '""')}"`; const lines = rows.map((v) => [v.id, v.cvss == null ? "" : v.cvss, v.severity, v.kev ? "yes" : "no", v.epss == null ? "" : v.epss, v.date || "", v.title || ""].map(q).join(",")); blob = new Blob(["id,cvss,severity,kev,epss,published,title\n" + lines.join("\n")], { type: "text/csv" }); name = "darknode-cves.csv"; }
    const url = URL.createObjectURL(blob), a = document.createElement("a"); a.href = url; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast("Exported " + rows.length + " CVEs");
  }

  // ---------- Attack Surface workspace (real external recon via the proxy) ----------
  let _surfLast = "";
  const surfClean = (d) => String(d || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^\*\./, "");
  function renderSurface(dom){
    const el = sceneEls.surface;
    const d0 = (typeof dom === "string" && dom) ? dom : _surfLast;
    el.innerHTML = `
      <div class="dk-ti-head"><h1>Attack Surface</h1><span class="mo" id="dkSurfFull">Open Exposure Mapping ${IC.ext}</span></div>
      <p class="dk-sublede">Enter a domain to map its real external footprint — certificate-transparency subdomains, DNS, registration, owning network, HTTP security headers, email authentication and security.txt. Everything is fetched live through the Darknode proxy; nothing is simulated.</p>
      <form class="dk-surfbar" id="dkSurfForm">
        <input id="dkSurfIn" placeholder="example.com" autocomplete="off" spellcheck="false" value="${esc(d0)}">
        <button type="submit" class="dk-tibtn on">Map surface</button>
      </form>
      <div class="dk-surfhint">Use a domain you own or are authorised to assess. Lookups use authoritative public records (certificate transparency, DNS, RDAP registries, BGP origin data) and a single read-only HTTP GET.</div>
      <div class="dk-surfgrid" id="dkSurfGrid" hidden></div>`;
    el.querySelector("#dkSurfFull").onclick = () => openTool("attacksurf", "Exposure Mapping");
    const form = el.querySelector("#dkSurfForm"), input = el.querySelector("#dkSurfIn");
    form.onsubmit = (e) => { e.preventDefault(); runSurface(input.value); };
    if (d0) runSurface(d0);
  }
  function runSurface(raw){
    const el = sceneEls.surface;
    const d = surfClean(raw);
    if (!d || !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(d)) { toast("Enter a valid domain, e.g. example.com"); return; }
    if (!proxyConfigured()) { el.querySelector("#dkSurfGrid").hidden = false; el.querySelector("#dkSurfGrid").innerHTML = `<div class="dk-errbox">Live lookups are unavailable — the Darknode proxy is not configured in this environment.</div>`; return; }
    _surfLast = d;
    const grid = el.querySelector("#dkSurfGrid"); grid.hidden = false;
    const P = [
      { id: "subs", title: "Subdomains", tool: "subdomains", label: "Subdomain Enum" },
      { id: "dns", title: "DNS records", tool: "dns", label: "DNS Toolkit" },
      { id: "reg", title: "Registration (RDAP)", tool: "whoisrecon", label: "WHOIS Recon" },
      { id: "net", title: "Owning network", tool: "asnexplorer", label: "ASN Explorer" },
      { id: "http", title: "HTTP & security headers", tool: "headeranalyzer", label: "Header Analyzer" },
      { id: "email", title: "Email authentication", tool: "emailauth", label: "Email Auth Analyzer" },
      { id: "stxt", title: "security.txt", tool: "securitytxt", label: "security.txt Studio" }
    ];
    grid.innerHTML = P.map((p) => `<div class="dk-surfp" id="surf-${p.id}"><div class="hd"><h2>${esc(p.title)}</h2><span class="hx" id="surfx-${p.id}"></span><span class="mo" data-opensec="${p.tool}" data-openlabel="${esc(p.label)}">Open tool</span></div><div class="bd" id="surfb-${p.id}"><div class="dk-loading"><span class="sp"></span>Looking up ${esc(d)}…</div></div></div>`).join("");
    grid.querySelectorAll("[data-opensec]").forEach((s) => s.onclick = () => openTool(s.dataset.opensec, s.dataset.openlabel));
    const bd = (id) => grid.querySelector("#surfb-" + id);
    const errHTML = (e) => `<div class="dk-errbox">${esc((e && e.message) || "Lookup failed.")}</div>`;
    const addGraphBtn = (id, items, linkName) => {
      const hx = grid.querySelector("#surfx-" + id); if (!hx || !items.length) return;
      hx.innerHTML = `<button class="dk-graphadd">Add ${items.length} to graph</button>`;
      hx.querySelector("button").onclick = () => import("/js/graph-bridge.js?v=20261012a").then((gb) => { const r = gb.sendToGraph("Attack Surface — " + linkName, items); toast("Security Graph: " + (r.created || 0) + " added, " + (r.updated || 0) + " updated"); }).catch(() => toast("Couldn't reach the Security Graph"));
    };
    // Subdomains (crt.sh)
    surface.subdomains(d).then((subs) => {
      bd("subs").innerHTML = subs.length
        ? `<div class="dk-surfcount">${subs.length} unique names from certificate transparency</div><div class="dk-chiplist">${subs.slice(0, 60).map((s) => `<span class="dk-chipv">${esc(s)}</span>`).join("")}${subs.length > 60 ? `<span class="dk-chipv more">+${subs.length - 60} more</span>` : ""}</div>`
        : `<div class="dk-tnone">No subdomains found in certificate transparency logs.</div>`;
      addGraphBtn("subs", subs.slice(0, 200).map((s) => ({ type: "DOMAIN", name: s, data: { source: "crt.sh", parent: d } })), "Subdomains");
    }).catch((e) => bd("subs").innerHTML = errHTML(e));
    // DNS
    surface.dns(d).then((rec) => {
      const row = (k) => (rec[k] && rec[k].length) ? `<div class="dk-dnsrow"><span class="t">${k}</span><span class="v">${rec[k].slice(0, 8).map((x) => `<span class="ln" title="${esc(x)}">${esc(x)}</span>`).join("")}</span></div>` : "";
      const html = ["A", "AAAA", "MX", "NS", "TXT"].map(row).join("");
      bd("dns").innerHTML = html || `<div class="dk-tnone">No DNS records resolved.</div>`;
      const ips = [].concat(rec.A || [], rec.AAAA || []);
      addGraphBtn("dns", ips.map((ip) => ({ type: "IP", name: ip, data: { source: "DoH", domain: d } })), "DNS");
      // Owning network for the first address (BGP origin + registry netblock)
      const ip0 = ips[0];
      if (ip0) {
        Promise.allSettled([surface.asn(ip0), surface.netblock(ip0)]).then(([a, n]) => {
          const asn = a.status === "fulfilled" ? a.value : null;
          const nb = n.status === "fulfilled" ? n.value : null;
          if (!asn && !nb) { bd("net").innerHTML = errHTML(a.reason || n.reason); return; }
          const kv = (k, v) => v ? `<div><span>${k}</span><b>${esc(v)}</b></div>` : "";
          bd("net").innerHTML = `<div class="dk-kv">${kv("IP", ip0)}${asn ? kv("ASN", asn.asn + " — " + asn.name) + kv("BGP prefix", asn.prefix) + kv("Registry", [asn.registry, asn.country].filter(Boolean).join(" · ")) : ""}${nb ? kv("Netblock", nb.name + (nb.handle ? " (" + nb.handle + ")" : "")) + kv("Allocation", nb.cidr || nb.range) : ""}</div>`;
        });
      } else { bd("net").innerHTML = `<div class="dk-tnone">No A or AAAA record to attribute to a network.</div>`; }
    }).catch((e) => { bd("dns").innerHTML = errHTML(e); bd("net").innerHTML = errHTML(e); });
    // Registration
    surface.rdap(d).then((r) => {
      bd("reg").innerHTML = `<div class="dk-kv"><div><span>Registrar</span><b>${esc(r.registrar)}</b></div><div><span>Registered</span><b>${esc(r.registered)}</b></div><div><span>Updated</span><b>${esc(r.updated)}</b></div><div><span>Expires</span><b>${esc(r.expires)}</b></div>${r.nameservers.length ? `<div><span>Nameservers</span><b>${esc(r.nameservers.slice(0, 6).join(", "))}</b></div>` : ""}${r.status.length ? `<div><span>Status</span><b>${esc(r.status.slice(0, 4).join(", "))}</b></div>` : ""}</div>`;
    }).catch((e) => bd("reg").innerHTML = errHTML(e));
    // HTTP + security headers
    surface.httpProbe(d).then((h) => {
      const sh = h.secHeaders.map((s) => `<div class="dk-shrow ${s.present ? "ok" : "no"}"><span class="d"></span><span class="l">${esc(s.label)}</span><span class="v">${s.present ? "present" : "missing"}</span></div>`).join("");
      const tech = h.tech.length ? `<div class="dk-techline">${h.tech.map((t) => `<span class="dk-chipv">${esc(t.k)}: ${esc(t.v)}</span>`).join("")}</div>` : "";
      bd("http").innerHTML = `<div class="dk-kv"><div><span>Status</span><b>${esc(String(h.status) + " " + h.statusText)}</b></div><div><span>Final URL</span><b>${esc(h.finalUrl)}</b></div><div><span>Server</span><b>${esc(h.server)}</b></div></div>${tech}<div class="dk-shlist">${sh}</div>`;
    }).catch((e) => bd("http").innerHTML = errHTML(e));
    // Email auth
    surface.emailAuth(d).then((m) => {
      const line = (lbl, o, extra) => `<div class="dk-shrow ${o.present ? "ok" : "no"}"><span class="d"></span><span class="l">${esc(lbl)}</span><span class="v">${o.present ? (extra || "configured") : "missing"}</span></div>`;
      bd("email").innerHTML = `<div class="dk-shlist">${line("SPF", m.spf)}${line("DMARC", m.dmarc, m.dmarc.policy ? "p=" + m.dmarc.policy : "")}</div>${m.spf.record ? `<div class="dk-rec">${esc(m.spf.record)}</div>` : ""}${m.dmarc.record ? `<div class="dk-rec">${esc(m.dmarc.record)}</div>` : ""}`;
    }).catch((e) => bd("email").innerHTML = errHTML(e));
    // security.txt
    surface.securityTxt(d).then((s) => {
      bd("stxt").innerHTML = s.found
        ? `<div class="dk-shrow ok"><span class="d"></span><span class="l">security.txt</span><span class="v">found</span></div>${s.contact ? `<div class="dk-rec">Contact: ${esc(s.contact)}</div>` : ""}`
        : `<div class="dk-shrow no"><span class="d"></span><span class="l">security.txt</span><span class="v">not found (HTTP ${esc(String(s.status))})</span></div>`;
    }).catch((e) => bd("stxt").innerHTML = errHTML(e));
  }

  // ---------- Cloud Security workspace ----------
  // Phase-1 value is real and offline: the deterministic cloud/K8s/Docker linters in
  // tools/cloud.js run entirely in the browser. Read-only cloud account connectors are
  // on the roadmap and are represented honestly — never faked.
  const CLOUD_WB = ["cl-iam-policy-lint", "cl-s3-bucket-policy-explain", "cl-sg-audit", "cl-dockerfile-lint", "cl-compose-lint"];
  let _cloudTools = null;
  function renderCloud(){
    const el = sceneEls.cloud;
    el.innerHTML = `
      <div class="dk-ti-head"><h1>Cloud Security</h1></div>
      <p class="dk-sublede">Posture checks that run entirely in your browser — paste a config and lint it; nothing is uploaded. Read-only AWS, Azure and GCP account connectors are on the roadmap below.</p>
      <div class="dk-cloudtop">
        <div class="dk-cloudwb">
          <div class="wbh"><h2>Posture workbench</h2></div>
          <select id="dkCloudSel" class="dk-cloudsel"></select>
          <div id="dkCloudDesc" class="dk-clouddesc"></div>
          <textarea id="dkCloudIn" class="dk-cloudin" spellcheck="false"></textarea>
          <div class="dk-cloudbtns"><button id="dkCloudRun" class="dk-tibtn on">Run check</button><span class="mo" id="dkCloudOpen">Open full tool</span></div>
          <pre id="dkCloudOut" class="dk-cloudout" hidden></pre>
        </div>
        <div class="dk-cloudconn">
          <div class="cc-badge">Roadmap</div>
          <h2>Connect a cloud account</h2>
          <p>Read-only AWS, Azure and GCP connectors will pull live posture — public buckets, over-broad IAM, open security groups, unencrypted volumes — using scoped read-only credentials. No write access, ever.</p>
          <div class="cc-list"><span>AWS (read-only) — coming</span><span>Azure (read-only) — coming</span><span>GCP (read-only) — coming</span></div>
          <button id="dkCloudRoadmap" class="dk-tibtn">See the plan</button>
        </div>
      </div>
      <h2 class="dk-cloudgridh">All cloud &amp; container checks <span id="dkCloudN">loading…</span></h2>
      <div class="dk-cloudgrid" id="dkCloudGrid"><div class="dk-loading"><span class="sp"></span>Loading the cloud toolset…</div></div>`;
    const sel = el.querySelector("#dkCloudSel"), descEl = el.querySelector("#dkCloudDesc"), inEl = el.querySelector("#dkCloudIn"), outEl = el.querySelector("#dkCloudOut"), runBtn = el.querySelector("#dkCloudRun"), grid = el.querySelector("#dkCloudGrid");
    el.querySelector("#dkCloudRoadmap").onclick = () => { if (window.dnModal) window.dnModal({ title: "Cloud connectors — the plan", desc: "Phase 1 (now): paste-and-lint posture checks for IAM, S3, security groups, Dockerfiles, docker-compose and Kubernetes — 69 deterministic checks that run in your browser.\n\nPhase 2 (next): read-only AWS, Azure and GCP connectors using scoped, read-only credentials (e.g. an AWS SecurityAudit role). They will inventory assets and surface public buckets, over-broad IAM, open security groups and unencrypted storage against live configuration.\n\nPrinciple: read-only only, no write access, and findings are always from real configuration — never simulated.", submitText: "Got it", cancelText: "" }); else toast("Read-only cloud connectors are on the roadmap."); };
    el.querySelector("#dkCloudOpen").onclick = () => { const t = _cloudTools && _cloudTools.find((x) => x.id === sel.value); if (sel.value) openTool("tool-" + sel.value, t ? t.name : sel.value); };
    import("/js/tools/cloud.js").then((m) => {
      _cloudTools = (m.TOOLS || []).filter((t) => t.cat === "cloud");
      const nEl = el.querySelector("#dkCloudN"); if (nEl) nEl.textContent = _cloudTools.length + " offline tools";
      const wb = CLOUD_WB.map((id) => _cloudTools.find((t) => t.id === id)).filter(Boolean);
      sel.innerHTML = wb.map((t) => `<option value="${t.id}">${esc(t.name)}</option>`).join("");
      const syncSel = () => { const t = wb.find((x) => x.id === sel.value) || wb[0]; if (!t) return; descEl.textContent = t.desc || ""; const inp = (t.inputs || [])[0] || {}; inEl.placeholder = inp.placeholder || "Paste configuration…"; inEl.value = ""; outEl.hidden = true; };
      sel.onchange = syncSel; syncSel();
      runBtn.onclick = () => {
        const t = wb.find((x) => x.id === sel.value); if (!t) return;
        const inp = (t.inputs || [])[0] || { k: "text" };
        let r; try { r = t.run({ [inp.k]: inEl.value }); } catch (e) { r = { error: (e && e.message) || "Error" }; }
        outEl.hidden = false;
        outEl.textContent = (r && r.error) ? ("Error: " + r.error) : (typeof r === "string" ? (r || "No output — check your input.") : JSON.stringify(r, null, 2));
      };
      grid.innerHTML = _cloudTools.map((t) => `<button class="dk-cloudcard" data-id="${t.id}"><b>${esc(t.name)}</b><span>${esc(t.desc || "")}</span></button>`).join("");
      grid.querySelectorAll(".dk-cloudcard").forEach((b) => b.onclick = () => { const t = _cloudTools.find((x) => x.id === b.dataset.id); openTool("tool-" + b.dataset.id, t ? t.name : b.dataset.id); });
    }).catch(() => { grid.innerHTML = `<div class="dk-errbox">Couldn't load the cloud toolset.</div>`; });
  }

  // ---------- Compliance & Posture workspace ----------
  const COMPLIANCE = [
    { sec: "compliance", name: "Compliance Checker", desc: "Assess controls against CIS, ISO 27001, SOC 2, PCI DSS, HIPAA, GDPR and NIST CSF." },
    { sec: "fedcompliance", name: "Federal Compliance (NIST 800-53)", desc: "Map and track NIST SP 800-53 control families for FedRAMP and FISMA." },
    { sec: "zerotrust", name: "Zero Trust Planner", desc: "Design a zero-trust architecture across identity, device, network and workload pillars." },
    { sec: "crosswalk", name: "GenAI Security Crosswalk", desc: "Map 51 OWASP GenAI risks across 26 frameworks — 3,771 real, sourced mappings." },
    { sec: "secchecklist", name: "Security Checklist", desc: "Work through a structured security self-assessment checklist." },
    { sec: "supplychain", name: "Supply Chain Analyzer", desc: "Assess third-party and software-supply-chain risk." }
  ];
  function renderCompliance(){
    const el = sceneEls.compliance;
    el.innerHTML = `
      <div class="dk-ti-head"><h1>Compliance &amp; Posture</h1></div>
      <div class="dk-compnote">Self-reported — these are frameworks and self-assessment tools, not an automated audit. Answers and mappings reflect what you enter and the frameworks' published control sets.</div>
      <div class="dk-compgrid">${COMPLIANCE.map((c) => `<button class="dk-compcard" data-sec="${esc(c.sec)}" data-label="${esc(c.name)}"><b>${esc(c.name)}</b><span>${esc(c.desc)}</span><span class="go">Open ${IC.ext}</span></button>`).join("")}</div>`;
    el.querySelectorAll(".dk-compcard").forEach((b) => b.onclick = () => openTool(b.dataset.sec, b.dataset.label));
  }

  // ---------- Integrations workspace (professional grid; honest status) ----------
  const INT_GROUPS = [
    { title: "AI Models", ids: ai.map((i) => i.id) },
    { title: "Threat Intelligence", ids: ["virustotal", "greynoise", "abuseipdb", "otx", "abusech", "urlscan", "pulsedive", "intelx", "misp", "mitre"] },
    { title: "Attack Surface & Recon", ids: ["shodan", "censys", "securitytrails", "zoomeye", "binaryedge", "netlas", "fullhunt", "ipinfo", "hunter", "maltego"] },
    { title: "Exposure & Breach", ids: ["hibp", "dehashed"] },
    { title: "Malware Sandbox", ids: ["hybrid", "anyrun"] },
    { title: "Vulnerability", ids: ["nvd", "circl", "exploitdb"] }
  ];
  function renderIntegrations(){
    const el = sceneEls.con;
    const byId = {}; INTEGRATIONS.forEach((i) => byId[i.id] = i);
    const card = (it) => {
      const rec = conns[it.id] || {};
      const live = rec.connected && rec.method === "key";
      const refOnly = rec.connected && rec.method !== "key";
      const cls = live ? "on" : refOnly ? "ref" : "off";
      const label = live ? "Connected" : refOnly ? "Reference only" : "Connect";
      return `<button class="dk-intcard" data-id="${esc(it.id)}">${logoHTML(it, "ic")}<div class="meta"><b>${esc(it.name)}</b><p>${esc(it.blurb)}</p></div><span class="dk-stat ${cls}"><span class="d"></span>${label}</span></button>`;
    };
    const groups = INT_GROUPS.map((g) => { const items = g.ids.map((id) => byId[id]).filter(Boolean); return items.length ? `<div class="dk-intgrp"><h2>${esc(g.title)} <span>${items.length}</span></h2><div class="dk-intcards">${items.map(card).join("")}</div></div>` : ""; }).join("");
    el.innerHTML = `
      <div class="dk-ti-head"><h1>Integrations</h1><span class="dk-intmeta">${countConnected()} connected of ${INTEGRATIONS.length}</span></div>
      <p class="dk-sublede">Connect AI models and threat-intelligence providers. API-key connections are live; providers shown as “reference” are directory entries you open and sign in to directly — Darknode does not stream their data on your behalf.</p>
      ${groups}`;
    el.querySelectorAll(".dk-intcard").forEach((b) => b.onclick = () => openDrawer(INTEGRATIONS.find((i) => i.id === b.dataset.id)));
  }

  // ---------- Investigations workspace ----------
  // ---------- Investigations & Graph workspace ----------
  // Reads the live security graph (singleton module — imported WITHOUT ?v=) and
  // presents KPIs, severity/status distributions, and a filterable entity table.
  let graphMod = null;
  const invF = { q: "", type: "", sev: "", status: "", sim: false };
  let postureMod = null;
  const capword = (s) => s ? s.charAt(0).toUpperCase() + s.slice(1) : "—";
  function withGraph(cb){
    if (graphMod) { cb(graphMod); return; }
    Promise.all([import("/js/security-graph.js"), import("/js/core/posture.js")]).then(([m, P]) => { graphMod = m; postureMod = P; cb(m); }).catch(() => cb(null));
  }
  function renderInvest(){
    const el = sceneEls.invest;
    el.innerHTML = `
      <div class="dk-ovhead"><div><h1>Investigations &amp; Graph</h1><p>Your security graph, cases and entity intelligence — built up as you work across the tools.</p></div>
        <div class="when"><button class="dk-tibtn" id="dkInvExport">${IC.copy} Export graph</button></div></div>
      <div class="dk-kpis" id="dkInvKpis"><div class="dk-loading"><span class="sp"></span>Reading the security graph…</div></div>
      <div class="dk-invdash" id="dkInvDash"></div>
      <div class="dk-ovp">
        <h2>${IC.folder} Entities <span class="mo" data-tool="secgraph">Open graph</span></h2>
        <div class="dk-invbar">
          <div class="dk-isearch">${IC_SEARCH}<input id="dkInvQ" placeholder="Search entities…" value="${esc(invF.q)}" autocomplete="off" spellcheck="false"></div>
          <select id="dkInvType" class="dk-isel"></select>
          <select id="dkInvSev" class="dk-isel"></select>
          <select id="dkInvStatus" class="dk-isel"></select>
          <label class="dk-invsim" data-explain="inv.sim"><input type="checkbox" id="dkInvSim"${invF.sim ? " checked" : ""}> Include simulated / sample</label>
        </div>
        <div class="dk-invsimnote" id="dkInvSimNote" hidden></div>
        <div id="dkInvTable"></div>
      </div>
      <div class="dk-qa" style="max-width:760px;margin-top:4px">
        <button class="dk-qacard" data-tool="investigation"><span class="qi" style="--a:#9b5cf0">${IC.folder}</span><b>Open Investigation Workspace</b><span>Build and track a full investigation.</span></button>
        <button class="dk-qacard" data-tool="secgraph"><span class="qi" style="--a:#4f86ff">${IC.grid}</span><b>Open Security Graph</b><span>Visualise entities and their links.</span></button>
        <button class="dk-qacard" data-tool="casemgmt"><span class="qi" style="--a:#f5920b">${IC.folder}</span><b>Case Manager</b><span>Track cases and their status.</span></button>
      </div>`;
    el.querySelectorAll(".dk-qacard[data-tool]").forEach((b) => b.onclick = () => openTool(b.dataset.tool, secLabel[b.dataset.tool] || b.dataset.tool));
    el.querySelector("#dkInvExport").onclick = () => withGraph((m) => {
      if (!m || !m.exportAll) { toast("Graph unavailable"); return; }
      const data = m.exportAll(), n = (data.entities || []).length;
      if (!n) { toast("Graph is empty"); return; }
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
      a.download = "darknode-graph.json"; a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 2000);
      toast(n + " entities exported");
    });
    withGraph((m) => paintInv(m));
  }
  function paintInv(m){
    const kpisEl = root.querySelector("#dkInvKpis"); if (!kpisEl) return;
    if (!m || !m.getStats || !m.exportAll || !postureMod) { kpisEl.innerHTML = `<div class="dk-nempty" style="grid-column:1/-1">Security graph unavailable in this context.</div>`; return; }
    // Real data by default; simulated/sample entities (CRUCIBLE, demos) only on request.
    const g = m.exportAll(), ps = postureMod.postureStats(g.entities, g.relationships);
    const st = invF.sim ? m.getStats() : ps;
    const simNote = root.querySelector("#dkInvSimNote");
    if (simNote) { simNote.hidden = !ps.simulated; simNote.textContent = invF.sim ? `Showing ${ps.simulated.toLocaleString()} simulated/sample entities alongside real data. They never count toward posture scores.` : `${ps.simulated.toLocaleString()} simulated/sample entities (CRUCIBLE, demos) are hidden. Tick "Include simulated / sample" to see them.`; }
    const kpi = (val, lab, accent) => `<div class="dk-kpi" style="--a:${accent};cursor:default"><div class="kn">${(val || 0).toLocaleString()}</div><div class="kl">${esc(lab)}</div></div>`;
    kpisEl.innerHTML = kpi(st.totalEntities, "Entities", "#9b5cf0") + kpi(st.totalRelationships, "Relationships", "#4f86ff") + kpi((st.byType || {}).CASE, "Cases", "#f5920b") + kpi((st.byType || {}).INCIDENT, "Incidents", "#f0484a");
    const sevOrder = ["critical", "high", "medium", "low", "info", "none"];
    const statusOrder = ["new", "open", "investigating", "resolved", "closed", "none"];
    const sevColor = (k) => k === "none" ? "#9aa4ba" : (m.getSeverityColor ? m.getSeverityColor(k) : "#6a7488");
    const stColor = (k) => k === "none" ? "#9aa4ba" : (m.getStatusColor ? m.getStatusColor(k) : "#6a7488");
    const bar = (title, obj, order, colorFn, labelFn) => {
      const total = Object.values(obj || {}).reduce((a, b) => a + b, 0);
      if (!total) return "";
      const keys = order.filter((k) => (obj || {})[k]);
      const segs = keys.map((k) => `<span style="width:${((obj[k] / total) * 100).toFixed(1)}%;--bg:${colorFn(k)}" title="${esc(labelFn(k))}: ${obj[k]}"></span>`).join("");
      const legend = keys.map((k) => `<span class="lg"><i style="--bg:${colorFn(k)}"></i>${esc(labelFn(k))} ${obj[k]}</span>`).join("");
      return `<div class="dk-invb"><div class="t">${esc(title)}</div><div class="track">${segs}</div><div class="leg">${legend}</div></div>`;
    };
    const typeTop = Object.entries(st.byType || {}).sort((a, b) => b[1] - a[1]).slice(0, 8);
    const typeHTML = typeTop.length ? `<div class="dk-invb"><div class="t">Top entity types</div><div class="dk-invtypes2">${typeTop.map(([t, n]) => `<div class="it"><b>${n}</b><span>${esc(m.getEntityTypeLabel ? m.getEntityTypeLabel(t) : t)}</span></div>`).join("")}</div></div>` : "";
    root.querySelector("#dkInvDash").innerHTML = bar("By severity", st.bySeverity, sevOrder, sevColor, (k) => k === "none" ? "Unrated" : capword(k)) + bar("By status", st.byStatus, statusOrder, stColor, (k) => k === "none" ? "No status" : capword(k)) + typeHTML;
    const typeSel = root.querySelector("#dkInvType");
    typeSel.innerHTML = `<option value="">All types</option>` + Object.keys(st.byType || {}).sort().map((t) => `<option value="${esc(t)}"${invF.type === t ? " selected" : ""}>${esc(m.getEntityTypeLabel ? m.getEntityTypeLabel(t) : t)}</option>`).join("");
    const sevSel = root.querySelector("#dkInvSev");
    sevSel.innerHTML = `<option value="">All severities</option>` + sevOrder.filter((k) => k !== "none" && (st.bySeverity || {})[k]).map((k) => `<option value="${k}"${invF.sev === k ? " selected" : ""}>${capword(k)}</option>`).join("");
    const statSel = root.querySelector("#dkInvStatus");
    statSel.innerHTML = `<option value="">All statuses</option>` + statusOrder.filter((k) => k !== "none" && (st.byStatus || {})[k]).map((k) => `<option value="${k}"${invF.status === k ? " selected" : ""}>${capword(k)}</option>`).join("");
    const q = root.querySelector("#dkInvQ");
    q.oninput = () => { invF.q = q.value; paintInvTable(m); };
    typeSel.onchange = () => { invF.type = typeSel.value; paintInvTable(m); };
    sevSel.onchange = () => { invF.sev = sevSel.value; paintInvTable(m); };
    statSel.onchange = () => { invF.status = statSel.value; paintInvTable(m); };
    const simBox = root.querySelector("#dkInvSim");
    if (simBox) simBox.onchange = () => { invF.sim = simBox.checked; paintInv(m); };
    paintInvTable(m);
  }
  function paintInvTable(m){
    const box = root.querySelector("#dkInvTable"); if (!box || !m || !m.listEntities) return;
    const filter = {};
    if (invF.type) filter.type = invF.type;
    if (invF.sev) filter.severity = invF.sev;
    if (invF.status) filter.status = invF.status;
    if (invF.q.trim()) filter.search = invF.q.trim();
    const isSim = postureMod ? postureMod.isSimulated : () => false;
    const rows = m.listEntities(filter).filter((e) => invF.sim || !isSim(e)).slice(0, 60);
    if (!rows.length) {
      const total = invF.sim ? m.getStats().totalEntities : postureMod.realEntities(m.exportAll().entities).length;
      box.innerHTML = `<div class="dk-nempty">${total ? "No entities match the filter." : "The graph is empty. As recon, intel and forensic tools run, the entities they find collect here."}</div>`;
      return;
    }
    const sevColor = (k) => k ? (m.getSeverityColor ? m.getSeverityColor(k) : "#6a7488") : "#9aa4ba";
    const stColor = (k) => k ? (m.getStatusColor ? m.getStatusColor(k) : "#6a7488") : "#9aa4ba";
    box.innerHTML = `<div class="dk-itwrap"><table class="dk-itable"><thead><tr><th>Name</th><th>Type</th><th>Severity</th><th>Status</th><th>Links</th><th>Updated</th></tr></thead><tbody>${rows.map((e) => {
      const rel = m.getRelationships ? m.getRelationships(e.id).length : 0;
      const up = e.updatedAt ? timeAgo(new Date(e.updatedAt).getTime()) : "—";
      return `<tr data-eid="${esc(e.id)}"><td class="nm">${esc(e.name || "—")}${isSim(e) ? ` <span class="pill" style="--c:#8a93a6">Sample</span>` : ""}</td><td>${esc(m.getEntityTypeLabel ? m.getEntityTypeLabel(e.type) : e.type)}</td><td>${e.severity ? `<span class="pill" style="--c:${sevColor(e.severity)}">${capword(e.severity)}</span>` : "—"}</td><td>${e.status ? `<span class="pill" style="--c:${stColor(e.status)}">${capword(e.status)}</span>` : "—"}</td><td class="num">${rel || "—"}</td><td class="ag">${up}</td></tr>`;
    }).join("")}</tbody></table></div>`;
    box.querySelectorAll("tr[data-eid]").forEach((tr) => tr.onclick = () => openTool("secgraph", secLabel["secgraph"] || "Security Graph"));
  }

  // ---------- Findings workspace: every real finding across tools, one triage queue ----------
  const fndF = { q: "", severity: "", status: "open", source: "", sim: false };
  const fndSel = new Set();
  let fndRows = [];
  const SEV_C = { critical: "#e0383a", high: "#f5920b", medium: "#d9a400", low: "#4f86ff", info: "#8a93a6" };
  const ST_C = { new: "#4f86ff", open: "#f5920b", investigating: "#9b5cf0", resolved: "#12a85f", closed: "#8a93a6" };
  const agoISO = (s) => s ? timeAgo(new Date(s).getTime()) : "—";
  function dl(name, text, type){
    const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([text], { type })); a.download = name;
    document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }
  const ONBOARD = `<div class="dk-onb"><b>No findings recorded yet</b><p>Findings appear here when a tool records them in the security graph. Start with one of these:</p><div class="dk-qa">
      <button class="dk-qacard" data-tool="codescan"><span class="qi" style="--a:#3f78ff">${IC.code}</span><b>Scan a codebase</b><span>Scan a GitHub repository, then choose Add to graph.</span></button>
      <button class="dk-qacard" data-scene="surface"><span class="qi" style="--a:#f0484a">${IC.radar}</span><b>Map your attack surface</b><span>Enter a domain and add what it finds to the graph.</span></button>
      <button class="dk-qacard" data-tool="cvesearch"><span class="qi" style="--a:#f5920b">${IC.alert}</span><b>Record a CVE you run</b><span>Look it up and send it to the graph to track the fix.</span></button>
    </div></div>`;
  function renderFindings(){
    const el = sceneEls.findings;
    el.innerHTML = `
      <div class="dk-ovhead"><div><h1>Findings</h1><p>Every finding and vulnerability your tools have recorded, in one queue. Select rows to change their status; sample data is excluded unless you include it.</p></div>
        <div class="when"><button class="dk-tibtn" id="dkFndCsv">${IC.copy} Export CSV</button> <button class="dk-tibtn" id="dkFndJson">${IC.copy} Export JSON</button></div></div>
      <div class="dk-kpis" id="dkFndKpis"></div>
      <div class="dk-ovp">
        <h2 data-explain="panel.findings">${IC.alert} Finding queue <span class="mo" data-tool="secgraph">Open graph</span></h2>
        <div class="dk-invbar">
          <div class="dk-isearch">${IC_SEARCH}<input id="dkFndQ" placeholder="Search findings" value="${esc(fndF.q)}" autocomplete="off" spellcheck="false"></div>
          <select id="dkFndSev" class="dk-isel" aria-label="Severity"></select>
          <select id="dkFndStatus" class="dk-isel" aria-label="Status"></select>
          <select id="dkFndSrc" class="dk-isel" aria-label="Source"></select>
          <label class="dk-invsim" data-explain="inv.sim"><input type="checkbox" id="dkFndSim"${fndF.sim ? " checked" : ""}> Include simulated / sample</label>
        </div>
        <div class="dk-fndbulk" id="dkFndBulk" hidden></div>
        <div id="dkFndTable"><div class="dk-loading"><span class="sp"></span>Reading the security graph…</div></div>
      </div>`;
    const q = el.querySelector("#dkFndQ"); let qT = 0;
    q.oninput = () => { clearTimeout(qT); qT = setTimeout(() => { fndF.q = q.value; withGraph(paintFindings); }, 150); };
    el.querySelector("#dkFndSev").onchange = (e) => { fndF.severity = e.target.value; withGraph(paintFindings); };
    el.querySelector("#dkFndStatus").onchange = (e) => { fndF.status = e.target.value; withGraph(paintFindings); };
    el.querySelector("#dkFndSrc").onchange = (e) => { fndF.source = e.target.value; withGraph(paintFindings); };
    el.querySelector("#dkFndSim").onchange = (e) => { fndF.sim = e.target.checked; withGraph(paintFindings); };
    const stamp = new Date().toISOString().slice(0, 10);
    el.querySelector("#dkFndCsv").onclick = () => { if (!fndRows.length) return toast("No findings to export"); dl("darknode-findings-" + stamp + ".csv", findings.toCSV(fndRows), "text/csv"); };
    el.querySelector("#dkFndJson").onclick = () => { if (!fndRows.length) return toast("No findings to export"); dl("darknode-findings-" + stamp + ".json", JSON.stringify(fndRows, null, 2), "application/json"); };
    withGraph(paintFindings);
  }
  function paintFindings(m){
    const el = sceneEls.findings, box = el.querySelector("#dkFndTable"); if (!box) return;
    const all = m && m.listEntities ? findings.collectFindings(m.listEntities(), { includeSim: fndF.sim }) : [];
    const c = findings.findingCounts(all.filter((r) => !r.sim));
    el.querySelector("#dkFndKpis").innerHTML = [[c.critical, "Open critical", SEV_C.critical, "fnd.critical"], [c.high, "Open high", SEV_C.high, "fnd.high"], [c.open, "Open findings", "#4f86ff", "fnd.open"], [c.resolved, "Resolved or closed", "#12a85f", "fnd.resolved"]]
      .map(([v, l, a, x]) => `<div class="dk-kpi" data-explain="${x}" style="--a:${a};cursor:default"><div class="kn">${v.toLocaleString()}</div><div class="kl">${esc(l)}</div></div>`).join("");
    const opt = (v, l, cur) => `<option value="${esc(v)}"${v === cur ? " selected" : ""}>${esc(l)}</option>`;
    el.querySelector("#dkFndSev").innerHTML = opt("", "All severities", fndF.severity) + ["critical", "high", "medium", "low", "info"].map((s) => opt(s, capword(s), fndF.severity)).join("");
    el.querySelector("#dkFndStatus").innerHTML = opt("", "Any status", fndF.status) + opt("open", "Open", fndF.status) + ["new", "investigating", "resolved", "closed"].map((s) => opt(s, capword(s), fndF.status)).join("");
    const srcs = [...new Set(all.map((r) => r.source))].sort();
    if (fndF.source && !srcs.includes(fndF.source)) fndF.source = "";
    el.querySelector("#dkFndSrc").innerHTML = opt("", "All sources", fndF.source) + srcs.map((s) => opt(s, s, fndF.source)).join("");
    fndRows = findings.filterFindings(all, fndF);
    for (const id of [...fndSel]) if (!fndRows.some((r) => r.id === id)) fndSel.delete(id);
    paintBulk(m);
    if (!all.length) { box.innerHTML = ONBOARD; box.querySelectorAll(".dk-qacard[data-tool]").forEach((b) => b.onclick = () => openTool(b.dataset.tool, secLabel[b.dataset.tool] || b.querySelector("b").textContent)); return; }
    if (!fndRows.length) { box.innerHTML = `<div class="dk-nempty">No findings match these filters.</div>`; return; }
    const shown = fndRows.slice(0, 500);
    box.innerHTML = `<div class="dk-itwrap"><table class="dk-itable dk-fndt"><thead><tr><th class="ck"><input type="checkbox" id="dkFndAll" aria-label="Select all shown"></th><th>Severity</th><th>Finding</th><th>Type</th><th>Source</th><th>Status</th><th>First seen</th><th>Updated</th></tr></thead><tbody>${shown.map((r) =>
      `<tr data-eid="${esc(r.id)}"><td class="ck"><input type="checkbox" data-sel="${esc(r.id)}"${fndSel.has(r.id) ? " checked" : ""} aria-label="Select finding"></td><td>${r.severity ? `<span class="pill" style="--c:${SEV_C[r.severity] || "#8a93a6"}">${capword(r.severity)}</span>` : "—"}</td><td class="nm">${esc(r.name)}${r.sim ? ' <span class="dk-simchip">Sample</span>' : ""}</td><td>${r.type === "VULNERABILITY" ? "Vulnerability" : "Finding"}</td><td>${esc(r.source)}</td><td><span class="pill" style="--c:${ST_C[r.status] || "#8a93a6"}">${capword(r.status)}</span></td><td class="ag">${agoISO(r.createdAt)}</td><td class="ag">${agoISO(r.updatedAt)}</td></tr>`).join("")}</tbody></table></div>${fndRows.length > shown.length ? `<div class="dk-nempty">Showing ${shown.length} of ${fndRows.length.toLocaleString()}. Narrow the filters, or export to get them all.</div>` : ""}`;
    const all1 = box.querySelector("#dkFndAll");
    all1.checked = shown.every((r) => fndSel.has(r.id));
    all1.onchange = () => { shown.forEach((r) => all1.checked ? fndSel.add(r.id) : fndSel.delete(r.id)); box.querySelectorAll("[data-sel]").forEach((x) => x.checked = all1.checked); paintBulk(m); };
    box.querySelectorAll("[data-sel]").forEach((x) => x.onchange = () => { x.checked ? fndSel.add(x.dataset.sel) : fndSel.delete(x.dataset.sel); paintBulk(m); });
    box.querySelectorAll("tr[data-eid] td.nm").forEach((td) => td.onclick = () => openTool("secgraph", secLabel["secgraph"] || "Security Graph"));
  }
  function paintBulk(m){
    const bar = sceneEls.findings.querySelector("#dkFndBulk"); if (!bar) return;
    bar.hidden = !fndSel.size; if (!fndSel.size) return;
    bar.innerHTML = `<b>${fndSel.size} selected</b><span>Set status:</span>${["open", "investigating", "resolved", "closed"].map((s) => `<button class="dk-tibtn" data-st="${s}">${capword(s)}</button>`).join("")}<button class="dk-tibtn" data-st="">Clear selection</button>`;
    bar.querySelectorAll("[data-st]").forEach((b) => b.onclick = () => {
      const st = b.dataset.st;
      if (st && m && m.updateEntity) { const ids = [...fndSel]; m.batch(() => ids.forEach((id) => m.updateEntity(id, { status: st }))); toast(ids.length + " finding" + (ids.length === 1 ? "" : "s") + " set to " + st); }
      fndSel.clear(); withGraph(paintFindings);
    });
  }

  // ---------- Section overview pages (one per sidebar group) ----------
  // What each section covers in the graph, and which integrations feed it. Coverage is
  // shown honestly: unconnected sources are listed greyed out with a Connect action.
  const SECTIONS = {
    exposure: { title: "Exposure", blurb: "What attackers can see and reach: your external footprint, cloud configuration and the vulnerabilities that matter this week.", types: ["ASSET", "DOMAIN", "IP", "PORT", "SERVICE", "CERTIFICATE", "ENDPOINT"], match: /attack surface|vanguard|subdomain|dns|ssl|http|exposure|posture|scorecard|certificate monitor|tls/i, ints: ["shodan", "censys", "securitytrails", "zoomeye", "binaryedge", "netlas", "fullhunt", "ipinfo", "hibp"], pub: "Certificate transparency (crt.sh), public DNS, RDAP registries and BGP routing data for Attack Surface; NVD, CISA KEV and FIRST EPSS for Threats & Vulnerabilities." },
    code: { title: "Application Security", blurb: "Secrets, risky code and vulnerable dependencies in the software you build, and the attack paths they open.", types: ["SOFTWARE"], match: /code scanner|supply|threatforest|attack tree|\bcode\b/i, ints: [], pub: "The GitHub API for repository contents and OSV.dev for dependency advisories, both used by the Code Scanner." },
    detect: { title: "Security Operations", blurb: "Alerts, indicators, incidents and cases: everything your tools have recorded, and the work to run it down.", types: ["ALERT", "INCIDENT", "CASE", "INVESTIGATION", "INDICATOR", "EVIDENCE", "THREAT_ACTOR", "MALWARE", "CAMPAIGN", "DETECTION", "EVENT", "FINDING", "VULNERABILITY"], ints: ["virustotal", "greynoise", "abuseipdb", "otx", "abusech", "urlscan", "pulsedive", "misp", "mitre", "hybrid", "anyrun", "intelx"] },
    finsec: { title: "Financial Controls", blurb: "Controls over money movement: fraud screening on your ledgers, payee bank-change control, sanctions screening, and a tamper-evident record of treasury approvals.", types: [], match: /strongroom|fund protection|vault|treasury|sanction|payee|vendor/i, ints: [] },
    identity: { title: "Identity", blurb: "Who can sign in and what they did. Sign-in log forensics for your identity provider, and the periodic access review that reconciles your directory against the HR roster.", types: [], match: /sign-in|signin|access review|identity|account|directory/i, ints: [] },
    compliance: { title: "Compliance", blurb: "Framework mappings, self-assessments and data-protection scanning. Self-reported findings reflect what you enter or paste, not an automated audit.", types: ["CONTROL", "REPORT"], match: /compliance|crosswalk|data protection|dlp/i, ints: [] },
  };
  let curSect = "exposure";
  try { const v = localStorage.getItem("dn_deck_sect"); if (v && SECTIONS[v]) curSect = v; } catch (_) {}
  function renderSection(){
    const id = curSect, S = SECTIONS[id], el = sceneEls.section;
    const grp = NAV_DEF.find((g) => g.id === id) || { items: [] };
    // Only key-based services can be "not connected"; free public feeds need no setup.
    const ints = S.ints.map((i) => INTEGRATIONS.find((x) => x.id === i)).filter((x) => x && x.connect !== "link");
    const live = ints.filter((i) => conns[i.id] && conns[i.id].connected);
    const cards = grp.items.map(([kind, tid, label, icon]) => {
      const ex = kind === "scene" ? EXPLAIN["scene." + tid] : (EXPLAIN["tool." + tid] || toolExplain(tid, label));
      return `<button class="dk-qacard" data-${kind}="${esc(tid)}"><span class="qi" style="--a:#2552c6">${icon}</span><b>${esc(label)}</b><span>${esc(ex ? ex.body : "")}</span></button>`;
    }).join("");
    const srcs = ints.length
      ? `<div class="dk-srcs">${ints.map((i) => { const c = live.includes(i); return `<div class="dk-src${c ? " on" : ""}"><span class="nm">${esc(i.name)}</span><span class="st">${c ? "Connected" : "Not connected"}</span>${c ? "" : `<button class="dk-tibtn" data-scene="con">Connect</button>`}</div>`; }).join("")}</div>`
      : S.pub ? "" : `<div class="dk-nempty">No external connections needed. These tools run on data you provide, in your browser.</div>`;
    const pubHTML = S.pub ? `<p class="dk-srcpub"><b>Public sources, no key needed:</b> ${esc(S.pub)}</p>` : "";
    el.innerHTML = `
      <div class="dk-ovhead"><div><h1>${esc(S.title)}</h1><p>${esc(S.blurb)}</p></div></div>
      <div class="dk-kpis" id="dkSectKpis"><div class="dk-loading"><span class="sp"></span>Reading the security graph…</div></div>
      <div class="dk-sectgrid">
        <div class="dk-ovp"><h2 data-explain="panel.sectools">${IC.grid} Tools in this section</h2><div class="dk-qa">${cards}</div></div>
        <div>
          <div class="dk-ovp"><h2 data-explain="panel.latest">${IC.pulse} Latest results</h2><div class="dk-ovact" id="dkSectLatest"></div></div>
          <div class="dk-ovp"><h2 data-explain="panel.sources">${IC.plug} Data sources <span class="mo" data-scene="con">Manage</span></h2>${srcs}${pubHTML}</div>
        </div>
      </div>`;
    el.querySelectorAll("button[data-tool]").forEach((b) => b.onclick = () => openTool(b.dataset.tool, secLabel[b.dataset.tool] || b.querySelector("b").textContent));
    withGraph((m) => {
      if (curScene !== "section" || curSect !== id) return;
      const ents = m && m.listEntities ? findings.sectionEntities(m.listEntities(), S).sort((a, b) => String(b.updatedAt || "").localeCompare(String(a.updatedAt || ""))) : [];
      const hot = ents.filter((e) => /^(critical|high)$/i.test(e.severity || "") && !/^(resolved|closed)$/i.test(e.status || "")).length;
      const kpiS = (v, l, a, x) => `<div class="dk-kpi" data-explain="${x}" style="--a:${a};cursor:default"><div class="kn">${v}</div><div class="kl">${esc(l)}</div></div>`;
      el.querySelector("#dkSectKpis").innerHTML = kpiS(ents.length.toLocaleString(), "Records", "#9b5cf0", "sect.records") + kpiS(hot.toLocaleString(), "Open critical / high", "#e0383a", "sect.hot")
        + kpiS(ints.length ? live.length + " / " + ints.length : S.pub ? "Public" : "Local", "Data sources connected", "#12a85f", "sect.sources") + kpiS(grp.items.length, "Tools", "#4f86ff", "sect.tools");
      const lat = el.querySelector("#dkSectLatest");
      const first = grp.items[0];
      lat.innerHTML = ents.length
        ? ents.slice(0, 8).map((e) => `<div class="r"><span class="dot" style="--bg:${SEV_C[String(e.severity || "").toLowerCase()] || "#9aa4ba"}"></span><span class="tx">${esc(e.name || "—")}</span><span class="ct">${esc(m.getEntityTypeLabel ? m.getEntityTypeLabel(e.type) : e.type)}</span><span class="ag">${agoISO(e.updatedAt)}</span></div>`).join("")
        : `<div class="dk-onb"><p>Nothing recorded in this section yet. Results appear here when its tools add them to the security graph.</p>${first ? `<button class="dk-tibtn on" data-${first[0]}="${esc(first[1])}">Start with ${esc(first[2])}</button>` : ""}</div>`;
      lat.querySelectorAll("button[data-tool]").forEach((b) => b.onclick = () => openTool(b.dataset.tool, secLabel[b.dataset.tool] || b.dataset.tool));
    });
  }

  // ---------- Overview "Top actions": ranked, real, each with a next step ----------
  function renderTopActions(){
    const box = sceneEls.overview.querySelector("#dkTopAct"); if (!box) return;
    Promise.allSettled([new Promise((r) => withGraph(r)), fetchIntel(30), fetchKev()]).then(([g, iv, kv]) => {
      if (!box.isConnected) return;
      const m = g.value;
      const acts = findings.topActions({
        findings: m && m.listEntities ? findings.collectFindings(m.listEntities(), { includeSim: true }) : [],
        cves: iv.status === "fulfilled" ? iv.value.cves : [],
        kev: kv.status === "fulfilled" ? kv.value.set : new Set(),
        connected: new Set(INTEGRATIONS.filter((x) => conns[x.id] && conns[x.id].connected).map((x) => x.id)),
        integrations: INTEGRATIONS,
        kevOnly: true,
      }).filter((a) => a.kind !== "start");
      const go1 = (a) => a.kind === "finding" ? `<button class="dk-tibtn" data-scene="findings">Triage</button>`
        : a.kind === "cve" ? `<button class="dk-tibtn" data-scene="threat">Review</button>`
        : a.kind === "connect" ? `<button class="dk-tibtn" data-scene="con">Connect</button>`
        : `<form class="dk-actform"><input placeholder="yourdomain.com" aria-label="Domain to map" autocomplete="off" spellcheck="false"><button class="dk-tibtn on" type="submit">Map surface</button><button class="dk-tibtn" type="button" data-tool="codescan">Scan code</button></form>`;
      const feedNote = iv.status === "rejected" && kv.status === "rejected" ? `<div class="dk-nempty">Live CVE feeds are unavailable right now, so this list uses your security graph only.</div>` : "";
      const SRC = { finding: "Your findings", cve: "Global feed", connect: "Setup" };
      box.innerHTML = (acts.length
        ? `<div class="dk-tscroll"><table class="dk-natbl"><thead><tr><th>Severity</th><th>Item</th><th>Source</th><th></th></tr></thead><tbody>${acts.map((a) => `<tr><td class="sv"><span class="dk-sev" style="--c:${SEV_C[a.sev] || "#8a93a6"}"><i></i>${esc(a.sev.charAt(0).toUpperCase() + a.sev.slice(1))}</span></td><td class="it"><b>${esc(a.title)}</b><span>${esc(a.detail)}</span></td><td class="so">${esc(SRC[a.kind] || "")}</td><td class="ac">${go1(a)}</td></tr>`).join("")}</tbody></table></div>`
        : `<div class="dk-nempty">Nothing urgent: no open critical or high findings and no known-exploited CVEs in this week's feed.</div>`) + feedNote;
      const f = box.querySelector(".dk-actform");
      if (f) {
        f.onsubmit = (e) => { e.preventDefault(); const d = f.querySelector("input").value.trim(); if (!d) return toast("Enter a domain you own, e.g. example.com"); go("surface"); renderSurface(d); };
        f.querySelector("[data-tool]").onclick = () => openTool("codescan", secLabel.codescan || "Code Scanner");
      }
    });
  }

  // ---------- Activity workspace ----------
  const ACT_CATS ={ tool: { label: "Tools", color: "#4f86ff" }, connection: { label: "Connections", color: "#12a85f" }, graph: { label: "Graph", color: "#9b5cf0" }, ai: { label: "AI", color: "#3f78ff" }, deck: { label: "Deck", color: "#f5920b" } };
  function activityCat(text){
    const t = (text || "").toLowerCase();
    if (/connect|provider|linked|api key|disconnect/.test(t)) return "connection";
    if (/graph|entit|relationship|\bcase\b|incident/.test(t)) return "graph";
    if (/assistant|prompt|\bchat\b|conversation|\bai\b/.test(t)) return "ai";
    if (/pin|note|export|import/.test(t)) return "deck";
    return "tool";
  }
  let actFilter = "", actQ = "";
  function renderActivity(){
    const el = sceneEls.activity;
    const all = notifs.map((x) => ({ text: x.text, ts: x.ts, cat: activityCat(x.text) }));
    const counts = {}; for (const a of all) counts[a.cat] = (counts[a.cat] || 0) + 1;
    const first = all.length ? all[all.length - 1].ts : null;
    const chips = Object.keys(ACT_CATS).filter((c) => counts[c]).map((c) => `<button class="dk-afch${actFilter === c ? " on" : ""}" data-cat="${c}"><i style="--bg:${ACT_CATS[c].color}"></i>${ACT_CATS[c].label}<span>${counts[c]}</span></button>`).join("");
    el.innerHTML = `
      <div class="dk-ovhead"><div><h1>Activity</h1><p>A live stream of platform events in this session — tool results, graph changes, connections and AI.</p></div>
        <div class="when"><button class="dk-tibtn" id="dkActExport">${IC.copy} Export log</button></div></div>
      <div class="dk-astats">
        <div class="dk-astat" style="--a:#4f86ff"><div class="n">${all.length}</div><div class="l">Events this session</div></div>
        <div class="dk-astat" style="--a:#12a85f"><div class="n">${Object.keys(counts).length}</div><div class="l">Categories</div></div>
        <div class="dk-astat" style="--a:#9b5cf0"><div class="n">${first ? timeAgo(first) : "—"}</div><div class="l">First event</div></div>
      </div>
      <div class="dk-afbar">
        <button class="dk-afch${actFilter === "" ? " on" : ""}" data-cat="">All<span>${all.length}</span></button>${chips}
        <div class="dk-isearch" style="margin-left:auto;max-width:280px"><input id="dkActQ" placeholder="Search events…" value="${esc(actQ)}" autocomplete="off" spellcheck="false"></div>
      </div>
      <div class="dk-ovp"><h2>${IC.pulse} Event stream</h2><div class="dk-ovact" id="dkActStream"></div></div>`;
    el.querySelectorAll(".dk-afch").forEach((b) => b.onclick = () => { actFilter = b.dataset.cat; el.querySelectorAll(".dk-afch").forEach((x) => x.classList.toggle("on", x === b)); paintActStream(); });
    const q = el.querySelector("#dkActQ"); q.oninput = () => { actQ = q.value; paintActStream(); };
    el.querySelector("#dkActExport").onclick = () => {
      if (!notifs.length) { toast("No events to export"); return; }
      const data = notifs.map((x) => ({ ts: new Date(x.ts).toISOString(), category: activityCat(x.text), text: x.text }));
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
      a.download = "darknode-activity.json"; a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 2000);
      toast(data.length + " events exported");
    };
    paintActStream();
  }
  function paintActStream(){
    const box = root.querySelector("#dkActStream"); if (!box) return;
    const ql = actQ.trim().toLowerCase();
    const rows = notifs.map((x) => ({ text: x.text, ts: x.ts, sim: x.sim, cat: activityCat(x.text) }))
      .filter((a) => (!actFilter || a.cat === actFilter) && (!ql || a.text.toLowerCase().includes(ql)));
    box.innerHTML = rows.length
      ? rows.map((a) => `<div class="r"><span class="dot" style="--bg:${(ACT_CATS[a.cat] || {}).color || "#4f86ff"}"></span><span class="tx">${esc(a.text)}${a.sim ? ' <span class="dk-simchip">Sample</span>' : ""}</span><span class="ct" style="--fg:${(ACT_CATS[a.cat] || {}).color || "#6a7488"}">${esc((ACT_CATS[a.cat] || {}).label || a.cat)}</span><span class="ag">${timeAgo(a.ts)}</span></div>`).join("")
      : `<div class="dk-nempty">${notifs.length ? "No events match the filter." : "No activity recorded yet in this browser. As you run tools, add graph entities or connect providers, events stream in here live."}</div>`;
  }

  // ---------- Toolkit workspace (instant client-side utilities) ----------
  let kitBuilt = false, kitSel = null;
  try { kitSel = localStorage.getItem("dn_deck_kit"); } catch (_) {}
  if (!TOOLKIT.some((t) => t.id === kitSel)) kitSel = TOOLKIT[0].id;
  function renderToolkit(){
    const el = sceneEls.toolkit;
    if (kitBuilt) return;
    kitBuilt = true;
    el.innerHTML = `
      <div class="dk-kitnav">
        <label class="dk-tsearch dk-kitsearch">${IC_SEARCH}<input id="dkKitSearch" type="search" placeholder="Search ${TOOLKIT.length} utilities…" autocomplete="off" spellcheck="false"></label>
        <div id="dkKitList" class="dk-kitlist"></div>
      </div>
      <div class="dk-kitmain" id="dkKitMain"></div>`;
    const search = el.querySelector("#dkKitSearch");
    search.oninput = () => buildKitList(search.value.trim().toLowerCase());
    buildKitList("");
    selectKit(kitSel);
  }
  function buildKitList(q){
    const box = root.querySelector("#dkKitList"); if (!box) return;
    const html = TK_CATS.map((cat) => {
      const tools = TOOLKIT.filter((t) => t.cat === cat.id && (!q || (t.name + " " + t.desc).toLowerCase().includes(q)));
      if (!tools.length) return "";
      return `<div class="dk-kitcat"><div class="kc-h" style="--fg:${cat.color}"><span class="kc-d"></span>${esc(cat.name)}</div>` +
        tools.map((t) => `<button class="dk-kititem${t.id === kitSel ? " on" : ""}" data-tk="${t.id}">${esc(t.name)}</button>`).join("") + `</div>`;
    }).join("");
    box.innerHTML = html || `<div class="dk-nempty">No utilities match "${esc(q)}".</div>`;
    box.querySelectorAll(".dk-kititem").forEach((b) => b.onclick = () => selectKit(b.dataset.tk));
  }
  function selectKit(id){
    const t = TOOLKIT.find((x) => x.id === id); if (!t) return;
    kitSel = id; try { localStorage.setItem("dn_deck_kit", id); } catch (_) {}
    root.querySelectorAll(".dk-kititem").forEach((b) => b.classList.toggle("on", b.dataset.tk === id));
    const main = root.querySelector("#dkKitMain"); if (!main) return;
    const cat = TK_CATS.find((c) => c.id === t.cat) || {};
    const optsHTML = (t.opts || []).map((o) => o.type === "select"
      ? `<label class="dk-kopt">${esc(o.label)}<select data-opt="${o.id}">${o.options.map(([v, l]) => `<option value="${esc(v)}">${esc(l)}</option>`).join("")}</select></label>` : "").join("");
    main.innerHTML = `
      <div class="dk-kithead"><div class="ki" style="--a:${cat.color || "#4f86ff"}">${IC.bolt}</div><div><h2>${esc(t.name)}</h2><p>${esc(t.desc)}</p></div></div>
      <div class="dk-kopts">${optsHTML}</div>
      ${t.generate ? `<button class="dk-b pri" id="dkKitGen" style="width:auto;align-self:flex-start">${IC.bolt}Generate</button>`
        : `<div class="dk-kiofield"><label class="dk-klbl">Input</label><textarea id="dkKitIn" class="dk-kitio" placeholder="Paste or type here…" spellcheck="false"></textarea></div>`}
      <div class="dk-kiofield"><div class="dk-kobar"><label class="dk-klbl">Output</label><span class="dk-kcopy" id="dkKitCopy">Copy</span>${t.generate ? "" : `<span class="dk-kcopy" id="dkKitSwap">Use as input</span>`}<span class="dk-kcopy" id="dkKitClear">Clear</span></div><pre id="dkKitOut" class="dk-kitio dk-kitout" aria-live="polite"></pre></div>`;
    const inEl = main.querySelector("#dkKitIn"), outEl = main.querySelector("#dkKitOut");
    const getOpts = () => { const o = {}; main.querySelectorAll("[data-opt]").forEach((s) => o[s.dataset.opt] = s.value); return o; };
    let rt = 0;
    const runNow = async () => {
      outEl.classList.remove("err");
      try {
        let res = t.run(inEl ? inEl.value : "", getOpts());
        if (res && typeof res.then === "function") res = await res;
        outEl.textContent = res;
      } catch (e) { outEl.classList.add("err"); outEl.textContent = "Error: " + ((e && e.message) || e); }
    };
    const schedule = () => { clearTimeout(rt); rt = setTimeout(runNow, t.async ? 200 : 60); };
    if (inEl) inEl.oninput = schedule;
    main.querySelectorAll("[data-opt]").forEach((s) => s.onchange = runNow);
    const gen = main.querySelector("#dkKitGen"); if (gen) gen.onclick = runNow;
    main.querySelector("#dkKitCopy").onclick = async () => { try { await navigator.clipboard.writeText(outEl.textContent); toast("Copied to clipboard"); } catch (_) { toast("Copy failed"); } };
    const clr = main.querySelector("#dkKitClear"); if (clr) clr.onclick = () => { if (inEl) inEl.value = ""; outEl.textContent = ""; outEl.classList.remove("err"); if (inEl) inEl.focus(); };
    const sw = main.querySelector("#dkKitSwap"); if (sw) sw.onclick = () => { if (inEl && outEl.textContent && !outEl.classList.contains("err")) { inEl.value = outEl.textContent; runNow(); } };
    if (t.generate) runNow();
    else if (inEl) setTimeout(() => { try { inEl.focus(); } catch (_) {} }, 30);
  }

  // ---------- Assistant workspace (embedded Darknode AI) ----------
  const asstFrame = $("#dkAsstFrame");
  let asstLoaded = false;
  function openAssistant(){
    if (asstLoaded) return;
    asstLoaded = true;
    asstFrame.innerHTML = '<div class="dk-wload"><div><div class="sp"></div>Loading Darknode AI…</div></div>';
    const f = document.createElement("iframe");
    f.title = "Darknode AI"; f.src = "/ai?embed=1&ink=1"; f.loading = "eager"; f.setAttribute("allow", "clipboard-write; clipboard-read");
    f.onload = () => { f.classList.add("in"); const l = asstFrame.querySelector(".dk-wload"); if (l) setTimeout(() => l.remove(), 180); };
    asstFrame.appendChild(f);
  }
  $("#dkAsstFull").onclick = () => { if (primary) { window.open("/ai", "_blank", "noopener"); return; } teardown(); onOpen("ai"); };
  // Prefill the embedded assistant with a question and open it. webai.js reads
  // sw_ai_prefill on load, so we reload the iframe to deliver a fresh prompt.
  function askAI(text){
    text = String(text || "").trim();
    if (text) { try { sessionStorage.setItem("sw_ai_prefill", text); } catch (_) {} asstLoaded = false; asstFrame.innerHTML = ""; }
    go("assistant");
  }

  // ---------- keyboard & shortcuts ----------
  // Vim-style navigation: press "g" then a scene key. "?" opens the cheatsheet.
  const GOTO = { o: "overview", e: "surface", i: "threat", l: "cloud", m: "compliance", n: "invest", c: "con", t: "tools", k: "toolkit", a: "activity", s: "assistant" };
  const SCENE_TITLE = { overview: "Security Overview", surface: "Attack Surface", threat: "Threats & Vulnerabilities", cloud: "Cloud Posture", compliance: "Frameworks", invest: "Investigations", findings: "Findings", section: "Section overview", con: "Integrations", tools: "Tool Library", toolkit: "Toolkit", activity: "Activity", assistant: "AI Assistant" };
  const keysEl = $("#dkKeys");
  function buildKeysOverlay(){
    const nav = Object.entries(GOTO).map(([k, sc]) => `<div class="dk-keyrow"><span>Go to ${esc(SCENE_TITLE[sc] || sc)}</span><span class="kb"><kbd>g</kbd><kbd>${esc(k)}</kbd></span></div>`).join("");
    keysEl.innerHTML = `<div class="dk-keysbox">
      <h3>Keyboard shortcuts</h3><div class="sub">The deck is fully keyboard-drivable. Press Esc to close.</div>
      <div class="dk-keysgrp">Global</div>
      <div class="dk-keyrow"><span>Command palette (tools, services, actions)</span><span class="kb"><kbd>Ctrl</kbd><kbd>K</kbd></span></div>
      <div class="dk-keyrow"><span>Quick search</span><span class="kb"><kbd>/</kbd></span></div>
      <div class="dk-keyrow"><span>This cheatsheet</span><span class="kb"><kbd>?</kbd></span></div>
      <div class="dk-keyrow"><span>Close / back / exit</span><span class="kb"><kbd>Esc</kbd></span></div>
      <div class="dk-keysgrp">Jump to workspace</div>${nav}</div>`;
  }
  const toggleKeys = (show) => { if (show && !keysEl.innerHTML) buildKeysOverlay(); keysEl.classList.toggle("on", show); };
  keysEl.addEventListener("click", (e) => { if (e.target === keysEl) toggleKeys(false); });
  const inTyping = (e) => { const t = e.target, n = t && t.tagName; return n === "INPUT" || n === "TEXTAREA" || n === "SELECT" || (t && t.isContentEditable); };
  let gPending = 0, gTimer = 0;
  function onKey(e){
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); spot.classList.contains("on") ? closeSpot() : openSpot(); return; }
    if (spot.classList.contains("on")) {
      if (e.key === "Escape") { e.preventDefault(); closeSpot(); }
      else if (e.key === "ArrowDown") { e.preventDefault(); moveSel(1); }
      else if (e.key === "ArrowUp") { e.preventDefault(); moveSel(-1); }
      else if (e.key === "Enter") { e.preventDefault(); chooseSpot(selIdx); }
      return;
    }
    if (keysEl.classList.contains("on")) { if (e.key === "Escape") { e.preventDefault(); toggleKeys(false); } return; }
    if (e.key === "Escape") {
      if (popNew.classList.contains("on") || popBell.classList.contains("on") || popAcct.classList.contains("on")) { closeAllMenus(); return; }
      if (!sceneWork.hidden) { closeTool(); return; }
      if (drawer.classList.contains("on")) { drawer.classList.remove("on"); return; }
      if (curScene !== "overview") { go("overview"); return; }
      if (!primary) exitDeck(); return;
    }
    if (e.ctrlKey || e.metaKey || e.altKey || inTyping(e)) return;   // don't hijack typing or combos
    if (e.key === "?") { e.preventDefault(); toggleKeys(true); return; }
    if (e.key === "/") { e.preventDefault(); openSpot(); return; }
    if (gPending) {
      gPending = 0; clearTimeout(gTimer);
      const sc = GOTO[e.key.toLowerCase()];
      if (sc) { e.preventDefault(); if (!sceneWork.hidden) closeTool(); go(sc); }
      return;
    }
    if (e.key.toLowerCase() === "g") { gPending = 1; clearTimeout(gTimer); gTimer = setTimeout(() => gPending = 0, 900); }
  }
  document.addEventListener("keydown", onKey);

  // ---------- resize ----------
  const onResize = () => { sizeStars(); applyNav(); try { closeAllMenus(); } catch (_) {} };
  window.addEventListener("resize", onResize);

  // ---------- shell: grouped left navigation + breadcrumb ----------
  // Job-named groups (how security teams think about the work), each entry an existing
  // scene or an in-deck tool. The sidebar is 248px, a 64px icon rail (auto below 1056px or
  // by choice, remembered), and an off-canvas drawer on phones.
  const LS_NAV = "dn_deck_nav";
  const NAV_DEF = [
    { g: "", items: [["scene", "overview", "Security Overview", IC.home]] },
    { id: "exposure", g: "Exposure", items: [["scene", "surface", "Attack Surface", IC.radar], ["scene", "cloud", "Cloud Posture", IC.cloud], ["scene", "threat", "Threats & Vulnerabilities", IC.alert], ["tool", "posture", "Posture Scorecard", IC.gauge], ["tool", "tlsfleet", "Certificate Monitor", IC.cert], ["tool", "fwaudit", "Firewall Rule Audit", IC.shield]] },
    { id: "identity", g: "Identity", items: [["tool", "signins", "Sign-in Forensics", IC.search], ["tool", "accessreview", "Access Review", IC.check]] },
    { id: "code", g: "Application Security", items: [["tool", "codescan", "Code Scanner", IC.code], ["tool", "supplychain", "Supply Chain", IC.branch], ["tool", "threatforest", "Attack Tree Builder", IC.tree]] },
    { id: "detect", g: "Security Operations", items: [["scene", "findings", "Findings", IC.alert], ["scene", "invest", "Investigations", IC.search], ["tool", "secgraph", "Security Graph", IC.nodes], ["tool", "incidents", "Incident Tracker", IC.shield], ["tool", "casemgmt", "Case Manager", IC.brief], ["tool", "phishtriage", "Phishing & URL Triage", IC.hook], ["tool", "loghunt", "Log Threat Hunter", IC.term], ["scene", "activity", "Activity", IC.pulse]] },
    { id: "finsec", g: "Financial Controls", items: [["tool", "strongroom", "Fund Protection", IC.coins], ["tool", "vault", "Treasury Vault", IC.lock], ["tool", "payees", "Payee Control", IC.shield], ["tool", "sanctions", "Sanctions Screening", IC.scale]] },
    { id: "compliance", g: "Compliance", items: [["scene", "compliance", "Frameworks", IC.check], ["tool", "crosswalk", "GenAI Crosswalk", IC.map], ["tool", "dlp", "Data Protection", IC.eye], ["tool", "leakprobe", "Secret Exposure", IC.key]] },
    { g: "Platform", items: [["scene", "con", "Integrations", IC.plug], ["scene", "tools", "Tool Library", IC.grid], ["scene", "toolkit", "Toolkit", IC.wrench], ["scene", "assistant", "AI Assistant", IC.spark], ["tool", "settings", "Settings", IC.gear]].concat(opts.isOwner ? [["tool", "admin", "Admin", IC.key]] : []) },
  ];
  const navIndex = {};
  NAV_DEF.forEach((grp) => { if (grp.id) navIndex["section:" + grp.id] = { group: grp.g, label: "Overview" }; grp.items.forEach(([kind, id, label]) => { navIndex[kind + ":" + id] = { group: grp.g || "Home", label }; }); });
  let navKey = "scene:overview", navLabel = "";
  function navBtn(kind, id, label, icon, extra){
    return `<button class="dk-nv${navKey === kind + ":" + id ? " on" : ""}" data-${kind}="${esc(id)}" data-l="${esc(label)}"${navKey === kind + ":" + id ? ' aria-current="page"' : ""}>${icon}<span class="nl">${esc(label)}</span>${extra || ""}</button>`;
  }
  function buildSideNav(){
    const nav = $("#dkSbNav"); if (!nav) return;
    // Index layout: each group is a numbered chapter (01, 02 ...) whose items hang off a guide line.
    let no = 0;
    const chap = (n) => `<span class="no">${n}</span>`;
    let html = NAV_DEF.map((grp) => {
      const items = grp.items.map(([kind, id, label, icon]) => navBtn(kind, id, label, icon, id === "tools" ? `<span class="nc">${TOTAL_TOOLS.toLocaleString()}</span>` : "")).join("");
      if (!grp.g) return `<div class="dk-nvg dk-nvg0">${items}</div>`;
      const n = String(++no).padStart(2, "0");
      const head = SECTIONS[grp.id] ? `<button class="dk-nvh dk-nvhb${navKey === "section:" + grp.id ? " on" : ""}" data-scene="section" data-sect="${grp.id}" data-explain="nav.section">${chap(n)}<span class="gt">${esc(grp.g)}</span><span class="ov">Overview</span></button>` : `<div class="dk-nvh">${chap(n)}<span class="gt">${esc(grp.g)}</span></div>`;
      return `<div class="dk-nvg">${head}<div class="dk-nvi">${items}</div></div>`;
    }).join("");
    const pinned = pins.filter((sec) => secLabel[sec]);
    if (pinned.length) html += `<div class="dk-nvg"><div class="dk-nvh">${chap("P")}<span class="gt">Pinned</span></div><div class="dk-nvi">${pinned.map((sec) => navBtn("tool", sec, secLabel[sec], toolIcon(secLabel[sec]))).join("")}</div></div>`;
    nav.innerHTML = html;
  }
  function setNav(key, label){
    navKey = key; navLabel = label || "";
    root.querySelectorAll("#dkSbNav .dk-nv").forEach((b) => {
      const on = (b.dataset.scene ? "scene:" + b.dataset.scene : "tool:" + b.dataset.tool) === key;
      b.classList.toggle("on", on); if (on) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current");
    });
    root.querySelectorAll("#dkSbNav .dk-nvhb").forEach((b) => b.classList.toggle("on", key === "section:" + b.dataset.sect));
    const meta = navIndex[key] || { group: key.indexOf("tool:") === 0 ? "Tools" : "Home", label: navLabel || key.split(":")[1] };
    const crumb = $("#dkCrumb");
    if (crumb) crumb.innerHTML = `<span class="cg">${esc(meta.group)}</span><span class="cs" aria-hidden="true">/</span><b>${esc(meta.label)}</b>`;
    if (root.classList.contains("nav-open")) root.classList.remove("nav-open");
  }
  // Effective CSS zoom of the Deck (it scales up on large screens): convert viewport
  // pixels from getBoundingClientRect() into the Deck's own CSS pixels.
  function zoomOf(){ const z = parseFloat(getComputedStyle(root).zoom); return z > 0 ? z : 1; }
  let navPref = "auto";
  try { navPref = localStorage.getItem(LS_NAV) || "auto"; } catch (_) {}
  try { root.classList.toggle("dense", localStorage.getItem("dn_deck_density") === "compact"); } catch (_) {}
  function applyNav(){
    const w = window.innerWidth, phone = w <= 720;
    const rail = !phone && (navPref === "rail" || (navPref === "auto" && w <= 1056));
    root.classList.toggle("nav-phone", phone);
    root.classList.toggle("nav-rail", rail);
    if (!phone) root.classList.remove("nav-open");
    const cb = $("#dkSbCollapse");
    if (cb) { cb.querySelector(".nl").textContent = rail ? "Expand" : "Collapse"; cb.dataset.l = rail ? "Expand navigation" : "Collapse navigation"; }
  }
  function toggleNav(){
    if (root.classList.contains("nav-phone")) { root.classList.toggle("nav-open"); return; }
    navPref = root.classList.contains("nav-rail") ? "full" : "rail";
    try { localStorage.setItem(LS_NAV, navPref); } catch (_) {}
    applyNav();
  }
  $("#dkSbTog").onclick = toggleNav;
  $("#dkSbCollapse").onclick = toggleNav;
  $("#dkSbShade").onclick = () => root.classList.remove("nav-open");
  // Rail mode: an immediate label flyout beside each icon (the sidebar scrolls, so a CSS
  // ::after would be clipped; one fixed element is positioned instead).
  const fly = $("#dkFly");
  const side = $("#dkSide");
  side.addEventListener("pointerover", (e) => {
    const b = e.target.closest(".dk-nv"); if (!b || !root.classList.contains("nav-rail")) { fly.classList.remove("on"); return; }
    const r = b.getBoundingClientRect(), z = zoomOf();
    fly.textContent = b.dataset.l || "";
    fly.style.left = (r.right / z + 10) + "px";
    fly.style.top = ((r.top + r.height / 2) / z) + "px";
    fly.classList.add("on");
  });
  side.addEventListener("pointerleave", () => fly.classList.remove("on"));
  side.addEventListener("scroll", () => fly.classList.remove("on"), true);
  buildSideNav();
  applyNav();

  // ---------- hover explainers (3s dwell; ui/explain.js) ----------
  // KPIs, nav scenes and badges come from the EXPLAIN registry; tools fall back to the
  // console's plain-English section help.
  let secHelp = null;
  import("/js/section-help.js?v=20261010j").then((m) => { secHelp = m.SECTION_HELP; }).catch(() => {});
  const toolExplain = (sec, label) => {
    const h = secHelp && secHelp[sec]; if (!h) return null;
    return { title: label || secLabel[sec] || sec, body: [h.what, h.when].filter(Boolean).join(" "), src: h.note || "" };
  };
  busOffs.push(attachExplain(root, { resolve: (el) => {
    const d = el.dataset || {};
    if (el.classList.contains("dk-kpi") && d.k) return EXPLAIN["kpi." + d.k] || null;
    if (el.classList.contains("dk-simchip")) return EXPLAIN["badge.sample"];
    if (el.classList.contains("dk-kevb")) return EXPLAIN["badge.kev"];
    if (el.classList.contains("dk-epssb")) return EXPLAIN["badge.epss"];
    if (el.matches(".dk-nv[data-scene],.dk-qacard[data-scene]")) return EXPLAIN["scene." + d.scene] || null;
    if (el.matches(".dk-nv[data-tool],.dk-qacard[data-tool]")) return EXPLAIN["tool." + d.tool] || toolExplain(d.tool, d.l) || EXPLAIN["scene." + d.tool] || null;
    if (el.matches(".dk-gcard[data-sec],.dk-pin[data-sec],.dk-compcard[data-sec]")) return EXPLAIN["tool." + d.sec] || toolExplain(d.sec, d.label);
    return null;
  } }));

  // ---------- boot: restore the last workspace ----------
  let initial = "overview";
  try { const sv = localStorage.getItem(LS_SCENE); if (sv && SCENES[sv]) initial = sv; } catch (_) {}
  requestAnimationFrame(() => { go(initial); if (opts.startSec) openTool(opts.startSec, secLabel[opts.startSec] || opts.startSec); });

  function teardown(){
    cancelAnimationFrame(rafId); clearInterval(clockId); clearTimeout(gTimer);
    busOffs.forEach((off) => { try { off(); } catch (_) {} }); busOffs = [];
    document.removeEventListener("keydown", onKey); window.removeEventListener("resize", onResize);
    root.remove();
  }
  return teardown;
}
