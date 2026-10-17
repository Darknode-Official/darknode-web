// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Web Gateway Hunt engine (proxyhunt). Reads secure web gateway / proxy logs and finds data
// leaving the company (uploads to personal storage, file transfer, paste sites, webmail and
// generative AI), builds a shadow-SaaS inventory with user counts, and surfaces anonymizers,
// remote-access tools, tunnelling services, malicious destinations and scripted clients.
//
// Inputs (auto-detected per file, column mapping for tabular files when unsure):
//   Zscaler NSS web: QRadar LEEF (LEEF:1.0|Zscaler|NSSWeblog|...), ArcSight CEF, Splunk key=value, CSV
//   Squid access.log native format (and custom logformats exported with a header row)
//   Palo Alto Networks URL Filtering and Traffic log CSV exports
//   Netskope web transactions / page events CSV
//   Cisco Umbrella proxy logs CSV (headerless S3 export or a CSV with headers)
//   Cloudflare Gateway HTTP Logpush (JSON / NDJSON)
//   Generic CSV / JSON (ts, user, src_ip, dst_host, url, method, status, bytes_out, bytes_in, ...)
//
// Pure ESM: no DOM, no network, no clock (opts.now is never needed: "recent" is relative to the
// last timestamp in the log). Deterministic: the same input gives byte-identical JSON.
// Streams lines and aggregates into compact per-user / per-app / per-host maps with small
// evidence reservoirs; it never keeps every event.

import { iterCsv, findColumn, normHeader, parseCef, parseLeef, flatten } from "../ingest/parse.js";
import { isIp, compileCidrs, isInternalIp, isOffHours } from "./log-hunter-engine.js";

export const TOOL_ID = "proxyhunt";
export const VERSION = "1.0.0";
export const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
export const CONF_RANK = { confirmed: 3, likely: 2, review: 1 };
export const EVIDENCE_CAP = 50;
const MB = 1048576;

/** Column aliases for tabular input: logical key -> accepted header names (case/punctuation-insensitive). */
export const COLUMNS = {
  ts: ["ts", "timestamp", "datetime", "time", "date", "_time", "receive time", "generate time", "devtime", "eventtime", "event_time", "start time"],
  user: ["user", "username", "user_name", "login", "usrname", "suser", "source user", "email", "identities", "identity", "src_user", "userprincipalname"],
  src: ["src_ip", "srcip", "client_ip", "clientip", "cip", "source address", "sourceip", "source_ip", "internal ip", "c-ip", "src"],
  dst: ["dst_ip", "dstip", "destination address", "destinationip", "destination ip", "serverip", "server_ip", "sip", "dest_ip", "dst"],
  host: ["dst_host", "host", "hostname", "httphost", "domain", "dhost", "cs-host", "destination host", "dest_host", "server_name"],
  url: ["url", "url/filename", "request", "uri", "cs-uri", "full_url", "eurl"],
  method: ["method", "http_method", "httpmethod", "http method", "reqmethod", "requestmethod", "request method", "cs-method"],
  status: ["status", "http_status", "httpstatuscode", "respcode", "statuscode", "status_code", "sc-status", "response code"],
  bytesOut: ["bytes_out", "bytesout", "client_bytes", "reqsize", "requestsize", "request size", "bytes sent", "srcbytes", "sent_bytes", "cs-bytes", "requestbytes", "upload_bytes"],
  bytesIn: ["bytes_in", "bytesin", "server_bytes", "respsize", "responsesize", "response size", "bytes received", "dstbytes", "received_bytes", "sc-bytes", "responsebytes", "download_bytes"],
  bytesTotal: ["bytes", "total_bytes", "transactionsize", "totalbytes"],
  category: ["category", "url_category", "urlcategory", "urlcat", "appcategory", "categories", "url category", "cat"],
  app: ["app", "application", "appname", "app_name", "application name", "destinationservicename"],
  action: ["action", "verdict", "disposition", "act"],
  ua: ["user_agent", "useragent", "ua", "http_user_agent", "user agent", "requestclientapplication"],
  filetype: ["filetype", "file_type", "file type", "fileclass"],
  instance: ["instance_id", "instance", "instanceid"],
  activity: ["activity"],
  uploaded: ["uploadedfilenames", "uploaded_file_names", "uploaded files"],
};

export const COLUMN_LABELS = {
  ts: "Timestamp", user: "User", src: "Client IP", dst: "Destination IP", host: "Destination host", url: "URL",
  method: "HTTP method", status: "HTTP status", bytesOut: "Bytes sent (upload)", bytesIn: "Bytes received (download)",
  bytesTotal: "Bytes (total, direction unknown)", category: "URL category", app: "Application", action: "Action / verdict",
  ua: "User agent", filetype: "File type", instance: "App instance", activity: "Activity", uploaded: "Uploaded file names",
};

/** Thresholds and settings; the UI renders these as the settings panel. */
export const DEFAULTS = {
  uploadMb: 100,          // per user per day, bytes sent to unsanctioned exfil-category apps
  uploadZ: 4,             // robust z of that day vs the user's own other days
  zMinMb: 10,             // the z rule needs at least this much (keeps 2 MB "spikes" out)
  baselineDays: 7,        // minimum other active days before the z rule applies
  uploadWrites: 20,       // POST/PUT per user per day to exfil apps when bytes are not logged
  aiUploadMb: 10,         // per user per AI service over the log period
  newAppDays: 7,          // "new app" = first seen within this many days of the last log entry
  uncatUploadMb: 50,      // bytes sent to an uncategorized / rare host
  rareUsers: 2,           // a host is rare when at most this many users reach it
  blockedPerHour: 30,     // blocked requests by one user in one clock hour
  blockedHosts: 5,        // ... across at least this many distinct hosts
  scriptedMin: 3,         // scripted-UA requests from one client before it is listed
  emptyUaMin: 20,         // empty-UA requests from one client before it is listed
  offHoursMb: 100,        // bytes sent outside business hours by one user in one day
  tunnelMinutes: 30,      // CONNECT tunnel duration
  tunnelMb: 50,           // CONNECT tunnel bytes (both directions)
  businessStart: 8,
  businessEnd: 18,
  utcOffset: 0,           // business time zone, hours from UTC
  weekendOffHours: true,
  ignoreDevHosts: true,   // package registries and OS update hosts are not "scripted client" findings
  sanctioned: [],         // one domain or app name per line
  ownDomains: [],
  allowHosts: [],
  internalCidrs: [],      // blank = RFC 1918 + RFC 4193 + loopback / link-local
  serverCidrs: [],
  maliciousIps: null,     // [{ip, source, score}] or ["ip"]; null = check skipped
  columns: {},            // { logicalKey: header } overrides for tabular files
};

export const DEFAULT_INTERNAL_CIDRS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", "fc00::/7", "fe80::/10", "::1/128"];

// ---------------------------------------------------------------------------
// App catalogue. [domain suffix, app name, category, flags, aliases]
// flags: "m" = mixed (the same host serves corporate and personal instances; the log alone
// usually cannot tell which, so sanctioned = unknown until you list it), "t" = tenant-aware
// (<tenant>.sharepoint.com / <tenant>-my.sharepoint.com: corporate when the tenant matches one
// of your own domains' first label or a sanctioned entry). Aliases match the application names
// gateways log (Palo Alto App-ID, Netskope, Zscaler appname). Longest suffix wins.
// ---------------------------------------------------------------------------
export const CATEGORIES = {
  storage: { label: "Personal storage", exfil: true },
  transfer: { label: "File transfer", exfil: true },
  paste: { label: "Paste / code sharing", exfil: true },
  webmail: { label: "Webmail", exfil: true },
  genai: { label: "Generative AI", exfil: true },
  messaging: { label: "Messaging" },
  social: { label: "Social" },
  remote: { label: "Remote access" },
  anonymizer: { label: "VPN / anonymizer / proxy" },
  crypto: { label: "Crypto exchange" },
  shortener: { label: "URL shortener" },
  ddns: { label: "Dynamic DNS" },
  tunnel: { label: "Tunnelling service" },
};

export const CATALOG = [
  // Generative AI
  ["chatgpt.com", "ChatGPT", "genai", "", ["openai-chatgpt", "chatgpt", "openai chatgpt"]],
  ["chat.openai.com", "ChatGPT", "genai", "", []],
  ["api.openai.com", "OpenAI API", "genai", "", ["openai-api", "openai"]],
  ["claude.ai", "Claude", "genai", "", ["claude", "anthropic-claude"]],
  ["api.anthropic.com", "Anthropic API", "genai", "", ["anthropic-api"]],
  ["gemini.google.com", "Google Gemini", "genai", "", ["google-gemini", "gemini"]],
  ["bard.google.com", "Google Gemini", "genai", "", []],
  ["aistudio.google.com", "Google AI Studio", "genai", "", []],
  ["notebooklm.google.com", "NotebookLM", "genai", "", []],
  ["copilot.microsoft.com", "Microsoft Copilot", "genai", "m", ["microsoft-copilot", "copilot"]],
  ["perplexity.ai", "Perplexity", "genai", "", ["perplexity"]],
  ["poe.com", "Poe", "genai", "", ["poe"]],
  ["character.ai", "Character.AI", "genai", "", ["character-ai"]],
  ["huggingface.co", "Hugging Face", "genai", "", ["hugging-face", "huggingface"]],
  ["deepseek.com", "DeepSeek", "genai", "", ["deepseek"]],
  ["mistral.ai", "Mistral AI", "genai", "", ["mistral", "le chat"]],
  ["you.com", "You.com", "genai", "", []],
  ["phind.com", "Phind", "genai", "", []],
  ["grok.com", "Grok", "genai", "", ["grok"]],
  ["x.ai", "xAI", "genai", "", []],
  ["meta.ai", "Meta AI", "genai", "", []],
  ["pi.ai", "Pi", "genai", "", []],
  ["jasper.ai", "Jasper", "genai", "", []],
  ["writesonic.com", "Writesonic", "genai", "", []],
  ["quillbot.com", "QuillBot", "genai", "", []],
  ["cohere.com", "Cohere", "genai", "", []],
  ["groq.com", "Groq", "genai", "", []],
  ["together.ai", "Together AI", "genai", "", []],
  ["replicate.com", "Replicate", "genai", "", []],
  ["midjourney.com", "Midjourney", "genai", "", []],
  ["elevenlabs.io", "ElevenLabs", "genai", "", []],
  ["otter.ai", "Otter.ai", "genai", "", []],
  ["chatpdf.com", "ChatPDF", "genai", "", []],
  ["deepl.com", "DeepL", "genai", "", ["deepl"]],
  // Personal storage
  ["drive.google.com", "Google Drive", "storage", "m", ["google-drive-base", "google-drive-web", "google drive", "google-drive"]],
  ["docs.google.com", "Google Docs", "storage", "m", ["google-docs-base", "google docs"]],
  ["drive.usercontent.google.com", "Google Drive", "storage", "m", []],
  ["dropbox.com", "Dropbox", "storage", "", ["dropbox-base", "dropbox", "dropbox-uploading"]],
  ["dropboxapi.com", "Dropbox", "storage", "", []],
  ["dropboxusercontent.com", "Dropbox", "storage", "", []],
  ["box.com", "Box", "storage", "m", ["box-base", "box"]],
  ["boxcloud.com", "Box", "storage", "m", []],
  ["onedrive.live.com", "OneDrive (personal)", "storage", "", ["ms-onedrive-personal", "onedrive personal", "onedrive"]],
  ["onedrive.com", "OneDrive (personal)", "storage", "", []],
  ["1drv.ms", "OneDrive (personal)", "storage", "", []],
  ["storage.live.com", "OneDrive (personal)", "storage", "", []],
  ["sharepoint.com", "SharePoint / OneDrive for Business", "storage", "mt", ["sharepoint-online", "ms-onedrive-business", "onedrive for business"]],
  ["mega.nz", "MEGA", "storage", "", ["mega", "mega.nz"]],
  ["mega.io", "MEGA", "storage", "", []],
  ["pcloud.com", "pCloud", "storage", "", ["pcloud"]],
  ["mediafire.com", "MediaFire", "storage", "", ["mediafire"]],
  ["icloud.com", "iCloud", "storage", "", ["icloud", "apple icloud"]],
  ["icloud-content.com", "iCloud", "storage", "", []],
  ["sync.com", "Sync.com", "storage", "", []],
  ["tresorit.com", "Tresorit", "storage", "", []],
  ["idrive.com", "IDrive", "storage", "", []],
  ["disk.yandex.com", "Yandex Disk", "storage", "", ["yandex-disk"]],
  ["disk.yandex.ru", "Yandex Disk", "storage", "", []],
  ["jottacloud.com", "Jottacloud", "storage", "", []],
  ["degoo.com", "Degoo", "storage", "", []],
  ["filen.io", "Filen", "storage", "", []],
  ["terabox.com", "TeraBox", "storage", "", []],
  ["4shared.com", "4shared", "storage", "", ["4shared"]],
  // File transfer
  ["wetransfer.com", "WeTransfer", "transfer", "", ["wetransfer"]],
  ["we.tl", "WeTransfer", "transfer", "", []],
  ["sendspace.com", "Sendspace", "transfer", "", ["sendspace"]],
  ["transfer.sh", "transfer.sh", "transfer", "", []],
  ["file.io", "file.io", "transfer", "", []],
  ["gofile.io", "Gofile", "transfer", "", []],
  ["filetransfer.io", "filetransfer.io", "transfer", "", []],
  ["fromsmash.com", "Smash", "transfer", "", []],
  ["swisstransfer.com", "SwissTransfer", "transfer", "", []],
  ["sendgb.com", "SendGB", "transfer", "", []],
  ["filemail.com", "Filemail", "transfer", "", []],
  ["catbox.moe", "Catbox", "transfer", "", []],
  ["uguu.se", "Uguu", "transfer", "", []],
  ["0x0.st", "0x0.st", "transfer", "", []],
  ["temp.sh", "temp.sh", "transfer", "", []],
  ["bashupload.com", "bashupload", "transfer", "", []],
  ["pixeldrain.com", "Pixeldrain", "transfer", "", []],
  ["krakenfiles.com", "KrakenFiles", "transfer", "", []],
  ["wormhole.app", "Wormhole", "transfer", "", []],
  ["transfernow.net", "TransferNow", "transfer", "", []],
  // Paste / code sharing
  ["pastebin.com", "Pastebin", "paste", "", ["pastebin"]],
  ["paste.ee", "Paste.ee", "paste", "", []],
  ["ghostbin.co", "Ghostbin", "paste", "", []],
  ["hastebin.com", "Hastebin", "paste", "", []],
  ["gist.github.com", "GitHub Gist", "paste", "m", ["github-gist"]],
  ["gist.githubusercontent.com", "GitHub Gist", "paste", "m", []],
  ["rentry.co", "Rentry", "paste", "", []],
  ["controlc.com", "ControlC", "paste", "", []],
  ["privatebin.net", "PrivateBin", "paste", "", []],
  ["justpaste.it", "JustPaste.it", "paste", "", []],
  ["dpaste.org", "dpaste", "paste", "", []],
  ["dpaste.com", "dpaste", "paste", "", []],
  ["paste.mozilla.org", "Mozilla Paste", "paste", "", []],
  ["termbin.com", "termbin", "paste", "", []],
  ["ix.io", "ix.io", "paste", "", []],
  ["sprunge.us", "sprunge", "paste", "", []],
  ["paste.rs", "paste.rs", "paste", "", []],
  // Webmail
  ["mail.google.com", "Gmail", "webmail", "m", ["gmail-base", "gmail", "gmail-uploading"]],
  ["outlook.live.com", "Outlook.com (personal)", "webmail", "", ["outlook-personal", "hotmail"]],
  ["mail.yahoo.com", "Yahoo Mail", "webmail", "", ["yahoo-mail", "yahoo mail"]],
  ["proton.me", "Proton Mail", "webmail", "", ["protonmail", "proton mail"]],
  ["protonmail.com", "Proton Mail", "webmail", "", []],
  ["tutanota.com", "Tuta Mail", "webmail", "", ["tutanota"]],
  ["tuta.com", "Tuta Mail", "webmail", "", []],
  ["mail.aol.com", "AOL Mail", "webmail", "", []],
  ["mail.zoho.com", "Zoho Mail", "webmail", "m", []],
  ["gmx.com", "GMX Mail", "webmail", "", ["gmx"]],
  ["gmx.net", "GMX Mail", "webmail", "", []],
  ["mail.com", "mail.com", "webmail", "", []],
  ["mail.yandex.com", "Yandex Mail", "webmail", "", []],
  ["fastmail.com", "Fastmail", "webmail", "", []],
  ["mail.ru", "Mail.ru", "webmail", "", []],
  ["hushmail.com", "Hushmail", "webmail", "", []],
  // Messaging
  ["web.whatsapp.com", "WhatsApp", "messaging", "", ["whatsapp-web", "whatsapp"]],
  ["whatsapp.com", "WhatsApp", "messaging", "", []],
  ["whatsapp.net", "WhatsApp", "messaging", "", []],
  ["telegram.org", "Telegram", "messaging", "", ["telegram", "telegram-base"]],
  ["t.me", "Telegram", "messaging", "", []],
  ["discord.com", "Discord", "messaging", "", ["discord"]],
  ["discordapp.com", "Discord", "messaging", "", []],
  ["signal.org", "Signal", "messaging", "", ["signal"]],
  ["messenger.com", "Facebook Messenger", "messaging", "", []],
  ["skype.com", "Skype", "messaging", "", ["skype"]],
  ["wechat.com", "WeChat", "messaging", "", ["wechat"]],
  // Social
  ["facebook.com", "Facebook", "social", "", ["facebook-base", "facebook"]],
  ["instagram.com", "Instagram", "social", "", ["instagram"]],
  ["x.com", "X (Twitter)", "social", "", ["twitter-base", "twitter"]],
  ["twitter.com", "X (Twitter)", "social", "", []],
  ["linkedin.com", "LinkedIn", "social", "", ["linkedin-base", "linkedin"]],
  ["reddit.com", "Reddit", "social", "", ["reddit"]],
  ["tiktok.com", "TikTok", "social", "", ["tiktok"]],
  ["pinterest.com", "Pinterest", "social", "", []],
  ["tumblr.com", "Tumblr", "social", "", []],
  ["snapchat.com", "Snapchat", "social", "", []],
  // Remote access
  ["teamviewer.com", "TeamViewer", "remote", "", ["teamviewer-base", "teamviewer"]],
  ["anydesk.com", "AnyDesk", "remote", "", ["anydesk"]],
  ["screenconnect.com", "ScreenConnect", "remote", "", ["screenconnect", "connectwise-control"]],
  ["logmein.com", "LogMeIn", "remote", "", ["logmeininc", "logmein"]],
  ["gotomypc.com", "GoToMyPC", "remote", "", ["gotomypc"]],
  ["splashtop.com", "Splashtop", "remote", "", ["splashtop"]],
  ["remotepc.com", "RemotePC", "remote", "", []],
  ["rustdesk.com", "RustDesk", "remote", "", ["rustdesk"]],
  ["getscreen.me", "Getscreen.me", "remote", "", []],
  ["supremocontrol.com", "Supremo", "remote", "", []],
  ["assist.zoho.com", "Zoho Assist", "remote", "", []],
  ["ammyy.com", "Ammyy Admin", "remote", "", ["ammyy"]],
  ["ultraviewer.net", "UltraViewer", "remote", "", []],
  ["dwservice.net", "DWService", "remote", "", []],
  ["atera.com", "Atera", "remote", "", []],
  ["parsec.app", "Parsec", "remote", "", []],
  ["remoteutilities.com", "Remote Utilities", "remote", "", []],
  ["bomgarcloud.com", "BeyondTrust Remote Support", "remote", "", []],
  // VPN / anonymizer / proxy
  ["torproject.org", "Tor Project", "anonymizer", "", ["tor", "tor-browser"]],
  ["tor2web.org", "Tor2web gateway", "anonymizer", "", []],
  ["onion.ws", "Tor2web gateway", "anonymizer", "", []],
  ["onion.ly", "Tor2web gateway", "anonymizer", "", []],
  ["onion.pet", "Tor2web gateway", "anonymizer", "", []],
  ["onion.to", "Tor2web gateway", "anonymizer", "", []],
  ["onion.city", "Tor2web gateway", "anonymizer", "", []],
  ["nordvpn.com", "NordVPN", "anonymizer", "", ["nordvpn"]],
  ["expressvpn.com", "ExpressVPN", "anonymizer", "", ["expressvpn"]],
  ["protonvpn.com", "Proton VPN", "anonymizer", "", ["protonvpn"]],
  ["surfshark.com", "Surfshark", "anonymizer", "", []],
  ["mullvad.net", "Mullvad VPN", "anonymizer", "", []],
  ["privateinternetaccess.com", "Private Internet Access", "anonymizer", "", []],
  ["windscribe.com", "Windscribe", "anonymizer", "", []],
  ["hide.me", "hide.me", "anonymizer", "", []],
  ["hidemyass.com", "HMA VPN", "anonymizer", "", []],
  ["tunnelbear.com", "TunnelBear", "anonymizer", "", []],
  ["cyberghostvpn.com", "CyberGhost", "anonymizer", "", []],
  ["psiphon.ca", "Psiphon", "anonymizer", "", ["psiphon"]],
  ["ultrasurf.us", "UltraSurf", "anonymizer", "", ["ultrasurf"]],
  ["hola.org", "Hola", "anonymizer", "", ["hola-unblocker"]],
  ["kproxy.com", "KProxy", "anonymizer", "", []],
  ["hidester.com", "Hidester", "anonymizer", "", []],
  ["croxyproxy.com", "CroxyProxy", "anonymizer", "", []],
  ["proxysite.com", "ProxySite", "anonymizer", "", []],
  // Crypto exchanges
  ["binance.com", "Binance", "crypto", "", ["binance"]],
  ["coinbase.com", "Coinbase", "crypto", "", ["coinbase"]],
  ["kraken.com", "Kraken", "crypto", "", []],
  ["kucoin.com", "KuCoin", "crypto", "", []],
  ["bybit.com", "Bybit", "crypto", "", []],
  ["okx.com", "OKX", "crypto", "", []],
  ["crypto.com", "Crypto.com", "crypto", "", []],
  ["gemini.com", "Gemini (exchange)", "crypto", "", []],
  ["bitfinex.com", "Bitfinex", "crypto", "", []],
  ["htx.com", "HTX", "crypto", "", []],
  // URL shorteners
  ["bit.ly", "Bitly", "shortener", "", []],
  ["tinyurl.com", "TinyURL", "shortener", "", []],
  ["t.co", "t.co", "shortener", "", []],
  ["goo.gl", "goo.gl", "shortener", "", []],
  ["ow.ly", "ow.ly", "shortener", "", []],
  ["is.gd", "is.gd", "shortener", "", []],
  ["cutt.ly", "Cuttly", "shortener", "", []],
  ["rebrand.ly", "Rebrandly", "shortener", "", []],
  ["shorturl.at", "shorturl.at", "shortener", "", []],
  ["tiny.cc", "tiny.cc", "shortener", "", []],
  ["rb.gy", "rb.gy", "shortener", "", []],
  // Dynamic DNS
  ["duckdns.org", "Duck DNS", "ddns", "", []],
  ["no-ip.com", "No-IP", "ddns", "", []],
  ["no-ip.org", "No-IP", "ddns", "", []],
  ["ddns.net", "No-IP", "ddns", "", []],
  ["hopto.org", "No-IP", "ddns", "", []],
  ["zapto.org", "No-IP", "ddns", "", []],
  ["sytes.net", "No-IP", "ddns", "", []],
  ["dynu.com", "Dynu", "ddns", "", []],
  ["dynu.net", "Dynu", "ddns", "", []],
  ["afraid.org", "FreeDNS (afraid.org)", "ddns", "", []],
  ["dyndns.org", "DynDNS", "ddns", "", []],
  // Tunnelling services
  ["ngrok.io", "ngrok", "tunnel", "", ["ngrok"]],
  ["ngrok.app", "ngrok", "tunnel", "", []],
  ["ngrok-free.app", "ngrok", "tunnel", "", []],
  ["trycloudflare.com", "Cloudflare Quick Tunnel", "tunnel", "", []],
  ["serveo.net", "Serveo", "tunnel", "", []],
  ["loca.lt", "localtunnel", "tunnel", "", []],
  ["localtunnel.me", "localtunnel", "tunnel", "", []],
  ["pagekite.me", "PageKite", "tunnel", "", []],
  ["portmap.io", "Portmap.io", "tunnel", "", []],
  ["bore.pub", "bore", "tunnel", "", []],
];

const CAT_BY_SUFFIX = new Map();
const CAT_BY_NAME = new Map();
for (const [d, n, c, f, aliases] of CATALOG) {
  const e = { domain: d, app: n, category: c, mixed: f.includes("m"), tenant: f.includes("t") };
  CAT_BY_SUFFIX.set(d, e);
  for (const a of [n, ...(aliases || [])]) { const k = normName(a); if (k && !CAT_BY_NAME.has(k)) CAT_BY_NAME.set(k, e); }
}
function normName(s) { return String(s || "").toLowerCase().replace(/[^a-z0-9]/g, ""); }

/** Longest-suffix catalogue match for a host; null when not catalogued. */
export function matchHost(host) {
  let h = String(host || "").toLowerCase().replace(/\.$/, "");
  if (!h || isIp(h)) return null;
  while (h) {
    const e = CAT_BY_SUFFIX.get(h);
    if (e) return e;
    const i = h.indexOf(".");
    if (i < 0) break;
    h = h.slice(i + 1);
  }
  return null;
}
/** Catalogue match on an application name logged by the gateway (App-ID, Netskope app, Zscaler appname). */
export function matchAppName(name) { return CAT_BY_NAME.get(normName(name)) || null; }

// Hosts commonly reached by scripts for legitimate reasons (package registries, OS updates,
// source hosting). Excluded from the scripted-client check when ignoreDevHosts is on.
export const DEV_HOSTS = ["pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "registry.yarnpkg.com", "rubygems.org", "repo.maven.apache.org", "repo1.maven.org",
  "proxy.golang.org", "sum.golang.org", "crates.io", "static.crates.io", "api.nuget.org", "packages.microsoft.com", "download.docker.com", "registry-1.docker.io",
  "auth.docker.io", "production.cloudflare.docker.com", "archive.ubuntu.com", "security.ubuntu.com", "deb.debian.org", "dl.fedoraproject.org", "mirrors.fedoraproject.org",
  "github.com", "api.github.com", "codeload.github.com", "objects.githubusercontent.com", "gitlab.com", "bitbucket.org", "windowsupdate.com", "update.microsoft.com", "download.microsoft.com"];

const SCRIPTED_UA = [
  [/^curl\//i, "curl"], [/python-requests|python-urllib|aiohttp|python-httpx/i, "Python"], [/go-http-client/i, "Go-http-client"],
  [/windowspowershell|powershell/i, "PowerShell"], [/^wget\//i, "wget"], [/libwww-perl|lwp::/i, "libwww-perl"],
  [/^java\/|apache-httpclient|okhttp/i, "Java"], [/node-fetch|axios\/|undici/i, "Node.js"], [/nmap|masscan|sqlmap|nikto|zgrab/i, "scanner"],
];
export function scriptedFamily(ua) {
  const s = String(ua || "");
  for (const [re, n] of SCRIPTED_UA) if (re.test(s)) return n;
  return null;
}

const EXEC_EXT = /\.(exe|dll|ps1|hta|js|vbs|iso|lnk|scr|msi|bat|cmd|jar)$/i;
const EXEC_FT = /^(exe|dll|ps1|hta|js|vbs|iso|lnk|scr|msi|bat|cmd|jar|windows executable|pe|exe64|exe32|application\/x-msdownload|application\/x-dosexec)$/i;
const UNCAT_RE = /uncategori|unknown|miscellaneous|not rated|unrated|newly|^none$|^-$/i;
const BLOCK_RE = /block|deny|denied|drop|reset|forbid|reject|quarantin/i;
const WRITE_METHODS = new Set(["POST", "PUT", "PATCH"]);
const CONTROLS = {
  exfil: [{ framework: "MITRE", id: "T1567" }, { framework: "MITRE", id: "T1567.002" }, { framework: "MITRE", id: "T1048" }, { framework: "NIST-800-53", id: "AC-4" }, { framework: "NIST-800-53", id: "SC-7" }, { framework: "NIST-800-53", id: "SI-4" }, { framework: "CIS Controls v8", id: "3.13" }],
  paste: [{ framework: "MITRE", id: "T1567.003" }],
  genai: [{ framework: "MITRE", id: "T1567" }, { framework: "NIST-800-53", id: "AC-4" }, { framework: "NIST-800-53", id: "SA-9" }, { framework: "CIS Controls v8", id: "3.13" }],
  saas: [{ framework: "NIST-800-53", id: "SA-9" }, { framework: "NIST-800-53", id: "CM-8" }, { framework: "CIS Controls v8", id: "2.1" }, { framework: "CIS Controls v8", id: "2.3" }, { framework: "CIS Controls v8", id: "9.3" }],
  anonymizer: [{ framework: "MITRE", id: "T1090" }, { framework: "NIST-800-53", id: "SC-7" }, { framework: "CIS Controls v8", id: "9.3" }],
  tor: [{ framework: "MITRE", id: "T1090.003" }],
  remote: [{ framework: "MITRE", id: "T1219" }, { framework: "NIST-800-53", id: "AC-17" }, { framework: "CIS Controls v8", id: "2.3" }],
  tunnel: [{ framework: "MITRE", id: "T1572" }, { framework: "MITRE", id: "T1102" }, { framework: "NIST-800-53", id: "SC-7" }],
  ddns: [{ framework: "MITRE", id: "T1568" }, { framework: "MITRE", id: "T1071.001" }, { framework: "NIST-800-53", id: "SC-7" }],
  malicious: [{ framework: "MITRE", id: "T1071.001" }, { framework: "NIST-800-53", id: "SI-4" }, { framework: "NIST-800-53", id: "SC-7" }, { framework: "CIS Controls v8", id: "9.3" }],
  uncat: [{ framework: "MITRE", id: "T1567" }, { framework: "MITRE", id: "T1048" }, { framework: "NIST-800-53", id: "AC-4" }, { framework: "CIS Controls v8", id: "9.3" }],
  ipexe: [{ framework: "MITRE", id: "T1105" }, { framework: "MITRE", id: "T1071.001" }, { framework: "NIST-800-53", id: "SI-4" }, { framework: "CIS Controls v8", id: "9.3" }],
  blocked: [{ framework: "NIST-800-53", id: "SI-4" }, { framework: "CIS Controls v8", id: "9.3" }],
  scripted: [{ framework: "MITRE", id: "T1071.001" }, { framework: "NIST-800-53", id: "SI-4" }],
  offhours: [{ framework: "MITRE", id: "T1029" }, { framework: "MITRE", id: "T1567" }, { framework: "NIST-800-53", id: "AC-4" }, { framework: "NIST-800-53", id: "SI-4" }],
  tunnelConnect: [{ framework: "MITRE", id: "T1572" }, { framework: "MITRE", id: "T1048" }, { framework: "NIST-800-53", id: "SC-7" }],
};

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
const str = (v) => (v == null ? "" : String(v)).trim();
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
function num(v) {
  if (v == null || v === "") return null;
  const s = String(v).trim().replace(/,/g, "");
  if (!/^-?\d+(\.\d+)?$/.test(s)) return null;
  const n = Number(s);
  return Number.isFinite(n) && n >= 0 ? n : null;
}
export function fmtBytes(n) {
  const v = Number(n) || 0;
  if (v >= 1073741824) return (v / 1073741824).toFixed(2) + " GB";
  if (v >= MB) return (v / MB).toFixed(1) + " MB";
  if (v >= 1024) return (v / 1024).toFixed(1) + " KB";
  return v + " B";
}
export function iso(ms) { return Number.isFinite(ms) ? new Date(ms).toISOString().replace(".000Z", "Z") : ""; }
function cyrb(s) {
  let h1 = 0xdeadbeef, h2 = 0x41c6ce57;
  for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); h1 = Math.imul(h1 ^ c, 2654435761); h2 = Math.imul(h2 ^ c, 1597334677); }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(36);
}
function* iterLines(text) {
  const s = String(text || "");
  let i = 0, n = 0;
  const L = s.length;
  if (s.charCodeAt(0) === 0xfeff) i = 1;
  while (i < L) {
    let j = s.indexOf("\n", i);
    if (j < 0) j = L;
    let line = s.slice(i, j);
    if (line.endsWith("\r")) line = line.slice(0, -1);
    n++;
    yield [line, n];
    i = j + 1;
  }
}

const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
function tzMs(z) {
  if (!z || /^(z|utc|gmt)$/i.test(z)) return 0;
  const m = String(z).match(/^([+-])(\d{2}):?(\d{2})$/);
  return m ? (m[1] === "-" ? -1 : 1) * (Number(m[2]) * 60 + Number(m[3])) * 60000 : 0;
}
function epochNorm(n) {
  if (!Number.isFinite(n)) return null;
  if (n > 1e17) return Math.floor(n / 1e6);
  if (n > 1e14) return Math.floor(n / 1e3);
  if (n > 1e11) return Math.floor(n);
  return Math.round(n * 1000);
}
/**
 * Deterministic timestamp parser (epoch ms or null). Epoch s / ms / us / ns (Squid, Netskope,
 * Logpush unixnano), ISO 8601, "YYYY/MM/DD HH:MM:SS" (PAN-OS, read as UTC), "Mon DD YYYY
 * HH:MM:SS TZ" (Zscaler devTime), CLF "DD/Mon/YYYY:HH:MM:SS +zzzz". Named zones other than
 * UTC/GMT are read as UTC.
 */
export function parseTime(v) {
  if (v == null || v === "") return null;
  if (typeof v === "number") return epochNorm(v);
  const s = String(v).trim();
  let m;
  if (/^\d{9,19}(\.\d+)?$/.test(s)) return epochNorm(Number(s));
  if ((m = s.match(/^(\d{4})[-/](\d{2})[-/](\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d+))?\s*(Z|UTC|GMT|[+-]\d{2}:?\d{2})?$/i))) {
    const ms = m[7] ? Math.round(Number("0." + m[7]) * 1000) : 0;
    return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6], ms) - tzMs(m[8]);
  }
  if ((m = s.match(/^(?:\w{3},?\s+)?(\w{3})\s+(\d{1,2}),?\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2})(?:\s+(\S+))?$/))) {
    const mon = MONTHS[m[1].toLowerCase()];
    if (mon != null) return Date.UTC(+m[3], mon, +m[2], +m[4], +m[5], +m[6]) - tzMs(m[7]);
  }
  if ((m = s.match(/^\w{3}\s+(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})$/))) {
    const mon = MONTHS[m[1].toLowerCase()];
    if (mon != null) return Date.UTC(+m[6], mon, +m[2], +m[3], +m[4], +m[5]);
  }
  if ((m = s.match(/^(\d{1,2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s*([+-]\d{4}))?$/))) {
    const mon = MONTHS[m[2].toLowerCase()];
    if (mon != null) return Date.UTC(+m[3], mon, +m[1], +m[4], +m[5], +m[6]) - tzMs(m[7]);
  }
  if ((m = s.match(/^(\d{4})-(\d{2})-(\d{2})$/))) return Date.UTC(+m[1], +m[2] - 1, +m[3]);
  return null;
}

/** Host from a URL, "host:port" CONNECT target or bare host; lower-case, no port. */
export function hostOf(u) {
  let s = str(u);
  if (!s) return "";
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
  s = s.split(/[/?#]/)[0];
  const at = s.lastIndexOf("@");
  if (at >= 0) s = s.slice(at + 1);
  if (s.startsWith("[")) { const e = s.indexOf("]"); return e > 0 ? s.slice(1, e).toLowerCase() : s.toLowerCase(); }
  if ((s.match(/:/g) || []).length === 1) s = s.split(":")[0];
  return s.toLowerCase().replace(/\.$/, "");
}
function pathOf(u) {
  const s = str(u).replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
  const i = s.search(/[/]/);
  return i < 0 ? "" : s.slice(i).split(/[?#]/)[0];
}
function cleanUser(u) {
  let s = str(u);
  if (!s || s === "-" || /^(unknown|n\/a|none|null)$/i.test(s)) return "";
  const em = s.match(/\(([^()\s]+@[^()\s]+)\)/);
  if (em) s = em[1];
  return s.toLowerCase();
}

// ---------------------------------------------------------------------------
// Format detection
// ---------------------------------------------------------------------------
export const FORMAT_LABEL = {
  "zscaler-leef": "Zscaler NSS web (QRadar LEEF)", leef: "LEEF web log", "zscaler-cef": "Zscaler NSS web (CEF)", cef: "CEF web log",
  "zscaler-kv": "Zscaler NSS web (Splunk key=value)", kv: "key=value web log", squid: "Squid access.log (native)",
  "pan-url": "Palo Alto Networks URL Filtering log CSV", "pan-traffic": "Palo Alto Networks Traffic log CSV",
  netskope: "Netskope web transactions / page events CSV", umbrella: "Cisco Umbrella proxy log CSV (with headers)",
  "umbrella-nohdr": "Cisco Umbrella proxy log CSV (S3, headerless)", cloudflare: "Cloudflare Gateway HTTP (Logpush)",
  "zscaler-csv": "Zscaler NSS web (CSV)", "generic-csv": "Generic proxy CSV", "generic-json": "Generic proxy JSON", unknown: "Unrecognised", empty: "Empty",
};
const SQUID_RE = /^(\d{9,10}(?:\.\d+)?)\s+(\d+)\s+(\S+)\s+([A-Z_]+|NONE[A-Z_]*)\/(\d{3})\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+([A-Z_]+)\/(\S+)(?:\s+(\S+))?/;
const UMB_RE = /^"?\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"?,/;

function firstLines(text, n) {
  const out = [];
  for (const [l] of iterLines(text)) { if (l.trim()) out.push(l); if (out.length >= n) break; }
  return out;
}
function kvPairs(line) {
  const out = {};
  const parts = line.includes("\t") ? line.split("\t") : (line.match(/(\w[\w.-]*)=("([^"\\]|\\.)*"|\S*)/g) || []);
  for (const p of parts) {
    const i = p.indexOf("=");
    if (i <= 0) continue;
    let v = p.slice(i + 1).trim();
    if (v.length >= 2 && v[0] === '"' && v[v.length - 1] === '"') v = v.slice(1, -1).replace(/\\"/g, '"');
    out[p.slice(0, i).trim()] = v;
  }
  return out;
}

function headersOf(text) {
  const it = iterCsv(text, { header: false });
  const h = it.next();
  return h.done ? [] : h.value.map((x) => String(x).trim());
}
function resolveCols(headers, overrides) {
  const cols = {};
  for (const k of Object.keys(COLUMNS)) {
    const o = overrides && overrides[k];
    if (o && headers.includes(o)) { cols[k] = o; continue; }
    const h = findColumn(headers, COLUMNS[k]);
    if (h) cols[k] = h;
  }
  // "Bytes" alone in a PAN Traffic export sits beside Bytes Sent / Received: keep it as total only.
  return cols;
}

/** Detect one file. Returns { name, format, label, confidence, headers, bytes, cols? }. */
export function detectFile(name, text) {
  const t = String(text || "");
  const base = { name: String(name || "input"), bytes: t.length, headers: [] };
  const lines = firstLines(t, 25);
  if (!lines.length) return { ...base, format: "empty", label: FORMAT_LABEL.empty, confidence: 0 };
  const done = (format, confidence, extra) => ({ ...base, format, label: FORMAT_LABEL[format], confidence, ...(extra || {}) });
  if (lines.some((l) => l.includes("LEEF:"))) return done(lines.some((l) => /LEEF:[\d.]+\|Zscaler\|/i.test(l)) ? "zscaler-leef" : "leef", lines.some((l) => /\|Zscaler\|/i.test(l)) ? 1 : 0.85);
  if (lines.some((l) => l.includes("CEF:"))) return done(lines.some((l) => /CEF:\d+\|Zscaler\|/i.test(l)) ? "zscaler-cef" : "cef", lines.some((l) => /\|Zscaler\|/i.test(l)) ? 1 : 0.8);
  const sq = lines.filter((l) => SQUID_RE.test(l)).length;
  if (sq && sq / lines.length >= 0.6) return done("squid", sq === lines.length ? 0.95 : 0.8);
  const c0 = lines[0].trimStart()[0];
  if (c0 === "{" || c0 === "[") {
    let sample = null;
    try { const o = JSON.parse(lines[0]); sample = Array.isArray(o) ? o[0] : o; } catch (_) {
      try { const o = JSON.parse(t); sample = Array.isArray(o) ? o[0] : (o && (o.data || o.records || o.Records || o.events)) ? (o.data || o.records || o.Records || o.events)[0] : o; } catch (_) { sample = null; }
    }
    if (sample && typeof sample === "object") {
      const keys = Object.keys(flatten(sample));
      const cols = resolveCols(keys);
      if (keys.includes("HTTPHost") || (keys.includes("Datetime") && keys.includes("SourceIP"))) return done("cloudflare", 0.95, { headers: keys, cols });
      return done("generic-json", cols.ts && (cols.host || cols.url) ? 0.8 : 0.5, { headers: keys, cols });
    }
    return done("unknown", 0);
  }
  const kvl = lines.filter((l) => (l.match(/(^|[\t ])[A-Za-z_][\w.-]*=/g) || []).length >= 5);
  if (kvl.length / lines.length >= 0.6 || lines.some((l) => /\bvendor=Zscaler\b/.test(l) && /=/.test(l) && (l.match(/=/g) || []).length >= 5)) {
    return done(lines.some((l) => /\bvendor=Zscaler\b|sourcetype="?zscalernss/i.test(l)) ? "zscaler-kv" : "kv", lines.some((l) => /zscaler/i.test(l)) ? 0.9 : 0.6);
  }
  if (UMB_RE.test(lines[0])) {
    const row = headersOf(lines[0]);
    if (row.length >= 12 && /^(ALLOWED|BLOCKED|allowed|blocked)$/.test(row[6] || "") && /^https?:\/\//i.test(row[7] || "")) return done("umbrella-nohdr", 0.7, { headers: row.map((_, i) => "col" + (i + 1)) });
  }
  const headers = headersOf(t);
  const n = headers.map(normHeader);
  const has = (...hs) => hs.every((h) => n.includes(normHeader(h)));
  const cols = resolveCols(headers);
  if (has("Receive Time", "Source address") && has("Bytes Sent", "Bytes Received")) return done("pan-traffic", 0.8, { headers, cols });
  if (has("Receive Time", "Source address") && (has("URL/Filename") || has("Threat/Content Type"))) return done("pan-url", 0.8, { headers, cols });
  if (has("client_bytes", "server_bytes") || has("ccl") || (has("appcategory") && has("instance_id"))) return done("netskope", 0.85, { headers, cols });
  if (has("Identities", "Verdict") || (has("Policy Identity") && has("Verdict"))) return done("umbrella", 0.8, { headers, cols });
  if (has("urlsupercategory") || has("urlsupercat") || ((has("reqsize") || has("requestsize")) && (has("urlcat") || has("urlcategory")))) return done("zscaler-csv", 0.85, { headers, cols });
  if (headers.length >= 3) {
    const conf = cols.ts && (cols.user || cols.src) && (cols.host || cols.url) ? 0.85 : (cols.host || cols.url) ? 0.6 : 0.3;
    return done("generic-csv", conf, { headers, cols });
  }
  return done("unknown", 0);
}

// ---------------------------------------------------------------------------
// Record -> normalised event
// ---------------------------------------------------------------------------
function pick(o, keys) {
  for (const k of keys) { const v = o[k]; if (v != null && String(v).trim() !== "" && String(v).trim() !== "-" && String(v).trim() !== "None") return String(v).trim(); }
  return "";
}
const LEEF_KEYS = {
  ts: ["devTime"], user: ["usrName", "login", "user"], src: ["src", "cip"], dst: ["dst", "sip"], host: ["hostname", "host", "ehost"], url: ["url", "eurl"],
  method: ["reqmethod"], status: ["respcode"], bytesOut: ["srcBytes", "reqsize"], bytesIn: ["dstBytes", "respsize"], category: ["urlcategory", "urlcat", "cat"],
  app: ["appname"], action: ["action"], ua: ["useragent", "ua", "eua"], filetype: ["filetype"],
};
const CEF_KEYS = {
  ts: ["rt", "end", "start"], user: ["suser"], src: ["src"], dst: ["dst"], host: ["dhost"], url: ["request"], method: ["requestMethod"], status: ["outcome"],
  bytesOut: ["out"], bytesIn: ["in"], category: ["cat"], app: ["destinationServiceName"], action: ["act"], ua: ["requestClientApplication"], filetype: ["fileType"],
};

function mkEvent(o) {
  const ev = {
    ts: parseTime(o.ts), user: cleanUser(o.user), src: str(o.src), dst: str(o.dst), host: "", url: str(o.url), method: str(o.method).toUpperCase(),
    status: str(o.status), bytesOut: num(o.bytesOut), bytesIn: num(o.bytesIn), bytesTotal: num(o.bytesTotal), category: str(o.category), app: str(o.app),
    action: str(o.action), ua: o.ua == null ? null : str(o.ua), filetype: str(o.filetype), instance: str(o.instance), activity: str(o.activity),
    uploaded: str(o.uploaded), connect: !!o.connect, elapsedMs: o.elapsedMs == null ? null : o.elapsedMs, file: o.file || "", line: o.line || 0,
  };
  ev.host = hostOf(o.host) || hostOf(ev.url);
  if (ev.method === "CONNECT") ev.connect = true;
  if (ev.uploaded === "[]") ev.uploaded = "";
  return ev;
}

function fromKeys(o, keys, extra) {
  const r = {};
  for (const k of Object.keys(keys)) r[k] = pick(o, keys[k]);
  return Object.assign(r, extra || {});
}
function fromCols(o, cols) {
  const r = {};
  for (const k of Object.keys(COLUMNS)) r[k] = cols[k] ? o[cols[k]] : undefined;
  if (cols.ua) r.ua = o[cols.ua] == null ? "" : o[cols.ua];
  else r.ua = null;
  return r;
}

/**
 * Generator over one file's normalised events. `info` collects counts:
 * { parsed, unparsed, fields: {key: true when seen non-empty}, hasUserField, uaField, notes[] }.
 */
export function* iterEvents(file, det, info, overrides) {
  const text = String(file.text || "");
  const name = file.name || "input";
  const f = det.format;
  const seen = info.fields;
  const mark = (ev) => {
    for (const k of ["ts", "user", "src", "dst", "host", "method", "bytesOut", "bytesIn", "bytesTotal", "category", "app", "action", "filetype", "instance", "activity", "uploaded"]) {
      const v = ev[k];
      if (v != null && v !== "" && !(k === "ts" && v === null)) seen[k] = true;
    }
    if (ev.ua != null) seen.uaField = true;
    if (ev.connect) seen.connect = true;
    if (ev.elapsedMs != null) seen.elapsed = true;
  };
  if (f === "zscaler-leef" || f === "leef" || f === "zscaler-cef" || f === "cef" || f === "zscaler-kv" || f === "kv" || f === "squid") {
    for (const [line, ln] of iterLines(text)) {
      if (!line.trim()) continue;
      let o = null;
      if (f.endsWith("leef")) {
        const p = parseLeef(line);
        if (p) { o = fromKeys(p.ext, LEEF_KEYS); if (!o.action) o.action = p.eventId; if (!("useragent" in p.ext || "ua" in p.ext || "eua" in p.ext)) o.ua = null; info.hasUserField = true; }
      } else if (f.endsWith("cef")) {
        const p = parseCef(line);
        if (p) { o = fromKeys(p.ext, CEF_KEYS); if (!o.action) o.action = p.name; if (!("requestClientApplication" in p.ext)) o.ua = null; if ("suser" in p.ext) info.hasUserField = true; }
      } else if (f.endsWith("kv")) {
        const p = kvPairs(line);
        if (Object.keys(p).length >= 3) {
          const cols = resolveCols(Object.keys(p), overrides);
          o = fromCols(p, cols);
          if (cols.user) info.hasUserField = true;
        }
      } else {
        const m = line.match(SQUID_RE);
        if (m) {
          const method = m[7], target = m[8];
          const isConnect = method === "CONNECT";
          const bytes = Number(m[6]);
          o = {
            ts: m[1], elapsedMs: Number(m[2]), src: m[3], action: m[4], status: m[5], method, url: target, user: m[9],
            dst: /^\d|:/.test(m[11]) && m[11] !== "-" ? m[11] : "", connect: isConnect,
            bytesTotal: isConnect ? bytes : null, bytesIn: isConnect ? null : bytes, ua: null, category: "",
          };
          if (!/DENIED|BLOCK/i.test(m[4])) o.action = "allowed"; else o.action = "blocked (" + m[4] + ")";
          info.hasUserField = true;
        }
      }
      if (!o) { info.unparsed++; continue; }
      o.file = name; o.line = ln;
      const ev = mkEvent(o);
      info.parsed++;
      mark(ev);
      yield ev;
    }
    return;
  }
  if (f === "umbrella-nohdr") {
    let ln = 0;
    for (const row of iterCsv(text, { header: false })) {
      ln++;
      if (row.length < 12) { info.unparsed++; continue; }
      const o = { ts: row[0], user: row[1], src: row[2], dst: row[4], action: row[6], url: row[7], ua: row[9] || "", status: row[10], bytesOut: row[11], bytesIn: row[12], category: row[15] || "", file: name, line: ln };
      info.hasUserField = true;
      const ev = mkEvent(o);
      info.parsed++; mark(ev); yield ev;
    }
    return;
  }
  if (f === "cloudflare" || f === "generic-json") {
    let records;
    const lines = firstLines(text, 2);
    let whole = null;
    if (lines.length && lines[0].trimStart()[0] === "[") { try { whole = JSON.parse(text); } catch (_) { whole = null; } }
    else if (lines.length === 1) { try { whole = JSON.parse(text); } catch (_) { whole = null; } }
    if (whole != null) {
      records = Array.isArray(whole) ? whole : (whole.data || whole.records || whole.Records || whole.events || whole.result || [whole]);
      let ln = 0;
      let cols = null;
      for (const r of records) {
        ln++;
        if (!r || typeof r !== "object") { info.unparsed++; continue; }
        const o = flatten(r);
        if (!cols) { cols = resolveCols(Object.keys(o), overrides); if (cols.user) info.hasUserField = true; }
        const e = fromCols(o, cols); e.file = name; e.line = ln;
        const ev = mkEvent(e); info.parsed++; mark(ev); yield ev;
      }
      return;
    }
    let cols = null;
    for (const [line, ln] of iterLines(text)) {
      if (!line.trim()) continue;
      let r;
      try { r = JSON.parse(line); } catch (_) { info.unparsed++; continue; }
      if (!r || typeof r !== "object") { info.unparsed++; continue; }
      const o = flatten(r);
      if (!cols) { cols = resolveCols(Object.keys(o), overrides); if (cols.user) info.hasUserField = true; }
      const e = fromCols(o, cols); e.file = name; e.line = ln;
      const ev = mkEvent(e); info.parsed++; mark(ev); yield ev;
    }
    return;
  }
  if (f === "unknown" || f === "empty") return;
  // Tabular CSV formats.
  const cols = resolveCols(det.headers && det.headers.length ? det.headers : headersOf(text), overrides);
  // PAN-OS exports carry a legacy "Domain" column (a number), not a hostname.
  if (f.startsWith("pan-") && cols.host && normHeader(cols.host) === "domain") delete cols.host;
  if (f === "pan-traffic" && cols.bytesTotal && (cols.bytesOut || cols.bytesIn)) delete cols.bytesTotal;
  if (cols.user) info.hasUserField = true;
  info.cols = cols;
  let ln = 1;
  for (const row of iterCsv(text)) {
    ln++;
    const e = fromCols(row, cols); e.file = name; e.line = ln;
    if (f === "netskope" && /upload|post|share/i.test(str(row.activity)) && !e.method) e.method = "POST";
    const ev = mkEvent(e);
    info.parsed++; mark(ev); yield ev;
  }
}

/** Parse raw text (or [{name,text}]) into normalised events plus per-file detection. */
export function parseInput(input, opts = {}) {
  const files = toFiles(input);
  const skipped = [];
  const formats = [];
  const rows = [];
  for (const file of files) {
    const det = detectFile(file.name, file.text);
    const info = { parsed: 0, unparsed: 0, fields: {}, hasUserField: false };
    formats.push(det);
    if (det.format === "unknown" || det.format === "empty") { if (det.format === "unknown") skipped.push({ check: "parse", reason: file.name + ": format not recognised" }); continue; }
    for (const ev of iterEvents(file, det, info, opts.columns)) rows.push(ev);
    if (info.unparsed) skipped.push({ check: "parse", reason: file.name + ": " + info.unparsed + " line(s) did not match " + det.label });
  }
  const headers = formats.length ? (formats[0].headers || []) : [];
  const format = !formats.length ? "empty" : formats.every((d) => d.format === formats[0].format) ? formats[0].format : "mixed";
  return { format, formats, headers, rows, skipped };
}

function toFiles(input) {
  if (input == null) return [];
  if (typeof input === "string") return input.trim() ? [{ name: "input", text: input }] : [];
  if (Array.isArray(input)) return input.filter((f) => f && typeof f.text === "string").map((f, i) => ({ name: f.name || "file" + (i + 1), text: f.text }));
  if (input.files) return toFiles(input.files);
  if (typeof input.text === "string") return [{ name: input.name || "input", text: input.text }];
  return [];
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------
function median(a) {
  if (!a.length) return 0;
  const s = a.slice().sort((x, y) => x - y);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}
/**
 * Robust (modified) z-score of x against a baseline sample (Iglewicz & Hoaglin):
 *   z = 0.6745 * (x - median) / MAD,  MAD = median(|b - median|)
 * When MAD is 0 the mean absolute deviation is used instead: z = (x - median) / (1.253314 * MeanAD).
 * When both are 0 the baseline is constant and z is undefined (returned as null).
 */
export function robustZ(x, baseline) {
  const med = median(baseline);
  const mad = median(baseline.map((b) => Math.abs(b - med)));
  if (mad > 0) return { z: (0.6745 * (x - med)) / mad, median: med, mad, method: "MAD" };
  const meanAd = baseline.length ? baseline.reduce((s, b) => s + Math.abs(b - med), 0) / baseline.length : 0;
  if (meanAd > 0) return { z: (x - med) / (1.253314 * meanAd), median: med, mad: 0, meanAd, method: "MeanAD" };
  return { z: null, median: med, mad: 0, method: "constant" };
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------
function lines(v) {
  if (Array.isArray(v)) return v.map((s) => str(s)).filter(Boolean);
  return String(v || "").split(/[\r\n,]+/).map((s) => s.trim()).filter((s) => s && !s.startsWith("#"));
}
function mergeOpts(opts) {
  const o = { ...DEFAULTS, ...(opts || {}) };
  for (const k of Object.keys(DEFAULTS)) {
    if (typeof DEFAULTS[k] === "number") { const n = Number(o[k]); o[k] = Number.isFinite(n) ? n : DEFAULTS[k]; }
  }
  o.sanctioned = lines(o.sanctioned).map((s) => s.toLowerCase());
  o.ownDomains = lines(o.ownDomains).map((s) => s.toLowerCase().replace(/^\*\./, ""));
  o.allowHosts = lines(o.allowHosts).map((s) => s.toLowerCase().replace(/^\*\./, ""));
  const ic = lines(o.internalCidrs);
  o.internal = compileCidrs(ic.length ? ic : DEFAULT_INTERNAL_CIDRS);
  o.servers = compileCidrs(lines(o.serverCidrs));
  o.tenants = new Set(o.ownDomains.map((d) => d.split(".")[0]).filter(Boolean));
  for (const s of o.sanctioned) { const m = s.match(/^([a-z0-9-]+?)(?:-my)?\.sharepoint\.com$/); if (m) o.tenants.add(m[1]); }
  o.columns = o.columns && typeof o.columns === "object" ? o.columns : {};
  return o;
}
const suffixIn = (host, list) => { const h = String(host || ""); return list.some((d) => h === d || h.endsWith("." + d)); };

/** Classify a destination: catalogue entry + sanctioned (yes / no / unknown) + instance. */
export function classify(ev, o) {
  let e = matchHost(ev.host);
  if (!e && ev.app) e = matchAppName(ev.app);
  if (!e) return null;
  let instance = "", sanctioned = "no";
  if (e.tenant && ev.host) {
    const m = ev.host.match(/^([a-z0-9-]+?)(-my)?\.sharepoint\.com$/);
    if (m) instance = o.tenants.has(m[1]) ? "corporate" : o.tenants.size ? "other tenant" : "unknown";
  }
  if (ev.instance) {
    const inst = ev.instance.toLowerCase();
    instance = o.ownDomains.some((d) => inst === d || inst.endsWith("." + d) || inst.includes(d)) || o.sanctioned.includes(inst) ? "corporate" : /personal/.test(inst) ? "personal" : instance || "other: " + inst;
  }
  let app = e.app;
  if (instance && (e.tenant || ev.instance)) app = e.app + " (" + (instance === "corporate" ? "corporate" : instance === "other tenant" ? "tenant " + ev.host.split(".")[0].replace(/-my$/, "") : instance) + ")";
  const listed = o.sanctioned.some((s) => s === normName(e.app) || s === e.app.toLowerCase() || (ev.host && (ev.host === s || ev.host.endsWith("." + s))) || s === e.domain);
  if (listed || instance === "corporate") sanctioned = "yes";
  else if ((e.mixed && (!instance || instance === "unknown"))) sanctioned = "unknown";
  return { ...e, app, instance: instance || (e.mixed ? "unknown" : ""), sanctioned };
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------
function evRow(ev) {
  return {
    time: iso(ev.ts), user: ev.user, src: ev.src, host: ev.host, method: ev.method, status: ev.status,
    bytesOut: ev.bytesOut, bytesIn: ev.bytesIn, bytesTotal: ev.bytesTotal, category: ev.category, app: ev.app, action: ev.action,
    ua: ev.ua == null ? "" : ev.ua.slice(0, 160), url: ev.url.slice(0, 240), file: ev.file, line: ev.line,
  };
}
// Keep the top K rows by a numeric key; ties keep the earlier row (deterministic).
function pushTop(arr, row, key, k) {
  if (arr.length < k) { arr.push(row); return; }
  let mi = 0;
  for (let i = 1; i < arr.length; i++) if ((arr[i][key] || 0) < (arr[mi][key] || 0)) mi = i;
  if ((row[key] || 0) > (arr[mi][key] || 0)) arr[mi] = row;
}
const pushFirst = (arr, row, k) => { if (arr.length < k) arr.push(row); };
const sortEv = (rows, key) => rows.slice().sort((a, b) => (key ? (b[key] || 0) - (a[key] || 0) : 0) || cmp(a.time, b.time) || cmp(a.file, b.file) || a.line - b.line);
const capAdd = (set, v, cap) => { if (v && set.size < cap) set.add(v); };

function dayKey(ts, o) { return ts == null ? "unknown" : new Date(ts + o.utcOffset * 3600000).toISOString().slice(0, 10); }

function normalizeRows(list, o) {
  // Rows that are already normalised events (from parseInput) or raw objects (generic table).
  if (!list.length) return [];
  if (list[0] && "bytesOut" in list[0] && "connect" in list[0] && "host" in list[0]) return list;
  const keys = [...new Set(list.slice(0, 50).flatMap((r) => Object.keys(r || {})))];
  const cols = resolveCols(keys, o.columns);
  return list.map((r, i) => { const e = fromCols(flatten(r || {}), cols); e.file = "rows"; e.line = i + 1; return mkEvent(e); });
}

/**
 * Analyze gateway logs. dataset: [{name,text}] | {files} | text | normalised rows | raw row objects.
 * Returns { summary, findings, tables, skipped, meta }.
 */
export function analyze(dataset, opts = {}, ctx) {
  const o = mergeOpts(opts);
  const progress = (i, n, label) => { try { ctx?.progress?.(i, n, label); } catch (_) {} };
  const skipped = [];
  const files = toFiles(dataset);
  const metaFiles = [];
  const fields = {};
  let curInfo = { hasUserField: false };

  // ---- accumulators
  const users = new Map(), apps = new Map(), hosts = new Map(), daily = new Map();
  const malicious = new Map(), ipexe = new Map(), blockedHours = new Map(), scripted = new Map(), emptyUa = new Map();
  const tunnels = [];
  const maliciousSet = o.maliciousIps ? new Map((Array.isArray(o.maliciousIps) ? o.maliciousIps : []).map((x) => (typeof x === "string" ? [x.trim(), { ip: x.trim(), source: "your list" }] : [str(x.ip), x])).filter((x) => x[0])) : null;
  let total = 0, firstTs = null, lastTs = null, squidLines = 0, bytesOutSeen = 0;
  const totalBytes = files.reduce((s, f) => s + f.text.length, 0) || 1;
  let doneBytes = 0;

  const getUser = (key, ev) => {
    let u = users.get(key);
    if (!u) { u = { key, user: ev.user, requests: 0, bytesOut: 0, bytesIn: 0, bytesUnk: 0, blocked: 0, writes: 0, apps: new Set(), srcs: new Set(), first: null, last: null, days: new Map(), ai: new Map(), server: false, flags: new Set(), risk: 0, worst: "" }; users.set(key, u); }
    return u;
  };

  const process = (ev) => {
    total++;
    const ts = ev.ts;
    if (ts != null) { if (firstTs == null || ts < firstTs) firstTs = ts; if (lastTs == null || ts > lastTs) lastTs = ts; }
    const server = (ev.src && o.servers.length && isInternalIp(ev.src, o.servers)) || (!ev.user && curInfo.hasUserField);
    const key = ev.user || (ev.src ? ev.src : "unknown");
    const u = getUser(key, ev);
    if (server) u.server = true;
    u.requests++;
    if (ev.bytesOut != null) { u.bytesOut += ev.bytesOut; bytesOutSeen++; }
    if (ev.bytesIn != null) u.bytesIn += ev.bytesIn;
    if (ev.bytesTotal != null) u.bytesUnk += ev.bytesTotal;
    capAdd(u.srcs, ev.src, 20);
    if (ts != null) { if (u.first == null || ts < u.first) u.first = ts; if (u.last == null || ts > u.last) u.last = ts; }
    const blocked = BLOCK_RE.test(ev.action);
    if (blocked) u.blocked++;
    const write = WRITE_METHODS.has(ev.method) || !!ev.uploaded || /upload|post|share/i.test(ev.activity);
    if (write) u.writes++;
    const day = dayKey(ts, o);
    let dd = daily.get(day);
    if (!dd) { dd = { day, requests: 0, bytesOut: 0, bytesIn: 0, bytesUnk: 0, blocked: 0, users: new Set() }; daily.set(day, dd); }
    dd.requests++; dd.bytesOut += ev.bytesOut || 0; dd.bytesIn += ev.bytesIn || 0; dd.bytesUnk += ev.bytesTotal || 0; if (blocked) dd.blocked++; capAdd(dd.users, key, 100000);
    let ud = u.days.get(day);
    if (!ud) { ud = { day, req: 0, evN: 0, offN: 0, riskyOut: 0, riskyOutZ: 0, riskyWritesUnk: 0, offOut: 0, apps: new Map(), ev: [], offEv: [], wev: [] }; u.days.set(day, ud); }
    ud.req++;

    // Catalogue / app inventory
    const c = classify(ev, o);
    const host = ev.host;
    if (c) {
      let a = apps.get(c.app);
      if (!a) {
        a = { app: c.app, category: c.category, domains: new Set(), users: new Set(), requests: 0, bytesOut: 0, bytesIn: 0, bytesUnk: 0, writes: 0, blocked: 0, first: null, last: null, instances: new Set(), sanctioned: c.sanctioned, mixed: c.mixed, groups: { server: null, user: null } };
        apps.set(c.app, a);
      }
      if (c.sanctioned === "yes") a.sanctioned = "yes";
      capAdd(a.domains, host || c.domain, 10);
      capAdd(a.users, key, 100000);
      if (c.instance) capAdd(a.instances, c.instance, 10);
      a.requests++; a.bytesOut += ev.bytesOut || 0; a.bytesIn += ev.bytesIn || 0; a.bytesUnk += ev.bytesTotal || 0; if (write) a.writes++; if (blocked) a.blocked++;
      if (ts != null) { if (a.first == null || ts < a.first) a.first = ts; if (a.last == null || ts > a.last) a.last = ts; }
      capAdd(u.apps, c.app, 1000);
      const unsanctioned = c.sanctioned !== "yes";
      if (CATEGORIES[c.category].exfil && unsanctioned && !blocked) {
        if (ev.bytesOut != null) {
          if (ev.bytesOut > 0) {
            ud.riskyOut += ev.bytesOut;
            if (c.category !== "genai") ud.riskyOutZ += ev.bytesOut;
            ud.evN++;
            ud.apps.set(c.app, (ud.apps.get(c.app) || 0) + ev.bytesOut);
            pushTop(ud.ev, { ...evRow(ev), appName: c.app, category: CATEGORIES[c.category].label, sanctioned: c.sanctioned }, "bytesOut", EVIDENCE_CAP);
          }
        } else if (write) {
          ud.riskyWritesUnk++;
          ud.apps.set(c.app, ud.apps.get(c.app) || 0);
          pushFirst(ud.wev, { ...evRow(ev), appName: c.app, category: CATEGORIES[c.category].label, sanctioned: c.sanctioned }, EVIDENCE_CAP);
        }
      }
      if (c.category === "genai") {
        let g = u.ai.get(c.app);
        if (!g) { g = { app: c.app, requests: 0, out: 0, writes: 0, sanctioned: c.sanctioned, mixed: c.mixed, ev: [] }; u.ai.set(c.app, g); }
        g.requests++; g.out += ev.bytesOut || 0; if (write) g.writes++;
        pushTop(g.ev, evRow(ev), "bytesOut", 20);
      }
      if (["remote", "anonymizer", "tunnel", "ddns"].includes(c.category) && c.sanctioned !== "yes") {
        const gk = server ? "server" : "user";
        let g = a.groups[gk];
        if (!g) { g = { users: new Set(), srcs: new Set(), requests: 0, blocked: 0, bytes: 0, hosts: new Set(), ev: [] }; a.groups[gk] = g; }
        g.requests++; if (blocked) g.blocked++; g.bytes += (ev.bytesOut || 0) + (ev.bytesIn || 0) + (ev.bytesTotal || 0);
        capAdd(g.users, key, 1000); capAdd(g.srcs, ev.src, 1000); capAdd(g.hosts, host, 20);
        pushFirst(g.ev, evRow(ev), EVIDENCE_CAP);
      }
    }

    // Destinations
    if (host) {
      let h = hosts.get(host);
      if (!h) {
        h = { host, app: c ? c.app : "", appCategory: c ? CATEGORIES[c.category].label : "", category: "", requests: 0, users: new Set(), usersOver: false, bytesOut: 0, bytesIn: 0, bytesUnk: 0, blocked: 0, writes: 0, first: null, last: null, ips: new Set(), uncat: false, ev: [] };
        hosts.set(host, h);
      }
      h.requests++;
      if (!h.users.has(key)) { if (h.users.size < 50) h.users.add(key); else h.usersOver = true; }
      h.bytesOut += ev.bytesOut || 0; h.bytesIn += ev.bytesIn || 0; h.bytesUnk += ev.bytesTotal || 0; if (blocked) h.blocked++; if (write) h.writes++;
      if (ev.category && !h.category) h.category = ev.category;
      if (ev.category && UNCAT_RE.test(ev.category)) h.uncat = true;
      capAdd(h.ips, ev.dst, 5);
      if (ts != null) { if (h.first == null || ts < h.first) h.first = ts; if (h.last == null || ts > h.last) h.last = ts; }
      if ((ev.bytesOut || 0) > 0) pushTop(h.ev, evRow(ev), "bytesOut", 20);
    }

    // Malicious destinations
    if (maliciousSet) {
      const ips = [ev.dst, isIp(host) ? host : ""].filter(Boolean);
      for (const ip of [...new Set(ips)]) {
        const hit = maliciousSet.get(ip);
        if (!hit) continue;
        let m = malicious.get(ip);
        if (!m) { m = { ip, hit, count: 0, users: new Set(), hosts: new Set(), ev: [], first: ts, last: ts }; malicious.set(ip, m); }
        m.count++; capAdd(m.users, key, 1000); capAdd(m.hosts, host, 20); pushFirst(m.ev, evRow(ev), EVIDENCE_CAP);
        if (ts != null) { if (m.first == null || ts < m.first) m.first = ts; if (m.last == null || ts > m.last) m.last = ts; }
      }
    }

    // Direct-to-IP executable download
    if (host && isIp(host) && !isInternalIp(host, o.internal) && !ev.connect) {
      const p = pathOf(ev.url);
      if (EXEC_EXT.test(p) || (ev.filetype && EXEC_FT.test(ev.filetype))) {
        let x = ipexe.get(host);
        if (!x) { x = { host, count: 0, blocked: 0, users: new Set(), ev: [] }; ipexe.set(host, x); }
        x.count++; if (blocked) x.blocked++; capAdd(x.users, key, 1000); pushFirst(x.ev, evRow(ev), EVIDENCE_CAP);
      }
    }

    // Blocked per user per clock hour
    if (blocked && ts != null) {
      const hk = key + "\u0000" + Math.floor(ts / 3600000);
      let b = blockedHours.get(hk);
      if (!b) { b = { key, hour: Math.floor(ts / 3600000), n: 0, hosts: new Set(), cats: new Set(), ev: [] }; blockedHours.set(hk, b); }
      b.n++; capAdd(b.hosts, host, 200); capAdd(b.cats, ev.category, 50); pushFirst(b.ev, evRow(ev), EVIDENCE_CAP);
    }

    // Scripted / empty user agents from workstations to external hosts
    if (ev.ua != null && !server && host && !ev.connect) {
      const external = !(isIp(host) && isInternalIp(host, o.internal)) && !suffixIn(host, o.ownDomains) && !suffixIn(host, o.allowHosts) && !(o.ignoreDevHosts && suffixIn(host, DEV_HOSTS));
      const internalSrc = !ev.src || isInternalIp(ev.src, o.internal);
      if (external && internalSrc) {
        const fam = ev.ua ? scriptedFamily(ev.ua) : null;
        if (fam) {
          const sk = key + "\u0000" + fam;
          let s = scripted.get(sk);
          if (!s) { s = { key, fam, n: 0, hosts: new Set(), uas: new Set(), out: 0, ev: [] }; scripted.set(sk, s); }
          s.n++; s.out += ev.bytesOut || 0; capAdd(s.hosts, host, 50); capAdd(s.uas, ev.ua.slice(0, 120), 10); pushFirst(s.ev, evRow(ev), EVIDENCE_CAP);
        } else if (!ev.ua) {
          let s = emptyUa.get(key);
          if (!s) { s = { key, n: 0, hosts: new Set(), ev: [] }; emptyUa.set(key, s); }
          s.n++; capAdd(s.hosts, host, 50); pushFirst(s.ev, evRow(ev), EVIDENCE_CAP);
        }
      }
    }

    // Off-hours upload volume
    if (ts != null && (ev.bytesOut || 0) > 0 && !blocked && isOffHours(ts, o) && !suffixIn(host, o.ownDomains) && !(isIp(host) && isInternalIp(host, o.internal))) {
      ud.offOut += ev.bytesOut;
      ud.offN++;
      pushTop(ud.offEv, evRow(ev), "bytesOut", EVIDENCE_CAP);
    }

    // Long CONNECT tunnels
    if (ev.connect && ev.elapsedMs != null && tunnels.length < 20000) {
      const bytes = ev.bytesTotal != null ? ev.bytesTotal : (ev.bytesOut || 0) + (ev.bytesIn || 0);
      if (ev.elapsedMs >= o.tunnelMinutes * 60000 && bytes >= o.tunnelMb * MB) tunnels.push({ ev: evRow(ev), host, key, bytes, elapsedMs: ev.elapsedMs });
    }
  };

  // ---- ingest files or rows
  if (files.length) {
    for (const file of files) {
      const det = detectFile(file.name, file.text);
      const info = { parsed: 0, unparsed: 0, fields, hasUserField: false };
      if (det.format === "unknown" || det.format === "empty") {
        metaFiles.push({ name: file.name, format: det.format, label: det.label, confidence: det.confidence, records: 0, unparsed: 0 });
        if (det.format === "unknown") skipped.push({ check: "parse", reason: file.name + ": format not recognised; map its columns or export CSV with a header row" });
        doneBytes += file.text.length;
        continue;
      }
      // iterEvents sets info.hasUserField before yielding the first record of a file.
      curInfo = info;
      let i = 0;
      for (const ev of iterEvents(file, det, info, o.columns)) {
        process(ev);
        if (++i % 5000 === 0) progress(Math.min(doneBytes + Math.round((ev.line / Math.max(1, countLinesFast(file))) * file.text.length), totalBytes), totalBytes, file.name + ": " + i + " records");
      }
      if (det.format === "squid") squidLines += info.parsed;
      doneBytes += file.text.length;
      progress(doneBytes, totalBytes, file.name + ": " + info.parsed + " records");
      metaFiles.push({ name: file.name, format: det.format, label: det.label, confidence: det.confidence, records: info.parsed, unparsed: info.unparsed });
      if (info.unparsed) skipped.push({ check: "parse", reason: file.name + ": " + info.unparsed + " line(s) did not match " + det.label });
    }
  } else {
    const list = Array.isArray(dataset) ? dataset : dataset && Array.isArray(dataset.rows) ? dataset.rows : [];
    const evs = normalizeRows(list, o);
    curInfo = { hasUserField: evs.some((e) => e.user) };
    const mark = (ev) => { for (const k of ["ts", "user", "src", "dst", "host", "method", "bytesOut", "bytesIn", "bytesTotal", "category", "app", "action", "filetype"]) if (ev[k] != null && ev[k] !== "") fields[k] = true; if (ev.ua != null) fields.uaField = true; if (ev.connect) fields.connect = true; if (ev.elapsedMs != null) fields.elapsed = true; };
    evs.forEach((ev, i) => { mark(ev); process(ev); if (i % 5000 === 0) progress(i, evs.length, i + " records"); });
    metaFiles.push({ name: "rows", format: "rows", label: "Rows", confidence: 1, records: evs.length, unparsed: 0 });
  }

  // ---- skipped checks (missing columns)
  const skip = (check, reason) => skipped.push({ check, reason });
  if (!fields.host && !fields.app) skip("app_inventory", "no destination host, URL or application column; shadow-SaaS and category checks need one");
  if (!fields.bytesOut) skip("upload_volume", "no upload byte column (bytes sent / reqsize / client_bytes / srcBytes); exfiltration uses POST/PUT counts instead, which shows that uploads happened but not how much");
  if (squidLines) skip("upload_volume (Squid native)", squidLines + " Squid native line(s): the bytes field is the reply size sent to the client, and for CONNECT tunnels it counts the whole tunnel in both directions. Upload volume cannot be separated, so these lines feed the POST/PUT count and the long-tunnel check only. Export a custom logformat with %>st (request size) and %<st (reply size) and a header row, then map them, to measure uploads.");
  if (!fields.ts) skip("time_based", "no timestamp column; per-day baselines, off-hours, new-app and blocked-spike checks are off");
  if (!fields.action) skip("blocked_spike", "no action / verdict column");
  if (!fields.uaField) skip("scripted_user_agent", "no user-agent column");
  if (!(fields.connect && fields.elapsed)) skip("long_connect_tunnel", "needs CONNECT records with a duration (Squid native access.log)");
  if (!maliciousSet) skip("malicious_destination", "malicious-IP list not loaded (turn on the mirrored feed or paste your own IPs)");
  else if (!fields.dst && !fields.host) skip("malicious_destination", "no destination IP column");
  if (!fields.category) skip("uncategorized_upload", "no URL category column; rare hosts with high upload are still checked when bytes sent are logged");
  const spanDays = firstTs != null ? (lastTs - firstTs) / 86400000 : 0;
  if (fields.ts && spanDays < o.newAppDays * 2) skip("new_app", "log spans " + spanDays.toFixed(1) + " day(s); new-app discovery needs at least " + o.newAppDays * 2 + " (" + o.newAppDays + " days of history before the recent window)");

  // ---- findings
  const findings = [];
  const add = (f) => {
    const evidence = (f.evidence || []).slice(0, EVIDENCE_CAP);
    const full = { id: TOOL_ID + "-" + f.rule + "-" + cyrb(f.rule + "|" + f.entity), ...f, evidence, evidenceCount: f.evidenceCount != null ? f.evidenceCount : evidence.length };
    findings.push(full);
    const keys = new Set([f.userKey || f.entity, ...(f.assets || []).filter((a) => a.type === "IDENTITY" || a.type === "IP").map((a) => a.name)]);
    for (const k of [...keys].sort()) {
      const u = users.get(k);
      if (u) { u.flags.add(f.rule); u.risk += { critical: 20, high: 10, medium: 4, low: 1, info: 0 }[f.severity]; if (!u.worst || SEV_RANK[f.severity] > SEV_RANK[u.worst]) u.worst = f.severity; }
    }
  };
  const idAsset = (k) => ({ type: isIp(k) ? "IP" : "IDENTITY", name: k });
  const userKeys = [...users.keys()].sort();

  // 1. Upload exfiltration per user per day (absolute or robust z vs own baseline)
  const exfilByUser = new Set();
  for (const k of userKeys) {
    const u = users.get(k);
    const days = [...u.days.values()].filter((d) => d.day !== "unknown").sort((a, b) => cmp(a.day, b.day));
    const hits = [];
    for (const d of days) {
      if (d.riskyOut <= 0) continue;
      // Absolute rule: every exfil category. z rule: AI uploads are left to the AI check.
      const others = days.filter((x) => x.day !== d.day).map((x) => x.riskyOutZ);
      const absHit = d.riskyOut >= o.uploadMb * MB;
      let zInfo = null, zHit = false;
      if (others.length >= o.baselineDays && d.riskyOutZ > 0) {
        zInfo = robustZ(d.riskyOutZ, others);
        zHit = d.riskyOutZ >= o.zMinMb * MB && (zInfo.z == null ? d.riskyOutZ > zInfo.median : zInfo.z > o.uploadZ);
      }
      if (absHit || zHit) hits.push({ d, absHit, zHit, zInfo, baseN: others.length });
    }
    if (hits.length) {
      exfilByUser.add(k);
      const totalOut = hits.reduce((s, h) => s + h.d.riskyOut, 0);
      const appTotals = new Map();
      for (const h of hits) for (const [a, b] of h.d.apps) appTotals.set(a, (appTotals.get(a) || 0) + b);
      const appList = [...appTotals].sort((a, b) => b[1] - a[1] || cmp(a[0], b[0]));
      const cats = [...new Set(appList.map(([a]) => apps.get(a) && apps.get(a).category))].filter(Boolean);
      const anyAbs = hits.some((h) => h.absHit);
      const allMixed = appList.every(([a]) => apps.get(a) && apps.get(a).sanctioned === "unknown");
      const ev = sortEv(hits.flatMap((h) => h.d.ev), "bytesOut");
      const dayTxt = hits.map((h) => h.d.day + " " + fmtBytes(h.d.riskyOut) + (h.zInfo ? (h.zInfo.z == null ? " (baseline constant at " + fmtBytes(h.zInfo.median) + " over " + h.baseN + " days)" : " (robust z " + h.zInfo.z.toFixed(1) + " vs median " + fmtBytes(h.zInfo.median) + ", " + h.zInfo.method + " over " + h.baseN + " days)") : " (baseline too short: " + h.baseN + " other days, need " + o.baselineDays + ")")).join("; ");
      const controls = CONTROLS.exfil.concat(cats.includes("paste") ? CONTROLS.paste : []);
      add({
        rule: "upload_exfil", entity: k, title: "Large upload to unsanctioned " + cats.map((c) => CATEGORIES[c].label.toLowerCase()).join(" / ") + ": " + k,
        severity: "high", confidence: anyAbs && !allMixed ? "likely" : "review", category: "Exfiltration",
        description: k + " sent " + fmtBytes(totalOut) + " to " + appList.map(([a, b]) => a + " (" + fmtBytes(b) + ")").join(", ") + " on " + hits.length + " day(s): " + dayTxt + ". Thresholds: " + o.uploadMb + " MB per day, or robust z > " + o.uploadZ + " with at least " + o.zMinMb + " MB and " + o.baselineDays + " baseline days." + (allMixed ? " The instance (personal or corporate) of these apps is not in the log; add them to the sanctioned list if your company uses them." : ""),
        recommendation: "Confirm with the user and their manager what was uploaded; pull the gateway DLP / file-name logs for these sessions; if not business use, revoke the session, block uploads to these services for this user and preserve evidence.",
        controls, evidence: ev, evidenceCount: hits.reduce((s, h) => s + h.d.evN, 0),
        assets: [idAsset(k), ...[...new Set(ev.map((e) => e.host))].slice(0, 5).map((h) => ({ type: "DOMAIN", name: h }))],
        firstSeen: hits[0].d.day, lastSeen: hits[hits.length - 1].d.day, tags: ["exfiltration", ...cats],
      });
    }
    // Writes without byte counts
    const wHits = days.filter((d) => d.riskyWritesUnk >= o.uploadWrites);
    if (wHits.length && !exfilByUser.has(k)) {
      const ev = wHits.flatMap((d) => d.wev);
      const appsW = [...new Set(wHits.flatMap((d) => [...d.apps.keys()]))].sort();
      add({
        rule: "upload_writes", entity: k, title: "Many uploads (POST/PUT) to unsanctioned storage, transfer, paste, webmail or AI: " + k,
        severity: "medium", confidence: "review", category: "Exfiltration",
        description: k + " made " + wHits.map((d) => d.riskyWritesUnk + " uploads on " + d.day).join(", ") + " to " + appsW.join(", ") + " (threshold " + o.uploadWrites + " per day). The log does not record upload bytes for these requests, so the volume is unknown.",
        recommendation: "Pull the full session from the gateway (with request sizes or DLP verdicts) to measure what left; confirm with the user.",
        controls: CONTROLS.exfil, evidence: ev, evidenceCount: wHits.reduce((s, d) => s + d.riskyWritesUnk, 0),
        assets: [idAsset(k)], firstSeen: wHits[0].day, lastSeen: wHits[wHits.length - 1].day, tags: ["exfiltration"],
      });
    }
  }

  // 2. Generative AI
  const aiApps = [...apps.values()].filter((a) => a.category === "genai").sort((a, b) => cmp(a.app, b.app));
  if (aiApps.length) {
    const inv = [];
    for (const k of userKeys) for (const g of [...users.get(k).ai.values()].sort((a, b) => cmp(a.app, b.app))) inv.push({ app: g.app, user: k, requests: g.requests, bytesOut: g.out, uploads: g.writes, sanctioned: g.sanctioned });
    add({
      rule: "genai_inventory", entity: "all", title: "Generative AI services in use: " + aiApps.length + " service(s), " + new Set(inv.map((r) => r.user)).size + " user(s)",
      severity: "info", confidence: "confirmed", category: "Generative AI",
      description: aiApps.map((a) => a.app + " (" + a.users.size + " users, " + a.requests + " requests, " + fmtBytes(a.bytesOut) + " sent, sanctioned: " + a.sanctioned + ")").join("; ") + ".",
      recommendation: "Review against your AI acceptable-use policy; route approved services through an enterprise tenant with data controls and block or coach on the rest.",
      controls: CONTROLS.genai, evidence: inv.sort((a, b) => b.bytesOut - a.bytesOut || cmp(a.app, b.app) || cmp(a.user, b.user)), evidenceCount: inv.length,
      assets: aiApps.map((a) => ({ type: "ASSET", name: a.app, data: { kind: "saas-app", category: CATEGORIES[a.category].label, users: a.users.size } })), tags: ["genai", "inventory"],
    });
    if (fields.bytesOut) {
      for (const k of userKeys) {
        const u = users.get(k);
        for (const g of [...u.ai.values()].sort((a, b) => cmp(a.app, b.app))) {
          if (g.sanctioned === "yes" || g.out < o.aiUploadMb * MB) continue;
          if (exfilByUser.has(k) && findings.some((f) => f.rule === "upload_exfil" && f.entity === k && f.description.includes(g.app + " ("))) continue;
          add({
            rule: "genai_upload", entity: k + " / " + g.app, userKey: k, title: "Large upload to " + g.app + ": " + k,
            severity: "medium", confidence: g.sanctioned === "unknown" ? "review" : "likely", category: "Generative AI",
            description: k + " sent " + fmtBytes(g.out) + " in " + g.requests + " requests to " + g.app + " (unsanctioned; threshold " + o.aiUploadMb + " MB over the log period). Large uploads to AI chat services are usually pasted documents or files.",
            recommendation: "Ask what was shared; if it was confidential, follow the data-handling procedure and move the user to an approved AI service.",
            controls: CONTROLS.genai, evidence: sortEv(g.ev, "bytesOut"), evidenceCount: g.requests,
            assets: [idAsset(k), { type: "ASSET", name: g.app, data: { kind: "saas-app", category: "Generative AI", users: apps.get(g.app).users.size } }], tags: ["genai"],
          });
        }
      }
    } else skip("genai_upload", "no upload byte column; AI usage is inventoried but upload volume is unknown");
  }

  // 3. Shadow SaaS inventory and new apps
  const appRows = [...apps.values()].sort((a, b) => b.users.size - a.users.size || b.requests - a.requests || cmp(a.app, b.app));
  const recentFrom = lastTs != null ? lastTs - o.newAppDays * 86400000 : null;
  const canNew = fields.ts && spanDays >= o.newAppDays * 2;
  const unsanctionedApps = appRows.filter((a) => a.sanctioned !== "yes");
  if (unsanctionedApps.length) {
    add({
      rule: "shadow_saas", entity: "all", title: "Unsanctioned apps discovered: " + unsanctionedApps.length,
      severity: "info", confidence: "confirmed", category: "Shadow SaaS",
      description: unsanctionedApps.length + " catalogued apps in risky categories were used without being on the sanctioned list (" + unsanctionedApps.filter((a) => a.sanctioned === "unknown").length + " of them are mixed corporate/personal services whose instance is unknown). Sanctioned list: " + (o.sanctioned.length ? o.sanctioned.length + " entries" : "empty") + ".",
      recommendation: "Send the shadow-SaaS inventory to the SaaS governance owner: sanction (and add here), replace, or block each app.",
      controls: CONTROLS.saas, evidence: unsanctionedApps.slice(0, EVIDENCE_CAP).map((a) => ({ app: a.app, category: CATEGORIES[a.category].label, sanctioned: a.sanctioned, users: a.users.size, requests: a.requests, bytesOut: a.bytesOut, first: iso(a.first), last: iso(a.last) })), evidenceCount: unsanctionedApps.length,
      assets: unsanctionedApps.slice(0, EVIDENCE_CAP).map((a) => ({ type: "ASSET", name: a.app, data: { kind: "saas-app", category: CATEGORIES[a.category].label, users: a.users.size } })), tags: ["shadow-saas", "inventory"],
    });
  }
  if (canNew) {
    for (const a of unsanctionedApps) {
      if (a.first == null || a.first < recentFrom) continue;
      // Remote access, anonymizers, tunnels and DDNS already get their own findings.
      if (!["storage", "transfer", "paste", "webmail", "genai", "crypto"].includes(a.category)) continue;
      add({
        rule: "new_app", entity: a.app, title: "New " + CATEGORIES[a.category].label.toLowerCase() + " app first seen: " + a.app,
        severity: "low", confidence: "review", category: "Shadow SaaS",
        description: a.app + " was first seen " + iso(a.first) + ", within the last " + o.newAppDays + " days of a " + spanDays.toFixed(1) + "-day log; " + a.users.size + " user(s), " + a.requests + " requests, " + fmtBytes(a.bytesOut) + " sent.",
        recommendation: "Decide whether to sanction or block it before adoption spreads.",
        controls: CONTROLS.saas, evidence: [{ app: a.app, category: CATEGORIES[a.category].label, users: [...a.users].sort().join(", ").slice(0, 300), requests: a.requests, bytesOut: a.bytesOut, first: iso(a.first), last: iso(a.last) }], evidenceCount: 1,
        assets: [{ type: "ASSET", name: a.app, data: { kind: "saas-app", category: CATEGORIES[a.category].label, users: a.users.size } }], tags: ["shadow-saas", "new"],
      });
    }
  }

  // 4. Anonymizers, remote access, tunnels, dynamic DNS
  const sevDown = { high: "medium", medium: "low", low: "low", info: "info" };
  for (const a of appRows) {
    if (!["remote", "anonymizer", "tunnel", "ddns"].includes(a.category) || a.sanctioned === "yes") continue;
    for (const gk of ["server", "user"]) {
      const g = a.groups[gk];
      if (!g) continue;
      const tor = /tor/i.test(a.app);
      let sev = gk === "server" ? "high" : "medium";
      const allBlocked = g.blocked === g.requests;
      if (allBlocked) sev = sevDown[sev];
      const controls = a.category === "remote" ? CONTROLS.remote : a.category === "tunnel" ? CONTROLS.tunnel : a.category === "ddns" ? CONTROLS.ddns : CONTROLS.anonymizer.concat(tor ? CONTROLS.tor : []);
      const who = gk === "server" ? "server / non-user sources" : "users";
      add({
        rule: a.category + "_" + gk, entity: a.app + " (" + gk + ")", userKey: g.users.size === 1 ? [...g.users][0] : undefined,
        title: CATEGORIES[a.category].label + " from " + who + ": " + a.app,
        severity: sev, confidence: a.category === "ddns" ? "review" : "likely", category: CATEGORIES[a.category].label,
        description: g.requests + " request(s) to " + [...g.hosts].sort().join(", ") + " from " + [...g.users].sort().slice(0, 10).join(", ") + (g.users.size > 10 ? " and " + (g.users.size - 10) + " more" : "") + " (" + fmtBytes(g.bytes) + ")" + (allBlocked ? "; every request was blocked by the gateway" : g.blocked ? "; " + g.blocked + " blocked" : "") + "." +
          (gk === "server" ? " The source is a server range or has no authenticated user, which is how an attacker-run tunnel or remote tool usually looks." : ""),
        recommendation: a.category === "remote" ? "Confirm the session was an approved support case; otherwise isolate the host, remove the tool and block the vendor's relay domains." :
          a.category === "tunnel" ? "Identify the process holding the tunnel on the source host; tunnelling services expose internal services to the internet and bypass inbound controls. Block the service domains." :
          a.category === "ddns" ? "Review what the host resolves and fetches on the dynamic-DNS name; block dynamic-DNS categories unless needed." :
          "Block anonymizer / proxy-avoidance categories and talk to the user; on a server treat it as a possible command-and-control channel.",
        controls, evidence: g.ev, evidenceCount: g.requests,
        assets: [...[...g.users].sort().slice(0, 10).map(idAsset), ...[...g.hosts].sort().slice(0, 5).map((h) => ({ type: "DOMAIN", name: h }))], tags: [a.category, gk],
      });
    }
  }

  // 5. Malicious destinations
  for (const m of [...malicious.values()].sort((a, b) => cmp(a.ip, b.ip))) {
    add({
      rule: "malicious_ip", entity: m.ip, userKey: m.users.size === 1 ? [...m.users][0] : undefined, title: "Traffic to a listed malicious IP: " + m.ip,
      severity: "high", confidence: "likely", category: "Threat intel",
      description: m.count + " request(s) from " + [...m.users].sort().join(", ") + " to " + m.ip + (m.hosts.size ? " (" + [...m.hosts].sort().join(", ") + ")" : "") + ". Listed by " + (m.hit.source || "the malicious-IP list") + (m.hit.score != null ? " (score " + m.hit.score + ")" : "") + ".",
      recommendation: "Check the source hosts for compromise (EDR, running processes, persistence) and block the IP at the gateway and firewall.",
      controls: CONTROLS.malicious, evidence: m.ev, evidenceCount: m.count, assets: [{ type: "IP", name: m.ip }, ...[...m.users].sort().slice(0, 10).map(idAsset)],
      firstSeen: iso(m.first), lastSeen: iso(m.last), tags: ["threat-intel"],
    });
  }

  // 6a. Uncategorized / rare destinations with high upload
  if (fields.bytesOut) {
    for (const h of [...hosts.values()].sort((a, b) => cmp(a.host, b.host))) {
      if (h.app || h.bytesOut < o.uncatUploadMb * MB) continue;
      if (suffixIn(h.host, o.ownDomains) || suffixIn(h.host, o.allowHosts) || (isIp(h.host) && isInternalIp(h.host, o.internal))) continue;
      const rare = !h.usersOver && h.users.size <= o.rareUsers;
      if (!(h.uncat || (rare && !h.category))) continue;
      const us = [...h.users].sort();
      add({
        rule: "uncat_upload", entity: h.host, userKey: us.length === 1 ? us[0] : undefined, title: "High upload to " + (h.uncat ? "an uncategorized" : "a rare, unclassified") + " destination: " + h.host,
        severity: "high", confidence: "review", category: "Exfiltration",
        description: fmtBytes(h.bytesOut) + " sent to " + h.host + " by " + us.join(", ") + " in " + h.requests + " request(s); gateway category: " + (h.category || "none") + "; users reaching it: " + h.users.size + (h.usersOver ? "+" : "") + " (rare = " + o.rareUsers + " or fewer). Threshold " + o.uncatUploadMb + " MB.",
        recommendation: "Look up the destination (registration date, hosting, reputation) and the process that sent the data; block it if it is not a known business partner.",
        controls: CONTROLS.uncat, evidence: sortEv(h.ev, "bytesOut"), evidenceCount: h.requests, assets: [{ type: "DOMAIN", name: h.host }, ...us.slice(0, 5).map(idAsset)],
        firstSeen: iso(h.first), lastSeen: iso(h.last), tags: ["exfiltration", "uncategorized"],
      });
    }
  }
  // 6b. Direct-to-IP executable downloads
  for (const x of [...ipexe.values()].sort((a, b) => cmp(a.host, b.host))) {
    const us = [...x.users].sort();
    add({
      rule: "ip_executable", entity: x.host, userKey: us.length === 1 ? us[0] : undefined, title: "Executable fetched straight from an IP address: " + x.host,
      severity: x.blocked === x.count ? "medium" : "high", confidence: "likely", category: "Malware delivery",
      description: x.count + " request(s) by " + us.join(", ") + " for executable or script content (.exe/.dll/.ps1/.hta/.js/.vbs/.iso/.lnk and similar, by URL extension or gateway file type) from http(s)://" + x.host + "/ with no hostname" + (x.blocked ? "; " + x.blocked + " blocked" : "") + ".",
      recommendation: "Find the file on the endpoint (hash, signer) and the parent process; hostless downloads of executables are a common stage-two delivery pattern. Block direct-to-IP executable downloads at the gateway.",
      controls: CONTROLS.ipexe, evidence: x.ev, evidenceCount: x.count, assets: [{ type: "IP", name: x.host }, ...us.slice(0, 5).map(idAsset)], tags: ["malware-delivery"],
    });
  }

  // 7. Blocked-attempt spikes
  if (fields.action && fields.ts) {
    const best = new Map();
    for (const b of blockedHours.values()) {
      if (b.n < o.blockedPerHour || b.hosts.size < o.blockedHosts) continue;
      const cur = best.get(b.key);
      if (!cur || b.n > cur.n || (b.n === cur.n && b.hour < cur.hour)) best.set(b.key, b);
    }
    for (const k of [...best.keys()].sort()) {
      const b = best.get(k);
      const hours = [...blockedHours.values()].filter((x) => x.key === k && x.n >= o.blockedPerHour && x.hosts.size >= o.blockedHosts).length;
      add({
        rule: "blocked_spike", entity: k, title: "Burst of blocked requests (policy probing?): " + k,
        severity: "medium", confidence: "review", category: "Policy evasion",
        description: k + " had " + b.n + " blocked requests to " + b.hosts.size + " hosts in the hour starting " + iso(b.hour * 3600000) + " (thresholds " + o.blockedPerHour + " requests and " + o.blockedHosts + " hosts per hour; " + hours + " such hour(s)). Categories: " + ([...b.cats].sort().join(", ") || "not logged") + ".",
        recommendation: "Review what the user was trying to reach; repeated attempts across many blocked hosts often mean searching for a way around policy (proxies, file sharing) or malware cycling through fallback domains.",
        controls: CONTROLS.blocked, evidence: b.ev, evidenceCount: b.n, assets: [idAsset(k)], firstSeen: iso(b.hour * 3600000), tags: ["blocked"],
      });
    }
  }

  // 8. Scripted and empty user agents
  if (fields.uaField) {
    for (const s of [...scripted.values()].sort((a, b) => cmp(a.key, b.key) || cmp(a.fam, b.fam))) {
      if (s.n < o.scriptedMin) continue;
      add({
        rule: "scripted_ua", entity: s.key + " / " + s.fam, userKey: s.key, title: s.fam + " client on a workstation reaching external hosts: " + s.key,
        severity: s.out >= o.uncatUploadMb * MB ? "medium" : "low", confidence: "review", category: "Scripted client",
        description: s.n + " request(s) with a " + s.fam + " user agent (" + [...s.uas].sort().join(" | ") + ") to " + [...s.hosts].sort().slice(0, 10).join(", ") + (s.hosts.size > 10 ? " and more" : "") + "; " + fmtBytes(s.out) + " sent. Not from a server range; destination not internal, own or allow-listed" + (o.ignoreDevHosts ? "; package registries and update hosts ignored" : "") + ".",
        recommendation: "Ask the user or check EDR for the process; scripted clients on workstations are common for developers but also for malware and data staging. Add legitimate destinations to the allow-list.",
        controls: CONTROLS.scripted, evidence: s.ev, evidenceCount: s.n, assets: [idAsset(s.key), ...[...s.hosts].sort().slice(0, 5).map((h) => ({ type: "DOMAIN", name: h }))], tags: ["user-agent"],
      });
    }
    for (const s of [...emptyUa.values()].sort((a, b) => cmp(a.key, b.key))) {
      if (s.n < o.emptyUaMin) continue;
      add({
        rule: "empty_ua", entity: s.key, title: "Requests with no user agent: " + s.key,
        severity: "low", confidence: "review", category: "Scripted client",
        description: s.n + " request(s) with an empty user agent to " + [...s.hosts].sort().slice(0, 10).join(", ") + " (threshold " + o.emptyUaMin + ").",
        recommendation: "Identify the process; browsers always send a user agent, so empty ones come from tools, services or malware.",
        controls: CONTROLS.scripted, evidence: s.ev, evidenceCount: s.n, assets: [idAsset(s.key)], tags: ["user-agent"],
      });
    }
  }

  // 9. Off-hours large transfers
  if (fields.bytesOut && fields.ts) {
    for (const k of userKeys) {
      const u = users.get(k);
      const days = [...u.days.values()].filter((d) => d.offOut >= o.offHoursMb * MB).sort((a, b) => cmp(a.day, b.day));
      if (!days.length) continue;
      add({
        rule: "offhours_upload", entity: k, title: "Large upload outside business hours: " + k,
        severity: "medium", confidence: "likely", category: "Exfiltration",
        description: k + " sent " + days.map((d) => fmtBytes(d.offOut) + " on " + d.day).join(", ") + " outside business hours (" + o.businessStart + ":00-" + o.businessEnd + ":00 UTC" + (o.utcOffset >= 0 ? "+" : "") + o.utcOffset + (o.weekendOffHours ? ", weekends off" : "") + "; threshold " + o.offHoursMb + " MB per day).",
        recommendation: "Confirm the user was working at that time and what was transferred; off-hours bulk uploads are a common exfiltration pattern.",
        controls: CONTROLS.offhours, evidence: sortEv(days.flatMap((d) => d.offEv), "bytesOut"), evidenceCount: days.reduce((s, d) => s + d.offN, 0),
        assets: [idAsset(k)], firstSeen: days[0].day, lastSeen: days[days.length - 1].day, tags: ["off-hours"],
      });
    }
  }

  // 10. Long CONNECT tunnels to rare hosts
  if (fields.connect && fields.elapsed) {
    const byHost = new Map();
    for (const t of tunnels) {
      const h = hosts.get(t.host);
      if (!h || h.usersOver || h.users.size > o.rareUsers) continue;
      if (suffixIn(t.host, o.ownDomains) || suffixIn(t.host, o.allowHosts)) continue;
      const c = classify({ host: t.host, app: "", instance: "" }, o);
      if (c && c.sanctioned === "yes") continue;
      let g = byHost.get(t.host);
      if (!g) { g = { host: t.host, list: [], users: new Set() }; byHost.set(t.host, g); }
      g.list.push(t); g.users.add(t.key);
    }
    for (const g of [...byHost.values()].sort((a, b) => cmp(a.host, b.host))) {
      const bytes = g.list.reduce((s, t) => s + t.bytes, 0), maxMin = Math.max(...g.list.map((t) => t.elapsedMs)) / 60000;
      const us = [...g.users].sort();
      add({
        rule: "long_tunnel", entity: g.host, userKey: us.length === 1 ? us[0] : undefined, title: "Long-lived CONNECT tunnel with high volume to a rare host: " + g.host,
        severity: "medium", confidence: "review", category: "Tunnel",
        description: g.list.length + " CONNECT tunnel(s) from " + us.join(", ") + " to " + g.host + ", longest " + maxMin.toFixed(0) + " min, " + fmtBytes(bytes) + " in both directions (Squid does not split upload and download). Thresholds " + o.tunnelMinutes + " min and " + o.tunnelMb + " MB; rare = " + o.rareUsers + " or fewer users.",
        recommendation: "Check what process held the tunnel; long encrypted sessions to a host nobody else uses can be exfiltration or a C2 channel.",
        controls: CONTROLS.tunnelConnect, evidence: g.list.map((t) => ({ ...t.ev, minutes: Math.round(t.elapsedMs / 60000) })), evidenceCount: g.list.length,
        assets: [{ type: "DOMAIN", name: g.host }, ...us.slice(0, 5).map(idAsset)], tags: ["tunnel"],
      });
    }
  }

  findings.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || CONF_RANK[b.confidence] - CONF_RANK[a.confidence] || cmp(a.rule, b.rule) || cmp(a.entity, b.entity));

  // ---- tables
  const tables = {
    users: [...users.values()].map((u) => ({
      user: u.key, server: u.server, requests: u.requests, bytesOut: u.bytesOut, bytesIn: u.bytesIn, bytesUnknown: u.bytesUnk, blocked: u.blocked, uploads: u.writes,
      apps: u.apps.size, riskyApps: [...u.apps].filter((a) => apps.get(a) && apps.get(a).sanctioned !== "yes").length, sources: [...u.srcs].sort().join(", "),
      first: iso(u.first), last: iso(u.last), flags: [...u.flags].sort().join(", "), risk: u.risk, worst: u.worst,
    })).sort((a, b) => b.risk - a.risk || b.bytesOut - a.bytesOut || b.requests - a.requests || cmp(a.user, b.user)),
    apps: appRows.map((a) => ({
      app: a.app, category: CATEGORIES[a.category].label, sanctioned: a.sanctioned, instance: [...a.instances].sort().join(", "), domains: [...a.domains].sort().join(", "),
      users: a.users.size, requests: a.requests, uploads: a.writes, bytesOut: a.bytesOut, bytesIn: a.bytesIn, bytesUnknown: a.bytesUnk, blocked: a.blocked,
      first: iso(a.first), last: iso(a.last), isNew: !!(canNew && a.first != null && a.first >= recentFrom),
    })),
    destinations: [...hosts.values()].sort((a, b) => (b.bytesOut + b.bytesIn + b.bytesUnk) - (a.bytesOut + a.bytesIn + a.bytesUnk) || b.requests - a.requests || cmp(a.host, b.host)).slice(0, 2000).map((h) => ({
      host: h.host, app: h.app, appCategory: h.appCategory, category: h.category, requests: h.requests, users: h.users.size + (h.usersOver ? "+" : ""), bytesOut: h.bytesOut, bytesIn: h.bytesIn, bytesUnknown: h.bytesUnk,
      uploads: h.writes, blocked: h.blocked, ips: [...h.ips].sort().join(", "), first: iso(h.first), last: iso(h.last), malicious: [...h.ips].some((ip) => malicious.has(ip)) || malicious.has(h.host),
    })),
    daily: [...daily.values()].sort((a, b) => cmp(a.day, b.day)).map((d) => ({ day: d.day, requests: d.requests, users: d.users.size, bytesOut: d.bytesOut, bytesIn: d.bytesIn, bytesUnknown: d.bytesUnk, blocked: d.blocked })),
  };

  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) bySeverity[f.severity]++;
  const summary = {
    requests: total, users: users.size, apps: apps.size, unsanctionedApps: unsanctionedApps.length,
    exfilCandidates: new Set(findings.filter((f) => ["upload_exfil", "upload_writes", "uncat_upload", "offhours_upload"].includes(f.rule)).map((f) => f.userKey || f.entity)).size,
    aiServices: aiApps.length, aiUsers: new Set(aiApps.flatMap((a) => [...a.users])).size, findings: findings.length, bySeverity,
    bytesOut: tables.users.reduce((s, u) => s + u.bytesOut, 0), bytesIn: tables.users.reduce((s, u) => s + u.bytesIn, 0),
    firstTs: iso(firstTs), lastTs: iso(lastTs), spanDays: Math.round(spanDays * 10) / 10, hosts: hosts.size,
  };
  progress(totalBytes, totalBytes, "done");
  return {
    summary, findings, tables, skipped,
    meta: { tool: TOOL_ID, version: VERSION, rows: total, files: metaFiles, fieldsSeen: Object.keys(fields).sort(), settings: { uploadMb: o.uploadMb, uploadZ: o.uploadZ, baselineDays: o.baselineDays, businessStart: o.businessStart, businessEnd: o.businessEnd, utcOffset: o.utcOffset, sanctioned: o.sanctioned.length } },
  };
}

const lineCounts = new WeakMap();
function countLinesFast(file) {
  // Estimated total lines for progress only (cached per file object).
  if (lineCounts.has(file)) return lineCounts.get(file);
  let n = 1;
  for (let i = file.text.indexOf("\n"); i >= 0; i = file.text.indexOf("\n", i + 1)) n++;
  lineCounts.set(file, n);
  return n;
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
const q = (v) => '"' + String(v == null ? "" : v).replace(/"/g, '""') + '"';
const FINDING_COLS = ["id", "severity", "confidence", "category", "title", "entity", "description", "recommendation", "controls", "evidenceCount", "firstSeen", "lastSeen"];
/** Findings as CSV with fixed columns. */
export function findingsToCsv(findings) {
  const body = (findings || []).map((f) => [f.id, f.severity, f.confidence, f.category, f.title, f.entity, f.description, f.recommendation,
    (f.controls || []).map((c) => c.framework + " " + c.id).join("; "), f.evidenceCount != null ? f.evidenceCount : (f.evidence || []).length, f.firstSeen, f.lastSeen].map(q).join(","));
  return [FINDING_COLS.join(","), ...body].join("\n") + "\n";
}
const APP_COLS = ["app", "category", "sanctioned", "instance", "domains", "users", "requests", "uploads", "bytesOut", "bytesIn", "bytesUnknown", "blocked", "first", "last", "isNew"];
/** Shadow-SaaS inventory CSV for the SaaS governance team. */
export function shadowSaasCsv(appsTable) {
  return [APP_COLS.join(","), ...(appsTable || []).map((a) => APP_COLS.map((k) => q(a[k])).join(","))].join("\n") + "\n";
}
const TABLE_COLS = {
  users: ["user", "server", "requests", "bytesOut", "bytesIn", "bytesUnknown", "uploads", "blocked", "apps", "riskyApps", "risk", "worst", "flags", "sources", "first", "last"],
  destinations: ["host", "app", "appCategory", "category", "requests", "users", "bytesOut", "bytesIn", "bytesUnknown", "uploads", "blocked", "ips", "malicious", "first", "last"],
  daily: ["day", "requests", "users", "bytesOut", "bytesIn", "bytesUnknown", "blocked"],
};
export function tableToCsv(name, rows) {
  const cols = TABLE_COLS[name] || (rows && rows[0] ? Object.keys(rows[0]) : []);
  return [cols.join(","), ...(rows || []).map((r) => cols.map((k) => q(r[k])).join(","))].join("\n") + "\n";
}
/** Domains named by confirmed / likely findings (catalogued SaaS stays out unless it is a tunnel, DDNS or anonymizer). */
export function blocklistText(findings) {
  const set = new Set();
  for (const f of findings || []) {
    if (!["confirmed", "likely"].includes(f.confidence) || !["critical", "high", "medium"].includes(f.severity)) continue;
    for (const a of f.assets || []) {
      if (a.type !== "DOMAIN" && !(a.type === "IP" && f.rule !== "upload_exfil")) continue;
      const c = a.type === "DOMAIN" ? matchHost(a.name) : null;
      if (c && !["tunnel", "ddns", "anonymizer", "remote"].includes(c.category)) continue;
      set.add(a.name);
    }
  }
  const list = [...set].sort();
  return "# Web Gateway Hunt blocklist - domains and IPs from confirmed / likely findings\n# Review before importing into the gateway.\n" + list.join("\n") + (list.length ? "\n" : "");
}
/** Per-user activity report (all users with findings, or the given user keys). */
export function userReportText(result, only) {
  const r = result || {};
  const rows = ((r.tables && r.tables.users) || []).filter((u) => (only && only.length ? only.includes(u.user) : u.flags));
  const out = ["Web Gateway Hunt - per-user activity report", "Log window: " + (r.summary ? r.summary.firstTs + " to " + r.summary.lastTs : ""), ""];
  for (const u of rows) {
    out.push("== " + u.user + (u.server ? " (server / no user)" : ""));
    out.push("Requests " + u.requests + ", sent " + fmtBytes(u.bytesOut) + ", received " + fmtBytes(u.bytesIn) + (u.bytesUnknown ? ", direction unknown " + fmtBytes(u.bytesUnknown) : "") + ", uploads " + u.uploads + ", blocked " + u.blocked);
    out.push("Apps " + u.apps + " (" + u.riskyApps + " unsanctioned); sources " + (u.sources || "-") + "; " + u.first + " to " + u.last);
    for (const f of (r.findings || []).filter((x) => x.userKey === u.user || x.entity === u.user || (x.assets || []).some((a) => a.name === u.user))) {
      out.push("  [" + f.severity + "/" + f.confidence + "] " + f.title);
      out.push("    " + f.description);
    }
    out.push("");
  }
  if (!rows.length) out.push("No users with findings.");
  return out.join("\n") + "\n";
}
/** Plain-text summary. */
export function summaryText(r) {
  const s = r.summary;
  const out = ["Web Gateway Hunt summary", "Window: " + s.firstTs + " to " + s.lastTs + " (" + s.spanDays + " days)",
    "Requests " + s.requests + ", users " + s.users + ", apps " + s.apps + " (" + s.unsanctionedApps + " unsanctioned), AI services " + s.aiServices + ", exfiltration candidates " + s.exfilCandidates,
    "Findings " + s.findings + ": " + Object.entries(s.bySeverity).map(([k, v]) => k + " " + v).join(", "), ""];
  for (const f of r.findings) out.push("[" + f.severity.toUpperCase() + " / " + f.confidence + "] " + f.title, "  " + f.description, "  Do: " + f.recommendation, "  Controls: " + f.controls.map((c) => c.framework + " " + c.id).join(", "), "");
  if (r.skipped.length) { out.push("Skipped or limited checks:"); for (const k of r.skipped) out.push("- " + k.check + ": " + k.reason); }
  return out.join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// Synthetic example (Zscaler LEEF + Squid native). Users at test.darknode.ai; workstation IPs
// RFC 1918; destination IPs from documentation ranges; well-known SaaS hostnames only where
// needed to show classification; the suspicious host lives under the .test TLD.
// ---------------------------------------------------------------------------
export function exampleDataset(seed = 7) {
  let s = seed >>> 0 || 7;
  const rnd = () => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s / 4294967296; };
  const ri = (a, b) => a + Math.floor(rnd() * (b - a + 1));
  const MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const users = ["alice", "bob", "carol", "dave", "erin", "frank", "grace"];
  const ipOf = (u) => "10.20.0." + (11 + users.indexOf(u));
  const em = (u) => u + "@test.darknode.ai";
  const BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36";
  const leef = [];
  const t0 = Date.UTC(2026, 8, 21); // Monday 2026-09-21
  const L = (ms, o) => {
    const d = new Date(ms);
    const p2 = (n) => String(n).padStart(2, "0");
    const hdr = MON[d.getUTCMonth()] + " " + p2(d.getUTCDate()) + " " + p2(d.getUTCHours()) + ":" + p2(d.getUTCMinutes()) + ":" + p2(d.getUTCSeconds());
    const dev = MON[d.getUTCMonth()] + " " + p2(d.getUTCDate()) + " " + d.getUTCFullYear() + " " + p2(d.getUTCHours()) + ":" + p2(d.getUTCMinutes()) + ":" + p2(d.getUTCSeconds()) + " UTC";
    const kv = [
      ["cat", o.cat], ["devTime", dev], ["devTimeFormat", "MMM dd yyyy HH:mm:ss z"], ["src", o.src], ["dst", o.dst], ["srcPostNAT", "198.51.100.10"], ["realm", "HQ"],
      ["usrName", o.user], ["srcBytes", o.out], ["dstBytes", o.in], ["role", "Engineering"], ["policy", o.action === "Blocked" ? "Blocked by URL filtering" : "Allowed"],
      ["url", o.url], ["recordid", String(700000 + leef.length)], ["bwthrottle", "NO"], ["useragent", o.ua], ["referer", "None"], ["hostname", o.host], ["appproto", "HTTPS"],
      ["urlcategory", o.cat], ["urlsupercategory", o.supercat || "Business and Economy"], ["urlclass", "Business Use"], ["appclass", o.appclass || "General Browsing"], ["appname", o.app || "General Browsing"],
      ["malwaretype", "None"], ["malwareclass", "None"], ["threatname", "None"], ["riskscore", "0"], ["dlpdict", "None"], ["dlpengine", "None"], ["fileclass", o.fileclass || "None"],
      ["filetype", o.filetype || "None"], ["reqmethod", o.method], ["respcode", o.code || (o.action === "Blocked" ? "403" : "200")],
    ];
    leef.push([ms, hdr + " zscaler-nss: LEEF:1.0|Zscaler|NSSWeblog|5.0|" + o.action + "|" + kv.map(([k, v]) => k + "=" + v).join("\t")]);
  };
  const ev = (ms, u, host, path, o) => L(ms, Object.assign({ user: em(u), src: ipOf(u), dst: "203.0.113." + ri(10, 60), host, url: host + path, method: "GET", out: String(ri(400, 4000)), in: String(ri(3000, 400000)), ua: BROWSER, action: "Allowed", cat: "Professional Services" }, o || {}));
  const normal = [["intranet.test.darknode.ai", "/home", "Corporate Marketing"], ["wiki.test.darknode.ai", "/pages/runbook", "Professional Services"], ["slack.com", "/api/conversations.history", "Online Chat"], ["github.com", "/test-darknode/app", "Professional Services"], ["login.microsoftonline.com", "/common/oauth2/v2.0/token", "Professional Services"]];
  const ai = [["alice", "chatgpt.com", "/backend-api/conversation", "ChatGPT"], ["carol", "chatgpt.com", "/backend-api/conversation", "ChatGPT"], ["dave", "claude.ai", "/api/organizations/chat", "Claude"], ["erin", "gemini.google.com", "/_/BardChatUi/data/batchexecute", "Google Gemini"], ["frank", "claude.ai", "/api/organizations/chat", "Claude"]];
  for (let day = 0; day < 21; day++) {
    const dow = (day + 1) % 7; // 0=Sun
    if (dow === 0 || dow === 6) continue;
    const base = t0 + day * 86400000;
    for (const u of users) {
      for (let i = 0; i < 10; i++) { const [h, p, c] = normal[ri(0, normal.length - 1)]; ev(base + ri(9, 16) * 3600000 + ri(0, 3599) * 1000, u, h, p, { cat: c }); }
    }
    for (const [u, h, p, app] of ai) {
      for (let i = 0; i < 2; i++) ev(base + ri(10, 16) * 3600000 + ri(0, 3599) * 1000, u, h, p, { method: "POST", out: String(ri(2000, 60000)), cat: "Generative AI", supercat: "Information Technology", appclass: "AI & ML Applications", app });
    }
  }
  // carol: one large upload to ChatGPT (45 MB) on Wednesday 2026-10-07 during hours
  ev(Date.UTC(2026, 9, 7, 14, 12, 5), "carol", "chatgpt.com", "/backend-api/files", { method: "POST", out: String(45 * MB), in: "2310", cat: "Generative AI", supercat: "Information Technology", appclass: "AI & ML Applications", app: "ChatGPT", filetype: "PDF", fileclass: "Documents" });
  // bob: 2.4 GB to Dropbox over the weekend (Sat 10-10 and Sun 10-11, early morning)
  for (let d = 0; d < 2; d++) {
    for (let i = 0; i < 24; i++) {
      ev(Date.UTC(2026, 9, 10 + d, 1, 30 + i * 3, ri(0, 59)), "bob", "content.dropboxapi.com", "/2/files/upload_session/append_v2", { method: "POST", out: String(50 * MB + ri(0, 1048575)), in: String(ri(200, 900)), cat: "Online Storage", supercat: "Internet Communication", appclass: "File Sharing", app: "Dropbox" });
    }
  }
  // erin: curl to an uncategorized host with an 80 MB upload
  for (let i = 0; i < 4; i++) ev(Date.UTC(2026, 9, 8, 15, 2 + i, 11), "erin", "q7vxk2lm-cdn.test", "/u/" + (1000 + i), { method: i ? "POST" : "GET", out: String(i ? 20 * MB + ri(0, 9999) : 512), in: "120", ua: "curl/8.4.0", cat: "Miscellaneous or Unknown", supercat: "Miscellaneous", appclass: "General Browsing" });
  // frank: executable straight from an IP address
  L(Date.UTC(2026, 9, 9, 11, 47, 3), { user: em("frank"), src: ipOf("frank"), dst: "203.0.113.77", host: "203.0.113.77", url: "203.0.113.77/update/agent.exe", method: "GET", out: "420", in: "1873408", ua: BROWSER, action: "Allowed", cat: "Miscellaneous or Unknown", supercat: "Miscellaneous", filetype: "EXE", fileclass: "Executables" });
  // grace: a burst of blocked proxy-avoidance attempts
  const proxies = ["www.croxyproxy.com", "www.kproxy.com", "hidester.com", "www.proxysite.com", "www.hidemyass.com", "q1w2proxy.test", "unblock-z9.test", "mirror-k3.test"];
  for (let i = 0; i < 40; i++) ev(Date.UTC(2026, 9, 6, 13, 5 + i, ri(0, 59)), "grace", proxies[i % proxies.length], "/", { action: "Blocked", cat: "Proxy Avoidance", supercat: "Security", appclass: "General Browsing", in: "1500" });
  leef.sort((a, b) => a[0] - b[0]);
  const zscaler = leef.map((x) => x[1]).join("\n") + "\n";
  // Squid native access.log: dave via TeamViewer, a server holding an ngrok tunnel, normal lines
  const sq = [];
  const S = (ms, elapsed, ip, code, bytes, method, url, user, hier, type) => sq.push([ms, (ms / 1000).toFixed(3) + " " + String(elapsed).padStart(6, " ") + " " + ip + " " + code + " " + bytes + " " + method + " " + url + " " + user + " " + hier + " " + type]);
  for (let day = 14; day < 19; day++) {
    const base = t0 + day * 86400000;
    for (let i = 0; i < 6; i++) S(base + ri(9, 16) * 3600000 + ri(0, 3599) * 1000, ri(40, 900), ipOf("dave"), "TCP_TUNNEL/200", ri(4000, 90000), "CONNECT", "wiki.test.darknode.ai:443", em("dave"), "HIER_DIRECT/198.51.100." + ri(20, 40), "-");
    S(base + 3 * 3600000 + ri(0, 3599) * 1000, ri(20, 300), "10.50.0.12", "TCP_MISS/200", ri(900, 5000), "GET", "http://repo.test.darknode.ai/dists/stable/InRelease", "-", "HIER_DIRECT/198.51.100.30", "text/plain");
  }
  S(Date.UTC(2026, 9, 8, 10, 15, 2), 2710000, ipOf("dave"), "TCP_TUNNEL/200", 38211450, "CONNECT", "router7.teamviewer.com:443", em("dave"), "HIER_DIRECT/203.0.113.140", "-");
  S(Date.UTC(2026, 9, 8, 10, 15, 4), 1520, ipOf("dave"), "TCP_TUNNEL/200", 6120, "CONNECT", "master5.teamviewer.com:443", em("dave"), "HIER_DIRECT/203.0.113.141", "-");
  S(Date.UTC(2026, 9, 9, 2, 0, 0), 3600000, "10.50.0.12", "TCP_TUNNEL/200", 188743680, "CONNECT", "k7q2vx.ngrok-free.app:443", "-", "HIER_DIRECT/203.0.113.150", "-");
  S(Date.UTC(2026, 9, 9, 3, 0, 5), 3540000, "10.50.0.12", "TCP_TUNNEL/200", 97517568, "CONNECT", "k7q2vx.ngrok-free.app:443", "-", "HIER_DIRECT/203.0.113.150", "-");
  sq.sort((a, b) => a[0] - b[0]);
  const squid = sq.map((x) => x[1]).join("\n") + "\n";
  return {
    label: "synthetic example (not real data)",
    files: [{ name: "zscaler-nss-web-leef.log", text: zscaler }, { name: "squid-access.log", text: squid }],
  };
}

/** Deterministic self-check of the engine. */
export function selfTest() {
  const tests = [];
  const t = (name, fn) => { let pass = false; try { pass = !!fn(); } catch (_) { pass = false; } tests.push({ name, pass }); };
  const ex = exampleDataset();
  const r = analyze(ex.files);
  const has = (rule, entity) => r.findings.some((f) => f.rule === rule && (!entity || f.entity === entity || f.userKey === entity));
  t("example: weekend Dropbox upload flagged as exfiltration", () => has("upload_exfil", "bob@test.darknode.ai"));
  t("example: off-hours upload flagged", () => has("offhours_upload", "bob@test.darknode.ai"));
  t("example: ngrok tunnel from a server is high", () => r.findings.some((f) => f.rule === "tunnel_server" && f.severity === "high"));
  t("example: TeamViewer flagged as remote access", () => has("remote_user"));
  t("example: curl from a workstation flagged", () => has("scripted_ua", "erin@test.darknode.ai"));
  t("example: executable from an IP flagged", () => has("ip_executable", "203.0.113.77"));
  t("example: AI inventory lists 3 services", () => r.summary.aiServices === 3);
  t("example: blocked spike for grace", () => has("blocked_spike", "grace@test.darknode.ai"));
  t("Squid byte limitation is reported", () => r.skipped.some((s) => s.check === "upload_volume (Squid native)"));
  t("deterministic", () => JSON.stringify(analyze(ex.files)) === JSON.stringify(r));
  t("robust z (MAD)", () => Math.abs(robustZ(10, [1, 2, 3, 4, 5]).z - 0.6745 * 7 / 1) < 1e-9);
  t("catalogue suffix match", () => matchHost("content.dropboxapi.com").app === "Dropbox" && matchHost("gemini.google.com").category === "genai" && matchHost("gemini.com").category === "crypto");
  t("empty input", () => analyze([]).findings.length === 0);
  return { pass: tests.every((x) => x.pass), tests };
}
