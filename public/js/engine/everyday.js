// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Everyday tools DI answers exactly, offline: clock arithmetic ("hours between 9am and
// 5:30pm", "add 45 minutes to 10:20"), the current time in a city, random draws (coin,
// dice, number, pick one), UUIDs, placeholder text, tip / BMI / loan / savings maths,
// travel time, well-known network ports, and "what year was N years ago".
// Each handler is a strict pattern with one exact computation behind it; a request that
// does not fit a pattern is not claimed (ask() returns null), so nothing here guesses.

const NUM = "(\\d+(?:\\.\\d+)?)";
const money = (s) => Number(String(s).replace(/[,$]/g, "").replace(/k$/i, "000"));
const r2 = (n) => Math.round(n * 100) / 100;
const fmt = (n) => Number.isInteger(n) ? String(n) : String(Math.round(n * 1e6) / 1e6);
const usd = (n) => n.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const plural = (n, w) => n + " " + w + (n === 1 ? "" : "s");
const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);

// ---------------------------------------------------------------------------
// Clock arithmetic
// ---------------------------------------------------------------------------
const TIME = "(\\d{1,2})(?::(\\d{2}))?\\s*(am|pm|a\\.m\\.|p\\.m\\.)?|noon|midnight";
function parseTime(str) {
  const t = String(str).toLowerCase().replace(/\./g, "").trim();
  if (t === "noon") return 12 * 60;
  if (t === "midnight") return 0;
  const m = t.match(/^(\d{1,2})(?::(\d{2}))?\s*(am|pm)?$/);
  if (!m) return null;
  let h = +m[1]; const min = m[2] ? +m[2] : 0;
  if (min > 59) return null;
  if (m[3]) { if (h < 1 || h > 12) return null; if (m[3] === "pm" && h !== 12) h += 12; if (m[3] === "am" && h === 12) h = 0; }
  else if (h > 23) return null;
  return h * 60 + min;
}
function fmtClock(mins, ampm) {
  mins = ((mins % 1440) + 1440) % 1440;
  const h = Math.floor(mins / 60), m = mins % 60;
  if (!ampm) return String(h).padStart(2, "0") + ":" + String(m).padStart(2, "0");
  const h12 = h % 12 === 0 ? 12 : h % 12;
  return h12 + ":" + String(m).padStart(2, "0") + " " + (h < 12 ? "AM" : "PM");
}
function fmtDur(mins) {
  const h = Math.floor(mins / 60), m = Math.round(mins % 60);
  const parts = []; if (h) parts.push(plural(h, "hour")); if (m || !h) parts.push(plural(m, "minute"));
  return parts.join(" ");
}
const TIME_RE = new RegExp(TIME, "i");
const hasClock = (s) => /\b\d{1,2}:\d{2}\b|\b\d{1,2}\s*(?:am|pm|a\.m\.|p\.m\.)\b|\bnoon\b|\bmidnight\b/i.test(s)
  || /\bhours?\b/.test(s) && /\b\d{1,2}\s+(?:to|until|till)\s+\d{1,2}\b/.test(s); // "9 to 5 is how many hours"

// ---------------------------------------------------------------------------
// Time zones: city / country / abbreviation -> IANA zone
// ---------------------------------------------------------------------------
const ZONES = {
  utc: "UTC", gmt: "UTC", zulu: "UTC", est: "America/New_York", edt: "America/New_York", cst: "America/Chicago", cdt: "America/Chicago", mst: "America/Denver", mdt: "America/Denver", pst: "America/Los_Angeles", pdt: "America/Los_Angeles",
  cet: "Europe/Paris", cest: "Europe/Paris", bst: "Europe/London", ist: "Asia/Kolkata", jst: "Asia/Tokyo", kst: "Asia/Seoul", aest: "Australia/Sydney", aedt: "Australia/Sydney", hkt: "Asia/Hong_Kong", sgt: "Asia/Singapore", eet: "Europe/Athens", msk: "Europe/Moscow",
  "new york": "America/New_York", nyc: "America/New_York", boston: "America/New_York", miami: "America/New_York", toronto: "America/Toronto", montreal: "America/Toronto", atlanta: "America/New_York", washington: "America/New_York", "washington dc": "America/New_York", philadelphia: "America/New_York", detroit: "America/Detroit",
  chicago: "America/Chicago", houston: "America/Chicago", dallas: "America/Chicago", "mexico city": "America/Mexico_City", mexico: "America/Mexico_City", denver: "America/Denver", phoenix: "America/Phoenix", "salt lake city": "America/Denver",
  "los angeles": "America/Los_Angeles", la: "America/Los_Angeles", "san francisco": "America/Los_Angeles", seattle: "America/Los_Angeles", "las vegas": "America/Los_Angeles", vancouver: "America/Vancouver", "san diego": "America/Los_Angeles", portland: "America/Los_Angeles",
  anchorage: "America/Anchorage", honolulu: "Pacific/Honolulu", hawaii: "Pacific/Honolulu", alaska: "America/Anchorage",
  "sao paulo": "America/Sao_Paulo", "são paulo": "America/Sao_Paulo", rio: "America/Sao_Paulo", "rio de janeiro": "America/Sao_Paulo", brazil: "America/Sao_Paulo", "buenos aires": "America/Argentina/Buenos_Aires", argentina: "America/Argentina/Buenos_Aires", santiago: "America/Santiago", chile: "America/Santiago", lima: "America/Lima", peru: "America/Lima", bogota: "America/Bogota", colombia: "America/Bogota", caracas: "America/Caracas",
  london: "Europe/London", uk: "Europe/London", england: "Europe/London", dublin: "Europe/Dublin", ireland: "Europe/Dublin", lisbon: "Europe/Lisbon", portugal: "Europe/Lisbon", reykjavik: "Atlantic/Reykjavik", iceland: "Atlantic/Reykjavik",
  paris: "Europe/Paris", france: "Europe/Paris", berlin: "Europe/Berlin", germany: "Europe/Berlin", munich: "Europe/Berlin", frankfurt: "Europe/Berlin", madrid: "Europe/Madrid", spain: "Europe/Madrid", barcelona: "Europe/Madrid", rome: "Europe/Rome", italy: "Europe/Rome", milan: "Europe/Rome", amsterdam: "Europe/Amsterdam", netherlands: "Europe/Amsterdam", brussels: "Europe/Brussels", belgium: "Europe/Brussels", zurich: "Europe/Zurich", switzerland: "Europe/Zurich", geneva: "Europe/Zurich", vienna: "Europe/Vienna", austria: "Europe/Vienna", prague: "Europe/Prague", "czech republic": "Europe/Prague", warsaw: "Europe/Warsaw", poland: "Europe/Warsaw", stockholm: "Europe/Stockholm", sweden: "Europe/Stockholm", oslo: "Europe/Oslo", norway: "Europe/Oslo", copenhagen: "Europe/Copenhagen", denmark: "Europe/Copenhagen", helsinki: "Europe/Helsinki", finland: "Europe/Helsinki", athens: "Europe/Athens", greece: "Europe/Athens", istanbul: "Europe/Istanbul", turkey: "Europe/Istanbul", kyiv: "Europe/Kyiv", kiev: "Europe/Kyiv", ukraine: "Europe/Kyiv", moscow: "Europe/Moscow", russia: "Europe/Moscow", budapest: "Europe/Budapest", hungary: "Europe/Budapest", bucharest: "Europe/Bucharest", romania: "Europe/Bucharest",
  cairo: "Africa/Cairo", egypt: "Africa/Cairo", lagos: "Africa/Lagos", nigeria: "Africa/Lagos", nairobi: "Africa/Nairobi", kenya: "Africa/Nairobi", johannesburg: "Africa/Johannesburg", "cape town": "Africa/Johannesburg", "south africa": "Africa/Johannesburg", casablanca: "Africa/Casablanca", morocco: "Africa/Casablanca", accra: "Africa/Accra", ghana: "Africa/Accra", addis: "Africa/Addis_Ababa", "addis ababa": "Africa/Addis_Ababa", ethiopia: "Africa/Addis_Ababa",
  dubai: "Asia/Dubai", uae: "Asia/Dubai", "abu dhabi": "Asia/Dubai", riyadh: "Asia/Riyadh", "saudi arabia": "Asia/Riyadh", doha: "Asia/Qatar", qatar: "Asia/Qatar", tehran: "Asia/Tehran", iran: "Asia/Tehran", "tel aviv": "Asia/Jerusalem", jerusalem: "Asia/Jerusalem", israel: "Asia/Jerusalem", baghdad: "Asia/Baghdad", iraq: "Asia/Baghdad",
  karachi: "Asia/Karachi", pakistan: "Asia/Karachi", lahore: "Asia/Karachi", islamabad: "Asia/Karachi", delhi: "Asia/Kolkata", "new delhi": "Asia/Kolkata", mumbai: "Asia/Kolkata", bangalore: "Asia/Kolkata", bengaluru: "Asia/Kolkata", chennai: "Asia/Kolkata", hyderabad: "Asia/Kolkata", kolkata: "Asia/Kolkata", india: "Asia/Kolkata", dhaka: "Asia/Dhaka", bangladesh: "Asia/Dhaka", kathmandu: "Asia/Kathmandu", nepal: "Asia/Kathmandu", colombo: "Asia/Colombo", "sri lanka": "Asia/Colombo",
  bangkok: "Asia/Bangkok", thailand: "Asia/Bangkok", hanoi: "Asia/Ho_Chi_Minh", "ho chi minh": "Asia/Ho_Chi_Minh", vietnam: "Asia/Ho_Chi_Minh", jakarta: "Asia/Jakarta", indonesia: "Asia/Jakarta", bali: "Asia/Makassar", "kuala lumpur": "Asia/Kuala_Lumpur", malaysia: "Asia/Kuala_Lumpur", singapore: "Asia/Singapore", manila: "Asia/Manila", philippines: "Asia/Manila",
  beijing: "Asia/Shanghai", shanghai: "Asia/Shanghai", china: "Asia/Shanghai", shenzhen: "Asia/Shanghai", "hong kong": "Asia/Hong_Kong", taipei: "Asia/Taipei", taiwan: "Asia/Taipei", seoul: "Asia/Seoul", korea: "Asia/Seoul", "south korea": "Asia/Seoul", tokyo: "Asia/Tokyo", japan: "Asia/Tokyo", osaka: "Asia/Tokyo", kyoto: "Asia/Tokyo",
  sydney: "Australia/Sydney", melbourne: "Australia/Melbourne", canberra: "Australia/Sydney", brisbane: "Australia/Brisbane", perth: "Australia/Perth", adelaide: "Australia/Adelaide", australia: "Australia/Sydney", auckland: "Pacific/Auckland", wellington: "Pacific/Auckland", "new zealand": "Pacific/Auckland", fiji: "Pacific/Fiji",
};
const ZONE_KEYS = Object.keys(ZONES).sort((a, b) => b.length - a.length);
function zoneOf(place) {
  const p = String(place).toLowerCase().replace(/[?.!,]+$/, "").replace(/^(?:the\s+)?/, "").trim();
  if (ZONES[p]) return { key: p, tz: ZONES[p] };
  for (const k of ZONE_KEYS) if (new RegExp("(?:^|\\s)" + k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "(?:\\s|$)").test(p)) return { key: k, tz: ZONES[k] };
  return null;
}
function nowIn(tz) {
  const d = new Date();
  const f = new Intl.DateTimeFormat("en-US", { timeZone: tz, weekday: "long", hour: "2-digit", minute: "2-digit", hour12: false, year: "numeric", month: "short", day: "numeric" });
  const parts = Object.fromEntries(f.formatToParts(d).filter((p) => p.type !== "literal").map((p) => [p.type, p.value]));
  // UTC offset from the zone's wall clock vs UTC (Node and every modern browser)
  const wall = new Date(new Intl.DateTimeFormat("en-US", { timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(d).replace(/(\d+)\/(\d+)\/(\d+), (\d+):(\d+):(\d+)/, "$3-$1-$2T$4:$5:$6Z").replace("T24:", "T00:"));
  const offMin = Math.round((wall.getTime() - Math.floor(d.getTime() / 1000) * 1000) / 60000);
  const sign = offMin >= 0 ? "+" : "-", a = Math.abs(offMin);
  const off = "UTC" + sign + Math.floor(a / 60) + (a % 60 ? ":" + String(a % 60).padStart(2, "0") : "");
  const hh = parts.hour === "24" ? "00" : parts.hour;
  return { time: hh + ":" + parts.minute, weekday: parts.weekday, date: parts.month + " " + parts.day + ", " + parts.year, offset: off };
}

// ---------------------------------------------------------------------------
// Random draws (a real random source, never a guess)
// ---------------------------------------------------------------------------
function randInt(lo, hi) { // inclusive, unbiased
  const span = hi - lo + 1;
  const c = globalThis.crypto;
  if (c && c.getRandomValues) { const buf = new Uint32Array(1); const lim = Math.floor(0x100000000 / span) * span; let x; do { c.getRandomValues(buf); x = buf[0]; } while (x >= lim); return lo + (x % span); }
  return lo + Math.floor(Math.random() * span);
}
function uuid4() {
  const c = globalThis.crypto;
  if (c && c.randomUUID) return c.randomUUID();
  const b = new Uint8Array(16); if (c && c.getRandomValues) c.getRandomValues(b); else for (let i = 0; i < 16; i++) b[i] = randInt(0, 255);
  b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
  const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return h.slice(0, 8) + "-" + h.slice(8, 12) + "-" + h.slice(12, 16) + "-" + h.slice(16, 20) + "-" + h.slice(20);
}
const LOREM = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. Curabitur pretium tincidunt lacus, nulla gravida orci a odio. Nullam varius, turpis et commodo pharetra, est eros bibendum elit, nec luctus magna felis sollicitudin mauris. Integer in mauris eu nibh euismod gravida. Duis ac tellus et risus vulputate vehicula. Donec lobortis risus a elit, etiam tempor. Ut ullamcorper, ligula eu tempor congue, eros est euismod turpis, id tincidunt sapien risus a quam. Maecenas fermentum consequat mi, donec fermentum. Pellentesque malesuada nulla a mi. Duis sapien sem, aliquet nec, commodo eget, consequat quis, neque. Aliquam faucibus, elit ut dictum aliquet, felis nisl adipiscing sapien, sed malesuada diam lacus eget erat. Cras mollis scelerisque nunc, nullam arcu. Aliquam consequat curabitur augue lorem, dapibus quis, laoreet et, pretium ac, nisi. Aenean magna nisl, mollis quis, molestie eu, feugiat in, orci. In hac habitasse platea dictumst.";
const LOREM_SENT = LOREM.match(/[^.]+\./g).map((s) => s.trim());
function lorem(n, unit) {
  if (unit === "words") { const w = LOREM.split(/\s+/); const out = []; for (let i = 0; i < n; i++) out.push(w[i % w.length].replace(/[.,]$/, "")); return cap(out.join(" ")) + "."; }
  if (unit === "paragraphs") { const out = []; for (let p = 0; p < n; p++) out.push(LOREM_SENT.slice((p * 5) % LOREM_SENT.length, (p * 5) % LOREM_SENT.length + 5).join(" ")); return out.join("\n\n"); }
  const out = []; for (let i = 0; i < n; i++) out.push(LOREM_SENT[i % LOREM_SENT.length]); return out.join(" ");
}

// ---------------------------------------------------------------------------
// Well-known ports (IANA assignments and de-facto defaults)
// ---------------------------------------------------------------------------
const PORTS = [
  [20, "tcp", "FTP data", ["ftp data", "ftp-data"]], [21, "tcp", "FTP (control)", ["ftp"]], [22, "tcp", "SSH (also SFTP and SCP)", ["ssh", "sftp", "scp"]], [23, "tcp", "Telnet", ["telnet"]], [25, "tcp", "SMTP", ["smtp", "mail", "email"]],
  [53, "tcp/udp", "DNS", ["dns"]], [67, "udp", "DHCP (server)", ["dhcp"]], [68, "udp", "DHCP (client)", []], [69, "udp", "TFTP", ["tftp"]], [80, "tcp", "HTTP", ["http", "web"]], [88, "tcp/udp", "Kerberos", ["kerberos"]], [110, "tcp", "POP3", ["pop3", "pop"]],
  [119, "tcp", "NNTP", ["nntp"]], [123, "udp", "NTP", ["ntp", "time sync"]], [135, "tcp", "Microsoft RPC", ["msrpc", "rpc"]], [137, "udp", "NetBIOS name service", ["netbios"]], [139, "tcp", "NetBIOS session service", []], [143, "tcp", "IMAP", ["imap"]],
  [161, "udp", "SNMP", ["snmp"]], [162, "udp", "SNMP trap", ["snmp trap"]], [194, "tcp", "IRC", ["irc"]], [389, "tcp/udp", "LDAP", ["ldap"]], [443, "tcp", "HTTPS (HTTP over TLS)", ["https", "tls", "ssl"]], [445, "tcp", "SMB (Microsoft-DS)", ["smb", "samba", "cifs"]],
  [465, "tcp", "SMTPS (SMTP over TLS)", ["smtps"]], [514, "udp", "Syslog", ["syslog"]], [587, "tcp", "SMTP submission (STARTTLS)", ["smtp submission"]], [631, "tcp", "IPP (printing, CUPS)", ["ipp", "cups"]], [636, "tcp", "LDAPS", ["ldaps"]], [853, "tcp", "DNS over TLS", ["dns over tls", "dot"]],
  [873, "tcp", "rsync", ["rsync"]], [989, "tcp", "FTPS data", []], [990, "tcp", "FTPS control", ["ftps"]], [993, "tcp", "IMAPS", ["imaps"]], [995, "tcp", "POP3S", ["pop3s"]], [1080, "tcp", "SOCKS proxy", ["socks"]], [1194, "udp", "OpenVPN", ["openvpn"]], [1433, "tcp", "Microsoft SQL Server", ["mssql", "sql server", "microsoft sql"]],
  [1521, "tcp", "Oracle database listener", ["oracle"]], [1723, "tcp", "PPTP VPN", ["pptp"]], [1883, "tcp", "MQTT", ["mqtt"]], [2049, "tcp/udp", "NFS", ["nfs"]], [2375, "tcp", "Docker daemon (unencrypted)", ["docker"]], [2376, "tcp", "Docker daemon (TLS)", []], [3000, "tcp", "common dev server (Node, Rails, Grafana)", ["grafana", "node dev server"]],
  [3306, "tcp", "MySQL / MariaDB", ["mysql", "mariadb"]], [3389, "tcp", "RDP (Remote Desktop)", ["rdp", "remote desktop"]], [4444, "tcp", "Metasploit default handler (also a common backdoor port)", ["metasploit"]], [5000, "tcp", "common dev server (Flask, UPnP)", ["flask"]], [5060, "tcp/udp", "SIP", ["sip"]], [5432, "tcp", "PostgreSQL", ["postgres", "postgresql"]],
  [5900, "tcp", "VNC", ["vnc"]], [5938, "tcp", "TeamViewer", ["teamviewer"]], [6379, "tcp", "Redis", ["redis"]], [6443, "tcp", "Kubernetes API server", ["kubernetes", "k8s"]], [6667, "tcp", "IRC (unencrypted)", []], [8000, "tcp", "common dev HTTP server (Django, python -m http.server)", ["django"]],
  [8080, "tcp", "HTTP alternate / proxies (Tomcat, Jenkins)", ["tomcat", "jenkins", "http alt"]], [8443, "tcp", "HTTPS alternate", []], [9000, "tcp", "SonarQube / PHP-FPM / Portainer", ["sonarqube", "php-fpm"]], [9090, "tcp", "Prometheus", ["prometheus"]], [9200, "tcp", "Elasticsearch", ["elasticsearch"]], [11211, "tcp", "Memcached", ["memcached"]], [27017, "tcp", "MongoDB", ["mongodb", "mongo"]],
  [51820, "udp", "WireGuard", ["wireguard"]],
];
const PORT_BY_NAME = new Map(); for (const p of PORTS) for (const n of p[3]) PORT_BY_NAME.set(n, p);
const PORT_NAMES = [...PORT_BY_NAME.keys()].sort((a, b) => b.length - a.length);

// words the typo corrector must leave alone (city names, service names, tool nouns)
export const VOCAB = [...new Set([...ZONE_KEYS.flatMap((k) => k.split(" ")), ...PORT_NAMES.flatMap((k) => k.split(/[\s-]/)), "uuid", "guid", "uuids", "guids", "lorem", "ipsum", "bmi", "mortgage", "loan", "tip", "coin", "dice", "die", "d20", "d6", "d10", "d12", "d8", "d4", "d100", "steps", "noon", "midnight", "am", "pm", "utc", "gmt", "shuffle", "pick", "choose", "port", "ports", "https", "http", "ssh", "ftp", "smtp", "dns", "rdp", "vnc", "mysql", "postgres", "redis", "mongodb"]).values()].filter((w) => w.length > 1);

// ---------------------------------------------------------------------------
// ask(): which everyday tool does this line want? (null = not one of these)
// ---------------------------------------------------------------------------
const RATE = "(mph|miles per hour|miles an hour|km/h|kmh|kph|km per hour|kilometers per hour|kilometres per hour|km an hour|m/s|meters per second|metres per second|knots?)";
const DIST = "(miles?|mi|km|kilometers?|kilometres?|m|meters?|metres?|nautical miles?|nm)";
export function ask(input) {
  const s = String(input || "").trim().replace(/\s+/g, " ");
  const low = s.toLowerCase().replace(/[?!.]+$/, "").replace(/\s+/g, " ");
  let m;
  // --- clock arithmetic ---
  if (hasClock(low)) {
    m = low.match(new RegExp("(?:how (?:many|much) (?:hours?|minutes?|time)|how long|hours?|minutes?|time|duration)\\b.*?(?:between|from|since)\\s+(" + TIME + ")\\s+(?:and|to|until|till|through)\\s+(" + TIME + ")$", "i"))
      || low.match(new RegExp("^(?:from\\s+)?(" + TIME + ")\\s+(?:to|until|till|-|–)\\s+(" + TIME + ")(?:\\s+(?:is )?how (?:long|many hours))?$", "i"));
    if (m) {
      const a = parseTime(m[1]); let b = parseTime(m[5]);
      // "9 to 5" with no am/pm: the second is the afternoon, as people mean it
      const bare = !/am|pm|noon|midnight|:/i.test(m[1] + m[5]);
      const pmAssumed = bare && a != null && b != null && b < a && b <= 12 * 60;
      if (pmAssumed) b += 12 * 60;
      if (a != null && b != null) return { kind: "between", a, b, aTxt: m[1], bTxt: m[5], pmAssumed };
    }
    const core = low.replace(/^(?:what time (?:is it |will it be |was it |is |it is )?|what is |whats |what's |calculate |find |tell me )/, "").replace(/^in\s+(?=\d)/, "").trim();
    let timeTxt, sign, n1, u1, n2;
    const shapeA = core.match(new RegExp("^(?:(add|plus|subtract|minus|take)\\s+)?" + NUM + "\\s*(hours?|hrs?|h|minutes?|mins?|m)(?:\\s+and\\s+" + NUM + "\\s*(?:minutes?|mins?|m))?\\s+(after|from|before|to|until|later than|earlier than|past)\\s+(" + TIME + ")$", "i"));
    const shapeB = shapeA ? null : core.match(new RegExp("^(" + TIME + ")\\s*(\\+|-|plus|minus|in|after)\\s*" + NUM + "\\s*(hours?|hrs?|h|minutes?|mins?|m)(?:\\s+and\\s+" + NUM + "\\s*(?:minutes?|mins?|m))?$", "i"));
    if (shapeA) {
      const verb = shapeA[1] || "", rel = shapeA[5];
      sign = (/subtract|minus|take/.test(verb) || /before|until|earlier/.test(rel)) ? -1 : 1;
      n1 = +shapeA[2]; u1 = shapeA[3]; n2 = shapeA[4] ? +shapeA[4] : 0; timeTxt = shapeA[6];
    } else if (shapeB) {
      timeTxt = shapeB[1]; sign = /^(?:-|minus)$/.test(shapeB[5]) ? -1 : 1; n1 = +shapeB[6]; u1 = shapeB[7]; n2 = shapeB[8] ? +shapeB[8] : 0;
    }
    if (shapeA || shapeB) {
      const t = parseTime(timeTxt); if (t == null) return null;
      const mins = (/^h/.test(u1) ? n1 * 60 : n1) + n2;
      return { kind: "clockadd", t, tTxt: timeTxt, delta: sign * mins, ampm: /am|pm|a\.m|p\.m|noon|midnight/i.test(timeTxt) };
    }
  }
  // --- current time somewhere ---
  m = low.match(/^(?:what(?:'s| is|s) the |what )?(?:current |local |exact )?time(?: is it| now| right now)?(?: right now| now)? in (?:the )?([a-z .'à-ÿ]+?)(?: right now| now| at the moment| currently)?$/)
    || low.match(/^(?:current |local )?time in ([a-z .'à-ÿ]+)$/) || low.match(/^([a-z .'à-ÿ]+?) (?:current |local )?time(?: now| right now)?$/)
    || low.match(/^what time is it (?:right now |now )?in ([a-z .'à-ÿ]+)$/);
  if (m) { const z = zoneOf(m[1]); if (z) return { kind: "tz", place: m[1].trim(), ...z }; if (/^(?:what|current|local|time)/.test(low)) return { kind: "tz", place: m[1].trim(), tz: null }; }
  // --- random draws ---
  if (/^(?:flip|toss) (?:a |the )?coin$|^coin (?:flip|toss)$|^heads or tails$/.test(low)) return { kind: "coin" };
  m = low.match(/^(?:roll|throw) (?:a |the |an |two |three |2 |3 |4 |\d+ )?(?:(\d*)d(\d+)|dice|die|d(\d+)|(\d+)[- ]sided (?:die|dice))$|^(?:dice|die) roll$|^(?:roll )?(\d*)d(\d+)$/);
  if (m) { const count = +(m[1] || m[5] || (low.match(/\b(two|2)\b/) ? 2 : low.match(/\b(three|3)\b/) ? 3 : low.match(/\b(\d+) dice/) ? RegExp.$1 : 1)) || 1; const sides = +(m[2] || m[3] || m[4] || m[6] || 6); if (sides >= 2 && sides <= 1000 && count >= 1 && count <= 100) return { kind: "dice", count, sides }; }
  m = low.match(new RegExp("^(?:(?:give me |pick |choose |generate |get |make )?(?:a |an )?random (?:number|integer|int|value)(?: between| from)?|pick a number(?: between| from)?|random)\\s*" + NUM + "?\\s*(?:and|to|-|through)?\\s*" + NUM + "?$"));
  if (m && /random|pick a number/.test(low)) { let lo = m[1] != null ? +m[1] : 1, hi = m[2] != null ? +m[2] : (m[1] != null ? null : 100); if (hi == null) { hi = lo; lo = 1; } if (lo > hi) [lo, hi] = [hi, lo]; if (hi - lo <= 1e15) return { kind: "randnum", lo, hi }; }
  m = low.match(/^random (?:number|integer|int) (?:up to|under|below|less than|to) (\d+)$/); if (m) return { kind: "randnum", lo: 1, hi: +m[1] };
  m = s.match(/^(?:(?:should|shall|can|could|would) (?:i|you|we) |help me |please )?(?:pick|choose|decide|select)(?: one| for me| between| from| among| out of|:)*\s+(.+)$/i);
  if (m && /(?:,| or | and |\/)/.test(m[1]) && !/\bnumber\b/i.test(low)) {
    const opts = m[1].replace(/\s+(?:or|and)\s+/gi, ",").split(/\s*[,\/]\s*/).map((x) => x.replace(/[?.!]+$/, "").trim()).filter(Boolean);
    if (opts.length >= 2 && opts.length <= 50) return { kind: "pick", opts };
  }
  m = s.match(/^shuffle(?: these| this| the list| the| :)?[: ]\s*(.+)$/i);
  if (m) { const opts = m[1].split(/\s*,\s*|\s+/).filter(Boolean); if (opts.length >= 2 && opts.length <= 200) return { kind: "shuffle", opts }; }
  if (/^(?:(?:generate|make|create|give me|get|new|random|a|an) )*(?:uuid|guid|uuid ?v4|uuid4)s?(?: v4)?$/.test(low)) return { kind: "uuid", n: 1 };
  m = low.match(/^(?:generate |make |give me |create )?(\d+) (?:random )?(?:uuid|guid)s?$/); if (m && +m[1] >= 1 && +m[1] <= 50) return { kind: "uuid", n: +m[1] };
  // --- placeholder text ---
  m = low.match(/^(?:generate |give me |make |write |some |)(?:(\d+) (words?|sentences?|paragraphs?) of )?lorem(?: ipsum)?(?: text| placeholder(?: text)?)?(?: (\d+) (words?|sentences?|paragraphs?))?$/) || low.match(/^(?:(\d+) (words?|sentences?|paragraphs?) of )?(?:placeholder|dummy|filler) text(?: (\d+) (words?|sentences?|paragraphs?))?$/);
  if (m) { const n = +(m[1] || m[3] || 3), u = (m[2] || m[4] || "sentences").replace(/s?$/, "s"); if (n >= 1 && n <= 500) return { kind: "lorem", n, unit: u }; }
  // --- tip ---
  if (/\btip\b/.test(low) && /\d/.test(low) && !/\btip (?:of the|for (?:the )?day)\b/.test(low)) {
    const pct = low.match(/(\d+(?:\.\d+)?)\s*(?:%|percent)/);
    const amt = low.replace(/(\d+(?:\.\d+)?)\s*(?:%|percent)/, " ").match(/\$?\s*(\d[\d,]*(?:\.\d+)?)/);
    const ways = low.match(/(?:split|between|among|for|shared by)\s+(\d+)\s*(?:people|persons|ways|of us|friends|guests|diners)/);
    if (amt) { const bill = money(amt[1]); if (bill > 0 && bill < 1e7) return { kind: "tip", bill, pct: pct ? +pct[1] : null, ways: ways ? +ways[1] : null }; }
  }
  // --- BMI ---
  if (/\bbmi\b|body mass index/.test(low)) {
    const kg = low.match(/(\d+(?:\.\d+)?)\s*(kg|kgs|kilos?|kilograms?)\b/), lb = low.match(/(\d+(?:\.\d+)?)\s*(lbs?|pounds?)\b/);
    const cm = low.match(/(\d+(?:\.\d+)?)\s*(cm|centimet(?:er|re)s?)\b/), mt = low.match(/(\d(?:\.\d+)?)\s*(m|met(?:er|re)s?)\b/), ftin = low.match(/(\d)\s*(?:'|ft|feet|foot)\s*(\d{1,2})?\s*(?:"|''|in|inches)?/), inch = low.match(/(\d{2,3})\s*(?:in|inches)\b/);
    const wkg = kg ? +kg[1] : lb ? +lb[1] * 0.45359237 : null;
    const hm = cm ? +cm[1] / 100 : mt ? +mt[1] : ftin ? (+ftin[1] * 12 + +(ftin[2] || 0)) * 0.0254 : inch ? +inch[1] * 0.0254 : null;
    if (wkg && hm && wkg > 10 && wkg < 500 && hm > 0.9 && hm < 2.6) return { kind: "bmi", wkg, hm, wTxt: (kg || lb)[0].trim(), hTxt: (cm || mt || ftin || inch)[0].trim() };
  }
  // --- loan / mortgage payment ---
  if (/\b(mortgage|loan|finance|financing|borrow(?:ing)?|car payment|monthly payment)\b/.test(low) && /%|percent/.test(low)) {
    const P = low.match(/\$\s*(\d[\d,]*(?:\.\d+)?k?)|(\d[\d,]*(?:\.\d+)?k?)\s*(?:dollars|usd|bucks)|\b(?:of|on|for|borrow(?:ing)?|loan|mortgage|finance|financing)\s+(?:a |an |the |my )?\$?(\d[\d,]*(?:\.\d+)?k?)\b(?!\s*(?:%|percent|years?|months?|yrs?))/);
    const R = low.match(/(\d+(?:\.\d+)?)\s*(?:%|percent)/);
    const T = low.match(/(\d+(?:\.\d+)?)\s*(years?|yrs?|months?|mos?)\b/);
    if (P && R && T) { const p = money(P[1] || P[2] || P[3]); const months = /^m/.test(T[2]) ? +T[1] : +T[1] * 12; if (p > 0 && +R[1] >= 0 && months >= 1 && months <= 1200) return { kind: "loan", p, rate: +R[1], months, term: T[0] }; }
  }
  // --- regular saving ---
  m = low.match(/(?:save|saving|put away|set aside|invest|deposit|contribute)\s+(?:\$\s*)?(\d[\d,]*(?:\.\d+)?)\s*(?:dollars|usd|bucks)?\s+(?:a|per|each|every)\s+(day|week|month|year)\b/);
  if (m) {
    const T = low.match(/(?:for|in|over|after|within)\s+(\d+(?:\.\d+)?|a|an|one|two|three|four|five|six|ten|twenty)\s*(years?|yrs?|months?|weeks?|days?)\b/);
    const R = low.match(/(?:at|with|earning|@)\s+(\d+(?:\.\d+)?)\s*(?:%|percent)/);
    const WORDN = { a: 1, an: 1, one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, ten: 10, twenty: 20 };
    if (T) return { kind: "save", amt: money(m[1]), per: m[2], n: WORDN[T[1]] || +T[1], unit: T[2].replace(/s$/, "").replace(/^yr$/, "year"), rate: R ? +R[1] : null };
  }
  // --- travel time / distance / speed ---
  m = low.match(new RegExp("^(?:how long (?:does it take |will it take |would it take |do i need |to )?(?:to )?(?:travel|drive|go|walk|run|cycle|ride|cover|fly|sail|bike) |travel time (?:for )?)" + NUM + "\\s*" + DIST + " at " + NUM + "\\s*" + RATE + "$"));
  if (m) return { kind: "travel", d: +m[1], du: m[2], v: +m[3], vu: m[4] };
  m = low.match(new RegExp("^how long (?:does it take |will it take |would it take |to )?(?:to )?(?:travel|drive|go|walk|run|cycle|ride|cover|fly|sail|bike) " + NUM + "\\s*" + DIST + " (?:at|going|doing) " + NUM + "$"));
  if (m) return null; // speed with no unit: not claimed
  // --- steps to distance (an estimate, said so) ---
  m = low.match(/^(?:how (?:far|many (?:miles|km|kilometers|meters)) (?:is|are) |how far is )?(\d[\d,]*)\s*steps(?: (?:in|to|into) (miles?|km|kilometers?|kilometres?|meters?|metres?|feet|ft))?$/) || low.match(/^(\d[\d,]*)\s*steps (?:in|to|into|=) (miles?|km|kilometers?|kilometres?|meters?|metres?|feet|ft)$/);
  if (m) return { kind: "steps", n: +m[1].replace(/,/g, ""), unit: m[2] || null };
  // --- ports ---
  m = low.match(/^(?:what|which)(?: is| are)?(?: the)?(?: default| standard| common| well[- ]known)? port(?: number)?s? (?:does|do|is|for|of|used by|used for|is used (?:by|for))\s+(?:the |a |an )?(.+?)(?: use| run on| listen on| use by default)?$/)
    || low.match(/^(.+?) (?:default |standard )?port(?: number)?$/) || low.match(/^(?:default |standard )?port (?:for|of) (?:the )?(.+)$/) || low.match(/^what does (.+?) (?:run|listen) on$/);
  if (m) { const name = m[1].trim().replace(/^(?:the |a |an )/, ""); const key = PORT_NAMES.find((n) => n === name) || PORT_NAMES.find((n) => new RegExp("(?:^|\\s)" + n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "(?:\\s|$)").test(name)); if (key) return { kind: "port", name: key, entry: PORT_BY_NAME.get(key) }; }
  m = low.match(/^(?:what (?:is|runs on|uses|listens on)|whats|what's|which service (?:uses|runs on)|service on|tcp|udp)?\s*port (\d{1,5})(?: (?:used )?for| do| does| is)?$/) || low.match(/^what (?:is|runs on|uses) (?:tcp |udp )?port (\d{1,5})$/) || low.match(/^(?:what|which) port is (\d{1,5})$/);
  if (m) { const n = +m[1]; const e = PORTS.find((p) => p[0] === n); return { kind: "portnum", n, entry: e || null }; }
  // --- years ago / from now ---
  m = low.match(/^(?:what|which) year (?:was (?:it )?|is )?(\d+) years? ago$/) || low.match(/^(\d+) years? ago(?: was)? (?:what|which) year$/) || low.match(/^(\d+) years ago$/);
  if (m) return { kind: "yearago", n: +m[1] };
  m = low.match(/^(?:what|which) year (?:will it be |is it |is )?(?:in )?(\d+) years?(?: from now| from today| later| time)?$/) || low.match(/^(?:in )?(\d+) years from now(?: is)? (?:what|which) year$/);
  if (m) return { kind: "yearahead", n: +m[1] };
  m = low.match(/^(?:what year |when )(?:was|were) (?:i|you|someone|a person|they|he|she) born (?:if|when) (?:i am|i'm|you are|you're|they are|they're|he is|she is|someone is|aged?)?\s*(\d{1,3})(?: years old| years| yo)?$/) || low.match(/^(?:birth year|year of birth|born year) (?:for|if|of) (?:someone |a person |age )?(?:aged? |who is )?(\d{1,3})(?: years old)?$/) || low.match(/^if (?:i am|i'm|you are|someone is) (\d{1,3})(?: years old)?,? (?:what year|when) (?:was|were) (?:i|you|they) born$/);
  if (m) return { kind: "birthyear", age: +m[1] };
  return null;
}

// ---------------------------------------------------------------------------
// run(): compute the answer for an ask() result
// ---------------------------------------------------------------------------
const DIST_M = { mile: 1609.344, miles: 1609.344, mi: 1609.344, km: 1000, kilometer: 1000, kilometers: 1000, kilometre: 1000, kilometres: 1000, m: 1, meter: 1, meters: 1, metre: 1, metres: 1, "nautical mile": 1852, "nautical miles": 1852, nm: 1852, feet: 0.3048, ft: 0.3048 };
const RATE_MPS = (u) => /^(?:mph|miles)/.test(u) ? 0.44704 : /^(?:km|kph|kmh|kilomet)/.test(u) ? 1000 / 3600 : /knot/.test(u) ? 0.514444 : 1;
export function run(q) {
  if (!q) return { ok: false, error: "not an everyday request" };
  const nowY = new Date().getUTCFullYear();
  switch (q.kind) {
    case "between": {
      let d = q.b - q.a; const wrapped = d < 0; if (wrapped) d += 1440;
      return { ok: true, kind: q.kind, value: d / 60, text: fmtDur(d) + " (" + fmt(d / 60) + " hours)" + (wrapped ? ", assuming " + q.bTxt + " is on the next day" : q.pmAssumed ? ", reading " + q.bTxt + " as " + q.bTxt + "pm" : ""), a: q.aTxt, b: q.bTxt, minutes: d };
    }
    case "clockadd": {
      const out = q.t + q.delta, days = Math.floor(out / 1440) - (out < 0 ? 0 : 0);
      const dayNote = out >= 1440 ? " (the next day)" : out < 0 ? " (the previous day)" : "";
      return { ok: true, kind: q.kind, text: fmtClock(out, q.ampm) + dayNote, from: q.tTxt, delta: q.delta, value: null, days };
    }
    case "tz": {
      if (!q.tz) return { ok: false, error: "I do not have a time zone for “" + q.place + "”. I know major cities, countries and zone abbreviations (UTC, EST, PST, CET, IST, JST, ...)." };
      const n = nowIn(q.tz);
      const place = q.place.length <= 3 ? q.place.toUpperCase() : q.place.replace(/\b[a-z]/g, (c) => c.toUpperCase()); // "LA", "New York"
      return { ok: true, kind: q.kind, text: n.time + " on " + n.weekday + ", " + n.date + " in " + place + " (" + q.tz + ", " + n.offset + ")", time: n.time, tz: q.tz, offset: n.offset, value: null };
    }
    case "coin": { const heads = randInt(0, 1) === 1; return { ok: true, kind: q.kind, text: heads ? "Heads" : "Tails", value: null }; }
    case "dice": { const rolls = []; for (let i = 0; i < q.count; i++) rolls.push(randInt(1, q.sides)); const total = rolls.reduce((a, b) => a + b, 0); return { ok: true, kind: q.kind, rolls, total, sides: q.sides, value: total, text: q.count === 1 ? "You rolled a " + rolls[0] + " (d" + q.sides + ")" : "You rolled " + rolls.join(" + ") + " = " + total + " (" + q.count + "d" + q.sides + ")" }; }
    case "randnum": { const n = randInt(q.lo, q.hi); return { ok: true, kind: q.kind, value: n, lo: q.lo, hi: q.hi, text: String(n) }; }
    case "pick": { const i = randInt(0, q.opts.length - 1); return { ok: true, kind: q.kind, choice: q.opts[i], opts: q.opts, text: q.opts[i], value: null }; }
    case "shuffle": { const a = q.opts.slice(); for (let i = a.length - 1; i > 0; i--) { const j = randInt(0, i); [a[i], a[j]] = [a[j], a[i]]; } return { ok: true, kind: q.kind, items: a, text: a.join(", "), value: null }; }
    case "uuid": { const ids = []; for (let i = 0; i < q.n; i++) ids.push(uuid4()); return { ok: true, kind: q.kind, ids, text: ids.join("\n"), value: null }; }
    case "lorem": return { ok: true, kind: q.kind, n: q.n, unit: q.unit, text: lorem(q.n, q.unit), value: null };
    case "tip": {
      const rows = (q.pct != null ? [q.pct] : [15, 18, 20]).map((p) => ({ pct: p, tip: r2(q.bill * p / 100), total: r2(q.bill * (1 + p / 100)) }));
      return { ok: true, kind: q.kind, bill: q.bill, rows, ways: q.ways, value: q.pct != null ? rows[0].tip : null, text: rows.map((r) => r.pct + "%: tip $" + usd(r.tip) + ", total $" + usd(r.total) + (q.ways ? ", $" + usd(r.total / q.ways) + " each for " + q.ways : "")).join("\n") };
    }
    case "bmi": {
      const bmi = q.wkg / (q.hm * q.hm), b = Math.round(bmi * 10) / 10;
      const band = bmi < 18.5 ? "underweight" : bmi < 25 ? "normal weight" : bmi < 30 ? "overweight" : "obese";
      return { ok: true, kind: q.kind, value: b, band, text: "BMI " + b + " (" + band + ") for " + q.wTxt + " and " + q.hTxt };
    }
    case "loan": {
      const r = q.rate / 100 / 12, n = q.months;
      const pay = r === 0 ? q.p / n : q.p * r / (1 - Math.pow(1 + r, -n));
      const total = pay * n, interest = total - q.p;
      return { ok: true, kind: q.kind, value: r2(pay), payment: r2(pay), total: r2(total), interest: r2(interest), p: q.p, rate: q.rate, months: n, text: "$" + usd(pay) + " per month for " + n + " months; total paid $" + usd(total) + ", of which $" + usd(interest) + " is interest" };
    }
    case "save": {
      const perYear = { day: 365, week: 52, month: 12, year: 1 }[q.per];
      const years = q.unit === "year" ? q.n : q.unit === "month" ? q.n / 12 : q.unit === "week" ? q.n / 52 : q.n / 365;
      const k = Math.round(perYear * years);
      const plain = q.amt * k;
      if (q.rate == null) return { ok: true, kind: q.kind, value: r2(plain), deposits: k, plain: r2(plain), text: "$" + usd(plain) + " (" + k + " deposits of $" + usd(q.amt) + ", no interest)" };
      // future value of an ordinary annuity compounded once per deposit period
      const i = q.rate / 100 / perYear;
      const fv = i === 0 ? plain : q.amt * ((Math.pow(1 + i, k) - 1) / i);
      return { ok: true, kind: q.kind, value: r2(fv), deposits: k, plain: r2(plain), interest: r2(fv - plain), rate: q.rate, text: "$" + usd(fv) + " (" + k + " deposits of $" + usd(q.amt) + " = $" + usd(plain) + ", plus $" + usd(fv - plain) + " interest at " + q.rate + "% compounded per deposit)" };
    }
    case "travel": {
      const meters = q.d * (DIST_M[q.du] || DIST_M[q.du.replace(/s$/, "")] || 1), mps = q.v * RATE_MPS(q.vu);
      if (!(mps > 0)) return { ok: false, error: "speed must be positive" };
      const hours = meters / mps / 3600, mins = Math.round(hours * 60);
      const mixed = (/^(?:mi|mile)/.test(q.du) !== /^(?:mph|miles)/.test(q.vu)) && !/^m$|^met|nautical|nm/.test(q.du);
      return { ok: true, kind: q.kind, value: Math.round(hours * 1e6) / 1e6, hours, text: fmtDur(mins) + " (" + fmt(Math.round(hours * 1000) / 1000) + " hours)", mixed, d: q.d, du: q.du, v: q.v, vu: q.vu };
    }
    case "steps": {
      const m = q.n * 0.762; // average adult stride, about 2.5 ft
      const km = m / 1000, mi = m / 1609.344;
      const want = q.unit ? (/^mi/.test(q.unit) ? "mi" : /^k/.test(q.unit) ? "km" : /^(?:m|met)/.test(q.unit) ? "m" : "ft") : null;
      const val = want === "mi" ? mi : want === "km" ? km : want === "m" ? m : want === "ft" ? m / 0.3048 : null;
      return { ok: true, kind: q.kind, n: q.n, km: r2(km), mi: r2(mi), value: val != null ? r2(val) : r2(km), unit: want, text: q.n.toLocaleString("en-US") + " steps is about " + (want ? r2(val) + " " + want : r2(km) + " km (" + r2(mi) + " miles)") };
    }
    case "port": { const [n, proto, desc] = q.entry; return { ok: true, kind: q.kind, value: n, port: n, proto, desc, text: desc + " uses " + proto.toUpperCase() + " port " + n }; }
    case "portnum": {
      if (!q.entry) return { ok: false, error: "Port " + q.n + " has no well-known assignment in my table (I cover the common service ports: 20-25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 27017, ...)." + (q.n > 65535 ? " Port numbers only go up to 65535." : q.n >= 49152 ? " Ports 49152-65535 are dynamic/ephemeral ports handed out to client connections." : q.n >= 1024 ? " Ports 1024-49151 are registered ports; many applications pick one." : "") };
      const [n, proto, desc] = q.entry; return { ok: true, kind: q.kind, value: n, port: n, proto, desc, text: "Port " + n + " (" + proto.toUpperCase() + ") is " + desc };
    }
    case "yearago": return { ok: true, kind: q.kind, value: nowY - q.n, text: String(nowY - q.n) + " (" + q.n + " years before " + nowY + ")" };
    case "yearahead": return { ok: true, kind: q.kind, value: nowY + q.n, text: String(nowY + q.n) + " (" + q.n + " years after " + nowY + ")" };
    case "birthyear": return { ok: true, kind: q.kind, value: nowY - q.age, text: (nowY - q.age) + " if their birthday has already passed this year, otherwise " + (nowY - q.age - 1) };
    default: return { ok: false, error: "not an everyday request" };
  }
}

// ---------------------------------------------------------------------------
// say(): the written answer
// ---------------------------------------------------------------------------
const RANDOM_NOTE = "Drawn from the device's cryptographic random source, so it is a fair draw, not a guess.";
export function say(res) {
  if (!res.ok) return { title: "Everyday tool", body: res.error, result: res };
  switch (res.kind) {
    case "between": return { title: "Time between", body: "From **" + res.a + "** to **" + res.b + "** is **" + res.text + "**.", note: "Clock arithmetic on the two times (no dates involved).", result: res };
    case "clockadd": return { title: "Clock math", body: "**" + res.from + "** " + (res.delta >= 0 ? "plus" : "minus") + " " + fmtDur(Math.abs(res.delta)) + " is **" + res.text + "**.", result: res };
    case "tz": return { title: "Current time", body: "It is **" + res.text + "**.", note: "Read from this device's clock and the IANA time zone database built into the browser, including daylight-saving rules.", result: res };
    case "coin": return { title: "Coin flip", body: "**" + res.text + "**.", note: RANDOM_NOTE, result: res };
    case "dice": return { title: "Dice roll", body: "**" + res.text + "**.", note: RANDOM_NOTE, result: res };
    case "randnum": return { title: "Random number", body: "**" + res.text + "** (between " + res.lo + " and " + res.hi + ", inclusive).", note: RANDOM_NOTE, result: res };
    case "pick": return { title: "Pick", body: "**" + res.choice + "**. (Chose one of " + res.opts.length + ": " + res.opts.join(", ") + ".)", note: RANDOM_NOTE, result: res };
    case "shuffle": return { title: "Shuffled", body: "In random order:", pre: res.items.join("\n"), note: "Fisher-Yates shuffle. " + RANDOM_NOTE, result: res };
    case "uuid": return { title: res.ids.length === 1 ? "UUID" : res.ids.length + " UUIDs", body: "Random (version 4) UUID" + (res.ids.length === 1 ? "" : "s") + ":", pre: res.text, note: "122 random bits from the device's cryptographic source; the version and variant bits are set per RFC 4122.", result: res };
    case "lorem": return { title: "Placeholder text", body: res.n + " " + res.unit + " of lorem ipsum:", pre: res.text, note: "The classic Cicero-derived filler, so it carries no meaning.", result: res };
    case "tip": return { title: "Tip", body: "On a bill of **$" + usd(res.bill) + "**" + (res.ways ? ", split " + res.ways + " ways" : "") + ":", pre: res.text, note: "Tip = bill x rate; rounded to the cent.", result: res };
    case "bmi": return { title: "BMI", body: "**" + res.text + "**.", note: "BMI = weight (kg) / height (m)^2. Bands: under 18.5 underweight, 18.5-24.9 normal, 25-29.9 overweight, 30+ obese (WHO adult ranges; a rough screen, not a diagnosis).", result: res };
    case "loan": return { title: "Loan payment", body: "**$" + usd(res.payment) + " per month** on $" + usd(res.p) + " at " + res.rate + "% for " + res.months + " months.", pre: "monthly payment  $" + usd(res.payment) + "\ntotal paid       $" + usd(res.total) + "\ntotal interest   $" + usd(res.interest), note: "Standard amortisation: payment = P r / (1 - (1 + r)^-n) with r the monthly rate; taxes, insurance and fees are not included.", result: res };
    case "save": return { title: "Savings", body: "You would have **" + res.text + "**.", note: res.rate == null ? "Plain total, no interest; add “at 4%” for compound growth." : "Future value of an ordinary annuity; interest compounds each deposit period.", result: res };
    case "travel": return { title: "Travel time", body: "**" + res.d + " " + res.du + "** at **" + res.v + " " + res.vu + "** takes **" + res.text + "**.", note: "time = distance / speed" + (res.mixed ? ", after converting the units to match" : "") + ".", result: res };
    case "steps": return { title: "Steps to distance", body: "**" + res.text + "**.", note: "Estimate: assumes an average stride of 0.76 m (2.5 ft); your own stride may differ by 10-20%.", result: res };
    case "port": return { title: "Port: " + res.desc.replace(/ \(.*$/, ""), body: "**" + res.text + "**.", note: "IANA service name and port number registry / de-facto default.", result: res };
    case "portnum": return { title: "Port " + res.port, body: "**" + res.text + "**.", note: "IANA service name and port number registry / de-facto default.", result: res };
    case "yearago": case "yearahead": return { title: "Year", body: "**" + res.text + "**.", note: "Counted from the current year on this device's clock.", result: res };
    case "birthyear": return { title: "Birth year", body: "**" + res.text + "**.", note: "Counted from the current year on this device's clock.", result: res };
    default: return { title: "Everyday tool", body: res.text || "", result: res };
  }
}
