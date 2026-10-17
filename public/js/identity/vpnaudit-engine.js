// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Remote Access Audit engine (vpnaudit). Pure: no DOM, no network, no clock
// (everything is relative to the timestamps in the data). Safe inside a Worker.
//
// Audits VPN / zero-trust remote-access logs against the HR roster: leavers still
// connecting, brute force that ended in a success, password spraying, impossible
// travel and concurrent distant sessions (only from coordinates the log itself
// carries), new countries, threat-feed sources, remote access without MFA,
// outdated clients, shared accounts, long / off-hours / dormant sessions and
// unusually large transfers.
//
// Inputs (several files, detected by content, column mapping when unsure):
//   fortigate        FortiGate event logs, subtype="vpn" (key=value syslog)
//   gp-csv           PAN-OS GlobalProtect log CSV export (Monitor > Logs > GlobalProtect)
//   gp-syslog        PAN-OS GlobalProtect syslog (CSV payload, type GLOBALPROTECT)
//   asa              Cisco ASA / FTD AnyConnect syslog (%ASA-x-nnnnnn)
//   openvpn-log      OpenVPN server log
//   openvpn-status   OpenVPN status file (status-version 1 or 2/3)
//   cloudflare       Cloudflare Access Logpush access_requests (JSON / NDJSON / CSV)
//   zpa              Zscaler ZPA LSS user status / user activity (JSON / CSV)
//   azure-p2s        Azure VPN Gateway P2SDiagnosticLog / GatewayDiagnosticLog (JSON)
//   generic          CSV: ts,user,src_ip,country,lat,lon,event,mfa,client,client_version,device_id,duration_s,bytes_in,bytes_out
//   roster / mapping / service   HR roster, username->email map, service-account list
//
// Normalised event: { t, u, ip, k: auth|connect|disconnect|touch, ok, m (method),
// mfa, lat, lon, cc, dev, cli, ver, prod, bin, bout, dur (s), sk (session key),
// gw, pip, why, f (file index), ln (line) }.
// "bout" is always bytes sent from the corporate side TO the remote user (what a
// user could take away): FortiGate sentbyte, ASA "Bytes xmt", OpenVPN "Bytes Sent",
// generic bytes_out.
//
// Controls cited: MITRE ATT&CK T1133, T1078, T1110, T1110.003, T1110.004;
// NIST SP 800-53 Rev. 5 AC-17, AC-2(3), AC-2(9), AC-2(12), AC-2(13), AC-7, AC-12,
// IA-2(1), IA-2(2), SA-22, SI-4; NIST SP 800-46 Rev. 2; CIS Controls v8 6.4, 6.2,
// 5.3, 2.2, 8.11; ISO/IEC 27001:2022 A.5.18, A.6.5, A.6.7, A.8.5, A.8.16, A.8.12;
// SOC 2 CC6.1, CC6.2, CC6.6, CC7.2.

import { iterCsv, iterJson, findColumn, flatten } from "../ingest/parse.js";
import { haversineKm } from "./signin-forensics-engine.js";
import { isIp, compileCidrs, isInternalIp, ipToInt } from "../ops/log-hunter-engine.js";

export const TOOL_ID = "vpnaudit";
export const VERSION = "1.0.0";

const MIN = 60000, HOUR = 3600000, DAY = 86400000, GB = 1024 ** 3;
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const SEV_WEIGHT = { critical: 40, high: 20, medium: 8, low: 3, info: 0 };
const EVIDENCE_CAP = 50;

/** Logical columns per tabular format -> accepted header names (case-insensitive, punctuation ignored). */
export const COLUMNS = {
  generic: {
    ts: ["ts", "timestamp", "time", "datetime", "date", "event_time", "created", "createdat"],
    user: ["user", "username", "user_name", "account", "email", "principal", "login"],
    src_ip: ["src_ip", "source_ip", "client_ip", "public_ip", "ip", "ip_address", "remote_ip", "remip"],
    country: ["country", "country_code", "geo_country", "srccountry"],
    lat: ["lat", "latitude", "geo_lat"],
    lon: ["lon", "lng", "long", "longitude", "geo_lon"],
    event: ["event", "event_type", "action", "type", "activity"],
    result: ["result", "outcome", "status"],
    mfa: ["mfa", "mfa_used", "multi_factor", "2fa"],
    method: ["auth_method", "method", "authentication_method"],
    client: ["client", "client_name", "product", "agent"],
    client_version: ["client_version", "version", "agent_version"],
    device_id: ["device_id", "device", "host_id", "hostname", "machine", "machine_name"],
    duration_s: ["duration_s", "duration", "session_duration", "duration_seconds"],
    bytes_in: ["bytes_in", "bytes_received", "rcvdbyte"],
    bytes_out: ["bytes_out", "bytes_sent", "sentbyte"],
    gateway: ["gateway", "vpn_gateway", "concentrator"],
    session_id: ["session_id", "sessionid", "tunnel_id"],
  },
  globalprotect: {
    ts: ["Time Generated", "Generate Time", "Generated Time", "time_generated", "Receive Time"],
    event_id: ["Event ID", "eventid"],
    stage: ["Stage"],
    method: ["Authentication Method", "Auth Method", "auth_method"],
    user: ["Source User", "srcuser", "User"],
    region: ["Source Region", "srcregion"],
    machine: ["Machine Name", "machinename"],
    public_ip: ["Public IP", "public_ip"],
    public_ipv6: ["Public IPv6", "public_ipv6"],
    private_ip: ["Private IP", "private_ip"],
    host_id: ["Host ID", "hostid"],
    client_version: ["Client Version", "client_ver"],
    client_os: ["Client OS", "client_os"],
    status: ["Status"],
    reason: ["Reason"],
    error: ["Error"],
    login_duration: ["Login Duration", "login_duration"],
    gateway: ["Gateway"],
    portal: ["Portal"],
  },
  zpa: {
    ts: ["TimestampAuthentication", "LogTimestamp", "Timestamp"],
    ts_end: ["TimestampUnAuthentication"],
    user: ["Username", "User"],
    session_id: ["SessionID", "Session ID"],
    status: ["SessionStatus", "Status"],
    conn_status: ["ConnectionStatus"],
    ip: ["ClientPublicIP", "PublicIP", "Public IP"],
    lat: ["ClientLatitude", "Latitude"],
    lon: ["ClientLongitude", "Longitude"],
    country: ["ClientCountryCode", "CountryCode"],
    city: ["ClientCity", "City"],
    platform: ["Platform"],
    version: ["Version", "ClientVersion"],
    device: ["Hostname", "CertificateCN", "DeviceID"],
    bytes_rx: ["TotalBytesRx", "ClientToServerBytes"],
    bytes_tx: ["TotalBytesTx", "ServerToClientBytes"],
    idp: ["Idp"],
  },
  cloudflare: {
    ts: ["CreatedAt", "Datetime", "created_at"],
    user: ["Email", "UserEmail", "email"],
    ip: ["IPAddress", "ip_address"],
    country: ["Country", "country"],
    action: ["Action", "action"],
    allowed: ["Allowed", "allowed"],
    app: ["AppDomain", "app_domain"],
    idp: ["Connection", "connection"],
    ray: ["RayID", "ray_id"],
    user_uid: ["UserUID", "user_uid"],
  },
  roster: {
    employee_id: ["employee_id", "employee id", "employee number", "worker id", "emp id", "employee #"],
    name: ["name", "full name", "worker", "display name", "employee name"],
    email: ["email", "work email", "email - primary work", "email address", "mail"],
    username: ["username", "user name", "login", "samaccountname", "user id", "userid", "uid"],
    department: ["department", "dept", "cost center", "team"],
    manager_email: ["manager_email", "manager email", "manager", "reports to"],
    status: ["status", "employment status", "active status", "worker status"],
    hire_date: ["hire_date", "hire date", "start date", "start_date"],
    termination_date: ["termination_date", "termination date", "term date", "end date", "last day", "separation date"],
  },
  mapping: {
    username: ["username", "user", "account", "vpn_user", "login", "user name"],
    email: ["email", "mail", "user_email", "upn"],
  },
};

/** Tunable thresholds and settings; the UI renders these as the settings panel. */
export const DEFAULTS = {
  failThreshold: 10, // failed authentications for one user ...
  bfWindowMin: 30, // ... within this many minutes before a success
  sprayUsers: 10, // distinct users failing from one source IP ...
  sprayWindowMin: 60, // ... within this many minutes
  maxKmh: 900, // impossible-travel speed
  minTravelKm: 100, // ignore hops shorter than this (IP geolocation jitter)
  concurrentMinKm: 500, // overlapping sessions this far apart
  sharedDevices: 3, // distinct devices connected at the same time
  sharedIps: 4, // distinct public source IPs ...
  sharedWindowMin: 60, // ... within this many minutes
  maxSessionHours: 24,
  dormantDays: 90,
  baselineDays: 7, // first N days of the log form each user's baseline
  minBaselineEvents: 3, // baseline accesses needed before "new" / off-hours checks judge a user
  bytesZ: 4, // robust z-score threshold for bytes sent to the user
  bytesOutGb: 5, // absolute per-session threshold
  minBytesSamples: 8, // sessions with byte counts needed before the z-score is used
  minZGb: 1, // the z-score only flags sessions above this many GB (small sessions vary widely)
  businessStart: 8,
  businessEnd: 18,
  weekendOffHours: true,
  timeZone: "UTC", // business-hours zone (IANA name or UTC+hh:mm)
  logTimeZone: "UTC", // zone for log timestamps that carry none
  syslogYear: null, // year for syslog lines without a year (blank = taken from the data)
  serviceAccounts: [],
  allowIps: [],
  internalCidrs: [],
  minClientVersions: {}, // { anyconnect, globalprotect, forticlient, openvpn, zscaler, other }
  feedIps: null, // array of IP strings from /data/feeds/malicious-ips.json
  feedUpdated: null,
  maxSessionRows: 20000,
};

export const PRODUCTS = ["anyconnect", "globalprotect", "forticlient", "openvpn", "zscaler", "cloudflare", "azure", "other"];
export const PRODUCT_LABEL = { anyconnect: "Cisco AnyConnect / Secure Client", globalprotect: "GlobalProtect", forticlient: "FortiClient", openvpn: "OpenVPN", zscaler: "Zscaler Client Connector", cloudflare: "Cloudflare WARP", azure: "Azure VPN Client", other: "Other clients" };

export const FORMAT_LABEL = {
  fortigate: "FortiGate VPN event log", "gp-csv": "GlobalProtect log CSV", "gp-syslog": "GlobalProtect syslog", asa: "Cisco ASA / AnyConnect syslog",
  "openvpn-log": "OpenVPN server log", "openvpn-status": "OpenVPN status file", cloudflare: "Cloudflare Access requests", zpa: "Zscaler ZPA user log",
  "azure-p2s": "Azure VPN Gateway P2S diagnostic log", generic: "Generic remote-access CSV", roster: "HR roster", mapping: "Account mapping (username to email)",
  service: "Service-account list", unknown: "Unrecognised",
};

const INTERNAL_DEFAULT = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128"];
export const DEFAULT_INTERNAL_CIDRS = INTERNAL_DEFAULT.slice();

const C = {
  t1133: { framework: "MITRE", id: "T1133" },
  t1078: { framework: "MITRE", id: "T1078" },
  t1110: { framework: "MITRE", id: "T1110" },
  t1110_3: { framework: "MITRE", id: "T1110.003" },
  t1110_4: { framework: "MITRE", id: "T1110.004" },
  ac17: { framework: "NIST-800-53", id: "AC-17" },
  ac2_3: { framework: "NIST-800-53", id: "AC-2(3)" },
  ac2_9: { framework: "NIST-800-53", id: "AC-2(9)" },
  ac2_12: { framework: "NIST-800-53", id: "AC-2(12)" },
  ac2_13: { framework: "NIST-800-53", id: "AC-2(13)" },
  ac7: { framework: "NIST-800-53", id: "AC-7" },
  ac12: { framework: "NIST-800-53", id: "AC-12" },
  ia2_1: { framework: "NIST-800-53", id: "IA-2(1)" },
  ia2_2: { framework: "NIST-800-53", id: "IA-2(2)" },
  sa22: { framework: "NIST-800-53", id: "SA-22" },
  si4: { framework: "NIST-800-53", id: "SI-4" },
  sp80046: { framework: "NIST SP 800-46", id: "Rev. 2" },
  cis6_4: { framework: "CIS", id: "6.4" },
  cis6_2: { framework: "CIS", id: "6.2" },
  cis5_3: { framework: "CIS", id: "5.3" },
  cis2_2: { framework: "CIS", id: "2.2" },
  cis8_11: { framework: "CIS", id: "8.11" },
  a5_18: { framework: "ISO27001", id: "A.5.18" },
  a6_5: { framework: "ISO27001", id: "A.6.5" },
  a6_7: { framework: "ISO27001", id: "A.6.7" },
  a8_5: { framework: "ISO27001", id: "A.8.5" },
  a8_12: { framework: "ISO27001", id: "A.8.12" },
  a8_16: { framework: "ISO27001", id: "A.8.16" },
  cc6_1: { framework: "SOC2", id: "CC6.1" },
  cc6_2: { framework: "SOC2", id: "CC6.2" },
  cc6_6: { framework: "SOC2", id: "CC6.6" },
  cc7_2: { framework: "SOC2", id: "CC7.2" },
};

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------
const str = (v) => (v == null ? "" : String(v));
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const iso = (t) => (Number.isFinite(t) ? new Date(t).toISOString().replace(".000Z", "Z") : "");
const round = (n, d = 1) => (Number.isFinite(n) ? Math.round(n * 10 ** d) / 10 ** d : null);
const numOrNull = (v) => { if (v == null || v === "") return null; const n = Number(String(v).replace(/,/g, "")); return Number.isFinite(n) ? n : null; };
const BAD_USER = new Set(["", "n/a", "na", "-", "none", "null", "(null)", "unknown", "undef", "*****", "***", "pre-logon", "prelogon"]);

/** Iterate lines of a big string without splitting it into one array. Yields [line, lineNo, endOffset]. */
export function* iterLines(text) {
  const s = String(text || "");
  const n = s.length;
  let i = s.charCodeAt(0) === 0xfeff ? 1 : 0, ln = 0;
  while (i < n) {
    let j = s.indexOf("\n", i);
    if (j < 0) j = n;
    let l = s.slice(i, j);
    if (l.endsWith("\r")) l = l.slice(0, -1);
    ln++;
    yield [l, ln, j];
    i = j + 1;
  }
}

function countLines(s) {
  let n = 0, i = -1;
  while ((i = s.indexOf("\n", i + 1)) !== -1) n++;
  return n + 1;
}

/** Numeric epoch in s / ms / us / ns -> ms. */
export function epochMs(n) {
  if (!Number.isFinite(n)) return null;
  if (n > 1e17) return Math.floor(n / 1e6);
  if (n > 1e14) return Math.floor(n / 1e3);
  if (n > 1e11) return Math.floor(n);
  return Math.floor(n * 1000);
}

// ---------------------------------------------------------------------------
// Time zones. A zone is UTC, a fixed offset ("UTC+02:00", "+0530") or an IANA
// name resolved with Intl (deterministic: depends only on the tz database).
// ---------------------------------------------------------------------------
const zoneCache = new Map();
export function makeZone(z) {
  const s = str(z).trim();
  if (!s || /^(utc|gmt|z)$/i.test(s)) return { kind: "fixed", off: 0, name: "UTC" };
  if (zoneCache.has(s)) return zoneCache.get(s);
  let out = null;
  const m = s.match(/^(?:utc|gmt)?\s*([+-])(\d{1,2})(?::?(\d{2}))?$/i);
  if (m) out = { kind: "fixed", off: (m[1] === "-" ? -1 : 1) * (Number(m[2]) * 60 + Number(m[3] || 0)) * MIN, name: s };
  else {
    try {
      const fmt = new Intl.DateTimeFormat("en-US", { timeZone: s, hourCycle: "h23", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", weekday: "short" });
      out = { kind: "iana", fmt, name: s };
    } catch (_) { out = null; }
  }
  zoneCache.set(s, out);
  return out;
}

const WD = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
/** Wall-clock parts of instant t in zone z: { y, mo, d, h, mi, s, dow }. */
export function zoneParts(t, z) {
  if (!z || z.kind === "fixed") {
    const d = new Date(t + (z ? z.off : 0));
    return { y: d.getUTCFullYear(), mo: d.getUTCMonth() + 1, d: d.getUTCDate(), h: d.getUTCHours(), mi: d.getUTCMinutes(), s: d.getUTCSeconds(), dow: d.getUTCDay() };
  }
  const p = {};
  for (const x of z.fmt.formatToParts(new Date(t))) p[x.type] = x.value;
  return { y: +p.year, mo: +p.month, d: +p.day, h: +p.hour % 24, mi: +p.minute, s: +p.second, dow: WD[p.weekday] };
}

function zoneOffset(t, z) {
  if (!z || z.kind === "fixed") return z ? z.off : 0;
  const p = zoneParts(t, z);
  return Date.UTC(p.y, p.mo - 1, p.d, p.h, p.mi, p.s) - Math.floor(t / 1000) * 1000;
}

/** Wall-clock time in zone z -> epoch ms (DST-aware for IANA zones). */
export function localToUtc(y, mo, d, h, mi, s, z, ms = 0) {
  const guess = Date.UTC(y, mo - 1, d, h, mi, s, ms);
  if (!z || z.kind === "fixed") return guess - (z ? z.off : 0);
  const o1 = zoneOffset(guess, z);
  let t = guess - o1;
  const o2 = zoneOffset(t, z);
  if (o2 !== o1) t = guess - o2;
  return t;
}

const MON = { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12 };
function offFromDesignator(z) {
  if (!z || /^(z|utc|gmt)$/i.test(z)) return 0;
  const m = z.match(/^([+-])(\d{2}):?(\d{2})$/);
  return m ? (m[1] === "-" ? -1 : 1) * (Number(m[2]) * 60 + Number(m[3])) * MIN : 0;
}

/**
 * Parse a log timestamp to epoch ms, or null. Zone-less wall-clock times are read
 * in tc.zone (the "log time zone" setting); syslog stamps without a year use tc.year.
 * Never consults the machine's local zone or clock.
 */
export function parseTime(v, tc = {}) {
  if (v == null || v === "") return null;
  if (typeof v === "number") return epochMs(v);
  const s = String(v).trim();
  const z = tc.zone || null;
  let m;
  if (/^\d{9,19}(\.\d+)?$/.test(s)) return epochMs(Number(s));
  if ((m = s.match(/^(\d{4})[-/](\d{1,2})[-/](\d{1,2})(?:[T ]+(\d{1,2}):(\d{2})(?::(\d{2}))?(?:[.,](\d+))?)?\s*(Z|UTC|GMT|[+-]\d{2}:?\d{2})?$/i))) {
    const ms = m[7] ? Math.round(Number("0." + m[7]) * 1000) : 0;
    if (m[8]) return Date.UTC(+m[1], +m[2] - 1, +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0), ms) - offFromDesignator(m[8]);
    return localToUtc(+m[1], +m[2], +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0), z, ms);
  }
  // "Oct 16 2026 09:14:03" (ASA logging timestamp) / "Oct 16 2026 09:14:03 UTC"
  if ((m = s.match(/^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})(?:\.\d+)?(?:\s*(Z|UTC|GMT|[+-]\d{2}:?\d{2}))?$/))) {
    const mo = MON[m[1].toLowerCase()]; if (!mo) return null;
    if (m[7]) return Date.UTC(+m[3], mo - 1, +m[2], +m[4], +m[5], +m[6]) - offFromDesignator(m[7]);
    return localToUtc(+m[3], mo, +m[2], +m[4], +m[5], +m[6], z);
  }
  // "Thu Oct 16 09:14:03 2026" (OpenVPN < 2.5, ZPA LogTimestamp)
  if ((m = s.match(/^(?:[A-Za-z]{3},?\s+)?([A-Za-z]{3})\s+(\d{1,2})\s+(\d{1,2}):(\d{2}):(\d{2})\s+(\d{4})$/))) {
    const mo = MON[m[1].toLowerCase()]; if (!mo) return null;
    return localToUtc(+m[6], mo, +m[2], +m[3], +m[4], +m[5], z);
  }
  // Syslog "Oct 16 09:14:03" (no year)
  if ((m = s.match(/^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{1,2}):(\d{2}):(\d{2})(?:\.\d+)?$/))) {
    const mo = MON[m[1].toLowerCase()]; if (!mo || !tc.year) return null;
    return localToUtc(tc.year, mo, +m[2], +m[3], +m[4], +m[5], z);
  }
  // "10/16/2026 09:14:03 AM"
  if ((m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4}),?\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([AP]M)?$/i))) {
    let h = +m[4];
    if (m[7]) { const pm = m[7].toUpperCase() === "PM"; if (pm && h < 12) h += 12; if (!pm && h === 12) h = 0; }
    return localToUtc(+m[3], +m[1], +m[2], h, +m[5], +(m[6] || 0), z);
  }
  if (/(z|utc|gmt|[+-]\d{2}:?\d{2})$/i.test(s)) { const t = Date.parse(s); return Number.isFinite(t) ? t : null; }
  return null;
}

/** Parse a date (roster) to { y, mo, d } or null. */
export function parseDay(v) {
  const s = str(v).trim();
  if (!s) return null;
  let m;
  if ((m = s.match(/^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})/))) return { y: +m[1], mo: +m[2], d: +m[3] };
  if ((m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})/))) return { y: +m[3], mo: +m[1], d: +m[2] };
  if ((m = s.match(/^(\d{1,2})[.-]([A-Za-z]{3})[.-](\d{4})/))) { const mo = MON[m[2].toLowerCase()]; return mo ? { y: +m[3], mo, d: +m[1] } : null; }
  return null;
}

// ---------------------------------------------------------------------------
// Identity helpers
// ---------------------------------------------------------------------------
/** Normalise a log user: lower-case, strip DOMAIN\ prefix and quotes; null for placeholders. */
export function normUser(u) {
  let s = str(u).trim().replace(/^["']|["']$/g, "").toLowerCase();
  if (BAD_USER.has(s)) return null;
  const bs = s.lastIndexOf("\\");
  if (bs >= 0) s = s.slice(bs + 1);
  s = s.trim();
  return BAD_USER.has(s) ? null : s;
}

function globToRe(g) {
  const s = str(g).trim().toLowerCase();
  if (!s) return null;
  if (!s.includes("*")) return { exact: s };
  return { re: new RegExp("^" + s.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$") };
}

/** Compare dotted versions numerically: -1 / 0 / 1. */
export function cmpVersion(a, b) {
  const pa = str(a).split(/[^0-9]+/).filter(Boolean).map(Number), pb = str(b).split(/[^0-9]+/).filter(Boolean).map(Number);
  const n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; i++) { const x = pa[i] || 0, y = pb[i] || 0; if (x !== y) return x < y ? -1 : 1; }
  return 0;
}

export function productOf(client) {
  const s = str(client).toLowerCase();
  if (!s) return null;
  if (/anyconnect|secure client|cisco/.test(s)) return "anyconnect";
  if (/globalprotect|palo ?alto|\bgp\b/.test(s)) return "globalprotect";
  if (/forti/.test(s)) return "forticlient";
  if (/openvpn|ovpn/.test(s)) return "openvpn";
  if (/zscaler|zcc|zpa|client connector/.test(s)) return "zscaler";
  if (/warp|cloudflare/.test(s)) return "cloudflare";
  if (/azure/.test(s)) return "azure";
  return "other";
}

/** MFA from an authentication method name: true / false / null (unknown, e.g. delegated to an IdP). */
export function mfaFromMethod(m) {
  const s = str(m).trim().toLowerCase();
  if (!s) return null;
  if (/\bmfa\b|otp|totp|duo|push|fido|webauthn|2fa|two.?factor|multi.?factor|token|okta verify|authenticator|smart ?card|yubi/.test(s)) return true;
  if (/^(local|local database|password|ldap|kerberos|ntlm|basic|pap|chap|mschap|mschapv2|aaa|radius-pap|user\/pass|username\/password)$/.test(s)) return false;
  return null;
}

function parseMfaFlag(v) {
  const s = str(v).trim().toLowerCase();
  if (!s) return null;
  if (["yes", "y", "true", "1", "mfa", "passed", "satisfied", "success"].includes(s)) return true;
  if (["no", "n", "false", "0", "none", "single", "single-factor", "password"].includes(s)) return false;
  return mfaFromMethod(s);
}

function parseBoolish(v) {
  if (v === true || v === false) return v;
  const s = str(v).trim().toLowerCase();
  if (["true", "yes", "1", "allowed", "allow"].includes(s)) return true;
  if (["false", "no", "0", "denied", "deny", "blocked"].includes(s)) return false;
  return null;
}

/** "1h:02m:03s" / "2d 3h:04m:05s" / "01:02:03" -> seconds. */
export function parseDuration(v) {
  const s = str(v).trim();
  if (!s) return null;
  if (/^\d+(\.\d+)?$/.test(s)) return Number(s);
  let m = s.match(/^(?:(\d+)d\s*)?(\d+)h:?\s*(\d+)m:?\s*(\d+)s$/i);
  if (m) return (+(m[1] || 0)) * 86400 + (+m[2]) * 3600 + (+m[3]) * 60 + (+m[4]);
  m = s.match(/^(\d+):(\d{2}):(\d{2})$/);
  if (m) return (+m[1]) * 3600 + (+m[2]) * 60 + (+m[3]);
  return null;
}

function stripPort(ip) {
  let s = str(ip).trim();
  if (!s) return null;
  if (s.startsWith("[")) { const k = s.indexOf("]"); return k > 0 ? s.slice(1, k) : null; }
  const m = s.match(/^(\d+\.\d+\.\d+\.\d+)(?::\d+)?$/);
  if (m) return m[1];
  s = s.replace(/^\[AF_INET6?\]/i, "");
  return isIp(s) ? s : null;
}

function cleanIp(v) {
  const s = stripPort(v);
  if (!s || s === "0.0.0.0" || s === "::" || !isIp(s)) return null;
  return s;
}

function geo(lat, lon) {
  const a = numOrNull(lat), o = numOrNull(lon);
  if (a == null || o == null || Math.abs(a) > 90 || Math.abs(o) > 180 || (a === 0 && o === 0)) return [null, null];
  return [a, o];
}

function cc(v) {
  const s = str(v).trim();
  if (!s || /^(n\/a|-|unknown|reserved|zz|xx|0)$/i.test(s)) return null;
  return s.length <= 3 ? s.toUpperCase() : s;
}

function mkEv(o) {
  return Object.assign({ t: null, u: null, ip: null, k: "auth", ok: null, m: null, mfa: null, lat: null, lon: null, cc: null, dev: null, cli: null, ver: null, prod: null, bin: null, bout: null, dur: null, sk: null, gw: null, pip: null, why: null, f: 0, ln: 0 }, o);
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------
const RE = {
  forti: /\blogid="?\d{10}"?/,
  fortiVpn: /\bsubtype="?vpn"?/,
  asa: /%(?:ASA|FTD)-\d-\d{6}:/,
  gpSys: /,GLOBALPROTECT,/,
  ovpnStatus: /^(?:HEADER,CLIENT_LIST|CLIENT_LIST[,\t]|OpenVPN CLIENT LIST|Common Name,Real Address)/m,
  ovpnLog: /Peer Connection Initiated|TLS Auth Error|AUTH_FAILED|client-instance exiting|MULTI_sva|peer info: IV_VER|Username\/Password authentication|OpenVPN \d+\.\d+/,
};

function headerHas(headers, aliases) { return !!findColumn(headers, aliases); }

function classifyHeaders(headers, name) {
  const H = headers || [];
  const has = (...a) => headerHas(H, a);
  if (has("Event ID") && (has("Source User") || has("Public IP")) && (has("Portal") || has("Gateway") || has("Stage") || has("Client Version"))) return { format: "gp-csv", confidence: has("Source User") && has("Public IP") ? "high" : "medium" };
  if (has("LogTimestamp") && has("Username") && (has("SessionStatus", "ConnectionStatus") || has("ClientPublicIP", "PublicIP"))) return { format: "zpa", confidence: has("SessionStatus", "ConnectionStatus") ? "high" : "medium" };
  if (has("RayID") && (has("Email") || has("IPAddress")) && (has("AppDomain") || has("Allowed"))) return { format: "cloudflare", confidence: "high" };
  const R = COLUMNS.roster;
  if ((has(...R.termination_date) || has(...R.hire_date) || has(...R.employee_id)) && (has(...R.email) || has(...R.username))) return { format: "roster", confidence: has(...R.termination_date) && has(...R.status) ? "high" : "medium" };
  const G = COLUMNS.generic;
  const gUser = has(...G.user), gTs = has(...G.ts), gEv = has(...G.event), gIp = has(...G.src_ip);
  if (gUser && gTs && (gEv || gIp)) return { format: "generic", confidence: gEv && gIp ? "high" : "medium" };
  if (H.length <= 3 && has(...COLUMNS.mapping.username) && has(...COLUMNS.mapping.email)) return { format: "mapping", confidence: "high" };
  if (H.length <= 3 && (has("service_account", "service account", "service accounts", "account") || /service/i.test(name || ""))) return { format: "service", confidence: "medium" };
  if (gUser && gTs) return { format: "generic", confidence: "low" };
  return { format: "unknown", confidence: "low" };
}

function firstJsonRecord(sample) {
  const t = sample.trim();
  const lineEnd = t.indexOf("\n");
  const first = lineEnd > 0 ? t.slice(0, lineEnd).trim() : t;
  try { const o = JSON.parse(first); if (o && typeof o === "object" && !Array.isArray(o)) return o; } catch (_) {}
  try { const all = iterJson(t); if (all.length && all[0] && typeof all[0] === "object") return all[0]; } catch (_) {}
  return null;
}

/**
 * Classify one file from a sample of its text. Returns
 * { format, kind: log|roster|mapping|service|unknown, confidence: high|medium|low, headers, container: csv|json|lines }.
 */
export function classifyText(name, text) {
  const sample = str(text).slice(0, 65536).replace(/^﻿/, "");
  const trimmed = sample.trim();
  const out = (format, confidence, headers = [], container = "lines") => ({
    format, confidence, headers, container,
    kind: format === "roster" || format === "mapping" || format === "service" ? format : format === "unknown" ? "unknown" : "log",
  });
  if (!trimmed) return out("unknown", "low");
  if (trimmed[0] === "{" || trimmed[0] === "[") {
    if (/P2SDiagnosticLog|GatewayDiagnosticLog|IKEDiagnosticLog|VIRTUALNETWORKGATEWAYS/i.test(sample)) return out("azure-p2s", /P2SDiagnosticLog/.test(sample) ? "high" : "medium", [], "json");
    const rec = firstJsonRecord(sample);
    const keys = rec ? Object.keys(flatten(rec)) : [];
    if (keys.length) {
      const c = classifyHeaders(keys, name);
      if (c.format !== "unknown") return out(c.format, c.confidence, keys, "json");
      if (keys.some((k) => /properties\.message/i.test(k))) return out("azure-p2s", "medium", keys, "json");
    }
    return out("unknown", "low", keys, "json");
  }
  const lines = [];
  for (const [l] of iterLines(sample)) { if (l.trim()) lines.push(l); if (lines.length >= 200) break; }
  const share = (re) => lines.filter((l) => re.test(l)).length / Math.max(1, lines.length);
  const csvHeaders = () => {
    try { const it = iterCsv(lines[0] + "\n", { header: false }); const h = it.next(); return h.done ? [] : h.value.map((x) => str(x).trim()); } catch (_) { return []; }
  };
  // A header row naming known columns wins over line patterns (a GlobalProtect CSV export contains ",GLOBALPROTECT," too).
  if (lines[0] && /[,;\t|]/.test(lines[0]) && !RE.forti.test(lines[0]) && !RE.asa.test(lines[0])) {
    const headers = csvHeaders();
    const c = classifyHeaders(headers, name);
    if (c.format !== "unknown" && c.confidence !== "low") return out(c.format, c.confidence, headers, "csv");
  }
  if (lines.some((l) => RE.forti.test(l)) && lines.some((l) => /\b(?:type="?event"?|action="?(?:tunnel-up|tunnel-down|ssl-login-fail))/.test(l))) return out("fortigate", share(RE.forti) >= 0.5 ? "high" : "medium");
  if (lines.some((l) => RE.asa.test(l))) return out("asa", share(RE.asa) >= 0.5 ? "high" : "medium");
  if (lines.some((l) => RE.gpSys.test(l))) return out("gp-syslog", share(RE.gpSys) >= 0.5 ? "medium" : "low");
  if (RE.ovpnStatus.test(sample)) return out("openvpn-status", "high");
  if (lines.some((l) => RE.ovpnLog.test(l))) return out("openvpn-log", share(/\d{1,3}(?:\.\d{1,3}){3}:\d+|MULTI|TLS|OpenVPN|SIG(?:TERM|USR1)/) >= 0.4 ? "high" : "medium");
  // Delimited text
  const first = lines[0] || "";
  if (/[,;\t|]/.test(first)) {
    const headers = csvHeaders();
    const c = classifyHeaders(headers, name);
    return out(c.format, c.confidence, headers, "csv");
  }
  if (/service/i.test(name || "")) return out("service", "medium", [], "lines");
  return out("unknown", "low");
}

/**
 * Parse the dropped input. `input` is a string or [{ name, text }]. Each file is
 * classified; with parse=true the log events are also parsed (returned as rows).
 * The UI calls it with parse=false and lets analyze() parse inside the Worker.
 */
export function parseInput(input, { parse = true, opts = {} } = {}) {
  const list = typeof input === "string" ? [{ name: "pasted.txt", text: input }] : Array.isArray(input) ? input : input && Array.isArray(input.files) ? input.files : [];
  const skipped = [];
  const files = [];
  for (const f of list) {
    if (!f) continue;
    const text = str(f.text);
    const c = classifyText(f.name, text);
    const file = { name: str(f.name || "file"), text, ...c, columns: f.columns || {}, lines: text ? countLines(text) : 0 };
    if (f.format && f.format !== c.format) { Object.assign(file, { format: f.format, kind: kindOf(f.format), confidence: "medium" }); }
    if (c.format === "unknown") skipped.push({ check: "parse", reason: file.name + ": format not recognised (choose one in the files panel)" });
    files.push(file);
  }
  files.sort((a, b) => cmp(a.name, b.name));
  let rows = [];
  if (parse) {
    const tc = timeContext(files, opts);
    files.forEach((file, i) => {
      if (file.kind !== "log") return;
      const r = parseLogFile(file, i, tc);
      for (const e of r.events) rows.push(e);
      for (const s of r.notes) skipped.push(s);
    });
  }
  return { format: files.length === 1 ? files[0].format : files.length ? "multi" : "empty", headers: files[0] ? files[0].headers : [], rows, skipped, files };
}

function kindOf(format) { return format === "roster" || format === "mapping" || format === "service" ? format : format === "unknown" || format === "ignore" ? "unknown" : "log"; }

/** Column spec (logical -> aliases) for a tabular format, used by the mapping panel. */
export function columnSpec(format) {
  return { "gp-csv": COLUMNS.globalprotect, zpa: COLUMNS.zpa, cloudflare: COLUMNS.cloudflare, generic: COLUMNS.generic, roster: COLUMNS.roster, mapping: COLUMNS.mapping }[format] || null;
}

function resolveColumns(headers, spec, overrides) {
  const out = {};
  for (const [k, aliases] of Object.entries(spec || {})) {
    const o = overrides && overrides[k];
    if (o && headers.includes(o)) { out[k] = o; continue; }
    const h = findColumn(headers, aliases);
    if (h) out[k] = h;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Log parsers
// ---------------------------------------------------------------------------
function timeContext(files, opts) {
  const zone = makeZone(opts.logTimeZone || "UTC") || makeZone("UTC");
  let year = Number(opts.syslogYear) || null;
  if (!year) {
    let best = 0;
    for (const f of files) {
      const s = f.text.slice(0, 65536);
      const re = /\b(20\d{2})[-/]\d{2}[-/]\d{2}\b|\b[A-Z][a-z]{2}\s+\d{1,2}\s+(20\d{2})\s+\d{2}:/g;
      let m;
      while ((m = re.exec(s))) { const y = Number(m[1] || m[2]); if (y > best) best = y; }
    }
    year = best || null;
  }
  return { zone, year };
}

const SYSLOG_PREFIX = /^(?:<\d+>\s*)?(?:\d+\s+)?(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|[A-Z][a-z]{2}\s+\d{1,2}\s+(?:\d{4}\s+)?\d{1,2}:\d{2}:\d{2}(?:\.\d+)?)/;

function prefixTime(line, tc) {
  const m = line.match(SYSLOG_PREFIX);
  return m ? parseTime(m[1], tc) : null;
}

/** FortiGate key=value with quoted and unquoted values. */
export function parseKv(line) {
  const o = {};
  const re = /([A-Za-z_][\w-]*)=(?:"((?:[^"\\]|\\.)*)"|(\S*))/g;
  let m;
  while ((m = re.exec(line))) o[m[1].toLowerCase()] = m[2] !== undefined ? m[2].replace(/\\"/g, '"') : m[3];
  return o;
}

function fortiTime(kv, tc) {
  if (kv.eventtime && /^\d+$/.test(kv.eventtime)) return epochMs(Number(kv.eventtime));
  if (kv.date && kv.time) {
    const m = kv.date.match(/^(\d{4})-(\d{2})-(\d{2})$/), t = kv.time.match(/^(\d{1,2}):(\d{2}):(\d{2})$/);
    if (m && t) {
      if (kv.tz && /^[+-]\d{4}$/.test(kv.tz)) return Date.UTC(+m[1], +m[2] - 1, +m[3], +t[1], +t[2], +t[3]) - offFromDesignator(kv.tz.slice(0, 3) + ":" + kv.tz.slice(3));
      return localToUtc(+m[1], +m[2], +m[3], +t[1], +t[2], +t[3], tc.zone);
    }
  }
  return null;
}

function parseFortiLine(line, f, ln, tc) {
  if (!RE.forti.test(line)) return null;
  const kv = parseKv(line);
  const action = str(kv.action).toLowerCase();
  const desc = str(kv.logdesc).toLowerCase();
  const isVpn = str(kv.subtype).toLowerCase() === "vpn" || /tunnel-|ssl-login|ssl-new-con/.test(action);
  if (!isVpn) return null;
  const t = fortiTime(kv, tc);
  const u = kv.user && kv.user !== "N/A" ? kv.user : kv.xauthuser && kv.xauthuser !== "N/A" ? kv.xauthuser : null;
  const ip = cleanIp(kv.remip);
  const base = { t, u, ip, f, ln, gw: kv.devname || null, cc: cc(kv.srccountry), prod: "forticlient", dev: kv.hostname || kv.clientmac || null };
  const sk = (kv.devname || "") + "|" + (kv.vd || "") + "|" + (kv.tunnelid || (u || "") + "@" + (ip || ""));
  if (/login-fail|auth-fail/.test(action) || /login fail|authentication fail/.test(desc)) return mkEv({ ...base, k: "auth", ok: false, why: kv.reason && kv.reason !== "N/A" ? kv.reason : kv.msg || null });
  if (action === "tunnel-up") return mkEv({ ...base, k: "connect", ok: true, sk, pip: cleanIp(kv.tunnelip) });
  if (action === "tunnel-down") return mkEv({ ...base, k: "disconnect", sk, dur: numOrNull(kv.duration), bout: numOrNull(kv.sentbyte), bin: numOrNull(kv.rcvdbyte), why: kv.reason && kv.reason !== "N/A" ? kv.reason : null });
  return null;
}

const ASA_MSG = /%(?:ASA|FTD)-(\d)-(\d{6}):\s*(.*)$/;
function parseAsaLine(line, f, ln, tc) {
  const m = line.match(ASA_MSG);
  if (!m) return null;
  const id = m[2], msg = m[3];
  const t = prefixTime(line.slice(0, line.indexOf("%")).trim(), tc);
  const base = { t, f, ln, prod: "anyconnect", m: "AAA" };
  let x;
  if (id === "113039" && (x = msg.match(/Group <([^>]*)> User <([^>]*)> IP <([^>]*)> AnyConnect parent session started/i))) {
    return mkEv({ ...base, k: "connect", ok: true, u: x[2], ip: cleanIp(x[3]), sk: normUser(x[2]) + "|" + x[3], gw: x[1] });
  }
  if (id === "722022" && (x = msg.match(/Group <([^>]*)> User <([^>]*)> IP <([^>]*)> (?:TCP|UDP) SVC connection established/i))) {
    return mkEv({ ...base, k: "connect", ok: true, u: x[2], ip: cleanIp(x[3]), sk: normUser(x[2]) + "|" + x[3], gw: x[1], why: "svc" });
  }
  if (id === "722051" && (x = msg.match(/Group <([^>]*)> User <([^>]*)> IP <([^>]*)> (?:IPv[46] )?Address <([^>]*)> assigned to session/i))) {
    return mkEv({ ...base, k: "touch", u: x[2], ip: cleanIp(x[3]), sk: normUser(x[2]) + "|" + x[3], pip: x[4], why: "assign" });
  }
  if (id === "722055" && (x = msg.match(/Group <([^>]*)> User <([^>]*)> IP <([^>]*)> Client Type: (.*)$/i))) {
    const ver = (x[4].match(/(\d+(?:\.\d+){1,3})\s*$/) || [])[1] || null;
    return mkEv({ ...base, k: "touch", u: x[2], ip: cleanIp(x[3]), sk: normUser(x[2]) + "|" + x[3], cli: x[4].trim(), ver, prod: productOf(x[4]) || "anyconnect", why: "client" });
  }
  if (id === "113019" && (x = msg.match(/Group = ([^,]*), Username = ([^,]*), IP = ([^,]*), Session disconnected\. Session Type: ([^,]*), Duration: ([^,]*), Bytes xmt: (\d+), Bytes rcv: (\d+), Reason: (.*)$/i))) {
    return mkEv({ ...base, k: "disconnect", u: x[2].trim(), ip: cleanIp(x[3]), sk: normUser(x[2]) + "|" + x[3].trim(), gw: x[1].trim(), dur: parseDuration(x[5]), bout: Number(x[6]), bin: Number(x[7]), why: x[8].trim() });
  }
  if (id === "113004" && (x = msg.match(/AAA user authentication Successful\s*:\s*server\s*=\s*([^:]+?)\s*:\s*user\s*=\s*(.+?)(?:\s*:\s*user IP\s*=\s*(\S+))?\s*$/i))) {
    return mkEv({ ...base, k: "auth", ok: true, u: x[2], ip: cleanIp(x[3]) });
  }
  if ((id === "113005" || id === "113015") && (x = msg.match(/AAA user authentication Rejected\s*:\s*reason\s*=\s*(.*?)\s*:.*?user\s*=\s*(.*?)\s*:\s*user IP\s*=\s*(\S+)/i))) {
    return mkEv({ ...base, k: "auth", ok: false, u: x[2], ip: cleanIp(x[3]), why: x[1] });
  }
  if (id === "716039" && (x = msg.match(/Group <([^>]*)> User <([^>]*)> IP <([^>]*)> Authentication: rejected/i))) {
    return mkEv({ ...base, k: "auth", ok: false, u: x[2], ip: cleanIp(x[3]), gw: x[1] });
  }
  return null;
}

// PAN-OS GlobalProtect syslog field order (PAN-OS 9.1+ GlobalProtect log format).
const GP_SYS = ["future1", "receive_time", "serial", "type", "subtype", "future2", "time_generated", "vsys", "event_id", "stage", "auth_method", "tunnel_type", "srcuser", "srcregion", "machinename", "public_ip", "public_ipv6", "private_ip", "private_ipv6", "hostid", "serialnumber", "client_ver", "client_os", "client_os_ver", "repeatcnt", "reason", "error", "opaque", "status", "location", "login_duration", "connect_method", "error_code", "portal", "seqno", "actionflags", "selection_type", "response_time", "priority", "attempted_gateways", "gateway"];

function gpEvent(r, f, ln, tc) {
  const evId = str(r.event_id).toLowerCase().trim();
  const status = str(r.status).toLowerCase().trim();
  const u = r.user;
  const t = parseTime(r.ts, tc);
  const ip = cleanIp(r.public_ip) || cleanIp(r.public_ipv6);
  const base = {
    t, u, ip, f, ln, m: r.method || null, mfa: mfaFromMethod(r.method), cc: cc(r.region), dev: r.host_id || r.machine || null,
    cli: r.client_os ? "GlobalProtect (" + r.client_os + ")" : "GlobalProtect", ver: r.client_version || null, prod: "globalprotect",
    gw: r.gateway || r.portal || null, pip: cleanIp(r.private_ip), why: r.error || r.reason || null,
  };
  const sk = normUser(u) + "|" + (r.host_id || r.machine || "") + "|" + (ip || "");
  if (/-auth$/.test(evId)) {
    if (status === "failure" || status === "failed") return mkEv({ ...base, k: "auth", ok: false });
    if (status === "success") return mkEv({ ...base, k: "auth", ok: true });
    return null;
  }
  if (evId === "gateway-connected") return status === "failure" ? null : mkEv({ ...base, k: "connect", ok: true, sk });
  if (evId === "gateway-logout") return mkEv({ ...base, k: "disconnect", sk, dur: numOrNull(r.login_duration) });
  return null;
}

function parseGpSyslogLine(line, f, ln, tc) {
  const i = line.search(/(?:^|[\s>])\d+,\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2},[^,]*,GLOBALPROTECT,/);
  if (i < 0) return null;
  const payload = line.slice(i).replace(/^[\s>]/, "");
  const it = iterCsv(payload, { header: false, delimiter: "," });
  const n = it.next();
  if (n.done) return null;
  const cols = n.value, r = {};
  GP_SYS.forEach((k, j) => { r[k] = cols[j] == null ? "" : cols[j]; });
  return gpEvent({ ts: r.time_generated || r.receive_time, event_id: r.event_id, status: r.status, user: r.srcuser, method: r.auth_method, region: r.srcregion, machine: r.machinename, host_id: r.hostid, public_ip: r.public_ip, public_ipv6: r.public_ipv6, private_ip: r.private_ip, client_version: r.client_ver, client_os: r.client_os, gateway: r.gateway, portal: r.portal, error: r.error, reason: r.reason, login_duration: r.login_duration }, f, ln, tc);
}

function makeOpenVpnParser() {
  const userByPeer = new Map(); // "ip:port" -> username from auth lines
  const verByPeer = new Map();
  return function parseOvpnLine(line, f, ln, tc) {
    const tsm = line.match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+|^([A-Z][a-z]{2} [A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2} \d{4})\s+/);
    let t = null, rest = line;
    if (tsm) { t = parseTime(tsm[1] || tsm[2], tc); rest = line.slice(tsm[0].length); }
    else {
      const sp = line.match(SYSLOG_PREFIX);
      if (sp) { t = parseTime(sp[1], tc); const k = line.indexOf("]: "); rest = k >= 0 ? line.slice(k + 3) : line.slice(sp[0].length).replace(/^\s*\S+\s+\S+:\s*/, ""); }
    }
    // "alice/203.0.113.5:51234 ..." or "203.0.113.5:51234 [alice] ..." or "203.0.113.5:51234 ..."
    const pm = rest.match(/^(?:([^\s/]+)\/)?(\[?[0-9a-fA-F:.]+\]?:\d+)\s+(?:\[([^\]]*)\]\s+)?(.*)$/);
    if (!pm) return null;
    const peer = pm[2], ip = cleanIp(peer.replace(/^\[AF_INET6?\]/, ""));
    const msg = pm[4];
    let u = pm[1] || pm[3] || null;
    const base = { t, ip, f, ln, prod: "openvpn", sk: peer };
    let x;
    if ((x = msg.match(/peer info:\s*IV_VER=(\S+)/))) { verByPeer.set(peer, x[1]); return null; }
    if ((x = msg.match(/Username\/Password authentication (succeeded|failed|deferred) for username '([^']*)'/i))) {
      userByPeer.set(peer, x[2]);
      if (/succeeded/i.test(x[1])) return mkEv({ ...base, k: "auth", ok: true, u: x[2], m: "password" });
      if (/failed/i.test(x[1])) return mkEv({ ...base, k: "auth", ok: false, u: x[2], m: "password" });
      return null;
    }
    if (/TLS Auth Error/i.test(msg)) return mkEv({ ...base, k: "auth", ok: false, u: u || userByPeer.get(peer) || null, why: msg.replace(/^TLS Auth Error:\s*/, "") });
    if ((x = msg.match(/SENT CONTROL \[([^\]]*)\]: 'AUTH_FAILED/))) return mkEv({ ...base, k: "auth", ok: false, u: x[1] || u, why: "AUTH_FAILED" });
    if (/Peer Connection Initiated/i.test(msg)) {
      const ver = verByPeer.get(peer) || null;
      return mkEv({ ...base, k: "connect", ok: true, u: u || userByPeer.get(peer) || null, ver, cli: ver ? "OpenVPN " + ver : "OpenVPN" });
    }
    if ((x = msg.match(/MULTI_sva: pool returned IPv4=(\S+)/))) return mkEv({ ...base, k: "touch", u, pip: x[1].replace(/,$/, ""), why: "assign" });
    if (/client-instance exiting|Inactivity timeout|connection-reset|Connection reset, restarting/i.test(msg) && (u || userByPeer.has(peer))) {
      return mkEv({ ...base, k: "disconnect", u: u || userByPeer.get(peer), why: msg.slice(0, 80) });
    }
    return null;
  };
}

function* parseOpenVpnStatus(text, f, tc) {
  // The status file is a snapshot: every client listed was still connected at the
  // snapshot time ("Updated," in v1, "TIME," in v2/v3), so each becomes a session
  // from "Connected Since" to the snapshot.
  let v1 = false, snap = null;
  const clients = [];
  for (const [l, ln] of iterLines(text)) {
    const d = l.includes("\t") && !l.includes(",") ? "\t" : ",";
    const p = l.split(d);
    if (/^OpenVPN CLIENT LIST/.test(l)) { v1 = true; continue; }
    if (p[0] === "Updated") { snap = parseTime(p[1], tc); continue; }
    if (p[0] === "TIME") { snap = /^\d+$/.test(str(p[2]).trim()) ? epochMs(Number(p[2])) : parseTime(p[1], tc); continue; }
    if (/^(ROUTING TABLE|GLOBAL STATS|END)/.test(l)) { v1 = false; continue; }
    if (p[0] === "CLIENT_LIST") {
      // CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID,Data Channel Cipher
      const v2 = p.length >= 10;
      const since = v2 ? p[8] : null;
      const t = since && /^\d+$/.test(since.trim()) ? epochMs(Number(since)) : parseTime(v2 ? p[7] : p[5], tc);
      const user = v2 && p[9] && p[9] !== "UNDEF" ? p[9] : p[1];
      clients.push(mkEv({ t, u: user, ip: cleanIp(p[2]), k: "connect", ok: true, sk: p[2], pip: p[3] || null, bin: numOrNull(v2 ? p[5] : p[4]), bout: numOrNull(v2 ? p[6] : p[5]), prod: "openvpn", f, ln, why: "status" }));
      continue;
    }
    // v1: Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
    if (v1 && p.length >= 5 && p[0] !== "Common Name") {
      clients.push(mkEv({ t: parseTime(p[4], tc), u: p[0], ip: cleanIp(p[1]), k: "connect", ok: true, sk: p[1], bin: numOrNull(p[2]), bout: numOrNull(p[3]), prod: "openvpn", f, ln, why: "status" }));
    }
  }
  for (const c of clients) {
    yield c;
    if (snap != null && c.t != null && snap > c.t) yield mkEv({ t: snap, u: c.u, ip: c.ip, k: "touch", sk: c.sk, f, ln: c.ln, why: "activity", prod: "openvpn" });
  }
}

function azureEvent(rec, f, ln, tc) {
  const flat = flatten(rec);
  const get = (...ks) => { for (const k of Object.keys(flat)) if (ks.includes(k.toLowerCase())) return flat[k]; return null; };
  const msg = str(get("properties.message", "message", "properties.msg"));
  if (!msg) return null;
  const t = parseTime(get("time", "timegenerated", "timestamp", "properties.time"), tc);
  const u = (msg.match(/\b(?:for user|user(?:name)?[:=]?)\s+'?([^\s',;]+@[^\s',;]+|[A-Za-z0-9._\\-]+)'?/i) || [])[1] || null;
  const ipm = msg.match(/\b(?:from|address|IP|public ip)[:=]?\s+(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?/i) || msg.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/);
  const ip = ipm ? cleanIp(ipm[1]) : null;
  const gw = str(get("resourceid")).split("/").pop() || null;
  const sk = normUser(u) + "|" + (ip || "");
  const base = { t, u, ip, f, ln, gw, prod: "azure", sk };
  if (/disconnect/i.test(msg)) return mkEv({ ...base, k: "disconnect", why: msg.slice(0, 100) });
  if (/(connection|authentication|auth)\b.*\b(fail|failed|failure|denied|rejected)|\bfailed to authenticate/i.test(msg)) return mkEv({ ...base, k: "auth", ok: false, why: msg.slice(0, 100) });
  if (/connection (?:successful|succeeded|established)|connected successfully|authentication (?:successful|succeeded)/i.test(msg)) return mkEv({ ...base, k: "connect", ok: true });
  return null;
}

function cfEvent(r, f, ln, tc) {
  const action = str(r.action).toLowerCase();
  if (action && !/login|sso/.test(action)) return null;
  const allowed = parseBoolish(r.allowed);
  return mkEv({
    t: parseTime(r.ts, tc), u: r.user, ip: cleanIp(r.ip), cc: cc(r.country), k: "auth", ok: allowed === null ? null : allowed,
    m: r.idp || null, gw: r.app || null, prod: "cloudflare", f, ln, why: allowed === false ? "policy denied" : null, deny: allowed === false ? "policy" : null,
  });
}

function zpaEvent(r, f, ln, tc) {
  const [lat, lon] = geo(r.lat, r.lon);
  const base = {
    u: r.user, ip: cleanIp(r.ip), lat, lon, cc: cc(r.country), dev: r.device || null, ver: r.version || null,
    cli: r.platform ? "Client Connector (" + r.platform + ")" : "Client Connector", prod: "zscaler", sk: r.session_id || null, f, ln, m: r.idp || null,
  };
  const st = str(r.status).toUpperCase();
  if (!st) {
    // User Activity log: one row per application connection; rows extend the session (SessionID) they belong to.
    if (r.conn_status === undefined && !r.session_id) return null;
    return mkEv({ ...base, t: parseTime(r.ts, tc), k: "touch", ok: true, why: "activity" });
  }
  // User Status log: ZPN_STATUS_AUTHENTICATED / ZPN_STATUS_DISCONNECTED / ZPN_STATUS_AUTH_FAILED
  if (/UNAUTH|DISCONNECT|CLOSE/.test(st)) {
    const tEnd = parseTime(r.ts_end, tc) ?? parseTime(r.ts, tc);
    return mkEv({ ...base, t: tEnd, k: "disconnect", bout: numOrNull(r.bytes_rx), bin: numOrNull(r.bytes_tx) });
  }
  if (/FAIL/.test(st)) return mkEv({ ...base, t: parseTime(r.ts, tc), k: "auth", ok: false, why: st });
  if (/AUTHENTICATED|CONNECTED/.test(st)) return mkEv({ ...base, t: parseTime(r.ts, tc), k: "connect", ok: true });
  return null;
}

function genericEvent(r, f, ln, tc) {
  const ev = str(r.event).toLowerCase().trim();
  const res = str(r.result).toLowerCase().trim();
  const t = parseTime(r.ts, tc);
  const [lat, lon] = geo(r.lat, r.lon);
  const mfaFlag = r.mfa != null && r.mfa !== "" ? parseMfaFlag(r.mfa) : mfaFromMethod(r.method);
  const prod = productOf(r.client) || (r.client_version ? "other" : null);
  const base = {
    t, u: r.user, ip: cleanIp(r.src_ip), lat, lon, cc: cc(r.country), m: r.method || null, mfa: mfaFlag, dev: r.device_id || null,
    cli: r.client || null, ver: r.client_version || null, prod, gw: r.gateway || null, f, ln,
    sk: r.session_id || normUser(r.user) + "|" + (r.device_id || "") + "|" + (cleanIp(r.src_ip) || ""),
    bin: numOrNull(r.bytes_in), bout: numOrNull(r.bytes_out), dur: numOrNull(r.duration_s),
  };
  if (/auth.*(fail|reject|deny)|login.*fail|^fail|failure/.test(ev) || (/^(auth|login|authentication)$/.test(ev) && /fail|deny|reject/.test(res))) return mkEv({ ...base, k: "auth", ok: false, bin: null, bout: null, dur: null });
  if (/auth.*success|login.*success|^success|^auth$|^login$/.test(ev)) return mkEv({ ...base, k: "auth", ok: true, bin: null, bout: null, dur: null });
  if (/disconnect|logout|logoff|session_end|tunnel-down|end/.test(ev)) return mkEv({ ...base, k: "disconnect" });
  if (/connect|session_start|tunnel-up|start/.test(ev)) return mkEv({ ...base, k: "connect", ok: true });
  if (!ev && res) { const ok = /fail|deny|reject/.test(res) ? false : /success|ok|allow/.test(res) ? true : null; if (ok !== null) return mkEv({ ...base, k: "auth", ok, bin: null, bout: null, dur: null }); }
  return null;
}

function rowGetter(cols) {
  return (row) => { const o = {}; for (const k of Object.keys(cols)) { const v = row[cols[k]]; o[k] = v == null ? "" : typeof v === "string" ? v.trim() : v; } return o; };
}

function* tabularRows(file) {
  if (file.container === "json") {
    const t = file.text.trim();
    let recs = null;
    if (t[0] === "[" || !/\n\s*\{/.test(t)) { try { recs = iterJson(t); } catch (_) { recs = null; } }
    if (recs) { let i = 0; for (const r of recs) { i++; if (r && typeof r === "object") yield [flatten(r), i]; } return; }
    for (const [l, ln] of iterLines(file.text)) {
      const s = l.trim(); if (!s) continue;
      let o; try { o = JSON.parse(s); } catch (_) { yield [null, ln]; continue; }
      if (o && typeof o === "object") yield [flatten(o), ln];
    }
    return;
  }
  let ln = 1;
  for (const r of iterCsv(file.text)) { ln++; yield [r, ln]; }
}

/**
 * Parse one classified log file into normalised events. Returns { events, notes, columns, lines }.
 * notes are skipped[] entries ({check, reason}) describing what could not be read.
 */
export function parseLogFile(file, fi, tc, progress) {
  const events = [], notes = [];
  let bad = 0, noTime = 0, total = 0;
  const push = (e) => { if (!e) return; if (e.t == null) { noTime++; return; } events.push(e); };
  const fmt = file.format;
  let columns = null;
  const prog = (i) => { if (progress && i % 5000 === 0) progress(i); };
  if (fmt === "fortigate" || fmt === "asa" || fmt === "gp-syslog" || fmt === "openvpn-log") {
    const fn = fmt === "fortigate" ? parseFortiLine : fmt === "asa" ? parseAsaLine : fmt === "gp-syslog" ? parseGpSyslogLine : makeOpenVpnParser();
    for (const [l, ln] of iterLines(file.text)) {
      total++; prog(total);
      if (!l.trim()) continue;
      let e = null;
      try { e = fn(l, fi, ln, tc); } catch (_) { bad++; }
      push(e);
    }
  } else if (fmt === "openvpn-status") {
    for (const e of parseOpenVpnStatus(file.text, fi, tc)) { total++; push(e); }
  } else if (fmt === "azure-p2s") {
    for (const [r, ln] of tabularRows(file)) { total++; prog(total); if (!r) { bad++; continue; } push(azureEvent(r, fi, ln, tc)); }
  } else if (fmt === "gp-csv" || fmt === "zpa" || fmt === "cloudflare" || fmt === "generic") {
    const spec = columnSpec(fmt);
    let get = null;
    const mapper = fmt === "gp-csv" ? gpEvent : fmt === "zpa" ? zpaEvent : fmt === "cloudflare" ? cfEvent : genericEvent;
    for (const [r, ln] of tabularRows(file)) {
      total++; prog(total);
      if (!r) { bad++; continue; }
      if (!get) {
        columns = resolveColumns(Object.keys(r), spec, file.columns);
        get = rowGetter(columns);
        const need = fmt === "generic" ? ["ts", "user"] : ["ts", "user"];
        const miss = need.filter((k) => !columns[k]);
        if (miss.length) { notes.push({ check: "parse", reason: file.name + ": no " + miss.join(" / ") + " column; map it in the files panel" }); break; }
      }
      let e = null;
      try { e = mapper(get(r), fi, ln, tc); } catch (_) { bad++; }
      push(e);
    }
  }
  if (noTime) notes.push({ check: "parse", reason: file.name + ": " + noTime + " event(s) without a readable timestamp were ignored" + (fmt === "asa" || fmt === "openvpn-log" || fmt === "gp-syslog" ? " (set the year for syslog lines without one)" : "") });
  if (bad) notes.push({ check: "parse", reason: file.name + ": " + bad + " malformed record(s) ignored" });
  return { events, notes, columns, lines: total };
}

// ---------------------------------------------------------------------------
// Roster
// ---------------------------------------------------------------------------
function parseRoster(file) {
  const people = [];
  const it = file.container === "json" ? tabularRows(file) : (function* () { let ln = 1; for (const r of iterCsv(file.text)) { ln++; yield [r, ln]; } })();
  let cols = null;
  for (const [r] of it) {
    if (!r) continue;
    if (!cols) cols = resolveColumns(Object.keys(r), COLUMNS.roster, file.columns);
    const g = rowGetter(cols)(r);
    const email = str(g.email).toLowerCase() || null;
    const username = normUser(g.username);
    if (!email && !username) continue;
    people.push({
      employeeId: g.employee_id || null, name: g.name || null, email, username, department: g.department || null, manager: g.manager_email || null,
      status: str(g.status).toLowerCase() || null, hire: parseDay(g.hire_date), term: parseDay(g.termination_date), termRaw: g.termination_date || null,
    });
  }
  return { people, columns: cols || {} };
}

function parseMapping(file) {
  const map = new Map();
  let cols = null;
  for (const [r] of tabularRows({ ...file, container: file.container === "json" ? "json" : "csv" })) {
    if (!r) continue;
    if (!cols) cols = resolveColumns(Object.keys(r), COLUMNS.mapping, file.columns);
    const u = normUser(r[cols.username]), e = str(r[cols.email]).trim().toLowerCase();
    if (u && e) map.set(u, e);
  }
  return map;
}

function parseServiceList(file) {
  const out = [];
  for (const [l, ln] of iterLines(file.text)) {
    const s = l.split(/[,;\t]/)[0].trim();
    if (!s || (ln === 1 && /^(service[_ ]?accounts?|account|name|username)$/i.test(s))) continue;
    out.push(s);
  }
  return out;
}

const INACTIVE_STATUS = /^(terminated|inactive|disabled|leaver|left|separated|offboarded|suspended|no|false|0|former|deactivated)$/;

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------
function buildSessions(events) {
  // events of one file, sorted by (t, ln)
  const sessions = [];
  const open = new Map();
  let orphanDown = 0;
  const startSession = (e) => ({
    uRaw: e.u, start: e.t, end: null, dur: null, ip: e.ip, dev: e.dev, cli: e.cli, ver: e.ver, prod: e.prod, bin: null, bout: null,
    gw: e.gw, pip: e.pip, lat: e.lat, lon: e.lon, cc: e.cc, mfa: e.mfa, f: e.f, startLine: e.ln, endLine: null, open: true, inferredStart: false, why: null,
  });
  const close = (s, e) => {
    s.end = e.t; s.endLine = e.ln; s.open = false;
    s.dur = e.dur != null ? e.dur : Math.max(0, (e.t - s.start) / 1000);
    if (e.bout != null) s.bout = e.bout;
    if (e.bin != null) s.bin = e.bin;
    if (e.why) s.why = e.why;
    if (!s.uRaw && e.u) s.uRaw = e.u;
  };
  for (const e of events) {
    if (!e.sk) continue;
    if (e.k === "connect") {
      const prev = open.get(e.sk);
      if (prev) {
        if (e.why === "svc") continue; // ASA SVC channel inside an already-open parent session
        sessions.push(prev); // previous never closed (missing disconnect)
      }
      const s = startSession(e);
      if (e.bout != null) s.bout = e.bout;
      if (e.bin != null) s.bin = e.bin;
      if (e.dur != null && e.dur > 0 && e.why !== "status") { close(s, { ...e, t: e.t + e.dur * 1000, ln: e.ln }); sessions.push(s); open.delete(e.sk); continue; }
      open.set(e.sk, s);
    } else if (e.k === "touch") {
      const s = open.get(e.sk);
      if (s) {
        if (e.pip && !s.pip) s.pip = e.pip;
        if (e.ver) { s.ver = e.ver; s.cli = e.cli || s.cli; s.prod = e.prod || s.prod; }
        if (e.why === "activity") s.last = e.t;
      } else if (e.why === "activity") {
        const n = startSession(e); n.last = e.t; open.set(e.sk, n);
      }
    } else if (e.k === "disconnect") {
      const s = open.get(e.sk);
      if (s) { close(s, e); sessions.push(s); open.delete(e.sk); }
      else if (e.dur != null && e.dur >= 0) {
        const n = startSession({ ...e, t: e.t - e.dur * 1000 });
        n.inferredStart = true; n.startLine = null; close(n, e); sessions.push(n);
      } else orphanDown++;
    }
  }
  for (const s of open.values()) {
    if (s.last != null && s.last > s.start) { s.end = s.last; s.dur = (s.last - s.start) / 1000; s.open = false; s.activitySpan = true; }
    sessions.push(s);
  }
  return { sessions, orphanDown };
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------
function median(a) {
  if (!a.length) return null;
  const s = a.slice().sort((x, y) => x - y), m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

/**
 * Robust z-score (Iglewicz & Hoaglin modified z): z = 0.6745 * (x - median) / MAD,
 * MAD = median(|x_i - median|). Returns null when MAD is 0.
 */
export function robustZ(x, values) {
  const med = median(values);
  if (med == null) return null;
  const mad = median(values.map((v) => Math.abs(v - med)));
  if (!mad) return null;
  return (0.6745 * (x - med)) / mad;
}

function net24(ip) {
  const p = ipToInt(ip);
  if (!p) return null;
  if (p.v === 4) return ip.split(".").slice(0, 3).join(".") + ".0/24";
  return ip.split(":").slice(0, 3).join(":") + "::/48";
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------
function normalizeDataset(dataset, opts) {
  if (typeof dataset === "string" || Array.isArray(dataset)) return parseInput(dataset, { parse: false, opts }).files;
  if (dataset && Array.isArray(dataset.files)) {
    return dataset.files.map((f) => {
      if (f.format && f.kind) return { container: "lines", headers: [], columns: {}, ...f, text: str(f.text) };
      const c = classifyText(f.name, f.text);
      return { name: str(f.name), text: str(f.text), ...c, columns: f.columns || {}, ...(f.format ? { format: f.format, kind: kindOf(f.format) } : {}) };
    }).sort((a, b) => cmp(a.name, b.name));
  }
  return [];
}

/**
 * Analyze the dataset ({ files: [{ name, text, format?, kind?, columns? }] }, an
 * array of { name, text }, or one string). opts overrides DEFAULTS.
 * ctx.progress(done, total, label) is called every ~5000 lines.
 */
export function analyze(dataset, opts = {}, ctx) {
  const o = { ...DEFAULTS, ...(opts || {}) };
  for (const k of Object.keys(DEFAULTS)) if (typeof DEFAULTS[k] === "number" && !Number.isFinite(Number(o[k]))) o[k] = DEFAULTS[k];
  const files = normalizeDataset(dataset, o);
  const skipped = [];
  const findings = [];
  const progress = ctx && typeof ctx.progress === "function" ? ctx.progress : null;

  const bizZone = makeZone(o.timeZone);
  if (!bizZone) skipped.push({ check: "settings", reason: "time zone '" + o.timeZone + "' not recognised; business hours read in UTC" });
  const zone = bizZone || makeZone("UTC");
  if (!makeZone(o.logTimeZone)) skipped.push({ check: "settings", reason: "log time zone '" + o.logTimeZone + "' not recognised; zone-less timestamps read as UTC" });
  const tc = timeContext(files, o);
  const internal = compileCidrs(o.internalCidrs && o.internalCidrs.length ? o.internalCidrs : INTERNAL_DEFAULT);
  const allow = compileCidrs((o.allowIps || []).map((s) => str(s).trim()).filter(Boolean).map((s) => (s.includes("/") ? s : s + (s.includes(":") ? "/128" : "/32"))));
  const isInternal = (ip) => !!ip && isInternalIp(ip, internal);
  const isAllowed = (ip) => !!ip && allow.length > 0 && isInternalIp(ip, allow);

  // ---- parse
  const totalChars = files.reduce((n, f) => n + f.text.length, 0) || 1;
  let doneChars = 0;
  const events = [];
  const roster = [];
  const mapping = new Map();
  const serviceList = (o.serviceAccounts || []).map((s) => str(s).trim()).filter(Boolean);
  const fileRows = [];
  let anyLog = false;
  files.forEach((file, fi) => {
    const linesTotal = Math.max(1, file.lines || countLines(file.text));
    const row = { file: file.name, format: file.format, label: FORMAT_LABEL[file.format] || file.format, kind: file.kind, confidence: file.confidence, events: 0, lines: 0 };
    if (file.kind === "log") {
      anyLog = true;
      const r = parseLogFile(file, fi, tc, (i) => progress && progress(Math.round(doneChars + (i / linesTotal) * file.text.length), totalChars, "Parsing " + file.name));
      for (const e of r.events) events.push(e);
      for (const n of r.notes) skipped.push(n);
      row.events = r.events.length; row.lines = r.lines;
    } else if (file.kind === "roster") {
      const r = parseRoster(file);
      for (const p of r.people) roster.push(p);
      row.events = r.people.length;
      if (!r.columns.termination_date) skipped.push({ check: "leaver_connecting", reason: file.name + ": roster has no termination date column (" + COLUMNS.roster.termination_date.slice(0, 3).join(", ") + "); only status is used" });
    } else if (file.kind === "mapping") {
      for (const [k, v] of parseMapping(file)) mapping.set(k, v);
      row.events = mapping.size;
    } else if (file.kind === "service") {
      const l = parseServiceList(file);
      for (const s of l) serviceList.push(s);
      row.events = l.length;
    }
    doneChars += file.text.length;
    progress && progress(doneChars, totalChars, "Parsed " + file.name);
    fileRows.push(row);
  });

  events.sort((a, b) => a.t - b.t || a.f - b.f || a.ln - b.ln);

  // ---- identities
  const byEmail = new Map(), byUser = new Map(), byLocal = new Map();
  for (const p of roster) {
    if (p.email) byEmail.set(p.email, p);
    if (p.username) byUser.set(p.username, p);
    if (p.email) { const l = p.email.split("@")[0]; byLocal.set(l, byLocal.has(l) && byLocal.get(l) !== p ? null : p); }
  }
  const svc = serviceList.map(globToRe).filter(Boolean);
  const isService = (...names) => names.some((n) => n && svc.some((g) => (g.exact ? g.exact === n : g.re.test(n))));
  const idCache = new Map();
  const serviceKeys = new Set();
  const keyIds = new Map();
  const resolve = (raw) => {
    const n = normUser(raw);
    if (!n) return null;
    if (idCache.has(n)) return idCache.get(n);
    let person = null, basis = null;
    const mapped = mapping.get(n) || (n.includes("@") ? mapping.get(n.split("@")[0]) : null);
    if (mapped && byEmail.has(mapped)) { person = byEmail.get(mapped); basis = "mapping"; }
    if (!person && byEmail.has(n)) { person = byEmail.get(n); basis = "email"; }
    if (!person && byUser.has(n)) { person = byUser.get(n); basis = "username"; }
    if (!person && n.includes("@")) { const l = n.split("@")[0]; if (byUser.has(l)) { person = byUser.get(l); basis = "username (email local part)"; } else if (byLocal.get(l)) { person = byLocal.get(l); basis = "email local part"; } }
    if (!person && byLocal.get(n)) { person = byLocal.get(n); basis = "email local part"; }
    const key = person ? person.email || person.username : mapped || n;
    const id = { key, raw: n, person, basis, service: isService(n, key, mapped) || serviceKeys.has(key) };
    if (id.service) serviceKeys.add(key);
    if (!keyIds.has(key)) keyIds.set(key, id); // first log spelling decides the reported match basis
    idCache.set(n, id);
    return id;
  };

  // attach identities
  let maskedFailures = 0;
  for (const e of events) {
    const id = resolve(e.u);
    e.id = id ? id.key : null;
    if (!id && e.k === "auth" && e.ok === false) maskedFailures++;
  }
  if (maskedFailures) skipped.push({ check: "brute_force_success", reason: maskedFailures + " failed authentication(s) carry no username (Cisco ASA masks them unless 'no logging hide username' is set); they count toward source-IP totals only" });

  // ---- sessions (per file)
  const byFile = new Map();
  for (const e of events) { if (!byFile.has(e.f)) byFile.set(e.f, []); byFile.get(e.f).push(e); }
  let sessions = [];
  let orphanDown = 0;
  for (const f of [...byFile.keys()].sort((a, b) => a - b)) {
    const r = buildSessions(byFile.get(f));
    for (const s of r.sessions) { const id = resolve(s.uRaw); s.id = id ? id.key : null; if (s.id) sessions.push(s); }
    orphanDown += r.orphanDown;
  }
  sessions.sort((a, b) => a.start - b.start || a.f - b.f || cmp(a.id, b.id) || (a.startLine || 0) - (b.startLine || 0));
  if (orphanDown) skipped.push({ check: "sessions", reason: orphanDown + " disconnect record(s) without a matching connect and without a duration could not form a session" });

  const firstTs = events.length ? events[0].t : null;
  const lastTs = events.length ? events[events.length - 1].t : null;
  const spanDays = firstTs != null ? (lastTs - firstTs) / DAY : 0;

  // ---- access points (successful auth or session start) per user
  const access = new Map(); // id -> [{t, ip, lat, lon, cc, dev, f, ln, src}]
  const seenAccess = new Set();
  const addAccess = (id, p) => {
    const k = id + "|" + p.t + "|" + (p.ip || "");
    if (seenAccess.has(k)) return;
    seenAccess.add(k);
    if (!access.has(id)) access.set(id, []);
    access.get(id).push(p);
  };
  for (const e of events) if (e.id && e.k === "auth" && e.ok === true) addAccess(e.id, { t: e.t, ip: e.ip, lat: e.lat, lon: e.lon, cc: e.cc, dev: e.dev, f: e.f, ln: e.ln, src: "auth", mfa: e.mfa, m: e.m });
  for (const s of sessions) addAccess(s.id, { t: s.start, ip: s.ip, lat: s.lat, lon: s.lon, cc: s.cc, dev: s.dev, f: s.f, ln: s.startLine, src: s.inferredStart ? "session (start inferred from duration)" : "session", mfa: s.mfa, m: null });
  for (const l of access.values()) l.sort((a, b) => a.t - b.t || a.f - b.f || (a.ln || 0) - (b.ln || 0));

  const fileName = (f) => (files[f] ? files[f].name : "");
  const evRow = (e) => clean({
    time: iso(e.t), user: e.id || normUser(e.u) || "(masked)", source_ip: e.ip, event: e.k === "auth" ? (e.ok ? "auth success" : e.ok === false ? "auth failure" : "auth") : e.k,
    method: e.m, mfa: e.mfa == null ? null : e.mfa ? "yes" : "no", country: e.cc, lat: e.lat, lon: e.lon, device: e.dev, client: e.cli, version: e.ver, reason: e.why, file: fileName(e.f), line: e.ln,
  });
  const apRow = (id, p) => clean({ time: iso(p.t), user: id, source_ip: p.ip, event: p.src, country: p.cc, lat: p.lat, lon: p.lon, device: p.dev, file: fileName(p.f), line: p.ln });
  const sesRow = (s) => clean({
    start: iso(s.start), end: s.open ? "(open)" : iso(s.end), hours: s.dur != null ? round(s.dur / 3600, 2) : null, user: s.id, source_ip: s.ip, device: s.dev, client: s.cli, version: s.ver,
    country: s.cc, lat: s.lat, lon: s.lon, bytes_out: s.bout, bytes_in: s.bin, gateway: s.gw, file: fileName(s.f), line: s.startLine || s.endLine,
  });

  const users = new Set();
  for (const e of events) if (e.id) users.add(e.id);
  const userList = [...users].sort();
  const flagsByUser = new Map();
  const flag = (u, label, sev) => { if (!flagsByUser.has(u)) flagsByUser.set(u, []); flagsByUser.get(u).push({ label, sev }); };

  const add = (f) => {
    const evidence = f.evidence || [];
    findings.push({ ...f, evidenceCount: f.evidenceCount != null ? f.evidenceCount : evidence.length, evidence: evidence.slice(0, EVIDENCE_CAP) });
  };
  const idAsset = (u) => { const id = resolve(u); return { type: "IDENTITY", name: u, data: id && id.person ? clean({ name: id.person.name, department: id.person.department, status: id.person.status }) : undefined }; };
  const ipAsset = (ip) => ({ type: "IP", name: ip });
  const tick = (label) => progress && progress(totalChars, totalChars, label);

  if (!anyLog || !events.length) skipped.push({ check: "all", reason: anyLog ? "no remote-access events were recognised in the log files" : "no remote-access log file loaded" });

  // =========================================================== leavers / roster
  const revocation = [];
  const lastSeen = (u) => { const a = access.get(u); return a && a.length ? a[a.length - 1] : null; };
  if (!roster.length) {
    skipped.push({ check: "leaver_connecting", reason: "no HR roster loaded (employee_id, email, username, status, termination_date)" });
    skipped.push({ check: "not_on_roster", reason: "no HR roster loaded" });
  } else if (events.length) {
    tick("Checking leavers");
    const people = new Map();
    for (const u of userList) { const id = resolve(u); if (id && id.person) people.set(u, id); }
    for (const u of userList) {
      const id = people.get(u);
      if (!id) continue;
      const p = id.person;
      const acc = access.get(u) || [];
      if (!acc.length) continue;
      const rehired = p.hire && p.term && Date.UTC(p.hire.y, p.hire.mo - 1, p.hire.d) > Date.UTC(p.term.y, p.term.mo - 1, p.term.d);
      if (p.term && !rehired) {
        const termEnd = localToUtc(p.term.y, p.term.mo, p.term.d + 1, 0, 0, 0, zone);
        const after = acc.filter((a) => a.t >= termEnd);
        if (after.length) {
          const days = Math.floor((after[0].t - termEnd) / DAY) + 1;
          const lastA = after[after.length - 1];
          const ips = [...new Set(after.map((a) => a.ip).filter(Boolean))].sort();
          add({
            id: "leaver:" + u, title: "Leaver still connecting: " + u, severity: "critical", confidence: "confirmed", category: "leaver",
            description: (p.name || u) + " was terminated on " + p.termRaw + " but authenticated or connected " + after.length + " time(s) afterwards, first " + days + " day(s) after termination (" + iso(after[0].t) + "), last " + iso(lastA.t) + " from " + (ips.join(", ") || "unknown IP") + ". Roster match by " + id.basis + ".",
            recommendation: "Disable the account in the VPN / IdP now, revoke certificates and tokens, kill active sessions, and review what the sessions accessed. Fix the offboarding hand-off so termination disables remote access the same day.",
            controls: [C.t1078, C.t1133, C.ac2_3, C.ac2_13, C.cis6_2, C.a6_5, C.a5_18, C.cc6_2],
            evidence: after.map((a) => apRow(u, a)), assets: [idAsset(u), ...ips.slice(0, 10).map(ipAsset)], tags: ["leaver"],
          });
          flag(u, "leaver", "critical");
          revocation.push({ user: u, name: p.name, email: p.email, reason: "terminated " + p.termRaw + ", still connecting", termination_date: p.termRaw, last_seen: iso(lastA.t), last_ip: lastA.ip, accesses_after: after.length });
          continue;
        }
      }
      if (p.status && INACTIVE_STATUS.test(p.status) && !p.term) {
        const lastA = acc[acc.length - 1];
        add({
          id: "inactive:" + u, title: "Inactive roster status but connecting: " + u, severity: "high", confidence: "likely", category: "leaver",
          description: (p.name || u) + " has HR status '" + p.status + "' with no termination date, and connected " + acc.length + " time(s) in the log (last " + iso(lastA.t) + "). Without a termination date the tool cannot tell whether these sessions came after the status change.",
          recommendation: "Confirm the employment status with HR; if the person has left, disable the account and review the sessions.",
          controls: [C.t1078, C.ac2_3, C.cis6_2, C.a6_5, C.cc6_2],
          evidence: acc.map((a) => apRow(u, a)), assets: [idAsset(u)], tags: ["leaver"],
        });
        flag(u, "inactive status", "high");
        revocation.push({ user: u, name: p.name, email: p.email, reason: "HR status " + p.status + ", still connecting", termination_date: "", last_seen: iso(lastA.t), last_ip: lastA.ip, accesses_after: acc.length });
      }
    }
    // not on roster
    const unknown = userList.filter((u) => !people.has(u) && !serviceKeys.has(u) && !(resolve(u) || {}).service);
    const unknownWithAccess = unknown.filter((u) => (access.get(u) || []).length);
    if (unknownWithAccess.length) {
      add({
        id: "notroster", title: unknownWithAccess.length + " remote-access account(s) not on the HR roster", severity: "medium", confidence: "review", category: "not_on_roster",
        description: "These accounts connected but match no roster email, username or mapping entry: " + unknownWithAccess.slice(0, 15).join(", ") + (unknownWithAccess.length > 15 ? " and " + (unknownWithAccess.length - 15) + " more" : "") + ". They may be contractors, shared or service accounts, or accounts that outlived their owner.",
        recommendation: "Assign an owner to each account, add service accounts to the service-account list, add a username-to-email mapping for naming mismatches, and disable accounts nobody owns.",
        controls: [C.t1078, C.ac2_3, C.cis5_3, C.a5_18, C.cc6_2],
        evidence: unknownWithAccess.map((u) => { const a = access.get(u); const l = a[a.length - 1]; return { user: u, accesses: a.length, first_seen: iso(a[0].t), last_seen: iso(l.t), last_ip: l.ip || "" }; }),
        assets: unknownWithAccess.slice(0, 25).map(idAsset), tags: ["roster"],
      });
      for (const u of unknownWithAccess) flag(u, "not on roster", "medium");
    }
  }

  // =========================================================== brute force -> success
  const authByUser = new Map();
  for (const e of events) {
    if (e.k !== "auth" || !e.id || e.ok === null || e.deny) continue;
    if (!authByUser.has(e.id)) authByUser.set(e.id, []);
    authByUser.get(e.id).push(e);
  }
  const anyFail = events.some((e) => e.k === "auth" && e.ok === false && !e.deny);
  let bfSuccesses = 0;
  if (!anyFail) skipped.push({ check: "brute_force_success", reason: "no failed authentications in the logs" });
  else {
    tick("Checking brute force");
    const win = o.bfWindowMin * MIN;
    for (const u of [...authByUser.keys()].sort()) {
      const list = authByUser.get(u);
      const fails = list.filter((e) => e.ok === false);
      if (fails.length < o.failThreshold) continue;
      // successes: auth ok events plus session starts
      const succ = (access.get(u) || []).map((p) => ({ t: p.t, p }));
      const hits = [];
      let lo = 0, hi = 0;
      for (const s of succ) {
        while (hi < fails.length && fails[hi].t <= s.t) hi++;
        while (lo < hi && fails[lo].t < s.t - win) lo++;
        if (hi - lo >= o.failThreshold) hits.push({ s, fails: fails.slice(lo, hi) });
      }
      if (!hits.length) continue;
      bfSuccesses++;
      const h = hits[0];
      const ips = [...new Set(h.fails.map((e) => e.ip).concat([h.s.p.ip]).filter(Boolean))].sort();
      add({
        id: "bf:" + u, title: "Brute force followed by a successful login: " + u, severity: "high", confidence: "likely", category: "brute_force",
        description: h.fails.length + " failed authentications for " + u + " within " + o.bfWindowMin + " minutes (threshold " + o.failThreshold + "), then a success at " + iso(h.s.t) + " from " + (ips.join(", ") || "unknown IP") + ". " + (hits.length > 1 ? hits.length + " successes met the pattern in total." : ""),
        recommendation: "Treat the account as compromised until proven otherwise: reset the password, revoke sessions, require MFA, and check the session's activity. Enforce lockout or throttling on the VPN portal.",
        controls: [C.t1110, C.t1078, C.t1133, C.ac7, C.cis6_4, C.a8_5, C.cc6_6],
        evidence: h.fails.map(evRow).concat([apRow(u, h.s.p)]), evidenceCount: h.fails.length + 1,
        assets: [idAsset(u), ...ips.slice(0, 10).map(ipAsset)], tags: ["brute-force"],
      });
      flag(u, "brute force success", "high");
    }
  }

  // =========================================================== password spraying
  const failsByIp = new Map();
  const succByIp = new Map();
  for (const e of events) {
    if (!e.ip) continue;
    if (e.k === "auth" && e.ok === false && !e.deny && e.id) { if (!failsByIp.has(e.ip)) failsByIp.set(e.ip, []); failsByIp.get(e.ip).push(e); }
  }
  for (const [u, l] of access) for (const p of l) if (p.ip) { if (!succByIp.has(p.ip)) succByIp.set(p.ip, []); succByIp.get(p.ip).push({ u, p }); }
  const sprayIps = [];
  if (anyFail) {
    tick("Checking password spraying");
    const win = o.sprayWindowMin * MIN;
    for (const ip of [...failsByIp.keys()].sort()) {
      if (isAllowed(ip)) continue;
      const l = failsByIp.get(ip);
      const counts = new Map();
      let lo = 0, best = 0, bestLo = 0, bestHi = 0;
      for (let hi = 0; hi < l.length; hi++) {
        counts.set(l[hi].id, (counts.get(l[hi].id) || 0) + 1);
        while (l[hi].t - l[lo].t > win) { const c = counts.get(l[lo].id) - 1; if (c) counts.set(l[lo].id, c); else counts.delete(l[lo].id); lo++; }
        if (counts.size > best) { best = counts.size; bestLo = lo; bestHi = hi; }
      }
      if (best < o.sprayUsers) continue;
      const wl = l.slice(bestLo, bestHi + 1);
      const targeted = [...new Set(wl.map((e) => e.id))].sort();
      const perUser = wl.length / targeted.length;
      const succ = (succByIp.get(ip) || []).filter((x) => x.p.t >= wl[0].t);
      const succUsers = [...new Set(succ.map((x) => x.u))].sort();
      sprayIps.push({ ip, users: targeted.length, failures: l.length, successes: succUsers.length, start: wl[0].t, end: wl[wl.length - 1].t, succUsers });
      const controls = [C.t1110, C.t1110_3, ...(perUser > 1.5 ? [C.t1110_4] : []), C.t1133, C.ac7, C.si4, C.a8_16, C.cc6_6];
      add({
        id: "spray:" + ip, title: "Password spraying from " + ip, severity: "high", confidence: "likely", category: "spraying",
        description: ip + (isInternal(ip) ? " (internal address)" : "") + " failed authentication for " + targeted.length + " distinct users within " + o.sprayWindowMin + " minutes (" + iso(wl[0].t) + " to " + iso(wl[wl.length - 1].t) + "; threshold " + o.sprayUsers + "), " + round(perUser, 1) + " attempt(s) per user. " + l.length + " failures from this source in total.",
        recommendation: "Block the source at the VPN edge, confirm none of the targeted accounts later logged in from it, enforce MFA and per-source throttling, and alert on many-users-one-source failures.",
        controls, evidence: wl.map(evRow), evidenceCount: wl.length, assets: [ipAsset(ip), ...targeted.slice(0, 15).map(idAsset)], tags: ["spraying"],
      });
      if (succUsers.length) {
        const targetedHit = succUsers.filter((u) => targeted.includes(u));
        add({
          id: "spraysucc:" + ip, title: "Successful login from a password-spraying source " + ip, severity: "critical", confidence: targetedHit.length ? "confirmed" : "likely", category: "spraying",
          description: "After spraying from " + ip + " began, " + succUsers.join(", ") + " authenticated successfully from the same address" + (targetedHit.length ? " (" + targetedHit.length + " of them were among the sprayed accounts)" : "") + ".",
          recommendation: "Assume these accounts are compromised: disable or reset them, revoke sessions and tokens, and investigate what the sessions reached.",
          controls: [C.t1110_3, C.t1078, C.t1133, C.ac2_12, C.ia2_2, C.cis6_4, C.a8_5, C.cc6_6],
          evidence: succ.map((x) => apRow(x.u, x.p)), assets: [ipAsset(ip), ...succUsers.map(idAsset)], tags: ["spraying"],
        });
        for (const u of succUsers) flag(u, "login from spraying IP", "critical");
      }
    }
  }

  // =========================================================== impossible travel / concurrency
  const anyCoord = events.some((e) => e.lat != null) || sessions.some((s) => s.lat != null);
  const anyCountry = events.some((e) => e.cc) || sessions.some((s) => s.cc);
  let travelUsers = 0;
  if (!anyCoord) {
    skipped.push({ check: "impossible_travel", reason: anyCountry ? "the logs carry a country but no latitude/longitude; impossible travel needs coordinates from the log, so the new-country check is used instead" : "the logs carry no latitude/longitude (no IP geolocation is performed)" });
    skipped.push({ check: "concurrent_distant_sessions", reason: "no latitude/longitude in the logs" });
  } else {
    tick("Checking impossible travel");
    for (const u of [...access.keys()].sort()) {
      const pts = access.get(u).filter((p) => p.lat != null && !isInternal(p.ip));
      const hits = [];
      for (let i = 1; i < pts.length; i++) {
        const a = pts[i - 1], b = pts[i];
        const km = haversineKm(a.lat, a.lon, b.lat, b.lon);
        if (km < o.minTravelKm) continue;
        const hrs = (b.t - a.t) / HOUR;
        const kmh = hrs > 0 ? km / hrs : Infinity;
        if (kmh > o.maxKmh) hits.push({ a, b, km, hrs, kmh });
      }
      if (!hits.length) continue;
      travelUsers++;
      const h = hits[0];
      add({
        id: "travel:" + u, title: "Impossible travel: " + u, severity: "high", confidence: "likely", category: "impossible_travel",
        description: u + " moved " + Math.round(h.km) + " km in " + round(h.hrs * 60, 0) + " minutes (" + (Number.isFinite(h.kmh) ? Math.round(h.kmh) + " km/h" : "simultaneous") + ", threshold " + o.maxKmh + " km/h) between " + (h.a.ip || "?") + (h.a.cc ? " (" + h.a.cc + ")" : "") + " at " + iso(h.a.t) + " and " + (h.b.ip || "?") + (h.b.cc ? " (" + h.b.cc + ")" : "") + " at " + iso(h.b.t) + ". Coordinates are the ones in the log. " + (hits.length > 1 ? hits.length + " impossible hops in total." : ""),
        recommendation: "Confirm with the user whether either location was a VPN egress or a travel day; if not, reset credentials, revoke sessions and review activity from the unexpected location.",
        controls: [C.t1078, C.t1133, C.ac2_12, C.si4, C.a8_16, C.cc7_2],
        evidence: hits.flatMap((x) => [apRow(u, x.a), { ...apRow(u, x.b), km: Math.round(x.km), kmh: Number.isFinite(x.kmh) ? Math.round(x.kmh) : "simultaneous" }]),
        assets: [idAsset(u), ...[...new Set(hits.flatMap((x) => [x.a.ip, x.b.ip]).filter(Boolean))].sort().slice(0, 10).map(ipAsset)], tags: ["travel"],
      });
      flag(u, "impossible travel", "high");
    }
    // concurrent distant sessions
    const byU = new Map();
    for (const s of sessions) if (s.lat != null && !s.open && s.end != null && !isInternal(s.ip)) { if (!byU.has(s.id)) byU.set(s.id, []); byU.get(s.id).push(s); }
    for (const u of [...byU.keys()].sort()) {
      const l = byU.get(u);
      const pairs = [];
      for (let i = 0; i < l.length; i++) for (let j = i + 1; j < l.length && l[j].start < l[i].end; j++) {
        if (l[i].ip === l[j].ip) continue;
        const km = haversineKm(l[i].lat, l[i].lon, l[j].lat, l[j].lon);
        if (km >= o.concurrentMinKm) pairs.push({ a: l[i], b: l[j], km });
      }
      if (!pairs.length) continue;
      const p = pairs[0];
      add({
        id: "concurrent:" + u, title: "Concurrent sessions far apart: " + u, severity: "high", confidence: "likely", category: "impossible_travel",
        description: u + " had overlapping sessions from " + p.a.ip + " and " + p.b.ip + ", " + Math.round(p.km) + " km apart (threshold " + o.concurrentMinKm + " km), starting " + iso(p.a.start) + " and " + iso(p.b.start) + ". " + pairs.length + " overlapping pair(s).",
        recommendation: "Two places at once usually means shared or stolen credentials. Terminate both sessions, reset the credentials and limit concurrent sessions per user.",
        controls: [C.t1078, C.ac2_12, C.ac17, C.si4, C.a8_16],
        evidence: pairs.flatMap((x) => [sesRow(x.a), { ...sesRow(x.b), km: Math.round(x.km) }]), assets: [idAsset(u), ipAsset(p.a.ip), ipAsset(p.b.ip)], tags: ["concurrent"],
      });
      flag(u, "concurrent distant sessions", "high");
    }
  }

  // =========================================================== baseline: new country / network / off-hours
  const baselineEnd = firstTs != null ? firstTs + o.baselineDays * DAY : null;
  const afterBaseline = baselineEnd != null && lastTs > baselineEnd;
  if (!afterBaseline) {
    const why = "the log covers " + round(spanDays, 1) + " day(s), not more than the " + o.baselineDays + "-day baseline";
    skipped.push({ check: "new_country", reason: why });
    skipped.push({ check: "off_hours", reason: why });
  } else {
    tick("Comparing against baselines");
    if (!anyCountry && !anyCoord) skipped.push({ check: "new_country", reason: "the logs carry no country" });
    for (const u of [...access.keys()].sort()) {
      const l = access.get(u);
      const base = l.filter((p) => p.t < baselineEnd), after = l.filter((p) => p.t >= baselineEnd);
      if (base.length < o.minBaselineEvents || !after.length) continue;
      if (anyCountry) {
        const known = new Set(base.map((p) => p.cc).filter(Boolean));
        if (known.size) {
          const fresh = after.filter((p) => p.cc && !known.has(p.cc));
          if (fresh.length) {
            const ccs = [...new Set(fresh.map((p) => p.cc))].sort();
            add({
              id: "newcountry:" + u, title: "New country for " + u + ": " + ccs.join(", "), severity: "medium", confidence: "review", category: "new_country",
              description: u + " connected from " + ccs.join(", ") + " after the baseline; during the first " + o.baselineDays + " days of the log (" + base.length + " accesses) only " + [...known].sort().join(", ") + " appeared. First new-country access " + iso(fresh[0].t) + ".",
              recommendation: "Confirm the travel with the user or their manager; if unexpected, reset credentials and review the sessions.",
              controls: [C.t1078, C.t1133, C.ac2_12, C.a8_16, C.cc7_2],
              evidence: fresh.map((p) => apRow(u, p)), assets: [idAsset(u), ...[...new Set(fresh.map((p) => p.ip).filter(Boolean))].sort().slice(0, 10).map(ipAsset)], tags: ["geo"],
            });
            flag(u, "new country", "medium");
          }
        }
      }
      const knownNets = new Set(base.map((p) => net24(p.ip)).filter(Boolean));
      const freshNets = after.filter((p) => p.ip && !isInternal(p.ip) && !isAllowed(p.ip) && knownNets.size && !knownNets.has(net24(p.ip)));
      if (freshNets.length) {
        const nets = [...new Set(freshNets.map((p) => net24(p.ip)))].sort();
        add({
          id: "newnet:" + u, title: "New source network for " + u, severity: "low", confidence: "review", category: "new_source",
          description: u + " connected from " + nets.length + " network(s) (" + nets.slice(0, 5).join(", ") + (nets.length > 5 ? ", ..." : "") + ") not seen in the " + o.baselineDays + "-day baseline (" + knownNets.size + " known /24 or /48 networks). Home ISPs rotate addresses, so this is context for other findings rather than an alert on its own.",
          recommendation: "Review together with any other finding for this user; no action needed if the user simply changed location or provider.",
          controls: [C.ac2_12, C.si4, C.a8_16],
          evidence: freshNets.map((p) => apRow(u, p)), assets: [idAsset(u)], tags: ["geo"],
        });
        flag(u, "new network", "low");
      }
      // off-hours
      const isOff = (t) => { const p = zoneParts(t, zone); return (o.weekendOffHours && (p.dow === 0 || p.dow === 6)) || p.h < o.businessStart || p.h >= o.businessEnd; };
      if (base.every((p) => !isOff(p.t))) {
        const off = after.filter((p) => isOff(p.t));
        if (off.length) {
          add({
            id: "offhours:" + u, title: "Off-hours remote access by " + u, severity: "low", confidence: "review", category: "off_hours",
            description: u + " connected " + off.length + " time(s) outside business hours (" + o.businessStart + ":00-" + o.businessEnd + ":00" + (o.weekendOffHours ? ", weekdays" : "") + ", " + zone.name + ") after a baseline of " + base.length + " accesses that were all within business hours. First " + iso(off[0].t) + ".",
            recommendation: "Confirm the work pattern with the user's manager; unexpected off-hours access combined with other findings warrants a credential reset.",
            controls: [C.ac2_12, C.ac17, C.si4, C.a8_16],
            evidence: off.map((p) => apRow(u, p)), assets: [idAsset(u)], tags: ["off-hours"],
          });
          flag(u, "off-hours", "low");
        }
      }
    }
  }

  // =========================================================== threat feed
  const feed = Array.isArray(o.feedIps) ? new Set(o.feedIps.map((x) => str(typeof x === "object" && x ? x.ip : x).trim()).filter(Boolean)) : null;
  const feedHits = [];
  if (!feed || !feed.size) skipped.push({ check: "threat_feed", reason: "malicious-IP feed not loaded" });
  else {
    const ipStats = new Map();
    for (const e of events) {
      if (!e.ip || !feed.has(e.ip) || isAllowed(e.ip)) continue;
      if (!ipStats.has(e.ip)) ipStats.set(e.ip, { ok: [], fail: [] });
      const s = ipStats.get(e.ip);
      if ((e.k === "auth" && e.ok === true) || e.k === "connect") s.ok.push(e); else if (e.k === "auth" && e.ok === false) s.fail.push(e);
    }
    for (const ip of [...ipStats.keys()].sort()) {
      const s = ipStats.get(ip);
      if (!s.ok.length && !s.fail.length) continue;
      const usersHit = [...new Set(s.ok.concat(s.fail).map((e) => e.id).filter(Boolean))].sort();
      const success = s.ok.length > 0;
      feedHits.push({ ip, success });
      add({
        id: "feed:" + ip, title: (success ? "Successful remote access" : "Failed remote-access attempts") + " from a listed malicious IP " + ip, severity: success ? "high" : "medium", confidence: "likely", category: "threat_feed",
        description: ip + " is on the malicious-IP feed (" + (o.feedUpdated ? "updated " + o.feedUpdated : "date unknown") + "). " + s.ok.length + " success(es) and " + s.fail.length + " failure(s) from it, users: " + (usersHit.join(", ") || "(masked)") + ".",
        recommendation: success ? "Review the successful sessions as possible compromise, reset the affected credentials and block the address at the VPN edge." : "Block the address at the VPN edge and watch the targeted accounts.",
        controls: [C.t1133, ...(success ? [C.t1078] : [C.t1110]), C.si4, C.a8_16, C.cc6_6],
        evidence: s.ok.concat(s.fail).map(evRow), assets: [ipAsset(ip), ...usersHit.slice(0, 10).map(idAsset)], tags: ["threat-feed"],
      });
      if (success) for (const u of usersHit) flag(u, "malicious source", "high");
    }
  }

  // =========================================================== MFA
  const mfaKnown = [...access.values()].some((l) => l.some((p) => p.mfa != null)) || events.some((e) => e.mfa != null);
  const noMfaUsers = [];
  if (!mfaKnown) skipped.push({ check: "no_mfa", reason: "the logs state no authentication method or MFA flag (FortiGate, ASA and Cloudflare logs do not); check the VPN / IdP configuration instead" });
  else {
    for (const u of [...access.keys()].sort()) {
      if (serviceKeys.has(u) || (resolve(u) || {}).service) continue;
      // Count authentications when the log states MFA on them, else sessions (avoids counting one login twice).
      const authPts = (access.get(u) || []).filter((p) => p.src === "auth" && p.mfa != null);
      const basePts = authPts.length ? authPts : (access.get(u) || []).filter((p) => p.src !== "auth");
      const pts = basePts.filter((p) => p.mfa === false);
      if (!pts.length) continue;
      const total = basePts.length;
      const methods = [...new Set(pts.map((p) => p.m).filter(Boolean))].sort();
      noMfaUsers.push(u);
      add({
        id: "nomfa:" + u, title: "Remote access without MFA: " + u, severity: "high", confidence: methods.length ? "likely" : "confirmed", category: "no_mfa",
        description: u + " connected " + pts.length + " of " + total + " time(s) without multi-factor authentication" + (methods.length ? " (method: " + methods.join(", ") + ")" : " (MFA flag 'no' in the log") + ").",
        recommendation: "Require phishing-resistant MFA for every remote-access connection (certificate plus MFA, or SAML to an IdP that enforces MFA) and remove password-only authentication profiles.",
        controls: [C.cis6_4, C.ia2_1, C.ia2_2, C.ac17, C.sp80046, C.a8_5, C.a6_7, C.cc6_1],
        evidence: pts.map((p) => ({ ...apRow(u, p), method: p.m || "", mfa: "no" })), assets: [idAsset(u)], tags: ["mfa"],
      });
      flag(u, "no MFA", "high");
    }
  }

  // =========================================================== legacy clients
  const mins = {};
  for (const [k, v] of Object.entries(o.minClientVersions || {})) if (str(v).trim() && /\d/.test(str(v))) mins[k] = str(v).trim();
  const verSeen = sessions.some((s) => s.ver) || events.some((e) => e.ver);
  if (!Object.keys(mins).length) skipped.push({ check: "legacy_client", reason: "no minimum client version entered (Settings, per product)" });
  else if (!verSeen) skipped.push({ check: "legacy_client", reason: "the logs carry no client version" });
  else {
    const old = new Map();
    const consider = (u, prod, ver, row) => {
      const min = mins[prod || "other"];
      if (!u || !ver || !min || cmpVersion(ver, min) >= 0) return;
      if (!old.has(u)) old.set(u, []);
      old.get(u).push({ ...row, product: PRODUCT_LABEL[prod || "other"], version: ver, minimum: min });
    };
    for (const s of sessions) consider(s.id, s.prod, s.ver, sesRow(s));
    for (const e of events) if (e.k === "auth" && e.ok && e.ver) consider(e.id, e.prod, e.ver, evRow(e));
    for (const u of [...old.keys()].sort()) {
      const rows = old.get(u);
      const vers = [...new Set(rows.map((r) => r.product + " " + r.version))].sort();
      add({
        id: "legacy:" + u, title: "Outdated VPN client: " + u, severity: "medium", confidence: "confirmed", category: "legacy_client",
        description: u + " connected with " + vers.join(", ") + ", older than the minimum you set (" + [...new Set(rows.map((r) => r.product + " " + r.minimum))].join(", ") + ").",
        recommendation: "Upgrade the client and enforce a minimum client version on the gateway (HIP / posture check, AnyConnect auto-update, FortiClient EMS compliance).",
        controls: [C.cis2_2, C.sa22, C.ac17, C.sp80046, C.a6_7],
        evidence: rows, assets: [idAsset(u)], tags: ["client"],
      });
      flag(u, "outdated client", "medium");
    }
  }

  // =========================================================== shared accounts
  const anyDev = sessions.some((s) => s.dev);
  if (!anyDev) skipped.push({ check: "shared_account_devices", reason: "the logs carry no device / host id" });
  const sharedUsers = [];
  {
    tick("Checking shared accounts");
    const win = o.sharedWindowMin * MIN;
    const sesByUserAll = new Map();
    for (const x of sessions) { if (!sesByUserAll.has(x.id)) sesByUserAll.set(x.id, []); sesByUserAll.get(x.id).push(x); }
    for (const u of [...access.keys()].sort()) {
      if (serviceKeys.has(u) || (resolve(u) || {}).service) continue;
      let devHit = null;
      if (anyDev) {
        // Sweep sessions by start; keep those still connected; count distinct devices among them.
        let active = [];
        for (const x of sesByUserAll.get(u) || []) {
          if (!x.dev || x.open || x.end == null) continue;
          active = active.filter((y) => y.end > x.start);
          active.push(x);
          const devs = new Set(active.map((y) => y.dev));
          if (devs.size >= o.sharedDevices) { devHit = { sessions: active.slice(), devs: [...devs].sort(), at: x.start }; break; }
        }
      }
      let ipHit = null;
      const pts = (access.get(u) || []).filter((p) => p.ip && !isInternal(p.ip) && !isAllowed(p.ip));
      const ipCount = new Map();
      for (let lo = 0, hi = 0; hi < pts.length; hi++) {
        ipCount.set(pts[hi].ip, (ipCount.get(pts[hi].ip) || 0) + 1);
        while (pts[hi].t - pts[lo].t > win) { const c = ipCount.get(pts[lo].ip) - 1; if (c) ipCount.set(pts[lo].ip, c); else ipCount.delete(pts[lo].ip); lo++; }
        if (ipCount.size >= o.sharedIps) { ipHit = { pts: pts.slice(lo, hi + 1), ips: [...ipCount.keys()].sort() }; break; }
      }
      if (!devHit && !ipHit) continue;
      sharedUsers.push(u);
      const desc = [];
      if (devHit) desc.push(devHit.devs.length + " different devices (" + devHit.devs.join(", ") + ") were connected at the same time at " + iso(devHit.at) + " (threshold " + o.sharedDevices + ")");
      if (ipHit) desc.push(ipHit.ips.length + " different public source IPs within " + o.sharedWindowMin + " minutes (threshold " + o.sharedIps + ")");
      const l = lastSeen(u);
      add({
        id: "shared:" + u, title: "Possible shared account: " + u, severity: "medium", confidence: devHit ? "likely" : "review", category: "shared_account",
        description: u + ": " + desc.join("; ") + ".",
        recommendation: "Give each person their own account, disable the shared credential and limit concurrent sessions per user on the gateway.",
        controls: [C.t1078, C.ac2_9, C.ac17, C.a5_18, C.cc6_1],
        evidence: devHit ? devHit.sessions.map(sesRow) : ipHit.pts.map((p) => apRow(u, p)), assets: [idAsset(u)], tags: ["shared"],
      });
      flag(u, "shared account", "medium");
      if (!revocation.some((r) => r.user === u)) {
        const id = resolve(u) || {};
        revocation.push({ user: u, name: id.person ? id.person.name : "", email: id.person ? id.person.email : "", reason: "possible shared account", termination_date: id.person ? id.person.termRaw || "" : "", last_seen: l ? iso(l.t) : "", last_ip: l ? l.ip : "", accesses_after: "" });
      }
    }
  }

  // =========================================================== long sessions
  {
    const lim = o.maxSessionHours * 3600;
    const byU = new Map();
    const laterStart = new Map(); // user|file -> latest session start
    for (const s of sessions) { const k = s.id + "|" + s.f; if (!laterStart.has(k) || laterStart.get(k) < s.start) laterStart.set(k, s.start); }
    for (const s of sessions) {
      // An open session followed by a later session of the same user in the same log lost its disconnect record; do not measure it.
      if (s.open && laterStart.get(s.id + "|" + s.f) > s.start) continue;
      const dur = s.open ? (lastTs - s.start) / 1000 : s.dur;
      if (dur == null || dur <= lim) continue;
      if (!byU.has(s.id)) byU.set(s.id, []);
      byU.get(s.id).push({ s, dur });
    }
    for (const u of [...byU.keys()].sort()) {
      const l = byU.get(u);
      const closed = l.filter((x) => !x.s.open), openL = l.filter((x) => x.s.open);
      const longest = l.reduce((a, b) => (b.dur > a.dur ? b : a));
      add({
        id: "long:" + u, title: "Long remote-access session: " + u, severity: closed.length ? "medium" : "low", confidence: closed.length ? "confirmed" : "review", category: "long_session",
        description: u + " had " + l.length + " session(s) longer than " + o.maxSessionHours + " hours; the longest lasted " + round(longest.dur / 3600, 1) + " hours from " + iso(longest.s.start) + "." + (openL.length ? " " + openL.length + " had no disconnect in the log (duration measured to the end of the log)." : ""),
        recommendation: "Enforce a session lifetime and idle timeout on the gateway and require re-authentication; confirm the long session was attended.",
        controls: [C.ac12, C.ac17, C.sp80046, C.a6_7],
        evidence: l.map((x) => ({ ...sesRow(x.s), hours: round(x.dur / 3600, 2) })), assets: [idAsset(u)], tags: ["session"],
      });
      flag(u, "long session", closed.length ? "medium" : "low");
    }
  }

  // =========================================================== dormant reactivated
  if (spanDays <= o.dormantDays) skipped.push({ check: "dormant_reactivated", reason: "the log covers " + round(spanDays, 1) + " day(s), not more than the " + o.dormantDays + "-day dormancy threshold" });
  else {
    for (const u of [...access.keys()].sort()) {
      const l = access.get(u);
      for (let i = 1; i < l.length; i++) {
        const gap = (l[i].t - l[i - 1].t) / DAY;
        if (gap <= o.dormantDays) continue;
        add({
          id: "dormant:" + u, title: "Dormant account reactivated: " + u, severity: "medium", confidence: "likely", category: "dormant",
          description: u + " had no remote access for " + Math.floor(gap) + " days (" + iso(l[i - 1].t) + " to " + iso(l[i].t) + "; threshold " + o.dormantDays + ") and then connected from " + (l[i].ip || "unknown IP") + ".",
          recommendation: "Disable remote access after the dormancy period automatically and require re-enrolment; confirm this reactivation with the account owner.",
          controls: [C.cis5_3, C.ac2_3, C.t1078, C.a5_18],
          evidence: [apRow(u, l[i - 1]), apRow(u, l[i])], assets: [idAsset(u)], tags: ["dormant"],
        });
        flag(u, "dormant reactivated", "medium");
        break;
      }
    }
  }

  // =========================================================== large transfers
  const anyBytes = sessions.some((s) => s.bout != null);
  if (!anyBytes) skipped.push({ check: "large_transfer", reason: "the logs carry no per-session byte counts" });
  else {
    const absLim = o.bytesOutGb * GB;
    const byU = new Map();
    for (const s of sessions) if (s.bout != null) { if (!byU.has(s.id)) byU.set(s.id, []); byU.get(s.id).push(s); }
    let lowSample = 0;
    for (const u of [...byU.keys()].sort()) {
      const l = byU.get(u);
      const vals = l.map((s) => s.bout);
      const canZ = l.length >= o.minBytesSamples;
      if (!canZ) lowSample++;
      // Modified z-score (Iglewicz & Hoaglin): z = 0.6745 * (x - median) / MAD over this user's sessions.
      const med = median(vals);
      const mad = canZ ? median(vals.map((v) => Math.abs(v - med))) : 0;
      const hits = [];
      for (const s of l) {
        const z = canZ && mad ? (0.6745 * (s.bout - med)) / mad : null;
        if (s.bout > absLim || (z != null && z > o.bytesZ && s.bout >= o.minZGb * GB)) hits.push({ s, z });
      }
      if (!hits.length) continue;
      const top = hits.reduce((a, b) => (b.s.bout > a.s.bout ? b : a));
      add({
        id: "bytes:" + u, title: "Large transfer to remote user: " + u, severity: "medium", confidence: "review", category: "large_transfer",
        description: u + " received " + round(top.s.bout / GB, 2) + " GB in one session starting " + iso(top.s.start) + " (absolute threshold " + o.bytesOutGb + " GB" + (canZ ? "; robust z " + (top.z == null ? "n/a (no spread)" : round(top.z, 1)) + " vs this user's " + l.length + " sessions, median " + round(med / GB, 3) + " GB, threshold " + o.bytesZ : "; z-score not used: " + l.length + " session(s) with byte counts, minimum " + o.minBytesSamples) + "). " + hits.length + " session(s) flagged.",
        recommendation: "Check what was transferred (proxy, DLP and file-server logs for the session window) and whether it fits the user's role; consider DLP controls on remote sessions.",
        controls: [C.a8_12, C.si4, C.ac17, C.a8_16],
        evidence: hits.map((h) => ({ ...sesRow(h.s), gb_out: round(h.s.bout / GB, 3), robust_z: h.z == null ? "" : round(h.z, 2) })), assets: [idAsset(u)], tags: ["exfiltration"],
      });
      flag(u, "large transfer", "medium");
    }
    if (lowSample) skipped.push({ check: "large_transfer_z", reason: lowSample + " user(s) have fewer than " + o.minBytesSamples + " sessions with byte counts; only the absolute " + o.bytesOutGb + " GB threshold applies to them" });
  }

  // ---- sort findings deterministically
  findings.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || cmp(a.category, b.category) || cmp(a.id || a.title, b.id || b.title));

  // ---- tables
  const failByUser = new Map(), succByUser = new Map();
  for (const e of events) {
    if (!e.id || e.k !== "auth") continue;
    if (e.ok === false) failByUser.set(e.id, (failByUser.get(e.id) || 0) + 1);
    else if (e.ok === true) succByUser.set(e.id, (succByUser.get(e.id) || 0) + 1);
  }
  const sesByUser = new Map();
  for (const s of sessions) { if (!sesByUser.has(s.id)) sesByUser.set(s.id, []); sesByUser.get(s.id).push(s); }
  const userRows = userList.map((u) => {
    const id = keyIds.get(u) || resolve(u) || {};
    const ss = sesByUser.get(u) || [];
    const acc = access.get(u) || [];
    const fl = flagsByUser.get(u) || [];
    const p = id.person;
    return {
      user: u, name: p ? p.name : null, department: p ? p.department : null, rosterStatus: p ? p.status || "listed" : id.service ? "service account" : roster.length ? "not on roster" : "no roster",
      termination: p ? p.termRaw : null, matchBasis: id.basis || null, sessions: ss.length, hours: round(ss.reduce((n, s) => n + (s.dur || 0), 0) / 3600, 1),
      countries: [...new Set(acc.map((a) => a.cc).filter(Boolean))].sort(), devices: new Set(ss.map((s) => s.dev).filter(Boolean)).size, ips: new Set(acc.map((a) => a.ip).filter(Boolean)).size,
      successes: (succByUser.get(u) || 0), failures: failByUser.get(u) || 0, firstSeen: acc.length ? iso(acc[0].t) : null, lastSeen: acc.length ? iso(acc[acc.length - 1].t) : null,
      lastIp: acc.length ? acc[acc.length - 1].ip : null, flags: [...new Set(fl.map((x) => x.label))].sort(), risk: Math.min(100, fl.reduce((n, x) => n + SEV_WEIGHT[x.sev], 0)),
    };
  }).sort((a, b) => b.risk - a.risk || cmp(a.user, b.user));

  const src = new Map();
  for (const e of events) {
    if (!e.ip) continue;
    if (!src.has(e.ip)) src.set(e.ip, { ip: e.ip, users: new Set(), successes: 0, failures: 0, countries: new Set(), first: e.t, last: e.t });
    const s = src.get(e.ip);
    if (e.id) s.users.add(e.id);
    if ((e.k === "auth" && e.ok === true) || e.k === "connect") s.successes++;
    else if (e.k === "auth" && e.ok === false) s.failures++;
    if (e.cc) s.countries.add(e.cc);
    s.last = e.t;
  }
  const sprayed = new Set(sprayIps.map((x) => x.ip));
  const sourceRows = [...src.values()].map((s) => ({
    ip: s.ip, users: s.users.size, successes: s.successes, failures: s.failures, countries: [...s.countries].sort(), internal: isInternal(s.ip), allowListed: isAllowed(s.ip),
    feed: !!(feed && feed.has(s.ip)), spraying: sprayed.has(s.ip), firstSeen: iso(s.first), lastSeen: iso(s.last),
  })).sort((a, b) => b.failures - a.failures || b.successes - a.successes || cmp(a.ip, b.ip));

  const ctry = new Map();
  for (const e of events) {
    if (!e.cc) continue;
    if (!ctry.has(e.cc)) ctry.set(e.cc, { country: e.cc, users: new Set(), ips: new Set(), successes: 0, failures: 0, sessions: 0 });
    const c = ctry.get(e.cc);
    if (e.id) c.users.add(e.id);
    if (e.ip) c.ips.add(e.ip);
    if ((e.k === "auth" && e.ok === true) || e.k === "connect") c.successes++; else if (e.k === "auth" && e.ok === false) c.failures++;
  }
  for (const s of sessions) if (s.cc && ctry.has(s.cc)) ctry.get(s.cc).sessions++;
  const countryRows = [...ctry.values()].map((c) => ({ country: c.country, users: c.users.size, sessions: c.sessions, successes: c.successes, failures: c.failures, ips: c.ips.size })).sort((a, b) => b.users - a.users || cmp(a.country, b.country));

  const maxRows = Math.max(100, Number(o.maxSessionRows) || DEFAULTS.maxSessionRows);
  const sessionRows = sessions.slice(0, maxRows).map((s) => clean({
    user: s.id, start: iso(s.start), end: s.open ? null : iso(s.end), hours: s.dur != null ? round(s.dur / 3600, 2) : s.open && lastTs != null ? round((lastTs - s.start) / HOUR, 2) : null, open: s.open,
    inferredStart: s.inferredStart || undefined, ip: s.ip, device: s.dev, client: s.cli, version: s.ver, country: s.cc, lat: s.lat, lon: s.lon, bytesOut: s.bout, bytesIn: s.bin, gateway: s.gw, file: fileName(s.f), line: s.startLine || s.endLine,
  }));

  revocation.sort((a, b) => cmp(a.user, b.user));
  const blocklist = [];
  for (const s of sprayIps) blocklist.push({ ip: s.ip, reason: "password spraying: " + s.users + " users failed between " + iso(s.start) + " and " + iso(s.end) + (s.successes ? "; " + s.successes + " later succeeded" : "") });
  for (const h of feedHits) if (!blocklist.some((b) => b.ip === h.ip)) blocklist.push({ ip: h.ip, reason: "malicious-IP feed" + (o.feedUpdated ? " (" + o.feedUpdated + ")" : "") + (h.success ? "; successful access" : "; failed attempts") });
  blocklist.sort((a, b) => cmp(a.ip, b.ip));

  const bySeverity = {};
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  const leaversConnecting = findings.filter((f) => f.id && f.id.startsWith("leaver:")).length;
  const summary = {
    files: files.length, events: events.length, sessions: sessions.length, users: userList.length, sources: src.size, countries: ctry.size,
    leaversConnecting, bruteForceSuccesses: bfSuccesses, sprayIps: sprayIps.length, impossibleTravel: travelUsers, noMfaUsers: noMfaUsers.length, sharedAccounts: sharedUsers.length,
    rosterPeople: roster.length, firstSeen: iso(firstTs), lastSeen: iso(lastTs), spanDays: round(spanDays, 1), findings: findings.length, bySeverity,
  };
  progress && progress(totalChars, totalChars, "Done");
  return {
    summary, findings,
    tables: { users: userRows, sources: sourceRows.slice(0, 5000), sessions: sessionRows, countries: countryRows, files: fileRows, revocation, blocklist },
    skipped,
    meta: {
      tool: TOOL_ID, version: VERSION, rows: events.length, sessionsTruncated: sessions.length > maxRows, sourcesTruncated: sourceRows.length > 5000,
      timeZone: zone.name, logTimeZone: (makeZone(o.logTimeZone) || makeZone("UTC")).name, syslogYear: tc.year, baselineEnd: iso(baselineEnd), feedUpdated: o.feedUpdated || null,
      feedSize: feed ? feed.size : 0, options: pickOptions(o),
    },
  };
}

function pickOptions(o) {
  const out = {};
  for (const k of Object.keys(DEFAULTS)) if (k !== "feedIps") out[k] = o[k];
  return out;
}

function clean(o) {
  const out = {};
  for (const k of Object.keys(o)) { const v = o[k]; if (v !== null && v !== undefined && v !== "") out[k] = v; }
  return out;
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
const q = (v) => '"' + str(v).replace(/"/g, '""') + '"';
const FINDING_COLS = ["severity", "confidence", "category", "title", "description", "recommendation", "controls", "assets", "evidenceCount"];

/** Findings as CSV with fixed columns. */
export function findingsToCsv(findings) {
  const body = (findings || []).map((f) => [
    f.severity, f.confidence, f.category, f.title, f.description, f.recommendation,
    (f.controls || []).map((c) => c.framework + " " + c.id).join("; "), (f.assets || []).map((a) => a.type + ":" + a.name).join("; "),
    f.evidenceCount != null ? f.evidenceCount : (f.evidence || []).length,
  ].map(q).join(","));
  return [FINDING_COLS.join(","), ...body].join("\n") + "\n";
}

/** Access-revocation list (leavers and shared accounts) as CSV. */
export function revocationCsv(result) {
  const cols = ["user", "name", "email", "reason", "termination_date", "last_seen", "last_ip", "accesses_after"];
  const rows = ((result && result.tables && result.tables.revocation) || []).map((r) => cols.map((c) => q(r[c])).join(","));
  return [cols.join(","), ...rows].join("\n") + "\n";
}

/** IP blocklist (spraying sources and feed matches), one IP per line with a comment. */
export function blocklistText(result) {
  const l = (result && result.tables && result.tables.blocklist) || [];
  return ["# Remote Access Audit IP blocklist", "# Sources: password-spraying detections and malicious-IP feed matches in the analysed logs", "# Review before applying; documentation-range example addresses are not real attackers.", ...l.map((b) => b.ip + "  # " + b.reason)].join("\n") + "\n";
}

/** Per-user activity report as plain text. */
export function userReportText(result) {
  const r = result || { tables: {}, summary: {} };
  const s = r.summary || {};
  const out = ["Remote Access Audit - user activity report", "Log span: " + (s.firstSeen || "-") + " to " + (s.lastSeen || "-") + " (" + (s.spanDays || 0) + " days)", "Users: " + (s.users || 0) + "  Sessions: " + (s.sessions || 0) + "  Events: " + (s.events || 0), ""];
  for (const u of (r.tables && r.tables.users) || []) {
    out.push(u.user + (u.name ? " (" + u.name + ")" : "") + " - " + u.rosterStatus + (u.termination ? ", terminated " + u.termination : ""));
    out.push("  sessions " + u.sessions + ", " + u.hours + " h, successes " + u.successes + ", failures " + u.failures + ", source IPs " + u.ips + ", devices " + u.devices + ", countries " + (u.countries.join(" ") || "-"));
    out.push("  first " + (u.firstSeen || "-") + ", last " + (u.lastSeen || "-") + (u.lastIp ? " from " + u.lastIp : "") + ", risk " + u.risk + (u.flags.length ? ", flags: " + u.flags.join("; ") : ""));
  }
  return out.join("\n") + "\n";
}

/** Summary as plain text. */
export function summaryText(result) {
  const r = result, s = r.summary;
  return ["Remote Access Audit - summary", "Log span: " + (s.firstSeen || "-") + " to " + (s.lastSeen || "-"),
    "Files: " + ((r.tables.files || []).map((f) => f.file + " [" + f.label + ", " + f.events + "]").join(", ")),
    "Sessions: " + s.sessions + "  Users: " + s.users + "  Sources: " + s.sources + "  Countries: " + s.countries,
    "Leavers connecting: " + s.leaversConnecting + "  Brute-force successes: " + s.bruteForceSuccesses + "  Spraying sources: " + s.sprayIps + "  Impossible travel: " + s.impossibleTravel + "  No-MFA users: " + s.noMfaUsers + "  Shared accounts: " + s.sharedAccounts,
    "Findings: " + s.findings + "  " + JSON.stringify(s.bySeverity), "",
    ...r.findings.map((f) => "- [" + f.severity + " / " + f.confidence + "] " + f.title + " (" + f.evidenceCount + " evidence) - " + f.recommendation),
    "", r.skipped.length ? "Skipped checks: " + r.skipped.map((x) => x.check + " (" + x.reason + ")").join("; ") : "All checks ran.",
  ].join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// Synthetic example (seeded, format-faithful). Documentation-range IPs only;
// people at test.darknode.ai.
// ---------------------------------------------------------------------------
export function exampleDataset(seed = 7) {
  let s = seed >>> 0;
  const rnd = () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 4294967296; };
  const D = "test.darknode.ai";
  const staff = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy", "ken", "lena", "mia", "nora", "oscar", "pete", "quinn", "rosa", "sam", "tara"];
  const homeIp = {};
  staff.forEach((u, i) => { homeIp[u] = "203.0.113." + (10 + i); });
  const pad = (n) => String(n).padStart(2, "0");
  const dstr = (t) => { const d = new Date(t); return d.getUTCFullYear() + "-" + pad(d.getUTCMonth() + 1) + "-" + pad(d.getUTCDate()); };
  const tstr = (t) => { const d = new Date(t); return pad(d.getUTCHours()) + ":" + pad(d.getUTCMinutes()) + ":" + pad(d.getUTCSeconds()); };
  const T0 = Date.UTC(2026, 9, 1); // 2026-10-01
  const forti = [];
  let tunnel = 1000;
  const fgUp = (t, user, ip) => { tunnel++; forti.push({ t, line: `date=${dstr(t)} time=${tstr(t)} devname="FGT-HQ" devid="FG100FTK19000001" eventtime=${t}000000 tz="+0000" logid="0101039947" type="event" subtype="vpn" level="information" vd="root" logdesc="SSL VPN tunnel up" action="tunnel-up" tunneltype="ssl-tunnel" tunnelid=${tunnel} remip=${ip} tunnelip=10.212.134.${10 + (tunnel % 200)} user="${user}" group="vpn-users" dst_host="N/A" reason="N/A" msg="SSL tunnel established"` }); return tunnel; };
  const fgDown = (t, user, ip, id, dur, sent, rcvd) => forti.push({ t, line: `date=${dstr(t)} time=${tstr(t)} devname="FGT-HQ" devid="FG100FTK19000001" eventtime=${t}000000 tz="+0000" logid="0101039948" type="event" subtype="vpn" level="information" vd="root" logdesc="SSL VPN tunnel down" action="tunnel-down" tunneltype="ssl-tunnel" tunnelid=${id} remip=${ip} tunnelip=N/A user="${user}" group="vpn-users" dst_host="N/A" reason="N/A" duration=${dur} sentbyte=${sent} rcvdbyte=${rcvd} msg="SSL tunnel shutdown"` });
  const fgFail = (t, user, ip) => forti.push({ t, line: `date=${dstr(t)} time=${tstr(t)} devname="FGT-HQ" devid="FG100FTK19000001" eventtime=${t}000000 tz="+0000" logid="0101039426" type="event" subtype="vpn" level="alert" vd="root" logdesc="SSL VPN login fail" action="ssl-login-fail" tunneltype="ssl-web" tunnelid=0 remip=${ip} tunnelip=N/A user="${user}" group="N/A" dst_host="N/A" reason="sslvpn_login_permission_denied" msg="SSL user failed to logged in"` });
  const fgSession = (t, user, ip, hours) => { const id = fgUp(t, user, ip); const dur = Math.round(hours * 3600); fgDown(t + dur * 1000, user, ip, id, dur, Math.round(40e6 + rnd() * 200e6), Math.round(5e6 + rnd() * 20e6)); };

  // background: 16 weekdays-ish of business-hours sessions for the first 10 staff via FortiGate
  for (let day = 0; day < 16; day++) {
    const dow = new Date(T0 + day * DAY).getUTCDay();
    if (dow === 0 || dow === 6) continue;
    for (const u of staff.slice(0, 10)) {
      if (u === "dave" && day >= 12) continue;
      const start = T0 + day * DAY + (8 * 60 + Math.floor(rnd() * 90)) * MIN;
      fgSession(start, u, homeIp[u], 6 + rnd() * 3);
    }
  }
  // brute force -> success: bob, 12 failures then success from 203.0.113.200
  const bf = T0 + 13 * DAY + 20 * HOUR;
  for (let i = 0; i < 12; i++) fgFail(bf + i * 90 * 1000, "bob", "203.0.113.200");
  fgSession(bf + 19 * MIN, "bob", "203.0.113.200", 1.5);
  // 31-hour session with a large download: dave
  { const t = T0 + 12 * DAY + 8 * HOUR; const id = fgUp(t, "dave", homeIp.dave); const dur = 31 * 3600; fgDown(t + dur * 1000, "dave", homeIp.dave, id, dur, 7 * GB, 120e6); }
  // leaver: mallory terminated 2026-10-03, connects 2026-10-12 (9 days after)
  fgSession(T0 + 2 * DAY + 9 * HOUR, "mallory", "198.51.100.23", 7);
  fgSession(T0 + 11 * DAY + 22 * HOUR + 14 * MIN, "mallory", "198.51.100.23", 2.2);
  forti.sort((a, b) => a.t - b.t);

  // GlobalProtect CSV export
  const GP_HEAD = "Domain,Receive Time,Serial #,Sequence Number,Action Flags,Type,Threat/Content Type,Config Version,Generate Time,Virtual System,Event ID,Stage,Authentication Method,Tunnel Type,Source User,Source Region,Machine Name,Public IP,Public IPv6,Private IP,Private IPv6,Host ID,Serial Number,Client Version,Client OS,Client OS Version,Repeat Count,Reason,Error,Description,Status,Location,Login Duration,Connect Method,Error Code,Portal,Selection Type,Response Time,Priority,Attempted Gateways,Gateway";
  const gp = [];
  let seq = 7000;
  const pan = (t) => { const d = new Date(t); return d.getUTCFullYear() + "/" + pad(d.getUTCMonth() + 1) + "/" + pad(d.getUTCDate()) + " " + tstr(t); };
  const gpRow = (t, ev, stage, user, ip, host, machine, status, method, ver, err, dur, region) => {
    seq++;
    gp.push({ t, line: ["1", pan(t), "012801000001", String(seq), "0x0", "GLOBALPROTECT", ev.split("-")[0], "2561", pan(t), "vsys1", ev, stage, method, "SSL", user + "@" + D, region || "US", machine, ip, "", status === "success" && ev === "gateway-connected" ? "10.20.0." + (seq % 200) : "", "", host, "", ver, "Windows", '"Microsoft Windows 11 Enterprise , 64-bit"', "1", "", err, "", status, "", dur == null ? "" : String(dur), "user-logon", status === "failure" ? "1" : "0", "GP-Portal", "auto", "", "0", "", "GW-East"].join(",") });
  };
  const gpUsers = staff.slice(10);
  for (let day = 0; day < 16; day++) {
    const dow = new Date(T0 + day * DAY).getUTCDay();
    if (dow === 0 || dow === 6) continue;
    for (const u of gpUsers) {
      if (u === "oscar" && day > 12) continue;
      const t = T0 + day * DAY + (8 * 60 + 30 + Math.floor(rnd() * 60)) * MIN;
      const method = u === "frank" ? "LDAP" : "SAML";
      gpRow(t, "gateway-auth", "login", u, homeIp[u], "host-" + u, "LT-" + u.toUpperCase(), "success", method, "6.2.4-24", "", null);
      gpRow(t + 20 * 1000, "gateway-connected", "connected", u, homeIp[u], "host-" + u, "LT-" + u.toUpperCase(), "success", method, "6.2.4-24", "", null);
      const dur = Math.round((7 + rnd() * 2) * 3600);
      gpRow(t + dur * 1000, "gateway-logout", "logout", u, homeIp[u], "host-" + u, "LT-" + u.toUpperCase(), "success", method, "6.2.4-24", "", dur);
    }
  }
  // frank uses LDAP-only authentication on GlobalProtect (no MFA)
  { const t = T0 + 8 * DAY + 10 * HOUR; gpRow(t, "gateway-auth", "login", "frank", "203.0.113.15", "host-frank", "LT-FRANK", "success", "LDAP", "6.2.4-24", "", null); gpRow(t + 15000, "gateway-connected", "connected", "frank", "203.0.113.15", "host-frank", "LT-FRANK", "success", "LDAP", "6.2.4-24", "", null); gpRow(t + 3 * HOUR, "gateway-logout", "logout", "frank", "203.0.113.15", "host-frank", "LT-FRANK", "success", "LDAP", "6.2.4-24", "", 3 * 3600); }
  // spraying: 198.51.100.77 tries 13 users within 40 minutes, then oscar succeeds
  const sp = T0 + 13 * DAY + 2 * HOUR;
  staff.slice(0, 13).forEach((u, i) => gpRow(sp + i * 3 * MIN, "gateway-auth", "login", u, "198.51.100.77", "", "", "failure", "LDAP", "", "Authentication failed: Invalid username or password", null, "NL"));
  gpRow(sp + 45 * MIN, "gateway-auth", "login", "oscar", "198.51.100.77", "", "", "failure", "LDAP", "", "Authentication failed: Invalid username or password", null, "NL");
  gpRow(sp + 47 * MIN, "gateway-auth", "login", "oscar", "198.51.100.77", "host-x9", "DESKTOP-Q7Z", "success", "SAML", "5.1.0-12", "", null, "NL");
  gpRow(sp + 48 * MIN, "gateway-connected", "connected", "oscar", "198.51.100.77", "host-x9", "DESKTOP-Q7Z", "success", "SAML", "5.1.0-12", "", null, "NL");
  // shared account: erin on three devices at once
  const sh = T0 + 14 * DAY + 13 * HOUR;
  ["host-erin", "host-e2", "host-e3"].forEach((h, i) => {
    const ip = ["203.0.113.14", "203.0.113.90", "203.0.113.91"][i];
    gpRow(sh + i * 5 * MIN, "gateway-auth", "login", "erin", ip, h, "LT-" + h.toUpperCase(), "success", "SAML", "6.2.4-24", "", null);
    gpRow(sh + i * 5 * MIN + 20000, "gateway-connected", "connected", "erin", ip, h, "LT-" + h.toUpperCase(), "success", "SAML", "6.2.4-24", "", null);
    gpRow(sh + 3 * HOUR + i * MIN, "gateway-logout", "logout", "erin", ip, h, "LT-" + h.toUpperCase(), "success", "SAML", "6.2.4-24", "", Math.round((3 * HOUR + i * MIN - i * 5 * MIN - 20000) / 1000));
  });
  gp.sort((a, b) => a.t - b.t);

  // Zscaler ZPA user status (CSV) with client coordinates: carol, New York then London 2 hours later
  const ZPA_HEAD = "LogTimestamp,Customer,Username,SessionID,SessionStatus,Version,ZEN,CertificateCN,PrivateIP,PublicIP,Latitude,Longitude,CountryCode,TimestampAuthentication,TimestampUnAuthentication,TotalBytesRx,TotalBytesTx,Idp,Hostname,Platform,ClientType";
  const zpa = [];
  const zts = (t) => { const d = new Date(t); return ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][d.getUTCDay()] + " " + ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][d.getUTCMonth()] + " " + pad(d.getUTCDate()) + " " + tstr(t) + " " + d.getUTCFullYear(); };
  // tAuth given = a disconnect row: TimestampAuthentication is the session start, TimestampUnAuthentication the row time.
  const zRow = (t, user, sid, st, ip, lat, lon, ccode, tAuth) => zpa.push({ t, line: [zts(t), "Darknode Test", user + "@" + D, sid, st, "4.3.0.188", "US-NY-8179", "cn-" + user, "10.30.0.5", ip, lat, lon, ccode, new Date(tAuth || t).toISOString(), tAuth ? new Date(t).toISOString() : "", tAuth ? String(Math.round(80e6 + rnd() * 50e6)) : "", tAuth ? String(Math.round(9e6 + rnd() * 5e6)) : "", "Okta", "LT-" + user.toUpperCase(), "windows", "zpn_client_type_zapp"].join(",") });
  for (let day = 0; day < 12; day++) {
    const dow = new Date(T0 + day * DAY).getUTCDay();
    if (dow === 0 || dow === 6) continue;
    const t = T0 + day * DAY + 13 * HOUR + Math.floor(rnd() * 30) * MIN;
    zRow(t, "carol", "zs-carol-" + day, "ZPN_STATUS_AUTHENTICATED", "203.0.113.12", "40.7128", "-74.0060", "US");
    zRow(t + 4 * HOUR, "carol", "zs-carol-" + day, "ZPN_STATUS_DISCONNECTED", "203.0.113.12", "40.7128", "-74.0060", "US", t);
  }
  const tr = T0 + 12 * DAY + 14 * HOUR; // Tue 2026-10-13
  zRow(tr, "carol", "zs-carol-ny", "ZPN_STATUS_AUTHENTICATED", "203.0.113.12", "40.7128", "-74.0060", "US");
  zRow(tr + 3 * HOUR, "carol", "zs-carol-ny", "ZPN_STATUS_DISCONNECTED", "203.0.113.12", "40.7128", "-74.0060", "US", tr);
  zRow(tr + 2 * HOUR, "carol", "zs-carol-ldn", "ZPN_STATUS_AUTHENTICATED", "198.51.100.40", "51.5074", "-0.1278", "GB");
  zRow(tr + 3.5 * HOUR, "carol", "zs-carol-ldn", "ZPN_STATUS_DISCONNECTED", "198.51.100.40", "51.5074", "-0.1278", "GB", tr + 2 * HOUR);
  zpa.sort((a, b) => a.t - b.t);

  const roster = ["employee_id,name,email,username,department,manager_email,status,hire_date,termination_date"];
  staff.forEach((u, i) => roster.push(["E" + (100 + i), u[0].toUpperCase() + u.slice(1) + " Example", u + "@" + D, u, i < 10 ? "Engineering" : "Sales", "grace@" + D, "active", "2023-0" + (1 + (i % 9)) + "-15", ""].join(",")));
  roster.push(["E200", "Mallory Example", "mallory@" + D, "mallory", "Finance", "grace@" + D, "terminated", "2022-04-01", "2026-10-03"].join(","));
  return {
    label: "synthetic example (not real data)",
    files: [
      { name: "example-fortigate-vpn.log", text: forti.map((x) => x.line).join("\n") + "\n" },
      { name: "example-globalprotect.csv", text: GP_HEAD + "\n" + gp.map((x) => x.line).join("\n") + "\n" },
      { name: "example-zpa-user-status.csv", text: ZPA_HEAD + "\n" + zpa.map((x) => x.line).join("\n") + "\n" },
      { name: "example-hr-roster.csv", text: roster.join("\n") + "\n" },
    ],
  };
}

/** Deterministic checks of the engine. */
export function selfTest() {
  const tests = [];
  const ex = exampleDataset();
  const r = analyze(ex, {});
  const has = (cat, u) => r.findings.some((f) => f.category === cat && (!u || (f.assets || []).some((a) => a.name === u || a.name.startsWith(u + "@"))));
  tests.push({ name: "leaver connecting detected", pass: has("leaver", "mallory") });
  tests.push({ name: "brute force success detected", pass: has("brute_force", "bob") });
  tests.push({ name: "spraying with success detected", pass: r.findings.some((f) => f.id === "spraysucc:198.51.100.77" && f.severity === "critical") });
  tests.push({ name: "impossible travel from log coordinates", pass: has("impossible_travel", "carol") });
  tests.push({ name: "31-hour session detected", pass: has("long_session", "dave") });
  tests.push({ name: "shared account detected", pass: has("shared_account", "erin") });
  tests.push({ name: "deterministic", pass: JSON.stringify(analyze(ex, {})) === JSON.stringify(r) });
  tests.push({ name: "empty input yields no findings", pass: analyze({ files: [] }).findings.length === 0 });
  tests.push({ name: "haversine NYC-London about 5570 km", pass: Math.abs(haversineKm(40.7128, -74.006, 51.5074, -0.1278) - 5570) < 15 });
  return { pass: tests.every((t) => t.pass), tests };
}
