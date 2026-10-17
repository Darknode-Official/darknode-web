// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Endpoint Fleet Compliance engine (fleetcomply). Pure logic: no DOM, no network, no timers.
//
// Reconciles every endpoint inventory a company has (MDM, EDR, identity directory,
// software inventory and the Darknode desktop app's Workstation Audit fleet record)
// into one device register, then checks each device against a baseline: disk
// encryption, EDR present and healthy, OS / browser / runtime end-of-life (from the
// mirrored endoflife.date feed passed in as opts.eol), patch level relative to the
// fleet, last check-in, local admins, firewall, screen lock, jailbreak, compliance,
// unauthorized and remote-access software, duplicates and coverage gaps.
//
// Inputs (auto-detected per file by header signature / JSON shape):
//   Darknode app   Workstation Audit "Fleet record" JSON (toFleetRecord in darknode-app lib/hardening-audit.js)
//   Intune         Devices CSV, Encryption report CSV, Graph managedDevices JSON, Discovered apps CSV
//   Jamf Pro       Computers CSV, /api/v1/computers-inventory JSON, Applications CSV
//   CrowdStrike    Host Management CSV
//   Defender       Devices CSV, DeviceInfo advanced-hunting CSV
//   Google         Endpoints CSV, ChromeOS devices CSV
//   Software       SCCM/MECM Installed Software CSV, Lansweeper CSV, Kandji apps CSV
//   Directory      Entra devices CSV, Okta devices CSV, AD Get-ADComputer CSV
//   Generic        any CSV with a column mapping
//
// Devices are matched across sources by serial number, then hostname (case-insensitive,
// domain stripped), then Intune / Entra device id, then MAC. A key never joins two
// records whose serial numbers disagree; that case is reported as a conflict.
// Same input -> byte-identical output: everything is sorted and no clock is read
// (opts.now, default = the newest timestamp in the data).

import { sniff, parseCsv, iterJson, normHeader, findColumn } from "../ingest/parse.js";

export const TOOL_ID = "fleetcomply";
export const VERSION = "1.0.0";

export const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const DAY = 86400000;

/** Tunable thresholds; the UI renders these as the baseline panel. */
export const DEFAULTS = {
  now: null,                // ISO reference date; default = newest timestamp in the data
  eol: null,                // parsed /data/feeds/eol-products.json
  edrStaleDays: 7,          // EDR sensor last seen older than this while MDM is recent
  staleDays: 30,            // no check-in in any source for this long
  lostDays: 90,             // stale this long with an enabled directory account
  eolSoonDays: 90,          // EOL within this many days = approaching
  patchAgeBuilds: 1,        // allowed distinct newer releases seen in the fleet for the same OS line
  sensorMinorLag: 2,        // EDR sensor minor versions behind the fleet mode
  maxLocalAdmins: 2,        // more local admin accounts than this
  windowsEdition: "w",      // Windows servicing track when the OS string does not say: "w" Home/Pro, "e" Enterprise/Education
  blocklist: "",            // one name or /regex/ per line
  allowlist: "",            // one name or /regex/ per line (suppresses the remote-access review list)
  weights: null,            // per-check score weights; null = WEIGHTS
  treatAs: {},              // { fileName: formatKey } overrides
  columns: {},              // { fileName: { logicalKey: header } } for generic CSV
};

/** Score points subtracted from 100 per failed check. */
export const WEIGHTS = {
  encryption: 25, edr_missing: 25, edr_unhealthy: 15, edr_stale: 10, sensor_behind: 2,
  os_eol: 25, os_eol_soon: 5, app_eol: 10, patch_behind: 10, stale: 10, stale_enabled: 15,
  local_admin: 15, many_admins: 5, firewall: 10, gatekeeper_sip: 15, jailbroken: 40, screen_lock: 5,
  secure_boot: 3, recovery_lock: 1, activation_lock: 2, guest_account: 5, noncompliant: 10, unmanaged: 20,
  blocklist: 15, remote_access: 3,
};

/** Generic CSV logical columns (key -> accepted header aliases). */
export const COLUMNS = {
  hostname: ["hostname", "host", "device name", "computer name", "name", "device", "asset name", "machine name"],
  serial: ["serial", "serial number", "serialnumber", "serial no"],
  os: ["os", "operating system", "platform", "os name"],
  osVersion: ["os version", "osversion", "version", "os build", "build"],
  user: ["user", "primary user", "owner", "upn", "username", "email"],
  lastSeen: ["last seen", "lastseen", "last check-in", "last sync", "last contact", "last checkin"],
  encrypted: ["encrypted", "encryption", "disk encryption", "bitlocker", "filevault"],
  edr: ["edr", "edr agent", "sensor", "av", "antivirus"],
  localAdmin: ["local admin", "localadmin", "is admin", "admin"],
  firewall: ["firewall", "firewall enabled"],
  model: ["model"],
  mac: ["mac", "mac address"],
  deviceId: ["device id", "deviceid", "id"],
};

export const KIND_LABEL = { mdm: "MDM", edr: "EDR", directory: "Directory", software: "Software inventory", audit: "Workstation Audit", encryption: "Encryption report", generic: "Generic" };

/** Recognised formats. `headers` is the vendor's exact column signature (CSV). */
export const FORMATS = {
  "dn-audit": { vendor: "Darknode", kind: "audit", label: "Darknode Workstation Audit fleet record (JSON)" },
  "intune-devices": { vendor: "Microsoft Intune", kind: "mdm", label: "Intune Devices export (CSV)", headers: ["Device name", "Managed by", "Ownership", "Compliance", "OS", "OS version", "Primary user UPN", "Last check-in", "Device ID", "Azure AD Device ID", "Serial number", "Manufacturer", "Model", "Encrypted", "Supervised", "Enrollment date", "Wi-Fi MAC", "Total storage", "Free storage", "IMEI", "EAS activated", "Join type", "Device state", "Jailbroken"] },
  "intune-encryption": { vendor: "Microsoft Intune", kind: "encryption", label: "Intune Encryption report (CSV)", headers: ["Device name", "OS", "OS version", "TPM version", "Encryption readiness state", "Encryption status", "UPN"] },
  "graph-managed": { vendor: "Microsoft Intune", kind: "mdm", label: "Graph managedDevices (JSON)" },
  "intune-apps": { vendor: "Microsoft Intune", kind: "software", label: "Intune Discovered apps (CSV)", headers: ["Device name", "App name", "App version", "Platform", "Publisher", "UPN"] },
  "jamf-computers": { vendor: "Jamf Pro", kind: "mdm", label: "Jamf Pro Computers (CSV)", headers: ["Computer Name", "Serial Number", "Last Check-in", "Last Inventory Update", "Operating System Version", "Model", "Username", "Email Address", "FileVault 2 Status", "FileVault 2 Enabled Users", "Gatekeeper", "System Integrity Protection", "Firewall Enabled", "Managed", "Supervised", "Recovery Lock Enabled", "Secure Boot Level", "Disk Encryption Configuration", "Activation Lock", "Last Enrollment", "IP Address", "MAC Address"] },
  "jamf-api": { vendor: "Jamf Pro", kind: "mdm", label: "Jamf Pro computers-inventory (JSON)" },
  "jamf-apps": { vendor: "Jamf Pro", kind: "software", label: "Jamf Pro Applications (CSV)", headers: ["Computer Name", "Application Title", "Application Version", "Application Path"] },
  crowdstrike: { vendor: "CrowdStrike Falcon", kind: "edr", label: "Falcon Host Management (CSV)", headers: ["Hostname", "Host ID", "Last Seen", "First Seen", "OS", "OS Version", "Platform", "Sensor Version", "Agent Status", "RFM (Reduced Functionality Mode)", "Local IP", "External IP", "MAC Address", "Serial Number", "Prevention Policy", "Sensor Update Policy", "Tags", "Containment Status", "Site"] },
  "defender-devices": { vendor: "Microsoft Defender for Endpoint", kind: "edr", label: "Defender Devices export (CSV)", headers: ["Device name", "Domain", "Risk level", "Exposure level", "OS platform", "OS version", "Windows version", "Health state", "Last device update", "First seen", "Tags", "Onboarding status", "Device ID", "Defender AV status", "Sensor health state", "Managed by", "Device value", "IP addresses"] },
  "defender-deviceinfo": { vendor: "Microsoft Defender for Endpoint", kind: "edr", label: "Defender DeviceInfo hunting (CSV)", headers: ["Timestamp", "DeviceId", "DeviceName", "OSPlatform", "OSVersion", "OSBuild", "OnboardingStatus", "SensorHealthState", "IsAzureADJoined", "LoggedOnUsers", "MachineGroup", "PublicIP"] },
  "google-endpoints": { vendor: "Google Workspace", kind: "mdm", label: "Google Endpoints (CSV)", headers: ["Name", "Owner", "Type", "OS", "OS Version", "Last Sync", "Status", "Encryption Status", "Password Status", "Device Id", "Model", "Serial Number", "Managed Type", "Compromised"] },
  chromeos: { vendor: "Google Chrome Enterprise", kind: "mdm", label: "ChromeOS devices (CSV)", headers: ["Serial Number", "Status", "Last Sync", "User", "Location", "OS Version", "Platform Version", "Model", "MEID/IMEI", "Last Policy Sync", "Auto-update Expiration"] },
  "sccm-software": { vendor: "Microsoft SCCM/MECM", kind: "software", label: "SCCM Installed Software (CSV)", headers: ["Computer Name", "Product Name", "Product Version", "Publisher", "Install Date"] },
  lansweeper: { vendor: "Lansweeper", kind: "software", label: "Lansweeper software (CSV)", headers: ["AssetName", "Software", "Version", "Publisher", "LastChanged"] },
  "kandji-apps": { vendor: "Kandji", kind: "software", label: "Kandji apps (CSV)", headers: ["Device Name", "Serial Number", "App Name", "Version", "Bundle ID"] },
  "entra-devices": { vendor: "Microsoft Entra ID", kind: "directory", label: "Entra devices (CSV)", headers: ["Name", "Enabled", "Operating system", "Version", "Join type", "Owner", "MDM", "Compliant", "Registered", "Activity (last sign-in)", "Object ID", "Device ID", "Trust type"] },
  "okta-devices": { vendor: "Okta", kind: "directory", label: "Okta devices (CSV)", headers: ["Device name", "Platform", "OS version", "Status", "Management status", "Serial number", "User", "Last seen"] },
  "ad-computers": { vendor: "Active Directory", kind: "directory", label: "AD Get-ADComputer (CSV)", headers: ["Name", "DNSHostName", "OperatingSystem", "OperatingSystemVersion", "LastLogonDate", "Enabled", "DistinguishedName", "PasswordLastSet"] },
  generic: { vendor: "Generic", kind: "generic", label: "Generic device list (CSV, mapped)" },
};

// ---------------------------------------------------------------------------
// Value helpers
// ---------------------------------------------------------------------------
const str = (v) => (v == null ? "" : String(v)).trim();
const lc = (v) => str(v).toLowerCase();
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const uniqSorted = (arr) => Array.from(new Set(arr.filter((x) => x != null && x !== ""))).sort(cmp);

const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };

/** Parse a timestamp as UTC. ISO, "YYYY-MM-DD HH:MM[:SS]", "M/D/YYYY [h:mm[:ss] [AM|PM]]", "Mon D, YYYY [h:mm AM]", epoch ms. */
export function parseTs(v) {
  const s = str(v);
  if (!s || /^(never|n\/a|-|none|null|unknown|not available)$/i.test(s)) return null;
  if (/^\d{12,14}$/.test(s)) return Number(s);
  let m = s.match(/^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{1,2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?)?\s*(Z|[+-]\d{2}:?\d{2}|UTC|GMT)?$/i);
  if (m) {
    let t = Date.UTC(+m[1], +m[2] - 1, +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0));
    if (m[7] && /^[+-]/.test(m[7])) { const z = m[7].replace(":", ""); t -= (z[0] === "-" ? -1 : 1) * (+z.slice(1, 3) * 60 + +z.slice(3, 5)) * 60000; }
    return Number.isFinite(t) ? t : null;
  }
  const hm = (h, mi, se, ap) => { h = +(h || 0); if (ap) { ap = ap.toUpperCase(); if (ap === "PM" && h < 12) h += 12; if (ap === "AM" && h === 12) h = 0; } return [h, +(mi || 0), +(se || 0)]; };
  m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})(?:,?\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM)?)?/i);
  if (m) { const [h, mi, se] = hm(m[4], m[5], m[6], m[7]); return Date.UTC(+m[3], +m[1] - 1, +m[2], h, mi, se); }
  m = s.match(/^(?:\w{3},?\s+)?([A-Za-z]{3})[a-z]*\.?\s+(\d{1,2}),?\s+(\d{4})(?:,?\s+(?:at\s+)?(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM)?)?/i);
  if (m && MONTHS[m[1].toLowerCase()] != null) { const [h, mi, se] = hm(m[4], m[5], m[6], m[7]); return Date.UTC(+m[3], MONTHS[m[1].toLowerCase()], +m[2], h, mi, se); }
  m = s.match(/^(\d{1,2})\s+([A-Za-z]{3})[a-z]*\s+(\d{4})/);
  if (m && MONTHS[m[2].toLowerCase()] != null) return Date.UTC(+m[3], MONTHS[m[2].toLowerCase()], +m[1]);
  return null;
}
export const iso = (ms) => (Number.isFinite(ms) ? new Date(ms).toISOString().replace(".000Z", "Z") : null);
const day = (ms) => (Number.isFinite(ms) ? new Date(ms).toISOString().slice(0, 10) : "");

/** Tri-state boolean from vendor wording; null when unknown. */
export function parseBool(v) {
  if (v === true || v === false) return v;
  if (typeof v === "number") return v !== 0;
  const s = lc(v);
  if (!s) return null;
  if (/^(yes|true|y|1|on|enabled?|active|encrypted|compliant|managed|all partitions encrypted|boot partitions encrypted|fully encrypted|protected|onboarded)$/.test(s)) return true;
  if (/^(no|false|n|0|off|disabled?|inactive|not encrypted|unencrypted|no partitions encrypted|decrypted|not ?compliant|noncompliant|unmanaged|not protected|none)$/.test(s)) return false;
  return null;
}

const BAD_SERIAL = /^(0+|n\/?a|none|null|unknown|defaultstring|tobefilledbyo\.?e\.?m\.?|systemserialnumber|chassisserialnumber|notspecified|notavailable|123456789|-)$/i;
/** Normalised serial (upper-case, no spaces) or "" when missing / placeholder. */
export function normSerial(v) { const s = str(v).replace(/\s+/g, "").toUpperCase(); return !s || BAD_SERIAL.test(s) || s.length < 4 ? "" : s; }
/** Normalised hostname: lower-case, domain stripped. IPs return "". */
export function normHost(v) {
  let s = lc(v);
  if (!s || /^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return "";
  s = s.replace(/^.*\\/, "");                 // DOMAIN\host
  if (!/\s/.test(s)) s = s.split(".")[0];     // host.corp.example -> host
  return s.trim();
}
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** Normalised device id (GUID or 32-40 hex) or "". */
export function normId(v) { const s = lc(v); return GUID.test(s) || /^[0-9a-f]{32,40}$/.test(s) ? s : ""; }
/** Normalised MAC (12 hex) or "". Takes the first of a list. */
export function normMac(v) { const s = lc(v).split(/[,;\s]+/)[0].replace(/[^0-9a-f]/g, ""); return s.length === 12 && !/^0+$/.test(s) && s !== "ffffffffffff" ? s : ""; }
export const LAPTOP_RE = /book|laptop|latitude|thinkpad|elitebook|surface|xps|zenbook/i;
const isLaptop = (model) => LAPTOP_RE.test(str(model));

/** Numeric version tuple from text ("14.6.1 (23G93)" -> [14,6,1]). */
export function verTuple(v) { const m = str(v).match(/\d+(?:\.\d+)*/); return m ? m[0].split(".").map(Number) : []; }
/** Compare dotted versions: -1, 0, 1. */
export function cmpVer(a, b) {
  const x = Array.isArray(a) ? a : verTuple(a), y = Array.isArray(b) ? b : verTuple(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) { const d = (x[i] || 0) - (y[i] || 0); if (d) return d < 0 ? -1 : 1; }
  return 0;
}
/** Windows "10.0.19045.4651" -> { major: 10, build: 19045, rev: 4651 }; bare build "19045" also accepted. */
export function parseWinBuild(v) {
  const s = str(v);
  let m = s.match(/(?:^|\D)(\d{1,2})\.(\d)\.(\d{4,5})(?:\.(\d{1,6}))?/);
  if (m) return { major: +m[1], build: +m[3], rev: m[4] != null ? +m[4] : null };
  m = s.match(/^(\d{4,5})(?:\.(\d{1,6}))?$/);
  if (m) return { major: 10, build: +m[1], rev: m[2] != null ? +m[2] : null };
  return null;
}

/** OS family from free text plus optional version. */
export function osFamily(os, version) {
  const s = lc(os) + " " + lc(version);
  if (/server/.test(s) && /windows/.test(s)) return "windows-server";
  if (/windows|win(10|11|32)/.test(s)) return "windows";
  if (/ipados|\bios\b|iphone|ipad/.test(s)) return "ios";
  if (/mac ?os|os ?x|darwin/.test(s)) return "macos";
  if (/android/.test(s)) return "android";
  if (/chrome ?os|chromeos|chromebook/.test(s)) return "chromeos";
  if (/ubuntu/.test(s)) return "ubuntu";
  if (/debian/.test(s)) return "debian";
  if (/red hat|rhel/.test(s)) return "rhel";
  if (/amazon linux/.test(s)) return "amazon-linux";
  if (/linux/.test(s)) return "linux";
  return lc(os) ? "other" : "";
}

// ---------------------------------------------------------------------------
// End-of-life mapping (endoflife.date mirror). Unknown mappings are reported, never guessed.
// ---------------------------------------------------------------------------
/** Index the mirrored feed: product -> cycles[]. Accepts {data:[{product,cycles}]} or a plain map. */
export function eolIndex(feed) {
  const idx = new Map();
  if (!feed) return idx;
  const list = Array.isArray(feed.data) ? feed.data : Array.isArray(feed) ? feed : null;
  if (list) for (const p of list) { if (p && p.product && Array.isArray(p.cycles)) idx.set(p.product, p.cycles); }
  else for (const k of Object.keys(feed)) if (Array.isArray(feed[k])) idx.set(k, feed[k]);
  return idx;
}

/** Status of one cycle on `now`: eol | soon | supported (plus the eol date). */
export function cycleStatus(c, now, soonDays = 90) {
  if (!c) return { status: "unknown", eol: null };
  if (c.eol === false || c.eol == null) return { status: "supported", eol: null };
  if (c.eol === true) return { status: "eol", eol: null };
  const t = parseTs(c.eol);
  if (t == null) return { status: "unknown", eol: str(c.eol) };
  if (t < now) return { status: "eol", eol: day(t) };
  if (t - now <= soonDays * DAY) return { status: "soon", eol: day(t) };
  return { status: "supported", eol: day(t) };
}

const winBuildOf = (c) => { const b = parseWinBuild(c && c.latest); return b ? b.build : null; };
const DARWIN_TO_MACOS = { 20: "11", 21: "12", 22: "13", 23: "14", 24: "15", 25: "26" };

/**
 * Map a device's OS to an endoflife.date product + cycle.
 * dev: { family, os, osVersion, release?, darwin?, aue? }. Returns { product, cycle, reason? }.
 */
export function mapOsCycle(dev, idx, opts = {}) {
  const fam = dev.family, os = str(dev.os), ver = str(dev.osVersion), both = os + " " + ver;
  const find = (product, pred) => { const cs = idx.get(product); return cs ? cs.find(pred) || null : null; };
  if (fam === "windows") {
    const cycles = idx.get("windows");
    if (!cycles) return { product: "windows", cycle: null, reason: "windows not in the EOL feed" };
    const b = parseWinBuild(ver) || parseWinBuild(os);
    const rid = (both.match(/\b(\d{2}H\d)\b/i) || [])[1];
    const fam11 = b ? (b.build >= 22000 ? "11" : b.build >= 10240 ? "10" : null) : /windows\s*11|windows11/i.test(both) ? "11" : /windows\s*10|windows10/i.test(both) ? "10" : null;
    const ed = /iot/i.test(both) ? "iot-lts" : /ltsc|ltsb/i.test(both) ? "e-lts" : /enterprise|education/i.test(both) ? "e" : (opts.windowsEdition === "e" ? "e" : "w");
    let cands;
    if (b && fam11) cands = cycles.filter((c) => winBuildOf(c) === b.build && String(c.cycle).startsWith(fam11 + "-"));
    else if (b) cands = cycles.filter((c) => winBuildOf(c) === b.build);
    else if (rid && fam11) cands = cycles.filter((c) => String(c.cycle).toLowerCase().startsWith(fam11 + "-" + rid.toLowerCase()));
    else return { product: "windows", cycle: null, reason: "no build number or release id in '" + both.trim() + "'" };
    if (ed !== "iot-lts") cands = cands.filter((c) => !/iot/.test(c.cycle));
    if (!/lts/.test(ed)) { const nl = cands.filter((c) => !/lts/.test(c.cycle)); if (nl.length) cands = nl; }
    const pick = cands.find((c) => String(c.cycle).endsWith("-" + ed)) || cands.find((c) => !/-(w|e|e-lts|iot-lts)$/.test(c.cycle)) || (cands.length === 1 ? cands[0] : null);
    return pick ? { product: "windows", cycle: pick } : { product: "windows", cycle: null, reason: "build " + (b ? b.build : rid) + " has no unambiguous cycle in the feed" };
  }
  if (fam === "windows-server") {
    const year = (both.match(/\b(2003|2008|2012|2016|2019|2022|2025)(\s*R2)?\b/i) || []);
    const b = parseWinBuild(ver) || parseWinBuild(os);
    const cycles = idx.get("windows-server") || [];
    let pick = null;
    if (year[1]) pick = cycles.find((c) => String(c.cycle).startsWith(year[1] + (year[2] ? "-r2" : "")) && (year[2] ? true : !/-r2/.test(c.cycle)));
    if (!pick && b) { const cs = cycles.filter((c) => winBuildOf(c) === b.build); pick = cs.find((c) => c.lts) || (cs.length === 1 ? cs[0] : null); }
    return pick ? { product: "windows-server", cycle: pick } : { product: "windows-server", cycle: null, reason: "no server year or known build in '" + both.trim() + "'" };
  }
  if (fam === "macos") {
    let t = verTuple(ver.match(/\d/) ? ver : os);
    if (dev.darwin && t.length) { const p = DARWIN_TO_MACOS[t[0]]; if (!p) return { product: "macos", cycle: null, reason: "Darwin " + t[0] + " has no known macOS mapping" }; t = [Number(p)]; }
    if (!t.length) return { product: "macos", cycle: null, reason: "no version" };
    const key = t[0] === 10 ? "10." + (t[1] || 0) : String(t[0]);
    const c = find("macos", (x) => String(x.cycle) === key);
    return c ? { product: "macos", cycle: c } : { product: "macos", cycle: null, reason: "macOS " + key + " not in the feed" };
  }
  const simple = { ios: 1, android: 1, debian: 1, rhel: 1 };
  if (simple[fam]) {
    const t = verTuple(ver.match(/\d/) ? ver : os);
    if (!t.length) return { product: fam, cycle: null, reason: "no version" };
    const c = find(fam, (x) => String(x.cycle) === String(t[0]));
    return c ? { product: fam, cycle: c } : { product: fam, cycle: null, reason: fam + " " + t[0] + " not in the feed" };
  }
  if (fam === "ubuntu") {
    const m = both.match(/(\d{2}\.\d{2})/);
    const c = m && find("ubuntu", (x) => String(x.cycle) === m[1]);
    return c ? { product: "ubuntu", cycle: c } : { product: "ubuntu", cycle: null, reason: "no Ubuntu release in '" + both.trim() + "'" };
  }
  if (fam === "amazon-linux") {
    const m = both.match(/\b(2023|2018\.03|2)\b/);
    const c = m && find("amazon-linux", (x) => String(x.cycle) === m[1]);
    return c ? { product: "amazon-linux", cycle: c } : { product: "amazon-linux", cycle: null, reason: "no Amazon Linux release in '" + both.trim() + "'" };
  }
  if (fam === "chromeos") {
    if (dev.aue != null) return { product: "chromeos-aue", cycle: { cycle: "auto-update expiration", eol: day(dev.aue) } };
    return { product: "chromeos", cycle: null, reason: "ChromeOS is not in the feed and no Auto-update Expiration column" };
  }
  return { product: fam || "", cycle: null, reason: fam ? "no EOL product for '" + both.trim() + "'" : "no OS reported" };
}

/** Software title -> endoflife.date product + cycle key, or null for titles this engine does not map. */
export function mapAppProduct(name, version) {
  const n = str(name), v = str(version);
  if (/google chrome/i.test(n) && !/remote desktop|frame|os\b/i.test(n)) { const t = verTuple(v); return t.length ? { product: "chrome", key: String(t[0]) } : null; }
  if (/mozilla firefox|^firefox\b/i.test(n)) { const t = verTuple(v || n); return t.length ? { product: "firefox", key: String(t[0]) } : null; }
  if (/^python\s*\d|python 3|^python$/i.test(n) && !/launcher|extension|pip/i.test(n)) { const t = verTuple((n.match(/\d+\.\d+/) || [v])[0]); return t.length >= 2 ? { product: "python", key: t[0] + "." + t[1] } : null; }
  if (/^node(\.?js)?\b/i.test(n)) { const t = verTuple(v); return t.length ? { product: "nodejs", key: String(t[0]) } : null; }
  if (/temurin|adoptium/i.test(n)) { const t = verTuple((n.match(/\b(\d{1,2})\b/) || [v])[0]); return t.length ? { product: "eclipse-temurin", key: String(t[0]) } : null; }
  const off = n.match(/microsoft office\b.*\b(2010|2013|2016|2019|2021|2024)\b/i);
  if (off) return { product: "office", key: off[1] + (/ltsc/i.test(n) && off[1] === "2024" ? "-ltsc" : "") };
  return null;
}

// ---------------------------------------------------------------------------
// Format detection
// ---------------------------------------------------------------------------
/** Best CSV format for a header row: { format, confidence: high|medium|low, score }. */
export function classifyHeaders(headers) {
  const have = new Set((headers || []).map(normHeader));
  let best = null;
  for (const [key, f] of Object.entries(FORMATS)) {
    if (!f.headers) continue;
    const hits = f.headers.filter((h) => have.has(normHeader(h))).length;
    const score = hits / f.headers.length;
    if (!best || score > best.score || (score === best.score && f.headers.length > best.n)) best = { format: key, score, n: f.headers.length };
  }
  if (best && best.score >= 0.85) return { format: best.format, confidence: "high", score: round3(best.score) };
  if (best && best.score >= 0.6) return { format: best.format, confidence: "medium", score: round3(best.score) };
  return { format: "generic", confidence: "low", score: best ? round3(best.score) : 0 };
}
const round3 = (n) => Math.round(n * 1000) / 1000;

const isFleetRecord = (o) => o && typeof o === "object" && !Array.isArray(o) &&
  ((Array.isArray(o.results) && typeof o.host === "string" && o.results.every((r) => r && typeof r === "object" && "id" in r && "status" in r)) ||
   (o.tool === "darknode-app" && Array.isArray(o.checks)));

/** Classify one parsed JSON value: { format, records } or null. */
export function classifyJson(v) {
  if (isFleetRecord(v)) return { format: "dn-audit", records: [v] };
  if (Array.isArray(v) && v.length && v.every(isFleetRecord)) return { format: "dn-audit", records: v };
  const arr = Array.isArray(v) ? v : v && typeof v === "object" ? (Array.isArray(v.value) ? v.value : Array.isArray(v.results) ? v.results : Array.isArray(v.devices) ? v.devices : null) : null;
  if (!arr || !arr.length) return null;
  const o = arr.find((x) => x && typeof x === "object") || {};
  if (o.general && (o.hardware || o.operatingSystem)) return { format: "jamf-api", records: arr };
  if ("deviceName" in o && ("complianceState" in o || "managementAgent" in o || "isEncrypted" in o)) return { format: "graph-managed", records: arr };
  return null;
}

function loadJson(text) {
  try { return JSON.parse(text); } catch (_) { /* fall through to NDJSON */ }
  const out = [];
  for (const l of text.split(/\r?\n/)) { const s = l.trim(); if (!s) continue; try { out.push(JSON.parse(s)); } catch (_) { return undefined; } }
  return out.length ? out : undefined;
}

/**
 * Detect one file without normalising it (cheap: first 64 KB for CSV header).
 * Returns { name, format, kind, vendor, label, confidence, headers }.
 */
export function detectFile(file) {
  const name = str(file && file.name) || "input";
  const text = String((file && file.text) || "").replace(/^﻿/, "");
  const base = (format, confidence, headers) => ({ name, format, kind: FORMATS[format] ? FORMATS[format].kind : "generic", vendor: FORMATS[format] ? FORMATS[format].vendor : "", label: FORMATS[format] ? FORMATS[format].label : format, confidence, headers: headers || [] });
  if (!text.trim()) return base("empty", "low");
  const sn = sniff(text);
  if (sn.format === "json" || sn.format === "ndjson") {
    const v = loadJson(text);
    const c = v === undefined ? null : classifyJson(v);
    return c ? base(c.format, "high") : base("unknown-json", "low");
  }
  const head = text.slice(0, 65536);
  const { headers } = parseCsv(head.slice(0, head.lastIndexOf("\n") > 0 ? head.lastIndexOf("\n") : head.length));
  const c = classifyHeaders(headers);
  return base(c.format, c.confidence, headers);
}

// ---------------------------------------------------------------------------
// Normalisation: one vendor row -> device record / software rows
// ---------------------------------------------------------------------------
const pick = (row, ...names) => { for (const n of names) { if (row[n] != null && str(row[n]) !== "") return str(row[n]); } return ""; };
function parseMonthEnd(v) {
  const s = str(v);
  let m = s.match(/^(\d{4})-(\d{1,2})$/);
  if (m) return Date.UTC(+m[1], +m[2], 0);
  m = s.match(/^([A-Za-z]{3})[a-z]*\.?\s+(\d{4})$/);
  if (m && MONTHS[m[1].toLowerCase()] != null) return Date.UTC(+m[2], MONTHS[m[1].toLowerCase()] + 1, 0);
  return parseTs(s);
}
const compliance = (v) => { const s = lc(v); if (!s) return null; if (/^(compliant|yes|true)$/.test(s)) return "compliant"; if (/not ?evaluated|unknown|n\/a|configmanager/.test(s)) return "not evaluated"; if (/grace/.test(s)) return "in grace period"; if (/non ?compliant|not compliant|^no$|false|error|conflict/.test(s)) return "noncompliant"; return s; };
const gk = (v) => { const s = lc(v); if (!s) return null; if (/off|disabled|anywhere|^no$|false/.test(s)) return false; if (/app ?store|identified|enabled|on|^yes$|true/.test(s)) return true; return null; };
const fv = (v) => { const s = lc(v).replace(/_/g, " "); if (!s) return null; if (/^(all|boot) (partitions )?encrypted|^encrypted|fully encrypted|^yes$|^true$/.test(s)) return true; if (/not encrypted|no partitions|unencrypted|^no$|^false$|decrypted|some encrypted|partially/.test(s)) return false; return null; };
const sb = (v) => { const s = lc(v).replace(/_/g, " "); if (!s || /not supported|unknown|not collected/.test(s)) return null; if (/^off|no security|disabled|^no$|false/.test(s)) return false; if (/full|medium|on|enabled|^yes$|true/.test(s)) return true; return null; };

function blank(src, format, row) {
  const f = FORMATS[format] || FORMATS.generic;
  return { src, format, kind: f.kind, vendor: f.vendor, name: "", host: "", serial: "", ids: [], mac: "", user: "", os: "", osVersion: "", family: "", model: "",
    lastSeen: null, encrypted: null, compliance: null, managed: null, enabled: null, edrIssues: [], edrReported: null, sensorVersion: "", localAdmins: null, primaryAdmin: null,
    firewall: null, gatekeeper: null, sip: null, jailbroken: null, screenLock: null, secureBoot: null, recoveryLock: null, activationLock: null, guest: null,
    autoUpdates: null, manyAdmins: null, aue: null, darwin: false, joinType: "", raw: row };
}
function finish(d) {
  d.host = normHost(d.name);
  d.serial = normSerial(d.serial);
  d.ids = uniqSorted(d.ids.map(normId));
  d.mac = normMac(d.mac);
  d.family = osFamily(d.os, d.osVersion);
  d.user = lc(d.user);
  return d;
}

/** Map one raw vendor row to a device record (or null). `cols` = mapped generic columns. */
export function normalizeDevice(format, row, src, cols) {
  const d = blank(src, format, row);
  switch (format) {
    case "intune-devices":
      d.name = pick(row, "Device name"); d.serial = pick(row, "Serial number"); d.ids = [pick(row, "Device ID"), pick(row, "Azure AD Device ID")];
      d.mac = pick(row, "Wi-Fi MAC"); d.user = pick(row, "Primary user UPN"); d.os = pick(row, "OS"); d.osVersion = pick(row, "OS version"); d.model = pick(row, "Model");
      d.lastSeen = parseTs(pick(row, "Last check-in")); d.encrypted = parseBool(pick(row, "Encrypted")); d.compliance = compliance(pick(row, "Compliance"));
      d.managed = pick(row, "Managed by") ? !/^(none|unmanaged|unknown)$/i.test(pick(row, "Managed by")) : null; d.jailbroken = parseBool(pick(row, "Jailbroken")); d.joinType = pick(row, "Join type");
      break;
    case "intune-encryption": {
      d.name = pick(row, "Device name"); d.os = pick(row, "OS"); d.osVersion = pick(row, "OS version"); d.user = pick(row, "UPN");
      const s = lc(pick(row, "Encryption status")); d.encrypted = /^encrypted$/.test(s) ? true : /not encrypted|unencrypted/.test(s) ? false : null;
      break;
    }
    case "graph-managed":
      d.name = str(row.deviceName); d.serial = str(row.serialNumber); d.ids = [str(row.id), str(row.azureADDeviceId)]; d.user = str(row.userPrincipalName);
      d.os = str(row.operatingSystem); d.osVersion = str(row.osVersion); d.model = str(row.model); d.lastSeen = parseTs(row.lastSyncDateTime);
      d.encrypted = typeof row.isEncrypted === "boolean" ? row.isEncrypted : parseBool(row.isEncrypted); d.compliance = compliance(row.complianceState);
      d.managed = row.managementAgent ? !/^unknown$/i.test(str(row.managementAgent)) : null; d.jailbroken = parseBool(row.jailBroken); d.mac = str(row.wiFiMacAddress);
      break;
    case "jamf-computers":
      d.name = pick(row, "Computer Name"); d.serial = pick(row, "Serial Number"); d.mac = pick(row, "MAC Address"); d.user = pick(row, "Email Address", "Username");
      d.os = "macOS"; d.osVersion = pick(row, "Operating System Version"); d.model = pick(row, "Model"); d.lastSeen = parseTs(pick(row, "Last Check-in"));
      d.encrypted = fv(pick(row, "FileVault 2 Status")); d.gatekeeper = gk(pick(row, "Gatekeeper")); d.sip = parseBool(pick(row, "System Integrity Protection"));
      d.firewall = parseBool(pick(row, "Firewall Enabled")); d.managed = parseBool(pick(row, "Managed")); d.recoveryLock = parseBool(pick(row, "Recovery Lock Enabled"));
      d.secureBoot = sb(pick(row, "Secure Boot Level")); d.activationLock = parseBool(pick(row, "Activation Lock"));
      break;
    case "jamf-api": {
      const g = row.general || {}, h = row.hardware || {}, o = row.operatingSystem || {}, s = row.security || {}, u = row.userAndLocation || {};
      d.name = str(g.name); d.serial = str(h.serialNumber); d.mac = str(h.macAddress); d.model = str(h.model); d.os = "macOS"; d.osVersion = str(o.version);
      d.user = str(u.email || u.username); d.lastSeen = parseTs(g.lastContactTime); d.encrypted = fv(o.fileVault2Status);
      d.sip = s.sipStatus ? /^enabled$/i.test(s.sipStatus) ? true : /^disabled$/i.test(s.sipStatus) ? false : null : null;
      d.gatekeeper = gk(s.gatekeeperStatus); d.firewall = typeof s.firewallEnabled === "boolean" ? s.firewallEnabled : parseBool(s.firewallEnabled);
      d.activationLock = typeof s.activationLockEnabled === "boolean" ? s.activationLockEnabled : parseBool(s.activationLockEnabled); d.secureBoot = sb(s.secureBootLevel);
      d.managed = g.mdmCapable && typeof g.mdmCapable === "object" && "capable" in g.mdmCapable ? !!g.mdmCapable.capable : typeof g.mdmCapable === "boolean" ? g.mdmCapable : null;
      if (Array.isArray(row.localUserAccounts)) {
        const admins = row.localUserAccounts.filter((a) => a && a.admin === true);
        d.localAdmins = admins.length;
        const pu = lc(u.username);
        d.primaryAdmin = pu ? admins.some((a) => lc(a.username) === pu) : null;
      }
      d.raw = { name: d.name, serialNumber: d.serial, lastContactTime: str(g.lastContactTime), version: d.osVersion, fileVault2Status: str(o.fileVault2Status), sipStatus: str(s.sipStatus), gatekeeperStatus: str(s.gatekeeperStatus), firewallEnabled: s.firewallEnabled, username: str(u.username), localAdmins: d.localAdmins };
      break;
    }
    case "crowdstrike": {
      d.name = pick(row, "Hostname"); d.ids = [pick(row, "Host ID")]; d.serial = pick(row, "Serial Number"); d.mac = pick(row, "MAC Address");
      d.os = pick(row, "OS Version", "OS", "Platform"); d.osVersion = pick(row, "OS Version"); d.lastSeen = parseTs(pick(row, "Last Seen")); d.sensorVersion = pick(row, "Sensor Version");
      d.edrReported = true;
      if (parseBool(pick(row, "RFM (Reduced Functionality Mode)")) === true) d.edrIssues.push("CrowdStrike sensor in Reduced Functionality Mode");
      const st = lc(pick(row, "Agent Status"));
      if (st && !/^(normal|online|ok|healthy|offline)$/.test(st)) d.edrIssues.push("CrowdStrike agent status: " + pick(row, "Agent Status"));
      break;
    }
    case "defender-devices": {
      d.name = pick(row, "Device name"); d.ids = [pick(row, "Device ID")]; d.os = pick(row, "OS platform"); d.osVersion = [pick(row, "OS version"), pick(row, "Windows version")].filter(Boolean).join(" ");
      d.lastSeen = parseTs(pick(row, "Last device update")); d.edrReported = true;
      const ob = pick(row, "Onboarding status"), sh = pick(row, "Sensor health state"), av = pick(row, "Defender AV status");
      if (ob && !/^onboarded$/i.test(ob)) { d.edrIssues.push("Defender onboarding status: " + ob); d.edrReported = false; }
      if (sh && !/^active$/i.test(sh) && /^onboarded$/i.test(ob || "onboarded")) d.edrIssues.push("Defender sensor health: " + sh);
      if (av && !/^(updated|up to date)$/i.test(av) && /^onboarded$/i.test(ob || "onboarded")) d.edrIssues.push("Defender AV status: " + av);
      break;
    }
    case "defender-deviceinfo": {
      d.name = pick(row, "DeviceName"); d.ids = [pick(row, "DeviceId")]; d.os = pick(row, "OSPlatform");
      const b = pick(row, "OSBuild"), v = pick(row, "OSVersion");
      d.osVersion = b && /^\d+\.\d+$/.test(v) ? v + "." + b : v || b; d.lastSeen = parseTs(pick(row, "Timestamp")); d.edrReported = true;
      const ob = pick(row, "OnboardingStatus"), sh = pick(row, "SensorHealthState");
      if (ob && !/^onboarded$/i.test(ob)) { d.edrIssues.push("Defender onboarding status: " + ob); d.edrReported = false; }
      if (sh && !/^active$/i.test(sh) && (!ob || /^onboarded$/i.test(ob))) d.edrIssues.push("Defender sensor health: " + sh);
      try { const lu = JSON.parse(pick(row, "LoggedOnUsers") || "[]"); if (Array.isArray(lu) && lu[0] && lu[0].UserName) d.user = str(lu[0].UserName); } catch (_) { /* free text */ }
      break;
    }
    case "google-endpoints": {
      d.name = pick(row, "Name"); d.user = pick(row, "Owner"); d.os = pick(row, "OS", "Type"); d.osVersion = pick(row, "OS Version"); d.lastSeen = parseTs(pick(row, "Last Sync"));
      d.ids = [pick(row, "Device Id")]; d.model = pick(row, "Model"); d.serial = pick(row, "Serial Number");
      const e = lc(pick(row, "Encryption Status")); d.encrypted = /^encrypted|^yes/.test(e) ? true : /unencrypted|not encrypted|^no/.test(e) ? false : null;
      const p = lc(pick(row, "Password Status")); d.screenLock = /no password|not set|^none|^off|^no$/.test(p) ? false : /set|^on|enabled|^yes/.test(p) ? true : null;
      const c = lc(pick(row, "Compromised")); d.jailbroken = /^(compromised|yes|true)$/.test(c) ? true : /not|^no|false/.test(c) ? false : null;
      const m = lc(pick(row, "Managed Type")); d.managed = m ? !/unmanaged|none/.test(m) : null;
      break;
    }
    case "chromeos":
      d.serial = pick(row, "Serial Number"); d.name = d.serial; d.user = pick(row, "User"); d.os = "ChromeOS"; d.osVersion = pick(row, "OS Version");
      d.lastSeen = parseTs(pick(row, "Last Sync")); d.model = pick(row, "Model"); d.aue = parseMonthEnd(pick(row, "Auto-update Expiration")); d.managed = true;
      break;
    case "entra-devices": {
      d.name = pick(row, "Name"); d.enabled = parseBool(pick(row, "Enabled")); d.os = pick(row, "Operating system"); d.osVersion = pick(row, "Version");
      d.user = pick(row, "Owner"); d.ids = [pick(row, "Device ID"), pick(row, "Object ID")]; d.lastSeen = parseTs(pick(row, "Activity (last sign-in)", "Activity"));
      const mdm = pick(row, "MDM"); d.managed = mdm && !/^(none|n\/a)$/i.test(mdm) ? true : false;
      const c = lc(pick(row, "Compliant")); d.compliance = c === "yes" ? "compliant" : c === "no" ? "noncompliant" : null; d.joinType = pick(row, "Join type");
      break;
    }
    case "okta-devices": {
      d.name = pick(row, "Device name"); d.os = pick(row, "Platform"); d.osVersion = pick(row, "OS version"); d.serial = pick(row, "Serial number"); d.user = pick(row, "User");
      d.lastSeen = parseTs(pick(row, "Last seen")); d.enabled = /^active$/i.test(pick(row, "Status")) ? true : pick(row, "Status") ? false : null;
      const m = lc(pick(row, "Management status")); d.managed = m ? /^managed$/.test(m) : null;
      break;
    }
    case "ad-computers": {
      d.name = pick(row, "Name", "DNSHostName"); d.os = pick(row, "OperatingSystem");
      const v = pick(row, "OperatingSystemVersion"), m = v.match(/(\d+\.\d+)\s*\((\d+)\)/); d.osVersion = m ? m[1] + "." + m[2] : v;
      d.lastSeen = parseTs(pick(row, "LastLogonDate")); d.enabled = parseBool(pick(row, "Enabled"));
      break;
    }
    case "generic": {
      const c = cols || {};
      const g = (k) => (c[k] ? str(row[c[k]]) : "");
      d.name = g("hostname"); d.serial = g("serial"); d.os = g("os"); d.osVersion = g("osVersion"); d.user = g("user"); d.lastSeen = parseTs(g("lastSeen"));
      d.encrypted = c.encrypted ? parseBool(g("encrypted")) : null; d.firewall = c.firewall ? parseBool(g("firewall")) : null; d.model = g("model"); d.mac = g("mac"); d.ids = [g("deviceId")];
      if (c.edr) { const e = g("edr"); const b = parseBool(e); d.edrReported = b === null ? (e ? true : false) : b; }
      if (c.localAdmin) { const a = g("localAdmin"); if (/^\d+$/.test(a)) d.localAdmins = Number(a); else d.primaryAdmin = parseBool(a); }
      break;
    }
    default: return null;
  }
  finish(d);
  return d.host || d.serial || d.ids.length || d.mac ? d : null;
}

const AUDIT_MAP = { "disk-encryption": "encrypted", firewall: "firewall", "screen-lock": "screenLock", "password-policy": "screenLock", gatekeeper: "gatekeeper", sip: "sip", "secure-boot": "secureBoot", "guest-account": "guest", "auto-updates": "autoUpdates", "local-admin": "primaryAdmin", "admin-count": "manyAdmins" };

/** Workstation Audit fleet record -> device record. */
export function normalizeAudit(rec, src) {
  const d = blank(src, "dn-audit", null);
  let checks;
  if (rec.tool === "darknode-app") {
    const h = rec.host || {};
    d.name = str(h.hostname); d.os = str(h.os); d.osVersion = str(h.osVersion); d.serial = str(h.serial); d.user = str(h.user);
    d.lastSeen = parseTs(rec.collectedAt); checks = rec.checks || [];
  } else {
    d.name = str(rec.host); const os = str(rec.os);
    const m = os.match(/^(macOS|Windows|Linux|\S+)\s+(.*)$/);
    d.os = m ? m[1] : os; d.osVersion = m ? m[2] : "";
    if (/^macos$/i.test(d.os)) d.darwin = true;   // the app reports os.release(), i.e. the Darwin kernel version
    d.lastSeen = parseTs(rec.generated); checks = rec.results || [];
  }
  const out = [];
  for (const c of checks) {
    const id = str(c.id), st = lc(c.status), field = AUDIT_MAP[id];
    const v = st === "pass" ? true : st === "fail" || st === "warn" ? false : null;
    out.push({ id, status: st, severity: str(c.severity), cisRef: str(c.cisRef) });
    if (v === null) continue;
    if (field === "primaryAdmin") d.primaryAdmin = !v;            // local-admin fail = primary user is admin
    else if (field === "manyAdmins") d.manyAdmins = !v;           // admin-count fail = too many admin accounts
    else if (field === "guest") d.guest = !v;                     // guest-account fail = guest enabled
    else if (field) d[field] = d[field] === false ? false : v;    // screen-lock + password-policy both feed screenLock
    if ((id === "defender" || id === "edr") && v === false) d.edrIssues.push("Workstation Audit: " + (id === "defender" ? "Microsoft Defender real-time protection off" : "no endpoint protection agent found") + " (" + st + ")");
  }
  d.raw = { host: d.name, os: str(rec.os && rec.os.os ? rec.os.os : rec.os || (rec.host && rec.host.os)), generated: str(rec.generated || rec.collectedAt), appVersion: str(rec.appVersion || rec.version), score: rec.score && rec.score.percent != null ? rec.score.percent : "", checks: out.map((c) => c.id + "=" + c.status).join(" ") };
  finish(d);
  return d.host || d.serial ? d : null;
}

/** Software rows from one raw row: { host, serial, name, version, publisher, src }. */
export function normalizeSoftware(format, row, src) {
  const m = {
    "intune-apps": ["Device name", "App name", "App version", "Publisher"],
    "sccm-software": ["Computer Name", "Product Name", "Product Version", "Publisher"],
    lansweeper: ["AssetName", "Software", "Version", "Publisher"],
    "kandji-apps": ["Device Name", "App Name", "Version", ""],
    "jamf-apps": ["Computer Name", "Application Title", "Application Version", ""],
  }[format];
  if (!m) return null;
  const name = pick(row, m[1], format === "kandji-apps" ? "Name" : m[1]);
  const host = normHost(pick(row, m[0]));
  if (!name || !(host || pick(row, "Serial Number"))) return null;
  return { src, host, serial: format === "kandji-apps" ? normSerial(pick(row, "Serial Number")) : "", name, version: pick(row, m[2]), publisher: m[3] ? pick(row, m[3]) : "" };
}

// ---------------------------------------------------------------------------
// parseInput: files -> sources with normalised device + software records
// ---------------------------------------------------------------------------
/** Logical generic columns resolved against headers, with per-file overrides. */
export function genericColumns(headers, override) {
  const cols = {};
  for (const k of Object.keys(COLUMNS)) {
    const ov = override && override[k];
    if (ov && headers.includes(ov)) { cols[k] = ov; continue; }
    const h = findColumn(headers, COLUMNS[k]);
    if (h) cols[k] = h;
  }
  return cols;
}

function toFiles(input) {
  if (input == null) return [];
  if (typeof input === "string") return [{ name: "input", text: input }];
  const list = Array.isArray(input) ? input : [input];
  return list.map((f, i) => (typeof f === "string" ? { name: "file " + (i + 1), text: f } : { name: str(f && f.name) || "file " + (i + 1), text: String((f && f.text) || "") }));
}

/**
 * Parse one or more files ({name,text}[] or a single text). Never throws.
 * opts.treatAs { fileName: format } forces a format; opts.columns { fileName: { key: header } } maps generic CSV.
 * Returns { sources: [{ name, format, kind, vendor, label, confidence, headers, columns, rows, devices, software }], skipped }.
 */
export function parseInput(input, opts = {}, ctx) {
  const files = toFiles(input);
  const sources = [], skipped = [];
  const treatAs = (opts && opts.treatAs) || {}, colMap = (opts && opts.columns) || {};
  files.forEach((file, fi) => {
    ctx?.progress?.(fi, files.length, "parsing " + file.name);
    const text = file.text.replace(/^﻿/, "");
    if (!text.trim()) { skipped.push({ check: "parse", reason: file.name + ": empty file" }); return; }
    const src = sources.length;
    const det = detectFile({ name: file.name, text });
    let format = treatAs[file.name] && FORMATS[treatAs[file.name]] ? treatAs[file.name] : det.format;
    const confidence = treatAs[file.name] ? "high" : det.confidence;
    const s = { name: file.name, format, kind: "", vendor: "", label: "", confidence, headers: det.headers, columns: {}, rows: 0, devices: [], software: [] };
    let raw = [];
    if (format === "dn-audit" || format === "jamf-api" || format === "graph-managed") {
      const v = loadJson(text); const c = v === undefined ? null : classifyJson(v);
      if (!c) { skipped.push({ check: "parse", reason: file.name + ": not a recognised JSON export" }); return; }
      if (!treatAs[file.name]) format = c.format;
      raw = c.records;
    } else if (format === "unknown-json" || format === "empty") {
      skipped.push({ check: "parse", reason: file.name + ": JSON shape not recognised (expected Workstation Audit fleet record, Jamf computers-inventory or Graph managedDevices)" }); return;
    } else {
      const p = parseCsv(text); raw = p.rows; s.headers = p.headers;
    }
    const f = FORMATS[format] || FORMATS.generic;
    s.format = format; s.kind = f.kind; s.vendor = f.vendor; s.label = f.label; s.rows = raw.length;
    if (format === "generic") {
      s.columns = genericColumns(s.headers, colMap[file.name]);
      if (!s.columns.hostname && !s.columns.serial) { skipped.push({ check: "parse", reason: file.name + ": no hostname or serial column could be mapped; map the columns to include it" }); s.unusable = true; }
    }
    const seen = new Map();
    for (let i = 0; i < raw.length; i++) {
      if (i % 1000 === 0 && i) ctx?.progress?.(fi, files.length, file.name + ": " + i + " rows");
      const row = raw[i];
      if (!row || typeof row !== "object" || s.unusable) continue;
      if (f.kind === "software") { const sw = normalizeSoftware(format, row, src); if (sw) s.software.push(sw); continue; }
      const d = format === "dn-audit" ? normalizeAudit(row, src) : normalizeDevice(format, row, src, s.columns);
      if (!d) continue;
      d.row = i;
      // Repeated rows for the same device inside one export (hunting tables): keep the newest.
      const k = d.serial + "|" + d.host + "|" + (d.ids[0] || "");
      const prev = seen.get(k);
      if (prev == null) { seen.set(k, s.devices.length); s.devices.push(d); }
      else if ((d.lastSeen || 0) > (s.devices[prev].lastSeen || 0)) { d.row = s.devices[prev].row; s.devices[prev] = d; }
    }
    if (!s.devices.length && !s.software.length) skipped.push({ check: "parse", reason: file.name + ": no device or software rows recognised" });
    sources.push(s);
  });
  ctx?.progress?.(files.length, files.length, "parsed");
  return { sources, skipped };
}

// ---------------------------------------------------------------------------
// Cross-source matching
// ---------------------------------------------------------------------------
const KIND_ORDER = { mdm: 0, encryption: 1, edr: 2, directory: 3, audit: 4, generic: 5, software: 6 };

/**
 * Group device records into physical devices. Serial first, then hostname, then
 * device id, then MAC; a key never joins records whose serials disagree.
 * Returns { groups: [{ recs }], groupOf: Map(record -> group), conflicts: [{ key, value, serials, sources }] }.
 */
export function matchDevices(records) {
  const recs = records.slice().sort((a, b) => (b.serial ? 1 : 0) - (a.serial ? 1 : 0) || KIND_ORDER[a.kind] - KIND_ORDER[b.kind] || a.src - b.src || (a.row || 0) - (b.row || 0));
  const groups = [], idx = { serial: new Map(), host: new Map(), id: new Map(), mac: new Map() };
  const conflicts = new Map();
  const groupOf = new Map();
  const ok = (g, r) => !(r.serial && g.serials.size && !g.serials.has(r.serial));
  for (const r of recs) {
    let g = r.serial ? idx.serial.get(r.serial) : null;
    if (!g) {
      const tries = [["host", [r.host]], ["id", r.ids], ["mac", [r.mac]]];
      outer: for (const [k, vals] of tries) {
        for (const v of vals) {
          if (!v) continue;
          const c = idx[k].get(v);
          if (!c) continue;
          if (ok(c, r)) { g = c; break outer; }
          const ck = k + "|" + v;
          const e = conflicts.get(ck) || { key: k === "host" ? "hostname" : k === "id" ? "device id" : "mac", value: v, serials: new Set(), groups: new Set() };
          for (const s of c.serials) e.serials.add(s);
          e.serials.add(r.serial); e.groups.add(c);
          conflicts.set(ck, e);
        }
      }
    }
    if (!g) { g = { recs: [], serials: new Set(), hosts: new Set(), ids: new Set(), macs: new Set() }; groups.push(g); }
    g.recs.push(r);
    if (r.serial) { g.serials.add(r.serial); if (!idx.serial.has(r.serial)) idx.serial.set(r.serial, g); }
    if (r.host) { g.hosts.add(r.host); if (!idx.host.has(r.host)) idx.host.set(r.host, g); }
    for (const v of r.ids) { g.ids.add(v); if (!idx.id.has(v)) idx.id.set(v, g); }
    if (r.mac) { g.macs.add(r.mac); if (!idx.mac.has(r.mac)) idx.mac.set(r.mac, g); }
    groupOf.set(r, g);
  }
  return { groups, groupOf, conflicts: [...conflicts.values()].map((c) => ({ key: c.key, value: c.value, serials: uniqSorted([...c.serials]) })).sort((a, b) => cmp(a.key + a.value, b.key + b.value)) };
}

const PRIORITY = { mdm: 0, directory: 1, edr: 2, audit: 3, encryption: 4, generic: 5 };
const byPriority = (recs) => recs.slice().sort((a, b) => PRIORITY[a.kind] - PRIORITY[b.kind] || a.src - b.src || (a.row || 0) - (b.row || 0));
const first = (recs, f) => { for (const r of recs) { const v = r[f]; if (v != null && v !== "") return v; } return ""; };
const tri = (recs, f) => { let t = null; for (const r of recs) { if (r[f] === false) return false; if (r[f] === true) t = true; } return t; };
const anyTrue = (recs, f) => { let t = null; for (const r of recs) { if (r[f] === true) return true; if (r[f] === false) t = false; } return t; };
const maxOf = (recs, f, pred) => { let m = null; for (const r of recs) if ((!pred || pred(r)) && r[f] != null && (m == null || r[f] > m)) m = r[f]; return m; };

/** Merge one group into a register row (pre-checks). */
export function mergeDevice(g, sources) {
  const recs = byPriority(g.recs);
  const osRec = recs.find((r) => r.family && r.family !== "other" && /\d/.test(r.osVersion)) || recs.find((r) => r.family) || recs[0];
  const kinds = new Set(recs.map((r) => r.kind));
  const comp = recs.map((r) => r.compliance).filter(Boolean);
  const d = {
    key: "", name: first(recs, "name") || first(recs, "serial"), serial: [...g.serials].sort(cmp)[0] || "", serials: [...g.serials].sort(cmp), hosts: [...g.hosts].sort(cmp),
    os: osRec ? osRec.os : "", osVersion: osRec ? osRec.osVersion : "", family: osRec ? osRec.family : "", darwin: !!(osRec && osRec.darwin), aue: maxOf(recs, "aue"),
    model: first(recs, "model"), user: first(recs, "user"),
    sources: uniqSorted(recs.map((r) => sources[r.src].format)), files: uniqSorted(recs.map((r) => sources[r.src].name)), kinds: [...kinds].sort(cmp),
    lastSeen: maxOf(recs, "lastSeen"), mdmLast: maxOf(recs, "lastSeen", (r) => r.kind === "mdm"), edrLast: maxOf(recs, "lastSeen", (r) => r.kind === "edr"),
    encrypted: tri(recs, "encrypted"), firewall: tri(recs, "firewall"), screenLock: tri(recs, "screenLock"), gatekeeper: tri(recs, "gatekeeper"), sip: tri(recs, "sip"),
    secureBoot: tri(recs, "secureBoot"), recoveryLock: tri(recs, "recoveryLock"), activationLock: tri(recs, "activationLock"), autoUpdates: tri(recs, "autoUpdates"),
    jailbroken: anyTrue(recs, "jailbroken"), guest: anyTrue(recs, "guest"), manyAdmins: anyTrue(recs, "manyAdmins"), primaryAdmin: anyTrue(recs, "primaryAdmin"),
    localAdmins: maxOf(recs, "localAdmins"), enabled: anyTrue(recs, "enabled"),
    hasEdr: recs.some((r) => r.edrReported === true), edrNo: recs.some((r) => r.edrReported === false) && !recs.some((r) => r.edrReported === true),
    edrIssues: uniqSorted(recs.flatMap((r) => r.edrIssues)), sensorVersion: first(recs.filter((r) => r.format === "crowdstrike"), "sensorVersion"),
    compliance: comp.includes("noncompliant") ? "noncompliant" : comp.includes("not evaluated") ? "not evaluated" : comp.includes("in grace period") ? "in grace period" : comp.length ? comp[0] : null,
    managed: kinds.has("mdm") ? true : recs.some((r) => r.managed === false) ? false : recs.some((r) => r.managed === true) ? true : null,
    managedEvidence: recs.filter((r) => r.managed === false).map((r) => sources[r.src].format + (r.joinType ? " (" + r.joinType + ")" : "")),
    joinType: first(recs, "joinType"), recs,
  };
  d.laptop = LAPTOP_RE.test(d.model) || (d.family === "macos" && /macbook/i.test(d.name));
  d.key = d.serial ? "serial:" + d.serial : d.hosts[0] ? "host:" + d.hosts[0] : "id:" + ([...g.ids].sort(cmp)[0] || [...g.macs].sort(cmp)[0] || "");
  return d;
}

// ---------------------------------------------------------------------------
// Detections
// ---------------------------------------------------------------------------
const C = (framework, id) => ({ framework, id });
const CIS = (id) => C("CIS Controls v8", id), ISO = (id) => C("ISO27001", id), NIST = (id) => C("NIST-800-53", id), PCI = (id) => C("PCI DSS 4.0.1", id), MITRE = (id) => C("MITRE", id);

/** Every check: id, severity, confidence, controls, recommendation and the data it needs. */
export const DETECTIONS = [
  { id: "encryption_laptop", flag: "encryption", title: "Laptops without disk encryption", severity: "critical", confidence: "confirmed", category: "encryption", controls: [CIS("3.6"), ISO("A.8.1"), NIST("SC-28")], needs: "Intune Encrypted / Encryption report, Graph isEncrypted, Jamf FileVault 2 Status, Google Encryption Status or Workstation Audit disk-encryption", rec: "Enforce BitLocker / FileVault through MDM policy, escrow the recovery key, and confirm the device reports encrypted at the next check-in. A lost unencrypted laptop is a reportable data breach in most regimes." },
  { id: "encryption", flag: "encryption", title: "Devices without disk encryption", severity: "high", confidence: "confirmed", category: "encryption", controls: [CIS("3.6"), ISO("A.8.1"), NIST("SC-28")], needs: "as above", rec: "Enable full-disk encryption through MDM policy and escrow the recovery key." },
  { id: "edr_missing", title: "Devices in MDM or the directory with no EDR sensor", severity: "high", confidence: "likely", category: "edr", controls: [CIS("10.1"), CIS("13.7"), ISO("A.8.7"), NIST("SI-3"), PCI("5.2"), MITRE("T1486")], needs: "an EDR export (CrowdStrike / Defender) plus an MDM or directory export", rec: "Deploy the EDR sensor to every listed device (MDM app assignment), then re-export both inventories to confirm. Devices no longer in use should be retired from MDM / the directory instead." },
  { id: "edr_unhealthy", title: "EDR sensors unhealthy, in reduced functionality or not onboarded", severity: "high", confidence: "confirmed", category: "edr", controls: [CIS("10.1"), PCI("5.3"), NIST("SI-3"), MITRE("T1562.001")], needs: "CrowdStrike RFM / Agent Status, Defender Onboarding / Sensor health / AV status, or Workstation Audit defender check", rec: "RFM usually means the sensor does not support the running kernel or OS build: update the sensor or the OS. Re-onboard Defender devices and fix sensor connectivity (proxy / service state). Treat tampering as an incident (T1562.001)." },
  { id: "edr_stale", title: "EDR sensor silent while the device still checks in to MDM", severity: "medium", confidence: "likely", category: "edr", controls: [CIS("10.1"), PCI("5.3"), MITRE("T1562.001")], needs: "EDR last seen plus MDM last check-in", rec: "A device that reaches MDM but not the EDR cloud often has a stopped, uninstalled or blocked sensor. Check the sensor service on each device." },
  { id: "sensor_behind", title: "EDR sensor versions behind the fleet", severity: "info", confidence: "confirmed", category: "edr", controls: [CIS("10.2"), PCI("5.3")], needs: "CrowdStrike Sensor Version", rec: "Move these hosts to the fleet's sensor update policy so they stay within N-1 / N-2 of the current build." },
  { id: "os_eol", title: "End-of-life operating systems", severity: "critical", confidence: "confirmed", category: "eol", controls: [CIS("2.2"), CIS("7.3"), ISO("A.8.8"), NIST("SI-2"), PCI("6.3.3"), MITRE("T1486")], needs: "OS name + version or build and the mirrored EOL feed", rec: "Upgrade or replace these devices. Until then isolate them from sensitive networks; end-of-life systems receive no security fixes." },
  { id: "os_eol_soon", flag: "os_eol_soon", title: "Operating systems reaching end of life soon", severity: "medium", confidence: "confirmed", category: "eol", controls: [CIS("2.2"), CIS("7.3"), ISO("A.8.8"), NIST("SI-2")], needs: "as above", rec: "Schedule the upgrade before the end-of-life date shown in the evidence." },
  { id: "app_eol", title: "End-of-life browsers and runtimes installed", severity: "high", confidence: "confirmed", category: "eol", controls: [CIS("2.2"), CIS("7.4"), ISO("A.8.8"), NIST("SI-2"), PCI("6.3.3")], needs: "a software inventory (Intune Discovered apps, SCCM, Lansweeper, Kandji, Jamf apps) and the mirrored EOL feed", rec: "Update or remove these versions. Browsers should auto-update; an out-of-cycle browser usually means updates are blocked by policy or a stale per-user install." },
  { id: "patch_behind", title: "OS patch level behind the rest of the fleet", severity: "medium", confidence: "likely", category: "patching", controls: [CIS("7.3"), ISO("A.8.8"), NIST("SI-2"), PCI("6.3.3")], needs: "comparable OS versions (Windows build.revision, macOS / iOS versions) on two or more devices, or Workstation Audit auto-updates", rec: "Push the pending cumulative / point update and check why these devices did not take it (deferral ring, update service, low disk). Ahead-of-fleet is measured against the newest build seen in your own data, not against the vendor's latest." },
  { id: "stale_enabled", title: "Devices silent for months with an enabled directory account", severity: "high", confidence: "likely", category: "inventory", controls: [CIS("1.1"), CIS("1.2"), ISO("A.8.1"), NIST("CM-8")], needs: "last check-in plus directory Enabled", rec: "Confirm with the owner whether the device is lost; if so wipe it and disable the directory object. Enabled stale computer objects can still authenticate." },
  { id: "stale", title: "Devices not seen recently in any source", severity: "medium", confidence: "likely", category: "inventory", controls: [CIS("1.1"), ISO("A.8.1"), NIST("CM-8")], needs: "a last check-in / last seen column", rec: "Contact the owner. Retire devices that are no longer used so the inventory stays accurate." },
  { id: "local_admin", title: "Primary user is a local administrator", severity: "high", confidence: "confirmed", category: "privilege", controls: [CIS("5.4"), NIST("AC-6"), MITRE("T1078.003")], needs: "Jamf computers-inventory localUserAccounts, Workstation Audit local-admin or a mapped localAdmin column", rec: "Remove standing admin rights and use just-in-time elevation (Jamf / Intune Endpoint Privilege Management, LAPS for break-glass)." },
  { id: "many_admins", title: "More local administrator accounts than the baseline allows", severity: "medium", confidence: "confirmed", category: "privilege", controls: [CIS("5.4"), NIST("AC-6"), MITRE("T1078.003")], needs: "Jamf localUserAccounts, Workstation Audit admin-count or a numeric localAdmin column", rec: "Remove unneeded admin accounts; keep one managed (LAPS-rotated) administrator." },
  { id: "jailbroken", title: "Jailbroken or compromised devices", severity: "critical", confidence: "confirmed", category: "integrity", controls: [CIS("4.1"), ISO("A.8.1")], needs: "Intune Jailbroken / Graph jailBroken or Google Compromised", rec: "Block the device with Conditional Access / context-aware access, revoke its sessions and wipe it." },
  { id: "gatekeeper_sip", title: "macOS Gatekeeper or System Integrity Protection disabled", severity: "high", confidence: "confirmed", category: "integrity", controls: [CIS("4.1"), CIS("10.5"), ISO("A.8.9"), MITRE("T1562.001")], needs: "Jamf Gatekeeper / System Integrity Protection or Workstation Audit", rec: "Re-enable SIP from recovery (csrutil enable) and Gatekeeper (spctl --master-enable); investigate why they were turned off." },
  { id: "firewall", title: "Host firewall off", severity: "medium", confidence: "confirmed", category: "configuration", controls: [CIS("4.5"), ISO("A.8.9")], needs: "Jamf Firewall Enabled, Workstation Audit firewall or a mapped firewall column", rec: "Enable the host firewall through an MDM configuration profile / Intune endpoint security policy." },
  { id: "screen_lock", title: "Screen lock or password policy failing", severity: "medium", confidence: "confirmed", category: "configuration", controls: [CIS("4.3"), ISO("A.8.1")], needs: "Google Password Status or Workstation Audit screen-lock / password-policy", rec: "Enforce a device passcode and an idle lock of 15 minutes or less through MDM." },
  { id: "guest_account", title: "Guest account enabled", severity: "medium", confidence: "confirmed", category: "configuration", controls: [CIS("4.7"), MITRE("T1078.001")], needs: "Workstation Audit guest-account", rec: "Disable the guest / default account by MDM policy." },
  { id: "noncompliant", title: "Devices non-compliant or not evaluated", severity: "medium", confidence: "confirmed", category: "compliance", controls: [CIS("4.1"), ISO("A.8.9"), NIST("CM-6")], needs: "Intune Compliance / Graph complianceState or Entra Compliant", rec: "Open each device's compliance detail in Intune and fix the failing setting. 'Not evaluated' usually means no compliance policy is assigned: assign one." },
  { id: "unmanaged", title: "Devices in the directory or Google with no MDM management", severity: "high", confidence: "likely", category: "inventory", controls: [CIS("1.1"), CIS("1.2"), ISO("A.8.1"), NIST("CM-8")], needs: "Entra MDM column, Okta Management status or Google Managed Type, and no matching MDM record", rec: "Enrol the device in MDM or block it with Conditional Access (require compliant device). Personal 'registered' devices should be limited to app-protected access." },
  { id: "secure_boot", title: "Secure Boot off", severity: "low", confidence: "confirmed", category: "configuration", controls: [CIS("4.1"), ISO("A.8.9")], needs: "Jamf Secure Boot Level or Workstation Audit secure-boot", rec: "Enable Secure Boot (Full Security on Apple silicon / T2 Macs, UEFI Secure Boot on PCs)." },
  { id: "activation_lock", title: "Laptops without Activation Lock", severity: "low", confidence: "confirmed", category: "configuration", controls: [CIS("4.1"), ISO("A.8.1")], needs: "Jamf Activation Lock", rec: "Enable MDM-managed Activation Lock so a stolen Mac cannot be reactivated." },
  { id: "recovery_lock", title: "Macs without Recovery Lock", severity: "info", confidence: "confirmed", category: "configuration", controls: [CIS("4.1")], needs: "Jamf Recovery Lock Enabled", rec: "Set a managed Recovery Lock password on Apple silicon Macs." },
  { id: "blocklist", title: "Unauthorized software installed", severity: "high", confidence: "confirmed", category: "software", controls: [CIS("2.3"), CIS("2.1"), ISO("A.8.19"), NIST("CM-7")], needs: "a software inventory and a blocklist entry", rec: "Uninstall from the listed devices and block the installer with application control (WDAC / AppLocker / Santa)." },
  { id: "remote_access", title: "Remote-access and tunnelling tools installed (review)", severity: "medium", confidence: "review", category: "software", controls: [CIS("2.3"), ISO("A.8.19"), MITRE("T1219")], needs: "a software inventory", rec: "Confirm each install is sanctioned. Unsanctioned remote-access tools are a common intrusion and ransomware path (T1219); allow-list the approved ones in the baseline." },
  { id: "conflicts", title: "Conflicting device records across sources", severity: "medium", confidence: "review", category: "inventory", controls: [CIS("1.1"), NIST("CM-8")], needs: "two or more device sources", rec: "Two physical machines share a hostname or id, or one device carries different users / operating systems across tools. Rename or retire the stale record so every tool reports the same asset." },
  { id: "coverage", title: "Coverage gaps between inventories", severity: "low", confidence: "likely", category: "inventory", controls: [CIS("1.1"), ISO("A.8.1"), NIST("CM-8")], needs: "three or more device sources", rec: "Each tool should see every device. Investigate devices missing from one inventory: unenrolled, retired, or renamed." },
];
const DET = Object.fromEntries(DETECTIONS.map((d) => [d.id, d]));

/** Built-in remote-access / tunnelling review list. */
export const REMOTE_ACCESS = [
  ["AnyDesk", /\banydesk\b/i], ["TeamViewer", /\bteam ?viewer\b/i], ["RustDesk", /\brustdesk\b/i], ["ngrok", /\bngrok\b/i], ["Tailscale", /\btailscale\b/i],
  ["LogMeIn", /\blogmein\b/i], ["Chrome Remote Desktop", /chrome remote desktop/i], ["uTorrent", /\b(?:µ|u)torrent\b/i], ["Tor Browser", /\btor browser\b/i],
  ["VNC server", /\b(?:realvnc|tightvnc|ultravnc|tigervnc|vnc server)\b/i],
];

/** Parse "one name or /regex/ per line" into matchers; invalid regexes are reported. */
export function parseMatchList(text) {
  const out = [], errors = [];
  for (const raw of String(text || "").split(/\r?\n/)) {
    const s = raw.trim();
    if (!s || s.startsWith("#")) continue;
    const m = s.match(/^\/(.+)\/([gimsuy]*)$/);
    if (m) { try { out.push({ label: s, re: new RegExp(m[1], m[2].replace("g", "")) }); } catch (e) { errors.push(s + ": " + (e && e.message || e)); } }
    else out.push({ label: s, re: new RegExp(s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i") });
  }
  return { list: out, errors };
}

const normUser = (u) => lc(u).replace(/^.*\\/, "").replace(/@.*$/, "");

// ---------------------------------------------------------------------------
// analyze
// ---------------------------------------------------------------------------
const MOBILE = new Set(["ios", "android", "chromeos"]);
const num = (v, d) => (Number.isFinite(Number(v)) && v !== "" && v !== null ? Number(v) : d);

/**
 * analyze(dataset, opts, ctx). dataset = parseInput() result, or the raw files
 * ({name,text}[] / text) which are parsed here (worker entry point).
 */
export function analyze(dataset, opts = {}, ctx) {
  const o = { ...DEFAULTS, ...(opts || {}) };
  const parsed = dataset && Array.isArray(dataset.sources) ? dataset : parseInput(dataset, o, ctx);
  const sources = parsed.sources;
  const skipped = (parsed.skipped || []).slice();
  const W = { ...WEIGHTS, ...(o.weights || {}) };
  const idx = eolIndex(o.eol);
  const eolUpdated = o.eol && o.eol.updated ? str(o.eol.updated) : null;

  // Register
  const records = sources.flatMap((s) => s.devices);
  const { groups, groupOf, conflicts } = matchDevices(records);
  const devices = groups.map((g) => mergeDevice(g, sources)).sort((a, b) => cmp(a.key, b.key) || cmp(lc(a.name), lc(b.name)));
  devices.forEach((d, i) => { d.idx = i; d.flags = new Set(); d.reasons = {}; });
  let nowMs = o.now ? parseTs(o.now) : null;
  if (nowMs == null) { for (const r of records) if (r.lastSeen != null && (nowMs == null || r.lastSeen > nowMs)) nowMs = r.lastSeen; }
  if (nowMs == null) nowMs = 0;
  ctx?.progress?.(1, 4, "matched " + records.length + " records into " + devices.length + " devices");

  // Software attached to devices
  const byHost = new Map(), bySerial = new Map();
  for (const d of devices) { for (const h of d.hosts) if (!byHost.has(h)) byHost.set(h, d); for (const s of d.serials) if (!bySerial.has(s)) bySerial.set(s, d); }
  const software = sources.flatMap((s) => s.software);
  const swUnmatched = new Map(), swDevice = new Map();
  for (const sw of software) {
    const d = (sw.serial && bySerial.get(sw.serial)) || (sw.host && byHost.get(sw.host)) || null;
    swDevice.set(sw, d);
    if (!d) swUnmatched.set(sw.src, (swUnmatched.get(sw.src) || 0) + 1);
    else (d.software || (d.software = [])).push(sw);
  }

  const kindsLoaded = new Set(sources.filter((s) => s.devices.length).map((s) => s.kind));
  const hits = Object.fromEntries(DETECTIONS.map((x) => [x.id, []]));
  const fail = (id, d, detail) => { hits[id].push({ d, detail }); d.flags.add(DET[id].flag || id); (d.reasons[DET[id].flag || id] || (d.reasons[DET[id].flag || id] = [])).push(detail); };
  const skip = (check, reason) => skipped.push({ check, reason });
  const has = (f) => devices.some((d) => d[f] !== null && d[f] !== undefined);

  // Encryption
  if (!has("encrypted")) skip("encryption", "no source reports disk encryption (needs " + DET.encryption_laptop.needs + ")");
  else for (const d of devices) if (d.encrypted === false) fail(d.laptop ? "encryption_laptop" : "encryption", d, "not encrypted per " + d.recs.filter((r) => r.encrypted === false).map((r) => sources[r.src].format).join(", "));

  // EDR presence / health / staleness
  const genericEdr = sources.some((s) => s.format === "generic" && s.columns.edr);
  if (!(kindsLoaded.has("edr") && (kindsLoaded.has("mdm") || kindsLoaded.has("directory"))) && !genericEdr) skip("edr_missing", "needs both an EDR export and an MDM or directory export (loaded: " + ([...kindsLoaded].sort().join(", ") || "none") + ")");
  else {
    let mobile = 0;
    for (const d of devices) {
      const inv = d.kinds.includes("mdm") || d.kinds.includes("directory") || d.kinds.includes("generic");
      if (d.hasEdr || d.kinds.includes("edr") || !inv) continue;
      if (d.enabled === false && !d.kinds.includes("mdm")) continue;
      if (MOBILE.has(d.family)) { mobile++; continue; }
      if (kindsLoaded.has("edr") || d.edrNo) fail("edr_missing", d, "absent from " + (kindsLoaded.has("edr") ? sources.filter((s) => s.kind === "edr").map((s) => s.format).join(", ") : "the EDR column"));
    }
    if (mobile) skip("edr_missing", mobile + " mobile / ChromeOS device(s) excluded from the EDR-missing check");
  }
  if (!devices.some((d) => d.edrIssues.length) && !kindsLoaded.has("edr") && !kindsLoaded.has("audit")) skip("edr_unhealthy", "no EDR health columns loaded (needs " + DET.edr_unhealthy.needs + ")");
  for (const d of devices) if (d.edrIssues.length) fail("edr_unhealthy", d, d.edrIssues.join("; "));
  const edrStale = num(o.edrStaleDays, 7) * DAY;
  if (!(kindsLoaded.has("edr") && kindsLoaded.has("mdm"))) skip("edr_stale", "needs EDR last seen and MDM last check-in");
  else for (const d of devices) if (d.edrLast != null && d.mdmLast != null && nowMs - d.edrLast > edrStale && nowMs - d.mdmLast <= edrStale) fail("edr_stale", d, "EDR last seen " + day(d.edrLast) + ", MDM check-in " + day(d.mdmLast));

  // Sensor version lag (CrowdStrike)
  const sv = devices.filter((d) => d.sensorVersion).map((d) => ({ d, t: verTuple(d.sensorVersion) })).filter((x) => x.t.length >= 2);
  if (!sv.length) skip("sensor_behind", "no CrowdStrike Sensor Version column loaded");
  else {
    const counts = new Map();
    for (const x of sv) { const k = x.t[0] + "." + x.t[1]; counts.set(k, (counts.get(k) || 0) + 1); }
    const mode = [...counts].sort((a, b) => b[1] - a[1] || cmpVer(b[0], a[0]))[0][0].split(".").map(Number);
    const lag = num(o.sensorMinorLag, 2);
    for (const x of sv) { const behind = x.t[0] < mode[0] ? Infinity : x.t[0] === mode[0] ? mode[1] - x.t[1] : 0; if (behind > lag) fail("sensor_behind", x.d, "sensor " + x.d.sensorVersion + " vs fleet mode " + mode.join(".")); }
  }

  // OS end of life
  const unmapped = new Map();
  const soonDays = num(o.eolSoonDays, 90);
  if (!idx.size) skip("os_eol", "EOL feed not loaded (opts.eol); OS and software end-of-life checks need /data/feeds/eol-products.json");
  for (const d of devices) {
    d.eolStatus = "unknown"; d.eolDate = ""; d.eolCycle = "";
    if (!idx.size) continue;
    const m = mapOsCycle(d, idx, o);
    if (!m.cycle) { unmapped.set(m.reason, (unmapped.get(m.reason) || 0) + 1); continue; }
    const st = cycleStatus(m.cycle, nowMs, soonDays);
    d.eolStatus = st.status; d.eolDate = st.eol || ""; d.eolCycle = m.product + " " + m.cycle.cycle;
    if (st.status === "eol") fail("os_eol", d, d.eolCycle + " end of life " + (st.eol || "(date not published)"));
    else if (st.status === "soon") fail("os_eol_soon", d, d.eolCycle + " end of life " + st.eol);
  }
  for (const [reason, n] of [...unmapped].sort((a, b) => b[1] - a[1] || cmp(a[0], b[0]))) skip("os_eol", n + " device(s) not mapped to an EOL cycle: " + reason);

  // Software: EOL apps, blocklist, remote-access review list
  const swTable = new Map();
  const block = parseMatchList(o.blocklist), allow = parseMatchList(o.allowlist);
  for (const e of [...block.errors, ...allow.errors]) skip("blocklist", "invalid pattern " + e);
  const unknownCycles = new Map();
  for (const sw of software) {
    const k = lc(sw.name) + "|" + sw.version;
    let t = swTable.get(k);
    if (!t) {
      t = { name: sw.name, version: sw.version, publisher: sw.publisher, devices: new Set(), eol: "", eolDate: "", blocklisted: "", remoteAccess: "" };
      const mp = idx.size ? mapAppProduct(sw.name, sw.version) : null;
      if (mp) {
        const c = (idx.get(mp.product) || []).find((x) => String(x.cycle) === mp.key);
        if (!c) unknownCycles.set(mp.product + " " + mp.key, (unknownCycles.get(mp.product + " " + mp.key) || 0) + 1);
        else { const st = cycleStatus(c, nowMs, soonDays); t.eol = st.status; t.eolDate = st.eol || ""; t.product = mp.product + " " + mp.key; }
      }
      const b = block.list.find((x) => x.re.test(sw.name));
      if (b) t.blocklisted = b.label;
      const ra = REMOTE_ACCESS.find(([, re]) => re.test(sw.name));
      if (ra && !allow.list.some((x) => x.re.test(sw.name))) t.remoteAccess = ra[0];
      swTable.set(k, t);
    }
    if (!t.publisher && sw.publisher) t.publisher = sw.publisher;
    if (swDevice.get(sw)) t.devices.add(swDevice.get(sw).idx);
  }
  for (const [k, n] of [...unknownCycles].sort((a, b) => cmp(a[0], b[0]))) skip("app_eol", n + " install(s) of " + k + " have no cycle in the EOL feed");
  if (!software.length) { skip("app_eol", "no software inventory loaded"); skip("blocklist", "no software inventory loaded"); skip("remote_access", "no software inventory loaded"); }
  else if (!block.list.length) skip("blocklist", "blocklist is empty (add names or /regex/ in the baseline)");
  for (const d of devices) {
    for (const sw of (d.software || []).slice().sort((a, b) => cmp(lc(a.name), lc(b.name)) || cmp(a.version, b.version))) {
      const t = swTable.get(lc(sw.name) + "|" + sw.version);
      if (t.eol === "eol") fail("app_eol", d, sw.name + " " + sw.version + " (" + t.product + " end of life " + (t.eolDate || "n/a") + ")");
      if (t.blocklisted) fail("blocklist", d, sw.name + " " + sw.version + " matches " + t.blocklisted);
      if (t.remoteAccess) fail("remote_access", d, sw.name + " " + sw.version + " (" + t.remoteAccess + ")");
    }
  }

  // Patch level relative to the fleet
  const lines = new Map();
  for (const d of devices) {
    let line = null, v = null;
    if (d.family === "windows" || d.family === "windows-server") { const b = parseWinBuild(d.osVersion) || parseWinBuild(d.os); if (b && b.rev != null) { line = d.family + " build " + b.build; v = [b.rev]; d.patchVer = b.major + ".0." + b.build + "." + b.rev; } }
    else if ((d.family === "macos" && !d.darwin) || d.family === "ios") { const t = verTuple(d.osVersion); if (t.length) { line = d.family + " " + t[0]; v = t; d.patchVer = t.join("."); } }
    if (line) { d.patchLine = line; d.patchTuple = v; (lines.get(line) || lines.set(line, []).get(line)).push(d); }
  }
  const allowBehind = num(o.patchAgeBuilds, 1);
  let comparable = 0;
  for (const [line, ds] of lines) {
    const vers = uniqSorted(ds.map((d) => d.patchTuple.join("."))).sort((a, b) => cmpVer(b, a));
    if (vers.length < 2) continue;
    comparable++;
    for (const d of ds) { const behind = vers.indexOf(d.patchTuple.join(".")); if (behind > allowBehind) fail("patch_behind", d, line + ": " + d.patchVer + " is " + behind + " release(s) behind " + (d.family.startsWith("windows") ? vers[0].replace(/^/, "rev ") : vers[0]) + " seen in the fleet"); }
  }
  for (const d of devices) if (d.autoUpdates === false) fail("patch_behind", d, "automatic OS updates disabled (Workstation Audit)");
  if (!comparable && !devices.some((d) => d.autoUpdates === false)) skip("patch_behind", "no OS line with two or more distinct comparable versions (needs Windows build.revision or macOS / iOS versions)");

  // Staleness
  const stale = num(o.staleDays, 30) * DAY, lost = num(o.lostDays, 90) * DAY;
  if (!has("lastSeen")) skip("stale", "no last check-in / last seen column in any source");
  for (const d of devices) {
    if (d.lastSeen == null) continue;
    const age = nowMs - d.lastSeen;
    if (age > lost && d.enabled === true) fail("stale_enabled", d, "last seen " + day(d.lastSeen) + " (" + Math.floor(age / DAY) + " days) and the directory account is enabled");
    else if (age > stale) fail("stale", d, "last seen " + day(d.lastSeen) + " (" + Math.floor(age / DAY) + " days ago) in every source");
  }

  // Privilege
  if (!has("primaryAdmin") && !has("localAdmins") && !has("manyAdmins")) skip("local_admin", "no local admin data (needs " + DET.local_admin.needs + ")");
  const maxAdm = num(o.maxLocalAdmins, 2);
  for (const d of devices) {
    if (d.primaryAdmin === true) fail("local_admin", d, (d.user || "primary user") + " is a local administrator");
    if ((d.localAdmins != null && d.localAdmins > maxAdm) || d.manyAdmins === true) fail("many_admins", d, d.localAdmins != null && d.localAdmins > maxAdm ? d.localAdmins + " local admin accounts (baseline " + maxAdm + ")" : "Workstation Audit admin-count failed");
  }

  // Configuration / integrity
  const cfg = [["jailbroken", "jailbroken", (d) => d.jailbroken === true, "reported jailbroken / compromised"],
    ["gatekeeper_sip", "gatekeeper", (d) => d.gatekeeper === false || d.sip === false, null],
    ["firewall", "firewall", (d) => d.firewall === false, "host firewall off"],
    ["screen_lock", "screenLock", (d) => d.screenLock === false, "screen lock / password policy failing"],
    ["guest_account", "guest", (d) => d.guest === true, "guest account enabled"],
    ["secure_boot", "secureBoot", (d) => d.secureBoot === false, "Secure Boot off"],
    ["recovery_lock", "recoveryLock", (d) => d.recoveryLock === false && d.family === "macos", "Recovery Lock not set"],
    ["activation_lock", "activationLock", (d) => d.activationLock === false && d.laptop, "Activation Lock off"]];
  for (const [id, field, pred, text] of cfg) {
    if (!has(field) && !(id === "gatekeeper_sip" && has("sip"))) { skip(id, "no source reports it (needs " + DET[id].needs + ")"); continue; }
    for (const d of devices) if (pred(d)) fail(id, d, text || [d.gatekeeper === false ? "Gatekeeper off" : "", d.sip === false ? "SIP off" : ""].filter(Boolean).join(", "));
  }
  if (!has("compliance")) skip("noncompliant", "no compliance state (needs " + DET.noncompliant.needs + ")");
  for (const d of devices) if (d.compliance === "noncompliant" || d.compliance === "not evaluated") fail("noncompliant", d, "compliance: " + d.compliance);
  if (!devices.some((d) => d.managed === false)) { if (!has("managed")) skip("unmanaged", "no management state (needs " + DET.unmanaged.needs + ")"); }
  for (const d of devices) if (d.managed === false && d.enabled !== false) fail("unmanaged", d, "unmanaged per " + d.managedEvidence.join(", "));

  // Conflicts: shared keys with different serials, or one device with different users / OS
  const conflictRows = conflicts.map((c) => ({ device: "", key: c.key, value: c.value, detail: "shared by serials " + c.serials.filter(Boolean).join(", ") }));
  for (const d of devices) {
    const users = uniqSorted(d.recs.map((r) => normUser(r.user)).filter(Boolean));
    const fams = uniqSorted(d.recs.map((r) => r.family).filter((f) => f && f !== "other" && f !== "linux"));
    if (users.length > 1) conflictRows.push({ device: d.name, key: "user", value: users.join(" / "), detail: "different users across " + d.sources.join(", ") });
    if (fams.length > 1) conflictRows.push({ device: d.name, key: "os", value: fams.join(" / "), detail: "different operating systems across " + d.sources.join(", ") });
  }

  // Coverage between inventories
  const devSources = sources.filter((s) => s.devices.length);
  const covKinds = ["mdm", "edr", "directory", "audit"].filter((k) => kindsLoaded.has(k));
  const coverage = [];
  for (const a of covKinds) for (const b of covKinds) {
    if (a === b) continue;
    const inA = devices.filter((d) => d.kinds.includes(a));
    const miss = inA.filter((d) => !d.kinds.includes(b) && !(b === "edr" && MOBILE.has(d.family)));
    coverage.push({ from: KIND_LABEL[a], to: KIND_LABEL[b], fromKind: a, toKind: b, inFrom: inA.length, missing: miss.length, devices: miss.map((d) => d.name).sort(cmp) });
  }

  // Scores
  for (const d of devices) {
    const lost = [...d.flags].reduce((s, f) => s + num(W[f], 0), 0);
    d.score = Math.max(0, 100 - lost);
  }
  ctx?.progress?.(3, 4, "building findings");

  // Findings
  const row = (d, detail) => ({ device: d.name, serial: d.serial, user: d.user, os: [d.os, d.osVersion].filter(Boolean).join(" "), sources: d.sources.join(" "), lastSeen: day(d.lastSeen), detail });
  const assetOf = (d) => ({ type: "ASSET", name: d.name || d.serial, data: { kind: "endpoint", os: d.os, osVersion: d.osVersion, user: d.user, encrypted: d.encrypted, edr: d.hasEdr ? "present" : d.kinds.includes("edr") ? "unhealthy" : "missing", score: d.score, sources: d.sources } });
  const findings = [];
  for (const det of DETECTIONS) {
    if (det.id === "conflicts" || det.id === "coverage") continue;
    const h = hits[det.id];
    if (!h.length) continue;
    h.sort((a, b) => cmp(lc(a.d.name), lc(b.d.name)) || cmp(a.detail, b.detail));
    const devs = uniqSorted(h.map((x) => x.d.idx)).map((i) => devices[i]).sort((a, b) => cmp(lc(a.name), lc(b.name)));
    const assets = devs.slice(0, 50).map(assetOf);
    const users = uniqSorted(devs.filter((d) => d.laptop && d.user).map((d) => d.user)).slice(0, 50);
    for (const u of users) assets.push({ type: "IDENTITY", name: u, data: { role: "primary user of a failing laptop" } });
    findings.push({
      id: TOOL_ID + ":" + det.id, check: det.id, title: det.title, severity: det.severity, confidence: det.confidence, category: det.category,
      description: devs.length + " device" + (devs.length === 1 ? "" : "s") + " (" + h.length + " item" + (h.length === 1 ? "" : "s") + "). " + h[0].detail + (h.length > 1 ? "; ..." : "") + ".",
      recommendation: det.rec, controls: det.controls, evidence: h.slice(0, 50).map((x) => row(x.d, x.detail)), evidenceCount: h.length, assets,
      tags: ["fleet", det.category],
    });
  }
  if (conflictRows.length) {
    const det = DET.conflicts;
    conflictRows.sort((a, b) => cmp(a.key, b.key) || cmp(a.device, b.device) || cmp(a.value, b.value));
    findings.push({ id: TOOL_ID + ":conflicts", check: "conflicts", title: det.title, severity: det.severity, confidence: det.confidence, category: det.category,
      description: conflictRows.length + " conflicting identity record(s). First: " + conflictRows[0].key + " " + conflictRows[0].value + " (" + conflictRows[0].detail + ").",
      recommendation: det.rec, controls: det.controls, evidence: conflictRows.slice(0, 50), evidenceCount: conflictRows.length, assets: devices.filter((d) => conflictRows.some((x) => x.device && x.device === d.name)).slice(0, 50).map(assetOf), tags: ["fleet", "inventory"] });
  }
  if (devSources.length >= 3) {
    for (const c of coverage) {
      if (!c.missing || c.toKind === "edr" || c.toKind === "audit") continue;
      const det = DET.coverage;
      findings.push({ id: TOOL_ID + ":coverage:" + c.fromKind + ">" + c.toKind, check: "coverage", title: "In " + c.from + " but not in " + c.to, severity: det.severity, confidence: det.confidence, category: det.category,
        description: c.missing + " of " + c.inFrom + " devices seen in " + c.from + " are absent from " + c.to + ". (Missing from EDR is reported separately as 'Devices in MDM or the directory with no EDR sensor'.)",
        recommendation: det.rec, controls: det.controls, evidence: c.devices.slice(0, 50).map((n) => ({ device: n, missingFrom: c.to, seenIn: c.from })), evidenceCount: c.missing, assets: devices.filter((d) => c.devices.slice(0, 50).includes(d.name)).map(assetOf), tags: ["fleet", "coverage"] });
    }
  } else skip("coverage", "coverage gaps need three or more device sources (" + devSources.length + " loaded)");
  findings.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || b.evidenceCount - a.evidenceCount || cmp(a.id, b.id));

  // Tables
  const tDevices = devices.map((d) => ({
    key: d.key, name: d.name, serial: d.serial, os: d.os, osVersion: d.osVersion, family: d.family, eolStatus: d.eolStatus, eolDate: d.eolDate, eolCycle: d.eolCycle,
    user: d.user, model: d.model, laptop: d.laptop, sources: d.sources, lastSeen: iso(d.lastSeen), encrypted: d.encrypted,
    edr: d.hasEdr ? "present" : d.kinds.includes("edr") ? "not onboarded" : kindsLoaded.has("edr") || d.edrNo ? "missing" : "unknown",
    edrHealth: d.edrIssues.length ? d.edrIssues.join("; ") : d.hasEdr ? "ok" : "", compliance: d.compliance, localAdmin: d.primaryAdmin === true ? true : d.primaryAdmin === false ? false : null,
    localAdmins: d.localAdmins, firewall: d.firewall, score: d.score, flags: [...d.flags].sort(cmp),
    checks: Object.fromEntries(Object.keys(d.reasons).sort(cmp).map((k) => [k, d.reasons[k]])),
    records: d.recs.slice().sort((a, b) => a.src - b.src || (a.row || 0) - (b.row || 0)).map((r) => ({ file: sources[r.src].name, format: r.format, kind: r.kind, row: r.raw })),
    software: (d.software || []).length,
  }));
  const tSources = sources.map((s, i) => {
    const matched = s.devices.filter((r) => groupOf.get(r) && groupOf.get(r).recs.some((x) => x.src !== i)).length;
    return { name: s.name, format: s.format, label: s.label, kind: s.kind, vendor: s.vendor, confidence: s.confidence, rows: s.rows,
      devices: s.devices.length, software: s.software.length,
      matched: s.kind === "software" ? s.software.length - (swUnmatched.get(i) || 0) : matched,
      unmatched: s.kind === "software" ? swUnmatched.get(i) || 0 : s.devices.length - matched };
  });
  const tSoftware = [...swTable.values()].map((t) => ({ name: t.name, version: t.version, publisher: t.publisher, devices: t.devices.size, eol: t.eol, eolDate: t.eolDate, blocklisted: t.blocklisted, remoteAccess: t.remoteAccess }))
    .sort((a, b) => b.devices - a.devices || cmp(lc(a.name), lc(b.name)) || cmpVer(b.version, a.version) || cmp(a.version, b.version));
  const osMap = new Map();
  for (const d of devices) {
    const label = d.eolCycle || (d.family ? d.family + " " + (verTuple(d.osVersion)[0] != null ? verTuple(d.osVersion)[0] : "?") : "unknown");
    const t = osMap.get(label) || { family: d.family || "unknown", version: label, devices: 0, eolStatus: d.eolStatus, eol: d.eolDate };
    t.devices++; osMap.set(label, t);
  }
  const tOs = [...osMap.values()].sort((a, b) => cmp(a.family, b.family) || b.devices - a.devices || cmp(a.version, b.version));
  const worklist = [];
  const flagSev = {};
  for (const det of DETECTIONS) { const f = det.flag || det.id; if (!flagSev[f] || SEV_RANK[det.severity] > SEV_RANK[flagSev[f].severity]) flagSev[f] = det; }
  for (const d of devices) for (const f of [...d.flags].sort(cmp)) {
    const det = f === "encryption" && d.laptop ? DET.encryption_laptop : flagSev[f];
    worklist.push({ device: d.name, serial: d.serial, owner: d.user, check: f, severity: det.severity, action: det.rec.split(/(?<=\.)\s/)[0], detail: d.reasons[f].join("; ") });
  }
  worklist.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || cmp(lc(a.device), lc(b.device)) || cmp(a.check, b.check));

  const scores = devices.map((d) => d.score);
  const mean = scores.length ? Math.round((scores.reduce((s, x) => s + x, 0) / scores.length) * 10) / 10 : null;
  const dist = { "90-100": 0, "75-89": 0, "50-74": 0, "0-49": 0 };
  for (const s of scores) dist[s >= 90 ? "90-100" : s >= 75 ? "75-89" : s >= 50 ? "50-74" : "0-49"]++;
  const count = (f) => devices.filter((d) => d.flags.has(f)).length;
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) bySeverity[f.severity]++;
  const summary = {
    devices: devices.length, sources: sources.length, records: records.length, software: software.length, fleetScore: mean, distribution: dist,
    unencrypted: count("encryption"), edrMissing: count("edr_missing"), edrUnhealthy: count("edr_unhealthy"), eolOs: count("os_eol"), stale: count("stale") + count("stale_enabled"),
    localAdmins: count("local_admin"), findings: findings.length, bySeverity, now: iso(nowMs), eolUpdated,
  };
  ctx?.progress?.(4, 4, "done");
  return {
    summary, findings, skipped,
    tables: { devices: tDevices, sources: tSources, software: tSoftware, coverage: coverage.map(({ devices: ds, ...c }) => ({ ...c, devices: ds.slice(0, 200) })), os: tOs, worklist },
    meta: { tool: TOOL_ID, version: VERSION, now: iso(nowMs), eolUpdated, weights: W, files: sources.map((s) => s.name) },
  };
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
// Quote every cell; neutralise spreadsheet formula prefixes (CSV injection) in text values.
const q = (v) => { let s = v == null ? "" : Array.isArray(v) ? v.join(" ") : String(v); if (typeof v !== "number" && /^(?:[=+@\t\r]|-(?!\d))/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };
const csv = (cols, rows) => [cols.join(","), ...(rows || []).map((r) => cols.map((c) => q(r[c])).join(","))].join("\n");

const FINDING_COLS = ["severity", "confidence", "category", "check", "title", "description", "recommendation", "controls", "assets", "evidenceCount"];
/** Findings as CSV with fixed columns. */
export function findingsToCsv(findings) {
  return [FINDING_COLS.join(","), ...(findings || []).map((f) => [f.severity, f.confidence, f.category, f.check, f.title, f.description, f.recommendation,
    (f.controls || []).map((c) => c.framework + " " + c.id).join("; "), (f.assets || []).map((a) => a.name).join("; "),
    f.evidenceCount != null ? f.evidenceCount : (f.evidence || []).length].map(q).join(","))].join("\n");
}
export const DEVICE_COLS = ["name", "serial", "os", "osVersion", "eolCycle", "eolStatus", "eolDate", "user", "model", "laptop", "sources", "lastSeen", "encrypted", "edr", "edrHealth", "compliance", "localAdmin", "localAdmins", "firewall", "score", "flags"];
/** Device register as CSV. */
export function devicesToCsv(devices) { return csv(DEVICE_COLS, devices); }
/** Software inventory as CSV. */
export function softwareToCsv(software) { return csv(["name", "version", "publisher", "devices", "eol", "eolDate", "blocklisted", "remoteAccess"], software); }
/** Remediation worklist (device, owner, action, severity) as CSV. */
export function worklistToCsv(worklist) { return csv(["device", "serial", "owner", "severity", "check", "action", "detail"], worklist); }
/** Coverage matrix as CSV. */
export function coverageToCsv(coverage) { return csv(["from", "to", "inFrom", "missing", "devices"], coverage); }

/** Plain-text summary for the TXT export. */
export function summaryText(r) {
  const s = r.summary;
  const L = [
    "Endpoint Fleet Compliance summary (" + TOOL_ID + " v" + VERSION + ")",
    "Reference date: " + (s.now || "n/a") + (s.eolUpdated ? "; EOL data mirrored " + s.eolUpdated.slice(0, 10) + " from endoflife.date" : "; EOL feed not loaded"),
    "Devices: " + s.devices + " from " + s.sources + " source file(s), " + s.records + " device records, " + s.software + " software rows",
    "Fleet score: " + (s.fleetScore == null ? "n/a" : s.fleetScore) + " / 100 " + JSON.stringify(s.distribution),
    "Unencrypted: " + s.unencrypted + "; EDR missing: " + s.edrMissing + "; EDR unhealthy: " + s.edrUnhealthy + "; EOL OS: " + s.eolOs + "; stale: " + s.stale + "; local admins: " + s.localAdmins,
    "Findings: " + s.findings + " " + JSON.stringify(s.bySeverity), "",
  ];
  for (const f of r.findings) L.push("- [" + f.severity + "/" + f.confidence + "] " + f.title + " (" + f.evidenceCount + "): " + (f.controls || []).map((c) => c.framework + " " + c.id).join(", "));
  if (r.skipped.length) { L.push("", "Skipped or limited checks:"); for (const k of r.skipped) L.push("- " + k.check + ": " + k.reason); }
  return L.join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// Synthetic example (seeded, exact vendor layouts, labelled). Not real data.
// ---------------------------------------------------------------------------
const line = (cells) => cells.map((c) => { const s = c == null ? "" : String(c); return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; }).join(",");

/** Example files: Intune devices + discovered apps, CrowdStrike, Jamf CSV + API JSON, Entra devices, one Workstation Audit fleet record. */
export function exampleDataset(seed = 7) {
  let s = seed >>> 0;
  const rnd = () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 4294967296; };
  const hex = (n) => Array.from({ length: n }, () => Math.floor(rnd() * 16).toString(16)).join("");
  const guid = () => hex(8) + "-" + hex(4) + "-4" + hex(3) + "-a" + hex(3) + "-" + hex(12);
  const mac = () => Array.from({ length: 6 }, () => hex(2)).join(":").toUpperCase();
  const people = ["user01", "user02", "user03", "user04", "user05", "user06", "user07", "user08", "user09", "user10", "user11", "user12"];
  const upn = (p) => p + "@test.darknode.ai";
  // 12 Windows devices managed by Intune
  const win = [
    ["WIN-LT-001", "Latitude 7450", "10.0.26200.6899", "Yes", "Compliant", "2026-10-15 08:12:04"],
    ["WIN-LT-002", "Latitude 7450", "10.0.26200.6899", "Yes", "Compliant", "2026-10-15 09:41:10"],
    ["WIN-LT-003", "ThinkPad T14 Gen 5", "10.0.26200.6899", "No", "Noncompliant", "2026-10-14 17:03:55"],
    ["WIN-LT-004", "ThinkPad T14 Gen 5", "10.0.26100.6899", "Yes", "Compliant", "2026-10-15 07:55:31"],
    ["WIN-LT-005", "EliteBook 840 G11", "10.0.26200.6584", "Yes", "Compliant", "2026-10-15 11:20:00"],
    ["WIN-LT-006", "EliteBook 840 G11", "10.0.26200.6584", "Yes", "Compliant", "2026-10-13 15:02:47"],
    ["WIN-LT-007", "Surface Laptop 7", "10.0.26200.6899", "Yes", "Not evaluated", "2026-10-15 10:10:10"],
    ["WIN-LT-008", "XPS 13 9350", "10.0.19045.6456", "Yes", "Compliant", "2026-10-15 12:00:00"],
    ["WIN-DT-001", "OptiPlex 7020", "10.0.26200.6899", "Yes", "Compliant", "2026-10-15 06:30:00"],
    ["WIN-DT-002", "OptiPlex 7020", "10.0.26200.6725", "Yes", "Compliant", "2026-10-15 06:31:00"],
    ["WIN-DT-003", "OptiPlex 7020", "10.0.26200.6899", "No", "Compliant", "2026-10-15 06:32:00"],
    ["WIN-DT-004", "OptiPlex 7010", "10.0.26200.6899", "Yes", "Compliant", "2026-08-02 09:00:00"],
  ].map((r, i) => ({ name: r[0], model: r[1], ver: r[2], enc: r[3], comp: r[4], seen: r[5], user: upn(people[i]), serial: "5CG" + String(4100 + i * 37) + hex(3).toUpperCase(), id: guid(), aad: guid(), mac: mac(), manu: /ThinkPad/.test(r[1]) ? "LENOVO" : /EliteBook/.test(r[1]) ? "HP" : /Surface/.test(r[1]) ? "Microsoft Corporation" : "Dell Inc." }));
  const intune = [FORMATS["intune-devices"].headers.join(",")].concat(win.map((d) => line([d.name, "Intune", "Corporate", d.comp, "Windows", d.ver, d.user, d.seen, d.id, d.aad, d.serial, d.manu, d.model, d.enc, "No", "2025-03-11 10:00:00", d.mac, "476.31 GB", "201.10 GB", "", "No", "Microsoft Entra joined", "Active", "False"]))).join("\r\n");
  // 4 Macs in Jamf
  const macs = [
    { name: "MBP-U01", serial: "C02F" + hex(4).toUpperCase() + "Q6L", model: "MacBook Pro (14-inch, Nov 2023)", ver: "15.7.1", fv: "All Partitions Encrypted", fw: "Yes", user: "user01", seen: "2026-10-15 09:00:00", sip: "Enabled", gk: "App Store and identified developers", rl: "Yes", al: "Enabled", admin: false },
    { name: "MBP-U02", serial: "C02G" + hex(4).toUpperCase() + "Q6L", model: "MacBook Pro (16-inch, 2024)", ver: "15.6.1", fv: "Not Encrypted", fw: "Yes", user: "user02", seen: "2026-10-15 13:30:00", sip: "Enabled", gk: "App Store and identified developers", rl: "Yes", al: "Enabled", admin: true },
    { name: "MBA-U03", serial: "FVFH" + hex(4).toUpperCase() + "1WK", model: "MacBook Air (M2, 2022)", ver: "14.8.1", fv: "All Partitions Encrypted", fw: "Yes", user: "user03", seen: "2026-10-14 18:45:00", sip: "Enabled", gk: "App Store and identified developers", rl: "No", al: "Enabled", admin: false },
    { name: "MINI-BUILD", serial: "H7WK" + hex(4).toUpperCase() + "PJ0", model: "Mac mini (2023)", ver: "15.7.1", fv: "All Partitions Encrypted", fw: "No", user: "build", seen: "2026-10-15 23:59:00", sip: "Enabled", gk: "App Store and identified developers", rl: "Yes", al: "Disabled", admin: false },
  ].map((m) => ({ ...m, mac: mac() }));
  const jamf = [FORMATS["jamf-computers"].headers.join(",")].concat(macs.map((m) => line([m.name, m.serial, m.seen, m.seen, m.ver, m.model, m.user, m.user === "build" ? "" : upn(m.user), m.fv, m.fv === "Not Encrypted" ? "" : m.user, m.gk, m.sip, m.fw, "Yes", "Yes", m.rl, "Full Security", "FileVault 2 Configuration", m.al, "2025-01-20 10:00:00", "10.20.4." + (20 + macs.indexOf(m)), m.mac]))).join("\n");
  const jamfApi = { totalCount: macs.length, results: macs.map((m, i) => ({
    id: String(100 + i), udid: guid().toUpperCase(),
    general: { name: m.name, lastContactTime: m.seen.replace(" ", "T") + "Z", lastEnrolledDate: "2025-01-20T10:00:00Z", mdmCapable: { capable: true, capableUsers: [m.user] } },
    hardware: { serialNumber: m.serial, macAddress: m.mac, model: m.model },
    operatingSystem: { version: m.ver, fileVault2Status: m.fv === "Not Encrypted" ? "NOT_ENCRYPTED" : "ALL_ENCRYPTED" },
    security: { sipStatus: "ENABLED", gatekeeperStatus: "APP_STORE_AND_IDENTIFIED_DEVELOPERS", firewallEnabled: m.fw === "Yes", activationLockEnabled: m.al === "Enabled", secureBootLevel: "FULL_SECURITY" },
    userAndLocation: { username: m.user, email: m.user === "build" ? "" : upn(m.user) },
    localUserAccounts: [{ username: m.user, admin: m.admin }, { username: "itadmin", admin: true }],
  })) };
  // CrowdStrike: 10 of the 12 Windows devices (WIN-LT-007 and WIN-DT-003 missing) + the Macs
  const csRows = win.filter((d) => d.name !== "WIN-LT-007" && d.name !== "WIN-DT-003").map((d) => ({ host: d.name, serial: d.serial, mac: d.mac.replace(/:/g, "-"), os: "Windows", osv: d.ver.startsWith("10.0.19045") ? "Windows 10" : "Windows 11", plat: "Windows",
    seen: d.name === "WIN-DT-002" ? "2026-10-01T04:10:00Z" : d.seen.replace(" ", "T") + "Z", sensor: d.name === "WIN-LT-006" ? "7.24.19607.0" : "7.29.20004.0", rfm: d.name === "WIN-LT-004" ? "Yes" : "No" }))
    .concat(macs.map((m) => ({ host: m.name, serial: m.serial, mac: m.mac.replace(/:/g, "-"), os: "Mac", osv: m.ver.startsWith("14") ? "Sonoma (14)" : "Sequoia (15)", plat: "Mac", seen: m.seen.replace(" ", "T") + "Z", sensor: "7.29.20004.0", rfm: "No" })));
  const cs = [FORMATS.crowdstrike.headers.join(",")].concat(csRows.map((c) => line([c.host, hex(32), c.seen, "2025-03-11T10:20:00Z", c.os, c.osv, c.plat, c.sensor, "Normal", c.rfm, "10.20.1." + Math.floor(rnd() * 200 + 10), "203.0.113." + Math.floor(rnd() * 200 + 10), c.mac, c.serial, "Workstations - Default", "N-1 Workstations", "SensorGroupingTags/Corp", "Normal", "HQ"]))).join("\n");
  // Entra devices: the Windows fleet + one unmanaged personal laptop + one stale enabled desktop
  const entraRows = win.map((d) => [d.name, "True", "Windows", d.ver, "Microsoft Entra joined", d.user, "Microsoft Intune", d.comp === "Noncompliant" ? "No" : d.comp === "Not evaluated" ? "N/A" : "Yes", "3/11/2025, 10:00:00 AM", d.seen.replace(/^(\d{4})-(\d{2})-(\d{2}).*$/, (_, y, m, dd) => Number(m) + "/" + Number(dd) + "/" + y + ", 9:00:00 AM"), guid(), d.aad, "AzureAd"])
    .concat([["DESKTOP-7KQ2M1P", "True", "Windows", "10.0.26200.6899", "Microsoft Entra registered", upn("user12"), "", "N/A", "6/2/2026, 2:14:00 PM", "10/14/2026, 8:02:00 PM", guid(), guid(), "Workplace"],
      ["OLD-DESK-07", "True", "Windows", "10.0.19045.3803", "Microsoft Entra hybrid joined", "", "", "N/A", "1/9/2022, 9:00:00 AM", "5/1/2026, 7:30:00 AM", guid(), guid(), "ServerAd"]]);
  const entra = [FORMATS["entra-devices"].headers.join(",")].concat(entraRows.map(line)).join("\n");
  // Intune discovered apps
  const apps = [];
  win.forEach((d, i) => {
    apps.push([d.name, "Google Chrome", d.name === "WIN-LT-005" ? "138.0.7204.101" : "155.0.7712.81", "Windows", "Google LLC", d.user]);
    apps.push([d.name, "Microsoft 365 Apps for enterprise - en-us", "16.0.19127.20264", "Windows", "Microsoft Corporation", d.user]);
    if (i % 3 === 0) apps.push([d.name, "Zoom Workplace (64-bit)", "6.6.2", "Windows", "Zoom Communications, Inc.", d.user]);
  });
  apps.push(["WIN-LT-003", "AnyDesk", "9.0.4", "Windows", "AnyDesk Software GmbH", win[2].user]);
  apps.push(["WIN-DT-002", "Microsoft Office Professional Plus 2016", "16.0.4266.1001", "Windows", "Microsoft Corporation", win[9].user]);
  apps.push(["WIN-LT-008", "Python 3.9.13 (64-bit)", "3.9.13150.0", "Windows", "Python Software Foundation", win[7].user]);
  const appsCsv = [FORMATS["intune-apps"].headers.join(",")].concat(apps.map(line)).join("\n");
  // Workstation Audit fleet record from the Darknode desktop app for one laptop
  const audit = { host: "WIN-LT-002", os: "Windows 10.0.26200", generated: "2026-10-15T14:02:11.000Z", appVersion: "1.9.0", score: { percent: 78, grade: "C", earned: 14, possible: 18, counts: { pass: 9, fail: 2, warn: 1, na: 0, error: 0, total: 12 } },
    results: [
      { id: "disk-encryption", status: "pass", severity: "high", cisRef: "CIS Windows 18.9.x" }, { id: "firewall", status: "fail", severity: "high", cisRef: "CIS Windows 9.x" },
      { id: "auto-updates", status: "pass", severity: "medium", cisRef: "CIS Windows 18.9.108.x" }, { id: "screen-lock", status: "warn", severity: "medium", cisRef: "CIS Windows 19.1.3.x" },
      { id: "defender", status: "pass", severity: "high", cisRef: "CIS Windows 18.9.47.x" }, { id: "secure-boot", status: "pass", severity: "medium", cisRef: "CIS Windows 18.x" },
      { id: "guest-account", status: "fail", severity: "medium", cisRef: "CIS Windows 1.1.x" }, { id: "password-policy", status: "pass", severity: "medium", cisRef: "CIS Windows 1.1/1.2" },
      { id: "remote-access", status: "pass", severity: "medium", cisRef: "CIS Windows 18.9.65.x" }, { id: "listening-services", status: "pass", severity: "medium", cisRef: "CIS Windows 9.x" },
      { id: "persistence-run", status: "pass", severity: "low", cisRef: "CIS Windows (review)" }, { id: "time-sync", status: "pass", severity: "low", cisRef: "CIS Windows 2.3.x" },
    ] };
  const files = [
    { name: "IntuneDevices.csv", text: intune },
    { name: "DiscoveredApps.csv", text: appsCsv },
    { name: "falcon-hosts.csv", text: cs },
    { name: "jamf-computers.csv", text: jamf },
    { name: "jamf-computers-inventory.json", text: JSON.stringify(jamfApi, null, 2) },
    { name: "entra-devices.csv", text: entra },
    { name: "workstation-audit-fleet-WIN-LT-002.json", text: JSON.stringify(audit, null, 2) },
  ];
  return { label: "synthetic example (not real data)", files, now: "2026-10-16T12:00:00Z" };
}

/** Minimal EOL fixture used by selfTest only (values copied from the endoflife.date cycles they name). */
const SELFTEST_EOL = { updated: "fixture", data: [
  { product: "windows", cycles: [{ cycle: "11-25h2-w", eol: "2027-10-12", latest: "10.0.26200" }, { cycle: "11-24h2-w", eol: "2026-10-13", latest: "10.0.26100" }, { cycle: "10-22h2", eol: "2025-10-14", latest: "10.0.19045" }] },
  { product: "macos", cycles: [{ cycle: "15", eol: false, latest: "15.8.1" }, { cycle: "14", eol: "2026-09-14", latest: "14.8.9" }] },
  { product: "chrome", cycles: [{ cycle: "155", eol: "2026-10-20" }, { cycle: "138", eol: "2025-08-05" }] },
] };

/** Real deterministic checks of the engine on the synthetic example. */
export function selfTest() {
  const tests = [];
  const ex = exampleDataset();
  const r = analyze(ex.files, { now: ex.now, eol: SELFTEST_EOL });
  const f = (check) => r.findings.find((x) => x.check === check);
  const names = (check) => (f(check) ? f(check).evidence.map((e) => e.device) : []);
  tests.push({ name: "seven sources detected, none generic", pass: r.tables.sources.length === 7 && r.tables.sources.every((s) => s.format !== "generic") });
  tests.push({ name: "register has 18 devices", pass: r.summary.devices === 18 });
  tests.push({ name: "EDR missing: two Intune devices plus two directory-only devices", pass: names("edr_missing").join() === "DESKTOP-7KQ2M1P,OLD-DESK-07,WIN-DT-003,WIN-LT-007" });
  tests.push({ name: "RFM sensor flagged", pass: names("edr_unhealthy").includes("WIN-LT-004") });
  tests.push({ name: "unencrypted laptops critical", pass: names("encryption_laptop").join() === "MBP-U02,WIN-LT-003" && f("encryption_laptop").severity === "critical" });
  tests.push({ name: "Windows 10 22H2 and macOS 14 are EOL", pass: ["WIN-LT-008", "MBA-U03", "OLD-DESK-07", "WIN-LT-004"].every((n) => names("os_eol").includes(n)) });
  tests.push({ name: "Chrome 138 EOL on WIN-LT-005", pass: names("app_eol").includes("WIN-LT-005") });
  tests.push({ name: "AnyDesk on review list", pass: names("remote_access").join() === "WIN-LT-003" });
  tests.push({ name: "Jamf primary user admin", pass: names("local_admin").join() === "MBP-U02" });
  tests.push({ name: "Workstation Audit firewall fail matched by hostname", pass: names("firewall").includes("WIN-LT-002") });
  tests.push({ name: "stale enabled directory device high", pass: names("stale_enabled").includes("OLD-DESK-07") });
  tests.push({ name: "deterministic", pass: JSON.stringify(analyze(ex.files, { now: ex.now, eol: SELFTEST_EOL })) === JSON.stringify(r) });
  tests.push({ name: "empty input yields no findings", pass: analyze([]).findings.length === 0 });
  return { pass: tests.every((t) => t.pass), tests };
}
