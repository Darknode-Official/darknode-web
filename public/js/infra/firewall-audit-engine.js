// Firewall Rule Audit, pure engine. Parses network firewall rule-base exports
// (iptables/nftables, Cisco ASA/IOS ACLs, pfSense/OPNsense, FortiGate, Windows
// Firewall) into one normalized ordered rule list, then runs deterministic
// analyses: shadowed/redundant rules by real address+port containment, any-to-any
// permits, admin services exposed to any source, missing default deny, logging
// gaps, hygiene, broad egress. No DOM, no network. BigInt is used for addresses
// so IPv4 and IPv6 share one code path.
// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.

import { controlsFromRefs } from "../core/sink-map.js";

// ===========================================================================
// 1. Address library
// ===========================================================================
const V4_MAX = (1n << 32n) - 1n;
const V6_MAX = (1n << 128n) - 1n;

export function parseIPv4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(s || "").trim());
  if (!m) return null;
  let n = 0n;
  for (let i = 1; i <= 4; i++) { const o = Number(m[i]); if (o > 255) return null; n = (n << 8n) | BigInt(o); }
  return n;
}

export function parseIPv6(s) {
  s = String(s || "").trim().replace(/%.*$/, "");
  if (!s.includes(":")) return null;
  let head = s, tail = "";
  const dbl = s.indexOf("::");
  if (dbl >= 0) { head = s.slice(0, dbl); tail = s.slice(dbl + 2); if (tail.includes("::")) return null; }
  const expand = (str) => {
    if (str === "") return [];
    const arr = str.split(":"), out = [];
    for (let i = 0; i < arr.length; i++) {
      const p = arr[i];
      if (p.includes(".")) {
        if (i !== arr.length - 1) return null;
        const v4 = parseIPv4(p); if (v4 === null) return null;
        out.push(Number(v4 >> 16n), Number(v4 & 0xffffn));
      } else {
        if (!/^[0-9a-f]{1,4}$/i.test(p)) return null;
        out.push(parseInt(p, 16));
      }
    }
    return out;
  };
  const h = expand(head), t = expand(tail);
  if (!h || !t) return null;
  const total = h.length + t.length;
  if (dbl >= 0) { if (total > 7) return null; } else if (total !== 8) return null;
  const groups = dbl >= 0 ? [...h, ...new Array(8 - total).fill(0), ...t] : h;
  let n = 0n;
  for (const g of groups) n = (n << 16n) | BigInt(g);
  return n;
}

export function fmtIPv4(n) {
  n = BigInt(n);
  return [24n, 16n, 8n, 0n].map((sh) => String((n >> sh) & 0xffn)).join(".");
}

export function fmtIPv6(n) {
  n = BigInt(n);
  const g = [];
  for (let i = 7; i >= 0; i--) g.push(Number((n >> BigInt(i * 16)) & 0xffffn));
  // find longest zero run (len >= 2) to compress
  let best = -1, bestLen = 0;
  for (let i = 0; i < 8;) {
    if (g[i] !== 0) { i++; continue; }
    let j = i; while (j < 8 && g[j] === 0) j++;
    if (j - i > bestLen && j - i >= 2) { best = i; bestLen = j - i; }
    i = j;
  }
  const hex = (x) => x.toString(16);
  if (best < 0) return g.map(hex).join(":");
  const a = g.slice(0, best).map(hex).join(":"), b = g.slice(best + bestLen).map(hex).join(":");
  return a + "::" + b;
}

// Range: { v: 4|6, lo: BigInt, hi: BigInt }
export function mkRange(v, lo, hi) { return { v, lo: BigInt(lo), hi: BigInt(hi) }; }
export const V4_ALL = mkRange(4, 0n, V4_MAX);
export const V6_ALL = mkRange(6, 0n, V6_MAX);

export function isNetmask(s) {
  const n = parseIPv4(s); if (n === null) return false;
  // contiguous ones followed by zeros
  const inv = (~n) & V4_MAX;
  return ((inv + 1n) & inv) === 0n;
}
export function isWildcard(s) {
  const n = parseIPv4(s); if (n === null) return false;
  return ((n + 1n) & n) === 0n; // contiguous zeros then ones
}
function maskLen(n) { let len = 0; for (let i = 31n; i >= 0n; i--) { if ((n >> i) & 1n) len++; else break; } return len; }

export function rangeFromMask(ipStr, maskStr) {
  const ip = parseIPv4(ipStr), mask = parseIPv4(maskStr);
  if (ip === null || mask === null || !isNetmask(maskStr)) return null;
  return mkRange(4, ip & mask, (ip & mask) | (~mask & V4_MAX));
}
export function rangeFromWildcard(ipStr, wcStr) {
  const ip = parseIPv4(ipStr), wc = parseIPv4(wcStr);
  if (ip === null || wc === null) return null;
  if (!isWildcard(wcStr)) return null; // non-contiguous wildcards are not representable as a single range
  const mask = (~wc) & V4_MAX;
  return mkRange(4, ip & mask, (ip & mask) | wc);
}
export function rangeFromCidr(ipStr, len, v) {
  const bits = v === 4 ? 32n : 128n, max = v === 4 ? V4_MAX : V6_MAX;
  const ip = v === 4 ? parseIPv4(ipStr) : parseIPv6(ipStr);
  if (ip === null) return null;
  len = Number(len); if (!(len >= 0 && len <= Number(bits))) return null;
  const host = bits - BigInt(len);
  const mask = host === bits ? 0n : ((max >> host) << host) & max;
  return mkRange(v, ip & mask, (ip & mask) | (~mask & max));
}

// Parse one address token: any | A.B.C.D | A.B.C.D/n | A.B.C.D/M.M.M.M | A.B.C.D-E.F.G.H | v6 | v6/n
export function parseRange(s) {
  s = String(s || "").trim();
  if (!s) return null;
  if (/^(any|any4|\*|0\.0\.0\.0\/0|0\.0\.0\.0 0\.0\.0\.0)$/i.test(s)) return V4_ALL;
  if (/^(any6|::\/0)$/i.test(s)) return V6_ALL;
  let m;
  if ((m = /^(\d+\.\d+\.\d+\.\d+)\/(\d+\.\d+\.\d+\.\d+)$/.exec(s))) return rangeFromMask(m[1], m[2]);
  if ((m = /^(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})$/.exec(s))) return rangeFromCidr(m[1], m[2], 4);
  if ((m = /^(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)$/.exec(s))) return rangeFromMask(m[1], m[2]);
  if ((m = /^(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)$/.exec(s))) {
    const a = parseIPv4(m[1]), b = parseIPv4(m[2]);
    if (a === null || b === null || b < a) return null;
    return mkRange(4, a, b);
  }
  if (/^\d+\.\d+\.\d+\.\d+$/.test(s)) { const a = parseIPv4(s); return a === null ? null : mkRange(4, a, a); }
  if ((m = /^([0-9a-f:.]+)\/(\d{1,3})$/i.exec(s)) && s.includes(":")) return rangeFromCidr(m[1], m[2], 6);
  if (s.includes(":")) { const a = parseIPv6(s); return a === null ? null : mkRange(6, a, a); }
  return null;
}

export function rangeContains(a, b) { return a.v === b.v && a.lo <= b.lo && a.hi >= b.hi; }
export function rangeOverlaps(a, b) { return a.v === b.v && a.lo <= b.hi && b.lo <= a.hi; }
export function rangeSize(r) { return r.hi - r.lo + 1n; }

export function mergeRanges(list) {
  const s = list.slice().sort((x, y) => x.v - y.v || (x.lo < y.lo ? -1 : x.lo > y.lo ? 1 : 0));
  const out = [];
  for (const r of s) {
    const last = out[out.length - 1];
    if (last && last.v === r.v && r.lo <= last.hi + 1n) { if (r.hi > last.hi) last.hi = r.hi; }
    else out.push({ v: r.v, lo: r.lo, hi: r.hi });
  }
  return out;
}
export function rangesCover(list, r) {
  for (const m of mergeRanges(list)) if (rangeContains(m, r)) return true;
  return false;
}

export function fmtRange(r) {
  if (!r) return "?";
  const bits = r.v === 4 ? 32n : 128n, fmt = r.v === 4 ? fmtIPv4 : fmtIPv6;
  if (r.lo === r.hi) return fmt(r.lo);
  const size = rangeSize(r);
  if ((size & (size - 1n)) === 0n && r.lo % size === 0n) {
    let host = 0n; while ((1n << host) < size) host++;
    const len = bits - host;
    if (len === 0n) return r.v === 4 ? "0.0.0.0/0" : "::/0";
    return fmt(r.lo) + "/" + String(len);
  }
  return fmt(r.lo) + "-" + fmt(r.hi);
}

// Address set: { any, ranges[], symbols[], unresolved[], negated, text }
export function addrSet(opts) {
  const s = { any: false, ranges: [], symbols: [], unresolved: [], negated: false, text: "", ...opts };
  if (!s.text) s.text = describeAddr(s);
  return s;
}
export const ANY_ADDR = () => addrSet({ any: true, text: "any" });
export function isAnyAddr(a) {
  if (!a) return false;
  if (a.negated) return false;
  if (a.any) return true;
  return rangesCover(a.ranges, V4_ALL) || rangesCover(a.ranges, V6_ALL);
}
export function addrUnknown(a) { return !a || a.unresolved.length > 0; }
export function addrContains(a, b) {
  if (!a || !b) return false;
  if (a.negated || b.negated) return a.negated && b.negated && a.text === b.text;
  if (addrUnknown(a) || addrUnknown(b)) return false;
  if (isAnyAddr(a)) return true;
  if (isAnyAddr(b)) return false;
  const asyms = a.symbols.map((x) => x.toLowerCase());
  for (const sym of b.symbols) if (!asyms.includes(sym.toLowerCase())) return false;
  for (const r of b.ranges) if (!rangesCover(a.ranges, r)) return false;
  return true;
}
export function addrOverlaps(a, b) {
  if (!a || !b) return false;
  if (a.negated || b.negated || addrUnknown(a) || addrUnknown(b)) return true; // can't exclude
  if (isAnyAddr(a) || isAnyAddr(b)) return true;
  if (a.symbols.length && b.symbols.length) {
    const bs = b.symbols.map((x) => x.toLowerCase());
    if (a.symbols.some((x) => bs.includes(x.toLowerCase()))) return true;
  }
  for (const x of a.ranges) for (const y of b.ranges) if (rangeOverlaps(x, y)) return true;
  return false;
}
export function describeAddr(a) {
  if (!a) return "?";
  if (a.any && !a.negated) return "any";
  const parts = [...a.ranges.map(fmtRange), ...a.symbols, ...a.unresolved.map((u) => u + " (unresolved)")];
  if (a.any) parts.unshift("any");
  return (a.negated ? "NOT " : "") + (parts.join(", ") || "(empty)");
}
// Is this set entirely inside the internal ranges (or made of internal symbols)?
const INTERNAL_SYMBOLS = /^(lan( net| address)?|lan\d+( net)?|opt\d+( net| address)?|localsubnet|intranet|inside|internal|private|trust(ed)?|dmz|this firewall \(self\)|\(self\)|lanip|wanip|wan address|dns|dhcp|wins|defaultgateway|lo)$/i;
export function addrIsInternal(a, internal) {
  if (!a || a.negated || a.any || addrUnknown(a)) return false;
  if (!a.ranges.length && !a.symbols.length) return false;
  for (const r of a.ranges) if (!rangesCover(internal, r)) return false;
  for (const s of a.symbols) if (!INTERNAL_SYMBOLS.test(s)) return false;
  return true;
}
// Total address count of ranges outside the internal set (BigInt). Used for the
// "broad external source" heuristic.
export function externalSize(a, internal) {
  if (!a || a.negated || addrUnknown(a)) return 0n;
  if (a.any) return V4_MAX + 1n;
  let n = 0n;
  const merged = mergeRanges(a.ranges);
  const intl = mergeRanges(internal);
  for (const r of merged) {
    let size = rangeSize(r);
    for (const i of intl) if (rangeOverlaps(i, r)) {
      const lo = i.lo > r.lo ? i.lo : r.lo, hi = i.hi < r.hi ? i.hi : r.hi;
      size -= (hi - lo + 1n);
    }
    if (size > 0n) n += size;
  }
  return n;
}

export const DEFAULT_INTERNAL = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "127.0.0.0/8", "::1/128", "169.254.0.0/16", "fe80::/10"];
export function parseInternalList(list) {
  const out = [], bad = [];
  for (const raw of Array.isArray(list) ? list : String(list || "").split(/[\n,;]+/)) {
    const s = raw.trim(); if (!s || s.startsWith("#")) continue;
    const r = parseRange(s); if (r) out.push(r); else bad.push(s);
  }
  return { ranges: out, bad };
}

// ===========================================================================
// 2. Ports and services
// ===========================================================================
export const SERVICES = {
  ssh: 22, rdp: 3389, smb: 445, "microsoft-ds": 445, cifs: 445, "netbios-ssn": 139, "netbios-ns": 137, "netbios-dgm": 138,
  telnet: 23, ftp: 21, "ftp-data": 20, smtp: 25, smtps: 465, submission: 587, dns: 53, domain: 53, http: 80, www: 80, https: 443,
  mysql: 3306, mssql: 1433, "ms-sql-s": 1433, "ms-sql-m": 1434, postgres: 5432, postgresql: 5432, oracle: 1521, sqlnet: 1521,
  mongodb: 27017, mongo: 27017, redis: 6379, elasticsearch: 9200, memcached: 11211, winrm: 5985, "winrm-https": 5986, "wsman": 5985,
  vnc: 5900, snmp: 161, snmptrap: 162, ldap: 389, ldaps: 636, docker: 2375, "docker-tls": 2376, "kube-api": 6443, kubernetes: 6443,
  etcd: 2379, nfs: 2049, rpc: 135, epmap: 135, "msrpc": 135, ntp: 123, pop3: 110, pop3s: 995, imap: 143, imap4: 143, imaps: 993,
  tftp: 69, syslog: 514, radius: 1812, kerberos: 88, bootps: 67, bootpc: 68, nntp: 119, lpd: 515, pptp: 1723, "citrix-ica": 1494,
  h323: 1720, sip: 5060, ike: 500, isakmp: 500, "ipsec-nat-t": 4500, rsh: 514, rlogin: 513, exec: 512, finger: 79, gopher: 70,
  whois: 43, irc: 194, echo: 7, discard: 9, daytime: 13, chargen: 19, time: 37, biff: 512, who: 513, talk: 517, klogin: 543,
  kshell: 544, cmd: 514, "pim-auto-rp": 496, tacacs: 49, "aol": 5190, "ctiqbe": 2748, "sqlserver": 1433,
};

// Risky / admin services that should never be reachable from "any".
export const RISKY = [
  { id: "telnet", label: "Telnet", proto: "tcp", ports: [[23, 23]], sev: "critical", attack: "T1021, T1133", why: "cleartext remote shell; credentials are sniffable and brute-forceable" },
  { id: "rdp", label: "RDP", proto: "tcp", ports: [[3389, 3389]], sev: "critical", attack: "T1021.001, T1133", why: "the most common ransomware entry point (brute force, credential stuffing, BlueKeep-class bugs)" },
  { id: "smb", label: "SMB", proto: "tcp", ports: [[445, 445], [139, 139]], sev: "critical", attack: "T1021.002, T1210", why: "worm propagation (EternalBlue), credential relay, lateral movement" },
  { id: "netbios", label: "NetBIOS", proto: "udp", ports: [[137, 138]], sev: "high", attack: "T1021.002", why: "name/datagram service leaks host names and supports relay attacks" },
  { id: "rpc", label: "MS-RPC", proto: "tcp", ports: [[135, 135]], sev: "critical", attack: "T1021.003, T1047", why: "DCOM/WMI endpoint mapper; remote execution surface" },
  { id: "winrm", label: "WinRM", proto: "tcp", ports: [[5985, 5986]], sev: "critical", attack: "T1021.006", why: "remote PowerShell management interface" },
  { id: "vnc", label: "VNC", proto: "tcp", ports: [[5900, 5910]], sev: "critical", attack: "T1021.005", why: "remote desktop, often without strong auth or encryption" },
  { id: "ssh", label: "SSH", proto: "tcp", ports: [[22, 22]], sev: "high", attack: "T1021.004, T1110", why: "admin shell; constant password brute force from the internet" },
  { id: "ftp", label: "FTP", proto: "tcp", ports: [[21, 21]], sev: "high", attack: "T1190, T1110", why: "cleartext credentials; anonymous upload abuse" },
  { id: "mysql", label: "MySQL/MariaDB", proto: "tcp", ports: [[3306, 3306]], sev: "critical", attack: "T1190, T1110", why: "database exposed to the internet; data theft" },
  { id: "mssql", label: "MS SQL", proto: "tcp", ports: [[1433, 1434]], sev: "critical", attack: "T1190, T1110", why: "database exposed; xp_cmdshell gives code execution" },
  { id: "postgres", label: "PostgreSQL", proto: "tcp", ports: [[5432, 5432]], sev: "critical", attack: "T1190, T1110", why: "database exposed to the internet" },
  { id: "oracle", label: "Oracle TNS", proto: "tcp", ports: [[1521, 1521]], sev: "critical", attack: "T1190", why: "database listener exposed" },
  { id: "mongodb", label: "MongoDB", proto: "tcp", ports: [[27017, 27019]], sev: "critical", attack: "T1190", why: "frequently unauthenticated; mass data-wipe campaigns" },
  { id: "redis", label: "Redis", proto: "tcp", ports: [[6379, 6379]], sev: "critical", attack: "T1190", why: "unauthenticated by default; trivial remote code execution" },
  { id: "elasticsearch", label: "Elasticsearch", proto: "tcp", ports: [[9200, 9200], [9300, 9300]], sev: "critical", attack: "T1190", why: "unauthenticated search index; data leaks" },
  { id: "memcached", label: "Memcached", proto: "any", ports: [[11211, 11211]], sev: "critical", attack: "T1190, T1498", why: "no auth; used as a DDoS amplifier" },
  { id: "docker", label: "Docker API", proto: "tcp", ports: [[2375, 2376]], sev: "critical", attack: "T1190, T1610", why: "remote API gives root on the host" },
  { id: "kube-api", label: "Kubernetes API", proto: "tcp", ports: [[6443, 6443]], sev: "critical", attack: "T1190, T1609", why: "cluster control plane exposed" },
  { id: "etcd", label: "etcd", proto: "tcp", ports: [[2379, 2380]], sev: "critical", attack: "T1190, T1552", why: "cluster secrets store, often unauthenticated" },
  { id: "nfs", label: "NFS", proto: "any", ports: [[2049, 2049]], sev: "high", attack: "T1021, T1039", why: "file shares exposed; weak host-based auth" },
  { id: "snmp", label: "SNMP", proto: "udp", ports: [[161, 162]], sev: "high", attack: "T1016, T1046", why: "default community strings leak device config; v1/v2c are cleartext" },
  { id: "ldap", label: "LDAP", proto: "tcp", ports: [[389, 389], [636, 636]], sev: "high", attack: "T1087, T1498", why: "directory enumeration; LDAP amplification" },
  { id: "smtp", label: "SMTP", proto: "tcp", ports: [[25, 25]], sev: "medium", attack: "T1566", why: "fine for a mail server; otherwise relay abuse and spoofing" },
  { id: "dns", label: "DNS", proto: "any", ports: [[53, 53]], sev: "medium", attack: "T1498, T1071.004", why: "open resolver abuse and amplification unless this is an authoritative server" },
];

export function portsFromToken(tok) {
  // returns [[lo,hi]] or null when unresolved
  tok = String(tok || "").trim().toLowerCase();
  if (!tok) return null;
  let m;
  if ((m = /^(\d+)\s*(?:-|:|\s+to\s+)\s*(\d+)$/.exec(tok))) {
    const a = +m[1], b = +m[2]; if (a > 65535 || b > 65535 || a > b) return null; return [[a, b]];
  }
  if ((m = /^(\d+)\s*(?:\(|$)/.exec(tok))) { const a = +m[1]; return a > 65535 ? null : [[a, a]]; }
  // iptables open-ended ranges: "1024:" = 1024-65535, ":1023" = 0-1023 (were unresolved)
  if ((m = /^(\d+):$/.exec(tok))) { const a = +m[1]; return a > 65535 ? null : [[a, 65535]]; }
  if ((m = /^:(\d+)$/.exec(tok))) { const b = +m[1]; return b > 65535 ? null : [[0, b]]; }
  if (SERVICES[tok] != null) { const p = SERVICES[tok]; return [[p, p]]; }
  return null;
}

// Port set: { any, ranges: [[lo,hi]], unresolved: [str], text }
export function portSet(opts) {
  const s = { any: false, ranges: [], unresolved: [], text: "", ...opts };
  if (!s.text) s.text = describePorts(s);
  return s;
}
export const ANY_PORTS = () => portSet({ any: true, text: "any" });
// Cisco port operator -> ranges ("gt 1023" -> 1024-65535); null when the port can't be read
function ciscoOpPorts(op, tok) {
  const a = portsFromToken(tok); if (!a) return null;
  const lo = a[0][0], hi = a[0][1];
  if (op === "gt") return hi < 65535 ? [[hi + 1, 65535]] : [];
  if (op === "lt") return lo > 0 ? [[0, lo - 1]] : [];
  if (op === "neq") return [[0, lo - 1], [hi + 1, 65535]].filter((r) => r[0] <= r[1]);
  return a;
}
export function parsePortSpec(spec) {
  // "22", "22-80", "22:80", "22,80,443", "ssh", "*", "any"
  const str = String(spec == null ? "" : spec).trim();
  if (!str || /^(any|\*|all|0-65535|1-65535)$/i.test(str)) return ANY_PORTS();
  const ranges = [], unresolved = [];
  for (const part of str.split(/[,\s]+/).filter(Boolean)) {
    const r = portsFromToken(part);
    if (r) ranges.push(...r); else unresolved.push(part);
  }
  return portSet({ ranges, unresolved, text: str });
}
export function mergePorts(list) {
  const s = list.slice().sort((a, b) => a[0] - b[0]);
  const out = [];
  for (const r of s) {
    const last = out[out.length - 1];
    if (last && r[0] <= last[1] + 1) { if (r[1] > last[1]) last[1] = r[1]; } else out.push([r[0], r[1]]);
  }
  return out;
}
export function portsCover(list, r) { return mergePorts(list).some((m) => m[0] <= r[0] && m[1] >= r[1]); }
export function portsContain(a, b) {
  if (!a || !b) return false;
  if (a.unresolved.length || b.unresolved.length) return false;
  if (a.any) return true;
  if (b.any) return false;
  return b.ranges.every((r) => portsCover(a.ranges, r));
}
export function portsOverlap(a, b) {
  if (!a || !b) return false;
  if (a.unresolved.length || b.unresolved.length) return true;
  if (a.any || b.any) return true;
  return a.ranges.some((x) => b.ranges.some((y) => x[0] <= y[1] && y[0] <= x[1]));
}
export function describePorts(p) {
  if (!p) return "?";
  if (p.any) return "any";
  const parts = p.ranges.map((r) => (r[0] === r[1] ? String(r[0]) : r[0] + "-" + r[1]));
  parts.push(...p.unresolved.map((u) => u + " (unresolved)"));
  return parts.join(", ") || "(none)";
}

export function normProto(p) {
  p = String(p == null ? "" : p).trim().toLowerCase();
  if (!p || /^(any|all|ip|\*|0|ipv4|ipv6|ip4|ip6)$/.test(p)) return "any";
  if (/^(tcp\/udp|tcp-udp|udp\/tcp|tcp_udp)$/.test(p)) return "tcp/udp";
  if (/^(tcp|6)$/.test(p)) return "tcp";
  if (/^(udp|17)$/.test(p)) return "udp";
  if (/^(icmp|1|icmpv4|icmp4)$/.test(p)) return "icmp";
  if (/^(icmpv6|ipv6-icmp|icmp6|58)$/.test(p)) return "icmpv6";
  return p;
}
export function protoContains(a, b) {
  if (a === "any") return true;
  if (a === b) return true;
  if (a === "tcp/udp" && (b === "tcp" || b === "udp")) return true;
  return false;
}
export function protoOverlaps(a, b) { return protoContains(a, b) || protoContains(b, a); }
function protoHasPorts(p) { return p === "tcp" || p === "udp" || p === "tcp/udp" || p === "any" || p === "sctp"; }

// ===========================================================================
// 3. Normalized rule model
// ===========================================================================
let RULE_SEQ = 0;
export function mkRule(o) {
  const r = {
    idx: 0, lineNo: o.lineNo || 0, raw: o.raw || "", format: o.format || "", scope: o.scope || "",
    name: o.name || "", action: o.action || "other", target: o.target || "",
    direction: o.direction || "any", chain: o.chain || "", iface: o.iface || "",
    srcZones: o.srcZones || null, dstZones: o.dstZones || null, profiles: o.profiles || null,
    proto: o.proto || "any", src: o.src || ANY_ADDR(), srcPorts: o.srcPorts || ANY_PORTS(),
    dst: o.dst || ANY_ADDR(), dstPorts: o.dstPorts || ANY_PORTS(),
    enabled: o.enabled !== false, log: o.log === undefined ? null : o.log,
    state: o.state || null, restricted: !!o.restricted, facing: o.facing || "unknown",
    unresolved: o.unresolved || [], notes: o.notes || [],
  };
  r.terminal = r.action === "allow" || r.action === "deny" || r.action === "reject";
  r.unresolved = [...new Set([...r.unresolved, ...r.src.unresolved, ...r.dst.unresolved, ...r.srcPorts.unresolved, ...r.dstPorts.unresolved])];
  return r;
}

function zonesContain(a, b) {
  if (!a) return true; if (!b) return false;
  const al = a.map((z) => z.toLowerCase());
  if (al.includes("any")) return true;
  return b.every((z) => al.includes(z.toLowerCase()));
}
// Does rule a's match set include every packet rule b matches? Conservative:
// anything we cannot model (restricted a, unresolved objects, negation) is "no".
export function matchContains(a, b) {
  if (a.scope !== b.scope) return false;
  if (a.restricted) return false;
  if (a.state && a.state !== b.state) return false;
  if (!zonesContain(a.srcZones, b.srcZones) || !zonesContain(a.dstZones, b.dstZones)) return false;
  if (!zonesContain(a.profiles, b.profiles)) return false;
  if (!protoContains(a.proto, b.proto)) return false;
  if (!addrContains(a.src, b.src) || !addrContains(a.dst, b.dst)) return false;
  if (!portsContain(a.srcPorts, b.srcPorts) || !portsContain(a.dstPorts, b.dstPorts)) return false;
  return true;
}

const EXTERNAL_IF = /\b(wan\d*|outside|internet|untrust(ed)?|external|ext\d*|public|isp|uplink)\b/i;
const INTERNAL_IF = /\b(lan\d*|inside|internal|trust(ed)?|private|mgmt|management|opt\d+|dmz|lo|loopback|vlan\d*|guest|servers?)\b/i;
export function classifyIface(name) {
  if (!name) return "unknown";
  if (/^lo\d*$|^loopback$/i.test(name)) return "loopback";
  if (EXTERNAL_IF.test(name)) return "external";
  if (INTERNAL_IF.test(name)) return "internal";
  return "unknown";
}

// ===========================================================================
// 4. Parsers
// ===========================================================================
function tokenize(line) {
  const out = []; let cur = "", q = null;
  for (const ch of line) {
    if (q) { if (ch === q) q = null; else cur += ch; continue; }
    if (ch === '"' || ch === "'") { q = ch; continue; }
    if (/\s/.test(ch)) { if (cur) { out.push(cur); cur = ""; } continue; }
    cur += ch;
  }
  if (cur) out.push(cur);
  return out;
}
function lines(text) { return String(text || "").replace(/\r\n?/g, "\n").split("\n"); }

function addrFromTokens(tokens, opts = {}) {
  // tokens: list of address strings; resolve(name) -> addrSet-like or null
  const set = addrSet({ negated: !!opts.negated, text: opts.text || tokens.join(", ") });
  for (const t0 of tokens) {
    const t = String(t0).trim(); if (!t) continue;
    if (/^(any|any4|any6|all|\*)$/i.test(t)) { set.any = true; continue; }
    const r = parseRange(t);
    if (r) { set.ranges.push(r); continue; }
    const res = opts.resolve ? opts.resolve(t) : null;
    if (res) {
      if (res.any) set.any = true;
      set.ranges.push(...(res.ranges || [])); set.symbols.push(...(res.symbols || [])); set.unresolved.push(...(res.unresolved || []));
      continue;
    }
    if (opts.symbol && opts.symbol(t)) { set.symbols.push(t); continue; }
    set.unresolved.push(t);
  }
  return set;
}

// ---------------------------------------------------------------- iptables
export function parseIptables(text) {
  const rules = [], policies = {}, notes = [], chains = new Set(["INPUT", "OUTPUT", "FORWARD"]);
  let table = "filter", skipped = 0, lineNo = 0;
  const pending = [];
  for (const raw of lines(text)) {
    lineNo++;
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    let m;
    if ((m = /^\*(\w+)/.exec(line))) { table = m[1]; continue; }
    if (line === "COMMIT") continue;
    if ((m = /^:(\S+)\s+(ACCEPT|DROP|REJECT|-)/.exec(line))) { if (table === "filter") { policies[m[1]] = m[2]; chains.add(m[1]); } continue; }
    const tk = tokenize(line.replace(/^(iptables|ip6tables)(\s+-w\s*\d*)?\s+/, ""));
    if (!tk.length) continue;
    if (tk[0] === "-t") { table = tk[1]; tk.splice(0, 2); }
    if (tk[0] === "-P" || tk[0] === "--policy") { if (table === "filter") policies[tk[1]] = tk[2]; continue; }
    if (tk[0] === "-N" || tk[0] === "--new-chain") { chains.add(tk[1]); continue; }
    if (tk[0] !== "-A" && tk[0] !== "-I" && tk[0] !== "--append" && tk[0] !== "--insert") continue;
    if (table !== "filter") { skipped++; continue; }
    const chain = tk[1];
    let i = 2;
    if (tk[0] === "-I" && /^\d+$/.test(tk[i] || "")) i++;
    const r = { chain, proto: "any", srcTok: [], dstTok: [], srcNeg: false, dstNeg: false, sp: null, dp: null, iface: "", oface: "", state: null, target: "", name: "", restricted: false, logPrefix: "" };
    let neg = false;
    const ZERO = new Set(["--syn", "-f", "--fragment", "--rcheck", "--set", "--update", "--remove", "--rdest", "--rsource", "--reap", "--rttl", "--log-tcp-sequence", "--log-tcp-options", "--log-ip-options", "--log-uid", "--nflog-group", "--notrack", "--random", "--persistent", "--ecn-tcp-remove", "--clamp-mss-to-pmtu"]);
    while (i < tk.length) {
      const t = tk[i];
      if (t === "!") { neg = true; i++; continue; }
      const val = tk[i + 1];
      switch (t) {
        case "-s": case "--source": case "--src": r.srcTok = (val || "").split(","); r.srcNeg = neg; i += 2; break;
        case "-d": case "--destination": case "--dst": r.dstTok = (val || "").split(","); r.dstNeg = neg; i += 2; break;
        case "-p": case "--protocol": r.proto = normProto(val); if (neg) r.restricted = true; i += 2; break;
        case "-i": case "--in-interface": r.iface = val || ""; if (neg) r.restricted = true; i += 2; break;
        case "-o": case "--out-interface": r.oface = val || ""; if (neg) r.restricted = true; i += 2; break;
        case "--dport": case "--destination-port": case "--dports": case "--destination-ports": r.dp = val; if (neg) r.restricted = true; i += 2; break;
        // -m iprange: the source/destination was read as ANY
        case "--src-range": r.srcTok = [val || ""]; r.srcNeg = neg; i += 2; break;
        case "--dst-range": r.dstTok = [val || ""]; r.dstNeg = neg; i += 2; break;
        case "--sport": case "--source-port": case "--sports": case "--source-ports": r.sp = val; if (neg) r.restricted = true; i += 2; break;
        case "--ports": r.dp = val; r.sp = val; i += 2; break;
        case "-m": case "--match": {
          if (!["multiport", "state", "conntrack", "comment", "tcp", "udp", "icmp", "icmp6", "ipv6-icmp", "iprange"].includes(val)) r.restricted = true;
          i += 2; break;
        }
        case "--state": case "--ctstate": {
          const st = (val || "").toUpperCase().split(",");
          if (st.includes("NEW")) r.state = null; else if (st.includes("ESTABLISHED") || st.includes("RELATED")) r.state = "established"; else r.state = st.join(",").toLowerCase();
          i += 2; break;
        }
        case "--comment": r.name = val || ""; i += 2; break;
        case "-j": case "--jump": case "-g": case "--goto": r.target = val || ""; i += 2; break;
        case "--log-prefix": r.logPrefix = val || ""; i += 2; break;
        case "--tcp-flags": r.restricted = true; i += 3; break;
        default:
          if (ZERO.has(t)) { if (t === "--syn" || t === "-f" || t === "--fragment") r.restricted = true; i++; break; }
          if (t.startsWith("-")) { r.restricted = true; i += (val && !val.startsWith("-")) ? 2 : 1; break; }
          i++;
      }
      neg = false;
    }
    const T = r.target.toUpperCase();
    let action = "jump";
    if (T === "ACCEPT") action = "allow"; else if (T === "DROP") action = "deny"; else if (T === "REJECT") action = "reject";
    else if (T === "LOG" || T === "NFLOG" || T === "ULOG") action = "log"; else if (T === "RETURN") action = "other"; else if (!T) action = "other";
    const dir = chain === "INPUT" ? "in" : chain === "OUTPUT" ? "out" : "any";
    let facing = "unknown";
    if (r.iface) facing = classifyIface(r.iface); else if (dir === "in" || chain === "FORWARD") facing = "unknown";
    const src = addrFromTokens(r.srcTok, { negated: r.srcNeg });
    if (!r.srcTok.length) src.any = true;
    const dst = addrFromTokens(r.dstTok, { negated: r.dstNeg });
    if (!r.dstTok.length) dst.any = true;
    const rule = mkRule({
      lineNo, raw: line, format: "iptables", scope: table + ":" + chain, name: r.name, action, target: r.target,
      direction: dir, chain, iface: [r.iface && "in " + r.iface, r.oface && "out " + r.oface].filter(Boolean).join(", "),
      srcZones: r.iface ? [r.iface] : null, dstZones: r.oface ? [r.oface] : null,
      proto: r.proto, src, dst, srcPorts: r.sp ? parsePortSpec(r.sp) : ANY_PORTS(), dstPorts: r.dp ? parsePortSpec(r.dp) : ANY_PORTS(),
      enabled: true, log: null, state: r.state, restricted: r.restricted, facing,
    });
    rules.push(rule);
  }
  // logging: a DROP/REJECT/ACCEPT rule counts as logged when a LOG rule earlier in
  // the same chain matches at least everything this rule matches.
  for (let j = 0; j < rules.length; j++) {
    const rj = rules[j];
    if (!rj.terminal) continue;
    let logged = false;
    for (let i = j - 1; i >= 0; i--) {
      const ri = rules[i];
      if (ri.scope !== rj.scope) continue;
      if (ri.action === "log" && matchContains(ri, rj)) { logged = true; break; }
      if (ri.terminal && matchContains(ri, rj)) break;
    }
    rj.log = logged;
  }
  if (skipped) notes.push(`${skipped} rule(s) in non-filter tables (nat/mangle/raw) were ignored; only the filter table is audited.`);
  if (!Object.keys(policies).length) notes.push("No chain policies found (:INPUT ACCEPT / -P INPUT DROP). Default-deny checks assume the policy is unknown.");
  return { format: "iptables", label: "iptables / ip6tables", partial: false, rules, policies, implicitDeny: false, ordered: true, notes, chains: [...chains] };
}

// ---------------------------------------------------------------- nftables (partial)
export function parseNft(text) {
  const rules = [], policies = {}, hooks = {}, notes = [];
  let table = "", family = "", chain = "", depth = 0, lineNo = 0;
  const chainDepth = {};
  for (const raw of lines(text)) {
    lineNo++;
    const line = raw.trim().replace(/#.*$/, "").trim();
    if (!line) continue;
    let m;
    if ((m = /^table\s+(inet|ip|ip6|bridge|arp|netdev)\s+(\S+)\s*\{?/.exec(line))) { family = m[1]; table = m[2]; depth++; continue; }
    if ((m = /^chain\s+(\S+)\s*\{?/.exec(line))) { chain = m[1]; depth++; chainDepth[chain] = depth; continue; }
    if (line === "}") { if (chain && chainDepth[chain] === depth) chain = ""; depth--; continue; }
    if (!chain) continue;
    if (/^type\s+\w+\s+hook/.test(line) || /^policy\s+/.test(line)) {
      const h = /hook\s+(\w+)/.exec(line); if (h) hooks[chain] = h[1];
      const p = /policy\s+(accept|drop)/.exec(line); if (p) policies[chain] = p[1].toUpperCase();
      continue;
    }
    // rule line
    const tk = tokenize(line.replace(/;$/, ""));
    const r = { proto: "any", src: null, dst: null, sp: null, dp: null, iif: "", oif: "", state: null, log: false, name: "", restricted: false, action: "", target: "" };
    const readSet = (i) => { // returns [tokens, nextIndex]
      if (tk[i] === "{") { const out = []; i++; while (i < tk.length && tk[i] !== "}") { out.push(tk[i].replace(/,$/, "")); i++; } return [out.filter(Boolean), i + 1]; }
      return [[tk[i]], i + 1];
    };
    let i = 0;
    while (i < tk.length) {
      const t = tk[i], n = tk[i + 1];
      if ((t === "ip" || t === "ip6") && (n === "saddr" || n === "daddr")) {
        let neg = false, j = i + 2; if (tk[j] === "!=") { neg = true; j++; }
        const [vals, nx] = readSet(j);
        const set = addrFromTokens(vals, { negated: neg, text: vals.join(", ") });
        if (n === "saddr") r.src = set; else r.dst = set; i = nx; continue;
      }
      if ((t === "ip" && n === "protocol") || (t === "meta" && n === "l4proto")) { const [vals, nx] = readSet(i + 2); r.proto = vals.length === 1 ? normProto(vals[0]) : (vals.every((v) => /^(tcp|udp)$/.test(v)) ? "tcp/udp" : "any"); if (vals.length > 1 && r.proto === "any") r.restricted = true; i = nx; continue; }
      if ((t === "tcp" || t === "udp" || t === "sctp") && (n === "dport" || n === "sport")) {
        r.proto = r.proto === "any" || r.proto === t ? t : "tcp/udp";
        let j = i + 2; if (tk[j] === "!=") { r.restricted = true; j++; }
        const [vals, nx] = readSet(j);
        const spec = vals.join(",");
        if (n === "dport") r.dp = spec; else r.sp = spec; i = nx; continue;
      }
      if (t === "th" && (n === "dport" || n === "sport")) { const [vals, nx] = readSet(i + 2); if (n === "dport") r.dp = vals.join(","); else r.sp = vals.join(","); i = nx; continue; }
      if (t === "iif" || t === "iifname") { const [vals, nx] = readSet(i + 1); r.iif = vals[0] || ""; i = nx; continue; }
      if (t === "oif" || t === "oifname") { const [vals, nx] = readSet(i + 1); r.oif = vals[0] || ""; i = nx; continue; }
      if (t === "ct" && n === "state") { const [vals, nx] = readSet(i + 2); const st = vals.join(",").toLowerCase(); r.state = st.includes("new") ? null : (/(established|related)/.test(st) ? "established" : st); i = nx; continue; }
      if (t === "log") { r.log = true; i++; if (tk[i] === "prefix") i += 2; if (tk[i] === "level") i += 2; if (tk[i] === "flags") i += 2; continue; }
      if (t === "counter") { i++; if (tk[i] === "packets") i += 4; continue; }
      if (t === "comment") { r.name = n || ""; i += 2; continue; }
      if (t === "accept" || t === "drop" || t === "reject" || t === "return") { r.action = t; i++; if (t === "reject" && tk[i] === "with") i += 3; continue; }
      if (t === "jump" || t === "goto") { r.action = "jump"; r.target = n || ""; i += 2; continue; }
      if (t === "icmp" || t === "icmpv6" || t === "ip6" || t === "meta" || t === "limit" || t === "fib" || t === "tcp" || t === "ip") { r.restricted = true; i += 1; continue; }
      r.restricted = true; i++;
    }
    if (!r.action) continue;
    const hook = hooks[chain] || "";
    const dir = hook === "input" ? "in" : hook === "output" ? "out" : "any";
    const action = r.action === "accept" ? "allow" : r.action === "drop" ? "deny" : r.action === "reject" ? "reject" : r.action === "jump" ? "jump" : "other";
    const src = r.src || ANY_ADDR(), dst = r.dst || ANY_ADDR();
    rules.push(mkRule({
      lineNo, raw: line, format: "nft", scope: `${family} ${table}:${chain}`, name: r.name, action, target: r.target, direction: dir, chain,
      iface: [r.iif && "in " + r.iif, r.oif && "out " + r.oif].filter(Boolean).join(", "), srcZones: r.iif ? [r.iif] : null, dstZones: r.oif ? [r.oif] : null,
      proto: r.proto, src, dst, srcPorts: r.sp ? parsePortSpec(r.sp) : ANY_PORTS(), dstPorts: r.dp ? parsePortSpec(r.dp) : ANY_PORTS(),
      log: r.log, state: r.state, restricted: r.restricted, facing: r.iif ? classifyIface(r.iif) : "unknown",
    }));
  }
  notes.push("nftables support is partial: saddr/daddr, tcp/udp dport/sport, sets in braces, iif/oif, ct state, log and verdicts are modelled; maps, vmaps, named sets and other expressions mark a rule as restricted (never used as a shadowing rule).");
  return { format: "nft", label: "nftables (partial)", partial: true, rules, policies, hooks, implicitDeny: false, ordered: true, notes };
}

// ---------------------------------------------------------------- Cisco ASA / IOS
const CISCO_IP_PROTOS = /^(ip|tcp|udp|icmp|icmp6|esp|ah|ahp|gre|ospf|eigrp|pim|igmp|igrp|nos|pcp|snp|ipinip|ipsec|sctp|\d+)$/i;
function ciscoPortTok(t) { return /^\d+$/.test(t) || SERVICES[t.toLowerCase()] != null; }

export function parseCisco(text) {
  const notes = [], netObjs = {}, svcObjs = {}, bindings = {}, remarks = {}, rules = [];
  let cur = null, lineNo = 0, iosBlock = null, curIface = null;
  const L = lines(text);
  // pass 1: objects + bindings
  for (let k = 0; k < L.length; k++) {
    const raw = L[k]; const line = raw.trim(); if (!line || line.startsWith("!")) { continue; }
    const indented = /^\s/.test(raw);
    let m;
    if (!indented) {
      cur = null; curIface = null;
      if ((m = /^object-group network (\S+)/.exec(line))) { cur = netObjs[m[1]] = netObjs[m[1]] || { items: [] }; continue; }
      if ((m = /^object network (\S+)/.exec(line))) { cur = netObjs[m[1]] = netObjs[m[1]] || { items: [] }; continue; }
      if ((m = /^object-group service (\S+)(?:\s+(tcp|udp|tcp-udp))?/.exec(line))) { cur = svcObjs[m[1]] = svcObjs[m[1]] || { proto: m[2] ? normProto(m[2]) : null, ports: [], items: [], unresolved: [] }; continue; }
      if ((m = /^object service (\S+)/.exec(line))) { cur = svcObjs[m[1]] = svcObjs[m[1]] || { proto: null, ports: [], items: [], unresolved: [] }; continue; }
      if (/^object-group (icmp-type|protocol|user)/.test(line)) { cur = { ignore: true }; continue; }
      if ((m = /^access-group (\S+) (in|out) interface (\S+)/.exec(line))) { bindings[m[1]] = bindings[m[1]] || { dir: m[2], iface: m[3] }; continue; }
      if ((m = /^access-group (\S+) global/.exec(line))) { bindings[m[1]] = bindings[m[1]] || { dir: "in", iface: "global" }; continue; }
      if ((m = /^interface (\S+)/.exec(line))) { curIface = m[1]; continue; }
      continue;
    }
    if (curIface && (m = /^ip access-group (\S+) (in|out)/.exec(line))) { bindings[m[1]] = bindings[m[1]] || { dir: m[2], iface: curIface }; continue; }
    if (!cur || cur.ignore) continue;
    if (cur.items && !cur.ports) { // network
      if ((m = /^network-object host (\S+)/.exec(line)) || (m = /^host (\S+)/.exec(line))) cur.items.push({ addr: m[1] });
      else if ((m = /^network-object object (\S+)/.exec(line)) || (m = /^group-object (\S+)/.exec(line))) cur.items.push({ ref: m[1] });
      else if ((m = /^network-object (\S+) (\S+)/.exec(line)) || (m = /^subnet (\S+) (\S+)/.exec(line))) cur.items.push({ addr: m[1] + " " + m[2] });
      else if ((m = /^network-object (\S+)/.exec(line))) cur.items.push({ addr: m[1] });
      else if ((m = /^range (\S+) (\S+)/.exec(line))) cur.items.push({ addr: m[1] + "-" + m[2] });
      else if ((m = /^fqdn\s+(?:v4\s+|v6\s+)?(\S+)/.exec(line))) cur.items.push({ sym: "fqdn:" + m[1] });
    } else if (cur.ports) { // service
      if ((m = /^port-object eq (\S+)/.exec(line))) { const p = portsFromToken(m[1]); if (p) cur.ports.push(...p); else cur.unresolved.push(m[1]); }
      else if ((m = /^port-object range (\S+) (\S+)/.exec(line))) { const a = portsFromToken(m[1]), b = portsFromToken(m[2]); if (a && b) cur.ports.push([a[0][0], b[0][1]]); else cur.unresolved.push(m[1] + "-" + m[2]); }
      // gt/lt/neq were dropped: "eq 80" + "gt 1023" read as port 80 only, hiding the open range
      else if ((m = /^port-object (gt|lt|neq) (\S+)/.exec(line))) { const r = ciscoOpPorts(m[1], m[2]); if (r) cur.ports.push(...r); else cur.unresolved.push(m[1] + " " + m[2]); }
      else if ((m = /^service-object object (\S+)/.exec(line)) || (m = /^group-object (\S+)/.exec(line))) cur.items.push({ ref: m[1] });
      else if ((m = /^(?:service-object|service) (tcp|udp|tcp-udp|ip|icmp|\S+)(.*)$/.exec(line))) {
        const proto = normProto(m[1]); const rest = tokenize(m[2]);
        let ports = null, anyP = true;
        const di = rest.indexOf("destination");
        const seg = di >= 0 ? rest.slice(di + 1) : rest.filter((x) => x !== "source");
        if (seg[0] === "eq") { ports = []; for (let q = 1; q < seg.length && ciscoPortTok(seg[q]); q++) { const p = portsFromToken(seg[q]); if (p) ports.push(...p); } anyP = false; }
        else if (seg[0] === "range") { const a = portsFromToken(seg[1]), b = portsFromToken(seg[2]); ports = a && b ? [[a[0][0], b[0][1]]] : []; anyP = false; }
        else if (/^(gt|lt|neq)$/.test(seg[0] || "")) { ports = ciscoOpPorts(seg[0], seg[1]); anyP = false; if (!ports) { ports = []; cur.unresolved.push(seg[0] + " " + seg[1]); } } // was read as ANY port
        if (rest.includes("source") && di < 0) cur.unresolved.push("source-port filter");
        cur.items.push({ proto, ports: anyP ? null : ports });
      }
    }
  }
  const resolveNet = (name, seen = new Set()) => {
    const o = netObjs[name]; if (!o) return null;
    if (seen.has(name)) return { ranges: [], symbols: [], unresolved: [name + " (cycle)"] };
    seen.add(name);
    const out = { any: false, ranges: [], symbols: [], unresolved: [] };
    for (const it of o.items) {
      if (it.addr) { const r = parseRange(it.addr); if (r) out.ranges.push(r); else if (/^(any|any4)$/i.test(it.addr)) out.any = true; else out.unresolved.push(it.addr); }
      else if (it.sym) out.symbols.push(it.sym);
      else if (it.ref) { const sub = resolveNet(it.ref, seen); if (!sub) out.unresolved.push(it.ref); else { if (sub.any) out.any = true; out.ranges.push(...sub.ranges); out.symbols.push(...sub.symbols); out.unresolved.push(...sub.unresolved); } }
    }
    return out;
  };
  const resolveSvc = (name, seen = new Set()) => { // -> { proto, ports: PortSet }
    const o = svcObjs[name]; if (!o) return null;
    if (seen.has(name)) return { proto: "any", ports: portSet({ unresolved: [name + " (cycle)"] }) };
    seen.add(name);
    const protos = new Set(); const ranges = []; const unresolved = [...o.unresolved]; let anyP = false;
    if (o.proto) protos.add(o.proto);
    if (o.ports.length) ranges.push(...o.ports);
    for (const it of o.items) {
      if (it.ref) { const s = resolveSvc(it.ref, seen); if (!s) { unresolved.push(it.ref); continue; } protos.add(s.proto); if (s.ports.any) anyP = true; ranges.push(...s.ports.ranges); unresolved.push(...s.ports.unresolved); }
      else { protos.add(it.proto); if (it.ports === null) anyP = true; else ranges.push(...it.ports); }
    }
    let proto = "any";
    const pl = [...protos].filter((p) => p !== "any");
    if (protos.has("any")) proto = "any"; else if (pl.length === 1) proto = pl[0]; else if (pl.length === 2 && pl.includes("tcp") && pl.includes("udp")) proto = "tcp/udp"; else if (pl.length > 1) proto = "any";
    if (!o.ports.length && !o.items.length) anyP = true;
    return { proto, ports: anyP ? ANY_PORTS() : portSet({ ranges, unresolved }) };
  };
  const unresolvedNames = new Set();
  const addr = (tk, i, wildcard) => { // -> [set, nextIndex]
    const t = tk[i]; if (!t) return [addrSet({ unresolved: ["(missing)"] }), i];
    const tl = t.toLowerCase();
    if (tl === "any" || tl === "any4" || tl === "any6") return [ANY_ADDR(), i + 1];
    if (tl === "host") { const r = parseRange(tk[i + 1]); return [r ? addrSet({ ranges: [r], text: tk[i + 1] }) : addrSet({ unresolved: [tk[i + 1] || "host ?"] }), i + 2]; }
    if (tl === "object" || tl === "object-group") {
      const nm = tk[i + 1]; const res = resolveNet(nm);
      if (!res) { unresolvedNames.add(nm); return [addrSet({ unresolved: [nm], text: nm }), i + 2]; }
      const set = addrSet({ any: res.any, ranges: res.ranges, symbols: res.symbols, unresolved: res.unresolved });
      set.text = nm + " = " + set.text;
      return [set, i + 2];
    }
    if (tl === "interface") return [addrSet({ symbols: ["interface:" + tk[i + 1]], text: "interface " + tk[i + 1] }), i + 2];
    if (/^\d+\.\d+\.\d+\.\d+$/.test(t) && /^\d+\.\d+\.\d+\.\d+$/.test(tk[i + 1] || "")) {
      const m2 = tk[i + 1];
      let r = null;
      if (wildcard) r = rangeFromWildcard(t, m2); else r = rangeFromMask(t, m2);
      if (!r) { r = wildcard ? rangeFromMask(t, m2) : rangeFromWildcard(t, m2); }
      return [r ? addrSet({ ranges: [r], text: t + " " + m2 }) : addrSet({ unresolved: [t + " " + m2 + " (non-contiguous mask)"] }), i + 2];
    }
    const r = parseRange(t);
    if (r) return [addrSet({ ranges: [r], text: t }), i + 1];
    unresolvedNames.add(t);
    return [addrSet({ unresolved: [t], text: t }), i + 1];
  };
  const ports = (tk, i) => { // -> [PortSet|null, nextIndex, restricted]
    const t = (tk[i] || "").toLowerCase();
    if (t === "eq") { const rs = []; let j = i + 1; const un = []; while (j < tk.length && ciscoPortTok(tk[j]) && !/^\d+\.\d+/.test(tk[j])) { const p = portsFromToken(tk[j]); if (p) rs.push(...p); else un.push(tk[j]); j++; } return [portSet({ ranges: rs, unresolved: un, text: tk.slice(i + 1, j).join(",") }), j, false]; }
    if (t === "range") { const a = portsFromToken(tk[i + 1]), b = portsFromToken(tk[i + 2]); return [a && b ? portSet({ ranges: [[a[0][0], b[0][1]]] }) : portSet({ unresolved: [tk[i + 1] + "-" + tk[i + 2]] }), i + 3, false]; }
    if (t === "gt") { const a = portsFromToken(tk[i + 1]); return [a ? portSet({ ranges: [[a[0][0] + 1, 65535]] }) : portSet({ unresolved: ["gt " + tk[i + 1]] }), i + 2, false]; }
    if (t === "lt") { const a = portsFromToken(tk[i + 1]); return [a ? portSet({ ranges: [[0, a[0][0] - 1]] }) : portSet({ unresolved: ["lt " + tk[i + 1]] }), i + 2, false]; }
    if (t === "neq") { const a = portsFromToken(tk[i + 1]); const p = a ? a[0][0] : null; return [p != null ? portSet({ ranges: [[0, p - 1], [p + 1, 65535]].filter((r) => r[0] <= r[1]) }) : portSet({ unresolved: ["neq " + tk[i + 1]] }), i + 2, false]; }
    // ASA port group: "permit tcp any any object-group WEB-PORTS" (object-group service NAME tcp) was read as ANY port
    if (t === "object-group" && svcObjs[tk[i + 1]] && svcObjs[tk[i + 1]].proto && !netObjs[tk[i + 1]]) return [resolveSvc(tk[i + 1]).ports, i + 2, false];
    return [null, i, false];
  };
  const parseEntry = (aclName, tk, lineNo, raw, wildcard, standard) => {
    // tk starts at permit|deny
    const action = tk[0].toLowerCase() === "permit" ? "allow" : "deny";
    let i = 1, proto = "any", svc = null, restricted = false, enabled = true, log = false, state = null, src, dst, sp = ANY_PORTS(), dp = ANY_PORTS();
    if (standard) { [src, i] = addr(tk, i, wildcard); dst = ANY_ADDR(); }
    else {
      const pt = (tk[i] || "").toLowerCase();
      if (pt === "object-group" || pt === "object") {
        svc = resolveSvc(tk[i + 1]);
        if (svc) { proto = svc.proto; dp = svc.ports; i += 2; }
        else { const net = resolveNet(tk[i + 1]); if (net) { proto = "any"; /* protocol group? unknown */ restricted = true; i += 2; } else { unresolvedNames.add(tk[i + 1]); dp = portSet({ unresolved: [tk[i + 1]] }); i += 2; } }
      } else if (CISCO_IP_PROTOS.test(pt)) { proto = normProto(pt); i++; }
      else { proto = "any"; }
      [src, i] = addr(tk, i, wildcard);
      if (!svc && protoHasPorts(proto)) { const [p, ni] = ports(tk, i); if (p) { sp = p; i = ni; } }
      [dst, i] = addr(tk, i, wildcard);
      if (!svc && protoHasPorts(proto)) { const [p, ni] = ports(tk, i); if (p) { dp = p; i = ni; } }
    }
    for (; i < tk.length; i++) {
      const t = tk[i].toLowerCase();
      if (t === "log") { log = true; while (i + 1 < tk.length && /^(\d+|interval|disable|default|input|debugging|informational|notifications|warnings|errors|critical|alerts|emergencies)$/i.test(tk[i + 1])) i++; continue; }
      if (t === "inactive") { enabled = false; continue; }
      if (t === "established") { state = "established"; continue; }
      if (t === "time-range") { restricted = true; i++; continue; }
      if (/^\(hitcnt=/.test(t) || /^0x[0-9a-f]+$/.test(t)) continue;
      if (proto === "icmp" || proto === "icmpv6") { restricted = true; continue; }
      restricted = true;
    }
    const b = bindings[aclName];
    const direction = b ? b.dir : "any";
    const facing = b ? (b.iface === "global" ? "unknown" : classifyIface(b.iface)) : "unknown";
    const r = mkRule({
      lineNo, raw, format: "cisco", scope: "acl:" + aclName, name: remarks[aclName] || "", action, direction, chain: aclName,
      iface: b ? `${b.iface} ${b.dir}` : "(not applied)", proto, src, dst, srcPorts: sp, dstPorts: dp, enabled, log, state, restricted, facing,
    });
    remarks[aclName] = "";
    rules.push(r);
  };
  // pass 2: ACL entries
  lineNo = 0; iosBlock = null;
  for (const raw0 of L) {
    lineNo++;
    const raw = raw0.replace(/\s+\(hitcnt=\d+\).*$/, "").replace(/\s+0x[0-9a-f]{8}\s*$/i, "");
    const line = raw.trim(); if (!line || line.startsWith("!")) continue;
    const indented = /^\s/.test(raw0);
    let m;
    if (!indented) {
      iosBlock = null;
      if ((m = /^ip access-list (extended|standard) (\S+)/i.exec(line))) { iosBlock = { name: m[2], standard: m[1].toLowerCase() === "standard" }; continue; }
      if ((m = /^access-list (\S+) remark (.*)$/i.exec(line))) { remarks[m[1]] = m[2]; continue; }
      if ((m = /^access-list (\S+)(?: line \d+)? (extended|standard|webtype|ethertype)?\s*(permit|deny)\b(.*)$/i.exec(line))) {
        const name = m[1], kind = (m[2] || "").toLowerCase(); if (kind === "webtype" || kind === "ethertype") continue;
        const tk = tokenize(m[3] + m[4]);
        const asa = kind === "extended" || kind === "standard";
        parseEntry(name, tk, lineNo, line, !asa /* IOS numbered -> wildcard */, kind === "standard" || (!asa && /^\d+$/.test(name) && +name <= 99));
        continue;
      }
      continue;
    }
    if (iosBlock) {
      const tk = tokenize(line); let i = 0;
      if (/^\d+$/.test(tk[0] || "")) i = 1;
      if ((tk[i] || "").toLowerCase() === "remark") { remarks[iosBlock.name] = tk.slice(i + 1).join(" "); continue; }
      if (/^(permit|deny)$/i.test(tk[i] || "")) parseEntry(iosBlock.name, tk.slice(i), lineNo, line, true, iosBlock.standard);
    }
  }
  rules.forEach((r) => { if (!bindings[r.chain]) r.notes.push("ACL is not applied to any interface in this paste (no access-group)."); });
  const acls = [...new Set(rules.map((r) => r.chain))];
  if (unresolvedNames.size) notes.push(`Unresolved object references: ${[...unresolvedNames].join(", ")}. Paste the object / object-group definitions too for exact results.`);
  notes.push("Cisco ACLs end with an implicit deny; the default-deny check passes. ASA netmask syntax and IOS wildcard syntax are both handled (IOS = 'ip access-list' blocks or numbered ACLs).");
  return { format: "cisco", label: "Cisco ASA / IOS ACL", partial: false, rules, policies: {}, implicitDeny: true, ordered: true, notes, acls, bindings };
}

// ---------------------------------------------------------------- pfSense / OPNsense CSV
export function parseCsv(text) {
  const rows = []; let row = [], cur = "", q = false;
  const s = String(text || "").replace(/\r\n?/g, "\n");
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (q) { if (ch === '"') { if (s[i + 1] === '"') { cur += '"'; i++; } else q = false; } else cur += ch; continue; }
    if (ch === '"') { q = true; continue; }
    if (ch === "," || ch === ";" || ch === "\t") { row.push(cur); cur = ""; continue; }
    if (ch === "\n") { row.push(cur); rows.push(row); row = []; cur = ""; continue; }
    cur += ch;
  }
  if (cur || row.length) { row.push(cur); rows.push(row); }
  return rows.filter((r) => r.some((c) => c.trim() !== ""));
}

const PF_SYMBOL = /^(lan|wan|opt\d+|\w+)(?: net| address)$|^this firewall|^\(self\)$/i;
function pfAddr(v, resolveAlias) {
  v = String(v || "").trim();
  if (!v || v === "*" || /^any$/i.test(v)) return ANY_ADDR();
  let neg = false;
  if (/^!\s*/.test(v)) { neg = true; v = v.replace(/^!\s*/, ""); }
  const parts = v.split(/\s*,\s*/);
  return addrFromTokens(parts, { negated: neg, text: (neg ? "NOT " : "") + v, resolve: resolveAlias, symbol: (t) => PF_SYMBOL.test(t) });
}
function pfPorts(v, resolveAlias) {
  v = String(v || "").trim();
  if (!v || v === "*" || /^any$/i.test(v)) return ANY_PORTS();
  const m = /^(\d+)\s*\((\w+)\)$/.exec(v); if (m) v = m[1];
  const ps = parsePortSpec(v.replace(/\s*-\s*/g, "-"));
  if (ps.unresolved.length && resolveAlias) {
    const un = []; for (const u of ps.unresolved) { const a = resolveAlias(u); if (a && a.ports) ps.ranges.push(...a.ports); else un.push(u); }
    ps.unresolved = un;
  }
  return ps;
}
function pfProto(v) {
  v = String(v || "").trim();
  const m = /^(ipv4|ipv6|ipv4\+6|inet|inet6|inet46)?\s*\*?\s*([A-Za-z\/]+|\*)?$/i.exec(v);
  const p = m && m[2] ? m[2] : (v.includes("*") || !v ? "*" : v.split(/\s+/).pop());
  return normProto(p);
}

export function parsePfsenseCsv(text) {
  const rows = parseCsv(text), notes = [], rules = [];
  let hi = rows.findIndex((r) => r.some((c) => /^action$/i.test(c.trim())) && r.some((c) => /source/i.test(c)));
  if (hi < 0) hi = 0;
  const hdr = rows[hi].map((c) => c.trim().toLowerCase());
  const col = (re) => hdr.findIndex((h) => re.test(h));
  const cAction = col(/^action$/), cIf = col(/^interface$/), cProto = col(/^proto(col)?$/), cSrc = col(/^(source|src)$/), cDst = col(/^(destination|dest|dst)$/);
  const portCols = hdr.map((h, i) => (/port/.test(h) ? i : -1)).filter((i) => i >= 0);
  let cSp = col(/^(source ?port|src ?port|sport)$/), cDp = col(/^(dest(ination)?\.? ?port|dst ?port|dport)$/);
  if (cSp < 0 && cDp < 0 && portCols.length >= 2) { cSp = portCols[0]; cDp = portCols[1]; }
  else if (cDp < 0 && portCols.length === 1) cDp = portCols[0];
  const cDesc = col(/^(description|descr|name)$/), cLog = col(/^log/), cDis = col(/^(disabled|enabled|status)$/), cDir = col(/^direction$/);
  if (cAction < 0 || cSrc < 0 || cDst < 0) notes.push("Header row not recognised fully (need Action, Source, Destination). Columns were guessed by position.");
  for (let i = hi + 1; i < rows.length; i++) {
    const r = rows[i]; const g = (c, d = "") => (c >= 0 && r[c] != null ? r[c].trim() : d);
    const act = g(cAction, r[0] || "").toLowerCase();
    if (!/^(pass|block|reject|allow|deny|match)$/.test(act)) continue;
    const iface = g(cIf, "floating") || "floating";
    const src = pfAddr(g(cSrc, "*")), dst = pfAddr(g(cDst, "*"));
    let enabled = true; const dv = g(cDis).toLowerCase();
    if (cDis >= 0) { if (/^(disabled|status)$/.test(hdr[cDis])) enabled = !/^(yes|true|1|disabled|x)$/.test(dv); else enabled = !/^(no|false|0)$/.test(dv); }
    const log = cLog >= 0 ? /^(yes|true|1|x|on)$/i.test(g(cLog)) : null;
    const dirv = g(cDir).toLowerCase();
    const facing = classifyIface(iface);
    rules.push(mkRule({
      lineNo: i + 1, raw: r.join(","), format: "pfsense-csv", scope: "if:" + iface.toLowerCase(), name: g(cDesc), action: act === "pass" || act === "allow" ? "allow" : act === "reject" ? "reject" : act === "match" ? "other" : "deny",
      direction: dirv === "out" ? "out" : dirv === "any" ? "any" : "in", chain: iface, iface, srcZones: iface === "floating" ? null : [iface],
      proto: pfProto(g(cProto, "*")), src, dst, srcPorts: pfPorts(g(cSp, "*")), dstPorts: pfPorts(g(cDp, "*")), enabled, log, facing,
    }));
  }
  if (cLog < 0) notes.push("The CSV has no Log column, so per-rule logging checks are skipped (export the XML config.xml to include them).");
  notes.push("pfSense/OPNsense apply an implicit default deny per interface; the default-deny check passes. Rules on LAN/OPT interfaces are evaluated as egress from inside, rules on WAN as ingress.");
  return { format: "pfsense-csv", label: "pfSense / OPNsense rules CSV", partial: cLog < 0, rules, policies: {}, implicitDeny: true, ordered: true, notes };
}

export function parsePfsenseXml(text) {
  const notes = [], rules = [], aliases = {};
  const s = String(text || "");
  const tag = (x, t) => { const m = new RegExp(`<${t}>([\\s\\S]*?)</${t}>`, "i").exec(x); return m ? m[1].trim() : null; };
  const has = (x, t) => new RegExp(`<${t}\\s*/>|<${t}>\\s*</${t}>|<${t}>`, "i").test(x);
  const amatch = /<aliases>([\s\S]*?)<\/aliases>/i.exec(s);
  if (amatch) for (const a of amatch[1].match(/<alias>[\s\S]*?<\/alias>/gi) || []) {
    const name = tag(a, "name"), type = tag(a, "type") || "", addr = (tag(a, "address") || "").split(/\s+/).filter(Boolean);
    if (!name) continue;
    if (/port/.test(type)) { const ps = parsePortSpec(addr.join(",").replace(/:/g, "-")); aliases[name] = { ports: ps.ranges }; }
    else { const set = addrFromTokens(addr, { text: name }); aliases[name] = { ranges: set.ranges, symbols: set.symbols, unresolved: set.unresolved }; }
  }
  const resolveAlias = (n) => aliases[n] || null;
  const fmatch = /<filter>([\s\S]*?)<\/filter>/i.exec(s);
  const body = fmatch ? fmatch[1] : s;
  const blocks = body.match(/<rule>[\s\S]*?<\/rule>/gi) || [];
  const lineOf = (idx) => s.slice(0, idx).split("\n").length;
  let pos = 0;
  blocks.forEach((b) => {
    const at = s.indexOf(b, pos); pos = at + b.length;
    const type = (tag(b, "type") || "pass").toLowerCase();
    if (!/^(pass|block|reject|match)$/.test(type)) return;
    const ifaces = (tag(b, "interface") || "floating").split(",").map((x) => x.trim()).filter(Boolean);
    const floating = has(b, "floating") || ifaces[0] === "floating";
    const ipp = (tag(b, "ipprotocol") || "inet").toLowerCase();
    const proto = normProto(tag(b, "protocol") || (ipp === "inet6" ? "ipv6" : "ipv4"));
    const side = (t) => {
      const x = tag(b, t) || "";
      const neg = has(x, "not");
      let set;
      if (has(x, "any")) set = ANY_ADDR();
      else {
        const addrv = tag(x, "address"), net = tag(x, "network");
        if (addrv) set = pfAddr((neg ? "! " : "") + addrv, resolveAlias);
        else if (net) { const sym = /^(\w+)ip$/.exec(net) ? net.replace(/ip$/, "") + " address" : net === "(self)" ? "This Firewall (self)" : net + " net"; set = addrSet({ symbols: [sym], negated: neg, text: (neg ? "NOT " : "") + sym }); }
        else set = ANY_ADDR();
      }
      if (neg) { set.negated = true; set.text = set.text.startsWith("NOT") ? set.text : "NOT " + set.text; }
      const port = tag(x, "port");
      return { set, ports: port ? pfPorts(port, resolveAlias) : ANY_PORTS() };
    };
    const S = side("source"), D = side("destination");
    const dirv = (tag(b, "direction") || "in").toLowerCase();
    const iface = ifaces.join(",");
    rules.push(mkRule({
      lineNo: lineOf(at), raw: b.replace(/\s+/g, " ").slice(0, 400), format: "pfsense-xml", scope: floating ? "floating" : "if:" + iface.toLowerCase(), name: tag(b, "descr") || "",
      action: type === "pass" ? "allow" : type === "reject" ? "reject" : type === "match" ? "other" : "deny", direction: dirv === "out" ? "out" : dirv === "any" ? "any" : "in",
      chain: iface, iface, srcZones: floating && ifaces[0] === "floating" ? null : ifaces, proto, src: S.set, dst: D.set, srcPorts: S.ports, dstPorts: D.ports,
      enabled: !has(b, "disabled"), log: has(b, "log"), facing: ifaces.length === 1 ? classifyIface(ifaces[0]) : "unknown",
      restricted: !!(tag(b, "sched") || tag(b, "os") || tag(b, "tagged")),
    }));
  });
  notes.push("pfSense/OPNsense apply an implicit default deny per interface; the default-deny check passes. Aliases defined in <aliases> are resolved; others are listed as unresolved.");
  return { format: "pfsense-xml", label: "pfSense / OPNsense config.xml", partial: false, rules, policies: {}, implicitDeny: true, ordered: true, notes, aliases: Object.keys(aliases) };
}

// ---------------------------------------------------------------- FortiGate
const FORTI_SERVICES = {
  "all": { proto: "any", ports: null }, "all_tcp": { proto: "tcp", ports: null }, "all_udp": { proto: "udp", ports: null }, "all_icmp": { proto: "icmp", ports: null }, "all_icmp6": { proto: "icmpv6", ports: null },
  "ping": { proto: "icmp", ports: null }, "ping6": { proto: "icmpv6", ports: null }, "traceroute": { proto: "udp", ports: [[33434, 33535]] },
  "http": { proto: "tcp", ports: [[80, 80]] }, "https": { proto: "tcp", ports: [[443, 443]] }, "ssh": { proto: "tcp", ports: [[22, 22]] }, "telnet": { proto: "tcp", ports: [[23, 23]] },
  "ftp": { proto: "tcp", ports: [[21, 21]] }, "ftp_get": { proto: "tcp", ports: [[21, 21]] }, "ftp_put": { proto: "tcp", ports: [[21, 21]] }, "smtp": { proto: "tcp", ports: [[25, 25]] }, "smtps": { proto: "tcp", ports: [[465, 465]] },
  "dns": { proto: "tcp/udp", ports: [[53, 53]] }, "rdp": { proto: "tcp", ports: [[3389, 3389]] }, "smb": { proto: "tcp", ports: [[445, 445]] }, "samba": { proto: "tcp", ports: [[139, 139]] },
  "netbios": { proto: "udp", ports: [[137, 138]] }, "snmp": { proto: "udp", ports: [[161, 162]] }, "ldap": { proto: "tcp", ports: [[389, 389]] }, "ldap_udp": { proto: "udp", ports: [[389, 389]] }, "ldaps": { proto: "tcp", ports: [[636, 636]] },
  "mysql": { proto: "tcp", ports: [[3306, 3306]] }, "ms-sql": { proto: "tcp", ports: [[1433, 1434]] }, "postgresql": { proto: "tcp", ports: [[5432, 5432]] }, "vnc": { proto: "tcp", ports: [[5900, 5900]] },
  "ntp": { proto: "udp", ports: [[123, 123]] }, "imap": { proto: "tcp", ports: [[143, 143]] }, "imaps": { proto: "tcp", ports: [[993, 993]] }, "pop3": { proto: "tcp", ports: [[110, 110]] }, "pop3s": { proto: "tcp", ports: [[995, 995]] },
  "syslog": { proto: "udp", ports: [[514, 514]] }, "radius": { proto: "udp", ports: [[1812, 1813]] }, "kerberos": { proto: "tcp/udp", ports: [[88, 88]] }, "winrm": { proto: "tcp", ports: [[5985, 5986]] },
  "dcе-rpc": { proto: "tcp", ports: [[135, 135]] }, "dce-rpc": { proto: "tcp/udp", ports: [[135, 135]] }, "nfs": { proto: "tcp/udp", ports: [[2049, 2049]] }, "ike": { proto: "udp", ports: [[500, 500], [4500, 4500]] },
  "web access": { proto: "tcp", ports: [[80, 80], [443, 443]] }, "windows ad": { proto: "any", ports: [[88, 88], [135, 135], [389, 389], [445, 445], [464, 464], [636, 636], [3268, 3269], [53, 53], [137, 139]] },
};
function fortiPortRange(v) { // "22", "22-23", "3389:1024-65535", "80 443"
  const out = []; for (const part of String(v).split(/\s+/).filter(Boolean)) { const dst = part.split(":")[0]; const p = portsFromToken(dst.replace(/-/, "-")); if (p) out.push(...p); } return out;
}
export function parseFortigate(text) {
  const notes = [], rules = [], addrs = {}, grps = {}, svcs = {}, svcGrps = {};
  let stack = [], cur = null, lineNo = 0, implicitLog = null;
  const section = () => stack[stack.length - 1] || "";
  for (const raw of lines(text)) {
    lineNo++;
    const line = raw.trim(); if (!line) continue;
    let m;
    if ((m = /^config\s+(.+)$/.exec(line))) { stack.push(m[1].toLowerCase()); continue; }
    if (line === "end") { stack.pop(); cur = null; continue; }
    if (line === "next") { if (cur && cur.kind === "policy") rules.push(cur); cur = null; continue; }
    if ((m = /^edit\s+(.+)$/.exec(line))) {
      const name = m[1].replace(/^"|"$/g, ""); const sec = section();
      if (sec === "firewall address" || sec === "firewall address6") cur = addrs[name] = { kind: "addr", name, type: "ipmask" };
      else if (sec === "firewall addrgrp" || sec === "firewall addrgrp6") cur = grps[name] = { kind: "grp", name, members: [] };
      else if (sec === "firewall service custom") cur = svcs[name] = { kind: "svc", name, proto: "tcp/udp", tcp: [], udp: [], sctp: [], protoSet: false };
      else if (sec === "firewall service group") cur = svcGrps[name] = { kind: "svcgrp", name, members: [] };
      else if (sec === "firewall policy" || sec === "firewall policy6" || sec === "firewall consolidated policy") cur = { kind: "policy", id: name, lineNo, raw: [], srcintf: [], dstintf: [], srcaddr: [], dstaddr: [], service: [], action: "deny", status: true, logtraffic: null, name: "", schedule: "always", srcneg: false, dstneg: false, users: false, comments: "" };
      else cur = { kind: "other" };
      continue;
    }
    if (section() === "log setting" && (m = /^set fwpolicy-implicit-log (enable|disable)/.exec(line))) { implicitLog = m[1] === "enable"; continue; }
    if (!cur || !(m = /^(set|unset|append)\s+(\S+)\s*(.*)$/.exec(line))) continue;
    const key = m[2].toLowerCase(), vals = tokenize(m[3]);
    if (cur.kind === "policy") cur.raw.push(line);
    switch (cur.kind) {
      case "addr":
        if (key === "subnet") cur.subnet = vals.join(" "); else if (key === "type") cur.type = vals[0]; else if (key === "start-ip") cur.start = vals[0]; else if (key === "end-ip") cur.end = vals[0];
        else if (key === "ip6") cur.subnet = vals[0]; else if (key === "fqdn") cur.fqdn = vals[0]; else if (key === "country") cur.country = vals[0]; else if (key === "wildcard") cur.wildcard = vals.join(" ");
        break;
      case "grp": if (key === "member") cur.members.push(...vals); break;
      case "svc":
        if (key === "tcp-portrange") cur.tcp.push(...fortiPortRange(vals.join(" "))); else if (key === "udp-portrange") cur.udp.push(...fortiPortRange(vals.join(" ")));
        else if (key === "sctp-portrange") cur.sctp.push(...fortiPortRange(vals.join(" "))); else if (key === "protocol") { cur.proto = vals[0].toUpperCase(); cur.protoSet = true; } else if (key === "protocol-number") cur.protoNum = vals[0];
        break;
      case "svcgrp": if (key === "member") cur.members.push(...vals); break;
      case "policy":
        if (key === "srcintf") cur.srcintf = vals; else if (key === "dstintf") cur.dstintf = vals; else if (key === "srcaddr") cur.srcaddr = vals; else if (key === "dstaddr") cur.dstaddr = vals;
        else if (key === "srcaddr6" && !cur.srcaddr.length) cur.srcaddr = vals; else if (key === "dstaddr6" && !cur.dstaddr.length) cur.dstaddr = vals;
        else if (key === "action") cur.action = vals[0]; else if (key === "status") cur.status = vals[0] !== "disable"; else if (key === "service") cur.service = vals;
        else if (key === "logtraffic") cur.logtraffic = vals[0]; else if (key === "name") cur.name = vals.join(" "); else if (key === "schedule") cur.schedule = vals[0];
        else if (key === "srcaddr-negate") cur.srcneg = vals[0] === "enable"; else if (key === "dstaddr-negate") cur.dstneg = vals[0] === "enable";
        else if (key === "users" || key === "groups" || key === "fsso-groups") cur.users = true; else if (key === "comments") cur.comments = vals.join(" ");
        break;
    }
  }
  const unresolvedNames = new Set();
  const resolveAddr = (name, seen = new Set()) => {
    if (/^all$/i.test(name)) return { any: true, ranges: [], symbols: [], unresolved: [] };
    if (seen.has(name)) return { ranges: [], symbols: [], unresolved: [name + " (cycle)"] };
    seen.add(name);
    const a = addrs[name];
    if (a) {
      const out = { any: false, ranges: [], symbols: [], unresolved: [] };
      if (a.type === "iprange" && a.start && a.end) { const r = parseRange(a.start + "-" + a.end); if (r) out.ranges.push(r); else out.unresolved.push(name); }
      else if (a.type === "fqdn" || a.fqdn) out.symbols.push("fqdn:" + (a.fqdn || name));
      else if (a.type === "geography" || a.country) out.symbols.push("geo:" + (a.country || name));
      else if (a.type === "wildcard" || a.wildcard) out.unresolved.push(name + " (wildcard)");
      else if (a.type === "dynamic" || a.type === "interface-subnet") out.symbols.push(a.type + ":" + name);
      else if (a.subnet) {
        let r = parseRange(a.subnet); if (!r) { const p = a.subnet.split(/\s+/); if (p.length === 2) r = rangeFromMask(p[0], p[1]); }
        if (r) out.ranges.push(r); else out.unresolved.push(name);
      } else out.ranges.push(V4_ALL); // FortiOS default subnet 0.0.0.0/0
      return out;
    }
    const g = grps[name];
    if (g) {
      const out = { any: false, ranges: [], symbols: [], unresolved: [] };
      for (const mm of g.members) { const s = resolveAddr(mm, seen); if (!s) { out.unresolved.push(mm); continue; } if (s.any) out.any = true; out.ranges.push(...s.ranges); out.symbols.push(...s.symbols); out.unresolved.push(...s.unresolved); }
      return out;
    }
    return null;
  };
  const resolveSvc = (name, seen = new Set()) => { // -> list of {proto, ports: [[..]]|null}
    const key = name.toLowerCase();
    if (seen.has(key)) return [{ proto: "any", ports: null, unresolved: name + " (cycle)" }];
    seen.add(key);
    const s = svcs[name] || svcs[key];
    if (s) {
      const out = [];
      if (s.protoSet && !/^tcp\/udp\/sctp$/i.test(s.proto)) {
        if (/^icmp6?$/i.test(s.proto)) return [{ proto: s.proto.toLowerCase() === "icmp6" ? "icmpv6" : "icmp", ports: null }];
        if (/^ip$/i.test(s.proto)) return [{ proto: s.protoNum ? normProto(s.protoNum) : "any", ports: null }];
      }
      if (s.tcp.length) out.push({ proto: "tcp", ports: s.tcp });
      if (s.udp.length) out.push({ proto: "udp", ports: s.udp });
      if (s.sctp.length) out.push({ proto: "sctp", ports: s.sctp });
      if (!out.length) out.push({ proto: "tcp/udp", ports: null });
      return out;
    }
    const g = svcGrps[name] || svcGrps[key];
    if (g) { const out = []; for (const mm of g.members) { const r = resolveSvc(mm, seen); if (!r) { out.push({ proto: "any", ports: null, unresolved: mm }); unresolvedNames.add(mm); } else out.push(...r); } return out; }
    const b = FORTI_SERVICES[key];
    if (b) return [{ proto: b.proto, ports: b.ports }];
    return null;
  };
  const out = [];
  for (const p of rules) {
    const mk = (names, neg) => {
      const set = addrSet({ negated: neg, text: (neg ? "NOT " : "") + names.join(", ") });
      if (!names.length) { set.unresolved.push("(no address set)"); return set; }
      for (const n of names) { const r = resolveAddr(n); if (!r) { set.unresolved.push(n); unresolvedNames.add(n); continue; } if (r.any) set.any = true; set.ranges.push(...r.ranges); set.symbols.push(...r.symbols); set.unresolved.push(...r.unresolved); }
      return set;
    };
    const src = mk(p.srcaddr, p.srcneg), dst = mk(p.dstaddr, p.dstneg);
    // services -> proto + ports
    let proto = "any", dstPorts, unresolvedSvc = [], entries = [];
    for (const sname of p.service) { const r = resolveSvc(sname); if (!r) { unresolvedSvc.push(sname); unresolvedNames.add(sname); continue; } entries.push(...r); }
    if (!p.service.length) { dstPorts = portSet({ unresolved: ["(no service set)"] }); }
    else {
      const protos = new Set(entries.map((e) => e.proto));
      const anyPorts = entries.some((e) => e.ports === null && (e.proto === "any" || e.proto === "tcp" || e.proto === "udp" || e.proto === "tcp/udp"));
      if (protos.has("any")) proto = "any"; else if (protos.size === 1) proto = [...protos][0]; else if ([...protos].every((x) => x === "tcp" || x === "udp" || x === "tcp/udp")) proto = "tcp/udp"; else proto = "any";
      const ranges = []; for (const e of entries) if (e.ports) ranges.push(...e.ports);
      const un = [...unresolvedSvc, ...entries.filter((e) => e.unresolved).map((e) => e.unresolved)];
      dstPorts = anyPorts && !un.length ? ANY_PORTS() : portSet({ any: anyPorts, ranges, unresolved: un, text: p.service.join(", ") });
      if (anyPorts && un.length) dstPorts.text = p.service.join(", ");
    }
    const action = p.action === "accept" ? "allow" : p.action === "ipsec" ? "other" : "deny";
    const sIn = p.srcintf.some((x) => classifyIface(x) === "external"), dOut = p.dstintf.some((x) => classifyIface(x) === "external");
    const direction = sIn && !dOut ? "in" : dOut && !sIn ? "out" : "any";
    const facing = p.srcintf.some((x) => x === "any") ? "unknown" : sIn ? "external" : p.srcintf.every((x) => classifyIface(x) === "internal") && p.srcintf.length ? "internal" : "unknown";
    let log; if (action === "allow") log = p.logtraffic === "all"; else log = p.logtraffic === "all";
    out.push(mkRule({
      lineNo: p.lineNo, raw: `edit ${p.id}\n  ` + p.raw.join("\n  "), format: "fortigate", scope: "policy", name: p.name || p.comments || `policy ${p.id}`, action, direction, chain: "policy " + p.id,
      iface: `${p.srcintf.join(",") || "?"} -> ${p.dstintf.join(",") || "?"}`, srcZones: p.srcintf.length ? p.srcintf : null, dstZones: p.dstintf.length ? p.dstintf : null,
      proto, src, dst, dstPorts, enabled: p.status, log, facing, restricted: p.users || (p.schedule && p.schedule !== "always"),
      notes: p.logtraffic === "utm" ? ["logtraffic utm: only security-profile events are logged, not all sessions."] : [],
    }));
  }
  if (unresolvedNames.size) notes.push(`Unresolved address/service names: ${[...unresolvedNames].join(", ")}. Include 'config firewall address' / 'service custom' blocks for exact results.`);
  notes.push("FortiGate policy tables end with the implicit deny (policy 0); the default-deny check passes." + (implicitLog === false ? " Implicit-deny logging is disabled (fwpolicy-implicit-log)." : ""));
  return { format: "fortigate", label: "FortiGate CLI", partial: false, rules: out, policies: {}, implicitDeny: true, implicitLog, ordered: true, notes };
}

// ---------------------------------------------------------------- Windows Firewall
const WIN_ADDR_SYMBOL = /^(any|localsubnet|dns|dhcp|wins|defaultgateway|intranet|internet|playtodevice|rmtintranet|ply2renders)$/i;
const WIN_PORT_SYMBOL = /^(rpc|rpc-epmap|iphttps|teredo|ply2disc|playtodiscovery|rpcdynamicports)$/i;
function winAddr(v) {
  v = String(v || "").trim();
  if (!v || /^any$/i.test(v)) return ANY_ADDR();
  const parts = v.split(/\s*,\s*/).filter(Boolean);
  return addrFromTokens(parts, { text: v, symbol: (t) => WIN_ADDR_SYMBOL.test(t) });
}
function winPorts(v) {
  v = String(v || "").trim();
  if (!v || /^any$/i.test(v)) return ANY_PORTS();
  if (WIN_PORT_SYMBOL.test(v)) return portSet({ unresolved: [v], text: v });
  return parsePortSpec(v);
}
function winRuleFrom(f, lineNo, raw, format) {
  const dir = /^out/i.test(f.direction || "") ? "out" : "in";
  const act = /^(allow)$/i.test(f.action || "") ? "allow" : /^(block|deny)$/i.test(f.action || "") ? "deny" : "other";
  const local = winAddr(f.localip), remote = winAddr(f.remoteip);
  const lport = f.localport === undefined ? portSet({ unresolved: ["(not in export)"] }) : winPorts(f.localport);
  const rport = f.remoteport === undefined ? portSet({ unresolved: ["(not in export)"] }) : winPorts(f.remoteport);
  const profiles = /^(any|all)$/i.test(f.profiles || "") || !f.profiles ? null : f.profiles.split(/\s*,\s*/);
  const restricted = !!((f.program && !/^any$/i.test(f.program)) || (f.service && !/^any$/i.test(f.service)) || (f.security && !/^notrequired$/i.test(f.security)) || (f.interfacetypes && !/^any$/i.test(f.interfacetypes)) || (f.edgetraversal && /^yes/i.test(f.edgetraversal)) === false && false);
  return mkRule({
    lineNo, raw, format, scope: "windows:" + dir, name: f.rulename || f.displayname || f.name || "", action: act, direction: dir, chain: dir === "in" ? "Inbound" : "Outbound",
    iface: f.profiles || "", profiles, proto: normProto(f.protocol || "any"),
    src: dir === "in" ? remote : local, srcPorts: dir === "in" ? rport : lport, dst: dir === "in" ? local : remote, dstPorts: dir === "in" ? lport : rport,
    enabled: !/^(no|false|0)$/i.test(f.enabled || "yes"), log: null, restricted, facing: dir === "in" ? (profiles && !profiles.some((p) => /public/i.test(p)) ? "internal" : "external") : "internal",
    notes: f.program && !/^any$/i.test(f.program) ? ["Scoped to program " + f.program] : [],
  });
}
export function parseWindowsNetsh(text) {
  const notes = [], rules = [], policies = {};
  const src = String(text || "").replace(/\r\n?/g, "\n");
  let m; const prof = /^(\w+) Profile Settings:[\s\S]*?Firewall Policy\s+(\w+),(\w+)/gm;
  while ((m = prof.exec(src))) policies[m[1]] = m[2] + "," + m[3];
  const parts = src.split(/^(?=Rule Name:)/m);
  let offset = 0;
  for (const block of parts) {
    const lineNo = src.slice(0, offset).split("\n").length; offset += block.length;
    if (!/^Rule Name:/.test(block)) continue;
    const f = {};
    for (const ln of block.split("\n")) { const mm = /^([A-Za-z][A-Za-z ]*?):\s*(.*)$/.exec(ln); if (mm) f[mm[1].toLowerCase().replace(/\s+/g, "")] = mm[2].trim(); }
    rules.push(winRuleFrom(f, lineNo, block.trim().split("\n").filter((l) => /^(Rule Name|Enabled|Direction|Profiles|LocalIP|RemoteIP|Protocol|LocalPort|RemotePort|Action|Program):/.test(l)).join("\n"), "windows-netsh"));
  }
  if (!Object.keys(policies).length) notes.push("Profile defaults are not in this export. Windows Firewall defaults to BlockInbound,AllowOutbound; include 'netsh advfirewall show allprofiles' to verify.");
  notes.push("Windows Firewall is not order-based: a Block rule always beats an Allow rule, so shadowing is reported as block-overrides-allow instead of first-match.");
  return { format: "windows-netsh", label: "Windows Firewall (netsh)", partial: false, rules, policies, implicitDeny: true, ordered: false, notes };
}
export function parseWindowsCsv(text) {
  const rows = parseCsv(text), notes = [], rules = [];
  const hdr = rows[0].map((c) => c.trim().toLowerCase().replace(/^#?type.*$/, ""));
  const idx = (names) => { for (const n of names) { const i = hdr.indexOf(n); if (i >= 0) return i; } return -1; };
  const cols = {
    rulename: idx(["displayname", "name", "rule name"]), enabled: idx(["enabled"]), direction: idx(["direction"]), action: idx(["action"]), profiles: idx(["profile", "profiles"]),
    localip: idx(["localaddress", "localip"]), remoteip: idx(["remoteaddress", "remoteip"]), protocol: idx(["protocol"]), localport: idx(["localport"]), remoteport: idx(["remoteport"]), program: idx(["program"]),
  };
  const hasFilters = cols.localport >= 0 || cols.remoteip >= 0;
  for (let i = 1; i < rows.length; i++) {
    const r = rows[i]; const f = {};
    for (const [k, c] of Object.entries(cols)) if (c >= 0 && r[c] !== undefined) f[k] = r[c].trim();
    if (!f.direction && !f.action) continue;
    if (f.enabled && /^(true|false)$/i.test(f.enabled)) f.enabled = /^true$/i.test(f.enabled) ? "Yes" : "No";
    if (f.direction && /^inbound$/i.test(f.direction)) f.direction = "In"; if (f.direction && /^outbound$/i.test(f.direction)) f.direction = "Out";
    if (f.profiles && /^(any|0)$/i.test(f.profiles)) f.profiles = "Any";
    rules.push(winRuleFrom(f, i + 1, r.join(","), "windows-csv"));
  }
  if (!hasFilters) notes.push("Get-NetFirewallRule CSV carries no address or port filters (those come from Get-NetFirewallPortFilter / AddressFilter). Ports and addresses are marked unresolved, so exposure checks are skipped; only enable/direction/action hygiene is audited.");
  notes.push("Windows Firewall is not order-based: a Block rule always beats an Allow rule, so shadowing is reported as block-overrides-allow instead of first-match.");
  return { format: "windows-csv", label: "Windows Firewall (Get-NetFirewallRule CSV)", partial: !hasFilters, rules, policies: {}, implicitDeny: true, ordered: false, notes };
}

// ---------------------------------------------------------------- detection
export const FORMATS = {
  iptables: "iptables / ip6tables", nft: "nftables", cisco: "Cisco ASA / IOS ACL", "pfsense-csv": "pfSense / OPNsense CSV", "pfsense-xml": "pfSense / OPNsense config.xml",
  fortigate: "FortiGate CLI", "windows-netsh": "Windows Firewall (netsh)", "windows-csv": "Windows Firewall (CSV)",
};
export function detectFormat(text) {
  const s = String(text || "");
  if (!s.trim()) return null;
  const score = {};
  const add = (f, re, w = 1) => { const m = s.match(re); if (m) score[f] = (score[f] || 0) + w * Math.min(m.length, 20); };
  add("iptables", /^\s*(?:ip6?tables\s+(?:-t \w+\s+)?)?(-A|-I|-P|-N)\s+\S+/gm, 2); add("iptables", /^:\w+\s+(ACCEPT|DROP|REJECT|-)\s/gm, 3); add("iptables", /^\*filter/gm, 5); add("iptables", /^COMMIT/gm, 2);
  add("nft", /^\s*table\s+(inet|ip|ip6|bridge)\s+\w+\s*\{/gm, 8); add("nft", /^\s*chain\s+\w+\s*\{/gm, 4); add("nft", /type\s+filter\s+hook/g, 5);
  add("cisco", /^access-list\s+\S+\s+(extended|standard|remark|permit|deny)\b/gm, 3); add("cisco", /^ip access-list (extended|standard)/gm, 6); add("cisco", /^object(-group)? (network|service)/gm, 3); add("cisco", /^access-group\s/gm, 4);
  add("pfsense-xml", /<filter>/g, 8); add("pfsense-xml", /<rule>[\s\S]{0,400}?<type>(pass|block|reject)<\/type>/g, 4); add("pfsense-xml", /<pfsense>|<opnsense>/g, 10);
  const head = s.split(/\r?\n/).slice(0, 3).join("\n");
  if (/action/i.test(head) && /interface/i.test(head) && /source/i.test(head) && /destination/i.test(head) && /[,;\t]/.test(head)) score["pfsense-csv"] = (score["pfsense-csv"] || 0) + 12;
  add("fortigate", /^\s*config firewall (policy|address|service)/gm, 8); add("fortigate", /^\s*set (srcintf|dstintf|srcaddr|dstaddr)\b/gm, 2);
  add("windows-netsh", /^Rule Name:/gm, 4); add("windows-netsh", /^(LocalIP|RemoteIP|LocalPort|Direction):/gm, 1);
  if (/displayname|rule name|^"?name"?/i.test(head) && /direction/i.test(head) && /action/i.test(head) && /[,;\t]/.test(head) && !/source/i.test(head)) score["windows-csv"] = (score["windows-csv"] || 0) + 12;
  let best = null, bestScore = 0;
  for (const [f, sc] of Object.entries(score)) if (sc > bestScore) { best = f; bestScore = sc; }
  if (!best) return null;
  return { format: best, label: FORMATS[best], confidence: bestScore >= 8 ? "high" : bestScore >= 4 ? "medium" : "low" };
}
export function parseConfig(text, format) {
  const f = format || (detectFormat(text) || {}).format;
  let parsed;
  switch (f) {
    case "iptables": parsed = parseIptables(text); break;
    case "nft": parsed = parseNft(text); break;
    case "cisco": parsed = parseCisco(text); break;
    case "pfsense-csv": parsed = parsePfsenseCsv(text); break;
    case "pfsense-xml": parsed = parsePfsenseXml(text); break;
    case "fortigate": parsed = parseFortigate(text); break;
    case "windows-netsh": parsed = parseWindowsNetsh(text); break;
    case "windows-csv": parsed = parseWindowsCsv(text); break;
    default: return { format: null, label: "Unrecognised", rules: [], policies: {}, notes: ["Format not recognised. Supported: iptables-save / iptables -S, nft list ruleset, Cisco ASA/IOS ACLs, pfSense/OPNsense CSV or config.xml, FortiGate CLI, Windows netsh advfirewall / Get-NetFirewallRule CSV."], partial: true, ordered: true, implicitDeny: false };
  }
  parsed.rules.forEach((r, i) => { r.idx = i + 1; });
  return parsed;
}

// ===========================================================================
// 5. Analysis
// ===========================================================================
export const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
export const SEVERITY_WEIGHT = { critical: 25, high: 12, medium: 6, low: 2, info: 0 };
const REF = {
  anyany: ["CIS Controls v8 4.4 / 4.5 (manage host and network firewalls)", "NIST SP 800-41r1 sec. 4.1 (default deny; permit only required traffic)", "PCI DSS 4.0 req. 1.2.5, 1.3.1"],
  exposure: ["CIS Controls v8 4.4, 13.4 (traffic filtering between segments)", "NIST SP 800-41r1 sec. 4.1", "PCI DSS 4.0 req. 1.2.6 (insecure services), 1.3.1, 1.4.1"],
  shadow: ["NIST SP 800-41r1 sec. 4.3 (ruleset management and review)", "PCI DSS 4.0 req. 1.2.7 (periodic NSC review)", "CIS Controls v8 4.1"],
  defaultDeny: ["NIST SP 800-41r1 sec. 2.1.1 / 4.1 (default deny)", "CIS Controls v8 4.4 / 4.5", "PCI DSS 4.0 req. 1.3.1 ('deny all' for other traffic)"],
  logging: ["CIS Controls v8 8.2 / 8.5 (collect audit logs, detailed logs)", "NIST SP 800-41r1 sec. 4.4 (logging and alerting)", "PCI DSS 4.0 req. 10.2"],
  hygiene: ["NIST SP 800-41r1 sec. 4.3 (ruleset management)", "PCI DSS 4.0 req. 1.2.7"],
  egress: ["CIS Controls v8 13.4", "NIST SP 800-41r1 sec. 4.1 (outbound filtering)", "PCI DSS 4.0 req. 1.3.2 (restrict outbound from CDE)"],
};
const ATTACK = { anyany: "T1190, T1133, T1021", exposure: "T1021, T1133, T1190", shadow: "", defaultDeny: "T1190, T1046", logging: "T1562 (defence evasion is harder to detect)", hygiene: "", egress: "T1041, T1071, T1048 (C2 and exfiltration)" };

function evidence(r) { return { idx: r.idx, lineNo: r.lineNo, raw: r.raw, name: r.name, scope: r.scope }; }
function ruleRef(r) { return `rule #${r.idx}` + (r.name ? ` "${r.name}"` : "") + (r.lineNo ? ` (line ${r.lineNo})` : ""); }

function fixSnippet(kind, r, ctx) {
  const f = r.format;
  const trusted = ctx.trusted || "<trusted-admin-cidr>";
  const svcPorts = ctx.ports || (r.dstPorts ? describePorts(r.dstPorts) : "<port>");
  const dstTxt = !r.dst || r.dst.any ? "<specific-host>" : describeAddr(r.dst);
  if (kind === "exposure" || kind === "anyany") {
    if (f === "iptables") return `# replace line ${r.lineNo}\n-A ${r.chain} -s ${trusted} -p ${r.proto === "any" ? "tcp" : r.proto} --dport ${svcPorts.split(",")[0].trim()} -j ACCEPT`;
    if (f === "nft") return `# in chain ${r.chain}\nip saddr ${trusted} ${r.proto === "any" ? "tcp" : r.proto} dport ${svcPorts.split(",")[0].trim()} accept`;
    if (f === "cisco") return `no ${r.raw}\naccess-list ${r.chain} extended permit ${r.proto === "any" ? "tcp" : r.proto} ${trusted.includes("/") ? "object-group ADMIN_HOSTS" : trusted} ${r.dst.any ? "any" : r.dst.ranges.length === 1 && r.dst.ranges[0].lo === r.dst.ranges[0].hi ? "host " + fmtRange(r.dst.ranges[0]) : dstTxt} eq ${svcPorts.split(",")[0].trim()}`;
    if (f === "fortigate") return `config firewall address\n  edit "ADMIN_HOSTS"\n    set subnet ${trusted}\n  next\nend\nconfig firewall policy\n  edit ${r.chain.replace("policy ", "")}\n    set srcaddr "ADMIN_HOSTS"\n    set logtraffic all\n  next\nend`;
    if (f.startsWith("pfsense")) return `Edit the rule on interface ${r.iface}: Source -> an alias of admin addresses (${trusted}); Destination -> ${dstTxt}; Destination port -> ${svcPorts}. Enable Log.`;
    if (f.startsWith("windows")) return `netsh advfirewall firewall set rule name="${r.name}" new remoteip=${trusted} profile=domain,private`;
  }
  if (kind === "defaultDeny") {
    if (f === "iptables") return `-P ${ctx.chain} DROP\n# or append as the last rule:\n-A ${ctx.chain} -j LOG --log-prefix "FW-DROP "\n-A ${ctx.chain} -j DROP`;
    if (f === "nft") return `chain ${ctx.chain} { type filter hook ${ctx.hook} priority 0; policy drop; ... log prefix "FW-DROP " drop }`;
    if (f.startsWith("windows")) return `netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound`;
  }
  if (kind === "shadow" || kind === "redundant") {
    if (f === "iptables") return `# remove or move above rule #${ctx.by.idx}:\n${r.raw.replace(/^-A/, "-D")}`;
    if (f === "cisco") return `no ${r.raw}`;
    if (f === "fortigate") return `config firewall policy\n  delete ${r.chain.replace("policy ", "")}\nend\n# or: move ${r.chain.replace("policy ", "")} before ${ctx.by.chain.replace("policy ", "")}`;
  }
  if (kind === "logging") {
    if (f === "iptables") return `# insert before line ${r.lineNo}:\n${r.raw.replace(/-j\s+\S+.*$/, "")}-j LOG --log-prefix "FW-${r.action.toUpperCase()} "`;
    if (f === "cisco") return `${r.raw} log`;
    if (f === "fortigate") return `config firewall policy\n  edit ${r.chain.replace("policy ", "")}\n    set logtraffic all\n  next\nend`;
    if (f === "nft") return r.raw.replace(/\b(accept|drop|reject)\b/, "log prefix \"FW \" $1");
    if (f.startsWith("pfsense")) return `Edit rule "${r.name || r.idx}": tick Log packets that are handled by this rule.`;
  }
  if (kind === "egress") {
    if (f === "iptables") return `-P OUTPUT DROP\n-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n-A OUTPUT -p udp --dport 53 -d <resolver> -j ACCEPT\n-A OUTPUT -p tcp -m multiport --dports 80,443 -j ACCEPT\n-A OUTPUT -j LOG --log-prefix "EGRESS-DROP "`;
    if (f === "cisco") return `access-list ${r.chain} extended permit tcp ${describeAddr(r.src) === "any" ? "<internal-net> <mask>" : r.src.text} any eq 443\naccess-list ${r.chain} extended permit udp <internal-net> <mask> host <resolver> eq 53\naccess-list ${r.chain} extended deny ip any any log`;
  }
  return "";
}

function mkFinding(o) {
  return { id: o.id, type: o.type, severity: o.severity, confidence: o.confidence || "high", title: o.title, detail: o.detail, evidence: o.evidence || [], fix: o.fix || "", snippet: o.snippet || "", refs: o.refs || [], attack: o.attack || "" };
}

export function analyze(parsed, opts = {}) {
  const internalParsed = parseInternalList(opts.internal && (Array.isArray(opts.internal) ? opts.internal.length : String(opts.internal).trim()) ? opts.internal : DEFAULT_INTERNAL);
  const internal = internalParsed.ranges;
  const trusted = opts.trusted || "";
  const rules = parsed.rules.map((r) => ({ ...r, flags: [], shadowedBy: null, redundantOf: null }));
  const findings = [];
  let seq = 0; const fid = (t) => `FWA-${t}-${String(++seq).padStart(3, "0")}`;
  const broadLimit = 1n << 16n; // a /16 or more of non-internal space counts as "broad external"
  const active = (r) => r.enabled && r.terminal;
  const inbound = (r) => r.direction !== "out" && r.facing !== "loopback" && !(r.srcZones && r.srcZones.every((z) => /^lo\d*$/i.test(z)));
  const notEstablished = (r) => r.state !== "established";
  const hostFw = (r) => r.format === "iptables" || r.format === "nft" || r.format.startsWith("windows");
  // Egress = leaving the protected network: explicit out rules; rules entering a
  // network firewall from an internal-facing interface or an internal source;
  // forward-type rules (direction any) whose source is internal.
  const egressRule = (r) => r.direction === "out"
    || (r.direction === "any" && (r.facing === "internal" || addrIsInternal(r.src, internal)))
    || (r.direction === "in" && !hostFw(r) && (r.facing === "internal" || (r.facing !== "external" && addrIsInternal(r.src, internal))));
  const fromAny = (r) => isAnyAddr(r.src);
  const fromBroad = (r) => !fromAny(r) && externalSize(r.src, internal) >= broadLimit;

  // --- shadowing / redundancy -------------------------------------------
  if (parsed.ordered !== false) {
    for (let j = 0; j < rules.length; j++) {
      const rj = rules[j]; if (!active(rj)) continue;
      for (let i = 0; i < j; i++) {
        const ri = rules[i]; if (!active(ri) || ri.scope !== rj.scope) continue;
        if (!matchContains(ri, rj)) continue;
        const same = (ri.action === rj.action) || (ri.action !== "allow" && rj.action !== "allow");
        if (same) {
          rj.flags.push("redundant"); rj.redundantOf = ri.idx;
          findings.push(mkFinding({ id: fid("RED"), type: "redundant", severity: "low", title: `Redundant rule: #${rj.idx} is fully covered by #${ri.idx}`,
            detail: `${ruleRef(rj)} (${rj.action}) can never add anything: every packet it matches is already matched by ${ruleRef(ri)}, which takes the same action. It is dead weight that makes reviews slower and hides the real policy.`,
            evidence: [evidence(ri), evidence(rj)], fix: `Delete ${ruleRef(rj)}. If it exists for documentation, fold its comment into ${ruleRef(ri)}.`, snippet: fixSnippet("redundant", rj, { by: ri }), refs: REF.shadow }));
        } else {
          const bypass = rj.action !== "allow" && ri.action === "allow";
          rj.flags.push("shadowed"); rj.shadowedBy = ri.idx;
          findings.push(mkFinding({ id: fid("SHD"), type: "shadowed", severity: bypass ? "high" : "medium", title: bypass ? `Deny rule #${rj.idx} is shadowed by allow rule #${ri.idx} (security bypass)` : `Rule #${rj.idx} is shadowed by #${ri.idx} and never matches`,
            detail: bypass
              ? `${ruleRef(rj)} is meant to block traffic, but ${ruleRef(ri)} permits a superset of the same traffic first. First match wins, so the block is never reached: whatever this deny was protecting is open.`
              : `${ruleRef(rj)} (${rj.action}) can never match because ${ruleRef(ri)} (${ri.action}) decides every packet it would match. If the ${rj.action} was intended, the rule base does not do what the author thinks.`,
            evidence: [evidence(ri), evidence(rj)], fix: bypass ? `Move ${ruleRef(rj)} above ${ruleRef(ri)}, or narrow ${ruleRef(ri)} so it no longer covers the denied traffic.` : `Move ${ruleRef(rj)} above ${ruleRef(ri)} if it is still wanted; otherwise delete it.`,
            snippet: fixSnippet("shadow", rj, { by: ri }), refs: REF.shadow, attack: bypass ? "T1190, T1021" : "" }));
        }
        break;
      }
    }
  } else {
    // Windows: block beats allow regardless of order; same-action containment is redundancy.
    for (let j = 0; j < rules.length; j++) {
      const rj = rules[j]; if (!active(rj)) continue;
      for (let i = 0; i < rules.length; i++) {
        if (i === j) continue;
        const ri = rules[i]; if (!active(ri) || ri.scope !== rj.scope) continue;
        if (!matchContains(ri, rj)) continue;
        if (ri.action === rj.action) {
          if (i < j || !matchContains(rj, ri)) { rj.flags.push("redundant"); rj.redundantOf = ri.idx;
            findings.push(mkFinding({ id: fid("RED"), type: "redundant", severity: "low", title: `Redundant rule: #${rj.idx} is fully covered by #${ri.idx}`, detail: `${ruleRef(rj)} matches a subset of ${ruleRef(ri)} with the same action.`, evidence: [evidence(ri), evidence(rj)], fix: `Delete ${ruleRef(rj)}.`, refs: REF.shadow })); break; }
        } else if (rj.action === "allow" && ri.action === "deny") {
          rj.flags.push("overridden"); rj.shadowedBy = ri.idx;
          findings.push(mkFinding({ id: fid("SHD"), type: "shadowed", severity: "medium", title: `Allow rule #${rj.idx} is overridden by block rule #${ri.idx}`, detail: `Windows Firewall gives Block precedence over Allow, so ${ruleRef(rj)} never permits anything while ${ruleRef(ri)} covers it. Either the allow is dead, or the block is broader than intended.`, evidence: [evidence(ri), evidence(rj)], fix: `Decide which rule reflects policy; delete the other or narrow the block rule.`, refs: REF.shadow })); break;
        }
      }
    }
  }

  // --- any-to-any -------------------------------------------------------
  for (const r of rules) {
    if (!active(r) || r.action !== "allow" || !notEstablished(r) || r.restricted || r.facing === "loopback") continue;
    if (!fromAny(r) || !isAnyAddr(r.dst) || !r.dstPorts.any || !(r.proto === "any" || r.proto === "tcp" || r.proto === "udp" || r.proto === "tcp/udp")) continue;
    if (egressRule(r) && !inbound(r)) continue; // handled by egress
    if (r.facing === "internal" && r.direction === "in") continue; // pfSense LAN-style pass-all: egress
    r.flags.push("any-any");
    const protoTxt = r.proto === "any" ? "every protocol" : `all ${r.proto.toUpperCase()} ports`;
    findings.push(mkFinding({ id: fid("ANY"), type: "any-any", severity: "critical", confidence: r.facing === "external" || !r.srcZones ? "high" : "medium",
      title: `Any-to-any allow: ${ruleRef(r)} permits ${protoTxt} from anywhere to anywhere`,
      detail: `${ruleRef(r)} accepts traffic from any source to any destination on ${protoTxt}${r.iface ? ` (${r.iface})` : ""}. This is the absence of a firewall policy: every service behind it, including admin interfaces, is reachable by anyone who can route to it.${r.facing !== "external" && r.srcZones ? " It is bound to an interface that is not obviously external; confirm what that interface faces." : ""}`,
      evidence: [evidence(r)], fix: `Replace it with explicit rules: one per required service, each with the narrowest source that still works (admin hosts, partner ranges, VPN pool) and a specific destination. Keep ESTABLISHED/RELATED (stateful) handling as its own rule and end the chain with deny + log.`,
      snippet: fixSnippet("anyany", r, { trusted, ports: "<port>" }), refs: REF.anyany, attack: ATTACK.anyany }));
  }

  // --- exposed admin services ------------------------------------------
  const exposure = RISKY.map((s) => ({ id: s.id, label: s.label, ports: s.ports.map((p) => (p[0] === p[1] ? String(p[0]) : p[0] + "-" + p[1])).join(", "), proto: s.proto, sev: s.sev, fromAny: [], fromBroad: [] }));
  for (const r of rules) {
    if (!active(r) || r.action !== "allow" || !notEstablished(r) || !inbound(r)) continue;
    if (r.flags.includes("shadowed") || r.flags.includes("overridden")) continue;
    if (r.facing === "internal" && r.format !== "iptables" && r.format !== "nft" && !r.format.startsWith("windows")) continue; // inside-facing interface: not exposure
    const any = fromAny(r), broad = !any && fromBroad(r);
    if (!any && !broad) continue;
    const hit = [];
    const matrixOnly = r.flags.includes("any-any"); // already reported as critical; still counts for the matrix
    for (const s of RISKY) {
      const protoOk = s.proto === "any" ? protoHasPorts(r.proto) : protoContains(r.proto, s.proto) || (r.proto === s.proto);
      if (!protoOk) continue;
      if (!r.dstPorts.any && !s.ports.some((p) => r.dstPorts.ranges.some((q) => q[0] <= p[1] && p[0] <= q[1]))) continue;
      hit.push(s);
      const ex = exposure.find((e) => e.id === s.id); (any ? ex.fromAny : ex.fromBroad).push(r.idx);
    }
    if (!hit.length || matrixOnly) continue;
    const allPorts = r.dstPorts.any && protoHasPorts(r.proto);
    let sev = hit.reduce((m, s) => (SEVERITY_ORDER[s.sev] < SEVERITY_ORDER[m] ? s.sev : m), "medium");
    if (allPorts) sev = "critical";
    if (broad) sev = sev === "critical" ? "high" : sev === "high" ? "medium" : "low";
    r.flags.push("exposed");
    const srcTxt = any ? "any source" : `a broad non-internal source (${describeAddr(r.src)})`;
    const dstTxt = isAnyAddr(r.dst) ? "any destination" : describeAddr(r.dst);
    const list = hit.map((s) => `${s.label} (${s.proto === "any" ? "" : s.proto + "/"}${s.ports.map((p) => (p[0] === p[1] ? p[0] : p[0] + "-" + p[1])).join(",")}): ${s.why}`);
    findings.push(mkFinding({ id: fid("EXP"), type: "exposure", severity: sev, confidence: any && (r.facing === "external" || (!r.srcZones && r.facing !== "internal")) ? "high" : "medium",
      title: allPorts ? `All ${r.proto === "any" ? "" : r.proto.toUpperCase() + " "}ports open from ${srcTxt} to ${dstTxt}` : `${hit.map((s) => s.label).join(", ")} reachable from ${srcTxt}`,
      detail: `${ruleRef(r)} allows ${r.proto === "any" ? "any protocol" : r.proto.toUpperCase()} ${allPorts ? "on every port" : "port(s) " + describePorts(r.dstPorts)} from ${srcTxt} to ${dstTxt}${r.iface ? ` via ${r.iface}` : ""}. Services this exposes:\n- ${list.join("\n- ")}${r.facing === "unknown" && r.srcZones ? "\nThe rule is bound to an interface whose role is not obvious from its name; confidence is medium until you confirm it faces an untrusted network." : ""}`,
      evidence: [evidence(r)],
      fix: `Restrict the source of ${ruleRef(r)} to the hosts that administer this system (jump host, VPN pool, office egress IP) and list the exact port(s). If the service must be public (for example SMTP on a mail server), say so in the rule comment and make sure it is hardened and logged. Prefer a VPN or bastion over exposing ${hit.map((s) => s.label).join("/")} directly.`,
      snippet: fixSnippet("exposure", r, { trusted, ports: hit[0].ports.map((p) => (p[0] === p[1] ? p[0] : p[0] + "-" + p[1])).join(",") }),
      refs: REF.exposure, attack: [...new Set(hit.map((s) => s.attack))].join(", ") }));
  }

  // --- default deny -----------------------------------------------------
  if (parsed.format === "iptables" || parsed.format === "nft") {
    const chains = parsed.format === "iptables" ? ["INPUT", "FORWARD", "OUTPUT"] : Object.keys(parsed.hooks || {});
    for (const ch of chains) {
      const hook = parsed.format === "nft" ? parsed.hooks[ch] : ch.toLowerCase();
      const pol = parsed.policies[ch];
      const inChain = rules.filter((r) => r.chain === ch);
      const lastTerminal = [...inChain].reverse().find((r) => r.terminal && r.enabled);
      const catchAll = lastTerminal && lastTerminal.action !== "allow" && isAnyAddr(lastTerminal.src) && isAnyAddr(lastTerminal.dst) && lastTerminal.proto === "any" && lastTerminal.dstPorts.any && !lastTerminal.srcZones && !lastTerminal.state && !lastTerminal.restricted;
      const isEgress = hook === "output";
      if (pol === undefined && parsed.format === "iptables" && !inChain.length) continue;
      if (pol === "DROP" || pol === "REJECT" || catchAll) {
        if (pol === "ACCEPT" && catchAll && !isEgress) findings.push(mkFinding({ id: fid("DEF"), type: "default-deny", severity: "low", title: `${ch}: policy ACCEPT relies on a final catch-all deny rule`, detail: `Chain ${ch} has policy ACCEPT but ends with ${ruleRef(lastTerminal)}, a catch-all deny. That works today, but a rule appended later lands after the deny and a flush leaves the chain wide open. Set the policy itself to DROP.`, evidence: [evidence(lastTerminal)], fix: `Set the chain policy to DROP and keep the explicit deny for logging.`, snippet: `-P ${ch} DROP`, refs: REF.defaultDeny }));
        continue;
      }
      if (pol === undefined) continue;
      if (isEgress) {
        const anyOutRule = inChain.some((r) => active(r) && r.action === "allow");
        findings.push(mkFinding({ id: fid("EGR"), type: "egress", severity: "medium", confidence: "high", title: `${ch}: unrestricted egress (policy ACCEPT${anyOutRule ? "" : ", no rules"})`,
          detail: `Outbound traffic is allowed by default. A compromised host can reach any command-and-control server and exfiltrate data on any port, and there is no log of it. Egress filtering is also what stops reverse shells and crypto-miners from calling home.`,
          evidence: inChain.slice(0, 3).map(evidence), fix: `Set ${ch} policy to DROP, allow ESTABLISHED/RELATED, then permit only what the host needs (DNS to your resolvers, HTTP/S to update mirrors or a proxy, NTP, SMTP to your relay). Log the final drop.`, snippet: fixSnippet("egress", { format: parsed.format, chain: ch, src: ANY_ADDR() }, {}), refs: REF.egress, attack: ATTACK.egress }));
        continue;
      }
      const noRules = !inChain.some((r) => r.terminal);
      findings.push(mkFinding({ id: fid("DEF"), type: "default-deny", severity: noRules ? "critical" : "high", confidence: "high",
        title: noRules ? `${ch}: policy ACCEPT with no rules, everything is open` : `${ch}: no default deny (policy ACCEPT, no final drop)`,
        detail: noRules ? `Chain ${ch} has policy ACCEPT and no terminal rules. Every port on this host${ch === "FORWARD" ? " and everything it routes" : ""} is reachable.` : `Chain ${ch} ends with policy ACCEPT and no catch-all deny, so anything the explicit rules do not mention is permitted. Firewalls must deny by default and permit by exception; otherwise every new service that starts listening is exposed automatically.`,
        evidence: lastTerminal ? [evidence(lastTerminal)] : [], fix: `Set the policy to DROP (after adding the allows you need, including ESTABLISHED/RELATED and loopback) and log what gets dropped.`, snippet: fixSnippet("defaultDeny", { format: parsed.format, chain: ch }, { chain: ch, hook }), refs: REF.defaultDeny, attack: ATTACK.defaultDeny }));
    }
  } else if (parsed.format === "cisco") {
    for (const acl of parsed.acls || []) {
      const inAcl = rules.filter((r) => r.chain === acl && r.enabled);
      const last = inAcl[inAcl.length - 1];
      const explicitDeny = last && last.action === "deny" && isAnyAddr(last.src) && isAnyAddr(last.dst) && last.proto === "any";
      if (!explicitDeny) findings.push(mkFinding({ id: fid("DEF"), type: "default-deny", severity: "low", title: `ACL ${acl}: no explicit final 'deny ip any any log'`, detail: `Cisco ACLs deny by default, so traffic is blocked, but the implicit deny is not logged and does not show hit counts. An explicit final deny with 'log' gives you visibility into what is being dropped (and into scans against the perimeter).`, evidence: last ? [evidence(last)] : [], fix: `Append 'access-list ${acl} extended deny ip any any log' as the last entry.`, snippet: `access-list ${acl} extended deny ip any any log`, refs: REF.logging }));
      if (!parsed.bindings[acl]) findings.push(mkFinding({ id: fid("HYG"), type: "hygiene", severity: "info", title: `ACL ${acl} is not applied to any interface in this paste`, detail: `No 'access-group ${acl} ...' (ASA) or 'ip access-group ${acl} ...' (IOS) line was found. Either the ACL is unused, or the binding was not included. Direction and interface for its rules are unknown, so exposure confidence is reduced.`, evidence: inAcl.slice(0, 1).map(evidence), fix: `Include the access-group lines in the export, or remove the unused ACL.`, refs: REF.hygiene }));
    }
  } else if (parsed.format === "fortigate") {
    if (parsed.implicitLog === false) findings.push(mkFinding({ id: fid("LOG"), type: "logging", severity: "low", title: "Implicit deny is not logged (fwpolicy-implicit-log disable)", detail: "The implicit deny policy (policy 0) silently drops everything the explicit policies do not permit. Without implicit-deny logging you cannot see scans or blocked lateral movement.", evidence: [], fix: "config log setting / set fwpolicy-implicit-log enable / end", snippet: "config log setting\n  set fwpolicy-implicit-log enable\nend", refs: REF.logging }));
  } else if (parsed.format.startsWith("windows")) {
    for (const [prof, pol] of Object.entries(parsed.policies || {})) {
      if (/allowinbound/i.test(pol)) findings.push(mkFinding({ id: fid("DEF"), type: "default-deny", severity: "high", title: `${prof} profile: inbound default is Allow`, detail: `The ${prof} profile is set to ${pol}. Every listening service on the host is reachable unless a Block rule names it. Windows default is BlockInbound.`, evidence: [], fix: `Set the inbound default back to Block for every profile.`, snippet: fixSnippet("defaultDeny", { format: parsed.format }, {}), refs: REF.defaultDeny, attack: ATTACK.defaultDeny }));
    }
  }

  // --- broad egress rules -----------------------------------------------
  for (const r of rules) {
    if (!active(r) || r.action !== "allow" || r.restricted || r.flags.includes("any-any") || r.flags.includes("shadowed")) continue;
    if (!egressRule(r)) continue;
    if (!isAnyAddr(r.dst) || !r.dstPorts.any || !(r.proto === "any" || r.proto === "tcp" || r.proto === "tcp/udp")) continue;
    if (!(fromAny(r) || addrIsInternal(r.src, internal) || r.src.symbols.length)) continue;
    r.flags.push("broad-egress");
    findings.push(mkFinding({ id: fid("EGR"), type: "egress", severity: "medium", confidence: r.facing === "internal" || r.direction === "out" ? "high" : "medium",
      title: `Unrestricted egress: ${ruleRef(r)} lets ${describeAddr(r.src)} reach any destination on ${r.proto === "any" ? "any protocol" : "all " + r.proto.toUpperCase() + " ports"}`,
      detail: `Outbound traffic from ${describeAddr(r.src)} is not filtered${r.iface ? ` (${r.iface})` : ""}. Malware on an internal host can reach command-and-control servers on any port, tunnel data out over DNS or raw TCP, and pull second-stage payloads. Egress filtering is the cheapest control against exfiltration and reverse shells, and it generates the logs that reveal a compromise.`,
      evidence: [evidence(r)], fix: `Replace with explicit outbound allows: DNS only to your resolvers, HTTP/S (ideally via a proxy), NTP, mail only to your relay, plus anything the business needs. Deny and log the rest. Start in log-only mode for a week to learn what is actually used.`,
      snippet: fixSnippet("egress", r, {}), refs: REF.egress, attack: ATTACK.egress }));
  }

  // --- logging -----------------------------------------------------------
  const denyNoLog = rules.filter((r) => active(r) && r.action !== "allow" && r.log === false);
  if (denyNoLog.length) findings.push(mkFinding({ id: fid("LOG"), type: "logging", severity: "low", title: `${denyNoLog.length} deny rule(s) drop traffic without logging`,
    detail: `Dropped traffic is the earliest signal of a scan, a misconfiguration, or lateral movement. These rules discard packets silently: ${denyNoLog.slice(0, 8).map(ruleRef).join("; ")}${denyNoLog.length > 8 ? "; ..." : ""}.`,
    evidence: denyNoLog.map(evidence), fix: `Enable logging on deny rules (rate-limited if volume is a concern) and ship the logs to your SIEM.`, snippet: fixSnippet("logging", denyNoLog[0], {}), refs: REF.logging }));
  const sensNoLog = rules.filter((r) => active(r) && r.action === "allow" && r.log === false && notEstablished(r) && !r.dstPorts.any && RISKY.some((s) => s.sev !== "medium" && s.ports.some((p) => r.dstPorts.ranges.some((q) => q[0] <= p[1] && p[0] <= q[1]))));
  if (sensNoLog.length) findings.push(mkFinding({ id: fid("LOG"), type: "logging", severity: "low", title: `${sensNoLog.length} allow rule(s) to admin/database ports are not logged`,
    detail: `Sessions to SSH, RDP, SMB, WinRM, databases and similar should leave a trace at the firewall so that a stolen credential or an unusual source stands out. Unlogged: ${sensNoLog.slice(0, 8).map(ruleRef).join("; ")}${sensNoLog.length > 8 ? "; ..." : ""}.`,
    evidence: sensNoLog.map(evidence), fix: `Turn on per-rule logging for allows to administrative and data services.`, snippet: fixSnippet("logging", sensNoLog[0], {}), refs: REF.logging, attack: "T1021" }));

  // --- hygiene -----------------------------------------------------------
  const disabled = rules.filter((r) => !r.enabled);
  if (disabled.length) findings.push(mkFinding({ id: fid("HYG"), type: "hygiene", severity: "info", title: `${disabled.length} disabled rule(s) left in the rule base`,
    detail: `Disabled rules are clutter: they are easy to re-enable by accident and they make reviews slower. ${disabled.slice(0, 8).map(ruleRef).join("; ")}${disabled.length > 8 ? "; ..." : ""}.`,
    evidence: disabled.map(evidence), fix: `Delete rules that have been disabled for more than one change cycle; keep history in version control, not in the live policy.`, refs: REF.hygiene }));
  const suspicious = rules.filter((r) => /\b(test|testing|temp|tmp|temporary|allow[-_ ]?all|permit[-_ ]?all|any[-_ ]?any|debug|todo|fixme|open[-_ ]?all|delete[-_ ]?me)\b/i.test(r.name || ""));
  if (suspicious.length) findings.push(mkFinding({ id: fid("HYG"), type: "hygiene", severity: "low", title: `${suspicious.length} rule(s) named like temporary or catch-all rules`,
    detail: `Names such as test, temp or allow-all usually mark a rule that was meant to be removed after troubleshooting: ${suspicious.map((r) => `#${r.idx} "${r.name}"`).join("; ")}.`,
    evidence: suspicious.map(evidence), fix: `Review each one with its owner; remove it or rename it with its real purpose and an expiry date.`, refs: REF.hygiene }));
  const unresolvedAll = [...new Set(rules.flatMap((r) => r.unresolved))];
  if (unresolvedAll.length) findings.push(mkFinding({ id: fid("UNR"), type: "unresolved", severity: "info", title: `${unresolvedAll.length} object / alias / service name(s) could not be resolved`,
    detail: `These names are referenced but not defined in the paste, so the rules that use them are analysed conservatively (never treated as 'any', never used to prove shadowing): ${unresolvedAll.slice(0, 20).join(", ")}${unresolvedAll.length > 20 ? ", ..." : ""}.`,
    evidence: rules.filter((r) => r.unresolved.length).slice(0, 10).map(evidence), fix: `Paste the object-group / address / service / alias definitions along with the rules for a complete audit.`, refs: REF.hygiene }));
  if (internalParsed.bad.length) findings.push(mkFinding({ id: fid("CFG"), type: "settings", severity: "info", title: `Ignored ${internalParsed.bad.length} invalid internal CIDR(s)`, detail: internalParsed.bad.join(", "), evidence: [], fix: "Use a.b.c.d/n or IPv6/n per line.", refs: [] }));

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.id.localeCompare(b.id));

  // --- stats + score ----------------------------------------------------
  const allows = rules.filter((r) => active(r) && r.action === "allow");
  const anySrcAllows = allows.filter((r) => fromAny(r) && notEstablished(r) && r.facing !== "loopback");
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  let penalty = 0; const breakdown = [];
  for (const sev of ["critical", "high", "medium", "low"]) { if (counts[sev]) { const p = counts[sev] * SEVERITY_WEIGHT[sev]; penalty += p; breakdown.push(`${counts[sev]} ${sev} x ${SEVERITY_WEIGHT[sev]} = ${p}`); } }
  const score = Math.max(0, 100 - penalty);
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
  const stats = {
    rules: rules.length, enabled: rules.filter((r) => r.enabled).length, allows: allows.length, denies: rules.filter((r) => active(r) && r.action !== "allow").length,
    anySrcAllows: anySrcAllows.length, pctAnySrcAllows: allows.length ? Math.round((anySrcAllows.length / allows.length) * 100) : 0,
    shadowed: rules.filter((r) => r.flags.includes("shadowed") || r.flags.includes("overridden")).length, redundant: rules.filter((r) => r.flags.includes("redundant")).length,
    disabled: disabled.length, unresolved: unresolvedAll.length, exposedServices: exposure.filter((e) => e.fromAny.length).length, counts,
  };
  return {
    format: parsed.format, label: parsed.label, partial: !!parsed.partial, notes: parsed.notes || [], policies: parsed.policies || {}, implicitDeny: !!parsed.implicitDeny, ordered: parsed.ordered !== false,
    rules, findings, exposure, stats,
    score: { value: score, grade, penalty, breakdown, explanation: `Score = 100 - (${breakdown.join(" + ") || "0"}) = ${score}. Weights: critical 25, high 12, medium 6, low 2, info 0; floor 0.` },
    internal: internal.map(fmtRange),
  };
}

export function audit(text, opts = {}) {
  const parsed = parseConfig(text, opts.format);
  return analyze(parsed, opts);
}

// ===========================================================================
// 6. Export helpers (plain strings; no BigInt leaks)
// ===========================================================================
export function ruleToPlain(r) {
  return {
    idx: r.idx, lineNo: r.lineNo, name: r.name, scope: r.scope, chain: r.chain, action: r.action, direction: r.direction, iface: r.iface, proto: r.proto,
    src: describeAddr(r.src), srcPorts: describePorts(r.srcPorts), dst: describeAddr(r.dst), dstPorts: describePorts(r.dstPorts),
    enabled: r.enabled, log: r.log, state: r.state, restricted: r.restricted, facing: r.facing, flags: r.flags || [], shadowedBy: r.shadowedBy || null, redundantOf: r.redundantOf || null, unresolved: r.unresolved, raw: r.raw,
  };
}
export function resultToJson(res) {
  return JSON.stringify({
    tool: "Darknode Firewall Rule Audit", generated: new Date().toISOString(), format: res.format, label: res.label, partial: res.partial, score: res.score, stats: res.stats,
    policies: res.policies, internal: res.internal, notes: res.notes, findings: res.findings, exposure: res.exposure, rules: res.rules.map(ruleToPlain),
  }, null, 2);
}
const csvQ = (s) => `"${String(s == null ? "" : s).replace(/"/g, '""')}"`;
export function findingsToCsv(findings) {
  const out = ["id,severity,confidence,type,title,rules,lines,fix,references,attack"];
  for (const f of findings) out.push([f.id, f.severity, f.confidence, f.type, csvQ(f.title), csvQ(f.evidence.map((e) => "#" + e.idx).join(" ")), csvQ(f.evidence.map((e) => e.lineNo).join(" ")), csvQ(f.fix), csvQ(f.refs.join("; ")), csvQ(f.attack)].join(","));
  return out.join("\n") + "\n";
}
export function remediationText(res) {
  const L = [`Firewall Rule Audit - remediation list`, `Format: ${res.label}   Rules: ${res.stats.rules}   Score: ${res.score.value}/100 (${res.score.grade})`, ""];
  let n = 0;
  for (const f of res.findings) {
    if (f.severity === "info") continue;
    n++;
    L.push(`${n}. [${f.severity.toUpperCase()}] ${f.title}`);
    if (f.evidence.length) L.push(`   Rules: ${f.evidence.map((e) => "#" + e.idx + (e.lineNo ? " (line " + e.lineNo + ")" : "")).join(", ")}`);
    L.push(`   Fix: ${f.fix}`);
    if (f.snippet) L.push(...f.snippet.split("\n").map((s) => "   | " + s));
    if (f.refs.length) L.push(`   Ref: ${f.refs.join("; ")}`);
    L.push("");
  }
  if (!n) L.push("No actionable findings.");
  return L.join("\n");
}
export function summaryText(res) {
  const c = res.stats.counts;
  return `Firewall Rule Audit (${res.label}): ${res.stats.rules} rules, score ${res.score.value}/100 (${res.score.grade}). ` +
    `${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low, ${c.info} info. ` +
    `${res.stats.anySrcAllows} of ${res.stats.allows} allow rules (${res.stats.pctAnySrcAllows}%) accept from any source; ${res.stats.exposedServices} risky service(s) reachable from any; ` +
    `${res.stats.shadowed} shadowed, ${res.stats.redundant} redundant, ${res.stats.disabled} disabled.` +
    (res.findings.length ? ` Top: ${res.findings[0].title}.` : "");
}

// Security Graph sink: audit findings -> common Finding shape (core/sink-map.js).
// FWA-xxx-nnn ids and "#idx (line n)" titles shift whenever a rule is added, so
// per-rule findings are keyed by the rule text itself (the dead rule for shadowed /
// redundant) and chain / aggregate findings by their title without counts. `device`
// (optional) names the firewall: it becomes the linked ASSET and scopes the keys so
// identical rules on two firewalls stay two findings.
const SINK_RULE_LABEL = { "any-any": "Any-to-any allow", exposure: "Risky service exposed", shadowed: "Shadowed rule", redundant: "Redundant rule", egress: "Unrestricted egress" };
export function toSinkFindings(res, { device } = {}) {
  const dev = String(device || "").trim();
  return ((res && res.findings) || []).map((f) => {
    const perRule = SINK_RULE_LABEL[f.type] && f.evidence.length && !/^[^:]+: unrestricted egress \(policy/.test(f.title);
    let id, title;
    if (perRule) {
      const e = f.evidence[f.evidence.length - 1];
      const raw = String(e.raw || "").replace(/\s+/g, " ").trim();
      id = [f.type, dev, e.scope || "", raw].join("|");
      title = `${SINK_RULE_LABEL[f.type]}: ${e.name || (raw.length > 120 ? raw.slice(0, 117) + "..." : raw)}`;
    } else {
      title = f.title.replace(/^(Ignored )?\d+ /, "$1");
      title = title.charAt(0).toUpperCase() + title.slice(1);
      id = [f.type, dev, title].join("|");
    }
    return {
      id, title, severity: f.severity, confidence: f.confidence, category: f.type,
      description: `${f.title}. ${f.detail || ""}`.trim(), recommendation: f.fix + (f.snippet ? "\n" + f.snippet : ""),
      controls: controlsFromRefs([...(f.refs || []), f.attack]),
      evidence: f.evidence.slice(0, 50).map((e) => ({ rule: e.idx, line: e.lineNo, name: e.name || "", scope: e.scope || "", raw: e.raw })),
      evidenceCount: f.evidence.length,
      assets: dev ? [{ type: "ASSET", name: dev, data: { kind: "firewall", format: res.format } }] : [],
      tags: ["fwaudit", res.format].filter(Boolean),
    };
  });
}
