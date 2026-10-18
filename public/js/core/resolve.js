// Entity resolution for the unified inventory (Deck D2). PURE — no DOM, no network.
//
// The same machine or person is reported by many tools under different spellings:
// "SERVER01", "server01", "server01.corp.local"; "jane@corp.com", "CORP\\jane",
// "Jane Doe". This module canonicalises those and clusters the Security Graph's
// existing entities into "same host" / "same person" groups so the Assets,
// Identities and Coverage scenes can show one row per real thing.
//
// NON-DESTRUCTIVE: this reads entities and returns groups. It does NOT change how
// tools merge into the graph (that merge key is still type+name in core/sink-map.js).
// Adopting these canonical names into the merge key itself is a separate, migration-
// guarded step, so this layer can never split or corrupt the live graph.
//
// Reuses the identity normalisers that the access-review / jml / oauthgov engines
// already share, rather than reinventing weaker lowercase-only variants.
import { normalizeEmail, normalizeName } from "../identity/access-review-engine.js";

const str = (v) => String(v == null ? "" : v).trim();
const lc = (v) => str(v).toLowerCase();

// Host-like graph types this layer resolves together (a host can show up as any of them).
export const HOST_TYPES = ["ASSET", "ENDPOINT", "IP", "DOMAIN"];

// ---------------------------------------------------------------------------
// Low-level canonicalisers
// ---------------------------------------------------------------------------

// Strip a scheme, path and port someone may have wrapped a host in, and unwrap a
// bracketed IPv6 literal. Returns a bare, lowercased host or address.
export function bareHost(name) {
  let s = lc(name).replace(/^[a-z][a-z0-9+.-]*:\/\//, ""); // scheme://
  s = s.split("/")[0].split("?")[0];                        // path / query
  const br = /^\[([0-9a-f:]+)\](?::\d+)?$/.exec(s);          // [ipv6]:port
  if (br) return br[1];
  if (!s.includes("::") && /:\d+$/.test(s)) s = s.replace(/:\d+$/, ""); // host:port (not ipv6)
  return s.replace(/\.+$/, "");                             // trailing FQDN root dot(s)
}

export function isIpv4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(str(s));
  return !!m && m.slice(1).every((o) => Number(o) <= 255);
}
export function isIpv6(s) {
  const t = lc(s);
  return /^[0-9a-f:]+$/.test(t) && t.includes(":") && (t.match(/:/g) || []).length >= 2 && !/:::/.test(t);
}
export function isIp(s) { return isIpv4(bareHost(s)) || isIpv6(bareHost(s)); }

// Canonical IPv6: expand "::", drop leading zeros per group, then compress the
// longest run of zero groups back to "::". RFC 5952-ish, enough to dedupe.
export function canonIpv6(s) {
  let t = lc(s);
  if (!isIpv6(t)) return t;
  let groups;
  if (t.includes("::")) {
    const [a, b] = t.split("::");
    const head = a ? a.split(":") : [];
    const tail = b ? b.split(":") : [];
    const fill = 8 - head.length - tail.length;
    if (fill < 0) return t;
    groups = [...head, ...Array(fill).fill("0"), ...tail];
  } else {
    groups = t.split(":");
    if (groups.length !== 8) return t;
  }
  groups = groups.map((g) => (g.replace(/^0+/, "") || "0"));
  // find the longest run of "0" (length >= 2) to compress
  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  for (let i = 0; i < groups.length; i++) {
    if (groups[i] === "0") { if (curStart < 0) curStart = i; curLen++; if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; } }
    else { curStart = -1; curLen = 0; }
  }
  if (bestLen < 2) return groups.join(":");
  const before = groups.slice(0, bestStart).join(":");
  const after = groups.slice(bestStart + bestLen).join(":");
  return `${before}::${after}`;
}

// Canonical IP string (leading zeros stripped for v4, compressed for v6), else the bare host.
export function canonIp(name) {
  const s = bareHost(name);
  if (isIpv4(s)) return s.split(".").map((o) => String(Number(o))).join(".");
  if (isIpv6(s)) return canonIpv6(s);
  return s;
}

// Canonical domain (bare host, wildcard "*." stripped).
export function canonDomain(name) { return bareHost(name).replace(/^\*\./, ""); }

// Canonical MAC "aa:bb:cc:dd:ee:ff", or null if the input is not exactly 12 hex digits
// once separators (:- .) are removed.
export function canonMac(name) {
  const raw = str(name);
  if (!/^[0-9a-fA-F]{2}([:\-.]?[0-9a-fA-F]{2}){5}$/.test(raw) && !/^[0-9a-fA-F]{12}$/.test(raw)) return null;
  const hex = raw.toLowerCase().replace(/[^0-9a-f]/g, "");
  return hex.length === 12 ? hex.match(/.{2}/g).join(":") : null;
}

// Break a host-like name into parts for clustering.
export function hostParts(name) {
  const s = bareHost(name);
  if (isIpv4(s) || isIpv6(s)) { const ip = canonIp(s); return { kind: "ip", key: ip, short: ip, fqdn: null, labels: [] }; }
  const labels = s.split(".").filter(Boolean);
  const short = labels[0] || s;
  return { kind: "host", key: s, short, fqdn: labels.length > 1 ? s : null, labels };
}

// ---------------------------------------------------------------------------
// Identity keys — reuse the shared normalisers
// ---------------------------------------------------------------------------

// Derive a person's matching keys from a graph IDENTITY entity's name + data, which
// are inconsistent across engines (name may be email, UPN, login or display name).
// Returns { emailKey, upnKey, samKey, nameKey } — any may be "".
export function identityKeys(name, data = {}) {
  const d = data || {};
  const nm = str(name);
  const pool = [d.email, d.upn, d.userPrincipalName, d.account, d.login, nm].map(str).filter(Boolean);
  let emailKey = "";
  for (const c of pool) { if (c.includes("@")) { const e = normalizeEmail(c); if (e && e.includes("@")) { emailKey = e; break; } } }
  const upnRaw = str(d.upn || d.userPrincipalName) || (emailKey || (nm.includes("@") ? nm : ""));
  const upnKey = upnRaw.includes("@") ? normalizeEmail(upnRaw) : "";
  const samKey = lc(d.samAccountName || d.sam || "").replace(/^.*\\/, ""); // strip DOMAIN\ prefix
  const nameKey = normalizeName(d.displayName || d.name || (nm.includes("@") ? "" : nm));
  return { emailKey, upnKey, samKey, nameKey };
}

// ---------------------------------------------------------------------------
// Union-find
// ---------------------------------------------------------------------------
function makeUF(n) {
  const p = Array.from({ length: n }, (_, i) => i);
  const find = (x) => { while (p[x] !== x) { p[x] = p[p[x]]; x = p[x]; } return x; };
  return { find, union: (a, b) => { const ra = find(a), rb = find(b); if (ra !== rb) p[Math.max(ra, rb)] = Math.min(ra, rb); } };
}

// source label for an entity (the tool that reported it).
function sourceOf(e) { return str(e.source || (e.data && e.data._toolSource) || (e.data && e.data.tool) || ""); }

// ---------------------------------------------------------------------------
// Resolve assets (hosts / IPs / domains)
// ---------------------------------------------------------------------------
// entities: the raw graph entities. Returns deterministic clusters:
//   { key, name, type, kind, members:[id], sources:[tool], bySource:{tool:[id]}, macs:[], ips:[] }
export function resolveAssets(entities) {
  const list = (entities || []).filter((e) => e && HOST_TYPES.includes(e.type) && str(e.name));
  const parts = list.map((e) => ({ e, p: hostParts(e.name), mac: canonMac((e.data && (e.data.mac || e.data.macAddress)) || "") }));
  const uf = makeUF(parts.length);

  // index by exact host/ip key and by MAC
  const byKey = new Map(), byMac = new Map();
  parts.forEach((x, i) => {
    const prev = byKey.get(x.p.key); if (prev != null) uf.union(prev, i); else byKey.set(x.p.key, i);
    if (x.mac) { const pm = byMac.get(x.mac); if (pm != null) uf.union(pm, i); else byMac.set(x.mac, i); }
  });

  // short <-> FQDN, only when the short label maps to exactly one distinct FQDN.
  const fqdnByShort = new Map(); // short -> Set(fqdn)
  parts.forEach((x) => { if (x.p.fqdn) { if (!fqdnByShort.has(x.p.short)) fqdnByShort.set(x.p.short, new Set()); fqdnByShort.get(x.p.short).add(x.p.fqdn); } });
  parts.forEach((x, i) => {
    if (x.p.kind === "host" && !x.p.fqdn) { // a short-only name
      const set = fqdnByShort.get(x.p.short);
      if (set && set.size === 1) { const fq = [...set][0]; const j = byKey.get(fq); if (j != null) uf.union(i, j); }
    }
  });

  return collect(parts, uf, (members) => {
    // display name + representative type: prefer an FQDN, then a short host, then an IP/domain.
    const fqdn = members.find((m) => m.p.fqdn);
    const host = fqdn || members.find((m) => m.p.kind === "host") || members[0];
    const ips = [...new Set(members.filter((m) => m.p.kind === "ip").map((m) => m.p.key))].sort();
    const macs = [...new Set(members.map((m) => m.mac).filter(Boolean))].sort();
    const type = host.e.type === "DOMAIN" ? "DOMAIN" : (members.some((m) => m.e.type === "ENDPOINT") ? "ENDPOINT" : (host.p.kind === "ip" ? "IP" : "ASSET"));
    return { key: host.p.key, name: host.e.name, type, kind: host.p.kind, ips, macs };
  });
}

// ---------------------------------------------------------------------------
// Resolve identities (people / accounts)
// ---------------------------------------------------------------------------
// Union only on strong keys (email, UPN, samAccountName). A name-only match never
// auto-merges (two different people share a name); it is surfaced as a suggestion.
export function resolveIdentities(entities) {
  const list = (entities || []).filter((e) => e && e.type === "IDENTITY" && str(e.name));
  const keyed = list.map((e) => ({ e, k: identityKeys(e.name, e.data || {}) }));
  const uf = makeUF(keyed.length);
  const idx = { email: new Map(), upn: new Map(), sam: new Map() };
  const join = (map, val, i) => { if (!val) return; const prev = map.get(val); if (prev != null) uf.union(prev, i); else map.set(val, i); };
  keyed.forEach((x, i) => { join(idx.email, x.k.emailKey, i); join(idx.upn, x.k.upnKey, i); join(idx.sam, x.k.samKey, i); });

  const clusters = collect(keyed, uf, (members) => {
    const withEmail = members.find((m) => m.k.emailKey);
    const rep = withEmail || members[0];
    const emails = [...new Set(members.map((m) => m.k.emailKey).filter(Boolean))].sort();
    const names = [...new Set(members.map((m) => m.k.nameKey).filter(Boolean))].sort();
    return { key: rep.k.emailKey || rep.k.upnKey || rep.k.samKey || lc(rep.e.name), name: rep.e.name, type: "IDENTITY", emails, nameKeys: names };
  });

  // suggestions: same nameKey across clusters that have *different* emails (possible same person, flagged not merged)
  const byName = new Map();
  clusters.forEach((c, ci) => c.nameKeys.forEach((nk) => { if (!byName.has(nk)) byName.set(nk, new Set()); byName.get(nk).add(ci); }));
  const suggestions = [];
  for (const [nk, set] of byName) if (set.size > 1) suggestions.push({ nameKey: nk, clusterKeys: [...set].map((ci) => clusters[ci].key).sort() });
  suggestions.sort((a, b) => a.nameKey.localeCompare(b.nameKey));
  return { clusters, suggestions };
}

// Build deterministic clusters from a union-find over `items` ({ e, ... }). `describe`
// maps a cluster's members to its summary fields. Members carry id/sources/bySource.
function collect(items, uf, describe) {
  const groups = new Map();
  items.forEach((x, i) => { const r = uf.find(i); if (!groups.has(r)) groups.set(r, []); groups.get(r).push(x); });
  const out = [];
  for (const members of groups.values()) {
    members.sort((a, b) => String(a.e.id).localeCompare(String(b.e.id))); // stable rep + output, independent of input order
    const ids = members.map((m) => m.e.id);
    const bySource = {};
    for (const m of members) { const s = sourceOf(m.e) || "unknown"; (bySource[s] = bySource[s] || []).push(m.e.id); }
    for (const s of Object.keys(bySource)) bySource[s].sort((a, b) => String(a).localeCompare(String(b)));
    const sources = Object.keys(bySource).sort();
    out.push({ ...describe(members), members: ids, sources, bySource });
  }
  out.sort((a, b) => String(a.key).localeCompare(String(b.key)));
  return out;
}

// ---------------------------------------------------------------------------
// Coverage matrix
// ---------------------------------------------------------------------------
// clusters: from resolveAssets / resolveIdentities. categories: [{ id, label, sources:[toolId] }]
// — which tools count as "covered" by each control category (e.g. EDR, backup, IdP).
// Returns per-cluster coverage plus which categories are missing.
export function coverageMatrix(clusters, categories) {
  const cats = categories || [];
  return (clusters || []).map((c) => {
    const have = new Set(c.sources);
    const cover = {}, missing = [];
    for (const cat of cats) {
      const hit = (cat.sources || []).some((s) => have.has(s));
      cover[cat.id] = hit;
      if (!hit) missing.push(cat.id);
    }
    return { key: c.key, name: c.name, type: c.type, sources: c.sources, cover, missing };
  });
}
