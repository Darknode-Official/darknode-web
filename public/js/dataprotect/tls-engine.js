// tls-engine.js — pure helpers for the certificate / TLS fleet monitor.
// Reuses the certificate-transparency parsing from posture-engine (DRY) and adds
// expiry banding, fleet roll-up and watchlist normalisation. No network, no state.
// Tested in test/security/tls-fleet.test.mjs.

import { newestCert, certDaysLeft } from "./posture-engine.js";

export { newestCert, certDaysLeft };

export const BANDS = {
  expired: { level: "expired", label: "Expired", c: "#b00020", rank: 4 },
  urgent:  { level: "urgent",  label: "< 14 days", c: "#d9480f", rank: 3 },
  soon:    { level: "soon",    label: "< 30 days", c: "#b58100", rank: 2 },
  watch:   { level: "watch",   label: "< 60 days", c: "#2f7d9e", rank: 1 },
  ok:      { level: "ok",      label: "OK", c: "#2f9e56", rank: 0 },
  unknown: { level: "unknown", label: "Unknown", c: "#8a93a6", rank: -1 },
};

export function expiryBand(daysLeft) {
  if (daysLeft == null) return BANDS.unknown;
  if (daysLeft < 0) return BANDS.expired;
  if (daysLeft < 14) return BANDS.urgent;
  if (daysLeft < 30) return BANDS.soon;
  if (daysLeft < 60) return BANDS.watch;
  return BANDS.ok;
}

// Trim an issuer DN down to a readable organisation / CN.
export function issuerLabel(issuer) {
  if (!issuer) return "";
  const s = String(issuer);
  const o = s.match(/O\s*=\s*"?([^",/]+)/i);
  const cn = s.match(/CN\s*=\s*"?([^",/]+)/i);
  return (o && o[1].trim()) || (cn && cn[1].trim()) || s.slice(0, 48);
}

// Normalise a pasted blob of hostnames (newline/comma/space separated) to a
// clean, de-duplicated, order-preserving list of valid domains.
export function parseDomains(raw) {
  const seen = new Set();
  const out = [];
  for (let tok of String(raw || "").split(/[\s,;]+/)) {
    if (!tok) continue;
    tok = tok.replace(/^[a-z]+:\/\//i, "").replace(/\/.*$/, "").replace(/:\d+$/, "").toLowerCase();
    if (!/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(tok)) continue;
    if (seen.has(tok)) continue;
    seen.add(tok); out.push(tok);
  }
  return out;
}

// Build one monitor entry from a domain + crt.sh rows (pure).
export function buildEntry(domain, rows, now = Date.now()) {
  const cert = newestCert(rows, now);
  if (!cert) return { domain, ok: false, band: BANDS.unknown, issuer: "", notAfter: "", notBefore: "", daysLeft: null, checked: now };
  const daysLeft = certDaysLeft(cert.notAfter, now);
  return {
    domain, ok: true, band: expiryBand(daysLeft),
    issuer: issuerLabel(cert.issuer), issuerRaw: cert.issuer,
    notAfter: cert.notAfter, notBefore: cert.notBefore,
    daysLeft, names: cert.names, checked: now,
  };
}

// Roll a set of entries into fleet KPIs, worst-first.
export function summarizeFleet(entries) {
  const list = [...(entries || [])];
  list.sort((a, b) => (b.band.rank - a.band.rank) || ((a.daysLeft ?? 1e9) - (b.daysLeft ?? 1e9)));
  const counts = { expired: 0, urgent: 0, soon: 0, watch: 0, ok: 0, unknown: 0 };
  let soonest = null;
  for (const e of list) {
    counts[e.band.level]++;
    if (e.daysLeft != null && (soonest == null || e.daysLeft < soonest)) soonest = e.daysLeft;
  }
  const alerting = counts.expired + counts.urgent + counts.soon;
  return { list, counts, soonest, alerting, total: list.length };
}

export function selfTest() {
  const out = [];
  const T = (n, c) => out.push({ name: n, pass: !!c });
  T("band expired", expiryBand(-1).level === "expired");
  T("band urgent", expiryBand(5).level === "urgent");
  T("band soon", expiryBand(20).level === "soon");
  T("band ok", expiryBand(200).level === "ok");
  T("band unknown", expiryBand(null).level === "unknown");
  T("issuerLabel O", issuerLabel("C=US, O=Let's Encrypt, CN=E5") === "Let's Encrypt");
  T("parseDomains dedupes", parseDomains("a.com\nhttps://a.com/x\n b.com , a.com").join(",") === "a.com,b.com");
  const e = buildEntry("x.com", [{ issuer_name: "O=Let's Encrypt", not_after: new Date(Date.now() + 5 * 86400000).toISOString() }]);
  T("entry urgent", e.band.level === "urgent" && e.issuer === "Let's Encrypt");
  const s = summarizeFleet([e, buildEntry("y.com", [])]);
  T("fleet counts", s.counts.urgent === 1 && s.counts.unknown === 1 && s.alerting === 1);
  return { pass: out.every((t) => t.pass), tests: out };
}

export default { BANDS, expiryBand, issuerLabel, parseDomains, buildEntry, summarizeFleet, newestCert, certDaysLeft, selfTest };
