// Server-side monitor checks (Deck D4). These run inside the worker on a schedule,
// using the worker's own fetch (not the browser proxy), and reuse the SAME pure engine
// grading the browser tools use. The network is injected so each check is unit-testable.
//
// Findings returned use the monitor shape monitor-core expects:
//   { key, severity, title, status, ...extra }
// `key` is stable across runs so diffFindings can tell a new issue from a persisting one.
import { newestCert, certDaysLeft } from "../public/js/dataprotect/posture-engine.js";

// Normalise SSLMate certspotter issuances into crt.sh-shaped rows (same mapping the
// browser ct-fetch uses), so newestCert() consumes either source unchanged.
function fromCertspotter(arr) {
  if (!Array.isArray(arr)) return [];
  return arr.map((x) => ({
    issuer_name: (x.issuer && (x.issuer.name || x.issuer.friendly_name)) || "",
    not_after: x.not_after || "", not_before: x.not_before || "",
    name_value: (x.dns_names || []).join("\n"),
  }));
}

// Fetch certificate-transparency rows for a domain, worker-native. crt.sh first
// (richest, flaky), certspotter as a fallback. Never throws; returns [] on failure.
export async function fetchCertRows(domain, f) {
  const d = encodeURIComponent(domain);
  try {
    const r = await f("https://crt.sh/?output=json&exclude=expired&q=" + d, { headers: { accept: "application/json" } });
    if (r.ok) { const a = await r.json().catch(() => null); if (Array.isArray(a) && a.length) return a; }
  } catch (_) {}
  try {
    const url = "https://api.certspotter.com/v1/issuances?include_subdomains=false&expand=issuer&expand=not_before&expand=not_after&expand=dns_names&domain=" + d;
    const r = await f(url, { headers: { accept: "application/json" } });
    if (r.ok) { const a = await r.json().catch(() => null); const rows = fromCertspotter(a); if (rows.length) return rows; }
  } catch (_) {}
  return [];
}

const sev = (days, warnDays) => {
  if (days == null) return null;          // no data -> no finding (never a fake pass/fail)
  if (days < 0) return "critical";        // already expired
  if (days <= 7) return "critical";
  if (days <= warnDays) return "high";
  return null;                            // healthy -> no finding
};

// certExpiryCheck(domains, deps) -> findings[]
// deps: { fetch, now, warnDays }. One finding per domain whose newest leaf cert is
// expired or expiring within warnDays. A domain with a healthy cert yields nothing
// (only real problems become findings), and a domain CT can't resolve is skipped.
export async function certExpiryCheck(domains, deps = {}) {
  const f = deps.fetch || (typeof fetch !== "undefined" ? fetch : null);
  const now = deps.now || Date.now();
  const warnDays = deps.warnDays || 21;
  if (!f) return [];
  const out = [];
  for (const domain of (domains || [])) {
    const dom = String(domain || "").trim().toLowerCase();
    if (!dom) continue;
    const rows = await fetchCertRows(dom, f);
    const cert = newestCert(rows, now);
    if (!cert || !cert.notAfter) continue;            // no CT data: skip, don't invent
    const days = certDaysLeft(cert.notAfter, now);
    const s = sev(days, warnDays);
    if (!s) continue;                                 // healthy
    out.push({
      key: "cert:" + dom,
      severity: s,
      status: "open",
      title: days < 0 ? `Certificate for ${dom} has expired` : `Certificate for ${dom} expires in ${days} day${days === 1 ? "" : "s"}`,
      domain: dom, daysToExpiry: days, issuer: cert.issuer, notAfter: cert.notAfter,
      category: "certificate", tool: "monitor:cert-expiry",
    });
  }
  return out;
}

// ---- KEV / EPSS watch (Deck D4 + D9 "what affects you", server-side) --------------------
// A monitor that matches the workspace's own CVE inventory against the current CISA KEV
// catalogue and the FIRST EPSS top-scores feed, so a newly-exploited vulnerability that
// already sits in your graph raises an alert even with nobody at the Deck. The CVE list is
// read from the workspace's graph by the MonitorDO and injected as deps.cves; the feeds are
// the same mirrored, same-origin files the browser "What affects you" panel reads, fetched
// here with the worker's own fetch. Nothing is invented: a CVE surfaces only if it is in the
// KEV catalogue or its EPSS score is at or above the floor.

const CVE_RE = /CVE-\d{4}-\d{4,7}/gi;

// Extract the unique CVE ids a set of graph entities assert, worker-side (mirrors the
// client cveIds/graphCves, kept self-contained so the worker needn't bundle browser modules).
export function cvesFromEntities(entities) {
  const out = new Set();
  for (const e of (entities || [])) {
    if (!e || typeof e !== "object") continue;
    const d = e.data || {};
    const add = (v) => { if (v == null) return; const s = String(v).match(CVE_RE); if (s) for (const c of s) out.add(c.toUpperCase()); };
    add(e.name);
    add(d.cve);
    if (Array.isArray(d.cves)) for (const c of d.cves) add(c);
    add(d.evidence);
  }
  return [...out];
}

// Fetch one mirrored feed ({data:[{cve,...}]}) and return its data array; [] on any failure.
async function fetchFeed(url, f) {
  try { const r = await f(url, { headers: { accept: "application/json" } }); if (r.ok) { const j = await r.json().catch(() => null); if (j && Array.isArray(j.data)) return j.data; } } catch (_) {}
  return [];
}

// matchKevEpss(cves, ctx) -> findings[]. PURE. ctx: { kev: Map cve->{dueDate,dateAdded}, epss:
// Map cve->score, epssFloor }. KEV match = critical (known-exploited); otherwise EPSS >= floor
// = high (>=0.9) or medium. Deterministic: keyed per CVE, sorted by key.
export function matchKevEpss(cves, ctx = {}) {
  const kev = ctx.kev instanceof Map ? ctx.kev : new Map();
  const epss = ctx.epss instanceof Map ? ctx.epss : new Map();
  const floor = typeof ctx.epssFloor === "number" ? ctx.epssFloor : 0.5;
  const seen = new Set(), out = [];
  for (const raw of (cves || [])) {
    const cve = String(raw || "").toUpperCase().trim();
    if (!/^CVE-\d{4}-\d{4,7}$/.test(cve) || seen.has(cve)) continue;
    seen.add(cve);
    const score = epss.get(cve);
    if (kev.has(cve)) {
      const info = kev.get(cve) || {};
      out.push({ key: "kev:" + cve, severity: "critical", status: "open", title: `Known-exploited vulnerability in your inventory: ${cve}`, cve, kev: true, dueDate: info.dueDate || "", epss: typeof score === "number" ? score : null, category: "vulnerability", tool: "monitor:kev-epss" });
    } else if (typeof score === "number" && score >= floor) {
      out.push({ key: "epss:" + cve, severity: score >= 0.9 ? "high" : "medium", status: "open", title: `High exploit-likelihood vulnerability in your inventory: ${cve} (EPSS ${Math.round(score * 100)}%)`, cve, kev: false, epss: score, category: "vulnerability", tool: "monitor:kev-epss" });
    }
  }
  out.sort((a, b) => a.key.localeCompare(b.key));
  return out;
}

// kevEpssCheck(cfg, deps) -> findings[]. deps: { fetch, cves, feedBase, epssFloor }.
export async function kevEpssCheck(cfg, deps = {}) {
  const f = deps.fetch || (typeof fetch !== "undefined" ? fetch : null);
  const cves = deps.cves || [];
  if (!f || !cves.length) return [];
  const base = (deps.feedBase || "https://sentinel-b4194.web.app").replace(/\/+$/, "");
  const [kevRows, epssRows] = await Promise.all([
    fetchFeed(base + "/data/feeds/cisa-kev-index.json", f),
    fetchFeed(base + "/data/feeds/epss-top.json", f),
  ]);
  if (!kevRows.length && !epssRows.length) return [];   // feeds unreachable: skip, don't invent
  const kev = new Map();
  for (const r of kevRows) if (r && r.cve) kev.set(String(r.cve).toUpperCase(), { dueDate: r.dueDate || "", dateAdded: r.dateAdded || "" });
  const epss = new Map();
  for (const r of epssRows) if (r && r.cve && typeof r.epss === "number") epss.set(String(r.cve).toUpperCase(), r.epss);
  return matchKevEpss(cves, { kev, epss, epssFloor: (cfg && typeof cfg.epssFloor === "number" ? cfg.epssFloor : deps.epssFloor) });
}

// Registry of worker-native check types a monitor can run. Each: (config, deps) -> findings[].
export const CHECKS = {
  "cert-expiry": (cfg, deps) => certExpiryCheck((cfg && cfg.domains) || [], { ...deps, warnDays: (cfg && cfg.warnDays) || 21 }),
  "kev-epss": (cfg, deps) => kevEpssCheck(cfg || {}, deps),
};

export function runCheck(type, cfg, deps) {
  const fn = CHECKS[type];
  if (!fn) return Promise.resolve([]);
  return fn(cfg, deps);
}
