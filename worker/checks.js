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

// Registry of worker-native check types a monitor can run. Each: (config, deps) -> findings[].
export const CHECKS = {
  "cert-expiry": (cfg, deps) => certExpiryCheck((cfg && cfg.domains) || [], { ...deps, warnDays: (cfg && cfg.warnDays) || 21 }),
};

export function runCheck(type, cfg, deps) {
  const fn = CHECKS[type];
  if (!fn) return Promise.resolve([]);
  return fn(cfg, deps);
}
