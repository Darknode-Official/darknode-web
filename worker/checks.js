// Server-side monitor checks (Deck D4). These run inside the worker on a schedule,
// using the worker's own fetch (not the browser proxy), and reuse the SAME pure engine
// grading the browser tools use. The network is injected so each check is unit-testable.
//
// Findings returned use the monitor shape monitor-core expects:
//   { key, severity, title, status, ...extra }
// `key` is stable across runs so diffFindings can tell a new issue from a persisting one.
import { newestCert, certDaysLeft, gradeEmail, parseSPF, parseDMARC } from "../public/js/dataprotect/posture-engine.js";
import { registrableDomain } from "../public/js/dataprotect/phish-engine.js";

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
// (richest, flaky), certspotter as a fallback. Never throws; returns [] on failure,
// marked .unreachable when neither log answered (as opposed to answering with no rows).
export async function fetchCertRows(domain, f) {
  const d = encodeURIComponent(domain);
  let answered = false, crtOk = false;
  try {
    const r = await f("https://crt.sh/?output=json&exclude=expired&q=" + d, { headers: { accept: "application/json" } });
    if (r.ok) { const a = await r.json().catch(() => null); if (Array.isArray(a)) answered = crtOk = true; if (Array.isArray(a) && a.length) return a; }
  } catch (_) {}
  try {
    const url = "https://api.certspotter.com/v1/issuances?include_subdomains=false&expand=issuer&expand=not_before&expand=not_after&expand=dns_names&domain=" + d;
    const r = await f(url, { headers: { accept: "application/json" } });
    if (r.ok) { const a = await r.json().catch(() => null); if (Array.isArray(a)) answered = true; const rows = fromCertspotter(a); if (rows.length) return rows; }
  } catch (_) {}
  // Both sources list only unexpired certificates, so a domain whose certificate has EXPIRED came
  // back empty and the monitor raised nothing for its most critical case. Ask crt.sh's full history.
  if (crtOk) try {
    const r = await f("https://crt.sh/?output=json&q=" + d, { headers: { accept: "application/json" } });
    if (r.ok) { const a = await r.json().catch(() => null); if (Array.isArray(a) && a.length) return a; }
  } catch (_) {}
  return answered ? [] : Object.assign([], { unreachable: true });
}

// "https://site.com/path", user@host, host:port, *.site and a trailing root dot -> the hostname
export const hostOnly = (d) => String(d || "").trim().toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, "").replace(/[/?#].*$/, "").replace(/^.*@/, "").replace(/:\d+$/, "").replace(/^\*\./, "").replace(/\.$/, "");

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
  // held: domains whose lookup got no answer this run. The monitor keeps their last finding
  // as it was, instead of reading the gap as "resolved" and alerting it as new next run.
  const out = [], held = [];
  for (const domain of (domains || [])) {
    // a monitor saved with "https://site.com/path", host:port or *.site gets no CT rows for that
    // string and was skipped every run (shown as 0 open); look up the hostname
    const dom = hostOnly(domain);
    if (!dom) continue;
    const rows = await fetchCertRows(dom, f);
    if (rows.unreachable) { held.push("cert:" + dom); continue; }
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
  return Object.assign(out, { held });
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

// Fetch one mirrored feed ({data:[{cve,...}]}) and return its data array; null on any failure.
async function fetchFeed(url, f) {
  try { const r = await f(url, { headers: { accept: "application/json" } }); if (r.ok) { const j = await r.json().catch(() => null); if (j && Array.isArray(j.data)) return j.data; } } catch (_) {}
  return null;
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
  // a feed that did not answer: skip, don't invent, and mark the run unreachable so the monitor
  // does not read its matches as resolved (and alert them as new when the feed is back)
  if (!kevRows || !epssRows) return Object.assign([], { unreachable: true });
  const kev = new Map();
  for (const r of kevRows) if (r && r.cve) kev.set(String(r.cve).toUpperCase(), { dueDate: r.dueDate || "", dateAdded: r.dateAdded || "" });
  const epss = new Map();
  for (const r of epssRows) if (r && r.cve && typeof r.epss === "number") epss.set(String(r.cve).toUpperCase(), r.epss);
  return matchKevEpss(cves, { kev, epss, epssFloor: (cfg && typeof cfg.epssFloor === "number" ? cfg.epssFloor : deps.epssFloor) });
}

// ---- Email & DNS posture drift (Deck D4) ------------------------------------------------
// Watches a domain's SPF, DMARC, MX and CAA records over DNS-over-HTTPS. SPF and DMARC are
// graded by the SAME gradeEmail() the browser Domain Posture tool uses, so a record that is
// removed or weakened between runs becomes a new or worsened finding (and an alert). A lookup
// neither resolver answered is "could not check": it yields no finding, is listed in .unknown,
// and its keys are .held so the monitor keeps the last state instead of calling it fixed.

const DOH = ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"];
const RR = { TXT: 16, MX: 15, CAA: 257 };

// dohQuery(name, type, f) -> record data strings ([] = answered with none, incl. NXDOMAIN);
// .failed when neither resolver gave an answer (network error, HTTP error, SERVFAIL/REFUSED).
export async function dohQuery(name, type, f) {
  for (const base of DOH) {
    try {
      const signal = typeof AbortSignal !== "undefined" && AbortSignal.timeout ? AbortSignal.timeout(8000) : undefined;
      const r = await f(base + "?type=" + type + "&name=" + encodeURIComponent(name), { headers: { accept: "application/dns-json" }, signal });
      if (!r || !r.ok) continue;
      const j = await r.json().catch(() => null);
      if (!j || (j.Status !== 0 && j.Status !== 3)) continue;
      const rows = (Array.isArray(j.Answer) ? j.Answer : []).filter((a) => a && (a.type === RR[type] || a.type === type)).map((a) => String(a.data || ""));
      // a long TXT arrives as several quoted strings ("v=spf1 ..." "...") that join into one
      return type === "TXT" ? rows.map((t) => t.replace(/^"|"$/g, "").replace(/"\s*"/g, "")) : rows;
    } catch (_) {}
  }
  return Object.assign([], { failed: true });
}

// One CAA answer, in presentation form (0 issue "ca.example") or the RFC 3597 generic form
// (\# 19 00 05 69 73 73 75 65 ...) some resolvers return. PURE. null when unreadable.
export function parseCaa(data) {
  const s = String(data || "").trim();
  const g = /^\\#\s+\d+\s+([0-9a-f\s]+)$/i.exec(s);
  if (g) {
    const b = (g[1].replace(/\s+/g, "").match(/../g) || []).map((h) => parseInt(h, 16));
    const n = b[1] || 0;
    if (b.length < 2 + n) return null;
    const txt = (a) => String.fromCharCode(...a);
    return { flags: b[0], tag: txt(b.slice(2, 2 + n)).toLowerCase(), value: txt(b.slice(2 + n)) };
  }
  const m = /^(\d+)\s+([a-z0-9]+)\s+"?(.*?)"?$/i.exec(s);
  return m ? { flags: +m[1], tag: m[2].toLowerCase(), value: m[3] } : null;
}

const EMAIL_IDS = { "SPF": "spf", "SPF lookup budget": "spf-lookups", "DMARC": "dmarc", "DMARC coverage (pct)": "dmarc-pct", "DMARC subdomain policy": "dmarc-sp", "DMARC reporting (rua)": "dmarc-rua" };

// gradeEmailDns(domain, rec) -> { findings, unknown }. PURE. rec: { spfTxts, dmarcTxts,
// dmarcFrom, mx, caa } as dohQuery returns them (an array marked .failed = could not check).
// Healthy records yield no finding; one finding per weak record, keyed per domain + record so
// a change (-all -> +all, p=reject -> missing) diffs as worsened rather than as a new issue.
export function gradeEmailDns(domain, rec = {}) {
  const findings = [], unknown = [];
  const k = (id) => "email:" + domain + ":" + id;
  const add = (id, check, severity, c) => findings.push({ key: k(id), severity, status: "open", title: `${check} on ${domain}: ${c.detail}`, domain, check, detail: c.detail, advice: c.advice || "", category: "email-dns", tool: "monitor:email-posture" });
  const skip = (ids, check, reason) => unknown.push({ domain, check, reason, keys: ids.map(k) });

  const spf = parseSPF(rec.spfTxts), dmarc = parseDMARC(rec.dmarcTxts);
  const sevOf = (c) => {
    if (c.status === "fail") return "high";                 // missing, duplicated, or over the lookup limit
    if (c.status !== "warn") return null;
    if (c.name === "SPF") {
      if (spf.qualifier === "+") return "critical";         // +all: any server may send as the domain
      if (spf.qualifier === "?") return "medium";
      if (spf.qualifier === "~") return "low";
      return /\bredirect=/i.test(spf.record || "") ? null : "medium"; // redirect= carries the policy elsewhere: not judged
    }
    if (c.name === "DMARC") return (rec.dmarcFrom ? dmarc.sp || dmarc.policy : dmarc.policy) === "none" ? "medium" : "low";
    return "low";
  };
  for (const c of gradeEmail({ spfTxts: rec.spfTxts, dmarcTxts: rec.dmarcTxts, dmarcFrom: rec.dmarcFrom || null }).checks) {
    const id = EMAIL_IDS[c.name];
    if (!id) continue;                                      // MTA-STS / TLS-RPT / DKIM are not watched here
    if (c.status === "na") { skip([id, ...(c.holds || []).map((n) => EMAIL_IDS[n]).filter(Boolean)], c.name, c.detail); continue; }
    const s = sevOf(c);
    if (s) add(id, c.name, s, c);
  }

  if (rec.mx && rec.mx.failed) skip(["mx"], "MX", "The DNS lookup for MX failed, so it could not be checked.");
  else {
    const mx = (rec.mx || []).map((d) => /^(\d+)\s+(\S+)$/.exec(String(d).trim())).filter(Boolean).map((m) => m[2].toLowerCase().replace(/\.$/, ""));
    if (!mx.length) add("mx", "MX", "medium", { detail: "No MX record, so mail to the domain has no declared server.", advice: "Publish MX records for your mail provider, or a null MX (0 .) if the domain never receives mail (RFC 7505)." });
    else if (mx.length > 1 && mx.includes("")) add("mx", "MX", "medium", { detail: "A null MX is published alongside other MX records (RFC 7505 3.3).", advice: "Keep either the null MX or real MX records, not both." });
    else if (mx.some((h) => /^\d{1,3}(\.\d{1,3}){3}$/.test(h))) add("mx", "MX", "medium", { detail: "An MX record points at an IP address instead of a hostname (RFC 5321 5.1).", advice: "Point MX at a mail server hostname." });
  }

  if (rec.caa && rec.caa.failed) skip(["caa"], "CAA", "The DNS lookup for CAA failed, so it could not be checked.");
  else {
    const caa = (rec.caa || []).map(parseCaa).filter(Boolean);
    if (!caa.some((c) => c.tag === "issue" || c.tag === "issuewild")) add("caa", "CAA", "low", { detail: caa.length ? "CAA is published without an issue tag, so any certificate authority may issue." : "No CAA record, so any certificate authority may issue certificates.", advice: "Publish CAA issue records naming only the certificate authorities you use." });
  }
  findings.sort((a, b) => a.key.localeCompare(b.key));
  return { findings, unknown };
}

const hasDmarc = (t) => t.some((x) => /^v=dmarc1\b/i.test(String(x).trim()));

// Resolve the records gradeEmailDns() grades. DMARC falls back to the organizational domain's
// record (RFC 7489 6.6.3) as the browser tool does; CAA uses the closest name, self first, that
// publishes a set (RFC 8659 3).
async function lookupEmailDns(dom, f) {
  const [spfTxts, own, mx] = await Promise.all([dohQuery(dom, "TXT", f), dohQuery("_dmarc." + dom, "TXT", f), dohQuery(dom, "MX", f)]);
  let dmarcTxts = own, dmarcFrom = null;
  const org = registrableDomain(dom);
  if (!own.failed && !hasDmarc(own) && org !== dom) {
    const inh = await dohQuery("_dmarc." + org, "TXT", f);
    if (inh.failed) dmarcTxts = inh; else if (hasDmarc(inh)) { dmarcTxts = inh; dmarcFrom = org; }
  }
  let caa = [];
  const labels = dom.split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    const rows = await dohQuery(labels.slice(i).join("."), "CAA", f);
    if (rows.failed || rows.length) { caa = rows; break; }
  }
  return { spfTxts, dmarcTxts, dmarcFrom, mx, caa };
}

// emailPostureCheck(domains, deps) -> findings[] (+ .held keys, .unknown skips). deps: { fetch }.
// When no resolver answered for any domain the run is .unreachable (nothing changed), never clean.
export async function emailPostureCheck(domains, deps = {}) {
  const f = deps.fetch || (typeof fetch !== "undefined" ? fetch : null);
  if (!f) return [];
  const out = [], held = [], unknown = [], checked = [];
  let tried = false, answered = false;
  for (const domain of (domains || [])) {
    const dom = hostOnly(domain);
    if (!dom) continue;
    tried = true;
    const rec = await lookupEmailDns(dom, f);
    if ([rec.spfTxts, rec.dmarcTxts, rec.mx, rec.caa].some((v) => !v.failed)) { answered = true; checked.push(dom); }
    const g = gradeEmailDns(dom, rec);
    out.push(...g.findings);
    for (const u of g.unknown) { unknown.push(u); held.push(...u.keys); }
  }
  if (tried && !answered) return Object.assign([], { unreachable: true, unknown });
  // checked: the domains that answered, so the monitor knows which have a baseline (see drift)
  return Object.assign(out, { held, unknown, checked });
}

// Registry of worker-native check types a monitor can run. Each: (config, deps) -> findings[].
export const CHECKS = {
  "cert-expiry": (cfg, deps) => certExpiryCheck((cfg && cfg.domains) || [], { ...deps, warnDays: (cfg && cfg.warnDays) || 21 }),
  "kev-epss": (cfg, deps) => kevEpssCheck(cfg || {}, deps),
  "email-posture": (cfg, deps) => emailPostureCheck((cfg && cfg.domains) || [], deps),
};

export function runCheck(type, cfg, deps) {
  const fn = Object.prototype.hasOwnProperty.call(CHECKS, type) ? CHECKS[type] : null; // "toString" etc. are not checks
  if (!fn) return Promise.resolve([]);
  return fn(cfg, deps);
}
