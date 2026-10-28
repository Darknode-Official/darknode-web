// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Pure mappers from the data-protection tools' real results to the common Finding
// shape (core/sink-map.js), so each tool can publish to the Security Graph through
// core/sink.js attachSinkButton. No DOM, no network. Tested in
// test/security/dp-sink.test.mjs.
//
// Rules: posture / tlsfleet publish only failing or warning checks (never passes);
// phishtriage publishes only items rated medium or worse; DLP never carries a matched
// value - only its type, location and a masked sample that reveals at most a short tail.
// Titles and ids are stable so a re-run merges into the same graph entity.

import { cyrb53 } from "../core/hash.js";

const str = (v) => String(v == null ? "" : v);

// ---- External Posture Scorecard (posture) ----------------------------------

// A failing check is medium unless it removes a primary defence outright.
const POSTURE_HIGH_ON_FAIL = new Set(["HTTPS", "Certificate validity", "DMARC", "Signature algorithm"]);

/**
 * scorePosture() result -> findings. Only "fail" and "warn" checks become findings.
 * @param {object} res posture-engine scorePosture() output
 * @returns {object[]}
 */
export function postureFindings(res) {
  const domain = str(res && res.domain).trim().toLowerCase();
  if (!domain) return [];
  const out = [];
  for (const cat of (res.categories || [])) {
    for (const c of (cat.checks || [])) {
      if (c.status !== "fail" && c.status !== "warn") continue;
      out.push({
        id: `posture|${domain}|${str(cat.key)}|${str(c.name)}`,
        title: `${str(c.name)} issue on ${domain}`,
        severity: c.status === "warn" ? "low" : POSTURE_HIGH_ON_FAIL.has(c.name) ? "high" : "medium",
        confidence: "confirmed",
        category: str(cat.label),
        description: str(c.detail),
        recommendation: c.advice ? str(c.advice) : undefined,
        evidence: [{ check: str(c.name), status: c.status, detail: str(c.detail) }],
        assets: [{ type: "DOMAIN", name: domain }],
        tags: ["posture", c.status],
      });
    }
  }
  return out;
}

/**
 * Finding ids a posture run could not re-check: every check whose lookup failed ("na"
 * with holds), plus the checks that lookup decides. Passed to the sink as held, so a
 * failed lookup is never offered as "verified fixed".
 * @param {object} res posture-engine scorePosture() output
 * @returns {string[]}
 */
export function postureHeld(res) {
  const domain = str(res && res.domain).trim().toLowerCase();
  if (!domain) return [];
  const out = [];
  for (const cat of (res.categories || [])) {
    for (const c of (cat.checks || [])) {
      if (c.status !== "na" || !Array.isArray(c.holds)) continue;
      for (const name of [c.name, ...c.holds]) out.push(`posture|${domain}|${str(cat.key)}|${str(name)}`);
    }
  }
  return out;
}

// ---- Certificate & TLS Fleet Monitor (tlsfleet) ------------------------------

const TLS_SEV = { expired: "critical", urgent: "high", soon: "medium", watch: "low" };

/**
 * Watchlist entries -> findings: certificates expired or inside 60 days, and HSTS
 * confirmed absent. OK, unknown (no CT data) and still-pending entries are skipped.
 * @param {object[]} entries tls-engine buildEntry() objects (plus .hsts)
 * @returns {object[]}
 */
export function tlsFleetFindings(entries) {
  const out = [];
  for (const e of entries || []) {
    if (!e || e.pending || !e.domain) continue;
    const domain = str(e.domain).toLowerCase();
    const level = e.band && e.band.level;
    const sev = TLS_SEV[level];
    if (e.ok && sev) {
      const days = e.daysLeft;
      out.push({
        id: `tlsfleet|${domain}|cert-expiry`,
        title: `TLS certificate expiry on ${domain}`,
        severity: sev,
        confidence: "likely",
        category: "Certificate lifecycle",
        description: days < 0
          ? `Newest issued certificate expired ${-days} day(s) ago (${str(e.notAfter).slice(0, 10)}). The live leaf may differ.`
          : `Newest issued certificate expires in ${days} day(s) (${str(e.notAfter).slice(0, 10)}).`,
        recommendation: "Renew the certificate and automate renewal (ACME).",
        evidence: [{ notAfter: str(e.notAfter), daysLeft: days, band: str(e.band.label), issuer: str(e.issuer) }],
        assets: [{ type: "DOMAIN", name: domain }],
        tags: ["tls", level],
      });
    }
    if (e.hsts === false) {
      out.push({
        id: `tlsfleet|${domain}|hsts`,
        title: `HSTS not served on ${domain}`,
        severity: "medium",
        confidence: "confirmed",
        category: "Transport security",
        description: `The HTTPS response from ${domain} carries no Strict-Transport-Security header.`,
        recommendation: "Send HSTS with a max-age of at least 15552000 (180 days).",
        evidence: [{ header: "strict-transport-security", present: false }],
        assets: [{ type: "DOMAIN", name: domain }],
        tags: ["tls", "hsts"],
      });
    }
  }
  return out;
}

/**
 * Finding ids a run could not re-check: the certificate logs did not answer, the HSTS
 * fetch failed, or the domain was past the run's cap. Passed to the sink as held, so a
 * failed lookup is never offered as "verified fixed".
 * @param {object[]} entries tls-engine buildEntry() objects (plus .unreachable, .hsts)
 * @param {string[]} [skipped] domains not checked at all
 * @returns {string[]}
 */
export function tlsFleetHeld(entries, skipped) {
  const out = [];
  for (const e of entries || []) {
    if (!e || !e.domain) continue;
    const domain = str(e.domain).toLowerCase();
    if (e.pending || e.unreachable || e.error) out.push(`tlsfleet|${domain}|cert-expiry`);
    if (e.pending || e.hsts == null) out.push(`tlsfleet|${domain}|hsts`);
  }
  for (const x of skipped || []) { const domain = str(x).toLowerCase(); out.push(`tlsfleet|${domain}|cert-expiry`, `tlsfleet|${domain}|hsts`); }
  return out;
}

// ---- Phishing & URL Triage (phishtriage) -------------------------------------

const PUBLISH_SEV = new Set(["critical", "high", "medium"]);
const signals = (reasons) => (reasons || []).filter((r) => r && r.w > 0).sort((a, b) => b.w - a.w)
  .slice(0, 15).map((r) => ({ weight: r.w, signal: str(r.t) }));

/**
 * One analysed link -> [finding] when rated medium or worse, else [].
 * @param {{ input:string, host?:string, registrable?:string, finalUrl?:string, finalRegistrable?:string, severity:string, reasons:object[] }} u
 * @returns {object[]}
 */
export function phishUrlFindings(u) {
  if (!u || !PUBLISH_SEV.has(u.severity)) return [];
  const input = str(u.input).trim();
  const host = str(u.host || u.registrable || input).toLowerCase();
  const assets = [];
  if (u.registrable) assets.push({ type: "DOMAIN", name: str(u.registrable).toLowerCase() });
  if (u.finalRegistrable && u.finalRegistrable !== u.registrable) assets.push({ type: "DOMAIN", name: str(u.finalRegistrable).toLowerCase() });
  const evidence = signals(u.reasons);
  if (u.finalUrl && u.finalUrl !== input) evidence.push({ finalUrl: str(u.finalUrl) });
  return [{
    id: `phishtriage|url|${input}`,
    title: `Suspicious link: ${host}`,
    severity: u.severity,
    confidence: "review",
    category: "Phishing link",
    description: `The link ${input} was rated ${u.severity} on observable signals (redirects, registration date, DNS, lookalikes). Not a malware verdict.`,
    recommendation: "Block the domain at the mail and web gateway if it is not a known business destination.",
    evidence,
    assets,
    tags: ["phishing", "url"],
  }];
}

const VERDICT_SEV = { "high-risk": "critical", suspicious: "high", caution: "medium" };
const firstAddress = (v) => { const m = str(v).match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/); return m ? m[0].toLowerCase() : ""; };

/**
 * triageEmail() result -> [finding] when the verdict is caution or worse, else [].
 * Assets: the sender domain, the targeted mailbox (To) and any high-risk link domains.
 * @param {object} t triageEmail() output
 * @param {{ to?: string }} [o] raw To header value of the message
 * @returns {object[]}
 */
export function phishEmailFindings(t, { to } = {}) {
  const sev = t && t.verdict && VERDICT_SEV[t.verdict.level];
  if (!sev) return [];
  const sender = str(t.fromReg || t.fromDomain).toLowerCase();
  const mailbox = firstAddress(to);
  const assets = [];
  if (sender) assets.push({ type: "DOMAIN", name: sender });
  if (mailbox) assets.push({ type: "IDENTITY", name: mailbox });
  for (const u of (t.urlAnalyses || [])) {
    if ((u.severity === "high" || u.severity === "critical") && u.registrable && u.registrable !== sender && assets.length < 8) {
      assets.push({ type: "DOMAIN", name: str(u.registrable).toLowerCase() });
    }
  }
  const msgId = str(t.messageId).trim();
  const seed = msgId || cyrb53([str(t.from), str(t.subject), mailbox].join("|"));
  const evidence = signals(t.findings);
  evidence.push({ spf: t.auth && t.auth.spf || "none", dkim: t.auth && t.auth.dkim || "none", dmarc: t.auth && t.auth.dmarc || "none" });
  evidence.push({ from: str(t.from).slice(0, 200), returnPath: str(t.returnPath), replyTo: str(t.replyTo), subject: str(t.subject).slice(0, 160), messageId: msgId });
  return [{
    id: `phishtriage|email|${seed}`,
    title: `Suspicious email from ${sender || "unknown sender"}`,
    severity: sev,
    confidence: "review",
    category: "Phishing email",
    description: `${str(t.verdict.label)}. Rated on the message's own headers, authentication results and links; a triage aid, not a verdict.`,
    recommendation: "Quarantine matching messages, reset credentials for any recipient who clicked, and block the sender domain if it is not a known partner.",
    evidence,
    assets,
    tags: ["phishing", "email"],
  }];
}

// ---- Data Protection Scanner (dlp) -------------------------------------------

const FILE_MARK = /^\/\* ===== (.+?) ===== \*\/$/gm; // inserted by dlp.js readFiles()

/**
 * Masked sample safe to persist: never the value. Fixed engine labels such as
 * "[PRIVATE KEY BLOCK]" pass through; card numbers keep the PCI last four digits;
 * other PII keeps nothing; secrets of 20+ characters keep their last four.
 * @param {object} f a dlp-engine scan() finding
 * @returns {string}
 */
export function dlpSample(f) {
  const masked = str(f && f.masked);
  if (/^\[[A-Z0-9 _-]+\]$/.test(masked)) return masked;
  const v = str(f && f.value);
  if (f && f.id === "conn-string") { const s = v.match(/^[a-z][a-z0-9+.-]*:\/\//i); return (s ? s[0].toLowerCase() : "") + "••••:••••@••••"; }
  if (f && f.id === "credit-card") { const d = v.replace(/\D/g, ""); return "•••• " + (d.length >= 12 ? d.slice(-4) : "••••"); }
  if (f && f.kind === "pii") return "•••• (" + v.length + " chars)";
  return "••••" + (v.length >= 20 ? v.slice(-4) : "") + " (" + v.length + " chars)";
}

/**
 * scan() result -> one finding per (detector, location). Location is the dropped
 * file name (from the markers dlp.js inserts) or "Pasted text <fingerprint>", where
 * the fingerprint hashes the pasted segment with every match removed, so re-scanning
 * the same input merges and the hash never derives from a secret.
 * @param {object} res dlp-engine scan() output
 * @param {string} text the scanned text
 * @returns {object[]}
 */
export function dlpFindings(res, text) {
  text = str(text);
  const hits = (res && res.findings) || [];
  if (!hits.length) return [];
  const marks = [];
  FILE_MARK.lastIndex = 0;
  let m;
  while ((m = FILE_MARK.exec(text))) marks.push({ name: m[1].trim(), index: m.index, line: text.slice(0, m.index).split("\n").length });
  const pastedEnd = marks.length ? marks[0].index : text.length;
  let pasted = "", cur = 0;
  for (const h of hits.slice().sort((a, b) => a.start - b.start)) {
    if (h.start >= pastedEnd) break;
    if (h.start >= cur) pasted += text.slice(cur, h.start) + "[R]";
    cur = Math.max(cur, Math.min(h.end, pastedEnd));
  }
  pasted += text.slice(cur, pastedEnd);
  const pastedLabel = "Pasted text " + cyrb53(pasted).slice(0, 8);

  const groups = new Map();
  for (const h of hits) {
    let loc = pastedLabel, line = h.line;
    for (let i = marks.length - 1; i >= 0; i--) if (marks[i].index <= h.start) { loc = marks[i].name; line = h.line - marks[i].line; break; }
    const k = h.id + "|" + loc;
    if (!groups.has(k)) groups.set(k, { h, loc, occ: [] });
    groups.get(k).occ.push({ line, col: h.col, sample: dlpSample(h) });
  }
  const out = [];
  for (const { h, loc, occ } of groups.values()) {
    out.push({
      id: `dlp|${h.id}|${loc}`,
      title: `${str(h.label)} in ${loc}`,
      severity: h.severity,
      confidence: h.id === "high-entropy" ? "review" : "likely",
      category: h.kind === "pii" ? "Personal data exposure" : "Secret exposure",
      description: `${occ.length} occurrence${occ.length === 1 ? "" : "s"} of ${str(h.label)} found in ${loc}. Values are masked; the scan ran in the browser.`,
      recommendation: h.advice ? str(h.advice) : undefined,
      evidence: occ.slice(0, 25),
      assets: [{ type: "ASSET", name: loc }],
      tags: ["dlp", h.kind === "pii" ? "pii" : "secret", h.id],
    });
  }
  return out;
}
