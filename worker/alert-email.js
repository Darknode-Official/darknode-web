// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Monitor alerts by email (the "email" channel). Mail goes through Resend (RESEND_KEY), from the
// same sender as the weekly digest (worker/digest.js), and ONLY to the account's own address:
// the channel records the address of the verified ID token that set it up, and each send checks
// the account again in Firebase Auth (still there, not disabled, address verified) and uses the
// address it has now. A client never supplies the recipient.
//
// Each email says what changed, why it matters in one line, the exact fix and where to look in the
// Deck. Plain text plus simple table HTML: no images, no tracking pixels, no emojis. Every email
// carries a link that stops the alerts (and the List-Unsubscribe one-click header), plus the Deck
// path that turns the watch off. The MonitorDO caps alert emails at ALERT_EMAILS_PER_DAY per
// account per UTC day, so a flapping record cannot flood anyone.
//
// The builders (explainEvent, buildAlertEmail, buildTestEmail) are pure and unit-tested.
import { FROM, SITE, googleToken, unsubSecret } from "./digest.js";

export const ALERT_EMAILS_PER_DAY = 5;
export const DECK_MONITORS = SITE + "/monitors";
const API_BASE = "https://darknode-proxy.darknode-ai.workers.dev";
export const STOP_PATH = "/api/watch/stop";

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const clip = (s, n) => { const t = String(s == null ? "" : s).replace(/\s+/g, " ").trim(); return t.length > n ? t.slice(0, n - 1) + "…" : t; };
const days = (n) => n + (n === 1 ? " day" : " days");
const SEV = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };

// "t***@example.com": shown to someone other than the address's owner.
export const maskEmail = (e) => { const s = String(e || ""), at = s.lastIndexOf("@"); return at > 0 ? s[0] + "***" + s.slice(at) : ""; };

// "C=US, O=Example CA, CN=R1" -> "Example CA"
const issuerName = (s) => { const t = String(s || ""), o = /(?:^|,\s*)O=([^,]+)/.exec(t), cn = /(?:^|,\s*)CN=([^,]+)/.exec(t); return clip((o && o[1]) || (cn && cn[1]) || t, 80); };

const POLICY = new Set(["none", "quarantine", "reject"]);
const SPF_ENDS = new Set(["-all", "~all", "?all", "+all", "redirect"]);

// -> { what, why, fix, severity } for one alerted event. `ev` carries the finding's fields
// (monitor.js alertEvent): key, title, severity, domain, check, advice, daysToExpiry, notAfter,
// issuer, cve, dueDate, epss, and for SPF/DMARC the state before and after (was / now / recordAt).
export function explainEvent(ev = {}) {
  const key = String(ev.key || ""), d = ev.domain || "", severity = String(ev.severity || "").toLowerCase();
  const out = (what, why, fix) => ({ what: clip(what || ev.title || "A monitored record changed", 200), why: why || "", fix: fix || ev.advice || "", severity });

  if (key.startsWith("cert:")) {
    const n = Number(ev.daysToExpiry), until = ev.notAfter && !isNaN(Date.parse(ev.notAfter)) ? new Date(ev.notAfter).toISOString().slice(0, 10) : "";
    const what = n < 0 ? `Certificate for ${d} has expired` : n === 0 ? `Certificate for ${d} expires today` : Number.isFinite(n) ? `Certificate for ${d} expires in ${days(n)}` : ev.title;
    const why = (n < 0 ? "Browsers now block" : "When it expires, browsers block") + ` visitors to ${d} with a full-page security warning, and apps and APIs that call it fail to connect.`;
    const fix = `Renew the certificate for ${d} and install it on every server, load balancer and CDN that serves ${d}.`
      + (ev.issuer || until ? " The current one" + (ev.issuer ? " was issued by " + issuerName(ev.issuer) : "") + (ev.issuer && until ? " and" : "") + (until ? (n < 0 ? " expired on " : " is valid until ") + until : "") + "." : "")
      + " If renewal is automated, check why the last renewal did not run.";
    return out(what, why, fix);
  }

  const dm = /^domain:(.+):([a-z]+)$/.exec(key);
  if (dm) {
    const dom = d || dm[1], id = dm[2], n = Number(ev.daysToExpiry), at = ev.registrar ? "your registrar (" + clip(ev.registrar, 60) + ")" : "your registrar";
    const until = ev.notAfter && !isNaN(Date.parse(ev.notAfter)) ? new Date(ev.notAfter).toISOString().slice(0, 10) : "";
    if (id === "expiry") {
      if (/is not registered/.test(ev.title || "")) return out(ev.title, `Anyone can register ${dom} now and receive its mail, serve its website and reset passwords sent to its addresses.`, ev.advice);
      const why = `When a registration lapses, the website, the mail and every sign-in on ${dom} stop working, and after the grace period anyone can register it.`;
      return out(ev.title, why, `Renew ${dom} at ${at}${until ? " (it is registered until " + until + ")" : ""}, and turn on auto-renew with a payment card that will still be valid.`);
    }
    if (id === "transfer") return out(ev.title, `A transfer moves ${dom} to another registrar account, which then controls its DNS, its mail and its website.`, ev.advice);
    if (id === "lock") return out(ev.title, `Without the lock, anyone who gets into the registrar account, or tricks its support, can move ${dom} away in days.`, ev.advice);
    return out(ev.title);
  }

  const wm = /^web:(.+):([a-z]+)$/.exec(key);
  if (wm) {
    const host = d || wm[1], id = wm[2];
    const WHY = {
      git: `Anyone can download the site's source code and its full history, including any password or key ever committed.`,
      env: `The file usually holds database passwords, API keys and signing secrets, and anyone who requested it has them.`,
      https: `Visitors to ${host} cannot reach it securely, so their sessions and logins can be read or changed on the way.`,
      redirect: `Visitors who type ${host} without https:// stay on plain HTTP, where their traffic can be read or changed.`,
      hsts: `Without HSTS a visitor's first request can be downgraded to plain HTTP by anyone on the same network.`,
      csp: `Without a strong Content-Security-Policy, an injected script runs with full access to the page and its visitors' sessions.`,
      frame: `Another site can load ${host} in a hidden frame and trick visitors into clicking its buttons (clickjacking).`,
      nosniff: `Browsers may guess content types, so an uploaded file can run as a script on ${host}.`,
      cookies: `Cookies without the right flags can be sent over plain HTTP or read by injected scripts.`,
    };
    return out(ev.title, WHY[id] || "", ev.advice);
  }

  const em = /^email:(.+):([a-z-]+)$/.exec(key);
  if (em) {
    const dom = d || em[1], id = em[2], at = ev.recordAt || "_dmarc." + dom, was = ev.was || "", now = ev.now || "";
    if (id === "spf") {
      const what = now === "missing" ? `The SPF record for ${dom} was removed` + (SPF_ENDS.has(was) ? ` (it ended in ${was})` : "")
        : now === "multiple" ? `${dom} now publishes more than one SPF record`
          : SPF_ENDS.has(was) && SPF_ENDS.has(now) ? `SPF for ${dom} weakened from ${was} to ${now}` : ev.title;
      const why = now === "missing" || /No SPF record/i.test(ev.title || "") ? `Without SPF, receivers cannot tell which servers may send mail as ${dom}, so mail forged in your name is more likely to be delivered.`
        : now === "multiple" || /More than one SPF/i.test(ev.title || "") ? `Two SPF records are a permanent error (RFC 7208), so SPF fails for all mail from ${dom} and real mail can land in spam.`
          : now === "+all" ? `+all tells receivers that any server in the world may send mail as ${dom}.`
            : `Mail from servers not listed in the record is no longer rejected outright, so mail forged in your name is treated less strictly.`;
      const fix = now === "missing" || /No SPF record/i.test(ev.title || "") ? `Publish one TXT record at ${dom}: v=spf1 include:<your mail provider's SPF domain> -all, listing every service that sends mail as ${dom}.`
        : now === "multiple" || /More than one SPF/i.test(ev.title || "") ? `Merge the SPF records at ${dom} into one TXT record that starts with v=spf1 and ends in -all.`
          : now === "redirect" ? ev.advice : `Change the end of the SPF TXT record at ${dom} to -all, after checking that every service that sends mail as ${dom} is listed in it.`;
      return out(what, why, fix);
    }
    if (id === "spf-lookups") {
      const over = severity === "high" || severity === "critical";
      return out(ev.title, (over ? "More than 10 DNS lookups is" : "Close to 10 DNS lookups, nested includes can tip it into") + ` a permanent error (RFC 7208), so SPF can fail for all mail from ${dom}.`,
        `Cut the SPF record at ${dom} to 10 DNS lookups or fewer: remove include: entries for services you no longer use, or replace them with ip4: and ip6: ranges.`);
    }
    if (id === "dmarc") {
      const missing = now === "missing" || /No DMARC record/i.test(ev.title || ""), multi = now === "multiple" || /More than one DMARC/i.test(ev.title || "");
      const what = now === "missing" ? `The DMARC record for ${dom} was removed` + (POLICY.has(was) ? ` (it had p=${was})` : "")
        : now === "multiple" ? `${dom} now publishes more than one DMARC record`
          : POLICY.has(was) && POLICY.has(now) ? `DMARC policy for ${dom} weakened from ${was} to ${now}` : ev.title;
      const why = multi ? `With more than one DMARC record, receivers apply no DMARC policy at all (RFC 7489), so mail spoofing ${dom} is not rejected.`
        : now === "quarantine" || (!missing && /quarantine/i.test(ev.title || "")) ? `Mail spoofing ${dom} now goes to spam instead of being rejected outright.`
          : `Without an enforced DMARC policy, receivers deliver mail that spoofs ${dom} instead of rejecting it, so phishing in your name reaches inboxes.`;
      const fix = missing ? `Publish one TXT record at ${at}: v=DMARC1; p=quarantine; rua=mailto:dmarc@${dom}. Move to p=reject once the reports show your real mail passes.`
        : multi ? `Delete the extra records at ${at} so exactly one v=DMARC1 TXT record remains.`
          : was === "reject" ? `Set the policy in the TXT record at ${at} back to p=reject.`
            : `Change the policy in the TXT record at ${at} to p=quarantine, then to p=reject once the reports show your real mail passes.`;
      return out(what, why, fix);
    }
    if (id === "dmarc-pct") return out(ev.title, `The policy covers only part of the failing mail, so the rest of the mail spoofing ${dom} is still delivered.`, `Remove pct= from the DMARC record at ${at}, or set it to pct=100.`);
    if (id === "dmarc-sp") return out(ev.title, `sp=none leaves every subdomain of ${dom} open to spoofing, even though ${dom} itself is protected.`, `Set sp=reject in the DMARC record at ${at}, or remove sp= so subdomains follow p=.`);
    if (id === "dmarc-rua") return out(ev.title, `Without aggregate reports you cannot see who sends mail as ${dom}, or notice when a real sender starts failing.`, `Add rua=mailto:dmarc@${dom} (or your DMARC report service's address) to the DMARC record at ${at}.`);
    if (id === "mx") return out(ev.title, `Mail sent to addresses at ${dom} has no valid destination, so it can bounce or be lost.`, ev.advice || "Publish MX records for your mail provider, or a null MX (0 .) if the domain never receives mail (RFC 7505).");
    if (id === "caa") return out(ev.title, `Any certificate authority may issue a certificate for ${dom}, so a mistaken or fraudulent certificate is easier to obtain.`, `Publish CAA records at ${dom} that name only the certificate authorities you use, in the form: 0 issue "<your CA's domain>".`);
    return out(ev.title);
  }

  const cv = /^(kev|epss):(CVE-\d{4}-\d{4,7})$/i.exec(key);
  if (cv) {
    const cve = cv[2].toUpperCase(), link = " Details: https://nvd.nist.gov/vuln/detail/" + cve;
    if (cv[1].toLowerCase() === "kev") return out(ev.title, "It is on CISA's Known Exploited Vulnerabilities list: attackers are using it now.", `Patch or mitigate ${cve} on every affected system` + (ev.dueDate ? `; CISA's deadline for US federal agencies is ${ev.dueDate}.` : ".") + link);
    const pct = typeof ev.epss === "number" ? Math.round(ev.epss * 100) + "%" : "";
    return out(ev.title, `Its EPSS score${pct ? " (" + pct + ")" : ""} puts it among the vulnerabilities most likely to be exploited in the next 30 days.`, `Patch or mitigate ${cve} on every affected system.` + link);
  }
  return out(ev.title);
}

const cadence = (ms) => {
  const h = Math.round((ms || 0) / 3600000);
  return h >= 24 && h % 24 === 0 ? (h === 24 ? "once a day" : "every " + h / 24 + " days") : h >= 1 ? "every " + h + (h === 1 ? " hour" : " hours") : "every " + Math.max(1, Math.round((ms || 0) / 60000)) + " minutes";
};

const F = "-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif";
const pill = (txt, warn) => `<span style="display:inline-block;padding:2px 8px;border:1px solid ${warn ? "#c62828" : "#e6e4de"};border-radius:999px;font:600 12px/1.4 ${F};color:${warn ? "#c62828" : "#56544f"};white-space:nowrap">${esc(txt)}</span>`;

// The page around a message: brand line, white card, footer. Table layout + inline styles only
// (Gmail and Outlook strip <style>), the same look as the weekly digest.
function shell({ title, preheader, date, body, footer, cta = { label: "Open Monitors in the Deck", url: DECK_MONITORS } }) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><meta name="supported-color-schemes" content="light"><title>${esc(title)}</title></head>
<body style="margin:0;padding:0;background:#f7f7f4">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:#f7f7f4">${esc(preheader)}</div>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f7f7f4"><tr><td align="center" style="padding:28px 12px">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:600px">
<tr><td style="padding:0 4px 14px"><table role="presentation" width="100%" cellspacing="0" cellpadding="0"><tr><td style="font:800 16px/1 ${F};color:#1d1c1a;letter-spacing:-.01em">Darknode</td><td align="right" style="font:13px/1 ${F};color:#86837c">${esc(date)}</td></tr></table></td></tr>
<tr><td style="background:#ffffff;border:1px solid #e6e4de;border-radius:12px;padding:28px 28px 30px">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0">
${body}
<tr><td style="padding-top:26px"><a href="${cta.url}" style="display:inline-block;background:#2552c6;color:#ffffff;text-decoration:none;font:600 14px/1 ${F};padding:12px 20px;border-radius:8px">${esc(cta.label)}</a></td></tr>
</table></td></tr>
<tr><td style="padding:16px 4px 0;font:12px/1.6 ${F};color:#86837c">${footer}</td></tr>
</table></td></tr></table></body></html>`;
}

/**
 * The alert email for one monitor run.
 * monitor: { name, type, intervalMs, config }; events: the alerted events (see explainEvent);
 * stopUrl: the signed link that stops these alerts ("" = none, the Deck path is still given);
 * sent / limit: this email's number today and the daily cap (the last one says so).
 * -> { subject, text, html }
 */
export function buildAlertEmail({ monitor = {}, events = [], stopUrl = "", sent = 0, limit = ALERT_EMAILS_PER_DAY, now = Date.now() } = {}) {
  const items = events.map(explainEvent);
  const doms = [...new Set(events.map((e) => e.domain).filter(Boolean))];
  const where = doms.length === 1 ? doms[0] : doms.length ? doms.length + " domains" : "your monitors";
  const name = clip(monitor.name || monitor.type || "Monitor", 80);
  const subject = items.length === 1 ? items[0].what : items.length + " changes on " + where + " need attention";
  const heading = (items.length === 1 ? "A change on " + where + " needs" : items.length + " changes on " + where + " need") + " attention";
  const summary = `Found by your monitor "${name}" on ${new Date(now).toISOString().slice(0, 16).replace("T", " ")} UTC.`;
  const watching = doms.length ? doms.join(", ") : where;
  const reason = `You get this because you set up the monitor "${name}" in Darknode. It checks ${watching} ${cadence(monitor.intervalMs)} and emails your account address when something changes.`;
  const capped = sent >= limit;
  const capLine = `This is alert email ${sent} of ${limit} today, the daily limit. Further changes today are listed in the Deck under Monitors and are not emailed.`;
  const deckPath = "To turn the watch off in the Deck: Monitors, then Pause or Delete on " + (doms.length === 1 ? "the watch for " + doms[0] : "the monitor") + ".";

  const t = [heading, summary, ""];
  items.forEach((it, i) => {
    t.push((items.length > 1 ? i + 1 + ". " : "") + it.what + (SEV[it.severity] ? " [" + SEV[it.severity] + "]" : ""));
    if (it.why) t.push("Why it matters: " + it.why);
    if (it.fix) t.push("Fix: " + it.fix);
    t.push("");
  });
  t.push("Open Monitors in the Deck: " + DECK_MONITORS, "", "--", reason);
  if (capped) t.push(capLine);
  if (stopUrl) t.push("Stop these alerts: " + stopUrl);
  t.push(deckPath);

  // one block per change, a rule between them
  const rows = items.map((it, i) => `<tr><td style="padding:${i ? "18px" : "22px"} 0 0"><table role="presentation" width="100%" cellspacing="0" cellpadding="0"><tr><td style="${i ? "border-top:1px solid #eceae4;padding-top:18px" : ""}">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0"><tr><td style="font:700 15px/1.4 ${F};color:#1d1c1a">${esc(it.what)}</td>${SEV[it.severity] ? `<td align="right" style="vertical-align:top;padding-left:12px">${pill(SEV[it.severity], it.severity === "critical" || it.severity === "high")}</td>` : ""}</tr></table>
${it.why ? `<div style="margin-top:6px;font:14px/1.5 ${F};color:#56544f"><b style="color:#1d1c1a">Why it matters:</b> ${esc(it.why)}</div>` : ""}
${it.fix ? `<div style="margin-top:8px;padding:10px 12px;background:#f7f7f4;border:1px solid #eceae4;border-radius:8px;font:14px/1.5 ${F};color:#1d1c1a"><b>Fix:</b> ${esc(it.fix)}</div>` : ""}
</td></tr></table></td></tr>`).join("");
  const body = `<tr><td style="font:700 20px/1.3 ${F};color:#1d1c1a;letter-spacing:-.01em">${esc(heading)}</td></tr>
<tr><td style="padding-top:8px;font:15px/1.5 ${F};color:#56544f">${esc(summary)}</td></tr>
${rows}`;
  const footer = esc(reason) + (capped ? "<br>" + esc(capLine) : "") + "<br>"
    + (stopUrl ? `<a href="${esc(stopUrl)}" style="color:#86837c">Stop these alerts</a> &middot; ` : "")
    + `<a href="${DECK_MONITORS}" style="color:#86837c">Monitors</a> &middot; <a href="${SITE}" style="color:#86837c">darknode.ai</a><br>` + esc(deckPath);
  const html = shell({ title: subject, preheader: items.length === 1 ? items[0].why || heading : heading, date: new Date(now).toISOString().slice(0, 10), body, footer });
  return { subject, text: t.join("\n"), html };
}

// The "Test channel" email: says plainly that it is a test and what real alerts are.
export function buildTestEmail({ stopUrl = "", sent = 0, limit = ALERT_EMAILS_PER_DAY, now = Date.now() } = {}) {
  const subject = "Darknode alert email test";
  const lines = [
    "This is a test of the alert email for your Darknode monitors. You asked for it with Test channel under Monitors in the Deck.",
    "Real alerts come to this address when a watched certificate is close to expiry, or an email or DNS record (SPF, DMARC, MX, CAA) is removed or weakened. Each one says what changed, why it matters and how to fix it.",
    `Alert emails are limited to ${limit} a day per account. This test counts as ${sent} of ${limit} today.`,
  ];
  const footer = "You get this because you tested email alerts in Darknode." + (stopUrl ? "<br>" + `<a href="${esc(stopUrl)}" style="color:#86837c">Stop alert emails</a> &middot; ` : "<br>") + `<a href="${DECK_MONITORS}" style="color:#86837c">Monitors</a>`;
  const body = `<tr><td style="font:700 20px/1.3 ${F};color:#1d1c1a;letter-spacing:-.01em">${esc(subject)}</td></tr>`
    + lines.map((l) => `<tr><td style="padding-top:10px;font:15px/1.5 ${F};color:#56544f">${esc(l)}</td></tr>`).join("");
  const text = [subject, "", ...lines, "", "Open Monitors in the Deck: " + DECK_MONITORS].concat(stopUrl ? ["Stop alert emails: " + stopUrl] : []).join("\n");
  return { subject, text, html: shell({ title: subject, preheader: lines[0], date: new Date(now).toISOString().slice(0, 10), body, footer }) };
}

// ---- deadline alerts (public/js/core/deadlines.js) --------------------------------------------
// A deadline alert goes out when a deadline is created and when a quarter of its time is left.
// Cyber Resilience Act alerts do not count against ALERT_EMAILS_PER_DAY: a busy day of monitor
// alerts must not hold back a 24-hour legal clock. They have their own daily limit instead, so a
// fault still cannot flood anyone.
export const CRA_EMAILS_PER_DAY = 20;
export const DECK_DEADLINES = SITE + "/deadlines";

/**
 * items: [{ title, detail, kind, stage }] (alertLine output plus the deadline's kind and stage);
 * cra: true for Cyber Resilience Act clocks (adds where to file and the disclaimer);
 * monitor: the monitor that found it; sent / limit: this email's number today and its cap.
 * -> { subject, text, html }
 */
export function buildDeadlineEmail({ items = [], cra = false, monitor = {}, stopUrl = "", sent = 0, limit = ALERT_EMAILS_PER_DAY, now = Date.now(), notes = [] } = {}) {
  const one = items.length === 1 ? items[0] : null;
  const allNew = items.length > 0 && items.every((it) => it.stage !== "quarter");
  const subject = one ? (one.stage === "quarter" ? "A quarter of the time is left: " : "New deadline: ") + one.title
    : items.length ? (allNew ? "New deadlines: " : "Deadlines need attention: ") + items[0].title + " and " + (items.length - 1) + " more" : "Deadlines need attention";
  const heading = one ? (one.stage === "quarter" ? "A quarter of the time is left" : "A new deadline started") : allNew ? items.length + " new deadlines started" : items.length + " deadlines need attention";
  const name = clip(monitor.name || monitor.type || "Monitor", 80);
  const reason = `You get this because the monitor "${name}" emails your account address, and Darknode keeps the deadlines it finds under Deadlines in the Deck.`;
  const capped = sent >= limit;
  const capLine = `This is deadline email ${sent} of ${limit} today, the daily limit. Further deadline alerts today are listed in the Deck under Deadlines and are not emailed.`;
  const t = [heading, ""];
  items.forEach((it, i) => { t.push((items.length > 1 ? i + 1 + ". " : "") + it.title); if (it.detail) t.push(it.detail); t.push(""); });
  for (const n of notes) t.push(n);
  if (notes.length) t.push("");
  t.push("Open Deadlines in the Deck: " + DECK_DEADLINES, "", "--", reason);
  if (capped) t.push(capLine);
  if (stopUrl) t.push("Stop these alerts: " + stopUrl);
  t.push("To stop them in the Deck: Monitors, then Pause on \"" + name + "\".");
  const rows = items.map((it, i) => `<tr><td style="padding:${i ? "18px" : "22px"} 0 0;${i ? "border-top:1px solid #eceae4" : ""}">
<div style="font:700 15px/1.4 ${F};color:#1d1c1a">${esc(it.title)}</div>
${it.detail ? `<div style="margin-top:6px;font:14px/1.5 ${F};color:#56544f">${esc(it.detail)}</div>` : ""}</td></tr>`).join("");
  const noteRows = notes.map((n) => `<tr><td style="padding-top:14px;font:13px/1.5 ${F};color:#56544f">${esc(n)}</td></tr>`).join("");
  const body = `<tr><td style="font:700 20px/1.3 ${F};color:#1d1c1a;letter-spacing:-.01em">${esc(heading)}</td></tr>${rows}${noteRows}`;
  const footer = esc(reason) + (capped ? "<br>" + esc(capLine) : "") + "<br>"
    + (stopUrl ? `<a href="${esc(stopUrl)}" style="color:#86837c">Stop these alerts</a> &middot; ` : "")
    + `<a href="${DECK_DEADLINES}" style="color:#86837c">Deadlines</a> &middot; <a href="${SITE}" style="color:#86837c">darknode.ai</a>`;
  const html = shell({ title: subject, preheader: one ? one.detail || heading : heading, date: new Date(now).toISOString().slice(0, 10), body, footer, cta: { label: "Open Deadlines in the Deck", url: DECK_DEADLINES } });
  return { subject: cra && !/Cyber Resilience Act|CRA/.test(subject) ? "CRA: " + subject : subject, text: t.join("\n"), html };
}

// ---- the stop link ----------------------------------------------------------------------------

const enc = new TextEncoder();
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

// HMAC of (workspace, account), keyed from a server-only secret. "" when there is no secret: a link
// signed with an empty key could be forged, so none is made (the Deck path is still in the email).
export async function stopToken(wid, uid, secret) {
  if (!secret) return "";
  const k = await crypto.subtle.importKey("raw", await crypto.subtle.digest("SHA-256", enc.encode("watch-stop:" + secret)), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64u(await crypto.subtle.sign("HMAC", k, enc.encode(wid + "\n" + uid))).slice(0, 32);
}
export async function stopUrl(env, wid, uid) {
  const t = await stopToken(wid, uid, unsubSecret(env || {}));
  return t ? ((env && env.DIGEST_API_BASE) || API_BASE) + STOP_PATH + "?w=" + encodeURIComponent(wid) + "&u=" + encodeURIComponent(uid) + "&t=" + t : "";
}

// ---- sending ----------------------------------------------------------------------------------

// The account's current address, read from Firebase Auth with the service account.
// -> { email, verified, disabled } | null (no such account) | undefined (no service account
// on this deployment: the caller keeps the address that was verified at setup). Throws on a failed lookup.
export async function accountEmail(env, uid, f = fetch) {
  if (!env || !env.FIREBASE_SA) return undefined;
  const tok = await googleToken(env);
  const r = await f("https://identitytoolkit.googleapis.com/v1/projects/" + env.FIREBASE_PROJECT_ID + "/accounts:lookup", { method: "POST", headers: { Authorization: "Bearer " + tok, "Content-Type": "application/json" }, body: JSON.stringify({ localId: [uid] }) });
  if (!r.ok) throw new Error("account lookup failed (" + r.status + ")");
  const a = (((await r.json().catch(() => ({}))) || {}).users || [])[0];
  return a ? { email: a.email || "", verified: !!a.emailVerified, disabled: !!a.disabled } : null;
}

// Who an email channel may send to right now. -> { to } | { error }
export async function recipient(env, channel, deps = {}) {
  if (!channel || !channel.uid || !channel.to) return { error: "This email channel has no verified account address. Save the monitor again while signed in with a verified email." };
  let a;
  try { a = await (deps.account || accountEmail)(env, channel.uid); }
  catch (e) { return { error: "Could not confirm the account email: " + String((e && e.message) || e).slice(0, 120) }; }
  if (a === undefined) return { to: channel.to };
  if (!a) return { error: "The account that set up these alerts no longer exists." };
  if (a.disabled) return { error: "The account that set up these alerts is disabled." };
  if (!a.verified || !a.email) return { error: "The account email is not verified. Verify it, then alerts resume." };
  return { to: a.email };
}

// One send through Resend. -> { ok, status, error? }
export async function sendEmail(env, { to, subject, html, text, stop, idempotencyKey }, f = fetch) {
  if (!env || !env.RESEND_KEY) return { ok: false, status: 0, error: "Email alerts are not configured on this server." };
  const payload = { from: FROM, to: [to], subject, html, text };
  if (stop) payload.headers = { "List-Unsubscribe": "<" + stop + ">", "List-Unsubscribe-Post": "List-Unsubscribe=One-Click" };
  const headers = { Authorization: "Bearer " + env.RESEND_KEY, "Content-Type": "application/json" };
  if (idempotencyKey) headers["Idempotency-Key"] = String(idempotencyKey).slice(0, 256); // a retried send is not delivered twice
  try {
    const r = await f("https://api.resend.com/emails", { method: "POST", headers, body: JSON.stringify(payload) });
    if (r.ok) return { ok: true, status: r.status };
    const d = await r.json().catch(() => ({}));
    return { ok: false, status: r.status, error: "Email provider error: " + String((d && (d.message || d.error)) || "").slice(0, 160) };
  } catch (e) { return { ok: false, status: 0, error: String((e && e.message) || e).slice(0, 160) }; }
}
