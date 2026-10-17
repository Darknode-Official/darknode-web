// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// DMARC Reports engine (dmarcreports). Pure: no DOM, no network, deterministic.
// Safe to run inside a Blob module Worker and in node tests.
//
// Reads DMARC aggregate (RUA) reports in the RFC 7489 Appendix C schema and the
// DMARCbis aggregate schema (xmlns urn:ietf:params:xml:ns:dmarc-2.0), the
// parsedmarc aggregate CSV layout or a mapped generic CSV, plus RUF forensic
// reports (ARF, RFC 5965 / RFC 6591). It recomputes DKIM / SPF identifier
// alignment itself (RFC 7489 section 3.1) from auth_results and the published
// adkim / aspf modes, using an embedded public-suffix SUBSET for the
// organizational domain, classifies sending sources from report data only
// (DKIM d= domains, SPF / envelope domains, well-known selectors), and builds
// a staged path from p=none to p=reject.
//
// Control references used in findings:
//   RFC 7489 (DMARC) sections 3.1, 6.3, 6.6, 7.2; RFC 9091 (np tag)
//   RFC 7208 (SPF) sections 2.4, 4.6.4; RFC 6376 (DKIM) section 3.5
//   M3AAWG Email Authentication Recommended Best Practices (2020)
//   CISA BOD 18-01; NIST SP 800-177 Rev.1 section 4 (SPF, DKIM, DMARC)
//   MITRE ATT&CK T1566 Phishing, T1656 Impersonation

import { xmlLite, xmlFind, xmlFindAll, xmlText, parseCsv, findColumn } from "../ingest/parse.js";
import { parseDMARC, parseSPF, spfLookupCount } from "../dataprotect/posture-engine.js";
import { cyrb53 } from "../core/hash.js";

export const TOOL_ID = "dmarcreports";
export const VERSION = "1.0.0";

/** Column aliases for CSV input (parsedmarc aggregate CSV and generic exports). */
export const COLUMNS = {
  source_ip: ["source_ip_address", "source_ip", "source ip", "ip", "sending ip"],
  count: ["count", "message_count", "messages", "volume"],
  header_from: ["header_from", "header from", "from domain", "from_domain"],
  envelope_from: ["envelope_from", "envelope from", "mail from", "return_path"],
  envelope_to: ["envelope_to", "envelope to"],
  disposition: ["disposition", "policy_disposition"],
  dkim_eval: ["dkim_aligned", "policy_dkim", "dkim_evaluated"],
  spf_eval: ["spf_aligned", "policy_spf", "spf_evaluated"],
  dkim_domains: ["dkim_domains", "dkim_domain", "dkim d="],
  dkim_selectors: ["dkim_selectors", "dkim_selector"],
  dkim_results: ["dkim_results", "dkim_result"],
  spf_domains: ["spf_domains", "spf_domain"],
  spf_scopes: ["spf_scopes", "spf_scope"],
  spf_results: ["spf_results", "spf_result"],
  reasons: ["policy_override_reasons", "override_reason", "reason"],
  org_name: ["org_name", "reporter", "reporting org"],
  report_id: ["report_id", "report id"],
  begin: ["begin_date", "begin", "date_begin", "date"],
  end: ["end_date", "end", "date_end"],
  policy_domain: ["domain", "policy_domain", "published_domain"],
  p: ["p", "policy"],
  sp: ["sp", "subdomain_policy"],
  pct: ["pct"],
  adkim: ["adkim"],
  aspf: ["aspf"],
};
const REQUIRED_CSV = ["source_ip", "count", "header_from"];

/** Tunable thresholds; the UI renders these as the settings panel. */
export const DEFAULTS = {
  noneDays: 30, // days at p=none before recommending enforcement
  spoofMin: 100, // failing messages from unknown sources that make spoofing "high"
  readyPassRate: 98, // % of legitimate-looking mail that must pass DMARC to advance a stage
  senderMinMessages: 10, // failing messages before a known service is reported as misaligned
  minObserveDays: 14, // days of reports at the current stage before advancing
  pctStuckDays: 30, // days at pct < 100 before reporting it as stuck
  knownDomains: "", // optional newline/comma list of From domains you send from
};

const DAY = 86400;
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

const C = {
  align: { framework: "RFC 7489", id: "3.1 Identifier Alignment" },
  policy: { framework: "RFC 7489", id: "6.3 General Record Format (p, sp, pct)" },
  report: { framework: "RFC 7489", id: "7.2 Aggregate Reports" },
  np: { framework: "RFC 9091", id: "np tag (non-existent subdomain policy)" },
  spfLimit: { framework: "RFC 7208", id: "4.6.4 DNS Lookup Limits" },
  spfFrom: { framework: "RFC 7208", id: "2.4 MAIL FROM Identity" },
  dkimD: { framework: "RFC 6376", id: "3.5 DKIM-Signature d= tag" },
  m3: { framework: "M3AAWG", id: "Email Authentication Recommended Best Practices (2020)" },
  bod: { framework: "CISA BOD 18-01", id: "DMARC p=reject" },
  nist: { framework: "NIST SP 800-177 Rev.1", id: "Section 4 (SPF, DKIM, DMARC)" },
  phish: { framework: "MITRE", id: "T1566" },
  imperson: { framework: "MITRE", id: "T1656" },
};

/** Detections with the inputs they need (shown in the UI). */
export const DETECTIONS = [
  { id: "policy_none", title: "Monitoring-only policy kept too long", needs: "policy_published p and report dates" },
  { id: "esp_misaligned", title: "Known sending service not aligned", needs: "auth_results DKIM/SPF domains" },
  { id: "spoofing", title: "Unauthenticated mail from unknown sources", needs: "auth_results and source_ip" },
  { id: "subdomain_spoofing", title: "Spoofed subdomains", needs: "header_from and policy_published domain" },
  { id: "forwarding", title: "Forwarding and mailing lists", needs: "auth_results, envelope_from" },
  { id: "pct_stuck", title: "Partial enforcement (pct below 100) kept too long", needs: "policy_published pct" },
  { id: "np_absent", title: "No np policy for non-existent subdomains", needs: "DMARCbis-schema reports" },
  { id: "reporter_mismatch", title: "Reporter evaluation differs from recomputed result", needs: "policy_evaluated and auth_results" },
  { id: "spf_lookup_limit", title: "SPF over 10 DNS lookups", needs: "live lookup (Look up sources)" },
  { id: "live_policy", title: "Published policy now versus in reports", needs: "live lookup (Look up sources)" },
];

// ---------------------------------------------------------------------------
// Organizational domain (RFC 7489 section 3.2) with a public-suffix SUBSET.
// This is not the full Public Suffix List: it covers the common two-label
// registry suffixes so that relaxed alignment works for typical domains.
// ---------------------------------------------------------------------------
export const PSL_SUBSET = [
  "ac.at", "co.at", "or.at", "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
  "com.br", "net.br", "org.br", "gov.br", "edu.br", "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
  "com.co", "com.ar", "com.mx", "org.mx", "gob.mx", "edu.mx", "com.pe", "com.ve", "com.ec", "com.uy", "com.py", "com.bo",
  "co.id", "or.id", "ac.id", "go.id", "co.il", "org.il", "ac.il", "gov.il", "co.in", "net.in", "org.in", "firm.in", "gen.in", "ind.in", "ac.in", "gov.in", "edu.in", "nic.in",
  "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ad.jp", "ed.jp", "gr.jp", "lg.jp", "co.kr", "or.kr", "ne.kr", "ac.kr", "go.kr", "re.kr",
  "co.nz", "net.nz", "org.nz", "ac.nz", "govt.nz", "geek.nz", "school.nz", "co.th", "in.th", "ac.th", "go.th", "or.th",
  "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "ac.uk", "gov.uk", "nhs.uk", "police.uk", "sch.uk",
  "co.za", "org.za", "web.za", "net.za", "gov.za", "ac.za", "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg",
  "com.hk", "net.hk", "org.hk", "edu.hk", "gov.hk", "com.tw", "net.tw", "org.tw", "edu.tw", "gov.tw", "idv.tw",
  "com.my", "net.my", "org.my", "gov.my", "edu.my", "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph", "com.vn", "net.vn", "gov.vn", "edu.vn",
  "com.pk", "net.pk", "org.pk", "gov.pk", "edu.pk", "com.bd", "com.np", "com.lk", "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr", "av.tr", "gen.tr",
  "com.sa", "net.sa", "gov.sa", "com.eg", "com.ng", "gov.ng", "co.ke", "or.ke", "co.tz", "co.ug", "com.gh",
  "com.ua", "net.ua", "org.ua", "com.pl", "net.pl", "org.pl", "co.hu", "com.ru", "com.es", "nom.es", "org.es", "com.pt", "com.gr", "com.cy", "com.mt",
  "co.cr", "com.gt", "com.do", "com.pa", "com.ni", "com.sv", "com.hn", "co.ve", "com.qa", "com.kw", "com.bh", "com.om", "co.ae", "com.ae", "ac.ae", "gov.ae",
  "co.ma", "com.tn", "com.dz", "co.ls", "co.zw", "co.zm", "co.bw", "com.na", "com.fj", "com.pg", "com.kh", "com.mm", "com.la", "com.mo", "com.bn",
  "gov.au", "us.com", "eu.com", "uk.com", "co.com", "gb.net", "uk.net", "jpn.com", "cn.com", "de.com", "br.com", "sa.com", "za.com",
  "github.io", "gitlab.io", "netlify.app", "vercel.app", "pages.dev", "workers.dev", "herokuapp.com", "azurewebsites.net", "cloudfront.net",
  "appspot.com", "web.app", "firebaseapp.com", "blogspot.com", "s3.amazonaws.com",
].filter((v, i, a) => a.indexOf(v) === i).sort();
const PSL_SET = new Set(PSL_SUBSET);

const normDomain = (d) => String(d == null ? "" : d).trim().toLowerCase().replace(/^.*@/, "").replace(/\.+$/, "").replace(/^\.+/, "");

/** Organizational domain via the embedded public-suffix subset. */
export function orgDomain(domain) {
  const d = normDomain(domain);
  if (!d) return "";
  const labels = d.split(".");
  if (labels.length <= 2) return d;
  // longest matching suffix from the subset (three-label suffixes like s3.amazonaws.com included)
  for (let k = Math.min(3, labels.length - 1); k >= 2; k--) {
    if (PSL_SET.has(labels.slice(-k).join("."))) return labels.slice(-(k + 1)).join(".");
  }
  return labels.slice(-2).join(".");
}

/** Identifier alignment: strict = exact match, relaxed = same organizational domain. */
export function aligned(authDomain, fromDomain, mode = "r") {
  const a = normDomain(authDomain), f = normDomain(fromDomain);
  if (!a || !f) return false;
  if (String(mode || "r").toLowerCase() === "s") return a === f;
  return orgDomain(a) === orgDomain(f);
}

const isSubdomainOf = (d, parent) => { d = normDomain(d); parent = normDomain(parent); return !!parent && d !== parent && d.endsWith("." + parent); };
const suffixMatch = (d, s) => { d = normDomain(d); return d === s || d.endsWith("." + s); };

// ---------------------------------------------------------------------------
// IP helpers (IPv4 / IPv6 canonical form, reverse-DNS names)
// ---------------------------------------------------------------------------
export function isIPv4(ip) {
  const m = String(ip || "").match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  return !!m && m.slice(1).every((x) => Number(x) <= 255 && String(Number(x)) === x);
}

/** Expand an IPv6 address to 8 groups of 4 hex digits, or "" when invalid. */
export function expandIPv6(ip) {
  let s = String(ip || "").trim().toLowerCase().replace(/^\[|\]$/g, "").replace(/%.*$/, "");
  if (!s.includes(":")) return "";
  const v4 = s.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) {
    if (!isIPv4(v4[2])) return "";
    const o = v4[2].split(".").map(Number);
    s = v4[1] + ((o[0] << 8) | o[1]).toString(16) + ":" + ((o[2] << 8) | o[3]).toString(16);
  }
  const dbl = s.split("::");
  if (dbl.length > 2) return "";
  const head = dbl[0] ? dbl[0].split(":") : [];
  const tail = dbl.length === 2 && dbl[1] ? dbl[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (dbl.length === 1 && head.length !== 8) return "";
  if (dbl.length === 2 && missing < 1) return "";
  const groups = [...head, ...Array(dbl.length === 2 ? missing : 0).fill("0"), ...tail];
  if (groups.length !== 8 || !groups.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return "";
  return groups.map((g) => g.padStart(4, "0")).join(":");
}

/** RFC 5952 canonical text form of an IPv6 address. */
export function compressIPv6(ip) {
  const full = expandIPv6(ip);
  if (!full) return "";
  const g = full.split(":").map((x) => x.replace(/^0+(?=.)/, ""));
  let best = -1, bestLen = 0;
  for (let i = 0; i < 8;) {
    if (g[i] !== "0") { i++; continue; }
    let j = i; while (j < 8 && g[j] === "0") j++;
    if (j - i > bestLen && j - i >= 2) { best = i; bestLen = j - i; }
    i = j;
  }
  if (best < 0) return g.join(":");
  return g.slice(0, best).join(":") + "::" + g.slice(best + bestLen).join(":");
}

/** Normalize a source IP: IPv4 kept, IPv6 canonicalized, anything else returned trimmed. */
export function normIp(ip) {
  const s = String(ip == null ? "" : ip).trim();
  if (isIPv4(s)) return s;
  const v6 = compressIPv6(s);
  return v6 || s.toLowerCase();
}
export const ipVersion = (ip) => (isIPv4(ip) ? 4 : expandIPv6(ip) ? 6 : 0);

/** Reverse-DNS query name for a PTR lookup (in-addr.arpa / ip6.arpa), or "" when not an IP. */
export function ptrName(ip) {
  if (isIPv4(ip)) return String(ip).split(".").reverse().join(".") + ".in-addr.arpa";
  const full = expandIPv6(ip);
  if (!full) return "";
  return full.replace(/:/g, "").split("").reverse().join(".") + ".ip6.arpa";
}

// ---------------------------------------------------------------------------
// Sending-service table, keyed by DKIM d= and SPF / envelope (return-path)
// domains. Classification uses report data only; it never looks up who owns
// an IP. Selector hints are weaker evidence and are marked as such.
// ---------------------------------------------------------------------------
export const ESP_TABLE = [
  { id: "m365", name: "Microsoft 365 (Exchange Online)", dkim: ["onmicrosoft.com"], spf: ["protection.outlook.com", "onmicrosoft.com"], selectors: ["selector1", "selector2"], include: "spf.protection.outlook.com",
    dkimFix: "Microsoft Defender portal > Email authentication settings > DKIM: enable signing for {domain} and publish the two CNAME records it shows (selector1._domainkey.{domain} and selector2._domainkey.{domain}).",
    spfFix: "Exchange Online sends with your accepted domain as MAIL FROM; add include:spf.protection.outlook.com to the SPF record of {domain}." },
  { id: "google", name: "Google Workspace / Gmail", dkim: ["gappssmtp.com", "gmail.com", "googlemail.com"], spf: ["gmail.com", "googlemail.com"], selectors: ["google"], include: "_spf.google.com",
    dkimFix: "Google Admin console > Apps > Google Workspace > Gmail > Authenticate email: generate a key for {domain}, publish the TXT record at <selector>._domainkey.{domain}, then click Start authentication.",
    spfFix: "Add include:_spf.google.com to the SPF record of {domain}. Mail sent through consumer Gmail (send mail as) cannot align; route it through your own server or Workspace." },
  { id: "amazonses", name: "Amazon SES", dkim: ["amazonses.com"], spf: ["amazonses.com"], selectors: [], include: "amazonses.com",
    dkimFix: "Amazon SES > Verified identities: verify {domain} with Easy DKIM and publish the three CNAME records SES generates.",
    spfFix: "Configure a custom MAIL FROM domain in SES (a subdomain you choose, e.g. <bounce-subdomain>.{domain}) and publish the MX and SPF TXT records SES shows for it." },
  { id: "sendgrid", name: "Twilio SendGrid", dkim: ["sendgrid.info", "sendgrid.net"], spf: ["sendgrid.net"], selectors: ["s1", "s2"], include: "sendgrid.net",
    dkimFix: "SendGrid > Settings > Sender Authentication > Authenticate Your Domain for {domain}; publish the CNAME records it generates (s1._domainkey, s2._domainkey and the em<id> return-path subdomain).",
    spfFix: "Domain authentication also sets a return-path subdomain of {domain} (em<id>.{domain}); publish the CNAME SendGrid shows for it." },
  { id: "mailgun", name: "Mailgun", dkim: ["mailgun.org", "mailgun.net"], spf: ["mailgun.org", "mailgun.net"], selectors: [], include: "mailgun.org",
    dkimFix: "Mailgun > Sending > Domains: add a sending domain on {domain} (or a subdomain) and publish the DKIM TXT record Mailgun shows.",
    spfFix: "Send from the Mailgun domain you added so the return-path is on {domain}; publish the SPF (include:mailgun.org) and MX records Mailgun shows for it." },
  { id: "mailchimp", name: "Mailchimp", dkim: ["mcsv.net", "mcdlv.net", "rsgsv.net"], spf: ["mcsv.net", "mcdlv.net", "rsgsv.net"], selectors: ["k1", "k2", "k3"], include: "servers.mcsv.net",
    dkimFix: "Mailchimp > Account > Domains: authenticate {domain} and publish the CNAME records it shows (k2._domainkey and k3._domainkey). Campaigns are then signed with d={domain}.",
    spfFix: "Mailchimp keeps its own return-path, so SPF will not align; DKIM alignment (above) is what makes this mail pass DMARC." },
  { id: "mandrill", name: "Mailchimp Transactional (Mandrill)", dkim: ["mandrillapp.com"], spf: ["mandrillapp.com"], selectors: ["mandrill"], include: "spf.mandrillapp.com",
    dkimFix: "Mandrill > Settings > Domains > Sending domains: verify {domain} and publish the mandrill._domainkey.{domain} DKIM record shown.",
    spfFix: "Set a custom return-path domain on {domain} in Mandrill (Tracking and return-path domains) and publish the CNAME it shows." },
  { id: "sparkpost", name: "SparkPost", dkim: ["sparkpostmail.com"], spf: ["sparkpostmail.com"], selectors: [], include: "sparkpostmail.com",
    dkimFix: "SparkPost > Configuration > Domains: add {domain} as a sending domain and publish the DKIM TXT record shown.",
    spfFix: "Add a bounce domain on {domain} in SparkPost and publish the CNAME it shows, so the return-path aligns." },
  { id: "salesforce", name: "Salesforce / Marketing Cloud (ExactTarget)", dkim: ["salesforce.com", "exacttarget.com", "force.com"], spf: ["salesforce.com", "exacttarget.com", "force.com"], selectors: [], include: "_spf.salesforce.com",
    dkimFix: "Salesforce Setup > DKIM Keys: create a key for {domain} and publish the CNAME records shown (Marketing Cloud: Sender Authentication Package / private domain for {domain}).",
    spfFix: "Add include:_spf.salesforce.com where Salesforce sends with MAIL FROM on {domain}; Marketing Cloud needs a private domain for an aligned return-path." },
  { id: "hubspot", name: "HubSpot", dkim: ["hubspotemail.net", "hubspotstarter.net", "hubspotfree.net", "hs-email.net"], spf: ["hubspotemail.net", "hubspotstarter.net", "hubspotfree.net"], selectors: ["hs1", "hs2"], include: null,
    dkimFix: "HubSpot > Settings > Domains & URLs > Email sending domains: connect {domain} and publish the two DKIM CNAME records shown (hs1-<id>._domainkey and hs2-<id>._domainkey).",
    spfFix: "HubSpot uses its own return-path unless a dedicated IP is configured; rely on DKIM alignment." },
  { id: "zendesk", name: "Zendesk", dkim: ["zendesk.com", "zdsys.com"], spf: ["zendesk.com"], selectors: ["zendesk1", "zendesk2"], include: "mail.zendesk.com",
    dkimFix: "Zendesk Admin Center > Channels > Email: enable digital signatures for {domain} and publish the CNAME records zendesk1._domainkey and zendesk2._domainkey shown.",
    spfFix: "Add include:mail.zendesk.com to the SPF record of {domain}." },
  { id: "freshdesk", name: "Freshdesk / Freshworks", dkim: ["freshdesk.com", "freshemail.io", "freshworks.com"], spf: ["freshdesk.com", "freshemail.io", "freshworks.com"], selectors: [], include: "email.freshdesk.com",
    dkimFix: "Freshdesk Admin > Email > DKIM: configure {domain} and publish the records shown.",
    spfFix: "Add include:email.freshdesk.com to the SPF record of {domain}." },
  { id: "mailjet", name: "Mailjet", dkim: ["mailjet.com"], spf: ["mailjet.com"], selectors: ["mailjet"], include: "spf.mailjet.com",
    dkimFix: "Mailjet > Account settings > Domains: set up DKIM for {domain} and publish mailjet._domainkey.{domain} as shown.",
    spfFix: "Add include:spf.mailjet.com to the SPF record of {domain}." },
  { id: "postmark", name: "Postmark", dkim: ["mtasv.net", "postmarkapp.com"], spf: ["mtasv.net", "postmarkapp.com"], selectors: [], selectorPattern: "^\\d{14}pm$", include: "spf.mtasv.net",
    dkimFix: "Postmark > Sender signatures / Domains: verify {domain} and publish the <timestamp>pm._domainkey TXT record shown.",
    spfFix: "Set a custom Return-Path on {domain} (CNAME to pm.mtasv.net as Postmark shows) so the bounce domain aligns." },
  { id: "constantcontact", name: "Constant Contact", dkim: ["constantcontact.com", "ccsend.com", "ccsend.net"], spf: ["constantcontact.com", "ccsend.com", "ccsend.net"], selectors: [], include: "spf.constantcontact.com",
    dkimFix: "Constant Contact > My Settings > Email authentication: authenticate {domain} and publish the two CNAME records shown.",
    spfFix: "Constant Contact keeps its own return-path; DKIM alignment is what makes this mail pass DMARC." },
  { id: "klaviyo", name: "Klaviyo", dkim: ["klaviyomail.com", "klaviyo.com"], spf: ["klaviyomail.com", "klaviyo.com"], selectors: ["kl", "kl2"], include: null,
    dkimFix: "Klaviyo > Settings > Domains: set up a branded sending domain on {domain} and publish the records shown.",
    spfFix: "A branded sending domain also moves the return-path onto {domain}." },
  { id: "intercom", name: "Intercom", dkim: ["intercom-mail.com", "intercom.io"], spf: ["intercom-mail.com", "intercom.io"], selectors: [], include: null,
    dkimFix: "Intercom > Settings > Channels > Email > Domains: authenticate {domain} and publish the DKIM CNAME records shown.",
    spfFix: "Intercom domain authentication also adds a return-path CNAME on {domain}; publish it as shown." },
  { id: "atlassian", name: "Atlassian (Jira / Confluence)", dkim: ["atlassian.net", "atlassian.com"], spf: ["atlassian.net", "atlassian.com"], selectors: [], include: "_spf.atlassian.net",
    dkimFix: "Atlassian Administration > Settings > Domains: verify {domain}, enable custom email sending and publish the DKIM records shown.",
    spfFix: "Add include:_spf.atlassian.net to the SPF record of {domain}." },
  { id: "docusign", name: "DocuSign", dkim: ["docusign.net", "docusign.com"], spf: ["docusign.net", "docusign.com"], selectors: [], include: null,
    dkimFix: "DocuSign sends envelopes from its own domain by default; if you use custom sending on {domain}, publish the DKIM records from DocuSign's configuration.",
    spfFix: "Only needed when DocuSign sends with MAIL FROM on {domain}; use the SPF include from DocuSign's documentation." },
  { id: "intuit", name: "Intuit (QuickBooks)", dkim: ["intuit.com"], spf: ["intuit.com"], selectors: [], include: null,
    dkimFix: "QuickBooks invoices sent as {domain} are signed by Intuit; switch the sender to an Intuit address or use a service that supports DKIM on {domain}.",
    spfFix: "Use the SPF include from Intuit's documentation only if Intuit sends with MAIL FROM on {domain}." },
  { id: "servicenow", name: "ServiceNow", dkim: ["service-now.com", "servicenowservices.com"], spf: ["service-now.com", "servicenowservices.com"], selectors: [], include: null,
    dkimFix: "ServiceNow: enable DKIM signing for {domain} for your instance (support request / instance email settings) and publish the TXT record provided.",
    spfFix: "Use the SPF include from ServiceNow's documentation if the instance sends with MAIL FROM on {domain}." },
  { id: "zoho", name: "Zoho Mail / Campaigns", dkim: ["zoho.com", "zohomail.com", "zoho.eu", "zcsend.net"], spf: ["zoho.com", "zohomail.com", "zoho.eu", "zcsend.net"], selectors: [], include: null,
    dkimFix: "Zoho Admin console > Domains > Email configuration > DKIM: add a selector for {domain} and publish the TXT record shown.",
    spfFix: "Use the SPF include for your Zoho data centre from Zoho's documentation." },
];

/** Forwarders and mailing lists: SPF breaks by design; DKIM may survive. */
export const FORWARDER_TABLE = [
  { id: "googlegroups", name: "Google Groups (mailing list)", domains: ["googlegroups.com"] },
  { id: "groupsio", name: "Groups.io (mailing list)", domains: ["groups.io"] },
  { id: "outlookfwd", name: "Outlook.com / Hotmail forwarding", domains: ["outlook.com", "hotmail.com", "live.com", "msn.com"], exact: true },
  { id: "icloudfwd", name: "iCloud Mail forwarding", domains: ["icloud.com", "me.com"], exact: true },
];
const OVERRIDE_FORWARD = new Set(["forwarded", "mailing_list", "trusted_forwarder"]);

function matchEsp(domains, selectors) {
  for (const e of ESP_TABLE) {
    const byDkim = domains.dkim.find((d) => e.dkim.some((s) => suffixMatch(d, s)));
    if (byDkim) return { esp: e, via: "DKIM d=" + byDkim, strength: "domain" };
    const bySpf = domains.spf.find((d) => e.spf.some((s) => suffixMatch(d, s)));
    if (bySpf) return { esp: e, via: "return-path " + bySpf, strength: "domain" };
  }
  for (const e of ESP_TABLE) {
    const re = e.selectorPattern ? new RegExp(e.selectorPattern, "i") : null;
    const sel = selectors.find((s) => e.selectors.includes(String(s).toLowerCase()) || (e.id === "hubspot" && /^hs[12]-/i.test(s)) || (re && re.test(s)));
    if (sel) return { esp: e, via: "DKIM selector " + sel, strength: "selector" };
  }
  return null;
}
function matchForwarder(domains) {
  for (const f of FORWARDER_TABLE) {
    const d = [...domains.spf, ...domains.dkim].find((x) => f.domains.some((s) => (f.exact ? normDomain(x) === s : suffixMatch(x, s))));
    if (d) return { fwd: f, via: d };
  }
  return null;
}

// ---------------------------------------------------------------------------
// Parsing: RUA XML (RFC 7489 + DMARCbis), parsedmarc / generic CSV, RUF (ARF)
// ---------------------------------------------------------------------------
const local = (tag) => String(tag || "").replace(/^.*:/, "");
const kid = (node, tag) => (node && node.children ? node.children.find((c) => local(c.tag) === tag) : null) || null;
const kids = (node, tag) => (node && node.children ? node.children.filter((c) => local(c.tag) === tag) : []);
const ktxt = (node, tag) => { const k = kid(node, tag); return k ? xmlText(k) : ""; };
const lc = (s) => String(s == null ? "" : s).trim().toLowerCase();
const toInt = (v) => { const s = String(v == null ? "" : v).trim(); return /^-?\d+$/.test(s) ? parseInt(s, 10) : NaN; };

/** Detect one file's format from its name and leading text. */
export function detectFile({ name = "", text = "" } = {}) {
  const t = String(text || "");
  const head = t.slice(0, 8192);
  const base = { name, headers: [], map: {}, missing: [] };
  if (!t.trim()) return { ...base, format: "empty", label: "Empty file", confidence: 0, confidenceLabel: "low" };
  if (/<(\w+:)?feedback[\s>]/.test(head) || /<(\w+:)?feedback[\s>]/.test(t.slice(0, 200000))) {
    const bis = /urn:ietf:params:xml:ns:dmarc-2\.0/i.test(head) || /<(\w+:)?(discovery_method|testing|generator)>/.test(t.slice(0, 200000));
    return { ...base, format: bis ? "rua-dmarcbis" : "rua-xml", label: bis ? "DMARC aggregate report (DMARCbis schema)" : "DMARC aggregate report (RFC 7489)", confidence: 1, confidenceLabel: "high" };
  }
  if (/^feedback-type\s*:/im.test(head) || /message\/feedback-report/i.test(head)) {
    return { ...base, format: "ruf-arf", label: "DMARC forensic report (ARF)", confidence: 0.9, confidenceLabel: "high" };
  }
  if (/^\s*</.test(head)) return { ...base, format: "unknown", label: "XML without a <feedback> element (not a DMARC aggregate report)", confidence: 0, confidenceLabel: "low" };
  const firstLine = head.split(/\r?\n/, 1)[0] || "";
  if (/[,;\t]/.test(firstLine)) {
    const { headers } = parseCsv(head.split(/\r?\n/).slice(0, 2).join("\n"));
    const map = {};
    for (const [k, al] of Object.entries(COLUMNS)) { const h = findColumn(headers, al); if (h) map[k] = h; }
    const missing = REQUIRED_CSV.filter((k) => !map[k]);
    const parsedmarc = ["xml_schema", "source_ip_address", "dkim_domains", "spf_results", "header_from"].every((h) => headers.map(lc).includes(h));
    const conf = parsedmarc ? 1 : missing.length ? 0.3 : 0.6;
    return { ...base, headers, map, missing, format: parsedmarc ? "csv-parsedmarc" : "csv", label: parsedmarc ? "parsedmarc aggregate CSV" : "CSV (generic, map the columns)", confidence: conf, confidenceLabel: conf >= 0.9 ? "high" : conf >= 0.5 ? "medium" : "low" };
  }
  return { ...base, format: "unknown", label: "Not a DMARC report", confidence: 0, confidenceLabel: "low" };
}

/** Parse one RFC 7489 / DMARCbis aggregate report. Returns { report } or { error }. */
export function parseAggregateXml(text, name = "") {
  let root;
  try { root = xmlLite(text); } catch (e) { return { error: "XML could not be read: " + (e && e.message || e) }; }
  const fb = local(root.tag) === "feedback" ? root : xmlFind(root, "feedback");
  if (!fb) return { error: "no <feedback> element (not a DMARC aggregate report)" };
  const meta = kid(fb, "report_metadata");
  const pp = kid(fb, "policy_published");
  if (!meta) return { error: "no <report_metadata> element" };
  if (!pp) return { error: "no <policy_published> element" };
  const dr = kid(meta, "date_range");
  const xmlns = Object.entries(fb.attrs || {}).filter(([k]) => k === "xmlns" || k.startsWith("xmlns:")).map(([, v]) => v).join(" ");
  const bisFields = ["discovery_method", "testing", "generator"].some((t) => kid(pp, t) || kid(meta, t) || kid(fb, t));
  const schema = /dmarc-2\.0/i.test(xmlns) || bisFields ? "dmarcbis" : "rfc7489";
  const pub = {
    domain: normDomain(ktxt(pp, "domain")),
    adkim: lc(ktxt(pp, "adkim")) === "s" ? "s" : "r",
    aspf: lc(ktxt(pp, "aspf")) === "s" ? "s" : "r",
    p: lc(ktxt(pp, "p")) || "",
    sp: kid(pp, "sp") ? lc(ktxt(pp, "sp")) : "",
    pct: kid(pp, "pct") && Number.isFinite(toInt(ktxt(pp, "pct"))) ? toInt(ktxt(pp, "pct")) : 100,
    fo: ktxt(pp, "fo"),
    np: kid(pp, "np") ? lc(ktxt(pp, "np")) : "",
    hasNp: !!kid(pp, "np"),
    testing: lc(ktxt(pp, "testing")),
    discovery: lc(ktxt(pp, "discovery_method")),
  };
  const report = {
    file: name, schema, version: ktxt(fb, "version"),
    org: ktxt(meta, "org_name") || "(no org_name)", email: ktxt(meta, "email"), reportId: ktxt(meta, "report_id"),
    begin: toInt(ktxt(dr, "begin")), end: toInt(ktxt(dr, "end")),
    errors: kids(meta, "error").map(xmlText).filter(Boolean),
    policy: pub, records: [], rejected: 0, rejectReasons: [],
  };
  if (!Number.isFinite(report.begin)) report.begin = null;
  if (!Number.isFinite(report.end)) report.end = null;
  for (const rec of kids(fb, "record")) {
    const row = kid(rec, "row"), pe = kid(row, "policy_evaluated"), ids = kid(rec, "identifiers"), ar = kid(rec, "auth_results");
    const count = toInt(ktxt(row, "count"));
    const ip = ktxt(row, "source_ip");
    const headerFrom = normDomain(ktxt(ids, "header_from"));
    if (!ip || !Number.isFinite(count) || count < 0 || !headerFrom) {
      report.rejected++;
      report.rejectReasons.push(!ip ? "record without source_ip" : !headerFrom ? "record without header_from" : "record with an invalid count");
      continue;
    }
    report.records.push({
      ip: normIp(ip), count, headerFrom,
      envelopeFrom: normDomain(ktxt(ids, "envelope_from")), envelopeTo: normDomain(ktxt(ids, "envelope_to")),
      disposition: lc(ktxt(pe, "disposition")) || "none",
      evalDkim: lc(ktxt(pe, "dkim")), evalSpf: lc(ktxt(pe, "spf")),
      reasons: kids(pe, "reason").map((r) => ({ type: lc(ktxt(r, "type")), comment: ktxt(r, "comment") })).filter((r) => r.type || r.comment),
      dkim: kids(ar, "dkim").map((d) => ({ domain: normDomain(ktxt(d, "domain")), selector: ktxt(d, "selector"), result: lc(ktxt(d, "result")), human: ktxt(d, "human_result") })),
      spf: kids(ar, "spf").map((s) => ({ domain: normDomain(ktxt(s, "domain")), scope: lc(ktxt(s, "scope")), result: lc(ktxt(s, "result")) })),
    });
  }
  return { report };
}

/** Parse an ARF (RFC 5965 / 6591) DMARC failure report: key headers only. */
export function parseForensic(text, name = "") {
  const t = String(text || "").replace(/\r\n/g, "\n").replace(/\n[ \t]+/g, " ");
  const get = (h) => { const m = t.match(new RegExp("^" + h + "\\s*:[ \\t]*(.*)$", "im")); return m ? m[1].trim() : ""; };
  const ft = get("Feedback-Type");
  if (!ft) return { error: "no Feedback-Type header (not an ARF report)" };
  return {
    report: {
      file: name, feedbackType: lc(ft), authFailure: lc(get("Auth-Failure")), sourceIp: normIp(get("Source-IP")),
      reportedDomain: normDomain(get("Reported-Domain")), originalMailFrom: get("Original-Mail-From").replace(/^<|>$/g, ""),
      arrivalDate: get("Arrival-Date") || get("Received-Date"), deliveryResult: lc(get("Delivery-Result")),
      dkimDomain: normDomain(get("DKIM-Domain")), dkimSelector: get("DKIM-Selector"), reportingMta: get("Reporting-MTA"),
    },
  };
}

const splitList = (v) => String(v == null ? "" : v).split(/[,|;]/).map((x) => x.trim()).filter(Boolean);
const toEpoch = (v) => {
  const s = String(v == null ? "" : v).trim();
  if (!s) return null;
  if (/^\d{9,11}$/.test(s)) return parseInt(s, 10);
  const iso = s.replace(" ", "T");
  const ms = Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(iso) ? iso : iso + (iso.length <= 10 ? "T00:00:00Z" : "Z"));
  return Number.isFinite(ms) ? Math.floor(ms / 1000) : null;
};
const truthy = (v) => /^(true|pass|yes|1)$/i.test(String(v == null ? "" : v).trim());

/** Parse parsedmarc / generic CSV rows into synthetic per-report groups. */
function parseCsvReports(text, name, columns = {}) {
  const { headers, rows } = parseCsv(text);
  const map = {};
  for (const [k, al] of Object.entries(COLUMNS)) { const h = columns[k] || findColumn(headers, al); if (h && headers.includes(h)) map[k] = h; }
  const missing = REQUIRED_CSV.filter((k) => !map[k]);
  if (missing.length) return { error: "missing column(s): " + missing.join(", "), headers, map };
  const g = (r, k) => (map[k] ? r[map[k]] : "");
  const groups = new Map();
  let rejected = 0;
  for (const r of rows) {
    const count = toInt(g(r, "count")), ip = String(g(r, "source_ip") || "").trim(), hf = normDomain(g(r, "header_from"));
    if (!ip || !hf || !Number.isFinite(count)) { rejected++; continue; }
    const org = String(g(r, "org_name") || "").trim() || "(CSV: " + name + ")";
    const rid = String(g(r, "report_id") || "").trim() || "csv-" + name;
    const key = org + "\u0000" + rid;
    if (!groups.has(key)) {
      const b = toEpoch(g(r, "begin")), e = toEpoch(g(r, "end"));
      const pRaw = lc(g(r, "p"));
      groups.set(key, {
        file: name, schema: "csv", version: "", org, email: "", reportId: rid, begin: b, end: e == null ? (b == null ? null : b + DAY - 1) : e, errors: [],
        policy: { domain: normDomain(g(r, "policy_domain")) || hf, adkim: lc(g(r, "adkim")) === "s" ? "s" : "r", aspf: lc(g(r, "aspf")) === "s" ? "s" : "r", p: pRaw, sp: lc(g(r, "sp")), pct: Number.isFinite(toInt(g(r, "pct"))) ? toInt(g(r, "pct")) : 100, fo: "", np: "", hasNp: false, testing: "", discovery: "" },
        records: [], rejected: 0, rejectReasons: [], fromCsv: true,
      });
    }
    const dd = splitList(g(r, "dkim_domains")), ds = splitList(g(r, "dkim_selectors")), dr = splitList(g(r, "dkim_results"));
    const sd = splitList(g(r, "spf_domains")), ss = splitList(g(r, "spf_scopes")), sr = splitList(g(r, "spf_results"));
    const hasAuth = !!(map.dkim_results || map.spf_results);
    groups.get(key).records.push({
      ip: normIp(ip), count, headerFrom: hf, envelopeFrom: normDomain(g(r, "envelope_from")), envelopeTo: normDomain(g(r, "envelope_to")),
      disposition: lc(g(r, "disposition")) || "none",
      evalDkim: map.dkim_eval ? (truthy(g(r, "dkim_eval")) ? "pass" : "fail") : "", evalSpf: map.spf_eval ? (truthy(g(r, "spf_eval")) ? "pass" : "fail") : "",
      reasons: splitList(g(r, "reasons")).map((t) => ({ type: lc(t), comment: "" })),
      dkim: hasAuth ? dd.map((d, i) => ({ domain: normDomain(d), selector: ds[i] || "", result: lc(dr[i] || ""), human: "" })) : null,
      spf: hasAuth ? sd.map((d, i) => ({ domain: normDomain(d), scope: lc(ss[i] || "mfrom"), result: lc(sr[i] || "") })) : null,
    });
  }
  return { reports: [...groups.values()], rejected, headers, map };
}

function asFiles(input) {
  if (input == null) return [];
  if (typeof input === "string") return [{ name: "input", text: input }];
  if (Array.isArray(input)) return input.map((f, i) => (typeof f === "string" ? { name: "input-" + (i + 1), text: f } : { name: String(f.name || "input-" + (i + 1)), text: String(f.text == null ? "" : f.text), columns: f.columns || {} }));
  if (Array.isArray(input.files)) return asFiles(input.files);
  return [];
}

/**
 * Parse report files. Accepts text, [{name,text,columns?}] or {files}.
 * Duplicate aggregate reports (same reporter org + report_id) are kept once.
 */
export function parseInput(input, ctx) {
  const files = asFiles(input).slice().sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const skipped = [], reports = [], forensic = [], fileInfo = [], seen = new Map();
  let duplicates = 0;
  files.forEach((f, i) => {
    if (i % 25 === 0) ctx?.progress?.(i, files.length, "parsing reports");
    const det = detectFile(f);
    const info = { name: f.name, format: det.format, label: det.label, confidence: det.confidenceLabel, reports: 0, records: 0, rejected: 0, duplicate: false, error: "" };
    let got = [];
    if (det.format === "rua-xml" || det.format === "rua-dmarcbis") {
      const r = parseAggregateXml(f.text, f.name);
      if (r.error) info.error = r.error; else got = [r.report];
    } else if (det.format === "csv-parsedmarc" || det.format === "csv") {
      const r = parseCsvReports(f.text, f.name, f.columns || {});
      if (r.error) info.error = r.error; else { got = r.reports; info.rejected += r.rejected; }
    } else if (det.format === "ruf-arf") {
      const r = parseForensic(f.text, f.name);
      if (r.error) info.error = r.error; else { forensic.push(r.report); info.reports = 1; }
    } else info.error = det.format === "empty" ? "empty file" : det.label;
    for (const rep of got) {
      const key = lc(rep.org) + "\u0000" + (rep.reportId || "noid:" + cyrb53(f.text));
      if (seen.has(key)) { duplicates++; info.duplicate = true; info.duplicateOf = seen.get(key); continue; }
      seen.set(key, f.name);
      reports.push(rep);
      info.reports++; info.records += rep.records.length; info.rejected += rep.rejected;
    }
    if (info.error) skipped.push({ file: f.name, reason: info.error });
    else if (info.duplicate && !info.reports) skipped.push({ file: f.name, reason: "duplicate report (same reporter and report_id as " + info.duplicateOf + ")" });
    fileInfo.push(info);
  });
  reports.sort((a, b) => (a.begin ?? 0) - (b.begin ?? 0) || cmp(a.org, b.org) || cmp(a.reportId, b.reportId) || cmp(a.file, b.file));
  const rows = [];
  for (const rep of reports) for (const r of rep.records) rows.push({ org: rep.org, report_id: rep.reportId, begin: rep.begin, policy_domain: rep.policy.domain, source_ip: r.ip, count: r.count, header_from: r.headerFrom, envelope_from: r.envelopeFrom, disposition: r.disposition });
  const fmts = [...new Set(fileInfo.map((x) => x.format))].sort();
  return { format: fmts.length === 1 ? fmts[0] : fmts.length ? "mixed" : "empty", headers: Object.keys(rows[0] || {}), rows, skipped, reports, forensic, files: fileInfo, duplicates };
}

const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const pct = (n, d) => (d > 0 ? Math.round((n / d) * 1000) / 10 : 0);
const sortedArr = (set) => [...set].sort();
const isoDay = (epoch) => (epoch == null ? "" : new Date(epoch * 1000).toISOString().slice(0, 10));

// ---------------------------------------------------------------------------
// Per-record evaluation
// ---------------------------------------------------------------------------

/** Recompute DMARC for one record against the published policy (RFC 7489 3.1). */
export function evaluateRecord(rec, policy) {
  const hf = rec.headerFrom;
  const adkim = policy.adkim || "r", aspf = policy.aspf || "r";
  if (rec.dkim == null || rec.spf == null) {
    // no auth_results (CSV without them): fall back to the reporter's evaluation
    const dk = rec.evalDkim === "pass", sp = rec.evalSpf === "pass";
    return { dkimAligned: dk, spfAligned: sp, pass: dk || sp, recomputed: false };
  }
  const dkimAligned = rec.dkim.some((d) => d.result === "pass" && aligned(d.domain, hf, adkim));
  let spfs = rec.spf.filter((s) => !s.scope || s.scope === "mfrom");
  if (!spfs.length) spfs = rec.spf.filter((s) => s.scope === "helo");
  const spfAligned = spfs.some((s) => s.result === "pass" && aligned(s.domain || rec.envelopeFrom, hf, aspf));
  return { dkimAligned, spfAligned, pass: dkimAligned || spfAligned, recomputed: true };
}

function sourceDomains(rec) {
  const dkim = (rec.dkim || []).map((d) => d.domain).filter(Boolean);
  const spf = [...(rec.spf || []).map((s) => s.domain), rec.envelopeFrom].filter(Boolean);
  return { dkim, spf };
}

// ---------------------------------------------------------------------------
// Live lookups (results passed in from the UI; this module never fetches)
// ---------------------------------------------------------------------------

/**
 * Total SPF DNS-lookup count for a domain by walking include:/redirect= through
 * the records fetched live. `records` maps domain -> TXT strings (or {error}).
 */
export function spfTotalLookups(domain, records = {}) {
  const unresolved = [], seen = new Set(), chain = [];
  const walk = (d, depth) => {
    d = normDomain(d);
    if (seen.has(d) || depth > 12) return 0;
    seen.add(d);
    const txt = records[d];
    if (!Array.isArray(txt)) { unresolved.push(d); return 0; }
    const spf = parseSPF(txt);
    if (!spf.present) { unresolved.push(d); return 0; }
    let n = spfLookupCount(spf.record);
    chain.push({ domain: d, lookups: n, record: spf.record });
    for (const tok of String(spf.record).split(/\s+/)) {
      const m = tok.replace(/^[-~?+]/, "").match(/^(?:include:|redirect=)(.+)$/i);
      if (m) n += walk(m[1], depth + 1);
    }
    return n;
  };
  const total = walk(domain, 0);
  unresolved.sort();
  return { domain: normDomain(domain), total, chain, unresolved: unresolved.filter((d) => d !== normDomain(domain) || !chain.length) };
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------
const STAGES = [
  { p: "none", pct: 100, label: "p=none (monitor)" },
  { p: "quarantine", pct: 10, label: "p=quarantine pct=10" },
  { p: "quarantine", pct: 25, label: "p=quarantine pct=25" },
  { p: "quarantine", pct: 50, label: "p=quarantine pct=50" },
  { p: "quarantine", pct: 100, label: "p=quarantine pct=100" },
  { p: "reject", pct: 10, label: "p=reject pct=10" },
  { p: "reject", pct: 25, label: "p=reject pct=25" },
  { p: "reject", pct: 50, label: "p=reject pct=50" },
  { p: "reject", pct: 100, label: "p=reject pct=100" },
];
export { STAGES };

/** Stage index for a published p / pct (pct below the first step maps to that step). */
export function stageIndex(p, pctV) {
  p = lc(p);
  if (p !== "quarantine" && p !== "reject") return 0;
  const n = Number.isFinite(pctV) ? pctV : 100;
  let idx = -1;
  STAGES.forEach((s, i) => { if (s.p === p && s.pct <= n) idx = i; });
  if (idx < 0) idx = STAGES.findIndex((s) => s.p === p);
  return idx;
}

const parseKnown = (s) => new Set(String(s || "").split(/[\s,;]+/).map(normDomain).filter(Boolean));

function mkFinding(o) {
  const evidence = o.evidence || [];
  return {
    id: o.id, title: o.title, severity: o.severity, confidence: o.confidence, category: o.category,
    description: o.description, recommendation: o.recommendation, controls: o.controls,
    evidence: evidence.slice(0, 50), evidenceCount: o.evidenceCount == null ? evidence.length : o.evidenceCount,
    assets: o.assets || [], tags: o.tags || [TOOL_ID],
  };
}

/**
 * Analyze DMARC reports. `dataset` is the parseInput() result, or anything
 * parseInput accepts. opts overrides DEFAULTS; opts.live carries DoH results.
 */
export function analyze(dataset, opts = {}, ctx) {
  const o = { ...DEFAULTS, ...(opts || {}) };
  for (const k of ["noneDays", "spoofMin", "readyPassRate", "senderMinMessages", "minObserveDays", "pctStuckDays"]) {
    const n = Number(o[k]); o[k] = Number.isFinite(n) && n >= 0 ? n : DEFAULTS[k];
  }
  const parsed = dataset && Array.isArray(dataset.reports) ? dataset : parseInput(dataset, ctx);
  const reports = parsed.reports || [];
  const live = o.live && typeof o.live === "object" ? o.live : null;
  const known = parseKnown(o.knownDomains);
  const skipped = (parsed.skipped || []).map((s) => ({ check: "parse", reason: s.file + ": " + s.reason }));
  const findings = [];

  // ---- per (header_from, ip) aggregation ----
  const totalRecords = reports.reduce((n, r) => n + r.records.length, 0);
  const agg = new Map(), domainsT = new Map(), dailyT = new Map(), reportersT = new Map(), policyDomains = new Map();
  const mismatches = [], selSeen = new Set();
  let messages = 0, passMsgs = 0, recIdx = 0, anyRecomputed = false, anyEval = false;
  for (const rep of reports) {
    const pd = rep.policy.domain || (rep.records[0] && rep.records[0].headerFrom) || "";
    const R = reportersT.get(rep.org) || { org: rep.org, email: rep.email, reports: 0, messages: 0, first: null, last: null, schemas: new Set() };
    R.reports++; R.schemas.add(rep.schema);
    if (rep.begin != null) R.first = R.first == null ? rep.begin : Math.min(R.first, rep.begin);
    if (rep.end != null) R.last = R.last == null ? rep.end : Math.max(R.last, rep.end);
    reportersT.set(rep.org, R);
    const PD = policyDomains.get(pd) || { domain: pd, reports: [] };
    PD.reports.push(rep); policyDomains.set(pd, PD);
    const day = isoDay(rep.begin);
    for (const rec of rep.records) {
      if (recIdx++ % 1000 === 0) ctx?.progress?.(recIdx, totalRecords, "evaluating records");
      const ev = evaluateRecord(rec, rep.policy);
      if (ev.recomputed) anyRecomputed = true;
      const n = rec.count;
      messages += n; R.messages += n;
      if (ev.pass) passMsgs += n;
      const key = rec.headerFrom + "\u0000" + rec.ip;
      let A = agg.get(key);
      if (!A) {
        A = { ip: rec.ip, headerFrom: rec.headerFrom, policyDomain: pd, messages: 0, dkimAligned: 0, spfAligned: 0, pass: 0, fail: 0, dispositions: { none: 0, quarantine: 0, reject: 0 },
          envelope: new Set(), dkimDomains: new Set(), selectors: new Set(), dkimPairs: new Set(), spfDomains: new Set(), reporters: new Set(), reasons: new Set(), fwdSignature: 0, overrideFwd: 0, days: new Set(), first: null, last: null };
        agg.set(key, A);
      }
      A.messages += n;
      if (ev.dkimAligned) A.dkimAligned += n;
      if (ev.spfAligned) A.spfAligned += n;
      if (ev.pass) A.pass += n; else A.fail += n;
      A.dispositions[rec.disposition] = (A.dispositions[rec.disposition] || 0) + n;
      if (rec.envelopeFrom) A.envelope.add(rec.envelopeFrom);
      for (const d of rec.dkim || []) { if (d.domain) A.dkimDomains.add(d.domain); if (d.selector) A.selectors.add(d.selector); if (d.domain) A.dkimPairs.add(d.domain + (d.selector ? " / " + d.selector : "") + " (" + (d.result || "?") + ")"); }
      for (const s of rec.spf || []) if (s.domain) A.spfDomains.add(s.domain);
      for (const d of rec.dkim || []) if (d.result === "pass" && d.domain && d.selector && aligned(d.domain, rec.headerFrom, rep.policy.adkim)) selSeen.add(d.domain + "|" + d.selector);
      A.reporters.add(rep.org);
      for (const r of rec.reasons) A.reasons.add(r.type || r.comment);
      if (rec.reasons.some((r) => OVERRIDE_FORWARD.has(r.type))) A.overrideFwd += n;
      // forwarding signature: aligned DKIM passes, SPF for an aligned envelope domain fails
      if (ev.recomputed && ev.dkimAligned && !ev.spfAligned && (rec.spf || []).some((s) => ["fail", "softfail", "neutral", "none", "temperror", "permerror"].includes(s.result) && aligned(s.domain || rec.envelopeFrom, rec.headerFrom, "r"))) A.fwdSignature += n;
      if (day) { A.days.add(day); A.first = A.first == null || day < A.first ? day : A.first; A.last = A.last == null || day > A.last ? day : A.last; }
      // reporter disagreement
      if (ev.recomputed && (rec.evalDkim || rec.evalSpf)) {
        anyEval = true;
        const diffs = [];
        if (rec.evalDkim && (rec.evalDkim === "pass") !== ev.dkimAligned) diffs.push("DKIM: reporter " + rec.evalDkim + ", recomputed " + (ev.dkimAligned ? "pass" : "fail"));
        if (rec.evalSpf && (rec.evalSpf === "pass") !== ev.spfAligned) diffs.push("SPF: reporter " + rec.evalSpf + ", recomputed " + (ev.spfAligned ? "pass" : "fail"));
        const effP = rec.headerFrom === pd ? rep.policy.p : (rep.policy.sp || rep.policy.p);
        if (ev.pass && rec.disposition !== "none" && !rec.reasons.length) diffs.push("disposition " + rec.disposition + " although DMARC passes");
        if (!ev.pass && effP === "reject" && rep.policy.pct >= 100 && rec.disposition === "none" && !rec.reasons.length && rep.policy.testing !== "y") diffs.push("p=reject not applied and no override reason given");
        if (diffs.length) mismatches.push({ reporter: rep.org, report_id: rep.reportId, date: day, source_ip: rec.ip, header_from: rec.headerFrom, messages: n, differences: diffs.join("; ") });
      }
      // domain + daily tables
      const D = domainsT.get(rec.headerFrom) || { domain: rec.headerFrom, policyDomain: pd, messages: 0, pass: 0, policies: new Set(), reporters: new Set(), sources: new Set() };
      D.messages += n; if (ev.pass) D.pass += n;
      D.policies.add("p=" + (rep.policy.p || "?") + (rep.policy.sp ? " sp=" + rep.policy.sp : "") + (rep.policy.pct !== 100 ? " pct=" + rep.policy.pct : "") + (rep.policy.testing === "y" ? " t=y" : ""));
      D.reporters.add(rep.org); D.sources.add(rec.ip);
      domainsT.set(rec.headerFrom, D);
      const dk = day || "(no date)";
      const Y = dailyT.get(dk) || { date: dk, pass: 0, fail: 0 };
      if (ev.pass) Y.pass += n; else Y.fail += n;
      dailyT.set(dk, Y);
    }
  }
  if (reports.length && !anyRecomputed) skipped.push({ check: "alignment", reason: "no auth_results in the input; alignment taken from the reporter's policy_evaluated instead of recomputed" });

  // ---- classify sources ----
  const ptrs = (live && live.ptr) || {};
  const sources = [];
  for (const A of agg.values()) {
    const doms = { dkim: sortedArr(A.dkimDomains).filter((d) => !aligned(d, A.headerFrom, "r")), spf: sortedArr(new Set([...A.spfDomains, ...A.envelope])).filter((d) => !aligned(d, A.headerFrom, "r")) };
    const fwd = matchForwarder(doms);
    const esp = matchEsp(doms, sortedArr(A.selectors));
    let kind, name, via = "", serviceId = "";
    if (fwd || A.overrideFwd > 0) { kind = "forwarder"; name = fwd ? fwd.fwd.name : "Forwarder (reporter override reason)"; via = fwd ? fwd.via : "override reason " + sortedArr(A.reasons).join(", "); serviceId = fwd ? fwd.fwd.id : "override"; }
    else if (esp && esp.strength === "domain") { kind = "esp"; name = esp.esp.name; via = esp.via; serviceId = esp.esp.id; }
    else if (A.fwdSignature > 0 && A.fwdSignature >= A.messages * 0.5) { kind = "forwarder"; name = "Forwarded mail (DKIM survives, SPF breaks)"; via = "aligned DKIM pass with failing SPF for your own envelope domain"; serviceId = "signature"; }
    else if (esp) { kind = "esp"; name = esp.esp.name; via = esp.via; serviceId = esp.esp.id; }
    else if (A.pass >= A.messages * 0.5 && A.pass > 0) { kind = "authenticated"; name = "Authenticated as your domain (service not identified)"; via = "aligned DKIM or SPF pass"; serviceId = "own"; }
    else { kind = "unknown"; name = "Unknown source"; via = "no aligned pass and no known service domain"; serviceId = "unknown"; }
    const ptr = Array.isArray(ptrs[A.ip]) ? ptrs[A.ip].join(", ") : ptrs[A.ip] && ptrs[A.ip].error ? "(lookup failed)" : undefined;
    sources.push({
      key: A.headerFrom + "|" + A.ip, ip: A.ip, ipVersion: ipVersion(A.ip), ...(ptr !== undefined ? { ptr } : {}),
      headerFrom: A.headerFrom, policyDomain: A.policyDomain, messages: A.messages, pass: A.pass, fail: A.fail,
      dkimAlignedPct: pct(A.dkimAligned, A.messages), spfAlignedPct: pct(A.spfAligned, A.messages), dmarcPassPct: pct(A.pass, A.messages),
      kind, classification: name, serviceId, classifiedVia: via, selectorOnly: !!(esp && esp.strength === "selector" && kind === "esp"),
      envelopeDomains: sortedArr(A.envelope).join(", "), dkimDomains: sortedArr(A.dkimPairs).join(", "), selectors: sortedArr(A.selectors).join(", "),
      dispositions: Object.entries(A.dispositions).filter(([, v]) => v).map(([k, v]) => k + " " + v).sort().join(", "),
      reporters: sortedArr(A.reporters).join(", "), reasons: sortedArr(A.reasons).join(", "), days: A.days.size, first: A.first || "", last: A.last || "",
      disp: A.dispositions,
    });
  }
  sources.sort((a, b) => b.messages - a.messages || cmp(a.headerFrom, b.headerFrom) || cmp(a.ip, b.ip));

  // ---- senders (classified services) ----
  const sendersM = new Map();
  for (const s of sources) {
    const k = s.kind + ":" + s.serviceId + (s.kind === "forwarder" && s.serviceId === "signature" ? "" : "");
    const S = sendersM.get(k) || { key: k, kind: s.kind, sender: s.classification, serviceId: s.serviceId, sources: 0, messages: 0, pass: 0, fail: 0, dkim: 0, spf: 0, domains: new Set(), via: new Set(), selectorOnly: true };
    S.sources++; S.messages += s.messages; S.pass += s.pass; S.fail += s.fail;
    S.dkim += Math.round((s.dkimAlignedPct / 100) * s.messages); S.spf += Math.round((s.spfAlignedPct / 100) * s.messages);
    S.domains.add(s.headerFrom); S.via.add(s.classifiedVia); if (!s.selectorOnly) S.selectorOnly = false;
    sendersM.set(k, S);
  }
  const senders = [...sendersM.values()].map((S) => {
    const esp = ESP_TABLE.find((e) => e.id === S.serviceId);
    return {
      key: S.key, kind: S.kind, sender: S.sender, sources: S.sources, messages: S.messages, failing: S.fail,
      dmarcPassPct: pct(S.pass, S.messages), dkimAlignedPct: pct(S.dkim, S.messages), spfAlignedPct: pct(S.spf, S.messages),
      domains: sortedArr(S.domains).join(", "), classifiedVia: sortedArr(S.via).slice(0, 5).join("; "), selectorOnly: S.kind === "esp" && S.selectorOnly,
      spfInclude: esp ? esp.include || "" : "",
    };
  }).sort((a, b) => b.messages - a.messages || cmp(a.sender, b.sender));

  // ---- domains / daily / reporters tables ----
  const domains = [...domainsT.values()].map((D) => ({ domain: D.domain, policyDomain: D.policyDomain, isSubdomain: isSubdomainOf(D.domain, D.policyDomain), messages: D.messages, pass: D.pass, fail: D.messages - D.pass, passPct: pct(D.pass, D.messages), policies: sortedArr(D.policies).join("; "), reporters: D.reporters.size, sources: D.sources.size }))
    .sort((a, b) => b.messages - a.messages || cmp(a.domain, b.domain));
  const daily = [...dailyT.values()].sort((a, b) => cmp(a.date, b.date)).map((d) => ({ ...d, messages: d.pass + d.fail, passPct: pct(d.pass, d.pass + d.fail) }));
  const reporters = [...reportersT.values()].map((R) => ({ org: R.org, email: R.email, reports: R.reports, messages: R.messages, first: isoDay(R.first), last: isoDay(R.last), schemas: sortedArr(R.schemas).join(", ") }))
    .sort((a, b) => b.reports - a.reports || cmp(a.org, b.org));

  const srcEv = (s) => ({ source_ip: s.ip, ...(s.ptr !== undefined ? { ptr: s.ptr } : {}), header_from: s.headerFrom, messages: s.messages, failing: s.fail, dmarc_pass_pct: s.dmarcPassPct, dkim_aligned_pct: s.dkimAlignedPct, spf_aligned_pct: s.spfAlignedPct, classification: s.classification, classified_via: s.classifiedVia, envelope_from: s.envelopeDomains, dkim: s.dkimDomains, dispositions: s.dispositions, reporters: s.reporters, first: s.first, last: s.last });

  // ---- policy per policy domain (latest report wins) ----
  const policyInfo = [];
  for (const PD of [...policyDomains.values()].sort((a, b) => cmp(a.domain, b.domain))) {
    const reps = PD.reports.slice().sort((a, b) => (a.begin ?? 0) - (b.begin ?? 0) || cmp(a.org, b.org) || cmp(a.reportId, b.reportId));
    const latest = reps[reps.length - 1].policy;
    const pkey = (p) => p.p + "|" + p.pct + "|" + (p.testing === "y" ? "y" : "n");
    const curKey = pkey(latest);
    // contiguous window at the current policy, walking back from the latest report
    let since = null, until = null, minB = null, maxE = null;
    for (const r of reps) { if (r.begin != null) minB = minB == null ? r.begin : Math.min(minB, r.begin); if (r.end != null) maxE = maxE == null ? r.end : Math.max(maxE, r.end); }
    for (let i = reps.length - 1; i >= 0; i--) {
      const p = reps[i].policy;
      if (pkey(p) !== curKey) break;
      if (reps[i].begin != null) since = reps[i].begin;
      if (until == null && reps[i].end != null) until = reps[i].end;
    }
    for (const r of reps) if (r.end != null && (until == null || r.end > until) && pkey(r.policy) === curKey) until = r.end;
    const days = since != null && until != null ? Math.max(0, Math.round((until - since + 1) / DAY)) : 0;
    const seenP = sortedArr(new Set(reps.map((r) => "p=" + (r.policy.p || "?") + (r.policy.pct !== 100 ? " pct=" + r.policy.pct : ""))));
    policyInfo.push({ domain: PD.domain, latest, days, since: isoDay(since), until: isoDay(until), coverageDays: minB != null && maxE != null ? Math.max(0, Math.round((maxE - minB + 1) / DAY)) : 0, policiesSeen: seenP, reports: reps.length, schemas: new Set(reps.map((r) => r.schema)), anyNp: reps.some((r) => r.policy.hasNp), bisReports: reps.filter((r) => r.schema === "dmarcbis").length });
  }
  const srcsFor = (pd) => sources.filter((s) => s.policyDomain === pd);
  const legitOf = (list) => list.filter((s) => s.kind === "esp" || s.kind === "authenticated");

  // ---- detection: monitoring-only policy too long ----
  for (const P of policyInfo) {
    if (P.latest.p !== "none" && P.latest.p !== "") continue;
    const list = srcsFor(P.domain), legit = legitOf(list);
    const lm = legit.reduce((n, s) => n + s.messages, 0), lp = legit.reduce((n, s) => n + s.pass, 0);
    const rate = pct(lp, lm);
    if (P.days <= o.noneDays) continue;
    const ready = lm > 0 && rate >= o.readyPassRate;
    findings.push(mkFinding({
      id: "dmr-policy-none-" + P.domain, title: ready ? "p=none kept with a high pass rate: ready for quarantine" : "p=none kept for a long time while senders still fail",
      severity: ready ? "medium" : "low", confidence: "confirmed", category: "policy",
      description: P.domain + " published p=none across " + P.days + " days of reports (" + P.since + " to " + P.until + "). Legitimate-looking mail passes DMARC at " + rate + "% (" + lp + " of " + lm + " messages; threshold " + o.readyPassRate + "%). p=none only monitors: spoofed mail is still delivered.",
      recommendation: ready ? "Move to p=quarantine in steps (pct=10, 25, 50, 100), watching these reports for at least " + o.minObserveDays + " days per step, then p=reject the same way. See the Progression plan tab." : "Fix the failing legitimate senders listed in the Progression plan tab first, then start p=quarantine at pct=10.",
      controls: [C.policy, C.bod, C.m3, C.nist], evidence: [{ policy_domain: P.domain, published: P.policiesSeen.join("; "), days_at_policy: P.days, since: P.since, until: P.until, legit_messages: lm, legit_pass_pct: rate, threshold_pct: o.readyPassRate }],
      assets: [{ type: "DOMAIN", name: P.domain }],
    }));
  }

  // ---- detection: known services not aligned ----
  const fixes = [];
  const espFail = new Map();
  for (const s of sources) {
    if (s.kind !== "esp" || s.fail <= 0) continue;
    const k = s.serviceId;
    const E = espFail.get(k) || { esp: ESP_TABLE.find((e) => e.id === k), srcs: [], fail: 0, messages: 0, dkimA: 0, spfA: 0, domains: new Set(), selectorOnly: true };
    E.srcs.push(s); E.fail += s.fail; E.messages += s.messages; E.dkimA += Math.round(s.dkimAlignedPct * s.messages / 100); E.spfA += Math.round(s.spfAlignedPct * s.messages / 100); E.domains.add(s.headerFrom); if (!s.selectorOnly) E.selectorOnly = false;
    espFail.set(k, E);
  }
  for (const E of [...espFail.values()].sort((a, b) => b.fail - a.fail || cmp(a.esp.name, b.esp.name))) {
    const doms = sortedArr(E.domains);
    const fixRows = doms.map((d) => ({
      sender: E.esp.name, domain: d,
      dkim: E.esp.dkimFix.replace(/\{domain\}/g, d),
      spf: E.esp.spfFix.replace(/\{domain\}/g, d),
      spfInclude: E.esp.include ? "include:" + E.esp.include : "",
      dkimAlignedPct: pct(E.dkimA, E.messages), spfAlignedPct: pct(E.spfA, E.messages), failing: E.srcs.filter((s) => s.headerFrom === d).reduce((n, s) => n + s.fail, 0),
    }));
    fixes.push(...fixRows);
    if (E.fail < o.senderMinMessages) continue;
    findings.push(mkFinding({
      id: "dmr-esp-" + E.esp.id, title: E.esp.name + " sends as your domain without DMARC alignment",
      severity: "medium", confidence: E.selectorOnly ? "review" : "likely", category: "alignment",
      description: E.fail + " of " + E.messages + " messages from " + E.esp.name + " (" + E.srcs.length + " source IP" + (E.srcs.length === 1 ? "" : "s") + ") fail DMARC for " + doms.join(", ") + ". DKIM aligned " + pct(E.dkimA, E.messages) + "%, SPF aligned " + pct(E.spfA, E.messages) + "%. Classified from report data (" + sortedArr(new Set(E.srcs.map((s) => s.classifiedVia))).slice(0, 3).join("; ") + ")" + (E.selectorOnly ? "; selector match only, confirm the service" : "") + ".",
      recommendation: "Sign with DKIM d=" + doms[0] + " in " + E.esp.name + " (" + E.esp.dkimFix.replace(/\{domain\}/g, doms[0]) + ") " + (E.esp.spfFix.replace(/\{domain\}/g, doms[0])) + " Until this is done, enforcing DMARC will quarantine or reject this mail.",
      controls: [C.align, C.dkimD, C.spfFrom, C.m3], evidence: E.srcs.map(srcEv), evidenceCount: E.srcs.length,
      assets: doms.map((d) => ({ type: "DOMAIN", name: d })), tags: [TOOL_ID, "esp:" + E.esp.id],
    }));
  }

  // ---- detection: spoofing (unknown sources failing DMARC) ----
  const byPd = new Map();
  for (const s of sources) {
    if (s.kind !== "unknown" || s.fail <= 0) continue;
    const pd = s.policyDomain;
    if (!byPd.has(pd)) byPd.set(pd, []);
    byPd.get(pd).push(s);
  }
  for (const pd of sortedArr(new Set(byPd.keys()))) {
    const list = byPd.get(pd).sort((a, b) => b.fail - a.fail || cmp(a.ip, b.ip));
    const fail = list.reduce((n, s) => n + s.fail, 0);
    const delivered = list.reduce((n, s) => n + (s.disp.none || 0), 0);
    const rejected = list.reduce((n, s) => n + (s.disp.reject || 0), 0);
    const P = policyInfo.find((x) => x.domain === pd);
    const blocked = rejected + list.reduce((n, s) => n + (s.disp.quarantine || 0), 0);
    const mostlyBlocked = fail > 0 && blocked / fail >= 0.95;
    const sev = mostlyBlocked ? "low" : fail > o.spoofMin ? "high" : "medium";
    const hfs = sortedArr(new Set(list.map((s) => s.headerFrom)));
    findings.push(mkFinding({
      id: "dmr-spoof-" + pd, title: mostlyBlocked ? "Spoofing attempts blocked by your DMARC policy" : "Unauthenticated mail sent as your domain from unknown sources",
      severity: sev, confidence: "likely", category: "spoofing",
      description: list.length + " source IP" + (list.length === 1 ? "" : "s") + " with no known sending service sent " + fail + " messages as " + hfs.join(", ") + " that failed DMARC (threshold for high: " + o.spoofMin + "). Receivers delivered " + delivered + " of them (disposition none), quarantined " + (blocked - rejected) + " and rejected " + rejected + ". Published policy: " + (P ? "p=" + (P.latest.p || "?") + (P.latest.pct !== 100 ? " pct=" + P.latest.pct : "") : "unknown") + ".",
      recommendation: mostlyBlocked ? "No action needed beyond keeping p=reject; review the source list for any legitimate sender you missed." : "Confirm none of these sources are yours (check the Sources tab, use Look up sources for PTR names). Then advance the DMARC policy per the Progression plan so receivers quarantine or reject this mail.",
      controls: [C.phish, C.imperson, C.policy, C.bod], evidence: list.map(srcEv), evidenceCount: list.length,
      assets: [...hfs.map((d) => ({ type: "DOMAIN", name: d })), ...list.slice(0, 50).map((s) => ({ type: "IP", name: s.ip, data: { messages: s.fail, headerFrom: s.headerFrom } }))],
    }));
  }

  // ---- detection: subdomain spoofing ----
  for (const P of policyInfo) {
    const subs = sources.filter((s) => s.policyDomain === P.domain && isSubdomainOf(s.headerFrom, P.domain) && s.kind === "unknown" && s.fail > 0);
    if (!subs.length) continue;
    const effSp = P.latest.sp || P.latest.p || "none";
    const fail = subs.reduce((n, s) => n + s.fail, 0);
    const hfs = sortedArr(new Set(subs.map((s) => s.headerFrom)));
    const notKnown = known.size ? hfs.filter((d) => !known.has(d)) : [];
    const sev = effSp === "reject" ? "low" : effSp === "quarantine" ? "medium" : fail > o.spoofMin ? "high" : "medium";
    findings.push(mkFinding({
      id: "dmr-subspoof-" + P.domain, title: "Spoofed subdomains of " + P.domain,
      severity: sev, confidence: "likely", category: "spoofing",
      description: fail + " failing messages used subdomain From addresses (" + hfs.join(", ") + ") from unknown sources. Subdomain policy in effect: sp=" + (P.latest.sp || "(not set, inherits p=" + (P.latest.p || "?") + ")") + "." + (notKnown.length ? " Not in your known sending domains: " + notKnown.join(", ") + "." : ""),
      recommendation: effSp === "reject" ? "Subdomain mail is rejected already; keep sp=reject." : "Publish an explicit sp= tag (sp=reject for subdomains that never send mail) and DMARC records on subdomains that do send. Advance sp together with p.",
      controls: [C.policy, C.np, C.imperson, C.m3], evidence: subs.map(srcEv), evidenceCount: subs.length,
      assets: hfs.map((d) => ({ type: "DOMAIN", name: d })),
    }));
  }

  // ---- detection: forwarding / mailing lists (informational) ----
  const fwdSrcs = sources.filter((s) => s.kind === "forwarder");
  if (fwdSrcs.length) {
    const byName = new Map();
    for (const s of fwdSrcs) { if (!byName.has(s.classification)) byName.set(s.classification, []); byName.get(s.classification).push(s); }
    for (const name of sortedArr(new Set(byName.keys()))) {
      const list = byName.get(name);
      const m = list.reduce((n, s) => n + s.messages, 0), f = list.reduce((n, s) => n + s.fail, 0);
      findings.push(mkFinding({
        id: "dmr-fwd-" + cyrb53(name), title: "Likely forwarding: " + name,
        severity: "info", confidence: "likely", category: "forwarding",
        description: m + " messages (" + f + " failing DMARC) arrived through " + list.length + " source IP" + (list.length === 1 ? "" : "s") + " that look like forwarding or a mailing list, not spoofing: " + sortedArr(new Set(list.map((s) => s.classifiedVia))).slice(0, 3).join("; ") + ".",
        recommendation: f ? "Forwarded mail passes DMARC only while the DKIM signature survives. Keep DKIM on every sender (sign with d=your domain), avoid body/subject rewrites on your own lists, and expect receivers using ARC to override. Do not add forwarders to SPF." : "No action: DKIM survives forwarding, so this mail passes DMARC.",
        controls: [C.align, C.dkimD, C.m3], evidence: list.map(srcEv), evidenceCount: list.length,
        assets: sortedArr(new Set(list.map((s) => s.headerFrom))).map((d) => ({ type: "DOMAIN", name: d })),
      }));
    }
  }

  // ---- detection: pct below 100 held too long ----
  for (const P of policyInfo) {
    const testing = P.latest.testing === "y";
    if (!(P.latest.p === "quarantine" || P.latest.p === "reject")) continue;
    if (!(P.latest.pct < 100 || testing)) continue;
    if (P.days <= o.pctStuckDays) continue;
    findings.push(mkFinding({
      id: "dmr-pct-" + P.domain, title: testing ? "DMARC testing mode (t=y) kept for " + P.days + " days" : "pct=" + P.latest.pct + " kept for " + P.days + " days",
      severity: "low", confidence: "confirmed", category: "policy",
      description: P.domain + " published p=" + P.latest.p + (testing ? " with t=y (testing)" : " pct=" + P.latest.pct) + " for " + P.days + " days (" + P.since + " to " + P.until + "); only part of the failing mail gets the policy" + (testing ? " (receivers apply the next lower policy)" : "") + ".",
      recommendation: "If the Progression plan shows no blocking senders, advance to the next pct step.",
      controls: [C.policy, C.m3, C.bod], evidence: [{ policy_domain: P.domain, p: P.latest.p, pct: P.latest.pct, testing: P.latest.testing || "", days: P.days, since: P.since, until: P.until }],
      assets: [{ type: "DOMAIN", name: P.domain }],
    }));
  }

  // ---- detection: np absent (DMARCbis-schema reports only) ----
  const bisAny = policyInfo.some((P) => P.bisReports > 0);
  if (!bisAny && reports.length) skipped.push({ check: "np_absent", reason: "np (non-existent subdomain policy) is only reported in DMARCbis-schema reports; none were loaded" });
  for (const P of policyInfo) {
    if (!P.bisReports || P.anyNp) continue;
    findings.push(mkFinding({
      id: "dmr-np-" + P.domain, title: "No np policy for non-existent subdomains of " + P.domain,
      severity: "info", confidence: "confirmed", category: "policy",
      description: P.bisReports + " DMARCbis-schema report(s) show no np tag in the published policy of " + P.domain + ". Mail from subdomains that do not exist in DNS falls back to sp / p.",
      recommendation: "Add np=reject to the DMARC record of " + P.domain + " so mail from made-up subdomains is rejected even while p / sp are still being stepped up.",
      controls: [C.np, C.policy], evidence: [{ policy_domain: P.domain, dmarcbis_reports: P.bisReports, latest_policy: "p=" + P.latest.p + (P.latest.sp ? " sp=" + P.latest.sp : "") }],
      assets: [{ type: "DOMAIN", name: P.domain }],
    }));
  }

  // ---- detection: reporter disagreement ----
  if (!anyEval && reports.length) skipped.push({ check: "reporter_mismatch", reason: "no policy_evaluated results alongside auth_results to compare" });
  if (mismatches.length) {
    mismatches.sort((a, b) => cmp(a.date, b.date) || cmp(a.reporter, b.reporter) || cmp(a.source_ip, b.source_ip) || cmp(a.report_id, b.report_id));
    const msgs = mismatches.reduce((n, m) => n + m.messages, 0);
    findings.push(mkFinding({
      id: "dmr-mismatch", title: "Reporter evaluations differ from the recomputed DMARC result",
      severity: "low", confidence: "review", category: "reporting",
      description: mismatches.length + " record(s) covering " + msgs + " messages, from " + new Set(mismatches.map((m) => m.reporter)).size + " reporter(s), disagree with alignment recomputed from auth_results and the published adkim/aspf. Causes include ARC or local overrides, a public-suffix difference, or reporter bugs.",
      recommendation: "Review the rows. A reporter marking aligned mail as failing can quarantine legitimate mail once you enforce; a reporter not applying p=reject without a reason is outside your control but worth noting.",
      controls: [C.report, C.align], evidence: mismatches, evidenceCount: mismatches.length,
    }));
  }

  // ---- live checks (only with DoH results from the UI) ----
  const liveDomains = (live && live.domains) || {};
  if (!live) {
    skipped.push({ check: "spf_lookup_limit", reason: "live check only: use Look up sources to fetch the SPF records (skipped offline)" });
    skipped.push({ check: "live_policy", reason: "live check only: use Look up sources to compare the published DMARC record now" });
  } else {
    for (const P of policyInfo) {
      const L = liveDomains[P.domain];
      if (!L) { skipped.push({ check: "live_policy", reason: P.domain + ": not looked up" }); continue; }
      if (L.spf && L.spf.error) skipped.push({ check: "spf_lookup_limit", reason: P.domain + ": SPF lookup failed (" + L.spf.error + ")" });
      else if (L.spf) {
        const t = spfTotalLookups(P.domain, { [P.domain]: L.spf.txt || [], ...(L.spf.includes || {}) });
        if (!t.chain.length) skipped.push({ check: "spf_lookup_limit", reason: P.domain + ": no SPF record published" });
        else if (t.total > 10) {
          findings.push(mkFinding({
            id: "dmr-spf-limit-" + P.domain, title: "SPF for " + P.domain + " needs " + t.total + " DNS lookups (limit 10)",
            severity: "high", confidence: t.unresolved.length ? "likely" : "confirmed", category: "spf",
            description: "Walking include: and redirect= through the live SPF records counts " + t.total + " lookup-causing terms (RFC 7208 limit 10). Receivers return permerror, so SPF fails for all mail from " + P.domain + "." + (t.unresolved.length ? " Not resolved: " + t.unresolved.join(", ") + "." : "") + " Checked " + (L.checkedAt || live.checkedAt || "") + ".",
            recommendation: "Remove includes for services you no longer use, move senders with their own return-path off your SPF record, or split senders onto subdomains. Do not flatten includes into IPs without a process to keep them current.",
            controls: [C.spfLimit, C.m3], evidence: t.chain.map((c) => ({ domain: c.domain, lookups: c.lookups, record: c.record })),
            assets: [{ type: "DOMAIN", name: P.domain }],
          }));
        }
      }
      if (L.dmarc && L.dmarc.error) skipped.push({ check: "live_policy", reason: P.domain + ": DMARC lookup failed (" + L.dmarc.error + ")" });
      else if (L.dmarc) {
        const now = parseDMARC(L.dmarc.txt || []);
        if (!now.present) {
          findings.push(mkFinding({
            id: "dmr-live-nodmarc-" + P.domain, title: "No DMARC record published now for " + P.domain,
            severity: "high", confidence: "confirmed", category: "policy",
            description: "Reports show p=" + (P.latest.p || "?") + " up to " + P.until + ", but _dmarc." + P.domain + " returned no v=DMARC1 record when checked " + (L.checkedAt || live.checkedAt || "") + ".",
            recommendation: "Republish the DMARC record (it may have been removed in a DNS change).",
            controls: [C.policy, C.bod], evidence: [{ domain: P.domain, reported_policy: "p=" + P.latest.p, txt_now: (L.dmarc.txt || []).join(" | ") || "(none)" }],
            assets: [{ type: "DOMAIN", name: P.domain }],
          }));
        } else if (now.policy !== P.latest.p || now.pct !== P.latest.pct || (now.sp || "") !== (P.latest.sp || "")) {
          findings.push(mkFinding({
            id: "dmr-live-changed-" + P.domain, title: "Published DMARC policy for " + P.domain + " differs from the reports",
            severity: "info", confidence: "confirmed", category: "policy",
            description: "Latest report: p=" + P.latest.p + (P.latest.sp ? " sp=" + P.latest.sp : "") + " pct=" + P.latest.pct + ". Published now: p=" + now.policy + (now.sp ? " sp=" + now.sp : "") + " pct=" + now.pct + ". The Progression plan is based on the reports; collect reports under the new policy before the next step.",
            recommendation: "Confirm the change was intended and give it at least " + o.minObserveDays + " days of reports.",
            controls: [C.policy], evidence: [{ domain: P.domain, reported: "p=" + P.latest.p + " sp=" + (P.latest.sp || "") + " pct=" + P.latest.pct, now: now.record }],
            assets: [{ type: "DOMAIN", name: P.domain }],
          }));
        }
      }
      if (L.dkim) {
        const gone = [];
        for (const sel of Object.keys(L.dkim).sort()) {
          const r = L.dkim[sel];
          if (r && r.error) { skipped.push({ check: "live_dkim", reason: P.domain + " selector " + sel + ": lookup failed (" + r.error + ")" }); continue; }
          if (r && !(r.txt || []).some((t) => /p=/i.test(t))) gone.push(sel);
        }
        if (gone.length) {
          findings.push(mkFinding({
            id: "dmr-live-dkim-" + P.domain, title: "DKIM selectors seen in reports are not published now",
            severity: "low", confidence: "likely", category: "dkim",
            description: "Selector(s) " + gone.join(", ") + " signed aligned mail for " + P.domain + " in the reports but <selector>._domainkey." + P.domain + " has no key now. If a sender still uses them, its mail will fail DKIM.",
            recommendation: "Confirm the selectors were rotated out on purpose; otherwise republish the keys from the sending service.",
            controls: [C.dkimD, C.m3], evidence: gone.map((s) => ({ selector: s, name: s + "._domainkey." + P.domain })),
            assets: [{ type: "DOMAIN", name: P.domain }],
          }));
        }
      }
    }
  }

  // ---- progression plan ----
  const plan = policyInfo.map((P) => buildPlan(P, srcsFor(P.domain), o));

  findings.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || cmp(a.category, b.category) || cmp(a.id, b.id));
  ctx?.progress?.(totalRecords, totalRecords, "done");

  const failing = messages - passMsgs;
  const unknown = sources.filter((s) => s.kind === "unknown");
  const primary = policyInfo.slice().sort((a, b) => srcsFor(b.domain).reduce((n, s) => n + s.messages, 0) - srcsFor(a.domain).reduce((n, s) => n + s.messages, 0) || cmp(a.domain, b.domain))[0];
  const allBegin = reports.map((r) => r.begin).filter((x) => x != null), allEnd = reports.map((r) => r.end).filter((x) => x != null);
  const summary = {
    reports: reports.length, duplicates: parsed.duplicates || 0, files: (parsed.files || []).length, forensic: (parsed.forensic || []).length,
    records: totalRecords, messages, pass: passMsgs, failing, dmarcPassPct: pct(passMsgs, messages),
    sources: sources.length, unknownSources: unknown.length, unknownFailing: unknown.reduce((n, s) => n + s.fail, 0),
    domains: domains.length, reporters: reporters.length,
    from: allBegin.length ? isoDay(Math.min(...allBegin)) : "", to: allEnd.length ? isoDay(Math.max(...allEnd)) : "",
    currentPolicy: primary ? "p=" + (primary.latest.p || "?") + (primary.latest.pct !== 100 ? " pct=" + primary.latest.pct : "") + (primary.latest.sp ? " sp=" + primary.latest.sp : "") : "",
    primaryDomain: primary ? primary.domain : "",
    findings: findings.length, bySeverity: countBy(findings, "severity"),
  };
  const forensic = (parsed.forensic || []).slice().sort((a, b) => cmp(a.file, b.file)).map((f) => ({ ...f }));
  const tables = {
    sources: sources.map(({ disp, key, ...s }) => ({ key, ...s })), senders, domains, daily, reporters, plan, fixes: fixes.sort((a, b) => cmp(a.sender, b.sender) || cmp(a.domain, b.domain)), forensic,
    selectorsSeen: sortedArr(selSeen).map((k) => ({ domain: k.split("|")[0], selector: k.split("|")[1] })),
    files: (parsed.files || []).map((f) => ({ ...f })),
  };
  return { summary, findings, tables, skipped, meta: { tool: TOOL_ID, version: VERSION, rows: totalRecords, pslSubset: PSL_SUBSET.length, espTable: ESP_TABLE.length, live: !!live, liveCheckedAt: live && live.checkedAt || "" } };
}

function buildPlan(P, list, o) {
  const cur = stageIndex(P.latest.p, P.latest.pct);
  const next = cur < STAGES.length - 1 ? cur + 1 : -1;
  const legit = list.filter((s) => s.kind === "esp" || s.kind === "authenticated");
  const lm = legit.reduce((n, s) => n + s.messages, 0), lp = legit.reduce((n, s) => n + s.pass, 0);
  const legitFail = lm - lp;
  const fwdFail = list.filter((s) => s.kind === "forwarder").reduce((n, s) => n + s.fail, 0);
  const unkFail = list.filter((s) => s.kind === "unknown").reduce((n, s) => n + s.fail, 0);
  const blockersM = new Map();
  for (const s of legit) {
    if (s.fail <= 0) continue;
    const k = s.classification;
    const b = blockersM.get(k) || { sender: k, kind: s.kind, failing: 0, sources: 0, domains: new Set() };
    b.failing += s.fail; b.sources++; b.domains.add(s.headerFrom);
    blockersM.set(k, b);
  }
  const blockers = [...blockersM.values()].filter((b) => b.failing >= o.senderMinMessages).map((b) => {
    const esp = ESP_TABLE.find((e) => e.name === b.sender);
    const d = sortedArr(b.domains)[0];
    return { sender: b.sender, kind: b.kind, failing: b.failing, sources: b.sources, domains: sortedArr(b.domains).join(", "), fix: esp ? esp.dkimFix.replace(/\{domain\}/g, d) : "Identify this sender (Look up sources shows PTR names) and sign its mail with DKIM d=" + d + "." };
  }).sort((a, b) => b.failing - a.failing || cmp(a.sender, b.sender));
  const rate = pct(lp, lm);
  const reasons = [];
  if (next < 0) reasons.push("Already at p=reject pct=100.");
  if (P.days < o.minObserveDays) reasons.push("Only " + P.days + " day(s) of reports at the current policy; wait for " + o.minObserveDays + ".");
  if (lm === 0) reasons.push("No legitimate-looking mail in the reports yet.");
  else if (rate < o.readyPassRate) reasons.push("Legitimate-looking mail passes DMARC at " + rate + "%, below " + o.readyPassRate + "%.");
  if (blockers.length) reasons.push(blockers.length + " sender(s) still fail DMARC (listed below).");
  const ready = next >= 0 && !reasons.length;
  const days = Math.max(1, P.coverageDays || 1);
  const nx = next >= 0 ? STAGES[next] : null;
  const share = nx ? nx.pct / 100 : 0;
  const est = nx ? {
    stage: nx.label, action: nx.p,
    legitimate: Math.round(legitFail * share), forwarded: Math.round(fwdFail * share), unknown: Math.round(unkFail * share),
    perDayLegitimate: Math.round((legitFail * share / days) * 10) / 10, perDayUnknown: Math.round((unkFail * share / days) * 10) / 10, windowDays: days,
  } : null;
  const notes = [];
  if (!P.latest.sp && list.some((s) => isSubdomainOf(s.headerFrom, P.domain))) notes.push("No sp= tag: subdomains inherit p. Set sp explicitly at the final stage (sp=reject for subdomains that never send).");
  if (P.latest.testing === "y") notes.push("t=y (DMARCbis testing) is published: receivers apply one level lower than p.");
  if (fwdFail) notes.push(fwdFail + " failing forwarded / mailing-list messages will also be affected; DKIM on every sender keeps most of them passing.");
  return {
    domain: P.domain, current: { p: P.latest.p || "none", pct: P.latest.pct, sp: P.latest.sp || "", label: STAGES[cur].label + (P.latest.p !== "none" && P.latest.pct !== STAGES[cur].pct ? " (published pct=" + P.latest.pct + ")" : ""), index: cur },
    daysAtCurrent: P.days, since: P.since, until: P.until, legitMessages: lm, legitPassPct: rate,
    next: nx ? { label: nx.label, index: next } : null, ready, reasons, blockers, estimate: est, notes,
    stages: STAGES.map((s, i) => ({ label: s.label, status: i < cur ? "done" : i === cur ? "current" : i === next ? (ready ? "next: ready" : "next: blocked") : "later" })),
  };
}

function countBy(items, key) {
  const out = {};
  for (const it of items) out[it[key]] = (out[it[key]] || 0) + 1;
  return out;
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
export const csvCell = (v) => {
  const s = Array.isArray(v) ? v.join("; ") : v && typeof v === "object" ? JSON.stringify(v) : String(v == null ? "" : v);
  const safe = /^[=+\-@\t\r]/.test(s) ? "'" + s : s;
  return /[",\n\r]/.test(safe) ? '"' + safe.replace(/"/g, '""') + '"' : safe;
};

const FINDING_COLS = ["id", "severity", "confidence", "category", "title", "description", "recommendation", "controls", "assets", "evidenceCount"];

/** Findings as CSV with fixed columns. */
export function findingsToCsv(findings) {
  const head = FINDING_COLS.join(",");
  const body = (findings || []).map((f) => [
    f.id, f.severity, f.confidence, f.category, f.title, f.description, f.recommendation,
    (f.controls || []).map((c) => c.framework + " " + c.id).join("; "), (f.assets || []).map((a) => a.type + ":" + a.name).join("; "),
    f.evidenceCount == null ? (f.evidence || []).length : f.evidenceCount,
  ].map(csvCell).join(","));
  return [head, ...body].join("\n") + "\n";
}

const SOURCE_COLS = ["ip", "ptr", "headerFrom", "messages", "pass", "fail", "dmarcPassPct", "dkimAlignedPct", "spfAlignedPct", "classification", "classifiedVia", "envelopeDomains", "dkimDomains", "selectors", "dispositions", "reporters", "first", "last"];
/** Sources table as CSV. */
export function sourcesToCsv(rows) {
  return [SOURCE_COLS.join(","), ...(rows || []).map((r) => SOURCE_COLS.map((c) => csvCell(r[c])).join(","))].join("\n") + "\n";
}

/** SPF / DKIM fix list (templates; values the user must fill in stay as <placeholders>). */
export function fixListText(r) {
  const out = ["DMARC Reports - SPF / DKIM fix list", "Generated from " + r.summary.reports + " aggregate reports (" + r.summary.from + " to " + r.summary.to + ").", "Placeholders in <angle brackets> are values the sending service gives you; never guess them.", ""];
  const fixes = r.tables.fixes || [];
  if (!fixes.length) out.push("No known sending service failed alignment.");
  for (const f of fixes) {
    out.push("== " + f.sender + " sending as " + f.domain + " (" + f.failing + " failing messages; DKIM aligned " + f.dkimAlignedPct + "%, SPF aligned " + f.spfAlignedPct + "%)");
    out.push("  DKIM (preferred, survives forwarding): " + f.dkim);
    out.push("  Return-path / SPF: " + f.spf);
    if (f.spfInclude) out.push("  SPF include for " + f.domain + " (only if MAIL FROM is on your domain): " + f.domain + ". TXT \"v=spf1 ... " + f.spfInclude + " ... -all\" (merge into the one existing SPF record; watch the 10-lookup limit)");
    out.push("");
  }
  const unk = (r.tables.plan || []).flatMap((p) => p.blockers.filter((b) => b.kind === "authenticated").map((b) => ({ ...b, domain: p.domain })));
  for (const b of unk) out.push("== " + b.sender + " (" + b.domains + "): " + b.fix, "");
  return out.join("\n") + "\n";
}

/** Progression plan as text. */
export function planText(r) {
  const out = ["DMARC Reports - progression plan to p=reject", "Deterministic rules: advance one stage when (1) at least the minimum observation days at the current stage, (2) legitimate-looking mail passes DMARC at or above the threshold, (3) no known or authenticated sender is still failing above the minimum message count.", ""];
  for (const p of r.tables.plan || []) {
    out.push("Domain: " + p.domain);
    out.push("  Current: " + p.current.label + (p.current.sp ? " sp=" + p.current.sp : "") + ", " + p.daysAtCurrent + " day(s) of reports (" + p.since + " to " + p.until + ")");
    out.push("  Legitimate-looking mail: " + p.legitMessages + " messages, " + p.legitPassPct + "% pass DMARC");
    out.push("  Stages:");
    for (const s of p.stages) out.push("    [" + s.status + "] " + s.label);
    if (p.next) out.push("  Next: " + p.next.label + " - " + (p.ready ? "READY" : "BLOCKED"));
    for (const x of p.reasons) out.push("    - " + x);
    if (p.estimate) out.push("  Estimated over the " + p.estimate.windowDays + "-day window at " + p.estimate.stage + ": " + p.estimate.legitimate + " legitimate-looking, " + p.estimate.forwarded + " forwarded and " + p.estimate.unknown + " unknown-source messages would get " + p.estimate.action + " (" + p.estimate.perDayLegitimate + " legitimate / " + p.estimate.perDayUnknown + " unknown per day).");
    if (p.blockers.length) { out.push("  Blocking senders:"); for (const b of p.blockers) out.push("    - " + b.sender + " (" + b.failing + " failing, " + b.domains + "): " + b.fix); }
    for (const n of p.notes) out.push("  Note: " + n);
    out.push("");
  }
  return out.join("\n") + "\n";
}

/** Short summary for the TXT export. */
export function summaryText(r) {
  const s = r.summary;
  const out = ["DMARC Reports summary", "Reports: " + s.reports + " (" + s.duplicates + " duplicates removed), files: " + s.files + ", forensic: " + s.forensic, "Window: " + s.from + " to " + s.to,
    "Messages: " + s.messages + ", DMARC pass " + s.dmarcPassPct + "%, failing " + s.failing, "Sources: " + s.sources + " (" + s.unknownSources + " unknown, " + s.unknownFailing + " failing messages from them)",
    "Current policy (" + s.primaryDomain + "): " + s.currentPolicy, "Findings: " + s.findings + " " + JSON.stringify(s.bySeverity), ""];
  for (const f of r.findings) out.push("- [" + f.severity + "/" + f.confidence + "] " + f.title + "\n    " + f.recommendation);
  if (r.skipped.length) { out.push("", "Skipped or limited checks:"); for (const k of r.skipped) out.push("- " + k.check + ": " + k.reason); }
  return out.join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// Synthetic example: 32 RUA reports for larkspur.test.darknode.ai.
// Documentation address space only (192.0.2.0/24, 198.51.100.0/24,
// 203.0.113.0/24, 2001:db8::/32). Fictional reporter organizations.
// ---------------------------------------------------------------------------
const xe = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

export function exampleDataset(seed = 7) {
  let st = seed >>> 0;
  const rnd = () => { st = (Math.imul(st, 1664525) + 1013904223) >>> 0; return st / 4294967296; };
  const ri = (a, b) => a + Math.floor(rnd() * (b - a + 1));
  const D = "larkspur.test.darknode.ai";
  const start = Date.UTC(2026, 8, 1) / 1000;
  const reporters = [
    { org: "Bluewren Mail", email: "noreply-dmarc@bluewren.test.darknode.ai", style: "google", ext: "zip" },
    { org: "Corvid Webmail", email: "dmarcreport@corvid.test.darknode.ai", style: "microsoft", ext: "gz" },
    { org: "Saltmarsh Mail", email: "dmarc-reports@saltmarsh.test.darknode.ai", style: "bis", ext: "gz" },
  ];
  const files = [];
  const pol = (style) => style === "bis"
    ? "<policy_published><domain>" + D + "</domain><p>none</p><adkim>r</adkim><aspf>r</aspf><discovery_method>treewalk</discovery_method><testing>n</testing></policy_published>"
    : "<policy_published><domain>" + D + "</domain><adkim>r</adkim><aspf>r</aspf><p>none</p>" + (style === "google" ? "<sp>none</sp>" : "") + "<pct>100</pct>" + (style === "microsoft" ? "<fo>1</fo>" : "") + "</policy_published>";
  const rec = (style, o) => {
    const dk = o.dkim.map((d) => "<dkim><domain>" + d.d + "</domain><selector>" + d.s + "</selector><result>" + d.r + "</result>" + (style === "google" ? "" : "") + "</dkim>").join("");
    const sp = o.spf.map((s) => "<spf><domain>" + s.d + "</domain>" + (style === "bis" ? "" : "<scope>mfrom</scope>") + "<result>" + s.r + "</result></spf>").join("");
    const reason = o.reason ? "<reason><type>" + o.reason + "</type></reason>" : "";
    return "<record><row><source_ip>" + o.ip + "</source_ip><count>" + o.n + "</count><policy_evaluated><disposition>none</disposition><dkim>" + o.ed + "</dkim><spf>" + o.es + "</spf>" + reason + "</policy_evaluated></row>" +
      "<identifiers>" + (style === "microsoft" ? "<envelope_to>" + o.to + "</envelope_to>" : "") + "<envelope_from>" + o.ef + "</envelope_from><header_from>" + (o.hf || D) + "</header_from></identifiers>" +
      "<auth_results>" + dk + sp + "</auth_results></record>";
  };
  for (let day = 0; day < 32; day++) {
    const R = reporters[day % 3];
    const b = start + day * DAY, e = b + DAY - 1;
    const rows = [];
    const to = R.org.split(" ")[0].toLowerCase() + ".test.darknode.ai";
    // Microsoft 365: aligned DKIM (d=your domain) plus tenant signature; SPF aligned
    for (const ip of ["192.0.2.10", "192.0.2.11"]) rows.push({ ip, n: ri(40, 90), dkim: [{ d: D, s: "selector1", r: "pass" }, { d: "larkspurtest.onmicrosoft.com", s: "selector1", r: "pass" }], spf: [{ d: D, r: "pass" }], ef: D, ed: "pass", es: R.style === "google" && day === 9 ? "fail" : "pass", to });
    // SendGrid: aligned DKIM via s1, return-path em subdomain (relaxed SPF alignment)
    rows.push({ ip: "192.0.2.40", n: ri(15, 35), dkim: [{ d: D, s: "s1", r: "pass" }, { d: "sendgrid.info", s: "smtpapi", r: "pass" }], spf: [{ d: "em4821." + D, r: "pass" }], ef: "em4821." + D, ed: "pass", es: "pass", to });
    // Mailchimp: signs with its own domain, its own return-path: not aligned
    if (day % 7 === 2 || day % 7 === 3) rows.push({ ip: "192.0.2.70", n: ri(60, 140), dkim: [{ d: "mcsv.net", s: "k1", r: "pass" }], spf: [{ d: "mail189.atl21.mcsv.net", r: "pass" }], ef: "mail189.atl21.mcsv.net", ed: "fail", es: "fail", to });
    // Forwarding: DKIM survives, SPF for our own envelope domain fails at the forwarder (IPv6)
    if (day % 2 === 0) rows.push({ ip: "2001:db8:4b::25", n: ri(2, 9), dkim: [{ d: D, s: "selector1", r: "pass" }], spf: [{ d: D, r: "softfail" }], ef: D, ed: "pass", es: "fail", to });
    // Mailing list (Google Groups style): list re-signs, original DKIM broken
    if (day % 5 === 1) rows.push({ ip: "192.0.2.150", n: ri(1, 6), dkim: [{ d: D, s: "selector1", r: "fail" }, { d: "googlegroups.com", s: "20230601", r: "pass" }], spf: [{ d: "googlegroups.com", r: "pass" }], ef: "googlegroups.com", ed: "fail", es: "fail", reason: R.style === "microsoft" ? "mailing_list" : "", to });
    // Spoofing: documentation ranges 198.51.100.0/24 and 203.0.113.0/24
    const bots = ["198.51.100.23", "198.51.100.57", "198.51.100.91", "198.51.100.144", "198.51.100.201", "203.0.113.8", "203.0.113.66", "203.0.113.120"];
    for (const ip of bots) if (rnd() < 0.55) rows.push({ ip, n: ri(1, 14), dkim: rnd() < 0.3 ? [{ d: D, s: "default", r: "fail" }] : [], spf: [{ d: D, r: rnd() < 0.5 ? "softfail" : "fail" }], ef: D, ed: "fail", es: "fail", to });
    // Subdomain spoofing, seen by the DMARCbis (tree-walk) reporter
    if (R.style === "bis") rows.push({ ip: "203.0.113.66", n: ri(8, 20), hf: "billing." + D, dkim: [], spf: [{ d: "billing." + D, r: "none" }], ef: "billing." + D, ed: "fail", es: "fail", to });
    const rid = R.style === "google" ? String(1770000000000000000n + BigInt(day) * 7919n) : R.style === "microsoft" ? "a1f3c2e0" + String(day).padStart(2, "0") + "b6d14c3e8f2a" + String(1000 + day) : "saltmarsh-" + D + "-" + isoDay(b);
    const meta = "<report_metadata><org_name>" + xe(R.org) + "</org_name><email>" + R.email + "</email>" + (R.style === "google" ? "<extra_contact_info>https://bluewren.test.darknode.ai/dmarc</extra_contact_info>" : "") + "<report_id>" + rid + "</report_id><date_range><begin>" + b + "</begin><end>" + e + "</end></date_range></report_metadata>";
    let xml;
    if (R.style === "google") xml = '<?xml version="1.0" encoding="UTF-8" ?>\n<feedback>\n  ' + meta + "\n  " + pol("google") + "\n  " + rows.map((x) => rec("google", x)).join("\n  ") + "\n</feedback>\n";
    else if (R.style === "microsoft") xml = '<?xml version="1.0"?>\n<feedback xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n  <version>1.0</version>\n  ' + meta + "\n  " + pol("microsoft") + "\n  " + rows.map((x) => rec("microsoft", x)).join("\n  ") + "\n</feedback>";
    else xml = '<?xml version="1.0" encoding="UTF-8"?>\n<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">\n  <version>1.0</version>\n  ' + meta + "\n  " + pol("bis") + "\n  " + rows.map((x) => rec("bis", x)).join("\n  ") + "\n</feedback>\n";
    const fname = R.style === "google" ? R.org.split(" ")[0].toLowerCase() + ".test.darknode.ai!" + D + "!" + b + "!" + e + ".xml"
      : R.style === "microsoft" ? R.org.split(" ")[0].toLowerCase() + ".test.darknode.ai!" + D + "!" + b + "!" + e + ".xml"
        : R.org.split(" ")[0].toLowerCase() + "!" + D + "!" + b + "!" + e + "!" + rid + ".xml";
    files.push({ name: fname, text: xml, pack: R.ext });
  }
  // A duplicate delivery of one Bluewren report (same report_id) under another name.
  files.push({ name: "resent-" + files[0].name, text: files[0].text, pack: "zip" });
  // One forensic (ARF) failure report.
  files.push({ name: "corvid-forensic-0001.eml", pack: "zip", text: [
    "From: dmarc-forensic@corvid.test.darknode.ai", "To: dmarc-ruf@" + D, "Subject: Report Domain: " + D + " Submitter: corvid.test.darknode.ai", "MIME-Version: 1.0",
    'Content-Type: multipart/report; report-type=feedback-report; boundary="b1"', "", "--b1", "Content-Type: text/plain", "", "This is an authentication failure report for an email message received from IP 198.51.100.57.", "",
    "--b1", "Content-Type: message/feedback-report", "", "Feedback-Type: auth-failure", "User-Agent: corvid-arf/1.0", "Version: 1", "Original-Mail-From: <billing@" + D + ">",
    "Arrival-Date: Thu, 10 Sep 2026 08:14:02 +0000", "Source-IP: 198.51.100.57", "Reported-Domain: " + D, "Authentication-Results: corvid.test.darknode.ai; dmarc=fail header.from=" + D + "; spf=softfail smtp.mailfrom=" + D,
    "Auth-Failure: dmarc", "Delivery-Result: delivered", "", "--b1", "Content-Type: text/rfc822-headers", "", "From: Accounts <billing@" + D + ">", "Subject: Overdue invoice", "", "--b1--", ""].join("\r\n") });
  return { label: "synthetic example (not real data)", domain: D, files };
}

/** Deterministic self-test over the synthetic example and crafted records. */
export function selfTest() {
  const tests = [];
  const t = (name, fn) => { let pass = false; try { pass = !!fn(); } catch (_) { pass = false; } tests.push({ name, pass }); };
  t("organizational domain uses the suffix subset", () => orgDomain("mail.shop.example.co.uk") === "example.co.uk" && orgDomain("a.b.test.darknode.ai") === "darknode.ai");
  t("relaxed vs strict alignment", () => aligned("em1.larkspur.test.darknode.ai", "larkspur.test.darknode.ai", "r") && !aligned("em1.larkspur.test.darknode.ai", "larkspur.test.darknode.ai", "s"));
  t("IPv6 canonical form", () => normIp("2001:0DB8:0000:0000:0000:0000:0000:0001") === "2001:db8::1");
  const ex = exampleDataset();
  const p = parseInput(ex.files);
  t("example parses 32 unique reports, 1 duplicate, 1 forensic", () => p.reports.length === 32 && p.duplicates === 1 && p.forensic.length === 1);
  const r = analyze(p, {});
  t("example finds Mailchimp misaligned", () => r.findings.some((f) => f.id === "dmr-esp-mailchimp"));
  t("example finds spoofing as high", () => r.findings.some((f) => f.id === "dmr-spoof-larkspur.test.darknode.ai" && f.severity === "high"));
  t("example plan is blocked by Mailchimp", () => r.tables.plan[0].ready === false && r.tables.plan[0].blockers.some((b) => /Mailchimp/.test(b.sender)));
  t("deterministic", () => JSON.stringify(analyze(p, {})) === JSON.stringify(r));
  t("empty input yields no findings", () => analyze([]).findings.length === 0);
  return { pass: tests.every((x) => x.pass), tests };
}
