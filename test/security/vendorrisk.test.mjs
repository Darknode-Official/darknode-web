// Third-Party Risk engine tests (public/js/risk/vendorrisk-engine.js): points table,
// inherent/residual maths, every finding positive + negative, posture grading from
// real dns.google / rdap.org / crt.sh response shapes, snapshot diffs and caps,
// register round-trip, ICS, CSV import mapping, determinism and selfTest.

import { test, assert, group } from "../harness.mjs";
import {
  TOOL_ID, DEFAULTS, DEFAULT_POLICY, selfTest, analyze, parseInput, exampleDataset, findingsToCsv, inherentRisk, assuranceCredit, gradeVendor,
  gradeDomain, postureScore, makeSnapshot, addSnapshot, diffSnapshots, normalizeRecord, validateRecord, addHistory, REGISTER_SCHEMA, icsEvents,
  csvToRecords, autoMap, dohAnswers, parseRdap, parseSecurityTxt, matchLeakRows, leakResponse, registrableGuess, nsProvider, daysUntil, addMonths,
  bandOf, registerToCsv, onePager, matchPayees, trendOf, compactRecord,
} from "../../public/js/risk/vendorrisk-engine.js";
import { openRegister } from "../../public/js/core/register.js";
import { toIcs } from "../../public/js/core/export.js";

const NOW = "2026-10-16T12:00:00Z";

// ---- fixtures: verbatim dns.google /resolve JSON shapes (captured 2026-10-16) ----
const GOOGLE_DMARC = { Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false, Question: [{ name: "_dmarc.google.com.", type: 16 }], Answer: [{ name: "_dmarc.google.com.", type: 16, TTL: 300, data: "v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com" }], Comment: "Response from 216.239.32.10." };
const GOOGLE_NS = { Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false, Question: [{ name: "google.com.", type: 2 }], Answer: [{ name: "google.com.", type: 2, TTL: 20111, data: "ns3.google.com." }, { name: "google.com.", type: 2, TTL: 20111, data: "ns1.google.com." }, { name: "google.com.", type: 2, TTL: 20111, data: "ns4.google.com." }, { name: "google.com.", type: 2, TTL: 20111, data: "ns2.google.com." }] };
const GOOGLE_CAA = { Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false, Question: [{ name: "google.com.", type: 257 }], Answer: [{ name: "google.com.", type: 257, TTL: 16980, data: "0 issue \"pki.goog\"" }] };
const CF_DS = { Status: 0, TC: false, RD: true, RA: true, AD: true, CD: false, Question: [{ name: "cloudflare.com.", type: 43 }], Answer: [{ name: "cloudflare.com.", type: 43, TTL: 5663, data: "2371 13 2 32996839A6D808AFE3EB4A795A0E6A7A39A76FC52FF228B22B76F6D63826F2B9" }] };
const GOOGLE_MTASTS = { Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false, Question: [{ name: "_mta-sts.google.com.", type: 16 }], Answer: [{ name: "_mta-sts.google.com.", type: 16, TTL: 300, data: "v=STSv1; id=20210803T010101;" }] };
const GOOGLE_TLSRPT = { Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false, Question: [{ name: "_smtp._tls.google.com.", type: 16 }], Answer: [{ name: "_smtp._tls.google.com.", type: 16, TTL: 300, data: "v=TLSRPTv1;rua=mailto:sts-reports@google.com" }] };
const GITHUB_MX = { Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false, Question: [{ name: "github.com.", type: 15 }], Answer: [{ name: "github.com.", type: 15, TTL: 3, data: "0 github-com.mail.protection.outlook.com." }] };
const NXDOMAIN = { Status: 3, TC: false, RD: true, RA: true, AD: false, CD: false, Question: [{ name: "nonexist-zz9.test.darknode.ai.", type: 16 }], Authority: [{ name: "darknode.ai.", type: 6, TTL: 1800, data: "curitiba.ns.porkbun.com. dns.cloudflare.com. 2416876861 10000 2400 604800 1800" }] };
const NOANS = (name, type) => ({ Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false, Question: [{ name: name + ".", type }] });
const TXT = (name, ...data) => ({ Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false, Question: [{ name: name + ".", type: 16 }], Answer: data.map((d) => ({ name: name + ".", type: 16, TTL: 300, data: d })) });
// Cloudflare's dns-query JSON quotes TXT data and splits long strings.
const CF_TXT_QUOTED = { Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false, Question: [{ name: "x.test.", type: 16 }], Answer: [{ name: "x.test", type: 16, TTL: 300, data: "\"v=spf1 include:_spf.x.test \" \"-all\"" }] };
// rdap.org (redirected to Verisign) for cloudflare.com, trimmed to the fields used.
const RDAP_CF = {
  objectClassName: "domain", ldhName: "CLOUDFLARE.COM", rdapConformance: ["rdap_level_0", "icann_rdap_response_profile_1"],
  status: ["client delete prohibited", "client transfer prohibited", "server delete prohibited"],
  events: [{ eventAction: "registration", eventDate: "2009-02-17T22:07:54Z" }, { eventAction: "expiration", eventDate: "2033-02-17T22:07:54Z" }, { eventAction: "last changed", eventDate: "2024-01-09T16:45:28Z" }, { eventAction: "last update of RDAP database", eventDate: "2026-10-17T05:32:41Z" }],
  entities: [{ objectClassName: "entity", roles: ["registrar"], vcardArray: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Cloudflare, Inc."]]], publicIds: [{ type: "IANA Registrar ID", identifier: "1910" }] }],
  secureDNS: { delegationSigned: true, dsData: [{ keyTag: 2371, algorithm: 13, digestType: 2, digest: "32996839A6D808AFE3EB4A795A0E6A7A39A76FC52FF228B22B76F6D63826F2B9" }] },
};
// crt.sh ?output=json row shape.
const CRT_ROW = (notAfter, names, issuer) => ({ issuer_ca_id: 295815, issuer_name: issuer || "C=US, O=Let's Encrypt, CN=R11", common_name: names.split("\n")[0], name_value: names, id: 1, entry_timestamp: "2026-08-01T00:00:00.000", not_before: "2026-08-01T00:00:00", not_after: notAfter, serial_number: "04ab" });
// ransomware.live /v2/searchvictims row shape.
const LEAK_ROW = { activity: "Manufacturing", attackdate: "2026-10-06T21:07:00+00:00", country: "US", discovered: "2026-10-07T05:08:14.160618+00:00", domain: "acmestamping.com", group: "incransom", url: "https://www.ransomware.live/id/x", victim: "acmestamping.com" };

const byCheck = (rs, c) => rs.find((r) => r.check === c);
const base = (o) => normalizeRecord({ id: "v1", legalName: "Testco Ltd", domains: ["testco.test.darknode.ai"], ...o });
const has = (g, idPart) => g.findings.some((f) => f.id.includes(idPart));

group("vendorrisk: points table and scores", () => {
  test("inherent risk uses the visible points table", () => {
    const r = base({ dataTier: "restricted", dataTypes: ["pii", "phi"], systemAccess: "admin", integrations: ["sso", "apikeys"], criticality: "critical", spof: true });
    const ir = inherentRisk(r, DEFAULT_POLICY);
    // base = 8 + min(3+4, 8) + 6 + (1+2) + 5 = 29; max = (8+8+6+8+5) * 2.5 = 87.5
    assert.equal(ir.base, 29); assert.equal(ir.multiplier, 2.5); assert.equal(ir.max, 87.5);
    assert.equal(ir.score, Math.round(29 * 2.5 / 87.5 * 100));
    assert.equal(ir.band, "critical");
  });
  test("data types are capped", () => {
    const r = base({ dataTypes: ["pii", "phi", "pci", "financial"], criticality: "low" });
    assert.equal(inherentRisk(r).parts.find((p) => p.factor === "Data types").points, 8);
  });
  test("editing the points table changes the score", () => {
    const r = base({ dataTier: "internal", criticality: "low" });
    const a = inherentRisk(r).score;
    const b = inherentRisk(r, { points: { dataTier: { internal: 20 } } }).score;
    assert.ok(b > a);
  });
  test("empty vendor scores zero", () => { assert.equal(inherentRisk(base({})).score, 0); });
  test("band thresholds", () => {
    assert.equal(bandOf(24), "low"); assert.equal(bandOf(25), "medium"); assert.equal(bandOf(50), "high"); assert.equal(bandOf(75), "critical");
    assert.equal(bandOf(30, { medium: 40, high: 60, critical: 80 }), "low");
  });
  test("assurance credit: current SOC 2 Type II, ISO, pentest, required DPA", () => {
    const r = base({ dataTypes: ["pii"], docs: [
      { id: "a", type: "soc2t2", periodEnd: "2026-06-30" }, { id: "b", type: "iso27001", expires: "2027-05-01" },
      { id: "c", type: "pentest", issued: "2026-03-01" }, { id: "d", type: "dpa", issued: "2024-01-01" }] });
    const c = assuranceCredit(r, DEFAULT_POLICY, NOW);
    assert.equal(c.pct, 25 + 20 + 10 + 5);
  });
  test("assurance credit is capped and stale pentest earns nothing", () => {
    const r = base({ docs: [{ id: "p", type: "pentest", issued: "2025-01-01" }] });
    assert.equal(assuranceCredit(r, DEFAULT_POLICY, NOW).pct, 0);
    const c = assuranceCredit(base({ dataTypes: ["pii"], docs: [{ id: "a", type: "soc2t2", periodEnd: "2026-06-30" }, { id: "b", type: "iso27001", expires: "2027-05-01" }, { id: "d", type: "dpa" }] }), { credit: { cap: 30 } }, NOW);
    assert.equal(c.pct, 30); assert.equal(c.uncapped, 50);
  });
  test("questionnaire credit scales with the entered score", () => {
    const r = base({ questionnaireScore: 50, docs: [{ id: "q", type: "questionnaire", issued: "2026-09-01" }] });
    assert.equal(assuranceCredit(r, DEFAULT_POLICY, NOW).pct, 2.5);
  });
  test("residual = inherent x (1 - credit) + posture adjustment", () => {
    const r = base({ dataTier: "restricted", systemAccess: "admin", criticality: "high", docs: [{ id: "b", type: "iso27001", expires: "2027-05-01" }] });
    const g = gradeVendor(r, [{ domain: "testco.test.darknode.ai", check: "spf", status: "fail" }], DEFAULT_POLICY, { now: NOW });
    assert.equal(g.posture.grade, "F");
    assert.equal(g.residual.score, Math.round(g.inherent.score * 0.8 + 10));
  });
});

group("vendorrisk: posture grading from fixture responses", () => {
  test("dohAnswers decodes dns.google and quoted cloudflare TXT", () => {
    assert.deepEqual(dohAnswers(GOOGLE_DMARC, "TXT"), ["v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com"]);
    assert.deepEqual(dohAnswers(CF_TXT_QUOTED, "TXT"), ["v=spf1 include:_spf.x.test -all"]);
  });
  test("SPF -all passes, +all fails, ?all warns, missing fails", () => {
    const g = (t) => byCheck(gradeDomain({ domain: "x.test", txt: TXT("x.test", t) }, { now: NOW }), "spf");
    assert.equal(g("v=spf1 include:_spf.google.com -all").status, "pass");
    assert.equal(g("v=spf1 +all").status, "fail");
    assert.ok(/\+all/.test(g("v=spf1 +all").evidence));
    assert.equal(g("v=spf1 a mx ?all").status, "warn");
    assert.equal(g("google-site-verification=abc").status, "fail");
  });
  test("SPF over 10 lookups fails", () => {
    const rec = "v=spf1 " + Array.from({ length: 11 }, (_, i) => "include:s" + i + ".x.test").join(" ") + " -all";
    assert.ok(/More than 10/.test(byCheck(gradeDomain({ domain: "x.test", txt: TXT("x.test", rec) }, { now: NOW }), "spf").evidence));
  });
  test("DMARC reject passes, p=none warns, pct<100 warns, missing fails", () => {
    const g = (resp) => byCheck(gradeDomain({ domain: "google.com", dmarc: resp }, { now: NOW }), "dmarc");
    assert.equal(g(GOOGLE_DMARC).status, "pass");
    assert.equal(g(TXT("_dmarc.x", "v=DMARC1; p=none")).status, "warn");
    assert.equal(g(TXT("_dmarc.x", "v=DMARC1; p=quarantine; pct=50")).status, "warn");
    assert.equal(g(NXDOMAIN).status, "fail");
  });
  test("MTA-STS: enforce policy passes, testing warns, no TXT warns, policy fetch error is error", () => {
    const g = (pol) => byCheck(gradeDomain({ domain: "google.com", mtasts: GOOGLE_MTASTS, mtastsPolicy: pol }, { now: NOW }), "mtasts");
    assert.equal(g({ status: 200, body: "version: STSv1\nmode: enforce\nmx: smtp.google.com\nmax_age: 86400\n" }).status, "pass");
    assert.equal(g({ status: 200, body: "version: STSv1\nmode: testing\nmax_age: 86400\n" }).status, "warn");
    assert.equal(g({ error: "timeout" }).status, "error");
    assert.equal(g({ status: 404, body: "" }).status, "fail");
    assert.equal(byCheck(gradeDomain({ domain: "x", mtasts: NXDOMAIN }, { now: NOW }), "mtasts").status, "warn");
  });
  test("TLS-RPT, CAA and DNSSEC from real shapes", () => {
    const rs = gradeDomain({ domain: "google.com", tlsrpt: GOOGLE_TLSRPT, caa: GOOGLE_CAA, ds: CF_DS }, { now: NOW });
    assert.equal(byCheck(rs, "tlsrpt").status, "pass");
    assert.equal(byCheck(rs, "caa").status, "pass");
    assert.equal(byCheck(rs, "dnssec").status, "pass");
    assert.ok(/AD flag set/.test(byCheck(rs, "dnssec").evidence));
    const rs2 = gradeDomain({ domain: "x", caa: NOANS("x", 257), ds: NOANS("x", 43) }, { now: NOW });
    assert.equal(byCheck(rs2, "caa").status, "warn"); assert.equal(byCheck(rs2, "dnssec").status, "warn");
  });
  test("NS diversity: one provider warns, single NS fails", () => {
    assert.equal(byCheck(gradeDomain({ domain: "google.com", ns: GOOGLE_NS }, { now: NOW }), "ns").status, "warn");
    const one = { ...GOOGLE_NS, Answer: [GOOGLE_NS.Answer[0]] };
    assert.equal(byCheck(gradeDomain({ domain: "google.com", ns: one }, { now: NOW }), "ns").status, "fail");
    const two = { ...GOOGLE_NS, Answer: [{ ...GOOGLE_NS.Answer[0] }, { ...GOOGLE_NS.Answer[1], data: "ns1.otherdns.net." }] };
    assert.equal(byCheck(gradeDomain({ domain: "google.com", ns: two }, { now: NOW }), "ns").status, "pass");
    assert.equal(nsProvider("NS3.CLOUDFLARE.COM."), "cloudflare.com");
  });
  test("MX info and DKIM skipped with a reason", () => {
    const rs = gradeDomain({ domain: "github.com", mx: GITHUB_MX }, { now: NOW });
    assert.equal(byCheck(rs, "mx").status, "info");
    assert.ok(/selector/.test(byCheck(rs, "dkim").evidence));
    assert.equal(byCheck(rs, "dkim").status, "skip");
  });
  test("network errors and SERVFAIL become error, never pass/fail", () => {
    const rs = gradeDomain({ domain: "x", txt: { error: "timeout" }, dmarc: { ...NXDOMAIN, Status: 2 }, https: { error: "proxy down" }, rdap: { error: "HTTP 503" }, cert: { error: "x" } }, { now: NOW });
    for (const c of ["spf", "dmarc", "https", "hsts", "headers", "rdap", "cert"]) assert.equal(byCheck(rs, c).status, "error", c);
    assert.equal(postureScore(rs).score, null);
  });
  test("RDAP fixture: expiry, registrar, warning windows", () => {
    const p = parseRdap(RDAP_CF);
    assert.equal(p.expires, "2033-02-17T22:07:54Z"); assert.equal(p.registrar, "Cloudflare, Inc."); assert.ok(p.dnssec);
    assert.equal(byCheck(gradeDomain({ domain: "cloudflare.com", rdap: { json: RDAP_CF } }, { now: NOW }), "rdap").status, "pass");
    const soon = { ...RDAP_CF, events: [{ eventAction: "expiration", eventDate: "2026-11-01T00:00:00Z" }] };
    assert.equal(byCheck(gradeDomain({ domain: "cloudflare.com", rdap: { json: soon } }, { now: NOW }), "rdap").status, "fail");
    const mid = { ...RDAP_CF, events: [{ eventAction: "expiration", eventDate: "2026-12-01T00:00:00Z" }] };
    assert.equal(byCheck(gradeDomain({ domain: "cloudflare.com", rdap: { json: mid } }, { now: NOW }), "rdap").status, "warn");
  });
  test("CT fixture: newest certificate days left, wildcard, expiring warns", () => {
    const rows = [CRT_ROW("2026-10-25T00:00:00", "*.x.test\nx.test"), CRT_ROW("2026-01-01T00:00:00", "x.test")];
    const c = byCheck(gradeDomain({ domain: "x.test", cert: { rows } }, { now: NOW }), "cert");
    assert.equal(c.status, "warn"); assert.ok(/wildcard/.test(c.evidence)); assert.ok(/Let's Encrypt/.test(c.evidence));
    assert.equal(byCheck(gradeDomain({ domain: "x.test", cert: { rows: [CRT_ROW("2027-03-01T00:00:00", "x.test")] } }, { now: NOW }), "cert").status, "pass");
    assert.equal(byCheck(gradeDomain({ domain: "x.test", cert: { rows: [] } }, { now: NOW }), "cert").status, "error");
  });
  test("HTTPS, HSTS and headers via posture-engine graders", () => {
    const good = { "strict-transport-security": "max-age=31536000", "content-security-policy": "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "permissions-policy": "camera=()", "cross-origin-opener-policy": "same-origin", "cross-origin-embedder-policy": "require-corp", "cross-origin-resource-policy": "same-origin" };
    const rs = gradeDomain({ domain: "x.test", https: { status: 200, headers: good, finalUrl: "https://x.test/" }, http: { status: 200, finalUrl: "https://x.test/" } }, { now: NOW });
    assert.equal(byCheck(rs, "https").status, "pass"); assert.equal(byCheck(rs, "hsts").status, "pass"); assert.equal(byCheck(rs, "headers").status, "pass");
    const bad = gradeDomain({ domain: "x.test", https: { status: 200, headers: {} }, http: { status: 200, finalUrl: "http://x.test/" } }, { now: NOW });
    assert.equal(byCheck(bad, "https").status, "fail"); assert.equal(byCheck(bad, "hsts").status, "fail"); assert.equal(byCheck(bad, "headers").status, "fail");
  });
  test("security.txt: RFC 9116 Expires parsing", () => {
    const g = (st) => byCheck(gradeDomain({ domain: "x", securityTxt: st }, { now: NOW }), "securitytxt");
    assert.equal(g({ status: 200, body: "Contact: mailto:sec@x.test\nExpires: 2027-01-01T00:00:00Z\n" }).status, "pass");
    assert.ok(/Expired/.test(g({ status: 200, body: "Contact: mailto:sec@x.test\nExpires: 2025-01-01T00:00:00Z\n" }).evidence));
    assert.ok(/no Expires/.test(g({ status: 200, body: "Contact: mailto:sec@x.test\n" }).evidence));
    assert.equal(g({ status: 404, body: "" }).status, "warn");
    assert.equal(g({ status: 200, body: "<!doctype html><html><script>var o={contact: 1}</script></html>" }).status, "warn", "an HTML page served for every path is not a security.txt");
    assert.equal(g({ status: 200, body: "# policy\nsee contact: below\n" }).status, "warn", "Contact must start a line");
    assert.deepEqual(parseSecurityTxt("Contact: a\ncontact: b\nExpires: z").contact, ["a", "b"]);
  });
  test("leak tracker: exact match vs unrelated substring hits; 404 body = zero rows; rate limit = error", () => {
    const m = matchLeakRows([LEAK_ROW, { ...LEAK_ROW, victim: "Jacmel Enterprise Inc.", domain: "jacmel.test" }], { domains: ["acmestamping.com"] });
    assert.equal(m.exact.length, 1); assert.equal(m.possible.length, 1);
    assert.equal(byCheck(gradeDomain({ domain: "acmestamping.com", leak: { rows: [LEAK_ROW], keyword: "acmestamping.com" } }, { now: NOW }), "leak").status, "fail");
    assert.equal(byCheck(gradeDomain({ domain: "other.test", leak: { rows: [LEAK_ROW], keyword: "other.test" } }, { now: NOW }), "leak").status, "info");
    assert.deepEqual(leakResponse({ error: "No victims found for keyword 'zz'." }, "zz"), { rows: [], keyword: "zz" });
    assert.ok(leakResponse({ message: "1 per 1 minute" }, "zz").error.includes("rate limited"));
  });
  test("leak status is excluded from the grade", () => {
    const rs = [{ domain: "a", check: "spf", status: "pass" }, { domain: "a", check: "leak", status: "fail" }];
    assert.equal(postureScore(rs).grade, "A");
  });
  test("a status or check named like an Object member does not turn the grade into NaN", () => {
    for (const k of ["constructor", "toString", "__proto__"]) {
      const p = postureScore([{ domain: "a", check: "spf", status: k }, { domain: "a", check: k, status: "fail" }, { domain: "a", check: "dmarc", status: "pass" }]);
      assert.equal(p.score, 100, k);
      assert.equal(p.domains[0].counts[k], 1, k);
    }
  });
  test("registrable domain guess", () => {
    assert.equal(registrableGuess("pay.quillcard.test.darknode.ai"), "darknode.ai");
    assert.equal(registrableGuess("a.b.example.co.uk"), "example.co.uk");
    assert.equal(registrableGuess("https://www.Vendor.com/x"), "vendor.com");
  });
});

group("vendorrisk: findings positive and negative", () => {
  const G = (o, results) => gradeVendor(base(o), results || null, DEFAULT_POLICY, { now: NOW });
  test("document expired (high) / expiring within 60 days (medium) / far future silent", () => {
    assert.equal(G({ docs: [{ id: "i", type: "insurance", expires: "2026-10-01" }] }).findings.find((f) => f.id.includes("doc-i")).severity, "high");
    assert.equal(G({ docs: [{ id: "i", type: "insurance", expires: "2026-11-30" }] }).findings.find((f) => f.id.includes("doc-i")).severity, "medium");
    assert.ok(!has(G({ docs: [{ id: "i", type: "insurance", expires: "2027-06-01" }] }), "doc-i"));
  });
  test("SOC 2 stale without bridge letter fires; bridge letter silences it", () => {
    assert.ok(has(G({ docs: [{ id: "s", type: "soc2t2", periodEnd: "2025-06-30" }] }), "soc-stale"));
    assert.ok(!has(G({ docs: [{ id: "s", type: "soc2t2", periodEnd: "2025-06-30" }, { id: "b", type: "bridge", issued: "2026-01-15", expires: "2026-12-31" }] }), "soc-stale"));
    assert.ok(!has(G({ docs: [{ id: "s", type: "soc2t2", periodEnd: "2026-03-31" }] }), "soc-stale"));
  });
  test("exceptions noted -> review confidence; none -> silent", () => {
    const f = G({ docs: [{ id: "s", type: "soc2t2", periodEnd: "2026-03-31", exceptions: true, exceptionsText: "CC6.2" }] }).findings.find((x) => x.id.includes("exc-s"));
    assert.equal(f.confidence, "review");
    assert.ok(!has(G({ docs: [{ id: "s", type: "soc2t2", periodEnd: "2026-03-31" }] }), "exc-"));
  });
  test("missing DPA with PII, BAA with PHI, AOC with PCI (high); present silences", () => {
    const g = G({ dataTypes: ["pii", "phi", "pci"] });
    for (const k of ["missing-dpa", "missing-baa", "missing-pciaoc"]) assert.equal(g.findings.find((f) => f.id.includes(k)).severity, "high", k);
    const ok = G({ dataTypes: ["pii", "phi", "pci"], docs: [{ id: "1", type: "dpa" }, { id: "2", type: "baa" }, { id: "3", type: "pciaoc", expires: "2027-01-01" }] });
    assert.ok(!has(ok, "missing-"));
    assert.ok(!has(G({ dataTypes: ["source"] }), "missing-"));
  });
  test("review overdue by policy; within policy silent; never reviewed fires", () => {
    assert.ok(has(G({ criticality: "critical", lastReview: "2025-09-01" }), "review-overdue"));
    assert.ok(!has(G({ criticality: "low", lastReview: "2025-09-01" }), "review-overdue"));
    assert.ok(has(G({ criticality: "medium" }), "review-none"));
    assert.ok(!has(gradeVendor(base({ criticality: "critical", lastReview: "2025-09-01" }), null, { reviewMonths: { critical: 24 } }, { now: NOW }), "review-overdue"));
  });
  test("critical vendor without exit plan (low); with exit plan silent", () => {
    assert.equal(G({ criticality: "critical" }).findings.find((f) => f.id.includes("exit")).severity, "low");
    assert.ok(!has(G({ criticality: "critical", exitPlan: "dual vendor" }), "-exit-"));
  });
  test("renewal in notice window: info, medium when residual high; outside silent", () => {
    const f = G({ renewal: "2026-11-20", noticeDays: 60 }).findings.find((x) => x.id.includes("renewal"));
    assert.equal(f.severity, "info");
    const hi = G({ renewal: "2026-11-20", noticeDays: 60, dataTier: "restricted", dataTypes: ["pii", "phi"], systemAccess: "admin", integrations: ["agent", "apikeys"], criticality: "critical", spof: true, docs: [{ id: "1", type: "dpa" }, { id: "2", type: "baa" }] });
    assert.equal(hi.findings.find((x) => x.id.includes("renewal")).severity, "medium");
    assert.ok(!has(G({ renewal: "2027-09-01", noticeDays: 30 }), "renewal"));
  });
  test("DMARC missing or p=none only for vendors that email you", () => {
    const res = [{ domain: "testco.test.darknode.ai", check: "dmarc", status: "warn", evidence: "Monitoring only: p=none" }];
    assert.ok(has(G({ sendsMail: true }, res), "dmarc-"));
    assert.ok(!has(G({ sendsMail: false }, res), "dmarc-"));
    assert.ok(!has(G({ sendsMail: true }, [{ domain: "testco.test.darknode.ai", check: "dmarc", status: "pass", evidence: "p=reject" }]), "dmarc-"));
  });
  test("SPF +all (high); ~all silent", () => {
    assert.equal(G({}, [{ domain: "d", check: "spf", status: "fail", evidence: "+all lets any host send" }]).findings[0].severity, "high");
    assert.ok(!has(G({}, [{ domain: "d", check: "spf", status: "warn", evidence: "~all (softfail)" }]), "spf-all"));
  });
  test("cert < 14 days (medium), domain < 30 days (high), security.txt (info); passes silent", () => {
    const g = G({}, [{ domain: "d", check: "cert", status: "warn", evidence: "9 days" }, { domain: "d", check: "rdap", status: "fail", evidence: "expires" }, { domain: "d", check: "securitytxt", status: "warn", evidence: "No /.well-known/security.txt with a Contact field (HTTP 404)" }]);
    assert.equal(g.findings.find((f) => f.id.includes("cert-")).severity, "medium");
    assert.equal(g.findings.find((f) => f.id.includes("domain-exp")).severity, "high");
    assert.equal(g.findings.find((f) => f.id.includes("sectxt")).severity, "info");
    assert.equal(G({}, [{ domain: "d", check: "cert", status: "pass" }, { domain: "d", check: "rdap", status: "pass" }, { domain: "d", check: "securitytxt", status: "pass" }]).findings.length, 0);
  });
  test("findings carry VENDOR and DOMAIN assets and >=1 control", () => {
    const g = G({ sendsMail: true }, [{ domain: "d.test", check: "dmarc", status: "fail", evidence: "No v=DMARC1" }]);
    const f = g.findings[0];
    assert.deepEqual(f.assets.map((a) => a.type), ["VENDOR", "DOMAIN"]);
    assert.equal(f.assets[0].data.legalName, "Testco Ltd");
    assert.ok(f.controls.length >= 1 && f.controls.every((c) => c.framework && c.id));
    assert.equal(f.evidenceCount, 1);
  });
  test("a check that errored holds the finding it raised last time, so it is not offered as fixed", () => {
    const was = G({ sendsMail: true }, [{ domain: "d.test", check: "leak", status: "fail", evidence: "listed" }, { domain: "d.test", check: "dmarc", status: "fail", evidence: "No v=DMARC1" }]);
    const now = G({ sendsMail: true }, [{ domain: "d.test", check: "leak", status: "error", evidence: "rate limited" }, { domain: "d.test", check: "dmarc", status: "error", evidence: "timeout" }]);
    assert.equal(now.findings.length, was.findings.length - 2);
    for (const f of was.findings.filter((x) => /-(leak|dmarc)-/.test(x.id))) assert.ok(now.held.includes(f.id), f.id);
    assert.deepEqual(was.held, [], "checks that answered hold nothing");
  });
});

group("vendorrisk: snapshots and diffs", () => {
  const S = (at, list) => makeSnapshot(list.map(([check, status]) => ({ domain: "d", check, status, evidence: check + " " + status })), at);
  test("diff reports new failures, fixed items, unreachable and grade change", () => {
    const a = S("2026-09-01T00:00:00Z", [["spf", "pass"], ["dmarc", "fail"], ["caa", "pass"], ["ns", "pass"]]);
    const b = S("2026-10-01T00:00:00Z", [["spf", "fail"], ["dmarc", "pass"], ["caa", "error"], ["ns", "warn"]]);
    const d = diffSnapshots(a, b);
    assert.deepEqual(d.newFailures.map((x) => x.check), ["spf"]);
    assert.deepEqual(d.fixed.map((x) => x.check), ["dmarc"]);
    assert.deepEqual(d.unreachable.map((x) => x.check), ["caa"]);
    assert.deepEqual(d.worsened.map((x) => x.check), ["ns"]);
  });
  test("grade drop >= 1 letter fires; same grade silent", () => {
    const good = S("2026-09-01T00:00:00Z", [["spf", "pass"], ["dmarc", "pass"]]);
    const bad = S("2026-10-01T00:00:00Z", [["spf", "fail"], ["dmarc", "pass"]]);
    assert.ok(has(gradeVendor(base({ posture: [good, bad] }), null, DEFAULT_POLICY, { now: NOW }), "grade-drop"));
    assert.ok(!has(gradeVendor(base({ posture: [good, { ...good, at: "2026-10-01T00:00:00Z" }] }), null, DEFAULT_POLICY, { now: NOW }), "grade-drop"));
    assert.equal(trendOf(base({ posture: [good, bad] })), "down");
  });
  test("snapshot cap keeps the last 12", () => {
    let r = base({});
    for (let i = 0; i < 15; i++) r = addSnapshot(r, S("2026-0" + (1 + (i % 9)) + "-" + String(10 + i).padStart(2, "0") + "T00:00:00Z", [["spf", "pass"]]));
    assert.equal(r.posture.length, 12);
    assert.ok(r.posture[0].at <= r.posture[11].at);
  });
  test("compaction keeps the record under the size limit and the newest two intact", () => {
    const big = (at) => makeSnapshot(Array.from({ length: 10 }, (_, d) => ["spf", "dmarc", "caa", "ns", "cert", "rdap"].map((c) => ({ domain: "dom" + d + ".test", check: c, status: "pass", evidence: "x".repeat(300) }))).flat(), at);
    let r = base({});
    for (let i = 0; i < 12; i++) r = addSnapshot(r, big("2026-01-" + String(10 + i).padStart(2, "0") + "T00:00:00Z"));
    assert.ok(JSON.stringify(r).length <= 36000, "size " + JSON.stringify(r).length);
    assert.equal(r.posture[11].results.length, 60);
    assert.equal(r.posture[0].compacted, "results");
    assert.equal(compactRecord({ a: 1 }).a, 1);
  });
  test("history cap 50", () => {
    let r = base({});
    for (let i = 0; i < 60; i++) r = addHistory(r, "2026-01-01T00:00:00Z", "edit " + i);
    assert.equal(r.history.length, 50); assert.equal(r.history[49].what, "edit 59");
  });
});

group("vendorrisk: dates, register, import, exports", () => {
  test("date maths with explicit now", () => {
    assert.equal(daysUntil("2026-10-26", NOW), 10);
    assert.equal(daysUntil("2026-10-01", NOW), -15);
    assert.equal(addMonths("2026-01-31", 1), "2026-02-28");
    assert.equal(addMonths("2025-10-16", 12), "2026-10-16");
    assert.equal(daysUntil("not a date", NOW), null);
  });
  test("a date counts in calendar days: a document expiring today is not yet expired", () => {
    // NOW is midday; expiring today used to read as "expired 1 days ago" and tomorrow as "in 0 days".
    assert.equal(daysUntil("2026-10-16", NOW), 0);
    assert.equal(daysUntil("2026-10-17", NOW), 1);
    const g = gradeVendor(normalizeRecord({ id: "v1", legalName: "Vendor X", dataTypes: "pii", docs: [{ id: "d1", type: "dpa", expires: "2026-10-16" }], renewal: "2026-11-15", noticeDays: 30 }), [], {}, { now: NOW });
    const ids = g.findings.map((f) => f.id);
    assert.ok(!ids.includes("tpr-missing-dpa-v1"), "a DPA expiring today is still on file");
    const doc = g.findings.find((f) => f.id === "tpr-doc-d1-v1");
    assert.equal(doc.title, "Assurance document expiring soon");
    assert.ok(g.findings.find((f) => f.id === "tpr-renewal-v1").description.includes("is due by 2026-10-16 (in 0 days)"));
  });
  test("register round-trip with Map storage and a fake graph mirrors VENDOR fields", () => {
    const m = new Map();
    const storage = { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) };
    const E = {}; let n = 0;
    const graph = { create: (type, name, data, o) => { const e = { id: "g" + (++n), type, name, data, source: o.source, severity: o.severity }; E[e.id] = e; return e; }, update: (id, u) => Object.assign(E[id], u), remove: (id) => delete E[id], list: (t) => Object.values(E).filter((e) => e.type === t), get: (id) => E[id] || null };
    const reg = openRegister(TOOL_ID, "VENDOR", { schema: REGISTER_SCHEMA, storage, graph, now: () => NOW });
    const rec = exampleDataset(7, NOW).records[0];
    const saved = reg.upsert(rec);
    const e = E[saved.graphId];
    assert.equal(e.type, "VENDOR"); assert.equal(e.name, "Vendor A Payroll Ltd"); assert.equal(e.severity, "critical");
    assert.equal(e.data.legalName, "Vendor A Payroll Ltd"); assert.equal(e.data.domain, "vendor-a.test.darknode.ai"); assert.equal(e.data.tier, "critical");
    assert.deepEqual(e.data._full.posture.length, 2);
    storage.setItem("dn_active_ws", "ws1");
    const team = openRegister(TOOL_ID, "VENDOR", { schema: REGISTER_SCHEMA, storage, graph, now: () => NOW });
    assert.equal(team.list()[0].legalName, "Vendor A Payroll Ltd");
    const back = JSON.parse(reg.exportJson());
    assert.equal(back[0].docs.length, rec.docs.length);
  });
  test("validateRecord", () => {
    assert.equal(validateRecord({ legalName: "", domains: [] }).length, 1);
    assert.ok(validateRecord({ legalName: "A", domains: ["not a domain"] }).some((e) => /Not a valid/.test(e)));
    assert.equal(validateRecord({ legalName: "A", domains: ["a.test.darknode.ai"], renewal: "2026-01-01" }).length, 0);
  });
  test("CSV import: auto mapping, enum normalisation, invalid domains reported", () => {
    const csv = "Vendor Name,Website,Tier,Data Classification,Data Shared,Access,Renewal Date,Notice Days\n" +
      "Acme Widgets Ltd,https://www.acmewidgets.test/,Critical,Restricted,\"PII; Card\",Read-only,3/15/2027,60\n" +
      ",nope.test,low,,,,,\n" +
      "Bad Domain Co,not_a_domain,low,internal,,none,,\n";
    const p = parseInput([{ name: "vendors.csv", text: csv }]);
    assert.equal(p.format, "vendor-csv"); assert.equal(p.confidence, "high");
    assert.equal(p.mapping.legalName, "Vendor Name"); assert.equal(p.mapping.domains, "Website"); assert.equal(p.mapping.criticality, "Tier");
    const { records, skipped } = csvToRecords(p.rows, p.mapping);
    assert.equal(records.length, 2);
    const a = records[0];
    assert.deepEqual(a.domains, ["acmewidgets.test"]); assert.equal(a.criticality, "critical"); assert.equal(a.dataTier, "restricted");
    assert.deepEqual(a.dataTypes, ["pci", "pii"]); assert.equal(a.systemAccess, "read"); assert.equal(a.renewal, "2027-03-15"); assert.equal(a.noticeDays, 60);
    assert.ok(skipped.some((s) => /no legal name/.test(s.reason))); assert.ok(skipped.some((s) => /invalid domain/.test(s.reason)));
  });
  test("CSV without a name column is low confidence and reported", () => {
    const p = parseInput("foo,bar\n1,2\n");
    assert.equal(autoMap(p.headers).confidence, "low");
    assert.ok(p.skipped.some((s) => s.check === "csv-import"));
  });
  test("register JSON import is detected", () => {
    const p = parseInput([{ name: "reg.json", text: JSON.stringify(exampleDataset(7, NOW).records) }]);
    assert.equal(p.format, "vendorrisk-register"); assert.equal(p.records.length, 8);
  });
  test("ICS: renewal, notice deadline, review and doc expiries; valid VCALENDAR", () => {
    const r = base({ renewal: "2027-03-01", noticeDays: 30, criticality: "high", lastReview: "2026-01-10", docs: [{ id: "i", type: "iso27001", expires: "2027-02-01" }] });
    const ev = icsEvents([r], { now: NOW });
    assert.deepEqual(ev.map((e) => e.start), ["2027-01-10", "2027-01-30", "2027-02-01", "2027-03-01"]);
    const ics = toIcs(ev);
    assert.ok(ics.startsWith("BEGIN:VCALENDAR")); assert.ok(ics.includes("DTSTART;VALUE=DATE:20270130")); assert.ok(ics.includes("UID:v1-notice@darknode.ai"));
  });
  test("register CSV, one-pager and payee matching", () => {
    const ex = exampleDataset(7, NOW);
    const r = analyze(ex, { now: NOW });
    const csv = registerToCsv(ex.records, r.tables.graded);
    assert.ok(csv.split("\r\n")[0].startsWith("ID,Legal name,Domains"));
    assert.ok(csv.includes("Vendor A Payroll Ltd"));
    const g = r.tables.graded.find((x) => x.id === "ex-vendor-a");
    const txt = onePager(ex.records.find((x) => x.id === "ex-vendor-a"), g);
    assert.ok(txt.includes("Residual risk:")); assert.ok(txt.includes("FINDINGS ("));
    assert.deepEqual(matchPayees("LedgerLoop Payroll Ltd.", [{ source: "payee", id: "1", name: "Ledgerloop Payroll" }, { source: "graph", id: "2", name: "Other" }]).map((c) => c.id), ["1"]);
  });
});

group("vendorrisk: analyze, determinism, selfTest", () => {
  test("in-engine self-test passes", () => {
    const r = selfTest();
    assert.ok(r.pass, "failed: " + r.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });
  test("analyze is deterministic (byte-identical JSON)", () => {
    const ex = exampleDataset(7, NOW);
    assert.equal(JSON.stringify(analyze(ex, { now: NOW })), JSON.stringify(analyze(ex, { now: NOW })));
    assert.equal(JSON.stringify(exampleDataset(7, NOW)), JSON.stringify(exampleDataset(7, NOW)));
  });
  test("example: 8 vendors on test.darknode.ai, precomputed posture, grid sums", () => {
    const ex = exampleDataset(7, NOW);
    assert.equal(ex.records.length, 8);
    assert.ok(ex.records.every((r) => r.domains.every((d) => d.endsWith(".test.darknode.ai"))));
    const r = analyze(ex, { now: NOW });
    const total = Object.values(r.tables.grid).reduce((a, row) => a + Object.values(row).reduce((x, y) => x + y, 0), 0);
    assert.equal(total, 8);
    assert.ok(r.skipped.some((s) => s.check === "posture"));
    assert.ok(r.findings.every((f) => f.controls.length && f.evidence.length <= 50));
  });
  test("no now: falls back to newest date and says so", () => {
    const r = analyze({ records: [base({ lastReview: "2026-01-01", criticality: "low" })] }, {});
    assert.ok(r.skipped.some((s) => s.check === "clock"));
    assert.equal(r.meta.now, "2026-01-01");
  });
  test("progress callback is called", () => {
    const calls = [];
    analyze(exampleDataset(7, NOW), { now: NOW }, { progress: (i, n) => calls.push([i, n]) });
    assert.deepEqual(calls[calls.length - 1], [8, 8]);
  });
  test("findingsToCsv header row and vendor column", () => {
    const csv = findingsToCsv(analyze(exampleDataset(7, NOW), { now: NOW }).findings);
    const lines = csv.split("\r\n");
    assert.equal(lines[0], "severity,confidence,category,vendor,title,description,recommendation,controls,evidenceCount");
    assert.ok(lines.length > 10);
    assert.equal(findingsToCsv([]).split("\r\n")[0].split(",").length, 9);
  });
  test("empty input safe", () => {
    assert.equal(parseInput("").format, "empty");
    const r = analyze({ records: [] }, { now: NOW });
    assert.equal(r.findings.length, 0); assert.equal(r.meta.rows, 0);
    assert.equal(DEFAULTS.snapshotCap, 12);
  });
});

group("vendorrisk: prototype-key safety (enumSyn reserved words)", () => {
  test("normalizeRecord never stores an inherited Object member for a reserved-word enum cell", () => {
    // SYN[kind]["constructor"] resolved to the native Object function before the guard,
    // so dataTier/dataTypes silently became a function instead of the blank fallback.
    const rec = normalizeRecord({ legalName: "V", dataTier: "constructor", systemAccess: "__proto__", dataTypes: "constructor", integrations: "toString" });
    assert.notEqual(typeof rec.dataTier, "function");
    assert.notEqual(typeof rec.systemAccess, "function");
    assert.ok(!(rec.dataTypes || []).some((x) => typeof x === "function"));
    assert.ok(!(rec.integrations || []).some((x) => typeof x === "function"));
  });
});
