// Domain Guard engine tests (public/js/exposure/domainguard-engine.js): DoH/RDAP
// graders on real response shapes, SPF nested lookup counting, parked-domain rule,
// takeover fingerprints, lookalike generation, Punycode, zone parsers, diff, exports.

import { domainToASCII } from "node:url";
import { test, assert, group } from "../harness.mjs";
import {
  selfTest, analyze, parseInput, exampleDataset, findingsToCsv, punycodeEncode, toAsciiDomain, generateLookalikes,
  parseBindZone, parseRoute53, parseAzureDns, parseDomainList, detectFormat, parseRdap, dohStatus, txtStrings, parseCaaData,
  parseMx, parseSoa, parseSpfRecords, spfLookupTree, spfIncludeTargets, parseDmarcStrict, mtaStsCoverage, gradeDomain,
  gradeHost, gradeLookalike, matchTakeoverProvider, matchHttpFingerprint, diffSnapshots, snapshotOf, dnsFixList,
  lookalikesToCsv, splitDomain, nsProvider, hostsFromRecords, DEFAULTS, dohJson, planDomainQueries, registrableDomain,
} from "../../public/js/exposure/domainguard-engine.js";

const NOW = Date.parse("2026-10-16T00:00:00Z");
const O = { ...DEFAULTS };

// Real dns.google response shape (TXT for a domain with SPF).
const GOOGLE_TXT = { Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false, Question: [{ name: "example.org.", type: 16 }],
  Answer: [{ name: "example.org.", type: 16, TTL: 3600, data: "v=spf1 include:_spf.example.org -all" }, { name: "example.org.", type: 16, TTL: 3600, data: "google-site-verification=abc" }] };
// cloudflare-dns.com quotes TXT data and splits long strings.
const CF_TXT = { Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false, Question: [{ name: "example.org", type: 16 }],
  Answer: [{ name: "example.org", type: 16, TTL: 300, data: "\"v=spf1 ip4:192.0.2.0/24 \" \"include:_spf.example.net -all\"" }] };
const NX = { Status: 3, TC: false, RD: true, RA: true, AD: false, CD: false, Question: [{ name: "nope.example.org.", type: 1 }],
  Authority: [{ name: "example.org.", type: 6, TTL: 1800, data: "ns1.example.org. hostmaster.example.org. 2026101601 7200 3600 1209600 300" }] };

// rdap.org domain JSON (Verisign-style layout, trimmed).
const RDAP = {
  objectClassName: "domain", handle: "2336799_DOMAIN_COM-VRSN", ldhName: "EXAMPLE.COM",
  links: [{ value: "https://rdap.verisign.com/com/v1/domain/EXAMPLE.COM", rel: "self", href: "https://rdap.verisign.com/com/v1/domain/EXAMPLE.COM", type: "application/rdap+json" }],
  status: ["client delete prohibited", "client transfer prohibited", "client update prohibited"],
  entities: [{ objectClassName: "entity", handle: "376", roles: ["registrar"], publicIds: [{ type: "IANA Registrar ID", identifier: "376" }],
    vcardArray: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"]]] }],
  events: [{ eventAction: "registration", eventDate: "1995-08-14T04:00:00Z" }, { eventAction: "expiration", eventDate: "2026-10-20T04:00:00Z" }, { eventAction: "last changed", eventDate: "2025-08-14T07:01:39Z" }, { eventAction: "last update of RDAP database", eventDate: "2026-10-15T20:00:00Z" }],
  secureDNS: { delegationSigned: true }, nameservers: [{ objectClassName: "nameserver", ldhName: "A.IANA-SERVERS.NET" }, { objectClassName: "nameserver", ldhName: "B.IANA-SERVERS.NET" }],
  rdapConformance: ["rdap_level_0"],
};

group("domainguard: punycode and names", () => {
  test("bücher -> xn--bcher-kva", () => assert.equal(toAsciiDomain("bücher.de"), "xn--bcher-kva.de"));
  test("RFC 3492 vectors", () => {
    assert.equal(punycodeEncode("bücher"), "bcher-kva");
    assert.equal(punycodeEncode("münchen"), "mnchen-3ya");
    assert.equal(punycodeEncode("españa"), "espaa-rta");
  });
  test("matches node domainToASCII on Cyrillic and mixed labels", () => {
    for (const d of ["пример.рф", "dаrknode.ai", "darknöde.com", "例え.テスト", "ñandú.com"]) assert.equal(toAsciiDomain(d), domainToASCII(d), d);
  });
  test("splitDomain handles multi-label suffixes", () => {
    assert.deepEqual(splitDomain("shop.brand.co.uk"), { prefix: "shop", label: "brand", suffix: "co.uk" });
    assert.equal(registrableDomain("mail.brand.com"), "brand.com");
  });
  test("nsProvider groups Route 53 across TLDs", () => {
    assert.equal(nsProvider("ns-1.awsdns-01.org"), nsProvider("ns-2.awsdns-02.co.uk"));
    assert.equal(nsProvider("ns1.othercorp.net"), "othercorp.net");
  });
});

group("domainguard: DoH parsers", () => {
  test("dohStatus maps rcodes and errors", () => {
    assert.equal(dohStatus(GOOGLE_TXT), "ok"); assert.equal(dohStatus(NX), "nxdomain");
    assert.equal(dohStatus({ Status: 2 }), "servfail"); assert.equal(dohStatus({ error: "x" }), "error"); assert.equal(dohStatus(undefined), "missing");
  });
  test("txtStrings: dns.google unquoted and cloudflare quoted multi-string", () => {
    assert.equal(txtStrings(GOOGLE_TXT)[0], "v=spf1 include:_spf.example.org -all");
    assert.equal(txtStrings(CF_TXT)[0], "v=spf1 ip4:192.0.2.0/24 include:_spf.example.net -all");
  });
  test("CAA presentation and RFC 3597 hex", () => {
    assert.deepEqual(parseCaaData('0 issue "letsencrypt.org"'), { flags: 0, tag: "issue", value: "letsencrypt.org" });
    // \# 22 00 05 'issue' 'letsencrypt.org'
    const hex = "\\# 22 00 05 69 73 73 75 65 6c 65 74 73 65 6e 63 72 79 70 74 2e 6f 72 67";
    assert.deepEqual(parseCaaData(hex), { flags: 0, tag: "issue", value: "letsencrypt.org" });
  });
  test("MX parsing incl. null MX", () => {
    assert.deepEqual(parseMx(dohJson("a.test", "MX", ["20 b.mx.", "10 a.mx."])).map((m) => m.host), ["a.mx", "b.mx"]);
    assert.deepEqual(parseMx(dohJson("a.test", "MX", ["0 ."])), [{ pref: 0, host: "" }]);
  });
  test("SOA serial and contact email", () => {
    const s = parseSoa(dohJson("example.org", "SOA", ["ns1.example.org. hostmaster.example.org. 2026101601 7200 3600 1209600 300"]));
    assert.equal(s.serial, 2026101601); assert.equal(s.email, "hostmaster@example.org");
  });
  test("plan includes wildcard probe only when given", () => {
    assert.ok(planDomainQueries("a.com", "x.a.com").some((q) => q.key === "WILDCARD"));
    assert.ok(!planDomainQueries("a.com").some((q) => q.key === "WILDCARD"));
  });
});

group("domainguard: SPF and DMARC", () => {
  test("SPF qualifiers and multiple records", () => {
    assert.equal(parseSpfRecords(["v=spf1 -all"]).all, "-");
    assert.equal(parseSpfRecords(["v=spf1 all"]).all, "+");
    assert.ok(parseSpfRecords(["v=spf1 -all", "v=spf1 ~all"]).multiple);
  });
  test("include targets skip macros", () => {
    assert.deepEqual(spfIncludeTargets("v=spf1 include:b.com include:a.com exists:%{i}.x.com redirect=c.com include:%{d}.y.com"), ["a.com", "b.com", "c.com"]);
  });
  test("nested lookup count from fixture answers", () => {
    const map = {
      "a.example": ["v=spf1 include:b.example mx a -all"], "b.example": ["v=spf1 include:c.example ip4:192.0.2.1 -all"],
      "c.example": ["v=spf1 a mx ptr exists:x.example -all"],
    };
    const lk = (d) => (map[d] ? { status: "ok", txts: map[d] } : { status: "missing" });
    const t = spfLookupTree("v=spf1 include:a.example -all", lk);
    assert.equal(t.count, 1 + 3 + 1 + 4); assert.ok(t.complete);
  });
  test("include without SPF and unresolved include are reported", () => {
    const t = spfLookupTree("v=spf1 include:none.example include:gone.example -all", (d) => (d === "none.example" ? { status: "none" } : { status: "missing" }));
    assert.deepEqual(t.noSpf, ["none.example"]); assert.deepEqual(t.missing, ["gone.example"]); assert.ok(!t.complete);
  });
  test("include loop is detected, not followed", () => {
    const t = spfLookupTree("v=spf1 include:x.example -all", (d) => ({ status: "ok", txts: ["v=spf1 include:x.example -all"] }));
    assert.deepEqual(t.loops, ["x.example"]);
  });
  test("DMARC strict: multiple, missing p, bad rua", () => {
    assert.ok(parseDmarcStrict(["v=DMARC1; p=reject", "v=DMARC1; p=none"]).multiple);
    assert.ok(parseDmarcStrict(["v=DMARC1; rua=mailto:a@b.c"]).errors.some((e) => /p= tag/.test(e)));
    assert.ok(parseDmarcStrict(["v=DMARC1; p=reject; rua=https://x"]).errors.some((e) => /mailto/.test(e)));
    assert.equal(parseDmarcStrict(["v=DMARC1; p=quarantine; pct=25; rua=mailto:d@x.y"]).errors.length, 0);
  });
  test("MTA-STS mx coverage incl. wildcard", () => {
    const c = mtaStsCoverage("version: STSv1\nmode: enforce\nmx: *.mx.example\nmax_age: 86400", ["a.mx.example", "other.example"]);
    assert.deepEqual(c.uncovered, ["other.example"]);
  });
});

group("domainguard: RDAP", () => {
  test("expiry, registrar and transfer lock from rdap.org JSON", () => {
    const r = parseRdap(RDAP, NOW);
    assert.ok(r.ok); assert.equal(r.daysLeft, 4); assert.equal(r.registrar, "RESERVED-Internet Assigned Numbers Authority");
    assert.ok(r.transferLock); assert.ok(r.deleteLock); assert.equal(r.registrarIanaId, "376");
    assert.deepEqual(r.nameservers, ["a.iana-servers.net", "b.iana-servers.net"]);
  });
  test("no lock when status is only active; EPP camelCase also accepted", () => {
    assert.ok(!parseRdap({ ...RDAP, status: ["active"] }, NOW).transferLock);
    assert.ok(parseRdap({ ...RDAP, status: ["serverTransferProhibited"] }, NOW).transferLock);
  });
  test("RDAP error object is not ok", () => {
    assert.ok(!parseRdap({ errorCode: 404, title: "Not Found" }, NOW).ok);
    assert.ok(!parseRdap({ error: "proxy down" }, NOW).ok);
  });
  test("ageDays floors a sub-day fraction instead of rounding the age up", () => {
    // Created exactly 10 days + 1 hour before NOW: whole-day age is 10. The old -floor(negative diff)
    // reported 11, which could drop a domain out of the newlyRegistered window a day early.
    const created = new Date(NOW - (10 * 86400000 + 3600000)).toISOString();
    const r = parseRdap({ ...RDAP, events: [{ eventAction: "registration", eventDate: created }] }, NOW);
    assert.equal(r.ageDays, 10);
    // Unparseable creation date yields null, not 0 (which -null used to produce).
    assert.equal(parseRdap({ ...RDAP, events: [{ eventAction: "registration", eventDate: "not-a-date" }] }, NOW).ageDays, null);
  });
});

// Build a domain observation from compact pieces.
function obs(d, x = {}) {
  return {
    at: "2026-10-16T00:00:00Z",
    dns: {
      NS: dohJson(d, "NS", x.ns || ["ns1.a-dns.example.", "ns2.b-dns.example."]), SOA: dohJson(d, "SOA", ["ns1.a-dns.example. h.x. 1 2 3 4 5"], { ad: x.ad }),
      MX: x.mxErr ? { error: "timeout" } : dohJson(d, "MX", x.mx || []), TXT: dohJson(d, "TXT", x.txt || []),
      DMARC: x.dmarc ? dohJson("_dmarc." + d, "TXT", x.dmarc) : dohJson("_dmarc." + d, "TXT", [], { status: 3 }),
      MTASTS: dohJson("_mta-sts." + d, "TXT", x.mts || [], x.mts ? {} : { status: 3 }), TLSRPT: dohJson("_smtp._tls." + d, "TXT", [], { status: 3 }),
      BIMI: dohJson("default._bimi." + d, "TXT", [], { status: 3 }), DS: dohJson(d, "DS", x.ds || []), CAA: dohJson(d, "CAA", x.caa || []),
      A: dohJson(d, "A", ["192.0.2.1"], { ad: x.ad }),
    },
    nsHosts: x.nsHosts || {}, spf: x.spf || {}, mtaStsPolicy: x.policy, rdap: x.rdap,
  };
}
const ids = (g) => g.issues.map((i) => i.id);

group("domainguard: per-domain graders", () => {
  test("parked domain with no records fails the M3AAWG trio", () => {
    const g = gradeDomain({ domain: "p.example", parked: true }, obs("p.example"), O, NOW);
    assert.ok(ids(g).includes("parked_unlocked")); assert.equal(g.row.checks.parked.status, "fail");
  });
  test("parked domain with null MX + -all + reject passes", () => {
    const g = gradeDomain({ domain: "p.example", parked: true }, obs("p.example", { mx: ["0 ."], txt: ["v=spf1 -all"], dmarc: ["v=DMARC1; p=reject"] }), O, NOW);
    assert.ok(!ids(g).includes("parked_unlocked")); assert.equal(g.row.checks.parked.status, "pass");
  });
  test("auto role: send-only domain (SPF ip4, no MX) is a mail domain", () => {
    const g = gradeDomain({ domain: "s.example" }, obs("s.example", { txt: ["v=spf1 ip4:192.0.2.0/24 -all"], dmarc: ["v=DMARC1; p=reject; rua=mailto:a@s.example"] }), O, NOW);
    assert.equal(g.row.role, "mail");
  });
  test("MX lookup error leaves role unknown and parked check errored, never pass/fail", () => {
    const g = gradeDomain({ domain: "e.example" }, obs("e.example", { mxErr: true }), O, NOW);
    assert.equal(g.row.role, "unknown"); assert.equal(g.row.checks.mx.status, "error"); assert.ok(!ids(g).includes("parked_unlocked"));
  });
  test("DMARC missing (high) and p=none (medium) on mail domains", () => {
    const base = { mx: ["10 mx.m.example."], txt: ["v=spf1 mx -all"] };
    assert.ok(ids(gradeDomain({ domain: "m.example" }, obs("m.example", base), O, NOW)).includes("dmarc_missing"));
    const g = gradeDomain({ domain: "m.example" }, obs("m.example", { ...base, dmarc: ["v=DMARC1; p=none; rua=mailto:x@m.example"] }), O, NOW);
    assert.ok(ids(g).includes("dmarc_none")); assert.ok(!ids(g).includes("dmarc_no_rua"));
  });
  test("DMARC pct<100 flagged; pct=100 silent", () => {
    const base = { mx: ["10 mx.m.example."], txt: ["v=spf1 mx -all"] };
    assert.ok(ids(gradeDomain({ domain: "m.example" }, obs("m.example", { ...base, dmarc: ["v=DMARC1; p=reject; pct=50; rua=mailto:x@y.z"] }), O, NOW)).includes("dmarc_pct"));
    assert.ok(!ids(gradeDomain({ domain: "m.example" }, obs("m.example", { ...base, dmarc: ["v=DMARC1; p=reject; pct=100; rua=mailto:x@y.z"] }), O, NOW)).includes("dmarc_pct"));
  });
  test("SPF +all and multiple SPF records", () => {
    const g = gradeDomain({ domain: "m.example" }, obs("m.example", { mx: ["10 mx.m.example."], txt: ["v=spf1 +all", "v=spf1 -all"] }), O, NOW);
    assert.ok(ids(g).includes("spf_plus_all")); assert.ok(ids(g).includes("spf_multiple"));
  });
  test("SPF permerror from nested includes in observations", () => {
    const spf = {};
    const incs = [];
    for (let i = 0; i < 6; i++) { incs.push("include:s" + i + ".example"); spf["s" + i + ".example"] = dohJson("s" + i + ".example", "TXT", ["v=spf1 a mx -all"]); }
    const g = gradeDomain({ domain: "m.example" }, obs("m.example", { mx: ["10 mx.m.example."], txt: ["v=spf1 " + incs.join(" ") + " -all"], spf }), O, NOW);
    assert.equal(g.row.mail.spfLookups, 18); assert.ok(ids(g).includes("spf_permerror"));
  });
  test("SPF at exactly 10 lookups is not a permerror", () => {
    const g = gradeDomain({ domain: "m.example" }, obs("m.example", { mx: ["10 mx.m.example."], txt: ["v=spf1 a mx a:x.example a:y.example mx:z.example a:1.example a:2.example a:3.example a:4.example a:5.example -all"] }), O, NOW);
    assert.equal(g.row.mail.spfLookups, 10); assert.ok(!ids(g).includes("spf_permerror"));
  });
  test("expiry thresholds: 4 days critical, 20 days high, 90 days pass", () => {
    const mk = (iso) => ids(gradeDomain({ domain: "x.example" }, obs("x.example", { rdap: { ...RDAP, events: [{ eventAction: "expiration", eventDate: iso }] } }), O, NOW));
    assert.ok(mk("2026-10-20T04:00:00Z").includes("expiry_critical"));
    assert.ok(mk("2026-11-05T00:00:00Z").includes("expiry_soon"));
    const ok = mk("2027-01-14T00:00:00Z"); assert.ok(!ok.includes("expiry_soon") && !ok.includes("expiry_critical"));
  });
  test("expiry edge: exactly 7 days is high, 6 is critical", () => {
    const mk = (iso) => ids(gradeDomain({ domain: "x.example" }, obs("x.example", { rdap: { ...RDAP, events: [{ eventAction: "expiration", eventDate: iso }] } }), O, NOW));
    assert.ok(mk("2026-10-23T00:00:00Z").includes("expiry_soon"));
    assert.ok(mk("2026-10-22T00:00:00Z").includes("expiry_critical"));
  });
  test("no transfer lock is medium; locked is silent", () => {
    assert.ok(ids(gradeDomain({ domain: "x.example" }, obs("x.example", { rdap: { ...RDAP, status: ["active"] } }), O, NOW)).includes("no_transfer_lock"));
    assert.ok(!ids(gradeDomain({ domain: "x.example" }, obs("x.example", { rdap: RDAP }), O, NOW)).includes("no_transfer_lock"));
  });
  test("DNSSEC: no DS -> absent; DS + AD -> pass; CAA absent / present", () => {
    const a = gradeDomain({ domain: "x.example" }, obs("x.example"), O, NOW);
    assert.ok(ids(a).includes("dnssec_absent")); assert.ok(ids(a).includes("caa_absent"));
    const b = gradeDomain({ domain: "x.example" }, obs("x.example", { ds: ["2371 13 2 ABCD"], ad: true, caa: ['0 issue "letsencrypt.org"'] }), O, NOW);
    assert.equal(b.row.checks.dnssec.status, "pass"); assert.equal(b.row.checks.caa.status, "pass");
  });
  test("single NS provider and dangling NS host", () => {
    const g = gradeDomain({ domain: "x.example" }, obs("x.example", { ns: ["ns1.one.example.", "ns2.one.example."], nsHosts: { "ns2.one.example": dohJson("ns2.one.example", "A", [], { status: 3 }) } }), O, NOW);
    assert.ok(ids(g).includes("ns_single_provider")); assert.ok(ids(g).includes("ns_dangling"));
  });
  test("MTA-STS testing mode is info; absent on mail domain is low", () => {
    const base = { mx: ["10 mx.m.example."], txt: ["v=spf1 mx -all"], dmarc: ["v=DMARC1; p=reject; rua=mailto:a@b.c"] };
    assert.ok(ids(gradeDomain({ domain: "m.example" }, obs("m.example", base), O, NOW)).includes("mtasts_absent"));
    const g = gradeDomain({ domain: "m.example" }, obs("m.example", { ...base, mts: ["v=STSv1; id=1"], policy: { status: 200, body: "version: STSv1\nmode: testing\nmx: mx.m.example\nmax_age: 86400" } }), O, NOW);
    assert.ok(ids(g).includes("mtasts_testing")); assert.ok(!ids(g).includes("mtasts_absent"));
  });
});

group("domainguard: subdomain takeover", () => {
  test("provider fingerprint table matches suffixes", () => {
    assert.equal(matchTakeoverProvider("old-app.azurewebsites.net").id, "azure-app");
    assert.equal(matchTakeoverProvider("b.s3-website-us-east-1.amazonaws.com").id, "aws-s3");
    assert.equal(matchTakeoverProvider("org.github.io").status, "edge case");
    assert.equal(matchTakeoverProvider("www.example.org"), null);
  });
  test("HTTP fingerprint match is case-insensitive", () => {
    const p = matchTakeoverProvider("x.herokuapp.com");
    assert.equal(matchHttpFingerprint(p, { status: 404, body: "<h1>no such app</h1>" }), "No such app");
    assert.equal(matchHttpFingerprint(p, { status: 200, body: "hello" }), null);
  });
  test("NXDOMAIN to Azure is high/likely", () => {
    const A = dohJson("c.ex.test", "A", [], { status: 3, cname: [["c.ex.test", "gone.azurewebsites.net"]] });
    const r = gradeHost({ host: "c.ex.test", types: ["CNAME"], target: "gone.azurewebsites.net" }, { A });
    assert.equal(r.severity, "high"); assert.equal(r.confidence, "likely");
  });
  test("S3 NoSuchBucket body is critical/confirmed; resolving GitHub without fingerprint is silent", () => {
    const A = dohJson("s.ex.test", "A", ["192.0.2.9"], { cname: [["s.ex.test", "b.s3-website-us-east-1.amazonaws.com"]] });
    const r = gradeHost({ host: "s.ex.test", types: ["CNAME"] }, { A, http: { status: 404, body: "Code: NoSuchBucket" } });
    assert.equal(r.severity, "critical"); assert.equal(r.confidence, "confirmed");
    const g = gradeHost({ host: "d.ex.test", types: ["CNAME"] }, { A: dohJson("d.ex.test", "A", ["192.0.2.2"], { cname: [["d.ex.test", "o.github.io"]] }), http: { status: 200, body: "docs" } });
    assert.equal(g.severity, null);
  });
  test("A-only host is not checked (cloud IP ownership)", () => {
    const r = gradeHost({ host: "w.ex.test", types: ["A"] }, { A: dohJson("w.ex.test", "A", ["203.0.113.1"]) });
    assert.equal(r.severity, null); assert.ok(/not checked/.test(r.verdict));
  });
  test("lookup error never becomes a verdict", () => {
    assert.equal(gradeHost({ host: "e.ex.test", types: ["CNAME"], target: "x.azurewebsites.net" }, { A: { error: "timeout" } }).verdict, "lookup error");
  });
});

group("domainguard: lookalikes", () => {
  const c = generateLookalikes("darknode.ai");
  const names = c.map((x) => x.domain);
  test("expected candidates: homoglyph, transposition, TLD swap", () => {
    assert.ok(names.includes("darkn0de.ai")); assert.ok(names.includes("draknode.ai")); assert.ok(names.includes("darknode.co"));
    assert.equal(c.find((x) => x.domain === "darkn0de.ai").kind, "homoglyph");
    assert.equal(c.find((x) => x.domain === "draknode.ai").kind, "transposition");
  });
  test("omission, repetition, hyphenation, keyword, bitsquat, IDN present", () => {
    for (const d of ["darknde.ai", "darkknode.ai", "dark-node.ai", "darknode-login.com", "darknode-ai.com"]) assert.ok(names.includes(d), d);
    assert.ok(c.some((x) => x.kind === "bitsquat")); assert.ok(c.some((x) => x.kind === "idn-homoglyph" && x.domain.includes("xn--")));
  });
  test("IDN candidate punycode equals node domainToASCII of its Unicode form", () => {
    for (const x of c.filter((y) => y.kind === "idn-homoglyph")) assert.equal(x.domain, domainToASCII(x.display));
  });
  test("deterministic, unique, excludes itself, honours cap", () => {
    assert.deepEqual(generateLookalikes("darknode.ai"), c);
    assert.equal(new Set(names).size, names.length); assert.ok(!names.includes("darknode.ai"));
    assert.equal(generateLookalikes("darknode.ai", { max: 25 }).length, 25);
  });
  test("brand keywords add combos", () => {
    assert.ok(generateLookalikes("darknode.ai", { keywords: ["nexus"], max: 2000 }).some((x) => x.domain === "nexus-sso.ai"));
  });
  test("gradeLookalike: NXDOMAIN unregistered; new with MX flagged", () => {
    assert.equal(gradeLookalike({ NS: NX }, NOW).status, "unregistered");
    const g = gradeLookalike({ NS: dohJson("x.ai", "NS", ["ns.p."]), A: dohJson("x.ai", "A", ["192.0.2.5"]), MX: dohJson("x.ai", "MX", ["10 m.x.ai."]),
      rdap: { ...RDAP, events: [{ eventAction: "registration", eventDate: "2026-10-10T00:00:00Z" }] } }, NOW, O);
    assert.equal(g.status, "registered"); assert.ok(g.mx && g.web && g.newlyRegistered); assert.equal(g.ageDays, 6);
  });
});

group("domainguard: input formats", () => {
  const BIND = `$ORIGIN example.org.
$TTL 3600
@  IN SOA ns1.example.org. hostmaster.example.org. (
      2026101601 ; serial
      7200 3600 1209600 300 )
   IN NS ns1.example.org.
   IN NS ns2.example.net.
@  IN MX 10 mail
@  IN TXT "v=spf1 mx " "-all"
www 300 IN CNAME app.azurewebsites.net.
mail IN A 192.0.2.25
api IN 600 AAAA 2001:db8::1
`;
  test("BIND: $ORIGIN, $TTL, parentheses, relative names, split TXT", () => {
    const z = parseBindZone(BIND);
    assert.equal(z.origin, "example.org");
    assert.equal(z.records.find((r) => r.type === "MX").value, "10 mail.example.org");
    assert.equal(z.records.find((r) => r.type === "TXT").value, "v=spf1 mx -all");
    assert.equal(z.records.find((r) => r.name === "www.example.org").value, "app.azurewebsites.net");
    assert.equal(z.records.find((r) => r.type === "AAAA").ttl, "600");
    assert.equal(z.records.filter((r) => r.type === "NS").every((r) => r.name === "example.org"), true);
  });
  test("Cloudflare export (BIND with ;; Domain and cf_tags)", () => {
    const CF = ";;\n;; Domain:     example.net.\n;; Exported:   2026-10-16 10:00:00\n;;\n;; A Records\nexample.net.\t1\tIN\tA\t192.0.2.10 ; cf_tags=cf-proxied:true\nblog.example.net.\t1\tIN\tCNAME\texample-blog.ghost.io. ; cf_tags=cf-proxied:false\n";
    assert.equal(detectFormat(CF).format, "cloudflare-bind");
    const p = parseInput([{ name: "cf.txt", text: CF }]);
    assert.ok(p.domains.some((d) => d.domain === "example.net"));
    assert.equal(p.hosts.find((h) => h.host === "blog.example.net").target, "example-blog.ghost.io");
  });
  test("Route 53 list-resource-record-sets JSON incl. alias", () => {
    const R53 = JSON.stringify({ ResourceRecordSets: [
      { Name: "example.com.", Type: "SOA", TTL: 900, ResourceRecords: [{ Value: "ns-1.awsdns-01.org. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400" }] },
      { Name: "example.com.", Type: "TXT", TTL: 300, ResourceRecords: [{ Value: "\"v=spf1 include:amazonses.com -all\"" }] },
      { Name: "static.example.com.", Type: "A", AliasTarget: { HostedZoneId: "Z3AQBSTGFYJSTF", DNSName: "s3-website-us-east-1.amazonaws.com.", EvaluateTargetHealth: false } },
      { Name: "\\052.example.com.", Type: "CNAME", TTL: 300, ResourceRecords: [{ Value: "lb.example.com" }] },
      { Name: "shop.example.com.", Type: "CNAME", TTL: 300, ResourceRecords: [{ Value: "shops.myshopify.com" }] },
    ] });
    assert.equal(detectFormat(R53).format, "route53-json");
    const z = parseRoute53(R53);
    assert.equal(z.origin, "example.com");
    assert.equal(z.records.find((r) => r.type === "TXT").value, "v=spf1 include:amazonses.com -all");
    assert.equal(z.records.find((r) => r.type === "ALIAS").value, "s3-website-us-east-1.amazonaws.com");
    const hosts = hostsFromRecords(z.records);
    assert.ok(hosts.some((h) => h.host === "shop.example.com" && h.target === "shops.myshopify.com"));
    assert.ok(!hosts.some((h) => h.host.startsWith("*")));
  });
  test("Azure az network dns record-set list JSON (both key casings)", () => {
    const AZ = JSON.stringify([
      { etag: "1", fqdn: "contoso.org.", id: "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/dnszones/contoso.org/MX/@", name: "@", provisioningState: "Succeeded", resourceGroup: "rg", ttl: 3600, type: "Microsoft.Network/dnszones/MX", mxRecords: [{ exchange: "contoso-org.mail.protection.outlook.com", preference: 0 }] },
      { etag: "2", fqdn: "careers.contoso.org.", id: "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/dnszones/contoso.org/CNAME/careers", name: "careers", ttl: 3600, type: "Microsoft.Network/dnszones/CNAME", cnameRecord: { cname: "contoso-careers.azurewebsites.net" } },
      { etag: "3", fqdn: "www.contoso.org.", id: "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/dnszones/contoso.org/A/www", name: "www", TTL: 300, type: "Microsoft.Network/dnszones/A", ARecords: [{ ipv4Address: "192.0.2.4" }] },
      { etag: "4", fqdn: "contoso.org.", id: "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/dnszones/contoso.org/TXT/@", name: "@", ttl: 3600, type: "Microsoft.Network/dnszones/TXT", txtRecords: [{ value: ["v=spf1 include:spf.protection.outlook.com -all"] }] },
    ]);
    assert.equal(detectFormat(AZ).format, "azure-dns-json");
    const z = parseAzureDns(AZ);
    assert.equal(z.origin, "contoso.org");
    assert.equal(z.records.find((r) => r.type === "CNAME").value, "contoso-careers.azurewebsites.net");
    assert.equal(z.records.find((r) => r.type === "A").value, "192.0.2.4");
    assert.equal(z.records.find((r) => r.type === "MX").value, "0 contoso-org.mail.protection.outlook.com");
  });
  test("domain list with flags, URLs and IDN", () => {
    const d = parseDomainList("Example.com mail\nhttps://parked.example/path parked\n# comment\nbücher.de\nnot a domain").domains;
    assert.deepEqual(d.map((x) => x.domain), ["example.com", "parked.example", "xn--bcher-kva.de"]);
    assert.equal(d.find((x) => x.domain === "parked.example").parked, true);
    assert.equal(d.find((x) => x.domain === "example.com").sendsMail, true);
  });
  test("domain CSV and missing domain column reported, not guessed", () => {
    assert.equal(parseDomainList("domain,sends_mail,parked\na.example,yes,no\nb.example,no,yes").domains.length, 2);
    const bad = parseDomainList("host_label,owner\nfoo,bar");
    assert.ok(bad.needsMapping); assert.equal(bad.skipped[0].check, "domain list");
    assert.equal(parseDomainList("host_label,owner\nfoo.example,bar", { domain: "host_label" }).domains[0].domain, "foo.example");
  });
});

group("domainguard: analyze, diff, exports", () => {
  const ex = exampleDataset();
  const r = analyze(ex.dataset, { now: ex.now });
  test("in-engine self-test passes", () => {
    const s = selfTest();
    assert.ok(s.pass, "failed: " + s.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });
  test("analyze is byte-identical across runs", () => assert.equal(JSON.stringify(analyze(ex.dataset, { now: ex.now })), JSON.stringify(r)));
  test("a lookup that errored holds the issues it decides, so they are not offered as fixed", () => {
    const mk = (dm) => ({ domains: [{ domain: "m.example" }], observations: { "m.example": obs("m.example", { txt: ["v=spf1 ip4:192.0.2.0/24 -all"], dmarc: dm }) } });
    const was = analyze(mk(null), { now: ex.now });
    assert.ok(was.findings.some((f) => f.id === "domainguard:dmarc_missing"));
    assert.ok(!was.held.includes("domainguard:dmarc_missing"), "an answered lookup holds nothing");
    const cur = mk(null); cur.observations["m.example"].dns.DMARC = { error: "timeout" };
    const now = analyze(cur, { now: ex.now });
    assert.ok(!now.findings.some((f) => f.id === "domainguard:dmarc_missing"));
    assert.ok(now.held.includes("domainguard:dmarc_missing"));
    const unchecked = analyze({ domains: [{ domain: "m.example" }], observations: {} }, { now: ex.now });
    assert.ok(unchecked.held.includes("domainguard:expiry_critical") && unchecked.held.includes("domainguard:spf_missing"), "a domain not checked holds every issue");
  });
  test("example covers parked, takeover, expiry and lookalike-with-MX", () => {
    const fid = r.findings.map((f) => f.id);
    for (const id of ["domainguard:parked_unlocked", "domainguard:expiry_critical", "takeover:careers.darknode-acq.test.darknode.ai", "domainguard:lookalike_mx_new:darknode.test.darknode.ai"]) assert.ok(fid.includes(id), id);
  });
  test("every finding has controls, confidence and assets", () => {
    for (const f of r.findings) {
      assert.ok(f.controls.length >= 1); assert.ok(["confirmed", "likely", "review"].includes(f.confidence));
      assert.ok(f.assets.length >= 1 && f.evidence.length <= 50 && f.evidenceCount >= f.evidence.length);
    }
  });
  test("unchecked domains and missing hosts go to skipped", () => {
    const s = analyze({ domains: ["a.example"] }, { now: ex.now });
    assert.equal(s.findings.length, 0);
    assert.ok(s.skipped.some((k) => k.check === "live DNS checks")); assert.ok(s.skipped.some((k) => k.check === "subdomain takeover"));
  });
  test("no reference date is reported in skipped", () => {
    assert.ok(analyze({ domains: ["a.example"] }).skipped.some((k) => /reference date/.test(k.reason)));
  });
  test("changes diff: new failures, fixes and new lookalikes", () => {
    const kinds = r.tables.changes.map((c) => c.kind + ":" + c.domain + ":" + c.check);
    assert.ok(kinds.includes("new failure:darknode-promo.test.darknode.ai:expiry"));
    assert.ok(kinds.includes("fixed:darknode-hold.test.darknode.ai:caa"));
    assert.ok(kinds.includes("lookalike newly registered:darknode.test.darknode.ai:darnode.test.darknode.ai"));
  });
  test("diff ignores error transitions and is empty for identical snapshots", () => {
    const snap = snapshotOf(r);
    assert.equal(diffSnapshots(snap, snap).length, 0);
    const a = { domains: { "x.example": { grade: "A", checks: { dmarc: "pass" } } } }, b = { domains: { "x.example": { grade: "A", checks: { dmarc: "error" } } } };
    assert.equal(diffSnapshots(a, b).length, 0);
  });
  test("findingsToCsv header row and quoting", () => {
    const csv = findingsToCsv(r.findings);
    assert.equal(csv.split("\n")[0], "severity,confidence,category,title,description,recommendation,controls,evidenceCount,assets");
    assert.equal(csv.split("\n").length, r.findings.length + 1);
  });
  test("DNS fix list contains the parked trio and the dangling delete", () => {
    const t = dnsFixList(r);
    assert.ok(t.includes("darknode-parked.test.darknode.ai.\t3600\tIN\tMX\t0 ."));
    assert.ok(t.includes('_dmarc.darknode-parked.test.darknode.ai.\t3600\tIN\tTXT\t"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s"'));
    assert.ok(t.includes("DELETE  careers.darknode-acq.test.darknode.ai."));
  });
  test("lookalikes CSV lists registered first", () => {
    const lines = lookalikesToCsv(r.tables.lookalikes).split("\n");
    assert.ok(lines[0].startsWith("owner,lookalike")); assert.ok(lines[1].includes("registered"));
    assert.equal(lookalikesToCsv(r.tables.lookalikes, { registeredOnly: true }).split("\n").length, 4);
  });
  test("progress callback is optional and called", () => {
    let n = 0; analyze(ex.dataset, { now: ex.now }, { progress: () => n++ }); assert.ok(n >= 1);
  });
});
