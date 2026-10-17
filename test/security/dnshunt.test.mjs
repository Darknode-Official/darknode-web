// DNS Hunt engine tests (public/js/ops/dnshunt-engine.js): one parser test per log
// format using fixture lines in each product's layout, every detection on a crafted
// positive and a negative, thresholds, skipped checks, determinism and exports.

import { test, assert, group } from "../harness.mjs";
import {
  selfTest, analyze, parseInput, exampleDataset, detectFormat, iterEvents, findingsToCsv, tableToCsv, blocklistText, summaryText,
  dgaTraits, looksEncoded, punycodeDecode, toUnicodeName, lookalikeOf, regDomain, winName, periodicity, editDistance, entropy,
} from "../../public/js/ops/dnshunt-engine.js";

const T0 = Date.UTC(2026, 9, 10, 9, 0, 0);
const evs = (det, text) => [...iterEvents(text, det, 2026)];
const run = (events, opts) => analyze({ events }, opts);
const cats = (r) => r.findings.map((f) => f.category);
// Deterministic consonant-heavy labels built at test time (no real domains).
function genLabels(n, seed = 3) {
  let s = seed;
  const rnd = () => { s = (s * 1103515245 + 12345) >>> 0; return s / 4294967296; };
  const cons = "bcdfghjklmnpqrstvwxz";
  return Array.from({ length: n }, () => { let o = ""; for (let i = 0; i < 16; i++) o += i === 5 ? String(Math.floor(rnd() * 10)) : cons[Math.floor(rnd() * cons.length)]; return o; });
}
function hex(n, seed) { let s = seed, o = ""; for (let i = 0; i < n; i++) { s = (s * 1103515245 + 12345) >>> 0; o += "0123456789abcdef"[(s >>> 16) % 16]; } return o; }

group("dnshunt: formats", () => {
  const ZEEK = [
    "#separator \\x09", "#set_separator\t,", "#empty_field\t(empty)", "#unset_field\t-", "#path\tdns",
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\trtt\tquery\tqclass\tqclass_name\tqtype\tqtype_name\trcode\trcode_name\tAA\tTC\tRD\tRA\tZ\tanswers\tTTLs\trejected",
    "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tcount\tinterval\tstring\tcount\tstring\tcount\tstring\tcount\tstring\tbool\tbool\tbool\tbool\tcount\tvector[string]\tvector[interval]\tbool",
    "1791622800.123456\tCk2Yz71\t10.1.1.5\t51515\t10.1.1.2\t53\tudp\t4242\t0.012\twww.test.darknode.ai\t1\tC_INTERNET\t1\tA\t0\tNOERROR\tF\tF\tT\tT\t0\t198.51.100.7,198.51.100.8\t60.000000,60.000000\tF",
    "1791622801.000000\tCk2Yz72\t10.1.1.6\t51516\t10.1.1.2\t53\tudp\t4243\t-\tmissing.test.darknode.ai\t1\tC_INTERNET\t1\tA\t3\tNXDOMAIN\tF\tF\tT\tT\t0\t-\t-\tF",
  ].join("\n");

  test("Zeek dns.log TSV detected and parsed", () => {
    const d = detectFormat(ZEEK);
    assert.equal(d.format, "zeek-tsv"); assert.equal(d.confidence, "high");
    const e = evs(d, ZEEK);
    assert.equal(e.length, 2);
    assert.equal(e[0].client, "10.1.1.5"); assert.equal(e[0].server, "10.1.1.2"); assert.equal(e[0].qtype, "A");
    assert.deepEqual(e[0].answers, ["198.51.100.7", "198.51.100.8"]);
    assert.equal(e[1].rcode, "NXDOMAIN"); assert.equal(e[0].ts, 1791622800123);
  });

  test("Zeek JSON lines detected", () => {
    const t = '{"ts":1791622800.5,"uid":"C1","id.orig_h":"10.1.1.9","id.orig_p":5000,"id.resp_h":"10.1.1.2","id.resp_p":53,"proto":"udp","query":"api.test.darknode.ai","qtype_name":"AAAA","rcode_name":"NOERROR","answers":["2001:db8::5"]}\n';
    const d = detectFormat(t);
    assert.equal(d.format, "zeek-json");
    const e = evs(d, t)[0];
    assert.equal(e.query, "api.test.darknode.ai"); assert.equal(e.qtype, "AAAA"); assert.deepEqual(e.answers, ["2001:db8::5"]);
  });

  test("BIND query log (with and without the queries: info: prefix)", () => {
    const t = "10-Oct-2026 09:00:00.120 queries: info: client @0x7f3a2c0e1b20 192.168.4.20#50001 (www.test.darknode.ai): query: www.test.darknode.ai IN A +E(0)K (192.168.4.2)\n" +
      "10-Oct-2026 09:00:01.000 client 192.168.4.21#50002 (mx.test.darknode.ai): view internal: query: mx.test.darknode.ai IN MX + (192.168.4.2)\n";
    const d = detectFormat(t);
    assert.equal(d.format, "bind");
    const e = evs(d, t);
    assert.equal(e.length, 2); assert.equal(e[1].client, "192.168.4.21"); assert.equal(e[1].qtype, "MX");
    assert.equal(e[0].ts, Date.UTC(2026, 9, 10, 9, 0, 0, 120));
  });

  test("Windows DNS debug log: queries from Rcv, result codes from Snd responses", () => {
    const t = [
      "10/10/2026 9:00:00 AM 0F2C PACKET  000001A2B3C4D5E6 UDP Rcv 10.2.0.15       1a2b   Q [0001   D   NOERROR] A      (3)www(4)test(8)darknode(2)ai(0)",
      "10/10/2026 9:00:00 AM 0F2C PACKET  000001A2B3C4D5E7 UDP Snd 10.2.0.15       1a2b R Q [8081   DR NXDOMAIN] A      (3)www(4)test(8)darknode(2)ai(0)",
      "10/10/2026 9:00:01 AM 0F2C PACKET  000001A2B3C4D5E8 UDP Snd 198.51.100.53   77aa   Q [0001   D   NOERROR] A      (3)www(4)test(8)darknode(2)ai(0)",
    ].join("\n");
    const d = detectFormat(t);
    assert.equal(d.format, "windns");
    const e = evs(d, t);
    assert.equal(e.length, 2);
    assert.equal(e[0].kind, "q"); assert.equal(e[0].query, "www.test.darknode.ai"); assert.equal(e[0].client, "10.2.0.15");
    assert.equal(e[1].kind, "r"); assert.equal(e[1].rcode, "NXDOMAIN");
    assert.equal(e[0].ts, Date.UTC(2026, 9, 10, 9, 0, 0));
  });

  test("dnsmasq / Pi-hole log pairs replies to the asking client", () => {
    const t = "Oct 10 09:00:00 dnsmasq[812]: query[A] nope.test.darknode.ai from 192.168.1.40\n" +
      "Oct 10 09:00:00 dnsmasq[812]: forwarded nope.test.darknode.ai to 192.168.1.1\n" +
      "Oct 10 09:00:00 dnsmasq[812]: reply nope.test.darknode.ai is NXDOMAIN\n" +
      "Oct 10 09:00:05 dnsmasq[812]: query[A] www.test.darknode.ai from 192.168.1.41\n" +
      "Oct 10 09:00:05 dnsmasq[812]: reply www.test.darknode.ai is 198.51.100.20\n";
    const d = detectFormat(t);
    assert.equal(d.format, "dnsmasq");
    const e = evs(d, t);
    assert.equal(e.length, 4);
    assert.equal(e[1].kind, "r"); assert.equal(e[1].client, "192.168.1.40"); assert.equal(e[1].rcode, "NXDOMAIN");
    assert.deepEqual(e[3].answers, ["198.51.100.20"]);
    assert.equal(e[0].ts, Date.UTC(2026, 9, 10, 9, 0, 0));
  });

  test("Unbound log-queries and log-replies lines", () => {
    const t = "[1791622800] unbound[1234:0] info: 10.3.0.9 www.test.darknode.ai. A IN\n[1791622801] unbound[1234:0] info: 10.3.0.9 gone.test.darknode.ai. A IN NXDOMAIN 0.000123 0 63\n";
    const d = detectFormat(t);
    assert.equal(d.format, "unbound");
    const e = evs(d, t);
    assert.equal(e.length, 2); assert.equal(e[0].ts, 1791622800000); assert.equal(e[1].rcode, "NXDOMAIN");
  });

  test("Route 53 Resolver query log JSON lines", () => {
    const t = '{"version":"1.100000","account_id":"111122223333","region":"us-east-1","vpc_id":"vpc-0abc","query_timestamp":"2026-10-10T09:00:00Z","query_name":"bucket.test.darknode.ai.","query_type":"A","query_class":"IN","rcode":"NOERROR","answers":[{"Rdata":"198.51.100.9","Type":"A","Class":"IN"}],"srcaddr":"10.0.5.7","srcport":"40000","transport":"UDP","srcids":{"instance":"i-0abc123"}}\n';
    const d = detectFormat(t);
    assert.equal(d.format, "route53");
    const e = evs(d, t)[0];
    assert.equal(e.query, "bucket.test.darknode.ai"); assert.equal(e.user, "i-0abc123"); assert.deepEqual(e.answers, ["198.51.100.9"]);
  });

  test("Umbrella DNS CSV with header (high) and headerless (medium)", () => {
    const head = '"Timestamp","Most Granular Identity","Identities","Internal IP","External IP","Action","QueryType","ResponseCode","Domain","Categories"\n';
    const row = '"2026-10-10 09:00:00","Pat Lee (pat@test.darknode.ai)","Pat Lee (pat@test.darknode.ai),Office","10.9.0.4","203.0.113.10","Allowed","1 (A)","NOERROR","files.test.darknode.ai.","Business Services"\n';
    const d1 = detectFormat(head + row);
    assert.equal(d1.format, "umbrella"); assert.equal(d1.confidence, "high");
    const e = evs(d1, head + row);
    assert.equal(e.length, 1); assert.equal(e[0].client, "10.9.0.4"); assert.equal(e[0].qtype, "A"); assert.equal(e[0].query, "files.test.darknode.ai");
    const d2 = detectFormat(row);
    assert.equal(d2.format, "umbrella"); assert.equal(d2.confidence, "medium");
    assert.equal(evs(d2, row).length, 1);
  });

  test("Umbrella DNS v13 layout: documented optional header and 16-field rows, Proxied action", () => {
    const head = '"Timestamp","Most Granular Identity","Identities","Internal IP","External IP","Action","Query Type","Response Code","Domain","Categories","Most Granular Identity Type","Identity Types","Blocked Categories","Rule ID","Destination Countries","Organization ID"\n';
    const row = '"2026-10-10 09:05:00","Pat Lee (pat@test.darknode.ai)","Pat Lee (pat@test.darknode.ai),WS-04","10.9.0.4","203.0.113.10","Blocked","28 (AAAA)","NXDOMAIN","drop.test.darknode.ai.","Chat,Social Networking","AD Users","AD Users,Roaming Computer","Social Networking","506165","","8234970"\n';
    const d1 = detectFormat(head + row);
    assert.equal(d1.format, "umbrella"); assert.equal(d1.confidence, "high");
    const e = evs(d1, head + row);
    assert.equal(e.length, 1); assert.equal(e[0].client, "10.9.0.4"); assert.equal(e[0].qtype, "AAAA"); assert.equal(e[0].rcode, "NXDOMAIN"); assert.equal(e[0].query, "drop.test.darknode.ai");
    const d2 = detectFormat(row);
    assert.equal(d2.format, "umbrella"); assert.equal(d2.confidence, "medium");
    const prox = row.replace('"Blocked"', '"Proxied"');
    assert.equal(detectFormat(prox).format, "umbrella");
  });

  test("generic CSV gets a guessed mapping; numeric rcodes are named", () => {
    const t = "time,src_ip,qname,qtype,rcode\n2026-10-10T09:00:00Z,10.4.0.1,a.test.darknode.ai,A,3\n";
    const d = detectFormat(t);
    assert.equal(d.format, "csv"); assert.equal(d.confidence, "high");
    assert.equal(d.mapping.query, "qname");
    assert.equal(evs(d, t)[0].rcode, "NXDOMAIN");
  });

  test("unknown text and CSV without a query column are skipped, not guessed", () => {
    const r = analyze({ files: [{ name: "x.txt", text: "hello world\nnothing here\n" }, { name: "y.csv", text: "a,b\n1,2\n" }] });
    assert.equal(r.findings.length, 0);
    assert.ok(r.skipped.some((s) => s.check === "file x.txt"));
    assert.ok(r.skipped.some((s) => s.check === "file y.csv" && /query/.test(s.reason)));
  });

  test("parseInput reports format, confidence and a sample per file", () => {
    const p = parseInput([{ name: "dns.log", text: exampleDataset().files[0].text }]);
    assert.equal(p.files[0].format, "zeek-tsv");
    assert.equal(p.files[0].sample.length, 5);
    assert.equal(parseInput("").files[0].format, "unknown");
  });
});

group("dnshunt: helpers", () => {
  test("DGA traits: random label scores high, ordinary names low", () => {
    assert.ok(dgaTraits("qxkzvbwtrplmhd7f").score >= 4);
    assert.equal(dgaTraits("salesforce").score, 0);
    assert.ok(dgaTraits("microsoftonline").score < 4);
  });
  test("entropy and edit distance", () => {
    assert.equal(entropy("aaaa"), 0); assert.equal(entropy("ab"), 1);
    assert.equal(editDistance("darknode", "darkndoe"), 1); assert.equal(editDistance("abc", "xyz", 1), 2);
  });
  test("encoded-label recognition", () => {
    assert.equal(looksEncoded("4f2a9c0e1b7d3a5f"), "hex");
    assert.equal(looksEncoded("mzxw6ytboi2dgnzq"), "base32");
    assert.equal(looksEncoded("www"), "");
    assert.equal(looksEncoded("documentation"), "");
  });
  test("punycode decode (RFC 3492)", () => {
    assert.equal(punycodeDecode("bcher-kva"), "bücher");
    assert.equal(toUnicodeName("xn--bcher-kva.test"), "bücher.test");
    assert.equal(punycodeDecode("!!!"), null);
  });
  test("lookalikes: homoglyph, edit, other TLD, brand, IDN; own domain is not", () => {
    const own = ["darknode.ai"];
    assert.equal(lookalikeOf("darkn0de.ai", own).kind, "homoglyph");
    assert.equal(lookalikeOf("darknoed.ai", own).kind, "edit-1");
    assert.equal(lookalikeOf("darknode.test", own).kind, "other TLD");
    assert.equal(lookalikeOf("darknode-login.test", own).kind, "contains brand");
    assert.equal(lookalikeOf("xn--drknode-2fg.test", own).kind, "IDN");
    assert.equal(lookalikeOf("darknode.ai", own), null);
    assert.equal(lookalikeOf("salesforce.com", own), null);
  });
  test("registrable domain, Windows names, periodicity", () => {
    assert.equal(regDomain("a.b.test.darknode.ai."), "darknode.ai");
    assert.equal(regDomain("www.shop.co.uk"), "shop.co.uk");
    assert.equal(winName("(3)www(4)test(0)"), "www.test");
    const p = periodicity([0, 60000, 120000, 180500, 240000, 300000]);
    assert.equal(p.medianSec, 60); assert.ok(p.cv < 0.05);
    assert.equal(periodicity([0, 1000]), null);
  });
});

group("dnshunt: detections", () => {
  test("DGA client: fires at threshold, silent below it", () => {
    const labels = genLabels(12);
    const mk = (n) => labels.slice(0, n).map((l, i) => ({ ts: T0 + i * 1000, client: "10.5.0.9", query: l + ".test", rcode: "NXDOMAIN" }));
    const hit = run(mk(10));
    assert.ok(hit.findings.some((f) => f.category === "dga" && f.severity === "high" && f.assets[0].name === "10.5.0.9"));
    const miss = run(mk(9));
    assert.ok(!miss.findings.some((f) => f.severity === "high" && f.category === "dga"));
  });

  test("DGA-like resolved domain is medium/review; allow list silences it", () => {
    const [l] = genLabels(1, 9);
    const e = [{ ts: T0, client: "10.5.0.1", query: "x." + l + ".test", rcode: "NOERROR" }];
    const r = run(e);
    assert.ok(r.findings.some((f) => f.title === "DGA-like domain resolved" && f.confidence === "review"));
    assert.equal(run(e, { allowDomains: l + ".test" }).findings.filter((f) => f.category === "dga").length, 0);
  });

  test("DGA check is skipped without response codes", () => {
    const r = run([{ ts: T0, client: "10.5.0.1", query: "www.test.darknode.ai" }]);
    assert.ok(r.skipped.some((s) => /DGA/.test(s.check)));
  });

  test("tunnelling: many encoded subdomains with TXT is high; ordinary subdomains are not", () => {
    const e = [];
    for (let i = 0; i < 220; i++) e.push({ ts: T0 + i * 1000, client: "10.6.0.4", query: hex(32, i + 1) + "." + hex(10, i + 999) + ".relay.tunnel-lab.invalid", qtype: "TXT", rcode: "NOERROR" });
    const r = run(e);
    const f = r.findings.find((x) => x.category === "tunnel");
    assert.ok(f); assert.equal(f.severity, "high"); assert.equal(f.assets[0].name, "tunnel-lab.invalid");
    const plain = [];
    for (let i = 0; i < 220; i++) plain.push({ ts: T0 + i * 1000, client: "10.6.0.4", query: "host" + i + ".corp-lab.invalid", qtype: "A", rcode: "NOERROR" });
    assert.ok(!run(plain).findings.some((x) => x.category === "tunnel"));
    assert.ok(!run(e.slice(0, 199)).findings.some((x) => x.category === "tunnel"), "below the unique-subdomain threshold");
  });

  test("tunnelling ignores built-in high-cardinality services", () => {
    const e = [];
    for (let i = 0; i < 250; i++) e.push({ ts: T0 + i * 1000, client: "10.6.0.5", query: hex(32, i + 7) + ".zen.spamhaus.org", qtype: "TXT", rcode: "NOERROR" });
    assert.ok(!run(e).findings.some((x) => x.category === "tunnel"));
  });

  test("beaconing: steady 5-minute check-ins fire; jittery ones do not", () => {
    const steady = Array.from({ length: 30 }, (_, i) => ({ ts: T0 + i * 300000 + (i % 2) * 1000, client: "10.7.0.3", query: "checkin.beacon-lab.invalid" }));
    const r = run(steady);
    const f = r.findings.find((x) => x.category === "beacon");
    assert.ok(f); assert.ok(/coefficient of variation/.test(f.description));
    let s = 5;
    const jitter = Array.from({ length: 30 }, (_, i) => { s = (s * 1103515245 + 12345) >>> 0; return { ts: T0 + i * 300000 + (s % 240000), client: "10.7.0.3", query: "checkin.beacon-lab.invalid" }; });
    assert.ok(!run(jitter).findings.some((x) => x.category === "beacon"));
    assert.ok(!run(steady.slice(0, 19)).findings.some((x) => x.category === "beacon"), "below the minimum sample size");
  });

  test("beaconing skipped without timestamps", () => {
    const r = run([{ client: "10.7.0.3", query: "a.test.darknode.ai" }]);
    assert.ok(r.skipped.some((s) => /Beaconing/.test(s.check)));
  });

  test("NXDOMAIN storm at thresholds", () => {
    const mk = (n, ok) => [
      ...Array.from({ length: n }, (_, i) => ({ ts: T0 + i, client: "10.8.0.2", query: "printer" + (i % 5) + ".corp.test.darknode.ai", rcode: "NXDOMAIN" })),
      ...Array.from({ length: ok }, (_, i) => ({ ts: T0 + i, client: "10.8.0.2", query: "www.test.darknode.ai", rcode: "NOERROR" })),
    ];
    assert.ok(run(mk(200, 10)).findings.some((f) => f.category === "nxdomain"));
    assert.ok(!run(mk(199, 10)).findings.some((f) => f.category === "nxdomain"));
    assert.ok(!run(mk(200, 400)).findings.some((f) => f.category === "nxdomain"), "share below 40%");
  });

  test("lookalike: high when resolved, low when NXDOMAIN, skipped without own domains", () => {
    const e = [{ ts: T0, client: "10.9.0.1", query: "login.darkn0de.test", rcode: "NOERROR" }];
    assert.equal(run(e, { ownDomains: "darknode.ai" }).findings.find((f) => f.category === "lookalike").severity, "high");
    assert.equal(run([{ ...e[0], rcode: "NXDOMAIN" }], { ownDomains: "darknode.ai" }).findings.find((f) => f.category === "lookalike").severity, "low");
    assert.ok(run(e).skipped.some((s) => /Lookalikes/.test(s.check)));
  });

  test("encrypted DNS lookups and the Firefox canary", () => {
    const r = run([
      { ts: T0, client: "10.1.0.1", query: "dns.google", rcode: "NOERROR" },
      { ts: T0, client: "10.1.0.1", query: "use-application-dns.net", rcode: "NOERROR" },
    ]);
    assert.ok(r.findings.some((f) => f.category === "encrypted-dns" && /resolvers/.test(f.title)));
    assert.ok(r.findings.some((f) => /canary/.test(f.title)));
    const blocked = run([{ ts: T0, client: "10.1.0.1", query: "use-application-dns.net", rcode: "NXDOMAIN" }]);
    assert.ok(!blocked.findings.some((f) => /canary/.test(f.title)));
  });

  test("resolver bypass: external server flagged, internal or approved not", () => {
    const e = [{ ts: T0, client: "10.1.0.7", query: "www.test.darknode.ai", server: "198.51.100.53" }];
    assert.ok(run(e).findings.some((f) => f.category === "resolver"));
    assert.ok(!run([{ ...e[0], server: "10.1.0.2" }]).findings.some((f) => f.category === "resolver"));
    assert.ok(!run(e, { approvedResolvers: "198.51.100.53" }).findings.some((f) => f.category === "resolver"));
    assert.ok(run([{ ts: T0, client: "10.1.0.7", query: "a.test.darknode.ai" }]).skipped.some((s) => /unapproved resolvers/.test(s.check)));
  });

  test("intel: answer on the feed is high; skipped when feed or answers are missing", () => {
    const e = [{ ts: T0, client: "10.1.0.8", query: "drop.intel-lab.invalid", answers: ["203.0.113.66"], rcode: "NOERROR" }];
    const r = run(e, { maliciousIps: [{ ip: "203.0.113.66" }], feedUpdated: "2026-10-16" });
    const f = r.findings.find((x) => x.category === "intel");
    assert.ok(f); assert.equal(f.severity, "high"); assert.ok(/2026-10-16/.test(f.description));
    assert.ok(run(e).skipped.some((s) => /malicious IPs/.test(s.check)));
    assert.ok(run([{ ...e[0], answers: [] }], { maliciousIps: ["203.0.113.66"] }).skipped.some((s) => /answer/.test(s.reason)));
  });

  test("newly observed: in-log baseline, baseline list, and skip when too short", () => {
    const day = 86400000;
    const e = [];
    for (let d = 0; d < 9; d++) e.push({ ts: T0 + d * day, client: "10.2.0.1", query: "www.test.darknode.ai" });
    e.push({ ts: T0 + 8 * day + 5, client: "10.2.0.1", query: "fresh.newdomain-lab.invalid" });
    const r = run(e);
    assert.deepEqual(r.tables.newDomains.map((x) => x.domain), ["newdomain-lab.invalid"]);
    assert.ok(run(e.slice(0, 3)).skipped.some((s) => /Newly observed/.test(s.check)));
    const r2 = run(e.slice(0, 3), { knownDomains: "darknode.ai" });
    assert.equal(r2.tables.newDomains.length, 0);
  });
});

group("dnshunt: contract", () => {
  test("in-engine self-test passes", () => {
    const r = selfTest();
    assert.ok(r.pass, "failed: " + r.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });

  test("analyze is deterministic on the example", () => {
    const ex = exampleDataset();
    assert.equal(JSON.stringify(analyze({ files: ex.files }, ex.opts)), JSON.stringify(analyze({ files: ex.files }, ex.opts)));
  });

  test("example is synthetic: documentation/private IPs and reserved names only", () => {
    const ex = exampleDataset();
    const text = ex.files.map((f) => f.text).join("\n");
    for (const ip of text.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g) || []) {
      assert.ok(/^(10\.|192\.168\.|198\.51\.100\.|203\.0\.113\.|192\.0\.2\.)/.test(ip), "unexpected IP " + ip);
    }
    assert.ok(!/example\.com|contoso/.test(text));
  });

  test("findings carry the contract fields and capped evidence", () => {
    const ex = exampleDataset();
    const r = analyze({ files: ex.files }, ex.opts);
    for (const f of r.findings) {
      assert.ok(["critical", "high", "medium", "low", "info"].includes(f.severity));
      assert.ok(["confirmed", "likely", "review"].includes(f.confidence));
      assert.ok(f.controls.length >= 1 && f.assets.length >= 1);
      assert.ok(f.evidence.length <= 50 && f.evidenceCount >= f.evidence.length);
      assert.ok(/^dnh-\d{3}$/.test(f.id));
    }
  });

  test("empty input yields zero findings and does not throw", () => {
    const r = analyze({ files: [] });
    assert.equal(r.findings.length, 0); assert.equal(r.meta.rows, 0);
    assert.equal(analyze(null).findings.length, 0);
  });

  test("progress is reported", () => {
    const ex = exampleDataset();
    const seen = [];
    analyze({ files: ex.files }, ex.opts, { progress: (i, n, label) => seen.push(label) });
    assert.ok(seen.length >= 3); assert.equal(seen[seen.length - 1], "Done");
  });

  test("CSV exports: header row and formula guard", () => {
    const csv = findingsToCsv([{ id: "dnh-001", severity: "high", confidence: "likely", category: "dga", title: "=cmd", description: "", recommendation: "", controls: [{ framework: "MITRE", id: "T1568.002" }], assets: [], evidenceCount: 1 }]);
    assert.equal(csv.split("\n")[0], "id,severity,confidence,category,title,description,recommendation,controls,assets,evidenceCount");
    assert.ok(csv.includes("\"'=cmd\""));
    assert.equal(tableToCsv([{ a: 1, b: "x" }]), "a,b\n\"1\",\"x\"\n");
  });

  test("blocklist keeps only likely/confirmed domain findings; summary text lists findings", () => {
    const ex = exampleDataset();
    const r = analyze({ files: ex.files }, ex.opts);
    const bl = blocklistText(r.findings);
    assert.ok(bl.includes("sync-relay.invalid"));
    assert.ok(!bl.includes("darkn0de.test"), "review-confidence lookalike is not auto-blocked");
    const txt = summaryText(r);
    assert.ok(txt.startsWith("DNS Hunt summary")); assert.ok(txt.includes("[HIGH/likely]"));
  });
});
