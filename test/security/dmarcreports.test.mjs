// DMARC Reports engine tests (public/js/exposure/dmarcreports-engine.js).
// Fixtures follow the layouts receivers actually send: Google (plain RFC 7489,
// no envelope_from), Microsoft (xsd/xsi namespaces, <version>, envelope_to, fo),
// Yahoo (no sp), the DMARCbis aggregate schema (default xmlns dmarc-2.0,
// discovery_method, testing), the parsedmarc aggregate CSV and an ARF report.

import { test, assert, group } from "../harness.mjs";
import {
  selfTest, analyze, parseInput, exampleDataset, detectFile, parseAggregateXml, parseForensic, findingsToCsv, sourcesToCsv, fixListText, planText, summaryText,
  orgDomain, aligned, evaluateRecord, normIp, expandIPv6, compressIPv6, ptrName, isIPv4, stageIndex, spfTotalLookups, ESP_TABLE, PSL_SUBSET, DEFAULTS,
} from "../../public/js/exposure/dmarcreports-engine.js";
import { unpackAll } from "../../public/js/ingest/unpack.js";
import { zipFiles } from "../../public/js/core/export.js";

const GOOGLE = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <extra_contact_info>https://support.google.com/a/answer/2466580</extra_contact_info>
    <report_id>13955212436931236427</report_id>
    <date_range>
      <begin>1788220800</begin>
      <end>1788307199</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>northwind-test.co.uk</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>none</p>
    <sp>none</sp>
    <pct>100</pct>
    <np>none</np>
  </policy_published>
  <record>
    <row>
      <source_ip>192.0.2.25</source_ip>
      <count>12</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>northwind-test.co.uk</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>northwind-test.co.uk</domain>
        <result>pass</result>
        <selector>google</selector>
      </dkim>
      <spf>
        <domain>bounce.northwind-test.co.uk</domain>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>198.51.100.7</source_ip>
      <count>3</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>fail</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>northwind-test.co.uk</header_from>
    </identifiers>
    <auth_results>
      <spf>
        <domain>other-test.co.uk</domain>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
</feedback>
`;

const MICROSOFT = `<?xml version="1.0"?>
<feedback xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <version>1.0</version>
  <report_metadata>
    <org_name>Enterprise Outlook</org_name>
    <email>dmarcreport@microsoft.com</email>
    <report_id>4c4d3a0f2b8e4b1aa9b6a7c2e1f00d11</report_id>
    <date_range>
      <begin>1788220800</begin>
      <end>1788307200</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>northwind.test.darknode.ai</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>quarantine</p>
    <sp>quarantine</sp>
    <pct>100</pct>
    <fo>0</fo>
  </policy_published>
  <record>
    <row>
      <source_ip>2001:DB8:0:0::1f</source_ip>
      <count>1</count>
      <policy_evaluated>
        <disposition>quarantine</disposition>
        <dkim>fail</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <envelope_to>corp.test.darknode.ai</envelope_to>
      <envelope_from>northwind.test.darknode.ai</envelope_from>
      <header_from>northwind.test.darknode.ai</header_from>
    </identifiers>
    <auth_results>
      <spf>
        <domain>northwind.test.darknode.ai</domain>
        <scope>mfrom</scope>
        <result>fail</result>
      </spf>
    </auth_results>
  </record>
</feedback>`;

const YAHOO = `<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>Yahoo</org_name>
    <email>dmarchelp@yahooinc.com</email>
    <report_id>1788220800.884213</report_id>
    <date_range>
      <begin>1788220800</begin>
      <end>1788307199</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>northwind.test.darknode.ai</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>reject</p>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>192.0.2.40</source_ip>
      <count>4</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>northwind.test.darknode.ai</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>northwind.test.darknode.ai</domain>
        <selector>s1</selector>
        <result>pass</result>
      </dkim>
      <spf>
        <domain>em77.northwind.test.darknode.ai</domain>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
</feedback>
`;

const BIS = `<?xml version="1.0" encoding="UTF-8"?>
<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">
  <version>1.0</version>
  <report_metadata>
    <org_name>Saltmarsh Mail</org_name>
    <email>dmarc-reports@saltmarsh.test.darknode.ai</email>
    <report_id>bis-0001</report_id>
    <date_range><begin>1788220800</begin><end>1788307199</end></date_range>
    <generator>saltmarsh-dmarc 2.1</generator>
  </report_metadata>
  <policy_published>
    <domain>northwind.test.darknode.ai</domain>
    <p>reject</p>
    <sp>reject</sp>
    <adkim>s</adkim>
    <aspf>r</aspf>
    <discovery_method>treewalk</discovery_method>
    <testing>n</testing>
  </policy_published>
  <record>
    <row>
      <source_ip>192.0.2.9</source_ip>
      <count>5</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated>
    </row>
    <identifiers><header_from>northwind.test.darknode.ai</header_from><envelope_from>northwind.test.darknode.ai</envelope_from></identifiers>
    <auth_results>
      <dkim><domain>northwind.test.darknode.ai</domain><selector>sel2026</selector><result>pass</result></dkim>
      <spf><domain>northwind.test.darknode.ai</domain><result>softfail</result></spf>
    </auth_results>
  </record>
</feedback>
`;

const PARSEDMARC_CSV = [
  "xml_schema,org_name,org_email,org_extra_contact_info,report_id,begin_date,end_date,errors,domain,adkim,aspf,p,sp,pct,fo,source_ip_address,source_country,source_reverse_dns,source_base_domain,count,spf_aligned,dkim_aligned,dmarc_aligned,disposition,policy_override_reasons,policy_override_comments,envelope_from,header_from,envelope_to,dkim_domains,dkim_selectors,dkim_results,spf_domains,spf_scopes,spf_results",
  'draft,google.com,noreply-dmarc-support@google.com,https://support.google.com/a/answer/2466580,9911,2026-09-01 00:00:00,2026-09-01 23:59:59,,northwind.test.darknode.ai,r,r,none,none,100,0,192.0.2.70,,,,40,False,False,False,none,,,mail1.mcsv.net,northwind.test.darknode.ai,,mcsv.net,k1,pass,mail1.mcsv.net,mfrom,pass',
  'draft,google.com,noreply-dmarc-support@google.com,https://support.google.com/a/answer/2466580,9911,2026-09-01 00:00:00,2026-09-01 23:59:59,,northwind.test.darknode.ai,r,r,none,none,100,0,192.0.2.10,,,,60,True,True,True,none,,,northwind.test.darknode.ai,northwind.test.darknode.ai,,"northwind.test.darknode.ai,northwind.onmicrosoft.com","selector1,selector1","pass,pass",northwind.test.darknode.ai,mfrom,pass',
].join("\n");

const ARF = [
  "From: dmarc-forensic@corvid.test.darknode.ai",
  'Content-Type: multipart/report; report-type=feedback-report; boundary="x"',
  "", "--x", "Content-Type: message/feedback-report", "",
  "Feedback-Type: auth-failure", "Version: 1", "Original-Mail-From: <ceo@northwind.test.darknode.ai>",
  "Arrival-Date: Tue, 01 Sep 2026 10:00:00", " +0000", "Source-IP: 203.0.113.9", "Reported-Domain: northwind.test.darknode.ai", "Auth-Failure: dmarc", "Delivery-Result: reject", "", "--x--",
].join("\r\n");

// ---- crafted report builder ----
const D = "northwind.test.darknode.ai";
let RID = 0;
function rua({ org = "Bluewren Mail", id, begin = 1788220800, days = 1, policy = {}, records = [], ns = "" } = {}) {
  const p = { domain: D, adkim: "r", aspf: "r", p: "none", pct: 100, ...policy };
  const pp = "<policy_published><domain>" + p.domain + "</domain><adkim>" + p.adkim + "</adkim><aspf>" + p.aspf + "</aspf><p>" + p.p + "</p>" + (p.sp ? "<sp>" + p.sp + "</sp>" : "") + "<pct>" + p.pct + "</pct>" + (p.np ? "<np>" + p.np + "</np>" : "") + (p.testing ? "<testing>" + p.testing + "</testing>" : "") + "</policy_published>";
  const recs = records.map((r) => "<record><row><source_ip>" + r.ip + "</source_ip><count>" + r.n + "</count><policy_evaluated><disposition>" + (r.disp || "none") + "</disposition>" + (r.ed ? "<dkim>" + r.ed + "</dkim>" : "") + (r.es ? "<spf>" + r.es + "</spf>" : "") + (r.reason ? "<reason><type>" + r.reason + "</type></reason>" : "") + "</policy_evaluated></row><identifiers>" + (r.ef ? "<envelope_from>" + r.ef + "</envelope_from>" : "") + "<header_from>" + (r.hf || D) + "</header_from></identifiers><auth_results>" +
    (r.dkim || []).map((d) => "<dkim><domain>" + d[0] + "</domain><selector>" + (d[2] || "s") + "</selector><result>" + d[1] + "</result></dkim>").join("") +
    (r.spf || []).map((s) => "<spf><domain>" + s[0] + "</domain><scope>" + (s[2] || "mfrom") + "</scope><result>" + s[1] + "</result></spf>").join("") + "</auth_results></record>").join("");
  return '<?xml version="1.0"?><feedback' + (ns ? ' xmlns="' + ns + '"' : "") + "><report_metadata><org_name>" + org + "</org_name><email>r@x.test.darknode.ai</email><report_id>" + (id || "r" + ++RID) + "</report_id><date_range><begin>" + begin + "</begin><end>" + (begin + days * 86400 - 1) + "</end></date_range></report_metadata>" + pp + recs + "</feedback>";
}
/** Daily reports over `n` days with the same records. */
const series = (n, opt) => Array.from({ length: n }, (_, i) => ({ name: "d" + String(i).padStart(3, "0") + ".xml", text: rua({ ...opt, id: (opt.idp || "s") + i, begin: 1788220800 + i * 86400 }) }));
const GOOD = { ip: "192.0.2.10", n: 100, dkim: [[D, "pass", "selector1"], ["northwind.onmicrosoft.com", "pass", "selector1"]], spf: [[D, "pass"]], ef: D, ed: "pass", es: "pass" };
const SPOOF = (ip, n) => ({ ip, n, spf: [[D, "fail"]], ef: D, ed: "fail", es: "fail" });
const ids = (r) => r.findings.map((f) => f.id);
const find = (r, prefix) => r.findings.find((f) => f.id.startsWith(prefix));

group("dmarcreports: parsing real layouts", () => {
  test("Google RFC 7489 report: metadata, policy, records, no envelope_from", () => {
    const { report } = parseAggregateXml(GOOGLE, "google.xml");
    assert.equal(report.org, "google.com");
    assert.equal(report.reportId, "13955212436931236427");
    assert.equal(report.begin, 1788220800);
    assert.equal(report.schema, "rfc7489");
    assert.deepEqual([report.policy.p, report.policy.sp, report.policy.pct, report.policy.np, report.policy.hasNp], ["none", "none", 100, "none", true]);
    assert.equal(report.records.length, 2);
    assert.equal(report.records[0].count, 12);
    assert.equal(report.records[0].dkim[0].selector, "google");
    assert.equal(report.records[0].envelopeFrom, "");
  });
  test("Microsoft report: xsd/xsi namespaces, version, envelope_to, fo, IPv6 canonicalized", () => {
    const { report } = parseAggregateXml(MICROSOFT, "ms.xml");
    assert.equal(report.org, "Enterprise Outlook");
    assert.equal(report.version, "1.0");
    assert.equal(report.schema, "rfc7489");
    assert.equal(report.policy.fo, "0");
    const r = report.records[0];
    assert.equal(r.envelopeTo, "corp.test.darknode.ai");
    assert.equal(r.disposition, "quarantine");
    assert.equal(r.ip, "2001:db8::1f");
  });
  test("Yahoo report without sp: sp empty, pct read", () => {
    const { report } = parseAggregateXml(YAHOO, "y.xml");
    assert.equal(report.policy.sp, "");
    assert.equal(report.policy.p, "reject");
    assert.equal(report.records[0].spf[0].scope, "");
  });
  test("DMARCbis default namespace, discovery_method and testing", () => {
    const { report } = parseAggregateXml(BIS, "bis.xml");
    assert.equal(report.schema, "dmarcbis");
    assert.equal(report.policy.discovery, "treewalk");
    assert.equal(report.policy.testing, "n");
    assert.equal(report.policy.adkim, "s");
    assert.equal(report.policy.pct, 100);
    assert.equal(detectFile({ name: "b.xml", text: BIS }).format, "rua-dmarcbis");
  });
  test("prefixed namespace tags are read", () => {
    const x = '<?xml version="1.0"?><d:feedback xmlns:d="urn:ietf:params:xml:ns:dmarc-2.0"><d:report_metadata><d:org_name>P</d:org_name><d:report_id>1</d:report_id><d:date_range><d:begin>1</d:begin><d:end>2</d:end></d:date_range></d:report_metadata><d:policy_published><d:domain>' + D + '</d:domain><d:p>none</d:p></d:policy_published><d:record><d:row><d:source_ip>192.0.2.1</d:source_ip><d:count>2</d:count></d:row><d:identifiers><d:header_from>' + D + "</d:header_from></d:identifiers></d:record></d:feedback>";
    const { report } = parseAggregateXml(x);
    assert.equal(report.records.length, 1);
    assert.equal(report.schema, "dmarcbis");
  });
  test("missing optional elements default (adkim/aspf r, pct 100)", () => {
    const x = "<feedback><report_metadata><org_name>o</org_name><report_id>1</report_id></report_metadata><policy_published><domain>" + D + "</domain><p>none</p></policy_published></feedback>";
    const { report } = parseAggregateXml(x);
    assert.deepEqual([report.policy.adkim, report.policy.aspf, report.policy.pct, report.begin], ["r", "r", 100, null]);
  });
  test("XML that is not a DMARC report is skipped with a reason", () => {
    const p = parseInput([{ name: "a.xml", text: "<?xml version='1.0'?><rss><channel/></rss>" }]);
    assert.equal(p.reports.length, 0);
    assert.ok(/not a DMARC aggregate report/.test(p.skipped[0].reason));
  });
  test("records with a bad count are rejected and counted", () => {
    const { report } = parseAggregateXml(rua({ records: [{ ...GOOD, n: "x" }, GOOD] }));
    assert.equal(report.records.length, 1);
    assert.equal(report.rejected, 1);
  });
  test("detectFile recognises every format", () => {
    assert.equal(detectFile({ text: GOOGLE }).format, "rua-xml");
    assert.equal(detectFile({ text: ARF }).format, "ruf-arf");
    assert.equal(detectFile({ text: PARSEDMARC_CSV }).format, "csv-parsedmarc");
    assert.equal(detectFile({ text: PARSEDMARC_CSV }).confidenceLabel, "high");
    assert.equal(detectFile({ text: "a,b\n1,2" }).confidenceLabel, "low");
    assert.equal(detectFile({ text: "" }).format, "empty");
  });
  test("parsedmarc CSV: lists split, alignment recomputed", () => {
    const r = analyze(parseInput([{ name: "agg.csv", text: PARSEDMARC_CSV }]));
    assert.equal(r.summary.reports, 1);
    assert.equal(r.summary.messages, 100);
    assert.equal(r.summary.pass, 60);
    const mc = r.tables.sources.find((s) => s.ip === "192.0.2.70");
    assert.equal(mc.classification, "Mailchimp");
    const m365 = r.tables.sources.find((s) => s.ip === "192.0.2.10");
    assert.equal(m365.serviceId, "m365");
  });
  test("generic CSV without required columns is skipped naming them", () => {
    const p = parseInput([{ name: "x.csv", text: "foo,bar\n1,2" }]);
    assert.ok(/source_ip, count, header_from/.test(p.skipped[0].reason));
  });
  test("generic CSV with a column mapping is analyzed (reporter evaluation fallback)", () => {
    const csv = "ip addr,n,from\n192.0.2.5,7," + D;
    const p = parseInput([{ name: "g.csv", text: csv, columns: { source_ip: "ip addr", count: "n", header_from: "from" } }]);
    const r = analyze(p);
    assert.equal(r.summary.messages, 7);
    assert.ok(r.skipped.some((s) => s.check === "alignment"));
  });
  test("ARF forensic report: key headers incl. a folded header", () => {
    const { report } = parseForensic(ARF, "f.eml");
    assert.equal(report.feedbackType, "auth-failure");
    assert.equal(report.sourceIp, "203.0.113.9");
    assert.equal(report.reportedDomain, D);
    assert.equal(report.originalMailFrom, "ceo@" + D);
    assert.equal(report.arrivalDate, "Tue, 01 Sep 2026 10:00:00 +0000");
    assert.equal(report.authFailure, "dmarc");
  });
});

group("dmarcreports: de-duplication and archives", () => {
  test("same org + report_id counted once; another org with the same id is kept", () => {
    const a = rua({ org: "A", id: "dup", records: [GOOD] }), b = rua({ org: "B", id: "dup", records: [GOOD] });
    const p = parseInput([{ name: "1.xml", text: a }, { name: "2.xml", text: a }, { name: "3.xml", text: b }]);
    assert.equal(p.reports.length, 2);
    assert.equal(p.duplicates, 1);
    assert.equal(analyze(p).summary.messages, 200);
  });
  test("reports without report_id are de-duplicated by content", () => {
    const x = rua({ records: [GOOD] }).replace(/<report_id>[^<]*<\/report_id>/, "");
    const p = parseInput([{ name: "1.xml", text: x }, { name: "2.xml", text: x }]);
    assert.equal(p.reports.length, 1);
  });
  test("gzip round trip (Microsoft .xml.gz) through unpack", async () => {
    const gz = new Uint8Array(await new Response(new Blob([new TextEncoder().encode(MICROSOFT)]).stream().pipeThrough(new CompressionStream("gzip"))).arrayBuffer());
    const { entries } = await unpackAll(gz, { name: "enterprise.protection.outlook.com!x.xml.gz" });
    assert.equal(entries.length, 1);
    assert.ok(entries[0].name.endsWith(".xml"));
    const p = parseInput([{ name: entries[0].name, text: entries[0].text() }]);
    assert.equal(p.reports[0].org, "Enterprise Outlook");
  });
  test("zip round trip (Google .zip) with a nested .gz member", async () => {
    const gz = new Uint8Array(await new Response(new Blob([new TextEncoder().encode(YAHOO)]).stream().pipeThrough(new CompressionStream("gzip"))).arrayBuffer());
    const zip = await zipFiles([{ name: "google.com!x!1!2.xml", text: GOOGLE }, { name: "yahoo.xml.gz", bytes: gz }]);
    const { entries } = await unpackAll(zip, { name: "google.com!x.zip" });
    const p = parseInput(entries.map((e) => ({ name: e.name, text: e.text() })));
    assert.equal(p.reports.length, 2);
    assert.deepEqual(p.reports.map((r) => r.org).sort(), ["Yahoo", "google.com"]);
  });
  test("example zip goes through the real unpack path: 32 reports, 1 duplicate, 1 forensic", async () => {
    const ex = exampleDataset();
    const zip = await zipFiles(ex.files.map((f) => ({ name: f.name, text: f.text })));
    const { entries } = await unpackAll(zip, { name: "example.zip", maxEntries: 5000 });
    const p = parseInput(entries.map((e) => ({ name: e.name, text: e.text() })));
    assert.equal(p.reports.length, 32);
    assert.equal(p.duplicates, 1);
    assert.equal(p.forensic.length, 1);
  });
});

group("dmarcreports: alignment and organizational domain", () => {
  test("org domain with the public-suffix subset", () => {
    assert.equal(orgDomain("mail.shop.northwind-test.co.uk"), "northwind-test.co.uk");
    assert.equal(orgDomain("a.b.example-test.com.au."), "example-test.com.au");
    assert.equal(orgDomain("X.Y.Z.test.darknode.ai"), "darknode.ai");
    assert.equal(orgDomain("bucket.s3.amazonaws.com"), "bucket.s3.amazonaws.com");
    assert.ok(PSL_SUBSET.includes("co.jp") && PSL_SUBSET.includes("com.br") && PSL_SUBSET.includes("co.za"));
  });
  test("relaxed aligns subdomains, strict does not", () => {
    assert.ok(aligned("em1." + D, D, "r"));
    assert.ok(!aligned("em1." + D, D, "s"));
    assert.ok(aligned(D.toUpperCase(), D, "s"));
  });
  test("different registrable domains under co.uk do not align", () => {
    assert.ok(!aligned("a-test.co.uk", "b-test.co.uk", "r"));
    assert.ok(aligned("x.a-test.co.uk", "a-test.co.uk", "r"));
  });
  test("DKIM aligned pass alone passes DMARC", () => {
    const ev = evaluateRecord({ headerFrom: D, envelopeFrom: "x.mcsv.net", dkim: [{ domain: D, result: "pass" }], spf: [{ domain: "x.mcsv.net", scope: "mfrom", result: "pass" }] }, { adkim: "r", aspf: "r" });
    assert.deepEqual([ev.dkimAligned, ev.spfAligned, ev.pass], [true, false, true]);
  });
  test("HELO scope is ignored when an mfrom result exists", () => {
    const ev = evaluateRecord({ headerFrom: D, dkim: [], spf: [{ domain: D, scope: "helo", result: "pass" }, { domain: "x.test.darknode.ai", scope: "mfrom", result: "fail" }] }, { adkim: "r", aspf: "r" });
    assert.equal(ev.spfAligned, false);
  });
  test("empty SPF domain falls back to envelope_from", () => {
    const ev = evaluateRecord({ headerFrom: D, envelopeFrom: "b." + D, dkim: [], spf: [{ domain: "", scope: "mfrom", result: "pass" }] }, { adkim: "r", aspf: "r" });
    assert.ok(ev.spfAligned);
  });
  test("strict adkim rejects a subdomain signature; a failed signature never counts", () => {
    assert.ok(!evaluateRecord({ headerFrom: D, dkim: [{ domain: "m." + D, result: "pass" }], spf: [] }, { adkim: "s" }).pass);
    assert.ok(!evaluateRecord({ headerFrom: D, dkim: [{ domain: D, result: "fail" }], spf: [] }, { adkim: "r" }).pass);
  });
});

group("dmarcreports: IP handling", () => {
  test("IPv6 expand / RFC 5952 compress, IPv4-mapped", () => {
    assert.equal(expandIPv6("2001:db8::1"), "2001:0db8:0000:0000:0000:0000:0000:0001");
    assert.equal(compressIPv6("2001:0DB8:0:0:1:0:0:1"), "2001:db8::1:0:0:1");
    assert.equal(compressIPv6("::ffff:192.0.2.1"), "::ffff:c000:201");
    assert.equal(expandIPv6("1::2::3"), "");
  });
  test("PTR names for IPv4 and IPv6", () => {
    assert.equal(ptrName("192.0.2.25"), "25.2.0.192.in-addr.arpa");
    assert.equal(ptrName("2001:db8::1"), "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa");
    assert.equal(ptrName("not-an-ip"), "");
  });
  test("IPv4 validation and passthrough of unparseable values", () => {
    assert.ok(isIPv4("203.0.113.9"));
    assert.ok(!isIPv4("256.1.1.1") && !isIPv4("01.2.3.4"));
    assert.equal(normIp(" Bogus "), "bogus");
  });
  test("different spellings of one IPv6 address aggregate into one source", () => {
    const r = analyze([{ name: "a.xml", text: rua({ records: [{ ...GOOD, ip: "2001:db8:0:0::5" }, { ...GOOD, ip: "2001:DB8::5" }] }) }]);
    assert.equal(r.tables.sources.length, 1);
    assert.equal(r.tables.sources[0].messages, 200);
    assert.equal(r.tables.sources[0].ipVersion, 6);
  });
});

group("dmarcreports: sender classification", () => {
  test("by DKIM d= (SendGrid) and by return-path (Amazon SES)", () => {
    const r = analyze([{ name: "a.xml", text: rua({ records: [
      { ip: "192.0.2.40", n: 5, dkim: [["sendgrid.info", "pass", "smtpapi"]], spf: [["sendgrid.net", "pass"]], ef: "sendgrid.net" },
      { ip: "192.0.2.41", n: 5, dkim: [], spf: [["eu-west-1.amazonses.com", "pass"]], ef: "eu-west-1.amazonses.com" },
    ] }) }]);
    assert.equal(r.tables.sources.find((s) => s.ip === "192.0.2.40").serviceId, "sendgrid");
    assert.equal(r.tables.sources.find((s) => s.ip === "192.0.2.41").serviceId, "amazonses");
    assert.ok(ESP_TABLE.length >= 20);
  });
  test("selector-only match gives review confidence on the misalignment finding", () => {
    const r = analyze([{ name: "a.xml", text: rua({ records: [{ ip: "192.0.2.50", n: 30, dkim: [["unrelated-test.net", "pass", "zendesk1"]], spf: [["unrelated-test.net", "pass"]] }] }) }]);
    const f = find(r, "dmr-esp-zendesk");
    assert.ok(f, ids(r).join(","));
    assert.equal(f.confidence, "review");
  });
  test("outlook.com forwarding is exact; protection.outlook.com stays Microsoft 365", () => {
    const r = analyze([{ name: "a.xml", text: rua({ records: [
      { ip: "192.0.2.60", n: 5, dkim: [], spf: [["northwind.mail.protection.outlook.com", "pass"]] },
      { ip: "192.0.2.61", n: 5, dkim: [], spf: [["outlook.com", "pass"]] },
    ] }) }]);
    assert.equal(r.tables.sources.find((s) => s.ip === "192.0.2.60").serviceId, "m365");
    assert.equal(r.tables.sources.find((s) => s.ip === "192.0.2.61").kind, "forwarder");
  });
  test("forwarding signature (DKIM aligned, own SPF fails) is forwarding, not spoofing", () => {
    const r = analyze([{ name: "a.xml", text: rua({ records: [{ ip: "2001:db8:4b::25", n: 300, dkim: [[D, "pass", "s9"]], spf: [[D, "softfail"]], ef: D }] }) }]);
    const s = r.tables.sources[0];
    assert.equal(s.kind, "forwarder");
    assert.ok(find(r, "dmr-fwd-"));
    assert.ok(!find(r, "dmr-spoof-"));
  });
  test("mailing_list override reason classifies as forwarding", () => {
    const r = analyze([{ name: "a.xml", text: rua({ records: [{ ip: "192.0.2.150", n: 200, dkim: [[D, "fail"]], spf: [["lists.test.darknode.ai", "pass"]], reason: "mailing_list" }] }) }]);
    assert.equal(r.tables.sources[0].kind, "forwarder");
    assert.ok(!find(r, "dmr-spoof-"));
  });
});

group("dmarcreports: detections", () => {
  test("p=none > noneDays with high pass rate: medium, ready for quarantine", () => {
    const r = analyze(series(31, { records: [GOOD] }));
    const f = find(r, "dmr-policy-none-");
    assert.equal(f.severity, "medium");
    assert.ok(/ready for quarantine/.test(f.title));
  });
  test("p=none exactly at noneDays is silent (edge)", () => {
    const r = analyze(series(30, { records: [GOOD] }));
    assert.ok(!find(r, "dmr-policy-none-"));
    assert.ok(find(analyze(series(30, { records: [GOOD] }), { noneDays: 29 }), "dmr-policy-none-"));
  });
  test("p=none with failing senders is low and points at the plan", () => {
    const mc = { ip: "192.0.2.70", n: 50, dkim: [["mcsv.net", "pass", "k1"]], spf: [["mail1.mcsv.net", "pass"]], ef: "mail1.mcsv.net" };
    const r = analyze(series(31, { records: [GOOD, mc] }));
    assert.equal(find(r, "dmr-policy-none-").severity, "low");
    const e = find(r, "dmr-esp-mailchimp");
    assert.equal(e.severity, "medium");
    assert.ok(/d=northwind.test.darknode.ai/.test(e.recommendation));
  });
  test("misaligned service under senderMinMessages is not reported", () => {
    const mc = { ip: "192.0.2.70", n: 3, dkim: [["mcsv.net", "pass", "k1"]], spf: [["mail1.mcsv.net", "pass"]] };
    assert.ok(!find(analyze([{ name: "a.xml", text: rua({ records: [GOOD, mc] }) }]), "dmr-esp-"));
  });
  test("spoofing: high above spoofMin, medium at exactly spoofMin", () => {
    const hi = analyze([{ name: "a.xml", text: rua({ records: [GOOD, SPOOF("198.51.100.1", 60), SPOOF("198.51.100.2", 41)] }) }]);
    assert.equal(find(hi, "dmr-spoof-").severity, "high");
    assert.equal(find(hi, "dmr-spoof-").assets.filter((a) => a.type === "IP").length, 2);
    const eq = analyze([{ name: "a.xml", text: rua({ records: [GOOD, SPOOF("198.51.100.1", 100)] }) }]);
    assert.equal(find(eq, "dmr-spoof-").severity, "medium");
  });
  test("spoofing blocked under p=reject is low", () => {
    const r = analyze([{ name: "a.xml", text: rua({ policy: { p: "reject" }, records: [GOOD, { ...SPOOF("198.51.100.1", 500), disp: "reject" }] }) }]);
    const f = find(r, "dmr-spoof-");
    assert.equal(f.severity, "low");
    assert.ok(/blocked/.test(f.title));
  });
  test("no spoofing finding when everything passes", () => {
    assert.ok(!find(analyze([{ name: "a.xml", text: rua({ records: [GOOD] }) }]), "dmr-spoof-"));
  });
  test("IP assets are capped at 50 and evidence at 50 with the full count kept", () => {
    const recs = Array.from({ length: 60 }, (_, i) => SPOOF("203.0.113." + (i + 1), 5));
    const f = find(analyze([{ name: "a.xml", text: rua({ records: recs }) }]), "dmr-spoof-");
    assert.equal(f.assets.filter((a) => a.type === "IP").length, 50);
    assert.equal(f.evidence.length, 50);
    assert.equal(f.evidenceCount, 60);
  });
  test("subdomain spoofing with sp missing and p=none; names domains not in the known list", () => {
    const r = analyze([{ name: "a.xml", text: rua({ records: [GOOD, { ...SPOOF("203.0.113.66", 150), hf: "billing." + D, spf: [["billing." + D, "none"]] }] }) }], { knownDomains: D + "\nnews." + D });
    const f = find(r, "dmr-subspoof-");
    assert.equal(f.severity, "high");
    assert.ok(/not set, inherits p=none/.test(f.description));
    assert.ok(/Not in your known sending domains: billing/.test(f.description));
    assert.equal(r.tables.domains.find((d) => d.domain === "billing." + D).isSubdomain, true);
  });
  test("subdomain spoofing under sp=reject is low; no subdomains means no finding", () => {
    const r = analyze([{ name: "a.xml", text: rua({ policy: { p: "none", sp: "reject" }, records: [{ ...SPOOF("203.0.113.66", 150), hf: "billing." + D }] }) }]);
    assert.equal(find(r, "dmr-subspoof-").severity, "low");
    assert.ok(!find(analyze([{ name: "a.xml", text: rua({ records: [GOOD, SPOOF("198.51.100.1", 5)] }) }]), "dmr-subspoof-"));
  });
  test("pct below 100 held too long fires; pct=100 does not", () => {
    const r = analyze(series(31, { policy: { p: "quarantine", pct: 25 }, records: [GOOD] }));
    assert.ok(/pct=25 kept for 31 days/.test(find(r, "dmr-pct-").title));
    assert.ok(!find(analyze(series(31, { policy: { p: "quarantine", pct: 100 }, records: [GOOD] })), "dmr-pct-"));
  });
  test("np absent: info for DMARCbis reports, silent with np, skipped for RFC 7489 only", () => {
    const ns = "urn:ietf:params:xml:ns:dmarc-2.0";
    assert.equal(find(analyze([{ name: "a.xml", text: rua({ ns, records: [GOOD] }) }]), "dmr-np-").severity, "info");
    assert.ok(!find(analyze([{ name: "a.xml", text: rua({ ns, policy: { np: "reject" }, records: [GOOD] }) }]), "dmr-np-"));
    const r = analyze([{ name: "a.xml", text: rua({ records: [GOOD] }) }]);
    assert.ok(!find(r, "dmr-np-"));
    assert.ok(r.skipped.some((s) => s.check === "np_absent"));
  });
  test("reporter disagreement: positive and negative", () => {
    const bad = analyze([{ name: "a.xml", text: rua({ records: [{ ...GOOD, es: "fail" }] }) }]);
    const f = find(bad, "dmr-mismatch");
    assert.equal(f.confidence, "review");
    assert.ok(/SPF: reporter fail, recomputed pass/.test(f.evidence[0].differences));
    assert.ok(!find(analyze([{ name: "a.xml", text: rua({ records: [GOOD] }) }]), "dmr-mismatch"));
  });
  test("p=reject not applied without an override reason is reported", () => {
    const r = analyze([{ name: "a.xml", text: rua({ policy: { p: "reject" }, records: [SPOOF("198.51.100.1", 5)] }) }]);
    assert.ok(/p=reject not applied/.test(find(r, "dmr-mismatch").evidence[0].differences));
  });
});

group("dmarcreports: live checks (results passed in)", () => {
  const base = () => [{ name: "a.xml", text: rua({ records: [GOOD] }) }];
  test("SPF lookup limit is skipped offline", () => {
    const r = analyze(base());
    assert.ok(r.skipped.some((s) => s.check === "spf_lookup_limit" && /live check only/.test(s.reason)));
  });
  test("SPF over 10 lookups through includes is high; 10 or fewer is silent", () => {
    const inc = (n, pre) => Array.from({ length: n }, (_, i) => "include:" + pre + i + ".test.darknode.ai").join(" ");
    const includes = {};
    for (let i = 0; i < 6; i++) includes["a" + i + ".test.darknode.ai"] = ["v=spf1 ip4:192.0.2.0/24 -all"];
    includes["a5.test.darknode.ai"] = ["v=spf1 " + inc(5, "b") + " -all"];
    for (let i = 0; i < 5; i++) includes["b" + i + ".test.darknode.ai"] = ["v=spf1 -all"];
    const live = { checkedAt: "2026-10-16T00:00:00Z", domains: { [D]: { spf: { txt: ["v=spf1 " + inc(6, "a") + " -all"], includes } } } };
    const f = find(analyze(base(), { live }), "dmr-spf-limit-");
    assert.equal(f.severity, "high");
    assert.ok(/11 DNS lookups/.test(f.title));
    const ok = { checkedAt: "x", domains: { [D]: { spf: { txt: ["v=spf1 include:_spf.google.com -all"], includes: { "_spf.google.com": ["v=spf1 ip4:192.0.2.0/24 ~all"] } } } } };
    assert.ok(!find(analyze(base(), { live: ok }), "dmr-spf-limit-"));
  });
  test("network failure is reported as skipped, never as pass or fail", () => {
    const r = analyze(base(), { live: { domains: { [D]: { spf: { error: "timeout" }, dmarc: { error: "HTTP 503" } } } } });
    assert.ok(r.skipped.some((s) => /SPF lookup failed \(timeout\)/.test(s.reason)));
    assert.ok(r.skipped.some((s) => /DMARC lookup failed/.test(s.reason)));
    assert.ok(!r.findings.some((f) => /^dmr-(spf|live)/.test(f.id)));
  });
  test("DMARC record missing now is high; changed policy is info", () => {
    assert.equal(find(analyze(base(), { live: { domains: { [D]: { dmarc: { txt: [] } } } } }), "dmr-live-nodmarc-").severity, "high");
    const ch = find(analyze(base(), { live: { domains: { [D]: { dmarc: { txt: ["v=DMARC1; p=quarantine; pct=50; rua=mailto:r@" + D] } } } } }), "dmr-live-changed-");
    assert.equal(ch.severity, "info");
    assert.ok(/p=quarantine/.test(ch.description));
  });
  test("DKIM selector seen in reports but not published now", () => {
    const r = analyze(base());
    assert.ok(r.tables.selectorsSeen.some((s) => s.domain === D && s.selector === "selector1"));
    const f = find(analyze(base(), { live: { domains: { [D]: { dkim: { selector1: { txt: [] } } } } } }), "dmr-live-dkim-");
    assert.ok(/selector1/.test(f.description));
    assert.ok(!find(analyze(base(), { live: { domains: { [D]: { dkim: { selector1: { txt: ["v=DKIM1; k=rsa; p=MIIB"] } } } } } }), "dmr-live-dkim-"));
  });
  test("spfTotalLookups walks includes and lists unresolved names", () => {
    const t = spfTotalLookups(D, { [D]: ["v=spf1 mx include:x.test.darknode.ai include:gone.test.darknode.ai -all"], "x.test.darknode.ai": ["v=spf1 a -all"] });
    assert.equal(t.total, 4);
    assert.deepEqual(t.unresolved, ["gone.test.darknode.ai"]);
  });
  test("spfTotalLookups counts a shared include once per evaluation", () => {
    const t = spfTotalLookups(D, { [D]: ["v=spf1 include:a.test.darknode.ai include:b.test.darknode.ai -all"], "a.test.darknode.ai": ["v=spf1 include:g.test.darknode.ai -all"], "b.test.darknode.ai": ["v=spf1 include:g.test.darknode.ai -all"], "g.test.darknode.ai": ["v=spf1 a mx exists:x.test.darknode.ai ptr -all"] });
    assert.equal(t.total, 12);
    const loop = spfTotalLookups(D, { [D]: ["v=spf1 include:a.test.darknode.ai -all"], "a.test.darknode.ai": ["v=spf1 include:" + D + " -all"] });
    assert.equal(loop.total, 2);
  });
  test("PTR names appear on sources only after a lookup", () => {
    assert.equal(analyze(base()).tables.sources[0].ptr, undefined);
    const r = analyze(base(), { live: { ptr: { "192.0.2.10": ["mail-a.test.darknode.ai"] }, domains: {} } });
    assert.equal(r.tables.sources[0].ptr, "mail-a.test.darknode.ai");
  });
});

group("dmarcreports: progression plan", () => {
  test("stage mapping from p / pct", () => {
    assert.equal(stageIndex("none", 100), 0);
    assert.equal(stageIndex("quarantine", 10), 1);
    assert.equal(stageIndex("quarantine", 30), 2);
    assert.equal(stageIndex("quarantine", 5), 1);
    assert.equal(stageIndex("reject", 100), 8);
  });
  test("ready to advance when everything passes long enough; estimate uses next pct", () => {
    const r = analyze(series(20, { records: [GOOD, SPOOF("198.51.100.1", 10)] }));
    const p = r.tables.plan[0];
    assert.equal(p.ready, true);
    assert.equal(p.next.label, "p=quarantine pct=10");
    assert.equal(p.estimate.unknown, 20); // 200 failing x 10%
    assert.equal(p.estimate.legitimate, 0);
    assert.equal(p.stages[1].status, "next: ready");
  });
  test("blocked by too few days, then by a failing service with its fix", () => {
    const short = analyze(series(5, { records: [GOOD] })).tables.plan[0];
    assert.equal(short.ready, false);
    assert.ok(short.reasons.some((x) => /Only 5 day/.test(x)));
    const mc = { ip: "192.0.2.70", n: 50, dkim: [["mcsv.net", "pass", "k1"]], spf: [["mail1.mcsv.net", "pass"]] };
    const blk = analyze(series(20, { policy: { p: "quarantine", pct: 50 }, records: [GOOD, mc] })).tables.plan[0];
    assert.equal(blk.current.index, 3);
    assert.equal(blk.blockers[0].sender, "Mailchimp");
    assert.ok(/k2._domainkey/.test(blk.blockers[0].fix));
    assert.equal(blk.estimate.legitimate, 1000); // 1000 failing x 100% at quarantine pct=100
  });
  test("p=reject pct=100 has no next stage", () => {
    const p = analyze(series(20, { policy: { p: "reject" }, records: [GOOD] })).tables.plan[0];
    assert.equal(p.next, null);
    assert.equal(p.stages[8].status, "current");
  });
  test("policy changes reset the days counted at the current stage", () => {
    const a = series(10, { idp: "a", policy: { p: "none" }, records: [GOOD] });
    const b = Array.from({ length: 4 }, (_, i) => ({ name: "q" + i + ".xml", text: rua({ id: "q" + i, begin: 1788220800 + (10 + i) * 86400, policy: { p: "quarantine", pct: 10 }, records: [GOOD] }) }));
    const p = analyze([...a, ...b]).tables.plan[0];
    assert.equal(p.daysAtCurrent, 4);
    assert.equal(p.current.label, "p=quarantine pct=10");
  });
});

group("dmarcreports: tables, exports, determinism", () => {
  test("daily, domains and reporters tables", () => {
    const r = analyze(series(3, { records: [GOOD, SPOOF("198.51.100.1", 5)] }));
    assert.deepEqual(r.tables.daily.map((d) => [d.date, d.pass, d.fail]), [["2026-09-01", 100, 5], ["2026-09-02", 100, 5], ["2026-09-03", 100, 5]]);
    assert.equal(r.tables.domains[0].passPct, 95.2);
    assert.equal(r.tables.reporters[0].reports, 3);
    assert.equal(r.tables.reporters[0].first, "2026-09-01");
  });
  test("analyze is byte-identical and file-order independent", () => {
    const ex = exampleDataset();
    const a = JSON.stringify(analyze(ex.files));
    assert.equal(a, JSON.stringify(analyze(ex.files)));
    assert.equal(a, JSON.stringify(analyze(ex.files.slice().reverse())));
  });
  test("progress callback is called", () => {
    const calls = [];
    analyze(exampleDataset().files, {}, { progress: (i, n, l) => calls.push(l) });
    assert.ok(calls.includes("parsing reports") && calls.includes("done"));
  });
  test("example: documentation address space only, expected findings", () => {
    const ex = exampleDataset();
    const r = analyze(ex.files);
    for (const s of r.tables.sources) assert.ok(/^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|2001:db8:)/.test(s.ip), s.ip);
    for (const id of ["dmr-esp-mailchimp", "dmr-spoof-", "dmr-subspoof-", "dmr-policy-none-", "dmr-np-", "dmr-mismatch", "dmr-fwd-"]) assert.ok(find(r, id), id);
    assert.ok(r.tables.senders.some((s) => s.sender === "Twilio SendGrid" && s.dmarcPassPct === 100));
  });
  test("selfTest passes", () => {
    const r = selfTest();
    assert.ok(r.pass, "failed: " + r.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });
  test("findingsToCsv header and formula-injection guard", () => {
    const csv = findingsToCsv([{ id: "x", severity: "low", confidence: "review", category: "c", title: "=HYPERLINK(1)", description: 'a "b", c', recommendation: "r", controls: [{ framework: "RFC 7489", id: "3.1" }], assets: [{ type: "DOMAIN", name: D }], evidenceCount: 3 }]);
    const lines = csv.trim().split("\n");
    assert.equal(lines[0], "id,severity,confidence,category,title,description,recommendation,controls,assets,evidenceCount");
    assert.ok(lines[1].includes("'=HYPERLINK(1)"));
    assert.ok(lines[1].includes('"a ""b"", c"'));
  });
  test("sources CSV, fix list, plan and summary texts", () => {
    const r = analyze(exampleDataset().files);
    assert.ok(sourcesToCsv(r.tables.sources).startsWith("ip,ptr,headerFrom,messages"));
    const fix = fixListText(r);
    assert.ok(/Mailchimp sending as testorg.test.darknode.ai/.test(fix));
    assert.ok(/<angle brackets>/.test(fix));
    assert.ok(/\[next: blocked\] p=quarantine pct=10/.test(planText(r)));
    assert.ok(/Reports: 32 \(1 duplicates removed\)/.test(summaryText(r)));
  });
  test("every finding has controls, a recommendation and a valid severity", () => {
    const r = analyze(exampleDataset().files);
    for (const f of r.findings) {
      assert.ok(f.controls.length >= 1 && f.recommendation && ["critical", "high", "medium", "low", "info"].includes(f.severity) && ["confirmed", "likely", "review"].includes(f.confidence), f.id);
    }
  });
  test("empty input yields zero findings and does not throw", () => {
    const r = analyze(parseInput(""));
    assert.equal(r.findings.length, 0);
    assert.equal(r.meta.rows, 0);
    assert.equal(DEFAULTS.noneDays, 30);
    assert.equal(DEFAULTS.spoofMin, 100);
  });
});
