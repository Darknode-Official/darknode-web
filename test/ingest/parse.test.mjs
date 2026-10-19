// Shared ingest kit tests (public/js/ingest/parse.js): format sniffing on
// inline fixtures for every format, CSV / JSON / NDJSON iteration, the
// dependency-free XML tree, header mapping, CEF / LEEF, the YAML subset, the
// HCL2 subset and determinism.

import { test, assert, group } from "../harness.mjs";
import {
  sniff, decodeText, iterCsv, parseCsv, iterNdjson, iterJson, iterRecords,
  parseXml, xmlLite, xmlFind, xmlFindAll, xmlText,
  findColumn, normHeader, mapColumns, flatten,
  parseCef, parseLeef, parseYamlSubset, parseHcl,
} from "../../public/js/ingest/parse.js";

const utf8 = (s) => new TextEncoder().encode(s);

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------
const ENTRA_CSV = 'Date (UTC),Request ID,User agent,Correlation ID,User ID,User,Username,User type,Cross tenant access type,Incoming token type,Authentication Protocol,Unique token identifier,Original transfer method,Client credential type,Token Protection - Sign In Session,Application,Application ID,Resource,Resource ID,Resource tenant ID,Resource owner tenant ID,Home tenant ID,Home tenant name,IP address,Location,Status,Sign-in error code,Failure reason,Client app,Device ID,Browser,Operating System,Compliant,Managed,Join Type,Multifactor authentication result,Multifactor authentication auth method,Multifactor authentication auth detail,Authentication requirement,Sign-in identifier,Session ID,IP address (seen by resource),Through Global Secure Access,Global Secure Access IP address,Autonomous system number,Flagged for review,Token issuer type,Incoming token type,Token issuer name,Latency,Conditional Access,Managed Identity type,Associated Resource Id,Federated Token Id,Federated Token Issuer\n2026-10-01T08:00:00Z,0f1,Mozilla/5.0,abc,u1,Test User,test@darknode.ai,Member,none,none,none,x,none,none,Unbound,Office 365,00000003,Microsoft Graph,00000003,t1,t1,t1,Darknode,203.0.113.5,"Oslo, Oslo, NO",Success,0,,Browser,,Chrome 130,Windows 11,,,,MFA requirement satisfied by claim in the token,,,Multifactor authentication,test@darknode.ai,s1,,,,,,,,,,,,,,\n';

const OKTA_NDJSON = '{"uuid":"1","published":"2026-10-01T08:00:00.000Z","eventType":"user.session.start","outcome":{"result":"SUCCESS"},"actor":{"alternateId":"test@darknode.ai"},"client":{"ipAddress":"203.0.113.5"}}\n{"uuid":"2","published":"2026-10-01T08:01:00.000Z","eventType":"user.authentication.sso","outcome":{"result":"SUCCESS"},"actor":{"alternateId":"test@darknode.ai"},"client":{"ipAddress":"203.0.113.5"}}\n';

const CLOUDTRAIL = '{"Records":[{"eventVersion":"1.08","eventTime":"2026-10-01T08:00:00Z","eventName":"ConsoleLogin","userIdentity":{"type":"IAMUser","userName":"test"}},{"eventVersion":"1.08","eventTime":"2026-10-01T08:05:00Z","eventName":"CreateUser","userIdentity":{"type":"IAMUser","userName":"test"}}]}';

const WIN_EVENT = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/><EventID>4624</EventID><TimeCreated SystemTime="2026-10-01T08:00:00.000000000Z"/><Computer>WS01.darknode.local</Computer></System><EventData><Data Name="TargetUserName">test</Data><Data Name="LogonType">10</Data><Data Name="IpAddress">203.0.113.5</Data></EventData></Event>';

const CEF_LINE = 'Oct 11 22:14:15 fw01 CEF:0|Palo Alto Networks|PAN-OS|10.2|THREAT|Vulnerability Exploit \\| Attempt|9|src=203.0.113.5 dst=10.0.0.4 spt=51234 dpt=443 msg=SQLi attempt key\\=value path=C:\\\\temp act=blocked';
const LEEF_LINE = 'LEEF:2.0|IBM|QRadar|7.5|12345|^|src=203.0.113.5^dst=10.0.0.4^usrName=test@darknode.ai^cat=Login Failure';
const LEEF1_LINE = 'LEEF:1.0|Vendor|Product|1.0|evt1|src=1.2.3.4\tdst=5.6.7.8';
const IIS_LOG = '#Software: Microsoft Internet Information Services 10.0\n#Version: 1.0\n#Date: 2026-10-01 08:00:00\n#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken\n2026-10-01 08:00:00 10.0.0.4 GET /login - 443 - 203.0.113.5 Mozilla/5.0 - 200 0 0 12\n';
const NGINX_CLF = '203.0.113.5 - - [01/Oct/2026:08:00:00 +0000] "GET /login HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n203.0.113.6 - - [01/Oct/2026:08:00:01 +0000] "POST /api HTTP/1.1" 401 42 "-" "curl/8.0"\n';
const SYSLOG_BSD = 'Oct 11 22:14:15 host01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51234 ssh2\nOct 11 22:14:16 host01 sshd[1234]: Connection closed by 203.0.113.5 port 51234 [preauth]\n';
const SYSLOG_ISO = '<34>1 2026-10-01T08:00:00.000Z host01 su - ID47 - su root failed for test on /dev/pts/8\n2026-10-01T08:00:01Z host01 CRON[42]: (root) CMD (run-parts /etc/cron.hourly)\n';
const TERRAFORM = `# bucket
resource "aws_s3_bucket" "b" {
  bucket = "my-bucket" // trailing comment
  acl    = "private"
  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
  versioning {
    enabled = true
  }
  /* block
     comment */
  policy = <<EOF
{
  "Version": "2012-10-17"
}
EOF
  cidrs = ["10.0.0.0/8", "192.168.0.0/16"]
  count = 2
  arn_ref = aws_iam_role.r.arn
  name = "\${var.prefix}-bucket"
  size = -5
  expr = length(var.list) > 0 ? "yes" : "no"
  nothing = null
}
variable "prefix" {
  type    = string
  default = "dn"
}
`;
const K8S_YAML = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  labels:
    app: web
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: web
          image: nginx:1.27
          ports:
            - containerPort: 80
          env:
            - name: MODE
              value: "prod"
          securityContext:
            runAsNonRoot: true
            privileged: false
`;
const SEMI_CSV_BOM = '\uFEFFname;amount;currency\nAlice;1,50;EUR\nBob;2,25;EUR\n';
const TSV = 'id\tname\temail\n1\tAlice\ttest@darknode.ai\n2\tBob\ttest@darknode.ai\n';

// ---------------------------------------------------------------------------
group("ingest/sniff: magic bytes and binary", () => {
  test("zip magic", () => {
    const r = sniff(new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00]));
    assert.equal(r.format, "zip"); assert.equal(r.confidence, 1);
  });
  test("gzip magic via ArrayBuffer", () => {
    const r = sniff(new Uint8Array([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00]).buffer);
    assert.equal(r.format, "gzip"); assert.equal(r.confidence, 1);
  });
  test("binary garbage is unknown", () => {
    const b = new Uint8Array(512); for (let i = 0; i < b.length; i++) b[i] = (i * 7919 + 13) & 0xff;
    const r = sniff(b);
    assert.equal(r.format, "unknown"); assert.equal(r.confidence, 0);
  });
  test("empty input is unknown", () => { assert.equal(sniff("").format, "unknown"); assert.equal(sniff("   \n").format, "unknown"); });
});

group("ingest/sniff: JSON family", () => {
  test("CloudTrail Records wrapper is json", () => { const r = sniff(CLOUDTRAIL); assert.equal(r.format, "json"); assert.equal(r.confidence, 1); });
  test("array is json", () => assert.equal(sniff('[{"a":1},{"a":2}]').format, "json"));
  test("Okta NDJSON", () => { const r = sniff(OKTA_NDJSON); assert.equal(r.format, "ndjson"); assert.equal(r.confidence, 1); });
  test("truncated large JSON still reports json", () => { const r = sniff("[" + '{"a":1},'.repeat(100) + '{"a":1}]', { sample: 64 }); assert.equal(r.format, "json"); assert.ok(r.confidence < 1); });
});

group("ingest/sniff: XML", () => {
  test("Windows Event record is evtx-xml", () => assert.equal(sniff(WIN_EVENT).format, "evtx-xml"));
  test("prolog without Event is xml", () => assert.equal(sniff('<?xml version="1.0"?>\n<root><a/></root>').format, "xml"));
  test("prolog with Events is evtx-xml", () => assert.equal(sniff('<?xml version="1.0"?><Events>' + WIN_EVENT + "</Events>").format, "evtx-xml"));
});

group("ingest/sniff: log lines", () => {
  test("CEF with syslog prefix", () => { const r = sniff(CEF_LINE); assert.equal(r.format, "cef"); assert.equal(r.confidence, 1); });
  test("LEEF", () => assert.equal(sniff(LEEF_LINE).format, "leef"));
  test("IIS #Fields header", () => { const r = sniff(IIS_LOG); assert.equal(r.format, "iis"); assert.equal(r.confidence, 1); });
  test("nginx CLF", () => { const r = sniff(NGINX_CLF); assert.equal(r.format, "clf"); assert.equal(r.confidence, 1); });
  test("syslog BSD flavour", () => { const r = sniff(SYSLOG_BSD); assert.equal(r.format, "syslog"); assert.equal(r.confidence, 1); });
  test("syslog RFC5424 / ISO flavour", () => { const r = sniff(SYSLOG_ISO); assert.equal(r.format, "syslog"); assert.equal(r.confidence, 1); });
  test("confidence is the share of matching lines", () => { const r = sniff(SYSLOG_BSD + "garbage line here\n"); assert.equal(r.format, "syslog"); assert.equal(r.confidence, 0.667); });
});

group("ingest/sniff: config and delimited", () => {
  test("Terraform is hcl", () => { const r = sniff(TERRAFORM); assert.equal(r.format, "hcl"); assert.ok(r.confidence > 0.5); });
  test("K8s Deployment is yaml", () => { const r = sniff(K8S_YAML); assert.equal(r.format, "yaml"); assert.ok(r.confidence >= 0.9); });
  test("generic key: lines without delimiter consensus are yaml", () => assert.equal(sniff("name: CI\non: push\njobs: x\n").format, "yaml"));
  test("Entra sign-in CSV header row", () => { const r = sniff(ENTRA_CSV); assert.equal(r.format, "csv"); assert.equal(r.delimiter, ","); assert.equal(r.confidence, 1); });
  test("semicolon CSV with BOM", () => { const r = sniff(SEMI_CSV_BOM); assert.equal(r.format, "csv"); assert.equal(r.delimiter, ";"); assert.equal(r.bom, true); });
  test("TSV", () => { const r = sniff(TSV); assert.equal(r.format, "tsv"); assert.equal(r.delimiter, "\t"); });
  test("pipe-delimited", () => { const r = sniff("a|b|c\n1|2|3\n"); assert.equal(r.format, "csv"); assert.equal(r.delimiter, "|"); });
  test("bytes input reports encoding and bom", () => {
    const r = sniff(utf8(SEMI_CSV_BOM));
    assert.equal(r.format, "csv"); assert.equal(r.encoding, "utf-8"); assert.equal(r.bom, true);
  });
  test("prose without structure is unknown", () => assert.equal(sniff("just some words\nand more words\nnothing else\n").format, "unknown"));
});

group("ingest/decodeText", () => {
  test("utf-8 with BOM stripped", () => assert.equal(decodeText(new Uint8Array([0xef, 0xbb, 0xbf, 0x68, 0x69])), "hi"));
  test("utf-16le by BOM", () => assert.equal(decodeText(new Uint8Array([0xff, 0xfe, 0x68, 0, 0x69, 0])), "hi"));
  test("utf-16be by BOM", () => assert.equal(decodeText(new Uint8Array([0xfe, 0xff, 0, 0x68, 0, 0x69])), "hi"));
  test("string passthrough strips BOM", () => assert.equal(decodeText("\uFEFFx"), "x"));
});

group("ingest/iterCsv", () => {
  test("quoted newlines, CRLF, BOM, duplicate headers", () => {
    const rows = [...iterCsv('\uFEFFa,b,a,b\r\n1,"line1\nline2",3,"x ""q"""\r\n4,5,6,7\r\n')];
    assert.equal(rows.length, 2);
    assert.deepEqual(Object.keys(rows[0]), ["a", "b", "a_2", "b_2"]);
    assert.equal(rows[0].b, "line1\nline2");
    assert.equal(rows[0].b_2, 'x "q"');
    assert.equal(rows[1].a_2, "6");
  });
  test("semicolon delimiter auto-detected", () => {
    const rows = [...iterCsv(SEMI_CSV_BOM)];
    assert.deepEqual(rows[0], { name: "Alice", amount: "1,50", currency: "EUR" });
  });
  test("header=false yields arrays and skips empty rows", () => {
    const rows = [...iterCsv("a,b\n\n1,2\n,\n", { header: false })];
    assert.deepEqual(rows, [["a", "b"], ["1", "2"]], "a bare delimiter row is dropped like an all-empty EOF row");
  });
  test("short rows fill with empty strings", () => assert.deepEqual([...iterCsv("a,b,c\n1,2\n")][0], { a: "1", b: "2", c: "" }));
  test("a row of explicitly-quoted empty fields is kept (not dropped like a blank line)", () => {
    assert.deepEqual([...iterCsv('a,b\n"",""\nx,y', { header: false })], [["a", "b"], ["", ""], ["x", "y"]]);
  });
  test("parseCsv convenience", () => {
    const r = parseCsv(TSV);
    assert.deepEqual(r.headers, ["id", "name", "email"]);
    assert.equal(r.rows.length, 2); assert.equal(r.rows[1].name, "Bob");
  });
});

group("ingest/iterJson + iterNdjson", () => {
  test("wrapper keys unwrap (case-insensitive Records)", () => {
    assert.equal(iterJson(CLOUDTRAIL).length, 2);
    assert.equal(iterJson('{"value":[{"a":1}]}').length, 1);
    assert.equal(iterJson('{"events":[1,2,3]}').length, 3);
    assert.deepEqual(iterJson('{"items":[]}'), []);
  });
  test("bare object becomes [obj]", () => assert.deepEqual(iterJson('{"id":"x","name":"y"}'), [{ id: "x", name: "y" }]));
  test("bare array passes through", () => assert.deepEqual(iterJson("[1,2]"), [1, 2]));
  test("multi-line non-document falls back to NDJSON", () => assert.equal(iterJson(OKTA_NDJSON).length, 2));
  test("iterNdjson skips blanks and reports the failing line", () => {
    assert.equal([...iterNdjson('{"a":1}\n\n{"a":2}\n')].length, 2);
    let msg = "";
    try { [...iterNdjson('{"a":1}\n\n{bad\n')]; } catch (e) { msg = e.message; }
    assert.ok(/^NDJSON parse error at line 3: /.test(msg), msg);
  });
});

group("ingest/iterRecords", () => {
  test("dispatches csv / tsv / json / ndjson", () => {
    assert.equal([...iterRecords(ENTRA_CSV)].length, 1);
    assert.equal([...iterRecords(TSV)][0].email, "test@darknode.ai");
    assert.equal([...iterRecords(CLOUDTRAIL)].length, 2);
    assert.equal([...iterRecords(OKTA_NDJSON)].length, 2);
  });
  test("explicit format and bytes input", () => {
    assert.equal([...iterRecords(utf8(TSV), "tsv")].length, 2);
    assert.equal([...iterRecords(SEMI_CSV_BOM, "csv")][1].name, "Bob");
  });
  test("returns null for clf and other log formats", () => {
    assert.equal(iterRecords(NGINX_CLF), null);
    assert.equal(iterRecords(SYSLOG_BSD), null);
    assert.equal(iterRecords(WIN_EVENT), null);
    assert.equal(iterRecords(K8S_YAML, "yaml"), null);
  });
});

group("ingest/xmlLite", () => {
  const XML = '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE root [<!ENTITY x "y">]>\n<!-- comment -->\n<root a="1" b=\'two\' flag>\n  <item id="i1">Tom &amp; Jerry &lt;3 &#65;&#x42; &quot;q&quot; &apos;s&apos;</item>\n  <item id="i2"><![CDATA[<raw> & stuff]]></item>\n  <empty/>\n  <ns:tagged ns:attr="v">ns text</ns:tagged>\n</root>';
  test("tree shape, attrs, self-closing", () => {
    const root = xmlLite(XML);
    assert.equal(root.tag, "root");
    assert.deepEqual(root.attrs, { a: "1", b: "two", flag: "" });
    assert.equal(root.children.length, 4);
    assert.equal(root.children[2].tag, "empty");
    assert.deepEqual(root.children[2].children, []);
    assert.equal(root.text, "");
  });
  test("entities decoded", () => assert.equal(xmlLite(XML).children[0].text, 'Tom & Jerry <3 AB "q" \'s\''));
  test("CDATA kept raw", () => assert.equal(xmlLite(XML).children[1].text, "<raw> & stuff"));
  test("namespaces kept in tag and attr names", () => {
    const t = xmlLite(XML).children[3];
    assert.equal(t.tag, "ns:tagged"); assert.deepEqual(t.attrs, { "ns:attr": "v" });
  });
  test("xmlFind / xmlFindAll / xmlText on a Windows event", () => {
    const ev = xmlLite(WIN_EVENT);
    assert.equal(ev.tag, "Event");
    assert.equal(xmlText(xmlFind(ev, "EventID")), "4624");
    assert.equal(xmlFind(ev, "TimeCreated").attrs.SystemTime, "2026-10-01T08:00:00.000000000Z");
    const data = xmlFindAll(ev, "Data");
    assert.equal(data.length, 3);
    assert.equal(data.find((d) => d.attrs.Name === "IpAddress").text, "203.0.113.5");
    assert.equal(xmlFind(ev, "Nope"), null);
    assert.deepEqual(xmlFindAll(ev, "Nope"), []);
    assert.equal(xmlFind(xmlLite(XML), "tagged").text, "ns text", "local-name lookup through prefix");
  });
  test("concatenated roots get a #document wrapper; deep xmlText", () => {
    const doc = xmlLite(WIN_EVENT + WIN_EVENT);
    assert.equal(doc.tag, "#document");
    assert.equal(xmlFindAll(doc, "Event").length, 2);
    assert.equal(xmlText(xmlFind(doc, "System")), "4624WS01.darknode.local");
  });
  test("parseXml falls back to xmlLite outside the DOM", () => {
    const n = parseXml(WIN_EVENT);
    assert.equal(xmlText(xmlFind(n, "Computer")), "WS01.darknode.local");
  });
});

group("ingest/headers", () => {
  test("normHeader strips brackets, parens, case and symbols", () => {
    assert.equal(normHeader("Email Address [Required]"), "emailaddress");
    assert.equal(normHeader("IP address (seen by resource)"), "ipaddress");
    assert.equal(normHeader("  User-Principal_Name "), "userprincipalname");
  });
  test("findColumn alias order wins over header order", () => {
    const h = ["User", "Username", "User ID", "Email Address [Required]"];
    assert.equal(findColumn(h, ["userprincipalname", "username", "user"]), "Username");
    assert.equal(findColumn(h, ["Email Address", "user"]), "Email Address [Required]");
    assert.equal(findColumn(h, ["nothing"]), null);
  });
  test("mapColumns reports found and missing", () => {
    const r = mapColumns(ENTRA_CSV.split("\n")[0].split(","), { ts: ["date", "timestamp"], user: ["username", "user"], ip: ["ipaddress"], missing: ["does not exist"] });
    assert.deepEqual(r.found, { ts: "Date (UTC)", user: "Username", ip: "IP address" });
    assert.deepEqual(r.missing, ["missing"]);
  });
});

group("ingest/flatten", () => {
  test("dot paths, primitive arrays joined, object arrays indexed", () => {
    assert.deepEqual(flatten({ a: { b: 1, c: { d: "x" } }, tags: ["t1", "t2"], list: [{ id: 1 }, { id: 2 }], n: null, e: [] }),
      { "a.b": 1, "a.c.d": "x", tags: "t1, t2", "list.0.id": 1, "list.1.id": 2, n: null, e: "" });
  });
  test("primitive root lands on the prefix key", () => assert.deepEqual(flatten(5, "k"), { k: 5 }));
});

group("ingest/parseCef + parseLeef", () => {
  test("CEF header with escaped pipe, extension escapes, syslog prefix", () => {
    const c = parseCef(CEF_LINE);
    assert.equal(c.prefix, "Oct 11 22:14:15 fw01");
    assert.equal(c.version, 0); assert.equal(c.vendor, "Palo Alto Networks"); assert.equal(c.product, "PAN-OS");
    assert.equal(c.deviceVersion, "10.2"); assert.equal(c.signatureId, "THREAT");
    assert.equal(c.name, "Vulnerability Exploit | Attempt"); assert.equal(c.severity, 9);
    assert.deepEqual(c.ext, { src: "203.0.113.5", dst: "10.0.0.4", spt: "51234", dpt: "443", msg: "SQLi attempt key=value", path: "C:\\temp", act: "blocked" });
  });
  test("CEF non-numeric severity and empty extension; non-CEF is null", () => {
    const c = parseCef("CEF:0|V|P|1|id|Name|High|");
    assert.equal(c.severity, "High"); assert.deepEqual(c.ext, {}); assert.equal(c.prefix, null);
    assert.equal(parseCef("relay01|CEF:0|V|P|1|id|Name|3|a=1").prefix, "relay01", "pipe-separated prefix");
    assert.equal(parseCef("not cef at all"), null);
  });
  test("LEEF 2.0 with custom delimiter", () => {
    const l = parseLeef(LEEF_LINE);
    assert.equal(l.version, "2.0"); assert.equal(l.vendor, "IBM"); assert.equal(l.eventId, "12345"); assert.equal(l.delimiter, "^");
    assert.deepEqual(l.ext, { src: "203.0.113.5", dst: "10.0.0.4", usrName: "test@darknode.ai", cat: "Login Failure" });
  });
  test("LEEF 1.0 tab default and hex delimiter hint", () => {
    const l = parseLeef(LEEF1_LINE);
    assert.equal(l.delimiter, "\t"); assert.deepEqual(l.ext, { src: "1.2.3.4", dst: "5.6.7.8" });
    const h = parseLeef("LEEF:2.0|V|P|1|e|x7c|a=1|b=2");
    assert.equal(h.delimiter, "|"); assert.deepEqual(h.ext, { a: "1", b: "2" });
    assert.equal(parseLeef("CEF:0|a|b|c|d|e|f|"), null);
  });
});

group("ingest/parseYamlSubset", () => {
  test("nested K8s Deployment", () => {
    const d = parseYamlSubset(K8S_YAML);
    assert.equal(d.apiVersion, "apps/v1"); assert.equal(d.kind, "Deployment");
    assert.equal(d.metadata.labels.app, "web"); assert.equal(d.spec.replicas, 3);
    const c = d.spec.template.spec.containers[0];
    assert.equal(c.image, "nginx:1.27");
    assert.deepEqual(c.ports, [{ containerPort: 80 }]);
    assert.deepEqual(c.env, [{ name: "MODE", value: "prod" }]);
    assert.deepEqual(c.securityContext, { runAsNonRoot: true, privileged: false });
  });
  test("docker-compose with same-indent sequences, quotes and comments", () => {
    const d = parseYamlSubset(`version: "3.9"  # compose
services:
  web:
    image: 'nginx:latest'
    ports:
    - "8080:80"
    - 443:443
    environment:
      MODE: prod   # it's fine
      EMPTY:
    depends_on: [db, cache]
  db:
    image: postgres
volumes:
  data: {}
`);
    assert.equal(d.version, "3.9");
    assert.deepEqual(d.services.web.ports, ["8080:80", "443:443"]);
    assert.deepEqual(d.services.web.environment, { MODE: "prod", EMPTY: null });
    assert.deepEqual(d.services.web.depends_on, ["db", "cache"]);
    assert.deepEqual(d.volumes, { data: {} });
  });
  test("GitHub Actions on: map and steps", () => {
    const d = parseYamlSubset(`name: CI
on:
  push:
    branches: [main]
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Test
        run: npm test
        env: { CI: true, N: 1 }
`);
    assert.deepEqual(d.on, { push: { branches: ["main"] }, pull_request: null });
    assert.equal(d.jobs.build["runs-on"], "ubuntu-latest");
    assert.deepEqual(d.jobs.build.steps, [{ uses: "actions/checkout@v4" }, { name: "Test", run: "npm test", env: { CI: true, N: 1 } }]);
  });
  test("block scalars literal and folded with chomping", () => {
    const d = parseYamlSubset(`a: |
  line one
  line two

b: >-
  folded
  text

  para
c: |-
  keep
d: >
  x
`);
    assert.equal(d.a, "line one\nline two\n");
    assert.equal(d.b, "folded text\npara");
    assert.equal(d.c, "keep");
    assert.equal(d.d, "x\n");
  });
  test("scalars: types, quotes, escapes, plain multi-line", () => {
    const d = parseYamlSubset(`i: 42
f: 3.5
neg: -7
hex: 0xff
t: yes
n: ~
nul: null
dq: "tab\\tnew\\nq\\"x"
sq: 'it''s'
url: http://darknode.ai/x
long: this is a
  continued value
zip: 00501
star: "*/5 * * * *"
`);
    assert.equal(d.i, 42); assert.equal(d.f, 3.5); assert.equal(d.neg, -7); assert.equal(d.hex, 255);
    assert.equal(d.t, "yes"); assert.equal(d.n, null); assert.equal(d.nul, null);
    assert.equal(d.dq, 'tab\tnew\nq"x'); assert.equal(d.sq, "it's");
    assert.equal(d.url, "http://darknode.ai/x"); assert.equal(d.long, "this is a continued value");
    assert.equal(d.zip, "00501"); // zero-padded id stays a string, not 501
    assert.equal(d.star, "*/5 * * * *");
  });
  test("flow sequences and maps, nested", () => {
    assert.deepEqual(parseYamlSubset("x: [1, 'a, b', [2, 3], {k: v}]").x, [1, "a, b", [2, 3], { k: "v" }]);
    assert.deepEqual(parseYamlSubset("m: {a: 1, b: [x], c}").m, { a: 1, b: ["x"], c: null });
    assert.deepEqual(parseYamlSubset("- 1\n- two\n- [3]\n"), [1, "two", [3]]);
  });
  test("multi-document returns an array; single returns the doc", () => {
    const docs = parseYamlSubset("---\na: 1\n---\nb: 2\n...\n");
    assert.deepEqual(docs, [{ a: 1 }, { b: 2 }]);
    assert.deepEqual(parseYamlSubset("---\na: 1\n"), { a: 1 });
  });
  test("CloudFormation local tags become {tag: value}; anchors, aliases and !! tags throw", () => {
    const cf = parseYamlSubset(`AWSTemplateFormatVersion: "2010-09-09"
Resources:
  B:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub "\${AWS::StackName}-b"
      Arn: !GetAtt [B, Arn]
      Ref: !Ref Other
`);
    assert.deepEqual(cf.Resources.B.Properties.BucketName, { "!Sub": "${AWS::StackName}-b" });
    assert.deepEqual(cf.Resources.B.Properties.Arn, { "!GetAtt": ["B", "Arn"] });
    assert.deepEqual(cf.Resources.B.Properties.Ref, { "!Ref": "Other" });
    assert.throws(() => parseYamlSubset("base: &b\n  x: 1\nother: *b\n"));
    assert.throws(() => parseYamlSubset("a: *alias\n"));
    assert.throws(() => parseYamlSubset("a: !!str 5\n"));
    let msg = ""; try { parseYamlSubset("x: 1\ny: &a 2\n"); } catch (e) { msg = e.message; }
    assert.ok(/anchors.*line 2/.test(msg), msg);
  });
  test("bad indentation and non-key lines throw with a line number", () => {
    let msg = ""; try { parseYamlSubset("a: 1\n  b: 2\n"); } catch (e) { msg = e.message; }
    assert.ok(/line 2/.test(msg), msg);
    assert.throws(() => parseYamlSubset("a: 1\nnot a key\n"));
  });
});

group("ingest/parseHcl", () => {
  test("resource with nested block, map, list, heredoc, interpolation, refs, comments", () => {
    const h = parseHcl(TERRAFORM);
    assert.equal(h.blocks.length, 2);
    assert.deepEqual(h.attrs, {});
    const r = h.blocks[0];
    assert.equal(r.type, "resource"); assert.deepEqual(r.labels, ["aws_s3_bucket", "b"]);
    assert.equal(r.attrs.bucket, "my-bucket"); assert.equal(r.attrs.acl, "private");
    assert.deepEqual(r.attrs.tags, { Name: "My bucket", Environment: "Dev" });
    assert.deepEqual(r.blocks, [{ type: "versioning", labels: [], attrs: { enabled: true }, blocks: [] }]);
    assert.equal(r.attrs.policy, '{\n  "Version": "2012-10-17"\n}\n');
    assert.deepEqual(r.attrs.cidrs, ["10.0.0.0/8", "192.168.0.0/16"]);
    assert.equal(r.attrs.count, 2); assert.equal(r.attrs.size, -5); assert.equal(r.attrs.nothing, null);
    assert.deepEqual(r.attrs.arn_ref, { ref: "aws_iam_role.r.arn" });
    assert.equal(r.attrs.name, "${var.prefix}-bucket");
    assert.deepEqual(r.attrs.expr, { raw: 'length(var.list) > 0 ? "yes" : "no"' });
    const v = h.blocks[1];
    assert.equal(v.type, "variable"); assert.deepEqual(v.labels, ["prefix"]);
    assert.deepEqual(v.attrs, { type: { ref: "string" }, default: "dn" });
  });
  test("indented heredoc, multi-line list, object with colons, for-expressions raw, top-level attrs", () => {
    const h = parseHcl(`region = "eu-west-1"
locals {
  script = <<-EOT
    echo hi
      indented
    EOT
  ports = [
    80,
    443,
  ]
  obj = { "a": 1, b: "x" }
  names = [for s in var.list : upper(s)]
  idx = var.subnets[0].id
  splat = aws_instance.web[*].id
  esc = "say \\"hi\\"\\n"
  lit = "$\${literal}"
}
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  cidr = var.cidr
}
`);
    assert.equal(h.attrs.region, "eu-west-1");
    const l = h.blocks[0];
    assert.equal(l.type, "locals"); assert.deepEqual(l.labels, []);
    assert.equal(l.attrs.script, "echo hi\n  indented\n");
    assert.deepEqual(l.attrs.ports, [80, 443]);
    assert.deepEqual(l.attrs.obj, { a: 1, b: "x" });
    assert.deepEqual(l.attrs.names, { raw: "[for s in var.list : upper(s)]" });
    assert.deepEqual(l.attrs.idx, { ref: "var.subnets[0].id" });
    assert.deepEqual(l.attrs.splat, { ref: "aws_instance.web[*].id" });
    assert.equal(l.attrs.esc, 'say "hi"\n');
    assert.equal(l.attrs.lit, "${literal}");
    assert.equal(h.blocks[1].type, "module"); assert.deepEqual(h.blocks[1].labels, ["vpc"]);
    assert.deepEqual(h.blocks[1].attrs.cidr, { ref: "var.cidr" });
  });
  test("provider / data / output / terraform blocks with nested required_providers", () => {
    const h = parseHcl(`terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}
provider "aws" { region = var.region }
data "aws_ami" "u" { most_recent = true }
output "id" { value = data.aws_ami.u.id }
`);
    assert.deepEqual(h.blocks.map((b) => b.type), ["terraform", "provider", "data", "output"]);
    assert.deepEqual(h.blocks[0].blocks[0].attrs.aws, { source: "hashicorp/aws", version: "~> 5.0" });
    assert.deepEqual(h.blocks[3].attrs.value, { ref: "data.aws_ami.u.id" });
  });
  test("errors carry a line number", () => {
    let msg = ""; try { parseHcl('resource "a" "b" {\n  x = 1\n'); } catch (e) { msg = e.message; }
    assert.ok(/^HCL: .*line 3/.test(msg), msg);
    assert.throws(() => parseHcl('x = "unterminated\n'));
    assert.throws(() => parseHcl("x = <<EOF\nnever closed\n"));
  });
});

group("ingest/determinism", () => {
  test("sniff twice is identical", () => {
    for (const f of [ENTRA_CSV, OKTA_NDJSON, CLOUDTRAIL, WIN_EVENT, CEF_LINE, IIS_LOG, NGINX_CLF, SYSLOG_BSD, TERRAFORM, K8S_YAML, SEMI_CSV_BOM, TSV]) assert.deepEqual(sniff(f), sniff(f));
  });
  test("parsers twice are identical", () => {
    assert.deepEqual(parseYamlSubset(K8S_YAML), parseYamlSubset(K8S_YAML));
    assert.deepEqual(parseHcl(TERRAFORM), parseHcl(TERRAFORM));
    assert.deepEqual(xmlLite(WIN_EVENT), xmlLite(WIN_EVENT));
    assert.deepEqual(parseCef(CEF_LINE), parseCef(CEF_LINE));
    assert.deepEqual(parseCsv(ENTRA_CSV), parseCsv(ENTRA_CSV));
  });
});
