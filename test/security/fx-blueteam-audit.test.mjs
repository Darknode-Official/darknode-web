// Forensics and blue-team quick tools: fixes found by running every tool against
// ground truth (epoch definitions, RFC 5424 / LEEF / CEF / Apache formats) and by
// checking that generated rules, queries and commands survive quotes, spaces and
// other special characters in the values typed in.

import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS as FX } from "../../public/js/tools/forensics.js";
import { TOOLS as BT } from "../../public/js/tools/blueteam.js";

const ALL = [...FX, ...BT];
const run = async (id, v) => {
  const t = ALL.find((x) => x.id === id); const d = {};
  for (const i of t.inputs) if (i.value !== undefined) d[i.k] = i.value;
  try { const r = await t.run({ ...d, ...v }, H); return typeof r === "string" ? r : JSON.stringify(r); } catch (e) { return "THROW " + e.message; }
};

group("forensics quick tools audit", () => {
  test("timeline reads an ISO or 'date time' stamp followed by a label", async () => {
    const r = await run("fx-timeline", { text: "2023-11-14T22:13:21Z file written\n2023-11-14 22:13:19 shell\n1700000000 login" });
    assert.ok(!/Unparsed/.test(r));
    assert.equal(r.split("\n")[0], "2023-11-14T22:13:19.000Z  shell");
    assert.ok(r.includes("2023-11-14T22:13:21.000Z  file written"));
  });
  test("AD interval rounding carries instead of printing 60 seconds", async () => {
    assert.ok((await run("fx-ad-interval", { val: "-599999999" })).includes("0 days, 0 hours, 1 minutes, 0 seconds"));
  });
  test("LEEF 1.0 event ID is not read as the first attribute", async () => {
    const r = await run("fx-leef-parse", { line: "LEEF:1.0|Microsoft|MSExchange|4.0|15345|src=192.0.2.1\tdst=192.0.2.2" });
    assert.ok(r.includes("  src = 192.0.2.1") && !r.includes("15345|"));
    assert.ok((await run("fx-leef-parse", { line: "LEEF:2.0|V|P|1.0|7|x5E|a=1^b=2" })).includes("  b = 2"));
  });
  test("RFC 5424 structured data with spaces stays out of the message (RFC example)", async () => {
    const r = await run("fx-syslog-parse", { line: '<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] An application event log entry' });
    assert.ok(r.includes("Message: An application event log entry"));
  });
  test("ARC-Authentication-Results shows the verifier, not the i= instance tag", async () => {
    const r = await run("fx-email-auth-results", { header: "ARC-Authentication-Results: i=1; mx.example.com; spf=pass smtp.mailfrom=example.org" });
    assert.ok(r.startsWith("Verifier: mx.example.com"));
  });
  test("journald and CloudTrail readers return an error for JSON null, and CloudTrail unwraps Records", async () => {
    assert.ok(/error/.test(await run("fx-journald-json", { json: "null" })));
    assert.ok(/error/.test(await run("fx-cloudtrail", { json: "null" })));
    assert.ok((await run("fx-cloudtrail", { json: '{"Records":[{"eventName":"ConsoleLogin","awsRegion":"us-east-1"}]}' })).includes("Event name:   ConsoleLogin"));
  });
  test("decimal to DMS never prints 60 seconds", async () => {
    assert.equal(await run("fx-gps-coord", { mode: "Decimal to DMS", dec: "37.9999999" }), `38 deg 0' 0.000" N`);
    assert.equal(await run("fx-gps-coord", { mode: "Decimal to DMS", dec: "-122.4194", axis: "Longitude" }), `122 deg 25' 9.840" W`);
  });
  test("GPS week left blank gives no date", async () => {
    assert.equal(await run("fx-gps-time", { week: "", tow: "" }), "");
    assert.ok((await run("fx-gps-time", { week: "2300", tow: "259200" })).includes("2024-02-06T23:59:42.000Z"));
  });
  test("access log keeps an escaped quote inside the User-Agent", async () => {
    const r = await run("fx-apache-log", { line: '192.0.2.1 - - [01/Jan/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 12 "-" "Mozilla \\"x\\" y"' });
    assert.ok(r.includes('User-Agent: Mozilla \\"x\\" y'));
  });
  test("CEF parser unescapes header pipes and extension equals signs", async () => {
    const r = await run("fx-cef-parse", { line: "CEF:0|V|P|1|100|Name with \\| pipe|5|msg=a\\=b c src=192.0.2.1" });
    assert.ok(r.includes("Name:          Name with | pipe") && r.includes("  msg = a=b c"));
  });
  test("DFIR command builders quote paths with spaces", async () => {
    assert.equal(await run("fx-volatility", { image: "C:\\Cases\\mem dump.raw" }), 'vol -f "C:\\Cases\\mem dump.raw" windows.pslist.PsList');
    assert.ok((await run("fx-dd-builder", { tool: "dd", src: "/dev/sdb", dst: "/cases/my disk.img", hash: "sha256" })).includes('sha256sum "/cases/my disk.img"'));
    assert.ok((await run("fx-tsk-builder", { image: "/cases/a b.img" })).startsWith('fls -r -p "/cases/a b.img"'));
    assert.ok((await run("fx-plaso", { source: "/x/it's $HOME" })).endsWith("'/x/it'\\''s $HOME'"));
    assert.equal(await run("fx-volatility", { image: "/cases/mem.raw" }), "vol -f /cases/mem.raw windows.pslist.PsList");
  });
});

group("blue-team quick tools audit", () => {
  test("grok builder keeps a literal's trailing space", async () => {
    assert.equal(await run("bt-grok-build", {}), "%{IPORHOST:client} - %{USER:user} [%{TIMESTAMP_ISO8601:ts}] %{WORD:method}");
  });
  test("nginx rate keeps the requested rate (100 per 60 s is 100r/m, not 2r/s) and is never 0", async () => {
    assert.ok((await run("bt-ratelimit-calc", {})).includes("rate=100r/m;"));
    assert.ok((await run("bt-ratelimit-calc", { limit: "10", window: "1" })).includes("rate=10r/s;"));
    assert.ok((await run("bt-ratelimit-calc", { limit: "1", window: "3600" })).includes("rate=1r/m;"));
  });
  test("IDS rule escapes ; and quotes in msg and hex-encodes them in content", async () => {
    const r = await run("bt-ids-rule", { msg: 'Bad; "x"', content: 'a;b"c|d\\e' });
    assert.ok(r.includes('msg:"Bad\\; \\"x\\""; ') && r.includes('content:"a|3B|b|22|c|7C|d|5C|e"; nocase'));
  });
  test("Wazuh and Sysmon XML escape & and <", async () => {
    assert.ok((await run("bt-wazuh-rule", { match: "a & b < c", desc: "x<y" })).includes("<match>a &amp; b &lt; c</match>"));
    assert.ok((await run("bt-sysmon-config", { value: "a & b" })).includes(">a &amp; b</Image>"));
  });
  test("Falco rule fields are YAML-safe with ': ', ' #' and backslashes", async () => {
    const r = await run("bt-falco-rule", { rule: "Shell: in container", desc: "spawned # here", output: 'x \\d "q"' });
    assert.ok(r.startsWith('- rule: "Shell: in container"\n  desc: "spawned # here"'));
    assert.ok(r.includes('  output: "x \\\\d \\"q\\""'));
  });
  test("jq builder quotes non-identifier fields, the value and the shell string", async () => {
    assert.equal(await run("bt-jq-build", { field: "event-type", value: `it's "q"` }), `jq 'select(."event-type" == "it'\\''s \\"q\\"")'`);
    assert.equal(await run("bt-jq-build", { field: "level", value: "error" }), `jq 'select(.level == "error")'`);
    assert.equal(await run("bt-jq-build", { op: "count by field", field: "a.@ts" }), `jq -s 'group_by(.a."@ts") | map({key: .[0].a."@ts", count: length}) | sort_by(-.count)'`);
  });
  test("KQL parse and SPL builder escape backslashes and quotes in string literals", async () => {
    assert.ok((await run("bt-kql-parse-build", { template: "DOMAIN\\{user} ok" })).startsWith('| parse RawData with "DOMAIN\\\\" user " ok"'));
    assert.ok((await run("bt-spl-builder", { sourcetype: 'a"b' })).includes('sourcetype="a\\"b"'));
  });
});
