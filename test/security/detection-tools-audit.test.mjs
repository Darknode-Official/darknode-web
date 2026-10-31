// Regression tests for the Deck detection-engineering audit (2026-10-30): YARA
// Rule Builder, Sigma Rule Builder, Log Analyzer, IOC Enrichment, Regex Lab and
// Hash Suite. Each test pins a reproduced bug. ioc-enrichment.js imports
// /js/shared.js by absolute path and hash-suite.js runs a location/licence check
// at import time, so those are exercised from their source text.

import fs from "node:fs";
import { test, assert, group } from "../harness.mjs";
import { buildYara, validateYara } from "../../public/js/yara-builder.js";
import { buildYaml, validate as validateSigma } from "../../public/js/sigma-builder.js";
import { evaluateRule } from "../../public/js/core/sigma.js";
import { parseApacheAccess, detectPatterns, parseSyslog, renderJSONLogTab, renderAuthLogTab } from "../../public/js/log-analyzer.js";

const src = (f) => fs.readFileSync(new URL("../../public/js/" + f, import.meta.url), "utf8");

// a container whose querySelector("#id") returns stub elements for every id in its innerHTML
function fakeContainer() {
  const els = {};
  return {
    set innerHTML(h) { for (const m of String(h).matchAll(/id="([^"]+)"/g)) els[m[1]] = { value: "", textContent: "", onclick: null, style: {}, addEventListener() {} }; },
    get innerHTML() { return ""; },
    querySelector: (sel) => els[sel.replace(/^#/, "")] || null,
    querySelectorAll: () => [],
    els,
  };
}

group("yara-builder", () => {
  const errs = (st) => validateYara({ name: "r1", condition: "any of them", ...st }).filter((f) => f.severity === "error").map((f) => f.message);
  const one = (s) => ({ strings: [{ id: "$a", type: "text", value: "abcd", ...s }] });
  test("several anonymous $ strings are not duplicates", () => {
    assert.deepEqual(errs({ strings: [{ id: "$", type: "text", value: "abcd" }, { id: "$", type: "text", value: "efgh" }] }), []);
    assert.equal(errs({ strings: [{ id: "$x", type: "text", value: "abcd" }, { id: "$x", type: "text", value: "efgh" }] }).length, 1);
  });
  test("hex bytes without spaces and tight ( | ) groups are valid", () => {
    assert.deepEqual(errs({ strings: [{ id: "$h", type: "hex", value: "4D5A9000" }] }), []);
    assert.deepEqual(errs({ strings: [{ id: "$h", type: "hex", value: "4D (5A|90) [2-4] 00" }] }), []);
    assert.equal(errs({ strings: [{ id: "$h", type: "hex", value: "4D5" }] }).length, 1);
    assert.equal(errs({ strings: [{ id: "$h", type: "hex", value: "ZZ" }] }).length, 1);
  });
  test("reserved words are case-sensitive own keys, and the list is complete", () => {
    assert.deepEqual(errs({ name: "constructor", ...one() }), []);
    assert.deepEqual(errs({ name: "All", ...one() }), []);
    for (const kw of ["none", "defined", "startswith", "uint32be", "all"]) assert.equal(errs({ name: kw, ...one() }).length, 1, kw);
  });
  test("an unescaped / in a regex string is escaped in the rule", () => {
    const text = buildYara({ name: "r1", condition: "any of them", strings: [{ id: "$r", type: "regex", value: "http://evil" }] });
    assert.ok(text.includes("$r = /http:\\/\\/evil/"), text);
    const kept = buildYara({ name: "r1", condition: "any of them", strings: [{ id: "$r", type: "regex", value: "a\\/b" }] });
    assert.ok(kept.includes("$r = /a\\/b/"), kept);
  });
  test("xor with nocase and base64 with fullword are rejected like YARA does", () => {
    assert.equal(errs(one({ mods: { xor: true, nocase: true } })).length, 1);
    assert.equal(errs(one({ mods: { base64: true, fullword: true } })).length, 1);
    assert.deepEqual(errs(one({ mods: { xor: true, wide: true } })), []);
  });
});

group("sigma-builder", () => {
  const base = { title: "t", id: "0f6b9f3e-1c2d-4e5f-8a9b-0c1d2e3f4a5b", level: "high", logsource: { product: "windows" }, condition: "selection" };
  test("the contains|all choice emits |contains|all and matches substrings", () => {
    const y = buildYaml({ ...base, selections: [{ name: "selection", rows: [{ field: "CommandLine", op: "all", value: "powershell\n-enc" }] }] });
    assert.ok(y.includes("CommandLine|contains|all:"), y);
    assert.equal(evaluateRule(y, [{ CommandLine: "powershell.exe -enc AAA" }]).count, 1);
  });
  test("hex, exponent and .inf values are quoted so YAML keeps them as strings", () => {
    const y = buildYaml({ ...base, selections: [{ name: "selection", rows: [{ field: "Status", op: "equals", value: "0xc000006d" }, { field: "Code", op: "equals", value: "1e3" }, { field: "V", op: "equals", value: ".inf" }] }] });
    assert.ok(y.includes("Status: '0xc000006d'") && y.includes("Code: '1e3'") && y.includes("V: '.inf'"), y);
    assert.ok(y.includes("level: high"));
    assert.deepEqual(validateSigma({ ...base, selections: [{ name: "selection", rows: [{ field: "A", op: "equals", value: "x" }] }] }), []);
  });
});

group("log-analyzer", () => {
  test("a host field named constructor does not crash the pattern detector", () => {
    const e = parseApacheAccess('constructor - - [10/Oct/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 1 "-" "x"');
    assert.equal(e.length, 1);
    assert.deepEqual(detectPatterns(e), []);
  });
  test("RFC 5424 nil structured data is not part of the message", () => {
    assert.equal(parseSyslog("<34>1 2003-10-11T22:14:15.003Z mymachine su - ID47 - 'su root' failed")[0].message, "'su root' failed");
    const sd = parseSyslog('<165>1 2003-10-11T22:14:15Z host app - ID [ex a="b"] hello')[0];
    assert.equal(sd.structured, 'ex a="b"'); assert.equal(sd.message, "hello");
  });
  test("JSON fields: own keys only, null lines skipped", () => {
    const c = fakeContainer(); renderJSONLogTab(c);
    c.els["la-json-input"].value = '{"constructor":"x","a":1}\n{"a":2}\nnull';
    c.els["la-json-fields"].onclick();
    const out = c.els["la-json-output"].textContent;
    assert.ok(/constructor\s+string\s+1\s+x/.test(out), out);
    assert.ok(!out.includes("native code"), out);
  });
  test("JSON filter reads own keys and reports a bad regex instead of throwing", () => {
    const c = fakeContainer(); renderJSONLogTab(c);
    c.els["la-json-input"].value = '{"a":1}\n{"a":2}';
    c.els["la-json-filter-key"].value = "constructor";
    c.els["la-json-filter"].onclick();
    assert.ok(c.els["la-json-output"].textContent.startsWith("Filtered 0 of 2"), c.els["la-json-output"].textContent);
    c.els["la-json-filter-key"].value = "a"; c.els["la-json-filter-val"].value = "(";
    c.els["la-json-filter"].onclick();
    assert.ok(c.els["la-json-output"].textContent.startsWith("Invalid filter regex"));
    c.els["la-json-search"].value = "[";
    c.els["la-json-search-btn"].onclick();
    assert.ok(c.els["la-json-output"].textContent.startsWith("Invalid search regex"));
  });
  test("a user named constructor is counted, not shown as a function", () => {
    const c = fakeContainer(); renderAuthLogTab(c);
    c.els["la-auth-input"].value = "Oct 10 sshd[1]: Failed password for invalid user constructor from 1.2.3.4 port 22 ssh2";
    c.els["la-auth-failed"].onclick();
    const out = c.els["la-auth-output"].textContent;
    assert.ok(/constructor\s+1\n/.test(out) && !out.includes("native code"), out);
  });
});

group("ioc-enrichment", () => {
  const s = src("ioc-enrichment.js");
  const body = s.slice(s.indexOf("var PATTERNS"), s.indexOf("/* ---- live enrichment"));
  const { extract, refang } = new Function(body + "\nreturn { extract: extract, refang: refang };")();
  const got = (t) => extract(t).map((r) => r.type + ":" + r.value);
  test("an IPv4 address ending a sentence is extracted", () => {
    assert.deepEqual(got("C2 is 185.220.101.47."), ["ipv4:185.220.101.47"]);
    assert.deepEqual(got("Hosts 1.2.3.4, 5.6.7.8."), ["ipv4:1.2.3.4", "ipv4:5.6.7.8"]);
    assert.deepEqual(got("version 1.2.3.4.5 build"), []);
  });
  test("a bare 'at' in prose does not turn a domain into an email", () => {
    assert.deepEqual(got("beacon seen at evil-c2.example.com today"), ["domain:evil-c2.example.com"]);
    assert.equal(refang("billing at secure-login-verify dot xyz"), "billing@secure-login-verify.xyz");
    assert.equal(refang("admin at corp[.]com"), "admin@corp.com");
  });
  test("STIX registry keys spell out the hive", () => {
    const m = s.match(/function fullHive\(k\) \{[\s\S]*?\n  \}/);
    assert.ok(m, "fullHive present");
    const fullHive = new Function(m[0] + "\nreturn fullHive;")();
    assert.equal(fullHive("HKCU\\Software\\Run"), "HKEY_CURRENT_USER\\Software\\Run");
    assert.equal(fullHive("HKEY_USERS\\x"), "HKEY_USERS\\x");
    assert.ok(s.includes("q(fullHive(v))"));
  });
});

group("regex-lab", () => {
  test("the Stripe library pattern is a real regex, not a placeholder", () => {
    const m = src("regex-lab.js").match(/name: "Stripe Secret Key", pattern: "([^"]+)"/);
    assert.ok(m && !m[1].startsWith("<"), m && m[1]);
    assert.ok(new RegExp(m[1]).test("sk_live_" + "a1B2c3D4e5F6g7H8i9J0k1L2"));
  });
});

group("hash-suite", () => {
  const s = src("hash-suite.js");
  test("MySQL 4.1+ hashes are 41 characters with the * prefix", () => {
    assert.ok(/name: "MySQL 4\.1\+",\s+len: 41,/.test(s));
  });
  test("Compare lowercases only hex digests (base64 is case-sensitive)", () => {
    assert.ok(!/#compare-a"\)\.value\.trim\(\)\.toLowerCase\(\)/.test(s));
    assert.ok(s.includes("if (/^[0-9a-f]+$/i.test(a) && /^[0-9a-f]+$/i.test(b))"));
  });
});
