// Regressions from the quick-utility bug sweep: IPv6 stray colons, factoring that gave up
// silently, lone trailing backslashes, file hashes that re-encoded binary bytes as UTF-8,
// /31 and /32 subnets, and engine conversions that were off in the 6th digit.
import { readFileSync } from "node:fs";
import crypto from "node:crypto";
import { test, assert, group } from "../harness.mjs";
import { TOOLS as appsec } from "../../public/js/tools/appsec.js";
import { TOOLS as cryptoTools } from "../../public/js/tools/crypto.js";
import { TOOLS as coding } from "../../public/js/tools/coding.js";
import { TOOLS as forensics } from "../../public/js/tools/forensics.js";
import { TOOLS as websec } from "../../public/js/tools/websec.js";
import { H } from "../../public/js/tools/_helpers.js";
import { CATALOG } from "../../public/js/toolkit.js";
import { numberBase } from "../../public/js/engine/data.js";
import { calc, convert } from "../../public/js/engine/skills.js";

const all = [...appsec, ...cryptoTools, ...coding, ...forensics, ...websec];
const tool = (id) => all.find((t) => t.id === id);
const err = (r) => (r && typeof r === "object" ? r.error : null);
const src = (p) => readFileSync(new URL("../../public/js/" + p, import.meta.url), "utf8");

group("quick tools: IPv6 Expand / Compress", () => {
  const t = tool("sx-ipv6");
  test("stray colons and a :: with eight groups are rejected", () => {
    for (const a of [":1:2:3:4:5:6:7", "1:2:3:4:5:6:7:", "1:2:3:4:5:6:7:8::", "::1:2:3:4:5:6:7:8", ":::"]) assert.ok(err(t.run({ addr: a, mode: "Expand" })), a);
  });
  test("embedded IPv4 tail is accepted", () => {
    assert.equal(t.run({ addr: "::ffff:1.2.3.4", mode: "Expand" }), "0000:0000:0000:0000:0000:ffff:0102:0304");
    assert.equal(t.run({ addr: "1:2:3:4:5:6:7::", mode: "Compress" }), "1:2:3:4:5:6:7:0");
  });
});

group("quick tools: factoring gives up honestly", () => {
  test("totient with more factors than the split budget errors instead of a partial phi", () => {
    assert.ok(err(tool("cr-totient").run({ n: (53n ** 250n).toString() })));
  });
  test("small semiprimes still factor", () => {
    assert.ok(/p = 1000000007\nq = 1000000009/.test(tool("cr-rsa-factor").run({ n: "1000000016000000063" })));
  });
});

group("quick tools: edge inputs", () => {
  test("regex explainer rejects a lone trailing backslash", () => {
    assert.ok(/lone backslash/.test(err(tool("cd-regex-explain").run({ pattern: "a\\", flags: "" }))));
  });
  test(".properties trailing backslash adds no 'undefined'", () => {
    assert.equal(JSON.parse(tool("cd-properties-json").run({ text: "a=b\\", mode: ".properties to JSON" })).a, "b");
  });
  test("AD interval beyond int64 is an error, not NaN", () => {
    assert.ok(err(tool("fx-ad-interval").run({ val: "99999999999999999999999999" })));
  });
  test("alg:none forge needs an object header", () => {
    assert.ok(err(tool("sx-jwt-none").run({ header: "0", payload: "{}" }, H)));
  });
  test("JWT forge names a new claim as not set", async () => {
    const tok = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.x";
    const out = await tool("w-jwt-analyzer").run({ token: tok, mode: "forge", wordlist: "", patch: '{"role":"admin"}', forgeAlg: "none", forgeSecret: "" }, H);
    const s = typeof out === "string" ? out : out.out;
    assert.ok(/role: \(not set\) -> "admin"/.test(s) && !/undefined/.test(s), s);
  });
});

group("hash suite: file hashes use the raw bytes", () => {
  const s = src("hash-suite.js");
  const { MD5, SHA1, SHA256, SHA512 } = new Function(s.slice(s.indexOf("const MD5 = (function"), s.indexOf("const HASH_TYPES")) + "\nreturn { MD5, SHA1, SHA256, SHA512 };")();
  test("binary bytes hash like Node's crypto", () => {
    const u = new Uint8Array([0, 0x80, 0xff, 0x41, 0xc3, 0xa9]);
    const bin = String.fromCharCode(...u);
    for (const [n, f] of [["md5", MD5], ["sha1", SHA1], ["sha256", SHA256], ["sha512", SHA512]]) assert.equal(f.raw(bin), crypto.createHash(n).update(u).digest("hex"), n);
  });
  test("file panel escapes the file name", () => {
    assert.ok(s.includes("${hsEsc(result.filename)}") && !s.includes("${result.filename}"));
  });
});

group("network tools: IPv6 parser", () => {
  const s = src("network-tools.js");
  const { parseIPv6 } = new Function(s.slice(s.indexOf("function compressIPv6"), s.indexOf("function ipv6ToBigInt")) + "return { parseIPv6 };")();
  test("stray colons are rejected, :: forms still parse", () => {
    for (const a of ["1:2:3:4:5:6:7:8:", ":1:2:3:4:5:6:7:8", "1:::2"]) assert.throws(() => parseIPv6(a), a);
    assert.deepEqual(parseIPv6("::1"), [0, 0, 0, 0, 0, 0, 0, 1]);
  });
});

group("toolkit: subnet and converters", () => {
  async function run(id, input, i = 0) {
    const inp = { value: input }, out = { textContent: "" }, btns = {};
    const root = { set innerHTML(v) {}, querySelector: (q) => (q === ".tk-in" ? inp : q === ".tk-out" ? out : btns) };
    CATALOG.find((x) => x.id === id).render(root);
    await btns.onclick({ target: { closest: () => ({ dataset: { i } }) } });
    return out.textContent;
  }
  test("/31 has 2 usable addresses and /32 has 1", async () => {
    assert.ok(/First host: 10\.0\.0\.0\nLast host:  10\.0\.0\.1\nUsable:     2/.test(await run("subnet", "10.0.0.0/31")));
    assert.ok(/Usable:     1$/.test(await run("subnet", "10.0.0.5/32")));
  });
  test("invalid colour and IP inputs error instead of fake values", async () => {
    assert.ok(/^Error/.test(await run("color", "zzz")));
    assert.ok(/^Error/.test(await run("ip2int", "1.2.3")));
    assert.ok(/^Error/.test(await run("ip2int", "4294967296", 1)));
  });
});

group("engine: base and unit conversions", () => {
  test("'1010 in binary to decimal' reads the digits as binary", () => {
    assert.equal(numberBase("1010 in binary to decimal").value, "10");
    assert.equal(numberBase("ff from hex to binary").value, "11111111");
    assert.equal(numberBase("102 in binary to decimal").ok, false);
  });
  test("an overflowing exponent is an error, not a silently dropped exponent", () => {
    assert.equal(calc("1e400").ok, false);
    assert.equal(calc("1e3").value, 1000);
  });
  test("pound, km/h and knot use exact definitions", () => {
    assert.equal(convert("10 kg to lb").value, 22.046226218);
    assert.equal(convert("100 km/h to mph").value, 62.137119224);
    assert.equal(convert("1 knot to kph").value, 1.852);
  });
});
