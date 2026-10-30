// websec.js / appsec.js quick-tool audit: every assertion below was first
// reproduced against ground truth in a scratch runner, then fixed in the owning
// file. Crypto/network outputs are checked against Node's own crypto and the
// relevant RFCs; the cheatsheet cases cover throws on an empty/absent select.

import crypto from "node:crypto";
import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS as WEB } from "../../public/js/tools/websec.js";
import { TOOLS as APP } from "../../public/js/tools/appsec.js";

const byId = Object.fromEntries([...WEB, ...APP].map((t) => [t.id, t]));
const run = async (id, v) => {
  const r = await byId[id].run(v, H);
  return typeof r === "string" ? r : JSON.stringify(r);
};

group("websec/appsec quick-tool audit", () => {
  // --- FIXED: cheatsheet tools threw on an empty select value instead of
  // returning a string (module contract: never throw for ordinary bad input). ---
  test("SQLi/SSTI/NoSQL cheatsheets return a string (no throw) on an empty select", async () => {
    for (const [id, k] of [["w-sqli-cheatsheet", "category"], ["w-ssti-cheatsheet", "engine"], ["w-nosqli-cheatsheet", "category"]]) {
      const out = await run(id, { [k]: "" });
      assert.equal(typeof out, "string");
      assert.equal(out, "");
    }
    // and still produce content for a real selection
    assert.ok((await run("w-sqli-cheatsheet", { category: "Auth bypass" })).length > 0);
  });

  test("XSS payload / smuggling builders return a string (no undefined) on an empty select", async () => {
    assert.equal(await run("w-xss-payload-gen", { context: "", marker: "X" }), "");
    assert.equal(await run("w-smuggling-cheatsheet", { variant: "", host: "h" }), "");
    assert.ok((await run("w-smuggling-cheatsheet", { variant: "CL.TE", host: "h" })).includes("Transfer-Encoding"));
  });

  // --- Ground-truth regression guards (were already correct; lock them in) ---
  test("TOTP matches RFC 6238 SHA-1 8-digit vectors", async () => {
    const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // base32 of "12345678901234567890"
    for (const [time, want] of [[59, "94287082"], [1111111109, "07081804"], [1234567890, "89005924"], [20000000000, "65353130"]]) {
      const code = (await run("sx-totp-code", { secret, digits: "8", period: "30", time: String(time) })).split("\n")[0];
      assert.equal(code, want);
    }
  });

  test("htpasswd {SHA} line equals {SHA} + base64(SHA1(password))", async () => {
    const want = "admin:{SHA}" + crypto.createHash("sha1").update("secret").digest("base64");
    assert.equal(await run("sx-htpasswd", { user: "admin", pass: "secret", mode: "sha" }), want);
  });

  test("SRI integrity is sha384 base64 of the exact content bytes (W3C SRI)", async () => {
    const want = "sha384-" + crypto.createHash("sha384").update("alert('hi');").digest("base64");
    assert.ok((await run("w-sri-hash", { content: "alert('hi');" })).includes(want));
  });

  test("Luhn validates and generates the correct check digit", async () => {
    assert.ok(/VALID/.test(await run("sx-luhn", { num: "4111111111111111", mode: "Validate" })));
    assert.ok(/INVALID/.test(await run("sx-luhn", { num: "4111111111111112", mode: "Validate" })));
    assert.ok((await run("sx-luhn", { num: "7992739871", mode: "Compute check digit" })).includes("79927398713"));
  });

  test("IPv6 expand/compress follows RFC 5952 (longest-run, single-zero untouched, embedded v4)", async () => {
    assert.equal(await run("sx-ipv6", { addr: "2001:db8::1", mode: "Expand" }), "2001:0db8:0000:0000:0000:0000:0000:0001");
    assert.equal(await run("sx-ipv6", { addr: "2001:0db8:0000:0000:0000:0000:0000:0001", mode: "Compress" }), "2001:db8::1");
    assert.equal(await run("sx-ipv6", { addr: "2001:0:0:1:0:0:0:1", mode: "Compress" }), "2001:0:0:1::1");
    assert.equal(await run("sx-ipv6", { addr: "1:0:1:1:1:1:1:1", mode: "Compress" }), "1:0:1:1:1:1:1:1");
    assert.equal(await run("sx-ipv6", { addr: "::ffff:192.168.1.1", mode: "Compress" }), "::ffff:c0a8:101");
    assert.ok(/error/.test(await run("sx-ipv6", { addr: "1:2:3:4:5:6:7:8::", mode: "Expand" })));
  });

  test("IPv4-in-CIDR handles /0 and /32 and rejects /33", async () => {
    assert.ok(/YES/.test(await run("sx-ip-in-cidr", { ip: "8.8.8.8", cidr: "0.0.0.0/0" })));
    assert.ok(/YES/.test(await run("sx-ip-in-cidr", { ip: "10.0.0.1", cidr: "10.0.0.1/32" })));
    assert.ok(/NO/.test(await run("sx-ip-in-cidr", { ip: "10.0.0.2", cidr: "10.0.0.1/32" })));
    assert.ok(/error/i.test(await run("sx-ip-in-cidr", { ip: "10.0.0.2", cidr: "10.0.0.1/33" })));
  });

  test("HSTS parser reads a quoted max-age and flags a duplicate directive (RFC 6797)", async () => {
    assert.ok((await run("sx-hsts-parser", { h: 'max-age="31536000"; includeSubDomains' })).startsWith("max-age: 31536000 s"));
    assert.ok(/INVALID/.test(await run("sx-hsts-parser", { h: "max-age=100; max-age=200" })));
  });
});
