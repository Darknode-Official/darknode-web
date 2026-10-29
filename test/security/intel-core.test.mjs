// Integrations relay table (public/js/integrations/intel-core.js): argument
// validation, and that every request it builds stays on the provider's fixed
// host with the key placed only where that provider expects it. Pure logic only.

import { test, assert, group } from "../harness.mjs";
import { ARG_TYPES, PROVIDERS, findTool, checkArgs, buildRequest, testPassed, statusReason, compact } from "../../public/js/integrations/intel-core.js";

const SAMPLE = { ip: "8.8.8.8", domain: "example.com", hash: "d41d8cd98f00b204e9800998ecf8427e", url: "https://example.com/a?b=1", email: "test@darknode.ai", cve: "CVE-2021-44228", query: "domain:example.com", indicator: "example.com" };
const K = "test-key-123";

group("intel-core arguments", () => {
  test("each type accepts its sample", () => { for (const [t, v] of Object.entries(SAMPLE)) assert.ok(ARG_TYPES[t].ok(v), t); });
  test("rejects malformed values", () => {
    assert.notOk(ARG_TYPES.ip.ok("999.1.1.1"));
    assert.notOk(ARG_TYPES.domain.ok("example.com/../x"));
    assert.notOk(ARG_TYPES.hash.ok("abc"));
    assert.notOk(ARG_TYPES.url.ok("javascript:alert(1)"));
    assert.notOk(ARG_TYPES.cve.ok("CVE-21-1"));
    assert.notOk(ARG_TYPES.query.ok("a\r\nHost: evil"));
  });
  test("checkArgs trims, and reports missing or bad args", () => {
    const t = findTool("vt_ip").tool;
    assert.deepEqual(checkArgs(t, { ip: " 1.1.1.1 " }), { args: { ip: "1.1.1.1" } });
    assert.ok(/missing ip/.test(checkArgs(t, {}).error));
    assert.ok(/must be/.test(checkArgs(t, { ip: "nope" }).error));
  });
});

group("intel-core requests", () => {
  test("tool names are unique", () => {
    const names = Object.values(PROVIDERS).flatMap((p) => p.tools.map((t) => t.name));
    assert.equal(new Set(names).size, names.length);
  });
  test("every tool and key test stays on its provider host", () => {
    for (const [pid, p] of Object.entries(PROVIDERS)) {
      for (const t of p.tools) {
        const args = Object.fromEntries(Object.entries(t.args).map(([k, ty]) => [k, SAMPLE[ty]]));
        const r = buildRequest(pid, t.name, args, K);
        assert.ok(!r.error, pid + "/" + t.name + ": " + r.error);
        assert.equal(new URL(r.url).host, p.host, t.name);
        assert.equal(new URL(r.url).protocol, "https:", t.name);
      }
      if (p.test) assert.equal(new URL(buildRequest(pid, null, null, K).url).host, p.host, pid + " test");
    }
  });
  test("hostile args cannot change the host or path", () => {
    assert.ok(buildRequest("virustotal", "vt_domain", { domain: "evil.com/@x" }, K).error);
    const r = buildRequest("virustotal", "vt_url", { url: "https://evil.com/../../x" }, K);
    assert.equal(new URL(r.url).host, "www.virustotal.com");
    assert.ok(new URL(r.url).pathname.startsWith("/api/v3/urls/"));
  });
  test("the key goes only where the provider expects it", () => {
    const vt = buildRequest("virustotal", "vt_ip", { ip: "8.8.8.8" }, K);
    assert.equal(vt.headers["x-apikey"], K); assert.ok(!vt.url.includes(K));
    const sh = buildRequest("shodan", "shodan_host", { ip: "8.8.8.8" }, K);
    assert.equal(new URL(sh.url).searchParams.get("key"), K);
  });
  test("keyed providers refuse to build without a key; keyless ones do not need one", () => {
    assert.ok(/no API key/.test(buildRequest("virustotal", "vt_ip", { ip: "8.8.8.8" }, "").error));
    assert.ok(!buildRequest("nvd", "nvd_cve", { cve: "CVE-2021-44228" }, "").error);
  });
  test("unknown provider and tool are refused", () => {
    assert.ok(buildRequest("nope", "x", {}, K).error);
    assert.ok(buildRequest("virustotal", "shodan_host", { ip: "8.8.8.8" }, K).error);
  });
});

group("intel-core responses", () => {
  test("testPassed defaults to 2xx", () => { assert.ok(testPassed("virustotal", 200, {})); assert.notOk(testPassed("virustotal", 401, {})); });
  test("statusReason names the cause and the provider message", () => {
    assert.ok(/rejected the key \(401\)/.test(statusReason(401, null)));
    assert.ok(/: bad key$/.test(statusReason(403, { message: "bad key" })));
    assert.ok(/429/.test(statusReason(429, null)));
  });
  test("compact bounds lists, strings and drops bulky fields", () => {
    const c = compact({ last_analysis_results: { a: 1 }, s: "x".repeat(500), list: Array.from({ length: 20 }, (_, i) => i) });
    assert.ok(!("last_analysis_results" in c));
    assert.equal(c.s.length, 403);
    assert.equal(c.list.length, 13);
  });
});
