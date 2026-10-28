// Unit tests for worker/checks.js — server-side cert-expiry monitor over CT logs.
import { test, group, assert } from "../harness.mjs";
import { certExpiryCheck, fetchCertRows, runCheck } from "../../worker/checks.js";

const NOW = Date.parse("2026-10-17T00:00:00Z");
const day = (n) => new Date(NOW + n * 86400000).toISOString();
// a fake fetch that serves crt.sh JSON per domain from a map
const ctFetch = (byDomain) => async (url) => {
  const m = /q=([^&]+)/.exec(url); const dom = m ? decodeURIComponent(m[1]) : "";
  const rows = byDomain[dom];
  if (!rows) return { ok: false, status: 502, json: async () => null };
  return { ok: true, status: 200, json: async () => rows };
};
const cert = (notAfter) => ({ issuer_name: "Lets Encrypt", not_after: notAfter, not_before: day(-80), name_value: "x" });

group("checks/cert-expiry", () => {
  test("a cert expiring within the window is a high finding", async () => {
    const f = ctFetch({ "a.test.darknode.ai": [cert(day(10))] });
    const out = await certExpiryCheck(["a.test.darknode.ai"], { fetch: f, now: NOW, warnDays: 21 });
    assert.equal(out.length, 1);
    assert.equal(out[0].severity, "high");
    assert.equal(out[0].daysToExpiry, 10);
    assert.equal(out[0].key, "cert:a.test.darknode.ai");
  });

  test("a domain saved as a URL, host:port or wildcard is looked up by its hostname", async () => {
    const f = ctFetch({ "a.test.darknode.ai": [cert(day(10))] });
    for (const d of ["https://a.test.darknode.ai/login?x=1", "a.test.darknode.ai:443", "*.a.test.darknode.ai", "A.test.darknode.ai."]) {
      const out = await certExpiryCheck([d], { fetch: f, now: NOW, warnDays: 21 });
      assert.equal(out.length, 1, d);
      assert.equal(out[0].key, "cert:a.test.darknode.ai");
    }
  });

  test("an already-expired cert is critical", async () => {
    const f = ctFetch({ "b.test.darknode.ai": [cert(day(-3))] });
    const out = await certExpiryCheck(["b.test.darknode.ai"], { fetch: f, now: NOW });
    assert.equal(out[0].severity, "critical");
  });

  test("a healthy cert yields no finding (never a fake pass)", async () => {
    const f = ctFetch({ "c.test.darknode.ai": [cert(day(200))] });
    const out = await certExpiryCheck(["c.test.darknode.ai"], { fetch: f, now: NOW, warnDays: 21 });
    assert.equal(out.length, 0);
  });

  test("a domain CT cannot resolve is skipped, not invented", async () => {
    const f = ctFetch({});
    const out = await certExpiryCheck(["unknown.test.darknode.ai"], { fetch: f, now: NOW });
    assert.equal(out.length, 0);
  });

  test("a domain neither log answered for is held; one they answered with no rows is not", async () => {
    const down = await certExpiryCheck(["u.test.darknode.ai"], { fetch: ctFetch({}), now: NOW });
    assert.deepEqual(down.held, ["cert:u.test.darknode.ai"]);
    const empty = await certExpiryCheck(["u.test.darknode.ai"], { fetch: ctFetch({ "u.test.darknode.ai": [] }), now: NOW });
    assert.deepEqual(empty.held, []);
  });

  test("newest leaf wins when several certs exist", async () => {
    const f = ctFetch({ "d.test.darknode.ai": [cert(day(5)), cert(day(400))] });
    const out = await certExpiryCheck(["d.test.darknode.ai"], { fetch: f, now: NOW, warnDays: 21 });
    assert.equal(out.length, 0, "newest (400d) is healthy, so no finding");
  });

  test("fetchCertRows falls back to certspotter when crt.sh is down", async () => {
    const f = async (url) => {
      if (url.includes("crt.sh")) return { ok: false, status: 502, json: async () => null };
      return { ok: true, status: 200, json: async () => [{ issuer: { name: "CS" }, not_after: day(9), not_before: day(-5), dns_names: ["e.test.darknode.ai"] }] };
    };
    const rows = await fetchCertRows("e.test.darknode.ai", f);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].not_after, day(9));
  });

  test("runCheck dispatches by type and is empty for unknown types", async () => {
    const f = ctFetch({ "g.test.darknode.ai": [cert(day(2))] });
    const out = await runCheck("cert-expiry", { domains: ["g.test.darknode.ai"], warnDays: 21 }, { fetch: f, now: NOW });
    assert.equal(out.length, 1);
    assert.equal((await runCheck("nope", {}, { fetch: f })).length, 0);
  });
});

// ---- KEV / EPSS watch -------------------------------------------------------
import { cvesFromEntities, matchKevEpss, kevEpssCheck } from "../../worker/checks.js";

group("checks/kev-epss", () => {
  test("cvesFromEntities pulls CVEs from name, data.cve/cves and evidence, uppercased + unique", () => {
    const out = cvesFromEntities([
      { name: "cve-2021-44228 Log4Shell", data: {} },
      { name: "x", data: { cve: "CVE-2021-44228" } },           // duplicate
      { name: "y", data: { cves: ["CVE-2023-0001", "CVE-2023-0002"] } },
      { name: "z", data: { evidence: "seen CVE-2024-9999 in logs" } },
      { name: "no cve here", data: {} },
    ]);
    assert.deepEqual(out.sort(), ["CVE-2021-44228", "CVE-2023-0001", "CVE-2023-0002", "CVE-2024-9999"]);
  });

  test("matchKevEpss: KEV is critical, high-EPSS is high/medium, others skipped", () => {
    const kev = new Map([["CVE-2021-44228", { dueDate: "2021-12-24" }]]);
    const epss = new Map([["CVE-2023-0001", 0.95], ["CVE-2023-0002", 0.6], ["CVE-2023-0003", 0.1]]);
    const out = matchKevEpss(["CVE-2021-44228", "CVE-2023-0001", "CVE-2023-0002", "CVE-2023-0003", "CVE-2099-0000"], { kev, epss, epssFloor: 0.5 });
    const by = Object.fromEntries(out.map((f) => [f.cve, f]));
    assert.equal(by["CVE-2021-44228"].severity, "critical");
    assert.equal(by["CVE-2021-44228"].kev, true);
    assert.equal(by["CVE-2023-0001"].severity, "high");
    assert.equal(by["CVE-2023-0002"].severity, "medium");
    assert.equal(by["CVE-2023-0003"], undefined);   // below floor
    assert.equal(by["CVE-2099-0000"], undefined);   // not in either feed
    assert.equal(out.length, 3);
  });

  test("matchKevEpss is deterministic and key-sorted", () => {
    const kev = new Map([["CVE-2021-44228", {}]]);
    const epss = new Map([["CVE-2023-0001", 0.9]]);
    const a = matchKevEpss(["CVE-2023-0001", "CVE-2021-44228"], { kev, epss });
    const b = matchKevEpss(["CVE-2021-44228", "CVE-2023-0001"], { kev, epss });
    assert.equal(JSON.stringify(a), JSON.stringify(b));
    assert.deepEqual(a.map((f) => f.key), ["epss:CVE-2023-0001", "kev:CVE-2021-44228"]);
  });

  test("kevEpssCheck fetches the mirrored feeds and matches the inventory", async () => {
    const f = async (url) => {
      if (url.includes("cisa-kev-index")) return { ok: true, status: 200, json: async () => ({ data: [{ cve: "CVE-2021-44228", dueDate: "2021-12-24" }] }) };
      if (url.includes("epss-top")) return { ok: true, status: 200, json: async () => ({ data: [{ cve: "CVE-2023-0001", epss: 0.97 }] }) };
      return { ok: false, status: 404, json: async () => null };
    };
    const out = await kevEpssCheck({ epssFloor: 0.5 }, { fetch: f, cves: ["CVE-2021-44228", "CVE-2023-0001", "CVE-2000-1111"] });
    assert.equal(out.length, 2);
    assert.ok(out.some((x) => x.key === "kev:CVE-2021-44228" && x.severity === "critical"));
    assert.ok(out.some((x) => x.key === "epss:CVE-2023-0001" && x.severity === "high"));
  });

  test("kevEpssCheck returns nothing with no inventory, and skips (no invention) when feeds are down", async () => {
    const down = async () => ({ ok: false, status: 500, json: async () => null });
    assert.equal((await kevEpssCheck({}, { fetch: down, cves: [] })).length, 0);
    assert.equal((await kevEpssCheck({}, { fetch: down, cves: ["CVE-2021-44228"] })).length, 0);
  });
});
