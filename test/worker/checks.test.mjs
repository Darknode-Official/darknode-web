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
