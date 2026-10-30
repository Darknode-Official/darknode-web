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

// ---- Email & DNS posture drift ---------------------------------------------
import { emailPostureCheck, gradeEmailDns, dohQuery, parseCaa } from "../../worker/checks.js";
import { diffFindings, diffToEvents } from "../../worker/monitor-core.js";

// a fake DoH resolver: zone maps "TYPE name" -> data strings; "fail" = that lookup errors on
// both resolvers; down = every request throws. Unlisted names answer NOERROR with no records.
const RRT = { TXT: 16, MX: 15, CAA: 257 };
const dohFetch = (zone, { down = false } = {}) => {
  const calls = [];
  const f = async (url) => {
    calls.push(url);
    if (down) throw new Error("network down");
    const u = new URL(url), type = u.searchParams.get("type"), name = u.searchParams.get("name");
    const rows = zone[type + " " + name];
    if (rows === "fail") return { ok: false, status: 502, json: async () => null };
    return { ok: true, status: 200, json: async () => ({ Status: 0, Answer: (rows || []).map((data) => ({ name, type: RRT[type], data: type === "TXT" ? `"${data}"` : data })) }) };
  };
  f.calls = calls;
  return f;
};
const healthy = (d) => ({
  ["TXT " + d]: ["v=spf1 include:_spf.example.net -all"],
  ["TXT _dmarc." + d]: ["v=DMARC1; p=reject; rua=mailto:dmarc@" + d],
  ["MX " + d]: ["10 mx1.example.net."],
  ["CAA " + d]: ['0 issue "letsencrypt.org"'],
});
const byId = (out, id) => out.find((f) => f.key.endsWith(":" + id));

group("checks/email-posture", () => {
  test("a healthy domain yields no findings and nothing unknown", async () => {
    const out = await emailPostureCheck(["example.com"], { fetch: dohFetch(healthy("example.com")) });
    assert.equal(out.length, 0);
    assert.equal(out.unknown.length, 0);
    assert.equal(out.held.length, 0);
  });

  test("a missing SPF record is a high finding", async () => {
    const z = healthy("example.com"); delete z["TXT example.com"];
    const out = await emailPostureCheck(["example.com"], { fetch: dohFetch(z) });
    assert.equal(out.length, 1);
    assert.equal(out[0].key, "email:example.com:spf");
    assert.equal(out[0].severity, "high");
    assert.equal(out[0].tool, "monitor:email-posture");
    assert.ok(/No SPF/.test(out[0].title));
  });

  test("SPF +all is critical, ~all low, ?all medium", async () => {
    for (const [q, sev] of [["+all", "critical"], ["all", "critical"], ["~all", "low"], ["?all", "medium"]]) {
      const z = healthy("example.com"); z["TXT example.com"] = ["v=spf1 mx " + q];
      const out = await emailPostureCheck(["example.com"], { fetch: dohFetch(z) });
      assert.equal(byId(out, "spf").severity, sev, q);
    }
  });

  test("DMARC missing is high, p=none medium, p=quarantine low", async () => {
    const z = healthy("example.com"); delete z["TXT _dmarc.example.com"];
    assert.equal(byId(await emailPostureCheck(["example.com"], { fetch: dohFetch(z) }), "dmarc").severity, "high");
    z["TXT _dmarc.example.com"] = ["v=DMARC1; p=none; rua=mailto:d@example.com"];
    const none = await emailPostureCheck(["example.com"], { fetch: dohFetch(z) });
    assert.equal(none.length, 1);
    assert.equal(byId(none, "dmarc").severity, "medium");
    z["TXT _dmarc.example.com"] = ["v=DMARC1; p=quarantine; rua=mailto:d@example.com"];
    assert.equal(byId(await emailPostureCheck(["example.com"], { fetch: dohFetch(z) }), "dmarc").severity, "low");
  });

  test("a subdomain inherits the organizational DMARC and the closest CAA", async () => {
    const z = { ...healthy("example.com"), "TXT mail.example.com": ["v=spf1 -all"], "MX mail.example.com": ["10 mx1.example.net."] };
    const out = await emailPostureCheck(["mail.example.com"], { fetch: dohFetch(z) });
    assert.equal(out.length, 0);
  });

  test("missing MX is medium, a null MX alone is fine, missing CAA is low", async () => {
    const z = healthy("example.com"); delete z["MX example.com"]; delete z["CAA example.com"];
    const out = await emailPostureCheck(["example.com"], { fetch: dohFetch(z) });
    assert.equal(byId(out, "mx").severity, "medium");
    assert.equal(byId(out, "caa").severity, "low");
    z["MX example.com"] = ["0 ."];
    assert.equal(byId(await emailPostureCheck(["example.com"], { fetch: dohFetch(z) }), "mx"), undefined);
  });

  test("parseCaa reads presentation and RFC 3597 generic forms", () => {
    assert.deepEqual(parseCaa('0 issue "pki.example"'), { flags: 0, tag: "issue", value: "pki.example" });
    const hx = (s) => [...s].map((c) => c.charCodeAt(0).toString(16)).join(" ");
    assert.deepEqual(parseCaa("\\# 14 00 05 " + hx("issue") + " " + hx("ca.test")), { flags: 0, tag: "issue", value: "ca.test" });
  });

  test("a DoH failure is no finding and an explicit unknown, held so the last state stands", async () => {
    const z = healthy("example.com"); z["TXT example.com"] = "fail"; z["CAA example.com"] = "fail";
    const out = await emailPostureCheck(["example.com"], { fetch: dohFetch(z) });
    assert.equal(out.length, 0, "no fake pass or fail");
    assert.deepEqual(out.unknown.map((u) => u.check).sort(), ["CAA", "SPF"]);
    for (const k of ["email:example.com:spf", "email:example.com:spf-lookups", "email:example.com:caa"]) assert.ok(out.held.includes(k), k);
  });

  test("resolvers down for every lookup marks the run unreachable, never clean", async () => {
    const f = dohFetch({}, { down: true });
    const out = await emailPostureCheck(["example.com"], { fetch: f });
    assert.equal(out.length, 0);
    assert.equal(out.unreachable, true);
    assert.ok(f.calls.some((u) => u.startsWith("https://cloudflare-dns.com/")) && f.calls.some((u) => u.startsWith("https://dns.google/")), "both resolvers tried");
    assert.equal((await dohQuery("example.com", "TXT", f)).failed, true);
  });

  test("a SERVFAIL answer is a failed lookup, NXDOMAIN is a real empty answer", async () => {
    const st = (Status) => async () => ({ ok: true, status: 200, json: async () => ({ Status }) });
    assert.equal((await dohQuery("example.com", "TXT", st(2))).failed, true);
    const nx = await dohQuery("example.com", "TXT", st(3));
    assert.equal(nx.failed, undefined);
    assert.equal(nx.length, 0);
  });

  test("a record weakened between runs diffs as new/worsened events via monitor-core", async () => {
    const z = healthy("example.com"); z["TXT example.com"] = ["v=spf1 mx ~all"];
    const run1 = await emailPostureCheck(["example.com"], { fetch: dohFetch(z) });
    z["TXT example.com"] = ["v=spf1 mx +all"]; delete z["TXT _dmarc.example.com"];
    const run2 = await emailPostureCheck(["example.com"], { fetch: dohFetch(z) });
    const ev = diffToEvents(diffFindings(run1, run2), "m1", NOW);
    assert.deepEqual(ev.map((e) => [e.kind, e.key, e.severity]), [
      ["new", "email:example.com:dmarc", "high"],
      ["worsened", "email:example.com:spf", "critical"],
    ]);
  });

  test("gradeEmailDns is pure and runCheck dispatches email-posture", async () => {
    const g = gradeEmailDns("example.com", { spfTxts: [], dmarcTxts: [], mx: [], caa: [] });
    assert.deepEqual(g.findings.map((f) => f.key), ["email:example.com:caa", "email:example.com:dmarc", "email:example.com:mx", "email:example.com:spf"]);
    const out = await runCheck("email-posture", { domains: ["https://Example.com/x"] }, { fetch: dohFetch(healthy("example.com")) });
    assert.equal(out.length, 0);
    assert.equal(out.unknown.length, 0);
  });
});
