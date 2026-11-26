// Domain check (public/js/check/domain-check.js): input normalisation, the weighted grade,
// each check's verdict from real-shaped DoH / proxy answers, and the findings mapping.
// The network is injected: a fake resolver answers in Cloudflare DoH JSON and a fake
// fetcher answers like the Worker /api/fetch proxy (net.js dnFetch).

import { test, group, assert } from "../harness.mjs";
import {
  CHECKS, CREDIT, normalizeDomain, isFreeMail, workDomainFromEmail, evaluate, gradeChecks,
  runDomainCheck, domainCheckFindings, domainCheckHeld, isProxyError, runLevel,
} from "../../public/js/check/domain-check.js";

const T = { A: 1, MX: 15, TXT: 16, AAAA: 28, DS: 43, CAA: 257 };
const ans = (name, type, datas, extra = {}) => ({ Status: 0, AD: false, Answer: datas.map((data) => ({ name, type: T[type], TTL: 300, data })), ...extra });
const nodata = (extra = {}) => ({ Status: 0, AD: false, ...extra });

// a fake resolver from a "name TYPE" -> answer table; unknown names are NXDOMAIN
function resolver(table) {
  const calls = [];
  const doh = async (name, type, o = {}) => {
    calls.push(name + " " + type + (o.cd ? " cd" : ""));
    const k = name + " " + type + (o.cd ? " cd" : "");
    if (k in table) { const v = table[k]; if (v instanceof Error) throw v; return v; }
    return { Status: 3 };
  };
  doh.calls = calls;
  return doh;
}
const GOOD_HEADERS = {
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "content-security-policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
};
const STXT = "Contact: mailto:security@good.test\nExpires: 2099-01-01T00:00:00.000Z\n";
function fetcher(map) {
  return async (url) => {
    const v = map[url];
    if (v instanceof Error) throw v;
    if (!v) throw new Error("connect ECONNREFUSED");
    return { url, finalUrl: v.finalUrl || url, status: v.status || 200, headers: v.headers || {}, body: v.body || "" };
  };
}
const goodDns = (d) => ({
  [`${d} A`]: ans(d, "A", ["192.0.2.10"], { AD: true }),
  [`${d} AAAA`]: nodata({ AD: true }),
  [`${d} TXT`]: ans(d, "TXT", ['"v=spf1 include:_spf.mail.test -all"']),
  [`_dmarc.${d} TXT`]: ans("_dmarc." + d, "TXT", [`"v=DMARC1; p=reject; rua=mailto:dmarc@${d}"`]),
  [`selector1._domainkey.${d} TXT`]: ans("selector1._domainkey." + d, "TXT", ['"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC"']),
  [`${d} MX`]: ans(d, "MX", ["10 mx1.mail.test."]),
  [`${d} DS`]: ans(d, "DS", ["2371 13 2 ABCDEF"]),
  [`${d} CAA`]: ans(d, "CAA", ['0 issue "ca.test"']),
});
const goodWeb = (d) => fetcher({
  [`https://${d}/`]: { status: 200, headers: GOOD_HEADERS },
  [`http://${d}/`]: { status: 200, finalUrl: `https://${d}/`, headers: GOOD_HEADERS },
  [`https://${d}/.well-known/security.txt`]: { status: 200, body: STXT },
});
const byId = (res) => Object.fromEntries(res.checks.map((c) => [c.id, c]));

group("domain check: catalog and grading", () => {
  test("weights total 100 and every check names a group and a Deck tool", () => {
    assert.equal(CHECKS.reduce((s, c) => s + c.weight, 0), 100);
    for (const c of CHECKS) assert.ok(c.group && c.tool && c.weight > 0, c.id);
    assert.equal(new Set(CHECKS.map((c) => c.id)).size, CHECKS.length);
  });
  test("pass earns all, warn half, fail none", () => {
    assert.deepEqual(CREDIT, { pass: 1, warn: 0.5, fail: 0 });
    const g = gradeChecks([{ status: "pass", weight: 10 }, { status: "warn", weight: 10 }, { status: "fail", weight: 20 }]);
    assert.equal(g.earned, 15); assert.equal(g.possible, 40); assert.equal(g.score, 38); assert.equal(g.grade, "F");
  });
  test("error and na are left out of the grade, never counted as a pass or a zero", () => {
    const checks = [{ status: "pass", weight: 60 }, { status: "error", weight: 30 }, { status: "na", weight: 10 }];
    const g = gradeChecks(checks);
    assert.equal(g.score, 100); assert.equal(g.grade, "A"); assert.equal(g.possible, 60); assert.equal(g.applicable, 90);
    assert.equal(checks[1].points, null); assert.equal(checks[2].points, null); assert.equal(checks[0].points, 60);
  });
  test("under half of the applicable weight graded -> N/A, not a letter", () => {
    const g = gradeChecks([{ status: "pass", weight: 40 }, { status: "error", weight: 60 }]);
    assert.equal(g.grade, "N/A"); assert.equal(g.score, null);
  });
  test("letter bands follow the posture engine (A 90, B 80, C 65, D 50)", () => {
    const at = (pct) => gradeChecks([{ status: "pass", weight: pct }, { status: "fail", weight: 100 - pct }]).grade;
    assert.equal(at(90), "A"); assert.equal(at(89), "B"); assert.equal(at(80), "B"); assert.equal(at(65), "C"); assert.equal(at(50), "D"); assert.equal(at(49), "F");
  });
  test("a check still waiting for its source is pending and not graded", () => {
    const checks = evaluate({ domain: "x.test", org: "x.test", webHost: "x.test", web: "pending" });
    assert.ok(checks.every((c) => c.status === "pending"));
    assert.equal(gradeChecks(checks).grade, "N/A");
  });
});

group("domain check: input", () => {
  test("pasted URLs, emails and www reduce to the bare domain", () => {
    assert.equal(normalizeDomain("https://WWW.Example.com/path?q=1#x"), "example.com");
    assert.equal(normalizeDomain("you@example.org"), "example.org");
    assert.equal(normalizeDomain("mailto:sec@sub.example.net"), "sub.example.net");
    assert.equal(normalizeDomain("example.com:8443."), "example.com");
    assert.equal(normalizeDomain("bücher.example"), "xn--bcher-kva.example");
  });
  test("not a domain -> empty", () => {
    for (const v of ["", "   ", "localhost", "192.0.2.1", "exa mple.com", "-bad-.com", null]) assert.equal(normalizeDomain(v), "", String(v));
  });
  test("free-mail and reserved domains are never offered as the user's domain", () => {
    assert.ok(isFreeMail("gmail.com")); assert.ok(isFreeMail("yahoo.co.uk")); assert.ok(isFreeMail("outlook.de"));
    assert.equal(workDomainFromEmail("a@gmail.com"), "");
    assert.equal(workDomainFromEmail("a@example.com"), "");
    assert.equal(workDomainFromEmail("a@corp.test"), "");
    assert.equal(workDomainFromEmail("Jane@Acme-Widgets.io"), "acme-widgets.io");
    assert.equal(workDomainFromEmail("no-at-sign"), "");
  });
});

group("domain check: live run with injected sources", () => {
  test("a well-configured domain passes every check (A)", async () => {
    const res = await runDomainCheck("good.test", { doh: resolver(goodDns("good.test")), fetchUrl: goodWeb("good.test") });
    const bad = res.checks.filter((c) => c.status !== "pass").map((c) => c.id + ":" + c.status + ":" + c.detail);
    assert.deepEqual(bad, []);
    assert.equal(res.grade, "A"); assert.equal(res.score, 100); assert.equal(res.possible, 100);
    assert.equal(runLevel(res), "good");
  });
  test("progress snapshots arrive with pending checks, and the last one is complete", async () => {
    const snaps = [];
    const res = await runDomainCheck("good.test", { doh: resolver(goodDns("good.test")), fetchUrl: goodWeb("good.test"), onProgress: (r) => snaps.push(r) });
    assert.ok(snaps.length >= 3);
    assert.ok(snaps.some((s) => s.checks.some((c) => c.status === "pending")));
    assert.equal(res.counts.pending, 0);
  });
  test("NXDOMAIN stops the check with a plain reason", async () => {
    let msg = "";
    try { await runDomainCheck("nope.test", { doh: resolver({}), fetchUrl: goodWeb("nope.test") }); } catch (e) { msg = e.message; }
    assert.ok(/does not exist/.test(msg), msg);
  });
  test("invalid input is rejected before any lookup", async () => {
    const doh = resolver({});
    let msg = "";
    try { await runDomainCheck("not a domain", { doh, fetchUrl: goodWeb("x") }); } catch (e) { msg = e.message; }
    assert.ok(/domain name/.test(msg)); assert.equal(doh.calls.length, 0);
  });
  test("a failing proxy makes the web checks 'error', not fails, and they leave the grade", async () => {
    const proxyDown = async () => { throw new Error("Network error reaching the Darknode proxy: Failed to fetch"); };
    const res = await runDomainCheck("good.test", { doh: resolver(goodDns("good.test")), fetchUrl: proxyDown });
    const c = byId(res);
    for (const id of ["https", "redirect", "hsts", "csp", "frame", "nosniff", "referrer", "securitytxt"]) assert.equal(c[id].status, "error", id);
    assert.equal(c.spf.status, "pass");
    assert.equal(res.possible, 46); // email 32 + DNS 14
    assert.equal(res.grade, "N/A"); // 46 of 100 applicable points graded is under half
  });
  test("a resolver outage on one record is 'error' for that check only", async () => {
    const t = goodDns("good.test"); t["good.test CAA"] = { Status: 2 };
    const res = await runDomainCheck("good.test", { doh: resolver(t), fetchUrl: goodWeb("good.test") });
    const c = byId(res);
    assert.equal(c.caa.status, "error"); assert.ok(/SERVFAIL/.test(c.caa.detail));
    assert.equal(c.caa.points, null); assert.equal(res.possible, 93); assert.equal(res.score, 100);
  });
  test("a weak site: no HTTPS redirect, missing headers, no security.txt", async () => {
    const d = "weak.test", t = goodDns(d);
    t[`${d} TXT`] = ans(d, "TXT", ['"v=spf1 include:_spf.mail.test ~all"']);
    t[`_dmarc.${d} TXT`] = ans("_dmarc." + d, "TXT", ['"v=DMARC1; p=none"']);
    t[`${d} A`] = ans(d, "A", ["192.0.2.20"]); t[`${d} AAAA`] = nodata(); delete t[`${d} DS`]; delete t[`${d} CAA`];
    const res = await runDomainCheck(d, { doh: resolver(t), fetchUrl: fetcher({ [`https://${d}/`]: { status: 200 }, [`http://${d}/`]: { status: 200 } }) });
    const c = byId(res);
    assert.equal(c.spf.status, "warn"); assert.equal(c.dmarc.status, "warn"); assert.ok(/p=quarantine/.test(c.dmarc.fix), c.dmarc.fix);
    assert.equal(c.https.status, "pass"); assert.equal(c.redirect.status, "fail");
    for (const id of ["hsts", "csp", "frame", "nosniff"]) assert.equal(c[id].status, "fail", id);
    assert.equal(c.referrer.status, "warn");
    assert.equal(c.dnssec.status, "warn"); assert.ok(/no DS record/.test(c.dnssec.detail));
    assert.equal(c.caa.status, "warn"); assert.equal(c.securitytxt.status, "warn");
    assert.ok(c.redirect.fix.length > 0);
    assert.equal(res.grade, "F");
  });
  test("an existing SPF or DMARC record gets the fix for its problem, not 'publish a record'", async () => {
    const run = async (spf, dmarc) => {
      const d = "mail.test", t = goodDns(d);
      if (spf == null) t[`${d} TXT`] = nodata(); else t[`${d} TXT`] = ans(d, "TXT", spf.map((s) => `"${s}"`));
      if (dmarc == null) t[`_dmarc.${d} TXT`] = nodata(); else t[`_dmarc.${d} TXT`] = ans("_dmarc." + d, "TXT", [`"${dmarc}"`]);
      return byId(await runDomainCheck(d, { doh: resolver(t), fetchUrl: goodWeb(d) }));
    };
    let c = await run(["v=spf1 include:_spf.mail.test ~all"], "v=DMARC1; p=quarantine; rua=mailto:r@mail.test");
    assert.ok(/change ~all to -all/.test(c.spf.fix), c.spf.fix); assert.ok(!/Publish/.test(c.spf.fix));
    assert.ok(/p=reject/.test(c.dmarc.fix) && !/Publish/.test(c.dmarc.fix), c.dmarc.fix);
    c = await run(["v=spf1 +all"], "v=DMARC1; p=reject");
    assert.equal(c.spf.status, "fail"); assert.ok(/Replace \+all with -all/.test(c.spf.fix), c.spf.fix);
    assert.ok(/rua=mailto:/.test(c.dmarc.fix) && /^Add/.test(c.dmarc.fix), c.dmarc.fix);
    c = await run(["v=spf1 -all", "v=spf1 include:_spf.mail.test -all"], "v=DMARC1; p=reject; pct=50; rua=mailto:r@mail.test");
    assert.ok(/Merge/.test(c.spf.fix), c.spf.fix); assert.ok(/pct=100/.test(c.dmarc.fix), c.dmarc.fix);
    c = await run(null, null);
    assert.equal(c.spf.status, "fail"); assert.ok(/^Publish one TXT record/.test(c.spf.fix), c.spf.fix);
    assert.equal(c.dmarc.status, "fail"); assert.ok(/^Publish a TXT record at _dmarc\.mail\.test/.test(c.dmarc.fix), c.dmarc.fix);
  });
  test("HTTPS down at the site is a fail; plain-HTTP-only headers fail HSTS", async () => {
    const d = "plain.test";
    const res = await runDomainCheck(d, { doh: resolver(goodDns(d)), fetchUrl: fetcher({ [`https://${d}/`]: new Error("TLS handshake failed"), [`http://${d}/`]: { status: 200, headers: GOOD_HEADERS } }) });
    const c = byId(res);
    assert.equal(c.https.status, "fail"); assert.ok(/TLS handshake failed/.test(c.https.detail));
    assert.equal(c.redirect.status, "fail");
    assert.equal(c.hsts.status, "fail"); assert.ok(/plain HTTP/.test(c.hsts.detail));
    assert.equal(c.csp.status, "pass"); // graded from the HTTP response
  });
  test("closed port 80 with working HTTPS is a pass for the redirect check", async () => {
    const d = "tls-only.test";
    const res = await runDomainCheck(d, { doh: resolver(goodDns(d)), fetchUrl: fetcher({ [`https://${d}/`]: { status: 200, headers: GOOD_HEADERS }, [`http://${d}/`]: new Error("connect ECONNREFUSED") }) });
    assert.equal(byId(res).redirect.status, "pass");
  });
  test("no address at the apex: the web checks run against www", async () => {
    const d = "apexless.test", t = goodDns(d);
    t[`${d} A`] = nodata({ AD: true }); t[`www.${d} A`] = ans("www." + d, "A", ["192.0.2.30"]);
    const w = "www." + d;
    const res = await runDomainCheck(d, { doh: resolver(t), fetchUrl: goodWeb(w) });
    assert.equal(res.webHost, w); assert.equal(byId(res).https.status, "pass");
  });
  test("no website at all: web checks are not applicable and the grade uses email + DNS", async () => {
    const d = "mailonly.test", t = goodDns(d);
    t[`${d} A`] = nodata({ AD: true });
    const res = await runDomainCheck(d, { doh: resolver(t), fetchUrl: async () => { throw new Error("must not fetch"); } });
    const c = byId(res);
    for (const id of ["https", "redirect", "hsts", "csp", "frame", "nosniff", "referrer", "securitytxt"]) assert.equal(c[id].status, "na", id);
    assert.equal(res.possible, 46); assert.equal(res.grade, "A");
  });
  test("a domain that sends no mail needs no DKIM; null MX passes", async () => {
    const d = "parked.test", t = goodDns(d);
    t[`${d} TXT`] = ans(d, "TXT", ['"v=spf1 -all"']); t[`${d} MX`] = ans(d, "MX", ["0 ."]);
    delete t[`selector1._domainkey.${d} TXT`];
    const res = await runDomainCheck(d, { doh: resolver(t), fetchUrl: goodWeb(d) });
    const c = byId(res);
    assert.equal(c.dkim.status, "na"); assert.equal(c.mx.status, "pass"); assert.ok(/Null MX/.test(c.mx.detail));
  });
  test("DKIM not found at the common selectors is a warning, not a fail", async () => {
    const d = "nodkim.test", t = goodDns(d); delete t[`selector1._domainkey.${d} TXT`];
    const res = await runDomainCheck(d, { doh: resolver(t), fetchUrl: goodWeb(d) });
    assert.equal(byId(res).dkim.status, "warn");
  });
  test("broken DNSSEC (SERVFAIL that answers with checking disabled) fails DNSSEC", async () => {
    const d = "bogus.test";
    // validating resolvers SERVFAIL every name in a bogus zone
    const t = { [`${d} A`]: { Status: 2 }, [`${d} AAAA`]: { Status: 2 }, [`${d} TXT`]: { Status: 2 }, [`${d} A cd`]: ans(d, "A", ["192.0.2.40"]) };
    const res = await runDomainCheck(d, { doh: resolver(t), fetchUrl: goodWeb(d) });
    const c = byId(res);
    assert.equal(c.dnssec.status, "fail"); assert.equal(c.https.status, "error"); assert.equal(c.spf.status, "error");
  });
  test("a subdomain inherits DMARC from its organisational domain and climbs for CAA", async () => {
    const t = goodDns("org.test");
    t["app.org.test A"] = ans("app.org.test", "A", ["192.0.2.50"], { AD: true }); t["app.org.test AAAA"] = nodata();
    t["app.org.test TXT"] = ans("app.org.test", "TXT", ['"v=spf1 -all"']);
    t["app.org.test MX"] = ans("app.org.test", "MX", ["0 ."]);
    const res = await runDomainCheck("app.org.test", { doh: resolver(t), fetchUrl: goodWeb("app.org.test") });
    const c = byId(res);
    assert.equal(c.dmarc.status, "pass"); assert.ok(/inherited from org\.test/.test(c.dmarc.detail), c.dmarc.detail);
    assert.equal(c.caa.status, "pass"); assert.ok(/CAA at org\.test/.test(c.caa.detail));
  });
  test("an invalid security.txt is a warning that says why", async () => {
    const d = "stxt.test";
    const res = await runDomainCheck(d, { doh: resolver(goodDns(d)), fetchUrl: fetcher({
      [`https://${d}/`]: { status: 200, headers: GOOD_HEADERS }, [`http://${d}/`]: { finalUrl: `https://${d}/`, headers: GOOD_HEADERS },
      [`https://${d}/.well-known/security.txt`]: { status: 200, body: "Contact: mailto:a@stxt.test\nExpires: 2000-01-01T00:00:00.000Z\n" } }) });
    const c = byId(res).securitytxt;
    assert.equal(c.status, "warn"); assert.ok(/not valid/.test(c.detail), c.detail);
  });
  test("an HTML app answering every path is not a security.txt", async () => {
    const d = "spa.test";
    const res = await runDomainCheck(d, { doh: resolver(goodDns(d)), fetchUrl: fetcher({
      [`https://${d}/`]: { status: 200, headers: GOOD_HEADERS }, [`http://${d}/`]: { finalUrl: `https://${d}/`, headers: GOOD_HEADERS },
      [`https://${d}/.well-known/security.txt`]: { status: 200, body: "<!doctype html><p>Contact: us</p>" },
      [`https://${d}/security.txt`]: { status: 200, body: "<!doctype html>" } }) });
    assert.equal(byId(res).securitytxt.status, "warn");
  });
});

group("domain check: proxy errors and findings", () => {
  test("proxy-side failures are told apart from the site not answering", () => {
    for (const m of ["Network error reaching the Darknode proxy: x", "Rate limit exceeded — slow down and retry shortly.", "Origin not allowed", "blocked (non-public or reserved host)", "Live fetch is unavailable — the Darknode proxy is not configured.", "a.test could not be reached: its firewall blocked the request."])
      assert.ok(isProxyError(new Error(m)), m);
    for (const m of ["connect ECONNREFUSED", "The operation was aborted", "a.test could not be reached: its name does not resolve to an address (DNS lookup failed)."])
      assert.notOk(isProxyError(new Error(m)), m);
  });
  test("only failing and warning checks become findings, with stable ids", () => {
    const res = { domain: "Weak.test", checks: [
      { id: "https", group: "https", label: "HTTPS", status: "fail", detail: "d1", fix: "f1" },
      { id: "csp", group: "headers", label: "Content-Security-Policy", status: "fail", detail: "d2", fix: "" },
      { id: "caa", group: "dns", label: "CAA records", status: "warn", detail: "d3", fix: "f3" },
      { id: "dkim", group: "email", label: "DKIM", status: "warn", detail: "d4", fix: "f4" },
      { id: "spf", group: "email", label: "SPF", status: "pass", detail: "ok" },
      { id: "dnssec", group: "dns", label: "DNSSEC", status: "error", detail: "x" },
    ] };
    const f = domainCheckFindings(res);
    assert.deepEqual(f.map((x) => x.id), ["domaincheck|weak.test|https", "domaincheck|weak.test|csp", "domaincheck|weak.test|caa", "domaincheck|weak.test|dkim"]);
    assert.deepEqual(f.map((x) => x.severity), ["high", "medium", "low", "low"]);
    assert.equal(f[3].confidence, "review");
    assert.equal(f[1].recommendation, undefined);
    assert.deepEqual(f[0].assets, [{ type: "DOMAIN", name: "weak.test" }]);
    assert.deepEqual(domainCheckHeld(res), ["domaincheck|weak.test|dnssec"]);
  });
});
