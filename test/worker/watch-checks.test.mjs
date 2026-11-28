// Unit tests for the domain-registration (RDAP) and website watches in worker/checks.js,
// plus the alert copy worker/alert-email.js writes for them.
import { test, group, assert } from "../harness.mjs";
import { rdapBase, gradeRdap, domainExpiryCheck, gradeWeb, webPostureCheck, looksLikeGitHead, looksLikeEnv, runCheck } from "../../worker/checks.js";
import { explainEvent } from "../../worker/alert-email.js";
import { FREE_WATCH, freeWatchDenied } from "../../worker/free-watch.js";

const NOW = Date.parse("2026-11-27T00:00:00Z");
const day = (n) => new Date(NOW + n * 86400000).toISOString();
const BOOT = { services: [[["com", "net"], ["https://rdap.verisign.example/com/v1/"]], [["uk", "co.uk"], ["http://insecure.example/", "https://rdap.nominet.example"]], [["de"], ["https://rdap.denic.example/"]]] };
const rdap = (o = {}) => ({ objectClassName: "domain", status: o.status || ["client transfer prohibited"], events: o.exp === null ? [] : [{ eventAction: "expiration", eventDate: o.exp || day(300) }],
  entities: [{ roles: ["registrar"], vcardArray: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar"]]] }] });
const res = (status, body, headers = {}, url = "") => ({
  ok: status >= 200 && status < 300, status, url,
  headers: new Headers(headers),
  json: async () => body, text: async () => typeof body === "string" ? body : JSON.stringify(body), body: null,
});

group("checks/domain-expiry: pure grading", () => {
  test("rdapBase takes the longest matching TLD and only https servers", () => {
    assert.equal(rdapBase(BOOT, "example.com"), "https://rdap.verisign.example/com/v1/");
    assert.equal(rdapBase(BOOT, "shop.example.co.uk"), "https://rdap.nominet.example/");
    assert.equal(rdapBase(BOOT, "example.org"), "");
    assert.equal(rdapBase(null, "example.com"), "");
  });
  test("a healthy, locked registration gives no finding", () => {
    assert.equal(gradeRdap("example.com", rdap(), { now: NOW }).findings.length, 0);
  });
  test("expiry inside the window is high, the last week critical, past expiry critical", () => {
    const at = (n) => gradeRdap("example.com", rdap({ exp: day(n) }), { now: NOW, warnDays: 30 }).findings[0];
    assert.equal(at(20).severity, "high");
    assert.equal(at(20).key, "domain:example.com:expiry");
    assert.ok(/expires in 20 days/.test(at(20).title));
    assert.equal(at(20).registrar, "Example Registrar");
    assert.equal(at(5).severity, "critical");
    assert.ok(/has expired/.test(at(-2).title));
    assert.equal(at(45), undefined);
  });
  test("redemption period is critical whatever the date says", () => {
    const f = gradeRdap("example.com", rdap({ status: ["redemption period", "client transfer prohibited"], exp: day(200) }), { now: NOW }).findings;
    assert.equal(f[0].severity, "critical");
    assert.ok(/redemption period/.test(f[0].title));
  });
  test("an unregistered domain (RDAP 404) is critical", () => {
    const f = gradeRdap("example.com", null, { now: NOW }).findings;
    assert.equal(f.length, 1);
    assert.ok(/is not registered/.test(f[0].title));
  });
  test("a pending transfer is high; an unlocked gTLD is medium; a ccTLD is not judged on the lock", () => {
    const f = gradeRdap("example.com", rdap({ status: ["active", "pending transfer"] }), { now: NOW }).findings;
    assert.deepEqual(f.map((x) => x.key + "=" + x.severity), ["domain:example.com:transfer=high", "domain:example.com:lock=medium"]);
    assert.equal(gradeRdap("example.de", rdap({ status: ["active"] }), { now: NOW }).findings.length, 0);
    assert.equal(gradeRdap("example.com", rdap({ status: ["server transfer prohibited"] }), { now: NOW }).findings.length, 0);
  });
  test("no expiry event is unknown (held), not a finding", () => {
    const g = gradeRdap("example.de", rdap({ exp: null }), { now: NOW });
    assert.equal(g.findings.length, 0);
    assert.deepEqual(g.unknown[0].keys, ["domain:example.de:expiry"]);
  });
});

group("checks/domain-expiry: network", () => {
  const fetcher = (map, log = []) => async (url) => { log.push(url); const v = map[url]; if (v instanceof Error) throw v; return v || res(500, null); };
  const bootUrl = "https://data.iana.org/rdap/dns.json";
  test("subdomains collapse to the registrable domain, looked up once", async () => {
    const log = [];
    const out = await domainExpiryCheck(["www.example.com", "https://api.example.com/x"], { now: NOW, fetch: fetcher({ [bootUrl]: res(200, BOOT), "https://rdap.verisign.example/com/v1/domain/example.com": res(200, rdap({ exp: day(10) })) }, log) });
    assert.equal(out.length, 1);
    assert.deepEqual(out.checked, ["example.com"]);
    assert.equal(log.filter((u) => /domain\/example\.com$/.test(u)).length, 1);
  });
  test("a registry that does not answer holds the last state; no bootstrap is unreachable", async () => {
    const out = await domainExpiryCheck(["example.com"], { now: NOW, fetch: fetcher({ [bootUrl]: res(200, BOOT), "https://rdap.verisign.example/com/v1/domain/example.com": new Error("timeout") }) });
    assert.ok(out.unreachable, "nothing answered");
    const out2 = await domainExpiryCheck(["example.com"], { now: NOW, fetch: fetcher({}) });
    assert.ok(out2.unreachable);
  });
  test("a TLD without RDAP is reported as unknown, not unreachable", async () => {
    const out = await domainExpiryCheck(["example.org", "example.com"], { now: NOW, fetch: fetcher({ [bootUrl]: res(200, BOOT), "https://rdap.verisign.example/com/v1/domain/example.com": res(200, rdap()) }) });
    assert.ok(!out.unreachable);
    assert.equal(out.unknown[0].domain, "example.org");
    assert.ok(out.held.includes("domain:example.org:expiry"));
  });
  test("runCheck dispatches domain-expiry with the monitor's warnDays", async () => {
    const f = fetcher({ [bootUrl]: res(200, BOOT), "https://rdap.verisign.example/com/v1/domain/example.com": res(200, rdap({ exp: day(50) })) });
    assert.equal((await runCheck("domain-expiry", { domains: ["example.com"] }, { fetch: f, now: NOW })).length, 0);
    assert.equal((await runCheck("domain-expiry", { domains: ["example.com"], warnDays: 60 }, { fetch: f, now: NOW })).length, 1);
  });
});

const GOOD = {
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "content-security-policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
};

group("checks/web-posture: pure", () => {
  test("file signatures: a real git HEAD and .env match, an HTML catch-all does not", () => {
    assert.ok(looksLikeGitHead("ref: refs/heads/main\n"));
    assert.ok(looksLikeGitHead("0123456789abcdef0123456789abcdef01234567"));
    assert.ok(!looksLikeGitHead("<!doctype html><html>"));
    assert.ok(looksLikeEnv("# app\nDB_PASSWORD=x\nAPI_KEY=y\n", "text/plain"));
    assert.ok(!looksLikeEnv("DB_PASSWORD=x\nAPI_KEY=y", "text/html"));
    assert.ok(!looksLikeEnv("<html>A=1\nB=2</html>", ""));
    assert.ok(!looksLikeEnv("ONLY=1", "text/plain"), "one line is not enough");
  });
  test("a well-configured site gives no finding", () => {
    assert.equal(gradeWeb("example.com", { httpsOk: true, headers: GOOD, httpTested: true, httpRedirectsToHttps: true }).length, 0);
  });
  test("missing headers and no redirect become keyed findings", () => {
    const f = gradeWeb("example.com", { httpsOk: true, headers: {}, httpTested: true, httpRedirectsToHttps: false });
    const keys = f.map((x) => x.key.split(":").pop() + "=" + x.severity);
    assert.deepEqual(keys.sort(), ["csp=medium", "frame=medium", "hsts=medium", "nosniff=low", "redirect=medium"]);
  });
  test("no HTTPS answer: one HTTPS finding, no header findings", () => {
    const f = gradeWeb("example.com", { httpsOk: false, headers: {}, httpTested: true, httpRedirectsToHttps: false });
    assert.deepEqual(f.map((x) => x.key).sort(), ["web:example.com:https", "web:example.com:redirect"]);
  });
  test("an exposed .git and .env are critical and carry only the URL", () => {
    const f = gradeWeb("example.com", { httpsOk: true, headers: GOOD, httpTested: true, httpRedirectsToHttps: true, git: "https://example.com/.git/HEAD", env: "https://example.com/.env" });
    assert.deepEqual(f.map((x) => x.severity), ["critical", "critical"]);
    assert.equal(f[0].url, "https://example.com/.env");
    assert.ok(!JSON.stringify(f).includes("PASSWORD"));
  });
});

group("checks/web-posture: network", () => {
  const site = (o = {}) => async (url, init = {}) => {
    if (o.down) throw new Error("connect failed");
    if (url === "https://example.com/") return res(200, "<html>", o.headers || GOOD, "https://example.com/");
    if (url === "http://example.com/") return o.noRedirect ? res(200, "<html>") : res(301, "", { location: "https://example.com/" });
    if (url === "https://example.com/.git/HEAD") return o.git ? res(200, "ref: refs/heads/main\n", { "content-type": "text/plain" }) : res(200, "<!doctype html>", { "content-type": "text/html" });
    if (url === "https://example.com/.env") return o.env ? res(200, "DB_PASSWORD=hunter2\nSECRET_KEY=abc\n", { "content-type": "application/octet-stream" }) : res(404, "");
    return res(404, "");
  };
  test("a good site: no findings, the host is checked", async () => {
    const out = await webPostureCheck(["https://example.com/login"], { fetch: site() });
    assert.equal(out.length, 0);
    assert.deepEqual(out.checked, ["example.com"]);
  });
  test("an SPA catch-all serving HTML for /.git/HEAD is not an exposure", async () => {
    assert.equal((await webPostureCheck(["example.com"], { fetch: site() })).filter((f) => /git/.test(f.key)).length, 0);
  });
  test("exposed files and a missing redirect are found", async () => {
    const out = await webPostureCheck(["example.com"], { fetch: site({ git: true, env: true, noRedirect: true }) });
    assert.deepEqual(out.map((f) => f.key.split(":").pop()).sort(), ["env", "git", "redirect"]);
    assert.ok(!JSON.stringify(out).includes("hunter2"), "file contents are never kept");
  });
  test("a site that answers nothing is unreachable, so nothing reads as fixed", async () => {
    assert.ok((await webPostureCheck(["example.com"], { fetch: site({ down: true }) })).unreachable);
  });
  test("private and local hosts are never requested", async () => {
    const log = [];
    const out = await webPostureCheck(["localhost", "127.0.0.1", "10.0.0.5"], { fetch: async (u) => { log.push(u); return res(200, ""); } });
    assert.equal(log.length, 0);
    assert.equal(out.length, 0);
  });
});

group("watch alerts and the Free watch", () => {
  test("alert copy explains registration and website findings", () => {
    const e = explainEvent({ key: "domain:example.com:expiry", title: "Registration for example.com expires in 9 days", domain: "example.com", daysToExpiry: 9, notAfter: day(9), registrar: "Example Registrar", severity: "high" });
    assert.ok(/Renew example\.com at your registrar \(Example Registrar\)/.test(e.fix));
    assert.ok(/anyone can register it/.test(e.why));
    const w = explainEvent({ key: "web:example.com:env", title: "The .env file of example.com is publicly readable", domain: "example.com", advice: "Rotate.", severity: "critical" });
    assert.ok(/database passwords/.test(w.why));
    assert.equal(w.fix, "Rotate.");
  });
  test("the Free watch takes all four domain checks on its one domain", () => {
    for (const t of ["domain-expiry", "web-posture"]) assert.ok(FREE_WATCH.types.includes(t));
    const mon = (type, d) => ({ id: type, type, config: { domains: [d] }, channels: [{ type: "email" }], intervalMs: 86400000 });
    assert.equal(freeWatchDenied(mon("web-posture", "example.com"), [mon("cert-expiry", "example.com")]), null);
    assert.ok(freeWatchDenied(mon("domain-expiry", "example.org"), [mon("cert-expiry", "example.com")]));
  });
});
