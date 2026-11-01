// Unit tests for worker/digest.js — the weekly email digest's pure parts.
import { test, group, assert } from "../harness.mjs";
import { validatePrefs, certRows, buildDigest, unsubToken } from "../../worker/digest.js";

const NOW = Date.parse("2026-11-02T14:00:00Z");
const DAY = 86400000;
const KEV = [
  { cve: "CVE-2026-0001", vendor: "Acme", product: "Gateway", dateAdded: "2026-10-30", dueDate: "2026-11-20", ransomware: true },
  { cve: "CVE-2026-0002", vendor: "Acme", product: "Mail", dateAdded: "2026-10-20", dueDate: "2026-11-10", ransomware: false },
];

group("digest/validatePrefs", () => {
  test("keeps valid domains, lowercases, dedupes, drops junk", () => {
    const v = validatePrefs({ domains: ["Example.com", "example.com.", "not a domain", "<script>", "a.b"] });
    assert.ok(v.ok);
    assert.deepEqual(v.prefs.domains, ["example.com", "a.b"]);
  });
  test("rejects a non-boolean on and a non-list domains", () => {
    assert.equal(validatePrefs({ on: "yes" }).ok, false);
    assert.equal(validatePrefs({ domains: "example.com" }).ok, false);
  });
  test("caps domain and cert lists", () => {
    const many = Array.from({ length: 80 }, (_, i) => "d" + i + ".example.com");
    assert.equal(validatePrefs({ domains: many }).prefs.domains.length, 50);
    assert.equal(validatePrefs({ certs: Array.from({ length: 300 }, (_, i) => ({ domain: "d" + i + ".example.com", notAfter: "2027-01-01" })) }).prefs.certs.length, 200);
  });
  test("normalises cert expiry and drops bad cert domains", () => {
    const v = validatePrefs({ certs: [{ domain: "example.com", notAfter: "2026-11-10T00:00:00Z", issuer: "R3" }, { domain: "bad domain", notAfter: "2027-01-01" }] });
    assert.equal(v.prefs.certs.length, 1);
    assert.equal(v.prefs.certs[0].notAfter, "2026-11-10T00:00:00.000Z");
  });
  test("merges into previous prefs without dropping unrelated fields", () => {
    const v = validatePrefs({ on: true }, { domains: ["example.com"], lastSent: 5 });
    assert.equal(v.prefs.on, true);
    assert.deepEqual(v.prefs.domains, ["example.com"]);
    assert.equal(v.prefs.lastSent, 5);
  });
});

group("digest/certRows", () => {
  test("lists expired, within-30-day and unreadable certs, soonest first", () => {
    const rows = certRows([
      { domain: "far.example.com", notAfter: new Date(NOW + 90 * DAY).toISOString() },
      { domain: "soon.example.com", notAfter: new Date(NOW + 9 * DAY).toISOString() },
      { domain: "gone.example.com", notAfter: new Date(NOW - 2 * DAY).toISOString() },
      { domain: "unknown.example.com", notAfter: "" },
    ], NOW);
    assert.deepEqual(rows.map((r) => r.domain), ["gone.example.com", "soon.example.com", "unknown.example.com"]);
    assert.equal(rows[1].daysLeft, 9);
  });
});

group("digest/buildDigest", () => {
  test("only this week's KEV entries, with ransomware flagged", () => {
    const d = buildDigest({ kev: KEV, now: NOW, unsubUrl: "https://x/u" });
    assert.ok(d.text.includes("CVE-2026-0001"));
    assert.ok(!d.text.includes("CVE-2026-0002"));
    assert.ok(d.html.includes("used in ransomware"));
    assert.ok(d.subject.includes("1 new exploited vulnerability"));
    assert.equal(d.empty, false);
  });
  test("expiring certificates lead the subject and say when they were checked", () => {
    const prefs = { certs: [{ domain: "shop.example.com", notAfter: new Date(NOW + 5 * DAY).toISOString() }], certsAt: NOW - 2 * DAY };
    const d = buildDigest({ kev: KEV, prefs, now: NOW, unsubUrl: "https://x/u" });
    assert.ok(d.subject.startsWith("Darknode weekly: 1 certificate expiring"));
    assert.ok(d.text.includes("shop.example.com: expires in 5 days"));
    assert.ok(d.text.includes("as of your check on 2026-10-31"));
  });
  test("an old certificate check gets a re-run nudge", () => {
    const prefs = { certs: [{ domain: "ok.example.com", notAfter: new Date(NOW + 200 * DAY).toISOString() }], certsAt: NOW - 12 * DAY };
    const d = buildDigest({ kev: [], prefs, now: NOW, unsubUrl: "https://x/u" });
    assert.ok(d.text.includes("12 days ago"));
    assert.equal(d.empty, false);
  });
  test("nothing new and nothing expiring means empty (not sent)", () => {
    assert.equal(buildDigest({ kev: [], now: NOW }).empty, true);
  });
  test("escapes feed text in the HTML and carries the unsubscribe link", () => {
    const d = buildDigest({ kev: [{ cve: "CVE-2026-0003", vendor: "<img src=x>", product: "P", dateAdded: "2026-11-01" }], now: NOW, unsubUrl: "https://x/u?a=1&b=2" });
    assert.ok(!d.html.includes("<img src=x>"));
    assert.ok(d.html.includes("&lt;img src=x&gt;"));
    assert.ok(d.html.includes("https://x/u?a=1&amp;b=2"));
    assert.ok(d.text.includes("Unsubscribe: https://x/u?a=1&b=2"));
  });
  test("test sends are marked", () => {
    assert.ok(buildDigest({ kev: KEV, now: NOW, test: true }).subject.startsWith("[Test] "));
  });
});

group("digest/unsubToken", () => {
  test("stable per uid and secret, different across both", async () => {
    const a = await unsubToken("uid1", "s1");
    assert.equal(a, await unsubToken("uid1", "s1"));
    assert.notEqual(a, await unsubToken("uid2", "s1"));
    assert.notEqual(a, await unsubToken("uid1", "s2"));
    assert.equal(a.length, 32);
  });
});
