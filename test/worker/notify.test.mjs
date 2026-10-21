// Unit tests for worker/notify.js — alert delivery payloads, signing and deliver().
import { test, group, assert } from "../harness.mjs";
import { slackPayload, teamsPayload, discordPayload, genericPayload, signBody, deliver } from "../../worker/notify.js";

const ALERT = {
  title: "New critical finding on web01",
  severity: "critical",
  text: "A KEV vulnerability is now exposed.",
  url: "https://darknode.ai/deck#findings",
  events: [{ kind: "new", severity: "critical", title: "CVE-2026-0001 on web01", detail: "exposed via RDP" }],
};

group("notify/payloads", () => {
  test("slack payload carries the title, body lines and a deck link", () => {
    const p = slackPayload(ALERT);
    assert.ok(p.text.includes("New critical finding"));
    const dump = JSON.stringify(p);
    assert.ok(dump.includes("CVE-2026-0001 on web01"));
    assert.ok(dump.includes("Open in the Deck"));
  });

  test("teams payload is a MessageCard with a themed colour", () => {
    const p = teamsPayload(ALERT);
    assert.equal(p["@type"], "MessageCard");
    assert.equal(p.themeColor, "C62828");
    assert.ok(p.potentialAction && p.potentialAction[0].targets[0].uri.includes("darknode"));
  });

  test("discord payload uses an embed with a numeric colour", () => {
    const p = discordPayload(ALERT);
    assert.equal(p.embeds[0].color, 0xc62828);
    assert.ok(p.embeds[0].description.includes("CVE-2026-0001"));
  });

  test("generic payload wraps the whole alert with a type tag", () => {
    const p = genericPayload(ALERT);
    assert.equal(p.type, "darknode.alert");
    assert.equal(p.alert.title, ALERT.title);
  });
});

group("notify/signing + deliver", () => {
  test("signBody is a stable 64-char hex HMAC and changes with the secret", async () => {
    const a = await signBody('{"x":1}', "s3cr3t");
    const b = await signBody('{"x":1}', "s3cr3t");
    const c = await signBody('{"x":1}', "other");
    assert.equal(a.length, 64);
    assert.ok(/^[0-9a-f]+$/.test(a));
    assert.equal(a, b);
    assert.ok(a !== c);
    assert.equal(await signBody("x", ""), "");
  });

  test("deliver posts the built body and reports status", async () => {
    let seen = null;
    const fakeFetch = async (url, opts) => { seen = { url, opts }; return { ok: true, status: 200 }; };
    const r = await deliver({ type: "slack", url: "https://hooks.slack.test/x" }, ALERT, { fetch: fakeFetch });
    assert.equal(r.ok, true);
    assert.equal(seen.url, "https://hooks.slack.test/x");
    assert.ok(JSON.parse(seen.opts.body).text.includes("New critical finding"));
  });

  test("a signed webhook attaches an HMAC header the receiver can verify", async () => {
    let seen = null;
    const fakeFetch = async (url, opts) => { seen = opts; return { ok: true, status: 202 }; };
    const r = await deliver({ type: "webhook", url: "https://ci.test/hook", secret: "shh" }, ALERT, { fetch: fakeFetch });
    assert.equal(r.status, 202);
    const sig = seen.headers["x-darknode-signature"];
    assert.ok(sig.startsWith("sha256="));
    const expected = "sha256=" + (await signBody(seen.body, "shh"));
    assert.equal(sig, expected);
  });

  test("a fetch failure is reported, not thrown", async () => {
    const fakeFetch = async () => { throw new Error("network down"); };
    const r = await deliver({ type: "slack", url: "https://x" }, ALERT, { fetch: fakeFetch });
    assert.equal(r.ok, false);
    assert.ok(r.error.includes("network"));
  });

  test("a channel with no url fails cleanly", async () => {
    const r = await deliver({ type: "slack" }, ALERT, { fetch: async () => ({ ok: true, status: 200 }) });
    assert.equal(r.ok, false);
  });
});

group("notify/ssrf guard", () => {
  test("deliver refuses a channel url on a private or metadata host (no fetch)", async () => {
    let called = false;
    const spy = async () => { called = true; return { ok: true, status: 200 }; };
    for (const url of ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1/hook", "http://10.0.0.1/x", "http://2130706433/x"]) {
      const r = await deliver({ type: "webhook", url }, ALERT, { fetch: spy });
      assert.equal(r.ok, false);
      assert.ok(r.error.includes("not allowed"));
    }
    assert.notOk(called, "fetch must not run for a blocked host");
  });
  test("deliver still posts to a public webhook host", async () => {
    const r = await deliver({ type: "webhook", url: "https://hooks.slack.com/services/x" }, ALERT, { fetch: async () => ({ ok: true, status: 200 }) });
    assert.equal(r.ok, true);
  });
});
