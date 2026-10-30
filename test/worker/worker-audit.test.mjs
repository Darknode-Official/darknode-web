// Regression tests for the worker security audit (2026-10-30). No network: fetch is mocked.
import { hostAllowed } from "../../worker/net-guard.js";
import { test, assert, group } from "../harness.mjs";
import worker from "../../worker/worker.js";
import { runCheck } from "../../worker/checks.js";

let ipN = 0;
async function call(path, init = {}, upstream) {
  const realFetch = globalThis.fetch;
  globalThis.fetch = upstream || (async () => { throw new Error("no network in tests"); });
  try {
    const headers = new Headers(init.headers || {});
    headers.set("cf-connecting-ip", "203.0.113." + (ipN++ % 250)); // fresh rate-limit bucket
    const r = await worker.fetch(new Request("https://w.test" + path, { ...init, headers }), {});
    return { status: r.status, type: r.headers.get("content-type") || "", body: await r.text() };
  } finally { globalThis.fetch = realFetch; }
}

group("worker audit", () => {
  test("a handler that throws (/api/intel with a JSON null body) answers JSON 500, not an uncaught 1101", async () => {
    const r = await call("/api/intel", { method: "POST", body: "null" });
    assert.equal(r.status, 500);
    assert.ok(r.type.includes("application/json"));
    assert.deepEqual(JSON.parse(r.body), { error: "Internal error." });
  });

  test("/api/chat rejects Object.prototype names as providers with 400 (was 500 'key not configured')", async () => {
    for (const provider of ["constructor", "toString", "__proto__"]) {
      const r = await call("/api/chat", { method: "POST", body: JSON.stringify({ provider, model: "m", messages: [{ role: "user", content: "hi" }] }) });
      assert.equal(r.status, 400, provider);
      assert.ok(JSON.parse(r.body).error.startsWith("Unknown provider"), provider);
    }
  });

  test("/api/fetch reports truncated:true when the body is cut to the cap below the read ceiling", async () => {
    const up = async () => new Response("x".repeat(500000), { status: 200, headers: { "content-type": "application/json" } });
    const j = JSON.parse((await call("/api/fetch?url=https://example.com/", {}, up)).body);
    assert.equal(j.body.length, 200000);
    assert.equal(j.bytes, 500000);
    assert.equal(j.truncated, true);
    const small = JSON.parse((await call("/api/fetch?url=https://example.com/", {}, async () => new Response("ok", { headers: { "content-type": "text/plain" } }))).body);
    assert.equal(small.truncated, false);
  });

  test("runCheck ignores Object.prototype names instead of running them as checks", async () => {
    for (const t of ["toString", "constructor", "valueOf", "__proto__"]) {
      assert.deepEqual(await runCheck(t, { domains: ["example.com"] }, {}), [], t);
    }
  });
});

group("worker/net-guard trailing-dot hosts", () => {
  test("a trailing dot does not bypass the private-host checks", () => {
    for (const h of ["localhost.", "db.internal.", "printer.local.", "a.localhost.."]) {
      assert.equal(hostAllowed(new URL("http://" + h + "/")), false, h);
    }
    assert.equal(hostAllowed(new URL("http://example.com./")), true);
  });
});

group("worker/body-cap", () => {
  test("bodies over the cap are refused without buffering them whole", async () => {
    const { readCapped } = await import("../../worker/body-cap.js");
    const req = (body, headers) => new Request("https://example.com/", { method: "POST", body, headers, duplex: "half" });
    assert.equal(await readCapped(req("héllo"), 100), "héllo");
    assert.equal(await readCapped(req("x".repeat(101)), 100), null);
    assert.equal(await readCapped(req("x", { "content-length": "999999" }), 100), null);
    let pulled = 0;
    const stream = new ReadableStream({ pull(c) { pulled++; c.enqueue(new Uint8Array(64 * 1024)); } });
    assert.equal(await readCapped(req(stream), 100000), null);
    assert.ok(pulled < 5, "stopped reading after the cap, pulled " + pulled);
    assert.equal(await readCapped(new Request("https://example.com/"), 10), "");
  });
  test("/api/chat rejects an oversized body with CORS headers", async () => {
    const r = await worker.fetch(new Request("https://w.test/api/chat", { method: "POST", body: "x".repeat(1024 * 1024 + 1), headers: { "cf-connecting-ip": "203.0.113.251" } }), {});
    assert.equal(r.status, 413);
    assert.ok(r.headers.get("access-control-allow-origin"));
  });
});
