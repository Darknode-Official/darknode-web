// /api/chat upstream failures: provider error bodies never reach the browser, and the
// shared Gemini path still retries on the backup key. No network: fetch is mocked.
import { test, assert, group } from "../harness.mjs";
import worker from "../../worker/worker.js";

let ipN = 0;
async function chat(env, upstream) {
  const realFetch = globalThis.fetch, realWarn = console.warn, seen = [];
  globalThis.fetch = async (url, init) => { seen.push(String(url)); return upstream(String(url), init); };
  console.warn = () => {}; // upstreamError logs the provider body server-side
  try {
    const body = JSON.stringify({ provider: "gemini", model: "gemini-test-model", messages: [{ role: "user", content: "hi" }] });
    const r = await worker.fetch(new Request("https://w.test/api/chat", { method: "POST", body, headers: { "cf-connecting-ip": "198.51.100." + (ipN++ % 250) } }), env);
    return { status: r.status, text: await r.text(), seen };
  } finally { globalThis.fetch = realFetch; console.warn = realWarn; }
}
const SECRET = "project 1234 billing account acct-SECRET quota detail";
const sse = () => new Response('data: {"candidates":[{"content":{"parts":[{"text":"ok"}]}}]}\n\n', { status: 200, headers: { "content-type": "text/event-stream" } });

group("worker: chat upstream errors", () => {
  test("a provider 500 becomes a plain 502 sentence; the provider body is not forwarded", async () => {
    const r = await chat({ GEMINI_KEY: "k1" }, async () => new Response(SECRET, { status: 500 }));
    assert.equal(r.status, 502);
    const j = JSON.parse(r.text);
    assert.ok(/didn't answer/.test(j.error), j.error);
    assert.ok(!r.text.includes("SECRET") && !r.text.includes("Upstream"), r.text);
  });
  test("a rejected key (401) retries on GEMINI_KEY_2 and streams the answer", async () => {
    const r = await chat({ GEMINI_KEY: "k1", GEMINI_KEY_2: "k2" }, async (url) => url.includes("key=k2") ? sse() : new Response(SECRET, { status: 401 }));
    assert.equal(r.status, 200);
    assert.ok(r.seen.some((u) => u.includes("key=k1")) && r.seen.some((u) => u.includes("key=k2")));
    assert.ok(r.text.includes('"content":"ok"'), r.text);
  });
  test("a key rejected on both keys is reported as our service being unavailable (503), not the user's fault", async () => {
    const r = await chat({ GEMINI_KEY: "k1", GEMINI_KEY_2: "k2" }, async () => new Response(SECRET, { status: 403 }));
    assert.equal(r.status, 503);
    assert.ok(!r.text.includes("SECRET"));
  });
  test("a retired model (404) steps down to the stable fallback models", async () => {
    const r = await chat({ GEMINI_KEY: "k1" }, async (url) => url.includes("gemini-test-model") ? new Response(SECRET, { status: 404 }) : sse());
    assert.equal(r.status, 200);
    assert.ok(r.seen.some((u) => u.includes("/gemini-3.5-flash:")), r.seen.join("\n"));
  });
  test("no server key configured: 503 with a neutral message (no provider or secret names)", async () => {
    const r = await chat({}, async () => sse());
    assert.equal(r.status, 503);
    assert.ok(!/GEMINI_KEY|configured/.test(r.text), r.text);
  });
});
