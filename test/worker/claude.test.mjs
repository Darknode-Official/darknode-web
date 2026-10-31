// Server-held Claude (provider "anthropic"): message conversion, stream conversion,
// the access gates on /api/chat, and a guard that no Anthropic key is ever committed.
import { test, group, assert } from "../harness.mjs";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import worker, { toClaudeBody, claudeStream, withPromptCache, CLAUDE_MODELS } from "../../worker/worker.js";

let ipN = 0;
async function chat(body, env, headers = {}) {
  const realFetch = globalThis.fetch;
  let upstreamCalls = 0;
  globalThis.fetch = async () => { upstreamCalls++; throw new Error("no network in tests"); };
  try {
    const h = new Headers({ "cf-connecting-ip": "203.0.113." + (ipN++ % 200), ...headers });
    const r = await worker.fetch(new Request("https://w.test/api/chat", { method: "POST", body: JSON.stringify(body), headers: h }), env);
    return { status: r.status, body: await r.json(), upstreamCalls };
  } finally { globalThis.fetch = realFetch; }
}
const msg = (model) => ({ provider: "anthropic", model, messages: [{ role: "user", content: "hi" }] });

group("worker: server-held Claude", () => {
  test("toClaudeBody: systems joined, roles filtered, neighbours merged, starts on user, capped output", () => {
    const b = toClaudeBody("claude-haiku-5-5", [
      { role: "system", content: "S1" }, { role: "assistant", content: "early" }, { role: "system", content: "S2" },
      { role: "user", content: "a" }, { role: "user", content: [{ type: "text", text: "b" }] }, { role: "tool", content: "x" },
      { role: "assistant", content: "c" }, { role: "user", content: "" },
    ]);
    assert.equal(b.system, "S1\n\nS2");
    assert.deepEqual(b.messages, [{ role: "user", content: "a\n\nb" }, { role: "assistant", content: "c" }]);
    assert.equal(b.stream, true); assert.equal(b.max_tokens, 4096);
  });
  test("withPromptCache: caches the system prefix and the end of the conversation", () => {
    const b = withPromptCache({ model: "m", system: "S", messages: [{ role: "user", content: "a" }, { role: "assistant", content: "b" }, { role: "user", content: "c" }] });
    // system becomes a cached text block
    assert.deepEqual(b.system, [{ type: "text", text: "S", cache_control: { type: "ephemeral" } }]);
    // only the last message carries a breakpoint, as a block array
    assert.deepEqual(b.messages[0], { role: "user", content: "a" });
    assert.deepEqual(b.messages[2], { role: "user", content: [{ type: "text", text: "c", cache_control: { type: "ephemeral" } }] });
    // at most the two breakpoints we place (max 4 allowed by the API)
    assert.equal(JSON.stringify(b).match(/cache_control/g).length, 2);
  });
  test("withPromptCache: no system, array content, and empty messages are handled", () => {
    const noSys = withPromptCache({ messages: [{ role: "user", content: [{ type: "text", text: "a" }, { type: "text", text: "b" }] }] });
    assert.ok(!("system" in noSys) || noSys.system === undefined);
    // breakpoint lands on the last existing block, the others untouched
    assert.deepEqual(noSys.messages[0].content, [{ type: "text", text: "a" }, { type: "text", text: "b", cache_control: { type: "ephemeral" } }]);
    // empty system / no messages: nothing to cache, and no throw
    const empty = withPromptCache({ system: "", messages: [] });
    assert.equal(JSON.stringify(empty).match(/cache_control/g), null);
  });
  test("the stream keeps only text deltas and ends with one [DONE]", async () => {
    const ev = (o) => "event: x\ndata: " + JSON.stringify(o) + "\n\n";
    const up = new Response(ev({ type: "message_start" }) + ev({ type: "content_block_delta", delta: { type: "thinking_delta", thinking: "secret" } })
      + ev({ type: "content_block_delta", delta: { type: "text_delta", text: "Hel" } }) + ev({ type: "ping" })
      + ev({ type: "content_block_delta", delta: { type: "text_delta", text: "lo" } }) + ev({ type: "message_stop" }));
    const out = await (claudeStream(up)).text();
    const texts = out.split("\n").filter((l) => l.startsWith("data: ") && l !== "data: [DONE]").map((l) => JSON.parse(l.slice(6)).choices[0].delta.content);
    assert.deepEqual(texts, ["Hel", "lo"]);
    assert.ok(!out.includes("secret") && !out.includes("event:"));
    assert.equal(out.match(/\[DONE\]/g).length, 1);
  });
  test("a refusal (stop_reason refusal, no text block) is surfaced, not a blank answer", async () => {
    const ev = (o) => "event: x\ndata: " + JSON.stringify(o) + "\n\n";
    const up = new Response(ev({ type: "message_start" })
      + ev({ type: "message_delta", delta: { stop_reason: "refusal", stop_details: { type: "refusal", category: "cyber" } } })
      + ev({ type: "message_stop" }));
    const out = await (claudeStream(up)).text();
    const texts = out.split("\n").filter((l) => l.startsWith("data: ") && l !== "data: [DONE]").map((l) => JSON.parse(l.slice(6)).choices[0].delta.content);
    assert.equal(texts.length, 1);
    assert.ok(/declined/i.test(texts[0]), texts[0]);
    assert.equal(out.match(/\[DONE\]/g).length, 1);
  });
  test("a first chunk with no text (message_start alone) does not stall the stream", async () => {
    const enc = new TextEncoder();
    const chunks = [{ type: "message_start" }, { type: "ping" }, { type: "content_block_delta", delta: { type: "text_delta", text: "ok" } }, { type: "message_stop" }]
      .map((o) => enc.encode("data: " + JSON.stringify(o) + "\n\n"));
    const body = new ReadableStream({ pull(c) { const x = chunks.shift(); if (x) c.enqueue(x); else c.close(); } });
    const out = await Promise.race([claudeStream(new Response(body)).text(), new Promise((r) => setTimeout(() => r("TIMEOUT"), 2000))]);
    assert.ok(out.includes('"content":"ok"') && out.endsWith("data: [DONE]\n\n"), out);
  });
  test("no key: 503; unknown model: 400; signed out: 401; none reach Anthropic", async () => {
    const env = { ANTHROPIC_KEY: "test-key", FIREBASE_PROJECT_ID: "p1" };
    const a = await chat(msg("claude-opus-5-5"), { FIREBASE_PROJECT_ID: "p1" });
    assert.equal(a.status, 503);
    const b = await chat(msg("claude-2"), env);
    assert.equal(b.status, 400);
    const c = await chat(msg("claude-opus-5-5"), env);
    assert.equal(c.status, 401); assert.equal(c.body.error, "Sign in to use Claude models.");
    const d = await chat(msg("claude-opus-5-5"), env, { Authorization: "Bearer not.a.jwt" });
    assert.equal(d.status, 401);
    for (const r of [a, b, c, d]) assert.equal(r.upstreamCalls, 0);
    assert.ok(![a, b, c, d].some((r) => JSON.stringify(r.body).includes("test-key")));
  });
  test("the allow-list holds only current Claude ids", () => {
    for (const m of CLAUDE_MODELS) assert.ok(/^claude-[a-z]+-\d+(-\d+)?$/.test(m), m);
  });
});

group("no Anthropic key in the repo", () => {
  test("public/, worker/, scripts/ and docs carry no sk-ant- key", () => {
    const root = join(dirname(fileURLToPath(import.meta.url)), "../..");
    const KEY = /sk-ant-[a-z0-9]+-[A-Za-z0-9_-]{20,}/;
    const hits = [];
    const walk = (d) => {
      for (const n of readdirSync(d)) {
        if (n === "node_modules" || n.startsWith(".")) continue;
        const f = join(d, n), st = statSync(f);
        if (st.isDirectory()) walk(f);
        else if (/\.(m?js|cjs|html|json|toml|md|txt|ya?ml)$/.test(n) && st.size < 8e6 && KEY.test(readFileSync(f, "utf8"))) hits.push(f.slice(root.length + 1));
      }
    };
    for (const d of ["public", "worker", "scripts", "docs", "functions"]) { try { walk(join(root, d)); } catch (_) {} }
    for (const f of ["README.md", "firebase.json"]) { try { if (KEY.test(readFileSync(join(root, f), "utf8"))) hits.push(f); } catch (_) {} }
    assert.deepEqual(hits, []);
  });
});

group("Claude persona is refusal-safe", () => {
  test("webai.js defines CLAUDE_SYS, used for the anthropic provider, without the jailbreak-shaped Gemini framing", () => {
    const root = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
    const src = readFileSync(join(root, "public/js/webai.js"), "utf8");
    assert.ok(/const CLAUDE_SYS = `/.test(src), "CLAUDE_SYS missing");
    const sys = src.slice(src.indexOf("const CLAUDE_SYS = `") + 20, src.indexOf("`;", src.indexOf("const CLAUDE_SYS = `")));
    // The persona Claude's strongest models refuse: pre-authorization + "don't refuse" + raw offensive command catalog.
    for (const bad of ["assume authorized", "refusing flatly", "reverse shell", "sqlmap", "--os-shell", "Credential Dumping"])
      assert.ok(!new RegExp(bad, "i").test(sys), "CLAUDE_SYS should not contain: " + bad);
    assert.ok(sys.length < 2000, "CLAUDE_SYS should stay lean, was " + sys.length);
    assert.ok(/anthropic.*CLAUDE_SYS|CLAUDE_SYS.*anthropic/s.test(src.replace(/\n/g, " ")), "CLAUDE_SYS is not wired to the anthropic provider");
  });
});
