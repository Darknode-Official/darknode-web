// Worker runner tests (public/js/ingest/worker.js). Node has no global Worker,
// so these exercise the main-thread fallback path and engineUrl().

import { test, assert, group } from "../harness.mjs";
import { engineUrl, runInWorker } from "../../public/js/ingest/worker.js";

const ENGINE = engineUrl("./fixtures/echo-engine.mjs", import.meta);

group("ingest: worker runner", () => {
  test("engineUrl resolves relative to import.meta", () => {
    assert.ok(ENGINE.startsWith("file://"), ENGINE);
    assert.ok(ENGINE.endsWith("/test/ingest/fixtures/echo-engine.mjs"), ENGINE);
    assert.equal(engineUrl("../x.js", { url: "https://h/a/b/c.js" }), "https://h/a/x.js");
  });
  test("fallback returns the engine result", async () => {
    const out = await runInWorker(ENGINE, "echo", [1, { k: "v" }]);
    assert.deepEqual(out, { a: 1, b: { k: "v" } });
  });
  test("progress callback is invoked with (done, total, label)", async () => {
    const seen = [];
    await runInWorker(ENGINE, "echo", [1, 2], { onProgress: (d, t, l) => seen.push([d, t, l]) });
    assert.deepEqual(seen, [[1, 2, "half"]]);
  });
  test("engine without onProgress still gets a callable ctx.progress", async () => {
    const out = await runInWorker(ENGINE, "noCtx", [7]);
    assert.deepEqual(out, { x: 7, hasCtx: true });
  });
  test("thrown engine error propagates", async () => {
    let err = null;
    try { await runInWorker(ENGINE, "boom", []); } catch (e) { err = e; }
    assert.ok(err instanceof Error);
    assert.equal(err.message, "boom failed");
  });
  test("missing export rejects with a clear message", async () => {
    let err = null;
    try { await runInWorker(ENGINE, "nope", []); } catch (e) { err = e; }
    assert.ok(err && /no export "nope"/.test(err.message), err && err.message);
  });
  test("bad engine URL rejects", async () => {
    let err = null;
    try { await runInWorker(ENGINE + ".missing.mjs", "echo", []); } catch (e) { err = e; }
    assert.ok(err instanceof Error);
  });
  test("returned promise exposes cancel()", () => {
    const p = runInWorker(ENGINE, "echo", [1, 2]);
    assert.equal(typeof p.cancel, "function");
    return p;
  });
  test("typed-array args pass through the fallback intact", async () => {
    const u = new Uint8Array([1, 2, 3]);
    const out = await runInWorker(ENGINE, "echo", [u, u.buffer]);
    assert.equal(out.a.length, 3);
    assert.equal(out.b.byteLength, 3);
  });
});
