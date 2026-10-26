// dnFetch (public/js/net.js) against a stubbed proxy: Cloudflare's own edge error
// page must not be returned as if the target site had answered.

import { test, assert, group } from "../harness.mjs";
import { dnFetch } from "../../public/js/net.js";

const withProxy = async (reply, fn) => {
  const prevW = globalThis.window, prevF = globalThis.fetch;
  globalThis.window = { DARKNODE_PROXY_URL: "https://proxy.test/api/chat" };
  globalThis.fetch = async () => ({ json: async () => reply });
  try { return await fn(); } finally { globalThis.window = prevW; globalThis.fetch = prevF; }
};
const rejects = async (p) => { try { await p; return ""; } catch (e) { return e.message; } };

group("net: dnFetch", () => {
  test("a Cloudflare 1016 page (host does not resolve) throws a plain reason", async () => {
    const msg = await withProxy({ status: 530, headers: { "referrer-policy": "same-origin" }, body: "error code: 1016\n" },
      () => rejects(dnFetch("https://nope.example/")));
    assert.ok(/nope\.example could not be reached: its name does not resolve/.test(msg), msg);
  });
  test("an unlisted Cloudflare edge code still throws, naming the code", async () => {
    const msg = await withProxy({ status: 502, body: "error code: 1033" }, () => rejects(dnFetch("https://x.example/")));
    assert.ok(/Cloudflare error 1033/.test(msg), msg);
  });
  test("a real site's error status is returned, not thrown", async () => {
    const r = await withProxy({ status: 404, body: "Not Found" }, () => dnFetch("https://x.example/missing"));
    assert.equal(r.status, 404);
    const ok = await withProxy({ status: 200, body: "the page mentions error code: 1016 in prose" }, () => dnFetch("https://x.example/"));
    assert.equal(ok.status, 200);
  });
});
