// public/sw.js navigation fallback: when the network, the cached shell and a direct fetch of
// "/" all fail, a navigation gets a plain offline page (503 HTML), never Response.error(),
// which Chrome logs as "FetchEvent ... resulted in a network error response".
import { test, group, assert } from "../harness.mjs";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const SW = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "../../public/sw.js"), "utf8");

function loadSw() {
  const handlers = {};
  const self = { addEventListener: (t, fn) => { handlers[t] = fn; }, skipWaiting() {}, clients: { claim() {} } };
  const caches = { match: async () => undefined, open: async () => ({ match: async () => undefined, put: async () => {}, addAll: async () => {} }), keys: async () => [], delete: async () => true };
  const fetch = async () => { throw new TypeError("Failed to fetch"); };
  const location = { origin: "https://darknode.ai" };
  new Function("self", "caches", "fetch", "location", SW)(self, caches, fetch, location);
  return handlers;
}

group("sw: offline navigation fallback", () => {
  test("a navigation with nothing reachable gets a 503 offline page, not Response.error()", async () => {
    const h = loadSw();
    let p = null;
    h.fetch({ request: { url: "https://darknode.ai/settings", method: "GET", mode: "navigate" }, respondWith: (r) => { p = r; } });
    const res = await p;
    assert.equal(res.status, 503);
    assert.equal(res.type, "default");
    assert.equal(res.headers.get("content-type"), "text/html; charset=utf-8");
    assert.equal(res.headers.get("cache-control"), "no-store");
    const html = await res.text();
    assert.ok(html.includes("You're offline") && html.includes("couldn't reach the server"), html);
    assert.ok(html.includes('<a href="">Reload</a>'), html);
    assert.ok(!/<script|<link|src=/i.test(html), "no script or external assets");
  });
});
