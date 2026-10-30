// Deck native tools audit (domain-check, phish-check, ui.js): each test pins one reproduced
// bug. The native tools import "/js/..." site-absolute paths, so a resolve hook maps those
// to public/js; network calls reject (offline) through a stubbed fetch.

import { test, group, assert } from "../harness.mjs";
import { register } from "node:module";

const PUB = new URL("../../public", import.meta.url).href;
register("data:text/javascript," + encodeURIComponent(
  `export async function resolve(s, c, n) { return n(s.startsWith("/js/") ? ${JSON.stringify(PUB)} + s : s, c); }`));

globalThis.window = globalThis.window || {};
if (!window.dispatchEvent) window.dispatchEvent = () => {};
if (!globalThis.localStorage) { const m = new Map(); globalThis.localStorage = { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) }; }

const { readFiles, ago, readList } = await import("../../public/js/deck/native/ui.js");
const { pickLink } = await import("../../public/js/deck/native/phish-check.js");
const domainCheck = await import("../../public/js/deck/native/domain-check.js");
const { analyzeUrl } = await import("../../public/js/dataprotect/phish-engine.js");

// a mount target: querySelector hands back one stub per selector, reset when innerHTML is replaced
function fakeRoot() {
  const nodes = {};
  const mk = () => ({ value: "", innerHTML: "", textContent: "", disabled: false, hidden: false, style: {}, dataset: {}, classList: { toggle() {}, add() {} },
    addEventListener() {}, setAttribute() {}, appendChild() {}, scrollIntoView() {}, querySelector: () => mk(), querySelectorAll: () => [] });
  let html = "";
  return { get innerHTML() { return html; }, set innerHTML(v) { html = v; for (const k in nodes) delete nodes[k]; },
    querySelector: (s) => (nodes[s] ||= mk()), querySelectorAll: () => [] };
}
async function offline(fn) {
  const f = globalThis.fetch, t = window.showToast, toasts = [];
  globalThis.fetch = async () => { throw new Error("offline"); }; window.showToast = (m) => toasts.push(m);
  try { return await fn(toasts); } finally { globalThis.fetch = f; window.showToast = t; }
}
const settle = () => new Promise((r) => setTimeout(r, 30));

group("deck native audit", () => {
  test("Link check picks a data:, javascript: or bare-IP link out of a sentence, not the first word", () => {
    // was "Click" (graded on the .click TLD) and "Go" ("No red flags found")
    assert.equal(pickLink("Click data:text/html;base64,PHNjcmlwdD4= now"), "data:text/html;base64,PHNjcmlwdD4=");
    assert.equal(pickLink("Please see javascript:alert(1)"), "javascript:alert(1)");
    assert.equal(pickLink("Go to 10.0.0.1/login now"), "10.0.0.1/login");
    assert.ok(analyzeUrl(pickLink("Go to 10.0.0.1/login now")).severity !== "info");
  });

  test("Link check keeps a closing ) or ] that is part of the link, strips one that is not", () => {
    assert.equal(pickLink("Open https://example.com/wiki/Foo_(bar)."), "https://example.com/wiki/Foo_(bar)");
    assert.equal(pickLink("(see https://example.com/a)"), "https://example.com/a");
    assert.equal(pickLink("[https://example.com]"), "https://example.com");
    assert.equal(pickLink("http://[::1]"), "http://[::1]");
    assert.equal(pickLink("Click here: hxxps[:]//example[.]com/a"), "hxxps[:]//example[.]com/a");
    assert.equal(pickLink("Version 1.2.3 is out at example.com."), "example.com");
  });

  test("Domain check accepts *.example.com like the portfolio does, and a deep link does not overwrite a running check", async () => {
    await offline(async (toasts) => {
      const el = fakeRoot(), api = domainCheck.mount(el, { space: "audit", mode: "personal" });
      el.querySelector("#nsDcIn").value = "*.example.com"; el.querySelector("#nsDcGo").onclick();
      assert.equal(toasts.length, 0, "was rejected with 'Enter a domain like yourdomain.com'");
      assert.ok(el.querySelector("#nsDcOut").innerHTML.includes("<b>example.com</b>"));
      api.run("other.example.com"); // arrives while the first check runs
      assert.equal(el.querySelector("#nsDcIn").value, "*.example.com");
      await settle();
      assert.ok(el.querySelector("#nsDcOut").innerHTML.includes("Could not reach example.com"));
    });
  });

  test("Domain portfolio does not grade 'com' for www.com: it is reported as skipped", async () => {
    await offline(async () => {
      const el = fakeRoot(); domainCheck.mount(el, { space: "audit-pf", mode: "portfolio" });
      el.querySelector("#nsPfIn").value = "www.com\nexample.com";
      await el.querySelector("#nsPfGo").onclick();
      assert.deepEqual(readList("audit-pf", "domains"), ["example.com"]);
      assert.ok(/Skipped 1 that is not a domain name: www\.com/.test(el.querySelector("#nsPfSt").textContent));
    });
  });

  test("readFiles skips one unreadable file instead of aborting the whole pick", async () => {
    const F = (p, t, bad) => ({ name: p, size: t.length, text: async () => { if (bad) throw new Error("NotReadableError"); return t; } });
    const r = await readFiles([F("a.js", "x"), F("locked.js", "y", true), F("b.js", "z"), F("empty.txt", "")]);
    assert.equal(r.files.map((f) => f.path).join(), "a.js,b.js,empty.txt");
    assert.equal(r.skipped.join(), "locked.js");
  });

  test("ago() never shows '60 min ago' or '24 h ago' at a unit boundary", () => {
    const now = Date.now();
    assert.equal(ago(now - 3590e3), "59 min ago");
    assert.equal(ago(now - 86000e3), "23 h ago");
    assert.equal(ago(now - 90e3), "1 min ago");
    assert.equal(ago(now - 2 * 86400e3), "2 d ago");
  });
});
