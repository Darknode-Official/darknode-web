// Regression tests for the Deck recon-tool audit (2026-10-30): SSL Inspector,
// Subdomain Finder, Wayback Recon, Favicon Hasher and ASN Explorer. Each test
// pins a reproduced bug. These tools keep their logic inside render closures
// and talk to the DOM by id, so the tests drive them through a tiny DOM shim
// (installed per test, then removed) with fetch and the clipboard stubbed.
// subdomain-finder.js imports /js/net.js by absolute path, so its pure helpers
// are evaluated from the source text.

import fs from "node:fs";
import { test, assert, group } from "../harness.mjs";

const src = (f) => fs.readFileSync(new URL("../../public/js/" + f, import.meta.url), "utf8");
const mod = (f) => new URL("../../public/js/" + f, import.meta.url).href;
const tick = () => new Promise((r) => setTimeout(r, 15));

// Elements by id; setting innerHTML registers every id="..." it contains.
async function withDom(fn) {
  const saved = {};
  for (const k of ["window", "document", "fetch", "navigator"]) saved[k] = Object.getOwnPropertyDescriptor(globalThis, k);
  const els = {};
  const mk = (id) => ({
    id, value: "", textContent: "", _html: "", style: {}, disabled: false, listeners: {},
    get innerHTML() { return this._html; },
    set innerHTML(h) { this._html = h; for (const m of String(h).matchAll(/id="([^"]+)"/g)) if (!els[m[1]]) els[m[1]] = mk(m[1]); },
    addEventListener(t, f) { (this.listeners[t] ||= []).push(f); },
    querySelectorAll() { return []; }, querySelector() { return null; },
    click() { (this.listeners.click || []).forEach((f) => f.call(this, {})); },
  });
  const plainEl = () => { let t = ""; return { set textContent(v) { t = String(v); }, get innerHTML() { return t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); } }; };
  Object.defineProperty(globalThis, "window", { value: globalThis, configurable: true, writable: true });
  Object.defineProperty(globalThis, "document", { value: { getElementById: (id) => els[id] || null, createElement: plainEl, querySelector: () => null }, configurable: true, writable: true });
  try { await fn({ els, mk }); }
  finally {
    for (const k of Object.keys(saved)) { if (saved[k]) Object.defineProperty(globalThis, k, saved[k]); else delete globalThis[k]; }
  }
}
const setGlobal = (k, v) => Object.defineProperty(globalThis, k, { value: v, configurable: true, writable: true });

group("ssl-inspector", () => {
  const rows = [{ id: 1, common_name: "example.com", issuer_name: "C=US, O=Let's Encrypt, CN=R3", not_before: "2026-01-01T00:00:00", not_after: "2027-01-01T00:00:00",
    name_value: "example.com\nwww.example.com\nmyexample.com\nexample.com.evil.net\nx');alert(1);('.example.com" }];
  async function search(input) {
    let out;
    await withDom(async ({ els, mk }) => {
      const { renderSSLInspector } = await import(mod("ssl-inspector.js"));
      let onTab; const c = mk("c"); c.addEventListener = (t, f) => { onTab = f; };
      renderSSLInspector(c);
      let asked = "";
      setGlobal("fetch", async (u) => { asked = u; return { ok: true, json: async () => rows }; });
      els["ssl-domain"].value = input;
      globalThis._sslSearch(); await tick();
      onTab({ target: { classList: { contains: () => true }, style: {}, getAttribute: () => "subdomains" } });
      out = { asked, html: els["ssl-results"].innerHTML };
    });
    return out;
  }
  test("only real subdomains are listed, not SANs that merely contain the domain", async () => {
    const { html } = await search("example.com");
    assert.ok(html.includes("2 UNIQUE SUBDOMAINS"), html.slice(0, 200));
    assert.ok(!html.includes("myexample.com") && !html.includes("example.com.evil.net"));
  });
  test("a port in the input is dropped from the CT query", async () => {
    assert.equal((await search("https://Example.com:8443/path")).asked, "https://crt.sh/?q=%25.example.com&output=json");
  });
  test("a quote in a certificate name cannot break out of the copy handler", async () => {
    const { html } = await search("example.com");
    const attr = [...html.matchAll(/onclick="(navigator\.clipboard\.writeText\([^"]*)"/g)].map((m) => m[1]).find((a) => a.includes("alert"));
    const decoded = attr.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, "&");
    assert.ok(decoded.startsWith("navigator.clipboard.writeText(" + JSON.stringify("x');alert(1);('.example.com") + ");"), decoded);
  });
});

group("subdomain-finder", () => {
  const s = src("subdomain-finder.js");
  const body = s.slice(s.indexOf("const TAKEOVER_FINGERPRINTS"), s.indexOf("// Real enumeration"));
  const { generatePermutations, takeoverMatches } = new Function(body + "\nreturn { generatePermutations, takeoverMatches };")();
  test("permutations are all valid hostnames", () => {
    const re = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i;
    const out = generatePermutations("a.bc.com").map((p) => p.domain);
    assert.ok(out.length > 50);
    assert.deepEqual(out.filter((d) => !re.test(d)), []);
  });
  test("takeover fingerprints match on label boundaries", () => {
    const svc = (c) => takeoverMatches(c).map((f) => f.service);
    assert.deepEqual(svc("myweb.apple.com"), []);
    assert.deepEqual(svc("helpdesk.company.com"), []);
    assert.deepEqual(svc("mygithub.company.com"), []);
    assert.deepEqual(svc("app.herokuapp.com."), ["Heroku"]);
    assert.deepEqual(svc("site.web.app"), ["Firebase"]);
    assert.deepEqual(svc("x.s3-website-us-east-1.amazonaws.com"), ["AWS S3"]);
    assert.ok(s.includes("var matched = takeoverMatches(cname);"));
  });
  test("an IDN (punycode) TLD is accepted for a scan", () => {
    const re = s.match(/!(\/\^\[a-z0-9\.-\]\+\\\.\(\?:[^/]+\/)\.test\(domain\)/);
    assert.ok(re, "scan regex present");
    const rx = new Function("return " + re[1])();
    assert.ok(rx.test("example.xn--p1ai") && rx.test("example.com") && !rx.test("example"));
  });
});

group("wayback-recon", () => {
  async function scanAnd(fn) {
    await withDom(async ({ els, mk }) => {
      const { renderWaybackRecon } = await import(mod("wayback-recon.js"));
      renderWaybackRecon(mk("c"));
      setGlobal("fetch", async () => ({ ok: true, json: async () => [["timestamp", "original", "mimetype", "statuscode", "digest"], ["20200101000000", "http://example.com/wp-admin/wp-login.php", "text/html", "200", "AAA"]] }));
      els["wb-domain"].value = "example.com";
      els["wb-scan"].click(); await tick();
      await fn(els);
    });
  }
  test("a URL matching several sensitive names gets one SENSITIVE tag", async () => {
    await scanAnd((els) => { assert.equal((els["wb-summary"].innerHTML.match(/>SENSITIVE</g) || []).length, 1); });
  });
  test("a refused clipboard write is reported as a failure", async () => {
    await scanAnd(async (els) => {
      setGlobal("navigator", { clipboard: { writeText: () => Promise.reject(new Error("denied")) } });
      els["wb-csv"].click(); await tick();
      assert.equal(els["wb-status"].textContent, "Copy failed: denied");
      setGlobal("navigator", { clipboard: { writeText: () => Promise.resolve() } });
      els["wb-json"].click(); await tick();
      assert.ok(els["wb-status"].textContent.startsWith("JSON copied"));
    });
  });
});

group("favicon-hasher", () => {
  test("a page URL fetches the favicon from the site root", async () => {
    await withDom(async ({ els, mk }) => {
      const { renderFaviconHasher } = await import(mod("favicon-hasher.js"));
      renderFaviconHasher(mk("c"));
      const asked = [];
      setGlobal("fetch", async (u) => { asked.push(u); return { ok: false }; });
      els["fh-url"].value = "https://example.com/blog/post?id=1";
      els["fh-fetch-btn"].click(); await tick();
      assert.deepEqual(asked, ["https://example.com/favicon.ico", "https://example.com/favicon.png", "https://example.com/apple-touch-icon.png"]);
    });
  });
});

group("asn-explorer", () => {
  test("AS044477 is looked up and flagged as AS44477", async () => {
    await withDom(async ({ els, mk }) => {
      const { renderAsnExplorer } = await import(mod("asn-explorer.js"));
      renderAsnExplorer(mk("c"));
      const asked = [];
      setGlobal("fetch", async (u) => {
        asked.push(u);
        const call = u.split("/data/")[1].split("/")[0];
        const data = call === "as-overview" ? { holder: "STARK-INDUSTRIES - Stark Industries" } : call === "announced-prefixes" ? { prefixes: [] } : call === "asn-neighbours" ? { neighbours: [] } : { located_resources: [] };
        return { ok: true, json: async () => ({ status: "ok", data }) };
      });
      els["asn-input"].value = "AS044477";
      globalThis._asnLookup(); await tick();
      assert.equal(asked[0], "https://stat.ripe.net/data/as-overview/data.json?resource=AS44477");
      assert.ok(/SUSPICIOUS/.test(els["asn-results"].innerHTML));
    });
  });
});
