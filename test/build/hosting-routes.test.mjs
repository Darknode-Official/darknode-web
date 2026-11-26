// scripts/lib/hosting-routes.mjs + scripts/build.mjs pageHtml: firebase.json answers a real
// 404 for unknown paths, while every path the app routes still gets the app shell and each
// public page gets its own title, description and canonical.
import { test, group, assert } from "../harness.mjs";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { appSecs, appPathRegex, hostingRewrites, syncFirebaseJson } from "../../scripts/lib/hosting-routes.mjs";
import { pageHtml } from "../../scripts/build.mjs";
import { isAppPath } from "../../public/js/deck/routes.js";
import * as SITE_META from "../../public/js/site-meta.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "../..");
const read = (f) => readFileSync(join(ROOT, f), "utf8");

group("hosting routes: firebase.json rewrites", () => {
  test("firebase.json rewrites are generated (run node scripts/sync-hosting-routes.mjs)", () => {
    const text = read("firebase.json");
    assert.equal(syncFirebaseJson(text), text);
    const hosting = JSON.parse(text).hosting;
    assert.ok(hosting.length >= 2);
    for (const h of hosting) {
      assert.deepEqual(h.rewrites, hostingRewrites(), h.target || h.site);
      assert.ok(!h.rewrites.some((r) => r.source === "**"), "a catch-all rewrite turns every typo into a 200");
    }
  });
  test("app paths get the shell; mistyped paths match nothing (404)", () => {
    const re = new RegExp(appPathRegex()), secs = appSecs();
    const app = ["/", "/check/example.com", "/check/example.com/", "/console", "/console/dns", "/emailauth", "/emailauth/",
      "/area/exposure", "/personal/certs", "/all-tools", "/docs", "/settings", "/overview", "/tool-hash", "/monitors", "/plans"];
    for (const p of app) assert.ok(re.test(p), p);
    for (const p of ["/nope-xyz", "/get-started", "/emailauth/extra", "/js/missing.js", "/check/", "/console/nope-xyz", "/wp-admin"]) assert.notOk(re.test(p), p);
    // the rule never admits a path the app itself would not open
    for (const p of app) if (!/^\/(check|tool-|console)/.test(p) && p !== "/") assert.ok(isAppPath(p.replace(/\/$/, ""), secs), p);
  });
  test("each public page is served from its own HTML and is in the sitemap", () => {
    const sitemap = read("public/sitemap.xml");
    const rules = hostingRewrites();
    for (const [path, p] of Object.entries(SITE_META.PAGES)) {
      const r = rules.find((x) => x.destination === "/pages/" + p.slug + ".html");
      assert.ok(r && new RegExp(r.regex).test(path) && new RegExp(r.regex).test(path + "/"), path);
      assert.ok(sitemap.includes("<loc>" + SITE_META.SITE + path + "</loc>"), path + " missing from sitemap.xml");
    }
  });
});

group("hosting routes: page HTML", () => {
  const index = read("public/index.html");
  test("a public page names itself in title, description, canonical, OG and Twitter tags", () => {
    const meta = SITE_META.PAGES["/pricing"];
    const html = pageHtml(index, "/pricing", meta, SITE_META);
    assert.ok(html.includes("<title>" + SITE_META.pageTitle(meta) + "</title>"));
    assert.ok(html.includes('<link rel="canonical" href="https://darknode.ai/pricing">'));
    assert.ok(html.includes('<meta property="og:url" content="https://darknode.ai/pricing">'));
    assert.ok(html.includes('<meta name="twitter:title" content="' + SITE_META.pageTitle(meta) + '">'));
    assert.ok(html.includes('<meta name="description" content="' + meta.description + '">'));
  });
  test("the 404 page is noindex and names no canonical", () => {
    const html = pageHtml(index, "/404", null, SITE_META);
    assert.ok(html.includes("<title>" + SITE_META.NOT_FOUND_TITLE + "</title>"));
    assert.ok(html.includes('<meta name="robots" content="noindex">'));
    assert.notOk(/rel="canonical"/.test(html));
  });
  test("the home page head matches site-meta HOME", () => {
    assert.ok(index.includes("<title>" + SITE_META.HOME.title + "</title>"));
    assert.ok(index.includes('<meta name="description" content="' + SITE_META.HOME.description + '">'));
  });
  test("llms.txt is Markdown with an H1 and a summary", () => {
    const t = read("public/llms.txt");
    assert.ok(/^# \S/.test(t)); assert.ok(/\n> \S/.test(t));
  });
});
