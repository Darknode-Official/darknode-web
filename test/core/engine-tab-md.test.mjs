// The DI tab's mini-markdown renderer: bullet lists become real <ul>, text is escaped once,
// and a real em dash survives (HTML entities in skill strings would be double-escaped).
import { readdirSync, readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { test, group, assert } from "../harness.mjs";

const js = fileURLToPath(new URL("../../public/js/", import.meta.url));
const dir = mkdtempSync(join(tmpdir(), "di-tab-"));
mkdirSync(join(dir, "engine"));
const fix = (s) => s.replace(/"\/js\/engine\//g, '"./engine/').replace(/"\/js\//g, '"./');
writeFileSync(join(dir, "engine-tab.js"), fix(readFileSync(join(js, "engine-tab.js"), "utf8")));
for (const f of readdirSync(join(js, "engine"))) if (f.endsWith(".js")) {
  writeFileSync(join(dir, "engine", f), readFileSync(join(js, "engine", f), "utf8").replace(/"\/js\/engine\//g, '"./'));
}
process.on("exit", () => { try { rmSync(dir, { recursive: true, force: true }); } catch (_) {} });

const { mdInline } = await import(pathToFileURL(join(dir, "engine-tab.js")).href);

group("engine tab markdown: lists", () => {
  test("consecutive dash lines become one list", () => {
    const html = mdInline("Offline I can:\n- **calculate**\n- convert units\n- build a regex\nJust ask.");
    assert.equal(html, "Offline I can:<ul><li><b>calculate</b></li><li>convert units</li><li>build a regex</li></ul>Just ask.");
  });
  test("asterisk bullets work and a second list after text is separate", () => {
    const html = mdInline("* a\n* b\nmiddle\n- c");
    assert.equal(html, "<ul><li>a</li><li>b</li></ul>middle<ul><li>c</li></ul>");
  });
  test("plain lines still break with <br>, blank lines preserved", () => {
    assert.equal(mdInline("one\ntwo\n\nthree"), "one<br>two<br><br>three");
  });
});

group("engine tab markdown: escaping", () => {
  test("HTML in text is escaped exactly once", () => {
    assert.equal(mdInline("a <b> & c"), "a &lt;b&gt; &amp; c");
  });
  test("a real em dash is kept, and an entity would be shown literally", () => {
    assert.ok(mdInline("I am **DI** — offline").includes("—"));
    assert.ok(mdInline("x &mdash; y").includes("&amp;mdash;"), "entities are not for md strings");
  });
  test("bold and code inside a list item", () => {
    assert.equal(mdInline("- run `ls` **now**"), "<ul><li>run <code>ls</code> <b>now</b></li></ul>");
  });
});

group("engine tab markdown: links", () => {
  test("a same-origin link renders, a Quelvra link carries the problem for the console router", () => {
    assert.equal(mdInline("open [x^2](/quelvra/?q=derivative%20of%20x%5E2) now"),
      'open <a class="ue-link" href="/quelvra/?q=derivative%20of%20x%5E2" data-sec="math" data-more="derivative of x^2">x^2</a> now');
    assert.equal(mdInline("see [docs](/docs)"), 'see <a class="ue-link" href="/docs">docs</a>');
  });
  test("protocol-relative and external links stay as plain text", () => {
    assert.equal(mdInline("[bad](//evil.example) [ext](https://x.example)"), "[bad](//evil.example) [ext](https://x.example)");
  });
  test("link text is escaped, not interpreted", () => {
    assert.equal(mdInline("[<b>](/docs)"), '<a class="ue-link" href="/docs">&lt;b&gt;</a>');
  });
});
