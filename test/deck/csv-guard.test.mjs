// The Deck's hand-built CSV exports (certificates, domain portfolio, CVE list) carry
// third-party text (CT issuer names, CVE titles): a cell a spreadsheet would run as a
// formula must be kept as text, while a plain negative number (days past expiry) stays numeric.
import { test, group, assert } from "../harness.mjs";
import { readFileSync } from "node:fs";

const files = ["public/js/deck/native/cert-watch.js", "public/js/deck/native/domain-check.js", "public/js/deck-ui.js"];
group("deck CSV exports: formula guard", () => {
  for (const f of files) test(f + " guards formula cells", () => {
    const src = readFileSync(new URL("../../" + f, import.meta.url), "utf8");
    const m = /const q = \((\w)\) => \{ let s = String\(\1 == null \? "" : \1\);(.*?)return '"' \+ s\.replace/.exec(src);
    assert.ok(m, "q helper found");
    const q = new Function(m[1], "let s = String(" + m[1] + " == null ? \"\" : " + m[1] + ");" + m[2] + "return s;");
    assert.equal(q("=HYPERLINK(\"x\")"), "'=HYPERLINK(\"x\")");
    assert.equal(q("-1+2"), "'-1+2");
    assert.equal(q("@SUM(A1)"), "'@SUM(A1)");
    assert.equal(q(-3), "-3");
    assert.equal(q("Let's Encrypt"), "Let's Encrypt");
  });
});
