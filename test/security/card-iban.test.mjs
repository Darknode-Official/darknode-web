// Card brand and IBAN checks. Mastercard's 2-series (2221-2720) pattern had the
// wrong digit counts, so those cards came out as an unknown brand in the quick
// tool and as a generic card in DLP; the IBAN tool checked only mod-97, which
// passes an IBAN of the wrong length for its country.

import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS } from "../../public/js/tools/hashing.js";
import { cardBrand } from "../../public/js/dataprotect/dlp-engine.js";

const run = (id, v) => TOOLS.find((t) => t.id === id).run(v, H);

group("card brand and IBAN", () => {
  test("Mastercard 2-series", () => {
    for (const n of ["2221000000000009", "2720999999999996", "2300000000000003"]) {
      assert.ok(/Brand: Mastercard/.test(run("h-cc-brand", { number: n })), n);
      assert.equal(cardBrand(n), "Mastercard");
    }
    assert.ok(/Brand: Unknown/.test(run("h-cc-brand", { number: "2220000000000000" })));
    assert.equal(cardBrand("5555555555554444"), "Mastercard");
  });
  test("IBAN of the wrong length for its country is invalid even when mod-97 passes", () => {
    const out = run("h-iban-validate", { iban: "GB31NWBK601613319268" });
    assert.ok(/Mod-97 remainder: 1/.test(out) && /GB IBANs are 22/.test(out) && /Valid: NO/.test(out));
    assert.ok(/Valid: YES/.test(run("h-iban-validate", { iban: "GB29 NWBK 6016 1331 9268 19" })));
  });
});

group("regex lab library: Mastercard pattern", () => {
  test("matches 2-series cards, not neighbours", async () => {
    const fs = await import("node:fs");
    const src = fs.readFileSync(new URL("../../public/js/regex-lab.js", import.meta.url), "utf8");
    const re = new RegExp(JSON.parse(src.match(/name: "Credit Card \(Mastercard\)", pattern: ("(?:[^"\\]|\\.)*")/)[1]));
    for (const n of ["5555 5555 5555 4444", "2221 0000 0000 0009", "2720-9999-9999-9996"]) assert.ok(re.test(n), n);
    for (const n of ["2220 0000 0000 0000", "2721 0000 0000 0000"]) assert.ok(!re.test(n), n);
  });
});

group("labs snippet: credit card pattern", () => {
  test("Amex 4-6-5, Mastercard 2-series and Discover 65 match", async () => {
    const fs = await import("node:fs");
    const src = fs.readFileSync(new URL("../../public/js/labs.js", import.meta.url), "utf8");
    const re = new RegExp(JSON.parse(src.match(/\["Credit card", ("(?:[^"\\]|\\.)*")\]/)[1]));
    for (const n of ["3782 822463 10005", "378282246310005", "2221 0000 0000 0009", "6500 0000 0000 0002", "4111 1111 1111 1111", "5555555555554444"]) assert.ok(re.test(n), n);
    assert.ok(!re.test("3782 8224 6310 0051"));
  });
});
