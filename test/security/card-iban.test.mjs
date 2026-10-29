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
