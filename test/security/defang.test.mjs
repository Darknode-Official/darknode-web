// threat-engine defang/refang: defanging twice is a no-op, and common defang styles refang.
import { test, group, assert } from "../harness.mjs";
import { defang, refang } from "../../public/js/threat-engine.js";

group("threat-engine: defang / refang", () => {
  test("defanging already-defanged text does not double-bracket", () => {
    assert.equal(defang(defang("https://evil.com/a")), "hxxps://evil[.]com/a");
    assert.equal(refang(defang(defang("bad@evil.com"))), "bad@evil.com");
  });
  test("refang reads HXXPS, [dot] and (.)", () => {
    assert.equal(refang("HXXPS://evil[dot]com"), "https://evil.com");
    assert.equal(refang("evil(.)com"), "evil.com");
  });
});
