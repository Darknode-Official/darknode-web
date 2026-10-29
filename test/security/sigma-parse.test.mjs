// Sigma rule parsers in the SIEM and threat engines: a selection or section
// named __proto__ in a pasted rule must stay a key. The SIEM parser used to
// write the selection's fields straight into Object.prototype.

import { test, assert, group } from "../harness.mjs";
import { parseSigmaRule as siemParse, sigmaToSplunk } from "../../public/js/siem-engine.js";
import { parseSigmaRule as threatParse } from "../../public/js/threat-engine.js";

group("Sigma rule parsing", () => {
  test("SIEM parser: a __proto__ selection does not reach Object.prototype", () => {
    const r = siemParse("title: t\ndetection:\n  __proto__:\n        polluted: yes\n  condition: __proto__\n");
    const leaked = ({}).polluted; delete Object.prototype.polluted;
    assert.equal(leaked, undefined);
    assert.deepEqual(Object.keys(r.detection), ["__proto__", "condition"]);
  });
  test("threat parser keeps a __proto__ selection as a key", () => {
    const r = threatParse("title: t\ndetection:\n    __proto__:\n        polluted: yes\n    condition: x\n");
    assert.deepEqual(Object.keys(r.detection), ["__proto__", "condition"]);
  });
  test("ordinary rules still convert", () => {
    assert.equal(sigmaToSplunk(siemParse("title: t\nlogsource:\n  product: windows\ndetection:\n  sel:\n        Image: x.exe\n  condition: sel\n")), 'index="windows" Image="x.exe"');
  });
});
