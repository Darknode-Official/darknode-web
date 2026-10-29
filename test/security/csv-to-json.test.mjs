// CSV to JSON: number conversion must not change a value, and the header row must not
// lose columns (repeated names, __proto__, cells past the header).

import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS } from "../../public/js/tools/coding.js";

const run = (csv, header = true) => JSON.parse(TOOLS.find((t) => t.id === "cd-csv-to-json").run({ csv, delim: ",", header, numbers: true }, H));

group("cd-csv-to-json: numbers and headers", () => {
  test("leading zeros, unsafe integers and out-of-range values stay text", () => {
    assert.deepEqual(run("zip,phone,id,e,x,z\n02134,0044123,12345678901234567890,1e999,1.50,0"),
      [{ zip: "02134", phone: "0044123", id: "12345678901234567890", e: "1e999", x: 1.5, z: 0 }]);
    assert.deepEqual(run("007,-0.5,9007199254740991", false), [["007", -0.5, 9007199254740991]]);
  });
  test("a repeated header is suffixed, __proto__ is a key, and extra cells are kept", () => {
    assert.deepEqual(run("a,a,a\n1,2,3"), [{ a: 1, "a.1": 2, "a.2": 3 }]);
    assert.equal(JSON.stringify(run("__proto__,b\n1,2")), '[{"__proto__":1,"b":2}]');
    assert.deepEqual(run("a,b\n1,2,3,4"), [{ a: 1, b: 2, _extra: [3, 4] }]);
  });
});
