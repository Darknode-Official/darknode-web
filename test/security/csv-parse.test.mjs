// The CSV quick tools read a file as Python's csv module and Excel do: a quote opens a quoted
// field only as its first character, and a lone \r ends a row.
import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS as CODING } from "../../public/js/tools/coding.js";

const toJson = (csv) => JSON.parse(CODING.find((t) => t.id === "cd-csv-to-json").run({ csv, delim: ",", header: true, numbers: false }, H));

group("quick tools: CSV parsing", () => {
  test("a quote inside a field is text, not the start of a quoted field", () => {
    assert.deepEqual(toJson('item,size\nmonitor,27" screen\nlamp,small'), [{ item: "monitor", size: '27" screen' }, { item: "lamp", size: "small" }]);
    assert.deepEqual(toJson('a,b\nx"y,z'), [{ a: 'x"y', b: "z" }]);
  });
  test("a quoted field still holds commas, newlines and doubled quotes", () => {
    assert.deepEqual(toJson('a,b\n"1,2","say ""hi""\nthere"'), [{ a: "1,2", b: 'say "hi"\nthere' }]);
  });
  test("a lone \\r ends a row, \\r\\n ends it once", () => {
    assert.deepEqual(toJson("a,b\r1,2\r3,4"), [{ a: "1", b: "2" }, { a: "3", b: "4" }]);
    assert.deepEqual(toJson("a,b\r\n1,2\r\n"), [{ a: "1", b: "2" }]);
  });
});

import { parseCSV as dataCSV } from "../../public/js/engine/data.js";
import { parseCSV as reviewCSV } from "../../public/js/identity/access-review-engine.js";
import { parseCSV as roomCSV } from "../../public/js/strongroom/engine.js";

group("engine CSV parsers: a quote opens a quoted field only at its start", () => {
  test("data engine", () => {
    assert.deepEqual(dataCSV('item,size\nmonitor,27" screen\nlamp,"a,b"').rows, [["monitor", '27" screen'], ["lamp", "a,b"]]);
  });
  test("Access Review", () => {
    assert.deepEqual(reviewCSV('user,role\nu1,"admin, ops"\nu2,5" display', { delimiter: "," }).rows, [{ user: "u1", role: "admin, ops" }, { user: "u2", role: '5" display' }]);
  });
  test("STRONGROOM", () => {
    assert.deepEqual(roomCSV('memo,amount\n12" pipe,40\n"a,b",5'), [["memo", "amount"], ['12" pipe', "40"], ["a,b", "5"]]);
  });
});
