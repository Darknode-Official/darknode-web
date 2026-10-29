// INI Parser: reads files as Python's configparser does (allow_no_value, keys kept as written,
// no interpolation). Expected values are configparser's output.

import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS } from "../../public/js/tools/dev.js";

const ini = (text) => JSON.parse(TOOLS.find((t) => t.id === "d-ini-to-json").run({ ini: text }, H));

group("d-ini-to-json: configparser rules", () => {
  test("a section header with a trailing comment is still a section", () => {
    assert.deepEqual(ini("[s] ; cm\nx=1\n"), { s: { x: "1" } });
  });
  test("key: value, the first = or : splits, indented lines continue a value", () => {
    assert.deepEqual(ini("[db]\nhost: localhost\nurl = http://a:1/x\nmulti = line1\n  line2\n\tline3\nnext=1"),
      { db: { host: "localhost", url: "http://a:1/x", multi: "line1\nline2\nline3", next: "1" } });
  });
  test("a bare key is kept with no value; inline ; text stays in the value", () => {
    assert.deepEqual(ini("[s]\nk2\nb = x ; c"), { s: { k2: null, b: "x ; c" } });
  });
});
