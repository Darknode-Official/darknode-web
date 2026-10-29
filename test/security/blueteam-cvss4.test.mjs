// CVSS v4.0 Vector Parser quick tool (public/js/tools/blueteam.js, bt-cvss4-parse): input validation.

import { test, assert, group } from "../harness.mjs";
import * as BT from "../../public/js/tools/blueteam.js";

const tools = BT.default || Object.values(BT).find(Array.isArray);
const parse = (vector) => tools.find((t) => t.id === "bt-cvss4-parse").run({ vector });
const BASE = "AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";

group("blueteam: CVSS v4.0 vector parser", () => {
  test("a valid base vector parses", () => {
    assert.ok(/AV \(Attack Vector\): Network/.test(parse("CVSS:4.0/AV:N/" + BASE)));
  });
  test("prototype names are not metrics or values", () => {
    assert.ok(/invalid value toString for AV/.test(parse("CVSS:4.0/AV:toString/" + BASE).error));
    assert.ok(/unknown metric constructor/.test(parse("CVSS:4.0/constructor:x/AV:N/" + BASE).error));
  });
  test("a repeated metric is an error", () => {
    assert.ok(/AV appears more than once/.test(parse("CVSS:4.0/AV:N/AV:L/" + BASE).error));
  });
});
