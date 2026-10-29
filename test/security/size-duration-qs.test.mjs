// Byte size, duration and query string tools. "-5m" parsed as +300 seconds,
// ISO P1M (one month) parsed as one minute, and junk between units was skipped;
// "1,024 KB", "512k" and "10 Gb" (bits) were rejected or misread; 1048575 bytes
// showed as "1024.00 KiB"; and a malformed %-escape made the query parser throw.

import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS as DEVX } from "../../public/js/tools/devx.js";
import { TOOLS as CODING } from "../../public/js/tools/coding.js";

const run = (list, id, v) => list.find((t) => t.id === id).run(v, H);
const dur = (input) => run(CODING, "cd-duration", { input, mode: "Parse to seconds" });
const secs = (input) => { const r = dur(input); return typeof r === "string" ? +/Total seconds : (-?[\d.]+)/.exec(r)[1] : r; };

group("cd-duration parse", () => {
  test("keeps the sign", () => assert.equal(secs("-5m"), -300));
  test("ISO forms", () => {
    assert.equal(secs("PT1H30M"), 5400);
    assert.equal(secs("P1DT2H"), 93600);
    assert.equal(secs("PT1M"), 60);
    assert.equal(secs("P2W"), 1209600);
  });
  test("ISO months and years are refused, not read as minutes", () => {
    assert.ok(dur("P1M").error);
    assert.ok(dur("P1Y").error);
  });
  test("words and separators", () => {
    assert.equal(secs("2 hours and 5 minutes"), 7500);
    assert.equal(secs("1h, 2m"), 3720);
    assert.equal(secs("1h 30m 15s"), 5415);
    assert.equal(secs("500ms"), 0.5);
  });
  test("junk is an error", () => {
    assert.ok(dur("1h foo 30m").error);
    assert.ok(dur("5 months").error);
  });
});

group("dv-bytes-parse / humanize", () => {
  const p = (text) => run(DEVX, "dv-bytes-parse", { text });
  test("thousands separators", () => assert.ok(String(p("1,024 KB")).startsWith("1024000 bytes")));
  test("single-letter suffix, with the 1024 reading noted", () => {
    const r = p("512k");
    assert.ok(r.startsWith("512000 bytes") && r.includes("524288"));
  });
  test("Gb is gigabits", () => assert.ok(p("10 Gb").startsWith("1250000000 bytes")));
  test("Kubernetes Gi", () => assert.equal(p("2Gi"), "2147483648 bytes"));
  test("humanize rolls over after rounding", () => {
    assert.equal(run(DEVX, "dv-bytes-humanize", { bytes: "1048575", base: "1024" }), "1.00 MiB");
    assert.equal(run(DEVX, "dv-bytes-humanize", { bytes: "999999", base: "1000" }), "1.00 MB");
  });
});

group("dv-querystring parse", () => {
  const q = (text) => JSON.parse(run(DEVX, "dv-querystring", { text, mode: "parse" }));
  test("malformed escape is kept, not thrown", () => assert.equal(q("?x=%zz&y=1").x, "%zz"));
  test("fragment is dropped", () => assert.equal(q("?x=1&y=2#frag").y, "2"));
  test("full URL input", () => assert.deepEqual(q("https://h.test/p?a=1&b=2"), { a: "1", b: "2" }));
  test("bare ? inside a value stays", () => assert.equal(q("a=b?c").a, "b?c"));
});
