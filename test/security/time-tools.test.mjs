// Forensic time decoders. UTCTime like 240131235959Z (the tool's own example)
// was read as GeneralizedTime year 2401 month 31 and rejected; impossible dates
// (Feb 31) rolled into March; OLE dates before 1899-12-30 were off by the
// fraction, since OLE counts whole days back but the time of day forward.

import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS } from "../../public/js/tools/forensics.js";

const run = (id, v) => TOOLS.find((t) => t.id === id).run(v, H);
const iso = (out) => (String(out).match(/ISO 8601\):\s+(\S+)/) || [])[1];

group("forensic time decoders", () => {
  test("UTCTime with 12 digits", () => {
    const out = run("fx-generalized-time", { val: "240131235959Z" });
    assert.ok(/^Type: UTCTime/.test(out));
    assert.equal(iso(out), "2024-01-31T23:59:59.000Z");
    assert.equal(iso(run("fx-generalized-time", { val: "491231235959Z" })), "2049-12-31T23:59:59.000Z");
    assert.equal(iso(run("fx-generalized-time", { val: "500101000000Z" })), "1950-01-01T00:00:00.000Z");
  });
  test("GeneralizedTime still parses, with fractions and offsets", () => {
    assert.equal(iso(run("fx-generalized-time", { val: "20240131235959.5Z" })), "2024-01-31T23:59:59.500Z");
    assert.equal(iso(run("fx-generalized-time", { val: "20240131235959+0530" })), "2024-01-31T18:29:59.000Z");
    assert.equal(iso(run("fx-generalized-time", { val: "2024013123.5Z" })), "2024-01-31T23:30:00.000Z");
  });
  test("an impossible date is an error, not the next month", () => {
    assert.ok(run("fx-generalized-time", { val: "20240231000000Z" }).error);
    assert.ok(run("fx-generalized-time", { val: "20240131246000Z" }).error);
  });
  test("OLE dates before 1899-12-30 round-trip", () => {
    assert.equal(iso(run("fx-ole-time", { mode: "Decode", val: "-1.25" })), "1899-12-29T06:00:00.000Z");
    assert.equal(run("fx-ole-time", { mode: "Encode", val: "1899-12-29T06:00:00Z" }), "OLE Automation date: -1.25");
    assert.equal(iso(run("fx-ole-time", { mode: "Decode", val: "45292.5" })), "2024-01-01T12:00:00.000Z");
  });
  test("DOS date word with month 0 is flagged", () => {
    assert.ok(/not a real date/.test(run("fx-dos-time", { date: "0x0000", time: "" })));
    assert.ok(!/not a real/.test(run("fx-dos-time", { date: "0x5821", time: "0x6000" })));
  });
});
