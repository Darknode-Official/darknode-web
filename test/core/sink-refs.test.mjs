// core/sink-map.js helpers used by the tool sink mappers: controlsFromRefs (free-text
// control references -> Finding controls) and sampleShare (is a run still the example?).

import { test, assert, group } from "../harness.mjs";
import { controlsFromRefs, sampleShare, SAMPLE_SHARE } from "../../public/js/core/sink-map.js";

group("sink-map: controlsFromRefs", () => {
  const one = (s) => controlsFromRefs([s]);
  test("framework prefixes normalise to the documented framework names", () => {
    assert.deepEqual(one("ISO 27001 A.5.18"), [{ framework: "ISO27001", id: "A.5.18" }]);
    assert.deepEqual(one("NIST 800-53 AC-2(3)"), [{ framework: "NIST-800-53", id: "AC-2(3)" }], "enhancement parentheses are part of the id");
    assert.deepEqual(one("CIS v8 6.2"), [{ framework: "CIS", id: "6.2" }]);
    assert.deepEqual(one("ATT&CK T1078"), [{ framework: "MITRE", id: "T1078" }]);
    assert.deepEqual(one("SOX ITGC: user access review"), [{ framework: "SOX", id: "ITGC user access review" }]);
  });
  test("lists split, notes in parentheses drop, technique lists expand", () => {
    assert.deepEqual(one("CIS Controls v8 4.4 / 4.5 (manage host and network firewalls)"), [{ framework: "CIS", id: "4.4" }, { framework: "CIS", id: "4.5" }]);
    assert.deepEqual(one("PCI DSS 4.0 req. 1.2.6 (insecure services), 1.3.1, 1.4.1").map((c) => c.id), ["1.2.6", "1.3.1", "1.4.1"]);
    assert.deepEqual(one("NIST SP 800-41r1 sec. 2.1.1 / 4.1 (default deny)"), [{ framework: "NIST-800-41", id: "2.1.1" }, { framework: "NIST-800-41", id: "4.1" }]);
    assert.deepEqual(one("T1110.004 / T1078.004"), [{ framework: "MITRE", id: "T1110.004" }, { framework: "MITRE", id: "T1078.004" }]);
    assert.deepEqual(one("T1562 (defence evasion is harder to detect)"), [{ framework: "MITRE", id: "T1562" }]);
  });
  test("unknown references are kept whole, blanks dropped, duplicates collapsed", () => {
    assert.deepEqual(controlsFromRefs(["Internal policy 7", "", null, "T1078", "ATT&CK T1078"]), [{ framework: "", id: "Internal policy 7" }, { framework: "MITRE", id: "T1078" }]);
    assert.deepEqual(controlsFromRefs("CIS v8 5.4"), [{ framework: "CIS", id: "5.4" }], "a single string is accepted");
  });
});

group("sink-map: sampleShare", () => {
  const ex = "h1,h2\na,1\nb,2\nc,3\nd,4\ne,5";
  test("the example itself, edited or appended to, stays sample", () => {
    assert.equal(sampleShare(ex, ex), 1);
    assert.ok(sampleShare(ex.replace("a,1", "a,9") + "\nreal,7", ex) >= SAMPLE_SHARE);
  });
  test("replacing the rows (same header) drops below the threshold; no example means 0", () => {
    assert.ok(sampleShare("h1,h2\nreal,1\nreal,2", ex) < SAMPLE_SHARE, "a shared header alone is not sample");
    assert.equal(sampleShare("anything", null), 0);
    assert.equal(sampleShare("", ex), 0);
  });
  test("skip=0 counts the first line (header-less examples)", () => {
    assert.equal(sampleShare("Name A", "Name A\nName B", 0), 0.5);
    assert.equal(sampleShare("Name A", "Name A\nName B"), 0);
  });
});
