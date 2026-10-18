// Unit tests for public/js/core/framework-map.js — the control-mapping report.
import { test, group, assert } from "../harness.mjs";
import { frameworkMap } from "../../public/js/core/framework-map.js";

const F = (id, severity, status, controls) => ({ id, type: "FINDING", name: id, severity, status, data: { controls } });

group("framework-map", () => {
  test("groups open findings by framework and control id", () => {
    const r = frameworkMap([
      F("f1", "critical", "open", [{ framework: "PCI DSS 4.0", id: "6.3.3" }, { framework: "CIS v8", id: "7.7" }]),
      F("f2", "high", "open", [{ framework: "PCI DSS 4.0", id: "6.3.3" }]),
      F("f3", "medium", "open", [{ framework: "CIS v8", id: "7.7" }]),
    ]);
    const pci = r.frameworks.find((x) => x.framework === "PCI DSS 4.0");
    assert.equal(pci.open, 2);
    assert.equal(pci.controls[0].id, "6.3.3");
    assert.equal(pci.controls[0].open, 2);
    assert.equal(pci.controls[0].bySeverity.critical, 1);
  });

  test("closed findings are excluded", () => {
    const r = frameworkMap([
      F("f1", "high", "closed", [{ framework: "CIS v8", id: "7.7" }]),
      F("f2", "high", "resolved", [{ framework: "CIS v8", id: "7.7" }]),
    ]);
    assert.equal(r.totalOpen, 0);
    assert.equal(r.frameworks.length, 0);
  });

  test("open findings with no controls count as unmapped, not dropped", () => {
    const r = frameworkMap([F("f1", "high", "open", []), F("f2", "low", "open", undefined)]);
    assert.equal(r.unmappedOpen, 2);
    assert.equal(r.totalOpen, 2);
  });

  test("a finding citing the same control twice is counted once", () => {
    const r = frameworkMap([F("f1", "high", "open", [{ framework: "CIS v8", id: "7.7" }, { framework: "CIS v8", id: "7.7" }])]);
    assert.equal(r.frameworks[0].controls[0].open, 1);
  });

  test("control ids sort naturally (6.3.3 before 6.10)", () => {
    const r = frameworkMap([
      F("a", "low", "open", [{ framework: "PCI DSS 4.0", id: "6.10" }]),
      F("b", "low", "open", [{ framework: "PCI DSS 4.0", id: "6.3.3" }]),
    ]);
    assert.deepEqual(r.frameworks[0].controls.map((c) => c.id), ["6.3.3", "6.10"]);
  });

  test("frameworks sort by open count, then name; and it is deterministic", () => {
    const ents = [
      F("f1", "high", "open", [{ framework: "CIS v8", id: "7.7" }, { framework: "ISO27001", id: "A.5.9" }]),
      F("f2", "high", "open", [{ framework: "CIS v8", id: "4.1" }]),
    ];
    const r = frameworkMap(ents);
    assert.equal(r.frameworks[0].framework, "CIS v8"); // 2 open > ISO's 1
    assert.equal(JSON.stringify(frameworkMap(ents)), JSON.stringify(frameworkMap(ents)));
  });
});
