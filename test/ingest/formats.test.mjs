// Unit tests for public/js/ingest/formats.js — ingest format parsers.
import { test, group, assert } from "../harness.mjs";
import { detectFormat, parseFindingContract, parseSarif, parseCycloneDX, ingestToFindings } from "../../public/js/ingest/formats.js";

group("formats/detect", () => {
  test("detects SARIF, CycloneDX and the Finding contract", () => {
    assert.equal(detectFormat({ version: "2.1.0", runs: [] }), "sarif");
    assert.equal(detectFormat({ bomFormat: "CycloneDX", vulnerabilities: [] }), "cyclonedx");
    assert.equal(detectFormat({ findings: [{ title: "x" }] }), "findings");
    assert.equal(detectFormat([{ title: "x", severity: "high" }]), "findings");
    assert.equal(detectFormat({ title: "x", severity: "high" }), "findings");
    assert.equal(detectFormat({ foo: 1 }), "unknown");
  });
});

group("formats/finding contract", () => {
  test("validates title, normalises severity, keeps known fields", () => {
    const { findings, errors } = parseFindingContract({ findings: [
      { title: "SQL injection", severity: "ERROR", category: "injection", assets: [{ type: "asset", name: "web01" }], controls: [{ framework: "CIS", id: "16.1" }], tags: ["x"] },
      { severity: "high" },               // no title -> error
      { title: "weak", severity: "nonsense" },  // unknown severity -> info
    ] });
    assert.equal(findings.length, 2);
    assert.equal(findings[0].severity, "high");   // ERROR -> high
    assert.equal(findings[0].assets[0].type, "ASSET");
    assert.equal(findings[1].severity, "info");
    assert.equal(errors.length, 1);
  });

  test("accepts a bare array and a single object", () => {
    assert.equal(parseFindingContract([{ title: "a", severity: "low" }]).findings.length, 1);
    assert.equal(parseFindingContract({ title: "a", severity: "low" }).findings.length, 1);
  });
});

group("formats/sarif", () => {
  const sarif = {
    version: "2.1.0", runs: [{
      tool: { driver: { name: "CodeQL", rules: [{ id: "js/sqli", name: "SQL injection", fullDescription: { text: "Tainted input reaches a query." }, help: { text: "Use parameterised queries." }, properties: { "security-severity": "9.1" } }] } },
      results: [
        { ruleId: "js/sqli", message: { text: "User input flows to SQL" }, locations: [{ physicalLocation: { artifactLocation: { uri: "src/db.js" }, region: { startLine: 42 } } }] },
        { ruleId: "js/weak", level: "warning", message: { text: "Weak hash" } },
      ],
    }],
  };
  test("maps results to findings with severity, category, assets", () => {
    const { findings } = parseSarif(sarif);
    assert.equal(findings.length, 2);
    const sqli = findings.find((f) => f.category === "js/sqli");
    assert.equal(sqli.severity, "critical");          // security-severity 9.1
    assert.equal(sqli.title, "User input flows to SQL");
    assert.equal(sqli.assets[0].name, "src/db.js");
    assert.equal(sqli.assets[0].data.line, 42);
    assert.ok(sqli.recommendation.includes("parameterised"));
    const weak = findings.find((f) => f.category === "js/weak");
    assert.equal(weak.severity, "medium");            // level warning
  });
});

group("formats/cyclonedx", () => {
  test("maps vulnerabilities to findings with affected components", () => {
    const bom = { bomFormat: "CycloneDX", components: [{ "bom-ref": "pkg:npm/lodash@4.17.0", name: "lodash", version: "4.17.0" }], vulnerabilities: [{ id: "CVE-2021-23337", description: "Command injection", ratings: [{ score: 7.2, severity: "high" }], affects: [{ ref: "pkg:npm/lodash@4.17.0" }] }] };
    const { findings } = parseCycloneDX(bom);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity, "high");
    assert.equal(findings[0].assets[0].name, "lodash@4.17.0");
    assert.equal(findings[0].assets[0].type, "SOFTWARE");
  });
});

group("formats/ingestToFindings", () => {
  test("parses a JSON string and reports the format", () => {
    const r = ingestToFindings(JSON.stringify([{ title: "a", severity: "high" }]));
    assert.equal(r.format, "findings");
    assert.equal(r.findings.length, 1);
  });
  test("invalid JSON and unknown formats are errors, not throws", () => {
    assert.ok(ingestToFindings("{not json").errors[0].includes("invalid JSON"));
    assert.ok(ingestToFindings({ foo: 1 }).errors.length === 1);
  });
});
