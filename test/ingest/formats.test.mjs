// Unit tests for public/js/ingest/formats.js — ingest format parsers.
import { test, group, assert } from "../harness.mjs";
import { detectFormat, parseFindingContract, parseSarif, parseCycloneDX, ingestToFindings, SUPPORTED_FORMATS } from "../../public/js/ingest/formats.js";

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

group("formats/native scanner exports", () => {
  const trivy = JSON.stringify({ SchemaVersion: 2, ArtifactName: "app:latest", Results: [{ Target: "app", Vulnerabilities: [{ VulnerabilityID: "CVE-2021-44228", PkgName: "log4j", InstalledVersion: "2.14", FixedVersion: "2.17", Severity: "CRITICAL", Title: "Log4Shell" }] }] });
  test("a Trivy JSON export becomes one finding per open vulnerability", () => {
    const r = ingestToFindings(trivy);
    assert.equal(r.format, "trivy");
    assert.equal(r.findings.length, 1);
    const f = r.findings[0];
    assert.equal(f.severity, "critical");
    assert.equal(f.category, "vulnerability");
    assert.ok(/CVE-2021-44228/.test(f.title));
    const types = f.assets.map((a) => a.type).sort();
    assert.deepEqual(types, ["ASSET", "VULNERABILITY"]);
  });
  test("a Snyk JSON export (no bomFormat) routes to the engine, not CycloneDX", () => {
    const snyk = JSON.stringify({ vulnerabilities: [{ id: "SNYK-1", title: "Prototype Pollution", severity: "high", identifiers: { CVE: ["CVE-2020-0001"] }, packageName: "lodash", version: "4.17.0" }], projectName: "svc" });
    const r = ingestToFindings(snyk);
    assert.equal(r.format, "snyk");
    assert.ok(r.findings.length >= 1);
  });
  test("a Nessus v2 XML export is parsed to findings", () => {
    const nessus = `<?xml version="1.0"?><NessusClientData_v2><Report name="r"><ReportHost name="host1.test.darknode.ai"><ReportItem port="443" severity="4" pluginID="1" pluginName="Critical flaw"><risk_factor>Critical</risk_factor><cve>CVE-2023-0001</cve><description>d</description><solution>Patch</solution></ReportItem></ReportHost></Report></NessusClientData_v2>`;
    const r = ingestToFindings(nessus);
    assert.equal(r.format, "nessus-xml");
    assert.ok(r.findings.length >= 1);
    assert.ok(r.findings.every((f) => f.assets.some((a) => a.type === "ASSET")));
  });
  test("ingest is deterministic for the same export", () => {
    assert.equal(JSON.stringify(ingestToFindings(trivy)), JSON.stringify(ingestToFindings(trivy)));
  });
  test("SUPPORTED_FORMATS advertises the native scanner formats", () => {
    for (const f of ["findings", "sarif", "cyclonedx", "nessus-xml", "trivy", "snyk"]) assert.ok(SUPPORTED_FORMATS.includes(f), "missing " + f);
  });
  test("a non-JSON, non-scanner blob is unrecognised, not a throw", () => {
    const r = ingestToFindings("just some prose not a scan");
    assert.equal(r.format, "unknown");
    assert.ok(r.errors.length >= 1);
  });
});
