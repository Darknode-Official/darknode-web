// Supply Chain engine tests (public/js/supply-chain-engine.js): manifest/lockfile
// parsing, Levenshtein typosquat detection, CVSS v3 base-score math, OSV advisory
// summarizing, risk scoring and SBOM generation. Pure logic only (no network).

import { test, assert, group } from "../harness.mjs";
import {
  levenshtein, typosquat, cvssV3BaseScore, severityFromCvss, summarizeVuln,
  parsePackageJson, parsePackageLock, parseRequirementsTxt, parseGemfile, parseGoMod,
  parsePomXml, autoDetectAndParse, scoreRisk, generateSBOM,
} from "../../public/js/supply-chain-engine.js";

group("sca: levenshtein", () => {
  test("identical is 0", () => assert.equal(levenshtein("lodash", "lodash"), 0));
  test("transposition costs 2 edits", () => assert.equal(levenshtein("lodash", "lodahs"), 2));
  test("insertion is 1", () => assert.equal(levenshtein("express", "expres"), 1));
  test("empty handled", () => assert.equal(levenshtein("", "abc"), 3));
});

group("sca: typosquat (edit distance, not a fixed list)", () => {
  test("novel squat of lodash flagged", () => {
    const r = typosquat("lodahs", "npm");
    assert.ok(r && r.real === "lodash", "expected lodash match, got " + JSON.stringify(r));
  });
  test("the real package is never a squat of itself", () => assert.equal(typosquat("lodash", "npm"), null));
  test("far-away name is not flagged", () => assert.equal(typosquat("my-internal-tool", "npm"), null));
  test("too-short names skipped", () => assert.equal(typosquat("ab", "npm"), null));
  test("requesrs flagged as requests (pypi)", () => {
    const r = typosquat("requesrs", "pypi");
    assert.ok(r && r.real === "requests");
  });
});

group("sca: CVSS v3 base score", () => {
  test("Log4Shell vector (10.0)", () => {
    assert.equal(cvssV3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0);
  });
  test("a medium vector", () => {
    // AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N -> 4.3
    assert.equal(cvssV3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"), 4.3);
  });
  test("no-impact vector is 0", () => {
    assert.equal(cvssV3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0);
  });
  test("garbage returns null", () => assert.equal(cvssV3BaseScore("not a vector"), null));
  test("severityFromCvss bands", () => {
    assert.equal(severityFromCvss(9.1), "critical");
    assert.equal(severityFromCvss(7.0), "high");
    assert.equal(severityFromCvss(4.0), "medium");
    assert.equal(severityFromCvss(0.1), "low");
  });
});

group("sca: summarizeVuln", () => {
  test("prefers CVSS vector, extracts CVE + fixed version", () => {
    const s = summarizeVuln({
      id: "GHSA-xxxx", aliases: ["CVE-2021-44228", "GHSA-xxxx"],
      summary: "Log4Shell",
      severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" }],
      affected: [{ ranges: [{ events: [{ introduced: "0" }, { fixed: "2.17.1" }] }] }],
    });
    assert.equal(s.cve, "CVE-2021-44228");
    assert.equal(s.severity, "critical");
    assert.equal(s.fixed, "2.17.1");
  });
  test("falls back to database_specific severity when no vector", () => {
    const s = summarizeVuln({ id: "GHSA-yyyy", summary: "x", database_specific: { severity: "MODERATE" } });
    assert.equal(s.severity, "medium");
  });
});

group("sca: parsers", () => {
  test("package.json records range + floor + exact flag", () => {
    const d = parsePackageJson('{"dependencies":{"express":"^4.17.1","lodash":"4.17.21"}}');
    const exp = d.find((x) => x.name === "express");
    const lod = d.find((x) => x.name === "lodash");
    assert.equal(exp.version, "4.17.1");
    assert.equal(exp.exact, false);
    assert.equal(lod.exact, true);
    assert.equal(exp.ecosystem, "npm");
  });
  test("package-lock.json gives exact versions", () => {
    const lock = JSON.stringify({ lockfileVersion: 3, packages: { "": { name: "app" }, "node_modules/lodash": { version: "4.17.21" } } });
    const d = parsePackageLock(lock);
    assert.equal(d.length, 1);
    assert.equal(d[0].name, "lodash");
    assert.equal(d[0].version, "4.17.21");
    assert.equal(d[0].exact, true);
  });
  test("requirements.txt == is exact, >= is not", () => {
    const d = parseRequirementsTxt("requests==2.31.0\nflask>=2.0");
    assert.equal(d.find((x) => x.name === "requests").exact, true);
    assert.equal(d.find((x) => x.name === "flask").exact, false);
  });
  test("go.mod require block", () => {
    const d = parseGoMod("module x\n\nrequire (\n\tgolang.org/x/crypto v0.16.0\n)");
    assert.equal(d[0].name, "golang.org/x/crypto");
    assert.equal(d[0].version, "0.16.0");
  });
  test("pom.xml dependency, skips property-ref versions", () => {
    const d = parsePomXml("<dependency><groupId>com.a</groupId><artifactId>b</artifactId><version>1.2.3</version></dependency><dependency><groupId>c</groupId><artifactId>d</artifactId><version>${managed}</version></dependency>");
    assert.equal(d.length, 1);
    assert.equal(d[0].name, "com.a:b");
  });
  test("Gemfile", () => {
    const d = parseGemfile("gem 'rails', '7.0.4'\ngem 'puma'");
    assert.equal(d.find((x) => x.name === "rails").version, "7.0.4");
  });
  test("autodetect picks package-lock over package.json", () => {
    const d = autoDetectAndParse(JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/x": { version: "1.0.0" } } }));
    assert.ok(d && d[0].exact);
  });
});

group("sca: scoring & sbom", () => {
  test("risk score deducts by weighted severity", () => {
    assert.equal(scoreRisk([{ severity: "critical" }, { severity: "high" }]), 100 - 15 - 8);
    assert.equal(scoreRisk([]), 100);
  });
  test("risk score floors at 0", () => {
    assert.equal(scoreRisk(Array.from({ length: 20 }, () => ({ severity: "critical" }))), 0);
  });
  test("cyclonedx SBOM has purl", () => {
    const x = generateSBOM([{ name: "lodash", version: "4.17.21", ecosystem: "npm" }], "cyclonedx");
    assert.ok(x.includes("pkg:npm/lodash@4.17.21"));
    assert.ok(x.includes("<bom"));
  });
  test("spdx SBOM lists packages", () => {
    const s = generateSBOM([{ name: "lodash", version: "4.17.21", ecosystem: "npm" }], "spdx");
    assert.ok(s.includes("PackageName: lodash"));
    assert.ok(s.includes("SPDXVersion: SPDX-2.3"));
  });
});
