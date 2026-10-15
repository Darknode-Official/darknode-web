// Supply Chain engine tests (public/js/supply-chain-engine.js): manifest/lockfile
// parsing, Levenshtein typosquat detection, CVSS v3 base-score math, OSV advisory
// summarizing, risk scoring and SBOM generation. Pure logic only (no network).

import { test, assert, group } from "../harness.mjs";
import {
  levenshtein, typosquat, cvssV3BaseScore, severityFromCvss, summarizeVuln,
  parsePackageJson, parsePackageLock, parseRequirementsTxt, parseGemfile, parseGoMod,
  parsePomXml, autoDetectAndParse, scoreRisk, generateSBOM,
  parseYarnLock, parseGemfileLock, parsePoetryLock, parseGoSum,
  threatWeight, kevCveSet, parseEpss,
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

// ---------------------------------------------------------------------------
// Transitive-dependency resolution: lockfiles carry the full resolved tree and
// each entry is labelled direct vs transitive where the format records it.
// ---------------------------------------------------------------------------
group("sca: transitive resolution", () => {
  test("package-lock v3 marks direct vs transitive from the root deps", () => {
    const lock = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "app", dependencies: { express: "^4.0.0" } },
        "node_modules/express": { version: "4.18.2" },
        "node_modules/accepts": { version: "1.3.8" },
        "node_modules/express/node_modules/debug": { version: "2.6.9" },
      },
    });
    const d = parsePackageLock(lock);
    const byName = Object.fromEntries(d.map((x) => [x.name, x]));
    assert.equal(byName.express.direct, true);
    assert.equal(byName.accepts.direct, false, "hoisted, not declared → transitive");
    assert.equal(byName.debug.direct, false, "nested → transitive");
    assert.equal(byName.express.version, "4.18.2");
  });
  test("package-lock v1 nested tree: top level direct, nested transitive", () => {
    const lock = JSON.stringify({
      lockfileVersion: 1,
      dependencies: { express: { version: "4.18.2", dependencies: { accepts: { version: "1.3.8" } } } },
    });
    const d = parsePackageLock(lock);
    assert.equal(d.find((x) => x.name === "express").direct, true);
    assert.equal(d.find((x) => x.name === "accepts").direct, false);
  });
  test("manifest package.json is all direct (no transitive tree)", () => {
    const d = parsePackageJson('{"dependencies":{"express":"^4.17.1"}}');
    assert.ok(d.every((x) => x.direct === true));
  });
  test("go.mod marks // indirect as transitive", () => {
    const d = parseGoMod("module x\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n\tgolang.org/x/sys v0.1.0 // indirect\n)");
    assert.equal(d.find((x) => x.name === "github.com/gin-gonic/gin").direct, true);
    assert.equal(d.find((x) => x.name === "golang.org/x/sys").direct, false);
  });
  test("yarn.lock resolves scoped names and merges specifiers", () => {
    const d = parseYarnLock('# yarn lockfile v1\n\nlodash@^4.17.21:\n  version "4.17.21"\n\n"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.20.0"\n');
    assert.equal(d.length, 2);
    assert.ok(d.find((x) => x.name === "@babel/core" && x.version === "7.20.0"));
    assert.equal(d.find((x) => x.name === "lodash").exact, true);
  });
  test("Gemfile.lock splits DEPENDENCIES (direct) from spec tree (transitive)", () => {
    const g = "GEM\n  remote: https://rubygems.org/\n  specs:\n    actionpack (7.0.4)\n      rack (~> 2.0)\n    rack (2.2.4)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rack\n";
    const d = parseGemfileLock(g);
    assert.equal(d.find((x) => x.name === "rack").direct, true);
    assert.equal(d.find((x) => x.name === "actionpack").direct, false);
  });
  test("poetry.lock pins every [[package]] and lower-cases names", () => {
    const p = parsePoetryLock('[[package]]\nname = "Requests"\nversion = "2.31.0"\ncategory = "main"\n\n[[package]]\nname = "certifi"\nversion = "2023.7.22"\n');
    assert.equal(p.length, 2);
    assert.ok(p.find((x) => x.name === "requests" && x.version === "2.31.0"));
  });
  test("go.sum dedupes module@version across hash + /go.mod lines", () => {
    const s = parseGoSum("github.com/davecgh/go-spew v1.1.0 h1:a=\ngithub.com/davecgh/go-spew v1.1.0/go.mod h1:b=\ngolang.org/x/crypto v0.16.0 h1:c=\n");
    assert.equal(s.length, 2);
    assert.equal(s.find((x) => x.name === "golang.org/x/crypto").version, "0.16.0");
  });
  test("autodetect routes yarn.lock, go.sum, poetry.lock and Gemfile.lock", () => {
    assert.ok(autoDetectAndParse('# yarn lockfile v1\n\nlodash@^4.0.0:\n  version "4.17.21"\n'));
    assert.ok(autoDetectAndParse("github.com/x/y v1.0.0 h1:a=\ngithub.com/x/y v1.0.0/go.mod h1:b=\n"));
    assert.ok(autoDetectAndParse('[[package]]\nname = "requests"\nversion = "2.31.0"\n'));
    assert.ok(autoDetectAndParse("GEM\n  specs:\n    rack (2.2.4)\n\nDEPENDENCIES\n  rack\n"));
  });
});

// ---------------------------------------------------------------------------
// KEV + EPSS exploitation weighting: real-world signals raise a finding's cost.
// ---------------------------------------------------------------------------
group("sca: KEV + EPSS weighting", () => {
  test("kevCveSet normalises CVE case from the mirrored feed shape", () => {
    const set = kevCveSet({ data: [{ cve: "CVE-2021-44228" }, { cve: "cve-2019-11358" }] });
    assert.ok(set.has("CVE-2021-44228"));
    assert.ok(set.has("CVE-2019-11358"), "lower-case input is upper-cased");
    assert.notOk(set.has("CVE-2000-0000"));
  });
  test("kevCveSet accepts a raw array and the CISA cveID field", () => {
    const set = kevCveSet([{ cveID: "CVE-2024-3400" }, "CVE-2023-1234"]);
    assert.ok(set.has("CVE-2024-3400") && set.has("CVE-2023-1234"));
  });
  test("parseEpss turns the FIRST response into numeric probabilities", () => {
    const m = parseEpss({ data: [{ cve: "CVE-2021-44228", epss: "0.97553", percentile: "0.99999" }, { cve: "bad", epss: "x" }] });
    assert.equal(m.size, 1);
    const v = m.get("CVE-2021-44228");
    assert.ok(Math.abs(v.epss - 0.97553) < 1e-9);
    assert.ok(Math.abs(v.percentile - 0.99999) < 1e-9);
  });
  test("parseEpss tolerates an empty / shapeless response", () => {
    assert.equal(parseEpss({}).size, 0);
    assert.equal(parseEpss(null).size, 0);
    assert.equal(parseEpss({ data: "nope" }).size, 0);
  });
  test("threatWeight: KEV dominates, EPSS is banded", () => {
    assert.equal(threatWeight({ kev: true }), 10);
    assert.equal(threatWeight({ kev: true, epss: 0.01 }), 10, "KEV wins over EPSS");
    assert.equal(threatWeight({ epss: 0.6 }), 6);
    assert.equal(threatWeight({ epss: 0.2 }), 3);
    assert.equal(threatWeight({ epss: 0.05 }), 1);
    assert.equal(threatWeight({ epss: 0.001 }), 0);
    assert.equal(threatWeight({ severity: "high" }), 0, "no intel → no extra weight");
  });
  test("scoreRisk adds KEV/EPSS weight on top of severity", () => {
    assert.equal(scoreRisk([{ severity: "high", kev: true }]), 100 - 8 - 10);
    assert.equal(scoreRisk([{ severity: "high", epss: 0.6 }]), 100 - 8 - 6);
    assert.equal(scoreRisk([{ severity: "high" }]), 100 - 8, "unchanged without intel");
  });
});

// ---------------------------------------------------------------------------
// Resilience: empty / malformed input and odd OSV response shapes must not throw
// and must degrade gracefully (null for unparseable, best-effort summaries).
// ---------------------------------------------------------------------------
group("sca: resilience", () => {
  test("empty / whitespace input returns null, never throws", () => {
    assert.equal(autoDetectAndParse(""), null);
    assert.equal(autoDetectAndParse("   \n  "), null);
    assert.equal(autoDetectAndParse(null), null);
  });
  test("malformed JSON manifests return null", () => {
    assert.equal(parsePackageJson("{not json"), null);
    assert.equal(parsePackageLock("{bad"), null);
    assert.equal(parsePackageJson("{}"), null, "no deps → null");
    assert.equal(parsePackageLock("{}"), null);
  });
  test("manifest with empty dependency maps returns null", () => {
    assert.equal(parsePackageJson('{"dependencies":{}}'), null);
  });
  test("garbage text falls through to requirements and yields nothing usable", () => {
    const d = autoDetectAndParse("!!! not a manifest at all ??? @#$");
    assert.ok(d === null || Array.isArray(d));
  });
  test("new lockfile parsers return null on empty / malformed input", () => {
    assert.equal(parseYarnLock(""), null);
    assert.equal(parseYarnLock("# yarn lockfile v1\n\n"), null, "header with no blocks");
    assert.equal(parseGemfileLock("GEM\n  specs:\n"), null, "no resolved specs");
    assert.equal(parsePoetryLock("no packages here"), null);
    assert.equal(parseGoSum("not a go.sum line"), null);
  });
  test("summarizeVuln handles a null / empty OSV object", () => {
    assert.equal(summarizeVuln(null), null);
    const s = summarizeVuln({ id: "GHSA-empty" });
    assert.equal(s.id, "GHSA-empty");
    assert.equal(s.cve, "GHSA-empty", "no aliases → falls back to id");
    assert.equal(s.severity, "medium", "no severity data → defaults to medium");
    assert.equal(s.fixed, "");
  });
  test("summarizeVuln ignores an unparseable CVSS vector and uses db severity", () => {
    const s = summarizeVuln({ id: "GHSA-x", severity: [{ type: "CVSS_V3", score: "garbage" }], database_specific: { severity: "HIGH" } });
    assert.equal(s.cvss, null);
    assert.equal(s.severity, "high");
  });
  test("summarizeVuln collects multiple fixed versions across ranges", () => {
    const s = summarizeVuln({ id: "x", affected: [{ ranges: [{ events: [{ fixed: "1.0.1" }] }] }, { ranges: [{ events: [{ fixed: "2.0.2" }] }] }] });
    assert.ok(s.fixed.includes("1.0.1") && s.fixed.includes("2.0.2"));
  });
});
