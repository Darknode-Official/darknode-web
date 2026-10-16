// Unit tests for scripts/lib/feeds-lib.mjs (pure helpers behind the EPSS and
// endoflife.date feeds). No network: fixtures are inline.
import { group, test, assert } from "../harness.mjs";
import { parseEpssCsv, selectEpssTop, compactEolProduct, EOL_PRODUCTS } from "../../scripts/lib/feeds-lib.mjs";

const EPSS_FIXTURE = [
  "#model_version:v2025.03.14,score_date:2025-10-16T00:00:00+0000",
  "cve,epss,percentile",
  "CVE-1999-0001,0.04753,0.91763",
  "CVE-2021-44228,0.97565,0.99999",
  "cve-2024-0001,0.123456789,0.5",
  "",
  "not-a-cve,0.5,0.5",
  "CVE-2024-0002,abc,0.1",
  "CVE-2024-0003,0.5,0.5",
].join("\n");

group("feeds-lib: parseEpssCsv", () => {
  test("reads model version and score date from the comment line", () => {
    const r = parseEpssCsv(EPSS_FIXTURE);
    assert.equal(r.modelVersion, "v2025.03.14");
    assert.equal(r.scoreDate, "2025-10-16T00:00:00+0000");
  });

  test("parses valid rows and skips blank, malformed and non-numeric lines", () => {
    const r = parseEpssCsv(EPSS_FIXTURE);
    assert.equal(r.rows.length, 4);
    assert.deepEqual(r.rows[0], { cve: "CVE-1999-0001", epss: 0.04753, percentile: 0.91763 });
    assert.ok(r.rows.every((x) => /^CVE-\d{4}-\d+$/.test(x.cve)));
  });

  test("rounds to 5 decimals and upper-cases CVE ids", () => {
    const r = parseEpssCsv(EPSS_FIXTURE);
    const row = r.rows.find((x) => x.cve === "CVE-2024-0001");
    assert.ok(row, "lower-case cve id should be normalised");
    assert.equal(row.epss, 0.12346);
    assert.equal(row.percentile, 0.5);
  });

  test("tolerates a missing comment line and CRLF endings", () => {
    const r = parseEpssCsv("cve,epss,percentile\r\nCVE-2020-0001,0.1,0.2\r\n");
    assert.equal(r.modelVersion, null);
    assert.equal(r.scoreDate, null);
    assert.equal(r.rows.length, 1);
  });

  test("throws on an empty body or wrong header", () => {
    assert.throws(() => parseEpssCsv(""));
    assert.throws(() => parseEpssCsv("id,score\nCVE-2020-0001,0.1\n"));
    assert.throws(() => parseEpssCsv("cve,epss,percentile\n"));
  });
});

const rows = [
  { cve: "CVE-2020-0005", epss: 0.5, percentile: 0.9 },
  { cve: "CVE-2020-0001", epss: 0.9, percentile: 0.99 },
  { cve: "CVE-2020-0003", epss: 0.7, percentile: 0.95 },
  { cve: "CVE-2020-0002", epss: 0.9, percentile: 0.99 },
  { cve: "CVE-2020-0004", epss: 0.6, percentile: 0.92 },
  { cve: "CVE-2020-0009", epss: 0.001, percentile: 0.1 },
  { cve: "CVE-2020-0008", epss: 0.002, percentile: 0.2 },
];

group("feeds-lib: selectEpssTop", () => {
  test("returns the top-n by epss, ties broken by cve ascending", () => {
    const out = selectEpssTop(rows, new Set(), 3);
    assert.deepEqual(out.map((r) => r.cve), ["CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003"]);
  });

  test("always includes KEV cves even when outside the top-n", () => {
    const out = selectEpssTop(rows, new Set(["CVE-2020-0009"]), 2);
    assert.deepEqual(out.map((r) => r.cve), ["CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0009"]);
  });

  test("KEV cves already in the top-n are not duplicated", () => {
    const out = selectEpssTop(rows, new Set(["CVE-2020-0001", "cve-2020-0008"]), 3);
    const ids = out.map((r) => r.cve);
    assert.equal(ids.length, new Set(ids).size);
    assert.deepEqual(ids, ["CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003", "CVE-2020-0008"]);
  });

  test("dedupes duplicate input rows, keeping the highest score", () => {
    const dup = [...rows, { cve: "CVE-2020-0005", epss: 0.95, percentile: 0.999 }];
    const out = selectEpssTop(dup, new Set(), 10);
    assert.equal(out.filter((r) => r.cve === "CVE-2020-0005").length, 1);
    assert.equal(out[0].cve, "CVE-2020-0005");
    assert.equal(out[0].epss, 0.95);
  });

  test("output is sorted epss desc then cve asc across the whole result", () => {
    const out = selectEpssTop(rows, new Set(["CVE-2020-0009", "CVE-2020-0008"]), 4);
    for (let i = 1; i < out.length; i++) {
      const a = out[i - 1], b = out[i];
      assert.ok(a.epss > b.epss || (a.epss === b.epss && a.cve < b.cve), `order broken at ${i}`);
    }
    assert.equal(out.length, 6);
  });

  test("n larger than the input returns everything, KEV unknown ids are ignored", () => {
    const out = selectEpssTop(rows, new Set(["CVE-1999-9999"]), 100);
    assert.equal(out.length, rows.length);
  });
});

group("feeds-lib: compactEolProduct", () => {
  const api = [
    { cycle: "26.04", codename: "Resolute Raccoon", lts: true, releaseDate: "2026-04-23", eol: "2031-05-29", latest: "26.04.1", latestReleaseDate: "2026-08-27", support: "2031-05-29", extendedSupport: "2036-04-23" },
    { cycle: 25.1, releaseDate: "2025-10-09", eol: false, latest: "25.10", lts: false, support: true, extendedSupport: false },
    { cycle: "24.10", releaseDate: "2024-10-10", eol: "2025-07-10" },
  ];

  test("keeps only the lifecycle fields, preserving string|boolean values", () => {
    const out = compactEolProduct(api, "ubuntu");
    assert.equal(out.product, "ubuntu");
    assert.equal(out.cycles.length, 3);
    assert.deepEqual(Object.keys(out.cycles[0]), ["cycle", "releaseDate", "eol", "latest", "lts", "support", "extendedSupport"]);
    assert.equal(out.cycles[0].codename, undefined);
    assert.equal(out.cycles[0].lts, true);
    assert.equal(out.cycles[1].eol, false);
    assert.equal(out.cycles[1].support, true);
    assert.equal(out.cycles[0].eol, "2031-05-29");
  });

  test("normalises numeric cycles to strings and fills missing fields with null", () => {
    const out = compactEolProduct(api, "ubuntu");
    assert.equal(out.cycles[1].cycle, "25.1");
    assert.equal(out.cycles[2].latest, null);
    assert.equal(out.cycles[2].lts, null);
    assert.equal(out.cycles[2].extendedSupport, null);
  });

  test("throws on a non-array or empty payload", () => {
    assert.throws(() => compactEolProduct({ error: "nope" }, "x"));
    assert.throws(() => compactEolProduct([], "x"));
    assert.throws(() => compactEolProduct([{ codename: "no cycle" }], "x"));
  });
});

group("feeds-lib: EOL_PRODUCTS allowlist", () => {
  test("has no duplicates and only lower-case slug characters", () => {
    assert.equal(new Set(EOL_PRODUCTS).size, EOL_PRODUCTS.length);
    assert.ok(EOL_PRODUCTS.length >= 60, "allowlist should cover at least 60 products");
    assert.ok(EOL_PRODUCTS.every((s) => /^[a-z0-9][a-z0-9-]*$/.test(s)), "slugs must be lower-case kebab");
  });

  test("is frozen and contains the core platforms", () => {
    assert.ok(Object.isFrozen(EOL_PRODUCTS));
    for (const s of ["windows", "ubuntu", "nodejs", "python", "postgresql", "kubernetes", "openssl"]) {
      assert.ok(EOL_PRODUCTS.includes(s), `missing ${s}`);
    }
  });
});
