// Invariant tests for the hand-curated reference tables under public/data/ref/
// and the control catalogs under public/data/controls/. These guard the
// envelope, uniqueness and count contracts the regulatory tools rely on.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { group, test, assert } from "../harness.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const DATA = join(here, "..", "..", "public", "data");
const load = (rel) => JSON.parse(readFileSync(join(DATA, rel), "utf8"));

const REF_FILES = ["ref/us-breach-laws.json", "ref/eu-adequacy.json", "ref/us-holidays.json"];
const CONTROL_FILES = ["controls/soc2.json", "controls/iso27001.json", "controls/pci4.json", "controls/cisv8.json", "controls/nistcsf2.json"];
const FREQ = new Set(["continuous", "daily", "weekly", "monthly", "quarterly", "semiannual", "annual", "event"]);
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;
const validDate = (s) => ISO_DATE.test(s) && !Number.isNaN(Date.parse(s + "T00:00:00Z")) && new Date(s + "T00:00:00Z").toISOString().startsWith(s);

group("ref-data: envelopes", () => {
  test("every ref file parses and carries the common envelope", () => {
    for (const f of REF_FILES) {
      const j = load(f);
      assert.ok(/^\d{4}-\d{2}$/.test(j.version), `${f}: version`);
      assert.ok(validDate(j.updated), `${f}: updated`);
      assert.ok(Array.isArray(j.sources) && j.sources.length >= 1 && j.sources.every((s) => /^https:\/\//.test(s)), `${f}: sources`);
      assert.ok(typeof j.notes === "string" && j.notes.length > 40, `${f}: notes`);
      assert.ok(Array.isArray(j.data) && j.data.length > 0, `${f}: data`);
    }
  });

  test("verifyWithCounsel is exactly true on every ref file", () => {
    for (const f of REF_FILES) assert.equal(load(f).verifyWithCounsel, true, f);
  });

  test("every controls file parses and carries framework, version, license, sourceUrl, data", () => {
    for (const f of CONTROL_FILES) {
      const j = load(f);
      assert.ok(typeof j.framework === "string" && j.framework.length, `${f}: framework`);
      assert.ok(typeof j.version === "string" && j.version.length, `${f}: version`);
      assert.ok(typeof j.license === "string" && j.license.length > 40, `${f}: license`);
      assert.ok(/^https:\/\//.test(j.sourceUrl), `${f}: sourceUrl`);
      assert.ok(Array.isArray(j.data) && j.data.length > 0, `${f}: data`);
    }
  });
});

group("ref-data: us-breach-laws", () => {
  const laws = load("ref/us-breach-laws.json");

  test("covers at least 53 jurisdictions with unique 2-letter codes", () => {
    assert.ok(laws.data.length >= 53, `got ${laws.data.length}`);
    const codes = laws.data.map((r) => r.code);
    assert.equal(new Set(codes).size, codes.length, "duplicate codes");
    assert.ok(codes.every((c) => /^[A-Z]{2}$/.test(c)), "codes must be 2 upper-case letters");
    for (const c of ["CA", "NY", "TX", "DC", "PR", "VI", "GU"]) assert.ok(codes.includes(c), `missing ${c}`);
  });

  test("every row has the required fields and sane types", () => {
    for (const r of laws.data) {
      assert.ok(r.jurisdiction && r.statute && r.deadlineText && r.piiDefinitionNotes, `${r.code}: text fields`);
      assert.ok(r.deadlineDays === null || (Number.isInteger(r.deadlineDays) && r.deadlineDays >= 1 && r.deadlineDays <= 365), `${r.code}: deadlineDays`);
      assert.ok(r.agDeadlineDays === null || (Number.isInteger(r.agDeadlineDays) && r.agDeadlineDays >= 1 && r.agDeadlineDays <= 365), `${r.code}: agDeadlineDays`);
      assert.ok(r.agThreshold === null || (Number.isInteger(r.agThreshold) && r.agThreshold >= 0), `${r.code}: agThreshold`);
      assert.ok(r.creditBureauThreshold === null || (Number.isInteger(r.creditBureauThreshold) && r.creditBureauThreshold >= 0), `${r.code}: creditBureauThreshold`);
      assert.ok(r.substituteNoticeAllowed === null || typeof r.substituteNoticeAllowed === "boolean", `${r.code}: substituteNoticeAllowed`);
      assert.equal(typeof r.riskOfHarmTrigger, "boolean", `${r.code}: riskOfHarmTrigger`);
      assert.ok(["curated", "verify"].includes(r.confidence), `${r.code}: confidence`);
      assert.ok(/^https:\/\//.test(r.sourceUrl), `${r.code}: sourceUrl`);
    }
  });

  test("well-known fixed deadlines are encoded", () => {
    const by = Object.fromEntries(laws.data.map((r) => [r.code, r]));
    assert.equal(by.CO.deadlineDays, 30);
    assert.equal(by.FL.deadlineDays, 30);
    assert.equal(by.WA.deadlineDays, 30);
    assert.equal(by.TX.deadlineDays, 60);
    assert.equal(by.TX.agDeadlineDays, 30);
    assert.equal(by.TX.agThreshold, 250);
    assert.equal(by.VT.agDeadlineDays, 14);
    assert.equal(by.CA.deadlineDays, null);
    assert.equal(by.CA.agThreshold, 500);
  });
});

group("ref-data: eu-adequacy", () => {
  const adq = load("ref/eu-adequacy.json");

  test("has at least 15 adequacy entries with unique country codes", () => {
    assert.ok(adq.data.length >= 15, `got ${adq.data.length}`);
    const codes = adq.data.map((r) => r.code);
    assert.equal(new Set(codes).size, codes.length);
    for (const c of ["GB", "US", "JP", "KR", "CH", "CA"]) assert.ok(codes.includes(c), `missing ${c}`);
  });

  test("entries have scope, valid or null decision dates and a source", () => {
    for (const r of adq.data) {
      assert.ok(r.country && r.scope && r.reviewed && r.notes, `${r.code}: text fields`);
      assert.ok(r.decisionDate === null || validDate(r.decisionDate), `${r.code}: decisionDate`);
      assert.ok(/^https:\/\//.test(r.sourceUrl), `${r.code}: sourceUrl`);
      if (r.decisionDate === null) assert.equal(r.confidence, "verify", `${r.code}: undecided entries must be marked verify`);
    }
  });

  test("ukAdequacy and transferMechanisms reference lists are present", () => {
    assert.ok(Array.isArray(adq.ukAdequacy.destinations) && adq.ukAdequacy.destinations.length >= 15);
    assert.ok(Array.isArray(adq.transferMechanisms) && adq.transferMechanisms.length >= 4);
    const ids = adq.transferMechanisms.map((m) => m.id);
    assert.equal(new Set(ids).size, ids.length);
    assert.ok(ids.includes("scc-2021") && ids.includes("bcr") && ids.includes("derogations"));
  });
});

group("ref-data: us-holidays", () => {
  const hol = load("ref/us-holidays.json");

  test("all dates parse, are unique and sorted", () => {
    const dates = hol.data.map((r) => r.date);
    assert.ok(dates.every(validDate), "invalid date present");
    assert.equal(new Set(dates).size, dates.length, "duplicate dates");
    for (let i = 1; i < dates.length; i++) assert.ok(dates[i - 1] < dates[i], `unsorted at ${dates[i]}`);
  });

  test("covers every year 2025-2030 with the 11 federal holidays each", () => {
    for (let y = 2025; y <= 2030; y++) {
      const rows = hol.data.filter((r) => !r.oneOff && (r.observedFor || r.date).startsWith(String(y)));
      assert.equal(rows.length, 11, `${y}: ${rows.length} holidays`);
    }
  });

  test("weekend shifts are recorded via observedFor and land on weekdays", () => {
    for (const r of hol.data) {
      const dow = new Date(r.date + "T00:00:00Z").getUTCDay();
      assert.ok(dow >= 1 && dow <= 5, `${r.date} ${r.name} observed on a weekend`);
      if (r.observedFor) {
        assert.ok(validDate(r.observedFor));
        const diff = Math.abs(Date.parse(r.date) - Date.parse(r.observedFor)) / 86400000;
        assert.equal(diff, 1, `${r.date}: shift must be one day`);
      }
    }
    const july4_2026 = hol.data.find((r) => r.observedFor === "2026-07-04");
    assert.ok(july4_2026 && july4_2026.date === "2026-07-03");
  });

  test("nyseHolidays, when present, parse and exclude Columbus and Veterans Day", () => {
    if (!hol.nyseHolidays) return;
    const rows = hol.nyseHolidays.data;
    assert.ok(rows.length >= 30);
    assert.ok(rows.every((r) => validDate(r.date)));
    assert.equal(new Set(rows.map((r) => r.date)).size, rows.length);
    assert.ok(rows.every((r) => !/Columbus|Veterans/.test(r.name)));
    assert.ok(rows.some((r) => r.name === "Good Friday" && r.date === "2026-04-03"));
  });
});

group("ref-data: control catalogs", () => {
  test("every catalog has unique ids and a valid defaultFrequency on each row", () => {
    for (const f of CONTROL_FILES) {
      const j = load(f);
      const ids = j.data.map((r) => r.id);
      assert.equal(new Set(ids).size, ids.length, `${f}: duplicate ids`);
      for (const r of j.data) {
        assert.ok(typeof r.id === "string" && r.id.length, `${f}: id`);
        assert.ok(typeof r.title === "string" && r.title.length >= 5, `${f} ${r.id}: title`);
        assert.ok(typeof r.domain === "string" && r.domain.length, `${f} ${r.id}: domain`);
        assert.ok(FREQ.has(r.defaultFrequency), `${f} ${r.id}: defaultFrequency ${r.defaultFrequency}`);
        assert.ok(Array.isArray(r.evidenceHints) && r.evidenceHints.length >= 1 && r.evidenceHints.every((h) => typeof h === "string" && h.length <= 120), `${f} ${r.id}: evidenceHints`);
      }
    }
  });

  test("iso27001 has exactly 93 Annex A controls across the four themes", () => {
    const j = load("controls/iso27001.json");
    assert.equal(j.data.length, 93);
    const byDomain = {};
    for (const r of j.data) byDomain[r.domain] = (byDomain[r.domain] || 0) + 1;
    assert.deepEqual(byDomain, { Organizational: 37, People: 8, Physical: 14, Technological: 34 });
    assert.ok(j.data.every((r) => /^[5-8]\.\d{1,2}$/.test(r.id)));
  });

  test("cisv8 has at least 150 safeguards across 18 controls with consistent IG flags", () => {
    const j = load("controls/cisv8.json");
    assert.ok(j.data.length >= 150, `got ${j.data.length}`);
    assert.equal(new Set(j.data.map((r) => r.control)).size, 18);
    for (const r of j.data) {
      assert.ok([1, 2, 3].includes(r.ig), `${r.id}: ig`);
      assert.equal(r.ig1, r.ig === 1, `${r.id}: ig1 flag`);
      assert.equal(r.ig2, r.ig <= 2, `${r.id}: ig2 flag`);
      assert.equal(r.ig3, true, `${r.id}: ig3 flag`);
    }
    assert.equal(j.data.filter((r) => r.ig1).length, 56, "IG1 has 56 safeguards in v8/v8.1");
    assert.ok(/CC BY-NC-ND/.test(j.license), "license note must mention the CIS licence");
  });

  test("nistcsf2 has at least 100 subcategories spanning all six functions", () => {
    const j = load("controls/nistcsf2.json");
    assert.ok(j.data.length >= 100, `got ${j.data.length}`);
    assert.deepEqual([...new Set(j.data.map((r) => r.function))].sort(), ["DE", "GV", "ID", "PR", "RC", "RS"]);
    assert.ok(j.data.every((r) => /^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{2}$/.test(r.id)), "subcategory id format");
    assert.ok(j.data.some((r) => r.id === "GV.OC-01") && j.data.some((r) => r.id === "RC.CO-04"));
    assert.equal(j.categories.length, 22);
  });

  test("soc2 covers CC1-CC9 plus A1, C1, PI1 and P1-P8", () => {
    const j = load("controls/soc2.json");
    const ids = j.data.map((r) => r.id);
    for (const p of ["CC1.1", "CC9.2", "A1.1", "C1.1", "PI1.1", "P1.1", "P8.1"]) assert.ok(ids.includes(p), `missing ${p}`);
    assert.ok(ids.filter((i) => i.startsWith("CC")).length >= 30);
  });

  test("pci4 has the 12 principal requirements and prescribed cadences on key sub-requirements", () => {
    const j = load("controls/pci4.json");
    const by = Object.fromEntries(j.data.map((r) => [r.id, r]));
    for (let n = 1; n <= 12; n++) assert.ok(by[String(n)] && by[String(n)].level === "requirement", `missing principal requirement ${n}`);
    assert.equal(by["11.3.2"].defaultFrequency, "quarterly");
    assert.equal(by["10.4.1"].defaultFrequency, "daily");
    assert.equal(by["1.2.7"].defaultFrequency, "semiannual");
    assert.equal(by["7.2.4"].defaultFrequency, "semiannual");
    assert.equal(by["12.6.3"].defaultFrequency, "annual");
    assert.equal(by["11.4.3"].defaultFrequency, "annual");
    assert.ok(j.data.every((r) => /^\d{1,2}(\.\d{1,2}){0,3}$/.test(r.id)));
  });
});
