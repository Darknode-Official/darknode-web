// Risk Register engine tests (public/js/risk/riskreg-engine.js): PRNG and
// samplers, statistics, LEC, portfolio, treatment economics, findings,
// validation, currencies, register round-trip, history, ICS, CSV import.

import { test, assert, group } from "../harness.mjs";
import {
  TOOL_ID, DEFAULTS, COLUMNS, CANON_HEADERS, REGISTER_SCHEMA, SETTINGS_SCHEMA, HISTORY_CAP, MODEL_NOTE,
  mulberry32, fnv1a32, makePert, pertMean, samplePoisson, simulateSpec, simulateRisk, quantileSorted, lossStats,
  lecGrid, exceedance, histogram, treatmentEconomics, normalizeSettings, bandsValid, validateRisk, normalizeRecord,
  hasResidual, parseNum, autoMap, rowsToRecords, parseInput, analyze, diffSummary, withHistory, snapshotOf,
  registerToCsv, registerToJson, lecToCsv, reviewEvents, boardSummary, findingsToCsv, exampleDataset, selfTest,
} from "../../public/js/risk/riskreg-engine.js";
import { openRegister } from "../../public/js/core/register.js";
import { toIcs } from "../../public/js/core/export.js";

const NOW = "2026-10-16T00:00:00Z";
const R = (min, ml, max) => ({ min, ml, max });
const risk = (o = {}) => ({ id: "r1", title: "Test risk", owner: "a@test.darknode.ai", status: "assessed", category: "cyber", currency: "USD", lef: R(0.5, 1, 2), plm: R(1000, 5000, 20000), lastReviewed: "2026-09-01", reviewDate: "2026-12-01", ...o });
const run = (records, o = {}) => analyze({ records }, { iterations: 2000, now: NOW, ...o });
const ids = (r) => r.findings.map((f) => f.id);
const sorted = (a) => Float64Array.from(a).sort();

group("riskreg: PRNG and samplers", () => {
  test("mulberry32 is deterministic per seed and differs across seeds", () => {
    const a = mulberry32(1), b = mulberry32(1), c = mulberry32(2);
    const xa = Array.from({ length: 20 }, a), xb = Array.from({ length: 20 }, b), xc = Array.from({ length: 20 }, c);
    assert.deepEqual(xa, xb);
    assert.notEqual(JSON.stringify(xa), JSON.stringify(xc));
    assert.ok(xa.every((x) => x >= 0 && x < 1));
  });
  test("mulberry32 uniform mean is about 0.5", () => {
    const r = mulberry32(99); let s = 0; for (let i = 0; i < 50000; i++) s += r();
    assert.ok(Math.abs(s / 50000 - 0.5) < 0.01);
  });
  test("fnv1a32 is stable", () => {
    assert.equal(fnv1a32("a"), 0xe40c292c);
    assert.equal(fnv1a32(""), 0x811c9dc5);
  });
  test("PERT mean matches (min + 4 ml + max) / 6 (skewed range)", () => {
    const rng = mulberry32(5); const s = makePert(R(1000, 5000, 100000), rng); let sum = 0; const N = 40000;
    for (let i = 0; i < N; i++) sum += s();
    const want = pertMean(R(1000, 5000, 100000));
    assert.ok(Math.abs(sum / N - want) / want < 0.02, "mean " + sum / N + " vs " + want);
  });
  test("PERT samples stay inside [min, max]", () => {
    const rng = mulberry32(3); const s = makePert(R(2, 3, 9), rng);
    for (let i = 0; i < 5000; i++) { const x = s(); assert.ok(x >= 2 && x <= 9); }
  });
  test("degenerate PERT range returns the constant", () => {
    const s = makePert(R(7, 7, 7), mulberry32(1));
    assert.equal(s(), 7); assert.equal(s(), 7);
  });
  test("Poisson mean and variance ~ lambda (Knuth branch)", () => {
    const rng = mulberry32(11); let s = 0, q = 0; const N = 30000;
    for (let i = 0; i < N; i++) { const k = samplePoisson(2.5, rng, null); s += k; q += k * k; }
    const m = s / N, v = q / N - m * m;
    assert.ok(Math.abs(m - 2.5) < 0.05, "mean " + m);
    assert.ok(Math.abs(v - 2.5) < 0.12, "var " + v);
  });
  test("Poisson large lambda uses normal approximation with the right mean", () => {
    const rng = mulberry32(12); let n = 0; const norm = () => { const u = rng() || 1e-12, w = rng(); return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * w); };
    let s = 0; for (let i = 0; i < 20000; i++) { const k = samplePoisson(50, rng, norm); assert.ok(k >= 0 && Number.isInteger(k)); s += k; n++; }
    assert.ok(Math.abs(s / n - 50) < 0.3);
  });
  test("Poisson(0) is always 0", () => assert.equal(samplePoisson(0, mulberry32(1), null), 0));
  test("simulated event frequency ~ PERT mean of the LEF range", () => {
    const { events } = simulateSpec(normalizeRecord(risk({ lef: R(1, 2, 6) })), 20000, 4);
    let s = 0; for (const e of events) s += e;
    assert.ok(Math.abs(s / 20000 - pertMean(R(1, 2, 6))) < 0.06);
  });
  test("TEF x vulnerability rate ~ product of PERT means", () => {
    const rec = normalizeRecord(risk({ freqMode: "tef", lef: R(null, null, null), tef: R(2, 4, 8), vuln: R(0.1, 0.2, 0.3) }));
    const { events } = simulateSpec(rec, 30000, 9);
    let s = 0; for (const e of events) s += e;
    assert.ok(Math.abs(s / 30000 - pertMean(R(2, 4, 8)) * 0.2) < 0.03, "got " + s / 30000);
  });
  test("simulateRisk is deterministic and seed-dependent", () => {
    const a = simulateRisk(risk(), { iterations: 500, seed: 3 }), b = simulateRisk(risk(), { iterations: 500, seed: 3 }), c = simulateRisk(risk(), { iterations: 500, seed: 4 });
    assert.deepEqual(Array.from(a.inherent.losses), Array.from(b.inherent.losses));
    assert.notEqual(JSON.stringify(Array.from(a.inherent.losses)), JSON.stringify(Array.from(c.inherent.losses)));
  });
  test("iterations are capped at 100,000 and default to 10,000", () => {
    assert.equal(normalizeSettings({ iterations: 5e6 }).iterations, 100000);
    assert.equal(normalizeSettings({}).iterations, 10000);
    assert.equal(DEFAULTS.seed, 1);
  });
});

group("riskreg: statistics and curves", () => {
  test("quantile type 7 interpolation", () => {
    const s = sorted([1, 2, 3, 4]);
    assert.equal(quantileSorted(s, 0.5), 2.5);
    assert.equal(quantileSorted(s, 0), 1);
    assert.equal(quantileSorted(s, 1), 4);
  });
  test("percentiles are monotone", () => {
    const sim = simulateRisk(risk(), { iterations: 5000 });
    const st = lossStats(sim.inherent.losses, sim.inherent.events);
    assert.ok(st.p10 <= st.p50 && st.p50 <= st.p90 && st.p90 <= st.p95 && st.p95 <= st.p99 && st.p99 <= st.max);
  });
  test("ALE mean ~ E[events] x E[loss per event]", () => {
    const rec = risk({ lef: R(1, 1, 1), plm: R(100, 400, 1000), slp: 0 });
    const sim = simulateRisk(rec, { iterations: 40000 });
    const st = lossStats(sim.inherent.losses, sim.inherent.events);
    const want = 1 * pertMean(R(100, 400, 1000));
    assert.ok(Math.abs(st.mean - want) / want < 0.03, st.mean + " vs " + want);
  });
  test("probability of at least one event ~ 1 - e^-lambda", () => {
    const sim = simulateRisk(risk({ lef: R(0.7, 0.7, 0.7) }), { iterations: 30000 });
    const st = lossStats(sim.inherent.losses, sim.inherent.events);
    assert.ok(Math.abs(st.pAny - (1 - Math.exp(-0.7))) < 0.012);
  });
  test("secondary loss adds SLP x secondary mean per event", () => {
    const base = risk({ lef: R(1, 1, 1), plm: R(100, 100, 100), slp: 0.5, slm: R(1000, 1000, 1000) });
    const sim = simulateRisk(base, { iterations: 30000 });
    const st = lossStats(sim.inherent.losses, sim.inherent.events);
    assert.ok(Math.abs(st.meanLossPerEvent - 600) < 12, "per event " + st.meanLossPerEvent);
  });
  test("LEC grid has at least 50 log-spaced points", () => {
    const sim = simulateRisk(risk(), { iterations: 3000 });
    const g = lecGrid([sorted(sim.inherent.losses)]);
    assert.ok(g.length >= 50);
    const r1 = g[1] / g[0], r2 = g[30] / g[29];
    assert.ok(Math.abs(r1 - r2) < 1e-9, "constant ratio");
  });
  test("LEC is monotone non-increasing", () => {
    const r = run([risk()]);
    const lec = r.tables.risks[0].lec;
    assert.ok(lec.length >= 50);
    for (let i = 1; i < lec.length; i++) assert.ok(lec[i].inherent <= lec[i - 1].inherent);
    for (let i = 1; i < r.tables.portfolios[0].lec.length; i++) assert.ok(r.tables.portfolios[0].lec[i].current <= r.tables.portfolios[0].lec[i - 1].current);
  });
  test("exceedance counts strictly greater", () => {
    assert.deepEqual(exceedance(sorted([0, 10, 20, 30]), [10, 25]), [0.5, 0.25]);
  });
  test("histogram counts every non-zero year below P99 plus overflow", () => {
    const sim = simulateRisk(risk(), { iterations: 4000 });
    const s = sorted(sim.inherent.losses);
    const h = histogram(s);
    assert.equal(h.counts.reduce((a, b) => a + b, 0) + h.zero + h.over, 4000);
    assert.equal(h.edges.length, h.counts.length + 1);
  });
  test("all-zero losses give an empty LEC grid", () => assert.equal(lecGrid([sorted([0, 0, 0])]).length, 0));
});

group("riskreg: portfolio and treatment", () => {
  test("portfolio losses equal the per-iteration sum of each risk", () => {
    const recs = [risk({ id: "a" }), risk({ id: "b", lef: R(0.1, 0.3, 1), plm: R(5000, 9000, 50000) })];
    const o = { iterations: 1500, seed: 8 };
    const a = simulateRisk(recs[0], o, 0), b = simulateRisk(recs[1], o, 1);
    const sum = Float64Array.from(a.current.losses, (x, i) => x + b.current.losses[i]);
    const s = sorted(sum);
    const r = analyze({ records: recs }, { ...o, now: NOW });
    const p = r.tables.portfolios[0];
    const mean = sum.reduce((x, y) => x + y, 0) / sum.length;
    assert.equal(p.current.mean, Math.round(mean * 100) / 100);
    assert.equal(p.current.p90, Math.round(quantileSorted(s, 0.9) * 100) / 100);
  });
  test("a risk's numbers do not change when other risks are added (seeded per id)", () => {
    const one = run([risk({ id: "x" })]).tables.risks[0].inherent;
    const two = run([risk({ id: "y", plm: R(1, 2, 3) }), risk({ id: "x" })]).tables.risks[1].inherent;
    assert.deepEqual(one, two);
  });
  test("top contributors sorted by ALE with shares summing to 1", () => {
    const r = run([risk({ id: "a" }), risk({ id: "b", plm: R(10000, 50000, 200000) }), risk({ id: "c", plm: R(10, 20, 30) })]);
    const t = r.tables.portfolios[0].topContributors;
    assert.equal(t[0].id, "b");
    for (let i = 1; i < t.length; i++) assert.ok(t[i].ale <= t[i - 1].ale);
    assert.ok(Math.abs(t.reduce((a, x) => a + x.share, 0) - 1) < 0.001);
  });
  test("treatment ROI and ROSI maths", () => {
    const e = treatmentEconomics(100000, 40000, 20000, 300000, 100000);
    assert.equal(e.aleReduction, 60000);
    assert.equal(e.netBenefit, 40000);
    assert.equal(e.roi, 2);
    assert.equal(e.rosi, 2);
    assert.equal(e.mitigationRatio, 0.6);
    assert.equal(e.p90Reduction, 200000);
  });
  test("ROI is null without a positive cost", () => {
    const e = treatmentEconomics(100, 50, 0);
    assert.equal(e.roi, null); assert.equal(e.aleReduction, 50);
  });
  test("residual ranges inherit blanks and reduce ALE; residual in effect drives current", () => {
    const rec = risk({ treatment: "mitigate", treatmentCost: 100, residual: { lef: R(0.1, 0.2, 0.4) } });
    const r = run([rec]).tables.risks[0];
    assert.ok(r.residual.mean < r.inherent.mean);
    assert.equal(r.current, "inherent");
    assert.ok(r.treatmentEcon.roi != null);
    const r2 = run([{ ...rec, residualInEffect: true }]).tables.risks[0];
    assert.equal(r2.current, "residual");
    assert.equal(r2.currentStats.mean, r2.residual.mean);
    assert.ok(r2.lec.every((p) => p.residual != null));
  });
  test("closed risks are simulated but excluded from the portfolio and findings", () => {
    const r = run([risk({ id: "a" }), risk({ id: "b", status: "closed", owner: "" })], { appetiteAmount: 0 });
    assert.equal(r.tables.portfolios[0].risks, 1);
    assert.ok(!ids(r).some((x) => x.endsWith(":b")));
  });
});

group("riskreg: currencies and validation", () => {
  test("mixed currencies produce separate portfolios", () => {
    const r = run([risk({ id: "a" }), risk({ id: "b", currency: "EUR" }), risk({ id: "c", currency: "EUR" })]);
    assert.deepEqual(r.tables.portfolios.map((p) => p.currency), ["EUR", "USD"]);
    assert.equal(r.tables.portfolios[0].risks, 2);
    assert.equal(r.tables.portfolios[1].risks, 1);
  });
  test("appetite only compared for the appetite currency", () => {
    const r = run([risk({ id: "a", currency: "EUR" })], { appetiteAmount: 0, currency: "USD" });
    assert.equal(r.tables.risks[0].appetite.exceeds, null);
    assert.ok(!ids(r).includes("riskreg:over_appetite:a"));
  });
  test("blank currency falls back to the settings currency", () => {
    const r = run([risk({ currency: "" })], { currency: "gbp" });
    assert.equal(r.tables.risks[0].currency, "GBP");
  });
  test("min <= likely <= max enforced", () => {
    const e = validateRisk(risk({ plm: R(10, 5, 20) }));
    assert.ok(e.some((x) => x.field === "plm" && /min <= most likely <= max/.test(x.message)));
  });
  test("incomplete range is reported", () => {
    assert.ok(validateRisk(risk({ lef: { min: 1, ml: null, max: 3 } })).some((x) => x.field === "lef" && /all three/.test(x.message)));
  });
  test("probabilities must be in [0, 1]", () => {
    assert.ok(validateRisk(risk({ slp: 1.5, slm: R(1, 2, 3) })).some((x) => x.field === "slp"));
    assert.ok(validateRisk(risk({ freqMode: "tef", tef: R(1, 2, 3), vuln: R(0.2, 0.5, 1.4) })).some((x) => x.field === "vuln"));
  });
  test("secondary probability requires a secondary range", () => {
    assert.ok(validateRisk(risk({ slp: 0.3 })).some((x) => x.field === "slm"));
  });
  test("title, category, status, currency and dates validated", () => {
    const f = validateRisk(risk({ title: "", category: "weather", status: "done", currency: "dollars", reviewDate: "next week" })).map((x) => x.field);
    for (const k of ["title", "category", "status", "currency", "reviewDate"]) assert.ok(f.includes(k), k);
  });
  test("valid record has no errors; invalid records are skipped from simulation", () => {
    assert.equal(validateRisk(risk()).length, 0);
    const r = run([risk({ id: "ok" }), risk({ id: "bad", lef: R(3, 2, 1) })]);
    assert.equal(r.summary.simulated, 1);
    assert.equal(r.tables.invalid[0].id, "bad");
    assert.ok(r.skipped.some((s) => s.check === "simulation"));
  });
  test("parseNum handles money shorthands and percents", () => {
    assert.equal(parseNum("$1,200,000"), 1200000);
    assert.equal(parseNum("2.5M"), 2500000);
    assert.equal(parseNum("250k"), 250000);
    assert.equal(parseNum("30%"), 0.3);
    assert.equal(parseNum(""), null);
    assert.equal(parseNum("abc"), null);
  });
});

group("riskreg: findings", () => {
  test("over appetite fires (high) above and stays silent below", () => {
    const hi = run([risk()], { appetiteAmount: 1 });
    const f = hi.findings.find((x) => x.id === "riskreg:over_appetite:r1");
    assert.equal(f.severity, "high");
    assert.ok(f.controls.length >= 1 && f.description.includes(MODEL_NOTE));
    assert.ok(!ids(run([risk()], { appetiteAmount: 1e12 })).includes("riskreg:over_appetite:r1"));
  });
  test("appetite edge: value equal to appetite does not exceed", () => {
    const base = run([risk()], { appetiteAmount: 1e12 }).tables.risks[0].currentStats.p90;
    assert.ok(!ids(run([risk()], { appetiteAmount: base })).includes("riskreg:over_appetite:r1"));
  });
  test("appetite percentile setting is honoured", () => {
    const r = run([risk()], { appetiteAmount: 1e12, appetitePercentile: 99 });
    assert.equal(r.tables.risks[0].appetite.percentile, 99);
    assert.equal(r.tables.risks[0].appetite.value, r.tables.risks[0].currentStats.p99);
  });
  test("no appetite set -> skipped, not guessed", () => {
    const r = run([risk()]);
    assert.ok(r.skipped.some((s) => s.check === "over_appetite"));
    assert.equal(r.tables.risks[0].appetite, null);
  });
  test("review overdue fires (medium) and not on the due date itself", () => {
    assert.equal(run([risk({ reviewDate: "2026-10-15" })]).findings.find((f) => f.id === "riskreg:review_overdue:r1").severity, "medium");
    assert.ok(!ids(run([risk({ reviewDate: "2026-10-16" })])).includes("riskreg:review_overdue:r1"));
  });
  test("overdue depends on opts.now", () => {
    assert.ok(!ids(analyze({ records: [risk({ reviewDate: "2026-10-15" })] }, { iterations: 200, now: "2026-10-01T00:00:00Z" })).includes("riskreg:review_overdue:r1"));
  });
  test("default now is the newest date in the data", () => {
    const r = analyze({ records: [risk({ reviewDate: "2026-08-01", lastReviewed: "2026-09-01" })] }, { iterations: 200 });
    assert.equal(r.meta.now, "2026-09-01T00:00:00.000Z");
    assert.ok(ids(r).includes("riskreg:review_overdue:r1"));
  });
  test("no owner fires (low) and is silent with an owner", () => {
    assert.equal(run([risk({ owner: "" })]).findings.find((f) => f.id === "riskreg:no_owner:r1").severity, "low");
    assert.ok(!ids(run([risk()])).includes("riskreg:no_owner:r1"));
  });
  test("accept above appetite without note fires (medium); with note it does not", () => {
    const a = run([risk({ treatment: "accept" })], { appetiteAmount: 1 });
    assert.equal(a.findings.find((f) => f.id === "riskreg:accept_no_note:r1").severity, "medium");
    const b = run([risk({ treatment: "accept", acceptanceNote: "CFO accepted until Q2" })], { appetiteAmount: 1 });
    assert.ok(!ids(b).includes("riskreg:accept_no_note:r1"));
    const c = run([risk({ treatment: "accept" })], { appetiteAmount: 1e12 });
    assert.ok(!ids(c).includes("riskreg:accept_no_note:r1"));
  });
  test("stale assessment > 365 days fires (low); 365 exactly does not", () => {
    assert.equal(run([risk({ lastReviewed: "2025-10-15" })]).findings.find((f) => f.id === "riskreg:stale_assessment:r1").severity, "low");
    assert.ok(!ids(run([risk({ lastReviewed: "2025-10-16" })])).includes("riskreg:stale_assessment:r1"));
  });
  test("missing last reviewed is reported in skipped", () => {
    assert.ok(run([risk({ lastReviewed: "" })]).skipped.some((s) => s.check === "stale_assessment"));
  });
  test("findings carry controls, evidence and assets from refs and text", () => {
    const r = run([risk({ owner: "", assets: "File server; NAS", assetRefs: [{ id: "g1", type: "VENDOR", name: "Acme Hosting (synthetic)" }] })]);
    const f = r.findings[0];
    assert.ok(f.controls.every((c) => c.framework && c.id));
    assert.equal(f.evidence[0].risk, "Test risk");
    assert.deepEqual(f.assets.map((a) => a.type + ":" + a.name), ["VENDOR:Acme Hosting (synthetic)", "ASSET:File server", "ASSET:NAS"]);
  });
});

group("riskreg: heatmap", () => {
  test("heatmap waits for band edges", () => {
    const r = run([risk()]);
    assert.equal(r.tables.heatmap.ready, false);
    assert.ok(/Settings/.test(r.tables.heatmap.reason));
  });
  test("bandsValid needs 4 ascending edges", () => {
    assert.ok(bandsValid([1, 2, 3, 4]));
    assert.ok(!bandsValid([1, 2, 3]));
    assert.ok(!bandsValid([1, 3, 2, 4]));
  });
  test("heatmap places risks in the cell from simulated frequency and magnitude", () => {
    const r = run([risk({ lef: R(1, 1, 1), plm: R(5000, 5000, 5000) })], { freqBands: "0.1, 0.5, 2, 10", magBands: [100, 1000, 10000, 100000] });
    assert.equal(r.tables.heatmap.ready, true);
    assert.deepEqual(r.tables.heatmap.cells[2][2], ["r1"]);
    assert.deepEqual(r.tables.risks[0].heat, { f: 2, m: 2 });
  });
  test("other-currency risks are excluded from the heatmap", () => {
    const r = run([risk({ currency: "EUR" })], { freqBands: [1, 2, 3, 4], magBands: [1, 2, 3, 4] });
    assert.equal(r.tables.heatmap.excluded[0].id, "r1");
  });
});

group("riskreg: register, history, exports", () => {
  test("register round-trip with Map storage and a fake graph (FINDING, category risk)", () => {
    const m = new Map();
    const storage = { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) };
    const E = {}; let n = 0;
    const graph = {
      create: (type, name, data, opts) => { const e = { id: "g" + (++n), type, name, data, severity: opts.severity, status: opts.status, source: opts.source }; E[e.id] = e; return e; },
      update: (id, u) => Object.assign(E[id], u), remove: (id) => delete E[id],
      list: (type) => Object.values(E).filter((e) => e.type === type), get: (id) => E[id] || null,
    };
    const reg = openRegister(TOOL_ID, "FINDING", { schema: REGISTER_SCHEMA, storage, graph, now: () => "2026-10-16T09:00:00.000Z" });
    const res = run([risk({ id: "rk-1" })], { appetiteAmount: 1 });
    const rec = { ...normalizeRecord(risk({ id: "rk-1" })), snapshot: snapshotOf(res.tables.risks[0], NOW) };
    const saved = reg.upsert(withHistory(null, rec, { at: NOW, by: "a@test.darknode.ai" }));
    const e = E[saved.graphId];
    assert.equal(e.type, "FINDING");
    assert.equal(e.data.category, "risk");
    assert.deepEqual(e.data.tags, ["risk-register"]);
    assert.equal(e.severity, "high");
    assert.equal(e.status, "open");
    assert.equal(e.data._full.plm.max, 20000);
    storage.setItem("dn_active_ws", "team1");
    const team = openRegister(TOOL_ID, "FINDING", { schema: REGISTER_SCHEMA, storage, graph });
    assert.equal(team.list()[0].id, "rk-1", "team sees the risk from the graph");
    storage.removeItem("dn_active_ws");
    reg.upsert({ ...reg.get("rk-1"), status: "closed" });
    assert.equal(E[saved.graphId].status, "closed");
    assert.equal(E[saved.graphId].severity, null);
    const back = parseInput(registerToJson(reg.list(), { appetiteAmount: 5 }));
    assert.equal(back.format, "riskreg-json");
    assert.equal(back.records[0].id, "rk-1");
    assert.equal(back.settings.appetiteAmount, 5);
    assert.ok(reg.remove("rk-1"));
    assert.equal(Object.keys(E).length, 0);
  });
  test("settings schema mirrors as a single named record", () => {
    assert.equal(SETTINGS_SCHEMA.name({}), "Risk register settings");
    assert.equal(SETTINGS_SCHEMA.summary({ appetiteAmount: 9 }).appetiteAmount, 9);
  });
  test("history appends a change summary and caps at 50", () => {
    let rec = normalizeRecord(risk());
    rec = withHistory(null, rec, { at: "t0" });
    assert.equal(rec.history[0].change, "created");
    for (let i = 1; i <= 60; i++) { const next = { ...rec, notes: "n" + i }; rec = withHistory(rec, next, { at: "t" + i, by: "b@test.darknode.ai" }); }
    assert.equal(rec.history.length, HISTORY_CAP);
    assert.equal(rec.history[HISTORY_CAP - 1].at, "t60");
    assert.equal(rec.history[HISTORY_CAP - 1].by, "b@test.darknode.ai");
  });
  test("diffSummary names changed fields with before/after for status", () => {
    const a = normalizeRecord(risk()), b = normalizeRecord(risk({ status: "treating", plm: R(1, 2, 3) }));
    const s = diffSummary(a, b);
    assert.ok(s.includes("status: assessed -> treating"));
    assert.ok(s.includes("plm"));
    assert.equal(diffSummary(a, a), "no changes");
  });
  test("register CSV round-trips through autoMap + rowsToRecords", () => {
    const ex = exampleDataset(1, NOW);
    const csv = registerToCsv(ex.records);
    const p = parseInput([{ name: "register.csv", text: csv }]);
    assert.equal(p.confidence, "high");
    const back = rowsToRecords(p.rows, p.mapping);
    const strip = (r) => { const c = normalizeRecord(r); delete c.history; c.assetRefs = []; return c; };
    assert.equal(back.length, 8);
    assert.deepEqual(back.map(strip).map((r) => JSON.stringify(r)), ex.records.map(strip).map((r) => JSON.stringify(r)));
  });
  test("CSV import with spreadsheet-style headers maps with medium confidence", () => {
    const csv = "Risk,Risk owner,Status,Loss event frequency min,Loss event frequency most likely,Loss event frequency max,Primary loss min,Primary loss most likely,Primary loss max,Next review\n" +
      "Laptop theft,c@test.darknode.ai,Assessed,1,2,4,\"$1,500\",4k,20k,2026-11-01\n";
    const p = parseInput(csv);
    assert.equal(p.confidence, "medium");
    assert.equal(p.mapping.owner, "Risk owner");
    const [r] = rowsToRecords(p.rows, p.mapping, { currency: "EUR" });
    assert.equal(r.title, "Laptop theft");
    assert.equal(r.status, "assessed");
    assert.deepEqual(r.plm, R(1500, 4000, 20000));
    assert.equal(r.currency, "EUR");
    assert.equal(r.reviewDate, "2026-11-01");
    assert.equal(validateRisk(r).length, 0);
  });
  test("CSV without a title column reports low/none confidence", () => {
    const p = parseInput("foo,bar\n1,2\n");
    assert.equal(p.confidence, "none");
    assert.ok(p.skipped.some((s) => s.check === "import"));
  });
  test("percent vulnerability in CSV is converted to a probability", () => {
    const csv = "title,tef_min,tef_likely,tef_max,vuln_min,vuln_likely,vuln_max,plm_min,plm_likely,plm_max\nX,1,2,3,10,20,30,1,2,3\n";
    const p = parseInput(csv);
    const [r] = rowsToRecords(p.rows, p.mapping);
    assert.equal(r.freqMode, "tef");
    assert.deepEqual(r.vuln, R(0.1, 0.2, 0.3));
  });
  test("ICS export of review dates (all-day, sorted, closed skipped)", () => {
    const recs = [risk({ id: "b", reviewDate: "2026-12-01" }), risk({ id: "a", title: "First, review", reviewDate: "2026-11-01" }), risk({ id: "c", status: "closed" })];
    const ev = reviewEvents(recs);
    assert.equal(ev.length, 2);
    assert.equal(ev[0].uid, "riskreg-a-20261101@darknode.ai");
    const ics = toIcs(ev);
    assert.ok(ics.includes("DTSTART;VALUE=DATE:20261101"));
    assert.ok(ics.includes("SUMMARY:Risk review: First\\, review"));
    assert.ok(ics.startsWith("BEGIN:VCALENDAR"));
  });
  test("LEC CSV has portfolio and per-risk rows", () => {
    const r = run([risk()]);
    const lines = lecToCsv(r).trim().split("\r\n");
    assert.equal(lines[0], "scope,risk_id,title,currency,loss,p_exceed_inherent,p_exceed_residual,p_exceed_current");
    assert.ok(lines.some((l) => l.startsWith("portfolio,")));
    assert.ok(lines.filter((l) => l.startsWith("risk,r1,")).length >= 50);
  });
  test("board summary lists portfolio, top risks, over-appetite and overdue", () => {
    const ex = exampleDataset(1, NOW);
    const r = analyze({ records: ex.records }, { ...ex.settings, iterations: 2000, now: ex.now });
    const t = boardSummary(r, { org: ex.org });
    assert.ok(t.includes(MODEL_NOTE));
    for (const h of ["PORTFOLIO ANNUALIZED LOSS EXPOSURE", "TOP 10 RISKS", "OVER APPETITE", "OVERDUE REVIEWS"]) assert.ok(t.includes(h), h);
    assert.ok(t.includes("DDoS on checkout"));
  });
  test("findingsToCsv header row and row count", () => {
    const r = run([risk({ owner: "" })]);
    const csv = findingsToCsv(r.findings).split("\n");
    assert.equal(csv[0], "severity,confidence,category,title,description,recommendation,controls,evidenceCount");
    assert.equal(csv.length, r.findings.length + 1);
  });
  test("findingsToCsv keeps formula-looking text inert (a title from an imported register is untrusted)", () => {
    const line = findingsToCsv([{ severity: "high", confidence: "likely", category: "x", title: "=HYPERLINK(\"http://x\")", description: "-2", recommendation: "@SUM(A1)", controls: [], evidenceCount: 0 }]).split("\n")[1];
    assert.ok(line.includes('"\'=HYPERLINK') && line.includes('"\'@SUM') && line.includes('"-2"'), line);
  });
  test("register CSV guards a formula that starts with a negative number (-2+3+cmd)", () => {
    const evil = "-2+3+cmd|' /C calc'!A0";
    const row = registerToCsv([{ id: "r1", title: evil, slp: -0.5 }]).split("\r\n")[1];
    assert.ok(row.includes(",'-2+3+cmd"), row);
    assert.ok(!row.includes("'-0.5"), row);
  });
});

group("riskreg: example, determinism, self-test", () => {
  test("example: 8 synthetic risks, owners at test.darknode.ai, two with residual", () => {
    const ex = exampleDataset(1, NOW);
    assert.equal(ex.records.length, 8);
    assert.ok(ex.org.includes("(synthetic)"));
    assert.ok(ex.records.every((r) => r.owner.endsWith("@test.darknode.ai")));
    assert.equal(ex.records.filter(hasResidual).length, 2);
    assert.ok(ex.records.every((r) => validateRisk(r).length === 0));
  });
  test("example run produces each finding type expected", () => {
    const ex = exampleDataset(1, NOW);
    const r = analyze({ records: ex.records }, { ...ex.settings, now: ex.now });
    const k = ids(r);
    assert.ok(k.includes("riskreg:review_overdue:testorg-06"));
    assert.ok(k.includes("riskreg:stale_assessment:testorg-08"));
    assert.ok(r.findings.some((f) => f.severity === "high"));
    assert.equal(r.tables.heatmap.ready, true);
  });
  test("analyze is byte-identical across runs", () => {
    const ex = exampleDataset(1, NOW);
    const o = { ...ex.settings, iterations: 3000, now: ex.now };
    assert.equal(JSON.stringify(analyze({ records: ex.records }, o)), JSON.stringify(analyze({ records: ex.records }, o)));
  });
  test("progress is reported per risk", () => {
    const calls = [];
    run([risk({ id: "a" }), risk({ id: "b" })], {}, undefined);
    analyze({ records: [risk({ id: "a" }), risk({ id: "b" })] }, { iterations: 100, now: NOW }, { progress: (i, n) => calls.push([i, n]) });
    assert.deepEqual(calls, [[0, 2], [1, 2], [2, 2]]);
  });
  test("20 risks x 10,000 iterations runs well under 2 s", () => {
    const ex = exampleDataset(1, NOW);
    const recs = Array.from({ length: 20 }, (_, i) => ({ ...ex.records[i % 8], id: "p" + i }));
    const t = Date.now();
    analyze({ records: recs }, { iterations: 10000, now: NOW });
    assert.ok(Date.now() - t < 2000, "took " + (Date.now() - t) + " ms");
  });
  test("empty input yields zero findings and does not throw", () => {
    const p = parseInput("");
    assert.equal(p.records.length, 0);
    const r = analyze(p.records, { now: NOW });
    assert.equal(r.findings.length, 0);
    assert.equal(r.meta.tool, "riskreg");
    assert.equal(r.tables.portfolios.length, 0);
  });
  test("COLUMNS cover every canonical header", () => {
    assert.ok(CANON_HEADERS.includes("plm_likely") && CANON_HEADERS.includes("res_slm_max"));
    assert.ok(COLUMNS.title.includes("risk"));
  });
  test("selfTest passes", () => {
    const r = selfTest();
    assert.ok(r.pass, r.tests.filter((t) => !t.pass).map((t) => t.name).join(", "));
  });
});
