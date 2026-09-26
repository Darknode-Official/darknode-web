// Probe the advanced discrete-math corpus and print a per-area table (correct / refused / wrong).
//   node tools/quelvra-adv-discrete-probe.mjs [area|substring] [-v]
import { judgeAll } from "../test/quelvra/advanced-discrete.judge.js";

const args = process.argv.slice(2);
const verbose = args.includes("-v");
const filter = args.find((a) => !a.startsWith("-")) || "";
const rows = judgeAll(filter);
const areas = new Map();
for (const r of rows) {
  const a = areas.get(r.area) || { correct: 0, refused: 0, wrong: 0, total: 0 };
  a[r.cat]++; a.total++;
  areas.set(r.area, a);
}
console.log("area       correct refused wrong total");
const tot = { correct: 0, refused: 0, wrong: 0, total: 0 };
for (const [k, a] of areas) {
  console.log(`${k.padEnd(10)} ${String(a.correct).padStart(7)} ${String(a.refused).padStart(7)} ${String(a.wrong).padStart(5)} ${String(a.total).padStart(5)}`);
  for (const f of Object.keys(tot)) tot[f] += a[f];
}
console.log(`${"TOTAL".padEnd(10)} ${String(tot.correct).padStart(7)} ${String(tot.refused).padStart(7)} ${String(tot.wrong).padStart(5)} ${String(tot.total).padStart(5)}`);
for (const r of rows) {
  if (r.cat === "wrong") console.log(`WRONG   [${r.area}] ${r.input}\n        ${r.why}`);
  else if (verbose && r.cat === "refused") console.log(`REFUSED [${r.area}] ${r.input}\n        ${String(r.why).slice(0, 300)}`);
  if (r.ms > 3000) console.log(`SLOW    [${r.area}] ${r.input} ${r.ms} ms`);
}
