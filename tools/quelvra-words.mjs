// Word-problem corpus report: node tools/quelvra-words.mjs [category] [-v] [-r] [--heldout|--fresh] [--json]
// Verdicts per category: ok / incomplete / refused / WRONG (see test/quelvra/wordproblems.judge.js).
import { solve } from "../public/quelvra/engine/quelvra.js";
import { textOf } from "./quelvra-coverage-judge.mjs";
import { judge } from "../test/quelvra/wordproblems.judge.js";
import { CASES as MAIN } from "../test/quelvra/wordproblems.corpus.js";
import { HELDOUT, HELDOUT_FRESH } from "../test/quelvra/wordproblems.heldout.js";

const args = process.argv.slice(2);
const verbose = args.includes("-v");
const filter = args.find((a) => !a.startsWith("-"));
const CASES = args.includes("--fresh") ? HELDOUT_FRESH : args.includes("--heldout") ? HELDOUT : MAIN;
const by = new Map();
const K = ["ok", "incomplete", "refused", "WRONG"];
for (const [cat, input, exp] of CASES) {
  if (filter && cat !== filter) continue;
  let r, v;
  try { r = solve(input, { timeLimit: 5000 }); v = judge(exp, r); } catch (e) { v = "refused"; r = { answers: [], error: { message: "CRASH " + e.message } }; }
  const c = by.get(cat) || Object.fromEntries([...K, "total"].map((k) => [k, 0]));
  c[v]++; c.total++;
  by.set(cat, c);
  if (verbose || v === "WRONG" || v === "incomplete" || (v === "refused" && args.includes("-r"))) {
    const shown = (r.answers || []).map(textOf).join("; ").slice(0, 120);
    console.log(`${v.padEnd(10)} [${cat}] ${input}\n           -> ${(r.input && r.input.interpretation) || ""} | ${shown || (r.error && r.error.message) || ""}`);
  }
}
const T = Object.fromEntries([...K, "total"].map((k) => [k, 0]));
console.log("");
for (const [cat, c] of by) { console.log(`${cat.padEnd(12)} ${K.map((k) => `${k} ${String(c[k]).padStart(2)}`).join("  ")}  / ${c.total}`); for (const k in T) T[k] += c[k]; }
console.log(`${"TOTAL".padEnd(12)} ${K.map((k) => `${k} ${T[k]}`).join("  ")}  / ${T.total}`);
if (args.includes("--json")) console.log(JSON.stringify(Object.fromEntries(by)));
