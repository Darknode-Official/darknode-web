// Checks the plain-English help for the mini-tools (public/js/tools/help/*.js).
// node tools/check-tool-help.mjs [file ...]   e.g. node tools/check-tool-help.mjs hashing
// For every tool: a help entry exists, `what`/`when` are present, example keys are real input
// names, and running the tool on the example gives non-empty output without an error.
import { readdirSync } from "fs";
import { fileURLToPath } from "url";
const root = fileURLToPath(new URL("../public/js/tools/", import.meta.url));
const { H } = await import(root + "_helpers.js");
const only = process.argv.slice(2);
const files = readdirSync(root).filter((f) => /^[a-z]\w*\.js$/.test(f)).map((f) => f.replace(/\.js$/, ""))
  .filter((f) => !only.length || only.includes(f));
const EMOJI = /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u;
let total = 0, bad = 0, missing = 0;
for (const f of files) {
  const { TOOLS } = await import(root + f + ".js");
  const { HELP } = await import(root + "help/" + f + ".js");
  let fbad = 0, fmiss = 0;
  for (const id of Object.keys(HELP)) if (!TOOLS.some((t) => t.id === id)) { console.log(`${f}: help for unknown tool ${id}`); fbad++; }
  for (const t of TOOLS) {
    total++;
    const h = HELP[t.id];
    if (!h) { fmiss++; continue; }
    const probs = [];
    if (!h.what || h.what.length < 15) probs.push("what missing/short");
    if (!h.when || h.when.length < 15) probs.push("when missing/short");
    if (EMOJI.test(h.what + h.when)) probs.push("emoji");
    const keys = new Set((t.inputs || []).map((i) => i.k));
    const ex = h.example || {};
    for (const k of Object.keys(ex)) if (!keys.has(k)) probs.push(`example key "${k}" is not an input`);
    if ((t.inputs || []).length && !Object.keys(ex).length) probs.push("no example");
    const v = {};
    for (const i of t.inputs || []) v[i.k] = i.type === "checkbox" ? !!i.value : (i.value ?? (i.type === "select" && i.opts && i.opts.length ? (Array.isArray(i.opts[0]) ? i.opts[0][0] : i.opts[0]) : i.type === "range" ? String(i.min ?? 0) : ""));
    for (const [k, val] of Object.entries(ex)) v[k] = val;
    for (const i of t.inputs || []) if (i.type === "select" && ex[i.k] !== undefined) {
      const vals = (i.opts || []).map((o) => String(Array.isArray(o) ? o[0] : o));
      if (!vals.includes(String(ex[i.k]))) probs.push(`example ${i.k}="${ex[i.k]}" is not an option`);
    }
    let out;
    try { out = await t.run(v, H); } catch (e) { probs.push("run threw: " + e.message); }
    if (!probs.length) {
      if (out && typeof out === "object" && out.error) probs.push("example gives error: " + out.error);
      else { const s = out == null ? "" : typeof out === "object" && "out" in out ? out.out : String(out); if (!String(s).trim()) probs.push("example gives empty output"); }
    }
    if (probs.length) { fbad++; console.log(`${f}: ${t.id}: ${probs.join("; ")}`); }
  }
  bad += fbad; missing += fmiss;
  console.log(`${f.padEnd(11)} tools ${String(TOOLS.length).padStart(3)}  help ${String(TOOLS.length - fmiss).padStart(3)}  problems ${fbad}`);
}
console.log(`\nTOTAL tools ${total}  missing help ${missing}  problems ${bad}`);
process.exit(missing || bad ? 1 : 0);
