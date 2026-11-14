#!/usr/bin/env node
// Replays real Claude Code sessions to measure what Nexus /cheap would have
// saved, priced at every current Claude model family's list rates.
//
//   node scripts/measure-cheap-replay.mjs [--days 14] [--cli ../darknode-cli] [--out public/data/nexus-cheap-replay.json]
//
// Input: ~/.claude/projects/**/*.jsonl (main-thread calls only; subagents use a
// 5-minute cache and are left out). Output: aggregate token counts and dollar
// figures only, never prompts, paths or content.
//
// What is counted (the /cheap levers whose effect can be measured from usage):
//  - keep-warm: on a 1-hour cache, a return after more than an hour rebuilds the
//    whole context. The replay sends the same keep-alive pings Nexus would
//    (4 minutes before expiry, up to 6 hours after the last call, contexts of
//    20k+ tokens) and charges them; a rebuild is avoided only if the cache was
//    still warm when the next call came. Pings in a break longer than that are
//    charged with no saving.
//  - unused skills by name only: SKILL_TOKENS fewer prompt tokens per call
//    (written on a rebuild, read otherwise). Measured on the owner's setup.
// Not counted (no honest way to measure it from usage): the model-switch hold,
// which depends on whether you would have switched anyway, and the shared
// cache prefix across folders.
// Assumption: Nexus stays open during breaks (keep-warm runs only while it is).

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { createRequire } from "node:module";

const arg = (k, d) => { const i = process.argv.indexOf("--" + k); return i > 0 ? process.argv[i + 1] : d; };
const DAYS = +arg("days", 14);
const CLI = path.resolve(arg("cli", path.join(os.homedir(), "projects", "darknode-cli")));
const OUT = arg("out", "public/data/nexus-cheap-replay.json");
const { costOf, priceOf } = createRequire(import.meta.url)(path.join(CLI, "lib", "nexus", "pricing.js"));

const HOUR = 3600e3, LEAD = 4 * 60e3, CAP = 6 * HOUR, MIN_CTX = 20000;
const SKILL_TOKENS = 3700;                       // measured: unused skill descriptions dropped per call
const PING = { input: 2, write: 100, output: 5 }; // measured keep-alive ping besides the cached read (Haiku run: wrote 50-153, output 4)
const MODELS = ["haiku 5.5", "sonnet 5.5", "opus 5.5", "fable 5.2"];

const since = Date.now() - DAYS * 24 * HOUR;
const walk = (d, o = []) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const f = path.join(d, e.name); if (e.isDirectory()) { if (e.name !== "subagents") walk(f, o); } else if (f.endsWith(".jsonl") && fs.statSync(f).mtimeMs >= since) o.push(f); } return o; };

// one session = one transcript file: its main-thread API calls in time order
function sessionCalls(file) {
  const seen = new Set(), calls = [];
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    if (!line.includes('"usage"')) continue;
    let j; try { j = JSON.parse(line); } catch { continue; }
    const m = j.message; if (!m || !m.usage || !m.model || j.isSidechain) continue;
    if (!/^claude-/.test(m.model)) continue;
    const ts = Date.parse(j.timestamp || 0); if (!(ts >= since)) continue;
    const id = (m.id || "") + ":" + (j.requestId || ""); if (seen.has(id)) continue; seen.add(id);
    const u = m.usage, cc = u.cache_creation || {}, cw = u.cache_creation_input_tokens || 0;
    const w1h = cc.ephemeral_1h_input_tokens || 0, w5 = cc.ephemeral_5m_input_tokens != null ? cc.ephemeral_5m_input_tokens : Math.max(0, cw - w1h);
    calls.push({ ts, input: u.input_tokens || 0, cacheWrite5m: w5, cacheWrite1h: w1h, cacheRead: u.cache_read_input_tokens || 0, output: u.output_tokens || 0 });
  }
  return calls.sort((a, b) => a.ts - b.ts);
}
const ctxOf = (c) => c.input + c.cacheWrite5m + c.cacheWrite1h + c.cacheRead;

// Per model: before = the real tokens; after = the same calls with /cheap's measured levers applied.
const tot = Object.fromEntries(MODELS.map((m) => [m, { before: 0, after: 0, keepWarmSaved: 0, pingCost: 0, skillSaved: 0 }]));
let sessions = 0, calls = 0, rebuildsAfterBreaks = 0, rebuildsAvoided = 0, pings = 0, firstTs = Infinity, lastTs = 0;

for (const f of walk(path.join(os.homedir(), ".claude", "projects"))) {
  const cs = sessionCalls(f); if (!cs.length) continue;
  sessions++; calls += cs.length; firstTs = Math.min(firstTs, cs[0].ts); lastTs = Math.max(lastTs, cs[cs.length - 1].ts);
  const oneHour = cs.some((c) => c.cacheWrite1h > 0);
  for (let i = 0; i < cs.length; i++) {
    const c = cs[i], prev = cs[i - 1], ctx = ctxOf(c);
    const rebuild = (c.cacheWrite5m + c.cacheWrite1h) >= 0.5 * ctx; // most of the prompt written, not read
    let after = c, nPings = 0, prevCtx = 0;
    if (prev && oneHour && rebuild && c.ts - prev.ts > HOUR && (prevCtx = ctxOf(prev)) >= MIN_CTX) {
      rebuildsAfterBreaks++;
      // keep-warm pings: each just before expiry, while within 6h of the last call
      let warmUntil = prev.ts + HOUR, t = warmUntil - LEAD;
      while (t - prev.ts < CAP && t < c.ts) { nPings++; warmUntil = t + HOUR; t = warmUntil - LEAD; }
      if (c.ts <= warmUntil) { // cache still warm: only the genuinely new tokens are written
        rebuildsAvoided++;
        const fresh = Math.max(0, ctx - prevCtx), w = c.cacheWrite5m + c.cacheWrite1h, keep = Math.min(w, fresh);
        after = Object.assign({}, c, { cacheWrite1h: c.cacheWrite1h ? keep : 0, cacheWrite5m: c.cacheWrite1h ? 0 : keep, cacheRead: c.cacheRead + (w - keep) });
      }
      pings += nPings;
    }
    for (const m of MODELS) {
      const t = tot[m], before = costOf(m, c), kept = costOf(m, after);
      const ping = nPings * costOf(m, { input: PING.input, cacheRead: prevCtx, cacheWrite1h: PING.write, output: PING.output });
      const p = priceOf(m, { promptTokens: ctx }), rate = (rebuild && after === c) ? (c.cacheWrite1h ? p.cw1h : p.cw5) : p.cr;
      const skill = Math.min(SKILL_TOKENS, ctx) * rate / 1e6;
      t.before += before; t.after += kept + ping - skill;
      t.keepWarmSaved += before - kept; t.pingCost += ping; t.skillSaved += skill;
    }
  }
}

const r2 = (n) => Math.round(n * 100) / 100;
const out = {
  measured: new Date().toISOString().slice(0, 10),
  period: { days: DAYS, from: new Date(firstTs).toISOString().slice(0, 10), to: new Date(lastTs).toISOString().slice(0, 10) },
  sample: { sessions, calls, rebuildsAfterBreaks, rebuildsAvoided, keepWarmPings: pings },
  method: "Real main-thread Claude Code calls from one developer's sessions, priced at each model's list rates (same tokens on every model). After = keep-warm and unused-skill trimming applied, keep-alive pings charged. Assumes Nexus stays open during breaks.",
  models: MODELS.map((m) => { const t = tot[m]; return { model: m, label: priceOf(m).label, before: r2(t.before), after: r2(t.after), saved: r2(t.before - t.after), pct: t.before ? Math.round((t.before - t.after) / t.before * 1000) / 10 : 0, keepWarmSaved: r2(t.keepWarmSaved), pingCost: r2(t.pingCost), skillSaved: r2(t.skillSaved) }; }),
};
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, JSON.stringify(out, null, 2) + "\n");
console.log(JSON.stringify(out, null, 2));
