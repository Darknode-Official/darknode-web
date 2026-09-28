// Smart mode (OPTIONAL, off by default): use the user's OWN Gemini key as a
// LANGUAGE FRONT-END for DI. Gemini only INTERPRETS the request into a command
// the deterministic engine understands; whenever the request reduces to an
// engine capability, DI still computes the answer, so the result stays exact and
// verifiable. Gemini answers directly only when the deterministic core has no
// rule for the request, and that case is clearly labelled as unverified.
//
// This module is browser-only (fetch + localStorage) and is NOT imported by the
// deterministic engine or its Node tests, so the no-AI core stays model-free.

const KEY_LS = "sw_gemini_key";      // shared with the site's Settings -> API Keys
const MODEL_LS = "di_smart_model";
const DEFAULT_MODEL = "gemini-flash-latest"; // an alias Google keeps current (the old 2.0 id can be retired)
const FALLBACK_MODEL = "gemini-flash-latest";

function readKey() { try { return (localStorage.getItem(KEY_LS) || "").trim(); } catch (_) { return ""; } }
export function hasSmartKey() { return !!readKey(); }
export function smartModel() { try { return (localStorage.getItem(MODEL_LS) || "").trim() || DEFAULT_MODEL; } catch (_) { return DEFAULT_MODEL; } }

const SYS = `You are the planner for DI, a deterministic (no-AI) computation engine. The engine can: evaluate arithmetic and math expressions (variables, functions, factorial, percentages); convert units; convert number bases and roman numerals; convert colors; solve linear and quadratic equations; do number theory (prime test, gcd/lcm, factorize, nth prime, nth fibonacci); compute statistics over a list; generate code from a spec in several languages (e.g. "write a fibonacci function in rust", or "f(x) = 3x^2 - 2x + 1 in go"); transform text (case, slug, counts, extract emails/urls/numbers); build and test regular expressions; run JSON path queries; do date math; encode/hash (base64, hex, url, rot13, morse, crc32); look up country capitals, chemical elements and physical constants; truth tables, set operations, matrices, sequences and combinatorics.

Your job: understand the user's request no matter how it is phrased or misspelled, using the earlier conversation for context, and turn it into a PLAN of short engine commands run in order. A later command may refer to the previous command's result as "it" (e.g. ["15% of 240", "multiply it by 3", "is it prime"]). Reply with STRICT JSON and nothing else:
{"steps": [<command strings>], "answer": <string or null>}

- Put every part the engine can do into "steps", one command each, normalized (e.g. "convert 5 km to miles", "solve x^2 - 5x + 6 = 0", "reverse: hello world", "capital of japan"). For a math word problem, a step is ONLY the arithmetic (a savings total becomes "45+62+58").
- Use "answer" only for what the engine genuinely cannot do (opinions, open-ended writing, whole applications, general knowledge outside the list). Keep it concise and correct. If everything is covered by steps, "answer" is null.
- Output JSON only: no code fences, no extra prose.`;

// history: [{ q, a }] of recent turns (a = a short text summary of DI's answer),
// so a follow-up like "now do it in rust" has its context.
export async function smartInterpret(input, history = []) {
  const key = readKey();
  if (!key) return { ok: false, needKey: true, error: "Smart mode needs your Gemini key. Add it in Settings → API Keys." };
  const contents = [];
  for (const h of (history || []).slice(-6)) {
    if (!h || !h.q) continue;
    contents.push({ role: "user", parts: [{ text: String(h.q) }] });
    contents.push({ role: "model", parts: [{ text: String(h.a || "(answered)").slice(0, 400) }] });
  }
  contents.push({ role: "user", parts: [{ text: String(input || "") }] });
  const body = {
    systemInstruction: { parts: [{ text: SYS }] },
    contents,
    generationConfig: { temperature: 0, responseMimeType: "application/json" },
  };
  const call = (model) => fetch("https://generativelanguage.googleapis.com/v1beta/models/" + model + ":generateContent?key=" + encodeURIComponent(key),
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  let model = smartModel(), r;
  try {
    r = await call(model);
    if (r.status === 404 && model !== FALLBACK_MODEL) { model = FALLBACK_MODEL; r = await call(model); } // a retired model id: retry on the current alias
  } catch (_) { return { ok: false, error: "Could not reach Gemini. Check your connection." }; }
  if (r.status === 401 || r.status === 403) return { ok: false, needKey: true, error: "That Gemini key was rejected. Check it in Settings → API Keys." };
  if (r.status === 429) return { ok: false, error: "Gemini is rate-limited right now. Wait a few seconds and try again." };
  if (!r.ok) {
    const t = await r.text().catch(() => "");
    if (r.status === 400 && /API_KEY_INVALID|API key not valid/i.test(t)) return { ok: false, needKey: true, error: "Google says that is not a valid Gemini API key. Create one at aistudio.google.com/apikey and paste it in Settings → API Keys." };
    return { ok: false, error: "Gemini API " + r.status + " (model " + model + ")" + (t ? ": " + t.slice(0, 160) : "") };
  }
  let j; try { j = await r.json(); } catch (_) { return { ok: false, error: "Gemini returned an unreadable response." }; }
  const cand = (j.candidates || [])[0] || {};
  const parts = (cand.content || {}).parts || [];
  const text = parts.map((p) => p.text || "").join("").trim();
  if (!text) return { ok: false, error: "Gemini returned an empty response." };
  let parsed = null;
  try { parsed = JSON.parse(text.replace(/^```(?:json)?/i, "").replace(/```$/, "").trim()); } catch (_) { parsed = null; }
  if (!parsed || typeof parsed !== "object") return { ok: true, steps: [], command: null, answer: text, raw: text };
  let steps = Array.isArray(parsed.steps) ? parsed.steps.filter((x) => typeof x === "string" && x.trim()).map((x) => x.trim()).slice(0, 12) : [];
  if (!steps.length && typeof parsed.command === "string" && parsed.command.trim()) steps = [parsed.command.trim()]; // older single-command shape
  return { ok: true, steps, command: steps[0] || null, answer: parsed.answer || null, raw: text };
}
