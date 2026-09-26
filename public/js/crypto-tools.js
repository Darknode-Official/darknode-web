// Darknode Crypto & Encoding Tools Suite
// A large, self-contained collection of classical and modern cryptography
// learning tools. Everything here runs client-side in the browser -- no
// network calls, no external libraries. Where the browser provides a real
// primitive (WebCrypto for AES / RSA / ECDSA / SHA hashing) we use it.
// Everything else (Vigenere, XOR, RSA-by-hand, Base32/58/85, Morse, CRC,
// Adler32, frequency analysis, entropy estimation ...) is implemented from
// scratch so learners can read the code and see exactly how it works.
//
// Exported entry point: renderCryptoTools(main)

// ---------------------------------------------------------------------------
// Shared low level helpers
// ---------------------------------------------------------------------------

const TE = new TextEncoder();
const TD = new TextDecoder();

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function clamp(n, lo, hi) {
  return Math.max(lo, Math.min(hi, n));
}

function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const clean = hex.trim().replace(/^0x/i, "").replace(/[\s,]+/g, "");
  if (clean.length === 0) return new Uint8Array(0);
  if (clean.length % 2 !== 0) throw new Error("Hex string must have an even number of digits");
  if (!/^[0-9a-fA-F]+$/.test(clean)) throw new Error("Hex string contains non-hex characters");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

function bytesToBase64(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function base64ToBytes(b64) {
  const bin = atob(b64.trim());
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function textToBytes(s) {
  return TE.encode(s);
}

function bytesToText(bytes) {
  return TD.decode(bytes);
}

function isLikelyHex(s) {
  const clean = s.trim().replace(/^0x/i, "").replace(/\s+/g, "");
  return clean.length > 0 && clean.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(clean);
}

function downloadBlob(filename, content, mime = "text/plain") {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}

function copyText(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(() => {});
  }
}

// Standard input -> transform -> output tool, matching the site-wide pattern
// used by toolkit.js. Kept local here so this module has zero cross-file
// dependencies.
function io(root, ops, ph = "Input") {
  root.innerHTML = `<textarea class="tk-in" rows="4" placeholder="${ph}"></textarea>
    <div class="tk-btns">${ops.map((o, i) => `<button class="btn sm" data-i="${i}">${o.label}</button>`).join("")}</div>
    <pre class="tk-out"></pre>`;
  const inp = root.querySelector(".tk-in"), out = root.querySelector(".tk-out");
  root.querySelector(".tk-btns").onclick = async (e) => {
    const b = e.target.closest("button[data-i]"); if (!b) return;
    try { out.textContent = await ops[+b.dataset.i].fn(inp.value); }
    catch (err) { out.textContent = "Error: " + err.message; }
  };
}

// ---------------------------------------------------------------------------
// BigInt number theory helpers (used by RSA + Diffie-Hellman)
// ---------------------------------------------------------------------------

// Modular exponentiation: base^exp mod m, computed with the classic
// square-and-multiply algorithm so it stays fast even for large exponents.
function modPow(base, exp, mod) {
  base = BigInt(base); exp = BigInt(exp); mod = BigInt(mod);
  if (mod === 1n) return 0n;
  let result = 1n;
  base = ((base % mod) + mod) % mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

// Extended Euclidean algorithm. Returns { g, x, y } such that a*x + b*y = g
// and g = gcd(a, b). Used to compute modular inverses for RSA's private
// exponent d.
function extendedGcd(a, b) {
  a = BigInt(a); b = BigInt(b);
  let [oldR, r] = [a, b];
  let [oldS, s] = [1n, 0n];
  let [oldT, t] = [0n, 1n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
    [oldT, t] = [t, oldT - q * t];
  }
  return { g: oldR, x: oldS, y: oldT };
}

function gcdBig(a, b) {
  a = a < 0n ? -a : a; b = b < 0n ? -b : b;
  while (b) { [a, b] = [b, a % b]; }
  return a;
}

// Modular multiplicative inverse of a mod m, or null if it doesn't exist
// (i.e. gcd(a, m) != 1).
function modInverse(a, m) {
  a = BigInt(a); m = BigInt(m);
  const { g, x } = extendedGcd(a, m);
  if (g !== 1n && g !== -1n) return null;
  return ((x % m) + m) % m;
}

// Deterministic Miller-Rabin primality test. Deterministic witness sets
// below are provably correct for numbers under the given bounds; for very
// large inputs we fall back to a generous fixed witness list plus extra
// random rounds, which is good enough for a learning tool.
function isProbablePrime(n) {
  n = BigInt(n);
  if (n < 2n) return false;
  const smallPrimes = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n];
  for (const p of smallPrimes) {
    if (n === p) return true;
    if (n % p === 0n) return false;
  }
  let d = n - 1n, r = 0n;
  while (d % 2n === 0n) { d /= 2n; r += 1n; }
  const witnesses = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n];
  witnessLoop: for (const a of witnesses) {
    if (a >= n) continue;
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    for (let i = 0n; i < r - 1n; i++) {
      x = (x * x) % n;
      if (x === n - 1n) continue witnessLoop;
    }
    return false;
  }
  return true;
}

function bigAbs(n) { return n < 0n ? -n : n; }

// Compute integer square root of a BigInt (Newton's method), used for a
// quick trial-division pre-check before running Miller-Rabin.
function bigSqrt(value) {
  if (value < 0n) throw new Error("square root of negative number");
  if (value < 2n) return value;
  let x0 = value, x1 = (x0 + 1n) >> 1n;
  while (x1 < x0) { x0 = x1; x1 = (x0 + value / x0) >> 1n; }
  return x0;
}

// ---------------------------------------------------------------------------
// English-language statistics used by frequency analysis and Caesar scoring
// ---------------------------------------------------------------------------

// Standard published English letter frequencies (percent), source: large
// corpus letter counts (Cornell / cryptanalysis references). Sums to ~100.
const ENGLISH_FREQ = {
  a: 8.167, b: 1.492, c: 2.782, d: 4.253, e: 12.702, f: 2.228, g: 2.015,
  h: 6.094, i: 6.966, j: 0.153, k: 0.772, l: 4.025, m: 2.406, n: 6.749,
  o: 7.507, p: 1.929, q: 0.095, r: 5.987, s: 6.327, t: 9.056, u: 2.758,
  v: 0.978, w: 2.360, x: 0.150, y: 1.974, z: 0.074,
};

// Common English bigrams / trigrams used to sanity check plaintext guesses.
const ENGLISH_COMMON_WORDS = new Set([
  "the", "and", "for", "are", "but", "not", "you", "all", "any", "can",
  "had", "her", "was", "one", "our", "out", "day", "get", "has", "him",
  "his", "how", "man", "new", "now", "old", "see", "two", "way", "who",
  "boy", "did", "its", "let", "put", "say", "she", "too", "use", "that",
  "with", "have", "this", "will", "your", "from", "they", "know", "want",
  "been", "good", "much", "some", "time", "very", "when", "come", "here",
  "just", "like", "long", "make", "many", "over", "such", "take", "than",
  "them", "well", "were",
]);

function letterCounts(text) {
  const counts = {};
  for (let i = 0; i < 26; i++) counts[String.fromCharCode(97 + i)] = 0;
  let total = 0;
  for (const ch of text.toLowerCase()) {
    if (ch >= "a" && ch <= "z") { counts[ch]++; total++; }
  }
  return { counts, total };
}

// Chi-squared statistic comparing observed letter distribution against the
// expected English distribution. Lower = more English-like.
function chiSquared(counts, total) {
  if (total === 0) return Infinity;
  let chi = 0;
  for (const letter of Object.keys(ENGLISH_FREQ)) {
    const observed = counts[letter] || 0;
    const expected = (ENGLISH_FREQ[letter] / 100) * total;
    if (expected > 0) chi += ((observed - expected) ** 2) / expected;
  }
  return chi;
}

// Quick English-likeness score used to rank Caesar / XOR brute force
// candidates: lower chi-squared plus a bonus for recognizable common words.
function englishScore(text) {
  const { counts, total } = letterCounts(text);
  const chi = chiSquared(counts, total);
  const words = text.toLowerCase().match(/[a-z]+/g) || [];
  let wordBonus = 0;
  for (const w of words) if (ENGLISH_COMMON_WORDS.has(w)) wordBonus += 1;
  const printableRatio = text.length
    ? [...text].filter((c) => {
        const code = c.charCodeAt(0);
        return (code >= 32 && code <= 126) || code === 9 || code === 10 || code === 13;
      }).length / text.length
    : 0;
  return { chi, wordBonus, printableRatio };
}

function barChart(pairs, maxWidth = 40) {
  const max = Math.max(...pairs.map((p) => p[1]), 0.0001);
  return pairs.map(([label, value]) => {
    const width = Math.round((value / max) * maxWidth);
    const bar = "#".repeat(width) || "";
    return `${label} | ${bar.padEnd(maxWidth, " ")} ${value.toFixed(3)}`;
  }).join("\n");
}

// ---------------------------------------------------------------------------
// Tab registry -- filled in below as each tool is implemented.
// ---------------------------------------------------------------------------

const TABS = [];

function registerTab(id, label, render) {
  TABS.push({ id, label, render });
}

// ---------------------------------------------------------------------------
// Tool 1: Frequency Analysis
// ---------------------------------------------------------------------------
//
// Counts how often each letter A-Z appears in a piece of text, renders an
// ASCII bar chart of the distribution, compares it against the well known
// English-language letter frequency table, and reports a chi-squared
// goodness-of-fit statistic. Chi-squared is the workhorse statistic used
// throughout classical cryptanalysis (Caesar / Vigenere / substitution
// cipher breaking) because it gives a single number describing how close
// an observed distribution is to the expected one -- lower is better.

// Reference digraph (bigram) and trigraph (trigram) frequency tables for
// English, expressed as approximate percentage of all bigrams/trigrams in
// a large English corpus. These are the classic "most common" lists used
// throughout cryptanalysis references -- useful for spotting polyalphabetic
// vs monoalphabetic ciphers and for manually verifying candidate plaintexts.
const ENGLISH_BIGRAMS = [
  ["TH", 3.56], ["HE", 3.07], ["IN", 2.43], ["ER", 2.05], ["AN", 1.99],
  ["RE", 1.85], ["ND", 1.54], ["AT", 1.44], ["ON", 1.32], ["NT", 1.11],
  ["HA", 1.09], ["ES", 1.08], ["ST", 1.05], ["EN", 1.03], ["ED", 1.02],
  ["TO", 1.00], ["IT", 0.90], ["OU", 0.87], ["EA", 0.85], ["HI", 0.81],
  ["IS", 0.80], ["OR", 0.78], ["TI", 0.76], ["AS", 0.75], ["TE", 0.73],
  ["ET", 0.71], ["NG", 0.68], ["OF", 0.66], ["AL", 0.64], ["DE", 0.63],
];

const ENGLISH_TRIGRAMS = [
  ["THE", 1.81], ["AND", 0.73], ["THA", 0.33], ["ENT", 0.42], ["ION", 0.43],
  ["TIO", 0.37], ["FOR", 0.31], ["NDE", 0.26], ["HAS", 0.24], ["NCE", 0.25],
  ["EDT", 0.19], ["TIS", 0.17], ["OFT", 0.22], ["STH", 0.19], ["MEN", 0.18],
];

// Index of Coincidence -- the probability that two randomly chosen letters
// from the text are identical. Plain English sits around 0.065-0.070;
// perfectly random/uniform 26-letter text sits around 0.0385. This one
// number is enough to distinguish a monoalphabetic substitution (IoC stays
// English-like, ~0.065-0.07, because relative letter frequencies are
// preserved just relabeled) from a polyalphabetic cipher like Vigenere
// (IoC drops toward the random value as the key length grows), which is
// exactly how the Friedman test estimates an unknown Vigenere key length.
function indexOfCoincidence(text) {
  const { counts, total } = letterCounts(text);
  if (total < 2) return 0;
  let sum = 0;
  for (const c of Object.values(counts)) sum += c * (c - 1);
  return sum / (total * (total - 1));
}

function extractNgrams(text, n) {
  const letters = text.toUpperCase().replace(/[^A-Z]/g, "");
  const counts = {};
  for (let i = 0; i + n <= letters.length; i++) {
    const gram = letters.slice(i, i + n);
    counts[gram] = (counts[gram] || 0) + 1;
  }
  return counts;
}

function topNgrams(counts, limit = 15) {
  return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, limit);
}

function renderFrequencyAnalysis(root) {
  root.innerHTML = `
    <div class="tk-section">
    <h2 class="pg-h2">Frequency Analysis</h2>
    <p class="muted">Paste any text below. This tool counts every letter A-Z, shows the
      distribution as a bar chart, and compares it against standard English letter
      frequencies using a chi-squared goodness-of-fit test. Classical ciphers like Caesar,
      Vigenere and simple substitution all leak information through letter frequency --
      this is the first tool a cryptanalyst reaches for.</p>
    <textarea class="tk-in" id="fa-in" rows="6" placeholder="Paste text or ciphertext to analyze..."></textarea>
    <div class="tk-btns">
      <button class="btn sm" id="fa-run">Analyze</button>
      <button class="btn sm ghost" id="fa-sample">Load sample text</button>
      <button class="btn sm ghost" id="fa-clear">Clear</button>
    </div>
    <div id="fa-stats" class="mono" style="margin-top:14px"></div>
    <pre class="tk-out" id="fa-out" style="min-height:420px"></pre>
    </div>
  `;

  const input = root.querySelector("#fa-in");
  const stats = root.querySelector("#fa-stats");
  const out = root.querySelector("#fa-out");

  root.querySelector("#fa-sample").onclick = () => {
    input.value = "The quick brown fox jumps over the lazy dog. Cryptanalysis relies on the "
      + "fact that natural language is never truly random -- some letters, like E and T, show "
      + "up far more often than letters like Q, X, and Z. A frequency table built from enough "
      + "text approaches the theoretical English distribution, and that regularity is exactly "
      + "what lets an analyst break a simple substitution or Caesar cipher without knowing the key.";
    run();
  };
  root.querySelector("#fa-clear").onclick = () => { input.value = ""; stats.textContent = ""; out.textContent = ""; };
  root.querySelector("#fa-run").onclick = run;

  function run() {
    const text = input.value;
    if (!text.trim()) { out.textContent = "Enter some text first."; return; }
    const { counts, total } = letterCounts(text);
    if (total === 0) { out.textContent = "No A-Z letters found in the input."; return; }

    const chi = chiSquared(counts, total);
    let verdict;
    if (chi < 30) verdict = "Very close match to English -- likely plaintext or a weak/no cipher.";
    else if (chi < 80) verdict = "Loosely resembles English -- could be lightly transformed text.";
    else if (chi < 200) verdict = "Noticeably different from English -- likely enciphered or non-English text.";
    else verdict = "Very far from English -- likely strongly enciphered, random, or non-alphabetic data.";

    stats.innerHTML = `
      <div class="tk-row" style="flex-wrap:wrap;gap:18px">
        <div class="stat"><div class="stat-n">${total}</div><div class="stat-l">Letters counted</div></div>
        <div class="stat"><div class="stat-n">${chi.toFixed(2)}</div><div class="stat-l">Chi-squared score</div></div>
        <div class="stat"><div class="stat-n">${Object.values(counts).filter((c) => c > 0).length}</div><div class="stat-l">Distinct letters used</div></div>
        <div class="stat"><div class="stat-n">${mostCommon(counts).toUpperCase()}</div><div class="stat-l">Most frequent letter</div></div>
      </div>
      <p class="muted" style="margin-top:10px">${verdict}</p>
    `;

    const sortedByFreq = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    const chartPairs = sortedByFreq.map(([letter, count]) => [letter.toUpperCase(), (count / total) * 100]);
    const observedChart = barChart(chartPairs, 40);

    const englishPairs = Object.entries(ENGLISH_FREQ).sort((a, b) => b[1] - a[1]).map(([l, v]) => [l.toUpperCase(), v]);
    const englishChart = barChart(englishPairs, 40);

    const ioc = indexOfCoincidence(text);
    let iocVerdict;
    if (ioc >= 0.06) iocVerdict = "Close to English (~0.065-0.070) -- consistent with plaintext or a monoalphabetic substitution/Caesar cipher (relative letter frequencies survive relabeling).";
    else if (ioc >= 0.045) iocVerdict = "Between English and random -- could be a short-key polyalphabetic cipher (e.g. Vigenere with a short key).";
    else iocVerdict = "Close to random/uniform (~0.0385) -- consistent with a polyalphabetic cipher with a longer key, or with modern encryption output.";

    const bigramCounts = extractNgrams(text, 2);
    const trigramCounts = extractNgrams(text, 3);
    const topBigrams = topNgrams(bigramCounts, 10);
    const topTrigrams = topNgrams(trigramCounts, 10);

    const tableRows = Object.keys(ENGLISH_FREQ).map((letter) => {
      const observedPct = total ? ((counts[letter] || 0) / total) * 100 : 0;
      const expectedPct = ENGLISH_FREQ[letter];
      const diff = observedPct - expectedPct;
      const sign = diff >= 0 ? "+" : "";
      return `${letter.toUpperCase()}  observed ${observedPct.toFixed(2).padStart(6)}%   `
        + `english ${expectedPct.toFixed(2).padStart(6)}%   diff ${sign}${diff.toFixed(2)}%   count=${counts[letter] || 0}`;
    }).join("\n");

    out.textContent =
`=== Observed distribution (this text) ===
${observedChart}

=== Expected distribution (standard English) ===
${englishChart}

=== Letter-by-letter comparison ===
${tableRows}

=== Chi-squared goodness of fit ===
chi-squared = sum over each letter of ((observed_count - expected_count)^2 / expected_count)
Score: ${chi.toFixed(3)}
Rule of thumb: < 30 very English-like, 30-80 plausible, 80-200 unlikely, > 200 not English.
This is the same statistic the Caesar Brute Force and Substitution Helper tools use
internally to automatically rank candidate plaintexts.

=== Index of Coincidence ===
IoC = sum(count_i * (count_i - 1)) / (total * (total - 1))
Score: ${ioc.toFixed(4)}
English plaintext: ~0.0650-0.0700   Random/uniform 26 letters: ~0.0385
${iocVerdict}

=== Most common bigrams (2-letter sequences) in this text ===
${topBigrams.map(([g, c]) => `${g}  count=${c}`).join("\n") || "(text too short)"}

Reference: most common English bigrams, by published corpus frequency:
${ENGLISH_BIGRAMS.slice(0, 10).map(([g, p]) => `${g} (${p}%)`).join("  ")}

=== Most common trigrams (3-letter sequences) in this text ===
${topTrigrams.map(([g, c]) => `${g}  count=${c}`).join("\n") || "(text too short)"}

Reference: most common English trigrams, by published corpus frequency:
${ENGLISH_TRIGRAMS.map(([g, p]) => `${g} (${p}%)`).join("  ")}`;
  }

  function mostCommon(counts) {
    let best = "a", bestCount = -1;
    for (const [letter, count] of Object.entries(counts)) {
      if (count > bestCount) { best = letter; bestCount = count; }
    }
    return best;
  }
}

registerTab("freq", "Frequency Analysis", renderFrequencyAnalysis);

// ---------------------------------------------------------------------------
// Tool 2: Caesar Cipher Brute Force
// ---------------------------------------------------------------------------
//
// A Caesar cipher only has 26 possible keys (shift 0-25), so the correct
// approach is never guessing -- it's trying every single one and letting
// statistics pick the winner. We shift the ciphertext by every rotation,
// score each result with englishScore() (chi-squared + common word count),
// and highlight whichever rotation looks most like English.

function caesarShift(text, shift) {
  shift = ((shift % 26) + 26) % 26;
  return text.replace(/[a-zA-Z]/g, (c) => {
    const base = c === c.toUpperCase() ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + shift) % 26) + base);
  });
}

function renderCaesarBruteForce(root) {
  root.innerHTML = `
    <div class="tk-section">
    <h2 class="pg-h2">Caesar Cipher Brute Force</h2>
    <p class="muted">A Caesar (shift) cipher rotates every letter of the alphabet by a fixed
      amount. Because there are only 26 possible shifts, the cipher is trivially breakable by
      trying all of them and picking whichever result looks most like English. Enter
      ciphertext below and every rotation will be tried automatically.</p>
    <textarea class="tk-in" id="cb-in" rows="4" placeholder="Enter Caesar-encrypted text..."></textarea>
    <div class="tk-btns">
      <button class="btn sm" id="cb-run">Brute force all 26 shifts</button>
      <button class="btn sm ghost" id="cb-sample">Load sample (shift 7)</button>
    </div>
    <div id="cb-best" style="margin-top:12px"></div>
    <pre class="tk-out" id="cb-out" style="min-height:460px"></pre>
    </div>

    <div class="tk-section">
    <h2 class="pg-h2" style="margin-top:0">Bonus: ROT47</h2>
    <p class="muted">ROT47 extends the same rotation idea across all 94 printable ASCII
      characters (33-126) instead of just the 26 letters, so it also scrambles digits and
      punctuation. It's self-inverse -- applying it twice restores the original text.</p>
    <textarea class="tk-in" id="r47-in" rows="3" placeholder="Text to ROT47..."></textarea>
    <div class="tk-btns"><button class="btn sm" id="r47-run">Apply ROT47</button></div>
    <pre class="tk-out" id="r47-out"></pre>
    </div>
  `;

  const input = root.querySelector("#cb-in");
  const best = root.querySelector("#cb-best");
  const out = root.querySelector("#cb-out");
  const r47in = root.querySelector("#r47-in");
  const r47out = root.querySelector("#r47-out");

  root.querySelector("#cb-sample").onclick = () => {
    input.value = caesarShift("Meet me at the old bridge after midnight, bring the documents.", 7);
    run();
  };
  root.querySelector("#cb-run").onclick = run;
  root.querySelector("#r47-run").onclick = () => { r47out.textContent = rot47(r47in.value); };

  function run() {
    const text = input.value;
    if (!text.trim()) { out.textContent = "Enter ciphertext first."; return; }

    const results = [];
    for (let shift = 0; shift < 26; shift++) {
      const candidate = caesarShift(text, -shift); // undo an assumed encryption shift of `shift`
      const score = englishScore(candidate);
      results.push({ shift, candidate, ...score });
    }

    // Rank: fewer common-word matches is bad, chi-squared lower is good.
    // Combine into one comparable rank score (lower is better).
    for (const r of results) {
      r.rank = r.chi - r.wordBonus * 25 + (1 - r.printableRatio) * 500;
    }
    const ranked = [...results].sort((a, b) => a.rank - b.rank);
    const winner = ranked[0];

    best.innerHTML = `
      <div class="card">
        <strong>Most likely plaintext: shift ${winner.shift}</strong>
        <div class="mono" style="margin-top:6px;white-space:pre-wrap">${escapeHtml(winner.candidate)}</div>
        <div class="muted" style="margin-top:6px">chi-squared=${winner.chi.toFixed(2)}, common words matched=${winner.wordBonus}</div>
      </div>`;

    out.textContent = results.map((r) => {
      const marker = r.shift === winner.shift ? " <== best match" : "";
      return `shift ${String(r.shift).padStart(2, "0")}  (chi=${r.chi.toFixed(1).padStart(7)}, words=${r.wordBonus})  ${r.candidate}${marker}`;
    }).join("\n");
  }
}

// ROT47 is a Caesar-style rotation over the 94 printable ASCII characters
// (33-126) instead of just the 26 letters, so it scrambles digits and
// punctuation too. It's self-inverse (applying it twice returns the
// original), which is why it's popular for lightly obscuring text (e.g. on
// Usenet) where a reversible-by-eye transform is all that's wanted.
function rot47(text) {
  return text.replace(/[!-~]/g, (c) => String.fromCharCode(33 + ((c.charCodeAt(0) + 14) % 94)));
}

registerTab("caesar", "Caesar Brute Force", renderCaesarBruteForce);

// ---------------------------------------------------------------------------
// Tool 3: Vigenere Cipher
// ---------------------------------------------------------------------------
//
// The Vigenere cipher encrypts each letter with a Caesar shift determined
// by the corresponding letter of a repeating key: cipher[i] = plain[i] +
// key[i mod keylen] (mod 26). Because the shift changes every position it
// flattens the letter-frequency signature that makes Caesar so easy to
// break -- this is why it was considered "le chiffre indechiffrable" for
// centuries, until Kasiski/Friedman techniques (key-length detection via
// repeated fragments) cracked it in the 1800s.

function vigenereProcess(text, key, decode) {
  const cleanKey = key.replace(/[^a-zA-Z]/g, "");
  if (!cleanKey) throw new Error("Key must contain at least one letter");
  let ki = 0;
  const steps = [];
  const result = text.replace(/[a-zA-Z]/g, (c) => {
    const base = c === c.toUpperCase() ? 65 : 97;
    const keyChar = cleanKey[ki % cleanKey.length].toLowerCase();
    const keyShift = keyChar.charCodeAt(0) - 97;
    const shift = decode ? -keyShift : keyShift;
    const plainIndex = c.charCodeAt(0) - base;
    const newIndex = ((plainIndex + shift) % 26 + 26) % 26;
    const outChar = String.fromCharCode(newIndex + base);
    steps.push({ input: c, key: cleanKey[ki % cleanKey.length].toUpperCase(), output: outChar });
    ki++;
    return outChar;
  });
  return { result, steps, cleanKey };
}

function buildVigenereTableau() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  let html = '<table class="mono" style="border-collapse:collapse;font-size:11px">';
  html += "<tr><td></td>" + [...alphabet].map((c) => `<td style="padding:2px 4px;text-align:center;opacity:.6">${c}</td>`).join("") + "</tr>";
  for (let row = 0; row < 26; row++) {
    html += `<tr><td style="padding:2px 4px;opacity:.6">${alphabet[row]}</td>`;
    for (let col = 0; col < 26; col++) {
      const ch = alphabet[(row + col) % 26];
      html += `<td style="padding:2px 4px;text-align:center;border:1px solid rgba(255,255,255,.06)">${ch}</td>`;
    }
    html += "</tr>";
  }
  html += "</table>";
  return html;
}

function renderVigenere(root) {
  root.innerHTML = `
    <div class="tk-section">
    <h2 class="pg-h2">Vigenere Cipher</h2>
    <p class="muted">A polyalphabetic substitution cipher: each letter is shifted by an amount
      taken from a repeating keyword. Row = plaintext letter, column = key letter (or use the
      tableau below directly): the cell where the plaintext row meets the key column is the
      ciphertext letter.</p>
    <div class="tk-row">
      <textarea class="tk-in" id="vg-text" rows="4" placeholder="Text to encode or decode..." style="flex:2"></textarea>
      <input class="tk-f" id="vg-key" placeholder="Key (letters only), e.g. LEMON" style="flex:1;align-self:flex-start">
    </div>
    <div class="tk-btns">
      <button class="btn sm" id="vg-enc">Encode</button>
      <button class="btn sm" id="vg-dec">Decode</button>
      <button class="btn sm ghost" id="vg-sample">Load sample</button>
      <button class="btn sm ghost" id="vg-showsteps">Show step-by-step</button>
      <button class="btn sm ghost" id="vg-showtable">Show tableau</button>
    </div>
    <pre class="tk-out" id="vg-out"></pre>
    <div id="vg-extra" style="margin-top:14px;overflow-x:auto"></div>
    </div>

    <div class="tk-section">
    <h2 class="pg-h2">Breaking an unknown key: Kasiski examination</h2>
    <p class="muted">If you don't know the key, the first step is estimating its length.
      Kasiski examination finds repeated sequences of 3+ letters in the ciphertext -- if the
      same plaintext fragment happens to line up with the same part of the repeating key twice,
      it produces identical ciphertext fragments, and the distance between repeats is a
      multiple of the key length. The Friedman test (Index of Coincidence) gives a second,
      independent estimate from the same ciphertext.</p>
    <textarea class="tk-in" id="vg-crack-in" rows="4" placeholder="Paste ciphertext with an unknown Vigenere key..."></textarea>
    <div class="tk-btns">
      <button class="btn sm" id="vg-crack-run">Estimate key length</button>
      <button class="btn sm ghost" id="vg-crack-sample">Load sample (key length 4)</button>
    </div>
    <pre class="tk-out" id="vg-crack-out" style="min-height:280px"></pre>
    </div>
  `;

  const text = root.querySelector("#vg-text");
  const key = root.querySelector("#vg-key");
  const out = root.querySelector("#vg-out");
  const extra = root.querySelector("#vg-extra");

  root.querySelector("#vg-sample").onclick = () => { text.value = "ATTACKATDAWN"; key.value = "LEMON"; };
  root.querySelector("#vg-enc").onclick = () => run(false);
  root.querySelector("#vg-dec").onclick = () => run(true);
  root.querySelector("#vg-showsteps").onclick = () => showSteps();
  root.querySelector("#vg-showtable").onclick = () => { extra.innerHTML = buildVigenereTableau(); };

  let lastSteps = null;

  function run(decode) {
    try {
      const { result, steps, cleanKey } = vigenereProcess(text.value, key.value, decode);
      lastSteps = steps;
      out.textContent = `${decode ? "Decoded" : "Encoded"} with key "${cleanKey.toUpperCase()}":\n\n${result}`;
      extra.innerHTML = "";
    } catch (err) {
      out.textContent = "Error: " + err.message;
    }
  }

  function showSteps() {
    if (!lastSteps) { extra.innerHTML = '<p class="muted">Encode or decode something first.</p>'; return; }
    const rows = lastSteps.filter((s) => /[a-zA-Z]/.test(s.input)).map((s, i) =>
      `${String(i + 1).padStart(3, "0")}  plaintext '${s.input}'  +  key '${s.key}'  =  '${s.output}'`
    ).join("\n");
    extra.innerHTML = `<pre class="tk-out">${escapeHtml(rows)}</pre>`;
  }

  const crackIn = root.querySelector("#vg-crack-in");
  const crackOut = root.querySelector("#vg-crack-out");

  root.querySelector("#vg-crack-sample").onclick = () => {
    const plaintext = "WHENINTHECOURSEOFHUMANEVENTSITBECOMESNECESSARYFORONEPEOPLETODISSOLVETHEPOLITICALBANDSWHICHHAVECONNECTEDTHEMWITHANOTHER";
    crackIn.value = vigenereProcess(plaintext, "GOLD", false).result;
  };
  root.querySelector("#vg-crack-run").onclick = crackRun;

  function crackRun() {
    const cipherLetters = crackIn.value.toUpperCase().replace(/[^A-Z]/g, "");
    if (cipherLetters.length < 12) { crackOut.textContent = "Need at least a few dozen letters of ciphertext for a meaningful estimate."; return; }

    // --- Kasiski examination: find repeated 3-letter+ sequences and their distances ---
    const seqLen = 3;
    const positions = {};
    for (let i = 0; i + seqLen <= cipherLetters.length; i++) {
      const seq = cipherLetters.slice(i, i + seqLen);
      (positions[seq] = positions[seq] || []).push(i);
    }
    const distances = [];
    for (const seq of Object.keys(positions)) {
      const pos = positions[seq];
      if (pos.length < 2) continue;
      for (let i = 1; i < pos.length; i++) distances.push(pos[i] - pos[0]);
    }
    const factorCounts = {};
    for (const d of distances) {
      for (let f = 2; f <= 20; f++) {
        if (d % f === 0) factorCounts[f] = (factorCounts[f] || 0) + 1;
      }
    }
    const kasiskiRanked = Object.entries(factorCounts).sort((a, b) => b[1] - a[1]).slice(0, 8);

    // --- Friedman test: average IoC across candidate key lengths 1-20 ---
    const friedmanScores = [];
    for (let keyLen = 1; keyLen <= 20; keyLen++) {
      const columns = Array.from({ length: keyLen }, () => "");
      for (let i = 0; i < cipherLetters.length; i++) columns[i % keyLen] += cipherLetters[i];
      const avgIoc = columns.reduce((sum, col) => sum + indexOfCoincidence(col), 0) / keyLen;
      friedmanScores.push({ keyLen, avgIoc });
    }
    const bestFriedman = [...friedmanScores].sort((a, b) => Math.abs(b.avgIoc - 0.0665) - Math.abs(a.avgIoc - 0.0665)).reverse().slice(0, 5);

    crackOut.textContent =
`Ciphertext letters analyzed: ${cipherLetters.length}
Repeated 3-letter sequences found: ${Object.values(positions).filter((p) => p.length > 1).length}

=== Kasiski examination: candidate key lengths ranked by how often they
    evenly divide the distance between repeated sequences ===
${kasiskiRanked.map(([factor, count]) => `key length ${factor.padStart(2)}  -- divides ${count} of ${distances.length} repeat distances`).join("\n") || "(not enough repeats found in this ciphertext)"}

=== Friedman test: average Index of Coincidence per candidate key length ===
(closer to 0.0665 = more likely correct; a wrong key length averages
 several unrelated alphabets together and drags the IoC toward ~0.0385)
${friedmanScores.map((f) => `key length ${String(f.keyLen).padStart(2)}   avg IoC = ${f.avgIoc.toFixed(4)}`).join("\n")}

Most promising key lengths by Friedman test: ${bestFriedman.map((f) => f.keyLen).join(", ")}

Once a key length is chosen, split the ciphertext into that many
interleaved columns -- each column was encrypted with a single repeated
Caesar shift, so the Caesar Brute Force / Frequency Analysis tools can
solve each column independently to recover the key letter by letter.`;
  }
}

registerTab("vigenere", "Vigenere Cipher", renderVigenere);

// ---------------------------------------------------------------------------
// Tool 4: XOR Cipher
// ---------------------------------------------------------------------------
//
// XOR encryption repeats a key over the plaintext bytes and XORs each byte
// pair; XOR is its own inverse so the same operation both encrypts and
// decrypts. Single-byte XOR is trivially brute-forceable (only 256 keys) --
// we score all 256 candidates with englishScore() exactly like the Caesar
// tool. Multi-byte XOR with a short repeating key is the basis of the
// "repeating-key XOR" family of challenges seen constantly in CTFs.

function xorBytes(dataBytes, keyBytes) {
  if (keyBytes.length === 0) throw new Error("Key must not be empty");
  const out = new Uint8Array(dataBytes.length);
  for (let i = 0; i < dataBytes.length; i++) out[i] = dataBytes[i] ^ keyBytes[i % keyBytes.length];
  return out;
}

function renderXorCipher(root) {
  root.innerHTML = `
    <div class="tk-section">
    <h2 class="pg-h2">XOR Cipher</h2>
    <p class="muted">XOR each byte of the input against a repeating key. XOR is symmetric --
      the same operation encrypts and decrypts, so "Apply XOR" works both directions as long
      as you feed it the right input format. Includes a single-byte brute-force mode that
      tries all 256 possible key bytes and ranks the results by English-likeness.</p>

    <div class="tk-row">
      <textarea class="tk-in" id="xr-in" rows="4" placeholder="Input text (or hex bytes if 'Input is hex' is checked)" style="flex:2"></textarea>
      <div style="flex:1;display:flex;flex-direction:column;gap:8px">
        <input class="tk-f" id="xr-key" placeholder="Key (text) e.g. secret">
        <label class="muted mono" style="font-size:12px"><input type="checkbox" id="xr-keyhex"> Key is hex bytes</label>
        <label class="muted mono" style="font-size:12px"><input type="checkbox" id="xr-inhex"> Input is hex bytes</label>
      </div>
    </div>
    <div class="tk-btns">
      <button class="btn sm" id="xr-run">Apply XOR</button>
      <button class="btn sm ghost" id="xr-sample">Load sample</button>
    </div>
    <pre class="tk-out" id="xr-out"></pre>
    </div>

    <div class="tk-section">
    <h2 class="pg-h2">Single-byte XOR brute force</h2>
    <p class="muted">Paste hex-encoded ciphertext that you believe was XORed against a single
      repeating byte (0x00-0xFF). All 256 keys are tried and ranked by how English-like the
      result looks.</p>
    <textarea class="tk-in" id="xrb-in" rows="3" placeholder="Hex-encoded ciphertext, e.g. 1b373733 3f 03 3d 3d 3e ..."></textarea>
    <div class="tk-btns">
      <button class="btn sm" id="xrb-run">Brute force single-byte key</button>
      <button class="btn sm ghost" id="xrb-sample">Load sample</button>
    </div>
    <div id="xrb-best"></div>
    <pre class="tk-out" id="xrb-out" style="min-height:360px"></pre>
    </div>
  `;

  const inp = root.querySelector("#xr-in");
  const keyInp = root.querySelector("#xr-key");
  const keyHex = root.querySelector("#xr-keyhex");
  const inHex = root.querySelector("#xr-inhex");
  const out = root.querySelector("#xr-out");

  root.querySelector("#xr-sample").onclick = () => { inp.value = "Attack at dawn"; keyInp.value = "key"; keyHex.checked = false; inHex.checked = false; };
  root.querySelector("#xr-run").onclick = () => {
    try {
      const dataBytes = inHex.checked ? hexToBytes(inp.value) : textToBytes(inp.value);
      const keyBytes = keyHex.checked ? hexToBytes(keyInp.value) : textToBytes(keyInp.value);
      const result = xorBytes(dataBytes, keyBytes);
      const resultText = (() => { try { return bytesToText(result); } catch { return null; } })();
      out.textContent =
`Hex:    ${bytesToHex(result)}
Base64: ${bytesToBase64(result)}
Text:   ${resultText !== null && /^[\x09\x0A\x0D\x20-\x7E]*$/.test(resultText) ? resultText : "(not printable ASCII -- see hex/base64 above)"}`;
    } catch (err) {
      out.textContent = "Error: " + err.message;
    }
  };

  const bIn = root.querySelector("#xrb-in");
  const bBest = root.querySelector("#xrb-best");
  const bOut = root.querySelector("#xrb-out");

  root.querySelector("#xrb-sample").onclick = () => {
    const secret = textToBytes("The password is hunter2, meet at 2200 hours by the docks.");
    const key = 0x42;
    const cipher = secret.map((b) => b ^ key);
    bIn.value = bytesToHex(cipher);
  };

  root.querySelector("#xrb-run").onclick = () => {
    let data;
    try { data = hexToBytes(bIn.value); } catch (err) { bOut.textContent = "Error: " + err.message; return; }
    if (data.length === 0) { bOut.textContent = "Enter hex ciphertext first."; return; }

    const results = [];
    for (let k = 0; k < 256; k++) {
      const plain = data.map((b) => b ^ k);
      let text;
      try { text = bytesToText(plain); } catch { text = null; }
      if (text === null) { results.push({ key: k, text: "(invalid UTF-8)", rank: -Infinity }); continue; }
      const score = englishScore(text);
      const rank = score.chi - score.wordBonus * 25 + (1 - score.printableRatio) * 1000;
      results.push({ key: k, text, ...score, rank });
    }
    results.sort((a, b) => a.rank - b.rank);
    const winner = results[0];
    bBest.innerHTML = `<div class="card"><strong>Most likely key: 0x${winner.key.toString(16).padStart(2, "0")} (${winner.key})</strong>
      <div class="mono" style="margin-top:6px;white-space:pre-wrap">${escapeHtml(winner.text)}</div></div>`;
    bOut.textContent = results.slice(0, 40).map((r) =>
      `key 0x${r.key.toString(16).padStart(2, "0")} (${String(r.key).padStart(3)})  rank=${r.rank === -Infinity ? "n/a" : r.rank.toFixed(1)}  ${r.text}`
    ).join("\n") + `\n\n... showing top 40 of 256 keys ranked by English-likeness ...`;
  };

  // --- Repeating-key XOR break (the classic "Cryptopals challenge 6" approach) ---
  // 1. Guess the key length by finding the size that minimizes the average
  //    normalized Hamming distance between consecutive blocks -- English
  //    text XORed with a repeating key produces blocks that are more
  //    "similar" (lower Hamming distance) at the true key length than at a
  //    wrong one, because at the true length every block was XORed with
  //    the exact same key bytes.
  // 2. Once a key length is guessed, transpose the ciphertext into that
  //    many interleaved column byte-arrays -- each column was XORed with a
  //    single repeated byte, so the single-byte brute forcer above solves
  //    each column independently, recovering the key one byte at a time.
  const rkSection = document.createElement("div");
  rkSection.className = "tk-section";
  rkSection.innerHTML = `
    <h2 class="pg-h2">Repeating-key XOR break</h2>
    <p class="muted">For ciphertext XORed against a repeating multi-byte key of unknown length:
      estimate the key length via normalized Hamming distance between blocks, then solve each
      resulting column as an independent single-byte XOR.</p>
    <textarea class="tk-in" id="rk-in" rows="4" placeholder="Hex-encoded ciphertext, repeating-key XOR..."></textarea>
    <div class="tk-btns">
      <button class="btn sm" id="rk-run">Break repeating-key XOR</button>
      <button class="btn sm ghost" id="rk-sample">Load sample (key length 5)</button>
    </div>
    <pre class="tk-out" id="rk-out" style="min-height:300px"></pre>
  `;
  root.appendChild(rkSection);

  const rkIn = rkSection.querySelector("#rk-in");
  const rkOut = rkSection.querySelector("#rk-out");

  rkSection.querySelector("#rk-sample").onclick = () => {
    const secret = textToBytes(
      "Burning down the highway skyline, on the back of a hurricane that started turning. "
      + "Whitest snow, we said we'd fall together, twisted up like branches in the weather. "
      + "This is the code that breaks repeating key exclusive or, one column at a time.");
    const key = textToBytes("light");
    rkIn.value = bytesToHex(xorBytes(secret, key));
  };

  rkSection.querySelector("#rk-run").onclick = () => {
    let data;
    try { data = hexToBytes(rkIn.value); } catch (err) { rkOut.textContent = "Error: " + err.message; return; }
    if (data.length < 40) { rkOut.textContent = "Need more ciphertext (at least a few dozen bytes) for reliable key-length detection."; return; }

    function hammingDistance(a, b) {
      let dist = 0;
      for (let i = 0; i < a.length; i++) {
        let x = a[i] ^ b[i];
        while (x) { dist += x & 1; x >>= 1; }
      }
      return dist;
    }

    const candidates = [];
    for (let keysize = 2; keysize <= Math.min(40, Math.floor(data.length / 4)); keysize++) {
      const blocks = [];
      for (let i = 0; i + keysize <= data.length && blocks.length < 6; i += keysize) blocks.push(data.slice(i, i + keysize));
      if (blocks.length < 2) continue;
      let totalDist = 0, pairs = 0;
      for (let i = 0; i < blocks.length - 1; i++) {
        totalDist += hammingDistance(blocks[i], blocks[i + 1]);
        pairs++;
      }
      const normalized = (totalDist / pairs) / keysize;
      candidates.push({ keysize, normalized });
    }
    candidates.sort((a, b) => a.normalized - b.normalized);
    const bestGuess = candidates[0].keysize;

    // Solve each column of the best-guess key length as single-byte XOR.
    function solveColumn(bytes) {
      let best = { key: 0, rank: Infinity, text: "" };
      for (let k = 0; k < 256; k++) {
        const plain = bytes.map((b) => b ^ k);
        let text;
        try { text = bytesToText(plain); } catch { continue; }
        const score = englishScore(text);
        const rank = score.chi - score.wordBonus * 25 + (1 - score.printableRatio) * 1000;
        if (rank < best.rank) best = { key: k, rank, text };
      }
      return best;
    }

    const columns = Array.from({ length: bestGuess }, () => []);
    for (let i = 0; i < data.length; i++) columns[i % bestGuess].push(data[i]);
    const recoveredKeyBytes = columns.map((col) => solveColumn(col).key);
    const recoveredKey = recoveredKeyBytes.map((b) => String.fromCharCode(b)).join("");
    const decrypted = xorBytes(data, new Uint8Array(recoveredKeyBytes));
    let decryptedText;
    try { decryptedText = bytesToText(decrypted); } catch { decryptedText = null; }

    rkOut.textContent =
`=== Step 1: key length candidates (lower normalized Hamming distance = better) ===
${candidates.slice(0, 8).map((c) => `keysize ${String(c.keysize).padStart(2)}   normalized distance = ${c.normalized.toFixed(4)}`).join("\n")}

Best guess: key length ${bestGuess}

=== Step 2: solve each of the ${bestGuess} columns as single-byte XOR ===
Recovered key bytes (hex): ${recoveredKeyBytes.map((b) => b.toString(16).padStart(2, "0")).join(" ")}
Recovered key (as text):   ${/^[\x20-\x7E]*$/.test(recoveredKey) ? recoveredKey : "(non-printable -- see hex above)"}

=== Decrypted plaintext ===
${decryptedText !== null ? decryptedText : "(decryption did not produce valid UTF-8 -- key length guess may be wrong)"}`;
  };
}

registerTab("xor", "XOR Cipher", renderXorCipher);

// ---------------------------------------------------------------------------
// Tool 5: Substitution Cipher Helper
// ---------------------------------------------------------------------------
//
// A general monoalphabetic substitution cipher maps each plaintext letter
// to a fixed different letter. Unlike Caesar it can't be brute-forced (26!
// possible keys), so cryptanalysts break it interactively: build a
// frequency table of the ciphertext, guess likely mappings for the most
// common ciphertext letters (E, T, A, O, ... in English), apply the partial
// key, and iterate. This tool automates the bookkeeping: you supply partial
// letter mappings, it shows you the partially-decoded text plus frequency-
// based suggestions for letters you haven't mapped yet.

// Reduces a word to its repeated-letter "shape", e.g. LETTER -> ABCCBD
// (positions 2 and 5 share a letter; positions 3 and 4 share a letter).
// Classic cryptogram-solving technique: this shape survives any monoalphabetic
// substitution unchanged, so matching ciphertext word shapes against a
// dictionary of common word shapes narrows candidates before any letters
// are mapped at all.
function wordPattern(word) {
  const seen = {};
  let next = 65; // 'A'
  let pattern = "";
  for (const ch of word.toUpperCase()) {
    if (!(ch in seen)) seen[ch] = String.fromCharCode(next++);
    pattern += seen[ch];
  }
  return pattern;
}

// A modest dictionary of common English words (length 3-8) used purely for
// pattern-shape matching in the Substitution Helper's "Find word patterns"
// feature -- deliberately small and curated toward high-frequency words so
// suggestions stay genuinely useful rather than an overwhelming list.
const PATTERN_DICTIONARY_WORDS = [
  "the","and","for","are","but","not","you","all","any","can","had","her","was","one",
  "our","out","day","get","has","him","his","how","man","new","now","old","see","two",
  "way","who","boy","did","its","let","put","say","she","too","use","dad","mom","yes",
  "big","dog","cat","sun","run","fun","cup","top","hot","red","bed","bad","sad","yet",
  "with","have","this","will","your","from","they","know","want","been","good","much",
  "some","time","very","when","come","here","just","like","long","make","many","over",
  "such","take","than","them","well","were","that","what","each","she","which","their",
  "said","each","tell","does","set","three","water","been","call","who","oil","its",
  "now","find","down","day","did","get","come","made","may","part","people","water",
  "little","world","school","never","seven","begin","between","children","example",
  "follow","important","letter","mother","picture","really","sentence","should",
  "though","together","another","because","different","enough","families","friends",
  "government","interest","morning","perhaps","picture","problem","question","several",
  "special","without","america","between","business","children","company","country",
  "example","general","however","million","nothing","numbers","officer","paragraph",
  "process","program","project","science","strange","student","subject","suppose",
  "thought","through","understand","therefore","yesterday","yellow","kitten","letter",
  "coffee","little","summer","dinner","common","happen","effect","mirror","success",
  "address","meeting","message","possess","balloon","bottle","cannon","channel",
];

const PATTERN_DICTIONARY = (() => {
  const dict = {};
  for (const word of PATTERN_DICTIONARY_WORDS) {
    const pattern = wordPattern(word);
    if (!dict[pattern]) dict[pattern] = [];
    if (!dict[pattern].includes(word.toUpperCase())) dict[pattern].push(word.toUpperCase());
  }
  return dict;
})();

function renderSubstitution(root) {
  root.innerHTML = `
    <div class="tk-section">
    <h2 class="pg-h2">Substitution Cipher Helper</h2>
    <p class="muted">General monoalphabetic substitution ciphers can't be brute-forced (26!
      possible keys) so they're broken interactively: guess a mapping for the most frequent
      ciphertext letters, apply it, read the partial plaintext, refine, repeat. Enter
      ciphertext and any letter mappings you've guessed so far (format: <code>A=E, B=T</code>
      one per line or comma separated).</p>
    <div class="tk-row">
      <textarea class="tk-in" id="sb-cipher" rows="6" placeholder="Ciphertext..." style="flex:2"></textarea>
      <textarea class="tk-in" id="sb-map" rows="6" placeholder="Known mappings, e.g.&#10;A=E&#10;B=T&#10;X=A" style="flex:1"></textarea>
    </div>
    <div class="tk-btns">
      <button class="btn sm" id="sb-run">Apply mapping</button>
      <button class="btn sm ghost" id="sb-suggest">Suggest mappings from frequency</button>
      <button class="btn sm ghost" id="sb-patterns">Find word patterns</button>
      <button class="btn sm ghost" id="sb-sample">Load sample</button>
      <button class="btn sm ghost" id="sb-reset">Clear mappings</button>
    </div>
    <pre class="tk-out" id="sb-decoded"></pre>
    <div id="sb-freq" style="margin-top:14px"></div>
    <div id="sb-patterns-out" style="margin-top:14px"></div>
    </div>
  `;

  const cipherInp = root.querySelector("#sb-cipher");
  const mapInp = root.querySelector("#sb-map");
  const decodedOut = root.querySelector("#sb-decoded");
  const freqOut = root.querySelector("#sb-freq");

  root.querySelector("#sb-sample").onclick = () => {
    // "the quick brown fox" enciphered with a fixed random substitution key
    const key = { a:"q", b:"w", c:"e", d:"r", e:"t", f:"y", g:"u", h:"i", i:"o", j:"p",
      k:"a", l:"s", m:"d", n:"f", o:"g", p:"h", q:"j", r:"k", s:"l", t:"z",
      u:"x", v:"c", w:"v", x:"b", y:"n", z:"m" };
    const plain = "the quick brown fox jumps over the lazy dog and runs into the forest";
    cipherInp.value = plain.replace(/[a-z]/g, (c) => key[c]).toUpperCase();
    mapInp.value = "Z=T\nQ=A";
    run();
  };
  root.querySelector("#sb-reset").onclick = () => { mapInp.value = ""; };
  root.querySelector("#sb-run").onclick = run;
  root.querySelector("#sb-suggest").onclick = suggest;
  root.querySelector("#sb-patterns").onclick = findPatterns;

  function parseMap(str) {
    const map = {};
    const pairs = str.split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
    for (const p of pairs) {
      const m = p.match(/^([a-zA-Z])\s*=\s*([a-zA-Z])$/);
      if (!m) continue;
      map[m[1].toLowerCase()] = m[2].toLowerCase();
    }
    return map;
  }

  function run() {
    const cipher = cipherInp.value;
    if (!cipher.trim()) { decodedOut.textContent = "Enter ciphertext first."; return; }
    const map = parseMap(mapInp.value);
    const mappedCount = Object.keys(map).length;

    const decoded = cipher.replace(/[a-zA-Z]/g, (c) => {
      const lower = c.toLowerCase();
      const mapped = map[lower];
      if (!mapped) return c === c.toUpperCase() ? "_" : "_";
      return c === c.toUpperCase() ? mapped.toUpperCase() : mapped;
    });

    decodedOut.textContent =
`Mapped ${mappedCount} of 26 letters (cipher-letter = plaintext-letter).
Unmapped ciphertext letters are shown as "_".

${decoded}`;

    renderFrequencyTable(cipher, map);
  }

  function suggest() {
    const cipher = cipherInp.value;
    if (!cipher.trim()) { freqOut.innerHTML = '<p class="muted">Enter ciphertext first.</p>'; return; }
    const { counts, total } = letterCounts(cipher);
    if (total === 0) { freqOut.innerHTML = '<p class="muted">No letters found.</p>'; return; }

    const cipherSorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([l]) => l);
    const englishSorted = Object.entries(ENGLISH_FREQ).sort((a, b) => b[1] - a[1]).map(([l]) => l);

    const map = parseMap(mapInp.value);
    const suggestions = cipherSorted.filter((l) => counts[l] > 0 && !map[l])
      .map((cl, i) => `${cl.toUpperCase()} (rank ${i + 1} in this text, count ${counts[cl]}) probably maps to '${englishSorted[i] ? englishSorted[i].toUpperCase() : "?"}' (rank ${i + 1} in English)`);

    freqOut.innerHTML = `<div class="card">
      <strong>Frequency-based suggestions</strong>
      <p class="muted" style="margin:6px 0">These are naive rank-order guesses (most frequent
      ciphertext letter maps to the most frequent English letter, and so on). Real cryptanalysis
      also uses common-word patterns, doubled letters, and word boundaries to refine this --
      treat these as a starting point, not the answer.</p>
      <pre class="tk-out mono" style="white-space:pre-wrap">${escapeHtml(suggestions.join("\n"))}</pre>
    </div>`;
  }

  function findPatterns() {
    const cipher = cipherInp.value;
    if (!cipher.trim()) { root.querySelector("#sb-patterns-out").innerHTML = '<p class="muted">Enter ciphertext first.</p>'; return; }
    const words = cipher.toUpperCase().match(/[A-Z]+/g) || [];
    const oneLetterWords = [...new Set(words.filter((w) => w.length === 1))];
    const twoLetterWords = [...new Set(words.filter((w) => w.length === 2))];
    const doubleLetterWords = [...new Set(words.filter((w) => /(.)\1/.test(w)))];

    const patternMatches = [];
    for (const w of [...new Set(words.filter((w) => w.length >= 3 && w.length <= 8))]) {
      const pattern = wordPattern(w);
      const candidates = PATTERN_DICTIONARY[pattern] || [];
      if (candidates.length) patternMatches.push({ word: w, pattern, candidates });
    }

    const lines = [];
    lines.push("=== One-letter words ===");
    lines.push(oneLetterWords.length
      ? `Found: ${oneLetterWords.join(", ")}\nIn English almost every one-letter word is "A" or "I" -- these are strong, nearly certain mapping candidates.`
      : "None found.");
    lines.push("");
    lines.push("=== Two-letter words ===");
    lines.push(twoLetterWords.length
      ? `Found: ${twoLetterWords.join(", ")}\nMost common English two-letter words: OF, TO, IN, IT, IS, BE, AS, AT, SO, WE, HE, BY, OR, ON, DO, IF, ME, MY, UP, AN, GO, NO, US, AM.`
      : "None found.");
    lines.push("");
    lines.push("=== Words with doubled letters ===");
    lines.push(doubleLetterWords.length
      ? `Found: ${doubleLetterWords.join(", ")}\nEnglish doubled letters are overwhelmingly LL, EE, SS, OO, TT, FF, RR, MM, PP, or CC (roughly in that order of frequency) -- narrows the mapping for whichever ciphertext letter appears doubled.`
      : "None found.");
    lines.push("");
    lines.push("=== Pattern dictionary matches ===");
    lines.push("A word's \"pattern\" records which letter positions repeat, ignoring which");
    lines.push("actual letters are used -- e.g. LETTER has pattern ABCCBD (positions 2 and 5");
    lines.push("share a letter, positions 3 and 4 share a letter). Matching that pattern");
    lines.push("against a dictionary of common words narrows down candidates dramatically,");
    lines.push("even with zero letters mapped yet.");
    lines.push("");
    if (patternMatches.length) {
      for (const m of patternMatches) {
        lines.push(`${m.word}  (pattern ${m.pattern})  possible words: ${m.candidates.join(", ")}`);
      }
    } else {
      lines.push("No matches against the built-in common-word pattern dictionary for this ciphertext's word lengths.");
    }

    root.querySelector("#sb-patterns-out").innerHTML = `<pre class="tk-out" style="min-height:200px">${escapeHtml(lines.join("\n"))}</pre>`;
  }

  function renderFrequencyTable(cipher, map) {
    const { counts, total } = letterCounts(cipher);
    if (total === 0) return;
    const rows = Object.entries(counts).sort((a, b) => b[1] - a[1])
      .filter(([, c]) => c > 0)
      .map(([l, c]) => `${l.toUpperCase()}${map[l] ? ` -> ${map[l].toUpperCase()}` : "     "}  count=${String(c).padStart(3)}  (${((c / total) * 100).toFixed(1)}%)`)
      .join("\n");
    freqOut.innerHTML = `<pre class="tk-out">${escapeHtml(rows)}</pre>`;
  }
}

registerTab("substitution", "Substitution Helper", renderSubstitution);

// ---------------------------------------------------------------------------
// Tool 6: RSA Calculator
// ---------------------------------------------------------------------------
//
// A from-scratch, fully worked implementation of textbook RSA using BigInt.
// Given two small primes p and q we compute n = p*q, phi(n) = (p-1)(q-1),
// find a valid public exponent e (coprime to phi(n)), derive the private
// exponent d as the modular inverse of e mod phi(n) via the extended
// Euclidean algorithm, and then let the user encrypt/decrypt a small
// integer message m < n using modular exponentiation. This is "textbook"
// RSA for teaching purposes only -- real RSA needs padding (OAEP), much
// larger primes, and careful side-channel-resistant implementations.

function renderRSA(root) {
  root.innerHTML = `
    <div class="tk-section">
    <h2 class="pg-h2">RSA Calculator</h2>
    <p class="muted">Textbook RSA, worked by hand with BigInt so nothing is hidden behind a
      library call. Enter two <em>distinct prime</em> numbers p and q (keep them small --
      under a few thousand -- so the numbers stay readable; this is for learning the math,
      not real security). Every step of key generation is shown, then you can encrypt and
      decrypt a small integer message.</p>
    <div class="tk-row">
      <input class="tk-f" id="rsa-p" placeholder="Prime p, e.g. 61">
      <input class="tk-f" id="rsa-q" placeholder="Prime q, e.g. 53">
      <input class="tk-f" id="rsa-e" placeholder="Public exponent e (optional, auto-picked if blank)">
    </div>
    <div class="tk-btns">
      <button class="btn sm" id="rsa-gen">Generate key pair</button>
      <button class="btn sm ghost" id="rsa-sample">Load classic textbook example (p=61, q=53, e=17)</button>
      <button class="btn sm ghost" id="rsa-random">Generate random small primes</button>
    </div>
    <pre class="tk-out" id="rsa-keys" style="min-height:200px"></pre>
    </div>

    <div class="tk-section">
    <h2 class="pg-h2">Encrypt / decrypt a message</h2>
    <p class="muted">Message must be an integer 0 &le; m &lt; n. To encrypt text, convert it to
      a number first (e.g. via the ASCII/Base tools) -- textbook RSA without padding can only
      safely handle a single small block.</p>
    <div class="tk-row">
      <input class="tk-f" id="rsa-msg" placeholder="Message integer m, or ciphertext integer c">
    </div>
    <div class="tk-btns">
      <button class="btn sm" id="rsa-enc">Encrypt (m^e mod n)</button>
      <button class="btn sm" id="rsa-dec">Decrypt (c^d mod n)</button>
    </div>
    <pre class="tk-out" id="rsa-result"></pre>
    </div>

    <div class="tk-section">
    <h2 class="pg-h2">Attack demo: Fermat factorization</h2>
    <p class="muted">RSA's security rests entirely on n = p*q being hard to factor. If p and q
      are chosen too close together, Fermat's factorization method cracks n almost instantly:
      write n = a^2 - b^2 = (a-b)(a+b) and search a = ceil(sqrt(n)), a+1, a+2, ... testing whether
      a^2 - n is a perfect square. This is exactly why real key generation rejects primes that
      are close to each other.</p>
    <div class="tk-row">
      <input class="tk-f" id="rsa-fermat-n" placeholder="n to factor, e.g. 8383489">
    </div>
    <div class="tk-btns">
      <button class="btn sm" id="rsa-fermat-run">Attempt Fermat factorization</button>
      <button class="btn sm ghost" id="rsa-fermat-sample">Load vulnerable example (close primes)</button>
    </div>
    <pre class="tk-out" id="rsa-fermat-out"></pre>
    </div>
  `;

  const pInp = root.querySelector("#rsa-p"), qInp = root.querySelector("#rsa-q"), eInp = root.querySelector("#rsa-e");
  const keysOut = root.querySelector("#rsa-keys");
  const msgInp = root.querySelector("#rsa-msg");
  const resultOut = root.querySelector("#rsa-result");

  let keys = null; // { p, q, n, phi, e, d }

  root.querySelector("#rsa-sample").onclick = () => { pInp.value = "61"; qInp.value = "53"; eInp.value = "17"; generate(); };
  root.querySelector("#rsa-random").onclick = () => {
    const primesUnder1000 = smallPrimesUpTo(2000).filter((p) => p > 100);
    const p = primesUnder1000[Math.floor(Math.random() * primesUnder1000.length)];
    let q = primesUnder1000[Math.floor(Math.random() * primesUnder1000.length)];
    while (q === p) q = primesUnder1000[Math.floor(Math.random() * primesUnder1000.length)];
    pInp.value = p; qInp.value = q; eInp.value = "";
    generate();
  };
  root.querySelector("#rsa-gen").onclick = generate;
  root.querySelector("#rsa-enc").onclick = () => operate(true);
  root.querySelector("#rsa-dec").onclick = () => operate(false);

  function smallPrimesUpTo(limit) {
    const sieve = new Uint8Array(limit + 1);
    const primes = [];
    for (let i = 2; i <= limit; i++) {
      if (!sieve[i]) {
        primes.push(i);
        for (let j = i * i; j <= limit; j += i) sieve[j] = 1;
      }
    }
    return primes;
  }

  function findValidE(phi) {
    // Prefer the conventional 65537 or 17 if they're coprime to phi; else
    // scan upward from 3 for the first valid odd candidate.
    for (const candidate of [65537n, 17n, 257n]) {
      if (candidate < phi && gcdBig(candidate, phi) === 1n) return candidate;
    }
    for (let e = 3n; e < phi; e += 2n) {
      if (gcdBig(e, phi) === 1n) return e;
    }
    throw new Error("Could not find a valid public exponent e");
  }

  function generate() {
    try {
      const p = BigInt(pInp.value.trim());
      const q = BigInt(qInp.value.trim());
      if (p <= 1n || q <= 1n) throw new Error("p and q must be greater than 1");
      if (p === q) throw new Error("p and q must be distinct primes");
      if (!isProbablePrime(p)) throw new Error(`${p} is not prime`);
      if (!isProbablePrime(q)) throw new Error(`${q} is not prime`);

      const n = p * q;
      const phi = (p - 1n) * (q - 1n);

      let e;
      if (eInp.value.trim()) {
        e = BigInt(eInp.value.trim());
        if (e <= 1n || e >= phi) throw new Error(`e must satisfy 1 < e < phi(n) = ${phi}`);
        if (gcdBig(e, phi) !== 1n) throw new Error(`e=${e} is not coprime to phi(n)=${phi}; gcd(e, phi) = ${gcdBig(e, phi)}`);
      } else {
        e = findValidE(phi);
      }

      const d = modInverse(e, phi);
      if (d === null) throw new Error("No modular inverse exists for the chosen e -- pick a different e");

      keys = { p, q, n, phi, e, d };

      keysOut.textContent =
`STEP 1 -- Choose two distinct primes
  p = ${p}
  q = ${q}
  (both verified prime via Miller-Rabin)

STEP 2 -- Compute the modulus n = p * q
  n = ${p} * ${q} = ${n}
  n has ${n.toString(2).length} bits (~${Math.round(n.toString(2).length * Math.log10(2) * 10) / 10} decimal digits)

STEP 3 -- Compute Euler's totient phi(n) = (p-1)(q-1)
  phi(n) = (${p} - 1) * (${q} - 1) = ${p - 1n} * ${q - 1n} = ${phi}
  (phi(n) counts integers < n that are coprime to n -- this is what makes
   modular exponentiation cycle back to the original message)

STEP 4 -- Choose public exponent e
  e must satisfy 1 < e < phi(n) and gcd(e, phi(n)) = 1
  e = ${e}  (gcd(e, phi(n)) = ${gcdBig(e, phi)})

STEP 5 -- Compute private exponent d = e^-1 mod phi(n)
  Solved via the extended Euclidean algorithm: find d such that
  (e * d) mod phi(n) = 1
  d = ${d}
  check: (${e} * ${d}) mod ${phi} = ${(e * d) % phi}

=== KEY PAIR ===
  Public key  (e, n) = (${e}, ${n})
  Private key (d, n) = (${d}, ${n})

Anyone can encrypt with the public key (e, n). Only the holder of the
private key (d, n) can decrypt.`;
      resultOut.textContent = "";
    } catch (err) {
      keysOut.textContent = "Error: " + err.message;
      keys = null;
    }
  }

  function operate(encrypt) {
    if (!keys) { resultOut.textContent = "Generate a key pair first."; return; }
    try {
      const m = BigInt(msgInp.value.trim());
      if (encrypt) {
        if (m < 0n || m >= keys.n) throw new Error(`Message must satisfy 0 <= m < n (n=${keys.n})`);
        const c = modPow(m, keys.e, keys.n);
        resultOut.textContent =
`ENCRYPT: c = m^e mod n
  c = ${m}^${keys.e} mod ${keys.n}
  c = ${c}

(computed via fast modular exponentiation -- square-and-multiply --
 so this works even when e and n are very large)`;
      } else {
        if (m < 0n || m >= keys.n) throw new Error(`Ciphertext must satisfy 0 <= c < n (n=${keys.n})`);
        const p2 = modPow(m, keys.d, keys.n);
        resultOut.textContent =
`DECRYPT: m = c^d mod n
  m = ${m}^${keys.d} mod ${keys.n}
  m = ${p2}`;
      }
    } catch (err) {
      resultOut.textContent = "Error: " + err.message;
    }
  }

  const fermatN = root.querySelector("#rsa-fermat-n");
  const fermatOut = root.querySelector("#rsa-fermat-out");

  root.querySelector("#rsa-fermat-sample").onclick = () => {
    // Two primes deliberately chosen close together (within a few hundred
    // of each other) so Fermat's method finds them almost instantly.
    const p = 2963n, q = 3001n; // both prime, |p - q| is tiny relative to n
    fermatN.value = (p * q).toString();
  };

  root.querySelector("#rsa-fermat-run").onclick = () => {
    try {
      const n = BigInt(fermatN.value.trim());
      if (n <= 3n) throw new Error("Enter a composite n greater than 3");
      if (n % 2n === 0n) { fermatOut.textContent = `n is even -- trivially factors as 2 x ${n / 2n}. Fermat's method assumes an odd n (product of two odd primes).`; return; }

      let a = bigSqrt(n);
      if (a * a < n) a += 1n;
      const maxIterations = 200000n;
      let iterations = 0n;
      let found = null;
      while (iterations < maxIterations) {
        const bSquared = a * a - n;
        const b = bigSqrt(bSquared);
        if (b * b === bSquared) { found = { a, b }; break; }
        a += 1n;
        iterations += 1n;
      }

      if (!found) {
        fermatOut.textContent =
`No factorization found within ${maxIterations} iterations.
This means p and q are NOT close together -- Fermat's method only works
efficiently when |p - q| is small relative to n. This is actually the
expected (good) outcome for properly generated RSA keys, where p and q
are chosen independently at random from a huge prime space and are
therefore overwhelmingly unlikely to be anywhere near each other.`;
        return;
      }

      const { a: aFound, b: bFound } = found;
      const factor1 = aFound - bFound;
      const factor2 = aFound + bFound;
      const bothPrime = isProbablePrime(factor1) && isProbablePrime(factor2);

      fermatOut.textContent =
`n = ${n}

Searching for a such that a^2 - n is a perfect square, starting from
a = ceil(sqrt(n)) = ${bigSqrt(n) * bigSqrt(n) < n ? bigSqrt(n) + 1n : bigSqrt(n)}...

Found after ${iterations} step(s):
  a = ${aFound}
  b = sqrt(a^2 - n) = ${bFound}

n = a^2 - b^2 = (a - b)(a + b)
  p = a - b = ${factor1}
  q = a + b = ${factor2}

Verify: p * q = ${factor1 * factor2}  (should equal n)
Both factors prime: ${bothPrime ? "yes -- n is fully factored" : "no -- one factor is composite, would need further factoring"}

Because n is now factored, phi(n) = (p-1)(q-1) can be computed directly and
the private exponent d recovered -- the entire RSA private key falls out
from a factorization that took ${iterations} simple integer steps, purely
because p and q were too close together.`;
    } catch (err) {
      fermatOut.textContent = "Error: " + err.message;
    }
  };
}

registerTab("rsa", "RSA Calculator", renderRSA);

// ---------------------------------------------------------------------------
// Tool 7: Diffie-Hellman Key Exchange Calculator
// ---------------------------------------------------------------------------
//
// Diffie-Hellman lets two parties agree on a shared secret over a public
// channel without ever transmitting the secret itself. Both sides agree on
// a public prime p and generator g. Each picks a private key (a and b),
// computes a public value (g^a mod p and g^b mod p) and exchanges those
// public values. Each side then raises the *other* side's public value to
// their own private exponent -- both arrive at the same shared secret
// because (g^a)^b = (g^b)^a = g^(ab) mod p.

function renderDH(root) {
  root.innerHTML = `
    <div class="tk-section">
    <h2 class="pg-h2">Diffie-Hellman Key Exchange</h2>
    <p class="muted">Alice and Bob want to agree on a shared secret over a channel an
      eavesdropper can see. They publicly agree on a prime p and a generator g, then each
      picks a private key. Only their public values ever cross the wire -- the shared secret
      itself is never transmitted, yet both sides compute the same value.</p>
    <div class="tk-row">
      <input class="tk-f" id="dh-p" placeholder="Prime p, e.g. 23">
      <input class="tk-f" id="dh-g" placeholder="Generator g, e.g. 5">
    </div>
    <div class="tk-row">
      <input class="tk-f" id="dh-a" placeholder="Alice's private key a, e.g. 6">
      <input class="tk-f" id="dh-b" placeholder="Bob's private key b, e.g. 15">
    </div>
    <div class="tk-btns">
      <button class="btn sm" id="dh-run">Run key exchange</button>
      <button class="btn sm ghost" id="dh-sample">Load classic example (p=23, g=5, a=6, b=15)</button>
    </div>
    <pre class="tk-out" id="dh-out" style="min-height:400px"></pre>
    </div>

    <div class="tk-section">
    <h2 class="pg-h2">Why authentication matters: a man-in-the-middle demo</h2>
    <p class="muted">Plain Diffie-Hellman protects the exchange from a passive eavesdropper, but
      on its own it does nothing to prove who you're actually talking to. If an active attacker
      (Eve) can intercept and replace messages in transit, she can run <em>two separate</em> key
      exchanges -- one with Alice, one with Bob -- and neither victim can tell. This is exactly
      why real protocols (TLS, Signal, SSH) always layer DH underneath a signature or
      pre-shared authentication step.</p>
    <div class="tk-btns">
      <button class="btn sm" id="dh-mitm-run">Simulate the MITM attack (using the values above)</button>
    </div>
    <pre class="tk-out" id="dh-mitm-out" style="min-height:300px"></pre>
    </div>
  `;

  const pInp = root.querySelector("#dh-p"), gInp = root.querySelector("#dh-g");
  const aInp = root.querySelector("#dh-a"), bInp = root.querySelector("#dh-b");
  const out = root.querySelector("#dh-out");

  root.querySelector("#dh-sample").onclick = () => { pInp.value = "23"; gInp.value = "5"; aInp.value = "6"; bInp.value = "15"; run(); };
  root.querySelector("#dh-run").onclick = run;

  function run() {
    try {
      const p = BigInt(pInp.value.trim());
      const g = BigInt(gInp.value.trim());
      const a = BigInt(aInp.value.trim());
      const b = BigInt(bInp.value.trim());
      if (p <= 2n) throw new Error("p should be a prime greater than 2");
      if (!isProbablePrime(p)) throw new Error(`${p} does not appear to be prime -- Diffie-Hellman requires a prime modulus`);
      if (g <= 1n || g >= p) throw new Error("g should satisfy 1 < g < p");
      if (a <= 0n || b <= 0n) throw new Error("Private keys should be positive integers");

      const A = modPow(g, a, p); // Alice's public value
      const B = modPow(g, b, p); // Bob's public value
      const secretFromAlice = modPow(B, a, p); // Alice computes B^a mod p
      const secretFromBob = modPow(A, b, p);   // Bob computes A^b mod p
      const match = secretFromAlice === secretFromBob;

      out.textContent =
`PUBLIC PARAMETERS (known to everyone, including an eavesdropper)
  p (prime modulus) = ${p}
  g (generator)      = ${g}

STEP 1 -- Alice picks a private key and computes her public value
  Alice's private key: a = ${a}  (kept secret)
  Alice's public value: A = g^a mod p = ${g}^${a} mod ${p} = ${A}
  Alice sends A = ${A} to Bob over the public channel.

STEP 2 -- Bob picks a private key and computes his public value
  Bob's private key: b = ${b}  (kept secret)
  Bob's public value: B = g^b mod p = ${g}^${b} mod ${p} = ${B}
  Bob sends B = ${B} to Alice over the public channel.

STEP 3 -- Each side computes the shared secret from the other's public value
  Alice computes: s = B^a mod p = ${B}^${a} mod ${p} = ${secretFromAlice}
  Bob computes:   s = A^b mod p = ${A}^${b} mod ${p} = ${secretFromBob}

  Why they match: B^a = (g^b)^a = g^(ab) mod p, and A^b = (g^a)^b = g^(ab) mod p.
  Both sides raise a value to a power and land on the same g^(ab) mod p,
  without either ever transmitting a, b, or the secret itself.

RESULT
  Shared secret: ${secretFromAlice}
  Secrets match: ${match ? "YES -- key exchange successful" : "NO -- check your inputs"}

WHAT AN EAVESDROPPER SEES: p=${p}, g=${g}, A=${A}, B=${B}
  Recovering a from A = g^a mod p is the discrete logarithm problem --
  believed computationally hard for a well-chosen large prime p, which is
  what makes this exchange secure in practice (with p hundreds of digits
  long, not the small teaching example used here).`;
    } catch (err) {
      out.textContent = "Error: " + err.message;
    }
  }

  const mitmOut = root.querySelector("#dh-mitm-out");

  root.querySelector("#dh-mitm-run").onclick = () => {
    try {
      const p = BigInt(pInp.value.trim());
      const g = BigInt(gInp.value.trim());
      const a = BigInt(aInp.value.trim());
      const b = BigInt(bInp.value.trim());
      if (!isProbablePrime(p)) throw new Error(`${p} does not appear to be prime`);

      // Eve picks her own two private keys -- one for the "Alice side" of
      // the conversation, one for the "Bob side".
      const e1 = (a * 7n + 3n) % (p - 2n) + 2n; // deterministic "random-looking" choice for reproducibility
      const e2 = (b * 11n + 5n) % (p - 2n) + 2n;

      const A = modPow(g, a, p);       // Alice's real public value, sent toward Bob
      const B = modPow(g, b, p);       // Bob's real public value, sent toward Alice
      const E1 = modPow(g, e1, p);     // Eve's public value, presented to Alice as if it were Bob's
      const E2 = modPow(g, e2, p);     // Eve's public value, presented to Bob as if it were Alice's

      // Alice thinks she's completing an exchange with Bob, but she actually
      // receives E1 (Eve's value) instead of B.
      const aliceSecret = modPow(E1, a, p);   // Alice computes E1^a mod p
      const eveSecretWithAlice = modPow(A, e1, p); // Eve computes A^e1 mod p -- matches Alice's

      // Bob thinks he's completing an exchange with Alice, but receives E2
      // (Eve's value) instead of A.
      const bobSecret = modPow(E2, b, p);     // Bob computes E2^b mod p
      const eveSecretWithBob = modPow(B, e2, p);   // Eve computes B^e2 mod p -- matches Bob's

      mitmOut.textContent =
`Eve sits on the wire between Alice and Bob and intercepts every message.

STEP 1 -- Real public values Alice and Bob generate (never actually delivered to each other)
  Alice's real public value A = g^a mod p = ${A}
  Bob's real public value   B = g^b mod p = ${B}

STEP 2 -- Eve generates two of her own private/public key pairs
  Eve's private key toward Alice: e1 = ${e1}  ->  public value E1 = g^e1 mod p = ${E1}
  Eve's private key toward Bob:   e2 = ${e2}  ->  public value E2 = g^e2 mod p = ${E2}

STEP 3 -- Eve intercepts and substitutes
  Eve sends E1 to Alice, claiming "this is Bob's public value".
  Eve sends E2 to Bob, claiming "this is Alice's public value".
  Alice and Bob each proceed completely unaware anything is wrong.

STEP 4 -- Two independent shared secrets are established, both with Eve
  Alice computes: s1 = E1^a mod p = ${aliceSecret}
  Eve computes (as "Bob"): s1 = A^e1 mod p = ${eveSecretWithAlice}
  Match: ${aliceSecret === eveSecretWithAlice ? "YES -- Eve shares a secret with Alice, who believes it's Bob" : "mismatch (check inputs)"}

  Bob computes: s2 = E2^b mod p = ${bobSecret}
  Eve computes (as "Alice"): s2 = B^e2 mod p = ${eveSecretWithBob}
  Match: ${bobSecret === eveSecretWithBob ? "YES -- Eve shares a separate secret with Bob, who believes it's Alice" : "mismatch (check inputs)"}

RESULT
  Eve now holds two independent shared secrets: one indistinguishable (to
  Alice) from a real exchange with Bob, and one indistinguishable (to Bob)
  from a real exchange with Alice. Every message can be decrypted, read,
  optionally modified, and re-encrypted by Eve as it passes through in
  either direction -- and unless something outside the DH math itself
  (a certificate, a pre-shared fingerprint, a signature) lets Alice and
  Bob authenticate each other's public values, neither one can detect it.`;
    } catch (err) {
      mitmOut.textContent = "Error: " + err.message;
    }
  };
}

registerTab("dh", "Diffie-Hellman", renderDH);

// ---------------------------------------------------------------------------
// Tool 8: Hash Identifier
// ---------------------------------------------------------------------------
//
// Hash algorithms produce fixed-length digests, and many have distinctive
// formatting (dollar-sign prefixed "crypt" style identifiers, curly-brace
// LDAP prefixes, base64 vs hex alphabets, etc). This tool can't tell you
// *for certain* what algorithm produced an opaque hex string -- MD5 and
// NTLM are both 32 hex characters, for instance -- but pattern matching on
// length, character set, and structural markers narrows things down and is
// exactly what tools like hashid / hash-identifier do under the hood.

const HASH_PATTERNS = [
  { name: "MD5", regex: /^[a-f0-9]{32}$/i, note: "32 hex chars. Also matches NTLM, MD4, LM/2, Haval-128, RIPEMD-128 -- length alone is ambiguous." },
  { name: "NTLM", regex: /^[a-f0-9]{32}$/i, note: "32 hex chars, unsalted MD4 of UTF-16LE password. Identical format to MD5/MD4." },
  { name: "MD4", regex: /^[a-f0-9]{32}$/i, note: "32 hex chars. Predecessor to MD5, also used as the basis for NTLM." },
  { name: "LM hash", regex: /^[a-f0-9]{32}$/i, note: "32 hex chars. Legacy Windows LAN Manager hash, often paired with an NTLM hash as user:LM:NTLM." },
  { name: "RIPEMD-128", regex: /^[a-f0-9]{32}$/i, note: "32 hex chars." },
  { name: "Haval-128", regex: /^[a-f0-9]{32}$/i, note: "32 hex chars." },
  { name: "MySQL (pre-4.1)", regex: /^[a-f0-9]{16}$/i, note: "16 hex chars. Old, very weak MySQL PASSWORD() format." },
  { name: "CRC32", regex: /^[a-f0-9]{8}$/i, note: "8 hex chars (32 bits). Checksum, not cryptographic -- collisions are trivial." },
  { name: "Adler32", regex: /^[a-f0-9]{8}$/i, note: "8 hex chars (32 bits). Checksum used by zlib." },
  { name: "CRC16", regex: /^[a-f0-9]{4}$/i, note: "4 hex chars (16 bits)." },
  { name: "SHA-1", regex: /^[a-f0-9]{40}$/i, note: "40 hex chars (160 bits). Deprecated for security use but still common as a checksum/identifier." },
  { name: "RIPEMD-160", regex: /^[a-f0-9]{40}$/i, note: "40 hex chars. Used inside Bitcoin addresses (hash of SHA-256 output)." },
  { name: "Haval-160", regex: /^[a-f0-9]{40}$/i, note: "40 hex chars." },
  { name: "Tiger-160", regex: /^[a-f0-9]{40}$/i, note: "40 hex chars." },
  { name: "MySQL 4.1+ (SHA1)", regex: /^\*[A-F0-9]{40}$/i, note: "Asterisk prefix + 40 hex chars. SHA1(SHA1(password))." },
  { name: "SHA-224", regex: /^[a-f0-9]{56}$/i, note: "56 hex chars (224 bits)." },
  { name: "SHA3-224", regex: /^[a-f0-9]{56}$/i, note: "56 hex chars (224 bits)." },
  { name: "SHA-256", regex: /^[a-f0-9]{64}$/i, note: "64 hex chars (256 bits). Extremely common: TLS certs, Bitcoin, checksums, password hashing input to KDFs." },
  { name: "SHA3-256", regex: /^[a-f0-9]{64}$/i, note: "64 hex chars (256 bits). Keccak-based SHA-3 family." },
  { name: "SHA-512/256", regex: /^[a-f0-9]{64}$/i, note: "64 hex chars, truncated SHA-512 variant." },
  { name: "BLAKE2s-256", regex: /^[a-f0-9]{64}$/i, note: "64 hex chars." },
  { name: "GOST R 34.11-94", regex: /^[a-f0-9]{64}$/i, note: "64 hex chars, Russian standard hash." },
  { name: "Whirlpool (part)/SHA-384", regex: /^[a-f0-9]{96}$/i, note: "96 hex chars (384 bits)." },
  { name: "SHA3-384", regex: /^[a-f0-9]{96}$/i, note: "96 hex chars (384 bits)." },
  { name: "SHA-512", regex: /^[a-f0-9]{128}$/i, note: "128 hex chars (512 bits)." },
  { name: "SHA3-512", regex: /^[a-f0-9]{128}$/i, note: "128 hex chars (512 bits)." },
  { name: "Whirlpool", regex: /^[a-f0-9]{128}$/i, note: "128 hex chars (512 bits)." },
  { name: "BLAKE2b-512", regex: /^[a-f0-9]{128}$/i, note: "128 hex chars (512 bits)." },
  { name: "bcrypt", regex: /^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$/, note: "$2a$/$2b$/$2y$ + cost factor + 22-char salt + 31-char hash, 60 chars total. Adaptive, salted, still recommended for password storage." },
  { name: "MD5 crypt (Unix)", regex: /^\$1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}$/, note: "$1$salt$hash -- classic Unix crypt(3) MD5 variant." },
  { name: "SHA-256 crypt (Unix)", regex: /^\$5\$(rounds=\d+\$)?[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{43}$/, note: "$5$salt$hash -- glibc SHA-256-based crypt." },
  { name: "SHA-512 crypt (Unix)", regex: /^\$6\$(rounds=\d+\$)?[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{86}$/, note: "$6$salt$hash -- glibc SHA-512-based crypt, common /etc/shadow format." },
  { name: "phpBB3 / WordPress (phpass)", regex: /^\$[PH]\$[./A-Za-z0-9]{31}$/, note: "$P$ or $H$ + 31 chars. Portable PHP password hashing framework." },
  { name: "Django PBKDF2-SHA256", regex: /^pbkdf2_sha256\$\d+\$[^$]+\$[A-Za-z0-9+/=]+$/, note: "pbkdf2_sha256$iterations$salt$hash -- Django's default password hasher." },
  { name: "Argon2", regex: /^\$argon2(i|d|id)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/, note: "$argon2id$v=19$m=...,t=...,p=...$salt$hash. Winner of the Password Hashing Competition, current best practice." },
  { name: "scrypt", regex: /^\$scrypt\$ln=\d+,r=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$/, note: "Memory-hard KDF, common in cryptocurrency wallets." },
  { name: "LDAP SSHA", regex: /^\{SSHA\}[A-Za-z0-9+/=]+$/, note: "{SSHA}base64(sha1-digest + salt) -- salted SHA-1, common in LDAP/OpenLDAP." },
  { name: "LDAP SHA", regex: /^\{SHA\}[A-Za-z0-9+/=]+$/, note: "{SHA}base64(sha1-digest) -- unsalted, weak." },
  { name: "LDAP MD5", regex: /^\{MD5\}[A-Za-z0-9+/=]+$/, note: "{MD5}base64(md5-digest)." },
  { name: "Cisco Type 7", regex: /^[0-9]{2}[0-9a-fA-F]{2,}$/, note: "Reversible XOR-based obfuscation used in old Cisco IOS configs -- not a real hash, trivially reversible." },
  { name: "Cisco Type 5 (MD5 crypt)", regex: /^\$1\$[./A-Za-z0-9]{4}\$[./A-Za-z0-9]{22}$/, note: "Cisco's Type 5 passwords are standard MD5-crypt." },
  { name: "JWT", regex: /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/, note: "Three base64url segments separated by dots: header.payload.signature. Not a hash -- a signed/encoded token; decode with the Hash Identifier's cousin, the JWT tool in Toolkit." },
  { name: "Base64-encoded MD5", regex: /^[A-Za-z0-9+/]{22}==$/, note: "22 base64 chars + == padding decodes to 16 raw bytes -- an MD5 digest stored as base64 instead of hex." },
  { name: "Base64-encoded SHA-1", regex: /^[A-Za-z0-9+/]{27}=$/, note: "27 base64 chars + = padding decodes to 20 raw bytes -- a SHA-1 digest as base64." },
  { name: "Base64-encoded SHA-256", regex: /^[A-Za-z0-9+/]{43}=$/, note: "43 base64 chars + = padding decodes to 32 raw bytes -- a SHA-256 digest as base64." },
  { name: "Unix DES crypt", regex: /^[./A-Za-z0-9]{13}$/, note: "13 chars, no dollar-sign markers. The original 1970s Unix crypt(3) -- only uses the first 8 password characters and a 12-bit salt, extremely weak by modern standards." },
  { name: "BSDi extended DES crypt", regex: /^_[./A-Za-z0-9]{19}$/, note: "Leading underscore + 19 chars. BSDi's extended-round variant of DES crypt." },
  { name: "Drupal (phpass, Drupal 7)", regex: /^\$S\$[./A-Za-z0-9]{52}$/, note: "$S$ + 52 chars. Drupal 7's salted, stretched SHA-512-based phpass variant." },
  { name: "Joomla (MD5 salted)", regex: /^[a-f0-9]{32}:[A-Za-z0-9]+$/i, note: "32-hex MD5 digest, colon, salt appended in plaintext -- classic older Joomla format." },
  { name: "vBulletin (salted MD5)", regex: /^[a-f0-9]{32}:[A-Za-z0-9]{3}$/i, note: "32-hex MD5 digest, colon, short salt -- classic vBulletin password format." },
  { name: "osCommerce / xt:Commerce (salted MD5)", regex: /^[a-f0-9]{32}:[a-f0-9]{2}$/i, note: "32-hex MD5 digest, colon, 2-char salt." },
  { name: "PostgreSQL MD5", regex: /^md5[a-f0-9]{32}$/i, note: "Literal 'md5' prefix + 32 hex chars. PostgreSQL stores password hashes as md5(password + username)." },
  { name: "Oracle 11g", regex: /^S:[A-F0-9]{60}$/, note: "'S:' prefix + 60 hex chars (20-byte SHA-1 hash + 10-byte salt, both hex). Oracle 11g password verifier." },
  { name: "Oracle 10g", regex: /^[A-F0-9]{16}$/, note: "16 hex chars, DES-based, case-insensitive username used as salt -- legacy Oracle password hash." },
  { name: "Kerberos 5 AS-REQ PA-ENC-TIMESTAMP (etype 23)", regex: /^\$krb5pa\$23\$/, note: "$krb5pa$23$user$realm$salt$hash -- captured during Kerberos pre-authentication, crackable offline (ASREPRoast-adjacent)." },
  { name: "Kerberos 5 TGS-REP (etype 23, Kerberoasting)", regex: /^\$krb5tgs\$23\$/, note: "$krb5tgs$23$*user$realm$service*$hash -- a Kerberoastable service ticket, RC4-HMAC encrypted." },
  { name: "NetNTLMv1", regex: /^[a-f0-9]{48}$/i, note: "48 hex chars. Windows network authentication response -- captured via SMB relay/responder-style attacks, not a stored password hash." },
  { name: "NetNTLMv2", regex: /^[A-Fa-f0-9]{32}:[A-Fa-f0-9]+$/, note: "32-hex HMAC-MD5 response, colon, variable-length blob -- the modern default NetNTLM challenge/response format." },
  { name: "WPA/WPA2 PMKID", regex: /^[a-f0-9]{32}\*[a-f0-9]{12}\*[a-f0-9]{12}\*[a-f0-9]+$/i, note: "pmkid*apmac*clientmac*essid, all hex/asterisk-delimited -- extracted from a captured WPA handshake for offline cracking." },
  { name: "RIPEMD-256", regex: /^[a-f0-9]{64}$/i, note: "64 hex chars (256 bits), less common RIPEMD variant." },
  { name: "RIPEMD-320", regex: /^[a-f0-9]{80}$/i, note: "80 hex chars (320 bits)." },
  { name: "Tiger-192", regex: /^[a-f0-9]{48}$/i, note: "48 hex chars (192 bits)." },
  { name: "Snefru-256", regex: /^[a-f0-9]{64}$/i, note: "64 hex chars, a lesser-used Xerox PARC hash function." },
  { name: "bcrypt-sha256 (Django)", regex: /^bcrypt_sha256\$\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$/, note: "Django's bcrypt+SHA256 pre-hash variant, avoids bcrypt's 72-byte input truncation." },
  { name: "Generic PBKDF2", regex: /^\$pbkdf2(-sha1|-sha256|-sha512)?\$\d+\$[A-Za-z0-9+/.=]+\$[A-Za-z0-9+/.=]+$/, note: "$pbkdf2-shaXXX$iterations$salt$hash -- generic PBKDF2 KDF string used by many non-Django frameworks (e.g. Passlib)." },
  { name: "1Password / Bitwarden-style KDF blob", regex: /^[A-Za-z0-9+/]{40,}={0,2}$/, note: "Long base64 blob with no separators -- consistent with an exported encrypted-vault key blob, though these are not directly hash-identifiable without the surrounding format." },
  { name: "Base64-encoded SHA-512", regex: /^[A-Za-z0-9+/]{86}==$/, note: "86 base64 chars + == padding decodes to 64 raw bytes -- a SHA-512 digest as base64." },
  { name: "Firebird/Interbase", regex: /^[A-Za-z0-9+/]{16}$/, note: "16-char base64-ish string, DES-based, legacy Firebird/Interbase user password hash." },
];

function identifyHash(value) {
  const trimmed = value.trim();
  if (!trimmed) return [];
  const matches = HASH_PATTERNS.filter((p) => p.regex.test(trimmed));
  return matches;
}

function renderHashIdentifier(root) {
  root.innerHTML = `
    <div class="tk-section">
    <h2 class="pg-h2">Hash Identifier</h2>
    <p class="muted">Paste a hash and this tool matches it against a database of ${HASH_PATTERNS.length}
      known hash/encoding formats by length, character set, and structural markers (dollar-sign
      prefixes, curly-brace LDAP tags, base64 padding, etc). Many algorithms share an identical
      output length and format -- MD5, MD4, and NTLM are all 32 hex characters -- so multiple
      matches for a plain hex string is normal and expected; context (where the hash came from)
      is what actually disambiguates them.</p>
    <textarea class="tk-in" id="hi-in" rows="3" placeholder="Paste a hash, e.g. 5f4dcc3b5aa765d61d8327deb882cf99"></textarea>
    <div class="tk-btns">
      <button class="btn sm" id="hi-run">Identify</button>
      <button class="btn sm ghost" id="hi-clear">Clear</button>
    </div>
    <div id="hi-out" style="margin-top:14px"></div>
    </div>
    <div class="tk-section">
    <h2 class="pg-h2">Reference: supported formats</h2>
    <div id="hi-db" class="mono" style="font-size:12px;line-height:1.7"></div>
    </div>
  `;

  const inp = root.querySelector("#hi-in");
  const out = root.querySelector("#hi-out");
  const db = root.querySelector("#hi-db");

  root.querySelector("#hi-clear").onclick = () => { inp.value = ""; out.innerHTML = ""; };
  root.querySelector("#hi-run").onclick = run;
  inp.oninput = run;

  db.innerHTML = HASH_PATTERNS.map((p) => `<div><strong>${escapeHtml(p.name)}</strong> -- ${escapeHtml(p.note)}</div>`).join("");

  function run() {
    const value = inp.value;
    if (!value.trim()) { out.innerHTML = ""; return; }
    const matches = identifyHash(value);
    const length = value.trim().length;
    if (matches.length === 0) {
      out.innerHTML = `<div class="card"><strong>No known format matched.</strong>
        <p class="muted">Input length: ${length} characters. This might be a hash format not in
        the database, a truncated/corrupted hash, or not a hash at all (e.g. an API key,
        session token, or UUID).</p></div>`;
      return;
    }
    out.innerHTML = `<div class="card">
      <strong>${matches.length} possible match${matches.length > 1 ? "es" : ""} (input length: ${length} characters)</strong>
      <div style="margin-top:10px;display:flex;flex-direction:column;gap:8px">
        ${matches.map((m) => `<div><strong>${escapeHtml(m.name)}</strong><div class="muted">${escapeHtml(m.note)}</div></div>`).join("")}
      </div>
    </div>`;
  }
}

registerTab("hashid", "Hash Identifier", renderHashIdentifier);

// ---------------------------------------------------------------------------
// Tool 9: Password Entropy Calculator
// ---------------------------------------------------------------------------
//
// Shannon entropy for a password drawn uniformly from a character set of
// size N and length L is L * log2(N) bits -- this measures the theoretical
// search space size, not how "clever" the password looks. We detect which
// character classes are present to estimate N, flag common weakening
// patterns (dictionary words, repeated characters, sequential runs,
// keyboard walks, dates), and translate the resulting bit count into rough
// crack-time estimates across a range of attacker speeds.

// A curated set of passwords that repeatedly top published "most common /
// most breached password" lists (annual reports drawn from leaked
// credential dumps). If a candidate password is in here, it would be among
// the very first guesses in any real-world credential stuffing or
// dictionary attack regardless of its raw character-pool entropy.
const COMMON_PASSWORDS = new Set([
  "password", "123456", "12345678", "123456789", "1234567890", "12345",
  "1234567", "qwerty", "qwerty123", "qwertyuiop", "abc123", "abcd1234",
  "letmein", "letmein123", "monkey", "monkey123", "dragon", "dragon123",
  "111111", "1111111", "iloveyou", "admin", "administrator", "welcome",
  "welcome1", "login", "starwars", "password1", "password123", "passw0rd",
  "p@ssw0rd", "football", "footballer", "baseball", "master", "master123",
  "sunshine", "shadow", "princess", "princess1", "trustno1", "hello",
  "hello123", "freedom", "whatever", "qazwsx", "qazwsx123", "123123",
  "123321", "michael", "jennifer", "jordan", "hunter", "hunter2",
  "superman", "1qaz2wsx", "zaq12wsx", "asdfghjkl", "asdf1234", "123abc",
  "abc12345", "111222", "121212", "654321", "000000", "999999", "666666",
  "555555", "iloveyou1", "iloveyou2", "flower", "sunflower", "summer",
  "summer2024", "winter", "spring", "autumn", "computer", "internet",
  "changeme", "changeme123", "default", "guest", "guest123", "temp123",
  "temppass", "test123", "testing", "test1234", "demo123", "sample",
  "root", "rootroot", "toor", "system", "user", "user123", "info",
  "backup", "database", "server", "network", "secret", "secret123",
  "mypassword", "mypass123", "newpassword", "newpass123", "letme", "access",
  "access14", "batman", "batman1", "superman1", "spiderman", "ironman",
  "pokemon", "pikachu", "charizard", "minecraft", "fortnite", "roblox",
  "steam123", "playstation", "xbox360", "nintendo", "gamer", "gaming",
  "chelsea", "arsenal", "liverpool", "manutd", "barcelona", "madrid",
  "soccer", "hockey", "basketball", "golfer", "tennis", "cricket11",
  "dolphin", "dolphins", "tigger", "cheese", "cookie", "chocolate",
  "coffee123", "banana", "orange123", "apple123", "google123", "yahoo123",
  "facebook", "instagram", "twitter1", "snapchat", "linkedin", "myspace",
  "hotmail", "gmail123", "outlook1", "amazon123", "netflix", "spotify",
  "abcdefg", "abcdefgh", "abcdefghi", "a1b2c3", "a1b2c3d4", "z1x2c3v4",
  "1a2b3c4d", "p4ssword", "passw0rd1", "p@ssword1", "welcome123",
  "changeme1", "12341234", "11223344", "13131313", "10203040", "20212022",
  "20232024", "january1", "february1", "december1", "monday123", "friday123",
  "loveme", "iloveme", "trustme", "believe", "forever", "always",
  "family1", "friends1", "brother1", "sister01", "mother01", "father01",
  "baby123", "angel123", "peanut12", "cookie123", "sweetie1", "honey123",
  "cutie123", "lovely01", "beauty01", "pretty01", "handsome", "sexy123",
  "iamgod", "godlike", "ninja123", "dragonball", "wizard01", "warrior1",
  "knight01", "soldier1", "captain01", "general1", "admiral1", "sergeant",
  "phoenix1", "phoenix01", "thunder1", "lightning", "hurricane", "tornado1",
  "shadow123", "darkness", "midnight1", "twilight1", "eclipse1", "galaxy01",
  "starfire", "moonlight", "sunrise01", "sunset123", "rainbow1", "diamond1",
  "goldstar", "silverfox", "bluejay01", "redfox123", "blackcat", "whitewolf",
  "iloveu", "loveyou1", "kissme01", "hugme123", "sweetdreams", "goodnight1",
  "welcome2024", "letmein2024", "password2024", "admin2024", "master2024",
]);

function analyzePasswordCharsets(password) {
  const has = {
    lower: /[a-z]/.test(password),
    upper: /[A-Z]/.test(password),
    digit: /[0-9]/.test(password),
    symbol: /[^A-Za-z0-9]/.test(password),
  };
  let poolSize = 0;
  if (has.lower) poolSize += 26;
  if (has.upper) poolSize += 26;
  if (has.digit) poolSize += 10;
  if (has.symbol) poolSize += 33; // approx printable ASCII symbols
  return { has, poolSize };
}

function detectPatterns(password) {
  const issues = [];
  const lower = password.toLowerCase();
  if (COMMON_PASSWORDS.has(lower)) issues.push("Exact match against a common password list -- would be cracked instantly regardless of length.");
  if (/(.)\1{2,}/.test(password)) issues.push("Contains a character repeated 3+ times in a row (e.g. 'aaa'), which reduces effective entropy.");
  const sequences = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl", "zxcvbnm"];
  for (const seq of sequences) {
    for (let i = 0; i <= seq.length - 4; i++) {
      const fwd = seq.slice(i, i + 4);
      const rev = [...fwd].reverse().join("");
      if (lower.includes(fwd) || lower.includes(rev)) {
        issues.push(`Contains a sequential/keyboard run ("${fwd}"), which is highly predictable.`);
        break;
      }
    }
  }
  if (/(19|20)\d{2}/.test(password)) issues.push("Contains what looks like a 4-digit year -- dates are commonly tried by crackers.");
  if (/^[A-Z][a-z]+\d+$/.test(password) || /^[A-Z][a-z]+\d+[^A-Za-z0-9]$/.test(password)) {
    issues.push("Matches the extremely common 'Word + digits (+ symbol)' pattern (e.g. Summer2024!), which is one of the first patterns dictionary+rules attacks try.");
  }
  if (password.length > 0 && password.length < 8) issues.push("Very short (under 8 characters) -- brute-forceable even with a large character set.");
  return issues;
}

function crackTimeEstimates(entropyBits) {
  const totalGuesses = Math.pow(2, entropyBits);
  const avgGuesses = totalGuesses / 2;
  const speeds = [
    { label: "Online, rate-limited (10/sec)", rate: 10 },
    { label: "Online, no rate limit (1k/sec)", rate: 1e3 },
    { label: "Offline, slow hash e.g. bcrypt (10k/sec)", rate: 1e4 },
    { label: "Offline, fast hash e.g. MD5, single GPU (10B/sec)", rate: 1e10 },
    { label: "Offline, fast hash, GPU cluster (1T/sec)", rate: 1e12 },
    { label: "Nation-state / ASIC farm (100T/sec)", rate: 1e14 },
  ];
  return speeds.map((s) => ({ ...s, seconds: avgGuesses / s.rate }));
}

function formatDuration(seconds) {
  if (!isFinite(seconds)) return "effectively infinite";
  if (seconds < 1) return "instant";
  const units = [
    ["century", 3153600000], ["year", 31536000], ["day", 86400],
    ["hour", 3600], ["minute", 60], ["second", 1],
  ];
  for (const [name, size] of units) {
    if (seconds >= size) {
      const count = seconds / size;
      if (count > 1e6) return `${count.toExponential(2)} ${name}s`;
      return `${count.toFixed(count < 10 ? 1 : 0)} ${name}${count >= 2 ? "s" : ""}`;
    }
  }
  return "instant";
}

function renderPasswordEntropy(root) {
  root.innerHTML = `
    <div class="tk-section">
    <h2 class="pg-h2">Password Entropy Calculator</h2>
    <p class="muted">Entropy measures the size of the search space an attacker who knows
      nothing about your password would have to search: bits = length * log2(character set
      size). It does not know if your password is a well-known phrase -- the pattern checks
      below cover some of that gap, but the single best thing you can do for a password's real
      strength is length plus true randomness (or a long, unique passphrase).</p>
    <div class="tk-row">
      <input class="tk-f" id="pe-in" type="text" placeholder="Type or paste a password to analyze">
      <label class="muted mono" style="font-size:12px;white-space:nowrap"><input type="checkbox" id="pe-show" checked> show</label>
    </div>
    <div id="pe-out" style="margin-top:14px"></div>
    </div>
  `;

  const inp = root.querySelector("#pe-in");
  const show = root.querySelector("#pe-show");
  const out = root.querySelector("#pe-out");

  show.onchange = () => { inp.type = show.checked ? "text" : "password"; };
  inp.oninput = run;
  run();

  function run() {
    const password = inp.value;
    if (!password) { out.innerHTML = '<p class="muted">Start typing to see live analysis.</p>'; return; }

    const { has, poolSize } = analyzePasswordCharsets(password);
    const entropyBits = password.length * Math.log2(Math.max(poolSize, 1));
    const issues = detectPatterns(password);

    let rating, ratingClass;
    if (entropyBits < 28) { rating = "Very weak"; ratingClass = "danger"; }
    else if (entropyBits < 36) { rating = "Weak"; ratingClass = "danger"; }
    else if (entropyBits < 60) { rating = "Reasonable"; ratingClass = ""; }
    else if (entropyBits < 80) { rating = "Strong"; ratingClass = ""; }
    else { rating = "Very strong"; ratingClass = ""; }

    const times = crackTimeEstimates(Math.max(entropyBits - issues.length * 4, 0));

    out.innerHTML = `
      <div class="tk-row" style="flex-wrap:wrap;gap:18px">
        <div class="stat"><div class="stat-n">${entropyBits.toFixed(1)}</div><div class="stat-l">Bits of entropy</div></div>
        <div class="stat"><div class="stat-n">${password.length}</div><div class="stat-l">Length</div></div>
        <div class="stat"><div class="stat-n">${poolSize}</div><div class="stat-l">Character pool size</div></div>
        <div class="stat"><div class="stat-n">${rating}</div><div class="stat-l">Rating</div></div>
      </div>
      <div class="card" style="margin-top:14px">
        <strong>Character classes detected</strong>
        <div class="mono" style="margin-top:6px">
          lowercase (a-z): ${has.lower ? "yes (+26)" : "no"}<br>
          uppercase (A-Z): ${has.upper ? "yes (+26)" : "no"}<br>
          digits (0-9): ${has.digit ? "yes (+10)" : "no"}<br>
          symbols: ${has.symbol ? "yes (+~33)" : "no"}<br>
          total pool size: ${poolSize}
        </div>
      </div>
      <div class="card" style="margin-top:14px">
        <strong>Pattern analysis</strong>
        ${issues.length
          ? `<ul style="margin:8px 0 0 18px">${issues.map((i) => `<li>${escapeHtml(i)}</li>`).join("")}</ul>`
          : '<p class="muted" style="margin-top:6px">No obvious weakening patterns detected by this checker.</p>'}
      </div>
      <div class="card" style="margin-top:14px">
        <strong>Estimated average crack time (adjusted for detected patterns)</strong>
        <table class="mono" style="width:100%;margin-top:8px;border-collapse:collapse">
          ${times.map((t) => `<tr><td style="padding:3px 8px 3px 0">${escapeHtml(t.label)}</td><td style="padding:3px 0;text-align:right">${formatDuration(t.seconds)}</td></tr>`).join("")}
        </table>
        <p class="muted" style="margin-top:8px">These are average-case estimates (half the full
          keyspace) assuming a brute-force attacker with no knowledge of your password structure.
          Real attacks usually use dictionaries and rules first, which is why the pattern
          penalties above matter as much as raw length.</p>
      </div>
    `;
  }
}

registerTab("entropy", "Password Entropy", renderPasswordEntropy);

// ---------------------------------------------------------------------------
// Tool 10: Password / Passphrase Generator
// ---------------------------------------------------------------------------
//
// Two generation modes. Random-character passwords draw uniformly from
// whichever character classes the user enables using crypto.getRandomValues
// (a cryptographically secure RNG, not Math.random) with rejection sampling
// so the distribution stays perfectly uniform. Passphrase mode implements
// the "Diceware" style approach popularized by the EFF: pick N words
// uniformly at random from a large wordlist and join them with a separator
// -- a handful of random dictionary words is both easier to remember and,
// for a big enough wordlist, has more entropy than a short random string.

// A large inline wordlist (2000+ common English words, grouped by theme)
// used for passphrase generation. Deduplicated at load time via Set so the
// entropy math (log2(uniqueWordCount) bits per word) stays accurate even
// though a few words naturally appear in more than one thematic group.
const WORDLIST_RAW = [
  // Animals
  "ant","bear","bee","beetle","bird","bison","boar","buffalo","butterfly","camel",
  "canary","cat","caterpillar","cheetah","chicken","chimp","chipmunk","cobra","cougar","cow",
  "coyote","crab","crane","cricket","crocodile","crow","deer","dingo","dog","dolphin",
  "donkey","dove","dragonfly","duck","eagle","eel","elephant","elk","falcon","ferret",
  "finch","fish","flamingo","fly","fox","frog","gazelle","gecko","giraffe","goat",
  "goose","gopher","gorilla","grasshopper","hamster","hare","hawk","hedgehog","heron","hippo",
  "horse","hound","hummingbird","hyena","ibis","iguana","impala","jackal","jaguar","jay",
  "jellyfish","kangaroo","kestrel","kingfisher","kiwi","koala","ladybug","lamb","lark","lemur",
  "leopard","lion","lizard","llama","lobster","locust","lynx","macaw","magpie","mallard",
  "mammoth","manatee","mantis","marmot","meerkat","mole","mongoose","monkey","moose","moth",
  "mouse","mule","narwhal","newt","nightingale","ocelot","octopus","opossum","orca","ostrich",
  "otter","owl","ox","oyster","panda","panther","parrot","partridge","peacock","pelican",
  "penguin","pheasant","pig","pigeon","piranha","platypus","polecat","pony","porcupine","porpoise",
  "puffin","puma","python","quail","rabbit","raccoon","ram","rat","raven","reindeer",
  "rhino","robin","rooster","salamander","salmon","sardine","scorpion","seagull","seahorse","seal",
  "shark","sheep","shrew","shrimp","skunk","sloth","snail","snake","sparrow","spider",
  "squid","squirrel","stallion","starling","stingray","stork","swallow","swan","tapir","termite",
  "tiger","toad","tortoise","toucan","trout","turkey","turtle","viper","vole","vulture",
  "wallaby","walrus","warbler","wasp","weasel","whale","wolf","wolverine","wombat","woodpecker",
  "worm","wren","yak","zebra",
  // Colors
  "amber","apricot","aqua","azure","beige","black","blue","bronze","brown","burgundy",
  "chartreuse","charcoal","chestnut","cobalt","copper","coral","cream","crimson","cyan","ebony",
  "emerald","fuchsia","gold","gray","green","indigo","ivory","jade","khaki","lavender",
  "lemon","lilac","lime","magenta","maroon","mauve","mint","mustard","navy","ochre",
  "olive","onyx","orange","peach","pearl","periwinkle","pink","plum","purple","rose",
  "ruby","russet","rust","sage","salmoncolor","sapphire","scarlet","sienna","silver","slate",
  "tan","taupe","teal","turquoise","ultramarine","umber","vermilion","violet","white","yellow",
  // Foods and drinks
  "almond","apple","artichoke","asparagus","avocado","bacon","bagel","banana","barley","bean",
  "beef","beet","berry","biscuit","blackberry","blueberry","bread","broccoli","brownie","butter",
  "cabbage","cake","candy","cantaloupe","caramel","carrot","cashew","cauliflower","celery","cereal",
  "cheese","cherry","chili","chives","chocolate","cider","cilantro","cinnamon","clam","clove",
  "cocoa","coconut","coffee","cookie","coriander","corn","cranberry","cucumber","cumin","curry",
  "custard","date","dill","doughnut","dumpling","egg","eggplant","endive","fennel","fig",
  "fondue","garlic","ginger","grape","grapefruit","gravy","guava","ham","hazelnut","herb",
  "honey","hummus","jalapeno","jam","kale","ketchup","kiwifruit","lentil","lettuce","mackerel",
  "mandarin","mango","maple","marmalade","marshmallow","meatball","melon","milk","mocha","molasses",
  "mushroom","noodle","nutmeg","oat","omelet","onion","oregano","pancake","papaya","paprika",
  "parsley","parsnip","pasta","pastry","peanut","pear","pecan","pepperoni","persimmon","pickle",
  "pineapple","pistachio","pizza","pomegranate","popcorn","pork","pretzel","pumpkin","quiche","quinoa",
  "radish","raisin","raspberry","relish","rhubarb","rosemary","saffron","salsa","sausage","scallion",
  "scallop","seaweed","sesame","soup","spinach","sprout","squash","strawberry","sushi","syrup",
  "taco","tamarind","tangerine","tart","thyme","toast","tofu","tomato","truffle","tuna",
  "turmeric","turnip","vanilla","veal","venison","vinegar","waffle","walnut","watercress","watermelon",
  "wheat","yam","yeast","yogurt","zucchini",
  // Nature and weather
  "acorn","avalanche","bay","beach","bedrock","blizzard","bluff","bog","boulder","breeze",
  "brook","canyon","cave","cliff","cloud","coast","comet","continent","crater","creek",
  "current","delta","desert","dew","dune","dust","earthquake","eclipse","ember","equinox",
  "estuary","fjord","flame","flood","fog","forest","fossil","frost","galaxy","geyser",
  "glacier","glade","glow","grove","gulf","gully","gust","hail","harbor","haze",
  "hill","horizon","hurricane","iceberg","island","isle","jungle","lagoon","lake","landslide",
  "lava","ledge","lightning","magma","marsh","meadow","mesa","meteor","mist","monsoon",
  "moon","moor","moss","mountain","mud","nebula","nova","oasis","ocean","orbit",
  "outcrop","peak","peninsula","plain","planet","plateau","pond","prairie","quake","quarry",
  "rainbow","rainfall","rapids","ravine","reef","ridge","ripple","river","rock","sand",
  "sandbar","savanna","sediment","shale","shore","shower","sky","sleet","slope","snow",
  "snowflake","spring","star","storm","stream","summit","sunrise","sunset","swamp","thicket",
  "thunder","tide","tornado","tsunami","tundra","twilight","typhoon","valley","volcano","vortex",
  "waterfall","wave","wetland","wildfire","wind","woodland",
  // Body parts
  "ankle","arm","armpit","back","beard","belly","bicep","bone","brain","brow",
  "calf","cheek","chest","chin","collarbone","ear","elbow","eyebrow","eyelash","eyelid",
  "face","finger","fist","foot","forearm","forehead","gum","hair","hand","head",
  "heart","heel","hip","jaw","joint","kidney","knee","knuckle","leg","lip",
  "liver","lung","mouth","muscle","nail","neck","nerve","nose","palm","rib",
  "shin","shoulder","skin","skull","spine","stomach","temple","throat","thumb","toe",
  "tongue","tooth","torso","vein","waist","wrist",
  // Professions
  "accountant","actor","admiral","analyst","ambassador","architect","artist","astronaut","athlete","attorney",
  "author","baker","banker","barber","barista","bartender","biologist","blacksmith","botanist","broker",
  "builder","butcher","captain","carpenter","cartographer","cashier","chauffeur","chef","chemist","clerk",
  "coach","composer","conductor","consultant","cook","counselor","courier","curator","dancer","dentist",
  "designer","detective","developer","diplomat","director","doctor","drummer","economist","editor","electrician",
  "engineer","entrepreneur","farmer","firefighter","fisherman","florist","gardener","geologist","guard","guide",
  "guitarist","historian","hunter","illustrator","inspector","instructor","inventor","investigator","jeweler","journalist",
  "judge","lawyer","lecturer","librarian","lifeguard","linguist","locksmith","magician","mason","mathematician",
  "mechanic","merchant","messenger","midwife","miner","minister","musician","navigator","negotiator","novelist",
  "nurse","nutritionist","officer","operator","optician","painter","paramedic","pastor","pharmacist","philosopher",
  "photographer","physician","pilot","plumber","poet","potter","president","priest","professor","programmer",
  "psychologist","publisher","ranger","receptionist","referee","reporter","researcher","sailor","scholar","scientist",
  "sculptor","secretary","senator","sergeant","singer","soldier","surgeon","surveyor","tailor","teacher",
  "technician","therapist","trader","trainer","translator","tutor","veterinarian","violinist","waiter","warden",
  "warrior","welder","writer","zoologist",
  // Tools and objects
  "adapter","adhesive","anchor","anvil","apron","awl","axe","ballast","barrel","basket",
  "battery","beacon","beaker","bell","belt","bench","bin","blade","blanket","bolt",
  "book","bottle","bowl","box","bracket","bracelet","brick","bridge","brush","bucket",
  "buckle","bulb","cable","cage","camera","candle","canvas","cart","case","chain",
  "chair","chart","chest","chisel","clamp","clip","clock","cloth","coil","compass",
  "container","cord","cork","crate","crayon","crowbar","cushion","dagger","dial","dish",
  "drill","drum","engine","envelope","eraser","fabric","fan","faucet","file","filter",
  "flag","flashlight","folder","fork","frame","funnel","gadget","gauge","gear","glass",
  "glove","goggles","grate","grinder","hammer","handle","hanger","harness","hatchet","headlamp",
  "helmet","hinge","hoe","hook","hose","jack","jar","jug","kettle","key",
  "knife","knob","ladder","lamp","lantern","lens","lever","lid","lock","magnet",
  "mallet","mask","mat","mattress","meter","mirror","mop","nail","needle","net",
  "notebook","nozzle","nut","oar","paddle","padlock","pail","pan","panel","peg",
  "pencil","pin","pipe","pitcher","pliers","pot","pouch","pulley","pump","puzzle",
  "rack","radio","rail","rake","ratchet","razor","reel","ring","rivet","rope",
  "ruler","sack","saddle","safe","sail","satchel","saw","scale","scissors","screw",
  "screwdriver","shears","shelf","shield","shovel","sickle","sieve","sign","socket","spade",
  "spanner","spatula","sponge","spoon","spring","spyglass","staple","statue","stove","strap",
  "string","switch","syringe","table","tape","tarp","thermometer","thimble","thread","timer",
  "tongs","torch","towel","tray","trowel","trunk","tube","tweezers","umbrella","valve",
  "vase","vessel","vial","vise","wallet","wand","washer","wedge","wheel","whistle",
  "wick","winch","wire","wrench","zipper",
  // Vehicles
  "airplane","ambulance","balloon","barge","bicycle","biplane","boat","bulldozer","bus","canoe",
  "car","caravan","carriage","catamaran","chariot","chopper","coach","convertible","cruiser","dinghy",
  "dirigible","dumptruck","ferry","forklift","freighter","glider","gondola","helicopter","hovercraft","jeep",
  "jet","jetski","kayak","limousine","locomotive","minivan","monorail","moped","motorbike","motorcycle",
  "pickup","plane","raft","rickshaw","rocket","rover","scooter","sedan","ship","skateboard",
  "sled","sleigh","snowmobile","spaceship","speedboat","streetcar","submarine","subway","taxi","tanker",
  "tractor","trailer","train","tram","tricycle","trolley","truck","tugboat","van","wagon","yacht",
  // Sports and games
  "archery","badminton","baseball","basketball","biathlon","billiards","bobsled","boxing","bowling","canoeing",
  "checkers","chess","cricket","croquet","curling","cycling","darts","decathlon","diving","dodgeball",
  "domino","equestrian","fencing","football","frisbee","golf","gymnastics","handball","hiking","hockey",
  "hurdles","javelin","judo","karate","kayaking","kickball","lacrosse","luge","marathon","netball",
  "paintball","parkour","pentathlon","pilates","pingpong","polo","racing","racquetball","rafting","rowing",
  "rugby","running","sailing","shooting","skating","skiing","sledding","snowboarding","soccer","softball",
  "squash","sumo","surfing","swimming","taekwondo","tennis","tetherball","trampoline","triathlon","volleyball",
  "weightlifting","wrestling","yoga","zumba",
  // Music and instruments
  "accordion","anthem","arrangement","ballad","banjo","baritone","bassoon","beat","cadence","cello",
  "chant","chord","chorus","clarinet","concert","contralto","cymbal","drum","duet","ensemble",
  "flute","fugue","glockenspiel","guitar","harmony","harp","harmonica","hymn","jazz","keyboard",
  "lullaby","lyric","mandolin","maestro","melody","mixer","oboe","opera","orchestra","organ",
  "overture","percussion","piano","piccolo","pitch","quartet","recital","rhythm","saxophone","serenade",
  "sonata","soprano","symphony","tempo","trumpet","tuba","ukulele","viola","violin","vocal","xylophone",
  // Emotions and traits
  "adventurous","affectionate","agreeable","ambitious","amiable","artistic","attentive","bold","brave","bright",
  "calm","candid","capable","careful","caring","cautious","cheerful","clever","compassionate","confident",
  "considerate","courageous","courteous","creative","curious","daring","decisive","dedicated","dependable","determined",
  "devoted","diligent","diplomatic","discreet","dutiful","eager","earnest","easygoing","elegant","empathetic",
  "energetic","enthusiastic","faithful","fearless","flexible","focused","forgiving","frank","friendly","generous",
  "gentle","genuine","gracious","grateful","happy","hardworking","helpful","honest","hopeful","humble",
  "humorous","imaginative","independent","industrious","ingenious","innovative","insightful","inspiring","intelligent","intuitive",
  "inventive","joyful","judicious","keen","kind","knowledgeable","lively","logical","loving","loyal",
  "mindful","modest","motivated","neat","noble","observant","optimistic","organized","original","outgoing",
  "passionate","patient","peaceful","perceptive","persistent","playful","polite","positive","practical","pragmatic",
  "precise","principled","proactive","punctual","quiet","rational","reliable","resilient","resourceful","respectful",
  "responsible","sensible","sincere","skillful","sociable","spirited","spontaneous","steadfast","strong","supportive",
  "sympathetic","tactful","talented","tenacious","thoughtful","thorough","tolerant","trustworthy","understanding","upbeat",
  "versatile","vibrant","virtuous","warm","wise","witty","zealous",
  // Common verbs
  "accept","achieve","act","adapt","add","address","adjust","admire","admit","advance",
  "advise","agree","aim","allow","analyze","announce","answer","appear","apply","approach",
  "argue","arrange","arrive","ask","assist","assume","assure","attach","attack","attempt",
  "attend","avoid","awake","bake","balance","begin","believe","belong","bend","bind",
  "bite","blend","block","blow","boil","borrow","bounce","break","breathe","build",
  "burn","buy","calculate","call","care","carry","catch","cause","celebrate","change",
  "charge","chase","check","choose","claim","clean","climb","close","collect","combine",
  "command","communicate","compare","compete","complain","complete","compose","connect","consider","construct",
  "contain","continue","control","convert","cook","copy","correct","count","cover","crash",
  "create","cross","cry","cut","dance","decide","defend","define","deliver","demand",
  "describe","design","destroy","detect","develop","differ","dig","direct","discover","discuss",
  "dismiss","display","dive","divide","draw","dream","drift","drive","drop","earn",
  "eat","edit","educate","elect","embrace","emerge","employ","enable","encourage","engage",
  "enjoy","ensure","enter","escape","establish","examine","exceed","exchange","exercise","exist",
  "expand","expect","experience","explain","explore","express","extend","face","fail","fall",
  "feed","feel","fight","fill","find","finish","fix","float","flow","fly",
  "focus","follow","forget","form","gain","gather","generate","give","grab","grasp",
  "greet","grow","guard","guess","guide","handle","hang","happen","harvest","heal",
  "hear","help","hide","hike","hold","hope","hunt","identify","ignore","imagine",
  "implement","improve","include","increase","indicate","influence","inform","inspect","install","intend",
  "interact","introduce","invent","invest","investigate","invite","join","judge","jump","keep",
  "kick","kiss","knock","know","land","laugh","launch","lead","learn","leave",
  "lend","lift","light","limit","listen","live","load","locate","lock","look",
  "lose","love","maintain","manage","march","mark","match","measure","meet","melt",
  "mention","merge","mix","monitor","move","name","navigate","need","negotiate","notice",
  "obey","observe","obtain","occur","offer","open","operate","order","organize","paint",
  "park","participate","pass","patrol","pause","pay","perform","permit","persuade","pick",
  "place","plan","plant","play","point","polish","post","pour","practice","praise",
  "predict","prefer","prepare","present","preserve","press","prevent","print","produce","promise",
  "promote","propose","protect","prove","provide","publish","pull","punch","purchase","push",
  "question","race","raise","reach","react","read","realize","receive","recognize","recommend",
  "record","recover","reduce","refer","reflect","refuse","regard","register","reject","relate",
  "release","rely","remain","remember","remind","remove","repair","repeat","replace","reply",
  "report","represent","request","require","rescue","research","resolve","respond","rest","restore",
  "result","retain","retreat","return","reveal","review","ride","ring","rise","risk",
  "roll","rotate","rule","run","save","scan","scare","scatter","schedule","scream",
  "search","secure","seek","select","sell","send","sense","separate","serve","settle",
  "share","shift","shine","shoot","shop","shout","show","shrink","sign","signal",
  "sing","sink","sketch","ski","sleep","slide","slip","smell","smile","snap",
  "solve","sort","sound","speak","spend","spin","split","spread","stand","start",
  "state","stay","steal","steer","step","stick","stop","store","strengthen","stretch",
  "strike","study","submit","succeed","suggest","summarize","supply","support","suppose","surprise",
  "surround","survive","suspect","swim","switch","take","talk","teach","tear","tell",
  "test","thank","think","throw","tie","touch","trace","track","trade","train",
  "translate","transport","travel","treat","trigger","trust","try","turn","understand","unite",
  "update","use","verify","view","visit","vote","wait","wake","walk","want",
  "warn","wash","watch","wave","wear","weigh","welcome","win","wish","withdraw",
  "wonder","work","wrap","write","yell","yield",
  // Common adjectives
  "able","absolute","abundant","active","actual","adequate","admirable","adorable","ancient","angry",
  "anxious","appropriate","average","awesome","awful","beautiful","bitter","bland","bleak","blunt",
  "boring","brief","brilliant","broad","broken","busy","casual","certain","cheap","classic",
  "clear","close","cold","common","complex","constant","cool","correct","crazy","crisp",
  "critical","crowded","cruel","current","curved","cute","damp","dangerous","dark","dead",
  "deep","delicate","dense","dry","dull","early","easy","empty","enormous","equal",
  "even","exact","excellent","exotic","expensive","extreme","faint","fair","familiar","famous",
  "fancy","fast","fat","faulty","favorite","feeble","fierce","fine","firm","flat",
  "fond","foolish","foreign","fragile","fresh","frozen","full","funny","fuzzy","giant",
  "gigantic","glad","gleaming","glossy","golden","good","gorgeous","graceful","grand","greasy",
  "great","grim","gritty","harsh","healthy","heavy","hidden","hollow","huge","hungry",
  "icy","ideal","immense","important","impressive","incredible","innocent","intense","intricate","jagged",
  "jolly","large","late","lavish","lean","legal","light","likely","limited","little",
  "local","loose","loud","lovely","low","lucky","mad","magic","major","massive",
  "mature","mellow","minor","mixed","modern","moist","muddy","narrow","natural","nearby",
  "nervous","noisy","normal","obvious","odd","ordinary","ornate","outstanding","painful","pale",
  "perfect","permanent","personal","plain","pleasant","polished","poor","popular","possible","powerful",
  "precious","pretty","prime","private","proper","proud","public","pure","quaint","quick",
  "rapid","rare","raw","ready","real","recent","remote","rich","rigid","robust",
  "rough","round","royal","rude","rugged","rusty","sacred","sad","safe","salty",
  "sandy","savage","scarce","scary","secret","secure","serious","sharp","shiny","short",
  "shy","silent","silly","simple","sincere","single","skinny","sleek","slick","slim",
  "slippery","slow","small","smart","smooth","soft","solid","sour","spare","sparse",
  "special","specific","splendid","spotless","square","stale","steady","steep","sticky","stiff",
  "still","straight","strange","strict","strong","stunning","sturdy","subtle","sudden","superb",
  "superior","supreme","sweet","swift","tall","tame","tasty","tender","tense","terrible",
  "thick","thin","tidy","tight","tiny","tired","tough","tranquil","transparent","tremendous",
  "tricky","true","twin","ugly","unique","unusual","upset","urgent","useful","usual",
  "vague","valid","valuable","vast","vibrant","vicious","violent","visible","vivid","wandering",
  "weak","wealthy","weary","weird","wet","wide","wild","worn","worried","worthy","young","zesty",
  // General nouns
  "adventure","agency","album","alliance","ambition","angle","apex","arena","argument","arrow",
  "article","aspect","assembly","asset","atom","attention","attitude","audience","authority","avenue",
  "award","banner","barrier","battle","beacon","belief","benefit","blessing","bond","bonus",
  "boundary","breakthrough","budget","bundle","burden","cabin","campaign","capsule","career","cargo",
  "carnival","castle","category","celebration","ceremony","challenge","champion","chance","channel","chapter",
  "character","charity","charm","checkpoint","choice","circle","circuit","citadel","citizen","civilization",
  "claim","cluster","code","collection","colony","column","comfort","comment","commitment","committee",
  "community","company","comparison","competition","component","concept","concern","conclusion","condition","conference",
  "confidence","conflict","connection","consequence","contact","content","context","contract","contrast","contribution",
  "convention","conversation","corner","council","county","courage","course","court","craft","creation",
  "credit","crew","crisis","crown","crystal","culture","curiosity","curve","custom","cycle",
  "deadline","debate","decade","decision","dedication","defense","delight","demand","department","design",
  "desire","destination","detail","development","device","dialogue","diamond","difference","dignity","dimension",
  "direction","disaster","discipline","discount","discovery","discussion","disease","distance","district","diversity",
  "division","document","domain","dominion","dose","doubt","drama","dream","duration","duty",
  "dynasty","echo","economy","edge","effect","effort","element","elevation","embassy","emblem",
  "emotion","emphasis","empire","energy","entity","environment","episode","equation","era","essay",
  "essence","estate","evening","event","evidence","example","exchange","exhibit","existence","exit",
  "expansion","experiment","expert","expression","extension","factor","faculty","fame","family","fantasy",
  "feast","feature","fee","festival","fiction","field","figure","finale","finance","flavor",
  "foundation","fraction","fragment","freedom","frequency","friction","frontier","fuel","function","fund",
  "fusion","future","gallery","garden","gathering","gem","gender","generation","genius","genre",
  "gesture","ghost","gift","glimpse","glory","goal","government","grace","grade","grain",
  "grant","gravity","ground","group","growth","guardian","guest","guild","habit","habitat",
  "harvest","haven","heritage","hero","hierarchy","highlight","history","honor","host","hub",
  "hypothesis","icon","identity","illusion","image","impact","impulse","incident","income","index",
  "industry","influence","initiative","injury","insight","inspiration","instance","institute","instrument","insurance",
  "integrity","intent","interest","interval","interview","invention","investment","invitation","issue","item",
  "journey","joy","judgment","junction","justice","kernel","kingdom","knowledge","label","labor",
  "landmark","language","layer","leadership","league","leap","lecture","legacy","legend","level",
  "liberty","license","lifestyle","limit","lineage","link","list","literature","logic","loop",
  "lore","loyalty","luxury","magnitude","majority","manner","manual","margin","market","marvel",
  "mass","master","matter","maze","meaning","measure","medal","media","memory","mentor",
  "merit","message","method","milestone","mind","mineral","minute","miracle","mission","mixture",
  "mode","model","module","moment","momentum","monument","morale","motion","motive","movement",
  "mystery","myth","narrative","nation","nature","network","node","notion","novel","nucleus",
  "number","oath","objective","obligation","occasion","offering","official","opening","opinion","opportunity",
  "option","orbit","order","organism","origin","outcome","outlet","output","overview","ownership",
  "package","page","palace","panel","paradigm","paradox","paragraph","parcel","partner","passage",
  "passion","path","pattern","penalty","perception","performance","perimeter","period","permission","perspective",
  "phase","phenomenon","philosophy","phrase","picture","piece","pillar","pioneer","plan","platform",
  "plot","poem","point","policy","portal","portfolio","portion","position","possibility","potential",
  "power","practice","precedent","preference","premise","presence","presentation","principle","priority","privilege",
  "prize","problem","procedure","process","product","profile","program","progress","project","promise",
  "proof","proposal","prospect","protocol","prototype","province","purpose","puzzle","quality","quantity",
  "quarter","quest","question","quota","race","range","rank","rate","ratio","reaction",
  "realm","reason","rebellion","receipt","recipe","recovery","region","relation","relationship","remedy",
  "reputation","requirement","reserve","resistance","resolution","resource","response","revenue","revolution","reward",
  "rhythm","ritual","role","root","route","routine","sample","sanctuary","scenario","scene",
  "scheme","scope","score","sculpture","season","sector","segment","sentence","sequence","series",
  "session","setting","shape","shelter","significance","site","situation","skill","society","solution",
  "source","space","specimen","spectrum","sphere","spirit","sponsor","stage","standard","standpoint",
  "statement","station","status","step","stimulus","story","strategy","strength","structure","style",
  "subject","substance","success","summary","supply","surface","survey","symbol","symmetry","sympathy",
  "system","tactic","talent","target","task","team","technique","temple","tendency","tension",
  "term","territory","testimony","text","texture","theme","theory","thought","threshold","title",
  "token","tone","topic","tournament","tower","trace","tradition","trail","trait","transaction",
  "transformation","transition","treasure","treaty","trend","tribe","trilogy","triumph","trophy","trust",
  "truth","tunnel","unit","unity","universe","upgrade","vacancy","valley","value","variable",
  "variety","vault","vehicle","venture","verdict","verse","version","vessel","veteran","victory",
  "vision","visitor","vista","vocabulary","voice","volume","voyage","wage","warehouse","warning",
  "wealth","wing","wisdom","witness","wonder","workshop","world","worth","zeal","zenith","zone",
  // Technology and security
  "algorithm","api","array","backdoor","backup","bandwidth","binary","biometric","bitcoin","blockchain",
  "botnet","breach","browser","buffer","bug","byte","cache","certificate","cipher","cloud",
  "cluster","codebase","command","compiler","compute","config","console","cookie","credential","cryptography",
  "dashboard","database","daemon","debug","decrypt","deploy","desktop","digest","directory","domain",
  "download","encrypt","endpoint","ethernet","exploit","firewall","firmware","framework","gateway","hacker",
  "handshake","hardware","hash","header","honeypot","host","hyperlink","inject","interface","kernel",
  "keyword","keystroke","latency","ledger","library","login","malware","metric","middleware","module",
  "offline","packet","password","patch","payload","phishing","pipeline","pixel","platform","plugin",
  "pointer","port","process","protocol","proxy","query","queue","ransomware","repository","router",
  "runtime","sandbox","script","sensor","server","session","shell","signal","socket","software",
  "spyware","stack","storage","subnet","syntax","sysadmin","terminal","thread","token","trojan",
  "tunnel","upload","username","variable","vector","virus","vulnerability","webhook","wireless","worm",
  // Places
  "airport","alley","bakery","bank","bazaar","boulevard","bridge","building","cabin","cafe",
  "campsite","campus","canal","capital","cathedral","cemetery","chapel","church","cinema","clinic",
  "college","corridor","cottage","country","courtyard","depot","dock","dormitory","downtown","embassy",
  "factory","farm","fortress","foundry","garage","garden","gate","ghetto","grove","hamlet",
  "harbor","highway","hospital","hostel","hotel","house","hut","inn","junction","laboratory",
  "lane","lighthouse","lodge","lookout","mall","manor","marketplace","memorial","metropolis","mill",
  "mine","monastery","motel","museum","neighborhood","observatory","orchard","outpost","parish","parking",
  "pasture","pavilion","pharmacy","pier","plaza","prison","quarry","ranch","refuge","resort",
  "restaurant","road","school","seaport","settlement","shrine","square","stable","stadium","station",
  "street","studio","suburb","terminal","theatre","town","trail","university","village","vineyard",
  "ward","waterfront","wharf","workshop","yard",
  // Clothing
  "armor","bandana","bathrobe","beanie","blazer","blouse","boot","bowtie","cardigan","cloak",
  "coat","collar","costume","cufflink","earring","gown","headband","hoodie","jacket","jeans",
  "jersey","kilt","kimono","legging","mitten","moccasin","necklace","necktie","overalls","pajama",
  "parka","poncho","pullover","sandal","scarf","shawl","shirt","shoe","shorts","skirt",
  "sneaker","sweater","trousers","tunic","turban","uniform","veil","vest","waistcoat",
  // Plants and trees
  "acacia","algae","aloe","azalea","bamboo","basil","birch","blossom","bluebell","bramble",
  "briar","buckthorn","bulb","bush","cactus","camellia","carnation","cedar","chrysanthemum","clover",
  "conifer","cypress","daffodil","daisy","dandelion","elm","eucalyptus","fern","fir","foxglove",
  "fungus","gardenia","geranium","ginseng","hawthorn","heather","hemlock","hibiscus","holly","honeysuckle",
  "ivy","jasmine","juniper","lichen","magnolia","marigold","mulberry","oak","orchid","palm",
  "pansy","peony","petunia","pine","poppy","redwood","sequoia","spruce","sunflower","thistle",
  "tulip","willow","wisteria",
  // Space and astronomy
  "andromeda","asteroid","astronaut","atmosphere","aurora","blackhole","celestial","comet","constellation","cosmos",
  "crater","crescent","eclipse","equinox","galaxy","gravity","horizon","jupiter","launchpad","lightyear",
  "lunar","mars","mercury","meteorite","milkyway","moon","nebula","neptune","nova","orbit",
  "orion","pluto","pulsar","quasar","rocket","satellite","saturn","shuttle","solstice","spacecraft",
  "spaceship","spacesuit","spacewalk","star","stardust","stargazer","sun","supernova","telescope","thruster",
  "universe","uranus","venus","void","zenith",
];

const WORDLIST = [...new Set(WORDLIST_RAW)];

function secureRandomInt(maxExclusive) {
  // Rejection sampling against crypto.getRandomValues to avoid modulo bias.
  const range = maxExclusive;
  const bytesNeeded = Math.ceil(Math.log2(range) / 8) || 1;
  const maxValid = Math.floor(256 ** bytesNeeded / range) * range;
  const arr = new Uint8Array(bytesNeeded);
  let value;
  do {
    crypto.getRandomValues(arr);
    value = 0;
    for (let i = 0; i < bytesNeeded; i++) value = value * 256 + arr[i];
  } while (value >= maxValid);
  return value % range;
}

function pickRandom(list) {
  return list[secureRandomInt(list.length)];
}

function generateRandomPassword(length, opts) {
  let pool = "";
  if (opts.lower) pool += "abcdefghijklmnopqrstuvwxyz";
  if (opts.upper) pool += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  if (opts.digits) pool += "0123456789";
  if (opts.symbols) pool += "!@#$%^&*()-_=+[]{};:,.<>/?~";
  if (opts.custom) pool += opts.custom;
  if (opts.excludeAmbiguous) pool = pool.replace(/[Il1O0o]/g, "");
  pool = [...new Set(pool.split(""))].join("");
  if (!pool) throw new Error("Select at least one character set");
  let out = "";
  for (let i = 0; i < length; i++) out += pool[secureRandomInt(pool.length)];
  return out;
}

function generatePassphrase(wordCount, separator, opts) {
  const words = [];
  for (let i = 0; i < wordCount; i++) {
    let w = pickRandom(WORDLIST);
    if (opts.capitalize) w = w[0].toUpperCase() + w.slice(1);
    words.push(w);
  }
  let phrase = words.join(separator);
  if (opts.appendNumber) phrase += separator + secureRandomInt(10000);
  return phrase;
}

function renderPasswordGenerator(root) {
  root.innerHTML = `
    <div class="tk-section">
    <h2 class="pg-h2">Password / Passphrase Generator</h2>
    <p class="muted">Both modes use <code>crypto.getRandomValues</code> (a cryptographically
      secure RNG) with rejection sampling, never <code>Math.random</code>. Random-character
      passwords maximize entropy per character; passphrases built from this ${WORDLIST.length}-word
      list trade a few extra characters for something a human can actually remember and type.</p>

    <div class="tab-bar" id="pg-mode" style="margin-top:10px">
      <button class="tab active" data-mode="password">Random password</button>
      <button class="tab" data-mode="passphrase">Passphrase</button>
    </div>

    <div id="pg-password-panel">
      <div class="tk-row" style="margin-top:14px;align-items:center">
        <label class="muted mono">Length: <span id="pg-len-val">16</span></label>
        <input type="range" id="pg-len" min="4" max="128" value="16" style="flex:1">
      </div>
      <div class="tk-row" style="flex-wrap:wrap;gap:14px">
        <label class="muted mono"><input type="checkbox" id="pg-lower" checked> lowercase a-z</label>
        <label class="muted mono"><input type="checkbox" id="pg-upper" checked> uppercase A-Z</label>
        <label class="muted mono"><input type="checkbox" id="pg-digits" checked> digits 0-9</label>
        <label class="muted mono"><input type="checkbox" id="pg-symbols" checked> symbols !@#$...</label>
        <label class="muted mono"><input type="checkbox" id="pg-ambig"> exclude ambiguous (Il1O0o)</label>
      </div>
      <div class="tk-row">
        <input class="tk-f" id="pg-custom" placeholder="Extra custom characters to include (optional)">
        <input class="tk-f" id="pg-count" placeholder="How many passwords?" value="5" style="max-width:160px">
      </div>
    </div>

    <div id="pg-passphrase-panel" style="display:none">
      <div class="tk-row" style="margin-top:14px;align-items:center">
        <label class="muted mono">Words: <span id="pg-words-val">5</span></label>
        <input type="range" id="pg-words" min="2" max="12" value="5" style="flex:1">
      </div>
      <div class="tk-row">
        <input class="tk-f" id="pg-sep" placeholder="Separator" value="-" style="max-width:140px">
        <label class="muted mono"><input type="checkbox" id="pg-cap" checked> Capitalize each word</label>
        <label class="muted mono"><input type="checkbox" id="pg-appendnum"> Append random number</label>
        <input class="tk-f" id="pg-pcount" placeholder="How many phrases?" value="5" style="max-width:160px">
      </div>
    </div>

    <div class="tk-btns">
      <button class="btn sm" id="pg-generate">Generate</button>
      <button class="btn sm ghost" id="pg-copyall">Copy all</button>
    </div>
    <pre class="tk-out" id="pg-out" style="min-height:200px"></pre>
    <div id="pg-strength"></div>
    </div>
  `;

  const modeBar = root.querySelector("#pg-mode");
  const pwPanel = root.querySelector("#pg-password-panel");
  const ppPanel = root.querySelector("#pg-passphrase-panel");
  const out = root.querySelector("#pg-out");
  const strength = root.querySelector("#pg-strength");

  let mode = "password";
  let lastResults = [];

  modeBar.onclick = (e) => {
    const btn = e.target.closest("button[data-mode]");
    if (!btn) return;
    mode = btn.dataset.mode;
    for (const b of modeBar.querySelectorAll(".tab")) b.classList.toggle("active", b === btn);
    pwPanel.style.display = mode === "password" ? "" : "none";
    ppPanel.style.display = mode === "passphrase" ? "" : "none";
  };

  const lenSlider = root.querySelector("#pg-len");
  const lenVal = root.querySelector("#pg-len-val");
  lenSlider.oninput = () => { lenVal.textContent = lenSlider.value; };

  const wordsSlider = root.querySelector("#pg-words");
  const wordsVal = root.querySelector("#pg-words-val");
  wordsSlider.oninput = () => { wordsVal.textContent = wordsSlider.value; };

  root.querySelector("#pg-generate").onclick = generate;
  root.querySelector("#pg-copyall").onclick = () => copyText(lastResults.join("\n"));

  function generate() {
    lastResults = [];
    if (mode === "password") {
      const length = +lenSlider.value;
      const count = clamp(parseInt(root.querySelector("#pg-count").value) || 1, 1, 50);
      const opts = {
        lower: root.querySelector("#pg-lower").checked,
        upper: root.querySelector("#pg-upper").checked,
        digits: root.querySelector("#pg-digits").checked,
        symbols: root.querySelector("#pg-symbols").checked,
        custom: root.querySelector("#pg-custom").value,
        excludeAmbiguous: root.querySelector("#pg-ambig").checked,
      };
      try {
        for (let i = 0; i < count; i++) lastResults.push(generateRandomPassword(length, opts));
        out.textContent = lastResults.join("\n");
        const { poolSize } = analyzePasswordCharsets(lastResults[0]);
        const bits = length * Math.log2(Math.max(poolSize, 1));
        strength.innerHTML = `<p class="muted">Estimated entropy: ~${bits.toFixed(1)} bits per password (pool size ${poolSize}, length ${length}).</p>`;
      } catch (err) {
        out.textContent = "Error: " + err.message;
      }
    } else {
      const wordCount = +wordsSlider.value;
      const separator = root.querySelector("#pg-sep").value || "-";
      const count = clamp(parseInt(root.querySelector("#pg-pcount").value) || 1, 1, 50);
      const opts = {
        capitalize: root.querySelector("#pg-cap").checked,
        appendNumber: root.querySelector("#pg-appendnum").checked,
      };
      for (let i = 0; i < count; i++) lastResults.push(generatePassphrase(wordCount, separator, opts));
      out.textContent = lastResults.join("\n");
      const bitsPerWord = Math.log2(WORDLIST.length);
      const totalBits = bitsPerWord * wordCount + (opts.appendNumber ? Math.log2(10000) : 0);
      strength.innerHTML = `<p class="muted">Wordlist has ${WORDLIST.length} unique words
        (~${bitsPerWord.toFixed(2)} bits per word). ${wordCount} words${opts.appendNumber ? " + a random number" : ""}
        gives ~${totalBits.toFixed(1)} bits of entropy total.</p>`;
    }
  }

  generate();
}

registerTab("passgen", "Password Generator", renderPasswordGenerator);

// ---------------------------------------------------------------------------
// Tool 11: Base Encoding (16 / 32 / 58 / 64 / 85)
// ---------------------------------------------------------------------------
//
// Every base-N text encoding does the same fundamental thing: treat the
// input as a big number (or a bit stream) and re-express it using an
// alphabet of N symbols so it's safe to embed in contexts that only accept
// a limited character set (URLs, JSON, binary protocols, source code
// literals...). Base64 and Base16 are implemented via the browser's native
// primitives where possible; Base32, Base58, and Base85 are implemented
// from scratch below since the browser has no built-in support for them.

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base16Encode(bytes) { return bytesToHex(bytes).toUpperCase(); }
function base16Decode(str) { return hexToBytes(str); }

function base32Encode(bytes) {
  let bits = "";
  for (const b of bytes) bits += b.toString(2).padStart(8, "0");
  let out = "";
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.slice(i, i + 5).padEnd(5, "0");
    out += BASE32_ALPHABET[parseInt(chunk, 2)];
  }
  while (out.length % 8 !== 0) out += "=";
  return out;
}

function base32Decode(str) {
  const clean = str.trim().toUpperCase().replace(/=+$/g, "");
  let bits = "";
  for (const ch of clean) {
    const index = BASE32_ALPHABET.indexOf(ch);
    if (index === -1) throw new Error(`Invalid Base32 character: ${ch}`);
    bits += index.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(bytes);
}

function base58Encode(bytes) {
  if (bytes.length === 0) return "";
  let value = 0n;
  for (const b of bytes) value = value * 256n + BigInt(b);
  let out = "";
  while (value > 0n) {
    const rem = value % 58n;
    out = BASE58_ALPHABET[Number(rem)] + out;
    value /= 58n;
  }
  let leadingZeros = 0;
  for (const b of bytes) { if (b === 0) leadingZeros++; else break; }
  return BASE58_ALPHABET[0].repeat(leadingZeros) + out;
}

function base58Decode(str) {
  const clean = str.trim();
  if (clean === "") return new Uint8Array(0);
  let value = 0n;
  for (const ch of clean) {
    const index = BASE58_ALPHABET.indexOf(ch);
    if (index === -1) throw new Error(`Invalid Base58 character: ${ch}`);
    value = value * 58n + BigInt(index);
  }
  let hex = value.toString(16);
  if (hex.length % 2 !== 0) hex = "0" + hex;
  // Guard on the value, not the padded hex: when value is 0 (input is all
  // leading '1's) hex has already become "00", so a `hex === "0"` check would
  // never fire and an extra zero byte would be appended on top of leadingZeros.
  const bytes = value === 0n ? [] : [...hexToBytes(hex)];
  let leadingZeros = 0;
  for (const ch of clean) { if (ch === BASE58_ALPHABET[0]) leadingZeros++; else break; }
  return new Uint8Array([...new Array(leadingZeros).fill(0), ...bytes]);
}

// Base85 / ASCII85, Adobe variant (no <~ ~> delimiters, but 'z' shorthand
// for an all-zero 4-byte group is supported both ways).
function base85Encode(bytes) {
  let out = "";
  const padded = new Uint8Array(Math.ceil(bytes.length / 4) * 4);
  padded.set(bytes);
  const padLen = padded.length - bytes.length;
  for (let i = 0; i < padded.length; i += 4) {
    const chunk = (padded[i] * 16777216) + (padded[i + 1] * 65536) + (padded[i + 2] * 256) + padded[i + 3];
    if (chunk === 0 && i + 4 <= bytes.length) { out += "z"; continue; }
    const digits = [];
    let n = chunk;
    for (let j = 0; j < 5; j++) { digits.unshift(n % 85); n = Math.floor(n / 85); }
    out += digits.map((d) => String.fromCharCode(d + 33)).join("");
  }
  if (padLen > 0) out = out.slice(0, out.length - padLen);
  return out;
}

function base85Decode(str) {
  const clean = str.trim().replace(/z/g, "!!!!!");
  const bytesOut = [];
  for (let i = 0; i < clean.length; i += 5) {
    let chunkStr = clean.slice(i, i + 5);
    const padLen = 5 - chunkStr.length;
    chunkStr = chunkStr.padEnd(5, "u");
    let value = 0;
    for (const ch of chunkStr) {
      const code = ch.charCodeAt(0) - 33;
      if (code < 0 || code > 84) throw new Error(`Invalid Base85 character: ${ch}`);
      value = value * 85 + code;
    }
    const b = [(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff];
    bytesOut.push(...(padLen > 0 ? b.slice(0, 4 - padLen) : b));
  }
  return new Uint8Array(bytesOut);
}

const BASE_ENCODERS = {
  "Base16 (hex)": { encode: base16Encode, decode: base16Decode },
  "Base32": { encode: base32Encode, decode: base32Decode },
  "Base58": { encode: base58Encode, decode: base58Decode },
  "Base64": { encode: bytesToBase64, decode: base64ToBytes },
  "Base85 (ASCII85)": { encode: base85Encode, decode: base85Decode },
};

function renderBaseEncoding(root) {
  root.innerHTML = `
    <div class="tk-section">
    <h2 class="pg-h2">Base Encoding</h2>
    <p class="muted">Convert text or bytes between Base16 (hex), Base32 (RFC 4648, used in TOTP
      secrets and DNS), Base58 (Bitcoin/IPFS-style, no visually ambiguous characters), Base64
      (the ubiquitous web/email encoding), and Base85/ASCII85 (denser than Base64, used in
      Adobe PostScript/PDF). All five are implemented here so you can see exactly how each
      alphabet re-packs the underlying bits.</p>
    <div class="tk-row">
      <textarea class="tk-in" id="be-in" rows="4" placeholder="Text to encode, or an encoded string to decode..." style="flex:2"></textarea>
      <div style="flex:1;display:flex;flex-direction:column;gap:8px">
        <label class="muted mono" style="font-size:12px"><input type="radio" name="be-fmt" value="text" checked> Input is plain text</label>
        <label class="muted mono" style="font-size:12px"><input type="radio" name="be-fmt" value="hex"> Input is hex bytes</label>
      </div>
    </div>
    <div class="tk-btns" id="be-encode-btns"></div>
    <div class="tk-btns" id="be-decode-btns" style="margin-top:6px"></div>
    <pre class="tk-out" id="be-out" style="min-height:220px"></pre>
    </div>

    <div class="tk-section">
    <h2 class="pg-h2">Encode to every base at once</h2>
    <div class="tk-btns"><button class="btn sm" id="be-all">Show all encodings</button></div>
    <pre class="tk-out" id="be-all-out"></pre>
    </div>
  `;

  const inp = root.querySelector("#be-in");
  const out = root.querySelector("#be-out");
  const allOut = root.querySelector("#be-all-out");
  const encodeBtns = root.querySelector("#be-encode-btns");
  const decodeBtns = root.querySelector("#be-decode-btns");

  encodeBtns.innerHTML = Object.keys(BASE_ENCODERS).map((name) => `<button class="btn sm" data-enc="${name}">Encode ${name}</button>`).join("");
  decodeBtns.innerHTML = Object.keys(BASE_ENCODERS).map((name) => `<button class="btn sm ghost" data-dec="${name}">Decode ${name}</button>`).join("");

  function getInputBytes() {
    const fmt = root.querySelector('input[name="be-fmt"]:checked').value;
    return fmt === "hex" ? hexToBytes(inp.value) : textToBytes(inp.value);
  }

  encodeBtns.onclick = (e) => {
    const btn = e.target.closest("button[data-enc]"); if (!btn) return;
    try {
      const bytes = getInputBytes();
      out.textContent = BASE_ENCODERS[btn.dataset.enc].encode(bytes);
    } catch (err) { out.textContent = "Error: " + err.message; }
  };

  decodeBtns.onclick = (e) => {
    const btn = e.target.closest("button[data-dec]"); if (!btn) return;
    try {
      const decoded = BASE_ENCODERS[btn.dataset.dec].decode(inp.value);
      let text;
      try { text = bytesToText(decoded); } catch { text = null; }
      out.textContent = `Hex:  ${bytesToHex(decoded)}\nText: ${text !== null ? text : "(not valid UTF-8 -- see hex above)"}`;
    } catch (err) { out.textContent = "Error: " + err.message; }
  };

  root.querySelector("#be-all").onclick = () => {
    try {
      const bytes = getInputBytes();
      allOut.textContent = Object.entries(BASE_ENCODERS).map(([name, codec]) => `${name.padEnd(20)} ${codec.encode(bytes)}`).join("\n");
    } catch (err) { allOut.textContent = "Error: " + err.message; }
  };
}

registerTab("baseenc", "Base Encoding", renderBaseEncoding);

// ---------------------------------------------------------------------------
// Tool 12: Morse Code
// ---------------------------------------------------------------------------

const MORSE_TABLE = {
  A: ".-", B: "-...", C: "-.-.", D: "-..", E: ".", F: "..-.", G: "--.",
  H: "....", I: "..", J: ".---", K: "-.-", L: ".-..", M: "--", N: "-.",
  O: "---", P: ".--.", Q: "--.-", R: ".-.", S: "...", T: "-", U: "..-",
  V: "...-", W: ".--", X: "-..-", Y: "-.--", Z: "--..",
  "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
  "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.",
  ".": ".-.-.-", ",": "--..--", "?": "..--..", "'": ".----.", "!": "-.-.--",
  "/": "-..-.", "(": "-.--.", ")": "-.--.-", "&": ".-...", ":": "---...",
  ";": "-.-.-.", "=": "-...-", "+": ".-.-.", "-": "-....-", "_": "..--.-",
  '"': ".-..-.", "$": "...-..-", "@": ".--.-.", " ": "/",
};

const MORSE_TABLE_REVERSE = Object.fromEntries(Object.entries(MORSE_TABLE).map(([k, v]) => [v, k]));

function textToMorse(text) {
  return text.toUpperCase().split("").map((ch) => {
    if (ch === " ") return "/";
    if (!(ch in MORSE_TABLE)) return "";
    return MORSE_TABLE[ch];
  }).filter(Boolean).join(" ");
}

function morseToText(morse) {
  return morse.trim().split(/\s+/).map((code) => {
    if (code === "/") return " ";
    return MORSE_TABLE_REVERSE[code] || "?";
  }).join("");
}

function renderMorse(root) {
  root.innerHTML = `
    <div class="tk-section">
    <h2 class="pg-h2">Morse Code</h2>
    <p class="muted">Encodes/decodes the international Morse code standard: letters, digits, and
      common punctuation. Dots and dashes are separated by spaces; a forward slash marks a word
      break. Includes an audio playback preview using the Web Audio API.</p>
    <textarea class="tk-in" id="mc-in" rows="4" placeholder="Text, or Morse code (dots/dashes separated by spaces, / for word breaks)"></textarea>
    <div class="tk-btns">
      <button class="btn sm" id="mc-enc">Text -> Morse</button>
      <button class="btn sm" id="mc-dec">Morse -> Text</button>
      <button class="btn sm ghost" id="mc-play">Play as audio</button>
      <button class="btn sm ghost" id="mc-sample">Load sample</button>
    </div>
    <pre class="tk-out" id="mc-out"></pre>
    </div>
    <div class="tk-section">
    <h2 class="pg-h2">Reference table</h2>
    <div id="mc-table" class="mono" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(90px,1fr));gap:6px;font-size:12px"></div>
    </div>
  `;

  const inp = root.querySelector("#mc-in");
  const out = root.querySelector("#mc-out");
  const table = root.querySelector("#mc-table");

  table.innerHTML = Object.entries(MORSE_TABLE).filter(([k]) => k !== " ")
    .map(([k, v]) => `<div>${escapeHtml(k)} = ${v}</div>`).join("");

  root.querySelector("#mc-sample").onclick = () => { inp.value = "SOS SEND HELP"; };
  root.querySelector("#mc-enc").onclick = () => { out.textContent = textToMorse(inp.value); };
  root.querySelector("#mc-dec").onclick = () => { out.textContent = morseToText(inp.value); };
  root.querySelector("#mc-play").onclick = () => playMorse(out.textContent || textToMorse(inp.value));

  function playMorse(morse) {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const unit = 0.08; // seconds per dot
    let t = ctx.currentTime;
    for (const symbol of morse) {
      if (symbol === ".") { beep(ctx, t, unit); t += unit * 2; }
      else if (symbol === "-") { beep(ctx, t, unit * 3); t += unit * 4; }
      else if (symbol === " ") { t += unit * 2; }
      else if (symbol === "/") { t += unit * 4; }
    }
  }

  function beep(ctx, startTime, duration) {
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.frequency.value = 600;
    osc.connect(gain);
    gain.connect(ctx.destination);
    gain.gain.setValueAtTime(0.2, startTime);
    osc.start(startTime);
    osc.stop(startTime + duration);
  }
}

registerTab("morse", "Morse Code", renderMorse);

// ---------------------------------------------------------------------------
// Tool 13: Number Base Converter
// ---------------------------------------------------------------------------
//
// Converts arbitrary-precision integers between binary, octal, decimal and
// hexadecimal using BigInt so there's no 32-bit or double-precision
// rounding -- numbers with hundreds of digits convert exactly. Also shows
// the manual long-division algorithm used to derive the result, the same
// process taught in a discrete math or computer architecture course.

const BASE_NAMES = { 2: "Binary", 8: "Octal", 10: "Decimal", 16: "Hexadecimal" };
const BASE_DIGITS = "0123456789abcdefghijklmnopqrstuvwxyz";

function parseBigIntInBase(str, base) {
  const clean = str.trim().toLowerCase().replace(/^0b|^0o|^0x/, "");
  if (!clean) throw new Error("Empty input");
  let negative = false;
  let s = clean;
  if (s[0] === "-") { negative = true; s = s.slice(1); }
  let value = 0n;
  const b = BigInt(base);
  for (const ch of s) {
    const digit = BASE_DIGITS.indexOf(ch);
    if (digit === -1 || digit >= base) throw new Error(`'${ch}' is not a valid digit in base ${base}`);
    value = value * b + BigInt(digit);
  }
  return negative ? -value : value;
}

function formatBigIntInBase(value, base) {
  if (value === 0n) return "0";
  let negative = value < 0n;
  let v = negative ? -value : value;
  const b = BigInt(base);
  let out = "";
  while (v > 0n) {
    out = BASE_DIGITS[Number(v % b)] + out;
    v /= b;
  }
  return (negative ? "-" : "") + out;
}

function renderNumberBase(root) {
  root.innerHTML = `
    <div class="tk-section">
    <h2 class="pg-h2">Number Base Converter</h2>
    <p class="muted">Convert integers of arbitrary size between binary, octal, decimal, and
      hexadecimal using BigInt arithmetic -- no precision loss even for numbers hundreds of
      digits long. Prefixes (0b, 0o, 0x) are optional and auto-detected when present.</p>
    <div class="tk-row">
      <input class="tk-f" id="nb-in" placeholder="Enter a number, e.g. 255 or 0xff or 11111111" style="flex:2">
      <select class="tk-f" id="nb-base" style="flex:1">
        <option value="2">Binary (base 2)</option>
        <option value="8">Octal (base 8)</option>
        <option value="10" selected>Decimal (base 10)</option>
        <option value="16">Hexadecimal (base 16)</option>
      </select>
    </div>
    <div class="tk-btns">
      <button class="btn sm" id="nb-run">Convert</button>
      <button class="btn sm ghost" id="nb-sample">Load sample (a big number)</button>
    </div>
    <div id="nb-out" style="margin-top:14px"></div>
    <div id="nb-steps" style="margin-top:10px"></div>
    </div>

    <div class="tk-section">
    <h2 class="pg-h2">Arbitrary base (2-36) with worked long division</h2>
    <p class="muted">Every base beyond 10 needs extra digit symbols -- by convention the letters
      a-z extend the digits 0-9, which is why base 36 is the practical ceiling (26 letters + 10
      digits). This section shows the actual long-division-by-target-base algorithm used to
      derive the digits, one remainder at a time, from least significant to most significant.</p>
    <div class="tk-row">
      <input class="tk-f" id="nb2-in" placeholder="Number, e.g. 1000" style="flex:1">
      <select class="tk-f" id="nb2-from" style="flex:1"></select>
      <span class="muted" style="align-self:center">to</span>
      <select class="tk-f" id="nb2-to" style="flex:1"></select>
    </div>
    <div class="tk-btns">
      <button class="btn sm" id="nb2-run">Convert with steps</button>
    </div>
    <pre class="tk-out" id="nb2-out" style="min-height:220px"></pre>
    </div>
  `;

  const inp = root.querySelector("#nb-in");
  const baseSel = root.querySelector("#nb-base");
  const out = root.querySelector("#nb-out");
  const steps = root.querySelector("#nb-steps");

  root.querySelector("#nb-sample").onclick = () => {
    inp.value = "123456789012345678901234567890";
    baseSel.value = "10";
    run();
  };
  root.querySelector("#nb-run").onclick = run;
  inp.oninput = run;
  baseSel.onchange = run;

  function run() {
    if (!inp.value.trim()) { out.innerHTML = ""; steps.innerHTML = ""; return; }
    try {
      const base = +baseSel.value;
      const value = parseBigIntInBase(inp.value, base);
      out.innerHTML = `<div class="tk-row" style="flex-wrap:wrap;gap:14px">
        ${[2, 8, 10, 16].map((b) => `
          <div class="card" style="flex:1;min-width:180px">
            <div class="muted" style="font-size:12px">${BASE_NAMES[b]} (base ${b})</div>
            <div class="mono" style="word-break:break-all;margin-top:4px">${formatBigIntInBase(value, b)}</div>
          </div>`).join("")}
      </div>`;

      const bitLength = value === 0n ? 1 : bigAbs(value).toString(2).length;
      steps.innerHTML = `<div class="card">
        <strong>Details</strong>
        <div class="mono" style="margin-top:6px">
          Sign: ${value < 0n ? "negative" : "non-negative"}<br>
          Bit length (magnitude): ${bitLength} bits<br>
          Byte length: ${Math.ceil(bitLength / 8)} bytes<br>
          Fits in 32-bit signed: ${value >= -2147483648n && value <= 2147483647n ? "yes" : "no"}<br>
          Fits in 64-bit signed: ${value >= -(2n ** 63n) && value <= 2n ** 63n - 1n ? "yes" : "no"}
        </div>
      </div>`;
    } catch (err) {
      out.innerHTML = `<p class="muted">Error: ${escapeHtml(err.message)}</p>`;
      steps.innerHTML = "";
    }
  }

  const fromSel = root.querySelector("#nb2-from");
  const toSel = root.querySelector("#nb2-to");
  const in2 = root.querySelector("#nb2-in");
  const out2 = root.querySelector("#nb2-out");

  const baseOptions = Array.from({ length: 35 }, (_, i) => i + 2)
    .map((b) => `<option value="${b}" ${b === 10 ? "selected" : ""}>Base ${b}</option>`).join("");
  fromSel.innerHTML = baseOptions;
  toSel.innerHTML = baseOptions.replace('value="10" selected', 'value="10"').replace('value="16"', 'value="16" selected');

  root.querySelector("#nb2-run").onclick = () => {
    try {
      const fromBase = +fromSel.value, toBase = +toSel.value;
      const value = parseBigIntInBase(in2.value, fromBase);
      if (value === 0n) {
        out2.textContent = `0 in base ${fromBase} is 0 in every base -- nothing to divide.`;
        return;
      }
      const negative = value < 0n;
      let v = negative ? -value : value;
      const steps2 = [];
      const b = BigInt(toBase);
      while (v > 0n) {
        const remainder = v % b;
        const quotient = v / b;
        steps2.push({ dividend: v, divisor: toBase, quotient, remainder: BASE_DIGITS[Number(remainder)] });
        v = quotient;
      }
      const digits = steps2.map((s) => s.remainder).reverse().join("");
      out2.textContent =
`Converting ${negative ? "-" : ""}${in2.value.trim()} (base ${fromBase}) to base ${toBase}

Interpreted value (base 10): ${negative ? "-" : ""}${value < 0n ? -value : value}

Long division by ${toBase}, reading remainders from bottom to top:
${steps2.map((s, i) => `  ${String(i + 1).padStart(2)}.  ${s.dividend} / ${toBase} = ${s.quotient} remainder ${s.remainder}`).join("\n")}

Reading the remainder column from the LAST line to the FIRST gives the
digits of the answer, most significant digit first:
${negative ? "-" : ""}${digits}

Result: ${negative ? "-" : ""}${in2.value.trim()} (base ${fromBase}) = ${negative ? "-" : ""}${digits} (base ${toBase})`;
    } catch (err) {
      out2.textContent = "Error: " + err.message;
    }
  };
}

registerTab("numbase", "Number Base Converter", renderNumberBase);

// ---------------------------------------------------------------------------
// Tool 14: ASCII Table Reference
// ---------------------------------------------------------------------------

const ASCII_CONTROL_NAMES = [
  "NUL (null)", "SOH (start of heading)", "STX (start of text)", "ETX (end of text)",
  "EOT (end of transmission)", "ENQ (enquiry)", "ACK (acknowledge)", "BEL (bell)",
  "BS (backspace)", "TAB (horizontal tab)", "LF (line feed / newline)", "VT (vertical tab)",
  "FF (form feed)", "CR (carriage return)", "SO (shift out)", "SI (shift in)",
  "DLE (data link escape)", "DC1 (device control 1 / XON)", "DC2 (device control 2)",
  "DC3 (device control 3 / XOFF)", "DC4 (device control 4)", "NAK (negative acknowledge)",
  "SYN (synchronous idle)", "ETB (end of transmission block)", "CAN (cancel)",
  "EM (end of medium)", "SUB (substitute)", "ESC (escape)", "FS (file separator)",
  "GS (group separator)", "RS (record separator)", "US (unit separator)",
];

function buildAsciiTable() {
  const rows = [];
  for (let i = 0; i <= 127; i++) {
    let char, description;
    if (i < 32) { char = "^" + String.fromCharCode(i + 64); description = ASCII_CONTROL_NAMES[i]; }
    else if (i === 32) { char = "(space)"; description = "SP (space)"; }
    else if (i === 127) { char = "^?"; description = "DEL (delete)"; }
    else { char = String.fromCharCode(i); description = printableDescription(i); }
    rows.push({
      dec: i, hex: i.toString(16).padStart(2, "0").toUpperCase(),
      oct: i.toString(8).padStart(3, "0"), bin: i.toString(2).padStart(8, "0"),
      char, description,
    });
  }
  return rows;
}

function printableDescription(code) {
  const ch = String.fromCharCode(code);
  if (/[A-Z]/.test(ch)) return "uppercase letter " + ch;
  if (/[a-z]/.test(ch)) return "lowercase letter " + ch;
  if (/[0-9]/.test(ch)) return "digit " + ch;
  const punctNames = {
    "!": "exclamation mark", '"': "quotation mark", "#": "number sign", "$": "dollar sign",
    "%": "percent sign", "&": "ampersand", "'": "apostrophe", "(": "left parenthesis",
    ")": "right parenthesis", "*": "asterisk", "+": "plus sign", ",": "comma",
    "-": "hyphen-minus", ".": "full stop", "/": "solidus (slash)", ":": "colon",
    ";": "semicolon", "<": "less-than sign", "=": "equals sign", ">": "greater-than sign",
    "?": "question mark", "@": "at sign", "[": "left square bracket", "\\": "reverse solidus (backslash)",
    "]": "right square bracket", "^": "circumflex accent", "_": "low line (underscore)",
    "`": "grave accent", "{": "left curly bracket", "|": "vertical line", "}": "right curly bracket",
    "~": "tilde",
  };
  return punctNames[ch] || "printable character";
}

const ASCII_TABLE_DATA = buildAsciiTable();

function renderAsciiTable(root) {
  root.innerHTML = `
    <div class="tk-section">
    <h2 class="pg-h2">ASCII Table Reference</h2>
    <p class="muted">All 128 standard ASCII characters (0-127) with decimal, hex, octal, and
      binary representations plus descriptions -- including full names for every control
      character. Searchable by character, decimal value, hex value, or description text.</p>
    <input class="tk-f" id="at-search" placeholder="Search by character, number (dec/hex/oct/bin), or description...">
    <div style="overflow:auto;max-height:640px;margin-top:12px;border:1px solid rgba(255,255,255,.08);border-radius:8px">
      <table class="mono" style="width:100%;border-collapse:collapse;font-size:12.5px" id="at-table">
        <thead style="position:sticky;top:0;background:rgba(0,0,0,.6)">
          <tr>
            <th style="text-align:left;padding:6px 10px">Dec</th>
            <th style="text-align:left;padding:6px 10px">Hex</th>
            <th style="text-align:left;padding:6px 10px">Oct</th>
            <th style="text-align:left;padding:6px 10px">Binary</th>
            <th style="text-align:left;padding:6px 10px">Char</th>
            <th style="text-align:left;padding:6px 10px">Description</th>
          </tr>
        </thead>
        <tbody id="at-body"></tbody>
      </table>
    </div>
    </div>
  `;

  const search = root.querySelector("#at-search");
  const body = root.querySelector("#at-body");

  function render(rows) {
    body.innerHTML = rows.map((r) => `<tr style="border-top:1px solid rgba(255,255,255,.05)">
      <td style="padding:5px 10px">${r.dec}</td>
      <td style="padding:5px 10px">0x${r.hex}</td>
      <td style="padding:5px 10px">${r.oct}</td>
      <td style="padding:5px 10px">${r.bin}</td>
      <td style="padding:5px 10px">${escapeHtml(r.char)}</td>
      <td style="padding:5px 10px">${escapeHtml(r.description)}</td>
    </tr>`).join("");
  }

  search.oninput = () => {
    const q = search.value.trim().toLowerCase();
    if (!q) { render(ASCII_TABLE_DATA); return; }
    const filtered = ASCII_TABLE_DATA.filter((r) =>
      String(r.dec).includes(q) || r.hex.toLowerCase().includes(q) || r.oct.includes(q) ||
      r.bin.includes(q) || r.char.toLowerCase().includes(q) || r.description.toLowerCase().includes(q)
    );
    render(filtered);
  };

  render(ASCII_TABLE_DATA);
}

registerTab("ascii", "ASCII Table", renderAsciiTable);

// ---------------------------------------------------------------------------
// Tool 15: Unicode Lookup
// ---------------------------------------------------------------------------
//
// Given a single character or a code point, shows its canonical name (best
// effort -- full Unicode name lookup would require shipping the entire
// UnicodeData.txt, so common ranges/blocks are covered explicitly here),
// general category, block, and UTF-8/UTF-16 byte encodings. Also supports
// reverse lookup of common named characters.

const UNICODE_BLOCKS = [
  { start: 0x0000, end: 0x001F, name: "C0 Controls" },
  { start: 0x0020, end: 0x007E, name: "Basic Latin (printable)" },
  { start: 0x007F, end: 0x009F, name: "C1 Controls" },
  { start: 0x00A0, end: 0x00FF, name: "Latin-1 Supplement" },
  { start: 0x0100, end: 0x017F, name: "Latin Extended-A" },
  { start: 0x0180, end: 0x024F, name: "Latin Extended-B" },
  { start: 0x0250, end: 0x02AF, name: "IPA Extensions" },
  { start: 0x0370, end: 0x03FF, name: "Greek and Coptic" },
  { start: 0x0400, end: 0x04FF, name: "Cyrillic" },
  { start: 0x0530, end: 0x058F, name: "Armenian" },
  { start: 0x0590, end: 0x05FF, name: "Hebrew" },
  { start: 0x0600, end: 0x06FF, name: "Arabic" },
  { start: 0x0900, end: 0x097F, name: "Devanagari" },
  { start: 0x0E00, end: 0x0E7F, name: "Thai" },
  { start: 0x1100, end: 0x11FF, name: "Hangul Jamo" },
  { start: 0x2000, end: 0x206F, name: "General Punctuation" },
  { start: 0x2070, end: 0x209F, name: "Superscripts and Subscripts" },
  { start: 0x20A0, end: 0x20CF, name: "Currency Symbols" },
  { start: 0x2100, end: 0x214F, name: "Letterlike Symbols" },
  { start: 0x2150, end: 0x218F, name: "Number Forms" },
  { start: 0x2190, end: 0x21FF, name: "Arrows" },
  { start: 0x2200, end: 0x22FF, name: "Mathematical Operators" },
  { start: 0x2300, end: 0x23FF, name: "Miscellaneous Technical" },
  { start: 0x2500, end: 0x257F, name: "Box Drawing" },
  { start: 0x2580, end: 0x259F, name: "Block Elements" },
  { start: 0x25A0, end: 0x25FF, name: "Geometric Shapes" },
  { start: 0x2600, end: 0x26FF, name: "Miscellaneous Symbols" },
  { start: 0x2700, end: 0x27BF, name: "Dingbats" },
  { start: 0x2E80, end: 0x2FDF, name: "CJK Radicals" },
  { start: 0x3040, end: 0x309F, name: "Hiragana" },
  { start: 0x30A0, end: 0x30FF, name: "Katakana" },
  { start: 0x3400, end: 0x4DBF, name: "CJK Unified Ideographs Extension A" },
  { start: 0x4E00, end: 0x9FFF, name: "CJK Unified Ideographs" },
  { start: 0xAC00, end: 0xD7AF, name: "Hangul Syllables" },
  { start: 0xD800, end: 0xDFFF, name: "Surrogates" },
  { start: 0xE000, end: 0xF8FF, name: "Private Use Area" },
  { start: 0xF900, end: 0xFAFF, name: "CJK Compatibility Ideographs" },
  { start: 0xFB00, end: 0xFB4F, name: "Alphabetic Presentation Forms" },
  { start: 0xFE00, end: 0xFE0F, name: "Variation Selectors" },
  { start: 0xFF00, end: 0xFFEF, name: "Halfwidth and Fullwidth Forms" },
  { start: 0x1F300, end: 0x1F5FF, name: "Miscellaneous Symbols and Pictographs" },
  { start: 0x1F600, end: 0x1F64F, name: "Emoticons" },
  { start: 0x1F680, end: 0x1F6FF, name: "Transport and Map Symbols" },
  { start: 0x1F900, end: 0x1F9FF, name: "Supplemental Symbols and Pictographs" },
];

// Systematically generated ranges (Greek and Latin-1 Supplement accented
// letters follow strict, well-documented code point ordering, so these are
// built with loops against their canonical names rather than typed out by
// hand -- reduces the chance of a transposition error across dozens of
// near-identical entries).
const GREEK_LETTER_NAMES = [
  "ALPHA", "BETA", "GAMMA", "DELTA", "EPSILON", "ZETA", "ETA", "THETA",
  "IOTA", "KAPPA", "LAMDA", "MU", "NU", "XI", "OMICRON", "PI", "RHO",
  null, "SIGMA", "TAU", "UPSILON", "PHI", "CHI", "PSI", "OMEGA",
];

function buildGreekAlphabetEntries() {
  const entries = {};
  for (let i = 0; i < GREEK_LETTER_NAMES.length; i++) {
    const name = GREEK_LETTER_NAMES[i];
    if (!name) continue; // 0x03A2 is an unassigned slot between RHO and SIGMA
    entries[0x0391 + i] = `GREEK CAPITAL LETTER ${name}`;
    entries[0x03B1 + i] = `GREEK SMALL LETTER ${name}`;
  }
  return entries;
}

// Index 23 (0x00D7 / 0x00F7) is the multiplication/division sign, not a
// letter, in both rows -- left null. Index 31 differs between rows: the
// capital row (0x00C0-0x00DF) has no letter there at all (0x00DF is
// lowercase-only SHARP S), while the lowercase row (0x00E0-0x00FF) has
// Y WITH DIAERESIS there instead of SHARP S -- so the two rows are built
// from separate name lists rather than one shared list.
const LATIN1_CAPITAL_NAMES = [
  "A WITH GRAVE", "A WITH ACUTE", "A WITH CIRCUMFLEX", "A WITH TILDE", "A WITH DIAERESIS",
  "A WITH RING ABOVE", "AE", "C WITH CEDILLA", "E WITH GRAVE", "E WITH ACUTE",
  "E WITH CIRCUMFLEX", "E WITH DIAERESIS", "I WITH GRAVE", "I WITH ACUTE",
  "I WITH CIRCUMFLEX", "I WITH DIAERESIS", "ETH", "N WITH TILDE", "O WITH GRAVE",
  "O WITH ACUTE", "O WITH CIRCUMFLEX", "O WITH TILDE", "O WITH DIAERESIS",
  null, "O WITH STROKE", "U WITH GRAVE", "U WITH ACUTE", "U WITH CIRCUMFLEX",
  "U WITH DIAERESIS", "Y WITH ACUTE", "THORN", null,
];

const LATIN1_SMALL_NAMES = [
  "A WITH GRAVE", "A WITH ACUTE", "A WITH CIRCUMFLEX", "A WITH TILDE", "A WITH DIAERESIS",
  "A WITH RING ABOVE", "AE", "C WITH CEDILLA", "E WITH GRAVE", "E WITH ACUTE",
  "E WITH CIRCUMFLEX", "E WITH DIAERESIS", "I WITH GRAVE", "I WITH ACUTE",
  "I WITH CIRCUMFLEX", "I WITH DIAERESIS", "ETH", "N WITH TILDE", "O WITH GRAVE",
  "O WITH ACUTE", "O WITH CIRCUMFLEX", "O WITH TILDE", "O WITH DIAERESIS",
  null, "O WITH STROKE", "U WITH GRAVE", "U WITH ACUTE", "U WITH CIRCUMFLEX",
  "U WITH DIAERESIS", "Y WITH ACUTE", "THORN", "Y WITH DIAERESIS",
];

function buildLatin1AccentedEntries() {
  const entries = { 0x00DF: "LATIN SMALL LETTER SHARP S" };
  for (let i = 0; i < LATIN1_CAPITAL_NAMES.length; i++) {
    if (LATIN1_CAPITAL_NAMES[i]) entries[0x00C0 + i] = `LATIN CAPITAL LETTER ${LATIN1_CAPITAL_NAMES[i]}`;
    if (LATIN1_SMALL_NAMES[i]) entries[0x00E0 + i] = `LATIN SMALL LETTER ${LATIN1_SMALL_NAMES[i]}`;
  }
  return entries;
}

const CURRENCY_SYMBOL_NAMES = {
  0x0024: "DOLLAR SIGN", 0x00A2: "CENT SIGN", 0x00A3: "POUND SIGN", 0x00A4: "CURRENCY SIGN",
  0x00A5: "YEN SIGN", 0x058F: "ARMENIAN DRAM SIGN", 0x060B: "AFGHANI SIGN",
  0x09F2: "BENGALI RUPEE MARK", 0x0E3F: "THAI CURRENCY SYMBOL BAHT", 0x17DB: "KHMER CURRENCY SYMBOL RIEL",
  0x20A0: "EURO-CURRENCY SIGN", 0x20A1: "COLON SIGN", 0x20A2: "CRUZEIRO SIGN", 0x20A3: "FRENCH FRANC SIGN",
  0x20A4: "LIRA SIGN", 0x20A6: "NAIRA SIGN", 0x20A8: "RUPEE SIGN", 0x20A9: "WON SIGN",
  0x20AA: "NEW SHEQEL SIGN", 0x20AB: "DONG SIGN", 0x20AC: "EURO SIGN", 0x20AD: "KIP SIGN",
  0x20AE: "TUGRIK SIGN", 0x20B1: "PESO SIGN", 0x20B4: "HRYVNIA SIGN", 0x20B9: "INDIAN RUPEE SIGN",
  0x20BA: "TURKISH LIRA SIGN", 0x20BD: "RUBLE SIGN", 0x20BF: "BITCOIN SIGN",
};

const ARROW_NAMES = {
  0x2190: "LEFTWARDS ARROW", 0x2191: "UPWARDS ARROW", 0x2192: "RIGHTWARDS ARROW", 0x2193: "DOWNWARDS ARROW",
  0x2194: "LEFT RIGHT ARROW", 0x2195: "UP DOWN ARROW", 0x2196: "NORTH WEST ARROW", 0x2197: "NORTH EAST ARROW",
  0x2198: "SOUTH EAST ARROW", 0x2199: "SOUTH WEST ARROW", 0x219A: "LEFTWARDS ARROW WITH STROKE",
  0x21A9: "LEFTWARDS ARROW WITH HOOK", 0x21AA: "RIGHTWARDS ARROW WITH HOOK",
  0x21B0: "UPWARDS ARROW WITH TIP LEFTWARDS", 0x21B3: "DOWNWARDS ARROW WITH TIP RIGHTWARDS",
  0x21BA: "ANTICLOCKWISE OPEN CIRCLE ARROW", 0x21BB: "CLOCKWISE OPEN CIRCLE ARROW",
  0x21C4: "RIGHTWARDS ARROW OVER LEFTWARDS ARROW", 0x21CC: "RIGHTWARDS HARPOON OVER LEFTWARDS HARPOON",
  0x21D0: "LEFTWARDS DOUBLE ARROW", 0x21D2: "RIGHTWARDS DOUBLE ARROW", 0x21D4: "LEFT RIGHT DOUBLE ARROW",
  0x27F5: "LONG LEFTWARDS ARROW", 0x27F6: "LONG RIGHTWARDS ARROW",
};

const MATH_OPERATOR_NAMES = {
  0x00B1: "PLUS-MINUS SIGN", 0x00D7: "MULTIPLICATION SIGN", 0x00F7: "DIVISION SIGN",
  0x2200: "FOR ALL", 0x2202: "PARTIAL DIFFERENTIAL", 0x2203: "THERE EXISTS", 0x2205: "EMPTY SET",
  0x2207: "NABLA", 0x2208: "ELEMENT OF", 0x2209: "NOT AN ELEMENT OF", 0x220B: "CONTAINS AS MEMBER",
  0x220F: "N-ARY PRODUCT", 0x2211: "N-ARY SUMMATION", 0x2212: "MINUS SIGN", 0x2213: "MINUS-OR-PLUS SIGN",
  0x2215: "DIVISION SLASH", 0x221A: "SQUARE ROOT", 0x221D: "PROPORTIONAL TO", 0x221E: "INFINITY",
  0x2220: "ANGLE", 0x2227: "LOGICAL AND", 0x2228: "LOGICAL OR", 0x2229: "INTERSECTION",
  0x222A: "UNION", 0x222B: "INTEGRAL", 0x222E: "CONTOUR INTEGRAL", 0x2234: "THEREFORE",
  0x2235: "BECAUSE", 0x223C: "TILDE OPERATOR", 0x2245: "APPROXIMATELY EQUAL TO",
  0x2248: "ALMOST EQUAL TO", 0x2260: "NOT EQUAL TO", 0x2261: "IDENTICAL TO",
  0x2264: "LESS-THAN OR EQUAL TO", 0x2265: "GREATER-THAN OR EQUAL TO", 0x2282: "SUBSET OF",
  0x2283: "SUPERSET OF", 0x2286: "SUBSET OF OR EQUAL TO", 0x2287: "SUPERSET OF OR EQUAL TO",
  0x2295: "CIRCLED PLUS", 0x2297: "CIRCLED TIMES", 0x22A5: "UP TACK", 0x22C5: "DOT OPERATOR",
};

const BOX_DRAWING_NAMES = {
  0x2500: "BOX DRAWINGS LIGHT HORIZONTAL", 0x2502: "BOX DRAWINGS LIGHT VERTICAL",
  0x250C: "BOX DRAWINGS LIGHT DOWN AND RIGHT", 0x2510: "BOX DRAWINGS LIGHT DOWN AND LEFT",
  0x2514: "BOX DRAWINGS LIGHT UP AND RIGHT", 0x2518: "BOX DRAWINGS LIGHT UP AND LEFT",
  0x251C: "BOX DRAWINGS LIGHT VERTICAL AND RIGHT", 0x2524: "BOX DRAWINGS LIGHT VERTICAL AND LEFT",
  0x252C: "BOX DRAWINGS LIGHT DOWN AND HORIZONTAL", 0x2534: "BOX DRAWINGS LIGHT UP AND HORIZONTAL",
  0x253C: "BOX DRAWINGS LIGHT VERTICAL AND HORIZONTAL", 0x2550: "BOX DRAWINGS DOUBLE HORIZONTAL",
  0x2551: "BOX DRAWINGS DOUBLE VERTICAL", 0x2554: "BOX DRAWINGS DOUBLE DOWN AND RIGHT",
  0x2557: "BOX DRAWINGS DOUBLE DOWN AND LEFT", 0x255A: "BOX DRAWINGS DOUBLE UP AND RIGHT",
  0x255D: "BOX DRAWINGS DOUBLE UP AND LEFT", 0x2580: "UPPER HALF BLOCK", 0x2584: "LOWER HALF BLOCK",
  0x2588: "FULL BLOCK", 0x258C: "LEFT HALF BLOCK", 0x2590: "RIGHT HALF BLOCK", 0x2591: "LIGHT SHADE",
  0x2592: "MEDIUM SHADE", 0x2593: "DARK SHADE",
};

const PUNCTUATION_EXTRA_NAMES = {
  0x2018: "LEFT SINGLE QUOTATION MARK", 0x2019: "RIGHT SINGLE QUOTATION MARK",
  0x201A: "SINGLE LOW-9 QUOTATION MARK", 0x201C: "LEFT DOUBLE QUOTATION MARK",
  0x201D: "RIGHT DOUBLE QUOTATION MARK", 0x201E: "DOUBLE LOW-9 QUOTATION MARK",
  0x2020: "DAGGER", 0x2021: "DOUBLE DAGGER", 0x2022: "BULLET", 0x2024: "ONE DOT LEADER",
  0x2025: "TWO DOT LEADER", 0x2026: "HORIZONTAL ELLIPSIS", 0x2030: "PER MILLE SIGN",
  0x2032: "PRIME", 0x2033: "DOUBLE PRIME", 0x2013: "EN DASH", 0x2014: "EM DASH",
  0x2015: "HORIZONTAL BAR", 0x2039: "SINGLE LEFT-POINTING ANGLE QUOTATION MARK",
  0x203A: "SINGLE RIGHT-POINTING ANGLE QUOTATION MARK", 0x203C: "DOUBLE EXCLAMATION MARK",
  0x2044: "FRACTION SLASH",
};

const SUPERSCRIPT_SUBSCRIPT_NAMES = {
  0x00B2: "SUPERSCRIPT TWO", 0x00B3: "SUPERSCRIPT THREE", 0x00B9: "SUPERSCRIPT ONE",
  0x2070: "SUPERSCRIPT ZERO", 0x2074: "SUPERSCRIPT FOUR", 0x2075: "SUPERSCRIPT FIVE",
  0x2076: "SUPERSCRIPT SIX", 0x2077: "SUPERSCRIPT SEVEN", 0x2078: "SUPERSCRIPT EIGHT",
  0x2079: "SUPERSCRIPT NINE", 0x2080: "SUBSCRIPT ZERO", 0x2081: "SUBSCRIPT ONE",
  0x2082: "SUBSCRIPT TWO", 0x2083: "SUBSCRIPT THREE", 0x2084: "SUBSCRIPT FOUR",
  0x2085: "SUBSCRIPT FIVE", 0x2086: "SUBSCRIPT SIX", 0x2087: "SUBSCRIPT SEVEN",
  0x2088: "SUBSCRIPT EIGHT", 0x2089: "SUBSCRIPT NINE",
};

const COMMON_EMOJI_NAMES = {
  0x1F600: "GRINNING FACE", 0x1F601: "GRINNING FACE WITH SMILING EYES", 0x1F602: "FACE WITH TEARS OF JOY",
  0x1F603: "SMILING FACE WITH OPEN MOUTH", 0x1F604: "SMILING FACE WITH OPEN MOUTH AND SMILING EYES",
  0x1F606: "SMILING FACE WITH OPEN MOUTH AND TIGHTLY-CLOSED EYES", 0x1F609: "WINKING FACE",
  0x1F60A: "SMILING FACE WITH SMILING EYES", 0x1F60D: "SMILING FACE WITH HEART-SHAPED EYES",
  0x1F60E: "SMILING FACE WITH SUNGLASSES", 0x1F611: "EXPRESSIONLESS FACE",
  0x1F614: "PENSIVE FACE", 0x1F61E: "DISAPPOINTED FACE", 0x1F622: "CRYING FACE",
  0x1F62D: "LOUDLY CRYING FACE", 0x1F631: "FACE SCREAMING IN FEAR", 0x1F633: "FLUSHED FACE",
  0x1F44D: "THUMBS UP SIGN", 0x1F44E: "THUMBS DOWN SIGN",
  0x1F44F: "CLAPPING HANDS SIGN", 0x1F64F: "PERSON WITH FOLDED HANDS", 0x2764: "HEAVY BLACK HEART",
  0x1F494: "BROKEN HEART", 0x1F525: "FIRE", 0x2B50: "WHITE MEDIUM STAR", 0x1F680: "ROCKET",
  0x1F512: "LOCK", 0x1F513: "OPEN LOCK", 0x1F511: "KEY", 0x1F6E1: "SHIELD", 0x1F41B: "BUG",
  0x1F4BB: "PERSONAL COMPUTER", 0x1F4F1: "MOBILE PHONE", 0x1F4A1: "ELECTRIC LIGHT BULB",
  0x2705: "WHITE HEAVY CHECK MARK", 0x274C: "CROSS MARK", 0x26A0: "WARNING SIGN",
  0x1F6A8: "POLICE CARS REVOLVING LIGHT", 0x1F3C6: "TROPHY",
};

const NAMED_CODE_POINTS = {
  ...buildGreekAlphabetEntries(),
  ...buildLatin1AccentedEntries(),
  ...CURRENCY_SYMBOL_NAMES,
  ...ARROW_NAMES,
  ...MATH_OPERATOR_NAMES,
  ...BOX_DRAWING_NAMES,
  ...PUNCTUATION_EXTRA_NAMES,
  ...SUPERSCRIPT_SUBSCRIPT_NAMES,
  ...COMMON_EMOJI_NAMES,
  0x0041: "LATIN CAPITAL LETTER A", 0x0061: "LATIN SMALL LETTER A",
  0x00A9: "COPYRIGHT SIGN", 0x00AE: "REGISTERED SIGN", 0x2122: "TRADE MARK SIGN",
  0x2713: "CHECK MARK", 0x2717: "BALLOT X", 0x00A0: "NO-BREAK SPACE",
  0x2605: "BLACK STAR", 0x2606: "WHITE STAR",
};

function findUnicodeBlock(codePoint) {
  return UNICODE_BLOCKS.find((b) => codePoint >= b.start && codePoint <= b.end) || null;
}

function unicodeGeneralCategoryGuess(codePoint) {
  if (codePoint <= 0x1F || (codePoint >= 0x7F && codePoint <= 0x9F)) return "Cc (Control)";
  const ch = String.fromCodePoint(codePoint);
  if (/\p{L}/u.test(ch)) return /\p{Lu}/u.test(ch) ? "Lu (Uppercase Letter)" : /\p{Ll}/u.test(ch) ? "Ll (Lowercase Letter)" : "Lo/Lt/Lm (Letter)";
  if (/\p{N}/u.test(ch)) return "N (Number)";
  if (/\p{P}/u.test(ch)) return "P (Punctuation)";
  if (/\p{S}/u.test(ch)) return "S (Symbol)";
  if (/\p{Z}/u.test(ch)) return "Z (Separator)";
  return "Other";
}

function utf8Bytes(codePoint) {
  return [...new TextEncoder().encode(String.fromCodePoint(codePoint))];
}

function utf16Units(codePoint) {
  const str = String.fromCodePoint(codePoint);
  const units = [];
  for (let i = 0; i < str.length; i++) units.push(str.charCodeAt(i));
  return units;
}

function renderUnicodeLookup(root) {
  root.innerHTML = `
    <div class="tk-section">
    <h2 class="pg-h2">Unicode Lookup</h2>
    <p class="muted">Enter a single character, or a code point (e.g. <code>U+1F600</code>,
      <code>0x1F600</code>, or plain decimal <code>128512</code>), to see its Unicode block,
      an approximate general category, and its UTF-8 / UTF-16 byte encodings. A small built-in
      database also supplies canonical names for common symbols; search by name to find a
      code point instead.</p>
    <div class="tk-row">
      <input class="tk-f" id="ul-in" placeholder="Character or code point, e.g. A or U+1F600">
      <button class="btn sm" id="ul-lookup">Look up</button>
    </div>
    <div class="tk-row">
      <input class="tk-f" id="ul-search" placeholder="Or search the name database, e.g. 'arrow' or 'euro'">
      <button class="btn sm ghost" id="ul-searchbtn">Search names</button>
    </div>
    <div id="ul-out" style="margin-top:14px"></div>
    </div>
  `;

  const inp = root.querySelector("#ul-in");
  const out = root.querySelector("#ul-out");
  const searchInp = root.querySelector("#ul-search");

  root.querySelector("#ul-lookup").onclick = lookup;
  inp.onkeydown = (e) => { if (e.key === "Enter") lookup(); };
  root.querySelector("#ul-searchbtn").onclick = searchNames;
  searchInp.onkeydown = (e) => { if (e.key === "Enter") searchNames(); };

  function parseCodePoint(value) {
    const v = value.trim();
    if (!v) throw new Error("Enter a character or code point");
    let match;
    if ((match = v.match(/^u\+([0-9a-f]+)$/i))) return parseInt(match[1], 16);
    if ((match = v.match(/^0x([0-9a-f]+)$/i))) return parseInt(match[1], 16);
    if (/^\d+$/.test(v)) return parseInt(v, 10);
    return v.codePointAt(0);
  }

  function lookup() {
    try {
      const cp = parseCodePoint(inp.value);
      if (cp === undefined || Number.isNaN(cp) || cp < 0 || cp > 0x10FFFF) throw new Error("Not a valid Unicode code point");
      const char = String.fromCodePoint(cp);
      const block = findUnicodeBlock(cp);
      const category = unicodeGeneralCategoryGuess(cp);
      const name = NAMED_CODE_POINTS[cp] || null;
      const utf8 = utf8Bytes(cp);
      const utf16 = utf16Units(cp);

      out.innerHTML = `<div class="card">
        <div style="font-size:42px">${cp < 32 ? "&lt;control&gt;" : escapeHtml(char)}</div>
        <table class="mono" style="margin-top:10px;width:100%;border-collapse:collapse">
          <tr><td style="padding:3px 8px 3px 0;opacity:.7">Code point</td><td>U+${cp.toString(16).toUpperCase().padStart(4, "0")} (decimal ${cp})</td></tr>
          <tr><td style="padding:3px 8px 3px 0;opacity:.7">Name</td><td>${name ? escapeHtml(name) : "(not in local database)"}</td></tr>
          <tr><td style="padding:3px 8px 3px 0;opacity:.7">Block</td><td>${block ? escapeHtml(block.name) : "unlisted block"}</td></tr>
          <tr><td style="padding:3px 8px 3px 0;opacity:.7">General category (approx)</td><td>${category}</td></tr>
          <tr><td style="padding:3px 8px 3px 0;opacity:.7">UTF-8 bytes</td><td>${utf8.map((b) => b.toString(16).padStart(2, "0")).join(" ")} (${utf8.length} byte${utf8.length > 1 ? "s" : ""})</td></tr>
          <tr><td style="padding:3px 8px 3px 0;opacity:.7">UTF-16 code units</td><td>${utf16.map((u) => "0x" + u.toString(16).padStart(4, "0")).join(" ")} (${utf16.length} unit${utf16.length > 1 ? "s" : ""})</td></tr>
          <tr><td style="padding:3px 8px 3px 0;opacity:.7">HTML entity</td><td>&amp;#${cp}; / &amp;#x${cp.toString(16)};</td></tr>
          <tr><td style="padding:3px 8px 3px 0;opacity:.7">JS escape</td><td>${cp <= 0xFFFF ? `\\u${cp.toString(16).padStart(4, "0")}` : `\\u{${cp.toString(16)}}`}</td></tr>
        </table>
      </div>`;
    } catch (err) {
      out.innerHTML = `<p class="muted">Error: ${escapeHtml(err.message)}</p>`;
    }
  }

  function searchNames() {
    const q = searchInp.value.trim().toUpperCase();
    if (!q) { out.innerHTML = ""; return; }
    const matches = Object.entries(NAMED_CODE_POINTS).filter(([, name]) => name.includes(q));
    if (matches.length === 0) { out.innerHTML = '<p class="muted">No matches in the local name database. Try the direct lookup above with U+XXXX instead.</p>'; return; }
    out.innerHTML = `<div class="card"><strong>${matches.length} match(es)</strong>
      <div style="margin-top:8px;display:flex;flex-direction:column;gap:6px">
        ${matches.map(([cp, name]) => `<div class="mono">U+${(+cp).toString(16).toUpperCase().padStart(4, "0")}  ${String.fromCodePoint(+cp)}  ${escapeHtml(name)}</div>`).join("")}
      </div>
    </div>`;
  }
}

registerTab("unicode", "Unicode Lookup", renderUnicodeLookup);

// ---------------------------------------------------------------------------
// Tool 16: Checksum Calculator (CRC16, CRC32, Adler32)
// ---------------------------------------------------------------------------
//
// Checksums are fast, non-cryptographic functions designed to catch
// accidental corruption (a bit flip on a wire, a truncated file) -- they
// are trivially forgeable by an attacker and must never be used for
// integrity against a malicious adversary. All three are implemented here
// from their mathematical definitions rather than delegated to a library.

// CRC32 (IEEE 802.3 / zlib polynomial 0xEDB88320), built via the classic
// 256-entry lookup table approach.
const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(bytes) {
  let crc = 0xFFFFFFFF;
  for (const b of bytes) crc = CRC32_TABLE[(crc ^ b) & 0xFF] ^ (crc >>> 8);
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

// CRC16-CCITT (polynomial 0x1021, initial value 0xFFFF) -- widely used in
// serial protocols (XMODEM variant uses init 0x0000; CCITT-FALSE uses
// 0xFFFF, implemented here).
function crc16Ccitt(bytes) {
  let crc = 0xFFFF;
  for (const b of bytes) {
    crc ^= b << 8;
    for (let i = 0; i < 8; i++) {
      crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) : (crc << 1);
      crc &= 0xFFFF;
    }
  }
  return crc;
}

// Adler32 (used inside zlib/PNG). Two running sums mod the largest prime
// below 65536.
function adler32(bytes) {
  const MOD_ADLER = 65521;
  let a = 1, b = 0;
  for (const byte of bytes) {
    a = (a + byte) % MOD_ADLER;
    b = (b + a) % MOD_ADLER;
  }
  return ((b << 16) | a) >>> 0;
}

// CRC32C (Castagnoli polynomial 0x82F63B78) -- used by iSCSI, ext4, Btrfs,
// and modern hardware-accelerated CRC instructions (SSE4.2's CRC32
// instruction implements this exact polynomial).
const CRC32C_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0x82F63B78 ^ (c >>> 1)) : (c >>> 1);
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32c(bytes) {
  let crc = 0xFFFFFFFF;
  for (const b of bytes) crc = CRC32C_TABLE[(crc ^ b) & 0xFF] ^ (crc >>> 8);
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

// CRC8 (polynomial 0x07, the "CRC-8" / SMBus / ATM HEC variant), bit by bit
// (no table -- small enough that a table isn't needed to stay fast).
function crc8(bytes) {
  let crc = 0x00;
  for (const b of bytes) {
    crc ^= b;
    for (let i = 0; i < 8; i++) {
      crc = (crc & 0x80) ? ((crc << 1) ^ 0x07) & 0xFF : (crc << 1) & 0xFF;
    }
  }
  return crc;
}

// Fletcher-16 and Fletcher-32 -- simpler running-sum checksums (predecessors
// to Adler32) that are cheaper to compute but slightly weaker at detecting
// certain error patterns (e.g. reordered zero bytes).
function fletcher16(bytes) {
  let sum1 = 0, sum2 = 0;
  for (const b of bytes) {
    sum1 = (sum1 + b) % 255;
    sum2 = (sum2 + sum1) % 255;
  }
  return ((sum2 << 8) | sum1) >>> 0;
}

function fletcher32(bytes) {
  // Fletcher-32 operates on 16-bit words; an odd trailing byte is zero-padded.
  let sum1 = 0, sum2 = 0;
  for (let i = 0; i < bytes.length; i += 2) {
    const word = bytes[i] | ((bytes[i + 1] || 0) << 8);
    sum1 = (sum1 + word) % 65535;
    sum2 = (sum2 + sum1) % 65535;
  }
  return ((sum2 << 16) | sum1) >>> 0;
}

// A generic, configurable bit-by-bit CRC calculator supporting arbitrary
// width/polynomial/init/reflect/xorout parameters -- the same parameter set
// used by the "CRC RevEng catalogue" to describe virtually every named CRC
// variant in existence (CRC-16/MODBUS, CRC-16/XMODEM, CRC-32/BZIP2, etc).
function genericCrc(bytes, { width, poly, init, refIn, refOut, xorOut }) {
  const mask = width === 32 ? 0xFFFFFFFFn : (1n << BigInt(width)) - 1n;
  const topBit = 1n << BigInt(width - 1);
  let crc = BigInt(init) & mask;
  const polyBig = BigInt(poly) & mask;

  function reflect(value, bits) {
    let out = 0n;
    let v = BigInt(value);
    for (let i = 0; i < bits; i++) { out = (out << 1n) | (v & 1n); v >>= 1n; }
    return out;
  }

  for (let byte of bytes) {
    let b = BigInt(refIn ? Number(reflect(byte, 8)) : byte);
    crc ^= (b << BigInt(width - 8)) & mask;
    for (let i = 0; i < 8; i++) {
      if (crc & topBit) crc = ((crc << 1n) ^ polyBig) & mask;
      else crc = (crc << 1n) & mask;
    }
  }
  if (refOut) crc = reflect(crc, width);
  crc ^= BigInt(xorOut) & mask;
  return crc & mask;
}

const CRC_PRESETS = {
  "CRC-8": { width: 8, poly: 0x07, init: 0x00, refIn: false, refOut: false, xorOut: 0x00 },
  "CRC-16/MODBUS": { width: 16, poly: 0x8005, init: 0xFFFF, refIn: true, refOut: true, xorOut: 0x0000 },
  "CRC-16/XMODEM": { width: 16, poly: 0x1021, init: 0x0000, refIn: false, refOut: false, xorOut: 0x0000 },
  "CRC-16/CCITT-FALSE": { width: 16, poly: 0x1021, init: 0xFFFF, refIn: false, refOut: false, xorOut: 0x0000 },
  "CRC-32/ISO-HDLC (zlib)": { width: 32, poly: 0x04C11DB7, init: 0xFFFFFFFF, refIn: true, refOut: true, xorOut: 0xFFFFFFFF },
  "CRC-32/BZIP2": { width: 32, poly: 0x04C11DB7, init: 0xFFFFFFFF, refIn: false, refOut: false, xorOut: 0xFFFFFFFF },
  "CRC-32C (Castagnoli)": { width: 32, poly: 0x1EDC6F41, init: 0xFFFFFFFF, refIn: true, refOut: true, xorOut: 0xFFFFFFFF },
};

function renderChecksum(root) {
  root.innerHTML = `
    <div class="tk-section">
    <h2 class="pg-h2">Checksum Calculator</h2>
    <p class="muted">CRC16-CCITT, CRC32 (IEEE/zlib), and Adler32, all implemented directly from
      their mathematical definitions. These detect accidental corruption -- they are <em>not</em>
      cryptographically secure and can be trivially forged by anyone who wants to; never use a
      checksum where you need tamper-evidence against an adversary (use a keyed MAC instead).</p>
    <div class="tk-row">
      <textarea class="tk-in" id="cs-in" rows="4" placeholder="Text or hex bytes to checksum..." style="flex:2"></textarea>
      <div style="flex:1;display:flex;flex-direction:column;gap:8px">
        <label class="muted mono" style="font-size:12px"><input type="radio" name="cs-fmt" value="text" checked> Input is plain text</label>
        <label class="muted mono" style="font-size:12px"><input type="radio" name="cs-fmt" value="hex"> Input is hex bytes</label>
      </div>
    </div>
    <div class="tk-btns">
      <button class="btn sm" id="cs-run">Calculate all checksums</button>
    </div>
    <pre class="tk-out" id="cs-out" style="min-height:260px"></pre>
    </div>

    <div class="tk-section">
    <h2 class="pg-h2">Generic CRC calculator (named variants)</h2>
    <p class="muted">CRCs are actually a whole family defined by five parameters: width,
      polynomial, initial value, whether input/output bits are reflected, and a final XOR mask.
      Pick a named, real-world variant below to see the same input checksummed under each
      parameter set.</p>
    <select class="tk-f" id="cs-preset"></select>
    <div class="tk-btns"><button class="btn sm" id="cs-preset-run">Calculate with this variant</button></div>
    <pre class="tk-out" id="cs-preset-out"></pre>
    </div>
  `;

  const inp = root.querySelector("#cs-in");
  const out = root.querySelector("#cs-out");

  root.querySelector("#cs-run").onclick = () => {
    try {
      const fmt = root.querySelector('input[name="cs-fmt"]:checked').value;
      const bytes = fmt === "hex" ? hexToBytes(inp.value) : textToBytes(inp.value);
      const crc32Val = crc32(bytes);
      const crc32cVal = crc32c(bytes);
      const crc16Val = crc16Ccitt(bytes);
      const crc8Val = crc8(bytes);
      const adlerVal = adler32(bytes);
      const fletcher16Val = fletcher16(bytes);
      const fletcher32Val = fletcher32(bytes);
      out.textContent =
`Input: ${bytes.length} bytes

CRC8 (poly 0x07)
  hex: ${crc8Val.toString(16).padStart(2, "0")}   dec: ${crc8Val}

CRC16-CCITT (poly 0x1021, init 0xFFFF)
  hex: ${crc16Val.toString(16).padStart(4, "0")}   dec: ${crc16Val}

CRC32 (IEEE 802.3 / zlib, poly 0xEDB88320)
  hex: ${crc32Val.toString(16).padStart(8, "0")}   dec: ${crc32Val}

CRC32C (Castagnoli, poly 0x82F63B78 -- used by iSCSI, ext4, SSE4.2 CRC32 instruction)
  hex: ${crc32cVal.toString(16).padStart(8, "0")}   dec: ${crc32cVal}

Adler32 (zlib/PNG)
  hex: ${adlerVal.toString(16).padStart(8, "0")}   dec: ${adlerVal}

Fletcher-16
  hex: ${fletcher16Val.toString(16).padStart(4, "0")}   dec: ${fletcher16Val}

Fletcher-32
  hex: ${fletcher32Val.toString(16).padStart(8, "0")}   dec: ${fletcher32Val}`;
    } catch (err) {
      out.textContent = "Error: " + err.message;
    }
  };

  const presetSel = root.querySelector("#cs-preset");
  const presetOut = root.querySelector("#cs-preset-out");
  presetSel.innerHTML = Object.keys(CRC_PRESETS).map((name) => `<option value="${escapeHtml(name)}">${escapeHtml(name)}</option>`).join("");

  root.querySelector("#cs-preset-run").onclick = () => {
    try {
      const fmt = root.querySelector('input[name="cs-fmt"]:checked').value;
      const bytes = fmt === "hex" ? hexToBytes(inp.value) : textToBytes(inp.value);
      const preset = CRC_PRESETS[presetSel.value];
      const result = genericCrc(bytes, preset);
      const hexWidth = Math.ceil(preset.width / 4);
      presetOut.textContent =
`${presetSel.value}
  width=${preset.width}  poly=0x${preset.poly.toString(16)}  init=0x${preset.init.toString(16)}
  refIn=${preset.refIn}  refOut=${preset.refOut}  xorOut=0x${preset.xorOut.toString(16)}

  Result: 0x${result.toString(16).padStart(hexWidth, "0")}  (decimal ${result})`;
    } catch (err) {
      presetOut.textContent = "Error: " + err.message;
    }
  };
}

registerTab("checksum", "Checksum Calculator", renderChecksum);

// ---------------------------------------------------------------------------
// Tool 17: AES Encryption (WebCrypto: AES-GCM and AES-CBC)
// ---------------------------------------------------------------------------
//
// Uses the browser's native WebCrypto SubtleCrypto API for real, audited
// AES implementations -- this is one place where "roll your own" would be
// actively dangerous, so unlike the classical ciphers above this tool
// delegates the actual cryptography to the platform. AES-GCM is an
// authenticated mode (detects tampering via a built-in tag) and is the
// modern default; AES-CBC needs a separate MAC to be tamper-evident and is
// shown mainly so the difference is visible side by side.

async function deriveAesKeyFromPassword(password, salt, usage) {
  const baseKey = await crypto.subtle.importKey("raw", TE.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 250000, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    true,
    usage
  );
}

function renderAES(root) {
  root.innerHTML = `
    <div class="tk-section">
    <h2 class="pg-h2">AES Encryption (WebCrypto)</h2>
    <p class="muted">Real AES-256 via the browser's native SubtleCrypto implementation, keyed
      from a password using PBKDF2 (250,000 iterations, SHA-256) with a random salt. AES-GCM is
      an <strong>authenticated</strong> mode: it produces a tag that detects any tampering with
      the ciphertext, and is the recommended default. AES-CBC provides confidentiality only --
      it has no built-in integrity check, so tampered ciphertext will decrypt to garbage instead
      of raising an error (in real systems, CBC must be paired with a separate MAC, i.e.
      encrypt-then-MAC).</p>

    <div class="tk-row">
      <textarea class="tk-in" id="aes-in" rows="4" placeholder="Plaintext to encrypt, or ciphertext (hex) to decrypt..." style="flex:2"></textarea>
      <div style="flex:1;display:flex;flex-direction:column;gap:8px">
        <input class="tk-f" id="aes-pass" placeholder="Password (used to derive the AES key)">
        <select class="tk-f" id="aes-mode">
          <option value="AES-GCM">AES-GCM (authenticated, recommended)</option>
          <option value="AES-CBC">AES-CBC (confidentiality only)</option>
        </select>
      </div>
    </div>
    <div class="tk-btns">
      <button class="btn sm" id="aes-enc">Encrypt</button>
      <button class="btn sm" id="aes-dec">Decrypt (paste the full output from Encrypt)</button>
      <button class="btn sm ghost" id="aes-genpass">Generate random password</button>
    </div>
    <pre class="tk-out" id="aes-out" style="min-height:220px"></pre>

    <div class="card" style="margin-top:16px">
      <strong>GCM vs CBC</strong>
      <table class="mono" style="width:100%;margin-top:8px;border-collapse:collapse;font-size:12.5px">
        <tr><td style="padding:4px 8px 4px 0;opacity:.7">Authentication</td><td>GCM: built-in tag detects tampering</td><td>CBC: none -- pair with HMAC</td></tr>
        <tr><td style="padding:4px 8px 4px 0;opacity:.7">Parallelizable</td><td>GCM: yes (counter mode internally)</td><td>CBC: encryption is sequential</td></tr>
        <tr><td style="padding:4px 8px 4px 0;opacity:.7">Padding</td><td>GCM: none needed (stream-like)</td><td>CBC: needs block padding (PKCS#7)</td></tr>
        <tr><td style="padding:4px 8px 4px 0;opacity:.7">Nonce reuse risk</td><td>GCM: catastrophic (breaks confidentiality+auth)</td><td>CBC: reveals shared prefixes (less catastrophic, still bad)</td></tr>
      </table>
    </div>
    </div>
  `;

  const inp = root.querySelector("#aes-in");
  const passInp = root.querySelector("#aes-pass");
  const modeSel = root.querySelector("#aes-mode");
  const out = root.querySelector("#aes-out");

  root.querySelector("#aes-genpass").onclick = () => {
    passInp.value = generateRandomPassword(24, { lower: true, upper: true, digits: true, symbols: true });
  };

  root.querySelector("#aes-enc").onclick = async () => {
    if (!passInp.value) { out.textContent = "Enter a password first."; return; }
    try {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const mode = modeSel.value;
      const key = await deriveKeyForMode(passInp.value, salt, mode, ["encrypt"]);
      const iv = crypto.getRandomValues(new Uint8Array(mode === "AES-GCM" ? 12 : 16));
      const plainBytes = TE.encode(inp.value);
      const algoParam = mode === "AES-GCM" ? { name: "AES-GCM", iv } : { name: "AES-CBC", iv };
      const cipherBuf = await crypto.subtle.encrypt(algoParam, key, plainBytes);
      const cipherBytes = new Uint8Array(cipherBuf);
      out.textContent =
`Mode: ${mode}
Salt (hex, for key derivation): ${bytesToHex(salt)}
IV/nonce (hex): ${bytesToHex(iv)}
Ciphertext (hex): ${bytesToHex(cipherBytes)}
Ciphertext (base64): ${bytesToBase64(cipherBytes)}

Combined (salt:iv:ciphertext, hex) -- paste this whole line into Decrypt:
${bytesToHex(salt)}:${bytesToHex(iv)}:${bytesToHex(cipherBytes)}`;
    } catch (err) {
      out.textContent = "Error: " + err.message;
    }
  };

  root.querySelector("#aes-dec").onclick = async () => {
    if (!passInp.value) { out.textContent = "Enter the password first."; return; }
    try {
      const parts = inp.value.trim().split(":");
      if (parts.length !== 3) throw new Error("Expected format salt:iv:ciphertext (all hex) -- paste the 'Combined' line from Encrypt");
      const [saltHex, ivHex, cipherHex] = parts;
      const salt = hexToBytes(saltHex);
      const iv = hexToBytes(ivHex);
      const cipherBytes = hexToBytes(cipherHex);
      const mode = modeSel.value;
      const key = await deriveKeyForMode(passInp.value, salt, mode, ["decrypt"]);
      const algoParam = mode === "AES-GCM" ? { name: "AES-GCM", iv } : { name: "AES-CBC", iv };
      const plainBuf = await crypto.subtle.decrypt(algoParam, key, cipherBytes);
      out.textContent = "Decrypted plaintext:\n\n" + TD.decode(plainBuf);
    } catch (err) {
      out.textContent = "Error: " + err.message + (err.name === "OperationError" ? "\n\n(Wrong password, wrong mode, or tampered/corrupted ciphertext -- GCM's authentication tag failed to verify.)" : "");
    }
  };

  async function deriveKeyForMode(password, salt, mode, usages) {
    const baseKey = await crypto.subtle.importKey("raw", TE.encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 250000, hash: "SHA-256" },
      baseKey,
      { name: mode, length: 256 },
      false,
      usages
    );
  }
}

registerTab("aes", "AES Encryption", renderAES);

// ---------------------------------------------------------------------------
// Tool 18: Digital Signature Demo (ECDSA / RSA via WebCrypto)
// ---------------------------------------------------------------------------
//
// A digital signature proves two things at once: the message came from the
// holder of a specific private key (authentication) and hasn't been
// altered since it was signed (integrity) -- unlike encryption, signing
// does not hide the message content. This walkthrough generates a real
// key pair with WebCrypto, signs a message with the private key, and
// verifies it with the public key, then lets you tamper with the message
// to watch verification fail.

async function generateSignatureKeyPair(algorithm) {
  if (algorithm === "ECDSA") {
    return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  }
  return crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"]
  );
}

async function signMessage(privateKey, algorithm, message) {
  const params = algorithm === "ECDSA" ? { name: "ECDSA", hash: "SHA-256" } : { name: "RSASSA-PKCS1-v1_5" };
  const sig = await crypto.subtle.sign(params, privateKey, TE.encode(message));
  return new Uint8Array(sig);
}

async function verifySignature(publicKey, algorithm, message, signature) {
  const params = algorithm === "ECDSA" ? { name: "ECDSA", hash: "SHA-256" } : { name: "RSASSA-PKCS1-v1_5" };
  return crypto.subtle.verify(params, publicKey, signature, TE.encode(message));
}

function renderSignatureDemo(root) {
  root.innerHTML = `
    <div class="tk-section">
    <h2 class="pg-h2">Digital Signature Demo</h2>
    <p class="muted">Signing is the mirror image of encryption: instead of a public key
      encrypting for a private key to decrypt, a <em>private</em> key signs and the matching
      <em>public</em> key verifies. Anyone with the public key can confirm the message hasn't
      been altered and really was signed by the private key holder -- without being able to
      forge a new signature themselves. This walkthrough uses real WebCrypto ECDSA (P-256) or
      RSA (RSASSA-PKCS1-v1_5, 2048-bit) key pairs.</p>

    <div class="tk-row">
      <select class="tk-f" id="sig-algo">
        <option value="ECDSA">ECDSA (P-256) -- smaller, faster keys</option>
        <option value="RSA">RSA (2048-bit, PKCS#1 v1.5) -- widely compatible</option>
      </select>
      <button class="btn sm" id="sig-genkeys">Step 1: Generate key pair</button>
    </div>
    <pre class="tk-out" id="sig-keys" style="min-height:120px"></pre>

    <div class="tk-row" style="margin-top:14px">
      <textarea class="tk-in" id="sig-msg" rows="3" placeholder="Step 2: message to sign..." style="flex:1"></textarea>
    </div>
    <div class="tk-btns">
      <button class="btn sm" id="sig-sign">Sign with private key</button>
    </div>
    <pre class="tk-out" id="sig-out" style="min-height:100px"></pre>

    <div class="tk-row" style="margin-top:14px">
      <textarea class="tk-in" id="sig-verifymsg" rows="3" placeholder="Step 3: message to verify (try editing it to see verification fail)..." style="flex:1"></textarea>
    </div>
    <div class="tk-btns">
      <button class="btn sm" id="sig-verify">Verify with public key</button>
    </div>
    <div id="sig-verify-out" style="margin-top:10px"></div>

    <div class="card" style="margin-top:16px">
      <strong>Why this matters</strong>
      <p class="muted" style="margin-top:6px">Software updates, TLS certificates, and
        cryptocurrency transactions all rely on this exact primitive: a private key you never
        share signs something, and everyone else uses the corresponding public key to confirm
        it's authentic and unmodified. Change even one character of the message below and
        verification will fail -- that's the whole security guarantee in action.</p>
    </div>
    </div>
  `;

  const algoSel = root.querySelector("#sig-algo");
  const keysOut = root.querySelector("#sig-keys");
  const msgInp = root.querySelector("#sig-msg");
  const sigOut = root.querySelector("#sig-out");
  const verifyMsgInp = root.querySelector("#sig-verifymsg");
  const verifyOut = root.querySelector("#sig-verify-out");

  let keyPair = null;
  let lastSignatureHex = null;

  root.querySelector("#sig-genkeys").onclick = async () => {
    keysOut.textContent = "Generating key pair...";
    try {
      keyPair = await generateSignatureKeyPair(algoSel.value);
      const spki = await crypto.subtle.exportKey("spki", keyPair.publicKey);
      const pkcs8 = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
      keysOut.textContent =
`Algorithm: ${algoSel.value}

Public key (SPKI, base64) -- safe to share:
${bytesToBase64(new Uint8Array(spki))}

Private key (PKCS8, base64) -- NEVER share this, shown here only for demonstration:
${bytesToBase64(new Uint8Array(pkcs8))}

Key pair generated and held in memory for this session. Proceed to Step 2.`;
    } catch (err) {
      keysOut.textContent = "Error: " + err.message;
    }
  };

  root.querySelector("#sig-sign").onclick = async () => {
    if (!keyPair) { sigOut.textContent = "Generate a key pair first (Step 1)."; return; }
    if (!msgInp.value) { sigOut.textContent = "Enter a message to sign."; return; }
    try {
      const sig = await signMessage(keyPair.privateKey, algoSel.value, msgInp.value);
      lastSignatureHex = bytesToHex(sig);
      sigOut.textContent =
`Message signed with the private key.

Signature (hex, ${sig.length} bytes):
${lastSignatureHex}

Signature (base64):
${bytesToBase64(sig)}

The message text itself is NOT hidden by this signature -- signing provides
authenticity and integrity, not confidentiality. Copy the message into the
verify box below (unchanged, or edited to test failure) and click Verify.`;
      verifyMsgInp.value = msgInp.value;
    } catch (err) {
      sigOut.textContent = "Error: " + err.message;
    }
  };

  root.querySelector("#sig-verify").onclick = async () => {
    if (!keyPair) { verifyOut.innerHTML = '<p class="muted">Generate a key pair first (Step 1).</p>'; return; }
    if (!lastSignatureHex) { verifyOut.innerHTML = '<p class="muted">Sign a message first (Step 2).</p>'; return; }
    try {
      const sig = hexToBytes(lastSignatureHex);
      const valid = await verifySignature(keyPair.publicKey, algoSel.value, verifyMsgInp.value, sig);
      verifyOut.innerHTML = valid
        ? '<div class="card"><strong style="color:#4ade80">VALID</strong><p class="muted" style="margin-top:6px">The signature matches this exact message and this public key. The message is authentic and unmodified since signing.</p></div>'
        : '<div class="card"><strong style="color:#f87171">INVALID</strong><p class="muted" style="margin-top:6px">The signature does NOT match this message. Either the message was altered after signing, or this isn\'t the matching key pair -- this is exactly the tamper-detection digital signatures are built for.</p></div>';
    } catch (err) {
      verifyOut.innerHTML = `<p class="muted">Error: ${escapeHtml(err.message)}</p>`;
    }
  };
}

registerTab("signature", "Digital Signature Demo", renderSignatureDemo);

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

export function renderCryptoTools(main) {
  main.innerHTML = `
    <div class="dash-hero">
      <div class="eyebrow">Cryptography &amp; Encoding</div>
      <h1 class="pg-h1">Crypto Tools</h1>
      <p class="pg-sub">Classical ciphers, modern crypto primitives, encodings and analysis --
        eighteen self-contained tools for learning how cryptography actually works, all running
        locally in your browser.</p>
    </div>
    <div class="tab-bar" id="ct-tabbar"></div>
    <div class="panel" id="ct-body"></div>
  `;

  const tabbar = main.querySelector("#ct-tabbar");
  const body = main.querySelector("#ct-body");

  tabbar.innerHTML = TABS.map((t, i) => `<button class="tab${i === 0 ? " active" : ""}" data-tab="${t.id}">${t.label}</button>`).join("");

  function activate(id) {
    for (const btn of tabbar.querySelectorAll(".tab")) {
      btn.classList.toggle("active", btn.dataset.tab === id);
    }
    const tab = TABS.find((t) => t.id === id) || TABS[0];
    body.innerHTML = "";
    const wrap = document.createElement("div");
    wrap.className = "ct-tool";
    body.appendChild(wrap);
    tab.render(wrap);
  }

  tabbar.onclick = (e) => {
    const btn = e.target.closest("button[data-tab]");
    if (!btn) return;
    activate(btn.dataset.tab);
  };

  activate(TABS[0].id);
}
