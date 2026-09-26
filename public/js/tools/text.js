// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Text manipulation mini-tools. See _schema.md for the contract.
const S = (v) => (v == null ? "" : String(v));

const stripAccents = (s) => S(s).normalize("NFD").replace(/[̀-ͯ]/g, "");

// Split arbitrary text (camelCase, snake_case, kebab-case, spaces, ...) into words.
const splitWords = (s) =>
  S(s)
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean);

const esc = (s) => S(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export const TOOLS = [
  { id: "t-text-stats", name: "Word / Character / Line Counter", cat: "text", desc: "Count words, characters, lines and UTF-8 bytes.", tags: ["count", "stats", "length"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8, placeholder: "Paste text here..." }],
    run(v, H) {
      if (!v.text) return "";
      const words = (v.text.match(/\S+/g) || []).length;
      const chars = Array.from(v.text).length;
      const charsNoSpaces = Array.from(v.text.replace(/\s/g, "")).length;
      const lines = v.text.split(/\r?\n/).length;
      const bytes = H.bytes(v.text).length;
      return `Words: ${words}\nCharacters: ${chars}\nCharacters (no spaces): ${charsNoSpaces}\nLines: ${lines}\nBytes (UTF-8): ${bytes}`;
    } },

  { id: "t-case-convert", name: "Case Converter", cat: "text", desc: "Convert text to UPPER, lower, Title, or Sentence case.", tags: ["case", "uppercase", "lowercase"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }, { k: "mode", label: "Case", type: "select", opts: ["UPPER CASE", "lower case", "Title Case", "Sentence case"], value: "Title Case" }],
    run(v) {
      if (!v.text) return "";
      if (v.mode === "UPPER CASE") return v.text.toUpperCase();
      if (v.mode === "lower case") return v.text.toLowerCase();
      if (v.mode === "Title Case") return v.text.replace(/\w\S*/g, (w) => w[0].toUpperCase() + w.slice(1).toLowerCase());
      if (v.mode === "Sentence case") { const lower = v.text.toLowerCase(); return lower.replace(/(^\s*\w|[.!?]\s+\w)/g, (c) => c.toUpperCase()); }
      return v.text;
    } },

  { id: "t-camel-case", name: "camelCase Converter", cat: "text", desc: "Convert text to camelCase.", tags: ["case", "identifier", "camel"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 4, placeholder: "some example text" }],
    run(v) { const w = splitWords(v.text); if (!w.length) return ""; return w.map((x, i) => (i === 0 ? x.toLowerCase() : x[0].toUpperCase() + x.slice(1).toLowerCase())).join(""); } },

  { id: "t-pascal-case", name: "PascalCase Converter", cat: "text", desc: "Convert text to PascalCase.", tags: ["case", "identifier", "pascal"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 4 }],
    run(v) { const w = splitWords(v.text); if (!w.length) return ""; return w.map((x) => x[0].toUpperCase() + x.slice(1).toLowerCase()).join(""); } },

  { id: "t-snake-case", name: "snake_case Converter", cat: "text", desc: "Convert text to snake_case.", tags: ["case", "identifier", "snake"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 4 }],
    run(v) { const w = splitWords(v.text); if (!w.length) return ""; return w.map((x) => x.toLowerCase()).join("_"); } },

  { id: "t-kebab-case", name: "kebab-case Converter", cat: "text", desc: "Convert text to kebab-case.", tags: ["case", "identifier", "kebab"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 4 }],
    run(v) { const w = splitWords(v.text); if (!w.length) return ""; return w.map((x) => x.toLowerCase()).join("-"); } },

  { id: "t-constant-case", name: "CONSTANT_CASE Converter", cat: "text", desc: "Convert text to CONSTANT_CASE.", tags: ["case", "identifier", "constant"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 4 }],
    run(v) { const w = splitWords(v.text); if (!w.length) return ""; return w.map((x) => x.toUpperCase()).join("_"); } },

  { id: "t-slugify", name: "Slugify", cat: "text", desc: "Turn text into a URL-safe slug (accents stripped).", tags: ["slug", "url", "seo"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 4, placeholder: "My Café Post!" }, { k: "separator", label: "Separator", type: "select", opts: ["-", "_"], value: "-" }],
    run(v) {
      if (!v.text) return "";
      const sep = v.separator === "_" ? "_" : "-";
      let slug = stripAccents(v.text).toLowerCase().replace(/[^a-z0-9]+/g, sep);
      while (slug.startsWith(sep)) slug = slug.slice(1);
      while (slug.endsWith(sep)) slug = slug.slice(0, -1);
      return slug;
    } },

  { id: "t-slug-maxlen", name: "Title → Slug (max length)", cat: "text", desc: "Slugify text and cap it at a maximum character length.", tags: ["slug", "url", "truncate"],
    inputs: [{ k: "text", label: "Title", type: "textarea", rows: 3, placeholder: "An extremely long article title goes here" }, { k: "maxLength", label: "Max length", type: "text", inputType: "number", value: "60" }],
    run(v, H) {
      if (!v.text) return "";
      const max = H.clampInt(v.maxLength, 1, 500, 60);
      let slug = stripAccents(v.text).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
      if (slug.length > max) slug = slug.slice(0, max).replace(/-+$/, "");
      return slug;
    } },

  { id: "t-sort-lines", name: "Sort Lines", cat: "text", desc: "Sort lines ascending, descending, naturally, or by length.", tags: ["sort", "lines", "order"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "order", label: "Order", type: "select", opts: ["Ascending", "Descending", "Natural", "By length"], value: "Ascending" }, { k: "caseInsensitive", label: "Case-insensitive", type: "checkbox", value: false }],
    run(v) {
      if (!v.text) return "";
      const lines = v.text.split(/\r?\n/);
      const cmp = (a, b) => v.caseInsensitive ? a.localeCompare(b, undefined, { sensitivity: "base" }) : (a < b ? -1 : a > b ? 1 : 0);
      if (v.order === "Ascending") lines.sort(cmp);
      else if (v.order === "Descending") lines.sort((a, b) => cmp(b, a));
      else if (v.order === "Natural") lines.sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: v.caseInsensitive ? "base" : "variant" }));
      else if (v.order === "By length") lines.sort((a, b) => a.length - b.length);
      return lines.join("\n");
    } },

  { id: "t-reverse-lines", name: "Reverse Line Order", cat: "text", desc: "Reverse the order of lines (last line first).", tags: ["reverse", "lines"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }],
    run(v) { if (!v.text) return ""; return v.text.split(/\r?\n/).reverse().join("\n"); } },

  { id: "t-reverse-line-chars", name: "Reverse Each Line's Characters", cat: "text", desc: "Reverse the characters within every line (line order kept).", tags: ["reverse", "characters"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }],
    run(v) { if (!v.text) return ""; return v.text.split(/\r?\n/).map((l) => Array.from(l).reverse().join("")).join("\n"); } },

  { id: "t-dedupe-lines", name: "Deduplicate Lines", cat: "text", desc: "Remove duplicate lines, keeping the first occurrence's order.", tags: ["dedupe", "unique", "lines"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }],
    run(v) {
      if (!v.text) return "";
      const seen = new Set(); const out = [];
      for (const line of v.text.split(/\r?\n/)) { if (!seen.has(line)) { seen.add(line); out.push(line); } }
      return out.join("\n");
    } },

  { id: "t-remove-blank-lines", name: "Remove Blank Lines", cat: "text", desc: "Strip out empty or whitespace-only lines.", tags: ["blank", "empty", "lines"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }],
    run(v) { if (!v.text) return ""; return v.text.split(/\r?\n/).filter((l) => l.trim() !== "").join("\n"); } },

  { id: "t-trim-lines", name: "Trim Whitespace on Each Line", cat: "text", desc: "Trim leading/trailing whitespace from every line.", tags: ["trim", "whitespace", "lines"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }],
    run(v) { if (!v.text) return ""; return v.text.split(/\r?\n/).map((l) => l.trim()).join("\n"); } },

  { id: "t-collapse-spaces", name: "Collapse Multiple Spaces", cat: "text", desc: "Collapse runs of spaces/tabs into a single space.", tags: ["whitespace", "collapse"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }],
    run(v) { if (!v.text) return ""; return v.text.replace(/[ \t]{2,}/g, " "); } },

  { id: "t-find-replace", name: "Find & Replace", cat: "text", desc: "Replace all matches of a string or regex pattern.", tags: ["replace", "regex", "search"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "find", label: "Find", type: "text", placeholder: "foo" }, { k: "replace", label: "Replace with", type: "text", placeholder: "bar" }, { k: "regex", label: "Treat find as regex", type: "checkbox", value: false }, { k: "caseInsensitive", label: "Case-insensitive", type: "checkbox", value: false }],
    run(v) {
      if (!v.text) return "";
      if (!v.find) return v.text;
      try {
        const flags = "g" + (v.caseInsensitive ? "i" : "");
        const pattern = v.regex ? v.find : esc(v.find);
        const re = new RegExp(pattern, flags);
        return v.text.replace(re, v.replace || "");
      } catch (e) { return { error: "Invalid regex pattern." }; }
    } },

  { id: "t-count-occurrences", name: "Count Substring Occurrences", cat: "text", desc: "Count how many times a substring appears.", tags: ["count", "occurrences", "search"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "substring", label: "Substring", type: "text" }, { k: "caseInsensitive", label: "Case-insensitive", type: "checkbox", value: false }],
    run(v) {
      if (!v.text || !v.substring) return "";
      try {
        const flags = "g" + (v.caseInsensitive ? "i" : "");
        const matches = v.text.match(new RegExp(esc(v.substring), flags));
        return `Occurrences: ${matches ? matches.length : 0}`;
      } catch (e) { return { error: "Invalid input." }; }
    } },

  { id: "t-line-numbers", name: "Add Line Numbers", cat: "text", desc: "Prefix every line with a sequential number.", tags: ["lines", "numbering"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "start", label: "Start at", type: "text", inputType: "number", value: "1" }, { k: "pad", label: "Zero-pad numbers", type: "checkbox", value: false }],
    run(v, H) {
      if (!v.text) return "";
      const lines = v.text.split(/\r?\n/);
      const start = H.clampInt(v.start, -1000000, 1000000, 1);
      const width = String(start + lines.length - 1).length;
      return lines.map((l, i) => { const n = start + i; return (v.pad ? String(n).padStart(width, "0") : String(n)) + ". " + l; }).join("\n");
    } },

  { id: "t-prefix-suffix", name: "Add Prefix / Suffix to Lines", cat: "text", desc: "Prepend and/or append text to every line.", tags: ["prefix", "suffix", "lines"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "prefix", label: "Prefix", type: "text" }, { k: "suffix", label: "Suffix", type: "text" }, { k: "skipBlank", label: "Skip blank lines", type: "checkbox", value: true }],
    run(v) {
      if (!v.text) return "";
      return v.text.split(/\r?\n/).map((l) => (v.skipBlank && l.trim() === "") ? l : (v.prefix || "") + l + (v.suffix || "")).join("\n");
    } },

  { id: "t-wrap-indent", name: "Wrap / Indent Lines", cat: "text", desc: "Word-wrap text to a column width and optionally indent it.", tags: ["wrap", "indent", "columns"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "width", label: "Wrap width", type: "text", inputType: "number", value: "80" }, { k: "indent", label: "Indent (prefix each line)", type: "text", placeholder: "    " }],
    run(v, H) {
      if (!v.text) return "";
      const width = H.clampInt(v.width, 10, 1000, 80);
      const indent = v.indent || "";
      const out = [];
      for (const para of v.text.split(/\r?\n/)) {
        if (para === "") { out.push(indent); continue; }
        const words = para.split(/\s+/).filter(Boolean);
        let line = "";
        for (const w of words) {
          if ((line ? line + " " + w : w).length > width && line) { out.push(indent + line); line = w; }
          else line = line ? line + " " + w : w;
        }
        if (line) out.push(indent + line);
      }
      return out.join("\n");
    } },

  { id: "t-truncate", name: "Truncate Text", cat: "text", desc: "Cut text down to N characters with an ellipsis.", tags: ["truncate", "ellipsis", "cut"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }, { k: "length", label: "Max characters", type: "text", inputType: "number", value: "100" }, { k: "ellipsis", label: "Ellipsis", type: "text", value: "..." }],
    run(v, H) {
      if (!v.text) return "";
      const n = H.clampInt(v.length, 0, 1000000, 100);
      if (v.text.length <= n) return v.text;
      const ell = v.ellipsis != null ? v.ellipsis : "...";
      return v.text.slice(0, Math.max(0, n - ell.length)) + ell;
    } },

  { id: "t-remove-accents", name: "Remove Accents / Diacritics", cat: "text", desc: "Strip accents so text becomes plain ASCII-ish letters.", tags: ["accents", "diacritics", "normalize"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6, placeholder: "Café, naïve, Zürich" }],
    run(v) { if (!v.text) return ""; return stripAccents(v.text); } },

  { id: "t-strip-html", name: "Strip HTML Tags", cat: "text", desc: "Remove all HTML tags, leaving plain text.", tags: ["html", "strip", "sanitize"],
    inputs: [{ k: "text", label: "HTML", type: "textarea", rows: 8, placeholder: "<p>Hello <b>world</b></p>" }],
    run(v) { if (!v.text) return ""; return v.text.replace(/<\/?[a-zA-Z][^>]*>/g, "").replace(/[ \t]{2,}/g, " "); } },

  { id: "t-extract-emails", name: "Extract Email Addresses", cat: "text", desc: "Pull all email addresses out of a block of text.", tags: ["email", "extract", "regex"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "dedupe", label: "Unique only", type: "checkbox", value: true }],
    run(v) {
      if (!v.text) return "";
      const m = v.text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [];
      const list = v.dedupe ? [...new Set(m)] : m;
      return list.length ? list.join("\n") : "No email addresses found.";
    } },

  { id: "t-extract-urls", name: "Extract URLs", cat: "text", desc: "Pull all http(s) URLs out of a block of text.", tags: ["url", "extract", "regex"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "dedupe", label: "Unique only", type: "checkbox", value: true }],
    run(v) {
      if (!v.text) return "";
      const m = v.text.match(/\bhttps?:\/\/[^\s<>"'\)]+/gi) || [];
      const list = v.dedupe ? [...new Set(m)] : m;
      return list.length ? list.join("\n") : "No URLs found.";
    } },

  { id: "t-extract-ips", name: "Extract IPv4 Addresses", cat: "text", desc: "Pull all valid IPv4 addresses out of a block of text.", tags: ["ip", "ipv4", "extract"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "dedupe", label: "Unique only", type: "checkbox", value: true }],
    run(v) {
      if (!v.text) return "";
      const m = v.text.match(/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g) || [];
      const list = v.dedupe ? [...new Set(m)] : m;
      return list.length ? list.join("\n") : "No IPv4 addresses found.";
    } },

  { id: "t-tabs-spaces", name: "Tabs ↔ Spaces", cat: "text", desc: "Convert tabs to spaces or spaces to tabs at a given width.", tags: ["tabs", "spaces", "indentation"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "mode", label: "Direction", type: "select", opts: ["Tabs → Spaces", "Spaces → Tabs"], value: "Tabs → Spaces" }, { k: "width", label: "Width", type: "text", inputType: "number", value: "4" }],
    run(v, H) {
      if (!v.text) return "";
      const width = H.clampInt(v.width, 1, 16, 4);
      if (v.mode === "Tabs → Spaces") return v.text.replace(/\t/g, " ".repeat(width));
      const re = new RegExp(" ".repeat(width), "g");
      return v.text.replace(re, "\t");
    } },

  { id: "t-shuffle-lines", name: "Shuffle Lines", cat: "text", desc: "Randomly shuffle the order of lines.", tags: ["shuffle", "random", "lines"], button: "Shuffle", live: false,
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }],
    run(v) {
      if (!v.text) return "";
      const lines = v.text.split(/\r?\n/);
      for (let i = lines.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [lines[i], lines[j]] = [lines[j], lines[i]]; }
      return lines.join("\n");
    } },

  { id: "t-unique-words", name: "List Unique Words", cat: "text", desc: "List each distinct word once, in order of first appearance.", tags: ["unique", "words", "list"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "caseInsensitive", label: "Case-insensitive", type: "checkbox", value: true }],
    run(v) {
      if (!v.text) return "";
      const words = v.text.match(/[A-Za-z0-9'’-]+/g) || [];
      const seen = new Set(); const out = [];
      for (const w of words) { const key = v.caseInsensitive ? w.toLowerCase() : w; if (!seen.has(key)) { seen.add(key); out.push(w); } }
      return out.join("\n");
    } },

  { id: "t-word-frequency", name: "Word Frequency Counter", cat: "text", desc: "Count word frequency and show the top N most common.", tags: ["frequency", "words", "count"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "topN", label: "Top N", type: "text", inputType: "number", value: "10" }, { k: "caseInsensitive", label: "Case-insensitive", type: "checkbox", value: true }],
    run(v, H) {
      if (!v.text) return "";
      const raw = v.text.match(/[A-Za-z0-9']+/g) || [];
      if (!raw.length) return "";
      const words = raw.map((w) => (v.caseInsensitive ? w.toLowerCase() : w));
      const freq = new Map();
      for (const w of words) freq.set(w, (freq.get(w) || 0) + 1);
      const n = H.clampInt(v.topN, 1, 1000, 10);
      return [...freq.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map(([w, c]) => `${w}: ${c}`).join("\n");
    } },

  { id: "t-palindrome-check", name: "Palindrome Checker", cat: "text", desc: "Check if text reads the same forwards and backwards.", tags: ["palindrome", "check"],
    inputs: [{ k: "text", label: "Text", type: "text", placeholder: "A man, a plan, a canal: Panama" }],
    run(v) {
      if (!v.text) return "";
      const cleaned = v.text.toLowerCase().replace(/[^a-z0-9]/g, "");
      if (!cleaned) return "Nothing to check.";
      const rev = Array.from(cleaned).reverse().join("");
      return cleaned === rev ? `Yes — that is a palindrome (ignoring case/punctuation/spaces).` : `No — that is not a palindrome.`;
    } },

  { id: "t-anagram-check", name: "Anagram Checker", cat: "text", desc: "Check whether two texts are anagrams of each other.", tags: ["anagram", "check", "compare"],
    inputs: [{ k: "text1", label: "Text A", type: "text", placeholder: "listen" }, { k: "text2", label: "Text B", type: "text", placeholder: "silent" }],
    run(v) {
      if (!v.text1 || !v.text2) return "";
      const norm = (s) => Array.from(s.toLowerCase().replace(/[^a-z0-9]/g, "")).sort().join("");
      const a = norm(v.text1), b = norm(v.text2);
      if (!a && !b) return "Both inputs are empty.";
      return a === b ? "Yes — these are anagrams of each other." : "No — these are not anagrams.";
    } },

  { id: "t-reading-time", name: "Reading Time / Text Statistics", cat: "text", desc: "Estimate reading time along with word and sentence counts.", tags: ["reading", "statistics", "time"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "wpm", label: "Words per minute", type: "text", inputType: "number", value: "200" }],
    run(v, H) {
      if (!v.text) return "";
      const words = (v.text.match(/\S+/g) || []).length;
      const sentences = (v.text.match(/[^.!?]+[.!?]+/g) || (v.text.trim() ? [v.text] : [])).length;
      const chars = v.text.length;
      const wpm = H.clampInt(v.wpm, 50, 1000, 200);
      const minutes = Math.max(1, Math.round(words / wpm));
      return `Words: ${words}\nSentences: ${sentences}\nCharacters: ${chars}\nEstimated reading time: ~${minutes} min (at ${wpm} wpm)`;
    } },

  { id: "t-dedupe-consecutive-words", name: "Remove Duplicate Consecutive Words", cat: "text", desc: "Collapse repeated back-to-back words (\"the the\" → \"the\").", tags: ["dedupe", "words", "repeat"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6, placeholder: "This is is a test test." }, { k: "caseInsensitive", label: "Case-insensitive", type: "checkbox", value: true }],
    run(v) {
      if (!v.text) return "";
      const flags = v.caseInsensitive ? "gi" : "g";
      return v.text.replace(new RegExp("\\b(\\S+)(\\s+\\1\\b)+", flags), "$1");
    } },

  { id: "t-json-oneline", name: "JSON-safe One-liner", cat: "text", desc: "Escape quotes/backslashes and collapse newlines so text is safe to embed as one JSON line.", tags: ["json", "oneline", "escape"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }],
    run(v) {
      if (!v.text) return "";
      return v.text.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\t/g, "\\t").replace(/\r\n|\r|\n/g, "\\n");
    } },
];
