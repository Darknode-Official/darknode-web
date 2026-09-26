// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Text & formatting mini-tools.
const S = (v) => (v == null ? "" : String(v));

// Split arbitrary text (camelCase, snake_case, kebab-case, spaces, ...) into words.
const splitWords = (s) =>
  S(s)
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean);

const stripAccents = (s) => S(s).normalize("NFD").replace(/[̀-ͯ]/g, "");
const escRe = (s) => S(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const lines = (s) => S(s).split(/\r?\n/);

// 5-row block font for the ASCII banner tool (A-Z, 0-9, space).
const BANNER_FONT = {
  A: [" ### ", "#   #", "#####", "#   #", "#   #"],
  B: ["#### ", "#   #", "#### ", "#   #", "#### "],
  C: [" ####", "#    ", "#    ", "#    ", " ####"],
  D: ["#### ", "#   #", "#   #", "#   #", "#### "],
  E: ["#####", "#    ", "#### ", "#    ", "#####"],
  F: ["#####", "#    ", "#### ", "#    ", "#    "],
  G: [" ####", "#    ", "#  ##", "#   #", " ####"],
  H: ["#   #", "#   #", "#####", "#   #", "#   #"],
  I: ["#####", "  #  ", "  #  ", "  #  ", "#####"],
  J: ["#####", "   # ", "   # ", "#  # ", " ##  "],
  K: ["#   #", "#  # ", "###  ", "#  # ", "#   #"],
  L: ["#    ", "#    ", "#    ", "#    ", "#####"],
  M: ["#   #", "## ##", "# # #", "#   #", "#   #"],
  N: ["#   #", "##  #", "# # #", "#  ##", "#   #"],
  O: [" ### ", "#   #", "#   #", "#   #", " ### "],
  P: ["#### ", "#   #", "#### ", "#    ", "#    "],
  Q: [" ### ", "#   #", "# # #", "#  # ", " ## #"],
  R: ["#### ", "#   #", "#### ", "#  # ", "#   #"],
  S: [" ####", "#    ", " ### ", "    #", "#### "],
  T: ["#####", "  #  ", "  #  ", "  #  ", "  #  "],
  U: ["#   #", "#   #", "#   #", "#   #", " ### "],
  V: ["#   #", "#   #", "#   #", " # # ", "  #  "],
  W: ["#   #", "#   #", "# # #", "## ##", "#   #"],
  X: ["#   #", " # # ", "  #  ", " # # ", "#   #"],
  Y: ["#   #", " # # ", "  #  ", "  #  ", "  #  "],
  Z: ["#####", "   # ", "  #  ", " #   ", "#####"],
  "0": [" ### ", "#  ##", "# # #", "##  #", " ### "],
  "1": ["  #  ", " ##  ", "  #  ", "  #  ", "#####"],
  "2": [" ### ", "#   #", "  ## ", " #   ", "#####"],
  "3": ["#### ", "    #", " ### ", "    #", "#### "],
  "4": ["#  # ", "#  # ", "#####", "   # ", "   # "],
  "5": ["#####", "#    ", "#### ", "    #", "#### "],
  "6": [" ####", "#    ", "#### ", "#   #", " ### "],
  "7": ["#####", "   # ", "  #  ", " #   ", " #   "],
  "8": [" ### ", "#   #", " ### ", "#   #", " ### "],
  "9": [" ### ", "#   #", " ####", "    #", " ### "],
  " ": ["     ", "     ", "     ", "     ", "     "],
};

export const TOOLS = [
  { id: "tx-uppercase", name: "UPPERCASE", cat: "textx", desc: "Convert all letters to uppercase.", tags: ["case", "upper"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }],
    run(v) { return v.text ? v.text.toUpperCase() : ""; } },

  { id: "tx-lowercase", name: "lowercase", cat: "textx", desc: "Convert all letters to lowercase.", tags: ["case", "lower"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }],
    run(v) { return v.text ? v.text.toLowerCase() : ""; } },

  { id: "tx-title-case", name: "Title Case", cat: "textx", desc: "Capitalize the first letter of each word, lowercasing the rest.", tags: ["case", "title"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }],
    run(v) { return v.text ? v.text.replace(/\w\S*/g, (w) => w[0].toUpperCase() + w.slice(1).toLowerCase()) : ""; } },

  { id: "tx-sentence-case", name: "Sentence case", cat: "textx", desc: "Lowercase everything, then capitalize the first letter of each sentence.", tags: ["case", "sentence"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }],
    run(v) { if (!v.text) return ""; return v.text.toLowerCase().replace(/(^\s*[a-z])|([.!?]\s+[a-z])/g, (c) => c.toUpperCase()); } },

  { id: "tx-camel-case", name: "camelCase", cat: "textx", desc: "Convert text to camelCase.", tags: ["case", "camel", "code"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 4 }],
    run(v) { const w = splitWords(v.text); if (!w.length) return ""; return w.map((x, i) => (i === 0 ? x.toLowerCase() : x[0].toUpperCase() + x.slice(1).toLowerCase())).join(""); } },

  { id: "tx-pascal-case", name: "PascalCase", cat: "textx", desc: "Convert text to PascalCase (UpperCamelCase).", tags: ["case", "pascal", "code"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 4 }],
    run(v) { const w = splitWords(v.text); if (!w.length) return ""; return w.map((x) => x[0].toUpperCase() + x.slice(1).toLowerCase()).join(""); } },

  { id: "tx-snake-case", name: "snake_case", cat: "textx", desc: "Convert text to snake_case.", tags: ["case", "snake", "code"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 4 }],
    run(v) { const w = splitWords(v.text); return w.length ? w.map((x) => x.toLowerCase()).join("_") : ""; } },

  { id: "tx-kebab-case", name: "kebab-case", cat: "textx", desc: "Convert text to kebab-case.", tags: ["case", "kebab", "code"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 4 }],
    run(v) { const w = splitWords(v.text); return w.length ? w.map((x) => x.toLowerCase()).join("-") : ""; } },

  { id: "tx-constant-case", name: "CONSTANT_CASE", cat: "textx", desc: "Convert text to CONSTANT_CASE (upper snake).", tags: ["case", "constant", "code"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 4 }],
    run(v) { const w = splitWords(v.text); return w.length ? w.map((x) => x.toUpperCase()).join("_") : ""; } },

  { id: "tx-dot-case", name: "dot.case", cat: "textx", desc: "Convert text to dot.case.", tags: ["case", "dot", "code"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 4 }],
    run(v) { const w = splitWords(v.text); return w.length ? w.map((x) => x.toLowerCase()).join(".") : ""; } },

  { id: "tx-path-case", name: "path/case", cat: "textx", desc: "Convert text to path/case (slash separated).", tags: ["case", "path", "code"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 4 }],
    run(v) { const w = splitWords(v.text); return w.length ? w.map((x) => x.toLowerCase()).join("/") : ""; } },

  { id: "tx-train-case", name: "Train-Case", cat: "textx", desc: "Convert text to Train-Case (capitalized, hyphen separated).", tags: ["case", "train"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 4 }],
    run(v) { const w = splitWords(v.text); return w.length ? w.map((x) => x[0].toUpperCase() + x.slice(1).toLowerCase()).join("-") : ""; } },

  { id: "tx-capitalize-words", name: "Capitalize Each Word", cat: "textx", desc: "Uppercase the first letter of every word, leaving the rest untouched.", tags: ["case", "capitalize"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }],
    run(v) { return v.text ? v.text.replace(/\b(\w)/g, (m) => m.toUpperCase()) : ""; } },

  { id: "tx-invert-case", name: "Invert Case", cat: "textx", desc: "Swap uppercase to lowercase and vice-versa.", tags: ["case", "invert", "swap"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }],
    run(v) { if (!v.text) return ""; return v.text.replace(/[a-zA-Z]/g, (c) => (c === c.toLowerCase() ? c.toUpperCase() : c.toLowerCase())); } },

  { id: "tx-alternating-case", name: "aLtErNaTiNg Case", cat: "textx", desc: "Alternate lower and upper case across letters.", tags: ["case", "alternating", "mock"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }, { k: "start", label: "Start with", type: "select", opts: ["lower", "upper"], value: "lower" }],
    run(v) { if (!v.text) return ""; let i = v.start === "upper" ? 1 : 0; return v.text.replace(/[a-zA-Z]/g, (c) => { const r = i % 2 === 0 ? c.toLowerCase() : c.toUpperCase(); i++; return r; }); } },

  { id: "tx-slugify", name: "Slugify (URL slug)", cat: "textx", desc: "Turn text into a lowercase, hyphenated, URL-safe slug.", tags: ["slug", "url", "seo"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 4 }, { k: "sep", label: "Separator", type: "text", value: "-" }],
    run(v) { if (!v.text) return ""; const sep = v.sep || "-"; return stripAccents(v.text).toLowerCase().replace(/[^a-z0-9]+/g, sep).replace(new RegExp("^" + escRe(sep) + "+|" + escRe(sep) + "+$", "g"), ""); } },

  { id: "tx-word-count", name: "Word Count", cat: "textx", desc: "Count the number of words in the text.", tags: ["count", "words"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }],
    run(v) { if (!v.text) return ""; return String((v.text.match(/\S+/g) || []).length); } },

  { id: "tx-char-count", name: "Character Count", cat: "textx", desc: "Count characters, with and without whitespace.", tags: ["count", "chars", "length"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }],
    run(v) { if (!v.text) return ""; const all = Array.from(v.text).length; const noSpace = Array.from(v.text.replace(/\s/g, "")).length; return `With spaces: ${all}\nWithout spaces: ${noSpace}`; } },

  { id: "tx-line-count", name: "Line Count", cat: "textx", desc: "Count the number of lines.", tags: ["count", "lines"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }],
    run(v) { if (!v.text) return ""; return String(lines(v.text).length); } },

  { id: "tx-sentence-count", name: "Sentence Count", cat: "textx", desc: "Count sentences (split on . ! ?).", tags: ["count", "sentences"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }],
    run(v) { if (!v.text) return ""; return String((v.text.match(/[^.!?]+[.!?]+/g) || (v.text.trim() ? [v.text] : [])).length); } },

  { id: "tx-paragraph-count", name: "Paragraph Count", cat: "textx", desc: "Count paragraphs (blocks separated by blank lines).", tags: ["count", "paragraphs"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }],
    run(v) { if (!v.text) return ""; return String(v.text.split(/\n\s*\n+/).map((p) => p.trim()).filter(Boolean).length); } },

  { id: "tx-unique-word-count", name: "Unique Word Count", cat: "textx", desc: "Count distinct words (case-insensitive).", tags: ["count", "unique", "words"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }],
    run(v) { if (!v.text) return ""; const w = (v.text.toLowerCase().match(/[a-z0-9']+/g) || []); return String(new Set(w).size); } },

  { id: "tx-word-frequency", name: "Word Frequency (Top N)", cat: "textx", desc: "Show the most frequent words and their counts.", tags: ["frequency", "count", "words"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }, { k: "n", label: "Top N", type: "range", min: 1, max: 50, step: 1, value: 10 }],
    run(v, H) { if (!v.text) return ""; const n = H.clampInt(v.n, 1, 50, 10); const w = (v.text.toLowerCase().match(/[a-z0-9']+/g) || []); const m = new Map(); for (const x of w) m.set(x, (m.get(x) || 0) + 1); const sorted = [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, n); return sorted.map(([k, c]) => `${c}\t${k}`).join("\n"); } },

  { id: "tx-sort-lines-alpha", name: "Sort Lines Alphabetically", cat: "textx", desc: "Sort lines A→Z or Z→A.", tags: ["sort", "lines", "alpha"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "dir", label: "Direction", type: "select", opts: ["ascending", "descending"], value: "ascending" }, { k: "ci", label: "Case-insensitive", type: "checkbox", value: true }],
    run(v) { if (!v.text) return ""; const arr = lines(v.text); arr.sort((a, b) => (v.ci ? a.toLowerCase().localeCompare(b.toLowerCase()) : a.localeCompare(b))); if (v.dir === "descending") arr.reverse(); return arr.join("\n"); } },

  { id: "tx-sort-lines-numeric", name: "Sort Lines Numerically", cat: "textx", desc: "Sort lines by the first number found on each line.", tags: ["sort", "lines", "numeric"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "dir", label: "Direction", type: "select", opts: ["ascending", "descending"], value: "ascending" }],
    run(v) { if (!v.text) return ""; const num = (s) => { const m = s.match(/-?\d+(\.\d+)?/); return m ? parseFloat(m[0]) : Infinity; }; const arr = lines(v.text).slice().sort((a, b) => num(a) - num(b)); if (v.dir === "descending") arr.reverse(); return arr.join("\n"); } },

  { id: "tx-sort-lines-length", name: "Sort Lines by Length", cat: "textx", desc: "Sort lines from shortest to longest (or reverse).", tags: ["sort", "lines", "length"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "dir", label: "Direction", type: "select", opts: ["shortest first", "longest first"], value: "shortest first" }],
    run(v) { if (!v.text) return ""; const arr = lines(v.text).slice().sort((a, b) => a.length - b.length); if (v.dir === "longest first") arr.reverse(); return arr.join("\n"); } },

  { id: "tx-reverse-lines", name: "Reverse Line Order", cat: "textx", desc: "Reverse the order of the lines.", tags: ["reverse", "lines"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }],
    run(v) { if (!v.text) return ""; return lines(v.text).reverse().join("\n"); } },

  { id: "tx-shuffle-lines", name: "Shuffle Lines", cat: "textx", desc: "Randomly shuffle the lines.", tags: ["shuffle", "lines", "random"], live: false,
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }],
    run(v, H) { if (!v.text) return ""; const arr = lines(v.text); for (let i = arr.length - 1; i > 0; i--) { const j = H.randBytes(1)[0] % (i + 1); const t = arr[i]; arr[i] = arr[j]; arr[j] = t; } return arr.join("\n"); } },

  { id: "tx-dedupe-lines", name: "Deduplicate Lines", cat: "textx", desc: "Remove duplicate lines, keeping the first occurrence.", tags: ["dedupe", "unique", "lines"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "ci", label: "Case-insensitive", type: "checkbox", value: false }],
    run(v) { if (!v.text) return ""; const seen = new Set(); const out = []; for (const l of lines(v.text)) { const key = v.ci ? l.toLowerCase() : l; if (!seen.has(key)) { seen.add(key); out.push(l); } } return out.join("\n"); } },

  { id: "tx-remove-empty-lines", name: "Remove Empty Lines", cat: "textx", desc: "Delete blank (or whitespace-only) lines.", tags: ["clean", "empty", "lines"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }],
    run(v) { if (!v.text) return ""; return lines(v.text).filter((l) => l.trim() !== "").join("\n"); } },

  { id: "tx-collapse-spaces", name: "Collapse Multiple Spaces", cat: "textx", desc: "Replace runs of spaces/tabs with a single space.", tags: ["clean", "spaces", "whitespace"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }],
    run(v) { if (!v.text) return ""; return v.text.replace(/[ \t]+/g, " "); } },

  { id: "tx-collapse-blank-lines", name: "Collapse Blank Lines", cat: "textx", desc: "Collapse runs of blank lines into a single blank line.", tags: ["clean", "blank", "lines"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }],
    run(v) { if (!v.text) return ""; return v.text.replace(/\n\s*\n\s*\n+/g, "\n\n"); } },

  { id: "tx-trim-lines", name: "Trim Lines", cat: "textx", desc: "Trim whitespace from each line (both sides, left, or right).", tags: ["trim", "lines", "whitespace"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "side", label: "Side", type: "select", opts: [["both", "Both sides"], ["left", "Left only"], ["right", "Right only"]], value: "both" }],
    run(v) { if (!v.text) return ""; return lines(v.text).map((l) => { if (v.side === "left") return l.replace(/^\s+/, ""); if (v.side === "right") return l.replace(/\s+$/, ""); return l.trim(); }).join("\n"); } },

  { id: "tx-number-lines", name: "Number the Lines", cat: "textx", desc: "Prefix each line with a line number.", tags: ["number", "lines"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "start", label: "Start at", type: "text", inputType: "number", value: "1" }, { k: "sep", label: "Separator", type: "text", value: ". " }],
    run(v, H) { if (!v.text) return ""; const start = H.clampInt(v.start, -1e9, 1e9, 1); const sep = v.sep == null ? ". " : v.sep; const arr = lines(v.text); const w = String(start + arr.length - 1).length; return arr.map((l, i) => String(start + i).padStart(w, " ") + sep + l).join("\n"); } },

  { id: "tx-prefix-lines", name: "Add Prefix to Each Line", cat: "textx", desc: "Add text to the start of every line.", tags: ["prefix", "lines"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "prefix", label: "Prefix", type: "text", value: "" }],
    run(v) { if (!v.text) return ""; const p = v.prefix || ""; return lines(v.text).map((l) => p + l).join("\n"); } },

  { id: "tx-suffix-lines", name: "Add Suffix to Each Line", cat: "textx", desc: "Add text to the end of every line.", tags: ["suffix", "lines"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "suffix", label: "Suffix", type: "text", value: "" }],
    run(v) { if (!v.text) return ""; const s = v.suffix || ""; return lines(v.text).map((l) => l + s).join("\n"); } },

  { id: "tx-wrap-columns", name: "Wrap Text to N Columns", cat: "textx", desc: "Hard-wrap text so no line exceeds N characters (word-aware).", tags: ["wrap", "columns", "format"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }, { k: "cols", label: "Columns", type: "range", min: 10, max: 200, step: 1, value: 80 }],
    run(v, H) { if (!v.text) return ""; const width = H.clampInt(v.cols, 1, 1000, 80); const out = []; for (const para of v.text.split(/\r?\n/)) { if (para === "") { out.push(""); continue; } let line = ""; for (const word of para.split(/\s+/)) { if (line === "") { line = word; } else if ((line + " " + word).length <= width) { line += " " + word; } else { out.push(line); line = word; } } out.push(line); } return out.join("\n"); } },

  { id: "tx-indent", name: "Indent by N Spaces", cat: "textx", desc: "Add N spaces (or tabs) of indentation to each line.", tags: ["indent", "format", "lines"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "n", label: "Amount", type: "range", min: 1, max: 16, step: 1, value: 2 }, { k: "tabs", label: "Use tabs", type: "checkbox", value: false }],
    run(v, H) { if (!v.text) return ""; const n = H.clampInt(v.n, 0, 100, 2); const pad = (v.tabs ? "\t" : " ").repeat(n); return lines(v.text).map((l) => (l === "" ? l : pad + l)).join("\n"); } },

  { id: "tx-dedent", name: "Dedent", cat: "textx", desc: "Remove the common leading whitespace from all lines.", tags: ["dedent", "format", "lines"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }],
    run(v) { if (!v.text) return ""; const arr = lines(v.text); let min = Infinity; for (const l of arr) { if (l.trim() === "") continue; const m = l.match(/^[ \t]*/)[0].length; if (m < min) min = m; } if (!isFinite(min) || min === 0) return v.text; return arr.map((l) => l.slice(min)).join("\n"); } },

  { id: "tx-remove-linebreaks", name: "Remove All Line Breaks", cat: "textx", desc: "Replace line breaks with a space (or nothing).", tags: ["clean", "linebreaks", "join"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "mode", label: "Replace with", type: "select", opts: [["space", "A space"], ["none", "Nothing"]], value: "space" }],
    run(v) { if (!v.text) return ""; return v.text.replace(/\r?\n/g, v.mode === "none" ? "" : " "); } },

  { id: "tx-join-lines", name: "Join Lines with Delimiter", cat: "textx", desc: "Join all lines using a chosen delimiter.", tags: ["join", "lines", "delimiter"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "delim", label: "Delimiter", type: "text", value: ", " }],
    run(v) { if (!v.text) return ""; const d = v.delim == null ? "" : v.delim; return lines(v.text).join(d); } },

  { id: "tx-split-lines", name: "Split into Lines by Delimiter", cat: "textx", desc: "Split text on a delimiter, one result per line.", tags: ["split", "lines", "delimiter"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }, { k: "delim", label: "Delimiter", type: "text", value: "," }, { k: "trim", label: "Trim parts", type: "checkbox", value: true }],
    run(v) { if (!v.text) return ""; const d = v.delim == null || v.delim === "" ? "," : v.delim; let parts = v.text.split(d); if (v.trim) parts = parts.map((p) => p.trim()); return parts.join("\n"); } },

  { id: "tx-find-replace-plain", name: "Find & Replace (Plain)", cat: "textx", desc: "Literal find-and-replace, optionally case-insensitive.", tags: ["replace", "find"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }, { k: "find", label: "Find", type: "text" }, { k: "repl", label: "Replace with", type: "text" }, { k: "ci", label: "Case-insensitive", type: "checkbox", value: false }],
    run(v) { if (!v.text) return ""; if (!v.find) return v.text; const flags = "g" + (v.ci ? "i" : ""); const re = new RegExp(escRe(v.find), flags); return v.text.replace(re, (v.repl == null ? "" : v.repl)); } },

  { id: "tx-find-replace-regex", name: "Find & Replace (Regex)", cat: "textx", desc: "Regex find-and-replace with custom flags; supports $1 groups.", tags: ["replace", "regex"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }, { k: "pattern", label: "Pattern", type: "text", placeholder: "\\d+" }, { k: "repl", label: "Replace with", type: "text" }, { k: "flags", label: "Flags", type: "text", value: "g" }],
    run(v) { if (!v.text) return ""; if (!v.pattern) return v.text; let re; try { re = new RegExp(v.pattern, v.flags || ""); } catch (e) { return { error: "Invalid regex: " + e.message }; } try { return v.text.replace(re, (v.repl == null ? "" : v.repl)); } catch (e) { return { error: e.message }; } } },

  { id: "tx-extract-emails", name: "Extract Email Addresses", cat: "textx", desc: "Pull all email addresses out of the text.", tags: ["extract", "email"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }, { k: "uniq", label: "Unique", type: "checkbox", value: true }],
    run(v) { if (!v.text) return ""; let m = v.text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || []; if (v.uniq) m = [...new Set(m)]; return m.join("\n"); } },

  { id: "tx-extract-urls", name: "Extract URLs", cat: "textx", desc: "Pull all http/https URLs out of the text.", tags: ["extract", "url", "links"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }, { k: "uniq", label: "Unique", type: "checkbox", value: true }],
    run(v) { if (!v.text) return ""; let m = v.text.match(/https?:\/\/[^\s<>"')\]]+/g) || []; if (v.uniq) m = [...new Set(m)]; return m.join("\n"); } },

  { id: "tx-extract-ipv4", name: "Extract IPv4 Addresses", cat: "textx", desc: "Pull all valid IPv4 addresses out of the text.", tags: ["extract", "ip", "ipv4"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }, { k: "uniq", label: "Unique", type: "checkbox", value: true }],
    run(v) { if (!v.text) return ""; const cand = v.text.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || []; let m = cand.filter((ip) => ip.split(".").every((o) => Number(o) <= 255 && (o === "0" || o[0] !== "0"))); if (v.uniq) m = [...new Set(m)]; return m.join("\n"); } },

  { id: "tx-extract-numbers", name: "Extract Numbers", cat: "textx", desc: "Pull all numbers (integers and decimals) out of the text.", tags: ["extract", "numbers"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }],
    run(v) { if (!v.text) return ""; return (v.text.match(/-?\d+(?:\.\d+)?/g) || []).join("\n"); } },

  { id: "tx-extract-tags", name: "Extract Hashtags & Mentions", cat: "textx", desc: "Pull #hashtags and/or @mentions out of the text.", tags: ["extract", "hashtag", "mention"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }, { k: "mode", label: "Extract", type: "select", opts: [["hash", "#hashtags"], ["at", "@mentions"], ["both", "Both"]], value: "both" }, { k: "uniq", label: "Unique", type: "checkbox", value: true }],
    run(v) { if (!v.text) return ""; let m = []; if (v.mode === "hash" || v.mode === "both") m = m.concat(v.text.match(/#[\w]+/g) || []); if (v.mode === "at" || v.mode === "both") m = m.concat(v.text.match(/@[\w]+/g) || []); if (v.uniq) m = [...new Set(m)]; return m.join("\n"); } },

  { id: "tx-remove-html", name: "Remove HTML Tags", cat: "textx", desc: "Strip HTML/XML tags, leaving the text content.", tags: ["html", "strip", "clean"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }],
    run(v) { if (!v.text) return ""; return v.text.replace(/<\/?[^>]+>/g, "").replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'"); } },

  { id: "tx-strip-accents", name: "Strip Accents / Diacritics", cat: "textx", desc: "Remove accent marks (café → cafe).", tags: ["accents", "diacritics", "normalize"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }],
    run(v) { return v.text ? stripAccents(v.text) : ""; } },

  { id: "tx-reverse-words", name: "Reverse Word Order", cat: "textx", desc: "Reverse the order of words in the text.", tags: ["reverse", "words"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }],
    run(v) { if (!v.text) return ""; return v.text.trim().split(/\s+/).reverse().join(" "); } },

  { id: "tx-count-substring", name: "Count Substring Occurrences", cat: "textx", desc: "Count how many times a substring appears.", tags: ["count", "substring", "find"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }, { k: "needle", label: "Substring", type: "text" }, { k: "ci", label: "Case-insensitive", type: "checkbox", value: false }, { k: "overlap", label: "Count overlaps", type: "checkbox", value: false }],
    run(v) { if (!v.text || !v.needle) return ""; const hay = v.ci ? v.text.toLowerCase() : v.text; const nd = v.ci ? v.needle.toLowerCase() : v.needle; let count = 0, i = 0; const step = v.overlap ? 1 : nd.length; while (true) { const idx = hay.indexOf(nd, i); if (idx === -1) break; count++; i = idx + step; } return String(count); } },

  { id: "tx-truncate", name: "Truncate with Ellipsis", cat: "textx", desc: "Cut text to N characters and append an ellipsis.", tags: ["truncate", "ellipsis", "shorten"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 4 }, { k: "n", label: "Max characters", type: "range", min: 1, max: 500, step: 1, value: 50 }, { k: "ell", label: "Ellipsis", type: "text", value: "..." }],
    run(v, H) { if (!v.text) return ""; const n = H.clampInt(v.n, 1, 100000, 50); const ell = v.ell == null ? "" : v.ell; const arr = Array.from(v.text); if (arr.length <= n) return v.text; return arr.slice(0, n).join("") + ell; } },

  { id: "tx-pad-center", name: "Pad / Center to Width", cat: "textx", desc: "Pad text left, right, or centered to a target width.", tags: ["pad", "center", "align"],
    inputs: [{ k: "text", label: "Text", type: "text" }, { k: "width", label: "Width", type: "range", min: 1, max: 120, step: 1, value: 20 }, { k: "align", label: "Align", type: "select", opts: [["center", "Center"], ["left", "Left"], ["right", "Right"]], value: "center" }, { k: "ch", label: "Fill char", type: "text", value: " " }],
    run(v, H) { const s = S(v.text); const w = H.clampInt(v.width, 0, 10000, 20); const fill = (v.ch && v.ch.length) ? v.ch[0] : " "; if (s.length >= w) return s; const total = w - s.length; if (v.align === "left") return s + fill.repeat(total); if (v.align === "right") return fill.repeat(total) + s; const left = Math.floor(total / 2); return fill.repeat(left) + s + fill.repeat(total - left); } },

  { id: "tx-repeat", name: "Repeat Text N Times", cat: "textx", desc: "Repeat the text a number of times, with an optional separator.", tags: ["repeat", "multiply"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 3 }, { k: "n", label: "Times", type: "range", min: 1, max: 1000, step: 1, value: 3 }, { k: "sep", label: "Separator", type: "select", opts: [["nl", "New line"], ["none", "None"], ["space", "Space"]], value: "nl" }],
    run(v, H) { if (!v.text) return ""; const n = H.clampInt(v.n, 1, 100000, 3); const sep = v.sep === "none" ? "" : v.sep === "space" ? " " : "\n"; return Array(n).fill(v.text).join(sep); } },

  { id: "tx-remove-punctuation", name: "Remove Punctuation", cat: "textx", desc: "Strip common punctuation characters.", tags: ["clean", "punctuation"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }],
    run(v) { if (!v.text) return ""; return v.text.replace(/[!-/:-@[-`{-~]/g, ""); } },

  { id: "tx-remove-non-ascii", name: "Remove Non-ASCII", cat: "textx", desc: "Delete characters outside the printable ASCII range.", tags: ["clean", "ascii", "non-ascii"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }],
    run(v) { if (!v.text) return ""; return v.text.replace(/[^\x00-\x7F]/g, ""); } },

  { id: "tx-remove-duplicate-words", name: "Remove Duplicate Words", cat: "textx", desc: "Remove repeated words, keeping the first occurrence.", tags: ["dedupe", "words", "unique"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }, { k: "ci", label: "Case-insensitive", type: "checkbox", value: true }],
    run(v) { if (!v.text) return ""; const seen = new Set(); const out = []; for (const w of v.text.split(/(\s+)/)) { if (/^\s+$/.test(w) || w === "") { out.push(w); continue; } const key = v.ci ? w.toLowerCase() : w; if (!seen.has(key)) { seen.add(key); out.push(w); } } return out.join("").replace(/\s+/g, " ").trim(); } },

  { id: "tx-whitespace-viz", name: "Whitespace Visualizer", cat: "textx", desc: "Reveal spaces (·), tabs (→) and line breaks (⏎).", tags: ["whitespace", "debug", "visualize"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "keepnl", label: "Keep real line breaks", type: "checkbox", value: true }],
    run(v) { if (!v.text) return ""; let out = v.text.replace(/ /g, "·").replace(/\t/g, "→   "); out = out.replace(/\r?\n/g, v.keepnl ? "⏎\n" : "⏎"); return out; } },

  { id: "tx-text-stats", name: "Text Statistics", cat: "textx", desc: "Characters, words, lines, sentences, paragraphs and reading time.", tags: ["stats", "count", "reading-time"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "wpm", label: "Words / minute", type: "range", min: 100, max: 500, step: 10, value: 200 }],
    run(v, H) { if (!v.text) return ""; const wpm = H.clampInt(v.wpm, 50, 1000, 200); const words = (v.text.match(/\S+/g) || []).length; const chars = Array.from(v.text).length; const charsNS = Array.from(v.text.replace(/\s/g, "")).length; const ln = lines(v.text).length; const sentences = (v.text.match(/[^.!?]+[.!?]+/g) || (v.text.trim() ? [v.text] : [])).length; const paras = v.text.split(/\n\s*\n+/).map((p) => p.trim()).filter(Boolean).length; const secs = Math.round((words / wpm) * 60); const mm = Math.floor(secs / 60), ss = secs % 60; return `Characters: ${chars}\nCharacters (no spaces): ${charsNS}\nWords: ${words}\nLines: ${ln}\nSentences: ${sentences}\nParagraphs: ${paras}\nReading time: ${mm}m ${ss}s @ ${wpm} wpm`; } },

  { id: "tx-rot-n", name: "ROT-N Cipher", cat: "textx", desc: "Rotate letters by N positions (ROT13 by default).", tags: ["rot13", "cipher", "caesar"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 6 }, { k: "n", label: "Shift", type: "range", min: 0, max: 25, step: 1, value: 13 }],
    run(v, H) { if (!v.text) return ""; const n = ((H.clampInt(v.n, 0, 25, 13) % 26) + 26) % 26; return v.text.replace(/[a-z]/g, (c) => String.fromCharCode(((c.charCodeAt(0) - 97 + n) % 26) + 97)).replace(/[A-Z]/g, (c) => String.fromCharCode(((c.charCodeAt(0) - 65 + n) % 26) + 65)); } },

  { id: "tx-ascii-banner", name: "ASCII Banner", cat: "textx", desc: "Render text as a big block-letter banner (A-Z, 0-9).", tags: ["ascii", "banner", "figlet"],
    inputs: [{ k: "text", label: "Text", type: "text", placeholder: "HELLO" }, { k: "block", label: "Block char", type: "text", value: "█" }, { k: "space", label: "Empty char", type: "text", value: " " }],
    run(v) { if (!v.text) return ""; const block = (v.block && v.block.length) ? v.block[0] : "█"; const empty = (v.space && v.space.length) ? v.space[0] : " "; const chars = v.text.toUpperCase().split("").filter((c) => BANNER_FONT[c] || c === " "); if (!chars.length) return { error: "No renderable characters (A-Z, 0-9, space)." }; const rows = ["", "", "", "", ""]; for (const c of chars) { const g = BANNER_FONT[c] || BANNER_FONT[" "]; for (let r = 0; r < 5; r++) rows[r] += g[r].replace(/#/g, block).replace(/ /g, empty) + empty; } return rows.join("\n"); } },

  { id: "tx-quote-lines", name: "Quote / Unquote Lines", cat: "textx", desc: "Wrap each line in quotes (with optional trailing comma) or remove them.", tags: ["quote", "lines", "list"],
    inputs: [{ k: "text", label: "Text", type: "textarea", rows: 8 }, { k: "mode", label: "Mode", type: "select", opts: [["quote", "Add quotes"], ["unquote", "Remove quotes"]], value: "quote" }, { k: "q", label: "Quote char", type: "select", opts: [["\"", "Double \""], ["'", "Single '"], ["`", "Backtick `"]], value: "\"" }, { k: "comma", label: "Trailing comma", type: "checkbox", value: false }],
    run(v) { if (!v.text) return ""; const q = v.q || "\""; const arr = lines(v.text); if (v.mode === "unquote") { return arr.map((l) => l.replace(/,\s*$/, "").trim().replace(/^(["'`])([\s\S]*)\1$/, "$2")).join("\n"); } return arr.map((l, i) => { const line = q + l.replace(new RegExp(escRe(q), "g"), "\\" + q) + q; return v.comma && i < arr.length - 1 ? line + "," : line; }).join("\n"); } },
];
