// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
// Plain-English help for the coding.js mini-tools. See help/README.md for the contract.
export const HELP = {
  "cd-json-format": {
    what: "Checks that text is valid JSON and either pretty-prints it with your indent, squeezes it onto one line, or just validates it and reports the top-level type.",
    when: "You have messy or minified JSON from a log or API and want it readable, compact, or confirmed valid.",
    example: { json: '{"b":[2,3],"a":1}', mode: "Pretty", indent: "2" },
  },
  "cd-jsonc-strip": {
    what: "Removes // and /* */ comments and trailing commas from JSON-with-comments (like VS Code settings or tsconfig) so you get strict JSON that standard parsers accept.",
    when: "You copied a config that has comments and a parser rejects it. Quotes inside strings are left alone.",
    example: { text: '{\n  // the port\n  "port": 8080,\n}', pretty: true },
  },
  "cd-json-to-yaml": {
    what: "Rewrites JSON as block-style YAML. Keys and text are quoted only when YAML needs it.",
    when: "You want to turn a JSON config or API body into the friendlier YAML form used by CI and Kubernetes files.",
    example: { json: '{"name":"api","ports":[80,443],"debug":true}' },
  },
  "cd-yaml-to-json": {
    what: "Parses common YAML (indented mappings and lists, scalars, # comments, simple [..] and {..} flow) and returns the same data as JSON.",
    when: "You have a YAML config and need it as JSON for a tool or code. Advanced YAML (anchors, multi-document, multi-line block scalars) is not supported.",
    example: { yaml: "name: api\ndebug: true\nports:\n  - 80\n  - 443", indent: "2" },
  },
  "cd-json-to-toml": {
    what: "Converts a JSON object into TOML, using [tables] for nested objects and [[arrays]] for arrays of objects.",
    when: "You want a Cargo/pyproject-style TOML config from JSON. JSON null becomes an empty string because TOML has no null.",
    example: { json: '{"title":"demo","server":{"host":"localhost","port":8080}}' },
  },
  "cd-toml-to-json": {
    what: "Parses common TOML (key = value, [tables], [[arrays of tables]], strings, numbers, booleans, single-line arrays and inline tables) into JSON.",
    when: "You have a TOML config and need it as JSON. Dates are kept as strings; multi-line values are not supported.",
    example: { toml: 'title = "demo"\n[server]\nhost = "localhost"\nport = 8080', indent: "2" },
  },
  "cd-json-to-xml": {
    what: "Builds a simple XML document from JSON: objects become nested elements, arrays repeat the element name, and primitives become element text.",
    when: "You need a quick XML representation of JSON data for a legacy system or template.",
    example: { json: '{"book":{"title":"X","tags":["a","b"]}}', root: "doc", decl: true },
  },
  "cd-json-to-csv": {
    what: "Flattens a JSON array of objects into CSV. The columns are the union of all keys; nested objects/arrays are written as JSON text in the cell.",
    when: "You have JSON records from an API and want them in a spreadsheet.",
    example: { json: '[{"id":1,"name":"Jane"},{"id":2,"name":"John"}]', header: true },
  },
  "cd-csv-to-json": {
    what: "Parses CSV (handling quoted fields, embedded commas and newlines) into JSON. With a header row you get an array of objects; without one, an array of cell arrays.",
    when: "You exported a spreadsheet as CSV and want structured JSON.",
    example: { csv: "id,name\n1,Jane\n2,John", header: true, numbers: true },
  },
  "cd-ndjson": {
    what: "Converts a JSON array to NDJSON (one compact JSON value per line) or parses NDJSON back into a JSON array.",
    when: "You work with log pipelines or streaming APIs that use newline-delimited JSON (JSON Lines).",
    example: { text: '[{"a":1},{"a":2}]', mode: "Array to NDJSON" },
  },
  "cd-json-to-ini": {
    what: "Writes an INI config from a JSON object: top-level values become global keys and nested objects become [sections].",
    when: "You need a quick INI file from structured JSON. Arrays and deeper nesting are written as JSON text.",
    example: { json: '{"debug":true,"db":{"host":"localhost","port":5432}}' },
  },
  "cd-properties-json": {
    what: "Converts a Java/Spring .properties file to JSON, or flat JSON back to .properties, handling comments, : or = separators and \\uXXXX escapes.",
    when: "You move settings between a Java app's .properties file and JSON tooling.",
    example: { text: "db.host=localhost\ndb.port=5432", mode: ".properties to JSON" },
  },
  "cd-json-pointer": {
    what: "Follows an RFC 6901 JSON Pointer (like /users/0/name) into a JSON document and returns the value found there.",
    when: "You need to pull one value out of JSON using the pointer syntax that JSON Schema and many APIs use. Use ~1 for a literal / and ~0 for a literal ~.",
    example: { json: '{"users":[{"name":"Jane"},{"name":"John"}]}', pointer: "/users/1/name" },
  },
  "cd-json-paths": {
    what: "Walks a JSON document and lists every location as an RFC 6901 pointer with the value type at that spot.",
    when: "You are exploring an unfamiliar API response and want to see all the paths and their types at a glance.",
    example: { json: '{"a":1,"b":{"c":[true,false]}}', leaves: false },
  },
  "cd-json-unflatten": {
    what: "Rebuilds nested JSON from a flat object whose keys are dot paths like user.name or tags.0. Numeric segments become array indexes.",
    when: "You have flattened key/value data (from a form, env or spreadsheet) and need the original nested structure back.",
    example: { json: '{"user.name":"Jane","tags.0":"a","tags.1":"b"}' },
  },
  "cd-json-merge": {
    what: "Deep-merges two JSON values. Objects combine key by key; for arrays and other values the second input wins.",
    when: "You apply an override config on top of a base config and want the combined result.",
    example: { base: '{"a":1,"b":{"x":1}}', over: '{"b":{"y":2},"c":3}' },
  },
  "cd-json-pick": {
    what: "Keeps only the named top-level keys (Pick) or removes them (Omit), for a JSON object or every object in a JSON array.",
    when: "You want to trim a response down to a few fields, or strip out sensitive keys before sharing.",
    example: { json: '{"id":1,"name":"Jane","secret":"x"}', keys: "id, name", mode: "Pick" },
  },
  "cd-json-stats": {
    what: "Reports structure metrics for JSON: counts of objects, arrays, strings, numbers, booleans and nulls, total keys, maximum nesting depth and minified size.",
    when: "You want a quick sense of how big and how deep a JSON payload is.",
    example: { json: '{"a":[1,2,{"b":true}],"c":null}' },
  },
  "cd-json-keyby": {
    what: "Turns a JSON array of objects into an object keyed by one field (last item wins), or groups items into arrays by that field.",
    when: "You have a list of records and want to look them up by id, or bucket them by category.",
    example: { json: '[{"id":1,"t":"a"},{"id":2,"t":"a"}]', field: "t", mode: "Group by (array)" },
  },
  "cd-json-to-ts": {
    what: "Generates TypeScript interfaces from a sample JSON value, naming nested objects and building unions for mixed arrays.",
    when: "You have an example API response and want starter TypeScript types. It is best-effort from one sample, so review the result.",
    example: { json: '{"id":1,"name":"a","tags":["x"]}', name: "User" },
  },
  "cd-json-to-go": {
    what: "Generates Go struct definitions with json tags from a sample JSON object. Whole numbers become int, decimals float64.",
    when: "You are writing a Go client and want starter structs for a JSON payload. Best-effort from one sample.",
    example: { json: '{"id":1,"name":"a","active":true}', name: "User" },
  },
  "cd-csv-clean": {
    what: "Tidies CSV by trimming every cell, dropping fully blank rows, and optionally collapsing inner whitespace and removing duplicate rows. Re-quotes fields as needed.",
    when: "You have CSV with stray spaces, empty lines or repeated rows and want it clean.",
    example: { csv: " id , name \n1, Jane \n\n1, Jane ", collapse: false, dedupe: true },
  },
  "cd-csv-to-md": {
    what: "Renders CSV as a GitHub-flavoured Markdown table, with optional column alignment.",
    when: "You want to paste tabular data into a README, issue or pull request as a Markdown table.",
    example: { csv: "name,score\nJane,42\nJohn,7", align: "Left" },
  },
  "cd-csv-transpose": {
    what: "Flips a CSV table so its rows become columns and its columns become rows.",
    when: "Your data is laid out the wrong way (fields across the top instead of down the side) and you want to pivot it.",
    example: { csv: "a,b,c\n1,2,3\n4,5,6" },
  },
  "cd-delim-convert": {
    what: "Re-delimits tabular text, for example CSV to tab-separated or pipe-separated, parsing the source quote-aware and re-quoting for the target.",
    when: "A tool wants TSV but you have CSV (or vice versa).",
    example: { text: "id,name\n1,Jane", from: ",", to: "\t" },
  },
  "cd-csv-stats": {
    what: "Summarises each CSV column: how many cells are filled, how many unique values, and for all-numeric columns the min, max, sum and mean.",
    when: "You want a quick profile of a CSV before importing or analysing it.",
    example: { csv: "name,score\nJane,42\nJohn,7\nAmy,50", header: true },
  },
  "cd-csv-filter": {
    what: "Keeps only CSV rows where a chosen column meets a condition (equals, contains, regex, numeric greater/less than), keeping the header.",
    when: "You want to pull just the matching rows out of a CSV, like a simple WHERE clause.",
    example: { csv: "name,score\nJane,42\nJohn,7\nAmy,50", col: "score", op: "> (number)", value: "40" },
  },
  "cd-column-extract": {
    what: "Pulls out and reorders chosen columns from delimited text by 1-based number, quote-aware, with a delimiter you pick for the output.",
    when: "You only need a couple of columns from a wide CSV, or you want them in a different order.",
    example: { text: "id,name,email\n1,Jane,jane@example.com", cols: "2,1" },
  },
  "cd-csv-to-sql": {
    what: "Generates INSERT statements from CSV, using the header as column names, quoting text with '' escaping, leaving numbers bare and turning empty cells into NULL.",
    when: "You want to load CSV data into a database by running generated INSERTs.",
    example: { csv: "id,name\n1,Jane\n2,John", table: "users", multi: false },
  },
  "cd-csv-create-table": {
    what: "Looks at the data in each CSV column and suggests a CREATE TABLE: all-integers become INTEGER, decimals REAL, true/false BOOLEAN, otherwise VARCHAR sized to the longest value.",
    when: "You are importing a CSV and want a starting table definition. Review the inferred types before using them.",
    example: { csv: "id,name,active\n1,Jane,true\n2,John,false", table: "users" },
  },
  "cd-sql-in-clause": {
    what: "Turns a list of values (lines, commas or spaces) into a SQL IN (...) clause, quoting text and leaving numbers bare in Auto mode.",
    when: "You have a list of ids or names and want to drop them into a SQL query safely.",
    example: { list: "alice\nbob\n42", col: "username", quote: "Auto" },
  },
  "cd-sql-minify": {
    what: "Removes -- and /* */ comments and collapses whitespace so a SQL statement fits on one line, keeping string literals intact.",
    when: "You want a compact one-line query for a log, a config value or an embedded string.",
    example: { sql: "SELECT id -- key\nFROM users\nWHERE active = 1;" },
  },
  "cd-sql-like-escape": {
    what: "Escapes the SQL LIKE wildcards % and _ in a literal search term and shows the full pattern with the matching ESCAPE clause.",
    when: "A user's search text contains % or _ and you need it treated literally in a LIKE query.",
    example: { text: "100%_off", pos: "Contains", esc: "\\" },
  },
  "cd-regex-explain": {
    what: "Describes a regular expression piece by piece in plain English: anchors, character classes, groups, quantifiers, look-arounds and flags.",
    when: "You are reading an unfamiliar regex and want to understand what it matches.",
    example: { pattern: "^\\d{3}-\\d{4}$", flags: "" },
  },
  "cd-glob-to-regex": {
    what: "Converts a shell or gitignore glob into an anchored regular expression, mapping * ? [abc] {a,b} and ** to their regex equivalents.",
    when: "You have a glob pattern and need an equivalent regex for a tool that only accepts regular expressions.",
    example: { glob: "src/**/*.{js,ts}" },
  },
  "cd-case-convert": {
    what: "Shows a word or identifier in many naming styles at once: camelCase, PascalCase, snake_case, SCREAMING_SNAKE, kebab-case, Title Case and more.",
    when: "You are renaming a variable, file or constant and want the right casing for the language or convention.",
    example: { text: "user profile ID" },
  },
  "cd-ws-normalize": {
    what: "Cleans up whitespace: trims each line, collapses runs of spaces/tabs, and can remove or squeeze blank lines.",
    when: "You pasted text or logs with irregular spacing and want it tidy.",
    example: { text: "  hello   world  \n\n\n  foo ", collapse: true, blanks: false, squeeze: true },
  },
  "cd-sort-lines": {
    what: "Sorts lines alphabetically, by number, by length, or naturally (file2 before file10), keeping duplicates. Supports reverse and case-insensitive order.",
    when: "You have a list and want it ordered without removing repeats.",
    example: { text: "file10\nfile2\nfile1", by: "Natural" },
  },
  "cd-reverse-lines": {
    what: "Reverses the order of the lines so the last line comes first (like the tac command).",
    when: "You want to flip a log or list top-to-bottom. This reverses line order, not the characters in a line.",
    example: { text: "first\nsecond\nthird" },
  },
  "cd-wrap-lines": {
    what: "Word-wraps text so no line is longer than the width you set, breaking on spaces. Blank lines separate paragraphs.",
    when: "You are writing a commit message or comment block that must stay within a column limit.",
    example: { text: "a fairly long sentence that should be wrapped to a fixed narrow width for a commit body", width: "40" },
  },
  "cd-join-split": {
    what: "Joins lines into one string with a separator (optionally wrapping each item in quotes), or splits a string on a separator into one item per line.",
    when: "You need to turn a column of values into a comma list, or break a delimited string back into lines.",
    example: { text: "a\nb\nc", mode: "Join lines", sep: ", ", wrap: "'" },
  },
  "cd-grep-lines": {
    what: "Keeps only the lines matching a regular expression, or drops them when you invert. Optional case-insensitive matching.",
    when: "You want to filter a log or list down to lines that match (or do not match) a pattern.",
    example: { text: "INFO ok\nERROR boom\nINFO done", pattern: "ERROR|WARN", invert: false, ci: false },
  },
  "cd-uniq-count": {
    what: "Counts how many times each distinct line appears and lists them by frequency, like sort | uniq -c.",
    when: "You want the most common entries in a log, such as top status codes or IPs.",
    example: { text: "200\n200\n404\n200\n500", order: "Most frequent first" },
  },
  "cd-prefix-suffix": {
    what: "Adds a prefix and/or suffix to every line, for example to quote and comma-join a list or comment out a block.",
    when: "You need to wrap each line of a list with the same text.",
    example: { text: "alice\nbob", prefix: "'", suffix: "',", skipEmpty: true },
  },
  "cd-text-stats": {
    what: "Counts characters (with and without whitespace), words, lines and UTF-8 bytes of your text.",
    when: "You need to size a payload, check a length limit, or count words quickly.",
    example: { text: "Hello world\nsecond line" },
  },
  "cd-regex-replace": {
    what: "Runs a regular-expression find-and-replace over text, supporting $1/$2 back-references, with global and case-insensitive options.",
    when: "You want a one-off sed-style transform, like reformatting dates or stripping a pattern.",
    example: { text: "2024-01-31", pattern: "(\\d{4})-(\\d{2})-(\\d{2})", replace: "$3/$2/$1", global: true, ci: false },
  },
  "cd-align-cols": {
    what: "Pads fields so columns line up neatly (like column -t), splitting on whitespace or a chosen delimiter.",
    when: "You want to tidy a table of values in a comment, README or terminal output.",
    example: { text: "name age city\nJane 30 Springfield\nJohn 7 Ogden", delim: "Whitespace", gap: "2" },
  },
  "cd-char-freq": {
    what: "Counts how often each character appears and sorts them with percentages, the first step in classic-cipher frequency analysis.",
    when: "You are analysing a substitution cipher or just want a character histogram. Not a decryption tool by itself.",
    example: { text: "the quick brown fox jumps over the lazy dog", ci: true, lettersOnly: true },
  },
  "cd-strip-ansi": {
    what: "Removes ANSI colour and cursor escape codes from captured terminal output, leaving clean plain text.",
    when: "You pasted coloured terminal output into a doc or log and want it without the escape gibberish.",
    example: { text: "\u001b[31mred\u001b[0m and \u001b[32mgreen\u001b[0m" },
  },
  "cd-envsubst": {
    what: "Expands ${VAR} and $VAR references in a template using KEY=value lines you provide, like the envsubst command.",
    when: "You want to fill placeholders in a config template with specific values.",
    example: { template: "server ${HOST}:${PORT}", vars: "HOST=example.com\nPORT=443", blank: false },
  },
  "cd-md-table-gen": {
    what: "Builds a Markdown table from rows of text, using the first row as the header and padding columns so the source lines up.",
    when: "You want a clean Markdown table from pipe-, tab- or comma-separated rows.",
    example: { text: "Name | Role\nJane | Admin\nJohn | User", sep: "Pipe", align: "Left" },
  },
  "cd-md-toc": {
    what: "Reads the headings in Markdown and builds a nested, linked table of contents with GitHub-style anchor slugs.",
    when: "You want a table of contents for a long README or doc. Code blocks are skipped.",
    example: { md: "# Title\n## Setup\n## Usage\n### Flags", minLevel: "1" },
  },
  "cd-md-to-text": {
    what: "Strips Markdown formatting down to plain text: removes heading marks, emphasis, list bullets and code fences, and keeps link text.",
    when: "You want the readable words out of a Markdown document without any of the markup.",
    example: { md: "# Title\n\nSome **bold** text and a [link](https://example.com)." },
  },
  "cd-html-to-text": {
    what: "Converts an HTML fragment to plain text: drops scripts and styles, turns block tags and <br> into line breaks, and decodes common entities.",
    when: "You have an HTML snippet or email body and want just the readable text.",
    example: { html: "<h1>Hi</h1><p>Some <b>bold</b> text &amp; more.</p>" },
  },
  "cd-css-minify": {
    what: "Shrinks CSS by removing comments and needless whitespace and the final semicolon in each rule.",
    when: "You want a smaller stylesheet for an inline style block or a quick size comparison.",
    example: { css: "body {\n  margin: 0; /* reset */\n  color: #fff;\n}" },
  },
  "cd-css-format": {
    what: "Pretty-prints minified CSS with one declaration per line and restored indentation.",
    when: "You have a one-line or minified stylesheet and want to read or edit it.",
    example: { css: "body{margin:0;color:#fff}a{color:red}", indent: "2" },
  },
  "cd-html-minify": {
    what: "Lightly minifies HTML by removing comments and collapsing whitespace between tags, while leaving pre, textarea, script and style content untouched.",
    when: "You want smaller HTML output without reformatting the content inside preformatted tags.",
    example: { html: "<ul>\n  <li> one </li>\n  <li> two </li>\n</ul>" },
  },
  "cd-xml-minify": {
    what: "Compacts XML by removing comments and whitespace between tags, preserving element text and CDATA sections.",
    when: "You want a one-line XML payload or a smaller document.",
    example: { xml: "<order>\n  <id>1</id>\n  <qty>3</qty>\n</order>" },
  },
  "cd-js-strip-comments": {
    what: "Removes // and /* */ comments from JavaScript-like source while keeping strings, template literals and regex literals intact.",
    when: "You want to clean comments out of a snippet. It is a lite cleanup, not a full minifier, so review the output.",
    example: { js: "const a = 1; // count\n/* block */ const b = '//not a comment';", blankLines: true },
  },
  "cd-int-bases": {
    what: "Shows one integer in decimal, hex, octal and binary at once, plus its two's-complement signed and unsigned values at 8, 16, 32 and 64 bits.",
    when: "You are reading a value in one base and want to see it in the others, or check how it looks as a signed byte or word. Accepts 0x, 0o, 0b and negatives.",
    example: { num: "0xFF", group: true },
  },
  "cd-bitwise-calc": {
    what: "Computes AND, OR, XOR, NOT, shifts and rotates on integers, masked to the width you pick, and shows the result in decimal, hex and binary.",
    when: "You are working with bit flags, masks or registers and want to check a bitwise operation.",
    example: { a: "0b1100", op: "XOR", b: "0b1010", width: "8" },
  },
  "cd-ieee754": {
    what: "Splits a floating-point number into its IEEE-754 sign, exponent and mantissa bits (32- or 64-bit) with the hex encoding, or decodes a hex pattern back to a value.",
    when: "You are debugging floating-point precision or a binary format and need the exact bit layout.",
    example: { value: "0.1", prec: "64-bit (double)" },
  },
  "cd-hexdump": {
    what: "Shows text as a hex dump: byte offset on the left, hex bytes in the middle, and a printable-ASCII gutter on the right.",
    when: "You want to inspect the exact bytes of a string, including whitespace and non-printable characters.",
    example: { text: "Hello, world!", width: "16" },
  },
  "cd-byte-array": {
    what: "Turns text or a hex string into a byte-array literal for C, Rust, Go, Java, Python, a JS Uint8Array, a 0x list or plain hex.",
    when: "You need to embed a sequence of bytes directly in source code.",
    example: { input: "ABC", from: "Text (UTF-8)", lang: "C" },
  },
  "cd-codepoint": {
    what: "Lists each character with its Unicode code point (U+XXXX), decimal value, UTF-8 bytes and UTF-16 code units.",
    when: "You suspect hidden, look-alike or multi-byte characters in a string and want to see exactly what is there.",
    example: { text: "Aé€" },
  },
  "cd-duration": {
    what: "Converts between a human duration like 1h30m and a total number of seconds or milliseconds, using w/d/h/m/s/ms units.",
    when: "You are reading or writing a timeout or interval and want it in the other form.",
    example: { input: "1h30m", mode: "Parse to seconds" },
  },
  "cd-exit-codes": {
    what: "A reference for shell exit status conventions (0, 1, 2, 126, 127, 128+N, 130, 255) and the usual Linux signal numbers, with a filter box.",
    when: "A command exited with a mystery code, or you need the number for a signal like SIGTERM.",
    example: { filter: "127" },
  },
  "cd-strftime-ref": {
    what: "A reference table of strftime date/time format codes (%Y, %m, %d, %H and so on) with their meaning. Type to filter.",
    when: "You are building a date format string in C, Python or shell date and need the right codes.",
    example: { filter: "year" },
  },
  "cd-printf-ref": {
    what: "A reference for C printf format specifiers: conversions, flags, width, precision and length modifiers. Type to filter.",
    when: "You are writing a printf/format string and need to recall a specifier or flag.",
    example: { filter: "hex" },
  },
  "cd-escape-ref": {
    what: "A reference for backslash escape sequences in C and JSON strings (\\n, \\t, \\xHH, \\uXXXX and more) with their meaning and where they are valid.",
    when: "You need to recall how to write a tab, newline or Unicode escape in a string literal.",
    example: { filter: "tab" },
  },
};
