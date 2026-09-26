// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Plain-English help for the dev.js mini-tools. See help/README.md for the contract.
export const HELP = {
  "d-diff": {
    what: "Compares two pieces of text line by line and shows the result: lines starting with - were removed, lines with + were added, and unchanged lines are indented.",
    when: "You have two versions of a file, email or config and want to see exactly which lines changed.",
    example: { a: "name: web\nport: 80\nmode: dev", b: "name: web\nport: 8080\nmode: dev\ndebug: true" },
  },
  "d-json-path": {
    what: "Pulls one value out of JSON (a common text format for structured data) using a path like user.orders[0].id.",
    when: "You have a big API response and only need one field from it, or want to test a path before using it in code.",
    example: { json: '{"user":{"name":"Jane Doe","orders":[{"id":101,"total":19.99},{"id":102,"total":5}]}}', path: "user.orders[1].id" },
  },
  "d-json-flatten": {
    what: "Turns nested JSON into one flat list of fields whose names show the full path, like user.name or tags[0].",
    when: "You need nested data as simple key/value pairs, for example for a spreadsheet, logs or search.",
    example: { json: '{"user":{"name":"Jane Doe","address":{"city":"Springfield"}},"tags":["admin","beta"]}' },
  },
  "d-json-sort-keys": {
    what: "Puts the field names of every object in your JSON, including nested ones, in A-Z or Z-A order, with the indentation you pick.",
    when: "You want two JSON files ordered the same way so differences are easy to spot.",
    example: { json: '{"zip":"12345","name":"Jane Doe","address":{"street":"1 Main St","city":"Springfield"}}', order: "A-Z", indent: "2" },
  },
  "d-xml-pretty": {
    what: "Takes XML (a tag-based data format) and lays it out one tag per line, indented to show the nesting.",
    when: "You have a squashed XML response or config that is hard to read.",
    example: { xml: '<order id="1001"><customer>Jane Doe</customer><items><item>Book</item><item>Pen</item></items></order>', indent: "2" },
  },
  "d-xml-validate": {
    what: "Checks that every XML tag is closed and that tags are nested in the right order. It reports the first mismatched or unclosed tag.",
    when: "An app rejects your XML and you want to find a missing or misplaced closing tag. It only checks tags, not a schema or attribute quoting.",
    example: { xml: "<order><customer>Jane Doe</customer><total>19.99</total></order>" },
  },
  "d-sql-format": {
    what: "Tidies up an SQL query (a database command) by writing keywords like SELECT and WHERE in capitals and putting each main clause on its own line.",
    when: "You have a long one-line query from a log or code and want to read it. It is a simple formatter, so check the result on complex queries.",
    example: { sql: "select id, name, email from users where active = 1 and city = 'Springfield' order by name" },
  },
  "d-env-to-json": {
    what: "Reads a .env settings file (KEY=value lines apps use for configuration) and returns it as a JSON object. Comments are skipped and surrounding quotes removed.",
    when: "You want to inspect or reuse an app's .env settings in a tool that expects JSON.",
    example: { env: "# app settings\nPORT=3000\nAPP_NAME=\"My App\"\nDB_HOST=db.example.com" },
  },
  "d-env-validate": {
    what: "Checks a .env settings file for keys that appear more than once and for keys with no value, and tells you the line numbers.",
    when: "Your app is picking up the wrong setting and you suspect a duplicated or empty entry in the .env file.",
    example: { env: "PORT=3000\nAPI_KEY=\nDB_HOST=db.example.com\nPORT=8080" },
  },
  "d-ini-to-json": {
    what: "Reads an INI config file ([section] headers with key=value lines) and returns it as JSON. All values stay as text.",
    when: "You have an .ini config and want to view it as JSON or use it in code.",
    example: { ini: "; main config\nname=demo\n\n[server]\nhost=example.com\nport=8080" },
  },
  "d-semver-compare": {
    what: "Compares two version numbers in semver format (major.minor.patch, like 1.2.3) and shows whether the first is lower, equal or higher.",
    when: "You need to know which of two software versions is newer, including pre-release tags like 2.0.0-beta.1.",
    example: { a: "1.10.0", b: "1.9.3" },
  },
  "d-semver-bump": {
    what: "Takes a version number like 1.2.3 and gives the next one after raising the patch, minor or major part (resetting the parts after it to 0).",
    when: "You are releasing a new version and want the correct next number. Pre-release tags are dropped.",
    example: { ver: "1.4.2", part: "minor" },
  },
  "d-regex-tester": {
    what: "Runs a regular expression (a search pattern for text) against your text and lists each match, where it starts and any captured parts.",
    when: "You are writing a pattern to find or extract things like emails or dates and want to check it works. Add the g flag to see all matches.",
    example: { pattern: "(\\w+)@([\\w.]+)", flags: "g", text: "Contact jane@example.com or john@example.org for help." },
  },
  "d-regex-cheatsheet": {
    what: "Shows a quick reference of common regular expression symbols (search pattern codes) and what each one means. Type a word to filter the list.",
    when: "You are writing a regex and cannot remember the symbol for a digit, word boundary or lookahead.",
    example: { q: "group" },
  },
  "d-contrast-checker": {
    what: "Takes a text colour and a background colour as hex codes (like #333333) and calculates how readable the text is, with pass or fail for the WCAG accessibility levels AA and AAA.",
    when: "You are choosing colours for a website or app and want to be sure text is easy to read for everyone, including people with low vision.",
    example: { fg: "#555555", bg: "#ffffff" },
  },
  "d-md-to-html": {
    what: "Converts basic Markdown (simple formatting like # headings, **bold**, *italic*, `code`, links and - lists) into HTML code.",
    when: "You wrote something in Markdown and need it as HTML for a web page or email. Tables, numbered lists and code blocks are not supported.",
    example: { md: "# Release notes\n\nThis update is **important**.\n\n- Faster *search*\n- New [docs](https://example.com/docs)" },
  },
  "d-multi-escape": {
    what: "Makes text safe to put inside a shell command, a JSON string, a regular expression or HTML, by adding the escape characters that place needs.",
    when: "You are pasting user text or a file name into code or a command and special characters like quotes, $ or < would break it.",
    example: { text: "It's \"50% off\" <today> & $5", target: "Shell" },
  },
  "d-uuid-v5": {
    what: "Makes a UUID (a standard 36-character unique ID) from a namespace ID and a name. The same inputs always give the same UUID.",
    when: "You need a stable ID for something like a domain or URL that comes out the same every time, instead of a random one.",
    example: { namespace: "6ba7b810-9dad-11d1-80b4-00c04fd430c8", name: "example.com" },
  },
  "d-uuid-namespaces": {
    what: "Shows the four standard namespace UUIDs (for DNS names, URLs, OIDs and X.500 names) that are used as the starting point for name-based UUIDs.",
    when: "You are making a version 3 or version 5 UUID and need the official namespace ID to use.",
    example: {},
  },
  "d-cron-next": {
    what: "Takes a cron expression (a five-part schedule code used by servers, like */15 9-17 * * 1-5) and lists the next run times starting from now, shown in UTC.",
    when: "You are setting up a scheduled job and want to confirm when it will run. Only numbers are supported, not names like MON.",
    example: { expr: "*/15 9-17 * * 1-5", count: "5" },
  },
  "d-timestamp-diff": {
    what: "Works out how much time lies between two dates and times, shown as days, hours, minutes and seconds, plus totals in seconds and milliseconds.",
    when: "You want the exact gap between two log timestamps or events.",
    example: { a: "2026-01-01T00:00:00Z", b: "2026-03-15T12:30:00Z" },
  },
  "d-htaccess-redirect": {
    what: "Writes one line of Apache web server config that sends visitors from an old path to a new URL. 301 means moved for good, 302 means temporary.",
    when: "You moved a page on a site hosted with Apache and want old links to keep working.",
    example: { from: "/old-page", to: "https://example.com/new-page", code: "301" },
  },
  "d-json-to-env": {
    what: "Turns a flat JSON object into .env lines (KEY=value, the format apps use for settings). Values containing spaces are wrapped in quotes.",
    when: "You have settings in JSON and need a .env file for an app or deployment.",
    example: { json: '{"PORT":3000,"APP_NAME":"My App","DEBUG":false}' },
  },
  "d-percentage-calc": {
    what: "Takes two numbers X and Y and answers two questions: what percent X is of Y, and what X percent of Y is.",
    when: "You want quick percentage answers, like \"25 is what percent of 80\" or \"what is 15% of 240\".",
    example: { x: "25", y: "80" },
  },
  "d-aspect-ratio": {
    what: "Reduces a width and height to its simplest ratio, like 1920x1080 to 16:9, and can work out the matching height for a new width.",
    when: "You are resizing an image or video and want to keep its shape without stretching it.",
    example: { w: "1920", h: "1080", targetW: "800" },
  },
  "d-text-templater": {
    what: "Fills placeholders written like {{name}} in your text with values from JSON, including nested values like {{user.city}}.",
    when: "You want to fill in a message or snippet template with real values. Placeholders with no matching value are left as they are.",
    example: { template: "Hello {{name}}, your order {{order.id}} ships to {{order.city}}.", data: '{"name":"Jane Doe","order":{"id":1042,"city":"Springfield"}}' },
  },
  "d-json-diff": {
    what: "Compares two JSON documents and lists fields that were added (+), removed (-) or changed (~), with old and new values.",
    when: "You want to see exactly what changed between two versions of a config file or API response.",
    example: { a: '{"name":"Jane Doe","plan":"free","tags":["beta"]}', b: '{"name":"Jane Doe","plan":"pro","tags":["beta"],"trial":false}' },
  },
  "d-dup-lines": {
    what: "Finds lines that appear more than once in your text and shows how many times each one appears.",
    when: "You have a list of emails, IDs or URLs and want to find the repeated entries. Blank lines are ignored.",
    example: { text: "jane@example.com\njohn@example.com\njane@example.com\nalex@example.com\njohn@example.com\njane@example.com", trim: true },
  },
  "d-list-set-ops": {
    what: "Compares two lists (one item per line) and shows which items are in both, only in the first, only in the second, and all items combined without repeats.",
    when: "You want to compare two lists, such as last month's and this month's subscribers, to see who joined or left.",
    example: { a: "jane@example.com\njohn@example.com\nalex@example.com", b: "john@example.com\nalex@example.com\nsam@example.com" },
  },
  "d-csv-inspect": {
    what: "Looks at CSV text (spreadsheet-style data) and tells you which separator it uses (comma, semicolon, tab or pipe), how many rows and columns it has, the header, and whether every row has the same number of columns.",
    when: "You received a data file and want a quick check of its layout before importing it.",
    example: { csv: "id;name;city\n1;Jane Doe;Springfield\n2;John Smith;Shelbyville" },
  },
  "d-http-header-explain": {
    what: "Takes raw HTTP headers (the \"Name: value\" lines sent with web requests and responses) and explains in plain words what each one is for.",
    when: "You are looking at a request or response in your browser's developer tools and want to know what the headers mean. Only common headers are known.",
    example: { headers: "Content-Type: application/json\nCache-Control: no-cache\nStrict-Transport-Security: max-age=31536000\nX-Frame-Options: DENY" },
  },
  "d-query-builder": {
    what: "Turns key=value lines into a URL query string (the part after ? in a web address), encoding spaces and special characters correctly.",
    when: "You are building a link or API call with several parameters and want them encoded correctly.",
    example: { pairs: "q=running shoes\npage=2\nsort=price & rating" },
  },
  "d-json-to-table": {
    what: "Turns a JSON list of objects into a plain-text table with lined-up columns, one row per object.",
    when: "You want to read JSON records at a glance in a terminal, a ticket or a chat message.",
    example: { json: '[{"id":1,"name":"Jane Doe","role":"Admin"},{"id":2,"name":"John Smith","role":"Editor"}]' },
  },
  "d-epoch-now": {
    what: "Shows the current time as a Unix timestamp (seconds and milliseconds since 1 January 1970), in ISO 8601 standard format, and in your local time.",
    when: "You need the current timestamp to paste into code, a log search or an API request.",
    example: {},
  },
  "d-backslash-join": {
    what: "Joins several lines into one shell command by adding a backslash at the end of each line, or splits such a command back into separate lines.",
    when: "You want to write a long terminal command across several readable lines, or undo that. Empty lines are dropped when joining.",
    example: { text: "docker run\n-p 8080:80\n-e MODE=production\nexample/web", mode: "Join with \\" },
  },
  "d-indent-dedent": {
    what: "Adds a chosen number of spaces to the start of every line, or removes the leading spaces that all lines share.",
    when: "You are pasting code or text into a place that needs different indentation, like a YAML file or a Markdown code block.",
    example: { text: "    def hello():\n        print(\"hi\")", mode: "Dedent (strip common leading whitespace)", size: "2" },
  },
  "d-diff-stats": {
    what: "Compares two pieces of text line by line and gives just the counts of added, removed and unchanged lines, without showing the full diff.",
    when: "You want a quick measure of how much a document or file changed between two versions.",
    example: { a: "name: web\nport: 80\nmode: dev", b: "name: web\nport: 8080\nmode: dev\ndebug: true" },
  },
  "d-json-schema-infer": {
    what: "Looks at a sample of JSON and writes a basic JSON Schema for it, a description listing each field, its type and which fields are required.",
    when: "You need a starting schema to validate or document data. It guesses from one sample and marks every field as required, so review it.",
    example: { json: '{"id":7,"name":"Jane Doe","score":9.5,"tags":["admin"],"active":true}' },
  },
};
