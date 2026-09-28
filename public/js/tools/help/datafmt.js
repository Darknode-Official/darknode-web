// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Plain-English help for the datafmt.js mini-tools. See help/README.md for the contract.
export const HELP = {
  "df-json-pretty": {
    what: "Takes JSON (a common text format for structured data, like {\"name\":\"Ada\"}) and lays it out neatly, one item per line with indentation you choose.",
    when: "You copied a squashed, hard-to-read API response and want to actually read it.",
    example: { json: '{"user":{"id":7,"name":"Jane Doe","tags":["admin","beta"]},"active":true}', indent: "2 spaces" },
  },
  "df-json-minify": {
    what: "Takes JSON and removes all the spaces and line breaks that are only there for looks, giving back the same data on one compact line.",
    when: "You want to paste JSON into a config field, URL or message where size or a single line matters.",
    example: { json: '{\n  "id": 7,\n  "name": "Jane Doe",\n  "roles": ["admin", "editor"]\n}' },
  },
  "df-json-validate": {
    what: "Checks whether your text is valid JSON. It tells you if it is valid and what it contains, or shows the error and roughly where it happened.",
    when: "An app rejects your JSON file or request and you want to find out if the JSON itself is broken, for example a missing comma or quote.",
    example: { json: '{"id": 7, "name": "Jane Doe", "roles": ["admin", "editor"]}' },
  },
  "df-json-sort-keys": {
    what: "Takes JSON and puts the field names of every object, including nested ones, in alphabetical order. The values stay the same.",
    when: "You want two JSON files to line up so they are easier to compare by eye or in a diff tool.",
    example: { json: '{"zip":"12345","name":"Jane Doe","address":{"street":"1 Main St","city":"Springfield"}}', indent: "2 spaces" },
  },
  "df-json-flatten": {
    what: "Turns nested JSON into a single flat list of fields whose names show the full path, like \"user.name\" or \"tags.0\".",
    when: "You need nested data as simple key/value pairs, for example to load it into a spreadsheet or a system that does not support nesting.",
    example: { json: '{"user":{"name":"Jane Doe","address":{"city":"Springfield"}},"tags":["admin","beta"]}' },
  },
  "df-json-unflatten": {
    what: "The reverse of flattening: takes a flat JSON object with dotted names like \"user.name\" and rebuilds the nested structure. Number parts like \"tags.0\" become list positions.",
    when: "You have flat key/value data (from a spreadsheet or env-style config) and need it back as normal nested JSON.",
    example: { json: '{"user.name":"Jane Doe","user.address.city":"Springfield","tags.0":"admin","tags.1":"beta"}' },
  },
  "df-json-escape": {
    what: "Wraps any text, including JSON, in quotes and escapes quotes, backslashes and line breaks so it can sit safely inside another JSON string.",
    when: "You need to put a piece of JSON or multi-line text as a string value inside another JSON document or code.",
    example: { text: '{"note": "She said \\"hi\\""}\nsecond line' },
  },
  "df-json-oneline": {
    what: "Takes JSON and rewrites it as one single line with no extra spaces.",
    when: "You need JSON on one line, for example for a log entry, a shell command or a newline-separated file.",
    example: { json: '{\n  "event": "signup",\n  "user": "jane@example.com"\n}' },
  },
  "df-json-to-qs": {
    what: "Turns a simple JSON object into a URL query string (the part after ? in a web address), like q=shoes&page=2. Lists repeat the key; nested objects are stored as JSON text.",
    when: "You have parameters as JSON and need to build a link or test an API call in the browser.",
    example: { json: '{"q":"running shoes","page":2,"size":["M","L"]}' },
  },
  "df-qs-to-json": {
    what: "Reads a URL query string (the part after ? in a web address) and shows it as JSON. You can paste the whole URL; keys that appear more than once become a list.",
    when: "You are looking at a long link full of parameters and want to see clearly what each one is set to.",
    example: { qs: "https://example.com/search?q=running+shoes&page=2&size=M&size=L" },
  },
  "df-json-merge": {
    what: "Combines two JSON objects into one. Nested objects are merged field by field, and when both have the same field the second one wins.",
    when: "You have default settings and a smaller set of overrides and want to see the final combined result. Lists are replaced, not joined.",
    example: { a: '{"theme":"light","db":{"host":"localhost","port":5432}}', b: '{"theme":"dark","db":{"port":6543}}' },
  },
  "df-json-remove-empty": {
    what: "Removes every null value, empty text, empty object and empty list from JSON, at every level, and returns the cleaned JSON.",
    when: "You want to tidy up API output or a config before saving it, so blank fields do not clutter it.",
    example: { json: '{"name":"Jane Doe","nickname":"","phone":null,"tags":[],"address":{"city":"Springfield","zip":""}}' },
  },
  "df-json-keys": {
    what: "Lists the full path of every final value in the JSON, one per line, like user.name or tags.0.",
    when: "You are exploring an unfamiliar JSON response and want a quick list of every field it contains.",
    example: { json: '{"user":{"id":7,"name":"Jane Doe"},"tags":["admin","beta"]}' },
  },
  "df-json-values": {
    what: "Lists every final value in the JSON (the text, numbers and true/false at the ends of the structure), one per line, without the field names.",
    when: "You want just the data out of a JSON document, for example to scan or copy all the values quickly.",
    example: { json: '{"user":{"id":7,"name":"Jane Doe"},"tags":["admin","beta"]}' },
  },
  "df-json-depth": {
    what: "Tells you how deeply nested the JSON is, meaning how many levels of objects and lists sit inside each other at the deepest point.",
    when: "You need to check that data is not nested too deeply for a system with a nesting limit, or just want to gauge its complexity.",
    example: { json: '{"a":{"b":{"c":[1,2,3]}}}' },
  },
  "df-json-type-summary": {
    what: "Replaces every value in the JSON with its type (string, number, boolean, null, object, array) so you can see the overall shape. For lists it shows only the first item's shape.",
    when: "You want to describe or document what a JSON response looks like without the actual data in it.",
    example: { json: '{"id":7,"name":"Jane Doe","active":true,"score":null,"tags":["admin"]}' },
  },
  "df-json-to-csv": {
    what: "Turns a JSON list of objects into CSV (spreadsheet-style text with one row per line and commas between columns). All field names become the header row.",
    when: "You have JSON records and want to open them in Excel or Google Sheets. Nested values are written as JSON text, not split into columns.",
    example: { json: '[{"id":1,"name":"Jane Doe","city":"Springfield"},{"id":2,"name":"John Smith","city":"Shelbyville"}]', delim: "," },
  },
  "df-csv-to-json": {
    what: "Reads CSV (spreadsheet-style text) and turns each row into a JSON object, using the first row as the field names. All values stay as text.",
    when: "You exported a spreadsheet as CSV and need the data as JSON for code or an API.",
    example: { csv: "id,name,city\n1,Jane Doe,Springfield\n2,John Smith,Shelbyville", delim: "," },
  },
  "df-json-path": {
    what: "Pulls out one value from JSON using a path like user.address.city or items[0].name.",
    when: "You have a large JSON response and only need one specific field from it.",
    example: { json: '{"user":{"name":"Jane Doe","orders":[{"id":101,"total":19.99},{"id":102,"total":5}]}}', path: "user.orders[0].total" },
  },
  "df-json-diff": {
    what: "Compares two JSON documents and lists which values were added, removed or changed, each with its full path.",
    when: "You want to see exactly what changed between two versions of a config file or API response.",
    example: { a: '{"name":"Jane Doe","plan":"free","tags":["beta"]}', b: '{"name":"Jane Doe","plan":"pro","tags":["beta"],"trial":false}' },
  },
  "df-json-to-yaml": {
    what: "Converts JSON into YAML, a config format that uses indentation instead of braces and quotes.",
    when: "You have settings in JSON but the tool you use (for example Docker Compose or Kubernetes) expects YAML.",
    example: { json: '{"name":"web","ports":[80,443],"env":{"MODE":"production"}}' },
  },
  "df-yaml-to-json": {
    what: "Converts YAML (an indentation-based config format) into JSON. It handles common YAML: key/value pairs, lists and nesting.",
    when: "You need a YAML config as JSON for code or an API. Advanced YAML features like anchors and multi-line blocks are not supported.",
    example: { yaml: "name: web\nports:\n  - 80\n  - 443\nenv:\n  MODE: production", indent: "2 spaces" },
  },
  "df-json-to-xml": {
    what: "Converts JSON into XML, a tag-based format like <name>Jane</name>. Each field becomes a tag inside a root tag you name.",
    when: "An older system or API only accepts XML and your data is in JSON.",
    example: { json: '{"user":{"id":7,"name":"Jane Doe"}}', root: "root" },
  },
  "df-xml-to-json": {
    what: "Converts simple XML (tags with text inside) into JSON. Tags that repeat become a list.",
    when: "You received XML from an older API and want it as JSON. Attributes inside tags (like id=\"1\") are ignored.",
    example: { xml: "<users><user><id>1</id><name>Jane Doe</name></user><user><id>2</id><name>John Smith</name></user></users>" },
  },
  "df-json-to-toml": {
    what: "Converts a JSON object into TOML, a simple config format with key = value lines and [section] headers.",
    when: "You are writing a config for a tool that uses TOML (such as Rust's Cargo or Python's pyproject) and your data is in JSON.",
    example: { json: '{"title":"My App","database":{"host":"localhost","port":5432},"servers":[{"name":"alpha"},{"name":"beta"}]}' },
  },
  "df-json-to-go": {
    what: "Reads a sample of JSON and writes matching Go code (struct type definitions) so a Go program can load that JSON.",
    when: "You are writing a Go program that reads an API response and do not want to type the structs by hand. Types are guessed from the one sample you give.",
    example: { json: '{"id":7,"name":"Jane Doe","score":9.5,"tags":["admin"],"address":{"city":"Springfield"}}', name: "User" },
  },
  "df-json-to-ts": {
    what: "Reads a sample of JSON and writes matching TypeScript interfaces (type descriptions) for it.",
    when: "You are writing TypeScript code that uses an API response and want types for it quickly. Types are guessed from the one sample you give.",
    example: { json: '{"id":7,"name":"Jane Doe","active":true,"tags":["admin"],"address":{"city":"Springfield"}}', name: "User" },
  },
  "df-json-to-env": {
    what: "Turns a flat JSON object into .env lines (KEY=VALUE, the format apps use for settings and secrets). Values with spaces are put in quotes.",
    when: "You have settings in JSON and need a .env file for an app or a deployment.",
    example: { json: '{"PORT":3000,"APP_NAME":"My App","DEBUG":false}' },
  },
  "df-env-to-json": {
    what: "Reads a .env settings file (KEY=VALUE lines) and returns it as a JSON object. It skips comments, understands \"export\" and removes surrounding quotes.",
    when: "You want to inspect or reuse an app's .env settings in a tool or script that expects JSON. All values stay as text.",
    example: { env: "# app settings\nPORT=3000\nexport APP_NAME=\"My App\"\nDB_HOST=db.example.com" },
  },
  "df-ini-to-json": {
    what: "Reads an INI config file ([section] headers with key=value lines) and returns it as nested JSON. Numbers and true/false are turned into real values.",
    when: "You have an old-style .ini config and want to use it in code or compare it as JSON.",
    example: { ini: "; main config\nname=demo\n\n[server]\nhost=example.com\nport=8080\n\n[debug]\nenabled=true" },
  },
  "df-json-to-ini": {
    what: "Turns a JSON object into an INI config file. Simple fields go at the top and each nested object becomes a [section].",
    when: "An app wants an .ini config file and you have the settings as JSON. Only one level of sections is created.",
    example: { json: '{"name":"demo","server":{"host":"example.com","port":8080},"debug":{"enabled":true}}' },
  },
  "df-props-to-json": {
    what: "Reads a Java .properties file (lines like key=value or key: value) and returns it as a flat JSON object. Comment lines are skipped.",
    when: "You are working with a Java or Spring config and want to view or reuse its settings as JSON. Lines continued with a backslash are not joined.",
    example: { props: "# app config\napp.name=demo\napp.port: 8080\ndb.url=jdbc:postgresql://db.example.com/app" },
  },
  "df-csv-align": {
    what: "Pads each CSV column with spaces so all columns line up, making the data easy to read as plain text.",
    when: "You want to read a CSV file in a terminal or paste it into a message where people will view it as text.",
    example: { csv: "id,name,city\n1,Jane Doe,Springfield\n22,Al,Shelbyville", delim: "," },
  },
  "df-csv-to-md": {
    what: "Turns CSV (spreadsheet-style text) into a Markdown table, the pipe-and-dash table format used on GitHub and many docs sites.",
    when: "You want to put spreadsheet data into a README, wiki page or chat that renders Markdown.",
    example: { csv: "name,role\nJane Doe,Admin\nJohn Smith,Editor", delim: "," },
  },
  "df-csv-to-html": {
    what: "Turns CSV (spreadsheet-style text) into HTML table code, using the first row as the header.",
    when: "You want to show spreadsheet data on a web page or in an HTML email.",
    example: { csv: "name,role\nJane Doe,Admin\nJohn Smith,Editor", delim: "," },
  },
  "df-md-to-csv": {
    what: "Reads a Markdown table (the pipe-and-dash format) and turns its cells into CSV you can open in a spreadsheet.",
    when: "You found a table in a README or wiki and want to work with it in Excel or Google Sheets.",
    example: { md: "| name | role |\n| --- | --- |\n| Jane Doe | Admin |\n| John Smith | Editor |", delim: "," },
  },
  "df-csv-transpose": {
    what: "Flips a CSV so rows become columns and columns become rows.",
    when: "Your data is laid out sideways (for example months across the top) and you need it the other way around.",
    example: { csv: "metric,Jan,Feb,Mar\nvisits,120,150,170\nsignups,8,11,9", delim: "," },
  },
  "df-csv-dedupe": {
    what: "Removes rows that are exact duplicates of an earlier row, keeping the first one. The header row can be kept untouched.",
    when: "You merged lists or exported data twice and now have repeated rows to clean out. Rows must match exactly, including spaces.",
    example: { csv: "email,name\njane@example.com,Jane Doe\njohn@example.com,John Smith\njane@example.com,Jane Doe", delim: ",", header: true },
  },
  "df-csv-sort": {
    what: "Sorts the rows of a CSV by one column, chosen by header name or column number (starting at 0). The header row stays on top.",
    when: "You want a CSV ordered by price, date or name without opening a spreadsheet. Tick Numeric for numbers, otherwise 10 sorts before 9.",
    example: { csv: "name,age\nJane Doe,34\nJohn Smith,9\nAlex Roe,27", col: "age", delim: ",", numeric: true, desc: false },
  },
  "df-csv-select": {
    what: "Keeps only the columns you list (by header name or column number starting at 0) and drops the rest.",
    when: "You have a wide export and only need a few columns, for example name and email.",
    example: { csv: "id,name,email,phone\n1,Jane Doe,jane@example.com,555-0100\n2,John Smith,john@example.com,555-0101", cols: "name,email", delim: "," },
  },
  "df-csv-filter": {
    what: "Keeps only the rows where a chosen column contains some text, plus the header row.",
    when: "You want just the matching rows from a CSV, for example all orders with status \"shipped\". It matches text anywhere in the cell, not exact values.",
    example: { csv: "order,status\n1001,shipped\n1002,pending\n1003,Shipped", col: "status", val: "shipped", delim: ",", ci: true },
  },
  "df-csv-count": {
    what: "Counts the lines, data rows and columns in a CSV.",
    when: "You want to quickly check how many records a CSV export has before importing it.",
    example: { csv: "id,name\n1,Jane Doe\n2,John Smith\n3,Alex Roe", delim: ",", header: true },
  },
  "df-csv-add-header": {
    what: "Adds a header row to the top of a CSV. You can type the column names, or leave it blank to get col1, col2 and so on.",
    when: "You have raw CSV data with no column names and a tool that needs a header row.",
    example: { csv: "1,Jane Doe,34\n2,John Smith,29", header: "id,name,age", delim: "," },
  },
  "df-tsv-to-csv": {
    what: "Converts TSV (columns separated by tabs, which is what you get when you copy cells from a spreadsheet) into CSV (columns separated by commas).",
    when: "You copied a block of cells from Excel or Google Sheets and need it as a proper CSV.",
    example: { tsv: "name\trole\nJane Doe\tAdmin\nJohn Smith\tEditor" },
  },
  "df-csv-to-tsv": {
    what: "Converts CSV (columns separated by commas) into TSV (columns separated by tabs).",
    when: "You want to paste CSV data into a spreadsheet so each value lands in its own cell.",
    example: { csv: "name,role\nJane Doe,Admin\n\"Smith, John\",Editor" },
  },
  "df-ndjson-to-json": {
    what: "Takes NDJSON (one JSON object per line, common in logs and data exports) and combines all lines into a single JSON list.",
    when: "You have a log or export file with one JSON record per line and need it as one normal JSON array. A bad line is reported by number.",
    example: { nd: '{"id":1,"event":"login"}\n{"id":2,"event":"logout"}' },
  },
  "df-json-to-ndjson": {
    what: "Takes a JSON list and writes each item on its own line (NDJSON, one JSON value per line).",
    when: "You need to feed records to a tool that reads one JSON object per line, such as a log pipeline or bulk import.",
    example: { json: '[{"id":1,"event":"login"},{"id":2,"event":"logout"}]' },
  },
  "df-json-to-base64": {
    what: "Compacts your JSON and encodes it as Base64 (a way of writing any data using only letters, digits, + and /).",
    when: "You need to pass JSON through a place that only accepts plain safe text, like a URL parameter or a header. Base64 is not encryption.",
    example: { json: '{"user":"jane@example.com","role":"admin"}' },
  },
  "df-base64-to-json": {
    what: "Decodes Base64 text and, if what is inside is JSON, shows it nicely formatted.",
    when: "You found a Base64 blob in a URL, cookie or header and suspect it contains JSON you want to read.",
    example: { b64: "eyJ1c2VyIjoiamFuZUBleGFtcGxlLmNvbSIsInJvbGUiOiJhZG1pbiJ9", indent: "2 spaces" },
  },
  "df-json-count-keys": {
    what: "Counts how many field names the JSON has at the top level and how many it has in total, including all nested objects.",
    when: "You want a quick sense of how big or complex a JSON document is.",
    example: { json: '{"id":7,"user":{"name":"Jane Doe","email":"jane@example.com"},"tags":["a","b"]}' },
  },
  "df-json-pick": {
    what: "Keeps only the top-level fields you list from a JSON object and drops everything else.",
    when: "You want to share or save only a few fields from a larger record. Only top-level fields can be picked.",
    example: { json: '{"id":7,"name":"Jane Doe","email":"jane@example.com","password":"hunter2"}', keys: "id,name" },
  },
  "df-json-omit": {
    what: "Removes the top-level fields you list from a JSON object and keeps the rest.",
    when: "You want to strip sensitive fields such as password or token before sharing JSON. Nested fields are not removed.",
    example: { json: '{"id":7,"name":"Jane Doe","password":"hunter2","token":"abc123"}', keys: "password,token" },
  },
  "df-json-rename-key": {
    what: "Renames one top-level field in a JSON object, keeping its value and its position.",
    when: "Two systems use different names for the same field (for example user_name vs username) and you need to match one of them.",
    example: { json: '{"id":7,"user_name":"Jane Doe","email":"jane@example.com"}', from: "user_name", to: "username" },
  },
  "df-commalist-to-json": {
    what: "Splits a comma-separated list into a JSON list. With auto-type on, numbers, true/false and null become real values instead of text.",
    when: "You have a list like \"red, green, blue\" and need it as a JSON array for code or a config.",
    example: { list: "apple, banana, 3, true, 4.5", typed: true, trim: true },
  },
  "df-json-flatten-array": {
    what: "Takes a list that contains other lists inside it and pulls every item out into one single flat list.",
    when: "You have nested lists like [1,[2,[3]]] and just want all the items in one level.",
    example: { json: '[1,[2,[3,4]],[5],"six"]' },
  },
  "df-json-group-by": {
    what: "Takes a JSON list of objects and groups them into buckets by the value of one field.",
    when: "You want to see all records sorted into groups, for example orders grouped by status or users by country.",
    example: { json: '[{"name":"Jane Doe","team":"red"},{"name":"John Smith","team":"blue"},{"name":"Alex Roe","team":"red"}]', key: "team" },
  },
  "df-json-unique-by": {
    what: "Removes objects from a JSON list when their value for a chosen field has already appeared, keeping the first one.",
    when: "Your list has repeated records with the same id or email and you want only one of each.",
    example: { json: '[{"id":1,"name":"Jane Doe"},{"id":2,"name":"John Smith"},{"id":1,"name":"Jane D."}]', key: "id" },
  },
  "df-csv-to-json-typed": {
    what: "Reads CSV and turns each row into a JSON object like the plain CSV to JSON tool, but also converts numbers, true/false and null into real values instead of text.",
    when: "You need CSV data as JSON and want numbers to stay numbers, for example for charts or calculations.",
    example: { csv: "id,name,active,score\n1,Jane Doe,true,9.5\n2,John Smith,false,null", delim: "," },
  },
  "df-xml-pretty": {
    what: "Takes XML (a tag-based data format) and lays it out with one tag per line and indentation that shows the nesting. Comments are removed.",
    when: "You have a squashed XML response or file that is hard to read.",
    example: { xml: '<order id="1001"><customer>Jane Doe</customer><items><item>Book</item><item>Pen</item></items></order>', indent: "2 spaces" },
  },
  "df-xml-minify": {
    what: "Makes XML as small as possible by removing comments and the spaces and line breaks between tags.",
    when: "You want to save space or send XML on a single line.",
    example: { xml: "<order>\n  <!-- test order -->\n  <customer>Jane Doe</customer>\n  <total>19.99</total>\n</order>" },
  },
  "df-html-table-to-json": {
    what: "Reads the rows of an HTML table and turns them into a JSON list, using the first row as the field names.",
    when: "You copied a table from a web page's HTML source and want the data in a usable format.",
    example: { html: "<table><tr><th>name</th><th>role</th></tr><tr><td>Jane Doe</td><td>Admin</td></tr><tr><td>John Smith</td><td>Editor</td></tr></table>" },
  },
  "df-lines-to-json": {
    what: "Turns each line of text into one item in a JSON list of text values. It can trim spaces and skip blank lines.",
    when: "You have a plain list (names, URLs, ids) and need it as a JSON array for code or a config.",
    example: { text: "apple\nbanana\n\n  cherry  ", trim: true, skipEmpty: true },
  },
  "df-kv-lines-to-json": {
    what: "Reads lines like key=value or key: value and turns them into a JSON object. Comment lines starting with # or ; are skipped.",
    when: "You have simple settings or notes written as key/value lines and want them as JSON.",
    example: { text: "host = example.com\nport: 8080\ndebug = true", typed: true },
  },
  "df-json-to-bracket-qs": {
    what: "Turns JSON, including nested objects and lists, into URL query parameters written with brackets, like user[name]=Jane&tags[0]=a.",
    when: "You are calling a web backend (such as PHP or Rails) that reads nested form data in this bracket style.",
    example: { json: '{"user":{"name":"Jane Doe","age":34},"tags":["admin","beta"]}' },
  },
  "df-json-to-flat-csv": {
    what: "Turns a JSON list of objects into CSV, first flattening nested fields into dotted column names like address.city.",
    when: "Your JSON records have nested objects and you still want each nested value in its own spreadsheet column.",
    example: { json: '[{"name":"Jane Doe","address":{"city":"Springfield","zip":"12345"}},{"name":"John Smith","address":{"city":"Shelbyville","zip":"67890"}}]', delim: "," },
  },
  "df-json-schema": {
    what: "Looks at a sample of JSON and writes a basic JSON Schema for it, a description of which fields exist and what type each one is.",
    when: "You need a starting schema to validate or document an API response. It guesses from one sample, so review it before relying on it.",
    example: { json: '{"id":7,"name":"Jane Doe","score":9.5,"tags":["admin"],"active":true}' },
  },
  "df-json-stats": {
    what: "Counts how many objects, lists, text values, numbers, true/false values and nulls appear anywhere in your JSON.",
    when: "You want a quick overview of what a large JSON document is made of.",
    example: { json: '{"id":7,"name":"Jane Doe","active":true,"manager":null,"tags":["admin","beta"]}' },
  },
  "df-json-to-md-table": {
    what: "Turns a JSON list of objects into a Markdown table (the pipe-and-dash table format used on GitHub and in many docs).",
    when: "You want to show JSON records as a readable table in a README, wiki or issue.",
    example: { json: '[{"id":1,"name":"Jane Doe","role":"Admin"},{"id":2,"name":"John Smith","role":"Editor"}]' },
  },
  "df-json-to-sql": {
    what: "Turns a JSON list of objects into SQL INSERT statements (database commands that add rows), one per object, for the table name you give.",
    when: "You want to load JSON records into a database table. Check the column names and types match your table first.",
    example: { json: '[{"id":1,"name":"Jane Doe","active":true},{"id":2,"name":"O\'Brien","active":false}]', table: "users" },
  },
  "df-csv-to-sql": {
    what: "Turns CSV rows into SQL INSERT statements (database commands that add rows), using the header row as column names.",
    when: "You want to load a spreadsheet export into a database table. Empty cells become NULL.",
    example: { csv: "id,name,city\n1,Jane Doe,Springfield\n2,John Smith,Shelbyville", table: "customers", delim: "," },
  },
};
