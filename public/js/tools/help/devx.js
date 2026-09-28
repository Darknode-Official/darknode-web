// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Plain-English help for the devx.js mini-tools. See help/README.md for the contract.
export const HELP = {
  "dv-uuid-v4": {
    what: "Creates random unique IDs (UUIDs, 36-character codes like 3f2a...-...) that will almost certainly never repeat. Choose how many you want.",
    when: "You need unique IDs for database rows, test data or file names and do not care about their order.",
    example: { count: "3" },
  },
  "dv-uuid-v7": {
    what: "Creates unique IDs (UUIDs) that start with the current time, so IDs made later always sort after earlier ones.",
    when: "You need unique database keys that also stay in creation order, which keeps indexes fast.",
    example: { count: "3" },
  },
  "dv-uuid-nil": {
    what: "Gives you one of the two special fixed UUIDs: the all-zeros NIL UUID or the all-ones (all f) MAX UUID.",
    when: "You need a placeholder UUID meaning \"none\" or \"highest possible\" in code, tests or database defaults.",
    example: { which: "max" },
  },
  "dv-ulid": {
    what: "Creates ULIDs: 26-character unique IDs that begin with the current time, so they sort in the order they were made.",
    when: "You want short, sortable, URL-safe unique IDs for records or logs.",
    example: { count: "3" },
  },
  "dv-nanoid": {
    what: "Creates short random IDs that are safe to use in URLs. You can set the length, the characters allowed, and how many to make.",
    when: "You need compact random IDs, such as for share links or short codes, and a full UUID is too long.",
    example: { size: "12", alphabet: "0123456789abcdef", count: "3" },
  },
  "dv-snowflake-decode": {
    what: "Takes a Snowflake ID (the long numeric IDs used by Twitter/X and Discord) and shows the date and time it was created, plus the machine and sequence numbers hidden inside it.",
    when: "You want to know when a Discord message, user or tweet was created just from its ID. Pick the matching service's epoch or the date will be wrong.",
    example: { id: "175928847299117063", epoch: "1420070400000" },
  },
  "dv-semver-parse": {
    what: "Splits a version number like 1.4.2-rc.1+build.9 into its parts: major, minor, patch, pre-release label and build info.",
    when: "You are reading or writing release tooling and want to check how a version string is understood under semantic versioning (semver) rules.",
    example: { version: "2.7.1-beta.3+build.42" },
  },
  "dv-semver-compare": {
    what: "Compares two version numbers and tells you which is newer, following semantic versioning rules (so 1.10.0 is newer than 1.9.0, and 1.0.0 is newer than 1.0.0-beta).",
    when: "You need to know if an update is really newer, or why a package manager picked one version over another.",
    example: { a: "1.10.0", b: "1.9.5" },
  },
  "dv-semver-bump": {
    what: "Takes a version number and gives the next one for the kind of release you pick: major, minor, patch or pre-release.",
    when: "You are about to publish a release and want the correct next version number.",
    example: { version: "1.4.2", type: "minor" },
  },
  "dv-semver-satisfies": {
    what: "Checks whether a version matches a version rule like ^1.2.0, ~1.2.0 or >=2.0.0, and answers yes or no.",
    when: "You want to know if a package.json range will accept a certain version. Only single rules are supported, not combined ranges like \">=1 <2\" or \"||\".",
    example: { version: "1.8.3", range: "^1.2.0" },
  },
  "dv-chmod-sym-to-oct": {
    what: "Turns a Unix permission string like rwxr-xr-- (as shown by ls -l) into the number form like 754 used by chmod.",
    when: "You see permissions in a file listing and want the number to use in a chmod command.",
    example: { sym: "rwxr-xr--" },
  },
  "dv-chmod-oct-to-sym": {
    what: "Turns a chmod permission number like 755 into the letters form like rwxr-xr-x, so you can see who can read, write and run the file.",
    when: "Someone tells you to \"chmod 640\" a file and you want to know what that actually allows.",
    example: { oct: "640" },
  },
  "dv-umask": {
    what: "Shows what permissions new files or folders will get when a given umask (the setting that removes default permissions) is applied.",
    when: "You are setting a umask for a server or user and want to check the result before new files are created.",
    example: { mask: "027", kind: "777" },
  },
  "dv-gitignore": {
    what: "Gives you a starter .gitignore file (the list of files Git should not track) for Node, Python, Go, Rust or Java projects.",
    when: "You are starting a new repository and want to avoid committing build output, dependencies and secrets by accident.",
    example: { stack: "python" },
  },
  "dv-dockerignore": {
    what: "Gives you a starter .dockerignore file that keeps unneeded files (like dependencies and git history) out of your Docker builds.",
    when: "Your Docker builds are slow or large because they copy in files the image does not need.",
    example: { stack: "node" },
  },
  "dv-editorconfig": {
    what: "Builds an .editorconfig file from your choices for indentation, line endings, character set and whitespace, so every editor formats files the same way.",
    when: "Your team uses different editors and keeps producing mixed tabs, spaces or line endings.",
    example: { style: "space", size: "4", eol: "lf", charset: "utf-8", finalnl: true, trim: true },
  },
  "dv-cron-build": {
    what: "Joins your five schedule parts (minute, hour, day of month, month, day of week) into one cron expression, the schedule format used by Linux cron jobs. Blank fields become * (every).",
    when: "You are setting up a scheduled task and want to build the cron line one part at a time.",
    example: { min: "30", hour: "2", dom: "*", mon: "*", dow: "1-5" },
  },
  "dv-cron-explain": {
    what: "Takes a five-part cron schedule and labels each part (minute, hour, day, month, weekday) with a short note like \"every 15\" or \"range 9-17\".",
    when: "You found a cron line in a config and want a quick breakdown of its fields. It gives short labels, not a full sentence; use Cron Next Runs to see real times.",
    example: { expr: "*/15 9-17 * * 1-5" },
  },
  "dv-curl-build": {
    what: "Builds a ready-to-paste curl command (a command-line tool for web requests) from a URL, method, headers and optional body.",
    when: "You want to test an API from the terminal or share an exact request with a teammate.",
    example: { url: "https://api.example.com/v1/items", method: "POST", headers: "Content-Type: application/json\nAuthorization: Bearer TEST_TOKEN", body: "{\"name\":\"widget\"}" },
  },
  "dv-curl-to-fetch": {
    what: "Turns a simple curl command into the matching JavaScript fetch() code, keeping the URL, method, headers and body.",
    when: "You copied a curl example from API docs and want to use it in browser or Node.js code. It understands only -X, -H and -d style options.",
    example: { cmd: "curl -X POST https://api.example.com/v1/items -H 'Content-Type: application/json' -d '{\"name\":\"widget\"}'" },
  },
  "dv-http-raw": {
    what: "Builds the raw text of an HTTP request (the exact lines a browser sends to a server) from a method, path, host, headers and body. It adds Content-Length for you.",
    when: "You are learning how HTTP works, or need a raw request to paste into a tool like netcat or a proxy.",
    example: { method: "POST", path: "/v1/items", host: "api.example.com", headers: "Content-Type: application/json", body: "{\"id\":3}" },
  },
  "dv-ascii-table": {
    what: "Shows a table of ASCII characters (the basic letters, digits and symbols) with their number codes in decimal, hex and octal. You can also include the invisible control characters.",
    when: "You are debugging text or binary data and need to know which character a code like 0x41 stands for.",
    example: { ctrl: true },
  },
  "dv-ansi-ref": {
    what: "Lists the 16 standard ANSI color codes used to color text in a terminal, for both text color and background. No input needed.",
    when: "You are adding colored output to a command-line script and need the right color numbers.",
    example: {},
  },
  "dv-ansi-build": {
    what: "Builds the special escape code that makes terminal text bold, underlined or colored, and shows it around your sample text, ready for echo or printf.",
    when: "You want colored or bold messages in a shell script or CLI tool without looking up the codes.",
    example: { style: "1", fg: "32", bg: "", text: "Build passed" },
  },
  "dv-ascii-box": {
    what: "Draws a box around your text using plain ASCII characters or neat line-drawing characters, with padding you choose.",
    when: "You want a banner in a README, code comment or terminal output.",
    example: { text: "Deploy complete\nVersion 2.4.0", style: "double", pad: "1" },
  },
  "dv-esc-shell": {
    what: "Wraps your text in single quotes, safely handling any quotes inside, so a Unix shell passes it exactly as written.",
    when: "You need to pass a string with spaces, $ signs or quotes as one argument in a bash command.",
    example: { text: "it's $HOME and more" },
  },
  "dv-esc-dquote": {
    what: "Puts your text inside double quotes and adds backslashes before \\, \", $ and ` so the shell does not treat them as special.",
    when: "You must use double quotes in a shell command or script but the text contains characters the shell would change.",
    example: { text: "Price is $5 and \"cheap\"" },
  },
  "dv-esc-regex": {
    what: "Adds backslashes before special regex characters (like . * ? and brackets) so your text is matched exactly as typed in a regular expression (a search pattern).",
    when: "You want to search for a literal string such as a file name or price inside a regex.",
    example: { text: "file(1).txt costs $5?" },
  },
  "dv-esc-sql": {
    what: "Wraps your text in single quotes and doubles any quote inside it, making a valid SQL text value.",
    when: "You are writing a one-off SQL query by hand with text like O'Brien. In application code, use parameterized queries instead.",
    example: { text: "O'Brien's Pub" },
  },
  "dv-unescape-backslash": {
    what: "Turns backslash codes like \\n, \\t, \\xHH and \\uHHHH in your text into the real characters they stand for (new lines, tabs, symbols).",
    when: "You copied a string from a log or JSON with escape codes and want to see what it actually says.",
    example: { text: "Line one\\nLine two\\tTabbed \\u00e9" },
  },
  "dv-base-convert": {
    what: "Converts a whole number from one number base to another, anywhere from base 2 (binary) to base 36, and works with very large numbers.",
    when: "You need to turn a hex value into binary, or decimal into base 36, for debugging or encoding.",
    example: { num: "ff3a", from: "16", to: "2" },
  },
  "dv-bytes-humanize": {
    what: "Turns a raw number of bytes into an easy size like 1.5 MiB or 1.6 MB, using either 1024-based or 1000-based units.",
    when: "You have a file or memory size in bytes from a log or API and want to read it quickly.",
    example: { bytes: "1572864", base: "1024" },
  },
  "dv-bytes-parse": {
    what: "Turns a size written like \"5 MB\" or \"2.5GiB\" into the exact number of bytes.",
    when: "A config or limit needs a byte count and you only know the size in MB or GiB.",
    example: { text: "2.5 GiB" },
  },
  "dv-bitrate-humanize": {
    what: "Turns a speed in bits per second into an easy form like kbps, Mbps or Gbps (using steps of 1000).",
    when: "You see a raw bandwidth number in a log or stream setting and want to read it quickly.",
    example: { bps: "2500000" },
  },
  "dv-cron-next": {
    what: "Takes a five-part cron schedule and lists the next times it will run, starting from now in your local time.",
    when: "You want to be sure a cron job will run when you expect before you deploy it.",
    example: { expr: "0 9 * * 1-5", count: "5" },
  },
  "dv-env-parse": {
    what: "Reads the contents of a .env file (KEY=value lines of settings) and shows a clean list of keys and values, skipping comments and removing quotes.",
    when: "You want to check what settings a .env file really defines.",
    example: { text: "# database\nDB_HOST=localhost\nDB_PORT=5432\nAPP_NAME=\"Demo App\"" },
  },
  "dv-env-export": {
    what: "Turns .env lines into shell \"export KEY='value'\" lines with safe quoting, ready to paste into a terminal or script.",
    when: "You want to load a .env file's settings into your current shell session.",
    example: { text: "PORT=3000\nAPP_NAME=\"Demo App\"\n# comment\nGREETING=it's fine" },
  },
  "dv-json-to-env": {
    what: "Turns a JSON settings object into .env lines. Keys become uppercase, and nested keys are joined with underscores (db.host becomes DB_HOST).",
    when: "You have settings in JSON and need them as environment variables for Docker or a hosting service.",
    example: { text: "{\"port\":3000,\"db\":{\"host\":\"localhost\",\"name\":\"shop\"}}" },
  },
  "dv-tab-spaces": {
    what: "Changes the indentation at the start of each line from tabs to spaces, or spaces to tabs, using the tab width you choose.",
    when: "A file has the wrong indentation style for your project or linter.",
    example: { text: "function hi() {\n\treturn 1;\n}", mode: "t2s", width: "4" },
  },
  "dv-line-endings": {
    what: "Changes every line ending in your text to one style: LF (Linux and macOS), CRLF (Windows) or CR (old Mac).",
    when: "A script fails or shows odd ^M characters because it was saved with Windows line endings.",
    example: { text: "first line\r\nsecond line\r\n", target: "lf" },
  },
  "dv-strip-trailing": {
    what: "Removes spaces and tabs left at the end of each line, and can also remove empty lines at the end of the text.",
    when: "Your diff or linter complains about trailing whitespace.",
    example: { text: "let a = 1;   \nlet b = 2;\t\n\n\n", endblank: true },
  },
  "dv-sort-imports": {
    what: "Sorts your import lines (or any lines) in alphabetical order and drops empty lines.",
    when: "You want a tidy, consistent import block in a code file. It sorts plain text only and does not understand multi-line imports.",
    example: { text: "import { z } from \"zod\";\nimport React from \"react\";\nimport axios from \"axios\";", ci: true },
  },
  "dv-dedupe-sort": {
    what: "Removes repeated lines from a list and then sorts it A to Z, Z to A, or keeps the original order.",
    when: "You have a list of emails, tags or names with duplicates and want a clean unique list.",
    example: { text: "banana\napple\ncherry\napple\nbanana", ci: false, order: "asc" },
  },
  "dv-random-token": {
    what: "Creates a secure random token (a hard-to-guess string) of the size you choose, as hex, base64 or URL-safe base64.",
    when: "You need an API key, session secret or password reset token for your own app.",
    example: { bytes: "32", format: "base64url" },
  },
  "dv-htaccess-redirect": {
    what: "Builds an Apache .htaccess line that sends visitors from an old path to a new URL, as a permanent (301) or temporary (302) redirect.",
    when: "You moved a page on an Apache website and do not want old links or search results to break.",
    example: { from: "/old-page", to: "https://example.com/new-page", code: "301", style: "redirect" },
  },
  "dv-nginx-redirect": {
    what: "Builds an nginx config block that redirects a path to a new URL, as a permanent (301) or temporary (302) redirect.",
    when: "You moved a page on an nginx server and want old links to keep working.",
    example: { path: "/blog", to: "https://blog.example.com/", code: "301" },
  },
  "dv-npm-name-validate": {
    what: "Checks whether a name is allowed as an npm package name and lists any rules it breaks, such as uppercase letters or bad characters.",
    when: "You are about to publish a JavaScript package and want to avoid a rejected name. It does not check whether the name is already taken.",
    example: { name: "My_Cool.Package" },
  },
  "dv-dockerfile-healthcheck": {
    what: "Builds a HEALTHCHECK line for a Dockerfile, which tells Docker how to test that your container is still working and how often.",
    when: "You want Docker or your orchestrator to notice and restart a container that has stopped responding.",
    example: { cmd: "curl -f http://localhost:8080/health || exit 1", interval: "30s", timeout: "5s", retries: "3", start: "10s" },
  },
  "dv-systemd-unit": {
    what: "Creates a basic systemd service file, which lets Linux start your program at boot and restart it if it crashes.",
    when: "You want your app or script to run as a background service on a Linux server.",
    example: { desc: "Demo web app", exec: "/usr/bin/node /srv/app/index.js", user: "www-data", after: "network.target", restart: "on-failure" },
  },
  "dv-makefile-target": {
    what: "Builds a Makefile target (a named task for the make tool) with its prerequisites and commands, using the required tab indentation.",
    when: "You want to add a build or test task to a Makefile and avoid the classic \"missing separator\" tab error.",
    example: { name: "test", deps: "build", recipe: "npm test\necho done", phony: true },
  },
  "dv-gitattributes": {
    what: "Builds a .gitattributes line that tells Git how to treat certain files, for example fixing line endings, marking them as binary, or storing them with Git LFS.",
    when: "You have line-ending problems between Windows and Linux, or large files that belong in Git LFS.",
    example: { pattern: "*.sh", attr: "text eol=lf" },
  },
  "dv-license-header": {
    what: "Creates a copyright and license notice as a comment block, in the right comment style for your language, to put at the top of source files.",
    when: "Your project needs a license header in every file, for example MIT or Apache-2.0.",
    example: { lang: "hash", license: "Apache-2.0", author: "Example Corp", year: "2026" },
  },
  "dv-todo-extract": {
    what: "Scans pasted code and lists every line that contains TODO, FIXME, HACK, XXX or NOTE (or your own words), with its line number.",
    when: "You want a quick list of unfinished work or known problems in a file before a release.",
    example: { code: "function a() {\n  // TODO: handle errors\n  return 1;\n}\n// FIXME slow on large input", tags: "TODO,FIXME" },
  },
  "dv-cloc": {
    what: "Counts the lines in pasted code and splits them into code, comment and blank lines.",
    when: "You want a rough size of a file. It only spots lines that start with your chosen comment mark, not block comments.",
    example: { code: "// add two numbers\nfunction add(a, b) {\n\n  return a + b;\n}", comment: "//" },
  },
  "dv-slug-filename": {
    what: "Turns a title or messy file name into a safe lowercase name with hyphens instead of spaces and symbols, keeping the file extension.",
    when: "You are saving or uploading files and want names that work well in URLs and on every operating system.",
    example: { name: "Quarterly Report (Final v2).PDF" },
  },
  "dv-mime-ext": {
    what: "Type a file extension or file name and get its MIME type, the label that tells browsers what kind of file it is (for example image/png).",
    when: "You are setting a Content-Type header or upload rule. It covers common web file types only.",
    example: { ext: "photo.webp" },
  },
  "dv-http-status": {
    what: "Type an HTTP status code (the number a web server sends back, like 404) and get its name and category.",
    when: "An API or browser shows a status code and you want to know what it means.",
    example: { code: "429" },
  },
  "dv-regex-common": {
    what: "Gives a ready-to-use regular expression (search pattern) for a common kind of data: email, URL, IPv4 address, UUID or date (YYYY-MM-DD).",
    when: "You need basic input checking in a form or script. These are simple patterns, not full standards checks.",
    example: { kind: "date" },
  },
  "dv-random-port": {
    what: "Picks random port numbers between 49152 and 65535, the range meant for temporary and private use.",
    when: "You need a port for a local test server that is unlikely to clash with common services. It does not check if the port is free on your machine.",
    example: { count: "3" },
  },
  "dv-jwt-decode": {
    what: "Shows the readable header and payload inside a JWT (a login token made of three dot-separated parts). It does not check the signature.",
    when: "You are debugging login and want to see a token's user info and expiry. Never trust a token just because it decodes; only the server can verify it.",
    example: { jwt: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" },
  },
  "dv-commit-lint": {
    what: "Checks whether a commit message title follows the Conventional Commits style (like \"feat(api): add paging\") and shows its type, scope and whether it marks a breaking change.",
    when: "Your project requires Conventional Commits and you want to check a message before pushing.",
    example: { msg: "feat(api): add pagination to list endpoint" },
  },
  "dv-ua-parse": {
    what: "Reads a browser's User-Agent text (the ID string browsers send to websites) and makes a best guess at the browser, its engine and the operating system.",
    when: "You are reading server logs or bug reports and want to know what browser a visitor used. User-Agents can be faked, so treat it as a hint.",
    example: { ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15" },
  },
  "dv-querystring": {
    what: "Turns a URL query string (the part after ?) into readable JSON, or turns a simple JSON object back into a query string.",
    when: "You are debugging URL parameters or building a link from a set of values.",
    example: { text: "q=red%20shoes&size=9&tag=sale&tag=new", mode: "parse" },
  },
  "dv-epoch": {
    what: "Converts a Unix timestamp (seconds or milliseconds since 1 January 1970) into a readable date, or a date into a timestamp.",
    when: "You see a long number like 1727280000 in a log or database and want to know what date it is.",
    example: { value: "1727280000", mode: "e2d", unit: "s" },
  },
};
