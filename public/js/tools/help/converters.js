// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Plain-English help for the converters.js mini-tools. See help/README.md for the contract.
export const HELP = {
  "c-json-prettify": {
    what: "Paste JSON (a common text format for data) that is squashed onto one line or messy, and get it back neatly indented with 2 spaces, 4 spaces or tabs so it is easy to read.",
    when: "You copied a compact API response or config file and need to read or review it. Invalid JSON gives an error instead of output.",
    example: { json: '{"user":{"id":7,"name":"Ada Example","roles":["admin","editor"]},"active":true}', indent: "2 spaces" },
  },
  "c-json-minify": {
    what: "Paste JSON and get the same data with all extra spaces and line breaks removed, on one compact line.",
    when: "You want to shrink JSON before putting it in a URL, an environment variable or a request body.",
    example: { json: '{\n  "id": 7,\n  "name": "Ada Example",\n  "tags": ["a", "b"]\n}' },
  },
  "c-json-validate": {
    what: "Paste JSON and find out whether it is valid. If it is, you get a short summary of what it contains; if not, you get the exact error message pointing at the problem.",
    when: "An app refuses to load your config or API payload and you want to know where the JSON is broken.",
    example: { json: '{"id": 7, "name": "Ada Example", "tags": ["a", "b"]}' },
  },
  "c-json-csv": {
    what: "Paste a JSON list of records (objects) and get a CSV table: the first line holds the column names and each record becomes one row.",
    when: "You have API data in JSON and want to open it in Excel or Google Sheets. Nested values are written as JSON text inside a cell.",
    example: { json: '[{"name":"Ada Example","city":"Springfield","age":36},{"name":"Bob Sample","city":"Salem","age":41}]', delim: "," },
  },
  "c-csv-json": {
    what: "Paste CSV text (a table with comma-separated values) and get a JSON list of objects, using the first row as the field names.",
    when: "You exported a spreadsheet and need its rows as JSON for code, a test fixture or an API. All values come out as text, not numbers.",
    example: { csv: "name,city,age\nAda Example,Springfield,36\nBob Sample,Salem,41", delim: "," },
  },
  "c-json-xml": {
    what: "Paste JSON and get the same data as simple XML, where every key becomes a tag, wrapped in a root tag you choose.",
    when: "An older system or SOAP-style service only accepts XML and you have your data in JSON. Attributes are not created, only nested tags.",
    example: { json: '{"user":{"id":1,"name":"Ada Example","email":"ada@example.com"}}', root: "root" },
  },
  "c-json-qs": {
    what: "Paste a flat JSON object and get a URL query string like q=test&page=2, with special characters safely encoded. List values become repeated keys.",
    when: "You are building a link or API request URL from a set of parameters.",
    example: { json: '{"q":"red shoes","page":2,"sort":"price"}' },
  },
  "c-qs-json": {
    what: "Paste the part of a URL after the ? (like q=test&page=2) and get a readable JSON object of the parameters. Encoded characters are decoded, and a key that appears more than once becomes a list.",
    when: "You are debugging a long tracking or API URL and want to see clearly which parameters it carries.",
    example: { qs: "?q=red+shoes&page=2&tag=sale&tag=new" },
  },
  "c-csv-md": {
    what: "Paste CSV text and get a Markdown table (the table style used on GitHub and many docs sites), with the first row as the header.",
    when: "You want to put spreadsheet data into a README, wiki page or GitHub issue.",
    example: { csv: "Name,Role,Team\nAda Example,Engineer,Platform\nBob Sample,Designer,Web", delim: "," },
  },
  "c-md-csv": {
    what: "Paste a Markdown table (rows with | between cells) and get the cells back as CSV text. The --- divider line is skipped.",
    when: "You found a table in a README or docs page and want to open it in a spreadsheet.",
    example: { md: "| Name | Role |\n| --- | --- |\n| Ada Example | Engineer |\n| Bob Sample | Designer |", delim: "," },
  },
  "c-base-convert": {
    what: "Type a whole number and choose the base it is written in and the base you want (anything from 2 to 36), and get the converted number. Base 2 is binary, 10 is normal decimal, 16 is hex.",
    when: "You need to turn a number from one number system into another, such as hex to decimal or decimal to base 36. Whole numbers only, no fractions.",
    example: { value: "ff", fromBase: "16", toBase: "10" },
  },
  "c-dec-hex": {
    what: "Convert a whole number between normal decimal and hexadecimal (base 16, using digits 0-9 and a-f), in the direction you choose.",
    when: "You are reading memory addresses, color codes or error codes written in hex and want the normal number, or the reverse.",
    example: { value: "255", mode: "Decimal → Hex" },
  },
  "c-dec-bin": {
    what: "Convert a whole number between normal decimal and binary (base 2, only 0s and 1s), in the direction you choose.",
    when: "You are learning how computers store numbers, or working with bit flags and masks.",
    example: { value: "42", mode: "Decimal → Binary" },
  },
  "c-dec-oct": {
    what: "Convert a whole number between normal decimal and octal (base 8, digits 0-7), in the direction you choose.",
    when: "You are dealing with Unix file permissions or older systems that write numbers in octal.",
    example: { value: "493", mode: "Decimal → Octal" },
  },
  "c-byte-size": {
    what: "Type a file or storage size with its unit and see it in bytes and in every other unit, both the 1000-based kind (KB, MB, GB) and the 1024-based kind (KiB, MiB, GiB).",
    when: "You want to know why a 500 GB drive shows less space in your computer, or convert a download size between units.",
    example: { value: "1.5", unit: "GB" },
  },
  "c-epoch-date": {
    what: "Type a Unix timestamp (the number of seconds, or milliseconds, since 1 January 1970) and get the readable date and time in UTC. It detects seconds or milliseconds automatically.",
    when: "You see a long number like 1700000000 in a log or database and want to know what date it is.",
    example: { epoch: "1700000000" },
  },
  "c-date-epoch": {
    what: "Type a date, ideally in the standard ISO form like 2026-01-01T00:00:00Z, and get its Unix timestamp in seconds and in milliseconds.",
    when: "You need a timestamp number for an API call, a database query or a cookie expiry. A date and time written without a time zone may be read in your browser's local time.",
    example: { date: "2026-01-01T00:00:00Z" },
  },
  "c-duration-sec": {
    what: "Type a duration in the ISO-8601 style (like P1DT2H3M4S, meaning 1 day, 2 hours, 3 minutes, 4 seconds) and get the total number of seconds.",
    when: "An API or video file gives you a length like PT1H30M and you need it as plain seconds. Months are counted as 30 days and years as 365 days.",
    example: { duration: "P1DT2H3M4S" },
  },
  "c-sec-duration": {
    what: "Type a number of seconds and get it written as days, hours, minutes and seconds, like 1d 2h 3m 4s.",
    when: "A log or script reports an uptime or wait time in seconds and you want to understand how long that actually is.",
    example: { seconds: "93784" },
  },
  "c-ms-hhmmss": {
    what: "Type a number of milliseconds (thousandths of a second) and get it as hours:minutes:seconds.milliseconds, like 01:01:01.234.",
    when: "You have a timing or video position in milliseconds and need a readable clock-style time, for example for subtitles.",
    example: { ms: "3661234" },
  },
  "c-roman": {
    what: "Type a number from 1 to 3999 to get Roman numerals, or type Roman numerals (like MCMXCIV) to get the number. It works out the direction by itself.",
    when: "You are reading a year on a building, movie credits or a clock face, or need Roman numerals for an outline or a title.",
    example: { value: "MCMXCIV" },
  },
  "c-temperature": {
    what: "Type a temperature and say whether it is Celsius, Fahrenheit or Kelvin, and get it in all three.",
    when: "You are following a recipe, a weather report or a science problem that uses a different temperature scale than you do.",
    example: { value: "100", from: "C" },
  },
  "c-data-rate": {
    what: "Type an internet or network speed with its unit (bits per second, such as Mbps) and see it in every other bit unit plus in bytes per second (B/s, KB/s, MB/s).",
    when: "Your internet plan says 100 Mbps and you want to know how many megabytes per second a download should actually reach.",
    example: { value: "100", unit: "Mbps" },
  },
  "c-hex-rgb": {
    what: "Convert a color between a hex code (like #3366ff) and rgb(red, green, blue) numbers, in the direction you choose.",
    when: "You have a color from a design file in one format and your code needs the other. The Color category has tools with more formats.",
    example: { value: "#3366ff", mode: "Hex → RGB" },
  },
  "c-rgb-hsl": {
    what: "Type red, green and blue numbers (0 to 255, separated by commas) and get the color as hsl(hue, saturation, lightness).",
    when: "You want to adjust a color's lightness or vividness in CSS and only have its RGB numbers.",
    example: { rgb: "51,102,255" },
  },
  "c-rgb-cmyk": {
    what: "Type red, green and blue numbers (0 to 255, separated by commas) and get the cyan, magenta, yellow and black ink percentages used in printing.",
    when: "You need rough print values for a screen color. It is a simple formula, so real printed color can differ.",
    example: { rgb: "51,102,255" },
  },
  "c-px-rem": {
    what: "Convert CSS sizes between pixels (px) and rem, a unit relative to the page's base font size (usually 16px). You can change the base size.",
    when: "Your design mock-up is in pixels but your stylesheet uses rem so text scales with the user's font settings.",
    example: { value: "24", base: "16", mode: "px → rem" },
  },
  "c-ascii-text": {
    what: "Turn text into its character code numbers (like H = 72) separated by spaces, or turn a list of such numbers back into text.",
    when: "You are decoding a puzzle, a CTF challenge or data that was stored as a list of character codes.",
    example: { text: "Hello", mode: "Text → Codes" },
  },
  "c-utf8-inspect": {
    what: "Paste text and get one line per character showing its Unicode code point (its official number, like U+00E9) and the exact UTF-8 bytes used to store it.",
    when: "You see strange characters, broken accents or odd lengths in text and want to find out what is really in it.",
    example: { text: "café" },
  },
  "c-chmod": {
    what: "Convert Unix or Linux file permissions between the number form (like 755) and the letter form (like rwxr-xr-x), where r is read, w is write and x is run, for owner, group and everyone.",
    when: "You need to understand or set file permissions with the chmod command and only know one of the two forms.",
    example: { value: "755", mode: "Octal → Symbolic" },
  },
  "c-deg-rad": {
    what: "Convert an angle between degrees (a full circle is 360) and radians (a full circle is about 6.283), in the direction you choose.",
    when: "You are doing math or coding a game or animation, where most functions expect radians but you think in degrees.",
    example: { value: "180", mode: "Degrees → Radians" },
  },
  "c-base64-hex": {
    what: "Convert raw data between Base64 (letters, numbers, + and /) and hex (pairs of 0-9 and a-f). Both are ways to write binary bytes as text; the bytes stay the same.",
    when: "One tool gives you a key, hash or signature in Base64 and another expects it in hex, or the reverse.",
    example: { value: "SGVsbG8gV29ybGQ=", mode: "Base64 → Hex" },
  },
  "c-json-ts": {
    what: "Paste a sample of JSON data and get a TypeScript interface (a type description for code) that matches its shape, with a name you choose.",
    when: "You are writing TypeScript that uses an API response and want the types without typing them by hand. It only knows the sample you give, so optional fields are not detected.",
    example: { json: '{"id":1,"name":"Ada Example","tags":["admin"],"address":{"city":"Springfield"}}', name: "User" },
  },
  "c-json-go": {
    what: "Paste a sample JSON object and get a Go struct (a type definition for the Go language) with matching fields and json tags.",
    when: "You are writing Go code that reads an API response and want the struct without typing it by hand. Arrays use the type of their first item only.",
    example: { json: '{"id":1,"user_name":"ada","active":true,"score":9.5}', name: "User" },
  },
  "c-sql-in": {
    what: "Paste a list of values (one per line or comma separated) and get a SQL IN (...) clause. Text values are put in single quotes with any quotes inside escaped; numbers are left bare unless you force quoting.",
    when: "You have a list of IDs or names from a spreadsheet and need to filter a database query by them.",
    example: { list: "alice\nbob\ncarol", forceQuote: false },
  },
  "c-list-json-array": {
    what: "Turn a list with one item per line into a JSON array of strings, or turn a JSON array back into one item per line.",
    when: "You copied a column of values and need it as a JSON array for code or a config file, or the other way round. Blank lines are dropped.",
    example: { text: "apples\nbananas\ncherries", mode: "List → JSON" },
  },
  "c-csv-column": {
    what: "Paste CSV text, give a column number (counting starts at 0, so the first column is 0), and get just that column's values, one per line. You can skip the header row.",
    when: "You only need the email addresses or IDs from a large CSV export.",
    example: { csv: "name,email,city\nAda Example,ada@example.com,Salem\nBob Sample,bob@example.com,Auburn", col: "1", delim: ",", skipHeader: true },
  },
  "c-csv-case": {
    what: "Paste CSV text, pick a column number (the first column is 0) and a letter case, and get the CSV back with that column changed to UPPERCASE, lowercase or Title Case.",
    when: "One column in your spreadsheet has messy capitalization, like names or country codes, and you want it consistent.",
    example: { csv: "name,country\nada example,us\nbob sample,gb", col: "0", delim: ",", skipHeader: true, mode: "Title Case" },
  },
  "c-cron-human": {
    what: "Type a cron schedule (five fields: minute, hour, day of month, month, day of week) and get a line-by-line plain-English explanation of each field.",
    when: "You found a scheduled job in a server config and want to know when it actually runs. Only the standard 5-field format is supported.",
    example: { cron: "*/15 9-17 * * 1-5" },
  },
  "c-hex-rgba": {
    what: "Type a hex color and choose an opacity from 0 (fully see-through) to 1 (solid), and get the color as a CSS rgba() value.",
    when: "You want a semi-transparent version of a brand color for an overlay, shadow or background.",
    example: { hex: "#3366ff", alpha: "0.5" },
  },
  "c-identifier-case": {
    what: "Type a variable or function name in any style and get it in the style you choose: camelCase, PascalCase, snake_case, kebab-case or CONSTANT_CASE.",
    when: "You are moving names between languages or files with different naming rules, such as a Python field into JavaScript code.",
    example: { text: "user_account-ID", mode: "camelCase" },
  },
  "c-thousands-sep": {
    what: "Type a number and get it with a separator between every group of three digits (like 1,234,567), optionally rounded to a set number of decimal places.",
    when: "You are putting big numbers in a report, invoice or slide and want them easy to read.",
    example: { value: "1234567.891", sep: ",", decimals: "2" },
  },
  "c-sci-decimal": {
    what: "Convert a number between normal form (like 123000) and scientific notation (like 1.23e+5, meaning 1.23 times 10 to the 5th), in the direction you choose.",
    when: "You are working with very large or very small numbers in science or engineering and need them in the other form. Very long numbers may lose precision.",
    example: { value: "123000", mode: "Decimal → Scientific", digits: "3" },
  },
  "c-csv-tsv": {
    what: "Convert table data between CSV (commas between values) and TSV (tabs between values), keeping quoted values correct.",
    when: "One program exports CSV but the program you paste into expects tab-separated data, or the reverse.",
    example: { text: "name,city\nAda Example,Springfield\nBob Sample,Salem", mode: "CSV → TSV" },
  },
};
