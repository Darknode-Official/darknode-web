// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Plain-English help for the text.js mini-tools. See help/README.md for the contract.
export const HELP = {
  "t-text-stats": {
    what: "Paste any text and get back how many words, characters (with and without spaces), lines and bytes it contains. Bytes is the size the text takes up when saved as a normal UTF-8 file.",
    when: "You are writing something with a length limit, such as a bio, a form field or a tweet, and want to check how long it is.",
    example: { text: "Hello world.\nThis is a short note for Jane." },
  },
  "t-case-convert": {
    what: "Changes the capital letters in your text: ALL CAPS, all lowercase, Title Case (first letter of each word capital) or Sentence case (first letter of each sentence capital).",
    when: "You pasted text that was typed in the wrong case, for example a heading in all caps, and want to fix it without retyping.",
    example: { text: "the QUICK brown fox. it jumps over the lazy dog!", mode: "Sentence case" },
  },
  "t-camel-case": {
    what: "Turns words into camelCase: spaces and symbols are removed, the first word stays lowercase and every following word starts with a capital (for example userFirstName).",
    when: "You are naming a variable or JSON field in JavaScript or a similar language and want the standard camelCase style.",
    example: { text: "user first name" },
  },
  "t-pascal-case": {
    what: "Turns words into PascalCase: spaces and symbols are removed and every word starts with a capital letter (for example UserProfilePage).",
    when: "You are naming a class, component or type in code, where PascalCase is the usual convention.",
    example: { text: "user profile page" },
  },
  "t-snake-case": {
    what: "Turns words into snake_case: everything lowercase with underscores between words (for example order_total_amount).",
    when: "You are naming a Python variable, a database column or a file and want the underscore style.",
    example: { text: "Order Total Amount" },
  },
  "t-kebab-case": {
    what: "Turns words into kebab-case: everything lowercase with hyphens between words (for example main-nav-button).",
    when: "You are naming a CSS class, an HTML id or a file where hyphen-separated names are the norm.",
    example: { text: "Main Nav Button" },
  },
  "t-constant-case": {
    what: "Turns words into CONSTANT_CASE: everything uppercase with underscores between words (for example MAX_RETRY_COUNT).",
    when: "You are naming a constant or an environment variable in code, which is usually written in this style.",
    example: { text: "max retry count" },
  },
  "t-slugify": {
    what: "Turns a title or phrase into a slug, the short lowercase part of a web address such as my-cafe-post. Accents are removed and anything that is not a letter or number becomes the separator.",
    when: "You are publishing a blog post or page and need a clean, readable address for it.",
    example: { text: "My Cafe Post: Best Coffee in Zurich!", separator: "-" },
  },
  "t-slug-maxlen": {
    what: "Turns a title into a slug (the lowercase, hyphenated part of a web address) and cuts it to a maximum number of characters without leaving a dangling hyphen at the end.",
    when: "You have a long article title and want a web address that is readable but not too long.",
    example: { text: "An Extremely Long Article Title About Planning a Weekend Trip to the Mountains", maxLength: "40" },
  },
  "t-sort-lines": {
    what: "Sorts the lines of your text A to Z, Z to A, by length, or in natural order (where item2 comes before item10). You can also ignore upper and lower case while sorting.",
    when: "You have a list of names, words or file names and want them in a tidy order.",
    example: { text: "banana\nApple\ncherry\nitem10\nitem2", order: "Natural", caseInsensitive: true },
  },
  "t-reverse-lines": {
    what: "Flips the order of your lines so the last line comes first and the first line comes last. The text inside each line is not changed.",
    when: "You have a log or list that is oldest-first and you want to read it newest-first.",
    example: { text: "Step 1: open\nStep 2: edit\nStep 3: save" },
  },
  "t-reverse-line-chars": {
    what: "Writes every line backwards, character by character, while keeping the lines in the same order.",
    when: "You want mirrored text for a puzzle or a bit of fun, or need to check how a string looks reversed.",
    example: { text: "hello world\nabc 123" },
  },
  "t-dedupe-lines": {
    what: "Removes repeated lines so each line appears only once, keeping the first time it appeared and the original order. Matching is exact, including upper and lower case.",
    when: "You merged two lists, such as email addresses or tags, and want to drop the duplicates.",
    example: { text: "apple\nbanana\napple\ncherry\nbanana" },
  },
  "t-remove-blank-lines": {
    what: "Deletes every line that is empty or contains only spaces or tabs, leaving the lines that have content.",
    when: "You copied text from a web page or PDF and it came with lots of gaps between lines.",
    example: { text: "First line\n\n   \nSecond line\n\nThird line" },
  },
  "t-trim-lines": {
    what: "Removes the spaces and tabs at the start and end of every line, but keeps the words and the line breaks.",
    when: "You pasted a list that has stray indentation or trailing spaces and want clean lines.",
    example: { text: "   apple   \n\tbanana\n cherry  " },
  },
  "t-collapse-spaces": {
    what: "Replaces any run of two or more spaces or tabs with a single space. Line breaks are kept.",
    when: "You have text with uneven gaps between words, for example after copying from a PDF, and want normal spacing.",
    example: { text: "This    has   too many\t\tspaces." },
  },
  "t-find-replace": {
    what: "Finds every place a word or phrase appears in your text and replaces it with something else. You can also turn on regex (a pattern language for matching text) and ignore upper and lower case.",
    when: "You need to change a name, word or pattern everywhere in a long piece of text at once.",
    example: { text: "Hello Jane. Jane said hello back.", find: "Jane", replace: "Alex", regex: false, caseInsensitive: false },
  },
  "t-count-occurrences": {
    what: "Counts how many times a word or piece of text appears inside a larger text. You can choose to ignore upper and lower case.",
    when: "You want to know how often a keyword or name is used in an article or document.",
    example: { text: "The cat sat. The cat ran. A dog saw the cat.", substring: "cat", caseInsensitive: true },
  },
  "t-line-numbers": {
    what: "Puts a number in front of every line (1. 2. 3. and so on). You choose the starting number and whether to pad numbers with leading zeros so they line up.",
    when: "You are sharing code, a script or a list and want people to be able to refer to a line by number.",
    example: { text: "Buy milk\nCall Sam\nSend report", start: "1", pad: false },
  },
  "t-prefix-suffix": {
    what: "Adds the same text to the start and/or end of every line, such as a bullet, a quote mark or a comma. Blank lines can be left untouched.",
    when: "You want to turn a plain list into bullet points, quoted values or lines ending with a comma.",
    example: { text: "apple\nbanana\ncherry", prefix: "- ", suffix: ";", skipBlank: true },
  },
  "t-wrap-indent": {
    what: "Re-breaks long lines so none is wider than the number of characters you choose, without splitting words, and can add an indent in front of every line.",
    when: "You are writing a plain-text email, commit message or code comment and want lines of a fixed width.",
    example: { text: "This is a fairly long sentence that should be wrapped onto several shorter lines for easier reading.", width: "30", indent: "  " },
  },
  "t-truncate": {
    what: "Shortens text to a maximum number of characters and ends it with an ellipsis such as three dots. The ellipsis counts toward the limit, and text that is already short enough is returned unchanged.",
    when: "You need a short preview of a longer text, for example for a card, list or notification.",
    example: { text: "This product description is much too long to fit inside the small preview box on the page.", length: "40", ellipsis: "..." },
  },
  "t-remove-accents": {
    what: "Removes accent marks from letters, so letters like e with an accent become a plain e. Other characters are left as they are.",
    when: "You need plain letters for a file name, search, or a system that does not handle accented characters well.",
    example: { text: "Café, naïve, Zürich, José" },
  },
  "t-strip-html": {
    what: "Removes HTML tags (the markup in angle brackets like <p> or <b>) from your text and leaves only the readable words.",
    when: "You copied the source of a web page or email and just want the plain text. It does not convert codes like &amp; back into symbols.",
    example: { text: "<p>Hello <b>world</b>, visit <a href=\"https://example.com\">our site</a>.</p>" },
  },
  "t-extract-emails": {
    what: "Scans a block of text and lists every email address it finds, one per line. You can keep only unique addresses.",
    when: "You have a long message, export or page and want to pull out the email addresses without reading it all.",
    example: { text: "Contact jane.doe@example.com or sales@example.com. Again: jane.doe@example.com", dedupe: true },
  },
  "t-extract-urls": {
    what: "Scans a block of text and lists every web link that starts with http:// or https://, one per line. You can keep only unique links.",
    when: "You want to collect all the links mentioned in an email, document or chat log.",
    example: { text: "See https://example.com/docs and http://example.org/about for details.", dedupe: true },
  },
  "t-extract-ips": {
    what: "Scans a block of text and lists every valid IPv4 address (a network address written as four numbers from 0 to 255, like 192.0.2.10). You can keep only unique ones.",
    when: "You are looking through a server log and want a list of the IP addresses that appear in it.",
    example: { text: "Login from 192.0.2.10 failed. Retry from 198.51.100.7. Again 192.0.2.10. Bad: 999.1.1.1", dedupe: true },
  },
  "t-tabs-spaces": {
    what: "Replaces each tab with a chosen number of spaces, or replaces each group of that many spaces with a tab.",
    when: "You are fixing indentation in code or a text file that mixes tabs and spaces.",
    example: { text: "\tif (x) {\n\t\treturn 1;\n\t}", mode: "Tabs → Spaces", width: "4" },
  },
  "t-shuffle-lines": {
    what: "Puts your lines in a random order each time you press Shuffle.",
    when: "You want to randomize a list, for example quiz questions, names for a draw or a playlist. Not suitable for anything that needs secure randomness.",
    example: { text: "Alice\nBob\nCarol\nDave\nEve" },
  },
  "t-unique-words": {
    what: "Lists each different word in your text once, one per line, in the order it first appears. Upper and lower case can be treated as the same.",
    when: "You want a quick vocabulary list or to see which distinct words a text uses.",
    example: { text: "The cat and the dog and THE bird", caseInsensitive: true },
  },
  "t-word-frequency": {
    what: "Counts how often each word appears and shows the most common ones with their counts, most frequent first.",
    when: "You want to see which words you overuse in an essay, or find the main keywords in a text.",
    example: { text: "the cat saw the dog and the dog saw the cat", topN: "5", caseInsensitive: true },
  },
  "t-palindrome-check": {
    what: "Tells you whether a word or phrase reads the same forwards and backwards, ignoring spaces, punctuation and upper and lower case.",
    when: "You are solving a word puzzle or just curious whether a phrase is a palindrome.",
    example: { text: "A man, a plan, a canal: Panama" },
  },
  "t-anagram-check": {
    what: "Tells you whether two words or phrases use exactly the same letters (an anagram), ignoring spaces, punctuation and case.",
    when: "You are playing a word game or checking a puzzle answer.",
    example: { text1: "listen", text2: "silent" },
  },
  "t-reading-time": {
    what: "Counts words, sentences and characters and estimates how many minutes the text takes to read at a chosen reading speed (words per minute).",
    when: "You are publishing an article or preparing a talk and want to show or know roughly how long it takes to read.",
    example: { text: "Reading time estimates help readers decide when to read. They are simple to compute. Most people read about 200 words per minute.", wpm: "200" },
  },
  "t-dedupe-consecutive-words": {
    what: "Finds words that are accidentally typed twice in a row (like \"the the\") and keeps just one.",
    when: "You are proofreading a draft and want to catch doubled words quickly.",
    example: { text: "This is is a test test of the the tool.", caseInsensitive: true },
  },
  "t-json-oneline": {
    what: "Turns multi-line text into a single line that can be placed inside quotes in JSON (a common data format): quotes, backslashes, tabs and line breaks are replaced with escape codes like \\n.",
    when: "You need to paste a paragraph or a snippet into a JSON file or API request as one string value.",
    example: { text: "Line one says \"hi\".\nLine two\thas a tab." },
  },
};
