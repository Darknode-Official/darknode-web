// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Plain-English help for the textx.js mini-tools. See help/README.md for the contract.
export const HELP = {
  "tx-uppercase": {
    what: "Changes every letter in your text to a capital letter. Numbers and symbols stay the same.",
    when: "You need a heading, label or code in ALL CAPS without retyping it.",
    example: { text: "please read carefully" },
  },
  "tx-lowercase": {
    what: "Changes every capital letter in your text to a small letter.",
    when: "You pasted text that was typed with caps lock on, or you need lowercase for an email address or tag.",
    example: { text: "HELLO FROM THE TEAM" },
  },
  "tx-title-case": {
    what: "Makes the first letter of every word a capital and the rest of the word lowercase.",
    when: "You are formatting headings, names or titles consistently.",
    example: { text: "the lord OF the rings" },
  },
  "tx-sentence-case": {
    what: "Makes everything lowercase, then capitalizes the first letter of each sentence (after a full stop, question mark or exclamation mark).",
    when: "You have text in all caps or mixed case and want it to read like normal sentences. Names inside sentences will also become lowercase.",
    example: { text: "THIS IS LOUD. PLEASE CALM DOWN! THANK YOU." },
  },
  "tx-camel-case": {
    what: "Turns words into camelCase: spaces and symbols removed, first word lowercase and each following word starting with a capital (for example userFirstName).",
    when: "You are naming a variable or JSON field in JavaScript or a similar language.",
    example: { text: "user first name" },
  },
  "tx-pascal-case": {
    what: "Turns words into PascalCase: spaces and symbols removed and every word starting with a capital letter (for example ShoppingCartItem).",
    when: "You are naming a class, component or type in code.",
    example: { text: "shopping cart item" },
  },
  "tx-snake-case": {
    what: "Turns words into snake_case: all lowercase with underscores between words (for example created_at_date).",
    when: "You are naming a Python variable, a database column or a file in the underscore style.",
    example: { text: "Created At Date" },
  },
  "tx-kebab-case": {
    what: "Turns words into kebab-case: all lowercase with hyphens between words (for example primary-button-large).",
    when: "You are naming a CSS class, HTML id or file where hyphen-separated names are the norm.",
    example: { text: "Primary Button Large" },
  },
  "tx-constant-case": {
    what: "Turns words into CONSTANT_CASE: all uppercase with underscores between words (for example API_BASE_URL).",
    when: "You are naming a constant or an environment variable in code.",
    example: { text: "api base url" },
  },
  "tx-dot-case": {
    what: "Turns words into dot.case: all lowercase with dots between words (for example app.settings.theme).",
    when: "You are writing configuration keys or translation keys that use dots to separate words.",
    example: { text: "App Settings Theme" },
  },
  "tx-path-case": {
    what: "Turns words into path/case: all lowercase with forward slashes between words (for example docs/getting/started).",
    when: "You want to turn a phrase into a folder-style path or a simple web route.",
    example: { text: "Docs Getting Started" },
  },
  "tx-train-case": {
    what: "Turns words into Train-Case: each word starts with a capital and words are joined by hyphens (for example Content-Type).",
    when: "You are writing names in the style used by HTTP headers, such as Content-Type or X-Request-Id.",
    example: { text: "x request id" },
  },
  "tx-capitalize-words": {
    what: "Makes the first letter of every word a capital but leaves all other letters exactly as they are.",
    when: "You want to capitalize words without breaking acronyms like NASA or brand names like iPhone in the middle of a word.",
    example: { text: "welcome to the NASA open day" },
  },
  "tx-invert-case": {
    what: "Swaps the case of every letter: capitals become small letters and small letters become capitals.",
    when: "You accidentally typed with caps lock on and want to flip the text back.",
    example: { text: "hELLO wORLD" },
  },
  "tx-alternating-case": {
    what: "Rewrites text so the letters alternate between lowercase and uppercase, like aLtErNaTiNg. You choose whether to start with a small or capital letter.",
    when: "You want the playful mocking-text style often used in memes and chat.",
    example: { text: "this is fine", start: "lower" },
  },
  "tx-slugify": {
    what: "Turns a title into a slug, the short lowercase part of a web address such as my-first-post. Accents are removed and everything that is not a letter or number becomes the separator you choose.",
    when: "You are publishing a page or post and need a clean, readable address for it.",
    example: { text: "My First Post: Tips & Tricks!", sep: "-" },
  },
  "tx-word-count": {
    what: "Counts how many words are in your text (anything separated by spaces or line breaks) and gives back a single number.",
    when: "You are writing an essay, summary or post that has a word limit.",
    example: { text: "The quick brown fox jumps over the lazy dog." },
  },
  "tx-char-count": {
    what: "Counts the characters in your text, both including and excluding spaces, tabs and line breaks.",
    when: "You are filling in a field with a character limit, such as a text message, meta description or bio.",
    example: { text: "Hello there, Jane!" },
  },
  "tx-line-count": {
    what: "Counts how many lines your text has and gives back a single number.",
    when: "You want to know how many entries are in a pasted list or how long a file snippet is.",
    example: { text: "apple\nbanana\ncherry" },
  },
  "tx-sentence-count": {
    what: "Counts sentences by looking for full stops, question marks and exclamation marks. Abbreviations like \"e.g.\" may be counted as extra sentences.",
    when: "You want a rough sentence count for readability or a writing assignment.",
    example: { text: "It rained today. Did you bring an umbrella? I forgot mine!" },
  },
  "tx-paragraph-count": {
    what: "Counts paragraphs, meaning blocks of text separated by at least one empty line.",
    when: "You are checking the structure of an essay or article that must have a set number of paragraphs.",
    example: { text: "First paragraph here.\n\nSecond paragraph here.\n\nThird paragraph." },
  },
  "tx-unique-word-count": {
    what: "Counts how many different words appear in your text, treating upper and lower case as the same.",
    when: "You want to measure how varied the vocabulary of a text is.",
    example: { text: "The cat and the dog and the bird" },
  },
  "tx-word-frequency": {
    what: "Lists the most common words in your text with how many times each appears, most frequent first. Upper and lower case are treated as the same.",
    when: "You want to spot words you overuse or find the main keywords of a text.",
    example: { text: "the cat saw the dog and the dog saw the cat", n: "5" },
  },
  "tx-sort-lines-alpha": {
    what: "Sorts your lines alphabetically, A to Z or Z to A, optionally ignoring upper and lower case.",
    when: "You have a list of names, words or items and want them in alphabetical order.",
    example: { text: "banana\nApple\ncherry\ndate", dir: "ascending", ci: true },
  },
  "tx-sort-lines-numeric": {
    what: "Sorts lines by the first number found on each line, from smallest to largest or the reverse. Lines without a number go to the end.",
    when: "You have a list like scores or prices where alphabetical sorting would put 10 before 9.",
    example: { text: "Carol 42\nAlex 7\nBen 105\nDana 19", dir: "descending" },
  },
  "tx-sort-lines-length": {
    what: "Sorts lines by how many characters they have, shortest first or longest first.",
    when: "You want to find the shortest or longest entries in a list, for example titles that are too long.",
    example: { text: "strawberry\nfig\nbanana\nkiwi", dir: "shortest first" },
  },
  "tx-reverse-lines": {
    what: "Flips the order of your lines so the last line comes first. The text inside each line is not changed.",
    when: "You have a list or log in oldest-first order and want it newest-first.",
    example: { text: "Monday\nTuesday\nWednesday" },
  },
  "tx-shuffle-lines": {
    what: "Puts your lines in a random order each time you run it.",
    when: "You want to randomize a list, such as names for a draw, quiz questions or a reading order.",
    example: { text: "Alice\nBob\nCarol\nDave\nEve" },
  },
  "tx-dedupe-lines": {
    what: "Removes repeated lines so each appears only once, keeping the first one and the original order. You can treat upper and lower case as the same.",
    when: "You combined lists, such as email addresses or tags, and want to drop the duplicates.",
    example: { text: "apple\nBanana\napple\nbanana\ncherry", ci: true },
  },
  "tx-remove-empty-lines": {
    what: "Deletes every line that is empty or contains only spaces or tabs.",
    when: "You copied text from a web page or PDF and it came with lots of gaps between lines.",
    example: { text: "First\n\n   \nSecond\n\nThird" },
  },
  "tx-collapse-spaces": {
    what: "Replaces every run of spaces or tabs with one single space. Line breaks are kept.",
    when: "You have text with uneven gaps between words, for example after copying from a PDF.",
    example: { text: "Too    many\t\tspaces   here." },
  },
  "tx-collapse-blank-lines": {
    what: "Where there are two or more blank lines in a row, keeps just one blank line, so paragraphs stay separated but big gaps disappear.",
    when: "You are tidying up a document or email that has large empty gaps between paragraphs.",
    example: { text: "Paragraph one.\n\n\n\nParagraph two.\n\n\nParagraph three." },
  },
  "tx-trim-lines": {
    what: "Removes spaces and tabs at the start and/or end of each line. You choose both sides, left only or right only.",
    when: "You pasted a list with stray indentation or trailing spaces and want clean lines.",
    example: { text: "   apple   \n\tbanana\n cherry  ", side: "both" },
  },
  "tx-number-lines": {
    what: "Puts a number in front of every line, starting at a number you choose and followed by a separator like \". \". Numbers are padded with spaces so they line up.",
    when: "You are sharing code, a script or a list and want people to refer to lines by number.",
    example: { text: "Buy milk\nCall Sam\nSend report", start: "1", sep: ". " },
  },
  "tx-prefix-lines": {
    what: "Adds the same text to the start of every line, such as a bullet, a comment marker or a quote sign.",
    when: "You want to turn a plain list into bullet points or comment out several lines at once.",
    example: { text: "apple\nbanana\ncherry", prefix: "- " },
  },
  "tx-suffix-lines": {
    what: "Adds the same text to the end of every line, such as a comma, a semicolon or a line ending marker.",
    when: "You are turning a list into comma-separated values or lines of code that each need an ending.",
    example: { text: "apple\nbanana\ncherry", suffix: "," },
  },
  "tx-wrap-columns": {
    what: "Re-breaks long lines so none is longer than the number of characters you choose, moving whole words to the next line instead of cutting them.",
    when: "You are writing a plain-text email, commit message or README and want lines of a fixed width.",
    example: { text: "This is a long sentence that should be wrapped onto several shorter lines so it is easier to read.", cols: "30" },
  },
  "tx-indent": {
    what: "Adds a chosen number of spaces or tabs to the start of every non-empty line.",
    when: "You are pasting code or text inside something else and need to push it all to the right by the same amount.",
    example: { text: "line one\nline two\n\nline three", n: "4", tabs: false },
  },
  "tx-dedent": {
    what: "Removes the indentation that all non-empty lines share, so the least indented line starts at the left edge and relative indentation is kept.",
    when: "You copied a block of code from deep inside a file and want to remove the extra leading spaces.",
    example: { text: "    def hello():\n        print(\"hi\")\n    hello()" },
  },
  "tx-remove-linebreaks": {
    what: "Joins all lines into one by replacing each line break with a space, or with nothing at all.",
    when: "You copied text from a PDF or email where every line is broken early and want one flowing paragraph.",
    example: { text: "This sentence was\nbroken across\nseveral lines.", mode: "space" },
  },
  "tx-join-lines": {
    what: "Joins all lines into one line, putting a separator of your choice (for example a comma and a space) between them.",
    when: "You have a list with one item per line and need it as a single comma-separated line.",
    example: { text: "apple\nbanana\ncherry", delim: ", " },
  },
  "tx-split-lines": {
    what: "Splits text at a separator you choose, such as a comma, and puts each piece on its own line. Extra spaces around each piece can be trimmed.",
    when: "You have a comma-separated list and want one item per line to read, sort or edit it.",
    example: { text: "apple, banana, cherry, date", delim: ",", trim: true },
  },
  "tx-find-replace-plain": {
    what: "Finds every place an exact word or phrase appears and replaces it with new text. Special characters are treated literally, and you can ignore upper and lower case.",
    when: "You need to swap one name or word for another throughout a long text.",
    example: { text: "Hello Jane. Jane said hello back.", find: "Jane", repl: "Alex", ci: false },
  },
  "tx-find-replace-regex": {
    what: "Finds text using a regular expression (a pattern language for matching text, like \\d+ for any number) and replaces the matches. Flags control the search, for example g for all matches and i to ignore case, and $1 inserts a captured group.",
    when: "You need to change text that follows a pattern, such as all dates or all numbers, rather than one fixed word.",
    example: { text: "Order 123 shipped on 2026-01-05, order 456 pending.", pattern: "order (\\d+)", repl: "Order #$1", flags: "gi" },
  },
  "tx-extract-emails": {
    what: "Scans your text and lists every email address it finds, one per line, optionally without duplicates.",
    when: "You want to pull the email addresses out of a long message, export or web page.",
    example: { text: "Contact jane.doe@example.com or sales@example.com. Again: jane.doe@example.com", uniq: true },
  },
  "tx-extract-urls": {
    what: "Scans your text and lists every web link that starts with http:// or https://, one per line, optionally without duplicates.",
    when: "You want to collect all the links mentioned in a document, email or chat log.",
    example: { text: "Read https://example.com/docs and http://example.org/about today.", uniq: true },
  },
  "tx-extract-ipv4": {
    what: "Scans your text and lists every valid IPv4 address (a network address made of four numbers from 0 to 255, like 192.0.2.10), optionally without duplicates.",
    when: "You are reading a server or firewall log and want a list of the IP addresses in it.",
    example: { text: "Blocked 192.0.2.10 and 198.51.100.7, then 192.0.2.10 again. Ignore 300.1.1.1.", uniq: true },
  },
  "tx-extract-numbers": {
    what: "Pulls out every number in your text, including negatives and decimals, and lists them one per line.",
    when: "You have a sentence or report with figures mixed into the words and want just the numbers.",
    example: { text: "We sold 42 items at 19.99 each, and returns were -3 this week." },
  },
  "tx-extract-tags": {
    what: "Pulls out #hashtags, @mentions or both from your text and lists them one per line, optionally without duplicates.",
    when: "You are reviewing social media posts and want a list of the hashtags or accounts mentioned.",
    example: { text: "Great day with @jane_doe and @sam at #launch #teamwork #launch", mode: "both", uniq: true },
  },
  "tx-remove-html": {
    what: "Removes HTML tags (the markup in angle brackets like <p> or <b>) and turns common codes like &amp; and &nbsp; back into normal characters, leaving readable text.",
    when: "You copied web page source or an HTML email and just want the plain words.",
    example: { text: "<p>Fish &amp; chips <b>today</b>&nbsp;only.</p>" },
  },
  "tx-strip-accents": {
    what: "Removes accent marks from letters, so letters like e with an accent become a plain e.",
    when: "You need plain letters for a file name, search, or a system that does not handle accented characters well.",
    example: { text: "Café, naïve, Zürich" },
  },
  "tx-reverse-words": {
    what: "Reverses the order of the words in your text, so the last word comes first. All text ends up on one line with single spaces.",
    when: "You want to flip a name like \"Doe Jane\" to \"Jane Doe\" or play with word order.",
    example: { text: "one two three four" },
  },
  "tx-count-substring": {
    what: "Counts how many times a piece of text appears inside a larger text. You can ignore upper and lower case and choose whether overlapping matches count (for example \"aa\" in \"aaa\" counts twice when overlaps are on).",
    when: "You want to know how often a word, name or code appears in a document.",
    example: { text: "The cat sat. The cat ran. A dog saw the cat.", needle: "cat", ci: true, overlap: false },
  },
  "tx-truncate": {
    what: "Keeps only the first N characters of your text and adds an ending such as three dots. Text that is already short enough is returned unchanged.",
    when: "You need a short preview of a longer text for a card, list or notification.",
    example: { text: "This product description is much too long to fit in the small preview box.", n: "30", ell: "..." },
  },
  "tx-pad-center": {
    what: "Adds a fill character (a space by default) to the left, right or both sides of your text until it reaches a chosen width. Text that is already that wide is left as is.",
    when: "You are lining up text in a plain-text table, a console banner or fixed-width output.",
    example: { text: "MENU", width: "20", align: "center", ch: "*" },
  },
  "tx-repeat": {
    what: "Repeats your text a chosen number of times, with a new line, a space or nothing between the copies.",
    when: "You need filler or test data, such as the same line many times, without copying and pasting.",
    example: { text: "test row", n: "3", sep: "nl" },
  },
  "tx-remove-punctuation": {
    what: "Deletes common punctuation and symbol characters such as . , ! ? - and quotes, leaving letters, numbers and spaces.",
    when: "You are preparing text for word counting, search or comparison where punctuation gets in the way.",
    example: { text: "Hello, world! It's a (very) nice day - isn't it?" },
  },
  "tx-remove-non-ascii": {
    what: "Deletes every character outside basic ASCII (the plain English letters, digits and common symbols), such as accented letters, curly quotes and emoji.",
    when: "You are feeding text into an old system or file format that only accepts plain characters. Accented letters are deleted, not converted.",
    example: { text: "Café “quoted” price: €5 or $5" },
  },
  "tx-remove-duplicate-words": {
    what: "Removes every word that already appeared earlier in the text, keeping only its first use, and joins the result with single spaces. Punctuation stuck to a word counts as part of it.",
    when: "You have a list of keywords or tags separated by spaces and want each only once.",
    example: { text: "red blue Red green blue yellow", ci: true },
  },
  "tx-whitespace-viz": {
    what: "Shows invisible characters by replacing spaces with a dot, tabs with an arrow and line breaks with a return symbol.",
    when: "You are debugging text or code where hidden tabs, double spaces or trailing spaces are causing a problem.",
    example: { text: "name:  Jane\n\tage: 30 ", keepnl: true },
  },
  "tx-text-stats": {
    what: "Gives a full summary of your text: characters (with and without spaces), words, lines, sentences, paragraphs and an estimated reading time at the reading speed you choose.",
    when: "You are checking an article, essay or post against length targets and want every count in one place.",
    example: { text: "Reading time estimates help readers.\n\nThey are simple to compute. Most people read about 200 words per minute.", wpm: "200" },
  },
  "tx-rot-n": {
    what: "Shifts every letter forward in the alphabet by a chosen number of places (13 by default, known as ROT13), wrapping from Z back to A. Other characters stay the same.",
    when: "You want to hide spoilers or puzzle answers from a quick glance. This is not real encryption and anyone can reverse it.",
    example: { text: "Hello World", n: "13" },
  },
  "tx-ascii-banner": {
    what: "Draws your text as big block letters made from characters, five lines tall. Only letters A to Z, digits and spaces are drawn.",
    when: "You want a large text heading for a terminal, a README or a code comment.",
    example: { text: "HELLO", block: "#", space: " " },
  },
  "tx-quote-lines": {
    what: "Wraps each line in quote marks (double, single or backtick), optionally with a comma after each, or removes quotes and trailing commas from each line.",
    when: "You have a plain list and need it as quoted items for code, SQL or JSON, or you want to turn such a list back into plain lines.",
    example: { text: "apple\nbanana\ncherry", mode: "quote", q: "\"", comma: true },
  },
};
