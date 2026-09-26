// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Plain-English help for the encoding.js mini-tools. See help/README.md for the contract.
export const HELP = {
  "base64": {
    what: "Turns text into Base64 (a safe string of letters, digits, + and /) or turns Base64 back into readable text. Tick URL-safe to use - and _ instead of + and / so the result fits in web addresses.",
    when: "You found a Base64 blob in a config file, email or token and want to read it, or need to embed text somewhere that only accepts plain characters. Base64 is not encryption; anyone can decode it.",
    example: { text: "Hello, Darknode", mode: "Encode", url: false },
  },
  "base32": {
    what: "Encodes text as Base32 (only capital letters A-Z and digits 2-7) or decodes Base32 back into text.",
    when: "You are working with something that uses Base32, such as two-factor authentication secret keys, and need to read or produce it. It hides nothing; anyone can decode it.",
    example: { text: "hello world", mode: "Encode" },
  },
  "base58": {
    what: "Encodes text as Base58, the alphabet Bitcoin uses, which leaves out look-alike characters (0, O, I and l). This tool only encodes; it does not decode.",
    when: "You want to see how data looks in the Base58 style used for crypto wallet addresses and short IDs that people may need to type by hand.",
    example: { text: "hello world" },
  },
  "url-encode": {
    what: "Converts special characters such as spaces, & and = into %XX codes so text is safe inside a web address, or turns those codes back into normal text. Tick the component option to also encode characters like / ? & (for a single query value).",
    when: "You are building a link with a search term or parameter that contains spaces or symbols, or you want to read a messy URL full of % codes.",
    example: { text: "name=Jane Doe&city=New York", mode: "Encode", component: true },
  },
  "html-entities": {
    what: "Replaces characters that have special meaning in HTML (< > & \" ') with safe codes like &lt; and &amp;, or turns such codes back into the real characters.",
    when: "You want to show code or user text on a web page without the browser treating it as HTML, or you need to read text that is full of &amp; style codes.",
    example: { text: "<b>Hello</b> & \"welcome\"", mode: "Encode" },
  },
  "hex-text": {
    what: "Turns text into hexadecimal (each byte written as two characters 0-9 and a-f) or turns hex back into text. You can separate bytes with spaces or colons when encoding.",
    when: "You are looking at a packet capture, memory dump or log that shows hex and want to read it, or need the exact bytes of some text.",
    example: { text: "Hi there", mode: "Text → Hex", sep: " " },
  },
  "binary-text": {
    what: "Turns text into ones and zeros (8 bits per byte, separated by spaces) or turns such a binary string back into text.",
    when: "You are solving a puzzle or learning how computers store characters and want to convert between text and binary.",
    example: { text: "Hi", mode: "Text → Binary" },
  },
  "rot13": {
    what: "Scrambles text by shifting letters 13 places (ROT13) or shifting all visible symbols 47 places (ROT47). Running it again on the output gives back the original.",
    when: "You want to hide spoilers or puzzle answers from a casual glance, or decode a ROT13 message. It offers no real protection.",
    example: { text: "Meet me at noon", mode: "ROT13" },
  },
  "caesar": {
    what: "Shifts every letter forward (encrypt) or backward (decrypt) in the alphabet by the number you choose. Non-letters stay the same.",
    when: "You are solving a classic cipher puzzle or teaching how simple ciphers work. Easy to break, so never use it to protect real secrets.",
    example: { text: "Attack at dawn", shift: "3", mode: "Encrypt" },
  },
  "atbash": {
    what: "Swaps each letter with its mirror in the alphabet (A becomes Z, B becomes Y, and so on). Running it twice gives back the original.",
    when: "You are solving a puzzle or CTF challenge that uses the Atbash cipher. It provides no real security.",
    example: { text: "Hello World" },
  },
  "vigenere": {
    what: "Encrypts or decrypts letters using a keyword: each letter is shifted by the matching letter of the key, which repeats along the message.",
    when: "You are solving a cipher puzzle or learning classical cryptography. It can be broken, so do not use it for real secrets.",
    example: { text: "Attack at dawn", key: "LEMON", mode: "Encrypt" },
  },
  "xor-cipher": {
    what: "Combines each byte of your text with a repeating key using XOR (a simple bit flip) and shows the result as hex, or reverses hex back into text with the same key.",
    when: "You are analysing malware or a CTF challenge that hides strings with a simple XOR key. Weak as real encryption.",
    example: { text: "secret message", key: "key", mode: "Text → Hex" },
  },
  "morse": {
    what: "Converts letters, digits and common punctuation into Morse code dots and dashes (words split by /), or reads Morse back into text.",
    when: "You want to send or decode a message in Morse code, for example for radio practice or a puzzle.",
    example: { text: "SOS help", mode: "Text → Morse" },
  },
  "unicode-escape": {
    what: "Turns accented and other non-basic characters into \\uXXXX codes, or turns those codes back into the real characters. Plain letters and digits are left alone.",
    when: "You need to put special characters into source code or a config file that only accepts plain ASCII, or you want to read text full of \\u codes.",
    example: { text: "café résumé", mode: "Escape" },
  },
  "json-string-escape": {
    what: "Wraps text in quotes and escapes quotes, backslashes and line breaks so it is a valid JSON string, or turns an escaped JSON string back into plain text.",
    when: "You need to paste multi-line text or text with quotes into a JSON file or API request without breaking it.",
    example: { text: "He said \"hi\"\nand left", mode: "Escape" },
  },
  "nato": {
    what: "Spells out text using the NATO phonetic alphabet (Alfa, Bravo, Charlie...). Digits stay as digits and spaces show as |.",
    when: "You need to read a code, name or serial number clearly over the phone or radio.",
    example: { text: "AB12 CD" },
  },
  "leetspeak": {
    what: "Replaces letters with look-alike digits (a to 4, e to 3, o to 0 ...) or turns such digits back into letters.",
    when: "You want to see how people disguise words, for example to guess password variations in an authorised test, or just for fun.",
    example: { text: "password is great", mode: "To leet" },
  },
  "a1z26": {
    what: "Replaces each letter with its position in the alphabet (A=1 to Z=26), or turns a list of numbers back into letters.",
    when: "You are solving a puzzle or geocache clue where letters are written as numbers.",
    example: { text: "hello world", mode: "Text → Numbers" },
  },
  "reverse-string": {
    what: "Writes your text backwards, character by character, and handles emoji and accented letters correctly.",
    when: "You need to reverse a string for a puzzle, a test case, or to read text that was stored backwards.",
    example: { text: "Darknode tools" },
  },
  "punycode": {
    what: "Converts a domain name with non-English letters (like münchen.de) into the xn-- form that the internet actually uses, or converts xn-- names back to readable text.",
    when: "You are checking an odd-looking link for a look-alike (homograph) domain, or configuring DNS for an international domain name.",
    example: { text: "münchen.example", mode: "To ASCII" },
  },
};
