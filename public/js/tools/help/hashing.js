// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Plain-English help for the hashing.js mini-tools. See help/README.md for the contract.
export const HELP = {
  "h-md5": {
    what: "Turns any text into its MD5 hash: a 32-character fingerprint that is always the same for the same text and changes completely if one character changes.",
    when: "You need to match a file or string against an MD5 value from a download page or old system. MD5 is broken; not safe for passwords or security.",
    example: { text: "hello world" },
  },
  "h-sha1": {
    what: "Turns text into its SHA-1 hash, a 40-character fingerprint that changes completely if the input changes.",
    when: "You need to match a SHA-1 value used by an older tool, Git or a legacy system. SHA-1 is weak; do not use it for new security work or passwords.",
    example: { text: "hello world" },
  },
  "h-sha256": {
    what: "Turns text into its SHA-256 hash, a 64-character fingerprint. The same text always gives the same result and you cannot reverse it to get the text back.",
    when: "You want to verify that some text or a published value has not been changed. On its own it is not a good way to store passwords.",
    example: { text: "hello world" },
  },
  "h-sha384": {
    what: "Turns text into its SHA-384 hash, a 96-character fingerprint from the SHA-2 family.",
    when: "You need a SHA-384 value, for example to build or check a Subresource Integrity (SRI) value or match a system that requires it.",
    example: { text: "hello world" },
  },
  "h-sha512": {
    what: "Turns text into its SHA-512 hash, a 128-character fingerprint from the SHA-2 family.",
    when: "You need to match or produce a SHA-512 value that a system or document asks for. Not a password storage method on its own.",
    example: { text: "hello world" },
  },
  "h-hash-all": {
    what: "Shows the MD5, SHA-1, SHA-256 and CRC32 fingerprints of your text at once, and optionally SHA-384 and SHA-512 too.",
    when: "You have a hash from somewhere and do not know which algorithm made it, so you want to compare against several at once.",
    example: { text: "hello world", extended: true },
  },
  "h-crc32": {
    what: "Computes a CRC32 checksum: an 8-character value used to catch accidental changes, such as in ZIP files and network frames.",
    when: "You want to check a CRC32 value shown by an archive or protocol. It detects accidents only and is easy to forge, so not for security.",
    example: { text: "hello world" },
  },
  "h-crc32c": {
    what: "Computes the CRC-32C checksum, a variant of CRC32 used by storage and network systems such as iSCSI, ext4 and SCTP.",
    when: "You are debugging a disk or protocol that uses CRC-32C and need to check a value. Detects accidental errors only, not tampering.",
    example: { text: "hello world" },
  },
  "h-crc16": {
    what: "Computes a 4-character CRC-16 (CCITT-FALSE) checksum of your text.",
    when: "You are working with serial, radio or embedded devices whose messages end with a CRC-16 and want to check one. Not for security.",
    example: { text: "123456789" },
  },
  "h-crc8": {
    what: "Computes a tiny 2-character CRC-8 checksum of your text.",
    when: "You are working with sensors or small device protocols that add a one-byte CRC-8 to each message. Not for security.",
    example: { text: "123456789" },
  },
  "h-adler32": {
    what: "Computes the Adler-32 checksum, an 8-character value used inside zlib compressed data.",
    when: "You are checking or debugging zlib or PNG data that stores an Adler-32 value. Detects accidents only, not for security.",
    example: { text: "Wikipedia" },
  },
  "h-hmac": {
    what: "Combines a message with a secret key to produce an HMAC, a signature that proves the message came from someone who knows the key and was not changed.",
    when: "You are testing webhook or API signatures (for example checking an X-Signature header) and need to compute the expected value yourself.",
    example: { text: "{\"event\":\"order.paid\",\"id\":42}", key: "example-secret", algo: "SHA-256" },
  },
  "h-ntlm": {
    what: "Computes the NTLM hash of a password, which is how Windows and Active Directory store account passwords.",
    when: "You are on an authorised security test or lab and want to confirm which password produces a given Windows hash. Only use passwords you are allowed to handle.",
    example: { text: "Summer2026!" },
  },
  "h-fnv1a-32": {
    what: "Computes a fast 32-bit FNV-1a hash of text, a short 8-character number mainly used to spread items across hash tables.",
    when: "You need to match an FNV-1a value from code, such as a cache key or bucket number. Not for security.",
    example: { text: "hello world" },
  },
  "h-fnv1-32": {
    what: "Computes the original FNV-1 32-bit hash (multiply first, then mix in each byte), giving an 8-character value.",
    when: "You are matching a value produced by code that uses FNV-1 rather than FNV-1a. Not for security.",
    example: { text: "hello world" },
  },
  "h-djb2": {
    what: "Turns any text into a short number (shown as 8 hex characters) that is always the same for the same text, using the classic DJB2 formula.",
    when: "You need a quick fingerprint of a string, for example to check a value used in a program's lookup table. Not for passwords or security.",
    example: { text: "hello" },
  },
  "h-sdbm": {
    what: "Computes the SDBM string hash (used in the sdbm database and gawk), giving an 8-character value.",
    when: "You are matching or debugging a program that uses SDBM hashing for lookups. Not for security.",
    example: { text: "hello" },
  },
  "h-murmur3-32": {
    what: "Computes a 32-bit MurmurHash3 value of text, with an optional starting number called a seed that changes the result.",
    when: "You need to reproduce a MurmurHash3 value used by databases, caches or sharding code. Fast but not for security.",
    example: { text: "hello world", seed: "42" },
  },
  "h-hash-identifier": {
    what: "Looks at a hash string (its length, characters and any $ prefix) and lists the algorithms that could have produced it.",
    when: "You found a hash in a config or dump and want to know what kind it is before doing anything else. It is a best guess, not a certainty.",
    example: { hash: "5f4dcc3b5aa765d61d8327deb882cf99" },
  },
  "h-bcrypt-info": {
    what: "Splits a bcrypt password hash into its parts: the version, the cost factor (how slow it is on purpose), the salt and the hash itself.",
    when: "You are reviewing how an app stores passwords and want to see how strong its bcrypt cost setting is.",
    example: { hash: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy" },
  },
  "h-luhn": {
    what: "Checks a number with the Luhn formula (the simple check used on card numbers and IMEIs) and says whether it passes.",
    when: "You want to spot a typo in a card or ID number, or confirm a test card number is well formed. Passing does not mean the card is real or active.",
    example: { number: "4111 1111 1111 1111" },
  },
  "h-cc-brand": {
    what: "Tells you which card network (Visa, Mastercard, Amex and others) a card number belongs to from its first digits, and whether it passes the Luhn check.",
    when: "You are testing a checkout form with public test card numbers and want to confirm brand detection. Use test numbers only, never real cards.",
    example: { number: "4111111111111111" },
  },
  "h-iban-validate": {
    what: "Checks whether an international bank account number (IBAN) has a correct built-in checksum, and shows its country and check digits.",
    when: "You want to catch a typo in an IBAN before sending a payment or saving it. It cannot tell if the account actually exists.",
    example: { iban: "GB29 NWBK 6016 1331 9268 19" },
  },
  "h-isbn": {
    what: "Checks whether a 10- or 13-digit book ISBN has a correct check digit.",
    when: "You are cataloguing books or cleaning a data set and want to catch mistyped ISBNs.",
    example: { isbn: "978-3-16-148410-0" },
  },
  "h-upc-ean": {
    what: "Works out or checks the last digit (check digit) of a product barcode number such as UPC-A, EAN-8, EAN-13 or GTIN-14.",
    when: "You are creating product barcodes and need the check digit, or want to verify a code you scanned or typed.",
    example: { digits: "036000291452", mode: "Verify (includes check digit)" },
  },
  "h-imei-validate": {
    what: "Checks a 15-digit phone IMEI (the device serial number) with the Luhn formula and splits it into device-type code, serial and check digit.",
    when: "You want to catch a typo in an IMEI before recording or reporting a device. It cannot tell you if a phone is stolen or blocked.",
    example: { imei: "490154203237518" },
  },
  "h-vin-check": {
    what: "Checks the 9th character of a 17-character vehicle identification number (VIN), which is a check digit, and shows the manufacturer code.",
    when: "You are buying a car or entering a VIN and want to catch a typo. The check digit rule is mainly used for North American vehicles.",
    example: { vin: "1M8GDM9AXKP042788" },
  },
  "h-verhoeff": {
    what: "Works out or checks a Verhoeff check digit, a stronger check that catches any single wrong digit and swapped neighbouring digits (used by India's Aadhaar).",
    when: "You are generating ID numbers that need a Verhoeff check digit, or verifying one someone typed.",
    example: { number: "236", mode: "Compute (payload only)" },
  },
  "h-password-entropy": {
    what: "Estimates how hard a password is to guess, in bits, based on its length and the kinds of characters used, plus a rough offline cracking time.",
    when: "You want a quick sense of password strength. It is a simple estimate and cannot tell that common words or patterns like Password1! are weak.",
    example: { password: "correct-Horse-battery-9" },
  },
  "h-hibp-prefix": {
    what: "Hashes a password with SHA-1 and splits the result into a 5-character prefix you can send to Have I Been Pwned and a suffix you keep to match locally. It makes no network requests itself.",
    when: "You want to check whether a password appears in known data breaches without ever sending the password or its full hash anywhere.",
    example: { password: "password123" },
  },
  "h-hash-compare": {
    what: "Compares two hash values (ignoring case and spaces) and tells you whether they match exactly.",
    when: "You downloaded a file and want to check its checksum against the one published on the website without comparing long strings by eye.",
    example: { a: "5EB63BBBE01EEED093CB22BB8F5ACDC3", b: "5eb63bbbe01eeed093cb22bb8f5acdc3" },
  },
  "h-uuid-validate": {
    what: "Checks that a UUID (a standard unique ID like 550e8400-e29b-...) is well formed and tells you its version (for example random or time-based) and variant.",
    when: "You are debugging an API or database and want to know what kind of ID you are looking at.",
    example: { uuid: "550e8400-e29b-41d4-a716-446655440000" },
  },
  "h-ulid-decode": {
    what: "Reads a ULID (a sortable 26-character ID) and shows the date and time hidden in its first 10 characters plus its random part.",
    when: "You want to know when a record with a ULID was created, for example while investigating logs or database rows.",
    example: { ulid: "01ARZ3NDEKTSV4RRFFQ69G5FAV" },
  },
  "h-simhash": {
    what: "Makes a SimHash fingerprint of text: similar texts give fingerprints that differ in only a few bits, unlike normal hashes.",
    when: "You want to detect near-duplicate documents, spam or copied content by comparing fingerprints of two texts.",
    example: { text: "The quick brown fox jumps over the lazy dog" },
  },
};
