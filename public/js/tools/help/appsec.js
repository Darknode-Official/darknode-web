// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Plain-English help for the appsec.js mini-tools. See help/README.md for the contract.
// Offensive-testing tools are for systems you are authorised to test.
export const HELP = {
  "sx-password-strength": {
    what: "Estimates how hard a password is to guess, giving an entropy score in bits, a rating, and a rough time to crack it offline.",
    when: "You want a quick sense of how strong a password is. It is an estimate and cannot tell that common words or patterns are weak.",
    example: { pw: "correct-horse-Battery-9" },
  },
  "sx-password-entropy": {
    what: "Works out the entropy (guessing difficulty) in bits for a password of a given length drawn from a character set of a given size. You choose the length and set size, not a real password.",
    when: "You are comparing password policies and want to see how length and allowed characters change strength.",
    example: { len: "16", charset: "62" },
  },
  "sx-password-generator": {
    what: "Creates a strong random password of the length you pick, using the character types you tick (lowercase, uppercase, digits, symbols).",
    when: "You need a fresh, hard-to-guess password for a new account or service.",
    example: { len: "20", lower: true, upper: true, digits: true, symbols: true },
  },
  "sx-passphrase": {
    what: "Builds a memorable password from several random words joined by a separator, with options to capitalise words and add a number.",
    when: "You want a password that is easy to remember and type but still hard to guess.",
    example: { n: "4", sep: "-", cap: false, num: true },
  },
  "sx-pin-generator": {
    what: "Generates one or more random numeric PINs of the length you choose.",
    when: "You need a random PIN for a device, card or lock and do not want an obvious sequence.",
    example: { len: "6", count: "1" },
  },
  "sx-jwt-none": {
    what: "Builds an unsigned JWT (algorithm set to none) from a header and payload, to test whether a server wrongly accepts tokens with no signature.",
    when: "You are testing a web app you are authorised to test for the alg:none signature-bypass flaw. Authorised testing only.",
    example: { header: '{"alg":"none","typ":"JWT"}', payload: '{"sub":"admin","role":"admin"}' },
  },
  "sx-jwt-hs256-sign": {
    what: "Builds a valid JWT from a payload and a secret, signing it with the HS256 method. You get a complete token back.",
    when: "You are testing token handling on a system you control or are authorised to test and need to make your own valid token.",
    example: { payload: '{"sub":"1234567890","name":"tester","iat":1700000000}', secret: "your-256-bit-secret" },
  },
  "sx-htpasswd": {
    what: "Builds an Apache htpasswd line (a username and hashed password) used to password-protect a folder, using SHA-1 or plaintext.",
    when: "You are setting up basic password protection for a folder on an Apache server. SHA-1 htpasswd is weak; use it only for low-stakes staging.",
    example: { user: "tester", pass: "s3cret-pass", mode: "sha" },
  },
  "sx-bcrypt-cost": {
    what: "Explains what a bcrypt cost factor means: how many rounds it runs and roughly how many hashes per second an attacker could try. bcrypt is a deliberately slow password-hashing method.",
    when: "You are choosing a bcrypt cost for storing passwords and want to understand the trade-off between speed and safety.",
    example: { cost: "12" },
  },
  "sx-ipv4-to-int": {
    what: "Converts a normal IPv4 address (like 192.0.2.10) into its single 32-bit number, in both decimal and hexadecimal.",
    when: "You need an IP address as a plain number, for example to store it in a database or compare ranges.",
    example: { ip: "192.0.2.10" },
  },
  "sx-int-to-ipv4": {
    what: "Converts a 32-bit number (decimal or 0x hex) back into a normal dotted IPv4 address.",
    when: "You have an IP stored as a number and want to read it as a normal address.",
    example: { n: "3221225994" },
  },
  "sx-ip-in-cidr": {
    what: "Checks whether an IPv4 address falls inside a given CIDR network block and tells you yes or no.",
    when: "You want to know if an address is part of a subnet, for example when reviewing a firewall or allowlist rule.",
    example: { ip: "192.0.2.10", cidr: "192.0.2.0/24" },
  },
  "sx-mask-prefix": {
    what: "Converts between a dotted subnet mask (like 255.255.255.0) and a prefix length (like /24), whichever you give it.",
    when: "You are configuring a network and need the mask in the other notation.",
    example: { in: "255.255.255.0" },
  },
  "sx-wildcard-mask": {
    what: "Turns a prefix or subnet mask into its wildcard (inverse) mask, the form used in Cisco access-control lists.",
    when: "You are writing router or firewall ACL rules that need a wildcard mask instead of a normal netmask.",
    example: { in: "24" },
  },
  "sx-ipv6": {
    what: "Expands an IPv6 address to its full long form, or compresses it to the short form, whichever you choose.",
    when: "You are comparing or documenting IPv6 addresses and need them in a consistent form.",
    example: { addr: "2001:db8::1", mode: "Expand" },
  },
  "sx-hash-string": {
    what: "Turns text into its hash fingerprint using the algorithm you pick (MD5, SHA-1, SHA-256 or SHA-512).",
    when: "You need a checksum of some text or want to reproduce a known hash. MD5 and SHA-1 are weak; not for storing passwords.",
    example: { text: "hello world", algo: "SHA-256" },
  },
  "sx-hmac": {
    what: "Combines a message with a secret key to make an HMAC, a signature proving the message came from someone who knows the key and was not changed.",
    when: "You are testing or building signed requests (such as a webhook signature) and need to compute the expected value.",
    example: { algo: "SHA-256", key: "example-secret", msg: "payload to sign" },
  },
  "sx-default-creds": {
    what: "Searches a built-in list of well-known factory default usernames and passwords for devices and software.",
    when: "You are auditing your own or an authorised client's devices to check whether default logins were left unchanged. Authorised use only.",
    example: { q: "router" },
  },
  "sx-headers-checklist": {
    what: "You paste a server's raw HTTP response headers and it lists which recommended security headers are missing.",
    when: "You want to quickly see what security headers a site is not sending.",
    example: { hdr: "HTTP/1.1 200 OK\nContent-Type: text/html\nServer: nginx" },
  },
  "sx-tls-versions": {
    what: "Explains the status of each SSL/TLS protocol version (the encryption used by HTTPS) and advises which to keep on or turn off.",
    when: "You are configuring a web server's TLS and want to know which versions are safe to allow.",
    example: { ver: "All" },
  },
  "sx-cipher-suite": {
    what: "Takes a TLS cipher-suite name and breaks it into plain parts: how keys are exchanged, how the server is authenticated, how data is encrypted and how integrity is checked.",
    when: "You see a cipher suite in a scan or config and want to understand the protection it provides.",
    example: { cs: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" },
  },
  "sx-hsts-parser": {
    what: "Reads a Strict-Transport-Security header (which forces browsers to use HTTPS) and reports its settings and any weak ones, such as a short lifetime.",
    when: "You are reviewing a site's HSTS header and want to check the max-age and subdomain settings.",
    example: { h: "max-age=31536000; includeSubDomains; preload" },
  },
  "sx-xss-cheatsheet": {
    what: "Shows XSS test payloads for the page context you pick. XSS (cross-site scripting) is getting your script to run in another user's browser through a vulnerable site.",
    when: "You are testing a site you are authorised to test and want reference payloads for a given injection spot. Authorised testing only.",
    example: { ctx: "HTML body" },
  },
  "sx-double-url-encode": {
    what: "URL-encodes text twice, so a % becomes %25 and so on. This is used to slip payloads past filters that decode once.",
    when: "You are testing whether a firewall or filter can be bypassed with double-encoding. Authorised testing only.",
    example: { text: "../etc/passwd" },
  },
  "sx-unicode-bypass": {
    what: "Re-encodes text using Unicode tricks (JS \\u escapes, HTML entities, percent-UTF-8, or full-width look-alike letters) to test filters that miss these forms.",
    when: "You are testing whether an input filter can be evaded with alternative character encodings. Authorised testing only.",
    example: { text: "<script>", mode: "ju" },
  },
  "sx-hex-escape": {
    what: "Rewrites each byte of text as a hex escape in the format you pick (\\xNN, \\u00NN, 0xNN or percent form).",
    when: "You need a payload as hex escapes for a script, shellcode string or filter-bypass test.",
    example: { text: "alert(1)", fmt: "x" },
  },
  "sx-xss-mutator": {
    what: "Applies a chosen evasion trick (mixed case, inserted comments, null byte, entities or removed spaces) to an XSS payload to test how a filter reacts.",
    when: "You are testing an XSS filter and want to see whether a mutated version of a payload gets through. Authorised testing only.",
    example: { text: "<script>alert(1)</script>", trick: "case" },
  },
  "sx-ua-list": {
    what: "Lists common User-Agent strings (the text a browser or tool sends to identify itself) for browsers, scanners or bots.",
    when: "You need a realistic User-Agent string for testing how a site responds to different clients.",
    example: { kind: "Browsers" },
  },
  "sx-path-wordlist": {
    what: "Lists commonly sensitive or hidden web paths (admin pages, config files, backups, API endpoints) for the group you pick, to use in content discovery.",
    when: "You are doing authorised content discovery on a target and want a starter list of paths to check. Authorised testing only.",
    example: { grp: "Config/Secrets" },
  },
  "sx-totp-secret": {
    what: "Generates a random Base32 secret for TOTP, the six-digit codes from apps like Google Authenticator. You pick how many bytes of randomness.",
    when: "You are setting up two-factor authentication and need a fresh shared secret.",
    example: { bytes: "20" },
  },
  "sx-totp-code": {
    what: "Computes the current six or eight digit TOTP code from a Base32 secret, the same code an authenticator app would show. You can also give a specific time.",
    when: "You are testing a two-factor login or building one and need to check the code for a known secret.",
    example: { secret: "JBSWY3DPEHPK3PXP", digits: "6", period: "30", time: "" },
  },
  "sx-otpauth-uri": {
    what: "Builds an otpauth:// link (which an authenticator app can turn into a QR code) from an issuer, account name and TOTP secret.",
    when: "You are adding two-factor authentication to an app and need the setup link or QR code for the user.",
    example: { issuer: "Example App", account: "user@example.com", secret: "JBSWY3DPEHPK3PXP", digits: "6", period: "30" },
  },
  "sx-api-key": {
    what: "Generates a random API key, with an optional prefix, in URL-safe Base64 or hex.",
    when: "You need a fresh secret key for an API or service.",
    example: { prefix: "sk_test", bytes: "24", fmt: "b64url" },
  },
  "sx-uuid-token": {
    what: "Generates one or more random version-4 UUIDs (standard unique IDs). Options let you uppercase them or wrap them in braces.",
    when: "You need unique IDs for records, requests or test data.",
    example: { count: "1", upper: false, braces: false },
  },
  "sx-nonce": {
    what: "Generates cryptographically random bytes (4 to 128) in the encoding you pick: a nonce for a CSP header or IV, a password salt, an anti-CSRF token or an API secret.",
    when: "You need a fresh random value for a security header, password hashing, a form token or an app secret.",
    example: { bytes: "16", fmt: "b64" },
  },
  "sx-phonetic": {
    what: "Spells out text using the NATO phonetic alphabet (Alfa, Bravo, Charlie...) so a password or code can be read aloud without mistakes.",
    when: "You need to read a password, key or token to someone over the phone clearly.",
    example: { text: "Ab3-Xy" },
  },
  "sx-entropy-bytes": {
    what: "Measures the randomness of data in bits per byte (Shannon entropy), reading it as text or hex. High values suggest random or encrypted data.",
    when: "You want to judge whether a key, token or blob looks truly random or has obvious structure.",
    example: { data: "9f8a7b6c5d4e3f2a1b0c", mode: "Hex" },
  },
  "sx-shannon": {
    what: "Computes the Shannon entropy of a string (how unpredictable its characters are) and shows how often each character appears.",
    when: "You want to gauge how random or repetitive a string is, for example a password or token.",
    example: { text: "correcthorsebatterystaple" },
  },
  "sx-b64-cred": {
    what: "Builds the Base64 of a username:password pair (as used by HTTP Basic authentication), or decodes such a Base64 value (or a whole Authorization: Basic header) back into the username and password.",
    when: "You are testing HTTP Basic auth and need the encoded credential string, or want to read one you found.",
    example: { user: "tester", pass: "s3cret", mode: "Encode user:pass", blob: "" },
  },
  "sx-email-obfuscate": {
    what: "Hides an email address from automated scrapers using HTML entities, [at]/[dot] text, hex entities or a rotation, while people can still read it.",
    when: "You want to publish an email address on a web page without spam bots harvesting it easily.",
    example: { email: "hello@example.com", mode: "at" },
  },
  "sx-basic-auth-header": {
    what: "Builds the Authorization: Basic header value from a username and password, ready to paste into a request.",
    when: "You are testing an API that uses HTTP Basic auth and need the header for a tool like curl.",
    example: { user: "tester", pass: "s3cret" },
  },
  "sx-luhn": {
    what: "Checks whether a number passes the Luhn checksum (used on card and ID numbers) or works out the correct final check digit for one.",
    when: "You want to catch a typo in a card or ID number, or make valid-looking test numbers. Passing does not mean a real, active card.",
    example: { num: "4111111111111111", mode: "Validate" },
  },
};
