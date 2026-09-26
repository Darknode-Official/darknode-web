// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Plain-English help for the websec.js mini-tools. See help/README.md for the contract.
// These are for security testing of systems you are authorised to test.
export const HELP = {
  "w-jwt-decode": {
    what: "Reads a JWT (a JSON Web Token, the signed login token many web apps put in a header or cookie) and shows the readable header and data inside it. It does not check the signature.",
    when: "You have a login token and want to see what it claims (who the user is, when it expires). Anyone can read a JWT, so never put secrets in one.",
    example: { token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" },
  },
  "w-jwt-none": {
    what: "Rebuilds a JWT so its algorithm says none and its signature is removed, to see if a server wrongly accepts unsigned tokens.",
    when: "You are testing a web app you are authorised to test and want to check for the classic alg:none signature-bypass flaw. Only use it against systems you own or have permission to test.",
    example: { token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", variant: "none" },
  },
  "w-jwt-hs256-verify": {
    what: "Checks whether a JWT was signed with the secret you provide, using the HS256 method. It tells you if the secret matches.",
    when: "You are auditing an app you are authorised to test and want to confirm whether a weak or guessed signing secret is in use. Authorised testing only.",
    example: { token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", secret: "your-256-bit-secret" },
  },
  "w-jwt-hs256-sign": {
    what: "Builds a valid JWT from a header, a data (payload) section and a secret key, signing it with HS256. You get a complete token back.",
    when: "You are testing how an app handles tokens and need to create your own valid token for a system you control or are authorised to test.",
    example: { header: '{"alg":"HS256","typ":"JWT"}', payload: '{"sub":"1234567890","name":"tester","iat":1700000000}', secret: "your-256-bit-secret" },
  },
  "w-csp-builder": {
    what: "Builds a Content-Security-Policy header (a browser rule that limits where a page may load scripts, images and other content from) out of the values you fill in per category.",
    when: "You are hardening a website and want a ready-to-paste CSP header that restricts content to trusted sources.",
    example: { defaultSrc: "'self'", scriptSrc: "'self'", styleSrc: "'self'", imgSrc: "'self' data:", frameAncestors: "'none'", upgradeInsecure: true },
  },
  "w-csp-evaluator": {
    what: "Reads a Content-Security-Policy header you paste in and flags weak settings that could let attackers run scripts, such as unsafe-inline or a wildcard *.",
    when: "You want to review an existing site's CSP and find gaps before an attacker does.",
    example: { policy: "default-src 'self'; script-src 'self' 'unsafe-inline'" },
  },
  "w-security-headers": {
    what: "Produces a recommended starter set of HTTP security response headers (such as HSTS, nosniff and X-Frame-Options) to add to a web server.",
    when: "You are setting up or hardening a website and want sensible security headers to copy in.",
    example: { hsts: true, hstsMaxAge: "31536000", frameOptions: "DENY", referrer: "strict-origin-when-cross-origin" },
  },
  "w-cors-preflight": {
    what: "Explains, for a cross-site browser request, exactly which CORS response headers a server must send back for that request to be allowed. CORS is the rule that controls which other websites may call an API.",
    when: "You are debugging why a cross-origin request is blocked, or checking an API for an over-permissive CORS setup.",
    example: { origin: "https://app.example.com", method: "PUT", headers: "Content-Type, X-Auth-Token", credentials: true },
  },
  "w-set-cookie-analyzer": {
    what: "Reads a Set-Cookie header and reports which protective flags (Secure, HttpOnly, SameSite) are missing and why that matters.",
    when: "You are reviewing how an app sets its session cookie and want to catch missing protections that could expose it to theft or CSRF.",
    example: { cookie: "session=abc123; Path=/" },
  },
  "w-csp-nonce": {
    what: "Generates a random nonce (a one-time random value) you can put in a CSP header and on a script tag so only your own inline scripts are allowed to run.",
    when: "You use a strict Content-Security-Policy and need a fresh nonce for an inline script or style.",
    example: { bytes: "16" },
  },
  "w-revshell": {
    what: "Builds a one-line reverse-shell command for the language you pick, filled in with your listener address and port. A reverse shell makes a target machine connect back to your machine so you can run commands on it.",
    when: "You are on an authorised penetration test and need a quick reverse-shell command for your listener. Only for systems you have explicit permission to test.",
    example: { lang: "bash", lhost: "192.0.2.10", lport: "4444" },
  },
  "w-bindshell": {
    what: "Builds a one-line bind-shell command that makes the target open a port and wait for you to connect and run commands.",
    when: "You are on an authorised penetration test and a reverse connection is blocked, so you want the target to listen instead. Authorised testing only.",
    example: { lang: "bash", port: "4444" },
  },
  "w-msfvenom": {
    what: "Assembles the correct msfvenom command line (Metasploit's payload-building tool) from the payload type, your address and port, and output format you choose.",
    when: "You are on an authorised engagement and want the right msfvenom command without memorising its flags. Authorised testing only.",
    example: { payload: "windows/x64/meterpreter/reverse_tcp", lhost: "192.0.2.10", lport: "4444", format: "exe", out: "payload.exe" },
  },
  "w-hashcat-mask": {
    what: "Builds a hashcat mask command (hashcat is a password-recovery tool) from the character types and length you select, describing which passwords to try.",
    when: "You are recovering passwords in an authorised test and want a brute-force mask for a known password pattern. Authorised testing only.",
    example: { lower: true, upper: true, digit: true, special: false, length: "8" },
  },
  "w-hashcat-modes": {
    what: "A searchable list of hashcat mode numbers and the hash type each one cracks. Type a keyword to filter it.",
    when: "You have a hash to recover and need the right hashcat -m mode number for it.",
    example: { q: "ntlm" },
  },
  "w-john-rules": {
    what: "A quick reference to John the Ripper's word-mangling rule letters (John is a password-cracking tool) and what each rule does. Type to filter.",
    when: "You are writing a John the Ripper rule to transform a wordlist and need to look up the syntax.",
    example: { q: "capitalize" },
  },
  "w-wordlist-mangler": {
    what: "Takes base words and expands them into common variants (capitalised, leetspeak, with digits or years added) to build a password guessing list.",
    when: "You are on an authorised password test and want a targeted wordlist from names or company words. Authorised testing only.",
    example: { words: "summer\ncompany", capitalize: true, leet: true, digits: true, years: false },
  },
  "w-sqli-cheatsheet": {
    what: "Shows example SQL injection test strings for the category you pick. SQL injection is tricking a database query by putting SQL code into an input field.",
    when: "You are testing a web form or parameter you are authorised to test and want reference payloads for a chosen SQLi technique. Authorised testing only.",
    example: { category: "Auth bypass" },
  },
  "w-xss-payload-gen": {
    what: "Generates a sample XSS proof-of-concept payload suited to where it will land on the page. XSS (cross-site scripting) is getting your script to run in someone else's browser via a vulnerable site.",
    when: "You are testing a site you are authorised to test and want a harmless marker payload to confirm an XSS flaw. Authorised testing only.",
    example: { context: "HTML body", marker: "XSS" },
  },
  "w-xss-context-encoder": {
    what: "Takes a payload and encodes it for a specific spot on a page (HTML, a JavaScript string, a URL, or Base64) so it survives being placed there.",
    when: "You are crafting an XSS test and your payload needs the right encoding for where it is injected. Authorised testing only.",
    example: { payload: "<script>alert(1)</script>", context: "HTML entities" },
  },
  "w-ssti-cheatsheet": {
    what: "Shows detection and exploitation strings for Server-Side Template Injection in the template engine you pick. SSTI is injecting template code that the server then runs.",
    when: "You suspect a page reflects your input through a template engine and want reference payloads. Authorised testing only.",
    example: { engine: "Jinja2 (Python)" },
  },
  "w-lfi-payloads": {
    what: "Produces a list of Local File Inclusion test strings (PHP wrappers and ../ path-traversal variants) aimed at a target file. LFI is tricking a page into reading files it should not.",
    when: "You are testing an endpoint that includes or reads a file based on user input. Authorised testing only.",
    example: { target: "/etc/passwd", maxDepth: "6" },
  },
  "w-path-traversal-encoder": {
    what: "Builds ../ sequences to reach a file and gives URL-encoded, double-encoded and overlong variants used to slip past filters. Path traversal is escaping a folder to reach other files.",
    when: "You are testing a file parameter and want traversal strings in several encodings to try against input filters. Authorised testing only.",
    example: { depth: "4", target: "etc/passwd" },
  },
  "w-xxe-builder": {
    what: "Builds an XXE (XML External Entity) payload: XML that tells a weak parser to read a local file and include its contents in the response.",
    when: "You are testing an endpoint that accepts XML and want to check whether its parser will read local files. Authorised testing only.",
    example: { file: "/etc/passwd", elementName: "foo" },
  },
  "w-ssrf-targets": {
    what: "Lists internal and cloud-metadata addresses (plus encodings) to try when testing for SSRF. SSRF (Server-Side Request Forgery) is making a server fetch a URL of your choosing.",
    when: "You found a feature that fetches a URL you supply and want a checklist of internal targets to probe. Authorised testing only.",
    example: { custom: "http://169.254.169.254/latest/meta-data/" },
  },
  "w-cmdi-cheatsheet": {
    what: "Shows the shell characters (like ; | && ) used to tack an extra OS command onto vulnerable input, with notes on when each works. This tests for command injection.",
    when: "You are testing an input that might be passed to a system shell and want reference separators. Authorised testing only.",
    example: { cmd: "id" },
  },
  "w-crlf-injection": {
    what: "Builds a CRLF-injection string (using encoded line breaks) that tries to insert a new HTTP response header. CRLF injection can split or poison HTTP responses.",
    when: "You are testing a parameter that is reflected into a response header or redirect. Authorised testing only.",
    example: { header: "Set-Cookie", value: "admin=true" },
  },
  "w-open-redirect": {
    what: "Lists tricky URL values that try to bypass a site's redirect allowlist and send users to another domain. This tests for open-redirect flaws.",
    when: "You are testing a redirect or return-URL parameter and want bypass strings to check its filtering. Authorised testing only.",
    example: { target: "attacker.example" },
  },
  "w-csrf-poc": {
    what: "Generates a small HTML form that submits itself to a target action, to demonstrate a CSRF flaw. CSRF tricks a logged-in user's browser into performing an action without their intent.",
    when: "You found a state-changing request with no CSRF protection and need a proof-of-concept page to show the impact. Authorised testing only.",
    example: { action: "https://app.example.com/account/email", method: "POST", fields: "email=attacker@evil.example", autoSubmit: true },
  },
  "w-clickjacking-poc": {
    what: "Generates an HTML page that loads a target site inside a faint invisible frame, to show it can be framed. Clickjacking tricks a user into clicking a hidden page.",
    when: "You suspect a site is missing frame protections (X-Frame-Options or frame-ancestors) and want a proof-of-concept. Authorised testing only.",
    example: { url: "https://app.example.com/settings", opacity: "50" },
  },
  "w-htaccess-basicauth": {
    what: "Generates the Apache .htaccess and .htpasswd lines needed to put a simple username/password prompt in front of a folder.",
    when: "You want to quickly password-protect a staging or test directory on an Apache server.",
    example: { realm: "Restricted Area", user: "tester", passwordHashHint: "" },
  },
  "w-spf-builder": {
    what: "Builds an SPF DNS record (a TXT line that lists which servers may send email for your domain) from the senders you allow.",
    when: "You are setting up email for a domain and want an SPF record to reduce spoofing of your address.",
    example: { includes: "_spf.google.com", ip4: "192.0.2.20", a: false, mx: true, all: "-all" },
  },
  "w-dkim-explainer": {
    what: "Explains the parts of a DKIM DNS record and how DKIM proves an email really came from your domain and was not altered.",
    when: "You are auditing or setting up a domain's email authentication and want to understand its DKIM record.",
    example: { selector: "default", domain: "example.com" },
  },
  "w-dmarc-builder": {
    what: "Builds a DMARC DNS record that tells receivers what to do with email that fails your SPF/DKIM checks and where to send reports.",
    when: "You have SPF and DKIM set up and want to add a DMARC policy to protect your domain from spoofing.",
    example: { policy: "quarantine", subPolicy: "", rua: "mailto:dmarc@example.com", pct: "100" },
  },
  "w-google-dork": {
    what: "Builds an advanced Google search string (a dork) from operators like site:, inurl: and filetype: to find specific pages or files.",
    when: "You are doing authorised recon and want to find exposed files or pages on a domain you are allowed to investigate.",
    example: { site: "example.com", inurl: "admin", intitle: "", filetype: "pdf", ext: "", extra: "" },
  },
  "w-cvss-calc": {
    what: "Reads a CVSS v3.1 vector string (the standard shorthand for how severe a vulnerability is) and works out its numeric base score and severity rating.",
    when: "You have a CVSS vector from an advisory or scan and want its 0-10 score and Low/Medium/High/Critical label.",
    example: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
  },
  "w-cvss-vector-builder": {
    what: "Builds a CVSS v3.1 vector string and score by picking each severity metric from dropdowns (attack vector, complexity, impact and so on).",
    when: "You are writing up a vulnerability and need to produce its CVSS vector and base score.",
    example: { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" },
  },
  "w-sri-hash": {
    what: "Computes a SHA-384 hash of the content you paste and formats it as an integrity attribute. SRI (Subresource Integrity) lets a browser refuse a script or stylesheet if it has been tampered with.",
    when: "You load a script or stylesheet from a CDN and want an integrity value so the browser checks it has not been changed.",
    example: { content: "console.log('hello world');" },
  },
  "w-password-policy-check": {
    what: "Checks a password against the length and character rules you set (uppercase, digits, symbols and so on) and reports which rules it meets.",
    when: "You are reviewing or demonstrating a password policy and want to see whether a sample password passes it.",
    example: { password: "Sup3r-Secret!23", minLen: "12", reqUpper: true, reqLower: true, reqDigit: true, reqSpecial: true, noSpaces: false },
  },
  "w-security-txt": {
    what: "Generates a security.txt file (the standard file that tells researchers how to report a vulnerability) for your domain.",
    when: "You want to publish clear contact and disclosure details so people can report security issues to you responsibly.",
    example: { contact: "mailto:security@example.com", expires: "2027-01-01", policy: "https://example.com/security-policy", acknowledgments: "", preferredLang: "en" },
  },
  "w-tls-cipher-decoder": {
    what: "Takes an official TLS cipher-suite name and breaks it into plain parts: how keys are exchanged, how the server is authenticated, how data is encrypted and how integrity is checked.",
    when: "You see a cipher suite name in a scan or config and want to understand what protection it actually provides.",
    example: { name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" },
  },
  "w-nosqli-cheatsheet": {
    what: "Shows NoSQL injection test payloads (mainly for MongoDB) for the category you pick. NoSQL injection abuses query operators to bypass logic like a login check.",
    when: "You are testing an app backed by a NoSQL database and want reference payloads for auth bypass or data extraction. Authorised testing only.",
    example: { category: "Auth bypass (JSON body)" },
  },
  "w-smuggling-cheatsheet": {
    what: "Gives raw HTTP request templates for request smuggling (CL.TE, TE.CL and TE.TE), which abuse disagreements between a front-end and back-end server about where a request ends.",
    when: "You are testing a site behind a proxy or load balancer for HTTP request smuggling. Authorised testing only.",
    example: { variant: "CL.TE", host: "app.example.com" },
  },
  "w-graphql-introspection": {
    what: "Builds a GraphQL introspection query, which asks a GraphQL API to describe its own schema (all its types and fields).",
    when: "You are testing or exploring a GraphQL API you are authorised to access and want to list everything it exposes.",
    example: { depth: "Full schema (types+fields)" },
  },
};
