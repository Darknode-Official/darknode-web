// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Plain-English help for the webhttp.js mini-tools. See help/README.md for the contract.
export const HELP = {
  "wb-status-explain": {
    what: "Type an HTTP status code (the three-digit number a web server sends back, like 404) and get its official name, its group (such as Client Error) and a short explanation.",
    when: "You saw a number like 403 or 502 in your browser, logs or an API response and want to know what it means.",
    example: { code: "404" },
  },
  "wb-status-by-class": {
    what: "Pick a group of HTTP status codes (1xx information, 2xx success, 3xx redirect, 4xx client error, 5xx server error) and get a list of every standard code in it with its name.",
    when: "You are learning HTTP or designing an API and want to see all the codes in one group at a glance.",
    example: { cls: "4xx" },
  },
  "wb-methods-ref": {
    what: "Shows the HTTP methods (the verb in a web request, such as GET or POST) with a short description and whether each one is safe (only reads data), idempotent (repeating it has the same effect) or usually carries a body.",
    when: "You are building or calling an API and need to choose the right method for an action.",
    example: { m: "PUT" },
  },
  "wb-req-headers": {
    what: "Type the name of a common request header (an extra line of information a browser sends with a request, like Authorization) and get a short explanation. Leave it blank to list all the headers it knows.",
    when: "You see an unfamiliar header in your browser developer tools or API docs and want a quick meaning. Only common headers are covered.",
    example: { name: "Authorization" },
  },
  "wb-res-headers": {
    what: "Type the name of a common response header (an extra line of information a server sends back, like ETag) and get a short explanation. Leave it blank to list all the headers it knows.",
    when: "You are inspecting a server response and want to know what a header does. Only common headers are covered.",
    example: { name: "ETag" },
  },
  "wb-mime-by-ext": {
    what: "Type a file extension or file name and get its MIME type, the label that tells browsers what kind of file it is (for example image/png).",
    when: "You are setting up a server, upload form or Content-Type header and need the right type for a file.",
    example: { ext: "report.pdf" },
  },
  "wb-ext-by-mime": {
    what: "Type a MIME type (the label for a kind of file, like image/jpeg) and get the file extensions that usually go with it.",
    when: "You received a file or response with a Content-Type and want to know what extension to save it with.",
    example: { mime: "image/jpeg" },
  },
  "wb-ua-parser": {
    what: "Paste a User-Agent string (the text a browser sends to identify itself) and get a best guess of the browser, operating system, device type and whether it looks like a bot.",
    when: "You are reading server logs or analytics and want to know what kind of visitor a request came from. It is a simple guess, not a full database.",
    example: { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" },
  },
  "wb-qs-parse": {
    what: "Paste a query string (the part of a web address after the ?, like a=1&b=2) and get each parameter as a readable name = value line, with codes like %20 decoded.",
    when: "You are debugging a long link full of parameters and want to see clearly what each one says.",
    example: { qs: "?q=blue%20shoes&page=2&sort=price" },
  },
  "wb-qs-build": {
    what: "Write one name=value pair per line and get a single encoded query string (the part of a web address after the ?), with spaces and special characters made safe.",
    when: "You are building a link or API call with several parameters and do not want to encode them by hand.",
    example: { lines: "q=blue shoes\npage=2\nsort=price & rating" },
  },
  "wb-url-parse": {
    what: "Paste a web address and see it split into its parts: protocol, host, port, path, query, hash and origin.",
    when: "You are debugging a link or redirect and want to see exactly which part is which.",
    example: { url: "https://shop.example.com:8080/products/shoes?color=blue#reviews" },
  },
  "wb-url-build": {
    what: "Fill in the parts of a web address (protocol, host, optional port, path, query and hash) and get the full, correctly formed URL.",
    when: "You are putting together a link or API endpoint from separate pieces and want to avoid missing slashes or question marks.",
    example: { proto: "https", host: "api.example.com", port: "8443", path: "v1/items", query: "limit=10&page=2", hash: "top" },
  },
  "wb-url-set-param": {
    what: "Give a web address, a parameter name and a value, and get the address back with that parameter added, or replaced if it was already there.",
    when: "You want to change one setting in a link, such as the page number, without editing the rest by hand.",
    example: { url: "https://example.com/search?q=shoes&page=1", key: "page", val: "2" },
  },
  "wb-url-remove-param": {
    what: "Give a web address and a parameter name, and get the address back with that parameter removed.",
    when: "You want to clean one unwanted setting, such as a session id, out of a link before sharing it.",
    example: { url: "https://example.com/search?q=shoes&session=abc123", key: "session" },
  },
  "wb-url-resolve": {
    what: "Combines a base web address with a relative link (like ../img/logo.png) and gives the full address the browser would actually load.",
    when: "You are scraping a page or fixing links and need to know where a relative link really points.",
    example: { base: "https://example.com/blog/post/index.html", rel: "../images/cover.png" },
  },
  "wb-url-domain": {
    what: "Paste a web address and get just its host name, the domain part such as shop.example.com.",
    when: "You have a list of long links and want to see which site each one belongs to.",
    example: { url: "https://shop.example.com/products/42?ref=home" },
  },
  "wb-url-path": {
    what: "Paste a web address and get just its path, the part after the domain and before any ? or #, such as /api/v1/users.",
    when: "You are setting up routes, redirects or analytics filters and need only the page path.",
    example: { url: "https://example.com/api/v1/users?id=7#top" },
  },
  "wb-host-port": {
    what: "Splits text like example.com:8080 into the host and the port number. It also handles IPv6 addresses written in square brackets.",
    when: "You are reading a config file or log entry and need the host and port as separate values.",
    example: { auth: "example.com:8080" },
  },
  "wb-cookie-parse": {
    what: "Paste a Cookie header (the line a browser sends listing its cookies, like a=1; b=2) and get each cookie as a name = value line.",
    when: "You copied a request from developer tools and want to read the cookies it sent.",
    example: { h: "Cookie: theme=dark; lang=en; sid=abc123" },
  },
  "wb-setcookie-build": {
    what: "Fill in a cookie name, value and options such as path, domain, lifetime, SameSite, Secure and HttpOnly, and get the Set-Cookie header line a server sends to create that cookie.",
    when: "You are writing server code and want a correct Set-Cookie line with sensible security options.",
    example: { name: "session", value: "abc123", path: "/", domain: "example.com", maxage: "3600", samesite: "Lax", secure: true, httponly: true },
  },
  "wb-csp-build": {
    what: "Write one CSP rule per line (for example default-src 'self') and get a single Content-Security-Policy header. CSP is a header that tells browsers which sources a page may load scripts, images and other content from.",
    when: "You are adding a Content-Security-Policy to a website and want to turn a readable list of rules into the header format. It does not check that the rules are valid.",
    example: { lines: "default-src 'self'\nimg-src 'self' data:\nscript-src 'self' https://cdn.example.com" },
  },
  "wb-csp-parse": {
    what: "Paste a Content-Security-Policy header (the rule list telling browsers where a page may load content from) and get each rule on its own line with its allowed sources.",
    when: "You are reviewing a site's security headers and want a CSP that is hard to read on one line broken out clearly.",
    example: { csp: "default-src 'self'; img-src * data:; script-src 'self' https://cdn.example.com" },
  },
  "wb-cors-preflight": {
    what: "Enter the site making a request, the method and any extra headers, and see what the browser sends in a CORS preflight and which headers your server must send back. CORS is the browser rule that controls whether one website can call another site's API.",
    when: "Your web app gets a CORS error when calling an API and you want to know what the server needs to reply with.",
    example: { origin: "https://app.example.com", method: "PUT", headers: "Content-Type, Authorization", creds: true },
  },
  "wb-cachecontrol-build": {
    what: "Choose caching options (who may cache, how many seconds, no-cache, no-store and others) and get the matching Cache-Control header, which tells browsers and servers how long they may keep a copy of a response.",
    when: "You are setting up caching for a website or API and want the header written correctly.",
    example: { visibility: "public", maxage: "3600", smaxage: "", nocache: false, nostore: false, immutable: false, mustreval: true },
  },
  "wb-cachecontrol-parse": {
    what: "Paste a Cache-Control header (the rules for how long a response may be stored) and get each rule on its own line with a short explanation.",
    when: "You are checking why a page is or is not being cached and want to understand its caching rules.",
    example: { cc: "public, max-age=3600, must-revalidate" },
  },
  "wb-content-disposition": {
    what: "Choose whether a file should open in the browser (inline) or download (attachment), add an optional file name, and get the Content-Disposition header that tells the browser what to do.",
    when: "You are writing server code that serves files and want a download to save with the right name.",
    example: { type: "attachment", filename: "report-2026.pdf" },
  },
  "wb-basic-auth-build": {
    what: "Enter a username and password and get an Authorization: Basic header, where the two are joined with a colon and encoded in Base64 (a simple text encoding, not encryption).",
    when: "You are testing an API or tool that uses Basic authentication and need the header value. Anyone can decode it, so only send it over HTTPS.",
    example: { user: "demo-user", pass: "example-pass" },
  },
  "wb-basic-auth-decode": {
    what: "Paste a Basic authentication header or token and get back the username and password it contains.",
    when: "You are debugging a request and want to check which credentials a Basic auth header is sending.",
    example: { token: "Basic ZGVtby11c2VyOmV4YW1wbGUtcGFzcw==" },
  },
  "wb-bearer-build": {
    what: "Paste an access token and get it formatted as an Authorization: Bearer header, the usual way APIs expect tokens to be sent.",
    when: "You have an API token and need the exact header line for a tool like curl or Postman.",
    example: { token: "example-token-1234567890" },
  },
  "wb-datauri-build": {
    what: "Enter a MIME type (the kind of content, like text/plain) and some text, and get a data: URI, a link that contains the content itself, either Base64-encoded or percent-encoded.",
    when: "You want to embed a small piece of text, CSS or SVG directly in HTML or CSS instead of hosting a separate file.",
    example: { mime: "text/plain", content: "Hello from example.com", b64: true },
  },
  "wb-datauri-parse": {
    what: "Paste a data: URI (a link that holds its content inside itself) and get its MIME type, how it is encoded and the decoded content.",
    when: "You found a long data: link in some HTML or CSS and want to see what is inside it. Binary content such as images will not display as readable text.",
    example: { uri: "data:text/plain;base64,SGVsbG8gZnJvbSBleGFtcGxlLmNvbQ==" },
  },
  "wb-robots-build": {
    what: "Enter which crawler the rules are for, the paths to allow and block, and an optional sitemap link, and get the text of a robots.txt file, which tells search engine crawlers which pages they may visit.",
    when: "You are launching a website and want to keep crawlers out of areas like /admin. Well-behaved crawlers follow it, but it does not actually block access.",
    example: { ua: "*", allow: "/public", disallow: "/admin\n/private", sitemap: "https://example.com/sitemap.xml" },
  },
  "wb-robots-test": {
    what: "Paste robots.txt rules, a page path and a crawler name, and find out whether that path is allowed or blocked and which rule decided it (the longest matching rule wins).",
    when: "You changed your robots.txt and want to check that an important page is not accidentally blocked from search engines.",
    example: { rules: "User-agent: *\nDisallow: /admin\nAllow: /admin/public", path: "/admin/settings", ua: "*" },
  },
  "wb-sitemap-entry": {
    what: "Enter a page address and optional last-modified date, change frequency and priority, and get one <url> entry for a sitemap.xml file, the list of pages you give to search engines.",
    when: "You are adding a page to your sitemap by hand and want the XML written correctly.",
    example: { loc: "https://example.com/blog/first-post", lastmod: "2026-01-15", freq: "weekly", priority: "0.8" },
  },
  "wb-referrer-policy": {
    what: "Pick a Referrer-Policy value and get a plain explanation of it, or choose (all) to list every value. This header controls how much of the previous page's address a browser shares when a visitor clicks a link.",
    when: "You are setting privacy or security headers on a website and need to choose a referrer policy.",
    example: { p: "strict-origin-when-cross-origin" },
  },
  "wb-permissions-policy": {
    what: "Write one browser feature per line with who may use it (for example camera=none or geolocation=self) and get a Permissions-Policy header, which turns features like the camera or location on or off for your pages.",
    when: "You want to lock down which powerful browser features your site and embedded content can use.",
    example: { lines: "geolocation=self\ncamera=none\nmicrophone=https://meet.example.com" },
  },
  "wb-hsts-build": {
    what: "Choose how long browsers should remember to use HTTPS only, whether it covers subdomains and whether to allow preloading, and get a Strict-Transport-Security (HSTS) header.",
    when: "Your site is fully on HTTPS and you want browsers to refuse insecure HTTP connections. Only turn on preload if you are sure every subdomain supports HTTPS.",
    example: { maxage: "31536000", subdomains: true, preload: false },
  },
  "wb-hsts-parse": {
    what: "Paste a Strict-Transport-Security (HSTS) header, which forces browsers to use HTTPS, and get its settings explained, including the time converted to days.",
    when: "You are checking a site's security headers and want to know how long its HTTPS-only rule lasts.",
    example: { h: "max-age=31536000; includeSubDomains; preload" },
  },
  "wb-etag-gen": {
    what: "Paste some content and get an ETag header, a short fingerprint of the content that lets browsers check whether a cached copy has changed. It can be marked weak (W/) if near-identical versions may share it.",
    when: "You are adding caching to a simple server or API and need an ETag value for a response. The fingerprint is a quick hash, not a security feature.",
    example: { content: "{\"id\":1,\"name\":\"Example item\"}", weak: false },
  },
  "wb-accept-lang": {
    what: "Paste an Accept-Language header (the list of languages a browser prefers) and get the languages sorted from most to least preferred, with their preference scores (q values).",
    when: "You are adding translations to a site and want to see which language a visitor's browser prefers.",
    example: { h: "fr-CA,fr;q=0.9,en;q=0.8,de;q=0.5" },
  },
  "wb-accept-parse": {
    what: "Paste an Accept header (the list of content types a client says it can handle) and get the types sorted from most to least preferred, with their preference scores (q values).",
    when: "You are debugging why an API returns HTML instead of JSON and want to see what the client asked for.",
    example: { h: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" },
  },
  "wb-link-header": {
    what: "Write one address and relation per line (for example /page/2 next) and get a single Link header, which points to related resources like the next page of results.",
    when: "You are building a paginated API and want to send next and previous links in the response headers.",
    example: { lines: "https://api.example.com/items?page=3 next\nhttps://api.example.com/items?page=1 prev" },
  },
  "wb-range-header": {
    what: "Enter a start byte and an optional end byte and get a Range header, which asks a server for only part of a file. Leave start empty to ask for the last N bytes.",
    when: "You are resuming a download or testing whether a server supports partial content.",
    example: { start: "0", end: "1023" },
  },
  "wb-retry-after": {
    what: "Enter a number of seconds and get a Retry-After header, either as that number of seconds or as the exact date and time that far from now. It tells clients how long to wait before trying again.",
    when: "Your API is rate-limiting or down for maintenance and you want to tell clients when to come back.",
    example: { mode: "secs", value: "120" },
  },
  "wb-xff-parse": {
    what: "Paste an X-Forwarded-For header, the list of IP addresses a request passed through, and see which one is the original visitor and which are the proxies in between.",
    when: "You are reading logs behind a load balancer or proxy and want to find the real visitor's IP. The header can be faked by the client, so do not trust it blindly.",
    example: { h: "203.0.113.1, 198.51.100.7, 192.0.2.44" },
  },
  "wb-punycode-host": {
    what: "Type a domain name that contains non-English letters (like munchen with an umlaut) and get its punycode form, the plain-ASCII version starting with xn-- that the internet actually uses.",
    when: "You are setting up DNS or checking a suspicious link and need the ASCII form of an international domain.",
    example: { host: "münchen.example" },
  },
  "wb-favicon-link": {
    what: "Enter the path to your site icon and optional size, and get the HTML <link rel=\"icon\"> tag to put in your page head, with the file type filled in when it recognizes the extension.",
    when: "You are adding a favicon (the small icon on a browser tab) to a website.",
    example: { href: "/favicon-32.png", sizes: "32x32" },
  },
  "wb-og-tags": {
    what: "Fill in a page title, type, address, image and description, and get the Open Graph <meta> tags that control how your link looks when shared on social media and chat apps.",
    when: "You want your page to show a proper title, picture and summary when someone shares its link.",
    example: { title: "Example Store Summer Sale", type: "website", url: "https://example.com/sale", image: "https://example.com/img/sale.png", desc: "Up to 50 percent off selected items." },
  },
  "wb-twitter-card": {
    what: "Choose a card type and fill in the site account, title, description and image, and get the Twitter card <meta> tags that control how your link previews on Twitter (X).",
    when: "You want links to your page to show a rich preview with an image when posted on Twitter (X).",
    example: { card: "summary_large_image", site: "@examplebrand", title: "Example Store Summer Sale", desc: "Up to 50 percent off selected items.", image: "https://example.com/img/sale.png" },
  },
  "wb-meta-viewport": {
    what: "Choose the page width and starting zoom, and whether users can zoom, and get the <meta name=\"viewport\"> tag that makes a page display properly on phones.",
    when: "Your web page looks tiny or zoomed out on mobile and you need the standard viewport tag. Blocking zoom makes pages harder to use for some people.",
    example: { width: "device-width", scale: "1", userscale: true },
  },
  "wb-canonical-link": {
    what: "Enter the main address of a page and get a <link rel=\"canonical\"> tag, which tells search engines which address is the official one when the same page is reachable in several ways.",
    when: "Your page is reachable through several addresses, for example with tracking parameters, and you want search engines to count them as one.",
    example: { url: "https://example.com/blog/first-post" },
  },
  "wb-hreflang-tags": {
    what: "Write one language code and address per line and get hreflang <link> tags, which tell search engines which translated version of a page to show to which language.",
    when: "Your site has the same page in several languages and you want search engines to show each visitor the right one.",
    example: { lines: "en https://example.com/en/\nfr https://example.com/fr/\nx-default https://example.com/" },
  },
  "wb-srcset-build": {
    what: "Write one image file and its width or density per line (for example small.jpg 480w) and get a srcset attribute, which lets the browser pick the best-sized image for the screen.",
    when: "You are making images load faster on phones by offering several sizes of the same picture.",
    example: { lines: "photo-480.jpg 480w\nphoto-1024.jpg 1024w\nphoto-1600.jpg 1600w" },
  },
  "wb-www-auth-parse": {
    what: "Paste a WWW-Authenticate header, the line a server sends when it asks you to log in, and get its login scheme and each setting on its own line.",
    when: "An API answered with 401 Unauthorized and you want to understand what kind of login it expects and why it refused.",
    example: { h: "Bearer realm=\"api\", error=\"invalid_token\", error_description=\"The token expired\"" },
  },
  "wb-http-date": {
    what: "Enter a date and time (or leave it blank for now) and get it in the standard HTTP date format used by headers, such as Thu, 01 Jan 2026 12:00:00 GMT.",
    when: "You are writing headers like Expires or Last-Modified by hand and need the exact date format.",
    example: { input: "2026-01-01T12:00:00Z" },
  },
  "wb-url-encode": {
    what: "Encodes text so it is safe to put inside a web address (spaces become %20, & becomes %26, and so on), or decodes such text back to normal.",
    when: "You are putting a search term or value with spaces or symbols into a link, or reading a link full of % codes.",
    example: { text: "blue shoes & socks", mode: "enc" },
  },
  "wb-slug": {
    what: "Turns a title into a slug, the short lowercase part of a web address with hyphens between words and accents and punctuation removed.",
    when: "You are publishing a blog post or product page and need a clean address for it.",
    example: { title: "Hello, World! Our 2026 Launch" },
  },
  "wb-extract-urls": {
    what: "Scans a block of text and lists every web link that starts with http:// or https://, one per line, with duplicates removed.",
    when: "You want to collect all the links mentioned in an email, document or chat log.",
    example: { text: "Visit https://example.com and http://example.org/docs, or https://example.com again." },
  },
  "wb-extract-params": {
    what: "Paste a full web address and get every query parameter (the name=value pairs after the ?) as a readable list, with codes like %20 decoded.",
    when: "You are debugging a link or tracking URL and want to see all its parameters clearly.",
    example: { url: "https://example.com/search?q=blue%20shoes&page=2&sort=price" },
  },
  "wb-valid-url": {
    what: "Checks whether some text is a complete, valid web address (including the protocol such as https://) and tells you the protocol if it is.",
    when: "You are checking user input or a config value and want to know if it is a proper full URL. It checks the format only, not whether the site exists.",
    example: { url: "https://example.com/path?x=1" },
  },
  "wb-valid-email": {
    what: "Checks whether some text looks like an email address (something@domain.ending) and tells you yes or no.",
    when: "You want a quick format check on an address before using it. It cannot tell whether the mailbox actually exists.",
    example: { email: "jane.doe@example.com" },
  },
  "wb-valid-ipv4": {
    what: "Checks whether some text is a valid IPv4 address, meaning four numbers from 0 to 255 separated by dots, like 192.0.2.10.",
    when: "You are checking an IP address in a form, config file or firewall rule before using it.",
    example: { ip: "192.0.2.10" },
  },
  "wb-port-service": {
    what: "Type a port number (the number that tells which program on a computer a network connection is for) and get the service that usually uses it, such as 443 for HTTPS.",
    when: "You see an open port in a scan or firewall log and want to know what it is normally used for. Only well-known ports are listed.",
    example: { port: "443" },
  },
  "wb-status-emoji": {
    what: "Type an HTTP status code and get a one-line summary with a text label for its group (such as [CLIENT ERROR]), its name and its meaning.",
    when: "You want a compact, readable description of a status code for a log message, report or chat.",
    example: { code: "503" },
  },
  "wb-http-request-build": {
    what: "Choose a method and fill in the path, host, extra headers and an optional body, and get the raw text of an HTTP/1.1 request exactly as it is sent over the network, including a correct Content-Length.",
    when: "You are testing a server with a raw-socket tool such as netcat, or learning what a web request really looks like.",
    example: { method: "POST", path: "/api/v1/items", host: "api.example.com", headers: "Content-Type: application/json\nAccept: application/json", body: "{\"name\":\"Example item\"}" },
  },
  "wb-parse-headers": {
    what: "Paste a block of raw HTTP headers (one Name: value per line) and get them as a clean name = value list, with the request or status line and any broken lines marked.",
    when: "You copied headers from curl, a proxy or developer tools and want to read them more easily.",
    example: { block: "HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8\nCache-Control: no-cache\nSet-Cookie: theme=dark" },
  },
  "wb-url-strip-tracking": {
    what: "Paste a web address and get it back without common tracking parameters such as utm_source, fbclid and gclid, keeping the ones that matter for the page.",
    when: "You want to share a cleaner, more private link without the marketing tags added by social media or ads.",
    example: { url: "https://example.com/product?id=42&utm_source=newsletter&utm_medium=email&fbclid=abc123" },
  },
  "wb-url-normalize": {
    what: "Tidies a web address into a standard form: lowercase domain, default ports (80 or 443) removed, dot segments like /a/../ resolved and, if you choose, parameters sorted by name.",
    when: "You are comparing or de-duplicating links that point to the same page but are written differently.",
    example: { url: "HTTPS://Example.COM:443/a/../b?c=2&a=1", sort: true },
  },
};
