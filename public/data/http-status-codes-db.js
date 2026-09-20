// HTTP Status Codes Database — complete reference for web security analysis
// Every standard HTTP status code with security implications and common attack patterns

export const HTTP_STATUS_CODES_DB = {

  // 1xx Informational
  informational: [
    {
      code: 100,
      name: "Continue",
      description: "Server received request headers and client should proceed with sending the body. Used in Expect: 100-continue flow.",
      securityImplications: "HTTP Request Smuggling can exploit 100 Continue behavior differences between frontend and backend servers.",
      category: "Informational"
    },
    {
      code: 101,
      name: "Switching Protocols",
      description: "Server is switching protocols as requested by the client's Upgrade header (e.g., from HTTP/1.1 to WebSocket).",
      securityImplications: "WebSocket upgrade hijacking. Ensure WebSocket connections are properly authenticated. CSWSH (Cross-Site WebSocket Hijacking) is possible.",
      category: "Informational"
    },
    {
      code: 102,
      name: "Processing",
      description: "WebDAV: Server has received the request but has not yet completed it.",
      securityImplications: "Can indicate WebDAV is enabled — check for PUT/MOVE method exploitation.",
      category: "Informational"
    },
    {
      code: 103,
      name: "Early Hints",
      description: "Used to return response headers before the final HTTP message. Allows preloading resources.",
      securityImplications: "Can be used for cache poisoning if improperly handled by CDNs.",
      category: "Informational"
    },
  ],

  // 2xx Success
  success: [
    {
      code: 200,
      name: "OK",
      description: "Request succeeded. Standard response for successful GET, POST, PUT, PATCH requests.",
      securityImplications: "A 200 on a sensitive endpoint (admin panel, API) indicates access was granted. Check if authentication is required.",
      category: "Success"
    },
    {
      code: 201,
      name: "Created",
      description: "Request succeeded and a new resource was created. Typically returned after POST requests.",
      securityImplications: "If returned without authentication on resource creation endpoints, indicates missing access controls.",
      category: "Success"
    },
    {
      code: 202,
      name: "Accepted",
      description: "Request accepted for processing but not yet completed. Used for asynchronous operations.",
      securityImplications: "Async processing may bypass rate limiting. Verify async results are properly validated.",
      category: "Success"
    },
    {
      code: 203,
      name: "Non-Authoritative Information",
      description: "Response from a transforming proxy. The response differs from what the origin server returned.",
      securityImplications: "May indicate a proxy is modifying responses. Check for proxy injection or content tampering.",
      category: "Success"
    },
    {
      code: 204,
      name: "No Content",
      description: "Request succeeded but no content to return. Common for DELETE requests and CORS preflight responses.",
      securityImplications: "204 on DELETE without authentication indicates missing access controls on resource deletion.",
      category: "Success"
    },
    {
      code: 206,
      name: "Partial Content",
      description: "Server is delivering only part of the resource due to a Range header. Used for resumable downloads.",
      securityImplications: "Range header abuse for DoS (requesting many small ranges). Can leak information about file sizes.",
      category: "Success"
    },
    {
      code: 207,
      name: "Multi-Status",
      description: "WebDAV: Multiple sub-requests completed with different status codes.",
      securityImplications: "WebDAV exposure. Check for file upload, directory listing, and PROPFIND information disclosure.",
      category: "Success"
    },
  ],

  // 3xx Redirection
  redirection: [
    {
      code: 301,
      name: "Moved Permanently",
      description: "Resource has been permanently moved to a new URL. Browsers cache this redirect.",
      securityImplications: "Open redirect vulnerability if the Location header is user-controlled. Cache poisoning via cached redirects.",
      category: "Redirection"
    },
    {
      code: 302,
      name: "Found (Temporary Redirect)",
      description: "Resource temporarily available at a different URL. Most common redirect code.",
      securityImplications: "Open redirect exploitation. Login bypass if redirect happens before authentication check. SSRF via redirect chains.",
      category: "Redirection"
    },
    {
      code: 303,
      name: "See Other",
      description: "Response to the request is at another URL, and should be retrieved using GET.",
      securityImplications: "Same open redirect risks as 302. Can be used to change POST to GET (losing body data).",
      category: "Redirection"
    },
    {
      code: 304,
      name: "Not Modified",
      description: "Resource has not been modified since the version specified by If-Modified-Since/If-None-Match headers.",
      securityImplications: "Cache timing attacks. Can reveal whether a user has visited a specific resource based on cache behavior.",
      category: "Redirection"
    },
    {
      code: 307,
      name: "Temporary Redirect",
      description: "Like 302 but guarantees the HTTP method is preserved (POST stays POST).",
      securityImplications: "HSTS redirects use 307. Open redirect risks if Location is controllable. Method preservation can cause unintended POST replays.",
      category: "Redirection"
    },
    {
      code: 308,
      name: "Permanent Redirect",
      description: "Like 301 but guarantees the HTTP method is preserved.",
      securityImplications: "Permanent cached redirect. If poisoned, attacker controls all future requests to the resource.",
      category: "Redirection"
    },
  ],

  // 4xx Client Errors
  client_errors: [
    {
      code: 400,
      name: "Bad Request",
      description: "Server cannot process the request due to malformed syntax.",
      securityImplications: "WAF/IDS may return 400 for blocked payloads. Different 400 vs 200 responses can indicate parameter parsing differences exploitable in smuggling.",
      category: "Client Error"
    },
    {
      code: 401,
      name: "Unauthorized",
      description: "Authentication is required and has not been provided or has failed.",
      securityImplications: "Indicates endpoint requires authentication. Brute force target. WWW-Authenticate header reveals auth scheme (Basic, Bearer, Negotiate).",
      category: "Client Error"
    },
    {
      code: 402,
      name: "Payment Required",
      description: "Reserved for future use. Sometimes used by APIs to indicate billing/quota issues.",
      securityImplications: "May reveal pricing tier information. API quota bypass may be possible.",
      category: "Client Error"
    },
    {
      code: 403,
      name: "Forbidden",
      description: "Server understood the request but refuses to authorize it. Authentication won't help.",
      securityImplications: "Indicates the resource exists but access is denied. Try bypass: IP spoofing headers (X-Forwarded-For), HTTP verb tampering, path traversal variants (/admin -> /Admin, /admin/, /admin.json).",
      category: "Client Error"
    },
    {
      code: 404,
      name: "Not Found",
      description: "Requested resource does not exist on the server.",
      securityImplications: "High 404 volume from one IP = directory brute forcing. Custom vs default 404 pages reveal server technology. 404 vs 403 response differences enable content discovery.",
      category: "Client Error"
    },
    {
      code: 405,
      name: "Method Not Allowed",
      description: "HTTP method is not supported for this resource. Allow header lists permitted methods.",
      securityImplications: "The Allow header in the response reveals which HTTP methods ARE accepted. Try PUT, DELETE, PATCH, OPTIONS for unintended access.",
      category: "Client Error"
    },
    {
      code: 406,
      name: "Not Acceptable",
      description: "Server cannot produce a response matching the Accept headers sent by the client.",
      securityImplications: "Indicates content negotiation. Try different Accept headers to find alternative representations (JSON vs XML).",
      category: "Client Error"
    },
    {
      code: 407,
      name: "Proxy Authentication Required",
      description: "Client must authenticate with the proxy before the request can be forwarded.",
      securityImplications: "Indicates a proxy is in the path. Proxy credential brute force. Proxy misconfiguration allowing bypass.",
      category: "Client Error"
    },
    {
      code: 408,
      name: "Request Timeout",
      description: "Server timed out waiting for the client to send a complete request.",
      securityImplications: "Slowloris DoS attack causes 408s. Connection timeout differences can reveal processing logic (timing attacks).",
      category: "Client Error"
    },
    {
      code: 409,
      name: "Conflict",
      description: "Request conflicts with the current state of the resource (e.g., edit conflict).",
      securityImplications: "Race condition indicator. TOCTOU (Time of Check Time of Use) vulnerabilities. Resource state manipulation.",
      category: "Client Error"
    },
    {
      code: 410,
      name: "Gone",
      description: "Resource previously existed but has been permanently removed.",
      securityImplications: "Confirms the resource existed at some point. Can reveal information about former endpoints and functionality.",
      category: "Client Error"
    },
    {
      code: 413,
      name: "Payload Too Large",
      description: "Request body exceeds the server's size limit.",
      securityImplications: "Reveals server upload limits. Try chunked transfer encoding to bypass size restrictions.",
      category: "Client Error"
    },
    {
      code: 414,
      name: "URI Too Long",
      description: "Request URI exceeds the server's maximum URI length.",
      securityImplications: "Buffer overflow attempts may trigger this. Some WAFs can be bypassed with very long URIs.",
      category: "Client Error"
    },
    {
      code: 415,
      name: "Unsupported Media Type",
      description: "Server does not support the media type in the request's Content-Type header.",
      securityImplications: "Content-Type confusion attacks. Try different content types (application/json vs application/xml) to find parsing differences.",
      category: "Client Error"
    },
    {
      code: 418,
      name: "I'm a teapot",
      description: "Easter egg from RFC 2324 (Hyper Text Coffee Pot Control Protocol). Not a real status code.",
      securityImplications: "If returned by a real server, may indicate a custom/unusual web framework or WAF rule.",
      category: "Client Error"
    },
    {
      code: 422,
      name: "Unprocessable Entity",
      description: "Server understands the content type and syntax but cannot process the instructions.",
      securityImplications: "Indicates input validation. Difference between 422 and 400 can help map validation rules. Common in GraphQL APIs.",
      category: "Client Error"
    },
    {
      code: 425,
      name: "Too Early",
      description: "Server is unwilling to process a request that might be replayed (TLS 1.3 0-RTT).",
      securityImplications: "Indicates TLS 1.3 early data protection. If not properly implemented, 0-RTT replay attacks are possible.",
      category: "Client Error"
    },
    {
      code: 429,
      name: "Too Many Requests",
      description: "Client has sent too many requests in a given time period (rate limiting).",
      securityImplications: "Rate limiting detected. Bypass attempts: rotate IPs, modify headers, change user agents, use different endpoints, slow down, or use API key rotation.",
      category: "Client Error"
    },
    {
      code: 431,
      name: "Request Header Fields Too Large",
      description: "Server refuses to process the request because headers are too large.",
      securityImplications: "Large cookie/header attacks. Can be used to DoS specific users by inflating their cookies.",
      category: "Client Error"
    },
    {
      code: 451,
      name: "Unavailable For Legal Reasons",
      description: "Resource is unavailable due to legal demands (censorship, DMCA, court order).",
      securityImplications: "Reveals content exists but is blocked. May be accessible from different jurisdictions or via VPN.",
      category: "Client Error"
    },
  ],

  // 5xx Server Errors
  server_errors: [
    {
      code: 500,
      name: "Internal Server Error",
      description: "Generic server error. The server encountered an unexpected condition.",
      securityImplications: "May reveal stack traces, framework info, database errors, or file paths in the response body. Always check 500 response bodies for information disclosure.",
      category: "Server Error"
    },
    {
      code: 501,
      name: "Not Implemented",
      description: "Server does not support the HTTP method used in the request.",
      securityImplications: "Reveals which methods the server recognizes vs implements. Try uncommon methods (PROPFIND, TRACE, CONNECT).",
      category: "Server Error"
    },
    {
      code: 502,
      name: "Bad Gateway",
      description: "Server acting as a gateway received an invalid response from the upstream server.",
      securityImplications: "Indicates reverse proxy/load balancer architecture. Backend server may be directly accessible. Request smuggling targets gateway/backend discrepancies.",
      category: "Server Error"
    },
    {
      code: 503,
      name: "Service Unavailable",
      description: "Server is temporarily unable to handle the request (overloaded or under maintenance).",
      securityImplications: "DoS success indicator. May reveal maintenance windows or capacity limits. Retry-After header shows when service returns.",
      category: "Server Error"
    },
    {
      code: 504,
      name: "Gateway Timeout",
      description: "Server acting as a gateway did not receive a timely response from the upstream server.",
      securityImplications: "Time-based blind injection may cause 504s. SSRF to slow internal services. Backend DoS via complex queries.",
      category: "Server Error"
    },
    {
      code: 505,
      name: "HTTP Version Not Supported",
      description: "Server does not support the HTTP protocol version used in the request.",
      securityImplications: "Try HTTP/1.0 for different behavior. HTTP/2 downgrade attacks. HTTP version confusion in smuggling.",
      category: "Server Error"
    },
    {
      code: 508,
      name: "Loop Detected",
      description: "WebDAV: Server detected an infinite loop while processing the request.",
      securityImplications: "Indicates WebDAV with complex operations. May be exploitable for DoS.",
      category: "Server Error"
    },
    {
      code: 520,
      name: "Web Server Returned an Unknown Error",
      description: "Cloudflare-specific: Origin server returned an unexpected response.",
      securityImplications: "Indicates Cloudflare CDN. Origin server may be reachable directly — check DNS history, certificate transparency.",
      category: "CDN Error"
    },
    {
      code: 521,
      name: "Web Server Is Down",
      description: "Cloudflare-specific: Origin server refused the connection.",
      securityImplications: "Origin server firewall may be blocking Cloudflare IPs. Origin discovery via historical DNS or certificate leaks.",
      category: "CDN Error"
    },
    {
      code: 522,
      name: "Connection Timed Out",
      description: "Cloudflare-specific: Connection to the origin server timed out.",
      securityImplications: "May indicate origin server is under load or blocking. DoS of origin behind CDN.",
      category: "CDN Error"
    },
    {
      code: 523,
      name: "Origin Is Unreachable",
      description: "Cloudflare-specific: Cannot reach the origin server (DNS resolution failure).",
      securityImplications: "DNS misconfiguration. Possible subdomain takeover if DNS points to decommissioned infrastructure.",
      category: "CDN Error"
    },
    {
      code: 524,
      name: "A Timeout Occurred",
      description: "Cloudflare-specific: Connection to origin was established but origin did not respond in time.",
      securityImplications: "Long-running requests. May indicate exploitable server-side processing delays.",
      category: "CDN Error"
    },
    {
      code: 525,
      name: "SSL Handshake Failed",
      description: "Cloudflare-specific: SSL/TLS handshake between Cloudflare and origin server failed.",
      securityImplications: "SSL misconfiguration on origin. May be exploitable for downgrade attacks or certificate mismatch.",
      category: "CDN Error"
    },
    {
      code: 530,
      name: "Origin DNS Error",
      description: "Cloudflare-specific: DNS resolution for the origin failed. Often accompanied by a 1016 error.",
      securityImplications: "DNS misconfiguration. Check for dangling DNS records and possible subdomain takeover.",
      category: "CDN Error"
    },
  ],

  // ═══════════════════════════════════════════════════════════════════════════
  // HTTP SECURITY HEADERS REFERENCE
  // ═══════════════════════════════════════════════════════════════════════════
  security_headers: [
    {
      header: "Content-Security-Policy",
      description: "Controls which resources the browser is allowed to load. Primary defense against XSS.",
      recommended: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';",
      attacks_mitigated: ["Reflected XSS", "Stored XSS", "Clickjacking", "Data injection", "Mixed content"],
      common_bypasses: ["Whitelisted CDN with user-uploadable content", "unsafe-inline allows inline scripts", "JSONP endpoints on whitelisted domains", "Angular/Vue template injection in CSP-whitelisted domains", "base-uri not restricted allows base tag hijacking"],
      severity: "Critical",
      category: "Response Header"
    },
    {
      header: "Strict-Transport-Security",
      description: "Forces browsers to use HTTPS for all future requests to the domain.",
      recommended: "max-age=31536000; includeSubDomains; preload",
      attacks_mitigated: ["SSL stripping", "Protocol downgrade attacks", "Cookie hijacking over HTTP", "Man-in-the-middle via HTTP interception"],
      common_bypasses: ["First visit is unprotected (use preload list)", "Subdomain not included (use includeSubDomains)", "Short max-age easily expires", "NTP attack to expire HSTS pin"],
      severity: "High",
      category: "Response Header"
    },
    {
      header: "X-Content-Type-Options",
      description: "Prevents browsers from MIME-type sniffing, reducing drive-by download attacks.",
      recommended: "nosniff",
      attacks_mitigated: ["MIME confusion attacks", "Content-type mismatch exploitation", "Script execution via mislabeled content types"],
      common_bypasses: ["Only affects script and style types in modern browsers", "Does not protect against server-side content type issues"],
      severity: "Medium",
      category: "Response Header"
    },
    {
      header: "X-Frame-Options",
      description: "Controls whether the page can be embedded in an iframe. Legacy clickjacking protection.",
      recommended: "DENY (or SAMEORIGIN if framing is needed)",
      attacks_mitigated: ["Clickjacking", "UI redressing", "Likejacking", "Cursorjacking"],
      common_bypasses: ["Superseded by CSP frame-ancestors", "ALLOW-FROM is not supported by all browsers", "Double-framing bypasses SAMEORIGIN in some cases"],
      severity: "Medium",
      category: "Response Header"
    },
    {
      header: "Referrer-Policy",
      description: "Controls how much referrer information is sent with requests. Prevents sensitive URL leakage.",
      recommended: "strict-origin-when-cross-origin",
      attacks_mitigated: ["Referrer-based information leakage", "Token exposure in URLs", "Session ID leakage via referrer"],
      common_bypasses: ["Not respected by all browsers/clients", "rel=noreferrer on individual links overrides"],
      severity: "Medium",
      category: "Response Header"
    },
    {
      header: "Permissions-Policy",
      description: "Controls which browser features and APIs can be used by the page and its iframes.",
      recommended: "camera=(), microphone=(), geolocation=(), interest-cohort=()",
      attacks_mitigated: ["Unauthorized camera/microphone access", "Location tracking", "FLoC tracking", "Payment API abuse", "USB/Bluetooth access"],
      common_bypasses: ["Only applies to embedded content, not top-level page", "Older browsers may not support all directives"],
      severity: "Medium",
      category: "Response Header"
    },
    {
      header: "Cross-Origin-Opener-Policy",
      description: "Controls whether a document can share a browsing context with cross-origin documents.",
      recommended: "same-origin",
      attacks_mitigated: ["Spectre-like side-channel attacks", "Cross-origin window reference attacks", "Timing attacks via window.length/window.opener"],
      common_bypasses: ["same-origin-allow-popups may still be exploitable", "Does not protect against network-level attacks"],
      severity: "Medium",
      category: "Response Header"
    },
    {
      header: "Cross-Origin-Resource-Policy",
      description: "Controls which origins can include a resource. Prevents cross-origin reads.",
      recommended: "same-origin (or same-site for CDN resources)",
      attacks_mitigated: ["Spectre-like cross-origin data leaks", "Cross-origin image/script inclusion attacks"],
      common_bypasses: ["Requires careful configuration for CDN-hosted resources"],
      severity: "Medium",
      category: "Response Header"
    },
    {
      header: "Cross-Origin-Embedder-Policy",
      description: "Controls loading of cross-origin resources that don't explicitly grant permission.",
      recommended: "require-corp",
      attacks_mitigated: ["Cross-origin data leaks via speculative execution", "Enables SharedArrayBuffer and high-resolution timers safely"],
      common_bypasses: ["credentialless mode may leak some information", "Requires CORP headers on all embedded resources"],
      severity: "Low",
      category: "Response Header"
    },
    {
      header: "X-XSS-Protection",
      description: "Legacy XSS filter in older browsers. Deprecated in modern browsers — CSP is the replacement.",
      recommended: "0 (disable — the filter itself can introduce vulnerabilities)",
      attacks_mitigated: ["Basic reflected XSS in older browsers"],
      common_bypasses: ["Easily bypassed with mutation XSS", "Can be weaponized to selectively disable legitimate scripts", "Not supported in modern browsers"],
      severity: "Low",
      category: "Response Header"
    },
    {
      header: "Cache-Control",
      description: "Controls caching behavior. Security-critical for pages containing sensitive data.",
      recommended: "no-store, no-cache, must-revalidate, private (for sensitive pages)",
      attacks_mitigated: ["Cached credential exposure", "Shared cache poisoning", "Browser history sniffing", "Sensitive data in CDN caches"],
      common_bypasses: ["Browser may still cache in memory", "CDN may ignore cache directives", "Service workers can cache regardless"],
      severity: "Medium",
      category: "Response Header"
    },
    {
      header: "Set-Cookie",
      description: "Sets cookies with security attributes. Critical for session management security.",
      recommended: "HttpOnly; Secure; SameSite=Strict; Path=/; Domain=.example.com",
      attacks_mitigated: ["XSS cookie theft (HttpOnly)", "Cookie interception over HTTP (Secure)", "CSRF (SameSite=Strict/Lax)", "Cookie scope attacks (Path/Domain)"],
      common_bypasses: ["HttpOnly doesn't prevent CSRF", "SameSite=Lax allows top-level GET", "Cookie tossing on shared parent domains", "Subdomain cookie injection"],
      severity: "Critical",
      category: "Response Header"
    },
    {
      header: "Access-Control-Allow-Origin",
      description: "CORS header specifying which origins can access the response. Misconfiguration leads to data theft.",
      recommended: "Specific origin (never * with credentials). Validate against allowlist server-side.",
      attacks_mitigated: ["Unauthorized cross-origin data access"],
      common_bypasses: ["Reflecting the Origin header without validation", "null origin allowed (sandboxed iframes)", "Wildcard with credentials (browsers block this but may be misconfigured)", "Subdomain trust leading to XSS→CORS chain"],
      severity: "High",
      category: "Response Header"
    },
    {
      header: "X-Permitted-Cross-Domain-Policies",
      description: "Controls Flash and PDF cross-domain data loading via crossdomain.xml policy files.",
      recommended: "none",
      attacks_mitigated: ["Flash-based cross-origin data theft", "PDF plugin data exfiltration"],
      common_bypasses: ["Flash is end-of-life but some legacy systems still use it"],
      severity: "Low",
      category: "Response Header"
    },
    {
      header: "Clear-Site-Data",
      description: "Instructs the browser to clear site data (cache, cookies, storage) for the origin.",
      recommended: "\"cache\", \"cookies\", \"storage\" (on logout endpoints)",
      attacks_mitigated: ["Session persistence after logout", "Cached credential access", "Stored XSS payload persistence"],
      common_bypasses: ["Only works over HTTPS", "Not supported by all browsers", "Service worker caches may persist"],
      severity: "Medium",
      category: "Response Header"
    },
    {
      header: "Expect-CT",
      description: "Enforces Certificate Transparency requirements. Being deprecated as browsers now require CT by default.",
      recommended: "max-age=86400, enforce (if CT infrastructure is in place)",
      attacks_mitigated: ["Fraudulent certificate issuance", "CA compromise detection"],
      common_bypasses: ["Being deprecated — browsers enforce CT natively now"],
      severity: "Low",
      category: "Response Header"
    },
    {
      header: "X-DNS-Prefetch-Control",
      description: "Controls DNS prefetching behavior. Prefetching can leak browsing information.",
      recommended: "off (for sensitive applications)",
      attacks_mitigated: ["DNS-based tracking via prefetch requests", "Information leakage about page content"],
      common_bypasses: ["Minimal security impact in most scenarios"],
      severity: "Low",
      category: "Response Header"
    },
    {
      header: "X-Download-Options",
      description: "IE-specific header preventing direct file opening (forces download).",
      recommended: "noopen",
      attacks_mitigated: ["Drive-by download execution in Internet Explorer"],
      common_bypasses: ["Only affects Internet Explorer", "Modern browsers ignore this header"],
      severity: "Low",
      category: "Response Header"
    },
    {
      header: "Feature-Policy",
      description: "Legacy name for Permissions-Policy. Controls browser feature access.",
      recommended: "Use Permissions-Policy instead (Feature-Policy is deprecated)",
      attacks_mitigated: ["Same as Permissions-Policy"],
      common_bypasses: ["Deprecated — use Permissions-Policy"],
      severity: "Low",
      category: "Response Header"
    },
    {
      header: "Timing-Allow-Origin",
      description: "Controls which origins can access detailed timing data via the Resource Timing API.",
      recommended: "Only list trusted origins or omit entirely",
      attacks_mitigated: ["Cross-origin timing attacks for cache probing", "Side-channel information leakage via timing"],
      common_bypasses: ["Coarse timing information is available regardless"],
      severity: "Low",
      category: "Response Header"
    },
  ],
};
