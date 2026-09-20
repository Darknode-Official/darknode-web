// Copyright (c) 2026 SpartanKing18. All rights reserved.
// HTTP Security Headers — comprehensive reference with directives, examples, misconfigurations

export const SECURITY_HEADERS = [
  {
    name: "Content-Security-Policy",
    aka: "CSP",
    description: "Controls which resources (scripts, styles, images, fonts, frames, etc.) the browser is allowed to load for a page. The most powerful defense against XSS and data injection attacks.",
    syntax: "Content-Security-Policy: directive value; directive value; ...",
    directives: [
      { name: "default-src", description: "Fallback for all resource types not explicitly set. Usually set to 'self' or 'none'.", values: ["'self'", "'none'", "https:", "data:", "*.example.com", "https://cdn.example.com"] },
      { name: "script-src", description: "Controls JavaScript sources. The most critical directive for XSS prevention.", values: ["'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "'strict-dynamic'", "'nonce-abc123'", "'sha256-hash'", "https://cdn.example.com"] },
      { name: "style-src", description: "Controls CSS sources. 'unsafe-inline' is often needed for inline styles.", values: ["'self'", "'unsafe-inline'", "'nonce-abc123'", "'sha256-hash'", "https://fonts.googleapis.com"] },
      { name: "img-src", description: "Controls image sources.", values: ["'self'", "data:", "blob:", "https:", "*"] },
      { name: "font-src", description: "Controls font sources.", values: ["'self'", "https://fonts.gstatic.com", "data:"] },
      { name: "connect-src", description: "Controls URLs that can be loaded via fetch, XHR, WebSocket, EventSource.", values: ["'self'", "https://api.example.com", "wss://ws.example.com"] },
      { name: "frame-src", description: "Controls which URLs can be embedded in iframes.", values: ["'self'", "'none'", "https://www.youtube.com", "https://accounts.google.com"] },
      { name: "frame-ancestors", description: "Controls which sites can embed THIS page in an iframe. Replaces X-Frame-Options.", values: ["'self'", "'none'", "https://parent.example.com"] },
      { name: "object-src", description: "Controls Flash, Java applets, and other plugins. Should almost always be 'none'.", values: ["'none'"] },
      { name: "media-src", description: "Controls audio and video sources.", values: ["'self'", "https://media.example.com"] },
      { name: "worker-src", description: "Controls Web Worker, SharedWorker, and ServiceWorker sources.", values: ["'self'", "blob:"] },
      { name: "child-src", description: "Controls web workers and nested browsing contexts (iframes). Fallback for frame-src and worker-src.", values: ["'self'", "blob:"] },
      { name: "manifest-src", description: "Controls web app manifest sources.", values: ["'self'"] },
      { name: "base-uri", description: "Restricts URLs for <base> element. Prevents base tag injection attacks.", values: ["'self'", "'none'"] },
      { name: "form-action", description: "Restricts URLs that forms can submit to. Prevents form hijacking.", values: ["'self'", "https://api.example.com"] },
      { name: "navigate-to", description: "Restricts URLs the page can navigate to. Still experimental.", values: ["'self'", "https://example.com"] },
      { name: "report-uri", description: "URL to send CSP violation reports to (deprecated, use report-to).", values: ["https://example.com/csp-report"] },
      { name: "report-to", description: "Reporting API endpoint group name for CSP violation reports.", values: ["csp-endpoint"] },
      { name: "upgrade-insecure-requests", description: "Automatically upgrades HTTP URLs to HTTPS. No value needed.", values: [] },
      { name: "block-all-mixed-content", description: "Blocks all mixed content (HTTP resources on HTTPS page). Deprecated in favor of upgrade-insecure-requests.", values: [] },
      { name: "sandbox", description: "Applies sandbox restrictions to the page (like iframe sandbox attribute).", values: ["allow-scripts", "allow-same-origin", "allow-forms", "allow-popups", "allow-top-navigation"] },
      { name: "require-trusted-types-for", description: "Requires Trusted Types for DOM XSS sinks.", values: ["'script'"] },
      { name: "trusted-types", description: "Restricts creation of Trusted Types policies.", values: ["policy-name", "default", "'allow-duplicates'"] }
    ],
    examples: [
      { level: "Strict", value: "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'", description: "Maximum security: only same-origin resources" },
      { level: "Nonce-based", value: "default-src 'none'; script-src 'nonce-abc123' 'strict-dynamic'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' https://api.example.com; frame-ancestors 'none'; base-uri 'self'", description: "Nonce-based CSP with strict-dynamic for modern apps" },
      { level: "Moderate", value: "default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com; frame-ancestors 'self'", description: "Balanced: allows common CDNs and inline styles" },
      { level: "Report-Only", value: "Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report", description: "Monitor violations without blocking — use during rollout" }
    ],
    misconfigurations: [
      { issue: "unsafe-inline in script-src", risk: "critical", description: "Allows inline scripts, defeating the primary purpose of CSP (XSS prevention)" },
      { issue: "unsafe-eval in script-src", risk: "high", description: "Allows eval(), Function(), setTimeout(string), etc. Enables many XSS payloads" },
      { issue: "Wildcard (*) in script-src", risk: "critical", description: "Allows scripts from any origin. Attacker can host malicious scripts on any domain" },
      { issue: "data: in script-src", risk: "high", description: "Allows scripts loaded from data: URIs, enabling XSS via data:text/html payloads" },
      { issue: "Missing frame-ancestors", risk: "medium", description: "Page can be framed by any site, enabling clickjacking attacks" },
      { issue: "Missing base-uri", risk: "medium", description: "Attacker can inject <base> tag to redirect relative URLs to attacker's server" },
      { issue: "Missing form-action", risk: "medium", description: "Forms can submit to any URL, enabling data theft via form hijacking" },
      { issue: "Overly broad connect-src", risk: "medium", description: "Allows XHR/fetch to many origins, enabling data exfiltration" },
      { issue: "object-src not set to 'none'", risk: "medium", description: "Allows Flash and other plugins which have known vulnerabilities" }
    ],
    testing: ["Google CSP Evaluator (csp-evaluator.withgoogle.com)", "Mozilla Observatory", "SecurityHeaders.com", "Browser DevTools Console (violations logged)", "report-uri.com (violation monitoring)"]
  },
  {
    name: "Strict-Transport-Security",
    aka: "HSTS",
    description: "Forces browsers to only use HTTPS for the domain. After the first HTTPS visit, the browser remembers and automatically upgrades all future HTTP requests to HTTPS, preventing SSL stripping attacks.",
    syntax: "Strict-Transport-Security: max-age=seconds; includeSubDomains; preload",
    directives: [
      { name: "max-age", description: "How long (seconds) the browser should remember to force HTTPS. 31536000 (1 year) recommended for production.", values: ["31536000", "63072000", "300 (testing)"] },
      { name: "includeSubDomains", description: "Apply HSTS to all subdomains. Required for HSTS preload.", values: [] },
      { name: "preload", description: "Request inclusion in browsers' HSTS preload list. Once preloaded, the domain is hardcoded as HTTPS-only in all major browsers.", values: [] }
    ],
    examples: [
      { level: "Production", value: "max-age=31536000; includeSubDomains; preload", description: "Full protection with preload — the gold standard" },
      { level: "Testing", value: "max-age=300", description: "Short max-age for initial testing (5 minutes)" },
      { level: "Without preload", value: "max-age=31536000; includeSubDomains", description: "Strong protection without preload list submission" }
    ],
    misconfigurations: [
      { issue: "max-age=0", risk: "critical", description: "Disables HSTS. Same as not setting the header." },
      { issue: "Missing includeSubDomains with preload", risk: "medium", description: "Cannot be preloaded without includeSubDomains" },
      { issue: "Short max-age in production", risk: "medium", description: "max-age under 31536000 won't qualify for preload and provides weaker protection" },
      { issue: "HSTS on HTTP", risk: "info", description: "HSTS header on HTTP responses is ignored by browsers (only processed over HTTPS)" },
      { issue: "Subdomains not HTTPS-ready", risk: "high", description: "includeSubDomains will break any subdomain not serving HTTPS" }
    ],
    testing: ["hstspreload.org (preload eligibility check)", "curl -sI https://example.com | grep -i strict", "SecurityHeaders.com", "SSL Labs (ssllabs.com/ssltest)"]
  },
  {
    name: "X-Content-Type-Options",
    aka: "XCTO",
    description: "Prevents browsers from MIME-sniffing a response away from the declared Content-Type. Without this, browsers may interpret a text file as HTML/JavaScript, enabling XSS.",
    syntax: "X-Content-Type-Options: nosniff",
    directives: [
      { name: "nosniff", description: "Only valid value. Tells the browser to strictly follow the Content-Type header.", values: [] }
    ],
    examples: [
      { level: "Standard", value: "nosniff", description: "Always use this — there's no reason not to" }
    ],
    misconfigurations: [
      { issue: "Missing header", risk: "medium", description: "Browser may MIME-sniff and execute content as a different type. A .txt file could be executed as JavaScript." },
      { issue: "Wrong Content-Type on responses", risk: "medium", description: "With nosniff, incorrect Content-Type headers will cause resources to be blocked. Ensure all responses have correct Content-Type." }
    ],
    testing: ["curl -sI https://example.com | grep -i x-content-type", "Browser DevTools → Network tab → check response headers"]
  },
  {
    name: "X-Frame-Options",
    aka: "XFO",
    description: "Controls whether the page can be displayed in an iframe. Prevents clickjacking attacks. Being superseded by CSP frame-ancestors but still widely used for backward compatibility.",
    syntax: "X-Frame-Options: DENY | SAMEORIGIN",
    directives: [
      { name: "DENY", description: "Page cannot be displayed in any iframe, even from the same origin.", values: [] },
      { name: "SAMEORIGIN", description: "Page can only be framed by pages from the same origin.", values: [] },
      { name: "ALLOW-FROM uri", description: "Allow framing from a specific URI. DEPRECATED — not supported in modern browsers. Use CSP frame-ancestors instead.", values: [] }
    ],
    examples: [
      { level: "Strict", value: "DENY", description: "No framing at all — use for login pages, payment forms, etc." },
      { level: "Same-origin", value: "SAMEORIGIN", description: "Allow framing from own domain only — use when you embed your own pages" }
    ],
    misconfigurations: [
      { issue: "Missing header", risk: "medium", description: "Page can be framed by any site, enabling clickjacking" },
      { issue: "Using ALLOW-FROM", risk: "medium", description: "Only supported in old IE and Firefox. Ignored by Chrome, Safari, Edge. Use CSP frame-ancestors." },
      { issue: "Conflicting with CSP frame-ancestors", risk: "low", description: "When both are set, CSP frame-ancestors takes precedence in modern browsers" }
    ],
    testing: ["Browser DevTools → try embedding in iframe", "curl -sI https://example.com | grep -i x-frame"]
  },
  {
    name: "Referrer-Policy",
    description: "Controls how much referrer information is sent with requests. Prevents leaking sensitive URLs (with tokens, session IDs, etc.) to third-party sites.",
    syntax: "Referrer-Policy: directive",
    directives: [
      { name: "no-referrer", description: "Never send the Referer header. Maximum privacy but breaks some analytics and CSRF protection.", values: [] },
      { name: "no-referrer-when-downgrade", description: "Send full referrer for HTTPS→HTTPS, none for HTTPS→HTTP. Was the default browser behavior.", values: [] },
      { name: "origin", description: "Send only the origin (scheme+host+port), not the full path.", values: [] },
      { name: "origin-when-cross-origin", description: "Full referrer for same-origin, origin-only for cross-origin. Good balance.", values: [] },
      { name: "same-origin", description: "Full referrer for same-origin, none for cross-origin.", values: [] },
      { name: "strict-origin", description: "Origin-only for same-security-level (HTTPS→HTTPS), none for downgrade (HTTPS→HTTP). Current browser default.", values: [] },
      { name: "strict-origin-when-cross-origin", description: "Full referrer for same-origin, origin for cross-origin (same security), none for downgrade. Recommended.", values: [] },
      { name: "unsafe-url", description: "Always send full referrer. NEVER use — leaks full URLs including query strings to all destinations.", values: [] }
    ],
    examples: [
      { level: "Recommended", value: "strict-origin-when-cross-origin", description: "Best balance of security and functionality" },
      { level: "Privacy-focused", value: "no-referrer", description: "Maximum privacy — no referrer sent anywhere" },
      { level: "Same-origin only", value: "same-origin", description: "Full referrer for own site, nothing for external" }
    ],
    misconfigurations: [
      { issue: "unsafe-url", risk: "high", description: "Sends full URL including query parameters to all sites. Tokens and session IDs in URLs will leak." },
      { issue: "Missing header", risk: "low", description: "Browser uses default (strict-origin-when-cross-origin in modern browsers)" }
    ],
    testing: ["Browser DevTools → Network tab → check Referer header on requests", "curl with redirect to see what referrer is sent"]
  },
  {
    name: "Permissions-Policy",
    aka: "Feature-Policy (old name)",
    description: "Controls which browser features (camera, microphone, geolocation, etc.) can be used by the page and its iframes. Reduces attack surface by disabling unnecessary APIs.",
    syntax: "Permissions-Policy: feature=(allowlist), feature=(allowlist), ...",
    directives: [
      { name: "camera", description: "Access to camera", values: ["()", "(self)", "(self \"https://meet.example.com\")"] },
      { name: "microphone", description: "Access to microphone", values: ["()", "(self)"] },
      { name: "geolocation", description: "Access to user's location", values: ["()", "(self)"] },
      { name: "payment", description: "Payment Request API", values: ["()", "(self)"] },
      { name: "usb", description: "WebUSB API", values: ["()", "(self)"] },
      { name: "bluetooth", description: "Web Bluetooth API", values: ["()"] },
      { name: "accelerometer", description: "Device accelerometer", values: ["()", "(self)"] },
      { name: "gyroscope", description: "Device gyroscope", values: ["()", "(self)"] },
      { name: "magnetometer", description: "Device magnetometer", values: ["()"] },
      { name: "midi", description: "Web MIDI API", values: ["()"] },
      { name: "fullscreen", description: "Fullscreen API", values: ["(self)"] },
      { name: "display-capture", description: "Screen capture (getDisplayMedia)", values: ["()", "(self)"] },
      { name: "autoplay", description: "Media autoplay", values: ["()", "(self)"] },
      { name: "picture-in-picture", description: "Picture-in-picture mode", values: ["(self)", "*"] },
      { name: "encrypted-media", description: "Encrypted Media Extensions (DRM)", values: ["(self)"] },
      { name: "serial", description: "Web Serial API", values: ["()"] },
      { name: "hid", description: "WebHID API (human interface devices)", values: ["()"] },
      { name: "xr-spatial-tracking", description: "WebXR spatial tracking", values: ["()"] },
      { name: "idle-detection", description: "Idle Detection API", values: ["()"] },
      { name: "clipboard-read", description: "Clipboard read access", values: ["(self)"] },
      { name: "clipboard-write", description: "Clipboard write access", values: ["(self)"] }
    ],
    examples: [
      { level: "Restrictive", value: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=(), magnetometer=(), gyroscope=(), accelerometer=(), midi=(), serial=(), hid=()", description: "Disable all sensitive APIs — good for content sites" },
      { level: "Video conferencing", value: "camera=(self), microphone=(self), display-capture=(self), fullscreen=(self), geolocation=(), payment=()", description: "Allow camera/mic for the app, disable everything else" },
      { level: "E-commerce", value: "camera=(), microphone=(), geolocation=(self), payment=(self), usb=(), fullscreen=(self)", description: "Allow payment and geolocation, disable hardware access" }
    ],
    misconfigurations: [
      { issue: "Missing header", risk: "low", description: "All features available by default. Embedded iframes can access camera, microphone, etc." },
      { issue: "Overly permissive (*)", risk: "medium", description: "Using * allows all origins including third-party iframes to access the feature" }
    ],
    testing: ["Browser DevTools → Application → Permissions", "SecurityHeaders.com", "Browser console: document.featurePolicy.allowedFeatures()"]
  },
  {
    name: "Cross-Origin-Opener-Policy",
    aka: "COOP",
    description: "Controls whether a window can be referenced by cross-origin documents. Prevents Spectre-like attacks by isolating the browsing context group.",
    syntax: "Cross-Origin-Opener-Policy: directive",
    directives: [
      { name: "unsafe-none", description: "Default. Window can be referenced by cross-origin documents (window.opener).", values: [] },
      { name: "same-origin", description: "Window is isolated from cross-origin documents. window.opener is null for cross-origin popups.", values: [] },
      { name: "same-origin-allow-popups", description: "Window is isolated but allows popups it opens to reference it. Good for OAuth flows.", values: [] }
    ],
    examples: [
      { level: "Strict", value: "same-origin", description: "Full isolation — needed for SharedArrayBuffer and high-resolution timers" },
      { level: "With OAuth", value: "same-origin-allow-popups", description: "Isolated but allows OAuth popup flows to work" }
    ],
    misconfigurations: [
      { issue: "Breaks OAuth popups", risk: "medium", description: "same-origin breaks window.opener which OAuth popups rely on. Use same-origin-allow-popups." },
      { issue: "Breaks payment popups", risk: "medium", description: "Same issue as OAuth — third-party payment windows may break" }
    ],
    testing: ["Browser DevTools → check cross-origin isolation status", "window.crossOriginIsolated === true in console"]
  },
  {
    name: "Cross-Origin-Embedder-Policy",
    aka: "COEP",
    description: "Controls whether the page can load cross-origin resources. Required (along with COOP) to enable SharedArrayBuffer and high-resolution timers (which were restricted after Spectre).",
    syntax: "Cross-Origin-Embedder-Policy: directive",
    directives: [
      { name: "unsafe-none", description: "Default. Cross-origin resources load normally.", values: [] },
      { name: "require-corp", description: "Only load cross-origin resources that explicitly grant permission via CORP or CORS.", values: [] },
      { name: "credentialless", description: "Cross-origin requests are sent without credentials. Resources don't need CORP headers.", values: [] }
    ],
    examples: [
      { level: "Cross-origin isolated", value: "require-corp", description: "With COOP: same-origin, enables SharedArrayBuffer. All cross-origin resources need CORP/CORS." },
      { level: "Credentialless", value: "credentialless", description: "Easier deployment — resources load without credentials, no CORP needed" }
    ],
    misconfigurations: [
      { issue: "Third-party resources break", risk: "high", description: "require-corp blocks resources from CDNs/third-parties that don't set CORS or CORP headers" }
    ],
    testing: ["window.crossOriginIsolated in console", "Check network tab for blocked resources"]
  },
  {
    name: "Cross-Origin-Resource-Policy",
    aka: "CORP",
    description: "Controls which origins can load a resource. Set on the RESPONSE of the resource, not the page loading it. Prevents cross-origin reads (Spectre defense).",
    syntax: "Cross-Origin-Resource-Policy: directive",
    directives: [
      { name: "same-site", description: "Only same-site origins can load this resource.", values: [] },
      { name: "same-origin", description: "Only same-origin can load this resource.", values: [] },
      { name: "cross-origin", description: "Any origin can load this resource.", values: [] }
    ],
    examples: [
      { level: "Private resources", value: "same-origin", description: "Only your own origin can load — for API responses, user data" },
      { level: "Public CDN assets", value: "cross-origin", description: "Allow anyone to load — for fonts, images, libraries on CDNs" }
    ],
    misconfigurations: [],
    testing: ["curl -sI https://cdn.example.com/image.png | grep -i cross-origin-resource"]
  },
  {
    name: "Clear-Site-Data",
    description: "Instructs the browser to clear stored data (cookies, storage, cache) for the origin. Useful for logout flows.",
    syntax: "Clear-Site-Data: \"cache\", \"cookies\", \"storage\", \"executionContexts\"",
    directives: [
      { name: "\"cache\"", description: "Clear the browser cache for this origin.", values: [] },
      { name: "\"cookies\"", description: "Clear all cookies for this origin.", values: [] },
      { name: "\"storage\"", description: "Clear localStorage, sessionStorage, IndexedDB, Service Workers for this origin.", values: [] },
      { name: "\"executionContexts\"", description: "Reload all browsing contexts for this origin. Experimental.", values: [] },
      { name: "\"*\"", description: "Clear everything.", values: [] }
    ],
    examples: [
      { level: "Logout", value: "\"cache\", \"cookies\", \"storage\"", description: "Clear all data on logout — ensures clean session termination" },
      { level: "Full reset", value: "\"*\"", description: "Nuclear option — clear absolutely everything" }
    ],
    misconfigurations: [
      { issue: "On every page load", risk: "high", description: "Setting this on every response clears data continuously, breaking the site" },
      { issue: "Missing on logout", risk: "medium", description: "Without clearing data on logout, stale tokens and cached data may persist" }
    ],
    testing: ["Set header on /logout endpoint", "Verify cookies and storage are cleared after visiting"]
  },
  {
    name: "NEL (Network Error Logging)",
    description: "Enables the browser to report network errors (DNS failures, TCP timeouts, TLS errors, HTTP errors) back to a collection endpoint. Provides real-user monitoring for connectivity issues.",
    syntax: "NEL: {\"report_to\": \"group-name\", \"max_age\": seconds, \"include_subdomains\": true}",
    directives: [
      { name: "report_to", description: "The Reporting API group to send reports to.", values: ["endpoint-group-name"] },
      { name: "max_age", description: "How long the NEL policy is valid (seconds).", values: ["86400", "2592000"] },
      { name: "include_subdomains", description: "Apply to all subdomains.", values: ["true", "false"] },
      { name: "success_fraction", description: "Fraction of successful requests to report (0.0-1.0). Use low values to avoid flooding.", values: ["0.0", "0.01", "0.1"] },
      { name: "failure_fraction", description: "Fraction of failed requests to report (0.0-1.0). Usually 1.0 to catch all errors.", values: ["1.0"] }
    ],
    examples: [
      { level: "Production", value: "{\"report_to\": \"nel\", \"max_age\": 2592000, \"include_subdomains\": true, \"failure_fraction\": 1.0, \"success_fraction\": 0.01}", description: "Report all failures, sample 1% of successes" }
    ],
    misconfigurations: [],
    testing: ["Requires Report-To header to define the endpoint", "Chrome DevTools → Application → Reporting API"]
  },
  {
    name: "Report-To",
    description: "Defines reporting endpoints for various browser reports (CSP violations, NEL, deprecations, interventions, crashes).",
    syntax: "Report-To: {\"group\": \"name\", \"max_age\": seconds, \"endpoints\": [{\"url\": \"https://...\"}]}",
    directives: [
      { name: "group", description: "Name of the endpoint group (referenced by other headers like NEL, CSP report-to).", values: ["default", "csp-endpoint", "nel-endpoint"] },
      { name: "max_age", description: "How long the reporting configuration is valid.", values: ["86400", "2592000"] },
      { name: "endpoints", description: "Array of endpoint objects with url property.", values: ["{\"url\": \"https://example.com/reports\"}"] },
      { name: "include_subdomains", description: "Apply to subdomains.", values: ["true"] }
    ],
    examples: [
      { level: "Standard", value: "{\"group\": \"default\", \"max_age\": 86400, \"endpoints\": [{\"url\": \"https://example.com/reports\"}]}", description: "Basic reporting endpoint" }
    ],
    misconfigurations: [],
    testing: ["Chrome DevTools → Application → Reporting API"]
  },
  {
    name: "X-DNS-Prefetch-Control",
    description: "Controls whether the browser performs DNS prefetching for links on the page. DNS prefetching improves performance but can leak which links exist on the page.",
    syntax: "X-DNS-Prefetch-Control: on | off",
    directives: [
      { name: "off", description: "Disable DNS prefetching. Prevents information leakage.", values: [] },
      { name: "on", description: "Enable DNS prefetching. Default behavior in most browsers.", values: [] }
    ],
    examples: [
      { level: "Privacy-focused", value: "off", description: "Disable for pages with sensitive links (medical, legal, etc.)" }
    ],
    misconfigurations: [],
    testing: ["Check DNS queries in browser DevTools"]
  },
  {
    name: "X-Permitted-Cross-Domain-Policies",
    description: "Controls whether Adobe Flash and Acrobat can load data from the domain. Mostly legacy but still relevant for preventing data theft via Flash crossdomain.xml.",
    syntax: "X-Permitted-Cross-Domain-Policies: directive",
    directives: [
      { name: "none", description: "No policy files are allowed anywhere on the server. Most secure.", values: [] },
      { name: "master-only", description: "Only the master policy file (/crossdomain.xml) is allowed.", values: [] },
      { name: "all", description: "All policy files are allowed. Least secure.", values: [] }
    ],
    examples: [
      { level: "Standard", value: "none", description: "Block all Flash/PDF cross-domain access — Flash is dead anyway" }
    ],
    misconfigurations: [],
    testing: ["curl -sI https://example.com | grep -i x-permitted"]
  },
  {
    name: "X-XSS-Protection",
    aka: "XSS Filter",
    description: "Legacy header that controlled the browser's built-in XSS filter. The filter has been REMOVED from all modern browsers (Chrome 78+, Edge 79+, Firefox never had it). Setting this header is now a no-op or potentially harmful.",
    syntax: "X-XSS-Protection: 0",
    directives: [
      { name: "0", description: "Disable the XSS filter. RECOMMENDED — the filter itself had vulnerabilities that could be exploited.", values: [] },
      { name: "1", description: "Enable the XSS filter (default in old browsers). Can introduce vulnerabilities.", values: [] },
      { name: "1; mode=block", description: "Enable and block the page instead of sanitizing. Less dangerous than mode=1 but still not recommended.", values: [] }
    ],
    examples: [
      { level: "Current best practice", value: "0", description: "Disable the XSS filter. Use CSP instead." },
      { level: "Or just don't set it", value: "(omit header)", description: "Modern browsers don't have the filter anymore, so the header does nothing" }
    ],
    misconfigurations: [
      { issue: "Setting 1 or 1; mode=block", risk: "low", description: "The XSS filter itself could be exploited to selectively disable scripts. Use CSP instead." }
    ],
    testing: ["Not applicable — filter removed from modern browsers"]
  }
];

export const HEADER_GRADING = {
  description: "Security header grading methodology — check for the presence and correct configuration of security headers",
  weights: [
    { header: "Content-Security-Policy", weight: 25, required: true, grade_if_missing: "F" },
    { header: "Strict-Transport-Security", weight: 20, required: true, grade_if_missing: "D" },
    { header: "X-Content-Type-Options", weight: 10, required: true, grade_if_missing: "C" },
    { header: "X-Frame-Options", weight: 10, required: true, grade_if_missing: "C" },
    { header: "Referrer-Policy", weight: 10, required: true, grade_if_missing: "B" },
    { header: "Permissions-Policy", weight: 10, required: false, grade_if_missing: "B" },
    { header: "Cross-Origin-Opener-Policy", weight: 5, required: false, grade_if_missing: "A" },
    { header: "Cross-Origin-Embedder-Policy", weight: 5, required: false, grade_if_missing: "A" },
    { header: "Cross-Origin-Resource-Policy", weight: 3, required: false, grade_if_missing: "A" },
    { header: "X-XSS-Protection: 0 or absent", weight: 2, required: false, grade_if_missing: "A" }
  ],
  grades: [
    { grade: "A+", score: "95-100", description: "Excellent — all critical headers present and correctly configured" },
    { grade: "A", score: "85-94", description: "Very good — all required headers present, most optional ones too" },
    { grade: "B", score: "70-84", description: "Good — major headers present but some gaps" },
    { grade: "C", score: "55-69", description: "Needs improvement — missing important headers" },
    { grade: "D", score: "40-54", description: "Poor — significant security gaps" },
    { grade: "F", score: "0-39", description: "Failing — critical headers missing" }
  ]
};
