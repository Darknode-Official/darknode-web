// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
// Darknode HTTP Inspector — headers, cookies, CSP, CORS, JWT, URL analysis

// ── HTTP Header Reference ───────────────────────────────────────────────────

const HEADER_REF = [
  { name: "Accept", category: "Request", desc: "Media types the client can handle", example: "text/html, application/json", security: "Low — can reveal client capabilities" },
  { name: "Accept-Encoding", category: "Request", desc: "Compression encodings accepted", example: "gzip, deflate, br", security: "BREACH attack exploits compression" },
  { name: "Accept-Language", category: "Request", desc: "Preferred response languages", example: "en-US,en;q=0.9", security: "Can fingerprint users" },
  { name: "Access-Control-Allow-Credentials", category: "CORS", desc: "Allow credentials in CORS requests", example: "true", security: "HIGH — if true with wildcard origin, credentials are exposed" },
  { name: "Access-Control-Allow-Headers", category: "CORS", desc: "Headers allowed in CORS requests", example: "Content-Type, Authorization", security: "Overly permissive headers expand attack surface" },
  { name: "Access-Control-Allow-Methods", category: "CORS", desc: "HTTP methods allowed in CORS", example: "GET, POST, OPTIONS", security: "Limit to required methods only" },
  { name: "Access-Control-Allow-Origin", category: "CORS", desc: "Origins allowed to access the resource", example: "https://example.com", security: "CRITICAL — * with credentials = vulnerability" },
  { name: "Access-Control-Expose-Headers", category: "CORS", desc: "Headers exposed to the client", example: "X-Request-Id", security: "Can leak server internals" },
  { name: "Access-Control-Max-Age", category: "CORS", desc: "How long preflight results are cached", example: "86400", security: "Long values reduce preflight traffic" },
  { name: "Age", category: "Caching", desc: "Time since the response was generated (seconds)", example: "600", security: "Can reveal caching behavior" },
  { name: "Authorization", category: "Auth", desc: "Client credentials for authentication", example: "Bearer eyJ...", security: "CRITICAL — never log or cache" },
  { name: "Cache-Control", category: "Caching", desc: "Caching directives for request/response", example: "no-store, no-cache, must-revalidate", security: "Sensitive pages: no-store prevents caching" },
  { name: "Clear-Site-Data", category: "Security", desc: "Clear browsing data for the origin", example: '"cache", "cookies", "storage"', security: "Useful for logout to prevent data leakage" },
  { name: "Content-Disposition", category: "Response", desc: "How content should be displayed", example: 'attachment; filename="report.pdf"', security: "Filename can be used for path traversal in old browsers" },
  { name: "Content-Encoding", category: "Response", desc: "Compression applied to the body", example: "gzip", security: "BREACH attack vector when combined with secrets" },
  { name: "Content-Length", category: "Response", desc: "Body size in bytes", example: "1234", security: "Mismatches can indicate HTTP smuggling" },
  { name: "Content-Security-Policy", category: "Security", desc: "Controls resources the page can load", example: "default-src 'self'; script-src 'self'", security: "CRITICAL — primary XSS mitigation. Must be strict." },
  { name: "Content-Security-Policy-Report-Only", category: "Security", desc: "CSP in report-only mode (no enforcement)", example: "default-src 'self'; report-uri /csp-report", security: "Test CSP before enforcing — doesn't block, only reports" },
  { name: "Content-Type", category: "General", desc: "Media type of the body", example: "application/json; charset=utf-8", security: "Mismatched type can enable MIME-sniffing attacks" },
  { name: "Cookie", category: "Request", desc: "Cookies sent with the request", example: "session=abc123; csrftoken=xyz", security: "Cookies with secrets must be HttpOnly and Secure" },
  { name: "Cross-Origin-Embedder-Policy", category: "Security", desc: "Controls embedding of cross-origin resources", example: "require-corp", security: "Enables SharedArrayBuffer (Spectre mitigations)" },
  { name: "Cross-Origin-Opener-Policy", category: "Security", desc: "Controls cross-origin window references", example: "same-origin", security: "Prevents Spectre-style side-channel attacks" },
  { name: "Cross-Origin-Resource-Policy", category: "Security", desc: "Controls who can load the resource", example: "same-origin", security: "Prevents unauthorized cross-origin embedding" },
  { name: "Date", category: "General", desc: "Response generation timestamp", example: "Tue, 09 Sep 2026 12:00:00 GMT", security: "Can fingerprint server clock skew" },
  { name: "ETag", category: "Caching", desc: "Entity tag for resource versioning", example: '"abc123"', security: "Can be used for tracking (supercookies)" },
  { name: "Expect-CT", category: "Security", desc: "Certificate Transparency enforcement", example: "max-age=86400, enforce", security: "Deprecated — CT is now required for all public CAs" },
  { name: "Expires", category: "Caching", desc: "Response expiration date", example: "Thu, 01 Jan 2027 00:00:00 GMT", security: "Use Cache-Control instead — Expires is legacy" },
  { name: "Feature-Policy", category: "Security", desc: "Controls browser features (deprecated for Permissions-Policy)", example: "camera 'none'; microphone 'none'", security: "Use Permissions-Policy instead" },
  { name: "Forwarded", category: "Proxy", desc: "Info about proxied request", example: "for=192.168.1.1; proto=https; by=10.0.0.1", security: "Can be spoofed — don't trust blindly for auth" },
  { name: "Host", category: "Request", desc: "Target host and port", example: "example.com:443", security: "Host header injection can cause cache poisoning" },
  { name: "If-Modified-Since", category: "Conditional", desc: "Conditional GET based on modification time", example: "Sat, 29 Oct 2026 19:43:31 GMT", security: "Can probe for resource existence (timing)" },
  { name: "If-None-Match", category: "Conditional", desc: "Conditional GET based on ETag", example: '"abc123"', security: "ETag tracking concern" },
  { name: "Location", category: "Redirect", desc: "URL to redirect the client to", example: "https://example.com/new-path", security: "Open redirect if user-controlled — validate!" },
  { name: "NEL", category: "Security", desc: "Network Error Logging configuration", example: '{"report_to":"default","max_age":31536000}', security: "Reports network errors to your endpoint" },
  { name: "Origin", category: "Request", desc: "Origin of the request", example: "https://example.com", security: "Used in CORS and CSRF protection" },
  { name: "Permissions-Policy", category: "Security", desc: "Controls browser API access", example: "camera=(), microphone=(), geolocation=()", security: "Disable APIs you don't use to reduce attack surface" },
  { name: "Pragma", category: "Caching", desc: "HTTP/1.0 backward-compatible cache control", example: "no-cache", security: "Legacy — use Cache-Control" },
  { name: "Proxy-Authorization", category: "Auth", desc: "Credentials for proxy authentication", example: "Basic dXNlcjpwYXNz", security: "CRITICAL — proxy credentials in transit" },
  { name: "Referrer-Policy", category: "Security", desc: "Controls Referer header behavior", example: "strict-origin-when-cross-origin", security: "Prevents leaking URLs with sensitive data" },
  { name: "Retry-After", category: "Response", desc: "When to retry after 503/429", example: "120", security: "Used in rate limiting responses" },
  { name: "Server", category: "Response", desc: "Web server software identification", example: "nginx/1.25.3", security: "Remove or obscure — reveals software versions" },
  { name: "Set-Cookie", category: "Response", desc: "Set a cookie on the client", example: "session=abc; HttpOnly; Secure; SameSite=Lax", security: "CRITICAL — always set HttpOnly, Secure, SameSite" },
  { name: "Strict-Transport-Security", category: "Security", desc: "Force HTTPS connections", example: "max-age=31536000; includeSubDomains; preload", security: "CRITICAL — prevents SSL stripping. Set max-age >= 1 year." },
  { name: "Transfer-Encoding", category: "Response", desc: "Encoding applied to the message body", example: "chunked", security: "Chunked + Content-Length = HTTP smuggling vector" },
  { name: "User-Agent", category: "Request", desc: "Client software identification", example: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", security: "Can be spoofed — never use for security decisions" },
  { name: "Vary", category: "Caching", desc: "Headers that affect cache key", example: "Origin, Accept-Encoding", security: "CORS: must include Origin to prevent cache poisoning" },
  { name: "Via", category: "Proxy", desc: "Intermediate proxies", example: "1.1 proxy.example.com", security: "Reveals proxy infrastructure" },
  { name: "WWW-Authenticate", category: "Auth", desc: "Authentication scheme for 401 responses", example: 'Bearer realm="api"', security: "Reveals auth mechanism" },
  { name: "X-Content-Type-Options", category: "Security", desc: "Prevents MIME-type sniffing", example: "nosniff", security: "CRITICAL — prevents script injection via MIME confusion" },
  { name: "X-DNS-Prefetch-Control", category: "Performance", desc: "Controls DNS prefetching", example: "off", security: "DNS prefetch can leak visited domains" },
  { name: "X-Download-Options", category: "Security", desc: "Prevents IE from opening downloads in site context", example: "noopen", security: "IE-specific — prevents drive-by downloads" },
  { name: "X-Frame-Options", category: "Security", desc: "Controls iframe embedding", example: "DENY", security: "Prevents clickjacking. Use CSP frame-ancestors instead." },
  { name: "X-Forwarded-For", category: "Proxy", desc: "Client IP through proxies", example: "203.0.113.50, 70.41.3.18", security: "Easily spoofed — use only from trusted proxies" },
  { name: "X-Forwarded-Host", category: "Proxy", desc: "Original Host header through proxies", example: "example.com", security: "Can be spoofed — host header injection risk" },
  { name: "X-Forwarded-Proto", category: "Proxy", desc: "Original protocol through proxies", example: "https", security: "Used to detect HTTPS — spoofable" },
  { name: "X-Permitted-Cross-Domain-Policies", category: "Security", desc: "Controls Flash/PDF cross-domain access", example: "none", security: "Set to 'none' unless Flash/PDF cross-domain needed" },
  { name: "X-Powered-By", category: "Response", desc: "Technology stack information", example: "Express", security: "REMOVE — reveals framework/version for targeted attacks" },
  { name: "X-Request-Id", category: "Debug", desc: "Unique request identifier", example: "a1b2c3d4-e5f6-7890-abcd-ef1234567890", security: "Useful for debugging but can leak in error pages" },
  { name: "X-XSS-Protection", category: "Security", desc: "Legacy XSS filter (deprecated)", example: "0", security: "Set to 0 — the filter itself has vulnerabilities. Use CSP." },
];

// ── Security Header Grading ────────────────────────────────────────────────

const SECURITY_HEADERS = [
  { name: "Strict-Transport-Security", weight: 20, required: true, check: v => /max-age=\d{7,}/.test(v) ? "good" : /max-age=\d+/.test(v) ? "weak" : "missing" },
  { name: "Content-Security-Policy", weight: 20, required: true, check: v => v && !v.includes("unsafe-inline") && !v.includes("unsafe-eval") ? "good" : v ? "weak" : "missing" },
  { name: "X-Content-Type-Options", weight: 10, required: true, check: v => v === "nosniff" ? "good" : "missing" },
  { name: "X-Frame-Options", weight: 8, required: true, check: v => /^(DENY|SAMEORIGIN)$/i.test(v) ? "good" : "missing" },
  { name: "Referrer-Policy", weight: 8, required: true, check: v => v ? "good" : "missing" },
  { name: "Permissions-Policy", weight: 8, required: false, check: v => v ? "good" : "missing" },
  { name: "Cross-Origin-Opener-Policy", weight: 5, required: false, check: v => v ? "good" : "missing" },
  { name: "Cross-Origin-Resource-Policy", weight: 5, required: false, check: v => v ? "good" : "missing" },
  { name: "Cross-Origin-Embedder-Policy", weight: 5, required: false, check: v => v ? "good" : "missing" },
  { name: "X-XSS-Protection", weight: 3, required: false, check: v => v === "0" ? "good" : v ? "weak" : "missing", note: "Should be 0 (the filter has known vulnerabilities)" },
  { name: "X-Permitted-Cross-Domain-Policies", weight: 3, required: false, check: v => v === "none" ? "good" : "missing" },
  { name: "Clear-Site-Data", weight: 2, required: false, check: v => v ? "good" : "missing" },
  { name: "NEL", weight: 1, required: false, check: v => v ? "good" : "missing" },
  { name: "Server", weight: 2, required: false, check: v => !v || v === "" ? "good" : /\d/.test(v) ? "bad" : "weak", note: "Should not reveal version numbers" },
  { name: "X-Powered-By", weight: 2, required: false, check: v => !v ? "good" : "bad", note: "Should be removed entirely" },
];

function gradeHeaders(headers) {
  let totalWeight = 0;
  let earnedWeight = 0;
  const results = [];
  for (const sh of SECURITY_HEADERS) {
    const val = headers[sh.name.toLowerCase()] || headers[sh.name] || "";
    const status = sh.check(val);
    totalWeight += sh.weight;
    if (status === "good") earnedWeight += sh.weight;
    else if (status === "weak") earnedWeight += sh.weight * 0.5;
    results.push({ name: sh.name, value: val || "(not set)", status, weight: sh.weight, required: sh.required, note: sh.note || "" });
  }
  const pct = Math.round((earnedWeight / totalWeight) * 100);
  const grade = pct >= 90 ? "A" : pct >= 80 ? "B" : pct >= 65 ? "C" : pct >= 50 ? "D" : "F";
  return { grade, score: pct, results };
}

// ── Cookie Parser ───────────────────────────────────────────────────────────

function parseCookies(setCookieHeader) {
  const cookies = [];
  const parts = setCookieHeader.split(/\n|(?<=;)\s*(?=[a-zA-Z_-]+=)/);
  for (const raw of parts) {
    if (!raw.trim()) continue;
    const attrs = raw.split(";").map(s => s.trim());
    const [nameVal, ...rest] = attrs;
    const eq = nameVal.indexOf("=");
    if (eq < 0) continue;
    const cookie = { name: nameVal.slice(0, eq), value: nameVal.slice(eq + 1), httpOnly: false, secure: false, sameSite: "None (default)", domain: "", path: "", expires: "", maxAge: "", issues: [] };
    for (const attr of rest) {
      const a = attr.toLowerCase();
      if (a === "httponly") cookie.httpOnly = true;
      else if (a === "secure") cookie.secure = true;
      else if (a.startsWith("samesite=")) cookie.sameSite = attr.split("=")[1];
      else if (a.startsWith("domain=")) cookie.domain = attr.split("=")[1];
      else if (a.startsWith("path=")) cookie.path = attr.split("=")[1];
      else if (a.startsWith("expires=")) cookie.expires = attr.split("=").slice(1).join("=");
      else if (a.startsWith("max-age=")) cookie.maxAge = attr.split("=")[1];
    }
    if (!cookie.httpOnly) cookie.issues.push("Missing HttpOnly — accessible to JavaScript (XSS risk)");
    if (!cookie.secure) cookie.issues.push("Missing Secure — sent over HTTP (MitM risk)");
    if (cookie.sameSite.toLowerCase() === "none" || cookie.sameSite.includes("default")) cookie.issues.push("SameSite=None or absent — vulnerable to CSRF");
    if (cookie.name.toLowerCase().includes("session") && !cookie.httpOnly) cookie.issues.push("Session cookie without HttpOnly is a high-severity finding");
    cookies.push(cookie);
  }
  return cookies;
}

// ── CSP Parser ──────────────────────────────────────────────────────────────

function parseCSP(csp) {
  const directives = [];
  for (const part of csp.split(";")) {
    const tokens = part.trim().split(/\s+/);
    if (!tokens[0]) continue;
    const name = tokens[0];
    const values = tokens.slice(1);
    const issues = [];
    if (values.includes("'unsafe-inline'")) issues.push("unsafe-inline allows inline scripts/styles (XSS risk)");
    if (values.includes("'unsafe-eval'")) issues.push("unsafe-eval allows eval() and similar (code injection risk)");
    if (values.includes("*")) issues.push("Wildcard (*) allows any source — extremely permissive");
    if (values.some(v => v.startsWith("http://"))) issues.push("HTTP source allows insecure loading");
    if (name === "default-src" && values.includes("*")) issues.push("default-src * provides no protection");
    if (name === "script-src" && !values.includes("'strict-dynamic'") && (values.includes("'unsafe-inline'") || values.includes("*"))) {
      issues.push("script-src should use nonces/hashes with strict-dynamic instead of unsafe-inline/*");
    }
    directives.push({ name, values, issues });
  }
  const hasDefault = directives.some(d => d.name === "default-src");
  const hasScript = directives.some(d => d.name === "script-src");
  if (!hasDefault && !hasScript) directives.push({ name: "(missing)", values: [], issues: ["No default-src or script-src — CSP provides minimal protection"] });
  return directives;
}

// ── JWT Decoder ─────────────────────────────────────────────────────────────

function decodeJWT(token) {
  const parts = token.split(".");
  if (parts.length < 2) return { error: "Not a valid JWT (needs at least 2 parts separated by '.')" };
  try {
    const header = JSON.parse(atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")));
    const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
    const issues = [];
    if (header.alg === "none") issues.push("CRITICAL: alg=none — signature not verified!");
    if (header.alg === "HS256" && !parts[2]) issues.push("HMAC algorithm but no signature present");
    if (payload.exp) {
      const expDate = new Date(payload.exp * 1000);
      if (expDate < new Date()) issues.push("Token expired at " + expDate.toISOString());
    }
    if (payload.iat) {
      const iatDate = new Date(payload.iat * 1000);
      if (iatDate > new Date()) issues.push("Token issued in the future (clock skew?)");
    }
    if (!payload.exp) issues.push("No expiration (exp) — token never expires");
    return { header, payload, signature: parts[2] || "(none)", issues };
  } catch (e) {
    return { error: "Failed to decode: " + e.message };
  }
}

// ── URL Parser ──────────────────────────────────────────────────────────────

function parseURL(urlStr) {
  try {
    const url = new URL(urlStr);
    const params = [];
    url.searchParams.forEach((v, k) => params.push({ key: k, value: v }));
    const issues = [];
    if (url.protocol === "http:") issues.push("Using HTTP — not encrypted");
    if (url.username || url.password) issues.push("Credentials in URL — visible in logs and Referer headers");
    params.forEach(p => {
      if (/token|key|secret|pass|auth|session|api.?key/i.test(p.key)) issues.push("Sensitive parameter '" + p.key + "' in URL — prefer headers or POST body");
    });
    if (url.hash && /token|key|secret/i.test(url.hash)) issues.push("Sensitive data in URL fragment");
    return { protocol: url.protocol, hostname: url.hostname, port: url.port || "(default)", pathname: url.pathname, search: url.search, hash: url.hash, username: url.username, password: url.password ? "***" : "", params, origin: url.origin, issues };
  } catch (e) {
    return { error: "Invalid URL: " + e.message };
  }
}

// ── UI ──────────────────────────────────────────────────────────────────────

function esc(s) { return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }

export function renderHttpInspector(container) {
  const CSS = `<style>
  .hti{font-family:var(--mono,'JetBrains Mono',monospace);color:var(--txt,#e0e6ed);max-width:1100px;margin:0 auto;padding:24px}
  .hti h2{font-family:var(--font-display,system-ui);font-weight:700;font-size:1.4rem;margin:0 0 16px;color:var(--acc,#00d4ff)}
  .hti-tabs{display:flex;gap:6px;margin-bottom:20px;flex-wrap:wrap}
  .hti-tab{padding:6px 14px;border-radius:6px;cursor:pointer;font-size:.85rem;border:1px solid var(--border,#1e2a3a);background:var(--bg2,#0d1520);color:var(--mut,#8892a4)}
  .hti-tab.active{background:var(--acc,#00d4ff);color:#000;border-color:var(--acc)}
  .hti-panel{display:none}.hti-panel.active{display:block}
  .hti-input{width:100%;padding:10px 12px;background:var(--bg2,#0d1520);border:1px solid var(--border,#1e2a3a);border-radius:6px;color:var(--txt);font-family:inherit;font-size:.85rem;margin-bottom:12px}
  .hti-input:focus{outline:none;border-color:var(--acc)}
  textarea.hti-input{min-height:100px;resize:vertical}
  .hti-btn{padding:6px 16px;border-radius:6px;border:none;background:var(--acc,#00d4ff);color:#000;font-weight:600;cursor:pointer;font-size:.85rem;margin-right:8px;margin-bottom:8px}
  .hti-btn:hover{opacity:.85}
  .hti-result{background:var(--bg2,#0d1520);border-radius:8px;padding:12px;margin-bottom:12px;font-size:.85rem;border:1px solid var(--border,#1e2a3a)}
  .hti-label{color:var(--mut,#8892a4);font-size:.8rem;margin-bottom:4px}
  .hti-good{color:#22c55e}.hti-warn{color:#f59e0b}.hti-bad{color:#ef4444}
  .hti-table{width:100%;border-collapse:collapse;font-size:.8rem;margin-bottom:12px}
  .hti-table th{text-align:left;padding:6px 8px;border-bottom:1px solid var(--border);color:var(--mut);font-weight:600}
  .hti-table td{padding:6px 8px;border-bottom:1px solid rgba(255,255,255,.04);color:var(--txt);word-break:break-all;vertical-align:top}
  .hti-table tr:hover td{background:rgba(0,212,255,.03)}
  .hti-grade{font-size:2rem;font-weight:800;display:inline-block;width:60px;height:60px;line-height:60px;text-align:center;border-radius:12px}
  .hti-grade-A{background:#22c55e;color:#000}.hti-grade-B{background:#86efac;color:#000}
  .hti-grade-C{background:#f59e0b;color:#000}.hti-grade-D{background:#fb923c;color:#000}
  .hti-grade-F{background:#ef4444;color:#fff}
  .hti-csp-dir{margin-bottom:8px;padding:8px;border-radius:6px;border:1px solid var(--border)}
  .hti-csp-name{color:var(--acc);font-weight:600}
  .hti-csp-val{color:var(--txt);margin-left:8px}
  .hti-issue{color:#f59e0b;font-size:.8rem;margin-top:4px}
  </style>`;

  const tabNames = ["Header Reference", "Security Grader", "Cookie Analyzer", "CSP Evaluator", "JWT Decoder", "URL Parser"];
  const tabHtml = tabNames.map((n, i) => '<div class="hti-tab' + (i === 0 ? " active" : "") + '" data-idx="' + i + '">' + n + '</div>').join("");

  container.innerHTML = CSS + '<div class="hti"><h2>HTTP Inspector</h2><div class="hti-tabs">' + tabHtml + '</div><div id="hti-panels"></div></div>';
  const panelsEl = container.querySelector("#hti-panels");

  function showTab(idx) {
    container.querySelectorAll(".hti-tab").forEach((t, i) => t.classList.toggle("active", i === idx));
    [renderHeaderRef, renderGrader, renderCookieAnalyzer, renderCSPEval, renderJWTDecoder, renderURLParser][idx]();
  }
  container.querySelectorAll(".hti-tab").forEach(t => t.onclick = () => showTab(parseInt(t.dataset.idx)));

  function renderHeaderRef() {
    panelsEl.innerHTML = `<div class="hti-panel active">
      <input class="hti-input" id="hti-hdr-filter" placeholder="Filter headers... (e.g. CSP, cookie, security)">
      <div id="hti-hdr-table"></div></div>`;
    const filter = panelsEl.querySelector("#hti-hdr-filter");
    const table = panelsEl.querySelector("#hti-hdr-table");
    function render(f) {
      const fl = (f || "").toLowerCase();
      const filtered = fl ? HEADER_REF.filter(h => h.name.toLowerCase().includes(fl) || h.category.toLowerCase().includes(fl) || h.desc.toLowerCase().includes(fl)) : HEADER_REF;
      table.innerHTML = '<table class="hti-table"><tr><th>Header</th><th>Category</th><th>Description</th><th>Security</th></tr>' +
        filtered.map(h => '<tr><td style="color:var(--acc);white-space:nowrap">' + esc(h.name) + '</td><td style="color:var(--mut)">' + esc(h.category) + '</td><td>' + esc(h.desc) + '</td><td style="font-size:.75rem">' + esc(h.security) + '</td></tr>').join("") +
        '</table><div style="color:var(--mut);font-size:.75rem">' + filtered.length + ' of ' + HEADER_REF.length + ' headers</div>';
    }
    filter.oninput = () => render(filter.value);
    render("");
  }

  function renderGrader() {
    panelsEl.innerHTML = `<div class="hti-panel active">
      <div class="hti-label">Paste response headers (one per line, Name: Value)</div>
      <textarea class="hti-input" id="hti-gr-input" placeholder="Strict-Transport-Security: max-age=31536000\nContent-Security-Policy: default-src 'self'\nX-Content-Type-Options: nosniff\n..."></textarea>
      <button class="hti-btn" id="hti-gr-go">Grade Security</button>
      <div id="hti-gr-result"></div></div>`;
    panelsEl.querySelector("#hti-gr-go").onclick = () => {
      const raw = panelsEl.querySelector("#hti-gr-input").value;
      const headers = {};
      for (const line of raw.split("\n")) {
        const colon = line.indexOf(":");
        if (colon > 0) headers[line.slice(0, colon).trim().toLowerCase()] = line.slice(colon + 1).trim();
      }
      const g = gradeHeaders(headers);
      panelsEl.querySelector("#hti-gr-result").innerHTML =
        '<div class="hti-result"><div style="display:flex;align-items:center;gap:16px;margin-bottom:16px"><div class="hti-grade hti-grade-' + g.grade + '">' + g.grade + '</div><div><div style="font-size:1.2rem;font-weight:700">' + g.score + '/100</div><div style="color:var(--mut);font-size:.85rem">Security Header Score</div></div></div>' +
        '<table class="hti-table"><tr><th>Header</th><th>Value</th><th>Status</th></tr>' +
        g.results.map(r => '<tr><td style="color:var(--acc)">' + esc(r.name) + (r.required ? ' <span style="color:#f59e0b">*</span>' : '') + '</td><td style="font-size:.75rem">' + esc(r.value).slice(0, 80) + '</td><td class="' + (r.status === "good" ? "hti-good" : r.status === "weak" ? "hti-warn" : r.status === "bad" ? "hti-bad" : "hti-bad") + '">' + r.status.toUpperCase() + (r.note ? ' <span style="color:var(--mut);font-size:.7rem">(' + esc(r.note) + ')</span>' : '') + '</td></tr>').join("") +
        '</table><div style="color:var(--mut);font-size:.75rem">* = required for baseline security</div></div>';
    };
  }

  function renderCookieAnalyzer() {
    panelsEl.innerHTML = `<div class="hti-panel active">
      <div class="hti-label">Paste Set-Cookie headers (one per line)</div>
      <textarea class="hti-input" id="hti-ck-input" placeholder="session=abc123; Path=/; HttpOnly; Secure; SameSite=Lax\ncsrf_token=xyz; Path=/"></textarea>
      <button class="hti-btn" id="hti-ck-go">Analyze Cookies</button>
      <div id="hti-ck-result"></div></div>`;
    panelsEl.querySelector("#hti-ck-go").onclick = () => {
      const cookies = parseCookies(panelsEl.querySelector("#hti-ck-input").value);
      panelsEl.querySelector("#hti-ck-result").innerHTML = cookies.map(c =>
        '<div class="hti-result"><div style="margin-bottom:8px"><strong style="color:var(--acc)">' + esc(c.name) + '</strong> = <span style="color:var(--mut)">' + esc(c.value).slice(0, 50) + '</span></div>' +
        '<table class="hti-table"><tr><td>HttpOnly</td><td class="' + (c.httpOnly ? "hti-good" : "hti-bad") + '">' + c.httpOnly + '</td></tr>' +
        '<tr><td>Secure</td><td class="' + (c.secure ? "hti-good" : "hti-bad") + '">' + c.secure + '</td></tr>' +
        '<tr><td>SameSite</td><td class="' + (/strict|lax/i.test(c.sameSite) ? "hti-good" : "hti-warn") + '">' + esc(c.sameSite) + '</td></tr>' +
        '<tr><td>Domain</td><td>' + esc(c.domain || "(not set)") + '</td></tr>' +
        '<tr><td>Path</td><td>' + esc(c.path || "(not set)") + '</td></tr>' +
        '<tr><td>Expires</td><td>' + esc(c.expires || "(session)") + '</td></tr>' +
        '<tr><td>Max-Age</td><td>' + esc(c.maxAge || "(not set)") + '</td></tr></table>' +
        (c.issues.length ? '<div style="margin-top:8px">' + c.issues.map(i => '<div class="hti-issue">⚠ ' + esc(i) + '</div>').join("") + '</div>' : '<div class="hti-good" style="margin-top:8px">✓ No issues found</div>') +
        '</div>'
      ).join("") || '<div class="hti-result">No cookies parsed</div>';
    };
  }

  function renderCSPEval() {
    panelsEl.innerHTML = `<div class="hti-panel active">
      <div class="hti-label">Paste Content-Security-Policy value</div>
      <textarea class="hti-input" id="hti-csp-input" placeholder="default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com; style-src 'self' 'unsafe-inline'; img-src *;"></textarea>
      <button class="hti-btn" id="hti-csp-go">Evaluate CSP</button>
      <div id="hti-csp-result"></div></div>`;
    panelsEl.querySelector("#hti-csp-go").onclick = () => {
      const directives = parseCSP(panelsEl.querySelector("#hti-csp-input").value);
      const totalIssues = directives.reduce((s, d) => s + d.issues.length, 0);
      panelsEl.querySelector("#hti-csp-result").innerHTML =
        '<div class="hti-result"><div style="margin-bottom:12px"><strong>CSP Analysis</strong> — <span class="' + (totalIssues === 0 ? "hti-good" : "hti-warn") + '">' + totalIssues + ' issue(s)</span></div>' +
        directives.map(d =>
          '<div class="hti-csp-dir"><span class="hti-csp-name">' + esc(d.name) + '</span><span class="hti-csp-val">' + d.values.map(v => {
            const isUnsafe = v.includes("unsafe") || v === "*";
            return '<span style="color:' + (isUnsafe ? "#ef4444" : "var(--txt)") + '">' + esc(v) + '</span>';
          }).join(" ") + '</span>' +
          (d.issues.length ? d.issues.map(i => '<div class="hti-issue">⚠ ' + esc(i) + '</div>').join("") : '') +
          '</div>'
        ).join("") + '</div>';
    };
  }

  function renderJWTDecoder() {
    panelsEl.innerHTML = `<div class="hti-panel active">
      <div class="hti-label">Paste JWT token</div>
      <textarea class="hti-input" id="hti-jwt-input" placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"></textarea>
      <button class="hti-btn" id="hti-jwt-go">Decode JWT</button>
      <div id="hti-jwt-result"></div></div>`;
    panelsEl.querySelector("#hti-jwt-go").onclick = () => {
      const result = decodeJWT(panelsEl.querySelector("#hti-jwt-input").value.trim());
      const res = panelsEl.querySelector("#hti-jwt-result");
      if (result.error) { res.innerHTML = '<div class="hti-result hti-bad">' + esc(result.error) + '</div>'; return; }
      res.innerHTML =
        '<div class="hti-result"><div class="hti-label">Header</div><pre style="background:rgba(0,212,255,.05);padding:8px;border-radius:4px;overflow-x:auto;color:var(--acc)">' + esc(JSON.stringify(result.header, null, 2)) + '</pre></div>' +
        '<div class="hti-result"><div class="hti-label">Payload</div><pre style="background:rgba(0,212,255,.05);padding:8px;border-radius:4px;overflow-x:auto;color:var(--txt)">' + esc(JSON.stringify(result.payload, null, 2)) + '</pre></div>' +
        '<div class="hti-result"><div class="hti-label">Signature</div><div style="word-break:break-all;color:var(--mut)">' + esc(result.signature) + '</div></div>' +
        (result.issues.length ? '<div class="hti-result">' + result.issues.map(i => '<div class="hti-issue">⚠ ' + esc(i) + '</div>').join("") + '</div>' : '<div class="hti-result hti-good">✓ No issues detected</div>');
    };
  }

  function renderURLParser() {
    panelsEl.innerHTML = `<div class="hti-panel active">
      <input class="hti-input" id="hti-url-input" placeholder="https://example.com:8443/api/v1/users?token=abc123&page=1#section">
      <button class="hti-btn" id="hti-url-go">Parse URL</button>
      <div id="hti-url-result"></div></div>`;
    panelsEl.querySelector("#hti-url-go").onclick = () => {
      const result = parseURL(panelsEl.querySelector("#hti-url-input").value.trim());
      const res = panelsEl.querySelector("#hti-url-result");
      if (result.error) { res.innerHTML = '<div class="hti-result hti-bad">' + esc(result.error) + '</div>'; return; }
      res.innerHTML =
        '<div class="hti-result"><table class="hti-table">' +
        '<tr><td style="color:var(--mut)">Protocol</td><td>' + esc(result.protocol) + '</td></tr>' +
        '<tr><td style="color:var(--mut)">Hostname</td><td style="color:var(--acc)">' + esc(result.hostname) + '</td></tr>' +
        '<tr><td style="color:var(--mut)">Port</td><td>' + esc(result.port) + '</td></tr>' +
        '<tr><td style="color:var(--mut)">Path</td><td>' + esc(result.pathname) + '</td></tr>' +
        '<tr><td style="color:var(--mut)">Query</td><td>' + esc(result.search) + '</td></tr>' +
        '<tr><td style="color:var(--mut)">Fragment</td><td>' + esc(result.hash) + '</td></tr>' +
        '<tr><td style="color:var(--mut)">Origin</td><td>' + esc(result.origin) + '</td></tr>' +
        '</table></div>' +
        (result.params.length ? '<div class="hti-result"><div class="hti-label">Query Parameters</div><table class="hti-table"><tr><th>Key</th><th>Value</th></tr>' +
          result.params.map(p => '<tr><td style="color:var(--acc)">' + esc(p.key) + '</td><td>' + esc(p.value) + '</td></tr>').join("") + '</table></div>' : '') +
        (result.issues.length ? '<div class="hti-result">' + result.issues.map(i => '<div class="hti-issue">⚠ ' + esc(i) + '</div>').join("") + '</div>' : '<div class="hti-result hti-good">✓ No security issues detected</div>');
    };
  }

  showTab(0);
}
