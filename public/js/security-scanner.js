// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
(function(){var _h=location.hostname,_a=["darknode.ai","www.darknode.ai","localhost","127.0.0.1"];if(!_a.some(function(d){return _h===d}))throw document.body.innerHTML="",new Error("unlicensed")}());

// Security Scanner — client-side HTTP header, cookie, CSP, CORS, tech stack analyzer.
// Renders a dashboard with scan results, ratings, and recommendations.

const SECURITY_HEADERS = [
  { name: "Strict-Transport-Security", abbr: "HSTS", weight: 10, category: "transport",
    desc: "Forces HTTPS connections, preventing SSL stripping attacks.",
    good: v => v && /max-age=\d{7,}/.test(v),
    best: "max-age=63072000; includeSubDomains; preload",
    risk: "Connections can be intercepted via SSL stripping / downgrade attacks." },
  { name: "Content-Security-Policy", abbr: "CSP", weight: 15, category: "injection",
    desc: "Controls which resources the browser is allowed to load, mitigating XSS.",
    good: v => v && v.length > 20 && !/unsafe-inline/.test(v),
    best: "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    risk: "Cross-site scripting (XSS) attacks are not mitigated by the browser." },
  { name: "X-Content-Type-Options", abbr: "XCTO", weight: 5, category: "injection",
    desc: "Prevents MIME type sniffing that can lead to XSS.",
    good: v => v === "nosniff",
    best: "nosniff",
    risk: "Browsers may interpret files as a different MIME type, enabling XSS." },
  { name: "X-Frame-Options", abbr: "XFO", weight: 8, category: "clickjacking",
    desc: "Prevents the page from being embedded in iframes (clickjacking protection).",
    good: v => v === "DENY" || v === "SAMEORIGIN",
    best: "DENY",
    risk: "Page can be embedded in malicious iframes for clickjacking attacks." },
  { name: "Referrer-Policy", abbr: "RP", weight: 5, category: "privacy",
    desc: "Controls how much referrer information is sent with requests.",
    good: v => v && ["no-referrer","same-origin","strict-origin","strict-origin-when-cross-origin"].includes(v),
    best: "strict-origin-when-cross-origin",
    risk: "Full URL may leak in Referer header to third parties." },
  { name: "Permissions-Policy", abbr: "PP", weight: 6, category: "privacy",
    desc: "Controls which browser features (camera, mic, geolocation) can be used.",
    good: v => v && v.length > 10,
    best: "camera=(), microphone=(), geolocation=(), payment=()",
    risk: "Malicious scripts could access browser features without restriction." },
  { name: "X-XSS-Protection", abbr: "XXSS", weight: 3, category: "injection",
    desc: "Legacy XSS filter (deprecated in modern browsers, but still checked by some).",
    good: v => v === "0" || v === "1; mode=block",
    best: "0 (with CSP) or 1; mode=block (without CSP)",
    risk: "Legacy XSS filter may not be active. Use CSP instead." },
  { name: "Cross-Origin-Opener-Policy", abbr: "COOP", weight: 5, category: "isolation",
    desc: "Isolates the browsing context to prevent cross-origin attacks.",
    good: v => v === "same-origin" || v === "same-origin-allow-popups",
    best: "same-origin",
    risk: "Window references may leak across origins." },
  { name: "Cross-Origin-Embedder-Policy", abbr: "COEP", weight: 4, category: "isolation",
    desc: "Requires resources to explicitly grant permission to be loaded.",
    good: v => v === "require-corp" || v === "credentialless",
    best: "require-corp",
    risk: "Cross-origin resources loaded without explicit permission." },
  { name: "Cross-Origin-Resource-Policy", abbr: "CORP", weight: 4, category: "isolation",
    desc: "Prevents other origins from reading the response.",
    good: v => v && ["same-origin","same-site","cross-origin"].includes(v),
    best: "same-origin",
    risk: "Resources may be read by any origin." },
  { name: "X-DNS-Prefetch-Control", abbr: "XDNS", weight: 2, category: "privacy",
    desc: "Controls browser DNS prefetching behavior.",
    good: v => v === "off" || v === "on",
    best: "off (for privacy-sensitive sites)",
    risk: "DNS prefetching may leak which links a user might visit." },
  { name: "X-Download-Options", abbr: "XDO", weight: 2, category: "injection",
    desc: "Prevents IE from opening files directly (forcing save dialog).",
    good: v => v === "noopen",
    best: "noopen",
    risk: "IE may execute downloaded files in the site context." },
  { name: "X-Permitted-Cross-Domain-Policies", abbr: "XPCDP", weight: 2, category: "injection",
    desc: "Controls Flash/PDF cross-domain policy loading.",
    good: v => v === "none",
    best: "none",
    risk: "Flash/PDF plugins may load cross-domain policy files." },
  { name: "Cache-Control", abbr: "CC", weight: 4, category: "caching",
    desc: "Controls how responses are cached. Sensitive pages should not be cached.",
    good: v => v && (v.includes("no-store") || v.includes("private")),
    best: "no-store, no-cache, must-revalidate (for sensitive pages)",
    risk: "Sensitive data may be cached in browser or proxy caches." },
  { name: "Clear-Site-Data", abbr: "CSD", weight: 2, category: "privacy",
    desc: "Instructs the browser to clear site data on logout.",
    good: v => v && v.includes("cache"),
    best: '"cache", "cookies", "storage"',
    risk: "Session data may persist after logout." },
  { name: "Feature-Policy", abbr: "FP", weight: 2, category: "privacy",
    desc: "Legacy version of Permissions-Policy (still checked by some scanners).",
    good: v => v && v.length > 10,
    best: "Use Permissions-Policy instead",
    risk: "See Permissions-Policy." },
  { name: "Expect-CT", abbr: "ECT", weight: 2, category: "transport",
    desc: "Certificate Transparency enforcement (deprecated in favor of built-in CT).",
    good: v => v && v.includes("enforce"),
    best: "max-age=86400, enforce",
    risk: "Misissued certificates may not be detected." },
  { name: "X-Robots-Tag", abbr: "XRT", weight: 1, category: "privacy",
    desc: "Controls search engine indexing at the HTTP header level.",
    good: v => !!v,
    best: "noindex, nofollow (for sensitive pages)",
    risk: "Sensitive pages may be indexed by search engines." },
  { name: "Server", abbr: "SRV", weight: 3, category: "disclosure",
    desc: "Reveals the web server software and version.",
    good: v => !v || v.length < 6,
    best: "Remove or minimize (e.g., just 'nginx' without version)",
    risk: "Reveals server technology, aiding targeted attacks." },
  { name: "X-Powered-By", abbr: "XPB", weight: 3, category: "disclosure",
    desc: "Reveals the application framework (e.g., Express, PHP).",
    good: v => !v,
    best: "Remove entirely",
    risk: "Reveals technology stack, aiding targeted attacks." },
  { name: "X-AspNet-Version", abbr: "XANV", weight: 2, category: "disclosure",
    desc: "Reveals ASP.NET version information.",
    good: v => !v,
    best: "Remove entirely",
    risk: "Reveals .NET version, enabling version-specific attacks." },
  { name: "Content-Type", abbr: "CT", weight: 3, category: "injection",
    desc: "Specifies the media type. Should include charset for text types.",
    good: v => v && v.includes("charset"),
    best: "text/html; charset=utf-8",
    risk: "Missing charset can lead to encoding-based XSS." },
  { name: "Access-Control-Allow-Origin", abbr: "ACAO", weight: 5, category: "cors",
    desc: "Controls which origins can access the response via CORS.",
    good: v => v !== "*",
    best: "Specific origin (not wildcard *)",
    risk: "Wildcard allows any origin to read the response." },
  { name: "Access-Control-Allow-Credentials", abbr: "ACAC", weight: 4, category: "cors",
    desc: "Allows credentials (cookies) in cross-origin requests.",
    good: v => v !== "true" || true,
    best: "true only with specific (non-wildcard) Allow-Origin",
    risk: "Credentials may be sent to unintended origins." },
  { name: "Access-Control-Allow-Methods", abbr: "ACAM", weight: 2, category: "cors",
    desc: "Specifies allowed HTTP methods for CORS preflight.",
    good: v => v && !v.includes("*"),
    best: "GET, POST (only methods actually needed)",
    risk: "Overly permissive methods may expose unintended endpoints." },
  { name: "Access-Control-Allow-Headers", abbr: "ACAH", weight: 2, category: "cors",
    desc: "Specifies allowed headers for CORS preflight.",
    good: v => v && !v.includes("*"),
    best: "Only headers actually needed",
    risk: "Overly permissive headers may enable attack vectors." },
  { name: "Access-Control-Max-Age", abbr: "ACMA", weight: 1, category: "cors",
    desc: "How long the CORS preflight result can be cached.",
    good: v => v && parseInt(v) <= 86400,
    best: "7200 (2 hours, balance between performance and security)",
    risk: "Very long max-age means CORS policy changes take time to propagate." },
  { name: "Timing-Allow-Origin", abbr: "TAO", weight: 2, category: "privacy",
    desc: "Controls which origins can access timing information via Resource Timing API.",
    good: v => !v || v !== "*",
    best: "Remove or restrict to specific origins",
    risk: "Timing information can be used for side-channel attacks." },
  { name: "NEL", abbr: "NEL", weight: 1, category: "monitoring",
    desc: "Network Error Logging — reports network-level errors to a collector.",
    good: v => !!v,
    best: '{"report_to":"default","max_age":31536000,"include_subdomains":true}',
    risk: "Network errors go unmonitored." },
  { name: "Report-To", abbr: "RT", weight: 1, category: "monitoring",
    desc: "Configures endpoint groups for receiving browser reports (CSP, NEL, etc.).",
    good: v => !!v,
    best: '{"group":"default","max_age":31536000,"endpoints":[{"url":"https://example.com/reports"}]}',
    risk: "Security violations and errors go unreported." },
];

const COOKIE_FLAGS = [
  { flag: "Secure", desc: "Cookie only sent over HTTPS", risk: "Cookie transmitted in cleartext over HTTP" },
  { flag: "HttpOnly", desc: "Cookie not accessible via JavaScript", risk: "Cookie can be stolen via XSS (document.cookie)" },
  { flag: "SameSite", desc: "Controls cross-site cookie sending", risk: "Cookie sent in cross-site requests (CSRF risk)",
    values: { Strict: "Never sent cross-site", Lax: "Sent with top-level navigations", None: "Always sent (requires Secure)" } },
  { flag: "Domain", desc: "Scope of the cookie", risk: "Overly broad domain scope" },
  { flag: "Path", desc: "URL path scope", risk: "Cookie accessible on unintended paths" },
  { flag: "Max-Age / Expires", desc: "Cookie lifetime", risk: "Session cookies (no expiry) persist until browser close; persistent cookies with long expiry increase exposure window" },
  { flag: "__Secure- prefix", desc: "Cookie must have Secure flag and be set over HTTPS", risk: "Without prefix, cookie naming gives no security guarantee" },
  { flag: "__Host- prefix", desc: "Must be Secure, no Domain, Path must be /", risk: "Without prefix, cookie may be set by subdomains" },
];

const CSP_DIRECTIVES = {
  "default-src": { desc: "Fallback for all resource types", risk: "If too permissive, all resource loads are unrestricted" },
  "script-src": { desc: "Controls script sources", risk: "XSS if 'unsafe-inline' or 'unsafe-eval' present" },
  "style-src": { desc: "Controls stylesheet sources", risk: "CSS injection if 'unsafe-inline' present" },
  "img-src": { desc: "Controls image sources", risk: "Data exfiltration via image requests" },
  "connect-src": { desc: "Controls fetch/XHR/WebSocket targets", risk: "Data exfiltration to unintended origins" },
  "font-src": { desc: "Controls font sources", risk: "Potential fingerprinting" },
  "object-src": { desc: "Controls <object>/<embed>/<applet>", risk: "Plugin-based code execution" },
  "media-src": { desc: "Controls <audio>/<video>", risk: "Media from untrusted sources" },
  "frame-src": { desc: "Controls <iframe> sources", risk: "Clickjacking, phishing via embedded frames" },
  "frame-ancestors": { desc: "Controls who can embed this page", risk: "Clickjacking if not 'none' or 'self'" },
  "base-uri": { desc: "Controls <base> element", risk: "Base tag injection for relative URL hijacking" },
  "form-action": { desc: "Controls form submission targets", risk: "Form data exfiltration" },
  "worker-src": { desc: "Controls Web Worker sources", risk: "Malicious worker execution" },
  "manifest-src": { desc: "Controls manifest sources", risk: "Manifest spoofing" },
  "navigate-to": { desc: "Controls navigation targets", risk: "Open redirect if unrestricted" },
  "sandbox": { desc: "Applies sandbox restrictions", risk: "Without sandbox, full page capabilities available" },
  "report-uri": { desc: "Endpoint for CSP violation reports (deprecated)", risk: "Violations go unreported" },
  "report-to": { desc: "Endpoint group for violation reports", risk: "Violations go unreported" },
  "upgrade-insecure-requests": { desc: "Upgrades HTTP to HTTPS", risk: "Mixed content may load over HTTP" },
  "block-all-mixed-content": { desc: "Blocks all mixed content", risk: "Passive mixed content may load" },
  "require-trusted-types-for": { desc: "Requires Trusted Types for DOM XSS prevention", risk: "DOM XSS via innerHTML etc." },
  "trusted-types": { desc: "Configures Trusted Types policies", risk: "Arbitrary DOM manipulation" },
};

const TECH_SIGNATURES = [
  { name: "React", pattern: /__react|reactDOM|react-dom|_reactRoot/i, category: "framework" },
  { name: "Vue.js", pattern: /__vue|vue\.runtime|v-cloak/i, category: "framework" },
  { name: "Angular", pattern: /ng-version|angular\.min|ng-app/i, category: "framework" },
  { name: "Svelte", pattern: /svelte|__svelte/i, category: "framework" },
  { name: "Next.js", pattern: /_next\/static|__NEXT_DATA__|next\/dist/i, category: "framework" },
  { name: "Nuxt", pattern: /__nuxt|_nuxt\//i, category: "framework" },
  { name: "jQuery", pattern: /jquery\.min|jQuery\(/i, category: "library" },
  { name: "Bootstrap", pattern: /bootstrap\.min|bootstrap\.bundle/i, category: "css" },
  { name: "Tailwind CSS", pattern: /tailwindcss|tailwind\.config/i, category: "css" },
  { name: "Firebase", pattern: /firebase\.js|firebaseapp\.com|gstatic\.com\/firebasejs/i, category: "backend" },
  { name: "Google Analytics", pattern: /google-analytics\.com|gtag|googletagmanager/i, category: "analytics" },
  { name: "Google Fonts", pattern: /fonts\.googleapis\.com/i, category: "fonts" },
  { name: "Cloudflare", pattern: /cloudflare|cf-ray|__cf_bm/i, category: "cdn" },
  { name: "Vercel", pattern: /vercel\.app|vercel\.com/i, category: "hosting" },
  { name: "Netlify", pattern: /netlify\.app|netlify\.com/i, category: "hosting" },
  { name: "WordPress", pattern: /wp-content|wp-includes|wordpress/i, category: "cms" },
  { name: "Shopify", pattern: /cdn\.shopify|shopify\.com/i, category: "cms" },
  { name: "Stripe", pattern: /js\.stripe\.com|stripe\.js/i, category: "payment" },
  { name: "Sentry", pattern: /sentry\.io|@sentry\/browser/i, category: "monitoring" },
  { name: "Intercom", pattern: /intercom\.io|intercomcdn/i, category: "support" },
  { name: "Hotjar", pattern: /hotjar\.com|static\.hotjar/i, category: "analytics" },
  { name: "Segment", pattern: /segment\.com|cdn\.segment/i, category: "analytics" },
  { name: "Mixpanel", pattern: /mixpanel\.com|cdn\.mxpnl/i, category: "analytics" },
  { name: "Amplitude", pattern: /amplitude\.com|cdn\.amplitude/i, category: "analytics" },
  { name: "Webpack", pattern: /webpackJsonp|__webpack_require__/i, category: "build" },
  { name: "Vite", pattern: /@vite\/client|import\.meta\.hot/i, category: "build" },
  { name: "TypeScript", pattern: /\.ts\b|typescript/i, category: "language" },
  { name: "GraphQL", pattern: /graphql|__schema|__typename/i, category: "api" },
  { name: "Socket.IO", pattern: /socket\.io/i, category: "realtime" },
  { name: "Service Worker", pattern: /navigator\.serviceWorker|sw\.js/i, category: "pwa" },
];

function parseCSP(raw) {
  if (!raw) return {};
  const directives = {};
  raw.split(";").forEach(part => {
    const trimmed = part.trim();
    if (!trimmed) return;
    const [name, ...values] = trimmed.split(/\s+/);
    directives[name.toLowerCase()] = values;
  });
  return directives;
}

function gradeScore(score, max) {
  const pct = (score / max) * 100;
  if (pct >= 90) return { grade: "A+", color: "#00c853" };
  if (pct >= 80) return { grade: "A", color: "#00c853" };
  if (pct >= 70) return { grade: "B", color: "#64dd17" };
  if (pct >= 60) return { grade: "C", color: "#ffd600" };
  if (pct >= 50) return { grade: "D", color: "#ff9100" };
  if (pct >= 35) return { grade: "E", color: "#ff6d00" };
  return { grade: "F", color: "#ff1744" };
}

function detectTech(html) {
  const found = [];
  const src = html || document.documentElement.outerHTML;
  for (const sig of TECH_SIGNATURES) {
    if (sig.pattern.test(src)) found.push(sig);
  }
  return found;
}

function analyzeCookies() {
  const raw = document.cookie;
  if (!raw) return [];
  return raw.split(";").map(c => {
    const [name, ...rest] = c.trim().split("=");
    return { name: name.trim(), value: rest.join("=").substring(0, 40) + (rest.join("=").length > 40 ? "..." : "") };
  });
}

export function renderSecurityScanner(container) {
  const categories = { transport: "Transport Security", injection: "Injection Prevention", clickjacking: "Clickjacking",
    privacy: "Privacy", isolation: "Cross-Origin Isolation", disclosure: "Information Disclosure",
    cors: "CORS", caching: "Caching", monitoring: "Monitoring" };
  const catColors = { transport: "#00d4ff", injection: "#ff4444", clickjacking: "#ff9100", privacy: "#aa66cc",
    isolation: "#64dd17", disclosure: "#ffd600", cors: "#ff6d00", caching: "#40c4ff", monitoring: "#69f0ae" };

  container.innerHTML = `
    <div class="scan-dashboard" style="max-width:1100px;margin:0 auto;padding:24px;">
      <h2 style="font-size:1.6rem;font-weight:700;margin:0 0 6px;color:var(--txt,#fff);">Security Header Scanner</h2>
      <p style="color:var(--txt-dim,#888);margin:0 0 20px;font-size:.9rem;">Analyze HTTP security headers, cookies, CSP, and technology stack. All checks run client-side.</p>
      <div style="display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap;">
        <input id="scan-url" type="text" placeholder="https://example.com" value="${location.origin}"
          style="flex:1;min-width:240px;padding:10px 14px;background:var(--bg-alt,#111);color:var(--txt,#fff);border:1px solid var(--border,#333);border-radius:8px;font-size:.9rem;font-family:inherit;">
        <button id="scan-go" style="padding:10px 24px;background:var(--acc,#00d4ff);color:#000;border:none;border-radius:4px;font-weight:600;cursor:pointer;font-size:.9rem;">Scan</button>
      </div>
      <div id="scan-results"></div>
      <div style="margin-top:32px;">
        <h3 style="font-size:1.1rem;font-weight:600;margin:0 0 12px;">Header Reference</h3>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:12px;">
          ${SECURITY_HEADERS.map(h => `
            <div style="background:var(--bg-alt,#111);border:1px solid var(--border,#222);border-radius:8px;padding:12px;border-left:3px solid ${catColors[h.category] || '#555'};">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                <strong style="font-size:.85rem;">${h.name}</strong>
                <span style="font-size:.7rem;padding:2px 6px;background:${catColors[h.category]}22;color:${catColors[h.category]};border-radius:4px;">${categories[h.category] || h.category}</span>
              </div>
              <p style="font-size:.78rem;color:var(--txt-dim,#888);margin:0 0 6px;">${h.desc}</p>
              <div style="font-size:.72rem;color:var(--txt-dim,#666);">
                <span style="color:#ff6b6b;">Risk:</span> ${h.risk}<br>
                <span style="color:#69db7c;">Best:</span> <code style="font-size:.68rem;overflow-wrap:anywhere;">${h.best}</code>
              </div>
            </div>
          `).join("")}
        </div>
      </div>
      <div style="margin-top:32px;">
        <h3 style="font-size:1.1rem;font-weight:600;margin:0 0 12px;">Cookie Security Flags</h3>
        <div style="overflow-x:auto;"><table style="width:100%;border-collapse:collapse;font-size:.82rem;">
          <thead><tr style="border-bottom:1px solid var(--border,#333);">
            <th style="text-align:left;padding:8px;color:var(--txt-dim,#888);">Flag</th>
            <th style="text-align:left;padding:8px;color:var(--txt-dim,#888);">Purpose</th>
            <th style="text-align:left;padding:8px;color:var(--txt-dim,#888);">Risk if Missing</th>
          </tr></thead>
          <tbody>
            ${COOKIE_FLAGS.map(f => `<tr style="border-bottom:1px solid var(--border,#222);">
              <td style="padding:8px;font-weight:600;">${f.flag}</td>
              <td style="padding:8px;color:var(--txt-dim,#ccc);">${f.desc}</td>
              <td style="padding:8px;color:#ff6b6b;">${f.risk}</td>
            </tr>`).join("")}
          </tbody>
        </table></div>
      </div>
      <div style="margin-top:32px;">
        <h3 style="font-size:1.1rem;font-weight:600;margin:0 0 12px;">CSP Directive Reference</h3>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:8px;">
          ${Object.entries(CSP_DIRECTIVES).map(([dir, info]) => `
            <div style="background:var(--bg-alt,#111);border:1px solid var(--border,#222);border-radius:6px;padding:10px;">
              <code style="font-size:.8rem;color:var(--acc,#00d4ff);font-weight:600;">${dir}</code>
              <p style="font-size:.75rem;color:var(--txt-dim,#888);margin:4px 0 0;">${info.desc}</p>
              <p style="font-size:.7rem;color:#ff6b6b;margin:2px 0 0;">Risk: ${info.risk}</p>
            </div>
          `).join("")}
        </div>
      </div>
      <div style="margin-top:32px;">
        <h3 style="font-size:1.1rem;font-weight:600;margin:0 0 12px;">Technology Detection</h3>
        <p style="font-size:.82rem;color:var(--txt-dim,#888);margin:0 0 12px;">Technologies detected on this page:</p>
        <div id="tech-detect" style="display:flex;flex-wrap:wrap;gap:8px;">
          ${detectTech().map(t => `<span style="padding:4px 10px;background:var(--bg-alt,#111);border:1px solid var(--border,#333);border-radius:6px;font-size:.78rem;">${t.name} <span style="color:var(--txt-dim,#666);font-size:.68rem;">${t.category}</span></span>`).join("") || '<span style="color:var(--txt-dim,#666);font-size:.82rem;">None detected</span>'}
        </div>
      </div>
      <div style="margin-top:32px;">
        <h3 style="font-size:1.1rem;font-weight:600;margin:0 0 12px;">Current Page Cookies</h3>
        <div id="cookie-list">
          ${analyzeCookies().length ? analyzeCookies().map(c => `
            <div style="display:flex;gap:8px;padding:6px 0;border-bottom:1px solid var(--border,#222);font-size:.82rem;">
              <code style="color:var(--acc,#00d4ff);min-width:120px;">${c.name}</code>
              <span style="color:var(--txt-dim,#888);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${c.value}</span>
            </div>
          `).join("") : '<p style="color:var(--txt-dim,#666);font-size:.82rem;">No cookies set on this page.</p>'}
        </div>
      </div>
    </div>
  `;

  const goBtn = container.querySelector("#scan-go");
  const urlInput = container.querySelector("#scan-url");
  const resultsDiv = container.querySelector("#scan-results");

  goBtn.addEventListener("click", () => {
    const url = urlInput.value.trim();
    if (!url) return;
    resultsDiv.innerHTML = '<div style="text-align:center;padding:40px;color:var(--txt-dim,#888);">Scanning headers...</div>';
    fetch(url, { method: "HEAD", mode: "cors" }).then(resp => {
      let score = 0, maxScore = 0;
      const results = SECURITY_HEADERS.map(h => {
        const val = resp.headers.get(h.name);
        maxScore += h.weight;
        const present = !!val;
        const passed = present && h.good(val);
        if (passed) score += h.weight;
        else if (present) score += Math.floor(h.weight * 0.5);
        return { ...h, value: val, present, passed };
      });
      const { grade, color } = gradeScore(score, maxScore);
      resultsDiv.innerHTML = `
        <div style="display:flex;gap:24px;margin-bottom:24px;flex-wrap:wrap;">
          <div style="width:120px;height:120px;border-radius:50%;border:6px solid ${color};display:flex;align-items:center;justify-content:center;flex-direction:column;">
            <span style="font-size:2.4rem;font-weight:800;color:${color};">${grade}</span>
            <span style="font-size:.72rem;color:var(--txt-dim,#888);">${score}/${maxScore}</span>
          </div>
          <div style="flex:1;min-width:200px;">
            <h3 style="margin:0 0 8px;font-size:1.1rem;">Scan Results</h3>
            <p style="color:var(--txt-dim,#888);font-size:.82rem;margin:0 0 8px;">${url}</p>
            <div style="display:flex;gap:12px;flex-wrap:wrap;">
              <span style="font-size:.78rem;color:#69db7c;">${results.filter(r=>r.passed).length} passed</span>
              <span style="font-size:.78rem;color:#ffd43b;">${results.filter(r=>r.present&&!r.passed).length} warnings</span>
              <span style="font-size:.78rem;color:#ff6b6b;">${results.filter(r=>!r.present).length} missing</span>
            </div>
          </div>
        </div>
        <div style="display:grid;gap:8px;">
          ${results.map(r => `
            <div style="display:flex;align-items:center;gap:12px;padding:10px;background:var(--bg-alt,#111);border-radius:6px;border-left:3px solid ${r.passed ? '#69db7c' : r.present ? '#ffd43b' : '#ff6b6b'};">
              <span style="font-size:1.1rem;">${r.passed ? '&#10003;' : r.present ? '&#9888;' : '&#10007;'}</span>
              <div style="flex:1;min-width:0;">
                <div style="font-size:.82rem;font-weight:600;">${r.name}</div>
                <div style="font-size:.72rem;color:var(--txt-dim,#888);">${r.value || 'Not set'}</div>
              </div>
              <span style="font-size:.68rem;padding:2px 6px;border-radius:4px;background:${catColors[r.category]}22;color:${catColors[r.category]};">${r.category}</span>
            </div>
          `).join("")}
        </div>
      `;
    }).catch(err => {
      resultsDiv.innerHTML = `<div style="text-align:center;padding:40px;color:#ff6b6b;">
        <p style="font-size:.9rem;font-weight:600;">Scan failed</p>
        <p style="font-size:.78rem;color:var(--txt-dim,#888);">${err.message}. Cross-origin scans are blocked by CORS — try scanning the current page or use a CORS proxy.</p>
      </div>`;
    });
  });
}
